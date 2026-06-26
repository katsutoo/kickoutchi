//! Optional Docker enrichment for local port ownership.
//!
//! The native OS collectors remain the source of truth. This module only tries
//! to explain Docker-looking or metadata-hidden owners in the selected-row
//! details view, and every failure path returns no enrichment instead of
//! breaking port collection.

use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::debug;

use crate::model::{DockerContainerPort, DockerPortContext, PermissionStatus, PortEntry, Protocol};

const DOCKER_COMMAND_TIMEOUT: Duration = Duration::from_millis(1_500);
const DOCKER_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const DOCKER_ROWS_MAX: usize = 128;
const DOCKER_MATCHES_MAX: usize = 8;
const DOCKER_FIELD_MAX_BYTES: usize = 4 * 1024;
const DOCKER_PORT_SEGMENTS_MAX: usize = 64;

const DOCKER_PROCESS_NAMES: &[&str] = &[
    "docker",
    "docker.exe",
    "docker-proxy",
    "docker-proxy.exe",
    "dockerd",
    "dockerd.exe",
    "Docker Desktop.exe",
    "com.docker.backend",
    "com.docker.backend.exe",
    "com.docker.vpnkit",
    "com.docker.slirp",
    "vpnkit",
];

#[derive(Debug, Deserialize)]
struct DockerPsJsonRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Ports")]
    ports: String,
    #[serde(rename = "Labels")]
    labels: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerContainerRow {
    id: String,
    name: String,
    ports: String,
    compose_project: Option<String>,
    compose_service: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    fn mapped_port(self, peer: Self, port: u16) -> Option<u16> {
        if !self.contains(port) {
            return None;
        }
        if peer.start == peer.end {
            return Some(peer.start);
        }
        let offset = port.checked_sub(self.start)?;
        peer.start
            .checked_add(offset)
            .filter(|mapped| *mapped <= peer.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishedPort {
    host_addr: Option<IpAddr>,
    host_ports: PortRange,
    container_ports: PortRange,
    protocol: Protocol,
}

pub(crate) fn enrich_port(entry: &PortEntry) -> Option<DockerPortContext> {
    if !should_try_docker_enrichment(entry) {
        return None;
    }

    let output = docker_container_ls(entry.local_port, entry.protocol)?;
    docker_context_from_ps_output(entry, &output)
}

fn docker_container_ls(port: u16, protocol: Protocol) -> Option<String> {
    let publish_filter = format!("publish={port}/{}", protocol_filter(protocol));
    let mut child = match Command::new("docker")
        .arg("container")
        .arg("ls")
        .arg("--filter")
        .arg(publish_filter)
        .arg("--format")
        .arg("json")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            debug!(%error, "docker CLI unavailable for port enrichment");
            return None;
        }
    };

    let deadline = Instant::now() + DOCKER_COMMAND_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                debug!("docker CLI timed out during port enrichment");
                return None;
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                debug!(%error, "docker CLI wait failed during port enrichment");
                return None;
            }
        }
    }

    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            debug!(%error, "docker CLI output collection failed during port enrichment");
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = %output.status, "docker CLI returned non-success status");
        return None;
    }
    if output.stdout.len() > DOCKER_OUTPUT_MAX_BYTES {
        debug!(
            bytes = output.stdout.len(),
            "docker CLI output exceeded enrichment cap"
        );
        return None;
    }

    match String::from_utf8(output.stdout) {
        Ok(stdout) => Some(stdout),
        Err(error) => {
            debug!(%error, "docker CLI output was not UTF-8");
            None
        }
    }
}

fn docker_context_from_ps_output(entry: &PortEntry, output: &str) -> Option<DockerPortContext> {
    let mut containers = Vec::new();
    let mut truncated = false;

    'rows: for (row_index, line) in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if row_index >= DOCKER_ROWS_MAX {
            truncated = true;
            break;
        }

        let Some(row) = parse_container_row(line) else {
            continue;
        };
        for published_port in parse_published_ports(&row.ports) {
            let Some(container_port) = matched_container_port(entry, published_port) else {
                continue;
            };
            if contains_container_match(&containers, &row.id, entry, container_port) {
                continue;
            }
            containers.push(DockerContainerPort {
                id: row.id.clone(),
                name: row.name.clone(),
                compose_project: row.compose_project.clone(),
                compose_service: row.compose_service.clone(),
                host_port: entry.local_port,
                container_port,
                protocol: entry.protocol,
            });
            if containers.len() >= DOCKER_MATCHES_MAX {
                truncated = true;
                break 'rows;
            }
        }
    }

    if containers.is_empty() {
        None
    } else {
        Some(DockerPortContext {
            containers,
            truncated,
        })
    }
}

fn contains_container_match(
    containers: &[DockerContainerPort],
    container_id: &str,
    entry: &PortEntry,
    container_port: u16,
) -> bool {
    containers.iter().any(|container| {
        container.id == container_id
            && container.host_port == entry.local_port
            && container.container_port == container_port
            && container.protocol == entry.protocol
    })
}

fn should_try_docker_enrichment(entry: &PortEntry) -> bool {
    looks_like_docker_owner(entry)
        || (entry.permission == PermissionStatus::Partial && entry.process_name.is_none())
}

fn looks_like_docker_owner(entry: &PortEntry) -> bool {
    entry
        .process_name
        .as_deref()
        .is_some_and(is_docker_process_name)
        || entry
            .executable_path
            .as_ref()
            .and_then(|path| path.file_name())
            .and_then(|name| name.to_str())
            .is_some_and(is_docker_process_name)
}

fn is_docker_process_name(name: &str) -> bool {
    DOCKER_PROCESS_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn parse_container_row(line: &str) -> Option<DockerContainerRow> {
    if line.len() > DOCKER_FIELD_MAX_BYTES * 4 {
        return None;
    }

    let row: DockerPsJsonRow = serde_json::from_str(line).ok()?;
    if field_too_large(&row.id)
        || field_too_large(&row.names)
        || field_too_large(&row.ports)
        || field_too_large(&row.labels)
    {
        return None;
    }

    let id = trimmed_non_empty(&row.id)?;
    let name = first_container_name(&row.names).unwrap_or_else(|| id.clone());
    Some(DockerContainerRow {
        id,
        name,
        ports: row.ports,
        compose_project: label_value(&row.labels, "com.docker.compose.project"),
        compose_service: label_value(&row.labels, "com.docker.compose.service"),
    })
}

fn field_too_large(field: &str) -> bool {
    field.len() > DOCKER_FIELD_MAX_BYTES
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn first_container_name(names: &str) -> Option<String> {
    names
        .split(',')
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(str::to_owned)
}

fn label_value(labels: &str, key: &str) -> Option<String> {
    labels.split(',').find_map(|label| {
        let (label_key, value) = label.split_once('=')?;
        if label_key.trim() == key && !value.is_empty() {
            Some(value.to_owned())
        } else {
            None
        }
    })
}

fn parse_published_ports(ports: &str) -> Vec<PublishedPort> {
    ports
        .split(',')
        .take(DOCKER_PORT_SEGMENTS_MAX)
        .filter_map(|segment| parse_published_port_segment(segment.trim()))
        .collect()
}

fn parse_published_port_segment(segment: &str) -> Option<PublishedPort> {
    let (host_binding, container_binding) = segment.split_once("->")?;
    let (container_ports, protocol) = parse_container_binding(container_binding.trim())?;
    let (host_addr, host_ports) = parse_host_binding(host_binding.trim())?;
    Some(PublishedPort {
        host_addr,
        host_ports,
        container_ports,
        protocol,
    })
}

fn parse_container_binding(binding: &str) -> Option<(PortRange, Protocol)> {
    let (ports, protocol) = binding.rsplit_once('/')?;
    Some((parse_port_range(ports.trim())?, parse_protocol(protocol)?))
}

fn parse_host_binding(binding: &str) -> Option<(Option<IpAddr>, PortRange)> {
    let (host, ports) = split_host_binding(binding)?;
    let host_addr = match host {
        Some(host) => Some(parse_host_addr(host)?),
        None => None,
    };
    Some((host_addr, parse_port_range(ports)?))
}

fn split_host_binding(binding: &str) -> Option<(Option<&str>, &str)> {
    if binding.is_empty() {
        return None;
    }
    if let Some(stripped) = binding.strip_prefix('[') {
        let (host, ports) = stripped.split_once("]:")?;
        return Some((Some(host), ports));
    }
    if let Some((host, ports)) = binding.rsplit_once(':') {
        if ports.is_empty() {
            return None;
        }
        return if host.is_empty() {
            Some((None, ports))
        } else {
            Some((Some(host), ports))
        };
    }
    Some((None, binding))
}

fn parse_host_addr(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse().ok()
}

fn parse_port_range(ports: &str) -> Option<PortRange> {
    let trimmed = ports.trim();
    let (start, end) = if let Some((start, end)) = trimmed.split_once('-') {
        (parse_port(start)?, parse_port(end)?)
    } else {
        let port = parse_port(trimmed)?;
        (port, port)
    };
    if start > end {
        return None;
    }
    Some(PortRange { start, end })
}

fn parse_port(port: &str) -> Option<u16> {
    port.trim().parse().ok()
}

fn parse_protocol(protocol: &str) -> Option<Protocol> {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

fn matched_container_port(entry: &PortEntry, published_port: PublishedPort) -> Option<u16> {
    if entry.protocol != published_port.protocol {
        return None;
    }
    if !host_addr_matches(entry.local_addr, published_port.host_addr) {
        return None;
    }
    published_port
        .host_ports
        .mapped_port(published_port.container_ports, entry.local_port)
}

fn host_addr_matches(row_addr: IpAddr, docker_addr: Option<IpAddr>) -> bool {
    let Some(docker_addr) = docker_addr else {
        return true;
    };
    let row_addr = normalize_addr(row_addr);
    let docker_addr = normalize_addr(docker_addr);
    row_addr == docker_addr || row_addr.is_unspecified() || docker_addr.is_unspecified()
}

fn normalize_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(addr),
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
    }
}

fn protocol_filter(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    use super::{
        docker_context_from_ps_output, host_addr_matches, looks_like_docker_owner,
        parse_published_ports, should_try_docker_enrichment,
    };
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    fn entry(port: u16, protocol: Protocol, addr: IpAddr, process_name: &str) -> PortEntry {
        PortEntry {
            protocol,
            local_addr: addr,
            local_port: port,
            state: match protocol {
                Protocol::Tcp => SocketState::Listen,
                Protocol::Udp => SocketState::Bound,
            },
            pid: Some(1234),
            process_name: Some(process_name.to_owned()),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{process_name}"))),
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    #[test]
    fn non_docker_processes_do_not_trigger_enrichment() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "postgres",
        );

        assert!(!should_try_docker_enrichment(&row));
    }

    #[test]
    fn missing_owner_metadata_can_trigger_optional_docker_enrichment() {
        let mut row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "postgres",
        );
        row.pid = None;
        row.process_name = None;
        row.executable_path = None;
        row.permission = PermissionStatus::Partial;

        assert!(should_try_docker_enrichment(&row));
    }

    #[test]
    fn docker_proxy_processes_trigger_enrichment_case_insensitively() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "Docker-Proxy",
        );

        assert!(looks_like_docker_owner(&row));
    }

    #[test]
    fn parses_published_ports_and_ignores_exposed_only_ports() {
        let ports = parse_published_ports("80/tcp, 127.0.0.1:5432->5432/tcp, [::]:5353->5353/udp");

        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].host_addr, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(ports[0].host_ports.start, 5432);
        assert_eq!(ports[0].container_ports.start, 5432);
        assert_eq!(ports[0].protocol, Protocol::Tcp);
        assert_eq!(ports[1].host_addr, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert_eq!(ports[1].protocol, Protocol::Udp);
    }

    #[test]
    fn port_ranges_map_host_port_to_container_port() {
        let row = entry(
            8001,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8000-8002->9000-9002/tcp","Labels":""}"#;

        let context = docker_context_from_ps_output(&row, output).expect("range matches");
        let container = context.single_container().expect("one container");

        assert_eq!(container.host_port, 8001);
        assert_eq!(container.container_port, 9001);
    }

    #[test]
    fn compose_labels_and_stop_command_are_preserved_for_one_match() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"a762a2b37a1d","Names":"postgres-dev","Ports":"0.0.0.0:5432->5432/tcp","Labels":"com.docker.compose.project=swamp,com.docker.compose.service=db"}"#;

        let context = docker_context_from_ps_output(&row, output).expect("container matches");
        let container = context.single_container().expect("one container");

        assert_eq!(container.name, "postgres-dev");
        assert_eq!(container.compose_project.as_deref(), Some("swamp"));
        assert_eq!(container.compose_service.as_deref(), Some("db"));
        assert_eq!(container.stop_command(), "docker stop postgres-dev");
        assert!(!context.truncated);
    }

    #[test]
    fn protocol_must_match_before_container_is_reported() {
        let row = entry(
            5353,
            Protocol::Udp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output =
            r#"{"ID":"abc123","Names":"dns","Ports":"0.0.0.0:5353->5353/tcp","Labels":""}"#;

        assert!(docker_context_from_ps_output(&row, output).is_none());
    }

    #[test]
    fn duplicate_ipv4_ipv6_bindings_do_not_make_one_container_ambiguous() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8080->80/tcp, [::]:8080->80/tcp","Labels":""}"#;

        let context = docker_context_from_ps_output(&row, output).expect("container matches");

        assert_eq!(context.containers.len(), 1);
        assert_eq!(context.containers[0].name, "web");
    }

    #[test]
    fn malformed_json_rows_are_ignored_without_losing_valid_matches() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "docker-proxy",
        );
        let output = concat!(
            "not-json\n",
            r#"{"ID":"abc123","Names":"api","Ports":"127.0.0.1:8080->80/tcp","Labels":""}"#,
        );

        let context = docker_context_from_ps_output(&row, output).expect("valid row matches");

        assert_eq!(context.containers.len(), 1);
        assert_eq!(context.containers[0].container_port, 80);
    }

    #[test]
    fn wildcard_addresses_match_specific_socket_views() {
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ));
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ));
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
            ))),
        ));
    }
}
