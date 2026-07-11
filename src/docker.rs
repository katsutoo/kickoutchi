//! Optional Docker enrichment for local port ownership.
//!
//! The native OS collectors remain the source of truth. This module only tries
//! to explain Docker-looking or metadata-hidden owners in the selected-row
//! details view, and every failure path returns no enrichment instead of
//! breaking port collection.

use std::io::{self, Read};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::debug;

use crate::model::{DockerContainerPort, DockerPortContext, PermissionStatus, PortEntry, Protocol};

const DOCKER_COMMAND_TIMEOUT: Duration = Duration::from_millis(1_500);
// How long to wait for a drain worker after the child is gone. Killing the
// direct docker child closes its pipe fds, so a healthy drain finishes almost
// immediately; the wait exists because a grandchild that inherited the pipe
// (Docker Desktop shims, credential helpers) can hold the write end open
// indefinitely, and an unbounded join would hang with it.
const DOCKER_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const DOCKER_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const DOCKER_OUTPUT_READ_CHUNK_BYTES: usize = 8 * 1024;
const DOCKER_OUTPUT_DRAIN_WORKERS_MAX: usize = 8;
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
    docker_container_ls_with_runner(port, protocol, run_command_bounded)
}

fn docker_container_ls_with_runner(
    port: u16,
    protocol: Protocol,
    run: impl FnOnce(&mut Command) -> Option<std::process::Output>,
) -> Option<String> {
    if docker_command_is_elevated() {
        debug!("skipping PATH-resolved docker CLI while process is elevated");
        return None;
    }

    let publish_filter = format!("publish={port}/{}", protocol_filter(protocol));
    // `docker` resolves through PATH on purpose: install locations vary too
    // much (distro packages, Docker Desktop, Homebrew) for a fixed allowlist.
    // Elevation is rejected above before PATH resolution.
    let mut command = Command::new("docker");
    command
        .arg("container")
        .arg("ls")
        .arg("--filter")
        .arg(publish_filter)
        .arg("--format")
        .arg("json");
    let output = run(&mut command)?;
    if !output.status.success() {
        debug!(status = %output.status, "docker CLI returned non-success status");
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

#[cfg(test)]
thread_local! {
    static TEST_ELEVATION_OVERRIDE: std::cell::Cell<Option<bool>> = const {
        std::cell::Cell::new(None)
    };
    #[cfg(target_os = "linux")]
    static TEST_LINUX_ELEVATION_SOURCES: std::cell::Cell<Option<(bool, bool, bool)>> = const {
        std::cell::Cell::new(None)
    };
}

fn docker_command_is_elevated() -> bool {
    #[cfg(test)]
    if let Some(elevated) = TEST_ELEVATION_OVERRIDE.with(std::cell::Cell::get) {
        return elevated;
    }
    process_is_elevated()
}

#[cfg(target_os = "linux")]
fn process_is_elevated() -> bool {
    unix_ids_are_elevated() || linux_aux_is_secure() || linux_process_has_capabilities()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn process_is_elevated() -> bool {
    unix_ids_are_elevated()
}

#[cfg(unix)]
fn unix_ids_are_elevated() -> bool {
    #[cfg(all(test, target_os = "linux"))]
    if let Some((ids, _, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return ids;
    }
    unsafe {
        // SAFETY: these libc identity queries take no arguments, access no
        // caller-provided memory, and cannot fail.
        libc::geteuid() == 0
            || libc::geteuid() != libc::getuid()
            || libc::getegid() != libc::getgid()
    }
}

#[cfg(target_os = "linux")]
fn linux_aux_is_secure() -> bool {
    #[cfg(test)]
    if let Some((_, aux_secure, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return aux_secure;
    }
    unsafe {
        // SAFETY: getauxval reads the process's immutable auxiliary vector and
        // takes no pointer arguments. AT_SECURE is nonzero for secure-execution
        // modes such as set-ID or file-capability launches.
        libc::getauxval(libc::AT_SECURE) != 0
    }
}

#[cfg(target_os = "linux")]
fn linux_process_has_capabilities() -> bool {
    const STATUS_READ_MAX_BYTES: u64 = 64 * 1024;
    #[cfg(test)]
    if let Some((_, _, capabilities)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return capabilities;
    }
    let mut status = String::new();
    let result = std::fs::File::open("/proc/self/status").and_then(|file| {
        file.take(STATUS_READ_MAX_BYTES)
            .read_to_string(&mut status)
            .map(|_| ())
    });
    // Docker enrichment is optional. If the privilege state cannot be proven
    // ordinary, fail closed and do not cross PATH with the process's authority.
    result.is_err() || linux_status_has_capabilities(&status).unwrap_or(true)
}

#[cfg(target_os = "linux")]
fn linux_status_has_capabilities(status: &str) -> Option<bool> {
    let mut found = 0_u8;
    let mut any = false;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(name, "CapPrm" | "CapEff" | "CapAmb") {
            continue;
        }
        found = found.saturating_add(1);
        any |= u64::from_str_radix(value.trim(), 16).ok()? != 0;
    }
    (found == 3).then_some(any)
}

#[cfg(windows)]
fn process_is_elevated() -> bool {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    let opened = unsafe {
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle, and `token`
        // points to storage for the returned owned token handle.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
    };
    if opened == 0 || token.is_null() {
        return true;
    }
    let token = unsafe {
        // SAFETY: OpenProcessToken returned a non-null handle owned by this
        // scope. OwnedHandle closes it exactly once.
        OwnedHandle::from_raw_handle(token)
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned_bytes = 0_u32;
    let expected_bytes =
        u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size must fit in u32");
    let queried = unsafe {
        // SAFETY: the token has TOKEN_QUERY access, `elevation` is valid for a
        // TOKEN_ELEVATION write, and both byte counts match its exact size.
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            expected_bytes,
            &raw mut returned_bytes,
        )
    };
    queried == 0 || returned_bytes != expected_bytes || elevation.TokenIsElevated != 0
}

#[cfg(not(any(unix, windows)))]
fn process_is_elevated() -> bool {
    false
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[derive(Debug)]
struct DrainCapacity {
    active: AtomicUsize,
    maximum: usize,
}

impl DrainCapacity {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn reserve_pair(self: &Arc<Self>) -> Option<[DrainPermit; 2]> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active.checked_add(2)? > self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 2,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some([DrainPermit(Arc::clone(self)), DrainPermit(Arc::clone(self))]);
                }
                Err(current) => active = current,
            }
        }
    }
}

#[derive(Debug)]
struct DrainPermit(Arc<DrainCapacity>);

impl Drop for DrainPermit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "drain worker reservation underflow");
    }
}

fn global_drain_capacity() -> Arc<DrainCapacity> {
    static CAPACITY: OnceLock<Arc<DrainCapacity>> = OnceLock::new();
    Arc::clone(
        CAPACITY.get_or_init(|| Arc::new(DrainCapacity::new(DOCKER_OUTPUT_DRAIN_WORKERS_MAX))),
    )
}

fn run_command_bounded(command: &mut Command) -> Option<std::process::Output> {
    run_command_bounded_with(command, DOCKER_COMMAND_TIMEOUT, DOCKER_OUTPUT_MAX_BYTES)
}

fn run_command_bounded_with(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
) -> Option<std::process::Output> {
    run_command_bounded_with_capacity(command, timeout, output_max_bytes, &global_drain_capacity())
}

fn run_command_bounded_with_capacity(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
    drain_capacity: &Arc<DrainCapacity>,
) -> Option<std::process::Output> {
    let [stdout_permit, stderr_permit] = drain_capacity.reserve_pair()?;
    let mut child = match command
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

    let Some(stdout) = child.stdout.take() else {
        terminate_and_reap(&mut child);
        debug!("docker CLI stdout pipe was unavailable");
        return None;
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_and_reap(&mut child);
        debug!("docker CLI stderr pipe was unavailable");
        return None;
    };
    let stdout_worker = match spawn_output_drain(
        "kickoutchi-docker-stdout",
        stdout,
        output_max_bytes,
        stdout_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            terminate_and_reap(&mut child);
            debug!(%error, "docker CLI stdout drain worker failed to start");
            return None;
        }
    };
    let stderr_worker = match spawn_output_drain(
        "kickoutchi-docker-stderr",
        stderr,
        output_max_bytes,
        stderr_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            // The stdout worker is detached by design; killing the child
            // closed its pipe, so the worker exits on its own.
            terminate_and_reap(&mut child);
            debug!(%error, "docker CLI stderr drain worker failed to start");
            return None;
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                terminate_and_reap(&mut child);
                let _ = finish_output_drain(&stdout_worker, "stdout");
                let _ = finish_output_drain(&stderr_worker, "stderr");
                debug!("docker CLI timed out during port enrichment");
                return None;
            }
            Err(error) => {
                terminate_and_reap(&mut child);
                let _ = finish_output_drain(&stdout_worker, "stdout");
                let _ = finish_output_drain(&stderr_worker, "stderr");
                debug!(%error, "docker CLI wait failed during port enrichment");
                return None;
            }
        }
    };

    let stdout = finish_output_drain(&stdout_worker, "stdout")?;
    let stderr = finish_output_drain(&stderr_worker, "stderr")?;
    if stdout.exceeded || stderr.exceeded {
        debug!(
            stdout_exceeded = stdout.exceeded,
            stderr_exceeded = stderr.exceeded,
            "docker CLI output exceeded enrichment cap",
        );
        return None;
    }
    Some(std::process::Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

/// Spawn a detached worker that drains one output pipe while the child runs.
///
/// The worker reports through a channel instead of a `JoinHandle` so the
/// parent can bound its wait: `read` on the pipe only returns once every
/// holder of the write end has closed it, and a grandchild that inherited the
/// fd can outlive the docker CLI itself, turning a `join` into an unbounded
/// hang. A worker that misses `DOCKER_OUTPUT_DRAIN_TIMEOUT` is abandoned and
/// exits on its own once the pipe finally closes; each enrichment attempt
/// remains charged against the global worker cap until its pipe closes.
fn spawn_output_drain<Reader>(
    name: &'static str,
    reader: Reader,
    output_max_bytes: usize,
    permit: DrainPermit,
) -> io::Result<mpsc::Receiver<io::Result<BoundedOutput>>>
where
    Reader: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _permit = permit;
            // A failed send only means the parent gave up waiting; the result is
            // discarded either way, so there is nothing to handle.
            let _ = sender.send(read_output_bounded(reader, output_max_bytes));
        })?;
    Ok(receiver)
}

fn read_output_bounded(
    mut reader: impl Read,
    output_max_bytes: usize,
) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(output_max_bytes);
    let mut exceeded = false;
    let mut chunk = [0_u8; DOCKER_OUTPUT_READ_CHUNK_BYTES];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = output_max_bytes.saturating_sub(bytes.len());
        let retained = count.min(remaining);
        bytes.extend_from_slice(&chunk[..retained]);
        exceeded |= retained < count;
    }
    Ok(BoundedOutput { bytes, exceeded })
}

fn finish_output_drain(
    worker: &mpsc::Receiver<io::Result<BoundedOutput>>,
    stream: &'static str,
) -> Option<BoundedOutput> {
    match worker.recv_timeout(DOCKER_OUTPUT_DRAIN_TIMEOUT) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(error)) => {
            debug!(%error, stream, "docker CLI output drain failed");
            None
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            debug!(
                stream,
                "docker CLI output drain timed out; abandoning the drain worker",
            );
            None
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            debug!(
                stream,
                "docker CLI output drain worker died before reporting"
            );
            None
        }
    }
}

fn terminate_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
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
    use std::io::{self, Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        DOCKER_OUTPUT_MAX_BYTES, DrainCapacity, TEST_ELEVATION_OVERRIDE,
        docker_container_ls_with_runner, docker_context_from_ps_output, finish_output_drain,
        host_addr_matches, looks_like_docker_owner, parse_published_ports, read_output_bounded,
        run_command_bounded_with, run_command_bounded_with_capacity, should_try_docker_enrichment,
        spawn_output_drain,
    };
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    #[cfg(target_os = "linux")]
    use super::{TEST_LINUX_ELEVATION_SOURCES, linux_status_has_capabilities};

    const LARGE_OUTPUT_HELPER_ENV: &str = "KICKOUTCHI_TEST_DOCKER_LARGE_OUTPUT";
    const INHERITED_PIPE_PARENT_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_PARENT";
    const INHERITED_PIPE_GRANDCHILD_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_GRANDCHILD";

    struct ChannelReader(std::sync::mpsc::Receiver<()>);

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_capability_status_is_fail_closed_and_detects_active_authority() {
        let ordinary =
            "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        assert_eq!(linux_status_has_capabilities(ordinary), Some(false));

        let privileged =
            "CapPrm:\t0000000000000000\nCapEff:\t0000000000000400\nCapAmb:\t0000000000000000\n";
        assert_eq!(linux_status_has_capabilities(privileged), Some(true));

        assert_eq!(linux_status_has_capabilities("CapEff:\t0\n"), None);
        assert_eq!(
            linux_status_has_capabilities("CapPrm:\txyz\nCapEff:\t0\nCapAmb:\t0\n"),
            None,
        );
    }

    impl Read for ChannelReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

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
    fn helper_writes_more_than_one_typical_pipe_buffer() {
        if std::env::var_os(LARGE_OUTPUT_HELPER_ENV).is_none() {
            return;
        }
        let bytes = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES / 2];
        std::io::stdout()
            .write_all(&bytes)
            .expect("large-output helper stdout must be writable");
        std::io::stderr()
            .write_all(&bytes)
            .expect("large-output helper stderr must be writable");
    }

    #[test]
    fn helper_leaves_grandchild_holding_output_pipes() {
        if std::env::var_os(INHERITED_PIPE_PARENT_ENV).is_none() {
            return;
        }
        let executable = std::env::current_exe().expect("test binary must resolve");
        let mut grandchild = Command::new(executable)
            .env_remove(INHERITED_PIPE_PARENT_ENV)
            .env(INHERITED_PIPE_GRANDCHILD_ENV, "1")
            .args([
                "--exact",
                "docker::tests::helper_holds_inherited_output_pipes",
                "--nocapture",
            ])
            .spawn()
            .expect("grandchild test helper must start");
        thread::spawn(move || {
            let _ = grandchild.wait();
        });
    }

    #[test]
    fn helper_holds_inherited_output_pipes() {
        if std::env::var_os(INHERITED_PIPE_GRANDCHILD_ENV).is_none() {
            return;
        }
        thread::sleep(Duration::from_secs(2));
    }

    #[test]
    fn stdout_and_stderr_are_drained_while_the_child_is_running() {
        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.env(LARGE_OUTPUT_HELPER_ENV, "1").args([
            "--exact",
            "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
            "--nocapture",
        ]);

        let output = run_command_bounded_with(
            &mut command,
            Duration::from_secs(10),
            DOCKER_OUTPUT_MAX_BYTES,
        )
        .expect("a child writing below the cap must not block on a full pipe");

        assert!(output.status.success());
        assert!(
            output.stdout.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
            "the helper's pipe-sized output was not fully drained",
        );
        assert!(
            output.stderr.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
            "the helper's pipe-sized stderr was not fully drained",
        );
    }

    #[test]
    fn elevated_enrichment_does_not_execute_docker() {
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(Some(true)));
        let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
            panic!("elevated enrichment must not execute a PATH-resolved command")
        });
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(None));

        assert!(output.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_only_elevation_blocks_the_real_docker_command_gate() {
        TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(Some((false, false, true))));
        let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
            panic!("Linux capabilities must block PATH-resolved Docker execution")
        });
        TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(None));

        assert!(output.is_none());
    }

    #[test]
    fn drain_capacity_is_bounded_and_recovers_when_workers_exit() {
        let capacity = Arc::new(DrainCapacity::new(2));
        let [first_permit, second_permit] =
            capacity.reserve_pair().expect("two slots are available");
        let (first_sender, first_reader) = std::sync::mpsc::channel();
        let (second_sender, second_reader) = std::sync::mpsc::channel();
        let first_worker = spawn_output_drain(
            "kickoutchi-test-drain-one",
            ChannelReader(first_reader),
            1,
            first_permit,
        )
        .expect("first drain starts");
        let second_worker = spawn_output_drain(
            "kickoutchi-test-drain-two",
            ChannelReader(second_reader),
            1,
            second_permit,
        )
        .expect("second drain starts");

        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.args([
            "--exact",
            "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
        ]);
        assert!(
            run_command_bounded_with_capacity(&mut command, Duration::from_secs(1), 1, &capacity,)
                .is_none(),
            "a command must not start while both drain slots are occupied",
        );
        assert_eq!(capacity.active.load(Ordering::Acquire), 2);

        drop(first_sender);
        drop(second_sender);
        finish_output_drain(&first_worker, "first").expect("first drain exits");
        finish_output_drain(&second_worker, "second").expect("second drain exits");
        let release_deadline = Instant::now() + Duration::from_secs(1);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
        assert!(capacity.reserve_pair().is_some());
    }

    #[test]
    fn inherited_grandchild_pipes_bound_latency_and_release_capacity() {
        let capacity = Arc::new(DrainCapacity::new(2));
        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.env(INHERITED_PIPE_PARENT_ENV, "1").args([
            "--exact",
            "docker::tests::helper_leaves_grandchild_holding_output_pipes",
            "--nocapture",
        ]);

        let started = Instant::now();
        assert!(
            run_command_bounded_with_capacity(
                &mut command,
                Duration::from_secs(5),
                DOCKER_OUTPUT_MAX_BYTES,
                &capacity,
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(capacity.active.load(Ordering::Acquire), 2);

        let release_deadline = Instant::now() + Duration::from_secs(3);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn drain_wait_is_bounded_when_the_worker_never_reports() {
        // A live sender that never sends models a drain worker stuck in
        // `read` on a pipe some grandchild still holds open. The wait must
        // give up on its own instead of blocking with the worker; a hang
        // here fails the test via the harness timeout rather than an assert.
        let (sender, receiver) = std::sync::mpsc::channel();

        let started = Instant::now();
        let output = finish_output_drain(&receiver, "stdout");
        let elapsed = started.elapsed();

        assert!(
            output.is_none(),
            "a drain that never completed must not produce output",
        );
        assert!(
            elapsed >= Duration::from_millis(200),
            "returned early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(750),
            "wait was not bounded: {elapsed:?}"
        );
        drop(sender);
    }

    #[test]
    fn output_reader_retains_the_cap_and_drains_the_rest() {
        let input = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES + 1];

        let output = read_output_bounded(Cursor::new(input), DOCKER_OUTPUT_MAX_BYTES)
            .expect("in-memory output read must succeed");

        assert_eq!(output.bytes.len(), DOCKER_OUTPUT_MAX_BYTES);
        assert!(output.exceeded);
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
