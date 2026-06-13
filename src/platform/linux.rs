//! Linux `/proc` collector.
//!
//! This collector intentionally reads kernel-provided `/proc` files directly
//! instead of shelling out to `ss`, `lsof`, or `netstat`. Socket table parsing
//! and process metadata enrichment are kept in this module so Linux-specific
//! formats never leak into the shared CLI or TUI code.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::collector::{Collector, CollectorError};
use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

const PROC_ROOT: &str = "/proc";
const TCP_LISTEN_STATE: &str = "0A";
const MAX_CMDLINE_BYTES: usize = 16 * 1024;
const MAX_CMDLINE_READ_BYTES: u64 = 16 * 1024 + 1;
const SOCKET_LINK_PREFIX: &str = "socket:[";
const SOCKET_LINK_SUFFIX: &str = "]";

/// Linux implementation of the collector contract.
pub(crate) struct LinuxCollector {
    proc_root: PathBuf,
}

impl LinuxCollector {
    pub(crate) fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
        }
    }

    #[cfg(test)]
    fn with_proc_root(proc_root: PathBuf) -> Self {
        Self { proc_root }
    }
}

impl Collector for LinuxCollector {
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError> {
        let records = collect_socket_records(&self.proc_root)?;
        let owners = collect_socket_owners(&self.proc_root)?;

        let mut entries = Vec::with_capacity(records.len());
        for record in records {
            let pid = owners.get(&record.inode).copied();
            entries.push(entry_from_record(&record, pid, &self.proc_root));
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Copy)]
struct SocketTable {
    relative_path: &'static str,
    protocol: Protocol,
    address_family: AddressFamily,
    optional: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: SocketState,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SocketParseError {
    #[error("missing field {field}")]
    MissingField { field: &'static str },
    #[error("local address must be ADDRESS:PORT, got {value}")]
    MalformedLocalAddress { value: String },
    #[error("invalid IPv4 address {value}")]
    InvalidIpv4Address { value: String },
    #[error("invalid IPv6 address {value}")]
    InvalidIpv6Address { value: String },
    #[error("invalid port {value}")]
    InvalidPort { value: String },
    #[error("invalid inode {value}")]
    InvalidInode { value: String },
}

#[derive(Debug, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    partial: bool,
}

fn collect_socket_records(proc_root: &Path) -> Result<Vec<SocketRecord>, CollectorError> {
    let tables = [
        SocketTable {
            relative_path: "net/tcp",
            protocol: Protocol::Tcp,
            address_family: AddressFamily::Ipv4,
            optional: false,
        },
        SocketTable {
            relative_path: "net/tcp6",
            protocol: Protocol::Tcp,
            address_family: AddressFamily::Ipv6,
            optional: true,
        },
        SocketTable {
            relative_path: "net/udp",
            protocol: Protocol::Udp,
            address_family: AddressFamily::Ipv4,
            optional: false,
        },
        SocketTable {
            relative_path: "net/udp6",
            protocol: Protocol::Udp,
            address_family: AddressFamily::Ipv6,
            optional: true,
        },
    ];

    let mut records = Vec::new();
    for table in tables {
        let path = proc_root.join(table.relative_path);
        let Some(text) = read_socket_table(&path, table.optional)? else {
            continue;
        };
        records.extend(parse_socket_table(
            &text,
            table.protocol,
            table.address_family,
        ));
    }
    Ok(records)
}

fn read_socket_table(path: &Path, optional: bool) -> Result<Option<String>, CollectorError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(source) if optional && source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CollectorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn parse_socket_table(
    text: &str,
    protocol: Protocol,
    address_family: AddressFamily,
) -> Vec<SocketRecord> {
    let mut records = Vec::new();
    for (line_index, line) in text.lines().enumerate().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        match parse_socket_line(line, protocol, address_family) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(line = line_index + 1, %error, "skipping malformed /proc/net row");
            }
        }
    }
    records
}

fn parse_socket_line(
    line: &str,
    protocol: Protocol,
    address_family: AddressFamily,
) -> Result<Option<SocketRecord>, SocketParseError> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let local = *fields.get(1).ok_or(SocketParseError::MissingField {
        field: "local_address",
    })?;
    let state_hex = *fields
        .get(3)
        .ok_or(SocketParseError::MissingField { field: "st" })?;
    let inode_hex = *fields
        .get(9)
        .ok_or(SocketParseError::MissingField { field: "inode" })?;

    if protocol == Protocol::Tcp && state_hex != TCP_LISTEN_STATE {
        return Ok(None);
    }

    let (addr_hex, port_hex) =
        local
            .split_once(':')
            .ok_or_else(|| SocketParseError::MalformedLocalAddress {
                value: local.to_owned(),
            })?;
    let local_addr = decode_addr(addr_hex, address_family)?;
    let local_port =
        u16::from_str_radix(port_hex, 16).map_err(|_| SocketParseError::InvalidPort {
            value: port_hex.to_owned(),
        })?;
    let inode = inode_hex
        .parse::<u64>()
        .map_err(|_| SocketParseError::InvalidInode {
            value: inode_hex.to_owned(),
        })?;
    let state = match protocol {
        Protocol::Tcp => SocketState::Listen,
        Protocol::Udp => SocketState::Bound,
    };

    Ok(Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        inode,
    }))
}

fn decode_addr(hex: &str, address_family: AddressFamily) -> Result<IpAddr, SocketParseError> {
    match address_family {
        AddressFamily::Ipv4 => decode_ipv4_addr(hex).map(IpAddr::V4),
        AddressFamily::Ipv6 => decode_ipv6_addr(hex),
    }
}

fn decode_ipv4_addr(hex: &str) -> Result<Ipv4Addr, SocketParseError> {
    if hex.len() != 8 {
        return Err(SocketParseError::InvalidIpv4Address {
            value: hex.to_owned(),
        });
    }
    let raw = u32::from_str_radix(hex, 16).map_err(|_| SocketParseError::InvalidIpv4Address {
        value: hex.to_owned(),
    })?;
    Ok(Ipv4Addr::from(raw.to_le_bytes()))
}

fn decode_ipv6_addr(hex: &str) -> Result<IpAddr, SocketParseError> {
    if hex.len() != 32 {
        return Err(SocketParseError::InvalidIpv6Address {
            value: hex.to_owned(),
        });
    }

    let mut bytes = [0_u8; 16];
    for chunk_index in 0..4 {
        let start = chunk_index * 8;
        let end = start + 8;
        let chunk = hex
            .get(start..end)
            .ok_or_else(|| SocketParseError::InvalidIpv6Address {
                value: hex.to_owned(),
            })?;
        let word =
            u32::from_str_radix(chunk, 16).map_err(|_| SocketParseError::InvalidIpv6Address {
                value: hex.to_owned(),
            })?;
        bytes[start / 2..start / 2 + 4].copy_from_slice(&word.to_le_bytes());
    }

    let addr = Ipv6Addr::from(bytes);
    if let Some(mapped) = addr.to_ipv4_mapped() {
        Ok(IpAddr::V4(mapped))
    } else {
        Ok(IpAddr::V6(addr))
    }
}

fn collect_socket_owners(proc_root: &Path) -> Result<BTreeMap<u64, u32>, CollectorError> {
    let mut pids = Vec::new();
    let proc_entries = fs::read_dir(proc_root).map_err(|source| CollectorError::Read {
        path: proc_root.to_path_buf(),
        source,
    })?;

    for entry in proc_entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        pids.push(pid);
    }
    pids.sort_unstable();

    let mut owners = BTreeMap::new();
    for pid in pids {
        collect_pid_socket_owners(proc_root, pid, &mut owners);
    }
    Ok(owners)
}

fn collect_pid_socket_owners(proc_root: &Path, pid: u32, owners: &mut BTreeMap<u64, u32>) {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let Ok(fd_entries) = fs::read_dir(fd_dir) else {
        return;
    };

    for entry in fd_entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let Some(inode) = parse_socket_inode(&target) else {
            continue;
        };
        owners.entry(inode).or_insert(pid);
    }
}

fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_str()?;
    let inode = text
        .strip_prefix(SOCKET_LINK_PREFIX)?
        .strip_suffix(SOCKET_LINK_SUFFIX)?;
    inode.parse::<u64>().ok()
}

fn entry_from_record(record: &SocketRecord, pid: Option<u32>, proc_root: &Path) -> PortEntry {
    let metadata = pid.map(|pid| read_process_metadata(proc_root, pid));
    let permission = if pid.is_none() || metadata.as_ref().is_some_and(|metadata| metadata.partial)
    {
        PermissionStatus::Partial
    } else {
        PermissionStatus::Full
    };

    PortEntry {
        protocol: record.protocol,
        local_addr: record.local_addr,
        local_port: record.local_port,
        state: record.state,
        pid,
        process_name: metadata
            .as_ref()
            .and_then(|metadata| metadata.process_name.clone()),
        executable_path: metadata
            .as_ref()
            .and_then(|metadata| metadata.executable_path.clone()),
        command_line: metadata
            .as_ref()
            .and_then(|metadata| metadata.command_line.clone()),
        parent_pid: None,
        parent_process_name: None,
        child_pids: Vec::new(),
        protected: false,
        platform: Platform::Linux,
        permission,
    }
}

fn read_process_metadata(proc_root: &Path, pid: u32) -> ProcessMetadata {
    let process_dir = proc_root.join(pid.to_string());
    let mut metadata = ProcessMetadata::default();

    match fs::read_to_string(process_dir.join("comm")) {
        Ok(text) => {
            metadata.process_name = trimmed_non_empty(&text);
            metadata.partial |= metadata.process_name.is_none();
        }
        Err(_) => metadata.partial = true,
    }

    match read_cmdline(&process_dir.join("cmdline")) {
        Ok((command_line, truncated)) => {
            metadata.command_line = command_line;
            metadata.partial |= truncated;
        }
        Err(_) => metadata.partial = true,
    }

    match fs::read_link(process_dir.join("exe")) {
        Ok(path) => metadata.executable_path = Some(path),
        Err(_) => metadata.partial = true,
    }

    metadata
}

fn trimmed_non_empty(text: &str) -> Option<String> {
    let trimmed = text.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn read_cmdline(path: &Path) -> std::io::Result<(Option<String>, bool)> {
    let file = File::open(path)?;
    let mut reader = file.take(MAX_CMDLINE_READ_BYTES);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;

    let truncated = bytes.len() > MAX_CMDLINE_BYTES;
    if truncated {
        bytes.truncate(MAX_CMDLINE_BYTES);
    }

    Ok((decode_cmdline(&bytes), truncated))
}

fn decode_cmdline(bytes: &[u8]) -> Option<String> {
    let parts: Vec<String> = bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};

    use super::{
        AddressFamily, LinuxCollector, SocketParseError, SocketRecord, collect_socket_owners,
        collect_socket_records, decode_cmdline, entry_from_record, parse_socket_inode,
        parse_socket_line, parse_socket_table,
    };
    use crate::collector::Collector;
    use crate::model::{PermissionStatus, Protocol, SocketState};

    const HEADER: &str =
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";

    fn row(local: &str, state: &str, inode: u64) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 00:00000000 00000000 1000 0 {inode} 1 0000000000000000 100 0 0 10 0"
        )
    }

    fn temp_proc_root(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("kickoutchi-linux-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(path.join("net")).expect("test proc net directory must be created");
        path
    }

    fn write_socket_table(proc_root: &Path, relative_path: &str, rows: &[String]) {
        let text = format!("{HEADER}\n{}\n", rows.join("\n"));
        fs::write(proc_root.join(relative_path), text).expect("test socket table must be written");
    }

    #[test]
    fn parses_ipv4_tcp_listen_rows() {
        let record = parse_socket_line(
            &row("0100007F:0BB8", "0A", 12_345),
            Protocol::Tcp,
            AddressFamily::Ipv4,
        )
        .expect("valid row")
        .expect("listen row is kept");

        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
        assert_eq!(record.state, SocketState::Listen);
        assert_eq!(record.inode, 12_345);
    }

    #[test]
    fn ignores_non_listening_tcp_rows() {
        let record = parse_socket_line(
            &row("0100007F:0BB8", "01", 12_345),
            Protocol::Tcp,
            AddressFamily::Ipv4,
        )
        .expect("valid row");

        assert_eq!(record, None);
    }

    #[test]
    fn parses_udp_rows_as_bound_sockets() {
        let record = parse_socket_line(
            &row("00000000:14E9", "07", 902),
            Protocol::Udp,
            AddressFamily::Ipv4,
        )
        .expect("valid row")
        .expect("udp row is kept");

        assert_eq!(record.protocol, Protocol::Udp);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(record.local_port, 5353);
        assert_eq!(record.state, SocketState::Bound);
    }

    #[test]
    fn decodes_ipv6_loopback_rows() {
        let record = parse_socket_line(
            &row("00000000000000000000000001000000:1F90", "0A", 55),
            Protocol::Tcp,
            AddressFamily::Ipv6,
        )
        .expect("valid row")
        .expect("listen row is kept");

        assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(record.local_port, 8080);
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6_rows() {
        let record = parse_socket_line(
            &row("0000000000000000FFFF00000100007F:0BB8", "0A", 55),
            Protocol::Tcp,
            AddressFamily::Ipv6,
        )
        .expect("valid row")
        .expect("listen row is kept");

        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
    }

    #[test]
    fn missing_ipv6_socket_tables_do_not_block_ipv4_collection() {
        let proc_root = temp_proc_root("missing-ipv6");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 1)]);
        write_socket_table(&proc_root, "net/udp", &[row("00000000:14E9", "07", 2)]);

        let records = collect_socket_records(&proc_root).expect("missing tcp6/udp6 is allowed");

        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|record| record.local_port == 3000));
        assert!(records.iter().any(|record| record.local_port == 5353));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn missing_ipv4_socket_tables_still_fail_collection() {
        let proc_root = temp_proc_root("missing-ipv4");

        let error = collect_socket_records(&proc_root).expect_err("missing tcp table must fail");

        assert!(error.to_string().contains("net/tcp"), "{error}");
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn rejects_malformed_rows_with_specific_errors() {
        let missing = parse_socket_line("0:", Protocol::Tcp, AddressFamily::Ipv4)
            .expect_err("missing fields must be rejected");
        assert_eq!(
            missing,
            SocketParseError::MissingField {
                field: "local_address"
            }
        );

        let malformed = parse_socket_line(
            &row("not-an-address", "0A", 1),
            Protocol::Tcp,
            AddressFamily::Ipv4,
        )
        .expect_err("missing address separator must be rejected");
        assert_eq!(
            malformed,
            SocketParseError::MalformedLocalAddress {
                value: "not-an-address".to_owned(),
            }
        );

        let bad_port = parse_socket_line(
            &row("0100007F:ZZZZ", "0A", 1),
            Protocol::Tcp,
            AddressFamily::Ipv4,
        )
        .expect_err("bad port must be rejected");
        assert_eq!(
            bad_port,
            SocketParseError::InvalidPort {
                value: "ZZZZ".to_owned(),
            }
        );
    }

    #[test]
    fn table_parser_keeps_valid_rows_and_skips_malformed_rows() {
        let text = format!(
            "{HEADER}\n{}\nnot enough fields\n{}\n",
            row("0100007F:0BB8", "0A", 1),
            row("0100007F:1770", "01", 2),
        );
        let records = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].local_port, 3000);
    }

    #[test]
    fn socket_inode_is_extracted_from_fd_symlink_targets() {
        assert_eq!(
            parse_socket_inode(Path::new("socket:[12345]")),
            Some(12_345)
        );
        assert_eq!(parse_socket_inode(Path::new("/tmp/file")), None);
        assert_eq!(parse_socket_inode(Path::new("socket:[]")), None);
    }

    #[test]
    fn command_line_decoding_joins_nul_separated_arguments() {
        assert_eq!(
            decode_cmdline(b"python3\0-m\0http.server\x003000\0"),
            Some("python3 -m http.server 3000".to_owned())
        );
        assert_eq!(decode_cmdline(b""), None);
        assert_eq!(decode_cmdline(b"\0\0"), None);
    }

    #[test]
    fn missing_process_metadata_produces_partial_rows_without_dropping_the_port() {
        let record = SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            inode: 1,
        };

        let entry = entry_from_record(
            &record,
            Some(1234),
            Path::new("/definitely-not-a-real-kickoutchi-proc-root"),
        );

        assert_eq!(entry.pid, Some(1234));
        assert_eq!(entry.process_name, None);
        assert_eq!(entry.executable_path, None);
        assert_eq!(entry.command_line, None);
        assert_eq!(entry.permission, PermissionStatus::Partial);
    }

    #[test]
    fn missing_proc_root_is_a_collection_error() {
        let collector = LinuxCollector::with_proc_root(PathBuf::from(
            "/definitely-not-a-real-kickoutchi-proc-root",
        ));

        let error = collector
            .collect()
            .expect_err("missing proc root must fail");
        assert!(error.to_string().contains("cannot read"), "{error}");
    }

    #[test]
    fn socket_owner_collection_requires_a_readable_proc_root() {
        let error = collect_socket_owners(Path::new("/definitely-not-a-real-kickoutchi-proc-root"))
            .expect_err("missing proc root must fail");

        assert!(error.to_string().contains("cannot read"), "{error}");
    }
}
