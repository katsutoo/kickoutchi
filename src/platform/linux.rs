//! The Linux `/proc` collector.
//!
//! This reads kernel-provided `/proc` files straight from disk on purpose,
//! rather than shelling out to `ss`, `lsof`, or `netstat`. All the socket-table
//! parsing and process-metadata digging stays in here, so Linux's particular
//! file formats never leak out into the shared CLI or TUI code.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
    Protocol, RelatedProcessHint, SocketState,
};
use crate::process::{
    TreeDeliveryHandle, tree_cont, tree_cont_handle, tree_deliver_handle,
    tree_open_delivery_handle, tree_stop_handle,
};
use crate::tree::{TreeProcessInfo, TreeProcessOps, TreeSignalResult};

const PROC_ROOT: &str = "/proc";
const TCP_LISTEN_STATE: &str = "0A";
// `/proc/net/{tcp,udp}{,6}` is one row per socket and read on every refresh, so
// it's bounded like every other /proc read here. The cap is deliberately generous
// (~100k sockets), but a socket table is the one /proc file we must not silently
// truncate: dropping bytes drops whole socket rows, i.e. real open ports. So
// `read_bounded_text` fails closed past this cap — the scan surfaces a clear
// error instead of a short, misleading table.
const MAX_SOCKET_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CMDLINE_BYTES: usize = 16 * 1024;
const MAX_CMDLINE_READ_BYTES: u64 = 16 * 1024 + 1;
// `/proc/<pid>/status` is kernel-generated and small, but we read it on every
// refresh, so we bound it like every other /proc read here. `PPid` lives near
// the top of the file, comfortably inside this cap, so the limit can never chop
// off the field the collector actually wants.
const MAX_STATUS_BYTES: u64 = 8 * 1024;
const MAX_STAT_BYTES: u64 = 4 * 1024;
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;
const SOCKET_LINK_PREFIX: &str = "socket:[";
const SOCKET_LINK_SUFFIX: &str = "]";

/// The Linux end of the collector contract.
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
        let target_inodes: HashSet<u64> = records.iter().map(|record| record.inode).collect();
        let owners = collect_socket_owners(&self.proc_root, &target_inodes)?;

        let mut entries = Vec::with_capacity(records.len());
        for record in records {
            match owners.get(&record.inode) {
                Some(pids) if !pids.is_empty() => {
                    for pid in pids {
                        entries.push(entry_from_record(&record, Some(*pid), &self.proc_root));
                    }
                }
                _ => entries.push(entry_from_record(&record, None, &self.proc_root)),
            }
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
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    partial: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct ProcessStatus {
    parent_pid: Option<u32>,
    owner_uid: Option<u32>,
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    collect_process_context_from(&PathBuf::from(PROC_ROOT), pid)
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    collect_related_process_hints_from(&PathBuf::from(PROC_ROOT), port)
}

/// Best-effort command line for one PID, for the read-only inspect view.
/// `None` covers vanished, restricted, and kernel processes alike — inspect
/// renders it as unknown rather than failing the report.
pub(crate) fn process_command_line(pid: u32) -> Option<String> {
    let path = PathBuf::from(PROC_ROOT)
        .join(pid.to_string())
        .join("cmdline");
    read_cmdline(&path)
        .ok()
        .and_then(|(command_line, _)| command_line)
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
    match read_bounded_text(path, MAX_SOCKET_TABLE_BYTES) {
        Ok(text) => Ok(Some(text)),
        Err(source) if optional && source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CollectorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_bounded_text(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let limit = u64::try_from(max_bytes)
        .expect("/proc read byte limit must fit in u64")
        .saturating_add(1);
    let mut text = String::new();
    File::open(path)?.take(limit).read_to_string(&mut text)?;
    if text.len() > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} byte read limit"),
        ));
    }
    Ok(text)
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
    Ok(Ipv4Addr::from(raw.to_ne_bytes()))
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
        bytes[start / 2..start / 2 + 4].copy_from_slice(&word.to_ne_bytes());
    }

    let addr = Ipv6Addr::from(bytes);
    if let Some(mapped) = addr.to_ipv4_mapped() {
        Ok(IpAddr::V4(mapped))
    } else {
        Ok(IpAddr::V6(addr))
    }
}

fn collect_socket_owners(
    proc_root: &Path,
    target_inodes: &HashSet<u64>,
) -> Result<HashMap<u64, Vec<u32>>, CollectorError> {
    if target_inodes.is_empty() {
        return Ok(HashMap::new());
    }

    let pids = process_ids(proc_root).map_err(|source| CollectorError::Read {
        path: proc_root.to_path_buf(),
        source,
    })?;

    // Walk every PID's file descriptors, no early exit. A single listening socket
    // can be shared by several processes (a parent that bound it then forked,
    // inherited fds, SO_REUSEPORT), so one inode can have several owners. Bailing
    // out the moment each inode has *an* owner would collapse those down to one
    // arbitrary PID — and then `kill --port` would signal one process while the
    // others happily keep the port open. Correctness wins over the fd walks we'd
    // save. If this scan ever becomes the refresh bottleneck on a huge host, the
    // fix is netlink `sock_diag`, not a correctness-breaking early stop.
    let mut owners = HashMap::with_capacity(target_inodes.len());
    for pid in pids {
        collect_pid_socket_owners(proc_root, pid, target_inodes, &mut owners);
    }
    Ok(owners)
}

fn process_ids(proc_root: &Path) -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir(proc_root)? {
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
    Ok(pids)
}

fn collect_pid_socket_owners(
    proc_root: &Path,
    pid: u32,
    target_inodes: &HashSet<u64>,
    owners: &mut HashMap<u64, Vec<u32>>,
) {
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
        if !target_inodes.contains(&inode) {
            continue;
        }
        let pids = owners.entry(inode).or_default();
        if !pids.contains(&pid) {
            pids.push(pid);
        }
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
        parent_pid: metadata.as_ref().and_then(|metadata| metadata.parent_pid),
        parent_process_name: metadata
            .as_ref()
            .and_then(|metadata| metadata.parent_process_name.clone()),
        child_pids: Vec::new(),
        protected: false,
        platform: Platform::Linux,
        permission,
    }
}

fn read_process_metadata(proc_root: &Path, pid: u32) -> ProcessMetadata {
    let process_dir = proc_root.join(pid.to_string());
    let mut metadata = ProcessMetadata::default();

    match read_process_name(&process_dir) {
        Ok(name) => {
            metadata.process_name = name;
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

    match read_process_status(&process_dir.join("status")) {
        Ok(ProcessStatus {
            parent_pid: Some(parent_pid),
            ..
        }) => {
            metadata.parent_pid = Some(parent_pid);
            if parent_pid != 0 {
                match read_process_name(&proc_root.join(parent_pid.to_string())) {
                    Ok(name) => {
                        metadata.parent_process_name = name;
                        metadata.partial |= metadata.parent_process_name.is_none();
                    }
                    Err(_) => metadata.partial = true,
                }
            }
        }
        Ok(ProcessStatus {
            parent_pid: None, ..
        })
        | Err(_) => metadata.partial = true,
    }

    metadata
}

fn collect_process_context_from(proc_root: &Path, pid: u32) -> ProcessContext {
    let process_dir = proc_root.join(pid.to_string());
    let owner_uid = read_process_status(&process_dir.join("status"))
        .ok()
        .and_then(|status| status.owner_uid);
    let process_start_time_marker = read_process_start_time_ticks(&process_dir.join("stat")).ok();
    ProcessContext {
        owner_uid,
        process_start_time_marker,
        children: collect_child_processes_from(proc_root, pid),
        docker: None,
    }
}

fn collect_child_processes_from(proc_root: &Path, parent_pid: u32) -> ChildProcessSnapshot {
    let Ok(pids) = process_ids(proc_root) else {
        return ChildProcessSnapshot::default();
    };

    let mut children = Vec::new();
    let mut truncated = false;
    for pid in pids {
        if pid == parent_pid {
            continue;
        }
        let process_dir = proc_root.join(pid.to_string());
        let Ok(status) = read_process_status(&process_dir.join("status")) else {
            continue;
        };
        if status.parent_pid != Some(parent_pid) {
            continue;
        }

        if children.len() == MAX_CHILD_PROCESSES {
            truncated = true;
            break;
        }
        let process_name = read_process_name(&process_dir).ok().flatten();
        children.push(ChildProcess { pid, process_name });
    }

    ChildProcessSnapshot {
        children,
        truncated,
    }
}

fn collect_related_process_hints_from(proc_root: &Path, port: u16) -> Vec<RelatedProcessHint> {
    let Ok(pids) = process_ids(proc_root) else {
        return Vec::new();
    };
    let current_pid = std::process::id();
    let excluded_pids = process_ancestor_pids_from(proc_root, current_pid);
    let mut hints = Vec::new();

    for pid in pids {
        if excluded_pids.contains(&pid) {
            continue;
        }
        let process_dir = proc_root.join(pid.to_string());
        let Ok((Some(command_line), _truncated)) = read_cmdline(&process_dir.join("cmdline"))
        else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }

        let process_name = read_process_name(&process_dir).ok().flatten();
        hints.push(RelatedProcessHint {
            pid,
            process_name,
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }

    hints
}

/// The Linux end of the process-tree I/O contract.
///
/// Snapshots come from a single `/proc` scan; signal delivery goes through the
/// `process` module's `libc` boundary. Every snapshot is a fresh read, which is
/// exactly what the freeze-first sweep relies on. The one thing held between
/// calls is deliberate state: the per-member pidfds opened before each
/// `SIGSTOP`, making the root and every descendant reuse-proof from the first
/// freeze signal through final delivery and thaw.
pub(crate) struct LinuxTreeOps {
    proc_root: PathBuf,
    delivery_handles: HashMap<u32, TreeDeliveryHandle>,
}

impl LinuxTreeOps {
    pub(crate) fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
            delivery_handles: HashMap::new(),
        }
    }
}

impl TreeProcessOps for LinuxTreeOps {
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        collect_tree_process_infos(&self.proc_root).map_err(|error| error.to_string())
    }

    fn pin_root_for_revalidation(&mut self, pid: u32) -> TreeSignalResult {
        // The verified marker is not known yet at pin time; the pidfd itself is
        // the reuse proof, so nothing is lost by passing None.
        self.prepare_delivery(pid, None)
    }

    fn stop(&mut self, pid: u32) -> TreeSignalResult {
        let handle = match self.delivery_handles.remove(&pid) {
            Some(handle) => handle,
            None => match tree_open_delivery_handle(pid) {
                Ok(handle) => handle,
                Err(result) => return result,
            },
        };
        let result = tree_stop_handle(&handle);
        if result == TreeSignalResult::Delivered {
            self.delivery_handles.insert(pid, handle);
        }
        result
    }

    fn cont(&mut self, pid: u32) {
        if let Some(handle) = self.delivery_handles.get(&pid) {
            let _ = tree_cont_handle(handle);
        } else {
            tree_cont(pid);
        }
    }

    // The verified start marker is unused on Linux: the pidfd opened before the
    // first stop already pins the process object, so delivery can never reach a
    // recycled PID regardless of markers.
    fn prepare_delivery(
        &mut self,
        pid: u32,
        _verified_start_marker: Option<u64>,
    ) -> TreeSignalResult {
        if self.delivery_handles.contains_key(&pid) {
            return TreeSignalResult::Delivered;
        }
        match tree_open_delivery_handle(pid) {
            Ok(handle) => {
                debug_assert_eq!(handle.pid(), pid);
                self.delivery_handles.insert(pid, handle);
                TreeSignalResult::Delivered
            }
            Err(result) => result,
        }
    }

    fn deliver(&mut self, pid: u32, mode: crate::process::KillMode) -> TreeSignalResult {
        let Some(handle) = self.delivery_handles.get(&pid) else {
            return TreeSignalResult::Denied;
        };
        tree_deliver_handle(handle, mode)
    }
}

/// Read one snapshot of the process table for scoped tree execution.
///
/// Reuses the same bounded `/proc` readers as the socket collector, so every
/// read here is capped exactly like the rest of the module. Fail-closed on
/// purpose: a process that vanished mid-scan (`NotFound`/`ESRCH`) is skipped, but a
/// live process whose name, parent, or start marker cannot be read is a hard
/// error — tree kill must never run against a table with holes in it, because
/// a missing parent edge silently drops that process's whole subtree.
fn collect_tree_process_infos(proc_root: &Path) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids(proc_root).map_err(|source| CollectorError::Read {
        path: proc_root.to_path_buf(),
        source,
    })?;

    let mut infos = Vec::with_capacity(pids.len());
    for pid in pids {
        let process_dir = proc_root.join(pid.to_string());
        let Some(status) = read_tree_status(&process_dir.join("status"))? else {
            continue;
        };
        let Some(process_name) = read_tree_process_name(&process_dir)? else {
            continue;
        };
        let Some(stat) = read_tree_stat(&process_dir.join("stat"))? else {
            continue;
        };
        infos.push(TreeProcessInfo {
            pid,
            parent_pid: status.parent_pid,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(process_name),
            start_time_marker: Some(stat.start_time_marker),
            owner_uid: status.owner_uid,
            process_group: stat.process_group,
        });
    }
    Ok(infos)
}

/// The two `stat` fields the tree snapshot carries, read in one pass.
struct TreeStat {
    start_time_marker: u64,
    process_group: Option<u32>,
}

fn read_tree_status(path: &Path) -> Result<Option<ProcessStatus>, CollectorError> {
    match read_process_status(path) {
        Ok(status) => Ok(Some(status)),
        Err(error) if process_vanished(&error) => Ok(None),
        Err(source) => Err(CollectorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn process_vanished(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn read_tree_process_name(process_dir: &Path) -> Result<Option<String>, CollectorError> {
    let path = process_dir.join("comm");
    match read_process_name(process_dir) {
        Ok(Some(name)) => Ok(Some(name)),
        Ok(None) => Err(CollectorError::Read {
            path,
            source: std::io::Error::new(ErrorKind::InvalidData, "empty process name"),
        }),
        Err(error) if process_vanished(&error) => Ok(None),
        Err(source) => Err(CollectorError::Read { path, source }),
    }
}

fn read_tree_stat(path: &Path) -> Result<Option<TreeStat>, CollectorError> {
    let text = match read_stat_text(path) {
        Ok(text) => text,
        Err(error) if process_vanished(&error) => return Ok(None),
        Err(source) => {
            return Err(CollectorError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    // Both fields are kill-safety data and fail closed: group kill derives its
    // membership from the group ID, so an unreadable group would be a silent
    // hole in the member set, exactly like a missing start marker would be a
    // hole in identity verification. Group 0 is the kernel's own group — never
    // a valid target — and maps to "no targetable group" rather than an error.
    let start_time_marker =
        parse_process_start_time_ticks(&text).map_err(|source| CollectorError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(process_group) = parse_process_group_id(&text) else {
        return Err(CollectorError::Read {
            path: path.to_path_buf(),
            source: std::io::Error::new(ErrorKind::InvalidData, "process group is unreadable"),
        });
    };
    Ok(Some(TreeStat {
        start_time_marker,
        process_group: (process_group != 0).then_some(process_group),
    }))
}

fn read_stat_text(path: &Path) -> std::io::Result<String> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_STAT_BYTES)
        .read_to_string(&mut text)?;
    Ok(text)
}

/// Process group ID from `/proc/<pid>/stat`: field 5 overall, so the third
/// token after the `") "` comm terminator (state, ppid, pgrp).
fn parse_process_group_id(text: &str) -> Option<u32> {
    let (_before_comm_end, after_comm_end) = text.rsplit_once(") ")?;
    after_comm_end
        .split_whitespace()
        .nth(2)?
        .parse::<u32>()
        .ok()
}

fn process_ancestor_pids_from(proc_root: &Path, pid: u32) -> HashSet<u32> {
    let mut ancestors = HashSet::from([pid]);
    let mut current = pid;
    for _ in 0..MAX_PROCESS_ANCESTORS {
        let process_dir = proc_root.join(current.to_string());
        let Some(parent_pid) = read_process_status(&process_dir.join("status"))
            .ok()
            .and_then(|status| status.parent_pid)
        else {
            break;
        };
        if !ancestors.insert(parent_pid) {
            break;
        }
        current = parent_pid;
    }
    ancestors
}

fn read_process_name(process_dir: &Path) -> std::io::Result<Option<String>> {
    fs::read_to_string(process_dir.join("comm")).map(|text| trimmed_non_empty(&text))
}

fn read_process_status(path: &Path) -> std::io::Result<ProcessStatus> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_STATUS_BYTES)
        .read_to_string(&mut text)?;
    parse_process_status(&text)
}

fn read_process_start_time_ticks(path: &Path) -> std::io::Result<u64> {
    let mut text = String::new();
    File::open(path)?
        .take(MAX_STAT_BYTES)
        .read_to_string(&mut text)?;
    parse_process_start_time_ticks(&text)
}

fn parse_process_start_time_ticks(text: &str) -> std::io::Result<u64> {
    // `/proc/<pid>/stat` is `pid (comm) state ...`, and comm is an unescaped task
    // name that can itself contain `)` and even `) `. Every field after comm is a
    // single char or an integer and holds no parens, so the *last* `") "` in the
    // line is always the real comm terminator. Splitting from the right is what
    // keeps this robust against a process named e.g. `ev) il`; a first/left split
    // would be fooled by a paren inside comm.
    let (_before_comm_end, after_comm_end) = text.rsplit_once(") ").ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidData, "missing process-name terminator")
    })?;
    // Once comm is stripped the fields are 1-indexed from `state` (field 3), so
    // start time (field 22) is the 20th token here — nth(19), zero-indexed.
    let start_time = after_comm_end
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing process start time"))?;
    start_time
        .parse::<u64>()
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))
}

fn parse_process_status(text: &str) -> std::io::Result<ProcessStatus> {
    let mut status = ProcessStatus::default();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("PPid:") {
            status.parent_pid = Some(parse_status_u32(value)?);
        } else if let Some(value) = line.strip_prefix("Uid:") {
            status.owner_uid = Some(parse_status_u32(value)?);
        }
    }
    Ok(status)
}

fn parse_status_u32(value: &str) -> std::io::Result<u32> {
    let first = value
        .split_whitespace()
        .next()
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing numeric value"))?;
    first
        .parse::<u32>()
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))
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
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};

    use super::{
        AddressFamily, LinuxCollector, MAX_CHILD_PROCESSES, SocketParseError, SocketRecord,
        collect_child_processes_from, collect_pid_socket_owners, collect_process_context_from,
        collect_related_process_hints_from, collect_socket_owners, collect_socket_records,
        collect_tree_process_infos, decode_cmdline, entry_from_record, parse_process_group_id,
        parse_process_start_time_ticks, parse_process_status, parse_socket_inode,
        parse_socket_line, parse_socket_table, read_bounded_text, read_process_status,
    };
    use crate::collector::Collector;
    use crate::model::{PermissionStatus, Platform, Protocol, SocketState};

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

    fn write_process(proc_root: &Path, pid: u32, name: &str, parent_pid: u32) {
        let process_dir = proc_root.join(pid.to_string());
        fs::create_dir_all(process_dir.join("fd")).expect("test process directory must be created");
        fs::write(process_dir.join("comm"), format!("{name}\n"))
            .expect("test process name must be written");
        fs::write(
            process_dir.join("cmdline"),
            format!("{name}\0--test\0").as_bytes(),
        )
        .expect("test cmdline must be written");
        fs::write(
            process_dir.join("status"),
            format!("Name:\t{name}\nPPid:\t{parent_pid}\nUid:\t1000\t1000\t1000\t1000\n"),
        )
        .expect("test status must be written");
        fs::write(
            process_dir.join("stat"),
            stat_text(pid, name, parent_pid, u64::from(pid) * 10),
        )
        .expect("test stat must be written");
        std::os::unix::fs::symlink(format!("/usr/bin/{name}"), process_dir.join("exe"))
            .expect("test exe symlink must be created");
    }

    fn stat_text(pid: u32, name: &str, parent_pid: u32, start_time_ticks: u64) -> String {
        let mut fields = vec!["S".to_owned(), parent_pid.to_string()];
        for _ in 0..17 {
            fields.push("0".to_owned());
        }
        fields.push(start_time_ticks.to_string());
        format!("{pid} ({name}) {}\n", fields.join(" "))
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
    fn bounded_text_reader_rejects_oversized_proc_files() {
        let proc_root = temp_proc_root("bounded-text");
        let path = proc_root.join("net").join("huge");
        fs::write(&path, "abcd").expect("test file must be written");

        let text = read_bounded_text(&path, 4).expect("file at the cap is accepted");
        assert_eq!(text, "abcd");

        let error = read_bounded_text(&path, 3).expect_err("over-cap file must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
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
    fn parent_pid_is_read_from_status_text() {
        assert_eq!(
            parse_process_status("Name:\tnode\nPPid:\t42\n")
                .expect("valid status text must parse")
                .parent_pid,
            Some(42),
        );
        assert_eq!(
            parse_process_status("Name:\tnode\n")
                .expect("missing PPid is not malformed")
                .parent_pid,
            None,
        );
        assert!(parse_process_status("PPid:\tnot-a-pid\n").is_err());
    }

    #[test]
    fn process_status_reads_parent_and_owner_uid() {
        let status = parse_process_status("Name:\tnode\nPPid:\t42\nUid:\t1000\t1001\t1002\t1003\n")
            .expect("valid status text must parse");

        assert_eq!(status.parent_pid, Some(42));
        assert_eq!(status.owner_uid, Some(1000));
    }

    #[test]
    fn process_group_id_is_read_from_stat_field_5_and_fails_closed() {
        // Field 5 (pgrp) is the third token after the comm terminator; the
        // right-split keeps a paren-laden comm from shifting it.
        let text = "1234 (node worker) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 0 0 987654\n";
        assert_eq!(parse_process_group_id(text), Some(4242));
        assert_eq!(parse_process_group_id("garbage with no comm"), None);

        // Group kill derives membership from the group ID, so the snapshot
        // read fails closed: a stat whose group token is unreadable while the
        // start marker still parses must error the scan, and the kernel's
        // group 0 must map to "no targetable group", never to a member edge.
        let dir = std::env::temp_dir().join(format!(
            "kickoutchi-tree-stat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos(),
        ));
        fs::create_dir_all(&dir).expect("temp stat dir must be created");
        // Derive both cases from the canonical `stat_text` shape (start marker
        // parseable at field 22) so only the pgrp token differs per case:
        // `stat_text` emits `... S <ppid> <pgrp=0> ...`, so its own output is
        // the kernel case, and one targeted replace corrupts the pgrp token.
        let corrupt = dir.join("stat-corrupt");
        let corrupt_text = stat_text(1234, "node", 1, 987_654).replacen("S 1 0", "S 1 x", 1);
        assert!(corrupt_text.contains("S 1 x"), "{corrupt_text}");
        fs::write(&corrupt, corrupt_text).expect("corrupt stat must be written");
        assert!(super::read_tree_stat(&corrupt).is_err());

        let kernel = dir.join("stat-kernel");
        fs::write(&kernel, stat_text(2, "kthreadd", 0, 987_654))
            .expect("kernel stat must be written");
        let stat = super::read_tree_stat(&kernel)
            .expect("kernel stat must read")
            .expect("kernel stat must exist");
        assert_eq!(stat.process_group, None);
        fs::remove_dir_all(dir).expect("temp stat dir must clean up");
    }

    #[test]
    fn process_start_time_is_read_from_stat_field_22() {
        let text = stat_text(1234, "node worker", 1, 987_654);

        let start_time = parse_process_start_time_ticks(&text)
            .expect("valid stat text must expose process start time");

        assert_eq!(start_time, 987_654);
    }

    #[test]
    fn process_start_time_survives_parens_in_comm() {
        // comm is an unescaped task name that can contain `) `; the right-split in
        // parse_process_start_time_ticks must still land on the real terminator
        // rather than a paren inside the name. A first/left split would read the
        // paren in `ev) il` as the terminator and parse the wrong field.
        let text = stat_text(1234, "ev) il", 1, 987_654);

        let start_time =
            parse_process_start_time_ticks(&text).expect("paren-laden comm must still parse");

        assert_eq!(start_time, 987_654);
    }

    #[test]
    fn parent_pid_read_is_bounded_and_still_finds_ppid_near_the_top() {
        // `PPid` lives near the top of `status`, so the byte cap on the read must
        // never hide it, even when the rest of the file runs well past the cap.
        let proc_root = temp_proc_root("status-cap");
        let process_dir = proc_root.join("99");
        fs::create_dir_all(&process_dir).expect("test process directory must exist");
        let status = format!("Name:\tnode\nPPid:\t42\n{}", "Filler:\t0\n".repeat(2000));
        fs::write(process_dir.join("status"), status).expect("test status must be written");

        let parent = read_process_status(&process_dir.join("status"))
            .expect("status read must succeed")
            .parent_pid;

        assert_eq!(parent, Some(42));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
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
    fn linux_collection_enriches_rows_with_parent_metadata() {
        let proc_root = temp_proc_root("parent-metadata");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 1234, "node", 1);
        fs::create_dir_all(proc_root.join("1")).expect("test parent process directory must exist");
        fs::write(proc_root.join("1").join("comm"), "systemd\n")
            .expect("test parent process name must be written");
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234").join("fd").join("0"))
            .expect("test socket symlink must be created");

        let entries = LinuxCollector::with_proc_root(proc_root.clone())
            .collect()
            .expect("test proc root must collect");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].pid, Some(1234));
        assert_eq!(entries[0].process_name.as_deref(), Some("node"));
        assert_eq!(entries[0].parent_pid, Some(1));
        assert_eq!(entries[0].parent_process_name.as_deref(), Some("systemd"));
        assert_eq!(entries[0].permission, PermissionStatus::Full);
        assert!(entries[0].is_system_process());
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn linux_collection_emits_one_row_per_shared_socket_owner() {
        let proc_root = temp_proc_root("shared-socket-rows");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 1234, "parent", 1);
        write_process(&proc_root, 1235, "child", 1234);
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234").join("fd").join("0"))
            .expect("parent socket symlink must be created");
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("1235").join("fd").join("0"))
            .expect("child socket symlink must be created");

        let entries = LinuxCollector::with_proc_root(proc_root.clone())
            .collect()
            .expect("test proc root must collect");
        let pids = entries.iter().map(|entry| entry.pid).collect::<Vec<_>>();

        assert_eq!(pids, vec![Some(1234), Some(1235)]);
        assert!(entries.iter().all(|entry| entry.local_port == 3000));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn selected_process_context_collects_owner_uid_and_direct_children() {
        let proc_root = temp_proc_root("selected-context");
        write_process(&proc_root, 100, "parent", 1);
        write_process(&proc_root, 101, "worker-a", 100);
        write_process(&proc_root, 102, "worker-b", 100);
        write_process(&proc_root, 200, "unrelated", 1);

        let context = collect_process_context_from(&proc_root, 100);

        assert_eq!(context.owner_uid, Some(1000));
        assert_eq!(context.process_start_time_marker, Some(1000));
        let children: Vec<(u32, Option<&str>)> = context
            .children
            .children
            .iter()
            .map(|child| (child.pid, child.process_name.as_deref()))
            .collect();
        assert_eq!(
            children,
            vec![(101, Some("worker-a")), (102, Some("worker-b"))]
        );
        assert!(!context.children.truncated);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn tree_process_snapshot_reads_parent_name_and_start_marker() {
        let proc_root = temp_proc_root("tree-snapshot");
        write_process(&proc_root, 100, "root", 1);
        write_process(&proc_root, 101, "child", 100);
        write_process(&proc_root, 102, "grandchild", 101);

        let infos = collect_tree_process_infos(&proc_root).expect("tree snapshot must collect");
        let tree = crate::tree::plan_process_tree(100, &infos, &[], Platform::Linux, 256)
            .expect("root must be present");
        let tuples = infos
            .iter()
            .filter(|info| matches!(info.pid, 100..=102))
            .map(|info| {
                (
                    info.pid,
                    info.parent_pid,
                    info.process_name.as_deref(),
                    info.start_time_marker,
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(tree.len(), 3);
        assert!(tuples.contains(&(100, Some(1), Some("root"), Some(1000))));
        assert!(tuples.contains(&(101, Some(100), Some("child"), Some(1010))));
        assert!(tuples.contains(&(102, Some(101), Some("grandchild"), Some(1020))));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn child_process_collection_is_bounded() {
        let proc_root = temp_proc_root("bounded-children");
        write_process(&proc_root, 100, "parent", 1);
        let max_children = u32::try_from(MAX_CHILD_PROCESSES)
            .expect("child-process cap must fit in u32 test PIDs");
        for offset in 0..=max_children {
            write_process(&proc_root, 1_000 + offset, "worker", 100);
        }

        let children = collect_child_processes_from(&proc_root, 100);

        assert_eq!(children.children.len(), MAX_CHILD_PROCESSES);
        assert!(children.truncated);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn related_process_hints_use_strict_command_line_evidence() {
        let proc_root = temp_proc_root("related-hints");
        write_process(&proc_root, 100, "candidate", 1);
        fs::write(
            proc_root.join("100").join("cmdline"),
            b"python3\0-m\0http.server\0--port\x003000\0",
        )
        .expect("candidate cmdline must be written");
        write_process(&proc_root, 101, "weak", 1);
        fs::write(
            proc_root.join("101").join("cmdline"),
            b"worker\0--timeout\x003000\0",
        )
        .expect("weak cmdline must be written");
        write_process(&proc_root, std::process::id(), "kickoutchi", 1);
        fs::write(
            proc_root
                .join(std::process::id().to_string())
                .join("cmdline"),
            b"kickoutchi\0list\0--port\x003000\0",
        )
        .expect("self cmdline must be written");
        write_process(&proc_root, 1, "cargo", 0);
        fs::write(
            proc_root.join("1").join("cmdline"),
            b"cargo\0run\0--\0list\0--port\x003000\0",
        )
        .expect("ancestor cmdline must be written");

        let hints = collect_related_process_hints_from(&proc_root, 3000);

        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].pid, 100);
        assert_eq!(hints[0].process_name.as_deref(), Some("candidate"));
        assert!(hints[0].command_line.contains("--port 3000"));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
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
        let target_inodes = HashSet::from([1]);
        let error = collect_socket_owners(
            Path::new("/definitely-not-a-real-kickoutchi-proc-root"),
            &target_inodes,
        )
        .expect_err("missing proc root must fail");

        assert!(error.to_string().contains("cannot read"), "{error}");
    }

    #[test]
    fn socket_owner_collection_ignores_non_target_inodes() {
        let proc_root = temp_proc_root("target-inodes");
        let fd_dir = proc_root.join("1234").join("fd");
        fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
        std::os::unix::fs::symlink("socket:[11]", fd_dir.join("0"))
            .expect("test socket symlink must be created");
        std::os::unix::fs::symlink("socket:[22]", fd_dir.join("1"))
            .expect("test socket symlink must be created");

        let owners = collect_socket_owners(&proc_root, &HashSet::from([22]))
            .expect("targeted owner collection must succeed");

        assert_eq!(owners.get(&22).map(Vec::as_slice), Some(&[1234][..]));
        assert!(!owners.contains_key(&11));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn socket_owner_collection_retains_multiple_pids_for_shared_inodes() {
        let proc_root = temp_proc_root("shared-inode-owners");
        for pid in [100, 101] {
            let fd_dir = proc_root.join(pid.to_string()).join("fd");
            fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
            std::os::unix::fs::symlink("socket:[44]", fd_dir.join("0"))
                .expect("test socket symlink must be created");
        }

        let owners = collect_socket_owners(&proc_root, &HashSet::from([44]))
            .expect("targeted owner collection must succeed");

        assert_eq!(owners.get(&44).map(Vec::as_slice), Some(&[100, 101][..]));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn pid_socket_owner_collection_records_matching_inode_once_per_pid() {
        let proc_root = temp_proc_root("target-owner-once");
        let fd_dir = proc_root.join("1234").join("fd");
        fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
        std::os::unix::fs::symlink("socket:[44]", fd_dir.join("0"))
            .expect("test socket symlink must be created");
        std::os::unix::fs::symlink("socket:[44]", fd_dir.join("1"))
            .expect("duplicate socket symlink must be created");

        let target_inodes = HashSet::from([44]);
        let mut owners = HashMap::new();
        collect_pid_socket_owners(&proc_root, 1234, &target_inodes, &mut owners);

        assert_eq!(owners.get(&44).map(Vec::as_slice), Some(&[1234][..]));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }
}
