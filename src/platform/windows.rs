//! Native Windows socket collection through IP Helper.
//!
//! No `netstat` scraping: IP Helper tells us which sockets exist and which PID
//! owns each one. Process metadata comes from one `sysinfo` snapshot per collect,
//! so rows do fast lookups instead of opening every swamp hut one by one. The
//! selected kill target gets one extra handle open for a high-resolution creation
//! time marker, because PID reuse is where the dragon lives.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString, c_void};
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;

use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, UpdateKind};
use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_SUCCESS, FILETIME,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
    Protocol, RelatedProcessHint, SocketState,
};
use crate::tree::TreeProcessInfo;

const MAX_IPHELPER_TABLE_BYTES: u32 = 16 * 1024 * 1024;
const TABLE_READ_ATTEMPTS: usize = 3;
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;

pub(crate) struct WindowsCollector;

impl Collector for WindowsCollector {
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError> {
        let records = collect_socket_records()?;
        let processes = ProcessSnapshot::collect();
        Ok(records
            .iter()
            .map(|record| entry_from_record(record, &processes))
            .collect())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: SocketState,
    pid: u32,
}

#[derive(Debug, Clone, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    partial: bool,
}

#[derive(Debug, Default)]
struct ProcessSnapshot {
    processes: HashMap<u32, ProcessMetadata>,
}

impl ProcessSnapshot {
    fn collect() -> Self {
        let refresh = RefreshKind::nothing().with_processes(
            ProcessRefreshKind::nothing()
                .with_cmd(UpdateKind::Always)
                .with_exe(UpdateKind::Always)
                .without_tasks(),
        );
        let system = System::new_with_specifics(refresh);
        let mut snapshot = Self::default();

        for (pid, process) in system.processes() {
            let pid = pid.as_u32();
            let process_name = non_empty_os_str(process.name());
            let executable_path = process.exe().map(PathBuf::from);
            let command_line = command_line_from_os_strings(process.cmd());
            let parent_pid = process.parent().map(Pid::as_u32);
            let partial =
                process_name.is_none() || executable_path.is_none() || command_line.is_none();

            snapshot.processes.insert(
                pid,
                ProcessMetadata {
                    process_name,
                    executable_path,
                    command_line,
                    parent_pid,
                    parent_process_name: None,
                    partial,
                },
            );
        }

        let names = snapshot
            .processes
            .iter()
            .filter_map(|(pid, metadata)| Some((*pid, metadata.process_name.clone()?)))
            .collect::<HashMap<_, _>>();

        for metadata in snapshot.processes.values_mut() {
            if let Some(parent_pid) = metadata.parent_pid {
                metadata.parent_process_name = names.get(&parent_pid).cloned();
            }
        }

        snapshot
    }

    fn metadata(&self, pid: u32) -> Option<&ProcessMetadata> {
        self.processes.get(&pid)
    }

    /// Direct children of `pid`, resolved on demand from the process map.
    ///
    /// No standing guest list of every ogre's offspring: this scans `processes`
    /// once per call instead of maintaining a precomputed parent->children index.
    /// Only `collect_process_context` asks for children, and only when the details
    /// modal opens — a rare, human-triggered action — so the per-refresh table path
    /// never builds a child index it does not read. It mirrors the Linux collector,
    /// which resolves children lazily too. Self is excluded, because no resident of
    /// the swamp gets to show up as its own kid.
    fn children(&self, pid: u32) -> ChildProcessSnapshot {
        let mut children = self
            .processes
            .iter()
            .filter(|&(&child_pid, metadata)| child_pid != pid && metadata.parent_pid == Some(pid))
            .map(|(&child_pid, metadata)| ChildProcess {
                pid: child_pid,
                process_name: metadata.process_name.clone(),
            })
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.pid);

        let truncated = children.len() > MAX_CHILD_PROCESSES;
        children.truncate(MAX_CHILD_PROCESSES);
        ChildProcessSnapshot {
            children,
            truncated,
        }
    }

    fn ancestor_pids(&self, pid: u32) -> HashSet<u32> {
        let mut ancestors = HashSet::from([pid]);
        let mut current = pid;
        for _ in 0..MAX_PROCESS_ANCESTORS {
            let Some(parent_pid) = self
                .processes
                .get(&current)
                .and_then(|metadata| metadata.parent_pid)
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
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let processes = ProcessSnapshot::collect();
    ProcessContext {
        owner_uid: None,
        process_start_time_marker: process_start_time_marker(pid),
        children: processes.children(pid),
        docker: None,
    }
}

pub(crate) fn process_command_line_reader() -> impl FnMut(u32) -> Option<String> {
    let processes = ProcessSnapshot::collect();
    move |pid| {
        processes
            .metadata(pid)
            .and_then(|metadata| metadata.command_line.clone())
    }
}

pub(crate) fn collect_tree_process_infos() -> Vec<TreeProcessInfo> {
    tree_process_infos_from_snapshot(&ProcessSnapshot::collect())
}

fn tree_process_infos_from_snapshot(processes: &ProcessSnapshot) -> Vec<TreeProcessInfo> {
    tree_process_infos_from_snapshot_with(processes, process_start_time_marker)
}

fn tree_process_infos_from_snapshot_with(
    processes: &ProcessSnapshot,
    mut marker_for_pid: impl FnMut(u32) -> Option<u64>,
) -> Vec<TreeProcessInfo> {
    let markers = processes
        .processes
        .keys()
        .map(|pid| (*pid, marker_for_pid(*pid)))
        .collect::<HashMap<_, _>>();
    let names = processes
        .processes
        .iter()
        .filter_map(|(pid, metadata)| Some((*pid, metadata.process_name.clone()?)))
        .collect::<HashMap<_, _>>();

    let mut rows = processes
        .processes
        .iter()
        .map(|(pid, metadata)| {
            let parent_edge = accepted_parent_edge(*pid, metadata.parent_pid, &markers);
            TreeProcessInfo {
                pid: *pid,
                parent_pid: parent_edge.verified,
                unverified_parent_pid: parent_edge.unverified,
                parent_process_name: parent_edge
                    .verified
                    .and_then(|parent_pid| names.get(&parent_pid).cloned()),
                process_name: metadata.process_name.clone(),
                start_time_marker: markers.get(pid).copied().flatten(),
                owner_uid: None,
                process_group: None,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|info| info.pid);
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedParentEdge {
    verified: Option<u32>,
    unverified: Option<u32>,
}

fn accepted_parent_edge(
    child_pid: u32,
    parent_pid: Option<u32>,
    markers: &HashMap<u32, Option<u64>>,
) -> AcceptedParentEdge {
    let Some(parent_pid) = parent_pid else {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    };
    if parent_pid == child_pid {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    }
    let Some(child_start) = markers.get(&child_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    let Some(parent_start) = markers.get(&parent_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    match child_start.cmp(&parent_start) {
        std::cmp::Ordering::Greater => AcceptedParentEdge {
            verified: Some(parent_pid),
            unverified: None,
        },
        std::cmp::Ordering::Equal => AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        },
        std::cmp::Ordering::Less => AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<u64> {
    let handle = unsafe {
        // SAFETY: OpenProcess takes only value arguments here. The returned handle
        // is checked before being wrapped for owned close-on-drop handling.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if handle.is_null() {
        return None;
    }

    let process_handle = unsafe {
        // SAFETY: OpenProcess returned a non-null process handle that this scope
        // owns. OwnedHandle closes it exactly once when Donkey leaves the room.
        OwnedHandle::from_raw_handle(handle)
    };
    process_start_time_marker_from_handle(&process_handle)
}

pub(crate) fn process_start_time_marker_from_handle(handle: &OwnedHandle) -> Option<u64> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    let result = unsafe {
        // SAFETY: all FILETIME pointers are valid for one write, and `handle` is
        // an owned process handle with query access.
        GetProcessTimes(
            handle.as_raw_handle(),
            &raw mut creation_time,
            &raw mut exit_time,
            &raw mut kernel_time,
            &raw mut user_time,
        )
    };
    (result != 0).then(|| filetime_to_u64(creation_time))
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    let current_pid = std::process::id();
    let processes = ProcessSnapshot::collect();
    let excluded_pids = processes.ancestor_pids(current_pid);
    let mut rows = processes.processes.into_iter().collect::<Vec<_>>();
    rows.sort_by_key(|(pid, _metadata)| *pid);

    let mut hints = Vec::new();
    for (pid, metadata) in rows {
        if excluded_pids.contains(&pid) {
            continue;
        }
        let Some(command_line) = metadata.command_line else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }
        hints.push(RelatedProcessHint {
            pid,
            process_name: metadata.process_name,
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }
    hints
}

fn collect_socket_records() -> Result<Vec<SocketRecord>, CollectorError> {
    let mut records = Vec::new();
    collect_tcp4_records(&mut records)?;
    collect_tcp6_records(&mut records)?;
    collect_udp4_records(&mut records)?;
    collect_udp6_records(&mut records)?;
    Ok(records)
}

fn collect_tcp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        // The buffer is u32-aligned and `size` is its byte length.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = tcp4_rows(&table)?;
    records.extend(rows.iter().filter_map(tcp4_record));
    Ok(())
}

fn collect_tcp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 call above; only the address family changes.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET6),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = tcp6_rows(&table)?;
    records.extend(rows.iter().filter_map(tcp6_record));
    Ok(())
}

fn collect_udp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = udp4_rows(&table)?;
    records.extend(rows.iter().map(udp4_record));
    Ok(())
}

fn collect_udp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 UDP call above; only the address family changes.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0)
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = udp6_rows(&table)?;
    records.extend(rows.iter().map(udp6_record));
    Ok(())
}

fn read_iphelper_table<F>(operation: &'static str, mut call: F) -> Result<Vec<u32>, CollectorError>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
{
    let mut size = 0_u32;
    let mut code = call(std::ptr::null_mut(), &raw mut size);
    if code == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_SUCCESS {
        return Err(windows_api_error(operation, code));
    }

    for _ in 0..TABLE_READ_ATTEMPTS {
        if size == 0 {
            return Ok(Vec::new());
        }
        if size > MAX_IPHELPER_TABLE_BYTES {
            return Err(CollectorError::Platform {
                operation,
                detail: format!("table exceeds {MAX_IPHELPER_TABLE_BYTES} byte read limit"),
            });
        }

        let words = usize::try_from(size)
            .expect("Windows table size must fit usize")
            .div_ceil(size_of::<u32>());
        let mut buffer = vec![0_u32; words];
        let mut buffer_size = u32::try_from(buffer.len() * size_of::<u32>())
            .expect("bounded Windows table buffer must fit u32");
        code = call(buffer.as_mut_ptr().cast::<c_void>(), &raw mut buffer_size);
        match code {
            ERROR_SUCCESS => return Ok(buffer),
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_INSUFFICIENT_BUFFER => size = buffer_size,
            code => return Err(windows_api_error(operation, code)),
        }
    }

    Err(CollectorError::Platform {
        operation,
        detail: "table kept growing while being read".to_owned(),
    })
}

fn tcp4_rows(buffer: &[u32]) -> Result<&[MIB_TCPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )
}

fn tcp6_rows(buffer: &[u32]) -> Result<&[MIB_TCP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )
}

fn udp4_rows(buffer: &[u32]) -> Result<&[MIB_UDPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
    )
}

fn udp6_rows(buffer: &[u32]) -> Result<&[MIB_UDP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
    )
}

fn table_rows<'a, Row>(
    buffer: &'a [u32],
    operation: &'static str,
    row_offset_bytes: usize,
) -> Result<&'a [Row], CollectorError> {
    let buffer_bytes = std::mem::size_of_val(buffer);
    if buffer_bytes < size_of::<u32>() {
        return Err(CollectorError::Platform {
            operation,
            detail: "table buffer is smaller than its row count".to_owned(),
        });
    }

    let count = usize::try_from(buffer[0]).expect("Windows table row count must fit usize");
    let row_bytes =
        count
            .checked_mul(size_of::<Row>())
            .ok_or_else(|| CollectorError::Platform {
                operation,
                detail: "table row count overflows usize".to_owned(),
            })?;
    let required =
        row_offset_bytes
            .checked_add(row_bytes)
            .ok_or_else(|| CollectorError::Platform {
                operation,
                detail: "table byte length overflows usize".to_owned(),
            })?;
    if required > buffer_bytes {
        return Err(CollectorError::Platform {
            operation,
            detail: "table row count exceeds returned buffer".to_owned(),
        });
    }

    let rows = unsafe {
        // SAFETY: the bounds check above proves the flexible array payload fits in
        // the returned u32-aligned buffer. IP Helper table rows are u32-aligned.
        let row_ptr = buffer
            .as_ptr()
            .cast::<u8>()
            .add(row_offset_bytes)
            .cast::<Row>();
        std::slice::from_raw_parts(row_ptr, count)
    };
    Ok(rows)
}

fn tcp4_record(row: &MIB_TCPROW_OWNER_PID) -> Option<SocketRecord> {
    (row.dwState == u32::try_from(MIB_TCP_STATE_LISTEN).expect("TCP listen state fits u32")).then(
        || SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
            local_port: decode_port(row.dwLocalPort),
            state: SocketState::Listen,
            pid: row.dwOwningPid,
        },
    )
}

fn tcp6_record(row: &MIB_TCP6ROW_OWNER_PID) -> Option<SocketRecord> {
    (row.dwState == u32::try_from(MIB_TCP_STATE_LISTEN).expect("TCP listen state fits u32")).then(
        || SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            local_port: decode_port(row.dwLocalPort),
            state: SocketState::Listen,
            pid: row.dwOwningPid,
        },
    )
}

fn udp4_record(row: &MIB_UDPROW_OWNER_PID) -> SocketRecord {
    SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        state: SocketState::Bound,
        pid: row.dwOwningPid,
    }
}

fn udp6_record(row: &MIB_UDP6ROW_OWNER_PID) -> SocketRecord {
    SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        state: SocketState::Bound,
        pid: row.dwOwningPid,
    }
}

fn entry_from_record(record: &SocketRecord, processes: &ProcessSnapshot) -> PortEntry {
    let metadata = processes.metadata(record.pid);
    let permission = if metadata.is_some_and(|metadata| !metadata.partial) {
        PermissionStatus::Full
    } else {
        PermissionStatus::Partial
    };

    PortEntry {
        protocol: record.protocol,
        local_addr: record.local_addr,
        local_port: record.local_port,
        state: record.state,
        pid: Some(record.pid),
        process_name: metadata.and_then(|metadata| metadata.process_name.clone()),
        executable_path: metadata.and_then(|metadata| metadata.executable_path.clone()),
        command_line: metadata.and_then(|metadata| metadata.command_line.clone()),
        parent_pid: metadata.and_then(|metadata| metadata.parent_pid),
        parent_process_name: metadata.and_then(|metadata| metadata.parent_process_name.clone()),
        child_pids: Vec::new(),
        protected: false,
        platform: Platform::Windows,
        permission,
    }
}

fn ipv4_addr(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

#[cfg(test)]
fn encode_port_for_tests(port: u16) -> u32 {
    u32::from(port.to_be())
}

fn decode_port(raw: u32) -> u16 {
    let port =
        u16::try_from(raw & u32::from(u16::MAX)).expect("masked IP Helper port value must fit u16");
    u16::from_be(port)
}

fn command_line_from_os_strings(parts: &[OsString]) -> Option<String> {
    if parts.is_empty() {
        return None;
    }
    Some(
        parts
            .iter()
            .map(|part| part.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

fn non_empty_os_str(value: &OsStr) -> Option<String> {
    let text = value.to_string_lossy();
    if text.is_empty() {
        None
    } else {
        Some(text.into_owned())
    }
}

fn windows_api_error(operation: &'static str, code: u32) -> CollectorError {
    CollectorError::Platform {
        operation,
        detail: format!("Windows error {code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedParentEdge, MAX_CHILD_PROCESSES, ProcessMetadata, ProcessSnapshot, SocketRecord,
        accepted_parent_edge, command_line_from_os_strings, decode_port, encode_port_for_tests,
        entry_from_record, filetime_to_u64, tcp4_record, tcp6_record,
        tree_process_infos_from_snapshot_with, udp4_record, udp6_record,
    };
    use crate::model::{PermissionStatus, Platform, Protocol, SocketState};
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDPROW_OWNER_PID,
    };

    fn full_process_snapshot(pid: u32) -> ProcessSnapshot {
        ProcessSnapshot {
            processes: HashMap::from([(
                pid,
                ProcessMetadata {
                    process_name: Some("python.exe".to_owned()),
                    executable_path: Some("C:/Python/python.exe".into()),
                    command_line: Some("python.exe -m http.server 3000".to_owned()),
                    parent_pid: Some(42),
                    parent_process_name: Some("WindowsTerminal.exe".to_owned()),
                    partial: false,
                },
            )]),
        }
    }

    #[test]
    fn process_snapshot_tracks_current_process_ancestors() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                (
                    10,
                    ProcessMetadata {
                        parent_pid: Some(5),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    5,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    1,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let ancestors = snapshot.ancestor_pids(10);

        assert!(ancestors.contains(&10));
        assert!(ancestors.contains(&5));
        assert!(ancestors.contains(&1));
        assert_eq!(ancestors.len(), 3);
    }

    #[test]
    fn children_are_resolved_on_demand_sorted_and_self_excluded() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                // Self-parented: must not show up as its own child.
                (
                    100,
                    ProcessMetadata {
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                // Two real children, inserted out of PID order to pin the sort.
                (
                    102,
                    ProcessMetadata {
                        process_name: Some("worker-b".to_owned()),
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    101,
                    ProcessMetadata {
                        process_name: Some("worker-a".to_owned()),
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                // Unrelated parent: must be filtered out.
                (
                    200,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let children = snapshot.children(100);

        let listed: Vec<(u32, Option<&str>)> = children
            .children
            .iter()
            .map(|child| (child.pid, child.process_name.as_deref()))
            .collect();
        assert_eq!(
            listed,
            vec![(101, Some("worker-a")), (102, Some("worker-b"))]
        );
        assert!(!children.truncated);
    }

    #[test]
    fn children_resolution_is_bounded() {
        let mut processes = HashMap::from([(100, ProcessMetadata::default())]);
        let max = u32::try_from(MAX_CHILD_PROCESSES).expect("child cap fits u32 test PIDs");
        for offset in 0..=max {
            processes.insert(
                1_000 + offset,
                ProcessMetadata {
                    parent_pid: Some(100),
                    ..ProcessMetadata::default()
                },
            );
        }
        let snapshot = ProcessSnapshot { processes };

        let children = snapshot.children(100);

        assert_eq!(children.children.len(), MAX_CHILD_PROCESSES);
        assert!(children.truncated);
    }

    #[test]
    fn tcp4_listen_row_becomes_socket_record() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: encode_port_for_tests(3000),
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 18422,
        };

        let record = tcp4_record(&row).expect("listen rows are kept");

        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
        assert_eq!(record.state, SocketState::Listen);
        assert_eq!(record.pid, 18422);
    }

    #[test]
    fn tcp4_non_listen_row_is_ignored() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: encode_port_for_tests(3000),
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 18422,
        };

        assert_eq!(tcp4_record(&row), None);
    }

    #[test]
    fn tcp6_listen_row_keeps_ipv6_address() {
        let row = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: encode_port_for_tests(8080),
            ucRemoteAddr: [0; 16],
            dwRemoteScopeId: 0,
            dwRemotePort: 0,
            dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
            dwOwningPid: 77,
        };

        let record = tcp6_record(&row).expect("listen rows are kept");

        assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(record.local_port, 8080);
        assert_eq!(record.pid, 77);
    }

    #[test]
    fn udp_rows_are_bound_sockets() {
        let udp4 = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: u32::from_ne_bytes([0, 0, 0, 0]),
            dwLocalPort: encode_port_for_tests(5353),
            dwOwningPid: 902,
        };
        let udp6 = MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::UNSPECIFIED.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: encode_port_for_tests(5355),
            dwOwningPid: 903,
        };

        assert_eq!(udp4_record(&udp4).state, SocketState::Bound);
        assert_eq!(udp4_record(&udp4).local_port, 5353);
        assert_eq!(udp6_record(&udp6).state, SocketState::Bound);
        assert_eq!(udp6_record(&udp6).local_port, 5355);
    }

    #[test]
    fn port_decoding_ignores_unused_high_bits() {
        assert_eq!(decode_port(0xDEAD_0000 | encode_port_for_tests(3000)), 3000);
    }

    #[test]
    fn filetime_marker_keeps_full_windows_creation_time_precision() {
        let marker = filetime_to_u64(FILETIME {
            dwLowDateTime: 0x89AB_CDEF,
            dwHighDateTime: 0x0123_4567,
        });

        assert_eq!(marker, 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn parent_edges_require_child_to_start_after_parent() {
        let markers = HashMap::from([(10, Some(100)), (20, Some(200)), (30, Some(50)), (40, None)]);

        assert_eq!(
            accepted_parent_edge(20, Some(10), &markers),
            AcceptedParentEdge {
                verified: Some(10),
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(10, Some(20), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(30, Some(10), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(20, Some(20), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
    }

    #[test]
    fn missing_creation_time_keeps_parent_edge_unverified() {
        let markers = HashMap::from([(10, Some(100)), (20, Some(200)), (40, None)]);

        assert_eq!(
            accepted_parent_edge(20, Some(99), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: Some(99),
            },
        );
        assert_eq!(
            accepted_parent_edge(40, Some(10), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: Some(10),
            },
        );
    }

    #[test]
    fn equal_creation_times_keep_parent_edge_unverified() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                (10, ProcessMetadata::default()),
                (
                    20,
                    ProcessMetadata {
                        parent_pid: Some(10),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let rows = tree_process_infos_from_snapshot_with(&snapshot, |_| Some(100));
        let child = rows.iter().find(|row| row.pid == 20).expect("child row");

        assert_eq!(child.parent_pid, None);
        assert_eq!(child.unverified_parent_pid, Some(10));
    }

    #[test]
    fn entry_from_record_uses_snapshot_metadata() {
        let snapshot = full_process_snapshot(18422);
        let record = SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 18422,
        };

        let entry = entry_from_record(&record, &snapshot);

        assert_eq!(entry.platform, Platform::Windows);
        assert_eq!(entry.permission, PermissionStatus::Full);
        assert_eq!(entry.process_name.as_deref(), Some("python.exe"));
        assert_eq!(
            entry.parent_process_name.as_deref(),
            Some("WindowsTerminal.exe")
        );
    }

    #[test]
    fn missing_snapshot_metadata_still_keeps_the_port() {
        let record = SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 18422,
        };

        let entry = entry_from_record(&record, &ProcessSnapshot::default());

        assert_eq!(entry.pid, Some(18422));
        assert_eq!(entry.process_name, None);
        assert_eq!(entry.permission, PermissionStatus::Partial);
    }

    #[test]
    fn command_line_decoding_matches_cli_display_shape() {
        let command = command_line_from_os_strings(&[
            OsString::from("python.exe"),
            OsString::from("-m"),
            OsString::from("http.server"),
            OsString::from("3000"),
        ]);

        assert_eq!(command.as_deref(), Some("python.exe -m http.server 3000"));
    }
}
