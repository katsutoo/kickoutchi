//! Native macOS socket collection through libproc.
//!
//! macOS does not have Linux's `/proc/net` tables or Windows' IP Helper owner
//! tables. The least bad native path is process-first: list PIDs, list each
//! process' file descriptors with `proc_pidinfo`, then ask `proc_pidfdinfo` for
//! socket descriptors. That keeps `lsof` out of the default path and keeps every
//! Darwin layout used for the FFI in this module.

#![allow(
    clippy::struct_field_names,
    reason = "Darwin FFI structs mirror the C header names exactly"
)]

use std::collections::{HashSet, VecDeque};
use std::ffi::{CStr, OsStr, c_void};
use std::mem::{MaybeUninit, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
    Protocol, RelatedProcessHint, SocketState,
};
use crate::process::{tree_cont, tree_deliver_by_pid, tree_prepare_delivery_probe, tree_stop};
use crate::tree::{
    MAX_TREE_PROCESSES, TreeProcessInfo, TreeProcessOps, TreeSignalResult, TreeSnapshotScope,
};

const PID_LIST_ATTEMPTS: usize = 3;
const FD_LIST_ATTEMPTS: usize = 3;
const PROCESS_LIST_GROWTH_MARGIN: usize = 64;
const FD_LIST_GROWTH_MARGIN: usize = 16;
const MAX_PROCESS_IDS: usize = 131_072;
const MAX_PROCESS_FDS: usize = 65_536;
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;
const MAX_PROCARGS_BYTES: usize = 1024 * 1024;

const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const SOCKINFO_IN: libc::c_int = 1;
const SOCKINFO_TCP: libc::c_int = 2;
const TSI_S_LISTEN: libc::c_int = 1;
const SOCK_MAXADDRLEN: usize = 255;
const MAX_KCTL_NAME: usize = 96;

pub(crate) struct MacosCollector;

impl Collector for MacosCollector {
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError> {
        let pids = process_ids()?;
        let mut entries = Vec::new();
        for pid in pids {
            collect_pid_entries(pid, &mut entries);
        }
        Ok(entries)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SocketRecordKey {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    socket_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    state: SocketState,
    pid: u32,
    socket_id: u64,
}

impl SocketRecord {
    fn key(&self) -> SocketRecordKey {
        SocketRecordKey {
            protocol: self.protocol,
            local_addr: self.local_addr,
            local_port: self.local_port,
            socket_id: self.socket_id,
        }
    }
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

#[repr(C)]
struct ProcFileinfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: libc::off_t,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: libc::in_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
union InSocketAddress {
    ina_46: In4In6Addr,
    ina_6: libc::in6_addr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfo {
    insi_fport: libc::c_int,
    insi_lport: libc::c_int,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InSocketAddress,
    insi_laddr: InSocketAddress,
    insi_v4: InSockinfoV4,
    insi_v6: InSockinfoV6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfoV4 {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockinfoV6 {
    in6_hlim: u8,
    in6_cksum: libc::c_int,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockinfo {
    tcpsi_ini: InSockinfo,
    tcpsi_state: libc::c_int,
    tcpsi_timer: [libc::c_int; 4],
    tcpsi_mss: libc::c_int,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UnSockinfo {
    unsi_conn_so: u64,
    unsi_conn_pcb: u64,
    unsi_addr: [u8; SOCK_MAXADDRLEN],
    unsi_caddr: [u8; SOCK_MAXADDRLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NdrvInfo {
    ndrvsi_if_family: u32,
    ndrvsi_if_unit: u32,
    ndrvsi_if_name: [libc::c_char; libc::IF_NAMESIZE],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct KernCtlInfo {
    kcsi_id: u32,
    kcsi_reg_unit: u32,
    kcsi_flags: u32,
    kcsi_recvbufsize: u32,
    kcsi_sendbufsize: u32,
    kcsi_unit: u32,
    kcsi_name: [libc::c_char; MAX_KCTL_NAME],
}

#[repr(C)]
#[derive(Clone, Copy)]
union SocketProtocolInfo {
    pri_in: InSockinfo,
    pri_tcp: TcpSockinfo,
    pri_un: UnSockinfo,
    pri_ndrv: NdrvInfo,
    pri_kern_ctl: KernCtlInfo,
}

#[repr(C)]
struct SockbufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
struct SocketInfo {
    soi_stat: libc::vinfo_stat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: libc::c_int,
    soi_protocol: libc::c_int,
    soi_family: libc::c_int,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockbufInfo,
    soi_snd: SockbufInfo,
    soi_kind: libc::c_int,
    rfu_1: u32,
    soi_proto: SocketProtocolInfo,
}

#[repr(C)]
struct SocketFdinfo {
    pfi: ProcFileinfo,
    psi: SocketInfo,
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let bsd_info = read_process_bsdinfo(pid).ok();
    ProcessContext {
        owner_uid: bsd_info.as_ref().map(|info| info.pbi_uid),
        process_start_time_marker: bsd_info
            .as_ref()
            .map(process_start_time_marker_from_bsd_info),
        children: collect_child_processes(pid),
        docker: None,
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<u64> {
    read_process_bsdinfo(pid)
        .ok()
        .map(|info| process_start_time_marker_from_bsd_info(&info))
}

/// Best-effort command line for one PID, for the read-only inspect view.
/// `None` covers vanished, restricted, and kernel processes alike — inspect
/// renders it as unknown rather than failing the report.
pub(crate) fn process_command_line(pid: u32) -> Option<String> {
    read_command_line(pid).ok().flatten()
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    let Ok(pids) = process_ids() else {
        return Vec::new();
    };
    let excluded_pids = process_ancestor_pids(std::process::id());
    let mut hints = Vec::new();

    for pid in pids {
        if excluded_pids.contains(&pid) {
            continue;
        }
        let Ok(Some(command_line)) = read_command_line(pid) else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }
        hints.push(RelatedProcessHint {
            pid,
            process_name: read_process_name(pid).ok().flatten(),
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }

    hints
}

/// The macOS end of the process-tree I/O contract.
///
/// Snapshots come from one `proc_listallpids` walk with a `proc_bsdinfo` read
/// per PID; signal delivery goes through the `process` module's shared `kill(2)`
/// boundary. Darwin has no pidfd, so delivery cannot be pinned to a process
/// object the way Linux pins it. The stop-verify gate covers most of the gap —
/// a stopped process cannot fork, exec, or exit *on its own* — but an external
/// `SIGKILL` can still remove a stopped process, and for a member whose parent
/// is running (the root, and group members with parents outside the group) the
/// zombie can be reaped and the PID recycled before our raw-PID signal lands.
/// To shrink that window, `prepare_delivery` records each member's verified
/// start marker and every subsequent raw-PID signal re-reads and compares the
/// marker immediately before `kill(2)`. The residual race is the few
/// instructions between that read and the signal; without a pidfd equivalent
/// it cannot be closed completely.
pub(crate) struct MacosTreeOps {
    verified_markers: std::collections::HashMap<u32, u64>,
    snapshot_scope: TreeSnapshotScope,
}

impl MacosTreeOps {
    pub(crate) fn new() -> Self {
        Self {
            verified_markers: std::collections::HashMap::new(),
            snapshot_scope: TreeSnapshotScope::Full,
        }
    }

    /// Whether `pid` still carries the start marker the pipeline verified.
    ///
    /// `Ok(())` when the marker matches or was never recorded (thaw paths run
    /// before `prepare_delivery`); `Err` with the honest signal result when the
    /// process is gone or has been replaced by a PID-recycled stranger.
    fn recheck_marker(&self, pid: u32) -> Result<(), TreeSignalResult> {
        let Some(expected) = self.verified_markers.get(&pid) else {
            return Ok(());
        };
        match read_process_bsdinfo(pid) {
            Ok(info) if process_start_time_marker_from_bsd_info(&info) == *expected => Ok(()),
            // A different marker means the verified process is gone and the
            // PID now belongs to someone else: report the member as exited
            // rather than signalling the stranger.
            Ok(_) => Err(TreeSignalResult::NotFound),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                Err(TreeSignalResult::NotFound)
            }
            // An unreadable marker cannot prove identity; fail closed.
            Err(_) => Err(TreeSignalResult::Denied),
        }
    }
}

impl TreeProcessOps for MacosTreeOps {
    fn set_snapshot_scope(&mut self, scope: TreeSnapshotScope) {
        self.snapshot_scope = scope;
    }

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        collect_tree_process_infos(self.snapshot_scope).map_err(|error| error.to_string())
    }

    fn stop(&mut self, pid: u32) -> TreeSignalResult {
        tree_stop(pid)
    }

    fn cont(&mut self, pid: u32) {
        match self.recheck_marker(pid) {
            Ok(()) | Err(TreeSignalResult::Denied) => tree_cont(pid),
            Err(TreeSignalResult::NotFound) => {}
            Err(TreeSignalResult::Delivered) => unreachable!("recheck_marker never delivers"),
        }
    }

    fn prepare_delivery(
        &mut self,
        pid: u32,
        verified_start_marker: Option<u64>,
    ) -> TreeSignalResult {
        // Post-stop verification guarantees a marker for every member; a
        // missing one here is a pipeline invariant break, so refuse delivery
        // rather than proceed without a reuse check.
        let Some(marker) = verified_start_marker else {
            return TreeSignalResult::Denied;
        };
        self.verified_markers.insert(pid, marker);
        tree_prepare_delivery_probe(pid)
    }

    fn deliver(&mut self, pid: u32, mode: crate::process::KillMode) -> TreeSignalResult {
        if let Err(result) = self.recheck_marker(pid) {
            return result;
        }
        tree_deliver_by_pid(pid, mode)
    }
}

/// Read one snapshot of the process table for scoped tree execution.
///
/// Process snapshots skip rows that vanished mid-scan (`ESRCH`) and rows macOS
/// explicitly hides from this non-root process (`EPERM`). GitHub's macOS runner
/// exposes protected system PIDs in `proc_listallpids` but denies their BSD info;
/// aborting on those unrelated rows would make user-owned tree/group kills and
/// read-only inspect unusable. Other metadata failures still fail closed.
fn collect_tree_process_infos(
    scope: TreeSnapshotScope,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    match scope {
        TreeSnapshotScope::Full => collect_full_tree_process_infos(),
        TreeSnapshotScope::Tree { root_pid } => collect_scoped_tree_process_infos(root_pid),
        TreeSnapshotScope::Group { root_pid, pgid } => {
            collect_scoped_group_process_infos(root_pid, pgid)
        }
    }
}

fn collect_full_tree_process_infos() -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids()?;

    let mut infos = Vec::with_capacity(pids.len());
    for pid in pids {
        let Some(info) = read_tree_process_info(pid, true)? else {
            continue;
        };
        infos.push(info);
    }
    Ok(infos)
}

fn collect_scoped_tree_process_infos(
    root_pid: u32,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let mut infos = Vec::new();
    let mut seen = HashSet::new();
    let mut queue = VecDeque::from([root_pid]);

    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid) {
            continue;
        }
        let Some(info) = read_tree_process_info(pid, false)? else {
            continue;
        };
        infos.push(info);
        if infos.len() > MAX_TREE_PROCESSES {
            return Ok(infos);
        }
        for child_pid in child_process_ids(pid)? {
            if !seen.contains(&child_pid) {
                queue.push_back(child_pid);
            }
        }
    }

    Ok(infos)
}

fn collect_scoped_group_process_infos(
    root_pid: u32,
    pgid: u32,
) -> Result<Vec<TreeProcessInfo>, CollectorError> {
    let pids = process_ids()?;
    let mut infos = Vec::new();

    for pid in pids {
        match read_process_bsdinfo(pid) {
            Ok(info) => {
                let row = tree_process_info_from_readable_bsd(pid, &info)?;
                if pid == root_pid || row.process_group == Some(pgid) {
                    infos.push(row);
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) if error.raw_os_error() == Some(libc::EPERM) => {
                if pid == root_pid || process_group_for_pid(pid)? == Some(pgid) {
                    return Err(platform_error(
                        "proc_pidinfo(PROC_PIDTBSDINFO)",
                        format!("PID {pid}: process group member metadata is unreadable: {error}"),
                    ));
                }
            }
            Err(error) => {
                return Err(platform_error(
                    "proc_pidinfo(PROC_PIDTBSDINFO)",
                    format!("PID {pid}: {error}"),
                ));
            }
        }
    }

    Ok(infos)
}

fn read_tree_process_info(
    pid: u32,
    skip_restricted: bool,
) -> Result<Option<TreeProcessInfo>, CollectorError> {
    let info = match read_process_bsdinfo(pid) {
        Ok(info) => info,
        Err(error) if skip_restricted && should_skip_unreadable_snapshot_error(&error) => {
            return Ok(None);
        }
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
        Err(error) => {
            return Err(platform_error(
                "proc_pidinfo(PROC_PIDTBSDINFO)",
                format!("PID {pid}: {error}"),
            ));
        }
    };
    tree_process_info_from_readable_bsd(pid, &info).map(Some)
}

fn tree_process_info_from_readable_bsd(
    pid: u32,
    info: &libc::proc_bsdinfo,
) -> Result<TreeProcessInfo, CollectorError> {
    // proc_name can be narrower than bsdinfo for other users' processes, so
    // fall back to the comm carried inside the bsdinfo we already read; a
    // readable process with no name at all fails the scan closed.
    let Some(name) = read_process_name(pid)
        .ok()
        .flatten()
        .or_else(|| process_name_from_bsd_info(info))
    else {
        return Err(platform_error(
            "proc_name",
            format!("PID {pid}: process name is unreadable"),
        ));
    };
    Ok(tree_process_info_from_bsd(pid, info, name))
}

fn should_skip_unreadable_snapshot_error(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(libc::ESRCH | libc::EPERM))
}

fn child_process_ids(parent_pid: u32) -> Result<Vec<u32>, CollectorError> {
    let parent_pid = pid_to_c_int(parent_pid).map_err(|error| {
        platform_error(
            "proc_listchildpids",
            format!("parent PID is invalid: {error}"),
        )
    })?;
    let capacity = MAX_TREE_PROCESSES + 1;
    let buffer_bytes = checked_buffer_len::<libc::pid_t>(capacity, "proc_listchildpids")?;
    let mut raw_pids = vec![0 as libc::pid_t; capacity];
    let count = unsafe {
        // SAFETY: raw_pids owns buffer_bytes bytes and proc_listchildpids writes
        // at most that many pid_t values into it. The count is capped at one
        // past the tree limit; that is enough for the shared cap refusal.
        libc::proc_listchildpids(
            parent_pid,
            raw_pids.as_mut_ptr().cast::<c_void>(),
            buffer_bytes,
        )
    };
    if count < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(Vec::new());
        }
        return Err(platform_error("proc_listchildpids", error.to_string()));
    }

    let count = usize::try_from(count).expect("non-negative child PID count must fit usize");
    raw_pids.truncate(count.min(capacity));
    let mut pids = raw_pids
        .into_iter()
        .filter_map(valid_pid)
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn process_group_for_pid(target_pid: u32) -> Result<Option<u32>, CollectorError> {
    let target_pid = pid_to_c_int(target_pid)
        .map_err(|error| platform_error("getpgid", format!("PID is invalid: {error}")))?;
    let process_group = unsafe {
        // SAFETY: getpgid takes a PID value and writes no Rust-owned memory.
        libc::getpgid(target_pid)
    };
    if process_group < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(platform_error(
            "getpgid",
            format!("PID {target_pid}: {error}"),
        ));
    }
    Ok(valid_pid(process_group))
}

/// Pure conversion from one Darwin BSD info read to a tree snapshot row.
///
/// `pbi_ppid` of `0` maps to no parent (kernel/launchd roots), matching how
/// the rest of this module treats PID 0 as "no such process". `pbi_pgid` of
/// `0` likewise maps to no targetable process group; both ride the same
/// fail-closed `proc_bsdinfo` read, which group kill relies on for complete
/// membership.
fn tree_process_info_from_bsd(
    pid: u32,
    info: &libc::proc_bsdinfo,
    process_name: String,
) -> TreeProcessInfo {
    TreeProcessInfo {
        pid,
        parent_pid: nonzero_pid(info.pbi_ppid),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(process_name),
        start_time_marker: Some(process_start_time_marker_from_bsd_info(info)),
        owner_uid: Some(info.pbi_uid),
        process_group: nonzero_pid(info.pbi_pgid),
    }
}

fn collect_pid_entries(pid: u32, entries: &mut Vec<PortEntry>) {
    let Ok(records) = collect_pid_socket_records(pid) else {
        return;
    };
    if records.is_empty() {
        return;
    }

    let metadata = read_process_metadata(pid);
    for record in records {
        entries.push(entry_from_record(&record, &metadata));
    }
}

fn collect_pid_socket_records(pid: u32) -> Result<Vec<SocketRecord>, std::io::Error> {
    let fds = list_socket_fds(pid)?;
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    for fd in fds {
        let Some(record) = socket_record_for_fd(pid, fd) else {
            continue;
        };
        if seen.insert(record.key()) {
            records.push(record);
        }
    }
    Ok(records)
}

fn entry_from_record(record: &SocketRecord, metadata: &ProcessMetadata) -> PortEntry {
    PortEntry {
        protocol: record.protocol,
        local_addr: record.local_addr,
        local_port: record.local_port,
        state: record.state,
        pid: Some(record.pid),
        process_name: metadata.process_name.clone(),
        executable_path: metadata.executable_path.clone(),
        command_line: metadata.command_line.clone(),
        parent_pid: metadata.parent_pid,
        parent_process_name: metadata.parent_process_name.clone(),
        child_pids: Vec::new(),
        protected: false,
        platform: Platform::Macos,
        permission: if metadata.partial {
            PermissionStatus::Partial
        } else {
            PermissionStatus::Full
        },
    }
}

fn read_process_metadata(pid: u32) -> ProcessMetadata {
    let bsd_info = read_process_bsdinfo(pid).ok();
    let process_name = read_process_name(pid)
        .ok()
        .flatten()
        .or_else(|| bsd_info.as_ref().and_then(process_name_from_bsd_info));
    let mut metadata = ProcessMetadata {
        process_name,
        ..ProcessMetadata::default()
    };
    metadata.partial |= metadata.process_name.is_none();

    match read_executable_path(pid) {
        Ok(Some(path)) => metadata.executable_path = Some(path),
        Ok(None) | Err(_) => metadata.partial = true,
    }

    match read_command_line(pid) {
        Ok(command_line) => metadata.command_line = command_line,
        Err(_) => metadata.partial = true,
    }

    if let Some(info) = &bsd_info {
        metadata.parent_pid = nonzero_pid(info.pbi_ppid);
        if let Some(parent_pid) = metadata.parent_pid {
            match read_process_name(parent_pid) {
                Ok(parent_name) => {
                    metadata.parent_process_name = parent_name;
                    metadata.partial |= metadata.parent_process_name.is_none();
                }
                Err(_) => metadata.partial = true,
            }
        }
    } else {
        metadata.partial = true;
    }

    metadata
}

fn collect_child_processes(parent_pid: u32) -> ChildProcessSnapshot {
    let Ok(pids) = process_ids() else {
        return ChildProcessSnapshot::default();
    };

    let mut children = Vec::new();
    let mut truncated = false;
    for pid in pids {
        if pid == parent_pid {
            continue;
        }
        let Ok(info) = read_process_bsdinfo(pid) else {
            continue;
        };
        if nonzero_pid(info.pbi_ppid) != Some(parent_pid) {
            continue;
        }

        if children.len() == MAX_CHILD_PROCESSES {
            truncated = true;
            break;
        }
        children.push(ChildProcess {
            pid,
            process_name: read_process_name(pid)
                .ok()
                .flatten()
                .or_else(|| process_name_from_bsd_info(&info)),
        });
    }

    ChildProcessSnapshot {
        children,
        truncated,
    }
}

fn process_ancestor_pids(pid: u32) -> HashSet<u32> {
    let mut ancestors = HashSet::from([pid]);
    let mut current = pid;
    for _ in 0..MAX_PROCESS_ANCESTORS {
        let Some(parent_pid) = read_process_bsdinfo(current)
            .ok()
            .and_then(|info| nonzero_pid(info.pbi_ppid))
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

fn process_ids() -> Result<Vec<u32>, CollectorError> {
    let initial_count = unsafe {
        // SAFETY: a null buffer and zero size is the documented sizing call for
        // proc_listallpids; it writes no Rust-owned memory.
        libc::proc_listallpids(std::ptr::null_mut(), 0)
    };
    if initial_count < 0 {
        return Err(last_platform_error("proc_listallpids"));
    }
    if initial_count == 0 {
        return Ok(Vec::new());
    }

    let mut capacity = usize::try_from(initial_count)
        .expect("non-negative proc_listallpids count must fit usize")
        .saturating_add(PROCESS_LIST_GROWTH_MARGIN);

    for _ in 0..PID_LIST_ATTEMPTS {
        if capacity > MAX_PROCESS_IDS {
            return Err(platform_error(
                "proc_listallpids",
                format!("process list exceeds {MAX_PROCESS_IDS} PID cap"),
            ));
        }
        let buffer_bytes = checked_buffer_len::<libc::pid_t>(capacity, "proc_listallpids")?;
        let mut raw_pids = vec![0 as libc::pid_t; capacity];
        let count = unsafe {
            // SAFETY: raw_pids owns buffer_bytes bytes and proc_listallpids writes
            // at most that many pid_t values into it.
            libc::proc_listallpids(raw_pids.as_mut_ptr().cast::<c_void>(), buffer_bytes)
        };
        if count < 0 {
            return Err(last_platform_error("proc_listallpids"));
        }

        let count =
            usize::try_from(count).expect("non-negative proc_listallpids count must fit usize");
        if count < raw_pids.len() {
            raw_pids.truncate(count);
            let mut pids = raw_pids
                .into_iter()
                .filter_map(valid_pid)
                .collect::<Vec<_>>();
            pids.sort_unstable();
            pids.dedup();
            return Ok(pids);
        }

        capacity = capacity.saturating_mul(2);
    }

    Err(platform_error(
        "proc_listallpids",
        "process list kept growing while being read".to_owned(),
    ))
}

fn list_socket_fds(pid: u32) -> std::io::Result<Vec<libc::c_int>> {
    let pid = pid_to_c_int(pid)?;
    let needed_bytes = unsafe {
        // SAFETY: null buffer sizing call; no Rust-managed memory is touched.
        libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0)
    };
    if needed_bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if needed_bytes == 0 {
        return Ok(Vec::new());
    }

    let needed_bytes =
        usize::try_from(needed_bytes).expect("non-negative proc_pidinfo byte count must fit usize");
    let mut capacity = needed_bytes
        .div_ceil(size_of::<libc::proc_fdinfo>())
        .saturating_add(FD_LIST_GROWTH_MARGIN);

    for _ in 0..FD_LIST_ATTEMPTS {
        if capacity > MAX_PROCESS_FDS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("fd list exceeds {MAX_PROCESS_FDS} descriptor cap"),
            ));
        }
        let buffer_bytes = checked_io_buffer_len::<libc::proc_fdinfo>(capacity)?;
        let mut fds = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0,
            };
            capacity
        ];
        let written_bytes = unsafe {
            // SAFETY: fds owns buffer_bytes bytes and proc_pidinfo writes at most
            // that many proc_fdinfo records for this PID.
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast::<c_void>(),
                buffer_bytes,
            )
        };
        if written_bytes < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let written_bytes = usize::try_from(written_bytes)
            .expect("non-negative proc_pidinfo byte count must fit usize");
        let count = written_bytes / size_of::<libc::proc_fdinfo>();
        if count < fds.len() {
            fds.truncate(count);
            let socket_fd_type = u32::try_from(libc::PROX_FDTYPE_SOCKET)
                .expect("Darwin socket fd type must fit u32");
            return Ok(fds
                .into_iter()
                .filter(|fd| fd.proc_fdtype == socket_fd_type)
                .map(|fd| fd.proc_fd)
                .collect());
        }

        capacity = capacity.saturating_mul(2);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "fd list kept growing while being read",
    ))
}

fn socket_record_for_fd(pid: u32, fd: libc::c_int) -> Option<SocketRecord> {
    let info = read_socket_fdinfo(pid, fd).ok()?;
    socket_record_from_info(pid, &info)
}

fn read_socket_fdinfo(pid: u32, fd: libc::c_int) -> std::io::Result<SocketFdinfo> {
    let pid = pid_to_c_int(pid)?;
    let expected_bytes = checked_io_buffer_len::<SocketFdinfo>(1)?;
    let mut info = MaybeUninit::<SocketFdinfo>::zeroed();
    let written_bytes = unsafe {
        // SAFETY: info points to one zeroed SocketFdinfo-sized out buffer. The
        // flavor asks libproc to fill exactly that layout for this PID/fd pair.
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            info.as_mut_ptr().cast::<c_void>(),
            expected_bytes,
        )
    };
    if written_bytes <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes != expected_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("socket fd info returned {written_bytes} bytes, expected {expected_bytes}"),
        ));
    }

    let info = unsafe {
        // SAFETY: proc_pidfdinfo reported it initialized the full SocketFdinfo.
        info.assume_init()
    };
    Ok(info)
}

fn socket_record_from_info(pid: u32, info: &SocketFdinfo) -> Option<SocketRecord> {
    let socket = &info.psi;
    match socket.soi_protocol {
        protocol if protocol == libc::IPPROTO_TCP && socket.soi_kind == SOCKINFO_TCP => {
            let tcp = unsafe {
                // SAFETY: soi_kind == SOCKINFO_TCP names pri_tcp as the active
                // protocol payload in Darwin's socket_info union.
                socket.soi_proto.pri_tcp
            };
            if tcp.tcpsi_state != TSI_S_LISTEN {
                return None;
            }
            socket_record_from_in_sockinfo(
                pid,
                Protocol::Tcp,
                SocketState::Listen,
                socket.soi_family,
                socket.soi_so,
                &tcp.tcpsi_ini,
            )
        }
        protocol if protocol == libc::IPPROTO_UDP && socket.soi_kind == SOCKINFO_IN => {
            let udp = unsafe {
                // SAFETY: soi_kind == SOCKINFO_IN names pri_in as the active
                // protocol payload for UDP sockets.
                socket.soi_proto.pri_in
            };
            socket_record_from_in_sockinfo(
                pid,
                Protocol::Udp,
                SocketState::Bound,
                socket.soi_family,
                socket.soi_so,
                &udp,
            )
        }
        _ => None,
    }
}

fn socket_record_from_in_sockinfo(
    pid: u32,
    protocol: Protocol,
    state: SocketState,
    family: libc::c_int,
    socket_id: u64,
    info: &InSockinfo,
) -> Option<SocketRecord> {
    let local_port = decode_port(info.insi_lport)?;
    let local_addr = decode_local_addr(info, family)?;
    Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        pid,
        socket_id,
    })
}

fn decode_port(raw: libc::c_int) -> Option<u16> {
    let masked = u32::try_from(raw).ok()? & u32::from(u16::MAX);
    let port = u16::try_from(masked).expect("masked port must fit u16");
    let port = u16::from_be(port);
    (port != 0).then_some(port)
}

fn decode_local_addr(info: &InSockinfo, family: libc::c_int) -> Option<IpAddr> {
    if info.insi_vflag & INI_IPV4 != 0 || family == libc::AF_INET {
        let raw = unsafe {
            // SAFETY: INI_IPV4/AF_INET says the IPv4 view of the address union is
            // active for this socket.
            info.insi_laddr.ina_46.i46a_addr4.s_addr
        };
        return Some(IpAddr::V4(Ipv4Addr::from(raw.to_ne_bytes())));
    }

    if info.insi_vflag & INI_IPV6 != 0 || family == libc::AF_INET6 {
        let raw = unsafe {
            // SAFETY: INI_IPV6/AF_INET6 says the IPv6 view of the address union is
            // active for this socket.
            info.insi_laddr.ina_6.s6_addr
        };
        let addr = Ipv6Addr::from(raw);
        return Some(addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4));
    }

    None
}

fn read_process_bsdinfo(pid: u32) -> std::io::Result<libc::proc_bsdinfo> {
    let pid = pid_to_c_int(pid)?;
    let expected_bytes = checked_io_buffer_len::<libc::proc_bsdinfo>(1)?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let written_bytes = unsafe {
        // SAFETY: info points to one proc_bsdinfo out buffer; libproc writes at
        // most expected_bytes bytes and does not retain the pointer.
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast::<c_void>(),
            expected_bytes,
        )
    };
    if written_bytes <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes != expected_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("process bsd info returned {written_bytes} bytes, expected {expected_bytes}"),
        ));
    }

    let info = unsafe {
        // SAFETY: proc_pidinfo reported it initialized the full proc_bsdinfo.
        info.assume_init()
    };
    Ok(info)
}

fn read_process_name(pid: u32) -> std::io::Result<Option<String>> {
    let pid = pid_to_c_int(pid)?;
    let mut buffer = [0 as libc::c_char; 64];
    let written_bytes = unsafe {
        // SAFETY: buffer is valid for one proc_name write and is not retained.
        libc::proc_name(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("process-name buffer length fits u32"),
        )
    };
    if written_bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(c_char_slice_to_string(&buffer))
}

fn read_executable_path(pid: u32) -> std::io::Result<Option<PathBuf>> {
    let pid = pid_to_c_int(pid)?;
    let buffer_len = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE)
        .expect("PROC_PIDPATHINFO_MAXSIZE must fit usize");
    let mut buffer = vec![0_u8; buffer_len];
    let written_bytes = unsafe {
        // SAFETY: buffer is valid for one proc_pidpath write and is not retained.
        libc::proc_pidpath(
            pid,
            buffer.as_mut_ptr().cast::<c_void>(),
            u32::try_from(buffer.len()).expect("path buffer length fits u32"),
        )
    };
    if written_bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if written_bytes == 0 {
        return Ok(None);
    }

    let written_bytes = usize::try_from(written_bytes)
        .expect("non-negative proc_pidpath byte count must fit usize");
    buffer.truncate(written_bytes);
    Ok(Some(PathBuf::from(OsStr::from_bytes(&buffer))))
}

fn read_command_line(pid: u32) -> std::io::Result<Option<String>> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid_to_c_int(pid)?];
    let mut buffer_len = 0_usize;
    let result = unsafe {
        // SAFETY: null oldp asks sysctl for the needed buffer length; buffer_len is
        // a valid out pointer for the size.
        libc::sysctl(
            mib.as_mut_ptr(),
            u32::try_from(mib.len()).expect("sysctl MIB length fits u32"),
            std::ptr::null_mut(),
            &raw mut buffer_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if buffer_len == 0 {
        return Ok(None);
    }
    if buffer_len > MAX_PROCARGS_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("process arguments exceed {MAX_PROCARGS_BYTES} byte cap"),
        ));
    }

    let mut buffer = vec![0_u8; buffer_len];
    let result = unsafe {
        // SAFETY: buffer is valid for buffer_len bytes and sysctl does not retain
        // the pointer. The MIB is unchanged from the successful sizing call.
        libc::sysctl(
            mib.as_mut_ptr(),
            u32::try_from(mib.len()).expect("sysctl MIB length fits u32"),
            buffer.as_mut_ptr().cast::<c_void>(),
            &raw mut buffer_len,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(buffer_len);
    Ok(decode_procargs2(&buffer))
}

fn decode_procargs2(bytes: &[u8]) -> Option<String> {
    let argc_bytes = bytes.get(..size_of::<libc::c_int>())?;
    let argument_count = libc::c_int::from_ne_bytes(
        argc_bytes
            .try_into()
            .expect("argc slice length is exactly c_int size"),
    );
    if argument_count <= 0 {
        return None;
    }

    let mut data = &bytes[size_of::<libc::c_int>()..];
    let exe_end = data.iter().position(|byte| *byte == 0)?;
    data = &data[exe_end..];
    while data.first() == Some(&0) {
        data = &data[1..];
    }

    let mut argv = Vec::new();
    for _ in 0..argument_count {
        if data.is_empty() {
            break;
        }
        let end = data
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(data.len());
        let arg = &data[..end];
        if !arg.is_empty() {
            argv.push(String::from_utf8_lossy(arg).into_owned());
        }
        data = &data[end..];
        while data.first() == Some(&0) {
            data = &data[1..];
        }
    }

    if argv.is_empty() {
        None
    } else {
        Some(argv.join(" "))
    }
}

fn process_name_from_bsd_info(info: &libc::proc_bsdinfo) -> Option<String> {
    c_char_slice_to_string(&info.pbi_name).or_else(|| c_char_slice_to_string(&info.pbi_comm))
}

fn process_start_time_marker_from_bsd_info(info: &libc::proc_bsdinfo) -> u64 {
    info.pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(info.pbi_start_tvusec)
}

fn c_char_slice_to_string(bytes: &[libc::c_char]) -> Option<String> {
    let ptr = bytes.as_ptr();
    if ptr.is_null() || bytes.first().copied() == Some(0) {
        return None;
    }

    let nul_index = bytes.iter().position(|byte| *byte == 0)?;
    let text = unsafe {
        // SAFETY: nul_index proves there is a NUL terminator inside bytes, and ptr
        // points to the start of that same live buffer.
        CStr::from_ptr(ptr)
    };
    let text = text.to_string_lossy();
    if nul_index == 0 || text.is_empty() {
        None
    } else {
        Some(text.into_owned())
    }
}

fn nonzero_pid(pid: u32) -> Option<u32> {
    (pid != 0).then_some(pid)
}

fn valid_pid(pid: libc::pid_t) -> Option<u32> {
    u32::try_from(pid).ok().filter(|pid| *pid != 0)
}

fn pid_to_c_int(pid: u32) -> std::io::Result<libc::c_int> {
    libc::c_int::try_from(pid).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PID does not fit platform c_int",
        )
    })
}

fn checked_buffer_len<T>(
    count: usize,
    operation: &'static str,
) -> Result<libc::c_int, CollectorError> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        platform_error(operation, "buffer byte length overflows usize".to_owned())
    })?;
    libc::c_int::try_from(bytes).map_err(|_| {
        platform_error(
            operation,
            "buffer byte length does not fit platform c_int".to_owned(),
        )
    })
}

fn checked_io_buffer_len<T>(count: usize) -> std::io::Result<libc::c_int> {
    let bytes = count.checked_mul(size_of::<T>()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer byte length overflows usize",
        )
    })?;
    libc::c_int::try_from(bytes).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "buffer byte length does not fit platform c_int",
        )
    })
}

fn last_platform_error(operation: &'static str) -> CollectorError {
    let error = std::io::Error::last_os_error();
    platform_error(operation, error.to_string())
}

fn platform_error(operation: &'static str, detail: String) -> CollectorError {
    CollectorError::Platform { operation, detail }
}

#[cfg(test)]
mod tests {
    use std::mem::{MaybeUninit, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        In4In6Addr, InSocketAddress, InSockinfo, InSockinfoV4, InSockinfoV6, SocketFdinfo,
        SocketProtocolInfo, TSI_S_LISTEN, TcpSockinfo, decode_port, decode_procargs2,
        socket_record_from_info,
    };
    use crate::model::{Protocol, SocketState};

    fn zeroed_socket_fdinfo() -> SocketFdinfo {
        unsafe {
            // SAFETY: these C layout structs are plain data buffers in production;
            // tests zero them before filling the fields relevant to record parsing.
            MaybeUninit::<SocketFdinfo>::zeroed().assume_init()
        }
    }

    fn in_sockinfo_v4(port: u16, addr: Ipv4Addr) -> InSockinfo {
        InSockinfo {
            insi_fport: 0,
            insi_lport: i32::from(port.to_be()),
            insi_gencnt: 0,
            insi_flags: 0,
            insi_flow: 0,
            insi_vflag: super::INI_IPV4,
            insi_ip_ttl: 0,
            rfu_1: 0,
            insi_faddr: InSocketAddress {
                ina_46: In4In6Addr {
                    i46a_pad32: [0; 3],
                    i46a_addr4: libc::in_addr { s_addr: 0 },
                },
            },
            insi_laddr: InSocketAddress {
                ina_46: In4In6Addr {
                    i46a_pad32: [0; 3],
                    i46a_addr4: libc::in_addr {
                        s_addr: u32::from_ne_bytes(addr.octets()),
                    },
                },
            },
            insi_v4: InSockinfoV4 { in4_tos: 0 },
            insi_v6: InSockinfoV6 {
                in6_hlim: 0,
                in6_cksum: 0,
                in6_ifindex: 0,
                in6_hops: 0,
            },
        }
    }

    fn in_sockinfo_v6(port: u16, addr: Ipv6Addr) -> InSockinfo {
        InSockinfo {
            insi_vflag: super::INI_IPV6,
            insi_lport: i32::from(port.to_be()),
            insi_laddr: InSocketAddress {
                ina_6: libc::in6_addr {
                    s6_addr: addr.octets(),
                },
            },
            ..in_sockinfo_v4(port, Ipv4Addr::UNSPECIFIED)
        }
    }

    fn procargs2(argument_count: i32, exe: &[u8], argv: &[&[u8]]) -> Vec<u8> {
        let mut bytes = argument_count.to_ne_bytes().to_vec();
        bytes.extend_from_slice(exe);
        bytes.push(0);
        bytes.push(0);
        for arg in argv {
            bytes.extend_from_slice(arg);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn socket_fdinfo_layout_is_large_enough_for_darwin_unix_socket_variant() {
        assert!(size_of::<SocketProtocolInfo>() >= 528);
        assert!(size_of::<SocketFdinfo>() > size_of::<libc::vinfo_stat>());
    }

    #[test]
    fn tcp_listen_socket_info_becomes_a_port_record() {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_TCP;
        info.psi.soi_family = libc::AF_INET;
        info.psi.soi_kind = super::SOCKINFO_TCP;
        info.psi.soi_so = 0xCAFE;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_tcp: TcpSockinfo {
                tcpsi_ini: in_sockinfo_v4(3000, Ipv4Addr::LOCALHOST),
                tcpsi_state: TSI_S_LISTEN,
                tcpsi_timer: [0; 4],
                tcpsi_mss: 0,
                tcpsi_flags: 0,
                rfu_1: 0,
                tcpsi_tp: 0,
            },
        };

        let record = socket_record_from_info(18422, &info).expect("listen socket is kept");

        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(record.state, SocketState::Listen);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
        assert_eq!(record.pid, 18422);
        assert_eq!(record.socket_id, 0xCAFE);
    }

    #[test]
    fn tcp_non_listen_socket_info_is_ignored() {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_TCP;
        info.psi.soi_family = libc::AF_INET;
        info.psi.soi_kind = super::SOCKINFO_TCP;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_tcp: TcpSockinfo {
                tcpsi_ini: in_sockinfo_v4(3000, Ipv4Addr::LOCALHOST),
                tcpsi_state: 4,
                tcpsi_timer: [0; 4],
                tcpsi_mss: 0,
                tcpsi_flags: 0,
                rfu_1: 0,
                tcpsi_tp: 0,
            },
        };

        assert_eq!(socket_record_from_info(18422, &info), None);
    }

    #[test]
    fn udp_socket_info_becomes_a_bound_port_record() {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_UDP;
        info.psi.soi_family = libc::AF_INET6;
        info.psi.soi_kind = super::SOCKINFO_IN;
        info.psi.soi_so = 77;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_in: in_sockinfo_v6(5353, Ipv6Addr::LOCALHOST),
        };

        let record = socket_record_from_info(902, &info).expect("udp socket is kept");

        assert_eq!(record.protocol, Protocol::Udp);
        assert_eq!(record.state, SocketState::Bound);
        assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(record.local_port, 5353);
        assert_eq!(record.pid, 902);
    }

    #[test]
    fn ipv4_mapped_ipv6_socket_info_normalizes_to_ipv4() {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_UDP;
        info.psi.soi_family = libc::AF_INET6;
        info.psi.soi_kind = super::SOCKINFO_IN;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_in: in_sockinfo_v6(3000, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
        };

        let record = socket_record_from_info(18422, &info).expect("mapped socket is kept");

        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
    }

    #[test]
    fn port_decoding_rejects_zero_and_uses_network_byte_order() {
        assert_eq!(decode_port(i32::from(3000_u16.to_be())), Some(3000));
        assert_eq!(decode_port(0), None);
    }

    #[test]
    fn procargs2_decoding_returns_only_argv_not_environment() {
        let mut bytes = procargs2(3, b"/usr/bin/python3", &[b"python3", b"-m", b"http.server"]);
        bytes.extend_from_slice(b"PORT=3000\0");

        let command = decode_procargs2(&bytes).expect("argv should decode");

        assert_eq!(command, "python3 -m http.server");
        assert!(!command.contains("PORT=3000"));
    }

    #[test]
    fn procargs2_decoding_rejects_empty_or_malformed_data() {
        assert_eq!(decode_procargs2(&[]), None);
        assert_eq!(decode_procargs2(&0_i32.to_ne_bytes()), None);
        assert_eq!(decode_procargs2(&1_i32.to_ne_bytes()), None);
    }

    #[test]
    fn tree_snapshot_row_maps_parent_and_start_marker_from_bsd_info() {
        let mut info = unsafe {
            // SAFETY: proc_bsdinfo is a plain-data C struct; the test zeroes it
            // and then sets only the fields the conversion reads.
            MaybeUninit::<libc::proc_bsdinfo>::zeroed().assume_init()
        };
        info.pbi_ppid = 100;
        info.pbi_pgid = 4242;
        info.pbi_start_tvsec = 1_700_000_000;
        info.pbi_start_tvusec = 250_000;

        let row = super::tree_process_info_from_bsd(4242, &info, "node".to_owned());

        assert_eq!(row.pid, 4242);
        assert_eq!(row.parent_pid, Some(100));
        assert_eq!(row.process_name.as_deref(), Some("node"));
        assert_eq!(row.process_group, Some(4242));
        // Seconds and microseconds fold into one marker so equal-second reuse
        // of a PID still changes identity.
        assert_eq!(
            row.start_time_marker,
            Some(1_700_000_000 * 1_000_000 + 250_000)
        );

        // A launchd/kernel-rooted process reports parent PID 0, which must map
        // to "no parent", never to a real PID 0 edge.
        info.pbi_ppid = 0;
        let row = super::tree_process_info_from_bsd(1, &info, "launchd".to_owned());
        assert_eq!(row.parent_pid, None);
    }

    #[test]
    fn tree_snapshot_skips_vanished_and_system_restricted_processes() {
        let vanished = std::io::Error::from_raw_os_error(libc::ESRCH);
        let denied = std::io::Error::from_raw_os_error(libc::EPERM);
        let interrupted = std::io::Error::from_raw_os_error(libc::EINTR);

        assert!(super::should_skip_unreadable_snapshot_error(&vanished));
        assert!(super::should_skip_unreadable_snapshot_error(&denied));
        assert!(!super::should_skip_unreadable_snapshot_error(&interrupted));
    }
}
