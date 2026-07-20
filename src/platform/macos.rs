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

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::ffi::{CStr, OsStr, c_void};
use std::mem::{MaybeUninit, align_of, offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint,
};
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact,
    FILE_DESCRIPTOR_ENTRIES_MAX, Ipv6Scope, MetadataCompleteness, MetadataOmission,
    MetadataProfile, NATIVE_RESIZE_ATTEMPTS_MAX, NativeSocketObservation, NetworkSnapshot,
    ObservationScope, ObservationScopeKind, OwnerAssociations, OwnerCompleteness,
    PlatformSocketToken, ProcessIdentity, ProcessObservation, ProcessRead, ProcessStartMarker,
    ScopeLimitation, SocketState as ObservationSocketState, UnverifiedOwnerReason,
};
use crate::observation::{OWNER_EDGES_MAX, SOCKET_OBSERVATIONS_MAX};
use crate::process::{tree_cont, tree_deliver_by_pid, tree_prepare_delivery_probe, tree_stop};
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
use crate::tree::{
    MAX_TREE_PROCESSES, TreeProcessInfo, TreeProcessOps, TreeSignalResult, TreeSnapshotScope,
};

const PROCESS_LIST_GROWTH_MARGIN: usize = 64;
const FD_LIST_GROWTH_MARGIN: usize = 16;
const MAX_PROCESS_FDS: usize = 65_536;
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;

const PROC_PIDFDSOCKETINFO: libc::c_int = 3;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;
const SOCKINFO_IN: libc::c_int = 1;
const SOCKINFO_TCP: libc::c_int = 2;
const TSI_S_CLOSED: libc::c_int = 0;
const TSI_S_LISTEN: libc::c_int = 1;
const TSI_S_SYN_SENT: libc::c_int = 2;
const TSI_S_SYN_RECEIVED: libc::c_int = 3;
const TSI_S_ESTABLISHED: libc::c_int = 4;
const TSI_S_CLOSE_WAIT: libc::c_int = 5;
const TSI_S_FIN_WAIT_1: libc::c_int = 6;
const TSI_S_CLOSING: libc::c_int = 7;
const TSI_S_LAST_ACK: libc::c_int = 8;
const TSI_S_FIN_WAIT_2: libc::c_int = 9;
const TSI_S_TIME_WAIT: libc::c_int = 10;
const SOCK_MAXADDRLEN: usize = 255;
const MAX_KCTL_NAME: usize = 96;

pub(crate) struct MacosCollector;

impl Collector for MacosCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentHostProcessVisibleSockets,
            None,
            [
                ScopeLimitation::ProcessFirstSocketVisibilityLimited,
                ScopeLimitation::Ipv6ScopeUnavailable,
                ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
            ],
        )?;
        crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| Self::collect_native_pass(),
            Self::read_native_processes,
        )
    }
}

impl MacosCollector {
    fn read_native_processes(
        pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<std::collections::BTreeMap<u32, ProcessRead>, CollectorError> {
        let mut parent_names = HashMap::new();
        crate::collector::read_processes_sequentially(
            pids,
            profile,
            optional_metadata_bytes_remaining,
            |pid, profile, remaining| {
                Ok(Self::read_native_process(
                    pid,
                    profile,
                    remaining,
                    &mut parent_names,
                ))
            },
        )
    }

    fn collect_native_pass() -> Result<crate::observation::NativeObservationPass, CollectorError> {
        Self::collect_native_pass_with(process_ids, collect_pid_socket_records)
    }

    fn collect_native_pass_with<ListProcesses, ScanProcess>(
        mut list_processes: ListProcesses,
        mut scan_process: ScanProcess,
    ) -> Result<crate::observation::NativeObservationPass, CollectorError>
    where
        ListProcesses: FnMut() -> Result<Vec<u32>, CollectorError>,
        ScanProcess: FnMut(
            u32,
            &mut usize,
        )
            -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error>,
    {
        let mut grouped_records = Vec::<SocketRecord>::new();
        let mut owners_by_socket = Vec::<Vec<u32>>::new();
        let mut socket_indexes = HashMap::<u64, usize>::new();
        let mut socket_set_losses = BTreeSet::new();
        let mut omitted_socket_set_loss_count = 0u64;
        let pids = match list_processes() {
            Ok(pids) => pids,
            Err(CollectorError::Observation(
                crate::observation::ObservationError::ProcessIdentityLimitExceeded,
            )) => {
                return Err(
                    crate::observation::ObservationError::ProcessIdentityLimitExceeded.into(),
                );
            }
            Err(error) => return Err(error),
        };
        let mut aggregate_fd_entries = 0usize;
        let mut owner_edges = 0usize;
        for pid in pids {
            let (records, pid_losses) = match scan_process(pid, &mut aggregate_fd_entries) {
                Ok(scan) => scan,
                Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                    return Err(crate::observation::ObservationError::NativeDataOversized.into());
                }
                Err(error) if error.kind() == std::io::ErrorKind::OutOfMemory => {
                    return Err(platform_error(
                        "proc_pidinfo(PROC_PIDLISTFDS)",
                        error.to_string(),
                    ));
                }
                Err(error) => {
                    retain_socket_scan_loss(
                        &mut socket_set_losses,
                        &mut omitted_socket_set_loss_count,
                        socket_scan_loss(pid, &error),
                    );
                    continue;
                }
            };
            for loss in pid_losses {
                retain_socket_scan_loss(
                    &mut socket_set_losses,
                    &mut omitted_socket_set_loss_count,
                    loss,
                );
            }
            for record in records {
                retain_socket_record(
                    &mut grouped_records,
                    &mut owners_by_socket,
                    &mut socket_indexes,
                    &mut owner_edges,
                    &mut socket_set_losses,
                    &mut omitted_socket_set_loss_count,
                    record,
                    pid,
                )?;
            }
        }
        native_pass_from_records(
            &grouped_records,
            owners_by_socket,
            socket_set_losses,
            omitted_socket_set_loss_count,
        )
    }

    fn read_native_process(
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
        parent_names: &mut HashMap<ProcessIdentity, ParentNameRead>,
    ) -> ProcessRead {
        let info = match read_process_bsdinfo(pid) {
            Ok(info) => info,
            Err(error) => return ProcessRead::Unverified(unverified_reason_for_io(&error)),
        };
        let Ok(microseconds) = u32::try_from(info.pbi_start_tvusec) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        let Ok(marker) = ProcessStartMarker::macos(info.pbi_start_tvsec, microseconds) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        if profile == MetadataProfile::IdentityOnly {
            return ProcessRead::Verified {
                marker,
                observation: ProcessObservation::identity_only(),
            };
        }
        let metadata = if optional_metadata_bytes_remaining == 0 {
            ProcessMetadata {
                partial: true,
                budget_omitted: true,
                ..ProcessMetadata::default()
            }
        } else {
            read_process_metadata_bounded(
                pid,
                profile,
                optional_metadata_bytes_remaining,
                parent_names,
            )
        };
        let after = match read_process_bsdinfo(pid) {
            Ok(info) => info,
            Err(error) => return ProcessRead::Unverified(unverified_reason_for_io(&error)),
        };
        let Ok(after_microseconds) = u32::try_from(after.pbi_start_tvusec) else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        let Ok(marker_after) = ProcessStartMarker::macos(after.pbi_start_tvsec, after_microseconds)
        else {
            return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
        };
        if marker_after != marker {
            return ProcessRead::Unverified(UnverifiedOwnerReason::Raced);
        }
        ProcessRead::Verified {
            marker: marker_after,
            observation: process_observation_from_metadata(metadata),
        }
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "bounded socket, owner, token-conflict, and evidence stores are updated atomically"
)]
fn retain_socket_record(
    grouped_records: &mut Vec<SocketRecord>,
    owners_by_socket: &mut Vec<Vec<u32>>,
    socket_indexes: &mut HashMap<u64, usize>,
    owner_edges: &mut usize,
    socket_set_losses: &mut BTreeSet<SocketScanLoss>,
    omitted_socket_set_loss_count: &mut u64,
    record: SocketRecord,
    pid: u32,
) -> Result<(), CollectorError> {
    let socket_token = (record.socket_id != 0).then_some(record.socket_id);
    if let Some(token) = socket_token
        && let Some(index) = socket_indexes.get(&token).copied()
    {
        if !grouped_records[index].same_non_owner_facts(&record) {
            retain_socket_scan_loss(
                socket_set_losses,
                omitted_socket_set_loss_count,
                SocketScanLoss::TokenConflict,
            );
            return Ok(());
        }
        if sorted_owner_is_new(&owners_by_socket[index], pid) {
            if *owner_edges >= OWNER_EDGES_MAX {
                return Err(
                    crate::observation::ObservationError::OwnerAttributionLimitExceeded.into(),
                );
            }
            owners_by_socket[index].push(pid);
            *owner_edges += 1;
        }
        return Ok(());
    }
    if grouped_records.len() >= SOCKET_OBSERVATIONS_MAX {
        return Err(crate::observation::ObservationError::SocketObservationLimitExceeded.into());
    }
    if *owner_edges >= OWNER_EDGES_MAX {
        return Err(crate::observation::ObservationError::OwnerAttributionLimitExceeded.into());
    }
    if let Some(token) = socket_token {
        socket_indexes.insert(token, grouped_records.len());
    }
    grouped_records.push(record);
    owners_by_socket.push(vec![pid]);
    *owner_edges += 1;
    Ok(())
}

fn sorted_owner_is_new(owners: &[u32], pid: u32) -> bool {
    owners.last().copied() != Some(pid)
}

pub(crate) fn fresh_process_evidence(
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    let before =
        read_process_bsdinfo(pid).map_err(|error| process_evidence_io_error(pid, &error))?;
    let name = read_process_name(pid)
        .map_err(|error| process_evidence_io_error(pid, &error))?
        .or_else(|| process_name_from_bsd_info(&before))
        .ok_or(ProcessEvidenceError::NameMissing { pid })?;
    let after =
        read_process_bsdinfo(pid).map_err(|error| process_evidence_io_error(pid, &error))?;
    fresh_process_evidence_from_reads(pid, &before, name, &after)
}

fn fresh_process_evidence_from_reads(
    pid: u32,
    before: &libc::proc_bsdinfo,
    name: String,
    after: &libc::proc_bsdinfo,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    if name.is_empty() {
        return Err(ProcessEvidenceError::NameMissing { pid });
    }
    let before_marker = process_start_time_marker_from_bsd_info(before)
        .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?;
    let after_marker = process_start_time_marker_from_bsd_info(after)
        .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?;
    if before_marker != after_marker {
        return Err(ProcessEvidenceError::IdentityChanged { pid });
    }
    if name.len() > crate::observation::PROTECTION_NAME_MAX_BYTES {
        return Err(ProcessEvidenceError::NameOversized {
            pid,
            bytes: name.len(),
        });
    }
    Ok(FreshProcessEvidence {
        pid,
        start_marker: after_marker,
        name,
    })
}

fn process_evidence_io_error(pid: u32, error: &std::io::Error) -> ProcessEvidenceError {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => ProcessEvidenceError::PermissionDenied { pid },
        _ => ProcessEvidenceError::Missing { pid },
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
    state: ObservationSocketState,
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

    fn same_non_owner_facts(&self, other: &Self) -> bool {
        self.protocol == other.protocol
            && self.local_addr == other.local_addr
            && self.local_port == other.local_port
            && self.state == other.state
            && self.socket_id == other.socket_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SocketScanLoss {
    TokenConflict,
    PermissionDenied(u32),
    Disappeared(u32),
    Malformed(u32),
    Unavailable(u32),
}

fn native_pass_from_records(
    records: &[SocketRecord],
    owners_by_socket: Vec<Vec<u32>>,
    losses: BTreeSet<SocketScanLoss>,
    mut omitted_evidence_gap_count: u64,
) -> Result<crate::observation::NativeObservationPass, CollectorError> {
    if records.len() != owners_by_socket.len() {
        return Err(crate::observation::ObservationError::NativeDataMalformed.into());
    }
    let sockets = records
        .iter()
        .map(|record| {
            let ipv6_scope = record
                .local_addr
                .is_ipv6()
                .then_some(Ipv6Scope::Unavailable);
            let endpoint = EndpointIdentity::new(
                record.protocol,
                record.local_addr,
                u32::from(record.local_port),
                ipv6_scope,
            )
            .map_err(|error| {
                CollectorError::Observation(
                    crate::observation::ObservationError::PlatformApiFailed(error.to_string()),
                )
            })?;
            Ok(NativeSocketObservation {
                endpoint,
                state: record.state,
                timer: None,
                token: PlatformSocketToken::macos_socket_id(record.socket_id),
            })
        })
        .collect::<Result<Vec<_>, CollectorError>>()?;

    let mut evidence_gaps = Vec::with_capacity(losses.len());
    for loss in losses {
        let (pid, code, message) = match loss {
            SocketScanLoss::TokenConflict => (
                None,
                EvidenceGapCode::NativeFieldUnavailable,
                "conflicting facts for one native socket token made the socket set ambiguous",
            ),
            SocketScanLoss::PermissionDenied(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerPermissionDenied,
                "permission denied before the PID's socket descriptors could be enumerated",
            ),
            SocketScanLoss::Disappeared(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerDisappeared,
                "PID or socket descriptor disappeared during socket enumeration",
            ),
            SocketScanLoss::Malformed(pid) => (
                Some(pid),
                EvidenceGapCode::NativeFieldUnavailable,
                "malformed socket descriptor information could have hidden a socket",
            ),
            SocketScanLoss::Unavailable(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerAttributionIncomplete,
                "a PID socket scan failed before its socket set could be enumerated",
            ),
        };
        evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            code,
            None,
            pid,
            message,
        ));
    }
    if sockets
        .iter()
        .any(|socket| socket.endpoint.ipv6_scope == Some(Ipv6Scope::Unavailable))
    {
        if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
            evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::Scope,
                EvidenceGapCode::NativeFieldUnavailable,
                None,
                None,
                "IPv6 scope identifiers are unavailable from macOS socket descriptor rows",
            ));
        } else {
            omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
        }
    }
    let local_completeness = vec![OwnerCompleteness::Complete; sockets.len()];
    Ok(crate::observation::NativeObservationPass {
        sockets,
        owners: OwnerAssociations {
            owners_by_socket,
            local_completeness,
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps,
            omitted_evidence_gap_count,
        },
    })
}

fn socket_scan_loss(pid: u32, error: &std::io::Error) -> SocketScanLoss {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => SocketScanLoss::PermissionDenied(pid),
        Some(libc::ESRCH | libc::ENOENT) => SocketScanLoss::Disappeared(pid),
        _ if error.kind() == std::io::ErrorKind::InvalidData => SocketScanLoss::Malformed(pid),
        _ => SocketScanLoss::Unavailable(pid),
    }
}

fn retain_socket_scan_loss(
    losses: &mut BTreeSet<SocketScanLoss>,
    omitted: &mut u64,
    loss: SocketScanLoss,
) {
    if losses.contains(&loss) {
        return;
    }
    if losses.len() < crate::observation::EVIDENCE_GAPS_MAX {
        losses.insert(loss);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn process_observation_from_metadata(mut metadata: ProcessMetadata) -> ProcessObservation {
    if metadata
        .executable_path
        .as_ref()
        .is_some_and(|path| path.to_str().is_none())
    {
        metadata.executable_path = None;
        metadata.partial = true;
    }
    ProcessObservation {
        name: metadata.process_name.map(Into::into),
        executable_path: metadata.executable_path.map(Into::into),
        command_line: metadata.command_line.map(Into::into),
        parent_pid: metadata.parent_pid,
        parent_process_name: metadata.parent_process_name.map(Into::into),
        metadata_omission: metadata
            .budget_omitted
            .then_some(MetadataOmission::BudgetExceeded),
        metadata_completeness: if metadata.partial {
            MetadataCompleteness::Partial
        } else {
            MetadataCompleteness::Complete
        },
    }
}

fn unverified_reason_for_io(error: &std::io::Error) -> UnverifiedOwnerReason {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => UnverifiedOwnerReason::PermissionDenied,
        Some(libc::ESRCH | libc::ENOENT) => UnverifiedOwnerReason::Disappeared,
        _ => UnverifiedOwnerReason::IdentityUnavailable,
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
    budget_omitted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParentNameRead {
    Value(String),
    Unavailable,
    BudgetExceeded,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandLineRead {
    Missing,
    Value(String),
    Omitted,
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

// These layouts are the public 64-bit Darwin ABI from <sys/proc_info.h>.
// Both supported macOS targets use the same LP64 layout. Keeping the checks in
// production source makes both cross-target builds reject ABI drift even when
// target tests cannot execute on the build host.
const _: () = {
    assert!(PROC_PIDFDSOCKETINFO == 3);
    assert!(INI_IPV4 == 1);
    assert!(INI_IPV6 == 2);
    assert!(SOCKINFO_IN == 1);
    assert!(SOCKINFO_TCP == 2);
    assert!(libc::PROX_FDTYPE_SOCKET == 2);

    assert!(size_of::<ProcFileinfo>() == 24);
    assert!(align_of::<ProcFileinfo>() == 8);
    assert!(offset_of!(ProcFileinfo, fi_openflags) == 0);
    assert!(offset_of!(ProcFileinfo, fi_status) == 4);
    assert!(offset_of!(ProcFileinfo, fi_offset) == 8);
    assert!(offset_of!(ProcFileinfo, fi_type) == 16);
    assert!(offset_of!(ProcFileinfo, fi_guardflags) == 20);

    assert!(size_of::<In4In6Addr>() == 16);
    assert!(align_of::<In4In6Addr>() == 4);
    assert!(size_of::<InSocketAddress>() == 16);
    assert!(align_of::<InSocketAddress>() == 4);
    assert!(size_of::<InSockinfo>() == 80);
    assert!(align_of::<InSockinfo>() == 8);
    assert!(offset_of!(InSockinfo, insi_fport) == 0);
    assert!(offset_of!(InSockinfo, insi_lport) == 4);
    assert!(offset_of!(InSockinfo, insi_gencnt) == 8);
    assert!(offset_of!(InSockinfo, insi_flags) == 16);
    assert!(offset_of!(InSockinfo, insi_flow) == 20);
    assert!(offset_of!(InSockinfo, insi_vflag) == 24);
    assert!(offset_of!(InSockinfo, insi_ip_ttl) == 25);
    assert!(offset_of!(InSockinfo, rfu_1) == 28);
    assert!(offset_of!(InSockinfo, insi_faddr) == 32);
    assert!(offset_of!(InSockinfo, insi_laddr) == 48);
    assert!(offset_of!(InSockinfo, insi_v4) == 64);
    assert!(offset_of!(InSockinfo, insi_v6) == 68);
    assert!(offset_of!(InSockinfoV6, in6_ifindex) == 8);

    assert!(size_of::<TcpSockinfo>() == 120);
    assert!(align_of::<TcpSockinfo>() == 8);
    assert!(offset_of!(TcpSockinfo, tcpsi_ini) == 0);
    assert!(offset_of!(TcpSockinfo, tcpsi_state) == 80);
    assert!(offset_of!(TcpSockinfo, tcpsi_timer) == 84);
    assert!(offset_of!(TcpSockinfo, tcpsi_mss) == 100);
    assert!(offset_of!(TcpSockinfo, tcpsi_flags) == 104);
    assert!(offset_of!(TcpSockinfo, rfu_1) == 108);
    assert!(offset_of!(TcpSockinfo, tcpsi_tp) == 112);

    assert!(size_of::<UnSockinfo>() == 528);
    assert!(align_of::<UnSockinfo>() == 8);
    assert!(size_of::<SocketProtocolInfo>() == 528);
    assert!(align_of::<SocketProtocolInfo>() == 8);
    assert!(size_of::<SockbufInfo>() == 24);
    assert!(align_of::<SockbufInfo>() == 4);

    assert!(size_of::<libc::vinfo_stat>() == 136);
    assert!(align_of::<libc::vinfo_stat>() == 8);
    assert!(size_of::<SocketInfo>() == 768);
    assert!(align_of::<SocketInfo>() == 8);
    assert!(offset_of!(SocketInfo, soi_stat) == 0);
    assert!(offset_of!(SocketInfo, soi_so) == 136);
    assert!(offset_of!(SocketInfo, soi_pcb) == 144);
    assert!(offset_of!(SocketInfo, soi_type) == 152);
    assert!(offset_of!(SocketInfo, soi_protocol) == 156);
    assert!(offset_of!(SocketInfo, soi_family) == 160);
    assert!(offset_of!(SocketInfo, soi_options) == 164);
    assert!(offset_of!(SocketInfo, soi_state) == 168);
    assert!(offset_of!(SocketInfo, soi_oobmark) == 180);
    assert!(offset_of!(SocketInfo, soi_rcv) == 184);
    assert!(offset_of!(SocketInfo, soi_snd) == 208);
    assert!(offset_of!(SocketInfo, soi_kind) == 232);
    assert!(offset_of!(SocketInfo, rfu_1) == 236);
    assert!(offset_of!(SocketInfo, soi_proto) == 240);

    assert!(size_of::<SocketFdinfo>() == 792);
    assert!(align_of::<SocketFdinfo>() == 8);
    assert!(offset_of!(SocketFdinfo, pfi) == 0);
    assert!(offset_of!(SocketFdinfo, psi) == 24);
};

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let bsd_info = read_process_bsdinfo(pid).ok();
    ProcessContext {
        owner_uid: bsd_info.as_ref().map(|info| info.pbi_uid),
        process_start_time_marker: bsd_info
            .as_ref()
            .and_then(|info| process_start_time_marker_from_bsd_info(info).ok()),
        children: collect_child_processes(pid),
        docker: None,
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    read_process_bsdinfo(pid)
        .ok()
        .and_then(|info| process_start_time_marker_from_bsd_info(&info).ok())
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
    verified_markers: std::collections::HashMap<u32, ProcessStartMarker>,
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
    /// `Ok(())` only when a recorded marker still matches; `Err` when identity
    /// is unavailable, the process is gone, or the PID was recycled.
    fn recheck_marker(&self, pid: u32) -> Result<(), TreeSignalResult> {
        let Some(expected) = self.verified_markers.get(&pid) else {
            return Err(TreeSignalResult::Denied);
        };
        match read_process_bsdinfo(pid) {
            Ok(info) if process_start_time_marker_from_bsd_info(&info).ok() == Some(*expected) => {
                Ok(())
            }
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

    fn cont(&mut self, pid: u32) -> TreeSignalResult {
        match self.recheck_marker(pid) {
            Ok(()) => tree_cont(pid),
            Err(TreeSignalResult::NotFound) => TreeSignalResult::NotFound,
            Err(TreeSignalResult::Denied) => TreeSignalResult::Denied,
            Err(TreeSignalResult::Delivered) => unreachable!("recheck_marker never delivers"),
        }
    }

    fn prepare_thaw(&mut self, pid: u32, marker: Option<ProcessStartMarker>) {
        if let Some(marker) = marker {
            self.verified_markers.insert(pid, marker);
        }
    }

    fn prepare_delivery(
        &mut self,
        pid: u32,
        verified_start_marker: Option<ProcessStartMarker>,
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

    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        fresh_process_evidence(pid)
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
    tree_process_info_from_bsd(pid, info, name)
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
    child_process_ids_with_reader(&mut raw_pids, buffer_bytes, |buffer, buffer_bytes| {
        call_count_api(|| unsafe {
            // SAFETY: buffer owns buffer_bytes bytes and proc_listchildpids writes
            // at most that many pid_t values into it. The count is capped at one
            // past the tree limit; that is enough for the shared cap refusal.
            libc::proc_listchildpids(
                parent_pid,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer_bytes,
            )
        })
    })
}

fn child_process_ids_with_reader<Read>(
    raw_pids: &mut Vec<libc::pid_t>,
    buffer_bytes: libc::c_int,
    mut read: Read,
) -> Result<Vec<u32>, CollectorError>
where
    Read: FnMut(&mut [libc::pid_t], libc::c_int) -> std::io::Result<libc::c_int>,
{
    let count = match read(raw_pids, buffer_bytes) {
        Ok(count) => count,
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => return Ok(Vec::new()),
        Err(error) => return Err(platform_error("proc_listchildpids", error.to_string())),
    };
    if count < 0 {
        return Err(platform_error(
            "proc_listchildpids",
            "negative child process count".to_owned(),
        ));
    }

    let count = usize::try_from(count).expect("non-negative child PID count must fit usize");
    raw_pids.truncate(count.min(raw_pids.len()));
    let mut pids = std::mem::take(raw_pids)
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
) -> Result<TreeProcessInfo, CollectorError> {
    let start_time_marker = process_start_time_marker_from_bsd_info(info).map_err(|error| {
        platform_error(
            "proc_pidinfo(PROC_PIDTBSDINFO)",
            format!("PID {pid}: invalid process start marker: {error}"),
        )
    })?;
    Ok(TreeProcessInfo {
        pid,
        parent_pid: nonzero_pid(info.pbi_ppid),
        unverified_parent_pid: None,
        parent_process_name: None,
        process_name: Some(process_name),
        start_time_marker: Some(start_time_marker),
        owner_uid: Some(info.pbi_uid),
        process_group: nonzero_pid(info.pbi_pgid),
    })
}

fn collect_pid_socket_records(
    pid: u32,
    aggregate_fd_entries: &mut usize,
) -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error> {
    let remaining = FILE_DESCRIPTOR_ENTRIES_MAX.saturating_sub(*aggregate_fd_entries);
    let fds = list_process_fds(pid, remaining)?;
    collect_pid_socket_records_from_fds(
        pid,
        &fds,
        aggregate_fd_entries,
        FILE_DESCRIPTOR_ENTRIES_MAX,
        |fd| socket_record_for_fd(pid, fd),
    )
}

fn collect_pid_socket_records_from_fds<ReadFd>(
    pid: u32,
    fds: &[libc::proc_fdinfo],
    aggregate_fd_entries: &mut usize,
    max_aggregate_fds: usize,
    mut read_fd: ReadFd,
) -> Result<(Vec<SocketRecord>, BTreeSet<SocketScanLoss>), std::io::Error>
where
    ReadFd: FnMut(libc::c_int) -> std::io::Result<Option<SocketRecord>>,
{
    *aggregate_fd_entries = aggregate_fd_entries.checked_add(fds.len()).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::FileTooLarge, "FD count overflow")
    })?;
    if *aggregate_fd_entries > max_aggregate_fds {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("aggregate FD traversal exceeds {max_aggregate_fds} entries"),
        ));
    }
    let mut records = Vec::new();
    let mut seen = HashSet::new();
    let mut losses = BTreeSet::new();
    for fd in fds {
        if fd.proc_fdtype
            != u32::try_from(libc::PROX_FDTYPE_SOCKET).expect("Darwin socket fd type must fit u32")
        {
            continue;
        }
        let record = match read_fd(fd.proc_fd) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) => {
                losses.insert(socket_scan_loss(pid, &error));
                continue;
            }
        };
        if record.socket_id == 0 || seen.insert(record.key()) {
            records.push(record);
        }
    }
    Ok((records, losses))
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered native metadata reads share one aggregate byte budget"
)]
fn read_process_metadata_bounded(
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
    parent_names: &mut HashMap<ProcessIdentity, ParentNameRead>,
) -> ProcessMetadata {
    if profile == MetadataProfile::IdentityOnly {
        return ProcessMetadata::default();
    }
    let bsd_info = read_process_bsdinfo(pid).ok();
    let name_budget = aggregate_remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
    let process_name = read_process_name_bounded(pid, name_budget)
        .ok()
        .flatten()
        .or_else(|| {
            bsd_info
                .as_ref()
                .and_then(|info| process_name_from_bsd_info_bounded(info, name_budget))
        });
    let mut metadata = ProcessMetadata {
        process_name,
        ..ProcessMetadata::default()
    };
    metadata.budget_omitted =
        metadata.process_name.is_none() && name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
    metadata.partial |= metadata.process_name.is_none();
    let mut remaining =
        aggregate_remaining.saturating_sub(metadata.process_name.as_ref().map_or(0, String::len));

    match read_executable_path_bounded(
        pid,
        remaining.min(crate::observation::EXECUTABLE_PATH_MAX_BYTES),
    ) {
        Ok(Some(path)) => {
            remaining = remaining.saturating_sub(path.as_os_str().as_bytes().len());
            metadata.executable_path = Some(path);
        }
        Ok(None) => metadata.partial = true,
        Err(_) => {
            metadata.partial = true;
            metadata.budget_omitted |= remaining < crate::observation::EXECUTABLE_PATH_MAX_BYTES;
        }
    }

    if let Some(info) = &bsd_info {
        metadata.parent_pid = nonzero_pid(info.pbi_ppid);
        if let Some(parent_pid) = metadata.parent_pid {
            let parent = read_process_bsdinfo(parent_pid)
                .ok()
                .and_then(|parent_info| {
                    let start_marker =
                        process_start_time_marker_from_bsd_info(&parent_info).ok()?;
                    let identity = ProcessIdentity {
                        pid: parent_pid,
                        start_marker,
                    };
                    if let Some(name) = parent_names.get(&identity) {
                        return Some(parent_name_for_budget(name, remaining));
                    }
                    let name = read_process_name_budgeted(
                        parent_pid,
                        remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES),
                    )
                    .unwrap_or(ParentNameRead::Unavailable);
                    read_process_bsdinfo(parent_pid)
                        .ok()
                        .and_then(|after| process_start_time_marker_from_bsd_info(&after).ok())
                        .filter(|after| *after == start_marker)?;
                    parent_names.insert(identity, name.clone());
                    Some(name)
                });
            retain_parent_process_name(&mut metadata, parent);
            remaining = remaining
                .saturating_sub(metadata.parent_process_name.as_ref().map_or(0, String::len));
        }
    } else {
        metadata.partial = true;
    }

    if profile == MetadataProfile::LegacyList {
        let command_line = read_command_line_bounded(
            pid,
            remaining.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES),
        );
        apply_command_line_read(&mut metadata, command_line, remaining);
    }

    metadata
}

fn retain_parent_process_name(metadata: &mut ProcessMetadata, parent_name: Option<ParentNameRead>) {
    match parent_name {
        Some(ParentNameRead::Value(name)) => metadata.parent_process_name = Some(name),
        Some(ParentNameRead::BudgetExceeded) => {
            metadata.partial = true;
            metadata.budget_omitted = true;
        }
        Some(ParentNameRead::Unavailable) | None => metadata.partial = true,
    }
}

fn parent_name_for_budget(parent_name: &ParentNameRead, max_bytes: usize) -> ParentNameRead {
    match parent_name {
        ParentNameRead::Value(name) if name.len() > max_bytes => ParentNameRead::BudgetExceeded,
        _ => parent_name.clone(),
    }
}

fn apply_command_line_read(
    metadata: &mut ProcessMetadata,
    read: std::io::Result<CommandLineRead>,
    remaining: usize,
) {
    match read {
        Ok(CommandLineRead::Value(command_line)) => {
            metadata.command_line = Some(command_line);
        }
        Ok(CommandLineRead::Omitted) => {
            metadata.partial = true;
            metadata.budget_omitted = true;
        }
        Ok(CommandLineRead::Missing) | Err(_) => {
            metadata.partial = true;
            metadata.budget_omitted |=
                remaining < crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        }
    }
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
    process_ids_with_reader(|buffer, buffer_bytes| {
        let (buffer, buffer_bytes) = buffer.map_or((std::ptr::null_mut(), 0), |buffer| {
            (buffer.as_mut_ptr().cast::<c_void>(), buffer_bytes)
        });
        match call_count_api(|| unsafe {
            // SAFETY: a null buffer and zero size is the documented sizing call.
            // Otherwise buffer owns buffer_bytes bytes and libproc does not retain it.
            libc::proc_listallpids(buffer, buffer_bytes)
        }) {
            Err(error) => {
                if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
                    Err(crate::observation::ObservationError::SocketTablePermissionDenied.into())
                } else {
                    Err(platform_error("proc_listallpids", error.to_string()))
                }
            }
            Ok(count) => Ok(count),
        }
    })
}

fn call_count_api<Call>(call: Call) -> std::io::Result<libc::c_int>
where
    Call: FnOnce() -> libc::c_int,
{
    unsafe {
        // SAFETY: __error returns this thread's valid errno slot. libproc uses
        // zero for both an empty result and failure, so stale errno must be gone.
        *libc::__error() = 0;
    }
    let count = call();
    let errno = if count <= 0 {
        unsafe {
            // SAFETY: __error returns this thread's valid errno slot.
            *libc::__error()
        }
    } else {
        0
    };
    count_result(count, errno)
}

fn count_result(count: libc::c_int, errno: libc::c_int) -> std::io::Result<libc::c_int> {
    if count < 0 || (count == 0 && errno != 0) {
        Err(std::io::Error::from_raw_os_error(errno))
    } else {
        Ok(count)
    }
}

fn process_ids_with_reader<Read>(mut read: Read) -> Result<Vec<u32>, CollectorError>
where
    Read: FnMut(Option<&mut [libc::pid_t]>, libc::c_int) -> Result<libc::c_int, CollectorError>,
{
    let initial_count = read(None, 0)?;
    if initial_count < 0 {
        return Err(platform_error(
            "proc_listallpids",
            "negative process count".to_owned(),
        ));
    }
    if initial_count == 0 {
        return Ok(Vec::new());
    }

    let initial_count =
        usize::try_from(initial_count).expect("non-negative proc_listallpids count must fit usize");
    if initial_count > CANDIDATE_PROCESS_IDS_MAX {
        return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
    }
    let sentinel_capacity = CANDIDATE_PROCESS_IDS_MAX.saturating_add(1);
    let mut capacity = initial_count
        .saturating_add(PROCESS_LIST_GROWTH_MARGIN)
        .min(sentinel_capacity);

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if capacity > sentinel_capacity {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        let buffer_bytes = checked_buffer_len::<libc::pid_t>(capacity, "proc_listallpids")?;
        let mut raw_pids = vec![0 as libc::pid_t; capacity];
        let count = read(Some(&mut raw_pids), buffer_bytes)?;
        if count < 0 {
            return Err(platform_error(
                "proc_listallpids",
                "negative process count".to_owned(),
            ));
        }

        let count =
            usize::try_from(count).expect("non-negative proc_listallpids count must fit usize");
        if count > CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
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

        capacity = capacity.saturating_mul(2).min(sentinel_capacity);
    }

    Err(platform_error(
        "proc_listallpids",
        "process list kept growing while being read".to_owned(),
    ))
}

fn list_process_fds(pid: u32, max_entries: usize) -> std::io::Result<Vec<libc::proc_fdinfo>> {
    let pid = pid_to_c_int(pid)?;
    list_process_fds_with_reader(
        |buffer, buffer_bytes| {
            let buffer = if let Some(buffer) = buffer {
                buffer.as_mut_ptr().cast::<c_void>()
            } else {
                std::ptr::null_mut()
            };
            unsafe {
                // SAFETY: __error returns this thread's valid errno slot. Clearing
                // it distinguishes a successful zero-byte result from libproc's
                // zero-on-error convention for both sizing and data calls.
                *libc::__error() = 0;
            }
            let written_bytes = unsafe {
                // SAFETY: a null buffer is the sizing call. Otherwise buffer owns
                // buffer_bytes bytes and libproc does not retain the pointer.
                libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, buffer, buffer_bytes)
            };
            match written_bytes.cmp(&0) {
                std::cmp::Ordering::Less => Err(std::io::Error::last_os_error()),
                std::cmp::Ordering::Equal => {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(0) {
                        Ok(0)
                    } else {
                        Err(error)
                    }
                }
                std::cmp::Ordering::Greater => Ok(written_bytes),
            }
        },
        max_entries,
        max_entries < MAX_PROCESS_FDS,
    )
}

fn list_process_fds_with_reader<Read>(
    mut read: Read,
    max_entries: usize,
    aggregate_allowance: bool,
) -> std::io::Result<Vec<libc::proc_fdinfo>>
where
    Read: FnMut(Option<&mut [libc::proc_fdinfo]>, libc::c_int) -> std::io::Result<libc::c_int>,
{
    let needed_bytes = read(None, 0)?;
    if needed_bytes < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "negative fd list byte count",
        ));
    }
    if needed_bytes == 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(0) {
            Ok(Vec::new())
        } else {
            Err(error)
        };
    }

    let needed_bytes =
        usize::try_from(needed_bytes).expect("non-negative proc_pidinfo byte count must fit usize");
    let initial_count = fd_record_count(needed_bytes, usize::MAX)?;
    let max_entries = max_entries.min(MAX_PROCESS_FDS);
    if initial_count > max_entries {
        return Err(std::io::Error::new(
            if aggregate_allowance {
                std::io::ErrorKind::FileTooLarge
            } else {
                std::io::ErrorKind::InvalidData
            },
            format!("fd list exceeds {max_entries} descriptor allowance"),
        ));
    }
    let sentinel_capacity = max_entries.saturating_add(1);
    let mut capacity = initial_count
        .saturating_add(FD_LIST_GROWTH_MARGIN)
        .min(sentinel_capacity);

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if capacity > sentinel_capacity {
            return Err(std::io::Error::new(
                if aggregate_allowance {
                    std::io::ErrorKind::FileTooLarge
                } else {
                    std::io::ErrorKind::InvalidData
                },
                format!("fd list exceeds {max_entries} descriptor allowance"),
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
        let written_bytes = read(Some(&mut fds), buffer_bytes)?;
        if written_bytes < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "negative fd list byte count",
            ));
        }

        let written_bytes = usize::try_from(written_bytes)
            .expect("non-negative proc_pidinfo byte count must fit usize");
        let count = fd_record_count(
            written_bytes,
            usize::try_from(buffer_bytes).expect("positive c_int fits usize"),
        )?;
        if count > max_entries {
            return Err(std::io::Error::new(
                if aggregate_allowance {
                    std::io::ErrorKind::FileTooLarge
                } else {
                    std::io::ErrorKind::InvalidData
                },
                format!("fd list exceeds {max_entries} descriptor allowance"),
            ));
        }
        if fd_list_is_complete(count, fds.len()) {
            fds.truncate(count);
            return Ok(fds);
        }

        capacity = capacity.saturating_mul(2).min(sentinel_capacity);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "fd list kept growing while being read",
    ))
}

fn fd_record_count(bytes: usize, max_bytes: usize) -> std::io::Result<usize> {
    if bytes > max_bytes || !bytes.is_multiple_of(size_of::<libc::proc_fdinfo>()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "fd list result is oversized or not record-aligned",
        ));
    }
    Ok(bytes / size_of::<libc::proc_fdinfo>())
}

const fn fd_list_is_complete(count: usize, capacity: usize) -> bool {
    count < capacity
}

fn socket_record_for_fd(pid: u32, fd: libc::c_int) -> std::io::Result<Option<SocketRecord>> {
    let info = read_socket_fdinfo(pid, fd)?;
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

fn socket_record_from_info(pid: u32, info: &SocketFdinfo) -> std::io::Result<Option<SocketRecord>> {
    let socket = &info.psi;
    match socket.soi_protocol {
        protocol if protocol == libc::IPPROTO_TCP && socket.soi_kind == SOCKINFO_TCP => {
            let tcp = unsafe {
                // SAFETY: soi_kind == SOCKINFO_TCP names pri_tcp as the active
                // protocol payload in Darwin's socket_info union.
                socket.soi_proto.pri_tcp
            };
            let state = darwin_tcp_state(tcp.tcpsi_state)?;
            socket_record_from_in_sockinfo(
                pid,
                Protocol::Tcp,
                state,
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
                ObservationSocketState::Bound,
                socket.soi_family,
                socket.soi_so,
                &udp,
            )
        }
        protocol if protocol == libc::IPPROTO_TCP || protocol == libc::IPPROTO_UDP => Err(
            malformed_socket_fdinfo("IP socket has an incompatible info kind"),
        ),
        _ => Ok(None),
    }
}

fn darwin_tcp_state(native: libc::c_int) -> std::io::Result<ObservationSocketState> {
    let state = match native {
        TSI_S_CLOSED => ObservationSocketState::Closed,
        TSI_S_LISTEN => ObservationSocketState::Listen,
        TSI_S_SYN_SENT => ObservationSocketState::SynSent,
        TSI_S_SYN_RECEIVED => ObservationSocketState::SynReceived,
        TSI_S_ESTABLISHED => ObservationSocketState::Established,
        TSI_S_CLOSE_WAIT => ObservationSocketState::CloseWait,
        TSI_S_FIN_WAIT_1 => ObservationSocketState::FinWait1,
        TSI_S_CLOSING => ObservationSocketState::Closing,
        TSI_S_LAST_ACK => ObservationSocketState::LastAck,
        TSI_S_FIN_WAIT_2 => ObservationSocketState::FinWait2,
        TSI_S_TIME_WAIT => ObservationSocketState::TimeWait,
        code if code >= 0 => ObservationSocketState::Unknown(
            u32::try_from(code).expect("nonnegative Darwin c_int must fit u32"),
        ),
        _ => return Err(malformed_socket_fdinfo("negative TCP state")),
    };
    Ok(state)
}

fn socket_record_from_in_sockinfo(
    pid: u32,
    protocol: Protocol,
    state: ObservationSocketState,
    family: libc::c_int,
    socket_id: u64,
    info: &InSockinfo,
) -> std::io::Result<Option<SocketRecord>> {
    let Some(local_port) = decode_port(info.insi_lport) else {
        if info.insi_lport == 0 {
            return Ok(None);
        }
        return Err(malformed_socket_fdinfo(
            "IP socket has an invalid local port",
        ));
    };
    let local_addr = decode_local_addr(info, family)
        .ok_or_else(|| malformed_socket_fdinfo("IP socket has an invalid local address"))?;
    Ok(Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        pid,
        socket_id,
    }))
}

fn malformed_socket_fdinfo(detail: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, detail)
}

fn decode_port(raw: libc::c_int) -> Option<u16> {
    let port = u16::try_from(raw).ok()?;
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
    read_process_name_bounded(pid, crate::observation::PROCESS_NAME_MAX_BYTES)
}

fn read_process_name_bounded(pid: u32, max_bytes: usize) -> std::io::Result<Option<String>> {
    Ok(match read_process_name_budgeted(pid, max_bytes)? {
        ParentNameRead::Value(name) => Some(name),
        ParentNameRead::Unavailable | ParentNameRead::BudgetExceeded => None,
    })
}

fn read_process_name_budgeted(pid: u32, max_bytes: usize) -> std::io::Result<ParentNameRead> {
    if max_bytes == 0 {
        return Ok(ParentNameRead::BudgetExceeded);
    }
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
    Ok(c_char_slice_to_parent_name(&buffer, max_bytes))
}

fn read_executable_path_bounded(pid: u32, max_bytes: usize) -> std::io::Result<Option<PathBuf>> {
    let pid = pid_to_c_int(pid)?;
    let buffer_len = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE)
        .expect("PROC_PIDPATHINFO_MAXSIZE must fit usize")
        .min(max_bytes);
    if buffer_len == 0 {
        return Ok(None);
    }
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
    let written_bytes = checked_returned_buffer_len(written_bytes, buffer.len(), "proc_pidpath")?;
    buffer.truncate(written_bytes);
    Ok(Some(PathBuf::from(OsStr::from_bytes(&buffer))))
}

fn read_command_line(pid: u32) -> std::io::Result<Option<String>> {
    read_command_line_bounded(pid, crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES).map(|read| {
        match read {
            CommandLineRead::Value(value) => Some(value),
            CommandLineRead::Missing | CommandLineRead::Omitted => None,
        }
    })
}

fn read_command_line_bounded(pid: u32, max_bytes: usize) -> std::io::Result<CommandLineRead> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid_to_c_int(pid)?];
    let final_max = max_bytes.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES);
    let native_max = final_max
        .checked_add(crate::observation::EXECUTABLE_PATH_MAX_BYTES)
        .and_then(|value| value.checked_add(size_of::<libc::c_int>() + 2))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "argument size overflow")
        })?;
    let buffer = read_changing_native_buffer(native_max, "KERN_PROCARGS2", |buffer| {
        let (oldp, mut buffer_len) = buffer.map_or((std::ptr::null_mut(), 0), |buffer| {
            (buffer.as_mut_ptr().cast::<c_void>(), buffer.len())
        });
        let result = unsafe {
            // SAFETY: mib is a live three-element KERN_PROCARGS2 name. oldp is
            // either null for sizing or points to buffer_len writable bytes;
            // buffer_len is a live out parameter and sysctl retains no pointer.
            libc::sysctl(
                mib.as_mut_ptr(),
                u32::try_from(mib.len()).expect("sysctl MIB length fits u32"),
                oldp,
                &raw mut buffer_len,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 {
            Ok(buffer_len)
        } else {
            Err(std::io::Error::last_os_error())
        }
    })?;
    if buffer.is_empty() {
        return Ok(CommandLineRead::Missing);
    }
    match decode_procargs2_bounded(&buffer, final_max) {
        Ok(value) => Ok(CommandLineRead::Value(value)),
        Err(ProcArgsDecodeError::OverLimit) => Ok(CommandLineRead::Omitted),
        Err(ProcArgsDecodeError::Missing) => Ok(CommandLineRead::Missing),
        Err(ProcArgsDecodeError::Malformed) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "KERN_PROCARGS2 returned malformed process arguments",
        )),
    }
}

fn read_changing_native_buffer<Read>(
    max_bytes: usize,
    api: &'static str,
    mut read: Read,
) -> std::io::Result<Vec<u8>>
where
    Read: FnMut(Option<&mut [u8]>) -> std::io::Result<usize>,
{
    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        let required = read(None)?;
        if required == 0 {
            return Ok(Vec::new());
        }
        if required > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{api} result exceeds its {max_bytes} byte allowance"),
            ));
        }

        let mut buffer = vec![0_u8; required];
        let returned = match read(Some(&mut buffer)) {
            Ok(returned) => returned,
            Err(error) if error.raw_os_error() == Some(libc::ENOMEM) => continue,
            Err(error) => return Err(error),
        };
        let returned = checked_returned_buffer_len(returned, buffer.len(), api)?;
        buffer.truncate(returned);
        return Ok(buffer);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("{api} kept growing while being read"),
    ))
}

fn checked_returned_buffer_len(
    returned: usize,
    capacity: usize,
    api: &'static str,
) -> std::io::Result<usize> {
    if returned > capacity {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{api} returned more bytes than its supplied buffer"),
        ));
    }
    Ok(returned)
}

#[cfg(test)]
fn decode_procargs2(bytes: &[u8]) -> Option<String> {
    decode_procargs2_bounded(bytes, crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcArgsDecodeError {
    Missing,
    OverLimit,
    Malformed,
}

fn decode_procargs2_bounded(bytes: &[u8], final_max: usize) -> Result<String, ProcArgsDecodeError> {
    let argc_bytes = bytes
        .get(..size_of::<libc::c_int>())
        .ok_or(ProcArgsDecodeError::Malformed)?;
    let argument_count = libc::c_int::from_ne_bytes(
        argc_bytes
            .try_into()
            .expect("argc slice length is exactly c_int size"),
    );
    if argument_count <= 0 {
        return Err(ProcArgsDecodeError::Missing);
    }

    let mut data = &bytes[size_of::<libc::c_int>()..];
    let exe_end = data
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ProcArgsDecodeError::Malformed)?;
    data = &data[exe_end + 1..];
    while data.first() == Some(&0) {
        data = &data[1..];
    }

    let mut final_bytes = 0usize;
    let mut accepted_arguments = 0usize;
    let argv_data = data;
    for _ in 0..argument_count {
        if data.is_empty() {
            return Err(ProcArgsDecodeError::Malformed);
        }
        let end = data
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(ProcArgsDecodeError::Malformed)?;
        let arg = &data[..end];
        if !arg.is_empty() {
            let argument_bytes =
                crate::observation::lossy_utf8_len(arg).ok_or(ProcArgsDecodeError::OverLimit)?;
            final_bytes = final_bytes
                .checked_add(usize::from(accepted_arguments != 0))
                .and_then(|value| value.checked_add(argument_bytes))
                .ok_or(ProcArgsDecodeError::OverLimit)?;
            if final_bytes > final_max {
                return Err(ProcArgsDecodeError::OverLimit);
            }
            accepted_arguments = accepted_arguments
                .checked_add(1)
                .ok_or(ProcArgsDecodeError::OverLimit)?;
        }
        data = &data[end + 1..];
    }

    if accepted_arguments == 0 {
        Err(ProcArgsDecodeError::Missing)
    } else {
        let mut value = String::new();
        value
            .try_reserve_exact(final_bytes)
            .map_err(|_| ProcArgsDecodeError::OverLimit)?;
        let mut data = argv_data;
        let mut written_arguments = 0usize;
        for _ in 0..argument_count {
            if data.is_empty() {
                return Err(ProcArgsDecodeError::Malformed);
            }
            let end = data
                .iter()
                .position(|byte| *byte == 0)
                .ok_or(ProcArgsDecodeError::Malformed)?;
            let argument = &data[..end];
            if !argument.is_empty() {
                if written_arguments != 0 {
                    value.push(' ');
                }
                crate::observation::push_utf8_lossy(&mut value, argument);
                written_arguments += 1;
            }
            data = &data[end + 1..];
        }
        debug_assert_eq!(written_arguments, accepted_arguments);
        debug_assert_eq!(value.len(), final_bytes);
        Ok(value)
    }
}

fn process_name_from_bsd_info(info: &libc::proc_bsdinfo) -> Option<String> {
    c_char_slice_to_string(&info.pbi_name).or_else(|| c_char_slice_to_string(&info.pbi_comm))
}

fn process_name_from_bsd_info_bounded(
    info: &libc::proc_bsdinfo,
    max_bytes: usize,
) -> Option<String> {
    c_char_slice_to_string_bounded(&info.pbi_name, max_bytes)
        .or_else(|| c_char_slice_to_string_bounded(&info.pbi_comm, max_bytes))
}

fn process_start_time_marker_from_bsd_info(
    info: &libc::proc_bsdinfo,
) -> Result<ProcessStartMarker, crate::observation::ProcessMarkerError> {
    let microseconds = u32::try_from(info.pbi_start_tvusec)
        .map_err(|_| crate::observation::ProcessMarkerError::InvalidMicroseconds)?;
    ProcessStartMarker::macos(info.pbi_start_tvsec, microseconds)
}

fn c_char_slice_to_string(bytes: &[libc::c_char]) -> Option<String> {
    c_char_slice_to_string_bounded(bytes, usize::MAX)
}

fn c_char_slice_to_string_bounded(bytes: &[libc::c_char], max_bytes: usize) -> Option<String> {
    match c_char_slice_to_parent_name(bytes, max_bytes) {
        ParentNameRead::Value(value) => Some(value),
        ParentNameRead::Unavailable | ParentNameRead::BudgetExceeded => None,
    }
}

fn c_char_slice_to_parent_name(bytes: &[libc::c_char], max_bytes: usize) -> ParentNameRead {
    let ptr = bytes.as_ptr();
    if ptr.is_null() || bytes.first().copied() == Some(0) {
        return ParentNameRead::Unavailable;
    }

    let Some(nul_index) = bytes.iter().position(|byte| *byte == 0) else {
        return ParentNameRead::Unavailable;
    };
    if nul_index == 0 {
        return ParentNameRead::Unavailable;
    }
    let text = unsafe {
        // SAFETY: nul_index proves there is a NUL terminator inside bytes, and ptr
        // points to the start of that same live buffer.
        CStr::from_ptr(ptr)
    };
    let bytes = text.to_bytes();
    let Some(decoded_len) = crate::observation::lossy_utf8_len(bytes) else {
        return ParentNameRead::Unavailable;
    };
    if decoded_len == 0 {
        return ParentNameRead::Unavailable;
    }
    if decoded_len > max_bytes {
        return ParentNameRead::BudgetExceeded;
    }
    let mut text = String::with_capacity(decoded_len);
    crate::observation::push_utf8_lossy(&mut text, bytes);
    ParentNameRead::Value(text)
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

fn platform_error(operation: &'static str, detail: String) -> CollectorError {
    CollectorError::Platform { operation, detail }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::mem::{MaybeUninit, align_of, offset_of, size_of};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::unix::ffi::OsStrExt;
    use std::path::PathBuf;

    use super::{
        In4In6Addr, InSocketAddress, InSockinfo, InSockinfoV4, InSockinfoV6, ProcessMetadata,
        SocketFdinfo, SocketProtocolInfo, SocketScanLoss, TSI_S_LISTEN, TcpSockinfo,
        checked_returned_buffer_len, collect_pid_socket_records_from_fds, decode_port,
        decode_procargs2, decode_procargs2_bounded, fd_list_is_complete, fd_record_count,
        fresh_process_evidence_from_reads, list_process_fds_with_reader, native_pass_from_records,
        process_ids_with_reader, process_observation_from_metadata, read_changing_native_buffer,
        retain_parent_process_name, retain_socket_record, socket_record_from_info,
        sorted_owner_is_new,
    };
    use crate::model::Protocol;
    use crate::observation::{
        EvidenceImpact, Ipv6Scope, MetadataCompleteness, OwnerCompleteness, PlatformSocketToken,
        SocketState,
    };
    use crate::process_evidence::ProcessEvidenceError;
    use crate::tree::TreeProcessOps;

    fn zeroed_socket_fdinfo() -> SocketFdinfo {
        unsafe {
            // SAFETY: these C layout structs are plain data buffers in production;
            // tests zero them before filling the fields relevant to record parsing.
            MaybeUninit::<SocketFdinfo>::zeroed().assume_init()
        }
    }

    #[test]
    fn prepare_thaw_records_the_identity_used_by_production_continuation() {
        let marker =
            crate::observation::ProcessStartMarker::macos(1, 0).expect("test marker is valid");
        let mut ops = super::MacosTreeOps::new();

        ops.prepare_thaw(42, Some(marker));

        assert_eq!(ops.verified_markers.get(&42), Some(&marker));
    }

    #[test]
    fn continuation_guard_refuses_a_pid_without_a_verified_marker() {
        let ops = super::MacosTreeOps::new();

        assert_eq!(
            ops.recheck_marker(42),
            Err(crate::tree::TreeSignalResult::Denied)
        );
    }

    #[test]
    fn shared_socket_owner_dedup_scales_with_sorted_owner_count() {
        let mut owners = Vec::new();
        for pid in 1..=32_768 {
            if sorted_owner_is_new(&owners, pid) {
                owners.push(pid);
            }
            if sorted_owner_is_new(&owners, pid) {
                owners.push(pid);
            }
        }

        assert_eq!(owners.len(), 32_768);
        assert_eq!(owners.first(), Some(&1));
        assert_eq!(owners.last(), Some(&32_768));
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

    fn tcp_socket_fdinfo(native_state: libc::c_int) -> SocketFdinfo {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_TCP;
        info.psi.soi_family = libc::AF_INET;
        info.psi.soi_kind = super::SOCKINFO_TCP;
        info.psi.soi_so = 0xCAFE;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_tcp: TcpSockinfo {
                tcpsi_ini: in_sockinfo_v4(3000, Ipv4Addr::LOCALHOST),
                tcpsi_state: native_state,
                tcpsi_timer: [0; 4],
                tcpsi_mss: 0,
                tcpsi_flags: 0,
                rfu_1: 0,
                tcpsi_tp: 0,
            },
        };
        info
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
    fn socket_fdinfo_layout_exactly_matches_the_supported_darwin_lp64_abi() {
        assert_eq!(size_of::<super::ProcFileinfo>(), 24);
        assert_eq!(align_of::<super::ProcFileinfo>(), 8);
        assert_eq!(size_of::<InSockinfo>(), 80);
        assert_eq!(align_of::<InSockinfo>(), 8);
        assert_eq!(offset_of!(InSockinfo, insi_laddr), 48);
        assert_eq!(offset_of!(InSockinfo, insi_v6), 68);
        assert_eq!(size_of::<TcpSockinfo>(), 120);
        assert_eq!(offset_of!(TcpSockinfo, tcpsi_state), 80);
        assert_eq!(size_of::<SocketProtocolInfo>(), 528);
        assert_eq!(align_of::<SocketProtocolInfo>(), 8);
        assert_eq!(size_of::<super::SocketInfo>(), 768);
        assert_eq!(offset_of!(super::SocketInfo, soi_so), 136);
        assert_eq!(offset_of!(super::SocketInfo, soi_proto), 240);
        assert_eq!(size_of::<SocketFdinfo>(), 792);
        assert_eq!(align_of::<SocketFdinfo>(), 8);
        assert_eq!(offset_of!(SocketFdinfo, psi), 24);
    }

    #[test]
    fn darwin_constants_and_tcp_states_match_supported_sdk_values() {
        assert_eq!(super::PROC_PIDFDSOCKETINFO, 3);
        assert_eq!(super::SOCKINFO_IN, 1);
        assert_eq!(super::SOCKINFO_TCP, 2);
        assert_eq!(libc::PROX_FDTYPE_SOCKET, 2);

        let expected = [
            SocketState::Closed,
            SocketState::Listen,
            SocketState::SynSent,
            SocketState::SynReceived,
            SocketState::Established,
            SocketState::CloseWait,
            SocketState::FinWait1,
            SocketState::Closing,
            SocketState::LastAck,
            SocketState::FinWait2,
            SocketState::TimeWait,
        ];
        for (native, expected) in (0..=10).zip(expected) {
            assert_eq!(super::darwin_tcp_state(native).unwrap(), expected);
            let record = socket_record_from_info(42, &tcp_socket_fdinfo(native))
                .expect("documented TCP state is valid")
                .expect("every documented TCP state is retained");
            assert_eq!(record.state, expected);
            let pass =
                super::native_pass_from_records(&[record], vec![vec![42]], BTreeSet::new(), 0)
                    .expect("documented state survives native observation materialization");
            assert_eq!(pass.sockets[0].state, expected);
        }
    }

    #[test]
    fn darwin_tcp_state_preserves_unknown_and_rejects_negative_values() {
        assert_eq!(
            super::darwin_tcp_state(11).unwrap(),
            SocketState::Unknown(11)
        );
        assert_eq!(
            super::darwin_tcp_state(libc::c_int::MAX).unwrap(),
            SocketState::Unknown(u32::try_from(libc::c_int::MAX).unwrap())
        );
        assert_eq!(
            super::darwin_tcp_state(-1).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
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

        let record = socket_record_from_info(18422, &info)
            .expect("valid fdinfo")
            .expect("listen socket is kept");

        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(record.state, SocketState::Listen);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
        assert_eq!(record.pid, 18422);
        assert_eq!(record.socket_id, 0xCAFE);
    }

    #[test]
    fn unbound_port_zero_socket_is_outside_endpoint_observations() {
        let mut info = tcp_socket_fdinfo(super::TSI_S_CLOSED);
        info.psi.soi_proto = SocketProtocolInfo {
            pri_tcp: TcpSockinfo {
                tcpsi_ini: in_sockinfo_v4(0, Ipv4Addr::UNSPECIFIED),
                tcpsi_state: super::TSI_S_CLOSED,
                tcpsi_timer: [0; 4],
                tcpsi_mss: 0,
                tcpsi_flags: 0,
                rfu_1: 0,
                tcpsi_tp: 0,
            },
        };

        assert_eq!(
            socket_record_from_info(42, &info).expect("unbound socket is valid native data"),
            None
        );
    }

    #[test]
    fn tcp_non_listen_socket_info_is_retained() {
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

        let record = socket_record_from_info(18422, &info)
            .expect("valid fdinfo")
            .expect("established socket is retained");
        assert_eq!(record.state, SocketState::Established);
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

        let record = socket_record_from_info(902, &info)
            .expect("valid fdinfo")
            .expect("udp socket is kept");

        assert_eq!(record.protocol, Protocol::Udp);
        assert_eq!(record.state, SocketState::Bound);
        assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(record.local_port, 5353);
        assert_eq!(record.pid, 902);

        let pass = native_pass_from_records(
            &[record],
            vec![vec![902]],
            std::collections::BTreeSet::new(),
            0,
        )
        .expect("unavailable native scope is representable");
        assert_eq!(
            pass.sockets[0].endpoint.ipv6_scope,
            Some(Ipv6Scope::Unavailable)
        );
    }

    #[test]
    fn production_orchestration_emits_endpoint_null_ipv6_scope_evidence() {
        let pass = super::MacosCollector::collect_native_pass_with(
            || Ok(vec![902]),
            |pid, _| {
                Ok((
                    vec![super::SocketRecord {
                        protocol: Protocol::Udp,
                        local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                        local_port: 5353,
                        state: SocketState::Bound,
                        pid,
                        socket_id: 77,
                    }],
                    BTreeSet::new(),
                ))
            },
        )
        .expect("IPv6 socket remains observable without native scope");

        assert_eq!(pass.owners.evidence_gaps[0].impact, EvidenceImpact::Scope);
        assert_eq!(pass.owners.evidence_gaps[0].endpoint, None);
        assert_eq!(pass.owners.evidence_gaps[0].pid, None);
    }

    #[test]
    fn native_pass_retains_socket_id_and_shared_owners() {
        let record = super::SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 100,
            socket_id: 0xCAFE,
        };

        let pass = native_pass_from_records(
            &[record],
            vec![vec![100, 101]],
            std::collections::BTreeSet::new(),
            0,
        )
        .expect("native macOS pass is valid");

        assert_eq!(
            pass.sockets[0].token,
            PlatformSocketToken::macos_socket_id(0xCAFE)
        );
        assert_eq!(pass.owners.owners_by_socket[0], [100, 101]);
        assert_eq!(pass.sockets[0].timer, None);
        assert_eq!(pass.owners.global_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            pass.owners.local_completeness,
            [OwnerCompleteness::Complete]
        );
    }

    #[test]
    fn tokenless_same_endpoint_descriptors_remain_distinct_within_one_pid() {
        let fds = [9, 10].map(|proc_fd| libc::proc_fdinfo {
            proc_fd,
            proc_fdtype: u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap(),
        });
        let record = super::SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 100,
            socket_id: 0,
        };
        let mut traversed = 0;

        let (records, losses) =
            collect_pid_socket_records_from_fds(100, &fds, &mut traversed, fds.len(), |_| {
                Ok(Some(record.clone()))
            })
            .expect("tokenless descriptors collect");

        assert_eq!(records, [record.clone(), record]);
        assert!(losses.is_empty());
    }

    #[test]
    fn tokenless_same_endpoint_sockets_do_not_merge_owners_across_pids() {
        let record = super::SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 100,
            socket_id: 0,
        };
        let mut records = Vec::new();
        let mut owners = Vec::new();
        let mut indexes = std::collections::HashMap::new();
        let mut owner_edges = 0;
        let mut losses = std::collections::BTreeSet::new();
        let mut omitted = 0;

        retain_socket_record(
            &mut records,
            &mut owners,
            &mut indexes,
            &mut owner_edges,
            &mut losses,
            &mut omitted,
            record.clone(),
            100,
        )
        .expect("first tokenless socket is retained");
        retain_socket_record(
            &mut records,
            &mut owners,
            &mut indexes,
            &mut owner_edges,
            &mut losses,
            &mut omitted,
            super::SocketRecord { pid: 101, ..record },
            101,
        )
        .expect("second tokenless socket is retained");
        let pass = native_pass_from_records(&records, owners, std::collections::BTreeSet::new(), 0)
            .expect("tokenless sockets form a valid pass");

        assert_eq!(pass.sockets.len(), 2);
        assert!(pass.sockets.iter().all(|socket| socket.token.is_none()));
        assert_eq!(pass.owners.owners_by_socket, [vec![100], vec![101]]);
        assert!(indexes.is_empty());
    }

    #[test]
    fn repeated_socket_token_with_conflicting_facts_is_a_socket_set_gap() {
        let first = super::SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: 100,
            socket_id: 0xCAFE,
        };
        let conflicting = super::SocketRecord {
            state: SocketState::Established,
            pid: 101,
            ..first.clone()
        };
        let mut records = Vec::new();
        let mut owners = Vec::new();
        let mut indexes = std::collections::HashMap::new();
        let mut owner_edges = 0;
        let mut losses = std::collections::BTreeSet::new();
        let mut omitted = 0;

        retain_socket_record(
            &mut records,
            &mut owners,
            &mut indexes,
            &mut owner_edges,
            &mut losses,
            &mut omitted,
            first,
            100,
        )
        .unwrap();
        retain_socket_record(
            &mut records,
            &mut owners,
            &mut indexes,
            &mut owner_edges,
            &mut losses,
            &mut omitted,
            conflicting,
            101,
        )
        .unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(owners, [vec![100]]);
        assert_eq!(
            losses,
            [SocketScanLoss::TokenConflict].into_iter().collect()
        );
        let pass = native_pass_from_records(&records, owners, losses, omitted).unwrap();
        assert_eq!(
            pass.owners.evidence_gaps[0].impact,
            EvidenceImpact::SocketSet
        );
        assert_eq!(pass.owners.evidence_gaps[0].pid, None);
        assert_eq!(pass.owners.evidence_gaps[0].endpoint, None);
    }

    #[test]
    fn pid_scan_denial_is_socket_set_loss_not_owner_loss() {
        let record = super::SocketRecord {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 5353,
            state: SocketState::Bound,
            pid: 902,
            socket_id: 77,
        };

        let pass = native_pass_from_records(
            &[record],
            vec![vec![902]],
            [SocketScanLoss::PermissionDenied(42)].into_iter().collect(),
            0,
        )
        .expect("permission loss remains representable");

        assert_eq!(pass.owners.global_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            pass.owners.local_completeness,
            [OwnerCompleteness::Complete]
        );
        assert_eq!(pass.owners.evidence_gaps[0].endpoint, None);
        assert_eq!(pass.owners.evidence_gaps[0].pid, Some(42));
        assert_eq!(
            pass.owners.evidence_gaps[0].impact,
            EvidenceImpact::SocketSet
        );
    }

    #[test]
    fn production_orchestration_propagates_process_enumeration_denial() {
        let error = super::MacosCollector::collect_native_pass_with(
            || Err(crate::observation::ObservationError::SocketTablePermissionDenied.into()),
            |_, _| unreachable!("PID scan must not start after process-list denial"),
        )
        .expect_err("total process enumeration denial is operational");

        assert!(matches!(
            error,
            crate::collector::CollectorError::Observation(
                crate::observation::ObservationError::SocketTablePermissionDenied
            )
        ));
    }

    #[test]
    fn production_orchestration_propagates_process_enumeration_failure() {
        let error = super::MacosCollector::collect_native_pass_with(
            || {
                Err(super::platform_error(
                    "proc_listallpids",
                    "I/O failure".to_owned(),
                ))
            },
            |_, _| unreachable!("PID scan must not start after process-list failure"),
        )
        .expect_err("generic process enumeration failure is operational");

        assert!(matches!(
            error,
            crate::collector::CollectorError::Platform {
                operation: "proc_listallpids",
                ..
            }
        ));
    }

    #[test]
    fn production_orchestration_preserves_rows_while_recording_pid_scan_denial() {
        let pass = super::MacosCollector::collect_native_pass_with(
            || Ok(vec![42, 902]),
            |pid, _| {
                if pid == 42 {
                    return Err(std::io::Error::from_raw_os_error(libc::EACCES));
                }
                Ok((
                    vec![super::SocketRecord {
                        protocol: Protocol::Udp,
                        local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        local_port: 5353,
                        state: SocketState::Bound,
                        pid,
                        socket_id: 77,
                    }],
                    BTreeSet::new(),
                ))
            },
        )
        .expect("one denied PID does not erase another PID's authoritative row");

        assert_eq!(pass.sockets.len(), 1);
        assert_eq!(pass.owners.owners_by_socket, [vec![902]]);
        assert_eq!(pass.owners.evidence_gaps.len(), 1);
        assert_eq!(pass.owners.evidence_gaps[0].pid, Some(42));
        assert_eq!(
            pass.owners.evidence_gaps[0].impact,
            EvidenceImpact::SocketSet
        );
    }

    #[test]
    fn production_orchestration_maps_pid_scan_failures_to_socket_set_gaps() {
        let cases = [
            (
                std::io::Error::from_raw_os_error(libc::ESRCH),
                crate::observation::EvidenceGapCode::OwnerDisappeared,
            ),
            (
                std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed fdinfo"),
                crate::observation::EvidenceGapCode::NativeFieldUnavailable,
            ),
            (
                std::io::Error::other("proc_pidinfo failed"),
                crate::observation::EvidenceGapCode::OwnerAttributionIncomplete,
            ),
        ];

        for (error, expected_code) in cases {
            let mut error = Some(error);
            let pass = super::MacosCollector::collect_native_pass_with(
                || Ok(vec![42]),
                |_, _| Err(error.take().expect("one PID scan")),
            )
            .expect("per-PID scan loss remains a partial pass");

            assert!(pass.sockets.is_empty());
            assert_eq!(pass.owners.evidence_gaps.len(), 1);
            assert_eq!(pass.owners.evidence_gaps[0].pid, Some(42));
            assert_eq!(
                pass.owners.evidence_gaps[0].impact,
                EvidenceImpact::SocketSet
            );
            assert_eq!(pass.owners.evidence_gaps[0].code, expected_code);
        }
    }

    #[test]
    fn production_orchestration_distinguishes_fd_limit_and_allocation_failures() {
        let oversized = super::MacosCollector::collect_native_pass_with(
            || Ok(vec![42]),
            |_, _| Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge)),
        )
        .expect_err("aggregate FD exhaustion is a native-data limit failure");
        assert!(matches!(
            oversized,
            crate::collector::CollectorError::Observation(
                crate::observation::ObservationError::NativeDataOversized
            )
        ));

        let allocation = super::MacosCollector::collect_native_pass_with(
            || Ok(vec![42]),
            |_, _| Err(std::io::Error::from(std::io::ErrorKind::OutOfMemory)),
        )
        .expect_err("FD allocation failure remains an operational platform error");
        assert!(matches!(
            allocation,
            crate::collector::CollectorError::Platform {
                operation: "proc_pidinfo(PROC_PIDLISTFDS)",
                ..
            }
        ));
    }

    #[test]
    fn socket_scan_losses_are_bounded_at_the_native_pass_source() {
        let mut losses = std::collections::BTreeSet::new();
        let mut omitted = 0u64;
        for pid in 1..=u32::try_from(crate::observation::EVIDENCE_GAPS_MAX).unwrap() {
            super::retain_socket_scan_loss(
                &mut losses,
                &mut omitted,
                SocketScanLoss::Disappeared(pid),
            );
        }
        assert_eq!(losses.len(), crate::observation::EVIDENCE_GAPS_MAX);
        assert_eq!(omitted, 0);

        super::retain_socket_scan_loss(
            &mut losses,
            &mut omitted,
            SocketScanLoss::Disappeared(u32::MAX),
        );
        let pass = native_pass_from_records(&[], Vec::new(), losses, omitted)
            .expect("bounded socket losses remain observable");
        assert_eq!(
            pass.owners.evidence_gaps.len(),
            crate::observation::EVIDENCE_GAPS_MAX
        );
        assert_eq!(pass.owners.omitted_evidence_gap_count, 1);
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

        let record = socket_record_from_info(18422, &info)
            .expect("valid fdinfo")
            .expect("mapped socket is kept");

        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
    }

    #[test]
    fn port_decoding_rejects_zero_and_uses_network_byte_order() {
        assert_eq!(decode_port(i32::from(3000_u16.to_be())), Some(3000));
        assert_eq!(decode_port(0), None);
        assert_eq!(decode_port(i32::from(u16::MAX) + 1), None);
        assert_eq!(decode_port(-1), None);
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
    fn procargs2_decoding_counts_empty_arguments_without_rendering_extra_spaces() {
        let bytes = procargs2(3, b"/bin/program", &[b"program", b"", b"value"]);

        assert_eq!(decode_procargs2(&bytes).as_deref(), Some("program value"));
    }

    #[test]
    fn procargs2_decoding_rejects_empty_or_malformed_data() {
        assert_eq!(decode_procargs2(&[]), None);
        assert_eq!(decode_procargs2(&0_i32.to_ne_bytes()), None);
        assert_eq!(decode_procargs2(&1_i32.to_ne_bytes()), None);

        let truncated_argv = procargs2(2, b"/bin/test", &[b"test"]);
        assert_eq!(
            decode_procargs2_bounded(&truncated_argv, 64),
            Err(super::ProcArgsDecodeError::Malformed)
        );

        let mut unterminated = 1_i32.to_ne_bytes().to_vec();
        unterminated.extend_from_slice(b"/bin/test\0\0test");
        assert_eq!(
            decode_procargs2_bounded(&unterminated, 64),
            Err(super::ProcArgsDecodeError::Malformed)
        );
    }

    #[test]
    fn unavailable_or_omitted_command_line_marks_metadata_partial() {
        let mut missing = super::ProcessMetadata::default();
        super::apply_command_line_read(
            &mut missing,
            Ok(super::CommandLineRead::Missing),
            crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
        );
        assert!(missing.partial);
        assert!(!missing.budget_omitted);

        let mut omitted = super::ProcessMetadata::default();
        super::apply_command_line_read(
            &mut omitted,
            Ok(super::CommandLineRead::Omitted),
            crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
        );
        assert!(omitted.partial);
        assert!(omitted.budget_omitted);

        let mut malformed = super::ProcessMetadata::default();
        super::apply_command_line_read(
            &mut malformed,
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed procargs2",
            )),
            crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
        );
        assert_eq!(malformed.command_line, None);
        assert!(malformed.partial);
        assert!(!malformed.budget_omitted);
    }

    #[test]
    fn parent_name_exact_fit_is_retained_without_budget_omission() {
        let mut metadata = ProcessMetadata::default();
        let native = [
            b'p'.cast_signed(),
            b'a'.cast_signed(),
            b'r'.cast_signed(),
            b'e'.cast_signed(),
            b'n'.cast_signed(),
            b't'.cast_signed(),
            0,
        ];

        retain_parent_process_name(
            &mut metadata,
            Some(super::c_char_slice_to_parent_name(&native, 6)),
        );

        assert_eq!(metadata.parent_process_name.as_deref(), Some("parent"));
        assert!(!metadata.partial);
        assert!(!metadata.budget_omitted);
    }

    #[test]
    fn parent_name_first_excess_and_zero_remaining_are_budget_omissions() {
        for max_bytes in [5, 0] {
            let mut metadata = ProcessMetadata::default();
            let native = [
                b'p'.cast_signed(),
                b'a'.cast_signed(),
                b'r'.cast_signed(),
                b'e'.cast_signed(),
                b'n'.cast_signed(),
                b't'.cast_signed(),
                0,
            ];

            retain_parent_process_name(
                &mut metadata,
                Some(super::c_char_slice_to_parent_name(&native, max_bytes)),
            );

            assert_eq!(metadata.parent_process_name, None);
            assert!(metadata.partial);
            assert!(metadata.budget_omitted);
            assert_eq!(
                process_observation_from_metadata(metadata).metadata_omission,
                Some(crate::observation::MetadataOmission::BudgetExceeded)
            );
        }
    }

    #[test]
    fn unavailable_parent_name_is_not_a_budget_omission() {
        let mut metadata = ProcessMetadata::default();

        retain_parent_process_name(&mut metadata, Some(super::ParentNameRead::Unavailable));

        assert!(metadata.partial);
        assert!(!metadata.budget_omitted);
    }

    #[test]
    fn cached_parent_name_respects_each_childs_remaining_budget() {
        let cached = super::ParentNameRead::Value("parent".to_owned());

        assert_eq!(
            super::parent_name_for_budget(&cached, 6),
            super::ParentNameRead::Value("parent".to_owned())
        );
        assert_eq!(
            super::parent_name_for_budget(&cached, 5),
            super::ParentNameRead::BudgetExceeded
        );
        assert_eq!(
            super::parent_name_for_budget(&cached, 0),
            super::ParentNameRead::BudgetExceeded
        );
    }

    #[test]
    fn procargs2_seam_enforces_one_mib_final_utf8_boundary() {
        let max = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        let exact_argument = vec![b'x'; max];
        let exact = procargs2(1, b"", &[&exact_argument]);
        assert_eq!(
            decode_procargs2_bounded(&exact, max)
                .as_deref()
                .map(str::len),
            Ok(max)
        );

        let oversized_argument = vec![b'x'; max + 1];
        let oversized = procargs2(1, b"", &[&oversized_argument]);
        assert_eq!(
            decode_procargs2_bounded(&oversized, max),
            Err(super::ProcArgsDecodeError::OverLimit)
        );
    }

    #[test]
    fn procargs2_join_budget_counts_separators_and_lossy_utf8_exactly() {
        let exact = procargs2(3, b"", &[b"ab", &[0xff], b"cd"]);
        assert_eq!(
            decode_procargs2_bounded(&exact, 9).as_deref(),
            Ok("ab � cd")
        );
        assert_eq!(
            decode_procargs2_bounded(&exact, 8),
            Err(super::ProcArgsDecodeError::OverLimit)
        );
    }

    #[test]
    fn procargs2_many_arguments_refuse_before_joining_over_budget_output() {
        let arguments = vec![b"x".as_slice(); 65_536];
        let bytes = procargs2(65_536, b"", &arguments);
        assert_eq!(
            decode_procargs2_bounded(&bytes, 31),
            Err(super::ProcArgsDecodeError::OverLimit)
        );
    }

    #[test]
    fn changing_native_read_succeeds_on_the_third_bounded_attempt() {
        let mut reads = 0;
        let mut allocations = Vec::new();
        let buffer = read_changing_native_buffer(8, "native_test", |buffer| {
            let Some(buffer) = buffer else {
                return Ok(4);
            };
            reads += 1;
            allocations.push(buffer.len());
            if reads < 3 {
                return Err(std::io::Error::from_raw_os_error(libc::ENOMEM));
            }
            buffer.copy_from_slice(b"test");
            Ok(4)
        })
        .expect("attempt three is accepted");

        assert_eq!(buffer, b"test");
        assert_eq!(reads, 3);
        assert_eq!(allocations, [4, 4, 4]);
    }

    #[test]
    fn changing_native_read_exhausts_after_three_attempts() {
        let mut reads = 0;
        let error = read_changing_native_buffer(8, "native_test", |buffer| {
            if buffer.is_none() {
                return Ok(4);
            }
            reads += 1;
            Err(std::io::Error::from_raw_os_error(libc::ENOMEM))
        })
        .expect_err("a fourth read attempt must not start");

        assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("kept growing"));
    }

    #[test]
    fn changing_native_read_checks_budget_before_allocation() {
        let mut buffer_reads = 0;
        let error = read_changing_native_buffer(8, "native_test", |buffer| {
            if buffer.is_some() {
                buffer_reads += 1;
            }
            Ok(9)
        })
        .expect_err("oversized sizing result is rejected");

        assert_eq!(buffer_reads, 0);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn malformed_socket_fdinfo_cannot_silently_hide_a_socket() {
        let mut info = zeroed_socket_fdinfo();
        info.psi.soi_protocol = libc::IPPROTO_TCP;
        info.psi.soi_family = libc::AF_INET;
        info.psi.soi_kind = super::SOCKINFO_TCP;
        info.psi.soi_proto = SocketProtocolInfo {
            pri_tcp: TcpSockinfo {
                tcpsi_ini: in_sockinfo_v4(0, Ipv4Addr::LOCALHOST),
                tcpsi_state: -1,
                tcpsi_timer: [0; 4],
                tcpsi_mss: 0,
                tcpsi_flags: 0,
                rfu_1: 0,
                tcpsi_tp: 0,
            },
        };
        let fds = [libc::proc_fdinfo {
            proc_fd: 9,
            proc_fdtype: u32::try_from(libc::PROX_FDTYPE_SOCKET).unwrap(),
        }];
        let mut traversed = 0;

        let (_, losses) = collect_pid_socket_records_from_fds(42, &fds, &mut traversed, 1, |_| {
            socket_record_from_info(42, &info)
        })
        .expect("malformed per-FD data is retained as socket-set loss");

        assert_eq!(
            losses,
            [SocketScanLoss::Malformed(42)].into_iter().collect()
        );
        let pass =
            native_pass_from_records(&[], Vec::new(), losses, 0).expect("loss is representable");
        assert_eq!(
            pass.owners.evidence_gaps[0].impact,
            EvidenceImpact::SocketSet
        );
    }

    #[test]
    fn malformed_or_truncated_fd_enumeration_is_not_accepted() {
        let record_size = size_of::<libc::proc_fdinfo>();
        assert_eq!(
            fd_record_count(record_size - 1, record_size)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert_eq!(
            fd_record_count(record_size * 2, record_size)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
        assert!(!fd_list_is_complete(16, 16));
        assert!(fd_list_is_complete(15, 16));
    }

    #[test]
    fn production_pid_reader_accepts_exact_maximum_on_attempt_three() {
        let max = crate::observation::CANDIDATE_PROCESS_IDS_MAX;
        let initial = max / 2 - super::PROCESS_LIST_GROWTH_MARGIN;
        let mut attempts = Vec::new();

        let pids = process_ids_with_reader(|buffer, _| {
            let Some(buffer) = buffer else {
                return Ok(libc::c_int::try_from(initial).unwrap());
            };
            attempts.push(buffer.len());
            if attempts.len() < 3 {
                return Ok(libc::c_int::try_from(buffer.len()).unwrap());
            }
            for (index, pid) in buffer[..max].iter_mut().rev().enumerate() {
                *pid = libc::pid_t::try_from(index + 1).unwrap();
            }
            Ok(libc::c_int::try_from(max).unwrap())
        })
        .expect("the exact production PID maximum is accepted");

        assert_eq!(attempts, [max / 2, max, max + 1]);
        assert_eq!(pids.len(), max);
        assert_eq!(pids.first(), Some(&1));
        assert_eq!(pids.last(), Some(&u32::try_from(max).unwrap()));
    }

    #[test]
    fn zero_count_with_errno_is_an_error_and_zero_without_errno_is_success() {
        let error = super::count_result(0, libc::EIO).expect_err("zero with errno is failure");
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(super::count_result(0, 0).unwrap(), 0);
    }

    #[test]
    fn count_call_clears_stale_errno_before_native_invocation() {
        unsafe {
            // SAFETY: __error returns this test thread's valid errno slot.
            *libc::__error() = libc::EIO;
        }

        assert_eq!(super::call_count_api(|| 0).unwrap(), 0);
        let error = super::call_count_api(|| {
            unsafe {
                // SAFETY: __error returns this test thread's valid errno slot.
                *libc::__error() = libc::EACCES;
            }
            0
        })
        .expect_err("errno set by the invocation makes zero an error");
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn all_pid_zero_error_cannot_become_an_empty_complete_list() {
        let error = process_ids_with_reader(|_, _| {
            super::count_result(0, libc::EACCES)
                .map_err(|error| super::platform_error("proc_listallpids", error.to_string()))
        })
        .expect_err("zero-on-error must remain an enumeration failure");

        assert!(matches!(
            error,
            crate::collector::CollectorError::Platform {
                operation: "proc_listallpids",
                ..
            }
        ));
        assert!(
            process_ids_with_reader(|_, _| Ok(0))
                .expect("genuine zero is not a native failure")
                .is_empty()
        );
    }

    #[test]
    fn child_pid_reader_preserves_genuine_zero_children_and_zero_error() {
        let mut buffer = vec![0; 4];
        let buffer_bytes = libc::c_int::try_from(std::mem::size_of_val(buffer.as_slice())).unwrap();
        let children = super::child_process_ids_with_reader(&mut buffer, buffer_bytes, |_, _| {
            super::count_result(0, 0)
        })
        .expect("zero children is a valid result");
        assert!(children.is_empty());

        let mut buffer = vec![0; 4];
        let error = super::child_process_ids_with_reader(&mut buffer, buffer_bytes, |_, _| {
            super::count_result(0, libc::EACCES)
        })
        .expect_err("zero with errno is a child enumeration failure");
        assert!(matches!(
            error,
            crate::collector::CollectorError::Platform {
                operation: "proc_listchildpids",
                ..
            }
        ));
    }

    #[test]
    fn production_pid_reader_refuses_max_plus_one_before_allocation() {
        let max = crate::observation::CANDIDATE_PROCESS_IDS_MAX;
        let mut buffer_reads = 0;

        let error = process_ids_with_reader(|buffer, _| {
            if buffer.is_some() {
                buffer_reads += 1;
            }
            Ok(libc::c_int::try_from(max + 1).unwrap())
        })
        .expect_err("one PID beyond the production maximum is refused");

        assert_eq!(buffer_reads, 0);
        assert!(matches!(
            error,
            crate::collector::CollectorError::Observation(
                crate::observation::ObservationError::ProcessIdentityLimitExceeded
            )
        ));
    }

    #[test]
    fn pid_reader_exhausts_after_three_full_results() {
        let mut reads = 0;
        let error = process_ids_with_reader(|buffer, _| {
            if let Some(buffer) = buffer {
                reads += 1;
                Ok(libc::c_int::try_from(buffer.len()).unwrap())
            } else {
                Ok(1)
            }
        })
        .expect_err("a fourth PID buffer read must not start");

        assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
        assert!(error.to_string().contains("kept growing"));
    }

    #[test]
    fn production_fd_reader_accepts_exact_maximum_on_attempt_three() {
        let max = super::MAX_PROCESS_FDS;
        let initial = max / 2 - super::FD_LIST_GROWTH_MARGIN;
        let record_size = size_of::<libc::proc_fdinfo>();
        let mut attempts = Vec::new();

        let fds = list_process_fds_with_reader(
            |buffer, _| {
                let Some(buffer) = buffer else {
                    return Ok(libc::c_int::try_from(initial * record_size).unwrap());
                };
                attempts.push(buffer.len());
                if attempts.len() < 3 {
                    return Ok(libc::c_int::try_from(std::mem::size_of_val(buffer)).unwrap());
                }
                for (index, fd) in buffer[..max].iter_mut().enumerate() {
                    fd.proc_fd = libc::c_int::try_from(index).unwrap();
                }
                Ok(libc::c_int::try_from(max * record_size).unwrap())
            },
            max,
            false,
        )
        .expect("the exact production per-process FD maximum is accepted");

        assert_eq!(attempts, [max / 2, max, max + 1]);
        assert_eq!(fds.len(), max);
        assert_eq!(fds.first().map(|fd| fd.proc_fd), Some(0));
        assert_eq!(
            fds.last().map(|fd| fd.proc_fd),
            Some(libc::c_int::try_from(max - 1).unwrap())
        );
    }

    #[test]
    fn production_fd_reader_refuses_max_plus_one_before_allocation() {
        let max = super::MAX_PROCESS_FDS;
        let record_size = size_of::<libc::proc_fdinfo>();
        let mut buffer_reads = 0;

        let error = list_process_fds_with_reader(
            |buffer, _| {
                if buffer.is_some() {
                    buffer_reads += 1;
                }
                Ok(libc::c_int::try_from((max + 1) * record_size).unwrap())
            },
            max,
            false,
        )
        .expect_err("one FD beyond the production maximum is refused");

        assert_eq!(buffer_reads, 0);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("descriptor allowance"));
    }

    #[test]
    fn fd_reader_exhausts_after_three_full_results() {
        let record_size = size_of::<libc::proc_fdinfo>();
        let mut reads = 0;
        let error = list_process_fds_with_reader(
            |buffer, _| {
                if let Some(buffer) = buffer {
                    reads += 1;
                    Ok(libc::c_int::try_from(std::mem::size_of_val(buffer)).unwrap())
                } else {
                    Ok(libc::c_int::try_from(record_size).unwrap())
                }
            },
            super::MAX_PROCESS_FDS,
            false,
        )
        .expect_err("a fourth FD buffer read must not start");

        assert_eq!(reads, crate::observation::NATIVE_RESIZE_ATTEMPTS_MAX);
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn aggregate_fd_allowance_refuses_before_native_buffer_allocation() {
        let record_size = size_of::<libc::proc_fdinfo>();
        let mut buffer_reads = 0;

        let error = list_process_fds_with_reader(
            |buffer, _| {
                if buffer.is_some() {
                    buffer_reads += 1;
                }
                Ok(libc::c_int::try_from(record_size).unwrap())
            },
            0,
            true,
        )
        .expect_err("one FD beyond the remaining aggregate allowance is refused");

        assert_eq!(buffer_reads, 0);
        assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
        assert!(error.to_string().contains("allowance"));
    }

    #[test]
    fn native_returned_lengths_accept_capacity_and_reject_capacity_plus_one() {
        assert_eq!(
            checked_returned_buffer_len(64, 64, "native_test").expect("exact capacity"),
            64
        );
        let error = checked_returned_buffer_len(65, 64, "native_test")
            .expect_err("capacity plus one is malformed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn aggregate_fd_limit_counts_every_entry_before_socket_filtering() {
        let regular_fd_type = 0;
        let fds = [
            libc::proc_fdinfo {
                proc_fd: 1,
                proc_fdtype: regular_fd_type,
            },
            libc::proc_fdinfo {
                proc_fd: 2,
                proc_fdtype: regular_fd_type,
            },
        ];
        let mut traversed = 0;
        let mut socket_reads = 0;
        collect_pid_socket_records_from_fds(7, &fds, &mut traversed, 2, |_| {
            socket_reads += 1;
            Ok(None)
        })
        .expect("the exact aggregate maximum is accepted");
        assert_eq!(traversed, 2);
        assert_eq!(socket_reads, 0);

        let error = collect_pid_socket_records_from_fds(8, &fds[..1], &mut traversed, 2, |_| {
            socket_reads += 1;
            Ok(None)
        })
        .expect_err("maximum plus one is rejected before socket filtering");
        assert_eq!(error.kind(), std::io::ErrorKind::FileTooLarge);
        assert_eq!(traversed, 3);
        assert_eq!(socket_reads, 0);
    }

    #[test]
    fn fresh_tree_evidence_rejects_zero_marker_and_marker_name_race() {
        let mut before = zeroed_bsd_info();
        let mut after = zeroed_bsd_info();
        assert_eq!(
            fresh_process_evidence_from_reads(7, &before, "worker".to_owned(), &after),
            Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
        );

        before.pbi_start_tvsec = 10;
        after.pbi_start_tvsec = 11;
        assert_eq!(
            fresh_process_evidence_from_reads(7, &before, "new-name".to_owned(), &after),
            Err(ProcessEvidenceError::IdentityChanged { pid: 7 })
        );
    }

    #[test]
    fn fresh_name_adapter_accepts_exact_4k_and_refuses_empty_and_max_plus_one() {
        let mut before = zeroed_bsd_info();
        before.pbi_start_tvsec = 10;
        let after = before;
        let limit = crate::observation::PROTECTION_NAME_MAX_BYTES;

        let exact = fresh_process_evidence_from_reads(7, &before, "x".repeat(limit), &after)
            .expect("exact 4 KiB name");
        assert_eq!(exact.name.len(), limit);
        assert_eq!(
            fresh_process_evidence_from_reads(7, &before, String::new(), &after),
            Err(ProcessEvidenceError::NameMissing { pid: 7 })
        );
        assert_eq!(
            fresh_process_evidence_from_reads(7, &before, "x".repeat(limit + 1), &after),
            Err(ProcessEvidenceError::NameOversized {
                pid: 7,
                bytes: limit + 1
            })
        );
    }

    #[test]
    fn bsd_start_marker_rejects_invalid_microseconds() {
        let mut info = zeroed_bsd_info();
        info.pbi_start_tvsec = 10;
        info.pbi_start_tvusec = 1_000_000;
        assert_eq!(
            super::process_start_time_marker_from_bsd_info(&info),
            Err(crate::observation::ProcessMarkerError::InvalidMicroseconds)
        );
    }

    #[test]
    fn non_utf8_executable_path_is_null_and_metadata_partial() {
        let observation = process_observation_from_metadata(ProcessMetadata {
            process_name: Some("worker".to_owned()),
            executable_path: Some(PathBuf::from(std::ffi::OsStr::from_bytes(b"/tmp/\xff"))),
            partial: false,
            ..ProcessMetadata::default()
        });

        assert!(observation.executable_path.is_none());
        assert_eq!(
            observation.metadata_completeness,
            MetadataCompleteness::Partial
        );
    }

    fn zeroed_bsd_info() -> libc::proc_bsdinfo {
        unsafe {
            // SAFETY: proc_bsdinfo is a plain-data C struct used as a test fixture.
            MaybeUninit::<libc::proc_bsdinfo>::zeroed().assume_init()
        }
    }

    #[test]
    fn tree_snapshot_row_maps_parent_and_start_marker_from_bsd_info() {
        let mut info = zeroed_bsd_info();
        info.pbi_ppid = 100;
        info.pbi_pgid = 4242;
        info.pbi_start_tvsec = 1_700_000_000;
        info.pbi_start_tvusec = 250_000;

        let row = super::tree_process_info_from_bsd(4242, &info, "node".to_owned())
            .expect("valid BSD info");

        assert_eq!(row.pid, 4242);
        assert_eq!(row.parent_pid, Some(100));
        assert_eq!(row.process_name.as_deref(), Some("node"));
        assert_eq!(row.process_group, Some(4242));
        assert_eq!(
            row.start_time_marker,
            crate::observation::ProcessStartMarker::macos(1_700_000_000, 250_000).ok()
        );

        // A launchd/kernel-rooted process reports parent PID 0, which must map
        // to "no parent", never to a real PID 0 edge.
        info.pbi_ppid = 0;
        let row = super::tree_process_info_from_bsd(1, &info, "launchd".to_owned())
            .expect("valid BSD info");
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
