//! The Linux `/proc` collector.
//!
//! This reads kernel-provided `/proc` files straight from disk on purpose,
//! rather than shelling out to `ss`, `lsof`, or `netstat`. All the socket-table
//! parsing and process-metadata digging stays in here, so Linux's particular
//! file formats never leak out into the shared CLI or TUI code.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, File};
use std::io::ErrorKind;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint,
};
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, DERIVED_PORT_ENTRIES_MAX, EndpointIdentity, EvidenceGap,
    EvidenceGapCode, EvidenceImpact, FILE_DESCRIPTOR_ENTRIES_MAX, Ipv6Scope, MetadataCompleteness,
    MetadataOmission, MetadataProfile, NATIVE_SOCKET_TABLE_MAX_BYTES, NativeSocketObservation,
    NetworkSnapshot, OWNER_EDGES_MAX, ObservationScope, ObservationScopeKind, OwnerAssociations,
    OwnerCompleteness, PROCESS_NAME_MAX_BYTES, PlatformSocketToken, ProcessIdentity,
    ProcessObservation, ProcessRead, ProcessStartMarker, SCOPE_IDENTIFIER_MAX_BYTES,
    ScopeLimitation, SnapshotCompleteness, SocketState as ObservationSocketState,
    TcpTimerObservation, UnverifiedOwnerReason,
};
use crate::process::{
    TreeDeliveryHandle, tree_cont, tree_cont_handle, tree_deliver_handle,
    tree_open_delivery_handle, tree_stop_handle,
};
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
use crate::tree::{TreeProcessInfo, TreeProcessOps, TreeSignalResult};

const PROC_ROOT: &str = "/proc";
// `/proc/net/{tcp,udp}{,6}` is one row per socket and read on every refresh, so
// it's bounded like every other /proc read here. The cap is deliberately generous
// (~100k sockets), but a socket table is the one /proc file we must not silently
// truncate: dropping bytes drops whole socket rows, i.e. real open ports. So
// `read_bounded_text` fails closed past this cap — the scan surfaces a clear
// error instead of a short, misleading table.
const MAX_CMDLINE_BYTES: usize = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
// `/proc/<pid>/status` and `/proc/<pid>/stat` are kernel-generated and read
// on every refresh, so they are bounded like every other /proc read here —
// and the reads fail closed past the cap rather than silently truncating,
// because a truncated stat line could parse a *prefix* of the start-time
// marker as a valid but wrong number: a wrong identity check on a kill path,
// not an error. The caps leave real files no way to trip the failure: stat is
// a fixed ~52-field line with comm capped at 16 bytes (a few hundred bytes),
// and status stays small except for `Groups:`, which can legitimately list up
// to NGROUPS_MAX (65536) GIDs — roughly 450 KiB — so its cap clears that with
// room to spare. `take()` reads only what exists, so the generous cap costs
// nothing on the ~1 KiB common case.
const MAX_STATUS_BYTES: usize = 1024 * 1024;
const MAX_STAT_BYTES: usize = 4 * 1024;
const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;
// The kernel's own pid_max (4 M) already bounds the /proc PID scan, but the
// bound deserves to be explicit and symmetric with the macOS collector's cap.
// Truncating would silently drop processes — potentially real port owners —
// so the scan fails closed past it, like the socket table above.
// Aggregate bounds for the two multiplicative parts of collection. One million
// fd entries covers ordinary high-density hosts while bounding procfs traversal;
// 262k rows allows substantial shared-socket fanout above the socket-table size.
// Both limits fail closed because a partial owner map or row set is misleading.
const SOCKET_LINK_PREFIX: &str = "socket:[";
const SOCKET_LINK_SUFFIX: &str = "]";

/// The Linux end of the collector contract.
pub(crate) struct LinuxCollector {
    proc_root: PathBuf,
    limits: CollectionLimits,
}

#[derive(Debug, Clone, Copy)]
struct CollectionLimits {
    process_ids: usize,
    fd_entries: usize,
    port_entries: usize,
}

impl CollectionLimits {
    const PRODUCTION: Self = Self {
        process_ids: CANDIDATE_PROCESS_IDS_MAX,
        fd_entries: FILE_DESCRIPTOR_ENTRIES_MAX,
        port_entries: DERIVED_PORT_ENTRIES_MAX,
    };
}

impl LinuxCollector {
    pub(crate) fn new() -> Self {
        Self {
            proc_root: PathBuf::from(PROC_ROOT),
            limits: CollectionLimits::PRODUCTION,
        }
    }

    #[cfg(test)]
    fn with_proc_root(proc_root: PathBuf) -> Self {
        Self {
            proc_root,
            limits: CollectionLimits::PRODUCTION,
        }
    }

    #[cfg(test)]
    fn with_proc_root_and_limits(proc_root: PathBuf, limits: CollectionLimits) -> Self {
        Self { proc_root, limits }
    }
}

pub(crate) fn fresh_process_evidence(
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    read_fresh_process_evidence(Path::new(PROC_ROOT), pid)
}

impl Collector for LinuxCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let raw_scope_identifier = fs::read_link(self.proc_root.join("self/ns/net")).ok();
        let scope_identifier = raw_scope_identifier
            .as_deref()
            .and_then(bounded_scope_identifier);
        let scope_read_failed = scope_identifier.is_none();
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            scope_identifier,
            [
                ScopeLimitation::OtherNetworkNamespacesExcluded,
                ScopeLimitation::Ipv6ScopeUnavailable,
                ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
            ],
        )?;
        let mut snapshot = crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| self.collect_native_pass(),
            |pids, profile, remaining| self.read_native_processes(pids, profile, remaining),
        )?;
        if snapshot
            .sockets
            .iter()
            .any(|socket| socket.local_endpoint.ipv6_scope == Some(Ipv6Scope::Unavailable))
        {
            push_snapshot_gap(
                &mut snapshot,
                EvidenceGap::new(
                    EvidenceImpact::Scope,
                    EvidenceGapCode::NativeFieldUnavailable,
                    None,
                    None,
                    "IPv6 scope identifiers are unavailable from Linux procfs socket rows",
                ),
            );
        }
        if scope_read_failed {
            push_snapshot_gap(
                &mut snapshot,
                EvidenceGap::new(
                    EvidenceImpact::Scope,
                    EvidenceGapCode::NativeFieldUnavailable,
                    None,
                    None,
                    "current network namespace identifier is unavailable",
                ),
            );
        }
        Ok(snapshot)
    }
}

fn push_snapshot_gap(snapshot: &mut NetworkSnapshot, gap: EvidenceGap) {
    if snapshot.evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
        snapshot.evidence_gaps.push(gap);
        snapshot.evidence_gaps.sort();
    } else {
        snapshot.omitted_evidence_gap_count = snapshot.omitted_evidence_gap_count.saturating_add(1);
    }
    if snapshot.completeness != SnapshotCompleteness::Raced {
        snapshot.completeness = SnapshotCompleteness::Partial;
    }
}

fn bounded_scope_identifier(path: &Path) -> Option<&str> {
    path.to_str()
        .filter(|identifier| identifier.len() <= SCOPE_IDENTIFIER_MAX_BYTES)
}

impl LinuxCollector {
    fn read_native_processes(
        &self,
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
                self.read_native_process_cached(pid, profile, remaining, &mut parent_names)
            },
        )
    }

    fn collect_native_pass(
        &self,
    ) -> Result<crate::observation::NativeObservationPass, CollectorError> {
        let records = collect_socket_records_bounded(&self.proc_root, self.limits.port_entries)?;
        let target_inodes: HashSet<u64> = records.iter().map(|record| record.inode).collect();
        let owner_scan = collect_socket_owners_detailed(
            &self.proc_root,
            &target_inodes,
            self.limits.process_ids,
            self.limits.fd_entries,
        )?;
        let projected_rows = records
            .iter()
            .filter(|record| {
                matches!(
                    record.state,
                    ObservationSocketState::Listen | ObservationSocketState::Bound
                )
            })
            .try_fold(0usize, |count, record| {
                count.checked_add(
                    owner_scan
                        .owners
                        .get(&record.inode)
                        .map_or(1, |owners| owners.len().max(1)),
                )
            });
        if projected_rows.is_none_or(|count| count > self.limits.port_entries) {
            return Err(resource_cap_error(
                &self.proc_root,
                format!(
                    "collected port rows exceed {} entry cap",
                    self.limits.port_entries
                ),
            ));
        }

        native_pass_from_records(&records, owner_scan)
    }

    #[cfg(test)]
    fn read_native_process(
        &self,
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<ProcessRead, CollectorError> {
        self.read_native_process_cached(
            pid,
            profile,
            optional_metadata_bytes_remaining,
            &mut HashMap::new(),
        )
    }

    fn read_native_process_cached(
        &self,
        pid: u32,
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
        parent_names: &mut HashMap<ProcessIdentity, Option<String>>,
    ) -> Result<ProcessRead, CollectorError> {
        let process_dir = self.proc_root.join(pid.to_string());
        let stat_path = process_dir.join("stat");
        let marker = match read_native_process_marker(&stat_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                return Err(CollectorError::Read {
                    path: stat_path,
                    source: error,
                });
            }
            Err(error) => {
                return Ok(ProcessRead::Unverified(unverified_reason_for_io(&error)));
            }
        };
        if profile == MetadataProfile::IdentityOnly {
            return Ok(ProcessRead::Verified {
                marker,
                observation: ProcessObservation::identity_only(),
            });
        }
        let metadata = if optional_metadata_bytes_remaining == 0 {
            ProcessMetadata {
                partial: true,
                budget_omitted: true,
                ..ProcessMetadata::default()
            }
        } else {
            read_process_metadata_bounded_with_parent_cache(
                &self.proc_root,
                pid,
                profile,
                optional_metadata_bytes_remaining,
                parent_names,
            )
        };
        let marker_after = match read_native_process_marker(&stat_path) {
            Ok(marker) => marker,
            Err(error) if error.kind() == ErrorKind::InvalidData => {
                return Err(CollectorError::Read {
                    path: stat_path,
                    source: error,
                });
            }
            Err(error) => {
                return Ok(ProcessRead::Unverified(unverified_reason_for_io(&error)));
            }
        };
        if marker_after != marker {
            return Ok(ProcessRead::Unverified(UnverifiedOwnerReason::Raced));
        }
        let path_invalid_utf8 = metadata
            .executable_path
            .as_ref()
            .is_some_and(|path| path.to_str().is_none());
        Ok(ProcessRead::Verified {
            marker: marker_after,
            observation: ProcessObservation {
                name: metadata.process_name.map(Into::into),
                executable_path: metadata
                    .executable_path
                    .filter(|path| path.to_str().is_some())
                    .map(Into::into),
                command_line: metadata.command_line.map(Into::into),
                parent_pid: metadata.parent_pid,
                parent_process_name: metadata.parent_process_name.map(Into::into),
                metadata_omission: metadata
                    .budget_omitted
                    .then_some(MetadataOmission::BudgetExceeded),
                metadata_completeness: if metadata.partial || path_invalid_utf8 {
                    MetadataCompleteness::Partial
                } else {
                    MetadataCompleteness::Complete
                },
            },
        })
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
    state: ObservationSocketState,
    timer: Option<TcpTimerObservation>,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum OwnerScanLoss {
    EnumerationIncomplete,
    AncestorPidOwnersInvisible,
    PermissionDenied(u32),
    Disappeared(u32),
    Unattributable(u32),
}

#[derive(Debug, Default)]
struct OwnerScanResult {
    owners: HashMap<u64, Vec<u32>>,
    losses: BTreeSet<OwnerScanLoss>,
    omitted_loss_count: u64,
    owner_edges: usize,
}

impl OwnerScanResult {
    fn record_loss(&mut self, loss: OwnerScanLoss) {
        if self.losses.contains(&loss) {
            return;
        }
        if self.losses.len() < crate::observation::EVIDENCE_GAPS_MAX {
            self.losses.insert(loss);
        } else {
            self.omitted_loss_count = self.omitted_loss_count.saturating_add(1);
        }
    }
}

fn native_pass_from_records(
    records: &[SocketRecord],
    owner_scan: OwnerScanResult,
) -> Result<crate::observation::NativeObservationPass, CollectorError> {
    let mut sockets = Vec::with_capacity(records.len());
    let mut owners_by_socket = Vec::with_capacity(records.len());
    for record in records {
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
            CollectorError::Observation(crate::observation::ObservationError::PlatformApiFailed(
                error.to_string(),
            ))
        })?;
        sockets.push(NativeSocketObservation {
            endpoint,
            state: record.state,
            timer: record.timer,
            token: PlatformSocketToken::linux_inode(record.inode),
        });
        owners_by_socket.push(
            owner_scan
                .owners
                .get(&record.inode)
                .cloned()
                .unwrap_or_default(),
        );
    }

    let ancestor_pid_owners_invisible = owner_scan
        .losses
        .contains(&OwnerScanLoss::AncestorPidOwnersInvisible);
    let mut reasons = BTreeSet::new();
    let mut evidence_gaps = Vec::with_capacity(owner_scan.losses.len());
    let mut omitted_evidence_gap_count = owner_scan.omitted_loss_count;
    for loss in owner_scan.losses {
        let (pid, code, message) = match loss {
            OwnerScanLoss::EnumerationIncomplete => (
                None,
                EvidenceGapCode::OwnerAttributionIncomplete,
                "process visibility or enumeration was incomplete before socket ownership could be attributed",
            ),
            OwnerScanLoss::AncestorPidOwnersInvisible => (
                None,
                EvidenceGapCode::OwnerAttributionIncomplete,
                "ancestor PID namespace processes may own sockets but are invisible to this process enumeration",
            ),
            OwnerScanLoss::PermissionDenied(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerPermissionDenied,
                "permission denied before the PID's socket ownership could be attributed",
            ),
            OwnerScanLoss::Disappeared(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerDisappeared,
                "PID disappeared before its socket ownership could be attributed",
            ),
            OwnerScanLoss::Unattributable(pid) => (
                Some(pid),
                EvidenceGapCode::OwnerAttributionIncomplete,
                "a PID file-descriptor entry could not be attributed to a socket",
            ),
        };
        reasons.insert(code);
        let gap = EvidenceGap::new(EvidenceImpact::Ownership, code, None, pid, message);
        if evidence_gaps.len() < crate::observation::EVIDENCE_GAPS_MAX {
            evidence_gaps.push(gap);
        } else {
            omitted_evidence_gap_count = omitted_evidence_gap_count.saturating_add(1);
        }
    }
    let global_completeness = OwnerCompleteness::partial(reasons)?;
    // Ordinary PID/fd traversal losses have no endpoint provenance and reduce
    // only global authority. Nested PID namespaces are different: an invisible
    // ancestor-namespace process may share any socket visible in the current
    // network namespace, so no socket's owner set is provably complete.
    let local_completeness = if ancestor_pid_owners_invisible {
        vec![
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?;
            records.len()
        ]
    } else {
        vec![OwnerCompleteness::Complete; records.len()]
    };
    Ok(crate::observation::NativeObservationPass {
        sockets,
        owners: OwnerAssociations {
            owners_by_socket,
            local_completeness,
            global_completeness,
            evidence_gaps,
            omitted_evidence_gap_count,
        },
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SocketParseError {
    #[error("invalid /proc/net socket table header")]
    InvalidHeader,
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
    #[error("invalid socket state {value}")]
    InvalidState { value: String },
    #[error("invalid TCP timer {value}")]
    InvalidTcpTimer { value: String },
    #[error("invalid inode {value}")]
    InvalidInode { value: String },
    #[error("socket observation limit exceeded")]
    SocketObservationLimitExceeded,
}

#[derive(Debug, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    partial: bool,
    budget_omitted: bool,
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

#[cfg(test)]
fn collect_socket_records(proc_root: &Path) -> Result<Vec<SocketRecord>, CollectorError> {
    collect_socket_records_bounded(proc_root, crate::observation::SOCKET_OBSERVATIONS_MAX)
}

fn collect_socket_records_bounded(
    proc_root: &Path,
    max_records: usize,
) -> Result<Vec<SocketRecord>, CollectorError> {
    let clock_ticks_per_second = linux_clock_ticks_per_second();
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
        let remaining = max_records.saturating_sub(records.len());
        let parsed = parse_socket_table(
            &text,
            table.protocol,
            table.address_family,
            clock_ticks_per_second,
            remaining,
        )
        .map_err(|error| match error {
            SocketParseError::SocketObservationLimitExceeded => CollectorError::Observation(
                crate::observation::ObservationError::SocketObservationLimitExceeded,
            ),
            error => CollectorError::Read {
                path: path.clone(),
                source: std::io::Error::new(ErrorKind::InvalidData, error),
            },
        })?;
        for record in parsed {
            if records.len() >= max_records {
                return Err(resource_cap_error(
                    proc_root,
                    format!("collected sockets exceed {max_records} entry cap"),
                ));
            }
            records.push(record);
        }
    }
    Ok(records)
}

fn read_socket_table(path: &Path, optional: bool) -> Result<Option<String>, CollectorError> {
    match read_bounded_text(path, NATIVE_SOCKET_TABLE_MAX_BYTES) {
        Ok(text) => Ok(Some(text)),
        Err(source) if optional && source.kind() == ErrorKind::NotFound => Ok(None),
        Err(source) => Err(CollectorError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_bounded_text(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    String::from_utf8(read_bounded_bytes(path, max_bytes)?)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
}

fn read_bounded_bytes(path: &Path, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let limit = u64::try_from(max_bytes)
        .expect("/proc read byte limit must fit in u64")
        .saturating_add(1);
    let mut bytes = Vec::new();
    File::open(path)?.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} byte read limit"),
        ));
    }
    Ok(bytes)
}

fn read_bounded_lossy_text(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let bytes = read_bounded_bytes(path, max_bytes)?;
    let decoded_len = crate::observation::lossy_utf8_len(&bytes).ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidData, "decoded text length overflow")
    })?;
    if decoded_len > max_bytes {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("decoded text exceeds {max_bytes} byte limit"),
        ));
    }
    let mut text = String::with_capacity(decoded_len);
    crate::observation::push_utf8_lossy(&mut text, &bytes);
    Ok(text)
}

fn parse_socket_table(
    text: &str,
    protocol: Protocol,
    address_family: AddressFamily,
    clock_ticks_per_second: Option<u64>,
    max_records: usize,
) -> Result<Vec<SocketRecord>, SocketParseError> {
    let mut lines = text.lines();
    let header = lines.next().ok_or(SocketParseError::InvalidHeader)?;
    let mut header_fields = header.split_whitespace();
    let expected_remote_address = match address_family {
        AddressFamily::Ipv4 => "rem_address",
        AddressFamily::Ipv6 => "remote_address",
    };
    if header_fields.next() != Some("sl")
        || header_fields.next() != Some("local_address")
        || header_fields.next() != Some(expected_remote_address)
        || header_fields.next() != Some("st")
        || header_fields.nth(7) != Some("inode")
    {
        return Err(SocketParseError::InvalidHeader);
    }

    let mut records = Vec::new();
    for (line_index, line) in lines.enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        if records.len() >= max_records {
            return Err(SocketParseError::SocketObservationLimitExceeded);
        }
        match parse_socket_line(line, protocol, address_family, clock_ticks_per_second) {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(line = line_index + 2, %error, "malformed /proc/net row");
                return Err(error);
            }
        }
    }
    Ok(records)
}

fn parse_socket_line(
    line: &str,
    protocol: Protocol,
    address_family: AddressFamily,
    clock_ticks_per_second: Option<u64>,
) -> Result<Option<SocketRecord>, SocketParseError> {
    let mut fields = line.split_whitespace();
    let _slot = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "sl" })?;
    let local = fields.next().ok_or(SocketParseError::MissingField {
        field: "local_address",
    })?;
    let _remote = fields.next().ok_or(SocketParseError::MissingField {
        field: "remote_address",
    })?;
    let state_hex = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "st" })?;
    let _queues = fields.next().ok_or(SocketParseError::MissingField {
        field: "tx_queue:rx_queue",
    })?;
    let timer_text = fields.next().ok_or(SocketParseError::MissingField {
        field: "tr:tm->when",
    })?;
    let _retransmits = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "retrnsmt" })?;
    let _uid = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "uid" })?;
    let _timeout = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "timeout" })?;
    let inode_hex = fields
        .next()
        .ok_or(SocketParseError::MissingField { field: "inode" })?;

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
    let native_state =
        u32::from_str_radix(state_hex, 16).map_err(|_| SocketParseError::InvalidState {
            value: state_hex.to_owned(),
        })?;
    let state = match protocol {
        Protocol::Tcp => linux_tcp_state(native_state),
        Protocol::Udp => ObservationSocketState::Bound,
    };
    let timer = match protocol {
        Protocol::Tcp => Some(parse_tcp_timer(timer_text, clock_ticks_per_second)?),
        Protocol::Udp => None,
    };

    Ok(Some(SocketRecord {
        protocol,
        local_addr,
        local_port,
        state,
        timer,
        inode,
    }))
}

const fn linux_tcp_state(native_state: u32) -> ObservationSocketState {
    match native_state {
        0x01 => ObservationSocketState::Established,
        0x02 => ObservationSocketState::SynSent,
        0x03 => ObservationSocketState::SynReceived,
        0x04 => ObservationSocketState::FinWait1,
        0x05 => ObservationSocketState::FinWait2,
        0x06 => ObservationSocketState::TimeWait,
        0x07 => ObservationSocketState::Closed,
        0x08 => ObservationSocketState::CloseWait,
        0x09 => ObservationSocketState::LastAck,
        0x0A => ObservationSocketState::Listen,
        0x0B => ObservationSocketState::Closing,
        0x0C => ObservationSocketState::NewSynReceived,
        code => ObservationSocketState::Unknown(code),
    }
}

fn parse_tcp_timer(
    value: &str,
    clock_ticks_per_second: Option<u64>,
) -> Result<TcpTimerObservation, SocketParseError> {
    let (kind, raw_ticks) =
        value
            .split_once(':')
            .ok_or_else(|| SocketParseError::InvalidTcpTimer {
                value: value.to_owned(),
            })?;
    let native_code =
        u32::from_str_radix(kind, 16).map_err(|_| SocketParseError::InvalidTcpTimer {
            value: value.to_owned(),
        })?;
    let raw_ticks =
        u64::from_str_radix(raw_ticks, 16).map_err(|_| SocketParseError::InvalidTcpTimer {
            value: value.to_owned(),
        })?;
    Ok(TcpTimerObservation::from_linux_native(
        native_code,
        raw_ticks,
        clock_ticks_per_second,
    ))
}

fn linux_clock_ticks_per_second() -> Option<u64> {
    // SAFETY: sysconf reads process-global configuration for a valid constant and
    // does not dereference pointers or retain caller-owned memory.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks).ok().filter(|ticks| *ticks != 0)
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
    // The kernel prints the address as its raw in-memory u32, so the hex is in
    // *host* byte order — localhost reads "0100007F" on little-endian machines.
    // Native-endian decoding is therefore correct on every target; a big-endian
    // "fix" here would flip every address (and fail the parser fixture tests).
    Ok(Ipv4Addr::from(raw.to_ne_bytes()))
}

fn decode_ipv6_addr(hex: &str) -> Result<IpAddr, SocketParseError> {
    if hex.len() != 32 {
        return Err(SocketParseError::InvalidIpv6Address {
            value: hex.to_owned(),
        });
    }

    // The kernel prints an IPv6 address as four raw in-memory u32 words, each
    // rendered as 8 hex chars in *host* byte order (same convention as the IPv4
    // decoder above). Each chunk of 8 hex chars covers 4 address bytes, so the
    // hex-char index `start` maps to byte index `start / 2`.
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

#[cfg(test)]
fn collect_socket_owners(
    proc_root: &Path,
    target_inodes: &HashSet<u64>,
    max_process_ids: usize,
    max_fd_entries: usize,
) -> Result<HashMap<u64, Vec<u32>>, CollectorError> {
    collect_socket_owners_detailed(proc_root, target_inodes, max_process_ids, max_fd_entries)
        .map(|result| result.owners)
}

fn collect_socket_owners_detailed(
    proc_root: &Path,
    target_inodes: &HashSet<u64>,
    max_process_ids: usize,
    max_fd_entries: usize,
) -> Result<OwnerScanResult, CollectorError> {
    if target_inodes.is_empty() {
        return Ok(OwnerScanResult::default());
    }

    let (pids, enumeration_incomplete) = owner_process_ids_with_limit(proc_root, max_process_ids)
        .map_err(|source| CollectorError::Read {
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
    let mut result = OwnerScanResult {
        owners: HashMap::with_capacity(target_inodes.len()),
        losses: BTreeSet::new(),
        omitted_loss_count: 0,
        owner_edges: 0,
    };
    if enumeration_incomplete || proc_visibility_restricted(proc_root) {
        result.record_loss(OwnerScanLoss::EnumerationIncomplete);
    }
    if ancestor_pid_visibility_not_proven(proc_root) {
        result.record_loss(OwnerScanLoss::AncestorPidOwnersInvisible);
    }
    let mut fd_entries_visited = 0;
    for pid in pids {
        scan_pid_socket_owners(
            proc_root,
            pid,
            target_inodes,
            &mut result,
            &mut fd_entries_visited,
            max_fd_entries,
        )?;
    }
    Ok(result)
}

fn process_ids(proc_root: &Path) -> std::io::Result<Vec<u32>> {
    process_ids_with_limit(proc_root, CANDIDATE_PROCESS_IDS_MAX)
}

fn process_ids_with_limit(proc_root: &Path, max_process_ids: usize) -> std::io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir(proc_root)? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pids.len() >= max_process_ids {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("process list exceeds {max_process_ids} PID cap"),
            ));
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    Ok(pids)
}

fn owner_process_ids_with_limit(
    proc_root: &Path,
    max_process_ids: usize,
) -> std::io::Result<(Vec<u32>, bool)> {
    let mut pids = Vec::new();
    let mut incomplete = false;
    for entry in fs::read_dir(proc_root)? {
        let Ok(entry) = entry else {
            incomplete = true;
            continue;
        };
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if pids.len() >= max_process_ids {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("process list exceeds {max_process_ids} PID cap"),
            ));
        }
        pids.push(pid);
    }
    pids.sort_unstable();
    Ok((pids, incomplete))
}

fn proc_visibility_restricted(proc_root: &Path) -> bool {
    let Ok(mounts) = read_bounded_text(&proc_root.join("mounts"), MAX_STATUS_BYTES) else {
        return false;
    };
    let proc_root = proc_root.as_os_str().as_bytes();
    mounts.lines().any(|line| {
        let mut fields = line.split_whitespace();
        let _source = fields.next();
        let mount_point = fields.next();
        let filesystem = fields.next();
        let options = fields.next();
        mount_point.is_some_and(|value| value.as_bytes() == proc_root)
            && filesystem == Some("proc")
            && options.is_some_and(|value| {
                value.split(',').any(|option| {
                    option
                        .strip_prefix("hidepid=")
                        .is_some_and(|mode| mode != "0" && mode != "off")
                })
            })
    })
}

fn ancestor_pid_visibility_not_proven(proc_root: &Path) -> bool {
    let Ok(status) = read_bounded_text(&proc_root.join("self/status"), MAX_STATUS_BYTES) else {
        return true;
    };
    let mut nspid_lines = status
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:"));
    let Some(nspid) = nspid_lines.next() else {
        return true;
    };
    if nspid_lines.next().is_some() {
        return true;
    }

    let mut id_count = 0usize;
    for field in nspid.split_whitespace() {
        let Ok(pid) = field.parse::<u32>() else {
            return true;
        };
        if pid == 0 {
            return true;
        }
        id_count += 1;
    }
    id_count != 1
}

#[cfg(test)]
fn collect_pid_socket_owners(
    proc_root: &Path,
    pid: u32,
    target_inodes: &HashSet<u64>,
    owners: &mut HashMap<u64, Vec<u32>>,
    fd_entries_visited: &mut usize,
    max_fd_entries: usize,
) -> Result<(), CollectorError> {
    let owner_edges = owners.values().map(Vec::len).sum();
    let mut result = OwnerScanResult {
        owners: std::mem::take(owners),
        losses: BTreeSet::new(),
        omitted_loss_count: 0,
        owner_edges,
    };
    let scan = scan_pid_socket_owners(
        proc_root,
        pid,
        target_inodes,
        &mut result,
        fd_entries_visited,
        max_fd_entries,
    );
    *owners = result.owners;
    scan
}

fn scan_pid_socket_owners(
    proc_root: &Path,
    pid: u32,
    target_inodes: &HashSet<u64>,
    result: &mut OwnerScanResult,
    fd_entries_visited: &mut usize,
    max_fd_entries: usize,
) -> Result<(), CollectorError> {
    let fd_dir = proc_root.join(pid.to_string()).join("fd");
    let fd_entries = match fs::read_dir(&fd_dir) {
        Ok(entries) => entries,
        Err(error) if process_vanished(&error) => {
            result.record_loss(OwnerScanLoss::Disappeared(pid));
            return Ok(());
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            result.record_loss(OwnerScanLoss::PermissionDenied(pid));
            return Ok(());
        }
        Err(source) => {
            return Err(CollectorError::Read {
                path: fd_dir,
                source,
            });
        }
    };

    for entry in fd_entries {
        if *fd_entries_visited >= max_fd_entries {
            return Err(resource_cap_error(
                &fd_dir,
                format!("file-descriptor traversal exceeds {max_fd_entries} entry cap"),
            ));
        }
        *fd_entries_visited += 1;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                result.record_loss(owner_scan_loss(pid, &error));
                continue;
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) => {
                result.record_loss(owner_scan_loss(pid, &error));
                continue;
            }
        };
        let Some(inode) = parse_socket_inode(&target) else {
            continue;
        };
        if !target_inodes.contains(&inode) {
            continue;
        }
        let pids = result.owners.entry(inode).or_default();
        if pids.last().copied() != Some(pid) {
            if result.owner_edges >= OWNER_EDGES_MAX {
                return Err(resource_cap_error(
                    &fd_dir,
                    format!("socket ownership exceeds {OWNER_EDGES_MAX} edge cap"),
                ));
            }
            pids.push(pid);
            result.owner_edges += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
fn append_sorted_owner(owners: &mut Vec<u32>, pid: u32) {
    if owners.last().copied() != Some(pid) {
        owners.push(pid);
    }
}

fn owner_scan_loss(pid: u32, error: &std::io::Error) -> OwnerScanLoss {
    if error.kind() == ErrorKind::PermissionDenied {
        OwnerScanLoss::PermissionDenied(pid)
    } else if process_vanished(error) {
        OwnerScanLoss::Disappeared(pid)
    } else {
        OwnerScanLoss::Unattributable(pid)
    }
}

fn unverified_reason_for_io(error: &std::io::Error) -> UnverifiedOwnerReason {
    if error.kind() == ErrorKind::PermissionDenied {
        UnverifiedOwnerReason::PermissionDenied
    } else if process_vanished(error) {
        UnverifiedOwnerReason::Disappeared
    } else {
        UnverifiedOwnerReason::IdentityUnavailable
    }
}

fn read_native_process_marker(path: &Path) -> std::io::Result<ProcessStartMarker> {
    let ticks = read_process_start_time_ticks(path)?;
    ProcessStartMarker::linux(ticks)
        .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
}

fn resource_cap_error(path: &Path, message: String) -> CollectorError {
    CollectorError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(ErrorKind::InvalidData, message),
    }
}

fn parse_socket_inode(target: &Path) -> Option<u64> {
    let text = target.to_str()?;
    let inode = text
        .strip_prefix(SOCKET_LINK_PREFIX)?
        .strip_suffix(SOCKET_LINK_SUFFIX)?;
    inode.parse::<u64>().ok()
}

#[cfg(test)]
fn read_process_metadata_bounded(
    proc_root: &Path,
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
) -> ProcessMetadata {
    read_process_metadata_bounded_with_parent_cache(
        proc_root,
        pid,
        profile,
        aggregate_remaining,
        &mut HashMap::new(),
    )
}

#[allow(
    clippy::too_many_lines,
    reason = "deterministic metadata field order and one aggregate budget stay together"
)]
fn read_process_metadata_bounded_with_parent_cache(
    proc_root: &Path,
    pid: u32,
    profile: MetadataProfile,
    aggregate_remaining: usize,
    parent_names: &mut HashMap<ProcessIdentity, Option<String>>,
) -> ProcessMetadata {
    if profile == MetadataProfile::IdentityOnly {
        return ProcessMetadata::default();
    }
    let process_dir = proc_root.join(pid.to_string());
    let mut metadata = ProcessMetadata::default();
    let mut remaining = aggregate_remaining;

    let name_budget = remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
    if let Ok(name) = read_bounded_lossy_text(&process_dir.join("comm"), name_budget)
        .map(|text| trimmed_non_empty(&text))
    {
        metadata.process_name = name;
        metadata.partial |= metadata.process_name.is_none();
        remaining = remaining.saturating_sub(metadata.process_name.as_ref().map_or(0, String::len));
    } else {
        metadata.partial = true;
        metadata.budget_omitted |= name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
    }

    let path_budget = remaining.min(crate::observation::EXECUTABLE_PATH_MAX_BYTES);
    match read_link_bounded(&process_dir.join("exe"), path_budget) {
        Ok(path)
            if path.as_os_str().as_encoded_bytes().len()
                <= remaining.min(crate::observation::EXECUTABLE_PATH_MAX_BYTES) =>
        {
            remaining = remaining.saturating_sub(path.as_os_str().as_encoded_bytes().len());
            metadata.executable_path = Some(path);
        }
        Err(_) | Ok(_) => {
            metadata.partial = true;
            metadata.budget_omitted |= path_budget < crate::observation::EXECUTABLE_PATH_MAX_BYTES;
        }
    }

    match read_process_status(&process_dir.join("status")) {
        Ok(ProcessStatus {
            parent_pid: Some(parent_pid),
            ..
        }) => {
            metadata.parent_pid = Some(parent_pid);
            if parent_pid != 0 {
                let parent_name_budget = remaining.min(crate::observation::PROCESS_NAME_MAX_BYTES);
                let parent_marker = read_native_process_marker(
                    &proc_root.join(parent_pid.to_string()).join("stat"),
                );
                let name = parent_marker.ok().and_then(|start_marker| {
                    let identity = ProcessIdentity {
                        pid: parent_pid,
                        start_marker,
                    };
                    if let Some(name) = parent_names.get(&identity) {
                        return name
                            .as_ref()
                            .filter(|name| name.len() <= parent_name_budget)
                            .cloned();
                    }
                    let name = (parent_name_budget != 0)
                        .then(|| {
                            read_bounded_lossy_text(
                                &proc_root.join(parent_pid.to_string()).join("comm"),
                                parent_name_budget,
                            )
                            .ok()
                            .and_then(|text| trimmed_non_empty(&text))
                        })
                        .flatten();
                    let marker_after = read_native_process_marker(
                        &proc_root.join(parent_pid.to_string()).join("stat"),
                    );
                    let verified = matches!(marker_after, Ok(after) if after == start_marker)
                        .then_some(name)
                        .flatten();
                    parent_names.insert(identity, verified.clone());
                    verified
                });
                if let Some(name) = name {
                    metadata.parent_process_name = Some(name);
                    remaining = remaining.saturating_sub(
                        metadata.parent_process_name.as_ref().map_or(0, String::len),
                    );
                } else {
                    metadata.partial = true;
                    metadata.budget_omitted |=
                        parent_name_budget < crate::observation::PROCESS_NAME_MAX_BYTES;
                }
            }
        }
        Ok(ProcessStatus {
            parent_pid: None, ..
        })
        | Err(_) => metadata.partial = true,
    }

    if profile == MetadataProfile::LegacyList {
        let command_line_budget = remaining.min(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES);
        if let Ok((command_line, truncated)) =
            read_cmdline_bounded(&process_dir.join("cmdline"), command_line_budget)
        {
            metadata.command_line = command_line;
            metadata.partial |= truncated;
            metadata.budget_omitted |= truncated;
        } else {
            metadata.partial = true;
            metadata.budget_omitted |=
                command_line_budget < crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        }
    }

    metadata
}

fn read_link_bounded(path: &Path, max_bytes: usize) -> std::io::Result<PathBuf> {
    if max_bytes == 0 {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            "symlink target has no remaining byte budget",
        ));
    }
    let reported_length = fs::symlink_metadata(path)
        .ok()
        .map(|metadata| metadata.len());
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut bytes = vec![0_u8; max_bytes];
    let written = unsafe {
        // SAFETY: `path` is NUL terminated, `bytes` is writable for its length
        // bytes, and readlink does not retain either pointer.
        libc::readlink(path.as_ptr(), bytes.as_mut_ptr().cast(), bytes.len())
    };
    if written < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let written = usize::try_from(written).expect("non-negative readlink size fits usize");
    if written == max_bytes && reported_length != u64::try_from(max_bytes).ok() {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("symlink target exceeds {max_bytes} byte limit"),
        ));
    }
    bytes.truncate(written);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn collect_process_context_from(proc_root: &Path, pid: u32) -> ProcessContext {
    let process_dir = proc_root.join(pid.to_string());
    let owner_uid = read_process_status(&process_dir.join("status"))
        .ok()
        .and_then(|status| status.owner_uid);
    let process_start_time_marker = read_process_start_time_ticks(&process_dir.join("stat"))
        .ok()
        .and_then(|ticks| ProcessStartMarker::linux(ticks).ok());
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

    fn cont(&mut self, pid: u32) -> TreeSignalResult {
        if let Some(handle) = self.delivery_handles.get(&pid) {
            tree_cont_handle(handle)
        } else {
            tree_cont(pid)
        }
    }

    // The verified start marker is unused on Linux: the pidfd opened before the
    // first stop already pins the process object, so delivery can never reach a
    // recycled PID regardless of markers.
    fn prepare_delivery(
        &mut self,
        pid: u32,
        _verified_start_marker: Option<ProcessStartMarker>,
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

    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        read_fresh_process_evidence(&self.proc_root, pid)
    }

    fn deliver(&mut self, pid: u32, mode: crate::process::KillMode) -> TreeSignalResult {
        let Some(handle) = self.delivery_handles.get(&pid) else {
            return TreeSignalResult::Denied;
        };
        tree_deliver_handle(handle, mode)
    }
}

fn read_fresh_process_evidence(
    proc_root: &Path,
    pid: u32,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    let process_dir = proc_root.join(pid.to_string());
    let start_marker = read_process_start_time_ticks(&process_dir.join("stat"))
        .map_err(|error| process_evidence_io_error(pid, &error))?;
    let name = read_bounded_text(
        &process_dir.join("comm"),
        crate::observation::PROTECTION_NAME_MAX_BYTES,
    )
    .map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            ProcessEvidenceError::NameOversized {
                pid,
                bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1,
            }
        } else {
            process_evidence_io_error(pid, &error)
        }
    })?
    .trim_end_matches(['\n', '\r'])
    .to_owned();
    if name.is_empty() {
        return Err(ProcessEvidenceError::NameMissing { pid });
    }
    let marker_after = read_process_start_time_ticks(&process_dir.join("stat"))
        .map_err(|error| process_evidence_io_error(pid, &error))?;
    if marker_after != start_marker {
        return Err(ProcessEvidenceError::IdentityChanged { pid });
    }
    Ok(FreshProcessEvidence {
        pid,
        start_marker: ProcessStartMarker::linux(marker_after)
            .map_err(|_| ProcessEvidenceError::IdentityChanged { pid })?,
        name,
    })
}

fn process_evidence_io_error(pid: u32, error: &std::io::Error) -> ProcessEvidenceError {
    if error.kind() == ErrorKind::PermissionDenied {
        ProcessEvidenceError::PermissionDenied { pid }
    } else {
        ProcessEvidenceError::Missing { pid }
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
    start_time_marker: ProcessStartMarker,
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
    let bytes = match read_stat_bytes(path) {
        Ok(bytes) => bytes,
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
    let start_time_marker = parse_process_start_time_ticks(&bytes)
        .and_then(|ticks| {
            ProcessStartMarker::linux(ticks)
                .map_err(|error| std::io::Error::new(ErrorKind::InvalidData, error))
        })
        .map_err(|source| CollectorError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    let Some(process_group) = parse_process_group_id(&bytes) else {
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

fn read_stat_bytes(path: &Path) -> std::io::Result<Vec<u8>> {
    read_bounded_bytes(path, MAX_STAT_BYTES)
}

/// Process group ID from `/proc/<pid>/stat`: field 5 overall, so the third
/// token after the `") "` comm terminator (state, ppid, pgrp).
fn parse_process_group_id(bytes: &[u8]) -> Option<u32> {
    let value = stat_field(bytes, 2).ok()?;
    std::str::from_utf8(value).ok()?.parse::<u32>().ok()
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
    let mut text = read_bounded_lossy_text(&process_dir.join("comm"), PROCESS_NAME_MAX_BYTES)?;
    let trimmed_len = text.trim_end_matches(['\n', '\r']).len();
    text.truncate(trimmed_len);
    Ok((!text.is_empty()).then_some(text))
}

fn read_process_status(path: &Path) -> std::io::Result<ProcessStatus> {
    parse_process_status(&read_bounded_text(path, MAX_STATUS_BYTES)?)
}

fn read_process_start_time_ticks(path: &Path) -> std::io::Result<u64> {
    parse_process_start_time_ticks(&read_bounded_bytes(path, MAX_STAT_BYTES)?)
}

fn parse_process_start_time_ticks(bytes: &[u8]) -> std::io::Result<u64> {
    // `/proc/<pid>/stat` is `pid (comm) state ...`, and comm is an unescaped task
    // name that can itself contain `)` and even `) `. Every field after comm is a
    // single char or an integer and holds no parens, so the *last* `") "` in the
    // line is always the real comm terminator. Splitting from the right is what
    // keeps this robust against a process named e.g. `ev) il`; a first/left split
    // would be fooled by a paren inside comm.
    // Once comm is stripped the fields are 1-indexed from `state` (field 3), so
    // start time (field 22) is the 20th token here — nth(19), zero-indexed.
    let start_time = stat_field(bytes, 19)?;
    let start_time = std::str::from_utf8(start_time)
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))?;
    start_time
        .parse::<u64>()
        .map_err(|source| std::io::Error::new(ErrorKind::InvalidData, source))
}

fn stat_field(bytes: &[u8], index: usize) -> std::io::Result<&[u8]> {
    let comm_end = bytes
        .windows(2)
        .rposition(|window| window == b") ")
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidData, "missing process-name terminator")
        })?;
    bytes[comm_end + 2..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .nth(index)
        .ok_or_else(|| std::io::Error::new(ErrorKind::InvalidData, "missing process stat field"))
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
    read_cmdline_bounded(path, MAX_CMDLINE_BYTES)
}

fn read_cmdline_bounded(path: &Path, max_bytes: usize) -> std::io::Result<(Option<String>, bool)> {
    let file = File::open(path)?;
    let read_limit = u64::try_from(max_bytes)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large"))?
        .checked_add(1)
        .ok_or_else(|| {
            std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large")
        })?;
    let mut reader = file.take(read_limit);
    let capacity = max_bytes.checked_add(1).ok_or_else(|| {
        std::io::Error::new(ErrorKind::InvalidInput, "cmdline limit is too large")
    })?;
    let mut bytes = Vec::with_capacity(capacity);
    reader.read_to_end(&mut bytes)?;

    let truncated = bytes.len() > max_bytes;
    if truncated {
        return Ok((None, true));
    }

    Ok(decode_cmdline(&bytes, max_bytes))
}

fn decode_cmdline(bytes: &[u8], max_bytes: usize) -> (Option<String>, bool) {
    let mut output_len = 0usize;
    let mut argument_count = 0usize;
    for argument in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let Some(argument_len) = crate::observation::lossy_utf8_len(argument) else {
            return (None, true);
        };
        let separator_len = usize::from(argument_count != 0);
        let Some(next_len) = output_len
            .checked_add(separator_len)
            .and_then(|length| length.checked_add(argument_len))
        else {
            return (None, true);
        };
        if next_len > max_bytes {
            return (None, true);
        }
        output_len = next_len;
        argument_count += 1;
    }

    if argument_count == 0 {
        return (None, false);
    }

    let mut output = String::with_capacity(output_len);
    for argument in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        if !output.is_empty() {
            output.push(' ');
        }
        crate::observation::push_utf8_lossy(&mut output, argument);
    }
    debug_assert_eq!(output.len(), output_len);
    (Some(output), false)
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::{Path, PathBuf};

    use super::{
        AddressFamily, CollectionLimits, LinuxCollector, MAX_CHILD_PROCESSES, MAX_STATUS_BYTES,
        OwnerScanLoss, OwnerScanResult, SocketParseError, SocketRecord,
        ancestor_pid_visibility_not_proven, append_sorted_owner, bounded_scope_identifier,
        collect_child_processes_from, collect_pid_socket_owners, collect_process_context_from,
        collect_related_process_hints_from, collect_socket_owners, collect_socket_owners_detailed,
        collect_socket_records, collect_tree_process_infos, decode_cmdline,
        native_pass_from_records, parse_process_group_id, parse_process_start_time_ticks,
        parse_process_status, parse_socket_inode, parse_socket_line, parse_socket_table,
        proc_visibility_restricted, read_bounded_text, read_cmdline, read_cmdline_bounded,
        read_fresh_process_evidence, read_link_bounded, read_process_metadata_bounded,
        read_process_status,
    };
    use crate::model::{PermissionStatus, Platform, Protocol};
    use crate::observation::{
        CANDIDATE_PROCESS_IDS_MAX, DERIVED_PORT_ENTRIES_MAX, EvidenceGapCode, EvidenceImpact,
        FILE_DESCRIPTOR_ENTRIES_MAX, OwnerCompleteness, PROCESS_NAME_MAX_BYTES,
        PlatformSocketToken, SCOPE_IDENTIFIER_MAX_BYTES, SnapshotCompleteness, SocketState,
        TcpTimerKind, UnverifiedOwnerReason,
    };

    #[test]
    fn scope_identifier_exact_max_is_retained_and_max_plus_one_is_omitted() {
        let exact = PathBuf::from("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES));
        let over = PathBuf::from("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1));

        assert_eq!(bounded_scope_identifier(&exact), exact.to_str());
        assert_eq!(bounded_scope_identifier(&over), None);
    }

    #[test]
    fn collector_reports_one_scope_gap_for_oversized_namespace_identifier() {
        let proc_root = temp_proc_root("oversized-scope-identifier");
        write_socket_table(&proc_root, "net/tcp", &[]);
        write_socket_table(&proc_root, "net/udp", &[]);
        fs::create_dir_all(proc_root.join("self/ns")).expect("test namespace directory");
        let namespace = proc_root.join("self/ns/net");
        let exact = "x".repeat(SCOPE_IDENTIFIER_MAX_BYTES);
        std::os::unix::fs::symlink(&exact, &namespace).expect("exact namespace identifier");
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        let exact_snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::Display,
        )
        .expect("exact scope identifier collects");
        assert_eq!(
            exact_snapshot.scope.identifier.as_deref(),
            Some(exact.as_str())
        );

        fs::remove_file(&namespace).expect("replace namespace identifier");
        std::os::unix::fs::symlink("x".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1), &namespace)
            .expect("oversized namespace identifier");
        let oversized_snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::Display,
        )
        .expect("oversized scope identifier remains a partial snapshot");

        assert_eq!(oversized_snapshot.scope.identifier, None);
        assert_eq!(
            oversized_snapshot.completeness,
            SnapshotCompleteness::Partial
        );
        assert_eq!(oversized_snapshot.omitted_evidence_gap_count, 0);
        assert_eq!(oversized_snapshot.evidence_gaps.len(), 1);
        let gap = &oversized_snapshot.evidence_gaps[0];
        assert_eq!(gap.impact, EvidenceImpact::Scope);
        assert_eq!(gap.code, EvidenceGapCode::NativeFieldUnavailable);
        assert_eq!(gap.endpoint, None);
        assert_eq!(gap.pid, None);

        fs::remove_dir_all(proc_root).expect("test proc root cleanup");
    }
    const HEADER: &str =
        "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";
    const HEADER6: &str = "sl local_address remote_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode";

    fn row(local: &str, state: &str, inode: u64) -> String {
        row_with_timer(local, state, "00:00000000", inode)
    }

    fn row_with_timer(local: &str, state: &str, timer: &str, inode: u64) -> String {
        format!(
            "   0: {local} 00000000:0000 {state} 00000000:00000000 {timer} 00000000 1000 0 {inode} 1 0000000000000000 100 0 0 10 0"
        )
    }

    #[test]
    fn shared_socket_owner_dedup_scales_with_sorted_owner_count() {
        let mut owners = Vec::new();
        for pid in 1..=32_768 {
            append_sorted_owner(&mut owners, pid);
            append_sorted_owner(&mut owners, pid);
        }

        assert_eq!(owners.len(), 32_768);
        assert_eq!(owners.first(), Some(&1));
        assert_eq!(owners.last(), Some(&32_768));
    }

    fn temp_proc_root(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock is after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-linux-{name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("net")).expect("test proc net directory must be created");
        fs::create_dir_all(path.join("self")).expect("test proc self directory must be created");
        fs::write(path.join("self/status"), "Name:\tkickoutchi\nNSpid:\t1\n")
            .expect("initial PID namespace evidence must be written");
        path
    }

    fn write_socket_table(proc_root: &Path, relative_path: &str, rows: &[String]) {
        let header = if relative_path.ends_with('6') {
            HEADER6
        } else {
            HEADER
        };
        let text = format!("{header}\n{}\n", rows.join("\n"));
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

    #[test]
    fn fresh_name_reader_accepts_exact_4k_and_refuses_empty_and_max_plus_one() {
        let proc_root = temp_proc_root("fresh-name-boundaries");
        let pid = 42;
        write_process(&proc_root, pid, "worker", 1);
        let comm = proc_root.join(pid.to_string()).join("comm");

        fs::write(
            &comm,
            "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES),
        )
        .expect("exact-max name");
        let exact = read_fresh_process_evidence(&proc_root, pid).expect("exact 4 KiB name");
        assert_eq!(
            exact.name.len(),
            crate::observation::PROTECTION_NAME_MAX_BYTES
        );

        fs::write(&comm, "").expect("empty name");
        assert_eq!(
            read_fresh_process_evidence(&proc_root, pid),
            Err(crate::process_evidence::ProcessEvidenceError::NameMissing { pid })
        );

        fs::write(
            &comm,
            "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES + 1),
        )
        .expect("oversized name");
        assert_eq!(
            read_fresh_process_evidence(&proc_root, pid),
            Err(
                crate::process_evidence::ProcessEvidenceError::NameOversized {
                    pid,
                    bytes: crate::observation::PROTECTION_NAME_MAX_BYTES + 1
                }
            )
        );
        fs::remove_dir_all(proc_root).expect("test proc root cleanup");
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
            Some(100),
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
    fn retains_and_maps_every_linux_tcp_state_and_unknown_codes() {
        let cases = [
            ("01", SocketState::Established),
            ("02", SocketState::SynSent),
            ("03", SocketState::SynReceived),
            ("04", SocketState::FinWait1),
            ("05", SocketState::FinWait2),
            ("06", SocketState::TimeWait),
            ("07", SocketState::Closed),
            ("08", SocketState::CloseWait),
            ("09", SocketState::LastAck),
            ("0A", SocketState::Listen),
            ("0B", SocketState::Closing),
            ("0C", SocketState::NewSynReceived),
            ("00", SocketState::Unknown(0)),
            ("FFFFFFFF", SocketState::Unknown(u32::MAX)),
        ];

        for (native, expected) in cases {
            let record = parse_socket_line(
                &row("0100007F:0BB8", native, 12_345),
                Protocol::Tcp,
                AddressFamily::Ipv4,
                Some(100),
            )
            .expect("numeric TCP state is valid")
            .expect("every TCP state is retained");
            assert_eq!(record.state, expected, "native state {native}");
        }
    }

    #[test]
    fn parses_udp_rows_as_bound_sockets() {
        let record = parse_socket_line(
            &row("00000000:14E9", "07", 902),
            Protocol::Udp,
            AddressFamily::Ipv4,
            Some(100),
        )
        .expect("valid row")
        .expect("udp row is kept");

        assert_eq!(record.protocol, Protocol::Udp);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(record.local_port, 5353);
        assert_eq!(record.state, SocketState::Bound);
        assert_eq!(record.timer, None);
    }

    #[test]
    fn rejects_malformed_or_out_of_range_udp_state() {
        for state in ["not-hex", "100000000"] {
            let error = parse_socket_line(
                &row("00000000:14E9", state, 902),
                Protocol::Udp,
                AddressFamily::Ipv4,
                Some(100),
            )
            .expect_err("UDP st must be bounded hexadecimal");
            assert_eq!(
                error,
                SocketParseError::InvalidState {
                    value: state.to_owned()
                }
            );
        }
    }

    #[test]
    fn parses_known_and_unknown_tcp_timers_with_checked_estimates() {
        let known = [
            ("00", TcpTimerKind::None),
            ("01", TcpTimerKind::Retransmit),
            ("02", TcpTimerKind::Other),
            ("03", TcpTimerKind::TimeWait),
            ("04", TcpTimerKind::ZeroWindowProbe),
        ];
        for (native, expected_kind) in known {
            let record = parse_socket_line(
                &row_with_timer("0100007F:0BB8", "01", &format!("{native}:00000001"), 7),
                Protocol::Tcp,
                AddressFamily::Ipv4,
                Some(3),
            )
            .expect("known timer parses")
            .expect("TCP row is retained");
            let timer = record.timer.expect("TCP rows carry timer evidence");
            assert_eq!(timer.kind, expected_kind);
            assert_eq!(timer.native_code, None);
            assert_eq!(timer.raw_ticks, 1);
            assert_eq!(timer.estimated_remaining_milliseconds, Some(334));
        }

        let unknown = parse_socket_line(
            &row_with_timer("0100007F:0BB8", "01", "FFFFFFFF:0000000A", 7),
            Protocol::Tcp,
            AddressFamily::Ipv4,
            None,
        )
        .expect("bounded unknown timer parses")
        .expect("TCP row is retained")
        .timer
        .expect("TCP rows carry timer evidence");
        assert_eq!(unknown.kind, TcpTimerKind::Unknown(u32::MAX));
        assert_eq!(unknown.native_code, Some(u32::MAX));
        assert_eq!(unknown.raw_ticks, 10);
        assert_eq!(unknown.estimated_remaining_milliseconds, None);
    }

    #[test]
    fn rejects_malformed_or_out_of_range_tcp_timer_fields() {
        for timer in [
            "00",
            "x:00000001",
            "100000000:00000001",
            "00:x",
            "00:10000000000000000",
        ] {
            let error = parse_socket_line(
                &row_with_timer("0100007F:0BB8", "01", timer, 7),
                Protocol::Tcp,
                AddressFamily::Ipv4,
                Some(100),
            )
            .expect_err("malformed timer text must fail the table");
            assert_eq!(
                error,
                SocketParseError::InvalidTcpTimer {
                    value: timer.to_owned()
                }
            );
        }
    }

    #[test]
    fn decodes_ipv6_loopback_rows() {
        let record = parse_socket_line(
            &row("00000000000000000000000001000000:1F90", "0A", 55),
            Protocol::Tcp,
            AddressFamily::Ipv6,
            Some(100),
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
            Some(100),
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
        let missing = parse_socket_line("0:", Protocol::Tcp, AddressFamily::Ipv4, Some(100))
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
            Some(100),
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
            Some(100),
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
    fn table_parser_rejects_a_pass_containing_a_malformed_row() {
        let text = format!(
            "{HEADER}\n{}\nnot enough fields\n{}\n",
            row("0100007F:0BB8", "0A", 1),
            row("0100007F:1770", "01", 2),
        );
        let error = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8)
            .expect_err("an authoritative table with a malformed row must fail");

        assert!(matches!(error, SocketParseError::MissingField { .. }));
    }

    #[test]
    fn table_parser_rejects_empty_garbage_and_headerless_inputs() {
        let first = row("0100007F:0BB8", "0A", 1);
        let second = row("0100007F:1770", "01", 2);
        for text in [
            String::new(),
            "not a proc socket table\n".to_owned(),
            format!("{first}\n"),
            format!("{first}\n{second}\n"),
        ] {
            assert_eq!(
                parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8,),
                Err(SocketParseError::InvalidHeader),
                "input must not be accepted without the procfs header: {text:?}",
            );
        }
    }

    #[test]
    fn table_parser_accepts_header_only_and_normal_proc_tables() {
        assert_eq!(
            parse_socket_table(HEADER, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8,),
            Ok(Vec::new()),
        );
        assert_eq!(
            parse_socket_table(HEADER6, Protocol::Tcp, AddressFamily::Ipv6, Some(100), 8,),
            Ok(Vec::new()),
        );

        let text = format!("  {HEADER}  \n{}\n", row("0100007F:0BB8", "0A", 7));
        let records = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 8)
            .expect("normal proc socket table parses");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].inode, 7);
        assert_eq!(records[0].local_port, 3000);
    }

    #[test]
    fn table_parser_refuses_the_first_row_past_its_retention_limit() {
        let text = format!(
            "{HEADER}\n{}\n{}\n",
            row("0100007F:0BB8", "0A", 1),
            row("0100007F:1770", "01", 2),
        );
        let exact = parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 2)
            .expect("exact socket retention limit is accepted");
        assert_eq!(exact.len(), 2);

        assert_eq!(
            parse_socket_table(&text, Protocol::Tcp, AddressFamily::Ipv4, Some(100), 1,),
            Err(SocketParseError::SocketObservationLimitExceeded)
        );
    }

    #[test]
    fn collector_fails_a_pass_with_a_malformed_authoritative_socket_row() {
        let proc_root = temp_proc_root("malformed-authoritative-row");
        let text = format!(
            "{HEADER}\n{}\nnot enough fields\n",
            row("0100007F:0BB8", "0A", 1),
        );
        fs::write(proc_root.join("net/tcp"), text).expect("test TCP table must be written");
        write_socket_table(&proc_root, "net/udp", &[]);

        let collector = LinuxCollector::with_proc_root(proc_root.clone());
        let error = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect_err("malformed authoritative rows must fail the pass");

        assert!(error.to_string().contains("net/tcp"), "{error}");
        assert!(error.to_string().contains("missing field"), "{error}");
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
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
    fn executable_symlink_reader_enforces_budget_before_read_allocation() {
        let root = temp_proc_root("bounded-readlink");
        fs::create_dir_all(&root).expect("fixture root");
        let link = root.join("exe");
        std::os::unix::fs::symlink("12345678", &link).expect("fixture symlink");

        assert_eq!(
            read_link_bounded(&link, 8).expect("exact byte maximum is accepted"),
            PathBuf::from("12345678"),
        );
        assert_eq!(
            read_link_bounded(&link, 7)
                .expect_err("maximum plus one is rejected")
                .kind(),
            ErrorKind::InvalidData,
        );
        fs::remove_dir_all(root).expect("remove fixture root");
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
    fn command_line_decoding_accepts_exact_output_max_and_counts_separators() {
        assert_eq!(
            decode_cmdline(b"python3\0-m\0http.server\x003000\0", 27),
            (Some("python3 -m http.server 3000".to_owned()), false)
        );
        assert_eq!(
            decode_cmdline(b"ab\0cd\0", 5),
            (Some("ab cd".to_owned()), false)
        );
        assert_eq!(decode_cmdline(b"ab\0cd\0", 4), (None, true));
    }

    #[test]
    fn command_line_decoding_handles_empty_arguments_without_extra_spaces() {
        assert_eq!(decode_cmdline(b"", 0), (None, false));
        assert_eq!(decode_cmdline(b"\0\0", 0), (None, false));
        assert_eq!(
            decode_cmdline(b"\0alpha\0\0beta\0", 10),
            (Some("alpha beta".to_owned()), false)
        );
    }

    #[test]
    fn command_line_decoding_bounds_lossy_utf8_expansion() {
        assert_eq!(
            decode_cmdline(b"a\xff\0b", 6),
            (Some("a� b".to_owned()), false)
        );
        assert_eq!(decode_cmdline(b"a\xff\0b", 5), (None, true));
        assert_eq!(decode_cmdline(b"\xff", 2), (None, true));
    }

    #[test]
    fn command_line_reader_rejects_lossy_output_over_max_when_raw_bytes_fit() {
        let proc_root = temp_proc_root("lossy-command-line-boundary");
        let path = proc_root.join("cmdline");
        fs::write(&path, [0xff]).expect("invalid UTF-8 command fixture");

        assert_eq!(
            read_cmdline_bounded(&path, 3).expect("exact decoded maximum reads"),
            (Some("�".to_owned()), false)
        );
        assert_eq!(
            read_cmdline_bounded(&path, 2).expect("decoded overage is typed"),
            (None, true)
        );

        fs::remove_dir_all(proc_root).expect("test proc root cleanup");
    }

    #[test]
    fn legacy_command_line_retains_exact_one_mib_and_rejects_max_plus_one() {
        let proc_root = temp_proc_root("legacy-command-line-boundary");
        let pid = 42;
        write_process(&proc_root, pid, "worker", 0);
        let path = proc_root.join(pid.to_string()).join("cmdline");
        let limit = crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES;
        assert_eq!(limit, 1024 * 1024);

        fs::write(&path, vec![b'x'; limit]).expect("exact-limit command fixture");
        let (command, partial) = read_cmdline(&path).expect("authoritative exact limit reads");
        assert_eq!(command.as_deref().map(str::len), Some(limit));
        assert!(!partial);

        fs::write(&path, vec![b'x'; limit + 1]).expect("oversized command fixture");
        let (command, partial) = read_cmdline(&path).expect("authoritative over limit is typed");
        assert_eq!(command, None);
        assert!(partial);

        let legacy = read_process_metadata_bounded(
            &proc_root,
            pid,
            crate::observation::MetadataProfile::LegacyList,
            usize::MAX,
        );
        assert!(legacy.command_line.is_none());
        assert!(legacy.partial);
        assert!(
            legacy.budget_omitted,
            "oversize must produce an evidence gap"
        );

        let display = read_process_metadata_bounded(
            &proc_root,
            pid,
            crate::observation::MetadataProfile::Display,
            usize::MAX,
        );
        assert!(
            display.command_line.is_none(),
            "Display skips command lines"
        );
        fs::remove_dir_all(proc_root).expect("test proc root cleanup");
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
        assert_eq!(parse_process_group_id(text.as_bytes()), Some(4242));
        assert_eq!(parse_process_group_id(b"garbage with no comm"), None);

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

        let start_time = parse_process_start_time_ticks(text.as_bytes())
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

        let start_time = parse_process_start_time_ticks(text.as_bytes())
            .expect("paren-laden comm must still parse");

        assert_eq!(start_time, 987_654);
    }

    #[test]
    fn process_identity_parsing_ignores_non_utf8_comm_bytes() {
        let text = stat_text(1234, "node", 1, 987_654);
        let mut bytes = text.into_bytes();
        let name = bytes
            .windows(4)
            .position(|window| window == b"node")
            .expect("fixture contains comm");
        bytes[name] = 0xff;

        assert_eq!(
            parse_process_start_time_ticks(&bytes).expect("numeric tail remains authoritative"),
            987_654
        );
        assert_eq!(parse_process_group_id(&bytes), Some(0));

        let proc_root = temp_proc_root("non-utf8-stat");
        let stat = proc_root.join("stat");
        fs::write(&stat, &bytes).expect("non-UTF-8 stat fixture");
        assert!(super::read_native_process_marker(&stat).is_ok());
        fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
    }

    #[test]
    fn restricted_proc_visibility_makes_global_ownership_partial() {
        let proc_root = temp_proc_root("hidepid-owner-scan");
        fs::write(
            proc_root.join("mounts"),
            format!(
                "proc {} proc rw,nosuid,nodev,hidepid=2 0 0\n",
                proc_root.display()
            ),
        )
        .expect("mount fixture");
        assert!(proc_visibility_restricted(&proc_root));

        let scan = collect_socket_owners_detailed(&proc_root, &HashSet::from([7]), 4, 4)
            .expect("restricted empty scan remains evidence");
        assert!(scan.losses.contains(&OwnerScanLoss::EnumerationIncomplete));
        let pass = native_pass_from_records(&[], scan).expect("loss is representable");
        assert!(matches!(
            pass.owners.global_completeness,
            OwnerCompleteness::Partial { .. }
        ));
        assert_eq!(pass.owners.evidence_gaps[0].pid, None);

        fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
    }

    #[test]
    fn initial_pid_namespace_keeps_visible_socket_ownership_complete() {
        let proc_root = temp_proc_root("initial-pid-namespace");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 1234, "worker", 1);
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234/fd/0"))
            .expect("visible socket owner fixture");
        fs::create_dir_all(proc_root.join("self")).expect("self proc fixture");
        fs::write(
            proc_root.join("self/status"),
            "Name:\tkickoutchi\nUmask:\t0022\nState:\tR (running)\nTgid:\t4321\nNgid:\t0\nPid:\t4321\nPPid:\t4000\nTracerPid:\t0\nNSpid:\t4321\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .expect("production-shaped initial namespace status");

        assert!(!ancestor_pid_visibility_not_proven(&proc_root));
        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::Display,
        )
        .expect("initial PID namespace collection succeeds");
        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::Complete
        );

        fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
    }

    #[test]
    fn nested_pid_namespace_marks_visible_owner_and_hidden_co_owner_incomplete() {
        let proc_root = temp_proc_root("nested-pid-namespace");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 12, "visible-worker", 1);
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("12/fd/0"))
            .expect("visible socket owner fixture");
        fs::create_dir_all(proc_root.join("self")).expect("self proc fixture");
        fs::write(
            proc_root.join("self/status"),
            "Name:\tkickoutchi\nUmask:\t0022\nState:\tR (running)\nTgid:\t12\nNgid:\t0\nPid:\t12\nPPid:\t1\nTracerPid:\t0\nNSpid:\t4321\t12\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .expect("production-shaped nested namespace status");

        assert!(ancestor_pid_visibility_not_proven(&proc_root));
        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::Display,
        )
        .expect("nested PID namespace collection remains usable");
        let visible_owner_pids = snapshot.sockets[0]
            .owners
            .iter()
            .map(|owner| match owner {
                crate::observation::OwnerObservation::Verified(identity) => identity.pid,
                crate::observation::OwnerObservation::UnverifiedPid { pid, .. } => *pid,
            })
            .collect::<Vec<_>>();
        assert_eq!(visible_owner_pids, [12]);
        assert!(!snapshot.owner_completeness.is_complete());
        assert!(!snapshot.sockets[0].owner_completeness.is_complete());
        assert!(snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::OwnerAttributionIncomplete && gap.pid.is_none()
        }));

        fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
    }

    #[test]
    fn missing_or_malformed_nspid_cannot_prove_complete_pid_visibility() {
        let proc_root = temp_proc_root("unknown-pid-namespace");
        fs::remove_file(proc_root.join("self/status")).expect("remove default status fixture");
        assert!(ancestor_pid_visibility_not_proven(&proc_root));

        for status in [
            "Name:\tkickoutchi\nPid:\t123\n",
            "Name:\tkickoutchi\nNSpid:\t123\tnot-a-pid\n",
            "Name:\tkickoutchi\nNSpid:\t123\t12\nNSpid:\t123\t12\n",
        ] {
            fs::write(proc_root.join("self/status"), status).expect("status fixture");
            assert!(
                ancestor_pid_visibility_not_proven(&proc_root),
                "status: {status:?}"
            );
        }

        fs::remove_dir_all(proc_root).expect("temp proc root must clean up");
    }

    #[test]
    fn status_read_parses_inside_the_cap_and_fails_closed_past_it() {
        // The cap is sized so every legitimate `status` file fits (even a
        // pathological `Groups:` line stays under it), and past the cap the
        // read must fail closed rather than hand the parser a silently
        // truncated view: a partial file that still "parses" is exactly the
        // wrong-but-valid answer the bounded-read convention exists to stop.
        let proc_root = temp_proc_root("status-cap");
        let process_dir = proc_root.join("99");
        fs::create_dir_all(&process_dir).expect("test process directory must exist");
        let status_path = process_dir.join("status");

        // A large-but-legitimate file (a long Groups line) parses fine.
        let groups = (0..60_000u32).fold(String::from("Groups:"), |mut line, gid| {
            line.push(' ');
            line.push_str(&gid.to_string());
            line
        });
        let status = format!("Name:\tnode\nPPid:\t42\n{groups}\n");
        assert!(status.len() < MAX_STATUS_BYTES, "fixture must fit the cap");
        fs::write(&status_path, status).expect("test status must be written");
        let parent = read_process_status(&status_path)
            .expect("in-cap status read must succeed")
            .parent_pid;
        assert_eq!(parent, Some(42));

        // Past the cap the read fails closed, PPid or not.
        let oversized = format!(
            "Name:\tnode\nPPid:\t42\n{}",
            "Filler:\t0\n".repeat(MAX_STATUS_BYTES / 8),
        );
        assert!(
            oversized.len() > MAX_STATUS_BYTES,
            "fixture must exceed cap"
        );
        fs::write(&status_path, oversized).expect("test status must be written");
        let error =
            read_process_status(&status_path).expect_err("over-cap status read must fail closed");
        assert_eq!(error.kind(), ErrorKind::InvalidData);

        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn linux_collection_enriches_rows_with_parent_metadata() {
        let proc_root = temp_proc_root("parent-metadata");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 1234, "node", 1);
        write_process(&proc_root, 1, "systemd", 0);
        std::os::unix::fs::symlink("socket:[77]", proc_root.join("1234").join("fd").join("0"))
            .expect("test socket symlink must be created");

        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect("test proc root must collect");
        let entries = crate::observation::project_legacy(&snapshot).expect("legacy projection");

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
    fn retried_enrichment_does_not_reuse_parent_names_from_discarded_attempts() {
        let proc_root = temp_proc_root("parent-metadata-retry");
        write_process(&proc_root, 1234, "child", 1);
        write_process(&proc_root, 1, "parent-old", 0);
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        let discarded = collector
            .read_native_processes(
                &[1234],
                crate::observation::MetadataProfile::Display,
                crate::observation::OPTIONAL_METADATA_MAX_BYTES,
            )
            .expect("discarded enrichment pass reads");
        fs::write(proc_root.join("1/comm"), "parent-new\n")
            .expect("parent name changes without changing its start marker");
        let accepted = collector
            .read_native_processes(
                &[1234],
                crate::observation::MetadataProfile::Display,
                crate::observation::OPTIONAL_METADATA_MAX_BYTES,
            )
            .expect("accepted retry reads");

        let discarded_parent_name = match &discarded[&1234] {
            crate::observation::ProcessRead::Verified { observation, .. } => {
                observation.parent_process_name.clone()
            }
            crate::observation::ProcessRead::Unverified(_) => None,
        };
        let accepted_parent_name = match &accepted[&1234] {
            crate::observation::ProcessRead::Verified { observation, .. } => {
                observation.parent_process_name.clone()
            }
            crate::observation::ProcessRead::Unverified(_) => None,
        };
        assert_eq!(discarded_parent_name.as_deref(), Some("parent-old"));
        assert_eq!(accepted_parent_name.as_deref(), Some("parent-new"));
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

        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect("test proc root must collect");
        let entries = crate::observation::project_legacy(&snapshot).expect("legacy projection");
        let pids = entries.iter().map(|entry| entry.pid).collect::<Vec<_>>();

        assert_eq!(pids, vec![Some(1234), Some(1235)]);
        assert!(entries.iter().all(|entry| entry.local_port == 3000));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn native_snapshot_retains_inode_and_complete_empty_owner_set() {
        let proc_root = temp_proc_root("native-inode-ownerless");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::Display,
        )
        .expect("native ownerless collection succeeds");

        assert_eq!(snapshot.sockets.len(), 1);
        assert_eq!(
            snapshot.sockets[0].socket_token,
            PlatformSocketToken::linux_inode(77)
        );
        assert_eq!(
            snapshot.sockets[0]
                .timer
                .expect("TCP timer is retained")
                .kind,
            TcpTimerKind::None
        );
        assert!(snapshot.sockets[0].owners.is_empty());
        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::Complete
        );
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn native_snapshot_retains_full_tcp_state_and_timer_before_legacy_projection() {
        let proc_root = temp_proc_root("native-full-state");
        write_socket_table(
            &proc_root,
            "net/tcp",
            &[
                row_with_timer("0100007F:0BB8", "01", "01:0000000A", 77),
                row_with_timer("0100007F:0BB9", "02", "FF:0000000A", 78),
                row("0100007F:0BBA", "03", 79),
                row("0100007F:0BBB", "04", 80),
                row("0100007F:0BBC", "05", 81),
                row("0100007F:0BBD", "06", 82),
                row("0100007F:0BBE", "07", 83),
                row("0100007F:0BBF", "08", 84),
                row("0100007F:0BC0", "09", 85),
                row("0100007F:0BC1", "0A", 86),
                row("0100007F:0BC2", "0B", 87),
                row("0100007F:0BC3", "0C", 88),
                row("0100007F:0BC4", "FF", 89),
            ],
        );
        write_socket_table(&proc_root, "net/udp", &[]);

        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::Display,
        )
        .expect("full-state native snapshot collects");

        let established = snapshot
            .sockets
            .iter()
            .find(|socket| socket.state == crate::observation::SocketState::Established)
            .expect("established row survives the platform bridge");
        assert_eq!(established.local_endpoint.port.get(), 3000);
        assert_eq!(
            established.timer.expect("nonzero timer survives").kind,
            TcpTimerKind::Retransmit
        );
        let timer = established.timer.expect("nonzero timer survives");
        assert_eq!(timer.native_code, None);
        assert_eq!(timer.raw_ticks, 10);
        assert!(timer.estimated_remaining_milliseconds.is_some());

        let syn_sent = snapshot
            .sockets
            .iter()
            .find(|socket| socket.state == crate::observation::SocketState::SynSent)
            .expect("SYN-SENT row survives the platform bridge");
        let unknown_timer = syn_sent.timer.expect("unknown timer survives");
        assert_eq!(unknown_timer.kind, TcpTimerKind::Unknown(255));
        assert_eq!(unknown_timer.native_code, Some(255));
        assert_eq!(unknown_timer.raw_ticks, 10);
        assert!(unknown_timer.estimated_remaining_milliseconds.is_some());

        let retained_states = snapshot
            .sockets
            .iter()
            .map(|socket| socket.state)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            retained_states,
            [
                crate::observation::SocketState::Closed,
                crate::observation::SocketState::Listen,
                crate::observation::SocketState::SynSent,
                crate::observation::SocketState::SynReceived,
                crate::observation::SocketState::Established,
                crate::observation::SocketState::FinWait1,
                crate::observation::SocketState::FinWait2,
                crate::observation::SocketState::CloseWait,
                crate::observation::SocketState::Closing,
                crate::observation::SocketState::LastAck,
                crate::observation::SocketState::TimeWait,
                crate::observation::SocketState::NewSynReceived,
                crate::observation::SocketState::Unknown(255),
            ]
            .into_iter()
            .collect()
        );
        let legacy = crate::observation::project_legacy(&snapshot).expect("legacy projection fits");
        assert_eq!(legacy.len(), 1);
        assert_eq!(legacy[0].local_port, 3009);
        assert_eq!(legacy[0].state, crate::model::SocketState::Listen);

        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn unavailable_ipv6_scope_adds_exactly_one_scope_gap() {
        let proc_root = temp_proc_root("ipv6-scope-gap");
        write_socket_table(&proc_root, "net/tcp", &[]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_socket_table(
            &proc_root,
            "net/tcp6",
            &[
                row("00000000000000000000000001000000:0BB8", "01", 11),
                row("00000000000000000000000001000000:0BB9", "02", 12),
            ],
        );
        write_socket_table(&proc_root, "net/udp6", &[]);
        fs::create_dir_all(proc_root.join("self/ns")).expect("test namespace directory");
        std::os::unix::fs::symlink("net:[42]", proc_root.join("self/ns/net"))
            .expect("test namespace identifier");
        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &LinuxCollector::with_proc_root(proc_root.clone()),
            crate::observation::MetadataProfile::Display,
        )
        .expect("IPv6 scope loss remains a partial snapshot");

        assert_eq!(
            snapshot
                .evidence_gaps
                .iter()
                .filter(|gap| {
                    gap.code == EvidenceGapCode::NativeFieldUnavailable
                        && gap.impact == EvidenceImpact::Scope
                        && gap.endpoint.is_none()
                })
                .count(),
            1
        );
        assert_eq!(snapshot.sockets.len(), 2);
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
        assert!(snapshot.evidence_gaps.iter().all(|gap| {
            gap.code != EvidenceGapCode::NativeFieldUnavailable
                || gap.impact == EvidenceImpact::Scope
        }));
        fs::remove_dir_all(proc_root).expect("test proc root cleanup");
    }

    #[test]
    fn native_snapshot_retains_shared_socket_owners() {
        let proc_root = temp_proc_root("native-shared-socket");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 77)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        for pid in [1234, 1235] {
            write_process(&proc_root, pid, "worker", 1);
            std::os::unix::fs::symlink("socket:[77]", proc_root.join(pid.to_string()).join("fd/0"))
                .expect("shared socket symlink must be created");
        }
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        let snapshot = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::Display,
        )
        .expect("native shared ownership collection succeeds");
        let owner_pids = snapshot.sockets[0]
            .owners
            .iter()
            .map(|owner| match owner {
                crate::observation::OwnerObservation::Verified(identity) => identity.pid,
                crate::observation::OwnerObservation::UnverifiedPid { pid, .. } => *pid,
            })
            .collect::<Vec<_>>();

        assert_eq!(owner_pids, vec![1234, 1235]);
        assert_eq!(snapshot.processes.len(), 2);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn unattributable_owner_scan_denial_is_global_not_socket_local() {
        let record = SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            timer: None,
            inode: 77,
        };
        let pass = native_pass_from_records(
            &[record],
            OwnerScanResult {
                owners: HashMap::new(),
                losses: [OwnerScanLoss::PermissionDenied(42)].into_iter().collect(),
                omitted_loss_count: 0,
                owner_edges: 0,
            },
        )
        .expect("denied scan is retained as partial evidence");

        assert_eq!(
            pass.owners.global_completeness,
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap()
        );
        assert_eq!(pass.owners.evidence_gaps[0].endpoint, None);
        assert_eq!(pass.owners.evidence_gaps[0].pid, Some(42));
        assert_eq!(
            pass.owners.local_completeness,
            [OwnerCompleteness::Complete]
        );
    }

    #[test]
    fn global_scan_denial_does_not_reduce_verified_endpoint_completeness() {
        let record = SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            timer: None,
            inode: 77,
        };
        let pass = native_pass_from_records(
            &[record],
            OwnerScanResult {
                owners: HashMap::from([(77, vec![1234])]),
                losses: [OwnerScanLoss::PermissionDenied(42)].into_iter().collect(),
                omitted_loss_count: 0,
                owner_edges: 1,
            },
        )
        .expect("proven ownership remains usable");

        assert!(!pass.owners.global_completeness.is_complete());
        assert_eq!(
            pass.owners.local_completeness,
            [OwnerCompleteness::Complete]
        );
    }

    #[test]
    fn owner_scan_losses_are_bounded_at_the_source() {
        let mut scan = OwnerScanResult::default();
        for pid in 1..=u32::try_from(crate::observation::EVIDENCE_GAPS_MAX).unwrap() {
            scan.record_loss(OwnerScanLoss::Disappeared(pid));
        }
        assert_eq!(scan.losses.len(), crate::observation::EVIDENCE_GAPS_MAX);
        assert_eq!(scan.omitted_loss_count, 0);

        scan.record_loss(OwnerScanLoss::Disappeared(u32::MAX));
        assert_eq!(scan.losses.len(), crate::observation::EVIDENCE_GAPS_MAX);
        assert_eq!(scan.omitted_loss_count, 1);

        let pass = native_pass_from_records(&[], scan).expect("bounded losses remain observable");
        assert_eq!(
            pass.owners.evidence_gaps.len(),
            crate::observation::EVIDENCE_GAPS_MAX
        );
        assert_eq!(pass.owners.omitted_evidence_gap_count, 1);
    }

    #[test]
    fn vanished_pid_identity_is_reported_after_an_owner_edge_is_known() {
        let proc_root = temp_proc_root("vanished-native-identity");
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        assert_eq!(
            collector
                .read_native_process(
                    42,
                    crate::observation::MetadataProfile::Display,
                    crate::observation::OPTIONAL_METADATA_MAX_BYTES,
                )
                .expect("a vanished stat is ordinary unavailable identity"),
            crate::observation::ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared)
        );
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn malformed_identity_stat_fails_the_collection_attempt() {
        let proc_root = temp_proc_root("malformed-native-identity");
        write_process(&proc_root, 42, "worker", 1);
        fs::write(proc_root.join("42/stat"), "malformed stat\n")
            .expect("malformed stat fixture must be written");
        let collector = LinuxCollector::with_proc_root(proc_root.clone());

        let error = collector
            .read_native_process(
                42,
                crate::observation::MetadataProfile::Display,
                crate::observation::OPTIONAL_METADATA_MAX_BYTES,
            )
            .expect_err("malformed identity-critical stat must fail");

        assert!(error.to_string().contains("42/stat"), "{error}");
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
        assert_eq!(
            context.process_start_time_marker,
            crate::observation::ProcessStartMarker::linux(1000).ok()
        );
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
    fn process_context_and_child_collection_bound_optional_process_names() {
        let proc_root = temp_proc_root("context-child-name-boundary");
        write_process(&proc_root, 100, "parent", 1);
        write_process(&proc_root, 101, "worker", 100);
        let comm = proc_root.join("101/comm");

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max child name");
        let exact = collect_process_context_from(&proc_root, 100);
        assert_eq!(exact.children.children.len(), 1);
        assert_eq!(
            exact.children.children[0]
                .process_name
                .as_deref()
                .map(str::len),
            Some(PROCESS_NAME_MAX_BYTES)
        );
        let exact_children = collect_child_processes_from(&proc_root, 100);
        assert_eq!(
            exact_children.children[0]
                .process_name
                .as_deref()
                .map(str::len),
            Some(PROCESS_NAME_MAX_BYTES)
        );

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized child name");
        let oversized = collect_process_context_from(&proc_root, 100);
        assert_eq!(oversized.children.children.len(), 1);
        assert_eq!(oversized.children.children[0].pid, 101);
        assert_eq!(oversized.children.children[0].process_name, None);
        let oversized_children = collect_child_processes_from(&proc_root, 100);
        assert_eq!(oversized_children.children.len(), 1);
        assert_eq!(oversized_children.children[0].pid, 101);
        assert_eq!(oversized_children.children[0].process_name, None);

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
        assert!(tuples.contains(&(
            100,
            Some(1),
            Some("root"),
            crate::observation::ProcessStartMarker::linux(1000).ok()
        )));
        assert!(tuples.contains(&(
            101,
            Some(100),
            Some("child"),
            crate::observation::ProcessStartMarker::linux(1010).ok()
        )));
        assert!(tuples.contains(&(
            102,
            Some(101),
            Some("grandchild"),
            crate::observation::ProcessStartMarker::linux(1020).ok()
        )));
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn tree_snapshot_accepts_exact_max_name_and_rejects_max_plus_one() {
        let proc_root = temp_proc_root("tree-name-boundary");
        write_process(&proc_root, 100, "worker", 1);
        let comm = proc_root.join("100/comm");

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max tree name");
        let exact =
            collect_tree_process_infos(&proc_root).expect("exact-max tree name must collect");
        assert_eq!(exact.len(), 1);
        assert_eq!(
            exact[0].process_name.as_deref().map(str::len),
            Some(PROCESS_NAME_MAX_BYTES)
        );

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized tree name");
        let error = collect_tree_process_infos(&proc_root)
            .expect_err("oversized live tree name must fail closed");
        assert!(error.to_string().contains("100/comm"), "{error}");
        assert!(
            error
                .to_string()
                .contains(&format!("exceeds {PROCESS_NAME_MAX_BYTES} byte read limit")),
            "{error}"
        );

        fs::remove_file(&comm).expect("vanished tree name");
        assert!(
            collect_tree_process_infos(&proc_root)
                .expect("a process vanishing during its name read must still be skipped")
                .is_empty()
        );

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
    fn related_hint_retains_exact_max_name_and_omits_max_plus_one() {
        let proc_root = temp_proc_root("hint-name-boundary");
        write_process(&proc_root, 100, "candidate", 1);
        fs::write(
            proc_root.join("100/cmdline"),
            b"python3\0-m\0http.server\0--port\x003000\0",
        )
        .expect("candidate cmdline must be written");
        let comm = proc_root.join("100/comm");

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES]).expect("exact-max hint name");
        let exact = collect_related_process_hints_from(&proc_root, 3000);
        assert_eq!(exact.len(), 1);
        assert_eq!(
            exact[0].process_name.as_deref().map(str::len),
            Some(PROCESS_NAME_MAX_BYTES)
        );

        fs::write(&comm, vec![b'x'; PROCESS_NAME_MAX_BYTES + 1]).expect("oversized hint name");
        let oversized = collect_related_process_hints_from(&proc_root, 3000);
        assert_eq!(oversized.len(), 1);
        assert_eq!(oversized[0].pid, 100);
        assert_eq!(oversized[0].process_name, None);

        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn missing_proc_root_is_a_collection_error() {
        let collector = LinuxCollector::with_proc_root(PathBuf::from(
            "/definitely-not-a-real-kickoutchi-proc-root",
        ));

        let error = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect_err("missing proc root must fail");
        assert!(error.to_string().contains("cannot read"), "{error}");
    }

    #[test]
    fn socket_owner_collection_requires_a_readable_proc_root() {
        let target_inodes = HashSet::from([1]);
        let error = collect_socket_owners(
            Path::new("/definitely-not-a-real-kickoutchi-proc-root"),
            &target_inodes,
            CANDIDATE_PROCESS_IDS_MAX,
            FILE_DESCRIPTOR_ENTRIES_MAX,
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

        let owners = collect_socket_owners(
            &proc_root,
            &HashSet::from([22]),
            CANDIDATE_PROCESS_IDS_MAX,
            FILE_DESCRIPTOR_ENTRIES_MAX,
        )
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

        let owners = collect_socket_owners(
            &proc_root,
            &HashSet::from([44]),
            CANDIDATE_PROCESS_IDS_MAX,
            FILE_DESCRIPTOR_ENTRIES_MAX,
        )
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
        let mut visited = 0;
        collect_pid_socket_owners(
            &proc_root,
            1234,
            &target_inodes,
            &mut owners,
            &mut visited,
            2,
        )
        .expect("fd traversal at the cap must succeed");

        assert_eq!(owners.get(&44).map(Vec::as_slice), Some(&[1234][..]));
        assert_eq!(visited, 2);
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn pid_socket_owner_collection_fails_closed_past_fd_budget() {
        let proc_root = temp_proc_root("fd-budget");
        let fd_dir = proc_root.join("1234").join("fd");
        fs::create_dir_all(&fd_dir).expect("test fd directory must be created");
        for fd in 0..3 {
            std::os::unix::fs::symlink("socket:[44]", fd_dir.join(fd.to_string()))
                .expect("test socket symlink must be created");
        }
        let mut owners = HashMap::new();
        let mut visited = 0;

        let error = collect_pid_socket_owners(
            &proc_root,
            1234,
            &HashSet::from([44]),
            &mut owners,
            &mut visited,
            2,
        )
        .expect_err("fd traversal past the cap must fail closed");

        assert_eq!(visited, 2);
        assert!(
            error.to_string().contains("file-descriptor traversal"),
            "{error}"
        );
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn collector_enforces_fd_budget_through_production_orchestration() {
        let proc_root = temp_proc_root("collector-fd-budget");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        write_process(&proc_root, 100, "worker", 1);
        for fd in 0..3 {
            std::os::unix::fs::symlink(
                "socket:[44]",
                proc_root.join("100/fd").join(fd.to_string()),
            )
            .expect("test socket symlink must be created");
        }
        let collector = LinuxCollector::with_proc_root_and_limits(
            proc_root.clone(),
            CollectionLimits {
                fd_entries: 2,
                ..CollectionLimits::PRODUCTION
            },
        );

        let error = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect_err("collector must enforce fd cap");

        assert!(
            error.to_string().contains("file-descriptor traversal"),
            "{error}"
        );
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn collector_enforces_row_budget_through_production_orchestration() {
        let proc_root = temp_proc_root("collector-row-budget");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        for pid in [100, 101, 102] {
            write_process(&proc_root, pid, "worker", 1);
            std::os::unix::fs::symlink("socket:[44]", proc_root.join(pid.to_string()).join("fd/0"))
                .expect("test socket symlink must be created");
        }
        let collector = LinuxCollector::with_proc_root_and_limits(
            proc_root.clone(),
            CollectionLimits {
                port_entries: 2,
                ..CollectionLimits::PRODUCTION
            },
        );

        let error = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect_err("collector must enforce row cap");

        assert!(error.to_string().contains("port rows exceed"), "{error}");
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn collector_enforces_pid_budget_through_production_orchestration() {
        let proc_root = temp_proc_root("collector-pid-budget");
        write_socket_table(&proc_root, "net/tcp", &[row("0100007F:0BB8", "0A", 44)]);
        write_socket_table(&proc_root, "net/udp", &[]);
        for pid in [100, 101, 102] {
            write_process(&proc_root, pid, "worker", 1);
        }
        let collector = LinuxCollector::with_proc_root_and_limits(
            proc_root.clone(),
            CollectionLimits {
                process_ids: 2,
                ..CollectionLimits::PRODUCTION
            },
        );

        let error = <LinuxCollector as crate::collector::Collector>::collect(
            &collector,
            crate::observation::MetadataProfile::LegacyList,
        )
        .expect_err("collector must enforce PID cap");

        assert!(
            error.to_string().contains("process list exceeds"),
            "{error}"
        );
        fs::remove_dir_all(proc_root).expect("test proc root must clean up");
    }

    #[test]
    fn production_collection_limits_match_the_documented_policy() {
        assert_eq!(
            CollectionLimits::PRODUCTION.process_ids,
            CANDIDATE_PROCESS_IDS_MAX
        );
        assert_eq!(
            CollectionLimits::PRODUCTION.fd_entries,
            FILE_DESCRIPTOR_ENTRIES_MAX
        );
        assert_eq!(
            CollectionLimits::PRODUCTION.port_entries,
            DERIVED_PORT_ENTRIES_MAX
        );
    }
}
