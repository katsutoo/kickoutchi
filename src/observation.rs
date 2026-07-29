//! Platform-neutral, bounded network observation domain.
//!
//! This module owns consistency and retention policy so every native adapter
//! has one contract to satisfy.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use thiserror::Error;

pub(crate) use crate::model::Protocol;
use crate::model::{
    PermissionStatus, Platform, PortEntry, PortEntryView, SocketState as LegacySocketState,
};

// Every collection, retention, and serialization bound lives here with the
// reasoning that chose it. Native adapters import the constant and nothing
// else: rationale that stays behind in an adapter drifts onto whichever
// constant happens to be adjacent, and a "fails closed" claim parked above a
// fail-open reader is worse than no comment at all.
//
// Each bound also states its over-limit behavior, because the two are not
// interchangeable:
//   * fails closed — the read or scan returns an operational error, because a
//     truncated result would be a *wrong* answer (a dropped socket row, a
//     prefix of an identity marker) rather than an incomplete one.
//   * degrades — the value is dropped and the record is marked partial with an
//     evidence gap, because the fact is optional enrichment and its absence is
//     honestly representable.

/// Bytes read from one native socket table (`/proc/net/*`, IP Helper).
///
/// Generous at ~100k sockets. Fails closed: a socket table is the one native
/// source that must never truncate, because dropping bytes drops whole socket
/// rows — real open ports — and a short table reads as a complete one.
#[allow(
    dead_code,
    reason = "unused on macOS, whose process-first collection has no socket table"
)]
pub(crate) const NATIVE_SOCKET_TABLE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// Socket observations retained in one snapshot. Fails closed.
pub(crate) const SOCKET_OBSERVATIONS_MAX: usize = 262_144;

/// Distinct PIDs considered as candidate socket owners in one pass.
///
/// The kernel's own `pid_max` (4 M) already bounds a `/proc` scan, but the
/// bound is stated explicitly so Linux and macOS share one number. Fails
/// closed: silently dropping PIDs can drop a real port owner.
pub(crate) const CANDIDATE_PROCESS_IDS_MAX: usize = 131_072;

/// Aggregate file-descriptor entries traversed per collection scope.
///
/// One million covers ordinary high-density hosts while bounding the
/// multiplicative `PIDs x descriptors` walk. Fails closed: a partial owner map
/// is misleading, not merely incomplete.
#[allow(
    dead_code,
    reason = "unused on Windows, which reads owner PIDs from the IP Helper table"
)]
pub(crate) const FILE_DESCRIPTOR_ENTRIES_MAX: usize = 1_048_576;

/// Socket-to-owner edges retained per association pass.
///
/// Above the socket-table size on purpose, so substantial shared-socket fanout
/// (fork-inherited listeners, `SO_REUSEPORT`) is representable. Fails closed.
pub(crate) const OWNER_EDGES_MAX: usize = 262_144;

/// Process identity reads per consistency attempt, and across both attempts.
///
/// The pair exists so one pathological attempt cannot spend the whole budget
/// and starve the retry. Both fail closed.
const PROCESS_IDENTITY_READS_PER_ATTEMPT_MAX: usize = 262_144;
const PROCESS_IDENTITY_READS_TOTAL_MAX: usize = 524_288;

/// Rows the legacy `PortEntry` projection may emit. Fails closed.
const DERIVED_PORT_ENTRIES_MAX: usize = 262_144;

/// Owners serialized per owner set; the remainder becomes
/// `omitted_owner_count`. Degrades, because the count keeps the omission
/// truthful.
pub(crate) const SERIALIZED_OWNERS_MAX: usize = 64;

/// Distinct reasons an owner set may carry. Fails closed: a ninth reason means
/// the caller is constructing completeness from something other than the fixed
/// evidence vocabulary.
pub(crate) const OWNER_COMPLETENESS_REASONS_MAX: usize = 8;

/// Process and parent-process name bytes. Degrades to `null` plus a metadata
/// gap. Also the width of the CLI table's padding buffer (see `output.rs`).
pub(crate) const PROCESS_NAME_MAX_BYTES: usize = 4 * 1024;

/// Executable path bytes. Degrades to `null` plus a metadata gap.
pub(crate) const EXECUTABLE_PATH_MAX_BYTES: usize = 128 * 1024;

/// Command-line bytes in the legacy list profile.
///
/// Degrades to `null` plus a metadata gap — never to a prefix, because half a
/// command line invites a wrong reading of what a process is doing.
pub(crate) const PROCESS_COMMAND_LINE_MAX_BYTES: usize = 1024 * 1024;

/// Aggregate optional metadata retained across one snapshot. Degrades: later
/// values are omitted before allocation while identities and sockets survive.
pub(crate) const OPTIONAL_METADATA_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Bytes of one fresh process name read at a termination gate. Fails closed:
/// protection policy is decided from this name, so a truncated one could clear
/// a gate the full name would have failed.
pub(crate) const PROTECTION_NAME_MAX_BYTES: usize = 4 * 1024;

/// Members and aggregate name bytes in one bounded protection-evidence scope.
/// Both fail closed for the same reason as the name bound above.
pub(crate) const PROTECTION_SCOPE_MAX_MEMBERS: usize = 512;
pub(crate) const PROTECTION_SCOPE_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Collection attempts before an unstable observation is reported as raced.
///
/// Two, not "until stable": a host whose socket table never settles must
/// surface that fact, not spin until it happens to agree with itself.
const CONSISTENCY_ATTEMPTS_MAX: usize = 2;

/// Retries when a native API reports that its output buffer grew between the
/// size query and the read. Fails closed after the third attempt.
#[allow(
    dead_code,
    reason = "unused on Linux, whose procfs reads size themselves"
)]
pub(crate) const NATIVE_RESIZE_ATTEMPTS_MAX: usize = 3;

/// Evidence gaps retained per snapshot; the remainder becomes
/// `omitted_evidence_gap_count`. Degrades, but omission forces the snapshot to
/// partial so the loss can never be mistaken for completeness.
pub(crate) const EVIDENCE_GAPS_MAX: usize = 4_096;

/// Bytes of one evidence or gap message. Truncated on a char boundary: these
/// are explanatory prose, not facts a consumer parses.
pub(crate) const EVIDENCE_MESSAGE_MAX_BYTES: usize = 512;

/// Bytes of an observation-scope identifier. Degrades to `null` plus a scope
/// gap rather than retaining a prefix that could read as a different namespace.
pub(crate) const SCOPE_IDENTIFIER_MAX_BYTES: usize = 256;

/// Distinct scope limitations. Fails closed, like the owner-reason bound.
pub(crate) const SCOPE_LIMITATIONS_MAX: usize = 8;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ObservationLimits {
    sockets: usize,
    candidate_pids: usize,
    owner_edges: usize,
    identity_reads_per_attempt: usize,
    identity_reads_total: usize,
    evidence_gaps: usize,
    optional_metadata_bytes: usize,
}

impl ObservationLimits {
    const PRODUCTION: Self = Self {
        sockets: SOCKET_OBSERVATIONS_MAX,
        candidate_pids: CANDIDATE_PROCESS_IDS_MAX,
        owner_edges: OWNER_EDGES_MAX,
        identity_reads_per_attempt: PROCESS_IDENTITY_READS_PER_ATTEMPT_MAX,
        identity_reads_total: PROCESS_IDENTITY_READS_TOTAL_MAX,
        evidence_gaps: EVIDENCE_GAPS_MAX,
        optional_metadata_bytes: OPTIONAL_METADATA_MAX_BYTES,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "scope variants are host-specific")]
pub(crate) enum Ipv6Scope {
    Unscoped,
    InterfaceIndex(NonZeroU32),
    Unavailable,
}

#[allow(dead_code, reason = "scope constructor is used by non-Linux adapters")]
impl Ipv6Scope {
    pub(crate) fn interface_index(value: u64) -> Result<Self, EndpointIdentityError> {
        u32::try_from(value)
            .ok()
            .and_then(NonZeroU32::new)
            .map(Self::InterfaceIndex)
            .ok_or(EndpointIdentityError::InvalidInterfaceIndex)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[allow(dead_code, reason = "validation variants are host-specific")]
pub(crate) enum EndpointIdentityError {
    #[error("endpoint port must be in 1..=65535")]
    InvalidPort,
    #[error("IPv4 endpoints cannot carry an IPv6 scope")]
    Ipv4WithScope,
    #[error("IPv6 endpoints require an explicit scope state")]
    Ipv6WithoutScope,
    #[error("IPv6 interface index must be in 1..=4294967295")]
    InvalidInterfaceIndex,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct EndpointIdentity {
    pub(crate) protocol: Protocol,
    pub(crate) address: IpAddr,
    pub(crate) port: NonZeroU16,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
}

impl EndpointIdentity {
    pub(crate) fn new(
        protocol: Protocol,
        address: IpAddr,
        port: u32,
        ipv6_scope: Option<Ipv6Scope>,
    ) -> Result<Self, EndpointIdentityError> {
        let was_ipv4_mapped =
            matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some());
        let address = match address {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address @ IpAddr::V4(_) => address,
        };
        let port = u16::try_from(port)
            .ok()
            .and_then(NonZeroU16::new)
            .ok_or(EndpointIdentityError::InvalidPort)?;
        let ipv6_scope = match (address, ipv6_scope) {
            (IpAddr::V4(_), None) => None,
            (IpAddr::V4(_), Some(_)) if was_ipv4_mapped => None,
            (IpAddr::V4(_), Some(_)) => return Err(EndpointIdentityError::Ipv4WithScope),
            (IpAddr::V6(_), None) => return Err(EndpointIdentityError::Ipv6WithoutScope),
            (IpAddr::V6(_), Some(scope)) => Some(scope),
        };
        Ok(Self {
            protocol,
            address,
            port,
            ipv6_scope,
        })
    }
}

pub(crate) fn compare_endpoint_identity(
    left: &EndpointIdentity,
    right: &EndpointIdentity,
) -> Ordering {
    left.protocol
        .cmp(&right.protocol)
        .then_with(|| match (left.address, right.address) {
            (IpAddr::V4(left), IpAddr::V4(right)) => left.octets().cmp(&right.octets()),
            (IpAddr::V4(_), IpAddr::V6(_)) => Ordering::Less,
            (IpAddr::V6(_), IpAddr::V4(_)) => Ordering::Greater,
            (IpAddr::V6(left), IpAddr::V6(right)) => left.octets().cmp(&right.octets()),
        })
        .then_with(|| left.ipv6_scope.cmp(&right.ipv6_scope))
        .then_with(|| left.port.cmp(&right.port))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MacOsProcessStartTime {
    seconds: u64,
    microseconds: u32,
}

#[allow(dead_code, reason = "constructed only on macOS")]
impl MacOsProcessStartTime {
    pub(crate) fn new(seconds: u64, microseconds: u32) -> Result<Self, ProcessMarkerError> {
        if microseconds > 999_999 {
            return Err(ProcessMarkerError::InvalidMicroseconds);
        }
        if seconds == 0 && microseconds == 0 {
            return Err(ProcessMarkerError::Zero);
        }
        Ok(Self {
            seconds,
            microseconds,
        })
    }

    pub(crate) const fn seconds(self) -> u64 {
        self.seconds
    }

    pub(crate) const fn microseconds(self) -> u32 {
        self.microseconds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[allow(dead_code, reason = "marker errors are host-specific")]
pub(crate) enum ProcessMarkerError {
    #[error("a process start marker cannot be zero")]
    Zero,
    #[error("macOS process-start microseconds must be in 0..=999999")]
    InvalidMicroseconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "marker variants are host-specific")]
pub(crate) enum ProcessStartMarker {
    LinuxStartTicks(NonZeroU64),
    MacOsStartTime(MacOsProcessStartTime),
    WindowsCreationTime(NonZeroU64),
}

#[allow(dead_code, reason = "marker constructors are host-specific")]
impl ProcessStartMarker {
    pub(crate) fn linux(ticks: u64) -> Result<Self, ProcessMarkerError> {
        NonZeroU64::new(ticks)
            .map(Self::LinuxStartTicks)
            .ok_or(ProcessMarkerError::Zero)
    }

    pub(crate) fn macos(seconds: u64, microseconds: u32) -> Result<Self, ProcessMarkerError> {
        MacOsProcessStartTime::new(seconds, microseconds).map(Self::MacOsStartTime)
    }

    pub(crate) fn windows(filetime_ticks: u64) -> Result<Self, ProcessMarkerError> {
        NonZeroU64::new(filetime_ticks)
            .map(Self::WindowsCreationTime)
            .ok_or(ProcessMarkerError::Zero)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    pub(crate) start_marker: ProcessStartMarker,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "socket tokens are host-specific")]
pub(crate) enum PlatformSocketToken {
    LinuxInode(NonZeroU64),
    MacOsSocketId(NonZeroU64),
}

#[allow(dead_code, reason = "socket token constructors are host-specific")]
impl PlatformSocketToken {
    pub(crate) fn linux_inode(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self::LinuxInode)
    }

    pub(crate) fn macos_socket_id(value: u64) -> Option<Self> {
        NonZeroU64::new(value).map(Self::MacOsSocketId)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code, reason = "some native states are host-specific")]
pub(crate) enum SocketState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    NewSynReceived,
    Bound,
    Unknown(u32),
}

impl SocketState {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Listen => "listen",
            Self::SynSent => "syn_sent",
            Self::SynReceived => "syn_received",
            Self::Established => "established",
            Self::FinWait1 => "fin_wait1",
            Self::FinWait2 => "fin_wait2",
            Self::CloseWait => "close_wait",
            Self::Closing => "closing",
            Self::LastAck => "last_ack",
            Self::TimeWait => "time_wait",
            Self::DeleteTcb => "delete_tcb",
            Self::NewSynReceived => "new_syn_received",
            Self::Bound => "bound",
            Self::Unknown(_) => "unknown",
        }
    }

    pub(crate) const fn order_key(self) -> (u8, u32) {
        match self {
            Self::Closed => (0, 0),
            Self::Listen => (1, 0),
            Self::SynSent => (2, 0),
            Self::SynReceived => (3, 0),
            Self::Established => (4, 0),
            Self::FinWait1 => (5, 0),
            Self::FinWait2 => (6, 0),
            Self::CloseWait => (7, 0),
            Self::Closing => (8, 0),
            Self::LastAck => (9, 0),
            Self::TimeWait => (10, 0),
            Self::DeleteTcb => (11, 0),
            Self::NewSynReceived => (12, 0),
            Self::Bound => (13, 0),
            Self::Unknown(code) => (14, code),
        }
    }
}

impl Ord for SocketState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.order_key().cmp(&other.order_key())
    }
}

impl PartialOrd for SocketState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "TCP timer kinds are Linux-specific")]
pub(crate) enum TcpTimerKind {
    None,
    Retransmit,
    Other,
    TimeWait,
    ZeroWindowProbe,
    Unknown(u32),
}

#[allow(dead_code, reason = "native timer mapping is Linux-specific")]
impl TcpTimerKind {
    pub(crate) const fn from_linux_native(native_code: u32) -> Self {
        match native_code {
            0 => Self::None,
            1 => Self::Retransmit,
            2 => Self::Other,
            3 => Self::TimeWait,
            4 => Self::ZeroWindowProbe,
            code => Self::Unknown(code),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TcpTimerObservation {
    pub(crate) kind: TcpTimerKind,
    pub(crate) native_code: Option<u32>,
    pub(crate) raw_ticks: u64,
    pub(crate) estimated_remaining_milliseconds: Option<u64>,
}

#[allow(dead_code, reason = "native timer fields are Linux-specific")]
impl TcpTimerObservation {
    pub(crate) fn from_linux_native(
        native_code: u32,
        raw_ticks: u64,
        clock_ticks_per_second: Option<u64>,
    ) -> Self {
        let estimated_remaining_milliseconds = clock_ticks_per_second
            .filter(|ticks| *ticks != 0)
            .and_then(|ticks| {
                let numerator = u128::from(raw_ticks)
                    .checked_mul(1_000)?
                    .checked_add(u128::from(ticks) - 1)?;
                u64::try_from(numerator / u128::from(ticks)).ok()
            });
        let kind = TcpTimerKind::from_linux_native(native_code);
        Self {
            native_code: matches!(kind, TcpTimerKind::Unknown(_)).then_some(native_code),
            kind,
            raw_ticks,
            estimated_remaining_milliseconds,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "not every evidence code is emitted on every host")]
pub(crate) enum EvidenceGapCode {
    OwnerPermissionDenied,
    OwnerAttributionIncomplete,
    OwnerDisappeared,
    ProcessIdentityUnavailable,
    ProcessMetadataUnavailable,
    NativeFieldUnavailable,
    ScopeExcluded,
    NoncriticalEvidenceTruncated,
    ObservationRaced,
}

impl EvidenceGapCode {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::OwnerPermissionDenied => "owner_permission_denied",
            Self::OwnerAttributionIncomplete => "owner_attribution_incomplete",
            Self::OwnerDisappeared => "owner_disappeared",
            Self::ProcessIdentityUnavailable => "process_identity_unavailable",
            Self::ProcessMetadataUnavailable => "process_metadata_unavailable",
            Self::NativeFieldUnavailable => "native_field_unavailable",
            Self::ScopeExcluded => "scope_excluded",
            Self::NoncriticalEvidenceTruncated => "noncritical_evidence_truncated",
            Self::ObservationRaced => "observation_raced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum EvidenceImpact {
    SocketSet,
    Ownership,
    Metadata,
    #[allow(
        dead_code,
        reason = "scope gaps are emitted by target-specific adapters"
    )]
    Scope,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct EvidenceGap {
    pub(crate) impact: EvidenceImpact,
    pub(crate) code: EvidenceGapCode,
    pub(crate) endpoint: Option<EndpointIdentity>,
    pub(crate) pid: Option<u32>,
    affected_pid_count: Option<NonZeroU64>,
    message: String,
}

impl Ord for EvidenceGap {
    fn cmp(&self, other: &Self) -> Ordering {
        self.impact
            .cmp(&other.impact)
            .then_with(|| self.code.name().cmp(other.code.name()))
            .then_with(|| match (&self.endpoint, &other.endpoint) {
                (Some(left), Some(right)) => compare_endpoint_identity(left, right),
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            })
            .then_with(|| self.pid.cmp(&other.pid))
            .then_with(|| self.affected_pid_count.cmp(&other.affected_pid_count))
            .then_with(|| self.message.cmp(&other.message))
    }
}

impl PartialOrd for EvidenceGap {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl EvidenceGap {
    pub(crate) fn new(
        impact: EvidenceImpact,
        code: EvidenceGapCode,
        endpoint: Option<EndpointIdentity>,
        pid: Option<u32>,
        message: &str,
    ) -> Self {
        Self {
            impact,
            code,
            endpoint,
            pid,
            affected_pid_count: None,
            message: truncate_utf8(message, EVIDENCE_MESSAGE_MAX_BYTES).to_owned(),
        }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn aggregate_for_pids(
        impact: EvidenceImpact,
        code: EvidenceGapCode,
        endpoint: Option<EndpointIdentity>,
        affected_pid_count: NonZeroU64,
        message: &str,
    ) -> Self {
        Self {
            impact,
            code,
            endpoint,
            pid: None,
            affected_pid_count: Some(affected_pid_count),
            message: truncate_utf8(message, EVIDENCE_MESSAGE_MAX_BYTES).to_owned(),
        }
    }

    pub(crate) const fn affected_pid_count(&self) -> Option<u64> {
        match self.affected_pid_count {
            Some(count) => Some(count.get()),
            None => None,
        }
    }

    fn same_aggregate_observation(&self, other: &Self) -> bool {
        self.affected_pid_count.is_some()
            && other.affected_pid_count.is_some()
            && self.impact == other.impact
            && self.code == other.code
            && self.endpoint == other.endpoint
            && self.pid == other.pid
            && self.message == other.message
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OwnerCompleteness {
    Complete,
    Partial { reasons: Vec<EvidenceGapCode> },
    Raced,
}

impl OwnerCompleteness {
    pub(crate) fn partial(
        reasons: impl IntoIterator<Item = EvidenceGapCode>,
    ) -> Result<Self, ObservationError> {
        let reasons: BTreeSet<_> = reasons.into_iter().collect();
        if reasons.len() > OWNER_COMPLETENESS_REASONS_MAX {
            return Err(ObservationError::OwnerReasonLimitExceeded);
        }
        if reasons.is_empty() {
            return Ok(Self::Complete);
        }
        let mut reasons = reasons.into_iter().collect::<Vec<_>>();
        reasons.sort_unstable_by_key(|reason| reason.name());
        Ok(Self::Partial { reasons })
    }

    pub(crate) fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

pub(crate) fn owner_reason_names(
    reasons: &[EvidenceGapCode],
) -> impl ExactSizeIterator<Item = &'static str> + '_ {
    reasons.iter().map(|reason| reason.name())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[allow(dead_code, reason = "unverified reasons depend on the native platform")]
pub(crate) enum UnverifiedOwnerReason {
    PermissionDenied,
    Disappeared,
    IdentityUnavailable,
    Raced,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum OwnerObservation {
    Verified(ProcessIdentity),
    UnverifiedPid {
        pid: u32,
        reason: UnverifiedOwnerReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketObservation {
    pub(crate) local_endpoint: EndpointIdentity,
    pub(crate) state: SocketState,
    pub(crate) timer: Option<TcpTimerObservation>,
    pub(crate) owners: Vec<OwnerObservation>,
    pub(crate) owner_completeness: OwnerCompleteness,
    pub(crate) socket_token: Option<PlatformSocketToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SnapshotCompleteness {
    Complete,
    Partial,
    Raced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(dead_code, reason = "limitations are host and capability specific")]
pub(crate) enum ScopeLimitation {
    OtherNetworkNamespacesExcluded,
    ProcessFirstSocketVisibilityLimited,
    WslNetworkStackExcluded,
    ProcessMetadataPermissionLimited,
    Ipv6ScopeUnavailable,
    ScopedIpv6ExactMatchingUnavailable,
    NativeFieldUnavailable,
    PollingIntervalBlindSpot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "the Current* names are frozen observation-scope contract values"
)]
#[allow(dead_code, reason = "scope kinds are host-specific")]
pub(crate) enum ObservationScopeKind {
    CurrentNetworkNamespace,
    CurrentHostProcessVisibleSockets,
    CurrentHostNetworkStack,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObservationScope {
    pub(crate) kind: ObservationScopeKind,
    pub(crate) identifier: Option<String>,
    pub(crate) limitations: Vec<ScopeLimitation>,
}

impl ObservationScope {
    pub(crate) fn new(
        kind: ObservationScopeKind,
        identifier: Option<&str>,
        limitations: impl IntoIterator<Item = ScopeLimitation>,
    ) -> Result<Self, ObservationError> {
        let limitations = bounded_scope_limitations(limitations)?;
        let identifier = match identifier {
            Some(value) if value.len() > SCOPE_IDENTIFIER_MAX_BYTES => {
                return Err(ObservationError::ScopeIdentifierOversized);
            }
            Some(value) => Some(value.to_owned()),
            None => None,
        };
        Ok(Self {
            kind,
            identifier,
            limitations,
        })
    }
}

fn bounded_scope_limitations<T: Ord>(
    limitations: impl IntoIterator<Item = T>,
) -> Result<Vec<T>, ObservationError> {
    let limitations: BTreeSet<_> = limitations.into_iter().collect();
    if limitations.len() > SCOPE_LIMITATIONS_MAX {
        return Err(ObservationError::ScopeLimitationLimitExceeded);
    }
    Ok(limitations.into_iter().collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataProfile {
    IdentityOnly,
    Display,
    LegacyList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataCompleteness {
    Complete,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MetadataOmission {
    BudgetExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessObservation {
    pub(crate) name: Option<Arc<str>>,
    pub(crate) executable_path: Option<Arc<Path>>,
    pub(crate) command_line: Option<Arc<str>>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<Arc<str>>,
    pub(crate) metadata_omission: Option<MetadataOmission>,
    pub(crate) metadata_completeness: MetadataCompleteness,
}

impl ProcessObservation {
    pub(crate) const fn identity_only() -> Self {
        Self {
            name: None,
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            metadata_omission: None,
            metadata_completeness: MetadataCompleteness::Complete,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NetworkSnapshot {
    pub(crate) capture_started_at: SystemTime,
    pub(crate) capture_completed_at: SystemTime,
    pub(crate) scope: ObservationScope,
    pub(crate) completeness: SnapshotCompleteness,
    pub(crate) owner_completeness: OwnerCompleteness,
    pub(crate) evidence_gaps: Vec<EvidenceGap>,
    pub(crate) omitted_evidence_gap_count: u64,
    pub(crate) sockets: Vec<SocketObservation>,
    pub(crate) processes: HashMap<ProcessIdentity, ProcessObservation>,
}

#[cfg(test)]
pub(crate) fn snapshot_from_test_rows(rows: Vec<PortEntry>) -> NetworkSnapshot {
    let platform = rows.first().map_or(Platform::Linux, |row| row.platform);
    let scope_kind = match platform {
        Platform::Linux => ObservationScopeKind::CurrentNetworkNamespace,
        Platform::Macos => ObservationScopeKind::CurrentHostProcessVisibleSockets,
        Platform::Windows => ObservationScopeKind::CurrentHostNetworkStack,
    };
    let mut processes = HashMap::new();
    let mut sockets = Vec::with_capacity(rows.len());
    let mut ownership_partial = false;
    for row in rows {
        let ipv6_scope = row
            .local_addr
            .is_ipv6()
            .then_some(row.ipv6_scope.unwrap_or(Ipv6Scope::Unavailable));
        let endpoint = EndpointIdentity::new(
            row.protocol,
            row.local_addr,
            u32::from(row.local_port),
            ipv6_scope,
        )
        .expect("test rows use valid endpoints");
        let owners = row.pid.map_or_else(Vec::new, |pid| {
            let identity = row.process_identity.unwrap_or(ProcessIdentity {
                pid,
                start_marker: ProcessStartMarker::linux(u64::from(pid) + 1)
                    .expect("test PID produces a nonzero marker"),
            });
            processes.entry(identity).or_insert(ProcessObservation {
                name: row.process_name,
                executable_path: row.executable_path,
                command_line: row.command_line,
                parent_pid: row.parent_pid,
                parent_process_name: row.parent_process_name,
                metadata_omission: None,
                metadata_completeness: if row.permission == PermissionStatus::Full {
                    MetadataCompleteness::Complete
                } else {
                    MetadataCompleteness::Partial
                },
            });
            vec![OwnerObservation::Verified(identity)]
        });
        ownership_partial |= owners.is_empty();
        sockets.push(SocketObservation {
            local_endpoint: endpoint,
            state: match row.state {
                LegacySocketState::Listen => SocketState::Listen,
                LegacySocketState::Bound => SocketState::Bound,
            },
            timer: None,
            owner_completeness: if owners.is_empty() {
                OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                    .expect("one reason fits")
            } else {
                OwnerCompleteness::Complete
            },
            owners,
            socket_token: None,
        });
    }
    NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH,
        scope: ObservationScope::new(scope_kind, Some("test"), []).expect("test scope is valid"),
        completeness: if ownership_partial {
            SnapshotCompleteness::Partial
        } else {
            SnapshotCompleteness::Complete
        },
        owner_completeness: if ownership_partial {
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits")
        } else {
            OwnerCompleteness::Complete
        },
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets,
        processes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortEntryDescriptor {
    socket_index: u32,
    owner_index: u32,
    protected: bool,
}

impl NetworkSnapshot {
    pub(crate) fn socket_set_diff_safe(&self) -> bool {
        self.completeness != SnapshotCompleteness::Raced
            && self.omitted_evidence_gap_count == 0
            && !self
                .evidence_gaps
                .iter()
                .any(|gap| gap.impact == EvidenceImpact::SocketSet)
    }

    pub(crate) fn platform(&self) -> Platform {
        snapshot_platform(self)
    }

    pub(crate) fn port_entry_descriptors(
        &self,
        protected_names: &[String],
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        self.port_entry_descriptors_matching(None, None, protected_names)
    }

    pub(crate) fn port_entry_descriptors_matching(
        &self,
        target_pid: Option<u32>,
        target_port: Option<u16>,
        protected_names: &[String],
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        self.port_entry_descriptors_matching_with_limit(
            target_pid,
            target_port,
            protected_names,
            DERIVED_PORT_ENTRIES_MAX,
        )
    }

    fn port_entry_descriptors_matching_with_limit(
        &self,
        target_pid: Option<u32>,
        target_port: Option<u16>,
        protected_names: &[String],
        max_entries: usize,
    ) -> Result<Vec<PortEntryDescriptor>, ObservationError> {
        let platform = snapshot_platform(self);
        let mut protection_by_identity = HashMap::new();
        let mut descriptors = Vec::new();
        for (socket_index, socket) in self.sockets.iter().enumerate() {
            if target_port.is_some_and(|port| socket.local_endpoint.port.get() != port) {
                continue;
            }
            if !matches!(socket.state, SocketState::Listen | SocketState::Bound) {
                continue;
            }
            let emitted = if let Some(pid) = target_pid {
                socket
                    .owners
                    .iter()
                    .filter(|owner| owner_pid(owner) == pid)
                    .count()
            } else {
                socket.owners.len().max(1)
            };
            if emitted == 0 {
                continue;
            }
            if descriptors
                .len()
                .checked_add(emitted)
                .is_none_or(|count| count > max_entries)
            {
                return Err(ObservationError::LegacyProjectionLimitExceeded);
            }
            let socket_index = u32::try_from(socket_index)
                .map_err(|_| ObservationError::LegacyProjectionLimitExceeded)?;
            if socket.owners.is_empty() {
                descriptors.push(PortEntryDescriptor {
                    socket_index,
                    owner_index: u32::MAX,
                    protected: false,
                });
                continue;
            }
            for (owner_index, owner) in socket.owners.iter().enumerate() {
                if target_pid.is_some_and(|pid| owner_pid(owner) != pid) {
                    continue;
                }
                let protected = match owner {
                    OwnerObservation::Verified(identity) => {
                        *protection_by_identity.entry(*identity).or_insert_with(|| {
                            self.processes
                                .get(identity)
                                .and_then(|process| process.name.as_deref())
                                .is_some_and(|name| {
                                    crate::protection::is_protected_process_name(
                                        platform,
                                        name,
                                        protected_names,
                                    )
                                })
                        })
                    }
                    OwnerObservation::UnverifiedPid { .. } => false,
                };
                descriptors.push(PortEntryDescriptor {
                    socket_index,
                    owner_index: u32::try_from(owner_index)
                        .map_err(|_| ObservationError::LegacyProjectionLimitExceeded)?,
                    protected,
                });
            }
        }
        Ok(descriptors)
    }

    pub(crate) fn port_entry_view(&self, descriptor: &PortEntryDescriptor) -> PortEntryView<'_> {
        let socket = &self.sockets[descriptor.socket_index as usize];
        let owner = (descriptor.owner_index != u32::MAX)
            .then(|| &socket.owners[descriptor.owner_index as usize]);
        let (pid, process_identity, process) = match owner {
            Some(OwnerObservation::Verified(identity)) => (
                Some(identity.pid),
                Some(*identity),
                self.processes.get(identity),
            ),
            Some(OwnerObservation::UnverifiedPid { pid, .. }) => (Some(*pid), None, None),
            None => (None, None, None),
        };
        let state = match socket.state {
            SocketState::Listen => LegacySocketState::Listen,
            SocketState::Bound => LegacySocketState::Bound,
            _ => unreachable!("descriptors contain only open socket states"),
        };
        PortEntryView {
            protocol: socket.local_endpoint.protocol,
            local_addr: socket.local_endpoint.address,
            local_port: socket.local_endpoint.port.get(),
            state,
            pid,
            process_name: process.and_then(|process| process.name.as_deref()),
            executable_path: process.and_then(|process| process.executable_path.as_deref()),
            command_line: process.and_then(|process| process.command_line.as_deref()),
            parent_pid: process.and_then(|process| process.parent_pid),
            parent_process_name: process.and_then(|process| process.parent_process_name.as_deref()),
            protected: descriptor.protected,
            platform: snapshot_platform(self),
            permission: if process.is_some_and(|process| {
                process.metadata_completeness == MetadataCompleteness::Complete
            }) && socket.owner_completeness.is_complete()
            {
                PermissionStatus::Full
            } else {
                PermissionStatus::Partial
            },
            process_identity,
            ipv6_scope: socket.local_endpoint.ipv6_scope,
            label: None,
        }
    }
}

fn snapshot_platform(snapshot: &NetworkSnapshot) -> Platform {
    match snapshot.scope.kind {
        ObservationScopeKind::CurrentNetworkNamespace => Platform::Linux,
        ObservationScopeKind::CurrentHostProcessVisibleSockets => Platform::Macos,
        ObservationScopeKind::CurrentHostNetworkStack => Platform::Windows,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[allow(
    dead_code,
    reason = "some operational variants are native-source specific"
)]
pub(crate) enum ObservationError {
    #[error("socket table is unavailable")]
    SocketTableUnavailable,
    #[error("permission was denied while reading the socket table")]
    SocketTablePermissionDenied,
    #[error("native observation data is malformed")]
    NativeDataMalformed,
    #[error("native observation data exceeds its byte limit")]
    NativeDataOversized,
    #[error("socket observation limit exceeded")]
    SocketObservationLimitExceeded,
    #[error("process identity limit exceeded")]
    ProcessIdentityLimitExceeded,
    #[error("owner attribution limit exceeded")]
    OwnerAttributionLimitExceeded,
    #[error("legacy projection limit exceeded")]
    LegacyProjectionLimitExceeded,
    #[error("platform API failed: {0}")]
    PlatformApiFailed(String),
    #[error("wall clock is unavailable")]
    ClockUnavailable,
    #[error("capture completion precedes capture start")]
    InvalidWallClockInterval,
    #[error("socket set is partial")]
    PartialSocketSet,
    #[error("observation raced")]
    ObservationRaced,
    #[error("owner completeness reason limit exceeded")]
    OwnerReasonLimitExceeded,
    #[error("scope identifier exceeds its byte limit")]
    ScopeIdentifierOversized,
    #[error("scope limitation limit exceeded")]
    ScopeLimitationLimitExceeded,
}

#[derive(Debug, Clone)]
pub(crate) struct NativeSocketObservation {
    pub(crate) endpoint: EndpointIdentity,
    pub(crate) state: SocketState,
    pub(crate) timer: Option<TcpTimerObservation>,
    pub(crate) token: Option<PlatformSocketToken>,
}

impl PartialEq for NativeSocketObservation {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.state == other.state && self.token == other.token
    }
}

impl Eq for NativeSocketObservation {}

impl Ord for NativeSocketObservation {
    fn cmp(&self, other: &Self) -> Ordering {
        self.endpoint
            .cmp(&other.endpoint)
            .then_with(|| self.state.cmp(&other.state))
            .then_with(|| self.token.cmp(&other.token))
    }
}

impl PartialOrd for NativeSocketObservation {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnerAssociations {
    pub(crate) owners_by_socket: Vec<Vec<u32>>,
    pub(crate) local_completeness: Vec<OwnerCompleteness>,
    pub(crate) global_completeness: OwnerCompleteness,
    pub(crate) evidence_gaps: Vec<EvidenceGap>,
    pub(crate) omitted_evidence_gap_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeObservationPass {
    pub(crate) sockets: Vec<NativeSocketObservation>,
    pub(crate) owners: OwnerAssociations,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProcessRead {
    Verified {
        marker: ProcessStartMarker,
        observation: ProcessObservation,
    },
    Unverified(UnverifiedOwnerReason),
}

/// The internal seam implemented by native adapters.
pub(crate) trait ObservationSource {
    fn wall_clock(&mut self) -> Result<SystemTime, ObservationError>;
    fn collect_native_pass(
        &mut self,
        profile: MetadataProfile,
    ) -> Result<NativeObservationPass, ObservationError>;
    fn read_processes(
        &mut self,
        sorted_pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<BTreeMap<u32, ProcessRead>, ObservationError>;
}

// The sequential metadata-budget reader is the Linux/macOS collection path;
// Windows accounts for its budget inside its own snapshot reader. Tests on
// every platform drive the fake source through this accounting.
#[cfg(any(target_os = "linux", target_os = "macos", test))]
pub(crate) fn process_read_metadata_bytes(read: &ProcessRead) -> usize {
    let ProcessRead::Verified { observation, .. } = read else {
        return 0;
    };
    [
        observation.name.as_ref().map_or(0, |value| value.len()),
        observation
            .executable_path
            .as_ref()
            .map_or(0, |value| value.as_os_str().as_encoded_bytes().len()),
        observation
            .parent_process_name
            .as_ref()
            .map_or(0, |value| value.len()),
        observation
            .command_line
            .as_ref()
            .map_or(0, |value| value.len()),
    ]
    .into_iter()
    .fold(0usize, usize::saturating_add)
}

#[derive(Debug)]
struct CollectedPass {
    sockets: Vec<NativeSocketObservation>,
    associations: OwnerAssociations,
    processes_by_pid: BTreeMap<u32, ProcessRead>,
    omitted_evidence_gap_count: u64,
}

#[derive(Debug, Default)]
struct Instability {
    socket_set: bool,
    ownership: bool,
    affected_sockets: BTreeSet<NativeSocketObservation>,
}

impl Instability {
    fn is_stable(&self) -> bool {
        !self.socket_set && !self.ownership
    }
}

pub(crate) fn collect_consistent<S: ObservationSource>(
    source: &mut S,
    scope: ObservationScope,
    profile: MetadataProfile,
) -> Result<NetworkSnapshot, ObservationError> {
    collect_consistent_with_limits(source, scope, profile, ObservationLimits::PRODUCTION)
}

fn collect_consistent_with_limits<S: ObservationSource>(
    source: &mut S,
    scope: ObservationScope,
    profile: MetadataProfile,
    limits: ObservationLimits,
) -> Result<NetworkSnapshot, ObservationError> {
    let mut identity_reads_total = 0usize;
    for attempt_index in 0..CONSISTENCY_ATTEMPTS_MAX {
        let mut identity_reads_attempt = 0usize;
        let started_at = source.wall_clock()?;
        let mut pass_a = collect_pass(
            source,
            MetadataProfile::IdentityOnly,
            limits,
            &mut identity_reads_attempt,
            &mut identity_reads_total,
        )?;
        let mut pass_b = collect_pass(
            source,
            profile,
            limits,
            &mut identity_reads_attempt,
            &mut identity_reads_total,
        )?;
        let completed_at = source.wall_clock()?;
        validate_wall_clock_interval(started_at, completed_at)?;
        let instability = compare_passes(&pass_a, &pass_b);
        merge_attempt_uncertainty(&mut pass_a, &mut pass_b)?;
        drop(pass_a);
        if instability.is_stable() {
            return build_snapshot(started_at, completed_at, scope, pass_b, None, limits);
        }
        if attempt_index + 1 == CONSISTENCY_ATTEMPTS_MAX {
            return build_snapshot(
                started_at,
                completed_at,
                scope,
                pass_b,
                Some(&instability),
                limits,
            );
        }
    }
    unreachable!("the positive consistency-attempt constant exhausts by return")
}

#[expect(
    clippy::too_many_lines,
    reason = "the bounded native-pass orchestration is clearer as one ordered operation"
)]
fn collect_pass<S: ObservationSource>(
    source: &mut S,
    profile: MetadataProfile,
    limits: ObservationLimits,
    identity_reads_attempt: &mut usize,
    identity_reads_total: &mut usize,
) -> Result<CollectedPass, ObservationError> {
    let NativeObservationPass {
        mut sockets,
        owners: mut associations,
    } = source.collect_native_pass(profile)?;
    if sockets.len() > limits.sockets {
        return Err(ObservationError::SocketObservationLimitExceeded);
    }
    if associations.owners_by_socket.len() != sockets.len()
        || associations.local_completeness.len() != sockets.len()
    {
        return Err(ObservationError::NativeDataMalformed);
    }
    validate_owner_completeness(&associations.global_completeness)?;
    for completeness in &associations.local_completeness {
        validate_owner_completeness(completeness)?;
    }
    if associations.evidence_gaps.len() > EVIDENCE_GAPS_MAX {
        return Err(ObservationError::NativeDataMalformed);
    }
    for owners in &mut associations.owners_by_socket {
        owners.sort_unstable();
    }
    let mut order = (0..sockets.len()).collect::<Vec<_>>();
    order.sort_by(|left, right| {
        sockets[*left]
            .cmp(&sockets[*right])
            .then_with(|| {
                associations.owners_by_socket[*left].cmp(&associations.owners_by_socket[*right])
            })
            .then_with(|| {
                compare_owner_completeness(
                    &associations.local_completeness[*left],
                    &associations.local_completeness[*right],
                )
            })
            .then_with(|| sockets[*left].timer.cmp(&sockets[*right].timer))
    });
    let mut socket_slots = sockets.into_iter().map(Some).collect::<Vec<_>>();
    let mut owner_slots = std::mem::take(&mut associations.owners_by_socket)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    let mut completeness_slots = std::mem::take(&mut associations.local_completeness)
        .into_iter()
        .map(Some)
        .collect::<Vec<_>>();
    sockets = Vec::with_capacity(order.len());
    associations.owners_by_socket = Vec::with_capacity(order.len());
    associations.local_completeness = Vec::with_capacity(order.len());
    for index in order {
        sockets.push(
            socket_slots[index]
                .take()
                .expect("canonical index is unique"),
        );
        associations.owners_by_socket.push(
            owner_slots[index]
                .take()
                .expect("canonical index is unique"),
        );
        associations.local_completeness.push(
            completeness_slots[index]
                .take()
                .expect("canonical index is unique"),
        );
    }
    let owner_edges = associations
        .owners_by_socket
        .iter()
        .try_fold(0usize, |count, owners| count.checked_add(owners.len()))
        .ok_or(ObservationError::OwnerAttributionLimitExceeded)?;
    if owner_edges > limits.owner_edges {
        return Err(ObservationError::OwnerAttributionLimitExceeded);
    }

    let pids: Vec<u32> = associations
        .owners_by_socket
        .iter()
        .flatten()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if pids.len() > limits.candidate_pids {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    let next_attempt = identity_reads_attempt
        .checked_add(pids.len())
        .ok_or(ObservationError::ProcessIdentityLimitExceeded)?;
    if next_attempt > limits.identity_reads_per_attempt {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    let next_total = identity_reads_total
        .checked_add(pids.len())
        .ok_or(ObservationError::ProcessIdentityLimitExceeded)?;
    if next_total > limits.identity_reads_total {
        return Err(ObservationError::ProcessIdentityLimitExceeded);
    }
    *identity_reads_attempt = next_attempt;
    *identity_reads_total = next_total;

    let processes_by_pid = source.read_processes(&pids, profile, limits.optional_metadata_bytes)?;
    if processes_by_pid.len() != pids.len()
        || !pids
            .iter()
            .zip(processes_by_pid.keys())
            .all(|(expected, actual)| expected == actual)
    {
        return Err(ObservationError::NativeDataMalformed);
    }
    Ok(CollectedPass {
        sockets,
        omitted_evidence_gap_count: associations.omitted_evidence_gap_count,
        associations,
        processes_by_pid,
    })
}

pub(crate) fn compare_owner_completeness(
    left: &OwnerCompleteness,
    right: &OwnerCompleteness,
) -> Ordering {
    owner_completeness_rank(left)
        .cmp(&owner_completeness_rank(right))
        .then_with(|| match (left, right) {
            (
                OwnerCompleteness::Partial { reasons: left },
                OwnerCompleteness::Partial { reasons: right },
            ) => owner_reason_names(left).cmp(owner_reason_names(right)),
            _ => Ordering::Equal,
        })
}

/// Snapshot and watch outputs share one owner-completeness ordering:
/// complete before partial before raced.
pub(crate) const fn owner_completeness_rank(completeness: &OwnerCompleteness) -> u8 {
    match completeness {
        OwnerCompleteness::Complete => 0,
        OwnerCompleteness::Partial { .. } => 1,
        OwnerCompleteness::Raced => 2,
    }
}

fn compare_passes(a: &CollectedPass, b: &CollectedPass) -> Instability {
    let mut affected_sockets = BTreeSet::new();
    let mut socket_set = false;
    let mut owner_edges_changed = false;
    let mut index_a = 0;
    let mut index_b = 0;
    while index_a < a.sockets.len() || index_b < b.sockets.len() {
        match (a.sockets.get(index_a), b.sockets.get(index_b)) {
            (Some(socket_a), Some(socket_b)) => match socket_a.cmp(socket_b) {
                Ordering::Less => {
                    let end_a = socket_group_end(&a.sockets, index_a);
                    socket_set = true;
                    owner_edges_changed |= group_has_owners(a, index_a, end_a);
                    affected_sockets.insert(socket_a.clone());
                    index_a = end_a;
                }
                Ordering::Greater => {
                    let end_b = socket_group_end(&b.sockets, index_b);
                    socket_set = true;
                    owner_edges_changed |= group_has_owners(b, index_b, end_b);
                    affected_sockets.insert(socket_b.clone());
                    index_b = end_b;
                }
                Ordering::Equal => {
                    let end_a = socket_group_end(&a.sockets, index_a);
                    let end_b = socket_group_end(&b.sockets, index_b);
                    let counts_changed = end_a - index_a != end_b - index_b;
                    socket_set |= counts_changed;
                    let edges_changed =
                        group_owner_pids(a, index_a, end_a) != group_owner_pids(b, index_b, end_b);
                    owner_edges_changed |= edges_changed;
                    if counts_changed || edges_changed {
                        affected_sockets.insert(socket_a.clone());
                    }
                    index_a = end_a;
                    index_b = end_b;
                }
            },
            (Some(socket), None) => {
                let end = socket_group_end(&a.sockets, index_a);
                socket_set = true;
                owner_edges_changed |= group_has_owners(a, index_a, end);
                affected_sockets.insert(socket.clone());
                index_a = end;
            }
            (None, Some(socket)) => {
                let end = socket_group_end(&b.sockets, index_b);
                socket_set = true;
                owner_edges_changed |= group_has_owners(b, index_b, end);
                affected_sockets.insert(socket.clone());
                index_b = end;
            }
            (None, None) => break,
        }
    }
    let identity_changed = !identities_equal(a, b);
    if identity_changed {
        for (index, socket) in b.sockets.iter().enumerate() {
            if b.associations.owners_by_socket[index]
                .iter()
                .any(|pid| process_marker(a, *pid) != process_marker(b, *pid))
            {
                affected_sockets.insert(socket.clone());
            }
        }
    }
    Instability {
        socket_set,
        ownership: owner_edges_changed || identity_changed,
        affected_sockets,
    }
}

fn group_owner_pids(pass: &CollectedPass, start: usize, end: usize) -> Vec<u32> {
    let mut pids = pass.associations.owners_by_socket[start..end]
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids
}

fn group_has_owners(pass: &CollectedPass, start: usize, end: usize) -> bool {
    pass.associations.owners_by_socket[start..end]
        .iter()
        .any(|owners| !owners.is_empty())
}

fn identities_equal(a: &CollectedPass, b: &CollectedPass) -> bool {
    a.processes_by_pid.len() == b.processes_by_pid.len()
        && a.processes_by_pid
            .iter()
            .zip(&b.processes_by_pid)
            .all(|((pid_a, _), (pid_b, _))| {
                pid_a == pid_b && process_marker(a, *pid_a) == process_marker(b, *pid_b)
            })
}

fn process_marker(pass: &CollectedPass, pid: u32) -> Option<ProcessStartMarker> {
    match pass.processes_by_pid.get(&pid) {
        Some(ProcessRead::Verified { marker, .. }) => Some(*marker),
        Some(ProcessRead::Unverified(_)) | None => None,
    }
}

fn validate_owner_completeness(completeness: &OwnerCompleteness) -> Result<(), ObservationError> {
    if let OwnerCompleteness::Partial { reasons } = completeness
        && reasons.len() > OWNER_COMPLETENESS_REASONS_MAX
    {
        return Err(ObservationError::OwnerReasonLimitExceeded);
    }
    Ok(())
}

fn merge_attempt_uncertainty(
    pass_a: &mut CollectedPass,
    pass_b: &mut CollectedPass,
) -> Result<(), ObservationError> {
    pass_b.associations.global_completeness = merge_owner_completeness(
        &pass_a.associations.global_completeness,
        &pass_b.associations.global_completeness,
    )?;
    let mut index_a = 0usize;
    let mut index_b = 0usize;
    while index_a < pass_a.sockets.len() && index_b < pass_b.sockets.len() {
        match pass_a.sockets[index_a].cmp(&pass_b.sockets[index_b]) {
            Ordering::Less => index_a = socket_group_end(&pass_a.sockets, index_a),
            Ordering::Greater => index_b = socket_group_end(&pass_b.sockets, index_b),
            Ordering::Equal => {
                let end_a = socket_group_end(&pass_a.sockets, index_a);
                let end_b = socket_group_end(&pass_b.sockets, index_b);
                let mut pass_a_completeness = OwnerCompleteness::Complete;
                for completeness in &pass_a.associations.local_completeness[index_a..end_a] {
                    pass_a_completeness =
                        merge_owner_completeness(&pass_a_completeness, completeness)?;
                }
                for completeness in &mut pass_b.associations.local_completeness[index_b..end_b] {
                    *completeness = merge_owner_completeness(&pass_a_completeness, completeness)?;
                }
                index_a = end_a;
                index_b = end_b;
            }
        }
    }
    pass_b.omitted_evidence_gap_count = pass_b
        .omitted_evidence_gap_count
        .saturating_add(pass_a.omitted_evidence_gap_count);
    // Both passes observe the same host, so a gap that is identical in every
    // field normally shows up in both. Aggregate counts are observations, not
    // disjoint sets: retain the maximum as "at least this many observed"
    // rather than summing and inventing a union. Exact gaps still deduplicate
    // by their complete tuple. Do this before enforcing the merged budget so
    // only distinct evidence consumes retention slots.
    let mut merged: BTreeSet<EvidenceGap> = std::mem::take(&mut pass_a.associations.evidence_gaps)
        .into_iter()
        .collect();
    for gap in pass_b.associations.evidence_gaps.drain(..) {
        if gap.affected_pid_count.is_some()
            && let Some(existing) = merged
                .iter()
                .find(|existing| existing.same_aggregate_observation(&gap))
                .cloned()
        {
            if gap.affected_pid_count > existing.affected_pid_count {
                let removed = merged.remove(&existing);
                debug_assert!(removed, "the aggregate gap was found immediately above");
                merged.insert(gap);
            }
            continue;
        }
        if merged.contains(&gap) {
            continue;
        }
        if merged.len() >= EVIDENCE_GAPS_MAX {
            pass_b.omitted_evidence_gap_count = pass_b.omitted_evidence_gap_count.saturating_add(1);
            continue;
        }
        merged.insert(gap);
    }
    pass_b.associations.evidence_gaps = merged.into_iter().collect();
    Ok(())
}

fn socket_group_end(sockets: &[NativeSocketObservation], start: usize) -> usize {
    let mut end = start + 1;
    while end < sockets.len() && sockets[end] == sockets[start] {
        end += 1;
    }
    end
}

fn merge_owner_completeness(
    left: &OwnerCompleteness,
    right: &OwnerCompleteness,
) -> Result<OwnerCompleteness, ObservationError> {
    if matches!(left, OwnerCompleteness::Raced) || matches!(right, OwnerCompleteness::Raced) {
        return Ok(OwnerCompleteness::Raced);
    }
    let reasons = [left, right]
        .into_iter()
        .flat_map(|completeness| match completeness {
            OwnerCompleteness::Partial { reasons } => reasons.as_slice(),
            OwnerCompleteness::Complete | OwnerCompleteness::Raced => &[],
        });
    let reasons: BTreeSet<_> = reasons.copied().collect();
    if reasons.is_empty() {
        Ok(OwnerCompleteness::Complete)
    } else {
        OwnerCompleteness::partial(reasons)
    }
}

fn build_snapshot(
    started_at: SystemTime,
    completed_at: SystemTime,
    scope: ObservationScope,
    mut pass: CollectedPass,
    instability: Option<&Instability>,
    limits: ObservationLimits,
) -> Result<NetworkSnapshot, ObservationError> {
    let raced = instability.is_some();
    let mut evidence_gaps = Vec::new();
    let mut omitted_evidence_gap_count = pass.omitted_evidence_gap_count;
    for gap in pass.associations.evidence_gaps.drain(..) {
        push_gap(
            &mut evidence_gaps,
            &mut omitted_evidence_gap_count,
            gap,
            limits.evidence_gaps,
        );
    }
    if let Some(instability) = instability {
        if instability.socket_set {
            push_gap(
                &mut evidence_gaps,
                &mut omitted_evidence_gap_count,
                EvidenceGap::new(
                    EvidenceImpact::SocketSet,
                    EvidenceGapCode::ObservationRaced,
                    None,
                    None,
                    "native socket multiplicity changed between consistency passes",
                ),
                limits.evidence_gaps,
            );
        }
        if instability.ownership {
            push_gap(
                &mut evidence_gaps,
                &mut omitted_evidence_gap_count,
                EvidenceGap::new(
                    EvidenceImpact::Ownership,
                    EvidenceGapCode::ObservationRaced,
                    None,
                    None,
                    "owner edges or process identities changed between consistency passes",
                ),
                limits.evidence_gaps,
            );
        }
    }

    for read in pass.processes_by_pid.values() {
        let ProcessRead::Unverified(reason) = read else {
            continue;
        };
        let completeness = if *reason == UnverifiedOwnerReason::Raced {
            OwnerCompleteness::Raced
        } else {
            OwnerCompleteness::partial([unverified_gap_code(*reason)])?
        };
        pass.associations.global_completeness =
            merge_owner_completeness(&pass.associations.global_completeness, &completeness)?;
    }

    let sockets = materialize_sockets(
        &pass,
        instability,
        &mut evidence_gaps,
        &mut omitted_evidence_gap_count,
        limits,
    )?;

    let processes = materialize_processes(
        &mut pass,
        &mut evidence_gaps,
        &mut omitted_evidence_gap_count,
        limits,
    );

    let owner_completeness = if instability.is_some_and(|change| change.ownership) {
        OwnerCompleteness::Raced
    } else {
        pass.associations.global_completeness.clone()
    };
    evidence_gaps.sort();
    // The merge above removes the cross-pass copies. This second pass covers
    // the remaining in-pass source: one process that exceeds the retention
    // budget on several optional fields raises the same PID-scoped gap once
    // per field. A repeated gap is not repeated evidence, and the public
    // ordering contract treats a gap as the tuple of all its fields, so the
    // serialized list must not contain the same tuple twice.
    evidence_gaps.dedup();
    let completeness = derive_snapshot_completeness(
        raced,
        &owner_completeness,
        &sockets,
        &evidence_gaps,
        omitted_evidence_gap_count,
    );
    Ok(NetworkSnapshot {
        capture_started_at: started_at,
        capture_completed_at: completed_at,
        scope,
        completeness,
        owner_completeness,
        evidence_gaps,
        omitted_evidence_gap_count,
        sockets,
        processes,
    })
}

fn materialize_processes(
    pass: &mut CollectedPass,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) -> HashMap<ProcessIdentity, ProcessObservation> {
    let mut processes = HashMap::new();
    let mut retained_bytes = 0usize;
    for (pid, read) in std::mem::take(&mut pass.processes_by_pid) {
        if let ProcessRead::Verified {
            marker,
            mut observation,
        } = read
        {
            let identity = ProcessIdentity {
                pid,
                start_marker: marker,
            };
            if observation.metadata_omission == Some(MetadataOmission::BudgetExceeded) {
                push_gap(
                    evidence_gaps,
                    omitted_evidence_gap_count,
                    EvidenceGap::new(
                        EvidenceImpact::Metadata,
                        EvidenceGapCode::NoncriticalEvidenceTruncated,
                        None,
                        Some(pid),
                        "optional process metadata exceeded its native allocation budget",
                    ),
                    limits.evidence_gaps,
                );
            }
            apply_process_metadata_budget(
                identity,
                &mut observation,
                &mut retained_bytes,
                evidence_gaps,
                omitted_evidence_gap_count,
                limits,
            );
            if observation.metadata_completeness == MetadataCompleteness::Partial
                && observation.metadata_omission != Some(MetadataOmission::BudgetExceeded)
            {
                push_gap(
                    evidence_gaps,
                    omitted_evidence_gap_count,
                    EvidenceGap::new(
                        EvidenceImpact::Metadata,
                        EvidenceGapCode::ProcessMetadataUnavailable,
                        None,
                        Some(pid),
                        "optional process metadata was incomplete",
                    ),
                    limits.evidence_gaps,
                );
            }
            processes.insert(identity, observation);
        }
    }
    processes
}

pub(crate) fn project_legacy(
    snapshot: &NetworkSnapshot,
) -> Result<Vec<PortEntry>, ObservationError> {
    project_legacy_with_limit(snapshot, DERIVED_PORT_ENTRIES_MAX, None, None)
}

pub(crate) fn project_legacy_target(
    snapshot: &NetworkSnapshot,
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, ObservationError> {
    project_legacy_with_limit(snapshot, DERIVED_PORT_ENTRIES_MAX, pid, port)
}

#[cfg(test)]
pub(crate) fn project_legacy_pids(
    snapshot: &NetworkSnapshot,
    pids: &std::collections::BTreeSet<u32>,
) -> Result<Vec<PortEntry>, ObservationError> {
    let platform = snapshot_platform(snapshot);
    let mut entries = Vec::new();
    for socket in &snapshot.sockets {
        let state = match socket.state {
            SocketState::Listen => LegacySocketState::Listen,
            SocketState::Bound => LegacySocketState::Bound,
            _ => continue,
        };
        for owner in &socket.owners {
            let pid = owner_pid(owner);
            if !pids.contains(&pid) {
                continue;
            }
            if entries.len() == DERIVED_PORT_ENTRIES_MAX {
                return Err(ObservationError::LegacyProjectionLimitExceeded);
            }
            let (identity, process) = match owner {
                OwnerObservation::Verified(identity) => {
                    (Some(*identity), snapshot.processes.get(identity))
                }
                OwnerObservation::UnverifiedPid { .. } => (None, None),
            };
            entries.push(legacy_entry(
                socket,
                state,
                platform,
                Some(pid),
                identity,
                process,
            ));
        }
    }
    Ok(entries)
}

pub(crate) fn project_legacy_identities(
    snapshot: &NetworkSnapshot,
    identities: &std::collections::BTreeSet<ProcessIdentity>,
) -> Result<Vec<PortEntry>, ObservationError> {
    let platform = snapshot_platform(snapshot);
    let mut entries = Vec::new();
    for socket in &snapshot.sockets {
        let state = match socket.state {
            SocketState::Listen => LegacySocketState::Listen,
            SocketState::Bound => LegacySocketState::Bound,
            _ => continue,
        };
        for owner in &socket.owners {
            let OwnerObservation::Verified(identity) = owner else {
                continue;
            };
            if !identities.contains(identity) {
                continue;
            }
            if entries.len() == DERIVED_PORT_ENTRIES_MAX {
                return Err(ObservationError::LegacyProjectionLimitExceeded);
            }
            entries.push(legacy_entry(
                socket,
                state,
                platform,
                Some(identity.pid),
                Some(*identity),
                snapshot.processes.get(identity),
            ));
        }
    }
    Ok(entries)
}

fn project_legacy_with_limit(
    snapshot: &NetworkSnapshot,
    max_entries: usize,
    target_pid: Option<u32>,
    target_port: Option<u16>,
) -> Result<Vec<PortEntry>, ObservationError> {
    let descriptors = snapshot.port_entry_descriptors_matching_with_limit(
        target_pid,
        target_port,
        &[],
        max_entries,
    )?;
    let platform = snapshot_platform(snapshot);
    Ok(descriptors
        .iter()
        .map(|descriptor| {
            let socket = &snapshot.sockets[descriptor.socket_index as usize];
            let owner = (descriptor.owner_index != u32::MAX)
                .then(|| &socket.owners[descriptor.owner_index as usize]);
            let (pid, identity, process) = match owner {
                Some(OwnerObservation::Verified(identity)) => (
                    Some(identity.pid),
                    Some(*identity),
                    snapshot.processes.get(identity),
                ),
                Some(OwnerObservation::UnverifiedPid { pid, .. }) => (Some(*pid), None, None),
                None => (None, None, None),
            };
            let state = match socket.state {
                SocketState::Listen => LegacySocketState::Listen,
                SocketState::Bound => LegacySocketState::Bound,
                _ => unreachable!("descriptors contain only open socket states"),
            };
            legacy_entry(socket, state, platform, pid, identity, process)
        })
        .collect())
}

const fn owner_pid(owner: &OwnerObservation) -> u32 {
    match owner {
        OwnerObservation::Verified(identity) => identity.pid,
        OwnerObservation::UnverifiedPid { pid, .. } => *pid,
    }
}

fn legacy_entry(
    socket: &SocketObservation,
    state: LegacySocketState,
    platform: Platform,
    pid: Option<u32>,
    process_identity: Option<ProcessIdentity>,
    process: Option<&ProcessObservation>,
) -> PortEntry {
    let permission = if process
        .is_some_and(|process| process.metadata_completeness == MetadataCompleteness::Complete)
        && socket.owner_completeness.is_complete()
    {
        PermissionStatus::Full
    } else {
        PermissionStatus::Partial
    };
    PortEntry {
        protocol: socket.local_endpoint.protocol,
        local_addr: socket.local_endpoint.address,
        local_port: socket.local_endpoint.port.get(),
        state,
        pid,
        process_name: process.and_then(|process| process.name.clone()),
        executable_path: process.and_then(|process| process.executable_path.clone()),
        command_line: process.and_then(|process| process.command_line.clone()),
        parent_pid: process.and_then(|process| process.parent_pid),
        parent_process_name: process.and_then(|process| process.parent_process_name.clone()),
        protected: false,
        platform,
        permission,
        process_identity,
        ipv6_scope: socket.local_endpoint.ipv6_scope,
    }
}

fn materialize_sockets(
    pass: &CollectedPass,
    instability: Option<&Instability>,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) -> Result<Vec<SocketObservation>, ObservationError> {
    let mut sockets = Vec::with_capacity(pass.sockets.len());
    for (index, native) in pass.sockets.iter().enumerate() {
        let mut owners = Vec::with_capacity(pass.associations.owners_by_socket[index].len());
        let mut unverified_local = OwnerCompleteness::Complete;
        for pid in &pass.associations.owners_by_socket[index] {
            let owner = match pass.processes_by_pid.get(pid) {
                Some(ProcessRead::Verified { marker, .. }) => {
                    OwnerObservation::Verified(ProcessIdentity {
                        pid: *pid,
                        start_marker: *marker,
                    })
                }
                Some(ProcessRead::Unverified(reason)) => {
                    let gap_code = unverified_gap_code(*reason);
                    let completeness = if *reason == UnverifiedOwnerReason::Raced {
                        OwnerCompleteness::Raced
                    } else {
                        OwnerCompleteness::partial([gap_code])?
                    };
                    unverified_local = merge_owner_completeness(&unverified_local, &completeness)?;
                    push_gap(
                        evidence_gaps,
                        omitted_evidence_gap_count,
                        EvidenceGap::new(
                            EvidenceImpact::Ownership,
                            gap_code,
                            Some(native.endpoint.clone()),
                            Some(*pid),
                            "native owner PID could not be verified to a process start identity",
                        ),
                        limits.evidence_gaps,
                    );
                    OwnerObservation::UnverifiedPid {
                        pid: *pid,
                        reason: *reason,
                    }
                }
                None => return Err(ObservationError::NativeDataMalformed),
            };
            owners.push(owner);
        }
        owners.sort();
        let local_raced =
            instability.is_some_and(|change| change.affected_sockets.contains(native));
        let source_local = &pass.associations.local_completeness[index];
        sockets.push(SocketObservation {
            local_endpoint: native.endpoint.clone(),
            state: native.state,
            timer: native.timer,
            owners,
            owner_completeness: if local_raced {
                OwnerCompleteness::Raced
            } else {
                merge_owner_completeness(source_local, &unverified_local)?
            },
            socket_token: native.token,
        });
    }

    Ok(sockets)
}

const fn unverified_gap_code(reason: UnverifiedOwnerReason) -> EvidenceGapCode {
    match reason {
        UnverifiedOwnerReason::PermissionDenied => EvidenceGapCode::OwnerPermissionDenied,
        UnverifiedOwnerReason::Disappeared => EvidenceGapCode::OwnerDisappeared,
        UnverifiedOwnerReason::IdentityUnavailable => EvidenceGapCode::ProcessIdentityUnavailable,
        UnverifiedOwnerReason::Raced => EvidenceGapCode::ObservationRaced,
    }
}

#[cfg(test)]
fn apply_metadata_budget(
    processes: &mut HashMap<ProcessIdentity, ProcessObservation>,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) {
    let mut identities: Vec<_> = processes.keys().copied().collect();
    identities.sort();
    let mut retained_bytes = 0usize;
    for identity in identities {
        let process = processes
            .get_mut(&identity)
            .expect("identity came from the same process map");
        apply_process_metadata_budget(
            identity,
            process,
            &mut retained_bytes,
            evidence_gaps,
            omitted_evidence_gap_count,
            limits,
        );
    }
}

fn apply_process_metadata_budget(
    identity: ProcessIdentity,
    process: &mut ProcessObservation,
    retained_bytes: &mut usize,
    evidence_gaps: &mut Vec<EvidenceGap>,
    omitted_evidence_gap_count: &mut u64,
    limits: ObservationLimits,
) {
    macro_rules! retain_field {
        ($field:expr, $length:expr, $value_limit:expr) => {
            if let Some(value) = $field.as_ref() {
                let value_length = $length(value);
                let next_total = retained_bytes.checked_add(value_length);
                if value_length <= $value_limit
                    && next_total.is_some_and(|total| total <= limits.optional_metadata_bytes)
                {
                    *retained_bytes = next_total.expect("checked as present");
                } else {
                    *$field = None;
                    process.metadata_omission = Some(MetadataOmission::BudgetExceeded);
                    process.metadata_completeness = MetadataCompleteness::Partial;
                    push_gap(
                        evidence_gaps,
                        omitted_evidence_gap_count,
                        EvidenceGap::new(
                            EvidenceImpact::Metadata,
                            EvidenceGapCode::NoncriticalEvidenceTruncated,
                            None,
                            Some(identity.pid),
                            "optional process metadata exceeded its retention budget",
                        ),
                        limits.evidence_gaps,
                    );
                }
            }
        };
    }
    retain_field!(
        &mut process.name,
        |value: &Arc<str>| value.len(),
        PROCESS_NAME_MAX_BYTES
    );
    retain_field!(
        &mut process.executable_path,
        |value: &Arc<Path>| value.as_os_str().as_encoded_bytes().len(),
        EXECUTABLE_PATH_MAX_BYTES
    );
    retain_field!(
        &mut process.parent_process_name,
        |value: &Arc<str>| value.len(),
        PROCESS_NAME_MAX_BYTES
    );
    retain_field!(
        &mut process.command_line,
        |value: &Arc<str>| value.len(),
        PROCESS_COMMAND_LINE_MAX_BYTES
    );
}

fn push_gap(gaps: &mut Vec<EvidenceGap>, omitted: &mut u64, gap: EvidenceGap, limit: usize) {
    if gaps.len() < limit {
        gaps.push(gap);
    } else {
        *omitted = omitted.saturating_add(1);
    }
}

fn derive_snapshot_completeness(
    raced: bool,
    owner_completeness: &OwnerCompleteness,
    sockets: &[SocketObservation],
    gaps: &[EvidenceGap],
    omitted_gap_count: u64,
) -> SnapshotCompleteness {
    if raced {
        return SnapshotCompleteness::Raced;
    }
    if !gaps.is_empty()
        || omitted_gap_count > 0
        || !owner_completeness.is_complete()
        || sockets
            .iter()
            .any(|socket| !socket.owner_completeness.is_complete())
    {
        return SnapshotCompleteness::Partial;
    }
    SnapshotCompleteness::Complete
}

fn validate_wall_clock_interval(
    started_at: SystemTime,
    completed_at: SystemTime,
) -> Result<(), ObservationError> {
    completed_at
        .duration_since(started_at)
        .map(|_| ())
        .map_err(|_| ObservationError::InvalidWallClockInterval)
}

fn truncate_utf8(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn lossy_utf8_len(bytes: &[u8]) -> Option<usize> {
    let mut len = 0usize;
    for chunk in bytes.utf8_chunks() {
        len = len.checked_add(chunk.valid().len())?;
        if !chunk.invalid().is_empty() {
            len = len.checked_add('�'.len_utf8())?;
        }
    }
    Some(len)
}

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
pub(crate) fn push_utf8_lossy(output: &mut String, bytes: &[u8]) {
    for chunk in bytes.utf8_chunks() {
        output.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            output.push('�');
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn scoped_ipv6_identity_survives_borrowed_and_owned_projection() {
        let mut snapshot = crate::collector::Collector::collect(
            &crate::collector::FakeCollector,
            MetadataProfile::Display,
        )
        .expect("fake snapshot is valid");
        let scope = Ipv6Scope::interface_index(7).expect("test scope is valid");
        let socket = snapshot.sockets.first_mut().expect("fixture has a socket");
        socket.local_endpoint.address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        socket.local_endpoint.ipv6_scope = Some(scope);

        let descriptors = snapshot
            .port_entry_descriptors(&[])
            .expect("projection descriptors fit");
        assert_eq!(
            snapshot.port_entry_view(&descriptors[0]).ipv6_scope,
            Some(scope)
        );
        assert_eq!(
            project_legacy(&snapshot).expect("owned projection fits")[0].ipv6_scope,
            Some(scope)
        );
    }

    #[test]
    fn legacy_permission_partial_does_not_imply_permission_denial() {
        let mut snapshot = crate::collector::Collector::collect(
            &crate::collector::FakeCollector,
            MetadataProfile::Display,
        )
        .expect("fake snapshot is valid");
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has the selected socket");
        socket.owner_completeness = OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared])
            .expect("one reason fits");

        let rows = project_legacy(&snapshot).expect("legacy projection fits");
        let row = rows
            .iter()
            .find(|row| row.local_port == 3000)
            .expect("selected row is projected");

        assert_eq!(row.permission, PermissionStatus::Partial);
    }

    #[test]
    fn lossy_utf8_length_matches_conversion() {
        for bytes in [
            b"a\xffb\xf0\x80\x80\x80c".as_slice(),
            b"trailing\xf0\x9f".as_slice(),
        ] {
            let expected = String::from_utf8_lossy(bytes);
            let len = lossy_utf8_len(bytes).expect("small decoded length fits");
            assert_eq!(len, expected.len());

            let mut actual = String::with_capacity(len);
            push_utf8_lossy(&mut actual, bytes);
            assert_eq!(actual, expected);
        }
    }

    #[derive(Debug, Clone)]
    enum Step {
        Clock(u64),
        Sockets(Vec<NativeSocketObservation>),
        Owners(OwnerAssociations),
        Process(u32, MetadataProfile, ProcessRead),
        Error(ObservationError),
    }

    struct FakeSource {
        steps: VecDeque<Step>,
        calls: Vec<String>,
        process_budgets: Vec<(u32, usize)>,
        process_batch_calls: usize,
    }

    impl FakeSource {
        fn new(steps: Vec<Step>) -> Self {
            Self {
                steps: steps.into(),
                calls: Vec::new(),
                process_budgets: Vec::new(),
                process_batch_calls: 0,
            }
        }

        fn next(&mut self) -> Result<Step, ObservationError> {
            match self.steps.pop_front().expect("test source exhausted") {
                Step::Error(error) => Err(error),
                step => Ok(step),
            }
        }

        fn read_process(
            &mut self,
            pid: u32,
            profile: MetadataProfile,
            optional_metadata_bytes_remaining: usize,
        ) -> Result<ProcessRead, ObservationError> {
            self.calls.push(format!("process:{pid}:{profile:?}"));
            self.process_budgets
                .push((pid, optional_metadata_bytes_remaining));
            match self.next()? {
                Step::Process(expected_pid, expected_profile, read) => {
                    assert_eq!(pid, expected_pid);
                    assert_eq!(profile, expected_profile);
                    Ok(read)
                }
                step => panic!("expected process, got {step:?}"),
            }
        }
    }

    impl ObservationSource for FakeSource {
        fn wall_clock(&mut self) -> Result<SystemTime, ObservationError> {
            self.calls.push("clock".to_owned());
            match self.next()? {
                Step::Clock(milliseconds) => Ok(UNIX_EPOCH + Duration::from_millis(milliseconds)),
                step => panic!("expected clock, got {step:?}"),
            }
        }

        fn collect_native_pass(
            &mut self,
            _profile: MetadataProfile,
        ) -> Result<NativeObservationPass, ObservationError> {
            self.calls.push("sockets".to_owned());
            let sockets = match self.next()? {
                Step::Sockets(sockets) => sockets,
                step => panic!("expected sockets, got {step:?}"),
            };
            self.calls.push("owners".to_owned());
            let owners = match self.next()? {
                Step::Owners(owners) => owners,
                step => panic!("expected owners, got {step:?}"),
            };
            Ok(NativeObservationPass { sockets, owners })
        }

        fn read_processes(
            &mut self,
            sorted_pids: &[u32],
            profile: MetadataProfile,
            optional_metadata_bytes_remaining: usize,
        ) -> Result<BTreeMap<u32, ProcessRead>, ObservationError> {
            self.process_batch_calls += 1;
            let mut retained_bytes = 0usize;
            let mut reads = BTreeMap::new();
            for &pid in sorted_pids {
                let remaining = optional_metadata_bytes_remaining.saturating_sub(retained_bytes);
                let read = self.read_process(pid, profile, remaining)?;
                retained_bytes = retained_bytes.saturating_add(process_read_metadata_bytes(&read));
                reads.insert(pid, read);
            }
            Ok(reads)
        }
    }

    fn endpoint(port: u32) -> EndpointIdentity {
        EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .expect("fixture endpoint is valid")
    }

    fn socket(port: u32) -> NativeSocketObservation {
        NativeSocketObservation {
            endpoint: endpoint(port),
            state: SocketState::Listen,
            timer: None,
            token: PlatformSocketToken::linux_inode(u64::from(port)),
        }
    }

    fn owners(pids: &[&[u32]]) -> OwnerAssociations {
        OwnerAssociations {
            owners_by_socket: pids.iter().map(|pids| pids.to_vec()).collect(),
            local_completeness: pids.iter().map(|_| OwnerCompleteness::Complete).collect(),
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
        }
    }

    fn verified(marker: u64, name: Option<&str>) -> ProcessRead {
        ProcessRead::Verified {
            marker: ProcessStartMarker::linux(marker).expect("fixture marker is nonzero"),
            observation: ProcessObservation {
                name: name.map(Arc::from),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        }
    }

    fn scope() -> ObservationScope {
        ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[1]"),
            [ScopeLimitation::OtherNetworkNamespacesExcluded],
        )
        .expect("fixture scope is valid")
    }

    fn limits(max: usize) -> ObservationLimits {
        ObservationLimits {
            sockets: max,
            candidate_pids: max,
            owner_edges: max,
            identity_reads_per_attempt: max.saturating_mul(2),
            identity_reads_total: max.saturating_mul(4),
            evidence_gaps: max,
            optional_metadata_bytes: max,
        }
    }

    fn stable_steps(rows: Vec<NativeSocketObservation>, pids: &[&[u32]]) -> Vec<Step> {
        let unique: BTreeSet<u32> = pids.iter().flat_map(|pids| pids.iter().copied()).collect();
        let mut steps = vec![
            Step::Clock(10),
            Step::Sockets(rows.clone()),
            Step::Owners(owners(pids)),
        ];
        for pid in &unique {
            steps.push(Step::Process(
                *pid,
                MetadataProfile::IdentityOnly,
                verified(7, None),
            ));
        }
        steps.push(Step::Sockets(rows));
        steps.push(Step::Owners(owners(pids)));
        for pid in unique {
            steps.push(Step::Process(
                pid,
                MetadataProfile::Display,
                verified(7, Some("p")),
            ));
        }
        steps.push(Step::Clock(20));
        steps
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the test helper names both complete consistency passes explicitly"
    )]
    fn append_attempt(
        steps: &mut Vec<Step>,
        started: u64,
        rows_a: Vec<NativeSocketObservation>,
        pids_a: &[&[u32]],
        reads_a: &[(u32, ProcessRead)],
        rows_b: Vec<NativeSocketObservation>,
        pids_b: &[&[u32]],
        reads_b: &[(u32, ProcessRead)],
    ) {
        steps.push(Step::Clock(started));
        steps.push(Step::Sockets(rows_a));
        steps.push(Step::Owners(owners(pids_a)));
        steps.extend(
            reads_a.iter().map(|(pid, read)| {
                Step::Process(*pid, MetadataProfile::IdentityOnly, read.clone())
            }),
        );
        steps.push(Step::Sockets(rows_b));
        steps.push(Step::Owners(owners(pids_b)));
        steps.extend(
            reads_b
                .iter()
                .map(|(pid, read)| Step::Process(*pid, MetadataProfile::Display, read.clone())),
        );
        steps.push(Step::Clock(started + 1));
    }

    #[test]
    fn owner_reason_and_scope_boundaries_use_the_contract_limits() {
        let reasons = [
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerDisappeared,
            EvidenceGapCode::ProcessIdentityUnavailable,
            EvidenceGapCode::ProcessMetadataUnavailable,
            EvidenceGapCode::NativeFieldUnavailable,
            EvidenceGapCode::ScopeExcluded,
            EvidenceGapCode::NoncriticalEvidenceTruncated,
            EvidenceGapCode::ObservationRaced,
        ];
        assert_eq!(
            OwnerCompleteness::partial([]).unwrap(),
            OwnerCompleteness::Complete
        );
        let exact =
            OwnerCompleteness::partial(reasons[..OWNER_COMPLETENESS_REASONS_MAX].iter().copied())
                .expect("eight distinct owner reasons fit");
        assert!(matches!(exact, OwnerCompleteness::Partial { reasons } if reasons.len() == 8));
        assert_eq!(
            OwnerCompleteness::partial(reasons),
            Err(ObservationError::OwnerReasonLimitExceeded)
        );

        assert!(
            ObservationScope::new(ObservationScopeKind::CurrentHostNetworkStack, None, []).is_ok()
        );
        let identifier = "s".repeat(SCOPE_IDENTIFIER_MAX_BYTES);
        assert_eq!(
            ObservationScope::new(
                ObservationScopeKind::CurrentHostNetworkStack,
                Some(&identifier),
                [
                    ScopeLimitation::OtherNetworkNamespacesExcluded,
                    ScopeLimitation::ProcessFirstSocketVisibilityLimited,
                    ScopeLimitation::WslNetworkStackExcluded,
                    ScopeLimitation::ProcessMetadataPermissionLimited,
                    ScopeLimitation::Ipv6ScopeUnavailable,
                    ScopeLimitation::ScopedIpv6ExactMatchingUnavailable,
                    ScopeLimitation::NativeFieldUnavailable,
                    ScopeLimitation::PollingIntervalBlindSpot,
                ],
            )
            .expect("exact scope bounds")
            .limitations
            .len(),
            SCOPE_LIMITATIONS_MAX
        );
        let oversized = "s".repeat(SCOPE_IDENTIFIER_MAX_BYTES + 1);
        assert_eq!(
            ObservationScope::new(
                ObservationScopeKind::CurrentHostNetworkStack,
                Some(&oversized),
                []
            ),
            Err(ObservationError::ScopeIdentifierOversized)
        );
    }

    #[test]
    fn owner_reasons_are_deduplicated_in_public_name_order() {
        let completeness = OwnerCompleteness::partial([
            EvidenceGapCode::ScopeExcluded,
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::NativeFieldUnavailable,
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::ObservationRaced,
        ])
        .expect("distinct reasons fit");
        let OwnerCompleteness::Partial { reasons } = completeness else {
            panic!("nonempty reasons must remain partial");
        };

        assert_eq!(
            owner_reason_names(&reasons).collect::<Vec<_>>(),
            [
                "native_field_unavailable",
                "observation_raced",
                "owner_permission_denied",
                "scope_excluded",
            ]
        );
    }

    #[test]
    fn ninth_scope_limitation_is_rejected() {
        assert_eq!(
            super::bounded_scope_limitations(0..=SCOPE_LIMITATIONS_MAX),
            Err(ObservationError::ScopeLimitationLimitExceeded),
        );
    }

    #[test]
    fn process_name_path_and_command_boundaries_use_actual_limits() {
        fn identity() -> ProcessIdentity {
            ProcessIdentity {
                pid: 7,
                start_marker: ProcessStartMarker::linux(7).unwrap(),
            }
        }

        let cases = [
            (PROCESS_NAME_MAX_BYTES, 0, 0),
            (0, EXECUTABLE_PATH_MAX_BYTES, 0),
            (0, 0, PROCESS_COMMAND_LINE_MAX_BYTES),
        ];
        for (name_bytes, path_bytes, command_bytes) in cases {
            let mut processes = HashMap::from([(
                identity(),
                ProcessObservation {
                    name: Some(Arc::from("n".repeat(name_bytes))),
                    executable_path: Some(Arc::from(Path::new(&"p".repeat(path_bytes)))),
                    command_line: Some(Arc::from("c".repeat(command_bytes))),
                    parent_pid: None,
                    parent_process_name: None,
                    metadata_omission: None,
                    metadata_completeness: MetadataCompleteness::Complete,
                },
            )]);
            let mut gaps = Vec::new();
            let mut omitted = 0;
            apply_metadata_budget(
                &mut processes,
                &mut gaps,
                &mut omitted,
                ObservationLimits::PRODUCTION,
            );
            let process = processes.get(&identity()).unwrap();
            assert_eq!(
                process.name.as_ref().map(|value| value.len()),
                Some(name_bytes)
            );
            assert_eq!(
                process
                    .executable_path
                    .as_ref()
                    .map(|value| value.as_os_str().as_encoded_bytes().len()),
                Some(path_bytes)
            );
            assert_eq!(
                process.command_line.as_ref().map(|value| value.len()),
                Some(command_bytes)
            );
            assert!(gaps.is_empty());
        }

        // Each over-limit case pins exactly which field the budget must drop,
        // as a literal expectation rather than re-deriving it from the limits.
        let over_cases = [
            (PROCESS_NAME_MAX_BYTES + 1, 0, 0, true, false, false),
            (0, EXECUTABLE_PATH_MAX_BYTES + 1, 0, false, true, false),
            (0, 0, PROCESS_COMMAND_LINE_MAX_BYTES + 1, false, false, true),
        ];
        for (name_bytes, path_bytes, command_bytes, name_dropped, path_dropped, command_dropped) in
            over_cases
        {
            let mut processes = HashMap::from([(
                identity(),
                ProcessObservation {
                    name: Some(Arc::from("n".repeat(name_bytes))),
                    executable_path: Some(Arc::from(Path::new(&"p".repeat(path_bytes)))),
                    command_line: Some(Arc::from("c".repeat(command_bytes))),
                    parent_pid: None,
                    parent_process_name: None,
                    metadata_omission: None,
                    metadata_completeness: MetadataCompleteness::Complete,
                },
            )]);
            let mut gaps = Vec::new();
            let mut omitted = 0;
            apply_metadata_budget(
                &mut processes,
                &mut gaps,
                &mut omitted,
                ObservationLimits::PRODUCTION,
            );
            let process = processes.get(&identity()).unwrap();
            assert_eq!(process.name.is_none(), name_dropped);
            assert_eq!(process.executable_path.is_none(), path_dropped);
            assert_eq!(process.command_line.is_none(), command_dropped);
            assert_eq!(process.metadata_completeness, MetadataCompleteness::Partial);
            assert_eq!(gaps.len(), 1);
        }
    }

    #[test]
    fn endpoints_reject_zero_and_overflow_and_accept_exact_maxima() {
        assert_eq!(
            EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), 0, None),
            Err(EndpointIdentityError::InvalidPort)
        );
        assert!(
            EndpointIdentity::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                u32::from(u16::MAX),
                None
            )
            .is_ok()
        );
        assert_eq!(
            EndpointIdentity::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                u32::from(u16::MAX) + 1,
                None
            ),
            Err(EndpointIdentityError::InvalidPort)
        );
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let maximum_scope = Ipv6Scope::interface_index(u64::from(u32::MAX))
            .expect("maximum interface index is valid");
        assert_eq!(
            EndpointIdentity::new(Protocol::Tcp, ipv6, 1, Some(maximum_scope))
                .expect("maximum interface index is valid")
                .ipv6_scope,
            Some(Ipv6Scope::InterfaceIndex(NonZeroU32::MAX))
        );
        assert_eq!(
            Ipv6Scope::interface_index(u64::from(u32::MAX) + 1),
            Err(EndpointIdentityError::InvalidInterfaceIndex)
        );
        assert_eq!(
            EndpointIdentity::new(
                Protocol::Tcp,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                1,
                Some(maximum_scope),
            ),
            Err(EndpointIdentityError::Ipv4WithScope)
        );
        let mapped = EndpointIdentity::new(
            Protocol::Tcp,
            IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
            1,
            Some(Ipv6Scope::Unavailable),
        )
        .expect("mapped IPv6 canonicalizes to IPv4");
        assert_eq!(mapped.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(mapped.ipv6_scope, None);
    }

    #[test]
    fn typed_markers_and_tokens_reject_zero() {
        assert_eq!(ProcessStartMarker::linux(0), Err(ProcessMarkerError::Zero));
        assert_eq!(
            ProcessStartMarker::windows(0),
            Err(ProcessMarkerError::Zero)
        );
        assert_eq!(
            ProcessStartMarker::macos(0, 0),
            Err(ProcessMarkerError::Zero)
        );
        assert_eq!(
            ProcessStartMarker::macos(1, 1_000_000),
            Err(ProcessMarkerError::InvalidMicroseconds)
        );
        assert!(ProcessStartMarker::macos(u64::MAX, 999_999).is_ok());
        assert_eq!(PlatformSocketToken::linux_inode(0), None);
        assert!(PlatformSocketToken::macos_socket_id(u64::MAX).is_some());
    }

    #[test]
    fn socket_state_order_is_frozen_and_unknown_retains_native_code() {
        let mut states = vec![
            SocketState::Unknown(9),
            SocketState::Bound,
            SocketState::Closed,
            SocketState::Unknown(2),
            SocketState::NewSynReceived,
            SocketState::DeleteTcb,
            SocketState::TimeWait,
            SocketState::LastAck,
            SocketState::Closing,
            SocketState::CloseWait,
            SocketState::FinWait2,
            SocketState::FinWait1,
            SocketState::Established,
            SocketState::SynReceived,
            SocketState::SynSent,
            SocketState::Listen,
        ];
        states.sort();
        assert_eq!(
            states,
            vec![
                SocketState::Closed,
                SocketState::Listen,
                SocketState::SynSent,
                SocketState::SynReceived,
                SocketState::Established,
                SocketState::FinWait1,
                SocketState::FinWait2,
                SocketState::CloseWait,
                SocketState::Closing,
                SocketState::LastAck,
                SocketState::TimeWait,
                SocketState::DeleteTcb,
                SocketState::NewSynReceived,
                SocketState::Bound,
                SocketState::Unknown(2),
                SocketState::Unknown(9)
            ]
        );
    }

    #[test]
    fn linux_tcp_timer_mapping_and_ceiling_conversion_are_frozen() {
        let expected = [
            TcpTimerKind::None,
            TcpTimerKind::Retransmit,
            TcpTimerKind::Other,
            TcpTimerKind::TimeWait,
            TcpTimerKind::ZeroWindowProbe,
        ];
        for (native, expected) in expected.into_iter().enumerate() {
            assert_eq!(
                TcpTimerKind::from_linux_native(u32::try_from(native).expect("small code")),
                expected
            );
        }
        assert_eq!(
            TcpTimerKind::from_linux_native(255),
            TcpTimerKind::Unknown(255)
        );

        let timer = TcpTimerObservation::from_linux_native(1, 1, Some(128));
        assert_eq!(timer.kind, TcpTimerKind::Retransmit);
        assert_eq!(timer.native_code, None);
        assert_eq!(timer.raw_ticks, 1);
        assert_eq!(timer.estimated_remaining_milliseconds, Some(8));
        assert_eq!(
            TcpTimerObservation::from_linux_native(255, 1, Some(100)).native_code,
            Some(255)
        );
        assert_eq!(
            TcpTimerObservation::from_linux_native(3, u64::MAX, Some(1))
                .estimated_remaining_milliseconds,
            None
        );
        assert_eq!(
            TcpTimerObservation::from_linux_native(0, 0, None).estimated_remaining_milliseconds,
            None
        );
    }

    #[test]
    fn stable_collection_returns_pass_b_and_exact_call_order() {
        let row = socket(80);
        let mut source = FakeSource::new(stable_steps(vec![row], &[&[42]]));
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("stable observation succeeds");
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
        assert_eq!(
            snapshot
                .processes
                .values()
                .next()
                .and_then(|p| p.name.as_deref()),
            Some("p")
        );
        assert_eq!(
            source.calls,
            [
                "clock",
                "sockets",
                "owners",
                "process:42:IdentityOnly",
                "sockets",
                "owners",
                "process:42:Display",
                "clock"
            ]
        );
        assert!(source.steps.is_empty());
        assert_eq!(source.process_batch_calls, 2);
    }

    #[test]
    fn timer_changes_do_not_create_socket_races_and_pass_b_is_retained() {
        let mut pass_a = socket(80);
        pass_a.timer = Some(TcpTimerObservation::from_linux_native(1, 20, Some(100)));
        let mut pass_b = pass_a.clone();
        pass_b.timer = Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)));
        let mut source = FakeSource::new(vec![
            Step::Clock(10),
            Step::Sockets(vec![pass_a]),
            Step::Owners(owners(&[&[]])),
            Step::Sockets(vec![pass_b]),
            Step::Owners(owners(&[&[]])),
            Step::Clock(20),
        ]);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(1),
        )
        .expect("timer-only movement remains a stable socket observation");

        assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
        assert_eq!(
            snapshot.sockets[0].timer,
            Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)))
        );
    }

    #[test]
    fn duplicate_timer_rows_have_deterministic_timer_order() {
        let mut earlier = socket(80);
        earlier.token = None;
        earlier.timer = Some(TcpTimerObservation::from_linux_native(1, 20, Some(100)));
        let mut later = earlier.clone();
        later.timer = Some(TcpTimerObservation::from_linux_native(1, 10, Some(100)));
        let mut source = FakeSource::new(stable_steps(vec![earlier, later], &[&[], &[]]));

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(2),
        )
        .expect("duplicate timer rows collect deterministically");

        assert_eq!(
            snapshot
                .sockets
                .iter()
                .map(|socket| socket.timer.expect("fixture timer").raw_ticks)
                .collect::<Vec<_>>(),
            [10, 20]
        );
    }

    #[test]
    fn platform_socket_tokens_survive_collection() {
        let linux = socket(80);
        let macos = NativeSocketObservation {
            endpoint: endpoint(81),
            state: SocketState::Listen,
            timer: None,
            token: PlatformSocketToken::macos_socket_id(0xCAFE),
        };
        let mut source = FakeSource::new(stable_steps(
            vec![linux.clone(), macos.clone()],
            &[&[], &[]],
        ));

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(4),
        )
        .expect("typed socket tokens collect");

        assert_eq!(snapshot.sockets[0].socket_token, linux.token);
        assert_eq!(snapshot.sockets[1].socket_token, macos.token);
    }

    #[test]
    fn complete_owner_scan_can_return_an_empty_owner_set() {
        let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[]]));

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(2),
        )
        .expect("an exhaustively ownerless socket is valid");

        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::Complete
        );
        assert!(snapshot.sockets[0].owners.is_empty());
        assert!(snapshot.evidence_gaps.is_empty());
    }

    #[test]
    fn attributable_vanished_pid_merges_into_global_completeness() {
        let row = socket(80);
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(owners(&[&[42]])),
            Step::Process(
                42,
                MetadataProfile::IdentityOnly,
                ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared),
            ),
            Step::Sockets(vec![row]),
            Step::Owners(owners(&[&[42]])),
            Step::Process(
                42,
                MetadataProfile::Display,
                ProcessRead::Unverified(UnverifiedOwnerReason::Disappeared),
            ),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(4),
        )
        .expect("a vanished attributed PID remains explicit");

        assert_eq!(
            snapshot.owner_completeness,
            OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap()
        );
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap()
        );
        assert!(snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::OwnerDisappeared
                && gap.endpoint.as_ref() == Some(&endpoint(80))
                && gap.pid == Some(42)
        }));
    }

    #[test]
    fn duplicate_rows_are_compared_as_a_multiset() {
        let row = socket(80);
        let mut source = FakeSource::new(stable_steps(vec![row.clone(), row], &[&[], &[]]));
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("equal duplicate multiplicity is stable");
        assert_eq!(snapshot.sockets.len(), 2);
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
    }

    #[test]
    fn large_duplicate_group_merges_local_uncertainty_linearly() {
        const DUPLICATES: usize = 32_768;

        let row = socket(80);
        let disappeared = OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap();
        let denied = OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
        let mut local_a = vec![OwnerCompleteness::Complete; DUPLICATES];
        local_a[0] = disappeared;
        local_a[DUPLICATES - 1] = denied;
        let associations = |local_completeness| OwnerAssociations {
            owners_by_socket: vec![Vec::new(); DUPLICATES],
            local_completeness,
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
        };
        let mut pass_a = CollectedPass {
            sockets: vec![row.clone(); DUPLICATES],
            associations: associations(local_a),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: 0,
        };
        let mut pass_b = CollectedPass {
            sockets: vec![row; DUPLICATES],
            associations: associations(vec![OwnerCompleteness::Complete; DUPLICATES]),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: 0,
        };

        merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("bounded reasons merge");

        let expected = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerDisappeared,
        ])
        .unwrap();
        assert!(
            pass_b
                .associations
                .local_completeness
                .iter()
                .all(|completeness| completeness == &expected)
        );
    }

    #[test]
    fn attempt_merge_keeps_global_and_socket_local_owner_reasons_separate() {
        let global_a = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .unwrap();
        let global_b = OwnerCompleteness::partial([EvidenceGapCode::OwnerDisappeared]).unwrap();
        let local_a =
            OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable]).unwrap();
        let local_b =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        let associations = |global_completeness, local_completeness| OwnerAssociations {
            owners_by_socket: vec![Vec::new()],
            local_completeness: vec![local_completeness],
            global_completeness,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
        };
        let mut pass_a = CollectedPass {
            sockets: vec![socket(80)],
            associations: associations(global_a, local_a),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: 0,
        };
        let mut pass_b = CollectedPass {
            sockets: vec![socket(80)],
            associations: associations(global_b, local_b),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: 0,
        };

        merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("bounded reasons merge");

        assert_eq!(
            pass_b.associations.global_completeness,
            OwnerCompleteness::partial([
                EvidenceGapCode::OwnerDisappeared,
                EvidenceGapCode::OwnerPermissionDenied,
            ])
            .unwrap()
        );
        assert_eq!(
            pass_b.associations.local_completeness,
            [OwnerCompleteness::partial([
                EvidenceGapCode::OwnerAttributionIncomplete,
                EvidenceGapCode::ProcessIdentityUnavailable,
            ])
            .unwrap()]
        );
    }

    #[test]
    fn merged_source_omission_counts_saturate() {
        let mut pass_a = CollectedPass {
            sockets: Vec::new(),
            associations: owners(&[]),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: u64::MAX,
        };
        let mut pass_b = CollectedPass {
            sockets: Vec::new(),
            associations: owners(&[]),
            processes_by_pid: BTreeMap::new(),
            omitted_evidence_gap_count: 1,
        };

        merge_attempt_uncertainty(&mut pass_a, &mut pass_b).expect("empty passes merge");

        assert_eq!(pass_b.omitted_evidence_gap_count, u64::MAX);
    }

    #[test]
    fn multiplicity_owner_edges_and_identity_races_are_independent() {
        let row = socket(80);
        let pass = |sockets: Vec<NativeSocketObservation>, pids: &[&[u32]], read: ProcessRead| {
            let unique = pids
                .iter()
                .flat_map(|pids| pids.iter().copied())
                .collect::<BTreeSet<_>>();
            let associations = owners(pids);
            CollectedPass {
                sockets,
                associations,
                processes_by_pid: unique.into_iter().map(|pid| (pid, read.clone())).collect(),
                omitted_evidence_gap_count: 0,
            }
        };

        let two = pass(
            vec![row.clone(), row.clone()],
            &[&[7], &[7]],
            verified(7, None),
        );
        let one = pass(vec![row.clone()], &[&[7]], verified(7, None));
        let change = compare_passes(&two, &one);
        assert!(change.socket_set);
        assert!(
            change.ownership,
            "duplicate owner-edge multiplicity also changed"
        );

        let owner_a = pass(vec![row.clone()], &[&[7]], verified(7, None));
        let owner_b = pass(vec![row.clone()], &[&[8]], verified(7, None));
        let change = compare_passes(&owner_a, &owner_b);
        assert!(!change.socket_set);
        assert!(change.ownership);

        let marker_a = pass(vec![row.clone()], &[&[7]], verified(7, None));
        let marker_b = pass(vec![row.clone()], &[&[7]], verified(8, None));
        let change = compare_passes(&marker_a, &marker_b);
        assert!(!change.socket_set);
        assert!(change.ownership);

        let unverified = pass(
            vec![row],
            &[&[7]],
            ProcessRead::Unverified(UnverifiedOwnerReason::Raced),
        );
        assert!(compare_passes(&marker_a, &unverified).ownership);
    }

    #[test]
    fn orchestrator_reports_multiplicity_only_races() {
        let row = socket(80);
        let mut steps = Vec::new();
        for started in [1, 3] {
            append_attempt(
                &mut steps,
                started,
                vec![row.clone(), row.clone()],
                &[&[], &[]],
                &[],
                vec![row.clone()],
                &[&[]],
                &[],
            );
        }
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("bounded raced snapshot");

        assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
        assert!(snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::SocketSet
        }));
        assert!(!snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::Ownership
        }));
        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
    }

    #[test]
    fn orchestrator_reports_owner_edge_only_races() {
        let row = socket(80);
        let mut steps = Vec::new();
        for started in [1, 3] {
            append_attempt(
                &mut steps,
                started,
                vec![row.clone()],
                &[&[1]],
                &[(1, verified(10, None))],
                vec![row.clone()],
                &[&[2]],
                &[(2, verified(20, Some("p")))],
            );
        }
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("bounded raced snapshot");

        assert_eq!(snapshot.sockets.len(), 1);
        assert!(snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::Ownership
        }));
        assert!(!snapshot.evidence_gaps.iter().any(|gap| {
            gap.code == EvidenceGapCode::ObservationRaced && gap.impact == EvidenceImpact::SocketSet
        }));
    }

    #[test]
    fn orchestrator_reports_marker_only_races() {
        let row = socket(80);
        let mut steps = Vec::new();
        for started in [1, 3] {
            append_attempt(
                &mut steps,
                started,
                vec![row.clone()],
                &[&[1]],
                &[(1, verified(10, None))],
                vec![row.clone()],
                &[&[1]],
                &[(1, verified(11, Some("p")))],
            );
        }
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("bounded raced snapshot");

        assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
        assert!(matches!(
            snapshot.sockets[0].owners[0],
            OwnerObservation::Verified(ProcessIdentity {
                start_marker: ProcessStartMarker::LinuxStartTicks(marker),
                ..
            }) if marker.get() == 11
        ));
    }

    #[test]
    fn orchestrator_reports_verified_to_unverified_races() {
        let row = socket(80);
        let mut steps = Vec::new();
        for started in [1, 3] {
            append_attempt(
                &mut steps,
                started,
                vec![row.clone()],
                &[&[1]],
                &[(1, verified(10, None))],
                vec![row.clone()],
                &[&[1]],
                &[(
                    1,
                    ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                )],
            );
        }
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("bounded raced snapshot");

        assert!(matches!(
            snapshot.sockets[0].owners[0],
            OwnerObservation::UnverifiedPid {
                pid: 1,
                reason: UnverifiedOwnerReason::IdentityUnavailable
            }
        ));
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn orchestrator_treats_one_pass_only_pids_as_races() {
        let row = socket(80);
        let mut steps = Vec::new();
        for started in [1, 3] {
            append_attempt(
                &mut steps,
                started,
                vec![row.clone()],
                &[&[1]],
                &[(1, verified(10, None))],
                vec![row.clone()],
                &[&[]],
                &[],
            );
        }
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("bounded raced snapshot");

        assert!(snapshot.sockets[0].owners.is_empty());
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::Raced
        );
        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Raced);
    }

    #[test]
    fn stable_output_is_independent_of_native_source_order() {
        let rows_a = vec![socket(81), socket(80)];
        let rows_b = vec![socket(80), socket(81)];
        let mut source_a = FakeSource::new(stable_steps(rows_a, &[&[2, 1], &[3]]));
        let mut source_b = FakeSource::new(stable_steps(rows_b, &[&[3], &[1, 2]]));
        let snapshot_a = collect_consistent_with_limits(
            &mut source_a,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("first ordering collects");
        let snapshot_b = collect_consistent_with_limits(
            &mut source_b,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("second ordering collects");
        assert_eq!(snapshot_a.sockets, snapshot_b.sockets);
        assert_eq!(snapshot_a.processes, snapshot_b.processes);
    }

    #[test]
    fn evidence_gaps_and_projected_rows_have_deterministic_order() {
        let gap = |port| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                Some(endpoint(port)),
                Some(port),
                "missing",
            )
        };
        let associations_a = OwnerAssociations {
            owners_by_socket: vec![vec![2], vec![1]],
            local_completeness: vec![OwnerCompleteness::Complete; 2],
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: vec![gap(81), gap(80)],
            omitted_evidence_gap_count: 0,
        };
        let associations_b = OwnerAssociations {
            owners_by_socket: vec![vec![1], vec![2]],
            local_completeness: vec![OwnerCompleteness::Complete; 2],
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: vec![gap(80), gap(81)],
            omitted_evidence_gap_count: 0,
        };
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![socket(81), socket(80)]),
            Step::Owners(associations_a),
            Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
            Step::Process(2, MetadataProfile::IdentityOnly, verified(2, None)),
            Step::Sockets(vec![socket(80), socket(81)]),
            Step::Owners(associations_b),
            Step::Process(1, MetadataProfile::Display, verified(1, Some("one"))),
            Step::Process(2, MetadataProfile::Display, verified(2, Some("two"))),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(16),
        )
        .expect("stable deterministic snapshot");
        let gap_ports = snapshot
            .evidence_gaps
            .iter()
            .map(|gap| gap.endpoint.as_ref().unwrap().port.get())
            .collect::<Vec<_>>();
        // Both passes report the same two gaps in opposite orders. The result
        // is that pair once, in canonical order: reporting order does not
        // reach the snapshot, and observing one gap twice does not make it two.
        assert_eq!(gap_ports, vec![80, 81]);

        let projected = project_legacy(&snapshot).expect("legacy projection");
        assert_eq!(
            projected
                .iter()
                .map(|row| (row.local_port, row.pid))
                .collect::<Vec<_>>(),
            vec![(80, Some(1)), (81, Some(2))]
        );
    }

    #[test]
    fn evidence_gap_order_uses_public_code_names() {
        let mut gaps = [
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                None,
                "process",
            ),
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::NativeFieldUnavailable,
                None,
                None,
                "native",
            ),
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::NoncriticalEvidenceTruncated,
                None,
                None,
                "truncated",
            ),
        ];

        gaps.sort();

        assert_eq!(
            gaps.iter().map(|gap| gap.code.name()).collect::<Vec<_>>(),
            [
                "native_field_unavailable",
                "noncritical_evidence_truncated",
                "process_metadata_unavailable",
            ]
        );
    }

    #[test]
    fn evidence_gap_endpoint_order_uses_scope_before_port() {
        let address = IpAddr::V6("fe80::1".parse().unwrap());
        let scope_two = Ipv6Scope::interface_index(2).unwrap();
        let scope_three = Ipv6Scope::interface_index(3).unwrap();
        let mut gaps = [
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                Some(
                    EndpointIdentity::new(Protocol::Tcp, address, 8_000, Some(scope_three))
                        .unwrap(),
                ),
                None,
                "scope three",
            ),
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                Some(
                    EndpointIdentity::new(Protocol::Tcp, address, 9_000, Some(scope_two)).unwrap(),
                ),
                None,
                "scope two",
            ),
        ];

        gaps.sort();

        assert_eq!(
            gaps[0].endpoint.as_ref().unwrap().ipv6_scope,
            Some(scope_two)
        );
        assert_eq!(gaps[0].endpoint.as_ref().unwrap().port.get(), 9_000);
        assert_eq!(
            gaps[1].endpoint.as_ref().unwrap().ipv6_scope,
            Some(scope_three)
        );
        assert_eq!(gaps[1].endpoint.as_ref().unwrap().port.get(), 8_000);
    }

    #[test]
    fn partial_and_denied_ownership_remain_explicit() {
        let row = socket(80);
        let gap = EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(row.endpoint.clone()),
            Some(42),
            "denied",
        );
        let partial = OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
            .expect("one reason fits");
        let associations = OwnerAssociations {
            owners_by_socket: vec![vec![42]],
            local_completeness: vec![partial.clone()],
            global_completeness: partial,
            evidence_gaps: vec![gap.clone()],
            omitted_evidence_gap_count: 0,
        };
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(associations.clone()),
            Step::Process(
                42,
                MetadataProfile::IdentityOnly,
                ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
            ),
            Step::Sockets(vec![row]),
            Step::Owners(associations),
            Step::Process(
                42,
                MetadataProfile::Display,
                ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied),
            ),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("permission loss is a partial snapshot, not an error");
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
        assert!(snapshot.evidence_gaps.contains(&gap));
        assert!(
            snapshot
                .evidence_gaps
                .iter()
                .all(|gap| gap.code == EvidenceGapCode::OwnerPermissionDenied)
        );
        assert!(matches!(
            snapshot.sockets[0].owners[0],
            OwnerObservation::UnverifiedPid {
                reason: UnverifiedOwnerReason::PermissionDenied,
                ..
            }
        ));
        assert!(snapshot.processes.is_empty());
    }

    #[test]
    fn second_unstable_attempt_returns_its_pass_b_without_a_third_attempt() {
        let a1 = socket(80);
        let b1 = socket(81);
        let a2 = socket(82);
        let b2 = socket(83);
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![a1]),
            Step::Owners(owners(&[&[]])),
            Step::Sockets(vec![b1]),
            Step::Owners(owners(&[&[]])),
            Step::Clock(2),
            Step::Clock(3),
            Step::Sockets(vec![a2]),
            Step::Owners(owners(&[&[]])),
            Step::Sockets(vec![b2.clone()]),
            Step::Owners(owners(&[&[]])),
            Step::Clock(4),
        ];
        let mut source = FakeSource::new(steps);
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("the second raced pass B is returned");
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Raced);
        assert_eq!(snapshot.sockets[0].local_endpoint, b2.endpoint);
        assert_eq!(snapshot.owner_completeness, OwnerCompleteness::Complete);
        assert_eq!(
            snapshot.sockets[0].owner_completeness,
            OwnerCompleteness::Raced
        );
        assert_eq!(
            source
                .calls
                .iter()
                .filter(|call| *call == "sockets")
                .count(),
            4
        );
        assert!(source.steps.is_empty(), "no third attempt may be consumed");
    }

    #[test]
    fn stable_retry_is_accepted_on_attempt_two() {
        let mut steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![socket(80)]),
            Step::Owners(owners(&[&[]])),
            Step::Sockets(vec![socket(81)]),
            Step::Owners(owners(&[&[]])),
            Step::Clock(2),
        ];
        steps.extend(stable_steps(vec![socket(82)], &[&[]]));
        let mut source = FakeSource::new(steps);
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("stable retry succeeds");
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Complete);
        assert_eq!(snapshot.sockets[0].local_endpoint, endpoint(82));
        assert_eq!(
            source
                .calls
                .iter()
                .filter(|call| *call == "sockets")
                .count(),
            4
        );
    }

    #[test]
    fn injectable_limits_cover_zero_max_and_max_plus_one() {
        let mut empty = FakeSource::new(stable_steps(Vec::new(), &[]));
        let snapshot = collect_consistent_with_limits(
            &mut empty,
            scope(),
            MetadataProfile::Display,
            limits(2),
        )
        .expect("zero rows are valid");
        assert!(snapshot.sockets.is_empty());

        let rows = vec![socket(80), socket(81)];
        let mut maximum = FakeSource::new(stable_steps(rows, &[&[], &[]]));
        assert!(
            collect_consistent_with_limits(
                &mut maximum,
                scope(),
                MetadataProfile::Display,
                limits(2)
            )
            .is_ok()
        );

        let mut over = FakeSource::new(vec![
            Step::Clock(1),
            Step::Sockets(vec![socket(80), socket(81), socket(82)]),
            Step::Owners(owners(&[&[], &[], &[]])),
        ]);
        assert_eq!(
            collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, limits(2)),
            Err(ObservationError::SocketObservationLimitExceeded)
        );
        assert_eq!(over.calls, ["clock", "sockets", "owners"]);
    }

    #[test]
    fn legacy_projection_preserves_owner_metadata_and_checks_projection_bounds() {
        let mut empty_source = FakeSource::new(stable_steps(Vec::new(), &[]));
        let empty = collect_consistent_with_limits(
            &mut empty_source,
            scope(),
            MetadataProfile::Display,
            limits(4),
        )
        .expect("empty snapshot is valid");
        assert!(
            project_legacy_with_limit(&empty, 0, None, None)
                .expect("zero rows fit a zero limit")
                .is_empty()
        );

        let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[1, 1]]));
        let mut snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(4),
        )
        .expect("duplicate owner edges remain countable");
        let process = snapshot
            .processes
            .values_mut()
            .next()
            .expect("shared owner has process metadata");
        process.name = Some(Arc::from("process"));
        process.executable_path = Some(Arc::from(Path::new("/usr/bin/process")));
        process.command_line = Some(Arc::from("process --serve"));
        process.parent_process_name = Some(Arc::from("parent"));
        let projected = project_legacy_with_limit(&snapshot, 2, None, None)
            .expect("exact projection maximum is accepted");
        assert_eq!(projected.len(), 2);
        for entry in &projected {
            assert_eq!(entry.process_name.as_deref(), Some("process"));
            assert_eq!(
                entry.executable_path.as_deref(),
                Some(Path::new("/usr/bin/process"))
            );
            assert_eq!(entry.command_line.as_deref(), Some("process --serve"));
            assert_eq!(entry.parent_process_name.as_deref(), Some("parent"));
            assert!(!entry.protected);
        }
        assert_eq!(
            project_legacy_with_limit(&snapshot, 1, None, None),
            Err(ObservationError::LegacyProjectionLimitExceeded)
        );
    }

    #[test]
    fn targeted_descriptors_ignore_unrelated_rows_over_global_projection_limit() {
        let mut source = FakeSource::new(stable_steps(vec![socket(80)], &[&[1]]));
        let mut snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(4),
        )
        .expect("target fixture collects");
        let mut unrelated = snapshot.sockets[0].clone();
        unrelated.local_endpoint = endpoint(81);
        unrelated.owners =
            vec![snapshot.sockets[0].owners[0].clone(); DERIVED_PORT_ENTRIES_MAX + 1];
        snapshot.sockets.push(unrelated);

        assert_eq!(
            snapshot
                .port_entry_descriptors_matching(None, Some(80), &[])
                .expect("unrelated rows do not consume the targeted limit")
                .len(),
            1,
        );
        assert_eq!(
            snapshot.port_entry_descriptors(&[]),
            Err(ObservationError::LegacyProjectionLimitExceeded),
        );
    }

    #[test]
    fn many_sockets_for_one_owner_use_one_process_record() {
        let rows = vec![socket(80), socket(81), socket(82)];
        let mut source = FakeSource::new(stable_steps(rows, &[&[7], &[7], &[7]]));
        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("shared owner snapshot");

        assert_eq!(snapshot.processes.len(), 1);
        let process = snapshot.processes.values().next().unwrap();
        assert_eq!(process.name.as_ref().map(|name| name.len()), Some(1));
        let rows = project_legacy(&snapshot).expect("legacy rows");
        assert_eq!(rows.len(), 3);
        for row in &rows {
            assert_eq!(row.process_name.as_deref(), Some("p"));
        }
    }

    #[test]
    fn identity_limit_refuses_before_any_process_read() {
        let mut small = limits(3);
        small.owner_edges = 3;
        small.candidate_pids = 2;
        let mut source = FakeSource::new(vec![
            Step::Clock(1),
            Step::Sockets(vec![socket(80)]),
            Step::Owners(owners(&[&[1, 2, 3]])),
        ]);
        assert_eq!(
            collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small),
            Err(ObservationError::ProcessIdentityLimitExceeded)
        );
        assert!(!source.calls.iter().any(|call| call.starts_with("process:")));
    }

    #[test]
    fn owner_edge_limit_accepts_max_and_refuses_max_plus_one_before_identity_reads() {
        let row = socket(80);
        let exact_pids: &[&[u32]] = &[&[1, 1]];
        let mut exact = FakeSource::new(stable_steps(vec![row.clone()], exact_pids));
        let mut small = limits(8);
        small.owner_edges = 2;
        assert!(
            collect_consistent_with_limits(&mut exact, scope(), MetadataProfile::Display, small)
                .is_ok()
        );

        let mut over = FakeSource::new(vec![
            Step::Clock(1),
            Step::Sockets(vec![row]),
            Step::Owners(owners(&[&[1, 1, 1]])),
        ]);
        assert_eq!(
            collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, small),
            Err(ObservationError::OwnerAttributionLimitExceeded)
        );
        assert!(!over.calls.iter().any(|call| call.starts_with("process:")));
    }

    #[test]
    fn identity_reads_are_bounded_across_both_passes_of_an_attempt() {
        let row = socket(80);
        let mut small = limits(8);
        small.identity_reads_per_attempt = 2;
        let mut exact = FakeSource::new(stable_steps(vec![row.clone()], &[&[1]]));
        assert!(
            collect_consistent_with_limits(&mut exact, scope(), MetadataProfile::Display, small)
                .is_ok()
        );

        let mut over = FakeSource::new(vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(owners(&[&[1]])),
            Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
            Step::Sockets(vec![row]),
            Step::Owners(owners(&[&[1, 2]])),
        ]);
        assert_eq!(
            collect_consistent_with_limits(&mut over, scope(), MetadataProfile::Display, small),
            Err(ObservationError::ProcessIdentityLimitExceeded)
        );
        assert_eq!(
            over.calls
                .iter()
                .filter(|call| call.starts_with("process:"))
                .count(),
            1
        );
    }

    #[test]
    fn total_identity_bound_is_exact_and_refuses_before_excess_read() {
        let row = socket(80);
        let mut exact_limits = limits(4);
        exact_limits.identity_reads_total = 2;
        let mut exact = FakeSource::new(stable_steps(vec![row.clone()], &[&[1]]));
        assert!(
            collect_consistent_with_limits(
                &mut exact,
                scope(),
                MetadataProfile::Display,
                exact_limits,
            )
            .is_ok()
        );
        assert_eq!(exact.process_budgets.len(), 2);

        let mut over_limits = exact_limits;
        over_limits.identity_reads_total = 1;
        let mut over = FakeSource::new(vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(owners(&[&[1]])),
            Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
            Step::Sockets(vec![row]),
            Step::Owners(owners(&[&[1]])),
        ]);
        assert_eq!(
            collect_consistent_with_limits(
                &mut over,
                scope(),
                MetadataProfile::Display,
                over_limits,
            ),
            Err(ObservationError::ProcessIdentityLimitExceeded)
        );
        assert_eq!(
            over.process_budgets,
            [(1, over_limits.optional_metadata_bytes)]
        );
    }

    #[test]
    fn readers_receive_remaining_metadata_budget_in_pid_order() {
        let rows = vec![socket(80), socket(81)];
        let mut small = limits(4);
        small.optional_metadata_bytes = 3;
        let mut source = FakeSource::new(stable_steps(rows, &[&[2], &[1]]));

        collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
            .expect("bounded metadata collection succeeds");

        assert_eq!(source.process_budgets, [(1, 3), (2, 3), (1, 3), (2, 2)]);
    }

    #[test]
    fn omitted_metadata_truncation_gaps_are_counted() {
        let row = socket(80);
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(owners(&[&[1]])),
            Step::Process(1, MetadataProfile::IdentityOnly, verified(1, None)),
            Step::Sockets(vec![row]),
            Step::Owners(owners(&[&[1]])),
            Step::Process(1, MetadataProfile::Display, verified(1, Some("xx"))),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);
        let mut small = limits(2);
        small.evidence_gaps = 0;
        small.optional_metadata_bytes = 1;

        let snapshot =
            collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
                .expect("metadata truncation retains the snapshot");

        assert!(snapshot.evidence_gaps.is_empty());
        assert_eq!(snapshot.omitted_evidence_gap_count, 1);
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
    }

    #[test]
    fn evidence_gap_overflow_is_counted_and_forces_partial() {
        let row = socket(80);
        // Four gaps that differ by PID. Overflow accounting has to be driven
        // by evidence that genuinely differs, because repeating one gap is
        // merged down to a single retained gap rather than filling the budget.
        let gap = |pid| {
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                Some(pid),
                "missing",
            )
        };
        let associations = OwnerAssociations {
            owners_by_socket: vec![vec![]],
            local_completeness: vec![OwnerCompleteness::Complete],
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: vec![gap(1), gap(2), gap(3), gap(4)],
            omitted_evidence_gap_count: 0,
        };
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(associations.clone()),
            Step::Sockets(vec![row]),
            Step::Owners(associations),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);
        let mut small = limits(8);
        small.evidence_gaps = 1;
        let snapshot =
            collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, small)
                .expect("gap truncation retains the snapshot");
        assert_eq!(snapshot.evidence_gaps.len(), 1);
        assert_eq!(snapshot.omitted_evidence_gap_count, 3);
        assert_eq!(snapshot.completeness, SnapshotCompleteness::Partial);
    }

    /// Both consistency passes read the same host, so a real collector reports
    /// the same per-PID gaps in each one. Retaining both copies would spend
    /// half the gap budget on evidence already recorded, and the resulting
    /// overflow would make an otherwise usable observation refuse a watch diff
    /// and a kill.
    #[test]
    fn a_gap_observed_in_both_passes_is_retained_once_and_costs_one_budget_slot() {
        let row = socket(80);
        let gap = |pid| {
            EvidenceGap::new(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerPermissionDenied,
                None,
                Some(pid),
                "denied",
            )
        };
        let associations = OwnerAssociations {
            owners_by_socket: vec![vec![]],
            local_completeness: vec![OwnerCompleteness::Complete],
            global_completeness: OwnerCompleteness::Complete,
            evidence_gaps: vec![gap(1), gap(2)],
            omitted_evidence_gap_count: 0,
        };
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(associations.clone()),
            Step::Sockets(vec![row]),
            Step::Owners(associations),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);
        // A budget of exactly two: the distinct pair fits, a doubled pair
        // would not, so this also pins that the copies never reach the budget.
        let mut exact = limits(8);
        exact.evidence_gaps = 2;

        let snapshot =
            collect_consistent_with_limits(&mut source, scope(), MetadataProfile::Display, exact)
                .expect("duplicate gaps do not fail collection");

        assert_eq!(
            snapshot
                .evidence_gaps
                .iter()
                .map(|gap| gap.pid)
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2)],
        );
        assert_eq!(snapshot.omitted_evidence_gap_count, 0);
    }

    #[test]
    fn aggregate_gap_counts_merge_by_max_without_inventing_a_cross_pass_union() {
        let row = socket(80);
        let aggregate = |count| {
            EvidenceGap::aggregate_for_pids(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerPermissionDenied,
                None,
                NonZeroU64::new(count).expect("fixture count is nonzero"),
                "at least the reported number of PIDs were denied",
            )
        };
        let associations = |count| OwnerAssociations {
            owners_by_socket: vec![vec![]],
            local_completeness: vec![OwnerCompleteness::Complete],
            global_completeness: OwnerCompleteness::partial([
                EvidenceGapCode::OwnerPermissionDenied,
            ])
            .expect("one reason fits"),
            evidence_gaps: vec![aggregate(count)],
            omitted_evidence_gap_count: 0,
        };
        let steps = vec![
            Step::Clock(1),
            Step::Sockets(vec![row.clone()]),
            Step::Owners(associations(4_096)),
            Step::Sockets(vec![row]),
            Step::Owners(associations(4_100)),
            Step::Clock(2),
        ];
        let mut source = FakeSource::new(steps);

        let snapshot = collect_consistent_with_limits(
            &mut source,
            scope(),
            MetadataProfile::Display,
            limits(8),
        )
        .expect("aggregate gaps merge within one slot");

        assert_eq!(snapshot.evidence_gaps.len(), 1);
        assert_eq!(snapshot.evidence_gaps[0].affected_pid_count(), Some(4_100));
        assert_eq!(snapshot.omitted_evidence_gap_count, 0);
    }

    #[test]
    fn metadata_budget_is_pid_then_field_order_and_omits_before_overflow() {
        let mut processes = HashMap::from([
            (
                ProcessIdentity {
                    pid: 2,
                    start_marker: ProcessStartMarker::linux(2).unwrap(),
                },
                ProcessObservation {
                    name: Some(Arc::from("bb")),
                    executable_path: None,
                    command_line: None,
                    parent_pid: None,
                    parent_process_name: None,
                    metadata_omission: None,
                    metadata_completeness: MetadataCompleteness::Complete,
                },
            ),
            (
                ProcessIdentity {
                    pid: 1,
                    start_marker: ProcessStartMarker::linux(1).unwrap(),
                },
                ProcessObservation {
                    name: Some(Arc::from("aa")),
                    executable_path: Some(Arc::from(Path::new("x"))),
                    command_line: None,
                    parent_pid: None,
                    parent_process_name: None,
                    metadata_omission: None,
                    metadata_completeness: MetadataCompleteness::Complete,
                },
            ),
        ]);
        let mut gaps = Vec::new();
        let mut omitted = 0;
        let mut small = limits(8);
        small.optional_metadata_bytes = 3;
        apply_metadata_budget(&mut processes, &mut gaps, &mut omitted, small);
        let pid1 = processes
            .iter()
            .find(|(identity, _)| identity.pid == 1)
            .unwrap()
            .1;
        let pid2 = processes
            .iter()
            .find(|(identity, _)| identity.pid == 2)
            .unwrap()
            .1;
        assert_eq!(pid1.name.as_deref(), Some("aa"));
        assert_eq!(pid1.executable_path.as_deref(), Some(Path::new("x")));
        assert_eq!(pid2.name, None);
        assert_eq!(
            pid2.metadata_omission,
            Some(MetadataOmission::BudgetExceeded)
        );
        assert_eq!(pid2.metadata_completeness, MetadataCompleteness::Partial);
        assert_eq!(
            gaps.iter().map(|gap| gap.code).collect::<Vec<_>>(),
            [EvidenceGapCode::NoncriticalEvidenceTruncated]
        );
        assert_eq!(omitted, 0);
    }

    #[test]
    fn metadata_budget_omits_fields_in_order_without_changing_identity_or_socket() {
        let expected_fields = [
            (None, None, None, None),
            (Some("n"), None, None, None),
            (Some("n"), Some(Path::new("x")), None, None),
            (Some("n"), Some(Path::new("x")), Some("p"), None),
            (Some("n"), Some(Path::new("x")), Some("p"), Some("c")),
        ];

        for (budget, expected) in expected_fields.into_iter().enumerate() {
            let row = socket(80);
            let token = row.token;
            let full = ProcessRead::Verified {
                marker: ProcessStartMarker::linux(7).unwrap(),
                observation: ProcessObservation {
                    name: Some(Arc::from("n")),
                    executable_path: Some(Arc::from(Path::new("x"))),
                    command_line: Some(Arc::from("c")),
                    parent_pid: Some(99),
                    parent_process_name: Some(Arc::from("p")),
                    metadata_omission: None,
                    metadata_completeness: MetadataCompleteness::Complete,
                },
            };
            let steps = vec![
                Step::Clock(1),
                Step::Sockets(vec![row.clone()]),
                Step::Owners(owners(&[&[42]])),
                Step::Process(42, MetadataProfile::IdentityOnly, verified(7, None)),
                Step::Sockets(vec![row]),
                Step::Owners(owners(&[&[42]])),
                Step::Process(42, MetadataProfile::Display, full),
                Step::Clock(2),
            ];
            let mut source = FakeSource::new(steps);
            let mut test_limits = limits(8);
            test_limits.optional_metadata_bytes = budget;

            let snapshot = collect_consistent_with_limits(
                &mut source,
                scope(),
                MetadataProfile::Display,
                test_limits,
            )
            .expect("metadata omission retains authoritative identity");
            let owner = snapshot.sockets[0].owners[0].clone();
            let OwnerObservation::Verified(identity) = owner else {
                panic!("owner identity must remain verified");
            };
            let process = snapshot.processes.get(&identity).unwrap();

            assert_eq!(identity.pid, 42);
            assert_eq!(identity.start_marker, ProcessStartMarker::linux(7).unwrap());
            assert_eq!(snapshot.sockets[0].local_endpoint, endpoint(80));
            assert_eq!(snapshot.sockets[0].socket_token, token);
            assert_eq!(process.name.as_deref(), expected.0);
            assert_eq!(process.executable_path.as_deref(), expected.1);
            assert_eq!(process.parent_process_name.as_deref(), expected.2);
            assert_eq!(process.command_line.as_deref(), expected.3);
            assert_eq!(process.parent_pid, Some(99));
            assert_eq!(
                process.metadata_omission,
                (budget < 4).then_some(MetadataOmission::BudgetExceeded)
            );
        }
    }

    #[test]
    fn clock_errors_are_operational_and_reverse_intervals_are_rejected() {
        assert_eq!(
            validate_wall_clock_interval(
                UNIX_EPOCH + Duration::from_secs(2),
                UNIX_EPOCH + Duration::from_secs(1)
            ),
            Err(ObservationError::InvalidWallClockInterval)
        );
        let mut source = FakeSource::new(vec![Step::Error(ObservationError::ClockUnavailable)]);
        assert_eq!(
            collect_consistent_with_limits(
                &mut source,
                scope(),
                MetadataProfile::Display,
                limits(2)
            ),
            Err(ObservationError::ClockUnavailable)
        );
    }
}
