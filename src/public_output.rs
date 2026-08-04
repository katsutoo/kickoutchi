//! Shared, deterministic serialization for public structured output.
//!
//! DTOs in this module borrow domain records. Snapshot rendering allocates only
//! bounded sorting indexes, owner references, and sanitized public strings; it
//! never clones the snapshot or retains the rendered document.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};
use thiserror::Error;

use crate::diagnostic::verdict::{Evidence, EvidenceCode, EvidenceSource};
use crate::display::sanitize_bounded;
use crate::labels::LabelRegistry;
use crate::model::{
    PermissionStatus, Platform, PortEntryView, Protocol, SocketState as LegacySocketState,
};
use crate::observation::{
    EVIDENCE_MESSAGE_MAX_BYTES, EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact,
    Ipv6Scope, MetadataCompleteness, NetworkSnapshot, OWNER_COMPLETENESS_REASONS_MAX,
    ObservationScope, ObservationScopeKind, OwnerCompleteness, OwnerObservation,
    PlatformSocketToken, ProcessIdentity, ProcessObservation, ProcessStartMarker,
    SCOPE_IDENTIFIER_MAX_BYTES, SERIALIZED_OWNERS_MAX, ScopeLimitation, SnapshotCompleteness,
    SocketObservation, SocketState, TcpTimerKind, TcpTimerObservation, UnverifiedOwnerReason,
    compare_endpoint_identity, owner_completeness_rank,
};
use crate::watch::Certainty;

const SNAPSHOT_SCHEMA: &str = "kickoutchi.snapshot";
const SNAPSHOT_VERSION: u32 = 1;

pub(crate) struct LegacyListRecord<'a> {
    view: PortEntryView<'a>,
}

impl<'a> From<&PortEntryView<'a>> for LegacyListRecord<'a> {
    fn from(view: &PortEntryView<'a>) -> Self {
        Self { view: *view }
    }
}

impl Serialize for LegacyListRecord<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut row = serializer.serialize_struct("PortEntry", 15)?;
        row.serialize_field("protocol", protocol_name(self.view.protocol))?;
        row.serialize_field("local_addr", &self.view.local_addr)?;
        row.serialize_field("local_port", &self.view.local_port)?;
        row.serialize_field("state", legacy_socket_state_name(self.view.state))?;
        row.serialize_field("pid", &self.view.pid)?;
        row.serialize_field("process_name", &self.view.process_name)?;
        row.serialize_field("executable_path", &self.view.executable_path)?;
        row.serialize_field("command_line", &self.view.command_line)?;
        row.serialize_field("parent_pid", &self.view.parent_pid)?;
        row.serialize_field("parent_process_name", &self.view.parent_process_name)?;
        // Frozen `1.x` compatibility field with no backing data. It has never
        // carried real children — per-row child enumeration would walk the
        // whole process table on every refresh — but existing scripts index the
        // key, so removing it would be a breaking change. The empty array is
        // the whole implementation; there is deliberately no struct field
        // behind it to drift out of sync.
        row.serialize_field("child_pids", &[] as &[u32])?;
        row.serialize_field("protected", &self.view.protected)?;
        row.serialize_field("platform", platform_name(self.view.platform))?;
        row.serialize_field("permission", permission_name(self.view.permission))?;
        row.serialize_field("label", &self.view.label)?;
        row.end()
    }
}

#[derive(Debug, Error)]
pub(crate) enum PublicOutputError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("wall clock is unavailable")]
    ClockUnavailable,
    #[error("capture completion precedes capture start")]
    InvalidWallClockInterval,
    #[error("public count exceeds the u64 domain")]
    CountOutOfRange,
    #[error("owner completeness reason limit exceeded")]
    OwnerReasonLimitExceeded,
    #[error("invalid native timer state")]
    InvalidTimer,
}

impl PublicOutputError {
    pub(crate) fn io_error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(error) => Some(error.kind()),
            Self::Serialization(error) => error.io_error_kind(),
            Self::ClockUnavailable
            | Self::InvalidWallClockInterval
            | Self::CountOutOfRange
            | Self::OwnerReasonLimitExceeded
            | Self::InvalidTimer => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct EndpointDto<'a> {
    protocol: &'static str,
    #[serde(serialize_with = "serialize_address")]
    address: &'a std::net::IpAddr,
    port: u16,
    ipv6_scope: Option<Ipv6ScopeDto>,
}

impl<'a> From<&'a EndpointIdentity> for EndpointDto<'a> {
    fn from(endpoint: &'a EndpointIdentity) -> Self {
        Self {
            protocol: protocol_name(endpoint.protocol),
            address: &endpoint.address,
            port: endpoint.port.get(),
            ipv6_scope: endpoint.ipv6_scope.map(Ipv6ScopeDto::from),
        }
    }
}

fn serialize_address<S>(address: &std::net::IpAddr, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.collect_str(address)
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct Ipv6ScopeDto {
    kind: &'static str,
    interface_index: Option<u32>,
}

impl From<Ipv6Scope> for Ipv6ScopeDto {
    fn from(scope: Ipv6Scope) -> Self {
        match scope {
            Ipv6Scope::Unscoped => Self {
                kind: "unscoped",
                interface_index: None,
            },
            Ipv6Scope::InterfaceIndex(index) => Self {
                kind: "interface_index",
                interface_index: Some(index.get()),
            },
            Ipv6Scope::Unavailable => Self {
                kind: "unavailable",
                interface_index: None,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct SocketStateDto {
    kind: &'static str,
    native_code: Option<u32>,
}

impl From<SocketState> for SocketStateDto {
    fn from(state: SocketState) -> Self {
        match state {
            SocketState::Unknown(code) => Self {
                kind: socket_state_name(state),
                native_code: Some(code),
            },
            _ => Self {
                kind: socket_state_name(state),
                native_code: None,
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct SocketTokenDto {
    kind: &'static str,
    value: u64,
}

impl From<PlatformSocketToken> for SocketTokenDto {
    fn from(token: PlatformSocketToken) -> Self {
        match token {
            PlatformSocketToken::LinuxInode(value) => Self {
                kind: "linux_inode",
                value: value.get(),
            },
            PlatformSocketToken::MacOsSocketId(value) => Self {
                kind: "macos_socket_id",
                value: value.get(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) struct ProcessIdentityDto {
    pid: u32,
    start_marker: ProcessStartMarkerDto,
}

impl From<ProcessIdentity> for ProcessIdentityDto {
    fn from(identity: ProcessIdentity) -> Self {
        Self {
            pid: identity.pid,
            start_marker: ProcessStartMarkerDto::from(identity.start_marker),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ProcessStartMarkerDto {
    LinuxStartTicks { ticks: u64 },
    MacosStartTime { seconds: u64, microseconds: u32 },
    WindowsCreationTime { filetime_ticks: u64 },
}

impl From<ProcessStartMarker> for ProcessStartMarkerDto {
    fn from(marker: ProcessStartMarker) -> Self {
        match marker {
            ProcessStartMarker::LinuxStartTicks(ticks) => {
                Self::LinuxStartTicks { ticks: ticks.get() }
            }
            ProcessStartMarker::MacOsStartTime(time) => Self::MacosStartTime {
                seconds: time.seconds(),
                microseconds: time.microseconds(),
            },
            ProcessStartMarker::WindowsCreationTime(ticks) => Self::WindowsCreationTime {
                filetime_ticks: ticks.get(),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum OwnerObservationDto {
    Verified { identity: ProcessIdentityDto },
    UnverifiedPid { pid: u32, reason: &'static str },
}

impl From<&OwnerObservation> for OwnerObservationDto {
    fn from(owner: &OwnerObservation) -> Self {
        match owner {
            OwnerObservation::Verified(identity) => Self::Verified {
                identity: ProcessIdentityDto::from(*identity),
            },
            OwnerObservation::UnverifiedPid { pid, reason } => Self::UnverifiedPid {
                pid: *pid,
                reason: unverified_owner_reason_name(*reason),
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct OwnerSetDto<'a> {
    #[serde(serialize_with = "serialize_owners")]
    owners: Vec<&'a OwnerObservation>,
    omitted_owner_count: u64,
    completeness: &'static str,
    reasons: Vec<&'static str>,
}

impl<'a> OwnerSetDto<'a> {
    pub(crate) fn new(
        owners: &'a [OwnerObservation],
        completeness: &OwnerCompleteness,
    ) -> Result<Self, PublicOutputError> {
        let mut sorted = owners.iter().collect::<Vec<_>>();
        sorted.sort_unstable_by(|left, right| compare_owner_observation(left, right));
        let omitted = sorted.len().saturating_sub(SERIALIZED_OWNERS_MAX);
        sorted.truncate(SERIALIZED_OWNERS_MAX);
        let omitted_owner_count =
            u64::try_from(omitted).map_err(|_| PublicOutputError::CountOutOfRange)?;
        let (completeness, reasons) = owner_completeness_parts(completeness)?;
        Ok(Self {
            owners: sorted,
            omitted_owner_count,
            completeness,
            reasons,
        })
    }

    fn from_sorted_indices(
        socket: &'a SocketObservation,
        owner_indices: &[usize],
    ) -> Result<Self, PublicOutputError> {
        let owners = owner_indices
            .iter()
            .map(|&index| &socket.owners[index])
            .collect();
        let omitted = socket.owners.len().saturating_sub(owner_indices.len());
        let omitted_owner_count =
            u64::try_from(omitted).map_err(|_| PublicOutputError::CountOutOfRange)?;
        let (completeness, reasons) = owner_completeness_parts(&socket.owner_completeness)?;
        Ok(Self {
            owners,
            omitted_owner_count,
            completeness,
            reasons,
        })
    }
}

fn serialize_owners<S>(owners: &Vec<&OwnerObservation>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let public = owners.iter().map(|owner| OwnerObservationDto::from(*owner));
    serializer.collect_seq(public)
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceGapDto<'a> {
    code: &'static str,
    impact: &'static str,
    endpoint: Option<EndpointDto<'a>>,
    pid: Option<u32>,
    affected_pid_count: Option<u64>,
    message: Cow<'a, str>,
}

impl<'a> From<&'a EvidenceGap> for EvidenceGapDto<'a> {
    fn from(gap: &'a EvidenceGap) -> Self {
        Self {
            code: evidence_gap_code_name(gap.code),
            impact: evidence_impact_name(gap.impact),
            endpoint: gap.endpoint.as_ref().map(EndpointDto::from),
            pid: gap.pid,
            affected_pid_count: gap.affected_pid_count(),
            message: Cow::Owned(sanitize_bounded(gap.message(), EVIDENCE_MESSAGE_MAX_BYTES)),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ScopeDto<'a> {
    kind: &'static str,
    identifier: Option<Cow<'a, str>>,
    limitations: Vec<&'static str>,
}

impl<'a> ScopeDto<'a> {
    pub(crate) fn new(scope: &'a ObservationScope) -> Result<Self, PublicOutputError> {
        let mut limitations = scope.limitations.clone();
        limitations.sort_unstable();
        limitations.dedup();
        if limitations.len() > crate::observation::SCOPE_LIMITATIONS_MAX {
            return Err(PublicOutputError::CountOutOfRange);
        }
        Ok(Self {
            kind: scope_kind_name(scope.kind),
            identifier: scope.identifier.as_deref().map(|identifier| {
                Cow::Owned(sanitize_bounded(identifier, SCOPE_IDENTIFIER_MAX_BYTES))
            }),
            limitations: limitations.into_iter().map(scope_limitation_name).collect(),
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub(crate) struct CaptureDto {
    started_unix_ms: u64,
    completed_unix_ms: u64,
}

impl CaptureDto {
    pub(crate) fn new(
        started_at: SystemTime,
        completed_at: SystemTime,
    ) -> Result<Self, PublicOutputError> {
        if completed_at.duration_since(started_at).is_err() {
            return Err(PublicOutputError::InvalidWallClockInterval);
        }
        Ok(Self {
            started_unix_ms: unix_milliseconds(started_at)?,
            completed_unix_ms: unix_milliseconds(completed_at)?,
        })
    }

    pub(crate) const fn started_unix_ms(self) -> u64 {
        self.started_unix_ms
    }

    pub(crate) const fn completed_unix_ms(self) -> u64 {
        self.completed_unix_ms
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct EvidenceDto<'a> {
    code: &'static str,
    source: &'static str,
    certainty: &'static str,
    message: Cow<'a, str>,
}

impl<'a> From<&'a Evidence> for EvidenceDto<'a> {
    fn from(evidence: &'a Evidence) -> Self {
        Self {
            code: evidence_code_name(evidence.code),
            source: evidence_source_name(evidence.source),
            certainty: certainty_name(evidence.certainty),
            message: Cow::Owned(sanitize_bounded(
                &evidence.message,
                EVIDENCE_MESSAGE_MAX_BYTES,
            )),
        }
    }
}

impl EvidenceDto<'static> {
    pub(crate) fn literal(
        code: &'static str,
        source: &'static str,
        certainty: &'static str,
        message: &str,
    ) -> Self {
        Self {
            code,
            source,
            certainty,
            message: Cow::Owned(sanitize_bounded(message, EVIDENCE_MESSAGE_MAX_BYTES)),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
struct TimerDto {
    kind: &'static str,
    native_code: Option<u32>,
    raw_ticks: u64,
    estimated_remaining_milliseconds: Option<u64>,
    certainty: &'static str,
}

impl TimerDto {
    fn new(timer: TcpTimerObservation) -> Result<Self, PublicOutputError> {
        let expected_native = match timer.kind {
            TcpTimerKind::Unknown(code) => Some(code),
            _ => None,
        };
        if timer.native_code != expected_native {
            return Err(PublicOutputError::InvalidTimer);
        }
        Ok(Self {
            kind: timer_kind_name(timer.kind),
            native_code: timer.native_code,
            raw_ticks: timer.raw_ticks,
            estimated_remaining_milliseconds: timer.estimated_remaining_milliseconds,
            certainty: "estimated",
        })
    }
}

#[derive(Debug, Serialize)]
struct SocketDto<'a> {
    endpoint: EndpointDto<'a>,
    state: SocketStateDto,
    timer: Option<TimerDto>,
    owners: OwnerSetDto<'a>,
    socket_token: Option<SocketTokenDto>,
    label: Option<&'a str>,
}

impl<'a> SocketDto<'a> {
    fn from_index(
        socket: &'a SocketObservation,
        owner_indices: &[usize],
        labels: &'a LabelRegistry,
    ) -> Result<Self, PublicOutputError> {
        Ok(Self {
            endpoint: EndpointDto::from(&socket.local_endpoint),
            state: SocketStateDto::from(socket.state),
            timer: socket.timer.map(TimerDto::new).transpose()?,
            owners: OwnerSetDto::from_sorted_indices(socket, owner_indices)?,
            socket_token: socket.socket_token.map(SocketTokenDto::from),
            label: labels.resolve(&socket.local_endpoint),
        })
    }
}

#[derive(Debug, Serialize)]
struct ProcessDto<'a> {
    identity: ProcessIdentityDto,
    name: Option<&'a str>,
    executable_path: Option<&'a Path>,
    parent_pid: Option<u32>,
    metadata_completeness: &'static str,
}

#[derive(Debug)]
struct SocketIndex {
    source_index: usize,
    owner_indices: Vec<usize>,
    owner_completeness_rank: u8,
    owner_reasons: Vec<&'static str>,
    omitted_owner_count: u64,
}

#[derive(Debug)]
struct GapIndex {
    gap_index: usize,
    message: String,
}

impl SocketIndex {
    fn new(source_index: usize, socket: &SocketObservation) -> Result<Self, PublicOutputError> {
        let mut owner_indices = (0..socket.owners.len()).collect::<Vec<_>>();
        owner_indices.sort_unstable_by(|&left, &right| {
            compare_owner_observation(&socket.owners[left], &socket.owners[right])
        });
        owner_indices.truncate(SERIALIZED_OWNERS_MAX);
        let (_, owner_reasons) = owner_completeness_parts(&socket.owner_completeness)?;
        let omitted_owner_count =
            u64::try_from(socket.owners.len().saturating_sub(owner_indices.len()))
                .map_err(|_| PublicOutputError::CountOutOfRange)?;
        Ok(Self {
            source_index,
            owner_indices,
            owner_completeness_rank: owner_completeness_rank(&socket.owner_completeness),
            owner_reasons,
            omitted_owner_count,
        })
    }
}

struct SnapshotDto<'a> {
    snapshot: &'a NetworkSnapshot,
    labels: &'a LabelRegistry,
    capture: CaptureDto,
    scope: ScopeDto<'a>,
    gap_indices: Vec<GapIndex>,
    socket_indices: Vec<SocketIndex>,
    process_identities: Vec<&'a ProcessIdentity>,
}

impl<'a> SnapshotDto<'a> {
    fn new(
        snapshot: &'a NetworkSnapshot,
        labels: &'a LabelRegistry,
    ) -> Result<Self, PublicOutputError> {
        let capture = CaptureDto::new(snapshot.capture_started_at, snapshot.capture_completed_at)?;
        let scope = ScopeDto::new(&snapshot.scope)?;

        let mut gap_indices = snapshot
            .evidence_gaps
            .iter()
            .enumerate()
            .map(|(gap_index, gap)| GapIndex {
                gap_index,
                message: sanitize_bounded(gap.message(), EVIDENCE_MESSAGE_MAX_BYTES),
            })
            .collect::<Vec<_>>();
        gap_indices.sort_unstable_by(|left, right| compare_gap_index(snapshot, left, right));

        let mut socket_indices = snapshot
            .sockets
            .iter()
            .enumerate()
            .map(|(index, socket)| SocketIndex::new(index, socket))
            .collect::<Result<Vec<_>, _>>()?;
        socket_indices.sort_unstable_by(|left, right| compare_socket_index(snapshot, left, right));

        let mut process_identities = snapshot.processes.keys().collect::<Vec<_>>();
        process_identities.sort_unstable_by(|left, right| compare_process_identity(left, right));

        // Reject invalid path encodings before writing any portion of the document.
        for identity in &process_identities {
            if let Some(path) = snapshot.processes[*identity].executable_path.as_deref() {
                serde_json::to_string(path).map_err(PublicOutputError::Serialization)?;
            }
        }
        for socket in &snapshot.sockets {
            if let Some(timer) = socket.timer {
                TimerDto::new(timer)?;
            }
        }

        Ok(Self {
            snapshot,
            labels,
            capture,
            scope,
            gap_indices,
            socket_indices,
            process_identities,
        })
    }
}

impl Serialize for SnapshotDto<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut document = serializer.serialize_struct("Snapshot", 10)?;
        document.serialize_field("schema", SNAPSHOT_SCHEMA)?;
        document.serialize_field("version", &SNAPSHOT_VERSION)?;
        document.serialize_field("capture", &self.capture)?;
        document.serialize_field("scope", &self.scope)?;
        document.serialize_field(
            "completeness",
            snapshot_completeness_name(self.snapshot.completeness),
        )?;
        document.serialize_field(
            "owner_completeness",
            owner_completeness_name(&self.snapshot.owner_completeness),
        )?;
        document.serialize_field(
            "evidence_gaps",
            &GapSequence {
                snapshot: self.snapshot,
                indices: &self.gap_indices,
            },
        )?;
        document.serialize_field(
            "omitted_evidence_gap_count",
            &self.snapshot.omitted_evidence_gap_count,
        )?;
        document.serialize_field(
            "sockets",
            &SocketSequence {
                snapshot: self.snapshot,
                labels: self.labels,
                indices: &self.socket_indices,
            },
        )?;
        document.serialize_field(
            "processes",
            &ProcessSequence {
                snapshot: self.snapshot,
                identities: &self.process_identities,
            },
        )?;
        document.end()
    }
}

struct GapSequence<'a> {
    snapshot: &'a NetworkSnapshot,
    indices: &'a [GapIndex],
}

impl Serialize for GapSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(
            self.indices
                .iter()
                .map(|index| EvidenceGapDto::from(&self.snapshot.evidence_gaps[index.gap_index])),
        )
    }
}

struct SocketSequence<'a> {
    snapshot: &'a NetworkSnapshot,
    labels: &'a LabelRegistry,
    indices: &'a [SocketIndex],
}

impl Serialize for SocketSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.indices.len()))?;
        for index in self.indices {
            let socket = &self.snapshot.sockets[index.source_index];
            let dto = SocketDto::from_index(socket, &index.owner_indices, self.labels)
                .map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&dto)?;
        }
        sequence.end()
    }
}

struct ProcessSequence<'a> {
    snapshot: &'a NetworkSnapshot,
    identities: &'a [&'a ProcessIdentity],
}

impl Serialize for ProcessSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(
            self.identities
                .iter()
                .map(|&&identity| process_dto(identity, &self.snapshot.processes[&identity])),
        )
    }
}

/// Write one pretty snapshot document followed by exactly one newline.
pub(crate) fn write_snapshot_json(
    writer: &mut impl Write,
    snapshot: &NetworkSnapshot,
    labels: &LabelRegistry,
) -> Result<(), PublicOutputError> {
    let document = SnapshotDto::new(snapshot, labels)?;
    serde_json::to_writer_pretty(&mut *writer, &document)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn process_dto(identity: ProcessIdentity, process: &ProcessObservation) -> ProcessDto<'_> {
    ProcessDto {
        identity: ProcessIdentityDto::from(identity),
        name: process.name.as_deref(),
        executable_path: process.executable_path.as_deref(),
        parent_pid: process.parent_pid,
        metadata_completeness: metadata_completeness_name(process.metadata_completeness),
    }
}

pub(crate) fn unix_milliseconds(time: SystemTime) -> Result<u64, PublicOutputError> {
    let milliseconds = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PublicOutputError::ClockUnavailable)?
        .as_millis();
    u64::try_from(milliseconds).map_err(|_| PublicOutputError::ClockUnavailable)
}

fn owner_completeness_parts(
    completeness: &OwnerCompleteness,
) -> Result<(&'static str, Vec<&'static str>), PublicOutputError> {
    match completeness {
        OwnerCompleteness::Complete => Ok(("complete", Vec::new())),
        OwnerCompleteness::Raced => Ok(("raced", vec!["observation_raced"])),
        OwnerCompleteness::Partial { reasons } => {
            let mut names = reasons
                .iter()
                .copied()
                .map(evidence_gap_code_name)
                .collect::<Vec<_>>();
            names.sort_unstable();
            names.dedup();
            if names.len() > OWNER_COMPLETENESS_REASONS_MAX {
                return Err(PublicOutputError::OwnerReasonLimitExceeded);
            }
            Ok(("partial", names))
        }
    }
}

fn compare_process_identity(left: &ProcessIdentity, right: &ProcessIdentity) -> Ordering {
    left.pid
        .cmp(&right.pid)
        .then_with(|| compare_process_marker(left.start_marker, right.start_marker))
}

fn compare_process_marker(left: ProcessStartMarker, right: ProcessStartMarker) -> Ordering {
    process_marker_key(left).cmp(&process_marker_key(right))
}

fn process_marker_key(marker: ProcessStartMarker) -> (u8, u64, u32) {
    match marker {
        ProcessStartMarker::LinuxStartTicks(value) => (0, value.get(), 0),
        ProcessStartMarker::MacOsStartTime(value) => (1, value.seconds(), value.microseconds()),
        ProcessStartMarker::WindowsCreationTime(value) => (2, value.get(), 0),
    }
}

fn compare_owner_observation(left: &OwnerObservation, right: &OwnerObservation) -> Ordering {
    owner_kind_key(left)
        .cmp(&owner_kind_key(right))
        .then_with(|| owner_pid(left).cmp(&owner_pid(right)))
        .then_with(|| match (left, right) {
            (OwnerObservation::Verified(left), OwnerObservation::Verified(right)) => {
                compare_process_marker(left.start_marker, right.start_marker)
            }
            _ => Ordering::Equal,
        })
        .then_with(|| owner_reason(left).cmp(owner_reason(right)))
}

fn owner_kind_key(owner: &OwnerObservation) -> u8 {
    match owner {
        OwnerObservation::Verified(_) => 0,
        OwnerObservation::UnverifiedPid { .. } => 1,
    }
}

fn owner_pid(owner: &OwnerObservation) -> u32 {
    match owner {
        OwnerObservation::Verified(identity) => identity.pid,
        OwnerObservation::UnverifiedPid { pid, .. } => *pid,
    }
}

fn owner_reason(owner: &OwnerObservation) -> &'static str {
    match owner {
        OwnerObservation::Verified(_) => "",
        OwnerObservation::UnverifiedPid { reason, .. } => unverified_owner_reason_name(*reason),
    }
}

fn compare_socket_token(
    left: Option<PlatformSocketToken>,
    right: Option<PlatformSocketToken>,
) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => socket_token_key(left).cmp(&socket_token_key(right)),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn socket_token_key(token: PlatformSocketToken) -> (u8, u64) {
    match token {
        PlatformSocketToken::LinuxInode(value) => (0, value.get()),
        PlatformSocketToken::MacOsSocketId(value) => (1, value.get()),
    }
}

fn compare_owner_indices(
    left_socket: &SocketObservation,
    left: &SocketIndex,
    right_socket: &SocketObservation,
    right: &SocketIndex,
) -> Ordering {
    left.owner_completeness_rank
        .cmp(&right.owner_completeness_rank)
        .then_with(|| left.owner_reasons.cmp(&right.owner_reasons))
        .then_with(|| left.omitted_owner_count.cmp(&right.omitted_owner_count))
        .then_with(|| {
            compare_owner_index_arrays(
                left_socket,
                &left.owner_indices,
                right_socket,
                &right.owner_indices,
            )
        })
}

fn compare_owner_index_arrays(
    left_socket: &SocketObservation,
    left: &[usize],
    right_socket: &SocketObservation,
    right: &[usize],
) -> Ordering {
    for (&left, &right) in left.iter().zip(right) {
        let ordering =
            compare_owner_observation(&left_socket.owners[left], &right_socket.owners[right]);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn compare_socket_index(
    snapshot: &NetworkSnapshot,
    left: &SocketIndex,
    right: &SocketIndex,
) -> Ordering {
    let left_socket = &snapshot.sockets[left.source_index];
    let right_socket = &snapshot.sockets[right.source_index];
    compare_endpoint_identity(&left_socket.local_endpoint, &right_socket.local_endpoint)
        .then_with(|| {
            left_socket
                .state
                .order_key()
                .cmp(&right_socket.state.order_key())
        })
        .then_with(|| compare_socket_token(left_socket.socket_token, right_socket.socket_token))
        .then_with(|| compare_owner_indices(left_socket, left, right_socket, right))
        .then_with(|| compare_timer(left_socket.timer, right_socket.timer))
}

fn compare_timer(
    left: Option<TcpTimerObservation>,
    right: Option<TcpTimerObservation>,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => timer_kind_key(left.kind)
            .cmp(&timer_kind_key(right.kind))
            .then_with(|| left.native_code.cmp(&right.native_code))
            .then_with(|| left.raw_ticks.cmp(&right.raw_ticks))
            .then_with(|| {
                left.estimated_remaining_milliseconds
                    .cmp(&right.estimated_remaining_milliseconds)
            }),
    }
}

const fn timer_kind_key(kind: TcpTimerKind) -> (u8, u32) {
    match kind {
        TcpTimerKind::None => (0, 0),
        TcpTimerKind::Retransmit => (1, 0),
        TcpTimerKind::Other => (2, 0),
        TcpTimerKind::TimeWait => (3, 0),
        TcpTimerKind::ZeroWindowProbe => (4, 0),
        TcpTimerKind::Unknown(code) => (5, code),
    }
}

fn compare_gap_index(snapshot: &NetworkSnapshot, left: &GapIndex, right: &GapIndex) -> Ordering {
    let left_gap = &snapshot.evidence_gaps[left.gap_index];
    let right_gap = &snapshot.evidence_gaps[right.gap_index];
    left_gap
        .impact
        .cmp(&right_gap.impact)
        .then_with(|| {
            evidence_gap_code_name(left_gap.code).cmp(evidence_gap_code_name(right_gap.code))
        })
        .then_with(|| match (&left_gap.endpoint, &right_gap.endpoint) {
            (Some(left), Some(right)) => compare_endpoint_identity(left, right),
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        })
        .then_with(|| left_gap.pid.cmp(&right_gap.pid))
        .then_with(|| {
            left_gap
                .affected_pid_count()
                .cmp(&right_gap.affected_pid_count())
        })
        .then_with(|| left.message.cmp(&right.message))
}

pub(crate) const fn socket_state_name(state: SocketState) -> &'static str {
    state.name()
}

pub(crate) const fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

const fn legacy_socket_state_name(state: LegacySocketState) -> &'static str {
    match state {
        LegacySocketState::Listen => "listen",
        LegacySocketState::Bound => "bound",
    }
}

const fn platform_name(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => "linux",
        Platform::Windows => "windows",
        Platform::Macos => "macos",
    }
}

const fn permission_name(permission: PermissionStatus) -> &'static str {
    match permission {
        PermissionStatus::Full => "full",
        PermissionStatus::Partial => "partial",
    }
}

const fn timer_kind_name(kind: TcpTimerKind) -> &'static str {
    match kind {
        TcpTimerKind::None => "none",
        TcpTimerKind::Retransmit => "retransmit",
        TcpTimerKind::Other => "other",
        TcpTimerKind::TimeWait => "time_wait",
        TcpTimerKind::ZeroWindowProbe => "zero_window_probe",
        TcpTimerKind::Unknown(_) => "unknown",
    }
}

const fn unverified_owner_reason_name(reason: UnverifiedOwnerReason) -> &'static str {
    match reason {
        UnverifiedOwnerReason::PermissionDenied => "owner_permission_denied",
        UnverifiedOwnerReason::Disappeared => "owner_disappeared",
        UnverifiedOwnerReason::IdentityUnavailable => "process_identity_unavailable",
        UnverifiedOwnerReason::Raced => "observation_raced",
    }
}

pub(crate) const fn evidence_gap_code_name(code: EvidenceGapCode) -> &'static str {
    code.name()
}

pub(crate) const fn evidence_code_name(code: EvidenceCode) -> &'static str {
    code.name()
}

pub(crate) const fn evidence_source_name(source: EvidenceSource) -> &'static str {
    source.name()
}

pub(crate) const fn certainty_name(certainty: Certainty) -> &'static str {
    certainty.name()
}

pub(crate) const fn evidence_impact_name(impact: EvidenceImpact) -> &'static str {
    match impact {
        EvidenceImpact::Metadata => "metadata",
        EvidenceImpact::Ownership => "ownership",
        EvidenceImpact::SocketSet => "socket_set",
        EvidenceImpact::Scope => "scope",
    }
}

pub(crate) const fn scope_kind_name(kind: ObservationScopeKind) -> &'static str {
    match kind {
        ObservationScopeKind::CurrentNetworkNamespace => "current_network_namespace",
        ObservationScopeKind::CurrentHostProcessVisibleSockets => {
            "current_host_process_visible_sockets"
        }
        ObservationScopeKind::CurrentHostNetworkStack => "current_host_network_stack",
    }
}

pub(crate) const fn scope_limitation_name(limitation: ScopeLimitation) -> &'static str {
    match limitation {
        ScopeLimitation::OtherNetworkNamespacesExcluded => "other_network_namespaces_excluded",
        ScopeLimitation::ProcessFirstSocketVisibilityLimited => {
            "process_first_socket_visibility_limited"
        }
        ScopeLimitation::WslNetworkStackExcluded => "wsl_network_stack_excluded",
        ScopeLimitation::ProcessMetadataPermissionLimited => "process_metadata_permission_limited",
        ScopeLimitation::Ipv6ScopeUnavailable => "ipv6_scope_unavailable",
        ScopeLimitation::ScopedIpv6ExactMatchingUnavailable => {
            "scoped_ipv6_exact_matching_unavailable"
        }
        ScopeLimitation::NativeFieldUnavailable => "native_field_unavailable",
        ScopeLimitation::PollingIntervalBlindSpot => "polling_interval_blind_spot",
    }
}

pub(crate) const fn snapshot_completeness_name(completeness: SnapshotCompleteness) -> &'static str {
    match completeness {
        SnapshotCompleteness::Complete => "complete",
        SnapshotCompleteness::Partial => "partial",
        SnapshotCompleteness::Raced => "raced",
    }
}

pub(crate) const fn owner_completeness_name(completeness: &OwnerCompleteness) -> &'static str {
    match completeness {
        OwnerCompleteness::Complete => "complete",
        OwnerCompleteness::Partial { .. } => "partial",
        OwnerCompleteness::Raced => "raced",
    }
}

const fn metadata_completeness_name(completeness: MetadataCompleteness) -> &'static str {
    match completeness {
        MetadataCompleteness::Complete => "complete",
        MetadataCompleteness::Partial => "partial",
    }
}

#[cfg(test)]
mod tests;
