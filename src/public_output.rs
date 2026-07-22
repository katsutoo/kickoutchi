//! Shared, deterministic serialization for public structured output.
//!
//! DTOs in this module borrow domain records. Snapshot rendering allocates only
//! bounded sorting indexes, owner references, and sanitized public strings; it
//! never clones the snapshot or retains the rendered document.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::fmt;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};

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
    compare_endpoint_identity,
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
        row.serialize_field("child_pids", &[] as &[u32])?;
        row.serialize_field("protected", &self.view.protected)?;
        row.serialize_field("platform", platform_name(self.view.platform))?;
        row.serialize_field("permission", permission_name(self.view.permission))?;
        row.serialize_field("label", &self.view.label)?;
        row.end()
    }
}

#[derive(Debug)]
pub(crate) enum PublicOutputError {
    Io(io::Error),
    Serialization(serde_json::Error),
    ClockUnavailable,
    InvalidWallClockInterval,
    CountOutOfRange,
    OwnerReasonLimitExceeded,
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

impl fmt::Display for PublicOutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Serialization(error) => error.fmt(formatter),
            Self::ClockUnavailable => formatter.write_str("wall clock is unavailable"),
            Self::InvalidWallClockInterval => {
                formatter.write_str("capture completion precedes capture start")
            }
            Self::CountOutOfRange => formatter.write_str("public count exceeds the u64 domain"),
            Self::OwnerReasonLimitExceeded => {
                formatter.write_str("owner completeness reason limit exceeded")
            }
            Self::InvalidTimer => formatter.write_str("invalid native timer state"),
        }
    }
}

impl std::error::Error for PublicOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::ClockUnavailable
            | Self::InvalidWallClockInterval
            | Self::CountOutOfRange
            | Self::OwnerReasonLimitExceeded
            | Self::InvalidTimer => None,
        }
    }
}

impl From<io::Error> for PublicOutputError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PublicOutputError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
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
    message: Cow<'a, str>,
}

impl<'a> From<&'a EvidenceGap> for EvidenceGapDto<'a> {
    fn from(gap: &'a EvidenceGap) -> Self {
        Self {
            code: evidence_gap_code_name(gap.code),
            impact: evidence_impact_name(gap.impact),
            endpoint: gap.endpoint.as_ref().map(EndpointDto::from),
            pid: gap.pid,
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
#[allow(
    dead_code,
    reason = "shared by public verdict and watch envelopes when they adopt this layer"
)]
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
    owner_completeness: &'static str,
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
        let (owner_completeness, owner_reasons) =
            owner_completeness_parts(&socket.owner_completeness)?;
        let omitted_owner_count =
            u64::try_from(socket.owners.len().saturating_sub(owner_indices.len()))
                .map_err(|_| PublicOutputError::CountOutOfRange)?;
        Ok(Self {
            source_index,
            owner_indices,
            owner_completeness,
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
        let mut sequence = serializer.serialize_seq(Some(self.indices.len()))?;
        for index in self.indices {
            sequence.serialize_element(&EvidenceGapDto::from(
                &self.snapshot.evidence_gaps[index.gap_index],
            ))?;
        }
        sequence.end()
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
        let mut sequence = serializer.serialize_seq(Some(self.identities.len()))?;
        for &&identity in self.identities {
            sequence
                .serialize_element(&process_dto(identity, &self.snapshot.processes[&identity]))?;
        }
        sequence.end()
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

pub(crate) fn compare_process_identity(
    left: &ProcessIdentity,
    right: &ProcessIdentity,
) -> Ordering {
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

pub(crate) fn compare_owner_observation(
    left: &OwnerObservation,
    right: &OwnerObservation,
) -> Ordering {
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

pub(crate) fn compare_socket_token(
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
    owner_completeness_order(left.owner_completeness)
        .cmp(&owner_completeness_order(right.owner_completeness))
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
        .then_with(|| left.message.cmp(&right.message))
}

#[allow(
    dead_code,
    reason = "shared by public verdict and watch envelopes when they adopt this layer"
)]
pub(crate) fn compare_evidence(left: &EvidenceDto<'_>, right: &EvidenceDto<'_>) -> Ordering {
    evidence_source_order(left.source)
        .cmp(&evidence_source_order(right.source))
        .then_with(|| left.code.cmp(right.code))
        .then_with(|| certainty_order(left.certainty).cmp(&certainty_order(right.certainty)))
        .then_with(|| left.message.cmp(&right.message))
}

pub(crate) const fn socket_state_name(state: SocketState) -> &'static str {
    match state {
        SocketState::Closed => "closed",
        SocketState::Listen => "listen",
        SocketState::SynSent => "syn_sent",
        SocketState::SynReceived => "syn_received",
        SocketState::Established => "established",
        SocketState::FinWait1 => "fin_wait1",
        SocketState::FinWait2 => "fin_wait2",
        SocketState::CloseWait => "close_wait",
        SocketState::Closing => "closing",
        SocketState::LastAck => "last_ack",
        SocketState::TimeWait => "time_wait",
        SocketState::DeleteTcb => "delete_tcb",
        SocketState::NewSynReceived => "new_syn_received",
        SocketState::Bound => "bound",
        SocketState::Unknown(_) => "unknown",
    }
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

pub(crate) const fn timer_kind_name(kind: TcpTimerKind) -> &'static str {
    match kind {
        TcpTimerKind::None => "none",
        TcpTimerKind::Retransmit => "retransmit",
        TcpTimerKind::Other => "other",
        TcpTimerKind::TimeWait => "time_wait",
        TcpTimerKind::ZeroWindowProbe => "zero_window_probe",
        TcpTimerKind::Unknown(_) => "unknown",
    }
}

pub(crate) const fn unverified_owner_reason_name(reason: UnverifiedOwnerReason) -> &'static str {
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

#[allow(
    dead_code,
    reason = "shared by public verdict and watch envelopes when they adopt this layer"
)]
pub(crate) const fn evidence_code_name(code: EvidenceCode) -> &'static str {
    code.name()
}

#[allow(
    dead_code,
    reason = "shared by public verdict and watch envelopes when they adopt this layer"
)]
pub(crate) const fn evidence_source_name(source: EvidenceSource) -> &'static str {
    source.name()
}

#[allow(
    dead_code,
    reason = "shared by public verdict and watch envelopes when they adopt this layer"
)]
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

pub(crate) const fn metadata_completeness_name(completeness: MetadataCompleteness) -> &'static str {
    match completeness {
        MetadataCompleteness::Complete => "complete",
        MetadataCompleteness::Partial => "partial",
    }
}

fn owner_completeness_order(name: &str) -> u8 {
    match name {
        "complete" => 0,
        "partial" => 1,
        "raced" => 2,
        _ => unreachable!("owner completeness names are closed"),
    }
}

#[allow(dead_code, reason = "supports the reusable public evidence comparator")]
fn evidence_source_order(name: &str) -> u8 {
    match name {
        "linux_procfs" => 0,
        "macos_libproc" => 1,
        "macos_sysctl" => 2,
        "windows_ip_helper" => 3,
        "windows_process_api" => 4,
        "bind_probe" => 5,
        "docker" => 6,
        "analysis" => 7,
        _ => unreachable!("evidence source names are closed"),
    }
}

#[allow(dead_code, reason = "supports the reusable public evidence comparator")]
fn certainty_order(name: &str) -> u8 {
    match name {
        "proven" => 0,
        "estimated" => 1,
        "heuristic" => 2,
        "unknown" => 3,
        _ => unreachable!("certainty names are closed"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::num::{NonZeroU32, NonZeroU64};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::labels::{LabelInput, LabelRegistry};
    use crate::observation::{MetadataOmission, ObservationScope};

    fn identity(pid: u32, marker: u64) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            start_marker: ProcessStartMarker::linux(marker).expect("nonzero fixture marker"),
        }
    }

    fn endpoint(port: u32) -> EndpointIdentity {
        EndpointIdentity::new(Protocol::Tcp, IpAddr::V4(Ipv4Addr::LOCALHOST), port, None)
            .expect("valid fixture endpoint")
    }

    fn socket(port: u32, owners: Vec<OwnerObservation>) -> SocketObservation {
        SocketObservation {
            local_endpoint: endpoint(port),
            state: SocketState::Listen,
            timer: None,
            owners,
            owner_completeness: OwnerCompleteness::Complete,
            socket_token: None,
        }
    }

    fn process(name: &str) -> ProcessObservation {
        ProcessObservation {
            name: Some(Arc::from(name)),
            executable_path: Some(std::path::PathBuf::from("/bin/worker").into()),
            command_line: Some(Arc::from("COMMAND_LINE_SENTINEL_7f2a")),
            parent_pid: Some(1),
            parent_process_name: Some(Arc::from("PARENT_NAME_SENTINEL_7f2a")),
            metadata_omission: Some(MetadataOmission::BudgetExceeded),
            metadata_completeness: MetadataCompleteness::Partial,
        }
    }

    fn snapshot(sockets: Vec<SocketObservation>) -> NetworkSnapshot {
        let mut processes = HashMap::new();
        for socket in &sockets {
            for owner in &socket.owners {
                if let OwnerObservation::Verified(identity) = owner {
                    processes.insert(*identity, process(&format!("worker-{}", identity.pid)));
                }
            }
        }
        NetworkSnapshot {
            capture_started_at: UNIX_EPOCH + Duration::from_secs(10),
            capture_completed_at: UNIX_EPOCH + Duration::from_secs(11),
            scope: ObservationScope::new(
                ObservationScopeKind::CurrentNetworkNamespace,
                Some("net:[42]"),
                [],
            )
            .expect("valid fixture scope"),
            completeness: SnapshotCompleteness::Complete,
            owner_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
            sockets,
            processes,
        }
    }

    fn render(snapshot: &NetworkSnapshot, labels: &LabelRegistry) -> serde_json::Value {
        let mut output = Vec::new();
        write_snapshot_json(&mut output, snapshot, labels).expect("snapshot serializes");
        assert_eq!(output.last(), Some(&b'\n'));
        assert_ne!(output.get(output.len().saturating_sub(2)), Some(&b'\n'));
        serde_json::from_slice(&output).expect("valid JSON")
    }

    #[test]
    fn snapshot_schema_omits_private_process_fields() {
        let identity = identity(7, 70);
        let value = render(
            &snapshot(vec![socket(
                3000,
                vec![OwnerObservation::Verified(identity)],
            )]),
            &LabelRegistry::default(),
        );
        assert_eq!(value["schema"], "kickoutchi.snapshot");
        assert_eq!(value["version"], 1);
        let process = &value["processes"][0];
        assert!(process.get("command_line").is_none());
        assert!(process.get("parent_process_name").is_none());
        assert!(process.get("metadata_omission").is_none());
        assert_eq!(process["metadata_completeness"], "partial");
        let rendered = serde_json::to_string(&value).expect("parsed value serializes");
        assert!(!rendered.contains("COMMAND_LINE_SENTINEL_7f2a"));
        assert!(!rendered.contains("PARENT_NAME_SENTINEL_7f2a"));
        assert!(!rendered.contains("budget_exceeded"));
    }

    #[test]
    fn canonical_sorting_ignores_input_and_hash_map_order_and_puts_null_tokens_last() {
        let first = identity(2, 20);
        let second = identity(9, 90);
        let mut high = socket(
            9000,
            vec![
                OwnerObservation::UnverifiedPid {
                    pid: 1,
                    reason: UnverifiedOwnerReason::PermissionDenied,
                },
                OwnerObservation::Verified(second),
                OwnerObservation::Verified(first),
            ],
        );
        high.socket_token = None;
        let mut token_high = socket(3000, Vec::new());
        token_high.socket_token = Some(PlatformSocketToken::MacOsSocketId(
            NonZeroU64::new(1).expect("nonzero token"),
        ));
        let mut token_low = socket(3000, Vec::new());
        token_low.socket_token = Some(PlatformSocketToken::LinuxInode(
            NonZeroU64::new(9).expect("nonzero token"),
        ));
        let null = socket(3000, Vec::new());
        let value = render(
            &snapshot(vec![high, null, token_high, token_low]),
            &LabelRegistry::default(),
        );

        assert_eq!(value["sockets"][0]["socket_token"]["kind"], "linux_inode");
        assert_eq!(value["sockets"][0]["socket_token"]["value"], 9);
        assert_eq!(
            value["sockets"][1]["socket_token"]["kind"],
            "macos_socket_id"
        );
        assert!(value["sockets"][2]["socket_token"].is_null());
        assert_eq!(value["sockets"][3]["endpoint"]["port"], 9000);
        assert_eq!(
            value["sockets"][3]["owners"]["owners"][0]["identity"]["pid"],
            2
        );
        assert_eq!(
            value["sockets"][3]["owners"]["owners"][0]["kind"],
            "verified"
        );
        assert_eq!(value["processes"][0]["identity"]["pid"], 2);
        assert_eq!(value["processes"][1]["identity"]["pid"], 9);
    }

    #[test]
    fn gaps_sort_by_public_key_after_sanitization() {
        let mut snapshot = snapshot(Vec::new());
        snapshot.evidence_gaps = vec![
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ScopeExcluded,
                None,
                Some(9),
                "z",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                Some(endpoint(9)),
                None,
                "specific",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                None,
                None,
                "global\nmessage",
            ),
        ];
        let value = render(&snapshot, &LabelRegistry::default());
        assert_eq!(
            value["evidence_gaps"][0]["endpoint"],
            serde_json::Value::Null
        );
        assert_eq!(value["evidence_gaps"][0]["message"], "global message");
        assert_eq!(value["evidence_gaps"][1]["endpoint"]["port"], 9);
        assert_eq!(value["evidence_gaps"][2]["impact"], "metadata");
    }

    #[test]
    fn gap_order_uses_code_endpoint_pid_and_sanitized_message_ties() {
        let endpoint = endpoint(3000);
        let mut snapshot = snapshot(Vec::new());
        snapshot.evidence_gaps = vec![
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                Some(endpoint.clone()),
                Some(2),
                "\tZ",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::NativeFieldUnavailable,
                None,
                None,
                "first code",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                Some(endpoint.clone()),
                Some(2),
                "\nA",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                Some(endpoint),
                Some(1),
                "lower pid",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ScopeExcluded,
                None,
                None,
                "global",
            ),
        ];

        let value = render(&snapshot, &LabelRegistry::default());
        let gaps = value["evidence_gaps"].as_array().expect("gap array");
        assert_eq!(gaps[0]["code"], "native_field_unavailable");
        assert!(gaps[1]["endpoint"].is_null());
        assert_eq!(gaps[2]["pid"], 1);
        assert_eq!(gaps[3]["message"], " A");
        assert_eq!(gaps[4]["message"], " Z");
    }

    #[test]
    fn validated_labels_are_attached_without_filtering() {
        let labels = LabelRegistry::from_inputs(vec![LabelInput {
            protocol: "tcp".to_owned(),
            address: "127.0.0.1".to_owned(),
            port: 3000,
            scope_id: None,
            label: "web dev".to_owned(),
        }])
        .expect("valid label");
        let value = render(
            &snapshot(vec![socket(4000, Vec::new()), socket(3000, Vec::new())]),
            &labels,
        );
        assert_eq!(value["sockets"].as_array().map(Vec::len), Some(2));
        assert_eq!(value["sockets"][0]["label"], "web dev");
        assert!(value["sockets"][1]["label"].is_null());
    }

    #[test]
    fn owner_output_is_capped_truthfully_and_race_reason_is_explicit() {
        let owners = (1..=SERIALIZED_OWNERS_MAX + 3)
            .rev()
            .map(|pid| {
                OwnerObservation::Verified(identity(
                    u32::try_from(pid).expect("fixture PID"),
                    u64::try_from(pid + 100).expect("fixture marker"),
                ))
            })
            .collect::<Vec<_>>();
        let mut socket = socket(3000, owners);
        socket.owner_completeness = OwnerCompleteness::Raced;
        let value = render(&snapshot(vec![socket]), &LabelRegistry::default());
        let owners = &value["sockets"][0]["owners"];
        assert_eq!(owners["owners"].as_array().map(Vec::len), Some(64));
        assert_eq!(owners["omitted_owner_count"], 3);
        assert_eq!(owners["completeness"], "raced");
        assert_eq!(owners["reasons"], serde_json::json!(["observation_raced"]));
    }

    #[test]
    fn owner_count_boundaries_are_exact() {
        for (count, retained, omitted) in [(0, 0, 0), (1, 1, 0), (64, 64, 0), (65, 64, 1)] {
            let owners = (1..=count)
                .map(|pid| {
                    OwnerObservation::Verified(identity(
                        u32::try_from(pid).expect("fixture PID"),
                        u64::try_from(pid + 100).expect("fixture marker"),
                    ))
                })
                .collect::<Vec<_>>();
            let value = render(
                &snapshot(vec![socket(3000, owners)]),
                &LabelRegistry::default(),
            );
            let owner_set = &value["sockets"][0]["owners"];
            assert_eq!(owner_set["owners"].as_array().map(Vec::len), Some(retained));
            assert_eq!(owner_set["omitted_owner_count"], omitted);
        }
    }

    #[test]
    fn reversed_snapshot_inputs_produce_identical_canonical_documents() {
        let owner = identity(42, 420);
        let mut first = socket(4000, vec![OwnerObservation::Verified(owner)]);
        first.state = SocketState::Established;
        first.socket_token = Some(PlatformSocketToken::LinuxInode(
            NonZeroU64::new(8).expect("nonzero token"),
        ));
        let mut second = socket(3000, Vec::new());
        second.owner_completeness = OwnerCompleteness::Partial {
            reasons: vec![
                EvidenceGapCode::OwnerPermissionDenied,
                EvidenceGapCode::OwnerDisappeared,
            ],
        };

        let mut left = snapshot(vec![first.clone(), second.clone()]);
        left.evidence_gaps = vec![
            EvidenceGap::new(
                EvidenceImpact::Metadata,
                EvidenceGapCode::ProcessMetadataUnavailable,
                None,
                Some(42),
                "z",
            ),
            EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::NativeFieldUnavailable,
                None,
                None,
                "a",
            ),
        ];
        let mut right = snapshot(vec![second, first]);
        right.evidence_gaps = left.evidence_gaps.iter().rev().cloned().collect();

        let mut left_output = Vec::new();
        let mut right_output = Vec::new();
        write_snapshot_json(&mut left_output, &left, &LabelRegistry::default())
            .expect("left snapshot serializes");
        write_snapshot_json(&mut right_output, &right, &LabelRegistry::default())
            .expect("right snapshot serializes");
        assert_eq!(left_output, right_output);
    }

    #[test]
    fn socket_order_uses_state_token_owner_and_timer_tie_breakers() {
        let mut established = socket(3000, Vec::new());
        established.state = SocketState::Established;
        let listen = socket(3000, Vec::new());
        let value = render(
            &snapshot(vec![established, listen]),
            &LabelRegistry::default(),
        );
        assert_eq!(value["sockets"][0]["state"]["kind"], "listen");
        assert_eq!(value["sockets"][1]["state"]["kind"], "established");

        let mut no_token = socket(3000, Vec::new());
        no_token.socket_token = None;
        let mut macos_token = socket(3000, Vec::new());
        macos_token.socket_token = PlatformSocketToken::macos_socket_id(1);
        let mut linux_token = socket(3000, Vec::new());
        linux_token.socket_token = PlatformSocketToken::linux_inode(1);
        let value = render(
            &snapshot(vec![no_token, macos_token, linux_token]),
            &LabelRegistry::default(),
        );
        assert_eq!(value["sockets"][0]["socket_token"]["kind"], "linux_inode");
        assert_eq!(
            value["sockets"][1]["socket_token"]["kind"],
            "macos_socket_id"
        );
        assert!(value["sockets"][2]["socket_token"].is_null());

        let complete = socket(3000, Vec::new());
        let mut partial = socket(3000, Vec::new());
        partial.owner_completeness = OwnerCompleteness::Partial {
            reasons: vec![EvidenceGapCode::OwnerPermissionDenied],
        };
        let mut raced = socket(3000, Vec::new());
        raced.owner_completeness = OwnerCompleteness::Raced;
        let value = render(
            &snapshot(vec![raced, partial, complete]),
            &LabelRegistry::default(),
        );
        assert_eq!(value["sockets"][0]["owners"]["completeness"], "complete");
        assert_eq!(value["sockets"][1]["owners"]["completeness"], "partial");
        assert_eq!(value["sockets"][2]["owners"]["completeness"], "raced");

        let no_timer = socket(3000, Vec::new());
        let mut idle_timer = socket(3000, Vec::new());
        idle_timer.timer = Some(TcpTimerObservation::from_linux_native(0, 2, Some(100)));
        let mut retransmit_high = socket(3000, Vec::new());
        retransmit_high.timer = Some(TcpTimerObservation::from_linux_native(1, 2, Some(100)));
        let mut retransmit_low = socket(3000, Vec::new());
        retransmit_low.timer = Some(TcpTimerObservation::from_linux_native(1, 1, Some(100)));
        let value = render(
            &snapshot(vec![retransmit_high, retransmit_low, idle_timer, no_timer]),
            &LabelRegistry::default(),
        );
        assert!(value["sockets"][0]["timer"].is_null());
        assert_eq!(value["sockets"][1]["timer"]["kind"], "none");
        assert_eq!(value["sockets"][2]["timer"]["kind"], "retransmit");
        assert_eq!(value["sockets"][2]["timer"]["raw_ticks"], 1);
        assert_eq!(value["sockets"][3]["timer"]["raw_ticks"], 2);
    }

    #[test]
    fn invalid_timer_fails_before_writing() {
        let mut socket = socket(3000, Vec::new());
        socket.timer = Some(TcpTimerObservation {
            kind: TcpTimerKind::Retransmit,
            native_code: Some(1),
            raw_ticks: 1,
            estimated_remaining_milliseconds: Some(10),
        });
        let snapshot = snapshot(vec![socket]);
        let mut output = Vec::new();
        assert!(matches!(
            write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
            Err(PublicOutputError::InvalidTimer),
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn owner_reason_limit_fails_before_writing() {
        let mut socket = socket(3000, Vec::new());
        socket.owner_completeness = OwnerCompleteness::Partial {
            reasons: vec![
                EvidenceGapCode::OwnerPermissionDenied,
                EvidenceGapCode::OwnerAttributionIncomplete,
                EvidenceGapCode::OwnerDisappeared,
                EvidenceGapCode::ProcessIdentityUnavailable,
                EvidenceGapCode::ProcessMetadataUnavailable,
                EvidenceGapCode::NativeFieldUnavailable,
                EvidenceGapCode::ScopeExcluded,
                EvidenceGapCode::NoncriticalEvidenceTruncated,
                EvidenceGapCode::ObservationRaced,
            ],
        };
        let snapshot = snapshot(vec![socket]);
        let mut output = Vec::new();
        assert!(matches!(
            write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
            Err(PublicOutputError::OwnerReasonLimitExceeded),
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn timestamps_reject_pre_epoch_and_reversed_intervals() {
        assert!(matches!(
            CaptureDto::new(UNIX_EPOCH - Duration::from_millis(1), UNIX_EPOCH),
            Err(PublicOutputError::ClockUnavailable)
        ));
        assert!(matches!(
            CaptureDto::new(
                UNIX_EPOCH + Duration::from_secs(2),
                UNIX_EPOCH + Duration::from_secs(1)
            ),
            Err(PublicOutputError::InvalidWallClockInterval)
        ));
    }

    #[test]
    fn invalid_capture_fails_before_writing() {
        let mut reversed = snapshot(Vec::new());
        reversed.capture_started_at = UNIX_EPOCH + Duration::from_secs(2);
        reversed.capture_completed_at = UNIX_EPOCH + Duration::from_secs(1);
        let mut output = Vec::new();
        assert!(matches!(
            write_snapshot_json(&mut output, &reversed, &LabelRegistry::default()),
            Err(PublicOutputError::InvalidWallClockInterval),
        ));
        assert!(output.is_empty());

        let mut pre_epoch = snapshot(Vec::new());
        pre_epoch.capture_started_at = UNIX_EPOCH - Duration::from_millis(1);
        pre_epoch.capture_completed_at = UNIX_EPOCH;
        assert!(matches!(
            write_snapshot_json(&mut output, &pre_epoch, &LabelRegistry::default()),
            Err(PublicOutputError::ClockUnavailable),
        ));
        assert!(output.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_process_path_fails_before_writing() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let identity = identity(7, 70);
        let mut process = process("worker");
        process.executable_path =
            Some(std::path::PathBuf::from(OsString::from_vec(vec![0xff])).into());
        let mut snapshot = snapshot(Vec::new());
        snapshot.processes.insert(identity, process);
        let mut output = Vec::new();
        assert!(matches!(
            write_snapshot_json(&mut output, &snapshot, &LabelRegistry::default()),
            Err(PublicOutputError::Serialization(_)),
        ));
        assert!(output.is_empty());
    }

    #[test]
    fn timer_shape_has_fixed_certainty_and_native_unknown_code() {
        let mut socket = socket(3000, Vec::new());
        socket.timer = Some(TcpTimerObservation::from_linux_native(99, 17, Some(100)));
        let value = render(&snapshot(vec![socket]), &LabelRegistry::default());
        let timer = &value["sockets"][0]["timer"];
        assert_eq!(timer["kind"], "unknown");
        assert_eq!(timer["native_code"], 99);
        assert_eq!(timer["raw_ticks"], 17);
        assert_eq!(timer["estimated_remaining_milliseconds"], 170);
        assert_eq!(timer["certainty"], "estimated");
    }

    fn tagged_variant_snapshot() -> NetworkSnapshot {
        let linux = identity(7, 70);
        let macos = ProcessIdentity {
            pid: 7,
            start_marker: ProcessStartMarker::macos(8, 9).expect("valid macOS marker"),
        };
        let windows = ProcessIdentity {
            pid: 7,
            start_marker: ProcessStartMarker::windows(10).expect("valid Windows marker"),
        };
        let mut snapshot = snapshot(Vec::new());
        snapshot.processes.insert(windows, process("windows"));
        snapshot.processes.insert(macos, process("macos"));
        snapshot.processes.insert(linux, process("linux"));

        let scoped_endpoint = |scope| {
            EndpointIdentity::new(
                Protocol::Tcp,
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                3000,
                Some(scope),
            )
            .expect("valid IPv6 fixture")
        };
        snapshot.sockets = vec![
            SocketObservation {
                local_endpoint: endpoint(3000),
                state: SocketState::Unknown(77),
                timer: None,
                owners: vec![OwnerObservation::UnverifiedPid {
                    pid: 99,
                    reason: UnverifiedOwnerReason::PermissionDenied,
                }],
                owner_completeness: OwnerCompleteness::Partial {
                    reasons: vec![EvidenceGapCode::OwnerPermissionDenied],
                },
                socket_token: Some(PlatformSocketToken::MacOsSocketId(
                    NonZeroU64::new(11).expect("nonzero token"),
                )),
            },
            SocketObservation {
                local_endpoint: scoped_endpoint(Ipv6Scope::Unavailable),
                state: SocketState::Listen,
                timer: None,
                owners: Vec::new(),
                owner_completeness: OwnerCompleteness::Complete,
                socket_token: None,
            },
            SocketObservation {
                local_endpoint: scoped_endpoint(Ipv6Scope::InterfaceIndex(
                    NonZeroU32::new(3).expect("nonzero scope"),
                )),
                state: SocketState::Listen,
                timer: None,
                owners: Vec::new(),
                owner_completeness: OwnerCompleteness::Complete,
                socket_token: None,
            },
            SocketObservation {
                local_endpoint: scoped_endpoint(Ipv6Scope::Unscoped),
                state: SocketState::Listen,
                timer: None,
                owners: Vec::new(),
                owner_completeness: OwnerCompleteness::Complete,
                socket_token: None,
            },
        ];
        snapshot
    }

    #[test]
    fn tagged_platform_and_scope_variants_have_exact_shapes() {
        let value = render(&tagged_variant_snapshot(), &LabelRegistry::default());
        assert_eq!(
            value["processes"][0]["identity"]["start_marker"],
            serde_json::json!({"kind": "linux_start_ticks", "ticks": 70}),
        );
        assert_eq!(
            value["processes"][1]["identity"]["start_marker"],
            serde_json::json!({"kind": "macos_start_time", "seconds": 8, "microseconds": 9}),
        );
        assert_eq!(
            value["processes"][2]["identity"]["start_marker"],
            serde_json::json!({"kind": "windows_creation_time", "filetime_ticks": 10}),
        );
        let sockets = value["sockets"].as_array().expect("socket array");
        assert!(sockets[0]["endpoint"]["ipv6_scope"].is_null());
        assert_eq!(
            sockets[0]["state"],
            serde_json::json!({"kind": "unknown", "native_code": 77})
        );
        assert_eq!(
            sockets[0]["owners"]["owners"][0],
            serde_json::json!({
                "kind": "unverified_pid",
                "pid": 99,
                "reason": "owner_permission_denied"
            }),
        );
        assert_eq!(
            sockets[0]["socket_token"],
            serde_json::json!({"kind": "macos_socket_id", "value": 11}),
        );
        assert_eq!(
            sockets[1]["endpoint"]["ipv6_scope"],
            serde_json::json!({"kind": "unscoped", "interface_index": null}),
        );
        assert_eq!(
            sockets[1]["state"],
            serde_json::json!({"kind": "listen", "native_code": null}),
        );
        assert_eq!(
            sockets[2]["endpoint"]["ipv6_scope"],
            serde_json::json!({"kind": "interface_index", "interface_index": 3}),
        );
        assert_eq!(
            sockets[3]["endpoint"]["ipv6_scope"],
            serde_json::json!({"kind": "unavailable", "interface_index": null}),
        );
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes: usize,
        writes: usize,
        largest_write: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("fixture count overflow"))?;
            self.writes += 1;
            self.largest_write = self.largest_write.max(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn large_snapshot_is_written_incrementally() {
        const SOCKETS: usize = 8_192;
        let sockets = (0..SOCKETS)
            .map(|offset| {
                let port = u32::try_from(offset % usize::from(u16::MAX) + 1).expect("fixture port");
                socket(port, Vec::new())
            })
            .collect();
        let snapshot = snapshot(sockets);
        let mut writer = CountingWriter::default();
        write_snapshot_json(&mut writer, &snapshot, &LabelRegistry::default())
            .expect("large snapshot streams");
        assert!(writer.writes > SOCKETS);
        assert!(writer.largest_write < writer.bytes / SOCKETS);
    }

    #[test]
    fn serde_writer_failure_preserves_io_kind() {
        struct FailedWriter;
        impl Write for FailedWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let error = write_snapshot_json(
            &mut FailedWriter,
            &snapshot(Vec::new()),
            &LabelRegistry::default(),
        )
        .expect_err("writer fails");
        assert_eq!(error.io_error_kind(), Some(io::ErrorKind::BrokenPipe));
    }
}
