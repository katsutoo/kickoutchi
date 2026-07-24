//! The collector contract, plus the fake data we lean on for tests.
//!
//! The trait pins down what every platform collector has to provide. The CLI and
//! TUI talk to that contract, so adding or swapping collectors never ripples out
//! into the output layer.

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(any(test, target_os = "linux"))]
use std::path::PathBuf;
use std::time::SystemTime;

use thiserror::Error;

use crate::model::{PortEntry, Protocol};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::observation::process_read_metadata_bytes;
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
use crate::observation::{
    EndpointIdentity, EvidenceGap, Ipv6Scope, MetadataCompleteness, ProcessIdentity,
    ProcessObservation, ProcessStartMarker, SocketObservation,
};
use crate::observation::{
    EvidenceGapCode, EvidenceImpact, MetadataProfile, NativeObservationPass, NetworkSnapshot,
    ObservationError, ObservationScope, ObservationSource, OwnerCompleteness, ProcessRead,
    SnapshotCompleteness, SocketState as ObservationSocketState, collect_consistent,
    project_legacy, project_legacy_target,
};

/// What went wrong during a collection pass.
#[derive(Debug, Error)]
pub(crate) enum CollectorError {
    /// We couldn't read a path we genuinely need. This is for the must-have
    /// paths only — one process being cagey about its metadata isn't fatal, it
    /// just becomes a partial row.
    #[cfg(target_os = "linux")]
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// A platform API failed without a filesystem path to name.
    #[cfg(any(target_os = "macos", windows))]
    #[error("{operation} failed: {detail}")]
    Platform {
        operation: &'static str,
        detail: String,
    },
    /// A background TUI refresh worker disappeared before sending its result.
    #[error("refresh worker exited before returning a snapshot")]
    WorkerExited,
    #[error(transparent)]
    Observation(#[from] ObservationError),
    #[error("permission denied while verifying complete endpoint ownership")]
    OwnershipPermissionDenied,
}

/// Anything that can hand us a snapshot of the open ports.
///
/// Every call returns a full snapshot — no incremental updates, on purpose. A
/// whole snapshot is trivially self-consistent, and we refresh at human speed
/// (seconds, not microseconds), so the extra complexity would buy us nothing.
pub(crate) trait Collector {
    /// Grab one bounded, consistency-checked observation.
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError>;
}

/// Collect the authoritative snapshot for the selected metadata profile.
pub(crate) fn collect_snapshot(
    profile: MetadataProfile,
) -> Result<NetworkSnapshot, CollectorError> {
    #[cfg(target_os = "linux")]
    {
        <crate::platform::linux::LinuxCollector as Collector>::collect(
            &crate::platform::linux::LinuxCollector::new(),
            profile,
        )
    }

    #[cfg(windows)]
    {
        <crate::platform::windows::WindowsCollector as Collector>::collect(
            &crate::platform::windows::WindowsCollector,
            profile,
        )
    }

    #[cfg(target_os = "macos")]
    {
        <crate::platform::macos::MacosCollector as Collector>::collect(
            &crate::platform::macos::MacosCollector,
            profile,
        )
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        FakeCollector.collect(profile)
    }
}

/// Collect one snapshot and hand back owned legacy rows that outlive it.
///
/// The owned projection exists because this function drops the snapshot it
/// collected from: the TUI stores these rows across frames, and the kill and
/// scoped-kill seams re-collect through closures that must return something
/// after their snapshot goes away. Callers that hold a live snapshot should
/// project `PortEntryView` from it instead of coming through here.
pub(crate) fn collect_ports() -> Result<Vec<PortEntry>, CollectorError> {
    collect_ports_with_profile(MetadataProfile::LegacyList)
}

pub(crate) fn collect_ports_with_profile(
    profile: MetadataProfile,
) -> Result<Vec<PortEntry>, CollectorError> {
    let snapshot = collect_snapshot(profile)?;
    project_legacy(&snapshot).map_err(CollectorError::from)
}

pub(crate) fn collect_kill_ports(
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, CollectorError> {
    let snapshot = collect_snapshot(MetadataProfile::Display)?;
    kill_ports_from_snapshot(&snapshot, pid, port)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn collect_target_ports(
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, CollectorError> {
    let snapshot = collect_snapshot(MetadataProfile::Display)?;
    crate::observation::project_legacy_target(&snapshot, pid, port).map_err(CollectorError::from)
}

/// Project the rows a destructive command is allowed to act on, or refuse.
///
/// The whole function is a fail-closed gate: it answers "may we signal based on
/// this snapshot?" before it answers "which rows?". Authority is accumulated
/// from two independent sources — the matched sockets themselves, and the
/// snapshot's evidence gaps — and only then converted into a refusal, so no
/// early return can skip a reason that a later source would have raised.
pub(crate) fn kill_ports_from_snapshot(
    snapshot: &NetworkSnapshot,
    pid: Option<u32>,
    port: Option<u16>,
) -> Result<Vec<PortEntry>, CollectorError> {
    let target_mode = match (pid, port) {
        (Some(pid), None) => DestructiveTargetMode::Pid(pid),
        (None, Some(port)) => DestructiveTargetMode::Port(port),
        _ => return Err(ObservationError::NativeDataMalformed.into()),
    };

    // An omitted gap is evidence we never got to inspect, so it is partial
    // before any socket is examined.
    let mut authority = Authority::complete();
    authority.partial |= snapshot.omitted_evidence_gap_count != 0;

    let mut matched_endpoints = std::collections::BTreeSet::new();
    for socket in &snapshot.sockets {
        let Some(target_match) = destructive_socket_match(socket, target_mode) else {
            continue;
        };
        matched_endpoints.insert(socket.local_endpoint.clone());
        authority.merge(socket_authority(socket, target_mode, target_match));
    }

    for gap in &snapshot.evidence_gaps {
        // A raced observation invalidates the whole snapshot regardless of
        // which endpoint or PID the gap names.
        authority.partial |= gap.code == EvidenceGapCode::ObservationRaced;
        if !gap_applies_to_target(gap, target_mode, &matched_endpoints) {
            continue;
        }
        authority.permission_denied |= gap.code == EvidenceGapCode::OwnerPermissionDenied;
        authority.partial = true;
    }

    // Permission denial outranks partiality: it is the more specific and more
    // actionable refusal, and it maps to a distinct exit code.
    if authority.permission_denied {
        return Err(CollectorError::OwnershipPermissionDenied);
    }
    if authority.partial {
        return Err(ObservationError::PartialSocketSet.into());
    }
    if snapshot.completeness == SnapshotCompleteness::Raced {
        return Err(ObservationError::ObservationRaced.into());
    }
    project_legacy_target(snapshot, pid, port).map_err(CollectorError::from)
}

/// Why a destructive command may not act on a snapshot, if it may not.
///
/// Two independent reasons rather than one flag, because they map to different
/// exit codes and different user advice. Both are monotonic: once raised, no
/// later evidence can lower them.
#[derive(Debug, Clone, Copy)]
struct Authority {
    permission_denied: bool,
    partial: bool,
}

impl Authority {
    const fn complete() -> Self {
        Self {
            permission_denied: false,
            partial: false,
        }
    }

    fn merge(&mut self, other: Self) {
        self.permission_denied |= other.permission_denied;
        self.partial |= other.partial;
    }
}

/// How a candidate socket matched the destructive target, if it matched.
#[derive(Debug, Clone, Copy)]
struct DestructiveSocketMatch {
    /// The reason the target PID's owner edge could not be verified, when the
    /// socket matched through an unverified owner rather than a verified one.
    unverified_target_reason: Option<crate::observation::UnverifiedOwnerReason>,
}

/// Match one socket against the destructive target.
///
/// Only listening TCP and bound UDP sockets carry destructive authority; a
/// snapshot's established and transitional connections are real observations
/// but are not something a kill can target.
fn destructive_socket_match(
    socket: &crate::observation::SocketObservation,
    target_mode: DestructiveTargetMode,
) -> Option<DestructiveSocketMatch> {
    if !matches!(
        (socket.local_endpoint.protocol, socket.state),
        (Protocol::Tcp, ObservationSocketState::Listen)
            | (Protocol::Udp, ObservationSocketState::Bound)
    ) {
        return None;
    }
    match target_mode {
        DestructiveTargetMode::Port(target_port) => {
            (socket.local_endpoint.port.get() == target_port).then_some(DestructiveSocketMatch {
                unverified_target_reason: None,
            })
        }
        DestructiveTargetMode::Pid(target_pid) => {
            let verified = socket.owners.iter().any(|owner| {
                matches!(
                    owner,
                    crate::observation::OwnerObservation::Verified(identity)
                        if identity.pid == target_pid
                )
            });
            let unverified_target_reason = socket.owners.iter().find_map(|owner| match owner {
                crate::observation::OwnerObservation::UnverifiedPid {
                    pid: owner_pid,
                    reason,
                } if *owner_pid == target_pid => Some(*reason),
                _ => None,
            });
            (verified || unverified_target_reason.is_some()).then_some(DestructiveSocketMatch {
                unverified_target_reason,
            })
        }
    }
}

/// The authority one matched socket contributes.
///
/// Port targets are held to a stricter rule than PID targets: a PID target has
/// already been resolved to one verified identity, but a port target must prove
/// that *every* holder of that endpoint is accounted for — otherwise the signal
/// frees a port someone else is still holding.
fn socket_authority(
    socket: &crate::observation::SocketObservation,
    target_mode: DestructiveTargetMode,
    target_match: DestructiveSocketMatch,
) -> Authority {
    let socket_local_permission_gap = matches!(
        &socket.owner_completeness,
        OwnerCompleteness::Partial { reasons }
            if reasons.contains(&EvidenceGapCode::OwnerPermissionDenied)
    );
    let target_owner_permission_denied = target_match.unverified_target_reason
        == Some(crate::observation::UnverifiedOwnerReason::PermissionDenied);

    let mut authority = Authority {
        permission_denied: socket_local_permission_gap || target_owner_permission_denied,
        partial: target_match.unverified_target_reason.is_some()
            || !socket.owner_completeness.is_complete(),
    };

    if matches!(target_mode, DestructiveTargetMode::Port(_)) {
        // No owner at all, or any owner we could not tie to a start identity,
        // means the port's holder set is unproven.
        authority.partial |= socket.owners.is_empty()
            || socket
                .owners
                .iter()
                .any(|owner| !matches!(owner, crate::observation::OwnerObservation::Verified(_)));
        authority.permission_denied |= socket.owners.iter().any(|owner| {
            matches!(
                owner,
                crate::observation::OwnerObservation::UnverifiedPid {
                    reason: crate::observation::UnverifiedOwnerReason::PermissionDenied,
                    ..
                }
            )
        });
    }

    authority
}

/// Whether an evidence gap can affect this target's authority.
///
/// Provenance is the whole point: an unrelated process losing its owner
/// attribution must not make an unprivileged `kill --port` impossible, while a
/// gap that could plausibly hide part of *this* target must refuse. The two
/// target modes need different rules because they are asking different
/// questions — "is this PID's evidence intact?" versus "is this port's holder
/// set complete?" — so a socket-set gap with no endpoint is fatal to a port
/// target but only to an unattributed PID target.
fn gap_applies_to_target(
    gap: &crate::observation::EvidenceGap,
    target_mode: DestructiveTargetMode,
    matched_endpoints: &std::collections::BTreeSet<crate::observation::EndpointIdentity>,
) -> bool {
    let names_matched_endpoint = || {
        gap.endpoint
            .as_ref()
            .is_some_and(|endpoint| matched_endpoints.contains(endpoint))
    };
    match (target_mode, gap.impact) {
        // Metadata and scope gaps never remove destructive authority: they
        // describe optional enrichment and declared observation boundaries,
        // neither of which changes who holds the endpoint.
        (_, EvidenceImpact::Metadata | EvidenceImpact::Scope) => false,
        (DestructiveTargetMode::Pid(target_pid), EvidenceImpact::SocketSet) => {
            gap.pid == Some(target_pid)
                || names_matched_endpoint()
                // An unattributed socket-set loss could have hidden a socket
                // belonging to this PID.
                || (gap.endpoint.is_none() && gap.pid.is_none())
        }
        (DestructiveTargetMode::Pid(target_pid), EvidenceImpact::Ownership) => {
            names_matched_endpoint() || (gap.endpoint.is_none() && gap.pid == Some(target_pid))
        }
        // Any socket-set loss that is not provably about another port could
        // have hidden a co-holder of this one.
        (DestructiveTargetMode::Port(target_port), EvidenceImpact::SocketSet) => gap
            .endpoint
            .as_ref()
            .is_none_or(|endpoint| endpoint.port.get() == target_port),
        (DestructiveTargetMode::Port(target_port), EvidenceImpact::Ownership) => gap
            .endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.port.get() == target_port),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DestructiveTargetMode {
    Pid(u32),
    Port(u16),
}

impl CollectorError {
    pub(crate) fn is_ownership_permission_denied(&self) -> bool {
        matches!(self, Self::OwnershipPermissionDenied)
    }
}

/// Deterministic fake rows: both the test fixture and the fallback collector on
/// platforms that don't have a native one yet.
///
/// The rows are hand-picked to hit every rendering path the model allows: full
/// metadata, permission-restricted partial metadata, a default-protected process
/// name, IPv6, and a bound UDP socket.
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
pub(crate) struct FakeCollector;

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
impl Collector for FakeCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        Ok(fake_snapshot(profile)?)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) fn collect_native_snapshot<Collect, ReadProcesses>(
    profile: MetadataProfile,
    scope: ObservationScope,
    collect_pass: Collect,
    read_processes: ReadProcesses,
) -> Result<NetworkSnapshot, CollectorError>
where
    Collect: FnMut(MetadataProfile) -> Result<NativeObservationPass, CollectorError>,
    ReadProcesses: FnMut(
        &[u32],
        MetadataProfile,
        usize,
    )
        -> Result<std::collections::BTreeMap<u32, ProcessRead>, CollectorError>,
{
    let mut source = NativeObservationSource {
        collect_pass,
        read_processes,
    };
    collect_consistent(&mut source, scope, profile).map_err(CollectorError::from)
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct NativeObservationSource<Collect, ReadProcesses> {
    collect_pass: Collect,
    read_processes: ReadProcesses,
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
impl<Collect, ReadProcesses> ObservationSource for NativeObservationSource<Collect, ReadProcesses>
where
    Collect: FnMut(MetadataProfile) -> Result<NativeObservationPass, CollectorError>,
    ReadProcesses: FnMut(
        &[u32],
        MetadataProfile,
        usize,
    )
        -> Result<std::collections::BTreeMap<u32, ProcessRead>, CollectorError>,
{
    fn wall_clock(&mut self) -> Result<SystemTime, ObservationError> {
        Ok(SystemTime::now())
    }

    fn collect_native_pass(
        &mut self,
        profile: MetadataProfile,
    ) -> Result<NativeObservationPass, ObservationError> {
        (self.collect_pass)(profile).map_err(native_observation_error)
    }

    fn read_processes(
        &mut self,
        sorted_pids: &[u32],
        profile: MetadataProfile,
        optional_metadata_bytes_remaining: usize,
    ) -> Result<std::collections::BTreeMap<u32, ProcessRead>, ObservationError> {
        (self.read_processes)(sorted_pids, profile, optional_metadata_bytes_remaining)
            .map_err(native_observation_error)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn native_observation_error(error: CollectorError) -> ObservationError {
    match error {
        CollectorError::Observation(error) => error,
        error => ObservationError::PlatformApiFailed(error.to_string()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn read_processes_sequentially<ReadProcess>(
    sorted_pids: &[u32],
    profile: MetadataProfile,
    optional_metadata_bytes_remaining: usize,
    mut read_process: ReadProcess,
) -> Result<std::collections::BTreeMap<u32, ProcessRead>, CollectorError>
where
    ReadProcess: FnMut(u32, MetadataProfile, usize) -> Result<ProcessRead, CollectorError>,
{
    let mut reads = std::collections::BTreeMap::new();
    let mut retained_bytes = 0usize;
    for &pid in sorted_pids {
        let remaining = optional_metadata_bytes_remaining.saturating_sub(retained_bytes);
        let read = read_process(pid, profile, remaining)?;
        retained_bytes = retained_bytes.saturating_add(process_read_metadata_bytes(&read));
        reads.insert(pid, read);
    }
    Ok(reads)
}

/// Deterministic authoritative fixture. It is built in snapshot form so tests
/// exercise the same borrowed projection as native collectors.
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
#[expect(
    clippy::too_many_lines,
    reason = "the five-row authoritative fixture keeps all snapshot facts together"
)]
fn fake_snapshot(profile: MetadataProfile) -> Result<NetworkSnapshot, ObservationError> {
    struct Fixture {
        protocol: Protocol,
        address: IpAddr,
        port: u16,
        state: ObservationSocketState,
        pid: Option<u32>,
        name: Option<&'static str>,
        path: Option<&'static str>,
        command: Option<&'static str>,
        parent_pid: Option<u32>,
        parent_name: Option<&'static str>,
        metadata: MetadataCompleteness,
    }

    let fixtures = [
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST.into(),
            port: 3000,
            state: ObservationSocketState::Listen,
            pid: Some(18_422),
            name: Some("node"),
            path: Some("/usr/bin/node"),
            command: Some("node server.js"),
            parent_pid: Some(18_001),
            parent_name: Some("cursor-agent"),
            metadata: MetadataCompleteness::Complete,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::LOCALHOST.into(),
            port: 5173,
            state: ObservationSocketState::Listen,
            pid: Some(21_988),
            name: Some("vite"),
            path: Some("/usr/bin/node"),
            command: Some("node /usr/local/bin/vite --port 5173"),
            parent_pid: Some(18_001),
            parent_name: Some("cursor-agent"),
            metadata: MetadataCompleteness::Complete,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv4Addr::UNSPECIFIED.into(),
            port: 5432,
            state: ObservationSocketState::Listen,
            pid: Some(1_201),
            name: Some("postgres"),
            path: None,
            command: Some("/usr/lib/postgresql/16/bin/postgres"),
            parent_pid: Some(1),
            parent_name: Some("systemd"),
            metadata: MetadataCompleteness::Partial,
        },
        Fixture {
            protocol: Protocol::Tcp,
            address: Ipv6Addr::UNSPECIFIED.into(),
            port: 8080,
            state: ObservationSocketState::Listen,
            pid: None,
            name: None,
            path: None,
            command: None,
            parent_pid: None,
            parent_name: None,
            metadata: MetadataCompleteness::Partial,
        },
        Fixture {
            protocol: Protocol::Udp,
            address: Ipv4Addr::UNSPECIFIED.into(),
            port: 5353,
            state: ObservationSocketState::Bound,
            pid: Some(902),
            name: Some("avahi-daemon"),
            path: Some("/usr/bin/avahi-daemon"),
            command: Some("avahi-daemon: running [linux.local]"),
            parent_pid: Some(1),
            parent_name: Some("systemd"),
            metadata: MetadataCompleteness::Complete,
        },
    ];
    let mut sockets = Vec::with_capacity(fixtures.len());
    let mut processes = std::collections::HashMap::new();
    for fixture in fixtures {
        let endpoint = EndpointIdentity::new(
            fixture.protocol,
            fixture.address,
            u32::from(fixture.port),
            fixture.address.is_ipv6().then_some(Ipv6Scope::Unavailable),
        )
        .map_err(|_| ObservationError::NativeDataMalformed)?;
        let owners = fixture.pid.map_or_else(Vec::new, |pid| {
            let identity = ProcessIdentity {
                pid,
                start_marker: ProcessStartMarker::linux(u64::from(pid) + 1)
                    .expect("fake PID produces a nonzero marker"),
            };
            processes.insert(
                identity,
                ProcessObservation {
                    name: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.name.map(Into::into))
                        .flatten(),
                    executable_path: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.path.map(|path| PathBuf::from(path).into()))
                        .flatten(),
                    command_line: (profile == MetadataProfile::LegacyList)
                        .then(|| fixture.command.map(Into::into))
                        .flatten(),
                    parent_pid: (profile != MetadataProfile::IdentityOnly)
                        .then_some(fixture.parent_pid)
                        .flatten(),
                    parent_process_name: (profile != MetadataProfile::IdentityOnly)
                        .then(|| fixture.parent_name.map(Into::into))
                        .flatten(),
                    metadata_omission: None,
                    metadata_completeness: fixture.metadata,
                },
            );
            vec![crate::observation::OwnerObservation::Verified(identity)]
        });
        sockets.push(SocketObservation {
            local_endpoint: endpoint,
            state: fixture.state,
            timer: None,
            owners,
            owner_completeness: if fixture.pid.is_some() {
                OwnerCompleteness::Complete
            } else {
                OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])?
            },
            socket_token: None,
        });
    }
    let ownerless_endpoint = sockets[3].local_endpoint.clone();
    Ok(NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH,
        scope: ObservationScope::new(
            crate::observation::ObservationScopeKind::CurrentNetworkNamespace,
            Some("net:[fake]"),
            [crate::observation::ScopeLimitation::OtherNetworkNamespacesExcluded],
        )?,
        completeness: SnapshotCompleteness::Partial,
        owner_completeness: OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
        ])?,
        evidence_gaps: vec![
            EvidenceGap::new(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerAttributionIncomplete,
                Some(ownerless_endpoint.clone()),
                None,
                "fake socket has no attributable owner PID",
            ),
            EvidenceGap::new(
                EvidenceImpact::Scope,
                EvidenceGapCode::NativeFieldUnavailable,
                Some(ownerless_endpoint),
                None,
                "fake IPv6 socket has no interface scope",
            ),
        ],
        omitted_evidence_gap_count: 0,
        sockets,
        processes,
    })
}

#[cfg(test)]
mod tests {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use super::NativeObservationSource;
    use super::{Collector, FakeCollector, kill_ports_from_snapshot};
    use crate::model::{PermissionStatus, Protocol, SocketState};
    use crate::observation::{
        EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot,
        ObservationError, OwnerCompleteness, OwnerObservation, ProcessIdentity,
        SnapshotCompleteness, UnverifiedOwnerReason, project_legacy, project_legacy_identities,
        project_legacy_pids,
    };
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    use crate::observation::{NativeObservationPass, ObservationSource};

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn socket_limit_pass(
        _profile: MetadataProfile,
    ) -> Result<NativeObservationPass, super::CollectorError> {
        Err(super::CollectorError::Observation(
            ObservationError::SocketObservationLimitExceeded,
        ))
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "function pointer must match the fallible native adapter seam"
    )]
    fn empty_process_reads(
        _pids: &[u32],
        _profile: MetadataProfile,
        _remaining: usize,
    ) -> Result<
        std::collections::BTreeMap<u32, crate::observation::ProcessRead>,
        super::CollectorError,
    > {
        Ok(std::collections::BTreeMap::new())
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "function pointer must match the fallible native adapter seam"
    )]
    fn empty_native_pass(
        _profile: MetadataProfile,
    ) -> Result<NativeObservationPass, super::CollectorError> {
        Ok(NativeObservationPass {
            sockets: Vec::new(),
            owners: crate::observation::OwnerAssociations {
                owners_by_socket: Vec::new(),
                local_completeness: Vec::new(),
                global_completeness: OwnerCompleteness::Complete,
                evidence_gaps: Vec::new(),
                omitted_evidence_gap_count: 0,
            },
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn process_limit_reads(
        _pids: &[u32],
        _profile: MetadataProfile,
        _remaining: usize,
    ) -> Result<
        std::collections::BTreeMap<u32, crate::observation::ProcessRead>,
        super::CollectorError,
    > {
        Err(super::CollectorError::Observation(
            ObservationError::ProcessIdentityLimitExceeded,
        ))
    }

    fn permission_denied_owner_snapshot() -> NetworkSnapshot {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let endpoint = {
            let socket = snapshot
                .sockets
                .iter_mut()
                .find(|socket| socket.local_endpoint.port.get() == 3000)
                .expect("fixture has target socket");
            socket.owners = vec![OwnerObservation::UnverifiedPid {
                pid: 18_422,
                reason: UnverifiedOwnerReason::PermissionDenied,
            }];
            socket.owner_completeness =
                OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                    .expect("one reason fits");
            socket.local_endpoint.clone()
        };
        snapshot
            .processes
            .retain(|identity, _| identity.pid != 18_422);
        snapshot.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .expect("fixture reasons fit");
        for _ in 0..2 {
            snapshot.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerPermissionDenied,
                Some(endpoint.clone()),
                Some(18_422),
                "native owner PID could not be verified to a process start identity",
            ));
        }
        snapshot
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    fn native_adapter_preserves_typed_observation_errors() {
        let mut pass_error = NativeObservationSource {
            collect_pass: socket_limit_pass,
            read_processes: empty_process_reads,
        };
        assert_eq!(
            ObservationSource::collect_native_pass(&mut pass_error, MetadataProfile::IdentityOnly),
            Err(ObservationError::SocketObservationLimitExceeded)
        );

        let mut process_error = NativeObservationSource {
            collect_pass: empty_native_pass,
            read_processes: process_limit_reads,
        };
        assert_eq!(
            ObservationSource::read_processes(
                &mut process_error,
                &[],
                MetadataProfile::IdentityOnly,
                0,
            ),
            Err(ObservationError::ProcessIdentityLimitExceeded)
        );
    }

    fn verified_owner_permission_snapshot() -> NetworkSnapshot {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let endpoint = {
            let socket = snapshot
                .sockets
                .iter_mut()
                .find(|socket| socket.local_endpoint.port.get() == 3000)
                .expect("fixture has target socket");
            socket.owner_completeness =
                OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                    .expect("one reason fits");
            socket.local_endpoint.clone()
        };
        snapshot.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .expect("fixture reasons fit");
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(endpoint),
            None,
            "native ownership attribution was permission denied",
        ));
        snapshot
    }

    #[test]
    fn fake_snapshot_covers_every_rendering_path() {
        let snapshot = FakeCollector
            .collect(MetadataProfile::LegacyList)
            .expect("fake collection cannot fail");
        let entries = project_legacy(&snapshot).expect("fake projection cannot fail");

        // Port 3000 has to be here: examples and CLI filter tests both lean on it.
        assert!(entries.iter().any(|entry| entry.local_port == 3000));
        // At least one row where all the metadata is withheld.
        assert!(
            entries
                .iter()
                .any(|entry| entry.pid.is_none() && entry.permission == PermissionStatus::Partial)
        );
        // And one half-withheld row: PID and name readable, executable path
        // hidden (the "someone else's process" shape the UI must explain).
        assert!(entries.iter().any(|entry| {
            entry.pid.is_some()
                && entry.executable_path.is_none()
                && entry.permission == PermissionStatus::Partial
        }));
        // At least one bound UDP row and one IPv6 row.
        assert!(
            entries
                .iter()
                .any(|entry| entry.protocol == Protocol::Udp && entry.state == SocketState::Bound)
        );
        assert!(entries.iter().any(|entry| entry.local_addr.is_ipv6()));
        // The collector never pre-marks protection — that's config's job.
        assert!(entries.iter().all(|entry| !entry.protected));
    }

    #[test]
    fn identity_projection_excludes_recycled_and_unverified_pid_owners() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let matching = snapshot
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has target listener")
            .clone();
        let identity = matching
            .owners
            .iter()
            .find_map(|owner| match owner {
                OwnerObservation::Verified(identity) => Some(*identity),
                OwnerObservation::UnverifiedPid { .. } => None,
            })
            .expect("fixture listener has a verified owner");
        let mut recycled = matching.clone();
        recycled.owners = vec![OwnerObservation::Verified(ProcessIdentity {
            pid: identity.pid,
            start_marker: crate::observation::ProcessStartMarker::linux(999)
                .expect("test marker is nonzero"),
        })];
        let mut unverified = matching.clone();
        unverified.owners = vec![OwnerObservation::UnverifiedPid {
            pid: identity.pid,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        }];
        snapshot.sockets = vec![matching, recycled, unverified];

        let entries =
            project_legacy_identities(&snapshot, &std::collections::BTreeSet::from([identity]))
                .expect("identity projection succeeds");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].process_identity, Some(identity));
    }

    #[test]
    fn destructive_authority_ignores_non_legacy_socket_states() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let template = snapshot
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has target listener")
            .clone();
        let non_legacy_states = [
            crate::observation::SocketState::Closed,
            crate::observation::SocketState::SynSent,
            crate::observation::SocketState::SynReceived,
            crate::observation::SocketState::Established,
            crate::observation::SocketState::FinWait1,
            crate::observation::SocketState::FinWait2,
            crate::observation::SocketState::CloseWait,
            crate::observation::SocketState::Closing,
            crate::observation::SocketState::LastAck,
            crate::observation::SocketState::TimeWait,
            crate::observation::SocketState::DeleteTcb,
            crate::observation::SocketState::NewSynReceived,
            crate::observation::SocketState::Unknown(255),
        ];
        for state in non_legacy_states {
            let mut socket = template.clone();
            socket.state = state;
            socket.owner_completeness =
                OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                    .expect("one reason fits");
            socket.owners = vec![OwnerObservation::UnverifiedPid {
                pid: 29_999,
                reason: UnverifiedOwnerReason::PermissionDenied,
            }];
            snapshot.sockets.push(socket);
        }

        let rows = kill_ports_from_snapshot(&snapshot, None, Some(3000))
            .expect("non-legacy states cannot invalidate listener authority");
        assert!(!rows.is_empty());
        assert!(rows.iter().all(|row| row.state == SocketState::Listen));
        assert!(
            kill_ports_from_snapshot(&snapshot, Some(29_999), None)
                .expect("non-legacy states cannot become PID kill targets")
                .is_empty()
        );
        assert!(
            project_legacy(&snapshot)
                .expect("legacy projection")
                .iter()
                .all(|row| matches!(row.state, SocketState::Listen | SocketState::Bound))
        );
        let pids = std::collections::BTreeSet::from([29_999]);
        assert!(
            project_legacy_pids(&snapshot, &pids)
                .expect("PID projection")
                .is_empty()
        );
    }

    #[test]
    fn metadata_profiles_only_change_optional_enrichment() {
        let identity = FakeCollector
            .collect(MetadataProfile::IdentityOnly)
            .expect("identity profile collects");
        let display = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("display profile collects");
        let legacy = FakeCollector
            .collect(MetadataProfile::LegacyList)
            .expect("legacy profile collects");

        assert_eq!(identity.sockets, display.sockets);
        assert_eq!(display.sockets, legacy.sockets);
        assert_eq!(
            identity
                .processes
                .keys()
                .collect::<std::collections::BTreeSet<_>>(),
            display
                .processes
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert_eq!(
            display
                .processes
                .keys()
                .collect::<std::collections::BTreeSet<_>>(),
            legacy
                .processes
                .keys()
                .collect::<std::collections::BTreeSet<_>>()
        );
        assert!(
            identity
                .processes
                .values()
                .all(|process| process.name.is_none()
                    && process.executable_path.is_none()
                    && process.command_line.is_none()
                    && process.parent_pid.is_none()
                    && process.parent_process_name.is_none())
        );
        assert!(
            display
                .processes
                .values()
                .any(|process| process.name.is_some())
        );
        assert!(
            display
                .processes
                .values()
                .all(|process| process.command_line.is_none())
        );
        assert!(display.processes.values().any(|process| {
            process.name.is_some()
                && process.executable_path.is_some()
                && process.parent_pid.is_some()
                && process.parent_process_name.is_some()
        }));
        assert!(
            legacy
                .processes
                .values()
                .any(|process| process.command_line.is_some())
        );
    }

    #[test]
    fn destructive_authority_distinguishes_pid_and_port_targets() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        snapshot.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .expect("fixture reasons fit");
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(99_999),
            "unrelated PID ownership denied",
        ));
        assert!(kill_ports_from_snapshot(&snapshot, Some(18_422), None).is_ok());
        assert!(kill_ports_from_snapshot(&snapshot, None, Some(3000)).is_ok());

        snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits");
        let selected_socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has selected endpoint");
        selected_socket.owner_completeness = snapshot.owner_completeness.clone();
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));

        snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has selected endpoint")
            .owner_completeness = OwnerCompleteness::Complete;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            Some(99_999),
            "unrelated global owner loss",
        ));
        assert!(kill_ports_from_snapshot(&snapshot, Some(18_422), None).is_ok());

        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            Some(18_422),
            "target PID owner loss",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
        snapshot.evidence_gaps.retain(|gap| gap.pid != Some(18_422));
    }

    #[test]
    fn destructive_projection_contains_only_rows_matching_the_target_mode() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        snapshot.owner_completeness = OwnerCompleteness::Complete;
        snapshot.evidence_gaps.clear();
        snapshot.omitted_evidence_gap_count = 0;
        for socket in &mut snapshot.sockets {
            socket.owner_completeness = OwnerCompleteness::Complete;
        }
        let co_owner = snapshot
            .processes
            .keys()
            .find(|identity| identity.pid == 21_988)
            .copied()
            .expect("fixture co-owner identity");
        snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture target socket")
            .owners
            .push(OwnerObservation::Verified(co_owner));

        let by_pid = kill_ports_from_snapshot(&snapshot, Some(18_422), None)
            .expect("verified PID remains the selected identity");
        assert!(!by_pid.is_empty());
        assert!(by_pid.iter().all(|row| row.pid == Some(18_422)));

        let by_port = kill_ports_from_snapshot(&snapshot, None, Some(3000))
            .expect("globally complete port ownership projects all candidates");
        assert_eq!(
            by_port
                .iter()
                .filter_map(|row| row.pid)
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from([18_422, 21_988])
        );
        assert!(by_port.iter().all(|row| row.local_port == 3000));
    }

    #[test]
    fn port_authority_requires_complete_local_evidence_and_verified_owners() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        snapshot.owner_completeness = OwnerCompleteness::Complete;
        snapshot.evidence_gaps.clear();
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture target socket");
        socket.owner_completeness = OwnerCompleteness::Complete;
        socket.owners.push(OwnerObservation::UnverifiedPid {
            pid: 99_999,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        });

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
    }

    #[test]
    fn matching_permission_denied_unverified_pid_preserves_authority_loss() {
        let snapshot = permission_denied_owner_snapshot();

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
    }

    #[test]
    fn matching_socket_local_permission_gap_preserves_authority_loss() {
        let snapshot = verified_owner_permission_snapshot();

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
    }

    #[test]
    fn matching_endpoint_ownership_permission_gap_preserves_authority_loss() {
        let snapshot = verified_owner_permission_snapshot();

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
    }

    #[test]
    fn target_pid_global_ownership_permission_gap_does_not_block_visible_port_owner() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        snapshot.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .expect("fixture reasons fit");
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(18_422),
            "target PID ownership denied without an endpoint",
        ));

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
        assert!(kill_ports_from_snapshot(&snapshot, None, Some(3000)).is_ok());
    }

    #[test]
    fn applicable_socket_set_permission_gaps_preserve_authority_loss() {
        let base = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let target_endpoint = base
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture target socket")
            .local_endpoint
            .clone();

        let mut global = base.clone();
        global.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(18_422),
            "target PID socket set denied",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&global, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&global, None, Some(3000)),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));

        let mut local = base;
        local.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(target_endpoint),
            None,
            "selected endpoint socket set denied",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&local, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));

        let unrelated_endpoint = local
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 5173)
            .expect("fixture unrelated socket")
            .local_endpoint
            .clone();
        let mut target_pid_on_other_endpoint = local;
        target_pid_on_other_endpoint.evidence_gaps.clear();
        target_pid_on_other_endpoint
            .evidence_gaps
            .push(EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::OwnerPermissionDenied,
                Some(unrelated_endpoint),
                Some(18_422),
                "target PID socket set denied on another endpoint",
            ));
        assert!(matches!(
            kill_ports_from_snapshot(&target_pid_on_other_endpoint, Some(18_422), None),
            Err(super::CollectorError::OwnershipPermissionDenied)
        ));
    }

    #[test]
    fn permission_refusal_precedes_raced_refusal_for_pid_and_port() {
        for (pid, port) in [(Some(18_422), None), (None, Some(3000))] {
            let mut snapshot = permission_denied_owner_snapshot();
            snapshot.completeness = SnapshotCompleteness::Raced;
            snapshot.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::ObservationRaced,
                None,
                None,
                "socket table changed during collection",
            ));

            assert!(matches!(
                kill_ports_from_snapshot(&snapshot, pid, port),
                Err(super::CollectorError::OwnershipPermissionDenied)
            ));
        }
    }

    #[test]
    fn permission_refusal_precedes_omitted_evidence_for_pid_and_port() {
        for (pid, port) in [(Some(18_422), None), (None, Some(3000))] {
            let mut snapshot = permission_denied_owner_snapshot();
            snapshot.omitted_evidence_gap_count = 1;

            assert!(matches!(
                kill_ports_from_snapshot(&snapshot, pid, port),
                Err(super::CollectorError::OwnershipPermissionDenied)
            ));
        }
    }

    #[test]
    fn empty_owner_port_gate_remains_generic_fail_closed() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture target socket");
        socket.owners.clear();
        socket.owner_completeness = OwnerCompleteness::Complete;

        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, None, Some(3000)),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
    }

    #[test]
    fn pid_socket_set_gaps_require_proven_unrelated_provenance() {
        let base = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let target_pid = 18_422;

        for pid in [None, Some(target_pid)] {
            let mut snapshot = base.clone();
            snapshot.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::OwnerAttributionIncomplete,
                None,
                pid,
                "socket set provenance is not unrelated",
            ));
            assert!(matches!(
                kill_ports_from_snapshot(&snapshot, Some(target_pid), None),
                Err(super::CollectorError::Observation(
                    ObservationError::PartialSocketSet
                ))
            ));
        }

        let mut unrelated = base.clone();
        unrelated.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            Some(99_999),
            "known unrelated PID socket scan loss",
        ));
        assert!(kill_ports_from_snapshot(&unrelated, Some(target_pid), None).is_ok());
        assert!(matches!(
            kill_ports_from_snapshot(&unrelated, None, Some(3000)),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));

        let selected_endpoint = base
            .sockets
            .iter()
            .find(|socket| {
                socket.owners.iter().any(|owner| {
                    matches!(
                        owner,
                        crate::observation::OwnerObservation::Verified(identity)
                            if identity.pid == target_pid
                    )
                })
            })
            .expect("target endpoint")
            .local_endpoint
            .clone();
        let mut matching_endpoint = base;
        matching_endpoint.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            Some(selected_endpoint),
            Some(99_999),
            "matching endpoint remains relevant despite unrelated PID",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&matching_endpoint, Some(target_pid), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));

        let unrelated_endpoint = matching_endpoint
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 5173)
            .expect("unrelated endpoint")
            .local_endpoint
            .clone();
        for pid in [None, Some(99_999)] {
            let mut unrelated = matching_endpoint.clone();
            unrelated.evidence_gaps.clear();
            unrelated.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::NativeFieldUnavailable,
                Some(unrelated_endpoint.clone()),
                pid,
                "nonmatching endpoint has no target provenance",
            ));
            assert!(kill_ports_from_snapshot(&unrelated, Some(target_pid), None).is_ok());
        }
    }

    #[test]
    fn port_socket_set_gaps_apply_only_globally_or_to_the_selected_port() {
        let base = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let selected_endpoint = base
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("selected endpoint")
            .local_endpoint
            .clone();
        let unrelated_endpoint = base
            .sockets
            .iter()
            .find(|socket| socket.local_endpoint.port.get() == 5173)
            .expect("unrelated endpoint")
            .local_endpoint
            .clone();

        let mut unrelated = base.clone();
        unrelated.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::OwnerPermissionDenied,
            Some(unrelated_endpoint),
            None,
            "another port was permission denied",
        ));
        assert!(kill_ports_from_snapshot(&unrelated, None, Some(3000)).is_ok());

        for endpoint in [None, Some(selected_endpoint)] {
            let mut applicable = base.clone();
            applicable.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::SocketSet,
                EvidenceGapCode::NativeFieldUnavailable,
                endpoint,
                Some(99_999),
                "selected port socket set is partial",
            ));
            assert!(matches!(
                kill_ports_from_snapshot(&applicable, None, Some(3000)),
                Err(super::CollectorError::Observation(
                    ObservationError::PartialSocketSet
                ))
            ));
        }
    }

    #[test]
    fn kill_collection_exhaustively_validates_snapshot_authority() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");

        let selected_endpoint = snapshot
            .sockets
            .iter()
            .find(|socket| {
                socket.owners.iter().any(|owner| {
                    matches!(
                        owner,
                        crate::observation::OwnerObservation::Verified(identity)
                            if identity.pid == 18_422
                    )
                })
            })
            .expect("selected owner has an endpoint")
            .local_endpoint
            .clone();
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerAttributionIncomplete,
            Some(selected_endpoint),
            Some(18_422),
            "selected endpoint owner loss",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));

        let mut raced = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        raced.completeness = SnapshotCompleteness::Raced;
        raced
            .evidence_gaps
            .retain(|gap| gap.code != EvidenceGapCode::ObservationRaced);
        assert!(matches!(
            kill_ports_from_snapshot(&raced, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::ObservationRaced
            ))
        ));
        snapshot.evidence_gaps.retain(|gap| gap.endpoint.is_none());

        snapshot.completeness = SnapshotCompleteness::Partial;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "injected partial socket authority",
        ));
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
    }

    #[test]
    fn naturally_unverified_attributable_owner_refuses_kill_projection() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture target socket");
        socket.owners = vec![OwnerObservation::UnverifiedPid {
            pid: 18_422,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        }];
        socket.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable])
                .expect("one reason fits");
        snapshot.owner_completeness = socket.owner_completeness.clone();

        assert!(!snapshot.owner_completeness.is_complete());
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));

        snapshot.owner_completeness = OwnerCompleteness::Raced;
        assert!(matches!(
            kill_ports_from_snapshot(&snapshot, Some(18_422), None),
            Err(super::CollectorError::Observation(
                ObservationError::PartialSocketSet
            ))
        ));
    }
}
