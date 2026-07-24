#![allow(dead_code)]

#[path = "../../../../src/display.rs"]
mod display;
#[path = "../../../../src/labels.rs"]
mod labels;
#[path = "../../../../src/model.rs"]
mod model;
#[path = "../../../../src/observation.rs"]
mod observation;
#[path = "../../../../src/protection.rs"]
mod protection;
#[path = "../../../../src/public_output.rs"]
mod public_output;
#[path = "../../../../src/query.rs"]
mod query;
#[path = "../../../../src/watch.rs"]
mod watch;

mod config {
    use crate::labels::LabelRegistry;

    #[derive(Debug, Default)]
    pub(crate) struct Config {
        pub(crate) protected_processes: Vec<String>,
        pub(crate) labels: LabelRegistry,
    }
}

mod collector {
    use thiserror::Error;

    use crate::observation::{MetadataProfile, NetworkSnapshot, ObservationError};

    #[derive(Debug, Error)]
    pub(crate) enum CollectorError {
        #[cfg(target_os = "linux")]
        #[error("cannot read {path}: {source}")]
        Read {
            path: std::path::PathBuf,
            source: std::io::Error,
        },
        #[cfg(any(target_os = "macos", windows))]
        #[error("{operation} failed: {detail}")]
        Platform {
            operation: &'static str,
            detail: String,
        },
        #[error("refresh worker exited before returning a snapshot")]
        WorkerExited,
        #[error(transparent)]
        Observation(#[from] ObservationError),
        #[error("permission denied while verifying complete endpoint ownership")]
        OwnershipPermissionDenied,
    }

    pub(crate) fn collect_snapshot(
        _profile: MetadataProfile,
    ) -> Result<NetworkSnapshot, CollectorError> {
        Err(CollectorError::WorkerExited)
    }
}

mod diagnostic {
    pub(crate) mod verdict {
        use crate::watch::Certainty;

        #[derive(Debug, Clone, Copy)]
        pub(crate) enum EvidenceSource {
            LinuxProcfs,
            MacosLibproc,
            MacosSysctl,
            WindowsIpHelper,
            WindowsProcessApi,
            BindProbe,
            Docker,
            Analysis,
        }

        impl EvidenceSource {
            pub(crate) const fn name(self) -> &'static str {
                match self {
                    Self::LinuxProcfs => "linux_procfs",
                    Self::MacosLibproc => "macos_libproc",
                    Self::MacosSysctl => "macos_sysctl",
                    Self::WindowsIpHelper => "windows_ip_helper",
                    Self::WindowsProcessApi => "windows_process_api",
                    Self::BindProbe => "bind_probe",
                    Self::Docker => "docker",
                    Self::Analysis => "analysis",
                }
            }
        }

        #[derive(Debug, Clone, Copy)]
        pub(crate) enum EvidenceCode {
            VisibleVerifiedOwner,
            VisibleUnreadableOwner,
            NonListeningKernelState,
            ExactBindSucceeded,
            ExactBindAddressInUse,
            ExactBindPermissionDenied,
            ExactBindAddressUnavailable,
            ExactBindUnsupported,
            ExactBindOtherError,
            LinuxTimerEstimate,
            ScopeLimitation,
            PotentialScopeOverlap,
            ObservationProbeConflict,
        }

        impl EvidenceCode {
            pub(crate) const fn name(self) -> &'static str {
                match self {
                    Self::VisibleVerifiedOwner => "visible_verified_owner",
                    Self::VisibleUnreadableOwner => "visible_unreadable_owner",
                    Self::NonListeningKernelState => "non_listening_kernel_state",
                    Self::ExactBindSucceeded => "exact_bind_succeeded",
                    Self::ExactBindAddressInUse => "exact_bind_address_in_use",
                    Self::ExactBindPermissionDenied => "exact_bind_permission_denied",
                    Self::ExactBindAddressUnavailable => "exact_bind_address_unavailable",
                    Self::ExactBindUnsupported => "exact_bind_unsupported",
                    Self::ExactBindOtherError => "exact_bind_other_error",
                    Self::LinuxTimerEstimate => "linux_timer_estimate",
                    Self::ScopeLimitation => "scope_limitation",
                    Self::PotentialScopeOverlap => "potential_scope_overlap",
                    Self::ObservationProbeConflict => "observation_probe_conflict",
                }
            }
        }

        #[derive(Debug, Clone)]
        pub(crate) struct Evidence {
            pub(crate) code: EvidenceCode,
            pub(crate) source: EvidenceSource,
            pub(crate) certainty: Certainty,
            pub(crate) message: String,
        }
    }
}

mod cli {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u8)]
    pub(crate) enum ExitReason {
        Success = 0,
        Failure = 1,
        InvalidArguments = 2,
        NoMatch = 3,
        PermissionDenied = 4,
        KillCancelled = 5,
        ProtectedNeedsConfirmation = 6,
    }

    pub(crate) mod watch {
        include!("../../../../src/cli/watch.rs");
        include!("fixture_adapter.rs");
    }
}

use std::collections::HashMap;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant, SystemTime};

use model::Protocol;
use observation::{
    EndpointIdentity, MetadataCompleteness, NetworkSnapshot, ObservationScope,
    ObservationScopeKind, OwnerCompleteness, OwnerObservation, ProcessIdentity, ProcessObservation,
    ProcessStartMarker, SOCKET_OBSERVATIONS_MAX, SnapshotCompleteness, SocketObservation,
    SocketState,
};
use watch::diff_snapshots;

const TYPICAL: usize = 1_024;
const LARGE: usize = 65_536;

pub(crate) fn identity(pid: u32, marker: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        start_marker: if cfg!(windows) {
            ProcessStartMarker::windows(marker).expect("fixture marker is nonzero")
        } else {
            ProcessStartMarker::linux(marker).expect("fixture marker is nonzero")
        },
    }
}

pub(crate) fn snapshot(
    count: usize,
    endpoint_offset: usize,
    owner: ProcessIdentity,
    capture_milliseconds: u64,
) -> NetworkSnapshot {
    let sockets = (0..count)
        .map(|index| {
            let index = endpoint_offset
                .checked_add(index)
                .expect("fixture endpoint index does not overflow");
            let port = u32::try_from(index % 65_535 + 1).expect("fixture port fits u32");
            let address_suffix =
                u8::try_from(index / 65_535 + 1).expect("fixture address suffix fits u8");
            SocketObservation {
                local_endpoint: EndpointIdentity::new(
                    Protocol::Tcp,
                    IpAddr::V4(Ipv4Addr::new(127, 0, 0, address_suffix)),
                    port,
                    None,
                )
                .expect("fixture endpoint is valid"),
                state: SocketState::Listen,
                timer: None,
                owners: vec![OwnerObservation::Verified(owner)],
                owner_completeness: OwnerCompleteness::Complete,
                socket_token: None,
            }
        })
        .collect();
    let process = ProcessObservation {
        name: Some(format!("fixture-{}", owner.pid).into()),
        executable_path: None,
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        metadata_omission: None,
        metadata_completeness: MetadataCompleteness::Complete,
    };
    NetworkSnapshot {
        capture_started_at: SystemTime::UNIX_EPOCH + Duration::from_millis(capture_milliseconds),
        capture_completed_at: SystemTime::UNIX_EPOCH
            + Duration::from_millis(capture_milliseconds + 1),
        scope: ObservationScope::new(
            if cfg!(windows) {
                ObservationScopeKind::CurrentHostNetworkStack
            } else {
                ObservationScopeKind::CurrentNetworkNamespace
            },
            Some("benchmark-isolated"),
            [],
        )
        .expect("fixture scope is valid"),
        completeness: SnapshotCompleteness::Complete,
        owner_completeness: OwnerCompleteness::Complete,
        evidence_gaps: Vec::new(),
        omitted_evidence_gap_count: 0,
        sockets,
        processes: HashMap::from([(owner, process)]),
    }
}

fn diff_scenario(name: &str) -> Option<(usize, bool, bool)> {
    match name {
        "empty" => Some((0, false, false)),
        "typical" => Some((TYPICAL, true, false)),
        "large" => Some((LARGE, true, false)),
        "maximum_same" => Some((SOCKET_OBSERVATIONS_MAX, false, false)),
        "maximum_replacement" => Some((SOCKET_OBSERVATIONS_MAX, true, true)),
        _ => None,
    }
}

fn run_diff(name: &str, count: usize, replacement: bool, disjoint_endpoints: bool) {
    let previous = snapshot(count, 0, identity(10_001, 20_001), 0);
    let current_owner = if replacement {
        identity(10_002, 20_002)
    } else {
        identity(10_001, 20_001)
    };
    let current_offset = if disjoint_endpoints { count } else { 0 };
    let current = snapshot(count, current_offset, current_owner, 2);
    let scanned_sockets = u64::try_from(
        previous
            .sockets
            .len()
            .checked_add(current.sockets.len())
            .expect("fixture socket count does not overflow"),
    )
    .expect("fixture socket count fits u64");
    let mut events = 0usize;
    let mut checksum = 0u64;
    let engine_started = Instant::now();
    for result in diff_snapshots(&previous, &current).expect("fixtures are diff-safe") {
        let event = result.expect("declared fixture cannot exceed the event bound");
        events += 1;
        checksum = checksum
            .wrapping_mul(1_099_511_628_211)
            .wrapping_add(u64::from(event.endpoint().port.get()))
            .wrapping_add(u64::from(event.multiplicity));
    }
    let engine_duration_ns = u64::try_from(engine_started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let expected = if disjoint_endpoints {
        count
            .checked_mul(2)
            .expect("fixture event count fits usize")
    } else if replacement {
        count
    } else {
        0
    };
    if events != expected {
        eprintln!("event count mismatch: expected {expected}, observed {events}");
        std::process::exit(1);
    }
    println!(
        "{{\"schema\":\"kickoutchi.release_diff_helper\",\"version\":1,\"scenario\":\"{name}\",\"input_sockets\":{count},\"scanned_sockets\":{scanned_sockets},\"events\":{events},\"iterator_exhausted\":true,\"checksum\":{checksum},\"engine_duration_ns\":{engine_duration_ns}}}"
    );
}

fn main() {
    let name = env::args().nth(1).unwrap_or_default();
    if let Some((count, replacement, disjoint_endpoints)) = diff_scenario(&name) {
        run_diff(&name, count, replacement, disjoint_endpoints);
        return;
    }
    if cli::watch::run_release_fixture(&name) {
        return;
    }
    eprintln!(
        "expected empty, typical, large, maximum_same, maximum_replacement, snapshot_large, snapshot_maximum, watch_high_churn, watch_transient_recovery, or watch_failure_exhaustion"
    );
    std::process::exit(2);
}
