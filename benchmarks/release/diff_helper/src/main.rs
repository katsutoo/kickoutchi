#![allow(dead_code)]

#[path = "../../../../src/model.rs"]
mod model;
#[path = "../../../../src/observation.rs"]
mod observation;
#[path = "../../../../src/protection.rs"]
mod protection;
#[path = "../../../../src/watch.rs"]
mod watch;

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

fn identity(pid: u32, marker: u64) -> ProcessIdentity {
    ProcessIdentity {
        pid,
        start_marker: ProcessStartMarker::linux(marker).expect("fixture marker is nonzero"),
    }
}

fn snapshot(count: usize, endpoint_offset: usize, owner: ProcessIdentity) -> NetworkSnapshot {
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
        capture_started_at: SystemTime::UNIX_EPOCH,
        capture_completed_at: SystemTime::UNIX_EPOCH + Duration::from_millis(1),
        scope: ObservationScope::new(
            ObservationScopeKind::CurrentNetworkNamespace,
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

fn scenario(name: &str) -> Option<(usize, bool, bool)> {
    match name {
        "empty" => Some((0, false, false)),
        "typical" => Some((TYPICAL, true, false)),
        "large" => Some((LARGE, true, false)),
        "maximum_same" => Some((SOCKET_OBSERVATIONS_MAX, false, false)),
        "maximum_replacement" => Some((SOCKET_OBSERVATIONS_MAX, true, true)),
        _ => None,
    }
}

fn main() {
    let name = env::args().nth(1).unwrap_or_default();
    let Some((count, replacement, disjoint_endpoints)) = scenario(&name) else {
        eprintln!("expected empty, typical, large, maximum_same, or maximum_replacement");
        std::process::exit(2);
    };
    let previous = snapshot(count, 0, identity(10_001, 20_001));
    let current_owner = if replacement {
        identity(10_002, 20_002)
    } else {
        identity(10_001, 20_001)
    };
    let current_offset = if disjoint_endpoints { count } else { 0 };
    let current = snapshot(count, current_offset, current_owner);
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
