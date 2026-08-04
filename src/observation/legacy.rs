//! Projection from authoritative snapshots into the legacy `PortEntry` view.

use crate::model::{PermissionStatus, Platform, PortEntry, SocketState as LegacySocketState};

use super::{
    DERIVED_PORT_ENTRIES_MAX, MetadataCompleteness, NetworkSnapshot, ObservationError,
    OwnerObservation, ProcessIdentity, ProcessObservation, SocketObservation, SocketState,
    snapshot_platform,
};

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

pub(super) fn project_legacy_with_limit(
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

pub(super) const fn owner_pid(owner: &OwnerObservation) -> u32 {
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
