//! Collector abstraction and the fake data source.
//!
//! The trait fixes the contract every platform collector (Linux today,
//! optionally Windows/macOS later) must satisfy, so the CLI and TUI are wired
//! against `dyn`-free generic call sites today and swapping fake data for real
//! collection never touches the output layer.

#[cfg(any(test, not(target_os = "linux")))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use thiserror::Error;

use crate::model::PortEntry;
#[cfg(any(test, not(target_os = "linux")))]
use crate::model::{PermissionStatus, Platform, Protocol, SocketState};

/// Why a collection pass failed.
#[derive(Debug, Error)]
pub(crate) enum CollectorError {
    /// A required collection path could not be read. Per-process metadata
    /// failures are not fatal; they produce partial rows instead.
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// A source of open-port snapshots.
///
/// Implementations return a full snapshot per call; incremental updates are
/// deliberately not part of the contract because a snapshot is trivially
/// consistent and refresh happens at human cadence (seconds, not micros).
pub(crate) trait Collector {
    /// Collect the current open ports, in no particular order.
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError>;
}

/// Collect from the best collector for the current build target.
pub(crate) fn collect_ports() -> Result<Vec<PortEntry>, CollectorError> {
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::LinuxCollector::new().collect()
    }

    #[cfg(not(target_os = "linux"))]
    {
        FakeCollector.collect()
    }
}

/// Deterministic fake rows: the test fixture and the non-Linux fallback
/// collector (compiled for tests and for platforms without a native collector
/// yet).
///
/// The rows are chosen to exercise every rendering path the model allows:
/// full metadata, permission-restricted partial metadata, a default-protected
/// process name, IPv6, and a bound UDP socket.
#[cfg(any(test, not(target_os = "linux")))]
pub(crate) struct FakeCollector;

#[cfg(any(test, not(target_os = "linux")))]
impl Collector for FakeCollector {
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError> {
        Ok(fake_entries())
    }
}

/// The fake snapshot. Hardcodes [`Platform::Linux`] because the data is
/// invented, not host-derived; pretending to match the build target would
/// only make fake rows look more real than they are.
#[cfg(any(test, not(target_os = "linux")))]
fn fake_entries() -> Vec<PortEntry> {
    vec![
        // A typical dev server with full metadata, parent context, and
        // children: the row the core product flow is designed around.
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 3000,
            state: SocketState::Listen,
            pid: Some(18_422),
            process_name: Some("node".to_owned()),
            executable_path: Some("/usr/bin/node".into()),
            command_line: Some("node server.js".to_owned()),
            parent_pid: Some(18_001),
            parent_process_name: Some("cursor-agent".to_owned()),
            child_pids: vec![18_430, 18_431],
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        },
        // A second dev server so filters have something to exclude.
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 5173,
            state: SocketState::Listen,
            pid: Some(21_988),
            process_name: Some("vite".to_owned()),
            executable_path: Some("/usr/bin/node".into()),
            command_line: Some("node /usr/local/bin/vite --port 5173".to_owned()),
            parent_pid: Some(18_001),
            parent_process_name: Some("cursor-agent".to_owned()),
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        },
        // A name on the default protected list, running as another user the
        // realistic Linux way: name and command line are world-readable in
        // /proc, but /proc/<pid>/exe is not, hence the missing path and the
        // Partial status. `protected` starts false here because marking is
        // the pipeline's job (config-driven), not the collector's.
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 5432,
            state: SocketState::Listen,
            pid: Some(1_201),
            process_name: Some("postgres".to_owned()),
            executable_path: None,
            command_line: Some("/usr/lib/postgresql/16/bin/postgres".to_owned()),
            parent_pid: Some(1),
            parent_process_name: Some("systemd".to_owned()),
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Partial,
        },
        // IPv6 socket owned by another user: the port is visible but every
        // piece of process metadata is withheld. Exercises the "render the
        // row anyway and explain why it is empty" requirement.
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            local_port: 8080,
            state: SocketState::Listen,
            pid: None,
            process_name: None,
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Partial,
        },
        // Bound UDP socket: UDP has no listen state, so `Bound` is what
        // "open" means for it.
        PortEntry {
            protocol: Protocol::Udp,
            local_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port: 5353,
            state: SocketState::Bound,
            pid: Some(902),
            process_name: Some("avahi-daemon".to_owned()),
            executable_path: Some("/usr/bin/avahi-daemon".into()),
            command_line: Some("avahi-daemon: running [linux.local]".to_owned()),
            parent_pid: Some(1),
            parent_process_name: Some("systemd".to_owned()),
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::{Collector, FakeCollector};
    use crate::model::{PermissionStatus, Protocol, SocketState};

    #[test]
    fn fake_snapshot_covers_every_rendering_path() {
        let entries = FakeCollector
            .collect()
            .expect("fake collection cannot fail");

        // Port 3000 must exist: PROJECT.md's "done when" examples and the
        // CLI filter tests rely on it.
        assert!(entries.iter().any(|entry| entry.local_port == 3000));
        // At least one row with fully withheld metadata.
        assert!(
            entries
                .iter()
                .any(|entry| entry.pid.is_none() && entry.permission == PermissionStatus::Partial)
        );
        // And one partially withheld row: PID and name readable, executable
        // path hidden (the "another user's process" shape from PROJECT.md).
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
        // The collector never pre-marks protection; that is config's job.
        assert!(entries.iter().all(|entry| !entry.protected));
    }
}
