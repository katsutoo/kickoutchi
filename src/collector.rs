//! The collector contract, plus the fake data we lean on for tests.
//!
//! The trait pins down what every platform collector has to provide. The CLI and
//! TUI talk to that contract, so adding or swapping collectors never ripples out
//! into the output layer.

#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use thiserror::Error;

use crate::model::PortEntry;
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
use crate::model::{PermissionStatus, Platform, Protocol, SocketState};

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
}

/// Anything that can hand us a snapshot of the open ports.
///
/// Every call returns a full snapshot — no incremental updates, on purpose. A
/// whole snapshot is trivially self-consistent, and we refresh at human speed
/// (seconds, not microseconds), so the extra complexity would buy us nothing.
pub(crate) trait Collector {
    /// Grab the current open ports, in whatever order they turn up.
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError>;
}

/// Pick whichever collector fits the platform we were built for.
pub(crate) fn collect_ports() -> Result<Vec<PortEntry>, CollectorError> {
    #[cfg(target_os = "linux")]
    {
        crate::platform::linux::LinuxCollector::new().collect()
    }

    #[cfg(windows)]
    {
        crate::platform::windows::WindowsCollector.collect()
    }

    #[cfg(target_os = "macos")]
    {
        crate::platform::macos::MacosCollector.collect()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        FakeCollector.collect()
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
    fn collect(&self) -> Result<Vec<PortEntry>, CollectorError> {
        Ok(fake_entries())
    }
}

/// The fake snapshot. Everything is hardcoded to [`Platform::Linux`] because
/// this data is made up, not read from the host — dressing it up to match the
/// build target would just make pretend rows look more legit than they are.
#[cfg(any(test, not(any(target_os = "linux", target_os = "macos", windows))))]
fn fake_entries() -> Vec<PortEntry> {
    vec![
        // The classic dev server: full metadata, a parent, a couple of kids.
        // This is the row the whole product flow is built around.
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
        // A second dev server, so filters actually have something to exclude.
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
        // A name on the default protected list, running as another user the way
        // Linux actually does it: name and command line are world-readable in
        // /proc, but /proc/<pid>/exe isn't, so the path is missing and the status
        // is Partial. `protected` starts false here on purpose — tagging it is
        // the pipeline's job (driven by config), not the collector's.
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
        // IPv6 socket owned by someone else: we can see the port, but every
        // scrap of process metadata is off-limits. This is the "show the row
        // anyway and explain why it's empty" case.
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
        // Bound UDP socket: UDP has no listen state, so for UDP "bound" is the
        // closest thing to "open".
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
}
