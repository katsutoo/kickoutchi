//! Shared domain model: the types the CLI, TUI, collectors, filters, and the
//! future kill flow all exchange.
//!
//! Every collector returns the same [`PortEntry`] shape so platform weirdness
//! stays inside `platform/` and the rest of the app reasons about one model.
//! The serde derives define the stable JSON contract for `list --json`:
//! renaming a field or enum variant here is a breaking change for scripts.

use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Transport protocol of a socket row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    /// Uppercase label for table output.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }
}

/// Socket state Kickoutchi considers "open".
///
/// Only two states exist by design: a TCP socket counts when it is listening,
/// and a UDP socket counts when it is bound (UDP has no listen state).
/// Established-connection visibility is a possible later filter, not part of
/// the core model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SocketState {
    Listen,
    Bound,
}

impl SocketState {
    /// Uppercase label for table output.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Listen => "LISTEN",
            Self::Bound => "BOUND",
        }
    }
}

/// OS a row was collected on. Carried per-row so the kill-command rendering
/// (Phase 6/9) can show platform-correct commands without re-detecting the OS.
/// All three variants are declared now because they are part of the JSON
/// contract; `Windows`/`Macos` are first constructed by the optional Phase 7/8
/// collectors.
#[allow(
    dead_code,
    reason = "windows/macos are contract variants until their collectors land"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    Linux,
    Windows,
    Macos,
}

/// How much process metadata the collector could read for a row.
///
/// Ports must still appear when metadata is restricted, so this status exists
/// to let the UI and CLI *explain* missing fields instead of hiding the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PermissionStatus {
    /// All process metadata was readable.
    Full,
    /// The socket is visible but some process metadata was not readable,
    /// typically because the process belongs to another user.
    Partial,
}

/// One open port and everything known about its owning process.
///
/// `Option` fields are `None` when the OS withheld the data; `permission`
/// records that this happened so consumers can tell "no value" apart from
/// "not allowed to know".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PortEntry {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) state: SocketState,
    pub(crate) pid: Option<u32>,
    pub(crate) process_name: Option<String>,
    pub(crate) executable_path: Option<PathBuf>,
    pub(crate) command_line: Option<String>,
    pub(crate) parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<String>,
    /// Resolved lazily for the selected row only; empty does not mean "no
    /// children", it can mean "not asked yet" (see PROJECT.md collection note).
    pub(crate) child_pids: Vec<u32>,
    pub(crate) protected: bool,
    pub(crate) platform: Platform,
    pub(crate) permission: PermissionStatus,
}

impl PortEntry {
    /// Exact port match, used by `list --port` and `kill --port`.
    pub(crate) fn matches_port(&self, port: u16) -> bool {
        self.local_port == port
    }

    /// Case-insensitive substring match on the process name, used by
    /// `list --process`. Substring (not exact) because users type fragments
    /// like `node`; case-insensitive because casing of process names is an OS
    /// detail users should not have to remember. Rows with no readable name
    /// never match: claiming a match on hidden data would be a guess.
    pub(crate) fn matches_process(&self, needle: &str) -> bool {
        let Some(name) = &self.process_name else {
            return false;
        };
        name.to_lowercase().contains(&needle.to_lowercase())
    }
}

/// Table sort orders shared by the CLI now and the TUI in Phase 4.
/// Deserialized from the config file (`default_sort = "port"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SortMode {
    Port,
    Pid,
    Protocol,
    Process,
}

/// Sort entries in place by the given mode.
///
/// Every mode falls back to (port, protocol) so the order is total and stable
/// across refreshes: equal keys must not reshuffle, or the future TUI table
/// would jitter. Rows missing the sort key (`None` PID or name) sort last so
/// the most informative rows surface first.
pub(crate) fn sort_entries(entries: &mut [PortEntry], mode: SortMode) {
    entries.sort_by(|a, b| {
        let key = match mode {
            SortMode::Port => std::cmp::Ordering::Equal,
            SortMode::Pid => (a.pid.is_none(), a.pid).cmp(&(b.pid.is_none(), b.pid)),
            SortMode::Protocol => a.protocol.cmp(&b.protocol),
            SortMode::Process => {
                let name_a = a.process_name.as_ref().map(|n| n.to_lowercase());
                let name_b = b.process_name.as_ref().map(|n| n.to_lowercase());
                (name_a.is_none(), name_a).cmp(&(name_b.is_none(), name_b))
            }
        };
        key.then_with(|| (a.local_port, a.protocol).cmp(&(b.local_port, b.protocol)))
    });
}

/// Flag entries whose process name is on the protected list.
///
/// Matching is exact and case-sensitive: this is the Unix convention from
/// PROJECT.md, and a substring rule would over-protect (a user process named
/// `postgres-backup-helper` must not inherit `postgres` protection and block
/// its own termination path). Platform-aware matching (case-insensitive on
/// Windows) moves into `protection.rs` in Phase 5.
pub(crate) fn mark_protected(entries: &mut [PortEntry], protected_names: &[String]) {
    for entry in entries.iter_mut() {
        let Some(name) = &entry.process_name else {
            continue;
        };
        if protected_names.iter().any(|protected| protected == name) {
            entry.protected = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;

    use super::{
        PermissionStatus, Platform, PortEntry, Protocol, SocketState, SortMode, mark_protected,
        sort_entries,
    };

    /// Minimal entry builder so each test states only the fields it cares about.
    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: name.map(str::to_owned),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    #[test]
    fn port_filter_is_exact() {
        let row = entry(3000, Some(1), Some("node"));
        assert!(row.matches_port(3000));
        assert!(!row.matches_port(300));
    }

    #[test]
    fn process_filter_is_case_insensitive_substring() {
        let row = entry(3000, Some(1), Some("Node"));
        assert!(row.matches_process("node"));
        assert!(row.matches_process("od"));
        assert!(!row.matches_process("vite"));
        // A hidden name must never match: that would claim knowledge we lack.
        assert!(!entry(53, None, None).matches_process("node"));
    }

    #[test]
    fn sort_by_port_orders_ascending() {
        let mut rows = vec![
            entry(5173, Some(2), Some("vite")),
            entry(80, Some(1), Some("nginx")),
        ];
        sort_entries(&mut rows, SortMode::Port);
        assert_eq!(rows[0].local_port, 80);
        assert_eq!(rows[1].local_port, 5173);
    }

    #[test]
    fn sort_by_pid_puts_unknown_pids_last() {
        let mut rows = vec![
            entry(53, None, None),
            entry(5173, Some(2), Some("vite")),
            entry(3000, Some(900), Some("node")),
        ];
        sort_entries(&mut rows, SortMode::Pid);
        assert_eq!(rows[0].pid, Some(2));
        assert_eq!(rows[1].pid, Some(900));
        assert_eq!(rows[2].pid, None);
    }

    #[test]
    fn sort_by_process_is_case_insensitive_with_unknown_last() {
        let mut rows = vec![
            entry(1, None, None),
            entry(2, Some(1), Some("Vite")),
            entry(3, Some(2), Some("node")),
        ];
        sort_entries(&mut rows, SortMode::Process);
        assert_eq!(rows[0].process_name.as_deref(), Some("node"));
        assert_eq!(rows[1].process_name.as_deref(), Some("Vite"));
        assert_eq!(rows[2].process_name, None);
    }

    #[test]
    fn equal_sort_keys_fall_back_to_port_order() {
        // Same protocol everywhere, so the protocol sort must still produce a
        // deterministic order via the (port, protocol) tie-breaker.
        let mut rows = vec![
            entry(5173, Some(2), Some("vite")),
            entry(80, Some(1), Some("nginx")),
            entry(3000, Some(3), Some("node")),
        ];
        sort_entries(&mut rows, SortMode::Protocol);
        let ports: Vec<u16> = rows.iter().map(|row| row.local_port).collect();
        assert_eq!(ports, vec![80, 3000, 5173]);
    }

    #[test]
    fn protection_marking_is_exact_not_substring() {
        let protected = vec!["postgres".to_owned()];
        let mut rows = vec![
            entry(5432, Some(1), Some("postgres")),
            entry(5433, Some(2), Some("postgres-backup-helper")),
            entry(53, None, None),
        ];
        mark_protected(&mut rows, &protected);
        assert!(rows[0].protected);
        assert!(!rows[1].protected);
        assert!(!rows[2].protected);
    }

    #[test]
    fn json_shape_is_stable() {
        // This pins the script-facing JSON contract: field names, enum casing,
        // and null handling. Changing any assertion here is a breaking change.
        let mut row = entry(3000, Some(18422), Some("node"));
        row.executable_path = Some(PathBuf::from("/usr/bin/node"));
        row.command_line = Some("node server.js".to_owned());
        row.parent_pid = Some(18001);
        row.parent_process_name = Some("cursor-agent".to_owned());
        row.child_pids = vec![18430];

        let value = serde_json::to_value(&row).expect("PortEntry must serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "protocol": "tcp",
                "local_addr": "127.0.0.1",
                "local_port": 3000,
                "state": "listen",
                "pid": 18422,
                "process_name": "node",
                "executable_path": "/usr/bin/node",
                "command_line": "node server.js",
                "parent_pid": 18001,
                "parent_process_name": "cursor-agent",
                "child_pids": [18430],
                "protected": false,
                "platform": "linux",
                "permission": "full",
            })
        );
    }

    #[test]
    fn json_renders_missing_metadata_as_null() {
        let value = serde_json::to_value(entry(53, None, None)).expect("must serialize");
        assert_eq!(value["pid"], serde_json::Value::Null);
        assert_eq!(value["process_name"], serde_json::Value::Null);
        assert_eq!(value["executable_path"], serde_json::Value::Null);
    }
}
