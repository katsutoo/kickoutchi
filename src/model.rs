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

/// OS a row was collected on. Carried per-row so kill-command rendering can
/// show platform-correct commands without re-detecting the OS. All three
/// variants are declared now because they are part of the JSON contract;
/// `Windows`/`Macos` stay unconstructed until the optional native collectors
/// for those platforms are built.
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

/// Human-facing bind scope for local socket addresses.
///
/// Ordering is safety-oriented for `sort: scope`: public binds sort before
/// local interface binds, and loopback-only binds last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum BindScope {
    Public,
    Local,
    Loopback,
}

impl BindScope {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Local => "local",
            Self::Loopback => "loopback",
        }
    }
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

/// Extra context collected lazily for the selected process.
///
/// Keeping this outside [`PortEntry`] preserves the rule that table rows and
/// JSON output are OS-confirmed socket rows only; process-tree enrichment is a
/// selected-row detail, not part of the main snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ProcessContext {
    pub(crate) owner_uid: Option<u32>,
    pub(crate) children: ChildProcessSnapshot,
}

/// Bounded child-process list for one selected PID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct ChildProcessSnapshot {
    pub(crate) children: Vec<ChildProcess>,
    pub(crate) truncated: bool,
}

/// One child process directly parented by the selected PID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChildProcess {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
}

/// Evidence-only hint for the no-confirmed-socket diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelatedProcessHint {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
    pub(crate) command_line: String,
}

impl PortEntry {
    /// Exact port match, used by `list --port` and `kill --port`.
    pub(crate) fn matches_port(&self, port: u16) -> bool {
        self.local_port == port
    }

    /// Substring match on a pre-normalized process-name needle. Rows with no
    /// readable name never match: claiming a match on hidden data would be a
    /// guess.
    pub(crate) fn matches_process_normalized(&self, needle_lower: &str) -> bool {
        let Some(name) = &self.process_name else {
            return false;
        };
        name.to_lowercase().contains(needle_lower)
    }

    /// Human-facing bind scope for table/details output.
    pub(crate) fn scope(&self) -> BindScope {
        let addr = match self.local_addr {
            IpAddr::V4(addr) => IpAddr::V4(addr),
            IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
        };

        if addr.is_loopback() {
            BindScope::Loopback
        } else if addr.is_unspecified() {
            BindScope::Public
        } else {
            BindScope::Local
        }
    }

    /// Human-facing bind scope label for table/details output.
    pub(crate) fn scope_label(&self) -> &'static str {
        self.scope().label()
    }

    /// Best-effort system/service process classification for optional hiding.
    ///
    /// This is intentionally conservative: PID 0/1, direct children of PID 1,
    /// and a short list of well-known OS process names. Per-row owner UID is not
    /// collected (it is resolved lazily only for the selected row), so this
    /// table-wide classification cannot key on it. Protected app names such as
    /// `postgres` are not treated as system processes just because they are
    /// protected.
    pub(crate) fn is_system_process(&self) -> bool {
        if self.pid.is_some_and(|pid| pid <= 1) || self.parent_pid == Some(1) {
            return true;
        }

        self.process_name.as_deref().is_some_and(|name| {
            matches!(
                name,
                "systemd" | "launchd" | "init" | "explorer.exe" | "WindowServer"
            )
        })
    }
}

/// Table sort orders shared by the CLI and the TUI.
/// Deserialized from the config file (`default_sort = "port"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SortMode {
    Port,
    Pid,
    Protocol,
    Process,
    Parent,
    Scope,
}

impl SortMode {
    /// Lowercase label used in status output and config-facing text.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Pid => "pid",
            Self::Protocol => "protocol",
            Self::Process => "process",
            Self::Parent => "parent",
            Self::Scope => "scope",
        }
    }

    pub(crate) fn from_label(label: &str) -> Option<Self> {
        match label {
            "port" => Some(Self::Port),
            "pid" => Some(Self::Pid),
            "protocol" => Some(Self::Protocol),
            "process" => Some(Self::Process),
            "parent" => Some(Self::Parent),
            "scope" => Some(Self::Scope),
            _ => None,
        }
    }

    pub(crate) fn next(self) -> Self {
        match self {
            Self::Port => Self::Pid,
            Self::Pid => Self::Protocol,
            Self::Protocol => Self::Process,
            Self::Process => Self::Parent,
            Self::Parent => Self::Scope,
            Self::Scope => Self::Port,
        }
    }
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
            SortMode::Parent => {
                let name_a = a.parent_process_name.as_ref().map(|n| n.to_lowercase());
                let name_b = b.parent_process_name.as_ref().map(|n| n.to_lowercase());
                (
                    name_a.is_none(),
                    name_a,
                    a.parent_pid.is_none(),
                    a.parent_pid,
                )
                    .cmp(&(
                        name_b.is_none(),
                        name_b,
                        b.parent_pid.is_none(),
                        b.parent_pid,
                    ))
            }
            SortMode::Scope => a.scope().cmp(&b.scope()),
        };
        key.then_with(|| {
            (a.local_port, a.protocol, a.local_addr, a.pid).cmp(&(
                b.local_port,
                b.protocol,
                b.local_addr,
                b.pid,
            ))
        })
    });
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    use super::{
        BindScope, PermissionStatus, Platform, PortEntry, Protocol, SocketState, SortMode,
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
    fn normalized_process_filter_matches_substring() {
        let row = entry(3000, Some(1), Some("Node"));
        assert!(row.matches_process_normalized("node"));
        assert!(row.matches_process_normalized("od"));
        assert!(!row.matches_process_normalized("vite"));
        // A hidden name must never match: that would claim knowledge we lack.
        assert!(!entry(53, None, None).matches_process_normalized("node"));
    }

    #[test]
    fn scope_label_identifies_common_bind_shapes() {
        let mut row = entry(3000, Some(1), Some("node"));
        assert_eq!(row.scope_label(), "loopback");

        row.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert_eq!(row.scope_label(), "public");

        row.local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        assert_eq!(row.scope_label(), "local");

        row.local_addr = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001));
        assert_eq!(row.scope_label(), "loopback");
        assert_eq!(row.scope(), BindScope::Loopback);
    }

    #[test]
    fn sort_mode_labels_match_config_values() {
        assert_eq!(SortMode::Port.label(), "port");
        assert_eq!(SortMode::Pid.label(), "pid");
        assert_eq!(SortMode::Protocol.label(), "protocol");
        assert_eq!(SortMode::Process.label(), "process");
        assert_eq!(SortMode::Parent.label(), "parent");
        assert_eq!(SortMode::Scope.label(), "scope");
        assert_eq!(SortMode::from_label("parent"), Some(SortMode::Parent));
        assert_eq!(SortMode::from_label("unknown"), None);
        assert_eq!(SortMode::Scope.next(), SortMode::Port);
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
    fn sort_by_parent_uses_name_then_pid_with_unknown_last() {
        let mut rows = vec![
            entry(1, Some(1), Some("a")),
            entry(2, Some(2), Some("b")),
            entry(3, Some(3), Some("c")),
        ];
        rows[0].parent_process_name = None;
        rows[0].parent_pid = Some(99);
        rows[1].parent_process_name = Some("Zed".to_owned());
        rows[1].parent_pid = Some(10);
        rows[2].parent_process_name = Some("agent".to_owned());
        rows[2].parent_pid = Some(20);

        sort_entries(&mut rows, SortMode::Parent);

        assert_eq!(rows[0].parent_process_name.as_deref(), Some("agent"));
        assert_eq!(rows[1].parent_process_name.as_deref(), Some("Zed"));
        assert_eq!(rows[2].parent_pid, Some(99));
    }

    #[test]
    fn sort_by_scope_surfaces_public_binds_first() {
        let mut rows = vec![
            entry(1, Some(1), Some("loopback")),
            entry(2, Some(2), Some("local")),
            entry(3, Some(3), Some("public")),
        ];
        rows[1].local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        rows[2].local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

        sort_entries(&mut rows, SortMode::Scope);

        let names: Vec<&str> = rows
            .iter()
            .filter_map(|row| row.process_name.as_deref())
            .collect();
        assert_eq!(names, vec!["public", "local", "loopback"]);
    }

    #[test]
    fn system_process_classification_is_conservative() {
        let mut row = entry(5432, Some(1201), Some("postgres"));
        assert!(!row.is_system_process());

        row.parent_pid = Some(1);
        assert!(row.is_system_process());

        row.parent_pid = None;
        row.process_name = Some("systemd".to_owned());
        assert!(row.is_system_process());
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
