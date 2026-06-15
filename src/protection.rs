//! Protected-process matching policy.
//!
//! This module owns safety classification for names that require stronger
//! confirmation before termination. The collector only reports process facts;
//! protection is a user/config policy layered on top.

use crate::model::{Platform, PortEntry};

const DEFAULT_PROTECTED_PROCESS_NAMES: [&str; 5] = [
    "docker",
    "postgres",
    "systemd",
    "explorer.exe",
    "WindowServer",
];

pub(crate) fn default_protected_processes() -> Vec<String> {
    DEFAULT_PROTECTED_PROCESS_NAMES
        .iter()
        .map(|name| (*name).to_owned())
        .collect()
}

/// Flag entries whose process name is on the protected list.
pub(crate) fn mark_protected(entries: &mut [PortEntry], protected_names: &[String]) {
    for entry in entries.iter_mut() {
        let Some(name) = &entry.process_name else {
            continue;
        };
        if is_protected_process_name(entry.platform, name, protected_names) {
            entry.protected = true;
        }
    }
}

/// Platform-aware protected-name match.
///
/// Unix process names are exact and case-sensitive. Windows process names are
/// matched case-insensitively because that is the platform convention. Matching
/// is never substring-based: `postgres-backup-helper` must not inherit
/// `postgres` protection by accident.
pub(crate) fn is_protected_process_name(
    platform: Platform,
    process_name: &str,
    protected_names: &[String],
) -> bool {
    protected_names.iter().any(|protected| match platform {
        Platform::Windows => protected.eq_ignore_ascii_case(process_name),
        Platform::Linux | Platform::Macos => protected == process_name,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{default_protected_processes, is_protected_process_name, mark_protected};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    fn entry(port: u16, name: Option<&str>, platform: Platform) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: name.map(str::to_owned),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform,
            permission: PermissionStatus::Full,
        }
    }

    #[test]
    fn defaults_cover_documented_safety_names() {
        let defaults = default_protected_processes();
        assert!(defaults.contains(&"docker".to_owned()));
        assert!(defaults.contains(&"postgres".to_owned()));
        assert!(defaults.contains(&"systemd".to_owned()));
        assert!(defaults.contains(&"explorer.exe".to_owned()));
        assert!(defaults.contains(&"WindowServer".to_owned()));
    }

    #[test]
    fn unix_matching_is_exact_and_case_sensitive() {
        let protected = vec!["postgres".to_owned()];

        assert!(is_protected_process_name(
            Platform::Linux,
            "postgres",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            "Postgres",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Linux,
            "postgres-backup-helper",
            &protected
        ));
    }

    #[test]
    fn windows_matching_is_exact_but_case_insensitive() {
        let protected = vec!["explorer.exe".to_owned()];

        assert!(is_protected_process_name(
            Platform::Windows,
            "EXPLORER.EXE",
            &protected
        ));
        assert!(!is_protected_process_name(
            Platform::Windows,
            "explorer.exe.old",
            &protected
        ));
    }

    #[test]
    fn marking_skips_unknown_names_and_preserves_exactness() {
        let protected = vec!["postgres".to_owned()];
        let mut rows = vec![
            entry(5432, Some("postgres"), Platform::Linux),
            entry(5433, Some("postgres-backup-helper"), Platform::Linux),
            entry(53, None, Platform::Linux),
        ];

        mark_protected(&mut rows, &protected);

        assert!(rows[0].protected);
        assert!(!rows[1].protected);
        assert!(!rows[2].protected);
    }
}
