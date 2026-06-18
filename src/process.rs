//! Process termination policy and platform signal delivery.
//!
//! This module owns the safety-critical boundary for termination: target snapshots,
//! confirmation requirements, PID guardrails, and the small Unix FFI call that
//! sends SIGTERM/SIGKILL. UI and CLI code decide *when* to ask the user; this
//! module decides what is safe to execute.

use std::net::IpAddr;

use crate::model::{PermissionStatus, Platform, PortEntry, ProcessContext, Protocol};

pub(crate) const CONFIRMATION_INPUT_MAX_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KillMode {
    Terminate,
    Force,
}

impl KillMode {
    pub(crate) fn action_label(self) -> &'static str {
        match self {
            Self::Terminate => "Terminate",
            Self::Force => "Force-kill",
        }
    }

    pub(crate) fn signal_label(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Force => "SIGKILL",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmationRequirement {
    Yes,
    ForceWord,
    ProtectedProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnsafePidReason {
    Zero,
    One,
    CurrentProcess,
}

impl UnsafePidReason {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Zero => "PID 0 is a process-group target, not one process",
            Self::One => "PID 1 is the init/system process",
            Self::CurrentProcess => "Kickoutchi cannot terminate itself",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TerminationOutcome {
    Success,
    PermissionDenied,
    OwnershipUnavailable,
    AlreadyExited,
    Cancelled,
    ProtectedProcess,
    TargetChanged,
    UnsafePid(UnsafePidReason),
    UnknownFailure(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KillTarget {
    pub(crate) pid: u32,
    pub(crate) process_name: Option<String>,
    pub(crate) platform: Platform,
    pub(crate) permission: PermissionStatus,
    pub(crate) protected: bool,
    pub(crate) system_process: bool,
    pub(crate) ports: Vec<KillTargetPort>,
    pub(crate) owner_uid: Option<u32>,
    pub(crate) process_start_time_ticks: Option<u64>,
    pub(crate) child_count: usize,
    pub(crate) children_truncated: bool,
}

impl KillTarget {
    pub(crate) fn from_entries<'a>(
        pid: u32,
        entries: impl IntoIterator<Item = &'a PortEntry>,
        context: Option<&ProcessContext>,
    ) -> Self {
        let mut process_name = None;
        let mut platform = Platform::Linux;
        let mut permission = PermissionStatus::Full;
        let mut protected = false;
        let mut system_process = false;
        let mut ports = Vec::new();
        let mut saw_entry = false;

        for entry in entries {
            saw_entry = true;
            debug_assert_eq!(entry.pid, Some(pid));
            if process_name.is_none() {
                process_name.clone_from(&entry.process_name);
            }
            platform = entry.platform;
            if entry.permission == PermissionStatus::Partial {
                permission = PermissionStatus::Partial;
            }
            protected |= entry.protected;
            system_process |= entry.is_system_process();
            ports.push(KillTargetPort::from(entry));
        }
        // A kill target with no rows would carry an empty port set, and the
        // confirmation/revalidation flow leans on those ports to identify the
        // process. Assert in release too (this runs once per kill request, not
        // on a hot path): an empty call is a programmer error, and a degenerate
        // target on a termination path is exactly what TigerStyle says to crash
        // on rather than carry forward silently.
        assert!(saw_entry, "kill target must contain at least one row");

        ports.sort_by(|left, right| {
            left.local_port
                .cmp(&right.local_port)
                .then_with(|| left.protocol.cmp(&right.protocol))
                .then_with(|| left.local_addr.cmp(&right.local_addr))
        });
        ports.dedup();

        let child_snapshot = context.map(|context| &context.children);
        Self {
            pid,
            process_name,
            platform,
            permission,
            protected,
            system_process,
            ports,
            owner_uid: context.and_then(|context| context.owner_uid),
            process_start_time_ticks: context.and_then(|context| context.process_start_time_ticks),
            child_count: child_snapshot.map_or(0, |snapshot| snapshot.children.len()),
            children_truncated: child_snapshot.is_some_and(|snapshot| snapshot.truncated),
        }
    }

    pub(crate) fn identity(&self) -> String {
        let name = self.process_name.as_deref().unwrap_or("<unknown>");
        format!("PID {} ({name})", self.pid)
    }

    pub(crate) fn process_name_or_unknown(&self) -> &str {
        self.process_name.as_deref().unwrap_or("<unknown>")
    }

    pub(crate) fn ports_text(&self) -> String {
        if self.ports.is_empty() {
            return "no visible open ports".to_owned();
        }
        self.ports
            .iter()
            .map(KillTargetPort::label)
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub(crate) fn has_children(&self) -> bool {
        self.child_count > 0 || self.children_truncated
    }

    pub(crate) fn warning_lines(&self) -> Vec<String> {
        let mut warnings = Vec::new();

        if self.protected {
            warnings.push("protected process; stronger confirmation is required".to_owned());
        }

        if self.system_process {
            warnings.push("system/service process; verify this is safe to terminate".to_owned());
        }

        let mut owner_warning_added = false;
        #[cfg(target_os = "linux")]
        if let Some(owner_uid) = self.owner_uid {
            let current_uid = current_user_id();
            if owner_uid != current_uid {
                warnings.push(format!(
                    "target is owned by uid {owner_uid}, current effective uid is {current_uid}",
                ));
                owner_warning_added = true;
            }
        }

        if !owner_warning_added && self.permission == PermissionStatus::Partial {
            warnings.push(
                "process metadata is partial; termination may fail with permission denied"
                    .to_owned(),
            );
        }

        if self.has_children() {
            let suffix = if self.children_truncated {
                " or more"
            } else {
                ""
            };
            warnings.push(format!(
                "target has {}{suffix} direct child process(es); tree-kill is not enabled",
                self.child_count,
            ));
        }

        warnings
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct KillTargetPort {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
}

impl KillTargetPort {
    fn label(&self) -> String {
        format!(
            "{} {}:{}",
            self.protocol.label(),
            self.local_addr,
            self.local_port,
        )
    }
}

impl From<&PortEntry> for KillTargetPort {
    fn from(entry: &PortEntry) -> Self {
        Self {
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
        }
    }
}

pub(crate) fn confirmation_requirement(
    protected: bool,
    mode: KillMode,
    yes: bool,
    confirm_force_kill: bool,
) -> Result<Option<ConfirmationRequirement>, TerminationOutcome> {
    if protected {
        if yes {
            return Err(TerminationOutcome::ProtectedProcess);
        }
        return Ok(Some(ConfirmationRequirement::ProtectedProcess));
    }

    if yes {
        return Ok(None);
    }

    if mode == KillMode::Force && confirm_force_kill {
        Ok(Some(ConfirmationRequirement::ForceWord))
    } else {
        Ok(Some(ConfirmationRequirement::Yes))
    }
}

pub(crate) fn confirmation_input_matches(
    input: &str,
    target: &KillTarget,
    requirement: ConfirmationRequirement,
) -> bool {
    let trimmed = input.trim();
    match requirement {
        ConfirmationRequirement::Yes => {
            trimmed.eq_ignore_ascii_case("y") || trimmed.eq_ignore_ascii_case("yes")
        }
        ConfirmationRequirement::ForceWord => trimmed == "force",
        ConfirmationRequirement::ProtectedProcess => {
            trimmed == target.pid.to_string()
                || target
                    .process_name
                    .as_deref()
                    .is_some_and(|name| trimmed == name)
        }
    }
}

pub(crate) fn target_still_matches_confirmation(
    confirmed: &KillTarget,
    fresh: &KillTarget,
) -> bool {
    if confirmed.pid != fresh.pid {
        return false;
    }
    if let Some(confirmed_name) = &confirmed.process_name {
        let Some(fresh_name) = &fresh.process_name else {
            return false;
        };
        if confirmed_name != fresh_name {
            return false;
        }
    }

    #[cfg(target_os = "linux")]
    {
        match (
            confirmed.process_start_time_ticks,
            fresh.process_start_time_ticks,
        ) {
            (Some(confirmed_start), Some(fresh_start)) if confirmed_start == fresh_start => {}
            _ => return false,
        }
    }

    confirmed
        .ports
        .iter()
        .all(|confirmed_port| fresh.ports.contains(confirmed_port))
}

pub(crate) fn revalidate_confirmed_target(
    confirmed: &KillTarget,
    fresh_entries: &[PortEntry],
    fresh_context: Option<&ProcessContext>,
) -> Result<KillTarget, TerminationOutcome> {
    if fresh_entries
        .iter()
        .any(|entry| entry.pid.is_none() && confirmed.ports.contains(&KillTargetPort::from(entry)))
    {
        return Err(TerminationOutcome::OwnershipUnavailable);
    }

    let rows = fresh_entries
        .iter()
        .filter(|entry| entry.pid == Some(confirmed.pid))
        .filter(|entry| confirmed.ports.contains(&KillTargetPort::from(*entry)))
        .collect::<Vec<_>>();
    if rows.is_empty() {
        return Err(TerminationOutcome::TargetChanged);
    }

    let fresh = KillTarget::from_entries(confirmed.pid, rows, fresh_context);
    if !target_still_matches_confirmation(confirmed, &fresh) {
        return Err(TerminationOutcome::TargetChanged);
    }
    if fresh.protected && !confirmed.protected {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(fresh)
}

pub(crate) fn unsafe_pid_reason(pid: u32) -> Option<UnsafePidReason> {
    match pid {
        0 => Some(UnsafePidReason::Zero),
        1 => Some(UnsafePidReason::One),
        pid if pid == std::process::id() => Some(UnsafePidReason::CurrentProcess),
        _ => None,
    }
}

pub(crate) fn terminate_pid(pid: u32, mode: KillMode) -> TerminationOutcome {
    if let Some(reason) = unsafe_pid_reason(pid) {
        return TerminationOutcome::UnsafePid(reason);
    }

    terminate_pid_platform(pid, mode)
}

#[cfg(target_os = "linux")]
fn current_user_id() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot invalidate memory; it
    // only returns the effective UID for this process.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "linux")]
fn terminate_pid_platform(pid: u32, mode: KillMode) -> TerminationOutcome {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return TerminationOutcome::UnknownFailure("PID does not fit platform pid_t".to_owned());
    };
    let signal = match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    };

    // SAFETY: pid has been range-checked for pid_t, signal is one of the two
    // constants supported by this module, and kill only crosses the OS boundary.
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        return TerminationOutcome::Success;
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TerminationOutcome::AlreadyExited,
        Some(code) if code == libc::EPERM => TerminationOutcome::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(error.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate_pid_platform(_pid: u32, _mode: KillMode) -> TerminationOutcome {
    TerminationOutcome::UnknownFailure(
        "termination is only implemented for the Linux collector".to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        ConfirmationRequirement, KillMode, KillTarget, TerminationOutcome, UnsafePidReason,
        confirmation_input_matches, confirmation_requirement, revalidate_confirmed_target,
        target_still_matches_confirmation, unsafe_pid_reason,
    };
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
        Protocol, SocketState,
    };

    fn entry(port: u16, protocol: Protocol) -> PortEntry {
        PortEntry {
            protocol,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: match protocol {
                Protocol::Tcp => SocketState::Listen,
                Protocol::Udp => SocketState::Bound,
            },
            pid: Some(18422),
            process_name: Some("node".to_owned()),
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

    fn context(start_time_ticks: u64) -> ProcessContext {
        ProcessContext {
            owner_uid: Some(1000),
            process_start_time_ticks: Some(start_time_ticks),
            children: ChildProcessSnapshot::default(),
        }
    }

    #[test]
    fn kill_target_names_every_visible_port_once() {
        let rows = [
            entry(3000, Protocol::Tcp),
            entry(3000, Protocol::Udp),
            entry(3000, Protocol::Tcp),
        ];
        let context = ProcessContext {
            owner_uid: Some(1000),
            process_start_time_ticks: Some(55),
            children: ChildProcessSnapshot {
                children: vec![ChildProcess {
                    pid: 18423,
                    process_name: Some("worker".to_owned()),
                }],
                truncated: false,
            },
        };

        let target = KillTarget::from_entries(18422, rows.iter(), Some(&context));

        assert_eq!(target.identity(), "PID 18422 (node)");
        assert_eq!(
            target.ports_text(),
            "TCP 127.0.0.1:3000, UDP 127.0.0.1:3000"
        );
        assert_eq!(target.owner_uid, Some(1000));
        assert_eq!(target.child_count, 1);
        assert!(target.has_children());
        assert!(
            target
                .warning_lines()
                .iter()
                .any(|line| line.contains("direct child")),
        );
    }

    #[test]
    fn kill_target_warns_for_system_processes() {
        let mut row = entry(3000, Protocol::Tcp);
        row.parent_pid = Some(1);

        let target = KillTarget::from_entries(18422, [&row], Some(&context(55)));

        assert!(target.system_process);
        assert!(
            target
                .warning_lines()
                .iter()
                .any(|line| line.contains("system/service process")),
        );
    }

    #[test]
    fn confirmation_requirements_keep_yes_from_bypassing_protected_processes() {
        assert_eq!(
            confirmation_requirement(false, KillMode::Terminate, true, true),
            Ok(None),
        );
        assert_eq!(
            confirmation_requirement(false, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(false, KillMode::Force, false, true),
            Ok(Some(ConfirmationRequirement::ForceWord)),
        );
        assert_eq!(
            confirmation_requirement(false, KillMode::Force, false, false),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(true, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::ProtectedProcess)),
        );
        assert_eq!(
            confirmation_requirement(true, KillMode::Terminate, true, true),
            Err(TerminationOutcome::ProtectedProcess),
        );
    }

    #[test]
    fn confirmation_input_is_specific_to_the_required_path() {
        let target = KillTarget::from_entries(
            18422,
            [entry(3000, Protocol::Tcp)].iter(),
            Some(&context(55)),
        );

        assert!(confirmation_input_matches(
            "yes",
            &target,
            ConfirmationRequirement::Yes,
        ));
        assert!(!confirmation_input_matches(
            "yes",
            &target,
            ConfirmationRequirement::ForceWord,
        ));
        assert!(confirmation_input_matches(
            "force",
            &target,
            ConfirmationRequirement::ForceWord,
        ));
        assert!(confirmation_input_matches(
            "18422",
            &target,
            ConfirmationRequirement::ProtectedProcess,
        ));
        assert!(confirmation_input_matches(
            "node",
            &target,
            ConfirmationRequirement::ProtectedProcess,
        ));
        assert!(!confirmation_input_matches(
            "NODE",
            &target,
            ConfirmationRequirement::ProtectedProcess,
        ));
    }

    #[test]
    fn unsafe_pid_guardrails_block_documented_targets() {
        assert_eq!(unsafe_pid_reason(0), Some(UnsafePidReason::Zero));
        assert_eq!(unsafe_pid_reason(1), Some(UnsafePidReason::One));
        assert_eq!(
            unsafe_pid_reason(std::process::id()),
            Some(UnsafePidReason::CurrentProcess),
        );
        assert_eq!(unsafe_pid_reason(u32::MAX), None);
    }

    #[test]
    fn revalidation_requires_same_pid_name_and_confirmed_ports() {
        let confirmed_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
        let confirmed = KillTarget::from_entries(18422, confirmed_rows.iter(), Some(&context(55)));

        let fresh_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
        let fresh = revalidate_confirmed_target(&confirmed, &fresh_rows, Some(&context(55)))
            .expect("same PID and ports are still valid");

        assert!(target_still_matches_confirmation(&confirmed, &fresh));
    }

    #[test]
    fn revalidation_rejects_missing_or_changed_targets() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[], Some(&context(55))),
            Err(TerminationOutcome::TargetChanged),
        );

        let mut changed_name = entry(3000, Protocol::Tcp);
        changed_name.process_name = Some("other".to_owned());
        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[changed_name], Some(&context(55))),
            Err(TerminationOutcome::TargetChanged),
        );

        let mut missing_name = entry(3000, Protocol::Tcp);
        missing_name.process_name = None;
        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[missing_name], Some(&context(55))),
            Err(TerminationOutcome::TargetChanged),
        );

        let changed_port = entry(4000, Protocol::Tcp);
        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[changed_port], Some(&context(55))),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_rejects_pid_reuse_with_changed_start_time() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));
        let fresh_row = entry(3000, Protocol::Tcp);

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[fresh_row], Some(&context(99))),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_rejects_missing_start_time_identity() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));
        let fresh_row = entry(3000, Protocol::Tcp);

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[fresh_row], None),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_reports_ownership_unavailable_when_owning_pid_becomes_unreadable() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));

        // The confirmed port is still listening, but its owner can no longer be
        // mapped to a PID: that is permission/ownership loss, not a moved target.
        let mut unreadable = entry(3000, Protocol::Tcp);
        unreadable.pid = None;
        unreadable.permission = PermissionStatus::Partial;

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[unreadable], Some(&context(55))),
            Err(TerminationOutcome::OwnershipUnavailable),
        );
    }

    #[test]
    fn revalidation_reports_ownership_unavailable_when_any_confirmed_port_loses_pid() {
        let confirmed_rows = [entry(3000, Protocol::Tcp), entry(3000, Protocol::Udp)];
        let confirmed = KillTarget::from_entries(18422, confirmed_rows.iter(), Some(&context(55)));
        let mut unreadable_udp = entry(3000, Protocol::Udp);
        unreadable_udp.pid = None;
        unreadable_udp.permission = PermissionStatus::Partial;

        assert_eq!(
            revalidate_confirmed_target(
                &confirmed,
                &[entry(3000, Protocol::Tcp), unreadable_udp],
                Some(&context(55)),
            ),
            Err(TerminationOutcome::OwnershipUnavailable),
        );
    }

    #[test]
    fn revalidation_rejects_targets_that_become_protected() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));
        let mut protected = entry(3000, Protocol::Tcp);
        protected.protected = true;

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[protected], Some(&context(55))),
            Err(TerminationOutcome::ProtectedProcess),
        );
    }
}
