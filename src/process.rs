//! The "are we really doing this?" brain, plus the actual signal delivery.
//!
//! This is the safety-critical side of termination: target snapshots,
//! confirmation rules, PID guardrails, and the tiny OS FFI paths that send the
//! final stop request. The UI and CLI decide *when* to ask the user; this module
//! decides what's actually safe to run. When in doubt, it says no.

use std::net::IpAddr;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, STILL_ACTIVE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::display::sanitize;
use crate::model::{
    PermissionStatus, Platform, PortEntry, PortEntryView, ProcessContext, Protocol,
};
use crate::observation::{Ipv6Scope, ProcessIdentity, ProcessStartMarker};
use crate::process_evidence::{
    ExpectedProcessEvidence, FreshProcessEvidence, ProcessEvidenceError, ProcessEvidenceScope,
};
use crate::protection::{is_protected_process_name, windows_process_name_eq};

pub(crate) const CONFIRMATION_INPUT_MAX_BYTES: usize = 128;

/// Suffix appended to permission-denied termination messages.
///
/// `EPERM`/`EACCES` from the pidfd syscalls almost always means a genuine lack of
/// permission to signal the target (same rule as `kill`), but a sandbox or
/// seccomp policy that blocks `pidfd_open`/`pidfd_send_signal` produces the same
/// errno. We can't tell the two apart at this layer, so the message names both.
pub(crate) const PERMISSION_DENIED_SANDBOX_HINT: &str =
    "a sandbox or seccomp policy blocking the pidfd syscalls can also cause this";

pub(crate) fn permission_denied_hint(platform: Platform) -> &'static str {
    match platform {
        Platform::Linux => PERMISSION_DENIED_SANDBOX_HINT,
        Platform::Windows => {
            "try an elevated terminal; protected or higher-integrity processes can also reject TerminateProcess"
        }
        Platform::Macos => "try again with sufficient privileges",
    }
}

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

    pub(crate) fn action_label_for(self, _platform: Platform) -> &'static str {
        self.action_label()
    }

    pub(crate) fn signal_label(self) -> &'static str {
        match self {
            Self::Terminate => "SIGTERM",
            Self::Force => "SIGKILL",
        }
    }

    pub(crate) fn delivery_label(self, platform: Platform) -> &'static str {
        match platform {
            Platform::Linux | Platform::Macos => self.signal_label(),
            Platform::Windows => "TerminateProcess",
        }
    }

    pub(crate) fn force_warning(self, platform: Platform) -> Option<&'static str> {
        match (platform, self) {
            (Platform::Linux | Platform::Macos, Self::Force) => {
                Some("SIGKILL is immediate; prefer normal termination first.")
            }
            (Platform::Windows, Self::Terminate) => Some(
                "Windows termination uses TerminateProcess, which is immediate; close the app normally first when possible.",
            ),
            (Platform::Windows, Self::Force) => Some(
                "TerminateProcess is immediate; use force only when normal termination did not work.",
            ),
            (Platform::Linux | Platform::Macos, Self::Terminate) => None,
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
    #[cfg(windows)]
    WindowsSystem,
    CurrentProcess,
}

impl UnsafePidReason {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Zero => "PID 0 is a process-group target, not one process",
            Self::One => "PID 1 is the init/system process",
            #[cfg(windows)]
            Self::WindowsSystem => "PID 4 is the Windows System process",
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
    #[allow(dead_code, reason = "constructed only by Unix thaw handling")]
    ThawFailed {
        pid: u32,
        prior: Box<TerminationOutcome>,
    },
}

#[derive(Debug)]
pub(crate) struct TerminationHandle {
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(windows)]
    process_handle: OwnedHandle,
    #[cfg(target_os = "macos")]
    process_start_time_marker: ProcessStartMarker,
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    _unsupported: (),
}

impl TerminationHandle {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
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
    pub(crate) process_start_time_marker: Option<ProcessStartMarker>,
    pub(crate) child_count: usize,
    pub(crate) children_truncated: bool,
}

impl KillTarget {
    pub(crate) fn from_entry_views<'a>(
        pid: u32,
        entries: impl IntoIterator<Item = PortEntryView<'a>>,
        context: Option<&ProcessContext>,
    ) -> Self {
        let mut process_name = None;
        let mut platform = Platform::Linux;
        let mut permission = PermissionStatus::Full;
        let mut protected = false;
        let mut system_process = false;
        let mut ports = Vec::new();
        let mut process_identity: Option<ProcessIdentity> = None;
        let mut identity_consistent = true;
        let mut saw_entry = false;
        for entry in entries {
            saw_entry = true;
            assert_eq!(
                entry.pid,
                Some(pid),
                "kill target row PID must match target PID"
            );
            if process_name.is_none() {
                process_name = entry.process_name.map(str::to_owned);
            }
            platform = entry.platform;
            if entry.permission == PermissionStatus::Partial {
                permission = PermissionStatus::Partial;
            }
            protected |= entry.protected;
            system_process |= entry.is_system_process();
            if let Some(identity) = entry.process_identity {
                identity_consistent &= identity.pid == pid
                    && process_identity.is_none_or(|existing| existing == identity);
                process_identity.get_or_insert(identity);
            } else {
                identity_consistent = false;
            }
            ports.push(KillTargetPort {
                protocol: entry.protocol,
                local_addr: entry.local_addr,
                local_port: entry.local_port,
                ipv6_scope: entry.ipv6_scope,
            });
        }
        assert!(saw_entry, "kill target must contain at least one row");
        ports.sort_unstable();
        ports.dedup();
        let children = context.map(|context| &context.children);
        Self {
            pid,
            process_name,
            platform,
            permission,
            protected,
            system_process,
            ports,
            owner_uid: context.and_then(|context| context.owner_uid),
            process_start_time_marker: identity_consistent
                .then_some(process_identity)
                .flatten()
                .map(|identity| identity.start_marker),
            child_count: children.map_or(0, |children| children.children.len()),
            children_truncated: children.is_some_and(|children| children.truncated),
        }
    }

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
        let mut process_identity: Option<ProcessIdentity> = None;
        let mut identity_consistent = true;
        let mut saw_entry = false;

        for entry in entries {
            saw_entry = true;
            assert_eq!(
                entry.pid,
                Some(pid),
                "kill target row PID must match target PID",
            );
            if process_name.is_none() {
                process_name = entry.process_name.as_deref().map(str::to_owned);
            }
            platform = entry.platform;
            if entry.permission == PermissionStatus::Partial {
                permission = PermissionStatus::Partial;
            }
            protected |= entry.protected;
            system_process |= entry.is_system_process();
            if let Some(identity) = entry.process_identity {
                identity_consistent &= identity.pid == pid
                    && process_identity.is_none_or(|existing| existing == identity);
                process_identity.get_or_insert(identity);
            } else {
                identity_consistent = false;
            }
            ports.push(KillTargetPort::from(entry));
        }
        // A kill target with no rows would carry an empty port set, and the
        // confirmation/revalidation flow leans on those ports to know which
        // process it's even looking at. We assert in release too (this runs once
        // per kill request, not on a hot path): calling this with zero rows is a
        // programmer bug, and a port-less target sitting on a termination path is
        // exactly the kind of thing you want to crash on, not quietly wave
        // through.
        assert!(saw_entry, "kill target must contain at least one row");

        ports.sort_unstable();
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
            process_start_time_marker: identity_consistent
                .then_some(process_identity)
                .flatten()
                .map(|identity| identity.start_marker),
            child_count: child_snapshot.map_or(0, |snapshot| snapshot.children.len()),
            children_truncated: child_snapshot.is_some_and(|snapshot| snapshot.truncated),
        }
    }

    pub(crate) fn identity(&self) -> String {
        format!(
            "PID {} ({})",
            self.pid,
            sanitize(self.process_name.as_deref().unwrap_or("<unknown>"))
        )
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

    /// The typed warnings attached to this target. Policy gates (for example
    /// the `--yes` all-clear check) match on these kinds; display surfaces
    /// render them through [`KillWarning::text`] via [`Self::warning_lines`],
    /// so the gate and the prose can never drift apart.
    pub(crate) fn warnings(&self) -> Vec<KillWarning> {
        let mut warnings = Vec::new();

        if self.protected {
            warnings.push(KillWarning::Protected);
        }

        if self.system_process {
            warnings.push(KillWarning::SystemProcess);
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let owner_mismatch = self.owner_uid.and_then(|owner_uid| {
            let current_uid = current_user_id();
            (owner_uid != current_uid).then_some(KillWarning::OwnerMismatch {
                owner_uid,
                current_uid,
            })
        });
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let owner_mismatch: Option<KillWarning> = None;

        let owner_mismatch_reported = owner_mismatch.is_some();
        if let Some(warning) = owner_mismatch {
            warnings.push(warning);
        }

        if !owner_mismatch_reported && self.permission == PermissionStatus::Partial {
            warnings.push(KillWarning::PartialMetadata);
        }

        if self.has_children() {
            warnings.push(KillWarning::HasChildren {
                child_count: self.child_count,
                children_truncated: self.children_truncated,
            });
        }

        warnings
    }

    pub(crate) fn warning_lines(&self) -> Vec<String> {
        self.warnings().iter().map(KillWarning::text).collect()
    }
}

/// One warning attached to a kill target, typed so policy can match on the
/// kind instead of on banner prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KillWarning {
    Protected,
    SystemProcess,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    OwnerMismatch {
        owner_uid: u32,
        current_uid: u32,
    },
    PartialMetadata,
    HasChildren {
        child_count: usize,
        children_truncated: bool,
    },
}

impl KillWarning {
    /// The single-kill banner wording. Tree and group surfaces rewrite the
    /// process-scope suffix through [`tree_scope_warning_text`].
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Protected => "protected process; stronger confirmation is required".to_owned(),
            Self::SystemProcess => {
                "system/service process; verify this is safe to terminate".to_owned()
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Self::OwnerMismatch {
                owner_uid,
                current_uid,
            } => format!(
                "target is owned by uid {owner_uid}, current effective uid is {current_uid}",
            ),
            Self::PartialMetadata => {
                "process metadata is partial; termination may fail with permission denied"
                    .to_owned()
            }
            Self::HasChildren {
                child_count,
                children_truncated,
            } => {
                let suffix = if *children_truncated { " or more" } else { "" };
                format!(
                    "target has {child_count}{suffix} direct child process(es); termination targets only the confirmed PID",
                )
            }
        }
    }
}

/// Rewrite a single-kill warning line for tree scope.
///
/// `KillTarget::warning_lines` tells single-kill users that children survive
/// ("termination targets only the confirmed PID") — under `--tree` that exact
/// sentence would be false, so the tree surfaces (CLI banner and TUI modal)
/// route every root warning through here. It lives beside `warning_lines` so
/// the suffix it strips and the text that produces it cannot drift apart.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
pub(crate) fn tree_scope_warning_text(warning: &str) -> String {
    scoped_warning_text(
        warning,
        "tree kill targets the bounded descendant tree shown above",
    )
}

/// Rewrite a single-kill warning line for group scope; see
/// [`tree_scope_warning_text`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn group_scope_warning_text(warning: &str) -> String {
    scoped_warning_text(warning, "group kill targets every group member shown above")
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn scoped_warning_text(warning: &str, scope_clause: &str) -> String {
    const PROCESS_SCOPE_SUFFIX: &str = "; termination targets only the confirmed PID";
    if let Some(prefix) = warning.strip_suffix(PROCESS_SCOPE_SUFFIX) {
        format!("{prefix}; {scope_clause}")
    } else {
        warning.to_owned()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KillTargetPort {
    pub(crate) protocol: Protocol,
    pub(crate) local_addr: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) ipv6_scope: Option<Ipv6Scope>,
}

impl Ord for KillTargetPort {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            self.local_port,
            self.protocol,
            self.local_addr,
            self.ipv6_scope,
        )
            .cmp(&(
                other.local_port,
                other.protocol,
                other.local_addr,
                other.ipv6_scope,
            ))
    }
}

impl PartialOrd for KillTargetPort {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
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

pub(crate) fn kill_target_has_port(ports: &[KillTargetPort], port: &KillTargetPort) -> bool {
    ports.binary_search(port).is_ok()
}

impl From<&PortEntry> for KillTargetPort {
    fn from(entry: &PortEntry) -> Self {
        Self {
            protocol: entry.protocol,
            local_addr: entry.local_addr,
            local_port: entry.local_port,
            ipv6_scope: entry.ipv6_scope,
        }
    }
}

pub(crate) fn confirmation_requirement(
    protected: bool,
    _platform: Platform,
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
        ConfirmationRequirement::ForceWord => trimmed.eq_ignore_ascii_case("force"),
        ConfirmationRequirement::ProtectedProcess => {
            trimmed == target.pid.to_string()
                || target
                    .process_name
                    .as_deref()
                    .is_some_and(|name| match target.platform {
                        Platform::Windows => windows_process_name_eq(trimmed, &sanitize(name)),
                        Platform::Linux | Platform::Macos => trimmed == sanitize(name),
                    })
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

    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        match (
            confirmed.process_start_time_marker,
            fresh.process_start_time_marker,
        ) {
            (Some(confirmed_start), Some(fresh_start)) if confirmed_start == fresh_start => {}
            _ => return false,
        }
    }

    confirmed
        .ports
        .iter()
        .all(|confirmed_port| kill_target_has_port(&fresh.ports, confirmed_port))
}

/// True when a confirmed target port is still visible but its owning PID is no
/// longer readable.
///
/// Both kill surfaces (CLI `--pid`/`--port` and the TUI) treat this as ownership
/// loss and bail out without signalling, instead of calling it a moved target:
/// the exact port the user confirmed is still listening, we just can't prove who
/// owns it anymore, so firing a signal now could hit the wrong process. One
/// shared check keeps those surfaces from drifting apart on this safety line.
pub(crate) fn confirmed_port_owner_unavailable(
    confirmed: &KillTarget,
    fresh_entries: &[PortEntry],
) -> bool {
    fresh_entries.iter().any(|entry| {
        entry.pid.is_none() && kill_target_has_port(&confirmed.ports, &KillTargetPort::from(entry))
    })
}

pub(crate) fn revalidate_confirmed_target(
    confirmed: &KillTarget,
    fresh_entries: &[PortEntry],
    fresh_context: Option<&ProcessContext>,
) -> Result<KillTarget, TerminationOutcome> {
    if confirmed_port_owner_unavailable(confirmed, fresh_entries) {
        return Err(TerminationOutcome::OwnershipUnavailable);
    }

    let rows = fresh_entries
        .iter()
        .filter(|entry| entry.pid == Some(confirmed.pid))
        .filter(|entry| kill_target_has_port(&confirmed.ports, &KillTargetPort::from(*entry)))
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

pub(crate) fn validate_single_delivery_evidence(
    confirmed: &KillTarget,
    fresh: &KillTarget,
) -> Result<(), TerminationOutcome> {
    let expected_marker = confirmed
        .process_start_time_marker
        .ok_or(TerminationOutcome::TargetChanged)?;
    let fresh_marker = fresh
        .process_start_time_marker
        .ok_or(TerminationOutcome::TargetChanged)?;
    let fresh_name = fresh.process_name.clone().ok_or_else(|| {
        TerminationOutcome::UnknownFailure(
            "fresh process name evidence is missing; refusing termination".to_owned(),
        )
    })?;
    let expected = ExpectedProcessEvidence {
        pid: confirmed.pid,
        start_marker: expected_marker,
        name: confirmed.process_name.as_deref(),
    };
    let mut scope = ProcessEvidenceScope::new(1).map_err(single_evidence_outcome)?;
    scope
        .observe(
            &expected,
            Ok(FreshProcessEvidence {
                pid: fresh.pid,
                start_marker: fresh_marker,
                name: fresh_name,
            }),
        )
        .map_err(single_evidence_outcome)?;
    scope.finish().map_err(single_evidence_outcome)
}

fn single_evidence_outcome(error: ProcessEvidenceError) -> TerminationOutcome {
    match error {
        ProcessEvidenceError::PermissionDenied { .. } => TerminationOutcome::PermissionDenied,
        ProcessEvidenceError::IdentityChanged { .. } | ProcessEvidenceError::NameChanged { .. } => {
            TerminationOutcome::UnknownFailure(
                "fresh process identity or protection name changed; refusing termination"
                    .to_owned(),
            )
        }
        ProcessEvidenceError::Missing { .. }
        | ProcessEvidenceError::NameMissing { .. }
        | ProcessEvidenceError::NameOversized { .. }
        | ProcessEvidenceError::IncompleteScope { .. }
        | ProcessEvidenceError::MemberLimitExceeded { .. }
        | ProcessEvidenceError::ByteLimitExceeded { .. } => TerminationOutcome::UnknownFailure(
            "fresh bounded process identity/name evidence is incomplete; refusing termination"
                .to_owned(),
        ),
    }
}

pub(crate) fn unsafe_pid_reason(pid: u32) -> Option<UnsafePidReason> {
    // Three PIDs we'll never signal, no matter how nicely you ask: 0 (a whole
    // process group, not a single process), 1 (init — the load-bearing ogre;
    // pull it out and the whole swamp comes down), and our own PID (Kickoutchi
    // doesn't get to kick itself out of its own swamp).
    if pid == 0 {
        return Some(UnsafePidReason::Zero);
    }
    if pid == 1 {
        return Some(UnsafePidReason::One);
    }
    #[cfg(windows)]
    if pid == 4 {
        return Some(UnsafePidReason::WindowsSystem);
    }
    if pid == std::process::id() {
        return Some(UnsafePidReason::CurrentProcess);
    }
    None
}

pub(crate) fn prepare_termination(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    if let Some(reason) = unsafe_pid_reason(pid) {
        return Err(TerminationOutcome::UnsafePid(reason));
    }

    prepare_termination_platform(pid)
}

pub(crate) fn terminate_handle_checked(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    debug_assert_eq!(handle.pid(), target.pid);
    terminate_handle_checked_platform(handle, target, protected_names, mode)
}

fn check_final_evidence(
    target: &KillTarget,
    protected_names: &[String],
    fresh: Result<FreshProcessEvidence, ProcessEvidenceError>,
) -> Result<(), TerminationOutcome> {
    let expected = ExpectedProcessEvidence {
        pid: target.pid,
        start_marker: target
            .process_start_time_marker
            .ok_or(TerminationOutcome::TargetChanged)?,
        name: target.process_name.as_deref(),
    };
    let mut scope = ProcessEvidenceScope::new(1).map_err(single_evidence_outcome)?;
    let fresh = scope
        .observe(&expected, fresh)
        .map_err(single_evidence_outcome)?;
    scope.finish().map_err(single_evidence_outcome)?;
    if is_protected_process_name(target.platform, &fresh.name, protected_names) && !target.protected
    {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn outcome_after_thaw(
    pid: u32,
    prior: TerminationOutcome,
    thaw: crate::tree::TreeSignalResult,
) -> TerminationOutcome {
    if thaw == crate::tree::TreeSignalResult::Denied {
        TerminationOutcome::ThawFailed {
            pid,
            prior: Box::new(prior),
        }
    } else {
        prior
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct TreeDeliveryHandle {
    pid: u32,
    pidfd: OwnedFd,
}

#[cfg(target_os = "linux")]
impl TreeDeliveryHandle {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn current_user_id() -> u32 {
    // SAFETY: geteuid takes no arguments, touches no memory, and can't fail —
    // it just hands back this process's effective UID.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
fn prepare_termination_platform(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    let platform_pid = pid_to_macos_pid(pid)?;
    let Some(process_start_time_marker) = crate::platform::macos::process_start_time_marker(pid)
    else {
        return if macos_process_exists(platform_pid) {
            Err(TerminationOutcome::OwnershipUnavailable)
        } else {
            Err(TerminationOutcome::AlreadyExited)
        };
    };
    Ok(TerminationHandle {
        pid,
        process_start_time_marker,
    })
}

#[cfg(target_os = "macos")]
fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    if target.process_start_time_marker != Some(handle.process_start_time_marker) {
        return TerminationOutcome::TargetChanged;
    }
    let pid = match pid_to_macos_pid(handle.pid) {
        Ok(pid) => pid,
        Err(outcome) => return outcome,
    };
    let stop = unsafe {
        // SAFETY: pid is range checked and SIGSTOP has no pointer arguments.
        libc::kill(pid, libc::SIGSTOP)
    };
    if stop != 0 {
        return macos_signal_outcome("kill(SIGSTOP)", &std::io::Error::last_os_error());
    }
    let fresh = crate::platform::macos::fresh_process_evidence(handle.pid);
    finish_macos_stopped_process(
        handle.pid,
        target,
        protected_names,
        mode,
        fresh,
        |mode| {
            let signal = match mode {
                KillMode::Terminate => libc::SIGTERM,
                KillMode::Force => libc::SIGKILL,
            };
            let result = unsafe {
                // SAFETY: pid is range checked and signal is one of two fixed values.
                libc::kill(pid, signal)
            };
            if result == 0 {
                TerminationOutcome::Success
            } else {
                macos_signal_outcome("kill", &std::io::Error::last_os_error())
            }
        },
        macos_cont_if_matches,
    )
}

#[cfg(target_os = "macos")]
fn finish_macos_stopped_process<Terminate, Continue>(
    pid: u32,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
    fresh: Result<FreshProcessEvidence, ProcessEvidenceError>,
    terminate: Terminate,
    continue_process: Continue,
) -> TerminationOutcome
where
    Terminate: FnOnce(KillMode) -> TerminationOutcome,
    Continue: FnOnce(u32, Option<ProcessStartMarker>) -> crate::tree::TreeSignalResult,
{
    let rollback_marker = fresh
        .as_ref()
        .ok()
        .map(|evidence| evidence.start_marker)
        .or(target.process_start_time_marker);
    if let Err(outcome) = check_final_evidence(target, protected_names, fresh) {
        return outcome_after_thaw(pid, outcome, continue_process(pid, rollback_marker));
    }
    let outcome = terminate(mode);
    if mode == KillMode::Terminate || outcome != TerminationOutcome::Success {
        return outcome_after_thaw(pid, outcome, continue_process(pid, rollback_marker));
    }
    outcome
}

#[cfg(target_os = "macos")]
fn macos_cont_if_matches(
    pid: u32,
    rollback_marker: Option<ProcessStartMarker>,
) -> crate::tree::TreeSignalResult {
    macos_cont_if_matches_with(
        pid,
        rollback_marker,
        crate::platform::macos::process_start_time_marker,
        tree_cont,
    )
}

#[cfg(target_os = "macos")]
fn macos_cont_if_matches_with<ReadMarker, Continue>(
    pid: u32,
    rollback_marker: Option<ProcessStartMarker>,
    read_marker: ReadMarker,
    continue_process: Continue,
) -> crate::tree::TreeSignalResult
where
    ReadMarker: FnOnce(u32) -> Option<ProcessStartMarker>,
    Continue: FnOnce(u32) -> crate::tree::TreeSignalResult,
{
    let Some(rollback_marker) = rollback_marker else {
        return crate::tree::TreeSignalResult::Denied;
    };
    if read_marker(pid) != Some(rollback_marker) {
        return crate::tree::TreeSignalResult::Denied;
    }
    continue_process(pid)
}

#[cfg(target_os = "macos")]
fn pid_to_macos_pid(pid: u32) -> Result<libc::pid_t, TerminationOutcome> {
    libc::pid_t::try_from(pid).map_err(|_| {
        TerminationOutcome::UnknownFailure("PID does not fit platform pid_t".to_owned())
    })
}

#[cfg(target_os = "macos")]
fn macos_process_exists(pid: libc::pid_t) -> bool {
    let result = unsafe {
        // SAFETY: signal 0 performs existence/permission checking only and writes
        // no Rust-managed memory.
        libc::kill(pid, 0)
    };
    if result == 0 {
        return true;
    }
    let error = std::io::Error::last_os_error();
    !matches!(error.raw_os_error(), Some(code) if code == libc::ESRCH)
}

#[cfg(target_os = "macos")]
fn macos_signal_outcome(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TerminationOutcome::AlreadyExited,
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            TerminationOutcome::PermissionDenied
        }
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

#[cfg(target_os = "linux")]
fn prepare_termination_platform(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return Err(TerminationOutcome::UnknownFailure(
            "PID does not fit platform pid_t".to_owned(),
        ));
    };

    // Open the pidfd before revalidation. That gives us a stable handle to the
    // process we are about to re-check, so if the old swamp squatter exits and
    // Linux recycles the numeric PID before signal delivery, the signal still
    // goes through this handle instead of chasing the recycled number.
    // SAFETY: pid has already been range-checked to pid_t, flags is zero as
    // required by pidfd_open(2), and the syscall writes no Rust-managed memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(outcome_from_errno("pidfd_open", &error));
    }

    let Ok(fd) = libc::c_int::try_from(fd) else {
        // Unreachable in practice (kernel fds fit c_int), but if it ever fires
        // the raw descriptor must not leak.
        // SAFETY: fd came from a successful pidfd_open and has not been wrapped
        // in an owner yet, so closing it here closes exactly one live fd.
        unsafe { libc::syscall(libc::SYS_close, fd) };
        return Err(TerminationOutcome::UnknownFailure(
            "pidfd_open returned a file descriptor that does not fit c_int".to_owned(),
        ));
    };

    // SAFETY: pidfd_open returned this fd successfully, so we now own exactly one
    // descriptor and hand that ownership to OwnedFd for close-on-drop.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(TerminationHandle {
        pid: u32::try_from(pid).expect("pid_t came from u32 and must fit back into u32"),
        pidfd,
    })
}

#[cfg(target_os = "linux")]
fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    if let Err(outcome) = linux_pidfd_signal(handle, libc::SIGSTOP) {
        return outcome;
    }
    if let Err(outcome) = check_final_evidence(
        target,
        protected_names,
        crate::platform::linux::fresh_process_evidence(handle.pid),
    ) {
        return outcome_after_thaw(
            handle.pid,
            outcome,
            tree_signal_result_from_outcome(&linux_pidfd_signal(handle, libc::SIGCONT)),
        );
    }
    let signal = match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    };
    let outcome = linux_pidfd_signal(handle, signal)
        .map_or_else(|outcome| outcome, |()| TerminationOutcome::Success);
    if mode == KillMode::Terminate || outcome != TerminationOutcome::Success {
        return outcome_after_thaw(
            handle.pid,
            outcome,
            tree_signal_result_from_outcome(&linux_pidfd_signal(handle, libc::SIGCONT)),
        );
    }
    outcome
}

#[cfg(target_os = "linux")]
fn tree_signal_result_from_outcome(
    result: &Result<(), TerminationOutcome>,
) -> crate::tree::TreeSignalResult {
    match result {
        Ok(()) => crate::tree::TreeSignalResult::Delivered,
        Err(TerminationOutcome::AlreadyExited) => crate::tree::TreeSignalResult::NotFound,
        Err(_) => crate::tree::TreeSignalResult::Denied,
    }
}

#[cfg(target_os = "linux")]
fn linux_pidfd_signal(
    handle: &TerminationHandle,
    signal: libc::c_int,
) -> Result<(), TerminationOutcome> {
    let result = unsafe {
        // SAFETY: pidfd is owned for this call; signal is a fixed process signal.
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(outcome_from_errno(
            "pidfd_send_signal",
            &std::io::Error::last_os_error(),
        ))
    }
}

/// Send `SIGSTOP` to a PID for the process-tree freeze.
///
/// macOS has no pidfd equivalent, so the freeze path stops by PID and then
/// immediately verifies identity while the process is stopped. Linux callers use
/// `tree_stop_handle` instead so the root and every descendant are pinned
/// before the first stop signal.
#[cfg(target_os = "macos")]
pub(crate) fn tree_stop(pid: u32) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, libc::SIGSTOP)
}

/// Send `SIGCONT` to a PID. Best-effort: used to resume a process before its
/// terminating signal and to thaw the tree on any abort, so callers ignore the
/// result — a `SIGCONT` to a process that already died is a harmless no-op.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn tree_cont(pid: u32) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, libc::SIGCONT)
}

/// macOS delivery preparation: probe that the stopped process still exists.
///
/// There is no pidfd to hold on Darwin, so the reuse defense is layered
/// instead of absolute: every member is stopped and identity-verified first (a
/// stopped process cannot fork, exec, or exit on its own), and `MacosTreeOps`
/// re-checks the verified start marker immediately before each raw-PID signal.
/// The stop does not make PID reuse impossible — an external `SIGKILL` can
/// remove a stopped process, and a running parent can reap it — it makes the
/// window a few instructions wide. Signal `0` performs the kernel's existence
/// and permission checks without delivering anything.
#[cfg(target_os = "macos")]
pub(crate) fn tree_prepare_delivery_probe(pid: u32) -> crate::tree::TreeSignalResult {
    tree_send_signal(pid, 0)
}

/// macOS terminating delivery, by PID. Only called after the member was
/// frozen, verified, and marker-rechecked (see `tree_prepare_delivery_probe`
/// and `MacosTreeOps::recheck_marker` for the layered reuse defense).
#[cfg(target_os = "macos")]
pub(crate) fn tree_deliver_by_pid(pid: u32, mode: KillMode) -> crate::tree::TreeSignalResult {
    let signal = match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    };
    tree_send_signal(pid, signal)
}

#[cfg(target_os = "linux")]
pub(crate) fn tree_open_delivery_handle(
    pid: u32,
) -> Result<TreeDeliveryHandle, crate::tree::TreeSignalResult> {
    use crate::tree::TreeSignalResult;

    if unsafe_pid_reason(pid).is_some() {
        return Err(TreeSignalResult::Denied);
    }
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return Err(TreeSignalResult::NotFound);
    };
    // SAFETY: pid has been range-checked to pid_t, flags is zero as required by
    // pidfd_open(2), and the syscall writes no Rust-managed memory.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, platform_pid, 0) };
    if fd < 0 {
        let error = std::io::Error::last_os_error();
        return Err(tree_signal_result_from_errno(&error));
    }
    let Ok(fd) = libc::c_int::try_from(fd) else {
        // Unreachable in practice (kernel fds fit c_int), but if it ever fires
        // the raw descriptor must not leak.
        // SAFETY: fd came from a successful pidfd_open and has not been wrapped
        // in an owner yet, so closing it here closes exactly one live fd.
        unsafe { libc::syscall(libc::SYS_close, fd) };
        return Err(TreeSignalResult::Denied);
    };
    // SAFETY: pidfd_open returned this fd successfully, so OwnedFd owns it once.
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(TreeDeliveryHandle { pid, pidfd })
}

#[cfg(target_os = "linux")]
pub(crate) fn tree_stop_handle(handle: &TreeDeliveryHandle) -> crate::tree::TreeSignalResult {
    tree_send_pidfd_signal(handle, libc::SIGSTOP)
}

#[cfg(target_os = "linux")]
pub(crate) fn tree_cont_handle(handle: &TreeDeliveryHandle) -> crate::tree::TreeSignalResult {
    tree_send_pidfd_signal(handle, libc::SIGCONT)
}

#[cfg(target_os = "linux")]
pub(crate) fn tree_deliver_handle(
    handle: &TreeDeliveryHandle,
    mode: KillMode,
) -> crate::tree::TreeSignalResult {
    let signal = match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    };
    tree_send_pidfd_signal(handle, signal)
}

#[cfg(target_os = "linux")]
fn tree_send_pidfd_signal(
    handle: &TreeDeliveryHandle,
    signal: libc::c_int,
) -> crate::tree::TreeSignalResult {
    // SAFETY: pidfd is an open descriptor from pidfd_open, signal is one of the
    // fixed process-tree signals, siginfo is null by pidfd_send_signal(2)
    // convention, and flags is zero. No Rust-managed memory is written.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            handle.pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        return crate::tree::TreeSignalResult::Delivered;
    }
    let error = std::io::Error::last_os_error();
    tree_signal_result_from_errno(&error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_send_signal(pid: u32, signal: libc::c_int) -> crate::tree::TreeSignalResult {
    use crate::tree::TreeSignalResult;

    if unsafe_pid_reason(pid).is_some() {
        return TreeSignalResult::Denied;
    }
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return TreeSignalResult::NotFound;
    };
    // SAFETY: kill(2) takes a pid and a fixed signal constant by value and writes
    // no Rust-managed memory. Every tree member is stopped and identity-verified
    // before it is targeted, and terminating signals additionally re-check the
    // verified start marker just before this call (see MacosTreeOps).
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        return TreeSignalResult::Delivered;
    }
    let error = std::io::Error::last_os_error();
    tree_signal_result_from_errno(&error)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_signal_result_from_errno(error: &std::io::Error) -> crate::tree::TreeSignalResult {
    use crate::tree::TreeSignalResult;

    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TreeSignalResult::NotFound,
        // EPERM is a real permission failure; anything else is treated as a
        // refusal too, so an unexpected errno fails closed rather than pretending
        // the signal landed.
        _ => TreeSignalResult::Denied,
    }
}

#[cfg(target_os = "linux")]
fn outcome_from_errno(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match error.raw_os_error() {
        Some(code) if code == libc::ESRCH => TerminationOutcome::AlreadyExited,
        // EACCES isn't documented for pidfd_open/pidfd_send_signal (they report
        // EPERM), but map any permission-shaped errno to denial defensively.
        Some(code) if code == libc::EPERM || code == libc::EACCES => {
            TerminationOutcome::PermissionDenied
        }
        // pidfd_open landed in Linux 5.3 and pidfd_send_signal in 5.1, so an
        // older kernel reports ENOSYS for the missing syscall. Name the floor so
        // the message is actionable rather than just "unsupported".
        Some(code) if code == libc::ENOSYS => TerminationOutcome::UnknownFailure(format!(
            "process termination requires Linux 5.3+ (pidfd); {operation} is unavailable on this kernel and no signal was sent",
        )),
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

#[cfg(windows)]
fn prepare_termination_platform(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    let desired_access =
        PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE;
    let handle = unsafe {
        // SAFETY: OpenProcess takes a PID and access mask by value. We request no
        // inherited handle, and no Rust-managed memory crosses this swamp gate.
        OpenProcess(desired_access, 0, pid)
    };
    if handle.is_null() {
        let error = std::io::Error::last_os_error();
        return Err(windows_api_outcome("OpenProcess", &error));
    }

    let process_handle = unsafe {
        // SAFETY: OpenProcess returned a non-null owned process handle. OwnedHandle
        // closes it exactly once, so the ogre does not leave handle crumbs behind.
        OwnedHandle::from_raw_handle(handle)
    };
    Ok(TerminationHandle {
        pid,
        process_handle,
    })
}

#[cfg(windows)]
fn terminate_handle_platform(handle: &TerminationHandle, _mode: KillMode) -> TerminationOutcome {
    if !windows_process_is_alive(handle) {
        return TerminationOutcome::AlreadyExited;
    }

    let result = unsafe {
        // SAFETY: the handle is the still-owned process handle opened during
        // preparation. Windows has one hard stop here; both UI modes use it.
        TerminateProcess(
            handle.process_handle.as_raw_handle(),
            WINDOWS_TERMINATE_EXIT_CODE,
        )
    };
    if result != 0 {
        return wait_for_windows_process_exit(handle);
    }

    let error = std::io::Error::last_os_error();
    if !windows_process_is_alive(handle) {
        return TerminationOutcome::AlreadyExited;
    }
    windows_api_outcome("TerminateProcess", &error)
}

#[cfg(windows)]
fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    target: &KillTarget,
    protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    let fresh = windows_fresh_process_evidence(handle);
    if let Err(outcome) = check_final_evidence(target, protected_names, fresh) {
        return outcome;
    }
    terminate_handle_platform(handle, mode)
}

#[cfg(windows)]
fn windows_fresh_process_evidence(
    handle: &TerminationHandle,
) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
    use windows_sys::Win32::System::Threading::{PROCESS_NAME_WIN32, QueryFullProcessImageNameW};
    const CODE_UNITS: usize = crate::observation::PROTECTION_NAME_MAX_BYTES / 2;

    let marker =
        crate::platform::windows::process_start_time_marker_from_handle(&handle.process_handle)
            .ok_or(ProcessEvidenceError::Missing { pid: handle.pid })?;
    let mut buffer = [0_u16; CODE_UNITS];
    let mut length = u32::try_from(buffer.len()).expect("fixed evidence buffer fits u32");
    let result = unsafe {
        // SAFETY: the prepared process handle remains owned and the fixed buffer
        // is valid for `length` UTF-16 writes.
        QueryFullProcessImageNameW(
            handle.process_handle.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(if windows_error_code(&error) == Some(ERROR_ACCESS_DENIED) {
            ProcessEvidenceError::PermissionDenied { pid: handle.pid }
        } else {
            ProcessEvidenceError::Missing { pid: handle.pid }
        });
    }
    let code_units =
        native_utf16_prefix(&buffer, length).ok_or(ProcessEvidenceError::NameOversized {
            pid: handle.pid,
            bytes: usize::try_from(length)
                .unwrap_or(usize::MAX)
                .saturating_mul(2),
        })?;
    let path = String::from_utf16_lossy(code_units);
    let name = std::path::Path::new(&path)
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or(ProcessEvidenceError::NameMissing { pid: handle.pid })?;
    Ok(FreshProcessEvidence {
        pid: handle.pid,
        start_marker: marker,
        name,
    })
}

#[cfg(windows)]
fn native_utf16_prefix(buffer: &[u16], reported_length: u32) -> Option<&[u16]> {
    buffer.get(..usize::try_from(reported_length).ok()?)
}

#[cfg(windows)]
const WINDOWS_TERMINATE_EXIT_CODE: u32 = 1;
#[cfg(windows)]
const WINDOWS_TERMINATE_WAIT_MS: u32 = 5_000;

#[cfg(windows)]
fn wait_for_windows_process_exit(handle: &TerminationHandle) -> TerminationOutcome {
    let result = unsafe {
        // SAFETY: the process handle is owned by `TerminationHandle` and was
        // opened with PROCESS_SYNCHRONIZE during preparation. Waiting does not
        // transfer ownership or write Rust-managed memory.
        WaitForSingleObject(
            handle.process_handle.as_raw_handle(),
            WINDOWS_TERMINATE_WAIT_MS,
        )
    };
    match result {
        WAIT_OBJECT_0 => TerminationOutcome::Success,
        WAIT_TIMEOUT => match windows_exit_code(handle) {
            Ok(Some(code)) => TerminationOutcome::UnknownFailure(format!(
                "process did not exit within {WINDOWS_TERMINATE_WAIT_MS}ms after TerminateProcess; exit code {code}"
            )),
            Ok(None) => TerminationOutcome::UnknownFailure(format!(
                "process did not exit within {WINDOWS_TERMINATE_WAIT_MS}ms after TerminateProcess"
            )),
            Err(outcome) => outcome,
        },
        WAIT_FAILED => {
            let error = std::io::Error::last_os_error();
            windows_api_outcome("WaitForSingleObject", &error)
        }
        other => TerminationOutcome::UnknownFailure(format!(
            "WaitForSingleObject returned unexpected status {other}"
        )),
    }
}

#[cfg(windows)]
fn windows_process_is_alive(handle: &TerminationHandle) -> bool {
    match windows_wait_status(handle, 0) {
        // Signaled: the process has already exited.
        Ok(WAIT_OBJECT_0) => false,
        // WAIT_TIMEOUT is a definitive "still running"; an Err means we couldn't
        // even ask, so we keep the conservative live assumption and let the real
        // termination call surface the error. Both cases mean "treat as alive".
        Ok(WAIT_TIMEOUT) | Err(_) => true,
        // Any other wait status is unexpected, so fall back to the exit code and
        // treat a real code as "not alive".
        Ok(_) => matches!(windows_exit_code(handle), Ok(None)),
    }
}

#[cfg(windows)]
fn windows_wait_status(
    handle: &TerminationHandle,
    milliseconds: u32,
) -> Result<u32, TerminationOutcome> {
    let result = unsafe {
        // SAFETY: the process handle is owned by `TerminationHandle` and was
        // opened with PROCESS_SYNCHRONIZE during preparation.
        WaitForSingleObject(handle.process_handle.as_raw_handle(), milliseconds)
    };
    match result {
        WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(result),
        WAIT_FAILED => Err(windows_api_outcome(
            "WaitForSingleObject",
            &std::io::Error::last_os_error(),
        )),
        other => Ok(other),
    }
}

#[cfg(windows)]
fn windows_exit_code(handle: &TerminationHandle) -> Result<Option<u32>, TerminationOutcome> {
    let mut exit_code = 0_u32;
    let result = unsafe {
        // SAFETY: the pointer is valid for one u32 write and the process handle is
        // owned by `TerminationHandle` for this whole call.
        GetExitCodeProcess(handle.process_handle.as_raw_handle(), &raw mut exit_code)
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(windows_api_outcome("GetExitCodeProcess", &error));
    }
    if exit_code == windows_still_active_exit_code() {
        Ok(None)
    } else {
        Ok(Some(exit_code))
    }
}

#[cfg(windows)]
fn windows_still_active_exit_code() -> u32 {
    u32::try_from(STILL_ACTIVE).expect("STILL_ACTIVE must fit in a process exit code")
}

#[cfg(windows)]
fn windows_api_outcome(operation: &str, error: &std::io::Error) -> TerminationOutcome {
    match windows_error_code(error) {
        Some(ERROR_INVALID_PARAMETER) => TerminationOutcome::AlreadyExited,
        Some(ERROR_ACCESS_DENIED) => TerminationOutcome::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            TerminationOutcome::PermissionDenied
        }
        _ => TerminationOutcome::UnknownFailure(format!("{operation} failed: {error}")),
    }
}

#[cfg(windows)]
fn windows_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn prepare_termination_platform(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    Ok(TerminationHandle {
        pid,
        _unsupported: (),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn terminate_handle_platform(_handle: &TerminationHandle, _mode: KillMode) -> TerminationOutcome {
    TerminationOutcome::UnknownFailure(
        "termination is only implemented for Linux, macOS, and Windows".to_owned(),
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn terminate_handle_checked_platform(
    handle: &TerminationHandle,
    _target: &KillTarget,
    _protected_names: &[String],
    mode: KillMode,
) -> TerminationOutcome {
    terminate_handle_platform(handle, mode)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::outcome_after_thaw;
    use super::{
        ConfirmationRequirement, KillMode, KillTarget, TerminationOutcome, UnsafePidReason,
        confirmation_input_matches, confirmation_requirement, revalidate_confirmed_target,
        target_still_matches_confirmation, unsafe_pid_reason,
    };
    #[cfg(target_os = "macos")]
    use super::{finish_macos_stopped_process, macos_cont_if_matches_with};
    #[cfg(windows)]
    use super::{native_utf16_prefix, windows_api_outcome, windows_still_active_exit_code};
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
        Protocol, SocketState,
    };
    #[cfg(target_os = "macos")]
    use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};
    #[cfg(windows)]
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

    #[cfg(windows)]
    #[test]
    fn malformed_windows_native_name_length_fails_closed_without_panicking() {
        let buffer = [0_u16; 4];
        assert_eq!(native_utf16_prefix(&buffer, 5), None);
        assert_eq!(native_utf16_prefix(&buffer, u32::MAX), None);
        assert_eq!(native_utf16_prefix(&buffer, 4), Some(buffer.as_slice()));
    }

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
            process_name: Some("node".into()),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: Some(crate::observation::ProcessIdentity {
                pid: 18422,
                start_marker: crate::observation::ProcessStartMarker::linux(55)
                    .expect("test marker is nonzero"),
            }),
            ipv6_scope: None,
        }
    }

    fn context(start_time_ticks: u64) -> ProcessContext {
        ProcessContext {
            owner_uid: Some(1000),
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(
                start_time_ticks,
            )
            .ok(),
            children: ChildProcessSnapshot::default(),
            docker: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn single_process_thaw_failure_is_typed() {
        let outcome = outcome_after_thaw(
            42,
            TerminationOutcome::TargetChanged,
            crate::tree::TreeSignalResult::Denied,
        );
        assert!(matches!(
            outcome,
            TerminationOutcome::ThawFailed { pid: 42, prior }
                if *prior == TerminationOutcome::TargetChanged
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cleanup_continues_the_identity_observed_after_stop() {
        let rollback_marker = crate::observation::ProcessStartMarker::macos(20, 30)
            .expect("rollback marker is valid");
        let mut continued = Vec::new();

        let result = macos_cont_if_matches_with(
            42,
            Some(rollback_marker),
            |_| Some(rollback_marker),
            |pid| {
                continued.push(pid);
                crate::tree::TreeSignalResult::Delivered
            },
        );

        assert_eq!(result, crate::tree::TreeSignalResult::Delivered);
        assert_eq!(continued, [42]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_identity_change_rolls_back_the_post_stop_process_without_terminating_it() {
        let original_marker = crate::observation::ProcessStartMarker::macos(20, 30)
            .expect("original marker is valid");
        let replacement_marker = crate::observation::ProcessStartMarker::macos(21, 30)
            .expect("replacement marker is valid");
        let target = KillTarget {
            pid: 42,
            process_name: Some("node".to_owned()),
            platform: Platform::Macos,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: Some(original_marker),
            child_count: 0,
            children_truncated: false,
        };
        let fresh = Ok(FreshProcessEvidence {
            pid: 42,
            start_marker: replacement_marker,
            name: "replacement".to_owned(),
        });
        let mut continued = Vec::new();

        let outcome = finish_macos_stopped_process(
            42,
            &target,
            &[],
            KillMode::Terminate,
            fresh,
            |_| panic!("replacement identity must not receive a terminating signal"),
            |pid, rollback_marker| {
                continued.push((pid, rollback_marker));
                crate::tree::TreeSignalResult::Delivered
            },
        );

        assert_eq!(
            outcome,
            TerminationOutcome::UnknownFailure(
                "fresh process identity or protection name changed; refusing termination"
                    .to_owned()
            )
        );
        assert_eq!(continued, [(42, Some(replacement_marker))]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_evidence_failure_rechecks_and_rolls_back_the_authorized_identity() {
        let original_marker = crate::observation::ProcessStartMarker::macos(20, 30)
            .expect("original marker is valid");
        let target = KillTarget {
            pid: 42,
            process_name: Some("node".to_owned()),
            platform: Platform::Macos,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: Some(original_marker),
            child_count: 0,
            children_truncated: false,
        };
        let mut continued = Vec::new();

        let outcome = finish_macos_stopped_process(
            42,
            &target,
            &[],
            KillMode::Terminate,
            Err(ProcessEvidenceError::PermissionDenied { pid: 42 }),
            |_| panic!("incomplete evidence must prevent termination"),
            |pid, rollback_marker| {
                continued.push((pid, rollback_marker));
                crate::tree::TreeSignalResult::Delivered
            },
        );

        assert_eq!(outcome, TerminationOutcome::PermissionDenied);
        assert_eq!(continued, [(42, Some(original_marker))]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cleanup_refuses_a_second_identity_change() {
        let rollback_marker = crate::observation::ProcessStartMarker::macos(20, 30)
            .expect("rollback marker is valid");
        let changed_marker =
            crate::observation::ProcessStartMarker::macos(21, 30).expect("changed marker is valid");

        let result = macos_cont_if_matches_with(
            42,
            Some(rollback_marker),
            |_| Some(changed_marker),
            |_| panic!("changed identity must not receive SIGCONT"),
        );

        assert_eq!(result, crate::tree::TreeSignalResult::Denied);
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
            process_start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
            children: ChildProcessSnapshot {
                children: vec![ChildProcess {
                    pid: 18423,
                    process_name: Some("worker".to_owned()),
                }],
                truncated: false,
            },
            docker: None,
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
    #[should_panic(expected = "kill target row PID must match target PID")]
    fn kill_target_rejects_rows_for_other_pids() {
        let mut row = entry(3000, Protocol::Tcp);
        row.pid = Some(999);

        let _ = KillTarget::from_entries(18422, [&row], Some(&context(55)));
    }

    #[test]
    fn confirmation_requirements_keep_yes_from_bypassing_protected_processes() {
        assert_eq!(
            confirmation_requirement(false, Platform::Linux, KillMode::Terminate, true, true),
            Ok(None),
        );
        assert_eq!(
            confirmation_requirement(false, Platform::Linux, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(false, Platform::Linux, KillMode::Force, false, true),
            Ok(Some(ConfirmationRequirement::ForceWord)),
        );
        assert_eq!(
            confirmation_requirement(false, Platform::Linux, KillMode::Force, false, false),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(true, Platform::Linux, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::ProtectedProcess)),
        );
        assert_eq!(
            confirmation_requirement(true, Platform::Linux, KillMode::Terminate, true, true),
            Err(TerminationOutcome::ProtectedProcess),
        );
    }

    #[test]
    fn windows_termination_warns_but_normal_confirmation_stays_simple() {
        assert_eq!(
            confirmation_requirement(false, Platform::Windows, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(false, Platform::Windows, KillMode::Terminate, false, false),
            Ok(Some(ConfirmationRequirement::Yes)),
        );
        assert_eq!(
            confirmation_requirement(false, Platform::Windows, KillMode::Terminate, true, true),
            Ok(None),
        );
        assert_eq!(
            KillMode::Terminate.action_label_for(Platform::Windows),
            "Terminate",
        );
        assert!(
            KillMode::Terminate
                .force_warning(Platform::Windows)
                .is_some()
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
            "FORCE",
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

        let mut windows_row = entry(3000, Protocol::Tcp);
        windows_row.platform = Platform::Windows;
        let windows_target = KillTarget::from_entries(18422, [&windows_row], Some(&context(55)));
        assert!(confirmation_input_matches(
            "NODE",
            &windows_target,
            ConfirmationRequirement::ProtectedProcess,
        ));
        let mut unicode_windows_target = windows_target;
        unicode_windows_target.process_name = Some("ÄPP.EXE".to_owned());
        assert!(confirmation_input_matches(
            "äpp.exe",
            &unicode_windows_target,
            ConfirmationRequirement::ProtectedProcess,
        ));
    }

    #[test]
    fn unsafe_pid_guardrails_block_documented_targets() {
        assert_eq!(unsafe_pid_reason(0), Some(UnsafePidReason::Zero));
        assert_eq!(unsafe_pid_reason(1), Some(UnsafePidReason::One));
        #[cfg(windows)]
        assert_eq!(unsafe_pid_reason(4), Some(UnsafePidReason::WindowsSystem));
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
        changed_name.process_name = Some("other".into());
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
        let mut fresh_row = entry(3000, Protocol::Tcp);
        fresh_row.process_identity = Some(crate::observation::ProcessIdentity {
            pid: 18422,
            start_marker: crate::observation::ProcessStartMarker::linux(99)
                .expect("test marker is nonzero"),
        });

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[fresh_row], Some(&context(99))),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_rejects_ipv6_interface_scope_movement() {
        let mut confirmed_row = entry(3000, Protocol::Tcp);
        confirmed_row.local_addr = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        confirmed_row.ipv6_scope = Some(
            crate::observation::Ipv6Scope::interface_index(2)
                .expect("test interface index is valid"),
        );
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));
        let mut moved = confirmed_row;
        moved.ipv6_scope = Some(
            crate::observation::Ipv6Scope::interface_index(3)
                .expect("test interface index is valid"),
        );

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[moved], Some(&context(55))),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_rejects_missing_start_time_identity() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));
        let mut fresh_row = entry(3000, Protocol::Tcp);
        fresh_row.process_identity = None;

        assert_eq!(
            revalidate_confirmed_target(&confirmed, &[fresh_row], None),
            Err(TerminationOutcome::TargetChanged),
        );
    }

    #[test]
    fn revalidation_reports_ownership_unavailable_when_owning_pid_becomes_unreadable() {
        let confirmed_row = entry(3000, Protocol::Tcp);
        let confirmed = KillTarget::from_entries(18422, [&confirmed_row], Some(&context(55)));

        // The confirmed port is still listening, but we can't map its owner to a
        // PID anymore: that's permission/ownership loss, not the target moving.
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

    #[cfg(windows)]
    #[test]
    fn windows_termination_maps_permission_denied_and_missing_pid_separately() {
        let denied = std::io::Error::from_raw_os_error(
            i32::try_from(ERROR_ACCESS_DENIED).expect("Windows error code fits i32"),
        );
        let missing = std::io::Error::from_raw_os_error(
            i32::try_from(ERROR_INVALID_PARAMETER).expect("Windows error code fits i32"),
        );

        assert_eq!(
            windows_api_outcome("OpenProcess", &denied),
            TerminationOutcome::PermissionDenied,
        );
        assert_eq!(
            windows_api_outcome("OpenProcess", &missing),
            TerminationOutcome::AlreadyExited,
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_still_active_code_matches_the_process_api_contract() {
        // The sentinel is pinned here so a Windows API behavior change can't
        // silently change `windows_exit_code`'s meaning of "still alive".
        assert_eq!(windows_still_active_exit_code(), 259);
    }
}
