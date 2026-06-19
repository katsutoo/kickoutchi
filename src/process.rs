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
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, STILL_ACTIVE};
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess,
};

use crate::model::{PermissionStatus, Platform, PortEntry, ProcessContext, Protocol};

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

    pub(crate) fn action_label_for(self, platform: Platform) -> &'static str {
        if self.uses_forceful_delivery(platform) {
            "Force-kill"
        } else {
            self.action_label()
        }
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

    pub(crate) fn uses_forceful_delivery(self, platform: Platform) -> bool {
        self == Self::Force || platform == Platform::Windows
    }

    pub(crate) fn force_warning(self, platform: Platform) -> Option<&'static str> {
        if !self.uses_forceful_delivery(platform) {
            return None;
        }
        Some(match platform {
            Platform::Linux | Platform::Macos => {
                "SIGKILL is immediate; prefer normal termination first."
            }
            Platform::Windows => "TerminateProcess is immediate; prefer normal termination first.",
        })
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

#[derive(Debug)]
pub(crate) struct TerminationHandle {
    pid: u32,
    #[cfg(target_os = "linux")]
    pidfd: OwnedFd,
    #[cfg(windows)]
    process_handle: OwnedHandle,
    #[cfg(not(any(target_os = "linux", windows)))]
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
    pub(crate) process_start_time_marker: Option<u64>,
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
            assert_eq!(
                entry.pid,
                Some(pid),
                "kill target row PID must match target PID",
            );
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
        // confirmation/revalidation flow leans on those ports to know which
        // process it's even looking at. We assert in release too (this runs once
        // per kill request, not on a hot path): calling this with zero rows is a
        // programmer bug, and a port-less target sitting on a termination path is
        // exactly the kind of thing you want to crash on, not quietly wave
        // through.
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
            process_start_time_marker: context
                .and_then(|context| context.process_start_time_marker),
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

        #[cfg(target_os = "linux")]
        let mut owner_warning_added = false;
        #[cfg(not(target_os = "linux"))]
        let owner_warning_added = false;
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
    platform: Platform,
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

    if mode.uses_forceful_delivery(platform) && confirm_force_kill {
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

    #[cfg(any(target_os = "linux", windows))]
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
        .all(|confirmed_port| fresh.ports.contains(confirmed_port))
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
    fresh_entries
        .iter()
        .any(|entry| entry.pid.is_none() && confirmed.ports.contains(&KillTargetPort::from(entry)))
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
    // Three PIDs we'll never signal, no matter how nicely you ask: 0 (a whole
    // process group, not a single process), 1 (init — the load-bearing ogre;
    // pull it out and the whole swamp comes down), and our own PID (Kickoutchi
    // doesn't get to kick itself out of its own swamp).
    match pid {
        0 => Some(UnsafePidReason::Zero),
        1 => Some(UnsafePidReason::One),
        pid if pid == std::process::id() => Some(UnsafePidReason::CurrentProcess),
        _ => None,
    }
}

pub(crate) fn prepare_termination(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    if let Some(reason) = unsafe_pid_reason(pid) {
        return Err(TerminationOutcome::UnsafePid(reason));
    }

    prepare_termination_platform(pid)
}

pub(crate) fn terminate_handle(handle: &TerminationHandle, mode: KillMode) -> TerminationOutcome {
    debug_assert!(
        unsafe_pid_reason(handle.pid()).is_none(),
        "prepared termination handles must never target unsafe PIDs"
    );
    terminate_handle_platform(handle, mode)
}

#[cfg(target_os = "linux")]
fn current_user_id() -> u32 {
    // SAFETY: geteuid takes no arguments, touches no memory, and can't fail —
    // it just hands back this process's effective UID.
    unsafe { libc::geteuid() }
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
fn terminate_handle_platform(handle: &TerminationHandle, mode: KillMode) -> TerminationOutcome {
    let signal = match mode {
        KillMode::Terminate => libc::SIGTERM,
        KillMode::Force => libc::SIGKILL,
    };

    // SAFETY: pidfd is an open descriptor from pidfd_open, signal is one of the
    // two constants this module supports, siginfo is null by pidfd_send_signal(2)
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
        return TerminationOutcome::Success;
    }

    let error = std::io::Error::last_os_error();
    outcome_from_errno("pidfd_send_signal", &error)
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
    match windows_exit_code(handle) {
        Ok(code) if code != windows_still_active_exit_code() => {
            return TerminationOutcome::AlreadyExited;
        }
        Ok(_) => {}
        Err(outcome) => return outcome,
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
        return TerminationOutcome::Success;
    }

    let error = std::io::Error::last_os_error();
    if matches!(windows_exit_code(handle), Ok(code) if code != windows_still_active_exit_code()) {
        return TerminationOutcome::AlreadyExited;
    }
    windows_api_outcome("TerminateProcess", &error)
}

#[cfg(windows)]
const WINDOWS_TERMINATE_EXIT_CODE: u32 = 1;

#[cfg(windows)]
fn windows_exit_code(handle: &TerminationHandle) -> Result<u32, TerminationOutcome> {
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
    Ok(exit_code)
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

#[cfg(not(any(target_os = "linux", windows)))]
fn prepare_termination_platform(pid: u32) -> Result<TerminationHandle, TerminationOutcome> {
    Ok(TerminationHandle {
        pid,
        _unsupported: (),
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn terminate_handle_platform(_handle: &TerminationHandle, _mode: KillMode) -> TerminationOutcome {
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
    #[cfg(windows)]
    use super::{windows_api_outcome, windows_still_active_exit_code};
    use crate::model::{
        ChildProcess, ChildProcessSnapshot, PermissionStatus, Platform, PortEntry, ProcessContext,
        Protocol, SocketState,
    };
    #[cfg(windows)]
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER};

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
            process_start_time_marker: Some(start_time_ticks),
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
            process_start_time_marker: Some(55),
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
    fn windows_termination_is_forceful_for_confirmation_policy() {
        assert_eq!(
            confirmation_requirement(false, Platform::Windows, KillMode::Terminate, false, true),
            Ok(Some(ConfirmationRequirement::ForceWord)),
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
            "Force-kill",
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
        assert_eq!(windows_still_active_exit_code(), 259);
    }
}
