//! The single-process `kill` command: exactly one confirmed target, resolved,
//! confirmed, revalidated fresh, and only then signalled. The scoped
//! (`--tree`/`--group`) flows reuse the resolution, revalidation, and
//! confirmation-input helpers defined here.

use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::time::Duration;

use crate::collector;
use crate::command;
use crate::config::Config;
use crate::display::sanitize;
use crate::model::{PortEntry, ProcessContext};
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome, UnsafePidReason,
};
use crate::protection::mark_protected;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::scoped::run_group_kill;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use super::scoped::run_tree_kill;
use super::{ExitReason, KillArgs};

pub(super) fn run_kill(args: &KillArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    if args.tree {
        return run_tree_kill(args, config, entries);
    }
    // clap rejects `--tree --group` at parse time, so exactly one scope
    // branch can be taken here.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if args.group {
        return run_group_kill(args, config, entries);
    }

    run_kill_with(
        args,
        config,
        entries,
        KillCollectors {
            collect_context: platform::collect_process_context,
            collect_ports: collector::collect_ports,
        },
        prompt_confirmation,
        process::prepare_termination,
        process::terminate_handle,
    )
}

struct KillCollectors<CollectContext, CollectPorts> {
    collect_context: CollectContext,
    collect_ports: CollectPorts,
}

fn run_kill_with<CollectContext, CollectPorts, Prompt, Prepare, Terminate, Handle>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntry],
    mut collectors: KillCollectors<CollectContext, CollectPorts>,
    mut prompt: Prompt,
    mut prepare: Prepare,
    mut terminate: Terminate,
) -> ExitReason
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    Prompt: FnMut(&KillTarget, KillMode, ConfirmationRequirement) -> std::io::Result<bool>,
    Prepare: FnMut(u32) -> Result<Handle, TerminationOutcome>,
    Terminate: FnMut(&Handle, KillMode) -> TerminationOutcome,
{
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    let target = match resolve_kill_target(args, entries, &mut collectors.collect_context) {
        Ok(target) => target,
        Err(error) => return print_target_error(error),
    };

    let requirement = match process::confirmation_requirement(
        target.protected,
        target.platform,
        mode,
        args.yes,
        config.confirm_force_kill,
    ) {
        Ok(requirement) => requirement,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };

    // Print the target banner — identity, ports, equivalent command, and any
    // safety warnings — before the confirmation branch, so it shows on the
    // `--yes` path too. Skipping the prompt must not also swallow the
    // "system/service process", "owned by another uid", partial-metadata, or
    // "has children" warnings: those are required safety notices, and
    // `--yes` opts out of being *asked*, not of being *told*.
    print_kill_banner(&target, mode);

    if let Some(requirement) = requirement {
        let confirmed = match prompt(&target, mode, requirement) {
            Ok(confirmed) => confirmed,
            Err(error) => {
                eprintln!("error: reading confirmation failed: {error}");
                return ExitReason::Failure;
            }
        };
        if !confirmed {
            let outcome = TerminationOutcome::Cancelled;
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    }

    let handle = match prepare(target.pid) {
        Ok(handle) => handle,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };

    let target = match revalidate_cli_target(
        args,
        config,
        &target,
        &mut collectors.collect_context,
        &mut collectors.collect_ports,
    ) {
        Ok(target) => target,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };

    let outcome = terminate(&handle, mode);
    print_termination_outcome(&target, mode, &outcome);
    if outcome == TerminationOutcome::Success {
        print_post_kill_refresh_status(&target, &mut collectors.collect_ports);
    }
    exit_reason_for_outcome(&outcome)
}

/// How many times the post-kill refresh re-reads the port table, and the pause
/// between reads. Termination is asynchronous: a `SIGTERM`'d process needs a
/// moment to run its handlers and close its sockets, so one immediate
/// re-collect would report "still visible" on perfectly successful kills.
/// Ten polls at 100ms bound the wait to roughly one second — long enough for a
/// normal shutdown, short enough that a genuinely stuck port is still reported
/// promptly.
const POST_KILL_SETTLE_ATTEMPTS_MAX: usize = 10;
const POST_KILL_SETTLE_RETRY_DELAY: Duration = Duration::from_millis(100);

/// What the confirmed ports looked like once the settle window closed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PostKillPortsStatus {
    Cleared,
    StillVisible,
    RefreshFailed(String),
}

pub(super) fn print_post_kill_refresh_status<CollectPorts>(
    target: &KillTarget,
    collect_ports: &mut CollectPorts,
) where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    if let Some(message) = post_kill_refresh_status_message(target, collect_ports) {
        eprintln!("{message}");
    }
}

pub(super) fn post_kill_refresh_status_message<CollectPorts>(
    target: &KillTarget,
    collect_ports: &mut CollectPorts,
) -> Option<String>
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // A portless root (a `--pid` supervisor) confirmed no ports, so there is
    // nothing to poll and nothing honest to report about port visibility.
    if target.ports.is_empty() {
        return None;
    }
    Some(match wait_for_confirmed_ports_to_clear(target, collect_ports, std::thread::sleep) {
        PostKillPortsStatus::Cleared => "confirmed target ports are no longer visible".to_owned(),
        PostKillPortsStatus::StillVisible => "warning: one or more confirmed ports are still visible after termination; another process may own them or shutdown may still be completing".to_owned(),
        PostKillPortsStatus::RefreshFailed(error) => format!(
            "warning: collecting ports after termination failed; refresh manually to verify the port disappeared: {error}",
        ),
    })
}

/// Poll the port table until every confirmed port is gone or the settle window
/// runs out. The sleep is injected so tests can drive the loop without real
/// delays. A refresh error fails closed to a warning rather than claiming the
/// ports cleared on data we never saw.
fn wait_for_confirmed_ports_to_clear<CollectPorts, Sleep>(
    target: &KillTarget,
    collect_ports: &mut CollectPorts,
    mut sleep: Sleep,
) -> PostKillPortsStatus
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    Sleep: FnMut(Duration),
{
    for attempt in 0..POST_KILL_SETTLE_ATTEMPTS_MAX {
        let entries = match collect_ports() {
            Ok(entries) => entries,
            Err(error) => return PostKillPortsStatus::RefreshFailed(error.to_string()),
        };
        let still_visible = entries
            .iter()
            .any(|entry| target.ports.contains(&process::KillTargetPort::from(entry)));
        if !still_visible {
            return PostKillPortsStatus::Cleared;
        }
        if attempt + 1 < POST_KILL_SETTLE_ATTEMPTS_MAX {
            sleep(POST_KILL_SETTLE_RETRY_DELAY);
        }
    }
    PostKillPortsStatus::StillVisible
}

pub(super) fn revalidate_cli_target<CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
) -> Result<KillTarget, TerminationOutcome>
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let mut fresh_entries = collect_ports().map_err(|error| {
        TerminationOutcome::UnknownFailure(format!("collecting ports before kill failed: {error}"))
    })?;
    mark_protected(&mut fresh_entries, &config.protected_processes);

    // A confirmed port that's still listening but whose owner PID is now
    // unreadable is ownership loss, not a moved target. Re-resolving a `--pid`
    // kill by PID alone would miss this: the owner-less row just drops out and
    // looks like the target vanished (exit 3). Check it up front so `--pid`
    // reports the same permission-denied exit `4` as `--port` (whose resolver
    // already flags it as `MissingPid`) and as the TUI. Sharing
    // `confirmed_port_owner_unavailable` keeps all three from drifting.
    if process::confirmed_port_owner_unavailable(confirmed, &fresh_entries) {
        return Err(TerminationOutcome::OwnershipUnavailable);
    }

    let fresh = match resolve_kill_target(args, &fresh_entries, collect_context) {
        Ok(fresh) => fresh,
        Err(KillTargetError::NoMatch) => {
            return Err(TerminationOutcome::TargetChanged);
        }
        Err(KillTargetError::MissingPid { .. }) => {
            return Err(TerminationOutcome::OwnershipUnavailable);
        }
        Err(KillTargetError::AmbiguousPort { port, candidates }) => {
            eprintln!(
                "error: port {port} became ambiguous before termination; refusing to guess. Use --pid with one of:",
            );
            for candidate in candidates {
                eprintln!("  {candidate}");
            }
            return Err(TerminationOutcome::TargetChanged);
        }
        Err(KillTargetError::UnsafePid(reason)) => {
            return Err(TerminationOutcome::UnsafePid(reason));
        }
    };

    if !process::target_still_matches_confirmation(confirmed, &fresh) {
        return Err(TerminationOutcome::TargetChanged);
    }
    if fresh.protected && !confirmed.protected {
        return Err(TerminationOutcome::ProtectedProcess);
    }
    Ok(fresh)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum KillTargetError {
    NoMatch,
    MissingPid { port: u16 },
    AmbiguousPort { port: u16, candidates: Vec<String> },
    UnsafePid(UnsafePidReason),
}

pub(super) fn resolve_kill_target<CollectContext>(
    args: &KillArgs,
    entries: &[PortEntry],
    collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    match (args.pid, args.port) {
        (Some(pid), None) => resolve_pid_target(pid, entries, collect_context),
        (None, Some(port)) => resolve_port_target(port, entries, collect_context),
        (None, None) | (Some(_), Some(_)) => unreachable!("clap requires exactly one kill target"),
    }
}

fn resolve_pid_target<CollectContext>(
    pid: u32,
    entries: &[PortEntry],
    mut collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let rows: Vec<&PortEntry> = entries
        .iter()
        .filter(|entry| entry.pid == Some(pid))
        .collect();
    if rows.is_empty() {
        return Err(KillTargetError::NoMatch);
    }
    let context = collect_context(pid);
    Ok(KillTarget::from_entries(pid, rows, Some(&context)))
}

fn resolve_port_target<CollectContext>(
    port: u16,
    entries: &[PortEntry],
    mut collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    let (pid, rows) = resolve_single_port_owner(port, entries)?;
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let context = collect_context(pid);
    Ok(KillTarget::from_entries(pid, rows, Some(&context)))
}

/// Resolve the single PID that owns `port`, with the precise refusal when it
/// cannot: no matching socket, a hidden owner (a row without a PID), or
/// several distinct owners. Kill and inspect resolution both go through here
/// so the two policies cannot drift; the unsafe-PID guard deliberately stays
/// with the kill caller, because reading PID 1's family is legitimate while
/// signalling it is not.
pub(super) fn resolve_single_port_owner(
    port: u16,
    entries: &[PortEntry],
) -> Result<(u32, Vec<&PortEntry>), KillTargetError> {
    let rows: Vec<&PortEntry> = entries
        .iter()
        .filter(|entry| entry.matches_port(port))
        .collect();
    if rows.is_empty() {
        return Err(KillTargetError::NoMatch);
    }
    if rows.iter().any(|entry| entry.pid.is_none()) {
        return Err(KillTargetError::MissingPid { port });
    }

    let mut pids = rows
        .iter()
        .filter_map(|entry| entry.pid)
        .collect::<Vec<_>>();
    pids.sort_unstable();
    pids.dedup();
    let [pid] = pids.as_slice() else {
        return Err(KillTargetError::AmbiguousPort {
            port,
            candidates: candidate_labels(&rows),
        });
    };
    Ok((*pid, rows))
}

fn candidate_labels(rows: &[&PortEntry]) -> Vec<String> {
    let mut candidates = rows
        .iter()
        .filter_map(|entry| {
            let pid = entry.pid?;
            let name = sanitize(entry.process_name.as_deref().unwrap_or("<unknown>"));
            Some(format!(
                "PID {pid} ({name}) {} {}:{}",
                entry.protocol.label(),
                entry.local_addr,
                entry.local_port,
            ))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.dedup();
    candidates
}

pub(super) fn print_target_error(error: KillTargetError) -> ExitReason {
    match error {
        KillTargetError::NoMatch => {
            eprintln!("error: no open port matches the requested target");
            ExitReason::NoMatch
        }
        KillTargetError::MissingPid { port } => {
            eprintln!(
                "error: port {port} is visible, but no owning PID is available; rerun with higher privileges or pass --pid when known",
            );
            ExitReason::PermissionDenied
        }
        KillTargetError::AmbiguousPort { port, candidates } => {
            eprintln!(
                "error: port {port} is owned by multiple PIDs; refusing to guess. Use --pid with one of:",
            );
            for candidate in candidates {
                eprintln!("  {candidate}");
            }
            ExitReason::Failure
        }
        KillTargetError::UnsafePid(reason) => {
            eprintln!("error: unsafe PID blocked: {}", reason.message());
            ExitReason::Failure
        }
    }
}

fn print_kill_banner(target: &KillTarget, mode: KillMode) {
    eprintln!(
        "{} {}",
        mode.action_label_for(target.platform),
        target.identity()
    );
    eprintln!("Scope: process");
    eprintln!("Ports: {}", sanitize(&target.ports_text()));
    eprintln!(
        "Command: {}",
        sanitize(&command::render_kill_command(
            target.platform,
            target.pid,
            mode
        )),
    );
    if let Some(warning) = mode.force_warning(target.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    for warning in target.warning_lines() {
        eprintln!("Warning: {}.", sanitize(&warning));
    }
}

fn prompt_confirmation(
    target: &KillTarget,
    mode: KillMode,
    requirement: ConfirmationRequirement,
) -> std::io::Result<bool> {
    match requirement {
        ConfirmationRequirement::Yes => eprint!("Type y to confirm, or press Enter to cancel: "),
        ConfirmationRequirement::ForceWord => {
            eprint!(
                "Type force to confirm {}: ",
                mode.delivery_label(target.platform)
            );
        }
        ConfirmationRequirement::ProtectedProcess => eprint!(
            "Protected process: type PID {} or process name {} to confirm: ",
            target.pid,
            sanitize(target.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(process::confirmation_input_matches(
        &answer,
        target,
        requirement,
    ))
}

pub(super) fn read_confirmation_line(max_bytes: usize) -> std::io::Result<String> {
    read_confirmation_line_from(&mut std::io::stdin().lock(), max_bytes)
}

fn read_confirmation_line_from(reader: &mut impl BufRead, max_bytes: usize) -> io::Result<String> {
    let limit = u64::try_from(max_bytes)
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "confirmation limit is too large"))?
        .checked_add(1)
        .ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidInput, "confirmation limit is too large")
        })?;
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(1));
    (&mut *reader).take(limit).read_until(b'\n', &mut bytes)?;

    if bytes.len() > max_bytes {
        if bytes.last() != Some(&b'\n') {
            drain_line(reader)?;
        }
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("confirmation input exceeds the {max_bytes}-byte limit"),
        ));
    }

    String::from_utf8(bytes).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
}

fn drain_line(reader: &mut impl BufRead) -> io::Result<()> {
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(());
        }
        let consumed = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        let line_ended = buffer[consumed - 1] == b'\n';
        reader.consume(consumed);
        if line_ended {
            return Ok(());
        }
    }
}

fn print_termination_outcome(target: &KillTarget, mode: KillMode, outcome: &TerminationOutcome) {
    let delivery = mode.delivery_label(target.platform);
    match outcome {
        TerminationOutcome::Success => eprintln!("sent {delivery} to {}", target.identity()),
        TerminationOutcome::PermissionDenied => eprintln!(
            "error: permission denied sending {delivery} to {}; {}",
            target.identity(),
            process::permission_denied_hint(target.platform),
        ),
        TerminationOutcome::OwnershipUnavailable => eprintln!(
            "error: ownership for {} became unavailable before {delivery}; no termination was sent",
            target.identity(),
        ),
        TerminationOutcome::AlreadyExited => {
            eprintln!(
                "{} already exited before termination was sent",
                target.identity()
            );
        }
        TerminationOutcome::Cancelled => eprintln!("kill cancelled"),
        TerminationOutcome::ProtectedProcess => eprintln!(
            "error: {} is protected; --yes cannot bypass protected-process confirmation",
            target.identity(),
        ),
        TerminationOutcome::TargetChanged => eprintln!(
            "error: {} no longer owns the confirmed port target; no termination was sent",
            target.identity(),
        ),
        TerminationOutcome::UnsafePid(reason) => {
            eprintln!("error: unsafe PID blocked: {}", reason.message());
        }
        TerminationOutcome::UnknownFailure(error) => eprintln!(
            "error: sending {delivery} to {} failed: {}",
            target.identity(),
            sanitize(error),
        ),
    }
}

fn exit_reason_for_outcome(outcome: &TerminationOutcome) -> ExitReason {
    match outcome {
        TerminationOutcome::Success => ExitReason::Success,
        TerminationOutcome::PermissionDenied | TerminationOutcome::OwnershipUnavailable => {
            ExitReason::PermissionDenied
        }
        TerminationOutcome::AlreadyExited | TerminationOutcome::TargetChanged => {
            ExitReason::NoMatch
        }
        TerminationOutcome::Cancelled => ExitReason::KillCancelled,
        TerminationOutcome::ProtectedProcess => ExitReason::ProtectedNeedsConfirmation,
        TerminationOutcome::UnsafePid(_) | TerminationOutcome::UnknownFailure(_) => {
            ExitReason::Failure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KillCollectors, KillTargetError, POST_KILL_SETTLE_ATTEMPTS_MAX, PostKillPortsStatus,
        read_confirmation_line_from, resolve_kill_target, run_kill_with,
        wait_for_confirmed_ports_to_clear,
    };
    use crate::cli::test_support::{entry, entry_with_pid, no_context};
    use crate::cli::{ExitReason, KillArgs};
    use crate::collector::CollectorError;
    use crate::config::Config;
    use crate::model::Protocol;
    use crate::process::{
        ConfirmationRequirement, KillMode, KillTarget, TerminationOutcome, UnsafePidReason,
    };

    fn kill_pid(pid: u32, force: bool, yes: bool) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force,
            yes,
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        }
    }

    fn kill_port(port: u16, force: bool, yes: bool) -> KillArgs {
        KillArgs {
            pid: None,
            port: Some(port),
            force,
            yes,
            #[cfg(any(target_os = "linux", target_os = "macos", windows))]
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        }
    }

    #[test]
    fn kill_port_resolution_refuses_ambiguous_pids() {
        let rows = vec![
            entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
            entry_with_pid(3000, Some(200), Protocol::Udp, "worker"),
        ];

        let error = resolve_kill_target(&kill_port(3000, false, true), &rows, no_context)
            .expect_err("two PIDs on one port must be ambiguous");

        let KillTargetError::AmbiguousPort { port, candidates } = error else {
            panic!("expected ambiguous port error, got {error:?}");
        };
        assert_eq!(port, 3000);
        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.contains("PID 100"))
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.contains("PID 200"))
        );
    }

    #[test]
    fn kill_port_resolution_refuses_rows_without_pids() {
        let rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

        let error = resolve_kill_target(&kill_port(3000, false, true), &rows, no_context)
            .expect_err("a port without a PID is not killable");

        assert_eq!(error, KillTargetError::MissingPid { port: 3000 });
    }

    #[test]
    fn kill_port_without_readable_pid_exits_permission_denied() {
        let rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_port(3000, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || panic!("missing PID target must fail before revalidation"),
            },
            |_target, _mode, _requirement| panic!("missing PID target must not prompt"),
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("missing PID target must not prepare termination")
            },
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert!(!terminated);
    }

    #[test]
    fn kill_port_resolution_allows_one_pid_with_multiple_rows() {
        let rows = vec![
            entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
            entry_with_pid(3000, Some(100), Protocol::Udp, "node"),
        ];

        let target = resolve_kill_target(&kill_port(3000, false, true), &rows, no_context)
            .expect("one PID can own multiple matching rows");

        assert_eq!(target.pid, 100);
        assert_eq!(
            target.ports_text(),
            "TCP 127.0.0.1:3000, UDP 127.0.0.1:3000"
        );
    }

    #[test]
    fn kill_pid_resolution_blocks_unsafe_pids_before_lookup() {
        let error = resolve_kill_target(&kill_pid(1, false, true), &[], no_context)
            .expect_err("PID 1 must be blocked even if no row exists");

        assert_eq!(error, KillTargetError::UnsafePid(UnsafePidReason::One));
    }

    #[test]
    fn kill_yes_sends_signal_without_prompt_for_unprotected_target() {
        let rows = vec![entry(3000)];
        let mut terminated = None;
        // First collect backs pre-signal revalidation, so it must still show the
        // target; the post-kill settle poll then sees the port gone.
        let mut collect_calls = 0;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || {
                    collect_calls += 1;
                    if collect_calls == 1 {
                        Ok(rows.clone())
                    } else {
                        Ok(Vec::new())
                    }
                },
            },
            |_target, _mode, _requirement| panic!("--yes must skip normal prompts"),
            Ok::<u32, TerminationOutcome>,
            |pid: &u32, mode| {
                terminated = Some((*pid, mode));
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(terminated, Some((18_422, KillMode::Terminate)));
    }

    #[test]
    fn protected_process_yes_returns_exit_6_without_signalling() {
        let mut row = entry_with_pid(5432, Some(54_321), Protocol::Tcp, "postgres");
        row.protected = true;
        let rows = vec![row];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_port(5432, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(rows.clone()),
            },
            |_target, _mode, _requirement| panic!("protected --yes must not prompt"),
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("protected --yes must not prepare termination")
            },
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
        assert!(!terminated);
    }

    #[test]
    fn force_kill_uses_force_word_confirmation_when_configured() {
        let rows = vec![entry(3000)];
        let mut prompted = None;
        // As above: revalidation still sees the target, the settle poll does not.
        let mut collect_calls = 0;

        let reason = run_kill_with(
            &kill_pid(18_422, true, false),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || {
                    collect_calls += 1;
                    if collect_calls == 1 {
                        Ok(rows.clone())
                    } else {
                        Ok(Vec::new())
                    }
                },
            },
            |_target, mode, requirement| {
                prompted = Some((mode, requirement));
                Ok(true)
            },
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _mode| TerminationOutcome::Success,
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(
            prompted,
            Some((KillMode::Force, ConfirmationRequirement::ForceWord)),
        );
    }

    #[test]
    fn declined_confirmation_cancels_without_signalling() {
        let rows = vec![entry(3000)];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, false),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(rows.clone()),
            },
            |_target, _mode, requirement| {
                assert_eq!(requirement, ConfirmationRequirement::Yes);
                Ok(false)
            },
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("declined confirmation must not prepare termination")
            },
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::KillCancelled);
        assert!(!terminated);
    }

    #[test]
    fn target_is_revalidated_after_confirmation_before_signal() {
        let rows = vec![entry(3000)];
        let fresh_rows = vec![entry_with_pid(4000, Some(18_422), Protocol::Tcp, "node")];
        let mut prepared = None;
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(fresh_rows.clone()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |pid| {
                prepared = Some(pid);
                Ok(pid)
            },
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::NoMatch);
        assert_eq!(prepared, Some(18_422));
        assert!(!terminated);
    }

    #[test]
    fn prepare_failure_stops_before_revalidation_or_signal() {
        let rows = vec![entry(3000)];
        let mut collected = false;
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || {
                    collected = true;
                    Ok(rows.clone())
                },
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |_pid| -> Result<u32, TerminationOutcome> { Err(TerminationOutcome::AlreadyExited) },
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::NoMatch);
        assert!(!collected);
        assert!(!terminated);
    }

    #[test]
    fn target_losing_readable_pid_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_port(3000, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(fresh_rows.clone()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert!(!terminated);
    }

    #[test]
    fn kill_pid_losing_readable_owner_during_revalidation_exits_permission_denied() {
        // A `--pid` kill whose confirmed port stays visible but whose owner PID
        // becomes unreadable during revalidation must abort as
        // ownership-unavailable (exit 4), matching `--port` and the TUI, instead
        // of looking like a vanished target (exit 3). No signal is sent.
        let rows = vec![entry(3000)];
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(fresh_rows.clone()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert!(!terminated);
    }

    #[test]
    fn target_becoming_protected_after_confirmation_blocks_signal() {
        let rows = vec![entry(3000)];
        let mut protected = entry(3000);
        protected.protected = true;
        let fresh_rows = vec![protected];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(fresh_rows.clone()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
        assert!(!terminated);
    }

    #[test]
    fn confirmation_input_accepts_utf8_at_the_byte_limit() {
        let mut input = std::io::Cursor::new("é\n".as_bytes());

        let answer = read_confirmation_line_from(&mut input, 3).expect("input fits exactly");

        assert_eq!(answer, "é\n");
    }

    #[test]
    fn overlong_confirmation_is_rejected_and_its_line_is_drained() {
        let mut input = std::io::Cursor::new(b"force-extra\ntree\n");

        let error = read_confirmation_line_from(&mut input, 5).expect_err("input is over limit");
        let next = read_confirmation_line_from(&mut input, 5).expect("next line remains intact");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("5-byte limit"));
        assert_eq!(next, "tree\n");
    }

    fn settle_target() -> KillTarget {
        let row = entry(3000);
        KillTarget::from_entries(18_422, [&row], None)
    }

    #[test]
    fn post_kill_settle_clears_when_ports_disappear_on_a_later_poll() {
        // SIGTERM teardown is asynchronous: the first polls still see the port,
        // a later one must turn that into a clean "cleared" rather than the
        // still-visible warning.
        let target = settle_target();
        let mut collect_calls = 0;
        let mut sleeps = 0;

        let status = wait_for_confirmed_ports_to_clear(
            &target,
            &mut || {
                collect_calls += 1;
                if collect_calls < 3 {
                    Ok(vec![entry(3000)])
                } else {
                    Ok(Vec::new())
                }
            },
            |_delay| sleeps += 1,
        );

        assert_eq!(status, PostKillPortsStatus::Cleared);
        assert_eq!(collect_calls, 3);
        assert_eq!(sleeps, 2);
    }

    #[test]
    fn post_kill_settle_reports_still_visible_after_bounded_attempts() {
        let target = settle_target();
        let mut collect_calls = 0;
        let mut sleeps = 0;

        let status = wait_for_confirmed_ports_to_clear(
            &target,
            &mut || {
                collect_calls += 1;
                Ok(vec![entry(3000)])
            },
            |_delay| sleeps += 1,
        );

        assert_eq!(status, PostKillPortsStatus::StillVisible);
        assert_eq!(collect_calls, POST_KILL_SETTLE_ATTEMPTS_MAX);
        // No trailing sleep after the last poll: once the verdict is known,
        // waiting longer would only delay the honest warning.
        assert_eq!(sleeps, POST_KILL_SETTLE_ATTEMPTS_MAX - 1);
    }

    #[test]
    fn post_kill_settle_stays_visible_while_any_confirmed_port_remains() {
        // A multi-port target is only "cleared" when every confirmed port is
        // gone: one lingering port must keep the still-visible warning, not
        // be averaged away because the other port closed. This pins the
        // any-port-remains check against a quiet flip to all-ports-remain.
        let row_a = entry(3000);
        let row_b = entry(3001);
        let target = KillTarget::from_entries(18_422, [&row_a, &row_b], None);
        let mut collect_calls = 0;
        let mut sleeps = 0;

        let status = wait_for_confirmed_ports_to_clear(
            &target,
            &mut || {
                collect_calls += 1;
                // Port 3000 closes immediately; 3001 never does.
                Ok(vec![entry(3001)])
            },
            |_delay| sleeps += 1,
        );

        assert_eq!(status, PostKillPortsStatus::StillVisible);
        assert_eq!(collect_calls, POST_KILL_SETTLE_ATTEMPTS_MAX);
        assert_eq!(sleeps, POST_KILL_SETTLE_ATTEMPTS_MAX - 1);
    }

    #[test]
    fn post_kill_settle_fails_closed_when_refresh_errors() {
        let target = settle_target();
        let mut collect_calls = 0;
        let mut sleeps = 0;

        let status = wait_for_confirmed_ports_to_clear(
            &target,
            &mut || {
                collect_calls += 1;
                if collect_calls == 1 {
                    Ok(vec![entry(3000)])
                } else {
                    Err(CollectorError::WorkerExited)
                }
            },
            |_delay| sleeps += 1,
        );

        // A failed refresh must not be spun into "cleared" or polled forever;
        // it surfaces as the refresh warning immediately.
        assert!(matches!(status, PostKillPortsStatus::RefreshFailed(_)));
        assert_eq!(collect_calls, 2);
        assert_eq!(sleeps, 1);
    }
}
