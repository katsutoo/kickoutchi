//! The single-process `kill` command: exactly one confirmed target, resolved,
//! confirmed, revalidated fresh, and only then signalled. The scoped
//! (`--tree`/`--group`) flows reuse the resolution, revalidation, and
//! confirmation-input helpers defined here.

use std::io::{self, BufRead, ErrorKind, Read, Write};
use std::time::Duration;

use crate::collector;
use crate::command;
use crate::config::Config;
use crate::display::{human_endpoint_text, sanitize};
use crate::model::{PortEntry, PortEntryView, ProcessContext};
use crate::observation::MetadataProfile;
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

pub(super) fn run_kill(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
) -> ExitReason {
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
            collect_kill_ports: || collector::collect_kill_ports(args.pid, args.port),
            collect_visibility_ports: || {
                collector::collect_ports_with_profile(POST_KILL_VISIBILITY_PROFILE)
            },
        },
        prompt_confirmation,
        process::prepare_termination,
        process::terminate_handle_checked,
    )
}

#[expect(
    clippy::struct_field_names,
    reason = "the shared collect_ prefix names the seam each field injects"
)]
struct KillCollectors<CollectContext, CollectKillPorts, CollectVisibilityPorts> {
    collect_context: CollectContext,
    collect_kill_ports: CollectKillPorts,
    collect_visibility_ports: CollectVisibilityPorts,
}

fn run_kill_with<
    CollectContext,
    CollectKillPorts,
    CollectVisibilityPorts,
    Prompt,
    Prepare,
    Terminate,
    Handle,
>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    mut collectors: KillCollectors<CollectContext, CollectKillPorts, CollectVisibilityPorts>,
    mut prompt: Prompt,
    mut prepare: Prepare,
    mut terminate: Terminate,
) -> ExitReason
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectKillPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    CollectVisibilityPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
    Prompt: FnMut(&KillTarget, KillMode, ConfirmationRequirement) -> std::io::Result<bool>,
    Prepare: FnMut(u32) -> Result<Handle, TerminationOutcome>,
    Terminate: FnMut(&Handle, &KillTarget, &[String], KillMode) -> TerminationOutcome,
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

    let target = match revalidate_single_cli_target(
        args,
        config,
        &target,
        &mut collectors.collect_context,
        &mut collectors.collect_kill_ports,
    ) {
        Ok(target) => target,
        Err(outcome) => {
            print_termination_outcome(&target, mode, &outcome);
            return exit_reason_for_outcome(&outcome);
        }
    };
    let outcome = terminate(&handle, &target, &config.protected_processes, mode);
    print_termination_outcome(&target, mode, &outcome);
    if outcome == TerminationOutcome::Success {
        print_post_kill_refresh_status(&target, &mut collectors.collect_visibility_ports);
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
const POST_KILL_VISIBILITY_PROFILE: MetadataProfile = MetadataProfile::IdentityOnly;

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
        let still_visible = entries.iter().map(PortEntryView::from).any(|entry| {
            process::kill_target_has_port(&target.ports, &process::KillTargetPort::from(entry))
        });
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
    revalidate_cli_target_with(
        args,
        config,
        confirmed,
        collect_context,
        collect_ports,
        false,
    )
}

fn revalidate_single_cli_target<CollectContext, CollectPorts>(
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
    revalidate_cli_target_with(
        args,
        config,
        confirmed,
        collect_context,
        collect_ports,
        true,
    )
}

fn revalidate_cli_target_with<CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    require_protection_name: bool,
) -> Result<KillTarget, TerminationOutcome>
where
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let mut fresh_entries = collect_ports().map_err(|error| {
        if error.is_ownership_permission_denied() {
            TerminationOutcome::OwnershipUnavailable
        } else {
            TerminationOutcome::UnknownFailure(format!(
                "collecting ports before kill failed: {error}"
            ))
        }
    })?;
    mark_protected(&mut fresh_entries, &config.protected_processes);
    // The closure owns the snapshot it collected from, so the rows arrive owned
    // and are borrowed once here for every read below.
    let fresh_entries = fresh_entries
        .iter()
        .map(PortEntryView::from)
        .collect::<Vec<_>>();

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
    if require_protection_name {
        process::validate_single_delivery_evidence(confirmed, &fresh)?;
    }
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
    entries: &[PortEntryView<'_>],
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
    entries: &[PortEntryView<'_>],
    mut collect_context: CollectContext,
) -> Result<KillTarget, KillTargetError>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let rows: Vec<PortEntryView<'_>> = entries
        .iter()
        .copied()
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
    entries: &[PortEntryView<'_>],
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
pub(super) fn resolve_single_port_owner<'a>(
    port: u16,
    entries: &[PortEntryView<'a>],
) -> Result<(u32, Vec<PortEntryView<'a>>), KillTargetError> {
    let rows: Vec<PortEntryView<'a>> = entries
        .iter()
        .copied()
        .filter(|entry| entry.local_port == port)
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

fn candidate_labels(rows: &[PortEntryView<'_>]) -> Vec<String> {
    let mut candidates = rows
        .iter()
        .filter_map(|entry| {
            let pid = entry.pid?;
            let name = sanitize(entry.process_name.unwrap_or("<unknown>"));
            Some(format!(
                "PID {pid} ({name}) {} {}",
                entry.protocol.label(),
                human_endpoint_text(entry.local_addr, entry.local_port, entry.ipv6_scope),
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
    eprintln!("{} {}", mode.action_label(), target.identity());
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
    // `usize` is at most 64 bits on every supported target, so widening to the
    // `u64` `Take` limit is lossless; the sole production limit is the small
    // constant `CONFIRMATION_INPUT_MAX_BYTES`, so the two bytes of headroom
    // for a trailing "\r\n" cannot overflow either — `saturating_add` only
    // guards the theoretical `usize::MAX` limit.
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(2);
    let mut bytes = Vec::with_capacity(max_bytes.saturating_add(2));
    (&mut *reader).take(limit).read_until(b'\n', &mut bytes)?;

    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("confirmation input exceeds the {max_bytes}-byte limit"),
        ));
    }

    String::from_utf8(bytes).map_err(|error| io::Error::new(ErrorKind::InvalidData, error))
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
        TerminationOutcome::ThawFailed { pid, prior } => eprintln!(
            "error: {}; cleanup could not continue PID {pid}; it may remain stopped and require SIGCONT",
            sanitize(&prior.failure_cause_text()),
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
        TerminationOutcome::UnsafePid(_)
        | TerminationOutcome::UnknownFailure(_)
        | TerminationOutcome::ThawFailed { .. } => ExitReason::Failure,
    }
}

#[cfg(test)]
mod tests {
    use crate::model::PortEntryView;
    use crate::model::entry_views;
    use std::cell::RefCell;

    use super::{
        KillCollectors, KillTargetError, POST_KILL_SETTLE_ATTEMPTS_MAX, PostKillPortsStatus,
        read_confirmation_line_from, resolve_kill_target, run_kill_with,
        wait_for_confirmed_ports_to_clear,
    };
    use crate::cli::test_support::{entry, entry_with_pid, no_context};
    use crate::cli::{ExitReason, KillArgs};
    use crate::collector::{Collector, CollectorError, FakeCollector, kill_ports_from_snapshot};
    use crate::config::Config;
    use crate::model::Protocol;
    use crate::observation::{
        EvidenceGap, EvidenceGapCode, EvidenceImpact, MetadataProfile, NetworkSnapshot,
        ObservationError, OwnerCompleteness, OwnerObservation, UnverifiedOwnerReason,
    };
    use crate::process::{
        CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
        TerminationOutcome, UnsafePidReason,
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

    fn permission_denied_owner_snapshot() -> NetworkSnapshot {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        let socket = snapshot
            .sockets
            .iter_mut()
            .find(|socket| socket.local_endpoint.port.get() == 3000)
            .expect("fixture has target socket");
        let endpoint = socket.local_endpoint.clone();
        socket.owners = vec![OwnerObservation::UnverifiedPid {
            pid: 18_422,
            reason: UnverifiedOwnerReason::PermissionDenied,
        }];
        socket.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied])
                .expect("one reason fits");
        snapshot
            .processes
            .retain(|identity, _| identity.pid != 18_422);
        snapshot.owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerPermissionDenied,
        ])
        .expect("fixture reasons fit");
        for _ in 0..2 {
            snapshot.evidence_gaps.push(EvidenceGap::new(
                EvidenceImpact::Ownership,
                EvidenceGapCode::OwnerPermissionDenied,
                Some(endpoint.clone()),
                Some(18_422),
                "native owner PID could not be verified to a process start identity",
            ));
        }
        snapshot
    }

    #[test]
    fn kill_port_resolution_refuses_ambiguous_pids() {
        let rows = vec![
            entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
            entry_with_pid(3000, Some(200), Protocol::Udp, "worker"),
        ];

        let error = resolve_kill_target(
            &kill_port(3000, false, true),
            &entry_views(&rows),
            no_context,
        )
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

        let error = resolve_kill_target(
            &kill_port(3000, false, true),
            &entry_views(&rows),
            no_context,
        )
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || panic!("missing PID target must fail before revalidation"),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("missing PID target must not prompt"),
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("missing PID target must not prepare termination")
            },
            |_pid: &u32, _target, _protected, _mode| {
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

        let target = resolve_kill_target(
            &kill_port(3000, false, true),
            &entry_views(&rows),
            no_context,
        )
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
    fn resolution_pins_the_snapshot_owner_marker_not_detached_context_identity() {
        let rows = vec![entry(3000)];
        let target = resolve_kill_target(
            &kill_pid(18_422, false, true),
            &entry_views(&rows),
            |_pid| crate::model::ProcessContext {
                process_start_time_marker: crate::observation::ProcessStartMarker::linux(99).ok(),
                ..crate::model::ProcessContext::default()
            },
        )
        .expect("verified snapshot row resolves");

        assert_eq!(
            target.process_start_time_marker,
            crate::observation::ProcessStartMarker::linux(55).ok(),
        );
    }

    #[test]
    fn kill_yes_sends_signal_without_prompt_for_unprotected_target() {
        let rows = vec![entry(3000)];
        let mut terminated = None;
        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes must skip normal prompts"),
            Ok::<u32, TerminationOutcome>,
            |pid: &u32, _target, _protected, mode| {
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("protected --yes must not prompt"),
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("protected --yes must not prepare termination")
            },
            |_pid: &u32, _target, _protected, _mode| {
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
        let reason = run_kill_with(
            &kill_pid(18_422, true, false),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, mode, requirement| {
                prompted = Some((mode, requirement));
                Ok(true)
            },
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _target, _protected, _mode| TerminationOutcome::Success,
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, requirement| {
                assert_eq!(requirement, ConfirmationRequirement::Yes);
                Ok(false)
            },
            |_pid| -> Result<u32, TerminationOutcome> {
                panic!("declined confirmation must not prepare termination")
            },
            |_pid: &u32, _target, _protected, _mode| {
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(fresh_rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |pid| {
                prepared = Some(pid);
                Ok(pid)
            },
            |_pid: &u32, _target, _protected, _mode| {
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || {
                    collected = true;
                    Ok(rows.clone())
                },
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |_pid| -> Result<u32, TerminationOutcome> { Err(TerminationOutcome::AlreadyExited) },
            |_pid: &u32, _target, _protected, _mode| {
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
        let snapshot = permission_denied_owner_snapshot();
        let mut prepared = false;
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_port(3000, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || kill_ports_from_snapshot(&snapshot, None, Some(3000)),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |pid| {
                prepared = true;
                Ok::<u32, TerminationOutcome>(pid)
            },
            |_pid: &u32, _target, _protected, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        // The denial surfaces during post-prepare revalidation: the handle was
        // already prepared, but no signal may be delivered through it.
        assert!(prepared);
        assert!(!terminated);
    }

    #[test]
    fn unrelated_endpointless_ownership_gap_does_not_block_port_delivery() {
        let mut snapshot = FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake collection succeeds");
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            Some(29_999),
            "unrelated process ownership could not be attributed to an endpoint",
        ));
        let rows = kill_ports_from_snapshot(&snapshot, None, Some(3000))
            .expect("the unrelated ownership gap must not block the target port");
        let mut delivered = false;
        let mut visibility_polls = 0;

        let reason = run_kill_with(
            &kill_port(3000, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || kill_ports_from_snapshot(&snapshot, None, Some(3000)),
                collect_visibility_ports: || {
                    visibility_polls += 1;
                    Ok(Vec::new())
                },
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_handle: &u32, target, _protected, _mode| {
                delivered = true;
                assert_eq!(target.pid, 18_422);
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert!(delivered);
        assert_eq!(visibility_polls, 1);
    }

    #[test]
    fn authoritative_snapshot_refusal_reaches_zero_delivery() {
        let rows = vec![entry(3000)];
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || {
                    Err(CollectorError::Observation(
                        ObservationError::PartialSocketSet,
                    ))
                },
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _target, _protected, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(!terminated);
    }

    #[test]
    fn port_owner_moving_after_handle_preparation_never_signals_old_owner() {
        let rows = vec![entry(3000)];
        let moved = vec![entry_with_pid(
            3000,
            Some(29_999),
            Protocol::Tcp,
            "replacement",
        )];
        let events = RefCell::new(Vec::new());

        let reason = run_kill_with(
            &kill_port(3000, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || {
                    events.borrow_mut().push("collect");
                    Ok(moved.clone())
                },
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            |pid| {
                assert_eq!(pid, 18_422);
                events.borrow_mut().push("prepare");
                Ok::<u32, TerminationOutcome>(pid)
            },
            |_handle: &u32, _target, _protected, _mode| {
                events.borrow_mut().push("deliver");
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(*events.borrow(), ["prepare", "collect"]);
    }

    #[test]
    fn kill_pid_losing_readable_owner_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let snapshot = permission_denied_owner_snapshot();
        let mut terminated = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || kill_ports_from_snapshot(&snapshot, Some(18_422), None),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _target, _protected, _mode| {
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
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(fresh_rows.clone()),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_pid: &u32, _target, _protected, _mode| {
                terminated = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
        assert!(!terminated);
    }

    #[test]
    fn missing_fresh_protection_name_refuses_without_delivery() {
        let rows = vec![entry(3000)];
        let mut fresh = entry(3000);
        fresh.process_name = None;
        let mut delivered = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(vec![fresh.clone()]),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_handle: &u32, _target, _protected, _mode| {
                delivered = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(!delivered);
    }

    #[test]
    fn oversized_fresh_protection_name_refuses_without_delivery() {
        let mut rows = vec![entry(3000)];
        rows[0].process_name = None;
        let mut fresh = entry(3000);
        fresh.process_name = Some(
            "x".repeat(crate::observation::PROTECTION_NAME_MAX_BYTES + 1)
                .into(),
        );
        let mut delivered = false;

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &entry_views(&rows),
            KillCollectors {
                collect_context: no_context,
                collect_kill_ports: || Ok(vec![fresh.clone()]),
                collect_visibility_ports: || Ok(Vec::new()),
            },
            |_target, _mode, _requirement| panic!("--yes skips prompts"),
            Ok::<u32, TerminationOutcome>,
            |_handle: &u32, _target, _protected, _mode| {
                delivered = true;
                TerminationOutcome::Success
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(!delivered);
    }

    #[test]
    fn confirmation_input_accepts_utf8_at_the_byte_limit() {
        let exact_payload = format!("{}é", "x".repeat(CONFIRMATION_INPUT_MAX_BYTES - 2));
        assert_eq!(exact_payload.len(), CONFIRMATION_INPUT_MAX_BYTES);

        for framed in [
            exact_payload.clone(),
            format!("{exact_payload}\n"),
            format!("{exact_payload}\r\n"),
        ] {
            let mut input = std::io::Cursor::new(framed.into_bytes());
            let answer = read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES)
                .expect("exact payload must fit with any supported line framing");

            assert_eq!(answer, exact_payload);
        }
    }

    #[test]
    fn overlong_confirmation_stops_after_limit_plus_one_bytes() {
        let mut bytes = vec![b'x'; CONFIRMATION_INPUT_MAX_BYTES + 1];
        bytes.push(b'\n');
        let mut input = std::io::Cursor::new(bytes);

        let error = read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES)
            .expect_err("first excess payload byte must be rejected");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(
            error
                .to_string()
                .contains(&format!("{CONFIRMATION_INPUT_MAX_BYTES}-byte limit"))
        );
        assert_eq!(
            input.position(),
            u64::try_from(CONFIRMATION_INPUT_MAX_BYTES + 2).unwrap()
        );
    }

    #[test]
    fn confirmation_input_handles_empty_lines_and_invalid_utf8() {
        for bytes in [b"".as_slice(), b"\n".as_slice(), b"\r\n".as_slice()] {
            let mut input = std::io::Cursor::new(bytes);
            assert_eq!(
                read_confirmation_line_from(&mut input, CONFIRMATION_INPUT_MAX_BYTES).unwrap(),
                ""
            );
        }

        let mut invalid = std::io::Cursor::new([0xff, b'\n']);
        let error = read_confirmation_line_from(&mut invalid, CONFIRMATION_INPUT_MAX_BYTES)
            .expect_err("invalid UTF-8 must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    fn settle_target() -> KillTarget {
        let row = entry(3000);
        KillTarget::from_entries(18_422, [PortEntryView::from(&row)], None)
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
        let target = KillTarget::from_entries(
            18_422,
            [PortEntryView::from(&row_a), PortEntryView::from(&row_b)],
            None,
        );
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
