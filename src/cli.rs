//! The non-TUI command-line side: the argument shape, the stable exit-code
//! contract, and the `list`/`kill` commands themselves.
//!
//! CLI commands never pop open the TUI — they print to stdout/stderr and exit.
//! The data flows through the same collector and model as the TUI, so the two
//! stay in sync and this layer doesn't care which collector produced the rows.

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::collector;
use crate::command;
use crate::config::{Config, REFRESH_INTERVAL_SECONDS_MAX, REFRESH_INTERVAL_SECONDS_MIN};
use crate::diagnostic;
use crate::display::sanitize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::inspect;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::model::{PermissionStatus, Platform, SystemProcessCheck};
use crate::model::{PortEntry, ProcessContext, SortMode};
use crate::output;
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome, UnsafePidReason,
};
use crate::protection::mark_protected;
use crate::query::{self, QueryOptions};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree;

/// Stable exit codes — the script-facing contract.
///
/// All in one place so scripts can count on the numbers never drifting. Every
/// variant really is constructed somewhere on the CLI exit path, so don't reach
/// for a dead-code allow here; keep the contract complete even though clap is the
/// one that actually hands out `InvalidArguments` (2) in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ExitReason {
    Success = 0,
    Failure = 1,
    InvalidArguments = 2,
    NoMatch = 3,
    PermissionDenied = 4,
    KillCancelled = 5,
    ProtectedNeedsConfirmation = 6,
}

impl From<ExitReason> for ExitCode {
    fn from(reason: ExitReason) -> Self {
        Self::from(reason as u8)
    }
}

/// Top-level argument shape. No subcommand opens the TUI; `list` and `kill`
/// run headless and exit.
///
/// `about` pulls the user-facing summary straight from the Cargo.toml
/// `description`; `long_about = None` is there so clap *doesn't* dump this doc
/// comment into `--help` — these lines are notes for developers, not users.
///
/// The fixed `name` keeps `--version` reporting the canonical `kickoutchi` under
/// both binary names, while clap takes the usage line from argv(0), so
/// `kick --help` correctly shows `Usage: kick ...`. Both are exactly what we want
/// for the short-alias binary.
#[derive(Debug, Parser)]
#[command(name = "kickoutchi", version, about, long_about = None)]
pub(crate) struct Cli {
    /// Path to an alternate config file (default: the platform config dir).
    #[arg(long, value_name = "FILE", global = true)]
    pub(crate) config: Option<PathBuf>,

    /// Override the configured refresh interval, in seconds.
    ///
    /// clap enforces the same bounds as the config file, so an out-of-range
    /// flag is a usage error (exit 2) instead of a config error (exit 1).
    #[arg(
        long,
        value_name = "SECONDS",
        global = true,
        value_parser = clap::value_parser!(u64).range(REFRESH_INTERVAL_SECONDS_MIN..=REFRESH_INTERVAL_SECONDS_MAX)
    )]
    pub(crate) refresh_interval: Option<u64>,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Print open ports and exit.
    List(ListArgs),
    /// Terminate the process owning a port or PID (after confirmation).
    Kill(KillArgs),
    /// Show a process's family — ancestors, descendants, siblings, process
    /// group, and ports — read-only, to pick the right root for a tree kill.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Inspect(InspectArgs),
}

/// `inspect` takes exactly one starting point, like `kill`: a PID (which may
/// own no port — supervisors usually don't) or a port whose owner to start
/// from. Strictly read-only; it never signals anything.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "port"])))]
pub(crate) struct InspectArgs {
    /// PID whose family to show.
    #[arg(long)]
    pub(crate) pid: Option<u32>,

    /// Show the family of the process that owns this port.
    #[arg(long)]
    pub(crate) port: Option<u16>,
}

#[derive(Debug, Args)]
pub(crate) struct ListArgs {
    /// Only show rows bound to this exact port.
    #[arg(long)]
    pub(crate) port: Option<u16>,

    /// Only show rows whose process name contains this text.
    #[arg(long)]
    pub(crate) process: Option<String>,

    /// Apply TUI-style search text or structured filters.
    ///
    /// Examples: `3000`, `port:3000`, `proto:udp`, `scope:public`,
    /// `protected:true`, `parent:node`.
    #[arg(long, value_name = "TEXT")]
    pub(crate) filter: Option<String>,

    /// Sort rows by port, pid, protocol, process, parent, or scope.
    #[arg(long, value_name = "MODE", value_parser = parse_sort_mode)]
    pub(crate) sort: Option<SortMode>,

    /// Print stable JSON instead of a table.
    #[arg(long)]
    pub(crate) json: bool,
}

/// `kill` requires exactly one target: a PID or a port. Requiring one stops
/// a bare `kickoutchi kill` from meaning "kill something"; forbidding both
/// stops a contradictory selection.
// Each bool is one independent CLI flag; clap's derive needs them as bools,
// and the contradictory combination (`--tree --group`) is already rejected at
// parse time via `conflicts_with`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("target").required(true).args(["pid", "port"])))]
pub(crate) struct KillArgs {
    /// PID of the process to terminate.
    #[arg(long)]
    pub(crate) pid: Option<u32>,

    /// Terminate the process that owns this port.
    #[arg(long)]
    pub(crate) port: Option<u16>,

    /// Force kill instead of normal termination where the platform supports a distinction.
    #[arg(long)]
    pub(crate) force: bool,

    /// Skip the confirmation prompt. Never bypasses protected-process
    /// confirmation.
    #[arg(long)]
    pub(crate) yes: bool,

    /// Terminate the whole process tree rooted at the target, not just the one
    /// process. Opt-in; typed confirmation unless --yes passes all-clear gates.
    /// Linux and macOS only.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long)]
    pub(crate) tree: bool,

    /// Terminate the target's whole process group — every process sharing its
    /// group ID, including members that reparented away from the tree. Opt-in;
    /// typed confirmation unless --yes passes all-clear gates. Linux and macOS
    /// only.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[arg(long, conflicts_with = "tree")]
    pub(crate) group: bool,
}

/// Run a CLI command to completion and report how the process should exit.
///
/// Errors are printed here (stderr) rather than propagated: the exit-code
/// mapping is this module's whole job, so letting errors escape to `main`
/// would split that contract across two files.
pub(crate) fn run(command: &Command, config: &Config) -> ExitReason {
    let mut entries = match collector::collect_ports() {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: collecting ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    mark_protected(&mut entries, &config.protected_processes);

    match command {
        Command::List(args) => run_list(args, config, &entries),
        Command::Kill(args) => run_kill(args, config, &entries),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Command::Inspect(args) => run_inspect(args, config, &entries),
    }
}

fn run_list(args: &ListArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    let sort_mode = args.sort.unwrap_or(config.default_sort);
    let diagnostic_port = diagnostic::requested_diagnostic_port(
        args.port,
        args.filter.as_deref().unwrap_or_default(),
    );
    let result = match query::query_entries(
        entries,
        QueryOptions {
            port: args.port,
            process: args.process.as_deref(),
            filter_text: args.filter.as_deref().unwrap_or_default(),
            sort_mode,
            hide_system_processes: config.hide_system_processes,
        },
    ) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("error: invalid filter: {error}");
            return ExitReason::InvalidArguments;
        }
    };
    let visible_entries = result.entries;

    if args.json {
        match output::render_json(&visible_entries) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("error: rendering JSON failed: {error}");
                return ExitReason::Failure;
            }
        }
    } else if visible_entries.is_empty() {
        let suffix = if result.explicit_filter_active {
            " match the filter"
        } else if result.hidden_system_process_count > 0 {
            " visible"
        } else {
            ""
        };
        println!("no open ports{suffix}");
        maybe_print_no_match_diagnostic(diagnostic_port, entries);
    } else {
        println!("{}", output::render_table(&visible_entries));
    }

    // An empty *filtered* result exits 3, so scripts can probe occupancy
    // (`kickoutchi list --port 3000 && echo busy`). An empty *unfiltered* list
    // just means a quiet machine — that's a success, not a failure.
    if result.explicit_filter_active && visible_entries.is_empty() {
        return ExitReason::NoMatch;
    }
    ExitReason::Success
}

fn maybe_print_no_match_diagnostic(diagnostic_port: Option<u16>, entries: &[PortEntry]) {
    let Some(port) = diagnostic_port_without_confirmed_socket(diagnostic_port, entries) else {
        return;
    };
    let hints = platform::collect_related_process_hints(port);
    if let Some(message) = diagnostic::diagnostic_message(port, &hints) {
        eprint!("{message}");
    }
}

fn diagnostic_port_without_confirmed_socket(
    diagnostic_port: Option<u16>,
    entries: &[PortEntry],
) -> Option<u16> {
    let port = diagnostic_port?;
    if entries.iter().any(|entry| entry.local_port == port) {
        None
    } else {
        Some(port)
    }
}

fn parse_sort_mode(value: &str) -> Result<SortMode, String> {
    SortMode::from_label(value)
        .ok_or_else(|| "expected one of: port, pid, protocol, process, parent, scope".to_owned())
}

fn run_kill(args: &KillArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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

/// Run the read-only family inspection and print the report to stdout.
///
/// No signals, no confirmation: the strongest thing this command does is
/// suggest a `kick kill --pid <root> --tree` for the user to run themselves.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_inspect(args: &InspectArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    let target_pid = match resolve_inspect_target(args, entries) {
        Ok(pid) => pid,
        Err(KillTargetError::NoMatch) => {
            eprintln!("error: no open port matches the requested target");
            // Same evidence-only hint `list` prints: a command line naming the
            // port often identifies the process the user was looking for.
            maybe_print_no_match_diagnostic(args.port, entries);
            return ExitReason::NoMatch;
        }
        Err(error) => return print_target_error(error),
    };

    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    let snapshot = match tree::TreeProcessOps::snapshot(&mut ops) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process table failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    match inspect::render_family_report(
        target_pid,
        &snapshot,
        entries,
        &config.protected_processes,
        TREE_HOST_PLATFORM,
        platform::process_command_line,
    ) {
        Ok(report) => {
            print!("{report}");
            ExitReason::Success
        }
        Err(inspect::InspectError::TargetMissing) => {
            eprintln!("error: PID {target_pid} is not running");
            ExitReason::NoMatch
        }
    }
}

/// Pick the PID to inspect. Unlike kill resolution there is no unsafe-PID
/// guard: reading PID 1's family is legitimate, and nothing here signals.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_inspect_target(
    args: &InspectArgs,
    entries: &[PortEntry],
) -> Result<u32, KillTargetError> {
    match (args.pid, args.port) {
        (Some(pid), None) => Ok(pid),
        (None, Some(port)) => {
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
            Ok(*pid)
        }
        (None, None) | (Some(_), Some(_)) => {
            unreachable!("clap requires exactly one inspect target")
        }
    }
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

fn print_post_kill_refresh_status<CollectPorts>(
    target: &KillTarget,
    collect_ports: &mut CollectPorts,
) where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // A portless root (a `--pid` supervisor) confirmed no ports, so there is
    // nothing to poll and nothing honest to report about port visibility.
    if target.ports.is_empty() {
        return;
    }
    match wait_for_confirmed_ports_to_clear(target, collect_ports, std::thread::sleep) {
        PostKillPortsStatus::Cleared => {
            eprintln!("confirmed target ports are no longer visible");
        }
        PostKillPortsStatus::StillVisible => eprintln!(
            "warning: one or more confirmed ports are still visible after termination; another process may own them or shutdown may still be completing",
        ),
        PostKillPortsStatus::RefreshFailed(error) => eprintln!(
            "warning: collecting ports after termination failed; refresh manually to verify the port disappeared: {error}",
        ),
    }
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

fn revalidate_cli_target<CollectContext, CollectPorts>(
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
enum KillTargetError {
    NoMatch,
    MissingPid { port: u16 },
    AmbiguousPort { port: u16, candidates: Vec<String> },
    UnsafePid(UnsafePidReason),
}

fn resolve_kill_target<CollectContext>(
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
    if let Some(reason) = process::unsafe_pid_reason(*pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }

    let context = collect_context(*pid);
    Ok(KillTarget::from_entries(*pid, rows, Some(&context)))
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

fn print_target_error(error: KillTargetError) -> ExitReason {
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

fn read_confirmation_line(max_bytes: usize) -> std::io::Result<String> {
    let mut answer = String::new();
    let limit = u64::try_from(max_bytes).expect("confirmation limit must fit in u64") + 1;
    std::io::stdin().lock().take(limit).read_line(&mut answer)?;
    truncate_to_char_boundary(&mut answer, max_bytes);
    Ok(answer)
}

fn truncate_to_char_boundary(text: &mut String, max_bytes: usize) {
    if text.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
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

/// Longest child preview printed in the tree confirmation banner.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const TREE_PREVIEW_MAX: usize = 12;

/// What the user must do to authorize a tree kill.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmation {
    /// Type a literal word (`tree` for terminate, `force` for force).
    TypedWord(&'static str),
    /// The root is protected: type its PID or process name, as with a
    /// single-process protected kill.
    ProtectedRoot,
}

/// The confirmation gate for a tree kill, decided before the prompt is shown.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TreeConfirmDecision {
    /// `--yes` on an all-clear tree: proceed without a prompt.
    Skip,
    /// Ask the user to satisfy this requirement.
    PromptWord(&'static str),
    /// Protected root requires the protected confirmation and then the tree word.
    PromptProtectedThenWord(&'static str),
    /// `--yes` cannot authorize a protected root: refuse.
    RefuseProtectedYes,
}

/// Facts established by confirmation and needed by the fresh
/// execution-time gates. `skipped_prompt` is deliberately separate from
/// `args.yes`: `--yes` can still fall back to a typed prompt when the preview has
/// warnings, and that explicit word should not be treated as a silent skip.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy)]
struct ScopedConfirmationFacts {
    protected_confirmed: bool,
    skipped_prompt: bool,
}

/// The confirmation facts in the pipeline's vocabulary, so the final frozen-set
/// policy can re-apply exactly what the prompt (or its skip) authorized.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scope_authorization(confirmation: ScopedConfirmationFacts) -> tree::ScopeAuthorization {
    tree::ScopeAuthorization {
        protected_root_confirmed: confirmation.protected_confirmed,
        prompt_skipped: confirmation.skipped_prompt,
    }
}

/// The injected seams for a tree kill, bundled so the entry point stays under
/// the argument-count limit and mirrors [`KillCollectors`].
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct TreeKillSeams<CollectContext, Prompt, CollectPorts> {
    collect_context: CollectContext,
    prompt: Prompt,
    collect_ports: CollectPorts,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_tree_kill(args: &KillArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_tree_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillSeams {
            collect_context: platform::collect_process_context,
            prompt: prompt_tree_confirmation,
            collect_ports: collector::collect_ports,
        },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_tree_kill_with<Ops, CollectContext, Prompt, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntry],
    mode: KillMode,
    ops: &mut Ops,
    mut seams: TreeKillSeams<CollectContext, Prompt, CollectPorts>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // Preview snapshot: informational only. Execution re-enumerates under the
    // freeze and is the authority; this drives the banner and the pre-flight
    // refusals, which have zero side effects.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process tree failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root = match resolve_scoped_kill_root(
        args,
        config,
        entries,
        &snapshot,
        &mut seams.collect_context,
    ) {
        Ok(target) => target,
        Err(reason) => return reason,
    };
    let preview = match tree::plan_process_tree(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_TREE_PROCESSES,
    ) {
        Ok(preview) => preview,
        Err(tree::TreePlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(&preview, "tree") {
        return reason;
    }

    let confirmation = match confirm_tree_kill(&root, &preview, mode, args.yes, &mut seams.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports);
    }

    let fresh_root = match revalidate_tree_root_before_freeze(
        args,
        config,
        &root,
        confirmation,
        &mut seams.collect_context,
        &mut seams.collect_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => return map_tree_outcome(&root, mode, &outcome, &mut seams.collect_ports),
    };

    let outcome = tree::execute_tree_kill(
        &fresh_root,
        mode,
        &config.protected_processes,
        fresh_root.platform,
        scope_authorization(confirmation),
        ops,
    );
    map_tree_outcome(&fresh_root, mode, &outcome, &mut seams.collect_ports)
}

/// Run the confirmation flow. On success, the returned bool records whether
/// the protected-root confirmation was actually completed — the execution-time
/// protection guard needs that fact, because a root can be classified as
/// protected by a fresh scan even when the confirmed port row could not be.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_tree_kill<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<ScopedConfirmationFacts, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    match tree_confirmation(root, preview, mode, yes) {
        TreeConfirmDecision::RefuseProtectedYes => {
            eprintln!(
                "error: {} is protected; --yes cannot bypass protected-process confirmation",
                root.identity(),
            );
            Err(ExitReason::ProtectedNeedsConfirmation)
        }
        TreeConfirmDecision::Skip => {
            print_tree_kill_banner(root, preview, mode);
            Ok(ScopedConfirmationFacts {
                protected_confirmed: false,
                skipped_prompt: true,
            })
        }
        TreeConfirmDecision::PromptWord(word) => {
            print_tree_kill_banner(root, preview, mode);
            prompt_tree_step(root, preview, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: false,
                skipped_prompt: false,
            })
        }
        TreeConfirmDecision::PromptProtectedThenWord(word) => {
            print_tree_kill_banner(root, preview, mode);
            prompt_tree_step(root, preview, TreeConfirmation::ProtectedRoot, prompt)?;
            prompt_tree_step(root, preview, TreeConfirmation::TypedWord(word), prompt)?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: true,
                skipped_prompt: false,
            })
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_tree_step<Prompt>(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
    prompt: &mut Prompt,
) -> Result<(), ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    let confirmed = match prompt(root, preview, requirement) {
        Ok(confirmed) => confirmed,
        Err(error) => {
            eprintln!("error: reading confirmation failed: {error}");
            return Err(ExitReason::Failure);
        }
    };
    if confirmed {
        Ok(())
    } else {
        eprintln!("kill cancelled");
        Err(ExitReason::KillCancelled)
    }
}

/// Resolve the confirmed root for a scoped (tree or group) kill.
///
/// Port targets resolve through the socket table exactly like a single kill;
/// a `--pid` target that owns no visible port falls back to the process-table
/// snapshot, because scoped kills legitimately start from portless
/// supervisors. Refusals are printed here and returned as the exit reason.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_scoped_kill_root<CollectContext>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntry],
    snapshot: &[tree::TreeProcessInfo],
    collect_context: &mut CollectContext,
) -> Result<KillTarget, ExitReason>
where
    CollectContext: FnMut(u32) -> ProcessContext,
{
    match (
        resolve_kill_target(args, entries, collect_context),
        args.pid,
    ) {
        (Ok(target), _) => Ok(target),
        (Err(KillTargetError::NoMatch), Some(pid)) => {
            match resolve_pid_tree_root_from_snapshot(pid, snapshot, &config.protected_processes) {
                Ok(target) => Ok(target),
                Err(KillTargetError::NoMatch) => {
                    eprintln!("error: root PID {pid} is no longer running; nothing to terminate");
                    Err(ExitReason::NoMatch)
                }
                Err(error) => Err(print_target_error(error)),
            }
        }
        (Err(KillTargetError::NoMatch), None) => {
            eprintln!("error: no open port matches the requested target");
            Err(ExitReason::NoMatch)
        }
        (Err(error), _) => Err(print_target_error(error)),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn resolve_pid_tree_root_from_snapshot(
    pid: u32,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, KillTargetError> {
    if let Some(reason) = process::unsafe_pid_reason(pid) {
        return Err(KillTargetError::UnsafePid(reason));
    }
    let Some(info) = snapshot.iter().find(|info| info.pid == pid) else {
        return Err(KillTargetError::NoMatch);
    };
    Ok(kill_target_from_tree_info(info, protected_names))
}

/// The platform a tree target built from the local process table lives on.
/// Snapshot rows come straight from the host OS, so this is a compile-time
/// fact, unlike `PortEntry.platform` which rides along per row.
#[cfg(target_os = "linux")]
const TREE_HOST_PLATFORM: Platform = Platform::Linux;
#[cfg(target_os = "macos")]
const TREE_HOST_PLATFORM: Platform = Platform::Macos;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn kill_target_from_tree_info(
    info: &tree::TreeProcessInfo,
    protected_names: &[String],
) -> KillTarget {
    let protected = info.process_name.as_deref().is_some_and(|name| {
        crate::protection::is_protected_process_name(TREE_HOST_PLATFORM, name, protected_names)
    });
    let system_process = SystemProcessCheck {
        platform: TREE_HOST_PLATFORM,
        pid: Some(info.pid),
        parent_pid: info.parent_pid,
        process_name: info.process_name.as_deref(),
        parent_process_name: None,
    }
    .is_system_process();
    // Honest metadata status: identity fields decide partial-vs-full, and the
    // snapshot's owner UID reaches the target so the ownership warning can
    // fire for a portless supervisor owned by another user. A missing UID is
    // not partial metadata by itself — it only mutes the ownership warning.
    let complete = info.process_name.is_some() && info.start_time_marker.is_some();
    KillTarget {
        pid: info.pid,
        process_name: info.process_name.clone(),
        platform: TREE_HOST_PLATFORM,
        permission: if complete {
            PermissionStatus::Full
        } else {
            PermissionStatus::Partial
        },
        protected,
        system_process,
        ports: Vec::new(),
        owner_uid: info.owner_uid,
        process_start_time_marker: info.start_time_marker,
        child_count: 0,
        children_truncated: false,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_tree_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmation: ScopedConfirmationFacts,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree {
            root_pid: confirmed.pid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        let preview = tree::plan_process_tree(
            root.pid,
            &snapshot,
            &config.protected_processes,
            root.platform,
            tree::MAX_TREE_PROCESSES,
        )
        .map_err(|tree::TreePlanError::RootMissing| tree::TreeKillOutcome::RootAlreadyExited)?;
        tree::preflight_outcome(&preview)?;
        tree::root_protection_outcome(&preview, confirmation.protected_confirmed)?;
        fresh_tree_yes_outcome(&root, &preview, confirmation)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Tree { root_pid: root.pid });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let preview = tree::plan_process_tree(
            root.pid,
            &snapshot,
            &config.protected_processes,
            root.platform,
            tree::MAX_TREE_PROCESSES,
        )
        .map_err(|tree::TreePlanError::RootMissing| tree::TreeKillOutcome::RootAlreadyExited)?;
        tree::preflight_outcome(&preview)?;
        tree::root_protection_outcome(&preview, confirmation.protected_confirmed)?;
        fresh_tree_yes_outcome(&root, &preview, confirmation)?;
        root
    };
    Ok(fresh_root)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_tree_yes_outcome(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    confirmation: ScopedConfirmationFacts,
) -> Result<(), tree::TreeKillOutcome> {
    if confirmation.skipped_prompt && !tree_yes_skip_allowed(root, preview) {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

/// Translate a single-kill revalidation refusal into the scoped-kill outcome
/// vocabulary, so tree and group revalidation report identically.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_outcome_from_termination(
    confirmed: &KillTarget,
    outcome: TerminationOutcome,
) -> tree::TreeKillOutcome {
    match outcome {
        TerminationOutcome::ProtectedProcess => tree::TreeKillOutcome::ProtectedRoot {
            pid: confirmed.pid,
            name: confirmed.process_name.clone(),
        },
        TerminationOutcome::UnsafePid(reason) => tree::TreeKillOutcome::UnsafePid {
            pid: confirmed.pid,
            reason,
        },
        TerminationOutcome::OwnershipUnavailable => {
            tree::TreeKillOutcome::OwnershipUnavailable { pid: confirmed.pid }
        }
        TerminationOutcome::AlreadyExited
        | TerminationOutcome::TargetChanged
        | TerminationOutcome::Success
        | TerminationOutcome::Cancelled => {
            tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid }
        }
        TerminationOutcome::PermissionDenied => {
            tree::TreeKillOutcome::PermissionDenied { pid: confirmed.pid }
        }
        TerminationOutcome::UnknownFailure(error) => tree::TreeKillOutcome::SnapshotFailed(error),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_portless_tree_root(
    confirmed: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    protected_names: &[String],
) -> Result<KillTarget, tree::TreeKillOutcome> {
    let Some(info) = snapshot.iter().find(|info| info.pid == confirmed.pid) else {
        return Err(tree::TreeKillOutcome::RootAlreadyExited);
    };
    let (Some(confirmed_start), Some(fresh_start)) =
        (confirmed.process_start_time_marker, info.start_time_marker)
    else {
        return Err(tree::TreeKillOutcome::PartialMetadata { pid: confirmed.pid });
    };
    if confirmed_start != fresh_start {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    if let Some(expected) = confirmed.process_name.as_deref()
        && info.process_name.as_deref() != Some(expected)
    {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: confirmed.pid });
    }
    let fresh = kill_target_from_tree_info(info, protected_names);
    if fresh.protected && !confirmed.protected {
        return Err(tree::TreeKillOutcome::ProtectedRoot {
            pid: fresh.pid,
            name: fresh.process_name.clone(),
        });
    }
    Ok(fresh)
}

/// Refuse a tree or group that fails a pre-flight rule, before any signal is
/// sent. `scope_noun` is `"tree"` or `"group"` and only changes the wording;
/// the gates and exit codes are identical for both scopes.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scoped_preflight_refusal(
    preview: &tree::ProcessTreeTarget,
    scope_noun: &str,
) -> Option<ExitReason> {
    tree::preflight_outcome(preview).err().map(|outcome| match outcome {
        tree::TreeKillOutcome::Truncated { limit } => {
            eprintln!(
                "error: process {scope_noun} exceeds the {limit} process cap; refusing to kill a partial {scope_noun}",
            );
            ExitReason::Failure
        }
        tree::TreeKillOutcome::UnsafePid { pid, .. } => {
            eprintln!("error: process {scope_noun} contains unsafe PID {pid}; refusing {scope_noun} kill");
            ExitReason::Failure
        }
        tree::TreeKillOutcome::ProtectedDescendant { pid, name } => {
            let name = sanitize(name.as_deref().unwrap_or("<unknown>"));
            eprintln!("error: process {scope_noun} contains protected process PID {pid} ({name}); refusing {scope_noun} kill");
            ExitReason::ProtectedNeedsConfirmation
        }
        // preflight_outcome only produces the gates above today; if it ever
        // grows one, refuse loudly rather than exiting without a word.
        other => {
            eprintln!("error: process {scope_noun} pre-flight refused the kill: {other:?}");
            ExitReason::Failure
        }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    // Protected if *either* reader says so: the port-row policy (which needs a
    // readable row name) or the tree scan's root classification. The two can
    // disagree on partial-metadata rows, and protection must win either way.
    if root.protected || preview.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::tree_scope_word(mode));
    }

    // Terminate asks for "tree"; force asks for "force" — the more dangerous
    // action wants the more deliberate word.
    let word = tree::tree_scope_word(mode);
    if yes && tree_yes_skip_allowed(root, preview) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_yes_skip_allowed(root: &KillTarget, preview: &tree::ProcessTreeTarget) -> bool {
    !preview.has_warnings() && !root_has_tree_yes_blocking_warning(root)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn root_has_tree_yes_blocking_warning(root: &KillTarget) -> bool {
    // The child-count notice is informational under tree scope (the tree
    // preview supersedes it); every other warning kind blocks a `--yes` skip.
    root.warnings()
        .iter()
        .any(|warning| !matches!(warning, process::KillWarning::HasChildren { .. }))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_tree_kill_banner(root: &KillTarget, preview: &tree::ProcessTreeTarget, mode: KillMode) {
    eprintln!(
        "{} process tree from {}",
        mode.action_label(),
        root.identity()
    );
    eprintln!("Scope: tree ({} processes)", preview.len());
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --tree", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    for node in preview.preview_nodes(TREE_PREVIEW_MAX) {
        let indent = "  ".repeat(node.depth + 1);
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        eprintln!("{indent}PID {} ({name})", node.pid);
    }
    if preview.len() > TREE_PREVIEW_MAX {
        eprintln!("  ... and {} more", preview.len() - TREE_PREVIEW_MAX);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if preview.has_system_process() {
        eprintln!(
            "Warning: tree includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(preview, "tree") {
        eprintln!("Warning: {warning}.");
    }
    for warning in root.warning_lines() {
        eprintln!(
            "Warning: {}.",
            sanitize(&process::tree_scope_warning_text(&warning))
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_tree_confirmation(
    root: &KillTarget,
    preview: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes, or press Enter to cancel: ",
            preview.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn tree_confirmation_matches(
    input: &str,
    root: &KillTarget,
    requirement: TreeConfirmation,
) -> bool {
    match requirement {
        TreeConfirmation::TypedWord(word) => tree::word_confirmation_matches(input, word),
        TreeConfirmation::ProtectedRoot => process::confirmation_input_matches(
            input,
            root,
            ConfirmationRequirement::ProtectedProcess,
        ),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_tree_outcome<CollectPorts>(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let scope_of_target = format!("the tree rooted at {}", root.identity());
    map_scoped_outcome(root, mode, outcome, "tree", &scope_of_target, collect_ports)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_group_outcome<CollectPorts>(
    root: &KillTarget,
    pgid: u32,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let scope_of_target = format!("process group {pgid} of {}", root.identity());
    map_scoped_outcome(
        root,
        mode,
        outcome,
        "group",
        &scope_of_target,
        collect_ports,
    )
}

/// Shared success/partial-success wording for tree and group delivery reports.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scoped_delivery_summary(
    delivery: &str,
    scope_noun: &str,
    scope_of_target: &str,
    report: &tree::TreeKillReport,
) -> String {
    if report.denied.is_empty() && report.already_exited == 0 {
        return format!(
            "sent {delivery} to {} process(es) in {scope_of_target}",
            report.delivered,
        );
    }

    let exited_suffix = if report.already_exited == 0 {
        String::new()
    } else {
        format!(
            "; {} already exited before final delivery",
            report.already_exited
        )
    };
    let denied_suffix = if report.denied.is_empty() {
        String::new()
    } else {
        format!(
            "; permission denied for PID(s): {}",
            tree::format_pid_list(&report.denied)
        )
    };
    format!(
        "sent {delivery} to {} of {} {scope_noun} process(es){exited_suffix}{denied_suffix}",
        report.delivered, report.total,
    )
}

/// Print the outcome of a scoped (tree or group) kill and map it to the exit
/// contract. One function for both scopes so a refusal can never exit with
/// different codes depending on how the same processes were targeted;
/// `scope_noun` and `scope_of_target` only shape the wording.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn map_scoped_outcome<CollectPorts>(
    root: &KillTarget,
    mode: KillMode,
    outcome: &tree::TreeKillOutcome,
    scope_noun: &str,
    scope_of_target: &str,
    collect_ports: &mut CollectPorts,
) -> ExitReason
where
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    use crate::tree::TreeKillOutcome;

    let delivery = mode.delivery_label(root.platform);
    match outcome {
        TreeKillOutcome::Completed(report) if report.denied.is_empty() => {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            print_post_kill_refresh_status(root, collect_ports);
            ExitReason::Success
        }
        TreeKillOutcome::Completed(report) => {
            eprintln!(
                "{}",
                scoped_delivery_summary(delivery, scope_noun, scope_of_target, report)
            );
            ExitReason::PermissionDenied
        }
        TreeKillOutcome::RootAlreadyExited => {
            eprintln!(
                "{} already exited before termination was sent",
                root.identity(),
            );
            print_post_kill_refresh_status(root, collect_ports);
            ExitReason::NoMatch
        }
        TreeKillOutcome::PermissionDenied { pid } => {
            eprintln!(
                "error: permission denied for PID {pid}; any frozen process was thawed and no termination was sent; {}",
                process::permission_denied_hint(root.platform),
            );
            ExitReason::PermissionDenied
        }
        TreeKillOutcome::TargetChanged { pid } => {
            eprintln!(
                "error: process {scope_noun} identity changed at PID {pid}; any frozen process was thawed and no termination was sent",
            );
            ExitReason::Failure
        }
        TreeKillOutcome::Truncated { limit } => {
            eprintln!(
                "error: the process {scope_noun} exceeded {limit} processes; any frozen process was thawed and no termination was sent",
            );
            ExitReason::Failure
        }
        TreeKillOutcome::SweepPassLimit { limit } => {
            eprintln!(
                "error: the process {scope_noun} did not converge after {limit} freeze passes; it was thawed and no termination was sent",
            );
            ExitReason::Failure
        }
        TreeKillOutcome::UnsafePid { pid, reason } => {
            eprintln!(
                "error: unsafe PID {pid} in {scope_noun}: {}; any frozen process was thawed and no termination was sent",
                reason.message(),
            );
            ExitReason::Failure
        }
        TreeKillOutcome::ProtectedDescendant { pid, name } => {
            let name = sanitize(name.as_deref().unwrap_or("<unknown>"));
            eprintln!(
                "error: protected process PID {pid} ({name}) in {scope_noun}; any frozen process was thawed and no termination was sent",
            );
            ExitReason::ProtectedNeedsConfirmation
        }
        TreeKillOutcome::ProtectedRoot { pid, name } => {
            let name = sanitize(name.as_deref().unwrap_or("<unknown>"));
            eprintln!(
                "error: root PID {pid} ({name}) is protected and requires PID/name confirmation; any frozen process was thawed and no termination was sent",
            );
            ExitReason::ProtectedNeedsConfirmation
        }
        TreeKillOutcome::FreshConfirmationRequired => {
            eprintln!(
                "error: process {scope_noun} changed after --yes; rerun without --yes to review fresh warnings; any frozen process was thawed and no termination was sent",
            );
            ExitReason::Failure
        }
        TreeKillOutcome::OwnershipUnavailable { pid } => {
            eprintln!(
                "error: ownership for PID {pid} became unavailable before {delivery}; any frozen process was thawed and no termination was sent",
            );
            ExitReason::PermissionDenied
        }
        TreeKillOutcome::PartialMetadata { pid } => {
            eprintln!(
                "error: process metadata for PID {pid} was incomplete during {scope_noun} verification; any frozen process was thawed and no termination was sent",
            );
            ExitReason::Failure
        }
        TreeKillOutcome::SnapshotFailed(error) => {
            eprintln!(
                "error: enumerating the process {scope_noun} during termination failed: {}; no termination was sent",
                sanitize(error),
            );
            ExitReason::Failure
        }
    }
}

// The group `--yes` skip ceiling lives in `tree.rs` because the final
// frozen-set policy re-applies it after the sweep; the confirmation gate here
// and that policy must share one number.
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::tree::GROUP_YES_SKIP_MAX_PROCESSES;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_group_kill(args: &KillArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    let mode = if args.force {
        KillMode::Force
    } else {
        KillMode::Terminate
    };
    #[cfg(target_os = "linux")]
    let mut ops = crate::platform::linux::LinuxTreeOps::new();
    #[cfg(target_os = "macos")]
    let mut ops = crate::platform::macos::MacosTreeOps::new();
    run_group_kill_with(
        args,
        config,
        entries,
        mode,
        &mut ops,
        TreeKillSeams {
            collect_context: platform::collect_process_context,
            prompt: prompt_group_confirmation,
            collect_ports: collector::collect_ports,
        },
    )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_group_kill_with<Ops, CollectContext, Prompt, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    entries: &[PortEntry],
    mode: KillMode,
    ops: &mut Ops,
    mut seams: TreeKillSeams<CollectContext, Prompt, CollectPorts>,
) -> ExitReason
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    // Preview snapshot: informational only, exactly like tree scope. Execution
    // re-enumerates under the freeze and is the authority.
    let snapshot = match ops.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => {
            eprintln!(
                "error: enumerating the process group failed: {}",
                sanitize(&error)
            );
            return ExitReason::Failure;
        }
    };

    let root = match resolve_scoped_kill_root(
        args,
        config,
        entries,
        &snapshot,
        &mut seams.collect_context,
    ) {
        Ok(target) => target,
        Err(reason) => return reason,
    };
    let group = match tree::plan_process_group(
        root.pid,
        &snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    ) {
        Ok(group) => group,
        Err(tree::GroupPlanError::RootMissing) => {
            eprintln!(
                "error: root PID {} is no longer running; nothing to terminate",
                root.pid
            );
            return ExitReason::NoMatch;
        }
        Err(tree::GroupPlanError::GroupUnavailable) => {
            eprintln!(
                "error: PID {} has no targetable process group; refusing group kill",
                root.pid
            );
            return ExitReason::Failure;
        }
    };

    if let Some(reason) = scoped_preflight_refusal(group.members(), "group") {
        return reason;
    }

    let confirmation = match confirm_group_kill(&root, &group, mode, args.yes, &mut seams.prompt) {
        Ok(confirmation) => confirmation,
        Err(reason) => return reason,
    };

    if let Err(outcome) = tree::pin_root_before_revalidation(root.pid, ops) {
        return map_group_outcome(
            &root,
            group.pgid(),
            mode,
            &outcome,
            &mut seams.collect_ports,
        );
    }

    let fresh_root = match revalidate_group_root_before_freeze(
        args,
        config,
        &root,
        ConfirmedGroupFacts {
            pgid: group.pgid(),
            confirmation,
        },
        &mut seams.collect_context,
        &mut seams.collect_ports,
        ops,
    ) {
        Ok(root) => root,
        Err(outcome) => {
            return map_group_outcome(
                &root,
                group.pgid(),
                mode,
                &outcome,
                &mut seams.collect_ports,
            );
        }
    };

    let outcome = tree::execute_group_kill(
        &fresh_root,
        group.pgid(),
        mode,
        &config.protected_processes,
        fresh_root.platform,
        scope_authorization(confirmation),
        ops,
    );
    map_group_outcome(
        &fresh_root,
        group.pgid(),
        mode,
        &outcome,
        &mut seams.collect_ports,
    )
}

/// Run the group confirmation flow; mirrors [`confirm_tree_kill`], including
/// the returned protected-root fact.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn confirm_group_kill<Prompt>(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
    prompt: &mut Prompt,
) -> Result<ScopedConfirmationFacts, ExitReason>
where
    Prompt: FnMut(&KillTarget, &tree::ProcessTreeTarget, TreeConfirmation) -> std::io::Result<bool>,
{
    match group_confirmation(root, group, mode, yes) {
        TreeConfirmDecision::RefuseProtectedYes => {
            eprintln!(
                "error: {} is protected; --yes cannot bypass protected-process confirmation",
                root.identity(),
            );
            Err(ExitReason::ProtectedNeedsConfirmation)
        }
        TreeConfirmDecision::Skip => {
            print_group_kill_banner(root, group, mode);
            Ok(ScopedConfirmationFacts {
                protected_confirmed: false,
                skipped_prompt: true,
            })
        }
        TreeConfirmDecision::PromptWord(word) => {
            print_group_kill_banner(root, group, mode);
            prompt_tree_step(
                root,
                group.members(),
                TreeConfirmation::TypedWord(word),
                prompt,
            )?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: false,
                skipped_prompt: false,
            })
        }
        TreeConfirmDecision::PromptProtectedThenWord(word) => {
            print_group_kill_banner(root, group, mode);
            prompt_tree_step(
                root,
                group.members(),
                TreeConfirmation::ProtectedRoot,
                prompt,
            )?;
            prompt_tree_step(
                root,
                group.members(),
                TreeConfirmation::TypedWord(word),
                prompt,
            )?;
            Ok(ScopedConfirmationFacts {
                protected_confirmed: true,
                skipped_prompt: false,
            })
        }
    }
}

/// The confirmation gate for a group kill.
///
/// Stricter than tree scope on `--yes`: a process group has no structural tie
/// to the confirmed target, so beyond the tree rules (no warnings anywhere,
/// no protected root) the group must also be tiny before the typed word may
/// be skipped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_confirmation(
    root: &KillTarget,
    group: &tree::ProcessGroupTarget,
    mode: KillMode,
    yes: bool,
) -> TreeConfirmDecision {
    let members = group.members();
    // Protected if *either* reader says so, exactly like tree scope.
    if root.protected || members.root().is_some_and(|node| node.protected) {
        if yes {
            return TreeConfirmDecision::RefuseProtectedYes;
        }
        return TreeConfirmDecision::PromptProtectedThenWord(tree::group_scope_word(mode));
    }

    let word = tree::group_scope_word(mode);
    if yes && group_yes_skip_allowed(root, members) {
        return TreeConfirmDecision::Skip;
    }
    TreeConfirmDecision::PromptWord(word)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn group_yes_skip_allowed(root: &KillTarget, members: &tree::ProcessTreeTarget) -> bool {
    members.len() <= GROUP_YES_SKIP_MAX_PROCESSES
        && !members.has_warnings()
        && !root_has_tree_yes_blocking_warning(root)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn print_group_kill_banner(root: &KillTarget, group: &tree::ProcessGroupTarget, mode: KillMode) {
    let members = group.members();
    eprintln!(
        "{} process group {} of {}",
        mode.action_label(),
        group.pgid(),
        root.identity()
    );
    eprintln!(
        "Scope: group {} ({} processes)",
        group.pgid(),
        members.len()
    );
    eprintln!("Ports: {}", sanitize(&root.ports_text()));
    let mut command = format!("kick kill --pid {} --group", root.pid);
    if mode == KillMode::Force {
        command.push_str(" --force");
    }
    eprintln!("Command: {}", sanitize(&command));
    // Every member, uncapped here (the builder already bounds the set): a process
    // group can contain unrelated commands launched from the same shell, so
    // the confirmation must show the entire blast radius.
    for node in members.preview_nodes(members.len()) {
        let name = sanitize(node.process_name.as_deref().unwrap_or("<unknown>"));
        let root_marker = if node.depth == 0 {
            " [confirmed target]"
        } else {
            ""
        };
        eprintln!("  PID {} ({name}){root_marker}", node.pid);
    }
    if let Some(warning) = mode.force_warning(root.platform) {
        eprintln!("Warning: {}", sanitize(warning));
    }
    if members.has_system_process() {
        eprintln!(
            "Warning: group includes system/service processes; verify this is safe to terminate."
        );
    }
    if let Some(warning) = scoped_owner_warning(members, "group") {
        eprintln!("Warning: {warning}.");
    }
    eprintln!(
        "Warning: a process group can include unrelated processes started from the same shell; review every member above."
    );
    for warning in root.warning_lines() {
        eprintln!(
            "Warning: {}.",
            sanitize(&process::group_scope_warning_text(&warning))
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn scoped_owner_warning(preview: &tree::ProcessTreeTarget, scope_noun: &str) -> Option<String> {
    let current_uid = process::current_user_id();
    let mut count = 0_usize;
    let mut first = None;
    for node in preview.preview_nodes(preview.len()) {
        let Some(owner_uid) = node.owner_uid else {
            continue;
        };
        if owner_uid == current_uid {
            continue;
        }
        count += 1;
        first.get_or_insert((node.pid, owner_uid));
    }

    let (pid, owner_uid) = first?;
    Some(format!(
        "{scope_noun} includes {count} process(es) owned by another uid; first is PID {pid} owned by uid {owner_uid}, current effective uid is {current_uid}"
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prompt_group_confirmation(
    root: &KillTarget,
    members: &tree::ProcessTreeTarget,
    requirement: TreeConfirmation,
) -> std::io::Result<bool> {
    match requirement {
        TreeConfirmation::TypedWord(word) => eprint!(
            "Type {word} to terminate all {} processes in the group, or press Enter to cancel: ",
            members.len(),
        ),
        TreeConfirmation::ProtectedRoot => eprint!(
            "Protected root: type PID {} or process name {} to confirm: ",
            root.pid,
            sanitize(root.process_name_or_unknown()),
        ),
    }
    std::io::stderr().flush()?;

    let answer = read_confirmation_line(CONFIRMATION_INPUT_MAX_BYTES)?;
    Ok(tree_confirmation_matches(&answer, root, requirement))
}

/// The two facts the group confirmation established, carried together into
/// revalidation: which group the user actually saw, and whether the
/// protected-root confirmation was completed.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy)]
struct ConfirmedGroupFacts {
    pgid: u32,
    confirmation: ScopedConfirmationFacts,
}

/// Revalidate the confirmed root and re-run every group gate against a fresh
/// scan, immediately before the freeze. The root must match exactly and must
/// still sit in the group the user confirmed; membership may have churned but
/// must re-pass the cap, unsafe-PID, and protection gates.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn revalidate_group_root_before_freeze<Ops, CollectContext, CollectPorts>(
    args: &KillArgs,
    config: &Config,
    confirmed: &KillTarget,
    confirmed_group: ConfirmedGroupFacts,
    collect_context: &mut CollectContext,
    collect_ports: &mut CollectPorts,
    ops: &mut Ops,
) -> Result<KillTarget, tree::TreeKillOutcome>
where
    Ops: tree::TreeProcessOps,
    CollectContext: FnMut(u32) -> ProcessContext,
    CollectPorts: FnMut() -> Result<Vec<PortEntry>, collector::CollectorError>,
{
    let fresh_root = if confirmed.ports.is_empty() {
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: confirmed.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        let root =
            revalidate_portless_tree_root(confirmed, &snapshot, &config.protected_processes)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    } else {
        let root = revalidate_cli_target(args, config, confirmed, collect_context, collect_ports)
            .map_err(|outcome| tree_outcome_from_termination(confirmed, outcome))?;
        ops.set_snapshot_scope(tree::TreeSnapshotScope::Group {
            root_pid: root.pid,
            pgid: confirmed_group.pgid,
        });
        let snapshot = ops
            .snapshot()
            .map_err(tree::TreeKillOutcome::SnapshotFailed)?;
        fresh_group_gates(&root, &snapshot, config, confirmed_group)?;
        root
    };
    Ok(fresh_root)
}

/// The fresh-scan gates for a group kill: the member set must still build, the root
/// must still sit in the confirmed group (otherwise the sweep would target a
/// member set the user never saw), and the pre-flight and root-protection
/// rules must re-pass.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fresh_group_gates(
    root: &KillTarget,
    snapshot: &[tree::TreeProcessInfo],
    config: &Config,
    confirmed_group: ConfirmedGroupFacts,
) -> Result<(), tree::TreeKillOutcome> {
    let group = tree::plan_process_group(
        root.pid,
        snapshot,
        &config.protected_processes,
        root.platform,
        tree::MAX_GROUP_PROCESSES,
    )
    .map_err(|error| match error {
        tree::GroupPlanError::RootMissing => tree::TreeKillOutcome::RootAlreadyExited,
        tree::GroupPlanError::GroupUnavailable => {
            tree::TreeKillOutcome::TargetChanged { pid: root.pid }
        }
    })?;
    if group.pgid() != confirmed_group.pgid {
        return Err(tree::TreeKillOutcome::TargetChanged { pid: root.pid });
    }
    tree::preflight_outcome(group.members())?;
    tree::root_protection_outcome(
        group.members(),
        confirmed_group.confirmation.protected_confirmed,
    )?;
    if confirmed_group.confirmation.skipped_prompt && !group_yes_skip_allowed(root, group.members())
    {
        return Err(tree::TreeKillOutcome::FreshConfirmationRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::cell::RefCell;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::rc::Rc;

    use super::{
        Cli, Command, ExitReason, KillArgs, KillCollectors, KillTargetError,
        POST_KILL_SETTLE_ATTEMPTS_MAX, PostKillPortsStatus,
        diagnostic_port_without_confirmed_socket, resolve_kill_target, run_kill_with,
        truncate_to_char_boundary, wait_for_confirmed_ports_to_clear,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use super::{
        GROUP_YES_SKIP_MAX_PROCESSES, TreeConfirmDecision, TreeKillSeams, group_confirmation,
        kill_target_from_tree_info, run_group_kill_with, run_tree_kill_with, tree_confirmation,
    };
    use crate::collector::CollectorError;
    use crate::config::Config;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::model::{ChildProcess, ChildProcessSnapshot};
    use crate::model::{
        PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState, SortMode,
    };
    use crate::process::{
        ConfirmationRequirement, KillMode, KillTarget, TerminationOutcome, UnsafePidReason,
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::tree::{ProcessTreeTarget, TreeProcessInfo, TreeProcessOps, TreeSignalResult};

    fn entry(port: u16) -> PortEntry {
        entry_with_pid(port, Some(18_422), Protocol::Tcp, "node")
    }

    fn entry_with_pid(port: u16, pid: Option<u32>, protocol: Protocol, name: &str) -> PortEntry {
        PortEntry {
            protocol,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: match protocol {
                Protocol::Tcp => SocketState::Listen,
                Protocol::Udp => SocketState::Bound,
            },
            pid,
            process_name: Some(name.to_owned()),
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

    fn kill_pid(pid: u32, force: bool, yes: bool) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force,
            yes,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
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
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            tree: false,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            group: false,
        }
    }

    fn no_context(_: u32) -> ProcessContext {
        ProcessContext {
            process_start_time_marker: Some(55),
            ..ProcessContext::default()
        }
    }

    #[test]
    fn exit_codes_match_the_documented_contract() {
        // These numbers are the script-facing API: if this test breaks, you've
        // made a breaking change, not done a refactor.
        assert_eq!(ExitReason::Success as u8, 0);
        assert_eq!(ExitReason::Failure as u8, 1);
        assert_eq!(ExitReason::InvalidArguments as u8, 2);
        assert_eq!(ExitReason::NoMatch as u8, 3);
        assert_eq!(ExitReason::PermissionDenied as u8, 4);
        assert_eq!(ExitReason::KillCancelled as u8, 5);
        assert_eq!(ExitReason::ProtectedNeedsConfirmation as u8, 6);
    }

    #[test]
    fn bare_invocation_has_no_command_and_opens_the_tui() {
        let cli = Cli::try_parse_from(["kickoutchi"]).expect("bare invocation parses");
        assert!(cli.command.is_none());
    }

    #[test]
    fn list_flags_parse() {
        let cli = Cli::try_parse_from([
            "kickoutchi",
            "list",
            "--port",
            "3000",
            "--process",
            "node",
            "--filter",
            "scope:public",
            "--sort",
            "scope",
            "--json",
        ])
        .expect("valid list invocation");
        let Some(Command::List(args)) = cli.command else {
            panic!("expected a list command");
        };
        assert_eq!(args.port, Some(3000));
        assert_eq!(args.process.as_deref(), Some("node"));
        assert_eq!(args.filter.as_deref(), Some("scope:public"));
        assert_eq!(args.sort, Some(SortMode::Scope));
        assert!(args.json);
    }

    #[test]
    fn list_sort_rejects_unknown_modes_at_parse_time() {
        assert!(Cli::try_parse_from(["kickoutchi", "list", "--sort", "alphabetical"]).is_err());
    }

    #[test]
    fn kill_requires_exactly_one_target() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "1", "--port", "80"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422"]).is_ok());
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--port", "3000", "--force"]).is_ok());
    }

    /// Windows builds have no `tree` field on `KillArgs`, so clap must reject
    /// the flag as an unknown argument (a usage error, exit 2) — the honest
    /// per-platform surface instead of a runtime "unsupported" branch.
    #[cfg(windows)]
    #[test]
    fn tree_flag_is_rejected_at_parse_time_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--tree"]).is_err());
    }

    /// Windows builds have no `Inspect` variant on `Command`, so clap must
    /// reject the subcommand as unknown (a usage error, exit 2), keeping
    /// `--help` honest per platform — the same contract as `--tree` above.
    #[cfg(windows)]
    #[test]
    fn inspect_subcommand_is_rejected_at_parse_time_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "18422"]).is_err());
    }

    /// Same per-platform contract for `--group`: no field on Windows builds,
    /// so the flag is a parse-time usage error there.
    #[cfg(windows)]
    #[test]
    fn group_flag_is_rejected_at_parse_time_on_windows() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--group"]).is_err());
    }

    /// `--tree` and `--group` are two different blast radii; asking for both
    /// is a contradiction clap must reject before any process is looked at.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_flag_parses_and_conflicts_with_tree() {
        assert!(Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--group"]).is_ok());
        assert!(
            Cli::try_parse_from(["kickoutchi", "kill", "--port", "3000", "--group", "--force"])
                .is_ok()
        );
        assert!(
            Cli::try_parse_from(["kickoutchi", "kill", "--pid", "18422", "--tree", "--group",])
                .is_err()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn inspect_requires_exactly_one_target() {
        assert!(Cli::try_parse_from(["kickoutchi", "inspect"]).is_err());
        assert!(
            Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "1", "--port", "80"]).is_err()
        );
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--pid", "18422"]).is_ok());
        assert!(Cli::try_parse_from(["kickoutchi", "inspect", "--port", "3000"]).is_ok());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn inspect_resolution_mirrors_kill_port_rules_but_allows_any_pid() {
        use super::{InspectArgs, resolve_inspect_target};

        let by_pid = |pid| InspectArgs {
            pid: Some(pid),
            port: None,
        };
        let by_port = |port| InspectArgs {
            pid: None,
            port: Some(port),
        };

        // Reading PID 1's family is legitimate — no unsafe-PID guard here.
        assert_eq!(resolve_inspect_target(&by_pid(1), &[]), Ok(1));

        let rows = vec![entry(3000)];
        assert_eq!(resolve_inspect_target(&by_port(3000), &rows), Ok(18_422));
        assert_eq!(
            resolve_inspect_target(&by_port(4000), &rows),
            Err(KillTargetError::NoMatch),
        );

        let hidden = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];
        assert_eq!(
            resolve_inspect_target(&by_port(3000), &hidden),
            Err(KillTargetError::MissingPid { port: 3000 }),
        );

        let shared = vec![
            entry_with_pid(3000, Some(100), Protocol::Tcp, "node"),
            entry_with_pid(3000, Some(200), Protocol::Udp, "worker"),
        ];
        assert!(matches!(
            resolve_inspect_target(&by_port(3000), &shared),
            Err(KillTargetError::AmbiguousPort { port: 3000, .. }),
        ));
    }

    #[test]
    fn global_flags_parse_with_and_without_subcommands() {
        let cli = Cli::try_parse_from(["kickoutchi", "--refresh-interval", "9"])
            .expect("global flag without subcommand");
        assert_eq!(cli.refresh_interval, Some(9));

        let cli = Cli::try_parse_from(["kickoutchi", "list", "--config", "/tmp/alt.toml"])
            .expect("global flag after subcommand");
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/tmp/alt.toml"))
        );
    }

    #[test]
    fn out_of_range_refresh_interval_is_a_usage_error() {
        // clap is the one that hands out exit code 2; this pins that the bound is
        // caught at parse time instead of leaking into config validation.
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "0"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "3601"]).is_err());
    }

    #[test]
    fn no_match_diagnostic_requires_absent_confirmed_socket() {
        assert_eq!(
            diagnostic_port_without_confirmed_socket(Some(3000), &[]),
            Some(3000)
        );
        assert_eq!(
            diagnostic_port_without_confirmed_socket(Some(3000), &[entry(3000)]),
            None
        );
        assert_eq!(diagnostic_port_without_confirmed_socket(None, &[]), None);
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
    fn confirmation_input_truncation_preserves_utf8_boundaries() {
        let mut input = "foé".to_owned();

        truncate_to_char_boundary(&mut input, 3);

        assert_eq!(input, "fo");
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

    /// Tree ops that allow the preview read but fail the test if the pipeline is
    /// ever reached: used to prove refusals happen before any process is touched.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct PreviewOnlyTreeOps(Vec<TreeProcessInfo>);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl TreeProcessOps for PreviewOnlyTreeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            Ok(self.0.clone())
        }

        fn stop(&mut self, _pid: u32) -> TreeSignalResult {
            panic!("no process may be stopped for an unresolved root")
        }

        fn cont(&mut self, _pid: u32) {
            panic!("no process may be continued for an unresolved root")
        }

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<u64>,
        ) -> TreeSignalResult {
            panic!("no pidfd may be opened for an unresolved root")
        }

        fn deliver(&mut self, _pid: u32, _mode: KillMode) -> TreeSignalResult {
            panic!("no signal may be sent for an unresolved root")
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordingTreeEvent {
        Pin(u32),
        CollectPorts,
        Stop(u32),
        Deliver(u32),
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct RecordingTreeOps {
        snapshots: Vec<Vec<TreeProcessInfo>>,
        next: usize,
        stops: Vec<u32>,
        events: Rc<RefCell<Vec<RecordingTreeEvent>>>,
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl RecordingTreeOps {
        fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
            Self {
                snapshots,
                next: 0,
                stops: Vec::new(),
                events: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl TreeProcessOps for RecordingTreeOps {
        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            let index = self.next.min(self.snapshots.len().saturating_sub(1));
            self.next += 1;
            Ok(self.snapshots.get(index).cloned().unwrap_or_default())
        }

        fn pin_root_for_revalidation(&mut self, pid: u32) -> TreeSignalResult {
            self.events.borrow_mut().push(RecordingTreeEvent::Pin(pid));
            TreeSignalResult::Delivered
        }

        fn stop(&mut self, pid: u32) -> TreeSignalResult {
            self.stops.push(pid);
            self.events.borrow_mut().push(RecordingTreeEvent::Stop(pid));
            TreeSignalResult::Delivered
        }

        fn cont(&mut self, _pid: u32) {}

        fn prepare_delivery(
            &mut self,
            _pid: u32,
            _verified_start_marker: Option<u64>,
        ) -> TreeSignalResult {
            TreeSignalResult::Delivered
        }

        fn deliver(&mut self, pid: u32, _mode: KillMode) -> TreeSignalResult {
            self.events
                .borrow_mut()
                .push(RecordingTreeEvent::Deliver(pid));
            TreeSignalResult::Delivered
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_tree(pid: u32) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes: false,
            tree: true,
            group: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_tree_yes(pid: u32) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes: true,
            tree: true,
            group: false,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_kill_of_missing_pid_reports_no_match_without_touching_processes() {
        // The PID owns no visible port and is absent from the tree snapshot, so
        // tree kill refuses before freeze, prompt, or signal delivery.
        let reason = run_tree_kill_with(
            &kill_pid_tree(4_242),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(Vec::new()),
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                    panic!("unresolved root must not prompt")
                },
                collect_ports: || panic!("unresolved root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::NoMatch);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info(pid: u32, parent_pid: Option<u32>, name: &str) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid,
            process_name: Some(name.to_owned()),
            start_time_marker: Some(u64::from(pid)),
            owner_uid: None,
            process_group: None,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info_without_start_marker(
        pid: u32,
        parent_pid: Option<u32>,
        name: &str,
    ) -> TreeProcessInfo {
        TreeProcessInfo {
            start_time_marker: None,
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_info_owned_by_other_uid(
        pid: u32,
        parent_pid: Option<u32>,
        name: &str,
    ) -> TreeProcessInfo {
        TreeProcessInfo {
            owner_uid: Some(crate::process::current_user_id().saturating_add(1)),
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn tree_target(infos: &[TreeProcessInfo], protected_names: &[String]) -> ProcessTreeTarget {
        crate::tree::plan_process_tree(100, infos, protected_names, Platform::Linux, 256)
            .expect("test tree root must be present")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn confirm_tree_prompt(
        _target: &KillTarget,
        _tree: &ProcessTreeTarget,
        _requirement: super::TreeConfirmation,
    ) -> std::io::Result<bool> {
        std::io::sink().write_all(&[])?;
        Ok(true)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn panic_tree_prompt(
        _target: &KillTarget,
        _tree: &ProcessTreeTarget,
        _requirement: super::TreeConfirmation,
    ) -> std::io::Result<bool> {
        panic!("tree prompt must not be reached")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_gates_yes_and_protected_roots() {
        // This is the --yes safety table: --yes may only skip the prompt on a
        // tree with nothing to warn about, and can never authorize a protected
        // root.
        let clean = tree_target(&[tree_info(100, Some(500), "node")], &[]);
        let clean_root = kill_target_from_tree_info(&tree_info(100, Some(500), "node"), &[]);
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Terminate, true),
            TreeConfirmDecision::Skip,
        );
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Terminate, false),
            TreeConfirmDecision::PromptWord("tree"),
        );
        assert_eq!(
            tree_confirmation(&clean_root, &clean, KillMode::Force, false),
            TreeConfirmDecision::PromptWord("force"),
        );

        // A system/service member is a warning, so --yes downgrades to the
        // typed prompt instead of skipping it.
        let with_system = tree_target(
            &[
                tree_info(100, Some(500), "node"),
                tree_info(101, Some(100), "systemd"),
            ],
            &[],
        );
        assert_eq!(
            tree_confirmation(&clean_root, &with_system, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("tree"),
        );

        // A member owned by another uid is also a warning, so --yes downgrades
        // to the typed prompt instead of skipping it.
        let with_other_uid = tree_target(
            &[
                tree_info(100, Some(500), "node"),
                tree_info_owned_by_other_uid(101, Some(100), "worker"),
            ],
            &[],
        );
        assert_eq!(
            tree_confirmation(&clean_root, &with_other_uid, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("tree"),
        );

        // A protected root keeps the protected typed confirmation, and --yes
        // refuses outright rather than silently skipping it.
        let protected_root = tree_target(
            &[tree_info(100, Some(500), "postgres")],
            &["postgres".to_owned()],
        );
        let protected_root_target = kill_target_from_tree_info(
            &tree_info(100, Some(500), "postgres"),
            &["postgres".to_owned()],
        );
        assert_eq!(
            tree_confirmation(
                &protected_root_target,
                &protected_root,
                KillMode::Terminate,
                true
            ),
            TreeConfirmDecision::RefuseProtectedYes,
        );
        assert_eq!(
            tree_confirmation(
                &protected_root_target,
                &protected_root,
                KillMode::Terminate,
                false
            ),
            TreeConfirmDecision::PromptProtectedThenWord("tree"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_banner_child_warning_uses_tree_scope() {
        // Feed the rewrite the *real* warning_lines() output, not a copied
        // literal: if the single-kill wording in process.rs ever drifts, the
        // suffix rewrite silently stops matching, and only a test wired to the
        // genuine source can catch that.
        let row = entry(3000);
        let context = ProcessContext {
            children: ChildProcessSnapshot {
                children: vec![
                    ChildProcess {
                        pid: 18_430,
                        process_name: None,
                    },
                    ChildProcess {
                        pid: 18_431,
                        process_name: None,
                    },
                ],
                truncated: false,
            },
            ..ProcessContext::default()
        };
        let target = KillTarget::from_entries(18_422, [&row], Some(&context));
        let warning = target
            .warning_lines()
            .into_iter()
            .find(|line| line.starts_with("target has"))
            .expect("a target with children must warn about them");

        assert_eq!(
            crate::process::tree_scope_warning_text(&warning),
            "target has 2 direct child process(es); tree kill targets the bounded descendant tree shown above",
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_root_is_pinned_before_revalidation_and_no_stop_on_drift() {
        let rows = vec![entry(3000)];
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(4000, Some(18_422), Protocol::Tcp, "node")];

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
            "the Linux root handle must be prepared before final revalidation",
        );
        assert!(ops.stops.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn portless_tree_root_missing_start_marker_refuses_before_any_stop() {
        // Real Linux/macOS tree snapshots fail closed before producing this row,
        // but the shared CLI seam still has to enforce the identity contract:
        // a portless PID root without a start marker is not safe to freeze.
        let snapshot = vec![tree_info_without_start_marker(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let events = Rc::clone(&ops.events);

        let reason = run_tree_kill_with(
            &kill_pid_tree(18_422),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || panic!("portless tree root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(&*events.borrow(), &[RecordingTreeEvent::Pin(18_422)]);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_losing_readable_owner_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
        );
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_tree_cap_preflight_refuses_before_any_stop() {
        let rows = vec![entry(3000)];
        let mut over_cap = vec![tree_info(18_422, Some(500), "node")];
        let max_tree_processes =
            u32::try_from(crate::tree::MAX_TREE_PROCESSES).expect("test cap must fit u32");
        for pid in 30_000..=(30_000 + max_tree_processes) {
            over_cap.push(tree_info(pid, Some(18_422), "child"));
        }
        let preview = vec![tree_info(18_422, Some(500), "node")];
        let mut ops = RecordingTreeOps::new(vec![preview, over_cap]);

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &Config::default(),
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || Ok(rows.clone()),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_tree_warning_after_yes_skip_refuses_before_any_stop() {
        let clean = vec![tree_info(18_422, Some(500), "node")];
        let warned = vec![
            tree_info(18_422, Some(500), "node"),
            TreeProcessInfo {
                pid: 18_423,
                parent_pid: Some(18_422),
                process_name: None,
                start_time_marker: Some(18_423),
                owner_uid: None,
                process_group: None,
            },
        ];
        let mut ops = RecordingTreeOps::new(vec![clean, warned]);

        let reason = run_tree_kill_with(
            &kill_pid_tree_yes(18_422),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("portless tree root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_tree_owner_warning_after_yes_skip_refuses_before_any_stop() {
        let clean = vec![tree_info(18_422, Some(500), "node")];
        let warned = vec![
            tree_info(18_422, Some(500), "node"),
            tree_info_owned_by_other_uid(18_423, Some(18_422), "worker"),
        ];
        let mut ops = RecordingTreeOps::new(vec![clean, warned]);

        let reason = run_tree_kill_with(
            &kill_pid_tree_yes(18_422),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("portless tree root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn protected_tree_descendant_refuses_before_prompt_or_stop_even_with_yes() {
        let rows = vec![entry(3000)];
        let snapshot = vec![
            tree_info(18_422, Some(500), "node"),
            tree_info(18_423, Some(18_422), "postgres"),
        ];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: true,
                tree: true,
                group: false,
            },
            &config,
            &rows,
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("protected descendant must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    /// A port row with no readable process name, so the row policy cannot mark
    /// the root protected — the tree scan is the only reader that can.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn nameless_row(port: u16, pid: u32) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(pid),
            process_name: None,
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Partial,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn root_turning_protected_between_confirmation_and_freeze_refuses_with_exit_6() {
        // The confirmed row has no readable name, so identity revalidation
        // cannot compare names. Between confirmation and execution the root
        // execs into a protected name — same PID, same start marker. The fresh
        // root-protection gate must refuse before any stop.
        let rows = vec![nameless_row(3000, 18_422)];
        let confirmation_snapshot = vec![tree_info(18_422, Some(500), "node")];
        let execed_snapshot = vec![TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            process_name: Some("postgres".to_owned()),
            start_time_marker: Some(18_422),
            owner_uid: None,
            process_group: None,
        }];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };
        let mut ops = RecordingTreeOps::new(vec![confirmation_snapshot, execed_snapshot]);

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &config,
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || Ok(rows.clone()),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn completed_protected_confirmation_passes_the_root_protection_gate() {
        // The inverse of the guard: a protected root whose two-step
        // confirmation was completed must execute, not be re-refused.
        // `cli::run` marks entries against the protected list before resolving
        // targets, so the test input must arrive marked the same way.
        let mut rows = vec![entry_with_pid(
            3000,
            Some(18_422),
            Protocol::Tcp,
            "postgres",
        )];
        crate::protection::mark_protected(&mut rows, &["postgres".to_owned()]);
        let snapshot = vec![TreeProcessInfo {
            pid: 18_422,
            parent_pid: Some(500),
            process_name: Some("postgres".to_owned()),
            // Matches the confirmed context marker from `no_context`.
            start_time_marker: Some(55),
            owner_uid: None,
            process_group: None,
        }];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let mut prompts = 0;
        let mut collect_calls = 0;

        let reason = run_tree_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: true,
                group: false,
            },
            &config,
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, _tree: &ProcessTreeTarget, _requirement| {
                    prompts += 1;
                    Ok(true)
                },
                collect_ports: || {
                    collect_calls += 1;
                    if collect_calls == 1 {
                        Ok(rows.clone())
                    } else {
                        Ok(Vec::new())
                    }
                },
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(prompts, 2, "protected root asks for PID/name and the word");
        assert_eq!(ops.stops, vec![18_422]);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn grouped_info(pid: u32, parent_pid: Option<u32>, name: &str, group: u32) -> TreeProcessInfo {
        TreeProcessInfo {
            owner_uid: None,
            process_group: Some(group),
            ..tree_info(pid, parent_pid, name)
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn group_target(
        infos: &[TreeProcessInfo],
        root_pid: u32,
        protected_names: &[String],
    ) -> crate::tree::ProcessGroupTarget {
        crate::tree::plan_process_group(root_pid, infos, protected_names, Platform::Linux, 512)
            .expect("test group root must be present")
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn kill_pid_group(pid: u32, yes: bool) -> KillArgs {
        KillArgs {
            pid: Some(pid),
            port: None,
            force: false,
            yes,
            tree: false,
            group: true,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_confirmation_gates_yes_by_size_warnings_and_protection() {
        let root = kill_target_from_tree_info(&grouped_info(100, Some(500), "node", 42), &[]);

        // Tiny, warning-free group: --yes may skip, everything else prompts
        // for the scope word ("group", or "force" under --force).
        let tiny = group_target(&[grouped_info(100, Some(500), "node", 42)], 100, &[]);
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Terminate, true),
            TreeConfirmDecision::Skip,
        );
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Terminate, false),
            TreeConfirmDecision::PromptWord("group"),
        );
        assert_eq!(
            group_confirmation(&root, &tiny, KillMode::Force, false),
            TreeConfirmDecision::PromptWord("force"),
        );

        // One member past the tiny cap: --yes falls back to the typed word. A
        // group has no structural tie to the target, so size alone is a risk.
        let mut big_infos = vec![grouped_info(100, Some(500), "node", 42)];
        for pid in 0..u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32") {
            big_infos.push(grouped_info(9_000 + pid, Some(500), "worker", 42));
        }
        let big = group_target(&big_infos, 100, &[]);
        assert!(big.members().len() > GROUP_YES_SKIP_MAX_PROCESSES);
        assert_eq!(
            group_confirmation(&root, &big, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A system/service member is a warning: --yes prompts.
        let with_system = group_target(
            &[
                grouped_info(100, Some(500), "node", 42),
                grouped_info(101, Some(1), "systemd", 42),
            ],
            100,
            &[],
        );
        assert_eq!(
            group_confirmation(&root, &with_system, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A different-uid group member is a warning: --yes prompts.
        let with_other_uid = group_target(
            &[
                grouped_info(100, Some(500), "node", 42),
                TreeProcessInfo {
                    process_group: Some(42),
                    ..tree_info_owned_by_other_uid(101, Some(500), "worker")
                },
            ],
            100,
            &[],
        );
        assert_eq!(
            group_confirmation(&root, &with_other_uid, KillMode::Terminate, true),
            TreeConfirmDecision::PromptWord("group"),
        );

        // A protected root keeps the two-step confirmation; --yes refuses.
        let protected_names = vec!["postgres".to_owned()];
        let protected_root_target = kill_target_from_tree_info(
            &grouped_info(100, Some(500), "postgres", 42),
            &protected_names,
        );
        let protected = group_target(
            &[grouped_info(100, Some(500), "postgres", 42)],
            100,
            &protected_names,
        );
        assert_eq!(
            group_confirmation(
                &protected_root_target,
                &protected,
                KillMode::Terminate,
                true
            ),
            TreeConfirmDecision::RefuseProtectedYes,
        );
        assert_eq!(
            group_confirmation(
                &protected_root_target,
                &protected,
                KillMode::Terminate,
                false
            ),
            TreeConfirmDecision::PromptProtectedThenWord("group"),
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn protected_group_member_refuses_before_prompt_or_stop_even_with_yes() {
        let snapshot = vec![
            grouped_info(18_422, Some(500), "node", 42),
            grouped_info(18_423, Some(1), "postgres", 42),
        ];
        let config = Config {
            protected_processes: vec!["postgres".to_owned()],
            ..Config::default()
        };

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, true),
            &config,
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("protected member must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::ProtectedNeedsConfirmation);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_kill_refuses_kernel_domain_roots_without_touching_processes() {
        // The root exists but has no targetable group (pgid 0 maps to None):
        // refuse before any prompt, freeze, or signal.
        let snapshot = vec![tree_info(18_422, Some(500), "node")];

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut PreviewOnlyTreeOps(snapshot),
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("untargetable group must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_root_moving_groups_between_confirmation_and_freeze_refuses_before_any_stop() {
        // The user confirmed group 42; by execution time the root sits in 77.
        // Killing group 77 was never shown to the user, so the fresh gate must
        // refuse with nothing stopped.
        let confirmation_snapshot = vec![
            grouped_info(18_422, Some(500), "node", 42),
            grouped_info(17_000, Some(1), "orphan", 42),
        ];
        let moved_snapshot = vec![grouped_info(18_422, Some(500), "node", 77)];
        let mut ops = RecordingTreeOps::new(vec![confirmation_snapshot, moved_snapshot]);

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || Ok(Vec::new()),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_losing_readable_owner_during_revalidation_exits_permission_denied() {
        let rows = vec![entry(3000)];
        let preview = vec![grouped_info(18_422, Some(500), "node", 42)];
        let mut ops = RecordingTreeOps::new(vec![preview]);
        let events = Rc::clone(&ops.events);
        let fresh_rows = vec![entry_with_pid(3000, None, Protocol::Tcp, "hidden")];

        let reason = run_group_kill_with(
            &KillArgs {
                pid: Some(18_422),
                port: None,
                force: false,
                yes: false,
                tree: false,
                group: true,
            },
            &Config::default(),
            &rows,
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: confirm_tree_prompt,
                collect_ports: || {
                    events.borrow_mut().push(RecordingTreeEvent::CollectPorts);
                    Ok(fresh_rows.clone())
                },
            },
        );

        assert_eq!(reason, ExitReason::PermissionDenied);
        assert_eq!(
            &*events.borrow(),
            &[
                RecordingTreeEvent::Pin(18_422),
                RecordingTreeEvent::CollectPorts,
            ],
        );
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn fresh_group_growing_past_yes_skip_cap_refuses_before_any_stop() {
        let clean = vec![grouped_info(18_422, Some(500), "node", 42)];
        let mut grown = clean.clone();
        for pid in 0..u32::try_from(GROUP_YES_SKIP_MAX_PROCESSES).expect("cap fits u32") {
            grown.push(grouped_info(30_000 + pid, Some(500), "worker", 42));
        }
        let mut ops = RecordingTreeOps::new(vec![clean, grown]);

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, true),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: panic_tree_prompt,
                collect_ports: || panic!("portless group root must not re-collect ports"),
            },
        );

        assert_eq!(reason, ExitReason::Failure);
        assert!(ops.stops.is_empty(), "refusal must precede any stop");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn group_kill_happy_path_freezes_root_first_and_succeeds() {
        // A portless supervisor root plus an already-reparented member: the
        // scenario group scope exists for. One word prompt, then execution
        // freezes the confirmed root before the member and reports success.
        let snapshot = vec![
            grouped_info(18_422, Some(500), "node", 42),
            grouped_info(17_000, Some(1), "orphan", 42),
        ];
        let mut ops = RecordingTreeOps::new(vec![snapshot]);
        let mut prompts = 0;
        let mut collect_calls = 0;

        let reason = run_group_kill_with(
            &kill_pid_group(18_422, false),
            &Config::default(),
            &[],
            KillMode::Terminate,
            &mut ops,
            TreeKillSeams {
                collect_context: no_context,
                prompt: |_target: &KillTarget, members: &ProcessTreeTarget, _requirement| {
                    prompts += 1;
                    assert_eq!(members.len(), 2, "the prompt must name the full count");
                    Ok(true)
                },
                collect_ports: || {
                    collect_calls += 1;
                    Ok(Vec::new())
                },
            },
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(prompts, 1, "an unprotected group asks for the word once");
        assert_eq!(
            ops.stops,
            vec![18_422, 17_000],
            "the confirmed root freezes before the members",
        );
    }
}
