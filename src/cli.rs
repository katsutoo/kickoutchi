//! The non-TUI command-line side: the argument shape, the stable exit-code
//! contract, and the `list`/`kill` commands themselves.
//!
//! CLI commands never pop open the TUI — they print to stdout/stderr and exit.
//! The data flows through the same collector and model as the TUI, so the two
//! stay in sync and this layer doesn't care which collector produced the rows.

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::collector;
use crate::command;
use crate::config::{Config, REFRESH_INTERVAL_SECONDS_MAX, REFRESH_INTERVAL_SECONDS_MIN};
use crate::diagnostic;
use crate::model::{PortEntry, ProcessContext, SortMode};
use crate::output;
use crate::platform;
use crate::process::{
    self, CONFIRMATION_INPUT_MAX_BYTES, ConfirmationRequirement, KillMode, KillTarget,
    TerminationOutcome, UnsafePidReason,
};
use crate::protection::mark_protected;
use crate::query::{self, QueryOptions};

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
    exit_reason_for_outcome(&outcome)
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
            let name = entry.process_name.as_deref().unwrap_or("<unknown>");
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
    eprintln!("Ports: {}", target.ports_text());
    eprintln!(
        "Command: {}",
        command::render_kill_command(target.platform, target.pid, mode),
    );
    if let Some(warning) = mode.force_warning(target.platform) {
        eprintln!("Warning: {warning}");
    }
    for warning in target.warning_lines() {
        eprintln!("Warning: {warning}.");
    }
}

fn prompt_confirmation(
    target: &KillTarget,
    mode: KillMode,
    requirement: ConfirmationRequirement,
) -> std::io::Result<bool> {
    match requirement {
        ConfirmationRequirement::Yes => print!("Type y to confirm, or press Enter to cancel: "),
        ConfirmationRequirement::ForceWord => {
            print!(
                "Type force to confirm {}: ",
                mode.delivery_label(target.platform)
            );
        }
        ConfirmationRequirement::ProtectedProcess => print!(
            "Protected process: type PID {} or process name {} to confirm: ",
            target.pid,
            target.process_name_or_unknown(),
        ),
    }
    std::io::stdout().flush()?;

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
        TerminationOutcome::Success => eprintln!(
            "sent {delivery} to {}; refresh to verify the port disappeared",
            target.identity(),
        ),
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
            "error: sending {delivery} to {} failed: {error}",
            target.identity(),
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
    use clap::Parser;

    use std::net::{IpAddr, Ipv4Addr};

    use super::{
        Cli, Command, ExitReason, KillArgs, KillCollectors, KillTargetError,
        diagnostic_port_without_confirmed_socket, resolve_kill_target, run_kill_with,
        truncate_to_char_boundary,
    };
    use crate::config::Config;
    use crate::model::{
        PermissionStatus, Platform, PortEntry, ProcessContext, Protocol, SocketState, SortMode,
    };
    use crate::process::{ConfirmationRequirement, KillMode, TerminationOutcome, UnsafePidReason};

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
        }
    }

    fn kill_port(port: u16, force: bool, yes: bool) -> KillArgs {
        KillArgs {
            pid: None,
            port: Some(port),
            force,
            yes,
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

        let reason = run_kill_with(
            &kill_pid(18_422, false, true),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(rows.clone()),
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

        let reason = run_kill_with(
            &kill_pid(18_422, true, false),
            &Config::default(),
            &rows,
            KillCollectors {
                collect_context: no_context,
                collect_ports: || Ok(rows.clone()),
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
}
