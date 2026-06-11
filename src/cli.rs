//! Non-TUI command-line surface: argument shape, the stable exit-code
//! contract, and the `list`/`kill` command implementations.
//!
//! CLI commands never open the TUI; they print to stdout/stderr and exit.
//! Data flows through the same collector and model as the TUI will, so
//! swapping the fake collector for a real one (Phase 3) changes nothing here.

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Args, Parser, Subcommand};

use crate::collector::{Collector, FakeCollector};
use crate::config::{Config, REFRESH_INTERVAL_SECONDS_MAX, REFRESH_INTERVAL_SECONDS_MIN};
use crate::model::{PortEntry, mark_protected, sort_entries};
use crate::output;

/// Stable exit codes: the script-facing contract from PROJECT.md.
///
/// Defined in one place so scripts can rely on the numbers never drifting.
/// `InvalidArguments` (2) is owned by clap, which exits with 2 on usage
/// errors by itself; `PermissionDenied` (4) becomes constructible when real
/// termination lands in Phase 6. Both are declared now anyway because the
/// contract must be complete before anyone scripts against it.
#[allow(
    dead_code,
    reason = "codes 2 and 4 are reserved contract slots until their flows land"
)]
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
#[derive(Debug, Parser)]
#[command(name = "kickoutchi", version, about)]
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

    /// Force kill (SIGKILL) instead of normal termination (SIGTERM).
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
    let mut entries = match FakeCollector.collect() {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("error: collecting ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    mark_protected(&mut entries, &config.protected_processes);

    match command {
        Command::List(args) => run_list(args, config, entries),
        Command::Kill(args) => run_kill(args, config, &entries),
    }
}

fn run_list(args: &ListArgs, config: &Config, mut entries: Vec<PortEntry>) -> ExitReason {
    let filter_active = args.port.is_some() || args.process.is_some();
    entries.retain(|entry| {
        args.port.is_none_or(|port| entry.matches_port(port))
            && args
                .process
                .as_deref()
                .is_none_or(|process| entry.matches_process(process))
    });
    sort_entries(&mut entries, config.default_sort);

    if args.json {
        match output::render_json(&entries) {
            Ok(json) => println!("{json}"),
            Err(error) => {
                eprintln!("error: rendering JSON failed: {error}");
                return ExitReason::Failure;
            }
        }
    } else if entries.is_empty() {
        println!(
            "no open ports{}",
            if filter_active {
                " match the filter"
            } else {
                ""
            }
        );
    } else {
        println!("{}", output::render_table(&entries));
    }

    // An empty *filtered* result exits 3 so scripts can probe occupancy
    // (`kickoutchi list --port 3000 && echo busy`). An empty unfiltered list
    // is just a quiet machine, which is a success.
    if filter_active && entries.is_empty() {
        return ExitReason::NoMatch;
    }
    ExitReason::Success
}

/// The kill command shape: target selection, safety messaging, and the
/// confirmation flow are real; the termination itself is a stub until
/// Phase 6 and always reports that honestly via exit code 1.
fn run_kill(args: &KillArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    // The two legal target shapes are enumerated; anything else means the
    // clap ArgGroup ("exactly one of --pid/--port") was broken by a code
    // change, which is a programmer error worth crashing on.
    //
    // First-match resolution is a stub-only simplification: a port can be
    // owned by several PIDs (TCP+UDP on one port, SO_REUSEPORT). Phase 6
    // replaces this with explicit ambiguity rejection (see PROJECT.md,
    // Phase 6 step 17) before any real termination ships.
    let target = match (args.pid, args.port) {
        (Some(pid), None) => entries.iter().find(|entry| entry.pid == Some(pid)),
        (None, Some(port)) => entries.iter().find(|entry| entry.matches_port(port)),
        (None, None) | (Some(_), Some(_)) => {
            unreachable!("clap requires exactly one kill target")
        }
    };

    let Some(target) = target else {
        eprintln!("error: no open port matches the requested target");
        return ExitReason::NoMatch;
    };

    // Protected processes are checked before --yes on purpose: PROJECT.md
    // forbids --yes from ever bypassing the protected-process path. The
    // stronger typed confirmation arrives with real termination in Phase 6.
    if target.protected {
        eprintln!(
            "error: {} is protected and requires explicit confirmation; \
             protected termination is not implemented yet",
            target_identity(target),
        );
        return ExitReason::ProtectedNeedsConfirmation;
    }

    if kill_needs_confirmation(args.force, args.yes, config.confirm_force_kill) {
        let confirmed = match prompt_confirmation(target, args.force) {
            Ok(confirmed) => confirmed,
            Err(error) => {
                eprintln!("error: reading confirmation failed: {error}");
                return ExitReason::Failure;
            }
        };
        if !confirmed {
            eprintln!("kill cancelled");
            return ExitReason::KillCancelled;
        }
    }

    eprintln!("error: real termination is not implemented yet (coming in Phase 6)");
    ExitReason::Failure
}

/// Whether the kill flow must ask before acting.
///
/// `--yes` skips prompting for scripts. For force kills the config's
/// `confirm_force_kill` gates the prompt; normal kills always prompt unless
/// `--yes` is given. Protected processes never reach this decision — they are
/// rejected earlier regardless of every flag.
fn kill_needs_confirmation(force: bool, yes: bool, confirm_force_kill: bool) -> bool {
    if yes {
        return false;
    }
    if force {
        return confirm_force_kill;
    }
    true
}

/// Render `PID <pid> (<name>)` for kill-flow messages, with explicit
/// placeholders for withheld metadata. One helper so the protected-process
/// message and the confirmation prompt can never drift apart.
fn target_identity(target: &PortEntry) -> String {
    let pid = target
        .pid
        .map_or_else(|| "?".to_owned(), |pid| pid.to_string());
    let name = target.process_name.as_deref().unwrap_or("<unknown>");
    format!("PID {pid} ({name})")
}

/// Ask the user to confirm on stdin. Default is "no": only an explicit
/// `y`/`yes` proceeds, so pressing Enter on reflex stays safe.
fn prompt_confirmation(target: &PortEntry, force: bool) -> std::io::Result<bool> {
    let action = if force { "Force-kill" } else { "Terminate" };
    print!(
        "{action} {} using port {}? [y/N] ",
        target_identity(target),
        target.local_port,
    );
    std::io::stdout().flush()?;

    let mut answer = String::new();
    // Bounded read: 16 bytes is plenty for any yes/no answer, and the cap
    // means piped or hostile stdin cannot grow the buffer without limit.
    std::io::stdin().lock().take(16).read_line(&mut answer)?;
    let answer = answer.trim();
    Ok(answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, ExitReason, kill_needs_confirmation};

    #[test]
    fn exit_codes_match_the_documented_contract() {
        // These numbers are the script-facing API; a failure here means a
        // breaking change, not a refactor.
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
            "--json",
        ])
        .expect("valid list invocation");
        let Some(Command::List(args)) = cli.command else {
            panic!("expected a list command");
        };
        assert_eq!(args.port, Some(3000));
        assert_eq!(args.process.as_deref(), Some("node"));
        assert!(args.json);
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
        // clap owns exit code 2; this pins that the bound is enforced at
        // parse time rather than leaking into config validation.
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "0"]).is_err());
        assert!(Cli::try_parse_from(["kickoutchi", "--refresh-interval", "3601"]).is_err());
    }

    #[test]
    fn confirmation_decision_covers_all_flag_combinations() {
        // (force, yes, confirm_force_kill) -> must prompt?
        assert!(kill_needs_confirmation(false, false, true));
        assert!(kill_needs_confirmation(false, false, false));
        assert!(kill_needs_confirmation(true, false, true));
        assert!(!kill_needs_confirmation(true, false, false));
        assert!(!kill_needs_confirmation(false, true, true));
        assert!(!kill_needs_confirmation(true, true, true));
    }
}
