//! Kickoutchi: a cross-platform TUI and CLI port janitor.
//!
//! Basically "what are you doing in my swamp?!" — but for whatever's squatting
//! on your local ports.
//!
//! This library is the shared brain both binaries run on. We ship two tiny
//! binaries (`kickoutchi` and `kick`) that just call [`run`], so Cargo isn't
//! stuck compiling and testing the same `main.rs` twice.

mod app;
mod cli;
mod collector;
mod command;
mod config;
mod diagnostic;
mod display;
mod docker;
mod error;
mod input;
// The read-only family/group inspection view. It renders data from the tree
// snapshot, so it exists exactly where tree kill does.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod inspect;
mod model;
mod output;
mod platform;
mod process;
mod protection;
mod query;
// Process-tree kill ships on Linux and macOS. Windows has no freeze primitive
// (no SIGSTOP equivalent), so the tree feature is gated to the platforms whose
// safety model it can actually honor; gating also keeps the deny-warnings gate
// happy on builds where the feature would have no caller.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod tree;
mod ui;

use std::io;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, ExitReason};
use crate::config::Config;

/// Run Kickoutchi and hand back the process exit code.
///
/// `Cli::parse` bails out on its own for usage errors (code 2, per our exit
/// contract) and for `--help`/`--version`, so everything below this line is
/// already working with validated arguments.
#[must_use]
pub fn run() -> ExitCode {
    init_tracing();
    let args = Cli::parse();

    let mut config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitReason::Failure.into();
        }
    };
    config.apply_cli_overrides(args.refresh_interval);

    match args.command {
        Some(command) => cli::run(&command, &config).into(),
        None => run_tui(&config),
    }
}

/// Run the TUI path. The panic hook lives here rather than in [`run`] because
/// its whole job is putting the terminal back the way we found it — and the
/// headless CLI path never enters the alternate screen, so it's happy with the
/// default panic output.
///
/// Order matters for safety: install the panic hook *before* entering the
/// alternate screen, so a panic during setup or rendering still restores the
/// terminal before anything prints. Normal exits and `?`-errors are already
/// covered by the `Drop` guard inside [`ui::run`].
fn run_tui(config: &Config) -> ExitCode {
    ui::install_panic_hook();

    match ui::run(config) {
        Ok(()) => ExitReason::Success.into(),
        Err(error) => {
            // The terminal's already restored by now, so this lands on the
            // normal screen. Just one line for the user: the tracing subscriber
            // also writes to stderr, so logging the same error here would print
            // it twice. Internal diagnostics go through tracing (see the
            // Drop/panic restore path); fatal user-facing output uses eprintln.
            eprintln!("error: {error}");
            ExitReason::Failure.into()
        }
    }
}

/// Set up tracing for diagnostics that must never touch the TUI surface.
///
/// Logs go to stderr, never stdout (the alternate screen owns stdout), and only
/// when we're outside the alternate screen anyway: startup, shutdown, panic, and
/// fatal-error time. So they can never scribble over a rendered frame.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
}
