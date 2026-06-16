//! Kickoutchi: a cross-platform TUI and CLI port janitor.
//!
//! This library owns the shared application entrypoint. The package ships two
//! tiny binaries (`kickoutchi` and `kick`) that both call [`run`], so Cargo does
//! not compile and test the same `main.rs` as two separate binary targets.

mod app;
mod cli;
mod collector;
mod command;
mod config;
mod diagnostic;
mod error;
mod input;
mod model;
mod output;
mod platform;
mod process;
mod protection;
mod query;
mod ui;

use std::io;
use std::process::ExitCode;

use clap::Parser;

use crate::cli::{Cli, ExitReason};
use crate::config::Config;

/// Run the Kickoutchi application and return the process exit code.
///
/// `Cli::parse` exits by itself on usage errors (code 2, matching the
/// documented exit contract) and on `--help`/`--version`, so everything past it
/// runs with validated arguments.
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

/// Run the TUI path. The panic hook is installed here, not in [`run`], because
/// its only job is restoring the terminal: the headless CLI path never enters
/// the alternate screen and keeps the default panic output.
///
/// Ordering is a safety constraint: install the panic hook *before* entering
/// the alternate screen so a panic during TUI setup or rendering still restores
/// the terminal before printing. The `Drop` guard inside [`ui::run`] covers
/// normal and `?`-error exits.
fn run_tui(config: &Config) -> ExitCode {
    ui::install_panic_hook();

    match ui::run(config) {
        Ok(()) => ExitReason::Success.into(),
        Err(error) => {
            // The terminal is already restored by this point, so this lands on
            // the normal screen. One user-facing line only: the tracing
            // subscriber currently also writes to stderr, so logging the same
            // error here would print it twice. Internal diagnostics use tracing
            // (see the Drop/panic restore path); fatal user output uses eprintln.
            eprintln!("error: {error}");
            ExitReason::Failure.into()
        }
    }
}

/// Initialise tracing for diagnostics that must never touch the TUI surface.
///
/// Logs go to stderr, never stdout (the alternate screen owns stdout). They are
/// also only emitted outside the alternate screen: at startup, shutdown, panic,
/// and fatal-error time. That way they can never corrupt a rendered frame.
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::WARN)
        .init();
}
