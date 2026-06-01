//! Kickoutchi: a cross-platform TUI port janitor.
//!
//! Phase 0 is intentionally minimal: it opens a terminal screen, runs an event
//! loop that quits on `q`/`Esc`/`Ctrl+C`, and guarantees the terminal is always
//! restored. Port collection, killing, and the full layout arrive in later
//! phases.

mod config;
mod error;
mod ui;

use std::io;
use std::process::ExitCode;

use crate::config::Config;

/// Entry point.
///
/// Ordering is a safety constraint: install the panic hook *before* entering the
/// alternate screen so a panic during TUI setup or rendering still restores the
/// terminal before printing. The `Drop` guard inside [`ui::run`] covers normal
/// and `?`-error exits.
fn main() -> ExitCode {
    init_tracing();
    ui::install_panic_hook();

    let config = Config::default();

    match ui::run(&config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // The terminal is already restored by this point, so this lands on
            // the normal screen. One user-facing line only: the tracing
            // subscriber currently also writes to stderr, so logging the same
            // error here would print it twice. Internal diagnostics use tracing
            // (see the Drop/panic restore path); fatal user output uses eprintln.
            eprintln!("error: {error}");
            ExitCode::FAILURE
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
