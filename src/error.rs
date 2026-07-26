//! The error types the app actually deals with.

use std::io;

use thiserror::Error;

/// Top-level error for the TUI path of the Kickoutchi binary.
///
/// This covers failures that must leave the TUI loop: terminal/IO failures and
/// caught worker panics. Config errors have their own type
/// (`config::ConfigError`, handled before the TUI even starts), and collector
/// and termination failures are operational, not fatal: those show up in the
/// status line (last collector error, kill outcome) instead of bubbling all the
/// way up here.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Something in the terminal dance failed: entering raw mode / the alternate
    /// screen, drawing a frame, or reading input. Restore failures don't come
    /// through here — those get logged best-effort, since they happen in `Drop`
    /// and the panic hook.
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
    /// A background TUI worker hit a programmer error. The worker boundary
    /// catches it so the owner can restore the terminal before reporting it.
    #[error(transparent)]
    Worker(#[from] crate::ui::WorkerFailure),
}

/// Shorthand `Result` for the fallible app paths.
pub(crate) type AppResult<T> = Result<T, AppError>;
