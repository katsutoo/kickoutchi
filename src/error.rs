//! Application error types.

use std::io;

use thiserror::Error;

/// Top-level error for the TUI path of the Kickoutchi binary.
///
/// Covers failures that leave the TUI loop: terminal I/O failures and
/// caught worker panics. Config errors have their own type
/// (`config::ConfigError`, handled before the TUI even starts), and collector
/// and termination failures are operational. The status line reports them
/// without ending the TUI loop.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Entering terminal mode, drawing, or reading input failed. Restoration
    /// failures are logged from `Drop` or the panic hook.
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
    /// A background TUI worker hit a programmer error. The worker boundary
    /// catches it so the owner can restore the terminal before reporting it.
    #[error(transparent)]
    Worker(#[from] crate::ui::WorkerFailure),
}

/// Shorthand `Result` for the fallible app paths.
pub(crate) type AppResult<T> = Result<T, AppError>;
