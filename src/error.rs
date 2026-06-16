//! Application-level error types.

use std::io;

use thiserror::Error;

/// Top-level error for the TUI path of the Kickoutchi binary.
///
/// This surfaces only terminal/IO failures, the one error class that is fatal
/// to the TUI run loop. Config errors have their own type
/// (`config::ConfigError`, handled before the TUI starts), and collector and
/// process-termination failures are operational rather than fatal: they are
/// shown in the status line (last collector error, kill outcome) instead of
/// being propagated here.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Entering raw mode / the alternate screen, drawing a frame, or reading
    /// input failed. Restore failures are not propagated here; they are logged
    /// best-effort because they surface in `Drop` and the panic hook.
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
}

/// Result alias for fallible application paths.
pub(crate) type AppResult<T> = Result<T, AppError>;
