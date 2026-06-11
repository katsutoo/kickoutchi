//! Application-level error types.

use std::io;

use thiserror::Error;

/// Top-level error for the TUI path of the Kickoutchi binary.
///
/// Today this only surfaces terminal/IO failures. Config and collector errors
/// have their own standalone types (`config::ConfigError`,
/// `collector::CollectorError`) because they are handled before or outside the
/// TUI; subsystems whose failures must cross the TUI boundary (process
/// termination, live collection) gain variants here as they land.
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
