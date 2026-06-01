//! Application-level error types.

use std::io;

use thiserror::Error;

/// Top-level error for the Kickoutchi binary.
///
/// Today this only surfaces terminal/IO failures; collector, process, and config
/// errors get their own variants as those subsystems land. Keeping a single
/// typed error at the binary boundary means `main` maps one enum to its exit
/// behaviour instead of matching on stringly-typed failures.
#[derive(Debug, Error)]
pub(crate) enum AppError {
    /// Entering raw mode / the alternate screen, drawing a frame, or restoring
    /// the terminal failed.
    #[error("terminal I/O failed: {0}")]
    Terminal(#[from] io::Error),
}

/// Result alias for fallible application paths.
pub(crate) type AppResult<T> = Result<T, AppError>;
