//! Kickoutchi: a cross-platform TUI and CLI port janitor.
//!
//! Basically "what are you doing in my swamp?!" — but for whatever's squatting
//! on your local ports.
//!
//! This library is the shared brain both binaries run on. We ship two tiny
//! binaries (`kickoutchi` and `kick`) that just call [`run`], so Cargo isn't
//! stuck compiling and testing the same `main.rs` twice.

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("Kickoutchi supports only Linux, macOS, and Windows");

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
mod labels;
// The read-only family inspection view. It renders data from the process-tree
// snapshot; Windows omits POSIX process-group sections.
mod inspect;
mod model;
mod observation;
mod output;
mod platform;
mod probe;
mod process;
mod process_evidence;
mod protection;
mod public_output;
mod query;
#[cfg(fuzzing)]
mod release_archive_path;
#[cfg(test)]
mod test_support;
// Shared process-tree planning. Linux/macOS use this module's freeze-first
// executor; Windows uses a separate Job Object containment executor.
mod tree;
mod ui;
mod watch;
#[cfg(windows)]
mod windows_tree;

#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind as ClapErrorKind;

use crate::cli::{Cli, Command, ExitReason, WatchSignalGuard};
use crate::config::Config;
use crate::display::sanitize_multiline;

/// Run Kickoutchi and hand back the process exit code.
///
/// Argument errors are rendered here rather than by clap's process-exiting
/// helper so untrusted argv text passes through the terminal sanitizer.
/// On Unix, embedded callers with pre-existing non-Kickoutchi threads must
/// block `SIGTERM` and `SIGHUP` in those threads while the TUI owns its temporary
/// process-wide handlers. The standalone binaries mask every worker they create.
/// Concurrent embedded watch sessions are refused because one process-global
/// Ctrl-C handler cannot have two independent owners. On Unix, an embedder must
/// not replace the `SIGINT` disposition while an active watch owns it. Ctrl-C
/// cancellation remains latched for the process lifetime, so embedders should
/// treat it as a process-wide shutdown request.
#[must_use]
pub fn run() -> ExitCode {
    init_tracing();
    let args = match Cli::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if matches!(
                error.kind(),
                ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion
            ) {
                let rendered = sanitize_multiline(&error.to_string());
                return match write_cli_stdout(io::stdout().lock(), &rendered) {
                    Ok(()) => ExitReason::Success.into(),
                    Err(error) => {
                        eprintln!("error: writing stdout failed: {error}");
                        ExitReason::Failure.into()
                    }
                };
            }
            let rendered = sanitize_multiline(&error.to_string());
            eprintln!("{}", rendered.trim_end());
            return ExitReason::InvalidArguments.into();
        }
    };

    let watch_signal_guard = if matches!(args.command.as_ref(), Some(Command::Watch(_))) {
        match WatchSignalGuard::install() {
            Ok(guard) => Some(guard),
            Err(error) => {
                eprintln!(
                    "error: installing Ctrl-C handler failed: {}",
                    sanitize_multiline(&error.to_string())
                );
                return ExitReason::Failure.into();
            }
        }
    } else {
        None
    };

    let mut config = match Config::load(args.config.as_deref()) {
        Ok(config) => config,
        Err(error) => {
            if watch_signal_guard.is_some() && WatchSignalGuard::cancelled() {
                return ExitReason::Success.into();
            }
            eprintln!("error: {}", error.render_terminal());
            return ExitReason::Failure.into();
        }
    };
    config.apply_cli_overrides(args.refresh_interval);

    match args.command {
        Some(command) => cli::run(&command, &config, watch_signal_guard).into(),
        None => run_tui(&config),
    }
}

/// Run the TUI path. [`ui::run_owned`] scopes the panic hook to this path because
/// its whole job is putting the terminal back the way we found it; the headless
/// CLI path never enters the alternate screen and keeps the embedder's hook.
///
/// Order matters for safety: install the panic hook *before* entering the
/// alternate screen, so a panic during setup or rendering still restores the
/// terminal before anything prints. Normal exits and `?`-errors are already
/// covered by the `Drop` guard inside [`ui::run`].
fn run_tui(config: &Config) -> ExitCode {
    let result = match ui::run_owned(|| ui::run(config)) {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(()) => ExitReason::Success.into(),
        Err(error) => {
            // The terminal's already restored by now, so this lands on the
            // normal screen. Just one line for the user: the tracing subscriber
            // also writes to stderr, so logging the same error here would print
            // it twice. Internal diagnostics go through tracing (see the
            // Drop/panic restore path); fatal user-facing output uses eprintln.
            eprintln!("error: {}", sanitize_multiline(&error.to_string()));
            ExitReason::Failure.into()
        }
    }
}

fn write_cli_stdout(mut writer: impl Write, text: &str) -> io::Result<()> {
    match writer
        .write_all(text.as_bytes())
        .and_then(|()| writer.flush())
    {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

/// Set up tracing for diagnostics that must never touch the TUI surface.
///
/// Logs go to stderr, never stdout (the alternate screen owns stdout), and only
/// when we're outside the alternate screen anyway: startup, shutdown, panic, and
/// fatal-error time. So they can never scribble over a rendered frame.
fn init_tracing() {
    // Embedders own the process-global subscriber; an existing one is valid.
    let _ = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(tracing::Level::WARN)
        .try_init();
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::write_cli_stdout;

    struct FailingWriter(io::ErrorKind);

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(self.0))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn help_output_treats_a_closed_pipe_as_success() {
        assert!(write_cli_stdout(FailingWriter(io::ErrorKind::BrokenPipe), "help").is_ok());
    }

    #[test]
    fn help_output_preserves_non_pipe_write_failures() {
        let error = write_cli_stdout(FailingWriter(io::ErrorKind::PermissionDenied), "help")
            .expect_err("permission errors must remain failures");

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
