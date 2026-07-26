//! Test-only coordination between process spawning and advisory file locks.
//!
//! The update cache guards itself with advisory `flock` locks, and several
//! tests spawn child processes. Those two facts collide inside one
//! multi-threaded test binary: `fork` duplicates the entire descriptor table,
//! so a child created by one test still references every lock descriptor other
//! threads hold at that instant. The duplicate keeps the open file description
//! alive until the child reaches `exec` and `O_CLOEXEC` closes it, which means
//! dropping the lock owner does not actually release the lock during that
//! window. A `try_lock` in the meantime reports `WouldBlock` for reasons that
//! have nothing to do with the behavior under test.
//!
//! Production never hits this: the one place Kickoutchi spawns a child while a
//! cache lock exists is the foreground update check, and it drops the lock
//! before spawning on purpose (see
//! `foreground_drops_lock_before_spawn_and_failed_spawn_retries_immediately`).
//! The collision is created by running both kinds of test in one process.
//!
//! The lock below keeps them apart with the smallest possible loss of
//! parallelism: cache tests take it shared, so they still run concurrently with
//! each other, and spawning tests take it exclusively for the `fork` itself.
//! Waiting on the child happens after the guard is released, so a slow child
//! never serializes the suite.

use std::io;
#[cfg(unix)]
use std::process::ExitStatus;
use std::process::{Child, Command, Output, Stdio};
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

static FILE_LOCKS_VERSUS_FORK: RwLock<()> = RwLock::new(());

/// Hold for as long as this thread owns an advisory lock on a cache file.
///
/// Shared: any number of tests may hold cache locks at once, because they use
/// distinct files. They only need to exclude `fork`.
pub(crate) fn holding_file_lock() -> RwLockReadGuard<'static, ()> {
    // A test that panics while holding a guard poisons the lock. Recovering the
    // inner guard keeps that failure reported as itself instead of cascading
    // into every later test as a poison panic.
    FILE_LOCKS_VERSUS_FORK
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Hold across `Command::spawn` only, never across waiting for the child.
fn spawning_process() -> RwLockWriteGuard<'static, ()> {
    FILE_LOCKS_VERSUS_FORK
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}

/// `Command::spawn`, with the fork excluded from concurrent lock holders.
///
/// The guard covers the fork and nothing else. Callers wait on the child after
/// it is released, so a child that runs for a second does not stall every cache
/// test for that second.
pub(crate) fn spawn_guarded(command: &mut Command) -> io::Result<Child> {
    let _guard = spawning_process();
    command.spawn()
}

/// `Command::status` with a guarded fork. Stdio is inherited, as it is there.
///
/// Gated to match its callers: every test that re-execs the binary to drive a
/// real signal is Unix-only, so an ungated definition would be dead code on
/// Windows and fail the `-D warnings` lint there.
#[cfg(unix)]
pub(crate) fn status_guarded(command: &mut Command) -> io::Result<ExitStatus> {
    spawn_guarded(command)?.wait()
}

/// `Command::output` with a guarded fork. The stdio configuration matches what
/// `Command::output` applies for itself: captured output, no inherited stdin.
pub(crate) fn output_guarded(command: &mut Command) -> io::Result<Output> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    spawn_guarded(command)?.wait_with_output()
}
