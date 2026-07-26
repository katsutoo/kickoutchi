//! Terminal lifecycle, the event loop, and drawing.
//!
//! The one promise this module makes: we enter the terminal and — above all —
//! always put it back. Clean quit, a propagated error, or a full-on panic, the
//! terminal gets restored either way.

mod confirm;
mod details;
mod help;
mod table;
mod theme;

use std::any::Any;
use std::fmt::Write as _;
use std::io::{self, Stdout};
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
#[cfg(unix)]
use std::sync::atomic::AtomicI32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::{Frame, Terminal};
use unicode_width::UnicodeWidthChar;

use crate::app::{App, Modal};
use crate::config::Config;
use crate::display::sanitize;
use crate::error::AppResult;
use crate::input;

use self::theme::Theme;

// The concrete terminal type we use all over the UI.
type Tui = Terminal<CrosstermBackend<Stdout>>;

const SIGNAL_POLL_INTERVAL: Duration = Duration::from_millis(100);
static TUI_SESSION_LOCK: Mutex<()> = Mutex::new(());
static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);

thread_local! {
    static OWNS_TUI_SESSION: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static IS_TUI_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

type PanicHook = dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static;

struct OriginalPanicHook {
    hook: Box<PanicHook>,
}

/// Restores the process hook when this TUI session completes.
///
/// `run_owned` has exclusive process panic-hook ownership for its lifetime.
/// Embedders must not replace the process hook concurrently; Rust exposes no
/// hook identity that would let us distinguish our dispatcher from a replacement.
pub(crate) struct PanicHookGuard {
    active: Arc<AtomicBool>,
    original: Option<Arc<OriginalPanicHook>>,
}

/// A panic caught at the TUI worker boundary and handed back to its owner.
#[derive(Debug, thiserror::Error)]
#[error("TUI worker {worker} panicked: {message}")]
pub(crate) struct WorkerFailure {
    worker: String,
    message: String,
}

impl WorkerFailure {
    fn from_panic(payload: &(dyn Any + Send)) -> Self {
        let message = payload
            .downcast_ref::<&str>()
            .map(|message| (*message).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        let worker = thread::current().name().unwrap_or("unnamed").to_owned();
        Self { worker, message }
    }

    #[cfg(test)]
    pub(crate) fn for_test(worker: &str, message: &str) -> Self {
        Self {
            worker: worker.to_owned(),
            message: message.to_owned(),
        }
    }
}

/// Result channel for one detached-capable TUI worker.
pub(crate) struct Worker<T> {
    receiver: mpsc::Receiver<Result<T, WorkerFailure>>,
    handle: thread::JoinHandle<()>,
}

impl<T> Worker<T> {
    fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<Result<T, WorkerFailure>, RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    #[cfg(test)]
    fn recv(&self) -> Result<Result<T, WorkerFailure>, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Keep only the completion channel. Dropping the handle preserves Rust's
    /// normal detached-thread behavior used by refresh/details/tree workers.
    pub(crate) fn detach(self) -> mpsc::Receiver<Result<T, WorkerFailure>> {
        self.receiver
    }

    fn join(self) -> thread::Result<()> {
        self.handle.join()
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
        let installed = std::panic::take_hook();
        drop(installed);
        let Some(shared) = self.original.take() else {
            return;
        };
        if let Ok(original) = Arc::try_unwrap(shared) {
            std::panic::set_hook(original.hook);
        }
    }
}

struct TuiSessionGuard {
    _lock: MutexGuard<'static, ()>,
}

impl TuiSessionGuard {
    fn acquire() -> io::Result<Self> {
        if OWNS_TUI_SESSION.with(std::cell::Cell::get) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "a nested TUI session is not supported",
            ));
        }
        let lock = TUI_SESSION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        OWNS_TUI_SESSION.with(|owns| owns.set(true));
        Ok(Self { _lock: lock })
    }
}

impl Drop for TuiSessionGuard {
    fn drop(&mut self) {
        OWNS_TUI_SESSION.with(|owns| owns.set(false));
    }
}

#[cfg(unix)]
static TERMINATION_SIGNAL: AtomicI32 = AtomicI32::new(0);

/// Keep the first shutdown request and ignore every later one.
///
/// Split out from the handler so the first-wins rule can be exercised against a
/// caller-supplied slot. Driving the process-global from a test instead would
/// race every concurrent reader of it — including the one inside
/// [`wait_for_startup_worker`], which consumes the slot on each poll and would
/// silently steal the recorded signal.
///
/// A relaxed compare-exchange is the whole body, so this stays
/// async-signal-safe: no allocation, no locks, no reentrancy.
#[cfg(unix)]
fn record_first_signal(slot: &AtomicI32, signal: libc::c_int) {
    let _ = slot.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

#[cfg(unix)]
extern "C" fn record_termination_signal(signal: libc::c_int) {
    record_first_signal(&TERMINATION_SIGNAL, signal);
}

#[cfg(unix)]
struct TuiSignalGuard {
    previous_term: libc::sigaction,
    previous_hup: libc::sigaction,
    installed: bool,
}

#[cfg(unix)]
impl TuiSignalGuard {
    fn install() -> io::Result<Self> {
        TERMINATION_SIGNAL.store(0, Ordering::Relaxed);
        // SAFETY: both actions are fully initialized before installation. The
        // handler only performs a lock-free atomic operation, and both previous
        // dispositions are retained for normal teardown.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = record_termination_signal as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = 0;

            let mut previous_term: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGTERM, &raw const action, &raw mut previous_term) != 0 {
                return Err(io::Error::last_os_error());
            }

            let mut previous_hup: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGHUP, &raw const action, &raw mut previous_hup) != 0 {
                let error = io::Error::last_os_error();
                libc::sigaction(
                    libc::SIGTERM,
                    &raw const previous_term,
                    std::ptr::null_mut(),
                );
                return Err(error);
            }

            Ok(Self {
                previous_term,
                previous_hup,
                installed: true,
            })
        }
    }

    fn restore_previous(&mut self) -> io::Result<()> {
        if !self.installed {
            return Ok(());
        }
        // SAFETY: these actions were returned by successful `sigaction` calls
        // and remain valid for the lifetime of the guard.
        unsafe {
            let term_result = libc::sigaction(
                libc::SIGTERM,
                &raw const self.previous_term,
                std::ptr::null_mut(),
            );
            let term_error = (term_result != 0).then(io::Error::last_os_error);
            let hup_result = libc::sigaction(
                libc::SIGHUP,
                &raw const self.previous_hup,
                std::ptr::null_mut(),
            );
            let hup_error = (hup_result != 0).then(io::Error::last_os_error);
            if let Some(error) = term_error.or(hup_error) {
                return Err(error);
            }
        }
        self.installed = false;
        Ok(())
    }

    fn previous_disposition(&self, signal: libc::c_int) -> usize {
        match signal {
            libc::SIGTERM => self.previous_term.sa_sigaction,
            libc::SIGHUP => self.previous_hup.sa_sigaction,
            _ => libc::SIG_DFL,
        }
    }
}

#[cfg(unix)]
impl Drop for TuiSignalGuard {
    fn drop(&mut self) {
        if let Err(error) = self.restore_previous() {
            tracing::warn!(%error, "failed to restore TUI signal handlers");
        }
    }
}

#[cfg(unix)]
struct BlockedTerminationSignals {
    previous: libc::sigset_t,
    active: bool,
}

#[cfg(unix)]
impl BlockedTerminationSignals {
    fn block() -> io::Result<Self> {
        // SAFETY: both sets are initialized by libc before being passed to
        // pthread_sigmask, and remain live for the duration of the call.
        unsafe {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            if libc::sigemptyset(&raw mut signals) != 0
                || libc::sigaddset(&raw mut signals, libc::SIGTERM) != 0
                || libc::sigaddset(&raw mut signals, libc::SIGHUP) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let mut previous: libc::sigset_t = std::mem::zeroed();
            let result =
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const signals, &raw mut previous);
            if result != 0 {
                return Err(io::Error::from_raw_os_error(result));
            }
            Ok(Self {
                previous,
                active: true,
            })
        }
    }

    fn restore(mut self) -> io::Result<()> {
        // SAFETY: `previous` is the exact mask returned by pthread_sigmask.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result));
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for BlockedTerminationSignals {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // SAFETY: `previous` remains initialized until this guard is dropped.
        let result = unsafe {
            libc::pthread_sigmask(
                libc::SIG_SETMASK,
                &raw const self.previous,
                std::ptr::null_mut(),
            )
        };
        if result != 0 {
            tracing::warn!(error = %io::Error::from_raw_os_error(result), "failed to restore signal mask");
        }
    }
}

/// RAII guard that owns the terminal's raw-mode and alternate-screen state.
///
/// Setup (raw mode + alternate screen) happens in [`TerminalGuard::enter`];
/// teardown happens in `Drop`. Bundling the two into one type makes a leak
/// impossible to miss at the type level: while the guard is alive the terminal is
/// in TUI mode, and the instant it drops the terminal is back to normal — whether
/// that drop came from a normal return, `?` unwinding an error, or a panic
/// unwinding the stack. That's the whole reason this guard exists instead of
/// loose enable/disable calls that an early return could quietly skip.
struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    /// Enter raw mode and the alternate screen, handing back a guard that puts
    /// both back on drop.
    ///
    /// Anything that fails *after* raw mode is on restores the terminal before
    /// propagating. There's no guard yet at that point, so `Drop` can't run, and
    /// the panic hook only fires on panics — so without this little dance, an
    /// error from entering the alternate screen or building the terminal (its
    /// first size query does real I/O) would leave the shell stuck in raw mode,
    /// the exact thing this module exists to prevent.
    fn enter() -> AppResult<Self> {
        enable_raw_mode()?;
        TERMINAL_ACTIVE.store(true, Ordering::Release);
        match Self::enter_alternate_screen() {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                restore_terminal_if_active();
                Err(error)
            }
        }
    }

    /// The fallible steps between raw mode and a live guard, pulled out so every
    /// failure in here funnels through that one restore back in `enter`.
    fn enter_alternate_screen() -> AppResult<Tui> {
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(terminal)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_if_active();
    }
}

/// Put the terminal back, logging instead of propagating if a step fails.
///
/// Called from `Drop` and the panic hook (where we can't return an error) and
/// from [`TerminalGuard::enter`]'s failure path (where a restore failure must not
/// clobber the original error). A terminal we can't reset is already a lost
/// cause, so the best we can do is note why it might be left messy without hiding
/// the failure that's already in flight. Callers can overlap — the panic hook and
/// `Drop` both run during one panic, and the `enter` path restores before the
/// alternate screen was ever entered — so a redundant restore is expected and
/// totally harmless.
///
/// Teardown undoes [`TerminalGuard::enter`] in reverse: leave the alternate
/// screen, then disable raw mode. Each step is tried and logged on its own — bail
/// out early here and you could strand the user on a blank alternate screen,
/// which is the exact failure this module exists to prevent.
fn best_effort_restore() {
    if let Err(error) = execute!(io::stdout(), LeaveAlternateScreen) {
        tracing::warn!(%error, "failed to leave alternate screen");
    }
    if let Err(error) = disable_raw_mode() {
        tracing::warn!(%error, "failed to disable raw mode");
    }
}

fn restore_terminal_if_active() {
    if TERMINAL_ACTIVE.swap(false, Ordering::AcqRel) {
        best_effort_restore();
    }
}

/// Install a panic hook that restores the terminal before the panic prints.
///
/// Has to run before we enter the alternate screen. Without it, the default hook
/// would print the panic onto the alternate screen, which the guard's `Drop` then
/// tears down — and poof, the message is gone. Restoring first means the panic
/// lands on the normal screen where the user can actually read it. We keep the
/// original hook so backtraces and `RUST_BACKTRACE` still work.
fn install_panic_hook() -> PanicHookGuard {
    let original_hook = std::panic::take_hook();
    let original = Arc::new(OriginalPanicHook {
        hook: original_hook,
    });
    let hook_original = Arc::clone(&original);
    let active = Arc::new(AtomicBool::new(true));
    let hook_active = Arc::clone(&active);
    std::panic::set_hook(Box::new(move |panic_info| {
        if hook_active.load(Ordering::Acquire) && IS_TUI_WORKER.with(std::cell::Cell::get) {
            // `spawn_worker` catches this panic and reports it to owner control
            // flow. Printing or restoring here would happen on the worker while
            // the alternate screen still belongs to the owner.
            return;
        }
        if hook_active.load(Ordering::Acquire) && OWNS_TUI_SESSION.with(std::cell::Cell::get) {
            restore_terminal_if_active();
        }
        (hook_original.hook)(panic_info);
    }));
    PanicHookGuard {
        active,
        original: Some(original),
    }
}

/// Own the process-global terminal and panic hook for one complete session.
/// The unwind is caught so hook restoration always occurs from normal control
/// flow; nested ownership is rejected rather than deadlocking the same thread.
pub(crate) fn run_owned<T>(operation: impl FnOnce() -> T) -> io::Result<T> {
    let session = TuiSessionGuard::acquire()?;
    let panic_hook = install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(operation));
    drop(panic_hook);
    drop(session);
    match outcome {
        Ok(value) => Ok(value),
        Err(payload) => resume_unwind(payload),
    }
}

/// Spawn a TUI worker with SIGTERM/SIGHUP blocked from its first instruction.
/// The child waits behind a gate until the owner thread's exact prior mask has
/// been restored, so a failed restore never starts background work.
pub(crate) fn spawn_worker<T: Send + 'static>(
    builder: thread::Builder,
    operation: impl FnOnce() -> T + Send + 'static,
) -> io::Result<Worker<T>> {
    let (result_sender, result_receiver) = mpsc::sync_channel(1);
    let run = move || {
        IS_TUI_WORKER.with(|worker| worker.set(true));
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(value) => {
                let _ = result_sender.send(Ok(value));
            }
            Err(payload) => {
                let failure = WorkerFailure::from_panic(payload.as_ref());
                if result_sender.send(Err(failure)).is_err() {
                    // No owner remains to surface the typed failure. Re-raise
                    // with the marker cleared so the normal panic hook reports
                    // the programmer error instead of silently dropping it.
                    IS_TUI_WORKER.with(|worker| worker.set(false));
                    resume_unwind(payload);
                }
            }
        }
        IS_TUI_WORKER.with(|worker| worker.set(false));
    };

    #[cfg(not(unix))]
    {
        let handle = builder.spawn(run)?;
        Ok(Worker {
            receiver: result_receiver,
            handle,
        })
    }

    #[cfg(unix)]
    {
        let blocked = BlockedTerminationSignals::block()?;
        let (start_sender, start_receiver) = mpsc::sync_channel(0);
        let worker = match builder.spawn(move || {
            if start_receiver.recv().is_ok() {
                run();
            }
        }) {
            Ok(worker) => worker,
            Err(error) => {
                return match blocked.restore() {
                    Ok(()) => Err(error),
                    Err(restore_error) => Err(restore_error),
                };
            }
        };

        if let Err(error) = blocked.restore() {
            drop(start_sender);
            let _ = worker.join();
            return Err(error);
        }
        if start_sender.send(()).is_err() {
            let _ = worker.join();
            return Err(io::Error::other("TUI worker stopped before its start gate"));
        }
        Ok(Worker {
            receiver: result_receiver,
            handle: worker,
        })
    }
}

/// Enter the TUI and run the event loop until the user quits.
///
/// Every exit path restores the terminal because the guard drops at the end of
/// this function's scope, after the loop's result has been computed.
pub(crate) fn run(config: &Config) -> AppResult<()> {
    #[cfg(unix)]
    let signal_guard = TuiSignalGuard::install()?;

    let startup = wait_for_initial_app(config.clone());
    let mut app = match startup {
        Ok(StartupOutcome::Ready(app)) => app,
        #[cfg(unix)]
        Ok(StartupOutcome::Signal(signal)) => {
            return finalize_unix(signal_guard, None, Ok(EventLoopExit::Signal(signal)));
        }
        Err(error) => {
            #[cfg(unix)]
            return finalize_unix(signal_guard, None, Err(error));
            #[cfg(not(unix))]
            return Err(error);
        }
    };

    let mut guard = match TerminalGuard::enter() {
        Ok(guard) => guard,
        Err(error) => {
            #[cfg(unix)]
            return finalize_unix(signal_guard, None, Err(error));
            #[cfg(not(unix))]
            return Err(error);
        }
    };
    let theme = Theme::from_environment();
    let outcome = event_loop(&mut guard.terminal, &mut app, config, theme);

    #[cfg(unix)]
    return finalize_unix(signal_guard, Some(guard), outcome);

    #[cfg(not(unix))]
    drop(guard);
    #[cfg(not(unix))]
    let _ = outcome?;
    #[cfg(not(unix))]
    Ok(())
}

fn wait_for_initial_app(config: Config) -> AppResult<StartupOutcome> {
    let worker = spawn_worker(
        thread::Builder::new().name("kickoutchi-initial-collection".to_owned()),
        move || App::new(&config),
    )?;

    wait_for_startup_worker(worker)
}

fn wait_for_startup_worker<T: Send + 'static>(
    worker: Worker<T>,
) -> AppResult<StartupOutcomeGeneric<T>> {
    loop {
        #[cfg(unix)]
        if let Some(signal) = take_termination_signal() {
            drop(worker);
            return Ok(StartupOutcomeGeneric::Signal(signal));
        }

        match worker.recv_timeout(SIGNAL_POLL_INTERVAL) {
            Ok(Ok(app)) => {
                worker.join().map_err(|_| {
                    io::Error::other("initial collection worker panicked after returning")
                })?;
                return Ok(StartupOutcomeGeneric::Ready(app));
            }
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error.into());
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                let message = if worker.join().is_err() {
                    "initial collection worker panicked"
                } else {
                    "initial collection worker exited before returning"
                };
                return Err(io::Error::other(message).into());
            }
        }
    }
}

type StartupOutcome = StartupOutcomeGeneric<App>;

#[derive(Debug)]
enum StartupOutcomeGeneric<T> {
    Ready(T),
    #[cfg(unix)]
    Signal(libc::c_int),
}

#[cfg(unix)]
fn finalize_unix(
    mut signal_guard: TuiSignalGuard,
    terminal: Option<TerminalGuard>,
    outcome: AppResult<EventLoopExit>,
) -> AppResult<()> {
    finalize_unix_after_block(&mut signal_guard, terminal, outcome, || {})
}

#[cfg(unix)]
fn finalize_unix_after_block(
    signal_guard: &mut TuiSignalGuard,
    terminal: Option<TerminalGuard>,
    outcome: AppResult<EventLoopExit>,
    after_block: impl FnOnce(),
) -> AppResult<()> {
    let blocked = BlockedTerminationSignals::block()?;
    drop(terminal);
    after_block();

    let requested_signal = match &outcome {
        Ok(EventLoopExit::Signal(signal)) => Some(*signal),
        _ => take_termination_signal(),
    };
    let default_disposition = requested_signal
        .is_some_and(|signal| signal_guard.previous_disposition(signal) == libc::SIG_DFL);
    signal_guard.restore_previous()?;

    if let Some(signal) = requested_signal {
        // Re-raise with the embedder's exact disposition while blocked. Restoring
        // the old mask below delivers default/custom handlers atomically; an
        // ignored disposition deliberately discards the signal.
        // SAFETY: `signal` is one of SIGTERM/SIGHUP recorded by our handler.
        if unsafe { libc::raise(signal) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
    }
    blocked.restore()?;

    if default_disposition {
        return Err(
            io::Error::other("default termination signal did not terminate process").into(),
        );
    }
    if requested_signal.is_some() {
        return Ok(());
    }
    let _ = outcome?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventLoopExit {
    Quit,
    #[cfg(unix)]
    Signal(libc::c_int),
}

// Draw a frame, wait for one input event, handle it, then go round again until
// a quit key shows up.
fn event_loop(
    terminal: &mut Tui,
    app: &mut App,
    config: &Config,
    theme: Theme,
) -> AppResult<EventLoopExit> {
    loop {
        #[cfg(unix)]
        if let Some(signal) = take_termination_signal() {
            return Ok(EventLoopExit::Signal(signal));
        }

        if let Some(error) = poll_workers(app) {
            return Err(error.into());
        }
        terminal.draw(|frame| draw(frame, app, theme))?;

        let wait = std::cmp::min(
            config.tick_interval,
            app.time_until_refresh(config.refresh_interval),
        );
        match event::poll(bounded_event_wait(wait)) {
            Ok(true) => {
                if let Event::Key(key) = event::read()? {
                    if handle_modal_scroll(app, key) {
                        continue;
                    }
                    app.apply_action(input::action_for_key(
                        key,
                        app.modal(),
                        app.search_mode(),
                        !app.filter_text().is_empty(),
                    ));
                    // A worker can fail while input is blocked. Poll again before
                    // honoring quit so a queued programmer error cannot become a
                    // successful TUI exit.
                    if let Some(error) = poll_workers(app) {
                        return Err(error.into());
                    }
                }
            }
            Ok(false) => {}
            Err(error) => {
                #[cfg(unix)]
                if let Some(signal) = take_termination_signal() {
                    return Ok(EventLoopExit::Signal(signal));
                }
                return Err(error.into());
            }
        }

        if app.should_quit() {
            return Ok(EventLoopExit::Quit);
        }

        if app.refresh_due(config.refresh_interval) {
            app.refresh();
        }
    }
}

fn poll_workers(app: &mut App) -> Option<WorkerFailure> {
    app.poll_refresh();
    app.poll_process_context();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    app.poll_tree_preview();
    app.take_worker_failure()
}

fn handle_modal_scroll(app: &mut App, key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press || !matches!(app.modal(), Modal::Details | Modal::Help) {
        return false;
    }
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => app.scroll_modal_by(1),
        KeyCode::Char('k') | KeyCode::Up => app.scroll_modal_by(-1),
        KeyCode::PageDown => app.scroll_modal_by(8),
        KeyCode::PageUp => app.scroll_modal_by(-8),
        KeyCode::Home => app.set_modal_scroll(0),
        KeyCode::End => app.set_modal_scroll(u16::MAX),
        _ => return false,
    }
    true
}

fn bounded_event_wait(wait: Duration) -> Duration {
    wait.min(SIGNAL_POLL_INTERVAL)
}

/// Consume the recorded request, leaving the slot empty. See
/// [`record_first_signal`] for why this takes the slot as an argument.
#[cfg(unix)]
fn take_first_signal(slot: &AtomicI32) -> Option<libc::c_int> {
    match slot.swap(0, Ordering::Relaxed) {
        0 => None,
        signal => Some(signal),
    }
}

#[cfg(unix)]
fn take_termination_signal() -> Option<libc::c_int> {
    take_first_signal(&TERMINATION_SIGNAL)
}

fn draw(frame: &mut Frame, app: &mut App, theme: Theme) {
    let area = frame.area();

    if is_too_small(area) {
        cancel_hidden_confirmation(app);
        render_too_small(frame, area, theme);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(7),
            Constraint::Length(9),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(frame, chunks[0], theme);
    table::render(frame, chunks[1], app, theme);
    details::render_panel(frame, chunks[2], app, theme);
    render_status(frame, chunks[3], app, theme);

    let modal_area = centered_rect(76, 76, area);
    match app.modal() {
        Modal::None => {}
        Modal::Details => details::render_modal(frame, modal_area, app, theme),
        Modal::Help => help::render(frame, centered_rect(90, 90, area), app, theme),
        Modal::ConfirmKill => confirm::render(frame, modal_area, app, theme),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Modal::ConfirmTreeKill => {
            if !confirm::render_tree(frame, centered_rect(76, 90, area), app, theme) {
                app.cancel_confirmation_for_layout();
            }
        }
    }
}

fn cancel_hidden_confirmation(app: &mut App) {
    let destructive_confirmation = match app.modal() {
        Modal::ConfirmKill => true,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Modal::ConfirmTreeKill => true,
        _ => false,
    };
    if destructive_confirmation {
        app.apply_action(input::Action::CancelKill);
    }
}

// The header advertises only keys that exist on this build: tree kill is a
// Linux/macOS feature, so Windows must not see a t/T hint it cannot use.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const HEADER_KEY_HINTS: &str = "   r refresh  / search  s sort  x/X kill  t/T tree  ? help  q quit";
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
const HEADER_KEY_HINTS: &str = "   r refresh  / search  s sort  x/X kill  ? help  q quit";

fn render_header(frame: &mut Frame, area: Rect, theme: Theme) {
    let line = Line::from(vec![
        Span::styled("Kickoutchi", theme.title()),
        Span::raw(HEADER_KEY_HINTS),
    ]);
    let header = Paragraph::new(line)
        .alignment(Alignment::Center)
        .block(Block::bordered().border_style(theme.border()));
    frame.render_widget(header, area);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let filter = if app.filter_text().is_empty() {
        "none".to_owned()
    } else {
        sanitize(app.filter_text())
    };
    let search = if app.search_mode() { "editing" } else { "idle" };
    let mut status = String::new();
    let _ = write!(
        status,
        "Status: {}/{} open ports, refreshed {} | sort: {} | filter: {filter} | search: {search}",
        app.rows().len(),
        app.total_row_count(),
        format_age(app.refresh_age()),
        app.sort_mode().label(),
    );

    if let Some(error) = app.filter_error() {
        append_status_field(&mut status, "filter error", error);
    }

    if let Some(error) = app.latest_error() {
        append_status_field(&mut status, "error", error);
    }

    if let Some(kill_status) = app.kill_status() {
        append_status_field(&mut status, "kill", kill_status);
    }

    frame.render_widget(Paragraph::new(status).style(theme.status()), area);
}

fn append_status_field(status: &mut String, label: &str, value: &str) {
    status.push_str(" | ");
    status.push_str(label);
    status.push_str(": ");
    status.push_str(&sanitize(value));
}

fn render_too_small(frame: &mut Frame, area: Rect, theme: Theme) {
    let message = Paragraph::new("Terminal too small\nNeed at least 80x20 to show the table")
        .alignment(Alignment::Center)
        .style(theme.warning())
        .block(
            Block::bordered()
                .title("Kickoutchi")
                .title_style(theme.title())
                .border_style(theme.border()),
        );
    frame.render_widget(message, area);
}

fn is_too_small(area: Rect) -> bool {
    area.width < 80 || area.height < 20
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    debug_assert!(percent_x <= 100);
    debug_assert!(percent_y <= 100);

    let vertical_margin = (100 - percent_y) / 2;
    let horizontal_margin = (100 - percent_x) / 2;
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(vertical_margin),
            Constraint::Percentage(percent_y),
            Constraint::Percentage(vertical_margin),
        ])
        .split(area);
    let horizontal = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(percent_x),
            Constraint::Percentage(horizontal_margin),
        ])
        .split(vertical[1]);
    horizontal[1]
}

/// A `Label: value` line, shared by the details panel, the details modal, and
/// the kill-confirmation modal so those panels stay visually consistent. It
/// lives here in the parent module instead of being copied into each submodule:
/// one definition means the label styling and the `: ` separator can never drift
/// between panels that are meant to look the same.
fn field(label: &'static str, value: String, theme: Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), theme.label()),
        Span::raw(value),
    ])
}

/// Conservative terminal-row budget for ratatui word wrapping. Unicode
/// whitespace is charged explicitly, wide characters use terminal columns,
/// and long words are hard-wrapped.
fn wrapped_rows(text: &str, content_cols: usize) -> usize {
    let cols = content_cols.max(1);
    text.split('\n')
        .map(|logical| {
            let mut rows = 1usize;
            let mut used = 0usize;
            let mut chars = logical.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch.is_whitespace() {
                    let width = ch.width().unwrap_or(0);
                    if width > 0 && used + width > cols {
                        rows += 1;
                        used = 0;
                    }
                    used = used.saturating_add(width).min(cols);
                    continue;
                }

                let mut word_width = ch.width().unwrap_or(0);
                while chars.peek().is_some_and(|next| !next.is_whitespace()) {
                    word_width = word_width.saturating_add(
                        chars.next().and_then(UnicodeWidthChar::width).unwrap_or(0),
                    );
                }
                if word_width <= cols {
                    if used > 0 && used + word_width > cols {
                        rows += 1;
                        used = 0;
                    }
                    used += word_width;
                } else {
                    if used > 0 {
                        rows += 1;
                    }
                    rows += word_width.div_ceil(cols).saturating_sub(1);
                    used = word_width % cols;
                    if used == 0 {
                        used = cols;
                    }
                }
            }
            rows
        })
        .sum::<usize>()
        .max(1)
}

fn rendered_rows(lines: &[Line<'_>], content_cols: usize) -> usize {
    lines
        .iter()
        .map(|line| wrapped_rows(&line.to_string(), content_cols))
        .sum()
}

fn format_age(duration: Option<Duration>) -> String {
    let Some(duration) = duration else {
        return "never".to_owned();
    };
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s ago")
    } else {
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        format!("{minutes}m {seconds}s ago")
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::mpsc;
    use std::time::Duration;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{SIGNAL_POLL_INTERVAL, Theme, append_status_field, bounded_event_wait, draw};
    use crate::app::{App, Modal};
    use crate::config::Config;
    use crate::input::Action;
    use crate::labels::{LabelInput, LabelRegistry};

    #[cfg(unix)]
    static CUSTOM_SIGNAL_CALLS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    #[cfg(unix)]
    extern "C" fn custom_sigterm_handler(_: libc::c_int) {
        CUSTOM_SIGNAL_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn render_frame(app: &mut App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test backend must initialize");
        terminal
            .draw(|frame| draw(frame, app, Theme::from_environment()))
            .expect("test frame must draw");

        let buffer = terminal.backend().buffer();
        let area = buffer.area;
        let mut text = String::new();
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        render_frame(app, width, height)
    }

    #[test]
    fn default_frame_renders_table_details_and_status() {
        let config = Config::default();
        let mut app = App::new_fake(&config);

        let text = render_text(&mut app, 100, 30);

        assert!(text.contains("Kickoutchi"), "{text}");
        // The force-kill key is advertised on the main screen, not just in help.
        assert!(text.contains("x/X kill"), "{text}");
        assert!(text.contains("Open Ports"), "{text}");
        assert!(text.contains("3000"), "{text}");
        assert!(text.contains("node"), "{text}");
        assert!(text.contains("Details"), "{text}");
        assert!(text.contains("PID: 18422 | Process: node"), "{text}");
        assert!(text.contains("Status: 5/5 open ports"), "{text}");
    }

    #[test]
    fn configured_labels_render_only_when_table_width_can_preserve_legacy_layout() {
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "127.0.0.1".to_owned(),
                port: 3000,
                scope_id: None,
                label: "web dev".to_owned(),
            }])
            .unwrap(),
            ..Config::default()
        };
        let mut app = App::new_fake(&config);

        let wide = render_text(&mut app, 120, 30);
        assert!(wide.contains("LABEL"), "{wide}");
        assert!(wide.contains("web dev"), "{wide}");

        let minimum = render_text(&mut app, 80, 20);
        assert!(!minimum.contains("LABEL"), "{minimum}");
        assert!(minimum.contains("SCOPE"), "{minimum}");

        let below_boundary = render_text(&mut app, 105, 30);
        assert!(!below_boundary.contains("LABEL"), "{below_boundary}");
        let at_boundary = render_text(&mut app, 106, 30);
        assert!(at_boundary.contains("LABEL"), "{at_boundary}");
        assert!(at_boundary.contains("web dev"), "{at_boundary}");
    }

    #[test]
    fn configured_unmatched_selector_still_enables_wide_label_column() {
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "*".to_owned(),
                port: 65_000,
                scope_id: None,
                label: "unused".to_owned(),
            }])
            .unwrap(),
            ..Config::default()
        };
        let mut app = App::new_fake(&config);

        let wide = render_text(&mut app, 120, 30);
        assert!(wide.contains("LABEL"), "{wide}");
        assert!(!wide.contains("unused"), "{wide}");
    }

    #[test]
    fn help_modal_renders_keybinds() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::OpenHelp);

        let text = render_text(&mut app, 100, 30);

        assert!(text.contains("Help"), "{text}");
        assert!(text.contains("Kickoutchi"), "{text}");
        assert!(text.contains("j / Down"), "{text}");
        assert!(text.contains('x'), "{text}");
        assert!(text.contains('/'), "{text}");
        assert!(text.contains("Ctrl+C"), "{text}");
        for filter in ["label:", "address:", "scope_id:", "family:"] {
            assert!(text.contains(filter), "missing {filter} in {text}");
        }
        // Tree keys are advertised only on builds that actually bind them.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(text.contains("terminate selected process tree"), "{text}");
    }

    #[test]
    fn status_shows_active_search_text() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::StartSearch);
        app.apply_action(Action::SearchAppend('3'));

        let text = render_text(&mut app, 100, 30);

        assert!(text.contains("filter: 3"), "{text}");
        assert!(text.contains("search: editing"), "{text}");
    }

    #[test]
    fn status_fields_are_sanitized_before_rendering() {
        let mut status = "Status: ok".to_owned();

        append_status_field(&mut status, "kill", "\x1b[31mfailed\nagain");

        assert_eq!(status, "Status: ok | kill: failed again");
    }

    #[test]
    fn help_and_details_bottom_rows_are_scrollable_at_minimum_size() {
        let mut config = Config::default();
        config.protected_processes.push("node".to_owned());
        let mut app = App::new_fake(&config);
        app.apply_action(Action::OpenHelp);

        let first = render_text(&mut app, 80, 20);
        assert!(first.contains("Up/Down"), "{first}");
        app.set_modal_scroll(u16::MAX);
        let bottom = render_text(&mut app, 80, 20);
        for filter in [
            "label:web",
            "address:127.0.0.1",
            "scope_id:3",
            "family:ipv6",
        ] {
            assert!(bottom.contains(filter), "missing {filter} in {bottom}");
        }

        app.apply_action(Action::CloseModal);
        app.apply_action(Action::OpenDetails);
        let top = render_text(&mut app, 80, 20);
        assert!(top.contains("Protected process"), "{top}");
        assert!(top.contains("Up/Down"), "{top}");
        app.set_modal_scroll(u16::MAX);
        let bottom = render_text(&mut app, 80, 20);
        assert!(bottom.contains("Path: /usr/bin/node"), "{bottom}");
        assert!(bottom.contains("Command: node server.js"), "{bottom}");
        assert!(bottom.contains("Protected process"), "{bottom}");
    }

    #[test]
    fn initial_worker_panic_is_reported_as_a_typed_failure() {
        let error = super::run_owned(|| {
            let worker = super::spawn_worker(
                std::thread::Builder::new().name("initial-test".to_owned()),
                || panic!("startup failed"),
            )
            .unwrap();
            super::wait_for_startup_worker(worker)
        })
        .unwrap()
        .expect_err("worker panic must be reported");
        assert!(
            error
                .to_string()
                .contains("TUI worker initial-test panicked: startup failed")
        );
    }

    #[test]
    fn details_modal_renders_selected_row_metadata() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::OpenDetails);

        let text = render_text(&mut app, 100, 30);

        assert!(text.contains("Port Details"), "{text}");
        assert!(text.contains("cursor-agent (PID 18001)"), "{text}");
        assert!(text.contains("node server.js"), "{text}");
    }

    #[test]
    fn kill_confirmation_modal_renders_target_and_command() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::RequestForceKill);

        let text = render_text(&mut app, 100, 30);

        assert!(text.contains("Confirm Termination"), "{text}");
        assert!(text.contains("Force-kill PID 18422"), "{text}");
        assert!(text.contains("kill -9 18422"), "{text}");
        assert!(text.contains("force"), "{text}");
    }

    #[test]
    fn small_terminal_renders_fallback_message() {
        let config = Config::default();
        let mut app = App::new_fake(&config);

        let text = render_text(&mut app, 40, 10);

        assert!(text.contains("Terminal too small"), "{text}");
        assert!(text.contains("Need at least 80x20"), "{text}");
    }

    #[test]
    fn small_terminal_cancels_a_single_process_confirmation() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::RequestForceKill);
        assert_eq!(app.modal(), Modal::ConfirmKill);

        let text = render_text(&mut app, 40, 10);

        assert!(text.contains("Terminal too small"), "{text}");
        assert_eq!(app.modal(), Modal::None);
        assert!(app.kill_confirmation().is_none());
        assert_eq!(app.kill_status(), Some("kill cancelled"));
        app.apply_action(Action::SubmitKillConfirmation);
        assert_eq!(app.modal(), Modal::None);
    }

    #[test]
    fn signal_observation_bounds_an_otherwise_long_event_wait() {
        assert_eq!(
            bounded_event_wait(Duration::from_secs(30)),
            SIGNAL_POLL_INTERVAL,
        );
        assert_eq!(
            bounded_event_wait(Duration::from_millis(25)),
            Duration::from_millis(25),
        );
    }

    #[cfg(unix)]
    fn current_signal_mask_contains(signal: libc::c_int) -> bool {
        // SAFETY: a null set queries the calling thread's current mask into the
        // initialized output set without modifying it.
        unsafe {
            let mut current: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(0, std::ptr::null(), &raw mut current),
                0,
            );
            libc::sigismember(&raw const current, signal) == 1
        }
    }

    #[cfg(unix)]
    #[test]
    fn tui_worker_inherits_blocked_termination_signals_and_parent_mask_is_exact() {
        let parent_term = current_signal_mask_contains(libc::SIGTERM);
        let parent_hup = current_signal_mask_contains(libc::SIGHUP);
        let (sender, receiver) = mpsc::sync_channel(1);

        let worker = super::spawn_worker(
            std::thread::Builder::new().name("signal-mask-probe".to_owned()),
            move || {
                sender
                    .send((
                        current_signal_mask_contains(libc::SIGTERM),
                        current_signal_mask_contains(libc::SIGHUP),
                    ))
                    .unwrap();
            },
        )
        .unwrap();

        assert_eq!(receiver.recv().unwrap(), (true, true));
        worker.recv().unwrap().unwrap();
        worker.join().unwrap();
        assert_eq!(current_signal_mask_contains(libc::SIGTERM), parent_term);
        assert_eq!(current_signal_mask_contains(libc::SIGHUP), parent_hup);
    }

    #[cfg(unix)]
    #[test]
    fn finalization_delivers_process_signal_only_after_worker_safe_teardown() {
        use std::process::Command;
        use std::sync::atomic::Ordering;

        const CHILD_ENV: &str = "KICKOUTCHI_TEST_FINAL_SIGNAL_RACE";
        if std::env::var_os(CHILD_ENV).is_some() {
            CUSTOM_SIGNAL_CALLS.store(0, Ordering::Relaxed);
            // SAFETY: this isolated child owns the process disposition.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = custom_sigterm_handler as *const () as usize;
                libc::sigemptyset(&raw mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut()),
                    0,
                );
            }
            let mut guard = super::TuiSignalGuard::install().unwrap();
            let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
            let (release_sender, release_receiver) = mpsc::sync_channel(1);
            let worker = super::spawn_worker(
                std::thread::Builder::new().name("final-signal-worker".to_owned()),
                move || {
                    ready_sender
                        .send(current_signal_mask_contains(libc::SIGTERM))
                        .unwrap();
                    release_receiver.recv().unwrap();
                },
            )
            .unwrap();
            assert!(ready_receiver.recv().unwrap());

            super::finalize_unix_after_block(
                &mut guard,
                None,
                Ok(super::EventLoopExit::Quit),
                || {
                    // SAFETY: queue SIGTERM specifically for the owner while it
                    // is blocked; the live TUI worker independently proves it
                    // inherited the same blocked set above.
                    assert_eq!(
                        unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
                        0,
                    );
                },
            )
            .unwrap();
            assert_eq!(CUSTOM_SIGNAL_CALLS.load(Ordering::Relaxed), 1);
            assert_eq!(super::take_termination_signal(), None);
            release_sender.send(()).unwrap();
            worker.recv().unwrap().unwrap();
            worker.join().unwrap();
            return;
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ui::tests::finalization_delivers_process_signal_only_after_worker_safe_teardown",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .expect("final-signal child must start");
        assert!(status.success(), "final-signal child exited with {status}");
    }

    /// The slot is local on purpose. The process-global one is consumed by
    /// `wait_for_startup_worker` on every poll, so a test that recorded into it
    /// would hand its signal to whichever other test happened to be polling —
    /// which is exactly the race this test used to lose intermittently. The
    /// installed handler is covered end to end by the child-process tests
    /// below, with real signals; this one owns the first-wins state machine.
    #[cfg(unix)]
    #[test]
    fn signal_handler_records_the_first_shutdown_request_for_normal_control_flow() {
        use super::{record_first_signal, take_first_signal};
        use std::sync::atomic::AtomicI32;

        let slot = AtomicI32::new(0);
        record_first_signal(&slot, libc::SIGTERM);
        record_first_signal(&slot, libc::SIGHUP);

        assert_eq!(take_first_signal(&slot), Some(libc::SIGTERM));
        assert_eq!(take_first_signal(&slot), None);
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_is_reraised_with_conventional_process_status() {
        use std::os::unix::process::ExitStatusExt;
        use std::process::Command;

        const CHILD_ENV: &str = "KICKOUTCHI_TEST_TUI_SIGTERM_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let guard = super::TuiSignalGuard::install().expect("signal handlers must install");
            // SAFETY: SIGTERM is handled by the just-installed atomic-only
            // handler, and this call occurs in ordinary test control flow.
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            let signal = super::take_termination_signal().expect("handler must record SIGTERM");
            super::finalize_unix(guard, None, Ok(super::EventLoopExit::Signal(signal)))
                .expect("default SIGTERM must terminate before returning");
            unreachable!("default SIGTERM returned");
        }

        let status = Command::new(std::env::current_exe().expect("test executable must exist"))
            .args([
                "--exact",
                "ui::tests::sigterm_is_reraised_with_conventional_process_status",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .status()
            .expect("signal child must start");

        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_restores_and_honors_custom_and_ignored_dispositions() {
        use std::process::Command;
        use std::sync::atomic::Ordering;

        const CHILD_ENV: &str = "KICKOUTCHI_TEST_TUI_SIGTERM_DISPOSITION";
        if let Some(mode) = std::env::var_os(CHILD_ENV) {
            let expected = if mode == "custom" {
                custom_sigterm_handler as *const () as usize
            } else {
                libc::SIG_IGN
            };
            // SAFETY: the action is initialized in full and this subprocess has
            // no other test manipulating SIGTERM.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = expected;
                libc::sigemptyset(&raw mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGTERM, &raw const action, std::ptr::null_mut()),
                    0,
                );
            }
            let guard = super::TuiSignalGuard::install().unwrap();
            // SAFETY: the temporary TUI handler records SIGTERM atomically.
            assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
            let signal = super::take_termination_signal().unwrap();
            super::finalize_unix(guard, None, Ok(super::EventLoopExit::Signal(signal))).unwrap();

            let mut restored: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: `restored` is writable and a null action performs a query.
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGTERM, std::ptr::null(), &raw mut restored) },
                0,
            );
            assert_eq!(restored.sa_sigaction, expected);
            assert_eq!(
                CUSTOM_SIGNAL_CALLS.load(Ordering::Relaxed),
                usize::from(mode == "custom"),
            );
            return;
        }

        for mode in ["custom", "ignored"] {
            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "ui::tests::sigterm_restores_and_honors_custom_and_ignored_dispositions",
                    "--nocapture",
                ])
                .env(CHILD_ENV, mode)
                .status()
                .expect("signal-disposition child must start");
            assert!(status.success(), "{mode} child exited with {status}");
        }
    }

    #[test]
    fn completed_tui_session_restores_the_previous_panic_hook() {
        use std::process::Command;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc;
        use std::time::Duration;

        const CHILD_ENV: &str = "KICKOUTCHI_TEST_PANIC_HOOK_CHILD";
        static PANICS: AtomicUsize = AtomicUsize::new(0);
        if std::env::var_os(CHILD_ENV).is_some() {
            std::panic::set_hook(Box::new(|_| {
                PANICS.fetch_add(1, Ordering::Relaxed);
            }));

            let caught = std::panic::catch_unwind(|| {
                super::run_owned(|| panic!("caught TUI panic")).unwrap();
            });
            assert!(caught.is_err());
            assert_eq!(PANICS.load(Ordering::Relaxed), 1);

            let _ = std::panic::catch_unwind(|| panic!("probe restored hook"));
            assert_eq!(PANICS.load(Ordering::Relaxed), 2);

            super::run_owned(|| {
                let worker = super::spawn_worker(
                    std::thread::Builder::new().name("pre-terminal-panic".to_owned()),
                    || panic!("startup worker panic"),
                )
                .unwrap();
                let failure = worker
                    .recv()
                    .unwrap()
                    .expect_err("worker panic must be typed");
                assert!(failure.to_string().contains("startup worker panic"));
                worker.join().unwrap();
            })
            .unwrap();
            assert_eq!(PANICS.load(Ordering::Relaxed), 2);

            super::run_owned(|| {
                let error = super::run_owned(|| ()).expect_err("nested TUI must be refused");
                assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            })
            .unwrap();

            let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
            let (release_sender, release_receiver) = mpsc::sync_channel(1);
            let first = std::thread::spawn(move || {
                super::run_owned(|| {
                    entered_sender.send(()).unwrap();
                    release_receiver.recv().unwrap();
                })
                .unwrap();
            });
            entered_receiver.recv().unwrap();
            let (second_sender, second_receiver) = mpsc::sync_channel(1);
            let second = std::thread::spawn(move || {
                super::run_owned(|| second_sender.send(()).unwrap()).unwrap();
            });
            assert_eq!(
                second_receiver.recv_timeout(Duration::from_millis(50)),
                Err(mpsc::RecvTimeoutError::Timeout),
            );
            release_sender.send(()).unwrap();
            second_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("concurrent session starts after ownership release");
            first.join().unwrap();
            second.join().unwrap();
            return;
        }

        let output = Command::new(std::env::current_exe().expect("test executable must exist"))
            .args([
                "--exact",
                "ui::tests::completed_tui_session_restores_the_previous_panic_hook",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("panic-hook child must start");

        assert!(
            output.status.success(),
            "panic-hook child exited with {}",
            output.status,
        );
        assert!(
            !output
                .stdout
                .windows(8)
                .any(|bytes| bytes == b"\x1b[?1049l"),
            "pre-terminal panic emitted alternate-screen teardown: {:?}",
            String::from_utf8_lossy(&output.stdout),
        );
    }

    #[test]
    fn worker_panic_after_terminal_activation_is_reported_by_owner_only() {
        use std::process::Command;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const CHILD_ENV: &str = "KICKOUTCHI_TEST_ACTIVE_WORKER_PANIC";
        static HOOK_CALLS: AtomicUsize = AtomicUsize::new(0);
        if std::env::var_os(CHILD_ENV).is_some() {
            std::panic::set_hook(Box::new(|_| {
                HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
                eprintln!("panic hook printed while terminal was active");
            }));

            super::run_owned(|| {
                super::TERMINAL_ACTIVE.store(true, Ordering::Release);
                let worker = super::spawn_worker(
                    std::thread::Builder::new().name("kickoutchi-refresh".to_owned()),
                    || panic!("refresh invariant failed"),
                )
                .unwrap();
                let failure = worker
                    .recv()
                    .unwrap()
                    .expect_err("owner must receive the worker panic");

                assert!(
                    super::TERMINAL_ACTIVE.load(Ordering::Acquire),
                    "the worker must not restore terminal state"
                );
                super::TERMINAL_ACTIVE.store(false, Ordering::Release);
                eprintln!("owner diagnostic after restore: {failure}");
                worker.join().unwrap();
            })
            .unwrap();
            assert_eq!(HOOK_CALLS.load(Ordering::Relaxed), 0);
            return;
        }

        let output = Command::new(std::env::current_exe().expect("test executable must exist"))
            .args([
                "--exact",
                "ui::tests::worker_panic_after_terminal_activation_is_reported_by_owner_only",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("worker-panic child must start");
        let stderr = String::from_utf8(output.stderr).expect("child stderr must be UTF-8");

        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains(
                "owner diagnostic after restore: TUI worker kickoutchi-refresh panicked: refresh invariant failed"
            ),
            "{stderr}"
        );
        assert!(!stderr.contains("panic hook printed"), "{stderr}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_modal_renders_loading_then_preview() {
        let config = Config::default();
        let mut app = App::new_fake(&config);

        // The header advertises the tree keys on builds that have them.
        assert!(render_text(&mut app, 100, 30).contains("t/T tree"));

        app.apply_action(Action::RequestTreeTerminate);
        let text = render_text(&mut app, 100, 30);
        assert!(text.contains("Confirm Tree Termination"), "{text}");
        assert!(text.contains("Enumerating the process tree"), "{text}");
        assert!(text.contains("Wait for the process count"), "{text}");
        assert!(!text.contains("Type tree"), "{text}");

        // The fake table's selected row is PID 18422 (node) with one child.
        let infos = vec![
            crate::tree::TreeProcessInfo {
                pid: 18_422,
                parent_pid: Some(1),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("node".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(55).ok(),
                owner_uid: None,
                process_group: None,
            },
            crate::tree::TreeProcessInfo {
                pid: 18_430,
                parent_pid: Some(18_422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("worker".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(56).ok(),
                owner_uid: None,
                process_group: None,
            },
        ];
        let preview =
            crate::tree::plan_process_tree(18_422, &infos, &[], crate::model::Platform::Linux, 256)
                .expect("preview must build");
        app.finish_tree_preview_for_test(Ok(preview));

        let text = render_text(&mut app, 100, 30);
        assert!(
            text.contains("Terminate process tree from PID 18422"),
            "{text}"
        );
        assert!(text.contains("tree (2 processes)"), "{text}");
        assert!(text.contains("PID 18430 (worker)"), "{text}");
        assert!(text.contains("Type tree"), "{text}");

        let mut crowded_infos = infos;
        for pid in 18_431..18_451 {
            crowded_infos.push(crate::tree::TreeProcessInfo {
                pid,
                parent_pid: Some(18_422),
                unverified_parent_pid: None,
                parent_process_name: None,
                process_name: Some("aaaaaaaaaaa bbbbbbbbbbb ccccccccccc".to_owned()),
                start_time_marker: crate::observation::ProcessStartMarker::linux(u64::from(pid))
                    .ok(),
                owner_uid: None,
                process_group: None,
            });
        }
        let preview = crate::tree::plan_process_tree(
            18_422,
            &crowded_infos,
            &[],
            crate::model::Platform::Linux,
            256,
        )
        .expect("crowded preview must build");
        app.finish_tree_preview_for_test(Ok(preview));
        for ch in "tre".chars() {
            app.apply_action(Action::KillInputAppend(ch));
        }
        app.apply_action(Action::SubmitKillConfirmation);

        let text = render_text(&mut app, 80, 20);
        assert!(text.contains("Type tree"), "{text}");
        assert!(text.contains("Input: tre"), "{text}");
        assert!(text.contains("Error: type tree"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn small_terminal_cancels_a_tree_confirmation() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::RequestTreeForceKill);
        assert_eq!(app.modal(), Modal::ConfirmTreeKill);

        let text = render_text(&mut app, 40, 10);

        assert!(text.contains("Terminal too small"), "{text}");
        assert_eq!(app.modal(), Modal::None);
        assert!(app.tree_confirmation().is_none());
        assert_eq!(app.kill_status(), Some("tree kill cancelled"));
        app.apply_action(Action::SubmitKillConfirmation);
        assert_eq!(app.modal(), Modal::None);
    }
}
