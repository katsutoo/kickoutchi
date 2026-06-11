//! Terminal lifecycle, the event loop, and rendering.
//!
//! The central guarantee of this module is that the terminal is entered and,
//! above all, always restored: on clean quit, on a propagated error, and on
//! panic.

use std::io::{self, Stdout};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Alignment;
use ratatui::widgets::{Block, Paragraph};
use ratatui::{Frame, Terminal};

use crate::config::Config;
use crate::error::AppResult;

// Concrete terminal type used throughout the UI.
type Tui = Terminal<CrosstermBackend<Stdout>>;

/// RAII guard that owns the terminal's raw-mode and alternate-screen state.
///
/// Acquisition (raw mode + alternate screen) happens in [`TerminalGuard::enter`];
/// release happens in `Drop`. Pairing the two in one type makes a leak visible at
/// the type level: while the guard is alive the terminal is in TUI mode, and the
/// moment it drops the terminal is restored, whether that drop comes from a
/// normal return, from `?` error unwinding, or from a panic unwinding. This is
/// the safety-first reason the guard exists instead of scattered enable/disable
/// calls that an early return could skip.
struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    /// Enter raw mode and the alternate screen, returning a guard that will
    /// restore both on drop.
    ///
    /// Failures *after* raw mode is enabled restore the terminal before
    /// propagating. No guard exists yet at that point, so `Drop` cannot run,
    /// and the panic hook only fires on panics — without this pairing, an
    /// error from entering the alternate screen or constructing the terminal
    /// (its initial size query does real I/O) would strand the shell in raw
    /// mode, the exact failure this module exists to prevent.
    fn enter() -> AppResult<Self> {
        enable_raw_mode()?;
        match Self::enter_alternate_screen() {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                best_effort_restore();
                Err(error)
            }
        }
    }

    /// The fallible steps between raw mode and a live guard, split out so
    /// every failure in them funnels through the single restore in `enter`.
    fn enter_alternate_screen() -> AppResult<Tui> {
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(terminal)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        best_effort_restore();
    }
}

/// Restore the terminal, logging rather than propagating on failure.
///
/// Used from `Drop` and the panic hook, where errors cannot be returned, and
/// from [`TerminalGuard::enter`]'s failure path, where a restore failure must
/// not mask the original error. A terminal we cannot reset is already
/// unrecoverable, so the best we can do is record why it may be left dirty
/// without masking the failure in flight. Callers may overlap (the panic hook
/// and `Drop` both run during one panic, and the `enter` path restores before
/// the alternate screen was ever entered), so a redundant restore is expected
/// and harmless.
///
/// Teardown mirrors [`TerminalGuard::enter`] in reverse order: leave the
/// alternate screen, then disable raw mode. Each step is attempted and logged
/// independently — a short-circuit here could strand the user on a blank
/// alternate screen, the exact failure this module exists to prevent.
fn best_effort_restore() {
    if let Err(error) = execute!(io::stdout(), LeaveAlternateScreen) {
        tracing::warn!(%error, "failed to leave alternate screen");
    }
    if let Err(error) = disable_raw_mode() {
        tracing::warn!(%error, "failed to disable raw mode");
    }
}

/// Install a panic hook that restores the terminal before the panic is printed.
///
/// Must be called before entering the alternate screen. Without it, the default
/// hook would print the panic message onto the alternate screen, which is then
/// torn down by the guard's `Drop`, losing the message. Restoring first means the
/// message lands on the normal screen where the user can read it. The original
/// hook is preserved so backtraces and `RUST_BACKTRACE` still work.
pub(crate) fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        best_effort_restore();
        original_hook(panic_info);
    }));
}

/// Enter the TUI and run the event loop until the user quits.
///
/// The terminal is restored in every exit path because the guard drops at the end
/// of this function's scope, after the loop's result is computed.
pub(crate) fn run(config: &Config) -> AppResult<()> {
    let mut guard = TerminalGuard::enter()?;
    event_loop(&mut guard.terminal, config)
}

// Draw, then wait for and handle one input event, repeating until a quit key.
fn event_loop(terminal: &mut Tui, config: &Config) -> AppResult<()> {
    loop {
        terminal.draw(|frame| draw(frame, config))?;

        // Bounded wait so the loop can never block forever. `poll` returns the
        // instant input is queued, so the tick interval only caps idle latency
        // rather than busy-polling. Per-tick work (auto refresh) arrives later.
        if !event::poll(config.tick_interval)? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        if is_quit(key) {
            return Ok(());
        }
    }
}

// Placeholder screen; the real table/details layout comes later. It already
// surfaces the active refresh interval because PROJECT.md requires the TUI to
// expose effective config values, and showing it now proves the
// defaults -> file -> CLI-flag merge end to end.
fn draw(frame: &mut Frame, config: &Config) {
    let refresh_seconds = config.refresh_interval.as_secs();
    let message = Paragraph::new(format!(
        "Kickoutchi: press q, Esc, or Ctrl+C to quit\n\
         auto-refresh every {refresh_seconds}s (live table coming in a later phase)"
    ))
    .alignment(Alignment::Center)
    .block(Block::bordered().title("Kickoutchi"));
    frame.render_widget(message, frame.area());
}

/// Return whether a key event should quit the app.
///
/// Only key *presses* count: crossterm also emits release and repeat events on
/// some platforms, and acting on those would quit on key-up as well.
fn is_quit(key: KeyEvent) -> bool {
    if key.kind != KeyEventKind::Press {
        return false;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => true,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_quit;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

    #[test]
    fn quit_keys_quit() {
        assert!(is_quit(KeyEvent::new(
            KeyCode::Char('q'),
            KeyModifiers::NONE
        )));
        assert!(is_quit(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert!(is_quit(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        )));
    }

    #[test]
    fn non_quit_keys_do_not_quit() {
        assert!(!is_quit(KeyEvent::new(
            KeyCode::Char('x'),
            KeyModifiers::NONE
        )));
        // Plain 'c' without Ctrl must not quit; only Ctrl+C does.
        assert!(!is_quit(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        )));
        // Uppercase 'Q' is a distinct code; only lowercase 'q' quits.
        assert!(!is_quit(KeyEvent::new(
            KeyCode::Char('Q'),
            KeyModifiers::NONE
        )));
    }

    #[test]
    fn only_key_press_quits() {
        // Release/repeat events must be ignored so the app does not quit on
        // key-up (crossterm emits these on some platforms).
        let release = KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release,
        );
        assert!(!is_quit(release));
    }
}
