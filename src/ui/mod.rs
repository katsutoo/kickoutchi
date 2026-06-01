//! Terminal lifecycle, the event loop, and minimal rendering.
//!
//! The full table/details/help layout is a later phase. Phase 0 proves only that
//! the terminal is entered and, above all, always restored: on clean quit, on a
//! propagated error, and on panic.

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
    fn enter() -> AppResult<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        best_effort_restore();
    }
}

// Reverse of `enter`: leave the alternate screen and disable raw mode.
fn restore_terminal() -> io::Result<()> {
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// Restore the terminal, logging rather than propagating on failure.
///
/// Used from `Drop` and the panic hook, where errors cannot be returned. A
/// terminal we cannot reset is already unrecoverable, so the best we can do is
/// record why it may be left dirty without masking the failure in flight. Both
/// callers may run during the same panic, so a redundant second restore is
/// expected and harmless.
fn best_effort_restore() {
    if let Err(error) = restore_terminal() {
        tracing::warn!(%error, "failed to restore terminal");
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
        terminal.draw(draw)?;

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

// Placeholder Phase 0 screen; the real table/details layout comes later.
fn draw(frame: &mut Frame) {
    let message = Paragraph::new("Kickoutchi: press q, Esc, or Ctrl+C to quit")
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
