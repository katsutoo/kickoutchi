//! Terminal lifecycle, the event loop, and rendering.
//!
//! The central guarantee of this module is that the terminal is entered and,
//! above all, always restored: on clean quit, on a propagated error, and on
//! panic.

mod details;
mod help;
mod table;
mod theme;

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::{Frame, Terminal};

use crate::app::{App, Modal};
use crate::config::Config;
use crate::error::AppResult;
use crate::input;

use self::theme::Theme;

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
    let mut app = App::new(config);
    let theme = Theme::from_environment();
    event_loop(&mut guard.terminal, &mut app, config, theme)
}

// Draw, then wait for and handle one input event, repeating until a quit key.
fn event_loop(terminal: &mut Tui, app: &mut App, config: &Config, theme: Theme) -> AppResult<()> {
    loop {
        terminal.draw(|frame| draw(frame, app, theme))?;

        // Bounded wait so the loop can never block forever. `poll` returns the
        // instant input is queued, so the tick interval only caps idle latency
        // rather than busy-polling. Per-tick work (auto refresh) arrives later.
        if !event::poll(config.tick_interval)? {
            continue;
        }

        let Event::Key(key) = event::read()? else {
            continue;
        };

        app.apply_action(input::action_for_key(key, app.modal()));
        if app.should_quit() {
            return Ok(());
        }
    }
}

fn draw(frame: &mut Frame, app: &App, theme: Theme) {
    let area = frame.area();

    if is_too_small(area) {
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
        Modal::Help => help::render(frame, modal_area, theme),
    }
}

fn render_header(frame: &mut Frame, area: Rect, theme: Theme) {
    let line = Line::from(vec![
        Span::styled("Kickoutchi", theme.title()),
        Span::raw("   j/k move  Enter details  ? help  q quit"),
    ]);
    let header = Paragraph::new(line)
        .alignment(Alignment::Center)
        .block(Block::bordered().border_style(theme.border()));
    frame.render_widget(header, area);
}

fn render_status(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let filter = if app.filter_text().is_empty() {
        "none"
    } else {
        app.filter_text()
    };
    let mut status = format!(
        "Status: {} open ports, refreshed {} ago | sort: {} | filter: {filter}",
        app.rows().len(),
        format_age(app.refresh_age()),
        app.sort_mode().label(),
    );

    if let Some(error) = app.latest_error() {
        status.push_str(" | error: ");
        status.push_str(error);
    }

    frame.render_widget(Paragraph::new(status).style(theme.status()), area);
}

fn render_too_small(frame: &mut Frame, area: Rect, theme: Theme) {
    let message = Paragraph::new("Terminal too small\nNeed at least 80x20 to show the table")
        .alignment(Alignment::Center)
        .style(theme.warning())
        .block(
            Block::bordered()
                .title("Kickoutchi")
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

fn format_age(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        let minutes = seconds / 60;
        let seconds = seconds % 60;
        format!("{minutes}m {seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{Theme, draw};
    use crate::app::App;
    use crate::config::Config;
    use crate::input::Action;

    fn render_text(app: &App, width: u16, height: u16) -> String {
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

    #[test]
    fn default_frame_renders_table_details_and_status() {
        let config = Config::default();
        let app = App::new(&config);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Kickoutchi"), "{text}");
        assert!(text.contains("Open Ports"), "{text}");
        assert!(text.contains("3000"), "{text}");
        assert!(text.contains("node"), "{text}");
        assert!(text.contains("Details"), "{text}");
        assert!(text.contains("PID: 18422 | Process: node"), "{text}");
        assert!(text.contains("Status: 5 open ports"), "{text}");
    }

    #[test]
    fn help_modal_renders_keybinds() {
        let config = Config::default();
        let mut app = App::new(&config);
        app.apply_action(Action::OpenHelp);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Help"), "{text}");
        assert!(text.contains("Kickoutchi Phase 2"), "{text}");
        assert!(text.contains("j / Down"), "{text}");
        assert!(text.contains("Ctrl+C"), "{text}");
    }

    #[test]
    fn details_modal_renders_selected_row_metadata() {
        let config = Config::default();
        let mut app = App::new(&config);
        app.apply_action(Action::OpenDetails);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Port Details"), "{text}");
        assert!(text.contains("cursor-agent (PID 18001)"), "{text}");
        assert!(text.contains("node server.js"), "{text}");
    }

    #[test]
    fn small_terminal_renders_fallback_message() {
        let config = Config::default();
        let app = App::new(&config);

        let text = render_text(&app, 40, 10);

        assert!(text.contains("Terminal too small"), "{text}");
        assert!(text.contains("Need at least 80x20"), "{text}");
    }
}
