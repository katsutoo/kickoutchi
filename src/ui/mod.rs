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
use crate::display::sanitize;
use crate::error::AppResult;
use crate::input;

use self::theme::Theme;

// The concrete terminal type we use all over the UI.
type Tui = Terminal<CrosstermBackend<Stdout>>;

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
        match Self::enter_alternate_screen() {
            Ok(terminal) => Ok(Self { terminal }),
            Err(error) => {
                best_effort_restore();
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
        best_effort_restore();
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

/// Install a panic hook that restores the terminal before the panic prints.
///
/// Has to run before we enter the alternate screen. Without it, the default hook
/// would print the panic onto the alternate screen, which the guard's `Drop` then
/// tears down — and poof, the message is gone. Restoring first means the panic
/// lands on the normal screen where the user can actually read it. We keep the
/// original hook so backtraces and `RUST_BACKTRACE` still work.
pub(crate) fn install_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        best_effort_restore();
        original_hook(panic_info);
    }));
}

/// Enter the TUI and run the event loop until the user quits.
///
/// Every exit path restores the terminal because the guard drops at the end of
/// this function's scope, after the loop's result has been computed.
pub(crate) fn run(config: &Config) -> AppResult<()> {
    let mut guard = TerminalGuard::enter()?;
    let mut app = App::new(config);
    let theme = Theme::from_environment();
    event_loop(&mut guard.terminal, &mut app, config, theme)
}

// Draw a frame, wait for one input event, handle it, then go round again until
// a quit key shows up.
fn event_loop(terminal: &mut Tui, app: &mut App, config: &Config, theme: Theme) -> AppResult<()> {
    loop {
        app.poll_refresh();
        app.poll_process_context();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        app.poll_tree_preview();
        terminal.draw(|frame| draw(frame, app, theme))?;

        let wait = std::cmp::min(
            config.tick_interval,
            app.time_until_refresh(config.refresh_interval),
        );
        if event::poll(wait)?
            && let Event::Key(key) = event::read()?
        {
            app.apply_action(input::action_for_key(
                key,
                app.modal(),
                app.search_mode(),
                !app.filter_text().is_empty(),
            ));
        }

        if app.should_quit() {
            return Ok(());
        }

        if app.refresh_due(config.refresh_interval) {
            app.refresh();
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
        Modal::ConfirmKill => confirm::render(frame, modal_area, app, theme),
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        Modal::ConfirmTreeKill => {
            confirm::render_tree(frame, centered_rect(76, 90, area), app, theme);
        }
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
    let mut status = format!(
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
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{Theme, append_status_field, draw};
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
        let app = App::new_fake(&config);

        let text = render_text(&app, 100, 30);

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
    fn help_modal_renders_keybinds() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::OpenHelp);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Help"), "{text}");
        assert!(text.contains("Kickoutchi"), "{text}");
        assert!(text.contains("j / Down"), "{text}");
        assert!(text.contains('x'), "{text}");
        assert!(text.contains('/'), "{text}");
        assert!(text.contains("Ctrl+C"), "{text}");
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

        let text = render_text(&app, 100, 30);

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
    fn details_modal_renders_selected_row_metadata() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::OpenDetails);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Port Details"), "{text}");
        assert!(text.contains("cursor-agent (PID 18001)"), "{text}");
        assert!(text.contains("node server.js"), "{text}");
    }

    #[test]
    fn kill_confirmation_modal_renders_target_and_command() {
        let config = Config::default();
        let mut app = App::new_fake(&config);
        app.apply_action(Action::RequestForceKill);

        let text = render_text(&app, 100, 30);

        assert!(text.contains("Confirm Termination"), "{text}");
        assert!(text.contains("Force-kill PID 18422"), "{text}");
        assert!(text.contains("kill -9 18422"), "{text}");
        assert!(text.contains("force"), "{text}");
    }

    #[test]
    fn small_terminal_renders_fallback_message() {
        let config = Config::default();
        let app = App::new_fake(&config);

        let text = render_text(&app, 40, 10);

        assert!(text.contains("Terminal too small"), "{text}");
        assert!(text.contains("Need at least 80x20"), "{text}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn tree_confirmation_modal_renders_loading_then_preview() {
        let config = Config::default();
        let mut app = App::new_fake(&config);

        // The header advertises the tree keys on builds that have them.
        assert!(render_text(&app, 100, 30).contains("t/T tree"));

        app.apply_action(Action::RequestTreeTerminate);
        let text = render_text(&app, 100, 30);
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

        let text = render_text(&app, 100, 30);
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

        let text = render_text(&app, 80, 20);
        assert!(text.contains("Type tree"), "{text}");
        assert!(text.contains("Input: tre"), "{text}");
        assert!(text.contains("Error: type tree"), "{text}");
        assert!(text.contains("Esc cancels."), "{text}");
    }
}
