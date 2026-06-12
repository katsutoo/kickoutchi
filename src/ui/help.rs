//! Help modal rendering.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use super::theme::Theme;

pub(crate) fn render(frame: &mut Frame, area: Rect, theme: Theme) {
    let lines = vec![
        Line::styled("Kickoutchi Phase 2", theme.title()),
        Line::raw(
            "Static fake-data TUI skeleton. Real refresh, filters, and termination land in later phases.",
        ),
        Line::raw(""),
        key_line("j / Down", "move selection down", theme),
        key_line("k / Up", "move selection up", theme),
        key_line("Enter", "open selected-row details", theme),
        key_line("?", "open this help", theme),
        key_line("Esc", "close a modal, or quit when no modal is open", theme),
        key_line("q", "quit", theme),
        key_line("Ctrl+C", "quit", theme),
    ];
    let help = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .block(Block::bordered().title("Help").border_style(theme.border()));
    frame.render_widget(Clear, area);
    frame.render_widget(help, area);
}

fn key_line(key: &'static str, description: &'static str, theme: Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<10}"), theme.key()),
        Span::raw(description),
    ])
}
