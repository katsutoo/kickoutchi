//! Startup update notice, kept separate from the one-row status surface.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use crate::display::sanitize;

use super::theme::Theme;

pub(crate) fn render(frame: &mut Frame, area: Rect, message: &str, theme: Theme) {
    let lines = vec![
        Line::styled("Update available", theme.title()),
        Line::raw(""),
        Line::raw(sanitize(message)),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Any key", theme.key()),
            Span::raw(" dismisses this notice."),
        ]),
    ];
    let notice = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Kickoutchi Update")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(notice, area);
}
