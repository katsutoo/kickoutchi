//! Help modal rendering.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Wrap};

use super::theme::Theme;

pub(crate) fn render(frame: &mut Frame, area: Rect, theme: Theme) {
    let lines = vec![
        Line::styled("Kickoutchi", theme.title()),
        Line::raw(
            "Real Linux ports with refresh, search filters, sortable rows, and process context.",
        ),
        Line::raw(""),
        key_line("r", "refresh ports now", theme),
        key_line("/", "edit search/filter text", theme),
        key_line("s", "cycle sort mode", theme),
        key_line("j / Down", "move selection down", theme),
        key_line("k / Up", "move selection up", theme),
        key_line("Enter", "open selected-row details", theme),
        key_line("?", "open this help", theme),
        key_line("Esc", "clear search, close a modal, or quit", theme),
        key_line("q", "quit", theme),
        key_line("Ctrl+C", "quit", theme),
        Line::raw(""),
        Line::raw("Search mode: type to filter, Enter keeps the filter, Esc clears it."),
        Line::raw("Filters: pid:18422 port:3000 proto:udp scope:public protected:true parent:node"),
        Line::raw("Press Enter to load selected-row children, owner UID, and protected warnings."),
    ];
    let help = Paragraph::new(lines).wrap(Wrap { trim: false }).block(
        Block::bordered()
            .title("Help")
            .title_style(theme.title())
            .border_style(theme.border()),
    );
    frame.render_widget(Clear, area);
    frame.render_widget(help, area);
}

fn key_line(key: &'static str, description: &'static str, theme: Theme) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<10}"), theme.key()),
        Span::raw(description),
    ])
}
