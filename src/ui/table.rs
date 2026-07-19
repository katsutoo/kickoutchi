//! Drawing the main open-ports table — the roll call of everything currently
//! squatting in your swamp.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Row, Table, TableState};

use crate::app::App;
use crate::display::sanitize;
use crate::model::{PermissionStatus, PortEntryView};

use super::theme::Theme;

const MISSING: &str = "-";

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let header = Row::new([
        "PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE", "SCOPE",
    ])
    .style(theme.table_header())
    .bottom_margin(1);
    // Borders, the header, and its bottom margin consume four rows.
    let viewport_len = usize::from(area.height.saturating_sub(4));
    let (viewport_start, viewport_end) =
        visible_range(app.rows().len(), app.selected_index(), viewport_len);
    let rows = app
        .rows_range(viewport_start..viewport_end)
        .map(|entry| row(entry, theme));
    let widths = [
        Constraint::Length(6),
        Constraint::Min(13),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Min(12),
        Constraint::Length(8),
        Constraint::Length(9),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::bordered()
                .title("Open Ports")
                .title_style(theme.title())
                .border_style(theme.border()),
        )
        .row_highlight_style(theme.selected())
        .highlight_symbol(">> ");
    let mut state = TableState::default();
    state.select(app.selected_index().and_then(|index| {
        (viewport_start..viewport_end)
            .contains(&index)
            .then_some(index - viewport_start)
    }));
    frame.render_stateful_widget(table, area, &mut state);
}

fn visible_range(total: usize, selected: Option<usize>, capacity: usize) -> (usize, usize) {
    if capacity == 0 || total == 0 {
        return (0, 0);
    }
    let selected = selected.unwrap_or(0).min(total - 1);
    let start = selected
        .saturating_add(1)
        .saturating_sub(capacity)
        .min(total.saturating_sub(capacity));
    (start, start.saturating_add(capacity).min(total))
}

fn row(entry: PortEntryView<'_>, theme: Theme) -> Row<'static> {
    let cells = [
        entry.protocol.label().to_owned(),
        entry.local_addr.to_string(),
        entry.local_port.to_string(),
        pid_text(entry),
        process_text(entry),
        entry.state.label().to_owned(),
        entry.scope_label().to_owned(),
    ];
    let mut row = Row::new(cells);

    if entry.protected {
        row = row.style(theme.protected());
    } else if entry.permission == PermissionStatus::Partial {
        row = row.style(theme.warning());
    }

    row
}

fn pid_text(entry: PortEntryView<'_>) -> String {
    entry
        .pid
        .map_or_else(|| MISSING.to_owned(), |pid| pid.to_string())
}

fn process_text(entry: PortEntryView<'_>) -> String {
    entry
        .process_name
        .map_or_else(|| MISSING.to_owned(), sanitize)
}

#[cfg(test)]
mod tests {
    use super::visible_range;

    #[test]
    fn viewport_bounds_rendering_around_nonzero_selection() {
        assert_eq!(visible_range(10_000, Some(5_000), 20), (4_981, 5_001));
        assert_eq!(visible_range(10_000, Some(9_999), 20), (9_980, 10_000));
        assert_eq!(visible_range(10_000, Some(5_000), 0), (0, 0));
    }
}
