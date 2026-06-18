//! Drawing the main open-ports table — the roll call of everything currently
//! squatting in your swamp.

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::widgets::{Block, Row, Table, TableState};

use crate::app::App;
use crate::model::{PermissionStatus, PortEntry};

use super::theme::Theme;

const MISSING: &str = "-";

pub(crate) fn render(frame: &mut Frame, area: Rect, app: &App, theme: Theme) {
    let header = Row::new([
        "PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE", "SCOPE",
    ])
    .style(theme.table_header())
    .bottom_margin(1);
    let rows = app.rows().iter().map(|entry| row(entry, theme));
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
    state.select(app.selected_index());
    frame.render_stateful_widget(table, area, &mut state);
}

fn row(entry: &PortEntry, theme: Theme) -> Row<'static> {
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

fn pid_text(entry: &PortEntry) -> String {
    entry
        .pid
        .map_or_else(|| MISSING.to_owned(), |pid| pid.to_string())
}

fn process_text(entry: &PortEntry) -> String {
    entry
        .process_name
        .clone()
        .unwrap_or_else(|| MISSING.to_owned())
}
