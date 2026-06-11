//! Table and JSON rendering for CLI mode.
//!
//! This layer only formats `Vec<PortEntry>`; it knows nothing about where the
//! data came from, which is what lets real collectors replace the fake one
//! without touching output.

use crate::model::PortEntry;

const COLUMN_COUNT: usize = 6;
const HEADERS: [&str; COLUMN_COUNT] = ["PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE"];

/// Placeholder for metadata the OS withheld. A visible dash keeps columns
/// aligned and makes "unknown" explicit instead of leaving a hole.
const MISSING: &str = "-";

/// Render entries as a plain-text table with columns padded to fit content.
///
/// Plain spaces, no box drawing: CLI output gets piped to `grep`/`awk`, so
/// every line must stay machine-splittable on whitespace.
pub(crate) fn render_table(entries: &[PortEntry]) -> String {
    let rows: Vec<[String; COLUMN_COUNT]> = entries.iter().map(row_cells).collect();

    // Column widths fit the widest cell. Content is bounded by the model's
    // types (addresses, ports, PIDs, comm-style names), so no width cap is
    // needed; command lines are deliberately not table columns.
    let mut widths: [usize; COLUMN_COUNT] = HEADERS.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.len());
        }
    }

    let mut table = String::new();
    push_row(&mut table, &HEADERS.map(str::to_owned), &widths);
    for row in &rows {
        table.push('\n');
        push_row(&mut table, row, &widths);
    }
    table
}

/// Render entries as pretty-printed JSON. The shape is the serde contract on
/// `PortEntry` (pinned by tests in `model`); pretty printing is for humans
/// and changes nothing for parsers.
pub(crate) fn render_json(entries: &[PortEntry]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(entries)
}

fn row_cells(entry: &PortEntry) -> [String; COLUMN_COUNT] {
    [
        entry.protocol.label().to_owned(),
        entry.local_addr.to_string(),
        entry.local_port.to_string(),
        entry
            .pid
            .map_or_else(|| MISSING.to_owned(), |pid| pid.to_string()),
        entry
            .process_name
            .clone()
            .unwrap_or_else(|| MISSING.to_owned()),
        entry.state.label().to_owned(),
    ]
}

fn push_row(out: &mut String, cells: &[String; COLUMN_COUNT], widths: &[usize; COLUMN_COUNT]) {
    for (index, (cell, width)) in cells.iter().zip(widths.iter()).enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        out.push_str(cell);
        // Pad all but the last column; trailing spaces would be invisible
        // noise for diffs and shells.
        if index < COLUMN_COUNT - 1 {
            for _ in cell.len()..*width {
                out.push(' ');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{render_json, render_table};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: name.map(str::to_owned),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    #[test]
    fn table_renders_header_rows_and_missing_placeholders() {
        let mut hidden = entry(8080, None, None);
        hidden.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let table = render_table(&[entry(3000, Some(18422), Some("node")), hidden]);

        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("PROTO"));
        assert!(lines[1].contains("node"));
        assert!(lines[1].contains("18422"));
        // Withheld metadata renders as "-" and the row still appears.
        assert!(lines[2].contains("::"));
        assert!(lines[2].contains('-'));
    }

    #[test]
    fn table_columns_stay_aligned() {
        let table = render_table(&[
            entry(80, Some(1), Some("nginx")),
            entry(65000, Some(4_000_000), Some("a-much-longer-name")),
        ]);
        // Every row must place the STATE column at the same offset; checking
        // the column header's position against the cell positions pins the
        // padding logic without snapshotting the whole table.
        let lines: Vec<&str> = table.lines().collect();
        let state_offset = lines[0].find("STATE").expect("header has STATE");
        assert_eq!(lines[1].find("LISTEN"), Some(state_offset));
        assert_eq!(lines[2].find("LISTEN"), Some(state_offset));
    }

    #[test]
    fn table_lines_have_no_trailing_whitespace() {
        let table = render_table(&[entry(80, Some(1), Some("x"))]);
        for line in table.lines() {
            assert_eq!(line, line.trim_end());
        }
    }

    #[test]
    fn json_is_an_array_even_when_empty() {
        assert_eq!(render_json(&[]).expect("serializes"), "[]");
        let json = render_json(&[entry(3000, Some(1), Some("node"))]).expect("serializes");
        let value: serde_json::Value = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(value.as_array().map(Vec::len), Some(1));
    }
}
