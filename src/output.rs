//! Table and JSON rendering for CLI mode.
//!
//! This layer only knows how to format a `Vec<PortEntry>` — it has no idea where
//! the data came from. That's exactly what lets real collectors swap in for the
//! fake one without anyone touching this file.

use unicode_width::UnicodeWidthStr;

use crate::display::sanitize;
use crate::model::PortEntry;

const COLUMN_COUNT: usize = 6;
const HEADERS: [&str; COLUMN_COUNT] = ["PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE"];

/// Stand-in for metadata the OS wouldn't give us. A visible dash keeps the
/// columns lined up and says "unknown" out loud instead of leaving a gap.
const MISSING: &str = "-";

/// Render entries as a plain-text table, columns padded to fit their content.
///
/// Plain spaces, no box-drawing characters: this output gets piped into
/// `grep`/`awk` all the time, so every line has to stay splittable on
/// whitespace.
pub(crate) fn render_table(entries: &[PortEntry]) -> String {
    let rows: Vec<[String; COLUMN_COUNT]> = entries.iter().map(row_cells).collect();

    // Each column grows to its widest cell. The model's own types keep content
    // in check (addresses, ports, PIDs, short comm-style names), so there's no
    // need for a width cap — and command lines deliberately aren't columns here.
    // Widths are terminal columns, not bytes: `sanitize` keeps visible Unicode,
    // and an accented or CJK process name occupies fewer/more columns than its
    // byte length suggests.
    let mut widths: [usize; COLUMN_COUNT] = HEADERS.map(UnicodeWidthStr::width);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row.iter()) {
            *width = (*width).max(cell.as_str().width());
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
/// `PortEntry` (pinned by tests in `model`); the pretty-printing is just for
/// human eyes and means nothing to a parser.
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
            .as_deref()
            .map_or_else(|| MISSING.to_owned(), sanitize),
        entry.state.label().to_owned(),
    ]
}

fn push_row(out: &mut String, cells: &[String; COLUMN_COUNT], widths: &[usize; COLUMN_COUNT]) {
    for (index, (cell, width)) in cells.iter().zip(widths.iter()).enumerate() {
        if index > 0 {
            out.push_str("  ");
        }
        out.push_str(cell);
        // Pad every column but the last — trailing spaces are just invisible
        // noise for diffs and shells.
        if index < COLUMN_COUNT - 1 {
            for _ in cell.as_str().width()..*width {
                out.push(' ');
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use unicode_width::UnicodeWidthStr;

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
        // Every row must put the STATE column at the same offset; comparing the
        // header's position against the cells pins the padding logic without
        // snapshotting the whole table.
        let lines: Vec<&str> = table.lines().collect();
        let state_offset = lines[0].find("STATE").expect("header has STATE");
        assert_eq!(lines[1].find("LISTEN"), Some(state_offset));
        assert_eq!(lines[2].find("LISTEN"), Some(state_offset));
    }

    #[test]
    fn table_sanitizes_hostile_process_names() {
        // `list` output lands on real terminals, and a process names itself:
        // the escape must be stripped by `render_table`'s own wiring, not
        // just be strippable by `sanitize` in isolation. Deleting the
        // `sanitize` call in `row_cells` must fail this test.
        let table = render_table(&[entry(3000, Some(1), Some("evil\x1b[2J\nname"))]);

        assert!(!table.contains('\x1b'), "{table}");
        let lines: Vec<&str> = table.lines().collect();
        // Header plus exactly one row: the embedded newline must not split
        // the entry across lines and break `awk`-style consumers.
        assert_eq!(lines.len(), 2, "{table}");
        assert!(lines[1].contains("evil"), "{table}");
    }

    #[test]
    fn table_columns_stay_aligned_for_wide_unicode_names() {
        // `sanitize` keeps visible Unicode, so widths must be terminal
        // columns, not bytes: "数据库" is 9 bytes but 6 columns, and
        // byte-based padding would shift every later column in that row.
        let table = render_table(&[
            entry(80, Some(1), Some("nginx")),
            entry(5432, Some(2), Some("数据库")),
            entry(3000, Some(3), Some("héllo")),
        ]);

        let lines: Vec<&str> = table.lines().collect();
        // The header is pure ASCII, so its byte offset is its column offset.
        let header_state_columns = lines[0].find("STATE").expect("header has STATE");
        for line in &lines[1..] {
            let listen_start = line.find("LISTEN").expect("row has LISTEN");
            assert_eq!(
                line[..listen_start].width(),
                header_state_columns,
                "STATE column drifted: {table}",
            );
        }
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
