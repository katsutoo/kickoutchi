//! Table and JSON rendering for CLI mode.
//!
//! This layer only knows how to format projected `PortEntry` indexes. It writes
//! rows incrementally so large shared process metadata is never duplicated into
//! cell vectors or a complete output string. Total output bytes are externally
//! driven by the selected row count and writer; this module retains no complete
//! rendered output.

use std::io::Write;

use serde::ser::{SerializeSeq, Serializer};
use unicode_width::UnicodeWidthStr;

use crate::display::sanitize;
#[cfg(test)]
use crate::model::PortEntry;
use crate::model::PortEntryView;

const COLUMN_COUNT: usize = 6;
const HEADERS: [&str; COLUMN_COUNT] = ["PROTO", "ADDRESS", "PORT", "PID", "PROCESS", "STATE"];

/// Stand-in for metadata the OS wouldn't give us. A visible dash keeps the
/// columns lined up and says "unknown" out loud instead of leaving a gap.
const MISSING: &str = "-";
const PADDING: [u8; crate::observation::PROCESS_NAME_MAX_BYTES] =
    [b' '; crate::observation::PROCESS_NAME_MAX_BYTES];

/// Render entries as a plain-text table, columns padded to fit their content.
///
/// Plain spaces, no box-drawing characters: this output gets piped into
/// `grep`/`awk` all the time, so every line has to stay splittable on
/// whitespace.
#[cfg(test)]
pub(crate) fn write_table(
    writer: &mut impl Write,
    entries: &[PortEntry],
    indices: &[usize],
) -> std::io::Result<()> {
    let views = entries.iter().map(PortEntryView::from).collect::<Vec<_>>();
    write_view_table(writer, &views, indices)
}

pub(crate) fn write_view_table(
    writer: &mut impl Write,
    entries: &[PortEntryView<'_>],
    indices: &[usize],
) -> std::io::Result<()> {
    // Each column grows to its widest cell. The model's own types keep content
    // in check (addresses, ports, PIDs, short comm-style names), so there's no
    // need for a width cap — and command lines deliberately aren't columns here.
    // Widths are terminal columns, not bytes: `sanitize` keeps visible Unicode,
    // and an accented or CJK process name occupies fewer/more columns than its
    // byte length suggests.
    let mut widths: [usize; COLUMN_COUNT] = HEADERS.map(UnicodeWidthStr::width);
    for &index in indices {
        update_widths(&entries[index], &mut widths);
    }

    write_cells(writer, HEADERS, &widths)?;
    writer.write_all(b"\n")?;
    for &index in indices {
        write_entry(writer, &entries[index], &widths)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

/// Render entries as pretty-printed JSON. The shape is the serde contract on
/// `PortEntry` (pinned by tests in `model`); the pretty-printing is just for
/// human eyes and means nothing to a parser.
#[cfg(test)]
pub(crate) fn write_json(
    writer: &mut impl Write,
    entries: &[PortEntry],
    indices: &[usize],
) -> Result<(), serde_json::Error> {
    let views = entries.iter().map(PortEntryView::from).collect::<Vec<_>>();
    write_view_json(writer, &views, indices)
}

pub(crate) fn write_view_json(
    writer: &mut impl Write,
    entries: &[PortEntryView<'_>],
    indices: &[usize],
) -> Result<(), serde_json::Error> {
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut serializer = serde_json::Serializer::with_formatter(&mut *writer, formatter);
    let mut sequence = serializer.serialize_seq(Some(indices.len()))?;
    for &index in indices {
        sequence.serialize_element(&entries[index])?;
    }
    sequence.end()?;
    writer.write_all(b"\n").map_err(serde_json::Error::io)
}

fn update_widths(entry: &PortEntryView<'_>, widths: &mut [usize; COLUMN_COUNT]) {
    widths[0] = widths[0].max(entry.protocol.label().width());
    widths[1] = widths[1].max(entry.local_addr.to_string().width());
    widths[2] = widths[2].max(entry.local_port.to_string().width());
    widths[3] = widths[3].max(entry.pid.map_or(1, |pid| pid.to_string().width()));
    widths[4] = widths[4].max(entry.process_name.map_or(1, |name| sanitize(name).width()));
    widths[5] = widths[5].max(entry.state.label().width());
}

fn write_entry(
    writer: &mut impl Write,
    entry: &PortEntryView<'_>,
    widths: &[usize; COLUMN_COUNT],
) -> std::io::Result<()> {
    let address = entry.local_addr.to_string();
    let port = entry.local_port.to_string();
    let pid = entry.pid.map(|pid| pid.to_string());
    let process = entry.process_name.map(sanitize);
    write_cells(
        writer,
        [
            entry.protocol.label(),
            &address,
            &port,
            pid.as_deref().unwrap_or(MISSING),
            process.as_deref().unwrap_or(MISSING),
            entry.state.label(),
        ],
        widths,
    )
}

fn write_cells(
    writer: &mut impl Write,
    cells: [&str; COLUMN_COUNT],
    widths: &[usize; COLUMN_COUNT],
) -> std::io::Result<()> {
    for (index, (cell, width)) in cells.into_iter().zip(widths.iter()).enumerate() {
        if index > 0 {
            writer.write_all(b"  ")?;
        }
        writer.write_all(cell.as_bytes())?;
        // Pad every column but the last — trailing spaces are just invisible
        // noise for diffs and shells.
        if index < COLUMN_COUNT - 1 {
            let remaining = width.saturating_sub(cell.width());
            debug_assert!(remaining <= PADDING.len());
            writer.write_all(&PADDING[..remaining])?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use unicode_width::UnicodeWidthStr;

    use super::{write_json, write_table};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState};

    fn entry(port: u16, pid: Option<u32>, name: Option<&str>) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid,
            process_name: name.map(Into::into),
            executable_path: None,
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    fn table(entries: &[PortEntry]) -> String {
        let indices = (0..entries.len()).collect::<Vec<_>>();
        let mut bytes = Vec::new();
        write_table(&mut bytes, entries, &indices).expect("table writes");
        String::from_utf8(bytes).expect("table is UTF-8")
    }

    fn json(entries: &[PortEntry]) -> String {
        let indices = (0..entries.len()).collect::<Vec<_>>();
        let mut bytes = Vec::new();
        write_json(&mut bytes, entries, &indices).expect("JSON writes");
        String::from_utf8(bytes).expect("JSON is UTF-8")
    }

    #[test]
    fn table_renders_header_rows_and_missing_placeholders() {
        let mut hidden = entry(8080, None, None);
        hidden.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let table = table(&[entry(3000, Some(18422), Some("node")), hidden]);

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
        let table = table(&[
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
        let table = table(&[entry(3000, Some(1), Some("evil\x1b[2J\nname"))]);

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
        let table = table(&[
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
        let table = table(&[entry(80, Some(1), Some("x"))]);
        for line in table.lines() {
            assert_eq!(line, line.trim_end());
        }
    }

    #[test]
    fn json_is_an_array_even_when_empty() {
        assert_eq!(json(&[]), "[]\n");
        let rows = [entry(3000, Some(1), Some("node"))];
        let json = json(&rows);
        assert_eq!(
            json,
            format!("{}\n", serde_json::to_string_pretty(&rows).unwrap())
        );
        let value: serde_json::Value = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(value.as_array().map(Vec::len), Some(1));
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes: usize,
        largest_write: usize,
        writes: usize,
    }

    impl Write for CountingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes = self.bytes.checked_add(bytes.len()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "output byte count overflow")
            })?;
            self.largest_write = self.largest_write.max(bytes.len());
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn json_streams_many_rows_with_shared_maximum_command_metadata() {
        const ROWS: usize = 32;
        let command: Arc<str> =
            Arc::from("x".repeat(crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES));
        let rows = (0..ROWS)
            .map(|offset| {
                let mut row = entry(
                    u16::try_from(3000 + offset).expect("fixture port fits"),
                    Some(1),
                    Some("worker"),
                );
                row.command_line = Some(Arc::clone(&command));
                row
            })
            .collect::<Vec<_>>();
        assert!(rows.iter().all(|row| Arc::ptr_eq(
            row.command_line.as_ref().expect("fixture command"),
            &command
        )));
        let indices = (0..rows.len()).collect::<Vec<_>>();
        let mut writer = CountingWriter::default();

        write_json(&mut writer, &rows, &indices).expect("large rows stream");

        assert!(
            writer.bytes >= ROWS * crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
            "writer must observe all rows without retaining their output"
        );
        assert!(
            writer.largest_write <= crate::observation::PROCESS_COMMAND_LINE_MAX_BYTES,
            "a write must never materialize more than one bounded metadata field"
        );
    }

    #[test]
    fn table_writes_rows_incrementally() {
        const ROWS: usize = 1_024;
        let rows = (0..ROWS)
            .map(|offset| {
                entry(
                    u16::try_from(offset + 1).expect("fixture port fits"),
                    Some(u32::try_from(offset + 1).expect("fixture PID fits")),
                    Some("worker"),
                )
            })
            .collect::<Vec<_>>();
        let indices = (0..rows.len()).collect::<Vec<_>>();
        let mut writer = CountingWriter::default();

        write_table(&mut writer, &rows, &indices).expect("large table streams");

        assert!(writer.writes > ROWS);
        assert!(writer.largest_write < writer.bytes / ROWS);
    }
}
