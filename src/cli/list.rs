//! The `list` command: filter and sort the collected port table, then print
//! it as the human-facing table or the stable JSON contract.

use std::io::{self, ErrorKind, Write};

use crate::config::Config;
use crate::diagnostic;
use crate::model::PortEntryView;
use crate::observation::NetworkSnapshot;
use crate::output;
use crate::query::{self, QueryOptions};

use super::{ExitReason, ListArgs};

pub(super) fn run_list_snapshot(
    args: &ListArgs,
    config: &Config,
    snapshot: &NetworkSnapshot,
) -> ExitReason {
    run_list_snapshot_with_writer(args, config, snapshot, &mut io::stdout().lock())
}

fn run_list_snapshot_with_writer(
    args: &ListArgs,
    config: &Config,
    snapshot: &NetworkSnapshot,
    writer: &mut impl Write,
) -> ExitReason {
    let descriptors = match snapshot.port_entry_descriptors(&config.protected_processes) {
        Ok(descriptors) => descriptors,
        Err(error) => {
            eprintln!("error: projecting collected ports failed: {error}");
            return ExitReason::Failure;
        }
    };
    let views = descriptors
        .iter()
        .map(|descriptor| snapshot.port_entry_view(descriptor))
        .collect::<Vec<_>>();
    run_list_views_with_writer(args, config, &views, writer)
}

fn run_list_views_with_writer(
    args: &ListArgs,
    config: &Config,
    entries: &[PortEntryView<'_>],
    writer: &mut impl Write,
) -> ExitReason {
    let sort_mode = args.sort.unwrap_or(config.default_sort);
    let diagnostic_port = diagnostic::requested_diagnostic_port(
        args.port,
        args.filter.as_deref().unwrap_or_default(),
    );
    let result = match query::query_view_indices(
        entries,
        QueryOptions {
            port: args.port,
            process: args.process.as_deref(),
            filter_text: args.filter.as_deref().unwrap_or_default(),
            sort_mode,
            hide_system_processes: config.hide_system_processes,
        },
    ) {
        Ok(result) => result,
        Err(error) => {
            eprintln!("error: invalid filter: {error}");
            return ExitReason::InvalidArguments;
        }
    };
    let visible_indices = result.indices;

    if args.json {
        match output::write_view_json(writer, entries, &visible_indices) {
            Ok(()) => {}
            Err(error) if error.io_error_kind() == Some(ErrorKind::BrokenPipe) => {
                return ExitReason::Success;
            }
            Err(error) => {
                eprintln!("error: rendering JSON failed: {error}");
                return ExitReason::Failure;
            }
        }
    } else if visible_indices.is_empty() {
        let suffix = if result.explicit_filter_active {
            " match the filter"
        } else if result.hidden_system_process_count > 0 {
            " visible"
        } else {
            ""
        };
        if let Err(error) = writeln!(writer, "no open ports{suffix}") {
            return output_error_reason(&error);
        }
        maybe_print_no_match_diagnostic_views(diagnostic_port, entries);
    } else if let Err(error) = output::write_view_table(writer, entries, &visible_indices) {
        return output_error_reason(&error);
    }

    if let Err(error) = writer.flush() {
        return output_error_reason(&error);
    }

    // An empty *filtered* result exits 3, so scripts can probe occupancy
    // (`kickoutchi list --port 3000 && echo busy`). An empty *unfiltered* list
    // just means a quiet machine — that's a success, not a failure.
    if result.explicit_filter_active && visible_indices.is_empty() {
        return ExitReason::NoMatch;
    }
    ExitReason::Success
}

fn maybe_print_no_match_diagnostic_views(
    diagnostic_port: Option<u16>,
    entries: &[PortEntryView<'_>],
) {
    let Some(port) = diagnostic_port else { return };
    if entries.iter().any(|entry| entry.local_port == port) {
        return;
    }
    let hints = crate::platform::collect_related_process_hints(port);
    if let Some(message) = diagnostic::diagnostic_message(port, &hints) {
        eprint!("{message}");
    }
}

fn output_error_reason(error: &io::Error) -> ExitReason {
    if error.kind() == ErrorKind::BrokenPipe {
        ExitReason::Success
    } else {
        eprintln!("error: writing output failed: {error}");
        ExitReason::Failure
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use super::run_list_snapshot_with_writer;
    use crate::cli::{ExitReason, ListArgs};
    use crate::config::Config;
    use crate::model::SortMode;

    fn args(json: bool) -> ListArgs {
        ListArgs {
            port: None,
            process: None,
            filter: None,
            sort: Some(SortMode::Port),
            json,
        }
    }

    fn run_list_with_writer(
        args: &ListArgs,
        config: &Config,
        rows: &[crate::model::PortEntry],
        writer: &mut impl Write,
    ) -> ExitReason {
        let snapshot = crate::observation::snapshot_from_test_rows(rows.to_vec());
        run_list_snapshot_with_writer(args, config, &snapshot, writer)
    }

    #[test]
    fn list_streams_sorted_source_indexes_in_legacy_json_shape() {
        let rows = [
            crate::cli::test_support::entry(5000),
            crate::cli::test_support::entry(3000),
        ];
        let mut output = Vec::new();

        let reason = run_list_with_writer(&args(true), &Config::default(), &rows, &mut output);
        let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON output");
        let ports = value
            .as_array()
            .expect("top-level array")
            .iter()
            .map(|row| row["local_port"].as_u64().expect("numeric port"))
            .collect::<Vec<_>>();

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(ports, [3000, 5000]);
        assert!(output.ends_with(b"\n"));
    }

    struct FailingWriter {
        bytes_before_failure: usize,
        write_error: Option<io::ErrorKind>,
        flush_error: Option<io::ErrorKind>,
    }

    impl Write for FailingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.bytes_before_failure == 0 {
                return self.write_error.map_or(Ok(bytes.len()), |kind| {
                    Err(io::Error::new(kind, "injected write failure"))
                });
            }
            let written = bytes.len().min(self.bytes_before_failure);
            self.bytes_before_failure -= written;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_error.map_or(Ok(()), |kind| {
                Err(io::Error::new(kind, "injected flush failure"))
            })
        }
    }

    #[test]
    fn writer_error_matrix_covers_formats_stages_and_empty_outputs() {
        let populated = [crate::cli::test_support::entry(3000)];
        for json in [false, true] {
            for rows in [&[][..], &populated[..]] {
                for flush_only in [false, true] {
                    for (kind, expected) in [
                        (io::ErrorKind::BrokenPipe, ExitReason::Success),
                        (io::ErrorKind::Other, ExitReason::Failure),
                    ] {
                        let mut writer = FailingWriter {
                            bytes_before_failure: if flush_only { 4_096 } else { 1 },
                            write_error: (!flush_only).then_some(kind),
                            flush_error: flush_only.then_some(kind),
                        };

                        assert_eq!(
                            run_list_with_writer(
                                &args(json),
                                &Config::default(),
                                rows,
                                &mut writer,
                            ),
                            expected,
                            "json={json} empty={} flush_only={flush_only} kind={kind:?}",
                            rows.is_empty(),
                        );
                    }
                }
            }
        }
    }
}
