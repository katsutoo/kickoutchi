//! The `list` command: filter and sort the collected port table, then print
//! it as the human-facing table or the stable JSON contract.

use crate::config::Config;
use crate::diagnostic;
use crate::model::PortEntry;
use crate::output;
use crate::query::{self, QueryOptions};

use super::{ExitReason, ListArgs, maybe_print_no_match_diagnostic, write_stdout_line};

pub(super) fn run_list(args: &ListArgs, config: &Config, entries: &[PortEntry]) -> ExitReason {
    let sort_mode = args.sort.unwrap_or(config.default_sort);
    let diagnostic_port = diagnostic::requested_diagnostic_port(
        args.port,
        args.filter.as_deref().unwrap_or_default(),
    );
    let result = match query::query_entries(
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
    let visible_entries = result.entries;

    if args.json {
        match output::render_json(&visible_entries) {
            Ok(json) => {
                if let Some(reason) = write_stdout_line(&json) {
                    return reason;
                }
            }
            Err(error) => {
                eprintln!("error: rendering JSON failed: {error}");
                return ExitReason::Failure;
            }
        }
    } else if visible_entries.is_empty() {
        let suffix = if result.explicit_filter_active {
            " match the filter"
        } else if result.hidden_system_process_count > 0 {
            " visible"
        } else {
            ""
        };
        if let Some(reason) = write_stdout_line(&format!("no open ports{suffix}")) {
            return reason;
        }
        maybe_print_no_match_diagnostic(diagnostic_port, entries);
    } else if let Some(reason) = write_stdout_line(&output::render_table(&visible_entries)) {
        return reason;
    }

    // An empty *filtered* result exits 3, so scripts can probe occupancy
    // (`kickoutchi list --port 3000 && echo busy`). An empty *unfiltered* list
    // just means a quiet machine — that's a success, not a failure.
    if result.explicit_filter_active && visible_entries.is_empty() {
        return ExitReason::NoMatch;
    }
    ExitReason::Success
}
