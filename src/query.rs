//! The shared filter-and-sort engine behind both the CLI and TUI views.
//!
//! The collector decides which rows exist; this module only picks which of those
//! confirmed rows are visible for a given query, and in what order. It never
//! conjures a row out of thin air.

use thiserror::Error;

use crate::model::{BindScope, PortEntry, Protocol, SortMode, sort_entries};

/// Longest search text we'll take from the TUI or CLI.
///
/// In the TUI, filtering runs on every keypress, so a small fixed cap keeps that
/// work bounded — and it's still way longer than any query you'd actually type.
pub(crate) const FILTER_TEXT_MAX_BYTES: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct QueryOptions<'a> {
    pub(crate) port: Option<u16>,
    pub(crate) process: Option<&'a str>,
    pub(crate) filter_text: &'a str,
    pub(crate) sort_mode: SortMode,
    pub(crate) hide_system_processes: bool,
}

#[derive(Debug)]
pub(crate) struct QueryResult {
    pub(crate) entries: Vec<PortEntry>,
    pub(crate) explicit_filter_active: bool,
    pub(crate) hidden_system_process_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum QueryError {
    #[error("filter text is {actual} bytes, maximum is {max}")]
    TooLong { actual: usize, max: usize },
    #[error("invalid {field} filter value {value:?}: expected {expected}")]
    InvalidValue {
        field: &'static str,
        value: String,
        expected: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterTerm {
    Plain(String),
    Pid(u32),
    Port(u16),
    Protocol(Protocol),
    Scope(BindScope),
    Protected(bool),
    Parent(String),
}

pub(crate) fn query_entries(
    entries: &[PortEntry],
    options: QueryOptions<'_>,
) -> Result<QueryResult, QueryError> {
    let terms = parse_filter_text(options.filter_text)?;
    let process_needle = options.process.map(normalized);
    let explicit_filter_active =
        options.port.is_some() || options.process.is_some() || !terms.is_empty();

    let mut hidden_system_process_count = 0;
    let mut filtered: Vec<PortEntry> = entries
        .iter()
        .filter(|entry| {
            if options.hide_system_processes && entry.is_system_process() {
                hidden_system_process_count += 1;
                false
            } else {
                true
            }
        })
        .filter(|entry| options.port.is_none_or(|port| entry.local_port == port))
        .filter(|entry| {
            process_needle
                .as_deref()
                .is_none_or(|process| entry.matches_process_normalized(process))
        })
        .filter(|entry| terms.iter().all(|term| term_matches(entry, term)))
        .cloned()
        .collect();

    sort_entries(&mut filtered, options.sort_mode);

    Ok(QueryResult {
        entries: filtered,
        explicit_filter_active,
        hidden_system_process_count,
    })
}

fn parse_filter_text(text: &str) -> Result<Vec<FilterTerm>, QueryError> {
    if text.len() > FILTER_TEXT_MAX_BYTES {
        return Err(QueryError::TooLong {
            actual: text.len(),
            max: FILTER_TEXT_MAX_BYTES,
        });
    }

    text.split_whitespace().map(parse_token).collect()
}

fn parse_token(token: &str) -> Result<FilterTerm, QueryError> {
    let Some((field, value)) = token.split_once(':') else {
        return Ok(FilterTerm::Plain(normalized(token)));
    };

    match field {
        "pid" => parse_pid(value),
        "port" => parse_port(value),
        "proto" => parse_protocol(value),
        "scope" => parse_scope(value),
        "protected" => parse_protected(value),
        "parent" => parse_parent(value),
        _ => Ok(FilterTerm::Plain(normalized(token))),
    }
}

fn parse_pid(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u32>()
        .map(FilterTerm::Pid)
        .map_err(|_| invalid_value("pid", value, "a non-negative integer PID"))
}

fn parse_port(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u16>()
        .map(FilterTerm::Port)
        .map_err(|_| invalid_value("port", value, "a TCP/UDP port from 0 to 65535"))
}

fn parse_protocol(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "tcp" => Ok(FilterTerm::Protocol(Protocol::Tcp)),
        "udp" => Ok(FilterTerm::Protocol(Protocol::Udp)),
        _ => Err(invalid_value("proto", value, "tcp or udp")),
    }
}

fn parse_scope(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "public" => Ok(FilterTerm::Scope(BindScope::Public)),
        "local" => Ok(FilterTerm::Scope(BindScope::Local)),
        "loopback" => Ok(FilterTerm::Scope(BindScope::Loopback)),
        _ => Err(invalid_value("scope", value, "public, local, or loopback")),
    }
}

fn parse_protected(value: &str) -> Result<FilterTerm, QueryError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "true" => Ok(FilterTerm::Protected(true)),
        "false" => Ok(FilterTerm::Protected(false)),
        _ => Err(invalid_value("protected", value, "true or false")),
    }
}

fn parse_parent(value: &str) -> Result<FilterTerm, QueryError> {
    if value.is_empty() {
        return Err(invalid_value(
            "parent",
            value,
            "a parent process name or PID",
        ));
    }
    Ok(FilterTerm::Parent(normalized(value)))
}

fn normalized(value: &str) -> String {
    value.to_lowercase()
}

fn invalid_value(field: &'static str, value: &str, expected: &'static str) -> QueryError {
    QueryError::InvalidValue {
        field,
        value: value.to_owned(),
        expected,
    }
}

fn term_matches(entry: &PortEntry, term: &FilterTerm) -> bool {
    match term {
        FilterTerm::Plain(needle) => plain_matches(entry, needle),
        FilterTerm::Pid(pid) => entry.pid == Some(*pid),
        FilterTerm::Port(port) => entry.local_port == *port,
        FilterTerm::Protocol(protocol) => entry.protocol == *protocol,
        FilterTerm::Scope(scope) => entry.scope() == *scope,
        FilterTerm::Protected(protected) => entry.protected == *protected,
        FilterTerm::Parent(needle) => parent_matches(entry, needle),
    }
}

fn plain_matches(entry: &PortEntry, needle_lower: &str) -> bool {
    contains(&entry.local_port.to_string(), needle_lower)
        || entry
            .pid
            .is_some_and(|pid| contains(&pid.to_string(), needle_lower))
        || contains(&entry.local_addr.to_string(), needle_lower)
        || socket_text_matches(entry, needle_lower)
        || contains(entry.protocol.label(), needle_lower)
        || contains(entry.state.label(), needle_lower)
        || contains(entry.scope_label(), needle_lower)
        || entry
            .process_name
            .as_deref()
            .is_some_and(|value| contains(value, needle_lower))
        || entry
            .executable_path
            .as_ref()
            .is_some_and(|path| contains(&path.display().to_string(), needle_lower))
        || entry
            .command_line
            .as_deref()
            .is_some_and(|value| contains(value, needle_lower))
        || parent_matches(entry, needle_lower)
}

fn socket_text_matches(entry: &PortEntry, needle_lower: &str) -> bool {
    if !needle_lower.contains(':') {
        return false;
    }

    contains(
        &format!("{}:{}", entry.local_addr, entry.local_port),
        needle_lower,
    ) || contains(
        &format!("[{}]:{}", entry.local_addr, entry.local_port),
        needle_lower,
    )
}

fn parent_matches(entry: &PortEntry, needle_lower: &str) -> bool {
    entry
        .parent_pid
        .is_some_and(|pid| contains(&pid.to_string(), needle_lower))
        || entry
            .parent_process_name
            .as_deref()
            .is_some_and(|value| contains(value, needle_lower))
}

fn contains(haystack: &str, needle_lower: &str) -> bool {
    haystack.to_lowercase().contains(needle_lower)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    use super::{FILTER_TEXT_MAX_BYTES, QueryError, QueryOptions, query_entries};
    use crate::model::{PermissionStatus, Platform, PortEntry, Protocol, SocketState, SortMode};

    fn entry(port: u16, name: &str) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: Some(name.to_owned()),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{name}"))),
            command_line: Some(format!("{name} --port {port}")),
            parent_pid: Some(10),
            parent_process_name: Some("agent".to_owned()),
            child_pids: Vec::new(),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
        }
    }

    fn query(filter_text: &str) -> QueryOptions<'_> {
        QueryOptions {
            port: None,
            process: None,
            filter_text,
            sort_mode: SortMode::Port,
            hide_system_processes: false,
        }
    }

    fn matching_ports(rows: &[PortEntry], filter_text: &str) -> Vec<u16> {
        query_entries(rows, query(filter_text))
            .expect("query is valid")
            .entries
            .iter()
            .map(|entry| entry.local_port)
            .collect()
    }

    #[test]
    fn plain_search_matches_user_visible_fields() {
        let mut node = entry(3000, "node");
        node.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        node.parent_process_name = Some("cursor-agent".to_owned());
        let mut vite = entry(5173, "vite");
        vite.local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let rows = vec![node, vite];

        assert_eq!(matching_ports(&rows, "3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "127.0.0.1"), vec![3000]);
        assert_eq!(matching_ports(&rows, "127.0.0.1:3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "NODE"), vec![3000]);
        assert_eq!(matching_ports(&rows, "/usr/bin/vite"), vec![5173]);
        assert_eq!(matching_ports(&rows, "--port 3000"), vec![3000]);
        assert_eq!(matching_ports(&rows, "cursor"), vec![3000]);
        assert_eq!(matching_ports(&rows, "tcp"), vec![3000, 5173]);
    }

    #[test]
    fn process_filter_option_matches_case_insensitive_substring() {
        let mut hidden = entry(8080, "hidden");
        hidden.process_name = None;
        let rows = vec![entry(3000, "Node"), entry(5173, "vite"), hidden];
        let options = QueryOptions {
            process: Some("OD"),
            ..query("")
        };

        let result = query_entries(&rows, options).expect("query is valid");
        let ports: Vec<u16> = result
            .entries
            .iter()
            .map(|entry| entry.local_port)
            .collect();

        assert_eq!(ports, vec![3000]);
        assert!(result.explicit_filter_active);
    }

    #[test]
    fn structured_filters_match_exact_fields() {
        let mut protected = entry(5432, "postgres");
        protected.protected = true;
        protected.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

        let mut udp = entry(5353, "avahi-daemon");
        udp.protocol = Protocol::Udp;
        udp.state = SocketState::Bound;
        udp.pid = Some(902);
        udp.parent_pid = Some(1);
        udp.parent_process_name = Some("systemd".to_owned());

        let rows = vec![entry(3000, "node"), protected, udp];

        assert_eq!(matching_ports(&rows, "pid:902"), vec![5353]);
        assert_eq!(matching_ports(&rows, "port:5432"), vec![5432]);
        assert_eq!(matching_ports(&rows, "proto:udp"), vec![5353]);
        assert_eq!(matching_ports(&rows, "scope:public"), vec![5432]);
        assert_eq!(matching_ports(&rows, "protected:true"), vec![5432]);
        assert_eq!(matching_ports(&rows, "parent:systemd"), vec![5353]);
    }

    #[test]
    fn structured_filters_reject_bad_values() {
        let rows = vec![entry(3000, "node")];

        let error = query_entries(&rows, query("port:not-a-port")).expect_err("invalid port");
        assert!(matches!(
            error,
            QueryError::InvalidValue { field: "port", .. }
        ));

        let error = query_entries(&rows, query("protected:maybe")).expect_err("invalid bool");
        assert!(matches!(
            error,
            QueryError::InvalidValue {
                field: "protected",
                ..
            }
        ));
    }

    #[test]
    fn filter_text_over_the_byte_cap_is_rejected() {
        // The TUI already caps input in `append_search_char`, so the only way to
        // actually hit this bound is via CLI `--filter`. The cap lives here, so
        // the test pins it here too; the CLI turns the error into exit 2.
        let rows = vec![entry(3000, "node")];
        let too_long = "a".repeat(FILTER_TEXT_MAX_BYTES + 1);

        let error =
            query_entries(&rows, query(&too_long)).expect_err("over-cap filter is rejected");

        assert_eq!(
            error,
            QueryError::TooLong {
                actual: FILTER_TEXT_MAX_BYTES + 1,
                max: FILTER_TEXT_MAX_BYTES,
            }
        );
    }

    #[test]
    fn hide_system_processes_uses_conservative_classification() {
        let mut service = entry(53, "systemd-resolved");
        service.parent_pid = Some(1);
        let rows = vec![entry(3000, "node"), service];
        let options = QueryOptions {
            hide_system_processes: true,
            ..query("")
        };

        let result = query_entries(&rows, options).expect("query is valid");

        assert_eq!(result.entries.len(), 1);
        assert_eq!(result.entries[0].process_name.as_deref(), Some("node"));
        assert!(!result.explicit_filter_active);
        assert_eq!(result.hidden_system_process_count, 1);
    }

    #[test]
    fn query_sort_mode_is_shared_with_model_sorting() {
        let mut public = entry(4000, "public");
        public.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut local = entry(2000, "local");
        local.local_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let mut loopback = entry(1000, "loopback");
        loopback.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let options = QueryOptions {
            sort_mode: SortMode::Scope,
            ..query("")
        };

        let result = query_entries(&[loopback, local, public], options).expect("valid query");
        let ports: Vec<u16> = result
            .entries
            .iter()
            .map(|entry| entry.local_port)
            .collect();

        assert_eq!(ports, vec![4000, 2000, 1000]);
    }
}
