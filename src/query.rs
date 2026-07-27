//! The shared filter-and-sort engine behind both the CLI and TUI views.
//!
//! The collector decides which rows exist; this module only picks which of those
//! confirmed rows are visible for a given query, and in what order. It never
//! conjures a row out of thin air.

use std::collections::HashMap;
use std::fmt::{self, Write as _};
use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU32};

use thiserror::Error;

use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, normalize_ip_address};
use crate::model::{BindScope, PortEntryView, Protocol, SortMode};
use crate::observation::Ipv6Scope;

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
    pub(crate) capabilities: QueryCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QueryCapabilities {
    state: bool,
}

impl QueryCapabilities {
    pub(crate) const LIST: Self = Self { state: false };
    pub(crate) const WATCH: Self = Self { state: true };
}

#[derive(Debug)]
pub(crate) struct QueryIndexResult {
    pub(crate) indices: Vec<usize>,
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
    #[error("filter field {field:?} is not supported by this command")]
    UnsupportedField { field: &'static str },
    #[error("scope_id filter cannot be combined with an IPv4 address or family")]
    ScopeRequiresIpv6,
    #[error("these filter capabilities require full socket-state entries")]
    FullStateEntriesRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FilterTerm {
    Plain(String),
    Pid(u32),
    Port(u16),
    Protocol(Protocol),
    Scope(BindScope),
    Protected(bool),
    Parent(String),
    Label(String),
    Address(IpAddr),
    ScopeId(NonZeroU32),
    Family(AddressFamily),
    State(StateFilter),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateFilter {
    Listen,
    Bound,
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    NewSynReceived,
    Unknown,
}

pub(crate) fn query_view_indices(
    entries: &[PortEntryView<'_>],
    options: QueryOptions<'_>,
) -> Result<QueryIndexResult, QueryError> {
    if options.capabilities != QueryCapabilities::LIST {
        return Err(QueryError::FullStateEntriesRequired);
    }
    if options.port == Some(0) {
        return Err(invalid_value("port", "0", "a TCP/UDP port from 1 to 65535"));
    }
    if options.process == Some("") {
        return Err(invalid_value(
            "process",
            "",
            "a nonempty process name substring",
        ));
    }
    let terms = parse_filter_text(options.filter_text, options.capabilities)?;
    let process_needle = options.process.map(normalized);
    let explicit_filter_active =
        options.port.is_some() || options.process.is_some() || !terms.is_empty();

    let mut hidden_system_process_count = 0;
    let mut metadata = MetadataMatchCache::default();
    let mut indices = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        if options.hide_system_processes && entry.is_system_process() {
            hidden_system_process_count += 1;
            continue;
        }
        if options.port.is_some_and(|port| entry.local_port != port) {
            continue;
        }
        indices.push(index);
    }

    if let Some(needle) = process_needle.as_deref() {
        metadata.clear_matches();
        indices.retain(|&index| {
            entries[index]
                .process_name
                .is_some_and(|name| metadata.contains(name, needle))
        });
    }
    for term in &terms {
        metadata.clear_matches();
        indices.retain(|&index| term_matches(&entries[index], term, &mut metadata));
    }

    let normalized_keys = normalized_sort_keys(
        entries,
        &indices,
        options.sort_mode,
        &mut metadata.normalization,
    );
    indices.sort_by(|left, right| {
        compare_views(
            entries[*left],
            entries[*right],
            options.sort_mode,
            normalized_keys[*left].map(|key| metadata.normalization.values[key].as_str()),
            normalized_keys[*right].map(|key| metadata.normalization.values[key].as_str()),
        )
    });

    Ok(QueryIndexResult {
        indices,
        explicit_filter_active,
        hidden_system_process_count,
    })
}

fn normalized_sort_keys<'a>(
    entries: &[PortEntryView<'a>],
    visible_indices: &[usize],
    mode: SortMode,
    normalization: &mut NormalizationCache<'a>,
) -> Vec<Option<usize>> {
    let mut keys = vec![None; entries.len()];
    for &index in visible_indices {
        let value = match mode {
            SortMode::Process => entries[index].process_name,
            SortMode::Parent => entries[index].parent_process_name,
            _ => None,
        };
        let Some(value) = value else { continue };
        keys[index] = Some(normalization.key(value));
    }
    keys
}

fn compare_views(
    a: PortEntryView<'_>,
    b: PortEntryView<'_>,
    mode: SortMode,
    normalized_a: Option<&str>,
    normalized_b: Option<&str>,
) -> std::cmp::Ordering {
    let key = match mode {
        SortMode::Port => std::cmp::Ordering::Equal,
        SortMode::Pid => (a.pid.is_none(), a.pid).cmp(&(b.pid.is_none(), b.pid)),
        SortMode::Protocol => a.protocol.cmp(&b.protocol),
        SortMode::Process => {
            (normalized_a.is_none(), normalized_a).cmp(&(normalized_b.is_none(), normalized_b))
        }
        SortMode::Parent => (
            normalized_a.is_none(),
            normalized_a,
            a.parent_pid.is_none(),
            a.parent_pid,
        )
            .cmp(&(
                normalized_b.is_none(),
                normalized_b,
                b.parent_pid.is_none(),
                b.parent_pid,
            )),
        SortMode::Scope => a.scope().cmp(&b.scope()),
    };
    key.then_with(|| {
        (a.local_port, a.protocol, a.local_addr, a.pid).cmp(&(
            b.local_port,
            b.protocol,
            b.local_addr,
            b.pid,
        ))
    })
}

pub(crate) fn validate_filter_text(
    text: &str,
    capabilities: QueryCapabilities,
) -> Result<(), QueryError> {
    parse_filter_text(text, capabilities).map(|_| ())
}

pub(crate) fn parse_filter_text(
    text: &str,
    capabilities: QueryCapabilities,
) -> Result<Vec<FilterTerm>, QueryError> {
    if text.len() > FILTER_TEXT_MAX_BYTES {
        return Err(QueryError::TooLong {
            actual: text.len(),
            max: FILTER_TEXT_MAX_BYTES,
        });
    }

    let terms = text
        .split_whitespace()
        .map(|token| parse_token(token, capabilities))
        .collect::<Result<Vec<_>, _>>()?;
    validate_term_combinations(&terms)?;
    Ok(terms)
}

fn parse_token(token: &str, capabilities: QueryCapabilities) -> Result<FilterTerm, QueryError> {
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
        "label" => parse_nonempty_text("label", value).map(FilterTerm::Label),
        "address" => parse_address(value),
        "scope_id" => parse_scope_id(value),
        "family" => parse_family(value),
        "state" if capabilities.state => parse_state(value),
        "state" => Err(QueryError::UnsupportedField { field: "state" }),
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
        .ok()
        .and_then(NonZeroU16::new)
        .map(|port| FilterTerm::Port(port.get()))
        .ok_or_else(|| invalid_value("port", value, "a TCP/UDP port from 1 to 65535"))
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

fn parse_nonempty_text(field: &'static str, value: &str) -> Result<String, QueryError> {
    if value.is_empty() {
        return Err(invalid_value(field, value, "a nonempty value"));
    }
    Ok(normalized(value))
}

fn parse_address(value: &str) -> Result<FilterTerm, QueryError> {
    if value.is_empty() || value.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err(invalid_value(
            "address",
            value,
            "a literal IP address of at most 64 bytes",
        ));
    }
    value
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map(FilterTerm::Address)
        .map_err(|_| invalid_value("address", value, "a literal IPv4 or IPv6 address"))
}

fn parse_scope_id(value: &str) -> Result<FilterTerm, QueryError> {
    value
        .parse::<u32>()
        .ok()
        .and_then(NonZeroU32::new)
        .map(FilterTerm::ScopeId)
        .ok_or_else(|| invalid_value("scope_id", value, "an integer from 1 to 4294967295"))
}

fn parse_family(value: &str) -> Result<FilterTerm, QueryError> {
    match value.to_ascii_lowercase().as_str() {
        "ipv4" => Ok(FilterTerm::Family(AddressFamily::Ipv4)),
        "ipv6" => Ok(FilterTerm::Family(AddressFamily::Ipv6)),
        _ => Err(invalid_value("family", value, "ipv4 or ipv6")),
    }
}

fn parse_state(value: &str) -> Result<FilterTerm, QueryError> {
    let state = match value {
        "listen" => StateFilter::Listen,
        "bound" => StateFilter::Bound,
        "closed" => StateFilter::Closed,
        "syn_sent" => StateFilter::SynSent,
        "syn_received" => StateFilter::SynReceived,
        "established" => StateFilter::Established,
        "fin_wait1" => StateFilter::FinWait1,
        "fin_wait2" => StateFilter::FinWait2,
        "close_wait" => StateFilter::CloseWait,
        "closing" => StateFilter::Closing,
        "last_ack" => StateFilter::LastAck,
        "time_wait" => StateFilter::TimeWait,
        "delete_tcb" => StateFilter::DeleteTcb,
        "new_syn_received" => StateFilter::NewSynReceived,
        "unknown" => StateFilter::Unknown,
        _ => {
            return Err(invalid_value(
                "state",
                value,
                "a lowercase socket state name",
            ));
        }
    };
    Ok(FilterTerm::State(state))
}

fn validate_term_combinations(terms: &[FilterTerm]) -> Result<(), QueryError> {
    let has_scope = terms
        .iter()
        .any(|term| matches!(term, FilterTerm::ScopeId(_)));
    if !has_scope {
        return Ok(());
    }
    if terms.iter().any(|term| {
        matches!(
            term,
            FilterTerm::Family(AddressFamily::Ipv4) | FilterTerm::Address(IpAddr::V4(_))
        )
    }) {
        return Err(QueryError::ScopeRequiresIpv6);
    }
    Ok(())
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

fn term_matches<'a>(
    entry: &'a PortEntryView<'a>,
    term: &FilterTerm,
    metadata: &mut MetadataMatchCache<'a>,
) -> bool {
    match term {
        FilterTerm::Plain(needle) => plain_matches(entry, needle, metadata),
        FilterTerm::Pid(pid) => entry.pid == Some(*pid),
        FilterTerm::Port(port) => entry.local_port == *port,
        FilterTerm::Protocol(protocol) => entry.protocol == *protocol,
        FilterTerm::Scope(scope) => entry.scope() == *scope,
        FilterTerm::Protected(protected) => entry.protected == *protected,
        FilterTerm::Parent(needle) => parent_matches(entry, needle, metadata),
        FilterTerm::Label(needle) => entry
            .label
            .is_some_and(|label| metadata.contains(label, needle)),
        FilterTerm::Address(address) => normalize_ip_address(entry.local_addr) == *address,
        FilterTerm::ScopeId(scope_id) => {
            entry.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(*scope_id))
        }
        FilterTerm::Family(AddressFamily::Ipv4) => normalize_ip_address(entry.local_addr).is_ipv4(),
        FilterTerm::Family(AddressFamily::Ipv6) => normalize_ip_address(entry.local_addr).is_ipv6(),
        FilterTerm::State(_) => {
            unreachable!("full-state filters cannot be evaluated against legacy list rows")
        }
    }
}

fn plain_matches<'a>(
    entry: &'a PortEntryView<'a>,
    needle_lower: &str,
    metadata: &mut MetadataMatchCache<'a>,
) -> bool {
    display_matches(entry.local_port, needle_lower)
        || entry
            .pid
            .is_some_and(|pid| display_matches(pid, needle_lower))
        || display_matches(entry.local_addr, needle_lower)
        || socket_text_matches(entry, needle_lower)
        || contains_ascii(entry.protocol.label(), needle_lower)
        || contains_ascii(entry.state.label(), needle_lower)
        || contains_ascii(entry.scope_label(), needle_lower)
        || entry
            .label
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .process_name
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .executable_path
            .as_ref()
            .and_then(|path| path.to_str())
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || entry
            .command_line
            .is_some_and(|value| metadata.contains(value, needle_lower))
        || parent_matches(entry, needle_lower, metadata)
}

fn socket_text_matches(entry: &PortEntryView<'_>, needle_lower: &str) -> bool {
    if !needle_lower.contains(':') {
        return false;
    }

    let mut plain = StackText::new();
    let _ = write!(plain, "{}:{}", entry.local_addr, entry.local_port);
    if contains_ascii(plain.as_str(), needle_lower) {
        return true;
    }
    let mut bracketed = StackText::new();
    let _ = write!(bracketed, "[{}]:{}", entry.local_addr, entry.local_port);
    contains_ascii(bracketed.as_str(), needle_lower)
}

fn parent_matches<'a>(
    entry: &'a PortEntryView<'a>,
    needle_lower: &str,
    metadata: &mut MetadataMatchCache<'a>,
) -> bool {
    entry
        .parent_pid
        .is_some_and(|pid| display_matches(pid, needle_lower))
        || entry
            .parent_process_name
            .is_some_and(|value| metadata.contains(value, needle_lower))
}

fn display_matches(value: impl fmt::Display, needle: &str) -> bool {
    let mut text = StackText::new();
    let _ = write!(text, "{value}");
    contains_ascii(text.as_str(), needle)
}

fn contains_ascii(haystack: &str, needle: &str) -> bool {
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

#[derive(Default)]
struct NormalizationCache<'a> {
    by_pointer: HashMap<(usize, usize), usize>,
    by_value: HashMap<&'a str, usize>,
    values: Vec<String>,
}

#[derive(Default)]
struct MetadataMatchCache<'a> {
    normalization: NormalizationCache<'a>,
    matches: HashMap<usize, bool>,
}

impl<'a> MetadataMatchCache<'a> {
    fn clear_matches(&mut self) {
        self.matches.clear();
    }

    fn contains(&mut self, value: &'a str, needle: &str) -> bool {
        let value_key = self.normalization.key(value);
        if let Some(result) = self.matches.get(&value_key) {
            return *result;
        }
        let result = self.normalization.values[value_key].contains(needle);
        self.matches.insert(value_key, result);
        result
    }
}

impl<'a> NormalizationCache<'a> {
    fn key(&mut self, value: &'a str) -> usize {
        let pointer = (value.as_ptr() as usize, value.len());
        if let Some(&key) = self.by_pointer.get(&pointer) {
            key
        } else if let Some(&key) = self.by_value.get(value) {
            self.by_pointer.insert(pointer, key);
            key
        } else {
            let key = self.values.len();
            self.values.push(value.to_lowercase());
            self.by_pointer.insert(pointer, key);
            self.by_value.insert(value, key);
            key
        }
    }
}

struct StackText {
    bytes: [u8; 128],
    len: usize,
}

impl StackText {
    const fn new() -> Self {
        Self {
            bytes: [0; 128],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("formatted scalars are UTF-8")
    }
}

impl fmt::Write for StackText {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    use super::{
        FILTER_TEXT_MAX_BYTES, QueryCapabilities, QueryError, QueryOptions, query_view_indices,
    };
    use crate::labels::SELECTOR_ADDRESS_MAX_BYTES;
    use crate::model::{
        PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState, SortMode,
    };
    use crate::observation::Ipv6Scope;

    fn entry(port: u16, name: &str) -> PortEntry {
        PortEntry {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: port,
            state: SocketState::Listen,
            pid: Some(u32::from(port)),
            process_name: Some(name.into()),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{name}")).into()),
            command_line: Some(format!("{name} --port {port}").into()),
            parent_pid: Some(10),
            parent_process_name: Some("agent".into()),
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    fn query(filter_text: &str) -> QueryOptions<'_> {
        QueryOptions {
            port: None,
            process: None,
            filter_text,
            sort_mode: SortMode::Port,
            hide_system_processes: false,
            capabilities: QueryCapabilities::LIST,
        }
    }

    fn matching_ports(rows: &[PortEntry], filter_text: &str) -> Vec<u16> {
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        query_view_indices(&views, query(filter_text))
            .expect("query is valid")
            .indices
            .into_iter()
            .map(|index| rows[index].local_port)
            .collect()
    }

    #[test]
    fn plain_search_matches_user_visible_fields() {
        let mut node = entry(3000, "node");
        node.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        node.parent_process_name = Some("cursor-agent".into());
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
        let rows = [entry(3000, "Node"), entry(5173, "vite"), hidden];
        let options = QueryOptions {
            process: Some("OD"),
            ..query("")
        };

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("query is valid");
        let ports: Vec<u16> = result
            .indices
            .iter()
            .map(|&index| rows[index].local_port)
            .collect();

        assert_eq!(ports, vec![3000]);
        assert!(result.explicit_filter_active);
    }

    /// The CLI parser rejects an empty `--process` before this seam is reached,
    /// so this guards the other construction site: a programmatic caller must
    /// not be able to turn an empty needle into "every row with a readable
    /// name", which is what an unguarded substring match would produce.
    #[test]
    fn empty_process_option_is_refused_instead_of_matching_every_named_row() {
        let mut hidden = entry(8080, "hidden");
        hidden.process_name = None;
        let rows = [entry(3000, "node"), hidden];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        let refused = query_view_indices(
            &views,
            QueryOptions {
                process: Some(""),
                ..query("")
            },
        )
        .expect_err("an empty process selector must be refused");

        assert_eq!(
            refused,
            QueryError::InvalidValue {
                field: "process",
                value: String::new(),
                expected: "a nonempty process name substring",
            }
        );
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
        udp.parent_process_name = Some("systemd".into());

        let rows = vec![entry(3000, "node"), protected, udp];

        assert_eq!(matching_ports(&rows, "pid:902"), vec![5353]);
        assert_eq!(matching_ports(&rows, "port:5432"), vec![5432]);
        assert_eq!(matching_ports(&rows, "proto:udp"), vec![5353]);
        assert_eq!(matching_ports(&rows, "scope:public"), vec![5432]);
        assert_eq!(matching_ports(&rows, "protected:true"), vec![5432]);
        assert_eq!(matching_ports(&rows, "parent:systemd"), vec![5353]);
    }

    #[test]
    fn endpoint_and_label_filters_match_normalized_fields() {
        let mut ipv4 = entry(3000, "node");
        ipv4.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut ipv6 = entry(5353, "mdns");
        ipv6.protocol = Protocol::Udp;
        ipv6.state = SocketState::Bound;
        ipv6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        ipv6.ipv6_scope = Some(crate::observation::Ipv6Scope::interface_index(7).unwrap());
        let rows = [ipv4, ipv6];
        let mut views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        views[0].label = Some("Web Development");
        views[1].label = Some("mDNS");

        let matching = |filter| {
            query_view_indices(&views, query(filter))
                .unwrap()
                .indices
                .iter()
                .map(|&index| rows[index].local_port)
                .collect::<Vec<_>>()
        };
        assert_eq!(matching("label:development"), [3000]);
        assert_eq!(matching("web"), [3000]);
        assert_eq!(matching("address:::1"), [5353]);
        assert_eq!(matching("family:ipv4"), [3000]);
        assert_eq!(matching("family:ipv6 scope_id:7"), [5353]);
        assert!(matching("scope_id:8").is_empty());
    }

    #[test]
    fn family_filters_ignore_transport_protocol() {
        let mut tcp_v4 = entry(3000, "tcp-v4");
        tcp_v4.local_addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut udp_v4 = entry(3001, "udp-v4");
        udp_v4.protocol = Protocol::Udp;
        udp_v4.local_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut tcp_v6 = entry(3002, "tcp-v6");
        tcp_v6.local_addr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let mut udp_v6 = entry(3003, "udp-v6");
        udp_v6.protocol = Protocol::Udp;
        udp_v6.local_addr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
        let rows = [tcp_v4, udp_v4, tcp_v6, udp_v6];

        assert_eq!(matching_ports(&rows, "family:ipv4"), [3000, 3001]);
        assert_eq!(matching_ports(&rows, "family:ipv6"), [3002, 3003]);
    }

    #[test]
    fn mapped_address_filters_normalize_and_scope_conflicts_fail() {
        let row = entry(3000, "node");
        assert_eq!(matching_ports(&[row], "address:::ffff:127.0.0.1"), [3000]);

        let mut mapped = entry(3000, "node");
        mapped.local_addr = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        mapped.ipv6_scope = Some(Ipv6Scope::Unavailable);
        assert_eq!(
            matching_ports(&[mapped.clone()], "address:127.0.0.1"),
            [3000]
        );
        assert_eq!(matching_ports(&[mapped.clone()], "family:ipv4"), [3000]);
        assert!(matching_ports(&[mapped], "family:ipv6").is_empty());

        let rows = [entry(3000, "node")];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        for filter in ["family:ipv4 scope_id:1", "address:127.0.0.1 scope_id:1"] {
            assert!(matches!(
                query_view_indices(&views, query(filter)),
                Err(QueryError::ScopeRequiresIpv6)
            ));
        }
    }

    #[test]
    fn watch_only_state_filter_is_reserved_from_list_queries() {
        assert_eq!(
            super::validate_filter_text("state:listen", QueryCapabilities::LIST),
            Err(QueryError::UnsupportedField { field: "state" })
        );
        assert!(super::validate_filter_text("state:listen", QueryCapabilities::WATCH).is_ok());
        assert!(super::validate_filter_text("state:established", QueryCapabilities::WATCH).is_ok());
        assert!(matches!(
            super::validate_filter_text("state:not-a-state", QueryCapabilities::WATCH),
            Err(QueryError::InvalidValue { field: "state", .. })
        ));
        assert!(super::validate_filter_text("future:value", QueryCapabilities::LIST).is_ok());

        let rows = [entry(3000, "node")];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let options = QueryOptions {
            capabilities: QueryCapabilities::WATCH,
            ..query("state:listen")
        };
        assert!(matches!(
            query_view_indices(&views, options),
            Err(QueryError::FullStateEntriesRequired)
        ));
    }

    #[test]
    fn structured_filters_reject_bad_values() {
        let rows = [entry(3000, "node")];

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let error = query_view_indices(&views, query("port:not-a-port")).expect_err("invalid port");
        assert!(matches!(
            error,
            QueryError::InvalidValue { field: "port", .. }
        ));

        assert!(matches!(
            query_view_indices(&views, query("port:0")),
            Err(QueryError::InvalidValue { field: "port", .. })
        ));

        let mut direct = query("");
        direct.port = Some(0);
        assert!(matches!(
            query_view_indices(&views, direct),
            Err(QueryError::InvalidValue { field: "port", .. })
        ));

        let error = query_view_indices(&views, query("protected:maybe")).expect_err("invalid bool");
        assert!(matches!(
            error,
            QueryError::InvalidValue {
                field: "protected",
                ..
            }
        ));
    }

    #[test]
    fn family_scope_and_address_filters_reject_malformed_values() {
        let cases = [
            ("family:ip", "family"),
            ("family:", "family"),
            ("scope:wan", "scope"),
            ("scope:", "scope"),
            ("scope_id:0", "scope_id"),
            ("scope_id:4294967296", "scope_id"),
            ("scope_id:not-a-number", "scope_id"),
            ("address:", "address"),
            ("address:localhost", "address"),
            ("address:127.0.0.999", "address"),
            ("address:gggg::1", "address"),
        ];

        for (filter, expected_field) in cases {
            assert!(matches!(
                super::validate_filter_text(filter, QueryCapabilities::LIST),
                Err(QueryError::InvalidValue { field, .. }) if field == expected_field
            ));
        }
    }

    #[test]
    fn filter_text_over_the_byte_cap_is_rejected() {
        // The TUI already caps input in `append_search_char`, so the only way to
        // actually hit this bound is via CLI `--filter`. The cap lives here, so
        // the test pins it here too; the CLI turns the error into exit 2.
        let rows = [entry(3000, "node")];
        let maximum = "a".repeat(FILTER_TEXT_MAX_BYTES);
        let too_long = "a".repeat(FILTER_TEXT_MAX_BYTES + 1);

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        assert!(query_view_indices(&views, query(&maximum)).is_ok());
        let error =
            query_view_indices(&views, query(&too_long)).expect_err("over-cap filter is rejected");

        assert_eq!(
            error,
            QueryError::TooLong {
                actual: FILTER_TEXT_MAX_BYTES + 1,
                max: FILTER_TEXT_MAX_BYTES,
            }
        );

        let address_at_cap = format!("address:{}", "1".repeat(SELECTOR_ADDRESS_MAX_BYTES));
        assert!(matches!(
            super::validate_filter_text(&address_at_cap, QueryCapabilities::LIST),
            Err(QueryError::InvalidValue {
                field: "address",
                expected: "a literal IPv4 or IPv6 address",
                ..
            })
        ));
        let address_above_cap = format!("address:{}", "1".repeat(SELECTOR_ADDRESS_MAX_BYTES + 1));
        assert!(matches!(
            super::validate_filter_text(&address_above_cap, QueryCapabilities::LIST),
            Err(QueryError::InvalidValue {
                field: "address",
                expected: "a literal IP address of at most 64 bytes",
                ..
            })
        ));
    }

    #[test]
    fn hide_system_processes_uses_conservative_classification() {
        let mut service = entry(53, "systemd-resolved");
        service.parent_pid = Some(1);
        let rows = [entry(3000, "node"), service];
        let options = QueryOptions {
            hide_system_processes: true,
            ..query("")
        };

        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("query is valid");

        assert_eq!(result.indices.len(), 1);
        assert_eq!(
            rows[result.indices[0]].process_name.as_deref(),
            Some("node")
        );
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

        let rows = [loopback, local, public];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();
        let result = query_view_indices(&views, options).expect("valid query");
        let ports: Vec<u16> = result
            .indices
            .iter()
            .map(|&index| rows[index].local_port)
            .collect();

        assert_eq!(ports, vec![4000, 2000, 1000]);
    }

    #[test]
    fn process_and_parent_sort_unicode_names() {
        let process_a: std::sync::Arc<str> = "Zulu".into();
        let process_b: std::sync::Arc<str> = "Äther".into();
        let parent_a: std::sync::Arc<str> = "Zulu Parent".into();
        let parent_b: std::sync::Arc<str> = "Äther Parent".into();
        let mut zulu = entry(3000, "placeholder");
        zulu.process_name = Some(std::sync::Arc::clone(&process_a));
        zulu.parent_process_name = Some(std::sync::Arc::clone(&parent_a));
        let mut aether = entry(4000, "placeholder");
        aether.process_name = Some(std::sync::Arc::clone(&process_b));
        aether.parent_process_name = Some(std::sync::Arc::clone(&parent_b));
        let rows = [zulu, aether];
        let views = rows.iter().map(PortEntryView::from).collect::<Vec<_>>();

        for sort_mode in [SortMode::Process, SortMode::Parent] {
            let result = query_view_indices(
                &views,
                QueryOptions {
                    sort_mode,
                    ..query("")
                },
            )
            .expect("sort succeeds");
            assert_eq!(result.indices, [0, 1]);
        }
    }
}
