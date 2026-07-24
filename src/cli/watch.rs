use std::collections::HashMap;
use std::io::{self, ErrorKind, Write};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use clap::Args;
use serde::Serialize;

use crate::collector::{self, CollectorError};
use crate::config::Config;
use crate::display::{sanitize, sanitize_bounded};
use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, label_display_text, normalize_ip_address};
use crate::model::{BindScope, Protocol};
use crate::observation::{
    EndpointIdentity, EvidenceGap, Ipv6Scope, MetadataCompleteness, MetadataProfile,
    NetworkSnapshot, ObservationError, OwnerCompleteness, OwnerObservation, ProcessIdentity,
    ProcessObservation, SnapshotCompleteness, SocketObservation, SocketState,
};
use crate::protection::is_protected_process_name;
use crate::public_output::{
    EndpointDto, EvidenceDto, EvidenceGapDto, OwnerSetDto, PublicOutputError, SocketStateDto,
    SocketTokenDto, socket_state_name, unix_milliseconds,
};
use crate::query::{AddressFamily, FilterTerm, QueryCapabilities, StateFilter};
use crate::watch::{
    Certainty, DiffError, EventKind, WATCH_EVENT_BATCH_MAX, WATCH_EVENT_EVIDENCE_MAX,
    WATCH_EVENT_GAPS_MAX, WATCH_FAILURES_MAX, WATCH_RECORD_MAX_BYTES, WatchEvent, baseline_events,
    compare_event_prefix, diff_snapshots,
};

use super::ExitReason;

const WATCH_INTERVAL_DEFAULT: Duration = Duration::from_secs(1);
const WATCH_INTERVAL_MIN: Duration = Duration::from_millis(100);
const WATCH_INTERVAL_MAX: Duration = Duration::from_mins(1);
const WATCH_DURATION_MIN: Duration = Duration::from_millis(100);
const WATCH_DURATION_MAX: Duration = Duration::from_hours(168);
const CANCELLATION_POLL_MAX: Duration = Duration::from_millis(25);

#[derive(Debug, Args)]
pub(crate) struct WatchArgs {
    /// Include TCP; combine with --udp. Neither flag means both protocols.
    #[arg(long)]
    tcp: bool,
    /// Include UDP; combine with --tcp. Neither flag means both protocols.
    #[arg(long)]
    udp: bool,
    /// Match this literal normalized IP address across IPv6 scopes.
    #[arg(long, value_name = "ADDRESS")]
    address: Option<String>,
    /// Narrow an explicit IPv6 address to this nonzero interface index.
    #[arg(long, value_name = "ID")]
    scope_id: Option<u64>,
    /// Match this exact nonzero port.
    #[arg(long)]
    port: Option<u64>,
    /// Apply plain or structured full-state filters using AND semantics.
    ///
    /// Fields: `pid:`, `port:`, `proto:`, `scope:`, `protected:`, `parent:`,
    /// `label:`, `address:`, `scope_id:`, `family:`, and `state:`. State values:
    /// `listen`, `bound`, `closed`, `syn_sent`, `syn_received`, `established`,
    /// `fin_wait1`, `fin_wait2`, `close_wait`, `closing`, `last_ack`,
    /// `time_wait`, `delete_tcb`, `new_syn_received`, `unknown`.
    #[arg(long, value_name = "TEXT")]
    filter: Option<String>,
    /// Poll every 100ms..=60s (default 1s), for example 500ms or 2s.
    #[arg(long, value_name = "DURATION", default_value = "1s")]
    interval: String,
    /// Stop after 100ms..=7d instead of waiting for Ctrl-C.
    #[arg(long, value_name = "DURATION")]
    duration: Option<String>,
    /// Emit `kickoutchi.watch_event/1` NDJSON to stdout; diagnostics use stderr.
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent CLI selectors and output mode remain explicit after validation"
)]
struct WatchOptions {
    tcp: bool,
    udp: bool,
    address: Option<IpAddr>,
    scope_id: Option<NonZeroU32>,
    port: Option<u16>,
    terms: Vec<FilterTerm>,
    filter_active: bool,
    interval: Duration,
    duration: Option<Duration>,
    json: bool,
}

impl WatchOptions {
    fn parse(args: &WatchArgs) -> Result<Self, String> {
        let interval = if args.interval == "1s" {
            WATCH_INTERVAL_DEFAULT
        } else {
            parse_duration_token(&args.interval, WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX)
                .map_err(|error| format!("invalid --interval: {error}"))?
        };
        let duration = args
            .duration
            .as_deref()
            .map(|value| parse_duration_token(value, WATCH_DURATION_MIN, WATCH_DURATION_MAX))
            .transpose()
            .map_err(|error| format!("invalid --duration: {error}"))?;
        let address = args.address.as_deref().map(parse_address).transpose()?;
        let scope_id = args
            .scope_id
            .map(|value| {
                u32::try_from(value)
                    .ok()
                    .and_then(NonZeroU32::new)
                    .ok_or_else(|| "--scope-id must be in 1..=4294967295".to_owned())
            })
            .transpose()?;
        if scope_id.is_some() && !matches!(address, Some(IpAddr::V6(_))) {
            return Err("--scope-id requires one explicit IPv6 --address".to_owned());
        }
        let port = args
            .port
            .map(|value| {
                u16::try_from(value)
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or_else(|| "--port must be in 1..=65535".to_owned())
            })
            .transpose()?;
        let terms = crate::query::parse_filter_text(
            args.filter.as_deref().unwrap_or_default(),
            QueryCapabilities::WATCH,
        )
        .map_err(|error| format!("invalid filter: {error}"))?;
        let protocol_selected = args.tcp || args.udp;
        Ok(Self {
            tcp: args.tcp || !protocol_selected,
            udp: args.udp || !protocol_selected,
            address,
            scope_id,
            port,
            filter_active: protocol_selected
                || args.address.is_some()
                || args.scope_id.is_some()
                || args.port.is_some()
                || !terms.is_empty(),
            terms,
            interval,
            duration,
            json: args.json,
        })
    }
}

pub(super) fn run_watch(
    args: &WatchArgs,
    config: &Config,
    mut signal_guard: WatchSignalGuard,
) -> ExitReason {
    signal_guard.activate_loop();
    let options = match WatchOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("error: {}", sanitize(&error));
            return ExitReason::InvalidArguments;
        }
    };
    let mut runtime = ProductionRuntime::new();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut output = stdout.lock();
    let mut diagnostics = stderr.lock();
    run_watch_loop(
        &options,
        config,
        &mut runtime,
        &mut output,
        &mut diagnostics,
    )
}

trait WatchRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError>;
    fn monotonic_now(&mut self) -> Duration;
    fn wall_now(&mut self) -> Result<SystemTime, ObservationError>;
    fn sleep(&mut self, duration: Duration);
    fn cancelled(&self) -> bool;
}

struct ProductionRuntime {
    started: Instant,
}

impl ProductionRuntime {
    fn new() -> Self {
        Self {
            started: Instant::now(),
        }
    }
}

impl WatchRuntime for ProductionRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError> {
        collector::collect_snapshot(MetadataProfile::Display)
    }

    fn monotonic_now(&mut self) -> Duration {
        self.started.elapsed()
    }

    fn wall_now(&mut self) -> Result<SystemTime, ObservationError> {
        Ok(SystemTime::now())
    }

    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }

    fn cancelled(&self) -> bool {
        WATCH_CANCELLED.load(Ordering::Relaxed)
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::single_match_else,
    reason = "the polling state machine keeps each failure and flush transition in execution order"
)]
fn run_watch_loop(
    options: &WatchOptions,
    config: &Config,
    runtime: &mut impl WatchRuntime,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> ExitReason {
    let started = runtime.monotonic_now();
    let deadline = match options.duration {
        Some(duration) => match started.checked_add(duration) {
            Some(deadline) => Some(deadline),
            None => {
                write_diagnostic(diagnostics, "watch duration overflowed the monotonic clock");
                return ExitReason::Failure;
            }
        },
        None => None,
    };
    if runtime.cancelled() {
        return flush_exit(output, diagnostics, ExitReason::Success);
    }

    let initial_started = match runtime.wall_now() {
        Ok(value) => value,
        Err(error) => return clock_failure(diagnostics, &error),
    };
    let initial_result = runtime.collect();
    let initial_completed = match runtime.wall_now() {
        Ok(value) => value,
        Err(error) => return clock_failure(diagnostics, &error),
    };
    if let Err(error) = validate_wall_interval(initial_started, initial_completed) {
        return clock_failure(diagnostics, &error);
    }
    if let Some(error) = collector_clock_error(&initial_result) {
        return clock_failure(diagnostics, error);
    }
    if let Err(error) = &initial_result {
        write_diagnostic(
            diagnostics,
            &format!(
                "initial collection failed: {}",
                sanitize(&error.to_string())
            ),
        );
        return ExitReason::Failure;
    }
    let mut previous = match initial_result {
        Ok(snapshot) if snapshot.socket_set_diff_safe() => snapshot,
        Ok(snapshot) => {
            let detail = if snapshot.completeness == SnapshotCompleteness::Raced {
                "initial observation raced"
            } else {
                "initial observation has a partial socket set"
            };
            write_diagnostic(diagnostics, detail);
            return ExitReason::Failure;
        }
        Err(_) => unreachable!("initial collection errors return before snapshot validation"),
    };
    if runtime.cancelled() || deadline.is_some_and(|deadline| runtime.monotonic_now() >= deadline) {
        return flush_exit(output, diagnostics, ExitReason::Success);
    }
    let mut sequence = 0_u64;
    let mut batch_count = 0usize;
    let mut previous_gap_index = GapIndex::new(&previous);
    let mut previous_filter_cache = FilterCache::default();
    let initial_times = ObservationTimes {
        previous_completed_unix_ms: None,
        attempt_started_unix_ms: match unix_milliseconds(previous.capture_started_at) {
            Ok(value) => value,
            Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
        },
        attempt_completed_unix_ms: match unix_milliseconds(previous.capture_completed_at) {
            Ok(value) => value,
            Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
        },
    };
    let baseline = match baseline_events(&previous) {
        Ok(events) => events,
        Err(error) => {
            write_diagnostic(diagnostics, &error.to_string());
            return ExitReason::Failure;
        }
    };
    let mut no_previous_cache = None;
    let mut initial_cache = Some(&mut previous_filter_cache);
    if let Some(reason) = write_ordered_events(
        baseline.map(baseline_event_result),
        options,
        config,
        runtime,
        output,
        diagnostics,
        deadline,
        &mut sequence,
        &mut batch_count,
        &mut no_previous_cache,
        &mut initial_cache,
        None,
        Some(&previous_gap_index),
        initial_times,
    ) {
        return reason;
    }
    if let Err(error) = output.flush() {
        return io_failure(diagnostics, &error);
    }

    let mut consecutive_failures = 0u8;
    let Some(mut next_poll) = runtime.monotonic_now().checked_add(options.interval) else {
        write_diagnostic(diagnostics, "watch poll deadline overflowed");
        return ExitReason::Failure;
    };
    loop {
        if wait_until(runtime, next_poll, deadline) {
            return flush_exit(output, diagnostics, ExitReason::Success);
        }
        let attempt_monotonic = runtime.monotonic_now();
        let attempt_started = match runtime.wall_now() {
            Ok(value) => value,
            Err(error) => return clock_failure(diagnostics, &error),
        };
        if let Err(error) = validate_wall_interval(previous.capture_completed_at, attempt_started) {
            return clock_failure(diagnostics, &error);
        }
        let collected = runtime.collect();
        let attempt_completed = match runtime.wall_now() {
            Ok(value) => value,
            Err(error) => return clock_failure(diagnostics, &error),
        };
        if let Err(error) = validate_wall_interval(attempt_started, attempt_completed) {
            return clock_failure(diagnostics, &error);
        }
        if let Some(error) = collector_clock_error(&collected) {
            return clock_failure(diagnostics, error);
        }
        let gap_times = ObservationTimes {
            previous_completed_unix_ms: match unix_milliseconds(previous.capture_completed_at) {
                Ok(value) => Some(value),
                Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
            },
            attempt_started_unix_ms: match unix_milliseconds(attempt_started) {
                Ok(value) => value,
                Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
            },
            attempt_completed_unix_ms: match unix_milliseconds(attempt_completed) {
                Ok(value) => value,
                Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
            },
        };

        let current = match collected {
            Ok(snapshot) if snapshot.socket_set_diff_safe() => snapshot,
            result => {
                consecutive_failures = match consecutive_failures.checked_add(1) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(diagnostics, "watch failure count overflowed");
                        return ExitReason::Failure;
                    }
                };
                let gap = gap_from_result(&result, consecutive_failures);
                match write_gap(output, options.json, sequence, gap_times, &gap) {
                    Ok(()) => {}
                    Err(OutputError::BrokenPipe) => return ExitReason::Success,
                    Err(error) => return output_failure(diagnostics, &error),
                }
                if let Err(error) = output.flush() {
                    return io_failure(diagnostics, &error);
                }
                sequence = match sequence.checked_add(1) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(diagnostics, "watch sequence overflowed");
                        return ExitReason::Failure;
                    }
                };
                if consecutive_failures == WATCH_FAILURES_MAX {
                    return ExitReason::Failure;
                }
                if runtime.cancelled()
                    || deadline.is_some_and(|deadline| runtime.monotonic_now() >= deadline)
                {
                    return flush_exit(output, diagnostics, ExitReason::Success);
                }
                next_poll = match runtime.monotonic_now().checked_add(options.interval) {
                    Some(value) => value,
                    None => {
                        write_diagnostic(diagnostics, "watch poll deadline overflowed");
                        return ExitReason::Failure;
                    }
                };
                continue;
            }
        };
        if let Err(error) =
            validate_wall_interval(previous.capture_completed_at, current.capture_started_at)
        {
            return clock_failure(diagnostics, &error);
        }
        if runtime.cancelled()
            || deadline.is_some_and(|deadline| runtime.monotonic_now() >= deadline)
        {
            return flush_exit(output, diagnostics, ExitReason::Success);
        }

        consecutive_failures = 0;
        let current_gap_index = GapIndex::new(&current);
        let mut current_filter_cache = FilterCache::default();
        let event_times = ObservationTimes {
            previous_completed_unix_ms: gap_times.previous_completed_unix_ms,
            attempt_started_unix_ms: match unix_milliseconds(current.capture_started_at) {
                Ok(value) => value,
                Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
            },
            attempt_completed_unix_ms: match unix_milliseconds(current.capture_completed_at) {
                Ok(value) => value,
                Err(error) => return output_failure(diagnostics, &OutputError::from(error)),
            },
        };
        let diff = match diff_snapshots(&previous, &current) {
            Ok(diff) => diff,
            Err(error) => {
                write_diagnostic(diagnostics, &error.to_string());
                return ExitReason::Failure;
            }
        };
        batch_count = 0;
        let mut previous_cache = Some(&mut previous_filter_cache);
        let mut current_cache = Some(&mut current_filter_cache);
        if let Some(reason) = write_ordered_events(
            diff,
            options,
            config,
            runtime,
            output,
            diagnostics,
            deadline,
            &mut sequence,
            &mut batch_count,
            &mut previous_cache,
            &mut current_cache,
            Some(&previous_gap_index),
            Some(&current_gap_index),
            event_times,
        ) {
            return reason;
        }
        if let Err(error) = output.flush() {
            return io_failure(diagnostics, &error);
        }
        previous = current;
        previous_gap_index = current_gap_index;
        previous_filter_cache = current_filter_cache;
        next_poll = match attempt_monotonic.checked_add(options.interval) {
            Some(value) => value,
            None => {
                write_diagnostic(diagnostics, "watch poll deadline overflowed");
                return ExitReason::Failure;
            }
        };
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "adapts baseline events to the fallible diff-event stream"
)]
const fn baseline_event_result(event: WatchEvent<'_>) -> Result<WatchEvent<'_>, DiffError> {
    Ok(event)
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "ordered streaming keeps runtime, output, caches, gaps, and sequence ownership explicit"
)]
fn write_ordered_events<'a, I>(
    mut events: I,
    options: &WatchOptions,
    config: &Config,
    runtime: &mut impl WatchRuntime,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    deadline: Option<Duration>,
    sequence: &mut u64,
    batch_count: &mut usize,
    previous_cache: &mut Option<&mut FilterCache>,
    current_cache: &mut Option<&mut FilterCache>,
    previous_gap_index: Option<&GapIndex>,
    current_gap_index: Option<&GapIndex>,
    observation: ObservationTimes,
) -> Option<ExitReason>
where
    I: Iterator<Item = Result<WatchEvent<'a>, DiffError>> + Clone,
{
    let mut scanned_since_check = 0usize;
    loop {
        let group_start = events.clone();
        let first = match events.next()? {
            Ok(event) => event,
            Err(error) => {
                write_diagnostic(diagnostics, &error.to_string());
                return Some(flush_exit(output, diagnostics, ExitReason::Failure));
            }
        };
        let mut scan = group_start.clone();
        let mut group_end = group_start.clone();
        let mut rank_mask = 0u16;
        while let Some(result) = scan.next() {
            let event = match result {
                Ok(event) => event,
                Err(error) => {
                    write_diagnostic(diagnostics, &error.to_string());
                    return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                }
            };
            if compare_event_prefix(first, event) != std::cmp::Ordering::Equal {
                break;
            }
            group_end = scan.clone();
            if let Some(filter_result) = evaluate_event(
                event,
                options,
                config,
                previous_cache.as_deref_mut(),
                current_cache.as_deref_mut(),
            ) {
                rank_mask |= 1 << event_order_rank(filter_result, event.certainty);
            }
            scanned_since_check += 1;
            if scanned_since_check == WATCH_EVENT_BATCH_MAX {
                if runtime.cancelled()
                    || deadline.is_some_and(|deadline| runtime.monotonic_now() >= deadline)
                {
                    return Some(flush_exit(output, diagnostics, ExitReason::Success));
                }
                scanned_since_check = 0;
            }
        }
        events = group_end;

        for rank in 0..u16::BITS {
            if rank_mask & (1 << rank) == 0 {
                continue;
            }
            let mut pass = group_start.clone();
            loop {
                if runtime.cancelled()
                    || deadline.is_some_and(|deadline| runtime.monotonic_now() >= deadline)
                {
                    return Some(flush_exit(output, diagnostics, ExitReason::Success));
                }
                let Some(result) = pass.next() else { break };
                let event = match result {
                    Ok(event) => event,
                    Err(error) => {
                        write_diagnostic(diagnostics, &error.to_string());
                        return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                    }
                };
                if compare_event_prefix(first, event) != std::cmp::Ordering::Equal {
                    break;
                }
                let Some(filter_result) = evaluate_event(
                    event,
                    options,
                    config,
                    previous_cache.as_deref_mut(),
                    current_cache.as_deref_mut(),
                ) else {
                    continue;
                };
                if event_order_rank(filter_result, event.certainty) != rank {
                    continue;
                }
                match write_endpoint_event(
                    output,
                    options.json,
                    *sequence,
                    observation,
                    event,
                    filter_result,
                    &options.terms,
                    config,
                    previous_gap_index,
                    current_gap_index,
                ) {
                    Ok(()) => {}
                    Err(OutputError::BrokenPipe) => return Some(ExitReason::Success),
                    Err(error) => return Some(output_failure(diagnostics, &error)),
                }
                let Some(next_sequence) = sequence.checked_add(1) else {
                    write_diagnostic(diagnostics, "watch sequence overflowed");
                    return Some(flush_exit(output, diagnostics, ExitReason::Failure));
                };
                *sequence = next_sequence;
                *batch_count += 1;
                if *batch_count == WATCH_EVENT_BATCH_MAX {
                    if let Err(error) = output.flush() {
                        return Some(io_failure(diagnostics, &error));
                    }
                    *batch_count = 0;
                }
            }
        }
    }
}

const fn event_order_rank(filter_result: FilterResult, certainty: Certainty) -> u32 {
    let filter_rank = match filter_result {
        FilterResult::NotApplied => 0,
        FilterResult::Matched => 1,
        FilterResult::Indeterminate => 2,
    };
    let certainty_rank = match certainty {
        Certainty::Proven => 0,
        Certainty::Estimated => 1,
        Certainty::Heuristic => 2,
        Certainty::Unknown => 3,
    };
    filter_rank * 4 + certainty_rank
}

fn wait_until(
    runtime: &mut impl WatchRuntime,
    deadline: Duration,
    watch_deadline: Option<Duration>,
) -> bool {
    loop {
        if runtime.cancelled() {
            return true;
        }
        let now = runtime.monotonic_now();
        if watch_deadline.is_some_and(|end| now >= end) {
            return true;
        }
        if now >= deadline {
            return false;
        }
        let remaining = deadline.saturating_sub(now);
        let duration_remaining = watch_deadline.map_or(remaining, |end| end.saturating_sub(now));
        runtime.sleep(remaining.min(duration_remaining).min(CANCELLATION_POLL_MAX));
    }
}

fn parse_duration_token(
    value: &str,
    minimum: Duration,
    maximum: Duration,
) -> Result<Duration, String> {
    let suffix = ["ms", "s", "m", "h", "d"]
        .into_iter()
        .find(|suffix| value.ends_with(suffix))
        .ok_or_else(|| "expected one unsigned integer followed by ms, s, m, h, or d".to_owned())?;
    let number = &value[..value.len() - suffix.len()];
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("expected one unsigned integer followed by ms, s, m, h, or d".to_owned());
    }
    let magnitude = number
        .parse::<u64>()
        .map_err(|_| "duration value is too large".to_owned())?;
    let multiplier = match suffix {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => unreachable!("suffix is selected from a fixed set"),
    };
    let milliseconds = magnitude
        .checked_mul(multiplier)
        .ok_or_else(|| "duration value is too large".to_owned())?;
    let duration = Duration::from_millis(milliseconds);
    if duration < minimum || duration > maximum {
        return Err(format!(
            "value must be between {}ms and {}ms",
            minimum.as_millis(),
            maximum.as_millis()
        ));
    }
    Ok(duration)
}

fn parse_address(value: &str) -> Result<IpAddr, String> {
    if value.is_empty() || value.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err("--address must be a literal IP address of at most 64 bytes".to_owned());
    }
    value
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map_err(|_| "--address must be a literal IPv4 or IPv6 address without a zone".to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterResult {
    NotApplied,
    Matched,
    Indeterminate,
}

impl FilterResult {
    const fn name(self) -> &'static str {
        match self {
            Self::NotApplied => "not_applied",
            Self::Matched => "matched",
            Self::Indeterminate => "indeterminate",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Truth {
    False,
    Unknown,
    True,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnerPidConstraint {
    Any,
    Exact(u32),
    Impossible,
}

#[derive(Debug, Default)]
struct FilterCache {
    processes: HashMap<ProcessIdentity, NormalizedProcessMetadata>,
}

#[derive(Debug)]
struct NormalizedProcessMetadata {
    name: Option<String>,
    executable_path: Option<String>,
    parent_process_name: Option<String>,
}

impl FilterCache {
    fn metadata<'a>(
        &'a mut self,
        snapshot: &'a NetworkSnapshot,
        identity: ProcessIdentity,
    ) -> Option<(&'a NormalizedProcessMetadata, &'a ProcessObservation)> {
        let raw = snapshot.processes.get(&identity)?;
        let normalized =
            self.processes
                .entry(identity)
                .or_insert_with(|| NormalizedProcessMetadata {
                    name: raw.name.as_deref().map(str::to_lowercase),
                    executable_path: raw
                        .executable_path
                        .as_ref()
                        .and_then(|path| path.to_str())
                        .map(str::to_lowercase),
                    parent_process_name: raw.parent_process_name.as_deref().map(str::to_lowercase),
                });
        Some((normalized, raw))
    }
}

fn evaluate_event(
    event: WatchEvent<'_>,
    options: &WatchOptions,
    config: &Config,
    previous_cache: Option<&mut FilterCache>,
    current_cache: Option<&mut FilterCache>,
) -> Option<FilterResult> {
    if !selectors_match(event.endpoint(), options) {
        return None;
    }
    if !options.filter_active {
        return Some(FilterResult::NotApplied);
    }
    let result = match event.kind {
        EventKind::Baseline | EventKind::Bind => evaluate_side(
            event
                .current_snapshot
                .expect("current event side has a snapshot"),
            event
                .current_socket
                .expect("current event side has a socket"),
            options,
            config,
            current_cache.expect("current event side has a filter cache"),
        ),
        EventKind::Release => evaluate_side(
            event
                .previous_snapshot
                .expect("release has a previous snapshot"),
            event
                .previous_socket
                .expect("release has a previous socket"),
            options,
            config,
            previous_cache.expect("previous event side has a filter cache"),
        ),
        EventKind::Replacement => {
            let previous = evaluate_side(
                event
                    .previous_snapshot
                    .expect("replacement has previous snapshot"),
                event
                    .previous_socket
                    .expect("replacement has previous socket"),
                options,
                config,
                previous_cache.expect("replacement previous side has a filter cache"),
            );
            let current = evaluate_side(
                event
                    .current_snapshot
                    .expect("replacement has current snapshot"),
                event
                    .current_socket
                    .expect("replacement has current socket"),
                options,
                config,
                current_cache.expect("replacement current side has a filter cache"),
            );
            match (previous, current) {
                (Truth::True, _) | (_, Truth::True) => Truth::True,
                (Truth::False, Truth::False) => Truth::False,
                _ => Truth::Unknown,
            }
        }
    };
    match result {
        Truth::False => None,
        Truth::True => Some(FilterResult::Matched),
        Truth::Unknown => Some(FilterResult::Indeterminate),
    }
}

fn selectors_match(endpoint: &EndpointIdentity, options: &WatchOptions) -> bool {
    let protocol = match endpoint.protocol {
        Protocol::Tcp => options.tcp,
        Protocol::Udp => options.udp,
    };
    protocol
        && options
            .address
            .is_none_or(|address| normalize_ip_address(endpoint.address) == address)
        && options.port.is_none_or(|port| endpoint.port.get() == port)
        && options
            .scope_id
            .is_none_or(|scope_id| endpoint.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(scope_id)))
}

fn evaluate_side(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    options: &WatchOptions,
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    if options.terms.is_empty() {
        return Truth::True;
    }
    let label = config.labels.resolve(&socket.local_endpoint);
    if options.terms.iter().any(|term| {
        owner_independent(term)
            && evaluate_term(snapshot, socket, None, label, term, false, config, cache)
                == Truth::False
    }) {
        return Truth::False;
    }
    let common_plain_matches = options
        .terms
        .iter()
        .map(|term| match term {
            FilterTerm::Plain(needle) => common_plain_match(socket, label, needle),
            _ => false,
        })
        .collect::<Vec<_>>();
    let owner_terms_present = options.terms.iter().any(|term| !owner_independent(term));
    let owner_pid_constraint = owner_pid_constraint(&options.terms);
    let endpointless_ownership_unknown = owner_terms_present
        && (snapshot.evidence_gaps.iter().any(|gap| {
            gap.impact == crate::observation::EvidenceImpact::Ownership
                && gap.endpoint.is_none()
                && endpointless_ownership_gap_is_relevant(gap.pid, owner_pid_constraint)
        }) || (snapshot.omitted_evidence_gap_count != 0
            && !snapshot.owner_completeness.is_complete()
            && endpointless_ownership_gap_is_relevant(None, owner_pid_constraint)));
    if socket.owners.is_empty() {
        let result = evaluate_terms_for_owner(
            snapshot,
            socket,
            None,
            label,
            &options.terms,
            &common_plain_matches,
            config,
            cache,
        );
        return if result == Truth::False && endpointless_ownership_unknown {
            Truth::Unknown
        } else {
            result
        };
    }
    let mut unknown = false;
    for owner in &socket.owners {
        match evaluate_terms_for_owner(
            snapshot,
            socket,
            Some(owner),
            label,
            &options.terms,
            &common_plain_matches,
            config,
            cache,
        ) {
            Truth::True => return Truth::True,
            Truth::Unknown => unknown = true,
            Truth::False => {}
        }
    }
    if unknown || !socket.owner_completeness.is_complete() || endpointless_ownership_unknown {
        Truth::Unknown
    } else {
        Truth::False
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "event-side filtering keeps snapshot, socket, owner, parsed terms, policy, and cache explicit"
)]
fn evaluate_terms_for_owner(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    owner: Option<&OwnerObservation>,
    label: Option<&str>,
    terms: &[FilterTerm],
    common_plain_matches: &[bool],
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    let mut unknown = false;
    for (index, term) in terms.iter().enumerate() {
        if owner_independent(term) {
            continue;
        }
        match evaluate_term(
            snapshot,
            socket,
            owner,
            label,
            term,
            common_plain_matches[index],
            config,
            cache,
        ) {
            Truth::False => return Truth::False,
            Truth::Unknown => unknown = true,
            Truth::True => {}
        }
    }
    if unknown { Truth::Unknown } else { Truth::True }
}

#[allow(
    clippy::too_many_arguments,
    reason = "term evaluation keeps endpoint facts and one conceptual owner row explicit"
)]
fn evaluate_term(
    snapshot: &NetworkSnapshot,
    socket: &SocketObservation,
    owner: Option<&OwnerObservation>,
    label: Option<&str>,
    term: &FilterTerm,
    common_plain_match: bool,
    config: &Config,
    cache: &mut FilterCache,
) -> Truth {
    let endpoint = &socket.local_endpoint;
    match term {
        FilterTerm::Port(port) => truth(endpoint.port.get() == *port),
        FilterTerm::Protocol(protocol) => truth(endpoint.protocol == *protocol),
        FilterTerm::Scope(scope) => truth(bind_scope(endpoint.address) == *scope),
        FilterTerm::Label(needle) => {
            truth(label.is_some_and(|label| lowered_contains(label, needle)))
        }
        FilterTerm::Address(address) => truth(normalize_ip_address(endpoint.address) == *address),
        FilterTerm::ScopeId(scope_id) => {
            truth(endpoint.ipv6_scope == Some(Ipv6Scope::InterfaceIndex(*scope_id)))
        }
        FilterTerm::Family(AddressFamily::Ipv4) => {
            truth(normalize_ip_address(endpoint.address).is_ipv4())
        }
        FilterTerm::Family(AddressFamily::Ipv6) => {
            truth(normalize_ip_address(endpoint.address).is_ipv6())
        }
        FilterTerm::State(state) => truth(state_matches(socket.state, *state)),
        FilterTerm::Pid(pid) => owner_pid_truth(owner, *pid, &socket.owner_completeness),
        FilterTerm::Parent(needle) => metadata_truth(
            snapshot,
            owner,
            cache,
            |metadata, normalized| {
                metadata
                    .parent_pid
                    .is_some_and(|pid| pid.to_string().contains(needle))
                    || normalized
                        .parent_process_name
                        .as_deref()
                        .is_some_and(|name| name.contains(needle))
            },
            &socket.owner_completeness,
        ),
        FilterTerm::Protected(expected) => protection_truth(
            snapshot,
            owner,
            *expected,
            config,
            &socket.owner_completeness,
        ),
        FilterTerm::Plain(needle) => {
            if common_plain_match
                || owner.is_some_and(|owner| owner_pid(owner).to_string().contains(needle))
            {
                Truth::True
            } else {
                let metadata = metadata_truth(
                    snapshot,
                    owner,
                    cache,
                    |metadata, normalized| process_plain_match(owner, metadata, normalized, needle),
                    &socket.owner_completeness,
                );
                match protection_plain_truth(snapshot, owner, needle, config) {
                    Truth::True => Truth::True,
                    Truth::Unknown if metadata == Truth::False => Truth::Unknown,
                    Truth::False | Truth::Unknown => metadata,
                }
            }
        }
    }
}

fn protection_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    expected: bool,
    config: &Config,
    owner_completeness: &OwnerCompleteness,
) -> Truth {
    let Some(owner) = owner else {
        return if owner_completeness.is_complete() {
            truth(!expected)
        } else {
            Truth::Unknown
        };
    };
    let OwnerObservation::Verified(identity) = owner else {
        return Truth::Unknown;
    };
    let Some(name) = snapshot
        .processes
        .get(identity)
        .and_then(|metadata| metadata.name.as_deref())
    else {
        return Truth::Unknown;
    };
    truth(
        is_protected_process_name(snapshot.platform(), name, &config.protected_processes)
            == expected,
    )
}

fn protection_plain_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    needle: &str,
    config: &Config,
) -> Truth {
    let Some(OwnerObservation::Verified(identity)) = owner else {
        return Truth::Unknown;
    };
    let Some(name) = snapshot
        .processes
        .get(identity)
        .and_then(|metadata| metadata.name.as_deref())
    else {
        return Truth::Unknown;
    };
    let protected =
        is_protected_process_name(snapshot.platform(), name, &config.protected_processes);
    let classification = if protected {
        "protected"
    } else {
        "unprotected"
    };
    match needle {
        "protected" => truth(protected),
        "unprotected" => truth(!protected),
        _ => truth(classification.contains(needle)),
    }
}

fn metadata_truth(
    snapshot: &NetworkSnapshot,
    owner: Option<&OwnerObservation>,
    cache: &mut FilterCache,
    predicate: impl FnOnce(&ProcessObservation, &NormalizedProcessMetadata) -> bool,
    owner_completeness: &OwnerCompleteness,
) -> Truth {
    let Some(owner) = owner else {
        return if owner_completeness.is_complete() {
            Truth::False
        } else {
            Truth::Unknown
        };
    };
    let OwnerObservation::Verified(identity) = owner else {
        return Truth::Unknown;
    };
    let Some((normalized, metadata)) = cache.metadata(snapshot, *identity) else {
        return Truth::Unknown;
    };
    if predicate(metadata, normalized) {
        Truth::True
    } else if metadata.metadata_completeness == MetadataCompleteness::Partial {
        Truth::Unknown
    } else {
        Truth::False
    }
}

fn owner_pid_truth(
    owner: Option<&OwnerObservation>,
    pid: u32,
    completeness: &OwnerCompleteness,
) -> Truth {
    match owner {
        Some(OwnerObservation::Verified(identity)) => truth(identity.pid == pid),
        Some(OwnerObservation::UnverifiedPid { pid: owner_pid, .. }) => truth(*owner_pid == pid),
        None if completeness.is_complete() => Truth::False,
        None => Truth::Unknown,
    }
}

fn common_plain_match(socket: &SocketObservation, label: Option<&str>, needle: &str) -> bool {
    let endpoint = &socket.local_endpoint;
    endpoint.port.get().to_string().contains(needle)
        || endpoint.address.to_string().to_lowercase().contains(needle)
        || format!("{}:{}", endpoint.address, endpoint.port)
            .to_lowercase()
            .contains(needle)
        || format!("[{}]:{}", endpoint.address, endpoint.port)
            .to_lowercase()
            .contains(needle)
        || endpoint
            .protocol
            .label()
            .to_ascii_lowercase()
            .contains(needle)
        || socket_state_name(socket.state).contains(needle)
        || bind_scope(endpoint.address).label().contains(needle)
        || label.is_some_and(|label| lowered_contains(label, needle))
}

fn process_plain_match(
    owner: Option<&OwnerObservation>,
    metadata: &ProcessObservation,
    normalized: &NormalizedProcessMetadata,
    needle: &str,
) -> bool {
    owner.is_some_and(|owner| owner_pid(owner).to_string().contains(needle))
        || normalized
            .name
            .as_deref()
            .is_some_and(|name| name.contains(needle))
        || normalized
            .executable_path
            .as_deref()
            .is_some_and(|path| path.contains(needle))
        || metadata
            .parent_pid
            .is_some_and(|pid| pid.to_string().contains(needle))
        || normalized
            .parent_process_name
            .as_deref()
            .is_some_and(|name| name.contains(needle))
}

const fn owner_independent(term: &FilterTerm) -> bool {
    matches!(
        term,
        FilterTerm::Port(_)
            | FilterTerm::Protocol(_)
            | FilterTerm::Scope(_)
            | FilterTerm::Label(_)
            | FilterTerm::Address(_)
            | FilterTerm::ScopeId(_)
            | FilterTerm::Family(_)
            | FilterTerm::State(_)
    )
}

fn owner_pid_constraint(terms: &[FilterTerm]) -> OwnerPidConstraint {
    let mut required = None;
    for term in terms {
        let FilterTerm::Pid(pid) = term else {
            continue;
        };
        if required.is_some_and(|required| required != *pid) {
            return OwnerPidConstraint::Impossible;
        }
        required = Some(*pid);
    }
    required.map_or(OwnerPidConstraint::Any, OwnerPidConstraint::Exact)
}

const fn endpointless_ownership_gap_is_relevant(
    gap_pid: Option<u32>,
    constraint: OwnerPidConstraint,
) -> bool {
    match (gap_pid, constraint) {
        (_, OwnerPidConstraint::Impossible) => false,
        (None, _) | (Some(_), OwnerPidConstraint::Any) => true,
        (Some(gap_pid), OwnerPidConstraint::Exact(required)) => gap_pid == required,
    }
}

fn lowered_contains(value: &str, lowered_needle: &str) -> bool {
    value.to_lowercase().contains(lowered_needle)
}

const fn truth(value: bool) -> Truth {
    if value { Truth::True } else { Truth::False }
}

fn bind_scope(address: IpAddr) -> BindScope {
    if address.is_unspecified() {
        BindScope::Public
    } else if address.is_loopback() {
        BindScope::Loopback
    } else {
        BindScope::Local
    }
}

fn state_matches(state: SocketState, filter: StateFilter) -> bool {
    matches!(
        (state, filter),
        (SocketState::Listen, StateFilter::Listen)
            | (SocketState::Bound, StateFilter::Bound)
            | (SocketState::Closed, StateFilter::Closed)
            | (SocketState::SynSent, StateFilter::SynSent)
            | (SocketState::SynReceived, StateFilter::SynReceived)
            | (SocketState::Established, StateFilter::Established)
            | (SocketState::FinWait1, StateFilter::FinWait1)
            | (SocketState::FinWait2, StateFilter::FinWait2)
            | (SocketState::CloseWait, StateFilter::CloseWait)
            | (SocketState::Closing, StateFilter::Closing)
            | (SocketState::LastAck, StateFilter::LastAck)
            | (SocketState::TimeWait, StateFilter::TimeWait)
            | (SocketState::DeleteTcb, StateFilter::DeleteTcb)
            | (SocketState::NewSynReceived, StateFilter::NewSynReceived)
            | (SocketState::Unknown(_), StateFilter::Unknown)
    )
}

#[derive(Debug, Clone, Copy, Serialize)]
#[allow(
    clippy::struct_field_names,
    reason = "field names are the versioned JSON contract"
)]
struct ObservationTimes {
    previous_completed_unix_ms: Option<u64>,
    attempt_started_unix_ms: u64,
    attempt_completed_unix_ms: u64,
}

#[derive(Serialize)]
struct WatchRecord<T> {
    schema: &'static str,
    version: u32,
    sequence: u64,
    event: &'static str,
    observation: ObservationTimes,
    data: T,
}

#[derive(Serialize)]
struct EndpointEventData<'a> {
    endpoint: EndpointDto<'a>,
    state: SocketStateDto,
    previous_owners: Option<OwnerSetDto<'a>>,
    current_owners: Option<OwnerSetDto<'a>>,
    previous_socket_token: Option<SocketTokenDto>,
    current_socket_token: Option<SocketTokenDto>,
    multiplicity: u32,
    label: Option<&'a str>,
    filter_result: &'static str,
    certainty: &'static str,
    evidence: Vec<EvidenceDto<'static>>,
    omitted_evidence_count: u64,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct GapData<'a> {
    error: PublicError,
    certainty: &'static str,
    consecutive_failures: u8,
    completeness: Option<&'static str>,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct PublicError {
    code: &'static str,
    message: String,
}

#[allow(
    clippy::too_many_arguments,
    reason = "the streaming boundary keeps event, schema, filter, and bounded gap context explicit"
)]
fn write_endpoint_event(
    writer: &mut impl Write,
    json: bool,
    sequence: u64,
    observation: ObservationTimes,
    event: WatchEvent<'_>,
    filter_result: FilterResult,
    filter_terms: &[FilterTerm],
    config: &Config,
    previous_gap_index: Option<&GapIndex>,
    current_gap_index: Option<&GapIndex>,
) -> Result<(), OutputError> {
    if !json {
        return write_human_event(writer, observation, event, filter_result, config);
    }
    let socket = event.event_socket();
    let (evidence_gaps, omitted_gap_count) = if filter_result == FilterResult::Indeterminate {
        event_gap_dtos(event, filter_terms, previous_gap_index, current_gap_index)
    } else {
        (Vec::new(), 0)
    };
    let evidence = if event.kind == EventKind::Replacement {
        vec![EvidenceDto::literal(
            "process_identity_changed",
            "analysis",
            Certainty::Proven.name(),
            "verified process identity changed between observations",
        )]
    } else {
        Vec::new()
    };
    let (evidence, omitted_evidence_count) = retain_event_evidence(evidence);
    let data = EndpointEventData {
        endpoint: EndpointDto::from(&socket.local_endpoint),
        state: SocketStateDto::from(socket.state),
        previous_owners: event
            .previous_socket
            .map(|socket| OwnerSetDto::new(&socket.owners, &socket.owner_completeness))
            .transpose()?,
        current_owners: event
            .current_socket
            .map(|socket| OwnerSetDto::new(&socket.owners, &socket.owner_completeness))
            .transpose()?,
        previous_socket_token: event
            .previous_socket
            .and_then(|socket| socket.socket_token.map(SocketTokenDto::from)),
        current_socket_token: event
            .current_socket
            .and_then(|socket| socket.socket_token.map(SocketTokenDto::from)),
        multiplicity: event.multiplicity,
        label: config.labels.resolve(&socket.local_endpoint),
        filter_result: filter_result.name(),
        certainty: event.certainty.name(),
        evidence,
        omitted_evidence_count,
        evidence_gaps,
        omitted_evidence_gap_count: omitted_gap_count,
    };
    write_json_record(
        writer,
        &WatchRecord {
            schema: "kickoutchi.watch_event",
            version: 1,
            sequence,
            event: event.kind.name(),
            observation,
            data,
        },
    )
}

fn retain_event_evidence(evidence: Vec<EvidenceDto<'static>>) -> (Vec<EvidenceDto<'static>>, u64) {
    let omitted = evidence.len().saturating_sub(WATCH_EVENT_EVIDENCE_MAX);
    (
        evidence
            .into_iter()
            .take(WATCH_EVENT_EVIDENCE_MAX)
            .collect(),
        u64::try_from(omitted).unwrap_or(u64::MAX),
    )
}

#[derive(Debug, Default)]
struct GapBucket {
    indices: Vec<usize>,
    total: u64,
}

impl GapBucket {
    fn add(&mut self, index: usize) {
        self.total = self.total.saturating_add(1);
        if self.indices.len() < WATCH_EVENT_GAPS_MAX {
            self.indices.push(index);
        }
    }
}

#[derive(Debug, Default)]
struct GapIndex {
    global: GapBucket,
    endpointless_ownership: GapBucket,
    ownership_by_pid: HashMap<u32, GapBucket>,
    by_endpoint: HashMap<EndpointIdentity, GapBucket>,
    by_pid: HashMap<u32, GapBucket>,
    omitted_endpointless_ownership: u64,
}

impl GapIndex {
    fn new(snapshot: &NetworkSnapshot) -> Self {
        let mut index = Self {
            omitted_endpointless_ownership: if snapshot.owner_completeness.is_complete() {
                0
            } else {
                snapshot.omitted_evidence_gap_count
            },
            ..Self::default()
        };
        for (gap_index, gap) in snapshot.evidence_gaps.iter().enumerate() {
            match (&gap.endpoint, gap.pid) {
                (Some(endpoint), _) => index
                    .by_endpoint
                    .entry(endpoint.clone())
                    .or_default()
                    .add(gap_index),
                (None, Some(pid))
                    if gap.impact == crate::observation::EvidenceImpact::Ownership =>
                {
                    index.endpointless_ownership.add(gap_index);
                    index
                        .ownership_by_pid
                        .entry(pid)
                        .or_default()
                        .add(gap_index);
                }
                (None, Some(pid)) => index.by_pid.entry(pid).or_default().add(gap_index),
                (None, None) => index.global.add(gap_index),
            }
        }
        index
    }

    fn append<'a>(
        &self,
        snapshot: &'a NetworkSnapshot,
        socket: &SocketObservation,
        owner_pid_constraint: OwnerPidConstraint,
        gaps: &mut Vec<&'a EvidenceGap>,
        total: &mut u64,
    ) {
        append_gap_bucket(&self.global, snapshot, gaps, total);
        match owner_pid_constraint {
            OwnerPidConstraint::Any => {
                append_gap_bucket(&self.endpointless_ownership, snapshot, gaps, total);
            }
            OwnerPidConstraint::Exact(pid) => {
                if let Some(bucket) = self.ownership_by_pid.get(&pid) {
                    append_gap_bucket(bucket, snapshot, gaps, total);
                }
            }
            OwnerPidConstraint::Impossible => {}
        }
        if owner_pid_constraint != OwnerPidConstraint::Impossible {
            *total = total.saturating_add(self.omitted_endpointless_ownership);
        }
        if let Some(bucket) = self.by_endpoint.get(&socket.local_endpoint) {
            append_gap_bucket(bucket, snapshot, gaps, total);
        }
        for owner in &socket.owners {
            if let Some(bucket) = self.by_pid.get(&owner_pid(owner)) {
                append_gap_bucket(bucket, snapshot, gaps, total);
            }
        }
    }
}

fn append_gap_bucket<'a>(
    bucket: &GapBucket,
    snapshot: &'a NetworkSnapshot,
    gaps: &mut Vec<&'a EvidenceGap>,
    total: &mut u64,
) {
    *total = total.saturating_add(bucket.total);
    for index in &bucket.indices {
        retain_bounded_gap(gaps, &snapshot.evidence_gaps[*index]);
    }
}

fn retain_bounded_gap<'a>(gaps: &mut Vec<&'a EvidenceGap>, gap: &'a EvidenceGap) {
    let position = gaps.partition_point(|retained| *retained <= gap);
    if gaps.len() < WATCH_EVENT_GAPS_MAX {
        gaps.insert(position, gap);
    } else if position < WATCH_EVENT_GAPS_MAX {
        gaps.copy_within(position..WATCH_EVENT_GAPS_MAX - 1, position + 1);
        gaps[position] = gap;
    }
}

fn event_gap_dtos<'a>(
    event: WatchEvent<'a>,
    filter_terms: &[FilterTerm],
    previous_index: Option<&GapIndex>,
    current_index: Option<&GapIndex>,
) -> (Vec<EvidenceGapDto<'a>>, u64) {
    let mut gaps = Vec::with_capacity(WATCH_EVENT_GAPS_MAX);
    let mut total = 0u64;
    let owner_pid_constraint = owner_pid_constraint(filter_terms);
    if let (Some(snapshot), Some(socket), Some(index)) = (
        event.previous_snapshot,
        event.previous_socket,
        previous_index,
    ) {
        index.append(
            snapshot,
            socket,
            owner_pid_constraint,
            &mut gaps,
            &mut total,
        );
    }
    if let (Some(snapshot), Some(socket), Some(index)) =
        (event.current_snapshot, event.current_socket, current_index)
    {
        index.append(
            snapshot,
            socket,
            owner_pid_constraint,
            &mut gaps,
            &mut total,
        );
    }
    let retained = gaps.len();
    let omitted = total.saturating_sub(u64::try_from(retained).unwrap_or(u64::MAX));
    (
        gaps.into_iter()
            .take(WATCH_EVENT_GAPS_MAX)
            .map(EvidenceGapDto::from)
            .collect(),
        omitted,
    )
}

fn write_human_event(
    writer: &mut impl Write,
    observation: ObservationTimes,
    event: WatchEvent<'_>,
    filter_result: FilterResult,
    config: &Config,
) -> Result<(), OutputError> {
    let socket = event.event_socket();
    let endpoint = &socket.local_endpoint;
    let mut owners = socket
        .owners
        .iter()
        .take(crate::observation::SERIALIZED_OWNERS_MAX)
        .map(owner_pid)
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(",");
    let omitted_owners = socket
        .owners
        .len()
        .saturating_sub(crate::observation::SERIALIZED_OWNERS_MAX);
    if omitted_owners != 0 {
        let _ = std::fmt::Write::write_fmt(&mut owners, format_args!(",+{omitted_owners}"));
    }
    let label = config.labels.resolve(endpoint).map(label_display_text);
    let endpoint_text = human_endpoint_text(endpoint);
    writeln!(
        writer,
        "{} {} {} {} owners={}{} filter={} certainty={} observed={}..{} previous_completed={}",
        event.kind.name().to_ascii_uppercase(),
        endpoint.protocol.label(),
        endpoint_text,
        socket_state_name(socket.state),
        if owners.is_empty() { "-" } else { &owners },
        label
            .as_deref()
            .map_or(String::new(), |label| format!(" label={label}")),
        filter_result.name(),
        event.certainty.name(),
        observation.attempt_started_unix_ms,
        observation.attempt_completed_unix_ms,
        observation
            .previous_completed_unix_ms
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
    )
    .map_err(OutputError::from)
}

fn human_endpoint_text(endpoint: &EndpointIdentity) -> String {
    match (endpoint.address, endpoint.ipv6_scope) {
        (IpAddr::V4(address), None) => format!("{address}:{}", endpoint.port),
        (IpAddr::V6(address), Some(Ipv6Scope::Unscoped)) => {
            format!("[{address}]:{}", endpoint.port)
        }
        (IpAddr::V6(address), Some(Ipv6Scope::InterfaceIndex(index))) => {
            format!("[{address}%{index}]:{}", endpoint.port)
        }
        (IpAddr::V6(address), Some(Ipv6Scope::Unavailable)) => {
            format!("[{address}%unavailable]:{}", endpoint.port)
        }
        _ => unreachable!("validated endpoint address and scope agree"),
    }
}

fn write_gap(
    writer: &mut impl Write,
    json: bool,
    sequence: u64,
    observation: ObservationTimes,
    gap: &GapData<'_>,
) -> Result<(), OutputError> {
    if !json {
        return writeln!(
            writer,
            "COLLECTION_GAP {} failures={} certainty=unknown observed={}..{} previous_completed={}",
            sanitize(&gap.error.message),
            gap.consecutive_failures,
            observation.attempt_started_unix_ms,
            observation.attempt_completed_unix_ms,
            observation
                .previous_completed_unix_ms
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        )
        .map_err(OutputError::from);
    }
    write_json_record(
        writer,
        &WatchRecord {
            schema: "kickoutchi.watch_event",
            version: 1,
            sequence,
            event: "collection_gap",
            observation,
            data: gap,
        },
    )
}

fn gap_from_result(
    result: &Result<NetworkSnapshot, CollectorError>,
    consecutive_failures: u8,
) -> GapData<'_> {
    match result {
        Err(error) => GapData {
            error: PublicError {
                code: collector_error_code(error),
                message: sanitize_bounded(&error.to_string(), 512),
            },
            certainty: "unknown",
            consecutive_failures,
            completeness: None,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
        },
        Ok(snapshot) => {
            let code = if snapshot.completeness == SnapshotCompleteness::Raced {
                "observation_raced"
            } else {
                "partial_socket_set"
            };
            let completeness = Some(if snapshot.completeness == SnapshotCompleteness::Raced {
                "raced"
            } else {
                "partial"
            });
            let omitted = snapshot.omitted_evidence_gap_count.saturating_add(
                u64::try_from(
                    snapshot
                        .evidence_gaps
                        .len()
                        .saturating_sub(WATCH_EVENT_GAPS_MAX),
                )
                .unwrap_or(u64::MAX),
            );
            GapData {
                error: PublicError {
                    code,
                    message: if code == "observation_raced" {
                        "observation raced during collection".to_owned()
                    } else {
                        "socket set was partial during collection".to_owned()
                    },
                },
                certainty: "unknown",
                consecutive_failures,
                completeness,
                evidence_gaps: snapshot
                    .evidence_gaps
                    .iter()
                    .take(WATCH_EVENT_GAPS_MAX)
                    .map(EvidenceGapDto::from)
                    .collect(),
                omitted_evidence_gap_count: omitted,
            }
        }
    }
}

fn write_json_record(writer: &mut impl Write, value: &impl Serialize) -> Result<(), OutputError> {
    let mut record = BoundedRecord::new();
    serde_json::to_writer(&mut record, value).map_err(|error| {
        if record.limit_exceeded {
            OutputError::EventLimit
        } else {
            OutputError::from(PublicOutputError::from(error))
        }
    })?;
    record
        .write_all(b"\n")
        .map_err(|_| OutputError::EventLimit)?;
    writer.write_all(&record.bytes).map_err(OutputError::from)
}

struct BoundedRecord {
    bytes: Vec<u8>,
    limit_exceeded: bool,
}

impl BoundedRecord {
    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(4_096),
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedRecord {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > WATCH_RECORD_MAX_BYTES)
        {
            self.limit_exceeded = true;
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "watch record exceeds 64 KiB",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum OutputError {
    BrokenPipe,
    Io(io::Error),
    Public(PublicOutputError),
    EventLimit,
}

impl From<io::Error> for OutputError {
    fn from(error: io::Error) -> Self {
        if error.kind() == ErrorKind::BrokenPipe {
            Self::BrokenPipe
        } else {
            Self::Io(error)
        }
    }
}

impl From<PublicOutputError> for OutputError {
    fn from(error: PublicOutputError) -> Self {
        if error.io_error_kind() == Some(ErrorKind::BrokenPipe) {
            Self::BrokenPipe
        } else {
            Self::Public(error)
        }
    }
}

fn output_failure(diagnostics: &mut impl Write, error: &OutputError) -> ExitReason {
    let message = match error {
        OutputError::BrokenPipe => return ExitReason::Success,
        OutputError::Io(error) => format!("writing watch output failed: {error}"),
        OutputError::Public(PublicOutputError::Io(error)) => {
            format!("writing watch output failed: {error}")
        }
        OutputError::Public(error @ PublicOutputError::Serialization(_)) => {
            format!("serializing watch event failed: {error}")
        }
        OutputError::Public(error) => format!("preparing watch event failed: {error}"),
        OutputError::EventLimit => "watch event exceeded its 64 KiB record limit".to_owned(),
    };
    write_diagnostic(diagnostics, &message);
    ExitReason::Failure
}

fn io_failure(diagnostics: &mut impl Write, error: &io::Error) -> ExitReason {
    if error.kind() == ErrorKind::BrokenPipe {
        ExitReason::Success
    } else {
        write_diagnostic(
            diagnostics,
            &format!("writing watch output failed: {error}"),
        );
        ExitReason::Failure
    }
}

fn flush_exit(
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    reason: ExitReason,
) -> ExitReason {
    match output.flush() {
        Ok(()) => reason,
        Err(error) if error.kind() == ErrorKind::BrokenPipe => ExitReason::Success,
        Err(error) => io_failure(diagnostics, &error),
    }
}

fn clock_failure(diagnostics: &mut impl Write, error: &ObservationError) -> ExitReason {
    write_diagnostic(diagnostics, &format!("wall clock failed: {error}"));
    ExitReason::Failure
}

fn write_diagnostic(writer: &mut impl Write, message: &str) {
    let _ = writeln!(writer, "error: {}", sanitize(message));
    let _ = writer.flush();
}

fn validate_wall_interval(
    started: SystemTime,
    completed: SystemTime,
) -> Result<(), ObservationError> {
    completed
        .duration_since(started)
        .map(|_| ())
        .map_err(|_| ObservationError::InvalidWallClockInterval)
}

const fn owner_pid(owner: &OwnerObservation) -> u32 {
    match owner {
        OwnerObservation::Verified(identity) => identity.pid,
        OwnerObservation::UnverifiedPid { pid, .. } => *pid,
    }
}

fn collector_error_code(error: &CollectorError) -> &'static str {
    match error {
        #[cfg(target_os = "linux")]
        CollectorError::Read { source, .. } if source.kind() == ErrorKind::PermissionDenied => {
            "socket_table_permission_denied"
        }
        #[cfg(target_os = "linux")]
        CollectorError::Read { .. } => "socket_table_unavailable",
        #[cfg(any(target_os = "macos", windows))]
        CollectorError::Platform { .. } => "platform_api_failed",
        CollectorError::WorkerExited => "platform_api_failed",
        CollectorError::OwnershipPermissionDenied => "socket_table_permission_denied",
        CollectorError::Observation(error) => observation_error_code(error),
    }
}

fn collector_clock_error(
    result: &Result<NetworkSnapshot, CollectorError>,
) -> Option<&ObservationError> {
    match result {
        Err(CollectorError::Observation(
            error @ (ObservationError::ClockUnavailable
            | ObservationError::InvalidWallClockInterval),
        )) => Some(error),
        _ => None,
    }
}

const fn observation_error_code(error: &ObservationError) -> &'static str {
    match error {
        ObservationError::SocketTableUnavailable => "socket_table_unavailable",
        ObservationError::SocketTablePermissionDenied => "socket_table_permission_denied",
        ObservationError::NativeDataMalformed => "native_data_malformed",
        ObservationError::NativeDataOversized
        | ObservationError::ScopeIdentifierOversized
        | ObservationError::ScopeLimitationLimitExceeded => "native_data_oversized",
        ObservationError::SocketObservationLimitExceeded => "socket_observation_limit_exceeded",
        ObservationError::ProcessIdentityLimitExceeded => "process_identity_limit_exceeded",
        ObservationError::OwnerAttributionLimitExceeded => "owner_attribution_limit_exceeded",
        ObservationError::LegacyProjectionLimitExceeded => "legacy_projection_limit_exceeded",
        ObservationError::PlatformApiFailed(_) => "platform_api_failed",
        ObservationError::ClockUnavailable | ObservationError::InvalidWallClockInterval => {
            "clock_unavailable"
        }
        ObservationError::PartialSocketSet => "partial_socket_set",
        ObservationError::ObservationRaced => "observation_raced",
        ObservationError::OwnerReasonLimitExceeded => "owner_reason_limit_exceeded",
    }
}

static WATCH_CANCELLED: AtomicBool = AtomicBool::new(false);
static WATCH_STARTING: AtomicBool = AtomicBool::new(false);

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct WatchSignalGuard {
    previous: libc::sigaction,
    startup: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" fn handle_sigint(_: libc::c_int) {
    if WATCH_STARTING.load(Ordering::Relaxed) {
        // SAFETY: `_exit` is async-signal-safe and startup has not emitted output
        // or acquired resources that require process-local cleanup.
        unsafe { libc::_exit(0) }
    }
    WATCH_CANCELLED.store(true, Ordering::Relaxed);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl WatchSignalGuard {
    pub(crate) fn install() -> io::Result<Self> {
        WATCH_CANCELLED.store(false, Ordering::Relaxed);
        WATCH_STARTING.store(true, Ordering::Relaxed);
        // SAFETY: sigaction structures are initialized before use, the handler only
        // uses lock-free atomics or async-signal-safe `_exit`, and the previous
        // process action is retained.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handle_sigint as *const () as usize;
            libc::sigemptyset(&raw mut action.sa_mask);
            action.sa_flags = 0;
            let mut previous: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &raw const action, &raw mut previous) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                previous,
                startup: true,
            })
        }
    }

    fn activate_loop(&mut self) {
        debug_assert!(self.startup, "watch signal startup mode changes only once");
        self.startup = false;
        WATCH_STARTING.store(false, Ordering::Relaxed);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for WatchSignalGuard {
    fn drop(&mut self) {
        WATCH_STARTING.store(false, Ordering::Relaxed);
        // SAFETY: `previous` came from a successful sigaction call and remains valid.
        unsafe {
            libc::sigaction(libc::SIGINT, &raw const self.previous, std::ptr::null_mut());
        }
    }
}

#[cfg(windows)]
pub(crate) struct WatchSignalGuard {
    startup: bool,
}

#[cfg(windows)]
unsafe extern "system" fn handle_console_control(control: u32) -> i32 {
    use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
    if matches!(control, CTRL_C_EVENT | CTRL_BREAK_EVENT) {
        if WATCH_STARTING.load(Ordering::Relaxed) {
            // SAFETY: startup has not emitted output or acquired resources that
            // require process-local cleanup.
            unsafe { windows_sys::Win32::System::Threading::ExitProcess(0) }
        }
        WATCH_CANCELLED.store(true, Ordering::Relaxed);
        1
    } else {
        0
    }
}

#[cfg(windows)]
impl WatchSignalGuard {
    pub(crate) fn install() -> io::Result<Self> {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        WATCH_CANCELLED.store(false, Ordering::Relaxed);
        WATCH_STARTING.store(true, Ordering::Relaxed);
        // SAFETY: the handler has static lifetime and performs only an atomic store.
        if unsafe { SetConsoleCtrlHandler(Some(handle_console_control), 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { startup: true })
    }

    fn activate_loop(&mut self) {
        debug_assert!(self.startup, "watch signal startup mode changes only once");
        self.startup = false;
        WATCH_STARTING.store(false, Ordering::Relaxed);
    }
}

#[cfg(windows)]
impl Drop for WatchSignalGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
        WATCH_STARTING.store(false, Ordering::Relaxed);
        // SAFETY: unregisters the exact static handler installed by this guard.
        unsafe {
            SetConsoleCtrlHandler(Some(handle_console_control), 0);
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) struct WatchSignalGuard {
    startup: bool,
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
impl WatchSignalGuard {
    pub(crate) fn install() -> io::Result<Self> {
        Ok(Self { startup: true })
    }

    fn activate_loop(&mut self) {
        debug_assert!(self.startup, "watch signal startup mode changes only once");
        self.startup = false;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::{self, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime};

    use super::{
        BoundedRecord, FilterCache, FilterResult, GapIndex, ObservationTimes, OwnerPidConstraint,
        Truth, WATCH_DURATION_MAX, WATCH_DURATION_MIN, WATCH_INTERVAL_DEFAULT, WATCH_INTERVAL_MAX,
        WATCH_INTERVAL_MIN, WatchArgs, WatchOptions, WatchRuntime, evaluate_event, evaluate_side,
        human_endpoint_text, parse_duration_token, run_watch_loop, write_human_event,
        write_ordered_events,
    };
    use crate::cli::ExitReason;
    use crate::collector::{Collector, CollectorError, FakeCollector};
    use crate::config::Config;
    use crate::labels::{LabelInput, LabelRegistry};
    use crate::observation::{
        EndpointIdentity, EvidenceGap, EvidenceGapCode, EvidenceImpact, Ipv6Scope,
        MetadataCompleteness, MetadataProfile, NetworkSnapshot, ObservationError,
        OwnerCompleteness, OwnerObservation, ProcessIdentity, ProcessObservation,
        ProcessStartMarker, Protocol, SnapshotCompleteness, UnverifiedOwnerReason,
    };
    use crate::query::QueryCapabilities;
    use crate::watch::{Certainty, EventKind, WatchEvent, baseline_events, diff_snapshots};

    #[test]
    fn duration_parser_accepts_boundaries_and_rejects_noncanonical_tokens() {
        assert_eq!(
            parse_duration_token("100ms", WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).unwrap(),
            WATCH_INTERVAL_MIN
        );
        assert_eq!(
            parse_duration_token("60s", WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).unwrap(),
            WATCH_INTERVAL_MAX
        );
        assert_eq!(
            parse_duration_token("7d", WATCH_DURATION_MIN, WATCH_DURATION_MAX).unwrap(),
            WATCH_DURATION_MAX
        );
        assert!(parse_duration_token("99ms", WATCH_DURATION_MIN, WATCH_DURATION_MAX).is_err());
        assert!(
            parse_duration_token("604800001ms", WATCH_DURATION_MIN, WATCH_DURATION_MAX,).is_err()
        );
        for invalid in [
            "0ms", "99ms", "60001ms", "-1s", "+1s", "1.5s", "1M", "1m30s", "1 s",
        ] {
            assert!(
                parse_duration_token(invalid, WATCH_INTERVAL_MIN, WATCH_INTERVAL_MAX).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn default_interval_is_one_second_and_scope_requires_ipv6_address() {
        let args = WatchArgs {
            tcp: false,
            udp: false,
            address: None,
            scope_id: None,
            port: None,
            filter: None,
            interval: "1s".to_owned(),
            duration: Some("100ms".to_owned()),
            json: true,
        };
        assert_eq!(
            WatchOptions::parse(&args).unwrap().interval,
            WATCH_INTERVAL_DEFAULT
        );
        let invalid = WatchArgs {
            scope_id: Some(1),
            ..args
        };
        assert!(WatchOptions::parse(&invalid).is_err());
    }

    struct FakeRuntime {
        snapshots: VecDeque<Result<NetworkSnapshot, CollectorError>>,
        monotonic: Duration,
        wall: SystemTime,
        cancelled: bool,
        cancel_at: Option<Duration>,
        collection_durations: VecDeque<Duration>,
        monotonic_step: Duration,
        collect_count: usize,
        wall_count: usize,
        wall_fail_on: Option<usize>,
        wall_values: VecDeque<Result<SystemTime, ObservationError>>,
    }

    impl FakeRuntime {
        fn new(snapshots: Vec<Result<NetworkSnapshot, CollectorError>>) -> Self {
            Self {
                snapshots: snapshots.into(),
                monotonic: Duration::ZERO,
                wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
                cancelled: false,
                cancel_at: None,
                collection_durations: VecDeque::new(),
                monotonic_step: Duration::ZERO,
                collect_count: 0,
                wall_count: 0,
                wall_fail_on: None,
                wall_values: VecDeque::new(),
            }
        }
    }

    impl WatchRuntime for FakeRuntime {
        fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError> {
            self.collect_count += 1;
            self.monotonic += self.collection_durations.pop_front().unwrap_or_default();
            if self
                .cancel_at
                .is_some_and(|deadline| self.monotonic >= deadline)
            {
                self.cancelled = true;
            }
            self.snapshots
                .pop_front()
                .unwrap_or_else(|| Err(ObservationError::SocketTableUnavailable.into()))
        }

        fn monotonic_now(&mut self) -> Duration {
            let now = self.monotonic;
            self.monotonic += self.monotonic_step;
            now
        }

        fn wall_now(&mut self) -> Result<SystemTime, ObservationError> {
            self.wall_count += 1;
            if let Some(value) = self.wall_values.pop_front() {
                return value;
            }
            if self.wall_fail_on == Some(self.wall_count) {
                return Err(ObservationError::ClockUnavailable);
            }
            self.wall += Duration::from_millis(1);
            Ok(self.wall)
        }

        fn sleep(&mut self, duration: Duration) {
            self.monotonic += duration;
            if self
                .cancel_at
                .is_some_and(|deadline| self.monotonic >= deadline)
            {
                self.cancelled = true;
            }
        }

        fn cancelled(&self) -> bool {
            self.cancelled
        }
    }

    fn snapshot() -> NetworkSnapshot {
        FakeCollector
            .collect(MetadataProfile::Display)
            .expect("fake snapshot is valid")
    }

    fn options(duration: Duration) -> WatchOptions {
        WatchOptions {
            tcp: true,
            udp: true,
            address: None,
            scope_id: None,
            port: Some(65_535),
            terms: Vec::new(),
            filter_active: true,
            interval: WATCH_INTERVAL_MIN,
            duration: Some(duration),
            json: true,
        }
    }

    fn filtered_options(text: &str) -> WatchOptions {
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms = crate::query::parse_filter_text(text, QueryCapabilities::WATCH).unwrap();
        filter
    }

    fn owned_snapshot(
        pid: u32,
        name: Option<&str>,
        metadata: MetadataCompleteness,
    ) -> NetworkSnapshot {
        let mut observed = snapshot();
        observed.sockets.truncate(1);
        observed.processes.clear();
        let identity = ProcessIdentity {
            pid,
            start_marker: ProcessStartMarker::linux(u64::from(pid) + 1).unwrap(),
        };
        observed.sockets[0].owners = vec![OwnerObservation::Verified(identity)];
        observed.processes.insert(
            identity,
            ProcessObservation {
                name: name.map(Into::into),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: metadata,
            },
        );
        observed
    }

    #[test]
    fn event_filter_uses_the_documented_side_and_three_valued_matrix() {
        let previous = owned_snapshot(10, Some("alpha"), MetadataCompleteness::Complete);
        let current = owned_snapshot(20, Some("beta"), MetadataCompleteness::Complete);
        let config = Config::default();
        let event = |kind| WatchEvent {
            kind,
            previous_snapshot: (kind != EventKind::Baseline).then_some(&previous),
            current_snapshot: (kind != EventKind::Release).then_some(&current),
            previous_socket: matches!(kind, EventKind::Release | EventKind::Replacement)
                .then_some(&previous.sockets[0]),
            current_socket: matches!(
                kind,
                EventKind::Baseline | EventKind::Bind | EventKind::Replacement
            )
            .then_some(&current.sockets[0]),
            multiplicity: 1,
            certainty: Certainty::Proven,
        };

        for kind in [EventKind::Baseline, EventKind::Bind] {
            assert_eq!(
                evaluate_event(
                    event(kind),
                    &filtered_options("pid:20 beta"),
                    &config,
                    None,
                    Some(&mut FilterCache::default()),
                ),
                Some(FilterResult::Matched),
                "{kind:?} must use current facts"
            );
        }
        assert_eq!(
            evaluate_event(
                event(EventKind::Release),
                &filtered_options("pid:10 alpha"),
                &config,
                Some(&mut FilterCache::default()),
                None,
            ),
            Some(FilterResult::Matched)
        );
        for text in ["pid:10 alpha", "pid:20 beta"] {
            assert_eq!(
                evaluate_event(
                    event(EventKind::Replacement),
                    &filtered_options(text),
                    &config,
                    Some(&mut FilterCache::default()),
                    Some(&mut FilterCache::default()),
                ),
                Some(FilterResult::Matched),
                "replacement must match either complete side"
            );
        }

        let unknown = owned_snapshot(20, None, MetadataCompleteness::Partial);
        let unknown_event = WatchEvent {
            current_snapshot: Some(&unknown),
            current_socket: Some(&unknown.sockets[0]),
            ..event(EventKind::Bind)
        };
        assert_eq!(
            evaluate_event(
                unknown_event,
                &filtered_options("missing"),
                &config,
                None,
                Some(&mut FilterCache::default()),
            ),
            Some(FilterResult::Indeterminate)
        );
        assert_eq!(
            evaluate_event(
                unknown_event,
                &filtered_options("port:1 missing"),
                &config,
                None,
                Some(&mut FilterCache::default()),
            ),
            None,
            "a definite false term suppresses an otherwise unknown event"
        );
    }

    #[test]
    fn owner_terms_must_be_satisfied_by_the_same_owner() {
        let mut observed = owned_snapshot(10, Some("alpha"), MetadataCompleteness::Complete);
        let second = ProcessIdentity {
            pid: 20,
            start_marker: ProcessStartMarker::linux(21).unwrap(),
        };
        observed.sockets[0]
            .owners
            .push(OwnerObservation::Verified(second));
        observed.processes.insert(
            second,
            ProcessObservation {
                name: Some("beta".into()),
                executable_path: None,
                command_line: None,
                parent_pid: None,
                parent_process_name: None,
                metadata_omission: None,
                metadata_completeness: MetadataCompleteness::Complete,
            },
        );

        assert_eq!(
            evaluate_side(
                &observed,
                &observed.sockets[0],
                &filtered_options("pid:10 beta"),
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::False
        );
        assert_eq!(
            evaluate_side(
                &observed,
                &observed.sockets[0],
                &filtered_options("pid:10 alpha"),
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::True
        );
    }

    #[test]
    fn third_consecutive_failure_flushes_three_gaps_and_stops_collection() {
        let snapshots = vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Ok(snapshot()),
        ];
        let mut runtime = FakeRuntime::new(snapshots);
        let mut stdout = BufferedTrackingWriter::default();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_secs(1)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert_eq!(runtime.collect_count, 4);
        assert_eq!(stdout.flush_count, 4);
        assert!(stdout.pending.is_empty());
        let records = String::from_utf8(stdout.committed).unwrap();
        let values = records
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 3);
        assert!(
            values
                .iter()
                .all(|value| value["event"] == "collection_gap")
        );
        assert_eq!(values[0]["schema"], "kickoutchi.watch_event");
        assert_eq!(values[0]["version"], 1);
        assert_eq!(values[0]["sequence"], 0);
        assert!(values[0]["observation"]["previous_completed_unix_ms"].is_number());
        assert!(values[0]["observation"]["attempt_started_unix_ms"].is_number());
        assert!(values[0]["observation"]["attempt_completed_unix_ms"].is_number());
        assert_eq!(values[0]["data"]["certainty"], "unknown");
        assert!(values[0]["data"]["completeness"].is_null());
        assert_eq!(values[0]["data"]["evidence_gaps"], serde_json::json!([]));
        assert_eq!(values[0]["data"]["omitted_evidence_gap_count"], 0);
        assert_eq!(values[2]["data"]["consecutive_failures"], 3);
        assert!(stderr.is_empty());
    }

    #[test]
    fn failed_collection_waits_a_full_interval_after_slow_completion() {
        let snapshots = vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ];
        let mut runtime = FakeRuntime::new(snapshots);
        runtime.collection_durations = [
            Duration::ZERO,
            Duration::from_millis(200),
            Duration::ZERO,
            Duration::ZERO,
        ]
        .into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_secs(2)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert_eq!(runtime.monotonic, Duration::from_millis(500));
        assert!(stderr.is_empty());
    }

    #[test]
    fn recovery_uses_the_last_valid_snapshot_without_fabricated_releases() {
        let baseline = snapshot();
        let snapshots = vec![
            Ok(baseline.clone()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Ok(baseline),
        ];
        let mut runtime = FakeRuntime::new(snapshots);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(250)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(runtime.collect_count, 3);
        let records = String::from_utf8(stdout).unwrap();
        let events = records
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect::<Vec<_>>();
        assert_eq!(events, ["collection_gap"]);
        assert!(stderr.is_empty());
    }

    #[test]
    fn ownership_and_metadata_partial_snapshot_advances_the_comparison_baseline() {
        let mut first = snapshot();
        first.sockets.truncate(1);
        first.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(10);
        first.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(11);
        let mut partial = snapshot();
        partial.sockets = vec![partial.sockets[1].clone()];
        partial.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(20);
        partial.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(21);
        partial.completeness = SnapshotCompleteness::Partial;
        partial.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        partial.processes.values_mut().for_each(|process| {
            process.metadata_completeness = MetadataCompleteness::Partial;
        });
        let mut final_snapshot = first.clone();
        final_snapshot.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(30);
        final_snapshot.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(31);
        let mut runtime = FakeRuntime::new(vec![Ok(first), Ok(partial), Ok(final_snapshot)]);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let mut watch_options = options(Duration::from_millis(250));
        watch_options.port = None;
        watch_options.filter_active = false;

        let reason = run_watch_loop(
            &watch_options,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Success);
        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect::<Vec<_>>();
        assert_eq!(events, ["baseline", "release", "bind", "bind", "release"]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn unsafe_snapshot_does_not_advance_the_comparison_baseline() {
        let mut first = snapshot();
        first.sockets.truncate(1);
        first.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(10);
        first.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(11);
        let mut changed = snapshot();
        changed.sockets = vec![changed.sockets[1].clone()];
        changed.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(20);
        changed.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(21);
        let mut unsafe_snapshot = changed.clone();
        unsafe_snapshot.completeness = SnapshotCompleteness::Partial;
        unsafe_snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "socket set incomplete",
        ));
        changed.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_millis(30);
        changed.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_millis(31);
        let mut runtime = FakeRuntime::new(vec![Ok(first), Ok(unsafe_snapshot), Ok(changed)]);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let mut watch_options = options(Duration::from_millis(250));
        watch_options.port = None;
        watch_options.filter_active = false;

        let reason = run_watch_loop(
            &watch_options,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Success);
        let events = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap()["event"].clone())
            .collect::<Vec<_>>();
        assert_eq!(events, ["baseline", "collection_gap", "release", "bind"]);
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn successful_poll_resets_the_failure_budget() {
        let observed = snapshot();
        let mut runtime = FakeRuntime::new(vec![
            Ok(observed.clone()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Ok(observed),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let reason = run_watch_loop(
            &options(Duration::from_millis(450)),
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(runtime.collect_count, 5);
        let failures = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["data"]
                    ["consecutive_failures"]
                    .as_u64()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(failures, [1, 1, 2]);
        assert!(diagnostics.is_empty());
    }

    struct FailingWriter {
        kind: io::ErrorKind,
    }

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(self.kind, "injected writer failure"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushFailWriter {
        kind: io::ErrorKind,
    }

    #[derive(Default)]
    struct BufferedTrackingWriter {
        pending: Vec<u8>,
        committed: Vec<u8>,
        flush_count: usize,
    }

    impl Write for BufferedTrackingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flush_count += 1;
            self.committed.append(&mut self.pending);
            Ok(())
        }
    }

    impl Write for FlushFailWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(self.kind, "injected flush failure"))
        }
    }

    #[test]
    fn broken_pipe_is_success_and_other_writer_failures_are_operational() {
        let mut broken_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        let mut broken = FailingWriter {
            kind: io::ErrorKind::BrokenPipe,
        };
        let mut diagnostics = Vec::new();
        let mut unfiltered = options(Duration::from_millis(100));
        unfiltered.port = None;
        unfiltered.filter_active = false;
        assert_eq!(
            run_watch_loop(
                &unfiltered,
                &Config::default(),
                &mut broken_runtime,
                &mut broken,
                &mut diagnostics,
            ),
            ExitReason::Success
        );
        assert!(diagnostics.is_empty());

        let mut failed_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        let mut failed = FailingWriter {
            kind: io::ErrorKind::Other,
        };
        assert_eq!(
            run_watch_loop(
                &unfiltered,
                &Config::default(),
                &mut failed_runtime,
                &mut failed,
                &mut diagnostics,
            ),
            ExitReason::Failure
        );
        assert!(
            String::from_utf8(diagnostics)
                .unwrap()
                .contains("writing watch output failed")
        );

        let mut flush_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        let mut flush_broken = FlushFailWriter {
            kind: io::ErrorKind::BrokenPipe,
        };
        let mut flush_diagnostics = Vec::new();
        let filtered = options(Duration::from_millis(100));
        assert_eq!(
            run_watch_loop(
                &filtered,
                &Config::default(),
                &mut flush_runtime,
                &mut flush_broken,
                &mut flush_diagnostics,
            ),
            ExitReason::Success
        );
        assert!(flush_diagnostics.is_empty());

        let mut flush_failed_runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        let mut flush_failed = FlushFailWriter {
            kind: io::ErrorKind::Other,
        };
        let mut flush_failed_diagnostics = Vec::new();
        assert_eq!(
            run_watch_loop(
                &filtered,
                &Config::default(),
                &mut flush_failed_runtime,
                &mut flush_failed,
                &mut flush_failed_diagnostics,
            ),
            ExitReason::Failure
        );
        assert!(
            String::from_utf8(flush_failed_diagnostics)
                .unwrap()
                .contains("injected flush failure")
        );
    }

    #[test]
    fn no_duration_watch_stops_on_injected_cancellation_without_an_extra_collection() {
        let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        runtime.cancel_at = Some(Duration::from_millis(25));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut watch_options = options(Duration::from_millis(100));
        watch_options.duration = None;

        let result = run_watch_loop(
            &watch_options,
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(runtime.collect_count, 1);
        assert!(stdout.is_empty());
        assert!(stderr.is_empty());
    }

    #[test]
    fn initial_collection_failure_emits_no_record_and_one_diagnostic() {
        let mut runtime =
            FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(100)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        let diagnostic = String::from_utf8(stderr).unwrap();
        assert_eq!(diagnostic.lines().count(), 1);
        assert!(diagnostic.contains("initial collection failed"));
    }

    #[test]
    fn slow_initial_collection_failure_is_not_masked_by_duration_expiry() {
        let mut runtime =
            FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
        runtime.collection_durations = [Duration::from_millis(200)].into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(100)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("initial collection failed")
        );
    }

    #[test]
    fn cancellation_during_initial_failure_does_not_mask_the_error() {
        let mut runtime =
            FakeRuntime::new(vec![Err(ObservationError::SocketTableUnavailable.into())]);
        runtime.collection_durations = [Duration::from_millis(200)].into();
        runtime.cancel_at = Some(Duration::from_millis(100));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_secs(1)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("initial collection failed")
        );
    }

    #[test]
    fn failed_poll_crossing_duration_emits_and_flushes_its_gap() {
        let mut runtime = FakeRuntime::new(vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(250)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(runtime.collect_count, 2);
        let records = String::from_utf8(stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
        assert_eq!(value["event"], "collection_gap");
        assert_eq!(value["data"]["error"]["code"], "socket_table_unavailable");
        assert!(stderr.is_empty());
    }

    #[test]
    fn unsafe_poll_crossing_duration_emits_and_flushes_its_gap() {
        let mut raced = snapshot();
        raced.completeness = SnapshotCompleteness::Raced;
        let mut partial = snapshot();
        partial.completeness = SnapshotCompleteness::Partial;
        partial.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            None,
            "injected partial socket set",
        ));

        for (unsafe_snapshot, expected_code) in [
            (raced, "observation_raced"),
            (partial, "partial_socket_set"),
        ] {
            let mut runtime = FakeRuntime::new(vec![Ok(snapshot()), Ok(unsafe_snapshot)]);
            runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            let result = run_watch_loop(
                &options(Duration::from_millis(250)),
                &Config::default(),
                &mut runtime,
                &mut stdout,
                &mut stderr,
            );

            assert_eq!(result, ExitReason::Success);
            assert_eq!(runtime.collect_count, 2);
            let records = String::from_utf8(stdout).unwrap();
            let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
            assert_eq!(value["event"], "collection_gap");
            assert_eq!(value["data"]["error"]["code"], expected_code);
            assert!(stderr.is_empty());
        }
    }

    #[test]
    fn third_failed_poll_crossing_duration_exhausts_the_failure_budget() {
        let mut runtime = FakeRuntime::new(vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        runtime.collection_durations = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_millis(200),
        ]
        .into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(450)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert_eq!(runtime.collect_count, 4);
        assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 3);
        assert!(stderr.is_empty());
    }

    #[test]
    fn cancellation_during_third_failed_poll_does_not_mask_budget_exhaustion() {
        let mut runtime = FakeRuntime::new(vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        runtime.collection_durations = [
            Duration::ZERO,
            Duration::ZERO,
            Duration::ZERO,
            Duration::from_millis(200),
        ]
        .into();
        runtime.cancel_at = Some(Duration::from_millis(350));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_secs(1)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert_eq!(runtime.collect_count, 4);
        assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 3);
        assert!(stderr.is_empty());
    }

    #[test]
    fn cancellation_during_failed_poll_exits_cleanly_after_its_gap() {
        let mut runtime = FakeRuntime::new(vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        runtime.collection_durations = [Duration::ZERO, Duration::from_millis(200)].into();
        runtime.cancel_at = Some(Duration::from_millis(150));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_secs(1)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(runtime.collect_count, 2);
        let records = String::from_utf8(stdout).unwrap();
        let value: serde_json::Value = serde_json::from_str(records.trim()).unwrap();
        assert_eq!(value["event"], "collection_gap");
        assert!(stderr.is_empty());
    }

    #[test]
    fn wall_clock_failure_after_baseline_emits_no_gap() {
        let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        runtime.wall_fail_on = Some(3);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(200)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("wall clock failed")
        );
    }

    #[test]
    fn reversed_failed_poll_interval_is_an_immediate_clock_failure() {
        let mut runtime = FakeRuntime::new(vec![
            Ok(snapshot()),
            Err(ObservationError::SocketTableUnavailable.into()),
        ]);
        runtime.wall_values = [
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(2)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(4)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(3)),
        ]
        .into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(200)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("wall clock failed")
        );
    }

    #[test]
    fn reversed_interval_between_successful_snapshots_is_a_clock_failure() {
        let mut previous = snapshot();
        previous.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(9);
        previous.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let mut current = snapshot();
        current.capture_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(5);
        current.capture_completed_at = SystemTime::UNIX_EPOCH + Duration::from_secs(6);
        let mut runtime = FakeRuntime::new(vec![Ok(previous), Ok(current)]);
        runtime.wall_values = [
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(1)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(2)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(11)),
            Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(12)),
        ]
        .into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(200)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("wall clock failed")
        );
    }

    #[test]
    fn collector_clock_failure_is_immediate_and_never_becomes_a_gap() {
        let mut runtime = FakeRuntime::new(vec![Err(ObservationError::ClockUnavailable.into())]);
        runtime.collection_durations = [Duration::from_millis(200)].into();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let result = run_watch_loop(
            &options(Duration::from_millis(200)),
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Failure);
        assert!(stdout.is_empty());
        assert_eq!(runtime.collect_count, 1);
        assert!(
            String::from_utf8(stderr)
                .unwrap()
                .contains("wall clock failed")
        );
    }

    #[test]
    fn duration_is_checked_between_baseline_events() {
        let mut runtime = FakeRuntime::new(vec![Ok(snapshot())]);
        runtime.monotonic_step = Duration::from_millis(10);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut unfiltered = options(Duration::from_millis(25));
        unfiltered.port = None;
        unfiltered.filter_active = false;

        let result = run_watch_loop(
            &unfiltered,
            &Config::default(),
            &mut runtime,
            &mut stdout,
            &mut stderr,
        );

        assert_eq!(result, ExitReason::Success);
        assert_eq!(String::from_utf8(stdout).unwrap().lines().count(), 1);
        assert!(stderr.is_empty());
    }

    #[test]
    fn unverified_owner_pid_plain_search_matches_without_metadata() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.sockets[0].owners = vec![OwnerObservation::UnverifiedPid {
            pid: 4_242,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        }];
        snapshot.sockets[0].owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::ProcessIdentityUnavailable]).unwrap();
        snapshot.owner_completeness = snapshot.sockets[0].owner_completeness.clone();
        snapshot.completeness = SnapshotCompleteness::Partial;
        let terms = crate::query::parse_filter_text("4242", QueryCapabilities::WATCH).unwrap();
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms = terms;

        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut super::FilterCache::default(),
            ),
            Truth::True
        );
    }

    #[test]
    fn partial_ownership_cannot_override_a_false_endpoint_term() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.sockets[0].owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        snapshot.owner_completeness = snapshot.sockets[0].owner_completeness.clone();
        snapshot.completeness = SnapshotCompleteness::Partial;
        let impossible_port = if snapshot.sockets[0].local_endpoint.port.get() == 1 {
            2
        } else {
            1
        };
        let terms = crate::query::parse_filter_text(
            &format!("port:{impossible_port}"),
            QueryCapabilities::WATCH,
        )
        .unwrap();
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms = terms;

        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut super::FilterCache::default(),
            ),
            Truth::False
        );
    }

    #[test]
    fn global_ownership_gap_makes_owner_dependent_miss_indeterminate() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        snapshot.completeness = SnapshotCompleteness::Partial;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerAttributionIncomplete,
            None,
            None,
            "an owner could not be attributed to an endpoint",
        ));
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms =
            crate::query::parse_filter_text("pid:4294967295", QueryCapabilities::WATCH).unwrap();

        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::Unknown
        );

        filter.terms = crate::query::parse_filter_text(
            &format!("port:{}", snapshot.sockets[0].local_endpoint.port),
            QueryCapabilities::WATCH,
        )
        .unwrap();
        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::True,
            "global owner uncertainty must not weaken endpoint-only filters"
        );
    }

    #[test]
    fn pid_scoped_ownership_gap_is_indeterminate_and_emitted_for_hidden_owner() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
        snapshot.completeness = SnapshotCompleteness::Partial;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(4_242),
            "permission denied before the PID's socket ownership could be attributed",
        ));
        let filter = filtered_options("pid:4242");
        let event = WatchEvent {
            kind: EventKind::Baseline,
            previous_snapshot: None,
            current_snapshot: Some(&snapshot),
            previous_socket: None,
            current_socket: Some(&snapshot.sockets[0]),
            multiplicity: 1,
            certainty: Certainty::Proven,
        };

        assert_eq!(
            evaluate_event(
                event,
                &filter,
                &Config::default(),
                None,
                Some(&mut FilterCache::default()),
            ),
            Some(FilterResult::Indeterminate)
        );
        assert_eq!(
            evaluate_event(
                event,
                &filtered_options("pid:9999"),
                &Config::default(),
                None,
                Some(&mut FilterCache::default()),
            ),
            None,
            "a PID-scoped gap must not weaken a filter for a different PID"
        );

        let gap_index = GapIndex::new(&snapshot);
        let mut output = Vec::new();
        super::write_endpoint_event(
            &mut output,
            true,
            0,
            ObservationTimes {
                previous_completed_unix_ms: None,
                attempt_started_unix_ms: 1,
                attempt_completed_unix_ms: 2,
            },
            event,
            FilterResult::Indeterminate,
            &filter.terms,
            &Config::default(),
            None,
            Some(&gap_index),
        )
        .unwrap();

        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["data"]["filter_result"], "indeterminate");
        assert_eq!(value["data"]["evidence_gaps"].as_array().unwrap().len(), 1);
        assert_eq!(value["data"]["evidence_gaps"][0]["impact"], "ownership");
        assert_eq!(
            value["data"]["evidence_gaps"][0]["code"],
            "owner_permission_denied"
        );
        assert_eq!(value["data"]["evidence_gaps"][0]["pid"], 4_242);
    }

    #[test]
    fn omitted_ownership_gap_keeps_pid_filter_indeterminate_and_counts_the_gap() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerPermissionDenied]).unwrap();
        snapshot.completeness = SnapshotCompleteness::Partial;
        snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Ownership,
            EvidenceGapCode::OwnerPermissionDenied,
            None,
            Some(9_999),
            "an unrelated retained PID could not be scanned",
        ));
        snapshot.omitted_evidence_gap_count = 1;
        let filter = filtered_options("pid:4242");
        let event = WatchEvent {
            kind: EventKind::Baseline,
            previous_snapshot: None,
            current_snapshot: Some(&snapshot),
            previous_socket: None,
            current_socket: Some(&snapshot.sockets[0]),
            multiplicity: 1,
            certainty: Certainty::Proven,
        };

        assert_eq!(
            evaluate_event(
                event,
                &filter,
                &Config::default(),
                None,
                Some(&mut FilterCache::default()),
            ),
            Some(FilterResult::Indeterminate)
        );

        let gap_index = GapIndex::new(&snapshot);
        let mut output = Vec::new();
        super::write_endpoint_event(
            &mut output,
            true,
            0,
            ObservationTimes {
                previous_completed_unix_ms: None,
                attempt_started_unix_ms: 1,
                attempt_completed_unix_ms: 2,
            },
            event,
            FilterResult::Indeterminate,
            &filter.terms,
            &Config::default(),
            None,
            Some(&gap_index),
        )
        .unwrap();

        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["data"]["filter_result"], "indeterminate");
        assert_eq!(value["data"]["evidence_gaps"], serde_json::json!([]));
        assert_eq!(value["data"]["omitted_evidence_gap_count"], 1);
    }

    #[test]
    fn complete_ownerless_socket_matches_protected_false() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.sockets[0].owners.clear();
        snapshot.sockets[0].owner_completeness = OwnerCompleteness::Complete;
        snapshot.owner_completeness = OwnerCompleteness::Complete;
        snapshot.completeness = SnapshotCompleteness::Complete;
        let mut filter = options(Duration::from_millis(100));
        filter.port = None;
        filter.terms =
            crate::query::parse_filter_text("protected:false", QueryCapabilities::WATCH).unwrap();

        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::True
        );
        filter.terms =
            crate::query::parse_filter_text("protected:true", QueryCapabilities::WATCH).unwrap();
        assert_eq!(
            evaluate_side(
                &snapshot,
                &snapshot.sockets[0],
                &filter,
                &Config::default(),
                &mut FilterCache::default(),
            ),
            Truth::False
        );
    }

    #[test]
    fn protection_filters_use_an_available_name_despite_unrelated_metadata_gaps() {
        let mut snapshot = snapshot();
        let protected_index = snapshot
            .sockets
            .iter()
            .position(|socket| socket.local_endpoint.port.get() == 5_432)
            .expect("fixture has the partial-metadata postgres socket");
        let unprotected_index = snapshot
            .sockets
            .iter()
            .position(|socket| socket.local_endpoint.port.get() == 3_000)
            .expect("fixture has the node socket");
        let unprotected_identity = match snapshot.sockets[unprotected_index].owners.as_slice() {
            [OwnerObservation::Verified(identity)] => *identity,
            _ => panic!("fixture node socket has one verified owner"),
        };
        snapshot
            .processes
            .get_mut(&unprotected_identity)
            .expect("fixture node metadata exists")
            .metadata_completeness = MetadataCompleteness::Partial;
        let config = Config::default();

        let evaluate = |socket_index: usize, text: &str| {
            let mut filter = options(Duration::from_millis(100));
            filter.port = None;
            filter.terms = crate::query::parse_filter_text(text, QueryCapabilities::WATCH)
                .expect("protection filter is valid");
            evaluate_side(
                &snapshot,
                &snapshot.sockets[socket_index],
                &filter,
                &config,
                &mut FilterCache::default(),
            )
        };

        assert_eq!(evaluate(protected_index, "protected:true"), Truth::True);
        assert_eq!(evaluate(protected_index, "protected:false"), Truth::False);
        assert_eq!(evaluate(unprotected_index, "protected:true"), Truth::False);
        assert_eq!(evaluate(unprotected_index, "protected:false"), Truth::True);
        assert_eq!(evaluate(protected_index, "protected"), Truth::True);
        assert_eq!(evaluate(protected_index, "unprotected"), Truth::Unknown);
        assert_eq!(evaluate(unprotected_index, "protected"), Truth::Unknown);
        assert_eq!(evaluate(unprotected_index, "unprotected"), Truth::True);
    }

    #[test]
    fn filter_result_order_crosses_batch_boundaries_without_retaining_the_group() {
        let mut snapshot = snapshot();
        let mut common_owners = (1..=64)
            .map(|pid| OwnerObservation::UnverifiedPid {
                pid,
                reason: UnverifiedOwnerReason::IdentityUnavailable,
            })
            .collect::<Vec<_>>();
        let mut indeterminate = snapshot.sockets[0].clone();
        common_owners.push(OwnerObservation::UnverifiedPid {
            pid: 101,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        });
        indeterminate.owners = common_owners.clone();
        indeterminate.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        let mut matched = indeterminate.clone();
        *matched.owners.last_mut().unwrap() = OwnerObservation::UnverifiedPid {
            pid: 100,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        };
        snapshot.sockets = vec![indeterminate; crate::watch::WATCH_EVENT_BATCH_MAX];
        snapshot.sockets.push(matched);
        snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete]).unwrap();
        snapshot.completeness = SnapshotCompleteness::Partial;

        let mut filter = options(Duration::from_secs(1));
        filter.json = false;
        filter.port = None;
        filter.terms =
            crate::query::parse_filter_text("pid:100", QueryCapabilities::WATCH).unwrap();
        let events = baseline_events(&snapshot)
            .unwrap()
            .map(super::baseline_event_result);
        let mut runtime = FakeRuntime::new(Vec::new());
        let mut output = BufferedTrackingWriter::default();
        let mut diagnostics = Vec::new();
        let mut sequence = 0;
        let mut batch_count = 0;
        let mut no_previous_cache = None;
        let mut current_cache = Some(&mut FilterCache::default());
        let gap_index = GapIndex::new(&snapshot);

        let reason = write_ordered_events(
            events,
            &filter,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
            None,
            &mut sequence,
            &mut batch_count,
            &mut no_previous_cache,
            &mut current_cache,
            None,
            Some(&gap_index),
            ObservationTimes {
                previous_completed_unix_ms: None,
                attempt_started_unix_ms: 1,
                attempt_completed_unix_ms: 2,
            },
        );
        output.flush().unwrap();

        assert_eq!(reason, None);
        assert!(diagnostics.is_empty());
        let rendered = String::from_utf8(output.committed).unwrap();
        let mut lines = rendered.lines();
        assert!(lines.next().unwrap().contains("filter=matched"));
        assert_eq!(
            lines
                .filter(|line| line.contains("filter=indeterminate"))
                .count(),
            crate::watch::WATCH_EVENT_BATCH_MAX
        );
        assert_eq!(
            usize::try_from(sequence).unwrap(),
            crate::watch::WATCH_EVENT_BATCH_MAX + 1
        );
    }

    #[test]
    fn filtering_uses_the_uncancelled_owner_beyond_the_public_owner_limit() {
        let mut previous = snapshot();
        previous.sockets.truncate(1);
        let common = (1..=crate::observation::SERIALIZED_OWNERS_MAX)
            .map(|pid| OwnerObservation::UnverifiedPid {
                pid: u32::try_from(pid).unwrap(),
                reason: UnverifiedOwnerReason::IdentityUnavailable,
            })
            .collect::<Vec<_>>();
        let mut hidden_100 = previous.sockets[0].clone();
        hidden_100.owners = common.clone();
        hidden_100.owners.push(OwnerObservation::UnverifiedPid {
            pid: 100,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        });
        let mut hidden_101 = previous.sockets[0].clone();
        hidden_101.owners = common;
        hidden_101.owners.push(OwnerObservation::UnverifiedPid {
            pid: 101,
            reason: UnverifiedOwnerReason::IdentityUnavailable,
        });
        previous.sockets = vec![hidden_101, hidden_100.clone()];
        let mut current = previous.clone();
        current.sockets = vec![hidden_100];
        let mut filter = options(Duration::from_secs(1));
        filter.json = false;
        filter.port = None;
        filter.terms =
            crate::query::parse_filter_text("pid:101", QueryCapabilities::WATCH).unwrap();
        let mut runtime = FakeRuntime::new(Vec::new());
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();
        let mut sequence = 0;
        let mut batch_count = 0;
        let mut previous_cache = Some(&mut FilterCache::default());
        let mut current_cache = Some(&mut FilterCache::default());

        let reason = write_ordered_events(
            diff_snapshots(&previous, &current).unwrap(),
            &filter,
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
            None,
            &mut sequence,
            &mut batch_count,
            &mut previous_cache,
            &mut current_cache,
            Some(&GapIndex::new(&previous)),
            Some(&GapIndex::new(&current)),
            ObservationTimes {
                previous_completed_unix_ms: Some(1),
                attempt_started_unix_ms: 2,
                attempt_completed_unix_ms: 3,
            },
        );

        assert_eq!(reason, None);
        assert!(diagnostics.is_empty());
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output.lines().count(), 1);
        assert!(output.contains("RELEASE"));
        assert!(output.contains("filter=matched"));
    }

    #[test]
    fn human_output_bounds_owner_and_label_display() {
        let mut snapshot = snapshot();
        snapshot.sockets.truncate(1);
        snapshot.sockets[0].owners = (1..=65)
            .map(|pid| OwnerObservation::UnverifiedPid {
                pid,
                reason: UnverifiedOwnerReason::IdentityUnavailable,
            })
            .collect();
        let endpoint = snapshot.sockets[0].local_endpoint.clone();
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: endpoint.protocol.label().to_ascii_lowercase(),
                address: endpoint.address.to_string(),
                port: u64::from(endpoint.port.get()),
                scope_id: None,
                label: "x".repeat(33),
            }])
            .unwrap(),
            ..Config::default()
        };
        let event = WatchEvent {
            kind: EventKind::Baseline,
            previous_snapshot: None,
            current_snapshot: Some(&snapshot),
            previous_socket: None,
            current_socket: Some(&snapshot.sockets[0]),
            multiplicity: 1,
            certainty: Certainty::Proven,
        };
        let mut output = Vec::new();

        write_human_event(
            &mut output,
            ObservationTimes {
                previous_completed_unix_ms: None,
                attempt_started_unix_ms: 1,
                attempt_completed_unix_ms: 2,
            },
            event,
            FilterResult::NotApplied,
            &config,
        )
        .unwrap();

        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("owners=1,2,3"));
        assert!(output.contains("64,+1"));
        assert!(!output.contains(",65"));
        assert!(output.contains(&format!("label={}…", "x".repeat(31))));
    }

    #[test]
    fn human_endpoint_text_preserves_ipv6_scope() {
        let endpoint = |address, ipv6_scope| {
            EndpointIdentity::new(Protocol::Tcp, address, 3000, ipv6_scope)
                .expect("test endpoint is valid")
        };

        assert_eq!(
            human_endpoint_text(&endpoint(IpAddr::V4(Ipv4Addr::LOCALHOST), None)),
            "127.0.0.1:3000"
        );
        assert_eq!(
            human_endpoint_text(&endpoint(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                Some(Ipv6Scope::Unscoped)
            )),
            "[::1]:3000"
        );
        assert_eq!(
            human_endpoint_text(&endpoint(
                IpAddr::V6("fe80::1".parse().expect("valid IPv6 address")),
                Some(Ipv6Scope::interface_index(3).expect("valid scope"))
            )),
            "[fe80::1%3]:3000"
        );
        assert_eq!(
            human_endpoint_text(&endpoint(
                IpAddr::V6("fe80::1".parse().expect("valid IPv6 address")),
                Some(Ipv6Scope::Unavailable)
            )),
            "[fe80::1%unavailable]:3000"
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the complete schema contract keeps every field and event-side rule explicit"
    )]
    fn endpoint_event_shapes_pin_previous_and_current_sides() {
        let mut previous = snapshot();
        let mut current = snapshot();
        previous.sockets[0].socket_token =
            Some(crate::observation::PlatformSocketToken::linux_inode(11).unwrap());
        current.sockets[0].socket_token =
            Some(crate::observation::PlatformSocketToken::macos_socket_id(12).unwrap());
        let current_identity = crate::observation::ProcessIdentity {
            pid: 20_000,
            start_marker: crate::observation::ProcessStartMarker::linux(20_001).unwrap(),
        };
        current.sockets[0].owners = vec![OwnerObservation::Verified(current_identity)];
        previous
            .processes
            .values_mut()
            .for_each(|process| process.command_line = Some("private previous command".into()));
        current
            .processes
            .values_mut()
            .for_each(|process| process.command_line = Some("private current command".into()));
        let previous_owner = serde_json::json!({
            "owners": [{
                "kind": "verified",
                "identity": {
                    "pid": 18_422,
                    "start_marker": {"kind": "linux_start_ticks", "ticks": 18_423}
                }
            }],
            "omitted_owner_count": 0,
            "completeness": "complete",
            "reasons": []
        });
        let current_owner = serde_json::json!({
            "owners": [{
                "kind": "verified",
                "identity": {
                    "pid": 20_000,
                    "start_marker": {"kind": "linux_start_ticks", "ticks": 20_001}
                }
            }],
            "omitted_owner_count": 0,
            "completeness": "complete",
            "reasons": []
        });
        let cases = [
            (
                EventKind::Baseline,
                None,
                Some(&current.sockets[0]),
                serde_json::Value::Null,
                current_owner.clone(),
                serde_json::Value::Null,
                serde_json::json!({"kind": "macos_socket_id", "value": 12}),
            ),
            (
                EventKind::Bind,
                None,
                Some(&current.sockets[0]),
                serde_json::Value::Null,
                current_owner.clone(),
                serde_json::Value::Null,
                serde_json::json!({"kind": "macos_socket_id", "value": 12}),
            ),
            (
                EventKind::Release,
                Some(&previous.sockets[0]),
                None,
                previous_owner.clone(),
                serde_json::Value::Null,
                serde_json::json!({"kind": "linux_inode", "value": 11}),
                serde_json::Value::Null,
            ),
            (
                EventKind::Replacement,
                Some(&previous.sockets[0]),
                Some(&current.sockets[0]),
                previous_owner.clone(),
                current_owner.clone(),
                serde_json::json!({"kind": "linux_inode", "value": 11}),
                serde_json::json!({"kind": "macos_socket_id", "value": 12}),
            ),
        ];

        for (
            kind,
            previous_socket,
            current_socket,
            expected_previous_owners,
            expected_current_owners,
            expected_previous_token,
            expected_current_token,
        ) in cases
        {
            let observation = ObservationTimes {
                previous_completed_unix_ms: (kind != EventKind::Baseline).then_some(1),
                attempt_started_unix_ms: 2,
                attempt_completed_unix_ms: 3,
            };
            let event = WatchEvent {
                kind,
                previous_snapshot: (kind != EventKind::Baseline).then_some(&previous),
                current_snapshot: Some(&current),
                previous_socket,
                current_socket,
                multiplicity: 1,
                certainty: if kind == EventKind::Replacement {
                    Certainty::Heuristic
                } else {
                    Certainty::Proven
                },
            };
            let mut output = Vec::new();
            super::write_endpoint_event(
                &mut output,
                true,
                7,
                observation,
                event,
                FilterResult::Matched,
                &[],
                &Config::default(),
                Some(&GapIndex::new(&previous)),
                Some(&GapIndex::new(&current)),
            )
            .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
            let certainty = if kind == EventKind::Replacement {
                "heuristic"
            } else {
                "proven"
            };
            let evidence = if kind == EventKind::Replacement {
                serde_json::json!([{
                    "code": "process_identity_changed",
                    "source": "analysis",
                    "certainty": "proven",
                    "message": "verified process identity changed between observations"
                }])
            } else {
                serde_json::json!([])
            };
            assert_eq!(
                value,
                serde_json::json!({
                    "schema": "kickoutchi.watch_event",
                    "version": 1,
                    "sequence": 7,
                    "event": kind.name(),
                    "observation": {
                        "previous_completed_unix_ms": observation.previous_completed_unix_ms,
                        "attempt_started_unix_ms": 2,
                        "attempt_completed_unix_ms": 3
                    },
                    "data": {
                        "endpoint": {
                            "protocol": "tcp",
                            "address": "127.0.0.1",
                            "port": 3000,
                            "ipv6_scope": null
                        },
                        "state": {"kind": "listen", "native_code": null},
                        "previous_owners": expected_previous_owners,
                        "current_owners": expected_current_owners,
                        "previous_socket_token": expected_previous_token,
                        "current_socket_token": expected_current_token,
                        "multiplicity": 1,
                        "label": null,
                        "filter_result": "matched",
                        "certainty": certainty,
                        "evidence": evidence,
                        "omitted_evidence_count": 0,
                        "evidence_gaps": [],
                        "omitted_evidence_gap_count": 0
                    }
                })
            );
            let rendered = String::from_utf8(output).unwrap();
            assert!(!rendered.contains("command_line"));
            assert!(!rendered.contains("private previous command"));
            assert!(!rendered.contains("private current command"));
        }
    }

    #[test]
    fn collection_gap_shape_is_fully_pinned() {
        let result = Err(ObservationError::SocketTableUnavailable.into());
        let gap = super::gap_from_result(&result, 2);
        let observation = ObservationTimes {
            previous_completed_unix_ms: Some(10),
            attempt_started_unix_ms: 11,
            attempt_completed_unix_ms: 12,
        };
        let mut output = Vec::new();

        super::write_gap(&mut output, true, 9, observation, &gap).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "schema": "kickoutchi.watch_event",
                "version": 1,
                "sequence": 9,
                "event": "collection_gap",
                "observation": {
                    "previous_completed_unix_ms": 10,
                    "attempt_started_unix_ms": 11,
                    "attempt_completed_unix_ms": 12
                },
                "data": {
                    "error": {
                        "code": "socket_table_unavailable",
                        "message": "socket table is unavailable"
                    },
                    "certainty": "unknown",
                    "consecutive_failures": 2,
                    "completeness": null,
                    "evidence_gaps": [],
                    "omitted_evidence_gap_count": 0
                }
            })
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the maximum schema fixture keeps every bounded field visible"
    )]
    fn fully_populated_replacement_record_stays_within_its_calculated_bound() {
        let snapshot = snapshot();
        let endpoint = &snapshot.sockets[0].local_endpoint;
        let owners = (0..crate::observation::SERIALIZED_OWNERS_MAX)
            .map(|offset| {
                OwnerObservation::Verified(crate::observation::ProcessIdentity {
                    pid: u32::MAX - u32::try_from(offset).unwrap(),
                    start_marker: crate::observation::ProcessStartMarker::windows(
                        u64::MAX - u64::try_from(offset).unwrap(),
                    )
                    .unwrap(),
                })
            })
            .collect::<Vec<_>>();
        let owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::NativeFieldUnavailable,
            EvidenceGapCode::NoncriticalEvidenceTruncated,
            EvidenceGapCode::ObservationRaced,
            EvidenceGapCode::OwnerAttributionIncomplete,
            EvidenceGapCode::OwnerDisappeared,
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::ProcessIdentityUnavailable,
            EvidenceGapCode::ProcessMetadataUnavailable,
        ])
        .unwrap();
        let owner_set = || super::OwnerSetDto::new(&owners, &owner_completeness).unwrap();
        let escaped_message = "\\".repeat(512);
        let evidence = (0..crate::watch::WATCH_EVENT_EVIDENCE_MAX)
            .map(|_| {
                super::EvidenceDto::literal(
                    "process_identity_changed",
                    "analysis",
                    "heuristic",
                    &escaped_message,
                )
            })
            .collect();
        let gaps = (0..crate::watch::WATCH_EVENT_GAPS_MAX)
            .map(|offset| {
                EvidenceGap::new(
                    EvidenceImpact::Metadata,
                    EvidenceGapCode::ProcessMetadataUnavailable,
                    Some(endpoint.clone()),
                    Some(u32::MAX - u32::try_from(offset).unwrap()),
                    &escaped_message,
                )
            })
            .collect::<Vec<_>>();
        let evidence_gaps = gaps.iter().map(super::EvidenceGapDto::from).collect();
        let label = "x".repeat(128);
        let data = super::EndpointEventData {
            endpoint: super::EndpointDto::from(endpoint),
            state: super::SocketStateDto::from(snapshot.sockets[0].state),
            previous_owners: Some(owner_set()),
            current_owners: Some(owner_set()),
            previous_socket_token: Some(super::SocketTokenDto::from(
                crate::observation::PlatformSocketToken::macos_socket_id(u64::MAX).unwrap(),
            )),
            current_socket_token: Some(super::SocketTokenDto::from(
                crate::observation::PlatformSocketToken::macos_socket_id(u64::MAX).unwrap(),
            )),
            multiplicity: u32::MAX,
            label: Some(&label),
            filter_result: "indeterminate",
            certainty: "heuristic",
            evidence,
            omitted_evidence_count: u64::MAX,
            evidence_gaps,
            omitted_evidence_gap_count: u64::MAX,
        };
        let record = super::WatchRecord {
            schema: "kickoutchi.watch_event",
            version: 1,
            sequence: u64::MAX,
            event: "replacement",
            observation: ObservationTimes {
                previous_completed_unix_ms: Some(u64::MAX),
                attempt_started_unix_ms: u64::MAX,
                attempt_completed_unix_ms: u64::MAX,
            },
            data,
        };
        let mut output = Vec::new();

        super::write_json_record(&mut output, &record).unwrap();

        assert!(output.len() <= 52_224, "record was {} bytes", output.len());
        assert!(output.len() <= crate::watch::WATCH_RECORD_MAX_BYTES);
        assert_eq!(output.last(), Some(&b'\n'));
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["event"], "replacement");
        assert_eq!(
            value["data"]["previous_owners"]["owners"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            value["data"]["current_owners"]["owners"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(value["data"]["evidence"].as_array().unwrap().len(), 8);
        assert_eq!(value["data"]["evidence_gaps"].as_array().unwrap().len(), 8);
    }

    #[test]
    fn gap_index_and_record_writer_enforce_exact_bounds() {
        let mut snapshot = snapshot();
        snapshot.evidence_gaps = (0..9)
            .map(|_| {
                EvidenceGap::new(
                    EvidenceImpact::Metadata,
                    EvidenceGapCode::ProcessMetadataUnavailable,
                    None,
                    None,
                    "metadata unavailable",
                )
            })
            .collect();
        let index = GapIndex::new(&snapshot);
        assert_eq!(index.global.indices.len(), 8);
        assert_eq!(index.global.total, 9);

        snapshot.evidence_gaps = (42..=51)
            .map(|pid| {
                EvidenceGap::new(
                    EvidenceImpact::Metadata,
                    EvidenceGapCode::ProcessMetadataUnavailable,
                    None,
                    Some(pid),
                    "metadata unavailable",
                )
            })
            .collect();
        snapshot.sockets[0].owners = (42..=50)
            .map(|pid| OwnerObservation::UnverifiedPid {
                pid,
                reason: UnverifiedOwnerReason::IdentityUnavailable,
            })
            .collect();
        let index = GapIndex::new(&snapshot);
        assert_eq!(index.global.total, 0);
        assert_eq!(index.by_pid[&42].total, 1);
        let mut applicable = Vec::new();
        let mut applicable_total = 0;
        index.append(
            &snapshot,
            &snapshot.sockets[0],
            OwnerPidConstraint::Any,
            &mut applicable,
            &mut applicable_total,
        );
        assert_eq!(applicable_total, 9);
        assert_eq!(applicable.len(), 8);
        assert_eq!(applicable[0].pid, Some(42));
        assert_eq!(applicable[7].pid, Some(49));

        let descending = (42..=50)
            .rev()
            .map(|pid| {
                EvidenceGap::new(
                    EvidenceImpact::Metadata,
                    EvidenceGapCode::ProcessMetadataUnavailable,
                    None,
                    Some(pid),
                    "metadata unavailable",
                )
            })
            .collect::<Vec<_>>();
        let mut retained = Vec::with_capacity(8);
        for gap in &descending {
            super::retain_bounded_gap(&mut retained, gap);
        }
        assert_eq!(retained.len(), 8);
        assert_eq!(retained[0].pid, Some(42));
        assert_eq!(retained[7].pid, Some(49));

        snapshot.sockets[0].owner_completeness = OwnerCompleteness::partial([
            EvidenceGapCode::OwnerPermissionDenied,
            EvidenceGapCode::OwnerAttributionIncomplete,
        ])
        .unwrap();
        let owner_set = super::OwnerSetDto::new(
            &snapshot.sockets[0].owners,
            &snapshot.sockets[0].owner_completeness,
        )
        .unwrap();
        let owner_set = serde_json::to_value(owner_set).unwrap();
        assert_eq!(
            owner_set["reasons"],
            serde_json::json!(["owner_attribution_incomplete", "owner_permission_denied"])
        );

        let mut record = BoundedRecord::new();
        assert_eq!(record.write(&vec![0; 65_536]).unwrap(), 65_536);
        assert!(record.write(&[0]).is_err());
        assert_eq!(record.bytes.len(), 65_536);
    }

    #[test]
    fn event_evidence_retains_zero_maximum_and_counts_the_first_omission() {
        for (count, retained, omitted) in [
            (0, 0, 0),
            (
                crate::watch::WATCH_EVENT_EVIDENCE_MAX,
                crate::watch::WATCH_EVENT_EVIDENCE_MAX,
                0,
            ),
            (
                crate::watch::WATCH_EVENT_EVIDENCE_MAX + 1,
                crate::watch::WATCH_EVENT_EVIDENCE_MAX,
                1,
            ),
        ] {
            let evidence = (0..count)
                .map(|_| {
                    super::EvidenceDto::literal("fixture", "analysis", "proven", "fixture evidence")
                })
                .collect();
            let (evidence, actual_omitted) = super::retain_event_evidence(evidence);
            assert_eq!(evidence.len(), retained, "count={count}");
            assert_eq!(actual_omitted, omitted, "count={count}");
        }
    }
}
