use std::io::{self, ErrorKind, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::time::SystemTime;

use clap::Args;
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};

use crate::collector::{self, CollectorError};
use crate::config::Config;
use crate::diagnostic::verdict::{Verdict, VerdictResult, WHY_ENDPOINTS_MAX, analyze};
use crate::display::{sanitize, sanitize_bounded};
use crate::labels::{SELECTOR_ADDRESS_MAX_BYTES, normalize_ip_address};
use crate::model::Protocol;
use crate::observation::{EndpointIdentity, Ipv6Scope, MetadataProfile, NetworkSnapshot};
use crate::probe::{Ipv6Mode, ProbeRequest, ProbeResult, ReuseAddressMode, probe};
use crate::public_output::{
    CaptureDto, EndpointDto, EvidenceDto, EvidenceGapDto, PublicOutputError, ScopeDto,
    certainty_name, evidence_code_name, evidence_gap_code_name, evidence_impact_name,
    evidence_source_name, owner_completeness_name, protocol_name, scope_kind_name,
    scope_limitation_name, snapshot_completeness_name,
};

use super::ExitReason;

const PUBLIC_MESSAGE_MAX_BYTES: usize = 512;

#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is one independent CLI flag; clap's derive requires bools, and the contradictory combinations are rejected at parse time"
)]
#[derive(Debug, Args)]
pub(crate) struct WhyArgs {
    /// Port to diagnose (1..=65535).
    pub(crate) port: u32,

    /// Evaluate TCP only (default; ordered before UDP in a matrix).
    #[arg(long, conflicts_with_all = ["udp", "all_protocols"])]
    pub(crate) tcp: bool,

    /// Evaluate UDP endpoints only.
    #[arg(long, conflicts_with_all = ["tcp", "all_protocols"])]
    pub(crate) udp: bool,

    /// Evaluate TCP then UDP endpoints.
    #[arg(long, conflicts_with_all = ["tcp", "udp"])]
    pub(crate) all_protocols: bool,

    /// Evaluate one literal local IP address (no `%zone`; use --scope-id).
    #[arg(long, value_name = "ADDRESS", conflicts_with = "all_addresses")]
    pub(crate) address: Option<String>,

    /// Use `127.0.0.1`, `0.0.0.0`, `::1`, then `::`; do not enumerate interfaces.
    #[arg(long, conflicts_with = "address")]
    pub(crate) all_addresses: bool,

    /// Nonzero IPv6 interface index; requires one explicit IPv6 --address.
    #[arg(long, value_name = "ID")]
    pub(crate) scope_id: Option<u32>,

    /// Require IPv6-only behavior; valid only when every address is IPv6.
    #[arg(long, conflicts_with = "dual_stack")]
    pub(crate) ipv6_only: bool,

    /// Require dual-stack behavior; valid only when every address is IPv6.
    #[arg(long, conflicts_with = "ipv6_only")]
    pub(crate) dual_stack: bool,

    /// Explicitly enable address reuse for the diagnostic bind.
    #[arg(long)]
    pub(crate) reuse_address: bool,

    /// Print one `kickoutchi.why/1` JSON document instead of human evidence.
    #[arg(long)]
    pub(crate) json: bool,
}

#[derive(Debug)]
struct WhyOptions {
    port: u16,
    protocols: Vec<Protocol>,
    addresses: Vec<IpAddr>,
    scope_id: Option<NonZeroU32>,
    ipv6_mode: Ipv6Mode,
    reuse_address: ReuseAddressMode,
    endpoints: Vec<RequestedEndpoint>,
    json: bool,
}

#[derive(Debug, Clone)]
struct RequestedEndpoint {
    identity: EndpointIdentity,
    probe_request: ProbeRequest,
}

#[derive(Debug)]
struct TimedProbe {
    result: ProbeResult,
    capture: CaptureDto,
}

#[derive(Debug)]
struct CompletedResult {
    verdict: VerdictResult,
    probe: TimedProbe,
}

trait WhyRuntime {
    fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError>;
    fn now(&mut self) -> SystemTime;
    fn probe(&mut self, request: ProbeRequest) -> ProbeResult;
}

struct ProductionRuntime;

impl WhyRuntime for ProductionRuntime {
    fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        collector::collect_snapshot(profile)
    }

    fn now(&mut self) -> SystemTime {
        SystemTime::now()
    }

    fn probe(&mut self, request: ProbeRequest) -> ProbeResult {
        probe(request)
    }
}

pub(super) fn run_why(args: &WhyArgs, config: &Config) -> ExitReason {
    let mut runtime = ProductionRuntime;
    let stdout = io::stdout();
    let stderr = io::stderr();
    run_why_with(
        args,
        config,
        &mut runtime,
        &mut stdout.lock(),
        &mut stderr.lock(),
    )
}

fn run_why_with(
    args: &WhyArgs,
    config: &Config,
    runtime: &mut impl WhyRuntime,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> ExitReason {
    let options = match WhyOptions::parse(args) {
        Ok(options) => options,
        Err(error) => {
            write_diagnostic(diagnostics, &format!("invalid why query: {error}"));
            return ExitReason::InvalidArguments;
        }
    };
    let snapshot = match runtime.collect(MetadataProfile::Display) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            write_diagnostic(
                diagnostics,
                &format!("collecting endpoint evidence failed: {error}"),
            );
            return ExitReason::Failure;
        }
    };

    let mut completed = Vec::with_capacity(options.endpoints.len());
    for endpoint in &options.endpoints {
        let started = runtime.now();
        let result = runtime.probe(endpoint.probe_request);
        let finished = runtime.now();
        let capture = match CaptureDto::new(started, finished) {
            Ok(capture) => capture,
            Err(error) => {
                write_diagnostic(
                    diagnostics,
                    &format!("recording probe time failed: {error}"),
                );
                return ExitReason::Failure;
            }
        };
        let label = config.labels.resolve(&endpoint.identity);
        completed.push(CompletedResult {
            verdict: analyze(
                &endpoint.identity,
                options.ipv6_mode,
                &snapshot,
                &result,
                label,
            ),
            probe: TimedProbe { result, capture },
        });
    }

    let aggregate = aggregate_exit(completed.iter().map(|result| result.verdict.verdict));
    match render_document(output, &options, &snapshot, &completed)
        .and_then(|()| output.flush().map_err(OutputError::from))
    {
        Ok(()) => aggregate,
        Err(error) if error.io_error_kind() == Some(ErrorKind::BrokenPipe) => aggregate,
        Err(error) => {
            write_diagnostic(diagnostics, &format!("writing why output failed: {error}"));
            ExitReason::Failure
        }
    }
}

impl WhyOptions {
    fn parse(args: &WhyArgs) -> Result<Self, String> {
        let port = u16::try_from(args.port)
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| "port must be in 1..=65535".to_owned())?;
        // `--tcp` is read here rather than left to fall through the `else`.
        // Both mean TCP today, but a flag that works only because it matches
        // the default is a flag that breaks silently when the default moves.
        // Same shape as watch's `protocol_selected`. clap rejects any two
        // protocol flags together, so at most one is set.
        let tcp_selected = args.tcp || !(args.udp || args.all_protocols);
        let protocols = if args.all_protocols {
            vec![Protocol::Tcp, Protocol::Udp]
        } else if tcp_selected {
            vec![Protocol::Tcp]
        } else {
            vec![Protocol::Udp]
        };
        let addresses = parse_addresses(args)?;
        let scope_id = args.scope_id.and_then(NonZeroU32::new);
        if args.scope_id.is_some() && scope_id.is_none() {
            return Err("scope ID must be in 1..=4294967295".to_owned());
        }
        if scope_id.is_some() && args.address.is_none() {
            return Err("scope ID requires one explicit IPv6 address".to_owned());
        }
        if scope_id.is_some() && addresses.first().is_none_or(IpAddr::is_ipv4) {
            return Err("scope ID is valid only with an explicit IPv6 address".to_owned());
        }
        let ipv6_mode = if args.ipv6_only {
            Ipv6Mode::V6Only
        } else if args.dual_stack {
            Ipv6Mode::DualStack
        } else {
            Ipv6Mode::SystemDefault
        };
        if ipv6_mode != Ipv6Mode::SystemDefault && addresses.iter().any(IpAddr::is_ipv4) {
            return Err("IPv6-only and dual-stack modes require only IPv6 addresses".to_owned());
        }
        let reuse_address = if args.reuse_address {
            ReuseAddressMode::Enabled
        } else {
            ReuseAddressMode::Disabled
        };
        let endpoint_count = endpoint_count(protocols.len(), addresses.len())?;
        let mut endpoints = Vec::with_capacity(endpoint_count);
        for protocol in &protocols {
            for address in &addresses {
                let ipv6_scope = match address {
                    IpAddr::V4(_) => None,
                    IpAddr::V6(_) => {
                        Some(scope_id.map_or(Ipv6Scope::Unscoped, Ipv6Scope::InterfaceIndex))
                    }
                };
                let identity =
                    EndpointIdentity::new(*protocol, *address, u32::from(port), ipv6_scope)
                        .map_err(|error| error.to_string())?;
                let probe_request = ProbeRequest::new(
                    *protocol,
                    *address,
                    u32::from(port),
                    ipv6_scope,
                    ipv6_mode,
                    reuse_address,
                )
                .map_err(|error| error.to_string())?;
                endpoints.push(RequestedEndpoint {
                    identity,
                    probe_request,
                });
            }
        }
        Ok(Self {
            port,
            protocols,
            addresses,
            scope_id,
            ipv6_mode,
            reuse_address,
            endpoints,
            json: args.json,
        })
    }
}

fn endpoint_count(protocols: usize, addresses: usize) -> Result<usize, String> {
    let count = protocols
        .checked_mul(addresses)
        .ok_or_else(|| "endpoint matrix size overflowed".to_owned())?;
    if count == 0 || count > WHY_ENDPOINTS_MAX {
        return Err(format!(
            "endpoint matrix must contain 1..={WHY_ENDPOINTS_MAX} entries"
        ));
    }
    Ok(count)
}

fn parse_addresses(args: &WhyArgs) -> Result<Vec<IpAddr>, String> {
    if args.all_addresses {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        ]);
    }
    let Some(address) = args.address.as_deref() else {
        return Ok(vec![
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ]);
    };
    if address.len() > SELECTOR_ADDRESS_MAX_BYTES {
        return Err("address exceeds the 64-byte limit".to_owned());
    }
    if address.contains('%') {
        return Err("address must not include a zone; use --scope-id".to_owned());
    }
    let address = address
        .parse::<IpAddr>()
        .map(normalize_ip_address)
        .map_err(|_| "address must be one literal IP address".to_owned())?;
    Ok(vec![address])
}

fn aggregate_exit(verdicts: impl IntoIterator<Item = Verdict>) -> ExitReason {
    let mut aggregate = ExitReason::Success;
    for verdict in verdicts {
        let reason = match verdict {
            Verdict::BindableNow => ExitReason::Success,
            Verdict::ObservationRaced | Verdict::Indeterminate => ExitReason::Failure,
            Verdict::PermissionDenied => ExitReason::PermissionDenied,
            Verdict::Owned
            | Verdict::OwnerHidden
            | Verdict::KernelStateObserved
            | Verdict::AddressUnavailable
            | Verdict::ReservationOrPolicyUnknown
            | Verdict::Unsupported => ExitReason::NoMatch,
        };
        aggregate = match (aggregate, reason) {
            (ExitReason::Failure, _) | (_, ExitReason::Failure) => ExitReason::Failure,
            (ExitReason::PermissionDenied, _) | (_, ExitReason::PermissionDenied) => {
                ExitReason::PermissionDenied
            }
            (ExitReason::NoMatch, _) | (_, ExitReason::NoMatch) => ExitReason::NoMatch,
            _ => ExitReason::Success,
        };
    }
    aggregate
}

fn render_document(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
) -> Result<(), OutputError> {
    if options.json {
        render_json(output, options, snapshot, results)
    } else {
        render_human(output, options, snapshot, results)
    }
}

fn render_json(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
) -> Result<(), OutputError> {
    let aggregate = aggregate_exit(results.iter().map(|result| result.verdict.verdict));
    let capture = CaptureDto::new(snapshot.capture_started_at, snapshot.capture_completed_at)?;
    let dto = WhyDto {
        schema: "kickoutchi.why",
        version: 1,
        query: QueryDto::from(options),
        capture,
        scope: ScopeDto::new(&snapshot.scope)?,
        completeness: snapshot_completeness_name(snapshot.completeness),
        owner_completeness: owner_completeness_name(&snapshot.owner_completeness),
        results: ResultSequence(results),
        aggregate_exit_code: aggregate as u8,
    };
    serde_json::to_writer_pretty(&mut *output, &dto).map_err(OutputError::Serialization)?;
    output.write_all(b"\n").map_err(OutputError::from)
}

fn render_human(
    output: &mut impl Write,
    options: &WhyOptions,
    snapshot: &NetworkSnapshot,
    results: &[CompletedResult],
) -> Result<(), OutputError> {
    let capture = CaptureDto::new(snapshot.capture_started_at, snapshot.capture_completed_at)?;
    let aggregate = aggregate_exit(results.iter().map(|result| result.verdict.verdict));
    writeln!(
        &mut *output,
        "WHY port={} protocols={} addresses={} scope_id={} ipv6_mode={} reuse_address={} snapshot={} ownership={} capture_started_unix_ms={} capture_completed_unix_ms={}",
        options.port,
        options
            .protocols
            .iter()
            .map(|protocol| protocol.label())
            .collect::<Vec<_>>()
            .join(","),
        options
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        options
            .scope_id
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        ipv6_mode_name(options.ipv6_mode),
        options.reuse_address == ReuseAddressMode::Enabled,
        snapshot_completeness_name(snapshot.completeness),
        owner_completeness_name(&snapshot.owner_completeness),
        capture.started_unix_ms(),
        capture.completed_unix_ms(),
    )?;
    writeln!(
        &mut *output,
        "scope kind={} identifier={} limitations={}",
        scope_kind_name(snapshot.scope.kind),
        snapshot
            .scope
            .identifier
            .as_deref()
            .map_or_else(|| "-".to_owned(), sanitize),
        snapshot
            .scope
            .limitations
            .iter()
            .copied()
            .map(scope_limitation_name)
            .collect::<Vec<_>>()
            .join(","),
    )?;
    for result in results {
        render_human_result(output, result)?;
    }
    writeln!(output, "aggregate_exit_code={}", aggregate as u8)?;
    Ok(())
}

fn render_human_result(
    output: &mut impl Write,
    result: &CompletedResult,
) -> Result<(), OutputError> {
    writeln!(
        output,
        "{} verdict={} certainty={} label={}",
        endpoint_text(&result.verdict.endpoint),
        result.verdict.verdict.name(),
        certainty_name(result.verdict.certainty),
        result
            .verdict
            .label
            .as_deref()
            .map_or_else(|| "-".to_owned(), sanitize),
    )?;
    let message = result.probe.result.os_error_message.as_deref().map_or_else(
        || "-".to_owned(),
        |message| sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES),
    );
    writeln!(
        output,
        "  probe={} started_unix_ms={} completed_unix_ms={} raw_os_error={} message={}",
        probe_outcome_name(result.probe.result.outcome),
        result.probe.capture.started_unix_ms(),
        result.probe.capture.completed_unix_ms(),
        result
            .probe
            .result
            .raw_os_error
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        message,
    )?;
    for item in &result.verdict.evidence {
        writeln!(
            output,
            "  evidence code={} source={} certainty={} message={}",
            evidence_code_name(item.code),
            evidence_source_name(item.source),
            certainty_name(item.certainty),
            sanitize_bounded(&item.message, PUBLIC_MESSAGE_MAX_BYTES),
        )?;
    }
    writeln!(
        output,
        "  omitted_evidence_count={}",
        result.verdict.omitted_evidence_count
    )?;
    for gap in &result.verdict.evidence_gaps {
        writeln!(
            output,
            "  gap code={} impact={} endpoint={} pid={} message={}",
            evidence_gap_code_name(gap.code),
            evidence_impact_name(gap.impact),
            gap.endpoint
                .as_ref()
                .map_or_else(|| "-".to_owned(), endpoint_text),
            gap.pid
                .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
            sanitize_bounded(gap.message(), PUBLIC_MESSAGE_MAX_BYTES),
        )?;
    }
    writeln!(
        output,
        "  omitted_evidence_gap_count={}",
        result.verdict.omitted_evidence_gap_count
    )?;
    Ok(())
}

#[derive(Serialize)]
struct WhyDto<'a> {
    schema: &'static str,
    version: u32,
    query: QueryDto,
    capture: CaptureDto,
    scope: ScopeDto<'a>,
    completeness: &'static str,
    owner_completeness: &'static str,
    results: ResultSequence<'a>,
    aggregate_exit_code: u8,
}

struct ResultSequence<'a>(&'a [CompletedResult]);

impl Serialize for ResultSequence<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for result in self.0 {
            sequence.serialize_element(&result_dto(result))?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct QueryDto {
    port: u16,
    protocols: Vec<&'static str>,
    addresses: Vec<String>,
    scope_id: Option<u32>,
    ipv6_mode: &'static str,
    reuse_address: bool,
}

impl From<&WhyOptions> for QueryDto {
    fn from(options: &WhyOptions) -> Self {
        Self {
            port: options.port,
            protocols: options
                .protocols
                .iter()
                .copied()
                .map(protocol_name)
                .collect(),
            addresses: options.addresses.iter().map(ToString::to_string).collect(),
            scope_id: options.scope_id.map(NonZeroU32::get),
            ipv6_mode: ipv6_mode_name(options.ipv6_mode),
            reuse_address: options.reuse_address == ReuseAddressMode::Enabled,
        }
    }
}

#[derive(Serialize)]
struct ResultDto<'a> {
    endpoint: EndpointDto<'a>,
    label: Option<String>,
    verdict: &'static str,
    certainty: &'static str,
    probe: ProbeDto,
    evidence: Vec<EvidenceDto<'a>>,
    omitted_evidence_count: u64,
    evidence_gaps: Vec<EvidenceGapDto<'a>>,
    omitted_evidence_gap_count: u64,
}

#[derive(Serialize)]
struct ProbeDto {
    outcome: &'static str,
    started_unix_ms: u64,
    completed_unix_ms: u64,
    raw_os_error: Option<i32>,
    message: Option<String>,
}

fn result_dto(result: &CompletedResult) -> ResultDto<'_> {
    ResultDto {
        endpoint: EndpointDto::from(&result.verdict.endpoint),
        label: result
            .verdict
            .label
            .as_deref()
            .map(|label| sanitize_bounded(label, PUBLIC_MESSAGE_MAX_BYTES)),
        verdict: result.verdict.verdict.name(),
        certainty: certainty_name(result.verdict.certainty),
        probe: ProbeDto {
            outcome: probe_outcome_name(result.probe.result.outcome),
            started_unix_ms: result.probe.capture.started_unix_ms(),
            completed_unix_ms: result.probe.capture.completed_unix_ms(),
            raw_os_error: result.probe.result.raw_os_error,
            message: result
                .probe
                .result
                .os_error_message
                .as_deref()
                .map(|message| sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES)),
        },
        evidence: result
            .verdict
            .evidence
            .iter()
            .map(EvidenceDto::from)
            .collect(),
        omitted_evidence_count: result.verdict.omitted_evidence_count,
        evidence_gaps: result
            .verdict
            .evidence_gaps
            .iter()
            .map(EvidenceGapDto::from)
            .collect(),
        omitted_evidence_gap_count: result.verdict.omitted_evidence_gap_count,
    }
}

fn endpoint_text(endpoint: &EndpointIdentity) -> String {
    match (endpoint.address, endpoint.ipv6_scope) {
        (IpAddr::V4(address), None) => format!(
            "{}://{address}:{}",
            protocol_name(endpoint.protocol),
            endpoint.port
        ),
        (IpAddr::V6(address), Some(Ipv6Scope::Unscoped)) => {
            format!(
                "{}://[{address}]:{}",
                protocol_name(endpoint.protocol),
                endpoint.port
            )
        }
        (IpAddr::V6(address), Some(Ipv6Scope::InterfaceIndex(index))) => format!(
            "{}://[{address}%{}]:{}",
            protocol_name(endpoint.protocol),
            index,
            endpoint.port
        ),
        (IpAddr::V6(address), Some(Ipv6Scope::Unavailable)) => format!(
            "{}://[{address}%unavailable]:{}",
            protocol_name(endpoint.protocol),
            endpoint.port
        ),
        _ => unreachable!("validated endpoint address and scope agree"),
    }
}

const fn probe_outcome_name(outcome: crate::probe::ProbeOutcome) -> &'static str {
    match outcome {
        crate::probe::ProbeOutcome::BindableNow => "bindable_now",
        crate::probe::ProbeOutcome::AddressInUse => "address_in_use",
        crate::probe::ProbeOutcome::PermissionDenied => "permission_denied",
        crate::probe::ProbeOutcome::AddressUnavailable => "address_unavailable",
        crate::probe::ProbeOutcome::Unsupported => "unsupported",
        crate::probe::ProbeOutcome::Other => "other",
    }
}

const fn ipv6_mode_name(mode: Ipv6Mode) -> &'static str {
    match mode {
        Ipv6Mode::SystemDefault => "system_default",
        Ipv6Mode::V6Only => "v6_only",
        Ipv6Mode::DualStack => "dual_stack",
    }
}

#[derive(Debug)]
enum OutputError {
    Io(io::Error),
    Serialization(serde_json::Error),
    Public(PublicOutputError),
}

impl OutputError {
    fn io_error_kind(&self) -> Option<ErrorKind> {
        match self {
            Self::Io(error) => Some(error.kind()),
            Self::Serialization(error) => error.io_error_kind(),
            Self::Public(error) => error.io_error_kind(),
        }
    }
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Serialization(error) => error.fmt(formatter),
            Self::Public(error) => error.fmt(formatter),
        }
    }
}

impl From<io::Error> for OutputError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<PublicOutputError> for OutputError {
    fn from(error: PublicOutputError) -> Self {
        Self::Public(error)
    }
}

fn write_diagnostic(writer: &mut impl Write, message: &str) {
    let _ = writeln!(
        writer,
        "error: {}",
        sanitize_bounded(message, PUBLIC_MESSAGE_MAX_BYTES)
    );
    let _ = writer.flush();
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io;
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::diagnostic::verdict::Evidence;
    use crate::labels::{LabelInput, LabelRegistry};
    use crate::observation::{
        EvidenceGap, EvidenceGapCode, EvidenceImpact, ObservationScope, ObservationScopeKind,
        OwnerCompleteness, ScopeLimitation, SnapshotCompleteness,
    };
    use crate::probe::ProbeOutcome;

    fn args() -> WhyArgs {
        WhyArgs {
            port: 3000,
            tcp: false,
            udp: false,
            all_protocols: false,
            address: None,
            all_addresses: false,
            scope_id: None,
            ipv6_only: false,
            dual_stack: false,
            reuse_address: false,
            json: false,
        }
    }

    fn snapshot() -> NetworkSnapshot {
        let captured = UNIX_EPOCH + Duration::from_secs(10);
        NetworkSnapshot {
            capture_started_at: captured,
            capture_completed_at: captured,
            scope: ObservationScope::new(
                ObservationScopeKind::CurrentNetworkNamespace,
                Some("net:[1]"),
                [],
            )
            .expect("test scope is valid"),
            completeness: SnapshotCompleteness::Complete,
            owner_completeness: OwnerCompleteness::Complete,
            evidence_gaps: Vec::new(),
            omitted_evidence_gap_count: 0,
            sockets: Vec::new(),
            processes: HashMap::new(),
        }
    }

    struct FakeRuntime {
        snapshot: NetworkSnapshot,
        collect_error: bool,
        outcomes: Vec<ProbeOutcome>,
        collect_profiles: Vec<MetadataProfile>,
        probes: usize,
        clock_calls: u64,
        raw_os_error: Option<i32>,
        os_error_message: Option<Box<str>>,
    }

    impl FakeRuntime {
        fn new(outcomes: Vec<ProbeOutcome>) -> Self {
            Self {
                snapshot: snapshot(),
                collect_error: false,
                outcomes,
                collect_profiles: Vec::new(),
                probes: 0,
                clock_calls: 0,
                raw_os_error: None,
                os_error_message: None,
            }
        }
    }

    impl WhyRuntime for FakeRuntime {
        fn collect(&mut self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
            self.collect_profiles.push(profile);
            if self.collect_error {
                Err(crate::observation::ObservationError::SocketTableUnavailable.into())
            } else {
                Ok(self.snapshot.clone())
            }
        }

        fn now(&mut self) -> SystemTime {
            self.clock_calls += 1;
            UNIX_EPOCH + Duration::from_millis(20_000 + self.clock_calls)
        }

        fn probe(&mut self, _request: ProbeRequest) -> ProbeResult {
            let outcome = self.outcomes[self.probes];
            self.probes += 1;
            ProbeResult {
                outcome,
                raw_os_error: self.raw_os_error,
                os_error_message: self.os_error_message.clone(),
            }
        }
    }

    struct BrokenWriter;

    impl Write for BrokenWriter {
        fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(ErrorKind::BrokenPipe))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct FlushWriter {
        kind: ErrorKind,
    }

    impl Write for FlushWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::from(self.kind))
        }
    }

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        flushes: usize,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    struct MidstreamErrorWriter {
        successful_writes: usize,
        attempts: usize,
        kind: ErrorKind,
    }

    impl Write for MidstreamErrorWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.attempts += 1;
            if self.attempts > self.successful_writes {
                Err(io::Error::new(self.kind, "injected midstream failure"))
            } else {
                Ok(bytes.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn bare_query_is_the_two_tcp_loopback_endpoints() {
        let options = WhyOptions::parse(&args()).expect("default query is valid");

        assert_eq!(options.protocols, vec![Protocol::Tcp]);
        assert_eq!(
            options.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
        assert_eq!(options.endpoints.len(), 2);
    }

    /// `--tcp` names the same protocol the bare query defaults to, so a version
    /// that ignored the flag would still pass the test above. Asserting each
    /// selector on its own is what catches a `--tcp` that stopped being read.
    #[test]
    fn every_protocol_selector_is_read_independently_of_the_default() {
        for (input, expected) in [
            (
                WhyArgs {
                    tcp: true,
                    ..args()
                },
                vec![Protocol::Tcp],
            ),
            (
                WhyArgs {
                    udp: true,
                    ..args()
                },
                vec![Protocol::Udp],
            ),
            (
                WhyArgs {
                    all_protocols: true,
                    ..args()
                },
                vec![Protocol::Tcp, Protocol::Udp],
            ),
            (args(), vec![Protocol::Tcp]),
        ] {
            let options = WhyOptions::parse(&input).expect("protocol selector is valid");
            assert_eq!(options.protocols, expected);
        }
    }

    #[test]
    fn expanded_query_is_the_canonical_eight_endpoint_matrix() {
        let mut input = args();
        input.all_protocols = true;
        input.all_addresses = true;

        let options = WhyOptions::parse(&input).expect("maximum matrix is valid");

        assert_eq!(options.protocols, vec![Protocol::Tcp, Protocol::Udp]);
        assert_eq!(
            options.addresses,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            ]
        );
        assert_eq!(options.endpoints.len(), WHY_ENDPOINTS_MAX);
    }

    #[test]
    fn endpoint_count_accepts_only_the_contract_range() {
        assert!(endpoint_count(0, 1).is_err());
        assert_eq!(
            endpoint_count(2, WHY_ENDPOINTS_MAX / 2).unwrap(),
            WHY_ENDPOINTS_MAX
        );
        assert!(endpoint_count(1, WHY_ENDPOINTS_MAX + 1).is_err());
        assert!(endpoint_count(usize::MAX, 2).is_err());
    }

    #[test]
    fn port_scope_and_address_boundaries_are_validated_exactly() {
        assert!(WhyOptions::parse(&WhyArgs { port: 1, ..args() }).is_ok());
        assert!(
            WhyOptions::parse(&WhyArgs {
                port: 65_535,
                ..args()
            })
            .is_ok()
        );
        assert!(WhyOptions::parse(&WhyArgs { port: 0, ..args() }).is_err());
        assert!(
            WhyOptions::parse(&WhyArgs {
                port: 65_536,
                ..args()
            })
            .is_err()
        );

        let scoped = WhyArgs {
            address: Some("fe80::1".to_owned()),
            scope_id: Some(u32::MAX),
            ..args()
        };
        assert!(WhyOptions::parse(&scoped).is_ok());
        assert!(
            WhyOptions::parse(&WhyArgs {
                scope_id: Some(0),
                ..scoped
            })
            .is_err()
        );

        let oversized = WhyArgs {
            address: Some("1".repeat(SELECTOR_ADDRESS_MAX_BYTES + 1)),
            ..args()
        };
        assert_eq!(
            WhyOptions::parse(&oversized).expect_err("oversized address must fail"),
            "address exceeds the 64-byte limit"
        );
    }

    #[test]
    fn invalid_queries_are_rejected_before_collection_or_probing() {
        let invalid = [
            WhyArgs { port: 0, ..args() },
            WhyArgs {
                address: Some("127.0.0.1".to_owned()),
                scope_id: Some(3),
                ..args()
            },
            WhyArgs {
                address: Some("fe80::1%3".to_owned()),
                ..args()
            },
            WhyArgs {
                all_addresses: true,
                ipv6_only: true,
                ..args()
            },
        ];

        for input in invalid {
            let mut runtime = FakeRuntime::new(Vec::new());
            let mut output = Vec::new();
            let mut diagnostics = Vec::new();
            let reason = run_why_with(
                &input,
                &Config::default(),
                &mut runtime,
                &mut output,
                &mut diagnostics,
            );

            assert_eq!(reason, ExitReason::InvalidArguments);
            assert!(output.is_empty());
            assert!(!diagnostics.is_empty());
            assert!(runtime.collect_profiles.is_empty());
            assert_eq!(runtime.probes, 0);
        }
    }

    #[test]
    fn collection_failure_happens_before_probes_or_output() {
        let mut runtime = FakeRuntime::new(Vec::new());
        runtime.collect_error = true;
        let mut output = RecordingWriter::default();
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &args(),
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Failure);
        assert_eq!(runtime.collect_profiles, [MetadataProfile::Display]);
        assert_eq!(runtime.probes, 0);
        assert_eq!(runtime.clock_calls, 0);
        assert!(output.bytes.is_empty());
        assert!(
            String::from_utf8(diagnostics)
                .unwrap()
                .contains("collecting endpoint evidence failed")
        );
    }

    #[test]
    fn orchestration_collects_display_once_and_probes_each_endpoint_sequentially() {
        let mut runtime =
            FakeRuntime::new(vec![ProbeOutcome::BindableNow, ProbeOutcome::BindableNow]);
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &args(),
            &Config::default(),
            &mut runtime,
            &mut output,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::Success);
        assert_eq!(runtime.collect_profiles, vec![MetadataProfile::Display]);
        assert_eq!(runtime.probes, 2);
        assert_eq!(runtime.clock_calls, 4);
        assert!(diagnostics.is_empty());
        assert!(
            String::from_utf8(output)
                .expect("human output is UTF-8")
                .contains("bindable_now")
        );
    }

    #[test]
    fn aggregate_precedence_is_failure_then_permission_then_unavailable_then_success() {
        assert_eq!(
            aggregate_exit([Verdict::BindableNow, Verdict::Owned]),
            ExitReason::NoMatch
        );
        assert_eq!(
            aggregate_exit([Verdict::Owned, Verdict::PermissionDenied]),
            ExitReason::PermissionDenied
        );
        assert_eq!(
            aggregate_exit([Verdict::PermissionDenied, Verdict::Indeterminate]),
            ExitReason::Failure
        );
        assert_eq!(
            aggregate_exit([Verdict::BindableNow, Verdict::BindableNow]),
            ExitReason::Success
        );

        for (verdict, expected) in [
            (Verdict::BindableNow, ExitReason::Success),
            (Verdict::Owned, ExitReason::NoMatch),
            (Verdict::OwnerHidden, ExitReason::NoMatch),
            (Verdict::KernelStateObserved, ExitReason::NoMatch),
            (Verdict::PermissionDenied, ExitReason::PermissionDenied),
            (Verdict::AddressUnavailable, ExitReason::NoMatch),
            (Verdict::ReservationOrPolicyUnknown, ExitReason::NoMatch),
            (Verdict::ObservationRaced, ExitReason::Failure),
            (Verdict::Unsupported, ExitReason::NoMatch),
            (Verdict::Indeterminate, ExitReason::Failure),
        ] {
            assert_eq!(aggregate_exit([verdict]), expected, "verdict {verdict:?}");
        }
    }

    #[test]
    fn broken_stdout_preserves_each_computed_aggregate_exit() {
        for (outcome, expected) in [
            (ProbeOutcome::BindableNow, ExitReason::Success),
            (ProbeOutcome::Other, ExitReason::Failure),
            (ProbeOutcome::Unsupported, ExitReason::NoMatch),
            (ProbeOutcome::PermissionDenied, ExitReason::PermissionDenied),
        ] {
            let mut input = args();
            input.address = Some("127.0.0.1".to_owned());
            let mut runtime = FakeRuntime::new(vec![outcome]);
            let mut diagnostics = Vec::new();

            let reason = run_why_with(
                &input,
                &Config::default(),
                &mut runtime,
                &mut BrokenWriter,
                &mut diagnostics,
            );

            assert_eq!(reason, expected, "outcome {outcome:?}");
            assert!(diagnostics.is_empty());
            assert_eq!(runtime.probes, 1);
        }
    }

    #[test]
    fn every_endpoint_is_evaluated_before_broken_output_is_observed() {
        let mut input = args();
        input.all_protocols = true;
        input.all_addresses = true;
        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported; WHY_ENDPOINTS_MAX]);
        let mut diagnostics = Vec::new();

        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut BrokenWriter,
            &mut diagnostics,
        );

        assert_eq!(reason, ExitReason::NoMatch);
        assert_eq!(runtime.probes, WHY_ENDPOINTS_MAX);
        assert_eq!(
            runtime.clock_calls,
            u64::try_from(WHY_ENDPOINTS_MAX * 2).unwrap()
        );
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn broken_flush_preserves_the_aggregate_but_other_writer_failures_do_not() {
        let mut input = args();
        input.address = Some("127.0.0.1".to_owned());
        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
        let mut diagnostics = Vec::new();
        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut FlushWriter {
                kind: ErrorKind::BrokenPipe,
            },
            &mut diagnostics,
        );
        assert_eq!(reason, ExitReason::NoMatch);
        assert!(diagnostics.is_empty());

        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
        let mut diagnostics = Vec::new();
        let reason = run_why_with(
            &input,
            &Config::default(),
            &mut runtime,
            &mut FlushWriter {
                kind: ErrorKind::Other,
            },
            &mut diagnostics,
        );
        assert_eq!(reason, ExitReason::Failure);
        assert!(
            String::from_utf8(diagnostics)
                .expect("diagnostic is UTF-8")
                .contains("writing why output failed")
        );
    }

    #[test]
    fn human_and_pretty_json_are_written_and_flushed() {
        for json in [false, true] {
            let mut input = args();
            input.address = Some("127.0.0.1".to_owned());
            input.json = json;
            let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
            let mut output = RecordingWriter::default();
            let mut diagnostics = Vec::new();

            let reason = run_why_with(
                &input,
                &Config::default(),
                &mut runtime,
                &mut output,
                &mut diagnostics,
            );

            assert_eq!(reason, ExitReason::Success, "json={json}");
            assert_eq!(output.flushes, 1, "json={json}");
            assert!(!output.bytes.is_empty());
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn midstream_writer_errors_preserve_only_broken_pipe_aggregate() {
        for json in [false, true] {
            for (kind, expected) in [
                (ErrorKind::BrokenPipe, ExitReason::NoMatch),
                (ErrorKind::Other, ExitReason::Failure),
            ] {
                let mut input = args();
                input.address = Some("127.0.0.1".to_owned());
                input.json = json;
                let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
                let mut output = MidstreamErrorWriter {
                    successful_writes: 3,
                    attempts: 0,
                    kind,
                };
                let mut diagnostics = Vec::new();

                let reason = run_why_with(
                    &input,
                    &Config::default(),
                    &mut runtime,
                    &mut output,
                    &mut diagnostics,
                );

                assert_eq!(reason, expected, "json={json}, kind={kind:?}");
                if kind == ErrorKind::BrokenPipe {
                    assert!(diagnostics.is_empty());
                } else {
                    assert!(
                        String::from_utf8(diagnostics)
                            .expect("diagnostic is UTF-8")
                            .contains("writing why output failed")
                    );
                }
            }
        }
    }

    #[test]
    fn maximum_quote_heavy_json_shape_can_exceed_the_old_document_cap() {
        let mut input = args();
        input.all_protocols = true;
        input.all_addresses = true;
        input.json = true;
        let options = WhyOptions::parse(&input).expect("maximum query is valid");
        let quote_heavy = "\"".repeat(PUBLIC_MESSAGE_MAX_BYTES);
        let completed = options
            .endpoints
            .iter()
            .map(|requested| CompletedResult {
                verdict: VerdictResult {
                    endpoint: requested.identity.clone(),
                    label: Some(quote_heavy.clone()),
                    verdict: Verdict::Indeterminate,
                    certainty: crate::watch::Certainty::Unknown,
                    evidence: (0..crate::diagnostic::verdict::WHY_EVIDENCE_MAX)
                        .map(|_| Evidence {
                            code: crate::diagnostic::verdict::EvidenceCode::ExactBindOtherError,
                            source: crate::diagnostic::verdict::EvidenceSource::Analysis,
                            certainty: crate::watch::Certainty::Unknown,
                            message: quote_heavy.clone(),
                        })
                        .collect(),
                    omitted_evidence_count: 0,
                    evidence_gaps: (0..crate::diagnostic::verdict::WHY_EVIDENCE_GAPS_MAX)
                        .map(|_| {
                            EvidenceGap::new(
                                EvidenceImpact::Metadata,
                                EvidenceGapCode::ProcessMetadataUnavailable,
                                Some(requested.identity.clone()),
                                None,
                                &quote_heavy,
                            )
                        })
                        .collect(),
                    omitted_evidence_gap_count: 0,
                },
                probe: TimedProbe {
                    result: ProbeResult {
                        outcome: ProbeOutcome::Other,
                        raw_os_error: None,
                        os_error_message: Some(quote_heavy.clone().into_boxed_str()),
                    },
                    capture: CaptureDto::new(
                        UNIX_EPOCH + Duration::from_millis(20_001),
                        UNIX_EPOCH + Duration::from_millis(20_002),
                    )
                    .expect("test probe interval is valid"),
                },
            })
            .collect::<Vec<_>>();
        let mut output = RecordingWriter::default();

        render_document(&mut output, &options, &snapshot(), &completed)
            .expect("maximum legal JSON shape renders");

        assert_eq!(completed.len(), WHY_ENDPOINTS_MAX);
        assert!(
            output.bytes.len() > 256 * 1024,
            "bytes={}",
            output.bytes.len()
        );
        let value: serde_json::Value =
            serde_json::from_slice(&output.bytes).expect("output is valid JSON");
        assert_eq!(
            value["results"].as_array().map(Vec::len),
            Some(WHY_ENDPOINTS_MAX)
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the schema contract asserts every envelope and nested result field"
    )]
    fn json_contract_has_exact_envelope_and_omits_command_lines() {
        let mut input = args();
        input.address = Some("fe80::1".to_owned());
        input.scope_id = Some(3);
        input.json = true;
        let mut runtime = FakeRuntime::new(vec![ProbeOutcome::BindableNow]);
        let endpoint = EndpointIdentity::new(
            Protocol::Tcp,
            "fe80::1".parse().expect("literal is valid"),
            3000,
            Some(Ipv6Scope::InterfaceIndex(
                NonZeroU32::new(3).expect("scope is nonzero"),
            )),
        )
        .expect("endpoint is valid");
        runtime.snapshot.completeness = SnapshotCompleteness::Partial;
        runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Scope,
            EvidenceGapCode::NativeFieldUnavailable,
            Some(endpoint),
            None,
            "scope detail is unavailable",
        ));
        runtime.snapshot.omitted_evidence_gap_count = 2;
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "fe80::1".to_owned(),
                port: 3000,
                scope_id: Some(3),
                label: "scoped fixture".to_owned(),
            }])
            .expect("label config is valid"),
            ..Config::default()
        };
        let mut output = Vec::new();
        let mut diagnostics = Vec::new();

        let reason = run_why_with(&input, &config, &mut runtime, &mut output, &mut diagnostics);

        assert_eq!(reason, ExitReason::Success);
        assert!(diagnostics.is_empty());
        let value: serde_json::Value =
            serde_json::from_slice(&output).expect("why output is valid JSON");
        let mut keys = value
            .as_object()
            .expect("why envelope is an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "aggregate_exit_code",
                "capture",
                "completeness",
                "owner_completeness",
                "query",
                "results",
                "schema",
                "scope",
                "version",
            ]
        );
        assert_eq!(value["schema"], "kickoutchi.why");
        assert_eq!(value["version"], 1);
        assert_eq!(value["aggregate_exit_code"], 0);
        assert_eq!(value["results"][0]["verdict"], "bindable_now");
        assert_eq!(value["completeness"], "partial");
        assert_eq!(value["results"][0]["label"], "scoped fixture");
        assert_object_keys(
            &value["query"],
            &[
                "port",
                "protocols",
                "addresses",
                "scope_id",
                "ipv6_mode",
                "reuse_address",
            ],
        );
        assert_object_keys(&value["capture"], &["started_unix_ms", "completed_unix_ms"]);
        assert_object_keys(&value["scope"], &["kind", "identifier", "limitations"]);
        assert_object_keys(
            &value["results"][0],
            &[
                "endpoint",
                "label",
                "verdict",
                "certainty",
                "probe",
                "evidence",
                "omitted_evidence_count",
                "evidence_gaps",
                "omitted_evidence_gap_count",
            ],
        );
        assert_object_keys(
            &value["results"][0]["endpoint"],
            &["protocol", "address", "port", "ipv6_scope"],
        );
        assert_object_keys(
            &value["results"][0]["endpoint"]["ipv6_scope"],
            &["kind", "interface_index"],
        );
        assert_eq!(
            value["results"][0]["endpoint"]["ipv6_scope"]["kind"],
            "interface_index"
        );
        assert_eq!(
            value["results"][0]["endpoint"]["ipv6_scope"]["interface_index"],
            3
        );
        assert_object_keys(
            &value["results"][0]["probe"],
            &[
                "outcome",
                "started_unix_ms",
                "completed_unix_ms",
                "raw_os_error",
                "message",
            ],
        );
        assert_object_keys(
            &value["results"][0]["evidence"][0],
            &["code", "source", "certainty", "message"],
        );
        assert_object_keys(
            &value["results"][0]["evidence_gaps"][0],
            &["code", "impact", "endpoint", "pid", "message"],
        );
        assert_eq!(value["results"][0]["omitted_evidence_gap_count"], 2);
        assert!(
            !String::from_utf8(output)
                .expect("JSON is UTF-8")
                .contains("command_line")
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "human and JSON output are compared across every result fact"
    )]
    fn human_and_json_renderers_carry_the_same_result_facts() {
        let mut json_input = args();
        json_input.address = Some("fe80::1".to_owned());
        json_input.scope_id = Some(3);
        json_input.json = true;
        let mut json_runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
        json_runtime.raw_os_error = Some(99);
        json_runtime.os_error_message = Some("unsupported fixture".into());
        json_runtime.snapshot.completeness = SnapshotCompleteness::Partial;
        json_runtime.snapshot.owner_completeness =
            OwnerCompleteness::partial([EvidenceGapCode::OwnerAttributionIncomplete])
                .expect("one reason fits");
        json_runtime
            .snapshot
            .scope
            .limitations
            .push(ScopeLimitation::NativeFieldUnavailable);
        let endpoint = EndpointIdentity::new(
            Protocol::Tcp,
            "fe80::1".parse().expect("literal is valid"),
            3000,
            Some(Ipv6Scope::InterfaceIndex(
                NonZeroU32::new(3).expect("scope is nonzero"),
            )),
        )
        .expect("endpoint is valid");
        json_runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::Metadata,
            EvidenceGapCode::ProcessMetadataUnavailable,
            Some(endpoint.clone()),
            None,
            "fixture metadata gap",
        ));
        json_runtime.snapshot.evidence_gaps.push(EvidenceGap::new(
            EvidenceImpact::SocketSet,
            EvidenceGapCode::NativeFieldUnavailable,
            None,
            Some(77),
            "fixture socket gap",
        ));
        json_runtime.snapshot.omitted_evidence_gap_count = 2;
        let config = Config {
            labels: LabelRegistry::from_inputs(vec![LabelInput {
                protocol: "tcp".to_owned(),
                address: "fe80::1".to_owned(),
                port: 3000,
                scope_id: Some(3),
                label: "parity fixture".to_owned(),
            }])
            .expect("label config is valid"),
            ..Config::default()
        };
        let mut json_output = Vec::new();
        let mut diagnostics = Vec::new();
        let json_reason = run_why_with(
            &json_input,
            &config,
            &mut json_runtime,
            &mut json_output,
            &mut diagnostics,
        );
        let value: serde_json::Value =
            serde_json::from_slice(&json_output).expect("why output is valid JSON");

        let mut human_input = args();
        human_input.address = Some("fe80::1".to_owned());
        human_input.scope_id = Some(3);
        let mut human_runtime = FakeRuntime::new(vec![ProbeOutcome::Unsupported]);
        human_runtime.raw_os_error = Some(99);
        human_runtime.os_error_message = Some("unsupported fixture".into());
        human_runtime.snapshot = json_runtime.snapshot.clone();
        let mut human_output = Vec::new();
        let human_reason = run_why_with(
            &human_input,
            &config,
            &mut human_runtime,
            &mut human_output,
            &mut diagnostics,
        );
        let human = String::from_utf8(human_output).expect("human output is UTF-8");

        assert_eq!(json_reason, human_reason);
        assert!(human.contains("tcp://[fe80::1%3]:3000"));
        assert!(human.contains("addresses=fe80::1 scope_id=3"));
        assert!(human.contains("ipv6_mode=system_default"));
        assert!(human.contains("snapshot=partial"));
        assert!(human.contains("ownership=partial"));
        assert!(human.contains("capture_started_unix_ms=10000"));
        assert!(human.contains("capture_completed_unix_ms=10000"));
        assert!(human.contains("scope kind=current_network_namespace"));
        assert!(human.contains("identifier=net:[1]"));
        assert!(human.contains("limitations=native_field_unavailable"));
        assert!(human.contains("label=parity fixture"));
        assert!(human.contains(&format!(
            "verdict={}",
            value["results"][0]["verdict"].as_str().unwrap()
        )));
        assert!(human.contains(&format!(
            "certainty={}",
            value["results"][0]["certainty"].as_str().unwrap()
        )));
        assert!(human.contains(&format!(
            "probe={}",
            value["results"][0]["probe"]["outcome"].as_str().unwrap()
        )));
        assert!(human.contains("raw_os_error=99"));
        assert!(human.contains("message=unsupported fixture"));
        assert!(human.contains("started_unix_ms=20001 completed_unix_ms=20002"));
        assert!(human.contains("evidence code=exact_bind_unsupported"));
        assert!(human.contains("source=bind_probe certainty=proven"));
        assert!(human.contains("gap code=process_metadata_unavailable impact=metadata"));
        assert!(human.contains("endpoint=tcp://[fe80::1%3]:3000 pid=-"));
        assert!(human.contains("message=fixture metadata gap"));
        assert!(human.contains("gap code=native_field_unavailable impact=socket_set"));
        assert!(human.contains("endpoint=- pid=77"));
        assert!(human.contains("omitted_evidence_count=0"));
        assert!(human.contains("omitted_evidence_gap_count=2"));
        assert!(human.contains(&format!(
            "aggregate_exit_code={}",
            value["aggregate_exit_code"]
        )));
    }

    #[test]
    fn public_probe_messages_are_sanitized_and_clipped_on_utf8_boundaries() {
        for (message, expected) in [
            ("a".repeat(512), "a".repeat(512)),
            ("é".repeat(257), "é".repeat(256)),
            (
                format!("safe\x1b[2J{}", "b".repeat(513)),
                format!("safe{}", "b".repeat(508)),
            ),
        ] {
            let mut input = args();
            input.address = Some("127.0.0.1".to_owned());
            input.json = true;
            let mut runtime = FakeRuntime::new(vec![ProbeOutcome::Other]);
            runtime.os_error_message = Some(message.into_boxed_str());
            let mut output = Vec::new();
            let mut diagnostics = Vec::new();

            let reason = run_why_with(
                &input,
                &Config::default(),
                &mut runtime,
                &mut output,
                &mut diagnostics,
            );
            let value: serde_json::Value =
                serde_json::from_slice(&output).expect("why output is valid JSON");
            let rendered = value["results"][0]["probe"]["message"]
                .as_str()
                .expect("probe message is present");

            assert_eq!(reason, ExitReason::Failure);
            assert_eq!(rendered, expected);
            assert_eq!(rendered.len(), PUBLIC_MESSAGE_MAX_BYTES);
            assert!(!rendered.contains('\x1b'));
            assert!(std::str::from_utf8(rendered.as_bytes()).is_ok());
            assert!(diagnostics.is_empty());
        }
    }

    #[test]
    fn evidence_and_gap_messages_share_the_public_utf8_bound_in_both_formats() {
        let mut input = args();
        input.address = Some("127.0.0.1".to_owned());
        let mut options = WhyOptions::parse(&input).expect("query is valid");
        let endpoint = options.endpoints[0].identity.clone();
        let completed = vec![CompletedResult {
            verdict: VerdictResult {
                endpoint: endpoint.clone(),
                label: None,
                verdict: Verdict::Indeterminate,
                certainty: crate::watch::Certainty::Unknown,
                evidence: vec![Evidence {
                    code: crate::diagnostic::verdict::EvidenceCode::ExactBindOtherError,
                    source: crate::diagnostic::verdict::EvidenceSource::Analysis,
                    certainty: crate::watch::Certainty::Unknown,
                    message: "é".repeat(257),
                }],
                omitted_evidence_count: 0,
                evidence_gaps: vec![EvidenceGap::new(
                    EvidenceImpact::Metadata,
                    EvidenceGapCode::ProcessMetadataUnavailable,
                    Some(endpoint),
                    None,
                    &"\x01".repeat(171),
                )],
                omitted_evidence_gap_count: 0,
            },
            probe: TimedProbe {
                result: ProbeResult {
                    outcome: ProbeOutcome::Other,
                    raw_os_error: None,
                    os_error_message: Some("a".repeat(513).into_boxed_str()),
                },
                capture: CaptureDto::new(
                    UNIX_EPOCH + Duration::from_millis(20_001),
                    UNIX_EPOCH + Duration::from_millis(20_002),
                )
                .expect("test probe interval is valid"),
            },
        }];
        options.json = true;
        let mut json = Vec::new();
        render_document(&mut json, &options, &snapshot(), &completed).expect("JSON renders");
        let value: serde_json::Value =
            serde_json::from_slice(&json).expect("why output is valid JSON");
        let evidence = value["results"][0]["evidence"][0]["message"]
            .as_str()
            .expect("evidence message is present");
        let gap = value["results"][0]["evidence_gaps"][0]["message"]
            .as_str()
            .expect("gap message is present");
        let probe = value["results"][0]["probe"]["message"]
            .as_str()
            .expect("probe message is present");

        assert_eq!(evidence, "é".repeat(256));
        assert_eq!(gap, crate::display::REPLACEMENT.to_string().repeat(170));
        assert_eq!(probe, "a".repeat(512));
        assert_eq!(evidence.len(), PUBLIC_MESSAGE_MAX_BYTES);
        assert_eq!(gap.len(), 510);
        assert_eq!(probe.len(), PUBLIC_MESSAGE_MAX_BYTES);

        options.json = false;
        let mut human = Vec::new();
        render_document(&mut human, &options, &snapshot(), &completed)
            .expect("human output renders");
        let human = String::from_utf8(human).expect("human output is UTF-8");
        assert!(human.contains(evidence));
        assert!(human.contains(gap));
        assert!(human.contains(probe));
    }

    fn assert_object_keys(value: &serde_json::Value, expected: &[&str]) {
        let actual = value
            .as_object()
            .expect("contract value must be an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = expected.iter().copied().collect();
        assert_eq!(actual, expected);
    }
}
