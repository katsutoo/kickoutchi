# Named Ports, Watch, and Why

## Status

This document is the implementation and release plan for three related features:

- Named endpoint labels.
- `kick watch`, a bounded polling event stream.
- `kick why`, an evidence-based endpoint diagnostic command.

The features may be developed in internal phases, but they ship together or not
at all. No incomplete platform fallback, provisional schema, or reduced first
version is released. The expected release is a new minor version, such as
`1.3.0`, because it adds commands, configuration, filters, and serialized
contracts.

This atomic release is a deliberate product choice, not an architectural
necessity. Labels could technically ship alone, but doing so would trade a
shorter release cycle for a split product story, early public contracts, and
follow-up migration work. Accept the corresponding costs: a longer-lived branch,
more drift to manage, a larger final regression surface, and no user feedback on
the individual features before the complete release.

This plan must be executed with the Rust, TigerStyle, security, test-quality,
QA, and benchmark skills. Those skills govern implementation and verification;
this document does not weaken their requirements.

## Product Goal

The three features add meaning to the port table:

- Labels say what an endpoint is expected to be used for.
- Watch says what changed between verified observations.
- Why explains what is known about a requested endpoint and whether an exact
  bind probe succeeds now.

All three must use one authoritative observation model. Platform collectors
produce facts, analysis code assigns meaning and certainty, and renderers only
format the result. No renderer may infer ownership, identity, or confidence.

## Non-Goals

- Do not promise visibility outside the current observation scope.
- Do not silently enter another network namespace.
- Do not elevate privileges.
- Do not shell out to `ss`, `lsof`, `netstat`, `netsh`, Docker, or another
  executable for core evidence.
- Do not claim that a successful probe reserves an endpoint for a later process.
- Do not claim exact event times from polling.
- Do not convert estimates or heuristics into proven verdicts.
- Do not add a watch view to the TUI in this release; `watch` is CLI-only.
- Do not ship one feature while the others or a supported platform remain
  incomplete.

## Engineering Priorities

Apply these priorities in order:

1. Safety and truthful reporting.
2. Bounded resource use and predictable performance.
3. Clear contracts and maintainable code.

Operational failures use `Result` and explicit error types. Assertions are only
for programmer-error invariants. Every loop, retry, allocation, table, buffer,
label, event batch, and native read must have an explicit bound.

## Definition of Complete

The release is complete only when all of the following are true:

- Named endpoints work in config, CLI tables, the TUI, plain search,
  structured filters, JSON, watch, and why.
- Watch reports deterministic, bounded events using verified process identity
  where the platform exposes it.
- Why evaluates exact protocol/address/port targets and labels every conclusion
  as proven, estimated, heuristic, or unknown.
- Linux, macOS, and Windows retain every socket state exposed by the supported
  native collection path.
- Observation scope, permissions, races, and unavailable platform fields are
  represented explicitly.
- Human output, JSON, NDJSON, filters, config, and exit codes are documented and
  pinned by contract tests.
- Automated tests and native end-to-end tests pass on every supported platform.
- Security review has no unresolved release-blocking finding.
- QA returns PASS and recommends `ship` for the exact release artifact.
- The final benchmark is reproducible and stays within predeclared regression
  budgets.

## Phase 0: Freeze the Contracts

Do not start platform implementation until these contracts are written and
reviewed.

### 0.1 Observation vocabulary

Define and approve:

- Endpoint identity: protocol, IP address, and port.
- Process identity: PID plus a platform start marker.
- Socket multiplicity for reuse-port and inherited sockets.
- Optional platform socket tokens, such as a Linux inode.
- Snapshot timestamps, scope, completeness, and evidence gaps.
- Shared TCP states, UDP-bound state, and unknown native states.
- Proven, estimated, heuristic, and unknown certainty levels.

### 0.2 Public contracts

Define and approve:

- Endpoint-aware label configuration and precedence.
- `watch` arguments, event kinds, ordering, recovery, and termination behavior.
- `why` arguments, probe matrix, verdicts, and exit behavior.
- Human table behavior with and without labels.
- Plain-search and structured-filter behavior.
- Versioned JSON and NDJSON schemas.
- Stdout and stderr separation.
- Backward compatibility expectations for existing commands.

### 0.3 Exit codes

Keep one documented process-wide contract:

| Code | Meaning |
| ---: | --- |
| 0 | Command completed and its requested positive condition holds |
| 1 | Operational or internal failure |
| 2 | Invalid arguments |
| 3 | Valid query has no match, or the requested endpoint is unavailable |
| 4 | Permissions prevented a reliable answer |
| 5 | Kill cancelled |
| 6 | Protected process requires confirmation |

For `why`, success means the exact requested bind probe succeeded at the
recorded time. It does not guarantee that a later process will bind first.

When `why` evaluates several endpoints, map the aggregate result with this fixed
precedence:

1. Exit `1` if an operational failure prevented the complete evaluation.
2. Otherwise exit `4` if any endpoint lacks a reliable verdict due to permission.
3. Otherwise exit `3` if any endpoint is not bindable.
4. Exit `0` only when every evaluated endpoint is proven bindable now.

For `watch`, Ctrl-C, duration expiry, and a broken stdout pipe exit `0`. Invalid
arguments exit `2`. Initial collection failure or exhaustion of the bounded
consecutive-failure budget exits `1`.

### 0.4 Filter capabilities

Filters are command-scoped rather than globally accepted:

- `list` and the TUI continue to expose listening TCP and bound UDP only.
- `list` and the TUI do not accept `state:` because non-listening states are not
  in their visible data set.
- `watch` accepts `state:` and filters the complete socket-state snapshot.
- `why` uses exact endpoint arguments and verdict evidence, not general filters.
- Unsupported filters fail with a clear invalid-arguments error instead of
  silently matching nothing.

Pass explicit query capabilities into shared parsing so command support cannot
drift accidentally.

### 0.5 Probe dependency decision

The required pre-bind controls are not adequately expressed by `std::net`, in
particular deterministic reuse-address behavior and IPv6-only/dual-stack setup
before bind. Plan to use `socket2`; do not defer this decision until probe
implementation.

Before Phase 1 begins:

- Select a version compatible with the pinned Rust toolchain.
- Review its exact API and enabled features.
- Review maintenance, advisories, licenses, transitive dependencies, unsafe
  boundary, and expected binary-size impact.
- Record approval or stop the feature plan if the dependency is unacceptable.

### 0.6 Initial threat model

Record assets, trust boundaries, attacker-controlled inputs, privileged/native
operations, availability risks, and security objectives. At minimum cover:

- TOML configuration.
- CLI arguments and filter expressions.
- Kernel and native socket tables.
- Process names, command lines, and Docker metadata.
- Native FFI buffers and lengths.
- Terminal, JSON, and NDJSON output.
- Bind probes and OS error strings.
- Collection loops, retries, and memory growth.

### Phase 0 gate

- [ ] Contracts have no unresolved semantic ambiguity.
- [ ] Every public schema has a proposed versioned shape.
- [ ] Every supported platform has a documented source for each promised fact.
- [ ] Permanent limitations are accepted as contract, not deferred work.
- [ ] Security objectives and resource bounds are documented.
- [ ] `socket2` version, features, and dependency review are approved.

## Phase 1: Build the Observation Foundation

Create a platform-neutral observation layer. The likely layout is:

```text
src/observation.rs
src/observation/diff.rs
src/observation/verdict.rs
```

### 1.1 Core types

Introduce concrete domain types similar to:

```rust
pub struct NetworkSnapshot {
    pub captured_at: SystemTime,
    pub scope: ObservationScope,
    pub completeness: SnapshotCompleteness,
    pub sockets: Vec<SocketObservation>,
    pub processes: HashMap<ProcessIdentity, ProcessObservation>,
}

pub struct ProcessIdentity {
    pub pid: u32,
    pub start_marker: ProcessStartMarker,
}

pub struct SocketObservation {
    pub protocol: Protocol,
    pub local_endpoint: SocketAddr,
    pub state: SocketState,
    pub owner: OwnerObservation,
    pub socket_token: Option<PlatformSocketToken>,
}
```

Use an enum for platform start markers rather than an unqualified integer:

- Linux process start ticks.
- macOS process start timestamp or unique native identity.
- Windows process creation time.

Represent unverified ownership separately. Do not invent a placeholder start
marker or collapse missing, denied, and raced states into `None` without reason.

### 1.2 Invariants

Enforce these invariants by construction where practical:

- A verified process owner always has a PID and start marker.
- Unknown native socket states retain their native numeric value.
- Duplicate observations remain countable as a multiset.
- Labels are not stored by platform collectors.
- Human-facing certainty is assigned before rendering.
- Snapshot completeness describes the whole observation, while evidence gaps
  describe specific rows or claims.

### 1.3 Bounded consistency collection

Use a bounded consistency algorithm:

1. Record start timestamps.
2. Collect the socket table.
3. Collect process identities once per unique referenced PID.
4. Collect the socket table a second time.
5. Accept the snapshot if relevant identity rows are stable.
6. Retry the complete operation once if they changed.
7. Return a snapshot marked `Raced` if the second attempt is unstable.

Reuse existing socket, PID, row, file-descriptor, and byte limits. Add explicit
limits for consistency attempts and unique process identity reads. Never retry
until success.

Watch always uses this full consistency algorithm. If collection takes longer
than the requested interval, it starts the next poll after completion without
overlap or backlog and records the actual observation times. Benchmark results
may require raising the minimum supported interval or optimizing collection;
they may not weaken identity consistency or truthful race reporting.

### 1.4 Existing model migration

Derive `PortEntry` views from `NetworkSnapshot`. Do not keep old and new
collectors as independent sources of truth. Preserve current list, kill,
inspect, and TUI behavior while migrating callers.

The kill path is the highest-risk migration surface. Preserve this safety order
explicitly:

1. Freshly collect socket ownership.
2. Re-establish the requested target.
3. Verify PID and process start marker.
4. Verify every confirmed endpoint still belongs to that identity.
5. Reapply protected-process policy.
6. Deliver only through the already prepared identity-safe handle.

No signal may be sent when any earlier gate fails. Existing single-process,
tree, and group kill tests are named migration criteria, not incidental coverage.
Mutation confirmation must first cover ownership loss, PID reuse, endpoint
movement, newly protected targets, and signal non-delivery on every refusal.

### Phase 1 gate

- [ ] Core invariants are represented in types or checked at internal boundaries.
- [ ] Operational errors do not panic.
- [ ] Every collection path is bounded.
- [ ] Existing commands pass unchanged regression tests.
- [ ] Kill revalidation ordering and signal non-delivery remain proven by unit,
      contract, integration, and mutation-confirmed tests.
- [ ] Unit tests cover stable, partial, denied, raced, duplicate, zero, maximum,
      and maximum-plus-one observations.

## Phase 2: Complete Native Collection

No new command is exposed until all supported platform collectors satisfy the
shared contract.

### 2.1 Linux

- Retain every TCP state from `/proc/net/tcp` and `/proc/net/tcp6`.
- Retain UDP-bound observations.
- Preserve socket inode as an optional native token.
- Parse timer fields with checked, bounded integer conversion.
- Read process start ticks from `/proc/<pid>/stat`.
- Report current network namespace scope.
- Distinguish inaccessible owners from sockets with no owner.
- Mark timer expiry as estimated.
- Fail closed on oversized or malformed identity-critical files.

### 2.2 macOS

- Extend the existing PCB/libproc path to retain all exposed TCP states.
- Retain UDP endpoints and ownership where exposed.
- Obtain a native process start identity.
- Represent unavailable fields explicitly.
- Bound changing sysctl-buffer retries and allocations.
- Validate counts, lengths, alignments, and pointers before reading native data.
- Keep unsafe blocks small and add a local `// SAFETY:` proof to each one.

### 2.3 Windows

- Use extended TCP owner tables for IPv4 and IPv6.
- Use extended UDP owner tables for IPv4 and IPv6.
- Retain all documented TCP states.
- Use process creation time as the identity marker.
- Validate native table lengths before constructing slices or indexing rows.
- Keep Win32 unsafe boundaries small and locally documented.
- Report WSL as outside the Windows collector scope.
- Report excluded-port evidence only when obtained through a supported source.
- Never label an unexplained access denial as a proven Hyper-V reservation.

### 2.4 Shared state mapping

Use a shared state enum that preserves unknown values. The normal `list` and TUI
views may continue to show listening TCP and bound UDP rows, while the snapshot
retains all states for watch and why.

### Phase 2 gate

- [ ] All native values map to a shared state or `Unknown(native_code)`.
- [ ] All unsafe code has reviewed safety contracts.
- [ ] Permission and scope gaps remain visible.
- [ ] Native fixture tests cover every documented state and malformed tables.
- [ ] Linux, macOS, and Windows CI compile and run their collector tests.

## Phase 3: Implement Named Endpoints

Use endpoint-aware labels from the first release:

```toml
[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "udp"
address = "0.0.0.0"
port = 5353
label = "mDNS"

[[ports]]
protocol = "tcp"
address = "*"
port = 8080
label = "local web services"
```

`protocol` and `address` are required. The explicit address `"*"` means all
local addresses for that protocol. There are no hidden selector defaults.

### 3.1 Validation

- Cap labels at 256 entries.
- Cap label bytes and displayed columns separately.
- Reject empty and whitespace-only labels.
- Reject duplicate selectors at equal specificity.
- Reject missing or invalid protocols and addresses, and reject port zero.
- Reject unknown fields.
- Validate untrusted text at config load and sanitize again at render time.
- Test ANSI, control, bidi, zero-width, wide-Unicode, and overlong input.

### 3.2 Matching precedence

Apply one deterministic rule:

1. Exact protocol, address, and port.
2. Protocol and port with an explicit wildcard address.
3. No ambiguous match at the same specificity.

### 3.3 Surfaces

- Add a conditional `LABEL` column to the CLI table.
- Add a conditional `LABEL` column to the TUI without harming minimum-size
  behavior.
- Include labels in plain search.
- Add a `label:` structured filter.
- Add nullable label data to versioned JSON.
- Include labels consistently in watch and why output.

### Phase 3 gate

- [ ] Unconfigured users see no human-table layout change.
- [ ] Config errors name the invalid selector without leaking unsafe text.
- [ ] Matching and precedence are deterministic.
- [ ] JSON changes are pinned and documented.
- [ ] CLI and TUI rendering remain aligned for Unicode labels.

## Phase 4: Implement the Watch Engine

Create:

```text
src/watch.rs
src/cli/watch.rs
```

### 4.1 Pure diff engine

The core API compares two snapshots without I/O:

```rust
fn diff_snapshots(
    previous: &NetworkSnapshot,
    current: &NetworkSnapshot,
) -> Result<Vec<PortEvent>, DiffError>
```

Event kinds:

- `baseline`
- `bind`
- `release`
- `replacement`
- `collection_gap`

Rules:

- Changed verified start markers prove process replacement.
- A failed collection emits `collection_gap` and never fabricated releases.
- Recovery compares against the last valid snapshot.
- Respawn wording remains heuristic unless identity and parent evidence prove it.
- Events are deterministically sorted before writing.
- Duplicate sockets are diffed by multiplicity.

### 4.2 Bounded loop

Inject collector, monotonic clock, wall clock, sleeper, cancellation source, and
writer. Keep only the previous valid snapshot and the current bounded event
batch. Stream events and discard them after writing.

- Clamp interval to `100ms..=60s`.
- Validate and bound duration arithmetic.
- Bound consecutive collection failures.
- Use bounded retry delay or backoff.
- Exit cleanly on Ctrl-C or duration expiry.
- Exit `0` for Ctrl-C, duration expiry, and broken stdout pipes.
- Exit `1` for initial collection failure or exhausted failure budget.
- Flush output before returning.
- Treat a broken stdout pipe as successful consumer termination.
- Never use sleeps for synchronization in tests.

### 4.3 CLI contract

```text
kick watch
kick watch --tcp --address 127.0.0.1 --port 3000
kick watch --filter label:web
kick watch --interval 500ms
kick watch --duration 30s
kick watch --json
```

JSON mode emits only versioned NDJSON records on stdout. Diagnostics go to
stderr. The baseline is a typed event, not unstructured prose.

Watch never invokes Docker enrichment in its polling loop. Native socket and
process observations plus configured labels are sufficient for events. This
prevents a 100 ms interval from becoming an external-process spawn loop.

### Phase 4 gate

- [ ] Bind, release, replacement, duplicates, and gaps are correct.
- [ ] No failed snapshot fabricates events.
- [ ] Output ordering is deterministic.
- [ ] Memory remains bounded by two snapshots and one bounded event batch.
- [ ] Cancellation, duration, broken pipes, and repeated failures are tested.
- [ ] NDJSON schema and stdout/stderr separation are pinned.

## Phase 5: Implement Exact Bind Probes

Create `src/probe.rs` as a narrow OS-I/O boundary.

### 5.1 Probe contract

Represent an exact probe with protocol, address, port, IPv6-only behavior, and
reuse-address behavior. Outcomes must distinguish:

- Bindable now.
- Address in use.
- Permission denied.
- Address unavailable.
- Unsupported option or family.
- Other owned OS error.

### 5.2 Probe matrix

- TCP and UDP.
- IPv4 exact and wildcard addresses.
- IPv6 exact and wildcard addresses.
- IPv6-only mode.
- Dual-stack mode where supported.
- Default bind behavior.
- Explicit reuse-address diagnostics where requested.

Run probes sequentially to avoid self-interference. Bind and immediately close;
do not listen, accept, send, or receive.

Use the Phase 0-approved `socket2` version and feature set so reuse-address and
IPv6-only/dual-stack options are configured before bind. Do not reproduce this
platform-sensitive socket setup with new local unsafe code.

### Phase 5 gate

- [ ] Every supported matrix entry has a native test.
- [ ] Probe results preserve exact OS error categories.
- [ ] No probe leaves a socket or helper process behind.
- [ ] Probe language says "now" and does not promise future availability.
- [ ] The approved `socket2` dependency matches the reviewed lockfile version.

## Phase 6: Implement the Why Verdict Engine

Create:

```text
src/diagnostic/verdict.rs
src/cli/why.rs
```

The verdict engine is pure. It receives a query, snapshot, probe results, and
labels. It performs no OS calls.

### 6.1 CLI contract

```text
kick why 3000 --tcp --address 127.0.0.1
kick why 5353 --udp --address 0.0.0.0
kick why 3000 --all-addresses
kick why 3000 --all-protocols --all-addresses
kick why 3000 --json
```

A bare port evaluates a documented endpoint matrix and prints one verdict per
exact endpoint. It must not collapse conflicting endpoints into a universal
"port free" statement.

### 6.2 Verdicts

- `BindableNow`
- `Owned`
- `OwnerHidden`
- `KernelStateObserved`
- `PermissionDenied`
- `AddressUnavailable`
- `ReservationOrPolicyUnknown`
- `ObservationRaced`
- `Indeterminate`

### 6.3 Evidence order

1. Verified visible listener or UDP owner.
2. Visible endpoint with unreadable ownership.
3. Non-listening kernel state.
4. Exact bind-probe result.
5. Platform, namespace, or container supporting evidence.
6. Explicit evidence gaps and scope limitations.

Why may request Docker enrichment at most once after native collection and probe
evidence are complete. It must reuse the existing timeout, output, concurrency,
privilege, and process-reaping bounds. Docker evidence is optional supporting
context and never changes the core verdict or exit code.

### 6.4 Certainty language

- Proven: directly observed from a native source or exact probe.
- Estimated: derived from a timer or bounded polling interval.
- Heuristic: plausible interpretation not established by authoritative data.
- Unknown: unavailable because of permission, scope, race, or platform limits.

A Linux TIME_WAIT timer may be shown as an estimate. It must never be presented
as a guarantee that a future bind will succeed at expiration.

### Phase 6 gate

- [ ] Every verdict has an explicit certainty and evidence list.
- [ ] Conflicting evidence produces raced or indeterminate output.
- [ ] Exact queries never imply a host-wide conclusion.
- [ ] Human and JSON results carry equivalent facts.
- [ ] Every verdict maps to a documented exit code.

## Phase 7: Stabilize Public Output and Documentation

### 7.1 Serialized contracts

Version all new output envelopes. Pin at least:

- Snapshot JSON schema.
- Watch NDJSON event schema.
- Why JSON verdict schema.
- Certainty, scope, completeness, and evidence-gap values.

Do not serialize internal error types directly. Convert them into stable public
codes and sanitized messages.

### 7.2 Filters

Document and test the command-specific vocabulary:

- `list`: existing filters plus `label:`, `address:`, and `family:ipv4|ipv6`.
- TUI: the same visible-row filters as `list`.
- `watch`: list-compatible filters plus `state:` over all collected states.
- `why`: no general filter expression; exact endpoint arguments only.
- Unsupported command/filter combinations return exit `2` with a clear error.
- Existing filters with unchanged meanings.

### 7.3 User documentation

Update:

- README command overview.
- Complete config reference.
- CLI help text.
- JSON and NDJSON schema documentation.
- Exit-code contract.
- Platform support matrix.
- Linux namespace, Docker, WSL, and permission limitations.
- Bind-probe race warning.
- Polling visibility limitation.
- Proven, estimated, heuristic, and unknown terminology.
- Security and privacy implications of process metadata.
- Changelog entries for commands, config, filters, and schema additions.

Changelog entries and commit messages must describe their changes
self-contained. Do not write public history such as "implements Phase 4" that
requires this planning document to understand the change.

### Phase 7 gate

- [ ] Every public field and enum value is documented.
- [ ] Help and README examples match executable behavior.
- [ ] Permanent limitations are visible, not buried.
- [ ] Changelog identifies additive serialized-contract changes.

## Phase 8: Security Review and Remediation

Load and follow the security skill for a review-and-remediate pass.

### 8.1 Review scope

Trace every untrusted source to sensitive sinks:

- Config text to terminal and serialization.
- CLI arguments to parsing, filters, probes, and allocation.
- Native table lengths to buffer allocation and unsafe reads.
- Process metadata to terminal, logs, JSON, and NDJSON.
- OS errors to public diagnostics.
- Collection failures to retry behavior.

### 8.2 Required properties

- No shell or command injection path.
- No implicit privilege transition.
- No unbounded retry, allocation, output buffering, or event retention.
- No required side effect inside an assertion.
- No debug assertion used for memory safety or input validation.
- Checked arithmetic at FFI and timer boundaries.
- Sanitized terminal output and structured JSON serialization.
- No full command-line leakage unless explicitly requested and documented.
- No namespace entry or external probing without explicit future authorization.
- No Docker process spawn from the watch polling loop.

### 8.3 Dependency checks

If dependencies change, run repository supply-chain checks and an applicable
Rust advisory audit. Confirm advisory applicability rather than treating scanner
output as a finding by itself.

### Phase 8 gate

- [ ] Threat model reflects final architecture.
- [ ] Confirmed findings have regression tests and fixes.
- [ ] No unresolved release-blocking security finding remains.
- [ ] Residual risks are documented with evidence confidence.

## Phase 9: Automated Test Completion

Load and follow the test-quality skill. Tests must protect behavior and fail for
the intended reason when that behavior is broken.

### 9.1 Unit coverage

Observation tests:

- Verified and unverified owners.
- Duplicate sockets and multiplicity changes.
- Unknown native states.
- Stable, raced, denied, and partial snapshots.
- Empty, one, maximum, and maximum-plus-one boundaries.

Label tests:

- Exact and wildcard precedence.
- TCP/UDP and IPv4/IPv6 separation.
- Duplicate and ambiguous selectors.
- Empty, wide, hostile, and overlong labels.
- Entry-count boundaries.

Watch tests:

- Bind, release, replacement, and collection gap.
- Same PID with changed start marker.
- Failed snapshot followed by recovery.
- Deterministic ordering.
- Cancellation and duration boundaries.
- Broken pipe and writer errors.
- No event retention beyond the documented bound.

Why tests:

- Visible verified owner.
- Hidden owner.
- TCP and UDP probe outcomes.
- Wildcard conflicts.
- IPv4/IPv6 disagreement.
- Dual-stack behavior.
- TIME_WAIT remains estimated.
- Observation/probe disagreement.
- Scope and permission limitations.
- Every verdict-to-exit-code mapping.

### 9.2 Contract coverage

Pin:

- Config syntax and validation errors.
- Human tables with and without labels.
- Snapshot JSON schema.
- Watch NDJSON schema.
- Why JSON schema.
- Filter vocabulary.
- CLI help.
- Exit codes.
- Stdout/stderr separation.
- Existing CLI contracts.
- Command-specific filter acceptance and rejection.
- Multi-endpoint why exit-code precedence.
- Watch Ctrl-C, duration, broken-pipe, and failure-budget exit codes.

### 9.3 Integration helper

Extend the test helper to support:

- TCP4, TCP6, UDP4, and UDP6.
- Exact and wildcard binds.
- IPv6-only and dual-stack behavior.
- Controlled close and rebind.
- Replacement processes.
- Multiple sockets sharing an endpoint.
- Readiness and control through pipes or another deterministic IPC mechanism.

Use dynamically assigned ports. Do not use sleeps for synchronization. Give
every helper a deadline, explicit owner, and guaranteed cleanup path.

### 9.4 Mutation confirmation

For critical safety and contract tests, deliberately restore the relevant faulty
behavior once and confirm that the targeted test fails for the intended reason.
Restore the correct implementation before continuing.

### Phase 9 gate

- [ ] Tests assert concrete behavior and negative space.
- [ ] No flaky retry policy hides failures.
- [ ] No timing test relies on arbitrary sleeps.
- [ ] Critical tests were mutation-confirmed.
- [ ] The full suite passes repeatedly and in parallel where supported.

## Phase 10: Native Continuous Integration

Run the exact pinned toolchain and repository policy on Linux, macOS, and
Windows.

Required checks:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo build --locked --release --all-features --bin kickoutchi --bin kick
cargo deny check
```

Before pushing platform-sensitive changes from Linux, also run the repository's
cross-target tasks where the required targets are installed:

```text
mise run clippy-windows
mise run check-macos
mise run clippy-macos
```

If repository policy changes, update this section to match `mise.toml` and CI;
the current repository policy always wins over a stale command copied here.

Also run platform-native integration tests for collectors, process identity,
socket states, probes, watch, and why. Verify the release artifacts, not only
test-harness binaries.

### Phase 10 gate

- [ ] Linux native matrix passes.
- [ ] macOS native matrix passes.
- [ ] Windows native matrix passes.
- [ ] Both release binaries build on every target.
- [ ] No platform test is skipped merely to make the matrix green.

## Phase 11: End-to-End QA

Load and follow the QA skill against exact candidate release artifacts. Passing
unit tests and CI is necessary but not sufficient.

### 11.1 QA preparation

Record:

- Candidate commit and artifact checksum.
- Dirty or clean worktree state.
- OS, architecture, kernel, and runtime/tool versions.
- Material configuration.
- Test data and helper processes.
- Allowed actions, stop conditions, and cleanup plan.

Use local or isolated test environments. Do not use production or third-party
systems without explicit authorization.

### 11.2 Acceptance charters

Exercise as a real user:

- Upgrade from the previous release with no labels configured.
- Configure exact and wildcard labels.
- Use labels in list, TUI, search, filters, JSON, watch, and why.
- Watch bind, release, replacement, transient failure, recovery, duration, and
  Ctrl-C behavior.
- Diagnose TCP and UDP across IPv4, IPv6, wildcard, and dual-stack cases.
- Exercise permission-denied and partial-metadata cases.
- Confirm namespace, Docker, WSL, and platform limitations are reported.
- Pipe JSON and NDJSON through normal consumers and early-closing consumers.
- Exercise malformed, empty, maximum, and maximum-plus-one inputs.
- Confirm all helper processes and sockets are cleaned up.

### 11.3 Regression charters

Exercise existing behavior:

- Bare invocation and TUI startup.
- List table and JSON.
- Kill by PID and port.
- Protected-process confirmation.
- Tree and group kill on supported platforms.
- Inspect output.
- Config loading and error reporting.
- Short `kick` binary parity.

### 11.4 QA verdict

The QA report must state PASS, PASS WITH KNOWN ISSUES, FAIL, BLOCKED, or
INCONCLUSIVE, followed separately by `ship`, `hold`, or `no recommendation`.
Preserve the first intermittent failure. Do not retry until green.

### Phase 11 gate

- [ ] QA tested the exact release artifacts on all three platforms.
- [ ] QA verdict is PASS.
- [ ] QA release recommendation is `ship`.
- [ ] Cleanup was verified and residual risk is documented.

## Phase 12: Release Benchmark

Load and follow the benchmark skill only after correctness, security, automated
tests, and QA are complete. Benchmark release builds, never debug builds.

### 12.1 Decisions and budgets

Before measuring, declare practical regression budgets for:

- One-shot list latency.
- Snapshot collection latency at typical and high socket counts.
- Watch polling CPU and memory at supported minimum interval.
- Diff-engine throughput for empty, typical, large, and maximum snapshots.
- Why latency for observation plus the complete requested probe matrix.
- Peak RSS during list, watch, and why.
- Release binary size and dependency growth.

Thresholds must be chosen before results are seen and must exceed the measured
noise floor.

Performance findings may justify implementation optimization or a higher minimum
watch interval. They may not justify single-pass identity collection, overlapping
polls, skipped validation, fabricated certainty, or weaker kill revalidation.

### 12.2 Workloads

- Empty machine or isolated namespace baseline.
- Typical developer workload.
- Large synthetic socket table.
- Maximum supported observation size.
- Stable watch snapshots.
- High-churn watch snapshots.
- Transient collection failures.
- TCP/UDP and IPv4/IPv6 why probes.
- Cold and warm CLI startup where meaningful.

### 12.3 Measurement discipline

- Compare baseline and candidate on the same machine and workload.
- Use production-equivalent release artifacts and flags.
- Record compiler, target, CPU, RAM, OS, kernel, thermal/power state, and
  concurrent load.
- Interleave or randomize baseline and candidate runs.
- Capture raw samples and exact commands.
- Report independent run count and uncertainty.
- Report p50, p95, p99, max, throughput, errors, CPU, peak RSS, and binary size
  where applicable.
- Treat noisy or threshold-crossing uncertainty as inconclusive.
- Never accept faster output that loses rows, evidence, validation, or safety.

### 12.4 Benchmark artifacts

Store reproducible commands, workload generation, raw machine-readable results,
and a concise report in an approved repository or release-artifact location.
Do not commit machine-specific marketing numbers without context.

### Phase 12 gate

- [ ] Correctness was verified before measurement.
- [ ] Baseline and candidate were measured under equivalent conditions.
- [ ] No practical regression budget was exceeded.
- [ ] Results are reproducible and include uncertainty and caveats.
- [ ] Binary and dependency growth are justified.

## Phase 13: Final Release Review

Perform one final review of the complete diff, not only the last phase.

### 13.1 Code review

- Recheck ownership, error flow, bounds, and state transitions.
- Recheck every unsafe block and native conversion.
- Recheck that operational failures cannot panic.
- Recheck deterministic output and stable schemas.
- Recheck that comments explain rationale and invariants.
- Remove dead compatibility layers, unused abstractions, and stale TODOs.

### 13.2 Release review

- Confirm version is a minor release.
- Confirm changelog entries are complete.
- Confirm README and help output match behavior.
- Confirm lockfile and dependency policy.
- Confirm artifact generation and checksums.
- Confirm native CI results belong to the exact release commit.
- Confirm QA and benchmark results belong to the exact release artifacts.

## Final All-or-Nothing Release Gate

Do not release unless every item is checked:

- [ ] All three features are complete.
- [ ] No supported platform has a provisional or reduced implementation.
- [ ] No required semantic decision remains deferred.
- [ ] All resource limits are explicit and tested.
- [ ] All unsafe code has a reviewed local safety proof.
- [ ] Existing command behavior remains regression-clean.
- [ ] Config, filters, output schemas, and exit codes are frozen and documented.
- [ ] Linux, macOS, and Windows native CI passes on the exact release commit.
- [ ] Security review has no unresolved release blocker.
- [ ] Automated tests are deterministic and repeatedly green.
- [ ] QA verdict is PASS and recommendation is `ship`.
- [ ] Release benchmark is trustworthy and within declared budgets.
- [ ] Changelog, README, help, and platform limitations are complete.
- [ ] Release artifacts and checksums were verified.

If any item fails, the release is held. Do not hide an incomplete path behind a
feature flag, undocumented fallback, optimistic wording, or a promise to fix it
after release.

## Expected Scope

This is a substantial cross-platform project. A realistic estimate is four to
eight weeks of focused implementation and verification, with native macOS and
Windows collection, dual-stack probe semantics, and integration testing likely
to dominate the schedule.

The internal implementation order is:

1. Freeze contracts and threat model.
2. Build the observation foundation.
3. Complete all platform collectors.
4. Implement named endpoints.
5. Implement watch.
6. Implement exact bind probes.
7. Implement why.
8. Freeze output and documentation.
9. Complete security review and remediation.
10. Complete deterministic automated tests.
11. Pass native CI.
12. Pass end-to-end QA.
13. Pass the release benchmark.
14. Pass the final all-or-nothing release gate.

Development may proceed phase by phase. Release remains atomic.
