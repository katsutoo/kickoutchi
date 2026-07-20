# Named Ports, Watch, and Why

## Status

This document is the implementation and release plan for three related features:

- Named endpoint labels.
- `kick watch`, a bounded polling event stream.
- `kick why`, an evidence-based endpoint diagnostic command.

The features may be developed in internal stages, but they ship together or not
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
for programmer-error invariants. Every retry loop and every operation with
application-controlled termination has an explicit iteration or duration bound.
A no-duration watch may run until cancellation; each poll, allocation, table,
buffer, label, event batch, native read, and retained state set remains
independently bounded.

## Definition of Complete

The release is complete only when all of the following are true:

- Named endpoints work in config, CLI tables, the TUI, plain search,
  structured filters, JSON, watch, and why.
- Watch reports deterministic, bounded events using verified process identity
  where the platform exposes it.
- Why evaluates exact protocol/address/port targets and labels every conclusion
  as proven, estimated, heuristic, or unknown.
- Linux, macOS, and Windows retain every TCP state exposed by the supported
  native collection path and every UDP endpoint exposed as bound. Native UDP
  status fields are not treated as a portable lifecycle-state vocabulary.
- Observation scope, permissions, races, and unavailable platform fields are
  represented explicitly.
- Human output, JSON, NDJSON, filters, config, and exit codes are documented and
  pinned by contract tests.
- Automated tests and native end-to-end tests pass on every supported platform.
- Security review has no unresolved release-blocking finding.
- QA returns PASS and recommends `ship` for the exact release artifact.
- The final benchmark is reproducible and stays within predeclared regression
  budgets.

## Stage 0: Freeze the Contracts

Do not start platform implementation until these contracts are written and
reviewed.

### 0.1 Observation vocabulary

Use the following vocabulary throughout collectors, analysis, schemas, tests,
and documentation:

- `Protocol` is exactly `Tcp` or `Udp`.
- An endpoint identity is a concrete protocol, `IpAddr`, validated port in
  `1..=65535`, and IPv6 scope. IPv4 scope is always absent. IPv6 scope is
  `Unscoped`, `InterfaceIndex(nonzero u32)`, or `Unavailable`; collectors retain
  a native scope index whenever the source exposes one. Observed endpoints never
  contain a wildcard. `Unavailable` retains the row, adds
  `native_field_unavailable`, cannot match an exact selector, and prevents an
  exact-address proven claim.
- An endpoint selector is separate from endpoint identity. Its address is either
  one exact `IpAddr` or the explicit `AnyLocalAddress` value represented as `"*"`
  in configuration. Hostnames, DNS resolution, interface names, and CIDR ranges
  are not endpoint selectors in this release. An exact IPv6 selector may include
  an optional separate numeric `scope_id`; it matches only the same scope, and
  absence matches only an unscoped endpoint. `scope_id` is invalid for IPv4 and
  wildcard selectors. CLI address arguments use the same literal address plus
  optional `--scope-id` rule; `%zone` text and interface names are rejected.
  Why probe targets follow this selector-style rule: an explicit IPv6 address
  without `--scope-id` is unscoped. Watch address flags are filters instead:
  `watch --address` matches the normalized address component across all scopes,
  while `--scope-id` optionally narrows that filter to one interface index.
- A process identity is a PID plus `ProcessStartMarker::LinuxStartTicks`,
  `ProcessStartMarker::MacOsStartTime`, or
  `ProcessStartMarker::WindowsCreationTime`. Values from different marker
  variants are never compared.
- An attributable owner is `Verified(ProcessIdentity)` or `UnverifiedPid { pid,
  reason }`. Each native socket has a bounded owner set plus owner-attribution
  completeness of `Complete`, `Partial { reason }`, or `Raced`. An empty complete
  set means `NoOwnerObserved`; an empty partial set does not claim that no owner
  exists. Hidden ownership that cannot be tied to one endpoint is a snapshot gap,
  not a fabricated per-socket owner. On Linux, socket-local `Complete` means the
  attributable `/proc/<pid>/fd` owner edges for that inode were complete; it does
  not prove that an unreadable process is not a same-inode co-holder.
- A platform socket token is a typed optional opaque value such as `LinuxInode`
  or `MacOsSocketId`. No synthetic token is created on a platform that does not
  expose one. Linux `/proc/net` inodes and macOS `socket_info.soi_so` values may
  be retained and used for within-pass association and deterministic ordering,
  but neither has an approved cross-capture uniqueness guarantee. A token alone
  therefore never raises replacement certainty to `Proven` in this release.
- TCP state values are `Closed`, `Listen`, `SynSent`, `SynReceived`,
  `Established`, `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`,
  `TimeWait`, `DeleteTcb`, `NewSynReceived`, or `Unknown(native_code)`. UDP uses
  `Bound`. A platform UDP status field may be retained later as separate native
  evidence, but this release does not reinterpret it as a TCP-style lifecycle
  state. Platform-specific known TCP states remain valid shared values even when
  another platform never emits them.
- The state order is the TCP order listed above, followed by UDP `Bound`, then
  `Unknown` ordered by native numeric code. This order is public wherever state
  sorting affects serialized or human output.
- A Linux TCP timer observation is optional and separate from socket state. It
  contains `kind`, `native_code`, `raw_ticks`, and
  `estimated_remaining_milliseconds`. Known kinds are `none`, `retransmit`,
  `other`, `time_wait`, and `zero_window_probe`, mapping Linux `/proc/net/tcp*`
  timer-active values `0..=4`; every other value is `unknown` and retains its
  unsigned native code. `raw_ticks` is the unsigned hexadecimal `tm->when`
  value. The estimate is present only when `_SC_CLK_TCK` returns a positive
  value representable as `u64`; it is
  `ceil(raw_ticks * 1000 / clock_ticks_per_second)` milliseconds using checked
  `u128` arithmetic followed by checked conversion to `u64`. Overflow or an
  unavailable clock rate leaves the estimate null while retaining kind and raw
  ticks. The estimate has `Estimated` certainty and is never a release-time or
  future-bindability promise. Non-Linux and UDP sockets have no timer
  observation in this release.
- A snapshot records collection start and completion wall-clock times. Monotonic
  time is internal and is used for polling, duration, and retry arithmetic.
- A snapshot has global owner-attribution completeness of `Complete`, `Partial`,
  or `Raced` in addition to each socket owner set. An endpoint-null ownership gap
  makes global attribution partial and disables claims that require globally
  complete ownership, while retaining every socket's separate local
  completeness and all observed owner edges. Global uncertainty is never
  rewritten as endpoint-local hidden ownership.
- Observation scope is `CurrentNetworkNamespace` on Linux,
  `CurrentHostProcessVisibleSockets` on macOS, and `CurrentHostNetworkStack` on
  Windows. Linux identifies its namespace from `/proc/self/ns/net` when readable.
  The macOS scope names the process-first libproc coverage and is not a claim of
  global PCB visibility. Windows excludes WSL networking. macOS and Windows have
  no native scope identifier in this release.
- Snapshot completeness is `Complete`, `Partial`, or `Raced`. A failed
  collection returns an error and is not represented as an empty snapshot.
- Evidence gaps use stable reason codes. The initial set is
  `owner_permission_denied`, `owner_attribution_incomplete`,
  `owner_disappeared`, `process_identity_unavailable`,
  `process_metadata_unavailable`, `native_field_unavailable`,
  `scope_excluded`, `noncritical_evidence_truncated`, and `observation_raced`.
- Every evidence gap has impact `Metadata`, `Ownership`, `SocketSet`, or `Scope`.
  The impact determines which analyses may still use a partial snapshot; the
  reason code alone is not interpreted by renderers.
- Certainty is `Proven`, `Estimated`, `Heuristic`, or `Unknown`. `Proven` means
  the specific claim is directly established by an authoritative native fact or
  exact probe; a native value alone does not prove cross-capture token identity,
  replacement, respawn, ownership completeness, or future availability. Certainty applies
  to a claim or verdict, not to decorative output text.
- Individual socket observations remain a multiset. Shared, inherited, and
  reuse-port sockets are not replaced internally by one endpoint count.

### 0.2 Public contracts

The feature-specific contracts in Stages 3 through 7 are part of the Stage 0
freeze and are normative before their implementation begins. The following
cross-cutting rules apply to every public surface:

- Human output may change layout only when the user configures labels or invokes
  a new command. Existing unconfigured list and TUI layouts remain unchanged.
- Existing `list --json` remains a top-level array throughout the `1.x` series,
  is documented as `kickoutchi.list/1`, and gains only the approved nullable
  `label` field. A versioned full snapshot uses the new, mutually exclusive
  `list --snapshot-json` mode; it does not replace the existing array.
- Snapshot JSON, watch NDJSON, and why JSON carry `schema` and integer `version`
  fields. Public DTOs are separate from internal Rust error and domain types.
- Structured timestamps are unsigned Unix milliseconds and include collection
  start and completion. Human output may format them as readable dates.
- New snapshot, watch, and why output omits full process command lines by
  default. Existing `list --json` retains its command-line field and raw value
  when the bounded read is at most 1 MiB. Larger values become `null` with
  partial metadata rather than an unbounded read or a silently truncated value;
  process names above 4 KiB and executable paths above 128 KiB receive the same
  explicit null/partial treatment. These named value and aggregate metadata
  bounds are safety exceptions to legacy value compatibility. Additional
  exposure requires a separately reviewed explicit diagnostic mode.
- Public string limits apply to the final UTF-8 byte representation. Process
  names and command lines retain the current lossy decoding semantics: invalid
  Unix bytes or Windows UTF-16 sequences become U+FFFD. An executable path that
  is not valid UTF-8 becomes `null`, adds `process_metadata_unavailable`, and
  makes metadata partial. Collectors bound native bytes or code units before
  conversion and recheck final UTF-8 bytes before retention. A legacy "raw"
  command-line value means the existing decoded string, not raw OS bytes.
- Machine-readable enum values and field names use lowercase `snake_case`.
  Stable public codes, not localized messages, are the programmatic contract.
- Stdout contains only the requested human or structured result. Diagnostics,
  warnings, and operational errors use stderr. JSON and NDJSON stdout is never
  contaminated with prose.
- A broken stdout pipe is successful consumer termination for list, inspect, and
  watch. Kill has no stdout result, so the rule is not applicable to kill. Why
  evaluates every endpoint before writing; a broken stdout pipe preserves its
  already-computed aggregate exit code instead of converting an unavailable
  endpoint into success. Every other writer or flush error is operational
  failure and exits `1`.
- Existing list, kill, inspect, TUI, config, and short-binary behavior remains
  compatible unless this plan names an additive change explicitly.
- Config reads remain byte-bounded, but a user-supplied special file or a stalled
  filesystem may block in the host OS. The CLI does not claim a portable config
  read deadline in this release. An absent default config retains its current
  success behavior.

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

When `why` evaluates several endpoints, first map each completed endpoint
verdict through Stage 6.2, then use this fixed precedence:

1. Exit `1` if an operational failure prevented complete evaluation or any
   completed endpoint maps to `1`.
2. Otherwise exit `4` if any endpoint maps to `4`.
3. Otherwise exit `3` if any endpoint maps to `3`.
4. Exit `0` only when every evaluated endpoint is proven bindable now.

For `watch`, Ctrl-C, duration expiry, and a broken stdout pipe exit `0`. Invalid
arguments exit `2`. Initial collection failure or exhaustion of the bounded
consecutive-failure budget exits `1`.

### 0.4 Filter capabilities

Filters are command-scoped rather than globally accepted:

- `list` and the TUI continue to expose listening TCP and bound UDP only and
  accept existing filters plus `label:`, `address:`, `scope_id:`, and
  `family:ipv4|ipv6`.
- `list` and the TUI do not accept `state:` because non-listening states are not
  in their visible data set.
- `watch` accepts the list/TUI vocabulary plus `state:` and filters the complete
  socket-state snapshot.
- `why` uses exact endpoint arguments and verdict evidence, not general filters.
- A recognized structured field unsupported by the current command fails with a
  clear invalid-arguments error. An unrecognized `name:value` token retains the
  existing plain-text-search behavior and is not a structured filter.

Pass explicit query capabilities into shared parsing so command support cannot
drift accidentally.

### 0.5 Probe dependency decision

The required pre-bind controls are not adequately expressed by `std::net`, in
particular deterministic reuse-address behavior and IPv6-only/dual-stack setup
before bind. Use `socket2` version `0.6.5` with default features only; do not
enable its `all` feature.

The selection is compatible with the pinned toolchain because its declared MSRV
is Rust 1.70. Its `MIT OR Apache-2.0` license is allowed by repository policy.
Its target dependencies, `libc ^0.2.172` and `windows-sys >=0.60,<0.62`, are
expected to unify with the versions already used by this repository. Linux,
macOS, and Windows are upstream Tier 1 targets. RUSTSEC-2020-0079 affects old
versions and is fixed from `0.3.16`, so it does not apply to `0.6.5`.

The selected application wrapper exposes only socket creation, reuse-address setup,
IPv6-only setup, bind, and owned drop. It does not expose raw handles, listen,
connect, accept, send, or receive. This keeps upstream unsafe system-call code
behind a narrow safe boundary. Record as residual supply-chain risk that the
upstream Windows implementation contains an unused vectored-send safety FIXME;
the selected probe path does not call that API.

Before Stage 1 begins, review the exact lockfile diff, run repository
supply-chain and advisory checks, confirm dependency unification, compile and
test the dependency on all native targets, and measure the release binary-size
delta. Until those checks pass, `0.6.5` is the conditionally accepted candidate,
not the approved dependency. Any failed check blocks the feature plan.

### 0.6 Initial threat model

Protect these assets:

- Correct process identity and signal delivery.
- Truthful endpoint ownership, availability, scope, and certainty claims.
- Memory safety at native and FFI boundaries.
- Predictable CPU, memory, process, file-descriptor, and output use.
- Terminal integrity and stable structured output.
- Privacy of process names, paths, command lines, and container metadata.
- Reproducible dependency and release integrity.

The relevant attacker is a local unprivileged user or process able to control a
configuration file, CLI arguments, process metadata, socket churn, or output
consumer. Kernel/native APIs are trusted for authority but not for stable sizes,
well-timed results, or Rust memory safety. Docker output and dependency source
code cross separate trust boundaries. No production or third-party system is an
authorized security-test target under this plan.

| Threat | Required control | Verification |
| --- | --- | --- |
| Config, process, Docker, or OS text controls the terminal | Validate bounded config text and sanitize again at every terminal sink | Hostile Unicode and control-character tests |
| Malformed native counts, lengths, or pointers cause invalid memory access | Checked arithmetic, pre-read bounds, alignment validation, and local `// SAFETY:` proofs | Malformed native fixtures and unsafe review |
| PID reuse or endpoint movement targets the wrong process | Typed start markers, fresh ownership collection, prepared identity-safe handles, and fail-closed revalidation | Mutation-confirmed non-delivery tests |
| Collection churn creates false ownership or fabricated watch events | Bounded two-pass consistency collection, explicit `Raced`, and recovery from the last valid snapshot | Deterministic race and recovery tests |
| Permission or scope gaps become a false "free" verdict | Explicit owner/gap/scope states, unknown certainty, and exit `4` where permission blocks reliability | Permission and namespace tests |
| Large tables, metadata, labels, or diffs exhaust resources | The Stage 0.7 limits, checked capacity arithmetic, streaming writers, and no retry-until-success | Zero, maximum, and maximum-plus-one tests |
| Watch accumulates unbounded state or spawns Docker repeatedly | Retain two snapshots and one bounded batch; never invoke Docker in the loop | Long-run and injected-failure tests |
| Bind probes interfere with one another or leak sockets | Sequential probes, RAII-owned sockets, bind then immediate drop, and no listen/send/receive | Native cleanup and rebind tests |
| A bind probe transiently denies the endpoint to an unrelated local binder | Keep each sequential RAII socket alive only through option setup and bind-result capture; document that `why` is diagnostic but not side-effect-free | Concurrent controlled-binder QA and help-text review |
| Shell or argument injection reaches Docker or another executable | No shell; fixed executable plus structured arguments; Docker remains optional evidence | Source-to-sink review and hostile-input tests |
| PATH substitution changes the Docker executable | PATH resolution is intentional only at proven ordinary privilege; skip when privilege is elevated or uncertain; treat output as non-authoritative and invoke at most once in why | Privilege/PATH unit tests and QA with Docker absent |
| A special config file, stalled filesystem, or stalled output consumer blocks synchronous I/O | Retain byte/memory caps, stream output without accumulation, and document host-OS backpressure as residual risk | Bounded-reader and early-closing consumer tests |
| New output leaks full command lines or unstable OS errors | Omit command lines by default; stable error codes plus sanitized messages | Schema and privacy contract tests |
| Dependency compromise or known unsoundness reaches release artifacts | Locked dependency, advisory applicability review, cargo-deny policy, native builds, and checksum verification | Recorded dependency and artifact review |

Residual risks that must remain documented are polling blind spots between
snapshots, a successful probe losing a later bind race, the probe itself briefly
occupying a successfully bound endpoint and racing another local binder,
unavailable information
outside the current namespace or host stack, OS/API behavior that differs across
versions, a Linux unreadable process sharing a visible socket inode, the private
Windows Job Object freeze ABI changing semantics, and the remaining macOS
interval between final identity check and signal delivery. A kernel API or stdout
consumer may also block a synchronous OS call beyond an application-controlled
duration; the implementation bounds retained memory and side effects but does
not claim a portable write deadline. These risks may not be described as proven
absence or future availability.

### 0.7 Resource bounds

Use these release-contract limits. A lower platform-native limit wins when an OS
API cannot safely support the shared maximum.

| Resource | Limit |
| --- | ---: |
| Config file | 64 KiB |
| Label selectors | 256 |
| Label text | 128 UTF-8 bytes |
| Displayed label | 32 terminal columns |
| Filter expression | 256 bytes |
| Native socket table buffer | 16 MiB per table |
| Socket observations per snapshot | 262,144 |
| Candidate or uniquely referenced PIDs | 131,072 |
| Aggregate Linux file-descriptor entries | 1,048,576 |
| Aggregate macOS file-descriptor entries per collection pass | 1,048,576 |
| Owner edges per owner-association pass | 262,144 |
| Process identity reads per consistency attempt | 262,144; 524,288 across both attempts |
| Derived `PortEntry` rows | 262,144 |
| Serialized owners per owner set | 64 plus an omitted count |
| Owner-completeness reason codes per set | 8 |
| Process name | 4 KiB |
| Executable path | 128 KiB |
| Process command line read | 1 MiB on every supported platform |
| Aggregate optional process metadata per snapshot | 64 MiB |
| Fresh protection name read | 4 KiB per target; 2 MiB across a 512-member scope |
| Consistency collection attempts | 2 total |
| Native changing-size buffer attempts | 3 per independent bounded native read |
| Retained evidence-gap records | 4,096 plus an omitted count |
| Scope identifier | 256 UTF-8 bytes after sanitization |
| Scope limitation codes | 8 |
| Retained watch snapshots | Previous valid plus current |
| Watch events produced per poll | 524,288 |
| Retained watch event batch | 4,096 events |
| Evidence items per watch event | 8 plus an omitted count |
| Evidence gaps per watch event | 8 plus an omitted count |
| Watch interval | `100ms..=60s`, default `1s` |
| Consecutive watch collection failures | 3 |
| Explicit watch duration | `100ms..=7d` |
| Why endpoints per invocation | 8 |
| Evidence items per why verdict | 16 plus an omitted count |
| Evidence gaps per why verdict | 16 plus an omitted count |
| Public evidence message | 512 UTF-8 bytes after sanitization |
| CLI literal address token | 64 bytes |
| NDJSON record | 64 KiB |

The per-poll event limit is twice the socket-observation limit so a complete
replacement between maximum snapshots is representable. Use checked arithmetic
to derive it. A deterministic merge emits batches of at most 4,096 events; it
does not retain all maximum-poll events simultaneously. Stream human, JSON, and
NDJSON output directly to a writer; do not build the complete rendered result in
one `String`.

The 64 KiB NDJSON cap covers the maximum compact replacement record by
construction. Its conservative bound is `2 * 64 * 192` bytes for two maximum
owner sets, `2 * 1024` bytes for owner-set wrappers and reasons, `8 * 1280` bytes
for evidence, `8 * 1408` bytes for evidence gaps, and 4,096 bytes for endpoint,
tokens, label, fixed fields, separators, and newline: 52,224 bytes total. The
message terms include worst-case two-byte JSON escaping for each sanitized input
byte. Any schema change must recalculate this bound before approval; a legal
maximum record may never fail with `event_limit_exceeded`.

Malformed or oversized native tables, unsafe native lengths, and malformed or
oversized identity-critical records fail the collection attempt. Permission or
race failures while reading one process identity remain explicit unverified
ownership and make the snapshot partial or raced; they never create a marker.
Unavailable bounded non-critical metadata produces `Partial` plus an evidence
gap. When the evidence-gap list reaches its cap, increment the serialized omitted
count and keep the snapshot partial instead of silently dropping that fact.

Existing stricter kill, tree, group, Docker, confirmation-input, and process-wait
limits remain unchanged unless a later measured change is separately approved.

### 0.8 Boundary-test plan

Every production limit is a named constant. Tests for large aggregate limits may
exercise the algorithm through an injected smaller limit, but must also assert
that the production constant equals this contract and that checked arithmetic is
identical. Per-value byte limits and serialized-record limits use their actual
production values. "Above" means the smallest representable value greater than
the maximum; no test performs an allocation before the above-limit refusal.
Exact shared-maximum acceptance is tested through source-independent domain and
serialization fixtures. If a documented native API has a lower representable
maximum, native tests cover that exact native maximum and first rejected value;
the lower source limit does not change the shared retained-data maximum.

| Resource | Zero or below-minimum case | Exact maximum case | Maximum-plus-one case |
| --- | --- | --- | --- |
| Endpoint port | Port zero rejected | 65,535 accepted | 65,536 rejected before conversion |
| IPv6 scope ID | Zero rejected as an interface index; IPv4-with-scope rejected | `u32::MAX` accepted | `u32::MAX + 1` rejected before conversion |
| Config bytes | Empty file succeeds | 65,536 bytes accepted | 65,537th byte rejected before retention |
| Label selectors | Zero selectors preserves legacy layout | 256 accepted | 257 rejected |
| Label bytes / columns | Empty label rejected; empty rendered value impossible | 128 bytes accepted; 32 columns displayed | 129 bytes rejected; 33 columns clipped to at most 32 |
| Filter bytes | Empty filter succeeds | 256 bytes accepted | 257 rejected before term parsing |
| Native table bytes | Zero-row table accepted when native format permits | 16 MiB accepted | 16 MiB plus one rejected before allocation/read |
| Socket observations | Empty snapshot accepted | 262,144 accepted | 262,145 rejected |
| Candidate or uniquely referenced PIDs | Zero candidates/references accepted | 131,072 accepted independently on each path | 131,073 rejected before identity reads on each path |
| Linux/macOS FD entries | Zero entries accepted | 1,048,576 accepted per applicable scope | 1,048,577 rejected before retention |
| Owner edges | Zero edges accepted | 262,144 accepted | 262,145 rejected |
| Identity reads | Zero reads accepted | 262,144 in one attempt and 524,288 total accepted | One more than either bound rejected; no third attempt |
| Derived legacy rows | Zero rows accepted | 262,144 accepted | 262,145 rejected before projection retention |
| Serialized owners | Empty complete and empty partial sets retain distinct meaning | 64 serialized | 65th counted as omitted without changing completeness |
| Owner reason codes | Zero reasons accepted where complete | Eight distinct reasons accepted | Ninth is `owner_reason_limit_exceeded` |
| Name/path/command bytes | Empty values retain defined empty-string semantics except protection names, which refuse | 4 KiB / 128 KiB / 1 MiB retained | One byte above becomes null plus partial metadata and a gap |
| Aggregate optional metadata | Zero metadata accepted | 64 MiB retained | Next value omitted before allocation; identities and sockets remain |
| Fresh protection evidence | Empty name refuses; zero-member scope is a no-op | 4 KiB name, 512 members, and 2 MiB aggregate accepted | 4 KiB+1, member 513, or 2 MiB+1 refuses delivery |
| Consistency attempts | Collector never performs zero passes for a requested snapshot | Stable second pass completes attempt two | A third complete attempt is never started |
| Changing-size read attempts | No call occurs after prevalidation refusal | Success on attempt three accepted | Fourth attempt never starts |
| Snapshot evidence gaps | Empty list preserves independently derived completeness | 4,096 retained | 4,097th increments omitted count and forces partial |
| Scope identifier / limitations | Null identifier and zero limitations accepted | 256 UTF-8 bytes and eight codes accepted | Byte 257 yields null, one endpoint-null `native_field_unavailable` Scope gap, and partial completeness without retaining a prefix; ninth distinct code is an operational error |
| Retained watch snapshots | Before baseline none are retained | Previous and current only | Installing a third drops the no-longer-needed snapshot first |
| Watch events / batch | Zero-event diff writes nothing | 524,288 events counted; batches contain at most 4,096 | Event 524,289 fails; event 4,097 starts a new batch rather than failing |
| Watch evidence/gaps | Zero-item arrays accepted | Eight items and eight gaps retained | Ninth increments the applicable omitted count |
| Watch interval | Zero and 99 ms rejected | 100 ms and 60 s accepted | 60 s plus 1 ms rejected |
| Consecutive failures | Zero after baseline and after recovery | Third gap is flushed, then exit 1 | Fourth collection is never attempted |
| Watch duration | Zero and 99 ms rejected | 100 ms and seven days accepted | Seven days plus 1 ms rejected |
| Why endpoints | Zero endpoints rejected | Eight evaluated sequentially | Ninth rejected before collection/probing |
| Why evidence/gaps | Zero-item arrays accepted | 16 items and 16 gaps retained | 17th increments the applicable omitted count |
| Evidence message | Empty explanatory message accepted only where the code remains sufficient | 512 UTF-8 bytes retained | 513th byte clipped safely before serialization |
| CLI address token | Empty rejected | 64 bytes parsed | 65th byte rejected before IP parsing |
| NDJSON record | Structurally minimal legal record is serialized and nonempty | Bounded-writer fixture accepts exactly 65,536 bytes; fully populated legal event remains within the separately calculated 52,224-byte bound | Writer refuses byte 65,537 without emitting a partial line |

Inherited limits receive the following explicit production-constant tests. Fixed
deadlines use injected clocks; tests do not sleep until a real deadline.

| Inherited resource | Zero or below-minimum case | Exact maximum case | Maximum-plus-one case |
| --- | --- | --- | --- |
| Config refresh seconds | Zero rejected | 1 and 3,600 accepted | 3,601 rejected |
| Protected process names | Empty extension accepted; empty name rejected | 256 merged names accepted | 257 rejected |
| macOS FDs per process | Zero accepted | 65,536 accepted | 65,537 rejected before allocation |
| Tree/group members | Missing/zero-member target refused | 256 tree and 512 group accepted | Member 257/513 refused before delivery |
| Group `--yes` members | Empty group refused | Eight accepted when warning-free | Ninth requires interactive confirmation |
| Unix freeze passes | Stable first pass accepted | Convergence on pass eight accepted | Pass nine never starts; all frozen members are thaw-attempted |
| Windows tree sweep passes | Stable first sweep accepted | Convergence on sweep eight accepted across the pre-freeze and frozen phases combined | Sweep nine never starts and post-commit partiality is reported |
| Confirmation input | Empty fails confirmation | 128 UTF-8 bytes accepted when otherwise valid | Byte 129 rejected and input remains untruncated |
| Post-kill settle | Zero attempts is impossible for a requested settle | Port disappearance on attempt ten succeeds | Attempt eleven never starts; timeout remains truthful |
| Windows single-process wait | Zero-time probe remains nonblocking | Exit at the five-second deadline succeeds | No wait beyond the shared deadline; survivor is unconfirmed |
| Windows tree wait | Zero-time per-handle probes remain nonblocking | All members share exactly five seconds | No member extends the shared deadline; survivors are reported |
| Docker command/drain time | Zero deadline returns immediately in injected-clock tests | Completion at 1,500 ms / 250 ms accepted | No poll or wait occurs after either deadline |
| Docker output bytes | Empty stream accepted | 256 KiB retained | Byte 262,145 drained but not retained |
| Docker drain workers | Zero available capacity refuses spawn | Eight workers acquired | Ninth refused until capacity returns |
| Docker rows/matches | Empty output yields none | 128 rows and eight matches retained | Row 129 ignored; match nine omitted deterministically |
| Docker field bytes | Empty fields handled by parser rules | 4 KiB accepted | 4 KiB+1 row rejected without prefix retention |
| Docker port segments | Empty segment list matches nothing | 64 parsed | Segment 65 rejects the row |
| Docker privilege-status read | Empty/malformed status fails closed | 64 KiB accepted | 64 KiB+1 fails closed before Docker execution |
| Linux identity-critical status/stat reads | Empty/malformed identity input fails closed | 1 MiB status and 4 KiB stat accepted | Next byte fails before parsing and no prefix is used |
| Linux protected `comm` comparison | Empty process name never proves unprotected | Exact 15-byte kernel `comm` comparison accepted | Configured byte 16 participates only in the documented truncation-aware exact rule, never substring matching |
| Platform children/hints/ancestors | Empty lists accepted | 64 children, eight hints, and 64 ancestors retained | Next item omitted with existing partial/truncation semantics |
| Inspect display ancestors/siblings/tree/group | Empty sections render safely | 12/8/20/16 displayed | Next item is omitted with explicit summary wording |
| Inspect ancestor walk | Missing parent stops immediately | 64 parent edges traversed | Edge 65 is never followed; the report marks the bounded stop |
| Inspect command/diagnostic text | Empty text remains safe | 120/240 characters displayed | Next character clips without control-sequence leakage |
| CLI/TUI preview and detail lists | Empty lists render safely | CLI preview 12, TUI tree preview eight, and TUI children/details eight are displayed | Next item is omitted while required prompts remain visible |

### Stage 0 gate

- [x] Contracts have no unresolved semantic ambiguity.
- [x] Every new public schema has a proposed in-band versioned shape, and the
      exceptional legacy `kickoutchi.list/1` array plus its sole additive
      `label` field are fully pinned.
- [x] Every supported platform has a documented source for each promised fact.
- [x] Permanent limitations are accepted as contract, not deferred work.
- [x] Security objectives and resource bounds are documented.
- [x] Every bound has zero, maximum, and maximum-plus-one test cases planned.
- [x] `socket2` version, features, and dependency review are approved.

## Stage 1: Build the Observation Foundation

Create a platform-neutral observation layer. The likely layout is:

```text
src/observation.rs
src/observation/diff.rs
```

### 1.1 Core types

Introduce concrete domain types similar to:

```rust
pub struct NetworkSnapshot {
    pub capture_started_at: SystemTime,
    pub capture_completed_at: SystemTime,
    pub scope: ObservationScope,
    pub completeness: SnapshotCompleteness,
    pub owner_completeness: OwnerCompleteness,
    pub evidence_gaps: Vec<EvidenceGap>,
    pub omitted_evidence_gap_count: u64,
    pub sockets: Vec<SocketObservation>,
    pub processes: HashMap<ProcessIdentity, ProcessObservation>,
}

pub struct ProcessIdentity {
    pub pid: u32,
    pub start_marker: ProcessStartMarker,
}

pub struct EndpointIdentity {
    pub protocol: Protocol,
    pub address: IpAddr,
    pub port: NonZeroU16,
    pub ipv6_scope: Option<Ipv6Scope>,
}

pub enum Ipv6Scope {
    Unscoped,
    InterfaceIndex(NonZeroU32),
    Unavailable,
}

pub struct SocketObservation {
    pub local_endpoint: EndpointIdentity,
    pub state: SocketState,
    pub timer: Option<TcpTimerObservation>,
    pub owners: Vec<OwnerObservation>,
    pub owner_completeness: OwnerCompleteness,
    pub socket_token: Option<PlatformSocketToken>,
}
```

Use enums and nonzero integer types for identity-bearing fields rather than
unqualified integers:

- Linux process start ticks.
- macOS process start timestamp from `proc_bsdinfo`.
- Windows process creation time.

Represent unverified ownership separately. Do not invent a placeholder start
marker or collapse missing, denied, and raced states into `None` without reason.
Only verified identities key the process map. PID-only owners remain in the
socket owner set. Unattributable hidden ownership is a bounded snapshot gap.

Use one collector with explicit metadata profiles, not separate sources of
truth:

- `IdentityOnly` reads only PID/start identity required for consistency.
- `Display` additionally reads bounded name, executable path, parent, and
  protection inputs, but no full command line.
- `LegacyList` additionally reads the bounded command line required by existing
  list/TUI JSON and plain-search behavior.

List and the TUI use `LegacyList`; kill uses `Display`; inspect may use
`LegacyList` for its existing report; watch, why, and `list --snapshot-json` use
`Display`. Profiles control optional enrichment only. Native socket rows, owner
edges, process identity, scope, and completeness always use the same collection
implementation.

Account every retained optional metadata string against a 64 MiB per-snapshot
budget in sorted PID/field order. On exhaustion, keep identities and socket
facts, omit remaining optional fields deterministically, add bounded
`noncritical_evidence_truncated` gaps, and mark the snapshot partial. Never
attempt an allocation before checking both the per-value and aggregate budget.

Protection evidence is not optional metadata. Before any single, tree, or group
signal delivery, freshly read each final target's bounded process name together
with its start identity through the platform identity-safe path. Reserve up to
4 KiB per name and 2 MiB across the existing maximum 512-member scope outside
the optional metadata budget. If protection evidence is unavailable, changed,
oversized, or permission-denied, refuse delivery; map permission denial to exit
`4` and every other incomplete protection check to exit `1`. An absent name never
means "not protected."

### 1.2 Invariants

Enforce these invariants by construction where practical:

- A verified process owner always has a PID and start marker.
- Unknown native socket states retain their native numeric value.
- Duplicate observations remain countable as a multiset.
- Labels are not stored by platform collectors.
- Human-facing certainty is assigned before rendering.
- Snapshot completeness describes the whole observation, while evidence gaps
  describe specific rows or claims.
- Snapshot completeness is derived with fixed precedence. It is `Raced` when the
  accepted result is the second unstable consistency attempt. Otherwise it is
  `Partial` when any evidence gap was retained or omitted, any socket or global
  owner set is partial/raced, or bounded optional data was omitted; otherwise it
  is `Complete`. Permanent limitations listed only in `scope.limitations` define
  the observation boundary and coexist with `Complete`; an actual failed or
  truncated scope read is an evidence gap and forces `Partial`.
- Global owner completeness is `Raced` when owner edges or attributable process
  identities changed across the returned attempt, `Partial` when any owner scan
  was denied/truncated/vanished or any native owner PID could not be verified,
  and `Complete` otherwise. Socket-local owner completeness follows the same rule
  using only evidence attributable to that socket. Global loss is never copied
  into an arbitrary local owner set.
- Diff readiness is derived before watch rendering. `SocketSet` gaps and `Raced`
  snapshots are not safe for bind/release diffing. `Ownership` gaps still permit
  socket multiplicity diffs when the native socket set is authoritative, but
  prevent replacement claims for affected sockets. `Metadata` and `Scope` gaps
  do not invalidate within-scope socket diffs.
- Capture completion is never earlier than capture start. Failure to obtain a
  valid wall-clock value is operational error, while monotonic scheduling never
  depends on wall-clock movement.
- Evidence-gap truncation always increments `omitted_evidence_gap_count` and
  forces `Partial`; it never silently reports `Complete`.

### 1.3 Bounded consistency collection

Use a bounded consistency algorithm:

1. Record start timestamps.
2. Collect native socket rows and platform socket tokens as table A.
3. Collect owner associations A for those rows.
4. Read process start identities A once per unique attributable PID.
5. Collect native socket rows and owner associations again as table B.
6. Read process start identities B once per unique attributable PID in B.
7. Accept the snapshot only when socket multiplicity, owner edges, and process
   identities are stable between A and B. A PID attributable in only one pass or
   a marker available in only one pass is unstable.
8. Retry the complete operation once when stability fails.
9. After the second unstable attempt, return pass B from that attempt as the
   most recent bounded evidence: socket rows and observed owner edges are from B,
   verified process metadata is keyed only by identities read in B, snapshot
   completeness is `Raced`, and global/local owner completeness is raced where
   the unstable comparison applies. Add `observation_raced` gaps naming the
   affected impact. A PID or identity present in only one pass is unstable, not
   "non-comparable". No analysis may convert this snapshot into bind, release,
   replacement, no-owner, or bindability facts.

Linux records whether any PID FD directory or entry was denied or disappeared
during each owner scan. If that loss cannot be attributed to a socket inode, add
the endpoint-null `owner_attribution_incomplete` gap, set global owner
completeness to partial, and disable globally complete ownership claims; do not
change socket-local completeness or label an arbitrary unowned socket as hidden.
This deliberately preserves unprivileged port kill, but `/proc` cannot prove that
the unreadable PID does not share an inode with a visible owner. Port mode may
therefore terminate one genuine attributable owner while an undiscovered
same-inode co-holder keeps the port bound; the post-kill visibility check reports
that survivor condition. This is an accepted availability limitation, not proof
of unique kernel-wide ownership.
macOS and Windows apply the equivalent rule when a native process-first or
owner-table step loses unattributable rows.

Reuse existing socket, PID, row, file-descriptor, and byte limits. Add explicit
limits for consistency attempts and unique process identity reads. Never retry
until success.

Watch always uses this full consistency algorithm. If collection takes longer
than the requested interval, it starts the next poll after completion without
overlap or backlog and records the actual observation times. Run a release-mode
feasibility measurement after Stage 2 and before exposing watch. If the 100 ms
minimum is not practical, reopen Stage 0 and update the contract before Stage 3;
never defer that product change until release QA or benchmarking. Performance
work may not weaken identity consistency or truthful race reporting.

### 1.4 Existing model migration

Derive borrowed `PortEntryView` values from `NetworkSnapshot`. Do not keep old
and new collectors as independent sources of truth, and do not materialize one
owned copy of process strings per owner edge. The TUI retains the snapshot plus
bounded visible-row indexes; query and rendering borrow process metadata through
those indexes. Legacy JSON streams each borrowed row. A selected kill target may
copy only its bounded revalidation fields. Preserve current list, kill, inspect,
and TUI behavior while migrating callers.

The legacy projection includes only listening TCP and bound UDP. It exposes one
borrowed row per attributable owner edge and one partial ownerless row only when
no owner is attributable. Projection indexes are capped at 262,144 rows
independently of raw socket count and never duplicate owned metadata. Kill
resolution may display an unverified PID but must refuse delivery unless fresh
revalidation establishes verified process identity, complete confirmed-endpoint
attributed ownership, and complete fresh protection evidence.

The kill path is the highest-risk migration surface. Preserve this safety order
explicitly:

1. Freshly collect socket ownership.
2. Re-establish the requested target.
3. Verify PID and process start marker.
4. Verify every confirmed endpoint still belongs to that identity.
5. Reapply protected-process policy.
6. Deliver only through the already prepared identity-safe handle.

Step 5 requires the fresh protection-critical read above for every final target;
snapshot metadata omission or an unknown name is a refusal, never an implicit
policy miss.

No signal may be sent when any earlier gate fails. Existing single-process,
tree, and group kill tests are named migration criteria, not incidental coverage.
Mutation confirmation must first cover ownership loss, PID reuse, endpoint
movement, newly protected targets, and signal non-delivery on every refusal.

Destructive target authority is normatively mode-aware. PID selection requires
proof that the exact verified PID/start-marker identity owns every endpoint
carried by the confirmation and that no target-local socket-set or ownership
evidence gap invalidates those endpoints. Global unattributable ownership loss
does not select a different identity and does not by itself block PID or port
mode. PID selection requires complete target-local evidence for its preselected
identity. Port selection may establish one identity from complete attributable
matching-endpoint owner sets, but any observed ambiguity, unverified matching
owner, matching-endpoint ownership gap, or applicable socket-set gap still
refuses. Linux cannot exclude the same-inode hidden co-holder described above;
the selected PID is still a verified genuine owner, but it is not claimed to be
the only kernel-wide holder. This preserves unprivileged port kill when unrelated
host processes are unreadable without guessing a PID that was not observed as an
owner. Implementations and tests must not replace these rules with one global
owner-completeness gate.
An omitted evidence gap has lost the impact and locality needed to prove it
unrelated; any nonzero omitted-gap count therefore blocks both destructive modes.

### Stage 1 gate

- [x] Core invariants are represented in types or checked at internal boundaries.
- [x] Operational errors do not panic.
- [x] Every collection path is bounded.
- [x] Existing commands pass unchanged regression tests.
- [x] Kill revalidation ordering and signal non-delivery remain proven by unit,
      contract, integration, and mutation-confirmed tests.
- [x] Unit tests cover stable, partial, denied, raced, duplicate, zero, maximum,
      and maximum-plus-one observations.

## Stage 2: Complete Native Collection

No new command is exposed until all supported platform collectors satisfy the
shared contract.

Use this fact-source and limitation matrix as the platform contract:

| Fact | Linux source | macOS source | Windows source |
| --- | --- | --- | --- |
| IPv4/IPv6 TCP rows and state | `/proc/net/tcp`, `/proc/net/tcp6` | `proc_listallpids` + `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` | `GetExtendedTcpTable` owner tables |
| IPv4/IPv6 UDP bound rows | `/proc/net/udp`, `/proc/net/udp6` | `proc_listallpids` + `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` | `GetExtendedUdpTable` owner tables |
| Socket owner PID | `/proc/<pid>/fd` inode links | Per-process libproc file descriptors | Extended owner-table PID |
| Process start identity | `/proc/<pid>/stat` field 22 | `proc_bsdinfo` start time | `GetProcessTimes` creation time |
| Process metadata | `/proc/<pid>` files and links | `proc_bsdinfo`, `proc_name`, `proc_pidpath`, and bounded `KERN_PROCARGS2` | `CreateToolhelp32Snapshot`/`Process32FirstW`/`Process32NextW` for bounded name and parent rows, `QueryFullProcessImageNameW` for path, and bounded `NtQueryInformationProcess(ProcessCommandLineInformation)` for the legacy command line; socket-owner enrichment falls back to bounded direct PID identity reads when Toolhelp relation enumeration fails |
| Socket token | `/proc/net` inode | `socket_info.soi_so` returned by `PROC_PIDFDSOCKETINFO` | Unavailable in this release |
| IPv6 scope ID | Unavailable from the selected `/proc/net` row format; every IPv6 row uses `Unavailable` | Unavailable from the selected libproc socket descriptor interpretation; every IPv6 row uses `Unavailable` | Network-byte-order `dwLocalScopeId` converted to host order |
| Timer estimate | TCP-only `/proc/net/tcp*` `tr` and `tm->when`, retained as kind and raw ticks; duration uses checked `_SC_CLK_TCK` conversion | Unavailable | Unavailable |
| Scope | `/proc/self/ns/net` current namespace | Declared process-visible host coverage; no global identifier | Declared current native Windows host stack; no global identifier |

Permanent limitations are part of the contract:

- Linux observes only the current network namespace and never enters another
  namespace implicitly.
- Linux `/proc/<pid>` enumeration sees only PIDs visible in the collector's PID
  namespace. A bounded, unique, positive `/proc/self/status` `NSpid` chain with
  exactly one value is required before ownership visibility is treated as
  initial-namespace complete. A nested, missing, unreadable, duplicate, zero, or
  malformed chain adds endpoint-null ownership uncertainty and makes every
  retained socket's owner set partial because an ancestor-namespace process may
  share a socket in the current network namespace.
- The selected Linux `/proc/net/*6` source exposes no scope identifier, so every
  Linux IPv6 observation uses `Ipv6Scope::Unavailable`. A snapshot containing
  such rows adds one endpoint-null `native_field_unavailable` gap with `Scope`
  impact. Those rows cannot match an exact IPv6 selector or support an
  exact-address proven observation claim. Wildcard label selectors still match
  because they do not require scope equality.
- macOS collection is process-first through `proc_listallpids`,
  `proc_pidinfo(PROC_PIDLISTFDS)`, and
  `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`, not a global PCB snapshot. It cannot
  observe sockets hidden with an inaccessible process or descriptor table, rows
  that vanish during enumeration, or sockets with no visible user-process
  descriptor. Such loss has `SocketSet` impact. Missing native fields are
  evidence gaps, not fabricated defaults.
- `CurrentHostProcessVisibleSockets` covers sockets reachable through process FD
  enumeration when every PID returned by `proc_listallpids` is processed
  successfully. Sockets with no user-process descriptor are permanently outside
  this scope. Denial, truncation, disappearance, or malformed enumeration for a
  returned process is a `SocketSet` gap and prevents socket-set completeness; it
  is not reclassified as an ordinary scope exclusion.
- The selected macOS libproc socket descriptor interpretation does not provide a
  supported IPv6 scope identifier. Every macOS IPv6 observation therefore uses
  `Ipv6Scope::Unavailable` and the snapshot adds one endpoint-null
  `native_field_unavailable` gap with `Scope` impact.
- Windows collection excludes the separate WSL network stack. Excluded-port or
  reservation evidence is reported only when a supported native source supplies
  it.
- Windows converts `dwLocalScopeId` from network byte order. IPv4-mapped IPv6
  owner-table rows normalize to IPv4 and discard IPv6 scope. An IP Helper UDP row
  with owning PID zero remains an authoritative endpoint with an empty partial
  owner set and endpoint-local `owner_attribution_incomplete` evidence; PID zero
  is never read as a process owner.
- Owner PID, verified process identity, and optional process metadata have
  separate completeness. Failure to read a start marker preserves a native PID
  as `UnverifiedPid` and affects ownership verification. Failure to read a name,
  path, parent, or command line has `Metadata` impact only. On process-first
  macOS, descriptor enumeration failure can hide socket rows and has `SocketSet`
  impact. A visible authoritative socket row is not removed merely because
  enrichment failed.
- Collection is a bounded observation interval, not an atomic kernel snapshot.
- No collector uses `ss`, `lsof`, `netstat`, `netsh`, Docker, or another process
  as its authoritative source.

### 2.1 Linux

- Retain every TCP state from `/proc/net/tcp` and `/proc/net/tcp6`.
- Map native TCP values `01` through `0C` to `Established`, `SynSent`,
  `SynReceived`, `FinWait1`, `FinWait2`, `TimeWait`, `Closed`, `CloseWait`,
  `LastAck`, `Listen`, `Closing`, and `NewSynReceived`; preserve every other
  value as `Unknown(native_code)`.
- Treat every retained Linux UDP row as the semantic state `Bound`. The `/proc`
  `st` token remains syntactically required so malformed rows fail, but it is not
  a portable UDP lifecycle state and no portable UDP lifecycle vocabulary is
  promised in this release.
- Preserve socket inode as an optional native token.
- Parse timer fields with checked, bounded integer conversion.
- Retain TCP timer kind and raw ticks at capture. Convert to an estimated
  duration using the Stage 0.1 typed timer and checked ceiling conversion only
  when `_SC_CLK_TCK` returns a positive representable value. The estimate is
  quantized and race-prone, applies only to the represented TCP kernel timer,
  and never promises socket release or future bindability. Malformed timer kind
  or tick text fails the collection attempt; an unknown numeric kind remains
  `unknown(native_code)`. UDP timer semantics are not promised in this release.
- Read process start ticks from `/proc/<pid>/stat`.
- Report current network namespace scope.
- Track denied or vanished FD scans. Claim `NoOwnerObserved` only when the owner
  association pass was complete; otherwise preserve observed owners and mark
  attribution partial at socket or snapshot scope as the source permits.
- Mark timer expiry as estimated.
- Fail closed on oversized or malformed identity-critical files.
- Validate the native socket-table header before accepting either rows or an
  empty table; recognize the kernel's family-specific `rem_address` and
  `remote_address` labels, and reject empty, garbage, or headerless input.
- Replace the current 16 KiB truncate-and-mark-partial command-line behavior
  with the shared 1 MiB contract. Preserve the complete raw value through 1 MiB;
  above the cap serialize `null`, mark metadata partial, and add the bounded
  truncation evidence gap. Do not expose a truncated command-line prefix.

### 2.2 macOS

- Extend the process-first libproc path to retain every TCP state and UDP row
  returned by `PROC_PIDFDSOCKETINFO`.
- Retain UDP endpoints and ownership where exposed.
- Obtain a native process start identity.
- Represent unavailable fields explicitly.
- Bound changing sysctl-buffer retries and allocations.
- Validate counts, lengths, alignments, and pointers before reading native data.
- Keep unsafe blocks small and add a local `// SAFETY:` proof to each one.
- If process-first libproc failure can hide complete socket rows, add a
  `SocketSet` evidence gap. Do not downgrade it to metadata-only partiality.
- Map Darwin `tcpsi_state` values `0..=10` to `Closed`, `Listen`, `SynSent`,
  `SynReceived`, `Established`, `CloseWait`, `FinWait1`, `Closing`, `LastAck`,
  `FinWait2`, and `TimeWait`; preserve every other nonnegative value as
  `Unknown(native_code)`; a negative signed value is malformed native data.
- Derive or validate Darwin layouts, field offsets, constants, and state codes
  against supported SDK headers for both release architectures. Coarse struct
  size checks alone are insufficient ABI evidence.
- Retain `socket_info.soi_so` only as an opaque token for within-pass association
  and ordering. It does not prove cross-capture identity or replacement.
- Clear and inspect thread-local errno around libproc count APIs so a genuine
  zero result remains valid while zero-plus-errno cannot become a complete empty
  process or child list.

### 2.3 Windows

- Use extended TCP owner tables for IPv4 and IPv6.
- Use extended UDP owner tables for IPv4 and IPv6.
- Retain all documented TCP states.
- Map the documented MIB values to `Closed`, `Listen`, `SynSent`, `SynReceived`,
  `Established`, `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`,
  `TimeWait`, and `DeleteTcb`; preserve every other value as
  `Unknown(native_code)`.
- Use process creation time as the identity marker.
- Validate native table lengths before constructing slices or indexing rows.
- Keep Win32 unsafe boundaries small and locally documented.
- Report WSL as outside the Windows collector scope.
- Report excluded-port evidence only when obtained through a supported source.
- Never label an unexplained access denial as a proven Hyper-V reservation.
- IP Helper owner-table rows remain socket-set evidence even when process
  identity or metadata reads fail. Such failure affects ownership or metadata,
  not the existence of the socket row.
- Toolhelp relation-enumeration failure during socket-owner enrichment falls
  back to bounded direct reads of only the owner PIDs and returns partial
  metadata. Tree snapshots still propagate Toolhelp failure. Read-only process
  context and command-line helpers fail closed to empty relationship or metadata
  evidence rather than returning partial native relations.
- The former `sysinfo` metadata snapshot was not considered bounded merely
  because results were truncated afterward and has been replaced by bounded
  native sources. Enumerate at most 131,072 fixed-size Toolhelp rows; allocate name,
  path, and command-line buffers only after per-value and aggregate budget checks;
  use at most three changing-size attempts per native read. Keep IP Helper as the
  socket authority. No provisional unbounded metadata path may remain.

### 2.4 Shared state mapping

Use a shared state enum that preserves unknown values. The normal `list` and TUI
views may continue to show listening TCP and bound UDP rows, while the snapshot
retains all states for watch and why.

### Stage 2 gate

- [x] All native values map to a shared state or `Unknown(native_code)`.
- [x] All unsafe code has reviewed safety contracts.
- [x] Permission and scope gaps remain visible.
- [x] Native fixture tests cover every documented state and malformed tables.
- [x] Every platform enforces process-metadata limits before allocation; Windows
      uses its bounded native replacement.
- [ ] Linux, macOS, and Windows CI compile and run their collector tests after
      the completeness and native endpoint remediation.
- [x] Release-mode feasibility measurements confirm the 100 ms watch minimum or
      Stage 0 is reopened before named endpoints and public commands begin.

## Stage 3: Implement Named Endpoints

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
local addresses for that protocol. Exact addresses are literal IP addresses;
hostnames, DNS, CIDR ranges, and interface names are rejected. There are no
hidden selector defaults. `scope_id` is an optional nonzero `u32` accepted only
with an exact IPv6 address. A selector without `scope_id` matches only an
unscoped endpoint; scoped exact selectors match only the same numeric scope.

### 3.1 Validation

- Cap labels at 256 entries.
- Cap each label at 128 UTF-8 bytes and 32 displayed terminal columns. Display
  width uses the pinned `unicode-width 0.2.2`. Clip without splitting a Unicode
  scalar value and append U+2026 only when it fits within the same 32-column
  bound.
- Reject empty and whitespace-only labels.
- Reject leading or trailing whitespace rather than silently normalizing it.
- Reject duplicate selectors at equal specificity.
- Reject missing or invalid protocols and addresses, and reject port zero.
- Reject selector address text above 64 bytes before IP parsing.
- Reject unknown fields.
- Parse and canonicalize exact addresses with `IpAddr`; apply the same
  IPv4-mapped-IPv6 normalization used by observed endpoints before duplicate
  detection and matching. Canonicalize mapped literals before scope validation;
  `scope_id` is invalid when normalization produces IPv4. Canonicalizing an
  observed mapped row produces IPv4 and removes IPv6 scope because scope is not
  part of canonical IPv4 identity.
- Accept Unicode scalar values without normalization except characters with
  Unicode 17.0 General Category `Cc`, the `Bidi_Control` property, or the
  `Default_Ignorable_Code_Point` property. Reject those values, including escape,
  ANSI controls, bidi controls, and zero-width formatting. Leading, trailing,
  and whitespace-only checks use Rust `char::is_whitespace`. Sanitize again at
  every terminal render boundary.
- Test ANSI, control, bidi, zero-width, wide-Unicode, canonicalized duplicate,
  128-byte, and 129-byte input.

### 3.2 Matching precedence

Apply one deterministic rule:

1. Exact protocol, address, and port.
2. Protocol and port with an explicit wildcard address.
3. No ambiguous match at the same specificity.

Exact precedence includes the normalized IPv6 scope. Wildcard selectors ignore
scope deliberately and therefore apply to scoped and scope-unavailable rows.

### 3.3 Surfaces

- Add a `LABEL` column to the CLI table whenever validated configuration contains
  at least one selector, even when no visible row currently matches.
- Apply the same condition to the TUI. `LABEL` is the first optional column
  omitted when necessary to preserve existing minimum-size behavior.
- Include labels in plain search.
- Add a `label:` structured filter.
- Implement normalized `address:`, exact numeric `scope_id:`, and
  `family:ipv4|ipv6` filters in the
  shared query layer for list, TUI, and watch. This stage owns their
  implementation; Stage 7 only freezes and documents the resulting vocabulary.
- Add nullable `label` data to `kickoutchi.list/1` and the versioned snapshot
  schema.
- Include labels consistently in watch and why output.

### Stage 3 gate

- [ ] Unconfigured users see no human-table layout change.
- [ ] Config errors name the invalid selector without leaking unsafe text.
- [ ] Matching and precedence are deterministic.
- [ ] JSON changes are pinned and documented.
- [ ] CLI and TUI rendering remain aligned for Unicode labels.

## Stage 4: Implement the Watch Engine

Create:

```text
src/watch.rs
src/cli/watch.rs
```

### 4.1 Pure diff engine

The core API compares two snapshots without I/O and yields deterministic bounded
batches instead of allocating every maximum-poll event at once:

```rust
fn diff_snapshots<'a>(
    previous: &'a NetworkSnapshot,
    current: &'a NetworkSnapshot,
) -> Result<SnapshotDiff<'a>, DiffError>
```

`SnapshotDiff` is a pure iterator/cursor over sorted snapshot indexes. The watch
loop may retain at most 4,096 yielded events before writing and discarding them.
The iterator counts total output and fails before exceeding 524,288 events.

Event kinds:

- `baseline`
- `bind`
- `release`
- `replacement`
- `collection_gap`

Rules:

- Changed verified start markers prove process replacement only under the
  exact-one, complete-single-owner rule below. Other identity changes remain
  heuristic or silent as that rule specifies.
- A failed collection emits `collection_gap` and never fabricated releases.
- Recovery compares against the last valid snapshot.
- Respawn wording remains heuristic unless identity and parent evidence prove it.
- Duplicate sockets are diffed by multiplicity. Internally preserve every
  observation; output may group otherwise identical events and carry a positive
  multiplicity.
- Reconcile each bucket deterministically. First cancel byte-for-byte equal
  canonical observations by multiplicity. Before positional pairing, apply the
  exact-one replacement rule below when both original bucket multiplicities are
  one. Otherwise sort each remaining side by token key then owner-set key and
  pair `min(previous_remaining, current_remaining)` items by index without
  emitting owner-only events. Emit releases for unpaired previous items and
  binds for unpaired current items, grouping adjacent equal event payloads. This
  fixes payload and filter sides without claiming that positional or token
  pairing proves socket persistence.
- `baseline` emits one event for each matching initial observation or grouped
  multiplicity and appears only after the first successful collection.
- `bind` means the current multiplicity is greater than the previous valid
  multiplicity. `release` means it is lower.
- Socket multiplicity counts native socket observations, not owner edges. One
  process closing an inherited descriptor while another owner retains the same
  native socket does not emit `release`.
- Socket multiplicity buckets are keyed by protocol, normalized address, numeric
  IPv6 scope, port, and socket state. Replacement pairing occurs only within one
  bucket, so both sides share the event's single state. A state transition emits
  a release from the previous state and a bind into the current state rather
  than a replacement.
- `replacement` is deliberately narrow. Emit it as `Proven` only for a
  bucket whose previous and current multiplicity are both exactly one, when both
  owner sets are complete, each has exactly one verified owner, the owner PIDs
  are equal, and their verified start markers differ. Emit `replacement` as
  `Heuristic` under the same exact-one/complete-single-owner conditions when the
  verified identities differ but the proven same-PID rule does not hold. If the
  verified identities are equal, emit no replacement regardless of token change.
  Opaque tokens participate only in deterministic event ordering. Shared,
  incomplete, or multiplicity-greater-than-one sets are never paired.
- Owner-only additions or removals do not change socket multiplicity and are
  intentionally silent unless the exact-one replacement rule above applies;
  token equality does not establish cross-capture socket persistence. Other
  owner-only changes are neither endpoint bind/release nor process replacement. Any
  global or per-socket owner-attribution incompleteness disables replacement for
  that comparison.
- Sort by protocol (`tcp`, then `udp`), address family (IPv4, then IPv6), address
  bytes, IPv6 scope (`unscoped`, interface index, `unavailable`; IPv4 before all
  IPv6), port, the Stage 0.1 state order, event kind (`release`, `replacement`,
  then `bind`), event token key, event-side owner-set key, label bytes, filter
  result, and certainty. Baseline uses the same key. Owner and token keys are
  frozen in Stage 7.1. A
  `collection_gap` is the only event for its failed poll.
- Event time is an observation interval derived from the previous and current
  capture windows. It is never described as the exact kernel event time.
- Baseline, bind, and release are `Proven` within the reported scope when socket
  diff readiness is valid; their observation interval is separate `Estimated`
  evidence. Replacement certainty follows the token rules above. Collection
  gaps have `Unknown` certainty.

### 4.2 Bounded loop

Inject collector, monotonic clock, wall clock, sleeper, cancellation source, and
writer. Keep only the previous valid snapshot and the current bounded event
batch. Stream events and discard them after writing.

- Reject intervals outside `100ms..=60s`; never silently clamp them.
- Default interval to `1s`.
- Run until Ctrl-C when duration is absent. Validate explicit duration in
  `100ms..=7d` with checked arithmetic. Duration and interval tokens are one
  unsigned decimal integer followed immediately by exactly one lowercase suffix
  from `ms`, `s`, `m`, `h`, or `d`. Signs, decimals, whitespace, uppercase
  suffixes, and compound forms such as `1m30s` are rejected.
- Allow a budget of three consecutive collection failures after a valid
  baseline. Emit one gap per failure and wait the requested interval before
  retrying. The third consecutive failure exhausts the budget and exits `1`
  after its gap is flushed.
- Exit cleanly on Ctrl-C or duration expiry.
- Exit `0` for Ctrl-C, duration expiry, and broken stdout pipes.
- Exit `1` for initial collection failure or exhausted failure budget.
- Flush output before returning.
- Treat a broken stdout pipe as successful consumer termination.
- Never use sleeps for synchronization in tests.
- Apply endpoint and state filters to baseline and diff events after complete
  native collection. Collection gaps bypass endpoint filters so failures remain
  visible.
- Keep no more than the previous valid snapshot, current snapshot, and 4,096
  current batch events. Count at most 524,288 events per poll; checked overflow
  or a larger diff is an operational error.

An initial collection failure writes one sanitized diagnostic to stderr, emits
no baseline or NDJSON record, and exits `1`. After a baseline, every failed poll
emits and flushes its typed `collection_gap` before retry or termination.

A wall-clock read failure is the exception because a conforming watch record
cannot fabricate its required observation timestamps. Whether it occurs before
or after a baseline, write one sanitized stderr diagnostic, emit no NDJSON
record for that attempt, and exit `1` immediately. It does not consume the
ordinary three-failure collection budget.

An initial snapshot that is `Raced` or has a `SocketSet` gap is not a valid
baseline and follows the same no-record exit-`1` behavior.

A `Raced` snapshot or partial snapshot with a `SocketSet` gap emits
`collection_gap`, consumes one failure-budget unit, and does not replace the last
valid baseline. A partial snapshot containing only `Metadata`, `Scope`, or
`Ownership` gaps may advance the baseline and reset the consecutive-failure
counter. It may emit bind and release events from stable socket multiplicity,
but replacement is emitted only when both snapshots have global `Complete`
owner attribution and both matched owner sets are locally `Complete` with the
verified identities required by the exact-one rule.

Filter event sides deterministically. Baseline and bind evaluate the current
event view; release evaluates the previous event view. Replacement builds one
previous and one current legacy-row-style view and matches when the entire ANDed
filter expression matches either side. For a side with several owners, process
fields match only when one conceptual owner row satisfies all process-related
terms together. Endpoint, label, protocol, family, address, and state terms use
the common event endpoint/state. Collection gaps bypass all user filters.

Filter evaluation is three-valued: `Match`, `NoMatch`, or `Indeterminate`.
Within one side, any definitely false AND term yields `NoMatch`; all true yields
`Match`; otherwise missing ownership or metadata required by a term yields
`Indeterminate`. For replacement, either-side `Match` wins, two `NoMatch` values
yield `NoMatch`, and every other combination is `Indeterminate`. Emit matching
and indeterminate events, suppress only definite non-matches, and attach the
bounded applicable evidence gaps to indeterminate events. This prevents a
partial snapshot from silently hiding a possible process-filter match.

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

`--tcp` and `--udp` may be combined to select both protocols. Address and port
arguments are exact event filters. `--filter` uses the Stage 7.2 watch
capability set. Conflicting or repeated scalar options fail with exit `2`.
Watch `--address` matches the normalized address component across every IPv6
scope. `--scope-id` requires one explicit IPv6 address, narrows the filter to
that nonzero interface index, and never matches unscoped or unavailable scope.

Watch never invokes Docker enrichment in its polling loop. Native socket and
process observations plus configured labels are sufficient for events. This
prevents a 100 ms interval from becoming an external-process spawn loop.

### Stage 4 gate

- [ ] Bind, release, replacement, duplicates, and gaps are correct.
- [ ] No failed snapshot fabricates events.
- [ ] Output ordering is deterministic.
- [ ] Memory remains bounded by two snapshots and one bounded event batch.
- [ ] Cancellation, duration, broken pipes, and repeated failures are tested.
- [ ] NDJSON schema and stdout/stderr separation are pinned.

## Stage 5: Implement Exact Bind Probes

Create `src/probe.rs` as a narrow OS-I/O boundary.

### 5.1 Probe contract

Represent an exact probe with protocol, normalized address, port, IPv6 scope,
IPv6-only behavior, and reuse-address behavior. IPv4 has no scope. IPv6 uses
`Unscoped` or `InterfaceIndex(nonzero u32)`; `Unavailable` is never a probe
target. The wrapper builds `SocketAddrV6` with scope ID zero or the selected
interface index before bind. Outcomes must distinguish:

- Bindable now.
- Address in use.
- Permission denied.
- Address unavailable.
- Unsupported option or family.
- Other owned OS error.

Use explicit request values:

- Protocol is TCP or UDP.
- Address is one concrete IPv4 or IPv6 address and port in `1..=65535`.
- Reuse-address mode is `Disabled` by default or `Enabled` only when explicitly
  requested.
- IPv6 mode is `SystemDefault`, `V6Only`, or `DualStack`. The latter two are
  invalid for IPv4 requests and are mutually exclusive at the CLI boundary.
- Result stores a stable category and, when the OS supplied one, the numeric raw
  OS error. Public OS error text is sanitized and is not a stable contract.

Map `AddrInUse`, `PermissionDenied`, and `AddrNotAvailable` to their dedicated
outcomes. Map a known unsupported family or option to `Unsupported`. Preserve
every other OS failure as `Other` rather than guessing a reservation or policy.
Argument validation happens before socket creation and returns exit `2`, not a
probe outcome.

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

Use `socket2 0.6.5` with default features only. The wrapper calls only
`Socket::new`, `set_reuse_address`, `set_only_v6` when applicable, `bind`, and
owned drop. Configure all requested options before bind. Do not reproduce this
platform-sensitive setup with new local unsafe code.

### Stage 5 gate

- [ ] Every supported matrix entry has a native test.
- [ ] Probe results preserve exact OS error categories.
- [ ] No probe leaves a socket or helper process behind.
- [ ] Probe language says "now" and does not promise future availability.
- [ ] The approved `socket2` dependency matches the reviewed lockfile version.

## Stage 6: Implement the Why Verdict Engine

Create:

```text
src/diagnostic/verdict.rs
src/cli/why.rs
```

The verdict engine is pure. It receives a query, snapshot, probe results, and
labels. It performs no OS calls.

The existing `src/diagnostic.rs` remains the list no-match command-line hint
module and declares the new `diagnostic::verdict` submodule. Its strict
command-line hints remain list-only: Why's `Display` metadata profile does not
read command lines, and those hints are not Why evidence in this release.

### 6.1 CLI contract

```text
kick why 3000 --tcp --address 127.0.0.1
kick why 3000 --tcp --address fe80::1 --scope-id 3
kick why 5353 --udp --address 0.0.0.0
kick why 3000 --all-addresses
kick why 3000 --all-protocols --all-addresses
kick why 3000 --json
```

A bare port evaluates a documented endpoint matrix and prints one verdict per
exact endpoint. It must not collapse conflicting endpoints into a universal
"port free" statement.

The CLI matrix is fixed:

- Bare `kick why PORT` evaluates TCP on `127.0.0.1:PORT` and `[::1]:PORT`.
- `--tcp` keeps TCP only; `--udp` selects UDP only; `--all-protocols` selects
  TCP and UDP. These protocol selectors are mutually exclusive.
- `--address ADDRESS` accepts at most 64 bytes, evaluates one literal IP address,
  and is mutually exclusive with `--all-addresses`.
- `--scope-id ID` accepts one nonzero `u32`, requires one explicit IPv6
  `--address`, and is invalid with IPv4, default addresses, or `--all-addresses`.
  Zone text such as `%eth0` or `%3` in `--address` is rejected.
- Without an address option, the default is the two loopback addresses.
- `--all-addresses` means exactly `127.0.0.1`, `0.0.0.0`, `::1`, and `::`; it
  never enumerates configured interfaces.
- `--ipv6-only` and `--dual-stack` are mutually exclusive and valid only when
  every selected address is IPv6. `--reuse-address` requests the explicit reuse
  diagnostic. Otherwise probes use system-default IPv6 behavior and disabled
  reuse-address.
- The Cartesian product is capped at eight endpoints. Any argument combination
  exceeding the cap or selecting no endpoint exits `2`.
- An unavailable IPv6 family remains an explicit endpoint result; it is not
  silently removed from the default matrix.

Collect the snapshot first, then execute exact probes sequentially. For each
probe target, classify same-protocol, same-port observations with this bounded
relationship matrix:

- `Exact`: observed and requested addresses and IPv6 scope IDs are equal.
- `ObservedWildcardCoversTarget`: an observed `0.0.0.0` covers a requested IPv4
  address, or observed `::` covers a requested IPv6 address.
- `TargetWildcardCoversObserved`: requested `0.0.0.0` covers any observed IPv4
  address, or requested `::` covers any observed IPv6 address.
- `PotentialDualStackOverlap`: an IPv6 wildcard and IPv4 address may overlap
  under `DualStack` or `SystemDefault`, but the native source does not expose
  enough socket-option evidence to prove it.
- `PotentialScopeOverlap`: addresses would otherwise have an exact or wildcard
  relationship, but either IPv6 scope is unavailable or the known scopes differ.
- `Unrelated`: different protocol, port, or non-overlapping address family.

Exact and same-family wildcard relationships may explain a failed probe.
For IPv6, `Exact`, `ObservedWildcardCoversTarget`, and
`TargetWildcardCoversObserved` require known equal scopes. `Unavailable` never
satisfies an authoritative relationship. `PotentialScopeOverlap` is supporting
`Unknown` evidence only and cannot select `Owned`, `OwnerHidden`, or
`KernelStateObserved`.
Potential dual-stack overlap is supporting context only; the exact probe decides
current bindability unless a supported native source proves the relevant
IPv6-only option. Never infer dual-stack behavior from address shape alone.

### 6.2 Verdicts

- `BindableNow`
- `Owned`
- `OwnerHidden`
- `KernelStateObserved`
- `PermissionDenied`
- `AddressUnavailable`
- `ReservationOrPolicyUnknown`
- `ObservationRaced`
- `Unsupported`
- `Indeterminate`

Map individual verdicts to process exits as follows:

- `BindableNow` maps to `0`.
- `PermissionDenied` maps to `4`.
- `Owned`, `OwnerHidden`, `KernelStateObserved`, `AddressUnavailable`,
  `ReservationOrPolicyUnknown`, and `Unsupported` map to `3`.
- `ObservationRaced` and `Indeterminate` map to `1` because evaluation did not
  produce the complete reliable answer required for success.

The multi-endpoint precedence in Stage 0.3 is applied after this mapping.

### 6.3 Evidence order

1. Verified visible listener or UDP owner.
2. Visible endpoint with unreadable ownership.
3. Non-listening kernel state.
4. Exact bind-probe result.
5. Platform, namespace, or container supporting evidence.
6. Explicit evidence gaps and scope limitations.

This is presentation order only. Verdict selection uses the probe-first total
decision table below because current bindability is defined by the later exact
probe.

Apply this total verdict decision table after gathering native and probe
evidence. A "matching active socket" is an exact or same-family wildcard TCP
listener or bound UDP socket from a socket-set-stable snapshot. A "matching
kernel state" is a relevant non-listening TCP state from such a snapshot. Apply
the table top to bottom; the first full predicate that matches wins.

| Probe outcome and usable evidence | Verdict | Certainty |
| --- | --- | --- |
| Bind succeeds | `BindableNow` | `Proven` at probe completion |
| Address unavailable | `AddressUnavailable` | `Proven` |
| Family or requested option unsupported | `Unsupported` | `Proven` |
| Permission denied | `PermissionDenied` | `Proven`; availability remains separate unknown evidence |
| Other OS error plus raced snapshot | `ObservationRaced` | `Unknown` |
| Other OS error with any non-raced snapshot | `Indeterminate` | `Unknown` |
| Address in use plus matching active socket with at least one verified owner | `Owned` | `Proven` |
| Address in use plus matching active socket with no verified owner and either an unverified PID or socket-local incomplete attribution | `OwnerHidden` | `Unknown`; probe evidence separately proves the failed bind |
| Address in use plus matching active socket with a locally complete empty owner set and globally incomplete attribution | `KernelStateObserved` | `Proven` for the socket state; global owner attribution remains `Unknown` evidence |
| Address in use plus matching active socket with a locally complete empty owner set and globally complete attribution | `KernelStateObserved` | `Proven` for the ownerless kernel socket observation |
| Address in use plus matching non-listening kernel state | `KernelStateObserved` | `Proven`; timer evidence remains separately `Estimated` |
| Address in use without an authoritative explanation | `ReservationOrPolicyUnknown` | `Unknown`; probe evidence separately proves the failed bind |

The later exact probe is authoritative for current bindability, so a successful
probe produces `BindableNow` even when the earlier snapshot observed a socket.
The earlier fact remains ordered evidence and may indicate that the socket closed
or binding semantics allowed coexistence between observations. Docker evidence
never selects or changes a core verdict. Existing list-only process-command
hints are not collected or considered by Why.

Why may request Docker enrichment at most once after native collection and probe
evidence are complete. It must reuse the existing timeout, output, concurrency,
privilege, and process-reaping bounds. Docker evidence is optional supporting
context and never changes the core verdict or exit code.

Each result contains at most 16 evidence items and 16 evidence gaps, with
separate omitted counts for additional applicable evidence and gaps. Full
process command lines are not evidence in human or JSON output. Labels are
assigned after native collection and before verdict rendering, using the Stage
3 precedence.

### 6.4 Certainty language

- Proven: the specific claim is directly established by an authoritative native
  fact or exact probe; interpretation of an opaque native value is not
  automatically proven.
- Estimated: derived from a timer or bounded polling interval.
- Heuristic: plausible interpretation not established by authoritative data.
- Unknown: unavailable because of permission, scope, race, or platform limits.

A Linux TIME_WAIT timer may be shown as an estimate. It must never be presented
as a guarantee that a future bind will succeed at expiration.

### Stage 6 gate

- [ ] Every verdict has an explicit certainty and evidence list.
- [ ] Conflicting evidence produces raced or indeterminate output.
- [ ] Exact queries never imply a host-wide conclusion.
- [ ] Human and JSON results carry equivalent facts.
- [ ] Every verdict maps to a documented exit code.

## Stage 7: Stabilize Public Output and Documentation

### 7.1 Serialized contracts

Do not serialize internal domain or error types directly. Dedicated public DTOs
use the following reusable shapes:

```text
Endpoint = {
  protocol: "tcp" | "udp",
  address: string,
  port: integer 1..65535,
  ipv6_scope:
    null |
    { kind: "unscoped", interface_index: null } |
    { kind: "interface_index", interface_index: unsigned integer } |
    { kind: "unavailable", interface_index: null }
}

ProcessIdentity = {
  pid: unsigned integer,
  start_marker:
    { kind: "linux_start_ticks", ticks: unsigned integer } |
    { kind: "macos_start_time", seconds: unsigned integer,
      microseconds: integer 0..999999 } |
    { kind: "windows_creation_time", filetime_ticks: unsigned integer }
}

SocketState = {
  kind: known lowercase state name | "bound" | "unknown",
  native_code: unsigned integer | null
}

OwnerObservation =
  { kind: "verified", identity: ProcessIdentity } |
  { kind: "unverified_pid", pid: unsigned integer, reason: string }

OwnerSet = {
  owners: [OwnerObservation],
  omitted_owner_count: unsigned integer,
  completeness: "complete" | "partial" | "raced",
  reasons: [stable evidence-gap code]
}

EvidenceGap = {
  code: stable lowercase code,
  impact: "metadata" | "ownership" | "socket_set" | "scope",
  endpoint: Endpoint | null,
  pid: unsigned integer | null,
  message: sanitized string
}

Scope = {
  kind: "current_network_namespace" | "current_host_process_visible_sockets" |
        "current_host_network_stack",
  identifier: string | null,
  limitations: [
    "other_network_namespaces_excluded" |
    "process_first_socket_visibility_limited" |
    "wsl_network_stack_excluded" |
    "process_metadata_permission_limited" |
    "ipv6_scope_unavailable" |
    "scoped_ipv6_exact_matching_unavailable" |
    "native_field_unavailable" |
    "polling_interval_blind_spot"
  ]
}

Evidence = {
  code: stable evidence code,
  source: "linux_procfs" | "macos_libproc" | "macos_sysctl" |
          "windows_ip_helper" | "windows_process_api" | "bind_probe" |
          "docker" | "analysis",
  certainty: "proven" | "estimated" | "heuristic" | "unknown",
  message: sanitized string
}
```

Known socket-state names are the lowercase `snake_case` forms frozen in Stage
0.1. `native_code` is non-null only when `kind` is `unknown`. An evidence gap's
message is explanatory and not a programmatic contract. Owner `reason` values
use the evidence-gap codes from Stage 0.1. Socket-token kinds are
`linux_inode` and `macos_socket_id`; an unavailable token is `null`.

`Endpoint.ipv6_scope` is `null` if and only if the normalized address is IPv4.
Every IPv6 endpoint uses exactly one scope variant. Interface indexes are in
`1..=4294967295`, and endpoint address strings use canonical `IpAddr` text with
no zone suffix.

An empty complete `OwnerSet` means no owner was observed after complete
attribution. An empty partial set makes no no-owner claim. Owner arrays use the
canonical owner key below. The internal aggregate edge count is bounded by Stage
0.7; public owner sets serialize at most 64 entries and report every additional
entry through `omitted_owner_count` without changing attribution completeness.

OwnerSet completeness and reasons are socket-local. Snapshot-global owner
completeness and endpoint-null reasons remain separate snapshot fields. Analysis
checks both when global attribution matters, but serializers never merge a
global reason into an arbitrary OwnerSet. Each local `reasons` array is
deduplicated and lexicographically sorted, capped at eight. Exceeding that cap is
an identity-reliability error, not silent truncation.

Canonical ordering keys are fixed:

- Marker kind order is Linux, macOS, then Windows, followed by each variant's
  numeric fields.
- Owner kind order is verified then unverified. An owner key is kind, PID,
  marker kind/value with absent marker last, then reason bytes.
- Owner arrays sort by owner key. An owner-set key is completeness (`complete`,
  `partial`, `raced`), lexicographic reasons array, omitted-owner count, then the
  lexicographic owner array.
- Token kind order is Linux inode then macOS socket ID; a token key is kind then
  value, with a null token after every present token.
- Endpoint scope order is IPv4/no-scope, IPv6 unscoped, IPv6 interface indexes
  numerically, then IPv6 unavailable.
- For event ordering, baseline/bind use current token and owner-set keys, release
  uses previous keys, and replacement uses previous/current key pairs.
- Filter-result order is `not_applied`, `matched`, then `indeterminate`.
- Certainty order is `proven`, `estimated`, `heuristic`, then `unknown`.

The exact known state strings are `closed`, `listen`, `syn_sent`,
`syn_received`, `established`, `fin_wait1`, `fin_wait2`, `close_wait`, `closing`,
`last_ack`, `time_wait`, `delete_tcb`, `new_syn_received`, and `bound`.
The exact verdict strings are `bindable_now`, `owned`, `owner_hidden`,
`kernel_state_observed`, `permission_denied`, `address_unavailable`,
`reservation_or_policy_unknown`, `observation_raced`, `unsupported`, and
`indeterminate`.

The initial stable evidence codes are `visible_verified_owner`,
`visible_unreadable_owner`, `non_listening_kernel_state`,
`process_identity_changed`, `exact_bind_succeeded`, `exact_bind_address_in_use`,
`exact_bind_permission_denied`, `exact_bind_address_unavailable`,
`exact_bind_unsupported`, `exact_bind_other_error`, `linux_timer_estimate`,
`docker_context`, `scope_limitation`, `potential_scope_overlap`, and
`observation_probe_conflict`. New codes
are additive schema changes and require documentation and contract tests.

The initial stable public operational codes are `socket_table_unavailable`,
`socket_table_permission_denied`, `native_data_malformed`,
`native_data_oversized`, `socket_observation_limit_exceeded`,
`process_identity_limit_exceeded`, `owner_attribution_limit_exceeded`,
`legacy_projection_limit_exceeded`,
`platform_api_failed`, `clock_unavailable`, `partial_socket_set`,
`observation_raced`, `owner_reason_limit_exceeded`, `event_limit_exceeded`, and
`writer_failed`. Watch
collection gaps use only collection-related codes; writer failure cannot be
represented reliably on the failed writer and is reported to stderr when
possible.

`native_data_oversized` is reserved for source byte buffers or malformed native
counts beyond the source-format limit. Socket-row overflow uses
`socket_observation_limit_exceeded`; PID or identity-read overflow uses
`process_identity_limit_exceeded`; aggregate FD or owner-edge overflow uses
`owner_attribution_limit_exceeded`; and derived legacy-row overflow uses
`legacy_projection_limit_exceeded`.

Scope `identifier` is the bounded sanitized `/proc/self/ns/net` link text in
`net:[decimal]` form on Linux and `null` on macOS and Windows. Scope limitation
arrays are deduplicated and sorted in the order listed by the `Scope` contract.
Every Evidence and EvidenceGap message is at most 512 UTF-8 bytes after
sanitization.

JSON integer domains are fixed: PID and multiplicity are `u32`, port is nonzero
`u16`, schema version is `u32`, sequence/timestamps/counts/tokens are `u64`,
IPv6 interface indexes and query scope IDs are nonzero `u32`, native state code
is `u32`, and raw OS error is `i32`. Serialization checks every
conversion; values outside the public domain are operational errors, not lossy
casts.

#### Existing list JSON

`list --json` remains a top-level array and is documented as
`kickoutchi.list/1`; it has no new envelope. Each record preserves the current
fields and meanings:

```text
{
  protocol,
  local_addr,
  local_port,
  state,
  pid,
  process_name,
  executable_path,
  command_line,
  parent_pid,
  parent_process_name,
  child_pids,
  protected,
  platform,
  permission,
  label
}
```

`label` is the only new field and is a string or `null`. Existing missing fields
remain `null`; command lines retain raw values within the Stage 0.7 bound and
become `null` plus partial permission metadata above it. An empty result remains
exactly `[]\n`.

#### Snapshot JSON

`list --snapshot-json` is mutually exclusive with `--json` and emits one
versioned object:

Snapshot mode is a complete within-scope observation, not a legacy visible-row
projection. It rejects `--port`, `--process`, `--filter`, and `--sort` as invalid
argument combinations before collection. It ignores
`hide_system_processes` because hidden display rows must not remove sockets or
process evidence from a full snapshot. Validated labels still apply because
they annotate rather than filter observations.

```text
{
  schema: "kickoutchi.snapshot",
  version: 1,
  capture: {
    started_unix_ms: unsigned integer,
    completed_unix_ms: unsigned integer
  },
  scope: Scope,
  completeness: "complete" | "partial" | "raced",
  owner_completeness: "complete" | "partial" | "raced",
  evidence_gaps: [EvidenceGap],
  omitted_evidence_gap_count: unsigned integer,
  sockets: [{
    endpoint: Endpoint,
    state: SocketState,
    timer: {
      kind: "none" | "retransmit" | "other" | "time_wait" |
            "zero_window_probe" | "unknown",
      native_code: unsigned integer | null,
      raw_ticks: unsigned integer,
      estimated_remaining_milliseconds: unsigned integer | null,
      certainty: "estimated"
    } | null,
    owners: OwnerSet,
    socket_token: {
      kind: "linux_inode" | "macos_socket_id",
      value: unsigned integer
    } | null,
    label: string | null
  }],
  processes: [{
    identity: ProcessIdentity,
    name: string | null,
    executable_path: string | null,
    parent_pid: unsigned integer | null,
    metadata_completeness: "complete" | "partial"
  }]
}
```

The process array does not include full command lines. `metadata_completeness`
describes optional metadata availability regardless of cause; permission and
other causes remain separate evidence gaps. The legacy `permission` field keeps
its existing name and meaning. Snapshot sockets sort by protocol, address
family, address bytes, IPv6 scope in the order defined above, port, the Stage 0.1 state order, token
kind/value with null last, then canonical owner-set key. Processes sort by PID,
marker kind, and marker value. Evidence gaps sort by impact (`socket_set`,
`ownership`, `metadata`, `scope`), code, endpoint, PID, and message. Evidence
items sort by source in the order listed by `Evidence`, then code, certainty, and
message. No public array uses hash-map iteration order.

#### Watch NDJSON

Every `watch --json` line is independently valid JSON:

```text
{
  schema: "kickoutchi.watch_event",
  version: 1,
  sequence: unsigned integer,
  event: "baseline" | "bind" | "release" | "replacement" |
         "collection_gap",
  observation: {
    previous_completed_unix_ms: unsigned integer | null,
    attempt_started_unix_ms: unsigned integer,
    attempt_completed_unix_ms: unsigned integer
  },
  data:
    {
      endpoint: Endpoint,
      state: SocketState,
      previous_owners: OwnerSet | null,
      current_owners: OwnerSet | null,
      previous_socket_token: {
        kind: "linux_inode" | "macos_socket_id",
        value: unsigned integer
      } | null,
      current_socket_token: {
        kind: "linux_inode" | "macos_socket_id",
        value: unsigned integer
      } | null,
      multiplicity: positive integer,
      label: string | null,
      filter_result: "not_applied" | "matched" | "indeterminate",
      certainty: "proven" | "estimated" | "heuristic" | "unknown",
      evidence: [Evidence],
      omitted_evidence_count: unsigned integer,
      evidence_gaps: [EvidenceGap],
      omitted_evidence_gap_count: unsigned integer
    } |
    {
      error: { code: stable public operational code, message: sanitized string },
      certainty: "unknown",
      consecutive_failures: integer 1..3,
      completeness: "partial" | "raced" | null,
      evidence_gaps: [EvidenceGap],
      omitted_evidence_gap_count: unsigned integer
    }
}
```

The first data shape is used by baseline, bind, release, and replacement.
Baseline has null previous owners; bind and replacement have current owners;
release has previous owners. Replacement requires both sets and complete
verified identity evidence. Socket-token fields follow the same previous/current
side rules; tokenless replacement has both token fields null. Multiplicity is the number added, removed, or
replaced, not the total current endpoint count. `filter_result` is `not_applied`
without a user filter, otherwise `matched` or `indeterminate` under Stage 4.2;
definite non-matches are not serialized. The second shape is used only by
collection gaps and contains no fabricated endpoint event. Event evidence and
gap arrays use the Stage 0.7 per-event limits. Sequence starts at zero and
increments with checked arithmetic.

Serialize each event into a fresh bounded 64 KiB record buffer, write it, flush
according to the watch policy, and then discard it. Exceeding the record bound is
`event_limit_exceeded` and exits `1`; never truncate a valid JSON record.

#### Why JSON

`why --json` emits one versioned object:

```text
{
  schema: "kickoutchi.why",
  version: 1,
  query: {
    port: integer,
    protocols: ["tcp" | "udp"],
    addresses: [string],
    scope_id: unsigned integer | null,
    ipv6_mode: "system_default" | "v6_only" | "dual_stack",
    reuse_address: boolean
  },
  capture: {
    started_unix_ms: unsigned integer,
    completed_unix_ms: unsigned integer
  },
  scope: Scope,
  completeness: "complete" | "partial" | "raced",
  owner_completeness: "complete" | "partial" | "raced",
  results: [{
    endpoint: Endpoint,
    label: string | null,
    verdict: stable verdict name,
    certainty: "proven" | "estimated" | "heuristic" | "unknown",
    probe: {
      outcome: "bindable_now" | "address_in_use" | "permission_denied" |
               "address_unavailable" | "unsupported" | "other",
      started_unix_ms: unsigned integer,
      completed_unix_ms: unsigned integer,
      raw_os_error: integer | null,
      message: sanitized string | null
    },
    evidence: [Evidence],
    omitted_evidence_count: unsigned integer,
    evidence_gaps: [EvidenceGap],
    omitted_evidence_gap_count: unsigned integer
  }],
  aggregate_exit_code: 0 | 1 | 3 | 4
}
```

Verdict names are the lowercase `snake_case` forms from Stage 6.2. Why JSON does
not include full command lines. Human and JSON output must be generated from the
same verdict DTO and carry equivalent facts.

### 7.2 Filters

Document and test the command-specific vocabulary:

- `list`: existing filters plus `label:`, `address:`, `scope_id:`, and
  `family:ipv4|ipv6`.
- TUI: the same visible-row filters as `list`.
- `watch`: list-compatible filters plus `state:` over all collected states.
- `why`: no general filter expression; exact endpoint arguments only.
- Unsupported command/filter combinations return exit `2` with a clear error.
- Existing filters with unchanged meanings.

Parse with an explicit capability set supplied by the command. The shared parser
recognizes the complete field vocabulary listed below. A recognized field that
the current command does not support is invalid. An unknown `name:value` token
remains plain text for compatibility with current path, command-line, and
address searches. All terms are ANDed.

- Existing `pid:`, `port:`, `proto:`, `scope:`, `protected:`, and `parent:`
  meanings remain unchanged.
- `label:VALUE` performs a case-insensitive substring match and never matches an
  unlabeled row. Both operands use the pinned Rust toolchain's
  `str::to_lowercase`; matching performs no Unicode normalization or full case
  folding.
- `address:VALUE` requires one literal IP address and performs exact normalized
  matching of the address component across all scopes.
- `scope_id:VALUE` accepts one nonzero `u32` and may be used alone. It matches
  only IPv6 `InterfaceIndex(VALUE)`, never IPv4, unscoped IPv6, or unavailable
  scope. If combined with `family:`, the family must be `ipv6`; if combined with
  `address:`, every address term must normalize to IPv6. Invalid combinations
  fail before collection with exit `2`.
- `family:ipv4|ipv6` matches the normalized endpoint family.
- `state:VALUE` accepts the lowercase known names from Stage 0.1 plus `bound` and
  `unknown`; `unknown` matches any retained unknown native code.
- List and TUI plain search add label text but otherwise preserve current
  visible-field behavior, including bounded command lines. Watch plain search
  uses endpoint, state, PID, process name, executable path, parent, protection,
  scope, and label from its `Display` profile; it intentionally excludes full
  command lines because the watch polling path never collects them.
- CLI selector flags and filter terms combine with logical AND.
- Recognized-field parse and capability errors occur before native collection,
  write diagnostics only to stderr, and exit `2`. This intentional precedence
  ensures invalid arguments are not masked by an unrelated collection failure.

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
self-contained. Do not write public history such as "implements Stage 4" that
requires this planning document to understand the change.

### Stage 7 gate

- [ ] Every public field and enum value is documented.
- [ ] Help and README examples match executable behavior.
- [ ] Permanent limitations are visible, not buried.
- [ ] Changelog identifies additive serialized-contract changes.

## Stage 8: Security Review and Remediation

Load and follow the security skill for a review-and-remediate pass.

### 8.1 Review scope

Trace every untrusted source to sensitive sinks:

- Config text to terminal and serialization.
- CLI arguments to parsing, filters, probes, and allocation.
- Native table lengths to buffer allocation and unsafe reads.
- Process metadata to terminal, logs, JSON, and NDJSON.
- OS errors to public diagnostics.
- Collection failures to retry behavior.

Revisit every row of the Stage 0.6 threat table against the final code. Add any
new assets, trust boundaries, attacker capabilities, or residual risks created
by the implementation. Record technical severity, remediation priority, and
evidence confidence separately for each confirmed finding.

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

For `socket2`, confirm that the final lockfile still selects `0.6.5`, does not
enable `all`, and does not introduce an unexpected duplicate `libc` or
`windows-sys`. Recheck advisories at the release commit; the Stage 0 review is
not permanent evidence that no later advisory exists.

### Stage 8 gate

- [ ] Threat model reflects final architecture.
- [ ] Confirmed findings have regression tests and fixes.
- [ ] No unresolved release-blocking security finding remains.
- [ ] Residual risks are documented with evidence confidence.

## Stage 9: Automated Test Completion

Load and follow the test-quality skill. Tests must protect behavior and fail for
the intended reason when that behavior is broken.

### 9.1 Unit coverage

Observation tests:

- Verified and unverified owners.
- Duplicate sockets and multiplicity changes.
- Unknown native states.
- Stable, raced, denied, and partial snapshots.
- Empty, one, maximum, and maximum-plus-one boundaries.
- Every owner variant and evidence-gap reason.
- Capture start/completion ordering and wall-clock failure.
- Evidence-gap cap, omitted count, and forced partial completeness.
- Endpoint-null owner-attribution loss changes only global completeness, keeps
  local owner sets and observed edges unchanged, disables replacement, and never
  fabricates endpoint-local `OwnerHidden`.
- Local owner-reason deduplication, canonical ordering, eight-code boundary, and
  checked refusal above the bound while global reasons remain separate gaps.
- Per-value and 64 MiB aggregate process-metadata budgets, deterministic
  omission order, and identity/socket preservation after exhaustion.
- Metadata-profile tests proving watch/why never read command lines while legacy
  list/TUI search retains bounded command-line behavior.
- Optional metadata exhaustion cannot bypass protection; fresh protection reads
  cover success, permission denial, missing/changed name, 4 KiB, 4 KiB plus one,
  and the 2 MiB scoped aggregate.
- Maximum shared-owner legacy projections use borrowed/shared metadata and do not
  multiply command-line allocation by row count.

Label tests:

- Exact and wildcard precedence.
- TCP/UDP and IPv4/IPv6 separation.
- Duplicate and ambiguous selectors.
- Empty, wide, hostile, and overlong labels.
- Entry-count boundaries.
- Literal-address-only parsing and IPv4-mapped-IPv6 normalization.
- 128-byte acceptance, 129-byte rejection, and 32-column clipping.

Filter tests:

- Exact `address:` matching after IPv4-mapped-IPv6 normalization.
- `family:ipv4|ipv6` separation across TCP and UDP.
- List/TUI/watch acceptance of `label:`, `address:`, and `family:`; list/TUI
  rejection and watch acceptance of `state:`.
- Maximum and malformed address/filter values, including unsupported
  command-capability errors before collection.

Watch tests:

- Bind, release, replacement, and collection gap.
- Same PID with changed start marker.
- Failed snapshot followed by recovery.
- Deterministic ordering.
- Proven baseline/bind/release, proven same-PID changed-marker replacement,
  heuristic token-supported or tokenless replacement, and unknown
  collection-gap certainty.
- Cancellation and duration boundaries.
- Broken pipe and writer errors.
- No event retention beyond the documented bound.
- Default 1-second interval and the 100-millisecond, 60-second, and invalid
  adjacent interval boundaries using injected time.
- Third consecutive failure emits its gap, flushes, and exits `1`.
- Maximum event batch and checked maximum-plus-one refusal.
- Process-filter side semantics for baseline/bind current state, release previous
  state, replacement either complete side, and multi-owner same-row conjunction.
- Three-valued filtering emits indeterminate possible matches with gaps, suppresses
  only definite non-matches, and preserves AND/ either-replacement-side rules.
- Shared socket losing one owner edge without emitting endpoint `release`.
- Partial metadata and ownership snapshots advancing safely, `SocketSet` partial
  and raced snapshots emitting gaps without advancing, and a later usable
  snapshot resetting the failure budget.
- Proven same-PID changed-marker replacement, heuristic token-supported and
  tokenless one-to-one replacement, and intentionally silent
  shared-owner-only additions/removals.

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
- Table-driven coverage of every probe outcome against complete, partial, and
  raced observation explanations so the Stage 6.3 table is total.
- Bare TCP loopback matrix, canonical all-addresses matrix, and eight-endpoint
  cap.
- Invalid protocol/address/IPv6-mode combinations exit `2` before probing.
- New output omits full command lines.
- Exact, observed-wildcard, target-wildcard, potential dual-stack, and unrelated
  evidence relationships for TCP and UDP, plus potential-scope overlap for
  unavailable and unequal IPv6 scopes.
- Unavailable default IPv6 returns `Unsupported` and aggregate exit `3` rather
  than being dropped or treated as internal failure.
- Why broken stdout preserves computed aggregate exits `0`, `1`, `3`, and `4`;
  non-broken writer failures exit `1`.

### 9.2 Contract coverage

Pin:

- Config syntax and validation errors.
- Bounded regular config reads, absent defaults, and reader errors. Special-file
  blocking remains the documented host-OS residual risk and is not simulated in
  automated tests with a potentially hanging open.
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
- List and inspect broken stdout exit `0`; kill has no stdout contract; why
  broken stdout preserves its computed aggregate result.
- Existing `list --json` remains an array with exactly one additive nullable
  `label` field and an empty result remains `[]\n`.
- `list --snapshot-json`, watch NDJSON, and why JSON schema names and version
  numbers.
- Unix-millisecond timestamp fields and deterministic array/event ordering.
- 512-byte evidence message and 64 KiB NDJSON record boundaries, including a
  fully populated maximum replacement event whose compact serialization stays
  within the 52,224-byte conservative calculation.
- 4 KiB process-name, 128 KiB executable-path, and 1 MiB command-line boundaries
  with explicit null/partial behavior above each cap.
- Linux migration from 16 KiB truncation to complete-through-1-MiB/null-above-cap
  behavior; no truncated command-line prefix reaches legacy JSON.
- Windows native metadata allocation is rejected before exceeding PID, per-value,
  or 64 MiB aggregate limits.
- Per-event and per-verdict evidence/gap caps with truthful omitted counts.
- Per-native-read retry limits and aggregate owner-edge/identity-read limits.

Parse structured output and assert concrete fields and values. Use small
reviewed canonical fixtures only where exact byte output is itself the contract;
do not replace behavioral assertions with broad snapshots that reviewers are
likely to approve blindly.

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

Mutation-confirm at least owner permission collapse, PID start-marker reuse,
endpoint movement, unknown-state loss, duplicate-socket deduplication, fabricated
release after a gap, replacement ordering, label precedence, probe-error
misclassification, why exit precedence, stdout contamination, unknown protection
treated as unprotected, and signal delivery before final revalidation.

### Stage 9 gate

- [ ] Tests assert concrete behavior and negative space.
- [ ] No flaky retry policy hides failures.
- [ ] No timing test relies on arbitrary sleeps.
- [ ] Critical tests were mutation-confirmed.
- [ ] The full suite passes repeatedly and in parallel where supported.

## Stage 10: Native Continuous Integration

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

### Stage 10 gate

- [ ] Linux native matrix passes.
- [ ] macOS native matrix passes.
- [ ] Windows native matrix passes.
- [ ] Both release binaries build on every target.
- [ ] No platform test is skipped merely to make the matrix green.

## Stage 11: End-to-End QA

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
- Confirm bare `why` evaluates only TCP loopback, while explicit expansion uses
  the canonical matrix and never enumerates interfaces.
- Confirm no-duration watch continues until Ctrl-C without memory growth, while
  explicit duration and the three-failure budget terminate as documented.
- Confirm existing list JSON consumers still receive an array and new snapshot,
  watch, and why output carries the exact schema/version pair.
- Confirm new structured output does not expose full process command lines.

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

### Stage 11 gate

- [ ] QA tested the exact release artifacts on all three platforms.
- [ ] QA verdict is PASS.
- [ ] QA release recommendation is `ship`.
- [ ] Cleanup was verified and residual risk is documented.

## Stage 12: Release Benchmark

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

The Stage 0 `socket2` size measurement is a dependency-acceptance check, not the
release benchmark. Repeat it here against the exact baseline and candidate
release artifacts and include all transitive dependency and symbol changes in
the final size justification.

Thresholds must be chosen before results are seen and must exceed the measured
noise floor.

Performance findings may justify implementation optimization, but any changed
candidate artifact must repeat the affected security review, automated tests,
native CI, end-to-end QA, and this benchmark. A higher minimum watch interval is
a public-contract change: reopen Stage 0 and repeat every affected downstream
gate. Findings may never justify single-pass identity collection, overlapping
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

### Stage 12 gate

- [ ] Correctness was verified before measurement.
- [ ] Baseline and candidate were measured under equivalent conditions.
- [ ] No practical regression budget was exceeded.
- [ ] Results are reproducible and include uncertainty and caveats.
- [ ] Binary and dependency growth are justified.

## Stage 13: Final Release Review

Perform one final review of the complete diff, not only the last stage.

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

Development may proceed stage by stage. Release remains atomic.

## Post-1.3.0 Follow-up: Update Notification

This is explicitly outside the atomic named endpoints, `watch`, and `why`
release. Do not begin it until this complete plan ships as `1.3.0`. Consider it
for `1.3.1` or a later release after separately freezing its behavior and privacy
contract.

Add a non-intrusive notification when a newer Kickoutchi release is available:

- Never block startup on a network request.
- Check in the background at most once every seven days. Persist the last attempt
  so offline or failed checks cannot cause a network request on every startup.
- When no newer applicable release exists, update the cache and show no message.
- Show a status notice rather than a modal or forced prompt.
- Never install an update automatically.
- Never contaminate normal stdout, legacy JSON, snapshot JSON, or watch NDJSON.
  An interactive CLI notice may use stderr only when attached to a terminal.
- Fail silently when offline, rate-limited, or unable to reach the release
  source.
- Allow automatic checks to be disabled.
- State in the privacy documentation that checking contacts the release source
  and can reveal the installed version, IP address, and approximate usage time.
- Give installation-aware guidance. Installer users may run
  `kickoutchi-update`; Homebrew, Scoop, Cargo, Nix, and future AUR users should
  update through their package manager.
- Do not execute `kickoutchi-update` merely to check for a release.

Before implementation, define the trusted release metadata source, cache file
location and bounds, timeout and response-size limits, version comparison rules,
pre-release handling, package-manager detection policy, tests, and failure
behavior.
