# Stage 6 Implementation Review

## Verdict

APPROVED for the Why verdict-engine gate.

QA verdict: PASS for the Linux native-runtime scope and the configured
cross-target compile scope.

Gate recommendation: proceed to public-output stabilization after native macOS
and Windows CI runs the exact commit.

Release recommendation: no recommendation. The complete `1.3.0` release still
requires the remaining documentation, security, native CI, QA, benchmark, and
final-review gates.

## Scope And Candidate

- Baseline commit: `e52dd5d8107c10c0fbb6db60496943cc0924780f`.
- Candidate source: uncommitted worktree based on the baseline commit.
- Reviewed production files: `src/diagnostic/verdict.rs`, `src/cli/why.rs`, and
  their module and dispatch integration in `src/diagnostic.rs`, `src/cli/mod.rs`,
  and `src/lib.rs`.
- Reviewed contract and release records: `FEATURE.md`, `CHANGELOG.md`, and
  `tests/cli_contract.rs`.
- No dependency or lockfile change was required.

## Implementation

- `diagnostic::verdict` is a pure engine. It performs no collection, clock,
  socket, Docker, terminal, or filesystem I/O.
- `kick why` validates and canonicalizes its complete endpoint matrix before
  collection or probing. A request contains at most eight endpoints.
- The command collects one `Display` snapshot, runs exact probes sequentially,
  resolves labels, computes every result, and only then writes output.
- Bare queries evaluate TCP on IPv4 and IPv6 loopback. Explicit selectors cover
  TCP, UDP, exact addresses, the canonical all-addresses matrix, numeric IPv6
  scope, system-default/IPv6-only/dual-stack behavior, and optional address
  reuse.
- Relationship analysis distinguishes exact, both same-family wildcard
  directions, potential dual-stack overlap, potential scope overlap, and
  unrelated observations. Potential relationships cannot select an ownership
  verdict.
- The probe-first total table produces all ten documented verdicts with explicit
  certainty. Ownership messages identify snapshot-capture time so they do not
  imply that the earlier owner necessarily caused the later failed bind.
- Evidence and evidence gaps retain at most 16 entries each and use saturating
  omitted counts. Public messages are sanitized and limited to 512 UTF-8 bytes.
- Gap applicability builds its matching-owner index once, then sorts and scans
  the bounded gap set without socket-by-gap multiplication. PID-scoped global
  socket-set loss remains visible for every endpoint it may hide, while unrelated
  process-metadata loss does not consume per-result retention.
- Human and `kickoutchi.why/1` JSON output are rendered from the same completed
  verdict records. JSON uses dedicated DTOs rather than serializing internal
  domain types.
- Human and JSON output stream directly after verdict completion, so every legal
  maximum result shape remains renderable without a whole-document byte cap.
  Broken stdout preserves the already-computed aggregate exit, while other
  writer or serialization failures exit `1`.
- Why uses `Display` metadata and does not collect or expose full process command
  lines. Existing list-only command-line hints remain isolated.
- Optional Docker enrichment is not requested. The contract permits omission,
  and the current legacy-row API cannot satisfy the one-invocation Why bound
  without introducing the wrong coupling.

## Decision And Exit Coverage

Focused tests cover:

- Every probe outcome against complete, partial, and raced snapshots.
- Verified, unverified, locally complete ownerless, globally incomplete, and
  non-listening kernel-state explanations.
- Closed and unknown TCP states not claiming to explain a failed bind.
- Exact and both wildcard directions for TCP and UDP.
- Known equal, unequal, and unavailable IPv6 scopes.
- Potential dual-stack overlap remaining supporting evidence only.
- Successful-probe precedence over an earlier matching observation.
- Permission denial separating the proven error from unknown bindability.
- Evidence and gap maximum-plus-one retention with exact omitted counts.
- Additive relationship-call growth rather than socket-by-gap multiplication.
- Every verdict-to-exit mapping and aggregate `1 > 4 > 3 > 0` precedence.
- Broken write and flush behavior for aggregate exits `0`, `1`, `3`, and `4`.
- Exact nested JSON shapes, human/JSON fact parity, UTF-8 message boundaries,
  terminal sanitization, command-line omission, and a legal maximum JSON document
  larger than 256 KiB rendered incrementally.

## Real-Binary QA

Linux real-binary journeys cover:

- Occupied TCP with a verified owner and versioned JSON evidence.
- Occupied UDP with human evidence.
- Bindable TCP and UDP with immediate post-command rebind.
- IPv6 scope-limited diagnosis and the full eight-endpoint matrix.
- Exact label propagation.
- Invalid port, zone, scope, and mode combinations before result output.
- Mixed bindable/unavailable aggregate exit behavior.
- Controlled real-binary bind faults proving aggregate `1 > 4 > 3 > 0`
  precedence across indeterminate, permission-denied, unavailable, and bindable
  endpoint results.
- A non-dumpable listener producing a real partial snapshot with permission-limited
  ownership evidence.
- Closed-reader stdout preserving aggregate exits `0` and `3`.
- Empty stderr for clean human and JSON results.

The macOS and Windows test modules contain bounded native TCP, UDP, IPv6, and
probe-release journeys. They compile under their target configurations and must
execute in native CI on the exact commit.

## Security And Resource Review

Independent review found and remediation fixed:

- A pathological socket-by-gap comparison path. Gap filtering now builds a
  bounded matching-owner index once before sorting and scanning the bounded gap
  set.
- Message allocation after evidence saturation. Evidence construction is lazy.
- PID-scoped global ownership and socket-set gaps being omitted from ownerless
  or incomplete results.
- Permission denial lacking separate unknown-bindability evidence.
- Hidden-owner evidence appearing before verified-owner evidence when socket
  order differed.
- Ownership wording that could blur snapshot time and later probe time.
- A legal maximum Why document exceeding an unrelated 256 KiB buffer cap.
- Future source-first ordering text conflicting with Why's frozen presentation
  order.
- Procfs visibility uncertainty being treated as complete ownership evidence.

No critical, high, or remaining actionable security finding was identified in
the reviewed scope. Inputs, retained collections, messages, output documents,
and probe counts have explicit bounds. Why child commands and fixture compilation
have exit deadlines and drain output concurrently.

## Verification

Passed with Rust 1.95.0:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo deny check
git diff --check
```

The final Linux suite passed 577 library tests, 39 real CLI contract tests, and
four socket lifecycle contract tests: 620 tests total, zero failures.

Strict cross-target checks passed for:

- `x86_64-pc-windows-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

## Benchmark

The exact dist artifact was built with:

```text
cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick
```

- Candidate SHA-256: `b0409ea25f5712dc673089aea47c493929fbdf158527d5027c513030bf10b244`.
- Candidate size: 3,686,584 bytes.
- Complete eight-endpoint Why JSON, three warmups and 30 retained samples, zero
  errors:
  - p50: 32.042 ms
  - p95: 32.455 ms
  - p99/max: 32.627 ms
- Peak RSS: 22,184 KiB across ten successful retained samples.
- Raw latency evidence:
  `benchmarks/why-complete-2026-07-22.tsv`
  (`a2822a45bf74a80d79ae07abb4f5eaece3ab2ab826bfae447a8cb504b0819673`).
- Exact source patch:
  `benchmarks/why-complete-2026-07-22.tsv.source.patch`
  (`4948fa4e8ebed89f9d7f20aed3e98b88b4a6e95cbd38387b343c3f56b3cecabd`).
- Raw RSS evidence:
  `benchmarks/why-complete-rss-2026-07-22.tsv`
  (`edc8df1a0d07a8c62a6ea26040de9b86d9d7151655cc5d8bcc2d06234f8e71fa`).

The latency samples are visibly bimodal on a shared workstation and are exact-
artifact acceptance evidence, not a production capacity estimate or a claim of
cross-machine performance.

## Documentation Audit

- `CHANGELOG.md` describes the command and public behavior without implementation
  stage or phase numbering.
- No added code comment uses numbered stage or phase terminology.
- `FEATURE.md` records the completed gate and remains the internal planning
  document.
- The requested review record is `STAGE6_REVIEW.md`.

## Residual Risk

- A successful bind probe proves only the instant at probe completion. Another
  process may claim the endpoint immediately after the probe socket closes.
- Positive real-binary probe tests release a kernel-assigned port before invoking
  the child command. They do not retry or hide a race with unrelated host
  processes.
- Snapshot ownership and later probe results are separate time-scoped facts.
  Output states both timestamps and does not claim causal continuity.
- A successful probe briefly occupies the endpoint. Probes are sequential and
  release the socket by owned drop before returning.
- Native Windows and macOS runtime evidence remains the exact-commit CI gate;
  cross-target compilation cannot establish native behavior.
