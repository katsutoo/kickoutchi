# Stage 2 Implementation Review

## Status

Stage 2 is complete. Native CI run
`https://github.com/nuggocto/kickoutchi/actions/runs/29779361235` passed on exact
remediation commit `4ba7fe3c2a614b0e9da5bf7bc003aa8c0183eff8`, including Linux,
macOS, Windows, and supply-chain jobs. The subsequent independent review found
no remaining actionable correctness, security, test-quality, or contract issue.

The implementation baseline is commit
`93c9f0a60b1c9006ee41f6c2b2e1573afcd210d0`. The optimized benchmark artifact
was rebuilt from current `HEAD` `8fe4fca234169219d42132486f2658dc248a4a0c`
plus the product-source patch identified in the raw sample file as
`2531ec1a4fcaed58ad94964c1dbb309d2cda924ddde475d999f224cd533d2093`.

## Implemented Contract

- Native snapshots retain every documented TCP state on Linux, macOS, and
  Windows, preserving other numeric states as `Unknown(native_code)`.
- UDP observations remain semantic `Bound` rows; Linux validates but does not
  reinterpret the native UDP state token.
- Linux retains typed timer kind, native unknown code, raw ticks, and the
  checked ceiling millisecond estimate. Timer movement does not create socket
  identity races, while accepted pass-B evidence is retained and duplicate
  timer rows are canonically ordered.
- Linux emits one endpoint-null Scope gap when retained IPv6 rows lack native
  scope identifiers and continues to declare the current network namespace.
- macOS retains process-visible TCP/UDP rows and opaque `soi_so` tokens. Its
  selected libproc interpretation marks IPv6 scope unavailable and emits one
  endpoint-null Scope gap. Conflicting facts for one token and process/descriptor
  scan losses remain `SocketSet` evidence. Expected unbound port-zero descriptors
  are outside endpoint observations rather than global malformed-data gaps.
- Darwin LP64 sizes, alignments, field offsets, constants, and TCP state codes
  are asserted for both release architectures. Native reads validate lengths,
  counts, alignment, and bounded changing-size attempts before interpretation.
- Windows retains all four extended owner-table forms, creation-time process
  identity, network-to-host converted scope IDs, bounded Toolhelp metadata, and
  authoritative rows whose process enrichment fails. Ownerless UDP rows remain
  partial endpoints, and Toolhelp failure in socket-owner enrichment falls back
  to direct bounded identity reads. Flexible-array payloads are length/alignment
  checked before slice construction.
- Existing list, TUI, and destructive projections remain limited to TCP
  `Listen` and UDP `Bound`; established and transitional rows cannot become kill
  targets.

## Review And Remediation

Independent security, architecture, and test-quality reviews found and closed:

- Linux per-table retention beyond the aggregate socket bound.
- Per-row Linux parser allocation after full-state retention increased volume.
- Nondeterministic ordering for otherwise-equal rows with different timers.
- macOS unbound TCP descriptors creating global `SocketSet` gaps.
- macOS unavailable, malformed, or over-budget command lines remaining falsely
  complete.
- macOS aggregate FD-cap exhaustion being reported as allocation failure.
- macOS process-list operational failures becoming empty partial snapshots.
- macOS token conflicts leaving one PID's socket ownership authoritative.
- Insufficient Windows raw-table fixtures and platform-to-observation bridge
  coverage.
- Benchmark artifact and sample-input path replacement races weakening evidence
  provenance.

The reopened review additionally found and remediated:

- macOS zero-plus-errno libproc count failures becoming complete empty results.
- Linux ancestor PID namespace owners being absent from ownership completeness.
- macOS retaining an unsupported IPv6 scope field as an interface index.
- Windows decoding `dwLocalScopeId` without network-byte-order conversion.
- Windows Toolhelp relation failure aborting authoritative socket rows.
- Windows UDP PID zero becoming a process-owner edge.
- Windows IPv4-mapped IPv6 rows retaining a noncanonical address and scope.
- Linux accepting empty, garbage, or headerless socket-table input.
- macOS and Windows parent-name budget exhaustion lacking exact boundary
  evidence and truthful `budget_exceeded` classification.

The Linux parser retest also caught and corrected a fixture-induced regression:
real IPv4 and IPv6 procfs headers use `rem_address` and `remote_address`
respectively. Validation remains strict and family-aware.

Windows `dwLocalPort` intentionally follows the documented `ntohs` behavior and
uses the low 16 bits of the DWORD; only decoded port zero is rejected. This was
rechecked against Microsoft's `MIB_TCPROW_OWNER_PID` documentation after two
reviewers made conflicting assumptions about unspecified high bits.

No unresolved code-level security finding remains in the reviewed Stage 2 diff.
Residual uncertainty is native ABI/API behavior across supported macOS and
Windows releases until exact-commit native CI executes.

## Verification

Passed locally on Linux x86_64:

```text
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo deny check
git diff --check
```

The current Linux run passes 442 unit tests, 22 real-binary CLI contracts, and four
`socket2` contracts. Documentation tests contain no doctests and passed.

Passed cross-target strict Clippy locally:

```text
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets --all-features -- -D warnings
cargo clippy --locked --target x86_64-apple-darwin --all-targets --all-features -- -D warnings
cargo clippy --locked --target aarch64-apple-darwin --all-targets --all-features -- -D warnings
```

GitHub Actions compiled, linted, and ran the native test suite on Linux, macOS,
and Windows for exact remediation commit
`4ba7fe3c2a614b0e9da5bf7bc003aa8c0183eff8`. Run
`https://github.com/nuggocto/kickoutchi/actions/runs/29779361235` also passed the
supply-chain job and `cargo deny check`.

Native fixture coverage includes every documented state, unknown states,
malformed and truncated table data, exact and first-excess bounds, third-attempt
resize success, no fourth attempt, Linux timer transport, Darwin ABI fields,
all four Windows raw table layouts, error-to-gap orchestration, and legacy/kill
negative space.

Mutation confirmation deliberately mapped Linux native `01` to `Listen` instead
of `Established`. The production-shaped full-snapshot test failed because the
established row disappeared before legacy projection. The correct mapping was
restored before final verification.

## Feasibility Measurement

Verdict: PASS for the Stage 2 decision. This is not the final release benchmark
and makes no cross-machine performance claim.

- Workload: optimized `target/dist/kick list --json`, which runs full native
  collection and then the legacy projection.
- Host workload at capture: 576 processes, 3,078 visible descriptor entries,
  45 native `/proc/net` data rows, and 22 projected JSON rows.
- Host: AMD Ryzen AI MAX+ 395, 16 cores/32 threads, 62 GiB RAM, Linux
  7.1.3-arch1-2 x86_64, Rust 1.95.0, AC power online.
- Concurrent load snapshot: 2.17 / 2.72 / 3.09 load average.
- Build: `cargo build --locked --profile dist --all-features --bin kickoutchi
  --bin kick`; thin LTO through the repository `dist` profile.
- Artifact: `target/dist/kick`, 3,248,464 bytes, SHA-256
  `7184727cea04e447b52c2ffb4dc73ba7d7dfeb4e973942c7bf1f290d33e47509`.
- Sampling: eight warmups, 1,000 bounded process invocations, 1,000 successes,
  zero failures. Python `time.monotonic_ns()` measures each bounded private
  snapshot of the optimized artifact; latency and RSS workloads were run
  separately.
- p50: 31.758 ms.
- p95: 32.214 ms.
- p99: 32.701 ms.
- observed maximum: 64.454 ms.
- Peak RSS: 21,960 KiB from 20 successful independent invocations, measured by
  Linux `wait4` accounting through Python `resource.getrusage`.
- Raw samples: `benchmarks/native-collection-feasibility-2026-07-20.tsv`, 15,271
  bytes, SHA-256
  `698c65f71cd90fbf9221c0a43d0af050e655c0eb2eab713a84d893431f62b06b`.

The observed p99 and maximum remain below the frozen 100 ms minimum watch
interval. The margin is sufficient for this host workload, so Stage 0 does not
need to be reopened before Stage 3. High-socket-count native QA and the final
interleaved baseline/candidate release benchmark remain later gates.

## QA Verdict

- Linux, macOS, and Windows Stage 2 scope: PASS.
- Release recommendation: no recommendation. This is an internal implementation
  stage, not a release candidate.

The native collection gate is complete. Stage 3 may proceed.
