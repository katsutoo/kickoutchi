# Stage 2 Implementation Review

## Status

Stage 2 implementation is complete in the current worktree. Linux runtime
verification, cross-target compilation/linting, security review, test-quality
review, and the release-mode feasibility measurement pass. The Stage 2 gate
remains open only for Linux, macOS, and Windows native CI on the exact committed
implementation SHA; cross-target checks do not replace native execution.

The implementation baseline is commit
`90508619e7e39cf7d34b7d9272ce4d5af02759d6`. The optimized benchmark artifact
was built from that commit plus the product-source patch identified in the raw
sample file as
`947fe196b39c7243095c69fe975d1900baa6308c363c3035cd727664c9a55202`.

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
- macOS retains process-visible TCP/UDP rows, native interface indexes, and
  opaque `soi_so` tokens. Conflicting facts for one token and process/descriptor
  scan losses remain `SocketSet` evidence. Expected unbound port-zero descriptors
  are outside endpoint observations rather than global malformed-data gaps.
- Darwin LP64 sizes, alignments, field offsets, constants, and TCP state codes
  are asserted for both release architectures. Native reads validate lengths,
  counts, alignment, and bounded changing-size attempts before interpretation.
- Windows retains all four extended owner-table forms, creation-time process
  identity, native scope IDs, bounded Toolhelp metadata, and authoritative rows
  whose process enrichment fails. Flexible-array payloads are length/alignment
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

The Linux run passed 437 unit tests, 22 real-binary CLI contracts, and four
`socket2` contracts. Documentation tests contain no doctests and passed.

Passed cross-target strict Clippy:

```text
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets --all-features -- -D warnings
cargo clippy --locked --target x86_64-apple-darwin --all-targets --all-features -- -D warnings
cargo clippy --locked --target aarch64-apple-darwin --all-targets --all-features -- -D warnings
```

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
- Host workload at capture: 606 processes, 3,486 visible descriptor entries,
  55 native `/proc/net` data rows, and 24 projected JSON rows.
- Host: AMD Ryzen AI MAX+ 395, 16 cores/32 threads, 62 GiB RAM, Linux
  7.1.3-arch1-2 x86_64, Rust 1.95.0, AC power online.
- Concurrent load snapshot: 3.19 / 2.66 / 2.65 load average.
- Build: `cargo build --locked --profile dist --all-features --bin kickoutchi
  --bin kick`; thin LTO through the repository `dist` profile.
- Artifact: `target/dist/kick`, 3,246,224 bytes, SHA-256
  `c31a325a08b511d1e1692b5f470a2e1055faa0d8c8fbcf4aeb3df78b0b991d66`.
- Sampling: eight warmups, 1,000 bounded process invocations, 1,000 successes,
  zero failures. Python `time.monotonic_ns()` measures each bounded private
  snapshot of the optimized artifact; latency and RSS workloads were run
  separately.
- p50: 31.846 ms.
- p95: 32.324 ms.
- p99: 32.530 ms.
- observed maximum: 63.864 ms.
- Peak RSS: 21,684 KiB from 20 successful independent invocations, measured by
  Linux `wait4` accounting through Python `resource.getrusage`.
- Raw samples: `benchmarks/native-collection-feasibility-2026-07-20.tsv`, 15,271
  bytes, SHA-256
  `82285f5b8c96814cb2c6b9245e725ee3cc2d70ed3c5508ed4c66cf35f4096b30`.

The observed p99 and maximum remain below the frozen 100 ms minimum watch
interval. The margin is sufficient for this host workload, so Stage 0 does not
need to be reopened before Stage 3. High-socket-count native QA and the final
interleaved baseline/candidate release benchmark remain later gates.

## QA Verdict

- Linux Stage 2 scope: PASS.
- macOS and Windows runtime scope: BLOCKED locally by host platform; native CI is
  required.
- Release recommendation: no recommendation. This is an internal implementation
  stage, not a release candidate.

Stage 3 must not begin as a completed gate until native CI passes the collector
tests on Linux, macOS, and Windows for the exact committed Stage 2 SHA.
