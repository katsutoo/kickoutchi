# Stage 3 Implementation Review

## Verdict

APPROVED for the named-endpoint gate.

QA verdict: PASS.

Gate recommendation: proceed to Stage 4.

Release recommendation: no recommendation; this is not a release candidate.
The later snapshot, watch, and why commands remain governed by their own
implementation gates; they do not exist in the current command surface and were
not implemented early here.

## Scope And Candidate

- Baseline commit: `ce7a6655aca2708a841364746d417a21401cf9f2`.
- Candidate source: dirty worktree based on the baseline commit.
- Candidate source patch SHA-256 recorded by the benchmark harness:
  `36320c8ddee725195f3901edc32e457e9db4756aba5a68e75033bae93d6650da`.
- Baseline `dist` artifact SHA-256:
  `7184727cea04e447b52c2ffb4dc73ba7d7dfeb4e973942c7bf1f290d33e47509`.
- Candidate `dist` artifact SHA-256:
  `9ce42134eb5e4fc3faa8bee055d97c5556d24b7cff9b110c512b9cf80f426bb7`.
- Authorized target: local isolated CLI/TUI test fixtures and local host
  observation only. No production, third-party, or destructive external target
  was used.
- Stop conditions: any unexpected signal delivery, helper leak, nonzero
  benchmark status, or first intermittent test failure.
- Cleanup: integration-test guards terminated helper processes; final benchmark
  samples and the maximum-selector fixture are retained under `benchmarks/`.

## Implementation

- `src/labels.rs` owns validated exact and wildcard selector indexes, IPv4-mapped
  IPv6 normalization, scope-aware identity, deterministic exact precedence,
  terminal clipping, and all label limits.
- `src/config.rs` parses strict `[[ports]]` selectors and adds `ports[index]`
  context to nested deserialization failures. It stops at the first excess
  selector without retaining it.
- Labels annotate borrowed views after collection. They never alter native
  observations, ownership evidence, or destructive authority.
- CLI and TUI queries share plain label search plus `label:`, `address:`,
  `scope_id:`, and `family:` terms. Parsing receives explicit command
  capabilities: list/TUI reject `state:`, watch validates its full state
  vocabulary, and legacy rows refuse full-state evaluation.
- `PortEntryView` is the sole `kickoutchi.list/1` serializer and emits the
  additive nullable `label` field. The exact 15-field production shape is pinned
  by tests.
- Human tables add `LABEL` only when selectors are configured. The TUI omits it
  below 106 columns so all legacy constraints, spacing, borders, and the selected
  row marker continue to fit.
- Unicode 17.0 `Default_Ignorable_Code_Point` is pinned once in `src/display.rs`
  and shared by validation and terminal sinks. Controls, bidi controls, and
  default-ignorable values are rejected before storage and sanitized again at
  rendering boundaries.

The versioned snapshot, watch, and why output types are introduced by later
stages. Their future integrations can resolve labels directly from
`EndpointIdentity` through `LabelRegistry`; no duplicate selector or matching
policy is required.

## Contract Evidence

- No configured selectors: CLI and TUI retain their prior human layout.
- Any validated selector: CLI shows `LABEL`; a sufficiently wide TUI shows
  `LABEL`, including when no visible endpoint matches.
- Exact protocol/address/port/scope beats protocol/port wildcard.
- Wildcards deliberately match every scope state; exact scoped selectors require
  the same numeric interface index.
- IPv4-mapped IPv6 selectors and observations normalize to unscoped IPv4 before
  duplicate detection, matching, and filtering.
- Limits are tested at adjacent boundaries for selector count, label bytes,
  address bytes, port, scope ID, display columns, and filter bytes.
- Real-binary Linux QA spawned a loopback listener and observed the exact label
  in the table, `label:` filter, and JSON while the wildcard label remained
  hidden by precedence. The same endpoint had no `LABEL` column without config.
- Config and rendering tests cover ANSI, C0/C1 controls, bidi, zero-width,
  default-ignorable, wide-Unicode, and direct sink sanitization cases.
- Reversing exact/wildcard lookup order made
  `exact_match_precedes_wildcard_and_protocol_port_remain_distinct` fail with
  `Some("wild")` instead of `Some("exact")`; restoring the implementation made
  the final suite pass.

## Independent Review

Two independent read-only reviews covered correctness, security, bounds,
serialization, rendering, and test quality. Their actionable findings were
resolved:

- Raised the TUI label threshold from 96 to the calculated 106-column boundary
  and added 105/106 tests.
- Added indexed context for unknown, missing, and malformed nested selector
  fields.
- Removed the premature watch-state capability whose non-legacy states could not
  match a legacy row.
- Removed the second, stale `PortEntry` serializer and moved the exact JSON oracle
  to the production view.
- Added adjacent boundary and direct terminal-sink tests.
- Moved the 256-selector retention bound into config deserialization and added
  exact 256/257 config-level tests.
- Added IPv6 scope to TUI row identity and pinned selection preservation across
  otherwise identical interface-scoped endpoints.
- Restored command-scoped parser capabilities while keeping full-state watch
  terms outside legacy list-row evaluation.

One proposed Unicode finding was rejected after checking the official Unicode
17.0 `DerivedCoreProperties.txt`: `U+13430..U+13440` is explicitly subtracted
from `Default_Ignorable_Code_Point`. Those valid format characters are therefore
not over-rejected by the pinned property table.

No critical or high-severity security issue remained. No new dependency or
unsafe block was introduced.

## Verification

Passed on Rust 1.95.0:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo deny check
```

The final host suite passed 464 library tests, 24 real CLI contract tests, four
socket lifecycle contract tests, binary targets, and doctests: 492 tests total,
zero failures.

Strict cross-target Clippy passed for:

- `x86_64-unknown-linux-gnu`
- `aarch64-unknown-linux-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-gnu`
- `x86_64-pc-windows-msvc`

Native macOS and Windows runtime behavior remains covered by exact-commit CI
when the candidate is committed and pushed. The changed feature logic itself is
target-neutral and passed every installed cross-target compile/lint boundary.

## Benchmark

Verdict: PASS for latency and size; peak-RSS delta is directional because the
short independent runs are noisy.

Environment:

- Linux `7.1.4-arch1-1`, x86_64.
- AMD Ryzen AI MAX+ 395, 16 cores/32 threads, boost enabled.
- Rust 1.95.0, LLVM 22.1.2, Python 3.14.4.
- `cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick`.
- Closed-loop `kick list --json`, one process per sample, eight warmups per
  block, two alternating 100-sample blocks per artifact.
- Observed workload near measurement: 579 processes, 3,135 readable
  descriptors, 31 native socket rows, and 22 projected JSON rows.
- Normal workstation power and scheduler state; CPU affinity and boost were not
  constrained. The bimodal tail is treated as environmental noise rather than
  an implementation speedup.

| Metric | Baseline | Candidate | Delta |
| --- | ---: | ---: | ---: |
| Samples / failures | 200 / 0 | 200 / 0 | no errors |
| p50 | 15.885 ms | 15.905 ms | +0.12% |
| p95 | 32.079 ms | 32.225 ms | +0.46% |
| p99 | 32.372 ms | 32.508 ms | +0.42% |
| Maximum | 32.447 ms | 33.251 ms | +2.48% |
| Binary bytes | 3,248,464 | 3,304,072 | +55,608, +1.71% |
| Peak RSS, two 20-run blocks | 21,452-21,696 KiB | 21,404-21,596 KiB | ranges overlap |

All latency observations remain below the predeclared 100 ms feasibility floor.
The latency differences are below the visible run noise and are interpreted as
no measurable regression, not as a speed improvement. Peak RSS remains around
22 MiB, with overlapping ranges; a longer controlled run would be needed to
attribute any difference to the feature.

The candidate was also measured with the maximum 256-selector configuration:
200 samples, zero failures, p50 31.579 ms, p95 31.829 ms, p99 31.965 ms, and
maximum 32.005 ms. The scheduler's bimodal 16/32 ms behavior moved the median
into the second bucket, while p95 and p99 remained within 1.7% of the
unconfigured candidate. This proves the legal maximum remains below the 100 ms
feasibility floor; the run is inconclusive about the selector configuration's
typical latency cost.

Raw files and SHA-256 checksums:

- `benchmarks/named-endpoints-baseline-1-2026-07-21.tsv`:
  `9cc0a219aca8c02f8eccb4e7e3f446664216562b206913243c4408ebde459549`
- `benchmarks/named-endpoints-baseline-2-2026-07-21.tsv`:
  `c8c9f2e1dd73e557d2fa935b3e024f8c568b275aba886d1363a06a63fcfc10f8`
- `benchmarks/named-endpoints-candidate-1-2026-07-21.tsv`:
  `7a97e6fdf28a12befaa8790bacbe77fd0c0d5fa7423869d97459f965f56d888c`
- `benchmarks/named-endpoints-candidate-2-2026-07-21.tsv`:
  `fce919ef031e54c2b4d3bdf86828fe3ac5a9229c216665653fa3c519b2e2d8c5`
- `benchmarks/named-endpoints-candidate-max-labels-2026-07-21.tsv`:
  `1d4d70a939c69e4a505b7a4704a804a4fcb6564cac92809301dfae3252bf882b`
- `benchmarks/named-endpoints-max-selectors.toml`:
  `42eae407d75d3faf526014c0be4a67602b71bdfa2bc425e340cadfce33b05ac9`

The max-label run uses the same candidate artifact. Its source-patch hash differs
because `XDG_CONFIG_HOME` intentionally hid the user's Git configuration while
also selecting the isolated Kickoutchi fixture; artifact identity is unchanged.

Throughput, allocations, and cold-cache behavior were not separately measured.
This gate changes a short-lived local CLI/TUI annotation path, so end-to-end
latency, artifact size, peak RSS, and the maximum legal selector workload were
the gate-relevant measurements.

## Residual Risk

- Native macOS and Windows execution must pass CI on the eventual exact commit.
- Snapshot, watch, and why schemas cannot be runtime-tested until their commands
  exist; each later gate must verify label propagation through the shared
  registry.
- The Unicode property table is intentionally pinned to Unicode 17.0 and must be
  reviewed explicitly if that contract version changes.
