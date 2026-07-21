# Stage 4 Implementation Review

## Verdict

APPROVED for the watch-engine gate.

QA verdict: PASS for the Linux release-artifact scope.

Gate recommendation: proceed to Stage 5.

Release recommendation: no recommendation; this is not the complete `1.3.0`
release candidate. Exact bind probes, why, final schema documentation, and native
macOS and Windows runtime gates remain later work.

## Scope And Candidate

- Baseline commit: `fb43938d455eb65d6d643509bc81464f5ac0080d`.
- Candidate source: dirty worktree based on the baseline commit.
- Final Linux `kick` dist artifact SHA-256:
  `857cc0fab90cd1babe4a5fc4260992327cc0844be49ed5eba17d8dbfd7a26ffb`.
- Final Linux `kickoutchi` dist artifact SHA-256:
  `fecbcb906748de8dea644b180bdd175eb03bb274bda8a1e703829f8627b9de48`.
- Authorized target: local host observation and isolated test helpers only. No
  production, third-party, or destructive external target was used.
- Cleanup: integration-test guards terminated helper processes. The benchmark
  script and final raw samples are retained under `benchmarks/`.

## Implementation

- `src/watch.rs` owns the pure bounded snapshot-diff cursor. It preserves socket
  multiplicity, emits deterministic baseline/bind/release/replacement events,
  applies the exact-one replacement rule, and refuses unsafe snapshots or the
  first event beyond the 524,288-event poll cap.
- Replacement readiness is indexed once per snapshot. Bucket reconciliation
  uses constant cursor state and never retains a bucket-sized event queue.
- `src/cli/watch.rs` owns argument validation, polling, cancellation, clocks,
  failure recovery, three-valued filtering, human rendering, and versioned
  `kickoutchi.watch_event/1` NDJSON.
- Polling retains the previous valid snapshot, current snapshot, bounded sorted
  indexes and filter caches, and constant event-cursor state. Output flushes at
  most every 4,096 emitted events. Records are capped at 64 KiB. Evidence and
  applicable evidence gaps retain at most eight entries and report omitted
  counts.
- An initial failed or socket-set-unsafe collection emits no record and exits 1.
  Later failed polls emit and flush one `collection_gap`, preserve the previous
  valid snapshot, and consume the three-failure budget.
- A failed poll that crosses duration expiry or observes cancellation still
  flushes its gap before clean termination. A third consecutive failure always
  exhausts the failure budget and exits 1 after its gap is flushed.
- Filters run after complete native collection. Baseline and bind use the current
  side, release uses the previous side, and replacement matches either side.
  Only definite non-matches are suppressed.
- Canonical ordering includes endpoint, state, event kind, token, owner-set,
  label, filter result, and certainty. Owner reason codes compare and serialize
  in the same lexicographic public-code order. Equivalent-key groups are replayed
  through cheap shared cursor checkpoints, so filter and certainty ordering stays
  global without retaining the group.
- Unix SIGINT and Windows console-control handlers are installed before config
  loading. They exit successfully during the no-output startup window, then use
  one atomic cancellation flag while watch can have output to flush. Watch never
  invokes Docker enrichment or another external executable.

## Contract Evidence

- Unit tests pin duplicate multiplicity, source-order independence, state
  transitions, token-only silence, shared-owner silence, heuristic replacement,
  and proven same-PID changed-marker replacement.
- Scaling tests prove readiness indexing scans each snapshot once and a
  4,097-event single bucket streams without pending event indexes.
- Mutation testing changed the proven same-PID replacement path to heuristic;
  `same_pid_changed_marker_is_proven_replacement` failed until the implementation
  was restored.
- Mutation testing also removed full-owner canonical comparison and cross-capture
  clock validation. The owner-suffix cancellation and reversed-successful-window
  tests each failed for the intended reason before both guards were restored.
- Injected-runtime tests cover initial failure, wall-clock failure, transient
  recovery, retry pacing, third-gap flushing, duration crossing, cancellation
  during a failed poll, baseline interruption, reversed failed-poll clocks,
  broken pipes, observable flushes, and exact evidence/record limits.
- Filter tests cover complete ownerless `protected:false` behavior and stable
  matched-before-indeterminate ordering across more than one output batch.
- Schema tests pin the complete baseline, bind, release, replacement, and
  collection-gap records, including exact key sets, types, nullability, stable
  enum values, claim-specific certainty, and command-line privacy. A fully
  populated replacement fixture remains below the calculated 52,224-byte
  conservative record bound.
- Real-binary Linux tests pin argument rejection, baseline NDJSON, duration exit,
  and SIGINT exit 0. Final dist-artifact smoke tests observed a real Redis
  baseline with uncontaminated NDJSON and successful Ctrl-C termination.
- Collection gaps bypass endpoint filters. Recovery compares against the last
  valid snapshot and therefore never converts a failed collection into fabricated
  releases.

## Independent Review

Independent correctness, security, bounds, and test-quality reviews found and
verified fixes for:

- Duration expiry masking slow initial errors and later invalid snapshots.
- Third-failure and Ctrl-C precedence before a required gap was flushed.
- Endpoint-null PID evidence being attached to unrelated matched events.
- Combining per-PID evidence buckets beyond the eight-reference event bound,
  including a transient ninth allocation during ordered replacement.
- Canonical owner-reason comparison and serialization using enum order instead
  of lexicographic public reason-code order.
- Whole-snapshot replacement-readiness scans repeated for every exact-one
  endpoint bucket.
- Bucket-sized pending release or bind queues exceeding the output batch bound.
- Complete ownerless sockets failing `protected:false` filters.
- Failed-poll wall-clock rollback producing inverted observation intervals.
- Duration or cancellation masking initial failure and third-failure budget
  exhaustion.
- Human owner and label output bypassing public owner and display bounds.
- Filter-result ordering depending on hidden owners beyond the public owner key.
- The event maximum being a disconnected literal rather than a checked
  derivation from the socket maximum.
- Canonical multiset cancellation comparing only the first 64 public owners and
  potentially cancelling sockets whose hidden owner suffix differed.
- Wall-clock rollback between otherwise valid snapshots producing an inverted
  cross-capture observation interval.
- Real-process watch tests lacking guaranteed child and temporary-directory
  cleanup on failure.
- Plain watch search omitting protection classification and structured
  protection filters treating known names as unknown when unrelated metadata was
  partial.
- Mixed owner-reason sets comparing in enum order while their public arrays
  serialized in lexicographic reason-code order.
- Replacement events incorrectly copying heuristic event certainty onto the
  separately proven `process_identity_changed` evidence claim.
- Evidence-gap endpoint ordering comparing port before IPv6 scope instead of
  using the canonical endpoint key.
- Ctrl-C during a blocking special-file config read exiting with the platform
  signal status instead of the watch success code.
- Partial schema assertions that could not detect removed, renamed, or leaked
  watch fields.

The final review reported no release-blocking finding. The only new production
unsafe blocks install and restore the Unix and Windows signal handlers; each has
a local safety proof. A Linux integration test uses one additional documented
unsafe call to signal its own child. No new crate dependency was introduced.
Windows console handling uses an added feature of the existing `windows-sys`
dependency.

## Verification

Passed on Rust 1.95.0:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo deny check
git diff --check
```

The final host suite passed 516 library tests, 28 real CLI contract tests, four
socket lifecycle contract tests, binary targets, and doctests: 548 tests total,
zero failures.

Cross-target checks passed for:

- `x86_64-unknown-linux-gnu` (host tests and checks)
- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

The capability-required Linux suite also passed with
`KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1`.

Native macOS and Windows runtime behavior remains an exact-commit CI requirement
after commit and push.

## Benchmark

Verdict: PASS for the stable-watch gate workload. This is not the final release
benchmark and has no pre-watch latency baseline because the baseline artifact
does not provide the command.

Environment and workload:

- Linux `7.1.4-arch1-1`, x86_64, AMD Ryzen AI MAX+ 395, boost enabled.
- Rust 1.95.0 and Python 3.14.4.
- `cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick`.
- 100 independent closed-loop processes after four warmups.
- `watch --address 192.0.2.1 --interval 100ms --duration 500ms --json`.
- Isolated empty configuration for every invocation.
- Source commit `fb43938d455eb65d6d643509bc81464f5ac0080d`, dirty product source,
  and source-patch fingerprint
  `a388d1b3404cbb720543296a20bd4e0cc87d41abc73a3bc0fa4b724da5c25d53`.
- The exact 217,815-byte applyable source patch is retained beside the raw TSV;
  it includes the benchmark harness and reconstructs cleanly from the recorded
  source commit with `git apply --unidiff-zero`.
- Normal workstation power, scheduler, and concurrent-load state; CPU affinity
  and boost were not constrained. Load average was 1.83 / 2.18 / 2.33.

| Metric | Final candidate |
| --- | ---: |
| Samples / failures | 100 / 0 |
| p50 | 514.882 ms |
| p95 | 515.074 ms |
| p99 | 515.118 ms |
| Maximum | 515.157 ms |
| User CPU, aggregate | 0.827 s |
| System CPU, aggregate | 7.515 s |
| Peak RSS, separate 20-process run | 22,088 KiB |
| `kick` binary bytes | 3,558,752 |

The approximately 15 ms above the requested 500 ms duration is release-process
startup, configuration, native collection, and shutdown overhead. All statuses
are zero. Compared with the 3,304,072-byte named-endpoint artifact, `kick` grew
by 254,680 bytes (7.71%).

The sampler runs separately from the build and records latency and CPU only.
Peak RSS comes from a separate fresh process running 20 independent watch
invocations, so compiler and warmup high-water marks cannot contaminate it.

Raw evidence:

- `benchmarks/watch-stable-2026-07-21.tsv`:
  `e85274635081199703f540d5e6dce188d57ddc12a7f1a886f8373e5e149d4936`.
- `benchmarks/watch-stable-2026-07-21.tsv.source.patch`:
  `a388d1b3404cbb720543296a20bd4e0cc87d41abc73a3bc0fa4b724da5c25d53`.
- `benchmarks/watch-stable-rss-2026-07-21.tsv`:
  `ba19d4c5405cf1fa7690f1431f0f0f4f873856fbfa6ed32de6d34d2bac7a9081`.

## Residual Risk

- Native macOS and Windows signal/runtime behavior is compile-checked here but
  must run in exact-commit CI.
- Stable filtered watch does not measure high churn, maximum snapshots,
  transient-failure throughput, or diff-engine saturation. Those remain final
  release benchmark workloads.
- One hundred samples describe this workstation run but provide limited p99
  confidence and are not a cross-machine performance promise.
- Complete schema reference, platform limitation, and filter-vocabulary
  documentation remains assigned to Stage 7 after watch, probes, and why share
  their final public surface.
