# Stage 7 Implementation Review

Date: 2026-07-22

Decision: PASS for the public-output and documentation implementation gate.
There are no unresolved code, security, test-quality, documentation, or Linux
artifact-QA findings in this scope. This is not the final release decision;
native artifact QA and release-candidate validation remain assigned to their
later gates.

## Reviewed Source State

- Branch: `shrek`
- Source commit: `0078bdfa3ab664a7939c6add75875116a4f76ea6`
- Package version: `1.2.0`, intentionally unchanged for this implementation
- Worktree: dirty with the implementation and retained evidence described here
- Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
- Host: Arch Linux, kernel `7.1.4-arch1-1`, x86_64

The retained benchmark companion patch records the complete product and harness
source delta from the source commit. Documentation and this review are reviewed
in the worktree but do not affect the measured executable.

## Implemented Contracts

- Added `list --snapshot-json` with parse-time conflicts against `--json`,
  `--port`, `--process`, `--filter`, and `--sort`.
- Snapshot collection uses `MetadataProfile::Display`, preserving bounded names,
  executable paths, parent PIDs, identities, full socket states, timers, owner
  sets, tokens, scope, completeness, and evidence gaps without collecting full
  command lines.
- Snapshot output ignores `hide_system_processes`, bypasses the legacy
  listener/bound projection, retains configured labels, and always represents a
  complete-within-declared-scope observation.
- Added the versioned `kickoutchi.snapshot/1` object with checked timestamps,
  counts, explicit nulls, stable names, canonical ordering, and one final
  newline.
- Added `src/public_output.rs` as the shared owner of reusable public DTOs,
  stable mappings, checked conversions, canonical comparisons, and the borrowed
  snapshot writer.
- Snapshot serialization retains only bounded socket, owner, process, and gap
  sorting indexes. It constructs each public record transiently through Serde
  and never clones the `NetworkSnapshot` or buffers the full document.
- Migrated reusable watch and Why DTOs and names to the shared public layer while
  preserving the existing `kickoutchi.watch_event/1` and `kickoutchi.why/1`
  shapes.
- Why result records now serialize one at a time rather than retaining a second
  result DTO graph.
- Moved the legacy `kickoutchi.list/1` serializer behind an explicit public DTO;
  its top-level array and 15-field record remain unchanged.
- Preflight validation rejects invalid capture intervals, timestamps, owner
  reason bounds, timer invariants, counts, and non-UTF-8 public paths before any
  snapshot byte is written.
- Untrusted argument and config diagnostics are flattened to one sanitized line,
  preventing newline-bearing values from forging stderr records.

## Canonical Ordering And Bounds

Focused tests pin:

- Protocol, address family/bytes, IPv6 scope, port, state, token, owner-set, and
  explicit timer socket tie-breakers.
- Linux, macOS, and Windows marker shapes and marker order.
- Verified and unverified owner shapes, owner ordering, partial/raced reasons,
  and exact 0, 1, 64, and 65 owner transitions.
- IPv4, IPv6 unscoped, interface-index, and unavailable scope shapes.
- Known and unknown socket states and both socket-token variants.
- Evidence-gap impact, code, null-first endpoint, PID, and sanitized-message
  ordering.
- Hash-map and input-order independence through reversed synthetic snapshots.
- Incremental writes for an 8,192-socket document without a retained rendered
  buffer.

Native collection already enforces the exact 262,144-socket retention boundary.
The public serializer remains bounded by those native limits; an exact maximum
synthetic serialization and comparative maximum-workload RSS gate remain part of
the later comprehensive test and release benchmark work.

## Compatibility And Privacy

- Legacy list JSON remains a top-level array and an empty result remains exactly
  `[]\n`.
- Existing watch NDJSON remains compact, one record per line, and bounded to
  64 KiB including its newline. Oversized records never partially write.
- Why result order remains protocol-major then address-minor, and verdict
  evidence retains presentation order.
- Snapshot, watch, and Why omit full command lines. Snapshot also omits parent
  process names and internal metadata-omission causes.
- Privacy tests place unique command-line, parent-name, and internal metadata
  sentinels in the source snapshot and prove they occur nowhere in output.
- Structured host strings remain sensitive and may contain terminal-significant
  Unicode. The security and structured-output references explicitly require
  parsing and redaction rather than direct terminal display.
- Why does not request Docker enrichment, and watch does not invoke Docker in its
  polling loop.

## Documentation

Added authoritative references:

- `docs/structured-output.md`
- `docs/configuration.md`
- `docs/platform-support.md`

Updated README, CLI help, `SECURITY.md`, and `CHANGELOG.md` for snapshot mode,
Why, filters, schemas, exits, privacy, namespace/WSL/platform limits, polling
blind spots, bind-probe occupancy and races, certainty, and Docker boundaries.
All relative links resolve. The changelog describes each additive contract
self-contained and contains no numbered stage or phase wording.

## Security Review

Review mode: review and remediate, limited to local source, tests, docs, and safe
local execution. No deployed system or third-party target was probed.

Remediated findings:

1. Newline-bearing argv and config paths could create forged diagnostic lines.
   CLI and config errors now use single-line sanitization with real-binary
   regression coverage.
2. The socket comparator allocated bounded reason vectors during every sort
   comparison. Owner completeness, reasons, and omitted counts are now computed
   once per socket index.
3. Invalid timer state could fail after a JSON prefix had been written. Timer and
   identity-critical bounds now preflight before serialization.
4. Documentation overstated JSON as display-safe. It now distinguishes syntax
   safety from terminal safety and redaction.

Security retest verdict: no remaining confirmed or high-confidence finding in
the reviewed implementation.

## Test-Quality Review

The independent test review initially found weak deep-order assertions, privacy
checks based only on key names, incomplete tagged variants, a false-positive
system-row fixture, missing preflight atomicity cases, and unsafe fixture-file
cleanup. Each was remediated with behavior-focused tests and RAII cleanup.

The shared public-output tests were then run ten consecutive times with eight
test threads. Every run passed without retry or intermittent failure.

## Automated Verification

Commands and results:

```text
cargo fmt --all -- --check
PASS

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS

KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features
PASS: 601 library tests, 46 real-binary CLI contract tests,
      4 native socket lifecycle tests

cargo test --locked --all-features --doc
PASS: 0 doctests, 0 failures

cargo deny check
PASS: advisories, bans, licenses, sources

cargo clippy --locked --target x86_64-pc-windows-gnu \
  --all-targets --all-features -- -D warnings
PASS

cargo clippy --locked --target x86_64-apple-darwin \
  --all-targets --all-features -- -D warnings
PASS

cargo clippy --locked --target aarch64-apple-darwin \
  --all-targets --all-features -- -D warnings
PASS
```

Cross-target Clippy compiles platform-gated code but does not replace native
macOS or Windows execution. Native platform artifact QA remains a later gate.

## Exact-Artifact QA

QA verdict: PASS on the Linux artifact below.

Release recommendation for this implementation gate: proceed. Final release
recommendation: not evaluated here.

The exact `target/dist/kick` artifact was exercised with an isolated config and
a controlled TCP listener. The run verified:

- Snapshot schema/version, configured label, verified owner PID, process record,
  and command-line absence.
- Legacy list JSON remains an array.
- Watch emits valid versioned baseline NDJSON for the controlled listener.
- Snapshot option conflicts exit `2` before a missing explicit config is read.
- Why reports a closed controlled endpoint as `bindable_now`, releases the probe
  socket, and permits immediate rebind.
- `list --help` advertises `--snapshot-json`.
- Closed stdout exits successfully; `/dev/full` exits `1` with stderr-only
  diagnostics.

No test process, listener, or configuration was left behind.

## Release Artifact

Build command:

```sh
cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick
```

Artifacts:

| Binary | Bytes | SHA-256 |
| --- | ---: | --- |
| `target/dist/kick` | 3,798,072 | `5f4ff685f6f6c110080077a34cafeefa4c1ebf3a45de27bf5892cfc430e7c583` |
| `target/dist/kickoutchi` | 3,798,080 | `d6afe69b0b9c8d8844a681990df8c595ff7d6ab036dce3a77ae40045790cb147` |

## Snapshot Benchmark

Benchmark verdict: PASS for implementation acceptance. The run is reproducible
and trustworthy for this host's current live snapshot, but it is not a baseline
comparison or the final multi-workload release benchmark.

Workload: exact release-profile `kick list --snapshot-json` with isolated empty
configuration. The harness validates `kickoutchi.snapshot/1` before sampling and
discards stdout during measurement.

| Metric | Result |
| --- | ---: |
| Samples | 30 |
| Warmups | 3 |
| Failures | 0 |
| p50 | 15.484965 ms |
| p95 | 16.370089 ms |
| p99 / max | 32.199485 ms |
| User CPU across samples | 0.088428 s |
| System CPU across samples | 0.292471 s |
| Peak RSS, 10 independent runs | 22,312 KiB |
| Artifact size | 3,798,072 bytes |

Retained evidence:

- `benchmarks/snapshot-complete-2026-07-22.tsv`
  - SHA-256: `f272df298aeb4f87c844b5a00180f54e62635d965ea7ced4f0f9ec88351f00e6`
- `benchmarks/snapshot-complete-2026-07-22.tsv.source.patch`
  - SHA-256: `47d66cb62bcebd8cd569c5ae1b385a0d0fec93cc3647af3dacf4fe1aee5d7906`
- `benchmarks/snapshot-complete-rss-2026-07-22.tsv`
  - SHA-256: `04776d410cde5bb2861f55b8df5f79f379e2d5c84b5d67b43869efb3c0e9c909`

The companion patch applies with `git apply --unidiff-zero -p1` from the recorded
source commit. The measured artifact hash matches both retained TSV files.

## Gate Conclusion

- Every public field, enum, stable code, null rule, range, cap, and ordering rule
  is documented.
- README and help examples match executable behavior.
- Permanent platform, permission, namespace, WSL, polling, Docker, privacy, and
  bind-probe limitations are prominent.
- Changelog entries identify the additive serialized contracts.
- Real-binary assertions pin documented commands, schema/version pairs, exits,
  stderr separation, compatibility, and privacy-sensitive absence.

The public-output and documentation implementation is complete.
