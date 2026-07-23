# Automated Test Completion Review

## Verdict

PASS. The automated-test gate is complete and the change is ready for the
native continuous-integration gate.

The local QA verdict for the exact Linux optimized artifacts is PASS. The
release recommendation for this gate is `proceed`. Native macOS and Windows
runtime execution, exploratory release QA, and the final interleaved release
benchmark remain later gates and are not inferred from cross-compilation.

## Scope And Environment

- Source commit: `2ef547eba4e54fe97eb5135e386c8701c9dff597` plus the recorded dirty patch.
- Branch: `shrek`.
- Host: Arch Linux, kernel `7.1.4-arch1-1`, x86_64.
- CPU: AMD Ryzen AI MAX+ 395, 16 cores and 32 hardware threads.
- Memory: 62 GiB.
- Toolchain: `rustc 1.95.0`, `cargo 1.95.0`, LLVM 22.1.2.
- Authorized runtime scope: local host state and test-owned processes, sockets,
  files, namespaces, and injected native failures. No deployed or third-party
  system was probed.

## Coverage Completed

The added unit and contract coverage pins the previously uncovered behavior:

- Owner-reason canonicalization, local/global gap separation, duplicate socket
  multiplicity, unknown native states, capture ordering, and exact bounds.
- Deterministic metadata omission by PID and field, identity/socket retention,
  command-line profile separation, and fresh protection evidence limits.
- Exact-before-wildcard labels, address-family separation, duplicate selectors,
  normalization, Unicode bounds, clipping, and selector-count limits.
- Address, family, scope, label, and state filter validation and event-side
  three-valued watch semantics.
- Watch failure budgets, safe and unsafe baseline advancement, recovery without
  fabricated events, shared-owner silence, ordering, cancellation, writer
  failures, and record/evidence limits.
- Why collection/probe orchestration, endpoint matrices and limits, verdict
  totality, aggregate precedence, unavailable and unsupported outcomes,
  human/JSON parity, privacy, and writer failures.
- Missing and malformed config, bounded reader failures, interval boundaries,
  CLI help, schema fields, and exact production-maximum serialization.

The Linux real-binary suite uses dynamically assigned ports and explicit IPC.
Its socket lifecycle helper supports TCP and UDP, IPv4 and IPv6, exact and
wildcard binds, IPv6-only and dual-stack settings, one or two sockets sharing an
endpoint, controlled close/rebind, bounded acknowledgements, and owned reader
thread/process cleanup. Deep process-chain fixtures run in a dedicated process
group, publish every member PID through bounded readiness files, verify every
member exits after the destructive journey, and kill the complete owned group on
any setup, assertion, or timeout failure. The public journeys cover legacy and snapshot list
output, label precedence and filtering, inspect, protected refusal and
test-owned termination, watch baseline/bind/release/duration/Ctrl-C/broken
  output, a one-shot native collection failure and recovery, and Why's
  bindable/occupied/unavailable/unsupported/permission-limited and aggregate-exit
  behavior. The helper separately proves endpoint handoff to a new observed
  process. Real-binary replacement event coverage remains conditional because a
  host polling boundary cannot be synchronized with the ownership handoff;
  deterministic in-process coverage pins every replacement class and ordering.

No test uses arbitrary sleep synchronization and no retry-until-green policy was
added. The test harness runs tests in parallel by default; host-observation
journeys serialize only their shared native observation boundary.

## Follow-Up Remediation

A full post-implementation review identified five test-gate defects. Each was
fixed and retested before this final verdict:

- Release workflow validators now require all seven checkout steps to disable
  credential persistence explicitly, normalize supported repository-token
  expression forms, bind each token to its exact publication step and command,
  preserve exact Unix archive/checksum-variable pairings, and require active
  Windows executable uniqueness before installation. In-memory mutations prove
  removed, commented, relocated, aliased, or miswired controls are rejected.
- Every deep-chain member is now published, owned through a dedicated process
  group, checked after successful tree termination, and removed by bounded guard
  cleanup on failure. A separate drop-path test proves every published PID exits.
- Socket lifecycle cleanup closes control input, terminates and reaps the child,
  and joins its reader only after bounded completion notification. Errors are
  retained without allowing one failed operation to skip the remaining cleanup.
- CLI confirmation framing now removes LF or CRLF before applying the 128-byte
  UTF-8 payload cap. Exact-maximum payloads succeed and the first excess payload
  remains a fail-closed input error.
- The real-binary closed-stdout watch journey has no duration fallback. Ignoring
  broken output now reaches the outer process deadline and fails the test rather
  than exiting successfully through an unrelated condition.

## Mutation Confirmation

Each mutation changed production behavior, caused the named regression to fail
for the expected assertion, and was restored before the final suite:

| Fault restored temporarily | Regression that rejected it |
| --- | --- |
| Owner permission denial collapsed into a generic partial snapshot | `permission_refusal_precedes_omitted_evidence_for_pid_and_port` |
| Changed PID start marker accepted | `revalidation_rejects_pid_reuse_with_changed_start_time` |
| IPv6 endpoint scope omitted from identity | `revalidation_rejects_ipv6_interface_scope_movement` |
| Unknown Linux TCP state mapped to closed | `retains_and_maps_every_linux_tcp_state_and_unknown_codes` |
| Duplicate baseline sockets deduplicated | `baseline_is_sorted_and_preserves_duplicate_observations` |
| Failed watch poll corrupted the retained baseline and fabricated release | `recovery_uses_the_last_valid_snapshot_without_fabricated_releases` |
| Previous/current watch owner sides reversed | `endpoint_event_shapes_pin_previous_and_current_sides` |
| Wildcard label preferred over exact label | `exact_match_precedes_wildcard_and_protocol_port_remain_distinct` |
| Address-unavailable probe error classified as other | `owned_errors_map_to_stable_categories` |
| Why failure lost aggregate precedence | `aggregate_precedence_is_failure_then_permission_then_unavailable_then_success` |
| Why collection diagnostic written to stdout | `collection_failure_happens_before_probes_or_output` |
| Missing fresh protection name replaced with stale confirmed metadata | `missing_fresh_protection_name_refuses_without_delivery` |
| Termination attempted before final revalidation | `target_is_revalidated_after_confirmation_before_signal` |

An initial duplicate-socket mutation of the failed watch baseline did not alter
the public event stream and therefore was not counted. It was replaced by the
distinct-endpoint corruption above, which produced the forbidden `release` and
failed the intended assertion.

## Automated Verification

```text
cargo fmt --all -- --check
PASS

cargo clippy --offline --locked --all-targets --all-features -- -D warnings
PASS

KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --offline --locked --all-features
PASS repeatedly after restoration; latest run: 639 library tests, 58 real-binary tests,
6 release-security tests, 4 socket lifecycle tests, 0 doctest failures

cargo test --offline --locked --all-features --doc
PASS: 0 doctests, 0 failures

cargo check --offline --locked --all-targets --all-features --target <target>
PASS: Linux aarch64, macOS aarch64/x86_64, Windows GNU/MSVC

cargo deny check
PASS: advisories, bans, licenses, sources

cargo audit --deny warnings
PASS: 225 locked dependencies, no reported advisory or warning

cargo tree --locked --target all -d
PASS: no duplicate package versions
```

The first strict C helper build failed because this toolchain hides
`SO_REUSEPORT` without its feature declaration. The fixture was corrected with
the required declaration, then the focused test and both complete restored
suites passed. During follow-up remediation, the first strict Clippy run rejected
a collapsible test-helper branch; the branch was simplified and all final host
and cross-target checks passed. No intermittent runtime failure was observed.

## Security Review

Risk verdict: no confirmed vulnerability or new high-confidence security finding
in the assessed test-completion patch.

The review traced untrusted config/filter text, structured output, native helper
inputs, process identity and protection evidence, signal ordering, resource
bounds, and helper cleanup. Tests run only against controlled local resources.
No dependency was added. Dependency policy, advisory scanning, duplicate-version
review, strict lints, and the release-security contracts pass. Residual risk is
unchanged: cross-compiled platform code still requires native execution, macOS
retains its documented raw-PID signal interval, and host special-file config
open behavior is documented rather than exercised with a potentially blocking
fixture.

## Artifact QA

Artifacts were built with:

```text
cargo build --offline --locked --profile dist --all-features \
  --bin kickoutchi --bin kick
```

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `target/dist/kick` | 3,830,872 | `0b1d6123693ebb238c40bd80098078d4760c587969c8c96299ccc51e14681fb0` |
| `target/dist/kickoutchi` | 3,830,888 | `df8b6f4b6bb4d7d720dc6f55e4178090e74663ca328eb7759dedcb33bc43f78c` |

The exact artifacts produced matching `kickoutchi 1.2.0` versions. The short
artifact successfully emitted `kickoutchi.snapshot/1`, evaluated the canonical
eight-endpoint Why matrix with matching aggregate status, and completed a
bounded JSON watch with clean stderr. Automated real-binary tests additionally
exercised early-closing stdout, deterministic helper cleanup, and test-owned
safe termination.

## Directional Benchmark

Verdict: directional PASS. This is a correctness-gate smoke benchmark against
the exact optimized local artifact, not the final baseline/candidate release
comparison.

- Workload: `list --snapshot-json`, one process invocation per sample, native
  collection plus canonical serialization to a discarded consumer.
- Warmups: 3.
- Retained latency samples: 30, all successful.
- p50: 31.759 ms.
- p95: 32.506 ms.
- p99/max: 32.623 ms.
- Peak RSS: 21,232 KiB over 10 independent successful invocations.
- Artifact: `target/dist/kick`, SHA-256
  `0b1d6123693ebb238c40bd80098078d4760c587969c8c96299ccc51e14681fb0`.
- Raw latency evidence:
  `benchmarks/stage9-remediation-snapshot-2026-07-23.tsv`.
- Source patch:
  `benchmarks/stage9-remediation-snapshot-2026-07-23.tsv.source.patch`, SHA-256
  `91bc2a854d4b62947f94bc27a9002572251d8a5da07da1c1117a123d6b077856`.
- Raw RSS evidence:
  `benchmarks/stage9-remediation-snapshot-rss-2026-07-23.tsv`.

The p99 remains well below the predeclared 100 ms polling floor. The workload
has zero request errors and no meaningful sustained-throughput model; CPU
breakdown, cold-start isolation, cross-platform distributions, and an
interleaved baseline comparison remain outside this directional run.

## Residual Gates

- Run all platform-specific tests and real-binary journeys natively on Linux,
  macOS, and Windows against exact release artifacts.
- Perform exploratory user-level QA rather than repeating this automated suite.
- Run the final interleaved baseline/candidate release benchmark and retain its
  versioned raw evidence.
