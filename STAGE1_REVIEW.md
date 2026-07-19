# Stage 1 Independent Retest Follow-up

## Status

Updated 2026-07-19 from the current worktree after reproducing the independent
retest findings. This document does not rely on the previous Stage 1 review.

The clean remediation baseline and current checked-out commit are both
`ffdb71212c0482a1d806c6c1a0a2a538a4b80462`. The uncommitted remediation patch,
including untracked files but excluding this review record, has SHA-256
`24d6f1eff19eee463d7a018efd9889f57d7bb5c6d8d5c6d5e592aec0218177a3` when
serialized by `git diff --cached --binary` from a temporary index based on that
commit. This identifies the locally verified patch without claiming that it is
a Git commit.

Host runtime: Linux x86_64. Windows and macOS changes were cross-compiled and
strictly linted, but were not executed on native hosts in this retest.

## Remediation Results

- The frozen contract now defines typed optional Linux TCP timer evidence,
  semantic UDP `Bound` rows, strict watch interval/duration parsing, clock
  failure behavior, snapshot JSON projection rules, probe side effects, and
  replacement certainty.
- Linux process identity parsing operates on bounded bytes and parses only the
  ASCII numeric tail of `/proc/<pid>/stat`; a non-UTF-8 `comm` no longer aborts
  a valid identity read.
- Restricted or incomplete procfs enumeration makes global ownership partial.
  Directory-entry errors fail closed rather than silently producing false
  completeness.
- Destructive authority accepts only TCP `Listen` and UDP `Bound` rows, so
  Stage 2 transitional and established TCP observations cannot become kill
  targets through legacy projection.
- CLI, configuration, and multiline startup diagnostics remove terminal control
  sequences while preserving useful line layout. Real-binary regressions cover
  hostile CLI and configuration input.
- Final process identity or protection-name drift is an operational failure with
  zero signal delivery. TUI post-kill handling now schedules one authoritative
  refresh rather than performing a redundant legacy collection first.
- macOS native FD reads reserve only the remaining aggregate allowance and
  reject returned lengths outside the supplied buffer.
- Docker polling, cleanup, and stdout/stderr draining share bounded deadlines.
  Published-port segment 65 is rejected, and retained-match truncation starts
  only at match nine.
- `SECURITY.md` now documents private reporting and sensitive-output handling.
  README timing claims without reproducible raw evidence were removed, and a
  checked-in release-artifact benchmark protocol and sampler were added.
- README configuration, exit-code, JSON privacy, target, checksum, and AUR
  documentation was corrected. Local task descriptions no longer overstate CI
  equivalence.
- CI checkout is pinned to a full action commit. Release verification now checks
  formatting and strict native-target Clippy before publishing artifacts.

## Corrected Guarantees

- Windows process metadata and parent edges are creation-identity checked.
  Toolhelp relation snapshots are bracketed by retained process handles and
  creation markers; the marker returned in `ProcessRead` is the exact marker
  captured before metadata and rechecked on the retained handle and a fresh PID
  handle after metadata. Any mismatch discards the metadata as an unverified
  race. Parent names are read only on demand from similarly validated handles.
- Windows IP Helper records now carry only endpoint/state/scope/PID facts. They
  enter the shared native observation orchestrator directly; no metadata-bearing
  `PortEntry` is created per socket. Sorted unique-PID enrichment receives the
  exact remaining aggregate budget before native allocation, and legacy rows
  are produced only through the shared `Arc` projection.
- Windows process names come only from the bounded `PROCESSENTRY32W.szExeFile`
  value in the frozen Toolhelp source. `QueryFullProcessImageNameW` supplies only
  executable paths. Selected owners are enriched in sorted PID and
  name/path/parent-name/command-line order, with each allocation reserved against
  the per-value cap and aggregate remainder first.
- Windows Job Object termination is withheld after post-commit snapshot, open,
  or evidence uncertainty and after sweep-pass exhaustion. An empty disposable
  job proves freeze and thaw capability before target assignment. Before the
  final validation sweep, the committed job is frozen through private Windows
  information class 18 and the reconstructed 16-byte
  `JOBOBJECT_FREEZE_INFORMATION` ABI, preventing contained descendants from
  spawning through the final validation-to-termination window on supported
  hosts. The pre-freeze and frozen sweeps share one eight-pass budget. Freeze
  failure, unsafe final evidence, and failed job termination attempt thaw and use
  verified per-process fallback/reporting rather than terminating an uncertain
  job. Primary, secondary, and cleanup issues remain separate. Injected tests
  cover capability, freeze/thaw failure, snapshot failure, pass exhaustion, a
  protected child in the frozen final window, and fallback exit verification.
- Optional process metadata readers receive the exact remaining aggregate byte
  budget before native allocation. Owner PIDs and fields are processed in
  deterministic PID then name/path/parent-name/command-line order. Linux,
  macOS, and Windows readers cap or skip native reads using that allowance.
- Legacy projection clones `Arc` owners, not metadata buffers. Tests assert
  pointer identity and strong-count changes across shared-owner projections.
  `child_pids` remains an empty legacy compatibility vector; it is not counted
  as process-string metadata or used as authoritative relationship evidence.
- Destructive legacy projection now materializes only rows matching the selected
  PID or port. Ordinary list/TUI projection remains unchanged.
- Process and parent sorting computes one Unicode lowercase key per visible row;
  sort comparisons allocate nothing. Consistency comparison uses canonical
  socket/owner-edge rows and linear merges instead of `BTreeMap` multisets.
- Linux and macOS shared-owner dedup uses sorted-last checks rather than
  quadratic `Vec::contains`; 32,768-owner fixtures verify sorted-dedup
  correctness on both implementations. Complexity was confirmed by code review,
  not by a mutation-sensitive scaling benchmark.
- Windows parent-name native reads are capped by both the per-name limit and
  aggregate remainder before allocation. Linux and macOS command-line parsers
  retain native argument slices while incrementally checking joined lossy UTF-8
  bytes, then reserve and allocate the accepted output once. Platform seams cover
  exact maxima, lossy expansion, separator accounting, and first refusal.
- Unix tree freeze discovery builds one bounded `ProcessTreeIndex` per snapshot
  and traverses parent-to-children edges across every generation. A depth-256
  tree in a 131,072-row snapshot has an instrumented regression test consistent
  with indexed traversal rather than repeated snapshot rescans.
- Query filtering caches each metadata comparison by shared pointer/value and
  term. Shared 1 MiB ASCII and Unicode command lines are normalized and scanned
  once on no-match paths, including equal values at distinct addresses.
- List writer tests use finite midstream write budgets for JSON and table output
  and separately cover flush-only broken pipes and ordinary failures. JSON keeps
  its legacy top-level array while streaming. Writer observations confirm
  incremental writes; code review confirms that the implementation does not
  construct one complete serialized result, while peak allocation was not
  independently measured.
- Every attributable unverified owner now merges into global owner
  completeness as well as socket-local completeness. A naturally constructed
  matching-endpoint unverified-owner snapshot is rejected by port-selected kill
  collection, while unrelated global incompleteness does not become a false
  target-local refusal.
- Kill collection rejects raced snapshots and any applicable target-local
  ownership or socket-set evidence gap. PID selection requires complete evidence
  for the exact verified PID/start-marker identity and every confirmed endpoint.
  Port selection requires complete, unambiguous attributable matching-endpoint
  owner sets. Unattributable gaps with target-local provenance refuse, while
  omitted gaps whose locality is unknown block both modes. Linux cannot exclude
  an unreadable same-inode co-holder; port mode still selects only a verified
  genuine visible owner, and post-kill polling reports when another holder keeps
  the port bound. Refusal occurs before legacy rows can reach signal delivery.
- Port-backed Unix tree/group, TUI Unix tree, and Windows tree revalidation now
  use `collector::collect_kill_ports`. Non-destructive views remain separate;
  post-kill visibility polling uses identity-only collection rather than repeated
  command-line enrichment. Authoritative uncertainty
  receives at most two bounded attempts of exactly two collection passes each,
  then retains the same fail-closed error and exit mapping before stop, Job
  Object assignment, or delivery.
- Unix continuation failures are typed and visible for single, tree, and group
  termination. Cleanup attempts every frozen member and reports every PID that
  may remain stopped. macOS cleanup rechecks the frozen start identity before
  every raw-PID continuation. Delivery reports also retain failed post-delivery
  thaws.
- Snapshot-derived process identity and IPv6 interface scope remain attached to
  internal legacy rows and kill targets without changing the 14-field JSON
  contract. Detached context reads cannot replace confirmed identity, and scope
  movement is endpoint movement.
- Diff readiness is derived as unsafe for raced/socket-set-incomplete evidence,
  multiplicity-only for incomplete ownership, and replacement-safe only when
  both socket and ownership evidence permit it.

## Regression Coverage

- Windows post-commit injected snapshot error with zero `TerminateJobObject`.
- Windows shared eight-pass sweep exhaustion with zero `TerminateJobObject`.
- Windows capability refusal before target job creation or assignment.
- Windows freeze failure with one best-effort thaw, zero `TerminateJobObject`,
  and independently verified fallback.
- Windows frozen final-window protected child with zero job termination and
  verified fallback for previously contained members.
- Windows primary, secondary, and cleanup issue retention, including both thaw
  failure branches and a fallback process that remains running.
- Unix single-process typed thaw failure.
- Unix tree cleanup attempts all members and reports all failed continuations.
- Unix group cleanup reports failed continuations.
- Global ownership incompleteness without target-local provenance does not block
  PID or port mode. Both modes require complete attributable target-local
  evidence. Linux's accepted unreadable same-inode co-holder limitation may leave
  the port bound, but cannot select a PID that was not observed as a genuine
  owner.
- Partial socket-set authority refuses kill projection.
- Permission-bearing target-local authority loss retains exit `4` through the
  real collector gate, including when raced or omitted evidence also refuses.
- Complete empty owner sets cannot select a port-kill target.
- Exact candidate/per-attempt/total identity bounds and refusal before excess
  process reads.
- Exact remaining metadata budgets in deterministic PID order.
- Many sockets owned by one PID perform one enriched per-pass metadata read,
  retain one bounded process observation, and project pointer-identical `Arc`
  fields into every legacy row.
- Full `collect_consistent` orchestration tests independently cover socket
  multiplicity, owner-edge, marker-only, verified-to-unverified, and
  one-pass-only PID races.
- Deterministic evidence-gap and projected-row ordering, plus actual zero,
  exact, and maximum-plus-one owner-reason, scope identifier/limitation,
  process-name, executable-path, and command-line boundaries.
- Linux tree/context/hint process-name reads enforce the same 4 KiB exact and
  maximum-plus-one bounds as owner metadata. Linux lossy command-line expansion
  and inserted separators are bounded before one accepted-output allocation.
- Windows IP Helper and macOS PID/FD changing-size readers use the production
  retry logic in injected tests covering exact native maxima, max-plus-one
  refusal, success on attempt three, and no fourth attempt.
- One retention-budget omission emits one
  `noncritical_evidence_truncated` gap; the metadata backstop does not duplicate
  it.
- Markerless Unix tree members refuse before `SIGSTOP`; macOS continuation
  requires a recorded, freshly matching start marker before every raw-PID
  `SIGCONT`.
- Tree and group production-wiring tests pass matching-local incomplete
  snapshots through the authoritative validator and prove zero stop and zero
  delivery. The corresponding Windows tree wiring proves the same refusal cannot
  reach Job Object execution. Completed delivery retains and reports a subsequent
  thaw failure.
- TUI tree wiring passes a matching-local incomplete snapshot through the
  authoritative kill validator and proves zero stop, zero delivery, and zero
  ordinary visibility polling. Its successful path separately proves that
  post-kill visibility still uses the ordinary collector.
- The ninth-distinct-scope-limitation boundary now explicitly asserts
  `ScopeLimitationLimitExceeded`; zero and exact-eight boundaries remain covered.
- A production-shaped CLI seam proves successful port delivery despite an
  endpoint-null ownership gap for an unrelated PID. A separate real-host smoke
  contract requires successful `SIGTERM`; it does not claim that the host
  happened to expose such a gap. Deterministic authority tests remain the
  target-local refusal oracle, and the documented Linux same-inode co-holder
  residual risk remains accepted.
- A separate real-binary port kill runs in isolated user, network, and PID
  namespaces with a private `/proc` and requires successful `SIGTERM` delivery.
  The Stage 1 gate sets `KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1`, so unavailable
  IPv6 loopback or user/network/PID namespaces fail rather than silently pass.
- Real Linux tree and group success contracts select their roots by port, pass
  through authoritative recollection, terminate every scoped member, and verify
  the selected port disappears.

## Verification

Passed on Linux x86_64:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features
  429 unit tests passed
  22 Linux test-harness cases passed, including 2 helper dispatch cases
  capability-required IPv6 and isolated namespace contracts executed and passed
  4 socket2 contract tests passed
cargo test --locked --all-features --doc
  passed (0 doctests)
cargo deny check
  advisories, bans, licenses, and sources passed
git diff --check
  passed
```

Cross-target compile/lint evidence:

```text
cargo clippy --locked --target x86_64-pc-windows-gnu --all-targets --all-features -- -D warnings
cargo clippy --locked --target x86_64-apple-darwin --all-targets --all-features -- -D warnings
cargo clippy --locked --target aarch64-apple-darwin --all-targets --all-features -- -D warnings
```

Native CI chronology: GitHub Actions run
[`29689761890`](https://github.com/nuggocto/kickoutchi/actions/runs/29689761890)
executed against exact commit
`ffdb71212c0482a1d806c6c1a0a2a538a4b80462` from 2026-07-19 13:53 UTC through
13:55 UTC. Its Linux, macOS, Windows, and Supply Chain jobs all passed. That run
establishes the clean baseline only; it predates this uncommitted remediation
patch and therefore is not native-CI evidence for the patch.

## Mutation Confirmation

The following eight critical safety guards were deliberately weakened, each
focused test failed for the intended reason, and every original guard was
restored before the full verification run:

- Endpoint movement: accepting every confirmed endpoint made
  `target_is_revalidated_after_confirmation_before_signal` deliver and fail with
  `Success` instead of `NoMatch`.
- PID reuse: accepting unequal non-null start markers made
  `revalidation_rejects_pid_reuse_with_changed_start_time` return a target
  instead of `TargetChanged`.
- Ownership loss: disabling `confirmed_port_owner_unavailable` made
  `revalidation_reports_ownership_unavailable_when_any_confirmed_port_loses_pid`
  return `TargetChanged` instead of `OwnershipUnavailable`.
- Newly protected target: disabling the fresh protection transition guard made
  `target_becoming_protected_after_confirmation_blocks_signal` deliver and fail
  with `Success` instead of `ProtectedNeedsConfirmation`.
- Permission precedence: disabling the typed permission refusal made
  `permission_refusal_precedes_raced_refusal_for_pid_and_port` return generic
  partial authority instead of `OwnershipPermissionDenied`.
- Markerless freeze: allowing a descendant without a start marker to reach
  `SIGSTOP` made
  `markerless_descendant_refuses_before_stop_and_thaws_prior_members` observe an
  extra stop/continue pair.
- Metadata accounting: re-enabling the generic partial-metadata backstop after a
  budget truncation made `omitted_metadata_truncation_gaps_are_counted` count two
  omitted gaps instead of one.
- Lossy command-line output: disabling the decoded-output bound made
  `command_line_decoding_bounds_lossy_utf8_expansion` retain an over-limit value.

## QA

Verdict: PASS for Stage 1 on the current Linux worktree. Recommendation: proceed
to Stage 2; this is not a release recommendation.

Development artifacts using the release profile were rebuilt with:

```text
cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick
```

The resulting non-release `target/dist/kick` artifact was exercised through `--version`, `--help`,
human `list`, and structured `list --json`. Structured
output remained a clean top-level array with all 14 legacy fields. Human output
retained its existing columns. Hostile CLI and configuration arguments were
also checked byte-for-byte; neither output contained terminal escape bytes. The
Linux real-binary contract suite additionally exercised actual
TCP/UDP collection, single termination, tree/group termination, refusal cleanup,
late forks, and port disappearance. A real port-selected termination in isolated
user, network, and PID namespaces with a private `/proc` delivered `SIGTERM` and
passed. Real-binary contracts use Cargo test-profile binaries and are distinct
from these release-profile smoke checks.

Current `dist` artifact SHA-256 values:

```text
ec8f34763cdf59c933e689e1b2c3348946e381cc3b1ad0ed43cc81375ac4f23c  target/dist/kick
583ccee81046a8ebfc006b911d4d1f3d25b15d4ecf86de73d3b8248230b74c48  target/dist/kickoutchi
```

## Benchmark Evidence Correction

The previous Stage 1 latency table and artifact-size comparison are withdrawn.
Their cited raw sample file is absent, so the measurements cannot be audited and
must not be used as acceptance evidence.

The checked-in sampler was smoke-tested against the current release-profile
`target/dist/kick` artifact with two warmups and 20 successful invocations. Its
TSV correctly recorded the source commit, dirty-worktree status, artifact hash,
toolchain, kernel, parameters, and one nanosecond latency per invocation. This
verifies harness operation only; no percentile or regression claim is made from
the smoke run.

Stage 2 must still perform the documented release-mode feasibility measurement
after full native collection exists, including workload counts, host state,
p50/p95/p99/max, failures, and peak RSS. The final release benchmark remains a
separate interleaved baseline/candidate gate with preserved ordering seed and raw
samples.

## Remaining Evidence Gap

Native Windows/macOS runtime behavior is not established by this Linux retest.
The native Windows suite now contains an empty-job class-18 freeze/thaw capability
test, but this Linux retest only cross-compiled it. Injected Job Object tests cover
control flow, partial-transition cleanup, bounded convergence, and reporting;
native Windows CI remains required to establish the private ABI on the target
host. macOS raw-PID behavior and changing-size native reads likewise remain
dependent on native CI despite cross-target compilation.

Because this remediation is still uncommitted, no native CI run can yet belong
to its exact patch identity. Stage 2 implementation may proceed from the locally
verified patch. This is not an interim release point: the eventual atomic `1.3.0`
release still requires every stage and final gate in `FEATURE.md`, including
Linux, macOS, Windows, and supply-chain CI on the exact release commit.

Full native collection of non-listening TCP states and Darwin ABI validation
remain Stage 2 gates. Early Stage 2 adapter work exists in this worktree but is
not claimed as complete or used as Stage 1 acceptance evidence.
