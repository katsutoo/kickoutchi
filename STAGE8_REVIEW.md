# Security Review and Remediation

Date: 2026-07-23

Decision: PASS for the security implementation gate. Confirmed and
high-confidence findings were remediated with focused regression coverage. No
unresolved release-blocking security finding remains in the reviewed scope.

This decision covers the local source, tests, documentation, dependency graph,
and release workflow. It is not the final release decision; exact native release
artifacts, publisher settings, and release-candidate provenance still require
their later gates.

## Reviewed Source State

- Branch: `shrek`
- Source commit: `2731cc2adb9714e3ab3575fbbba9c472c53ad264`
- Package version: `1.2.0`, intentionally unchanged
- Worktree: dirty with the reviewed remediation and evidence described here
- Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
- Host: Arch Linux, kernel `7.1.4-arch1-1`, x86_64
- Engagement mode: review and remediate
- Authorized execution: local source analysis, controlled child processes,
  loopback/local bind behavior, repository tooling, and read-only upstream
  release metadata
- Excluded: production, third-party systems, remote Docker daemons, discovered
  credentials, destructive load, persistence, and external exploit attempts

## Final Threat Model

Protected assets:

- Correct process identity, protection policy, and signal delivery.
- Truthful endpoint ownership, bindability, observation scope, and certainty.
- Memory safety and resource ownership at native and FFI boundaries.
- Predictable CPU, memory, process, file-descriptor, retry, and output use.
- Terminal integrity and stable JSON/NDJSON contracts.
- Privacy of process names, paths, command lines, labels, and Docker metadata.
- Locked dependency resolution and verified release-tool inputs.

Relevant attackers are local unprivileged users or processes able to influence
config files, arguments, process metadata, socket churn, child output, or an
output consumer. Kernel and native APIs provide authority but are not trusted for
stable sizes or timing. Docker output, PATH resolution, package registries,
GitHub Actions, downloaded build tools, release hosting, and the Homebrew tap are
separate trust boundaries.

| Threat | Final control | Evidence confidence | Residual risk |
| --- | --- | --- | --- |
| Hostile config, process, Docker, or OS text controls a terminal | Bounded input and sanitization at every human sink | High | Structured JSON is escaped but still sensitive and unsafe for direct terminal display |
| Malformed native lengths or pointers violate memory safety | Checked arithmetic, alignment and returned-length validation, initialized storage, RAII ownership, local safety proofs | High | Hand-maintained Darwin layouts and private Windows freeze semantics remain OS-version contracts |
| PID reuse or endpoint movement targets another process | Typed markers, fresh authoritative collection, pidfds or handles where available, final protection evidence, fail-closed delivery | High | macOS retains a raw-PID marker-read-to-signal interval |
| A detected macOS replacement remains stopped | Rollback uses the identity observed after `SIGSTOP` and rechecks it before `SIGCONT` | High | A second replacement can make cleanup fail closed and require manual recovery |
| Collection churn fabricates ownership or watch events | Two-pass bounded collection, explicit raced results, last-valid-snapshot recovery | High | Polling cannot observe activity wholly between snapshots |
| Permission or scope loss becomes a false free result | Typed gaps, local/global completeness, unknown certainty, destructive refusal | High | Information outside the declared namespace or host stack is unavailable |
| Native tables, metadata, labels, hints, or diffs exhaust resources | Named source bounds, checked capacity arithmetic, streaming writers, fixed retries and batches | High | Synchronous kernel or filesystem calls have no portable deadline |
| Optional related-process hints scan an entire hostile host | Highest-PID-first Linux/macOS scan capped at 64 command-line reads; separately bounded Windows snapshot; no token index | High | A matching process outside the scan budget can be omitted |
| Watch retains state or invokes Docker repeatedly | Two snapshots, bounded cursors and batches, no Docker call path | High | A blocked output consumer can stall a synchronous write |
| Docker output descendants retain unbounded drain work | Each pipe stops at the first excess byte; worker concurrency remains capped | High | A quiet inherited pipe can retain one bounded worker until the writer closes |
| Docker cleanup abandons direct children or blocks the caller | A pre-reserved cleanup worker retains each terminated child through reap; four-worker capacity refuses further process spawn | High | A stuck kernel wait can retain one bounded worker and child indefinitely |
| Bind probes leak sockets or interfere with each other | Sequential RAII sockets, setup then bind-result capture and immediate drop | High | A successful probe briefly occupies the endpoint and cannot reserve it after close |
| Shell, argument, PATH, or remote-Docker injection crosses authority | No shell, structured arguments, local host validation, ambient selector removal, privilege gate | High | Ordinary users intentionally trust their PATH-resolved local Docker client |
| Public output leaks command lines or unstable errors | Dedicated DTOs, stable codes, bounded messages, command lines only in documented compatibility/detail surfaces | High | Explicit legacy/detail output remains sensitive local-system data |
| Dependency or release-tool compromise reaches artifacts | Locked registry checksums, cargo-deny and RustSec review, full-SHA actions, archive digests before extraction | High | Compromise of an approved upstream release or publisher identity remains possible |
| Mutable tooling receives repository credentials unnecessarily | Release planning is read-only and scopes its token to the dist step; Homebrew validation runs without credentials and its PAT exists only during final push | High | Repository contents cannot prove external token scope or hosting policy |
| Artifact and checksum are replaced by one publisher | Documentation does not treat same-channel checksums as signatures | High | Independent attestation and immutable-release settings remain release-owner controls |

Authentication, browser sessions, server-side requests, databases, multi-tenant
authorization, cryptographic key storage, and web protocol controls are not
applicable to this local CLI/TUI architecture.

## Remediated Findings

### macOS replacement cleanup used stale identity

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: High
- Root cause: rollback compared the current PID occupant with the originally
  authorized marker after final evidence had already identified a replacement.
- Impact: an unrelated replacement that accepted `SIGSTOP` could be denied the
  compensating `SIGCONT` and remain suspended.
- Fix: retain the marker from post-stop fresh evidence, keep termination
  authorization bound to the original marker, and guard continuation with the
  post-stop marker.
- Regression coverage: matching post-stop identity receives one continuation;
  failed evidence falls back to a guarded recheck of the authorized identity;
  a second identity change receives none. Both macOS targets compile the tests.

### Related-process diagnostics had no aggregate work limit

- Technical severity: Low
- Remediation priority: Medium
- Evidence confidence: High
- Root cause: Linux and macOS stopped after eight matches rather than after a
  bounded number of command-line reads; matching also allocated a token index.
- Impact: a local process population could force excessive command-line I/O,
  allocation, and CPU for an optional no-match hint.
- Fix: inspect at most 64 command lines on Linux and macOS, prefer newer/highest
  PIDs, and use a peekable token iterator without building a token index. Windows
  retains its separately bounded process-snapshot path.
- Regression coverage: the exact read budget accepts its final candidate and
  refuses the first candidate beyond it; a 100,000-token command is matched
  without requiring a collected token vector.

### Oversized Docker output continued draining forever

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: High
- Root cause: retention stopped at 256 KiB but the worker continued reading
  until every inherited writer closed the pipe.
- Impact: bounded memory could still hide unbounded CPU, I/O, worker, and pipe
  lifetime.
- Fix: each read requests only the remaining allowance plus one sentinel byte
  and returns immediately on the first excess byte.
- Regression coverage: exact maximum is accepted; maximum plus one is refused;
  a reader that panics on a second read proves no post-overflow drain occurs.

### Docker cleanup could lose reap ownership

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: High
- Root cause: cleanup dropped a `Child` after a foreground reap deadline or
  wait error.
- Impact: repeated exceptional cleanup could accumulate live or zombie direct
  children without durable ownership accounting.
- Fix: reserve a cleanup worker before process spawn and transfer the child to it
  after timeout or failure. The worker attempts termination and owns one blocking
  wait without extending the enrichment caller's deadline. Successful reap
  releases its slot; an indeterminate wait parks while retaining the child and
  slot. Four retained workers refuse further Docker process spawn.
- Regression coverage: injected cleanup distinguishes confirmed reap from an
  indeterminate one-wait outcome without retries, worker capacity refuses the
  first excess reservation, and a controlled long-running child is handed off
  promptly and remains observably reaped at the OS boundary.

### Release installer verification stopped before the executable

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: Confirmed
- Root cause: a verified installer script downloaded a second executable archive
  whose verification could be unavailable or fail open on a runner.
- Impact: the unverified executable controls artifact construction and hosting.
- Fix: Unix and Windows jobs now download the selected cargo-dist archive
  directly, compare a platform-specific pinned SHA-256 before extraction, require
  exactly the expected executable, and execute it only after verification.
- Regression coverage: static workflow contracts pin all seven archive digests
  and assert checksum comparison precedes extraction on both script paths. The
  Linux installer was executed successfully, and a corrupted expected hash
  failed before extraction. Native Windows execution remains a release-runner
  gate.

### Homebrew validation ran with tap credentials configured

- Technical severity: Medium
- Remediation priority: Medium
- Evidence confidence: High
- Root cause: checkout persisted the tap PAT while `brew update` and `brew style`
  executed mutable tooling.
- Impact: compromised validation tooling could use the ambient tap credential.
- Fix: checkout is credential-free; the PAT is introduced through `GH_TOKEN`
  only in the final push step.
- Regression coverage: workflow contracts reject persisted credentials and prove
  the token appears after Homebrew validation and before the push only.

### Release planning exposed write authority to tool installation

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: High
- Root cause: the plan job granted `contents: write` and exported `GH_TOKEN`
  across checkout, installer execution, and planning.
- Impact: repository-controlled setup code received release-repository authority
  before any step required it.
- Fix: planning has read-only repository permission; no write-scoped token is
  exported to checkout or installation. The explicit planning token exists only
  in the verified dist step.
- Regression coverage: a workflow contract isolates the plan job and asserts its
  permission and step-level credential boundary.

### Release publication exported write authority job-wide

- Technical severity: Medium
- Remediation priority: High
- Evidence confidence: High
- Root cause: the host job exported its write-scoped `GH_TOKEN` to setup,
  checkout, artifact transfer, hosting, and release creation.
- Impact: commands and actions that did not need publication authority inherited
  it as ambient environment state.
- Fix: the explicit token environment is present only in the dist host and final
  GitHub release steps. GitHub's built-in token remains governed by job-scoped
  permission and is recorded below as residual risk.
- Regression coverage: a workflow contract rejects a host job-level token
  environment and asserts the two explicit publication boundaries.

## Follow-up Remediation

- Rollback identity is now captured immediately after every successful stop,
  including descendants that are followed by an unrelated sweep refusal. A
  targeted mutation to retain the pre-stop marker failed the regression test.
- The snapshot proving a tree or group sweep has converged is also the final
  frozen-identity snapshot. A targeted mutation that performed another snapshot
  read failed the group convergence regression test.
- Single-process confirmation text no longer wraps long metadata into additional
  rows. Decorative blank rows are removed under pressure and the actionable tail
  remains visible; removing that bound failed the minimum-height regression.
- Related-process command matching now streams tokens and uses allocation-free
  ASCII name and socket-port checks. Restoring the collected token index failed
  the early-consumption regression.
- Homebrew update and style validation now fail closed before staging. Restoring
  suppressed style failure failed the workflow contract.
- Explicit repository tokens outside the three planning or publication commands
  were removed. Global token accounting and step-indentation assertions prevent
  build, setup, Homebrew validation, or announce jobs from regaining ambient
  token environment values.
- Inspect joins socket owners, process rows, and command-line reads by PID plus
  start marker. It refuses a changed port owner and omits unverified or recycled
  socket attribution. Restoring the raw-PID report join failed its regression.
- Human watch output preserves unscoped, interface-indexed, and unavailable IPv6
  scope text. Removing an interface index failed the scoped-output regression.

Both macOS targets and both Windows targets compile the platform-specific
identity changes; native runtime behavior remains a release-runner gate.

## Unsafe And Assertion Review

Every production unsafe block in Linux, macOS, Windows, process termination,
Windows tree containment, Docker privilege detection, observation decoding, and
watch signal handling was reviewed with its caller invariants. Native buffers
validate capacity, returned byte counts, record divisibility, pointer range and
alignment before typed reads. Raw descriptors and handles transfer immediately
to RAII owners or are explicitly closed on pre-transfer failure.

No required cleanup, signal, state transition, allocation check, or validation
occurs only in an assertion. Debug assertions diagnose internal invariants only;
none is required for memory safety or input validation.

## Dependency And Workflow Review

- `socket2` resolves exactly once at `0.6.5` with only its default feature.
- The broad `socket2/all` feature is not enabled.
- `cargo tree --locked --target all -d` reports no duplicate `libc`,
  `windows-sys`, or other package version.
- `cargo deny check` passes advisories, bans, licenses, and sources.
- `cargo audit --deny warnings` scanned 225 locked packages with no applicable
  advisory or warning.
- RUSTSEC-2020-0079 does not apply to `socket2 0.6.5`.
- Active GitHub Actions remain pinned by full commit SHA.
- Cargo-dist executable archive hashes match the immutable upstream v0.32.0
  release metadata reviewed on 2026-07-23.
- No new application dependency was introduced.

## QA And Performance Evidence

QA verdict: PASS on the local Linux dist artifact. Release recommendation for
this implementation gate: proceed. No external daemon or production system was
tested.

The exact artifact completed snapshot JSON validation, legacy JSON validation,
Why's canonical endpoint matrix and immediate socket release, a bounded watch
run, closed-output behavior through the real-binary suite, and the controlled
Docker child lifecycle tests. Test-owned processes and sockets were cleaned up.

The first complete test run preserved one failure: the new hint budget scanned
low PIDs first and missed the newly created diagnostic helper. The implementation
was changed to scan highest PIDs first, the focused journey passed, and the full
suite then passed without retrying or suppressing the failure.

Benchmark verdict: directional PASS for bounded resource acceptance, not a
baseline performance claim. The measured snapshot path was not changed by the
remediation; it was exercised to detect broad artifact regressions.

- Build: `cargo build --locked --profile dist --all-features --bin kickoutchi --bin kick`
- Artifact: `target/dist/kick`
- SHA-256: `456ffe35004305494dd7d992ea00dad788e393dcbb8db1bf34cd882d86fb96f4`
- Size: 3,792,848 bytes
- Workload: `list --snapshot-json`, isolated empty config
- Samples: 30 after 3 warmups, 0 failures
- p50: 15.922 ms
- p95: 31.931 ms
- p99/max: 32.000 ms
- Peak RSS: 22,068 KiB across 10 independent runs, 0 failures
- Raw evidence: `/tmp/opencode/security-snapshot.tsv` and
  `/tmp/opencode/security-snapshot-rss.tsv`

The host load average was `4.64,2.61,1.95`; the tail was bimodal and is not used
to claim a latency improvement or regression. Peak RSS remained below the prior
same-host snapshot evidence, while binary size decreased by 5,224 bytes. These
comparisons are directional because the source state and live host workload
differ.

## Automated Verification

```text
cargo fmt --all -- --check
PASS

cargo clippy --locked --all-targets --all-features -- -D warnings
PASS

KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --offline --locked --all-features
PASS: 617 library tests, 46 real-binary CLI tests,
      5 release-workflow security tests, 4 socket lifecycle tests

cargo test --offline --locked --all-features --doc
PASS: 0 doctests, 0 failures

cargo deny check
PASS: advisories, bans, licenses, sources

cargo audit --deny warnings
PASS: 225 locked packages, no warnings

cargo check --locked --all-targets --all-features --target <installed target>
PASS: Linux aarch64, macOS aarch64/x86_64, Windows GNU/MSVC

sh .github/scripts/install-cargo-dist.sh
PASS: downloaded archive hash verified; cargo-dist 0.32.0 executed
```

Cross-target compilation validates platform-gated code and tests but does not
replace native macOS or Windows runtime execution. The release workflow itself
will be exercised on native runners by its pull-request and tag gates.

## Residual Risk Acceptance

- macOS raw-PID signals retain a few-instruction identity race. Severity:
  Medium; confidence: High; accepted because no stable pidfd-equivalent is
  available and every observable boundary fails closed.
- Private Windows Job Object freeze class semantics may change across OS
  versions. Severity: Medium; confidence: Medium; accepted with disposable
  capability preflight, exact layout checks, and withheld delivery on failure.
- Polling can miss transient sockets, successful probes lose later bind races,
  and probes briefly occupy endpoints. Severity: Low; confidence: High;
  documented product limitations.
- Linux procfs and platform scope can hide owners or entire network stacks.
  Severity: Medium; confidence: High; represented as partial/unknown evidence,
  never a false free claim.
- Synchronous kernel, filesystem, or output calls can block beyond an application
  deadline. A child wait can retain one of four cleanup workers indefinitely but
  does not block the enrichment caller. Severity: Low; confidence: High;
  concurrency, retries, and retained resources remain bounded.
- Related-process hints can omit a match outside the 64-read budget. Severity:
  Informational; confidence: High; hints are explicitly non-authoritative.
- Same-channel release checksums are not independent signatures or provenance.
  Severity: Medium supply-chain residual; confidence: High; exact release
  attestation and immutable publisher settings remain release-owner gates.
- GitHub grants `contents: write` to the whole host job rather than individual
  steps, so its full-SHA actions can access the built-in job token even where no
  `GH_TOKEN` environment value is exported. Severity: Medium supply-chain
  residual; confidence: High; accepted because publication requires write
  authority, every action is commit-pinned, checkout does not persist credentials,
  and explicit token environment exposure is limited to publishing commands.

## Gate Conclusion

- The threat model reflects the final architecture and new implementation trust
  boundaries.
- Every confirmed finding has a focused fix and regression coverage.
- No unresolved release-blocking security finding remains in scope.
- Residual risks state severity and evidence confidence and remain visible in
  user or release documentation where applicable.
