# Stage 10 Native Continuous Integration Review

Date: 2026-07-23

## Verdict

Implementation verdict: PASS on the reviewed Linux worktree.

Gate verdict: PENDING NATIVE CI. The implementation is not committed or pushed,
so no exact-commit GitHub Actions run yet proves the Linux, macOS, Windows, and
cargo-dist artifact matrices. Stage 11 must remain on hold until that run passes
and this record is updated with its commit SHA, run URL, native job results, and
artifact identities.

The package is now the unpublished `1.3.0` release candidate. This is not a
release recommendation.

## Reviewed Scope

- Candidate metadata in `Cargo.toml`, `Cargo.lock`, and `flake.nix`.
- Native policy in `mise.toml`, `.github/workflows/ci.yml`, and
  `.github/workflows/release.yml`.
- Exact-archive validation in
  `.github/scripts/validate-release-artifact.py` and its executable boundary
  tests.
- Runtime product-binary selection and native real-binary journeys in
  `tests/cli_contract.rs`.
- Mutation-sensitive workflow controls in
  `tests/release_security_contract.rs`.
- `FEATURE.md` and `CHANGELOG.md` consistency.

The Arch and Scoop package seeds intentionally remain on the latest published
`1.2.0` assets. Their repository documentation requires real `1.3.0` release
URLs and checksums before they are updated.

## Implementation Evidence

### Candidate identity

- Package version: `1.3.0`.
- Pinned Rust toolchain: `1.95.0`.
- Reviewed base commit: `a808279ffc9a11bf6ae81191fd9d0b883e33fdfe`.
- Source state: uncommitted implementation patch; therefore local artifacts are
  verification evidence, not final release evidence.

### Native policy

Every Linux, macOS, and Windows CI job now runs:

```text
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo build --locked --release --all-features --bin kickoutchi --bin kick
cargo test --locked --all-features --test cli_contract
```

The final command receives explicit release-profile paths and requires both
paths as one all-or-nothing mode. Linux requires its declared native
capabilities in both test passes. The platform-independent cargo-deny policy and
archive-validator tests run in the same-commit supply-chain job.

The release workflow repeats the exact-commit native verification before
building cargo-dist payloads. Every cargo-dist matrix member must match its
runner's native target. Before upload, the validator:

- verifies the archive's bounded, single-record SHA-256 sidecar;
- rejects mismatched runner targets, traversal, links, devices, encrypted ZIP
  entries, duplicate or unexpected members, excess member count, and excess
  expanded size;
- requires the exact cargo-dist directory layout on Unix and flat layout on
  Windows;
- requires exactly one `kickoutchi` and one `kick` executable;
- confirms both executables report the Cargo package version;
- runs the complete platform-compiled real-binary contract suite against the
  extracted payload paths.

The write-capable publication job requires successful local and global artifact
jobs. Generic skipped artifact states are not accepted.

### Real-binary coverage

Linux retains its full collector, process identity, socket state, probe, label,
watch, Why, inspect, and test-owned termination journeys.

The shared macOS and Windows journey now additionally proves:

- exact label precedence over a wildcard selector;
- label filtering through canonical and short release binaries;
- labeled native Why output;
- a synchronized watch baseline followed by a real socket release event;
- bounded process/output collection and cleanup.

Existing native macOS and Windows tests continue to cover collector output,
TCP/UDP probes, IPv6 capability results, inspect, and safe test-owned single,
tree, and group termination where supported.

## Local Verification

Passed on x86_64 Linux:

- Formatting and host strict Clippy.
- 639 library tests.
- 62 real-binary tests against the validated cargo-dist archive after the review
  remediations.
- Ten release-security contract tests.
- Four socket lifecycle contract tests.
- Documentation tests, with zero doctest cases currently defined.
- `cargo deny check`.
- `cargo audit --no-fetch --deny warnings`.
- `cargo tree --locked --target all -d`, with no duplicate tree to print.
- Strict Clippy for Linux ARM64, Windows GNU, Windows MSVC, macOS x86_64, and
  macOS ARM64 target bodies.
- Eleven executable archive-validator tests covering target lists, raw archive
  path spelling, traversal, checksum association, exact Unix and Windows
  layouts, links, count limits, and complete validation orchestration.
- Ordinary release-profile `kick`: 3,883,000 bytes, SHA-256
  `8fe48da64c142fb0a25917f96825aacfeb2a82e36ab3e54a5f3daa8131dea146`.
- Ordinary release-profile `kickoutchi`: 3,883,008 bytes, SHA-256
  `ae88a1078a5d4e15364a27e287da82fe755436f016092b3373b242343888945b`.

Local cargo-dist x86_64 Linux archive evidence from the final review worktree:

- Archive: `kickoutchi-x86_64-unknown-linux-gnu.tar.xz`.
- Size: 1,259,828 bytes.
- SHA-256:
  `128193d2ed450cfc84c4e96f4e50102a85488d9e68c0b36cc9c9dc6e5c37388c`.
- Both extracted binaries reported `kickoutchi 1.3.0`.
- All 62 current Linux real-binary journeys passed against the extracted
  archive payloads with required Linux capabilities.

These values are local smoke evidence only. They must not be used as final
release or performance claims because the source patch is uncommitted and the
final native workflow has not run.

## Review Findings And Remediation

The first exact-release run found that the short executable intentionally
reports the canonical package name. The new validator initially expected the
short filename and failed. It was corrected to preserve the existing public
version contract, then the complete exact-artifact suite passed.

Cross-target review then found and corrected:

- a target-specific unused short-binary resolver;
- release overrides that could be activated partially or accidentally;
- a portable watch check that proved only its baseline rather than a later
  poll;
- artifact matrix mismatches that could report build-only success;
- basename-only extraction that could hide a broken archive layout;
- eager tar member allocation and missing expanded-size accounting;
- executable permissions that were repaired after extraction instead of
  validated as shipped;
- duplicate archive directories and multi-target matrix entries that could hide
  an unexecuted payload;
- weak checksum filename association;
- publication conditions that accepted skipped artifact jobs;
- unbounded child-process output collection at the artifact trust boundary;
- release workflow contracts that accepted command substrings rather than exact
  active commands and conditions;
- missing executable tests and workflow mutations for the new controls.

A final independent review found and corrected seven additional gaps:

- the portable native journey asserted a nonexistent JSON field instead of the
  canonical `local_port` field;
- the release build step relied on the runner's default shell even though its
  tag propagation uses Bash syntax;
- native CI jobs could run without first passing the same-commit supply-chain
  gate;
- archive validation normalized malformed backslashes, repeated separators,
  dot components, and file trailing slashes before checking them;
- the archive validator's complete checksum, version, binary-selection,
  environment, timeout, and Cargo-test orchestration lacked direct tests;
- workflow mutation contracts did not pin the Rust version, exact native
  dependencies, release matrix, artifact dependencies, or Bash tag propagation;
- the review provenance named the parent revision, and disposable Python,
  benchmark, package, and stale-worktree artifacts remained locally.

The fixes are covered by the ten release-security contracts and eleven Python
validator tests. Generated caches and unreferenced outputs were removed while
tracked benchmark evidence cited by prior stage reviews was retained.

No unresolved code-level or workflow-level release blocker is known in the
locally reviewed patch. Native runtime execution remains required evidence, not
an inferred result from cross-compilation.

## Formal Gate Status

- [ ] Linux native matrix passes on the exact committed candidate.
- [ ] macOS native matrix passes on the exact committed candidate.
- [ ] Windows native matrix passes on the exact committed candidate.
- [ ] Both release binaries build in every cargo-dist target job.
- [ ] No platform test is skipped merely to make the matrix green.
- [ ] Native automated journeys pass against every exact cargo-dist archive.

The corresponding `FEATURE.md` gate remains unchecked until these items have
GitHub Actions evidence from the exact commit.

## Required Follow-up

1. Commit the complete patch without changing the candidate source.
2. Push it and monitor both the native CI workflow and cargo-dist pull-request
   workflow.
3. Preserve the first failure if any job is intermittent; do not rerun until
   green without diagnosis.
4. Fix every verified failure and repeat all affected checks on the new commit.
5. Record the final commit, workflow URLs, native job results, archive names,
   sizes, and SHA-256 values here.
6. Check the `FEATURE.md` gate only after every required native result is green.

Stage 11 is ready to begin only after that follow-up changes this gate verdict
from PENDING NATIVE CI to PASS.
