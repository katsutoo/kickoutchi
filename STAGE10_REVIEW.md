# Stage 10 Native Continuous Integration Review

Date: 2026-07-23

## Verdict

Implementation verdict: PASS.

Gate verdict: PASS. Exact-commit GitHub Actions evidence proves the Linux,
macOS, Windows, supply-chain, and five cargo-dist artifact matrices. Stage 11
may begin.

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
- Verified candidate commit: `59bb4fd76e9b00c0425658865d6ad59d93b52578`.
- The gate-completion commit changes only this review record and the `FEATURE.md`
  checkboxes; it receives the same full workflows before Stage 11 begins.

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
- a synchronized watch baseline followed by a real socket release event, or the
  exact fail-closed partial-socket-set result on a capability-limited macOS host;
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

These values are local smoke evidence only. The GitHub identities below are the
authoritative native gate evidence; neither set is a release or performance
claim.

## GitHub Actions Gate Evidence

- Candidate commit: `59bb4fd76e9b00c0425658865d6ad59d93b52578`.
- Native CI: https://github.com/nuggocto/kickoutchi/actions/runs/30042603082
- Non-publishing release validation:
  https://github.com/nuggocto/kickoutchi/actions/runs/30042624287
- Native CI conclusion: Linux, macOS, Windows, and Supply Chain passed.
- Release conclusion: four exact-commit verification jobs, five local artifact
  jobs, and global artifact assembly passed. Publication jobs were skipped by
  the workflow's tag-only publication policy; no release was created.

Validated native archives:

| Target | Archive bytes | SHA-256 |
| --- | ---: | --- |
| `aarch64-apple-darwin` | 1,077,036 | `ca18ad23cdfc26e21896b3567c8c141abbe8c7434945f720da237d9152624e26` |
| `x86_64-apple-darwin` | 1,167,560 | `96e36c4d711cdc366d51a8ebf81c2bb48aaeae217eb1f1105b408fab3843f002` |
| `aarch64-unknown-linux-gnu` | 1,113,688 | `9d7d5e2a5579254aa6294a97894cfd5c788d91aa410f5cecb8824ab4d2bf17c5` |
| `x86_64-unknown-linux-gnu` | 1,261,188 | `bf97f2a9323fd460af8a9f053f7bc3b6a1dc47f3bdcabb0ba8cbd22e3850c133` |
| `x86_64-pc-windows-msvc` | 2,762,631 | `9b43d247bd8ec2fa6a5fbc0da4311dbe208c272ac74379d2d4dbe7ad570e8cc0` |

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

- [x] Linux native matrix passes on the exact committed candidate.
- [x] macOS native matrix passes on the exact committed candidate.
- [x] Windows native matrix passes on the exact committed candidate.
- [x] Both release binaries build in every cargo-dist target job.
- [x] No platform test is skipped merely to make the matrix green.
- [x] Native automated journeys pass against every exact cargo-dist archive.

The corresponding `FEATURE.md` gate is complete.

## Required Follow-up

Begin Stage 11 against the recorded candidate artifacts. Preserve these run and
archive identities as the Stage 10 handoff; Stage 11 remains exploratory QA and
must not be treated as a release recommendation by itself.
