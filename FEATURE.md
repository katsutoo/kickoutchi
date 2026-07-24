# Do Before Release 1.3.0

Kickoutchi 1.3.0 ships named endpoints, full native snapshots, `watch`, and
`why`. Keep this checklist short and tied to the release commit.

## Release Blockers

- [x] Treat Windows TCP owner PID `0` as unavailable ownership, never as a real
  process identity.
- [x] Make owner-dependent watch filters indeterminate when a global ownership
  gap could hide a matching owner.
- [x] Keep E2E cleanup tied to the process identity instead of signalling a
  possibly reused numeric PID.
- [x] Ensure the active-spawner E2E test cannot pass after its fixture settles.
- [x] Detect a config file's maximum-plus-one byte without retaining that byte.
- [x] Remove the one-off Stage review, qualification, QA, and benchmark
  infrastructure from the repository and release workflows.

## Local Verification

- [x] `cargo fmt --all --check`
- [x] `cargo clippy --locked --all-targets --all-features -- -D warnings`
- [x] `cargo test --locked --all-features`
- [x] `cargo test --locked --all-features --doc`
- [x] `cargo deny check`
- [x] `cargo build --locked --release --all-features --bin kickoutchi --bin kick`

Do not add or run a release benchmark for this checklist.

## Native Release Checks

- [ ] Linux, macOS, and Windows CI pass on the exact release commit.
- [ ] Real-binary CLI journeys pass against release-profile binaries on all
  three supported operating systems.
- [ ] A manual `Release` workflow dispatch builds all cargo-dist artifacts
  without publishing.
- [ ] Installer, archive, Homebrew, Scoop, Nix, and Arch documentation still
  matches the generated release assets.

## Publish

- [ ] Confirm `Cargo.toml`, `Cargo.lock`, help output, and changelog all report
  version `1.3.0`.
- [ ] Review the final diff for generated files, secrets, local artifacts, and
  accidental API or schema changes.
- [ ] Tag the verified commit as `v1.3.0` and let the release workflow publish.
- [ ] Smoke-test one published archive on each supported operating system.
