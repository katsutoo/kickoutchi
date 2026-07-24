# Release Runbook

This runbook keeps release qualification separate from publication. Completing
the pre-publication section does not authorize a tag or a public release.

## Final Candidate

Repeat this section for every candidate commit. A qualification result belongs
to one exact SHA and does not carry forward to a later commit.

1. Confirm `Cargo.toml`, `Cargo.lock`, `flake.nix`, both binary `--version`
   outputs, and the dated changelog section report the intended version.
2. Review the exact candidate diff for generated files, credentials, local
   artifacts, accidental schema changes, and package documentation drift.
3. Run formatting, strict Clippy, all tests, doctests, `cargo deny`, optimized
   dual-binary builds, and release-profile journeys locally. Clippy must also
   pass for the `cfg(windows)` and `cfg(target_os = "macos")` code, which the
   host lint never compiles: `mise run clippy-windows` and `mise run
   clippy-macos`.
4. Push the candidate commit and require native Linux, macOS, Windows, and
   Supply Chain CI to pass on that exact SHA.
5. Dispatch `Release` manually on the candidate branch immediately after its
   push. Verify the run's `headSha` equals the recorded candidate commit. Every
   manual dispatch, including one that names a tag ref, must remain
   non-publishing while building and validating the cargo-dist artifact graph.
6. Record the exact commit and both successful workflow URLs for maintainer
   review. Stop here until the maintainer explicitly approves publication.

### Qualification log

| Candidate SHA | Native CI | Non-publishing Release | Notes |
| --- | --- | --- | --- |
| `7eeb7bf` | passed | passed | Superseded: post-audit cleanup landed after it. Requalify the new head. |

## Publish After Approval

1. Tag the approved commit as `v1.3.0` and push only that tag. The tag-triggered
   Release workflow must repeat same-commit verification before publication.
2. Verify the public GitHub Release target commit, title, notes, installers,
   updater artifacts, source archive, five native binary archives, per-archive
   `.sha256` files, and release-wide `sha256.sum`.
3. Download public archives on Linux, macOS, and Windows, verify their checksums
   from the downloaded sidecars, run both binary names, and exercise the native
   release journeys. Pre-upload workflow artifacts are not substitutes for this
   public-path smoke test.
4. Confirm `nuggocto/homebrew-tap` contains the generated `1.3.0` formula with
   final public URLs and hashes, then smoke-test installation and upgrade on a
   supported Homebrew host.
5. Manually dispatch `Excavator` in `nuggocto/scoop-bucket`, wait for success,
   confirm the live manifest reports `1.3.0`, and smoke-test installation and
   update on x64 Windows.
6. Update both Arch `PKGBUILD` files from the real public `1.3.0` source and
   Linux archive checksums, regenerate both `.SRCINFO` files, and build and check
   both packages locally. Commit and push the verified metadata to this
   repository.
7. Push both packages to the AUR, then verify their public metadata and install
   both on a real Arch host from a clean cache. `kickoutchi-bin` and
   `kickoutchi` must each report the released version.
8. Update `../kickoutchi-front` from `RECAP.md` and the final changelog. Remove
   the obsolete benchmark panel and the note that AUR packages are unavailable,
   publish the `1.3.0` feature and command docs, and show package availability
   only after each live source is truthful. Run formatting, lint, Astro checks, a
   production build, and browser QA before deployment.

## Package Timing

Homebrew is pushed by Kickoutchi's tag release workflow. Scoop updates through
its independent Excavator workflow. AUR packages are pushed by hand after the
release, because their version and checksums are taken from the real published
assets. Nix and Cargo Git references resolve from the repository revision they
select. These channels therefore do not become `1.3.0` atomically, and
documentation must not claim otherwise.

Order matters for public claims: publish every package channel before the
website advertises it. The site is the surface that promises availability, so it
is deployed last.
