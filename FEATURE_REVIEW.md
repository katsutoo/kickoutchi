# Feature Contract and Dependency Review

## Status

The implementation contract is approved on 2026-07-18. The semantic, schema, platform-source,
threat-model, resource-bound, test-plan, dependency, native-platform, and
supply-chain gates are complete. Observation-foundation implementation may begin.

The review baseline was commit `80271fc` on branch `shrek`. The review worktree
contains the intentional contract-review changes, so artifact hashes below identify the
measured files more precisely than a dirty-worktree commit ID would.

## Frozen Decisions

- The authoritative model is one bounded `NetworkSnapshot`; legacy rows borrow
  from it and never use a second collector.
- Endpoint identity includes a three-state IPv6 scope. Linux's selected procfs
  source marks every IPv6 scope unavailable; macOS and Windows retain native
  interface indexes.
- A raced result retains pass B of the second complete attempt as non-authoritative
  evidence and cannot produce event or bindability claims.
- Snapshot and owner completeness have total derivation rules.
- Native socket tokens are opaque association and ordering values. They never
  prove cross-capture identity or replacement.
- Replacement is limited to deterministic exact-one buckets with complete,
  single verified owners. Shared and incomplete owner sets are never paired.
- macOS scope explicitly means process-visible libproc sockets, not a global PCB
  snapshot.
- Windows optional metadata will move from unbounded `sysinfo` allocation to the
  bounded native sources named in `FEATURE.md`.
- Why maps each endpoint first and aggregates with fixed `1 > 4 > 3 > 0`
  precedence.
- Every new schema has an in-band version; the legacy list array remains the
  documented `kickoutchi.list/1` exception.
- Every shared and inherited bound has an explicit zero/below-minimum, exact
  maximum, and maximum-plus-one test plan.

## Threat Model Review

The threat table in `FEATURE.md` covers the relevant local attacker controlling config,
arguments, process metadata, socket churn, and output consumption. The frozen
controls require bounded reads and allocations before retention, checked native
arithmetic, typed process identity, two-pass consistency, explicit scope and
permission gaps, terminal-sink sanitization, streaming structured output,
identity-safe signal delivery, sequential RAII probes, and no shell or implicit
privilege transition.

The current single-process path's unknown-name protection gap is not accepted as
future behavior. The observation migration requires a fresh bounded protection-critical name and
start-identity read before every delivery; unavailable evidence refuses rather
than meaning "not protected."

Accepted residual risks remain polling blind spots, the post-probe bind race,
platform/version differences, scope exclusions, synchronous native/output calls
that the application cannot portably deadline, and the final macOS identity-read
to signal interval.

## socket2 Acceptance

Candidate:

- Exact package: `socket2 0.6.5`.
- Registry checksum:
  `c3d1e2c7f27f8d4cb10542a02c49005dbd6e93095799d6f3be745fae9f8fedd4`.
- License: `MIT OR Apache-2.0`, allowed by `deny.toml`.
- Declared MSRV: Rust 1.70; repository toolchain: Rust 1.95.0.
- Features: only the empty default set; `all` is not enabled.
- Build script: none.
- Lockfile growth: one package and one root dependency edge; no new transitive
  packages.
- Dependency unification: existing `libc 0.2.186` and `windows-sys 0.61.2` are
  reused; `cargo tree --target all -d` reports no duplicate versions.
- `cargo-deny 0.19.4`: advisories, bans, licenses, and sources all pass.
- `cargo fetch --locked` succeeds, validating the registry checksum through
  Cargo's normal package-integrity path.

Reviewed safe call surface:

- `Socket::new`.
- Safe `SocketAddr` to `SockAddr` conversion.
- `set_reuse_address`.
- `set_only_v6` for IPv6.
- `bind`.
- `local_addr` in dependency contract tests only.
- Owned drop.

The production wrapper will not expose raw handles, unsafe `SockAddr`
constructors, connect, listen, accept, send, receive, or ownership-escaping
conversion. The upstream Windows vectored-send safety FIXME is outside this call
graph. The wrapper is implemented with the exact bind probes, not provisionally
during contract review.

`tests/socket2_contract.rs` verifies TCP and UDP, IPv4 and IPv6 loopback,
wildcards, default controls, reuse enabled/disabled, IPv6-only and dual-stack
configuration, immediate owned drop, and rebinding the same assigned endpoint.

## Binary-Size Acceptance

Environment: Linux x86_64, kernel `7.1.3-arch1-2`, Rust 1.95.0, release profile
with thin LTO inherited from the repository's dist profile only when dist is
selected. The command used for these values was:

```text
cargo build --locked --release --all-features --bin kickoutchi --bin kick
```

| Binary | Baseline bytes | Representative linked bytes | Delta | Delta % |
| --- | ---: | ---: | ---: | ---: |
| `kick` | 3,043,640 | 3,045,664 | +2,024 | +0.067% |
| `kickoutchi` | 3,043,648 | 3,045,680 | +2,032 | +0.067% |

The linked measurement temporarily called the approved create, reuse-address,
bind, and owned-drop surface behind an environment gate so linker elimination
could not hide dependency cost. The temporary harness was removed after the
measurement. With the dependency present but unused, the rebuilt binaries were
3,043,488 and 3,043,504 bytes respectively, confirming that manifest-only size
is not representative. The approximately 2 KiB linked increase is accepted.

Baseline SHA-256:

```text
4a027ba377615841d17096ec5b1b602fac48c6c7ab6d92f6af3d794b30f0bd23  kick
b1e7b7ace0f28a4e6ff8869dacf3e9405ea33fce86d32d9420f830dd92ae7475  kickoutchi
```

Representative linked SHA-256:

```text
dc1471a89f864b2832db95541e2267e07f2cc43e514d3b244f7b3a3c70f637b9  kick
7e576faf4a15b3905a25b2895013cd1873b7a363991d64de626263bc45968897  kickoutchi
```

This is the dependency-acceptance size check, not the deferred release benchmark.

## Verification Evidence

Passed locally:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --all-targets --all-features -- -D warnings`.
- `cargo test --locked --all-features`: 307 unit tests, 19 Linux real-binary
  integration tests, and four dependency contract tests.
- `cargo test --locked --all-features --doc`.
- `cargo test --locked --test socket2_contract`: four tests.
- `cargo build --locked --release --all-features --bin kickoutchi --bin kick`.
- `cargo deny check`.
- `mise run clippy-windows`.
- `mise run check-macos` for x86_64 and aarch64 Darwin.
- `mise run clippy-macos` for x86_64 and aarch64 Darwin.

Native CI evidence for the reviewed dependency and contract tests:

- Run: <https://github.com/nuggocto/kickoutchi/actions/runs/29650821097>.
- Linux: passed formatting, Clippy, and all tests.
- macOS: passed formatting, Clippy, and all tests.
- Windows: passed formatting, Clippy, and all tests.
- Supply chain: passed `cargo deny check`.

## Gate Decision

Every prerequisite contract gate is closed. The repository is authorized to
begin the observation foundation; no semantic, architectural, dependency,
security, test-plan, or native-platform decision remains deferred.
