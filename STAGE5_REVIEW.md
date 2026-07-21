# Stage 5 Implementation Review

## Verdict

APPROVED for the exact bind-probe gate.

QA verdict: PASS for the Linux native-runtime scope and the cross-target compile
scope.

Gate recommendation: proceed to Stage 6.

Release recommendation: no recommendation; this is not the complete `1.3.0`
release candidate. The Why verdict engine, final public-output documentation,
and native macOS and Windows runtime gates remain later work.

## Scope And Candidate

- Baseline commit: `fb43938d455eb65d6d643509bc81464f5ac0080d`.
- Candidate source: dirty worktree based on the baseline commit.
- Exact probe source SHA-256:
  `d140f599885f78fe3903f2853a9b2e80b70ee70a0938a7537e7a5e62effafa78`.
- Reviewed production files: `src/probe.rs` and the module declaration in
  `src/lib.rs`.
- Reviewed contract and release records: `FEATURE.md`, `CHANGELOG.md`,
  `Cargo.toml`, `Cargo.lock`, and `tests/socket2_contract.rs`.
- Authorized targets: loopback, wildcard, and documentation-only local bind
  addresses used by the test process. No remote traffic, listening probe, data
  transfer, helper process, or destructive external target was used.

## Implementation

- `src/probe.rs` is the sole production `socket2` boundary. One call creates one
  TCP or UDP socket, applies requested options, attempts one exact bind, and
  closes the socket by owned drop before returning.
- Requests carry protocol, normalized IP address, a nonzero port, explicit IPv6
  scope, IPv6 mode, and reuse-address mode. Validation rejects zero or overflowing
  ports, IPv4 scope, missing or unavailable IPv6 scope, and IPv6-only or
  dual-stack controls on IPv4.
- IPv4-mapped IPv6 input canonicalizes before scope validation. A mapped address
  with an explicit scope is rejected because its normalized identity is IPv4.
- IPv6 socket addresses use flowinfo zero and either scope ID zero for unscoped
  endpoints or the requested nonzero interface index.
- Reuse-address is explicitly disabled unless requested. IPv6 system-default
  mode leaves `IPV6_V6ONLY` untouched; IPv6-only and dual-stack modes set it
  before bind.
- Outcomes distinguish bindable now, address in use, permission denied, address
  unavailable, unsupported family or option, and every other OS error. Results
  preserve the numeric raw OS error when supplied and retain an owned message for
  later bounded sanitization at a public rendering boundary.
- Unsupported-family and unsupported-option raw codes are recognized on Unix
  and Windows without adding local unsafe code.

## Contract Evidence

- Port validation tests cover zero, one, 65,535, and 65,536.
- Address-control tests cover IPv4 scope rejection, missing IPv6 scope,
  unavailable IPv6 scope, invalid IPv4 mode controls, and mapped-address
  canonicalization before scope validation.
- A socket-address test proves a nonzero IPv6 interface index reaches the native
  scope ID while flowinfo remains zero.
- The native IPv4 matrix covers TCP and UDP, exact loopback and wildcard
  addresses, and disabled and enabled reuse-address behavior.
- The native IPv6 matrix covers TCP and UDP, exact loopback and wildcard
  addresses, system-default, IPv6-only, and dual-stack behavior, and both
  reuse-address modes. Each case first performs an independent native capability
  attempt, then requires the application wrapper to bind when supported or to
  return the same explicit unsupported category.
- Every successful matrix probe immediately repeats the same bind. The second
  success demonstrates that the first probe retained no live socket.
- Controlled live TCP and UDP holders produce `AddressInUse` with retained raw
  OS errors and messages.
- An unassigned documentation address produces `AddressUnavailable` with its raw
  OS error.
- Error-kind and native-code tests cover address-in-use, permission-denied,
  address-unavailable, unsupported, and unknown-to-`Other` classification without
  losing raw codes.
- Existing dependency contract tests independently cover the approved
  `socket2` call surface and immediate exact-endpoint rebinding.

## Independent Review

The first independent review found one contract mismatch: mapped IPv6 targets
discarded an explicit scope after canonicalization. The implementation now
rejects that input, matching the selector contract. The review also requested a
direct assertion for interface-index propagation; the test now pins both the
native scope ID and zero flowinfo.

The follow-up review and the final uncommitted-change review reported no
actionable findings. The production wrapper exposes no raw handle, unsafe socket
address constructor, connect, listen, accept, send, receive, or ownership escape.
No new unsafe block or helper process was introduced.

A later test-quality review found that the first IPv6 matrix accepted
`Unsupported` even when the same host's direct socket2 contract proved the mode
worked. The matrix now derives support independently and would fail if the
application wrapper regressed every IPv6 request to `Unsupported`.

## Verification

Passed on Rust 1.95.0:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES=1 cargo test --locked --all-features
cargo test --locked --all-features --doc
cargo deny check
git diff --check
```

The final host suite passed 527 library tests, 28 real CLI contract tests, and
four socket lifecycle contract tests: 559 tests total, zero failures. Eleven
library tests directly exercise the exact probe boundary.

Strict cross-target Clippy passed for:

- `aarch64-unknown-linux-gnu`
- `x86_64-pc-windows-gnu`
- `x86_64-pc-windows-msvc`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

The lockfile retains exactly `socket2 0.6.5`, and the manifest keeps its empty
default feature set without enabling `all`. Supply-chain advisories, bans,
licenses, and sources pass through `cargo deny check`.

## Documentation Audit

- `CHANGELOG.md` describes exact bind diagnostics, controls, result categories,
  immediate socket closure, and the later-bind race in product-facing terms.
- No added code comment or changelog text uses implementation stage or phase
  terminology.
- Existing `stage` identifiers and comments under `src/app.rs`, `src/tree.rs`,
  and `src/ui/confirm.rs` describe the user-visible multi-step confirmation state;
  they predate and are unrelated to this implementation.
- `FEATURE.md` remains the internal planning document and records the completed
  exact bind-probe gate there.

## Residual Risk

- Native macOS and Windows bind behavior is compile-checked here but must run in
  exact-commit CI.
- Ephemeral-port tests necessarily have a small bind-release-rebind race with
  unrelated local processes. The test performs the probe immediately and does
  not hide an `AddressInUse` result with retries.
- The unavailable-address test requires at least one RFC 5737 documentation
  address to remain unassigned on the test host.
- A successful probe proves bindability only at probe completion. It neither
  reserves the endpoint nor promises that a later process wins the bind race.
