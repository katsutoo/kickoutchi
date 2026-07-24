# Stage 11 Exploratory QA Review

Date: 2026-07-24

## Verdict

QA verdict: PASS.

Release recommendation from this gate: `ship`.

The complete bounded exploratory matrix passed against the exact candidate
artifacts on five native targets. Benchmarking may proceed without changing the
candidate identity.

## Candidate And Evidence Identity

- Candidate source commit:
  `7393b56a5d86a5e2afb298cf6d1eb185a77bf02a`.
- Candidate Release run:
  https://github.com/nuggocto/kickoutchi/actions/runs/30046834702
- Qualification harness commit:
  `f5c6ad590eddc33b36d5c17c41f777e697a427b9`.
- Passing qualification run:
  https://github.com/nuggocto/kickoutchi/actions/runs/30057691151
- Earlier incomplete/failing runs `30052379065`, `30057283200`, and
  `30057577754` remain preserved and are not cited as passing evidence.

The workflow had read-only repository and Actions permissions, persisted no
checkout credentials, and downloaded the immutable candidate run by explicit
run ID. The qualification-only commits do not alter the candidate executables.
Every report verifies the candidate and v1.2.0 baseline executable hashes.

## Native Artifacts

| Native target | Archive SHA-256 | `kickoutchi` SHA-256 | `kick` SHA-256 |
| --- | --- | --- | --- |
| Linux x86_64 | `9a43d95b311f0b6c62a66275ca4d1e2c00be5c7e52b99ebe9f4c5c7cbdef8c71` | `f50ba902e7ac624f01f2ee3e9f27a462a5e250474075039bc729def0f096a03c` | `847fcf0ab12648cd0ccd3b2f30870e26a3b263b69956c5a2206d6f9c8a159855` |
| Linux ARM64 | `52ccbd920ef4a0de4b5eec7c521146741716e9338db0478895ad5a01d5fd1862` | `ec3ffecfe3f431957a3ea2fc8ffbe8704a61a5c7845f6923146752657a9235dc` | `aabbfafa7054da8f16536062fd449219fe88462987bb7b2ace785c73085034c2` |
| macOS x86_64 | `60e4adf470676656e658ee9bb8b172edcabf602477919a3f7cd0f5c3d7eede15` | `5fa09ac6de7e9ec0de521dbf9c8442232263a90690034f803cce1c4d7acf096b` | `5407bd94f646e71972008b11246c55ce0d34fbcdf3ec53ea983d16e2a4225774` |
| macOS ARM64 | `b2570c73f94b9114ad875abad6efed37d4ff70507ce6b177d5e4efdc8d5f12da` | `7b89f7d7ee71298259032d18514f05d18ff5d0bf449fbd2fabf9f9e17dc0228c` | `54177695affffec2a0d2f06c9d339c5138bd39973980c8d64be3a5ceef9ec72c` |
| Windows x86_64 | `e31eb5709a7f7385f18306b92cec6c47a7341e75558f4dea74875dfdf3874f15` | `4e2cc692d2e5a828e51aa6d5b10ce05ff79af9de39173e19c5e7d8ff7b7d774b` | `431a4bec837e32f4daf7f206286e007072f4373c5a9636ab81a97c1930df897d` |

All ten base and extended reports recorded `overall: PASS`. The reports preserve
exact commands, bounded stream byte counts and digests, environment metadata,
and cleanup results while redacting private stream contents.

## Coverage

The native charters established:

- canonical and short-binary parity, legacy list compatibility, structured
  snapshot privacy, inspect, and safe test-owned termination;
- exact and wildcard labels in list and TUI presentation/search;
- v1.2.0-to-v1.3.0 upgrades with absent and existing configuration;
- bindable and occupied TCP/UDP, IPv4/IPv6, loopback, and wildcard Why matrices;
- watch baseline, bind, release, replacement, bounded duration, Ctrl-C, finite
  memory trend, transient recovery, and three-failure exhaustion;
- malformed, empty, legal-maximum, and maximum-plus-one public inputs;
- protected-process refusal and safe PID, tree, and process-group termination;
- real permission-limited process metadata, isolated network namespaces,
  hash-pinned Docker isolation, and an actual Windows WSL capability probe;
- early-closing JSON/NDJSON consumers and complete helper/resource cleanup.

Windows TUI evidence used ConPTY through hash-pinned `pywinpty 3.0.5`. It proved
alternate-screen entry/exit, label rendering, applied search, status 0, bounded
12,150-byte terminal output with SHA-256
`a161d58870dd00da90f943427e2e03a1f18cd33561ec693c335c380c98baead2`,
and verified process cleanup.

## Platform Limits And Residual Risk

- macOS retained its exact fail-closed `partial_socket_set` watch behavior and
  process-first port-kill refusal. Tree and process-group termination still
  passed against owned fixtures.
- Windows retained `wsl_network_stack_excluded`. The hosted machine's actual WSL
  status/list probes were recorded, without claiming execution inside WSL.
- Windows correctly suppressed replacement certainty when global ownership was
  partial; Linux exact artifacts proved replacement under complete ownership.
- GitHub Linux denied direct unprivileged namespace creation. The failed attempt
  was preserved and the charter used a second hash-pinned Docker network
  namespace rather than claiming host namespace access.
- Hosted runners cannot represent every local policy, container topology,
  permission model, thermal condition, or short-lived race. Product output
  reports those boundaries rather than asserting machine-wide certainty.

Every harness-owned process, socket, container, pseudo-console, and temporary
tree was closed or reaped. No timeout, oversized stream, failed cleanup, or
privacy-marker disclosure occurred in the passing run.

## Formal Gate Status

- [x] QA tested the complete required matrix against exact Linux, macOS, and Windows artifacts.
- [x] QA verdict is PASS.
- [x] QA release recommendation is `ship`.
- [x] Cleanup and residual risk are complete for the full matrix.

The corresponding `FEATURE.md` gate may be closed. Release benchmarking is the
next gate.
