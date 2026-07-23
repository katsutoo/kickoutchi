# Stage 11 Exploratory QA Review

Date: 2026-07-24

## Verdict

QA verdict: BLOCKED.

Release recommendation from this gate: `hold`.

The exact artifacts passed twelve bounded native charters on all five targets,
but those charters do not cover the complete mandatory exploratory matrix. The
passing run is retained as partial evidence and is not promoted to a gate pass.

## Candidate And Harness Identity

- Candidate source commit:
  `7393b56a5d86a5e2afb298cf6d1eb185a77bf02a`.
- Candidate Release run:
  https://github.com/nuggocto/kickoutchi/actions/runs/30046834702
- Qualification harness commit:
  `4fa553c8fcb55d7c3387be8db704b5446660150a`.
- Passing qualification run:
  https://github.com/nuggocto/kickoutchi/actions/runs/30052379065
- The harness checkout was clean on every target.
- The workflow used read-only repository and Actions permissions, did not use
  persisted checkout credentials, and downloaded the immutable candidate run by
  explicit run ID.

The qualification harness was added after the candidate was built. Its separate
commit does not alter the candidate archives or executables; every report binds
the executed binaries to the candidate commit, archive checksum, and executable
checksums.

## Native Artifact Evidence

| Native target | Archive SHA-256 | `kickoutchi` SHA-256 | `kick` SHA-256 |
| --- | --- | --- | --- |
| Linux x86_64 | `9a43d95b311f0b6c62a66275ca4d1e2c00be5c7e52b99ebe9f4c5c7cbdef8c71` | `f50ba902e7ac624f01f2ee3e9f27a462a5e250474075039bc729def0f096a03c` | `847fcf0ab12648cd0ccd3b2f30870e26a3b263b69956c5a2206d6f9c8a159855` |
| Linux ARM64 | `52ccbd920ef4a0de4b5eec7c521146741716e9338db0478895ad5a01d5fd1862` | `ec3ffecfe3f431957a3ea2fc8ffbe8704a61a5c7845f6923146752657a9235dc` | `aabbfafa7054da8f16536062fd449219fe88462987bb7b2ace785c73085034c2` |
| macOS x86_64 | `60e4adf470676656e658ee9bb8b172edcabf602477919a3f7cd0f5c3d7eede15` | `5fa09ac6de7e9ec0de521dbf9c8442232263a90690034f803cce1c4d7acf096b` | `5407bd94f646e71972008b11246c55ce0d34fbcdf3ec53ea983d16e2a4225774` |
| macOS ARM64 | `b2570c73f94b9114ad875abad6efed37d4ff70507ce6b177d5e4efdc8d5f12da` | `7b89f7d7ee71298259032d18514f05d18ff5d0bf449fbd2fabf9f9e17dc0228c` | `54177695affffec2a0d2f06c9d339c5138bd39973980c8d64be3a5ceef9ec72c` |
| Windows x86_64 | `e31eb5709a7f7385f18306b92cec6c47a7341e75558f4dea74875dfdf3874f15` | `4e2cc692d2e5a828e51aa6d5b10ce05ff79af9de39173e19c5e7d8ff7b7d774b` | `431a4bec837e32f4daf7f206286e007072f4373c5a9636ab81a97c1930df897d` |

All five native reports recorded `overall: PASS`, no first failure, and twelve
unique passing charters. That report verdict describes the implemented harness,
not the broader gate in `FEATURE.md`.

## Evidence Collected

The bounded user-level harness exercised:

- canonical and short-binary version parity;
- no-label table output and the legacy JSON array;
- exact and wildcard labels in list and search;
- snapshot schema, labels, and privacy;
- TCP and UDP IPv4-loopback Why schema, labels, and privacy;
- bounded watch duration, baseline NDJSON, labels, and privacy;
- short-binary functional parity;
- configuration and filter boundaries;
- early-closing JSON and NDJSON consumers;
- read-only inspect behavior;
- a safe test-owned kill with verified process cleanup;
- native TUI alternate-screen startup and restoration.

Every product invocation had a deadline and bounded output capture. The harness
used isolated home, configuration, and temporary directories. It retained exact
commands and stream metadata while redacting stream contents and the unique
privacy marker. No privacy marker occurred in the published evidence.

The legacy list JSON compatibility interface still exposes its documented
command-line field. Each report identifies the two affected legacy rows and does
not misrepresent that compatibility exception as new structured-output privacy.

## Windows TUI Evidence

Windows used the native ConPTY backend through hash-pinned `pywinpty 3.0.5`.
The evidence binds to canonical executable SHA-256
`4e2cc692d2e5a828e51aa6d5b10ce05ff79af9de39173e19c5e7d8ff7b7d774b`
and records:

- alternate-screen entry: true;
- alternate-screen exit: true;
- process exit status: 0;
- timeout: false;
- oversized output: false;
- combined terminal output: 3,722 bytes, SHA-256
  `a63ca309dac16623d0fd8bb1f6138f729bef4de75500298dd77b160455a952ca`.

ConPTY exposes one combined terminal stream, so the retained report's legacy
`stdout` and `stderr` field names must not be interpreted as independently
captured process handles.

This replaced the initial WinPTY approach after preserved failures proved that
the hosted PowerShell runner supplied no terminal dimensions. The first failure
was not retried unchanged or hidden.

## Missing Mandatory Coverage

The native run did not establish all required user-level behavior. In
particular, it did not independently exercise:

- upgrade from the previous release with existing and absent configuration;
- watch bind, release, replacement, transient failure, recovery, three-failure
  exhaustion, no-duration memory behavior, and Ctrl-C as exploratory journeys;
- the complete TCP/UDP, IPv4/IPv6, wildcard, and dual-stack Why matrix under
  controlled occupied and bindable states;
- real permission-denied and partial-metadata environments on every applicable
  platform;
- actual Docker, WSL, and isolated namespace environments rather than only the
  documented limitation text;
- malformed, empty, legal maximum, and maximum-plus-one user inputs;
- protected-process confirmation and tree/group kill regressions.

Prior automated suites cover many of these behaviors, but this gate explicitly
requires exploratory user-level coverage and cannot pass by referring back to
the automated gate.

## Platform Limits And Cleanup

- Both macOS hosts reported the exact fail-closed `partial_socket_set`
  limitation during watch collection. No partial baseline was accepted.
- Linux and Windows reported no qualification-harness platform limitation.
- The retained run reports successful cleanup for every helper and socket. No timeout,
  oversized stream, failed reap, dirty worktree, or residual test resource was
  reported.
- Docker, WSL, namespace, process-visibility, bind-race, and polling limitations
  were checked through their user-visible contracts without accessing production
  or third-party systems.

Residual risk remains that hosted runners cannot reproduce every local policy,
container topology, WSL network stack, permission model, or short-lived socket
race. The product reports those boundaries rather than claiming machine-wide
certainty. The macOS process-first limitation remains an accepted known platform
constraint.

## Preserved Failure History

Qualification runs `30050990781`, `30051209003`, `30051346961`,
`30051485961`, `30051615417`, `30051752121`, and `30052095190` preserve the
progression from harness defects and missing Windows pseudo-console evidence to
the final native ConPTY solution. None is cited as passing evidence.

## Formal Gate Status

- [ ] QA tested the complete required matrix against exact Linux, macOS, and Windows artifacts.
- [ ] QA verdict is PASS.
- [ ] QA release recommendation is `ship`.
- [ ] Cleanup and residual risk are complete for the full matrix.

The corresponding `FEATURE.md` gate remains open.

## Required Follow-up

Extend the exploratory harness or conduct equivalent bounded manual charters for
the missing matrix, rerun all native targets against the same artifact identity,
and retain a new report. Benchmarking remains gated on a complete QA pass.
