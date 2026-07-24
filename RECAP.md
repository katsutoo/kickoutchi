# Kickoutchi 1.3.0 Recap

This is the product-facing recap for updating the Kickoutchi landing page. It
summarizes the completed work from the previous feature plan and the current
`[Unreleased]` changelog section.

Status: implemented locally for the unreleased `1.3.0` release. Native CI,
artifact generation, publication, and published-archive smoke tests remain
release-time checks.

## Short Landing-Page Summary

Kickoutchi 1.3.0 adds names, history, and explanations to local ports:

- Name expected TCP and UDP endpoints with validated labels.
- Export a complete, versioned native socket snapshot.
- Watch sockets bind, release, or change owners in real time.
- Ask why an exact endpoint is or is not bindable right now.
- Filter by address, family, scope, state, label, owner, and process metadata.
- Keep destructive actions tied to verified process identity and explicit
  evidence rather than PID guesses.

The existing TUI, `kick list`, `kick kill`, and `kick inspect` workflows remain
available. The new features share the same native observation model on Linux,
macOS, and Windows.

## Suggested Feature Cards

### Name Your Ports

Add labels such as `web dev`, `postgres`, or `mDNS` to exact endpoints or
protocol-and-port wildcard fallbacks. Exact matches win over wildcard matches.
Labels appear in the CLI, sufficiently wide TUI tables, search, filters, legacy
JSON, full snapshots, watch events, and bind diagnostics.

### Watch The Swamp

`kick watch` streams deterministic baseline, bind, release, replacement, and
collection-gap events. Use human output for a terminal session or versioned
NDJSON for tools and automations.

### Ask Why

`kick why PORT` combines one native snapshot with immediate TCP or UDP bind
probes. It distinguishes bindable endpoints, address conflicts, permission
denials, unavailable addresses, unsupported behavior, and other OS errors while
showing the evidence and certainty behind the result.

### Export The Full Picture

`kick list --snapshot-json` emits the complete bounded native socket observation
within the platform's declared scope, including full TCP states, owner identity,
process metadata, completeness, evidence gaps, scope, and configured labels.

### Safer Process Cleanup

Single-process, tree, and process-group termination revalidate ownership,
process-start identity, protection policy, and scope immediately before action.
Uncertainty refuses the kill instead of guessing.

## Endpoint Labels

Labels are configured with up to 256 `[[ports]]` selectors:

```toml
[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "tcp"
address = "*"
port = 3000
label = "web service"
```

Implemented behavior:

- TCP and UDP selectors are separate.
- Exact literal IPv4 and IPv6 addresses are supported.
- A separate nonzero `scope_id` can identify an exact IPv6 interface scope.
- `"*"` matches any address for one protocol and port.
- Exact endpoint selectors always take precedence over wildcard fallbacks.
- IPv4-mapped IPv6 addresses normalize to IPv4 before duplicate detection and
  matching.
- Hostnames, DNS, CIDR ranges, interface names, and `%zone` syntax are rejected.
- Labels must be nonempty safe visible Unicode and at most 128 UTF-8 bytes.
- Control characters, terminal escapes, bidi controls, and zero-width text are
  rejected.
- Human display clips labels to 32 terminal columns; structured output retains
  the complete validated label.

## Full Native Snapshots

The observation layer behind list, TUI, inspect, kill, watch, and why was unified
around one bounded, consistency-checked native snapshot.

The public command is:

```sh
kick list --snapshot-json
```

The `kickoutchi.snapshot/1` document includes:

- Native TCP and UDP endpoints within the declared platform scope.
- Listening, established, transitional, closed, bound, and unknown native states.
- Process owners as verified PID-plus-start-marker identities or explicit
  unverified PIDs.
- Socket-local and snapshot-global owner completeness.
- Bounded process names, executable paths, parent relationships, and metadata
  completeness.
- Platform socket tokens where the native source exposes one.
- Observation scope, permanent limitations, capture times, evidence gaps, and
  omitted counts.
- Configured endpoint labels.
- Linux TCP timer evidence with typed kind, raw ticks, and an explicitly
  estimated remaining duration when the clock rate is available.

Snapshot mode intentionally bypasses list filters, list sorting,
`hide_system_processes`, and the listening-TCP/bound-UDP legacy projection. It
does not include complete process command lines.

Collection performs bounded consistency checks across native socket rows, owner
edges, and process-start identities. A second attempt is the maximum. Unstable,
partial, denied, unavailable, and out-of-scope evidence stays explicit instead
of being converted into an empty or complete-looking result.

## Watch

Examples:

```sh
kick watch
kick watch --tcp --address 127.0.0.1 --port 3000
kick watch --filter label:web --interval 500ms
kick watch --filter state:established --duration 30s --json
```

Implemented behavior:

- Emits `baseline`, `bind`, `release`, `replacement`, and `collection_gap`.
- Supports terminal output and `kickoutchi.watch_event/1` NDJSON.
- Each NDJSON line is independently valid and bounded to 64 KiB.
- Poll intervals are `100ms..=60s`; the default is `1s`.
- Optional durations are `100ms..=7d`.
- Ctrl-C, duration expiry, and a closed stdout consumer exit successfully.
- One failed poll emits a collection gap and preserves the last valid snapshot.
- Recovery compares against that last valid snapshot, preventing fabricated
  release events.
- Three consecutive collection failures flush the third gap and exit with code
  `1`.
- Polls never overlap or build a backlog when collection is slower than the
  requested interval.
- Docker and external network tools are never invoked in the polling loop.
- Event ordering is deterministic and output is streamed in bounded batches.
- Owner-dependent filters preserve `indeterminate` when missing ownership or
  metadata could hide a match.

Watch is a polling view, not a kernel event feed. A socket can open and close
between polls, several changes can collapse into one net difference, and event
times describe capture intervals rather than exact kernel event times.

## Why

Examples:

```sh
kick why 3000
kick why 5353 --udp --address 127.0.0.1
kick why 3000 --tcp --address :: --ipv6-only --json
kick why 3000 --all-protocols --all-addresses --json
```

Implemented behavior:

- Evaluates TCP, UDP, IPv4, and IPv6 endpoints.
- Supports exact literal addresses, numeric IPv6 scope IDs, reuse-address, and
  IPv6-only or dual-stack behavior.
- The default query checks TCP on IPv4 and IPv6 loopback.
- Expanded queries can evaluate a canonical matrix of up to eight endpoints.
- Uses one native snapshot followed by sequential exact bind probes.
- Closes every probe socket immediately after recording the result.
- Reports bindability, address-in-use, permission denied, address unavailable,
  unsupported behavior, and retained OS errors.
- Reports certainty as `proven`, `estimated`, `heuristic`, or `unknown` for the
  specific claim carrying it.
- Includes ordered evidence, evidence gaps, omitted counts, labels, and an
  aggregate exit status.
- Supports human output and one versioned `kickoutchi.why/1` JSON document.
- Does not collect complete command lines or invoke Docker.
- Streams every legal bounded output shape rather than imposing the removed
  256-KiB whole-document cap.

A successful probe temporarily occupies and then releases the endpoint. It
proves only that the exact bind succeeded at that moment. It does not reserve the
endpoint or eliminate a later race.

## Filters And Search

List, TUI search, and watch now share AND-composed plain and structured filters:

```text
pid:
port:
proto:
scope:
protected:
parent:
label:
address:
scope_id:
family:
```

Watch additionally supports the complete native `state:` vocabulary:

```text
listen bound closed syn_sent syn_received established fin_wait1 fin_wait2
close_wait closing last_ack time_wait delete_tcb new_syn_received unknown
```

Additional behavior:

- Filter expressions are bounded to 256 UTF-8 bytes.
- Terms use AND semantics.
- Repeated fields also use AND semantics.
- Address matching uses parsed normalized IP addresses rather than text
  substrings.
- `family:` distinguishes normalized IPv4 and IPv6.
- Owner-dependent watch terms must be satisfied by the same conceptual owner;
  separate owners cannot each satisfy half of one expression.
- Missing owner or metadata facts can produce `indeterminate` watch matches.
- `state:` is reserved and rejected by list/TUI rather than silently treated as
  plain text.
- `why` uses exact endpoint arguments instead of the general filter language.

## Structured Output Contracts

Four machine-readable interfaces are now documented:

| Command | Contract | Form |
| --- | --- | --- |
| `kick list --json` | `kickoutchi.list/1` | JSON array |
| `kick list --snapshot-json` | `kickoutchi.snapshot/1` | One JSON object |
| `kick watch --json` | `kickoutchi.watch_event/1` | NDJSON |
| `kick why PORT --json` | `kickoutchi.why/1` | One JSON object |

Compatibility details:

- Existing `list --json` remains a top-level array.
- Its only additive 1.3.0 field is nullable `label`.
- Snapshot, watch, and why carry in-band `schema` and integer `version` fields.
- Stable field and enum names use lowercase `snake_case`.
- Diagnostics stay on stderr and do not contaminate JSON or NDJSON stdout.
- Null, empty, partial, raced, unknown, and omitted values remain distinct.
- Process identity is PID plus a Linux start tick, macOS start time, or Windows
  creation-time marker; PID alone is not treated as stable identity.

Structured output can expose endpoints, PIDs, process identities, names, paths,
labels, ownership, and evidence. Legacy `list --json` can also expose complete
bounded command lines. Escaping and terminal sanitization are not redaction.

## Termination And Safety Improvements

The existing destructive commands now consume the same authoritative snapshot
model as the new read-only commands.

Implemented safety behavior:

- Freshly recollect socket ownership before destructive action.
- Re-establish the requested PID or port target.
- Verify PID plus process-start identity.
- Reconfirm every selected endpoint still belongs to that identity.
- Reapply protected-process policy with fresh bounded process-name evidence.
- Deliver only through the platform's identity-aware path.
- Refuse ambiguous owners, ownerless destructive targets, changed identities,
  changed endpoints, missing protection evidence, unsafe PIDs, and incomplete
  target-local authority.
- Keep unprivileged `kill --port` usable when one endpoint owner is verified;
  unrelated unreadable host processes do not automatically make it root-only.
- Ignore non-listening TCP states for destructive authority while retaining them
  in full snapshots and watch.
- Poll after successful termination and report whether confirmed ports actually
  disappeared.

Linux termination uses pidfds on Linux 5.3 or newer. macOS rechecks native start
identity immediately before signalling and reports its unavoidable residual
PID-reuse window. Windows single-process termination uses process handles.

Windows tree kill now:

- Proves Job Object freeze/thaw support on an empty disposable job.
- Preflights the tree before committing the root.
- Treats root assignment as the irreversible containment boundary.
- Freezes the committed job for a final bounded validation sweep.
- Reapplies `--yes` warning authorization during committed sweeps.
- Withholds whole-job termination when a late child needs fresh review.
- Attempts thaw and verified fallback handling after post-commit failures.
- Preserves delivered, already-exited, fallback, unconfirmed, and not-terminated
  PID outcomes instead of reporting false total success.

Tree and process-group rollback now pin the identity observed immediately after
each successful stop and use one snapshot to prove convergence and final frozen
membership. A detected replacement is resumed when appropriate but never receives
the unauthorized terminating signal.

## Correctness And Hardening Delivered

- Confirmation limits apply to the entered 128-byte UTF-8 payload, not the line
  ending, and overlong input stops after the first excess byte.
- Single-process confirmation content stays within the modal while preserving
  the prompt, input, error, and cancellation lines.
- TUI kill refresh invalidates stale in-flight work and queues one authoritative
  post-kill snapshot.
- Inspect joins process, port, and command observations by PID and start identity
  and refuses attribution to a recycled PID.
- Human watch output preserves IPv6 interface scope and explicitly reports
  unavailable scope.
- Linux process identity parsing handles valid non-UTF-8 process names in
  `/proc/<pid>/stat` without losing the numeric start marker.
- Linux rejects empty, malformed, and headerless authoritative socket tables.
- Linux treats restricted or unverifiable procfs and PID namespace visibility as
  partial ownership instead of false complete emptiness.
- Linux exact-fit procfs executable links are retained even when the magic link
  reports a zero size.
- macOS process enumeration distinguishes a genuine empty result from an API
  failure and treats descriptor-enumeration loss as socket-set loss.
- macOS enforces aggregate descriptor limits before allocation and rejects native
  lengths beyond supplied buffers.
- Windows converts IPv6 scope IDs from network byte order and normalizes
  IPv4-mapped IPv6 endpoints.
- Windows retains ownerless TCP and UDP rows as partial evidence and never treats
  PID `0` as a process.
- Windows preserves authoritative socket rows when Toolhelp metadata enumeration
  fails by using bounded direct owner-identity reads.
- Endpoint selector and filter normalization consistently handles mapped IPv6,
  exact scope identity, exact-before-wildcard resolution, and unsafe Unicode.
- Evidence, completeness, scope, and certainty remain explicit instead of being
  inferred by renderers.
- Public collections, values, buffers, event batches, records, retries, and
  helper processes have explicit bounds and maximum-plus-one behavior.

## Docker Hardening

Docker remains optional, non-authoritative details enrichment.

Implemented changes:

- Pins enrichment to a bounded local Unix socket or Windows named pipe.
- Removes ambient Docker host, context, and TLS selectors from the child process.
- Rejects remote Docker endpoints as local ownership evidence.
- Disables PATH-resolved Docker enrichment while elevated or when privilege
  status cannot be established safely.
- Drains stdout and stderr concurrently under one bounded deadline.
- Stops retaining at the first byte above each output cap while continuing safe
  child cleanup.
- Hands timed-out direct children to capped cleanup workers that retain ownership
  until confirmed reap.
- Keeps an indeterminate wait charged against its bounded slot rather than
  allowing unbounded stuck workers.
- Keeps IPv4 and IPv6 publications separate instead of cross-associating them.
- Rejects oversized Linux privilege-status input before Docker execution.
- Rejects a row at port segment 65 and starts deterministic match omission only
  when a ninth match exists.
- Never runs Docker in `watch` or `why`.

## Platform Scope

| Platform | Native source | Declared scope | Main exclusion |
| --- | --- | --- | --- |
| Linux | `/proc/net/*` and `/proc/<pid>/fd` | Current network namespace | Other network namespaces and possibly hidden ancestor-namespace owners |
| macOS | `libproc` process and descriptor enumeration | Current host process-visible sockets | Sockets without a visible user-process descriptor |
| Windows | IP Helper extended owner tables | Native Windows host network stack | Separate WSL network stack |

`complete` always means complete within that declared native scope. It does not
mean every socket in every container, namespace, VM, or subsystem.

Published targets remain:

- Linux `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- macOS `x86_64-apple-darwin` and `aarch64-apple-darwin`.
- Windows `x86_64-pc-windows-msvc`.

## Exit Codes

| Code | Meaning |
| ---: | --- |
| 0 | Command completed and its requested positive condition holds |
| 1 | Operational or internal failure |
| 2 | Invalid arguments |
| 3 | No match, or a requested endpoint is unavailable |
| 4 | Permissions prevented a reliable answer |
| 5 | Kill was cancelled |
| 6 | A protected process requires confirmation |

For multi-endpoint `why`, aggregate precedence is `1`, then `4`, then `3`, then
`0` only when every endpoint is proven bindable now.

## Release And Repository Work

- Native Linux, macOS, and Windows release jobs run formatting, strict Clippy,
  tests, doctests, optimized dual-binary builds, and real-binary journeys against
  the exact release commit.
- GitHub Actions are pinned to full commit SHAs and checkout credentials are not
  persisted.
- Release publication is tag-only and waits for verification and artifact jobs.
- Cargo-dist is installed at exact locked version `0.32.0`.
- Repository and Homebrew credentials are introduced only in the specific steps
  that require them.
- A private vulnerability-reporting policy is available in `SECURITY.md`.
- One-off Stage reviews, qualification automation, QA harnesses, and benchmark
  artifacts were removed before release.

## Landing-Page Command Set

```sh
kickoutchi
kick list
kick list --filter 'label:web family:ipv4'
kick list --snapshot-json
kick watch --filter state:listen --json
kick why 3000
kick inspect --port 3000
kick kill --port 3000
kick kill --pid 12345 --tree
kick kill --pid 12345 --group
```

`kick` and `kickoutchi` remain equivalent binary names. Running either without a
subcommand opens the TUI.
