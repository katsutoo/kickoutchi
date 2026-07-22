# Security Policy

## Supported Versions

Security fixes are provided for the latest published release. Upgrade to the
newest GitHub Release before reporting behavior that may already be fixed.

## Reporting A Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private
security-advisory form for this repository:

<https://github.com/nuggocto/kickoutchi/security/advisories/new>

Include the affected version and platform, the required local permissions,
reproduction steps, impact, and the least sensitive evidence needed to explain
the issue. Do not include credentials, personal command lines, or another
user's process metadata.

You should receive an acknowledgement within seven days. No testing against
third-party or production systems is authorized by this policy.

## Sensitive Output

Treat output from `list`, `list --snapshot-json`, `watch`, `why`, and `inspect` as
sensitive local-system data, whether it is human-readable or structured.

`list --json` is a compatibility interface that can include process and parent
names, executable paths, and complete command lines. `inspect` can expose command
lines, names, paths, parent and child relationships, PIDs, and ports. Command
lines commonly contain tokens, credentials, URLs, file paths, or user data.

Snapshot, watch, and Why never collect or serialize complete process command
lines. They can still expose endpoints, PIDs, stable process-start markers,
process and parent names, executable paths where applicable, ownership,
configured labels, namespace or scope identifiers, evidence, evidence gaps, and
raw or explanatory OS errors. Labels can reveal project names, service roles,
and local topology. Optional TUI details can also include bounded local Docker
metadata; Why does not invoke Docker, and watch does not invoke it in its polling
loop.

Terminal sanitization protects human output, and JSON escaping preserves JSON
syntax. Structured host strings can still contain terminal-significant Unicode,
so JSON is not safe for direct terminal display. Neither mechanism is redaction.
Before sharing output, remove or replace command lines,
PIDs and start markers, names, paths, parent relationships, addresses and ports,
labels, scope identifiers, evidence and error messages, and Docker container,
Compose, or publication metadata. Prefer the smallest excerpt needed to report
the issue, and preserve stable schema codes only when they are relevant.

## Observation And Probe Limits

A complete result is complete only inside the collector's declared scope. Linux
observes the current network namespace and can have separate procfs/PID namespace
ownership gaps. Native Windows does not observe the WSL network stack. macOS
collection is process-first and cannot include sockets without a visible
user-process descriptor. Elevation may reveal more identities, metadata, or
termination handles, but it does not remove these scope boundaries; Kickoutchi
does not elevate itself.

Watch compares periodic snapshots. Activity that starts and ends between polls
can be missed, multiple changes can collapse into one net difference, and event
timestamps are observation intervals rather than exact kernel times. A missing
event is not proof that no transient activity occurred.

Why takes one snapshot and then performs sequential exact bind probes. A
successful probe temporarily occupies the endpoint until its immediate close
and can briefly race a concurrent binder. After close, another process can bind
before output is rendered or acted upon, so `bindable_now` is not a reservation
or future guarantee. Snapshot ownership evidence can also change before a later
probe. Run Why only against endpoints where this short-lived bind is acceptable.

Kickoutchi does not require elevated privileges for ordinary use. Do not run it
as root or Administrator merely to obtain more metadata unless you understand
the expanded process visibility and termination authority. PATH-based Docker
enrichment is disabled while elevated, but structured host data remains
sensitive.

The canonical contracts and privacy distinctions are documented in the
[structured output reference](docs/structured-output.md). Configuration labels
and filters are documented in the [configuration reference](docs/configuration.md),
and permanent scope, polling, WSL, and bind-probe limitations are documented in
[platform support](docs/platform-support.md).
