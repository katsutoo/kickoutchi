# Kickoutchi ༼⁠ ⁠つ⁠ ⁠◕⁠‿⁠◕⁠ ⁠༽⁠つ

**"What are you doing in my swamp?!"**, but for whatever is squatting on your
local ports.

Kickoutchi is a native TUI and CLI for finding local TCP/UDP sockets, understanding
who owns them, and safely evicting stale development processes. Use `kickoutchi`
for the full name or `kick` when every keystroke counts.

Website: <https://kickoutchi.com>

## Highlights

- Browse listening TCP and bound UDP sockets in a terminal UI.
- Script port discovery with human tables, legacy JSON, or a complete versioned
  native snapshot.
- Attach names such as `web dev` or `local postgres` to exact or wildcard
  endpoints.
- Stream bind, release, replacement, and collection-gap events with `kick watch`.
- Ask whether exact endpoints are bindable now with `kick why`.
- Inspect process families before acting.
- Terminate one verified process, a process tree, or a POSIX process group with
  explicit confirmation and fail-closed revalidation.
- Collect through native OS APIs. Core socket discovery does not parse `ss`,
  `netstat`, or `lsof` output.

Kickoutchi asks before terminating anything unless you pass `--yes`. It refuses
ambiguous ownership, unsafe PIDs, changed identities, incomplete destructive
evidence, and protected processes that were not explicitly confirmed.

## Install

### GitHub Release

Linux and macOS:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-installer.sh \
  | sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -NoProfile -Command "irm https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-installer.ps1 | iex"
```

Installer-based installs include `kickoutchi-update` for later upgrades.
Release pages also provide direct archives, per-archive `.sha256` files, and a
release-wide `sha256.sum`. Same-release checksums detect corruption; they are not
an independent signature.

### Package Managers

```sh
# Homebrew (Linux and macOS)
brew install nuggocto/tap/kickoutchi

# Arch (AUR) — prebuilt binary, or build from the release source
yay -S kickoutchi-bin
yay -S kickoutchi

# Cargo from Git
cargo install --locked --git https://github.com/nuggocto/kickoutchi

# Nix (Linux only)
nix run github:nuggocto/kickoutchi
nix profile install github:nuggocto/kickoutchi
```

```powershell
# Scoop
scoop bucket add nuggocto https://github.com/nuggocto/scoop-bucket
scoop install kickoutchi
```

Stable releases publish their generated Homebrew formula to
[`nuggocto/homebrew-tap`](https://github.com/nuggocto/homebrew-tap) after formula
validation. [`nuggocto/scoop-bucket`](https://github.com/nuggocto/scoop-bucket)
checks GitHub Releases every four hours with Scoop Excavator. Those repositories
are the package-manager sources of truth.

Arch packages are maintained from `packaging/arch/` and pushed to the AUR after
a GitHub Release exists, because their `pkgver` and checksums are taken from the
real published assets. `kickoutchi-bin` installs the prebuilt Linux archive;
`kickoutchi` builds from the release source archive.

Every package manager here is an independent publisher, so each can lag a new
GitHub Release rather than updating with it.

### Updating

Installer-based installs update through the generated updater:

```sh
kickoutchi-update
```

Package-manager installs should use the same manager that installed Kickoutchi:

```sh
# Homebrew
brew update
brew upgrade nuggocto/tap/kickoutchi

# Arch (AUR) — a normal full-system upgrade covers it
yay -Syu

# Nix profile installed from the repository flake (Linux only)
nix profile upgrade kickoutchi

# Cargo from Git
cargo install --force --locked --git https://github.com/nuggocto/kickoutchi
```

```powershell
# Scoop
scoop update
scoop update kickoutchi
```

Kickoutchi does not perform automatic release checks. The deprecated boolean
configuration key `check_for_updates` is accepted and ignored so older strict
configuration files continue to load. Use the generated standalone updater or
the package manager commands above when you choose to check for an update.

An unqualified Git or Linux Nix GitHub source follows the repository's default branch,
which can contain changes newer than the latest stable release. For a
reproducible stable source install, select an explicit tag such as `v1.3.9` and
replace that tag deliberately when upgrading. Direct-archive installs must be
replaced manually after verifying the new archive.

## Quick Start

```sh
kickoutchi                              # open the TUI
kick list                               # list visible ports
kick list --port 3000                   # select one port
kick list --json                        # stable script-friendly array
kick list --snapshot-json               # complete within-scope snapshot
kick inspect --port 3000                # inspect the owning process family
kick watch --port 3000 --duration 30s   # stream socket changes
kick why 3000                            # probe TCP loopback bindability
kick kill --port 3000                    # confirm, then terminate one owner
kick kill --pid 12345 --tree             # terminate a verified process tree
kick kill --pid 12345 --group            # Linux/macOS process group
```

`kick` and `kickoutchi` expose the same commands. Running either without a
subcommand opens the TUI.

### Direct PID safety policy

A direct `--pid` kill may intentionally target an ordinary parent process,
including the shell that launched Kickoutchi. For example,
`kick kill --pid "$PPID" --yes` terminates the invoking Unix shell without an
additional parent-specific override. Treat `--yes` as authorization for exactly
the PID you supplied and inspect an unfamiliar target before using it.

Kickoutchi always refuses PID 0, PID 1, Windows System PID 4, and its own current
PID. Tree and group kills also refuse a scope containing Kickoutchi itself so
the safety pipeline cannot terminate midway through revalidation or cleanup.

## Watch Changes

`kick watch` polls full-state native snapshots and reports deterministic changes:

```sh
kick watch
kick watch --tcp --address 127.0.0.1 --port 3000
kick watch --filter label:web --interval 500ms
kick watch --filter state:established --duration 30s --json
```

Intervals are `100ms..=60s` and default to `1s`. Explicit durations are
`100ms..=7d`. JSON mode writes one `kickoutchi.watch_event/1` object per line.

Watch is polling, not a kernel event feed. Activity entirely between polls can be
missed, and event times describe capture intervals rather than exact kernel event
times. Failed polls emit `collection_gap`; three consecutive failures stop the
command. Ctrl-C, duration expiry, and a closed stdout consumer exit successfully.

## Explain Availability

`kick why PORT` combines one native snapshot with immediate, sequential bind
probes. It never terminates a process and does not invoke Docker.

```sh
kick why 3000
kick why 5353 --udp --address 127.0.0.1
kick why 3000 --tcp --address :: --ipv6-only --json
kick why 3000 --all-protocols --all-addresses --json
```

A successful probe temporarily occupies and then releases the endpoint. It proves
only that the exact bind succeeded at that moment; it does not reserve the port or
eliminate a later race.

## Configuration

The default file is `~/.config/kickoutchi/config.toml` on Linux and the native
platform config directory on macOS and Windows. Use `--config FILE` to select a
different file. Unknown keys and files larger than 64 KiB are rejected.
A copy-ready [`config.example.toml`](config.example.toml) is included in the
repository.

```toml
refresh_interval_seconds = 3
default_sort = "port"
hide_system_processes = false
confirm_force_kill = true
protected_processes = ["redis-server"]

[[ports]]
protocol = "tcp"
address = "127.0.0.1"
port = 3000
label = "web dev"

[[ports]]
protocol = "tcp"
address = "*"
port = 8080
label = "local web services"
```

Configured protected names extend the built-in safety list. Exact endpoint labels
take precedence over wildcard labels. See [`docs/configuration.md`](docs/configuration.md)
for paths, precedence, validation, and the complete filter reference.

List, TUI search, and watch support plain search plus structured `pid:`, `port:`,
`proto:`, `scope:`, `protected:`, `parent:`, `label:`, `address:`, `scope_id:`, and
`family:` terms. Watch also supports `state:`. Terms compose with AND semantics.

## Structured Output

- `list --json` emits the stable `kickoutchi.list/1` top-level array. It can
  include process names, paths, parent data, and complete command lines.
- `list --snapshot-json` emits one `kickoutchi.snapshot/1` object containing the
  bounded full-state native observation within the declared platform scope.
- `watch --json` emits `kickoutchi.watch_event/1` NDJSON.
- `why --json` emits one `kickoutchi.why/1` result document.

Structured output can contain sensitive local information: endpoints, PIDs,
process identities, names, executable paths, labels, and command lines. JSON
escaping and terminal sanitization are not redaction. Review output before
sharing it. Schema details live in
[`docs/structured-output.md`](docs/structured-output.md).

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

## Performance

The 2026-07-29 same-machine snapshot compares the v1.3.8 release with candidate
implementation `b4af784`. Lower is better.

| Workload | Candidate p50 | p90 | p95 | p99 | p99 vs. v1.3.8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Cold startup | 1.145 ms | 1.170 ms | 1.182 ms | 1.222 ms | +0.27% |
| Warm startup | 1.146 ms | 1.174 ms | 1.184 ms | 1.215 ms | -0.09% |
| `list` | 12.799 ms | 17.156 ms | 18.466 ms | 22.435 ms | +3.84% |
| `list --json` | 12.774 ms | 17.106 ms | 18.137 ms | 21.275 ms | -0.30% |

This 2026-07-29 Linux run used an AMD Ryzen AI Max+ 395 with 32 logical CPUs:
three independent fixed-seed sessions, 3,000 observations per build and
workload, and 24,000 timed process executions in total. Every execution exited
successfully without a timeout, and every independently evaluated workload
remained within measured noise. Candidate peak-RSS p99 was at most 25.9 MiB;
the pre-strip candidate binary and Linux package grew by 0.14% and 0.09%,
respectively.

The 1.3.9 distribution profile subsequently removed symbol tables without
changing runtime code or panic unwinding. On the same x86_64 Linux build, each
executable fell from 4,046,488 to 3,289,136 bytes (-18.72%), and the complete
archive fell by about 11% to roughly 1.17 MB.

These are directional results from one machine, not portable latency
guarantees. See the [full performance snapshot](docs/performance.md) for
baseline values, CPU and memory distributions, hardware, methodology, and
limitations.

## Platform Support

Published archives target:

| Platform | Targets | Notes |
| --- | --- | --- |
| Linux | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` | Linux 5.3+ is required for identity-safe termination through pidfd |
| macOS | `x86_64-apple-darwin`, `aarch64-apple-darwin` | Intel and Apple Silicon |
| Windows | `x86_64-pc-windows-msvc` | x64; hard termination through process handles and Job Objects |

- Linux observes the current network namespace through `/proc`. PID namespace
  and procfs permissions can separately limit owner attribution.
- macOS uses process-first `libproc` collection. Sockets without a visible user
  process descriptor are outside its declared scope.
- Windows uses IP Helper and excludes the separate WSL network stack. Run the
  Linux build inside WSL to inspect WSL sockets and processes.
- Tree kill is supported on all three platforms. Process-group kill is available
  only on Linux and macOS.

### Reading addresses and scope

- `127.0.0.1` and `::1` are IPv4 and IPv6 loopback addresses.
- `0.0.0.0` and `::` are wildcard addresses that bind every applicable
  interface. Kickoutchi labels these `public`, but that classification alone
  does not prove Internet reachability; firewall and network policy still apply.
- `fe80::/10` addresses are IPv6 link-local and stay on their local network
  link.
- An IPv6 suffix such as `%3` is an interface index. `%unavailable` means the
  native collector could not report that index, which is expected for IPv6
  observations on Linux and macOS. It is not part of the literal IP address or
  an error.
- `-` in the PID or process columns means ownership metadata was unavailable;
  it does not mean the socket has no owner.

The `SCOPE` column labels wildcard addresses `public`, loopback addresses
`loopback`, and other concrete addresses `local`.

Completeness is always relative to the declared native observation scope. See
[`docs/platform-support.md`](docs/platform-support.md) for permanent limitations,
permissions, WSL, polling, IPv6 scope, and certainty semantics.

## Security and Safety

Kickoutchi never elevates itself. Destructive commands require confirmation by
default, reject ambiguous or incomplete ownership, and revalidate process
identity immediately before termination. Linux retains pidfds and Windows
retains process handles across final validation and delivery. macOS revalidates
native process start identity but cannot eliminate the platform's final raw-PID
signal race.

Socket visibility, owner visibility, and process metadata visibility are
separate. An empty or partial result is not a machine-wide proof that an endpoint
or owner does not exist. Structured and inspect output may contain sensitive
local paths, command lines, labels, PIDs, endpoints, and process relationships;
review and redact it before sharing.

Release archives include checksums for corruption detection, but the checksums
and archives share the same GitHub repository trust boundary and are not an
independent signature. Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/nuggocto/kickoutchi/security/advisories/new).
The full threat model, authority boundaries, output-handling guidance, and
release controls are in [`SECURITY.md`](SECURITY.md).

## Build From Source

Rust 1.95.0 or newer is required.

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
cargo build --locked
cargo test --locked --all-features
cargo run --bin kick -- list
```

Install the local checkout with:

```sh
cargo install --path . --locked
```

## License

[MIT](LICENSE)
