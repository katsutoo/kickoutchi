---
title: Kickoutchi - Linux-First Rust + ratatui Port Janitor Roadmap
tags: [rust, project, tui, ratatui, ports, processes, linux, windows, macos]
created: 2026-05-30
status: planning
---

# Kickoutchi - Rust + ratatui Port Janitor

> A clean cross-platform TUI and CLI that shows which local ports are open, which process owns each port, and how to stop the culprit safely without hunting through terminal commands.

## Project Goal

Build a local terminal application that:

- Lists listening TCP ports and bound UDP ports
- Shows protocol, address, port, PID, process name, executable path, and command line when available
- Works on Linux first; Windows and macOS are optional, deferred targets (Phases 7 and 8)
- Lets the user refresh, search, filter, and sort ports
- Provides a non-TUI CLI mode for scripts and quick checks
- Shows the exact kill command for the selected process
- Can terminate or force-kill a selected process only after confirmation
- Supports protected-process rules for extra safety
- Shows parent/child process context when available
- Uses a config file for user preferences
- Is safe by default and does not kill anything accidentally
- Has a clear, fast `ratatui` interface
- Stays fully open source under MIT

This is not an SSH-hosted app. Kickoutchi runs locally on the developer machine.

Separately, a static marketing landing page presents Kickoutchi and links to the install options. It is built with Astro, kept in its own repository, and deployed to Cloudflare Pages at the project domain `kickoutchi.com`, with download buttons that point at the GitHub Releases artifacts. The website lives outside this repository so this repo stays a clean, all-Rust project; it is not part of the cargo build or the phases below.

Why local install is required:

- Kickoutchi needs to inspect ports on the user's own machine
- Kickoutchi needs local OS permissions to read process metadata
- Kickoutchi needs local OS permissions to terminate processes
- An SSH-hosted version would only show ports on the remote server, not on the user's laptop or workstation

---

## Installation And Setup Options

Users should be able to install Kickoutchi in several ways.

### Option 1 - Download Release Binary

Recommended for most users.

Release artifacts produced by the `cargo-dist` workflow:

```txt
kickoutchi-x86_64-unknown-linux-gnu.tar.xz
kickoutchi-aarch64-unknown-linux-gnu.tar.xz
kickoutchi-x86_64-apple-darwin.tar.xz
kickoutchi-aarch64-apple-darwin.tar.xz
kickoutchi-x86_64-pc-windows-msvc.zip
kickoutchi-installer.sh
kickoutchi-installer.ps1
sha256.sum
dist-manifest.json
```

Linux/macOS example:

```sh
curl -L https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-x86_64-unknown-linux-gnu.tar.xz -o kickoutchi.tar.xz
tar -xf kickoutchi.tar.xz
./kickoutchi-x86_64-unknown-linux-gnu/kickoutchi
```

Windows example:

```powershell
Invoke-WebRequest -Uri "https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-x86_64-pc-windows-msvc.zip" -OutFile "kickoutchi.zip"
Expand-Archive .\kickoutchi.zip -DestinationPath .\kickoutchi
.\kickoutchi\kickoutchi-x86_64-pc-windows-msvc\kickoutchi.exe
```

### Option 2 - Install With Cargo

Recommended for Rust users.

```sh
cargo install --locked kickoutchi
kickoutchi
```

If installing from the Git repository before crates.io release:

```sh
cargo install --git https://github.com/nuggocto/kickoutchi
kickoutchi
```

### Option 3 - Build From Source

Recommended for contributors.

The project should use `mise` to pin the Rust toolchain and keep contributor environments consistent. `mise.toml` also defines local task aliases for the standard verification commands, so contributors do not have to remember the full Cargo invocations.

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
mise trust
mise install
mise run check
cargo run --release
```

Common local tasks:

```sh
mise run fmt
mise run fmt-check
mise run clippy
mise run test
mise run check
mise run tui
mise run list
```

To install the locally built binary:

```sh
cargo install --path .
kickoutchi
```

### Option 4 - Native Package Managers

Good distribution targets:

```sh
# Arch Linux through the AUR
yay -S kickoutchi
yay -S kickoutchi-bin

# Nix with flakes
nix run github:nuggocto/kickoutchi

# Nix install into profile
nix profile install github:nuggocto/kickoutchi
```

Arch and Nix are first-class packaging targets because they fit Rust CLI/TUI tools well. The Homebrew formula and winget distribution can come after the first public release, once the release artifacts and checksums have been exercised in the generated GitHub Release flow.

Arch packaging plan:

- Publish `kickoutchi-bin` AUR package first, using GitHub release binaries
- Publish `kickoutchi` AUR package after the binary package is stable, building from source with Cargo
- Include completions and man page if added later
- Keep `PKGBUILD` templates under `packaging/arch/`
- Validate with `makepkg --clean --syncdeps --install` and `namcap`

Nix packaging plan:

- Add `flake.nix`
- Provide `packages.x86_64-linux.default`
- Provide `packages.aarch64-linux.default`
- Provide `packages.x86_64-darwin.default`
- Provide `packages.aarch64-darwin.default`
- Provide `apps.<system>.default` so `nix run` works
- Provide a dev shell with Rust, clippy, rustfmt, and platform build tools
- Keep Nix packaging in-tree from the beginning

Linux distro packages such as `.deb`, `.rpm`, and Alpine packages can come after release binaries, Arch, and Nix are stable.

### Permissions Notes

Kickoutchi should run without administrator/root privileges for normal use, but process metadata may be incomplete for processes owned by another user or protected by the OS.

When permissions are limited:

- The port should still appear if the OS exposes it
- PID may be present while path or command line is hidden
- Kill attempts may fail with permission denied
- The UI should explain the missing permission clearly

Users can choose to run with elevated privileges when they explicitly need complete visibility or permission to terminate protected processes:

```sh
# Linux/macOS, only when needed
sudo kickoutchi
```

```powershell
# Windows, only when needed
# Run Windows Terminal or PowerShell as Administrator, then:
kickoutchi.exe
```

---

## Product Shape

The common use case:

```txt
cargo run
-> see :3000 owned by PID 18422 node
-> see :5173 owned by PID 21988 vite
-> select stale process
-> press x
-> confirm termination
-> port disappears after refresh
```

The app should be useful for AI-agent-heavy development, where agents often start servers and leave them behind.

Recommended behavior:

- Open directly into the port table
- Refresh automatically every few seconds
- Support manual refresh
- Support non-TUI commands for automation
- Never terminate a process without explicit confirmation
- Prefer normal termination before force kill
- Warn when the selected PID looks like a system process
- Add an extra warning for protected process names
- Show permission errors clearly instead of hiding them

Do not build first:

- Remote host management
- SSH deployment
- Daemon mode
- Background service
- Full process manager replacement
- Network packet inspection

Keep the product focused:

```txt
What owns this port, and how do I safely kick it out?
```

---

## Important Product Decisions

### Clean Cross-Platform Design

Do not make shell-command parsing the core architecture.

Use a shared domain model with platform-specific collectors:

```txt
src/platform/linux.rs   -> Linux socket/process collector
src/platform/windows.rs -> Windows socket/process collector
src/platform/macos.rs   -> macOS socket/process collector
```

Each collector returns the same internal type:

```rust
pub struct PortEntry {
    pub protocol: Protocol,
    pub local_addr: IpAddr,
    pub local_port: u16,
    pub state: SocketState,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub executable_path: Option<PathBuf>,
    pub command_line: Option<String>,
    pub parent_pid: Option<u32>,
    pub parent_process_name: Option<String>,
    pub child_pids: Vec<u32>,
    pub protected: bool,
    pub platform: Platform,
    pub permission: PermissionStatus,
}
```

This keeps the UI simple and keeps platform weirdness contained.

### What Counts As Open

For Kickoutchi, open means:

- TCP socket in `LISTEN` state
- UDP socket bound to a local port

Optional later filters can include:

- Established TCP connections
- Loopback-only ports
- Publicly reachable ports
- IPv4 only
- IPv6 only

### Non-TUI CLI Mode

Kickoutchi should also work without opening the TUI.

This makes it useful for scripts, aliases, CI debugging, and quick terminal checks.

Recommended commands:

```sh
kickoutchi
kickoutchi list
kickoutchi list --port 3000
kickoutchi list --process node
kickoutchi list --json
kickoutchi kill --port 3000
kickoutchi kill --pid 18422
kickoutchi kill --pid 18422 --force
```

Behavior:

- `kickoutchi` opens the TUI by default
- `kickoutchi list` prints a table and exits
- `kickoutchi list --json` prints stable JSON and exits
- `kickoutchi kill` still asks for confirmation unless `--yes` is passed
- `--yes` should never bypass protected-process extra warnings unless a separate explicit flag is added later
- Exit codes should be stable for scripts

Short binary name: the crate builds the same program under two names, `kickoutchi` (canonical, used in all docs and on the website) and `kick` (short form for daily CLI use: `kick list`, `kick kill --port 3000`). Both behave identically, including opening the TUI when run bare; the help usage line follows the invoked name (`Usage: kick ...`) while `--version` reports the canonical `kickoutchi`. The project cannot be renamed (the `kickoutchi.com` domain is the brand), so the short form ships as a second binary instead. `kick` was verified free in the Arch official repos, the AUR, and as a crates.io binary before adoption; `ko` was rejected because the Go container tool `ko` owns it in Arch extra. Phase 10 packaging must ship both names (as a copy or a symlink, whichever the package format prefers) and re-verify the name is still free in each target repository before first publication.

Suggested exit codes:

```txt
0 -> success
1 -> generic failure
2 -> invalid arguments
3 -> no matching port/process
4 -> permission denied
5 -> kill cancelled by user
6 -> protected process requires explicit confirmation
```

### Config File

Kickoutchi should support a small config file for user preferences.

Example:

```toml
refresh_interval_seconds = 3
default_sort = "port"
hide_system_processes = false
confirm_force_kill = true

protected_processes = [
  "docker",
  "postgres",
  "systemd",
  "explorer.exe",
  "WindowServer",
]
```

Default config paths:

```txt
Linux:   ~/.config/kickoutchi/config.toml
macOS:   ~/Library/Application Support/kickoutchi/config.toml
Windows: %APPDATA%\kickoutchi\config.toml
```

Config rules:

- App should run without a config file
- Missing config means safe defaults
- Invalid config should show a clear error
- CLI flags override config values
- TUI should expose active config values in the help/details screen

### Protected Process Allowlist

Some processes should require an extra warning before termination.

Default protected process names:

```txt
docker
docker.exe
dockerd.exe
Docker Desktop.exe
com.docker.backend.exe
postgres
postgres.exe
systemd
System
smss.exe
csrss.exe
wininit.exe
services.exe
lsass.exe
svchost.exe
winlogon.exe
explorer.exe
dwm.exe
WindowServer
```

Behavior:

- Matching should be case-insensitive on Windows and case-sensitive on Unix unless platform conventions suggest otherwise
- Protected process names can be extended in the config file
- Protected processes can still be terminated, but only after a stronger confirmation
- Force-killing a protected process should require typing the PID or process name, not just pressing `y`

### Process Tree And Details

Kickoutchi should show parent and child process context when available.

This is especially useful for AI-agent and dev-server workflows where the port owner might be a child process started by `node`, `python`, `cargo`, `bun`, or an editor agent.

Details to collect when available:

```txt
pid
parent_pid
parent_process_name
child_pids
child_process_names
process_start_time
current_user
```

UI behavior:

- Details panel shows parent process
- Details modal can show child processes
- Kill confirmation should mention if the selected PID has children

Collection note: child context is resolved lazily only when the user asks for details on the selected row. Building the full child map for every row would mean walking the whole process table on every refresh, and doing that work on every selection move would make table navigation depend on process-table size. The side details panel may say child context is not loaded yet; the details modal loads and shows it.

### Docker And Container Awareness

Docker/container awareness is useful now that native OS collectors and safe termination are solid. It stays narrow: explain local Docker-owned ports, do not become a container dashboard.

Example details output:

```txt
Port 5432 -> docker-proxy -> container postgres-dev
```

Implemented behavior:

- Detect Docker proxy/backend processes and partial-metadata rows that may map to a Docker-published port
- Resolve container name and ID when Docker is available
- Show compose project/service names when available
- Show equivalent Docker command, such as `docker stop postgres-dev`, when exactly one container matches
- Do not require Docker for normal Kickoutchi usage

### Linux Support

Clean Linux v1 should use `/proc`, not `ss` or `lsof` parsing.

Collector approach:

- Read `/proc/net/tcp`
- Read `/proc/net/tcp6`
- Read `/proc/net/udp`
- Read `/proc/net/udp6`
- Parse socket inode from each row
- Walk `/proc/<pid>/fd/*` symlinks to map socket inode to PID
- Read `/proc/<pid>/comm` for process name
- Read `/proc/<pid>/cmdline` for command line
- Read `/proc/<pid>/exe` for executable path when permitted

Notes:

- Some process details may require elevated permissions
- Ports should still appear even when process metadata is partially unavailable
- `/proc` parsing is stable enough for this use case and avoids spawning tools
- Netlink can be added later if `/proc` performance becomes a problem

### Windows Support

Clean Windows v1 should use Windows APIs through `windows-sys`, not `netstat -ano` parsing.

Collector approach:

- Use `GetExtendedTcpTable` for TCP sockets with owner PID
- Use `GetExtendedUdpTable` for UDP sockets with owner PID
- Filter TCP rows to `LISTEN`
- Normalize IPv4 and IPv6 rows
- Use process APIs or `sysinfo` to resolve PID to name, path, and command line

Notes:

- UDP does not have a listen state; a bound UDP port is shown as open
- Some process paths may require administrator privileges
- Kill commands should use Windows terminology in the UI

### macOS Support

macOS is possible and should be supported.

Clean macOS v1 should use native APIs through a small FFI wrapper, with `lsof` only as a fallback or debug mode.

Collector approach:

- Enumerate processes with `sysctl` or `libproc`
- Use `proc_pidinfo` with `PROC_PIDLISTFDS` to list file descriptors
- Use `proc_pidfdinfo` with socket fd info to inspect sockets
- Keep TCP sockets in listen state
- Keep UDP sockets that are bound to a local address/port
- Use `proc_name` and `proc_pidpath` for process metadata

Notes:

- macOS process/socket APIs are more awkward than Linux and Windows
- Some process details may require root or extra permissions
- The app should still render partial rows when metadata is restricted
- `lsof -nP -iTCP -sTCP:LISTEN -iUDP` can be a fallback behind a feature flag or `--collector lsof`

### Killing Processes

Killing must be explicit and reversible only until confirmed.

Behavior:

```txt
x -> ask to terminate selected PID normally
X -> ask to force-kill selected PID
```

Confirmation example:

```txt
Terminate PID 18422 (node) using port 3000?

Command: kill 18422

Press y to confirm, Esc to cancel.
```

Platform commands shown in UI:

| Platform | Normal terminate | Force kill |
|---|---|---|
| Linux | `kill <PID>` | `kill -9 <PID>` |
| macOS | `kill <PID>` | `kill -9 <PID>` |
| Windows | `taskkill /F /PID <PID>` | `taskkill /F /PID <PID>` |

Implementation should use platform APIs where reasonable, but the UI should show the equivalent command so users understand what will happen.

Windows note: Kickoutchi's current Windows implementation uses a prepared process handle plus `TerminateProcess`, so both `x` and `X` have the same OS delivery and the equivalent command includes `/F`. The keys still differ in user intent and confirmation strength: `x` is the normal termination request and asks for `y`; `X` is an explicit force-kill request and asks for typed `force` when `confirm_force_kill` is enabled. The confirmation warning names `TerminateProcess` so users understand that Windows delivery is immediate.

Safety rules:

- Never kill PID `0`, PID `1`, or the Kickoutchi process itself
- Never resolve an ambiguous target by guessing: when a requested port is owned by more than one PID, refuse and require an explicit PID
- Warn before killing processes owned by another user
- Warn before killing known system/service processes
- Prefer normal termination before force kill
- Refresh immediately after a kill attempt
- Show success, permission denied, process already exited, or unknown failure clearly

---

## The Stack

Current version snapshot checked on 2026-05-04 with crates.io metadata and local Rust toolchain.

| Concern          |                           Choice |      Current version | Why                                                                |
| ---------------- | -------------------------------: | -------------------: | ------------------------------------------------------------------ |
| Language         |                      Rust stable |       `rustc 1.95.0` | Safe systems code and cross-platform binaries                      |
| Build tool       |                            Cargo |        `cargo 1.95.0` | Matches the installed Rust toolchain                               |
| Tool versions    |                           `mise` | `2026.4.28` available | Pin Rust and local project tools consistently                      |
| Edition          |                     Rust edition |               `2024` | Current stable edition supported by the installed compiler         |
| TUI              |                        `ratatui` |             `0.30.0` | Structured terminal UI                                             |
| Terminal events  |                      `crossterm` |             `0.29.0` | Cross-platform keyboard, raw mode, alternate screen                |
| Process metadata |                        `sysinfo` |             `0.38.4` | Cross-platform process names, paths, command lines where available |
| CLI flags        |                           `clap` |              `4.6.1` | Filters, refresh interval, collector mode                          |
| Serialization    |          `serde` + `serde_json` | `1.0.228` + `1.0.149` | JSON output for non-TUI mode and stable data snapshots             |
| Config format    |                            `toml` |              `1.1.2` | Human-editable user config                                         |
| Windows APIs     |                    `windows-sys` |             `0.61.2` | Direct access to IP Helper and process APIs                        |
| Unix FFI         |                           `libc` |            `0.2.177` | Latest non-alpha Unix/macOS FFI bindings                           |
| Config paths     |                            `dirs` |              `6.0.0` | Cross-platform config/cache directory resolution (`XDG_CONFIG_HOME`, `%APPDATA%`, `~/Library/...`) |
| Errors           |                        `thiserror` |             `2.0.18` | Typed errors at module boundaries; no app-level `anyhow` yet       |
| Logging          | `tracing` + `tracing-subscriber` |  `0.1.44` + `0.3.23` | Debug collector failures without polluting the UI                  |
| Release tooling  |          `cargo-dist` (`dist`) |    `0.30.0` available | Rust-native cross-platform release pipeline, configured from `Cargo.toml` |

### One-Time Setup

```sh
cargo new kickoutchi
cd kickoutchi
cat > mise.toml <<'EOF'
[tools]
rust = "1.95.0"
EOF
mise trust
mise install
cargo add ratatui@0.30.0 crossterm@0.29.0
cargo add sysinfo@0.38.4
cargo add clap@4.6.1 --features derive
cargo add serde@1.0.228 --features derive
cargo add serde_json@1.0.149 toml@1.1.2
cargo add dirs@6.0.0
cargo add thiserror@2.0.18
cargo add tracing@0.1.44 tracing-subscriber@0.3.23
cargo add libc@0.2.177 --target 'cfg(unix)'
cargo add windows-sys@0.61.2 --target 'cfg(windows)' --features Win32_Foundation,Win32_NetworkManagement_IpHelper,Win32_Networking_WinSock,Win32_System_ProcessStatus,Win32_System_Threading
```

---

## Architecture Overview

```txt
+----------------------------------------------------------------+
| lib.rs              - shared entrypoint: startup and dispatch     |
| bin/kickoutchi.rs   - canonical binary, calls kickoutchi::run()   |
| bin/kick.rs         - short-alias binary, calls kickoutchi::run() |
+----------------------------------------------------------------+
| app.rs              - app state, selected row, filters, mode     |
| config.rs           - CLI options and defaults                   |
| cli.rs              - non-TUI commands and exit codes            |
| model.rs            - PortEntry, Protocol, SocketState, errors   |
| collector.rs        - Collector trait and orchestration          |
| process.rs          - process metadata and kill operations       |
| protection.rs       - protected-process matching and warnings     |
| platform/           - OS-specific socket/process collectors      |
| ui/                 - ratatui layout and widgets                 |
| input.rs            - key events -> app commands                 |
| command.rs          - kill command rendering                     |
| output.rs           - table/JSON output for CLI mode              |
| error.rs            - typed errors                               |
+----------------------------------------------------------------+
```

Suggested repo structure:

```txt
kickoutchi/
|-- Cargo.toml
|-- Cargo.lock
|-- mise.toml
|-- README.md
|-- LICENSE
|-- src/
|   |-- lib.rs
|   |-- bin/
|   |   |-- kickoutchi.rs
|   |   |-- kick.rs
|   |-- app.rs
|   |-- config.rs
|   |-- cli.rs
|   |-- model.rs
|   |-- collector.rs
|   |-- process.rs
|   |-- protection.rs
|   |-- command.rs
|   |-- output.rs
|   |-- input.rs
|   |-- error.rs
|   |-- platform/
|   |   |-- mod.rs
|   |   |-- linux.rs
|   |   |-- windows.rs
|   |   |-- macos.rs
|   |-- ui/
|       |-- mod.rs
|       |-- table.rs
|       |-- details.rs
|       |-- confirm.rs
|       |-- help.rs
|       |-- theme.rs
|-- tests/
|   |-- parser_linux_test.rs
|   |-- ui_snapshot_test.rs
```

## Runtime Model

- Main thread owns the terminal UI
- Collector runs on refresh tick or manual refresh
- TUI collection runs in a single in-flight background worker so the Linux `/proc/<pid>/fd` owner scan does not block rendering or input
- If a refresh is already running, another automatic or manual refresh does not start a second scan; the last successful snapshot stays visible until the worker returns
- UI stores the last successful snapshot and the latest collector error
- Kill action targets a PID from the latest snapshot
- After kill attempt, refresh immediately

---

## TUI Design

Default layout:

```txt
Kickoutchi                                                        r refresh  / search  x kill  X force  q quit
+ Proto + Address        + Port  + PID    + Process        + State     + Scope      +
| TCP   | 127.0.0.1      | 3000  | 18422  | node           | LISTEN    | loopback   |
| TCP   | 127.0.0.1      | 5173  | 21988  | vite           | LISTEN    | loopback   |
| UDP   | 0.0.0.0        | 5353  | 902    | mdnsresponder  | BOUND     | public     |
+------------------------------------------------------------------------------+

Details
PID: 18422
Process: node
Parent: cursor-agent (PID 18001)
Children: 2
Path: /usr/bin/node
Command: node server.js
Kill: kill 18422
Force: kill -9 18422

Status: 18 open ports, refreshed 2s ago
```

Design principles:

- Dense but readable
- Important columns fit in `100x30`
- Details panel explains the selected row
- Permission problems are visible, not noisy
- No animation needed
- Color is helpful but not required
- Support `NO_COLOR`

Keybinds:

| Key | Action |
|---|---|
| `r` | Refresh now |
| `/` | Search/filter |
| `Esc` | Clear search or close modal |
| `j` / `Down` | Move down |
| `k` / `Up` | Move up when not in table action mode |
| `Enter` | Open details modal |
| `x` | Terminate selected process normally |
| `X` | Force-kill selected process |
| `s` | Change sort |
| `p` | Toggle process-tree details |
| `?` | Help |
| `q` | Quit |

Use `x` and `X` for kill actions so `k` can remain a navigation key for users who expect vim-style movement.

Filters:

```txt
/3000          -> match port, process, path, command, address
tcp            -> TCP only if typed as normal search text
pid:18422      -> exact PID filter
port:3000      -> exact port filter
proto:udp      -> protocol filter
scope:public   -> public bind filter
protected:true -> protected processes only
parent:node    -> match parent process
```

---

# Phases

The phases below are ordered so Kickoutchi moves from an empty repository to a finished, installable cross-platform app.

The most important rule is that every phase should leave the project in a working state. Do not build a large pile of disconnected code and hope it comes together later. Each phase should produce either a usable app slice, a tested collector, or a release artifact.

Milestones:

| Milestone | Finished after | Meaning |
|---|---:|---|
| Local prototype | Phase 2 | The app opens, renders fake data, and proves the TUI shape |
| Linux MVP | Phase 6 | Linux can show real ports, filter them, and safely terminate stale processes |
| Cross-platform app (optional) | Phase 8 | Linux, Windows, and macOS collectors all work; Windows and macOS are deferred until there is motivation to build them |
| Public release | Phase 10 | Users can install Linux binaries and packages; Windows/macOS artifacts ship only if Phases 7 and 8 are built |

Recommended order:

```txt
setup
-> shared model, config, and CLI
-> fake-data TUI
-> Linux real-data vertical slice
-> filtering, sorting, refresh
-> process context and protection
-> safe termination
-> Windows collector
-> macOS collector
-> optional Docker awareness
-> packaging and release
```

Phase 9 is intentionally optional for the first public release. Docker awareness is useful, but the core product is complete when native port collection and safe termination work reliably on all target platforms.

---

## Phase 0 - Project Foundation

**Goal:** Create a clean Rust project that always builds, formats, lints, and restores the terminal correctly.

**Why this comes first:** Terminal apps can leave the user's shell in a broken state if raw mode or alternate screen handling is wrong. Before adding features, make startup and shutdown boring and safe.

**Expected result:** Running `cargo run` opens a minimal terminal screen, exits cleanly, and never leaves the terminal stuck in raw mode.

### Build steps

1. Create the project with `cargo new kickoutchi`.
2. Set `edition = "2024"` in `Cargo.toml`.
3. Add required `Cargo.toml` metadata fields early: `license = "MIT"`, `description`, `repository`, `authors`, and `readme = "README.md"`. These are needed for both `cargo publish` and `cargo-dist` later.
4. Add `mise.toml` pinned to Rust `1.95.0`.
5. Run `mise trust` and `mise install` so contributors use the same Rust toolchain.
6. Add the dependencies from the stack table, starting with `ratatui`, `crossterm`, `clap`, `serde`, `serde_json`, `toml`, `thiserror`, and `tracing`.
7. Add strict project lints in `Cargo.toml`.

```toml
[lints.rust]
warnings = "deny"

[lints.clippy]
pedantic = "warn"
```

8. Create the first module boundaries: `main.rs`, `config.rs`, `error.rs`, and a minimal `ui/mod.rs`.
9. Add terminal setup code that enters raw mode and the alternate screen.
10. Add a terminal guard type that restores raw mode and the alternate screen on normal exit.
11. Add a panic hook that restores the terminal before printing the panic.
12. Add a minimal event loop that exits on `q`, `Esc`, or Ctrl+C.
13. Add `cargo fmt`, `cargo clippy`, and `cargo test` as the default local verification commands.

### Done when

- `cargo run` opens and closes cleanly.
- `q`, `Esc`, and Ctrl+C return the terminal to normal.
- A forced panic during startup or rendering does not leave the terminal broken.
- `mise install` provisions the expected Rust toolchain.
- `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` pass.

### Do not build yet

- Real port collection.
- Kill behavior.
- Full TUI layout.
- Cross-platform collectors.

---

## Phase 1 - Shared Model, Config, And CLI Shape

**Goal:** Define the data Kickoutchi works with and make non-TUI commands parse correctly before real collection exists.

**Why this comes next:** The TUI, CLI, collectors, filters, JSON output, and kill confirmations should all use the same types. Getting the model right early prevents rewriting every feature later.

**Expected result:** `kickoutchi list` and related commands run against fake sample data, print useful output, and prove the command/config shape.

### Build steps

1. Create `model.rs` with `PortEntry`, `Protocol`, `SocketState`, `Platform`, and `PermissionStatus`.
2. Include all fields the UI and CLI need: protocol, address, port, state, PID, process name, executable path, command line, parent process, children, protection status, platform, and permission status.
3. Create `collector.rs` with a `Collector` trait or simple collection function that returns `Vec<PortEntry>`.
4. Add a fake collector that returns a few realistic TCP and UDP rows, including one row with partial metadata.
5. Create `config.rs` with safe defaults for refresh interval, default sort, protected processes, and confirmation behavior.
6. Load config from the platform default path, but allow the app to run when no config file exists.
7. Return a clear error when a config file exists but is invalid.
8. Create `cli.rs` with `clap` commands for `list` and `kill`.
9. Implement `kickoutchi list`, `kickoutchi list --port 3000`, `kickoutchi list --process node`, and `kickoutchi list --json` using fake data.
10. Add the `kill` command shape with confirmation prompts, but route it to a stub that says real termination is not implemented yet.
11. Define stable exit codes in one place so scripts can rely on them later.
12. Make CLI flags override config values.
13. Add tests for config loading, CLI parsing, JSON shape, and exit-code mapping.

### Done when

- `kickoutchi list` prints a readable table and exits.
- `kickoutchi list --json` prints stable JSON and exits.
- `kickoutchi list --port 3000` filters fake rows correctly.
- Invalid config errors name the config file and the bad value.
- CLI commands never open the TUI.
- The code can switch from fake data to real collectors without changing the CLI output layer.

### Do not build yet

- Real process killing.
- Advanced search syntax.
- Native Linux, Windows, or macOS collectors.

---

## Phase 2 - Static TUI Skeleton

**Goal:** Build the visible TUI experience using fake port data.

**Why this comes before real collectors:** A fake-data UI lets the layout, navigation, details panel, and help flow stabilize without debugging OS-specific socket code at the same time.

**Expected result:** `kickoutchi` opens a polished local TUI with fake rows, a selected row, a details panel, a status bar, and a help modal.

### Build steps

1. Create `app.rs` to hold app state: rows, selected index, active filter text, sort mode, last refresh time, modal state, and latest error.
2. Create `input.rs` to map keys into app actions.
3. Create `ui/table.rs` for the main port table.
4. Create `ui/details.rs` for selected-row details.
5. Create `ui/help.rs` for keybind help.
6. Create `ui/theme.rs` for colors and `NO_COLOR` handling.
7. Render fake TCP and UDP rows from Phase 1.
8. Implement selection movement with `j`, `k`, Up, and Down.
9. Implement `Enter` to open a details modal.
10. Implement `?` to open help.
11. Implement `q` and `Esc` behavior consistently.
12. Show a status bar with row count and refresh age.
13. Add a small terminal-size fallback message if the viewport is too small.
14. Add UI snapshot tests if practical, or at minimum tests for app-state transitions.

### Done when

- The TUI is readable at `100x30`.
- Selection changes update the details panel immediately.
- `?` shows all keybinds.
- `Enter` opens details for the selected row.
- `q` quits cleanly.
- The UI can render rows with missing PID, path, or command line.

### Do not build yet

- Real refresh behavior.
- Real kill behavior.
- Docker awareness.
- Platform-specific collectors.

---

## Phase 3 - Linux Native Collector

**Goal:** Replace fake data with real Linux port data without shelling out to `ss`, `lsof`, or `netstat`.

**Why this is the first real collector:** Linux gives the simplest native path through `/proc`, so it is the best platform for proving the full data flow from OS collection to UI rendering.

**Expected result:** On Linux, `cargo run` shows actual listening TCP ports and bound UDP ports with PID and process metadata when permissions allow it.

### Build steps

1. Create `platform/linux.rs` behind `cfg(target_os = "linux")`.
2. Parse `/proc/net/tcp` and `/proc/net/tcp6`.
3. Keep only TCP rows with state `0A`, which means `LISTEN`.
4. Parse `/proc/net/udp` and `/proc/net/udp6`.
5. Treat UDP rows as bound sockets because UDP has no listen state.
6. Decode local IPv4 and IPv6 addresses.
7. Decode local ports from hex.
8. Extract socket inode from each row.
9. Walk `/proc/<pid>/fd/*` symlinks to map socket inodes to PIDs.
10. Read `/proc/<pid>/comm` for process name when permitted.
11. Read `/proc/<pid>/cmdline` for command line when permitted.
12. Read `/proc/<pid>/exe` for executable path when permitted.
13. Mark rows with partial metadata instead of dropping them.
14. Return permission status so the UI can explain missing data.
15. Connect the Linux collector to the CLI and TUI on Linux.
16. Keep the fake collector available for tests and non-Linux development if useful.
17. Add fixture-based unit tests for `/proc/net` parsing.
18. Add tests for IPv4, IPv6, port decoding, socket state filtering, and malformed rows.

### Done when

- `cargo run` on Linux shows real local ports.
- `python3 -m http.server 3000` appears as port `3000` with the correct PID.
- `kickoutchi list --port 3000` finds the same row as the TUI.
- Permission-denied process metadata does not crash collection.
- Parser tests are deterministic and do not depend on the current machine.

### Do not build yet

- Windows collector.
- macOS collector.
- Process termination.

---

## Phase 4 - Filtering, Sorting, And Refresh

**Goal:** Make the Linux app useful on a noisy developer machine.

**Why this comes before killing:** Users need to reliably find the right process before Kickoutchi offers destructive actions.

**Expected result:** The TUI can refresh real data, keep selection stable, search rows, apply structured filters, and sort the table.

### Build steps

1. Add manual refresh with `r`.
2. Add automatic refresh using the configured refresh interval.
3. Store the last successful snapshot separately from the latest collector error.
4. Preserve selection across refresh by matching PID, protocol, local address, and local port when possible.
5. If the selected process disappears, move selection to the nearest sensible row.
6. Add search mode with `/`.
7. Make plain search text match port, process name, path, command line, address, and parent process.
8. Add structured filters for `pid:`, `port:`, `proto:`, `scope:`, `protected:`, and `parent:`.
9. Add sort modes for port, PID, protocol, process name, parent process, and scope.
10. Make sort and filter behavior shared by the CLI and TUI where possible.
11. Show active filter text, sorted column, row count, and last refresh time in the status bar.
12. Add config-driven defaults for sort mode, refresh interval, and hidden system processes.
13. Add tests for filter parsing, filter matching, sort ordering, and selection preservation.

**Refresh hardening note:** After Phase 6, the TUI refresh path was moved to a single in-flight background worker. This preserves the correctness-first Linux `/proc/<pid>/fd` owner scan, including shared socket owner detection, without making table navigation and key handling wait for the scan on large hosts. The first snapshot is collected synchronously so the TUI opens onto real rows instead of a blank table, refresh requests do not pile up, and an in-flight refresh is abandoned when an authoritative snapshot (such as the post-kill refresh) is applied so a stale scan cannot overwrite newer rows. Refresh progress is intentionally not surfaced in the status bar.

**Parent-context note:** Steps 8–9 add `parent:` filtering and parent sorting, which are only meaningful if rows actually carry parent data. To avoid shipping a filter and a sort that silently match nothing, the Linux collector's parent-PID and parent-name collection (originally Phase 5 steps 1–2) was implemented as part of this phase: `parent_pid` is read from `/proc/<pid>/status` and the parent name from `/proc/<ppid>/comm`, and the details-panel parent line is fed by the same data. Child-PID collection stays in Phase 5.

### Done when

- Search feels immediate on normal developer machines.
- Refresh does not jump selection unnecessarily.
- Filters and sorting work together predictably.
- CLI and TUI filtering produce consistent results.
- Collector errors are visible without erasing the last good table.

### Do not build yet

- Killing from the UI.
- Docker-specific filtering.
- Remote host management.

---

## Phase 5 - Process Context And Protected Processes

**Goal:** Show enough process context that users understand what they are looking at before terminating anything.

**Why this comes before safe termination:** A port owner might be a child of an editor, AI agent, dev tool, Docker process, database, or system service. The app should explain risk before offering action.

**Expected result:** The selected row shows parent process information, child process hints, and protected-process warnings when available.

### Build steps

1. ~~Extend process metadata collection to include parent PID where the platform exposes it.~~ **Done in Phase 4** to back the `parent:` filter and parent sort: the Linux collector reads `PPid` from `/proc/<pid>/status`.
2. ~~Resolve parent process name when permitted.~~ **Done in Phase 4:** the parent name is read from `/proc/<ppid>/comm`.
3. **Done in Phase 5:** collect direct child PIDs for the selected process where practical. The Linux implementation scans `/proc` only when the details modal is opened for the selected row, caches that selected-row context until refresh, and caps displayed children.
4. **Done in Phase 5:** resolve child process names from `/proc/<pid>/comm` where permitted, as part of the details-modal context load.
5. **Partially done in Phase 5:** show the selected process owner as a UID when `/proc/<pid>/status` exposes it. `process_start_time` is intentionally not displayed yet because the current `/proc` source needs clock-tick and boot-time conversion to become a useful timestamp; do not add a raw tick counter to the UI.
6. **Done in Phase 5:** add a separate no-match port diagnostic that can scan process command lines for likely related processes when an explicit port search/filter finds no confirmed socket. This must never create a fake port row, never claim ownership, and never weaken the invariant that the main table only contains OS-confirmed listening TCP or bound UDP sockets.
7. **Done in Phase 5:** use strict port-shaped matchers for the diagnostic, not raw substring search. Good matches include socket-shaped text such as `:3000`, `127.0.0.1:3000`, `[::1]:3000`, flag-shaped text such as `--port 3000`, `--port=3000`, `-p 3000`, and environment/config-shaped text such as `PORT=3000`; weak incidental numbers such as `--timeout 3000`, `--max-bytes 3000`, `3000k`, or version numbers must not produce confident hints.
8. **Done in Phase 5:** keep the CLI contract stable for diagnostics: `kickoutchi list --port 3000` still exits `3` when no confirmed socket exists, diagnostic hints print to stderr in human table mode, and `list --json` is not polluted with hints unless a dedicated JSON contract is designed later.
9. **Done in Phase 5:** phrase diagnostics as evidence, not diagnosis: `No listening socket found on port 3000. Possible related process: PID 12345 python3 -m http.server 3000 references this port, but no socket was confirmed.` Do not claim whether the process failed to bind, is still starting, or is in another network namespace unless the app can prove that separately.
10. **Done in Phase 5:** add `protection.rs` for protected-process matching.
11. **Done in Phase 1/5:** seed protected-process defaults with `docker`, `postgres`, `systemd`, `explorer.exe`, and `WindowServer`.
12. **Done before Phase 5:** merge config-defined protected process names with defaults.
13. **Done in Phase 5:** use platform-appropriate matching rules, such as case-insensitive matching on Windows.
14. **Done in Phase 4:** render parent process in the details panel.
15. **Done in Phase 5:** render child process count in the details panel.
16. **Done in Phase 5:** add a details modal that can show child processes when available.
17. **Done in Phase 2/5:** add visual warning text for protected processes.
18. **Done in Phase 5:** add tests for protected-process matching, process-tree rendering, diagnostic matcher behavior, CLI stderr/exit-code behavior, and JSON non-pollution.

### Done when

- Details show parent process information when available.
- Details show child process information when available.
- Rows still render clearly when parent or child metadata is restricted.
- Default protected process names trigger a warning.
- The protected process list can be extended in config.
- Tests cover platform-specific protected-name matching.
- No-match port diagnostics can point to possible related processes without adding unconfirmed rows or changing CLI exit-code/JSON contracts.

### Do not build yet

- Actual kill execution.
- Docker container resolution.

---

## Phase 6 - Safe Termination MVP

**Goal:** Let users terminate stale port owners safely from the TUI and CLI.

**Why this is the Linux MVP milestone:** This phase completes the core promise: find what owns a port, understand the risk, confirm the action, terminate it, and see the port disappear.

**Expected result:** On Linux, a user can start a local server, find it in Kickoutchi, press `x`, confirm, and see the port disappear after refresh.

### Build steps

1. **Done in Phase 6:** create `process.rs` for process termination operations.
2. **Done in Phase 6:** add a typed result for termination outcomes: success, permission denied, already exited, cancelled, protected process, stale confirmed target, unsafe PID, and unknown failure.
3. **Done in Phase 6:** add guardrails that block PID `0`, PID `1`, and Kickoutchi's own PID.
4. **Done in Phase 6 and hardened after Phase 6:** add normal terminate per platform, starting with Unix `SIGTERM` on Linux. Linux opens a pidfd before pre-signal revalidation and sends through `pidfd_send_signal`, so the final signal is tied to the prepared process handle rather than a recycled raw PID. Real signal delivery is gated to Linux until native non-Linux collectors exist, so fake non-Linux rows can never terminate arbitrary local PIDs.
5. **Done in Phase 6 and hardened after Phase 6:** add force kill per platform, starting with Unix `SIGKILL` on Linux, using the same pidfd-backed delivery path.
6. **Done in Phase 6:** add `command.rs` to render the equivalent command shown to users.
7. **Done in Phase 6:** in the TUI, map `x` to normal termination confirmation.
8. **Done in Phase 6:** in the TUI, map `X` to force-kill confirmation.
9. **Done in Phase 6:** show PID, process name, port, protocol, and equivalent command in the confirmation modal.
10. **Done in Phase 6:** make force-kill require a different confirmation path from normal termination by requiring typed `force` confirmation when `confirm_force_kill` is enabled.
11. **Done in Phase 6:** make protected processes require stronger confirmation by typing the PID or process name.
12. **Done in Phase 6:** warn when the selected PID has child processes.
13. **Done in Phase 6:** prefer normal termination before recommending force kill in UI copy.
14. **Done in Phase 6 and hardened after Phase 6:** refresh immediately after every kill attempt. Before sending a signal, open the Linux pidfd, re-collect, and verify that the confirmed PID still owns the confirmed port rows; if the target changed, abort and refresh instead of risking PID reuse, and if a visible port's owning PID becomes unavailable during revalidation, abort with the documented permission-denied exit path instead of sending a signal. The pidfd is opened before revalidation so a post-validation PID recycle cannot redirect the signal to a different process.
15. **Done in Phase 6:** show clear success, cancelled, permission denied, already exited, and failure messages.
16. **Done in Phase 6:** wire `kickoutchi kill --pid <PID>` and `kickoutchi kill --port <PORT>` to the same safety rules.
17. **Done in Phase 6:** resolve ambiguous kill targets explicitly instead of silently acting on the first match. A port number can be owned by more than one process (TCP and UDP sharing the same port, `SO_REUSEPORT` listeners with different PIDs, or forked/inherited listeners that share the same socket inode), so when `kill --port` matches rows with more than one distinct PID, refuse with a message listing the candidates and require `--pid`. When one PID owns several matching rows, the confirmation names every affected port, not just the first. On Linux, socket-inode ownership keeps every PID that references a collected target inode so shared listeners cannot be collapsed to one arbitrary owner.
18. **Done in Phase 6:** keep `--yes` convenient for scripts, but do not let it bypass protected-process extra confirmation.
19. **Done in Phase 6 and hardened after Phase 6:** add tests for unsafe PID guardrails, confirmation decisions, prepared-handle ordering, ambiguous-target resolution including inherited/shared socket owners, command rendering, CLI diagnostic stdout/stderr contracts, JSON non-pollution, and exit codes.

### Done when

- Normal terminate works for a user-owned Linux process.
- Force kill requires separate confirmation.
- `python3 -m http.server 3000` can be terminated through the TUI and CLI.
- The app cannot kill PID `0`, PID `1`, or itself.
- `kill --port` on a port owned by more than one PID refuses to guess and names the candidate processes.
- Protected processes require stronger confirmation.
- Permission errors are shown clearly.
- The table refreshes after termination and the freed port disappears.

### Do not build yet

- Killing remote processes.
- Background daemon behavior.

---

## Phase 7 - Windows Native Collector And Termination

**Status: Implemented.** Linux remains the primary supported platform, but the Windows native collector and process-handle termination path are now built and covered by Windows CI. (WSL2 dev-server ports are still covered by the Linux build, since WSL2 is Linux.)

**Goal:** Bring the same core behavior to Windows using Windows APIs instead of parsing `netstat`.

**Why this comes after the Linux MVP:** The product behavior is already proven. This phase adapts collection and termination to Windows while reusing the shared model, UI, CLI, filters, and safety rules.

**Expected result:** In Windows Terminal, Kickoutchi shows real listening TCP ports and bound UDP ports, resolves process metadata where possible, and can safely terminate user-owned processes.

### Build steps

1. **Done in Phase 7:** create `platform/windows.rs` behind `cfg(windows)`.
2. **Done in Phase 7:** wrap `GetExtendedTcpTable` for TCP rows with owner PID.
3. **Done in Phase 7:** wrap `GetExtendedUdpTable` for UDP rows with owner PID.
4. **Done in Phase 7:** normalize IPv4 TCP and UDP rows into `PortEntry`.
5. **Done in Phase 7:** normalize IPv6 TCP and UDP rows into `PortEntry`.
6. **Done in Phase 7:** filter TCP rows to `LISTEN`.
7. **Done in Phase 7:** treat UDP rows as bound sockets.
8. **Done in Phase 7:** resolve process name, executable path, and command line with `sysinfo` where permissions allow it.
9. **Done in Phase 7:** handle access-denied process metadata as partial rows.
10. **Done in Phase 7:** implement the normal termination request with a prepared Windows process handle and `TerminateProcess`, with `y` confirmation and a warning that Windows delivery is immediate.
11. **Done in Phase 7:** implement force kill with the same prepared process-handle delivery, but keep the stronger typed `force` confirmation for explicit force requests.
12. **Done in Phase 7:** render Windows command equivalents as `taskkill /F /PID <PID>` for both paths because both use `TerminateProcess`.
13. **Done in Phase 7:** verify that protected-process matching is case-insensitive on Windows.
14. **Done in Phase 7:** add Windows-only smoke tests behind `cfg(windows)` for real list and interactive kill behavior.
15. **Done in Phase 7:** add CI coverage for formatting, tests, and clippy on Windows.

### Done when

- The app runs in Windows Terminal.
- A local dev server appears with the correct PID.
- UDP rows render as bound sockets.
- Access-denied rows are displayed clearly.
- Normal termination request works for a user-owned process and accepts `y` confirmation.
- Force kill uses the stronger typed `force` confirmation path.
- Windows CI passes.

### Do not build yet

- Windows package manager releases.
- Docker Desktop container resolution.
- Windows service management beyond owned port processes.

---

## Phase 8 - macOS Native Collector And Termination

**Status: Implemented; needs runtime validation on a real Mac or macOS CI run.** macOS has the most awkward native APIs of the three platforms, so the implementation keeps all Darwin FFI inside `platform/macos.rs` and leaves `lsof` out of the default path.

**Goal:** Bring the same core behavior to macOS using native process/socket APIs by default.

**Why this comes after Windows:** macOS socket inspection is awkward enough to deserve its own focused phase. Keep it separate so Linux and Windows do not get blocked by macOS-specific FFI details.

**Expected result:** In Terminal.app and iTerm2, Kickoutchi shows real listening TCP ports and bound UDP ports, resolves process metadata where possible, and can safely terminate user-owned processes.

### Build steps

1. **Done in Phase 8:** create `platform/macos.rs` behind `cfg(target_os = "macos")`.
2. **Done in Phase 8:** add a small macOS-only FFI layer for the needed `libproc` and `sysctl` calls.
3. **Done in Phase 8:** enumerate processes with `libproc`.
4. **Done in Phase 8:** use `proc_pidinfo` with `PROC_PIDLISTFDS` to list file descriptors for each PID.
5. **Done in Phase 8:** use `proc_pidfdinfo` to inspect socket file descriptors.
6. **Done in Phase 8:** identify TCP sockets in listen state.
7. **Done in Phase 8:** identify UDP sockets bound to a local address and port.
8. **Done in Phase 8:** resolve process name with `proc_name`.
9. **Done in Phase 8:** resolve executable path with `proc_pidpath` when permitted.
10. **Done in Phase 8:** return partial rows when metadata is restricted.
11. **Done in Phase 8:** implement normal terminate with Unix `SIGTERM`.
12. **Done in Phase 8:** implement force kill with Unix `SIGKILL`.
13. **Done in Phase 8:** render macOS command equivalents as `kill <PID>` and `kill -9 <PID>`.
14. **Not built in Phase 8:** optional `lsof` fallback remains a future explicit debug/fallback path, never the default collector.
15. **Done in Phase 8:** add macOS-only smoke tests behind `cfg(target_os = "macos")`.
16. **Done in Phase 8:** add CI coverage for formatting, tests, and clippy on macOS.

### Done when

- The app runs in Terminal.app and iTerm2.
- A local dev server appears with the correct PID.
- Restricted process details render as partial rows.
- No `lsof` dependency is needed for the default collector.
- Normal termination works for a user-owned process.
- Force kill uses the stronger confirmation path.
- macOS CI is configured and passes before release.

### Do not build yet

- macOS notarized installers.
- Advanced codesigning flows.

---

## Phase 9 - Docker And Container Awareness

**Status: Implemented.** Docker support is intentionally narrow: it explains Docker-owned local ports in the selected-row details view, but it does not become a container dashboard or a lazydocker replacement. Native OS collection remains the source of truth.

**Goal:** Explain Docker-owned ports without making Docker required for normal Kickoutchi usage.

**Why this is optional:** Docker metadata is helpful, but native OS process detection must remain the reliable core. Kickoutchi should still be excellent on machines with no Docker installed.

**Expected result:** When a port appears to be owned by Docker proxy/backend behavior, or has partial metadata with no readable process name and Docker reports a matching published host port, the details panel can show the likely container, compose service, and safer Docker command.

### Build steps

1. **Done in Phase 9:** detect common Docker proxy/backend process names, including `docker-proxy`, `dockerd`, Docker Desktop backend names, and related helper names.
2. **Done in Phase 9:** detect whether Docker CLI is available by attempting a bounded `docker container ls --filter publish=<port>/<proto> --format json` lookup only for selected rows that already look Docker-owned or have partial metadata with no readable process name.
3. **Done in Phase 9:** if Docker is unavailable, stopped, slow, returns an error, or emits malformed output, skip Docker enrichment silently except for debug logs.
4. **Done in Phase 9:** resolve container names and IDs for published host ports when possible.
5. **Done in Phase 9:** resolve Compose project and service labels from Docker's label output when available.
6. **Done in Phase 9:** add optional Docker metadata to selected-row `ProcessContext` and the details view without changing the main table or the stable `list --json` `PortEntry` contract. Selected-row context loads in a background details worker so a slow Docker lookup does not freeze the TUI.
7. **Done in Phase 9:** show an equivalent `docker stop <container>` command only when exactly one container matches.
8. **Done in Phase 9:** treat Docker metadata failures as enrichment failures, not collector failures.
9. **Done in Phase 9:** add fixture-style unit tests for Docker JSON output parsing, published-port parsing, Compose labels, protocol/address matching, malformed rows, and UI details rendering.
10. **Done in Phase 9:** add manual testing notes for Docker Desktop, Linux Docker Engine, and Compose.

### Done when

- Docker-owned ports show container name when available.
- Details can explain `Port 5432 -> docker-proxy -> container postgres-dev`.
- Docker metadata failures do not break normal port collection.
- The TUI still works on machines without Docker installed.
- Docker support is clearly documented as optional.

### Manual validation notes

Linux Docker Engine / Docker Desktop smoke path:

```sh
docker run --rm --name kickoutchi-phase9-nginx -p 127.0.0.1:18080:80 nginx:alpine
kickoutchi
```

Then select the `18080` row and open details. The row should still be an OS-confirmed local socket, but details may add Docker context such as `kickoutchi-phase9-nginx 18080->80/tcp` and `docker stop kickoutchi-phase9-nginx`.

Compose smoke path:

```sh
docker compose up -d
kickoutchi
```

Select a published Compose-owned port and open details. When Docker labels are available, details should include the Compose project/service. If Docker is unavailable or the daemon is stopped, Kickoutchi should still list ports normally and simply omit Docker details.

---

## Phase 10 - Packaging, Release, And Documentation

**Goal:** Produce installable binaries and clear documentation so real users can install, run, and trust Kickoutchi.

**Why this comes after core behavior:** Packaging should happen after the behavior is stable enough that install instructions, release artifacts, and checksums will not churn constantly. Optional power-user features can still come later without blocking the first public release.

**Expected result:** A pushed version tag drives a `cargo-dist`-generated release that publishes working Linux, macOS, and Windows archives with per-artifact checksums, a release-wide checksum file, generated shell/PowerShell installers, and clear README install instructions. Registry/package-manager publication remains explicit and manual so a tag cannot silently publish to crates.io, the AUR, Homebrew, or winget.

### Release tooling decision

Kickoutchi uses **`cargo-dist`** (the `dist` tool) as the release pipeline rather than a hand-written GitHub Actions build matrix or a Go-oriented tool like GoReleaser.

Why `cargo-dist`:

- It is Rust-native and keeps release config in `dist-workspace.toml`, while still reading crate metadata from `Cargo.toml`.
- It generates the GitHub Actions release workflow, so the multi-target build matrix is maintained by the tool instead of by hand.
- It cross-builds all target triples, archives them (`.tar.xz` for Linux/macOS, `.zip` for Windows), emits per-artifact SHA-256 checksums and a `dist-manifest.json`, and uploads everything to a GitHub Release.
- It produces the `curl | sh` and PowerShell one-line installers from the same config, covering the direct GitHub Release install path without extra scripting.
- It does not require a Zig cross-compilation toolchain, unlike GoReleaser's experimental Rust builder.

What `cargo-dist` does **not** own, to avoid drift with the existing plans:

- The **Nix flake** (`flake.nix`) stays the source of truth for `nix run` / `nix profile install`; it is not generated by `cargo-dist`.
- The **AUR `PKGBUILD`** files under `packaging/arch/` stay hand-maintained and consume the `cargo-dist` release artifacts (for `kickoutchi-bin`) or build from source (for `kickoutchi`).
- **crates.io** publishing (`cargo publish`) remains a separate step; `cargo-dist` handles binaries and installers, not the crate registry.
- Homebrew and winget publication are out of scope for the first release; they should consume the proven GitHub Release artifacts later.
- macOS **codesigning and notarization** are out of scope for the first release; unsigned binaries ship with clear install notes.
- The **landing page website** (built with Astro, deployed to Cloudflare Pages at `kickoutchi.com`) lives in its own repository and deploys separately; `cargo-dist` only produces the release binaries and installers that the site links to.

### Build steps

1. **Done after Phase 6 and expanded later:** add GitHub Actions CI for every supported OS that runs on pushes and pull requests, separate from the release workflow.
2. **Done after Phase 6:** run `cargo fmt --all --check` in CI.
3. **Done after Phase 6:** run clippy on all targets in CI.
4. **Done after Phase 6 and expanded later:** run tests in CI on every supported operating system.
5. **Done in Phase 10:** install and initialize `cargo-dist` with `dist init`, writing release config to `dist-workspace.toml`. This is the CD/release workflow and stays separate from the regular CI workflow.
6. **Done in Phase 10:** configure release target triples for `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `aarch64-apple-darwin`, and `x86_64-apple-darwin`.
7. **Done in Phase 10:** use the archive formats generated by `cargo-dist`: `.tar.xz` for Linux/macOS and `.zip` for Windows.
8. **Done in Phase 10:** enable the `shell` and `powershell` installers. Defer Homebrew formula output until a tap is ready.
9. **Done in Phase 10:** let `cargo-dist generate` produce `.github/workflows/release.yml`; verify the plan locally with `dist plan --tag v0.1.0`.
10. **Pending first release run:** confirm the GitHub Release publishes per-artifact SHA-256 checksums, `sha256.sum`, and `dist-manifest.json`.
11. **Manual release step:** cut releases by pushing a version tag (for example `v0.1.0`) so the generated workflow builds, checksums, and uploads every artifact to GitHub Releases.
12. **Done in Phase 10:** add `README.md` install instructions for the GitHub Release installers, direct archives, Cargo install, source build, Nix, and Arch, and link to the live landing page at `kickoutchi.com`.
13. **Done earlier:** add `LICENSE` with MIT text.
14. Add shell completions and man page only if they are ready and tested.
15. **Done in Phase 10:** add `flake.nix` for native Nix install and `nix run`.
16. **Done in Phase 10:** add Arch `PKGBUILD` templates under `packaging/arch/`.
17. **Manual package step:** validate Arch packaging with `makepkg --clean --syncdeps --install` and `namcap` once the release archives and final checksums exist.
18. **Manual package step:** publish `kickoutchi-bin` to the AUR first.
19. **Manual package step:** publish source-building `kickoutchi` after the binary package is stable.
20. **Manual registry step:** publish to crates.io only after the dry run passes and the release notes are final.

### Done when

- Pushing a version tag triggers the `cargo-dist` release workflow with no manual build steps.
- Linux, macOS, and Windows release archives contain both `kickoutchi` and `kick`.
- Releases include per-artifact SHA-256 checksums, `sha256.sum`, and `dist-manifest.json`.
- The `curl | sh` installer downloads and installs the correct Unix binary.
- The PowerShell installer downloads and installs the correct Windows binary.
- `cargo install --locked kickoutchi` works after crates.io publication.
- `nix run github:nuggocto/kickoutchi` works on Linux and macOS.
- `nix profile install github:nuggocto/kickoutchi` works on Linux and macOS.
- Arch AUR package can install with `yay -S kickoutchi-bin` after publication.
- README explains permissions, safe termination, protected processes, and platform limitations.
- README links to the live landing page at `kickoutchi.com`.
- A new user can install Kickoutchi and complete the core flow without reading the source code.

Deferred done-when items for later package-manager work:

- The Homebrew formula installs the correct macOS/Linux binary from a maintained tap.
- The winget manifest installs the correct Windows binary.

---

## Testing Strategy

- Unit tests for Linux `/proc/net` parsing
- Unit tests for address and port decoding
- Unit tests for filter parsing
- Unit tests for sort ordering
- Unit tests for command rendering per OS
- Unit tests for unsafe PID guardrails
- Unit tests for prepared termination handle ordering before revalidation and signal delivery
- Unit tests for config loading and CLI override precedence
- Unit tests for non-TUI table and JSON output
- Unit tests for protected-process matching
- Unit tests for process-tree rendering
- UI snapshot tests for table, details, help, and confirmation modal
- TUI state tests for single-flight background refresh and completed refresh polling
- Platform smoke tests for collectors behind `cfg(target_os = "...")`
- Integration tests that run the built binary to pin script-facing CLI contracts (stderr diagnostics, `list --json` non-pollution, exit codes)
- Windows integration tests that run the built binary against a real local TCP listener and verify interactive `kill --pid` removes the port
- macOS integration tests that run the built binary against a real local TCP listener and verify interactive `kill --pid` removes the port

Verification commands:

```sh
mise run check
mise run tui
```

Equivalent raw Cargo commands:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo run --locked
```

`--all-features` stays in the verification commands so any optional feature added later is covered automatically. The project currently defines no optional features, so this builds the same as a default build.

Manual test commands:

```sh
# Linux/macOS
python3 -m http.server 3000

# Windows PowerShell
python -m http.server 3000
```

Then open Kickoutchi and verify port `3000` shows the Python PID.

---

## Honest Notes

The TUI is easy. The clean cross-platform socket collection is the real work.

Linux is straightforward with `/proc`. Windows is clean with IP Helper APIs. macOS is possible, but its native process/socket APIs are more awkward, so it should get its own focused phase instead of being hidden behind fragile command parsing.

The first serious milestone should be:

```txt
cargo run
table opens cleanly
local port 3000 appears with PID and process name
select row
see kill command
press x
confirm
process terminates
port disappears after refresh
```

Do not start by parsing `lsof`, `ss`, or `netstat` as the main path. Those can exist as fallback/debug collectors, but Kickoutchi should be designed around native collectors from the beginning.
