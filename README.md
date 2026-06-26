# Kickoutchi ༼⁠ ⁠つ⁠ ⁠◕⁠‿⁠◕⁠ ⁠༽⁠つ

**"What are you doing in my swamp?!"** but for whatever is squatting on your
local ports.

Kickoutchi is a small TUI and CLI that shows open local TCP/UDP ports, names the
process behind them when the OS allows it, and lets you kick stale dev servers
out safely. Two binaries, one tool: `kickoutchi` is the full name, `kick` is the
daily-use shortcut.

## What You Need

- **Rust 1.95.0+** to build from source.
- **Git** if you are cloning the repository.
- **Linux 5.3+** for safe termination through `pidfd`; listing ports works on
  older kernels too.
- **Windows** with the normal Rust C++ build tooling available.
- **macOS** with normal developer tooling available.

## What It Does

- Lists listening TCP sockets and bound UDP sockets.
- Shows address, port, PID, process name, parent, path, command, bind scope, and
  permission status when available.
- Opens as a terminal UI when run without a command.
- Works as a script-friendly CLI with table or JSON output.
- Asks before termination, because Donkey may yell but Donkey does not kill
  random swamp residents without confirmation.
- Uses native collectors: no `ss`, `netstat`, or `lsof` parsing in the default
  path.

## Get The Code

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
```

## Run From Source

```sh
cargo run                                 # open the TUI
cargo run --bin kick -- list              # list ports
cargo run --bin kick -- list --port 3000  # show one port
cargo run --bin kick -- list --json       # JSON for scripts
cargo run --bin kick -- kill --port 3000  # ask, then kick it out
```

Kickoutchi always asks before it terminates anything. Use `--yes` only when you
already trust the exact target; protected processes still require stronger
confirmation.

## Install Locally

```sh
cargo install --path . --locked
```

Then use either binary name:

```sh
kick list
kick kill --port 3000
kickoutchi
```

Running either binary with no command opens the TUI.

## Platform Notes

- **Linux:** native `/proc` collection. Termination uses `pidfd`, so the final
  signal is tied to the prepared process handle instead of a recycled PID.
- **Windows:** native IP Helper collection and process-handle termination through
  Windows APIs. Use an elevated terminal when higher-privilege processes hide
  metadata or reject termination.
- **macOS:** native `libproc` / `sysctl` collection and Unix `SIGTERM` / `SIGKILL`
  termination. macOS has no pidfd, so Kickoutchi re-checks process identity right
  before signalling and refuses if the PID changed faces.

## Safety Rules

- PID `0`, PID `1`, and Kickoutchi's own PID are blocked.
- `kill --port` refuses ambiguous ports instead of guessing.
- Protected processes require typing the PID or process name.
- Force kill requires stronger confirmation by default.
- Termination targets only the confirmed PID.

## Before You Push

The swamp gates run these checks:

```sh
mise run check
```

Or by hand:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```
