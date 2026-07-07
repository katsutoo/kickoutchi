# Kickoutchi ༼⁠ ⁠つ⁠ ⁠◕⁠‿⁠◕⁠ ⁠༽⁠つ

**"What are you doing in my swamp?!"** but for whatever is squatting on your
local ports.

Kickoutchi is a small TUI and CLI that shows open local TCP/UDP ports, names the
process behind them when the OS allows it, and lets you kick stale dev servers
out safely. Two binaries, one tool: `kickoutchi` is the full name, `kick` is the
daily-use shortcut.

Website: <https://kickoutchi.com>

## What You Need

- **Rust 1.95.0+** to build from source or install with Cargo.
- **Git** if you are cloning the repository or using `cargo install --git`.
- **Linux 5.3+** for safe termination through `pidfd`; listing ports works on
  older kernels too.
- **Windows** with the normal Rust C++ build tooling available.
- **macOS** with normal developer tooling available.

## What It Does

- Lists listening TCP sockets and bound UDP sockets.
- Shows address, port, PID, process name, parent, path, command, bind scope, and
  permission status when available.
- Explains Docker-owned or partial-metadata ports in details when Docker CLI
  metadata is available; Docker is optional and never required for normal port
  listing.
- Opens as a terminal UI when run without a command.
- Works as a script-friendly CLI with table or JSON output.
- Asks before termination, because Donkey may yell but Donkey does not kill
  random swamp residents without confirmation.
- Kicks out whole process trees (`kill --tree` in the CLI; `t`/`T` in the TUI
  on Linux and macOS): Linux/macOS freeze the root first so it cannot spawn
  more children, then sweep and signal the verified tree leaves-first. Windows
  uses Job Object containment instead: it preflights safely, assigns the root as
  the commit boundary, converges descendants, then hard-terminates contained
  members. Useful for dev servers, agents, and runners that leave workers
  behind — even ones actively spawning.
- Kicks out whole process groups too (`kill --group`, Linux and macOS): same
  freeze-first pipeline, but membership comes from the POSIX process group
  instead of parent links — for survivors that reparented away from the tree
  (double-fork daemons, orphaned workers) and for spawners too big for the
  tree cap. The confirmation lists every member, because a group can contain
  more than you think.
- Inspects a process family without signalling anything (`inspect --port` or
  `--pid`): ancestors, descendants, siblings, ports, and kill hints, so you can
  pick the right root before using `--tree` or `--group` where available.
  Windows omits the POSIX process-group section because there is no Windows
  process-group analog.
- Uses native collectors: no `ss`, `netstat`, or `lsof` parsing in the default
  path.

## Install

Pick your swamp path.

Linux and macOS users can use the generated GitHub Release installer:

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-installer.sh \
  | sh
```

Windows users get the PowerShell spell:

```powershell
irm https://github.com/nuggocto/kickoutchi/releases/latest/download/kickoutchi-installer.ps1 | iex
```

Installer-based installs also include `kickoutchi-update`. Run it later to check
for and install the newest GitHub Release:

```sh
kickoutchi-update
```

If you installed Kickoutchi before this updater existed, rerun the latest
installer once to get `kickoutchi-update`; later upgrades can use the updater.

Every release also includes direct archives for Linux, macOS, and Windows, plus
matching `.sha256` files and a release-wide `sha256.sum`. If installers make you
nervous, grab the archive, check the hash, and run `kickoutchi` or `kick`.

macOS users can install from the Homebrew tap (one formula, both `kickoutchi`
and `kick`):

```sh
brew install nuggocto/tap/kickoutchi
```

Windows users can install from the Scoop bucket:

```powershell
scoop bucket add nuggocto https://github.com/nuggocto/scoop-bucket
scoop install kickoutchi
```

Arch and Nix are first-class too. The Homebrew formula is generated and pushed to
the tap on every release; the Scoop manifest lives in `packaging/scoop/` and
auto-updates its bucket. winget is not planned right now. Homebrew users should
use `nuggocto/tap`; PRs for winget or Homebrew/core are welcome if someone wants
to maintain them :3.

Rust users can install from Git:

```sh
cargo install --locked --git https://github.com/nuggocto/kickoutchi
```

Nix users can run or install the flake directly:

```sh
nix run github:nuggocto/kickoutchi
nix run github:nuggocto/kickoutchi#kick -- list
nix profile install github:nuggocto/kickoutchi
```

The flake is locked in the repository for reproducible builds; release commits
update `flake.lock` deliberately instead of floating silently with nixpkgs.

Arch users can use the AUR package after it is published:

```sh
yay -S kickoutchi-bin
```

The AUR templates live in `packaging/arch/` for maintainers who want to build or
review the package locally before publication. They are pinned to the latest
published GitHub Release assets and checksums — bumped only after each release's
assets exist, never against placeholders — and AUR publication waits until AUR
account creation is available again.

Then use either binary name:

```sh
kick list
kick kill --port 3000
kickoutchi
```

Running either binary with no command opens the TUI.

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
cargo run --bin kick -- inspect --port 3000  # read-only family view
cargo run --bin kick -- inspect --pid 12345  # inspect a portless supervisor
cargo run --bin kick -- kill --port 3000 --tree  # kick out the whole tree
cargo run --bin kick -- kill --port 3000 --group  # kick out the whole process group (Linux/macOS)
```

Kickoutchi asks before it terminates anything unless you pass `--yes`. Use
`--yes` only when you already trust the exact target; protected processes still
require stronger confirmation.

## Install Locally

```sh
cargo install --path . --locked
```

## Platform Notes

- **Linux:** native `/proc` collection. Termination uses `pidfd`, so the final
  signal is tied to the prepared process handle instead of a recycled PID.
- **Windows:** native IP Helper collection, process-handle single-PID
  termination, read-only `inspect`, and CLI `kill --tree` through Job Object
  containment. Windows termination is hard termination (`TerminateProcess` /
  `TerminateJobObject`); there is no graceful signal tier. Use an elevated
  terminal when higher-privilege processes hide metadata or reject termination.
  `--group` and the TUI `t`/`T` tree keys are not available on Windows. Native
  Windows cannot see individual Linux processes inside WSL2; use the Linux build
  inside WSL2 for those trees.
- **macOS:** native `libproc` / `sysctl` collection and Unix `SIGTERM` / `SIGKILL`
  termination. macOS has no pidfd, so Kickoutchi re-checks process identity right
  before signalling and refuses if the PID changed faces.

## Safety Rules

- PID `0`, PID `1`, Kickoutchi's own PID, and Windows PID `4` are blocked.
- `kill --port` refuses ambiguous ports instead of guessing.
- Protected processes require typing the PID or process name.
- Force kill requires stronger confirmation by default.
- Termination targets only the confirmed PID; `--tree` and `--group` are the
  explicit opt-ins for more. They require the typed word (`tree` or `group`, or
  `force`) unless `--yes` passes the all-clear scoped-kill gates. `--group` is
  Linux/macOS-only.
- Linux/macOS tree and group kills refuse anything uncertain: a set over its cap
  (256 for trees, 512 for groups), an unsafe or protected member, unreadable
  process metadata, or an identity that changed under it — and every refusal
  after freezing thaws what it stopped.
- Windows tree kill refuses cleanly before Job Object commit when preflight sees
  an unsafe PID, protected descendant, incomplete metadata, identity drift, or an
  over-cap tree. If Windows reports a parent link into the confirmed tree but the
  creation-time metadata needed to sanity-check that edge is missing, Kickoutchi
  refuses as incomplete metadata rather than omitting a possible descendant.
  After the root is assigned to the Job Object, failures are reported as partial
  containment, fallback termination, or not-terminated PIDs; they are never
  hidden as full success. The preview is an observed tree, not the complete
  blast radius: Windows may also terminate newly spawned job-contained children
  that were not visible before confirmation.
- A protected tree or group root requires its PID or name *and* the scope
  word, checked again against a fresh scan right before scoped execution.
- Group kill shows every member before asking, never signals a raw `-pgid`,
  and refuses outright if Kickoutchi itself sits in the target group.
