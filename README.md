# Kickoutchi ༼⁠ ⁠つ⁠ ⁠◕⁠‿⁠◕⁠ ⁠༽⁠つ

**"What are you doing in my swamp?!"** • but for whatever's squatting on your
local ports.

A small TUI and CLI that shows which process owns each open port and lets you
kick it out safely. Two binaries, one tool: `kickoutchi` (the full name) and
`kick` (for daily use).

## What you need

- **Rust 1.95.0+** (and Git, if you're cloning).
- **Linux 5.3+** to actually kill things • `kick kill` and the TUI `x` / `X` keys
  ride on `pidfd`. Listing ports works on older kernels too.
- **Windows** uses native APIs. If the build grumbles about a missing `link.exe`,
  install the Visual Studio Build Tools "C++ build tools" workload.
- **macOS** builds and runs the shell, but can't see real ports yet • native
  macOS collection isn't built. Treat it as a test, not a port view, yet.

## Get Rust

Inside the repo, `mise` handles it:

```sh
mise install
```

No `mise`? Install Rust by hand:

- **Windows:** `winget install Rustlang.Rustup` (then reopen PowerShell), or grab
  `rustup-init.exe` from [rustup.rs](https://rustup.rs/).
- **macOS / Linux:** `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

Then check it took: `cargo --version`.

## Get the code

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
```

## Run it from source

No install needed while you're poking around:

```sh
cargo run                                 # open the TUI
cargo run --bin kick -- list              # list ports
cargo run --bin kick -- list --port 3000  # one port
cargo run --bin kick -- list --json       # for scripts
cargo run --bin kick -- kill --port 3000  # kick it out
```

Kickoutchi always asks before it kicks anything out. Keep `--yes` in your pocket
until you're scripting a target you already trust.

## Install it for real

Want `kickoutchi` and `kick` on your `PATH` everywhere?

```sh
cargo install --path . --locked
```

Then, from any shell:

```sh
kick list
kick kill --port 3000
```

Run either name with no arguments to open the TUI. The binaries land in
`~/.cargo/bin` (`%USERPROFILE%\.cargo\bin` on Windows) • add that to `PATH` or
restart your terminal if the shell can't find them.

## Before you push

The same checks the swamp runs on every change:

```sh
mise run check     # or, by hand:
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

## Platform notes

- **Linux:** native `/proc` collection and `pidfd` termination. The real deal.
- **Windows:** native listing and termination via Windows APIs. Run PowerShell or
  Windows Terminal as Administrator to reach higher-privilege processes.
- **macOS:** builds and runs, but native collection is still pending.
