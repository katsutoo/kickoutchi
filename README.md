# kickoutchi

A clean TUI and CLI port janitor: see which process owns each open local port and
kick it out safely.

## Requirements

- Rust 1.95.0 or newer.
- Git, if you are cloning the repository.
- Linux 5.3 or newer for process termination. Listing ports works on older
  kernels too, but `kick kill` and the TUI `x` / `X` actions use `pidfd`.
- Windows support uses native Windows APIs. If the Rust installer or build says
  `link.exe` is missing, install Visual Studio Build Tools with the C++ build
  tools workload.
- macOS can build and run the app shell, but native macOS port collection is not
  implemented yet. Use these steps to get the machine ready for the macOS port.

## Install Rust

### With mise

If you use `mise`, this is the easiest way to get the repository-ready Rust
toolchain:

```sh
mise install
```

That reads `mise.toml` and installs the pinned Rust version for this project.
After that, you can run the Cargo commands below from the repository root.

If you do not use `mise`, install Rust manually for your platform.

### Windows

In PowerShell:

```powershell
winget install Rustlang.Rustup
```

Then close and reopen PowerShell so Cargo is on `PATH`.

If you do not use `winget`, install `rustup-init.exe` from
[rustup.rs](https://rustup.rs/).

### macOS and Linux

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then restart your shell or run the command printed by the installer to load
Cargo into `PATH`.

Check that Rust is ready:

```sh
rustc --version
cargo --version
```

## Get The Code

```sh
git clone https://github.com/nuggocto/kickoutchi.git
cd kickoutchi
```

If you already have the repository, just `cd` into it.

## Run Locally Without Installing

Use this path while developing or testing the project from source. You do not
need `cargo install` for these commands.

Open the TUI:

```sh
cargo run --locked
```

List ports from the CLI:

```sh
cargo run --locked --bin kick -- list
```

Filter to one port:

```sh
cargo run --locked --bin kick -- list --port 3000
```

Print JSON:

```sh
cargo run --locked --bin kick -- list --json
```

Terminate the process owning a port:

```sh
cargo run --locked --bin kick -- kill --port 3000
```

Kickoutchi asks for confirmation before terminating a process. Avoid `--yes`
until you are intentionally scripting a known-safe target.

## Install Locally

Use this path when you want `kickoutchi` and `kick` available as normal shell
commands outside the repository. This is optional for development.

Install the two local binaries into Cargo's bin directory:

```sh
cargo install --path . --locked
```

After that, run them from any shell:

```sh
kickoutchi
kick list
kick list --port 3000
kick kill --port 3000
```

Cargo installs binaries into:

- Windows: `%USERPROFILE%\.cargo\bin`
- macOS and Linux: `$HOME/.cargo/bin`

If the commands are not found after installation, add that directory to `PATH`
or restart your terminal.

## Verify Your Local Build

Run the same local checks used during development:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

If you use `mise`, the shortcut is:

```sh
mise run check
```

## Platform Notes

- Windows: native port listing and process termination are implemented through
  Windows APIs. Run PowerShell or Windows Terminal as Administrator if you need
  to inspect or terminate higher-privilege processes.
- macOS: setup and build commands are ready, but native macOS collection is still
  pending. Current macOS runs should be treated as development smoke tests, not a
  real port-owner view.
- Linux: native `/proc` collection and `pidfd` termination are implemented.
