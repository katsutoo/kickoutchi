# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project foundation (Phase 0): Rust 1.95.0 pinned via `mise.toml`, edition
  2024, and strict lints (`warnings = "deny"`, `clippy::pedantic`).
- Core dependency set: ratatui, crossterm, clap, serde, serde_json, toml,
  thiserror, anyhow, tracing, and tracing-subscriber.
- Module boundaries: `main`, `config`, `error`, and `ui`.
- Safe terminal lifecycle: an RAII `TerminalGuard` that enters raw mode and the
  alternate screen and restores both on drop (clean exit, propagated error, or
  panic), plus a panic hook that restores the terminal before the message prints.
- Minimal event loop with a bounded poll that quits on `q`, `Esc`, or `Ctrl+C`.
- `tracing` diagnostics routed to stderr only, never the TUI surface.
- Unit tests for the quit predicate, including the key-release edge case.

[Unreleased]: https://github.com/nuggocto/kickoutchi/commits/shrek
