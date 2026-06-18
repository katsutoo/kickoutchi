# kickoutchi

Port janitor

## Requirements

- Linux 5.3 or newer for process termination: `kick kill` and the TUI `x` / `X`
  actions use the `pidfd` syscalls. Listing ports works on older kernels too.
