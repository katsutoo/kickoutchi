# Native API boundary audit

Audit date: 2026-07-29

Inventory paths updated: 2026-08-04 after a behavior-preserving module split;
the reviewed native boundaries and block counts are unchanged.

This audit covers the explicit native operating-system boundary in the
Kickoutchi 1.3.9 release candidate. It is a finite review of ownership, buffer
contracts, identity stability, and error handling. It is not a mandate to
replace working native integrations.

## Inventory

| Area | Blocks | Primary boundary |
| --- | ---: | --- |
| `src/platform/linux.rs` | 2 | process filesystem links and system limits |
| `src/platform/macos.rs` | 23 | libproc, sysctl, and native socket rows |
| `src/platform/windows.rs` | 31 | process snapshots, handles, and IP Helper tables |
| `src/process.rs`, `src/process/{linux,macos,windows}.rs` | 23 | signals, pidfds, and Windows process handles |
| `src/windows_tree.rs` | 12 | jobs, process handles, membership, and termination |
| `src/ui/mod.rs` | 14 | terminal signal lifecycle and restoration |
| `src/ui/confirm.rs` | 1 | test-only effective-user query |
| `src/cli/watch/{signal,tests}.rs` | 7 | console and signal handler lifecycle, including test-only disposition checks |
| `src/docker.rs` | 6 | user identity, token ownership, and test child reaping |
| **Total** | **119** | |

## Review record

The inventory was evaluated against the following invariants:

- Every acquired file descriptor, process handle, token, snapshot, or job has
  one owner after a successful call and one close-on-drop path. Error paths
  before ownership transfer close or roll back the resource.
- Writable buffers remain live for the full native call. Returned byte and
  element counts are checked before initialization is assumed, a slice is
  formed, or a variable-length row is read.
- Allocations used for native structures provide the required alignment.
  Structure sizes and integer conversions are checked before crossing the API
  boundary.
- OS error state is captured immediately after failure. Expected absence,
  permission failure, stale identity, partial data, and unexpected failure
  remain distinct and default to refusal where authority is uncertain.
- Linux termination uses pidfds after numeric PID validation. macOS termination
  combines start markers, stop acknowledgement, and fresh revalidation.
  Windows termination retains process handles and rechecks job membership and
  process identity across the commit boundary.
- Variant native rows are interpreted only after the protocol or address-family
  selector establishes the corresponding representation.
- Signal and console handlers retain their previous state, restore partial
  installations on error, and restore the complete state during normal
  teardown.

No demonstrated native-boundary defect was found, so the audit made no runtime
code changes. Strict linting, tests, and release builds continue to run on
native Linux, macOS, and Windows workers; platform-specific checks are required
after changes in these files.

## Re-audit triggers

Repeat the affected platform review when:

- an OS API, structure layout, target architecture, or minimum OS version
  changes;
- Rust, `libc`, or `windows-sys` changes a binding used at the boundary;
- ownership, buffer sizing, process identity, signal, job, or error mapping
  logic changes; or
- a native-only compiler warning, test failure, or field report appears.

Review the smallest affected inventory first. Expand to the complete platform
when a shared invariant or binding changed.
