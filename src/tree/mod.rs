//! Process-tree planning plus the Unix freeze-first execution pipeline.
//!
//! Single-process kill (see `process.rs`) is precise on purpose: it signals
//! exactly one confirmed PID. Tree kill is the big ogre button — it terminates a
//! confirmed root together with its descendants — and its whole design exists to
//! win one specific race: a target that keeps spawning children faster than you
//! can kill them.
//!
//! Group kill shares the same freeze-first pipeline but derives membership from
//! the POSIX process group instead of parent links. It exists for the two cases
//! tree scope honestly cannot cover: survivors that reparented away from the
//! tree (double-fork daemons, orphaned workers) and runaway spawners whose tree
//! outgrows the tree cap. It is deliberately never implemented as
//! `kill(-pgid)`: every member is enumerated, frozen, identity-verified, and
//! signalled individually, so the same refusal gates apply to every PID.
//!
//! On Unix, the trick is to freeze before you count. A process observed stopped
//! cannot `fork` unless another actor continues it, so the tree normally stops
//! growing from the root while a bounded re-scan sweep reaches descendants.
//! Identity is re-checked after each observed stop; Linux pins delivery with a
//! pidfd and macOS re-checks start markers at each raw-PID boundary. Any refusal
//! after freezing thaws only processes Kickoutchi transitioned to stopped, so an
//! externally stopped process is not resumed as refusal cleanup. Concurrent
//! external `SIGSTOP`/`SIGCONT` can still race those observations; scoped kill is
//! bounded best-effort convergence, not an atomic kernel transaction.
//!
//! This module is the pure orchestration. All real process I/O — enumerating
//! `/proc`, sending signals — is injected through [`TreeProcessOps`], so the
//! whole pipeline is exercised in tests with a fake that scripts snapshots and
//! records the exact order of stop/continue/signal calls.

mod execute;
mod plan;
#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests;
#[cfg(windows)]
pub(crate) mod windows;

use crate::observation::ProcessStartMarker;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process::KillMode;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::process_evidence::{FreshProcessEvidence, ProcessEvidenceError};

#[cfg(windows)]
pub(crate) use execute::evidence_tree_outcome;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use execute::{
    ScopeAuthorization, TreeKillReport, execute_group_kill, execute_tree_kill,
    pin_root_before_revalidation,
};
pub(crate) use execute::{TreeKillOutcome, TreeRefusalClass};
#[cfg(windows)]
pub(crate) use plan::plan_process_tree_with_index;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use plan::{GroupPlanError, ProcessGroupTarget, group_scope_word, plan_process_group};
pub(crate) use plan::{
    PROCESS_TREE_INDEX_MAX, ProcessTreeIndex, ProcessTreeNode, ProcessTreeTarget, TreePlanError,
    format_pid_list, plan_error_outcome, plan_process_tree, preflight_outcome,
    root_protection_outcome, tree_scope_word, word_confirmation_matches,
};

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
use execute::{FrozenNode, SweepScope, thaw_all, verify_frozen_identities};

/// Hard cap on the number of processes a single tree kill will touch.
///
/// A real dev-server or agent tree is a handful to a few dozen processes. This
/// ceiling is generous for that and still bounds the work per kill. A tree that
/// exceeds it is refused, not partially killed: partial kills of a runaway
/// spawner report false progress while the survivors regrow.
pub(crate) const MAX_TREE_PROCESSES: usize = 256;

/// Hard cap on the number of processes a single group kill will touch.
///
/// Higher than the tree cap because group scope is the designated tool for
/// runaway spawners whose tree outgrows [`MAX_TREE_PROCESSES`]. Still a hard
/// bound: past it the kill is refused, never partially executed. The value
/// also respects a resource budget — on Linux every member holds one pidfd
/// during delivery, and 512 stays comfortably under the common 1024
/// soft file-descriptor limit.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const MAX_GROUP_PROCESSES: usize = 512;

/// Ceiling on group size for a `--yes` prompt skip. A tiny, all-clear group is
/// the only group kill allowed to proceed without the typed word, and the same
/// ceiling is re-applied to the final frozen set: a group that grows past it
/// mid-freeze no longer matches what `--yes` was allowed to skip for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) const GROUP_YES_SKIP_MAX_PROCESSES: usize = 8;

/// One raw process as read from a single snapshot of the process table.
///
/// The platform layer fills these; the pipeline derives every tree relationship
/// from `parent_pid` and every identity check from `start_time_marker`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeProcessInfo {
    pub(crate) pid: u32,
    /// Parent edge accepted for tree walking. On Windows this is set only after
    /// the creation-time sanity rule proves the recorded parent PID has not gone
    /// dangling or been recycled.
    pub(crate) parent_pid: Option<u32>,
    /// A recorded parent PID that could not be sanity-checked because required
    /// creation-time metadata was missing. Tree rendering ignores this edge, but
    /// Windows tree kill treats it as fail-closed partial metadata if the edge
    /// could belong under the confirmed root.
    pub(crate) unverified_parent_pid: Option<u32>,
    pub(crate) parent_process_name: Option<String>,
    pub(crate) process_name: Option<String>,
    pub(crate) start_time_marker: Option<ProcessStartMarker>,
    /// Effective owner UID when readable. Drives the ownership warning in kill
    /// banners; deliberately not part of identity verification, which stands on
    /// the start marker and the scope relation.
    pub(crate) owner_uid: Option<u32>,
    /// Process group ID. `None` means the kernel domain (pgid `0`), which is
    /// never a targetable group. Group kill derives its membership from this
    /// field, so the platform snapshots read it as fail-closed as the start
    /// marker: a live process whose group cannot be read fails the whole scan,
    /// because a hole here would silently exclude a member from the kill.
    pub(crate) process_group: Option<u32>,
}

/// The result of asking the OS to deliver one signal to one process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeSignalResult {
    /// The signal was accepted by the kernel.
    Delivered,
    /// No such process — it exited before we signalled it.
    NotFound,
    /// Permission denied, or any other refusal we treat conservatively as one.
    Denied,
}

/// Result of stopping one member, including cleanup ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeStopResult {
    /// Stopped state was observed. `transitioned` is false when it was already
    /// stopped before Kickoutchi submitted `SIGSTOP`.
    Stopped { transitioned: bool },
    /// The process exited before stopped state could be established.
    NotFound,
    /// The stop failed. A successful submission can still require cleanup when
    /// the bounded stopped-state observation subsequently fails.
    Failed {
        cleanup_required: bool,
        rollback_start_time_marker: Option<ProcessStartMarker>,
        error: TreeStopError,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeStopError {
    PermissionDenied,
    ObservationFailed(String),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stop_deadline_expired() -> TreeStopResult {
    TreeStopResult::Failed {
        cleanup_required: false,
        rollback_start_time_marker: None,
        error: TreeStopError::ObservationFailed(
            "the operation-wide SIGSTOP acknowledgement deadline expired".to_owned(),
        ),
    }
}

/// What portion of the process table a platform snapshot should prove.
///
/// Linux already reads a complete `/proc` table cheaply. macOS uses this during
/// execution to avoid unrelated `EPERM` rows from hiding real scoped members:
/// tree scope can walk descendants directly, and group scope can prove denied
/// rows are outside the confirmed process group before skipping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) enum TreeSnapshotScope {
    #[cfg(target_os = "macos")]
    Full,
    Tree {
        root_pid: u32,
    },
    Group {
        root_pid: u32,
        pgid: u32,
    },
}

/// The injected process I/O the pipeline drives.
///
/// A trait rather than loose closures because there are four related operations
/// and a fake needs to implement all of them coherently (scripted snapshots plus
/// a recorded call log). The real Linux implementation lives in
/// `platform/linux.rs`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) trait TreeProcessOps {
    /// Narrow subsequent snapshots to the scope currently being executed.
    ///
    /// The default keeps platforms and tests with complete snapshots unchanged.
    fn set_snapshot_scope(&mut self, _scope: TreeSnapshotScope) {}

    /// One fresh read of the whole process table.
    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String>;
    /// Pin the confirmed root before execution-time revalidation.
    ///
    /// Linux overrides this to open and retain the root pidfd before the final
    /// identity checks. macOS has no pidfd equivalent, so the default no-op keeps
    /// its existing stop-then-verify safety model.
    fn pin_root_for_revalidation(&mut self, _pid: u32) -> TreeSignalResult {
        TreeSignalResult::Delivered
    }
    /// `SIGSTOP` a process.
    fn stop(&mut self, pid: u32) -> TreeSignalResult;
    /// Stop and wait for observable stopped state, retaining whether cleanup may
    /// later send `SIGCONT`.
    ///
    /// Real Unix signal helpers publish the richer result while preserving the
    /// older signal-shaped `stop` boundary used by platform adapters. Test and
    /// preview implementations that do not publish one retain the historical
    /// assumption that a delivered fake stop made the transition.
    fn stop_checked(&mut self, pid: u32, deadline: std::time::Instant) -> TreeStopResult {
        if self.stop_acknowledgement_now() >= deadline {
            return stop_deadline_expired();
        }
        let result = crate::process::with_tree_stop_deadline(deadline, || self.stop(pid));
        crate::process::take_tree_stop_result(pid).unwrap_or(match result {
            TreeSignalResult::Delivered => TreeStopResult::Stopped { transitioned: true },
            TreeSignalResult::NotFound => TreeStopResult::NotFound,
            TreeSignalResult::Denied => TreeStopResult::Failed {
                cleanup_required: false,
                rollback_start_time_marker: None,
                error: TreeStopError::PermissionDenied,
            },
        })
    }
    /// Clock used to bound stopped-state acknowledgement across this operation.
    /// Implementations normally use the monotonic system clock; deterministic
    /// fakes can override it without sleeping.
    fn stop_acknowledgement_now(&self) -> std::time::Instant {
        std::time::Instant::now()
    }
    /// Capture the identity that accepted `SIGSTOP`, for guarded rollback.
    ///
    /// Linux continuation is pinned by pidfd, so retaining the previously
    /// observed marker is sufficient there. macOS overrides this to read the
    /// identity immediately after the raw-PID stop succeeds.
    fn rollback_identity_after_stop(
        &mut self,
        _pid: u32,
        prior_marker: Option<ProcessStartMarker>,
    ) -> Option<ProcessStartMarker> {
        prior_marker
    }
    /// `SIGCONT` a process.
    ///
    /// `NotFound` leaves no stopped survivor — the process is gone, so there is
    /// nothing to resume and nothing to report. Only `Denied` is a cleanup
    /// failure: the process is still there and may still be stopped. Every
    /// caller classifies on `Denied` alone; see the executor's thaw cleanup.
    fn cont(&mut self, pid: u32) -> TreeSignalResult;
    /// Retain the verified identity needed to make a raw-PID thaw safe.
    fn prepare_thaw(&mut self, _pid: u32, _marker: Option<ProcessStartMarker>) {}
    /// Prepare reuse-proof delivery for a stopped, verified process.
    ///
    /// `verified_start_marker` is the start marker the post-stop verification
    /// just proved. Linux ignores it (the pidfd held since the first stop is
    /// the reuse proof); macOS has no pidfd, so it records the marker and
    /// re-checks it immediately before every raw-PID signal to the member.
    fn prepare_delivery(
        &mut self,
        pid: u32,
        verified_start_marker: Option<ProcessStartMarker>,
    ) -> TreeSignalResult;
    /// Read identity and name again at the final delivery boundary.
    fn fresh_process_evidence(
        &mut self,
        pid: u32,
    ) -> Result<FreshProcessEvidence, ProcessEvidenceError> {
        let snapshot = self
            .snapshot()
            .map_err(|_| ProcessEvidenceError::Missing { pid })?;
        let info = snapshot
            .iter()
            .find(|info| info.pid == pid)
            .ok_or(ProcessEvidenceError::Missing { pid })?;
        Ok(FreshProcessEvidence {
            pid,
            start_marker: info
                .start_time_marker
                .ok_or(ProcessEvidenceError::Missing { pid })?,
            name: info
                .process_name
                .clone()
                .ok_or(ProcessEvidenceError::NameMissing { pid })?,
        })
    }
    /// Deliver the terminating signal (`SIGTERM` for terminate, `SIGKILL` for
    /// force).
    fn deliver(&mut self, pid: u32, mode: KillMode) -> TreeSignalResult;
}
