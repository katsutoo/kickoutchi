//! Windows process-tree termination through Job Object containment.
//!
//! This is deliberately separate from the Unix freeze-first tree executor. Windows
//! has no supported SIGSTOP-equivalent safety primitive, so the safety boundary is
//! different: verify process handles first, assign the root to a Job Object as the
//! commit point, converge on descendants, then explicitly terminate the job.

use std::collections::{HashMap, HashSet};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

use crate::model::Platform;
use crate::process::{KillTarget, UnsafePidReason, unsafe_pid_reason};
use crate::tree::{
    self, MAX_TREE_PROCESSES, ProcessTreeTarget, TreeKillOutcome, TreePlanError, TreeProcessInfo,
};

// Same finite convergence budget as the Unix freeze sweep. Windows containment
// is a different mechanism, but it still needs an explicit pass limit.
const WINDOWS_TREE_SWEEP_PASSES: usize = 8;
const WINDOWS_TREE_TERMINATE_EXIT_CODE: u32 = 1;
const WINDOWS_TREE_WAIT_MS: u32 = 5_000;
const WINDOWS_TREE_PROBE_WAIT_MS: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowsTreeKillReport {
    pub(crate) total: usize,
    pub(crate) job_terminated: usize,
    pub(crate) fallback_terminated: usize,
    pub(crate) already_exited: usize,
    pub(crate) not_terminated: Vec<u32>,
    pub(crate) containment_partial: bool,
    pub(crate) post_commit_issue: Option<WindowsTreePostCommitIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsTreePostCommitIssue {
    RootAlreadyExited,
    PermissionDenied { pid: u32 },
    TargetChanged { pid: u32 },
    Truncated { limit: usize },
    SweepPassLimit { limit: usize },
    UnsafePid { pid: u32, reason: UnsafePidReason },
    ProtectedDescendant { pid: u32, name: Option<String> },
    PartialMetadata { pid: u32 },
    SnapshotFailed(String),
}

impl WindowsTreePostCommitIssue {
    fn from_outcome(outcome: WindowsTreeKillOutcome) -> Option<Self> {
        match outcome {
            WindowsTreeKillOutcome::Completed(_)
            | WindowsTreeKillOutcome::ProtectedRoot { .. }
            | WindowsTreeKillOutcome::FreshConfirmationRequired
            | WindowsTreeKillOutcome::OwnershipUnavailable { .. }
            | WindowsTreeKillOutcome::CommitFailed { .. }
            | WindowsTreeKillOutcome::JobTerminateFailed(_) => None,
            WindowsTreeKillOutcome::RootAlreadyExited => Some(Self::RootAlreadyExited),
            WindowsTreeKillOutcome::PermissionDenied { pid } => {
                Some(Self::PermissionDenied { pid })
            }
            WindowsTreeKillOutcome::TargetChanged { pid } => Some(Self::TargetChanged { pid }),
            WindowsTreeKillOutcome::Truncated { limit } => Some(Self::Truncated { limit }),
            WindowsTreeKillOutcome::SweepPassLimit { limit } => {
                Some(Self::SweepPassLimit { limit })
            }
            WindowsTreeKillOutcome::UnsafePid { pid, reason } => {
                Some(Self::UnsafePid { pid, reason })
            }
            WindowsTreeKillOutcome::ProtectedDescendant { pid, name } => {
                Some(Self::ProtectedDescendant { pid, name })
            }
            WindowsTreeKillOutcome::PartialMetadata { pid } => Some(Self::PartialMetadata { pid }),
            WindowsTreeKillOutcome::SnapshotFailed(error) => Some(Self::SnapshotFailed(error)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsTreeKillOutcome {
    Completed(WindowsTreeKillReport),
    RootAlreadyExited,
    PermissionDenied { pid: u32 },
    TargetChanged { pid: u32 },
    Truncated { limit: usize },
    SweepPassLimit { limit: usize },
    UnsafePid { pid: u32, reason: UnsafePidReason },
    ProtectedDescendant { pid: u32, name: Option<String> },
    ProtectedRoot { pid: u32, name: Option<String> },
    FreshConfirmationRequired,
    OwnershipUnavailable { pid: u32 },
    PartialMetadata { pid: u32 },
    SnapshotFailed(String),
    CommitFailed { pid: u32, error: String },
    JobTerminateFailed(String),
}

impl WindowsTreeKillOutcome {
    pub(crate) fn from_precommit_outcome(outcome: TreeKillOutcome) -> Self {
        match outcome {
            TreeKillOutcome::RootAlreadyExited => Self::RootAlreadyExited,
            TreeKillOutcome::PermissionDenied { pid } => Self::PermissionDenied { pid },
            TreeKillOutcome::TargetChanged { pid } => Self::TargetChanged { pid },
            TreeKillOutcome::Truncated { limit } => Self::Truncated { limit },
            TreeKillOutcome::UnsafePid { pid, reason } => Self::UnsafePid { pid, reason },
            TreeKillOutcome::ProtectedDescendant { pid, name } => {
                Self::ProtectedDescendant { pid, name }
            }
            TreeKillOutcome::ProtectedRoot { pid, name } => Self::ProtectedRoot { pid, name },
            TreeKillOutcome::FreshConfirmationRequired => Self::FreshConfirmationRequired,
            TreeKillOutcome::OwnershipUnavailable { pid } => Self::OwnershipUnavailable { pid },
            TreeKillOutcome::PartialMetadata { pid } => Self::PartialMetadata { pid },
            TreeKillOutcome::SnapshotFailed(error) => Self::SnapshotFailed(error),
        }
    }
}

pub(crate) fn execute_tree_kill(
    root: &KillTarget,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
) -> WindowsTreeKillOutcome {
    let mut api = RealWindowsTreeApi;
    execute_tree_kill_with(
        root,
        protected_names,
        protected_root_confirmed,
        prompt_skipped,
        &mut api,
    )
}

fn execute_tree_kill_with<Api: WindowsTreeApi>(
    root: &KillTarget,
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
    api: &mut Api,
) -> WindowsTreeKillOutcome {
    if let Some(reason) = unsafe_pid_reason(root.pid) {
        return WindowsTreeKillOutcome::UnsafePid {
            pid: root.pid,
            reason,
        };
    }

    let snapshot = match api.snapshot() {
        Ok(snapshot) => snapshot,
        Err(error) => return WindowsTreeKillOutcome::SnapshotFailed(error),
    };
    let (preview, confirmed_root_marker) = match build_precommit_preview(
        root,
        &snapshot,
        protected_names,
        protected_root_confirmed,
        prompt_skipped,
    ) {
        Ok(preview) => preview,
        Err(outcome) => return outcome,
    };

    let mut members =
        match pin_preview_members(api, &snapshot, &preview, root.pid, confirmed_root_marker) {
            Ok(members) => members,
            Err(outcome) => return outcome,
        };
    let job = match api.create_job() {
        Ok(job) => job,
        Err(error) => return WindowsTreeKillOutcome::SnapshotFailed(error),
    };

    match commit_root_to_job(api, &job, root.pid, &mut members) {
        Ok(()) => {}
        Err(outcome) => return outcome,
    }

    let mut report = WindowsTreeKillReport {
        total: 0,
        job_terminated: 0,
        fallback_terminated: 0,
        already_exited: 0,
        not_terminated: Vec::new(),
        containment_partial: false,
        post_commit_issue: None,
    };

    let mut assigned = HashSet::from([root.pid]);
    assign_initial_members(
        api,
        &job,
        root.pid,
        &mut members,
        &mut assigned,
        &mut report,
    );

    if let Err(outcome) = sweep_committed_tree(
        api,
        &job,
        root.pid,
        protected_names,
        &mut members,
        &mut assigned,
        &mut report,
    ) {
        record_post_commit_issue(&mut report, outcome);
    }

    if let Err(error) = api.terminate_job(&job) {
        return WindowsTreeKillOutcome::JobTerminateFailed(error);
    }

    finish_report(api, &members, &assigned, &mut report);
    WindowsTreeKillOutcome::Completed(report)
}

fn build_precommit_preview(
    root: &KillTarget,
    snapshot: &[TreeProcessInfo],
    protected_names: &[String],
    protected_root_confirmed: bool,
    prompt_skipped: bool,
) -> Result<(ProcessTreeTarget, u64), WindowsTreeKillOutcome> {
    let confirmed_root_marker = verify_snapshot_root_identity(root, snapshot)?;
    let preview = tree::plan_process_tree(
        root.pid,
        snapshot,
        protected_names,
        Platform::Windows,
        MAX_TREE_PROCESSES,
    )
    .map_err(|TreePlanError::RootMissing| WindowsTreeKillOutcome::RootAlreadyExited)?;
    tree::preflight_outcome(&preview).map_err(WindowsTreeKillOutcome::from_precommit_outcome)?;
    tree::root_protection_outcome(&preview, protected_root_confirmed)
        .map_err(WindowsTreeKillOutcome::from_precommit_outcome)?;
    if prompt_skipped && preview.has_warnings() {
        return Err(WindowsTreeKillOutcome::FreshConfirmationRequired);
    }
    if let Some(pid) = first_partial_metadata_pid(snapshot, &preview) {
        return Err(WindowsTreeKillOutcome::PartialMetadata { pid });
    }
    Ok((preview, confirmed_root_marker))
}

fn verify_snapshot_root_identity(
    root: &KillTarget,
    snapshot: &[TreeProcessInfo],
) -> Result<u64, WindowsTreeKillOutcome> {
    let confirmed_marker = root
        .process_start_time_marker
        .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid })?;
    let info = snapshot
        .iter()
        .find(|info| info.pid == root.pid)
        .ok_or(WindowsTreeKillOutcome::RootAlreadyExited)?;
    match info.start_time_marker {
        Some(marker) if marker == confirmed_marker => {}
        Some(_) => return Err(WindowsTreeKillOutcome::TargetChanged { pid: root.pid }),
        None => return Err(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid }),
    }
    if let Some(confirmed_name) = root.process_name.as_deref() {
        match info.process_name.as_deref() {
            Some(fresh_name) if fresh_name == confirmed_name => {}
            Some(_) => return Err(WindowsTreeKillOutcome::TargetChanged { pid: root.pid }),
            None => return Err(WindowsTreeKillOutcome::PartialMetadata { pid: root.pid }),
        }
    }
    Ok(confirmed_marker)
}

fn first_partial_metadata_pid(
    snapshot: &[TreeProcessInfo],
    preview: &ProcessTreeTarget,
) -> Option<u32> {
    let preview_nodes = preview.preview_nodes(preview.len());
    let preview_pids = preview_nodes
        .iter()
        .map(|node| node.pid)
        .collect::<HashSet<_>>();
    for node in preview_nodes {
        let Some(info) = snapshot.iter().find(|info| info.pid == node.pid) else {
            continue;
        };
        if info.process_name.is_none() || info.start_time_marker.is_none() {
            return Some(info.pid);
        }
    }

    let mut unverified_children = snapshot
        .iter()
        .filter(|info| !preview_pids.contains(&info.pid))
        .filter(|info| {
            info.unverified_parent_pid
                .is_some_and(|parent_pid| preview_pids.contains(&parent_pid))
        })
        .collect::<Vec<_>>();
    unverified_children.sort_by_key(|info| info.pid);
    unverified_children.first().map(|info| info.pid)
}

fn pin_preview_members<Api: WindowsTreeApi>(
    api: &mut Api,
    snapshot: &[TreeProcessInfo],
    preview: &ProcessTreeTarget,
    root_pid: u32,
    confirmed_root_marker: u64,
) -> Result<HashMap<u32, PinnedProcess<Api::ProcessHandle>>, WindowsTreeKillOutcome> {
    let mut members = HashMap::new();
    for node in preview.preview_nodes(preview.len()) {
        let Some(info) = snapshot.iter().find(|info| info.pid == node.pid) else {
            return Err(WindowsTreeKillOutcome::TargetChanged { pid: node.pid });
        };
        let expected_marker = if info.pid == root_pid {
            confirmed_root_marker
        } else {
            info.start_time_marker
                .ok_or(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid })?
        };
        let process =
            open_verified_process(api, info, expected_marker).map_err(|error| match error {
                OpenVerifiedError::NotFound => {
                    WindowsTreeKillOutcome::TargetChanged { pid: info.pid }
                }
                OpenVerifiedError::PermissionDenied => {
                    WindowsTreeKillOutcome::PermissionDenied { pid: info.pid }
                }
                OpenVerifiedError::PartialMetadata => {
                    WindowsTreeKillOutcome::PartialMetadata { pid: info.pid }
                }
                OpenVerifiedError::Other(error) => WindowsTreeKillOutcome::SnapshotFailed(error),
            })?;
        members.insert(info.pid, process);
    }
    Ok(members)
}

fn record_post_commit_issue(report: &mut WindowsTreeKillReport, outcome: WindowsTreeKillOutcome) {
    report.containment_partial = true;
    report.post_commit_issue = WindowsTreePostCommitIssue::from_outcome(outcome);
}

fn commit_root_to_job<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
) -> Result<(), WindowsTreeKillOutcome> {
    let Some(root) = members.get_mut(&root_pid) else {
        return Err(WindowsTreeKillOutcome::RootAlreadyExited);
    };
    match api.assign_process(job, &root.handle) {
        Ok(()) => {
            root.status = PinnedProcessStatus::AssignedToJob;
            Ok(())
        }
        Err(WindowsApiError::NotFound) => Err(WindowsTreeKillOutcome::RootAlreadyExited),
        Err(WindowsApiError::PermissionDenied) => {
            Err(WindowsTreeKillOutcome::PermissionDenied { pid: root_pid })
        }
        Err(WindowsApiError::Other(error)) => Err(WindowsTreeKillOutcome::CommitFailed {
            pid: root_pid,
            error,
        }),
    }
}

fn assign_initial_members<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    let mut pids = members.keys().copied().collect::<Vec<_>>();
    pids.sort_unstable();
    for pid in pids {
        if pid == root_pid {
            continue;
        }
        assign_or_fallback(api, job, pid, members, assigned, report);
    }
}

fn sweep_committed_tree<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    root_pid: u32,
    protected_names: &[String],
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) -> Result<(), WindowsTreeKillOutcome> {
    for _ in 0..WINDOWS_TREE_SWEEP_PASSES {
        let snapshot = api
            .snapshot()
            .map_err(WindowsTreeKillOutcome::SnapshotFailed)?;
        let preview = tree::plan_process_tree(
            root_pid,
            &snapshot,
            protected_names,
            Platform::Windows,
            MAX_TREE_PROCESSES,
        )
        .map_err(|TreePlanError::RootMissing| WindowsTreeKillOutcome::RootAlreadyExited)?;
        if preview.truncated() {
            return Err(WindowsTreeKillOutcome::Truncated {
                limit: MAX_TREE_PROCESSES,
            });
        }
        if let Some(pid) = first_partial_metadata_pid(&snapshot, &preview) {
            return Err(WindowsTreeKillOutcome::PartialMetadata { pid });
        }

        let mut discovered = false;
        for node in preview.preview_nodes(preview.len()) {
            if members.contains_key(&node.pid) {
                continue;
            }
            if members.len() >= MAX_TREE_PROCESSES {
                return Err(WindowsTreeKillOutcome::Truncated {
                    limit: MAX_TREE_PROCESSES,
                });
            }
            let Some(info) = snapshot.iter().find(|info| info.pid == node.pid) else {
                continue;
            };
            if let Some(reason) = unsafe_pid_reason(node.pid) {
                report.not_terminated.push(node.pid);
                return Err(WindowsTreeKillOutcome::UnsafePid {
                    pid: node.pid,
                    reason,
                });
            }
            if node.protected {
                return Err(handle_protected_post_commit_child(
                    api,
                    job,
                    info,
                    node.process_name.clone(),
                    members,
                    assigned,
                    report,
                ));
            }
            let Some(expected_marker) = info.start_time_marker else {
                report.not_terminated.push(info.pid);
                return Err(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid });
            };
            let process = match open_verified_process(api, info, expected_marker) {
                Ok(process) => process,
                Err(OpenVerifiedError::NotFound) => {
                    report.already_exited += 1;
                    continue;
                }
                Err(OpenVerifiedError::PermissionDenied | OpenVerifiedError::Other(_)) => {
                    report.not_terminated.push(info.pid);
                    return Err(WindowsTreeKillOutcome::PermissionDenied { pid: info.pid });
                }
                Err(OpenVerifiedError::PartialMetadata) => {
                    report.not_terminated.push(info.pid);
                    return Err(WindowsTreeKillOutcome::PartialMetadata { pid: info.pid });
                }
            };
            members.insert(info.pid, process);
            assign_or_fallback(api, job, info.pid, members, assigned, report);
            discovered = true;
        }
        if !discovered {
            return Ok(());
        }
    }
    Err(WindowsTreeKillOutcome::SweepPassLimit {
        limit: WINDOWS_TREE_SWEEP_PASSES,
    })
}

fn handle_protected_post_commit_child<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    info: &TreeProcessInfo,
    name: Option<String>,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) -> WindowsTreeKillOutcome {
    let Some(expected_marker) = info.start_time_marker else {
        report.not_terminated.push(info.pid);
        return WindowsTreeKillOutcome::PartialMetadata { pid: info.pid };
    };
    match open_verified_process(api, info, expected_marker) {
        Ok(mut process) => match api.process_in_job(job, &process.handle) {
            Ok(true) => {
                process.status = PinnedProcessStatus::AssignedToJob;
                assigned.insert(info.pid);
                members.insert(info.pid, process);
            }
            Ok(false) | Err(_) => report.not_terminated.push(info.pid),
        },
        Err(OpenVerifiedError::NotFound) => report.already_exited += 1,
        Err(
            OpenVerifiedError::PermissionDenied
            | OpenVerifiedError::PartialMetadata
            | OpenVerifiedError::Other(_),
        ) => report.not_terminated.push(info.pid),
    }
    WindowsTreeKillOutcome::ProtectedDescendant {
        pid: info.pid,
        name,
    }
}

fn assign_or_fallback<Api: WindowsTreeApi>(
    api: &mut Api,
    job: &Api::JobHandle,
    pid: u32,
    members: &mut HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &mut HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    let Some(process) = members.get_mut(&pid) else {
        return;
    };
    if let Ok(true) = api.process_in_job(job, &process.handle) {
        process.status = PinnedProcessStatus::AssignedToJob;
        assigned.insert(pid);
        return;
    }

    match api.assign_process(job, &process.handle) {
        Ok(()) => {
            process.status = PinnedProcessStatus::AssignedToJob;
            assigned.insert(pid);
        }
        Err(WindowsApiError::NotFound) => {
            process.status = PinnedProcessStatus::AlreadyExited;
            report.already_exited += 1;
        }
        Err(WindowsApiError::PermissionDenied | WindowsApiError::Other(_)) => {
            if matches!(
                api.wait_process_exit(&process.handle, WINDOWS_TREE_PROBE_WAIT_MS),
                WindowsWaitResult::Exited
            ) {
                process.status = PinnedProcessStatus::AlreadyExited;
                report.already_exited += 1;
                return;
            }
            report.containment_partial = true;
            match api.terminate_process(&process.handle) {
                Ok(()) => {
                    process.status = PinnedProcessStatus::FallbackTerminated;
                    report.fallback_terminated += 1;
                }
                Err(WindowsApiError::NotFound) => {
                    process.status = PinnedProcessStatus::AlreadyExited;
                    report.already_exited += 1;
                }
                Err(WindowsApiError::PermissionDenied | WindowsApiError::Other(_)) => {
                    if matches!(
                        api.wait_process_exit(&process.handle, WINDOWS_TREE_PROBE_WAIT_MS),
                        WindowsWaitResult::Exited
                    ) {
                        process.status = PinnedProcessStatus::AlreadyExited;
                        report.already_exited += 1;
                    } else {
                        process.status = PinnedProcessStatus::NotTerminated;
                        report.not_terminated.push(pid);
                    }
                }
            }
        }
    }
}

fn finish_report<Api: WindowsTreeApi>(
    api: &mut Api,
    members: &HashMap<u32, PinnedProcess<Api::ProcessHandle>>,
    assigned: &HashSet<u32>,
    report: &mut WindowsTreeKillReport,
) {
    report.total = members.len();
    report.job_terminated = assigned.len();
    for (pid, process) in members {
        if matches!(
            process.status,
            PinnedProcessStatus::AlreadyExited | PinnedProcessStatus::NotTerminated
        ) {
            continue;
        }
        if matches!(
            process.status,
            PinnedProcessStatus::AssignedToJob | PinnedProcessStatus::FallbackTerminated
        ) {
            match api.wait_process_exit(&process.handle, WINDOWS_TREE_WAIT_MS) {
                WindowsWaitResult::Exited => {}
                WindowsWaitResult::StillRunning | WindowsWaitResult::Failed(_) => {
                    if !report.not_terminated.contains(pid) {
                        report.not_terminated.push(*pid);
                    }
                }
            }
        }
    }
    report.not_terminated.sort_unstable();
    report.not_terminated.dedup();
    if !report.not_terminated.is_empty() {
        report.containment_partial = true;
    }
}

fn open_verified_process<Api: WindowsTreeApi>(
    api: &mut Api,
    info: &TreeProcessInfo,
    expected_marker: u64,
) -> Result<PinnedProcess<Api::ProcessHandle>, OpenVerifiedError> {
    if info.process_name.is_none() {
        return Err(OpenVerifiedError::PartialMetadata);
    }
    let handle = api.open_process(info.pid).map_err(|error| match error {
        WindowsApiError::NotFound => OpenVerifiedError::NotFound,
        WindowsApiError::PermissionDenied => OpenVerifiedError::PermissionDenied,
        WindowsApiError::Other(error) => OpenVerifiedError::Other(error),
    })?;
    match api.process_start_marker(&handle) {
        Some(marker) if marker == expected_marker => Ok(PinnedProcess {
            handle,
            status: PinnedProcessStatus::Pending,
        }),
        Some(_) => Err(OpenVerifiedError::NotFound),
        None => Err(OpenVerifiedError::PartialMetadata),
    }
}

struct PinnedProcess<Handle> {
    handle: Handle,
    status: PinnedProcessStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PinnedProcessStatus {
    Pending,
    AssignedToJob,
    FallbackTerminated,
    AlreadyExited,
    NotTerminated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OpenVerifiedError {
    NotFound,
    PermissionDenied,
    PartialMetadata,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsApiError {
    NotFound,
    PermissionDenied,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WindowsWaitResult {
    Exited,
    StillRunning,
    Failed(String),
}

trait WindowsTreeApi {
    type ProcessHandle;
    type JobHandle;

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String>;
    fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError>;
    fn process_start_marker(&mut self, handle: &Self::ProcessHandle) -> Option<u64>;
    fn create_job(&mut self) -> Result<Self::JobHandle, String>;
    fn process_in_job(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<bool, WindowsApiError>;
    fn assign_process(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<(), WindowsApiError>;
    fn terminate_job(&mut self, job: &Self::JobHandle) -> Result<(), String>;
    fn terminate_process(&mut self, process: &Self::ProcessHandle) -> Result<(), WindowsApiError>;
    fn wait_process_exit(
        &mut self,
        process: &Self::ProcessHandle,
        timeout_ms: u32,
    ) -> WindowsWaitResult;
}

struct RealWindowsTreeApi;

struct RealProcessHandle {
    pid: u32,
    handle: OwnedHandle,
}

struct RealJobHandle {
    handle: OwnedHandle,
}

impl WindowsTreeApi for RealWindowsTreeApi {
    type ProcessHandle = RealProcessHandle;
    type JobHandle = RealJobHandle;

    fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
        Ok(crate::platform::windows::collect_tree_process_infos())
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError> {
        let desired_access = PROCESS_TERMINATE
            | PROCESS_QUERY_LIMITED_INFORMATION
            | PROCESS_SYNCHRONIZE
            | PROCESS_SET_QUOTA;
        let handle = unsafe {
            // SAFETY: OpenProcess takes only value arguments here. The returned
            // handle is checked before it is wrapped for owned close-on-drop.
            OpenProcess(desired_access, 0, pid)
        };
        if handle.is_null() {
            return Err(last_windows_api_error("OpenProcess"));
        }
        let handle = unsafe {
            // SAFETY: OpenProcess returned a non-null process handle owned by this
            // scope. OwnedHandle closes it exactly once on drop.
            OwnedHandle::from_raw_handle(handle)
        };
        Ok(RealProcessHandle { pid, handle })
    }

    fn process_start_marker(&mut self, handle: &Self::ProcessHandle) -> Option<u64> {
        crate::platform::windows::process_start_time_marker_from_handle(&handle.handle)
    }

    fn create_job(&mut self) -> Result<Self::JobHandle, String> {
        let handle = unsafe {
            // SAFETY: null security attributes and name create an unnamed job and
            // pass no Rust-managed memory to Windows.
            CreateJobObjectW(std::ptr::null(), std::ptr::null())
        };
        if handle.is_null() {
            return Err(format!(
                "CreateJobObjectW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let handle = unsafe {
            // SAFETY: CreateJobObjectW returned a non-null owned handle. OwnedHandle
            // closes it once; the job is not configured with kill-on-close.
            OwnedHandle::from_raw_handle(handle)
        };
        Ok(RealJobHandle { handle })
    }

    fn process_in_job(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<bool, WindowsApiError> {
        let mut in_job = 0;
        let result = unsafe {
            // SAFETY: both handles are live and `in_job` is valid for one BOOL
            // write. Windows does not retain the pointer.
            IsProcessInJob(
                process.handle.as_raw_handle(),
                job.handle.as_raw_handle(),
                &raw mut in_job,
            )
        };
        if result == 0 {
            return Err(last_windows_api_error("IsProcessInJob"));
        }
        Ok(in_job != 0)
    }

    fn assign_process(
        &mut self,
        job: &Self::JobHandle,
        process: &Self::ProcessHandle,
    ) -> Result<(), WindowsApiError> {
        let result = unsafe {
            // SAFETY: both handles are live. Assigning a process to a job is the
            // intended Windows API side effect and transfers no Rust ownership.
            AssignProcessToJobObject(job.handle.as_raw_handle(), process.handle.as_raw_handle())
        };
        if result == 0 {
            return Err(last_windows_api_error("AssignProcessToJobObject"));
        }
        Ok(())
    }

    fn terminate_job(&mut self, job: &Self::JobHandle) -> Result<(), String> {
        let result = unsafe {
            // SAFETY: the job handle is live and owned by this process. The exit
            // code is a fixed diagnostic value.
            TerminateJobObject(job.handle.as_raw_handle(), WINDOWS_TREE_TERMINATE_EXIT_CODE)
        };
        if result == 0 {
            return Err(format!(
                "TerminateJobObject failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    fn terminate_process(&mut self, process: &Self::ProcessHandle) -> Result<(), WindowsApiError> {
        let result = unsafe {
            // SAFETY: the process handle is live and was opened with terminate
            // access. The exit code is a fixed diagnostic value.
            TerminateProcess(
                process.handle.as_raw_handle(),
                WINDOWS_TREE_TERMINATE_EXIT_CODE,
            )
        };
        if result == 0 {
            return Err(last_windows_api_error("TerminateProcess"));
        }
        Ok(())
    }

    fn wait_process_exit(
        &mut self,
        process: &Self::ProcessHandle,
        timeout_ms: u32,
    ) -> WindowsWaitResult {
        let result = unsafe {
            // SAFETY: the process handle is live and was opened with synchronize
            // access. Waiting transfers no ownership and writes no Rust memory.
            WaitForSingleObject(process.handle.as_raw_handle(), timeout_ms)
        };
        match result {
            WAIT_OBJECT_0 => WindowsWaitResult::Exited,
            WAIT_TIMEOUT => WindowsWaitResult::StillRunning,
            WAIT_FAILED => WindowsWaitResult::Failed(format!(
                "WaitForSingleObject(PID {}) failed: {}",
                process.pid,
                std::io::Error::last_os_error()
            )),
            other => WindowsWaitResult::Failed(format!(
                "WaitForSingleObject(PID {}) returned unexpected status {other}",
                process.pid,
            )),
        }
    }
}

fn last_windows_api_error(operation: &str) -> WindowsApiError {
    let error = std::io::Error::last_os_error();
    match windows_error_code(&error) {
        Some(ERROR_INVALID_PARAMETER) => WindowsApiError::NotFound,
        Some(ERROR_ACCESS_DENIED) => WindowsApiError::PermissionDenied,
        _ if error.kind() == std::io::ErrorKind::PermissionDenied => {
            WindowsApiError::PermissionDenied
        }
        _ => WindowsApiError::Other(format!("{operation} failed: {error}")),
    }
}

fn windows_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        WindowsApiError, WindowsTreeApi, WindowsTreeKillOutcome, WindowsTreePostCommitIssue,
        WindowsWaitResult, execute_tree_kill_with,
    };
    use crate::model::{PermissionStatus, Platform};
    use crate::process::KillTarget;
    use crate::tree::TreeProcessInfo;
    use std::collections::{HashMap, HashSet, VecDeque};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Event {
        CreateJob,
        Assign(u32),
        TerminateJob,
        TerminateProcess(u32),
        Wait(u32, u32),
    }

    #[derive(Default)]
    struct FakeApi {
        snapshots: Vec<Vec<TreeProcessInfo>>,
        next_snapshot: usize,
        markers: HashMap<u32, u64>,
        events: Vec<Event>,
        deny_assign: HashSet<u32>,
        deny_terminate: HashSet<u32>,
        fail_root_assign: bool,
        already_in_job: HashSet<u32>,
        terminated_processes: HashSet<u32>,
        wait_results: HashMap<u32, VecDeque<WindowsWaitResult>>,
        job_terminated: bool,
    }

    impl FakeApi {
        fn new(snapshots: Vec<Vec<TreeProcessInfo>>) -> Self {
            let markers = snapshots
                .iter()
                .flat_map(|snapshot| snapshot.iter())
                .filter_map(|info| Some((info.pid, info.start_time_marker?)))
                .collect();
            Self {
                snapshots,
                markers,
                ..Self::default()
            }
        }
    }

    impl WindowsTreeApi for FakeApi {
        type ProcessHandle = u32;
        type JobHandle = ();

        fn snapshot(&mut self) -> Result<Vec<TreeProcessInfo>, String> {
            let index = self
                .next_snapshot
                .min(self.snapshots.len().saturating_sub(1));
            self.next_snapshot += 1;
            Ok(self.snapshots.get(index).cloned().unwrap_or_default())
        }

        fn open_process(&mut self, pid: u32) -> Result<Self::ProcessHandle, WindowsApiError> {
            if self.markers.contains_key(&pid) {
                Ok(pid)
            } else {
                Err(WindowsApiError::NotFound)
            }
        }

        fn process_start_marker(&mut self, handle: &Self::ProcessHandle) -> Option<u64> {
            self.markers.get(handle).copied()
        }

        fn create_job(&mut self) -> Result<Self::JobHandle, String> {
            self.events.push(Event::CreateJob);
            Ok(())
        }

        fn process_in_job(
            &mut self,
            _job: &Self::JobHandle,
            process: &Self::ProcessHandle,
        ) -> Result<bool, WindowsApiError> {
            Ok(self.already_in_job.contains(process))
        }

        fn assign_process(
            &mut self,
            _job: &Self::JobHandle,
            process: &Self::ProcessHandle,
        ) -> Result<(), WindowsApiError> {
            self.events.push(Event::Assign(*process));
            if *process == 100 && self.fail_root_assign {
                return Err(WindowsApiError::Other("root cannot join job".to_owned()));
            }
            if self.deny_assign.contains(process) {
                return Err(WindowsApiError::Other("member cannot join job".to_owned()));
            }
            Ok(())
        }

        fn terminate_job(&mut self, _job: &Self::JobHandle) -> Result<(), String> {
            self.events.push(Event::TerminateJob);
            self.job_terminated = true;
            Ok(())
        }

        fn terminate_process(
            &mut self,
            process: &Self::ProcessHandle,
        ) -> Result<(), WindowsApiError> {
            self.events.push(Event::TerminateProcess(*process));
            if self.deny_terminate.contains(process) {
                return Err(WindowsApiError::Other(
                    "member ignored termination".to_owned(),
                ));
            }
            self.terminated_processes.insert(*process);
            Ok(())
        }

        fn wait_process_exit(
            &mut self,
            process: &Self::ProcessHandle,
            timeout_ms: u32,
        ) -> WindowsWaitResult {
            self.events.push(Event::Wait(*process, timeout_ms));
            if let Some(results) = self.wait_results.get_mut(process)
                && let Some(result) = results.pop_front()
            {
                return result;
            }
            if self.job_terminated || self.terminated_processes.contains(process) {
                WindowsWaitResult::Exited
            } else {
                WindowsWaitResult::StillRunning
            }
        }
    }

    fn info(pid: u32, parent_pid: Option<u32>, marker: u64) -> TreeProcessInfo {
        TreeProcessInfo {
            pid,
            parent_pid,
            unverified_parent_pid: None,
            parent_process_name: None,
            process_name: Some(format!("p{pid}")),
            start_time_marker: Some(marker),
            owner_uid: None,
            process_group: None,
        }
    }

    fn root() -> KillTarget {
        KillTarget {
            pid: 100,
            process_name: Some("p100".to_owned()),
            platform: Platform::Windows,
            permission: PermissionStatus::Full,
            protected: false,
            system_process: false,
            ports: Vec::new(),
            owner_uid: None,
            process_start_time_marker: Some(100),
            child_count: 0,
            children_truncated: false,
        }
    }

    #[test]
    fn root_assignment_is_the_commit_boundary() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.fail_root_assign = true;

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert!(matches!(
            outcome,
            WindowsTreeKillOutcome::CommitFailed { .. }
        ));
        assert_eq!(api.events, vec![Event::CreateJob, Event::Assign(100)]);
    }

    #[test]
    fn root_snapshot_identity_drift_refuses_before_job_creation() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 200), info(101, Some(100), 201)]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(outcome, WindowsTreeKillOutcome::TargetChanged { pid: 100 });
        assert!(api.events.is_empty());
    }

    #[test]
    fn root_handle_identity_drift_refuses_before_job_creation() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.markers.insert(100, 200);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(outcome, WindowsTreeKillOutcome::TargetChanged { pid: 100 });
        assert!(api.events.is_empty());
    }

    #[test]
    fn member_assignment_failure_falls_back_after_commit() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_assign.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(report.containment_partial);
        assert_eq!(report.fallback_terminated, 1);
        assert!(api.events.contains(&Event::TerminateProcess(101)));
        assert!(api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn exited_member_after_assign_failure_is_not_reported_alive() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_assign.insert(101);
        api.wait_results
            .insert(101, VecDeque::from([WindowsWaitResult::Exited]));

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.already_exited, 1);
        assert_eq!(report.fallback_terminated, 0);
        assert!(report.not_terminated.is_empty());
        assert!(!report.containment_partial);
        assert!(!api.events.contains(&Event::TerminateProcess(101)));
        assert!(api.events.contains(&Event::Wait(101, 0)));
    }

    #[test]
    fn exited_member_after_failed_fallback_is_not_reported_alive() {
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), info(101, Some(100), 101)]]);
        api.deny_assign.insert(101);
        api.deny_terminate.insert(101);
        api.wait_results.insert(
            101,
            VecDeque::from([WindowsWaitResult::StillRunning, WindowsWaitResult::Exited]),
        );

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.already_exited, 1);
        assert_eq!(report.fallback_terminated, 0);
        assert!(report.not_terminated.is_empty());
        assert!(report.containment_partial);
        assert!(api.events.contains(&Event::TerminateProcess(101)));
    }

    #[test]
    fn already_contained_late_child_does_not_need_fallback() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.already_in_job.insert(101);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert_eq!(report.fallback_terminated, 0);
        assert!(!api.events.contains(&Event::TerminateProcess(101)));
    }

    #[test]
    fn protected_late_child_is_reported_after_commit() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(report.containment_partial);
        assert_eq!(report.not_terminated, vec![101]);
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn protected_late_child_already_in_job_is_not_reported_alive() {
        let first = vec![info(100, None, 100)];
        let second = vec![info(100, None, 100), info(101, Some(100), 101)];
        let mut api = FakeApi::new(vec![first, second]);
        api.already_in_job.insert(101);

        let outcome = execute_tree_kill_with(&root(), &["p101".to_owned()], false, false, &mut api);

        let WindowsTreeKillOutcome::Completed(report) = outcome else {
            panic!("expected completed report");
        };
        assert!(report.containment_partial);
        assert!(report.not_terminated.is_empty());
        assert_eq!(report.job_terminated, 2);
        assert_eq!(
            report.post_commit_issue,
            Some(WindowsTreePostCommitIssue::ProtectedDescendant {
                pid: 101,
                name: Some("p101".to_owned()),
            })
        );
        assert!(api.events.contains(&Event::TerminateJob));
    }

    #[test]
    fn partial_metadata_refuses_before_job_creation() {
        let mut partial = info(101, Some(100), 101);
        partial.start_time_marker = None;
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
    }

    #[test]
    fn unverified_parent_edge_into_preview_refuses_before_job_creation() {
        let mut partial_child = info(101, None, 101);
        partial_child.start_time_marker = None;
        partial_child.unverified_parent_pid = Some(100);
        let mut api = FakeApi::new(vec![vec![info(100, None, 100), partial_child]]);

        let outcome = execute_tree_kill_with(&root(), &[], false, false, &mut api);

        assert_eq!(
            outcome,
            WindowsTreeKillOutcome::PartialMetadata { pid: 101 }
        );
        assert!(api.events.is_empty());
    }
}
