//! Native Windows socket collection through IP Helper.
//!
//! No `netstat` scraping: IP Helper tells us which sockets exist and which PID
//! owns each one. Process metadata is read natively for all sorted owner PIDs in
//! one bounded batch bracketed by at most two Toolhelp relation snapshots. Open
//! process handles retain high-resolution creation markers across that bracket,
//! because PID reuse is where the dragon lives.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::c_void;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_NO_DATA,
    ERROR_NO_MORE_FILES, ERROR_SUCCESS, FILETIME, INVALID_HANDLE_VALUE, UNICODE_STRING,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID,
    MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
    MIB_UDP6TABLE_OWNER_PID, MIB_UDPROW_OWNER_PID, MIB_UDPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use crate::collector::{Collector, CollectorError};
use crate::diagnostic;
use crate::model::{
    ChildProcess, ChildProcessSnapshot, ProcessContext, Protocol, RelatedProcessHint, SocketState,
};
use crate::observation::NativeObservationPass;
use crate::observation::{
    CANDIDATE_PROCESS_IDS_MAX, EXECUTABLE_PATH_MAX_BYTES, Ipv6Scope, MetadataCompleteness,
    MetadataOmission, MetadataProfile, NATIVE_RESIZE_ATTEMPTS_MAX, NATIVE_SOCKET_TABLE_MAX_BYTES,
    NativeSocketObservation, NetworkSnapshot, OPTIONAL_METADATA_MAX_BYTES, ObservationScope,
    ObservationScopeKind, OwnerAssociations, OwnerCompleteness, PROCESS_COMMAND_LINE_MAX_BYTES,
    PROCESS_NAME_MAX_BYTES, ProcessIdentity, ProcessObservation, ProcessRead, ProcessStartMarker,
    SOCKET_OBSERVATIONS_MAX, ScopeLimitation, UnverifiedOwnerReason,
};
use crate::tree::TreeProcessInfo;

const MAX_CHILD_PROCESSES: usize = 64;
const MAX_RELATED_PROCESS_HINTS: usize = 8;
const MAX_PROCESS_ANCESTORS: usize = 64;

pub(crate) struct WindowsCollector;

impl Collector for WindowsCollector {
    fn collect(&self, profile: MetadataProfile) -> Result<NetworkSnapshot, CollectorError> {
        let scope = ObservationScope::new(
            ObservationScopeKind::CurrentHostNetworkStack,
            None,
            [ScopeLimitation::WslNetworkStackExcluded],
        )?;
        crate::collector::collect_native_snapshot(
            profile,
            scope,
            |_profile| Self::collect_native_pass(),
            read_process_observations,
        )
    }
}

impl WindowsCollector {
    fn collect_native_pass() -> Result<NativeObservationPass, CollectorError> {
        let records = collect_socket_records()?;
        let mut owner_pids = HashSet::new();
        for record in &records {
            if !owner_pids.contains(&record.pid) && owner_pids.len() >= CANDIDATE_PROCESS_IDS_MAX {
                return Err(
                    crate::observation::ObservationError::ProcessIdentityLimitExceeded.into(),
                );
            }
            owner_pids.insert(record.pid);
        }
        let mut sockets = Vec::with_capacity(records.len());
        let mut owners_by_socket = Vec::with_capacity(records.len());
        for record in records {
            sockets.push(NativeSocketObservation {
                endpoint: crate::observation::EndpointIdentity::new(
                    record.protocol,
                    record.local_addr,
                    u32::from(record.local_port),
                    record.ipv6_scope,
                )
                .map_err(|_| crate::observation::ObservationError::NativeDataMalformed)?,
                state: match record.state {
                    SocketState::Listen => crate::observation::SocketState::Listen,
                    SocketState::Bound => crate::observation::SocketState::Bound,
                },
                token: None,
            });
            owners_by_socket.push(vec![record.pid]);
        }
        Ok(NativeObservationPass {
            owners: OwnerAssociations {
                owners_by_socket,
                local_completeness: vec![OwnerCompleteness::Complete; sockets.len()],
                global_completeness: OwnerCompleteness::Complete,
                evidence_gaps: Vec::new(),
                omitted_evidence_gap_count: 0,
            },
            sockets,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketRecord {
    protocol: Protocol,
    local_addr: IpAddr,
    local_port: u16,
    ipv6_scope: Option<Ipv6Scope>,
    state: SocketState,
    pid: u32,
}

#[derive(Debug, Clone, Default)]
struct ProcessMetadata {
    process_name: Option<String>,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    unverified_parent_pid: Option<u32>,
    parent_process_name: Option<String>,
    start_time_marker: Option<ProcessStartMarker>,
    identity_reason: Option<UnverifiedOwnerReason>,
    partial: bool,
    budget_omitted: bool,
}

#[derive(Debug, Default)]
struct ProcessSnapshot {
    processes: HashMap<u32, ProcessMetadata>,
}

const PROCESS_HANDLE_CHUNK_MAX: usize = 256;
const RETAINED_PROCESS_HANDLES_MAX: usize = PROCESS_HANDLE_CHUNK_MAX + 1;

#[derive(Clone, Copy)]
enum ProcessSelection<'a> {
    All,
    Exact(&'a [u32]),
    ExactWithDirectChildren(&'a [u32]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessOpenError {
    PermissionDenied,
    Disappeared,
    IdentityUnavailable,
}

trait ProcessApi {
    type Handle;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError>;
    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError>;
    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker>;
    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker>;
    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String>;
    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf>;
    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String>;
    #[cfg(test)]
    fn observe_retained_handle_count(&mut self, _count: usize) {}
}

#[derive(Default)]
struct RealProcessApi {
    names: HashMap<u32, [u16; 260]>,
}

impl ProcessApi for RealProcessApi {
    type Handle = OwnedHandle;

    fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
        enumerate_process_relations(&mut self.names)
    }

    fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError> {
        open_query_process(pid)
    }

    fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker> {
        process_start_time_marker_from_handle(handle)
    }

    fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker> {
        process_start_time_marker(pid)
    }

    fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String> {
        decode_toolhelp_name(self.names.get(&pid)?, max_bytes)
    }

    fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf> {
        query_process_path(handle, max_bytes)
    }

    fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String> {
        query_process_command_line(handle, max_bytes)
    }
}

impl ProcessSnapshot {
    #[allow(
        clippy::too_many_lines,
        reason = "creation-handle bracketing and deterministic metadata budgeting are one safety transaction"
    )]
    fn collect(
        profile: MetadataProfile,
        selection: ProcessSelection<'_>,
    ) -> Result<Self, CollectorError> {
        Self::collect_with_budget(profile, selection, OPTIONAL_METADATA_MAX_BYTES)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "creation-handle bracketing and deterministic metadata budgeting are one safety transaction"
    )]
    fn collect_with_budget(
        profile: MetadataProfile,
        selection: ProcessSelection<'_>,
        metadata_budget: usize,
    ) -> Result<Self, CollectorError> {
        Self::collect_with(
            &mut RealProcessApi::default(),
            profile,
            selection,
            metadata_budget,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "creation-handle bracketing and deterministic metadata budgeting are one safety transaction"
    )]
    fn collect_with<Api: ProcessApi>(
        api: &mut Api,
        profile: MetadataProfile,
        selection: ProcessSelection<'_>,
        metadata_budget: usize,
    ) -> Result<Self, CollectorError> {
        if profile == MetadataProfile::IdentityOnly {
            return Ok(Self::default());
        }
        let first_relations = api.enumerate_relations()?;
        let mut selected = selected_process_ids(&first_relations, selection);
        if selected.len() > CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        selected.sort_unstable();
        selected.dedup();
        // Creation markers tie each first-snapshot PID to the process opened in
        // its later bounded chunk. This retains scalar identities, not every OS
        // handle, while still rejecting a recycled PID before metadata or a
        // parent edge can be accepted.
        let markers_before = selected
            .iter()
            .copied()
            .map(|pid| (pid, api.marker_for_pid(pid)))
            .collect::<HashMap<_, _>>();
        let relations = api.enumerate_relations()?;
        let mut snapshot = Self::default();
        let mut retained_bytes = 0usize;
        let mut parent_names = HashMap::new();
        for chunk in selected.chunks(PROCESS_HANDLE_CHUNK_MAX) {
            let mut handles = chunk
                .iter()
                .copied()
                .map(|pid| (pid, api.open_process(pid)))
                .collect::<HashMap<_, _>>();
            debug_assert!(handles.len() < RETAINED_PROCESS_HANDLES_MAX);
            #[cfg(test)]
            api.observe_retained_handle_count(handles.len());
            let retained_chunk_handles = handles.len();
            for &pid in chunk {
                let handle = match handles.remove(&pid) {
                    Some(Ok(handle)) => handle,
                    Some(Err(error)) => {
                        snapshot.processes.insert(
                            pid,
                            ProcessMetadata {
                                identity_reason: Some(unverified_reason_for_open(error)),
                                partial: true,
                                ..ProcessMetadata::default()
                            },
                        );
                        continue;
                    }
                    None => {
                        return Err(
                            crate::observation::ObservationError::NativeDataMalformed.into()
                        );
                    }
                };
                let Some(before) = markers_before.get(&pid).copied().flatten() else {
                    snapshot.processes.insert(
                        pid,
                        ProcessMetadata {
                            identity_reason: Some(UnverifiedOwnerReason::IdentityUnavailable),
                            partial: true,
                            ..ProcessMetadata::default()
                        },
                    );
                    continue;
                };
                let handle_marker = api.marker_from_handle(&handle);
                if handle_marker != Some(before) {
                    snapshot.processes.insert(
                        pid,
                        ProcessMetadata {
                            identity_reason: Some(UnverifiedOwnerReason::Raced),
                            partial: true,
                            ..ProcessMetadata::default()
                        },
                    );
                    continue;
                }
                let remaining = metadata_budget.saturating_sub(retained_bytes);
                let name_budget = remaining.min(PROCESS_NAME_MAX_BYTES);
                let mut process_name = (name_budget != 0)
                    .then(|| api.name(pid, name_budget))
                    .flatten();
                let mut budget_omitted =
                    process_name.is_none() && name_budget < PROCESS_NAME_MAX_BYTES;
                retain_string_field(
                    &mut process_name,
                    &mut retained_bytes,
                    PROCESS_NAME_MAX_BYTES,
                    metadata_budget,
                );
                let path_budget = metadata_budget
                    .saturating_sub(retained_bytes)
                    .min(EXECUTABLE_PATH_MAX_BYTES);
                let mut path = (path_budget != 0)
                    .then(|| api.path(&handle, path_budget))
                    .flatten();
                budget_omitted |= path.is_none() && path_budget < EXECUTABLE_PATH_MAX_BYTES;
                retain_path_field(&mut path, &mut retained_bytes, metadata_budget);
                let first_parent_pid = first_relations.get(&pid).copied().flatten();
                let second_parent_pid = relations.get(&pid).copied().flatten();
                let parent_relation_changed = first_parent_pid != second_parent_pid;
                let parent_pid = (!parent_relation_changed)
                    .then_some(second_parent_pid)
                    .flatten();
                let recorded_parent_pid = second_parent_pid.or(first_parent_pid);
                let (parent_pid, parent_process_name) = parent_pid
                    .and_then(|parent_pid| {
                        query_verified_parent(
                            api,
                            parent_pid,
                            before,
                            metadata_budget.saturating_sub(retained_bytes),
                            retained_chunk_handles,
                            &mut parent_names,
                        )
                        .map(|parent| (Some(parent_pid), parent.name))
                    })
                    .unwrap_or((None, None));
                let mut metadata = ProcessMetadata {
                    process_name,
                    executable_path: path.take(),
                    command_line: None,
                    parent_pid,
                    unverified_parent_pid: recorded_parent_pid.filter(|_| parent_pid.is_none()),
                    parent_process_name,
                    start_time_marker: Some(before),
                    identity_reason: None,
                    partial: false,
                    budget_omitted,
                };
                retain_string_field(
                    &mut metadata.parent_process_name,
                    &mut retained_bytes,
                    PROCESS_NAME_MAX_BYTES,
                    metadata_budget,
                );
                let command_line_budget = metadata_budget.saturating_sub(retained_bytes);
                metadata.command_line = (profile == MetadataProfile::LegacyList
                    && command_line_budget != 0)
                    .then(|| api.command_line(&handle, command_line_budget))
                    .flatten();
                metadata.budget_omitted |= profile == MetadataProfile::LegacyList
                    && metadata.command_line.is_none()
                    && command_line_budget < PROCESS_COMMAND_LINE_MAX_BYTES;
                retain_string_field(
                    &mut metadata.command_line,
                    &mut retained_bytes,
                    PROCESS_COMMAND_LINE_MAX_BYTES,
                    metadata_budget,
                );
                metadata.partial = metadata.process_name.is_none()
                    || metadata.executable_path.is_none()
                    || parent_relation_changed
                    || metadata.unverified_parent_pid.is_some()
                    || (metadata.parent_pid.is_some() && metadata.parent_process_name.is_none())
                    || (profile == MetadataProfile::LegacyList && metadata.command_line.is_none());
                let after = api.marker_from_handle(&handle);
                let current = api.marker_for_pid(pid);
                snapshot.processes.insert(
                    pid,
                    finish_bracketed_metadata(metadata, before, after, current),
                );
            }
        }

        Ok(snapshot)
    }

    fn metadata(&self, pid: u32) -> Option<&ProcessMetadata> {
        self.processes.get(&pid)
    }

    /// Direct children of `pid`, resolved on demand from the process map.
    ///
    /// No standing guest list of every ogre's offspring: this scans `processes`
    /// once per call instead of maintaining a precomputed parent->children index.
    /// Only `collect_process_context` asks for children, and only when the details
    /// modal opens — a rare, human-triggered action — so the per-refresh table path
    /// never builds a child index it does not read. It mirrors the Linux collector,
    /// which resolves children lazily too. Self is excluded, because no resident of
    /// the swamp gets to show up as its own kid.
    fn children(&self, pid: u32) -> ChildProcessSnapshot {
        let mut children = self
            .processes
            .iter()
            .filter(|&(&child_pid, metadata)| child_pid != pid && metadata.parent_pid == Some(pid))
            .map(|(&child_pid, metadata)| ChildProcess {
                pid: child_pid,
                process_name: metadata.process_name.clone(),
            })
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.pid);

        let truncated = children.len() > MAX_CHILD_PROCESSES;
        children.truncate(MAX_CHILD_PROCESSES);
        ChildProcessSnapshot {
            children,
            truncated,
        }
    }

    fn ancestor_pids(&self, pid: u32) -> HashSet<u32> {
        let mut ancestors = HashSet::from([pid]);
        let mut current = pid;
        for _ in 0..MAX_PROCESS_ANCESTORS {
            let Some(parent_pid) = self
                .processes
                .get(&current)
                .and_then(|metadata| metadata.parent_pid)
            else {
                break;
            };
            if !ancestors.insert(parent_pid) {
                break;
            }
            current = parent_pid;
        }
        ancestors
    }
}

fn selected_process_ids(
    relations: &HashMap<u32, Option<u32>>,
    selection: ProcessSelection<'_>,
) -> Vec<u32> {
    match selection {
        ProcessSelection::All => relations.keys().copied().collect(),
        ProcessSelection::Exact(pids) => pids.to_vec(),
        ProcessSelection::ExactWithDirectChildren(pids) => {
            let selected = pids.iter().copied().collect::<HashSet<_>>();
            relations
                .iter()
                .filter_map(|(pid, parent_pid)| {
                    (selected.contains(pid)
                        || parent_pid.is_some_and(|parent| selected.contains(&parent)))
                    .then_some(*pid)
                })
                .chain(pids.iter().copied())
                .collect()
        }
    }
}

const fn unverified_reason_for_open(error: ProcessOpenError) -> UnverifiedOwnerReason {
    match error {
        ProcessOpenError::PermissionDenied => UnverifiedOwnerReason::PermissionDenied,
        ProcessOpenError::Disappeared => UnverifiedOwnerReason::Disappeared,
        ProcessOpenError::IdentityUnavailable => UnverifiedOwnerReason::IdentityUnavailable,
    }
}

fn finish_bracketed_metadata(
    metadata: ProcessMetadata,
    before: ProcessStartMarker,
    after: Option<ProcessStartMarker>,
    current: Option<ProcessStartMarker>,
) -> ProcessMetadata {
    if after == Some(before) && current == Some(before) {
        metadata
    } else {
        ProcessMetadata {
            identity_reason: Some(UnverifiedOwnerReason::Raced),
            partial: true,
            ..ProcessMetadata::default()
        }
    }
}

fn enumerate_process_relations(
    names: &mut HashMap<u32, [u16; 260]>,
) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
    let raw_snapshot = unsafe {
        // SAFETY: process ID is ignored for TH32CS_SNAPPROCESS.
        CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    };
    if raw_snapshot == INVALID_HANDLE_VALUE {
        return Err(CollectorError::Platform {
            operation: "CreateToolhelp32Snapshot",
            detail: std::io::Error::last_os_error().to_string(),
        });
    }
    let snapshot = unsafe {
        // SAFETY: Toolhelp returned one owned non-sentinel handle.
        OwnedHandle::from_raw_handle(raw_snapshot)
    };
    let mut rows = HashMap::new();
    names.clear();
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(size_of::<PROCESSENTRY32W>()).expect("entry size fits u32"),
        ..PROCESSENTRY32W::default()
    };
    let mut present = unsafe {
        // SAFETY: entry has the required size and is writable.
        Process32FirstW(snapshot.as_raw_handle(), &raw mut entry)
    } != 0;
    while present {
        if rows.len() >= CANDIDATE_PROCESS_IDS_MAX {
            return Err(crate::observation::ObservationError::ProcessIdentityLimitExceeded.into());
        }
        rows.insert(
            entry.th32ProcessID,
            (entry.th32ParentProcessID != 0).then_some(entry.th32ParentProcessID),
        );
        names.insert(entry.th32ProcessID, entry.szExeFile);
        present = unsafe {
            // SAFETY: entry remains valid for the next API write.
            Process32NextW(snapshot.as_raw_handle(), &raw mut entry)
        } != 0;
    }
    let error = std::io::Error::last_os_error();
    if error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        != Some(ERROR_NO_MORE_FILES)
    {
        return Err(CollectorError::Platform {
            operation: "Process32NextW",
            detail: error.to_string(),
        });
    }
    Ok(rows)
}

fn open_query_process(pid: u32) -> Result<OwnedHandle, ProcessOpenError> {
    let handle = unsafe {
        // SAFETY: OpenProcess receives only value arguments and is checked.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if handle.is_null() {
        // Capture GetLastError before any formatting, allocation, or helper call
        // can overwrite this thread's Windows error slot.
        let error = std::io::Error::last_os_error();
        return Err(match windows_io_error_code(&error) {
            Some(ERROR_ACCESS_DENIED) => ProcessOpenError::PermissionDenied,
            Some(ERROR_INVALID_PARAMETER) => ProcessOpenError::Disappeared,
            _ => ProcessOpenError::IdentityUnavailable,
        });
    }
    Ok(unsafe {
        // SAFETY: the successful OpenProcess handle is owned by this scope.
        OwnedHandle::from_raw_handle(handle)
    })
}

struct VerifiedParent {
    name: Option<String>,
}

fn query_verified_parent<Api: ProcessApi>(
    api: &mut Api,
    parent_pid: u32,
    child_marker: ProcessStartMarker,
    max_bytes: usize,
    retained_chunk_handles: usize,
    names: &mut HashMap<ProcessIdentity, Option<String>>,
) -> Option<VerifiedParent> {
    let marker = api.marker_for_pid(parent_pid)?;
    if marker >= child_marker {
        return None;
    }
    let identity = ProcessIdentity {
        pid: parent_pid,
        start_marker: marker,
    };
    if let Some(name) = names.get(&identity) {
        return Some(VerifiedParent {
            name: name
                .as_ref()
                .filter(|name| name.len() <= max_bytes.min(PROCESS_NAME_MAX_BYTES))
                .cloned(),
        });
    }
    let handle = api.open_process(parent_pid).ok()?;
    debug_assert!(retained_chunk_handles < RETAINED_PROCESS_HANDLES_MAX);
    #[cfg(test)]
    api.observe_retained_handle_count(retained_chunk_handles + 1);
    let before = api.marker_from_handle(&handle)?;
    if before != marker {
        return None;
    }
    let name_budget = max_bytes.min(PROCESS_NAME_MAX_BYTES);
    let name = (name_budget != 0)
        .then(|| api.name(parent_pid, name_budget))
        .flatten();
    let after = api.marker_from_handle(&handle)?;
    let current = api.marker_for_pid(parent_pid)?;
    (before == after && after == current).then(|| {
        names.insert(identity, name.clone());
        VerifiedParent { name }
    })
}

fn query_process_path(handle: &OwnedHandle, max_bytes: usize) -> Option<PathBuf> {
    let code_units = max_bytes / 2;
    if code_units == 0 {
        return None;
    }
    let mut buffer = vec![0u16; code_units];
    let mut length = u32::try_from(buffer.len()).ok()?;
    let result = unsafe {
        // SAFETY: buffer owns `length` writable UTF-16 code units and the API
        // writes the resulting count through a valid pointer.
        QueryFullProcessImageNameW(
            handle.as_raw_handle(),
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    if result == 0 {
        return None;
    }
    let length = usize::try_from(length).ok()?;
    decode_utf16_bounded(
        buffer.get(..length)?,
        max_bytes.min(EXECUTABLE_PATH_MAX_BYTES),
    )
    .map(PathBuf::from)
}

fn query_process_command_line(handle: &OwnedHandle, max_bytes: usize) -> Option<String> {
    let mut required_bytes = 0u32;
    unsafe {
        // SAFETY: the null probe has zero capacity and writes only required_bytes.
        NtQueryInformationProcess(
            handle.as_raw_handle(),
            ProcessCommandLineInformation,
            std::ptr::null_mut(),
            0,
            &raw mut required_bytes,
        );
    }
    let required = usize::try_from(required_bytes).ok()?;
    let final_max = max_bytes.min(PROCESS_COMMAND_LINE_MAX_BYTES);
    let native_max = size_of::<UNICODE_STRING>().checked_add(final_max.checked_mul(2)?)?;
    if required < size_of::<UNICODE_STRING>() || required > native_max {
        return None;
    }
    // UNICODE_STRING contains a pointer and therefore needs pointer alignment;
    // a u16 allocation is not sufficiently aligned on 64-bit Windows.
    let mut buffer = vec![0_u64; required.div_ceil(size_of::<u64>())];
    let status = unsafe {
        // SAFETY: buffer owns required_bytes writable bytes and the API does not
        // retain either pointer.
        NtQueryInformationProcess(
            handle.as_raw_handle(),
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            required_bytes,
            &raw mut required_bytes,
        )
    };
    if status < 0 {
        return None;
    }
    let unicode = unsafe {
        // SAFETY: the successful API call initialized the leading UNICODE_STRING.
        &*buffer.as_ptr().cast::<UNICODE_STRING>()
    };
    let byte_length = usize::from(unicode.Length);
    if byte_length == 0 || byte_length % 2 != 0 || byte_length > final_max.checked_mul(2)? {
        return None;
    }
    let buffer_start = buffer.as_ptr() as usize;
    let start = (unicode.Buffer as usize).checked_sub(buffer_start)?;
    let end = start.checked_add(byte_length)?;
    if start % 2 != 0 || end > buffer.len().checked_mul(size_of::<u64>())? {
        return None;
    }
    let code_units = unsafe {
        // SAFETY: the returned pointer lies in the aligned u16 buffer, and both
        // offset and byte length were validated as even and in bounds.
        std::slice::from_raw_parts(unicode.Buffer, byte_length / 2)
    };
    decode_command_line_utf16(code_units, final_max)
}

fn decode_command_line_utf16(code_units: &[u16], final_max: usize) -> Option<String> {
    decode_utf16_bounded(code_units, final_max)
}

fn decode_toolhelp_name(code_units: &[u16; 260], final_max: usize) -> Option<String> {
    let end = code_units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(code_units.len());
    if end == 0 {
        return None;
    }
    decode_utf16_bounded(&code_units[..end], final_max)
}

fn decode_utf16_bounded(code_units: &[u16], final_max: usize) -> Option<String> {
    let mut final_bytes = 0usize;
    for decoded in std::char::decode_utf16(code_units.iter().copied()) {
        final_bytes =
            final_bytes.checked_add(decoded.unwrap_or(char::REPLACEMENT_CHARACTER).len_utf8())?;
        if final_bytes > final_max {
            return None;
        }
    }
    let mut value = String::new();
    value.try_reserve_exact(final_bytes).ok()?;
    value.extend(
        std::char::decode_utf16(code_units.iter().copied())
            .map(|decoded| decoded.unwrap_or(char::REPLACEMENT_CHARACTER)),
    );
    Some(value)
}

fn retain_string_field(
    field: &mut Option<String>,
    retained: &mut usize,
    per_value_max: usize,
    aggregate_max: usize,
) {
    let Some(length) = field.as_ref().map(String::len) else {
        return;
    };
    let Some(next) = retained.checked_add(length) else {
        *field = None;
        return;
    };
    if length > per_value_max || next > aggregate_max {
        *field = None;
    } else {
        *retained = next;
    }
}

fn retain_path_field(field: &mut Option<PathBuf>, retained: &mut usize, aggregate_max: usize) {
    let Some(length) = field.as_ref().map(|path| path.as_os_str().len()) else {
        return;
    };
    let Some(next) = retained.checked_add(length) else {
        *field = None;
        return;
    };
    if length > EXECUTABLE_PATH_MAX_BYTES || next > aggregate_max {
        *field = None;
    } else {
        *retained = next;
    }
}

fn read_process_observations(
    sorted_pids: &[u32],
    profile: MetadataProfile,
    optional_metadata_bytes_remaining: usize,
) -> Result<BTreeMap<u32, ProcessRead>, CollectorError> {
    if profile == MetadataProfile::IdentityOnly {
        let mut api = RealProcessApi::default();
        return Ok(sorted_pids
            .iter()
            .copied()
            .map(|pid| {
                let read = match api.open_process(pid) {
                    Ok(handle) => api.marker_from_handle(&handle).map_or(
                        ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                        |marker| ProcessRead::Verified {
                            marker,
                            observation: ProcessObservation::identity_only(),
                        },
                    ),
                    Err(error) => ProcessRead::Unverified(unverified_reason_for_open(error)),
                };
                (pid, read)
            })
            .collect());
    }

    let mut snapshot = ProcessSnapshot::collect_with_budget(
        profile,
        ProcessSelection::Exact(sorted_pids),
        optional_metadata_bytes_remaining,
    )?;
    Ok(sorted_pids
        .iter()
        .copied()
        .map(|pid| {
            let read = snapshot.processes.remove(&pid).map_or(
                ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable),
                process_read_from_metadata,
            );
            (pid, read)
        })
        .collect())
}

fn process_read_from_metadata(metadata: ProcessMetadata) -> ProcessRead {
    if let Some(reason) = metadata.identity_reason {
        return ProcessRead::Unverified(reason);
    }
    let Some(marker) = metadata.start_time_marker else {
        return ProcessRead::Unverified(UnverifiedOwnerReason::IdentityUnavailable);
    };
    ProcessRead::Verified {
        marker,
        observation: ProcessObservation {
            name: metadata.process_name.map(Arc::from),
            executable_path: metadata
                .executable_path
                .map(|path| Arc::<Path>::from(path.into_boxed_path())),
            command_line: metadata.command_line.map(Arc::from),
            parent_pid: metadata.parent_pid,
            parent_process_name: metadata.parent_process_name.map(Arc::from),
            metadata_omission: metadata
                .budget_omitted
                .then_some(MetadataOmission::BudgetExceeded),
            metadata_completeness: if metadata.partial {
                MetadataCompleteness::Partial
            } else {
                MetadataCompleteness::Complete
            },
        },
    }
}

pub(crate) fn collect_process_context(pid: u32) -> ProcessContext {
    let referenced = [pid];
    let processes = ProcessSnapshot::collect(
        MetadataProfile::Display,
        ProcessSelection::ExactWithDirectChildren(&referenced),
    )
    .unwrap_or_else(|_| ProcessSnapshot::default());
    ProcessContext {
        owner_uid: None,
        process_start_time_marker: process_start_time_marker(pid),
        children: processes.children(pid),
        docker: None,
    }
}

pub(crate) fn process_command_line_reader(pids: &[u32]) -> impl FnMut(u32) -> Option<String> {
    let processes =
        ProcessSnapshot::collect(MetadataProfile::LegacyList, ProcessSelection::Exact(pids))
            .unwrap_or_else(|_| ProcessSnapshot::default());
    move |pid| {
        processes
            .metadata(pid)
            .and_then(|metadata| metadata.command_line.clone())
    }
}

pub(crate) fn collect_tree_process_infos() -> Result<Vec<TreeProcessInfo>, CollectorError> {
    ProcessSnapshot::collect(MetadataProfile::Display, ProcessSelection::All)
        .map(|snapshot| tree_process_infos_from_snapshot(&snapshot))
}

fn tree_process_infos_from_snapshot(processes: &ProcessSnapshot) -> Vec<TreeProcessInfo> {
    tree_process_infos_from_snapshot_with(processes, |pid| {
        processes
            .processes
            .get(&pid)
            .and_then(|metadata| metadata.start_time_marker)
    })
}

fn tree_process_infos_from_snapshot_with(
    processes: &ProcessSnapshot,
    mut marker_for_pid: impl FnMut(u32) -> Option<ProcessStartMarker>,
) -> Vec<TreeProcessInfo> {
    let markers = processes
        .processes
        .keys()
        .map(|pid| (*pid, marker_for_pid(*pid)))
        .collect::<HashMap<_, _>>();
    let names = processes
        .processes
        .iter()
        .filter_map(|(pid, metadata)| Some((*pid, metadata.process_name.clone()?)))
        .collect::<HashMap<_, _>>();

    let mut rows = processes
        .processes
        .iter()
        .map(|(pid, metadata)| {
            let parent_edge = accepted_parent_edge(*pid, metadata.parent_pid, &markers);
            TreeProcessInfo {
                pid: *pid,
                parent_pid: parent_edge.verified,
                unverified_parent_pid: metadata.unverified_parent_pid.or(parent_edge.unverified),
                parent_process_name: parent_edge
                    .verified
                    .and_then(|parent_pid| names.get(&parent_pid).cloned()),
                process_name: metadata.process_name.clone(),
                start_time_marker: markers.get(pid).copied().flatten(),
                owner_uid: None,
                process_group: None,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(|info| info.pid);
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AcceptedParentEdge {
    verified: Option<u32>,
    unverified: Option<u32>,
}

fn accepted_parent_edge(
    child_pid: u32,
    parent_pid: Option<u32>,
    markers: &HashMap<u32, Option<ProcessStartMarker>>,
) -> AcceptedParentEdge {
    let Some(parent_pid) = parent_pid else {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    };
    if parent_pid == child_pid {
        return AcceptedParentEdge {
            verified: None,
            unverified: None,
        };
    }
    let Some(child_start) = markers.get(&child_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    let Some(parent_start) = markers.get(&parent_pid).copied().flatten() else {
        return AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        };
    };
    match child_start.cmp(&parent_start) {
        std::cmp::Ordering::Greater => AcceptedParentEdge {
            verified: Some(parent_pid),
            unverified: None,
        },
        std::cmp::Ordering::Equal => AcceptedParentEdge {
            verified: None,
            unverified: Some(parent_pid),
        },
        std::cmp::Ordering::Less => AcceptedParentEdge {
            verified: None,
            unverified: None,
        },
    }
}

pub(crate) fn process_start_time_marker(pid: u32) -> Option<ProcessStartMarker> {
    let handle = unsafe {
        // SAFETY: OpenProcess takes only value arguments here. The returned handle
        // is checked before being wrapped for owned close-on-drop handling.
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid)
    };
    if handle.is_null() {
        return None;
    }

    let process_handle = unsafe {
        // SAFETY: OpenProcess returned a non-null process handle that this scope
        // owns. OwnedHandle closes it exactly once when Donkey leaves the room.
        OwnedHandle::from_raw_handle(handle)
    };
    process_start_time_marker_from_handle(&process_handle)
}

pub(crate) fn process_start_time_marker_from_handle(
    handle: &OwnedHandle,
) -> Option<ProcessStartMarker> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();
    let result = unsafe {
        // SAFETY: all FILETIME pointers are valid for one write, and `handle` is
        // an owned process handle with query access.
        GetProcessTimes(
            handle.as_raw_handle(),
            &raw mut creation_time,
            &raw mut exit_time,
            &raw mut kernel_time,
            &raw mut user_time,
        )
    };
    (result != 0)
        .then(|| filetime_to_u64(creation_time))
        .and_then(|ticks| ProcessStartMarker::windows(ticks).ok())
}

fn filetime_to_u64(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime)
}

pub(crate) fn collect_related_process_hints(port: u16) -> Vec<RelatedProcessHint> {
    let current_pid = std::process::id();
    let processes = ProcessSnapshot::collect(MetadataProfile::LegacyList, ProcessSelection::All)
        .unwrap_or_else(|_| ProcessSnapshot::default());
    let excluded_pids = processes.ancestor_pids(current_pid);
    let mut rows = processes.processes.into_iter().collect::<Vec<_>>();
    rows.sort_by_key(|(pid, _metadata)| *pid);

    let mut hints = Vec::new();
    for (pid, metadata) in rows {
        if excluded_pids.contains(&pid) {
            continue;
        }
        let Some(command_line) = metadata.command_line else {
            continue;
        };
        if !diagnostic::command_mentions_port(&command_line, port) {
            continue;
        }
        hints.push(RelatedProcessHint {
            pid,
            process_name: metadata.process_name,
            command_line,
        });
        if hints.len() == MAX_RELATED_PROCESS_HINTS {
            break;
        }
    }
    hints
}

fn collect_socket_records() -> Result<Vec<SocketRecord>, CollectorError> {
    let mut records = Vec::new();
    collect_tcp4_records(&mut records)?;
    collect_tcp6_records(&mut records)?;
    collect_udp4_records(&mut records)?;
    collect_udp6_records(&mut records)?;
    Ok(records)
}

fn collect_tcp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        // The buffer is u32-aligned and `size` is its byte length.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = tcp4_rows(&table)?;
    extend_socket_records(records, rows.iter().filter_map(tcp4_record))?;
    Ok(())
}

fn collect_tcp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedTcpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 call above; only the address family changes.
        GetExtendedTcpTable(
            buffer,
            size,
            0,
            u32::from(AF_INET6),
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = tcp6_rows(&table)?;
    extend_socket_records(records, rows.iter().filter_map(tcp6_record))?;
    Ok(())
}

fn collect_udp4_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET)", |buffer, size| unsafe {
        // SAFETY: IP Helper writes at most `*size` bytes to the caller-owned buffer.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET), UDP_TABLE_OWNER_PID, 0)
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = udp4_rows(&table)?;
    extend_socket_records(records, rows.iter().map(udp4_record))?;
    Ok(())
}

fn collect_udp6_records(records: &mut Vec<SocketRecord>) -> Result<(), CollectorError> {
    let table = read_iphelper_table("GetExtendedUdpTable(AF_INET6)", |buffer, size| unsafe {
        // SAFETY: see the IPv4 UDP call above; only the address family changes.
        GetExtendedUdpTable(buffer, size, 0, u32::from(AF_INET6), UDP_TABLE_OWNER_PID, 0)
    })?;
    if table.is_empty() {
        return Ok(());
    }

    let rows = udp6_rows(&table)?;
    extend_socket_records(records, rows.iter().map(udp6_record))?;
    Ok(())
}

fn extend_socket_records(
    records: &mut Vec<SocketRecord>,
    incoming: impl IntoIterator<Item = SocketRecord>,
) -> Result<(), CollectorError> {
    for record in incoming {
        if records.len() >= SOCKET_OBSERVATIONS_MAX {
            return Err(
                crate::observation::ObservationError::SocketObservationLimitExceeded.into(),
            );
        }
        records.push(record);
    }
    Ok(())
}

fn read_iphelper_table<F>(operation: &'static str, mut call: F) -> Result<Vec<u32>, CollectorError>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
{
    read_iphelper_table_with(operation, &mut call, |words| vec![0_u32; words])
}

fn read_iphelper_table_with<F, A>(
    operation: &'static str,
    mut call: F,
    mut allocate: A,
) -> Result<Vec<u32>, CollectorError>
where
    F: FnMut(*mut c_void, *mut u32) -> u32,
    A: FnMut(usize) -> Vec<u32>,
{
    let mut size = 0_u32;
    let mut code = call(std::ptr::null_mut(), &raw mut size);
    if code == ERROR_NO_DATA {
        return Ok(Vec::new());
    }
    if code != ERROR_INSUFFICIENT_BUFFER && code != ERROR_SUCCESS {
        return Err(windows_api_error(operation, code));
    }

    for _ in 0..NATIVE_RESIZE_ATTEMPTS_MAX {
        if size == 0 {
            return Ok(Vec::new());
        }
        if size
            > u32::try_from(NATIVE_SOCKET_TABLE_MAX_BYTES)
                .expect("native socket-table byte limit fits the Windows API")
        {
            return Err(CollectorError::Platform {
                operation,
                detail: format!("table exceeds {NATIVE_SOCKET_TABLE_MAX_BYTES} byte read limit"),
            });
        }

        let words = usize::try_from(size)
            .expect("Windows table size must fit usize")
            .div_ceil(size_of::<u32>());
        let mut buffer = allocate(words);
        let mut buffer_size = u32::try_from(buffer.len() * size_of::<u32>())
            .expect("bounded Windows table buffer must fit u32");
        code = call(buffer.as_mut_ptr().cast::<c_void>(), &raw mut buffer_size);
        match code {
            ERROR_SUCCESS => {
                let returned_bytes =
                    usize::try_from(buffer_size).expect("Windows table size must fit usize");
                let allocated_bytes = std::mem::size_of_val(buffer.as_slice());
                if returned_bytes > allocated_bytes || returned_bytes % size_of::<u32>() != 0 {
                    return Err(CollectorError::Platform {
                        operation,
                        detail: "table returned an invalid byte length".to_owned(),
                    });
                }
                buffer.truncate(returned_bytes / size_of::<u32>());
                return Ok(buffer);
            }
            ERROR_NO_DATA => return Ok(Vec::new()),
            ERROR_INSUFFICIENT_BUFFER => size = buffer_size,
            code => return Err(windows_api_error(operation, code)),
        }
    }

    Err(CollectorError::Platform {
        operation,
        detail: "table kept growing while being read".to_owned(),
    })
}

fn tcp4_rows(buffer: &[u32]) -> Result<&[MIB_TCPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table),
    )
}

fn tcp6_rows(buffer: &[u32]) -> Result<&[MIB_TCP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_TCP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
    )
}

fn udp4_rows(buffer: &[u32]) -> Result<&[MIB_UDPROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDPTABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDPTABLE_OWNER_PID, table),
    )
}

fn udp6_rows(buffer: &[u32]) -> Result<&[MIB_UDP6ROW_OWNER_PID], CollectorError> {
    table_rows(
        buffer,
        "MIB_UDP6TABLE_OWNER_PID",
        std::mem::offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
    )
}

fn table_rows<'a, Row>(
    buffer: &'a [u32],
    operation: &'static str,
    row_offset_bytes: usize,
) -> Result<&'a [Row], CollectorError> {
    let buffer_bytes = std::mem::size_of_val(buffer);
    if buffer_bytes < size_of::<u32>() {
        return Err(CollectorError::Platform {
            operation,
            detail: "table buffer is smaller than its row count".to_owned(),
        });
    }

    let count = usize::try_from(buffer[0]).expect("Windows table row count must fit usize");
    let required = checked_table_byte_len(operation, count, size_of::<Row>(), row_offset_bytes)?;
    if required > buffer_bytes {
        return Err(CollectorError::Platform {
            operation,
            detail: "table row count exceeds returned buffer".to_owned(),
        });
    }

    let rows = unsafe {
        // SAFETY: the bounds check above proves the flexible array payload fits in
        // the returned u32-aligned buffer. IP Helper table rows are u32-aligned.
        let row_ptr = buffer
            .as_ptr()
            .cast::<u8>()
            .add(row_offset_bytes)
            .cast::<Row>();
        std::slice::from_raw_parts(row_ptr, count)
    };
    Ok(rows)
}

fn checked_table_byte_len(
    operation: &'static str,
    count: usize,
    row_size: usize,
    row_offset_bytes: usize,
) -> Result<usize, CollectorError> {
    let row_bytes = count
        .checked_mul(row_size)
        .ok_or_else(|| CollectorError::Platform {
            operation,
            detail: "table row count overflows usize".to_owned(),
        })?;
    row_offset_bytes
        .checked_add(row_bytes)
        .ok_or_else(|| CollectorError::Platform {
            operation,
            detail: "table byte length overflows usize".to_owned(),
        })
}

fn tcp4_record(row: &MIB_TCPROW_OWNER_PID) -> Option<SocketRecord> {
    (row.dwState == u32::try_from(MIB_TCP_STATE_LISTEN).expect("TCP listen state fits u32")).then(
        || SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
            local_port: decode_port(row.dwLocalPort),
            ipv6_scope: None,
            state: SocketState::Listen,
            pid: row.dwOwningPid,
        },
    )
}

fn tcp6_record(row: &MIB_TCP6ROW_OWNER_PID) -> Option<SocketRecord> {
    (row.dwState == u32::try_from(MIB_TCP_STATE_LISTEN).expect("TCP listen state fits u32")).then(
        || SocketRecord {
            protocol: Protocol::Tcp,
            local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            local_port: decode_port(row.dwLocalPort),
            ipv6_scope: Some(ipv6_scope(row.dwLocalScopeId)),
            state: SocketState::Listen,
            pid: row.dwOwningPid,
        },
    )
}

fn udp4_record(row: &MIB_UDPROW_OWNER_PID) -> SocketRecord {
    SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V4(ipv4_addr(row.dwLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        ipv6_scope: None,
        state: SocketState::Bound,
        pid: row.dwOwningPid,
    }
}

fn udp6_record(row: &MIB_UDP6ROW_OWNER_PID) -> SocketRecord {
    SocketRecord {
        protocol: Protocol::Udp,
        local_addr: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
        local_port: decode_port(row.dwLocalPort),
        ipv6_scope: Some(ipv6_scope(row.dwLocalScopeId)),
        state: SocketState::Bound,
        pid: row.dwOwningPid,
    }
}

const fn ipv6_scope(scope_id: u32) -> Ipv6Scope {
    match std::num::NonZeroU32::new(scope_id) {
        Some(scope_id) => Ipv6Scope::InterfaceIndex(scope_id),
        None => Ipv6Scope::Unscoped,
    }
}

fn ipv4_addr(raw: u32) -> Ipv4Addr {
    Ipv4Addr::from(raw.to_ne_bytes())
}

#[cfg(test)]
fn encode_port_for_tests(port: u16) -> u32 {
    u32::from(port.to_be())
}

fn decode_port(raw: u32) -> u16 {
    let port =
        u16::try_from(raw & u32::from(u16::MAX)).expect("masked IP Helper port value must fit u16");
    u16::from_be(port)
}

fn windows_api_error(operation: &'static str, code: u32) -> CollectorError {
    CollectorError::Platform {
        operation,
        detail: format!("Windows error {code}"),
    }
}

fn windows_io_error_code(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

#[cfg(test)]
mod tests {
    use super::{
        AcceptedParentEdge, MAX_CHILD_PROCESSES, ProcessApi, ProcessMetadata, ProcessOpenError,
        ProcessSelection, ProcessSnapshot, accepted_parent_edge, checked_table_byte_len,
        decode_command_line_utf16, decode_port, encode_port_for_tests, filetime_to_u64,
        finish_bracketed_metadata, process_read_from_metadata, read_iphelper_table_with,
        tcp4_record, tcp4_rows, tcp6_record, tcp6_rows, tree_process_infos_from_snapshot_with,
        udp4_record, udp4_rows, udp6_record, udp6_rows,
    };
    use crate::collector::CollectorError;
    use crate::model::{Protocol, SocketState};
    use crate::observation::{
        Ipv6Scope, MetadataProfile, ProcessRead, ProcessStartMarker, UnverifiedOwnerReason,
    };
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID, MIB_UDP6ROW_OWNER_PID,
        MIB_UDPROW_OWNER_PID,
    };

    fn full_process_metadata() -> ProcessMetadata {
        ProcessMetadata {
            process_name: Some("python.exe".to_owned()),
            executable_path: Some("C:/Python/python.exe".into()),
            command_line: Some("python.exe -m http.server 3000".to_owned()),
            parent_pid: Some(42),
            unverified_parent_pid: None,
            parent_process_name: Some("WindowsTerminal.exe".to_owned()),
            start_time_marker: ProcessStartMarker::windows(100).ok(),
            identity_reason: None,
            partial: false,
            budget_omitted: false,
        }
    }

    #[derive(Default)]
    struct FakeProcessApi {
        relations: Vec<HashMap<u32, Option<u32>>>,
        enumeration_count: usize,
        open_errors: HashMap<u32, ProcessOpenError>,
        markers: HashMap<u32, u64>,
        marker_reads: HashMap<u32, VecDeque<u64>>,
        paths: HashMap<u32, PathBuf>,
        names: HashMap<u32, String>,
        path_budgets: Vec<usize>,
        metadata_reads: Vec<(&'static str, u32, usize)>,
        max_retained_handles: usize,
    }

    impl FakeProcessApi {
        fn stable(relations: HashMap<u32, Option<u32>>) -> Self {
            let markers = relations
                .keys()
                .copied()
                .map(|pid| (pid, u64::from(pid) + 100))
                .collect();
            let paths = relations
                .keys()
                .copied()
                .map(|pid| (pid, PathBuf::from(format!("C:/fake/p{pid}.exe"))))
                .collect();
            let names = relations
                .keys()
                .copied()
                .map(|pid| (pid, format!("p{pid}.exe")))
                .collect();
            Self {
                relations: vec![relations.clone(), relations],
                markers,
                paths,
                names,
                ..Self::default()
            }
        }
    }

    impl ProcessApi for FakeProcessApi {
        type Handle = u32;

        fn enumerate_relations(&mut self) -> Result<HashMap<u32, Option<u32>>, CollectorError> {
            let index = self
                .enumeration_count
                .min(self.relations.len().saturating_sub(1));
            self.enumeration_count += 1;
            Ok(self.relations.get(index).cloned().unwrap_or_default())
        }

        fn open_process(&mut self, pid: u32) -> Result<Self::Handle, ProcessOpenError> {
            self.open_errors.get(&pid).copied().map_or(Ok(pid), Err)
        }

        fn marker_from_handle(&mut self, handle: &Self::Handle) -> Option<ProcessStartMarker> {
            self.marker_reads
                .get_mut(handle)
                .and_then(VecDeque::pop_front)
                .or_else(|| self.markers.get(handle).copied())
                .and_then(|marker| ProcessStartMarker::windows(marker).ok())
        }

        fn marker_for_pid(&mut self, pid: u32) -> Option<ProcessStartMarker> {
            self.markers
                .get(&pid)
                .copied()
                .and_then(|marker| ProcessStartMarker::windows(marker).ok())
        }

        fn name(&mut self, pid: u32, max_bytes: usize) -> Option<String> {
            self.metadata_reads.push(("name", pid, max_bytes));
            let name = self.names.get(&pid)?;
            (name.len() <= max_bytes).then(|| name.clone())
        }

        fn path(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<PathBuf> {
            self.metadata_reads.push(("path", *handle, max_bytes));
            self.path_budgets.push(max_bytes);
            let path = self.paths.get(handle)?;
            (path.as_os_str().len() <= max_bytes).then(|| path.clone())
        }

        fn command_line(&mut self, handle: &Self::Handle, max_bytes: usize) -> Option<String> {
            self.metadata_reads
                .push(("command_line", *handle, max_bytes));
            let command = format!("p{handle}.exe --serve");
            (command.len() <= max_bytes).then_some(command)
        }

        fn observe_retained_handle_count(&mut self, count: usize) {
            self.max_retained_handles = self.max_retained_handles.max(count);
        }
    }

    #[test]
    fn iphelper_zero_row_tables_are_legal() {
        let table = [0_u32];

        assert!(tcp4_rows(&table).unwrap().is_empty());
        assert!(tcp6_rows(&table).unwrap().is_empty());
        assert!(udp4_rows(&table).unwrap().is_empty());
        assert!(udp6_rows(&table).unwrap().is_empty());
    }

    #[test]
    fn iphelper_accepts_exact_byte_limit_without_oversized_allocation() {
        let limit = super::NATIVE_SOCKET_TABLE_MAX_BYTES;
        let mut calls = 0;
        let mut allocations = Vec::new();
        let table = read_iphelper_table_with(
            "test",
            |buffer, size| {
                calls += 1;
                if buffer.is_null() {
                    unsafe {
                        // SAFETY: the reader supplies a valid size output pointer.
                        *size = u32::try_from(limit).unwrap();
                    }
                    super::ERROR_INSUFFICIENT_BUFFER
                } else {
                    super::ERROR_SUCCESS
                }
            },
            |words| {
                allocations.push(words);
                vec![0_u32; words]
            },
        )
        .expect("the exact table byte limit is accepted");

        assert_eq!(calls, 2);
        assert_eq!(allocations, [limit / size_of::<u32>()]);
        assert_eq!(std::mem::size_of_val(table.as_slice()), limit);
    }

    #[test]
    fn iphelper_refuses_over_limit_before_allocation_or_data_call() {
        let mut calls = 0;
        let mut allocations = 0;
        let result = read_iphelper_table_with(
            "test",
            |_buffer, size| {
                calls += 1;
                unsafe {
                    // SAFETY: the reader supplies a valid size output pointer.
                    *size = u32::try_from(super::NATIVE_SOCKET_TABLE_MAX_BYTES + 1).unwrap();
                }
                super::ERROR_INSUFFICIENT_BUFFER
            },
            |words| {
                allocations += 1;
                vec![0_u32; words]
            },
        );

        assert!(result.is_err());
        assert_eq!(calls, 1, "only the size probe may reach IP Helper");
        assert_eq!(allocations, 0);
    }

    #[test]
    fn iphelper_can_succeed_on_third_resize_attempt() {
        let mut calls = 0;
        let table = read_iphelper_table_with(
            "test",
            |buffer, size| {
                calls += 1;
                unsafe {
                    // SAFETY: the reader supplies a valid size output pointer.
                    *size = u32::try_from(size_of::<u32>()).unwrap();
                    if calls == 4 {
                        buffer.cast::<u32>().write(0);
                    }
                }
                if calls == 4 {
                    super::ERROR_SUCCESS
                } else {
                    super::ERROR_INSUFFICIENT_BUFFER
                }
            },
            |words| vec![0_u32; words],
        )
        .expect("the third bounded resize attempt may succeed");

        assert_eq!(calls, 4, "one probe plus three data calls");
        assert_eq!(table, [0]);
    }

    #[test]
    fn iphelper_never_makes_a_fourth_resize_attempt() {
        let mut calls = 0;
        let result = read_iphelper_table_with(
            "test",
            |_buffer, size| {
                calls += 1;
                unsafe {
                    // SAFETY: the reader supplies a valid size output pointer.
                    *size = u32::try_from(size_of::<u32>()).unwrap();
                }
                super::ERROR_INSUFFICIENT_BUFFER
            },
            |words| vec![0_u32; words],
        );

        assert!(result.is_err());
        assert_eq!(calls, 4, "one probe plus exactly three data calls");
    }

    #[test]
    fn iphelper_truncates_to_successful_returned_byte_size() {
        let mut calls = 0;
        let table = read_iphelper_table_with(
            "test",
            |buffer: *mut c_void, size| {
                calls += 1;
                unsafe {
                    // SAFETY: the reader supplies a valid size output pointer and,
                    // on the data call, a buffer of the probed size.
                    if buffer.is_null() {
                        *size = 4 * u32::try_from(size_of::<u32>()).unwrap();
                        return super::ERROR_INSUFFICIENT_BUFFER;
                    }
                    buffer.cast::<u32>().write(0);
                    *size = u32::try_from(size_of::<u32>()).unwrap();
                }
                super::ERROR_SUCCESS
            },
            |words| vec![u32::MAX; words],
        )
        .expect("a shorter successful return is valid");

        assert_eq!(calls, 2);
        assert_eq!(table, [0]);
    }

    #[test]
    fn table_rows_reject_malicious_count_and_checked_arithmetic_overflow() {
        let malicious = [u32::MAX];
        assert!(udp4_rows(&malicious).is_err());

        assert!(checked_table_byte_len("test", usize::MAX, 2, 0).is_err());
        assert!(checked_table_byte_len("test", 1, 2, usize::MAX).is_err());
    }

    #[test]
    fn owner_batch_relation_enumeration_is_constant_vs_owner_count() {
        for owner_count in [1_u32, 128] {
            let relations = (1..=owner_count)
                .map(|pid| (pid, None))
                .collect::<HashMap<_, _>>();
            let pids = (1..=owner_count).collect::<Vec<_>>();
            let mut api = FakeProcessApi::stable(relations);

            let snapshot = ProcessSnapshot::collect_with(
                &mut api,
                MetadataProfile::Display,
                ProcessSelection::Exact(&pids),
                super::OPTIONAL_METADATA_MAX_BYTES,
            )
            .expect("fake batch collection succeeds");

            assert_eq!(snapshot.processes.len(), pids.len());
            assert_eq!(api.enumeration_count, 2);
        }
    }

    #[test]
    fn process_handles_are_retained_in_bounded_chunks() {
        let count = u32::try_from(super::PROCESS_HANDLE_CHUNK_MAX + 1).unwrap();
        let relations = (1..=count)
            .map(|pid| (pid, (pid != 1).then_some(1)))
            .collect::<HashMap<_, _>>();
        let pids = (1..=count).collect::<Vec<_>>();
        let mut api = FakeProcessApi::stable(relations);

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::Exact(&pids),
            super::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("chunked collection succeeds");

        assert_eq!(snapshot.processes.len(), pids.len());
        assert_eq!(api.enumeration_count, 2);
        assert_eq!(
            api.max_retained_handles,
            super::RETAINED_PROCESS_HANDLES_MAX
        );
    }

    #[test]
    fn parent_name_reads_are_capped_by_each_low_aggregate_remainder() {
        let relations = (1..=64)
            .map(|pid| (pid, (pid != 1).then_some(1)))
            .collect::<HashMap<_, _>>();
        let pids = (2..=64).collect::<Vec<_>>();
        let mut api = FakeProcessApi::stable(relations);

        ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::Exact(&pids),
            7,
        )
        .expect("low-budget metadata collection remains bounded");

        assert!(!api.path_budgets.is_empty());
        assert!(api.path_budgets.iter().all(|budget| *budget <= 7));
    }

    #[test]
    fn metadata_reads_use_toolhelp_name_source_and_deterministic_field_order() {
        let relations = HashMap::from([(7, Some(1)), (1, None)]);
        let mut api = FakeProcessApi::stable(relations);
        api.markers.insert(1, 1);
        api.markers.insert(7, 107);
        api.names.insert(7, "toolhelp.exe".to_owned());
        api.paths.insert(7, PathBuf::from("C:/different/path.exe"));

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::LegacyList,
            ProcessSelection::Exact(&[7]),
            super::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("fake collection succeeds");

        assert_eq!(
            snapshot.processes[&7].process_name.as_deref(),
            Some("toolhelp.exe")
        );
        let fields = api
            .metadata_reads
            .iter()
            .map(|(field, _, _)| *field)
            .collect::<Vec<_>>();
        assert_eq!(fields, ["name", "path", "name", "command_line"]);
    }

    #[test]
    fn low_aggregate_budget_is_reserved_in_name_then_path_order() {
        let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
        api.names.insert(7, "seven.exe".to_owned());

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::LegacyList,
            ProcessSelection::Exact(&[7]),
            9,
        )
        .expect("low-budget collection succeeds");

        assert_eq!(
            snapshot.processes[&7].process_name.as_deref(),
            Some("seven.exe")
        );
        assert_eq!(snapshot.processes[&7].executable_path, None);
        assert_eq!(
            api.metadata_reads,
            vec![("name", 7, 9)],
            "no later field allocates after the name consumes the reserve",
        );
    }

    #[test]
    fn command_line_utf16_seam_enforces_final_utf8_boundary() {
        let exact = vec![u16::from(b'x'); super::PROCESS_COMMAND_LINE_MAX_BYTES];
        assert_eq!(
            decode_command_line_utf16(&exact, super::PROCESS_COMMAND_LINE_MAX_BYTES)
                .as_deref()
                .map(str::len),
            Some(super::PROCESS_COMMAND_LINE_MAX_BYTES)
        );

        let oversized = vec![u16::from(b'x'); super::PROCESS_COMMAND_LINE_MAX_BYTES + 1];
        assert_eq!(
            decode_command_line_utf16(&oversized, super::PROCESS_COMMAND_LINE_MAX_BYTES),
            None
        );
    }

    #[test]
    fn batch_refuses_reused_pid_and_discards_its_metadata() {
        let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
        api.marker_reads.insert(7, VecDeque::from([107, 108]));
        api.markers.insert(7, 108);

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::Exact(&[7]),
            super::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("fake batch collection succeeds");

        assert_eq!(
            process_read_from_metadata(snapshot.processes[&7].clone()),
            ProcessRead::Unverified(UnverifiedOwnerReason::Raced)
        );
    }

    #[test]
    fn selected_process_context_batch_keeps_direct_children() {
        let relations = HashMap::from([(100, None), (101, Some(100)), (200, Some(1))]);
        let mut api = FakeProcessApi::stable(relations);
        api.markers.insert(100, 100);
        api.markers.insert(101, 200);

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::ExactWithDirectChildren(&[100]),
            0,
        )
        .expect("fake context collection succeeds");

        assert_eq!(
            snapshot.processes.keys().copied().collect::<HashSet<_>>(),
            HashSet::from([100, 101])
        );
        assert_eq!(snapshot.children(100).children[0].pid, 101);
        assert_eq!(snapshot.children(100).children[0].process_name, None);
        assert_eq!(api.enumeration_count, 2);
    }

    #[test]
    fn process_open_permission_denial_remains_distinct() {
        let mut api = FakeProcessApi::stable(HashMap::from([(7, None)]));
        api.open_errors
            .insert(7, ProcessOpenError::PermissionDenied);

        let snapshot = ProcessSnapshot::collect_with(
            &mut api,
            MetadataProfile::Display,
            ProcessSelection::Exact(&[7]),
            super::OPTIONAL_METADATA_MAX_BYTES,
        )
        .expect("permission denial remains row-local");

        assert_eq!(
            process_read_from_metadata(snapshot.processes[&7].clone()),
            ProcessRead::Unverified(UnverifiedOwnerReason::PermissionDenied)
        );
    }

    #[test]
    fn process_snapshot_tracks_current_process_ancestors() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                (
                    10,
                    ProcessMetadata {
                        parent_pid: Some(5),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    5,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    1,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let ancestors = snapshot.ancestor_pids(10);

        assert!(ancestors.contains(&10));
        assert!(ancestors.contains(&5));
        assert!(ancestors.contains(&1));
        assert_eq!(ancestors.len(), 3);
    }

    #[test]
    fn children_are_resolved_on_demand_sorted_and_self_excluded() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                // Self-parented: must not show up as its own child.
                (
                    100,
                    ProcessMetadata {
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                // Two real children, inserted out of PID order to pin the sort.
                (
                    102,
                    ProcessMetadata {
                        process_name: Some("worker-b".to_owned()),
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                (
                    101,
                    ProcessMetadata {
                        process_name: Some("worker-a".to_owned()),
                        parent_pid: Some(100),
                        ..ProcessMetadata::default()
                    },
                ),
                // Unrelated parent: must be filtered out.
                (
                    200,
                    ProcessMetadata {
                        parent_pid: Some(1),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let children = snapshot.children(100);

        let listed: Vec<(u32, Option<&str>)> = children
            .children
            .iter()
            .map(|child| (child.pid, child.process_name.as_deref()))
            .collect();
        assert_eq!(
            listed,
            vec![(101, Some("worker-a")), (102, Some("worker-b"))]
        );
        assert!(!children.truncated);
    }

    #[test]
    fn children_resolution_is_bounded() {
        let mut processes = HashMap::from([(100, ProcessMetadata::default())]);
        let max = u32::try_from(MAX_CHILD_PROCESSES).expect("child cap fits u32 test PIDs");
        for offset in 0..=max {
            processes.insert(
                1_000 + offset,
                ProcessMetadata {
                    parent_pid: Some(100),
                    ..ProcessMetadata::default()
                },
            );
        }
        let snapshot = ProcessSnapshot { processes };

        let children = snapshot.children(100);

        assert_eq!(children.children.len(), MAX_CHILD_PROCESSES);
        assert!(children.truncated);
    }

    #[test]
    fn tcp4_listen_row_becomes_socket_record() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: encode_port_for_tests(3000),
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 18422,
        };

        let record = tcp4_record(&row).expect("listen rows are kept");

        assert_eq!(record.protocol, Protocol::Tcp);
        assert_eq!(record.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(record.local_port, 3000);
        assert_eq!(record.state, SocketState::Listen);
        assert_eq!(record.pid, 18422);
    }

    #[test]
    fn tcp4_non_listen_row_is_ignored() {
        let row = MIB_TCPROW_OWNER_PID {
            dwState: 5,
            dwLocalAddr: u32::from_ne_bytes([127, 0, 0, 1]),
            dwLocalPort: encode_port_for_tests(3000),
            dwRemoteAddr: 0,
            dwRemotePort: 0,
            dwOwningPid: 18422,
        };

        assert_eq!(tcp4_record(&row), None);
    }

    #[test]
    fn tcp6_listen_row_keeps_ipv6_address() {
        let row = MIB_TCP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::LOCALHOST.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: encode_port_for_tests(8080),
            ucRemoteAddr: [0; 16],
            dwRemoteScopeId: 0,
            dwRemotePort: 0,
            dwState: u32::try_from(MIB_TCP_STATE_LISTEN).expect("listen state fits u32"),
            dwOwningPid: 77,
        };

        let record = tcp6_record(&row).expect("listen rows are kept");

        assert_eq!(record.local_addr, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(record.local_port, 8080);
        assert_eq!(record.ipv6_scope, Some(Ipv6Scope::Unscoped));
        assert_eq!(record.pid, 77);
    }

    #[test]
    fn udp_rows_are_bound_sockets() {
        let udp4 = MIB_UDPROW_OWNER_PID {
            dwLocalAddr: u32::from_ne_bytes([0, 0, 0, 0]),
            dwLocalPort: encode_port_for_tests(5353),
            dwOwningPid: 902,
        };
        let udp6 = MIB_UDP6ROW_OWNER_PID {
            ucLocalAddr: Ipv6Addr::UNSPECIFIED.octets(),
            dwLocalScopeId: 0,
            dwLocalPort: encode_port_for_tests(5355),
            dwOwningPid: 903,
        };

        assert_eq!(udp4_record(&udp4).state, SocketState::Bound);
        assert_eq!(udp4_record(&udp4).local_port, 5353);
        assert_eq!(udp6_record(&udp6).state, SocketState::Bound);
        assert_eq!(udp6_record(&udp6).local_port, 5355);
    }

    #[test]
    fn port_decoding_ignores_unused_high_bits() {
        assert_eq!(decode_port(0xDEAD_0000 | encode_port_for_tests(3000)), 3000);
    }

    #[test]
    fn filetime_marker_keeps_full_windows_creation_time_precision() {
        let marker = filetime_to_u64(FILETIME {
            dwLowDateTime: 0x89AB_CDEF,
            dwHighDateTime: 0x0123_4567,
        });

        assert_eq!(marker, 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn parent_edges_require_child_to_start_after_parent() {
        let markers = HashMap::from([
            (10, ProcessStartMarker::windows(100).ok()),
            (20, ProcessStartMarker::windows(200).ok()),
            (30, ProcessStartMarker::windows(50).ok()),
            (40, None),
        ]);

        assert_eq!(
            accepted_parent_edge(20, Some(10), &markers),
            AcceptedParentEdge {
                verified: Some(10),
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(10, Some(20), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(30, Some(10), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
        assert_eq!(
            accepted_parent_edge(20, Some(20), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: None,
            },
        );
    }

    #[test]
    fn missing_creation_time_keeps_parent_edge_unverified() {
        let markers = HashMap::from([
            (10, ProcessStartMarker::windows(100).ok()),
            (20, ProcessStartMarker::windows(200).ok()),
            (40, None),
        ]);

        assert_eq!(
            accepted_parent_edge(20, Some(99), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: Some(99),
            },
        );
        assert_eq!(
            accepted_parent_edge(40, Some(10), &markers),
            AcceptedParentEdge {
                verified: None,
                unverified: Some(10),
            },
        );
    }

    #[test]
    fn equal_creation_times_keep_parent_edge_unverified() {
        let snapshot = ProcessSnapshot {
            processes: HashMap::from([
                (10, ProcessMetadata::default()),
                (
                    20,
                    ProcessMetadata {
                        parent_pid: Some(10),
                        ..ProcessMetadata::default()
                    },
                ),
            ]),
        };

        let rows = tree_process_infos_from_snapshot_with(&snapshot, |_| {
            ProcessStartMarker::windows(100).ok()
        });
        let child = rows.iter().find(|row| row.pid == 20).expect("child row");

        assert_eq!(child.parent_pid, None);
        assert_eq!(child.unverified_parent_pid, Some(10));
    }

    #[test]
    fn process_read_uses_the_marker_that_bracketed_its_metadata() {
        let read = process_read_from_metadata(full_process_metadata());

        let ProcessRead::Verified {
            marker,
            observation,
        } = read
        else {
            panic!("identity-bracketed metadata must be verified");
        };
        assert_eq!(marker, ProcessStartMarker::windows(100).unwrap());
        assert_eq!(observation.name.as_deref(), Some("python.exe"));
        assert_eq!(
            observation.parent_process_name.as_deref(),
            Some("WindowsTerminal.exe")
        );
    }

    #[test]
    fn pid_reuse_marker_mismatch_is_unverified_and_discards_metadata() {
        let metadata = finish_bracketed_metadata(
            full_process_metadata(),
            ProcessStartMarker::windows(100).unwrap(),
            ProcessStartMarker::windows(101).ok(),
            ProcessStartMarker::windows(101).ok(),
        );

        assert_eq!(
            process_read_from_metadata(metadata),
            ProcessRead::Unverified(UnverifiedOwnerReason::Raced)
        );
    }
}
