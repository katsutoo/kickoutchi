//! Optional Docker enrichment for local port ownership.
//!
//! The native OS collectors remain the source of truth. This module only tries
//! to explain Docker-looking or metadata-hidden owners in the selected-row
//! details view, and every failure path returns no enrichment instead of
//! breaking port collection.

use std::io::{self, Read};
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::debug;

use crate::model::{
    DockerContainerPort, DockerPortContext, PermissionStatus, PortEntryView, Protocol,
};

const DOCKER_COMMAND_TIMEOUT: Duration = Duration::from_millis(1_500);
// How long to wait for a drain worker after the child is gone. Killing the
// direct docker child closes its pipe fds, so a healthy drain finishes almost
// immediately; the wait exists because a grandchild that inherited the pipe
// (Docker Desktop shims, credential helpers) can hold the write end open
// indefinitely, and an unbounded join would hang with it.
const DOCKER_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const DOCKER_OUTPUT_MAX_BYTES: usize = 256 * 1024;
const DOCKER_OUTPUT_READ_CHUNK_BYTES: usize = 8 * 1024;
const DOCKER_OUTPUT_DRAIN_WORKERS_MAX: usize = 8;
const DOCKER_CHILD_CLEANUP_WORKERS_MAX: usize = 4;
const DOCKER_ROWS_MAX: usize = 128;
const DOCKER_MATCHES_MAX: usize = 8;
const DOCKER_FIELD_MAX_BYTES: usize = 4 * 1024;
const DOCKER_PORT_SEGMENTS_MAX: usize = 64;
const DOCKER_HOST_MAX_BYTES: usize = 4 * 1024;

#[cfg(target_os = "linux")]
const LINUX_STATUS_READ_MAX_BYTES: usize = 64 * 1024;

#[cfg(unix)]
const DEFAULT_LOCAL_DOCKER_HOST: &str = "unix:///var/run/docker.sock";
#[cfg(windows)]
const DEFAULT_LOCAL_DOCKER_HOST: &str = "npipe:////./pipe/docker_engine";
#[cfg(not(any(unix, windows)))]
const DEFAULT_LOCAL_DOCKER_HOST: &str = "";

const DOCKER_PROCESS_NAMES: &[&str] = &[
    "docker",
    "docker.exe",
    "docker-proxy",
    "docker-proxy.exe",
    "dockerd",
    "dockerd.exe",
    "Docker Desktop.exe",
    "com.docker.backend",
    "com.docker.backend.exe",
    "com.docker.vpnkit",
    "com.docker.slirp",
    "vpnkit",
];

#[derive(Debug, Deserialize)]
struct DockerPsJsonRow {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Ports")]
    ports: String,
    #[serde(rename = "Labels")]
    labels: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DockerContainerRow {
    id: String,
    name: String,
    ports: String,
    compose_project: Option<String>,
    compose_service: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

impl PortRange {
    fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    fn mapped_port(self, peer: Self, port: u16) -> Option<u16> {
        if !self.contains(port) {
            return None;
        }
        if peer.start == peer.end {
            return Some(peer.start);
        }
        let offset = port.checked_sub(self.start)?;
        peer.start
            .checked_add(offset)
            .filter(|mapped| *mapped <= peer.end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublishedPort {
    host_addr: Option<IpAddr>,
    host_ports: PortRange,
    container_ports: PortRange,
    protocol: Protocol,
}

pub(crate) fn enrich_port(entry: PortEntryView<'_>) -> Option<DockerPortContext> {
    if !should_try_docker_enrichment(entry) {
        return None;
    }

    let output = docker_container_ls(entry.local_port, entry.protocol)?;
    docker_context_from_ps_output(entry, &output)
}

fn docker_container_ls(port: u16, protocol: Protocol) -> Option<String> {
    docker_container_ls_with_runner(port, protocol, run_command_bounded)
}

fn docker_container_ls_with_runner(
    port: u16,
    protocol: Protocol,
    run: impl FnOnce(&mut Command) -> Option<std::process::Output>,
) -> Option<String> {
    let configured_host = std::env::var("DOCKER_HOST").ok();
    docker_container_ls_with_host_and_runner(port, protocol, configured_host.as_deref(), run)
}

fn docker_container_ls_with_host_and_runner(
    port: u16,
    protocol: Protocol,
    configured_host: Option<&str>,
    run: impl FnOnce(&mut Command) -> Option<std::process::Output>,
) -> Option<String> {
    if docker_command_is_elevated() {
        debug!("skipping PATH-resolved docker CLI while process is elevated");
        return None;
    }

    let docker_host = local_docker_host(configured_host);
    if configured_host.is_some_and(|host| !docker_host_is_local(host)) {
        debug!("ignoring non-local Docker endpoint during port enrichment");
    }
    let publish_filter = format!("publish={port}/{}", protocol_filter(protocol));
    // `docker` resolves through PATH on purpose: install locations vary too
    // much (distro packages, Docker Desktop, Homebrew) for a fixed allowlist.
    // Elevation is rejected above before PATH resolution. An explicit local
    // host prevents the user's current Docker context from selecting a remote
    // daemon; a local DOCKER_HOST remains useful for rootless engines.
    let mut command = Command::new("docker");
    command
        .env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_TLS")
        .env_remove("DOCKER_TLS_VERIFY")
        .env_remove("DOCKER_CERT_PATH")
        .arg("--host")
        .arg(docker_host)
        .arg("container")
        .arg("ls")
        .arg("--filter")
        .arg(publish_filter)
        .arg("--format")
        .arg("json");
    let output = run(&mut command)?;
    if !output.status.success() {
        debug!(status = %output.status, "docker CLI returned non-success status");
        return None;
    }

    match String::from_utf8(output.stdout) {
        Ok(stdout) => Some(stdout),
        Err(error) => {
            debug!(%error, "docker CLI output was not UTF-8");
            None
        }
    }
}

fn local_docker_host(configured_host: Option<&str>) -> String {
    #[cfg(windows)]
    if let Some(host) = configured_host.and_then(normalize_windows_npipe_host) {
        return host;
    }

    #[cfg(unix)]
    if let Some(host) = configured_host.filter(|host| docker_host_is_local(host)) {
        return (*host).to_owned();
    }

    DEFAULT_LOCAL_DOCKER_HOST.to_owned()
}

fn docker_host_is_local(host: &str) -> bool {
    if host.is_empty()
        || host.len() > DOCKER_HOST_MAX_BYTES
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return false;
    }

    #[cfg(unix)]
    {
        host.strip_prefix("unix://")
            .is_some_and(|path| path.starts_with('/') && path.len() > 1)
    }

    #[cfg(windows)]
    {
        normalize_windows_npipe_host(host).is_some()
    }

    #[cfg(not(any(unix, windows)))]
    false
}

#[cfg(any(windows, test))]
fn normalize_windows_npipe_host(host: &str) -> Option<String> {
    const LOCAL_PREFIX: &str = "////./pipe/";

    if host.is_empty()
        || host.len() > DOCKER_HOST_MAX_BYTES
        || host.bytes().any(|byte| byte.is_ascii_control())
    {
        return None;
    }

    let (scheme, endpoint) = host.split_once(':')?;
    if !scheme.eq_ignore_ascii_case("npipe")
        || endpoint.contains(['%', '?', '#'])
        || endpoint.contains(':')
    {
        return None;
    }

    let endpoint = endpoint.replace('\\', "/");
    let prefix = endpoint.get(..LOCAL_PREFIX.len())?;
    if !prefix.eq_ignore_ascii_case(LOCAL_PREFIX) {
        return None;
    }
    let pipe_name = &endpoint[LOCAL_PREFIX.len()..];
    if pipe_name.is_empty()
        || pipe_name.split('/').any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.trim_end_matches([' ', '.']) != component
        })
    {
        return None;
    }

    Some(format!("npipe:////./pipe/{pipe_name}"))
}

#[cfg(test)]
thread_local! {
    static TEST_ELEVATION_OVERRIDE: std::cell::Cell<Option<bool>> = const {
        std::cell::Cell::new(None)
    };
    #[cfg(target_os = "linux")]
    pub(crate) static TEST_LINUX_ELEVATION_SOURCES: std::cell::Cell<Option<(bool, bool, bool)>> = const {
        std::cell::Cell::new(None)
    };
}

fn docker_command_is_elevated() -> bool {
    #[cfg(test)]
    if let Some(elevated) = TEST_ELEVATION_OVERRIDE.with(std::cell::Cell::get) {
        return elevated;
    }
    process_is_elevated()
}

#[cfg(target_os = "linux")]
fn process_is_elevated() -> bool {
    unix_ids_are_elevated() || linux_aux_is_secure() || linux_process_has_capabilities()
}

#[cfg(all(unix, not(target_os = "linux")))]
pub(crate) fn process_is_elevated() -> bool {
    unix_ids_are_elevated()
}

#[cfg(unix)]
fn unix_ids_are_elevated() -> bool {
    #[cfg(all(test, target_os = "linux"))]
    if let Some((ids, _, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return ids;
    }
    unsafe {
        // SAFETY: these libc identity queries take no arguments, access no
        // caller-provided memory, and cannot fail.
        libc::geteuid() == 0
            || libc::geteuid() != libc::getuid()
            || libc::getegid() != libc::getgid()
    }
}

#[cfg(target_os = "linux")]
fn linux_aux_is_secure() -> bool {
    #[cfg(test)]
    if let Some((_, aux_secure, _)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return aux_secure;
    }
    unsafe {
        // SAFETY: getauxval reads the process's immutable auxiliary vector and
        // takes no pointer arguments. AT_SECURE is nonzero for secure-execution
        // modes such as set-ID or file-capability launches.
        libc::getauxval(libc::AT_SECURE) != 0
    }
}

#[cfg(target_os = "linux")]
fn linux_process_has_capabilities() -> bool {
    #[cfg(test)]
    if let Some((_, _, capabilities)) = TEST_LINUX_ELEVATION_SOURCES.with(std::cell::Cell::get) {
        return capabilities;
    }
    // Docker enrichment is optional. If the privilege state cannot be proven
    // ordinary, fail closed and do not cross PATH with the process's authority.
    std::fs::File::open("/proc/self/status")
        .and_then(read_linux_status_bounded)
        .map_or(true, |status| {
            linux_status_has_capabilities(&status).unwrap_or(true)
        })
}

#[cfg(target_os = "linux")]
fn read_linux_status_bounded(mut reader: impl Read) -> io::Result<String> {
    let mut status = String::new();
    reader
        .by_ref()
        .take((LINUX_STATUS_READ_MAX_BYTES + 1) as u64)
        .read_to_string(&mut status)?;
    if status.len() > LINUX_STATUS_READ_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux process status exceeds the read limit",
        ));
    }
    Ok(status)
}

#[cfg(target_os = "linux")]
fn linux_status_has_capabilities(status: &str) -> Option<bool> {
    let mut found = 0_u8;
    let mut any = false;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !matches!(name, "CapPrm" | "CapEff" | "CapAmb") {
            continue;
        }
        found = found.saturating_add(1);
        any |= u64::from_str_radix(value.trim(), 16).ok()? != 0;
    }
    (found == 3).then_some(any)
}

#[cfg(windows)]
pub(crate) fn process_is_elevated() -> bool {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    let opened = unsafe {
        // SAFETY: GetCurrentProcess returns a valid pseudo-handle, and `token`
        // points to storage for the returned owned token handle.
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
    };
    if opened == 0 || token.is_null() {
        return true;
    }
    let token = unsafe {
        // SAFETY: OpenProcessToken returned a non-null handle owned by this
        // scope. OwnedHandle closes it exactly once.
        OwnedHandle::from_raw_handle(token)
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut returned_bytes = 0_u32;
    let expected_bytes =
        u32::try_from(size_of::<TOKEN_ELEVATION>()).expect("TOKEN_ELEVATION size must fit in u32");
    let queried = unsafe {
        // SAFETY: the token has TOKEN_QUERY access, `elevation` is valid for a
        // TOKEN_ELEVATION write, and both byte counts match its exact size.
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            expected_bytes,
            &raw mut returned_bytes,
        )
    };
    queried == 0 || returned_bytes != expected_bytes || elevation.TokenIsElevated != 0
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn process_is_elevated() -> bool {
    false
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    exceeded: bool,
}

#[derive(Debug)]
struct DrainCapacity {
    active: AtomicUsize,
    maximum: usize,
}

impl DrainCapacity {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn reserve_pair(self: &Arc<Self>) -> Option<[DrainPermit; 2]> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active.checked_add(2)? > self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 2,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some([DrainPermit(Arc::clone(self)), DrainPermit(Arc::clone(self))]);
                }
                Err(current) => active = current,
            }
        }
    }
}

#[derive(Debug)]
struct DrainPermit(Arc<DrainCapacity>);

impl Drop for DrainPermit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "drain worker reservation underflow");
    }
}

fn global_drain_capacity() -> Arc<DrainCapacity> {
    static CAPACITY: OnceLock<Arc<DrainCapacity>> = OnceLock::new();
    Arc::clone(
        CAPACITY.get_or_init(|| Arc::new(DrainCapacity::new(DOCKER_OUTPUT_DRAIN_WORKERS_MAX))),
    )
}

#[derive(Debug)]
struct ChildCleanupCapacity {
    active: AtomicUsize,
    maximum: usize,
}

impl ChildCleanupCapacity {
    const fn new(maximum: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            maximum,
        }
    }

    fn reserve(self: &Arc<Self>) -> Option<ChildCleanupPermit> {
        let mut active = self.active.load(Ordering::Acquire);
        loop {
            if active >= self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                active,
                active + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ChildCleanupPermit(Arc::clone(self))),
                Err(current) => active = current,
            }
        }
    }
}

#[derive(Debug)]
struct ChildCleanupPermit(Arc<ChildCleanupCapacity>);

impl Drop for ChildCleanupPermit {
    fn drop(&mut self) {
        let previous = self.0.active.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "child cleanup worker reservation underflow");
    }
}

struct ChildCleanup {
    child: mpsc::SyncSender<Child>,
    completed: mpsc::Receiver<()>,
}

impl ChildCleanup {
    fn handoff(self, child: Child) -> mpsc::Receiver<()> {
        self.child
            .try_send(child)
            .expect("new child cleanup channel must be empty and connected");
        self.completed
    }
}

fn global_child_cleanup_capacity() -> Arc<ChildCleanupCapacity> {
    static CAPACITY: OnceLock<Arc<ChildCleanupCapacity>> = OnceLock::new();
    Arc::clone(
        CAPACITY
            .get_or_init(|| Arc::new(ChildCleanupCapacity::new(DOCKER_CHILD_CLEANUP_WORKERS_MAX))),
    )
}

fn spawn_child_cleanup(capacity: &Arc<ChildCleanupCapacity>) -> io::Result<ChildCleanup> {
    let permit = capacity.reserve().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::WouldBlock,
            "docker child cleanup worker capacity exhausted",
        )
    })?;
    let (child_sender, child_receiver) = mpsc::sync_channel(1);
    let (completed_sender, completed_receiver) = mpsc::channel();
    thread::Builder::new()
        .name("kickoutchi-docker-child-cleanup".to_owned())
        .spawn(move || {
            let _permit = permit;
            let Ok(mut child) = child_receiver.recv() else {
                return;
            };
            if terminate_and_reap(&mut child) == ReapOutcome::OwnershipUncertain {
                // No later code may assume this child was reaped. Retain both
                // the handle and capacity slot without retrying or spinning.
                loop {
                    thread::park();
                }
            }
            let _ = completed_sender.send(());
        })?;
    Ok(ChildCleanup {
        child: child_sender,
        completed: completed_receiver,
    })
}

fn run_command_bounded(command: &mut Command) -> Option<std::process::Output> {
    run_command_bounded_with(command, DOCKER_COMMAND_TIMEOUT, DOCKER_OUTPUT_MAX_BYTES)
}

fn run_command_bounded_with(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
) -> Option<std::process::Output> {
    run_command_bounded_with_capacity(command, timeout, output_max_bytes, &global_drain_capacity())
}

fn run_command_bounded_with_capacity(
    command: &mut Command,
    timeout: Duration,
    output_max_bytes: usize,
    drain_capacity: &Arc<DrainCapacity>,
) -> Option<std::process::Output> {
    let [stdout_permit, stderr_permit] = drain_capacity.reserve_pair()?;
    let cleanup = match spawn_child_cleanup(&global_child_cleanup_capacity()) {
        Ok(cleanup) => cleanup,
        Err(error) => {
            debug!(%error, "docker CLI child cleanup worker unavailable");
            return None;
        }
    };
    let mut child = match command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            debug!(%error, "docker CLI unavailable for port enrichment");
            return None;
        }
    };

    let Some(stdout) = child.stdout.take() else {
        let _ = cleanup.handoff(child);
        debug!("docker CLI stdout pipe was unavailable");
        return None;
    };
    let Some(stderr) = child.stderr.take() else {
        let _ = cleanup.handoff(child);
        debug!("docker CLI stderr pipe was unavailable");
        return None;
    };
    let stdout_worker = match spawn_output_drain(
        "kickoutchi-docker-stdout",
        stdout,
        output_max_bytes,
        stdout_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            let _ = cleanup.handoff(child);
            debug!(%error, "docker CLI stdout drain worker failed to start");
            return None;
        }
    };
    let stderr_worker = match spawn_output_drain(
        "kickoutchi-docker-stderr",
        stderr,
        output_max_bytes,
        stderr_permit,
    ) {
        Ok(worker) => worker,
        Err(error) => {
            // The stdout worker is detached by design; killing the child
            // closed its pipe, so the worker exits on its own.
            let _ = cleanup.handoff(child);
            debug!(%error, "docker CLI stderr drain worker failed to start");
            return None;
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        let now = Instant::now();
        if now >= deadline {
            let _ = cleanup.handoff(child);
            let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
            let _ = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline);
            let _ = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline);
            debug!("docker CLI timed out during port enrichment");
            return None;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                thread::sleep(
                    Duration::from_millis(10).min(deadline.saturating_duration_since(now)),
                );
            }
            Err(error) => {
                let _ = cleanup.handoff(child);
                let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
                let _ = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline);
                let _ = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline);
                debug!(%error, "docker CLI wait failed during port enrichment");
                return None;
            }
        }
    };

    let drain_deadline = Instant::now() + DOCKER_OUTPUT_DRAIN_TIMEOUT;
    let stdout = finish_output_drain_before(&stdout_worker, "stdout", drain_deadline)?;
    let stderr = finish_output_drain_before(&stderr_worker, "stderr", drain_deadline)?;
    if stdout.exceeded || stderr.exceeded {
        debug!(
            stdout_exceeded = stdout.exceeded,
            stderr_exceeded = stderr.exceeded,
            "docker CLI output exceeded enrichment cap",
        );
        return None;
    }
    Some(std::process::Output {
        status,
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

/// Spawn a detached worker that drains one output pipe while the child runs.
///
/// The worker reports through a channel instead of a `JoinHandle` so the
/// parent can bound its wait: `read` on the pipe only returns once every
/// holder of the write end has closed it, and a grandchild that inherited the
/// fd can outlive the docker CLI itself, turning a `join` into an unbounded
/// hang. A worker that misses `DOCKER_OUTPUT_DRAIN_TIMEOUT` is abandoned and
/// exits on its own once the pipe finally closes; each enrichment attempt
/// remains charged against the global worker cap until its pipe closes.
fn spawn_output_drain<Reader>(
    name: &'static str,
    reader: Reader,
    output_max_bytes: usize,
    permit: DrainPermit,
) -> io::Result<mpsc::Receiver<io::Result<BoundedOutput>>>
where
    Reader: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let _permit = permit;
            // A failed send only means the parent gave up waiting; the result is
            // discarded either way, so there is nothing to handle.
            let _ = sender.send(read_output_bounded(reader, output_max_bytes));
        })?;
    Ok(receiver)
}

fn read_output_bounded(
    mut reader: impl Read,
    output_max_bytes: usize,
) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(output_max_bytes);
    let mut chunk = [0_u8; DOCKER_OUTPUT_READ_CHUNK_BYTES];
    loop {
        let remaining = output_max_bytes.saturating_sub(bytes.len());
        let read_capacity = remaining.saturating_add(1).min(chunk.len());
        let count = reader.read(&mut chunk[..read_capacity])?;
        if count == 0 {
            break;
        }
        let retained = count.min(remaining);
        bytes.extend_from_slice(&chunk[..retained]);
        if retained < count {
            return Ok(BoundedOutput {
                bytes,
                exceeded: true,
            });
        }
    }
    Ok(BoundedOutput {
        bytes,
        exceeded: false,
    })
}

fn finish_output_drain_before(
    worker: &mpsc::Receiver<io::Result<BoundedOutput>>,
    stream: &'static str,
    deadline: Instant,
) -> Option<BoundedOutput> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match worker.recv_timeout(remaining) {
        Ok(Ok(output)) => Some(output),
        Ok(Err(error)) => {
            debug!(%error, stream, "docker CLI output drain failed");
            None
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            debug!(
                stream,
                "docker CLI output drain timed out; abandoning the drain worker",
            );
            None
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            debug!(
                stream,
                "docker CLI output drain worker died before reporting"
            );
            None
        }
    }
}

trait ReapChild {
    fn process_id(&self) -> u32;
    fn terminate(&mut self) -> io::Result<()>;
    fn wait_for_exit(&mut self) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReapOutcome {
    Reaped,
    OwnershipUncertain,
}

impl ReapChild for std::process::Child {
    fn process_id(&self) -> u32 {
        self.id()
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.kill()
    }

    fn wait_for_exit(&mut self) -> io::Result<()> {
        self.wait().map(|_| ())
    }
}

fn terminate_and_reap(child: &mut impl ReapChild) -> ReapOutcome {
    if let Err(error) = child.terminate() {
        debug!(%error, pid = child.process_id(), "docker CLI cleanup termination failed");
    }
    match child.wait_for_exit() {
        Ok(()) => ReapOutcome::Reaped,
        Err(error) => {
            debug!(%error, pid = child.process_id(), "docker CLI cleanup wait failed; retaining ownership and capacity");
            ReapOutcome::OwnershipUncertain
        }
    }
}

fn docker_context_from_ps_output(
    entry: PortEntryView<'_>,
    output: &str,
) -> Option<DockerPortContext> {
    let mut containers = Vec::new();
    let mut truncated = false;

    'rows: for (row_index, line) in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        if row_index >= DOCKER_ROWS_MAX {
            truncated = true;
            break;
        }

        let Some(row) = parse_container_row(line) else {
            continue;
        };
        for published_port in parse_published_ports(&row.ports) {
            let Some(container_port) = matched_container_port(entry, published_port) else {
                continue;
            };
            if contains_container_match(&containers, &row.id, entry, container_port) {
                continue;
            }
            if containers.len() >= DOCKER_MATCHES_MAX {
                truncated = true;
                break 'rows;
            }
            containers.push(DockerContainerPort {
                id: row.id.clone(),
                name: row.name.clone(),
                compose_project: row.compose_project.clone(),
                compose_service: row.compose_service.clone(),
                host_port: entry.local_port,
                container_port,
                protocol: entry.protocol,
            });
        }
    }

    if containers.is_empty() {
        None
    } else {
        Some(DockerPortContext {
            containers,
            truncated,
        })
    }
}

fn contains_container_match(
    containers: &[DockerContainerPort],
    container_id: &str,
    entry: PortEntryView<'_>,
    container_port: u16,
) -> bool {
    containers.iter().any(|container| {
        container.id == container_id
            && container.host_port == entry.local_port
            && container.container_port == container_port
            && container.protocol == entry.protocol
    })
}

fn should_try_docker_enrichment(entry: PortEntryView<'_>) -> bool {
    looks_like_docker_owner(entry)
        || (entry.permission == PermissionStatus::Partial && entry.process_name.is_none())
}

fn looks_like_docker_owner(entry: PortEntryView<'_>) -> bool {
    entry.process_name.is_some_and(is_docker_process_name)
        || entry
            .executable_path
            .and_then(Path::file_name)
            .and_then(|name| name.to_str())
            .is_some_and(is_docker_process_name)
}

fn is_docker_process_name(name: &str) -> bool {
    DOCKER_PROCESS_NAMES
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn parse_container_row(line: &str) -> Option<DockerContainerRow> {
    if line.len() > DOCKER_FIELD_MAX_BYTES * 4 {
        return None;
    }

    let row: DockerPsJsonRow = serde_json::from_str(line).ok()?;
    if field_too_large(&row.id)
        || field_too_large(&row.names)
        || field_too_large(&row.ports)
        || field_too_large(&row.labels)
    {
        return None;
    }

    let id = trimmed_non_empty(&row.id)?;
    let name = first_container_name(&row.names).unwrap_or_else(|| id.clone());
    Some(DockerContainerRow {
        id,
        name,
        ports: row.ports,
        compose_project: label_value(&row.labels, "com.docker.compose.project"),
        compose_service: label_value(&row.labels, "com.docker.compose.service"),
    })
}

fn field_too_large(field: &str) -> bool {
    field.len() > DOCKER_FIELD_MAX_BYTES
}

fn trimmed_non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn first_container_name(names: &str) -> Option<String> {
    names
        .split(',')
        .map(str::trim)
        .find(|name| !name.is_empty())
        .map(str::to_owned)
}

fn label_value(labels: &str, key: &str) -> Option<String> {
    labels.split(',').find_map(|label| {
        let (label_key, value) = label.split_once('=')?;
        if label_key.trim() == key && !value.is_empty() {
            Some(value.to_owned())
        } else {
            None
        }
    })
}

fn parse_published_ports(ports: &str) -> Vec<PublishedPort> {
    let mut segments = ports.split(',');
    let parsed = segments
        .by_ref()
        .take(DOCKER_PORT_SEGMENTS_MAX)
        .filter_map(|segment| parse_published_port_segment(segment.trim()))
        .collect::<Vec<_>>();
    if segments.next().is_some() {
        Vec::new()
    } else {
        parsed
    }
}

fn parse_published_port_segment(segment: &str) -> Option<PublishedPort> {
    let (host_binding, container_binding) = segment.split_once("->")?;
    let (container_ports, protocol) = parse_container_binding(container_binding.trim())?;
    let (host_addr, host_ports) = parse_host_binding(host_binding.trim())?;
    Some(PublishedPort {
        host_addr,
        host_ports,
        container_ports,
        protocol,
    })
}

fn parse_container_binding(binding: &str) -> Option<(PortRange, Protocol)> {
    let (ports, protocol) = binding.rsplit_once('/')?;
    Some((parse_port_range(ports.trim())?, parse_protocol(protocol)?))
}

fn parse_host_binding(binding: &str) -> Option<(Option<IpAddr>, PortRange)> {
    let (host, ports) = split_host_binding(binding)?;
    let host_addr = match host {
        Some(host) => Some(parse_host_addr(host)?),
        None => None,
    };
    Some((host_addr, parse_port_range(ports)?))
}

fn split_host_binding(binding: &str) -> Option<(Option<&str>, &str)> {
    if binding.is_empty() {
        return None;
    }
    if let Some(stripped) = binding.strip_prefix('[') {
        let (host, ports) = stripped.split_once("]:")?;
        return Some((Some(host), ports));
    }
    if let Some((host, ports)) = binding.rsplit_once(':') {
        if ports.is_empty() {
            return None;
        }
        return if host.is_empty() {
            Some((None, ports))
        } else {
            Some((Some(host), ports))
        };
    }
    Some((None, binding))
}

fn parse_host_addr(host: &str) -> Option<IpAddr> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse().ok()
}

fn parse_port_range(ports: &str) -> Option<PortRange> {
    let trimmed = ports.trim();
    let (start, end) = if let Some((start, end)) = trimmed.split_once('-') {
        (parse_port(start)?, parse_port(end)?)
    } else {
        let port = parse_port(trimmed)?;
        (port, port)
    };
    if start > end {
        return None;
    }
    Some(PortRange { start, end })
}

fn parse_port(port: &str) -> Option<u16> {
    port.trim()
        .parse::<u16>()
        .ok()
        .and_then(NonZeroU16::new)
        .map(NonZeroU16::get)
}

fn parse_protocol(protocol: &str) -> Option<Protocol> {
    match protocol.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

fn matched_container_port(entry: PortEntryView<'_>, published_port: PublishedPort) -> Option<u16> {
    if entry.protocol != published_port.protocol {
        return None;
    }
    if !host_addr_matches(entry.local_addr, published_port.host_addr) {
        return None;
    }
    published_port
        .host_ports
        .mapped_port(published_port.container_ports, entry.local_port)
}

fn host_addr_matches(row_addr: IpAddr, docker_addr: Option<IpAddr>) -> bool {
    let Some(docker_addr) = docker_addr else {
        return true;
    };
    let row_addr = normalize_addr(row_addr);
    let docker_addr = normalize_addr(docker_addr);
    let same_family = matches!(
        (row_addr, docker_addr),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    );
    same_family
        && (row_addr == docker_addr || row_addr.is_unspecified() || docker_addr.is_unspecified())
}

fn normalize_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(addr),
        IpAddr::V6(addr) => addr.to_ipv4_mapped().map_or(IpAddr::V6(addr), IpAddr::V4),
    }
}

fn protocol_filter(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{
        ChildCleanupCapacity, DEFAULT_LOCAL_DOCKER_HOST, DOCKER_HOST_MAX_BYTES, DOCKER_MATCHES_MAX,
        DOCKER_OUTPUT_MAX_BYTES, DOCKER_PORT_SEGMENTS_MAX, DrainCapacity, ReapChild, ReapOutcome,
        TEST_ELEVATION_OVERRIDE, docker_container_ls_with_host_and_runner,
        docker_container_ls_with_runner, docker_context_from_ps_output, docker_host_is_local,
        finish_output_drain_before, host_addr_matches, local_docker_host, looks_like_docker_owner,
        normalize_windows_npipe_host, parse_published_ports, read_output_bounded,
        run_command_bounded_with, run_command_bounded_with_capacity, should_try_docker_enrichment,
        spawn_child_cleanup, spawn_output_drain, terminate_and_reap,
    };
    use crate::model::{
        PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState,
    };

    #[cfg(target_os = "linux")]
    use super::{
        LINUX_STATUS_READ_MAX_BYTES, TEST_LINUX_ELEVATION_SOURCES, linux_status_has_capabilities,
        read_linux_status_bounded,
    };

    const LARGE_OUTPUT_HELPER_ENV: &str = "KICKOUTCHI_TEST_DOCKER_LARGE_OUTPUT";
    const INHERITED_PIPE_PARENT_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_PARENT";
    const INHERITED_PIPE_GRANDCHILD_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_GRANDCHILD";
    #[cfg(unix)]
    const REAP_CHILD_HELPER_ENV: &str = "KICKOUTCHI_TEST_DOCKER_REAP_CHILD";

    struct ChannelReader(std::sync::mpsc::Receiver<()>);

    struct ExcessThenPanicReader {
        bytes: Vec<u8>,
        read: bool,
    }

    struct ReapChildProbe {
        events: Vec<&'static str>,
        terminate_error: bool,
        wait_error: bool,
    }

    impl ReapChild for ReapChildProbe {
        fn process_id(&self) -> u32 {
            42
        }

        fn terminate(&mut self) -> io::Result<()> {
            self.events.push("terminate");
            if self.terminate_error {
                Err(io::Error::other("injected termination failure"))
            } else {
                Ok(())
            }
        }

        fn wait_for_exit(&mut self) -> io::Result<()> {
            self.events.push("wait");
            if self.wait_error {
                Err(io::Error::other("injected wait failure"))
            } else {
                Ok(())
            }
        }
    }

    impl Read for ExcessThenPanicReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(
                !self.read,
                "the reader was polled after the first excess byte"
            );
            self.read = true;
            let count = self.bytes.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            Ok(count)
        }
    }

    #[cfg(target_os = "linux")]
    struct ErrorReader;

    #[cfg(target_os = "linux")]
    impl Read for ErrorReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected status read failure"))
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_capability_status_is_fail_closed_and_detects_active_authority() {
        let ordinary =
            "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
        assert_eq!(linux_status_has_capabilities(ordinary), Some(false));

        let privileged =
            "CapPrm:\t0000000000000000\nCapEff:\t0000000000000400\nCapAmb:\t0000000000000000\n";
        assert_eq!(linux_status_has_capabilities(privileged), Some(true));

        assert_eq!(linux_status_has_capabilities("CapEff:\t0\n"), None);
        assert_eq!(
            linux_status_has_capabilities("CapPrm:\txyz\nCapEff:\t0\nCapAmb:\t0\n"),
            None,
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_status_reader_accepts_the_exact_limit() {
        let input = "x".repeat(LINUX_STATUS_READ_MAX_BYTES);

        let status = read_linux_status_bounded(Cursor::new(input.as_bytes()))
            .expect("an exact-limit status must be accepted");

        assert_eq!(status, input);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_status_reader_rejects_limit_plus_one() {
        let input = vec![b'x'; LINUX_STATUS_READ_MAX_BYTES + 1];

        let error = read_linux_status_bounded(Cursor::new(input))
            .expect_err("an oversized status must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_status_reader_propagates_read_errors() {
        let error = read_linux_status_bounded(ErrorReader)
            .expect_err("a status read failure must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::Other);
    }

    impl Read for ChannelReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            let _ = self.0.recv();
            Ok(0)
        }
    }

    fn entry(port: u16, protocol: Protocol, addr: IpAddr, process_name: &str) -> PortEntry {
        PortEntry {
            protocol,
            local_addr: addr,
            local_port: port,
            state: match protocol {
                Protocol::Tcp => SocketState::Listen,
                Protocol::Udp => SocketState::Bound,
            },
            pid: Some(1234),
            process_name: Some(process_name.into()),
            executable_path: Some(PathBuf::from(format!("/usr/bin/{process_name}")).into()),
            command_line: None,
            parent_pid: None,
            parent_process_name: None,
            protected: false,
            platform: Platform::Linux,
            permission: PermissionStatus::Full,
            process_identity: None,
            ipv6_scope: None,
        }
    }

    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
    fn helper_writes_more_than_one_typical_pipe_buffer() {
        if std::env::var_os(LARGE_OUTPUT_HELPER_ENV).is_none() {
            return;
        }
        let bytes = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES / 2];
        std::io::stdout()
            .write_all(&bytes)
            .expect("large-output helper stdout must be writable");
        std::io::stderr()
            .write_all(&bytes)
            .expect("large-output helper stderr must be writable");
    }

    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
    fn helper_leaves_grandchild_holding_output_pipes() {
        if std::env::var_os(INHERITED_PIPE_PARENT_ENV).is_none() {
            return;
        }
        let executable = std::env::current_exe().expect("test binary must resolve");
        let mut grandchild = Command::new(executable)
            .env_remove(INHERITED_PIPE_PARENT_ENV)
            .env(INHERITED_PIPE_GRANDCHILD_ENV, "1")
            .args([
                "--exact",
                "docker::tests::helper_holds_inherited_output_pipes",
                "--ignored",
                "--nocapture",
            ])
            .spawn()
            .expect("grandchild test helper must start");
        thread::spawn(move || {
            let _ = grandchild.wait();
        });
    }

    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
    fn helper_holds_inherited_output_pipes() {
        if std::env::var_os(INHERITED_PIPE_GRANDCHILD_ENV).is_none() {
            return;
        }
        thread::sleep(Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by Docker cleanup tests"]
    fn helper_waits_to_be_reaped() {
        if std::env::var_os(REAP_CHILD_HELPER_ENV).is_none() {
            return;
        }
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn stdout_and_stderr_are_drained_while_the_child_is_running() {
        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.env(LARGE_OUTPUT_HELPER_ENV, "1").args([
            "--exact",
            "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
            "--ignored",
            "--nocapture",
        ]);

        let output = run_command_bounded_with(
            &mut command,
            Duration::from_secs(10),
            DOCKER_OUTPUT_MAX_BYTES,
        )
        .expect("a child writing below the cap must not block on a full pipe");

        assert!(output.status.success());
        assert!(
            output.stdout.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
            "the helper's pipe-sized output was not fully drained",
        );
        assert!(
            output.stderr.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
            "the helper's pipe-sized stderr was not fully drained",
        );
    }

    #[test]
    fn elevated_enrichment_does_not_execute_docker() {
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(Some(true)));
        let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
            panic!("elevated enrichment must not execute a PATH-resolved command")
        });
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(None));

        assert!(output.is_none());
    }

    #[test]
    fn remote_docker_endpoints_fall_back_to_the_platform_local_daemon() {
        for remote in [
            "tcp://docker.example:2376",
            "ssh://builder.example",
            "http://docker.example",
            "https://docker.example",
            "npipe:////remote-host/pipe/docker_engine",
            "unix://relative.sock",
            "unix:///tmp/socket\nignored",
        ] {
            assert!(
                !docker_host_is_local(remote),
                "unexpectedly local: {remote}"
            );
            assert_eq!(local_docker_host(Some(remote)), DEFAULT_LOCAL_DOCKER_HOST);
        }
        let oversized = format!("unix:///{}", "x".repeat(DOCKER_HOST_MAX_BYTES));
        assert!(!docker_host_is_local(&oversized));
        assert_eq!(
            local_docker_host(Some(&oversized)),
            DEFAULT_LOCAL_DOCKER_HOST
        );
    }

    #[test]
    fn docker_command_removes_ambient_remote_selectors_and_pins_local_host() {
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(Some(false)));
        let output = docker_container_ls_with_host_and_runner(
            8080,
            Protocol::Tcp,
            Some("ssh://builder.example"),
            |command| {
                let arguments = command
                    .get_args()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>();
                assert_eq!(
                    arguments,
                    [
                        "--host",
                        DEFAULT_LOCAL_DOCKER_HOST,
                        "container",
                        "ls",
                        "--filter",
                        "publish=8080/tcp",
                        "--format",
                        "json",
                    ]
                );
                for variable in [
                    "DOCKER_HOST",
                    "DOCKER_CONTEXT",
                    "DOCKER_TLS",
                    "DOCKER_TLS_VERIFY",
                    "DOCKER_CERT_PATH",
                ] {
                    assert_eq!(
                        command
                            .get_envs()
                            .find(|(name, _)| *name == variable)
                            .map(|(_, value)| value),
                        Some(None),
                        "{variable} must be removed"
                    );
                }
                None
            },
        );
        TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(None));
        assert!(output.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn absolute_local_unix_docker_host_is_preserved() {
        let host = "unix:///run/user/1000/docker.sock";
        assert!(docker_host_is_local(host));
        assert_eq!(local_docker_host(Some(host)), host);
    }

    #[cfg(windows)]
    #[test]
    fn local_windows_docker_named_pipe_is_preserved() {
        let host = "npipe:////./pipe/docker_engine_rootless";
        assert!(docker_host_is_local(host));
        assert_eq!(local_docker_host(Some(host)), host);
    }

    #[test]
    fn windows_named_pipe_hosts_are_structurally_normalized() {
        assert_eq!(
            normalize_windows_npipe_host("NPIPE://\\\\.\\PIPE\\docker_engine\\rootless").as_deref(),
            Some("npipe:////./pipe/docker_engine/rootless")
        );
        assert_eq!(
            normalize_windows_npipe_host("npipe:////./PIPE/docker_engine").as_deref(),
            Some("npipe:////./pipe/docker_engine")
        );
    }

    #[test]
    fn windows_named_pipe_hosts_reject_nonlocal_or_ambiguous_paths() {
        for host in [
            "npipe:////remote/pipe/docker_engine",
            "npipe://localhost/pipe/docker_engine",
            "npipe:////?/pipe/docker_engine",
            "npipe:////./pipe/../docker_engine",
            "npipe:////./pipe/a/../../docker_engine",
            "npipe:////./pipe/.. /docker_engine",
            "npipe:////./pipe/docker_engine. ",
            "npipe:////./pipe//docker_engine",
            "npipe:////./pipe/docker_engine/",
            "npipe:////./pipe/%2e%2e/docker_engine",
            "npipe:////%2e/pipe/docker_engine",
            "npipe:////./pipe/docker_engine?ignored",
            "npipe:////./pipe/docker_engine#ignored",
            "npipe:////./pipe/C:/docker_engine",
            "npipe:////.\\pipe\\..\\docker_engine",
        ] {
            assert_eq!(
                normalize_windows_npipe_host(host),
                None,
                "unexpectedly accepted {host}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn capability_only_elevation_blocks_the_real_docker_command_gate() {
        TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(Some((false, false, true))));
        let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
            panic!("Linux capabilities must block PATH-resolved Docker execution")
        });
        TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(None));

        assert!(output.is_none());
    }

    #[test]
    fn drain_capacity_is_bounded_and_recovers_when_workers_exit() {
        let capacity = Arc::new(DrainCapacity::new(2));
        let [first_permit, second_permit] =
            capacity.reserve_pair().expect("two slots are available");
        let (first_sender, first_reader) = std::sync::mpsc::channel();
        let (second_sender, second_reader) = std::sync::mpsc::channel();
        let first_worker = spawn_output_drain(
            "kickoutchi-test-drain-one",
            ChannelReader(first_reader),
            1,
            first_permit,
        )
        .expect("first drain starts");
        let second_worker = spawn_output_drain(
            "kickoutchi-test-drain-two",
            ChannelReader(second_reader),
            1,
            second_permit,
        )
        .expect("second drain starts");

        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.args([
            "--exact",
            "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
            "--ignored",
        ]);
        assert!(
            run_command_bounded_with_capacity(&mut command, Duration::from_secs(1), 1, &capacity,)
                .is_none(),
            "a command must not start while both drain slots are occupied",
        );
        assert_eq!(capacity.active.load(Ordering::Acquire), 2);

        drop(first_sender);
        drop(second_sender);
        let finish_deadline = Instant::now() + Duration::from_secs(1);
        finish_output_drain_before(&first_worker, "first", finish_deadline)
            .expect("first drain exits");
        finish_output_drain_before(&second_worker, "second", finish_deadline)
            .expect("second drain exits");
        let release_deadline = Instant::now() + Duration::from_secs(1);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
        assert!(capacity.reserve_pair().is_some());
    }

    #[test]
    fn inherited_grandchild_pipes_bound_latency_and_release_capacity() {
        let capacity = Arc::new(DrainCapacity::new(2));
        let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
        command.env(INHERITED_PIPE_PARENT_ENV, "1").args([
            "--exact",
            "docker::tests::helper_leaves_grandchild_holding_output_pipes",
            "--ignored",
            "--nocapture",
        ]);

        assert!(
            run_command_bounded_with_capacity(
                &mut command,
                Duration::from_secs(5),
                DOCKER_OUTPUT_MAX_BYTES,
                &capacity,
            )
            .is_none()
        );
        assert_eq!(capacity.active.load(Ordering::Acquire), 2);

        let release_deadline = Instant::now() + Duration::from_secs(3);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn expired_drain_deadline_returns_without_a_worker_result() {
        // A live sender that never sends models a drain worker stuck in
        // `read` on a pipe some grandchild still holds open. The wait must
        // return once its deadline has passed instead of blocking with the
        // worker.
        let (sender, receiver) = std::sync::mpsc::channel();

        let output = finish_output_drain_before(&receiver, "stdout", Instant::now());

        assert!(
            output.is_none(),
            "a drain that never completed must not produce output",
        );
        drop(sender);
    }

    #[test]
    fn output_reader_stops_after_the_first_excess_byte() {
        let reader = ExcessThenPanicReader {
            bytes: vec![b'x'; 4],
            read: false,
        };

        let output = read_output_bounded(reader, 3).expect("in-memory output read must succeed");

        assert_eq!(output.bytes, b"xxx");
        assert!(output.exceeded);
    }

    #[test]
    fn output_reader_accepts_the_exact_cap() {
        let input = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES];

        let output = read_output_bounded(Cursor::new(input), DOCKER_OUTPUT_MAX_BYTES)
            .expect("exact-limit output read must succeed");

        assert_eq!(output.bytes.len(), DOCKER_OUTPUT_MAX_BYTES);
        assert!(!output.exceeded);
    }

    #[test]
    fn docker_cleanup_waits_once_even_when_termination_fails() {
        let mut child = ReapChildProbe {
            events: Vec::new(),
            terminate_error: true,
            wait_error: false,
        };

        let outcome = terminate_and_reap(&mut child);

        assert_eq!(child.events, ["terminate", "wait"]);
        assert_eq!(outcome, ReapOutcome::Reaped);
    }

    #[test]
    fn docker_cleanup_does_not_retry_a_failed_wait() {
        let mut child = ReapChildProbe {
            events: Vec::new(),
            terminate_error: false,
            wait_error: true,
        };

        let outcome = terminate_and_reap(&mut child);

        assert_eq!(child.events, ["terminate", "wait"]);
        assert_eq!(outcome, ReapOutcome::OwnershipUncertain);
    }

    #[test]
    fn docker_cleanup_worker_capacity_refuses_spawn_until_ownership_returns() {
        let capacity = Arc::new(ChildCleanupCapacity::new(1));
        let cleanup = spawn_child_cleanup(&capacity).expect("first cleanup worker must start");

        let error = spawn_child_cleanup(&capacity)
            .err()
            .expect("second cleanup worker must be refused");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

        drop(cleanup);
        let release_deadline = Instant::now() + Duration::from_secs(1);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
        assert!(spawn_child_cleanup(&capacity).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn docker_cleanup_reaps_a_real_direct_child() {
        let capacity = Arc::new(ChildCleanupCapacity::new(1));
        let cleanup = spawn_child_cleanup(&capacity).expect("cleanup worker must start");
        let child = Command::new(std::env::current_exe().expect("test binary must resolve"))
            .env(REAP_CHILD_HELPER_ENV, "1")
            .args([
                "--exact",
                "docker::tests::helper_waits_to_be_reaped",
                "--ignored",
                "--nocapture",
            ])
            .spawn()
            .expect("reap test helper must start");
        let pid = libc::pid_t::try_from(child.id()).expect("child PID must fit pid_t");

        let completed = cleanup.handoff(child);
        completed
            .recv_timeout(Duration::from_secs(2))
            .expect("cleanup worker must terminate and reap the child");

        let mut status = 0;
        let result = unsafe {
            // SAFETY: pid came from the direct child and status is writable.
            libc::waitpid(pid, &raw mut status, libc::WNOHANG)
        };
        assert_eq!(result, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        let release_deadline = Instant::now() + Duration::from_secs(1);
        while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
            thread::yield_now();
        }
        assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn non_docker_processes_do_not_trigger_enrichment() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "postgres",
        );

        assert!(!should_try_docker_enrichment(PortEntryView::from(&row)));
    }

    #[test]
    fn missing_owner_metadata_can_trigger_optional_docker_enrichment() {
        let mut row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "postgres",
        );
        row.pid = None;
        row.process_name = None;
        row.executable_path = None;
        row.permission = PermissionStatus::Partial;

        assert!(should_try_docker_enrichment(PortEntryView::from(&row)));
    }

    #[test]
    fn docker_proxy_processes_trigger_enrichment_case_insensitively() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "Docker-Proxy",
        );

        assert!(looks_like_docker_owner(PortEntryView::from(&row)));
    }

    #[test]
    fn parses_published_ports_and_ignores_exposed_only_ports() {
        let ports = parse_published_ports("80/tcp, 127.0.0.1:5432->5432/tcp, [::]:5353->5353/udp");

        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].host_addr, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert_eq!(ports[0].host_ports.start, 5432);
        assert_eq!(ports[0].container_ports.start, 5432);
        assert_eq!(ports[0].protocol, Protocol::Tcp);
        assert_eq!(ports[1].host_addr, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert_eq!(ports[1].protocol, Protocol::Udp);
    }

    #[test]
    fn published_port_parser_rejects_zero_at_the_input_boundary() {
        assert!(parse_published_ports("0.0.0.0:0->5432/tcp").is_empty());
        assert!(parse_published_ports("0.0.0.0:5432->0/tcp").is_empty());
    }

    #[test]
    fn published_port_segment_limit_rejects_the_first_excess_segment() {
        let segment = "0.0.0.0:5432->5432/tcp";
        let exact = std::iter::repeat_n(segment, DOCKER_PORT_SEGMENTS_MAX)
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_published_ports(&exact).len(),
            DOCKER_PORT_SEGMENTS_MAX
        );

        let over = format!("{exact},{segment}");
        assert!(parse_published_ports(&over).is_empty());
    }

    #[test]
    fn docker_match_truncation_starts_only_at_match_nine() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = (0..=DOCKER_MATCHES_MAX)
            .map(|index| {
                format!(
                    r#"{{"ID":"container-{index}","Names":"db-{index}","Ports":"0.0.0.0:5432->5432/tcp","Labels":""}}"#
                )
            })
            .collect::<Vec<_>>();

        let exact = docker_context_from_ps_output(
            PortEntryView::from(&row),
            &output[..DOCKER_MATCHES_MAX].join("\n"),
        )
        .expect("eight matches are retained");
        assert_eq!(exact.containers.len(), DOCKER_MATCHES_MAX);
        assert!(!exact.truncated);

        let over = docker_context_from_ps_output(PortEntryView::from(&row), &output.join("\n"))
            .expect("the first eight matches remain available");
        assert_eq!(over.containers.len(), DOCKER_MATCHES_MAX);
        assert!(over.truncated);
    }

    #[test]
    fn port_ranges_map_host_port_to_container_port() {
        let row = entry(
            8001,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8000-8002->9000-9002/tcp","Labels":""}"#;

        let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
            .expect("range matches");
        let container = context.single_container().expect("one container");

        assert_eq!(container.host_port, 8001);
        assert_eq!(container.container_port, 9001);
    }

    #[test]
    fn compose_labels_and_stop_command_are_preserved_for_one_match() {
        let row = entry(
            5432,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"a762a2b37a1d","Names":"postgres-dev","Ports":"0.0.0.0:5432->5432/tcp","Labels":"com.docker.compose.project=swamp,com.docker.compose.service=db"}"#;

        let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
            .expect("container matches");
        let container = context.single_container().expect("one container");

        assert_eq!(container.name, "postgres-dev");
        assert_eq!(container.compose_project.as_deref(), Some("swamp"));
        assert_eq!(container.compose_service.as_deref(), Some("db"));
        assert_eq!(container.stop_command(), "docker stop postgres-dev");
        assert!(!context.truncated);
    }

    #[test]
    fn protocol_must_match_before_container_is_reported() {
        let row = entry(
            5353,
            Protocol::Udp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output =
            r#"{"ID":"abc123","Names":"dns","Ports":"0.0.0.0:5353->5353/tcp","Labels":""}"#;

        assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
    }

    #[test]
    fn duplicate_ipv4_ipv6_bindings_do_not_make_one_container_ambiguous() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8080->80/tcp, [::]:8080->80/tcp","Labels":""}"#;

        let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
            .expect("container matches");

        assert_eq!(context.containers.len(), 1);
        assert_eq!(context.containers[0].name, "web");
    }

    #[test]
    fn ipv6_wildcard_publish_does_not_match_an_ipv4_socket_row() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"[::]:8080->80/tcp","Labels":""}"#;

        assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
    }

    #[test]
    fn ipv4_wildcard_publish_does_not_match_an_ipv6_socket_row() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            "docker-proxy",
        );
        let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8080->80/tcp","Labels":""}"#;

        assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
    }

    #[test]
    fn malformed_json_rows_are_ignored_without_losing_valid_matches() {
        let row = entry(
            8080,
            Protocol::Tcp,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "docker-proxy",
        );
        let output = concat!(
            "not-json\n",
            r#"{"ID":"abc123","Names":"api","Ports":"127.0.0.1:8080->80/tcp","Labels":""}"#,
        );

        let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
            .expect("valid row matches");

        assert_eq!(context.containers.len(), 1);
        assert_eq!(context.containers[0].container_port, 80);
    }

    #[test]
    fn wildcard_addresses_match_specific_socket_views() {
        assert!(host_addr_matches(IpAddr::V6(Ipv6Addr::LOCALHOST), None,));
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        ));
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        ));
        assert!(host_addr_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V6(Ipv6Addr::new(
                0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
            ))),
        ));
        assert!(!host_addr_matches(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
        ));
    }
}
