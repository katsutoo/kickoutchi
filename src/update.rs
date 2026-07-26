//! Silent weekly release checks and their small per-user cache.

use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

const INTERNAL_WORKER_ARG: &str = "__kickoutchi-internal-update-check";
const RELEASE_ENDPOINT: &str = "https://api.github.com/repos/nuggocto/kickoutchi/releases/latest";
const RELEASE_URL: &str = "https://github.com/nuggocto/kickoutchi/releases/latest";
const WEEK_SECONDS: u64 = 7 * 24 * 60 * 60;
const WORKER_LOCK_WAIT: Duration = Duration::from_secs(1);
const WORKER_LOCK_RETRY: Duration = Duration::from_millis(10);
const CACHE_MAX_BYTES: usize = 4096;
const RELEASE_MAX_BYTES: u64 = 64 * 1024;
const MARKER_MAX_BYTES: usize = 32;
const TOKEN_MAX_BYTES: usize = 96;

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CacheState {
    last_attempt: Option<u64>,
    last_success: Option<u64>,
    available_version: Option<String>,
    provenance: Option<Provenance>,
    notice_pending: bool,
    worker_token: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Provenance {
    Homebrew,
    Scoop,
    Aur,
    Nix,
    CargoDist,
    CargoGit,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Version(u64, u64, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateNotice {
    version: String,
    message: String,
}

impl UpdateNotice {
    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    #[cfg(test)]
    pub(crate) fn for_test(message: impl Into<String>) -> Self {
        Self {
            version: "99.0.0".to_owned(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

struct CachePaths {
    directory: PathBuf,
    state: PathBuf,
    lock: PathBuf,
}

#[derive(Debug)]
struct CacheLock {
    _file: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cadence {
    Due,
    Waiting,
    ClockRollback,
}

pub(crate) fn is_internal_worker() -> bool {
    internal_worker_token().is_some()
}

pub(crate) fn is_elevated() -> bool {
    crate::docker::process_is_elevated()
}

/// Read an existing notice without acknowledging it and, independently, start
/// a due worker. Display surfaces acknowledge only after successful output.
pub(crate) fn foreground() -> Option<UpdateNotice> {
    if is_elevated() {
        return None;
    }
    let now = unix_now()?;
    let paths = cache_paths()?;
    foreground_with(&paths, now, spawn_worker)
}

fn foreground_with(
    paths: &CachePaths,
    now: u64,
    spawn: impl FnOnce(&str) -> io::Result<()>,
) -> Option<UpdateNotice> {
    let (notice, worker_token) = {
        let lock = acquire_lock(paths).ok()?;
        let mut state = read_state(paths).unwrap_or_default();
        let original_state = state.clone();
        let notice = pending_notice(&mut state);
        let worker_token = reserve_due_worker(&mut state, now);
        if state != original_state && write_state(paths, &state).is_err() {
            return None;
        }
        drop(lock);
        (notice, worker_token)
    };

    if let Some(token) = worker_token.as_deref()
        && spawn(token).is_err()
    {
        let _ = clear_worker_reservation(paths, token);
    }
    notice.map(|(version, provenance)| UpdateNotice {
        message: notice_message(&version, provenance),
        version,
    })
}

fn clear_worker_reservation(paths: &CachePaths, token: &str) -> io::Result<()> {
    let _lock = acquire_lock_bounded(paths, WORKER_LOCK_WAIT)?;
    let mut state = read_state(paths)?;
    if state.worker_token.as_deref() == Some(token) {
        state.worker_token = None;
        state.last_attempt = None;
        write_state(paths, &state)?;
    }
    Ok(())
}

/// Mark exactly the notice that was displayed as consumed. A newer worker
/// result is never cleared by a delayed acknowledgment from an older launch.
pub(crate) fn acknowledge(notice: &UpdateNotice) -> io::Result<()> {
    let paths = cache_paths().ok_or_else(|| io::Error::other("update cache is unavailable"))?;
    acknowledge_with(&paths, notice)
}

fn acknowledge_with(paths: &CachePaths, notice: &UpdateNotice) -> io::Result<()> {
    let _lock = acquire_lock(paths)?;
    let mut state = read_state(paths)?;
    if state.notice_pending && state.available_version.as_deref() == Some(&notice.version) {
        state.notice_pending = false;
        write_state(paths, &state)?;
    }
    Ok(())
}

pub(crate) fn run_internal_worker() {
    if is_elevated() {
        return;
    }
    let Some(token) = internal_worker_token() else {
        return;
    };
    let Some(now) = unix_now() else {
        return;
    };
    let Some(paths) = cache_paths() else {
        return;
    };
    let executable = std::env::current_exe().ok();
    let _ = run_worker_with(&paths, now, &token, executable.as_deref(), fetch_release);
}

fn run_worker_with<F>(
    paths: &CachePaths,
    now: u64,
    worker_token: &str,
    executable: Option<&Path>,
    fetch: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<GithubRelease>,
{
    let _lock = acquire_lock_bounded(paths, WORKER_LOCK_WAIT)?;
    let mut state = read_state(paths).unwrap_or_default();
    if state.worker_token.as_deref() != Some(worker_token) {
        return Ok(());
    }

    // Keep the lock through the one bounded request and final state write. A
    // foreground launch may skip this cache access, but cannot consume or
    // overwrite a successful result between those two operations.
    let release = match fetch() {
        Ok(release) => release,
        Err(error) => {
            state.worker_token = None;
            write_state(paths, &state)?;
            return Err(error);
        }
    };
    state.worker_token = None;
    let Some(version) = validated_release(&release) else {
        return write_state(paths, &state);
    };

    state.last_success = Some(now);
    if version > current_version() {
        state.available_version = Some(
            release
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&release.tag_name)
                .to_owned(),
        );
        state.provenance = Some(resolve_provenance(executable));
        state.notice_pending = true;
    } else {
        state.available_version = None;
        state.provenance = None;
        state.notice_pending = false;
    }
    write_state(paths, &state)
}

fn fetch_release() -> io::Result<GithubRelease> {
    let config = ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(3)
        .timeout_global(Some(Duration::from_secs(5)))
        .timeout_connect(Some(Duration::from_secs(2)))
        .max_response_header_size(32 * 1024)
        .user_agent(format!(
            "kickoutchi/{} update-check",
            env!("CARGO_PKG_VERSION")
        ))
        .accept("application/vnd.github+json")
        .build();
    let agent: ureq::Agent = config.into();
    let mut response = agent
        .get(RELEASE_ENDPOINT)
        .header("X-GitHub-Api-Version", "2022-11-28")
        .call()
        .map_err(io::Error::other)?;
    let bytes = response
        .body_mut()
        .with_config()
        .limit(RELEASE_MAX_BYTES)
        .read_to_vec()
        .map_err(io::Error::other)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn validated_release(release: &GithubRelease) -> Option<Version> {
    if release.draft || release.prerelease {
        return None;
    }
    Version::parse(&release.tag_name)
}

fn current_version() -> Version {
    Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is stable SemVer")
}

impl Version {
    fn parse(text: &str) -> Option<Self> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let mut parts = text.split('.');
        let major = parse_version_number(parts.next()?)?;
        let minor = parse_version_number(parts.next()?)?;
        let patch = parse_version_number(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self(major, minor, patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.0, self.1, self.2).cmp(&(other.0, other.1, other.2))
    }
}

fn parse_version_number(part: &str) -> Option<u64> {
    if part.is_empty()
        || (part.len() > 1 && part.starts_with('0'))
        || !part.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    part.parse().ok()
}

fn cadence(last_attempt: Option<u64>, now: u64) -> Cadence {
    let Some(last) = last_attempt else {
        return Cadence::Due;
    };
    let Some(age) = now.checked_sub(last) else {
        return Cadence::ClockRollback;
    };
    if age >= WEEK_SECONDS {
        Cadence::Due
    } else {
        Cadence::Waiting
    }
}

fn reserve_due_worker(state: &mut CacheState, now: u64) -> Option<String> {
    match cadence(state.last_attempt, now) {
        Cadence::Due => {
            let token = unique_token();
            state.last_attempt = Some(now);
            state.worker_token = Some(token.clone());
            Some(token)
        }
        Cadence::ClockRollback => {
            // Rebase on the observed clock without a request. This recovers
            // after one normal cadence and cannot request on every launch.
            state.last_attempt = Some(now);
            state.worker_token = None;
            None
        }
        Cadence::Waiting => None,
    }
}

fn pending_notice(state: &mut CacheState) -> Option<(String, Provenance)> {
    if !state.notice_pending {
        return None;
    }
    let Some(version) = state.available_version.clone() else {
        state.notice_pending = false;
        state.provenance = None;
        return None;
    };
    let Some(parsed) = Version::parse(&version) else {
        state.notice_pending = false;
        state.available_version = None;
        state.provenance = None;
        return None;
    };
    if parsed <= current_version() {
        state.notice_pending = false;
        state.available_version = None;
        state.provenance = None;
        return None;
    }
    Some((version, state.provenance.unwrap_or(Provenance::Unknown)))
}

fn notice_message(version: &str, provenance: Provenance) -> String {
    let instruction = match provenance {
        Provenance::CargoDist => "kickoutchi-update",
        Provenance::Homebrew => "brew update && brew upgrade nuggocto/tap/kickoutchi",
        Provenance::Scoop => "scoop update; scoop update kickoutchi",
        Provenance::Aur => {
            "use your AUR helper (for example, yay or paru) through your normal system update"
        }
        Provenance::Nix => "nix profile upgrade kickoutchi",
        Provenance::CargoGit => {
            return format!(
                "Kickoutchi {version} is available. Update with: cargo install --force --locked --git https://github.com/nuggocto/kickoutchi --tag v{version}"
            );
        }
        Provenance::Unknown => {
            return format!(
                "Kickoutchi {version} is available. Download it from {RELEASE_URL} and replace the current executable manually."
            );
        }
    };
    format!("Kickoutchi {version} is available. Update with: {instruction}")
}

fn resolve_provenance(executable: Option<&Path>) -> Provenance {
    let Some(executable) = executable else {
        return Provenance::Unknown;
    };
    let Some(binary_directory) = executable.parent() else {
        return Provenance::Unknown;
    };

    if let Some(prefix) = binary_directory.parent()
        && let Some(value) = read_marker(&prefix.join("share/kickoutchi/install-provenance"))
    {
        return value;
    }
    if let Some(value) = read_marker(&binary_directory.join("install-provenance")) {
        return value;
    }

    let updater = if cfg!(windows) {
        binary_directory.join("kickoutchi-update.exe")
    } else {
        binary_directory.join("kickoutchi-update")
    };
    if valid_updater(&updater) {
        Provenance::CargoDist
    } else {
        Provenance::Unknown
    }
}

fn read_marker(path: &Path) -> Option<Provenance> {
    trusted_provenance_file(path).ok()?;
    let bytes = read_bounded(path, MARKER_MAX_BYTES).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    match text {
        "homebrew" => Some(Provenance::Homebrew),
        "scoop" => Some(Provenance::Scoop),
        "aur" => Some(Provenance::Aur),
        "nix" => Some(Provenance::Nix),
        "cargo-dist" => Some(Provenance::CargoDist),
        "cargo-git" => Some(Provenance::CargoGit),
        _ => None,
    }
}

fn valid_updater(path: &Path) -> bool {
    let Ok(metadata) = trusted_provenance_file(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn cache_paths() -> Option<CachePaths> {
    let root = dirs::cache_dir()?;
    ensure_cache_root(&root).ok()?;
    let directory = root.join("kickoutchi");
    ensure_private_directory(&directory).ok()?;
    Some(CachePaths {
        state: directory.join("update.json"),
        lock: directory.join("update.lock"),
        directory,
    })
}

fn ensure_cache_root(path: &Path) -> io::Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
    }
    let metadata = fs::symlink_metadata(path)?;
    validate_directory(&metadata, false)
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = fs::symlink_metadata(path)?;
    validate_directory(&metadata, false)?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    validate_directory(&fs::symlink_metadata(path)?, true)
}

fn validate_directory(metadata: &fs::Metadata, private: bool) -> io::Result<()> {
    if unsafe_file_type(metadata) || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe cache directory",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        if metadata.uid() != unsafe { libc::geteuid() } || unix_group_or_world_writable(metadata) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe cache owner or mode",
            ));
        }
        if private && metadata.mode() & 0o777 != 0o700 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cache directory is not private",
            ));
        }
    }
    let _ = private;
    Ok(())
}

fn acquire_lock(paths: &CachePaths) -> io::Result<CacheLock> {
    let file = open_lock_file(&paths.lock)?;
    match file.try_lock() {
        Ok(()) => Ok(CacheLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(io::ErrorKind::WouldBlock.into()),
        Err(TryLockError::Error(error)) => Err(error),
    }
}

fn acquire_lock_bounded(paths: &CachePaths, timeout: Duration) -> io::Result<CacheLock> {
    let deadline = Instant::now() + timeout;
    loop {
        match acquire_lock(paths) {
            Ok(lock) => return Ok(lock),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(
                    WORKER_LOCK_RETRY.min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    match secure_cache_file(path) {
        Ok(_) => open_existing_lock_file(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_lock_file(path),
        Err(error) => Err(error),
    }
}

fn create_lock_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => {
            validate_open_lock_file(path, &file)?;
            Ok(file)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => open_existing_lock_file(path),
        Err(error) => Err(error),
    }
}

fn open_existing_lock_file(path: &Path) -> io::Result<File> {
    secure_cache_file(path)?;
    let mut options = OpenOptions::new();
    let file = options.read(true).write(true).open(path)?;
    validate_open_lock_file(path, &file)?;
    Ok(file)
}

fn validate_open_lock_file(path: &Path, file: &File) -> io::Result<()> {
    let path_metadata = secure_cache_file(path)?;
    let file_metadata = file.metadata()?;
    if unsafe_file_type(&file_metadata) || !file_metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe lock file type",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "lock file changed while opening",
            ));
        }
    }
    let _ = path_metadata;
    Ok(())
}

fn read_state(paths: &CachePaths) -> io::Result<CacheState> {
    match secure_cache_file(&paths.state) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(CacheState::default()),
        Err(error) => return Err(error),
    }
    match read_bounded(&paths.state, CACHE_MAX_BYTES) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(error) => Err(error),
    }
}

fn write_state(paths: &CachePaths, state: &CacheState) -> io::Result<()> {
    let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
    if bytes.len() > CACHE_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "update cache exceeds limit",
        ));
    }
    if paths.state.exists() {
        secure_cache_file(&paths.state)?;
    }
    let temporary = paths
        .directory
        .join(format!(".update-{}.tmp", std::process::id()));
    if temporary.exists() {
        secure_cache_file(&temporary)?;
        fs::remove_file(&temporary)?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    #[cfg(unix)]
    let result = set_private_file_permissions(&file)
        .and_then(|()| file.write_all(&bytes))
        .and_then(|()| file.sync_all());
    #[cfg(not(unix))]
    let result = file.write_all(&bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    if let Err(error) = atomic_replace(&temporary, &paths.state) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

#[cfg(not(windows))]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

#[cfg(windows)]
fn atomic_replace(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let to = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: both paths are NUL-terminated UTF-16 buffers valid for this call.
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn read_bounded(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    secure_regular_file(path)?;
    let file = File::open(path)?;
    let mut bytes = Vec::with_capacity(limit.min(1024));
    file.take(u64::try_from(limit + 1).expect("small read limit fits u64"))
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds limit",
        ));
    }
    Ok(bytes)
}

fn secure_cache_file(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = secure_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unsafe cache file",
            ));
        }
    }
    Ok(metadata)
}

#[cfg(unix)]
fn set_private_file_permissions(file: &File) -> io::Result<()> {
    file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(())
}

fn secure_regular_file(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if unsafe_file_type(&metadata) || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe file type",
        ));
    }
    Ok(metadata)
}

fn trusted_provenance_file(path: &Path) -> io::Result<fs::Metadata> {
    let metadata = secure_regular_file(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no preconditions and only reads process credentials.
        let effective_uid = unsafe { libc::geteuid() };
        if (metadata.uid() != effective_uid && metadata.uid() != 0)
            || unix_group_or_world_writable(&metadata)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "untrusted provenance file",
            ));
        }
    }
    Ok(metadata)
}

fn unsafe_file_type(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

#[cfg(unix)]
fn unix_group_or_world_writable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o022 != 0
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|age| age.as_secs())
}

fn spawn_worker(worker_token: &str) -> io::Result<()> {
    let (child_sender, child_receiver) = mpsc::sync_channel::<Child>(1);
    crate::ui::spawn_worker(
        thread::Builder::new().name("kickoutchi-update-reaper".to_owned()),
        move || {
            if let Ok(mut child) = child_receiver.recv() {
                let _ = child.wait();
            }
        },
    )?;

    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg(format!("{INTERNAL_WORKER_ARG}={worker_token}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure_detached(&mut command);
    let child = command.spawn()?;
    child_sender
        .send(child)
        .map_err(|_| io::Error::other("update reaper stopped before receiving child"))
}

fn internal_worker_token() -> Option<String> {
    let mut args = std::env::args_os();
    let _program = args.next();
    let argument = args.next()?.into_string().ok()?;
    let token = argument.strip_prefix(&format!("{INTERNAL_WORKER_ARG}="))?;
    (args.next().is_none() && valid_token(token)).then(|| token.to_owned())
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= TOKEN_MAX_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
}

fn unique_token() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |age| age.as_nanos());
    let sequence = SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed);
    format!("{:x}-{nanos:x}-{sequence:x}", std::process::id())
}

#[cfg(unix)]
fn configure_detached(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and this closure performs no allocation.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
}

#[cfg(windows)]
fn configure_detached(command: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    command.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW);
}

#[cfg(not(any(unix, windows)))]
fn configure_detached(_command: &mut Command) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cadence_is_exact_and_distinguishes_clock_rollback() {
        assert_eq!(cadence(None, 1), Cadence::Due);
        assert_eq!(cadence(Some(100), 100 + WEEK_SECONDS - 1), Cadence::Waiting);
        assert_eq!(cadence(Some(100), 100 + WEEK_SECONDS), Cadence::Due);
        assert_eq!(cadence(Some(100), 99), Cadence::ClockRollback);
    }

    #[test]
    fn clock_rollback_rebases_without_requesting_each_launch() {
        let mut state = CacheState {
            last_attempt: Some(1_000),
            worker_token: Some("old-token".to_owned()),
            ..CacheState::default()
        };

        assert_eq!(reserve_due_worker(&mut state, 500), None);
        assert_eq!(state.last_attempt, Some(500));
        assert_eq!(state.worker_token, None);
        assert_eq!(reserve_due_worker(&mut state, 500), None);
        assert_eq!(reserve_due_worker(&mut state, 500 + WEEK_SECONDS - 1), None);
        assert!(reserve_due_worker(&mut state, 500 + WEEK_SECONDS).is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn update_gate_reuses_capability_aware_privilege_detection() {
        crate::docker::TEST_LINUX_ELEVATION_SOURCES
            .with(|sources| sources.set(Some((false, false, true))));
        assert!(is_elevated());
        assert_eq!(foreground(), None);
        crate::docker::TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(None));
    }

    #[test]
    fn versions_are_strict_stable_numeric_semver() {
        assert_eq!(Version::parse("v2.10.3"), Some(Version(2, 10, 3)));
        assert!(Version::parse("2.10.3").unwrap() > Version::parse("2.9.99").unwrap());
        for invalid in [
            "1.2",
            "1.2.3.4",
            "1.02.3",
            "1.2.3-beta",
            "1.2.3+build",
            " 1.2.3",
            "vv1.2.3",
        ] {
            assert_eq!(Version::parse(invalid), None, "accepted {invalid}");
        }
    }

    #[test]
    fn release_validation_rejects_drafts_and_prereleases() {
        let release = |draft, prerelease, tag_name: &str| GithubRelease {
            tag_name: tag_name.to_owned(),
            draft,
            prerelease,
        };
        assert_eq!(
            validated_release(&release(false, false, "v2.0.0")),
            Some(Version(2, 0, 0))
        );
        assert_eq!(validated_release(&release(true, false, "v2.0.0")), None);
        assert_eq!(validated_release(&release(false, true, "v2.0.0")), None);
        assert_eq!(validated_release(&release(false, false, "latest")), None);
    }

    #[test]
    fn cache_notice_is_peeked_without_consumption_and_old_versions_are_cleared() {
        let mut state = CacheState {
            available_version: Some("99.0.0".to_owned()),
            provenance: Some(Provenance::Nix),
            notice_pending: true,
            ..CacheState::default()
        };
        assert_eq!(
            pending_notice(&mut state),
            Some(("99.0.0".to_owned(), Provenance::Nix))
        );
        assert!(state.notice_pending);
        assert!(pending_notice(&mut state).is_some());

        state.available_version = Some(env!("CARGO_PKG_VERSION").to_owned());
        state.notice_pending = true;
        assert_eq!(pending_notice(&mut state), None);
        assert!(state.available_version.is_none());
    }

    #[test]
    fn delayed_acknowledgment_clears_only_the_rendered_version() {
        let directory = test_directory("notice-ack");
        let paths = cache_paths_for(&directory);
        let mut state = CacheState {
            available_version: Some("99.0.0".to_owned()),
            provenance: Some(Provenance::Nix),
            notice_pending: true,
            ..CacheState::default()
        };
        write_state(&paths, &state).unwrap();
        let old_notice = UpdateNotice {
            version: "98.0.0".to_owned(),
            message: "old".to_owned(),
        };
        acknowledge_with(&paths, &old_notice).unwrap();
        assert!(read_state(&paths).unwrap().notice_pending);

        let current_notice = UpdateNotice {
            version: "99.0.0".to_owned(),
            message: "current".to_owned(),
        };
        acknowledge_with(&paths, &current_notice).unwrap();
        state = read_state(&paths).unwrap();
        assert!(!state.notice_pending);
        assert_eq!(state.available_version.as_deref(), Some("99.0.0"));
    }

    #[test]
    fn failed_acknowledgment_leaves_notice_pending_for_next_invocation() {
        let directory = test_directory("notice-ack-failure");
        let paths = cache_paths_for(&directory);
        write_state(
            &paths,
            &CacheState {
                available_version: Some("99.0.0".to_owned()),
                provenance: Some(Provenance::Nix),
                notice_pending: true,
                ..CacheState::default()
            },
        )
        .unwrap();
        let notice = UpdateNotice {
            version: "99.0.0".to_owned(),
            message: "current".to_owned(),
        };
        let lock = acquire_lock(&paths).unwrap();

        assert!(acknowledge_with(&paths, &notice).is_err());
        drop(lock);
        assert!(read_state(&paths).unwrap().notice_pending);
    }

    #[test]
    fn foreground_drops_lock_before_spawn_and_failed_spawn_retries_immediately() {
        let directory = test_directory("spawn-failure");
        let paths = cache_paths_for(&directory);
        let mut saw_unlocked_cache = false;

        assert!(
            foreground_with(&paths, 500, |_: &str| {
                let lock = acquire_lock(&paths)
                    .expect("foreground lock must be dropped before child spawn");
                saw_unlocked_cache = true;
                drop(lock);
                Err(io::Error::other("spawn refused"))
            })
            .is_none()
        );
        assert!(saw_unlocked_cache);
        let state = read_state(&paths).unwrap();
        assert_eq!(state.worker_token, None);
        assert_eq!(state.last_attempt, None);

        let mut retried = false;
        assert!(
            foreground_with(&paths, 500, |_: &str| {
                retried = true;
                Ok(())
            })
            .is_none()
        );
        assert!(retried, "failed spawn reservation must be immediately due");
    }

    #[test]
    fn failed_spawn_does_not_clear_a_newer_worker_reservation() {
        let directory = test_directory("spawn-replacement");
        let paths = cache_paths_for(&directory);

        foreground_with(&paths, 600, |_: &str| {
            let _lock = acquire_lock(&paths).unwrap();
            let mut state = read_state(&paths).unwrap();
            state.worker_token = Some("replacement-token".to_owned());
            state.last_attempt = Some(601);
            write_state(&paths, &state).unwrap();
            Err(io::Error::other("original spawn failed"))
        });

        let state = read_state(&paths).unwrap();
        assert_eq!(state.worker_token.as_deref(), Some("replacement-token"));
        assert_eq!(state.last_attempt, Some(601));
    }

    #[test]
    fn provenance_messages_are_static_and_package_aware() {
        let cases = [
            (Provenance::CargoDist, "kickoutchi-update"),
            (
                Provenance::Homebrew,
                "brew update && brew upgrade nuggocto/tap/kickoutchi",
            ),
            (Provenance::Scoop, "scoop update; scoop update kickoutchi"),
            (Provenance::Aur, "yay or paru"),
            (Provenance::Nix, "nix profile upgrade kickoutchi"),
            (Provenance::CargoGit, "cargo install --force --locked --git"),
            (Provenance::Unknown, RELEASE_URL),
        ];
        for (provenance, expected) in cases {
            assert!(notice_message("9.0.0", provenance).contains(expected));
        }
        assert!(notice_message("9.0.0", Provenance::CargoGit).ends_with("--tag v9.0.0"));
    }

    #[test]
    fn marker_parser_accepts_only_closed_values() {
        let directory = test_directory("marker");
        let marker = directory.join("install-provenance");
        fs::write(&marker, "homebrew\n").unwrap();
        set_private_file(&marker);
        assert_eq!(read_marker(&marker), Some(Provenance::Homebrew));
        fs::write(&marker, "homebrew; rm -rf /\n").unwrap();
        assert_eq!(read_marker(&marker), None);
    }

    #[cfg(unix)]
    #[test]
    fn cache_files_reject_symlinks_and_non_private_modes() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = test_directory("cache-security");
        let target = directory.join("target");
        fs::write(&target, "{}").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secure_cache_file(&target).is_err());

        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.join("link");
        symlink(&target, &link).unwrap();
        assert!(secure_cache_file(&link).is_err());
    }

    #[test]
    fn worker_records_failed_attempt_before_network_and_waits_a_week() {
        let directory = test_directory("worker");
        let paths = cache_paths_for(&directory);
        let token = schedule_worker(&paths, 500);
        let result = run_worker_with(&paths, 500, &token, None, || {
            Err(io::Error::other("offline"))
        });
        assert!(result.is_err());
        assert_eq!(read_state(&paths).unwrap().last_attempt, Some(500));
        assert_eq!(read_state(&paths).unwrap().worker_token, None);

        let mut called = false;
        run_worker_with(&paths, 500 + WEEK_SECONDS - 1, &token, None, || {
            called = true;
            Err(io::Error::other("must not run"))
        })
        .unwrap();
        assert!(!called);
    }

    #[test]
    fn each_successful_outdated_week_can_schedule_one_reminder() {
        let directory = test_directory("reminder");
        let paths = cache_paths_for(&directory);
        let release = || {
            Ok(GithubRelease {
                tag_name: "v99.0.0".to_owned(),
                draft: false,
                prerelease: false,
            })
        };

        let token = schedule_worker(&paths, 500);
        run_worker_with(&paths, 500, &token, None, release).unwrap();
        let mut state = read_state(&paths).unwrap();
        let (version, provenance) = pending_notice(&mut state).expect("notice is pending");
        let notice = UpdateNotice {
            message: notice_message(&version, provenance),
            version,
        };
        acknowledge_with(&paths, &notice).unwrap();
        assert!(pending_notice(&mut read_state(&paths).unwrap()).is_none());

        let token = schedule_worker(&paths, 500 + WEEK_SECONDS);
        run_worker_with(&paths, 500 + WEEK_SECONDS, &token, None, release).unwrap();
        assert!(pending_notice(&mut read_state(&paths).unwrap()).is_some());
    }

    #[test]
    fn successful_current_release_records_success_without_notice() {
        let directory = test_directory("current");
        let paths = cache_paths_for(&directory);
        let token = schedule_worker(&paths, 700);
        run_worker_with(&paths, 700, &token, None, || {
            Ok(GithubRelease {
                tag_name: env!("CARGO_PKG_VERSION").to_owned(),
                draft: false,
                prerelease: false,
            })
        })
        .unwrap();

        let state = read_state(&paths).unwrap();
        assert_eq!(state.last_attempt, Some(700));
        assert_eq!(state.last_success, Some(700));
        assert!(!state.notice_pending);
        assert!(state.available_version.is_none());
    }

    #[test]
    fn worker_holds_lock_until_success_is_persisted() {
        let directory = test_directory("worker-contention");
        let paths = cache_paths_for(&directory);
        let token = schedule_worker(&paths, 800);

        run_worker_with(&paths, 800, &token, None, || {
            let error = acquire_lock(&paths)
                .expect_err("foreground contention must not enter during the request");
            assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            Ok(GithubRelease {
                tag_name: "v99.0.0".to_owned(),
                draft: false,
                prerelease: false,
            })
        })
        .unwrap();

        let state = read_state(&paths).unwrap();
        assert_eq!(state.last_success, Some(800));
        assert_eq!(state.available_version.as_deref(), Some("99.0.0"));
        assert!(state.notice_pending);
    }

    #[test]
    fn exclusive_lock_contention_is_nonblocking() {
        let directory = test_directory("lock-contention");
        let paths = cache_paths_for(&directory);
        let lock = acquire_lock(&paths).unwrap();

        let error = acquire_lock(&paths).expect_err("exclusive lock must reject contention");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(paths.lock.exists());
        drop(lock);
    }

    #[test]
    fn dropping_guard_releases_lock_without_removing_canonical_file() {
        let directory = test_directory("lock-release");
        let paths = cache_paths_for(&directory);
        let first = acquire_lock(&paths).unwrap();
        assert_eq!(
            acquire_lock(&paths).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        drop(first);
        let second = acquire_lock(&paths).expect("closing the owner must release the OS lock");
        assert!(paths.lock.exists());
        drop(second);
        assert!(paths.lock.exists());
    }

    #[test]
    fn cadence_reservation_allows_only_one_worker_token() {
        let mut state = CacheState::default();
        let token = reserve_due_worker(&mut state, 900).expect("first launch is due");

        assert_eq!(state.worker_token.as_deref(), Some(token.as_str()));
        assert_eq!(reserve_due_worker(&mut state, 900), None);
        assert_eq!(state.worker_token.as_deref(), Some(token.as_str()));
    }

    fn cache_paths_for(directory: &Path) -> CachePaths {
        CachePaths {
            state: directory.join("update.json"),
            lock: directory.join("update.lock"),
            directory: directory.to_owned(),
        }
    }

    fn schedule_worker(paths: &CachePaths, now: u64) -> String {
        let mut state = read_state(paths).unwrap_or_default();
        let token = reserve_due_worker(&mut state, now).expect("cadence must be due");
        write_state(paths, &state).unwrap();
        token
    }

    /// A private cache directory for one test.
    ///
    /// It carries the shared guard that keeps the suite's process-spawning
    /// tests from forking while this test holds an advisory lock on a file
    /// inside it; see `crate::test_sync` for why that matters. Removal happens
    /// in `Drop` rather than at the end of each test body, so a failing
    /// assertion cannot leave the directory behind in the temp folder.
    struct TestCacheDir {
        path: PathBuf,
        _fork_guard: std::sync::RwLockReadGuard<'static, ()>,
    }

    impl std::ops::Deref for TestCacheDir {
        type Target = Path;

        fn deref(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestCacheDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn test_directory(label: &str) -> TestCacheDir {
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-update-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        TestCacheDir {
            path,
            _fork_guard: crate::test_sync::holding_file_lock(),
        }
    }

    fn set_private_file(path: &Path) {
        #[cfg(unix)]
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        let _ = path;
    }
}
