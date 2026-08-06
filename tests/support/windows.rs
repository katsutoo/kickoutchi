use super::{
    HELPER_PARK_MAX, REAL_BINARY_EXIT_WAIT, create_unique_temp_directory, kickoutchi_binary,
    lock_host_observation, park_bounded, run_command_with_deadline, stderr, stdout,
    stdout_table_has_pid,
};
use std::fs;
use std::net::TcpListener;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::JobObjects::IsProcessInJob;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    PROCESS_TERMINATE, TerminateProcess, WaitForSingleObject,
};

const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
const HELPER_LATE_ENV: &str = "KICKOUTCHI_TEST_HELPER_LATE";
const CHILD_EXIT_WAIT: Duration = Duration::from_secs(5);
const HELPER_READY_WAIT: Duration = Duration::from_secs(5);
static UNIQUE_SUFFIX_COUNTER: AtomicU64 = AtomicU64::new(0);

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn id(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct PidGuard {
    handle: Option<OwnedHandle>,
}

impl PidGuard {
    fn new(pid: u32) -> Self {
        let handle = unsafe {
            // SAFETY: OpenProcess takes value arguments and returns a new
            // process-identity handle when successful.
            OpenProcess(PROCESS_TERMINATE | PROCESS_SYNCHRONIZE, 0, pid)
        };
        let handle = (!handle.is_null()).then(|| unsafe {
            // SAFETY: the non-null OpenProcess result is one owned handle.
            OwnedHandle::from_raw_handle(handle)
        });
        Self { handle }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        let Some(handle) = &self.handle else {
            return;
        };
        unsafe {
            // SAFETY: this retained handle identifies the original helper,
            // even if its numeric PID has since been reused.
            TerminateProcess(handle.as_raw_handle(), 1);
            WaitForSingleObject(handle.as_raw_handle(), 1_000);
        }
    }
}

fn kickoutchi(args: &[&str]) -> Output {
    kickoutchi_with_stdin(args, None)
}

fn kickoutchi_with_stdin(args: &[&str], stdin: Option<&str>) -> Output {
    let config_home = isolated_config_home();
    let mut command = Command::new(kickoutchi_binary());
    command.env("APPDATA", &config_home).args(args);
    let output = run_command_with_deadline(
        &mut command,
        stdin.map(str::as_bytes),
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("kickoutchi output must be collected before its deadline");
    let _ = fs::remove_dir_all(config_home);
    output
}

fn isolated_config_home() -> PathBuf {
    create_unique_temp_directory("windows-config")
}

fn spawn_listener_process() -> (ChildGuard, u16, PathBuf) {
    let ready_file = temp_file_path("listener-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_LISTENER_ENV, "1")
        .env(HELPER_PORT_ENV, "0")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "windows::helper_tcp_listener_process",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("listener helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let port = fs::read_to_string(&ready_file)
        .expect("helper ready file must contain the bound port")
        .parse::<u16>()
        .expect("helper bound port must be a u16");
    (guard, port, ready_file)
}

fn spawn_tree_process(mode: &str) -> (ChildGuard, u16, u32, PathBuf) {
    let ready_file = temp_file_path("tree-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, mode)
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "windows::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("tree helper process must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let ready = fs::read_to_string(&ready_file).expect("tree ready file must be readable");
    let mut parts = ready.split_whitespace();
    let port = parts
        .next()
        .expect("ready file must contain port")
        .parse::<u16>()
        .expect("tree helper port must be a u16");
    let child_pid = parts
        .next()
        .expect("ready file must contain child pid")
        .parse::<u32>()
        .expect("tree helper child pid must be a u32");
    (guard, port, child_pid, ready_file)
}

fn spawn_late_spawner_tree() -> (ChildGuard, u16, PathBuf, PathBuf) {
    let ready_file = temp_file_path("late-tree-ready");
    let late_file = temp_file_path("late-tree-child");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_TREE_ENV, "spawn-after-job")
        .env(HELPER_READY_ENV, &ready_file)
        .env(HELPER_LATE_ENV, &late_file)
        .args([
            "--exact",
            "windows::helper_process_tree",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("late-spawner tree helper must start");
    let guard = ChildGuard { child };
    wait_for_file(&ready_file);
    let port = fs::read_to_string(&ready_file)
        .expect("late-spawner ready file must be readable")
        .parse::<u16>()
        .expect("late-spawner helper port must be a u16");
    (guard, port, late_file, ready_file)
}

fn temp_file_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kickoutchi-cli-contract-windows-{label}-{}-{}",
        std::process::id(),
        unique_suffix(),
    ))
}

fn unique_suffix() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    let counter = UNIQUE_SUFFIX_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{timestamp}-{counter}")
}

fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + HELPER_READY_WAIT;
    loop {
        if path.exists() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "helper process never created ready file {}",
            path.display(),
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_child_exit(guard: &mut ChildGuard) {
    let deadline = Instant::now() + CHILD_EXIT_WAIT;
    loop {
        if guard
            .child
            .try_wait()
            .expect("child exit status must be readable")
            .is_some()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "helper process did not exit after TerminateProcess",
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_pid_gone(pid: u32) {
    let deadline = Instant::now() + CHILD_EXIT_WAIT;
    loop {
        if !pid_exists(pid) {
            return;
        }
        assert!(Instant::now() < deadline, "PID {pid} did not exit");
        thread::sleep(Duration::from_millis(10));
    }
}

fn publish_file(path: &Path, contents: impl AsRef<str>) {
    let ready_tmp = path.with_extension("tmp");
    fs::write(&ready_tmp, contents.as_ref()).expect("helper file must be written");
    fs::rename(&ready_tmp, path).expect("helper file must publish atomically");
}

fn current_process_in_any_job() -> bool {
    let handle = unsafe {
        // SAFETY: GetCurrentProcess returns the current process pseudo-handle.
        GetCurrentProcess()
    };
    process_handle_in_any_job(handle)
}

fn process_handle_in_any_job(handle: RawHandle) -> bool {
    let mut in_job = 0;
    let result = unsafe {
        // SAFETY: handle is a process handle or pseudo-handle, the null job
        // handle asks Windows whether the process is in any job, and `in_job`
        // is valid for the single BOOL write.
        IsProcessInJob(handle, std::ptr::null_mut(), &raw mut in_job)
    };
    result != 0 && in_job != 0
}

fn pid_exists(pid: u32) -> bool {
    let handle = unsafe {
        // SAFETY: OpenProcess takes only value arguments here. The handle is
        // checked before being wrapped for owned close-on-drop.
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return false;
    }
    let handle = unsafe {
        // SAFETY: OpenProcess returned a non-null owned handle. OwnedHandle
        // closes it once when this probe returns.
        OwnedHandle::from_raw_handle(handle)
    };
    let wait = unsafe {
        // SAFETY: handle is live and was opened with synchronize access.
        WaitForSingleObject(handle.as_raw_handle(), 0)
    };
    match wait {
        WAIT_OBJECT_0 => false,
        WAIT_TIMEOUT => true,
        WAIT_FAILED => panic!(
            "WaitForSingleObject failed while probing PID {pid}: {}",
            std::io::Error::last_os_error(),
        ),
        result => panic!("WaitForSingleObject returned unexpected status {result:#x}"),
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn helper_tcp_listener_process() {
    if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
        return;
    }

    let port = std::env::var(HELPER_PORT_ENV)
        .expect("helper port must be set")
        .parse::<u16>()
        .expect("helper port must be a u16");
    let ready_file =
        PathBuf::from(std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"));
    let listener = TcpListener::bind(("127.0.0.1", port))
        .expect("helper listener must bind the requested port");
    let bound_port = listener
        .local_addr()
        .expect("helper listener must have a local address")
        .port();
    let ready_tmp = ready_file.with_extension("tmp");
    fs::write(&ready_tmp, bound_port.to_string()).expect("helper ready file must be written");
    fs::rename(&ready_tmp, &ready_file).expect("helper ready file must be published");

    park_bounded()
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn helper_process_tree() {
    let Some(mode) = std::env::var_os(HELPER_TREE_ENV) else {
        return;
    };
    let mode = mode.to_string_lossy();
    let ready_file =
        PathBuf::from(std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"));

    match mode.as_ref() {
        "park-child" => park_bounded(),
        "spawn-after-job" => {
            let late_file = PathBuf::from(
                std::env::var_os(HELPER_LATE_ENV).expect("late child path must be set"),
            );
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .expect("late-spawner helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            publish_file(&ready_file, port.to_string());

            let deadline = Instant::now() + HELPER_PARK_MAX;
            while Instant::now() < deadline {
                if current_process_in_any_job() {
                    let child = Command::new(
                        std::env::current_exe().expect("test binary path must resolve"),
                    )
                    .env(HELPER_TREE_ENV, "park-child")
                    .env(HELPER_READY_ENV, &ready_file)
                    .args([
                        "--exact",
                        "windows::helper_process_tree",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("post-job child must spawn");
                    let child_pid = child.id();
                    let child_in_job = process_handle_in_any_job(child.as_raw_handle());
                    publish_file(&late_file, format!("{child_pid} {child_in_job}"));
                    let _child_guard = ChildGuard { child };
                    park_bounded()
                }
                thread::yield_now();
            }
            std::process::exit(0)
        }
        "root-owns-port" => {
            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("root tree helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            let child =
                Command::new(std::env::current_exe().expect("test binary path must resolve"))
                    .env(HELPER_TREE_ENV, "park-child")
                    .env(HELPER_READY_ENV, &ready_file)
                    .args([
                        "--exact",
                        "windows::helper_process_tree",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("tree child must spawn");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{port} {}", child.id()))
                .expect("tree ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("tree ready file must publish");
            let _child_guard = ChildGuard { child };
            park_bounded()
        }
        "child-owns-port" => {
            let child_ready = ready_file.with_extension("child");
            let child =
                Command::new(std::env::current_exe().expect("test binary path must resolve"))
                    .env(HELPER_LISTENER_ENV, "1")
                    .env(HELPER_PORT_ENV, "0")
                    .env(HELPER_READY_ENV, &child_ready)
                    .args([
                        "--exact",
                        "windows::helper_tcp_listener_process",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("tree listener child must spawn");
            wait_for_file(&child_ready);
            let port = fs::read_to_string(&child_ready).expect("child port must be readable");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{} {}", port.trim(), child.id()))
                .expect("tree ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("tree ready file must publish");
            let _child_guard = ChildGuard { child };
            park_bounded()
        }
        other => panic!("unknown tree helper mode {other}"),
    }
}
