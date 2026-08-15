use super::{
    REAL_BINARY_EXIT_WAIT, kickoutchi_binary, lock_host_observation, park_bounded,
    run_command_with_deadline, stderr, stdout, stdout_table_has_pid,
};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
const CHILD_EXIT_WAIT: Duration = Duration::from_secs(10);
const HELPER_READY_WAIT: Duration = Duration::from_secs(5);

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
        // Thaw first so cleanup can terminate a helper left stopped by a failed
        // test.
        continue_pid(self.child.id());
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Cleanup for helper-tree members that are not our direct children (the
/// grandchild listener), so a failed test cannot leak them.
struct PidGuard {
    pid: u32,
    start_time: (u64, u64),
}

impl PidGuard {
    fn new(pid: u32) -> Self {
        let start_time = process_start_time(pid).expect("test helper identity must be readable");
        Self { pid, start_time }
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        if process_start_time(self.pid) != Some(self.start_time) {
            return;
        }
        continue_pid(self.pid);
        if process_start_time(self.pid) != Some(self.start_time) {
            return;
        }
        terminate_pid(self.pid);
    }
}

fn process_start_time(pid: u32) -> Option<(u64, u64)> {
    let platform_pid = libc::c_int::try_from(pid).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let read = unsafe {
        // SAFETY: info reserves one proc_bsdinfo output buffer and libproc
        // does not retain it. A full-size result proves initialization.
        libc::proc_pidinfo(
            platform_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected,
        )
    };
    if read != expected {
        return None;
    }
    let info = unsafe {
        // SAFETY: proc_pidinfo reported one complete proc_bsdinfo result.
        info.assume_init()
    };
    Some((info.pbi_start_tvsec, info.pbi_start_tvusec))
}

fn continue_pid(pid: u32) {
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    unsafe {
        libc::kill(platform_pid, libc::SIGCONT);
    }
}

fn terminate_pid(pid: u32) {
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return;
    };
    unsafe {
        libc::kill(platform_pid, libc::SIGTERM);
    }
}

/// Existence probe via signal 0. `EPERM` still means "exists"; only `ESRCH`
/// (or an unrepresentable PID) means gone.
fn pid_exists(pid: u32) -> bool {
    let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let result = unsafe { libc::kill(platform_pid, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
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

fn kickoutchi(args: &[&str]) -> Output {
    kickoutchi_with_stdin(args, None)
}

fn kickoutchi_with_stdin(args: &[&str], stdin: Option<&str>) -> Output {
    let config_dir = isolated_config_dir();
    let config_path = config_dir.join("config.toml");
    fs::write(&config_path, "").expect("isolated config file must be written");
    let mut command = Command::new(kickoutchi_binary());
    command.args(args).arg("--config").arg(&config_path);
    let output = run_command_with_deadline(
        &mut command,
        stdin.map(str::as_bytes),
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("kickoutchi output must be collected before its deadline");
    let _ = fs::remove_dir_all(config_dir);
    output
}

fn isolated_config_dir() -> PathBuf {
    super::create_unique_temp_directory("macos-config")
}

fn spawn_listener_process() -> (ChildGuard, u16, PathBuf) {
    let ready_file = temp_file_path("listener-ready");
    let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
        .env(HELPER_LISTENER_ENV, "1")
        .env(HELPER_PORT_ENV, "0")
        .env(HELPER_READY_ENV, &ready_file)
        .args([
            "--exact",
            "macos::helper_tcp_listener_process",
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
            "macos::helper_process_tree",
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

fn temp_file_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "kickoutchi-cli-contract-macos-{label}-{}-{}",
        std::process::id(),
        unique_suffix(),
    ))
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos()
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
            "helper process did not exit after SIGTERM",
        );
        thread::sleep(Duration::from_millis(10));
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
        "root-owns-port" => {
            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("root tree helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            let child = Command::new("sleep")
                .arg("300")
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
                        "macos::helper_tcp_listener_process",
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
        "group-orphan" => {
            // Detach into a fresh process group first: the kill target's
            // group must never be the cargo-test session's group, or a
            // group kill in this test would sweep the whole test run (the
            // pipeline would refuse on its own PID, but the test must not
            // depend on that guard for its safety).
            // SAFETY: setpgid(0, 0) makes the calling process a group
            // leader; it takes no pointers and cannot affect other
            // processes.
            let result = unsafe { libc::setpgid(0, 0) };
            assert_eq!(result, 0, "group helper must become a group leader");

            let listener =
                TcpListener::bind(("127.0.0.1", 0)).expect("group helper listener must bind");
            let port = listener.local_addr().expect("listener addr").port();
            // `sh` starts a sleeper in our group, prints its PID, and
            // exits: the sleeper reparents away immediately, leaving a
            // group member that is no longer a descendant. The sleeper's
            // stdio must not inherit the pipe, or `output()` would wait
            // for the sleeper's EOF instead of sh's exit.
            let output = run_command_with_deadline(
                Command::new("sh").args(["-c", "sleep 300 >/dev/null 2>&1 & echo $!"]),
                None,
                CHILD_EXIT_WAIT,
            )
            .expect("group orphan spawner must run");
            let orphan_pid = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse::<u32>()
                .expect("orphan PID must be printed");
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, format!("{port} {orphan_pid}"))
                .expect("group ready file must be written");
            fs::rename(&ready_tmp, &ready_file).expect("group ready file must publish");
            park_bounded()
        }
        other => panic!("unknown tree helper mode {other}"),
    }
}
