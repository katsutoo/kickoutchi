#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CMDLINE_WAIT: Duration = Duration::from_secs(2);
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(2);
    /// How long a parked helper may outlive its test before self-destructing.
    /// Generous enough for the slowest passing run; short enough that a
    /// killed-by-`SIGKILL` test binary can never leak an immortal helper.
    const HELPER_PARK_MAX: Duration = Duration::from_mins(5);
    /// Building a deep chain re-execs this test binary once per link, so its
    /// ready file gets a deadline far beyond the usual helper waits.
    const DEEP_CHAIN_READY_WAIT: Duration = Duration::from_secs(30);
    const DEEP_CHAIN_DEPTH: usize = 12;
    /// How long the live spawner keeps forking before it settles into a plain
    /// park. Long enough that the kill under test always lands mid-burst.
    const LIVE_SPAWN_WINDOW: Duration = Duration::from_secs(20);
    const LIVE_SPAWN_MAX: usize = 200;
    /// Deadline for a spawned `kick` to print an expected stderr line and for
    /// it to exit after confirmation input.
    const PROMPT_WAIT: Duration = Duration::from_secs(10);
    const KICK_EXIT_WAIT: Duration = Duration::from_secs(10);
    /// Deadline for a killed helper's whole process group to drain to empty.
    const GROUP_CLEAR_WAIT: Duration = Duration::from_secs(10);
    const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
    const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
    const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
    const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
    // Port 0 never hosts a real listening socket (the kernel reads it as "assign an
    // ephemeral port"), so `list --port 0` deterministically finds no confirmed
    // socket — exactly the no-match condition these diagnostics exercise — with no
    // free-port hunting and no bind/release race.
    const DIAGNOSTIC_TEST_PORT: u16 = 0;

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
            continue_pid(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    struct PidGuard {
        pid: u32,
    }

    impl Drop for PidGuard {
        fn drop(&mut self) {
            continue_pid(self.pid);
            terminate_pid(self.pid);
        }
    }

    fn kickoutchi(args: &[&str]) -> Output {
        run_binary(env!("CARGO_BIN_EXE_kickoutchi"), args, None)
    }

    fn kickoutchi_with_stdin(args: &[&str], stdin: &str) -> Output {
        run_binary(env!("CARGO_BIN_EXE_kickoutchi"), args, Some(stdin))
    }

    fn kick(args: &[&str]) -> Output {
        run_binary(env!("CARGO_BIN_EXE_kick"), args, None)
    }

    fn run_binary(path: &str, args: &[&str], stdin: Option<&str>) -> Output {
        let config_home = isolated_config_home();
        let mut command = Command::new(path);
        command
            .env("XDG_CONFIG_HOME", &config_home)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().expect("kickoutchi binary must run");
        if let Some(input) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin must be piped")
                .write_all(input.as_bytes())
                .expect("confirmation input must be written");
        }
        let output = child
            .wait_with_output()
            .expect("kickoutchi output must be collected");
        let _ = fs::remove_dir_all(config_home);
        output
    }

    fn isolated_config_home() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-{}-{unique}",
            std::process::id(),
        ));
        fs::create_dir_all(&path).expect("isolated config directory must be created");
        path
    }

    fn spawn_related_process(port: u16) -> ChildGuard {
        let port_text = port.to_string();
        // A dependency-free stand-in for "a process that names this port on its
        // command line but holds no socket" — so the suite needs no Python (or
        // any other interpreter) on PATH. The `sleep 30; :` body is a command
        // list, not a single command, which keeps `sh` hanging around with its
        // full argv: a bare `sleep 30` would let `sh` exec-optimize itself into
        // `sleep` and drop the trailing `--port <port>` from /proc/<pid>/cmdline
        // that the diagnostic keys off.
        let child = Command::new("sh")
            .args(["-c", "sleep 30; :", "--port", port_text.as_str()])
            .spawn()
            .expect("sh helper process must start");
        let guard = ChildGuard { child };
        wait_for_cmdline(guard.id(), &port_text);
        guard
    }

    fn spawn_listener_process() -> (ChildGuard, u16, PathBuf) {
        let ready_file = temp_file_path("listener-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_LISTENER_ENV, "1")
            .env(HELPER_PORT_ENV, "0")
            .env(HELPER_READY_ENV, &ready_file)
            .args([
                "--exact",
                "linux::helper_tcp_listener_process",
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
            .args(["--exact", "linux::helper_process_tree", "--nocapture"])
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
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-{label}-{}-{unique}",
            std::process::id(),
        ))
    }

    fn wait_for_cmdline(pid: u32, needle: &str) {
        let path = format!("/proc/{pid}/cmdline");
        let deadline = Instant::now() + CMDLINE_WAIT;
        loop {
            // A read failure (helper died, or has not surfaced in /proc yet)
            // stays inside the poll: the honest failure is the deadline
            // assertion below, not a confusing panic on the read itself.
            let matched = fs::read(&path)
                .is_ok_and(|cmdline| String::from_utf8_lossy(&cmdline).contains(needle));
            if matched {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "helper process command line never contained {needle}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_file(path: &Path) {
        wait_for_file_within(path, CMDLINE_WAIT);
    }

    fn wait_for_file_within(path: &Path, wait: Duration) {
        let deadline = Instant::now() + wait;
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

    /// Park a helper process for the remainder of its useful life, then exit.
    /// Bounded so helpers are self-terminating: even when the test binary that
    /// spawned them is killed by `SIGKILL` and never runs cleanup, the park is the
    /// helper's own self-destruct timer.
    fn park_bounded() -> ! {
        let deadline = Instant::now() + HELPER_PARK_MAX;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_secs(1));
        }
        std::process::exit(0)
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

    fn wait_for_pid_state(pid: u32, expected: char) {
        let deadline = Instant::now() + CHILD_EXIT_WAIT;
        loop {
            if process_state(pid) == Some(expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "PID {pid} never reached state {expected:?}",
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn pid_exists(pid: u32) -> bool {
        Path::new("/proc").join(pid.to_string()).exists()
    }

    fn process_state(pid: u32) -> Option<char> {
        let stat =
            fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat")).ok()?;
        let (_before, after) = stat.rsplit_once(") ")?;
        after.chars().next()
    }

    fn terminate_pid(pid: u32) {
        let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
            return;
        };
        unsafe {
            libc::kill(platform_pid, libc::SIGTERM);
        }
    }

    fn continue_pid(pid: u32) {
        let Ok(platform_pid) = libc::pid_t::try_from(pid) else {
            return;
        };
        unsafe {
            libc::kill(platform_pid, libc::SIGCONT);
        }
    }

    fn stop_pid(pid: u32) {
        let platform_pid = libc::pid_t::try_from(pid).expect("test pid must fit pid_t");
        let result = unsafe { libc::kill(platform_pid, libc::SIGSTOP) };
        assert_eq!(result, 0, "SIGSTOP test helper PID {pid} must succeed");
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn helper_tcp_listener_process() {
        if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
            return;
        }

        let port = std::env::var(HELPER_PORT_ENV)
            .expect("helper port must be set")
            .parse::<u16>()
            .expect("helper port must be a u16");
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );
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
    fn helper_process_tree() {
        let Some(mode) = std::env::var_os(HELPER_TREE_ENV) else {
            return;
        };
        let mode = mode.to_string_lossy();
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );

        match mode.as_ref() {
            "root-owns-port" => {
                let listener = TcpListener::bind(("127.0.0.1", 0))
                    .expect("root tree helper listener must bind");
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
                            "linux::helper_tcp_listener_process",
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
            "live-spawner" => run_live_spawner_helper(&ready_file),
            "fork-on-trigger" => run_fork_on_trigger_helper(&ready_file),
            chain if chain.starts_with("chain-") => run_chain_link_helper(chain, &ready_file),
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
                let output = Command::new("sh")
                    .args(["-c", "sleep 300 >/dev/null 2>&1 & echo $!"])
                    .output()
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

    /// One link of the deep static chain: every link but the leaf spawns the
    /// next link and parks; the leaf publishes its own PID (the deepest member
    /// the kill must reach) and parks.
    fn run_chain_link_helper(mode: &str, ready_file: &Path) -> ! {
        let depth = mode
            .strip_prefix("chain-")
            .expect("chain mode must carry a depth")
            .parse::<usize>()
            .expect("chain depth must be numeric");
        if depth <= 1 {
            let ready_tmp = ready_file.with_extension("tmp");
            fs::write(&ready_tmp, std::process::id().to_string())
                .expect("chain leaf ready file must be written");
            fs::rename(&ready_tmp, ready_file).expect("chain leaf ready file must publish");
        } else {
            // The handle is dropped without killing: the next link lives on as
            // a chain member until the kill (or its own bounded park) ends it.
            let next =
                Command::new(std::env::current_exe().expect("test binary path must resolve"))
                    .env(HELPER_TREE_ENV, format!("chain-{}", depth - 1))
                    .env(HELPER_READY_ENV, ready_file)
                    .args(["--exact", "linux::helper_process_tree", "--nocapture"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("next chain link must spawn");
            drop(next);
        }
        park_bounded()
    }

    /// A root that actively spawns short-lived children for a bounded window,
    /// then settles into a plain park. Every child is a plain `sleep 2`, so
    /// even a fully failed test leaves nothing that outlives its own timer.
    fn run_live_spawner_helper(ready_file: &Path) -> ! {
        // A fresh process group: children inherit pgid == this PID, giving the
        // test one precise membership question to poll after the kill.
        // SAFETY: setpgid(0, 0) makes the calling process a group leader; it
        // takes no pointers and cannot affect other processes.
        let result = unsafe { libc::setpgid(0, 0) };
        assert_eq!(result, 0, "live spawner must become a group leader");

        let spawn_deadline = Instant::now() + LIVE_SPAWN_WINDOW;
        let mut children: Vec<Child> = Vec::new();
        let mut spawned: usize = 0;
        while Instant::now() < spawn_deadline && spawned < LIVE_SPAWN_MAX {
            let child = Command::new("sleep")
                .arg("2")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("live spawner child must spawn");
            children.push(child);
            spawned += 1;
            if spawned == 1 {
                let ready_tmp = ready_file.with_extension("tmp");
                fs::write(&ready_tmp, "spawning").expect("live spawner ready file must be written");
                fs::rename(&ready_tmp, ready_file).expect("live spawner ready file must publish");
            }
            // Reap finished children so the brood stays bounded and zombie-light.
            children.retain_mut(|child| matches!(child.try_wait(), Ok(None)));
            // Pacing, not synchronization: it keeps the burst under the tree cap
            // while still guaranteeing the kill under test lands mid-spawn.
            thread::sleep(Duration::from_millis(50));
        }
        park_bounded()
    }

    /// A parent that owns one child from the start and forks one more member
    /// only when the trigger file appears — after the kill's preview already
    /// printed. The second ready file publishes the late member's PID.
    fn run_fork_on_trigger_helper(ready_file: &Path) -> ! {
        let child = Command::new("sh")
            .args(["-c", "sleep 300"])
            .spawn()
            .expect("fork-on-trigger child must spawn");
        let ready_tmp = ready_file.with_extension("tmp");
        fs::write(&ready_tmp, child.id().to_string())
            .expect("fork-on-trigger ready file must be written");
        fs::rename(&ready_tmp, ready_file).expect("fork-on-trigger ready file must publish");
        let _child_guard = ChildGuard { child };

        let trigger_file = ready_file.with_extension("trigger");
        let deadline = Instant::now() + HELPER_PARK_MAX;
        while Instant::now() < deadline {
            if trigger_file.exists() {
                let grandchild = Command::new("sh")
                    .args(["-c", "sleep 300"])
                    .spawn()
                    .expect("fork-on-trigger late member must spawn");
                let second_tmp = ready_file.with_extension("second-tmp");
                fs::write(&second_tmp, grandchild.id().to_string())
                    .expect("fork-on-trigger second ready file must be written");
                fs::rename(&second_tmp, ready_file.with_extension("second"))
                    .expect("fork-on-trigger second ready file must publish");
                let _grandchild_guard = ChildGuard { child: grandchild };
                park_bounded()
            }
            thread::sleep(Duration::from_millis(10));
        }
        std::process::exit(0)
    }

    fn spawn_deep_chain_process(depth: usize) -> (ChildGuard, u32, PathBuf) {
        let ready_file = temp_file_path("chain-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, format!("chain-{depth}"))
            .env(HELPER_READY_ENV, &ready_file)
            .args(["--exact", "linux::helper_process_tree", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("chain helper process must start");
        let guard = ChildGuard { child };
        wait_for_file_within(&ready_file, DEEP_CHAIN_READY_WAIT);
        let leaf_pid = fs::read_to_string(&ready_file)
            .expect("chain ready file must be readable")
            .trim()
            .parse::<u32>()
            .expect("chain leaf pid must be a u32");
        (guard, leaf_pid, ready_file)
    }

    fn spawn_live_spawner_process() -> (ChildGuard, PathBuf) {
        let ready_file = temp_file_path("spawner-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, "live-spawner")
            .env(HELPER_READY_ENV, &ready_file)
            .args(["--exact", "linux::helper_process_tree", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("live spawner helper process must start");
        let guard = ChildGuard { child };
        wait_for_file(&ready_file);
        (guard, ready_file)
    }

    fn spawn_fork_on_trigger_process() -> (ChildGuard, u32, PathBuf) {
        let ready_file = temp_file_path("fork-trigger-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, "fork-on-trigger")
            .env(HELPER_READY_ENV, &ready_file)
            .args(["--exact", "linux::helper_process_tree", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("fork-on-trigger helper process must start");
        let guard = ChildGuard { child };
        wait_for_file(&ready_file);
        let child_pid = fs::read_to_string(&ready_file)
            .expect("fork-on-trigger ready file must be readable")
            .trim()
            .parse::<u32>()
            .expect("fork-on-trigger child pid must be a u32");
        (guard, child_pid, ready_file)
    }

    /// Every live process in group `pgid`, with its one-letter state. Reads
    /// `/proc` directly; entries that vanish mid-scan simply drop out.
    fn process_group_members(pgid: u32) -> Vec<(u32, char)> {
        let pgid_text = pgid.to_string();
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut members = Vec::new();
        for entry in entries.flatten() {
            let Some(member_pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            // Fields after the ")" closing comm: state, ppid, pgrp, ...
            let Some((_before, after)) = stat.rsplit_once(") ") else {
                continue;
            };
            let mut fields = after.split_whitespace();
            let state = fields.next().and_then(|field| field.chars().next());
            let group = fields.nth(1);
            if group == Some(pgid_text.as_str())
                && let Some(state) = state
            {
                members.push((member_pid, state));
            }
        }
        members
    }

    fn wait_for_process_group_clear(pgid: u32) {
        let deadline = Instant::now() + GROUP_CLEAR_WAIT;
        loop {
            let members = process_group_members(pgid);
            if members.is_empty() {
                return;
            }
            // A survivor frozen in state 'T' would never clear on its own; the
            // deadline turns it into a visible failure listing (pid, state).
            assert!(
                Instant::now() < deadline,
                "process group {pgid} still has members (pid, state): {members:?}",
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// A `kick kill` run whose stdin stays open across the confirmation
    /// prompt, so a test can change the world *between* the preview banner and
    /// the typed word. Stderr is drained by a reader thread into a shared
    /// buffer the test polls; the prompt has no trailing newline, so the
    /// buffer fills from raw reads, not lines.
    struct InteractiveKick {
        child: Child,
        config_home: PathBuf,
        stderr_buf: Arc<Mutex<String>>,
        reader: Option<thread::JoinHandle<()>>,
    }

    impl InteractiveKick {
        fn spawn(args: &[&str]) -> Self {
            let config_home = isolated_config_home();
            let mut child = Command::new(env!("CARGO_BIN_EXE_kickoutchi"))
                .env("XDG_CONFIG_HOME", &config_home)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("kickoutchi binary must run");
            let mut child_stderr = child.stderr.take().expect("stderr must be piped");
            let stderr_buf = Arc::new(Mutex::new(String::new()));
            let buffer = Arc::clone(&stderr_buf);
            let reader = thread::spawn(move || {
                let mut chunk = [0_u8; 4096];
                loop {
                    match child_stderr.read(&mut chunk) {
                        Ok(0) | Err(_) => break,
                        Ok(count) => buffer
                            .lock()
                            .expect("stderr buffer lock must not be poisoned")
                            .push_str(&String::from_utf8_lossy(&chunk[..count])),
                    }
                }
            });
            Self {
                child,
                config_home,
                stderr_buf,
                reader: Some(reader),
            }
        }

        fn wait_for_stderr(&self, needle: &str) {
            let deadline = Instant::now() + PROMPT_WAIT;
            loop {
                {
                    let buffer = self
                        .stderr_buf
                        .lock()
                        .expect("stderr buffer lock must not be poisoned");
                    if buffer.contains(needle) {
                        return;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "kickoutchi never printed {needle:?}; stderr so far:\n{}",
                        buffer.as_str(),
                    );
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn send_stdin(&mut self, input: &str) {
            self.child
                .stdin
                .as_mut()
                .expect("stdin must be piped")
                .write_all(input.as_bytes())
                .expect("confirmation input must be written");
        }

        /// Close stdin, wait (bounded) for exit, and return the exit code
        /// together with the complete stderr transcript.
        fn finish(&mut self) -> (Option<i32>, String) {
            drop(self.child.stdin.take());
            let deadline = Instant::now() + KICK_EXIT_WAIT;
            let status = loop {
                if let Some(status) = self
                    .child
                    .try_wait()
                    .expect("kickoutchi exit status must be readable")
                {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "kickoutchi did not exit after confirmation input",
                );
                thread::sleep(Duration::from_millis(10));
            };
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
            let transcript = self
                .stderr_buf
                .lock()
                .expect("stderr buffer lock must not be poisoned")
                .clone();
            (status.code(), transcript)
        }
    }

    impl Drop for InteractiveKick {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
            let _ = fs::remove_dir_all(&self.config_home);
        }
    }

    #[test]
    fn human_list_no_match_prints_diagnostic_to_stderr() {
        let port = DIAGNOSTIC_TEST_PORT;
        let port_text = port.to_string();
        let _helper = spawn_related_process(port);

        let output = kickoutchi(&["list", "--port", port_text.as_str()]);

        assert_eq!(output.status.code(), Some(3));
        assert!(stdout(&output).contains("no open ports match the filter"));
        assert!(!stdout(&output).contains("Possible related process"));
        assert!(stderr(&output).contains("Possible related process"));
        assert!(stderr(&output).contains("but no socket was confirmed"));
        assert!(!stderr(&output).contains("owns this port"));
    }

    #[test]
    fn json_list_no_match_keeps_diagnostic_out_of_stdout_and_stderr() {
        let port = DIAGNOSTIC_TEST_PORT;
        let port_text = port.to_string();
        let _helper = spawn_related_process(port);

        let output = kickoutchi(&["list", "--port", port_text.as_str(), "--json"]);

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(stdout(&output), "[]\n");
        assert_eq!(stderr(&output), "");
    }

    #[test]
    fn kill_pid_yes_sends_real_sigterm_and_port_disappears() {
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout(&before).contains(pid_text.as_str()));

        let killed = kickoutchi(&["kill", "--pid", pid_text.as_str(), "--yes"]);
        assert_eq!(killed.status.code(), Some(0));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        // The target banner (identity + equivalent command) prints even on the
        // `--yes` path, so a scripted kill still leaves the safety context — and
        // any warning lines — on stderr instead of signalling silently.
        assert!(
            killed_stderr.contains(&format!("Terminate PID {pid_text}")),
            "{killed_stderr}"
        );
        assert!(
            killed_stderr.contains(&format!("Command: kill {pid_text}")),
            "{killed_stderr}"
        );
        wait_for_child_exit(&mut helper);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        assert!(stdout(&after).contains("no open ports match the filter"));

        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_port_removes_root_and_child() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(root_pid_text.as_str()));

        let killed =
            kickoutchi_with_stdin(&["kill", "--port", port_text.as_str(), "--tree"], "tree\n");

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    /// Declining the typed-word prompt must leave the whole tree alive and
    /// *running*: confirmation happens before any freeze, so no member may be
    /// left `SIGSTOP`ped in state `T`. This pins that ordering end to end — a
    /// refactor that froze the tree before prompting (say, to make the count
    /// exact) would fail here by leaving a frozen member behind.
    #[test]
    fn tree_kill_declined_at_prompt_leaves_tree_running_and_unfrozen() {
        let (helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        let root_pid = helper.id();

        // Enter alone at the typed-word prompt declines the kill.
        let declined =
            kickoutchi_with_stdin(&["kill", "--port", port_text.as_str(), "--tree"], "\n");

        assert_eq!(declined.status.code(), Some(5), "{}", stderr(&declined));
        let declined_stderr = stderr(&declined);
        // The preview printed and the prompt was really reached before the
        // cancel — this declined after enumeration, not before it.
        assert!(declined_stderr.contains("Scope: tree"), "{declined_stderr}");
        assert!(
            declined_stderr.contains("kill cancelled"),
            "{declined_stderr}"
        );

        // Both members survive, and neither is left stopped.
        for pid in [root_pid, child_pid] {
            assert!(pid_exists(pid), "PID {pid} must survive a declined kill");
            let state = process_state(pid);
            assert!(state.is_some(), "PID {pid} state must be readable");
            assert_ne!(state, Some('T'), "PID {pid} must not be left frozen");
        }

        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_port_terminates_previously_stopped_child() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        stop_pid(child_pid);
        wait_for_pid_state(child_pid, 'T');

        let killed =
            kickoutchi_with_stdin(&["kill", "--port", port_text.as_str(), "--tree"], "tree\n");

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_port_force_uses_sigkill_wording() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();

        let killed = kickoutchi_with_stdin(
            &["kill", "--port", port_text.as_str(), "--tree", "--force"],
            "force\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(
            killed_stderr.contains("Force-kill process tree"),
            "{killed_stderr}"
        );
        assert!(killed_stderr.contains("sent SIGKILL"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_pid_allows_portless_parent_when_child_owns_port() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();
        let child_pid_text = child_pid.to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(child_pid_text.as_str()));
        assert!(!stdout(&before).contains(root_pid_text.as_str()));

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
            "tree\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_pid_reaches_deep_static_chain() {
        let (mut helper, leaf_pid, ready_file) = spawn_deep_chain_process(DEEP_CHAIN_DEPTH);
        let _leaf_cleanup = PidGuard { pid: leaf_pid };
        let root_pid_text = helper.id().to_string();

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
            "tree\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(
            killed_stderr.contains(&format!("{DEEP_CHAIN_DEPTH} processes")),
            "{killed_stderr}",
        );
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(leaf_pid);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_converges_on_active_spawner_and_clears_group() {
        let (mut helper, ready_file) = spawn_live_spawner_process();
        let root_pid = helper.id();
        let root_pid_text = root_pid.to_string();

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
            "tree\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_process_group_clear(root_pid);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_recollects_after_prompt_and_kills_late_fork() {
        let (mut helper, first_child_pid, ready_file) = spawn_fork_on_trigger_process();
        let _first_child_cleanup = PidGuard {
            pid: first_child_pid,
        };
        let root_pid_text = helper.id().to_string();
        let mut kick = InteractiveKick::spawn(&["kill", "--pid", root_pid_text.as_str(), "--tree"]);

        kick.wait_for_stderr("Type tree");
        let trigger_file = ready_file.with_extension("trigger");
        fs::write(&trigger_file, "go").expect("fork trigger file must be written");
        let second_file = ready_file.with_extension("second");
        wait_for_file(&second_file);
        let late_pid = fs::read_to_string(&second_file)
            .expect("late fork ready file must be readable")
            .trim()
            .parse::<u32>()
            .expect("late fork pid must be a u32");
        let _late_cleanup = PidGuard { pid: late_pid };

        kick.send_stdin("tree\n");
        let (code, transcript) = kick.finish();

        assert_eq!(code, Some(0), "{transcript}");
        assert!(transcript.contains("Scope: tree"), "{transcript}");
        assert!(transcript.contains("sent SIGTERM"), "{transcript}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(first_child_pid);
        wait_for_pid_gone(late_pid);
        let _ = fs::remove_file(ready_file);
        let _ = fs::remove_file(trigger_file);
        let _ = fs::remove_file(second_file);
    }

    /// The scenario group scope exists for: a member that double-forked away
    /// from the tree (its spawner exited, so it reparented) but kept the
    /// group. A tree kill from the root can never reach it; the group kill
    /// must — and the confirmation must have shown every member first.
    #[test]
    fn group_kill_reaches_reparented_member_a_tree_walk_cannot() {
        let (mut helper, port, orphan_pid, ready_file) = spawn_group_process();
        let _orphan_cleanup = PidGuard { pid: orphan_pid };
        let root_pid = helper.id();
        let port_text = port.to_string();

        // Prove the premise: the orphan is alive but no longer our helper's
        // child, so it is invisible to a parent-link walk from the root.
        let orphan_parent = read_ppid(orphan_pid);
        assert_ne!(orphan_parent, root_pid, "orphan must have reparented");

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid.to_string().as_str(), "--group"],
            "group\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: group"), "{killed_stderr}");
        // Every member is listed, the reparented one included.
        assert!(
            killed_stderr.contains(&format!("PID {orphan_pid}")),
            "{killed_stderr}",
        );
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(orphan_pid);
        wait_for_process_group_clear(root_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    fn spawn_group_process() -> (ChildGuard, u16, u32, PathBuf) {
        let ready_file = temp_file_path("group-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, "group-orphan")
            .env(HELPER_READY_ENV, &ready_file)
            .args(["--exact", "linux::helper_process_tree", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("group helper process must start");
        let guard = ChildGuard { child };
        wait_for_file(&ready_file);
        let ready = fs::read_to_string(&ready_file).expect("group ready file must be readable");
        let mut parts = ready.split_whitespace();
        let port = parts
            .next()
            .expect("ready file must contain port")
            .parse::<u16>()
            .expect("group helper port must be a u16");
        let orphan_pid = parts
            .next()
            .expect("ready file must contain orphan pid")
            .parse::<u32>()
            .expect("group orphan pid must be a u32");
        (guard, port, orphan_pid, ready_file)
    }

    fn read_ppid(pid: u32) -> u32 {
        let status = fs::read_to_string(format!("/proc/{pid}/status"))
            .expect("orphan status must be readable");
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .expect("status must carry PPid")
            .trim()
            .parse::<u32>()
            .expect("PPid must be numeric")
    }

    #[test]
    fn inspect_shows_family_read_only_with_kill_hint() {
        let (helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let root_pid_text = helper.id().to_string();
        let port_text = port.to_string();

        // By parent PID: the root owns no port, only its child does.
        let by_pid = kickoutchi(&["inspect", "--pid", root_pid_text.as_str()]);
        assert_eq!(by_pid.status.code(), Some(0), "{}", stderr(&by_pid));
        let out = stdout(&by_pid);
        assert!(
            out.contains(&format!("Target: PID {root_pid_text}")),
            "{out}"
        );
        assert!(out.contains("Ancestors (nearest first):"), "{out}");
        assert!(out.contains(&format!("PID {child_pid}")), "{out}");
        assert!(out.contains(&format!("TCP 127.0.0.1:{port}")), "{out}");
        assert!(
            out.contains(&format!("kick kill --pid {root_pid_text} --tree")),
            "{out}",
        );

        // By port: resolves to the owning child.
        let by_port = kickoutchi(&["inspect", "--port", port_text.as_str()]);
        assert_eq!(by_port.status.code(), Some(0), "{}", stderr(&by_port));
        assert!(
            stdout(&by_port).contains(&format!("Target: PID {child_pid}")),
            "{}",
            stdout(&by_port),
        );

        // Read-only: everything is still alive after both reports.
        assert!(pid_exists(child_pid), "inspect must not signal anything");

        // A PID that cannot exist is a clean no-match.
        let missing = kickoutchi(&["inspect", "--pid", "4000000000"]);
        assert_eq!(missing.status.code(), Some(3));

        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn short_kick_binary_matches_canonical_help_and_version() {
        let help = kick(&["--help"]);
        assert!(help.status.success(), "kick --help must exit 0");
        let help_text = stdout(&help);
        assert!(
            help_text.contains("Usage: kick "),
            "kick --help must show the short binary name; got:\n{help_text}"
        );
        // Column padding between the name and the description shifts whenever
        // a longer subcommand is added, so pin content, not layout.
        assert!(
            help_text.contains("list") && help_text.contains("Print open ports and exit"),
            "kick --help must list subcommands; got:\n{help_text}"
        );

        let version = kick(&["--version"]);
        assert!(version.status.success(), "kick --version must exit 0");
        let version_text = stdout(&version);
        assert!(
            version_text.contains("kickoutchi"),
            "kick --version must report the canonical kickoutchi name; got:\n{version_text}"
        );

        let list = kick(&["list", "--json"]);
        assert!(
            list.status.success(),
            "kick list --json must exit 0; stderr:\n{}",
            stderr(&list)
        );
        assert!(
            stdout(&list).starts_with('['),
            "kick list --json must print a JSON array"
        );
    }
}

#[cfg(windows)]
mod windows {
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
    const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
    const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(5);
    const HELPER_READY_WAIT: Duration = Duration::from_secs(5);
    /// How long a parked helper may outlive its test before self-destructing.
    const HELPER_PARK_MAX: Duration = Duration::from_mins(5);

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

    fn kickoutchi(args: &[&str]) -> Output {
        kickoutchi_with_stdin(args, None)
    }

    fn kickoutchi_with_stdin(args: &[&str], stdin: Option<&str>) -> Output {
        let config_home = isolated_config_home();
        let mut command = Command::new(env!("CARGO_BIN_EXE_kickoutchi"));
        command
            .env("APPDATA", &config_home)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().expect("kickoutchi binary must run");
        if let Some(input) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin must be piped")
                .write_all(input.as_bytes())
                .expect("confirmation input must be written");
        }
        let output = child
            .wait_with_output()
            .expect("kickoutchi output must be collected");
        let _ = fs::remove_dir_all(config_home);
        output
    }

    fn isolated_config_home() -> PathBuf {
        let unique = unique_suffix();
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-windows-config-{}-{unique}",
            std::process::id(),
        ));
        fs::create_dir_all(&path).expect("isolated config directory must be created");
        path
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

    fn temp_file_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-windows-{label}-{}-{}",
            std::process::id(),
            unique_suffix(),
        ))
    }

    /// Park a helper process for the remainder of its useful life, then exit.
    /// Bounded so helpers are self-terminating: even when the test binary that
    /// spawned them is killed and never runs cleanup, the park is the helper's
    /// own self-destruct timer.
    fn park_bounded() -> ! {
        let deadline = Instant::now() + HELPER_PARK_MAX;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_secs(1));
        }
        std::process::exit(0)
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
                "helper process did not exit after TerminateProcess",
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn helper_tcp_listener_process() {
        if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
            return;
        }

        let port = std::env::var(HELPER_PORT_ENV)
            .expect("helper port must be set")
            .parse::<u16>()
            .expect("helper port must be a u16");
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );
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
    fn windows_interactive_normal_kill_accepts_y_and_port_disappears() {
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout(&before).contains(pid_text.as_str()));

        let killed = kickoutchi_with_stdin(&["kill", "--pid", pid_text.as_str()], Some("y\n"));
        assert_eq!(killed.status.code(), Some(0));
        let killed_stderr = stderr(&killed);
        assert!(
            killed_stderr.contains(&format!("Terminate PID {pid_text}")),
            "{killed_stderr}",
        );
        assert!(
            killed_stderr.contains(&format!("Command: taskkill /F /PID {pid_text}")),
            "{killed_stderr}",
        );
        assert!(
            killed_stderr.contains("sent TerminateProcess"),
            "{killed_stderr}"
        );
        assert!(
            killed_stderr.contains("confirmed target ports are no longer visible"),
            "{killed_stderr}",
        );
        wait_for_child_exit(&mut helper);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        assert!(stdout(&after).contains("no open ports match the filter"));
        assert!(!stderr(&after).contains("Possible related process"));

        let _ = fs::remove_file(ready_file);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::fs;
    use std::io::Write;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
    const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
    const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
    const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(2);
    const HELPER_READY_WAIT: Duration = Duration::from_secs(5);
    /// How long a parked helper may outlive its test before self-destructing.
    const HELPER_PARK_MAX: Duration = Duration::from_mins(5);

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
            // Thaw first: a helper a failed test left SIGSTOPped would otherwise
            // shrug off the SIGKILL-less cleanup and linger frozen.
            continue_pid(self.child.id());
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Cleanup for helper-tree members that are not our direct children (the
    /// grandchild listener), so a failed test cannot leak them.
    struct PidGuard {
        pid: u32,
    }

    impl Drop for PidGuard {
        fn drop(&mut self) {
            continue_pid(self.pid);
            terminate_pid(self.pid);
        }
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
        let mut command = Command::new(env!("CARGO_BIN_EXE_kickoutchi"));
        command
            .args(args)
            .arg("--config")
            .arg(&config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().expect("kickoutchi binary must run");
        if let Some(input) = stdin {
            child
                .stdin
                .as_mut()
                .expect("stdin must be piped")
                .write_all(input.as_bytes())
                .expect("confirmation input must be written");
        }
        let output = child
            .wait_with_output()
            .expect("kickoutchi output must be collected");
        let _ = fs::remove_dir_all(config_dir);
        output
    }

    fn isolated_config_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-macos-config-{}-{}",
            std::process::id(),
            unique_suffix(),
        ));
        fs::create_dir_all(&path).expect("isolated config directory must be created");
        path
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
            .args(["--exact", "macos::helper_process_tree", "--nocapture"])
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

    /// Park a helper process for the remainder of its useful life, then exit.
    /// Bounded so helpers are self-terminating: even when the test binary that
    /// spawned them is killed by `SIGKILL` and never runs cleanup, the park is the
    /// helper's own self-destruct timer.
    fn park_bounded() -> ! {
        let deadline = Instant::now() + HELPER_PARK_MAX;
        while Instant::now() < deadline {
            thread::sleep(Duration::from_secs(1));
        }
        std::process::exit(0)
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

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn helper_tcp_listener_process() {
        if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
            return;
        }

        let port = std::env::var(HELPER_PORT_ENV)
            .expect("helper port must be set")
            .parse::<u16>()
            .expect("helper port must be a u16");
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );
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
    fn helper_process_tree() {
        let Some(mode) = std::env::var_os(HELPER_TREE_ENV) else {
            return;
        };
        let mode = mode.to_string_lossy();
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );

        match mode.as_ref() {
            "root-owns-port" => {
                let listener = TcpListener::bind(("127.0.0.1", 0))
                    .expect("root tree helper listener must bind");
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
                let output = Command::new("sh")
                    .args(["-c", "sleep 300 >/dev/null 2>&1 & echo $!"])
                    .output()
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

    /// The scenario group scope exists for: a member that double-forked away
    /// from the tree but kept the group. See the Linux twin for the full
    /// premise; macOS has no `/proc`, so the reparenting itself is not
    /// asserted here — the sweep reaching a non-descendant is.
    #[test]
    fn macos_group_kill_reaches_reparented_member_a_tree_walk_cannot() {
        let (mut helper, port, orphan_pid, ready_file) = spawn_tree_process_in_group();
        let _orphan_cleanup = PidGuard { pid: orphan_pid };
        let root_pid = helper.id();
        let port_text = port.to_string();

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid.to_string().as_str(), "--group"],
            Some("group\n"),
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: group"), "{killed_stderr}");
        assert!(
            killed_stderr.contains(&format!("PID {orphan_pid}")),
            "{killed_stderr}",
        );
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(orphan_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    fn spawn_tree_process_in_group() -> (ChildGuard, u16, u32, PathBuf) {
        let ready_file = temp_file_path("group-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, "group-orphan")
            .env(HELPER_READY_ENV, &ready_file)
            .args(["--exact", "macos::helper_process_tree", "--nocapture"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("group helper process must start");
        let guard = ChildGuard { child };
        wait_for_file(&ready_file);
        let ready = fs::read_to_string(&ready_file).expect("group ready file must be readable");
        let mut parts = ready.split_whitespace();
        let port = parts
            .next()
            .expect("ready file must contain port")
            .parse::<u16>()
            .expect("group helper port must be a u16");
        let orphan_pid = parts
            .next()
            .expect("ready file must contain orphan pid")
            .parse::<u32>()
            .expect("group orphan pid must be a u32");
        (guard, port, orphan_pid, ready_file)
    }

    #[test]
    fn macos_tree_kill_by_port_removes_root_and_child() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(root_pid_text.as_str()));

        let killed = kickoutchi_with_stdin(
            &["kill", "--port", port_text.as_str(), "--tree"],
            Some("tree\n"),
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn macos_tree_kill_by_pid_allows_portless_parent_when_child_owns_port() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();
        let child_pid_text = child_pid.to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(child_pid_text.as_str()));
        assert!(!stdout(&before).contains(root_pid_text.as_str()));

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
            Some("tree\n"),
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        let killed_stderr = stderr(&killed);
        assert!(killed_stderr.contains("Scope: tree"), "{killed_stderr}");
        assert!(killed_stderr.contains("2 processes"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn macos_inspect_shows_family_read_only_with_kill_hint() {
        let (helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard { pid: child_pid };
        let root_pid_text = helper.id().to_string();
        let port_text = port.to_string();

        let by_pid = kickoutchi(&["inspect", "--pid", root_pid_text.as_str()]);
        assert_eq!(by_pid.status.code(), Some(0), "{}", stderr(&by_pid));
        let out = stdout(&by_pid);
        assert!(
            out.contains(&format!("Target: PID {root_pid_text}")),
            "{out}"
        );
        assert!(out.contains(&format!("PID {child_pid}")), "{out}");
        assert!(out.contains(&format!("TCP 127.0.0.1:{port}")), "{out}");
        assert!(
            out.contains(&format!("kick kill --pid {root_pid_text} --tree")),
            "{out}",
        );

        let by_port = kickoutchi(&["inspect", "--port", port_text.as_str()]);
        assert_eq!(by_port.status.code(), Some(0), "{}", stderr(&by_port));
        assert!(
            stdout(&by_port).contains(&format!("Target: PID {child_pid}")),
            "{}",
            stdout(&by_port),
        );

        // Read-only: everything is still alive after both reports.
        assert!(pid_exists(child_pid), "inspect must not signal anything");

        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn macos_interactive_normal_kill_accepts_y_and_port_disappears() {
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout(&before).contains(pid_text.as_str()));

        let killed = kickoutchi_with_stdin(&["kill", "--pid", pid_text.as_str()], Some("y\n"));
        assert_eq!(killed.status.code(), Some(0));
        let killed_stderr = stderr(&killed);
        assert!(
            killed_stderr.contains(&format!("Terminate PID {pid_text}")),
            "{killed_stderr}",
        );
        assert!(
            killed_stderr.contains(&format!("Command: kill {pid_text}")),
            "{killed_stderr}",
        );
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        assert!(stdout(&after).contains("no open ports match the filter"));
        assert!(!stderr(&after).contains("Possible related process"));

        let _ = fs::remove_file(ready_file);
    }
}
