#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CMDLINE_WAIT: Duration = Duration::from_secs(2);
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(2);
    const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
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
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn kickoutchi(args: &[&str]) -> Output {
        let config_home = isolated_config_home();
        let output = Command::new(env!("CARGO_BIN_EXE_kickoutchi"))
            .env("XDG_CONFIG_HOME", &config_home)
            .args(args)
            .output()
            .expect("kickoutchi binary must run");
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
            let cmdline = fs::read(&path).expect("helper process cmdline must be readable");
            if String::from_utf8_lossy(&cmdline).contains(needle) {
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
        let deadline = Instant::now() + CMDLINE_WAIT;
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

        loop {
            thread::sleep(Duration::from_mins(1));
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
}
