#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Child, Command, Output};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CMDLINE_WAIT: Duration = Duration::from_secs(2);

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

    fn unused_local_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral port must bind");
        listener
            .local_addr()
            .expect("bound listener must have a local address")
            .port()
    }

    fn spawn_related_process(port: u16) -> ChildGuard {
        let port_text = port.to_string();
        // A dependency-free stand-in for "a process that names this port on its
        // command line but holds no socket", so the suite needs no Python (or any
        // other interpreter) on PATH. The `sleep 30; :` body is a command list,
        // not a single command, which keeps `sh` resident with its full argv: a
        // bare `sleep 30` would let `sh` exec-optimize into `sleep` and drop the
        // trailing `--port <port>` from /proc/<pid>/cmdline that the diagnostic
        // matches on.
        let child = Command::new("sh")
            .args(["-c", "sleep 30; :", "--port", port_text.as_str()])
            .spawn()
            .expect("sh helper process must start");
        let guard = ChildGuard { child };
        wait_for_cmdline(guard.id(), &port_text);
        guard
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

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    #[test]
    fn human_list_no_match_prints_diagnostic_to_stderr() {
        let port = unused_local_port();
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
        let port = unused_local_port();
        let port_text = port.to_string();
        let _helper = spawn_related_process(port);

        let output = kickoutchi(&["list", "--port", port_text.as_str(), "--json"]);

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(stdout(&output), "[]\n");
        assert_eq!(stderr(&output), "");
    }
}
