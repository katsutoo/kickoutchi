use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const REAL_BINARY_EXIT_WAIT: Duration = Duration::from_secs(10);
const COMMAND_OUTPUT_BYTES_MAX: u64 = 8 * 1024 * 1024;
const COMMAND_RUNNER_HELPER_ENV: &str = "KICKOUTCHI_TEST_COMMAND_RUNNER_HELPER";
const BINARY_OVERRIDE_HELPER_ENV: &str = "KICKOUTCHI_TEST_BINARY_OVERRIDE_HELPER";
const TRACING_HELPER_ENV: &str = "KICKOUTCHI_TEST_TRACING_HELPER";
const RELEASE_E2E_REQUIRED_ENV: &str = "KICKOUTCHI_RELEASE_E2E_REQUIRED";
const KICKOUTCHI_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICKOUTCHI";
const KICK_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICK";

fn product_binary(variable: &str, fallback: &str) -> OsString {
    let required = std::env::var_os(RELEASE_E2E_REQUIRED_ENV).is_some();
    match (required, std::env::var_os(variable)) {
        (true, Some(path)) => path,
        (true, None) => panic!("release E2E requires {variable}"),
        (false, None) => OsString::from(fallback),
        (false, Some(_)) => panic!("{variable} requires {RELEASE_E2E_REQUIRED_ENV}"),
    }
}

fn kickoutchi_binary() -> OsString {
    product_binary(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi"))
}

fn kick_binary() -> OsString {
    product_binary(KICK_BINARY_ENV, env!("CARGO_BIN_EXE_kick"))
}

struct CommandChild(Option<Child>);

impl CommandChild {
    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("command child must be owned")
    }

    #[cfg(any(target_os = "macos", windows))]
    fn wait_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            match self.child_mut().try_wait()? {
                Some(status) => return Ok(status),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => return Err(io::Error::new(io::ErrorKind::TimedOut, "command deadline")),
            }
        }
    }

    fn kill_and_reap(&mut self, deadline: Instant) -> io::Result<()> {
        if let Some(mut child) = self.0.take() {
            let kill_error = child.kill().err();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => {
                        return Err(kill_error.unwrap_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "killed command exceeded its reap deadline",
                            )
                        }));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    fn disarm(&mut self) {
        drop(self.0.take());
    }
}

impl Drop for CommandChild {
    fn drop(&mut self) {
        let _ = self.kill_and_reap(Instant::now() + Duration::from_secs(1));
    }
}

fn pipe_reader(pipe: impl Read + Send + 'static) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe
            .take(COMMAND_OUTPUT_BYTES_MAX + 1)
            .read_to_end(&mut bytes)
            .and_then(|_| {
                if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > COMMAND_OUTPUT_BYTES_MAX {
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "command output exceeded its byte limit",
                    ))
                } else {
                    Ok(bytes)
                }
            });
        let _ = sender.send(result);
    });
    receiver
}

fn finish_pipe(
    reader: Option<mpsc::Receiver<io::Result<Vec<u8>>>>,
    name: &str,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    match reader {
        Some(reader) => reader
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{name} pipe exceeded its drain deadline"),
                ),
                mpsc::RecvTimeoutError::Disconnected => {
                    io::Error::other(format!("{name} reader stopped without output"))
                }
            })?,
        None => Ok(Vec::new()),
    }
}

fn collect_child_output(child: Child, stdin: Option<&[u8]>, wait: Duration) -> io::Result<Output> {
    let pid = child.id();
    let mut child = CommandChild(Some(child));
    let deadline = Instant::now() + wait;
    let stdout_reader = child.child_mut().stdout.take().map(pipe_reader);
    let stderr_reader = child.child_mut().stderr.take().map(pipe_reader);

    if let Some(input) = stdin {
        let write_result = child
            .child_mut()
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("command stdin was not piped"))
            .and_then(|pipe| pipe.write_all(input));
        drop(child.child_mut().stdin.take());
        if let Err(error) = write_result {
            let cleanup_deadline = Instant::now() + Duration::from_secs(1);
            let cleanup_error = child.kill_and_reap(cleanup_deadline).err();
            let _ = finish_pipe(stdout_reader, "stdout", cleanup_deadline);
            let _ = finish_pipe(stderr_reader, "stderr", cleanup_deadline);
            if let Some(cleanup_error) = cleanup_error {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{error}; command cleanup failed: {cleanup_error}"),
                ));
            }
            return Err(error);
        }
    }

    let status: ExitStatus = loop {
        match child.child_mut().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let cleanup_deadline = Instant::now() + Duration::from_secs(1);
                let cleanup_error = child.kill_and_reap(cleanup_deadline).err();
                let _ = finish_pipe(stdout_reader, "stdout", cleanup_deadline);
                let _ = finish_pipe(stderr_reader, "stderr", cleanup_deadline);
                let cleanup = cleanup_error
                    .map_or_else(String::new, |error| format!("; cleanup failed: {error}"));
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("command PID {pid} exceeded its exit deadline{cleanup}"),
                ));
            }
            Err(error) => {
                let cleanup_deadline = Instant::now() + Duration::from_secs(1);
                let cleanup_error = child.kill_and_reap(cleanup_deadline).err();
                let _ = finish_pipe(stdout_reader, "stdout", cleanup_deadline);
                let _ = finish_pipe(stderr_reader, "stderr", cleanup_deadline);
                if let Some(cleanup_error) = cleanup_error {
                    return Err(io::Error::new(
                        error.kind(),
                        format!("{error}; command cleanup failed: {cleanup_error}"),
                    ));
                }
                return Err(error);
            }
        }
    };
    child.disarm();
    let stdout = finish_pipe(stdout_reader, "stdout", deadline);
    let stderr = finish_pipe(stderr_reader, "stderr", deadline);

    Ok(Output {
        status,
        stdout: stdout?,
        stderr: stderr?,
    })
}

fn run_command_with_deadline(
    command: &mut Command,
    stdin: Option<&[u8]>,
    wait: Duration,
) -> io::Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin.is_some() {
        command.stdin(Stdio::piped());
    }
    collect_child_output(command.spawn()?, stdin, wait)
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn command_runner_helper_process() {
    match std::env::var(COMMAND_RUNNER_HELPER_ENV).as_deref() {
        Ok("dual-output") => {
            let bytes = vec![0xa5; 256 * 1024];
            io::stdout()
                .write_all(&bytes)
                .expect("helper stdout must be writable");
            io::stderr()
                .write_all(&bytes)
                .expect("helper stderr must be writable");
        }
        Ok("output-over-limit") => {
            let bytes = vec![0xa5; usize::try_from(COMMAND_OUTPUT_BYTES_MAX + 1).unwrap()];
            let _ = io::stdout().write_all(&bytes);
        }
        Ok("park") => loop {
            thread::park();
        },
        _ => {}
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn binary_override_helper_process() {
    if std::env::var_os(BINARY_OVERRIDE_HELPER_ENV).is_some() {
        drop(kickoutchi_binary());
        drop(kick_binary());
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by contract tests"]
fn tracing_helper_process() {
    if std::env::var_os(TRACING_HELPER_ENV).is_some() {
        tracing_subscriber::fmt()
            .with_writer(io::sink)
            .try_init()
            .expect("helper tracing subscriber must install");
        assert_eq!(kickoutchi::run(), std::process::ExitCode::from(2));
        assert_eq!(kickoutchi::run(), std::process::ExitCode::from(2));
    }
}

#[test]
fn public_run_tracing_preserves_an_existing_subscriber_across_repeated_calls() {
    let output = run_command_with_deadline(
        Command::new(std::env::current_exe().expect("test binary path resolves"))
            .args([
                "--exact",
                "tracing_helper_process",
                "--ignored",
                "--nocapture",
            ])
            .env(TRACING_HELPER_ENV, "1"),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("tracing helper must exit before its deadline");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn binary_overrides_are_all_or_nothing() {
    fn helper() -> Command {
        let mut command = Command::new(std::env::current_exe().expect("test binary path resolves"));
        command
            .args([
                "--exact",
                "binary_override_helper_process",
                "--ignored",
                "--nocapture",
            ])
            .env(BINARY_OVERRIDE_HELPER_ENV, "1")
            .env_remove(RELEASE_E2E_REQUIRED_ENV)
            .env_remove(KICKOUTCHI_BINARY_ENV)
            .env_remove(KICK_BINARY_ENV);
        command
    }

    let stale = run_command_with_deadline(
        helper().env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("stale override helper must exit before its deadline");
    assert!(!stale.status.success());

    let incomplete = run_command_with_deadline(
        helper()
            .env(RELEASE_E2E_REQUIRED_ENV, "1")
            .env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("incomplete override helper must exit before its deadline");
    assert!(!incomplete.status.success());

    let complete = run_command_with_deadline(
        helper()
            .env(RELEASE_E2E_REQUIRED_ENV, "1")
            .env(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi"))
            .env(KICK_BINARY_ENV, env!("CARGO_BIN_EXE_kick")),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("complete override helper must exit before its deadline");
    assert!(complete.status.success());
}

#[test]
#[allow(
    clippy::naive_bytecount,
    reason = "the helper output includes test-harness text around the exact binary payload"
)]
fn command_runner_drains_large_stdout_and_stderr_without_deadlock() {
    let output = run_command_with_deadline(
        Command::new(std::env::current_exe().expect("test binary path resolves"))
            .env(COMMAND_RUNNER_HELPER_ENV, "dual-output")
            .args([
                "--exact",
                "command_runner_helper_process",
                "--ignored",
                "--nocapture",
            ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("dual-output helper must finish before its deadline");

    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == 0xa5).count(),
        256 * 1024,
    );
    assert_eq!(
        output.stderr.iter().filter(|byte| **byte == 0xa5).count(),
        256 * 1024,
    );
}

#[test]
fn command_runner_rejects_output_past_its_byte_limit() {
    let error = run_command_with_deadline(
        Command::new(std::env::current_exe().expect("test binary path resolves"))
            .env(COMMAND_RUNNER_HELPER_ENV, "output-over-limit")
            .args([
                "--exact",
                "command_runner_helper_process",
                "--ignored",
                "--nocapture",
            ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect_err("over-limit command output must be rejected");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn command_runner_timeout_kills_and_reaps_child() {
    let child = Command::new(std::env::current_exe().expect("test binary path resolves"))
        .env(COMMAND_RUNNER_HELPER_ENV, "park")
        .args([
            "--exact",
            "command_runner_helper_process",
            "--ignored",
            "--nocapture",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("parked helper must start");
    #[cfg(unix)]
    let pid = child.id();

    let error = collect_child_output(child, None, Duration::from_millis(100))
        .expect_err("parked helper must exceed its deadline");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);

    #[cfg(unix)]
    {
        let pid = libc::pid_t::try_from(pid).expect("helper PID must fit pid_t");
        let result = unsafe { libc::kill(pid, 0) };
        assert_eq!(result, -1, "timed-out helper must have been reaped");
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "timed-out helper PID must no longer exist",
        );
    }
}

#[test]
fn required_release_artifact_paths_are_complete_and_versioned() {
    if std::env::var_os(RELEASE_E2E_REQUIRED_ENV).is_none() {
        return;
    }

    let canonical = kickoutchi_binary();
    let short = kick_binary();
    assert_ne!(canonical, short, "release binary paths must be distinct");
    for path in [canonical, short] {
        let metadata = std::fs::metadata(&path).expect("release binary path must be readable");
        assert!(metadata.is_file(), "release binary must be a regular file");
        assert!(metadata.len() > 0, "release binary must not be empty");

        let output = run_command_with_deadline(
            Command::new(&path).arg("--version"),
            None,
            REAL_BINARY_EXIT_WAIT,
        )
        .expect("release binary version command must finish before its deadline");
        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty());
        assert_eq!(
            String::from_utf8(output.stdout).expect("version output must be UTF-8"),
            format!("kickoutchi {}\n", env!("CARGO_PKG_VERSION")),
        );
    }
}

#[test]
fn cli_and_config_errors_sanitize_terminal_controls() {
    let argument = run_command_with_deadline(
        Command::new(kickoutchi_binary()).args(["list", "--sort", "evil\u{202e}value"]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("invalid argument command runs");
    assert_eq!(argument.status.code(), Some(2));
    let stderr = String::from_utf8(argument.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains('\u{202e}'), "{stderr:?}");

    let config = run_command_with_deadline(
        Command::new(kickoutchi_binary()).args([
            "--config",
            "missing\x1b]0;spoof\x07.toml",
            "list",
        ]),
        None,
        REAL_BINARY_EXIT_WAIT,
    )
    .expect("missing config command runs");
    assert_eq!(config.status.code(), Some(1));
    let stderr = String::from_utf8(config.stderr).expect("stderr is UTF-8");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    assert!(!stderr.contains('\x07'), "{stderr:?}");
}

#[cfg(any(target_os = "macos", windows))]
mod why_native {
    use super::{REAL_BINARY_EXIT_WAIT, kickoutchi_binary, run_command_with_deadline};
    use std::fs;
    use std::net::{Ipv6Addr, TcpListener, UdpSocket};
    use std::path::PathBuf;
    use std::process::{Command, Output};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct ConfigGuard(PathBuf);

    impl ConfigGuard {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "kickoutchi-why-native-{}-{unique}.toml",
                std::process::id()
            ));
            fs::write(&path, "").expect("isolated config must be written");
            Self(path)
        }
    }

    impl Drop for ConfigGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn run_why(args: &[&str]) -> Output {
        let config = ConfigGuard::new();
        run_command_with_deadline(
            Command::new(kickoutchi_binary())
                .arg("--config")
                .arg(&config.0)
                .arg("why")
                .args(args)
                .arg("--json"),
            None,
            REAL_BINARY_EXIT_WAIT,
        )
        .expect("why command must run before its deadline")
    }

    fn json(output: &Output) -> serde_json::Value {
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "why stdout must be JSON: {error}; stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
    }

    fn assert_native_occupancy(output: &Output) {
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stderr.is_empty());
        let value = json(output);
        assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
        #[cfg(windows)]
        assert_eq!(value["results"][0]["verdict"], "owned");
        #[cfg(target_os = "macos")]
        assert!(matches!(
            value["results"][0]["verdict"].as_str(),
            Some("owned" | "owner_hidden" | "reservation_or_policy_unknown")
        ));
    }

    #[test]
    fn why_reports_native_tcp_and_udp_occupancy() {
        let tcp = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
        let tcp_port = tcp.local_addr().expect("TCP address is known").port();
        let tcp_port = tcp_port.to_string();
        let tcp_output = run_why(&[tcp_port.as_str(), "--tcp", "--address", "127.0.0.1"]);
        assert_native_occupancy(&tcp_output);

        let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP fixture must bind");
        let udp_port = udp.local_addr().expect("UDP address is known").port();
        let udp_port = udp_port.to_string();
        let udp_output = run_why(&[udp_port.as_str(), "--udp", "--address", "127.0.0.1"]);
        assert_native_occupancy(&udp_output);
    }

    #[test]
    fn why_keeps_ipv6_as_an_explicit_native_result() {
        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            let output = run_why(&["3000", "--tcp", "--address", "::1"]);
            let value = json(&output);
            assert_eq!(output.status.code(), Some(3));
            assert_eq!(value["results"].as_array().map(Vec::len), Some(1));
            assert_eq!(value["results"][0]["endpoint"]["address"], "::1");
            assert!(matches!(
                value["results"][0]["verdict"].as_str(),
                Some("unsupported" | "address_unavailable")
            ));
            return;
        };
        let port = listener.local_addr().expect("IPv6 address is known").port();
        let port = port.to_string();

        let output = run_why(&[port.as_str(), "--tcp", "--address", "::1"]);
        let value = json(&output);

        assert_eq!(output.status.code(), Some(3));
        assert!(output.stderr.is_empty());
        assert_eq!(value["results"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["results"][0]["endpoint"]["address"], "::1");
        assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
        #[cfg(windows)]
        assert_eq!(value["results"][0]["verdict"], "owned");
        #[cfg(target_os = "macos")]
        assert_eq!(
            value["results"][0]["verdict"],
            "reservation_or_policy_unknown"
        );
    }

    #[test]
    fn why_closes_a_successful_native_probe() {
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("temporary UDP fixture must bind");
        let port = socket.local_addr().expect("UDP address is known").port();
        drop(socket);
        let port_text = port.to_string();

        let output = run_why(&[port_text.as_str(), "--udp", "--address", "127.0.0.1"]);

        assert_eq!(output.status.code(), Some(0));
        assert_eq!(json(&output)["results"][0]["verdict"], "bindable_now");
        let rebound = UdpSocket::bind(("127.0.0.1", port))
            .expect("the completed probe must not retain its socket");
        drop(rebound);
    }
}

#[cfg(any(target_os = "macos", windows))]
mod portable_native {
    use super::{
        COMMAND_OUTPUT_BYTES_MAX, CommandChild, REAL_BINARY_EXIT_WAIT, finish_pipe, kick_binary,
        kickoutchi_binary, pipe_reader, run_command_with_deadline,
    };
    use std::ffi::OsStr;
    use std::fs;
    use std::io::{self, BufRead, BufReader, Read};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    struct ConfigGuard(PathBuf);

    impl ConfigGuard {
        fn new(contents: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "kickoutchi-portable-native-{}-{unique}.toml",
                std::process::id()
            ));
            fs::write(&path, contents).expect("isolated config must be written");
            Self(path)
        }
    }

    impl Drop for ConfigGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    enum WatchOutcome {
        Events(Vec<serde_json::Value>),
        #[cfg(target_os = "macos")]
        PartialSocketSet,
    }

    #[cfg(target_os = "macos")]
    const WATCH_RELEASE_ATTEMPTS: usize = 3;

    fn endpoint_config(port: u16) -> ConfigGuard {
        ConfigGuard::new(&format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"wildcard fixture\"\n\n[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"native artifact fixture\"\n"
        ))
    }

    #[cfg(target_os = "macos")]
    fn partial_socket_set_outcome(
        status: std::process::ExitStatus,
        stderr: &[u8],
        error: mpsc::RecvTimeoutError,
    ) -> WatchOutcome {
        assert_eq!(error, mpsc::RecvTimeoutError::Disconnected);
        assert_eq!(status.code(), Some(1));
        assert_eq!(
            stderr,
            b"error: initial observation has a partial socket set\n"
        );
        WatchOutcome::PartialSocketSet
    }

    fn run_with_binary(
        binary: impl AsRef<OsStr>,
        config: &ConfigGuard,
        args: &[&str],
    ) -> std::process::Output {
        run_command_with_deadline(
            Command::new(binary)
                .arg("--config")
                .arg(&config.0)
                .args(args),
            None,
            REAL_BINARY_EXIT_WAIT,
        )
        .expect("native command must finish before its deadline")
    }

    fn run_with_config(config: &ConfigGuard, args: &[&str]) -> std::process::Output {
        run_with_binary(kickoutchi_binary(), config, args)
    }

    fn watch_line_reader(
        stdout: impl Read + Send + 'static,
    ) -> (thread::JoinHandle<()>, mpsc::Receiver<io::Result<String>>) {
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut retained = 0_u64;
            loop {
                let mut line = Vec::new();
                let result = (&mut reader)
                    .take(COMMAND_OUTPUT_BYTES_MAX - retained + 1)
                    .read_until(b'\n', &mut line)
                    .and_then(|read| {
                        retained += u64::try_from(read).unwrap_or(u64::MAX);
                        if retained > COMMAND_OUTPUT_BYTES_MAX {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "watch output exceeded its byte limit",
                            ));
                        }
                        if read == 0 {
                            return Ok(None);
                        }
                        String::from_utf8(line)
                            .map(Some)
                            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
                    });
                match result {
                    Ok(Some(line)) => {
                        if sender.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        return;
                    }
                }
            }
        });
        (reader, receiver)
    }

    fn watch_until_release(
        config: &ConfigGuard,
        port_text: &str,
        listener: TcpListener,
    ) -> WatchOutcome {
        #[cfg(target_os = "macos")]
        let mut command = if std::env::var_os(super::RELEASE_E2E_REQUIRED_ENV).is_some() {
            let mut command = Command::new("sudo");
            command.args(["-n", "--"]).arg(kickoutchi_binary());
            command
        } else {
            Command::new(kickoutchi_binary())
        };
        #[cfg(windows)]
        let mut command = Command::new(kickoutchi_binary());
        let mut child = command
            .arg("--config")
            .arg(&config.0)
            .args([
                "watch",
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                port_text,
                "--filter",
                "state:listen label:artifact",
                "--interval",
                "100ms",
                "--duration",
                "2s",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("native watch must start");
        let stdout = child.stdout.take().expect("watch stdout must be piped");
        let stderr = pipe_reader(child.stderr.take().expect("watch stderr must be piped"));
        let mut child = CommandChild(Some(child));
        let (stdout_reader, receiver) = watch_line_reader(stdout);
        let deadline = Instant::now() + REAL_BINARY_EXIT_WAIT;
        let baseline =
            match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(result) => result.expect("watch baseline must be UTF-8"),
                Err(error) => {
                    let status = child
                        .wait_until(deadline)
                        .expect("native watch must exit before its deadline");
                    child.disarm();
                    let stderr = finish_pipe(Some(stderr), "stderr", deadline)
                        .expect("watch stderr must drain before the deadline");
                    stdout_reader.join().expect("watch stdout reader must join");
                    #[cfg(target_os = "macos")]
                    return partial_socket_set_outcome(status, &stderr, error);
                    #[cfg(windows)]
                    panic!(
                        "watch emitted no baseline ({error}); status {status}; stderr: {}",
                        String::from_utf8_lossy(&stderr)
                    );
                }
            };
        drop(listener);

        let status = child
            .wait_until(deadline)
            .expect("native watch must exit before its deadline");
        child.disarm();
        let stderr = finish_pipe(Some(stderr), "stderr", deadline)
            .expect("watch stderr must drain before the deadline");
        let mut lines = vec![baseline];
        lines.extend(receiver.into_iter().collect::<Result<Vec<_>, _>>().unwrap());
        stdout_reader.join().expect("watch stdout reader must join");
        assert_eq!(status.code(), Some(0));
        assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
        WatchOutcome::Events(
            lines
                .iter()
                .map(|line| serde_json::from_str(line).expect("watch line must be JSON"))
                .collect(),
        )
    }

    fn watch_release_attempt() -> (u16, WatchOutcome) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
        let port = listener.local_addr().expect("TCP address is known").port();
        let port_text = port.to_string();
        let config = endpoint_config(port);
        (port, watch_until_release(&config, &port_text, listener))
    }

    #[cfg(target_os = "macos")]
    fn watch_release_journey() -> Option<(u16, Vec<serde_json::Value>)> {
        let required = std::env::var_os(super::RELEASE_E2E_REQUIRED_ENV).is_some();
        let attempts = if required { WATCH_RELEASE_ATTEMPTS } else { 1 };
        let mut partial_attempts = 0;
        for _attempt in 1..=attempts {
            let (port, outcome) = watch_release_attempt();
            match outcome {
                WatchOutcome::Events(records) => return Some((port, records)),
                WatchOutcome::PartialSocketSet => partial_attempts += 1,
            }
        }

        assert!(
            !required,
            "release-profile native watch produced a partial initial socket set in all {partial_attempts} attempts"
        );
        None
    }

    #[cfg(windows)]
    fn watch_release_journey() -> (u16, Vec<serde_json::Value>) {
        let (port, WatchOutcome::Events(records)) = watch_release_attempt();
        (port, records)
    }

    #[test]
    fn labels_and_watch_run_through_the_native_binary() {
        #[cfg(target_os = "macos")]
        let _host_observation = super::macos::lock_host_observation();

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
        let port = listener.local_addr().expect("TCP address is known").port();
        let port_text = port.to_string();
        let config = endpoint_config(port);

        let list = run_with_config(
            &config,
            &[
                "list",
                "--port",
                port_text.as_str(),
                "--filter",
                "label:artifact",
                "--json",
            ],
        );
        assert_eq!(
            list.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&list.stderr)
        );
        assert!(list.stderr.is_empty());
        let rows: serde_json::Value =
            serde_json::from_slice(&list.stdout).expect("list stdout must be JSON");
        assert_eq!(rows.as_array().map(Vec::len), Some(1));
        assert_eq!(rows[0]["local_port"], port);
        assert_eq!(rows[0]["label"], "native artifact fixture");

        let alias = run_with_binary(
            kick_binary(),
            &config,
            &[
                "list",
                "--port",
                port_text.as_str(),
                "--filter",
                "label:artifact",
                "--json",
            ],
        );
        assert_eq!(alias.status.code(), Some(0));
        assert!(alias.stderr.is_empty());
        let alias_rows: serde_json::Value =
            serde_json::from_slice(&alias.stdout).expect("short binary list must be JSON");
        assert_eq!(alias_rows[0]["label"], "native artifact fixture");

        let why = run_with_config(
            &config,
            &[
                "why",
                port_text.as_str(),
                "--tcp",
                "--address",
                "127.0.0.1",
                "--json",
            ],
        );
        assert_eq!(
            why.status.code(),
            Some(3),
            "{}",
            String::from_utf8_lossy(&why.stderr)
        );
        assert!(why.stderr.is_empty());
        let why_value: serde_json::Value =
            serde_json::from_slice(&why.stdout).expect("why stdout must be JSON");
        assert_eq!(why_value["results"][0]["label"], "native artifact fixture");
        drop(listener);

        #[cfg(target_os = "macos")]
        let Some((watch_port, records)) = watch_release_journey() else {
            return;
        };
        #[cfg(windows)]
        let (watch_port, records) = watch_release_journey();
        assert!(records.len() >= 2);
        assert_eq!(records[0]["schema"], "kickoutchi.watch_event");
        assert_eq!(records[0]["event"], "baseline");
        assert_eq!(records[0]["data"]["endpoint"]["port"], watch_port);
        assert_eq!(records[0]["data"]["label"], "native artifact fixture");
        assert_eq!(records[0]["data"]["filter_result"], "matched");
        let releases = records
            .iter()
            .skip(1)
            .filter(|record| record["event"] == "release")
            .collect::<Vec<_>>();
        assert_eq!(releases.len(), 1, "{records:#?}");
        assert!(
            records.iter().skip(1).all(|record| matches!(
                record["event"].as_str(),
                Some("release" | "collection_gap")
            )),
            "{records:#?}"
        );
        let release = releases[0];
        assert_eq!(release["data"]["endpoint"]["port"], watch_port);
        assert_eq!(release["data"]["label"], "native artifact fixture");
        assert_eq!(release["data"]["filter_result"], "matched");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        CommandChild, REAL_BINARY_EXIT_WAIT, collect_child_output, kick_binary, kickoutchi_binary,
        run_command_with_deadline,
    };
    use std::fs;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, ExitStatus, Output, Stdio};
    use std::sync::{Arc, Mutex, mpsc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CMDLINE_WAIT: Duration = Duration::from_secs(10);
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(10);
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
    const LIVE_SPAWN_MAX: usize = 400;

    fn required_linux_capabilities() -> bool {
        std::env::var_os("KICKOUTCHI_REQUIRE_LINUX_CAPABILITIES").is_some()
    }
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
    const HELPER_BIND_ANY_ENV: &str = "KICKOUTCHI_TEST_HELPER_BIND_ANY";
    const HELPER_NONDUMPABLE_ENV: &str = "KICKOUTCHI_TEST_HELPER_NONDUMPABLE";
    const IPC_WAIT: Duration = Duration::from_secs(10);
    static HOST_OBSERVATION_LOCK: Mutex<()> = Mutex::new(());
    // Port 0 never hosts a real listening socket (the kernel reads it as "assign an
    // ephemeral port"), so `list --port 0` deterministically finds no confirmed
    // socket — exactly the no-match condition these diagnostics exercise — with no
    // free-port hunting and no bind/release race.
    const DIAGNOSTIC_TEST_PORT: u16 = 0;

    fn lock_host_observation() -> std::sync::MutexGuard<'static, ()> {
        HOST_OBSERVATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn assert_json_keys(value: &serde_json::Value, expected: &[&str]) {
        let actual = value
            .as_object()
            .expect("contract value must be an object")
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = expected
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

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

    struct DirectoryGuard(PathBuf);

    impl Drop for DirectoryGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct DeepChainGuard {
        root: Option<Child>,
        process_group: u32,
        pids: Vec<u32>,
        _directory: DirectoryGuard,
    }

    impl DeepChainGuard {
        fn root_id(&self) -> u32 {
            self.root
                .as_ref()
                .expect("deep-chain root must be owned")
                .id()
        }

        fn wait_for_all_gone(&mut self) {
            let deadline = Instant::now() + GROUP_CLEAR_WAIT;
            loop {
                let exited = self
                    .root
                    .as_mut()
                    .expect("deep-chain root must be owned")
                    .try_wait()
                    .expect("deep-chain root status must be readable")
                    .is_some();
                if exited {
                    self.root.take();
                    break;
                }
                assert!(Instant::now() < deadline, "deep-chain root did not exit");
                thread::sleep(Duration::from_millis(10));
            }
            for &pid in &self.pids {
                while pid_exists(pid) {
                    assert!(
                        Instant::now() < deadline,
                        "deep-chain PID {pid} survived termination"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        fn cleanup(&mut self, deadline: Instant) {
            let Ok(process_group) = libc::pid_t::try_from(self.process_group) else {
                return;
            };
            // SAFETY: a negative PID targets the dedicated process group created
            // for this test fixture; no pointer or borrowed memory crosses FFI.
            unsafe {
                libc::kill(-process_group, libc::SIGKILL);
            }
            let mut root = CommandChild(self.root.take());
            let _ = root.kill_and_reap(deadline);
            while Instant::now() < deadline {
                if self.pids.iter().all(|pid| !pid_exists(*pid)) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl Drop for DeepChainGuard {
        fn drop(&mut self) {
            self.cleanup(Instant::now() + GROUP_CLEAR_WAIT);
        }
    }

    struct FileGuard(PathBuf);

    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    struct SocketLifecycle {
        child: Option<Child>,
        stdin: Option<std::process::ChildStdin>,
        lines: mpsc::Receiver<io::Result<String>>,
        reader: Option<thread::JoinHandle<()>>,
        reader_done: mpsc::Receiver<()>,
    }

    fn finish_reader_thread(
        reader: &mut Option<thread::JoinHandle<()>>,
        reader_done: &mpsc::Receiver<()>,
        deadline: Instant,
    ) -> io::Result<()> {
        if reader.is_none() {
            return Ok(());
        }
        let completion =
            reader_done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        match completion {
            Ok(()) => reader
                .take()
                .expect("completed helper reader must be owned")
                .join()
                .map_err(|_| io::Error::other("helper reader panicked")),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let joined = reader
                    .take()
                    .expect("disconnected helper reader must be owned")
                    .join();
                match joined {
                    Ok(()) => Err(io::Error::other("helper reader stopped without completion")),
                    Err(_) => Err(io::Error::other("helper reader panicked")),
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "helper reader exceeded its exit deadline",
            )),
        }
    }

    impl SocketLifecycle {
        fn spawn(binary: &Path, args: &[&str]) -> (Self, u16) {
            let mut child = Command::new(binary)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("socket lifecycle helper must start");
            let stdin = child.stdin.take().expect("helper stdin must be piped");
            let stdout = child.stdout.take().expect("helper stdout must be piped");
            let (sender, lines) = mpsc::channel();
            let (done_sender, reader_done) = mpsc::channel();
            let mut helper = Self {
                child: Some(child),
                stdin: Some(stdin),
                lines,
                reader: None,
                reader_done,
            };
            helper.reader = Some(
                thread::Builder::new()
                    .name("socket-lifecycle-reader".to_owned())
                    .spawn(move || {
                        for line in BufReader::new(stdout).lines() {
                            if sender.send(line).is_err() {
                                break;
                            }
                        }
                        let _ = done_sender.send(());
                    })
                    .expect("socket lifecycle reader must start"),
            );
            let ready = helper.response();
            let port = ready
                .strip_prefix("READY ")
                .expect("helper must acknowledge readiness with its port")
                .parse::<u16>()
                .expect("helper port must be a u16");
            (helper, port)
        }

        fn command(&mut self, command: &str) {
            let stdin = self.stdin.as_mut().expect("helper stdin must remain open");
            writeln!(stdin, "{command}").expect("helper command must be writable");
            stdin.flush().expect("helper command must be flushed");
            assert_eq!(self.response(), command);
        }

        fn id(&self) -> u32 {
            self.child
                .as_ref()
                .expect("helper child must be owned")
                .id()
        }

        fn response(&self) -> String {
            self.lines
                .recv_timeout(IPC_WAIT)
                .expect("helper acknowledgement must arrive before its deadline")
                .expect("helper acknowledgement must be readable")
        }

        fn exit(&mut self) {
            self.command("EXIT");
            drop(self.stdin.take());
            let deadline = Instant::now() + IPC_WAIT;
            let status = self
                .wait_for_exit(deadline)
                .expect("helper must exit after acknowledging EXIT");
            assert!(status.success(), "helper must exit successfully");
            self.finish_reader(deadline)
                .expect("helper reader must finish before its deadline");
        }

        fn wait_for_exit(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
            let child = self
                .child
                .as_mut()
                .ok_or_else(|| io::Error::other("helper child is not owned"))?;
            loop {
                if let Some(status) = child.try_wait()? {
                    self.child.take();
                    return Ok(status);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "helper exceeded its exit deadline",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        }

        fn finish_reader(&mut self, deadline: Instant) -> io::Result<()> {
            finish_reader_thread(&mut self.reader, &self.reader_done, deadline)
        }

        fn cleanup(&mut self, deadline: Instant) -> io::Result<()> {
            drop(self.stdin.take());
            let mut first_error = None;
            if let Some(child) = self.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        self.child.take();
                    }
                    Ok(None) => {
                        first_error = child.kill().err();
                    }
                    Err(error) => first_error = Some(error),
                }
            }
            if self.child.is_some()
                && let Err(error) = self.wait_for_exit(deadline)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            if let Err(error) = self.finish_reader(deadline)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
            first_error.map_or(Ok(()), Err)
        }
    }

    impl Drop for SocketLifecycle {
        fn drop(&mut self) {
            let _ = self.cleanup(Instant::now() + IPC_WAIT);
        }
    }

    struct PidGuard {
        pidfd: OwnedFd,
    }

    impl PidGuard {
        fn new(pid: u32) -> Self {
            let platform_pid = libc::pid_t::try_from(pid).expect("test PID must fit pid_t");
            let raw_pidfd = unsafe {
                // SAFETY: pidfd_open takes value arguments and returns a new owned
                // descriptor. Keeping it open pins cleanup to this process identity.
                libc::syscall(libc::SYS_pidfd_open, platform_pid, 0)
            };
            assert!(raw_pidfd >= 0, "test helper PID {pid} must open a pidfd");
            let pidfd = unsafe {
                // SAFETY: a nonnegative pidfd_open result is one owned descriptor.
                OwnedFd::from_raw_fd(i32::try_from(raw_pidfd).expect("pidfd must fit i32"))
            };
            Self { pidfd }
        }

        fn signal(&self, signal: libc::c_int) {
            unsafe {
                // SAFETY: the owned pidfd remains live for this call; null siginfo
                // and zero flags are the documented basic signal form.
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
    }

    impl Drop for PidGuard {
        fn drop(&mut self) {
            self.signal(libc::SIGCONT);
            self.signal(libc::SIGTERM);
        }
    }

    fn kickoutchi(args: &[&str]) -> Output {
        run_binary(kickoutchi_binary(), args, None)
    }

    fn kickoutchi_with_stdin(args: &[&str], stdin: &str) -> Output {
        run_binary(kickoutchi_binary(), args, Some(stdin))
    }

    fn kickoutchi_with_config(args: &[&str], config_text: &str) -> Output {
        kickoutchi_with_config_deadline(args, config_text)
    }

    fn kickoutchi_with_config_deadline(args: &[&str], config_text: &str) -> Output {
        binary_with_config_deadline_with_env(kickoutchi_binary(), args, config_text, &[])
    }

    fn binary_with_config_deadline_with_env(
        path: impl AsRef<std::ffi::OsStr>,
        args: &[&str],
        config_text: &str,
        environment: &[(&str, &std::ffi::OsStr)],
    ) -> Output {
        let config_dir = isolated_config_home();
        let config_guard = DirectoryGuard(config_dir.clone());
        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, config_text).expect("test config file must be written");
        let mut command = Command::new(path);
        command
            .arg("--config")
            .arg(&config_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (name, value) in environment {
            command.env(name, value);
        }
        let output = run_command_with_deadline(&mut command, None, KICK_EXIT_WAIT)
            .expect("CLI binary must run with explicit config before its deadline");
        drop(config_guard);
        output
    }

    fn why(args: &[&str]) -> Output {
        why_with_config(args, "")
    }

    fn why_with_config(args: &[&str], config_text: &str) -> Output {
        let mut command_args = Vec::with_capacity(args.len() + 1);
        command_args.push("why");
        command_args.extend_from_slice(args);
        kickoutchi_with_config_deadline(&command_args, config_text)
    }

    fn kick_why(args: &[&str]) -> Output {
        let mut command_args = Vec::with_capacity(args.len() + 1);
        command_args.push("why");
        command_args.extend_from_slice(args);
        binary_with_config_deadline_with_env(kick_binary(), &command_args, "", &[])
    }

    fn why_with_bind_faults(args: &[&str], library: &Path, mode: &str) -> Output {
        let mut command_args = Vec::with_capacity(args.len() + 1);
        command_args.push("why");
        command_args.extend_from_slice(args);
        binary_with_config_deadline_with_env(
            kickoutchi_binary(),
            &command_args,
            "",
            &[
                ("LD_PRELOAD", library.as_os_str()),
                (
                    "KICKOUTCHI_TEST_BIND_FAULT_MODE",
                    std::ffi::OsStr::new(mode),
                ),
            ],
        )
    }

    fn build_bind_fault_library() -> (DirectoryGuard, PathBuf) {
        let directory = temp_file_path("bind-faults");
        fs::create_dir(&directory).expect("bind-fault directory must be created");
        let guard = DirectoryGuard(directory.clone());
        let library = directory.join("libkickoutchi_bind_faults.so");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bind_faults.c");
        let output = run_command_with_deadline(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-ldl")
                .arg("-o")
                .arg(&library),
            None,
            CHILD_EXIT_WAIT,
        )
        .expect("C compiler must build the bind-fault fixture before its deadline");
        assert!(
            output.status.success(),
            "bind-fault fixture compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (guard, library)
    }

    fn build_collect_fault_library() -> (DirectoryGuard, PathBuf) {
        let directory = temp_file_path("collect-faults");
        fs::create_dir(&directory).expect("collect-fault directory must be created");
        let guard = DirectoryGuard(directory.clone());
        let library = directory.join("libkickoutchi_collect_faults.so");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/collect_faults.c");
        let output = run_command_with_deadline(
            Command::new("cc")
                .args(["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-ldl")
                .arg("-o")
                .arg(&library),
            None,
            CHILD_EXIT_WAIT,
        )
        .expect("C compiler must build the collect-fault fixture before its deadline");
        assert!(
            output.status.success(),
            "collect-fault fixture compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (guard, library)
    }

    fn build_socket_lifecycle_helper() -> (DirectoryGuard, PathBuf) {
        let directory = temp_file_path("socket-lifecycle");
        fs::create_dir(&directory).expect("socket lifecycle directory must be created");
        let guard = DirectoryGuard(directory.clone());
        let binary = directory.join("socket-lifecycle");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/socket_lifecycle.c");
        let output = run_command_with_deadline(
            Command::new("cc")
                .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
                .arg(&source)
                .arg("-o")
                .arg(&binary),
            None,
            CHILD_EXIT_WAIT,
        )
        .expect("C compiler must build the socket helper before its deadline");
        assert!(
            output.status.success(),
            "socket helper compilation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        (guard, binary)
    }

    fn kick(args: &[&str]) -> Output {
        run_binary(kick_binary(), args, None)
    }

    fn run_binary(path: impl AsRef<std::ffi::OsStr>, args: &[&str], stdin: Option<&str>) -> Output {
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let mut command = Command::new(path);
        command.env("XDG_CONFIG_HOME", &config_home).args(args);
        let output = run_command_with_deadline(
            &mut command,
            stdin.map(str::as_bytes),
            REAL_BINARY_EXIT_WAIT,
        )
        .expect("kickoutchi output must be collected before its deadline");
        drop(config_guard);
        output
    }

    fn run_why_with_closed_stdout(args: &[&str]) -> Output {
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
        drop(reader);
        let child = Command::new(kick_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .arg("why")
            .args(args)
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
            .stderr(Stdio::piped())
            .spawn()
            .expect("why binary must run with a closed stdout reader");
        let output = collect_child_output(child, None, KICK_EXIT_WAIT)
            .expect("why output must be collected before its deadline");
        drop(config_guard);
        output
    }

    fn run_list_with_closed_stdout(args: &[&str]) -> Output {
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
        drop(reader);
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .arg("list")
            .args(args)
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
            .stderr(Stdio::piped())
            .spawn()
            .expect("list binary must run with a closed stdout reader");
        let output = collect_child_output(child, None, KICK_EXIT_WAIT)
            .expect("list output must be collected before its deadline");
        drop(config_guard);
        output
    }

    fn run_subcommand_with_closed_stdout(subcommand: &str, args: &[&str]) -> Output {
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let (reader, writer) = UnixStream::pair().expect("test pipe must be created");
        drop(reader);
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .arg(subcommand)
            .args(args)
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(writer)))
            .stderr(Stdio::piped())
            .spawn()
            .expect("binary must run with a closed stdout reader");
        let output = collect_child_output(child, None, KICK_EXIT_WAIT)
            .expect("closed-stdout command must finish before its deadline");
        drop(config_guard);
        output
    }

    fn run_list_with_full_stdout(args: &[&str]) -> Output {
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let full = fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("Linux exposes /dev/full");
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .arg("list")
            .args(args)
            .stdout(Stdio::from(full))
            .stderr(Stdio::piped())
            .spawn()
            .expect("list binary must run with a failing stdout writer");
        let output = collect_child_output(child, None, KICK_EXIT_WAIT)
            .expect("list output must be collected before its deadline");
        drop(config_guard);
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
        spawn_listener_process_with_metadata_access(true)
    }

    fn spawn_listener_process_with_metadata_access(
        metadata_accessible: bool,
    ) -> (ChildGuard, u16, PathBuf) {
        let ready_file = temp_file_path("listener-ready");
        let mut command = Command::new(std::env::current_exe().expect("test binary path resolves"));
        command
            .env(HELPER_LISTENER_ENV, "1")
            .env(HELPER_PORT_ENV, "0")
            .env(HELPER_READY_ENV, &ready_file)
            .args([
                "--exact",
                "linux::helper_tcp_listener_process",
                "--ignored",
                "--nocapture",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if !metadata_accessible {
            command.env(HELPER_NONDUMPABLE_ENV, "1");
        }
        let child = command.spawn().expect("listener helper process must start");
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
                "linux::helper_process_tree",
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

    fn stdout_table_has_pid(output: &Output, pid: u32) -> bool {
        let pid_text = pid.to_string();
        stdout(output)
            .lines()
            .skip(1)
            .any(|line| line.split_whitespace().nth(3) == Some(pid_text.as_str()))
    }

    fn toml_string(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }

    fn assert_json_keys_absent_recursively(value: &serde_json::Value, forbidden: &[&str]) {
        match value {
            serde_json::Value::Object(object) => {
                for key in object.keys() {
                    assert!(
                        !forbidden.contains(&key.as_str()),
                        "snapshot unexpectedly exposed key {key:?}"
                    );
                }
                for child in object.values() {
                    assert_json_keys_absent_recursively(child, forbidden);
                }
            }
            serde_json::Value::Array(array) => {
                for child in array {
                    assert_json_keys_absent_recursively(child, forbidden);
                }
            }
            _ => {}
        }
    }

    #[test]
    #[ignore = "subprocess fixture; invoked explicitly by contract tests"]
    fn helper_tcp_listener_process() {
        if std::env::var_os(HELPER_LISTENER_ENV).is_none() {
            return;
        }

        if std::env::var_os(HELPER_NONDUMPABLE_ENV).is_some() {
            // SAFETY: prctl is called with the documented PR_SET_DUMPABLE
            // operation and one integer value; no pointer crosses the boundary.
            let result = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
            assert_eq!(result, 0, "test helper must disable dumpability");
        }

        let port = std::env::var(HELPER_PORT_ENV)
            .expect("helper port must be set")
            .parse::<u16>()
            .expect("helper port must be a u16");
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );
        let bind_address = if std::env::var_os(HELPER_BIND_ANY_ENV).is_some() {
            "0.0.0.0"
        } else {
            "127.0.0.1"
        };
        let listener = TcpListener::bind((bind_address, port))
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

    fn chain_pid_file(ready_file: &Path, depth: usize) -> PathBuf {
        ready_file.with_extension(format!("chain-{depth}-pid"))
    }

    fn chain_ready_file(ready_file: &Path, depth: usize) -> PathBuf {
        ready_file.with_extension(format!("chain-{depth}-ready"))
    }

    /// One link of the deep static chain. Each link publishes its PID and does
    /// not report subtree readiness until every descendant has done the same.
    fn run_chain_link_helper(mode: &str, ready_file: &Path) -> ! {
        let depth = mode
            .strip_prefix("chain-")
            .expect("chain mode must carry a depth")
            .parse::<usize>()
            .expect("chain depth must be numeric");
        let pid_file = chain_pid_file(ready_file, depth);
        let pid_tmp = pid_file.with_extension("tmp");
        fs::write(&pid_tmp, std::process::id().to_string())
            .expect("chain PID file must be written");
        fs::rename(&pid_tmp, &pid_file).expect("chain PID file must publish");

        let _next_guard = if depth > 1 {
            let next =
                Command::new(std::env::current_exe().expect("test binary path must resolve"))
                    .env(HELPER_TREE_ENV, format!("chain-{}", depth - 1))
                    .env(HELPER_READY_ENV, ready_file)
                    .args([
                        "--exact",
                        "linux::helper_process_tree",
                        "--ignored",
                        "--nocapture",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("next chain link must spawn");
            wait_for_file_within(
                &chain_ready_file(ready_file, depth - 1),
                DEEP_CHAIN_READY_WAIT,
            );
            Some(ChildGuard { child: next })
        } else {
            None
        };

        let subtree_ready = chain_ready_file(ready_file, depth);
        let subtree_tmp = subtree_ready.with_extension("tmp");
        fs::write(&subtree_tmp, "ready").expect("chain subtree marker must be written");
        fs::rename(&subtree_tmp, &subtree_ready).expect("chain subtree marker must publish");
        park_bounded()
    }

    /// A root that actively spawns short-lived children for a bounded window.
    /// Missing that window exits the fixture with failure instead of letting the
    /// test pass against a settled tree. Every child self-exits after two seconds.
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
        std::process::exit(2)
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

    fn spawn_deep_chain_process(depth: usize) -> DeepChainGuard {
        let directory = temp_file_path("chain-ready");
        fs::create_dir(&directory).expect("chain ready directory must be created");
        let ready_file = directory.join("state");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, format!("chain-{depth}"))
            .env(HELPER_READY_ENV, &ready_file)
            .args([
                "--exact",
                "linux::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("chain helper process must start");
        let process_group = child.id();
        let mut guard = DeepChainGuard {
            root: Some(child),
            process_group,
            pids: Vec::new(),
            _directory: DirectoryGuard(directory),
        };
        wait_for_file_within(&chain_ready_file(&ready_file, depth), DEEP_CHAIN_READY_WAIT);
        guard.pids = (1..=depth)
            .rev()
            .map(|link_depth| {
                fs::read_to_string(chain_pid_file(&ready_file, link_depth))
                    .expect("chain PID file must be readable")
                    .trim()
                    .parse::<u32>()
                    .expect("chain PID must be a u32")
            })
            .collect();
        assert_eq!(guard.pids.len(), depth);
        assert_eq!(guard.pids.first().copied(), Some(guard.root_id()));
        guard
    }

    fn spawn_live_spawner_process() -> (ChildGuard, PathBuf) {
        let ready_file = temp_file_path("spawner-ready");
        let child = Command::new(std::env::current_exe().expect("test binary path must resolve"))
            .env(HELPER_TREE_ENV, "live-spawner")
            .env(HELPER_READY_ENV, &ready_file)
            .args([
                "--exact",
                "linux::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
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
            .args([
                "--exact",
                "linux::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
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
            let mut child = Command::new(kickoutchi_binary())
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
        let _host_observation = lock_host_observation();
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
        let _host_observation = lock_host_observation();
        let port = DIAGNOSTIC_TEST_PORT;
        let port_text = port.to_string();
        let _helper = spawn_related_process(port);

        let output = kickoutchi(&["list", "--port", port_text.as_str(), "--json"]);

        assert_eq!(output.status.code(), Some(3));
        assert_eq!(stdout(&output), "[]\n");
        assert_eq!(stderr(&output), "");
    }

    #[test]
    fn snapshot_json_real_binary_exposes_versioned_private_deterministic_shape() {
        let _host_observation = lock_host_observation();
        let (helper, port, ready_file) = spawn_listener_process();
        let _ready_file = FileGuard(ready_file);
        let config = format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"snapshot fixture\"\n"
        );

        let output = kickoutchi_with_config(&["list", "--snapshot-json"], &config);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let value: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("snapshot stdout must be JSON");
        assert_json_keys(
            &value,
            &[
                "schema",
                "version",
                "capture",
                "scope",
                "completeness",
                "owner_completeness",
                "evidence_gaps",
                "omitted_evidence_gap_count",
                "sockets",
                "processes",
            ],
        );
        assert_eq!(value["schema"], "kickoutchi.snapshot");
        assert_eq!(value["version"], 1);
        assert_json_keys(&value["capture"], &["started_unix_ms", "completed_unix_ms"]);
        assert_json_keys(&value["scope"], &["kind", "identifier", "limitations"]);

        let sockets = value["sockets"]
            .as_array()
            .expect("snapshot sockets must be an array");
        let socket = sockets
            .iter()
            .find(|socket| {
                socket["endpoint"]["protocol"] == "tcp"
                    && socket["endpoint"]["address"] == "127.0.0.1"
                    && socket["endpoint"]["port"] == port
            })
            .expect("snapshot must contain the controlled listener");
        assert_snapshot_socket(socket, helper.id());

        let processes = value["processes"]
            .as_array()
            .expect("snapshot processes must be an array");
        let process = processes
            .iter()
            .find(|process| process["identity"]["pid"] == helper.id())
            .expect("snapshot must contain the controlled listener process");
        assert_snapshot_process(process);
        assert_json_keys_absent_recursively(
            &value,
            &["command_line", "cmdline", "argv", "command"],
        );

        assert_snapshot_order(sockets, processes);
    }

    fn assert_snapshot_socket(socket: &serde_json::Value, helper_pid: u32) {
        assert_json_keys(
            socket,
            &[
                "endpoint",
                "state",
                "timer",
                "owners",
                "socket_token",
                "label",
            ],
        );
        assert_json_keys(
            &socket["endpoint"],
            &["protocol", "address", "port", "ipv6_scope"],
        );
        assert_json_keys(&socket["state"], &["kind", "native_code"]);
        assert_json_keys(
            &socket["owners"],
            &["owners", "omitted_owner_count", "completeness", "reasons"],
        );
        assert_eq!(socket["label"], "snapshot fixture");
        let owner = socket["owners"]["owners"]
            .as_array()
            .expect("snapshot owners must be an array")
            .iter()
            .find(|owner| owner["identity"]["pid"] == helper_pid)
            .expect("controlled listener must have its verified owner");
        assert_json_keys(owner, &["kind", "identity"]);
        assert_json_keys(&owner["identity"], &["pid", "start_marker"]);
        assert_json_keys(&owner["identity"]["start_marker"], &["kind", "ticks"]);
    }

    fn assert_snapshot_process(process: &serde_json::Value) {
        assert_json_keys(
            process,
            &[
                "identity",
                "name",
                "executable_path",
                "parent_pid",
                "metadata_completeness",
            ],
        );
        assert_json_keys(&process["identity"], &["pid", "start_marker"]);
        assert_json_keys(&process["identity"]["start_marker"], &["kind", "ticks"]);
    }

    fn assert_snapshot_order(sockets: &[serde_json::Value], processes: &[serde_json::Value]) {
        let protocol_order = |socket: &serde_json::Value| match socket["endpoint"]["protocol"]
            .as_str()
            .expect("socket protocol must be a string")
        {
            "tcp" => 0,
            "udp" => 1,
            protocol => panic!("unexpected protocol {protocol:?}"),
        };
        assert!(
            sockets
                .windows(2)
                .all(|pair| protocol_order(&pair[0]) <= protocol_order(&pair[1])),
            "snapshot sockets must be monotonic by protocol"
        );
        assert!(
            processes.windows(2).all(|pair| {
                pair[0]["identity"]["pid"].as_u64() <= pair[1]["identity"]["pid"].as_u64()
            }),
            "snapshot processes must be monotonic by PID"
        );
    }

    #[test]
    fn snapshot_json_preserves_legacy_list_json_array_and_exact_row_keys() {
        let _host_observation = lock_host_observation();
        let (helper, port, ready_file) = spawn_listener_process();
        let _ready_file = FileGuard(ready_file);
        let port = port.to_string();

        let output = kickoutchi(&["list", "--port", port.as_str(), "--json"]);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let rows: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("legacy list stdout must be JSON");
        let rows = rows
            .as_array()
            .expect("legacy list JSON must remain a top-level array");
        let row = rows
            .iter()
            .find(|row| row["pid"] == helper.id())
            .expect("legacy list must contain the controlled listener");
        assert_json_keys(
            row,
            &[
                "protocol",
                "local_addr",
                "local_port",
                "state",
                "pid",
                "process_name",
                "executable_path",
                "command_line",
                "parent_pid",
                "parent_process_name",
                "child_pids",
                "protected",
                "platform",
                "permission",
                "label",
            ],
        );
        assert_eq!(row.as_object().map(serde_json::Map::len), Some(15));
    }

    #[test]
    fn snapshot_json_conflicts_exit_before_missing_config_is_loaded() {
        let missing_config = temp_file_path("missing-snapshot-config");
        assert!(!missing_config.exists());
        let missing_config = missing_config.to_string_lossy();
        let conflicts: &[&[&str]] = &[
            &["--json"],
            &["--port", "3000"],
            &["--process", "fixture"],
            &["--filter", "proto:tcp"],
            &["--sort", "port"],
        ];

        for conflict in conflicts {
            let mut args = vec![
                "list",
                "--snapshot-json",
                "--config",
                missing_config.as_ref(),
            ];
            args.extend_from_slice(conflict);
            let output = kickoutchi(&args);
            assert_eq!(
                output.status.code(),
                Some(2),
                "conflict {conflict:?} must be rejected by argument parsing; stderr: {}",
                stderr(&output)
            );
            assert_eq!(output.stdout, b"", "conflict {conflict:?} wrote stdout");
            assert!(
                !output.stderr.is_empty(),
                "conflict {conflict:?} omitted stderr"
            );
        }
    }

    #[test]
    fn untrusted_newlines_cannot_forge_diagnostic_lines() {
        let missing = temp_file_path("missing\nFORGED_CONFIG_LINE");
        let missing = missing.to_string_lossy();
        let config_error = kickoutchi(&["--config", missing.as_ref(), "list"]);
        assert_eq!(config_error.status.code(), Some(1));
        assert!(
            !stderr(&config_error)
                .lines()
                .any(|line| line == "FORGED_CONFIG_LINE")
        );

        let argument_error = kickoutchi(&["list", "--sort", "bad\nFORGED_ARG_LINE"]);
        assert_eq!(argument_error.status.code(), Some(2));
        assert!(
            !stderr(&argument_error)
                .lines()
                .any(|line| line == "FORGED_ARG_LINE")
        );
        assert!(argument_error.stdout.is_empty());
    }

    #[test]
    fn snapshot_json_is_available_from_kick_alias_and_list_help() {
        let help = kickoutchi(&["list", "--help"]);
        assert_eq!(help.status.code(), Some(0));
        assert!(
            stdout(&help).contains("--snapshot-json"),
            "{}",
            stdout(&help)
        );

        let snapshot = kick(&["list", "--snapshot-json"]);
        assert_eq!(snapshot.status.code(), Some(0), "{}", stderr(&snapshot));
        let value: serde_json::Value =
            serde_json::from_slice(&snapshot.stdout).expect("kick snapshot stdout must be JSON");
        assert_eq!(value["schema"], "kickoutchi.snapshot");
        assert_eq!(value["version"], 1);
    }

    #[test]
    fn snapshot_json_closed_stdout_is_success() {
        let output = run_list_with_closed_stdout(&["--snapshot-json"]);

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
    }

    #[test]
    fn snapshot_json_non_pipe_writer_failure_is_operational() {
        let output = run_list_with_full_stdout(&["--snapshot-json"]);

        assert_eq!(output.status.code(), Some(1));
        assert!(stderr(&output).contains("rendering snapshot JSON failed"));
    }

    #[test]
    fn exact_label_precedes_wildcard_through_search_filter_table_and_json() {
        let _host_observation = lock_host_observation();
        let (_helper, port, ready_file) = spawn_listener_process();
        let _ready_file = FileGuard(ready_file);
        let port_text = port.to_string();
        let config = format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"Wildcard Preview\"\n\n[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"Exact Web Dev\"\n"
        );
        let table = kickoutchi_with_config(
            &[
                "list",
                "--port",
                port_text.as_str(),
                "--filter",
                "exact web label:web dev",
            ],
            &config,
        );
        assert_eq!(table.status.code(), Some(0), "{}", stderr(&table));
        assert!(stdout(&table).lines().next().unwrap().ends_with("LABEL"));
        assert!(
            stdout(&table).contains("Exact Web Dev"),
            "{}",
            stdout(&table)
        );
        assert!(
            !stdout(&table).contains("Wildcard Preview"),
            "{}",
            stdout(&table)
        );

        let json = kickoutchi_with_config(
            &[
                "list",
                "--port",
                port_text.as_str(),
                "--filter",
                "label:exact web",
                "--json",
            ],
            &config,
        );
        assert_eq!(json.status.code(), Some(0), "{}", stderr(&json));
        let value: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["label"], "Exact Web Dev");
        assert!(!stdout(&json).contains("Wildcard Preview"));

        let unconfigured = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(
            unconfigured.status.code(),
            Some(0),
            "{}",
            stderr(&unconfigured)
        );
        assert!(
            !stdout(&unconfigured)
                .lines()
                .next()
                .unwrap()
                .contains("LABEL")
        );
    }

    #[test]
    fn list_rejects_watch_only_state_filter_as_invalid_arguments() {
        let output = kickoutchi(&["list", "--filter", "state:listen"]);

        assert_eq!(output.status.code(), Some(2));
        assert_eq!(stdout(&output), "");
        assert!(stderr(&output).contains("not supported by this command"));
    }

    #[test]
    fn why_reports_a_test_owned_tcp_listener_with_versioned_json() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
        let port = listener
            .local_addr()
            .expect("listener address is known")
            .port();
        let port_text = port.to_string();

        let output = why(&[
            port_text.as_str(),
            "--tcp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);

        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("why output must be JSON");
        assert_json_keys(
            &value,
            &[
                "schema",
                "version",
                "query",
                "capture",
                "scope",
                "completeness",
                "owner_completeness",
                "results",
                "aggregate_exit_code",
            ],
        );
        assert_eq!(value["schema"], "kickoutchi.why");
        assert_eq!(value["version"], 1);
        assert_eq!(value["aggregate_exit_code"], 3);
        assert_eq!(value["results"][0]["verdict"], "owned");
        assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
        assert!(
            value["results"][0]["evidence"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| {
                    item["code"] == "visible_verified_owner" && item["certainty"] == "proven"
                }))
        );
        assert!(!stdout(&output).contains("command_line"));
    }

    #[test]
    fn why_reports_real_permission_limited_owner_evidence() {
        let _host_observation = lock_host_observation();
        let (_helper, port, ready_file) = spawn_listener_process_with_metadata_access(false);
        let _ready_file = FileGuard(ready_file);
        let port_text = port.to_string();

        let output = why(&[
            port_text.as_str(),
            "--tcp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);

        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("why output must be JSON");
        assert_eq!(value["results"][0]["probe"]["outcome"], "address_in_use");
        assert_eq!(value["completeness"], "partial");
        assert_eq!(value["owner_completeness"], "partial");
        assert!(
            value["results"][0]["evidence_gaps"]
                .as_array()
                .is_some_and(|gaps| gaps.iter().any(|gap| {
                    gap["impact"] == "ownership"
                        && matches!(
                            gap["code"].as_str(),
                            Some("owner_permission_denied" | "owner_attribution_incomplete")
                        )
                }))
        );
    }

    #[test]
    fn why_reports_bindable_udp_and_releases_its_probe_socket() {
        let _host_observation = lock_host_observation();
        let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("temporary UDP socket must bind");
        let port = socket.local_addr().expect("socket address is known").port();
        drop(socket);
        let port_text = port.to_string();

        let output = kick_why(&[
            port_text.as_str(),
            "--udp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("why output must be JSON");
        assert_eq!(value["aggregate_exit_code"], 0);
        assert_eq!(value["results"][0]["verdict"], "bindable_now");
        let rebound = UdpSocket::bind(("127.0.0.1", port))
            .expect("why must close the exact probe socket before returning");
        drop(rebound);
    }

    #[test]
    fn why_reports_occupied_udp_in_human_output_and_bindable_tcp_in_json() {
        let _host_observation = lock_host_observation();
        let udp = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP fixture must bind");
        let udp_port = udp.local_addr().expect("UDP address is known").port();
        let udp_port_text = udp_port.to_string();
        let occupied = why(&[udp_port_text.as_str(), "--udp", "--address", "127.0.0.1"]);
        assert_eq!(occupied.status.code(), Some(3), "{}", stderr(&occupied));
        assert_eq!(stderr(&occupied), "");
        let occupied_stdout = stdout(&occupied);
        assert!(
            occupied_stdout.contains("probe=address_in_use"),
            "{occupied_stdout}"
        );
        assert!(
            (occupied_stdout.contains("verdict=owned")
                && occupied_stdout.contains("certainty=proven"))
                || (occupied_stdout.contains("verdict=reservation_or_policy_unknown")
                    && occupied_stdout.contains("certainty=unknown")),
            "{occupied_stdout}"
        );

        let tcp = TcpListener::bind(("127.0.0.1", 0)).expect("temporary TCP fixture must bind");
        let tcp_port = tcp.local_addr().expect("TCP address is known").port();
        drop(tcp);
        let tcp_port_text = tcp_port.to_string();
        let bindable = why(&[
            tcp_port_text.as_str(),
            "--tcp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);
        assert_eq!(bindable.status.code(), Some(0), "{}", stderr(&bindable));
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&bindable)).expect("why output must be JSON");
        assert_eq!(value["results"][0]["verdict"], "bindable_now");
        drop(
            TcpListener::bind(("127.0.0.1", tcp_port))
                .expect("why must release the successful TCP probe"),
        );
    }

    #[test]
    fn why_real_binary_preserves_aggregate_exit_when_stdout_has_no_reader() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
        let occupied_port = listener.local_addr().expect("TCP address is known").port();
        let occupied_port = occupied_port.to_string();
        let occupied = run_why_with_closed_stdout(&[
            occupied_port.as_str(),
            "--tcp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);
        assert_eq!(occupied.status.code(), Some(3));
        assert!(occupied.stderr.is_empty());

        let temporary = UdpSocket::bind(("127.0.0.1", 0)).expect("UDP fixture must bind");
        let bindable_port = temporary.local_addr().expect("UDP address is known").port();
        drop(temporary);
        let bindable_port = bindable_port.to_string();
        let bindable = run_why_with_closed_stdout(&[
            bindable_port.as_str(),
            "--udp",
            "--address",
            "127.0.0.1",
            "--json",
        ]);
        assert_eq!(bindable.status.code(), Some(0));
        assert!(bindable.stderr.is_empty());
    }

    #[test]
    fn why_real_binary_applies_full_aggregate_exit_precedence() {
        let _host_observation = lock_host_observation();
        let (_library_guard, library) = build_bind_fault_library();
        let temporary =
            TcpListener::bind(("127.0.0.1", 0)).expect("temporary aggregate fixture must bind");
        let port = temporary
            .local_addr()
            .expect("temporary aggregate address is known")
            .port();
        drop(temporary);
        let port = port.to_string();
        let args = [
            port.as_str(),
            "--all-protocols",
            "--all-addresses",
            "--json",
        ];

        let failure = why_with_bind_faults(&args, &library, "mixed");
        assert_eq!(failure.status.code(), Some(1), "{}", stderr(&failure));
        assert_eq!(stderr(&failure), "");
        let failure_json: serde_json::Value =
            serde_json::from_str(&stdout(&failure)).expect("why output must be JSON");
        let failure_verdicts = failure_json["results"]
            .as_array()
            .expect("results are an array")
            .iter()
            .filter_map(|result| result["verdict"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(failure_json["aggregate_exit_code"], 1);
        assert!(failure_verdicts.contains("indeterminate"));
        assert!(failure_verdicts.contains("permission_denied"));
        assert!(failure_verdicts.contains("reservation_or_policy_unknown"));
        assert!(failure_verdicts.contains("bindable_now"));

        let permission = why_with_bind_faults(&args, &library, "permission");
        assert_eq!(permission.status.code(), Some(4), "{}", stderr(&permission));
        assert_eq!(stderr(&permission), "");
        let permission_json: serde_json::Value =
            serde_json::from_str(&stdout(&permission)).expect("why output must be JSON");
        let permission_verdicts = permission_json["results"]
            .as_array()
            .expect("results are an array")
            .iter()
            .filter_map(|result| result["verdict"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(permission_json["aggregate_exit_code"], 4);
        assert!(permission_verdicts.contains("permission_denied"));
        assert!(permission_verdicts.contains("reservation_or_policy_unknown"));
        assert!(!permission_verdicts.contains("indeterminate"));
    }

    #[test]
    fn why_bare_query_emits_the_default_public_matrix() {
        let _host_observation = lock_host_observation();
        let (_library_guard, library) = build_bind_fault_library();
        let temporary =
            TcpListener::bind(("127.0.0.1", 0)).expect("temporary matrix port must bind");
        let port = temporary
            .local_addr()
            .expect("matrix address is known")
            .port();
        drop(temporary);
        let port = port.to_string();

        let output = why_with_bind_faults(&[port.as_str(), "--json"], &library, "unavailable");

        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let value: serde_json::Value =
            serde_json::from_str(&stdout(&output)).expect("bare why output must be JSON");
        assert_eq!(value["query"]["protocols"], serde_json::json!(["tcp"]));
        assert_eq!(
            value["query"]["addresses"],
            serde_json::json!(["127.0.0.1", "::1"])
        );
        assert_eq!(value["results"].as_array().map(Vec::len), Some(2));
        assert!(
            value["results"]
                .as_array()
                .is_some_and(|results| results.iter().all(|result| {
                    result["verdict"] == "address_unavailable"
                        && result["probe"]["outcome"] == "address_unavailable"
                }))
        );
        assert_eq!(value["aggregate_exit_code"], 3);
    }

    #[test]
    fn why_human_and_json_agree_for_unavailable_and_unsupported_probes() {
        let _host_observation = lock_host_observation();
        let (_library_guard, library) = build_bind_fault_library();
        let temporary =
            TcpListener::bind(("127.0.0.1", 0)).expect("temporary parity port must bind");
        let port = temporary
            .local_addr()
            .expect("parity address is known")
            .port();
        drop(temporary);
        let port = port.to_string();

        for (mode, expected) in [
            ("unavailable", "address_unavailable"),
            ("unsupported", "unsupported"),
        ] {
            let base = [port.as_str(), "--tcp", "--address", "127.0.0.1"];
            let human = why_with_bind_faults(&base, &library, mode);
            let mut json_args = base.to_vec();
            json_args.push("--json");
            let json = why_with_bind_faults(&json_args, &library, mode);

            assert_eq!(human.status.code(), Some(3), "{}", stderr(&human));
            assert_eq!(json.status.code(), Some(3), "{}", stderr(&json));
            assert_eq!(stderr(&human), "");
            assert_eq!(stderr(&json), "");
            let value: serde_json::Value =
                serde_json::from_str(&stdout(&json)).expect("why parity output must be JSON");
            assert_eq!(value["results"][0]["verdict"], expected);
            assert_eq!(value["results"][0]["probe"]["outcome"], expected);
            assert_eq!(value["aggregate_exit_code"], 3);
            let human = stdout(&human);
            assert!(human.contains(&format!("verdict={expected}")), "{human}");
            assert!(human.contains(&format!("probe={expected}")), "{human}");
            assert!(human.contains("aggregate_exit_code=3"), "{human}");
        }
    }

    #[test]
    fn why_applies_exact_and_wildcard_labels_and_rejects_invalid_scope_before_output() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
        let port = listener
            .local_addr()
            .expect("listener address is known")
            .port();
        let port_text = port.to_string();
        for (selector, label) in [
            ("127.0.0.1", "exact web fixture"),
            ("*", "wildcard web fixture"),
        ] {
            let config = format!(
                "[[ports]]\nprotocol = \"tcp\"\naddress = \"{selector}\"\nport = {port}\nlabel = \"{label}\"\n"
            );
            let labeled = why_with_config(
                &[port_text.as_str(), "--address", "127.0.0.1", "--json"],
                &config,
            );
            assert_eq!(labeled.status.code(), Some(3), "{}", stderr(&labeled));
            let value: serde_json::Value =
                serde_json::from_str(&stdout(&labeled)).expect("why output must be JSON");
            assert_eq!(value["results"][0]["label"], label);
        }

        let invalid = why(&[
            port_text.as_str(),
            "--address",
            "127.0.0.1",
            "--scope-id",
            "3",
        ]);
        assert_eq!(invalid.status.code(), Some(2));
        assert_eq!(stdout(&invalid), "");
        assert!(stderr(&invalid).contains("scope ID is valid only"));

        for invalid_args in [
            vec!["0", "--address", "127.0.0.1"],
            vec!["65536", "--address", "127.0.0.1"],
            vec!["3000", "--address", "fe80::1%3"],
            vec!["3000", "--address", "::1", "--scope-id", "0"],
        ] {
            let output = why(&invalid_args);
            assert_eq!(output.status.code(), Some(2), "{invalid_args:?}");
            assert_eq!(stdout(&output), "");
            assert!(!stderr(&output).is_empty());
        }
    }

    #[test]
    fn why_keeps_linux_ipv6_and_the_complete_expansion_explicit() {
        let _host_observation = lock_host_observation();
        let ipv6 = match TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)) {
            Ok(listener) => listener,
            Err(error) if !required_linux_capabilities() => {
                eprintln!("skipping IPv6 why contract because loopback is unavailable: {error}");
                return;
            }
            Err(error) => panic!("required IPv6 loopback is unavailable: {error}"),
        };
        let ipv6_port = ipv6.local_addr().expect("IPv6 address is known").port();
        let ipv6_port_text = ipv6_port.to_string();
        let ipv6_output = why(&[
            ipv6_port_text.as_str(),
            "--tcp",
            "--address",
            "::1",
            "--json",
        ]);
        assert_eq!(ipv6_output.status.code(), Some(3));
        let ipv6_value: serde_json::Value =
            serde_json::from_str(&stdout(&ipv6_output)).expect("IPv6 why output must be JSON");
        assert_eq!(ipv6_value["results"][0]["endpoint"]["address"], "::1");
        assert_eq!(
            ipv6_value["results"][0]["probe"]["outcome"],
            "address_in_use"
        );
        assert_eq!(
            ipv6_value["results"][0]["verdict"],
            "reservation_or_policy_unknown"
        );
        assert!(
            ipv6_value["results"][0]["evidence"]
                .as_array()
                .is_some_and(|items| items.iter().any(|item| {
                    item["code"] == "potential_scope_overlap" && item["certainty"] == "unknown"
                }))
        );

        let matrix_output = why(&[
            ipv6_port_text.as_str(),
            "--all-protocols",
            "--all-addresses",
            "--json",
        ]);
        assert_eq!(matrix_output.status.code(), Some(3));
        assert_eq!(stderr(&matrix_output), "");
        let matrix: serde_json::Value =
            serde_json::from_str(&stdout(&matrix_output)).expect("matrix output must be JSON");
        assert_eq!(matrix["results"].as_array().map(Vec::len), Some(8));
        assert_eq!(matrix["aggregate_exit_code"], 3);
        let verdicts = matrix["results"]
            .as_array()
            .expect("matrix results are an array")
            .iter()
            .filter_map(|result| result["verdict"].as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(verdicts.contains("bindable_now"));
        assert!(verdicts.iter().any(|verdict| *verdict != "bindable_now"));
        assert!(
            matrix["scope"]["limitations"]
                .as_array()
                .is_some_and(|limitations| limitations
                    .iter()
                    .any(|limitation| { limitation == "scoped_ipv6_exact_matching_unavailable" }))
        );
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "the real-binary schema contract asserts every field and nested shape"
    )]
    fn watch_emits_versioned_baseline_ndjson_and_exits_after_duration() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
        let port = listener.local_addr().expect("listener address").port();
        let port_text = port.to_string();

        let config = format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"127.0.0.1\"\nport = {port}\nlabel = \"watch fixture\"\n"
        );
        let output = kickoutchi_with_config_deadline(
            &[
                "watch",
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port_text,
                "--filter",
                "state:listen label:fixture",
                "--interval",
                "100ms",
                "--duration",
                "1s",
                "--json",
            ],
            &config,
        );

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert_eq!(stderr(&output), "");
        let records = stdout(&output)
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(!records.is_empty(), "{}", stdout(&output));
        assert!(
            records.iter().skip(1).enumerate().all(|(index, record)| {
                record["schema"] == "kickoutchi.watch_event"
                    && record["version"] == 1
                    && record["sequence"] == index + 1
                    && record["event"] == "collection_gap"
            }),
            "{}",
            stdout(&output)
        );
        assert_eq!(records[0]["schema"], "kickoutchi.watch_event");
        assert_eq!(records[0]["version"], 1);
        assert_eq!(records[0]["sequence"], 0);
        assert_eq!(records[0]["event"], "baseline");
        assert_eq!(
            records[0]["observation"]["previous_completed_unix_ms"],
            serde_json::Value::Null
        );
        assert_eq!(records[0]["data"]["endpoint"]["port"], port);
        assert_eq!(records[0]["data"]["state"]["kind"], "listen");
        assert_eq!(records[0]["data"]["label"], "watch fixture");
        assert_eq!(
            records[0]["data"]["previous_owners"],
            serde_json::Value::Null
        );
        assert_eq!(records[0]["data"]["filter_result"], "matched");
        assert_json_keys(
            &records[0],
            &[
                "schema",
                "version",
                "sequence",
                "event",
                "observation",
                "data",
            ],
        );
        assert_json_keys(
            &records[0]["observation"],
            &[
                "previous_completed_unix_ms",
                "attempt_started_unix_ms",
                "attempt_completed_unix_ms",
            ],
        );
        assert!(records[0]["observation"]["attempt_started_unix_ms"].is_u64());
        assert!(records[0]["observation"]["attempt_completed_unix_ms"].is_u64());
        assert_json_keys(
            &records[0]["data"],
            &[
                "endpoint",
                "state",
                "previous_owners",
                "current_owners",
                "previous_socket_token",
                "current_socket_token",
                "multiplicity",
                "label",
                "filter_result",
                "certainty",
                "evidence",
                "omitted_evidence_count",
                "evidence_gaps",
                "omitted_evidence_gap_count",
            ],
        );
        assert_json_keys(
            &records[0]["data"]["endpoint"],
            &["protocol", "address", "port", "ipv6_scope"],
        );
        assert!(matches!(
            records[0]["data"]["endpoint"]["protocol"].as_str(),
            Some("tcp" | "udp")
        ));
        assert!(records[0]["data"]["endpoint"]["address"].is_string());
        assert!(records[0]["data"]["endpoint"]["port"].is_u64());
        if !records[0]["data"]["endpoint"]["ipv6_scope"].is_null() {
            assert_json_keys(
                &records[0]["data"]["endpoint"]["ipv6_scope"],
                &["kind", "interface_index"],
            );
        }
        assert_json_keys(&records[0]["data"]["state"], &["kind", "native_code"]);
        assert!(records[0]["data"]["state"]["kind"].is_string());
        assert_json_keys(
            &records[0]["data"]["current_owners"],
            &["owners", "omitted_owner_count", "completeness", "reasons"],
        );
        let owners = records[0]["data"]["current_owners"]["owners"]
            .as_array()
            .expect("current owner set is an array");
        assert!(!owners.is_empty());
        for owner in owners {
            match owner["kind"].as_str() {
                Some("verified") => {
                    assert_json_keys(owner, &["kind", "identity"]);
                    assert_json_keys(&owner["identity"], &["pid", "start_marker"]);
                    assert!(owner["identity"]["pid"].is_u64());
                    let marker = &owner["identity"]["start_marker"];
                    match marker["kind"].as_str() {
                        Some("linux_start_ticks") => assert_json_keys(marker, &["kind", "ticks"]),
                        Some("macos_start_time") => {
                            assert_json_keys(marker, &["kind", "seconds", "microseconds"]);
                        }
                        Some("windows_creation_time") => {
                            assert_json_keys(marker, &["kind", "filetime_ticks"]);
                        }
                        other => panic!("unexpected process marker kind: {other:?}"),
                    }
                }
                Some("unverified_pid") => {
                    assert_json_keys(owner, &["kind", "pid", "reason"]);
                    assert!(owner["pid"].is_u64());
                    assert!(owner["reason"].is_string());
                }
                other => panic!("unexpected owner kind: {other:?}"),
            }
        }
        assert!(records[0]["data"]["current_owners"]["omitted_owner_count"].is_u64());
        assert!(matches!(
            records[0]["data"]["current_owners"]["completeness"].as_str(),
            Some("complete" | "partial" | "raced")
        ));
        assert!(records[0]["data"]["current_owners"]["reasons"].is_array());
        assert!(records[0]["data"]["previous_socket_token"].is_null());
        if !records[0]["data"]["current_socket_token"].is_null() {
            assert_json_keys(
                &records[0]["data"]["current_socket_token"],
                &["kind", "value"],
            );
            assert!(matches!(
                records[0]["data"]["current_socket_token"]["kind"].as_str(),
                Some("linux_inode" | "macos_socket_id")
            ));
            assert!(records[0]["data"]["current_socket_token"]["value"].is_u64());
        }
        assert!(records[0]["data"]["multiplicity"].is_u64());
        assert!(records[0]["data"]["label"].is_null() || records[0]["data"]["label"].is_string());
        assert!(matches!(
            records[0]["data"]["filter_result"].as_str(),
            Some("not_applied" | "matched" | "indeterminate")
        ));
        assert!(matches!(
            records[0]["data"]["certainty"].as_str(),
            Some("proven" | "estimated" | "heuristic" | "unknown")
        ));
        assert!(records[0]["data"]["evidence"].is_array());
        assert!(records[0]["data"]["omitted_evidence_count"].is_u64());
        assert!(records[0]["data"]["evidence_gaps"].is_array());
        assert!(records[0]["data"]["omitted_evidence_gap_count"].is_u64());
        assert!(!stdout(&output).contains("command_line"));
        drop(listener);
    }

    #[test]
    fn socket_lifecycle_helper_covers_protocol_family_bind_and_sharing_modes() {
        let _host_observation = lock_host_observation();
        let (_binary_guard, binary) = build_socket_lifecycle_helper();
        let mut modes = vec![
            (["tcp4", "exact", "default", "1"], "tcp", "127.0.0.1", 1),
            (["tcp4", "wildcard", "default", "2"], "tcp", "0.0.0.0", 2),
            (["udp4", "exact", "default", "1"], "udp", "127.0.0.1", 1),
            (["udp4", "wildcard", "default", "1"], "udp", "0.0.0.0", 1),
        ];
        let tcp6_supported = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok();
        let udp6_supported = UdpSocket::bind((std::net::Ipv6Addr::LOCALHOST, 0)).is_ok();
        let dual_tcp_supported = dual_stack_probe(socket2::Type::STREAM, socket2::Protocol::TCP);
        let dual_udp_supported = dual_stack_probe(socket2::Type::DGRAM, socket2::Protocol::UDP);
        if required_linux_capabilities() {
            assert!(tcp6_supported && udp6_supported && dual_tcp_supported && dual_udp_supported);
        }
        if tcp6_supported {
            modes.extend([
                (["tcp6", "exact", "v6only", "1"], "tcp", "::1", 1),
                (["tcp6", "wildcard", "v6only", "1"], "tcp", "::", 1),
            ]);
        }
        if dual_tcp_supported {
            modes.push((["tcp6", "wildcard", "dual", "1"], "tcp", "::", 1));
        }
        if udp6_supported {
            modes.extend([
                (["udp6", "exact", "v6only", "1"], "udp", "::1", 1),
                (["udp6", "wildcard", "v6only", "1"], "udp", "::", 1),
            ]);
        }
        if dual_udp_supported {
            modes.push((["udp6", "wildcard", "dual", "1"], "udp", "::", 1));
        }

        for (args, protocol, address, multiplicity) in modes {
            let (mut helper, port) = SocketLifecycle::spawn(&binary, &args);
            assert_ne!(port, 0, "mode {args:?} must use a dynamic port");
            let output = kickoutchi(&["list", "--snapshot-json"]);
            assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
            let snapshot: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
            let matching = snapshot["sockets"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|socket| {
                    socket["endpoint"]["protocol"] == protocol
                        && socket["endpoint"]["address"] == address
                        && socket["endpoint"]["port"] == port
                })
                .count();
            assert_eq!(matching, multiplicity, "mode {args:?}: {}", stdout(&output));

            if args[0] == "tcp6" {
                let ipv4 = TcpListener::bind(("0.0.0.0", port));
                assert_eq!(ipv4.is_ok(), args[2] == "v6only", "mode {args:?}");
            } else if args[0] == "udp6" {
                let ipv4 = UdpSocket::bind(("0.0.0.0", port));
                assert_eq!(ipv4.is_ok(), args[2] == "v6only", "mode {args:?}");
            }
            helper.command("CLOSE");
            helper.command("REBIND");
            helper.exit();
        }
    }

    fn dual_stack_probe(socket_type: socket2::Type, protocol: socket2::Protocol) -> bool {
        let Ok(socket) = socket2::Socket::new(socket2::Domain::IPV6, socket_type, Some(protocol))
        else {
            return false;
        };
        socket.set_only_v6(false).is_ok()
            && socket
                .bind(&std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)).into())
                .is_ok()
    }

    #[test]
    fn watch_wildcard_label_reaches_filtered_output() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
        let port = listener
            .local_addr()
            .expect("watch address is known")
            .port();
        let config = format!(
            "[[ports]]\nprotocol = \"tcp\"\naddress = \"*\"\nport = {port}\nlabel = \"wildcard watch fixture\"\n"
        );
        let config_dir = temp_file_path("wildcard-watch-config");
        fs::create_dir(&config_dir).expect("watch config directory must be created");
        let _config_guard = DirectoryGuard(config_dir.clone());
        let config_path = config_dir.join("config.toml");
        fs::write(&config_path, config).expect("watch config must be written");
        let child = Command::new(kickoutchi_binary())
            .arg("--config")
            .arg(&config_path)
            .args([
                "watch",
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--filter",
                "label:wildcard watch",
                "--interval",
                "100ms",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("wildcard watch process must start");
        let mut child = ChildGuard { child };
        let mut stdout = BufReader::new(
            child
                .child
                .stdout
                .take()
                .expect("wildcard watch stdout must be piped"),
        );
        let (sender, record) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let result = stdout.read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let record = record
            .recv_timeout(IPC_WAIT)
            .expect("wildcard watch baseline must arrive before its deadline")
            .expect("wildcard watch baseline must be readable");
        let record: serde_json::Value = serde_json::from_str(&record).unwrap();
        assert_eq!(record["event"], "baseline");
        assert_eq!(record["data"]["label"], "wildcard watch fixture");
        assert_eq!(record["data"]["filter_result"], "matched");

        let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
        assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
        let deadline = Instant::now() + KICK_EXIT_WAIT;
        let status = loop {
            if let Some(status) = child
                .child
                .try_wait()
                .expect("watch status must be readable")
            {
                break status;
            }
            assert!(Instant::now() < deadline, "wildcard watch did not exit");
            thread::yield_now();
        };
        reader.join().expect("wildcard watch reader must finish");
        let mut diagnostics = String::new();
        child
            .child
            .stderr
            .take()
            .expect("wildcard watch stderr must be piped")
            .read_to_string(&mut diagnostics)
            .expect("wildcard watch stderr must be readable");
        assert_eq!(status.code(), Some(0), "{diagnostics}");
        assert!(diagnostics.is_empty(), "{diagnostics}");
    }

    #[test]
    fn socket_lifecycle_drop_forces_process_and_reader_cleanup() {
        let (_binary_guard, binary) = build_socket_lifecycle_helper();
        let pid = {
            let (helper, _port) =
                SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
            helper.id()
        };
        assert!(!pid_exists(pid), "dropped helper process must be reaped");
    }

    #[test]
    fn reader_panic_is_joined_and_reported() {
        let (done_sender, reader_done) = mpsc::channel();
        let mut reader = Some(thread::spawn(move || {
            drop(done_sender);
            panic!("injected reader panic");
        }));

        let error = finish_reader_thread(&mut reader, &reader_done, Instant::now() + IPC_WAIT)
            .expect_err("reader panic must be reported");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("reader panicked"));
        assert!(reader.is_none(), "panicked reader must still be joined");
    }

    #[test]
    fn deep_chain_drop_terminates_every_owned_process() {
        let pids = {
            let helper = spawn_deep_chain_process(4);
            helper.pids.clone()
        };
        for pid in pids {
            assert!(!pid_exists(pid), "dropped deep-chain PID {pid} must exit");
        }
    }

    #[test]
    fn socket_lifecycle_helper_hands_an_endpoint_to_a_replacement_process() {
        let _host_observation = lock_host_observation();
        let (_binary_guard, binary) = build_socket_lifecycle_helper();
        let (mut original, port) =
            SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
        let original_pid = original.id();
        original.command("CLOSE");
        let port_text = port.to_string();
        let (mut replacement, replacement_port) = SocketLifecycle::spawn(
            &binary,
            &["tcp4", "exact", "default", "1", port_text.as_str()],
        );
        assert_eq!(replacement_port, port);
        assert_ne!(replacement.id(), original_pid);

        let output = kickoutchi(&["list", "--snapshot-json"]);
        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        let snapshot: serde_json::Value = serde_json::from_str(&stdout(&output)).unwrap();
        let socket = snapshot["sockets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|socket| {
                socket["endpoint"]["protocol"] == "tcp"
                    && socket["endpoint"]["address"] == "127.0.0.1"
                    && socket["endpoint"]["port"] == port
            })
            .expect("replacement endpoint must be observed");
        let owner_pids = socket["owners"]["owners"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|owner| owner["identity"]["pid"].as_u64())
            .collect::<Vec<_>>();
        assert_eq!(owner_pids, [u64::from(replacement.id())]);
        assert!(!owner_pids.contains(&u64::from(original_pid)));

        original.exit();
        replacement.exit();
    }

    #[test]
    fn watch_real_binary_observes_baseline_release_and_bind() {
        let _host_observation = lock_host_observation();
        let (_binary_guard, binary) = build_socket_lifecycle_helper();
        let (mut helper, port) =
            SocketLifecycle::spawn(&binary, &["tcp4", "exact", "default", "1"]);
        let config_home = isolated_config_home();
        let _config_guard = DirectoryGuard(config_home.clone());
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .args([
                "watch",
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--interval",
                "100ms",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("watch process must start");
        let mut child = ChildGuard { child };
        let stdout = child
            .child
            .stdout
            .take()
            .expect("watch stdout must be piped");
        let (sender, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let receive_event = |expected: &str| {
            let line = lines
                .recv_timeout(IPC_WAIT)
                .expect("watch event must arrive before its deadline")
                .expect("watch event must be readable");
            let value: serde_json::Value =
                serde_json::from_str(&line).expect("watch event must be JSON");
            assert_eq!(value["event"], expected, "{line}");
            assert_eq!(value["data"]["endpoint"]["port"], port, "{line}");
        };

        receive_event("baseline");
        helper.command("CLOSE");
        receive_event("release");
        helper.command("REBIND");
        receive_event("bind");

        let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
        assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
        let deadline = Instant::now() + KICK_EXIT_WAIT;
        let status = loop {
            if let Some(status) = child
                .child
                .try_wait()
                .expect("watch status must be readable")
            {
                break status;
            }
            assert!(Instant::now() < deadline, "watch did not exit after SIGINT");
            thread::yield_now();
        };
        reader.join().expect("watch stdout reader must finish");
        let mut diagnostics = String::new();
        child
            .child
            .stderr
            .take()
            .expect("watch stderr must be piped")
            .read_to_string(&mut diagnostics)
            .expect("watch stderr must be readable");
        assert_eq!(status.code(), Some(0), "{diagnostics}");
        assert!(diagnostics.is_empty(), "{diagnostics}");
        helper.exit();
    }

    #[test]
    fn watch_real_binary_recovers_after_one_native_collection_failure() {
        let _host_observation = lock_host_observation();
        let (_library_guard, library) = build_collect_fault_library();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
        let port = listener
            .local_addr()
            .expect("watch address is known")
            .port();
        let config_home = isolated_config_home();
        let _config_guard = DirectoryGuard(config_home.clone());
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .env("LD_PRELOAD", &library)
            .args([
                "watch",
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--interval",
                "100ms",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("watch recovery process must start");
        let mut child = ChildGuard { child };
        let stdout = child
            .child
            .stdout
            .take()
            .expect("watch recovery stdout must be piped");
        let (sender, lines) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let baseline = lines
            .recv_timeout(IPC_WAIT)
            .expect("watch must emit a baseline before its deadline")
            .expect("baseline must be readable");
        let baseline: serde_json::Value = serde_json::from_str(&baseline).unwrap();
        assert_eq!(baseline["event"], "baseline");
        assert_eq!(baseline["data"]["endpoint"]["port"], port);

        let platform_pid = libc::pid_t::try_from(child.id()).expect("watch PID must fit pid_t");
        assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGUSR2) }, 0);
        let gap = lines
            .recv_timeout(IPC_WAIT)
            .expect("watch must emit the armed collection gap before its deadline")
            .expect("collection gap must be readable");
        let gap: serde_json::Value = serde_json::from_str(&gap).unwrap();
        assert_eq!(gap["event"], "collection_gap");
        assert_eq!(gap["data"]["consecutive_failures"], 1);
        assert_eq!(gap["data"]["certainty"], "unknown");
        assert!(
            matches!(
                lines.recv_timeout(IPC_WAIT),
                Err(mpsc::RecvTimeoutError::Disconnected)
            ),
            "recovery must close stdout without fabricating an event"
        );
        reader.join().expect("watch recovery reader must finish");
        let deadline = Instant::now() + KICK_EXIT_WAIT;
        let status = loop {
            if let Some(status) = child
                .child
                .try_wait()
                .expect("watch recovery status must be readable")
            {
                break status;
            }
            assert!(Instant::now() < deadline, "recovered watch did not exit");
            thread::yield_now();
        };
        let mut diagnostics = String::new();
        child
            .child
            .stderr
            .take()
            .expect("watch recovery stderr must be piped")
            .read_to_string(&mut diagnostics)
            .expect("watch recovery stderr must be readable");
        assert_eq!(status.code(), Some(0), "{diagnostics}");
        assert!(diagnostics.is_empty(), "{diagnostics}");
    }

    #[test]
    fn watch_closed_stdout_is_success() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("watch fixture must bind");
        let port = listener
            .local_addr()
            .expect("watch address is known")
            .port();

        let output = run_subcommand_with_closed_stdout(
            "watch",
            &[
                "--tcp",
                "--address",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--json",
            ],
        );

        assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
    }

    #[test]
    fn watch_rejects_invalid_arguments_before_collection() {
        for args in [
            vec!["watch", "--interval", "99ms"],
            vec!["watch", "--duration", "7d1s"],
            vec!["watch", "--scope-id", "1"],
            vec!["watch", "--port", "0"],
            vec!["watch", "--filter", "state:not-a-state"],
        ] {
            let output = kickoutchi(&args);
            assert_eq!(output.status.code(), Some(2), "{args:?}");
            assert_eq!(stdout(&output), "", "{args:?}");
            assert!(stderr(&output).contains("error:"), "{args:?}");
        }
    }

    #[test]
    fn watch_ctrl_c_after_baseline_exits_successfully() {
        let _host_observation = lock_host_observation();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener must bind");
        let port = listener.local_addr().expect("listener address").port();
        let config_home = isolated_config_home();
        let config_guard = DirectoryGuard(config_home.clone());
        let child = Command::new(kickoutchi_binary())
            .env("XDG_CONFIG_HOME", &config_home)
            .args([
                "watch",
                "--port",
                &port.to_string(),
                "--interval",
                "100ms",
                "--json",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("watch process must start");
        let mut child = ChildGuard { child };
        let pid = child.id();
        let stdout = child
            .child
            .stdout
            .take()
            .expect("watch stdout must be piped");
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = ready_tx.send(result);
        });
        let baseline = ready_rx
            .recv_timeout(KICK_EXIT_WAIT)
            .expect("watch must emit a bounded baseline")
            .expect("watch baseline must be readable");
        let value: serde_json::Value = serde_json::from_str(&baseline).expect("baseline is JSON");
        assert_eq!(value["event"], "baseline");

        let platform_pid = libc::pid_t::try_from(pid).expect("child PID must fit pid_t");
        // SAFETY: the PID belongs to this test's child and SIGINT is the behavior under test.
        assert_eq!(unsafe { libc::kill(platform_pid, libc::SIGINT) }, 0);
        let deadline = Instant::now() + KICK_EXIT_WAIT;
        let status = loop {
            if let Some(status) = child
                .child
                .try_wait()
                .expect("watch exit status must be readable")
            {
                break status;
            }
            assert!(Instant::now() < deadline, "watch did not exit after SIGINT");
            thread::sleep(Duration::from_millis(10));
        };
        reader.join().expect("watch stdout reader must finish");
        assert_eq!(status.code(), Some(0));
        drop(config_guard);
        drop(listener);
    }

    #[test]
    fn udp_ipv6_socket_is_listed_through_the_real_binary() {
        let _host_observation = lock_host_observation();
        let socket = match UdpSocket::bind("[::1]:0") {
            Ok(socket) => socket,
            Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                assert!(
                    !required_linux_capabilities(),
                    "required IPv6 loopback capability is unavailable: {error}"
                );
                eprintln!("IPv6 loopback unavailable: {error}");
                return;
            }
            Err(error) => panic!("IPv6 UDP socket must bind on loopback: {error}"),
        };
        let port = socket
            .local_addr()
            .expect("UDP socket must have a local address")
            .port();
        let port_text = port.to_string();

        let output = kickoutchi(&["list", "--port", port_text.as_str()]);

        assert_eq!(output.status.code(), Some(0));
        let out = stdout(&output);
        assert!(out.contains("UDP"), "{out}");
        assert!(out.contains("::1"), "{out}");
        assert!(out.contains(port_text.as_str()), "{out}");
        assert!(stdout_table_has_pid(&output, std::process::id()), "{out}");
    }

    #[test]
    fn configured_protected_process_refuses_yes_kill_with_exit_6() {
        let _host_observation = lock_host_observation();
        let (mut helper, _port, ready_file) = spawn_listener_process();
        let pid = helper.id();
        let pid_text = pid.to_string();
        let process_name = fs::read_to_string(format!("/proc/{pid}/comm"))
            .expect("helper process comm must be readable")
            .trim_end()
            .to_owned();
        let config = format!(
            "protected_processes = [\"{}\"]\n",
            toml_string(&process_name),
        );

        let output =
            kickoutchi_with_config(&["kill", "--pid", pid_text.as_str(), "--yes"], &config);

        assert_eq!(output.status.code(), Some(6));
        assert!(stderr(&output).contains("protected"));
        assert!(
            helper
                .child
                .try_wait()
                .expect("helper status must be readable")
                .is_none(),
            "protected helper must still be running",
        );
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn overlong_confirmation_cannot_be_truncated_into_force() {
        let _host_observation = lock_host_observation();
        let (mut helper, _port, ready_file) = spawn_listener_process();
        let pid_text = helper.id().to_string();
        let input = format!("force{}\n", " ".repeat(1024));

        let output =
            kickoutchi_with_stdin(&["kill", "--pid", pid_text.as_str(), "--force"], &input);

        assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
        assert!(
            stderr(&output).contains("confirmation input exceeds"),
            "{}",
            stderr(&output),
        );
        assert!(
            helper
                .child
                .try_wait()
                .expect("helper status must be readable")
                .is_none(),
            "overlong confirmation must not terminate the helper",
        );
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn kill_pid_yes_sends_real_sigterm_and_port_disappears() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout_table_has_pid(&before, helper.id()));

        let killed = kickoutchi(&["kill", "--pid", pid_text.as_str(), "--yes"]);
        let killed_stderr = stderr(&killed);
        assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
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
    fn host_port_kill_sends_real_sigterm() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();

        let killed = kickoutchi(&["kill", "--port", port_text.as_str(), "--yes"]);
        let killed_stderr = stderr(&killed);
        assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
        assert!(killed_stderr.contains("sent SIGTERM"), "{killed_stderr}");
        wait_for_child_exit(&mut helper);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn isolated_user_and_network_namespace_port_kill_delivers_sigterm() {
        let test_binary = std::env::current_exe().expect("test binary path resolves");
        let ready_file = temp_file_path("namespace-listener-ready");
        let script = r#"KICKOUTCHI_TEST_HELPER_LISTENER=1 KICKOUTCHI_TEST_HELPER_BIND_ANY=1 KICKOUTCHI_TEST_HELPER_PORT=0 KICKOUTCHI_TEST_HELPER_READY="$3" "$1" --exact linux::helper_tcp_listener_process --ignored --nocapture & helper=$!; i=0; while test ! -s "$3"; do i=$((i+1)); test "$i" -lt 10000 || exit 90; done; port=$(cat "$3"); XDG_CONFIG_HOME="$3-config" "$2" kill --port "$port" --yes; kick_status=$?; if test "$kick_status" -ne 0; then kill "$helper"; wait "$helper"; exit "$kick_status"; fi; wait "$helper"; helper_status=$?; rm -f "$3"; test "$helper_status" -eq 143"#;
        let output = run_command_with_deadline(
            Command::new("unshare")
                .args([
                    "--user",
                    "--map-root-user",
                    "--net",
                    "--pid",
                    "--fork",
                    "--mount-proc",
                    "sh",
                    "-c",
                    script,
                    "sh",
                ])
                .arg(test_binary)
                .arg(kickoutchi_binary())
                .arg(&ready_file),
            None,
            CHILD_EXIT_WAIT,
        );
        let output = match output {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                assert!(
                    !required_linux_capabilities(),
                    "required unshare capability is unavailable: {error}"
                );
                eprintln!("unshare unavailable: {error}");
                return;
            }
            Err(error) => panic!("unshare must start: {error}"),
        };
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success()
            && (stderr.contains("Operation not permitted")
                || stderr.contains("Permission denied")
                || stderr.contains("unshare failed"))
        {
            assert!(
                !required_linux_capabilities(),
                "required user/network namespaces are unavailable: {stderr}"
            );
            eprintln!("user/network namespaces unavailable: {stderr}");
            return;
        }
        assert!(output.status.success(), "{stderr}");
        assert!(stderr.contains("sent SIGTERM"), "{stderr}");
    }

    #[test]
    fn tree_kill_by_port_removes_root_and_child_and_clears_port() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
        let _host_observation = lock_host_observation();
        let (helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
    fn tree_kill_by_pid_terminates_previously_stopped_child() {
        let _host_observation = lock_host_observation();
        let (mut helper, _port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let root_pid_text = helper.id().to_string();
        stop_pid(child_pid);
        wait_for_pid_state(child_pid, 'T');

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
            "tree\n",
        );

        assert_eq!(killed.status.code(), Some(0), "{}", stderr(&killed));
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn tree_kill_by_pid_force_uses_sigkill_wording() {
        let _host_observation = lock_host_observation();
        let (mut helper, _port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let root_pid_text = helper.id().to_string();

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree", "--force"],
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
        let _host_observation = lock_host_observation();
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(
            stdout_table_has_pid(&before, child_pid),
            "{}",
            stdout(&before)
        );
        assert!(
            !stdout_table_has_pid(&before, helper.id()),
            "{}",
            stdout(&before)
        );

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
        let _host_observation = lock_host_observation();
        let mut helper = spawn_deep_chain_process(DEEP_CHAIN_DEPTH);
        let root_pid_text = helper.root_id().to_string();

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
        helper.wait_for_all_gone();
    }

    #[test]
    fn tree_kill_converges_on_active_spawner_and_clears_group() {
        let _host_observation = lock_host_observation();
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
        let _host_observation = lock_host_observation();
        let (mut helper, first_child_pid, ready_file) = spawn_fork_on_trigger_process();
        let _first_child_cleanup = PidGuard::new(first_child_pid);
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
        let _late_cleanup = PidGuard::new(late_pid);

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
    fn group_kill_by_port_reaches_reparented_member_and_clears_port() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, orphan_pid, ready_file) = spawn_group_process();
        let _orphan_cleanup = PidGuard::new(orphan_pid);
        let root_pid = helper.id();
        let port_text = port.to_string();

        // Prove the premise: the orphan is alive but no longer our helper's
        // child, so it is invisible to a parent-link walk from the root.
        let orphan_parent = read_ppid(orphan_pid);
        assert_ne!(orphan_parent, root_pid, "orphan must have reparented");

        let killed = kickoutchi_with_stdin(
            &["kill", "--port", port_text.as_str(), "--group"],
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
            .args([
                "--exact",
                "linux::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
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
        let _host_observation = lock_host_observation();
        let (helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
    fn inspect_closed_stdout_is_success() {
        let _host_observation = lock_host_observation();
        let (helper, port, ready_file) = spawn_listener_process();
        let _ready_file = FileGuard(ready_file);

        let output =
            run_subcommand_with_closed_stdout("inspect", &["--port", port.to_string().as_str()]);

        assert_eq!(output.status.code(), Some(0));
        assert!(output.stderr.is_empty(), "{}", stderr(&output));
        assert!(pid_exists(helper.id()), "inspect must remain read-only");
    }

    #[test]
    fn short_kick_binary_matches_canonical_help_and_version() {
        let _host_observation = lock_host_observation();
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
    use super::{REAL_BINARY_EXIT_WAIT, kickoutchi_binary, run_command_with_deadline};
    use std::fs;
    use std::net::TcpListener;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
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
    /// How long a parked helper may outlive its test before self-destructing.
    const HELPER_PARK_MAX: Duration = Duration::from_mins(5);
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
        matches!(wait, WAIT_TIMEOUT) || !matches!(wait, WAIT_OBJECT_0)
    }

    fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).into_owned()
    }

    fn stdout_table_has_pid(output: &Output, pid: u32) -> bool {
        let pid_text = pid.to_string();
        stdout(output)
            .lines()
            .skip(1)
            .any(|line| line.split_whitespace().nth(3) == Some(pid_text.as_str()))
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
    #[ignore = "subprocess fixture; invoked explicitly by contract tests"]
    fn helper_process_tree() {
        let Some(mode) = std::env::var_os(HELPER_TREE_ENV) else {
            return;
        };
        let mode = mode.to_string_lossy();
        let ready_file = PathBuf::from(
            std::env::var_os(HELPER_READY_ENV).expect("helper ready path must be set"),
        );

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
                let listener = TcpListener::bind(("127.0.0.1", 0))
                    .expect("root tree helper listener must bind");
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

    #[test]
    fn windows_interactive_normal_kill_accepts_y_and_port_disappears() {
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout_table_has_pid(&before, helper.id()));

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

    #[test]
    fn windows_inspect_shows_family_read_only_with_kill_hint() {
        let (helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
        assert!(out.contains("Windows note"), "{out}");
        assert!(out.contains("WSL2 note"), "{out}");
        assert!(!out.contains("Process group"), "{out}");
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
        assert!(pid_exists(child_pid), "inspect must not signal anything");

        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn windows_tree_kill_by_port_removes_root_and_child() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
        assert!(
            killed_stderr.contains("Windows Job Object"),
            "{killed_stderr}",
        );
        assert!(
            killed_stderr.contains("newly spawned job-contained children"),
            "{killed_stderr}",
        );
        wait_for_child_exit(&mut helper);
        wait_for_pid_gone(child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
    }

    #[test]
    fn windows_tree_kill_removes_child_spawned_after_job_assignment() {
        let (mut helper, port, late_file, ready_file) = spawn_late_spawner_tree();
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
        wait_for_child_exit(&mut helper);
        wait_for_file(&late_file);
        let late = fs::read_to_string(&late_file).expect("late child record must be readable");
        let mut parts = late.split_whitespace();
        let late_child_pid = parts
            .next()
            .expect("late child record must include pid")
            .parse::<u32>()
            .expect("late child pid must be a u32");
        let _late_child_cleanup = PidGuard::new(late_child_pid);
        let inherited_job = parts
            .next()
            .expect("late child record must include job inheritance")
            .parse::<bool>()
            .expect("job inheritance marker must be a bool");
        assert!(inherited_job, "late child did not inherit the root job");
        wait_for_pid_gone(late_child_pid);

        let after = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(after.status.code(), Some(3));
        let _ = fs::remove_file(ready_file);
        let _ = fs::remove_file(late_file);
    }

    #[test]
    fn windows_tree_kill_by_pid_allows_portless_parent_when_child_owns_port() {
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout_table_has_pid(&before, child_pid));
        assert!(!stdout_table_has_pid(&before, helper.id()));

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
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{REAL_BINARY_EXIT_WAIT, kickoutchi_binary, run_command_with_deadline};
    use std::fs;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Output, Stdio};
    use std::sync::Mutex;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const HELPER_LISTENER_ENV: &str = "KICKOUTCHI_TEST_HELPER_LISTENER";
    const HELPER_TREE_ENV: &str = "KICKOUTCHI_TEST_HELPER_TREE";
    const HELPER_PORT_ENV: &str = "KICKOUTCHI_TEST_HELPER_PORT";
    const HELPER_READY_ENV: &str = "KICKOUTCHI_TEST_HELPER_READY";
    const CHILD_EXIT_WAIT: Duration = Duration::from_secs(10);
    const HELPER_READY_WAIT: Duration = Duration::from_secs(5);
    /// How long a parked helper may outlive its test before self-destructing.
    const HELPER_PARK_MAX: Duration = Duration::from_mins(5);
    static HOST_OBSERVATION_LOCK: Mutex<()> = Mutex::new(());

    pub(super) fn lock_host_observation() -> std::sync::MutexGuard<'static, ()> {
        HOST_OBSERVATION_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

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
        start_time: (u64, u64),
    }

    impl PidGuard {
        fn new(pid: u32) -> Self {
            let start_time =
                process_start_time(pid).expect("test helper identity must be readable");
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

    fn stdout_table_has_pid(output: &Output, pid: u32) -> bool {
        let pid_text = pid.to_string();
        stdout(output)
            .lines()
            .skip(1)
            .any(|line| line.split_whitespace().nth(3) == Some(pid_text.as_str()))
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
    #[ignore = "subprocess fixture; invoked explicitly by contract tests"]
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

    /// The scenario group scope exists for: a member that double-forked away
    /// from the tree but kept the group. See the Linux twin for the full
    /// premise; macOS has no `/proc`, so the reparenting itself is not
    /// asserted here — the sweep reaching a non-descendant is.
    #[test]
    fn macos_group_kill_reaches_reparented_member_a_tree_walk_cannot() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, orphan_pid, ready_file) = spawn_tree_process_in_group();
        let _orphan_cleanup = PidGuard::new(orphan_pid);
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
            .args([
                "--exact",
                "macos::helper_process_tree",
                "--ignored",
                "--nocapture",
            ])
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
    fn macos_tree_kill_by_pid_removes_root_owned_port_and_child() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("root-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(root_pid_text.as_str()));

        let killed = kickoutchi_with_stdin(
            &["kill", "--pid", root_pid_text.as_str(), "--tree"],
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
        let _host_observation = lock_host_observation();
        let (mut helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
        let port_text = port.to_string();
        let root_pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout_table_has_pid(&before, child_pid));
        assert!(!stdout_table_has_pid(&before, helper.id()));

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
        let _host_observation = lock_host_observation();
        let (helper, port, child_pid, ready_file) = spawn_tree_process("child-owns-port");
        let _child_cleanup = PidGuard::new(child_pid);
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
    fn macos_interactive_normal_kill_accepts_y_or_refuses_a_raced_observation() {
        let _host_observation = lock_host_observation();
        let (mut helper, port, ready_file) = spawn_listener_process();
        let port_text = port.to_string();
        let pid_text = helper.id().to_string();

        let before = kickoutchi(&["list", "--port", port_text.as_str()]);
        assert_eq!(before.status.code(), Some(0));
        assert!(stdout(&before).contains(port_text.as_str()));
        assert!(stdout_table_has_pid(&before, helper.id()));

        let killed = kickoutchi_with_stdin(&["kill", "--pid", pid_text.as_str()], Some("y\n"));
        let killed_stderr = stderr(&killed);
        if killed.status.code() == Some(1) {
            assert!(
                killed_stderr == "error: collecting ports failed: observation raced\n"
                    || killed_stderr
                        .contains("collecting ports before kill failed: observation raced"),
                "{killed_stderr}",
            );
            assert!(
                pid_exists(helper.id()),
                "a raced observation must fail before signaling the fixture"
            );
            let _ = fs::remove_file(ready_file);
            return;
        }
        assert_eq!(killed.status.code(), Some(0), "{killed_stderr}");
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
