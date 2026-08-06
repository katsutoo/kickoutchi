use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const REAL_BINARY_EXIT_WAIT: Duration = Duration::from_secs(10);
pub(crate) const COMMAND_OUTPUT_BYTES_MAX: u64 = 8 * 1024 * 1024;
pub(crate) const COMMAND_RUNNER_HELPER_ENV: &str = "KICKOUTCHI_TEST_COMMAND_RUNNER_HELPER";
pub(crate) const BINARY_OVERRIDE_HELPER_ENV: &str = "KICKOUTCHI_TEST_BINARY_OVERRIDE_HELPER";
pub(crate) const TRACING_HELPER_ENV: &str = "KICKOUTCHI_TEST_TRACING_HELPER";
pub(crate) const RELEASE_E2E_REQUIRED_ENV: &str = "KICKOUTCHI_RELEASE_E2E_REQUIRED";
pub(crate) const KICKOUTCHI_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICKOUTCHI";
pub(crate) const KICK_BINARY_ENV: &str = "KICKOUTCHI_E2E_KICK";
static UNIQUE_TEMP_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn create_unique_temp_directory(label: &str) -> PathBuf {
    for _ in 0..u16::MAX {
        let counter = UNIQUE_TEMP_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "kickoutchi-cli-contract-{label}-{}-{counter}",
            std::process::id(),
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("isolated temporary directory must be created: {error}"),
        }
    }
    panic!("isolated temporary directory collision limit exceeded");
}

pub(crate) struct TemporaryDirectory(PathBuf);

impl TemporaryDirectory {
    pub(crate) fn new(label: &str) -> Self {
        Self(create_unique_temp_directory(label))
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(any(target_os = "macos", windows))]
pub(crate) struct TemporaryConfigFile {
    _directory: TemporaryDirectory,
    path: PathBuf,
}

#[cfg(any(target_os = "macos", windows))]
impl TemporaryConfigFile {
    pub(crate) fn new(label: &str, contents: &str) -> Self {
        let directory = TemporaryDirectory::new(label);
        let path = directory.path().join("config.toml");
        fs::write(&path, contents).expect("isolated config must be written");
        Self {
            _directory: directory,
            path,
        }
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

pub(crate) fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub(crate) fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub(crate) fn stdout_table_has_pid(output: &Output, pid: u32) -> bool {
    let pid_text = pid.to_string();
    stdout(output)
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(3) == Some(pid_text.as_str()))
}

/// How long a parked helper may outlive its test before self-destructing.
/// Generous enough for the slowest passing run; short enough that a
/// killed-by-`SIGKILL` test binary can never leak an immortal helper.
pub(crate) const HELPER_PARK_MAX: Duration = Duration::from_mins(5);

/// Park a helper process for the remainder of its useful life, then exit.
/// Bounded so helpers are self-terminating: even when the test binary that
/// spawned them is killed by `SIGKILL` and never runs cleanup, the park is the
/// helper's own self-destruct timer.
pub(crate) fn park_bounded() -> ! {
    let deadline = Instant::now() + HELPER_PARK_MAX;
    while Instant::now() < deadline {
        thread::sleep(Duration::from_secs(1));
    }
    std::process::exit(0)
}

/// Serialize tests that observe host process and socket state (process
/// tables, listening sockets) so parallel tests cannot race each other.
static HOST_OBSERVATION_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn lock_host_observation() -> std::sync::MutexGuard<'static, ()> {
    HOST_OBSERVATION_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn product_binary(variable: &str, fallback: &str) -> OsString {
    let required = std::env::var_os(RELEASE_E2E_REQUIRED_ENV).is_some();
    match (required, std::env::var_os(variable)) {
        (true, Some(path)) => path,
        (true, None) => panic!("release E2E requires {variable}"),
        (false, None) => OsString::from(fallback),
        (false, Some(_)) => panic!("{variable} requires {RELEASE_E2E_REQUIRED_ENV}"),
    }
}

pub(crate) fn kickoutchi_binary() -> OsString {
    product_binary(KICKOUTCHI_BINARY_ENV, env!("CARGO_BIN_EXE_kickoutchi"))
}

pub(crate) fn kick_binary() -> OsString {
    product_binary(KICK_BINARY_ENV, env!("CARGO_BIN_EXE_kick"))
}

pub(crate) struct CommandChild(pub(crate) Option<Child>);

impl CommandChild {
    pub(crate) fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("command child must be owned")
    }

    #[cfg(any(target_os = "macos", windows))]
    pub(crate) fn wait_until(&mut self, deadline: Instant) -> io::Result<ExitStatus> {
        loop {
            match self.child_mut().try_wait()? {
                Some(status) => return Ok(status),
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                None => return Err(io::Error::new(io::ErrorKind::TimedOut, "command deadline")),
            }
        }
    }

    pub(crate) fn kill_and_reap(&mut self, deadline: Instant) -> io::Result<()> {
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

    pub(crate) fn disarm(&mut self) {
        drop(self.0.take());
    }
}

impl Drop for CommandChild {
    fn drop(&mut self) {
        let _ = self.kill_and_reap(Instant::now() + Duration::from_secs(1));
    }
}

pub(crate) fn pipe_reader(pipe: impl Read + Send + 'static) -> mpsc::Receiver<io::Result<Vec<u8>>> {
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

pub(crate) fn finish_pipe(
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

pub(crate) fn collect_child_output(
    child: Child,
    stdin: Option<&[u8]>,
    wait: Duration,
) -> io::Result<Output> {
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

pub(crate) fn run_command_with_deadline(
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
