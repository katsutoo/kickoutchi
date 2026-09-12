use std::io::{self, Read, Write};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

pub(crate) const COMMAND_OUTPUT_BYTES_MAX: u64 = 8 * 1024 * 1024;

pub(crate) struct CommandChild(pub(crate) Option<Child>);

impl CommandChild {
    pub(crate) fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("command child must be owned")
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
