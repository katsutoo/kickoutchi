//! Bounded child-process protocol for checking private Job Object freeze behavior.
//!
//! The helper is the current Kickoutchi executable in an internal mode. A
//! disposable Job Object contains only that helper, so a failed probe cannot
//! affect the user's selected process.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::WaitForSingleObject;

const PROBE_ENVIRONMENT: &str = "KICKOUTCHI_INTERNAL_WINDOWS_FREEZE_PROBE";
const PROBE_VERSION: &str = "v1";
const READY: u8 = b'R';
const PING: u8 = b'P';
const ACKNOWLEDGED: u8 = b'A';
const EXIT: u8 = b'X';
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
const SUSPENSION_OBSERVATION_TIMEOUT: Duration = Duration::from_millis(250);
const CHILD_EXIT_TIMEOUT_MS: u32 = 5_000;

pub(crate) fn requested() -> bool {
    std::env::var_os(PROBE_ENVIRONMENT).as_deref() == Some(OsStr::new(PROBE_VERSION))
}

pub(crate) fn run_child() -> ExitCode {
    match run_child_protocol(std::io::stdin().lock(), std::io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(1),
    }
}

pub(super) struct FreezeProbe {
    pid: u32,
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    events: Receiver<Result<u8, String>>,
    reader: Option<JoinHandle<()>>,
}

impl FreezeProbe {
    pub(super) fn spawn() -> Result<Self, String> {
        let executable = std::env::current_exe().map_err(|error| {
            format!("resolving the freeze behavior probe executable failed: {error}")
        })?;
        let mut child = Command::new(executable)
            .env(PROBE_ENVIRONMENT, PROBE_VERSION)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("spawning the freeze behavior probe failed: {error}"))?;
        let pid = child.id();
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| "freeze behavior probe stdin was not piped".to_owned())?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "freeze behavior probe stdout was not piped".to_owned())?;
        let (event_sender, events) = mpsc::channel();
        let reader = match thread::Builder::new()
            .name("kickoutchi-freeze-probe-reader".to_owned())
            .spawn(move || read_events(stdout, &event_sender))
        {
            Ok(reader) => reader,
            Err(error) => {
                drop(stdin);
                let _ = child.kill();
                let _ = wait_for_child_exit(&mut child, CHILD_EXIT_TIMEOUT_MS);
                return Err(format!(
                    "starting the freeze behavior probe reader failed: {error}"
                ));
            }
        };

        Ok(Self {
            pid,
            child: Some(child),
            stdin: Some(stdin),
            events,
            reader: Some(reader),
        })
    }

    pub(super) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn wait_until_ready(&self) -> Result<(), String> {
        self.expect_event(READY, "become ready")
    }

    pub(super) fn request_acknowledgement(&mut self) -> Result<(), String> {
        self.write_command(PING)
    }

    pub(super) fn wait_for_acknowledgement(&self) -> Result<(), String> {
        self.expect_event(ACKNOWLEDGED, "acknowledge its request")
    }

    pub(super) fn verify_acknowledgement_is_suspended(&self) -> Result<(), String> {
        match self.events.recv_timeout(SUSPENSION_OBSERVATION_TIMEOUT) {
            Err(RecvTimeoutError::Timeout) => Ok(()),
            Err(RecvTimeoutError::Disconnected) => {
                Err("freeze behavior probe event channel disconnected".to_owned())
            }
            Ok(Ok(ACKNOWLEDGED)) => Err(
                "private Job Object freeze call returned success but did not suspend execution"
                    .to_owned(),
            ),
            Ok(Ok(other)) => Err(format!(
                "freeze behavior probe emitted unexpected byte {other:#04x} while frozen"
            )),
            Ok(Err(error)) => Err(error),
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), String> {
        self.write_command(EXIT)?;
        self.stdin.take();

        let mut child = self
            .child
            .take()
            .ok_or_else(|| "freeze behavior probe child was already reaped".to_owned())?;
        let status = match wait_for_child_exit(&mut child, CHILD_EXIT_TIMEOUT_MS) {
            Ok(status) => status,
            Err(error) => {
                self.child = Some(child);
                return Err(error);
            }
        };
        let reader_result = self.join_reader();
        if !status.success() {
            return Err(format!(
                "freeze behavior probe exited unsuccessfully: {status}"
            ));
        }
        reader_result
    }

    fn write_command(&mut self, command: u8) -> Result<(), String> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| "freeze behavior probe stdin is closed".to_owned())?;
        stdin
            .write_all(&[command])
            .and_then(|()| stdin.flush())
            .map_err(|error| format!("writing to the freeze behavior probe failed: {error}"))
    }

    fn expect_event(&self, expected: u8, phase: &str) -> Result<(), String> {
        match self.events.recv_timeout(IPC_TIMEOUT) {
            Ok(Ok(actual)) if actual == expected => Ok(()),
            Ok(Ok(actual)) => Err(format!(
                "freeze behavior probe emitted unexpected byte {actual:#04x} while waiting to {phase}"
            )),
            Ok(Err(error)) => Err(error),
            Err(RecvTimeoutError::Timeout) => Err(format!(
                "freeze behavior probe did not {phase} within 5 seconds"
            )),
            Err(RecvTimeoutError::Disconnected) => {
                Err("freeze behavior probe event channel disconnected".to_owned())
            }
        }
    }

    fn join_reader(&mut self) -> Result<(), String> {
        let Some(reader) = self.reader.take() else {
            return Ok(());
        };
        reader
            .join()
            .map_err(|_| "freeze behavior probe reader panicked".to_owned())
    }
}

impl Drop for FreezeProbe {
    fn drop(&mut self) {
        self.stdin.take();
        if let Some(mut child) = self.child.take()
            && !matches!(child.try_wait(), Ok(Some(_)))
        {
            let _ = child.kill();
            let _ = wait_for_child_exit(&mut child, CHILD_EXIT_TIMEOUT_MS);
        }
        if self.reader.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(reader) = self.reader.take()
        {
            let _ = reader.join();
        }
    }
}

fn read_events(mut stdout: impl Read, event_sender: &Sender<Result<u8, String>>) {
    loop {
        let mut byte = [0u8; 1];
        let event = match stdout.read_exact(&mut byte) {
            Ok(()) => Ok(byte[0]),
            Err(error) => Err(format!(
                "reading from the freeze behavior probe failed: {error}"
            )),
        };
        let should_stop = event.is_err();
        if event_sender.send(event).is_err() || should_stop {
            return;
        }
    }
}

fn run_child_protocol(mut input: impl Read, mut output: impl Write) -> io::Result<()> {
    output.write_all(&[READY])?;
    output.flush()?;

    for _ in 0..3 {
        let mut command = [0u8; 1];
        input.read_exact(&mut command)?;
        match command[0] {
            PING => {
                output.write_all(&[ACKNOWLEDGED])?;
                output.flush()?;
            }
            EXIT => return Ok(()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid freeze behavior probe command",
                ));
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "freeze behavior probe command limit exceeded",
    ))
}

fn wait_for_child_exit(
    child: &mut Child,
    timeout_ms: u32,
) -> Result<std::process::ExitStatus, String> {
    let wait_result = unsafe {
        // SAFETY: Child owns a live process handle. Waiting neither transfers
        // ownership nor exposes Rust-managed memory to Windows.
        WaitForSingleObject(child.as_raw_handle(), timeout_ms)
    };
    match wait_result {
        WAIT_OBJECT_0 => child
            .wait()
            .map_err(|error| format!("reaping the freeze behavior probe failed: {error}")),
        WAIT_TIMEOUT => Err(format!(
            "freeze behavior probe did not exit within {timeout_ms} milliseconds"
        )),
        WAIT_FAILED => Err(format!(
            "waiting for the freeze behavior probe failed: {}",
            io::Error::last_os_error()
        )),
        other => Err(format!(
            "waiting for the freeze behavior probe returned unexpected status {other}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{ACKNOWLEDGED, EXIT, PING, READY, run_child_protocol};

    #[test]
    fn child_protocol_acknowledges_two_requests_and_exits() {
        let mut output = Vec::new();

        run_child_protocol(Cursor::new([PING, PING, EXIT]), &mut output)
            .expect("the bounded probe conversation must complete");

        assert_eq!(output, [READY, ACKNOWLEDGED, ACKNOWLEDGED]);
    }
}
