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

#[cfg(target_os = "macos")]
fn partial_socket_set_after_baseline(
    status: std::process::ExitStatus,
    stderr: &[u8],
    records: &[serde_json::Value],
) -> Option<WatchOutcome> {
    if status.code() != Some(1) {
        return None;
    }
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(stderr));
    assert!(records.len() >= 4, "{records:#?}");
    assert_eq!(records[0]["event"], "baseline");
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record["schema"], "kickoutchi.watch_event", "{records:#?}");
        assert_eq!(record["version"], 1, "{records:#?}");
        assert_eq!(
            record["sequence"],
            u64::try_from(index).unwrap(),
            "{records:#?}"
        );
        assert!(
            index == 0 || matches!(record["event"].as_str(), Some("release" | "collection_gap")),
            "{records:#?}"
        );
        if record["event"] == "collection_gap" {
            assert!(
                matches!(
                    record["data"]["error"]["code"].as_str(),
                    Some("partial_socket_set" | "observation_raced")
                ),
                "{records:#?}"
            );
        }
    }
    for (index, record) in records.iter().rev().take(3).rev().enumerate() {
        assert_eq!(record["event"], "collection_gap", "{records:#?}");
        assert_eq!(
            record["data"]["consecutive_failures"],
            u64::try_from(index + 1).unwrap(),
            "{records:#?}"
        );
    }
    let release_count = records
        .iter()
        .filter(|record| record["event"] == "release")
        .count();
    assert!(release_count <= 1, "{records:#?}");
    Some(if release_count == 1 {
        WatchOutcome::Events(records.to_vec())
    } else {
        WatchOutcome::PartialSocketSet
    })
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
    let baseline = match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
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
    let records = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("watch line must be JSON"))
        .collect::<Vec<_>>();
    #[cfg(target_os = "macos")]
    if let Some(outcome) = partial_socket_set_after_baseline(status, &stderr, &records) {
        return outcome;
    }
    assert_eq!(
        status.code(),
        Some(0),
        "{}; records: {records:#?}",
        String::from_utf8_lossy(&stderr)
    );
    assert!(stderr.is_empty(), "{}", String::from_utf8_lossy(&stderr));
    WatchOutcome::Events(records)
}

fn watch_release_attempt() -> (u16, WatchOutcome) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("TCP fixture must bind");
    let port = listener.local_addr().expect("TCP address is known").port();
    let port_text = port.to_string();
    let config = endpoint_config(port);
    (port, watch_until_release(&config, &port_text, listener))
}

/// Run the macOS watch journey, returning events only when the host gave a
/// complete observation.
///
/// This journey has two correct outcomes, and the host picks which one.
/// macOS collection is process-first through `libproc`, so a SIP-protected
/// process holding a socket makes the machine-wide observation partial even
/// under `sudo`. `watch` then refuses to publish a baseline it cannot vouch
/// for, or emits bounded collection gaps when the loss begins after a valid
/// baseline. Those refusals are the designed behavior, not defects, and no
/// retry budget can make a shared runner stop running protected processes.
///
/// So both outcomes are asserted rather than one being demanded:
/// [`partial_socket_set_outcome`] pins refusal before the baseline, while
/// [`partial_socket_set_after_baseline`] pins the ordered baseline, any valid
/// intermediate release or gap records, and the terminal three consecutive
/// gaps when visibility remains lost. The caller still pins a release that
/// arrived before those terminal gaps. A regression cannot hide in either
/// partial path because each exact public contract is asserted.
///
/// The attempts remain because a complete observation asserts strictly more.
/// They exist to prefer the richer assertion, not to retry a failure into a
/// pass — every attempt already had to satisfy one contract or the other.
#[cfg(target_os = "macos")]
fn watch_release_journey() -> Option<(u16, Vec<serde_json::Value>)> {
    let required = std::env::var_os(super::RELEASE_E2E_REQUIRED_ENV).is_some();
    let attempts = if required { WATCH_RELEASE_ATTEMPTS } else { 1 };
    for _attempt in 1..=attempts {
        let (port, outcome) = watch_release_attempt();
        match outcome {
            WatchOutcome::Events(records) => return Some((port, records)),
            WatchOutcome::PartialSocketSet => {}
        }
    }
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
        records
            .iter()
            .skip(1)
            .all(|record| matches!(record["event"].as_str(), Some("release" | "collection_gap"))),
        "{records:#?}"
    );
    let release = releases[0];
    assert_eq!(release["data"]["endpoint"]["port"], watch_port);
    assert_eq!(release["data"]["label"], "native artifact fixture");
    assert_eq!(release["data"]["filter_result"], "matched");
}
