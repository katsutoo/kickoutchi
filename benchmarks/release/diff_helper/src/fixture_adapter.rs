use std::collections::{BTreeMap, VecDeque};

use serde_json::{Value, json};

struct CountingWriter {
    bytes: u64,
    checksum: u64,
    socket_records: usize,
    socket_marker_position: usize,
    prefix: Vec<u8>,
}

const SOCKET_MARKER: &[u8] = b"\"socket_token\"";

impl CountingWriter {
    const fn new() -> Self {
        Self {
            bytes: 0,
            checksum: 0xcbf2_9ce4_8422_2325,
            socket_records: 0,
            socket_marker_position: 0,
            prefix: Vec::new(),
        }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("serialized byte count overflowed"))?;
        for byte in bytes {
            if self.prefix.len() < 1_024 {
                self.prefix.push(*byte);
            }
            self.checksum ^= u64::from(*byte);
            self.checksum = self.checksum.wrapping_mul(0x0000_0100_0000_01b3);
            if *byte == SOCKET_MARKER[self.socket_marker_position] {
                self.socket_marker_position += 1;
                if self.socket_marker_position == SOCKET_MARKER.len() {
                    self.socket_records += 1;
                    self.socket_marker_position = 0;
                }
            } else {
                self.socket_marker_position = usize::from(*byte == SOCKET_MARKER[0]);
            }
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FixtureRuntime {
    snapshots: VecDeque<Result<NetworkSnapshot, CollectorError>>,
    monotonic: Duration,
    wall: SystemTime,
    cancel_at: Option<Duration>,
    collect_count: usize,
}

impl FixtureRuntime {
    fn new(
        snapshots: Vec<Result<NetworkSnapshot, CollectorError>>,
        cancel_at: Option<Duration>,
    ) -> Self {
        Self {
            snapshots: snapshots.into(),
            monotonic: Duration::ZERO,
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            cancel_at,
            collect_count: 0,
        }
    }
}

impl WatchRuntime for FixtureRuntime {
    fn collect(&mut self) -> Result<NetworkSnapshot, CollectorError> {
        self.collect_count += 1;
        self.snapshots
            .pop_front()
            .unwrap_or(Err(CollectorError::WorkerExited))
    }

    fn monotonic_now(&mut self) -> Duration {
        self.monotonic
    }

    fn wall_now(&mut self) -> Result<SystemTime, ObservationError> {
        self.wall += Duration::from_millis(1);
        Ok(self.wall)
    }

    fn sleep(&mut self, duration: Duration) {
        self.monotonic += duration;
    }

    fn cancelled(&self) -> bool {
        self.cancel_at
            .is_some_and(|deadline| self.monotonic >= deadline)
    }
}

fn fixture_options(duration: Duration) -> WatchOptions {
    WatchOptions {
        tcp: true,
        udp: true,
        address: None,
        scope_id: None,
        port: None,
        terms: Vec::new(),
        filter_active: false,
        interval: WATCH_INTERVAL_MIN,
        duration: Some(duration),
        json: true,
    }
}

fn validate_watch_output(
    bytes: &[u8],
    expected: &[(&str, usize)],
) -> Result<BTreeMap<String, usize>, String> {
    if !bytes.ends_with(b"\n") {
        return Err("watch output has no terminal newline".to_owned());
    }
    let mut counts = BTreeMap::new();
    for (sequence, line) in bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate() {
        if line.len() + 1 > WATCH_RECORD_MAX_BYTES {
            return Err("watch record exceeds its production bound".to_owned());
        }
        let value: Value = serde_json::from_slice(line).map_err(|error| error.to_string())?;
        if value.get("schema") != Some(&Value::String("kickoutchi.watch_event".to_owned()))
            || value.get("version") != Some(&Value::from(1))
            || value.get("sequence") != Some(&Value::from(sequence))
        {
            return Err("watch envelope differs".to_owned());
        }
        let event = value
            .get("event")
            .and_then(Value::as_str)
            .ok_or_else(|| "watch event is absent".to_owned())?;
        *counts.entry(event.to_owned()).or_insert(0) += 1;
    }
    for (event, count) in expected {
        if counts.get(*event).copied().unwrap_or(0) != *count {
            return Err(format!("{event} count differs"));
        }
    }
    if counts.values().sum::<usize>() != expected.iter().map(|(_, count)| *count).sum::<usize>() {
        return Err("watch output contains an unexpected event".to_owned());
    }
    Ok(counts)
}

fn run_snapshot_fixture(name: &str, count: usize) -> Result<Value, String> {
    let observed = crate::snapshot(count, 0, crate::identity(10_001, 20_001), 0);
    let mut writer = CountingWriter::new();
    let started = Instant::now();
    crate::public_output::write_snapshot_json(
        &mut writer,
        &observed,
        &crate::labels::LabelRegistry::default(),
    )
    .map_err(|error| error.to_string())?;
    let duration = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    if writer.socket_records != count
        || !writer
            .prefix
            .windows(b"\"schema\": \"kickoutchi.snapshot\"".len())
            .any(|window| window == b"\"schema\": \"kickoutchi.snapshot\"")
    {
        return Err("serialized snapshot contract or socket count differs".to_owned());
    }
    Ok(json!({
        "schema": "kickoutchi.release_fixture_helper",
        "version": 1,
        "scenario": name,
        "socket_count": count,
        "record_count": count,
        "change_event_count": 0,
        "event_counts": {},
        "collection_attempts": 0,
        "serialized_bytes": writer.bytes,
        "checksum": writer.checksum,
        "operation_duration_ns": duration,
        "candidate_exit_code": 0,
        "assertions_passed": true
    }))
}

fn run_watch_fixture(name: &str) -> Result<Value, String> {
    let owner = crate::identity(10_001, 20_001);
    let baseline_count = if name == "watch_high_churn" { 1_024 } else { 1 };
    let baseline = crate::snapshot(baseline_count, 0, owner, 0);
    let (snapshots, cancel_at, duration, expected, expected_attempts, expected_exit) = match name {
        "watch_high_churn" => (
            vec![
                Ok(baseline),
                Ok(crate::snapshot(
                    1_024,
                    1_024,
                    crate::identity(10_002, 20_002),
                    2,
                )),
            ],
            Some(Duration::from_millis(200)),
            Duration::from_millis(300),
            vec![("baseline", 1_024), ("release", 1_024), ("bind", 1_024)],
            2,
            ExitReason::Success,
        ),
        "watch_transient_recovery" => (
            vec![
                Ok(baseline.clone()),
                Err(ObservationError::SocketTableUnavailable.into()),
                Ok(crate::snapshot(1, 0, owner, 2)),
            ],
            Some(Duration::from_millis(300)),
            Duration::from_millis(400),
            vec![("baseline", 1), ("collection_gap", 1)],
            3,
            ExitReason::Success,
        ),
        "watch_failure_exhaustion" => (
            vec![
                Ok(baseline),
                Err(ObservationError::SocketTableUnavailable.into()),
                Err(ObservationError::SocketTableUnavailable.into()),
                Err(ObservationError::SocketTableUnavailable.into()),
                Ok(crate::snapshot(1, 0, owner, 2)),
            ],
            None,
            Duration::from_secs(1),
            vec![("baseline", 1), ("collection_gap", 3)],
            4,
            ExitReason::Failure,
        ),
        _ => return Err("unknown watch fixture".to_owned()),
    };
    let mut runtime = FixtureRuntime::new(snapshots, cancel_at);
    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    let started = Instant::now();
    let exit = run_watch_loop(
        &fixture_options(duration),
        &crate::config::Config::default(),
        &mut runtime,
        &mut output,
        &mut diagnostics,
    );
    let operation_duration_ns = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
    if exit != expected_exit || runtime.collect_count != expected_attempts || !diagnostics.is_empty() {
        return Err("watch state-machine result differs".to_owned());
    }
    let counts = validate_watch_output(&output, &expected)?;
    let change_event_count = counts
        .iter()
        .filter(|(event, _)| !matches!(event.as_str(), "baseline" | "collection_gap"))
        .map(|(_, count)| count)
        .sum::<usize>();
    let checksum = output.iter().fold(0xcbf2_9ce4_8422_2325_u64, |value, byte| {
        (value ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    Ok(json!({
        "schema": "kickoutchi.release_fixture_helper",
        "version": 1,
        "scenario": name,
        "socket_count": baseline_count,
        "record_count": counts.values().sum::<usize>(),
        "change_event_count": change_event_count,
        "event_counts": counts,
        "collection_attempts": runtime.collect_count,
        "serialized_bytes": output.len(),
        "checksum": checksum,
        "operation_duration_ns": operation_duration_ns,
        "candidate_exit_code": exit as u8,
        "assertions_passed": true
    }))
}

pub(crate) fn run_release_fixture(name: &str) -> bool {
    let result = match name {
        "snapshot_large" => run_snapshot_fixture(name, 65_536),
        "snapshot_maximum" => {
            run_snapshot_fixture(name, crate::observation::SOCKET_OBSERVATIONS_MAX)
        }
        "watch_high_churn" | "watch_transient_recovery" | "watch_failure_exhaustion" => {
            run_watch_fixture(name)
        }
        _ => return false,
    };
    match result {
        Ok(summary) => println!("{summary}"),
        Err(error) => {
            eprintln!("fixture assertion failed: {error}");
            std::process::exit(1);
        }
    }
    true
}
