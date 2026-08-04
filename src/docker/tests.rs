use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use super::{
    DEFAULT_LOCAL_DOCKER_HOST, DOCKER_HOST_MAX_BYTES, DOCKER_MATCHES_MAX, DOCKER_OUTPUT_MAX_BYTES,
    DOCKER_PORT_SEGMENTS_MAX, ReapChild, ReapOutcome, TEST_ELEVATION_OVERRIDE, WorkerCapacity,
    docker_container_ls_with_host_and_runner, docker_container_ls_with_runner,
    docker_context_from_ps_output, docker_host_is_local, finish_output_drain_before,
    host_addr_matches, local_docker_host, looks_like_docker_owner, normalize_windows_npipe_host,
    parse_published_ports, read_output_bounded, run_command_bounded_with,
    run_command_bounded_with_capacity, should_try_docker_enrichment, spawn_child_cleanup,
    spawn_output_drain, terminate_and_reap,
};
use crate::model::{PermissionStatus, Platform, PortEntry, PortEntryView, Protocol, SocketState};

#[cfg(target_os = "linux")]
use super::{
    LINUX_STATUS_READ_MAX_BYTES, TEST_LINUX_ELEVATION_SOURCES, linux_status_has_capabilities,
    read_linux_status_bounded,
};

const LARGE_OUTPUT_HELPER_ENV: &str = "KICKOUTCHI_TEST_DOCKER_LARGE_OUTPUT";
const INHERITED_PIPE_PARENT_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_PARENT";
const INHERITED_PIPE_GRANDCHILD_ENV: &str = "KICKOUTCHI_TEST_DOCKER_PIPE_GRANDCHILD";
#[cfg(unix)]
const REAP_CHILD_HELPER_ENV: &str = "KICKOUTCHI_TEST_DOCKER_REAP_CHILD";

struct ChannelReader(std::sync::mpsc::Receiver<()>);

struct ExcessThenPanicReader {
    bytes: Vec<u8>,
    read: bool,
}

struct ReapChildProbe {
    events: Vec<&'static str>,
    terminate_error: bool,
    wait_error: bool,
}

impl ReapChild for ReapChildProbe {
    fn process_id(&self) -> u32 {
        42
    }

    fn terminate(&mut self) -> io::Result<()> {
        self.events.push("terminate");
        if self.terminate_error {
            Err(io::Error::other("injected termination failure"))
        } else {
            Ok(())
        }
    }

    fn wait_for_exit(&mut self) -> io::Result<()> {
        self.events.push("wait");
        if self.wait_error {
            Err(io::Error::other("injected wait failure"))
        } else {
            Ok(())
        }
    }
}

impl Read for ExcessThenPanicReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(
            !self.read,
            "the reader was polled after the first excess byte"
        );
        self.read = true;
        let count = self.bytes.len().min(buffer.len());
        buffer[..count].copy_from_slice(&self.bytes[..count]);
        Ok(count)
    }
}

#[cfg(target_os = "linux")]
struct ErrorReader;

#[cfg(target_os = "linux")]
impl Read for ErrorReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected status read failure"))
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_capability_status_is_fail_closed_and_detects_active_authority() {
    let ordinary =
        "CapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\n";
    assert_eq!(linux_status_has_capabilities(ordinary), Some(false));

    let privileged =
        "CapPrm:\t0000000000000000\nCapEff:\t0000000000000400\nCapAmb:\t0000000000000000\n";
    assert_eq!(linux_status_has_capabilities(privileged), Some(true));

    assert_eq!(linux_status_has_capabilities("CapEff:\t0\n"), None);
    assert_eq!(
        linux_status_has_capabilities("CapPrm:\txyz\nCapEff:\t0\nCapAmb:\t0\n"),
        None,
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_status_reader_accepts_the_exact_limit() {
    let input = "x".repeat(LINUX_STATUS_READ_MAX_BYTES);

    let status = read_linux_status_bounded(Cursor::new(input.as_bytes()))
        .expect("an exact-limit status must be accepted");

    assert_eq!(status, input);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_status_reader_rejects_limit_plus_one() {
    let input = vec![b'x'; LINUX_STATUS_READ_MAX_BYTES + 1];

    let error = read_linux_status_bounded(Cursor::new(input))
        .expect_err("an oversized status must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_status_reader_propagates_read_errors() {
    let error =
        read_linux_status_bounded(ErrorReader).expect_err("a status read failure must fail closed");

    assert_eq!(error.kind(), io::ErrorKind::Other);
}

impl Read for ChannelReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Ok(0)
    }
}

fn entry(port: u16, protocol: Protocol, addr: IpAddr, process_name: &str) -> PortEntry {
    PortEntry {
        protocol,
        local_addr: addr,
        local_port: port,
        state: match protocol {
            Protocol::Tcp => SocketState::Listen,
            Protocol::Udp => SocketState::Bound,
        },
        pid: Some(1234),
        process_name: Some(process_name.into()),
        executable_path: Some(PathBuf::from(format!("/usr/bin/{process_name}")).into()),
        command_line: None,
        parent_pid: None,
        parent_process_name: None,
        protected: false,
        platform: Platform::Linux,
        permission: PermissionStatus::Full,
        process_identity: None,
        ipv6_scope: None,
    }
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
fn helper_writes_more_than_one_typical_pipe_buffer() {
    if std::env::var_os(LARGE_OUTPUT_HELPER_ENV).is_none() {
        return;
    }
    let bytes = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES / 2];
    std::io::stdout()
        .write_all(&bytes)
        .expect("large-output helper stdout must be writable");
    std::io::stderr()
        .write_all(&bytes)
        .expect("large-output helper stderr must be writable");
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
fn helper_leaves_grandchild_holding_output_pipes() {
    if std::env::var_os(INHERITED_PIPE_PARENT_ENV).is_none() {
        return;
    }
    let executable = std::env::current_exe().expect("test binary must resolve");
    let mut grandchild = Command::new(executable)
        .env_remove(INHERITED_PIPE_PARENT_ENV)
        .env(INHERITED_PIPE_GRANDCHILD_ENV, "1")
        .args([
            "--exact",
            "docker::tests::helper_holds_inherited_output_pipes",
            "--ignored",
            "--nocapture",
        ])
        .spawn()
        .expect("grandchild test helper must start");
    thread::spawn(move || {
        let _ = grandchild.wait();
    });
}

#[test]
#[ignore = "subprocess fixture; invoked explicitly by Docker command tests"]
fn helper_holds_inherited_output_pipes() {
    if std::env::var_os(INHERITED_PIPE_GRANDCHILD_ENV).is_none() {
        return;
    }
    thread::sleep(Duration::from_secs(2));
}

#[cfg(unix)]
#[test]
#[ignore = "subprocess fixture; invoked explicitly by Docker cleanup tests"]
fn helper_waits_to_be_reaped() {
    if std::env::var_os(REAP_CHILD_HELPER_ENV).is_none() {
        return;
    }
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn stdout_and_stderr_are_drained_while_the_child_is_running() {
    let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
    command.env(LARGE_OUTPUT_HELPER_ENV, "1").args([
        "--exact",
        "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
        "--ignored",
        "--nocapture",
    ]);

    let output = run_command_bounded_with(
        &mut command,
        Duration::from_secs(10),
        DOCKER_OUTPUT_MAX_BYTES,
    )
    .expect("a child writing below the cap must not block on a full pipe");

    assert!(output.status.success());
    assert!(
        output.stdout.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
        "the helper's pipe-sized output was not fully drained",
    );
    assert!(
        output.stderr.len() >= DOCKER_OUTPUT_MAX_BYTES / 2,
        "the helper's pipe-sized stderr was not fully drained",
    );
}

#[test]
fn elevated_enrichment_does_not_execute_docker() {
    TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(Some(true)));
    let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
        panic!("elevated enrichment must not execute a PATH-resolved command")
    });
    TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(None));

    assert!(output.is_none());
}

#[test]
fn remote_docker_endpoints_fall_back_to_the_platform_local_daemon() {
    for remote in [
        "tcp://docker.example:2376",
        "ssh://builder.example",
        "http://docker.example",
        "https://docker.example",
        "npipe:////remote-host/pipe/docker_engine",
        "unix://relative.sock",
        "unix:///tmp/socket\nignored",
    ] {
        assert!(
            !docker_host_is_local(remote),
            "unexpectedly local: {remote}"
        );
        assert_eq!(local_docker_host(Some(remote)), DEFAULT_LOCAL_DOCKER_HOST);
    }
    let oversized = format!("unix:///{}", "x".repeat(DOCKER_HOST_MAX_BYTES));
    assert!(!docker_host_is_local(&oversized));
    assert_eq!(
        local_docker_host(Some(&oversized)),
        DEFAULT_LOCAL_DOCKER_HOST
    );
}

#[test]
fn docker_command_removes_ambient_remote_selectors_and_pins_local_host() {
    TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(Some(false)));
    // The command-shape assertions live inside the injected runner, so this
    // flag proves the product actually invoked it; without it the test
    // would pass vacuously if the runner were never called.
    let runner_invoked = std::cell::Cell::new(false);
    let output = docker_container_ls_with_host_and_runner(
        8080,
        Protocol::Tcp,
        Some("ssh://builder.example"),
        |command| {
            runner_invoked.set(true);
            let arguments = command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                arguments,
                [
                    "--host",
                    DEFAULT_LOCAL_DOCKER_HOST,
                    "container",
                    "ls",
                    "--filter",
                    "publish=8080/tcp",
                    "--format",
                    "json",
                ]
            );
            for variable in [
                "DOCKER_HOST",
                "DOCKER_CONTEXT",
                "DOCKER_TLS",
                "DOCKER_TLS_VERIFY",
                "DOCKER_CERT_PATH",
            ] {
                assert_eq!(
                    command
                        .get_envs()
                        .find(|(name, _)| *name == variable)
                        .map(|(_, value)| value),
                    Some(None),
                    "{variable} must be removed"
                );
            }
            None
        },
    );
    TEST_ELEVATION_OVERRIDE.with(|override_value| override_value.set(None));
    assert!(runner_invoked.get(), "the injected runner must be invoked");
    assert!(output.is_none());
}

#[cfg(unix)]
#[test]
fn absolute_local_unix_docker_host_is_preserved() {
    let host = "unix:///run/user/1000/docker.sock";
    assert!(docker_host_is_local(host));
    assert_eq!(local_docker_host(Some(host)), host);
}

#[cfg(windows)]
#[test]
fn local_windows_docker_named_pipe_is_preserved() {
    let host = "npipe:////./pipe/docker_engine_rootless";
    assert!(docker_host_is_local(host));
    assert_eq!(local_docker_host(Some(host)), host);
}

#[test]
fn windows_named_pipe_hosts_are_structurally_normalized() {
    assert_eq!(
        normalize_windows_npipe_host("NPIPE://\\\\.\\PIPE\\docker_engine\\rootless").as_deref(),
        Some("npipe:////./pipe/docker_engine/rootless")
    );
    assert_eq!(
        normalize_windows_npipe_host("npipe:////./PIPE/docker_engine").as_deref(),
        Some("npipe:////./pipe/docker_engine")
    );
}

#[test]
fn windows_named_pipe_hosts_reject_nonlocal_or_ambiguous_paths() {
    for host in [
        "npipe:////remote/pipe/docker_engine",
        "npipe://localhost/pipe/docker_engine",
        "npipe:////?/pipe/docker_engine",
        "npipe:////./pipe/../docker_engine",
        "npipe:////./pipe/a/../../docker_engine",
        "npipe:////./pipe/.. /docker_engine",
        "npipe:////./pipe/docker_engine. ",
        "npipe:////./pipe//docker_engine",
        "npipe:////./pipe/docker_engine/",
        "npipe:////./pipe/%2e%2e/docker_engine",
        "npipe:////%2e/pipe/docker_engine",
        "npipe:////./pipe/docker_engine?ignored",
        "npipe:////./pipe/docker_engine#ignored",
        "npipe:////./pipe/C:/docker_engine",
        "npipe:////.\\pipe\\..\\docker_engine",
    ] {
        assert_eq!(
            normalize_windows_npipe_host(host),
            None,
            "unexpectedly accepted {host}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn capability_only_elevation_blocks_the_real_docker_command_gate() {
    TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(Some((false, false, true))));
    let output = docker_container_ls_with_runner(8080, Protocol::Tcp, |_| {
        panic!("Linux capabilities must block PATH-resolved Docker execution")
    });
    TEST_LINUX_ELEVATION_SOURCES.with(|sources| sources.set(None));

    assert!(output.is_none());
}

#[test]
fn worker_capacity_reserves_exact_slots_and_releases_them_independently() {
    let capacity = Arc::new(WorkerCapacity::new(3));
    let [first, second] = capacity.reserve::<2>().expect("two slots must fit");
    let [third] = capacity.reserve::<1>().expect("the final slot must fit");

    assert_eq!(capacity.active.load(Ordering::Acquire), 3);
    assert!(
        capacity.reserve::<1>().is_none(),
        "limit plus one must fail"
    );

    drop(second);
    assert_eq!(capacity.active.load(Ordering::Acquire), 2);
    let [replacement] = capacity
        .reserve::<1>()
        .expect("dropping one permit must restore exactly one slot");
    assert_eq!(capacity.active.load(Ordering::Acquire), 3);

    drop(first);
    drop(third);
    drop(replacement);
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    assert!(
        Arc::new(WorkerCapacity::new(0)).reserve::<1>().is_none(),
        "zero capacity must refuse the first slot"
    );
}

#[test]
fn worker_capacity_never_admits_more_than_its_limit_under_contention() {
    const MAXIMUM: usize = 4;
    const CONTENDERS: usize = 16;

    let capacity = Arc::new(WorkerCapacity::new(MAXIMUM));
    let start = Arc::new(Barrier::new(CONTENDERS + 1));
    let release = Arc::new(Barrier::new(MAXIMUM + 1));
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(CONTENDERS);
    for _ in 0..CONTENDERS {
        let capacity = Arc::clone(&capacity);
        let start = Arc::clone(&start);
        let release = Arc::clone(&release);
        let sender = sender.clone();
        workers.push(thread::spawn(move || {
            start.wait();
            let permit = capacity.reserve::<1>();
            sender
                .send(permit.is_some())
                .expect("contention result receiver must remain connected");
            if let Some([permit]) = permit {
                release.wait();
                drop(permit);
            }
        }));
    }
    drop(sender);

    start.wait();
    let admitted = (0..CONTENDERS)
        .map(|_| {
            receiver
                .recv()
                .expect("every contender must report its reservation")
        })
        .filter(|admitted| *admitted)
        .count();
    assert_eq!(admitted, MAXIMUM);
    assert_eq!(capacity.active.load(Ordering::Acquire), MAXIMUM);

    release.wait();
    for worker in workers {
        worker.join().expect("capacity contender must not panic");
    }
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
}

#[test]
fn drain_capacity_is_bounded_and_recovers_when_workers_exit() {
    let capacity = Arc::new(WorkerCapacity::new(2));
    let [first_permit, second_permit] = capacity.reserve::<2>().expect("two slots are available");
    let (first_sender, first_reader) = std::sync::mpsc::channel();
    let (second_sender, second_reader) = std::sync::mpsc::channel();
    let first_worker = spawn_output_drain(
        "kickoutchi-test-drain-one",
        ChannelReader(first_reader),
        1,
        first_permit,
    )
    .expect("first drain starts");
    let second_worker = spawn_output_drain(
        "kickoutchi-test-drain-two",
        ChannelReader(second_reader),
        1,
        second_permit,
    )
    .expect("second drain starts");

    let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
    command.args([
        "--exact",
        "docker::tests::helper_writes_more_than_one_typical_pipe_buffer",
        "--ignored",
    ]);
    assert!(
        run_command_bounded_with_capacity(&mut command, Duration::from_secs(1), 1, &capacity,)
            .is_none(),
        "a command must not start while both drain slots are occupied",
    );
    assert_eq!(capacity.active.load(Ordering::Acquire), 2);

    drop(first_sender);
    drop(second_sender);
    let finish_deadline = Instant::now() + Duration::from_secs(1);
    finish_output_drain_before(&first_worker, "first", finish_deadline).expect("first drain exits");
    finish_output_drain_before(&second_worker, "second", finish_deadline)
        .expect("second drain exits");
    let release_deadline = Instant::now() + Duration::from_secs(1);
    while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
        thread::yield_now();
    }
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    assert!(capacity.reserve::<2>().is_some());
}

#[test]
fn inherited_grandchild_pipes_bound_latency_and_release_capacity() {
    let capacity = Arc::new(WorkerCapacity::new(2));
    let mut command = Command::new(std::env::current_exe().expect("test binary must resolve"));
    command.env(INHERITED_PIPE_PARENT_ENV, "1").args([
        "--exact",
        "docker::tests::helper_leaves_grandchild_holding_output_pipes",
        "--ignored",
        "--nocapture",
    ]);

    assert!(
        run_command_bounded_with_capacity(
            &mut command,
            Duration::from_secs(5),
            DOCKER_OUTPUT_MAX_BYTES,
            &capacity,
        )
        .is_none()
    );
    assert_eq!(capacity.active.load(Ordering::Acquire), 2);

    let release_deadline = Instant::now() + Duration::from_secs(3);
    while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
        thread::yield_now();
    }
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
}

#[test]
fn expired_drain_deadline_returns_without_a_worker_result() {
    // A live sender that never sends models a drain worker stuck in
    // `read` on a pipe some grandchild still holds open. The wait must
    // return once its deadline has passed instead of blocking with the
    // worker.
    let (sender, receiver) = std::sync::mpsc::channel();

    let output = finish_output_drain_before(&receiver, "stdout", Instant::now());

    assert!(
        output.is_none(),
        "a drain that never completed must not produce output",
    );
    drop(sender);
}

#[test]
fn output_reader_stops_after_the_first_excess_byte() {
    let reader = ExcessThenPanicReader {
        bytes: vec![b'x'; 4],
        read: false,
    };

    let output = read_output_bounded(reader, 3).expect("in-memory output read must succeed");

    assert_eq!(output.bytes, b"xxx");
    assert!(output.exceeded);
}

#[test]
fn output_reader_accepts_the_exact_cap() {
    let input = vec![b'x'; DOCKER_OUTPUT_MAX_BYTES];

    let output = read_output_bounded(Cursor::new(input), DOCKER_OUTPUT_MAX_BYTES)
        .expect("exact-limit output read must succeed");

    assert_eq!(output.bytes.len(), DOCKER_OUTPUT_MAX_BYTES);
    assert!(!output.exceeded);
}

#[test]
fn docker_cleanup_waits_once_even_when_termination_fails() {
    let mut child = ReapChildProbe {
        events: Vec::new(),
        terminate_error: true,
        wait_error: false,
    };

    let outcome = terminate_and_reap(&mut child);

    assert_eq!(child.events, ["terminate", "wait"]);
    assert_eq!(outcome, ReapOutcome::Reaped);
}

#[test]
fn docker_cleanup_does_not_retry_a_failed_wait() {
    let mut child = ReapChildProbe {
        events: Vec::new(),
        terminate_error: false,
        wait_error: true,
    };

    let outcome = terminate_and_reap(&mut child);

    assert_eq!(child.events, ["terminate", "wait"]);
    assert_eq!(outcome, ReapOutcome::OwnershipUncertain);
}

#[test]
fn docker_cleanup_worker_capacity_refuses_spawn_until_ownership_returns() {
    let capacity = Arc::new(WorkerCapacity::new(1));
    let cleanup = spawn_child_cleanup(&capacity).expect("first cleanup worker must start");

    let error = spawn_child_cleanup(&capacity)
        .err()
        .expect("second cleanup worker must be refused");
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);

    drop(cleanup);
    let release_deadline = Instant::now() + Duration::from_secs(1);
    while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
        thread::yield_now();
    }
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
    assert!(spawn_child_cleanup(&capacity).is_ok());
}

#[cfg(unix)]
#[test]
fn docker_cleanup_reaps_a_real_direct_child() {
    let capacity = Arc::new(WorkerCapacity::new(1));
    let cleanup = spawn_child_cleanup(&capacity).expect("cleanup worker must start");
    let child = Command::new(std::env::current_exe().expect("test binary must resolve"))
        .env(REAP_CHILD_HELPER_ENV, "1")
        .args([
            "--exact",
            "docker::tests::helper_waits_to_be_reaped",
            "--ignored",
            "--nocapture",
        ])
        .spawn()
        .expect("reap test helper must start");
    let pid = libc::pid_t::try_from(child.id()).expect("child PID must fit pid_t");

    let completed = cleanup.handoff(child);
    completed
        .recv_timeout(Duration::from_secs(2))
        .expect("cleanup worker must terminate and reap the child");

    let mut status = 0;
    let result = unsafe {
        // SAFETY: pid came from the direct child and status is writable.
        libc::waitpid(pid, &raw mut status, libc::WNOHANG)
    };
    assert_eq!(result, -1);
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    let release_deadline = Instant::now() + Duration::from_secs(1);
    while capacity.active.load(Ordering::Acquire) != 0 && Instant::now() < release_deadline {
        thread::yield_now();
    }
    assert_eq!(capacity.active.load(Ordering::Acquire), 0);
}

#[test]
fn non_docker_processes_do_not_trigger_enrichment() {
    let row = entry(
        5432,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "postgres",
    );

    assert!(!should_try_docker_enrichment(PortEntryView::from(&row)));
}

#[test]
fn missing_owner_metadata_can_trigger_optional_docker_enrichment() {
    let mut row = entry(
        5432,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "postgres",
    );
    row.pid = None;
    row.process_name = None;
    row.executable_path = None;
    row.permission = PermissionStatus::Partial;

    assert!(should_try_docker_enrichment(PortEntryView::from(&row)));
}

#[test]
fn docker_proxy_processes_trigger_enrichment_case_insensitively() {
    let row = entry(
        5432,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "Docker-Proxy",
    );

    assert!(looks_like_docker_owner(PortEntryView::from(&row)));
}

#[test]
fn parses_published_ports_and_ignores_exposed_only_ports() {
    let ports = parse_published_ports("80/tcp, 127.0.0.1:5432->5432/tcp, [::]:5353->5353/udp");

    assert_eq!(ports.len(), 2);
    assert_eq!(ports[0].host_addr, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert_eq!(ports[0].host_ports.start, 5432);
    assert_eq!(ports[0].container_ports.start, 5432);
    assert_eq!(ports[0].protocol, Protocol::Tcp);
    assert_eq!(ports[1].host_addr, Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    assert_eq!(ports[1].protocol, Protocol::Udp);
}

#[test]
fn published_port_parser_rejects_zero_at_the_input_boundary() {
    assert!(parse_published_ports("0.0.0.0:0->5432/tcp").is_empty());
    assert!(parse_published_ports("0.0.0.0:5432->0/tcp").is_empty());
}

#[test]
fn published_port_segment_limit_rejects_the_first_excess_segment() {
    let segment = "0.0.0.0:5432->5432/tcp";
    let exact = std::iter::repeat_n(segment, DOCKER_PORT_SEGMENTS_MAX)
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        parse_published_ports(&exact).len(),
        DOCKER_PORT_SEGMENTS_MAX
    );

    let over = format!("{exact},{segment}");
    assert!(parse_published_ports(&over).is_empty());
}

#[test]
fn docker_match_truncation_starts_only_at_match_nine() {
    let row = entry(
        5432,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "docker-proxy",
    );
    let output = (0..=DOCKER_MATCHES_MAX)
        .map(|index| {
            format!(
                r#"{{"ID":"container-{index}","Names":"db-{index}","Ports":"0.0.0.0:5432->5432/tcp","Labels":""}}"#
            )
        })
        .collect::<Vec<_>>();

    let exact = docker_context_from_ps_output(
        PortEntryView::from(&row),
        &output[..DOCKER_MATCHES_MAX].join("\n"),
    )
    .expect("eight matches are retained");
    assert_eq!(exact.containers.len(), DOCKER_MATCHES_MAX);
    assert!(!exact.truncated);

    let over = docker_context_from_ps_output(PortEntryView::from(&row), &output.join("\n"))
        .expect("the first eight matches remain available");
    assert_eq!(over.containers.len(), DOCKER_MATCHES_MAX);
    assert!(over.truncated);
}

#[test]
fn port_ranges_map_host_port_to_container_port() {
    let row = entry(
        8001,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "docker-proxy",
    );
    let output =
        r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8000-8002->9000-9002/tcp","Labels":""}"#;

    let context =
        docker_context_from_ps_output(PortEntryView::from(&row), output).expect("range matches");
    let container = context.single_container().expect("one container");

    assert_eq!(container.host_port, 8001);
    assert_eq!(container.container_port, 9001);
}

#[test]
fn compose_labels_and_stop_command_are_preserved_for_one_match() {
    let row = entry(
        5432,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "docker-proxy",
    );
    let output = r#"{"ID":"a762a2b37a1d","Names":"postgres-dev","Ports":"0.0.0.0:5432->5432/tcp","Labels":"com.docker.compose.project=swamp,com.docker.compose.service=db"}"#;

    let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
        .expect("container matches");
    let container = context.single_container().expect("one container");

    assert_eq!(container.name, "postgres-dev");
    assert_eq!(container.compose_project.as_deref(), Some("swamp"));
    assert_eq!(container.compose_service.as_deref(), Some("db"));
    assert_eq!(container.stop_command(), "docker stop postgres-dev");
    assert!(!context.truncated);
}

#[test]
fn protocol_must_match_before_container_is_reported() {
    let row = entry(
        5353,
        Protocol::Udp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "docker-proxy",
    );
    let output = r#"{"ID":"abc123","Names":"dns","Ports":"0.0.0.0:5353->5353/tcp","Labels":""}"#;

    assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
}

#[test]
fn duplicate_ipv4_ipv6_bindings_do_not_make_one_container_ambiguous() {
    let row = entry(
        8080,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        "docker-proxy",
    );
    let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8080->80/tcp, [::]:8080->80/tcp","Labels":""}"#;

    let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
        .expect("container matches");

    assert_eq!(context.containers.len(), 1);
    assert_eq!(context.containers[0].name, "web");
}

#[test]
fn ipv6_wildcard_publish_does_not_match_an_ipv4_socket_row() {
    let row = entry(
        8080,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "docker-proxy",
    );
    let output = r#"{"ID":"abc123","Names":"web","Ports":"[::]:8080->80/tcp","Labels":""}"#;

    assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
}

#[test]
fn ipv4_wildcard_publish_does_not_match_an_ipv6_socket_row() {
    let row = entry(
        8080,
        Protocol::Tcp,
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        "docker-proxy",
    );
    let output = r#"{"ID":"abc123","Names":"web","Ports":"0.0.0.0:8080->80/tcp","Labels":""}"#;

    assert!(docker_context_from_ps_output(PortEntryView::from(&row), output).is_none());
}

#[test]
fn malformed_json_rows_are_ignored_without_losing_valid_matches() {
    let row = entry(
        8080,
        Protocol::Tcp,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "docker-proxy",
    );
    let output = concat!(
        "not-json\n",
        r#"{"ID":"abc123","Names":"api","Ports":"127.0.0.1:8080->80/tcp","Labels":""}"#,
    );

    let context = docker_context_from_ps_output(PortEntryView::from(&row), output)
        .expect("valid row matches");

    assert_eq!(context.containers.len(), 1);
    assert_eq!(context.containers[0].container_port, 80);
}

#[test]
fn wildcard_addresses_match_specific_socket_views() {
    assert!(host_addr_matches(IpAddr::V6(Ipv6Addr::LOCALHOST), None,));
    assert!(host_addr_matches(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    ));
    assert!(host_addr_matches(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
    ));
    assert!(host_addr_matches(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001,
        ))),
    ));
    assert!(!host_addr_matches(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
    ));
}
