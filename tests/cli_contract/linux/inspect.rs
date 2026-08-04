use super::*;

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
