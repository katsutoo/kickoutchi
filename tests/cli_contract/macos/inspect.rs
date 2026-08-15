use super::*;

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

    assert!(pid_exists(child_pid), "inspect must not signal anything");

    let _ = fs::remove_file(ready_file);
}
