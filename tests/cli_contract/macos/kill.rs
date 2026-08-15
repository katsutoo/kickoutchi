use super::*;

/// A double-forked member leaves the root's tree but remains in its process
/// group. macOS has no `/proc`, so this test asserts that group scope reaches a
/// non-descendant rather than inspecting its reparenting directly.
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
                || killed_stderr.contains("collecting ports before kill failed: observation raced"),
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
