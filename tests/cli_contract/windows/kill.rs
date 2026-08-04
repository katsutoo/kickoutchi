use super::*;

#[test]
fn windows_interactive_normal_kill_accepts_y_and_port_disappears() {
    let _host_observation = lock_host_observation();
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
fn windows_tree_kill_by_port_removes_root_and_child() {
    let _host_observation = lock_host_observation();
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
    let _host_observation = lock_host_observation();
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
