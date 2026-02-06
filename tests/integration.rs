use std::path::PathBuf;
use std::process::Command;

/// Path to the sandtrace binary (debug build)
fn sandtrace_bin() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target");
    path.push("debug");
    path.push("sandtrace");
    path
}

/// Path to a test fixture binary
fn fixture_bin(name: &str) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.push("fixtures");
    path.push("binaries");
    path.push("target");
    path.push("release");
    path.push(name);
    path
}

/// Path to the fixtures directory (for --allow-path)
fn fixture_dir() -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("tests");
    path.to_str().unwrap().to_string()
}

/// Run sandtrace with given args and return (exit_code, stdout, stderr)
fn run_sandtrace(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(sandtrace_bin())
        .args(args)
        .output()
        .expect("failed to execute sandtrace");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    (code, stdout, stderr)
}

/// Parse JSONL stdout into a Vec of serde_json::Value
fn parse_jsonl(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// Find events of a specific type in JSONL output
fn events_of_type<'a>(events: &'a [serde_json::Value], event_type: &str) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|e| e.get("event_type").and_then(|v| v.as_str()) == Some(event_type))
        .collect()
}

/// Find syscall events with a specific syscall name
fn syscall_events_named<'a>(events: &'a [serde_json::Value], name: &str) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|e| {
            e.get("event_type").and_then(|v| v.as_str()) == Some("syscall")
                && e.get("syscall").and_then(|v| v.as_str()) == Some(name)
        })
        .collect()
}

// ========== Basic Trace Tests ==========

#[test]
fn trace_bin_true_exits_zero() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0, "expected exit code 0 for /bin/true");

    let events = parse_jsonl(&stdout);
    assert!(!events.is_empty(), "expected JSONL output");

    // Should have at least one process event (exec) and a summary
    let process_events = events_of_type(&events, "process");
    assert!(!process_events.is_empty(), "expected process events");

    let summaries = events_of_type(&events, "summary");
    assert_eq!(summaries.len(), 1, "expected exactly one summary");

    let summary = summaries[0].clone();
    assert_eq!(summary["exit_code"], 0);
    assert!(summary["total_syscalls"].as_u64().unwrap() > 0);
}

#[test]
fn trace_bin_true_has_execve_event() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);

    // Should have an exec process event
    let process_events = events_of_type(&events, "process");
    let exec_events: Vec<_> = process_events
        .iter()
        .filter(|e| e.get("kind").and_then(|k| k.get("type")).and_then(|t| t.as_str()) == Some("exec"))
        .collect();
    assert!(!exec_events.is_empty(), "expected at least one exec event");
}

#[test]
fn trace_bin_true_has_exit_event() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);
    let process_events = events_of_type(&events, "process");
    let exit_events: Vec<_> = process_events
        .iter()
        .filter(|e| {
            e.get("kind").and_then(|k| k.get("type")).and_then(|t| t.as_str()) == Some("exit")
                && e.get("kind").and_then(|k| k.get("code")).and_then(|c| c.as_i64()) == Some(0)
        })
        .collect();
    assert!(!exit_events.is_empty(), "expected exit event with code 0");
}

// ========== File Access Tests ==========

#[test]
fn trace_file_read_etc_hostname() {
    // /etc/hostname should be readable in trace-only mode
    let (code, stdout, _stderr) = run_sandtrace(&[
        "run", "--trace-only", "/bin/cat", "/etc/hostname",
    ]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);

    // Should have openat events with /etc/hostname
    let openat_events = syscall_events_named(&events, "openat");
    let hostname_opens: Vec<_> = openat_events
        .iter()
        .filter(|e| {
            e.get("args")
                .and_then(|a| a.get("decoded"))
                .and_then(|d| d.get("path"))
                .and_then(|p| p.as_str())
                .map(|p| p.contains("hostname"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        !hostname_opens.is_empty(),
        "expected openat event for /etc/hostname"
    );
}

// ========== Sandbox Deny Tests ==========

#[test]
fn sandbox_denies_etc_shadow_read() {
    let fixture = fixture_bin("read_file");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?} - build fixtures first", fixture);
    }

    let fdir = fixture_dir();
    let (code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--allow-path", &fdir,
        "--allow-exec",
        fixture.to_str().unwrap(),
        "/etc/shadow",
    ]);

    // Should have non-zero exit (denied)
    assert_ne!(code, 0, "expected non-zero exit code when reading /etc/shadow");

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);
    assert!(
        summary[0]["denied_count"].as_u64().unwrap() > 0,
        "expected at least one denied syscall"
    );

    // Check for denied syscall events
    let denied_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.get("event_type").and_then(|v| v.as_str()) == Some("syscall")
                && e.get("action").and_then(|v| v.as_str()) == Some("deny")
        })
        .collect();
    assert!(
        !denied_events.is_empty(),
        "expected denied syscall events"
    );
}

#[test]
fn sandbox_allows_usr_read() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "/bin/ls", "/usr"]);
    assert_eq!(code, 0, "expected exit code 0 for /bin/ls /usr");

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["exit_code"], 0);
}

// ========== Network Block Tests ==========

#[test]
fn sandbox_blocks_network_connect() {
    let fixture = fixture_bin("connect_out");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?}", fixture);
    }

    let fdir = fixture_dir();
    let (code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--allow-path", &fdir,
        "--allow-exec",
        fixture.to_str().unwrap(),
    ]);

    // connect should fail in sandbox (network blocked)
    assert_ne!(code, 0, "expected non-zero exit when network is blocked");

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);
}

#[test]
fn sandbox_allows_network_with_flag() {
    let fixture = fixture_bin("connect_out");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?}", fixture);
    }

    let fdir = fixture_dir();
    // With --allow-net, the connect should at least not be denied by policy
    // (it may still fail due to network namespace / no route, but the syscall shouldn't be denied)
    let (_code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--allow-net",
        "--allow-path", &fdir,
        "--allow-exec",
        fixture.to_str().unwrap(),
    ]);

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);

    // With --allow-net, connect shouldn't be policy-denied
    let connect_events = syscall_events_named(&events, "connect");
    for evt in &connect_events {
        let action = evt.get("action").and_then(|a| a.as_str()).unwrap_or("");
        assert_ne!(action, "deny", "connect should not be denied with --allow-net");
    }
}

// ========== Fork Follow Tests ==========

#[test]
fn trace_follows_forks() {
    let fixture = fixture_bin("fork_child");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?}", fixture);
    }

    let (code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--trace-only",
        fixture.to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "fork_child should exit 0");

    let events = parse_jsonl(&stdout);

    // Should have a fork process event
    let process_events = events_of_type(&events, "process");
    let fork_events: Vec<_> = process_events
        .iter()
        .filter(|e| e.get("kind").and_then(|k| k.get("type")).and_then(|t| t.as_str()) == Some("fork"))
        .collect();
    assert!(
        !fork_events.is_empty(),
        "expected fork event in process events"
    );

    // Summary should show process_count >= 2
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);
    let proc_count = summary[0]["process_count"].as_u64().unwrap();
    assert!(
        proc_count >= 2,
        "expected at least 2 processes, got {proc_count}"
    );
}

// ========== Timeout Tests ==========

#[test]
fn timeout_kills_long_running_process() {
    let fixture = fixture_bin("busy_loop");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?}", fixture);
    }

    let start = std::time::Instant::now();
    let (_code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--trace-only",
        "--timeout", "2",
        fixture.to_str().unwrap(),
    ]);

    let elapsed = start.elapsed();

    // Should complete within ~10 seconds (2s timeout + some overhead)
    assert!(
        elapsed.as_secs() < 10,
        "timeout should have killed the process, took {}s",
        elapsed.as_secs()
    );

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);

    // Summary should mention the timeout in suspicious_activity
    let suspicious = summary[0]["suspicious_activity"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();
    let has_timeout_note = suspicious.iter().any(|s| s.to_lowercase().contains("timed out") || s.to_lowercase().contains("timeout"));
    assert!(has_timeout_note, "expected timeout note in suspicious_activity, got: {:?}", suspicious);
}

// ========== Seccomp Trap Tests ==========

#[test]
fn seccomp_traps_mount_syscall() {
    let fixture = fixture_bin("try_mount");
    if !fixture.exists() {
        panic!("fixture binary not found at {:?}", fixture);
    }

    let fdir = fixture_dir();
    let (code, stdout, stderr) = run_sandtrace(&[
        "run",
        "--allow-path", &fdir,
        "--allow-exec",
        fixture.to_str().unwrap(),
    ]);

    // Should have non-zero exit
    assert_ne!(code, 0, "try_mount should fail in sandbox");

    let events = parse_jsonl(&stdout);

    // The mount syscall should be denied by policy
    let denied_events: Vec<_> = events
        .iter()
        .filter(|e| {
            e.get("event_type").and_then(|v| v.as_str()) == Some("syscall")
                && (e.get("action").and_then(|v| v.as_str()) == Some("deny")
                    || e.get("action").and_then(|v| v.as_str()) == Some("kill"))
        })
        .collect();

    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);

    // Either denied_count > 0 in summary, or the process was killed by SIGSYS
    let denied_count = summary[0]["denied_count"].as_u64().unwrap_or(0);
    let exit_code = summary[0]["exit_code"].as_i64();
    assert!(
        denied_count > 0 || exit_code == Some(159) || !denied_events.is_empty(),
        "expected mount to be denied/trapped. denied_count={denied_count}, exit_code={exit_code:?}, stderr={stderr}"
    );
}

// ========== Policy File Tests ==========

#[test]
fn custom_policy_file_loaded() {
    let policy_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("permissive.toml");

    if !policy_path.exists() {
        // Skip if no example policy
        return;
    }

    let (code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--trace-only",
        "--policy",
        policy_path.to_str().unwrap(),
        "/bin/true",
    ]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);
    assert!(!events.is_empty());
}

// ========== Allow-path CLI flag Tests ==========

#[test]
fn allow_path_flag_permits_access() {
    let (code, stdout, _stderr) = run_sandtrace(&[
        "run",
        "--allow-path", "/tmp",
        "/bin/ls", "/tmp",
    ]);
    assert_eq!(code, 0, "expected /bin/ls /tmp to succeed with --allow-path /tmp");

    let events = parse_jsonl(&stdout);
    let summary = events_of_type(&events, "summary");
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0]["exit_code"], 0);
}

// ========== JSONL Output Format Tests ==========

#[test]
fn jsonl_output_is_valid_json_lines() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0);

    // Every non-empty line should be valid JSON
    for (i, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(line);
        assert!(
            parsed.is_ok(),
            "line {} is not valid JSON: {}",
            i + 1,
            line
        );
    }
}

#[test]
fn every_event_has_event_type() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);
    for (i, event) in events.iter().enumerate() {
        assert!(
            event.get("event_type").is_some(),
            "event {} missing event_type field: {:?}",
            i,
            event
        );
    }
}

#[test]
fn syscall_events_have_required_fields() {
    let (code, stdout, _stderr) = run_sandtrace(&["run", "--trace-only", "/bin/true"]);
    assert_eq!(code, 0);

    let events = parse_jsonl(&stdout);
    let syscall_events = events_of_type(&events, "syscall");

    for evt in &syscall_events {
        assert!(evt.get("timestamp").is_some(), "missing timestamp");
        assert!(evt.get("pid").is_some(), "missing pid");
        assert!(evt.get("syscall").is_some(), "missing syscall");
        assert!(evt.get("syscall_nr").is_some(), "missing syscall_nr");
        assert!(evt.get("return_value").is_some(), "missing return_value");
        assert!(evt.get("success").is_some(), "missing success");
        assert!(evt.get("action").is_some(), "missing action");
        assert!(evt.get("category").is_some(), "missing category");
    }
}
