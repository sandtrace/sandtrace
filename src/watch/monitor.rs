use crate::error::{SandtraceError, WatchError};
use crate::event::{FileAccessEvent, FileAccessType};
use crate::watch::handler::EventHandler;
use chrono::Utc;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

pub async fn start_monitoring(
    watch_entries: Vec<(PathBuf, bool)>,
    handler: Arc<EventHandler>,
) -> Result<(), SandtraceError> {
    let (tx, mut rx) = mpsc::channel::<notify::Result<Event>>(256);

    // Create filesystem watcher
    let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
        let _ = tx.blocking_send(res);
    })
    .map_err(|e| {
        SandtraceError::Watch(WatchError::InotifyInit(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        )))
    })?;

    // Add watches for each path
    for (path, recursive) in &watch_entries {
        let mode = if *recursive {
            RecursiveMode::Recursive
        } else {
            RecursiveMode::NonRecursive
        };

        if let Err(e) = watcher.watch(path, mode) {
            log::warn!("Failed to watch {}: {}", path.display(), e);
        }
    }

    eprintln!("Sandtrace watching... Press Ctrl+C to stop.");

    // Setup signal handler for graceful shutdown
    let mut sigterm = signal_hook_tokio::Signals::new(&[
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .map_err(|e| SandtraceError::Io(e))?;

    loop {
        tokio::select! {
            Some(event_result) = rx.recv() => {
                match event_result {
                    Ok(event) => {
                        if let Some(file_event) = convert_notify_event(event) {
                            handler.handle_file_access(file_event).await;
                        }
                    }
                    Err(e) => {
                        log::error!("Watch error: {}", e);
                    }
                }
            }
            _ = wait_for_signal(&mut sigterm) => {
                eprintln!("\nShutting down watcher...");
                break;
            }
        }
    }

    drop(watcher);
    Ok(())
}

fn convert_notify_event(event: Event) -> Option<FileAccessEvent> {
    let access_type = match event.kind {
        EventKind::Access(_) => FileAccessType::Read,
        EventKind::Create(_) => FileAccessType::Create,
        EventKind::Modify(notify::event::ModifyKind::Data(_)) => FileAccessType::Write,
        EventKind::Modify(notify::event::ModifyKind::Metadata(_)) => FileAccessType::Chmod,
        EventKind::Remove(_) => FileAccessType::Delete,
        _ => return None,
    };

    let path = event.paths.first()?.to_string_lossy().to_string();

    // Try to get process info from /proc for the most recent accessor
    // Note: inotify doesn't provide PID directly, so we do best-effort detection
    let (pid, process_name) = detect_accessor(&path);

    Some(FileAccessEvent {
        timestamp: Utc::now(),
        path,
        access_type,
        pid,
        process_name,
        process_lineage: vec![],
    })
}

fn detect_accessor(path: &str) -> (Option<i32>, Option<String>) {
    let our_pid = std::process::id() as i32;

    // Strategy 1: Check /proc/<pid>/fd for open file handles (works for long-lived processes)
    // Collect PIDs and sort descending (newer processes first, more likely to be the accessor)
    let mut pids: Vec<i32> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name_str = entry.file_name();
            if let Ok(pid) = name_str.to_string_lossy().parse::<i32>() {
                if pid != our_pid {
                    pids.push(pid);
                }
            }
        }
    }
    pids.sort_unstable_by(|a, b| b.cmp(a)); // newest first

    for pid in &pids {
        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(fds) = std::fs::read_dir(&fd_dir) {
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    if target.to_string_lossy() == path {
                        let name = crate::process::get_process_name(*pid);
                        return (Some(*pid), name);
                    }
                }
            }
        }
    }

    // Strategy 2: Check /proc/<pid>/cmdline for processes that reference this file path
    // (catches cases where the fd is already closed but the process is still running)
    let file_name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if !file_name.is_empty() {
        for pid in &pids {
            let cmdline_path = format!("/proc/{}/cmdline", pid);
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                // cmdline uses NUL separators
                let args = cmdline.replace('\0', " ");
                if args.contains(path) || args.contains(file_name) {
                    let name = crate::process::get_process_name(*pid);
                    // Skip shell processes that just happen to have the path in their env
                    let name_str = name.as_deref().unwrap_or("");
                    if !matches!(name_str, "bash" | "zsh" | "sh" | "fish") {
                        return (Some(*pid), name);
                    }
                }
            }
        }
    }

    (None, None)
}

async fn wait_for_signal(signals: &mut signal_hook_tokio::Signals) {
    use futures_util::stream::StreamExt;
    signals.next().await;
}
