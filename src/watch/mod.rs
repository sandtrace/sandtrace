pub mod handler;
pub mod monitor;

use crate::alert::AlertRouter;
use crate::cli::WatchArgs;
use crate::error::SandtraceError;
use crate::event::AlertChannel;
use crate::process::ProcessTree;
use crate::rules::matcher::RuleMatcher;
use crate::rules::RuleRegistry;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn run_watch(args: WatchArgs) -> Result<(), SandtraceError> {
    args.validate().map_err(|e| SandtraceError::InvalidArgument(e.to_string()))?;

    // Load rules
    let mut registry = RuleRegistry::new();
    registry.load_builtins();

    let rules_dir = expand_tilde(&args.rules);
    if rules_dir.exists() {
        registry.load_directory(&rules_dir)?;
    }

    let rule_count = registry.rule_count();
    eprintln!("Sandtrace watch mode: {} rules loaded", rule_count);

    let rules = registry.into_rules();
    let matcher = RuleMatcher::new(rules)?;

    // Determine watch paths from rules + CLI args
    let mut watch_paths: Vec<PathBuf> = matcher
        .rules_for_watch_paths()
        .iter()
        .filter_map(|p| {
            let path = PathBuf::from(p);
            // For glob patterns, watch the parent directory
            if let Some(parent) = path.parent() {
                if parent.exists() {
                    return Some(parent.to_path_buf());
                }
            }
            if path.exists() {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    for path in &args.watch_paths {
        watch_paths.push(path.clone());
    }

    watch_paths.sort();
    watch_paths.dedup();

    if watch_paths.is_empty() {
        eprintln!("Warning: No watchable paths found. Check that credential directories exist.");
        return Ok(());
    }

    eprintln!("Watching {} paths:", watch_paths.len());
    for path in &watch_paths {
        eprintln!("  {}", path.display());
    }

    // Setup alert channels
    let channels = if args.alert_channels.is_empty() {
        vec![AlertChannel::Stdout]
    } else {
        args.parsed_alert_channels()
    };
    let alert_router = Arc::new(AlertRouter::new(&channels));

    // Setup process tree
    let process_tree = Arc::new(Mutex::new(ProcessTree::new()));

    // Setup handler
    let handler = Arc::new(handler::EventHandler::new(
        matcher,
        alert_router,
        process_tree,
    ));

    // Write PID file if daemon mode
    if let Some(ref pid_file) = args.pid_file {
        std::fs::write(pid_file, std::process::id().to_string())
            .map_err(|e| SandtraceError::Io(e))?;
    }

    // Start monitoring
    monitor::start_monitoring(watch_paths, handler).await?;

    // Cleanup PID file
    if let Some(ref pid_file) = args.pid_file {
        let _ = std::fs::remove_file(pid_file);
    }

    Ok(())
}

fn expand_tilde(path: &std::path::Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(format!("{}{}", home, &path_str[1..]));
        }
    }
    path.to_path_buf()
}
