pub mod handler;
pub mod monitor;

use crate::alert::AlertRouter;
use crate::cli::WatchArgs;
use crate::config::{self, SandtraceConfig};
use crate::error::SandtraceError;
use crate::event::AlertChannel;
use crate::process::ProcessTree;
use crate::rules::matcher::RuleMatcher;
use crate::rules::RuleRegistry;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn run_watch(args: WatchArgs) -> Result<(), SandtraceError> {
    let config = config::load_config();
    run_watch_with_config(args, &config).await
}

pub async fn run_watch_with_config(args: WatchArgs, config: &SandtraceConfig) -> Result<(), SandtraceError> {
    args.validate().map_err(|e| SandtraceError::InvalidArgument(e.to_string()))?;

    // Load rules
    let mut registry = RuleRegistry::new();
    registry.load_builtins();

    // Use config rules_dir as the base, but CLI --rules overrides it
    let rules_dir = if args.rules != std::path::PathBuf::from("~/.sandtrace/rules/") {
        // User explicitly provided --rules
        config::expand_tilde(&args.rules)
    } else {
        config::expand_tilde_str(&config.rules_dir)
    };

    if rules_dir.exists() {
        registry.load_directory(&rules_dir)?;
    }

    // Load additional rule directories from config
    for additional_dir in &config.additional_rules {
        let dir = config::expand_tilde_str(additional_dir);
        if dir.exists() {
            registry.load_directory(&dir)?;
        }
    }

    let rule_count = registry.rule_count();
    eprintln!("Sandtrace watch mode: {} rules loaded", rule_count);

    let rules = registry.into_rules();
    let matcher = RuleMatcher::new(rules)?;

    // Determine watch paths from rules + CLI args.
    // Strategy: watch specific files and credential directories directly.
    // NEVER watch $HOME or other large directories — too many inotify watches.
    let mut watch_entries: Vec<(PathBuf, bool)> = Vec::new();

    for p in matcher.rules_for_watch_paths() {
        let path = PathBuf::from(&p);
        let has_glob = p.contains('*') || p.contains('?') || p.contains('[');

        if has_glob {
            // Skip ** patterns — can't practically watch the whole filesystem
            if p.contains("**") {
                log::debug!("Skipping recursive glob pattern for watch: {}", p);
                continue;
            }
            // For single-level glob like ~/.aws/*, watch the parent directory
            if let Some(parent) = path.parent() {
                let parent_str = parent.to_string_lossy();
                // Only add if parent is a specific credential directory, not $HOME
                if !parent_str.contains('*') && parent.exists() && parent.is_dir() {
                    watch_entries.push((parent.to_path_buf(), false));
                }
            }
        } else if path.exists() {
            // Watch the exact path: file or directory
            watch_entries.push((path, false));
        } else {
            // Path doesn't exist yet — watch parent to catch creation,
            // but only if parent is a credential subdirectory (not $HOME)
            if let Some(parent) = path.parent() {
                if parent.exists() && is_credential_dir(parent) {
                    watch_entries.push((parent.to_path_buf(), false));
                }
            }
        }
    }

    // Add CLI --paths (user explicitly chose these)
    for path in &args.watch_paths {
        watch_entries.push((path.clone(), path.is_dir()));
    }

    // Deduplicate
    watch_entries.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    watch_entries.dedup_by(|a, b| a.0 == b.0);

    if watch_entries.is_empty() {
        eprintln!("Warning: No watchable paths found. Check that credential directories exist.");
        return Ok(());
    }

    eprintln!("Watching {} paths:", watch_entries.len());
    for (path, recursive) in &watch_entries {
        let mode = if *recursive { " (recursive)" } else { "" };
        eprintln!("  {}{}", path.display(), mode);
    }

    // Setup alert channels: CLI flags override config defaults
    let channels = if args.alert_channels.is_empty() {
        // Use config default_alerts if no CLI flags provided
        let config_channels: Vec<AlertChannel> = config
            .default_alerts
            .iter()
            .filter_map(|s| crate::cli::parse_alert_channel(s))
            .collect();
        if config_channels.is_empty() {
            vec![AlertChannel::Stdout]
        } else {
            config_channels
        }
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
    monitor::start_monitoring(watch_entries, handler).await?;

    // Cleanup PID file
    if let Some(ref pid_file) = args.pid_file {
        let _ = std::fs::remove_file(pid_file);
    }

    Ok(())
}

/// Returns true if the directory is a known credential/config subdirectory,
/// as opposed to a top-level directory like $HOME that would be too noisy to watch.
fn is_credential_dir(dir: &std::path::Path) -> bool {
    let name = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
    matches!(
        name,
        ".aws" | ".ssh" | ".gnupg" | ".docker" | ".kube" | ".azure"
            | ".config" | ".pip" | ".npm" | ".cargo" | ".composer"
            | ".pgpass" | ".triton" | ".volta" | ".local"
            | "gcloud" | "npm"
    )
}

