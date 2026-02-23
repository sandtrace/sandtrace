use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sandtrace")]
#[command(
    about = "A Rust-based security tool: malware sandbox, credential watcher, and codebase auditor"
)]
#[command(version = "0.2.4")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command in the sandbox
    Run(RunArgs),

    /// Watch credential files for suspicious access in real-time
    Watch(WatchArgs),

    /// Audit a codebase for supply-chain threats and hidden payloads
    Audit(AuditArgs),

    /// Initialize ~/.sandtrace/ with default config and rules
    Init(InitArgs),

    /// Scan filesystem for whitespace obfuscation (wormsign detection)
    Scan(ScanArgs),
}

#[derive(Parser, Debug)]
pub struct RunArgs {
    /// Command to execute in sandbox
    #[arg(required = true, trailing_var_arg = true)]
    pub command: Vec<String>,

    /// TOML policy file for rules
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Allow filesystem access to path (repeatable)
    #[arg(long = "allow-path", value_name = "PATH")]
    pub allow_paths: Vec<PathBuf>,

    /// Allow network access
    #[arg(long)]
    pub allow_net: bool,

    /// Allow child process execution
    #[arg(long)]
    pub allow_exec: bool,

    /// JSONL output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,

    /// Kill process after N seconds
    #[arg(long, value_name = "SECONDS", default_value = "30")]
    pub timeout: u64,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable enforcement, just trace
    #[arg(long)]
    pub trace_only: bool,

    /// Trace child processes
    #[arg(long, default_value = "true")]
    pub follow_forks: bool,
}

#[derive(Parser, Debug)]
pub struct WatchArgs {
    /// Path to YAML rules directory
    #[arg(long, value_name = "DIR", default_value = "~/.sandtrace/rules/")]
    pub rules: PathBuf,

    /// Additional paths to monitor (repeatable)
    #[arg(long = "paths", value_name = "PATH")]
    pub watch_paths: Vec<PathBuf>,

    /// Alert channels: stdout, desktop, webhook:<url>, syslog
    #[arg(long = "alert", value_name = "CHANNEL")]
    pub alert_channels: Vec<String>,

    /// Fork to background as a daemon
    #[arg(long)]
    pub daemon: bool,

    /// PID file for daemon mode
    #[arg(long, value_name = "PATH")]
    pub pid_file: Option<PathBuf>,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Parser, Debug)]
pub struct AuditArgs {
    /// Directory to scan
    #[arg(required = true)]
    pub target: PathBuf,

    /// Path to YAML rules directory
    #[arg(long, value_name = "DIR", default_value = "~/.sandtrace/rules/")]
    pub rules: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value = "terminal")]
    pub format: AuditFormat,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value = "low")]
    pub severity: SeverityFilter,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,
}

#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Overwrite existing config and rules
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct ScanArgs {
    /// Directory to scan (defaults to $HOME)
    #[arg(default_value_t = default_scan_target())]
    pub target: String,

    /// Minimum consecutive whitespace characters to flag
    #[arg(short = 'n', long, default_value_t = 100)]
    pub min_whitespace: usize,

    /// Show line preview for each finding
    #[arg(short, long)]
    pub verbose: bool,

    /// Only print filenames with matches (like ripgrep -l)
    #[arg(short = 'l', long = "files-with-matches")]
    pub files_only: bool,

    /// Maximum file size in bytes to scan (skip larger files)
    #[arg(long, default_value_t = 10_000_000)]
    pub max_size: u64,

    /// Disable colored terminal output
    #[arg(long)]
    pub no_color: bool,
}

fn default_scan_target() -> String {
    std::env::var("HOME").unwrap_or_else(|_| ".".into())
}

#[derive(Debug, Clone, ValueEnum)]
pub enum AuditFormat {
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SeverityFilter {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl RunArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.command.is_empty() {
            anyhow::bail!("Command is required");
        }

        if let Some(policy) = &self.policy {
            if !policy.exists() {
                anyhow::bail!("Policy file does not exist: {}", policy.display());
            }
        }

        for path in &self.allow_paths {
            if !path.exists() {
                anyhow::bail!("Allow path does not exist: {}", path.display());
            }
        }

        Ok(())
    }
}

impl WatchArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        for path in &self.watch_paths {
            if !path.exists() {
                anyhow::bail!("Watch path does not exist: {}", path.display());
            }
        }
        Ok(())
    }

    pub fn parsed_alert_channels(&self) -> Vec<crate::event::AlertChannel> {
        self.alert_channels
            .iter()
            .filter_map(|s| parse_alert_channel(s))
            .collect()
    }
}

impl AuditArgs {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.target.exists() {
            anyhow::bail!("Target directory does not exist: {}", self.target.display());
        }
        if !self.target.is_dir() {
            anyhow::bail!("Target must be a directory: {}", self.target.display());
        }
        Ok(())
    }

    pub fn min_severity(&self) -> crate::event::Severity {
        match self.severity {
            SeverityFilter::Info => crate::event::Severity::Info,
            SeverityFilter::Low => crate::event::Severity::Low,
            SeverityFilter::Medium => crate::event::Severity::Medium,
            SeverityFilter::High => crate::event::Severity::High,
            SeverityFilter::Critical => crate::event::Severity::Critical,
        }
    }
}

pub fn parse_alert_channel(s: &str) -> Option<crate::event::AlertChannel> {
    match s {
        "stdout" => Some(crate::event::AlertChannel::Stdout),
        "desktop" => Some(crate::event::AlertChannel::Desktop),
        "syslog" => Some(crate::event::AlertChannel::Syslog),
        s if s.starts_with("webhook:") => {
            let url = s.strip_prefix("webhook:").unwrap().to_string();
            Some(crate::event::AlertChannel::Webhook(url))
        }
        _ => None,
    }
}
