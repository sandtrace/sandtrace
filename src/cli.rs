use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "sandtrace")]
#[command(about = "A Rust-based malware sandbox with syscall tracing and filesystem restriction")]
#[command(version = "0.1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Run a command in the sandbox
    Run(RunArgs),
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
