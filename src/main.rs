use anyhow::Context;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod alert;
mod audit;
mod cli;
mod cloud;
mod config;
mod error;
mod event;
mod init;
mod output;
mod policy;
mod process;
mod rules;
mod sandbox;
mod sbom;
mod scan;
#[cfg(feature = "telemetry")]
mod telemetry;
mod tracer;
mod watch;

use cli::{Cli, Commands};
use output::OutputManager;
use tracer::Tracer;

fn main() -> anyhow::Result<()> {
    // Initialize logging
    env_logger::init();

    // Check we're on Linux
    if !cfg!(target_os = "linux") {
        eprintln!("Error: sandtrace is only supported on Linux");
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => {
            args.validate().context("Invalid arguments")?;
            run_sandbox(args)?;
        }
        Commands::Watch(args) => {
            let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
            rt.block_on(watch::run_watch(args))
                .context("Watch mode failed")?;
        }
        Commands::Audit(args) => {
            let exit_code = audit::run_audit(args).context("Audit failed")?;
            std::process::exit(exit_code);
        }
        Commands::Init(args) => {
            init::run_init(args.force).context("Init failed")?;
        }
        Commands::Scan(args) => {
            scan::run_scan(args).context("Scan failed")?;
        }
        Commands::Sbom(args) => {
            sbom::run_sbom(args).context("SBOM generation failed")?;
        }
    }

    Ok(())
}

fn run_sandbox(args: cli::RunArgs) -> anyhow::Result<()> {
    // Setup signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
        eprintln!("\nReceived interrupt, shutting down...");
    })
    .context("Failed to set signal handler")?;

    // Setup output
    let jsonl_file = if let Some(ref path) = args.output {
        let file = std::fs::File::create(path)
            .with_context(|| format!("Failed to create output file: {}", path.display()))?;
        Some(file)
    } else {
        None
    };

    let output = OutputManager::new(jsonl_file, args.verbose, args.no_color);

    // Create and run tracer
    let mut tracer = Tracer::new(&args, output, shutdown).context("Failed to initialize tracer")?;

    let exit_code = tracer.run().context("Tracing failed")?;

    if let (Some(cloud_config), Some(summary)) =
        (cloud::CloudConfig::from_env(), tracer.last_summary())
    {
        let working_dir = std::env::current_dir().unwrap_or_else(|_| ".".into());
        match cloud::upload_run(&cloud_config, &args, summary, &working_dir) {
            Ok(response) => {
                if let Err(error) = persist_cloud_result(&response) {
                    eprintln!(
                        "Warning: failed to persist Sandtrace Cloud upload response: {error}"
                    );
                }
            }
            Err(error) => {
                eprintln!("Warning: failed to upload run results to Sandtrace Cloud: {error}");
            }
        }
    }

    std::process::exit(exit_code);
}

fn persist_cloud_result(response: &serde_json::Value) -> anyhow::Result<()> {
    let Some(path) = std::env::var_os("SANDTRACE_CLOUD_RESULT_FILE") else {
        return Ok(());
    };

    let path = std::path::PathBuf::from(path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create parent directory for cloud result file: {}",
                parent.display()
            )
        })?;
    }

    let json = serde_json::to_vec_pretty(response).context("failed to encode cloud result")?;
    std::fs::write(&path, json)
        .with_context(|| format!("failed to write cloud result file: {}", path.display()))?;
    Ok(())
}
