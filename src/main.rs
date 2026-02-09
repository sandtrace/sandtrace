use anyhow::Context;
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod alert;
mod audit;
mod cli;
mod error;
mod event;
mod output;
mod policy;
mod process;
mod rules;
mod sandbox;
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
            let rt = tokio::runtime::Runtime::new()
                .context("Failed to create async runtime")?;
            rt.block_on(watch::run_watch(args))
                .context("Watch mode failed")?;
        }
        Commands::Audit(args) => {
            audit::run_audit(args)
                .context("Audit failed")?;
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
    let mut tracer = Tracer::new(&args, output, shutdown)
        .context("Failed to initialize tracer")?;

    let exit_code = tracer.run().context("Tracing failed")?;

    std::process::exit(exit_code);
}
