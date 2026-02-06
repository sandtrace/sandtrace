mod cli;
mod error;
mod event;
mod output;
mod policy;
mod sandbox;
mod tracer;

use anyhow::{Context, Result};
use clap::Parser;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use cli::{Cli, Commands};
use output::OutputManager;
use policy::Policy;
use tracer::Tracer;

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            policy: policy_path,
            allow_paths,
            allow_net,
            allow_exec,
            output,
            no_color,
            timeout,
            verbose,
            trace_only,
            follow_forks,
            command,
        } => {
            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_clone = shutdown.clone();
            ctrlc::set_handler(move || {
                shutdown_clone.store(true, Ordering::SeqCst);
            })
            .context("failed to set signal handler")?;

            let mut policy = if let Some(ref path) = policy_path {
                Policy::from_file(path).context("failed to load policy")?
            } else {
                Policy::default_restrictive()
            };

            // Merge CLI flags into policy
            for path in &allow_paths {
                let p = path.to_string_lossy().to_string();
                policy.filesystem.allow_read.push(p.clone());
                policy.filesystem.allow_write.push(p);
            }
            if allow_net {
                policy.network.allow = true;
            }
            if allow_exec {
                policy.filesystem.allow_exec.push("**".to_string());
            }

            let output_manager = OutputManager::new(output.as_deref(), no_color, verbose)?;

            let mut tracer = Tracer::new(
                command,
                policy,
                output_manager,
                trace_only,
                follow_forks,
                timeout,
                shutdown,
            );

            let exit_code = tracer.run().context("tracer failed")?;
            std::process::exit(exit_code);
        }
    }
}
