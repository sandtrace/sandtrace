use crate::cli::RunArgs;
use crate::error::{Result, SandboxError};
use crate::policy::{Policy};

pub mod capabilities;
pub mod landlock;
pub mod namespaces;
pub mod seccomp;

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    pub policy: Policy,
    pub trace_only: bool,
    pub command: Vec<String>,
}

impl SandboxConfig {
    pub fn from_args(args: &RunArgs) -> Result<Self> {
        let policy = if let Some(policy_path) = &args.policy {
            let mut policy = crate::policy::parse_policy_file(policy_path)?;
            policy.merge_cli_args(args);
            policy
        } else {
            let mut policy = Policy::default_restrictive();
            policy.merge_cli_args(args);
            policy
        };

        Ok(Self {
            policy,
            trace_only: args.trace_only,
            command: args.command.clone(),
        })
    }
}

/// Apply all sandbox layers in the child process after fork.
/// This must be called in the child before execve.
pub fn apply_child_sandbox(config: &SandboxConfig) -> Result<()> {
    // 1. User namespace - must be first to gain capabilities
    namespaces::setup_user_namespace()?;

    // 2. Mount namespace - restrict filesystem view
    namespaces::setup_mount_namespace()?;

    // 3. PID namespace - hide host processes
    namespaces::setup_pid_namespace()?;

    // 4. Network namespace - no network by default
    if !config.policy.network.allow {
        namespaces::setup_network_namespace()?;
    }

    // 5. PR_SET_NO_NEW_PRIVS - prevent privilege escalation
    capabilities::set_no_new_privs()?;

    // 6. Landlock - kernel-level filesystem access control (if not trace-only)
    if !config.trace_only {
        landlock::apply_landlock_rules(&config.policy)?;
    }

    // 7. seccomp-bpf - block dangerous syscalls (if not trace-only)
    if !config.trace_only {
        seccomp::install_seccomp_filter(&config.policy)?;
    }

    // 8. ptrace TRACEME + SIGSTOP - signal readiness to tracer
    setup_ptrace_traceme()?;

    Ok(())
}

fn setup_ptrace_traceme() -> Result<()> {
    if let Err(e) = nix::sys::ptrace::traceme() {
        return Err(SandboxError::Ptrace(e).into());
    }

    // Raise SIGSTOP to wait for tracer to attach
    if let Err(e) = nix::sys::signal::raise(nix::sys::signal::SIGSTOP) {
        return Err(SandboxError::Ptrace(e).into());
    }

    Ok(())
}
