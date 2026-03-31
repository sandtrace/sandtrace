use crate::cli::RunArgs;
use crate::error::{Result, SandboxError};
use crate::policy::Policy;

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
///
/// In trace-only mode, namespace creation is best-effort — if the kernel
/// blocks it (e.g., Ubuntu 24.04 AppArmor userns restrictions), we skip
/// the sandbox and continue with ptrace tracing only.
pub fn apply_child_sandbox(config: &SandboxConfig) -> Result<()> {
    let sandbox_available = try_setup_namespaces(config);

    if !sandbox_available && !config.trace_only {
        // Full sandbox mode requires namespaces — can't proceed without them
        return Err(SandboxError::NamespaceCreation(nix::Error::EPERM).into());
    }

    // 5. PR_SET_NO_NEW_PRIVS - prevent privilege escalation
    // Required for Landlock enforcement even without namespaces
    capabilities::set_no_new_privs()?;

    if sandbox_available {
        // Full sandbox: namespaces + Landlock + seccomp
        if !config.trace_only {
            landlock::apply_landlock_rules(&config.policy)?;
            seccomp::install_seccomp_filter(&config.policy)?;
        }
    } else if landlock::check_landlock_support() {
        // Fallback: no namespaces but Landlock works — apply filesystem restrictions
        eprintln!(
            "Warning: namespace sandbox unavailable — using Landlock filesystem \
             isolation only (no network/PID isolation)"
        );
        landlock::apply_landlock_rules(&config.policy)?;
    } else {
        if config.trace_only {
            eprintln!(
                "Warning: no sandbox available on this kernel — \
                 running with ptrace tracing only"
            );
        } else {
            // Can't sandbox at all — refuse to run in full mode
            return Err(SandboxError::NamespaceCreation(nix::Error::EPERM).into());
        }
    }

    // 8. ptrace TRACEME + SIGSTOP - signal readiness to tracer
    setup_ptrace_traceme()?;

    Ok(())
}

/// Try to set up namespace isolation. Returns true if successful, false if
/// the kernel blocked namespace creation (common on Ubuntu 24.04+ with
/// AppArmor userns restrictions).
fn try_setup_namespaces(config: &SandboxConfig) -> bool {
    // 1. User namespace - must be first to gain capabilities
    if namespaces::setup_user_namespace().is_err() {
        return false;
    }

    // 2. Mount namespace - restrict filesystem view
    if namespaces::setup_mount_namespace().is_err() {
        return false;
    }

    // 3. PID namespace - hide host processes
    if namespaces::setup_pid_namespace().is_err() {
        return false;
    }

    // 4. Network namespace - no network by default
    if !config.policy.network.allow {
        if namespaces::setup_network_namespace().is_err() {
            return false;
        }
    }

    true
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
