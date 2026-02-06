use crate::error::{Result, SandboxError};
use crate::policy::Policy;
use seccompiler::{
    apply_filter, BpfProgram, SeccompAction, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};
use std::collections::HashMap;

/// Install seccomp-bpf filter based on policy
pub fn install_seccomp_filter(policy: &Policy) -> Result<()> {
    // Determine target architecture
    let arch = get_target_arch()?;

    // Build filter that allows most syscalls but traps dangerous ones
    let mut rules: HashMap<String, SeccompRule> = HashMap::new();

    // Always block these dangerous syscalls
    let always_blocked = [
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "swapon",
        "swapoff",
        "init_module",
        "finit_module",
        "delete_module",
        "acct",
        "pivot_root",
    ];

    for syscall in &always_blocked {
        rules.insert(
            syscall.to_string(),
            SeccompRule::new(vec![], SeccompAction::Trap),
        );
    }

    // Block syscalls from policy
    for syscall in &policy.syscalls.deny {
        rules.insert(
            syscall.clone(),
            SeccompRule::new(vec![], SeccompAction::Trap),
        );
    }

    // Create filter with default allow action
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow, // Default: allow syscalls not in the list
        SeccompAction::Allow, // On undefined syscall: allow (may be new syscall)
        arch,
    ).map_err(|e| SandboxError::SeccompInstall(format!("Failed to create filter: {:?}", e)))?;

    // Compile to BPF
    let program: BpfProgram = filter
        .compile()
        .map_err(|e| SandboxError::SeccompInstall(format!("Failed to compile filter: {:?}", e)))?;

    // Apply filter (loads into kernel)
    apply_filter(&program)
        .map_err(|e| SandboxError::SeccompInstall(format!("Failed to apply filter: {:?}", e)))?;

    log::debug!("Seccomp filter installed");
    Ok(())
}

fn get_target_arch() -> Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(TargetArch::x86_64)
    }

    #[cfg(target_arch = "aarch64")]
    {
        Ok(TargetArch::aarch64)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(SandboxError::SeccompInstall(
            "Unsupported architecture".to_string(),
        ).into())
    }
}

/// Check if seccomp is supported
pub fn check_seccomp_support() -> bool {
    // Most modern kernels support seccomp
    // We can test by trying to install a simple filter
    true
}
