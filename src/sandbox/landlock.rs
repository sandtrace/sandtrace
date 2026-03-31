use crate::error::{Result, SandboxError};
use crate::policy::Policy;
use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
    ABI,
};
use std::path::Path;

/// Apply Landlock filesystem access control rules from the policy.
///
/// Landlock restricts which files/directories the process can access,
/// even without user namespaces. Works on Linux 5.13+ (including Ubuntu 24.04).
pub fn apply_landlock_rules(policy: &Policy) -> Result<()> {
    let read_access = AccessFs::ReadFile | AccessFs::ReadDir;
    let write_access = AccessFs::WriteFile
        | AccessFs::RemoveFile
        | AccessFs::RemoveDir
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym;
    let exec_access = AccessFs::Execute.into();
    let all_access = read_access | write_access | exec_access;

    let mut ruleset = Ruleset::default()
        .handle_access(all_access)
        .map_err(|e| SandboxError::LandlockSetup(format!("failed to create ruleset: {e}")))?
        .create()
        .map_err(|e| SandboxError::LandlockSetup(format!("failed to create ruleset: {e}")))?;

    // System paths needed by any process
    let system_read_paths = [
        "/usr",
        "/lib",
        "/lib64",
        "/etc",
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/proc",
        "/sys/kernel",
    ];

    for path_str in &system_read_paths {
        add_rule_if_exists(&mut ruleset, path_str, read_access | exec_access);
    }

    // /tmp — many tools need temp dirs
    add_rule_if_exists(&mut ruleset, "/tmp", all_access);

    // Policy allow_read paths
    for pattern in &policy.filesystem.allow_read {
        let path = resolve_glob_to_path(pattern);
        add_rule_if_exists(&mut ruleset, &path, read_access);
    }

    // Policy allow_write paths
    for pattern in &policy.filesystem.allow_write {
        let path = resolve_glob_to_path(pattern);
        add_rule_if_exists(&mut ruleset, &path, read_access | write_access);
    }

    // Policy allow_exec paths
    for pattern in &policy.filesystem.allow_exec {
        let path = resolve_glob_to_path(pattern);
        add_rule_if_exists(&mut ruleset, &path, exec_access);
    }

    // Current working directory — full access for the project being scanned
    if let Ok(cwd) = std::env::current_dir() {
        add_rule_if_exists(&mut ruleset, &cwd.to_string_lossy(), all_access);
    }

    // Enforce — from here, only allowed paths are accessible
    let status = ruleset
        .restrict_self()
        .map_err(|e| SandboxError::LandlockSetup(format!("failed to enforce: {e}")))?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            eprintln!("Landlock sandbox: fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            eprintln!("Landlock sandbox: partially enforced");
        }
        RulesetStatus::NotEnforced => {
            eprintln!("Warning: Landlock sandbox not enforced");
        }
    }

    Ok(())
}

/// Check if Landlock is supported on this kernel
pub fn check_landlock_support() -> bool {
    Ruleset::default()
        .handle_access(AccessFs::ReadFile)
        .and_then(|r| r.create())
        .is_ok()
}

fn add_rule_if_exists(
    ruleset: &mut landlock::RulesetCreated,
    path_str: &str,
    access: landlock::BitFlags<AccessFs>,
) {
    if Path::new(path_str).exists() {
        if let Ok(fd) = PathFd::new(path_str) {
            let _ = ruleset.add_rule(PathBeneath::new(fd, access));
        }
    }
}

/// Convert glob patterns to concrete paths for Landlock
fn resolve_glob_to_path(pattern: &str) -> String {
    let path = pattern
        .trim_end_matches("/**")
        .trim_end_matches("/*")
        .trim_end_matches('*');

    if path.starts_with("~/") || path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return path.replacen('~', &home, 1);
        }
    }

    path.to_string()
}
