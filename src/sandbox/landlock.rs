use crate::error::{Result, SandboxError};
use crate::policy::{Policy, PathAccess};
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
    RulesetStatus, ABI,
};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Apply Landlock rules from policy
pub fn apply_landlock_rules(policy: &Policy) -> Result<()> {
    // Determine the best ABI version
    let abi = ABI::V1; // Start with v1 for compatibility

    // Create ruleset with all file access rights
    let ruleset = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::LandlockSetup(format!("Failed to create ruleset: {}", e)))?;

    let ruleset = ruleset.create()
        .map_err(|e| SandboxError::LandlockSetup(format!("Failed to create ruleset: {}", e)))?;

    // Add allowed read paths
    let mut ruleset = ruleset;
    for path_str in &policy.filesystem.allow_read {
        let path = Path::new(path_str);
        if path.exists() {
            let access = AccessFs::ReadFile | AccessFs::ReadDir | AccessFs::Execute;
            ruleset = add_path_rule(ruleset, path, access)?;
        }
    }

    // Add allowed write paths
    for path_str in &policy.filesystem.allow_write {
        let path = Path::new(path_str);
        if path.exists() {
            let access = AccessFs::WriteFile
                | AccessFs::ReadFile
                | AccessFs::ReadDir
                | AccessFs::MakeReg
                | AccessFs::MakeDir;
            ruleset = add_path_rule(ruleset, path, access)?;
        }
    }

    // Restrict self - this applies the ruleset
    let status = ruleset.restrict_self()
        .map_err(|e| SandboxError::LandlockSetup(format!("Failed to restrict self: {}", e)))?;

    match status {
        RulesetStatus::FullyEnforced => {
            log::debug!("Landlock fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            log::warn!("Landlock partially enforced - some features may not work");
        }
        RulesetStatus::NotEnforced => {
            log::warn!("Landlock not enforced - kernel may not support it");
        }
    }

    Ok(())
}

fn add_path_rule(
    ruleset: landlock::RulesetCreated,
    path: &Path,
    access: AccessFs,
) -> Result<landlock::RulesetCreated> {
    let ruleset = ruleset
        .add_rules(path_beneath_rules(
            [path],
            access,
        ))
        .map_err(|e| SandboxError::LandlockSetup(format!("Failed to add rule: {}", e)))?;

    Ok(ruleset)
}

/// Check if Landlock is supported on this kernel
pub fn check_landlock_support() -> bool {
    match Ruleset::new().create() {
        Ok(_) => true,
        Err(_) => false,
    }
}
