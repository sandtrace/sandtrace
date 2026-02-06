use crate::error::{Result, SandboxError};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::Uid;
use std::fs;

/// Setup user namespace - map current user to root inside namespace
pub fn setup_user_namespace() -> Result<()> {
    // First unshare the user namespace
    unshare(CloneFlags::CLONE_NEWUSER).map_err(SandboxError::NamespaceCreation)?;

    // Map current UID to 0 (root) inside the namespace
    let uid = Uid::current();
    let uid_map = format!("0 {} 1\n", uid);
    fs::write("/proc/self/uid_map", uid_map).map_err(|e| {
        SandboxError::NamespaceCreation(nix::Error::from(e))
    })?;

    // Set up gid_map - need to disable setgroups first for unprivileged user
    let _ = fs::write("/proc/self/setgroups", "deny");
    
    let gid_map = format!("0 {} 1\n", uid);
    fs::write("/proc/self/gid_map", gid_map).map_err(|e| {
        SandboxError::NamespaceCreation(nix::Error::from(e))
    })?;

    Ok(())
}

/// Setup mount namespace - isolate filesystem view
pub fn setup_mount_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).map_err(SandboxError::NamespaceCreation)?;

    // Make all mounts private to prevent propagation
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        nix::mount::MsFlags::MS_REC | nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    ).map_err(|e| SandboxError::NamespaceCreation(e))?;

    Ok(())
}

/// Setup PID namespace - isolate process IDs
pub fn setup_pid_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWPID).map_err(SandboxError::NamespaceCreation)?;
    Ok(())
}

/// Setup network namespace - isolate network stack
pub fn setup_network_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNET).map_err(SandboxError::NamespaceCreation)?;
    Ok(())
}

/// Check if namespaces are supported
pub fn check_namespace_support() -> Result<()> {
    // Try to check if we're running as root or have CAP_SYS_ADMIN
    // For now, just assume unprivileged user namespaces work (kernel 3.8+)
    Ok(())
}
