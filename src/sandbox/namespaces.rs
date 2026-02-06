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
    if let Err(e) = fs::write("/proc/self/uid_map", uid_map) {
        return Err(SandboxError::NamespaceCreation(nix::Error::from_raw(e.raw_os_error().unwrap_or(1))).into());
    }

    // Set up gid_map - need to disable setgroups first for unprivileged user
    let _ = fs::write("/proc/self/setgroups", "deny");
    
    let gid_map = format!("0 {} 1\n", uid);
    if let Err(e) = fs::write("/proc/self/gid_map", gid_map) {
        return Err(SandboxError::NamespaceCreation(nix::Error::from_raw(e.raw_os_error().unwrap_or(1))).into());
    }

    Ok(())
}

/// Setup mount namespace - isolate filesystem view
pub fn setup_mount_namespace() -> Result<()> {
    unshare(CloneFlags::CLONE_NEWNS).map_err(SandboxError::NamespaceCreation)?;

    // Make all mounts private to prevent propagation
    let res = unsafe {
        libc::mount(
            std::ptr::null(),
            "/".as_ptr() as *const libc::c_char,
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    };

    if res < 0 {
        return Err(SandboxError::NamespaceCreation(nix::Error::last()).into());
    }

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
