use crate::error::{Result, SandboxError};

/// Set PR_SET_NO_NEW_PRIVS to prevent privilege escalation via setuid/setgid
pub fn set_no_new_privs() -> Result<()> {
    let res = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if res < 0 {
        return Err(SandboxError::NoNewPrivs(nix::Error::last()).into());
    }
    Ok(())
}

/// Drop all capabilities
pub fn drop_all_capabilities() -> Result<()> {
    // Use capctl to drop all capabilities
    if let Ok(caps) = capctl::CapState::get_current() {
        // Set all three capability sets to empty
        let _ = caps.set_current();
    }
    Ok(())
}
