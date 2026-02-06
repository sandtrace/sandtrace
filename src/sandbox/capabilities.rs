use crate::error::{Result, SandboxError};
use capctl::prctl;

/// Set PR_SET_NO_NEW_PRIVS to prevent privilege escalation via setuid/setgid
pub fn set_no_new_privs() -> Result<()> {
    prctl::set_no_new_privs(true)
        .map_err(|e| SandboxError::NoNewPrivs(nix::Error::from_raw(e.raw_os_error().unwrap_or(1))))?;
    Ok(())
}

/// Drop all capabilities
pub fn drop_all_capabilities() -> Result<()> {
    // In a user namespace with UID 0, we have all capabilities
    // But we want to drop them to be safe
    if let Ok(caps) = capctl::CapState::get_current() {
        let empty = capctl::caps::FullCapSet::empty();
        let _ = caps.set_current(
            capctl::caps::CapSet::empty(),
            capctl::caps::CapSet::empty(),
            empty,
            capctl::caps::CapSet::empty(),
        );
    }
    Ok(())
}

/// Check if we're in a user namespace with root privileges
pub fn has_capability(cap: capctl::caps::Cap) -> bool {
    capctl::CapState::get_current()
        .map(|state| state.effective.has(cap))
        .unwrap_or(false)
}
