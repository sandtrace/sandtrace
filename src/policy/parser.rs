use super::Policy;
use crate::error::{PolicyError, Result};
use std::fs;
use std::path::Path;

pub fn parse_policy_file(path: &Path) -> Result<Policy> {
    let content = fs::read_to_string(path).map_err(|e| PolicyError::FileRead {
        path: path.display().to_string(),
        source: e,
    })?;

    let policy: Policy = toml::from_str(&content)
        .map_err(|e| PolicyError::Parse(e))?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_policy() {
        let policy = Policy::default_restrictive();
        assert!(!policy.network.allow);
        assert!(policy.limits.timeout > 0);
    }

    #[test]
    fn test_parse_toml_policy() {
        let toml_str = r#"
[filesystem]
allow_read = ["/usr", "/lib"]
allow_write = ["/tmp/output"]
deny = ["/etc/shadow"]

[network]
allow = true

[syscalls]
deny = ["mount"]
log_only = ["mprotect"]

[limits]
timeout = 60
"#;

        let policy: Policy = toml::from_str(toml_str).unwrap();
        assert_eq!(policy.filesystem.allow_read.len(), 2);
        assert!(policy.network.allow);
        assert_eq!(policy.limits.timeout, 60);
    }
}
