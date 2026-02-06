use crate::error::{PolicyError, Result};
use crate::event::{PolicyAction, SyscallCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub mod parser;
pub mod rules;

pub use parser::parse_policy_file;
pub use rules::{PolicyEvaluator, RuleMatch};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub network: NetworkPolicy,
    #[serde(default)]
    pub syscalls: SyscallPolicy,
    #[serde(default)]
    pub limits: LimitsPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allow_read: Vec<String>,
    #[serde(default)]
    pub allow_write: Vec<String>,
    #[serde(default)]
    pub allow_exec: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallPolicy {
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub log_only: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsPolicy {
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_file_size: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_processes: Option<u32>,
}

fn default_timeout() -> u64 {
    30
}

impl Default for Policy {
    fn default() -> Self {
        Self::default_restrictive()
    }
}

impl Policy {
    pub fn default_restrictive() -> Self {
        Policy {
            filesystem: FilesystemPolicy {
                allow_read: vec![
                    "/usr".to_string(),
                    "/lib".to_string(),
                    "/lib64".to_string(),
                    "/etc/ld.so.cache".to_string(),
                    "/etc/localtime".to_string(),
                    "/dev/null".to_string(),
                    "/dev/zero".to_string(),
                    "/dev/urandom".to_string(),
                    "/proc/self".to_string(),
                ],
                allow_write: vec![],
                allow_exec: vec![],
                deny: vec![
                    "/home/*/.ssh".to_string(),
                    "/etc/shadow".to_string(),
                    "/etc/gshadow".to_string(),
                    "**/.env".to_string(),
                ],
            },
            network: NetworkPolicy { allow: false },
            syscalls: SyscallPolicy {
                deny: vec![
                    "mount".to_string(),
                    "umount2".to_string(),
                    "ptrace".to_string(),
                    "kexec_load".to_string(),
                    "kexec_file_load".to_string(),
                    "reboot".to_string(),
                    "init_module".to_string(),
                    "finit_module".to_string(),
                    "delete_module".to_string(),
                ],
                log_only: vec![],
            },
            limits: LimitsPolicy {
                timeout: 30,
                max_file_size: None,
                max_processes: None,
            },
        }
    }

    pub fn merge_cli_args(&mut self, args: &crate::cli::RunArgs) {
        // Merge allow paths
        for path in &args.allow_paths {
            let path_str = path.to_string_lossy().to_string();
            if !self.filesystem.allow_read.contains(&path_str) {
                self.filesystem.allow_read.push(path_str.clone());
            }
            if !self.filesystem.allow_write.contains(&path_str) {
                self.filesystem.allow_write.push(path_str);
            }
        }

        // Network
        if args.allow_net {
            self.network.allow = true;
        }

        // Timeout
        self.limits.timeout = args.timeout;
    }

    pub fn is_path_allowed(&self, path: &Path, access: PathAccess) -> PolicyAction {
        let path_str = path.to_string_lossy();

        // Check deny list first (deny overrides allow)
        for pattern in &self.filesystem.deny {
            if let Ok(glob) = glob::Pattern::new(pattern) {
                if glob.matches(&path_str) {
                    return PolicyAction::Deny;
                }
            }
        }

        // Check specific allow lists based on access type
        let allowed_paths = match access {
            PathAccess::Read => &self.filesystem.allow_read,
            PathAccess::Write => &self.filesystem.allow_write,
            PathAccess::Execute => &self.filesystem.allow_exec,
        };

        for pattern in allowed_paths {
            if let Ok(glob) = glob::Pattern::new(pattern) {
                if glob.matches(&path_str) {
                    return PolicyAction::Allow;
                }
            }
        }

        // Default deny for write, default allow for read if in /usr, /lib, etc.
        match access {
            PathAccess::Write => PolicyAction::Deny,
            PathAccess::Execute => PolicyAction::Allow, // More permissive for exec
            PathAccess::Read => {
                // Allow reading from standard system paths
                let system_prefixes = ["/usr/", "/lib", "/etc/ld.so", "/dev/", "/proc/"];
                for prefix in &system_prefixes {
                    if path_str.starts_with(prefix) {
                        return PolicyAction::Allow;
                    }
                }
                PolicyAction::Deny
            }
        }
    }

    pub fn get_syscall_action(&self, syscall_name: &str) -> PolicyAction {
        // Hardcoded dangerous syscalls
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

        if always_blocked.contains(&syscall_name) {
            return PolicyAction::Deny;
        }

        // Policy-configured denials
        if self.syscalls.deny.iter().any(|s| s == syscall_name) {
            return PolicyAction::Deny;
        }

        // Log-only syscalls
        if self.syscalls.log_only.iter().any(|s| s == syscall_name) {
            return PolicyAction::LogOnly;
        }

        PolicyAction::Allow
    }
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            allow_read: vec![],
            allow_write: vec![],
            allow_exec: vec![],
            deny: vec![],
        }
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self { allow: false }
    }
}

impl Default for SyscallPolicy {
    fn default() -> Self {
        Self {
            deny: vec![],
            log_only: vec![],
        }
    }
}

impl Default for LimitsPolicy {
    fn default() -> Self {
        Self {
            timeout: default_timeout(),
            max_file_size: None,
            max_processes: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAccess {
    Read,
    Write,
    Execute,
}
