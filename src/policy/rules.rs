use crate::event::{PolicyAction, SyscallCategory};
use std::collections::HashMap;

pub struct PolicyEvaluator {
    syscall_rules: HashMap<String, PolicyAction>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub action: PolicyAction,
    pub reason: String,
}

impl PolicyEvaluator {
    pub fn new() -> Self {
        Self {
            syscall_rules: HashMap::new(),
        }
    }

    pub fn add_rule(&mut self, syscall: String, action: PolicyAction) {
        self.syscall_rules.insert(syscall, action);
    }

    pub fn evaluate_syscall(&self, name: &str, category: SyscallCategory) -> RuleMatch {
        if let Some(action) = self.syscall_rules.get(name) {
            RuleMatch {
                action: *action,
                reason: format!("Explicit syscall rule for {}", name),
            }
        } else {
            // Default rules based on category
            match category {
                SyscallCategory::System => RuleMatch {
                    action: PolicyAction::Deny,
                    reason: "System category syscalls denied by default".to_string(),
                },
                _ => RuleMatch {
                    action: PolicyAction::Allow,
                    reason: "No rule matched, allowing by default".to_string(),
                },
            }
        }
    }
}

impl Default for PolicyEvaluator {
    fn default() -> Self {
        Self::new()
    }
}
