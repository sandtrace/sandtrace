pub mod builtin;
pub mod matcher;
pub mod schema;

use crate::error::{RuleError, SandtraceError};
use schema::{DetectionRule, RuleFile};
use std::path::Path;

pub struct RuleRegistry {
    rules: Vec<DetectionRule>,
}

impl RuleRegistry {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn load_builtins(&mut self) {
        self.rules.extend(builtin::all_builtin_rules());
        log::info!("Loaded {} built-in rules", self.rules.len());
    }

    pub fn load_directory(&mut self, dir: &Path) -> Result<usize, SandtraceError> {
        if !dir.exists() {
            log::debug!("Rules directory does not exist: {}", dir.display());
            return Ok(0);
        }

        let mut count = 0;
        let entries = std::fs::read_dir(dir).map_err(|e| {
            SandtraceError::Rule(RuleError::FileRead {
                path: dir.display().to_string(),
                source: e,
            })
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SandtraceError::Rule(RuleError::FileRead {
                    path: dir.display().to_string(),
                    source: e,
                })
            })?;

            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yml")
                || path.extension().and_then(|e| e.to_str()) == Some("yaml")
            {
                match self.load_file(&path) {
                    Ok(n) => count += n,
                    Err(e) => log::warn!("Failed to load rule file {}: {}", path.display(), e),
                }
            }
        }

        log::info!("Loaded {} rules from {}", count, dir.display());
        Ok(count)
    }

    pub fn load_file(&mut self, path: &Path) -> Result<usize, SandtraceError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SandtraceError::Rule(RuleError::FileRead {
                path: path.display().to_string(),
                source: e,
            })
        })?;

        let rule_file: RuleFile = serde_yml::from_str(&content).map_err(|e| {
            SandtraceError::Rule(RuleError::YamlParse(format!(
                "{}: {}",
                path.display(),
                e
            )))
        })?;

        let count = rule_file.rules.len();
        self.rules.extend(rule_file.rules);
        Ok(count)
    }

    pub fn rules(&self) -> &[DetectionRule] {
        &self.rules
    }

    pub fn into_rules(self) -> Vec<DetectionRule> {
        self.rules
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for RuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}
