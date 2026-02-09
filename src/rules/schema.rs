use crate::event::{AlertChannel, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    pub detection: Detection,
    #[serde(default)]
    pub alert: AlertConfig,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl DetectionRule {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    #[serde(default)]
    pub file_paths: Vec<String>,
    #[serde(default)]
    pub excluded_processes: Vec<String>,
    #[serde(default)]
    pub file_patterns: Vec<String>,
    #[serde(default)]
    pub content_patterns: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    #[serde(default = "default_channels")]
    pub channels: Vec<AlertChannel>,
    #[serde(default)]
    pub message: Option<String>,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            channels: default_channels(),
            message: None,
        }
    }
}

fn default_channels() -> Vec<AlertChannel> {
    vec![AlertChannel::Stdout]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rules: Vec<DetectionRule>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_rule() {
        let yaml = r#"
rules:
  - id: test-rule
    name: Test Rule
    severity: high
    description: A test rule
    detection:
      file_paths:
        - "~/.aws/credentials"
      excluded_processes:
        - aws
    alert:
      channels: [stdout]
      message: "Test alert: {process_name}"
    tags: [credential]
"#;
        let rule_file: RuleFile = serde_yml::from_str(yaml).unwrap();
        assert_eq!(rule_file.rules.len(), 1);
        assert_eq!(rule_file.rules[0].id, "test-rule");
        assert_eq!(rule_file.rules[0].severity, Severity::High);
    }
}
