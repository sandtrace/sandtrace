use crate::event::{FileAccessEvent, FileAccessType, RuleMatchEvent, Severity};
use crate::error::{RuleError, SandtraceError};
use super::schema::DetectionRule;
use chrono::Utc;
use regex::Regex;
use std::path::Path;

pub struct RuleMatcher {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    rule: DetectionRule,
    file_path_patterns: Vec<glob::Pattern>,
    excluded_process_patterns: Vec<String>,
    content_regexes: Vec<Regex>,
    /// Empty means match all access types
    access_types: Vec<FileAccessType>,
}

impl RuleMatcher {
    pub fn new(rules: Vec<DetectionRule>) -> Result<Self, SandtraceError> {
        let compiled = rules
            .into_iter()
            .filter(|r| r.is_enabled())
            .map(|rule| compile_rule(rule))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { rules: compiled })
    }

    pub fn match_file_access(&self, event: &FileAccessEvent) -> Vec<RuleMatchEvent> {
        let mut matches = Vec::new();

        for compiled in &self.rules {
            if !self.file_path_matches(compiled, &event.path) {
                continue;
            }

            // Filter by access type if the rule specifies them
            if !compiled.access_types.is_empty()
                && !compiled.access_types.contains(&event.access_type)
            {
                continue;
            }

            if let Some(ref proc_name) = event.process_name {
                if compiled.excluded_process_patterns.iter().any(|p| p == proc_name) {
                    continue;
                }
            }

            let message = compiled
                .rule
                .alert
                .message
                .as_deref()
                .unwrap_or(&compiled.rule.description)
                .replace("{process_name}", event.process_name.as_deref().unwrap_or("unknown"))
                .replace("{pid}", &event.pid.map_or("?".to_string(), |p| p.to_string()))
                .replace("{path}", &event.path);

            matches.push(RuleMatchEvent {
                timestamp: Utc::now(),
                rule_id: compiled.rule.id.clone(),
                rule_name: compiled.rule.name.clone(),
                severity: compiled.rule.severity,
                description: message,
                matched_data: anonymize_path(&event.path),
                file_path: event.path.clone(),
                access_type: Some(event.access_type),
                process_name: event.process_name.clone(),
                pid: event.pid,
                process_lineage: event.process_lineage.clone(),
                alert_channels: compiled.rule.alert.channels.clone(),
            });
        }

        matches
    }

    pub fn match_content(&self, file_path: &str, content: &str) -> Vec<ContentMatch> {
        let mut matches = Vec::new();

        for compiled in &self.rules {
            for regex in &compiled.content_regexes {
                for mat in regex.find_iter(content) {
                    let line_number = content[..mat.start()].lines().count() + 1;
                    matches.push(ContentMatch {
                        rule_id: compiled.rule.id.clone(),
                        rule_name: compiled.rule.name.clone(),
                        severity: compiled.rule.severity,
                        description: compiled.rule.description.clone(),
                        file_path: file_path.to_string(),
                        line_number,
                        matched_text: mat.as_str().to_string(),
                    });
                }
            }
        }

        matches
    }

    pub fn rules_for_watch_paths(&self) -> Vec<String> {
        let mut paths = Vec::new();
        for compiled in &self.rules {
            for pattern in &compiled.rule.detection.file_paths {
                let expanded = expand_tilde(pattern);
                paths.push(expanded);
            }
        }
        paths
    }

    fn file_path_matches(&self, compiled: &CompiledRule, path: &str) -> bool {
        compiled.file_path_patterns.iter().any(|p| p.matches(path))
    }
}

#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub description: String,
    pub file_path: String,
    pub line_number: usize,
    pub matched_text: String,
}

fn compile_rule(rule: DetectionRule) -> Result<CompiledRule, SandtraceError> {
    let file_path_patterns = rule
        .detection
        .file_paths
        .iter()
        .map(|p| {
            let expanded = expand_tilde(p);
            glob::Pattern::new(&expanded).map_err(|e| {
                SandtraceError::Rule(RuleError::InvalidRule(format!(
                    "Invalid glob pattern '{}': {}",
                    p, e
                )))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let content_regexes = rule
        .detection
        .content_patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| {
                SandtraceError::Rule(RuleError::InvalidRegex {
                    pattern: p.clone(),
                    source: e,
                })
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let access_types: Vec<FileAccessType> = rule
        .detection
        .access_types
        .iter()
        .filter_map(|s| match s.to_lowercase().as_str() {
            "read" => Some(FileAccessType::Read),
            "write" => Some(FileAccessType::Write),
            "delete" => Some(FileAccessType::Delete),
            "chmod" => Some(FileAccessType::Chmod),
            "create" => Some(FileAccessType::Create),
            _ => None,
        })
        .collect();

    Ok(CompiledRule {
        excluded_process_patterns: rule.detection.excluded_processes.clone(),
        rule,
        file_path_patterns,
        content_regexes,
        access_types,
    })
}

fn expand_tilde(path: &str) -> String {
    if path.starts_with("~/") {
        if let Some(home) = dirs_home() {
            return format!("{}{}", home, &path[1..]);
        }
    }
    path.to_string()
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

fn anonymize_path(path: &str) -> String {
    let p = Path::new(path);
    if let Some(parent) = p.parent() {
        format!("{}/*", parent.display())
    } else {
        "*".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::schema::{AlertConfig, Detection};

    fn test_rule() -> DetectionRule {
        DetectionRule {
            id: "test-cred".to_string(),
            name: "Test Credential Rule".to_string(),
            severity: Severity::High,
            description: "Test access by {process_name}".to_string(),
            detection: Detection {
                file_paths: vec!["/home/*/.aws/credentials".to_string()],
                excluded_processes: vec!["aws".to_string()],
                file_patterns: vec![],
                content_patterns: vec![],
                process_names: vec![],
                condition: None,
                access_types: vec![],
            },
            alert: AlertConfig::default(),
            tags: vec!["credential".to_string()],
            enabled: Some(true),
        }
    }

    #[test]
    fn test_matcher_matches_file_access() {
        let matcher = RuleMatcher::new(vec![test_rule()]).unwrap();
        let event = FileAccessEvent {
            timestamp: Utc::now(),
            path: "/home/user/.aws/credentials".to_string(),
            access_type: crate::event::FileAccessType::Read,
            pid: Some(1234),
            process_name: Some("curl".to_string()),
            process_lineage: vec![],
        };
        let matches = matcher.match_file_access(&event);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_id, "test-cred");
    }

    #[test]
    fn test_matcher_excludes_process() {
        let matcher = RuleMatcher::new(vec![test_rule()]).unwrap();
        let event = FileAccessEvent {
            timestamp: Utc::now(),
            path: "/home/user/.aws/credentials".to_string(),
            access_type: crate::event::FileAccessType::Read,
            pid: Some(1234),
            process_name: Some("aws".to_string()),
            process_lineage: vec![],
        };
        let matches = matcher.match_file_access(&event);
        assert!(matches.is_empty());
    }
}
