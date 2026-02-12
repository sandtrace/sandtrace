pub mod advanced;
pub mod encoding;
pub mod supply_chain;

use crate::config::ObfuscationConfig;
use crate::event::{AuditFinding, Severity};
use std::path::Path;

// --- Shared infrastructure ---

/// Dangerous function/command names used by multiple rules (3, 5, 13, 14).
pub const DANGEROUS_FUNCS: &[&str] = &[
    "eval",
    "exec",
    "system",
    "require",
    "import",
    "function",
    "settimeout",
    "setinterval",
    "shell_exec",
    "passthru",
    "popen",
    "proc_open",
    "curl",
    "wget",
    "fetch",
];

/// Homoglyph character ranges shared between content scanner and filename scanner.
pub const HOMOGLYPH_RANGES: &[(char, char, &str)] = &[
    ('\u{0410}', '\u{044F}', "Cyrillic"), // А-я (looks like A-a)
    ('\u{0391}', '\u{03C9}', "Greek"),    // Α-ω
];

/// Check if a file has one of the given extensions.
pub fn is_language(path: &Path, extensions: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| extensions.iter().any(|e| ext.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

/// Compute Levenshtein edit distance between two strings.
pub fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();
    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev: Vec<usize> = (0..=b_len).collect();
    let mut curr = vec![0usize; b_len + 1];

    for (i, ca) in a.chars().enumerate() {
        curr[0] = i + 1;
        for (j, cb) in b.chars().enumerate() {
            let cost = if ca == cb { 0 } else { 1 };
            curr[j + 1] = (prev[j + 1] + 1).min(curr[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[b_len]
}

/// ROT13 decode a string.
pub fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}

// --- Existing detection logic ---

/// Patterns that indicate the hidden portion of a long line is actually malicious,
/// not just a normal long SQL statement or seed data array.
const SUSPICIOUS_PATTERNS: &[&str] = &[
    // Code execution / injection
    "eval(",
    "exec(",
    "system(",
    "passthru(",
    "shell_exec(",
    "atob(",
    "btoa(",
    "base64_decode(",
    "base64_encode(",
    "document.write(",
    "innerhtml",
    "outerhtml",
    "importscripts(",
    // Shell commands
    "curl ",
    "wget ",
    "nc ",
    "bash ",
    "/bin/sh",
    "/bin/bash",
    "powershell",
    "cmd.exe",
    // XSS / injection
    "<script",
    "javascript:",
    "onerror=",
    "onload=",
    // Hex/unicode escapes (obfuscation)
    "\\x",
    "\\u00",
];

/// File extensions where long lines are expected and hidden-content checks produce false positives.
const NON_EXECUTABLE_EXTENSIONS: &[&str] = &[
    "md", "markdown", "txt", "rst", "adoc", "csv", "tsv", "log", "json", "yaml", "yml", "toml",
    "xml", "html", "htm", "svg", "lock", "sum", "mod", "snap", "png", "jpg", "jpeg", "gif", "ico",
    "woff", "woff2", "ttf", "eot", "map", "min.js", "min.css",
];

fn is_non_executable(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    // Check compound extensions like .min.js
    for ext in NON_EXECUTABLE_EXTENSIONS {
        if name.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    false
}

/// Detect minified/bundled files where long lines are the norm, not steganography.
/// If any line exceeds 5000 chars, it's bundled/minified code — not a steganographic attack.
fn is_minified(lines: &[&str]) -> bool {
    lines.iter().any(|line| line.len() > 5000)
}

/// Main entry point: scan a file for obfuscation patterns.
///
/// Reads raw bytes first for polyglot detection, then converts to string for
/// line-by-line analysis. Binary files that fail UTF-8 conversion get filesystem
/// checks only (symlinks, filename homoglyphs, dotfiles) then return early.
pub fn scan_file(
    path: &Path,
    obfuscation_config: &ObfuscationConfig,
) -> Result<Vec<AuditFinding>, std::io::Error> {
    let file_path_str = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    // Filesystem-level checks (work on any file, including binary)
    // Rule 11: Symlink attack
    if let Some(finding) = advanced::check_symlink(path) {
        findings.push(finding);
    }

    // Rule 12: Filename homoglyph
    if let Some(finding) = advanced::check_filename_homoglyph(path) {
        findings.push(finding);
    }

    // Rule 22: Suspicious dotfile
    if let Some(finding) = advanced::check_suspicious_dotfile(path) {
        findings.push(finding);
    }

    // Read raw bytes for polyglot detection
    let raw_bytes = std::fs::read(path)?;

    // Rule 10: Polyglot detection (binary magic bytes in source files)
    if let Some(finding) = advanced::check_polyglot(&raw_bytes, &file_path_str, path) {
        findings.push(finding);
    }

    // Convert to UTF-8 string; if it fails, the file is binary — return filesystem findings only
    let content = match String::from_utf8(raw_bytes) {
        Ok(s) => s,
        Err(_) => return Ok(findings),
    };

    let max_trailing = obfuscation_config.max_trailing_spaces;
    let steg_column = obfuscation_config.steganographic_column;

    let lines: Vec<&str> = content.lines().collect();
    let skip_hidden_content = is_non_executable(path) || is_minified(&lines);

    for (i, line) in lines.iter().enumerate() {
        let line_number = i + 1;

        // Inline suppression: previous line contains @sandtrace-ignore or sandtrace:ignore
        if i > 0 {
            let prev = lines[i - 1].to_lowercase();
            if prev.contains("@sandtrace-ignore") || prev.contains("sandtrace:ignore") {
                continue;
            }
        }

        // 1. Excessive trailing whitespace (steganographic payload indicator)
        let trailing_spaces = line.len() - line.trim_end().len();
        if trailing_spaces > max_trailing {
            findings.push(AuditFinding {
                file_path: file_path_str.clone(),
                line_number: Some(line_number),
                rule_id: "obfuscation-trailing-whitespace".to_string(),
                severity: Severity::High,
                description: format!(
                    "Excessive trailing whitespace ({} spaces) — possible steganographic payload",
                    trailing_spaces
                ),
                matched_pattern: format!("{} trailing spaces", trailing_spaces),
                context_lines: vec![format!(
                    "{}[{} trailing spaces hidden]",
                    line.trim_end(),
                    trailing_spaces
                )],
            });
        }

        // 2. Content past steganographic column (hidden payload past visible area)
        let char_count = line.chars().count();
        if !skip_hidden_content && char_count > steg_column {
            let visible: String = line.chars().take(steg_column).collect();
            let hidden: String = line.chars().skip(steg_column).collect();
            if !hidden.trim().is_empty() {
                let hidden_lower = hidden.to_lowercase();
                let is_suspicious = SUSPICIOUS_PATTERNS.iter().any(|p| hidden_lower.contains(p));

                if is_suspicious {
                    let visible_preview: String = visible.chars().take(80).collect();
                    let hidden_preview: String = hidden.chars().take(80).collect();
                    findings.push(AuditFinding {
                        file_path: file_path_str.clone(),
                        line_number: Some(line_number),
                        rule_id: "obfuscation-hidden-content".to_string(),
                        severity: Severity::Critical,
                        description: format!(
                            "Suspicious hidden content past column {} ({} hidden chars)",
                            steg_column,
                            hidden.len()
                        ),
                        matched_pattern: format!("suspicious content past column {}", steg_column),
                        context_lines: vec![
                            format!("visible: {}...", visible_preview),
                            format!("hidden:  {}", hidden_preview),
                        ],
                    });
                }
            }
        }

        // 3. Zero-width and invisible unicode characters
        check_invisible_chars(line, line_number, &file_path_str, &mut findings);

        // --- New rules: Tier 1 (encoding) ---
        encoding::scan_line(line, line_number, &file_path_str, path, &mut findings);

        // --- New rules: Tier 2 (advanced) ---
        advanced::scan_line(line, line_number, &file_path_str, path, &mut findings);

        // --- New rules: Tier 3 (supply chain per-line) ---
        supply_chain::scan_line(line, line_number, &file_path_str, path, &mut findings);
    }

    // 4. Base64-encoded content in unexpected file types
    check_base64_content(&content, &file_path_str, path, &mut findings);

    // 5. Unicode homoglyphs in source code
    check_homoglyphs(&content, &file_path_str, &lines, &mut findings);

    Ok(findings)
}

fn check_invisible_chars(
    line: &str,
    line_number: usize,
    file_path: &str,
    findings: &mut Vec<AuditFinding>,
) {
    let invisible_chars: Vec<(usize, char, &str)> = line
        .char_indices()
        .filter_map(|(idx, ch)| {
            let name = match ch {
                '\u{200B}' => Some("ZERO WIDTH SPACE"),
                '\u{200C}' => Some("ZERO WIDTH NON-JOINER"),
                '\u{200D}' => {
                    // ZWJ between non-ASCII chars is likely emoji (e.g. 👨‍👩‍👧)
                    // Only flag ZWJ between ASCII chars (suspicious injection)
                    let prev_is_ascii = idx > 0
                        && line[..idx]
                            .chars()
                            .next_back()
                            .is_some_and(|c| c.is_ascii());
                    let next_is_ascii = line[idx + ch.len_utf8()..]
                        .chars()
                        .next()
                        .is_some_and(|c| c.is_ascii());
                    if prev_is_ascii && next_is_ascii {
                        Some("ZERO WIDTH JOINER")
                    } else {
                        None // Likely emoji ZWJ sequence
                    }
                }
                '\u{FEFF}' => Some("ZERO WIDTH NO-BREAK SPACE (BOM)"),
                '\u{2060}' => Some("WORD JOINER"),
                '\u{2061}' => Some("FUNCTION APPLICATION"),
                '\u{2062}' => Some("INVISIBLE TIMES"),
                '\u{2063}' => Some("INVISIBLE SEPARATOR"),
                '\u{2064}' => Some("INVISIBLE PLUS"),
                '\u{00AD}' => Some("SOFT HYPHEN"),
                '\u{034F}' => Some("COMBINING GRAPHEME JOINER"),
                '\u{180E}' => Some("MONGOLIAN VOWEL SEPARATOR"),
                '\u{061C}' => Some("ARABIC LETTER MARK"),
                '\u{202A}'..='\u{202E}' => Some("BIDI CONTROL"),
                '\u{2066}'..='\u{2069}' => Some("BIDI ISOLATE"),
                _ => None,
            };
            name.map(|n| (idx, ch, n))
        })
        .collect();

    if !invisible_chars.is_empty() {
        let descriptions: Vec<String> = invisible_chars
            .iter()
            .map(|(idx, _, name)| format!("{} at col {}", name, idx))
            .collect();

        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-invisible-chars".to_string(),
            severity: Severity::Critical,
            description: format!(
                "Invisible/zero-width characters detected: {}",
                descriptions.join(", ")
            ),
            matched_pattern: "invisible unicode".to_string(),
            context_lines: descriptions,
        });
    }
}

fn check_base64_content(
    content: &str,
    file_path: &str,
    path: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    // Only flag base64 in source files (not JSON, YAML configs where it's expected)
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if matches!(
        ext,
        "json" | "yaml" | "yml" | "toml" | "xml" | "pem" | "crt" | "key"
    ) {
        return;
    }

    let base64_regex = regex::Regex::new(r"(?m)^[A-Za-z0-9+/]{100,}={0,2}$").unwrap();

    for mat in base64_regex.find_iter(content) {
        let line_number = content[..mat.start()].lines().count();

        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-base64".to_string(),
            severity: Severity::Medium,
            description: format!(
                "Large base64-encoded blob ({} chars) in source file",
                mat.as_str().len()
            ),
            matched_pattern: "base64 blob".to_string(),
            context_lines: vec![format!(
                "{}...",
                &mat.as_str()[..60.min(mat.as_str().len())]
            )],
        });
    }
}

fn check_homoglyphs(
    _content: &str,
    file_path: &str,
    lines: &[&str],
    findings: &mut Vec<AuditFinding>,
) {
    for (i, line) in lines.iter().enumerate() {
        let line_number = i + 1;
        let mut found_homoglyphs = Vec::new();

        for ch in line.chars() {
            for (start, end, script) in HOMOGLYPH_RANGES {
                if ch >= *start && ch <= *end {
                    found_homoglyphs.push(format!("U+{:04X} ({})", ch as u32, script));
                }
            }
        }

        if !found_homoglyphs.is_empty() {
            // Only flag if the file also contains ASCII — a mixed-script file is suspicious
            let has_ascii = line.chars().any(|c| c.is_ascii_alphabetic());
            if has_ascii {
                findings.push(AuditFinding {
                    file_path: file_path.to_string(),
                    line_number: Some(line_number),
                    rule_id: "obfuscation-homoglyph".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "Unicode homoglyph characters mixed with ASCII: {}",
                        found_homoglyphs.join(", ")
                    ),
                    matched_pattern: "mixed-script homoglyphs".to_string(),
                    context_lines: vec![line.to_string()],
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_obfuscation_config() -> ObfuscationConfig {
        ObfuscationConfig::default()
    }

    #[test]
    fn test_detect_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Write a line with 30 trailing spaces
        write!(file, "const x = 1;{}", " ".repeat(30)).unwrap();

        let findings = scan_file(&file_path, &test_obfuscation_config()).unwrap();
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-trailing-whitespace"));
    }

    #[test]
    fn test_detect_hidden_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Write visible content + hidden content past column 200
        let config = test_obfuscation_config();
        let visible = "const x = 1;";
        let padding = " ".repeat(config.steganographic_column - visible.len());
        let hidden = "eval(atob('malicious'))";
        write!(file, "{}{}{}", visible, padding, hidden).unwrap();

        let findings = scan_file(&file_path, &config).unwrap();
        let hidden_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "obfuscation-hidden-content")
            .collect();
        assert!(!hidden_findings.is_empty());
    }

    #[test]
    fn test_custom_trailing_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // 15 trailing spaces — below default 20, but above custom 10
        write!(file, "const x = 1;{}", " ".repeat(15)).unwrap();

        // Default config: should NOT flag (15 < 20)
        let findings = scan_file(&file_path, &test_obfuscation_config()).unwrap();
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-trailing-whitespace"));

        // Custom config with lower threshold: SHOULD flag (15 > 10)
        let custom = ObfuscationConfig {
            max_trailing_spaces: 10,
            steganographic_column: 200,
            ..ObfuscationConfig::default()
        };
        let findings = scan_file(&file_path, &custom).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-trailing-whitespace"));
    }

    #[test]
    fn test_detect_zero_width_chars() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Zero-width space injected into variable name
        write!(file, "const my\u{200B}Var = 'hello';").unwrap();

        let findings = scan_file(&file_path, &test_obfuscation_config()).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-invisible-chars"));
    }

    #[test]
    fn test_clean_file_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clean.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const x = 1;").unwrap();
        writeln!(file, "console.log(x);").unwrap();

        let findings = scan_file(&file_path, &test_obfuscation_config()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("express", "expres"), 1);
        assert_eq!(levenshtein("lodash", "lodash"), 0);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn test_rot13_roundtrip() {
        assert_eq!(rot13("eval"), "riny");
        assert_eq!(rot13("riny"), "eval");
        assert_eq!(rot13("system"), "flfgrz");
        assert_eq!(rot13("flfgrz"), "system");
    }

    #[test]
    fn test_is_language() {
        assert!(is_language(Path::new("test.php"), &["php"]));
        assert!(is_language(Path::new("test.PHP"), &["php"]));
        assert!(!is_language(Path::new("test.js"), &["php"]));
        assert!(is_language(Path::new("test.js"), &["js", "ts"]));
    }
}
