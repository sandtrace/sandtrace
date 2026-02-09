use crate::event::{AuditFinding, Severity};
use std::path::Path;

const MAX_TRAILING_SPACES: usize = 20;
const STEGANOGRAPHIC_COLUMN: usize = 200;

pub fn scan_file(path: &Path) -> Result<Vec<AuditFinding>, std::io::Error> {
    let content = std::fs::read_to_string(path)?;
    let file_path_str = path.to_string_lossy().to_string();
    let mut findings = Vec::new();

    let lines: Vec<&str> = content.lines().collect();

    for (i, line) in lines.iter().enumerate() {
        let line_number = i + 1;

        // 1. Excessive trailing whitespace (steganographic payload indicator)
        let trailing_spaces = line.len() - line.trim_end().len();
        if trailing_spaces > MAX_TRAILING_SPACES {
            findings.push(AuditFinding {
                file_path: file_path_str.clone(),
                line_number: Some(line_number),
                rule_id: "shai-hulud-trailing-whitespace".to_string(),
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

        // 2. Content past column 200 (hidden payload past visible area)
        if line.len() > STEGANOGRAPHIC_COLUMN {
            let visible = &line[..STEGANOGRAPHIC_COLUMN.min(line.len())];
            let hidden = &line[STEGANOGRAPHIC_COLUMN..];
            if !hidden.trim().is_empty() {
                findings.push(AuditFinding {
                    file_path: file_path_str.clone(),
                    line_number: Some(line_number),
                    rule_id: "shai-hulud-hidden-content".to_string(),
                    severity: Severity::Critical,
                    description: format!(
                        "Hidden content past column {} ({} hidden chars)",
                        STEGANOGRAPHIC_COLUMN,
                        hidden.len()
                    ),
                    matched_pattern: format!("content past column {}", STEGANOGRAPHIC_COLUMN),
                    context_lines: vec![
                        format!("visible: {}...", &visible[..80.min(visible.len())]),
                        format!("hidden:  {}", &hidden[..80.min(hidden.len())]),
                    ],
                });
            }
        }

        // 3. Zero-width and invisible unicode characters
        check_invisible_chars(line, line_number, &file_path_str, &mut findings);
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
                '\u{200D}' => Some("ZERO WIDTH JOINER"),
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
            rule_id: "shai-hulud-invisible-chars".to_string(),
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
    if matches!(ext, "json" | "yaml" | "yml" | "toml" | "xml" | "pem" | "crt" | "key") {
        return;
    }

    let base64_regex = regex::Regex::new(
        r"(?m)^[A-Za-z0-9+/]{100,}={0,2}$"
    ).unwrap();

    for mat in base64_regex.find_iter(content) {
        let line_number = content[..mat.start()].lines().count() + 1;

        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "shai-hulud-base64".to_string(),
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
    // Common homoglyph pairs: Cyrillic/Latin lookalikes
    let homoglyph_ranges = [
        ('\u{0410}', '\u{044F}', "Cyrillic"),  // А-я (looks like A-a)
        ('\u{0391}', '\u{03C9}', "Greek"),      // Α-ω
    ];

    for (i, line) in lines.iter().enumerate() {
        let line_number = i + 1;
        let mut found_homoglyphs = Vec::new();

        for ch in line.chars() {
            for (start, end, script) in &homoglyph_ranges {
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
                    rule_id: "shai-hulud-homoglyph".to_string(),
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

    #[test]
    fn test_detect_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Write a line with 30 trailing spaces
        write!(file, "const x = 1;{}", " ".repeat(30)).unwrap();

        let findings = scan_file(&file_path).unwrap();
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "shai-hulud-trailing-whitespace"));
    }

    #[test]
    fn test_detect_hidden_content() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Write visible content + hidden content past column 200
        let visible = "const x = 1;";
        let padding = " ".repeat(STEGANOGRAPHIC_COLUMN - visible.len());
        let hidden = "eval(atob('malicious'))";
        write!(file, "{}{}{}", visible, padding, hidden).unwrap();

        let findings = scan_file(&file_path).unwrap();
        let hidden_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "shai-hulud-hidden-content")
            .collect();
        assert!(!hidden_findings.is_empty());
    }

    #[test]
    fn test_detect_zero_width_chars() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        // Zero-width space injected into variable name
        write!(file, "const my\u{200B}Var = 'hello';").unwrap();

        let findings = scan_file(&file_path).unwrap();
        assert!(findings.iter().any(|f| f.rule_id == "shai-hulud-invisible-chars"));
    }

    #[test]
    fn test_clean_file_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("clean.js");
        let mut file = std::fs::File::create(&file_path).unwrap();
        writeln!(file, "const x = 1;").unwrap();
        writeln!(file, "console.log(x);").unwrap();

        let findings = scan_file(&file_path).unwrap();
        assert!(findings.is_empty());
    }
}
