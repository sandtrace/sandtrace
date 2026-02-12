use crate::event::{AuditFinding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use super::{is_language, rot13, DANGEROUS_FUNCS, HOMOGLYPH_RANGES};

// --- Lazy-compiled regex patterns ---

static RE_ATOB_NESTED: Lazy<Regex> = Lazy::new(|| Regex::new(r"atob\s*\(\s*atob\s*\(").unwrap());

static RE_ATOB_LONG: Lazy<Regex> = Lazy::new(|| Regex::new(r"atob\s*\([^)]{20,}\)").unwrap());

static RE_ROT13_PHP: Lazy<Regex> = Lazy::new(|| Regex::new(r"str_rot13\s*\(").unwrap());

static RE_ROT13_STRING_ARG: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"str_rot13\s*\(\s*['"]([a-zA-Z]+)['"]\s*\)"#).unwrap());

static RE_TEMPLATE_LITERAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\$\{['"][^'"]+['"]\}\s*\$\{['"][^'"]+['"]\}"#).unwrap());

static RE_PHP_CREATE_FUNCTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"create_function\s*\(").unwrap());

static RE_PHP_BACKTICK: Lazy<Regex> = Lazy::new(|| Regex::new(r"`[^`]+`").unwrap());

static RE_PYTHON_IMPORT_OS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"__import__\s*\(\s*['"]os['"]\s*\)"#).unwrap());

static RE_PYTHON_PICKLE: Lazy<Regex> = Lazy::new(|| Regex::new(r"pickle\.loads\s*\(").unwrap());

static RE_PYTHON_EXEC_COMPILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"exec\s*\(\s*compile\s*\(").unwrap());

static RE_PYTHON_MARSHAL: Lazy<Regex> = Lazy::new(|| Regex::new(r"marshal\.loads\s*\(").unwrap());

/// Magic byte signatures for polyglot detection (Rule 10).
const MAGIC_BYTES: &[(&[u8], &str)] = &[
    (b"\x89PNG", "PNG image"),
    (b"\xFF\xD8\xFF", "JPEG image"),
    (b"%PDF", "PDF document"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"PK\x03\x04", "ZIP/JAR archive"),
    (b"\x7FELF", "ELF binary"),
    (b"MZ", "Windows PE executable"),
];

/// Source file extensions where binary magic bytes are suspicious (polyglot check).
const SOURCE_EXTENSIONS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "mjs", "cjs", "py", "rb", "php", "go", "rs", "java", "kt", "swift",
    "c", "cpp", "h", "sh", "bash", "pl", "pm", "css", "scss", "sql",
];

/// Known-good dotfiles that are not suspicious.
const KNOWN_GOOD_DOTFILES: &[&str] = &[
    ".gitignore",
    ".gitattributes",
    ".gitmodules",
    ".gitkeep",
    ".editorconfig",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintignore",
    ".prettierrc",
    ".prettierrc.js",
    ".prettierrc.json",
    ".prettierignore",
    ".stylelintrc",
    ".stylelintrc.json",
    ".babelrc",
    ".babelrc.js",
    ".babelrc.json",
    ".npmrc",
    ".npmignore",
    ".yarnrc",
    ".yarnrc.yml",
    ".env",
    ".env.example",
    ".env.local",
    ".env.development",
    ".env.production",
    ".env.test",
    ".dockerignore",
    ".htaccess",
    ".flake8",
    ".pylintrc",
    ".pyproject.toml",
    ".python-version",
    ".rubocop.yml",
    ".ruby-version",
    ".ruby-gemset",
    ".php-cs-fixer.php",
    ".php-cs-fixer.dist.php",
    ".phpunit.xml",
    ".phpunit.result.cache",
    ".travis.yml",
    ".circleci",
    ".github",
    ".vscode",
    ".idea",
    ".DS_Store",
    ".browserslistrc",
    ".nvmrc",
    ".node-version",
    ".tool-versions",
    ".clang-format",
    ".clang-tidy",
    ".rustfmt.toml",
    ".mailmap",
    ".gitmessage",
];

/// Sensitive targets for symlink attack detection (Rule 11).
const SENSITIVE_TARGETS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".gpg",
    "/etc/shadow",
    "/etc/passwd",
    ".env",
    ".git/config",
    "id_rsa",
    "id_ed25519",
    "credentials",
    ".kube/config",
    ".docker/config.json",
    ".npmrc",
    ".pypirc",
];

/// Scan a single line for Tier 2 advanced obfuscation patterns.
pub fn scan_line(
    line: &str,
    line_number: usize,
    file_path: &str,
    path: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    // Rule 9: Nested atob() chains / long atob payloads
    if RE_ATOB_NESTED.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-atob-chain".to_string(),
            severity: Severity::High,
            description: "Nested atob() calls — multi-layer base64 decoding".to_string(),
            matched_pattern: "nested atob".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    } else if RE_ATOB_LONG.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-atob-chain".to_string(),
            severity: Severity::High,
            description: "atob() with large payload — possible encoded malware".to_string(),
            matched_pattern: "long atob payload".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 13: ROT13 in PHP
    if is_language(path, &["php"]) && RE_ROT13_PHP.is_match(line) {
        let mut is_dangerous = false;
        for cap in RE_ROT13_STRING_ARG.captures_iter(line) {
            if let Some(m) = cap.get(1) {
                let decoded = rot13(m.as_str());
                let lower = decoded.to_lowercase();
                if DANGEROUS_FUNCS.iter().any(|f| lower.contains(f)) {
                    is_dangerous = true;
                }
            }
        }

        let severity = if is_dangerous {
            Severity::High
        } else {
            Severity::Medium
        };
        let desc = if is_dangerous {
            "str_rot13() decodes to dangerous function name".to_string()
        } else {
            "str_rot13() call — potential obfuscation".to_string()
        };

        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-rot13".to_string(),
            severity,
            description: desc,
            matched_pattern: "rot13 obfuscation".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 14: Template literal concatenation in JS/TS
    if is_language(path, &["js", "ts", "jsx", "tsx", "mjs", "cjs"])
        && RE_TEMPLATE_LITERAL.is_match(line)
    {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-template-literal".to_string(),
            severity: Severity::High,
            description: "Adjacent template literal fragments — possible string construction"
                .to_string(),
            matched_pattern: "template literal concat".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 15: PHP create_function (deprecated, often abused)
    if is_language(path, &["php"]) && RE_PHP_CREATE_FUNCTION.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-php-create-function".to_string(),
            severity: Severity::High,
            description: "create_function() — deprecated PHP dynamic code execution".to_string(),
            matched_pattern: "create_function".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 16: PHP backtick execution
    if is_language(path, &["php"]) && RE_PHP_BACKTICK.is_match(line) {
        let trimmed = line.trim();
        // Skip comment lines (// # * | for PHP/Laravel docblocks)
        let is_comment_line = trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with('*')
            || trimmed.starts_with('|')
            || trimmed.starts_with("/*");
        // Skip lines with inline comments containing backticks (e.g. code // `foo`)
        let has_inline_comment_backtick = line.contains("//") && {
            let after_comment = &line[line.find("//").unwrap()..];
            after_comment.contains('`')
        };
        // Skip JS template literals inside Blade/PHP files (`...${...}...`)
        let is_js_template_literal = RE_PHP_BACKTICK.find(line).is_some_and(|m| {
            let inner = &line[m.start() + 1..m.end() - 1];
            inner.contains("${")
        });
        if !is_comment_line && !has_inline_comment_backtick && !is_js_template_literal {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-php-backtick".to_string(),
                severity: Severity::Critical,
                description: "PHP backtick execution operator — equivalent to shell_exec()"
                    .to_string(),
                matched_pattern: "php backtick exec".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
    }

    // Rule 17: Python dangerous imports/calls
    if is_language(path, &["py"]) {
        if RE_PYTHON_IMPORT_OS.is_match(line) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-python-dangerous".to_string(),
                severity: Severity::High,
                description: "__import__('os') — dynamic OS module import".to_string(),
                matched_pattern: "python dynamic import".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
        if RE_PYTHON_PICKLE.is_match(line) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-python-dangerous".to_string(),
                severity: Severity::High,
                description: "pickle.loads() — untrusted deserialization risk".to_string(),
                matched_pattern: "python pickle".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
        if RE_PYTHON_EXEC_COMPILE.is_match(line) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-python-dangerous".to_string(),
                severity: Severity::High,
                description: "exec(compile()) — dynamic code execution".to_string(),
                matched_pattern: "python exec compile".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
        if RE_PYTHON_MARSHAL.is_match(line) {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-python-dangerous".to_string(),
                severity: Severity::High,
                description: "marshal.loads() — bytecode deserialization".to_string(),
                matched_pattern: "python marshal".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
    }
}

/// Rule 10: Polyglot file detection — binary magic bytes in source file extensions.
pub fn check_polyglot(raw_bytes: &[u8], file_path: &str, path: &Path) -> Option<AuditFinding> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if !SOURCE_EXTENSIONS.contains(&ext) {
        return None;
    }

    for (magic, format_name) in MAGIC_BYTES {
        if raw_bytes.starts_with(magic) {
            return Some(AuditFinding {
                file_path: file_path.to_string(),
                line_number: None,
                rule_id: "obfuscation-polyglot".to_string(),
                severity: Severity::Critical,
                description: format!(
                    "Polyglot file: {} magic bytes in .{} file",
                    format_name, ext
                ),
                matched_pattern: "polyglot file".to_string(),
                context_lines: vec![format!(
                    "First bytes: {:02X?}",
                    &raw_bytes[..16.min(raw_bytes.len())]
                )],
            });
        }
    }

    None
}

/// Rule 11: Symlink attack detection.
pub fn check_symlink(path: &Path) -> Option<AuditFinding> {
    if !path.is_symlink() {
        return None;
    }

    let target = match std::fs::read_link(path) {
        Ok(t) => t,
        Err(_) => return None,
    };

    let target_str = target.to_string_lossy().to_string();
    let target_lower = target_str.to_lowercase();

    for sensitive in SENSITIVE_TARGETS {
        if target_lower.contains(sensitive) {
            return Some(AuditFinding {
                file_path: path.to_string_lossy().to_string(),
                line_number: None,
                rule_id: "obfuscation-symlink-attack".to_string(),
                severity: Severity::Critical,
                description: format!("Symlink points to sensitive target: {}", target_str),
                matched_pattern: "symlink to sensitive path".to_string(),
                context_lines: vec![format!("{} -> {}", path.display(), target_str)],
            });
        }
    }

    None
}

/// Rule 12: Filename homoglyph detection (Cyrillic/Greek chars in filenames).
pub fn check_filename_homoglyph(path: &Path) -> Option<AuditFinding> {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    let mut found = Vec::new();
    let has_ascii = file_name.chars().any(|c| c.is_ascii_alphabetic());

    if !has_ascii {
        return None;
    }

    for ch in file_name.chars() {
        for (start, end, script) in HOMOGLYPH_RANGES {
            if ch >= *start && ch <= *end {
                found.push(format!("U+{:04X} ({})", ch as u32, script));
            }
        }
    }

    if found.is_empty() {
        return None;
    }

    Some(AuditFinding {
        file_path: path.to_string_lossy().to_string(),
        line_number: None,
        rule_id: "obfuscation-filename-homoglyph".to_string(),
        severity: Severity::High,
        description: format!(
            "Filename contains homoglyph characters: {}",
            found.join(", ")
        ),
        matched_pattern: "filename homoglyphs".to_string(),
        context_lines: vec![file_name.to_string()],
    })
}

/// Rule 22: Suspicious dotfile detection.
pub fn check_suspicious_dotfile(path: &Path) -> Option<AuditFinding> {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if !file_name.starts_with('.') {
        return None;
    }

    // Check if the parent directory looks like a source dir (not repo root)
    let parent_name = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let in_source_dir = matches!(
        parent_name,
        "src"
            | "lib"
            | "app"
            | "pkg"
            | "internal"
            | "cmd"
            | "components"
            | "pages"
            | "routes"
            | "controllers"
            | "models"
            | "views"
            | "services"
            | "utils"
            | "helpers"
    );

    if !in_source_dir {
        return None;
    }

    let name_lower = file_name.to_lowercase();
    if KNOWN_GOOD_DOTFILES.iter().any(|k| name_lower == *k) {
        return None;
    }

    Some(AuditFinding {
        file_path: path.to_string_lossy().to_string(),
        line_number: None,
        rule_id: "obfuscation-suspicious-dotfile".to_string(),
        severity: Severity::Medium,
        description: format!("Unusual dotfile '{}' in source directory", file_name),
        matched_pattern: "suspicious dotfile".to_string(),
        context_lines: vec![path.to_string_lossy().to_string()],
    })
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
    fn test_nested_atob() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "var x = atob(atob('Y1dWeA=='));").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-atob-chain"));
    }

    #[test]
    fn test_polyglot_png_in_js() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.js");
        // PNG magic bytes followed by JS code
        let mut content = vec![0x89, b'P', b'N', b'G'];
        content.extend_from_slice(b"/* JS payload */");
        std::fs::write(&path, &content).unwrap();

        let finding = check_polyglot(&content, &path.to_string_lossy(), &path);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().rule_id, "obfuscation-polyglot");
    }

    #[test]
    fn test_polyglot_normal_js() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("normal.js");
        let content = b"const x = 1;";
        std::fs::write(&path, content).unwrap();

        let finding = check_polyglot(content, &path.to_string_lossy(), &path);
        assert!(finding.is_none());
    }

    #[test]
    fn test_symlink_attack() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(".ssh");
        std::fs::create_dir(&target).unwrap();

        let link = dir.path().join("innocent-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let finding = check_symlink(&link);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().rule_id, "obfuscation-symlink-attack");
    }

    #[test]
    fn test_normal_symlink_ok() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real-file.txt");
        std::fs::write(&target, "hello").unwrap();

        let link = dir.path().join("my-link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let finding = check_symlink(&link);
        assert!(finding.is_none());
    }

    #[test]
    fn test_php_create_function() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.php");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"$f = create_function('$a', 'return eval($a);');"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-php-create-function"));
    }

    #[test]
    fn test_php_backtick() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.php");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "$output = `whoami`;").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-php-backtick"));
    }

    #[test]
    fn test_python_dangerous_import() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.py");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "os = __import__('os')").unwrap();
        writeln!(f, "os.system('rm -rf /')").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-python-dangerous"));
    }

    #[test]
    fn test_python_pickle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.py");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "import pickle").unwrap();
        writeln!(f, "obj = pickle.loads(data)").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-python-dangerous"));
    }

    #[test]
    fn test_rot13_dangerous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.php");
        let mut f = std::fs::File::create(&path).unwrap();
        // "riny" is ROT13 of "eval"
        writeln!(f, "$x = str_rot13('riny');").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-rot13" && f.severity == Severity::High));
    }

    #[test]
    fn test_suspicious_dotfile_in_src() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let dotfile = src.join(".hidden-payload");
        std::fs::write(&dotfile, "malicious content").unwrap();

        let finding = check_suspicious_dotfile(&dotfile);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().rule_id, "obfuscation-suspicious-dotfile");
    }

    #[test]
    fn test_known_good_dotfile_ok() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        let dotfile = src.join(".gitignore");
        std::fs::write(&dotfile, "node_modules/").unwrap();

        let finding = check_suspicious_dotfile(&dotfile);
        assert!(finding.is_none());
    }
}
