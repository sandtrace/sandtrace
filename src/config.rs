use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Global configuration loaded from ~/.sandtrace/config.toml
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandtraceConfig {
    /// Primary rules directory
    pub rules_dir: String,

    /// Additional rule directories (e.g. community packs)
    #[serde(default)]
    pub additional_rules: Vec<String>,

    /// Redaction markers — lines containing these are skipped during audit.
    /// Prevents false positives on documentation samples.
    pub redaction_markers: Vec<String>,

    /// Custom credential patterns for audit scanning.
    /// Appended to the built-in CREDENTIAL_PATTERNS.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    /// Additional TOML files containing [[custom_patterns]] entries.
    /// Patterns from these files are merged with custom_patterns from config.toml.
    #[serde(default)]
    pub pattern_files: Vec<String>,

    /// Obfuscation scanner settings
    #[serde(default, alias = "shai_hulud")]
    pub obfuscation: ObfuscationConfig,

    /// Default alert channels for watch mode
    #[serde(default)]
    pub default_alerts: Vec<String>,
}

/// A user-defined credential pattern for audit scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub pattern: String,
    /// Match type: "regex" (default), "literal", "filename"
    /// - regex: pattern is a regex matched against file content
    /// - literal: pattern is an exact string matched against file content (case-insensitive)
    /// - filename: pattern is matched against file names/paths
    #[serde(default = "default_match_type")]
    pub match_type: String,
    /// Only scan files with these extensions (empty = all files)
    #[serde(default)]
    pub file_extensions: Vec<String>,
    /// Tags for categorization (e.g. "ioc", "malware", "c2")
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_match_type() -> String {
    "regex".to_string()
}

/// Obfuscation scanner settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ObfuscationConfig {
    pub max_trailing_spaces: usize,
    pub steganographic_column: usize,
    /// Enable typosquat detection (Levenshtein distance 1 from popular packages).
    /// Disabled by default to avoid false positives on private packages.
    pub enable_typosquat: bool,
    /// Package name prefixes that indicate internal/private packages.
    /// Used by dependency confusion detection to flag packages without private registries.
    pub known_internal_prefixes: Vec<String>,
}

impl Default for ObfuscationConfig {
    fn default() -> Self {
        Self {
            max_trailing_spaces: 20,
            steganographic_column: 200,
            enable_typosquat: false,
            known_internal_prefixes: Vec::new(),
        }
    }
}

impl Default for SandtraceConfig {
    fn default() -> Self {
        Self {
            rules_dir: "~/.sandtrace/rules".to_string(),
            additional_rules: Vec::new(),
            redaction_markers: default_redaction_markers(),
            custom_patterns: Vec::new(),
            pattern_files: Vec::new(),
            obfuscation: ObfuscationConfig::default(),
            default_alerts: vec!["stdout".to_string()],
        }
    }
}

/// The full default list of redaction markers (matches current REDACTION_MARKERS constant)
pub fn default_redaction_markers() -> Vec<String> {
    vec![
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
    ]
    .into_iter()
    .map(String::from)
    .collect()
}

/// Helper struct for pattern files that only contain [[custom_patterns]] entries.
#[derive(Debug, Deserialize)]
struct PatternFile {
    #[serde(default)]
    custom_patterns: Vec<CustomPattern>,
}

/// Load config from ~/.sandtrace/config.toml, falling back to defaults.
/// After loading, merges patterns from any files listed in `pattern_files`.
pub fn load_config() -> SandtraceConfig {
    let config_path = config_path();
    let mut config = if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    log::info!("Loaded config from {}", config_path.display());
                    config
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse {}: {}. Using defaults.",
                        config_path.display(),
                        e
                    );
                    SandtraceConfig::default()
                }
            },
            Err(e) => {
                log::warn!(
                    "Failed to read {}: {}. Using defaults.",
                    config_path.display(),
                    e
                );
                SandtraceConfig::default()
            }
        }
    } else {
        SandtraceConfig::default()
    };

    // Merge patterns from external pattern files
    for pattern_path in &config.pattern_files.clone() {
        let expanded = expand_tilde_str(pattern_path);
        match std::fs::read_to_string(&expanded) {
            Ok(content) => match toml::from_str::<PatternFile>(&content) {
                Ok(pf) => {
                    let count = pf.custom_patterns.len();
                    config.custom_patterns.extend(pf.custom_patterns);
                    log::info!("Loaded {} patterns from {}", count, expanded.display());
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse pattern file {}: {}. Skipping.",
                        expanded.display(),
                        e
                    );
                }
            },
            Err(e) => {
                log::warn!(
                    "Pattern file {} not found or unreadable: {}. Skipping.",
                    expanded.display(),
                    e
                );
            }
        }
    }

    config
}

/// Returns the path to ~/.sandtrace/config.toml
pub fn config_path() -> PathBuf {
    sandtrace_dir().join("config.toml")
}

/// Returns the path to the global ignore file (~/.sandtrace/.sandtraceignore)
pub fn global_ignore_path() -> PathBuf {
    sandtrace_dir().join(".sandtraceignore")
}

/// Returns the path to ~/.sandtrace/
pub fn sandtrace_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".sandtrace")
}

/// Expand ~ to $HOME in a path string
pub fn expand_tilde(path: &Path) -> PathBuf {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(format!("{}{}", home, &path_str[1..]));
        }
    }
    path.to_path_buf()
}

/// Expand ~ in a string path
pub fn expand_tilde_str(path: &str) -> PathBuf {
    expand_tilde(Path::new(path))
}

/// Generate the default config.toml content
pub fn default_config_toml() -> String {
    let config = SandtraceConfig::default();

    let mut toml = String::from("# SandTrace configuration\n");
    toml.push_str("# https://github.com/example/sandtrace\n\n");

    toml.push_str("# Primary rules directory\n");
    toml.push_str(&format!("rules_dir = {:?}\n\n", config.rules_dir));

    toml.push_str("# Additional rule directories (e.g. community packs)\n");
    toml.push_str("additional_rules = []\n");
    toml.push_str("# additional_rules = [\"~/.sandtrace/community-rules\"]\n\n");

    toml.push_str("# Default alert channels for watch mode\n");
    toml.push_str("default_alerts = [\"stdout\"]\n\n");

    toml.push_str("# Redaction markers — lines containing these are skipped during audit.\n");
    toml.push_str("# Prevents false positives on documentation samples.\n");
    toml.push_str("redaction_markers = [\n");
    for marker in &config.redaction_markers {
        toml.push_str(&format!("  {:?},\n", marker));
    }
    toml.push_str("]\n\n");

    toml.push_str("# Obfuscation scanner settings\n");
    toml.push_str("[obfuscation]\n");
    toml.push_str(&format!(
        "max_trailing_spaces = {}\n",
        config.obfuscation.max_trailing_spaces
    ));
    toml.push_str(&format!(
        "steganographic_column = {}\n",
        config.obfuscation.steganographic_column
    ));
    toml.push_str(&format!(
        "enable_typosquat = {}\n",
        config.obfuscation.enable_typosquat
    ));
    toml.push_str("known_internal_prefixes = []\n");
    toml.push_str("# known_internal_prefixes = [\"@mycompany/\", \"internal-\"]\n\n");

    toml.push_str("# Additional pattern files (merged with custom_patterns above)\n");
    toml.push_str("# pattern_files = [\"~/.sandtrace/npm-malware.toml\"]\n\n");

    toml.push_str("# Custom patterns for audit scanning.\n");
    toml.push_str("# Supports three match types:\n");
    toml.push_str("#   \"regex\"    — pattern is a regular expression (default)\n");
    toml.push_str("#   \"literal\"  — pattern is an exact string match (case-insensitive)\n");
    toml.push_str("#   \"filename\" — pattern matches against file names/paths\n");
    toml.push_str("#\n");
    toml.push_str("# [[custom_patterns]]\n");
    toml.push_str("# id = \"cred-internal-api\"\n");
    toml.push_str("# description = \"Internal API key found in source\"\n");
    toml.push_str("# severity = \"high\"\n");
    toml.push_str("# pattern = 'INTERNAL_[A-Z0-9]{32}'\n");
    toml.push_str("#\n");
    toml.push_str("# # IOC example: known malicious domain\n");
    toml.push_str("# [[custom_patterns]]\n");
    toml.push_str("# id = \"ioc-c2-domain\"\n");
    toml.push_str("# description = \"Known C2 domain found in source\"\n");
    toml.push_str("# severity = \"critical\"\n");
    toml.push_str("# match_type = \"literal\"\n");
    toml.push_str("# pattern = \"malware-c2.example.com\"\n");
    toml.push_str("# tags = [\"ioc\", \"c2\"]\n");
    toml.push_str("#\n");
    toml.push_str("# # IOC example: malicious file hash\n");
    toml.push_str("# [[custom_patterns]]\n");
    toml.push_str("# id = \"ioc-malware-hash\"\n");
    toml.push_str("# description = \"Known malware SHA256 hash\"\n");
    toml.push_str("# severity = \"critical\"\n");
    toml.push_str("# match_type = \"literal\"\n");
    toml.push_str(
        "# pattern = \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"\n",
    );
    toml.push_str("# tags = [\"ioc\", \"malware\"]\n");
    toml.push_str("#\n");
    toml.push_str("# # IOC example: suspicious filename\n");
    toml.push_str("# [[custom_patterns]]\n");
    toml.push_str("# id = \"ioc-suspicious-file\"\n");
    toml.push_str("# description = \"Known malicious filename pattern\"\n");
    toml.push_str("# severity = \"high\"\n");
    toml.push_str("# match_type = \"filename\"\n");
    toml.push_str("# pattern = \"mimikatz\"\n");
    toml.push_str("# file_extensions = [\"exe\", \"dll\", \"ps1\"]\n");
    toml.push_str("# tags = [\"ioc\", \"tool\"]\n");

    toml
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_has_redaction_markers() {
        let config = SandtraceConfig::default();
        assert!(!config.redaction_markers.is_empty());
        assert!(config.redaction_markers.contains(&"_redacted".to_string()));
        assert!(config.redaction_markers.contains(&"changeme".to_string()));
        assert!(config
            .redaction_markers
            .contains(&"process.env".to_string()));
    }

    #[test]
    fn test_default_obfuscation_values() {
        let config = SandtraceConfig::default();
        assert_eq!(config.obfuscation.max_trailing_spaces, 20);
        assert_eq!(config.obfuscation.steganographic_column, 200);
    }

    #[test]
    fn test_config_toml_roundtrip() {
        let toml_str = default_config_toml();
        let parsed: SandtraceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.rules_dir, "~/.sandtrace/rules");
        assert_eq!(parsed.obfuscation.max_trailing_spaces, 20);
        assert_eq!(parsed.obfuscation.steganographic_column, 200);
        assert!(!parsed.redaction_markers.is_empty());
        assert_eq!(parsed.default_alerts, vec!["stdout"]);
    }

    #[test]
    fn test_expand_tilde() {
        std::env::set_var("HOME", "/home/testuser");
        let result = expand_tilde(Path::new("~/.sandtrace/rules"));
        assert_eq!(result, PathBuf::from("/home/testuser/.sandtrace/rules"));
    }

    #[test]
    fn test_partial_config_deserialize() {
        // Only override obfuscation settings, everything else defaults
        let toml_str = r#"
[obfuscation]
max_trailing_spaces = 10
steganographic_column = 300
"#;
        let config: SandtraceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.obfuscation.max_trailing_spaces, 10);
        assert_eq!(config.obfuscation.steganographic_column, 300);
        // Defaults should still apply
        assert_eq!(config.rules_dir, "~/.sandtrace/rules");
        assert!(!config.redaction_markers.is_empty());
    }

    #[test]
    fn test_backward_compat_shai_hulud_alias() {
        // Old [shai_hulud] config key should still work via serde alias
        let toml_str = r#"
[shai_hulud]
max_trailing_spaces = 15
steganographic_column = 250
"#;
        let config: SandtraceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.obfuscation.max_trailing_spaces, 15);
        assert_eq!(config.obfuscation.steganographic_column, 250);
    }

    #[test]
    fn test_special_chars_in_markers() {
        // Verify markers with TOML-hostile chars survive roundtrip
        let toml_str = default_config_toml();
        let parsed: SandtraceConfig = toml::from_str(&toml_str).unwrap();
        assert!(parsed.redaction_markers.contains(&"{{ .".to_string()));
        assert!(parsed.redaction_markers.contains(&"${".to_string()));
        assert!(parsed.redaction_markers.contains(&"'.$".to_string()));
        assert!(parsed.redaction_markers.contains(&"\".$".to_string()));
    }

    #[test]
    fn test_pattern_files_default_empty() {
        let config = SandtraceConfig::default();
        assert!(config.pattern_files.is_empty());
    }

    #[test]
    fn test_pattern_files_deserialize() {
        let toml_str = r#"
pattern_files = ["~/.sandtrace/npm-malware.toml", "/opt/iocs/custom.toml"]
"#;
        let config: SandtraceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.pattern_files.len(), 2);
        assert_eq!(config.pattern_files[0], "~/.sandtrace/npm-malware.toml");
        assert_eq!(config.pattern_files[1], "/opt/iocs/custom.toml");
    }

    #[test]
    fn test_pattern_file_struct_parse() {
        let toml_str = r#"
[[custom_patterns]]
id = "test-1"
description = "Test pattern"
severity = "high"
match_type = "literal"
pattern = "evil-package"
tags = ["ioc", "npm"]
file_extensions = ["json"]

[[custom_patterns]]
id = "test-2"
description = "Another pattern"
severity = "critical"
pattern = "bad-thing"
"#;
        let pf: PatternFile = toml::from_str(toml_str).unwrap();
        assert_eq!(pf.custom_patterns.len(), 2);
        assert_eq!(pf.custom_patterns[0].id, "test-1");
        assert_eq!(pf.custom_patterns[0].match_type, "literal");
        assert_eq!(pf.custom_patterns[0].tags, vec!["ioc", "npm"]);
        assert_eq!(pf.custom_patterns[1].id, "test-2");
        assert_eq!(pf.custom_patterns[1].match_type, "regex"); // default
    }

    #[test]
    fn test_pattern_files_merge_from_file() {
        use std::io::Write;

        // Create a temp pattern file
        let dir = tempfile::tempdir().unwrap();
        let pattern_file = dir.path().join("test-patterns.toml");
        let mut f = std::fs::File::create(&pattern_file).unwrap();
        writeln!(
            f,
            r#"
[[custom_patterns]]
id = "external-1"
description = "External pattern"
severity = "critical"
match_type = "literal"
pattern = "malicious-pkg"
tags = ["ioc"]
"#
        )
        .unwrap();

        // Create a config that references the pattern file
        let config_toml = format!(
            r#"
pattern_files = [{:?}]

[[custom_patterns]]
id = "inline-1"
description = "Inline pattern"
severity = "high"
pattern = "INTERNAL_KEY"
"#,
            pattern_file.to_string_lossy()
        );

        // Parse the config
        let mut config: SandtraceConfig = toml::from_str(&config_toml).unwrap();
        assert_eq!(config.custom_patterns.len(), 1);
        assert_eq!(config.pattern_files.len(), 1);

        // Simulate what load_config does: merge pattern files
        for pattern_path in &config.pattern_files.clone() {
            let expanded = expand_tilde_str(pattern_path);
            let content = std::fs::read_to_string(&expanded).unwrap();
            let pf: PatternFile = toml::from_str(&content).unwrap();
            config.custom_patterns.extend(pf.custom_patterns);
        }

        assert_eq!(config.custom_patterns.len(), 2);
        assert_eq!(config.custom_patterns[0].id, "inline-1");
        assert_eq!(config.custom_patterns[1].id, "external-1");
        assert_eq!(config.custom_patterns[1].pattern, "malicious-pkg");
    }

    #[test]
    fn test_missing_pattern_file_no_crash() {
        // A config referencing a non-existent file should not crash
        let toml_str = r#"
pattern_files = ["/nonexistent/path/patterns.toml"]
"#;
        let config: SandtraceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.pattern_files.len(), 1);
        // The file doesn't exist, but parsing the config itself succeeds.
        // load_config() would log a warning and skip it.
        let expanded = expand_tilde_str(&config.pattern_files[0]);
        assert!(!expanded.exists());
    }
}
