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

    /// Shai-Hulud scanner settings
    #[serde(default)]
    pub shai_hulud: ShaiHuludConfig,

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
}

/// Shai-Hulud obfuscation scanner settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ShaiHuludConfig {
    pub max_trailing_spaces: usize,
    pub steganographic_column: usize,
}

impl Default for ShaiHuludConfig {
    fn default() -> Self {
        Self {
            max_trailing_spaces: 20,
            steganographic_column: 200,
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
            shai_hulud: ShaiHuludConfig::default(),
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

/// Load config from ~/.sandtrace/config.toml, falling back to defaults
pub fn load_config() -> SandtraceConfig {
    let config_path = config_path();
    if config_path.exists() {
        match std::fs::read_to_string(&config_path) {
            Ok(content) => match toml::from_str(&content) {
                Ok(config) => {
                    log::info!("Loaded config from {}", config_path.display());
                    return config;
                }
                Err(e) => {
                    log::warn!(
                        "Failed to parse {}: {}. Using defaults.",
                        config_path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                log::warn!(
                    "Failed to read {}: {}. Using defaults.",
                    config_path.display(),
                    e
                );
            }
        }
    }
    SandtraceConfig::default()
}

/// Returns the path to ~/.sandtrace/config.toml
pub fn config_path() -> PathBuf {
    sandtrace_dir().join("config.toml")
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

    toml.push_str("# Shai-Hulud obfuscation scanner settings\n");
    toml.push_str("[shai_hulud]\n");
    toml.push_str(&format!(
        "max_trailing_spaces = {}\n",
        config.shai_hulud.max_trailing_spaces
    ));
    toml.push_str(&format!(
        "steganographic_column = {}\n\n",
        config.shai_hulud.steganographic_column
    ));

    toml.push_str("# Custom credential patterns for audit scanning.\n");
    toml.push_str("# Each [[custom_patterns]] block adds a regex matched against file contents.\n");
    toml.push_str("#\n");
    toml.push_str("# [[custom_patterns]]\n");
    toml.push_str("# id = \"cred-internal-api\"\n");
    toml.push_str("# description = \"Internal API key found in source\"\n");
    toml.push_str("# severity = \"high\"\n");
    toml.push_str("# pattern = 'INTERNAL_[A-Z0-9]{32}'\n");

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
    fn test_default_shai_hulud_values() {
        let config = SandtraceConfig::default();
        assert_eq!(config.shai_hulud.max_trailing_spaces, 20);
        assert_eq!(config.shai_hulud.steganographic_column, 200);
    }

    #[test]
    fn test_config_toml_roundtrip() {
        let toml_str = default_config_toml();
        let parsed: SandtraceConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.rules_dir, "~/.sandtrace/rules");
        assert_eq!(parsed.shai_hulud.max_trailing_spaces, 20);
        assert_eq!(parsed.shai_hulud.steganographic_column, 200);
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
        // Only override shai_hulud settings, everything else defaults
        let toml_str = r#"
[shai_hulud]
max_trailing_spaces = 10
steganographic_column = 300
"#;
        let config: SandtraceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.shai_hulud.max_trailing_spaces, 10);
        assert_eq!(config.shai_hulud.steganographic_column, 300);
        // Defaults should still apply
        assert_eq!(config.rules_dir, "~/.sandtrace/rules");
        assert!(!config.redaction_markers.is_empty());
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
}
