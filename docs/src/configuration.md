# Configuration

sandtrace is configured through `~/.sandtrace/config.toml`, created by `sandtrace init`.

## config.toml reference

```toml
# Primary rules directory
rules_dir = "~/.sandtrace/rules"

# Additional rule directories (e.g. community packs)
additional_rules = ["~/.sandtrace/community-rules"]

# Default alert channels for watch mode
default_alerts = ["stdout"]

# Obfuscation scanner thresholds
[obfuscation]
max_trailing_spaces = 20       # Flag lines with more trailing spaces than this
steganographic_column = 200    # Flag content found past this column
enable_typosquat = false       # Enable typosquatting detection (Levenshtein distance 1)
known_internal_prefixes = []   # Package prefixes for dependency confusion detection
# known_internal_prefixes = ["@mycompany/", "internal-"]

# Custom patterns (appended to built-in patterns)
[[custom_patterns]]
id = "cred-internal-api"
description = "Internal API key found in source"
severity = "high"              # critical, high, medium, low, info
pattern = 'INTERNAL_[A-Z0-9]{32}'

# IOC example: literal string match
[[custom_patterns]]
id = "ioc-c2-domain"
description = "Known C2 domain found in source"
severity = "critical"
match_type = "literal"
pattern = "malware-c2.example.com"
tags = ["ioc", "c2"]
```

See [`examples/config.toml`](https://github.com/cc-consulting-nv/sandtrace/blob/main/examples/config.toml) for a fully commented example.

## Settings

### pattern_files

Array of additional TOML files containing `[[custom_patterns]]` entries. Patterns from these files are merged with `custom_patterns` defined in `config.toml` at load time. Missing files log a warning but do not cause an error.

```toml
pattern_files = ["~/.sandtrace/npm-malware.toml"]
```

This is useful for large, auto-generated pattern sets (e.g. the [npm malware IOC feed](./rules/custom-rules.md#automated-ioc-feeds)) that you don't want mixed into your hand-curated config file.

### rules_dir

Path to the primary rules directory. Defaults to `~/.sandtrace/rules`.

### additional_rules

Array of additional rule directory paths. Rules from all directories are merged. Useful for community rule packs or team-specific rules.

### default_alerts

Default alert channels for `sandtrace watch` when no `--alert` flag is specified. Options: `stdout`, `desktop`, `syslog`, `webhook:<url>`.

### obfuscation

Thresholds and feature flags for the obfuscation detection scanner used by `sandtrace audit`:

- **max_trailing_spaces** — Lines with more trailing spaces than this are flagged (default: 20).
- **steganographic_column** — Content found past this column is flagged as potentially hidden (default: 200).
- **enable_typosquat** — Enable typosquatting detection, which flags package names that are 1 Levenshtein edit distance from popular npm/pip packages (default: false). Disabled by default to avoid false positives on private packages.
- **known_internal_prefixes** — List of package name prefixes that indicate internal/private packages. Used by the dependency confusion rule to flag internal-looking packages without a private registry configured (default: empty).

> **Backward compatibility:** existing config files using `[shai_hulud]` will continue to work.

### custom_patterns

Add custom detection patterns that are appended to the built-in set. Each pattern supports three match types:

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | — | Unique identifier for the rule |
| `description` | Yes | — | Human-readable description |
| `severity` | Yes | — | `critical`, `high`, `medium`, `low`, or `info` |
| `pattern` | Yes | — | Pattern to match (regex, literal string, or filename) |
| `match_type` | No | `"regex"` | `"regex"`, `"literal"`, or `"filename"` |
| `file_extensions` | No | `[]` | Only scan files with these extensions (empty = all) |
| `tags` | No | `[]` | Tags for categorization (e.g. `"ioc"`, `"malware"`) |

See [Custom Rules — IOC Rules](./rules/custom-rules.md#ioc-rules) for IOC examples.

## Redaction markers

Lines containing redaction markers are skipped during audit to prevent false positives. Default markers include `placeholder`, `your_token`, `changeme`, `process.env`, `{{ .`, `${`, and more.

Add your own markers:

```toml
redaction_markers = [
  # ... default markers ...
  "test_fixture_value",
  "my_custom_marker",
]
```

## Inline suppression

Suppress a specific finding by adding a comment on the line above it:

```javascript
// @sandtrace-ignore
const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE";
```

Both `@sandtrace-ignore` and `sandtrace:ignore` are recognized. The suppression applies only to the immediately following line.
