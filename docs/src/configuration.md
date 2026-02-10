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

# Shai-Hulud obfuscation scanner thresholds
[shai_hulud]
max_trailing_spaces = 20       # Flag lines with more trailing spaces than this
steganographic_column = 200    # Flag content found past this column

# Custom credential patterns (appended to built-in patterns)
[[custom_patterns]]
id = "cred-internal-api"
description = "Internal API key found in source"
severity = "high"              # critical, high, medium, low, info
pattern = 'INTERNAL_[A-Z0-9]{32}'
```

See [`examples/config.toml`](https://github.com/cc-consulting-nv/sandtrace/blob/main/examples/config.toml) for a fully commented example.

## Settings

### rules_dir

Path to the primary rules directory. Defaults to `~/.sandtrace/rules`.

### additional_rules

Array of additional rule directory paths. Rules from all directories are merged. Useful for community rule packs or team-specific rules.

### default_alerts

Default alert channels for `sandtrace watch` when no `--alert` flag is specified. Options: `stdout`, `desktop`, `syslog`, `webhook:<url>`.

### shai_hulud

Thresholds for the Shai-Hulud obfuscation detection used by `sandtrace audit`:

- **max_trailing_spaces** — Lines with more trailing spaces than this are flagged (default: 20).
- **steganographic_column** — Content found past this column is flagged as potentially hidden (default: 200).

### custom_patterns

Add custom credential detection patterns that are appended to the built-in set. Each pattern needs:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the rule |
| `description` | Yes | Human-readable description |
| `severity` | Yes | `critical`, `high`, `medium`, `low`, or `info` |
| `pattern` | Yes | Regex pattern to match |

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
