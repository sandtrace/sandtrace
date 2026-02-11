# sandtrace audit

Scans source code for hardcoded secrets, supply-chain threats, steganographic payloads, and unicode obfuscation.

## Usage

```bash
sandtrace audit ./my-project                           # Terminal output
sandtrace audit ./my-project --format json              # JSON for CI pipelines
sandtrace audit ./my-project --format sarif > r.sarif   # SARIF for GitHub Code Scanning
sandtrace audit ./my-project --severity high            # Only high + critical
sandtrace audit ./my-project --rules ./my-rules/        # Custom rules directory
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | *(required)* | Directory to scan |
| `--format` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `--severity` | `low` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--rules` | `~/.sandtrace/rules/` | YAML rules directory |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` | — | Increase verbosity |

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings at or above the minimum severity |
| `1` | High findings detected |
| `2` | Critical findings detected |

Exit codes make `sandtrace audit` easy to use as a CI gate — any non-zero exit fails the build.

## Examples

### Audit with high severity filter

```bash
sandtrace audit ./my-project --severity high
```

Only reports findings with severity `high` or `critical`.

### JSON output for scripting

```bash
sandtrace audit ./my-project --format json | jq '.findings | length'
```

### SARIF for GitHub Code Scanning

```bash
sandtrace audit . --format sarif > sandtrace.sarif
```

Upload the SARIF file using the `github/codeql-action/upload-sarif@v3` action. See [CI/CD Integration](../ci-cd.md) for a full workflow example.

### Custom rules directory

```bash
sandtrace audit ./my-project --rules ./my-custom-rules/
```

Override the default rules directory. See [Custom Rules](../rules/custom-rules.md) for the YAML rule format.

## Built-in detection rules

See [Detection Rules](../rules/detection-rules.md) for the full list of 50+ built-in patterns that `sandtrace audit` checks, including 30 obfuscation rules across 3 tiers.
