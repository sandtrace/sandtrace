# sandtrace scan

Fast parallel filesystem sweep using rayon thread pool and ignore-aware directory walking. Detects whitespace obfuscation techniques used in supply-chain attacks.

## Usage

```bash
sandtrace scan                              # Scan $HOME for 50+ consecutive whitespace chars
sandtrace scan /tmp                         # Scan specific directory
sandtrace scan /tmp -n 20                   # Lower threshold to 20 chars
sandtrace scan /tmp -v                      # Show line previews
sandtrace scan /tmp --max-size 5000000      # Skip files over 5MB
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | `$HOME` | Directory to scan |
| `-n, --min-whitespace` | `50` | Minimum consecutive whitespace characters to flag |
| `-v, --verbose` | `false` | Show line preview for each finding |
| `--max-size` | `10000000` | Maximum file size in bytes |
| `--no-color` | `false` | Disable colored output |

## Skipped directories

The following directories are automatically skipped during scanning:

`node_modules`, `.git`, `vendor`, `.pnpm`, `dist`, `build`, `.cache`, `__pycache__`, `.venv`, `venv`, `.tox`

## How it works

`sandtrace scan` uses rayon for parallel directory walking. Each file is checked line-by-line for runs of consecutive whitespace characters (spaces and tabs) that exceed the threshold. This detects whitespace obfuscation attacks where malicious payloads are hidden in whitespace at the end of source lines or past column 200.

## Examples

### Quick scan with default threshold

```bash
sandtrace scan
```

Scans your entire home directory for lines with 50+ consecutive whitespace characters.

### Targeted scan with lower threshold

```bash
sandtrace scan ./vendor -n 20 -v
```

Scans a vendor directory with a lower threshold and shows line previews for each finding.
