# CI/CD Integration

sandtrace integrates into CI/CD pipelines through SARIF output (for GitHub Code Scanning) and JSON output (for custom pipelines).

## GitHub Actions with SARIF

Upload findings directly to GitHub Code Scanning:

```yaml
name: Security Audit

on:
  push:
    branches: [main]
  pull_request:

jobs:
  sandtrace:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install sandtrace
        run: |
          cargo install --path .
          sandtrace init

      - name: Run sandtrace audit
        run: sandtrace audit . --format sarif > sandtrace.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: sandtrace.sarif
```

SARIF findings appear in the **Security** tab of your GitHub repository under **Code scanning alerts**.

## JSON output for custom pipelines

Use JSON output with exit codes for custom CI logic:

```yaml
- name: Security audit
  run: |
    sandtrace audit . --format json --severity high > findings.json
    if [ $? -eq 2 ]; then echo "Critical findings detected"; exit 1; fi
```

## Exit codes

| Code | Meaning | CI action |
|------|---------|-----------|
| `0` | Clean | Pass |
| `1` | High findings | Fail (or warn, depending on your policy) |
| `2` | Critical findings | Always fail |

## Severity gating

Control which severity levels fail your build:

```bash
# Fail on critical only
sandtrace audit . --severity critical

# Fail on high and critical
sandtrace audit . --severity high

# Report everything (never fails on medium/low/info alone)
sandtrace audit . --severity low
```

## Pre-commit hook

Run sandtrace as a git pre-commit hook:

```bash
#!/bin/sh
# .git/hooks/pre-commit
sandtrace audit . --severity high --format terminal
```

## JSON output schema

The JSON output is an array of finding objects:

```json
{
  "findings": [
    {
      "rule_id": "cred-aws-key",
      "severity": "critical",
      "file": "src/config.rs",
      "line": 42,
      "message": "AWS Access Key ID found",
      "snippet": "AKIAIOSFODNN7EXAMPLE"
    }
  ],
  "summary": {
    "total": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}
```
