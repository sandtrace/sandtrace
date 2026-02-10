# Sandtrace

A Rust-based security tool that combines malware sandboxing, credential file watching, and codebase auditing on Linux.

## Overview

Sandtrace provides three modes of operation:

- **`run`** — Execute untrusted binaries in an isolated sandbox with syscall tracing, filesystem restriction, and network control
- **`watch`** — Monitor credential files (SSH keys, AWS tokens, etc.) for suspicious access in real-time
- **`audit`** — Scan codebases for hardcoded secrets, supply-chain threats, steganographic payloads, and unicode obfuscation

## Features

- **8-layer sandbox** defense-in-depth architecture (namespaces, Landlock, seccomp-bpf, ptrace)
- **Credential watcher** with YAML rule engine and real-time alerting (stdout, desktop, webhook, syslog)
- **Codebase auditor** detecting AWS keys, private keys, JWTs, GitHub/Slack/Stripe tokens, and more
- **Shai-Hulud scanner** for steganographic attacks: hidden content past visible columns, zero-width unicode, homoglyphs, suspicious base64 blobs
- **Supply-chain scanner** for malicious postinstall scripts in package.json
- **Configurable** via `~/.sandtrace/config.toml` with custom patterns, redaction markers, and community rulesets
- **Output formats**: colored terminal, JSON, SARIF (for CI/CD integration)
- **Structured JSONL output** for machine parsing (sandbox mode)
- **TOML policy files** for sandbox rules

## Getting Started

### Requirements

- Rust 1.75+
- Linux 5.13+ (for Landlock v1)
- Linux 5.3+ (for PTRACE_GET_SYSCALL_INFO)

### Build

```bash
cargo build --release
```

### Initialize config and rules

```bash
sandtrace init
```

This creates `~/.sandtrace/` with:
- `config.toml` — global configuration (redaction markers, custom patterns, Shai-Hulud thresholds)
- `rules/` — YAML detection rules (credential-access, supply-chain, exfiltration)

Use `--force` to overwrite existing files:

```bash
sandtrace init --force
```

## Usage

### Audit a codebase

```bash
# Scan a project directory
sandtrace audit ./my-project

# JSON output for CI pipelines
sandtrace audit ./my-project --format json

# SARIF output for GitHub Code Scanning
sandtrace audit ./my-project --format sarif > results.sarif

# Only show high and critical findings
sandtrace audit ./my-project --severity high

# Use custom rules directory
sandtrace audit ./my-project --rules ./my-rules/
```

### Watch credential files

```bash
# Watch with default settings (stdout alerts)
sandtrace watch

# Desktop notifications
sandtrace watch --alert desktop

# Webhook alerts
sandtrace watch --alert webhook:https://hooks.slack.com/services/T00/B00/XXX

# Multiple alert channels
sandtrace watch --alert stdout --alert desktop

# Watch additional paths
sandtrace watch --paths /opt/secrets/

# Run as daemon
sandtrace watch --daemon --pid-file /tmp/sandtrace.pid
```

### Sandbox untrusted binaries

```bash
# Basic trace (trace-only mode)
sandtrace run --trace-only -vv /bin/ls /tmp

# Strict sandbox (default policy)
sandtrace run --allow-path ./project --output trace.jsonl npm install

# Custom policy file
sandtrace run --policy policies/strict.toml ./untrusted_binary

# Allow network access
sandtrace run --allow-net curl https://example.com
```

## Configuration

Sandtrace uses `~/.sandtrace/config.toml` for global settings. Run `sandtrace init` to generate the default config.

See [`examples/config.toml`](examples/config.toml) for a fully commented example.

### Key settings

```toml
# Primary rules directory
rules_dir = "~/.sandtrace/rules"

# Additional rule directories (e.g. community packs)
additional_rules = ["~/.sandtrace/community-rules"]

# Default alert channels for watch mode
default_alerts = ["stdout"]

# Shai-Hulud obfuscation scanner thresholds
[shai_hulud]
max_trailing_spaces = 20
steganographic_column = 200

# Custom credential patterns (appended to built-in patterns)
[[custom_patterns]]
id = "cred-internal-api"
description = "Internal API key found in source"
severity = "high"
pattern = 'INTERNAL_[A-Z0-9]{32}'
```

### Redaction markers

Lines containing redaction markers are skipped during audit to prevent false positives on documentation samples, environment variable lookups, and template variables. The default config includes markers for common patterns like `placeholder`, `your_token`, `changeme`, `process.env`, `{{ .`, `${`, etc.

Add your own markers in `config.toml`:

```toml
redaction_markers = [
  # ... default markers ...
  "test_fixture_value",
  "my_custom_marker",
]
```

### Inline suppression

Add a comment on the line above a finding to suppress it:

```javascript
// @sandtrace-ignore
const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE";
```

Both `@sandtrace-ignore` and `sandtrace:ignore` are recognized.

## Sandbox Policy Files (TOML)

Policy files configure the sandbox for `sandtrace run`:

```toml
[filesystem]
allow_read = ["/usr", "/lib", "/etc/ld.so.cache"]
allow_write = ["./output"]
deny = ["/home/*/.ssh", "/etc/shadow"]

[network]
allow = false

[syscalls]
deny = ["mount", "ptrace", "reboot"]

[limits]
timeout = 30
```

See [`examples/`](examples/) for more policy examples.

## Built-in Audit Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `cred-aws-key` | Critical | AWS Access Key ID |
| `cred-private-key` | Critical | Private key (RSA, EC, DSA, OpenSSH) |
| `cred-github-token` | Critical | GitHub personal access token |
| `cred-slack-token` | Critical | Slack token |
| `cred-stripe-key` | Critical | Stripe API key |
| `cred-jwt-token` | High | JWT token |
| `cred-generic-password` | High | Hardcoded password assignment |
| `cred-generic-secret` | High | Hardcoded secret/token assignment |
| `shai-hulud-trailing-whitespace` | High | Excessive trailing whitespace (steganographic payload) |
| `shai-hulud-hidden-content` | Critical | Suspicious content hidden past visible column |
| `shai-hulud-invisible-chars` | Critical | Zero-width/invisible unicode characters |
| `shai-hulud-base64` | Medium | Large base64-encoded blob in source file |
| `shai-hulud-homoglyph` | High | Unicode homoglyphs mixed with ASCII (Cyrillic/Greek) |
| `supply-chain-suspicious-script` | Critical | Suspicious postinstall/preinstall script |

## Architecture

```
sandtrace/
├── Cargo.toml
├── rules/                    # Built-in YAML detection rules
│   ├── credential-access.yml
│   ├── supply-chain.yml
│   └── exfiltration.yml
├── examples/                 # Example policy and config files
│   ├── config.toml           # Example global config
│   ├── strict.toml           # Strict sandbox policy
│   ├── permissive.toml       # Permissive sandbox policy
│   └── *_audit.toml          # Package manager audit policies
├── src/
│   ├── main.rs               # CLI entry point
│   ├── cli.rs                # clap derive structs
│   ├── config.rs             # Global config (~/.sandtrace/config.toml)
│   ├── init.rs               # `init` subcommand
│   ├── error.rs              # thiserror error hierarchy
│   ├── event.rs              # Event structs (SyscallEvent, AuditFinding, etc.)
│   ├── rules/                # YAML rule engine
│   │   ├── mod.rs            # RuleRegistry, rule loading
│   │   └── matcher.rs        # Pattern matching
│   ├── audit/                # Codebase auditor
│   │   ├── mod.rs            # Audit orchestrator
│   │   ├── scanner.rs        # Credential + supply-chain scanner
│   │   └── shai_hulud.rs     # Steganography + obfuscation scanner
│   ├── watch/                # Credential file watcher
│   │   ├── mod.rs            # Watch orchestrator
│   │   ├── monitor.rs        # inotify file monitoring
│   │   └── handler.rs        # Event handler + rule matching
│   ├── alert/                # Alert dispatch
│   ├── policy/               # Sandbox policy engine
│   ├── sandbox/              # Sandbox layers
│   │   ├── namespaces.rs     # Linux namespaces
│   │   ├── landlock.rs       # Landlock LSM
│   │   ├── seccomp.rs        # seccomp-bpf
│   │   └── capabilities.rs   # Capability dropping
│   ├── tracer/               # Ptrace tracer
│   │   ├── mod.rs            # Main event loop
│   │   ├── arch/             # Architecture abstraction
│   │   ├── decoder.rs        # Syscall argument decoding
│   │   ├── memory.rs         # Tracee memory access
│   │   └── state.rs          # Per-PID state tracking
│   ├── process/              # Process tree tracking
│   └── output/               # Output formats
│       ├── jsonl.rs          # JSONL writer
│       └── terminal.rs       # Colored terminal output
```

## Security Note

This is a prototype implementation. In production environments:
- Ensure unprivileged user namespaces are enabled (`kernel.unprivileged_userns_clone=1`)
- Run with appropriate YAMA ptrace scope (`kernel.yama.ptrace_scope <= 1`)
- Test thoroughly in your environment before production use

## License

MIT OR Apache-2.0
