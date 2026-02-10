# sandtrace

A Rust security tool for Linux that combines malware sandboxing, credential file monitoring, codebase auditing, and whitespace obfuscation scanning in a single binary.

> **Wormsign never lies.** — The surface tremor that reveals a hidden threat before it strikes.

## Overview

```
sandtrace run     Sandbox untrusted binaries with syscall tracing + 8-layer isolation
sandtrace watch   Monitor credential files for suspicious access in real-time
sandtrace audit   Scan codebases for hardcoded secrets, supply-chain threats, steganography
sandtrace scan    Fast parallel filesystem sweep for whitespace obfuscation
sandtrace init    Initialize ~/.sandtrace/ config and rules
```

## Quick Start

### Requirements

- Rust 1.75+
- Linux 5.13+ (Landlock v1)
- Linux 5.3+ (PTRACE_GET_SYSCALL_INFO)

### Install

```bash
cargo build --release
cp target/release/sandtrace ~/.cargo/bin/
```

### Initialize

```bash
sandtrace init
```

Creates `~/.sandtrace/` with:

| File | Purpose |
|------|---------|
| `config.toml` | Global settings — redaction markers, custom patterns, thresholds |
| `rules/credential-access.yml` | 14 credential file monitoring rules |
| `rules/supply-chain.yml` | 4 supply-chain attack detection rules |
| `rules/exfiltration.yml` | Data exfiltration detection rules |

Use `sandtrace init --force` to overwrite existing files.

---

## Commands

### `sandtrace audit` — Codebase Auditor

Scans source code for hardcoded secrets, supply-chain threats, steganographic payloads, and unicode obfuscation.

```bash
sandtrace audit ./my-project                       # Terminal output
sandtrace audit ./my-project --format json          # JSON for CI pipelines
sandtrace audit ./my-project --format sarif > r.sarif  # SARIF for GitHub Code Scanning
sandtrace audit ./my-project --severity high        # Only high + critical
sandtrace audit ./my-project --rules ./my-rules/    # Custom rules directory
```

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | *(required)* | Directory to scan |
| `--format` | `terminal` | Output format: `terminal`, `json`, `sarif` |
| `--severity` | `low` | Minimum severity: `info`, `low`, `medium`, `high`, `critical` |
| `--rules` | `~/.sandtrace/rules/` | YAML rules directory |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` | — | Increase verbosity |

**Exit codes:** `0` = clean, `1` = high findings, `2` = critical findings.

#### Built-in Detection Rules

**Credential patterns:**

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `cred-aws-key` | Critical | AWS Access Key IDs (`AKIA...`) |
| `cred-private-key` | Critical | RSA, EC, DSA, OpenSSH private keys |
| `cred-github-token` | Critical | GitHub PATs (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) |
| `cred-slack-token` | Critical | Slack tokens (`xoxb-`, `xoxp-`, `xoxa-`, `xoxr-`, `xoxs-`) |
| `cred-stripe-key` | Critical | Stripe API keys (`sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`) |
| `cred-jwt-token` | High | JWT tokens (`eyJ...`) |
| `cred-generic-password` | High | Hardcoded `password = "..."` assignments |
| `cred-generic-secret` | High | Hardcoded `secret`, `token`, `api_key` assignments |

**Shai-Hulud obfuscation detection:**

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `shai-hulud-trailing-whitespace` | High | Excessive trailing whitespace (>20 chars) |
| `shai-hulud-hidden-content` | Critical | Content hidden past column 200 |
| `shai-hulud-invisible-chars` | Critical | Zero-width unicode characters (U+200B, U+FEFF, U+2060, etc.) |
| `shai-hulud-base64` | Medium | Large base64-encoded blobs in source files |
| `shai-hulud-homoglyph` | High | Cyrillic/Greek homoglyphs mixed with ASCII |

**Supply-chain detection:**

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `supply-chain-suspicious-script` | Critical | `package.json` postinstall/preinstall scripts with `curl`, `wget`, `eval(`, `base64`, pipe-to-shell |

---

### `sandtrace scan` — Whitespace Obfuscation Scanner

Fast parallel filesystem sweep using rayon thread pool and ignore-aware directory walking. Detects the signature technique of the Shai-Hulud supply-chain attack campaign.

```bash
sandtrace scan                          # Scan $HOME for 50+ consecutive whitespace chars
sandtrace scan /tmp                     # Scan specific directory
sandtrace scan /tmp -n 20              # Lower threshold to 20 chars
sandtrace scan /tmp -v                 # Show line previews
sandtrace scan /tmp --max-size 5000000 # Skip files over 5MB
```

| Flag | Default | Description |
|------|---------|-------------|
| `TARGET` | `$HOME` | Directory to scan |
| `-n, --min-whitespace` | `50` | Minimum consecutive whitespace characters to flag |
| `-v, --verbose` | `false` | Show line preview for each finding |
| `--max-size` | `10000000` | Maximum file size in bytes |
| `--no-color` | `false` | Disable colored output |

Skips: `node_modules`, `.git`, `vendor`, `.pnpm`, `dist`, `build`, `.cache`, `__pycache__`, `.venv`, `venv`, `.tox`

---

### `sandtrace watch` — Credential File Watcher

Monitors sensitive files via inotify and matches access events against YAML rules. Alerts through multiple channels.

```bash
sandtrace watch                                    # stdout alerts
sandtrace watch --alert desktop                    # Desktop notifications
sandtrace watch --alert webhook:https://hooks.slack.com/services/T00/B00/XXX
sandtrace watch --alert stdout --alert desktop     # Multiple channels
sandtrace watch --paths /opt/secrets/              # Watch additional paths
sandtrace watch --daemon --pid-file /tmp/st.pid    # Run as daemon
```

| Flag | Default | Description |
|------|---------|-------------|
| `--rules` | `~/.sandtrace/rules/` | YAML rules directory |
| `--paths` | — | Additional paths to monitor (repeatable) |
| `--alert` | `stdout` | Alert channel (repeatable) |
| `--daemon` | `false` | Fork to background |
| `--pid-file` | — | PID file for daemon mode |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` | — | Increase verbosity |

**Alert channels:**

| Channel | Format | Description |
|---------|--------|-------------|
| `stdout` | `--alert stdout` | Print to console |
| `desktop` | `--alert desktop` | Desktop notification (notify-rust) |
| `webhook` | `--alert webhook:<url>` | HTTP POST to webhook URL |
| `syslog` | `--alert syslog` | System log |

#### Built-in Watch Rules

**Credential access** (14 rules) — alerts when processes outside the expected allowlist access sensitive files:

| Rule ID | Files Monitored | Allowed Processes |
|---------|----------------|-------------------|
| `cred-access-aws` | `~/.aws/credentials`, `~/.aws/config` | aws, terraform, pulumi, cdktf |
| `cred-access-ssh` | `~/.ssh/id_*`, `~/.ssh/config` | ssh, scp, sftp, ssh-agent, git |
| `cred-access-gpg` | `~/.gnupg/*` | gpg, gpg2, gpg-agent, git |
| `cred-access-npm` | `~/.npmrc`, `~/.config/npm/*` | npm, npx, pnpm, yarn, node |
| `cred-access-docker` | `~/.docker/config.json` | docker, dockerd, containerd |
| `cred-access-kube` | `~/.kube/config` | kubectl, helm, k9s, kubectx |
| `cred-access-gcloud` | `~/.config/gcloud/*` | gcloud, terraform, pulumi |
| `cred-access-azure` | `~/.azure/*` | az, terraform, pulumi |
| `cred-access-pgpass` | `~/.pgpass` | psql, pg_dump, pg_restore, pgcli |
| `cred-access-volta` | `~/.volta/*` | volta, node, npm, npx |
| `cred-access-triton` | `~/.triton/*` | triton, node |
| `cred-access-netrc` | `~/.netrc` | curl, wget, git, ftp |
| `cred-access-git-credentials` | `~/.git-credentials` | git, git-credential-store |
| `cred-access-cpln` | `~/.config/cpln/*` | cpln, node |

**Supply-chain** (4 rules) — detects writes to dependency directories outside package managers:

| Rule ID | What it detects |
|---------|----------------|
| `supply-chain-node-modules` | Direct write to `node_modules` outside npm/yarn/pnpm |
| `supply-chain-npmrc-write` | Unexpected modification of `.npmrc` |
| `supply-chain-pip-conf` | Unexpected modification of pip configuration |
| `supply-chain-cargo-registry` | Direct modification of Cargo registry cache |

**Exfiltration** (1 rule):

| Rule ID | What it detects |
|---------|----------------|
| `exfil-curl-unknown` | curl/wget outbound requests during build/install |

---

### `sandtrace run` — Sandbox

Executes untrusted binaries inside an 8-layer isolation sandbox with ptrace-based syscall tracing.

```bash
sandtrace run --trace-only -vv /bin/ls /tmp                   # Trace only (no enforcement)
sandtrace run --allow-path ./project --output trace.jsonl npm install  # With filesystem restriction
sandtrace run --policy policies/strict.toml ./untrusted        # Custom policy
sandtrace run --allow-net curl https://example.com             # Allow network
```

| Flag | Default | Description |
|------|---------|-------------|
| `--policy` | — | TOML policy file |
| `--allow-path` | — | Allow filesystem access to path (repeatable) |
| `--allow-net` | `false` | Allow network access |
| `--allow-exec` | `false` | Allow child process execution |
| `-o, --output` | — | JSONL output file |
| `--timeout` | `30` | Kill process after N seconds |
| `--trace-only` | `false` | Disable enforcement (no Landlock/seccomp) |
| `--follow-forks` | `true` | Trace child processes |
| `--no-color` | `false` | Disable colored output |
| `-v` / `-vv` / `-vvv` | — | Verbosity level |

#### Sandbox Layers

Applied in order after `fork()`:

| Layer | Mechanism | What it does |
|-------|-----------|--------------|
| 1 | User namespace | Gain capabilities without privilege escalation |
| 2 | Mount namespace | Restrict filesystem view |
| 3 | PID namespace | Hide host processes |
| 4 | Network namespace | Isolate network (unless `--allow-net`) |
| 5 | `PR_SET_NO_NEW_PRIVS` | Prevent privilege escalation via setuid |
| 6 | Landlock LSM | Kernel-level filesystem access control |
| 7 | seccomp-bpf | Block dangerous syscalls at kernel level |
| 8 | ptrace `TRACEME` | Signal readiness to tracer, raise SIGSTOP |

Layers 6-7 are skipped when `--trace-only` is set.

**Always-blocked syscalls:** `kexec_load`, `kexec_file_load`, `reboot`, `swapon`, `swapoff`, `init_module`, `finit_module`, `delete_module`, `acct`, `pivot_root`

#### JSONL Output Format

Each line is a self-contained JSON object:

```jsonc
// Syscall event
{
  "event_type": "syscall",
  "timestamp": "2025-01-01T12:00:00Z",
  "pid": 1234,
  "syscall": "openat",
  "syscall_nr": 257,
  "args": {"raw": [...]},
  "return_value": 3,
  "success": true,
  "duration_us": 42,
  "action": "allow",
  "category": "file_read"
}

// Process lifecycle
{"event_type": "process", "action": "exec", "pid": 1234, "comm": "npm"}
{"event_type": "process", "action": "exited", "pid": 1234, "exit_code": 0}

// Trace summary
{"event_type": "summary", "total_syscalls": 4521, "unique_syscalls": 23, "duration_ms": 1200}
```

---

## Configuration

### `~/.sandtrace/config.toml`

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

See [`examples/config.toml`](examples/config.toml) for a fully commented example.

### Redaction Markers

Lines containing redaction markers are skipped during audit to prevent false positives. Default markers include `placeholder`, `your_token`, `changeme`, `process.env`, `{{ .`, `${`, and more.

Add your own:

```toml
redaction_markers = [
  # ... default markers ...
  "test_fixture_value",
  "my_custom_marker",
]
```

### Inline Suppression

Suppress a finding by adding a comment on the line above it:

```javascript
// @sandtrace-ignore
const EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE";
```

Both `@sandtrace-ignore` and `sandtrace:ignore` are recognized.

---

## Policy Files

TOML policy files configure the sandbox for `sandtrace run`:

```toml
[filesystem]
allow_read = ["/usr", "/lib", "/lib64", "/etc/ld.so.cache", "/dev/null", "/proc/self"]
allow_write = ["./output"]
allow_exec = []
deny = ["/home/*/.ssh", "/etc/shadow", "**/.env"]

[network]
allow = false

[syscalls]
deny = ["mount", "ptrace", "reboot"]
log_only = ["mprotect", "mmap"]

[limits]
timeout = 30
```

Example policies in [`examples/`](examples/):

| File | Description |
|------|-------------|
| `strict.toml` | Minimal filesystem access, no network, blocked dangerous syscalls |
| `permissive.toml` | Broad read access, trace-focused |
| `npm_audit.toml` | Tuned for `npm install` sandboxing |
| `pnpm_audit.toml` | Tuned for `pnpm install` sandboxing |
| `composer_audit.toml` | Tuned for `composer install` sandboxing |

---

## Custom YAML Rules

Write custom detection rules for watch mode:

```yaml
rules:
  - id: cred-access-custom-vault
    name: Custom Vault File Access
    severity: high
    description: Unexpected process accessed vault credentials
    detection:
      file_paths:
        - "/opt/vault/creds/*"
      excluded_processes:
        - vault
        - consul
      access_types: [read, write]
    alert:
      channels: [stdout, desktop]
      message: "{process_name} (PID: {pid}) accessed {path}"
    tags: [credential, vault]
    enabled: true
```

**Template variables:** `{process_name}`, `{pid}`, `{path}`

Place custom rules in `~/.sandtrace/rules/` or any directory listed in `additional_rules` in your config.

---

## CI/CD Integration

### GitHub Actions with SARIF

```yaml
- name: Run sandtrace audit
  run: sandtrace audit . --format sarif > sandtrace.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sandtrace.sarif
```

### JSON output for custom pipelines

```yaml
- name: Security audit
  run: |
    sandtrace audit . --format json --severity high > findings.json
    if [ $? -eq 2 ]; then echo "Critical findings detected"; exit 1; fi
```

---

## Architecture

```
sandtrace/
├── Cargo.toml
├── rules/                        # Built-in YAML detection rules
│   ├── credential-access.yml     # 14 credential file monitoring rules
│   ├── supply-chain.yml          # 4 supply-chain attack detection rules
│   └── exfiltration.yml          # Data exfiltration detection rules
├── examples/                     # Example policy and config files
│   ├── config.toml               # Annotated global config
│   ├── strict.toml               # Strict sandbox policy
│   ├── permissive.toml           # Permissive sandbox policy
│   └── *_audit.toml              # Package manager audit policies
├── src/
│   ├── main.rs                   # CLI entry point + dispatch
│   ├── cli.rs                    # clap derive structs + validation
│   ├── config.rs                 # Global config (~/.sandtrace/config.toml)
│   ├── error.rs                  # thiserror error hierarchy
│   ├── event.rs                  # SyscallEvent, AuditFinding, Severity
│   ├── init.rs                   # `init` subcommand
│   ├── scan.rs                   # `scan` subcommand (rayon parallel sweep)
│   ├── process.rs                # Process tree tracking via /proc
│   ├── rules/
│   │   ├── mod.rs                # RuleRegistry, rule loading
│   │   ├── matcher.rs            # File access + process matching
│   │   ├── schema.rs             # YAML schema definitions
│   │   └── builtin.rs            # Built-in rule definitions
│   ├── audit/
│   │   ├── mod.rs                # Audit orchestrator (parallel via rayon)
│   │   ├── scanner.rs            # Credential + supply-chain patterns
│   │   └── shai_hulud.rs         # Steganography + obfuscation detection
│   ├── watch/
│   │   ├── mod.rs                # Watch orchestrator (tokio async)
│   │   ├── monitor.rs            # inotify file monitoring
│   │   └── handler.rs            # Event handler + rule matching
│   ├── alert/
│   │   ├── mod.rs                # AlertRouter + AlertDispatcher trait
│   │   ├── stdout.rs             # Console alerts
│   │   ├── desktop.rs            # Desktop notifications (notify-rust)
│   │   ├── webhook.rs            # HTTP webhook (reqwest)
│   │   └── syslog.rs             # Syslog alerts
│   ├── policy/
│   │   ├── mod.rs                # Policy struct, path/syscall evaluation
│   │   ├── parser.rs             # TOML policy parsing
│   │   └── rules.rs              # PolicyEvaluator
│   ├── sandbox/
│   │   ├── mod.rs                # SandboxConfig, apply_child_sandbox()
│   │   ├── namespaces.rs         # User, mount, PID, network namespaces
│   │   ├── landlock.rs           # Landlock LSM filesystem control
│   │   ├── seccomp.rs            # seccomp-bpf syscall filtering
│   │   └── capabilities.rs       # Capability dropping, NO_NEW_PRIVS
│   ├── tracer/
│   │   ├── mod.rs                # Main ptrace event loop
│   │   ├── decoder.rs            # Syscall argument decoding
│   │   ├── memory.rs             # Tracee memory access
│   │   ├── state.rs              # Per-PID state tracking
│   │   ├── syscalls.rs           # Syscall categorization
│   │   └── arch/
│   │       ├── mod.rs            # Architecture trait
│   │       ├── x86_64.rs         # x86_64 syscall table
│   │       └── aarch64.rs        # ARM64 syscall table
│   └── output/
│       ├── mod.rs                # OutputManager + OutputSink trait
│       ├── jsonl.rs              # JSONL writer
│       └── terminal.rs           # Colored terminal output
└── tests/
    ├── integration.rs            # Integration tests
    └── fixtures/binaries/        # Test binaries (fork, mount, read, connect)
```

---

## Security Notes

This is a prototype. In production environments:

- Ensure unprivileged user namespaces are enabled: `kernel.unprivileged_userns_clone=1`
- Run with appropriate YAMA ptrace scope: `kernel.yama.ptrace_scope <= 1`
- The sandbox is defense-in-depth but not a security boundary guarantee
- Test thoroughly in your environment before production use

## License

MIT OR Apache-2.0
