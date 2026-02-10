# Getting Started

## Requirements

- **Rust 1.75+** (for building from source)
- **Linux 5.13+** (Landlock v1 support for `sandtrace run`)
- **Linux 5.3+** (PTRACE_GET_SYSCALL_INFO for `sandtrace run`)

> `sandtrace audit`, `sandtrace scan`, and `sandtrace watch` work on any Linux kernel. The kernel version requirements above only apply to the `sandtrace run` sandbox.

## Install

```bash
cargo build --release
cp target/release/sandtrace ~/.cargo/bin/
```

## Initialize

```bash
sandtrace init
```

This creates `~/.sandtrace/` with default configuration and rules:

| File | Purpose |
|------|---------|
| `config.toml` | Global settings — redaction markers, custom patterns, thresholds |
| `rules/credential-access.yml` | 14 credential file monitoring rules |
| `rules/supply-chain.yml` | 4 supply-chain attack detection rules |
| `rules/exfiltration.yml` | Data exfiltration detection rules |

Use `sandtrace init --force` to overwrite existing files.

## Quick examples

### Audit a project for secrets

```bash
sandtrace audit ./my-project
```

### Scan your home directory for obfuscation

```bash
sandtrace scan
```

### Watch credential files

```bash
sandtrace watch --alert desktop
```

### Sandbox an npm install

```bash
sandtrace run --allow-path ./project --output trace.jsonl npm install
```

### Generate SARIF for GitHub Code Scanning

```bash
sandtrace audit ./my-project --format sarif > sandtrace.sarif
```
