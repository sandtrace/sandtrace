# sandtrace

A Rust security tool for Linux that combines malware sandboxing, credential file monitoring, codebase auditing, and whitespace obfuscation scanning in a single binary.

> **Wormsign never lies.** — The surface tremor that reveals a hidden threat before it strikes.

## Commands

| Command | Description |
|---------|-------------|
| `sandtrace audit` | Scan codebases for hardcoded secrets, supply-chain threats, steganography |
| `sandtrace scan` | Fast parallel filesystem sweep for whitespace obfuscation |
| `sandtrace watch` | Monitor credential files for suspicious access in real-time |
| `sandtrace run` | Sandbox untrusted binaries with syscall tracing + 8-layer isolation |
| `sandtrace init` | Initialize `~/.sandtrace/` config and rules |

## Quick Start

### Requirements

- Rust 1.75+
- Linux 5.13+ (for `sandtrace run` Landlock support)
- Linux 5.3+ (for `sandtrace run` ptrace support)

### Install

```bash
cargo build --release
cp target/release/sandtrace ~/.cargo/bin/
```

### Initialize

```bash
sandtrace init
```

### Examples

```bash
# Audit a project for secrets
sandtrace audit ./my-project

# SARIF output for GitHub Code Scanning
sandtrace audit ./my-project --format sarif > sandtrace.sarif

# Scan for whitespace obfuscation
sandtrace scan

# Watch credential files with desktop alerts
sandtrace watch --alert desktop

# Sandbox an npm install
sandtrace run --allow-path ./project --output trace.jsonl npm install
```

## Detection

- **27+ built-in rules** — AWS keys, GitHub PATs, Stripe keys, JWTs, private keys, and more
- **Shai-Hulud detection** — trailing whitespace, hidden content past column 200, zero-width unicode, homoglyphs
- **Supply-chain scanning** — suspicious postinstall scripts, unexpected dependency directory writes
- **19 watch rules** — real-time monitoring of credential files across 14 services

## Documentation

**Read the full documentation at [https://cc-consulting-nv.github.io/sandtrace/](https://cc-consulting-nv.github.io/sandtrace/)**

The docs cover all commands, flags, configuration, custom rules, policies, CI/CD integration, and architecture.

## License

MIT OR Apache-2.0
