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
# If you don't have Rust/Cargo installed:
sudo apt install cargo rustup && rustup update stable

# Build and install
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

- **50+ built-in rules** — AWS keys, GitHub PATs, Stripe keys, JWTs, private keys, and more
- **30 obfuscation rules** across 3 tiers:
  - **Tier 1 — Encoding** — hex/unicode escapes, string concatenation, charcode construction, constructor chains, git hook injection, PHP variable functions
  - **Tier 2 — Advanced** — nested atob(), polyglot files, symlink attacks, filename homoglyphs, ROT13, template literals, PHP backtick/create_function, Python dangerous imports
  - **Tier 3 — Supply chain** — typosquatting, dependency confusion, install script chains, preg_replace /e, suspicious dotfiles, Proxy/Reflect, JSON eval, encoded shell commands
- **Supply-chain scanning** — suspicious postinstall scripts, unexpected dependency directory writes
- **IOC support** — add custom indicators of compromise (domains, hashes, IPs, filenames) as detection rules
- **npm malware feed** — auto-generate patterns from the OpenSSF [malicious-packages](https://github.com/ossf/malicious-packages) OSV dataset via `scripts/update-npm-iocs.sh`
- **19 watch rules** — real-time monitoring of credential files across 14 services

## Documentation

**Read the full documentation at [https://sandtrace.github.io/sandtrace/](https://sandtrace.github.io/sandtrace/)**

The docs cover all commands, flags, configuration, custom rules, policies, CI/CD integration, and architecture.

## Maintained by

[Closed Circuit Inc.](https://closedcircuit.io) and [Closed Circuit Consultants](https://closedcircuitconsultants.com)

## License

MIT OR Apache-2.0
