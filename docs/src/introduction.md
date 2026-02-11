# Introduction

**sandtrace** is a Rust security tool for Linux that combines malware sandboxing, credential file monitoring, codebase auditing, and whitespace obfuscation scanning in a single binary.

> **Wormsign never lies.** — The surface tremor that reveals a hidden threat before it strikes.

## What sandtrace does

| Command | Purpose |
|---------|---------|
| `sandtrace run` | Sandbox untrusted binaries with syscall tracing + 8-layer isolation |
| `sandtrace watch` | Monitor credential files for suspicious access in real-time |
| `sandtrace audit` | Scan codebases for hardcoded secrets, supply-chain threats, steganography |
| `sandtrace scan` | Fast parallel filesystem sweep for whitespace obfuscation |
| `sandtrace init` | Initialize `~/.sandtrace/` config and rules |

## Use cases

- **Audit your codebase** before every commit or CI run — catch hardcoded AWS keys, Stripe tokens, JWTs, and 27+ credential patterns before they ship.
- **Sandbox untrusted installs** — run `npm install` or `pip install` inside an 8-layer isolation envelope and get a full JSONL syscall trace of what it tried to do.
- **Monitor credential files** — get real-time alerts when an unexpected process touches `~/.aws/credentials`, `~/.ssh/id_rsa`, or any of 14 monitored credential locations.
- **Detect obfuscation attacks** — scan for whitespace obfuscation techniques used in supply-chain attacks: trailing spaces, content hidden past column 200, zero-width unicode, and homoglyph substitution.
- **CI/CD gating** — output SARIF for GitHub Code Scanning or JSON for custom pipelines, with exit codes that fail the build on high/critical findings.

## Philosophy

sandtrace follows the "wormsign" philosophy: detect the surface tremor that reveals a hidden threat before it strikes. Rather than trying to be a comprehensive security platform, it focuses on the specific attack vectors that are most commonly exploited in modern software supply chains.

Each subcommand operates independently and can be adopted incrementally — start with `audit` in CI, add `watch` on developer machines, and use `run` when evaluating untrusted packages.
