# Audit Detection Rules

`sandtrace audit` checks codebases against 27+ built-in detection rules across three categories: credential patterns, Shai-Hulud obfuscation, and supply-chain threats.

## Credential patterns

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

## Shai-Hulud obfuscation detection

These rules detect whitespace and unicode obfuscation techniques used in supply-chain attacks:

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `shai-hulud-trailing-whitespace` | High | Excessive trailing whitespace (>20 chars) |
| `shai-hulud-hidden-content` | Critical | Content hidden past column 200 |
| `shai-hulud-invisible-chars` | Critical | Zero-width unicode characters (U+200B, U+FEFF, U+2060, etc.) |
| `shai-hulud-base64` | Medium | Large base64-encoded blobs in source files |
| `shai-hulud-homoglyph` | High | Cyrillic/Greek homoglyphs mixed with ASCII |

### What is Shai-Hulud?

Shai-Hulud is a supply-chain attack technique where malicious code is hidden using whitespace padding, zero-width unicode characters, or visual homoglyphs. The name comes from the giant sandworms of Dune — hidden beneath the surface but devastating when they strike.

These rules detect the "wormsign" — the surface indicators that suggest malicious content is hiding in plain sight.

## Supply-chain detection

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `supply-chain-suspicious-script` | Critical | `package.json` postinstall/preinstall scripts with `curl`, `wget`, `eval(`, `base64`, pipe-to-shell |

## Severity levels

| Level | Meaning | Exit code |
|-------|---------|-----------|
| `critical` | Confirmed secret or active threat | 2 |
| `high` | Likely secret or dangerous pattern | 1 |
| `medium` | Suspicious but may be intentional | 0 |
| `low` | Worth reviewing | 0 |
| `info` | Informational only | 0 |

Use `--severity` to filter the minimum level reported:

```bash
sandtrace audit . --severity high    # Only high + critical
sandtrace audit . --severity medium  # Medium and above
```

## Suppressing false positives

See [Configuration — Redaction Markers](../configuration.md#redaction-markers) and [Configuration — Inline Suppression](../configuration.md#inline-suppression) for ways to suppress known false positives.
