# Audit Detection Rules

`sandtrace audit` checks codebases against 50+ built-in detection rules across four categories: credential patterns, obfuscation detection (3 tiers), and supply-chain threats.

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

## Obfuscation detection

These rules detect code obfuscation techniques used in supply-chain attacks. They are organized into three tiers by sophistication.

### Original rules

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `obfuscation-trailing-whitespace` | High | Excessive trailing whitespace (>20 chars) |
| `obfuscation-hidden-content` | Critical | Content hidden past column 200 |
| `obfuscation-invisible-chars` | Critical | Zero-width unicode characters (U+200B, U+FEFF, U+2060, etc.) |
| `obfuscation-base64` | Medium | Large base64-encoded blobs in source files |
| `obfuscation-homoglyph` | High | Cyrillic/Greek homoglyphs mixed with ASCII |

### Tier 1 — Encoding & string manipulation

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `obfuscation-hex-escape` | Medium | Chains of 3+ hex escape sequences (`\x63\x75\x72\x6c`). Skips .c/.h/.cpp files. |
| `obfuscation-unicode-escape` | Medium | Chains of 3+ unicode escapes (`\u0065\u0076\u0061\u006C`). Skips .json files. |
| `obfuscation-string-concat` | High | String concatenation hiding dangerous function names (`'ev' + 'al'`) |
| `obfuscation-charcode` | High | `String.fromCharCode()` and PHP `chr()` concatenation chains |
| `obfuscation-bracket-notation` | High | Bracket notation hiding dangerous functions (`window['ev' + 'al']`) |
| `obfuscation-constructor-chain` | Critical | `.constructor.constructor()` chains — almost exclusively malicious |
| `obfuscation-git-hook-injection` | Critical | Suspicious content in `.git/hooks/` (curl, wget, eval, pipe-to-shell) |
| `obfuscation-php-variable-function` | High | PHP variable functions storing dangerous names (`$fn = 'system'`) |

### Tier 2 — Advanced obfuscation

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `obfuscation-atob-chain` | High | Nested `atob(atob(...))` or large `atob()` payloads |
| `obfuscation-polyglot` | Critical | Binary magic bytes (PNG/JPEG/PDF/ELF/MZ) in source file extensions |
| `obfuscation-symlink-attack` | Critical | Symlinks targeting .ssh, .aws, .gnupg, /etc/shadow, .env, etc. |
| `obfuscation-filename-homoglyph` | High | Cyrillic/Greek characters in filenames mixed with ASCII |
| `obfuscation-rot13` | Medium/High | PHP `str_rot13()` calls; elevated to High when decoding to dangerous functions |
| `obfuscation-template-literal` | High | Adjacent template literal fragments in JS/TS (`${'ev'}${'al'}`) |
| `obfuscation-php-create-function` | High | `create_function()` — deprecated PHP dynamic code execution |
| `obfuscation-php-backtick` | Critical | PHP backtick execution operator (equivalent to `shell_exec()`) |
| `obfuscation-python-dangerous` | High | `__import__('os')`, `pickle.loads()`, `exec(compile())`, `marshal.loads()` |

### Tier 3 — Supply chain

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `obfuscation-typosquat` | High | Package names 1 edit distance from popular npm/pip packages. Requires `enable_typosquat = true`. |
| `obfuscation-dependency-confusion` | High | Internal-looking packages (`-internal`, `-private`, `@company/`) without `.npmrc` |
| `obfuscation-install-script-chain` | Critical | `node -e`, `python -c`, hidden dir refs, env var URLs in install scripts |
| `obfuscation-php-preg-replace-e` | Critical | `preg_replace()` with `/e` modifier — executes replacement as PHP code |
| `obfuscation-suspicious-dotfile` | Medium | Unknown dotfiles in source directories (src/, lib/, app/, etc.) |
| `obfuscation-proxy-reflect` | Medium | `new Proxy()` / `Reflect.apply()` metaprogramming in JS/TS |
| `obfuscation-json-eval` | Critical | `eval(`, `Function(`, `javascript:`, `<script` in .json files |
| `obfuscation-encoded-shell` | Critical | `echo B64 | base64 -d | sh`, `curl URL | bash`, `python -c 'import base64'` |

### What are obfuscation attacks?

Obfuscation attacks hide malicious code using encoding, string manipulation, binary polyglots, or visual tricks. These techniques make payloads invisible to code review while remaining executable. Common vectors include:

- **Encoding** — hex escapes, unicode escapes, charcode construction, base64 nesting
- **String splitting** — concatenation (`'ev'+'al'`), bracket notation, template literals, ROT13
- **Binary tricks** — polyglot files (PNG header + JS payload), constructor chain exploits
- **Filesystem** — symlinks to sensitive files, homoglyph filenames, git hook injection, suspicious dotfiles
- **Supply chain** — typosquatting, dependency confusion, malicious install scripts, preg_replace /e

These rules detect the surface indicators that suggest malicious content is hiding in plain sight.

## Supply-chain detection

| Rule ID | Severity | What it finds |
|---------|----------|---------------|
| `supply-chain-suspicious-script` | Critical | `package.json` postinstall/preinstall scripts with `curl`, `wget`, `eval(`, `base64`, pipe-to-shell |

## Custom IOC patterns

In addition to built-in rules, you can add custom indicators of compromise (IOCs) as detection rules. See [Custom Rules — IOC Rules](./custom-rules.md#ioc-rules) for examples of matching known malicious domains, file hashes, IP addresses, and filenames.

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
