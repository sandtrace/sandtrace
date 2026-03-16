# sandtrace

A Rust security tool for Linux that combines malware sandboxing, credential file monitoring, codebase auditing, and whitespace obfuscation scanning in a single binary.

> **Wormsign never lies.** — The surface tremor that reveals a hidden threat before it strikes.

## Commands

| Command | Description |
|---------|-------------|
| `sandtrace audit` | Scan codebases for hardcoded secrets, supply-chain threats, steganography |
| `sandtrace sbom` | Generate a CycloneDX SBOM from package manifests and lockfiles |
| `sandtrace scan` | Fast parallel filesystem sweep for whitespace obfuscation |
| `sandtrace watch` | Monitor credential files for suspicious access in real-time |
| `sandtrace run` | Sandbox untrusted binaries with syscall tracing + 8-layer isolation |
| `sandtrace init` | Initialize `~/.sandtrace/` config and rules |

## Quick Start

### Requirements

- Rust 1.87+
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

# Generate a CycloneDX SBOM
sandtrace sbom ./my-project --output bom.json

# Generate an SBOM for npm shrinkwrap, pnpm, Yarn, Composer, Ruby, Python, Conda, Go, Elixir, Java, .NET, Swift, Bun, or Deno projects
sandtrace sbom ./workspace --output bom.json

# Scan for whitespace obfuscation
sandtrace scan

# Watch credential files with desktop alerts
sandtrace watch --alert desktop

# Sandbox an npm install
sandtrace run --allow-path ./project --output trace.jsonl npm install
```

## Cloud Ingest

The repository now includes a separate ingest workload, `sandtrace-ingest`, for receiving uploads from `sandtrace audit`, `sandtrace run`, and `sandtrace sbom`.

Local example:

```bash
SANDTRACE_INGEST_DATABASE_URL=postgres://localhost/sandtrace_ingest \
SANDTRACE_INGEST_KEYS_FILE=examples/ingest-principals.json \
cargo run --bin sandtrace-ingest
```

Then point the CLI at it:

```bash
SANDTRACE_API_KEY=st_dev_acme_web_123 \
SANDTRACE_CLOUD_URL=http://127.0.0.1:8080 \
./target/debug/sandtrace audit .
```

When `SANDTRACE_INGEST_DATABASE_URL` is set, `sandtrace-ingest` writes normalized metadata to Postgres while keeping raw payloads on disk under `SANDTRACE_INGEST_DIR`.
The ingest database also stores organizations, projects, and hashed API keys, so auth can move off flat files in hosted deployments. Any principals loaded from `SANDTRACE_INGEST_KEYS_FILE` or the fallback env vars are bootstrapped into those tables on startup.
With Postgres enabled, those bootstrapped principals are seed data only. Request auth becomes database-authoritative, so deactivated or rotated keys stop working immediately.
Startup seeding is non-destructive: it inserts missing keys, but it does not reactivate inactive hashes or mark them as recently used.
Set `SANDTRACE_INGEST_ADMIN_TOKEN` to enable admin API key management endpoints.
Set `SANDTRACE_INGEST_ADMIN_SUBJECT` if you want lifecycle audit events tagged with something more specific than the default `admin-token`.
Project-scoped API keys only see records for their own `project_slug`; org-level keys can see all records for the org.

Containerized local stack:

```bash
docker compose -f docker-compose.ingest.yml up --build
```

That starts:
- Postgres on `127.0.0.1:5432`
- `sandtrace-ingest` on `127.0.0.1:8080`

Then point the CLI at it:

```bash
SANDTRACE_API_KEY=st_dev_acme_web_123 \
SANDTRACE_CLOUD_URL=http://127.0.0.1:8080 \
./target/debug/sandtrace audit .
```

Admin API example:

```bash
curl -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"org_slug":"acme","project_slug":"worker","actor":"ci"}' \
  http://127.0.0.1:8080/v1/admin/api-keys
```

Rotate an existing API key:

```bash
curl -X POST \
  -H "Authorization: Bearer dev-admin-token" \
  http://127.0.0.1:8080/v1/admin/api-keys/<api_key_hash>/rotate
```

Delete an inactive API key:

```bash
curl -X DELETE \
  -H "Authorization: Bearer dev-admin-token" \
  http://127.0.0.1:8080/v1/admin/api-keys/<api_key_hash>
```

List API key lifecycle events:

```bash
curl -H "Authorization: Bearer dev-admin-token" \
  "http://127.0.0.1:8080/v1/admin/api-key-events?org_slug=acme&limit=20"
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

Published docs are served from [https://sandtrace.github.io/sandtrace/](https://sandtrace.github.io/sandtrace/) when GitHub Pages is enabled for the repository and the `Deploy Docs` workflow succeeds.

Build the docs locally with:

```bash
mdbook build docs
```

The docs cover all commands, flags, configuration, custom rules, policies, CI/CD integration, and architecture.

## Maintained by

[Closed Circuit Inc.](https://closedcircuit.io) and [Closed Circuit Consultants](https://closedcircuitconsultants.com)

## License

MIT OR Apache-2.0
