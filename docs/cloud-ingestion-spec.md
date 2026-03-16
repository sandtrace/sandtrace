# Sandtrace Cloud Ingestion Spec

## Purpose

This document defines the first stable ingestion contract for Sandtrace Cloud.

The goal is to make `sandtrace audit`, `sandtrace run`, and `sandtrace sbom` upload useful security data to a hosted service without turning the open-source CLI into a privacy risk or a slow dependency.

This spec is intentionally opinionated:

- `audit` uploads structured findings and summary metadata.
- `run` uploads summary data and suspicious slices by default.
- `sbom` uploads CycloneDX manifests and normalized package inventory.
- Raw syscall traces are not uploaded by default.
- If an API key is present in the environment, the CLI should push to cloud automatically unless explicitly disabled.

## Design Principles

1. Best effort, not blocking.
   Cloud upload must not make local scanning or sandboxing fragile. Upload failures must not change the command exit code by default.

2. Summary-first.
   The hosted product should default to findings, verdicts, counts, suspicious events, and investigation pivots. Full raw traces are an opt-in investigation feature.

3. Stable envelope, flexible payloads.
   Every upload should carry a shared envelope with schema version, tool version, timestamp, and execution context so the backend can evolve without breaking clients.

4. Privacy by default.
   Do not upload file contents, secret values, full environment dumps, or full raw syscall streams unless explicitly opted in.

5. Explicit escalation for deep forensics.
   Raw trace retention requires a separate policy decision and a separate upload path.

## Environment Variables

The first cloud integration should use environment variables so it works in local shells and CI with no extra login flow.

| Variable | Required | Default | Purpose |
|---------|----------|---------|---------|
| `SANDTRACE_API_KEY` | Yes for cloud upload | — | Enables automatic upload when set |
| `SANDTRACE_CLOUD_URL` | No | `https://api.sandtrace.io` | Base URL for hosted or self-hosted cloud |
| `SANDTRACE_CLOUD_RAW_TRACE` | No | `never` | Raw trace policy: `never`, `suspicious`, or `always` |
| `SANDTRACE_CLOUD_TIMEOUT_MS` | No | `3000` | Upload timeout budget per request |
| `SANDTRACE_CLOUD_ENVIRONMENT` | No | inferred | Logical environment such as `dev`, `staging`, `prod`, `ci` |

## Client Upload Behavior

### Automatic upload trigger

If `SANDTRACE_API_KEY` is defined in the environment, `sandtrace audit`, `sandtrace run`, and `sandtrace sbom` should automatically upload to Sandtrace Cloud.

This should work the same way in:

- developer laptops
- CI pipelines
- ephemeral build runners
- air-gapped deployments with a custom `SANDTRACE_CLOUD_URL`

### Local-first behavior

The CLI remains locally useful even when cloud upload is enabled.

- Local output still prints normally.
- Local `--format json` and `--format sarif` behavior stays unchanged.
- Upload happens after findings are produced or after a run summary is finalized.
- Upload failures are logged as warnings and do not fail the command by default.

### Recommended CLI controls

These controls are not implemented yet, but this spec assumes they will exist:

- `--no-cloud`
  Disable cloud upload for a single invocation even if `SANDTRACE_API_KEY` is present.
- `--require-cloud`
  Fail the command if upload does not succeed.
- `--cloud-raw-trace`
  Override `SANDTRACE_CLOUD_RAW_TRACE` for a single invocation.

## Shared Envelope

All ingestion requests should use the same top-level envelope.

```json
{
  "schema_version": "2026-03-12",
  "upload_id": "01JNYRZG8A1X9B3P6Q7R8S9T0U",
  "uploaded_at": "2026-03-12T22:00:00Z",
  "tool": {
    "name": "sandtrace",
    "version": "0.2.9",
    "command": "run"
  },
  "source": {
    "mode": "cli",
    "environment": "ci",
    "hostname_hash": "sha256:...",
    "user_hash": "sha256:..."
  },
  "project": {
    "repo_url": "https://github.com/acme/payments",
    "repo_root_hash": "sha256:...",
    "git_branch": "main",
    "git_commit": "abc123def456",
    "provider": "github_actions"
  },
  "payload": {}
}
```

### Envelope rules

- `schema_version` is required and date-based.
- `upload_id` must be unique and idempotent.
- `uploaded_at` must be RFC 3339 UTC.
- Host and user identity should be hashed client-side before upload.
- Repo metadata should be included when discoverable, but omitted instead of guessed.

## Authentication

All cloud requests should use:

```http
Authorization: Bearer <SANDTRACE_API_KEY>
Content-Type: application/json
User-Agent: sandtrace/<version>
```

Recommended additional headers:

```http
Idempotency-Key: <upload_id>
X-Sandtrace-Schema-Version: 2026-03-12
```

## Endpoint Summary

| Endpoint | Purpose |
|---------|---------|
| `POST /v1/ingest/audit` | Upload one audit execution |
| `POST /v1/ingest/run` | Upload one sandbox execution summary |
| `POST /v1/ingest/sbom` | Upload one SBOM manifest and normalized inventory summary |
| `GET /v1/projects/overview` | Read one row per visible project with latest activity and current alert counts |
| `GET /v1/sbom/inventory` | Read package inventory for a specific SBOM or commit |
| `GET /v1/sbom/timeline` | Read commit-level SBOM history with package-change and security-alert counts |
| `GET /v1/sbom/diff` | Read package additions, removals, and version changes between two SBOMs |
| `GET /v1/sbom/alerts` | Read direct-package additions and direct version-change alerts from the latest commit comparison |
| `GET /v1/sbom/advisories` | Read OSV vulnerability matches for packages in a specific SBOM or commit |
| `GET /v1/sbom/security-alerts` | Read vulnerable direct-package additions and vulnerable direct version changes from the latest commit comparison |
| `GET /v1/sbom/security-alerts/history` | Read persisted vulnerable package-change history with filters for project, commit, kind, and package identity |
| `POST /v1/ingest/run/{run_id}/trace` | Upload a gzipped raw trace when policy allows |

## `audit` Ingestion

### What gets uploaded

Best-practice default for `sandtrace audit`:

- scan target metadata
- severity counts
- structured findings
- rule distribution
- elapsed time
- whether the run was executed in CI

Do not upload:

- full file contents
- secret values
- large source snippets beyond the existing redacted `context_lines`

### Request shape

```json
{
  "schema_version": "2026-03-12",
  "upload_id": "01JNYRZG8A1X9B3P6Q7R8S9T0U",
  "uploaded_at": "2026-03-12T22:00:00Z",
  "tool": {
    "name": "sandtrace",
    "version": "0.2.9",
    "command": "audit"
  },
  "source": {
    "mode": "cli",
    "environment": "ci",
    "hostname_hash": "sha256:...",
    "user_hash": "sha256:..."
  },
  "project": {
    "repo_url": "https://github.com/acme/payments",
    "repo_root_hash": "sha256:...",
    "git_branch": "main",
    "git_commit": "abc123def456",
    "provider": "github_actions"
  },
  "payload": {
    "target_path_hash": "sha256:...",
    "severity_threshold": "medium",
    "ruleset_version": "builtin@0.2.9",
    "file_count": 412,
    "duration_ms": 1840,
    "summary": {
      "total": 4,
      "critical": 1,
      "high": 1,
      "medium": 2,
      "low": 0,
      "info": 0
    },
    "rule_counts": {
      "cred-aws-key": 1,
      "obfuscation-hidden-content": 2,
      "supply-chain-postinstall": 1
    },
    "findings": [
      {
        "file_path_hash": "sha256:...",
        "file_name": "package.json",
        "line_number": 18,
        "rule_id": "supply-chain-postinstall",
        "severity": "high",
        "description": "Suspicious postinstall script chain",
        "matched_pattern": "postinstall",
        "context_lines": [
          "\"postinstall\": \"node scripts/bootstrap.js\""
        ]
      }
    ]
  }
}
```

### Server response

```json
{
  "audit_id": "aud_01JNZ04Q1B7N6S9N8XK4B2V6PX",
  "status": "accepted"
}
```

## `run` Ingestion

### Default upload policy

Best-practice default for `sandtrace run` is summary-first upload.

Upload by default:

- command metadata
- policy mode and timeout
- summary event
- suspicious events only
- normalized high-signal file and network indicators
- verdict and severity

Do not upload by default:

- full JSONL trace
- every syscall event
- raw argv for every spawned process when it may contain secrets
- full local filesystem paths unless already normalized or hashed

### Derived verdict

The client should derive a cloud-facing verdict from the summary and suspicious events:

- `clean`
- `suspicious`
- `blocked`
- `failed`

Recommended logic:

- `blocked` if policy denials occurred and caused termination
- `suspicious` if suspicious activity is present or sensitive file/network behavior is observed
- `failed` if the traced process exited abnormally without enough evidence for a security verdict
- `clean` otherwise

### Suspicious slices

The default `run` upload should include only high-signal slices, for example:

- denied syscalls
- accesses to sensitive file classes such as `.env`, `.ssh`, `.npmrc`, cloud credentials, shell profiles
- outbound network attempts
- process exec events for children started during the run
- rule matches or file access events classified as medium or above

### Request shape

```json
{
  "schema_version": "2026-03-12",
  "upload_id": "01JNZ08R3A5J2G4V6N8P1Q7R9S",
  "uploaded_at": "2026-03-12T22:01:00Z",
  "tool": {
    "name": "sandtrace",
    "version": "0.2.9",
    "command": "run"
  },
  "source": {
    "mode": "cli",
    "environment": "ci",
    "hostname_hash": "sha256:...",
    "user_hash": "sha256:..."
  },
  "project": {
    "repo_url": "https://github.com/acme/payments",
    "repo_root_hash": "sha256:...",
    "git_branch": "main",
    "git_commit": "abc123def456",
    "provider": "github_actions"
  },
  "payload": {
    "command": {
      "program": "npm",
      "argv": [
        "npm",
        "install"
      ],
      "working_dir_hash": "sha256:..."
    },
    "policy": {
      "trace_only": false,
      "allow_net": false,
      "allow_exec": false,
      "follow_forks": true,
      "timeout_seconds": 30
    },
    "summary": {
      "timestamp": "2026-03-12T22:00:59Z",
      "total_syscalls": 4521,
      "unique_syscalls": 23,
      "denied_count": 2,
      "process_count": 3,
      "duration_ms": 1200,
      "exit_code": 1,
      "files_accessed": [
        "~/.npmrc",
        ".env"
      ],
      "network_attempts": [
        "198.51.100.10:443"
      ],
      "suspicious_activity": [
        "accessed sensitive file ~/.npmrc",
        "attempted outbound network connection to 198.51.100.10:443"
      ]
    },
    "verdict": "suspicious",
    "severity": "high",
    "suspicious_events": [
      {
        "event_type": "process",
        "kind": "spawned",
        "timestamp": "2026-03-12T22:00:10Z",
        "parent_pid": 1234,
        "child_pid": 1235
      },
      {
        "event_type": "summary_signal",
        "category": "file_access",
        "path_class": "credential_store",
        "path_label": "~/.npmrc",
        "action": "read"
      },
      {
        "event_type": "summary_signal",
        "category": "network",
        "destination": "198.51.100.10:443",
        "action": "connect"
      }
    ]
  }
}
```

### Server response

```json
{
  "run_id": "run_01JNZ0BKC2YXGQ7S3V9J6R1W5M",
  "status": "accepted"
}
```

## `sbom` Ingestion

### Default upload policy

Best-practice default for `sandtrace sbom` is to upload the full generated CycloneDX document plus a compact normalized summary.

Upload by default:

- the exact CycloneDX 1.5 JSON emitted by the CLI
- component counts and direct dependency counts
- package ecosystem counts
- manifest and lockfile provenance when inferable
- project metadata and commit context

Do not upload separately:

- source files that produced the SBOM
- raw manifest contents outside the generated SBOM
- duplicate component rows when the same package already exists inside the CycloneDX payload

### Why SBOM is different

Unlike `audit` and `run`, the SBOM artifact is already intended to be a portable exchange format. The cloud should therefore store the raw CycloneDX document as a first-class artifact and derive search indexes from it, rather than trying to reconstruct the package graph from ad hoc summary fields later.

### Request shape

```json
{
  "schema_version": "2026-03-13",
  "upload_id": "01JNZ1D5R7JY62Y8WQ1KX4M2CP",
  "uploaded_at": "2026-03-13T02:10:00Z",
  "tool": {
    "name": "sandtrace",
    "version": "0.2.9",
    "command": "sbom"
  },
  "source": {
    "mode": "cli",
    "environment": "ci",
    "hostname_hash": "sha256:...",
    "user_hash": "sha256:..."
  },
  "project": {
    "repo_url": "https://github.com/acme/payments",
    "repo_root_hash": "sha256:...",
    "git_branch": "main",
    "git_commit": "abc123def456",
    "provider": "github_actions"
  },
  "payload": {
    "target_path_hash": "sha256:...",
    "format": "cyclonedx-json",
    "spec_version": "1.5",
    "component_count": 386,
    "direct_dependency_count": 1,
    "ecosystem_counts": {
      "npm": 122,
      "pypi": 44,
      "cargo": 18,
      "maven": 12,
      "conda": 3
    },
    "manifest_sources": [
      "package-lock.json",
      "uv.lock",
      "conda-lock.yml"
    ],
    "sbom": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.5",
      "serialNumber": "urn:uuid:...",
      "version": 1,
      "metadata": {},
      "components": [],
      "dependencies": []
    }
  }
}
```

### Server response

```json
{
  "sbom_id": "sbm_01JNZ1GF3QTX8P6M7H4A2V9RKE",
  "status": "accepted"
}
```

### Server-side handling

On ingest, the cloud should do four things:

1. Persist the raw CycloneDX document unchanged for export and evidence use.
2. Extract normalized component rows keyed by `org`, `project`, `git_commit`, `purl`, and `sbom_id`.
3. Compute summary indexes used by the dashboard:
   - package counts by ecosystem
   - direct dependency counts
   - new packages introduced since the previous commit or upload
   - high-risk package flags once vulnerability or reputation enrichment exists
4. Associate the SBOM with adjacent `audit` and `run` uploads from the same project and commit.

Current implementation note:

- raw SBOM artifacts are still stored as JSON files
- normalized SBOM package rows are written into Postgres when `SANDTRACE_INGEST_DATABASE_URL` is configured
- inventory and diff reads prefer those normalized rows and fall back to raw payload parsing only when needed
- OSV advisory results are cached in Postgres by normalized package query when `SANDTRACE_INGEST_DATABASE_URL` is configured
- derived SBOM security alerts are written into Postgres at ingest time and can be queried later through `GET /v1/sbom/security-alerts/history`
- if persisted SBOM security-alert rows are missing, the history endpoint backfills them from normalized package rows and cached OSV results before responding

### Deduplication and retention

The ingest service should deduplicate SBOMs by:

- `org_slug`
- `project_slug`
- `git_commit`
- SBOM content hash

If a duplicate upload arrives, the server should return the existing `sbom_id` with a status such as `duplicate`.

Retention recommendation:

- raw SBOM artifact: `90` to `365` days
- normalized package index rows: `90` to `365` days
- commit-to-package diff summaries: at least as long as the normalized rows

### Product behavior built on top

Once stored, SBOM uploads should power:

- package inventory by project and commit
- diff views between commits or releases
- “new package introduced” alerts
- cross-linking from an `audit` finding or `run` verdict to the exact package set present for that execution
- future CVE, advisory, or reputation enrichment without re-parsing old manifests

## Raw Trace Upload Policy

Raw trace upload is a separate decision from normal `run` ingestion.

### Default

`SANDTRACE_CLOUD_RAW_TRACE=never`

This means:

- no raw JSONL upload
- only summary and suspicious slices are retained
- cloud cost and privacy exposure stay bounded

### Optional modes

`SANDTRACE_CLOUD_RAW_TRACE=suspicious`

- Upload raw trace only when the derived verdict is `suspicious` or `blocked`
- Recommended first paid default for investigation-capable teams

`SANDTRACE_CLOUD_RAW_TRACE=always`

- Upload every run trace
- Only appropriate for dedicated investigation or compliance-heavy environments

### Raw trace upload format

Raw trace uploads should:

- use `POST /v1/ingest/run/{run_id}/trace`
- send gzipped JSONL
- include `Content-Encoding: gzip`
- include the same `Authorization` and `Idempotency-Key` headers

### Retention recommendation

- Summary retention: `90` to `365` days
- Suspicious slices retention: `90` to `365` days
- Raw trace retention: `7` to `14` days by default

### Access control recommendation

Raw traces should be limited to:

- org admins
- security investigators
- explicitly delegated incident responders

## Reliability Requirements

Cloud upload should follow these rules:

- timeout budget defaults to `3000ms`
- uploads should be retried with bounded exponential backoff
- duplicate uploads must be safe via `Idempotency-Key`
- CLI should continue if cloud is unreachable unless `--require-cloud` is set
- upload warnings must be emitted to `stderr`, not mixed into machine output streams

## Privacy Requirements

The client must never upload by default:

- secret values
- full file contents
- environment variable dumps
- raw syscall streams
- home-directory absolute paths when a normalized or hashed representation is sufficient

The client may upload by default:

- hashed host and user identifiers
- repo metadata
- redacted context lines already emitted by audit
- normalized sensitive path labels such as `.env`, `~/.npmrc`, `~/.aws/credentials`
- destination host and port for outbound network attempts

## Implementation Order

1. Add cloud configuration loading:
   - `SANDTRACE_API_KEY`
   - `SANDTRACE_CLOUD_URL`
   - `SANDTRACE_CLOUD_RAW_TRACE`
2. Add a shared upload envelope builder.
3. Add `POST /v1/ingest/audit` client support.
4. Add `POST /v1/ingest/run` client support.
5. Add `POST /v1/ingest/sbom` client support.
6. Add `--no-cloud` and `--require-cloud`.
7. Add opt-in raw trace upload for `suspicious` and `always` modes.

## Immediate Product Contract

If you need one sentence to align product, engineering, and sales:

Sandtrace Cloud stores audit findings, package-behavior verdicts, and SBOM inventories automatically when `SANDTRACE_API_KEY` is set, while keeping full raw traces opt-in and investigation-only.
