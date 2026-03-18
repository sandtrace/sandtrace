# Cloud Ingest

Sandtrace Cloud is split into two parts:

- the CLI uploader in `sandtrace`
- the ingest workload in `sandtrace-ingest`

The CLI produces and uploads audit, run, and SBOM payloads when `SANDTRACE_API_KEY` is set. The ingest workload receives those machine-facing payloads, validates them, persists them, and exposes lightweight read APIs for recent records and dashboard summaries. The stable contract is documented in [`docs/cloud-ingestion-spec.md`](../../docs/cloud-ingestion-spec.md).

## Why this is separate

The ingest workload is intentionally separate from the product UI.

- `sandtrace` stays a local-first CLI
- `sandtrace-ingest` stays machine-facing and write-heavy
- a future Laravel app or dashboard can sit on top of the normalized records instead of handling raw uploads directly

For `sandtrace run`, the recommended long-term product model is a separate hosted execution add-on rather than forcing privileged tracing into standard CI runners. See [Hosted Runtime Analysis](./guides/hosted-runtime-analysis.md).

## Service endpoints

Current endpoints exposed by `sandtrace-ingest`:

| Method | Path | Purpose |
|-------|------|---------|
| `GET` | `/healthz` | Liveness check |
| `GET` | `/v1/admin/api-keys` | List hashed API keys from Postgres |
| `GET` | `/v1/admin/api-key-events` | List admin API key lifecycle events from Postgres |
| `POST` | `/v1/admin/api-keys` | Mint a new API key in Postgres |
| `POST` | `/v1/admin/api-keys/{api_key_hash}` | Deactivate an API key |
| `DELETE` | `/v1/admin/api-keys/{api_key_hash}` | Permanently remove an inactive API key |
| `POST` | `/v1/admin/api-keys/{api_key_hash}/rotate` | Replace an active API key and return a new plaintext key once |
| `POST` | `/v1/ingest/audit` | Accept an `audit` upload |
| `POST` | `/v1/ingest/run` | Accept a `run` upload |
| `POST` | `/v1/ingest/sbom` | Accept an `sbom` upload |
| `GET` | `/v1/ingest/audits` | List recent audit index records |
| `GET` | `/v1/ingest/runs` | List recent run index records |
| `GET` | `/v1/ingest/sboms` | List recent SBOM index records |
| `GET` | `/v1/ingest/audit/{id}` | Fetch one audit record and payload |
| `GET` | `/v1/ingest/run/{id}` | Fetch one run record and payload |
| `GET` | `/v1/ingest/sbom/{id}` | Fetch one SBOM record and payload |
| `GET` | `/v1/projects/overview` | Return one row per visible project with latest activity and current SBOM alert counts |
| `GET` | `/v1/sbom/inventory` | Return package inventory for one SBOM or commit |
| `GET` | `/v1/sbom/timeline` | Return commit-level SBOM history with package-change and security-alert counts |
| `GET` | `/v1/sbom/diff` | Return package additions, removals, and version changes between two SBOMs |
| `GET` | `/v1/sbom/alerts` | Return direct-package additions and direct version-change alerts from the latest SBOM comparison |
| `GET` | `/v1/sbom/advisories` | Query OSV for vulnerability matches on packages from one SBOM or commit |
| `GET` | `/v1/sbom/security-alerts` | Return vulnerable direct-package additions and vulnerable direct version changes from the latest SBOM comparison |
| `GET` | `/v1/sbom/security-alerts/history` | Return persisted vulnerable package-change history with filters for project, commit, kind, and package identity |
| `GET` | `/v1/dashboard/overview` | Return dashboard-ready aggregate counts |

## Environment variables

### CLI uploader

| Variable | Purpose |
|---------|---------|
| `SANDTRACE_API_KEY` | Enables upload from `sandtrace audit`, `sandtrace run`, and `sandtrace sbom` |
| `SANDTRACE_CLOUD_URL` | Base URL for the ingest service |
| `SANDTRACE_CLOUD_TIMEOUT_MS` | Upload timeout budget |
| `SANDTRACE_CLOUD_ENVIRONMENT` | Logical environment label |
| `SANDTRACE_CLOUD_RAW_TRACE` | Raw trace policy flag parsed by the client |

### Ingest service

| Variable | Purpose |
|---------|---------|
| `SANDTRACE_INGEST_BIND` | Bind address, default `127.0.0.1:8080` |
| `SANDTRACE_INGEST_ADMIN_TOKEN` | Bearer token required for admin API key endpoints |
| `SANDTRACE_INGEST_ADMIN_SUBJECT` | Label stored in API key lifecycle events, default `admin-token` |
| `SANDTRACE_INGEST_DIR` | Storage root, default `./var/ingest` |
| `SANDTRACE_INGEST_DATABASE_URL` | Optional Postgres DSN for normalized metadata records |
| `SANDTRACE_INGEST_KEYS_FILE` | JSON file of API key principals |
| `SANDTRACE_INGEST_API_KEYS` | Comma-separated fallback key list |
| `SANDTRACE_INGEST_ORG` | Fallback org slug when using env-only keys |
| `SANDTRACE_INGEST_PROJECT` | Fallback project slug when using env-only keys |
| `SANDTRACE_INGEST_ACTOR` | Fallback actor label when using env-only keys |
| `SANDTRACE_OSV_API_URL` | Optional OSV API base URL, default `https://api.osv.dev` |
| `SANDTRACE_OSV_CACHE_TTL_HOURS` | Advisory cache freshness window in hours, default `24` |

## Principal file format

Use a JSON file when you want multiple orgs or projects on one ingest instance.

Example: [`examples/ingest-principals.json`](../../examples/ingest-principals.json)

```json
[
  {
    "api_key": "st_dev_acme_web_123",
    "org_slug": "acme",
    "project_slug": "web",
    "actor": "ci"
  }
]
```

## Local end-to-end flow

### 1. Start the ingest service

```bash
SANDTRACE_INGEST_KEYS_FILE=examples/ingest-principals.json \
cargo run --bin sandtrace-ingest
```

### 2. Send an audit upload

```bash
SANDTRACE_API_KEY=st_dev_acme_web_123 \
SANDTRACE_CLOUD_URL=http://127.0.0.1:8080 \
sandtrace audit .
```

### 3. Send a run upload

```bash
SANDTRACE_API_KEY=st_dev_acme_web_123 \
SANDTRACE_CLOUD_URL=http://127.0.0.1:8080 \
sandtrace run --trace-only /bin/true
```

### 4. Send an SBOM upload

```bash
SANDTRACE_API_KEY=st_dev_acme_web_123 \
SANDTRACE_CLOUD_URL=http://127.0.0.1:8080 \
sandtrace sbom . --output bom.json
```

### 5. Query recent ingests

```bash
curl -H "Authorization: Bearer st_dev_acme_web_123" \
  http://127.0.0.1:8080/v1/ingest/audits

curl -H "Authorization: Bearer st_dev_acme_web_123" \
  http://127.0.0.1:8080/v1/ingest/runs

curl -H "Authorization: Bearer st_dev_acme_web_123" \
  http://127.0.0.1:8080/v1/ingest/sboms
```

### 6. Query dashboard summary

```bash
curl -H "Authorization: Bearer st_dev_acme_web_123" \
  http://127.0.0.1:8080/v1/dashboard/overview
```

### 7. Mint an API key

```bash
curl -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"org_slug":"acme","project_slug":"worker","actor":"ci"}' \
  http://127.0.0.1:8080/v1/admin/api-keys
```

### 8. Rotate an API key

```bash
curl -X POST \
  -H "Authorization: Bearer dev-admin-token" \
  http://127.0.0.1:8080/v1/admin/api-keys/<api_key_hash>/rotate
```

### 9. Delete an inactive API key

```bash
curl -X DELETE \
  -H "Authorization: Bearer dev-admin-token" \
  http://127.0.0.1:8080/v1/admin/api-keys/<api_key_hash>
```

### 10. Query API key lifecycle events

```bash
curl -H "Authorization: Bearer dev-admin-token" \
  "http://127.0.0.1:8080/v1/admin/api-key-events?org_slug=acme&limit=20"
```

## Docker Compose stack

Use [`docker-compose.ingest.yml`](../../docker-compose.ingest.yml) when you want a local Postgres-backed stack without installing Rust or Postgres directly on the host.

```bash
docker compose -f docker-compose.ingest.yml up --build
```

The stack starts:

- `postgres` on `127.0.0.1:5432`
- `sandtrace-ingest` on `127.0.0.1:8080`

It uses:

- [`Dockerfile.ingest`](../../Dockerfile.ingest) for the ingest service image
- [`examples/ingest-principals.json`](../../examples/ingest-principals.json) for API key principals
- a named volume for raw payload files and a separate named volume for Postgres data

## Storage model today

Today the ingest workload stores:

- raw accepted payloads as JSON files
- normalized index records as JSON files
- records partitioned by authenticated `org_slug`

If `SANDTRACE_INGEST_DATABASE_URL` is set, normalized index records are also written to Postgres and the read endpoints prefer Postgres for list, detail, and dashboard queries. Raw payloads remain on disk.

With Postgres enabled, the ingest service also maintains:

- `organizations`
- `projects`
- `ingest_api_keys`

API keys are stored as SHA-256 hashes, not plaintext. Principals loaded from `SANDTRACE_INGEST_KEYS_FILE` or the fallback env vars are upserted into those tables on startup, and request authorization prefers the database-backed keys before falling back to in-memory config.
When Postgres auth is enabled, the database is authoritative for request auth. The file or env principals are treated as startup seed data, so deactivated or rotated keys stop working immediately even if they originally came from `SANDTRACE_INGEST_KEYS_FILE`.
Bootstrapping is non-destructive: it inserts missing keys, but it does not reactivate inactive hashes or mark keys as recently used on startup.
The admin endpoints return plaintext API keys only once at creation time. Subsequent reads expose only the stored hash and metadata.
Rotation follows the same rule: the replacement plaintext key is only returned by the rotate response, and the replaced key is marked inactive.
Deletion is only allowed for inactive keys so an admin cannot accidentally hard-delete the only active credential for a project without first revoking it.
Keys with a `project_slug` are project-scoped for reads. Keys without a `project_slug` can read records across the whole organization.

The service also records API key lifecycle events for `created`, `deactivated`, `rotated`, and `deleted`. Those events are stored in Postgres and can be queried through `/v1/admin/api-key-events` for operational auditing.

This is enough for local evaluation and API-contract testing, but not the intended production storage model.

## Production direction

The expected next step is:

1. API keys stored in a real auth table
2. normalized records in Postgres
3. raw payloads or optional raw traces in object storage
4. Laravel or another product app reading normalized records for customer-facing dashboards

## SBOM handling

SBOMs need a different treatment from `audit` and `run` because the generated CycloneDX document is already the portable artifact customers expect to export, diff, and enrich later.

The current cloud flow is:

1. `sandtrace sbom` uploads the raw CycloneDX JSON when `SANDTRACE_API_KEY` is set.
2. The ingest layer stores that raw SBOM unchanged for evidence and export use.
3. The ingest layer stores normalized SBOM summary records keyed by org, project, commit, and SBOM hash.
4. When `SANDTRACE_INGEST_DATABASE_URL` is configured, the ingest layer also writes normalized package rows into Postgres.
5. The read API serves package inventory views and commit diffs from those normalized rows when available, with file-backed fallback when they are absent.
6. The product layer can use those records for “new package introduced” alerts and future advisory enrichment.

Today that alert surface is exposed as `GET /v1/sbom/alerts`, which compares the latest SBOM to the previous SBOM for each visible project and emits only:

- new direct packages
- direct package version changes

On-demand advisory enrichment is exposed as `GET /v1/sbom/advisories`. It queries OSV for the selected SBOM or commit and returns package-to-vulnerability matches.

When `SANDTRACE_INGEST_DATABASE_URL` is configured, advisory results are cached in Postgres by package query key. The response summary includes:

- `cache_hits`
- `fresh_queries`

Security-focused change detection is exposed as `GET /v1/sbom/security-alerts`. It compares the latest SBOM to the previous SBOM for each visible project, uses the cached OSV advisory layer, and emits only:

- `new_vulnerable_direct_package`
- `vulnerable_direct_version_change`

Persisted alert history is exposed as `GET /v1/sbom/security-alerts/history`. When Postgres is enabled, the ingest service writes those alerts at SBOM ingest time and serves them back without re-querying OSV. If the persisted table is empty, the history route backfills it from normalized SBOM package rows and the OSV cache before returning results. The history endpoint supports filters for:

- `project_slug`
- `kind`
- `from_git_commit`
- `to_git_commit`
- `package_identity`

Commit history for UI timelines is exposed as `GET /v1/sbom/timeline`. It returns one record per visible SBOM upload with:

- `component_count`
- `direct_dependency_count`
- `diff_base_git_commit`
- `package_alert_count`
- `security_alert_count`

That gives the product app a single read for “what changed on this commit” without stitching together inventory, diff, and alert endpoints client-side.

Project landing views are exposed as `GET /v1/projects/overview`. It returns one row per visible project with:

- latest activity timestamp
- upload counts for `audit`, `run`, and `sbom`
- latest audit, run, and SBOM index records
- current package-change alert count for the latest SBOM
- current vulnerable package-change alert count for the latest SBOM

The contract and next persistence step live in [`docs/cloud-ingestion-spec.md`](../../docs/cloud-ingestion-spec.md) under `POST /v1/ingest/sbom`.
