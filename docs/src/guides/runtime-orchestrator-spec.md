# Runtime Orchestrator Spec

This document defines the first implementation boundary for Hosted Runtime Analysis.

`sandtrace-ingest` already accepts normalized `run` uploads. The missing piece is the service that decides when to execute a hosted runtime job, how a worker claims it, and how the result is handed off to ingest.

## Scope

This spec covers:

- job submission
- job state transitions
- worker lease behavior
- runtime execution payloads
- result upload handoff into `sandtrace-ingest`
- minimal database schema

This spec does not cover:

- customer billing calculations
- dedicated worker pools
- custom base images
- private networking
- full GitHub App design

## Core model

### Job lifecycle

Each hosted runtime execution is a `runtime_job`.

Required high-level states:

- `queued`
- `running`
- `uploaded`
- `failed`
- `canceled`

Optional internal states that are useful but not required on day one:

- `lease_acquired`
- `checking_out`
- `executing`
- `uploading`

The public API should expose only the high-level states unless debugging requires more detail.

### State rules

- new jobs start as `queued`
- only a worker with an active lease can move a job to `running`
- a job becomes `uploaded` only after `sandtrace-ingest` acknowledges the run payload
- terminal states are `uploaded`, `failed`, and `canceled`
- terminal jobs cannot be resumed; retries create a new job row linked to the original

## Job submission API

The orchestrator should accept a single create-job request from either the product UI or a GitHub-triggered integration layer.

### `POST /v1/runtime/jobs`

Creates a hosted runtime job.

Example request:

```json
{
  "org_slug": "sandtrace",
  "project_slug": "web",
  "source": {
    "kind": "github",
    "repo_url": "https://github.com/cc-consulting-nv/web.git",
    "owner": "cc-consulting-nv",
    "repo": "web",
    "ref": "refs/heads/main",
    "git_commit": "c13aa82903ea336cf3f21bdf2d930dc1a41f65cf",
    "pull_request_number": 98
  },
  "execution": {
    "working_directory": ".",
    "command": [
      "pnpm",
      "install"
    ],
    "timeout_seconds": 300,
    "allow_network": true,
    "allow_exec": true
  },
  "trigger": {
    "kind": "pull_request",
    "actor": "github-app"
  }
}
```

Example response:

```json
{
  "job_id": "rtj_01kkygkagq0jk17bx6y1w8c3df",
  "status": "queued",
  "created_at": "2026-03-17T20:00:00Z"
}
```

### Validation rules

- org must have Hosted Runtime Analysis enabled
- repo/project must be enabled for hosted runtime analysis
- `command` must be non-empty
- `timeout_seconds` must be within the allowed plan limit
- `repo_url` and `git_commit` must be present

## Job query API

### `GET /v1/runtime/jobs`

Lists jobs for a visible org or project.

Recommended filters:

- `project_slug`
- `status`
- `trigger_kind`
- `git_commit`
- `limit`

### `GET /v1/runtime/jobs/{job_id}`

Returns the job record, current status, and last event summary.

### `POST /v1/runtime/jobs/{job_id}/cancel`

Cancels a job if it is still `queued` or `running`.

If a worker already holds a lease, the worker should observe the cancellation signal and stop execution as soon as possible.

## Worker lease API

Workers should not scan the database directly for jobs. Use a lease endpoint so orchestration policy stays centralized.

### `POST /v1/runtime/leases`

Claims one queued job and returns a worker lease plus the full execution payload.

Example request:

```json
{
  "worker_id": "wrk_01kkygmfjf4j9s26hzd0h93j0r",
  "pool": "shared-linux",
  "capabilities": {
    "linux": true,
    "ptrace": true,
    "namespaces": true
  }
}
```

Example response:

```json
{
  "lease_id": "rtl_01kkygn4z3fkef0g4tgm6g3b1j",
  "job": {
    "job_id": "rtj_01kkygkagq0jk17bx6y1w8c3df",
    "org_slug": "sandtrace",
    "project_slug": "web",
    "source": {
      "repo_url": "https://github.com/cc-consulting-nv/web.git",
      "owner": "cc-consulting-nv",
      "repo": "web",
      "ref": "refs/heads/main",
      "git_commit": "c13aa82903ea336cf3f21bdf2d930dc1a41f65cf"
    },
    "execution": {
      "working_directory": ".",
      "command": [
        "pnpm",
        "install"
      ],
      "timeout_seconds": 300,
      "allow_network": true,
      "allow_exec": true
    }
  },
  "lease_expires_at": "2026-03-17T20:05:00Z"
}
```

### Lease rules

- a lease is exclusive to one worker
- a lease must expire automatically
- workers must renew the lease while running long jobs
- expired leases return the job to `queued` or `failed`, depending on retry policy
- lease expiry should emit a job event

### `POST /v1/runtime/leases/{lease_id}/heartbeat`

Renews the lease expiry while the job is still healthy.

### `POST /v1/runtime/leases/{lease_id}/complete`

Marks worker execution complete and provides the ingest handoff details.

Example request:

```json
{
  "result": {
    "status": "uploaded",
    "ingest_run_id": "run_20260317143329_bd39b25f6f31",
    "uploaded_at": "2026-03-17T20:03:20Z"
  }
}
```

### `POST /v1/runtime/leases/{lease_id}/fail`

Marks the job failed and includes failure metadata.

Example request:

```json
{
  "result": {
    "status": "failed",
    "reason": "sandbox_apply_failed",
    "message": "Namespace creation failed: EPERM"
  }
}
```

## Result upload handoff

The worker should upload the final `run` result to `sandtrace-ingest` using the existing ingest contract instead of inventing a second result store.

### Worker flow

1. worker claims lease
2. worker checks out repo
3. worker executes `sandtrace run`
4. worker uploads the normalized `run` payload to `POST /v1/ingest/run`
5. worker records the returned `run_id`
6. worker completes the lease with `status=uploaded`

### Required run upload metadata

The worker-generated upload should include:

- `org_slug`
- `project_slug`
- `repo_url`
- `git_commit`
- `command`
- `trigger_kind`
- `worker_id`
- `job_id`

`job_id` should be preserved inside the run payload metadata so the UI can link a hosted runtime job to the stored run record.

## Minimal database schema

The first implementation only needs three tables.

### `runtime_jobs`

Suggested columns:

- `id`
- `job_ulid`
- `org_slug`
- `project_slug`
- `source_kind`
- `repo_url`
- `repo_owner`
- `repo_name`
- `git_ref`
- `git_commit`
- `pull_request_number`
- `trigger_kind`
- `trigger_actor`
- `working_directory`
- `command_json`
- `timeout_seconds`
- `allow_network`
- `allow_exec`
- `status`
- `retry_of_job_ulid`
- `ingest_run_id`
- `failure_reason`
- `failure_message`
- `created_at`
- `started_at`
- `finished_at`

Indexes:

- `(org_slug, project_slug, created_at desc)`
- `(org_slug, git_commit)`
- `(status, created_at)`
- unique `(job_ulid)`

### `runtime_job_events`

Suggested columns:

- `id`
- `job_ulid`
- `event_type`
- `actor_kind`
- `actor_id`
- `payload_json`
- `created_at`

Purpose:

- audit trail
- debugging
- timeline rendering

### `runtime_worker_leases`

Suggested columns:

- `id`
- `lease_ulid`
- `job_ulid`
- `worker_id`
- `pool`
- `status`
- `leased_at`
- `expires_at`
- `completed_at`

Indexes:

- unique `(lease_ulid)`
- `(job_ulid, status)`
- `(worker_id, status)`

## Retry policy

The first version should stay conservative.

- no automatic retry for successful upload failures without operator review
- allow one automatic retry for worker crash or lease expiry
- do not retry permanent validation failures
- retries create a new `runtime_jobs` row with `retry_of_job_ulid` set

## UI implications

The product UI will need these read shapes later:

- recent hosted jobs per project
- job detail by `job_id`
- status badge for `queued`, `running`, `uploaded`, `failed`, `canceled`
- link from job detail to the uploaded run detail when `ingest_run_id` exists

That means the orchestrator should preserve `ingest_run_id` and terminal failure details from the first version onward.

## MVP recommendations

The first implementation should:

- support only GitHub-backed jobs
- use one shared Linux worker pool
- allow one command per repo
- support only manual and pull-request triggers
- upload only the final normalized run payload

Do not add these yet:

- customer-provided worker images
- multi-step pipelines
- arbitrary environment variable passthrough
- private networking
- non-GitHub source providers

## Relationship to current product behavior

Until the orchestrator exists:

- `audit` and `sbom` stay in standard CI
- `run` stays local or self-hosted on a privileged Linux environment

This spec is the bridge from that model to a hosted paid add-on.
