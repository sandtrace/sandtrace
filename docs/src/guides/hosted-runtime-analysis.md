# Hosted Runtime Analysis

Hosted Runtime Analysis is the recommended product model for `sandtrace run`.

`audit` and `sbom` fit standard CI runners. `run` does not. It depends on `ptrace`, namespace creation, and a tightly controlled Linux environment. That makes it a separate operational product, not just another step in the default GitHub workflow.

## Product shape

Recommended packaging:

- base plan: `audit` + `sbom`
- add-on: `Hosted Runtime Analysis`
- enterprise add-on: dedicated isolated runner pool with stronger tenancy controls

Recommended positioning:

- base plan catches static package risk before merge
- hosted runtime analysis executes package install or setup commands in Sandtrace-managed workers
- customers get runtime telemetry without owning ptrace-capable CI infrastructure

## Why this should be separate

`sandtrace run` is not reliable on:

- GitHub-hosted runners
- many WSL environments
- locked-down containers without full namespace and ptrace support

It is reliable on:

- native privileged Linux hosts
- Sandtrace-managed isolated workers
- customer self-hosted runners that meet the sandbox requirements

That makes `run` a good premium capability:

- it costs real infrastructure to operate
- it needs queueing and scheduling
- it has a different support and security profile from `audit` and `sbom`

## Customer workflow

### Default flow

1. Customer installs the GitHub integration or reusable workflow.
2. Standard CI runs `sandtrace audit` and `sandtrace sbom`.
3. Customer enables Hosted Runtime Analysis for selected repos.
4. Sandtrace receives a runtime job request on selected events.
5. Sandtrace checks out the repo in an isolated privileged worker.
6. Sandtrace executes the configured command through `sandtrace run`.
7. Results are uploaded to `sandtrace-ingest` and shown in Sandtrace Cloud.
8. GitHub receives a check result or PR comment.

### First supported triggers

Ship the simplest useful set first:

- manual “Run hosted analysis” button from the product UI
- pull request to protected branch
- push to default branch

Keep the runtime trigger narrow at first:

- dependency manifest changes
- lockfile changes
- install script changes

## Repo-level configuration

Each repo that enables Hosted Runtime Analysis needs a small configuration record:

- command to execute, such as `pnpm install` or `npm ci`
- working directory
- timeout
- branch rules
- event rules
- whether outbound network is allowed
- whether child process execution is allowed

Good first defaults:

- command: package-manager install command inferred from repo files
- timeout: `300` seconds
- branch rules: protected branches and pull requests
- network: enabled only when the install process needs it
- process execution: enabled

## Architecture

Hosted Runtime Analysis should be built as a service layer around the existing ingest pipeline.

The first concrete implementation boundary is documented in [Runtime Orchestrator Spec](./runtime-orchestrator-spec.md).

### Components

- `sandtrace-web`
  - billing, repo settings, user controls, results UI
- `runtime-orchestrator`
  - accepts jobs, schedules workers, tracks status
- `runtime-workers`
  - ephemeral privileged Linux workers that execute `sandtrace run`
- `sandtrace-ingest`
  - accepts normalized `run` uploads and serves read APIs
- queue and metadata store
  - job state, retries, metering, worker assignment

### Execution path

1. Product UI or GitHub event requests a hosted runtime job.
2. `runtime-orchestrator` validates plan entitlements and repo settings.
3. Orchestrator creates a queued job.
4. A worker claims the job.
5. Worker fetches repo contents with a GitHub App installation token.
6. Worker executes the configured command through `sandtrace run`.
7. Worker uploads the resulting `run` payload to `sandtrace-ingest`.
8. Orchestrator marks the job complete and publishes check/status output back to GitHub.

### Worker requirements

Workers should be:

- native Linux
- ephemeral per job
- privileged enough for `ptrace` and namespace creation
- isolated from one another
- configured with strict egress policy
- short-lived with guaranteed teardown

## Security model

Hosted Runtime Analysis is higher risk than static scanning and should be designed that way from the start.

### Required controls

- one fresh worker per job
- no shared writable workspace between jobs
- installation-token checkout instead of long-lived repo credentials
- short-lived upload credentials
- strict timeout and kill behavior
- upload only the normalized `run` result and selected evidence
- explicit retention policy for raw traces or evidence slices

### Recommended controls

- outbound network policy per job
- package registry allowlists
- environment variable injection policy
- encryption for evidence at rest
- audit log for who triggered each run

## Billing model

Recommended packaging:

- base plan includes `audit` and `sbom`
- Hosted Runtime Analysis is an add-on
- enterprise tier can upgrade to dedicated workers

Recommended metering:

- base add-on fee
- plus usage by runtime minute or completed run

This matches the actual cost model better than folding `run` into the base plan.

## UI changes

Sandtrace Cloud should expose Hosted Runtime Analysis as a clearly separate capability.

### Billing and plan UI

- add-on enabled or disabled
- monthly usage summary
- run-minute or run-count consumption
- upgrade CTA when disabled

### Repo settings UI

- enable hosted runtime analysis for this repo
- command to execute
- branch and event rules
- timeout
- network policy

### Results UI

- list of hosted runtime jobs
- current job status
- run detail page
- verdict, suspicious events, and evidence summary
- links from project pages into runtime results

## MVP scope

The first version should stay intentionally narrow.

### Include

- shared worker pool only
- one Linux base image
- one command per repo
- manual trigger plus pull-request trigger
- upload results into the existing `run` cloud views
- basic GitHub check status output

### Exclude

- customer-provided base images
- private networking
- long-lived workers
- multi-step runtime pipelines
- arbitrary secrets passthrough
- non-Linux workers

## Recommended rollout

1. Keep `audit` and `sbom` in the current reusable GitHub workflow.
2. Treat local `sandtrace run` as an advanced developer workflow.
3. Build Hosted Runtime Analysis as a paid Sandtrace-managed execution path.
4. Add GitHub App support for repo installation, status checks, and job triggering.
5. Keep the existing ingest service as the storage and read boundary for results.

## Current recommendation

Until Hosted Runtime Analysis exists, the practical support model is:

- CI: `audit` + `sbom`
- local or self-hosted privileged Linux: `run`
- WSL: best-effort only, not a supported `run` platform

That keeps the current product reliable while leaving a clear path to a premium hosted execution model.
