# Sandtrace Cloud Export And Monetization Assessment

Date: 2026-03-12

## Bottom line

Sandtrace already has enough structured output to support a paid cloud product.

The fastest path is not a full "developer EDR cloud." The fastest path is:

1. Upload `audit` findings.
2. Upload `run` summaries plus selected suspicious trace slices.
3. Sell team visibility, history, CI gating, and alerts.

## What `audit` already produces

`sandtrace audit` already produces structured findings that are straightforward to export.

Source references:

- `src/event.rs`
- `src/audit/mod.rs`

Current finding shape:

- `file_path`
- `line_number`
- `rule_id`
- `severity`
- `description`
- `matched_pattern`
- `context_lines`

Current output modes:

- Terminal
- JSON
- SARIF

Commercially useful outcomes:

- Centralized finding history by repo / branch / team
- Severity dashboards
- Policy gating in CI
- Compliance evidence and trend reporting
- Finding deduplication and remediation workflows

## What `run` already produces

`sandtrace run` already emits JSONL events that are rich enough for cloud-side analysis.

Source references:

- `src/event.rs`
- `src/tracer/mod.rs`
- `src/tracer/decoder.rs`
- `src/output/jsonl.rs`

Current event families:

- `syscall`
- `process`
- `summary`

Important `syscall` fields already available:

- timestamp
- pid / tgid
- syscall name and number
- raw args
- decoded args when available
- return value
- success / failure
- duration
- allow / deny action
- syscall category

Important decoded data already available:

- file paths from `open/openat`
- network addresses from `connect`
- exec paths from `execve`
- chmod/chown/rename/mkdir paths
- mmap / mprotect flags

Important `summary` fields already available:

- `total_syscalls`
- `unique_syscalls`
- `denied_count`
- `process_count`
- `duration_ms`
- `exit_code`
- `files_accessed`
- `network_attempts`
- `suspicious_activity`

Commercially useful outcomes:

- "What did this package install actually do?"
- High-signal package verdicts from runtime behavior
- Team-wide historical install activity
- Alerting on credential access, network calls, or denied syscalls
- Behavioral fingerprints for repeated package versions

## What is already pointing at a cloud product

There is a telemetry stub in `src/telemetry.rs` with a comment that explicitly says it is for a future paid cloud dashboard.

Current telemetry shape is intentionally privacy-preserving:

- timestamp
- process name hash
- path pattern
- severity
- rule id

That is the right default shape for an opt-in SaaS tier.

## Gaps that matter before selling this

### 1. The code has schemas that are not yet emitted

`TraceEvent` defines `FileAccess`, `RuleMatch`, and `AuditFinding`, but the current `run` path emits only syscall, process, and summary events.

Implication:

- The cloud story is viable now.
- The richer "developer EDR dashboard" story is ahead of the implementation.

### 2. Raw syscall export is too heavy and too sensitive as the default

`run` can surface real file paths and network targets.

Implication:

- Default SaaS ingestion should not be "upload every syscall."
- Default SaaS ingestion should be summaries, suspicious activities, policy denials, and selected abnormal events.
- Full raw trace upload should be an explicit opt-in for incident investigation.

### 3. Docs are currently ahead of or inconsistent with implementation

Observed mismatches:

- `docs/src/ci-cd.md` documents `audit --format json` as an object with `findings` and `summary`, but the implementation prints a JSON array.
- `docs/src/commands/run.md` shows process events with `action` / `comm`, but the actual process schema uses serde tagging with `kind` and fields like `path` / `argv`.

Implication:

- Fix this before exposing an ingestion API.
- Otherwise early users will build against the wrong schema.

## Fastest monetizable product shape

## Team plan

Ship this first:

- CLI stays open source.
- Cloud accepts signed uploads from `audit` and `run`.
- Cloud stores:
  - audit findings
  - run summaries
  - denied syscalls
  - suspicious activity
  - optional suspicious syscall excerpts
- Cloud shows:
  - per-repo and per-package verdict history
  - alert feed
  - top risky packages
  - install behavior timelines
  - exportable CSV / JSON / SARIF artifacts

This can be sold as:

"Behavioral package analysis and team visibility for install-time supply-chain risk."

## Enterprise plan

Add later:

- SSO / SAML
- on-prem deployment
- longer retention
- full trace retention
- SIEM forwarding
- policy packs

## What to avoid

Do not lead with "developer EDR" as the monetization wedge.

Why:

- The website currently positions Sandtrace as a broad developer EDR.
- The best differentiated asset in the code and in the marketing plan is sandboxed runtime analysis of installs and untrusted package behavior.
- That is easier to explain, easier to price, and easier to compare against current market demand.

## Website and GTM observations

The current site in `~/sandtrace/web` is not aligned with the strongest monetization path.

### Current site strength

- Pricing already frames cloud as team visibility.
- A leads table and lead controller already exist.

### Current site weakness

- Homepage headline is generic "Developer EDR."
- Homepage CTA pushes GitHub and docs, not waitlist capture.
- Pricing advertises `$29/dev/mo`, but there is no active waitlist form on the pricing page.
- The best message from the marketing plan, "Know what runs before you run it," is not the primary site message.

## Recommended sequence

### This week

1. Reposition the website around sandboxed package-install analysis.
2. Add an actual waitlist / demo request form to pricing using the existing leads backend.
3. Define a stable cloud ingestion schema for:
   - audit finding upload
   - run summary upload
   - suspicious event upload

### Next

1. Add opt-in telemetry upload in the CLI behind a flag and config.
2. Normalize / hash sensitive paths by default.
3. Build the smallest dashboard possible:
   - org
   - repo
   - package
   - verdict
   - time
   - severity

## Pricing sanity check

Current website pricing seeds Team at `$29/dev/mo`.

That is plausible, but only if the cloud tier clearly includes:

- shared visibility
- history
- alerts
- policy / CI value

Competitor reference points checked on 2026-03-12:

- Socket Team: `$25` per developer per month, with analytics/reporting, Slack alerts, and higher scan quotas.
- Socket Business: `$50` per developer per month, including unlimited scans/API and SSO/SAML.
- Snyk Team: starting at `$25/month` per contributing developer.

Conclusion:

- `$29/dev/mo` is not obviously too high.
- It is too high for a vague "coming soon" message.
- It is reasonable for a concrete team dashboard plus CI/package verdict workflow.
