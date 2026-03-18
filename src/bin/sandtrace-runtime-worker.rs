use anyhow::Context;
use chrono::Utc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::watch;
use tokio::time::{sleep, Duration, MissedTickBehavior};
use ulid::Ulid;

#[derive(Debug, Deserialize)]
struct LeaseResponse {
    lease_id: String,
    job: LeaseJob,
}

#[derive(Debug, Deserialize)]
struct LeaseJob {
    job_id: String,
    org_slug: String,
    project_slug: String,
    source: SourcePayload,
    execution: ExecutionPayload,
}

#[derive(Debug, Deserialize)]
struct SourcePayload {
    kind: String,
    repo_url: String,
    owner: Option<String>,
    repo: Option<String>,
    #[serde(default)]
    r#ref: Option<String>,
    git_commit: String,
    #[serde(default)]
    pull_request_number: Option<i32>,
}

#[derive(Debug, Deserialize)]
struct ExecutionPayload {
    working_directory: String,
    command: Vec<String>,
    timeout_seconds: i32,
    #[serde(default)]
    allow_network: bool,
    #[serde(default)]
    allow_exec: bool,
}

#[derive(Debug, Serialize)]
struct ClaimLeaseRequest<'a> {
    worker_id: &'a str,
    pool: &'a str,
    capabilities: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct CompleteLeaseRequest {
    result: CompleteLeaseResult,
}

#[derive(Debug, Serialize)]
struct CompleteLeaseResult {
    status: &'static str,
    ingest_run_id: String,
    uploaded_at: String,
}

#[derive(Debug, Serialize)]
struct FailLeaseRequest {
    result: FailLeaseResult,
}

#[derive(Debug, Serialize)]
struct FailLeaseResult {
    status: &'static str,
    reason: String,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutionMode {
    StubUploaded,
    StubFailed,
    Command,
}

impl ExecutionMode {
    fn from_env() -> Self {
        match std::env::var("SANDTRACE_RUNTIME_EXECUTION_MODE")
            .unwrap_or_else(|_| "stub".to_string())
            .to_lowercase()
            .as_str()
        {
            "command" => return Self::Command,
            "failed" => return Self::StubFailed,
            "uploaded" => return Self::StubUploaded,
            _ => {}
        }

        match std::env::var("SANDTRACE_RUNTIME_STUB_MODE")
            .unwrap_or_else(|_| "uploaded".to_string())
            .to_lowercase()
            .as_str()
        {
            "failed" => Self::StubFailed,
            _ => Self::StubUploaded,
        }
    }
}

#[derive(Debug, Clone)]
struct WorkerConfig {
    runtime_url: String,
    worker_id: String,
    pool: String,
    worker_token: Option<String>,
    execution_mode: ExecutionMode,
    stub_delay_secs: u64,
    heartbeat_secs: u64,
    git_bin: String,
    workspace_root: Option<PathBuf>,
}

#[derive(Debug)]
enum WorkerOutcome {
    Uploaded(String),
}

#[derive(Debug)]
struct WorkerFailure {
    reason: String,
    message: String,
}

impl WorkerFailure {
    fn new(reason: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            message: message.into(),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let config = WorkerConfig {
        runtime_url: std::env::var("SANDTRACE_RUNTIME_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string())
            .trim_end_matches('/')
            .to_string(),
        worker_id: std::env::var("SANDTRACE_RUNTIME_WORKER_ID")
            .unwrap_or_else(|_| format!("wrk_{}", Ulid::new().to_string().to_lowercase())),
        pool: std::env::var("SANDTRACE_RUNTIME_WORKER_POOL")
            .unwrap_or_else(|_| "shared-linux".to_string()),
        worker_token: std::env::var("SANDTRACE_RUNTIME_WORKER_TOKEN").ok(),
        execution_mode: ExecutionMode::from_env(),
        stub_delay_secs: std::env::var("SANDTRACE_RUNTIME_STUB_DELAY_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(5),
        heartbeat_secs: std::env::var("SANDTRACE_RUNTIME_HEARTBEAT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(30),
        git_bin: std::env::var("SANDTRACE_RUNTIME_GIT_BIN").unwrap_or_else(|_| "git".to_string()),
        workspace_root: std::env::var_os("SANDTRACE_RUNTIME_WORKSPACE_ROOT").map(PathBuf::from),
    };

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build runtime worker http client")?;

    let lease = claim_lease(
        &client,
        &config.runtime_url,
        &config.worker_id,
        &config.pool,
        config.worker_token.as_deref(),
    )
    .await?;

    let Some(lease) = lease else {
        eprintln!("sandtrace-runtime-worker: no queued runtime jobs");
        return Ok(());
    };

    eprintln!(
        "sandtrace-runtime-worker: claimed {} for {}/{} {} {:?}",
        lease.job.job_id,
        lease.job.org_slug,
        lease.job.project_slug,
        lease.job.source.repo_url,
        lease.job.execution.command
    );

    let (stop_heartbeat_tx, stop_heartbeat_rx) = watch::channel(false);
    let heartbeat_task = tokio::spawn(heartbeat_loop(
        client.clone(),
        config.runtime_url.clone(),
        lease.lease_id.clone(),
        config.worker_token.clone(),
        config.heartbeat_secs,
        stop_heartbeat_rx,
    ));

    let outcome = match config.execution_mode {
        ExecutionMode::StubUploaded => run_stub_success(&config).await.map(WorkerOutcome::Uploaded),
        ExecutionMode::StubFailed => run_stub_failure(&config).await.map(WorkerOutcome::Uploaded),
        ExecutionMode::Command => run_command_mode(&lease.job, &config)
            .await
            .map(WorkerOutcome::Uploaded),
    };

    let _ = stop_heartbeat_tx.send(true);
    let _ = heartbeat_task.await;

    match outcome {
        Ok(WorkerOutcome::Uploaded(ingest_run_id)) => {
            complete_lease(
                &client,
                &config.runtime_url,
                &lease.lease_id,
                &ingest_run_id,
                config.worker_token.as_deref(),
            )
            .await?;
            eprintln!(
                "sandtrace-runtime-worker: marked {} uploaded with ingest_run_id={}",
                lease.job.job_id, ingest_run_id
            );
        }
        Err(failure) => {
            fail_lease(
                &client,
                &config.runtime_url,
                &lease.lease_id,
                &failure.reason,
                &failure.message,
                config.worker_token.as_deref(),
            )
            .await?;
            eprintln!(
                "sandtrace-runtime-worker: marked {} failed: {}",
                lease.job.job_id, failure.message
            );
        }
    }

    Ok(())
}

async fn claim_lease(
    client: &reqwest::Client,
    runtime_url: &str,
    worker_id: &str,
    pool: &str,
    worker_token: Option<&str>,
) -> anyhow::Result<Option<LeaseResponse>> {
    let request = ClaimLeaseRequest {
        worker_id,
        pool,
        capabilities: json!({
            "linux": true,
            "ptrace": true,
            "namespaces": true
        }),
    };

    let mut builder = client
        .post(format!("{runtime_url}/v1/runtime/leases"))
        .json(&request);
    if let Some(token) = worker_token {
        builder = builder.bearer_auth(token);
    }

    let response = builder
        .send()
        .await
        .context("failed to claim runtime lease")?;
    match response.status() {
        StatusCode::OK => Ok(Some(
            response
                .json::<LeaseResponse>()
                .await
                .context("failed to decode lease response")?,
        )),
        StatusCode::NOT_FOUND => Ok(None),
        status => {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("runtime lease claim failed: {status} {body}");
        }
    }
}

async fn send_heartbeat(
    client: &reqwest::Client,
    runtime_url: &str,
    lease_id: &str,
    worker_token: Option<&str>,
) -> anyhow::Result<()> {
    let mut builder = client.post(format!(
        "{runtime_url}/v1/runtime/leases/{lease_id}/heartbeat"
    ));
    if let Some(token) = worker_token {
        builder = builder.bearer_auth(token);
    }
    let response = builder.send().await.context("failed to heartbeat lease")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("runtime lease heartbeat failed: {status} {body}");
    }
    Ok(())
}

async fn complete_lease(
    client: &reqwest::Client,
    runtime_url: &str,
    lease_id: &str,
    ingest_run_id: &str,
    worker_token: Option<&str>,
) -> anyhow::Result<()> {
    let request = CompleteLeaseRequest {
        result: CompleteLeaseResult {
            status: "uploaded",
            ingest_run_id: ingest_run_id.to_string(),
            uploaded_at: Utc::now().to_rfc3339(),
        },
    };
    let mut builder = client
        .post(format!(
            "{runtime_url}/v1/runtime/leases/{lease_id}/complete"
        ))
        .json(&request);
    if let Some(token) = worker_token {
        builder = builder.bearer_auth(token);
    }
    let response = builder.send().await.context("failed to complete lease")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("runtime lease completion failed: {status} {body}");
    }
    Ok(())
}

async fn fail_lease(
    client: &reqwest::Client,
    runtime_url: &str,
    lease_id: &str,
    reason: &str,
    message: &str,
    worker_token: Option<&str>,
) -> anyhow::Result<()> {
    let request = FailLeaseRequest {
        result: FailLeaseResult {
            status: "failed",
            reason: reason.to_string(),
            message: message.to_string(),
        },
    };
    let mut builder = client
        .post(format!("{runtime_url}/v1/runtime/leases/{lease_id}/fail"))
        .json(&request);
    if let Some(token) = worker_token {
        builder = builder.bearer_auth(token);
    }
    let response = builder.send().await.context("failed to fail lease")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("runtime lease failure update failed: {status} {body}");
    }
    Ok(())
}

async fn heartbeat_loop(
    client: reqwest::Client,
    runtime_url: String,
    lease_id: String,
    worker_token: Option<String>,
    heartbeat_secs: u64,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut heartbeat = tokio::time::interval(Duration::from_secs(heartbeat_secs));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;

    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                if let Err(error) = send_heartbeat(&client, &runtime_url, &lease_id, worker_token.as_deref()).await {
                    eprintln!("sandtrace-runtime-worker: heartbeat failed for {lease_id}: {error:#}");
                }
            }
            changed = stop_rx.changed() => {
                if changed.is_err() || *stop_rx.borrow() {
                    break;
                }
            }
        }
    }
}

async fn run_stub_success(config: &WorkerConfig) -> Result<String, WorkerFailure> {
    let mut remaining = config.stub_delay_secs;
    while remaining > 0 {
        let step = remaining.min(config.heartbeat_secs);
        sleep(Duration::from_secs(step)).await;
        remaining -= step;
    }

    Ok(std::env::var("SANDTRACE_RUNTIME_STUB_INGEST_RUN_ID")
        .unwrap_or_else(|_| format!("run_stub_{}", Ulid::new().to_string().to_lowercase())))
}

async fn run_stub_failure(config: &WorkerConfig) -> Result<String, WorkerFailure> {
    let mut remaining = config.stub_delay_secs;
    while remaining > 0 {
        let step = remaining.min(config.heartbeat_secs);
        sleep(Duration::from_secs(step)).await;
        remaining -= step;
    }

    Err(WorkerFailure::new(
        "stub_failed",
        "runtime worker stub marked the job failed",
    ))
}

async fn run_command_mode(job: &LeaseJob, config: &WorkerConfig) -> Result<String, WorkerFailure> {
    let workspace = prepare_workspace(job, config)?;
    let checkout_dir = workspace.path().join("repo");

    checkout_repo(&config.git_bin, job, &checkout_dir).await?;

    let working_directory =
        resolve_working_directory(&checkout_dir, &job.execution.working_directory)?;
    let mut command = build_command(job, &working_directory)?;
    let output = tokio::time::timeout(
        Duration::from_secs(job.execution.timeout_seconds.max(1) as u64),
        command.output(),
    )
    .await
    .map_err(|_| WorkerFailure::new("timeout", "runtime command timed out"))?
    .map_err(|error| WorkerFailure::new("command_spawn_failed", error.to_string()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let message = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("command exited with status {}", output.status)
        };

        return Err(WorkerFailure::new("command_failed", message));
    }

    Ok(format!(
        "run_cmd_{}",
        Ulid::new().to_string().to_lowercase()
    ))
}

fn prepare_workspace(job: &LeaseJob, config: &WorkerConfig) -> Result<TempDir, WorkerFailure> {
    let prefix = format!("sandtrace-runtime-{}-", job.job_id);
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);

    match &config.workspace_root {
        Some(root) => builder
            .tempdir_in(root)
            .map_err(|error| WorkerFailure::new("workspace_create_failed", error.to_string())),
        None => builder
            .tempdir()
            .map_err(|error| WorkerFailure::new("workspace_create_failed", error.to_string())),
    }
}

async fn checkout_repo(
    git_bin: &str,
    job: &LeaseJob,
    checkout_dir: &Path,
) -> Result<(), WorkerFailure> {
    let clone_status = Command::new(git_bin)
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--no-tags")
        .arg("--branch")
        .arg(clone_ref(job))
        .arg(&job.source.repo_url)
        .arg(checkout_dir)
        .status()
        .await
        .map_err(|error| WorkerFailure::new("checkout_failed", error.to_string()))?;

    if !clone_status.success() {
        return Err(WorkerFailure::new(
            "checkout_failed",
            format!("git clone failed with status {clone_status}"),
        ));
    }

    let fetch_status = Command::new(git_bin)
        .arg("-C")
        .arg(checkout_dir)
        .arg("fetch")
        .arg("--depth")
        .arg("1")
        .arg("origin")
        .arg(&job.source.git_commit)
        .status()
        .await
        .map_err(|error| WorkerFailure::new("checkout_failed", error.to_string()))?;

    if !fetch_status.success() {
        return Err(WorkerFailure::new(
            "checkout_failed",
            format!("git fetch failed with status {fetch_status}"),
        ));
    }

    let checkout_status = Command::new(git_bin)
        .arg("-C")
        .arg(checkout_dir)
        .arg("checkout")
        .arg("--detach")
        .arg(&job.source.git_commit)
        .status()
        .await
        .map_err(|error| WorkerFailure::new("checkout_failed", error.to_string()))?;

    if !checkout_status.success() {
        return Err(WorkerFailure::new(
            "checkout_failed",
            format!("git checkout failed with status {checkout_status}"),
        ));
    }

    Ok(())
}

fn resolve_working_directory(
    checkout_dir: &Path,
    working_directory: &str,
) -> Result<PathBuf, WorkerFailure> {
    let working_path = Path::new(working_directory);
    if working_path.is_absolute() {
        return Err(WorkerFailure::new(
            "invalid_working_directory",
            "working_directory must be relative",
        ));
    }

    if working_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(WorkerFailure::new(
            "invalid_working_directory",
            "working_directory must not escape the checkout",
        ));
    }

    let resolved = checkout_dir.join(working_path);
    if !resolved.exists() {
        return Err(WorkerFailure::new(
            "invalid_working_directory",
            format!("working directory does not exist: {}", resolved.display()),
        ));
    }

    Ok(resolved)
}

fn build_command(job: &LeaseJob, working_directory: &Path) -> Result<Command, WorkerFailure> {
    if job.execution.command.is_empty() {
        return Err(WorkerFailure::new(
            "invalid_command",
            "execution command is empty",
        ));
    }

    let mut command = Command::new(&job.execution.command[0]);
    command.args(&job.execution.command[1..]);
    command.current_dir(working_directory);
    Ok(command)
}

fn clone_ref(job: &LeaseJob) -> &str {
    job.source
        .r#ref
        .as_deref()
        .and_then(normalize_ref_name)
        .unwrap_or("main")
}

fn normalize_ref_name(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.rsplit('/').next().unwrap_or(trimmed))
}

#[cfg(test)]
mod tests {
    use super::{normalize_ref_name, resolve_working_directory};

    #[test]
    fn normalize_ref_name_handles_head_refs() {
        assert_eq!(normalize_ref_name("refs/heads/main"), Some("main"));
        assert_eq!(normalize_ref_name("refs/pull/123/head"), Some("head"));
        assert_eq!(normalize_ref_name("main"), Some("main"));
        assert_eq!(normalize_ref_name(""), None);
    }

    #[test]
    fn resolve_working_directory_rejects_parent_dirs() {
        let checkout = tempfile::tempdir().unwrap();
        let error = resolve_working_directory(checkout.path(), "../secret").unwrap_err();

        assert_eq!(error.reason, "invalid_working_directory");
    }
}
