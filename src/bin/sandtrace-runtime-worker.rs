use anyhow::Context;
use chrono::Utc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
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
    sandtrace_bin: Option<PathBuf>,
    ingest_url: Option<String>,
    ingest_api_key: Option<String>,
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
        sandtrace_bin: std::env::var_os("SANDTRACE_RUNTIME_SANDTRACE_BIN").map(PathBuf::from),
        ingest_url: std::env::var("SANDTRACE_RUNTIME_INGEST_URL")
            .ok()
            .or_else(|| std::env::var("SANDTRACE_CLOUD_URL").ok())
            .map(|value| value.trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty()),
        ingest_api_key: std::env::var("SANDTRACE_RUNTIME_INGEST_API_KEY")
            .ok()
            .or_else(|| std::env::var("SANDTRACE_API_KEY").ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
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
    let ingest_api_key = config.ingest_api_key.as_ref().ok_or_else(|| {
        WorkerFailure::new(
            "missing_ingest_api_key",
            "configure SANDTRACE_RUNTIME_INGEST_API_KEY or SANDTRACE_API_KEY",
        )
    })?;
    let ingest_url = config.ingest_url.as_ref().ok_or_else(|| {
        WorkerFailure::new(
            "missing_ingest_url",
            "configure SANDTRACE_RUNTIME_INGEST_URL or SANDTRACE_CLOUD_URL",
        )
    })?;
    let workspace = prepare_workspace(job, config)?;
    let checkout_dir = workspace.path().join("repo");

    checkout_repo(&config.git_bin, job, &checkout_dir).await?;

    let working_directory =
        resolve_working_directory(&checkout_dir, &job.execution.working_directory)?;
    let sandtrace_bin = resolve_sandtrace_bin(config);
    let output_path = workspace.path().join("sandtrace-run.jsonl");
    let result_path = workspace.path().join("sandtrace-cloud-result.json");
    let mut command =
        build_sandtrace_command(&sandtrace_bin, job, &working_directory, &output_path)?;
    command.env("SANDTRACE_API_KEY", ingest_api_key);
    command.env("SANDTRACE_CLOUD_URL", ingest_url);
    command.env("SANDTRACE_CLOUD_RESULT_FILE", &result_path);
    command.env("SANDTRACE_CLOUD_ENVIRONMENT", "hosted_runtime");
    let output = tokio::time::timeout(
        Duration::from_secs(job.execution.timeout_seconds.max(1) as u64 + 30),
        command.output(),
    )
    .await
    .map_err(|_| WorkerFailure::new("timeout", "runtime command timed out"))?
    .map_err(|error| WorkerFailure::new("command_spawn_failed", error.to_string()))?;

    if let Some(run_id) = load_ingest_run_id(&result_path)? {
        return Ok(run_id);
    }

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

    Err(WorkerFailure::new(
        "ingest_upload_missing",
        format!(
            "sandtrace run completed without a cloud result file: {}",
            result_path.display()
        ),
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

fn build_sandtrace_command(
    sandtrace_bin: &Path,
    job: &LeaseJob,
    working_directory: &Path,
    output_path: &Path,
) -> Result<Command, WorkerFailure> {
    if job.execution.command.is_empty() {
        return Err(WorkerFailure::new(
            "invalid_command",
            "execution command is empty",
        ));
    }

    let mut command = Command::new(sandtrace_bin);
    command.arg("run");
    if job.execution.allow_network {
        command.arg("--allow-net");
    }
    if job.execution.allow_exec {
        command.arg("--allow-exec");
    }
    command.arg("--timeout");
    command.arg(job.execution.timeout_seconds.max(1).to_string());
    command.arg("--output");
    command.arg(output_path);
    command.arg("--");
    command.args(&job.execution.command);
    command.current_dir(working_directory);
    Ok(command)
}

fn resolve_sandtrace_bin(config: &WorkerConfig) -> PathBuf {
    if let Some(path) = &config.sandtrace_bin {
        return path.clone();
    }

    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("sandtrace");
            if sibling.exists() {
                return sibling;
            }
        }
    }

    PathBuf::from("sandtrace")
}

fn load_ingest_run_id(result_path: &Path) -> Result<Option<String>, WorkerFailure> {
    if !result_path.exists() {
        return Ok(None);
    }

    let contents = std::fs::read_to_string(result_path)
        .map_err(|error| WorkerFailure::new("ingest_result_read_failed", error.to_string()))?;
    let payload: Value = serde_json::from_str(&contents)
        .map_err(|error| WorkerFailure::new("ingest_result_invalid", error.to_string()))?;
    Ok(payload
        .get("run_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned))
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
    use super::{
        normalize_ref_name, resolve_sandtrace_bin, resolve_working_directory, ExecutionMode,
        WorkerConfig,
    };
    use std::path::PathBuf;

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

    #[test]
    fn resolve_sandtrace_bin_uses_explicit_path() {
        let config = WorkerConfig {
            runtime_url: "http://127.0.0.1:8081".into(),
            worker_id: "wrk_test".into(),
            pool: "shared-linux".into(),
            worker_token: None,
            execution_mode: ExecutionMode::StubUploaded,
            stub_delay_secs: 1,
            heartbeat_secs: 1,
            sandtrace_bin: Some(PathBuf::from("/opt/sandtrace/bin/sandtrace")),
            ingest_url: None,
            ingest_api_key: None,
            git_bin: "git".into(),
            workspace_root: None,
        };

        assert_eq!(
            resolve_sandtrace_bin(&config),
            PathBuf::from("/opt/sandtrace/bin/sandtrace")
        );
    }
}
