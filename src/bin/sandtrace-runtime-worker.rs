use anyhow::Context;
use chrono::Utc;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::{sleep, Duration, MissedTickBehavior};
use ulid::Ulid;

#[derive(Debug, Deserialize)]
struct LeaseResponse {
    lease_id: String,
    job: LeaseJob,
    lease_expires_at: String,
}

#[derive(Debug, Deserialize)]
struct LeaseJob {
    job_id: String,
    org_slug: String,
    project_slug: String,
    source: SourcePayload,
    execution: ExecutionPayload,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
enum StubMode {
    Uploaded,
    Failed,
}

impl StubMode {
    fn from_env() -> Self {
        match std::env::var("SANDTRACE_RUNTIME_STUB_MODE")
            .unwrap_or_else(|_| "uploaded".to_string())
            .to_lowercase()
            .as_str()
        {
            "failed" => Self::Failed,
            _ => Self::Uploaded,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let runtime_url = std::env::var("SANDTRACE_RUNTIME_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8081".to_string())
        .trim_end_matches('/')
        .to_string();
    let worker_id = std::env::var("SANDTRACE_RUNTIME_WORKER_ID")
        .unwrap_or_else(|_| format!("wrk_{}", Ulid::new().to_string().to_lowercase()));
    let pool = std::env::var("SANDTRACE_RUNTIME_WORKER_POOL")
        .unwrap_or_else(|_| "shared-linux".to_string());
    let worker_token = std::env::var("SANDTRACE_RUNTIME_WORKER_TOKEN").ok();
    let stub_mode = StubMode::from_env();
    let stub_delay_secs = std::env::var("SANDTRACE_RUNTIME_STUB_DELAY_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5);
    let heartbeat_secs = std::env::var("SANDTRACE_RUNTIME_HEARTBEAT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build runtime worker http client")?;

    let lease = claim_lease(&client, &runtime_url, &worker_id, &pool, worker_token.as_deref())
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

    let mut heartbeat = tokio::time::interval(Duration::from_secs(heartbeat_secs));
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    heartbeat.tick().await;

    let mut remaining = stub_delay_secs;
    while remaining > 0 {
        let step = remaining.min(heartbeat_secs);
        sleep(Duration::from_secs(step)).await;
        remaining -= step;

        if remaining > 0 {
            send_heartbeat(&client, &runtime_url, &lease.lease_id, worker_token.as_deref()).await?;
            eprintln!(
                "sandtrace-runtime-worker: heartbeat {} expires_at={}",
                lease.lease_id, lease.lease_expires_at
            );
        }
    }

    match stub_mode {
        StubMode::Uploaded => {
            let ingest_run_id = std::env::var("SANDTRACE_RUNTIME_STUB_INGEST_RUN_ID")
                .unwrap_or_else(|_| format!("run_stub_{}", Ulid::new().to_string().to_lowercase()));
            complete_lease(
                &client,
                &runtime_url,
                &lease.lease_id,
                &ingest_run_id,
                worker_token.as_deref(),
            )
            .await?;
            eprintln!(
                "sandtrace-runtime-worker: marked {} uploaded with ingest_run_id={}",
                lease.job.job_id, ingest_run_id
            );
        }
        StubMode::Failed => {
            fail_lease(
                &client,
                &runtime_url,
                &lease.lease_id,
                worker_token.as_deref(),
            )
            .await?;
            eprintln!(
                "sandtrace-runtime-worker: marked {} failed",
                lease.job.job_id
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

    let response = builder.send().await.context("failed to claim runtime lease")?;
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
    worker_token: Option<&str>,
) -> anyhow::Result<()> {
    let request = FailLeaseRequest {
        result: FailLeaseResult {
            status: "failed",
            reason: "stub_worker_failure".to_string(),
            message: "runtime worker stub marked the job failed".to_string(),
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
