use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use deadpool_postgres::{
    Manager, ManagerConfig as PgManagerConfig, Pool, RecyclingMethod, Runtime,
};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio_postgres::{NoTls, Row, Transaction};
use ulid::Ulid;

#[derive(Clone)]
pub struct RuntimeState {
    pool: Pool,
    admin_token: Option<String>,
    worker_token: Option<String>,
    github_status_token: Option<String>,
    github_status_context: String,
    runtime_status_target_base_url: Option<String>,
    http_client: HttpClient,
}

impl RuntimeState {
    pub async fn from_env() -> anyhow::Result<Self> {
        let database_url = std::env::var("SANDTRACE_RUNTIME_DATABASE_URL")
            .or_else(|_| std::env::var("SANDTRACE_INGEST_DATABASE_URL"))
            .map_err(|_| {
                anyhow::anyhow!(
                    "configure SANDTRACE_RUNTIME_DATABASE_URL or SANDTRACE_INGEST_DATABASE_URL"
                )
            })?;

        let config: tokio_postgres::Config = database_url.parse()?;
        let manager = Manager::from_config(
            config,
            NoTls,
            PgManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager).runtime(Runtime::Tokio1).build()?;

        let state = Self {
            pool,
            admin_token: std::env::var("SANDTRACE_RUNTIME_ADMIN_TOKEN")
                .ok()
                .or_else(|| std::env::var("SANDTRACE_INGEST_ADMIN_TOKEN").ok()),
            worker_token: std::env::var("SANDTRACE_RUNTIME_WORKER_TOKEN").ok(),
            github_status_token: std::env::var("SANDTRACE_RUNTIME_GITHUB_STATUS_TOKEN")
                .ok()
                .or_else(|| std::env::var("SANDTRACE_RUNTIME_GITHUB_TOKEN").ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
            github_status_context: std::env::var("SANDTRACE_RUNTIME_GITHUB_STATUS_CONTEXT")
                .unwrap_or_else(|_| "sandtrace/hosted-runtime".to_string()),
            runtime_status_target_base_url: std::env::var(
                "SANDTRACE_RUNTIME_STATUS_TARGET_BASE_URL",
            )
            .ok()
            .or_else(|| std::env::var("SANDTRACE_CLOUD_APP_URL").ok())
            .map(|value| value.trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty()),
            http_client: HttpClient::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?,
        };
        state.initialize_schema().await?;
        Ok(state)
    }

    async fn initialize_schema(&self) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client
            .batch_execute(
                r#"
                create table if not exists runtime_jobs (
                    id bigserial primary key,
                    job_ulid text not null unique,
                    org_slug text not null,
                    project_slug text not null,
                    source_kind text not null,
                    repo_url text not null,
                    repo_owner text,
                    repo_name text,
                    git_ref text,
                    git_commit text not null,
                    pull_request_number integer,
                    trigger_kind text not null,
                    trigger_actor text,
                    working_directory text not null,
                    command_json jsonb not null,
                    timeout_seconds integer not null,
                    allow_network boolean not null default false,
                    allow_exec boolean not null default false,
                    status text not null,
                    retry_of_job_ulid text,
                    ingest_run_id text,
                    failure_reason text,
                    failure_message text,
                    created_at timestamptz not null default now(),
                    started_at timestamptz,
                    finished_at timestamptz
                );

                create index if not exists runtime_jobs_org_project_created_idx
                    on runtime_jobs (org_slug, project_slug, created_at desc);
                create index if not exists runtime_jobs_org_commit_idx
                    on runtime_jobs (org_slug, git_commit);
                create index if not exists runtime_jobs_status_created_idx
                    on runtime_jobs (status, created_at);

                create table if not exists runtime_job_events (
                    id bigserial primary key,
                    job_ulid text not null references runtime_jobs(job_ulid) on delete cascade,
                    event_type text not null,
                    actor_kind text not null,
                    actor_id text,
                    payload_json jsonb not null default '{}'::jsonb,
                    created_at timestamptz not null default now()
                );

                create index if not exists runtime_job_events_job_created_idx
                    on runtime_job_events (job_ulid, created_at desc);

                create table if not exists runtime_worker_leases (
                    id bigserial primary key,
                    lease_ulid text not null unique,
                    job_ulid text not null references runtime_jobs(job_ulid) on delete cascade,
                    worker_id text not null,
                    pool text not null,
                    status text not null,
                    leased_at timestamptz not null default now(),
                    expires_at timestamptz not null,
                    completed_at timestamptz
                );

                create index if not exists runtime_worker_leases_job_status_idx
                    on runtime_worker_leases (job_ulid, status);
                create index if not exists runtime_worker_leases_worker_status_idx
                    on runtime_worker_leases (worker_id, status);
                "#,
            )
            .await?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
struct ExecutionPayload {
    working_directory: String,
    command: Vec<String>,
    timeout_seconds: i32,
    #[serde(default)]
    allow_network: bool,
    #[serde(default)]
    allow_exec: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct TriggerPayload {
    kind: String,
    #[serde(default)]
    actor: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CreateRuntimeJobRequest {
    org_slug: String,
    project_slug: String,
    source: SourcePayload,
    execution: ExecutionPayload,
    trigger: TriggerPayload,
}

#[derive(Debug, Serialize)]
struct CreateRuntimeJobResponse {
    job_id: String,
    status: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct RuntimeJobResponse {
    job_id: String,
    org_slug: String,
    project_slug: String,
    source_kind: String,
    repo_url: String,
    repo_owner: Option<String>,
    repo_name: Option<String>,
    git_ref: Option<String>,
    git_commit: String,
    pull_request_number: Option<i32>,
    trigger_kind: String,
    trigger_actor: Option<String>,
    working_directory: String,
    command: Vec<String>,
    timeout_seconds: i32,
    allow_network: bool,
    allow_exec: bool,
    status: String,
    retry_of_job_id: Option<String>,
    ingest_run_id: Option<String>,
    failure_reason: Option<String>,
    failure_message: Option<String>,
    created_at: String,
    started_at: Option<String>,
    finished_at: Option<String>,
}

#[derive(Debug, Clone)]
struct GitHubStatusJob {
    job_id: String,
    project_slug: String,
    repo_url: String,
    repo_owner: Option<String>,
    repo_name: Option<String>,
    git_commit: String,
}

#[derive(Debug, Clone, Copy)]
enum GitHubStatusState {
    Pending,
    Success,
    Failure,
    Error,
}

impl GitHubStatusState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Serialize)]
struct RuntimeJobEventResponse {
    event_type: String,
    actor_kind: String,
    actor_id: Option<String>,
    payload: Value,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ListRuntimeJobsQuery {
    project_slug: Option<String>,
    status: Option<String>,
    trigger_kind: Option<String>,
    git_commit: Option<String>,
    limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct LeaseRequest {
    worker_id: String,
    pool: String,
    #[serde(default)]
    capabilities: Value,
}

#[derive(Debug, Serialize)]
struct LeaseResponse {
    lease_id: String,
    job: LeaseJobResponse,
    lease_expires_at: String,
}

#[derive(Debug, Serialize)]
struct LeaseJobResponse {
    job_id: String,
    org_slug: String,
    project_slug: String,
    source: SourcePayload,
    execution: ExecutionPayload,
}

#[derive(Debug, Deserialize)]
struct CompleteLeaseRequest {
    result: CompleteLeaseResult,
}

#[derive(Debug, Deserialize)]
struct CompleteLeaseResult {
    status: String,
    ingest_run_id: String,
    #[serde(default)]
    uploaded_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FailLeaseRequest {
    result: FailLeaseResult,
}

#[derive(Debug, Deserialize)]
struct FailLeaseResult {
    status: String,
    reason: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    ok: bool,
}

pub async fn serve(state: RuntimeState, bind: SocketAddr) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route(
            "/v1/runtime/jobs",
            post(create_runtime_job).get(list_runtime_jobs),
        )
        .route("/v1/runtime/jobs/{job_id}", get(get_runtime_job))
        .route(
            "/v1/runtime/jobs/{job_id}/events",
            get(list_runtime_job_events),
        )
        .route("/v1/runtime/jobs/{job_id}/cancel", post(cancel_runtime_job))
        .route("/v1/runtime/leases", post(claim_runtime_lease))
        .route(
            "/v1/runtime/leases/{lease_id}/heartbeat",
            post(heartbeat_runtime_lease),
        )
        .route(
            "/v1/runtime/leases/{lease_id}/complete",
            post(complete_runtime_lease),
        )
        .route(
            "/v1/runtime/leases/{lease_id}/fail",
            post(fail_runtime_lease),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> impl IntoResponse {
    Json(json!({ "ok": true }))
}

async fn create_runtime_job(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Json(payload): Json<CreateRuntimeJobRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&state, &headers)?;
    validate_job_request(&payload)?;

    let job_id = prefixed_ulid("rtj");
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let command_json =
        serde_json::to_value(&payload.execution.command).map_err(ApiError::internal)?;
    let created_at = Utc::now();

    client
        .execute(
            r#"
            insert into runtime_jobs (
                job_ulid, org_slug, project_slug, source_kind, repo_url, repo_owner, repo_name,
                git_ref, git_commit, pull_request_number, trigger_kind, trigger_actor,
                working_directory, command_json, timeout_seconds, allow_network, allow_exec, status, created_at
            ) values (
                $1, $2, $3, $4, $5, $6, $7,
                $8, $9, $10, $11, $12,
                $13, $14, $15, $16, $17, 'queued', $18
            )
            "#,
            &[
                &job_id,
                &payload.org_slug,
                &payload.project_slug,
                &payload.source.kind,
                &payload.source.repo_url,
                &payload.source.owner,
                &payload.source.repo,
                &payload.source.r#ref,
                &payload.source.git_commit,
                &payload.source.pull_request_number,
                &payload.trigger.kind,
                &payload.trigger.actor,
                &payload.execution.working_directory,
                &command_json,
                &payload.execution.timeout_seconds,
                &payload.execution.allow_network,
                &payload.execution.allow_exec,
                &created_at,
            ],
        )
        .await
        .map_err(ApiError::internal)?;

    insert_job_event(
        &client,
        &job_id,
        "job_created",
        "admin",
        extract_bearer_token(&headers).as_deref(),
        json!({
            "trigger_kind": payload.trigger.kind,
            "repo_url": payload.source.repo_url,
            "git_commit": payload.source.git_commit
        }),
    )
    .await
    .map_err(ApiError::internal)?;

    publish_github_status(
        &state,
        GitHubStatusJob {
            job_id: job_id.clone(),
            project_slug: payload.project_slug.clone(),
            repo_url: payload.source.repo_url.clone(),
            repo_owner: payload.source.owner.clone(),
            repo_name: payload.source.repo.clone(),
            git_commit: payload.source.git_commit.clone(),
        },
        GitHubStatusState::Pending,
        "Hosted runtime job queued",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(CreateRuntimeJobResponse {
            job_id,
            status: "queued".to_string(),
            created_at: created_at.to_rfc3339(),
        }),
    ))
}

async fn list_runtime_jobs(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Query(query): Query<ListRuntimeJobsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&state, &headers)?;
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);

    let rows = client
        .query(
            r#"
            select *
            from runtime_jobs
            where ($1::text is null or project_slug = $1)
              and ($2::text is null or status = $2)
              and ($3::text is null or trigger_kind = $3)
              and ($4::text is null or git_commit = $4)
            order by created_at desc
            limit $5
            "#,
            &[
                &query.project_slug,
                &query.status,
                &query.trigger_kind,
                &query.git_commit,
                &limit,
            ],
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(
        rows.into_iter()
            .map(runtime_job_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::internal)?,
    ))
}

async fn get_runtime_job(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&state, &headers)?;
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let row = client
        .query_opt("select * from runtime_jobs where job_ulid = $1", &[&job_id])
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("runtime job not found"))?;

    Ok(Json(runtime_job_from_row(row).map_err(ApiError::internal)?))
}

async fn list_runtime_job_events(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&state, &headers)?;
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let rows = client
        .query(
            r#"
            select event_type, actor_kind, actor_id, payload_json, created_at
            from runtime_job_events
            where job_ulid = $1
            order by created_at desc
            "#,
            &[&job_id],
        )
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(
        rows.into_iter()
            .map(runtime_job_event_from_row)
            .collect::<Result<Vec<_>, _>>()
            .map_err(ApiError::internal)?,
    ))
}

async fn cancel_runtime_job(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_admin(&state, &headers)?;
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let updated = client
        .execute(
            r#"
            update runtime_jobs
            set status = 'canceled', finished_at = now(), failure_reason = coalesce(failure_reason, 'canceled')
            where job_ulid = $1 and status in ('queued', 'running')
            "#,
            &[&job_id],
        )
        .await
        .map_err(ApiError::internal)?;
    if updated == 0 {
        return Err(ApiError::bad_request("job is not cancelable"));
    }
    insert_job_event(
        &client,
        &job_id,
        "job_canceled",
        "admin",
        extract_bearer_token(&headers).as_deref(),
        json!({}),
    )
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(StatusResponse { ok: true }))
}

async fn claim_runtime_lease(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Json(payload): Json<LeaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_worker(&state, &headers)?;
    if payload.worker_id.trim().is_empty() || payload.pool.trim().is_empty() {
        return Err(ApiError::bad_request("worker_id and pool are required"));
    }

    let mut client = state.pool.get().await.map_err(ApiError::internal)?;
    reap_expired_leases(&mut client)
        .await
        .map_err(ApiError::internal)?;
    let tx = client.transaction().await.map_err(ApiError::internal)?;
    let job_row = tx
        .query_opt(
            r#"
            select *
            from runtime_jobs
            where status = 'queued'
            order by created_at asc
            for update skip locked
            limit 1
            "#,
            &[],
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("no queued runtime jobs available"))?;

    let job_id: String = job_row.get("job_ulid");
    let lease_id = prefixed_ulid("rtl");
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    tx.execute(
        r#"
        insert into runtime_worker_leases (
            lease_ulid, job_ulid, worker_id, pool, status, expires_at
        ) values ($1, $2, $3, $4, 'active', $5)
        "#,
        &[
            &lease_id,
            &job_id,
            &payload.worker_id,
            &payload.pool,
            &expires_at,
        ],
    )
    .await
    .map_err(ApiError::internal)?;

    tx.execute(
        r#"
        update runtime_jobs
        set status = 'running', started_at = coalesce(started_at, now())
        where job_ulid = $1
        "#,
        &[&job_id],
    )
    .await
    .map_err(ApiError::internal)?;

    insert_job_event_tx(
        &tx,
        &job_id,
        "lease_acquired",
        "worker",
        Some(payload.worker_id.as_str()),
        json!({
            "lease_id": lease_id,
            "pool": payload.pool,
            "capabilities": payload.capabilities
        }),
    )
    .await
    .map_err(ApiError::internal)?;

    tx.commit().await.map_err(ApiError::internal)?;

    let lease_job = lease_job_from_row(job_row).map_err(ApiError::internal)?;
    publish_github_status(
        &state,
        GitHubStatusJob {
            job_id: lease_job.job_id.clone(),
            project_slug: lease_job.project_slug.clone(),
            repo_url: lease_job.source.repo_url.clone(),
            repo_owner: lease_job.source.owner.clone(),
            repo_name: lease_job.source.repo.clone(),
            git_commit: lease_job.source.git_commit.clone(),
        },
        GitHubStatusState::Pending,
        "Hosted runtime analysis running",
    )
    .await;

    Ok(Json(LeaseResponse {
        lease_id,
        job: lease_job,
        lease_expires_at: expires_at.to_rfc3339(),
    }))
}

async fn heartbeat_runtime_lease(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    require_worker(&state, &headers)?;
    let client = state.pool.get().await.map_err(ApiError::internal)?;
    let expires_at = Utc::now() + chrono::Duration::minutes(5);
    let updated = client
        .query_opt(
            r#"
            update runtime_worker_leases
            set expires_at = $2
            where lease_ulid = $1 and status = 'active'
            returning job_ulid
            "#,
            &[&lease_id, &expires_at],
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("active lease not found"))?;
    let job_id: String = updated.get("job_ulid");
    insert_job_event(
        &client,
        &job_id,
        "lease_heartbeat",
        "worker",
        extract_bearer_token(&headers).as_deref(),
        json!({
            "lease_id": lease_id,
            "expires_at": expires_at
        }),
    )
    .await
    .map_err(ApiError::internal)?;
    Ok(Json(
        json!({ "ok": true, "lease_expires_at": expires_at.to_rfc3339() }),
    ))
}

async fn complete_runtime_lease(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Json(payload): Json<CompleteLeaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_worker(&state, &headers)?;
    if payload.result.status != "uploaded" {
        return Err(ApiError::bad_request("completion status must be uploaded"));
    }

    let mut client = state.pool.get().await.map_err(ApiError::internal)?;
    let tx = client.transaction().await.map_err(ApiError::internal)?;
    let lease_row = tx
        .query_opt(
            r#"
            update runtime_worker_leases
            set status = 'completed', completed_at = now()
            where lease_ulid = $1 and status = 'active'
            returning job_ulid
            "#,
            &[&lease_id],
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("active lease not found"))?;
    let job_id: String = lease_row.get("job_ulid");
    tx.execute(
        r#"
        update runtime_jobs
        set status = 'uploaded',
            ingest_run_id = $2,
            finished_at = now()
        where job_ulid = $1
        "#,
        &[&job_id, &payload.result.ingest_run_id],
    )
    .await
    .map_err(ApiError::internal)?;

    insert_job_event_tx(
        &tx,
        &job_id,
        "job_uploaded",
        "worker",
        extract_bearer_token(&headers).as_deref(),
        json!({
            "lease_id": lease_id,
            "ingest_run_id": payload.result.ingest_run_id
        }),
    )
    .await
    .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;

    let row = client
        .query_one(
            "select job_ulid, project_slug, repo_url, repo_owner, repo_name, git_commit from runtime_jobs where job_ulid = $1",
            &[&job_id],
        )
        .await
        .map_err(ApiError::internal)?;
    publish_github_status(
        &state,
        github_status_job_from_row(&row),
        GitHubStatusState::Success,
        "Hosted runtime analysis uploaded",
    )
    .await;
    Ok(Json(StatusResponse { ok: true }))
}

async fn fail_runtime_lease(
    State(state): State<RuntimeState>,
    headers: HeaderMap,
    Path(lease_id): Path<String>,
    Json(payload): Json<FailLeaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    require_worker(&state, &headers)?;
    if payload.result.status != "failed" {
        return Err(ApiError::bad_request("failure status must be failed"));
    }

    let mut client = state.pool.get().await.map_err(ApiError::internal)?;
    let tx = client.transaction().await.map_err(ApiError::internal)?;
    let lease_row = tx
        .query_opt(
            r#"
            update runtime_worker_leases
            set status = 'failed', completed_at = now()
            where lease_ulid = $1 and status = 'active'
            returning job_ulid
            "#,
            &[&lease_id],
        )
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("active lease not found"))?;
    let job_id: String = lease_row.get("job_ulid");

    tx.execute(
        r#"
        update runtime_jobs
        set status = 'failed',
            failure_reason = $2,
            failure_message = $3,
            finished_at = now()
        where job_ulid = $1
        "#,
        &[&job_id, &payload.result.reason, &payload.result.message],
    )
    .await
    .map_err(ApiError::internal)?;

    insert_job_event_tx(
        &tx,
        &job_id,
        "job_failed",
        "worker",
        extract_bearer_token(&headers).as_deref(),
        json!({
            "lease_id": lease_id,
            "reason": payload.result.reason,
            "message": payload.result.message
        }),
    )
    .await
    .map_err(ApiError::internal)?;
    tx.commit().await.map_err(ApiError::internal)?;

    let row = client
        .query_one(
            "select job_ulid, project_slug, repo_url, repo_owner, repo_name, git_commit from runtime_jobs where job_ulid = $1",
            &[&job_id],
        )
        .await
        .map_err(ApiError::internal)?;
    let description =
        summarize_failure_description(&payload.result.reason, &payload.result.message);
    publish_github_status(
        &state,
        github_status_job_from_row(&row),
        GitHubStatusState::Failure,
        &description,
    )
    .await;
    Ok(Json(StatusResponse { ok: true }))
}

fn require_admin(state: &RuntimeState, headers: &HeaderMap) -> Result<(), ApiError> {
    match &state.admin_token {
        Some(token) if extract_bearer_token(headers).as_deref() == Some(token.as_str()) => Ok(()),
        Some(_) => Err(ApiError::unauthorized("invalid admin token")),
        None => Ok(()),
    }
}

fn require_worker(state: &RuntimeState, headers: &HeaderMap) -> Result<(), ApiError> {
    match &state.worker_token {
        Some(token) if extract_bearer_token(headers).as_deref() == Some(token.as_str()) => Ok(()),
        Some(_) => Err(ApiError::unauthorized("invalid worker token")),
        None => require_admin(state, headers),
    }
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

fn validate_job_request(payload: &CreateRuntimeJobRequest) -> Result<(), ApiError> {
    if payload.org_slug.trim().is_empty() {
        return Err(ApiError::bad_request("org_slug is required"));
    }
    if payload.project_slug.trim().is_empty() {
        return Err(ApiError::bad_request("project_slug is required"));
    }
    if payload.source.repo_url.trim().is_empty() || payload.source.git_commit.trim().is_empty() {
        return Err(ApiError::bad_request(
            "repo_url and git_commit are required",
        ));
    }
    if payload.execution.command.is_empty()
        || payload
            .execution
            .command
            .iter()
            .any(|part| part.trim().is_empty())
    {
        return Err(ApiError::bad_request("command must be non-empty"));
    }
    if payload.execution.working_directory.trim().is_empty() {
        return Err(ApiError::bad_request("working_directory is required"));
    }
    if payload.execution.timeout_seconds <= 0 || payload.execution.timeout_seconds > 3600 {
        return Err(ApiError::bad_request(
            "timeout_seconds must be between 1 and 3600",
        ));
    }
    if payload.trigger.kind.trim().is_empty() {
        return Err(ApiError::bad_request("trigger.kind is required"));
    }
    Ok(())
}

async fn insert_job_event(
    client: &deadpool_postgres::Client,
    job_id: &str,
    event_type: &str,
    actor_kind: &str,
    actor_id: Option<&str>,
    payload: Value,
) -> anyhow::Result<()> {
    client
        .execute(
            r#"
            insert into runtime_job_events (job_ulid, event_type, actor_kind, actor_id, payload_json)
            values ($1, $2, $3, $4, $5)
            "#,
            &[&job_id, &event_type, &actor_kind, &actor_id, &payload],
        )
        .await?;
    Ok(())
}

async fn insert_job_event_tx(
    tx: &Transaction<'_>,
    job_id: &str,
    event_type: &str,
    actor_kind: &str,
    actor_id: Option<&str>,
    payload: Value,
) -> anyhow::Result<()> {
    tx.execute(
        r#"
        insert into runtime_job_events (job_ulid, event_type, actor_kind, actor_id, payload_json)
        values ($1, $2, $3, $4, $5)
        "#,
        &[&job_id, &event_type, &actor_kind, &actor_id, &payload],
    )
    .await?;
    Ok(())
}

fn runtime_job_from_row(row: Row) -> anyhow::Result<RuntimeJobResponse> {
    let command: Vec<String> = serde_json::from_value(row.get::<_, Value>("command_json"))?;
    Ok(RuntimeJobResponse {
        job_id: row.get("job_ulid"),
        org_slug: row.get("org_slug"),
        project_slug: row.get("project_slug"),
        source_kind: row.get("source_kind"),
        repo_url: row.get("repo_url"),
        repo_owner: row.get("repo_owner"),
        repo_name: row.get("repo_name"),
        git_ref: row.get("git_ref"),
        git_commit: row.get("git_commit"),
        pull_request_number: row.get("pull_request_number"),
        trigger_kind: row.get("trigger_kind"),
        trigger_actor: row.get("trigger_actor"),
        working_directory: row.get("working_directory"),
        command,
        timeout_seconds: row.get("timeout_seconds"),
        allow_network: row.get("allow_network"),
        allow_exec: row.get("allow_exec"),
        status: row.get("status"),
        retry_of_job_id: row.get("retry_of_job_ulid"),
        ingest_run_id: row.get("ingest_run_id"),
        failure_reason: row.get("failure_reason"),
        failure_message: row.get("failure_message"),
        created_at: row.get::<_, DateTime<Utc>>("created_at").to_rfc3339(),
        started_at: row
            .get::<_, Option<DateTime<Utc>>>("started_at")
            .map(|value| value.to_rfc3339()),
        finished_at: row
            .get::<_, Option<DateTime<Utc>>>("finished_at")
            .map(|value| value.to_rfc3339()),
    })
}

fn lease_job_from_row(row: Row) -> anyhow::Result<LeaseJobResponse> {
    let command: Vec<String> = serde_json::from_value(row.get::<_, Value>("command_json"))?;
    Ok(LeaseJobResponse {
        job_id: row.get("job_ulid"),
        org_slug: row.get("org_slug"),
        project_slug: row.get("project_slug"),
        source: SourcePayload {
            kind: row.get("source_kind"),
            repo_url: row.get("repo_url"),
            owner: row.get("repo_owner"),
            repo: row.get("repo_name"),
            r#ref: row.get("git_ref"),
            git_commit: row.get("git_commit"),
            pull_request_number: row.get("pull_request_number"),
        },
        execution: ExecutionPayload {
            working_directory: row.get("working_directory"),
            command,
            timeout_seconds: row.get("timeout_seconds"),
            allow_network: row.get("allow_network"),
            allow_exec: row.get("allow_exec"),
        },
    })
}

fn runtime_job_event_from_row(row: Row) -> anyhow::Result<RuntimeJobEventResponse> {
    Ok(RuntimeJobEventResponse {
        event_type: row.get("event_type"),
        actor_kind: row.get("actor_kind"),
        actor_id: row.get("actor_id"),
        payload: row.get("payload_json"),
        created_at: row.get::<_, DateTime<Utc>>("created_at").to_rfc3339(),
    })
}

fn github_status_job_from_row(row: &Row) -> GitHubStatusJob {
    GitHubStatusJob {
        job_id: row.get("job_ulid"),
        project_slug: row.get("project_slug"),
        repo_url: row.get("repo_url"),
        repo_owner: row.get("repo_owner"),
        repo_name: row.get("repo_name"),
        git_commit: row.get("git_commit"),
    }
}

async fn publish_github_status(
    state: &RuntimeState,
    job: GitHubStatusJob,
    status: GitHubStatusState,
    description: &str,
) {
    let Some(token) = state.github_status_token.as_deref() else {
        return;
    };

    let Some((owner, repo)) = github_repo_identity(&job) else {
        eprintln!(
            "sandtrace-runtime-orchestrator: unable to infer GitHub repo for {}",
            job.job_id
        );
        return;
    };

    let description = truncate_github_description(description);
    let mut payload = json!({
        "state": status.as_str(),
        "context": state.github_status_context,
        "description": description,
    });
    if let Some(target_url) = runtime_job_target_url(state, &job) {
        payload["target_url"] = Value::String(target_url);
    }

    let response = state
        .http_client
        .post(format!(
            "https://api.github.com/repos/{owner}/{repo}/statuses/{}",
            job.git_commit
        ))
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "sandtrace-runtime-orchestrator")
        .json(&payload)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => {
            let status_code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            eprintln!(
                "sandtrace-runtime-orchestrator: github status publish failed for {}: {} {}",
                job.job_id, status_code, body
            );
        }
        Err(error) => {
            eprintln!(
                "sandtrace-runtime-orchestrator: github status publish failed for {}: {}",
                job.job_id, error
            );
        }
    }
}

fn github_repo_identity(job: &GitHubStatusJob) -> Option<(String, String)> {
    if let (Some(owner), Some(repo)) = (&job.repo_owner, &job.repo_name) {
        let owner = owner.trim();
        let repo = repo.trim();
        if !owner.is_empty() && !repo.is_empty() {
            return Some((owner.to_string(), repo.to_string()));
        }
    }

    infer_github_repo_from_url(&job.repo_url)
}

fn infer_github_repo_from_url(repo_url: &str) -> Option<(String, String)> {
    let trimmed = repo_url.trim().trim_end_matches('/');
    let path = if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("http://github.com/") {
        rest
    } else if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        rest
    } else {
        return None;
    };

    let mut parts = path.split('/');
    let owner = parts.next()?.trim();
    let repo = parts.next()?.trim().trim_end_matches(".git");
    if owner.is_empty() || repo.is_empty() {
        return None;
    }

    Some((owner.to_string(), repo.to_string()))
}

fn runtime_job_target_url(state: &RuntimeState, job: &GitHubStatusJob) -> Option<String> {
    let base = state.runtime_status_target_base_url.as_deref()?;
    Some(format!(
        "{base}/cloud/projects/{}/runtime/{}",
        job.project_slug, job.job_id
    ))
}

fn truncate_github_description(description: &str) -> String {
    const MAX: usize = 140;
    let trimmed = description.trim();
    if trimmed.chars().count() <= MAX {
        return trimmed.to_string();
    }

    trimmed.chars().take(MAX - 1).collect::<String>() + "…"
}

fn summarize_failure_description(reason: &str, message: &str) -> String {
    let reason = reason.trim();
    let first_line = message
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("Hosted runtime analysis failed");
    if reason.is_empty() {
        truncate_github_description(first_line)
    } else {
        truncate_github_description(&format!("{reason}: {first_line}"))
    }
}

async fn reap_expired_leases(client: &mut deadpool_postgres::Client) -> anyhow::Result<()> {
    let tx = client.transaction().await?;
    let rows = tx
        .query(
            r#"
            update runtime_worker_leases
            set status = 'expired', completed_at = now()
            where status = 'active' and expires_at < now()
            returning job_ulid, lease_ulid
            "#,
            &[],
        )
        .await?;

    for row in rows {
        let job_id: String = row.get("job_ulid");
        let lease_id: String = row.get("lease_ulid");
        tx.execute(
            r#"
            update runtime_jobs
            set status = case
                when status = 'running' then 'queued'
                else status
            end
            where job_ulid = $1
            "#,
            &[&job_id],
        )
        .await?;
        insert_job_event_tx(
            &tx,
            &job_id,
            "lease_expired",
            "system",
            None,
            json!({
                "lease_id": lease_id
            }),
        )
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

fn prefixed_ulid(prefix: &str) -> String {
    format!("{}_{}", prefix, Ulid::new().to_string().to_lowercase())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "error": self.message
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_job_request_requires_non_empty_command() {
        let payload = CreateRuntimeJobRequest {
            org_slug: "sandtrace".to_string(),
            project_slug: "web".to_string(),
            source: SourcePayload {
                kind: "github".to_string(),
                repo_url: "https://github.com/cc-consulting-nv/web.git".to_string(),
                owner: Some("cc-consulting-nv".to_string()),
                repo: Some("web".to_string()),
                r#ref: Some("refs/heads/main".to_string()),
                git_commit: "abc123".to_string(),
                pull_request_number: Some(1),
            },
            execution: ExecutionPayload {
                working_directory: ".".to_string(),
                command: vec![],
                timeout_seconds: 300,
                allow_network: true,
                allow_exec: true,
            },
            trigger: TriggerPayload {
                kind: "pull_request".to_string(),
                actor: Some("github-app".to_string()),
            },
        };

        assert!(validate_job_request(&payload).is_err());
    }

    #[test]
    fn prefixed_ulid_is_lowercase() {
        let value = prefixed_ulid("rtj");
        assert!(value.starts_with("rtj_"));
        assert_eq!(value, value.to_lowercase());
    }

    #[test]
    fn infer_github_repo_from_url_handles_https_and_ssh() {
        assert_eq!(
            infer_github_repo_from_url("https://github.com/cc-consulting-nv/web.git"),
            Some(("cc-consulting-nv".to_string(), "web".to_string()))
        );
        assert_eq!(
            infer_github_repo_from_url("git@github.com:cc-consulting-nv/ccc-web.git"),
            Some(("cc-consulting-nv".to_string(), "ccc-web".to_string()))
        );
        assert_eq!(
            infer_github_repo_from_url("https://gitlab.com/acme/demo"),
            None
        );
    }

    #[test]
    fn summarize_failure_description_uses_reason_and_first_line() {
        assert_eq!(
            summarize_failure_description(
                "checkout_failed",
                "git clone failed with status 128\nextra detail"
            ),
            "checkout_failed: git clone failed with status 128"
        );
    }
}
