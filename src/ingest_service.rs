use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use chrono::Utc;
use deadpool_postgres::{
    Manager, ManagerConfig as PgManagerConfig, Pool, RecyclingMethod, Runtime,
};
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::ObjectStore;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio_postgres::types::ToSql;
use tokio_postgres::{NoTls, Row};
use tracing::{error, info, instrument, warn};
use ulid::Ulid;

#[derive(Clone)]
pub struct IngestState {
    principals: Arc<HashMap<String, ApiPrincipal>>,
    storage_dir: Arc<PathBuf>,
    payload_store: Arc<PayloadStore>,
    metadata_store: Option<MetadataStore>,
    admin_token: Option<String>,
    admin_subject: String,
    osv_api_url: Arc<String>,
    osv_cache_ttl_hours: i64,
}

impl IngestState {
    pub async fn from_env() -> anyhow::Result<Self> {
        let principals = load_principals_from_env()?;
        let storage_dir = std::env::var("SANDTRACE_INGEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./var/ingest"));
        let payload_store = PayloadStore::from_env(storage_dir.clone())?;
        let metadata_store = MetadataStore::from_env().await?;
        let admin_token = std::env::var("SANDTRACE_INGEST_ADMIN_TOKEN").ok();
        let admin_subject = std::env::var("SANDTRACE_INGEST_ADMIN_SUBJECT")
            .unwrap_or_else(|_| "admin-token".to_string());
        let osv_api_url = std::env::var("SANDTRACE_OSV_API_URL")
            .unwrap_or_else(|_| "https://api.osv.dev".to_string());
        let osv_cache_ttl_hours = std::env::var("SANDTRACE_OSV_CACHE_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(24);

        if principals.is_empty() && metadata_store.is_none() {
            anyhow::bail!(
                "configure api keys via SANDTRACE_INGEST_KEYS_FILE, SANDTRACE_INGEST_API_KEYS, SANDTRACE_API_KEY, or the ingest database"
            );
        }

        if let Some(store) = &metadata_store {
            store.bootstrap_principals(principals.values()).await?;
        }

        Ok(Self {
            principals: Arc::new(principals),
            storage_dir: Arc::new(storage_dir.clone()),
            payload_store: Arc::new(payload_store),
            metadata_store,
            admin_token,
            admin_subject,
            osv_api_url: Arc::new(osv_api_url),
            osv_cache_ttl_hours,
        })
    }
}

enum PayloadStore {
    Filesystem {
        root: PathBuf,
    },
    ObjectStorage {
        bucket: String,
        prefix: String,
        store: Arc<dyn ObjectStore>,
    },
}

#[derive(Debug, Clone)]
struct StorageScope {
    org_key: String,
    project_key: Option<String>,
}

impl PayloadStore {
    fn from_env(storage_dir: PathBuf) -> anyhow::Result<Self> {
        let Ok(bucket) = std::env::var("SANDTRACE_OBJECT_STORAGE_BUCKET") else {
            return Ok(Self::Filesystem { root: storage_dir });
        };
        let bucket = bucket.trim().to_string();

        let endpoint = std::env::var("SANDTRACE_OBJECT_STORAGE_ENDPOINT").map_err(|_| {
            anyhow::anyhow!(
                "SANDTRACE_OBJECT_STORAGE_ENDPOINT is required when object storage is enabled"
            )
        })?;
        let endpoint = endpoint.trim().to_string();
        let access_key_id = std::env::var("SANDTRACE_OBJECT_STORAGE_ACCESS_KEY_ID")
            .map_err(|_| anyhow::anyhow!("SANDTRACE_OBJECT_STORAGE_ACCESS_KEY_ID is required when object storage is enabled"))?;
        let access_key_id = access_key_id.trim().to_string();
        let secret_access_key = std::env::var("SANDTRACE_OBJECT_STORAGE_SECRET_ACCESS_KEY")
            .map_err(|_| anyhow::anyhow!("SANDTRACE_OBJECT_STORAGE_SECRET_ACCESS_KEY is required when object storage is enabled"))?;
        let secret_access_key = secret_access_key.trim().to_string();
        let region = std::env::var("SANDTRACE_OBJECT_STORAGE_REGION")
            .unwrap_or_else(|_| "us-east-1".to_string())
            .trim()
            .to_string();
        let prefix = std::env::var("SANDTRACE_OBJECT_STORAGE_PREFIX")
            .unwrap_or_else(|_| "sandtrace-ingest".to_string())
            .trim()
            .trim_matches('/')
            .to_string();
        let allow_http = std::env::var("SANDTRACE_OBJECT_STORAGE_ALLOW_HTTP")
            .ok()
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        let store = AmazonS3Builder::new()
            .with_bucket_name(bucket.clone())
            .with_region(region)
            .with_access_key_id(access_key_id)
            .with_secret_access_key(secret_access_key)
            .with_endpoint(endpoint)
            .with_allow_http(allow_http)
            .build()?;

        Ok(Self::ObjectStorage {
            bucket,
            prefix,
            store: Arc::new(store),
        })
    }

    async fn write_json(
        &self,
        org_key: &str,
        project_key: Option<&str>,
        kind: &str,
        record_id: &str,
        payload: &Value,
    ) -> anyhow::Result<String> {
        let body = serde_json::to_vec_pretty(payload)?;
        match self {
            Self::Filesystem { root } => {
                let dir = root.join(org_key).join(kind);
                tokio::fs::create_dir_all(&dir).await?;
                let path = dir.join(format!("{record_id}.json"));
                tokio::fs::write(&path, body).await?;
                Ok(path.to_string_lossy().into_owned())
            }
            Self::ObjectStorage {
                bucket,
                prefix,
                store,
            } => {
                let key = object_storage_key(prefix, org_key, project_key, kind, record_id);
                store
                    .put(&ObjectPath::from(key.as_str()), Bytes::from(body).into())
                    .await?;
                Ok(format!("s3://{bucket}/{key}"))
            }
        }
    }

    async fn read_json(
        &self,
        org_key: &str,
        project_key: Option<&str>,
        kind: &str,
        record_id: &str,
        payload_path: Option<&str>,
    ) -> std::io::Result<Value> {
        match self {
            Self::Filesystem { root } => {
                let path = payload_path.map(PathBuf::from).unwrap_or_else(|| {
                    root.join(org_key)
                        .join(kind)
                        .join(format!("{record_id}.json"))
                });
                read_json_file(&path).await
            }
            Self::ObjectStorage { prefix, store, .. } => {
                let key = payload_path
                    .and_then(parse_object_storage_key)
                    .unwrap_or_else(|| {
                        object_storage_key(prefix, org_key, project_key, kind, record_id)
                    });
                let response = store
                    .get(&ObjectPath::from(key.as_str()))
                    .await
                    .map_err(std::io::Error::other)?;
                let bytes = response.bytes().await.map_err(std::io::Error::other)?;
                serde_json::from_slice(&bytes).map_err(std::io::Error::other)
            }
        }
    }
}

fn object_storage_key(
    prefix: &str,
    org_key: &str,
    project_key: Option<&str>,
    kind: &str,
    record_id: &str,
) -> String {
    let trimmed = prefix.trim_matches('/');
    let mut parts = Vec::new();
    if !trimmed.is_empty() {
        parts.push(trimmed.to_string());
    }
    parts.push("orgs".to_string());
    parts.push(org_key.to_string());
    if let Some(project_key) = project_key.filter(|value| !value.is_empty()) {
        parts.push("projects".to_string());
        parts.push(project_key.to_string());
    }
    parts.push(kind.to_string());
    parts.push(format!("{record_id}.json"));
    parts.join("/")
}

fn parse_object_storage_key(value: &str) -> Option<String> {
    let remainder = value.strip_prefix("s3://")?;
    let (_, key) = remainder.split_once('/')?;
    Some(key.to_string())
}

fn load_principals_from_env() -> anyhow::Result<HashMap<String, ApiPrincipal>> {
    if let Ok(path) = std::env::var("SANDTRACE_INGEST_KEYS_FILE") {
        let content = std::fs::read_to_string(&path)?;
        let principals: Vec<ApiPrincipal> = serde_json::from_str(&content)?;
        return Ok(principals
            .into_iter()
            .map(|principal| (principal.api_key.clone(), principal))
            .collect());
    }

    let org_slug = std::env::var("SANDTRACE_INGEST_ORG").unwrap_or_else(|_| "default".to_string());
    let project_slug = std::env::var("SANDTRACE_INGEST_PROJECT").ok();
    let actor = std::env::var("SANDTRACE_INGEST_ACTOR").ok();

    let keys = std::env::var("SANDTRACE_INGEST_API_KEYS")
        .ok()
        .or_else(|| std::env::var("SANDTRACE_API_KEY").ok())
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .map(|token| ApiPrincipal {
                    api_key: token.to_string(),
                    org_slug: org_slug.clone(),
                    project_slug: project_slug.clone(),
                    actor: actor.clone(),
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Ok(keys
        .into_iter()
        .map(|principal| (principal.api_key.clone(), principal))
        .collect())
}

#[derive(Debug, Clone, Deserialize)]
pub struct ApiPrincipal {
    pub api_key: String,
    pub org_slug: String,
    #[serde(default)]
    pub project_slug: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateApiKeyRequest {
    org_slug: String,
    #[serde(default)]
    project_slug: Option<String>,
    #[serde(default)]
    actor: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug)]
struct CreatedApiKey {
    api_key: String,
    api_key_hash: String,
    org_slug: String,
    project_slug: Option<String>,
    actor: Option<String>,
    label: String,
}

#[derive(Debug)]
struct StoredApiKey {
    org_slug: String,
    project_slug: Option<String>,
    actor: Option<String>,
    label: Option<String>,
    active: bool,
}

#[derive(Debug, Default, Deserialize)]
struct AdminApiKeyListParams {
    org_slug: Option<String>,
    project_slug: Option<String>,
    include_inactive: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct AdminApiKeyEventListParams {
    org_slug: Option<String>,
    project_slug: Option<String>,
    api_key_hash: Option<String>,
    action: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomRecordParams {
    sbom_id: Option<String>,
    git_commit: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomInventoryParams {
    sbom_id: Option<String>,
    git_commit: Option<String>,
    limit: Option<u32>,
    ecosystem: Option<String>,
    direct_only: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomDiffParams {
    from_sbom_id: Option<String>,
    to_sbom_id: Option<String>,
    from_commit: Option<String>,
    to_commit: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomAdvisoryParams {
    sbom_id: Option<String>,
    git_commit: Option<String>,
    limit: Option<u32>,
    ecosystem: Option<String>,
    direct_only: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomSecurityAlertHistoryParams {
    project_slug: Option<String>,
    kind: Option<String>,
    from_git_commit: Option<String>,
    to_git_commit: Option<String>,
    package_identity: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct SbomTimelineParams {
    project_slug: Option<String>,
    limit: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
struct ProjectOverviewParams {
    limit: Option<u32>,
}

#[derive(Debug, Clone)]
struct SbomPackage {
    bom_ref: String,
    identity: String,
    ecosystem: String,
    name: String,
    version: String,
    purl: Option<String>,
    package_type: String,
    direct: bool,
}

#[derive(Debug, Default, Clone, Copy)]
struct OsvCacheStats {
    cache_hits: usize,
    fresh_queries: usize,
}

#[derive(Clone)]
struct MetadataStore {
    client: Arc<DbClient>,
}

#[derive(Clone)]
struct DbClient {
    pool: Pool,
}

impl DbClient {
    async fn batch_execute(&self, query: &str) -> anyhow::Result<()> {
        let client = self.pool.get().await?;
        client.batch_execute(query).await?;
        Ok(())
    }

    async fn execute(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> anyhow::Result<u64> {
        let client = self.pool.get().await?;
        Ok(client.execute(query, params).await?)
    }

    async fn query(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> anyhow::Result<Vec<Row>> {
        let client = self.pool.get().await?;
        Ok(client.query(query, params).await?)
    }

    async fn query_one(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> anyhow::Result<Row> {
        let client = self.pool.get().await?;
        Ok(client.query_one(query, params).await?)
    }

    async fn query_opt(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> anyhow::Result<Option<Row>> {
        let client = self.pool.get().await?;
        Ok(client.query_opt(query, params).await?)
    }
}

impl MetadataStore {
    async fn from_env() -> anyhow::Result<Option<Self>> {
        let Ok(database_url) = std::env::var("SANDTRACE_INGEST_DATABASE_URL") else {
            return Ok(None);
        };

        let config: tokio_postgres::Config = database_url.parse()?;
        let manager = Manager::from_config(
            config,
            NoTls,
            PgManagerConfig {
                recycling_method: RecyclingMethod::Verified,
            },
        );
        let pool = Pool::builder(manager)
            .runtime(Runtime::Tokio1)
            .max_size(16)
            .build()?;

        let store = Self {
            client: Arc::new(DbClient { pool }),
        };
        store.ensure_schema().await?;
        Ok(Some(store))
    }

    async fn ensure_schema(&self) -> anyhow::Result<()> {
        self.client
            .batch_execute(
                r#"
                CREATE TABLE IF NOT EXISTS ingest_records (
                    record_id TEXT PRIMARY KEY,
                    org_slug TEXT NOT NULL,
                    project_slug TEXT,
                    actor TEXT,
                    kind TEXT NOT NULL,
                    upload_id TEXT NOT NULL,
                    uploaded_at TIMESTAMPTZ,
                    payload_path TEXT NOT NULL,
                    index_record JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS ingest_records_org_kind_uploaded_at_idx
                    ON ingest_records (org_slug, kind, uploaded_at DESC, created_at DESC);

                CREATE TABLE IF NOT EXISTS organizations (
                    org_slug TEXT PRIMARY KEY,
                    org_id TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE TABLE IF NOT EXISTS projects (
                    org_slug TEXT NOT NULL REFERENCES organizations(org_slug) ON DELETE CASCADE,
                    project_slug TEXT NOT NULL,
                    project_id TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (org_slug, project_slug)
                );

                ALTER TABLE organizations
                    ADD COLUMN IF NOT EXISTS org_id TEXT;

                ALTER TABLE projects
                    ADD COLUMN IF NOT EXISTS project_id TEXT;

                CREATE UNIQUE INDEX IF NOT EXISTS organizations_org_id_idx
                    ON organizations (org_id)
                    WHERE org_id IS NOT NULL;

                CREATE UNIQUE INDEX IF NOT EXISTS projects_project_id_idx
                    ON projects (project_id)
                    WHERE project_id IS NOT NULL;

                CREATE TABLE IF NOT EXISTS ingest_api_keys (
                    api_key_hash TEXT PRIMARY KEY,
                    org_slug TEXT NOT NULL REFERENCES organizations(org_slug) ON DELETE CASCADE,
                    project_slug TEXT,
                    actor TEXT,
                    label TEXT,
                    active BOOLEAN NOT NULL DEFAULT TRUE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    last_seen_at TIMESTAMPTZ,
                    FOREIGN KEY (org_slug, project_slug)
                        REFERENCES projects(org_slug, project_slug)
                        ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS ingest_api_keys_org_active_idx
                    ON ingest_api_keys (org_slug, active);

                CREATE TABLE IF NOT EXISTS ingest_api_key_events (
                    event_id BIGSERIAL PRIMARY KEY,
                    event_kind TEXT NOT NULL,
                    api_key_hash TEXT NOT NULL,
                    org_slug TEXT NOT NULL REFERENCES organizations(org_slug) ON DELETE CASCADE,
                    project_slug TEXT,
                    actor TEXT,
                    label TEXT,
                    performed_by TEXT NOT NULL,
                    details JSONB NOT NULL DEFAULT '{}'::jsonb,
                    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (org_slug, project_slug)
                        REFERENCES projects(org_slug, project_slug)
                        ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS ingest_api_key_events_lookup_idx
                    ON ingest_api_key_events (org_slug, project_slug, event_kind, occurred_at DESC);

                CREATE TABLE IF NOT EXISTS ingest_sbom_packages (
                    record_id TEXT NOT NULL REFERENCES ingest_records(record_id) ON DELETE CASCADE,
                    org_slug TEXT NOT NULL REFERENCES organizations(org_slug) ON DELETE CASCADE,
                    project_slug TEXT,
                    git_commit TEXT,
                    package_index INTEGER NOT NULL,
                    bom_ref TEXT,
                    package_identity TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT,
                    purl TEXT,
                    package_type TEXT,
                    direct BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    PRIMARY KEY (record_id, package_index),
                    FOREIGN KEY (org_slug, project_slug)
                        REFERENCES projects(org_slug, project_slug)
                        ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS ingest_sbom_packages_record_idx
                    ON ingest_sbom_packages (record_id, package_index);

                CREATE INDEX IF NOT EXISTS ingest_sbom_packages_commit_idx
                    ON ingest_sbom_packages (org_slug, project_slug, git_commit, ecosystem, package_name);

                CREATE TABLE IF NOT EXISTS ingest_osv_cache (
                    query_key TEXT PRIMARY KEY,
                    package_identity TEXT NOT NULL,
                    ecosystem TEXT NOT NULL,
                    package_name TEXT NOT NULL,
                    package_version TEXT,
                    purl TEXT,
                    advisory_result JSONB NOT NULL,
                    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE INDEX IF NOT EXISTS ingest_osv_cache_lookup_idx
                    ON ingest_osv_cache (fetched_at DESC, ecosystem, package_name);

                CREATE TABLE IF NOT EXISTS ingest_sbom_security_alerts (
                    alert_key TEXT PRIMARY KEY,
                    org_slug TEXT NOT NULL REFERENCES organizations(org_slug) ON DELETE CASCADE,
                    project_slug TEXT,
                    alert_kind TEXT NOT NULL,
                    from_record_id TEXT NOT NULL REFERENCES ingest_records(record_id) ON DELETE CASCADE,
                    to_record_id TEXT NOT NULL REFERENCES ingest_records(record_id) ON DELETE CASCADE,
                    from_git_commit TEXT,
                    to_git_commit TEXT,
                    package_identity TEXT NOT NULL,
                    occurred_at TIMESTAMPTZ,
                    alert_record JSONB NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    FOREIGN KEY (org_slug, project_slug)
                        REFERENCES projects(org_slug, project_slug)
                        ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS ingest_sbom_security_alerts_lookup_idx
                    ON ingest_sbom_security_alerts (org_slug, project_slug, occurred_at DESC, created_at DESC);
                "#,
            )
            .await?;

        self.backfill_scope_ids().await?;

        Ok(())
    }

    async fn backfill_scope_ids(&self) -> anyhow::Result<()> {
        let org_rows = self
            .client
            .query(
                r#"
                SELECT org_slug
                FROM organizations
                WHERE org_id IS NULL OR org_id = ''
                "#,
                &[],
            )
            .await?;

        for row in org_rows {
            let org_slug = row.get::<_, String>(0);
            self.client
                .execute(
                    r#"
                    UPDATE organizations
                    SET org_id = $2
                    WHERE org_slug = $1
                      AND (org_id IS NULL OR org_id = '')
                    "#,
                    &[&org_slug, &generate_lowercase_ulid()],
                )
                .await?;
        }

        let project_rows = self
            .client
            .query(
                r#"
                SELECT org_slug, project_slug
                FROM projects
                WHERE project_id IS NULL OR project_id = ''
                "#,
                &[],
            )
            .await?;

        for row in project_rows {
            let org_slug = row.get::<_, String>(0);
            let project_slug = row.get::<_, String>(1);
            self.client
                .execute(
                    r#"
                    UPDATE projects
                    SET project_id = $3
                    WHERE org_slug = $1
                      AND project_slug = $2
                      AND (project_id IS NULL OR project_id = '')
                    "#,
                    &[&org_slug, &project_slug, &generate_lowercase_ulid()],
                )
                .await?;
        }

        Ok(())
    }

    async fn persist_index_record(
        &self,
        kind: &str,
        record_id: &str,
        payload_path: &str,
        index_record: &Value,
    ) -> anyhow::Result<()> {
        let uploaded_at = index_record
            .get("uploaded_at")
            .and_then(Value::as_str)
            .and_then(parse_uploaded_at);

        self.client
            .execute(
                r#"
                INSERT INTO ingest_records (
                    record_id,
                    org_slug,
                    project_slug,
                    actor,
                    kind,
                    upload_id,
                    uploaded_at,
                    payload_path,
                    index_record
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (record_id) DO UPDATE
                SET
                    org_slug = EXCLUDED.org_slug,
                    project_slug = EXCLUDED.project_slug,
                    actor = EXCLUDED.actor,
                    kind = EXCLUDED.kind,
                    upload_id = EXCLUDED.upload_id,
                    uploaded_at = EXCLUDED.uploaded_at,
                    payload_path = EXCLUDED.payload_path,
                    index_record = EXCLUDED.index_record
                "#,
                &[
                    &record_id,
                    &string_field(index_record, "org_slug"),
                    &optional_string_field(index_record, "project_slug"),
                    &optional_string_field(index_record, "actor"),
                    &kind,
                    &string_field(index_record, "upload_id"),
                    &uploaded_at,
                    &payload_path,
                    &index_record,
                ],
            )
            .await?;

        Ok(())
    }

    async fn persist_sbom_packages(
        &self,
        record_id: &str,
        index_record: &Value,
        payload: &Value,
    ) -> anyhow::Result<()> {
        let packages = extract_sbom_packages(payload.pointer("/payload/sbom"));
        let org_slug = string_field(index_record, "org_slug");
        let project_slug = optional_string_field(index_record, "project_slug");
        let git_commit = optional_string_field(index_record, "git_commit");

        self.client
            .execute(
                r#"
                DELETE FROM ingest_sbom_packages
                WHERE record_id = $1
                "#,
                &[&record_id],
            )
            .await?;

        for (package_index, package) in packages.iter().enumerate() {
            self.client
                .execute(
                    r#"
                    INSERT INTO ingest_sbom_packages (
                        record_id,
                        org_slug,
                        project_slug,
                        git_commit,
                        package_index,
                        bom_ref,
                        package_identity,
                        ecosystem,
                        package_name,
                        package_version,
                        purl,
                        package_type,
                        direct
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    "#,
                    &[
                        &record_id,
                        &org_slug,
                        &project_slug,
                        &git_commit,
                        &(package_index as i32),
                        &package.bom_ref,
                        &package.identity,
                        &package.ecosystem,
                        &package.name,
                        &blank_string_as_none(&package.version),
                        &package.purl,
                        &blank_string_as_none(&package.package_type),
                        &package.direct,
                    ],
                )
                .await?;
        }

        Ok(())
    }

    async fn resolve_storage_scope(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
    ) -> anyhow::Result<StorageScope> {
        let org_row = self
            .client
            .query_one(
                r#"
                SELECT org_id
                FROM organizations
                WHERE org_slug = $1
                "#,
                &[&org_slug],
            )
            .await?;
        let org_key = match row_string(org_row.get::<_, Option<String>>(0)) {
            Some(value) => value,
            None => {
                let generated = generate_lowercase_ulid();
                self.client
                    .execute(
                        r#"
                        UPDATE organizations
                        SET org_id = $2
                        WHERE org_slug = $1
                        "#,
                        &[&org_slug, &generated],
                    )
                    .await?;
                generated
            }
        };

        let project_key = if let Some(project_slug) = project_slug.filter(|value| !value.is_empty())
        {
            let row = self
                .client
                .query_opt(
                    r#"
                    SELECT project_id
                    FROM projects
                    WHERE org_slug = $1
                      AND project_slug = $2
                    "#,
                    &[&org_slug, &project_slug],
                )
                .await?;
            match row.and_then(|row| row_string(row.get::<_, Option<String>>(0))) {
                Some(value) => Some(value),
                None => {
                    let generated = generate_lowercase_ulid();
                    self.client
                        .execute(
                            r#"
                            UPDATE projects
                            SET project_id = $3
                            WHERE org_slug = $1
                              AND project_slug = $2
                            "#,
                            &[&org_slug, &project_slug, &generated],
                        )
                        .await?;
                    Some(generated)
                }
            }
        } else {
            None
        };

        Ok(StorageScope {
            org_key,
            project_key,
        })
    }

    async fn bootstrap_principals<'a, I>(&self, principals: I) -> anyhow::Result<()>
    where
        I: IntoIterator<Item = &'a ApiPrincipal>,
    {
        for principal in principals {
            self.upsert_principal(principal).await?;
        }

        Ok(())
    }

    async fn upsert_principal(&self, principal: &ApiPrincipal) -> anyhow::Result<()> {
        self.client
            .execute(
                r#"
                INSERT INTO organizations (org_slug, org_id)
                VALUES ($1, $2)
                ON CONFLICT (org_slug) DO NOTHING
                "#,
                &[&principal.org_slug, &generate_lowercase_ulid()],
            )
            .await?;

        if let Some(project_slug) = principal
            .project_slug
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.client
                .execute(
                    r#"
                    INSERT INTO projects (org_slug, project_slug, project_id)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (org_slug, project_slug) DO NOTHING
                    "#,
                    &[
                        &principal.org_slug,
                        &project_slug,
                        &generate_lowercase_ulid(),
                    ],
                )
                .await?;
        }

        let api_key_hash = sha256_hex(&principal.api_key);
        self.client
            .execute(
                r#"
                INSERT INTO ingest_api_keys (
                    api_key_hash,
                    org_slug,
                    project_slug,
                    actor,
                    label,
                    active,
                    last_seen_at
                )
                VALUES ($1, $2, $3, $4, $5, TRUE, NULL)
                ON CONFLICT (api_key_hash) DO UPDATE
                SET
                    org_slug = EXCLUDED.org_slug,
                    project_slug = EXCLUDED.project_slug,
                    actor = EXCLUDED.actor,
                    label = EXCLUDED.label
                "#,
                &[
                    &api_key_hash,
                    &principal.org_slug,
                    &principal.project_slug,
                    &principal.actor,
                    &api_key_label(principal),
                ],
            )
            .await?;

        Ok(())
    }

    async fn find_principal_by_api_key(
        &self,
        api_key: &str,
    ) -> anyhow::Result<Option<ApiPrincipal>> {
        let api_key_hash = sha256_hex(api_key);
        let row = self
            .client
            .query_opt(
                r#"
                SELECT org_slug, project_slug, actor
                FROM ingest_api_keys
                WHERE api_key_hash = $1 AND active = TRUE
                "#,
                &[&api_key_hash],
            )
            .await?;

        if let Some(row) = row {
            self.client
                .execute(
                    r#"
                    UPDATE ingest_api_keys
                    SET last_seen_at = NOW()
                    WHERE api_key_hash = $1
                    "#,
                    &[&api_key_hash],
                )
                .await?;

            return Ok(Some(ApiPrincipal {
                api_key: api_key.to_string(),
                org_slug: row.get::<_, String>(0),
                project_slug: row.get::<_, Option<String>>(1),
                actor: row.get::<_, Option<String>>(2),
            }));
        }

        Ok(None)
    }

    async fn ensure_org_and_project(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
    ) -> anyhow::Result<()> {
        self.client
            .execute(
                r#"
                INSERT INTO organizations (org_slug, org_id)
                VALUES ($1, $2)
                ON CONFLICT (org_slug) DO NOTHING
                "#,
                &[&org_slug, &generate_lowercase_ulid()],
            )
            .await?;

        if let Some(project_slug) = project_slug
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            self.client
                .execute(
                    r#"
                    INSERT INTO projects (org_slug, project_slug, project_id)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (org_slug, project_slug) DO NOTHING
                    "#,
                    &[&org_slug, &project_slug, &generate_lowercase_ulid()],
                )
                .await?;
        }

        Ok(())
    }

    async fn create_api_key(&self, request: &CreateApiKeyRequest) -> anyhow::Result<CreatedApiKey> {
        self.ensure_org_and_project(request.org_slug.as_str(), request.project_slug.as_deref())
            .await?;

        let api_key = generate_api_key(&request.org_slug, request.project_slug.as_deref());
        let api_key_hash = sha256_hex(&api_key);
        let label = request.label.clone().unwrap_or_else(|| {
            api_key_label_parts(&request.org_slug, request.project_slug.as_deref())
        });

        self.client
            .execute(
                r#"
                INSERT INTO ingest_api_keys (
                    api_key_hash,
                    org_slug,
                    project_slug,
                    actor,
                    label,
                    active,
                    last_seen_at
                )
                VALUES ($1, $2, $3, $4, $5, TRUE, NULL)
                "#,
                &[
                    &api_key_hash,
                    &request.org_slug,
                    &request.project_slug,
                    &request.actor,
                    &label,
                ],
            )
            .await?;

        Ok(CreatedApiKey {
            api_key,
            api_key_hash,
            org_slug: request.org_slug.clone(),
            project_slug: request.project_slug.clone(),
            actor: request.actor.clone(),
            label,
        })
    }

    async fn list_api_keys(
        &self,
        org_slug: Option<&str>,
        project_slug: Option<&str>,
        include_inactive: bool,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .client
            .query(
                r#"
                SELECT
                    api_key_hash,
                    org_slug,
                    project_slug,
                    actor,
                    label,
                    active,
                    created_at,
                    last_seen_at
                FROM ingest_api_keys
                WHERE ($1::TEXT IS NULL OR org_slug = $1)
                  AND ($2::TEXT IS NULL OR project_slug = $2)
                  AND ($3::BOOL OR active = TRUE)
                ORDER BY org_slug, project_slug NULLS FIRST, created_at DESC, api_key_hash DESC
                "#,
                &[&org_slug, &project_slug, &include_inactive],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "api_key_hash": row.get::<_, String>(0),
                    "org_slug": row.get::<_, String>(1),
                    "project_slug": row.get::<_, Option<String>>(2),
                    "actor": row.get::<_, Option<String>>(3),
                    "label": row.get::<_, Option<String>>(4),
                    "active": row.get::<_, bool>(5),
                    "created_at": row.get::<_, chrono::DateTime<Utc>>(6).to_rfc3339(),
                    "last_seen_at": row.get::<_, Option<chrono::DateTime<Utc>>>(7).map(|ts| ts.to_rfc3339()),
                })
            })
            .collect())
    }

    async fn record_api_key_event(
        &self,
        event_kind: &str,
        api_key_hash: &str,
        org_slug: &str,
        project_slug: Option<&str>,
        actor: Option<&str>,
        label: Option<&str>,
        performed_by: &str,
        details: &Value,
    ) -> anyhow::Result<()> {
        self.client
            .execute(
                r#"
                INSERT INTO ingest_api_key_events (
                    event_kind,
                    api_key_hash,
                    org_slug,
                    project_slug,
                    actor,
                    label,
                    performed_by,
                    details
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                "#,
                &[
                    &event_kind,
                    &api_key_hash,
                    &org_slug,
                    &project_slug,
                    &actor,
                    &label,
                    &performed_by,
                    &details,
                ],
            )
            .await?;

        Ok(())
    }

    async fn list_api_key_events(
        &self,
        org_slug: Option<&str>,
        project_slug: Option<&str>,
        api_key_hash: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .client
            .query(
                r#"
                SELECT
                    event_id,
                    event_kind,
                    api_key_hash,
                    org_slug,
                    project_slug,
                    actor,
                    label,
                    performed_by,
                    details,
                    occurred_at
                FROM ingest_api_key_events
                WHERE ($1::TEXT IS NULL OR org_slug = $1)
                  AND ($2::TEXT IS NULL OR project_slug = $2)
                  AND ($3::TEXT IS NULL OR api_key_hash = $3)
                  AND ($4::TEXT IS NULL OR event_kind = $4)
                ORDER BY occurred_at DESC, event_id DESC
                LIMIT $5
                "#,
                &[
                    &org_slug,
                    &project_slug,
                    &api_key_hash,
                    &action,
                    &(limit as i64),
                ],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "event_id": row.get::<_, i64>(0),
                    "event_kind": row.get::<_, String>(1),
                    "api_key_hash": row.get::<_, String>(2),
                    "org_slug": row.get::<_, String>(3),
                    "project_slug": row.get::<_, Option<String>>(4),
                    "actor": row.get::<_, Option<String>>(5),
                    "label": row.get::<_, Option<String>>(6),
                    "performed_by": row.get::<_, String>(7),
                    "details": row.get::<_, Value>(8),
                    "occurred_at": row.get::<_, chrono::DateTime<Utc>>(9).to_rfc3339(),
                })
            })
            .collect())
    }

    async fn get_stored_api_key(&self, api_key_hash: &str) -> anyhow::Result<Option<StoredApiKey>> {
        let row = self
            .client
            .query_opt(
                r#"
                SELECT api_key_hash, org_slug, project_slug, actor, label, active
                FROM ingest_api_keys
                WHERE api_key_hash = $1
                "#,
                &[&api_key_hash],
            )
            .await?;

        Ok(row.map(|row| StoredApiKey {
            org_slug: row.get::<_, String>(1),
            project_slug: row.get::<_, Option<String>>(2),
            actor: row.get::<_, Option<String>>(3),
            label: row.get::<_, Option<String>>(4),
            active: row.get::<_, bool>(5),
        }))
    }

    async fn deactivate_api_key(&self, api_key_hash: &str) -> anyhow::Result<bool> {
        let updated = self
            .client
            .execute(
                r#"
                UPDATE ingest_api_keys
                SET active = FALSE
                WHERE api_key_hash = $1 AND active = TRUE
                "#,
                &[&api_key_hash],
            )
            .await?;

        Ok(updated > 0)
    }

    async fn delete_api_key(&self, api_key_hash: &str) -> anyhow::Result<bool> {
        let deleted = self
            .client
            .execute(
                r#"
                DELETE FROM ingest_api_keys
                WHERE api_key_hash = $1 AND active = FALSE
                "#,
                &[&api_key_hash],
            )
            .await?;

        Ok(deleted > 0)
    }

    async fn rotate_api_key(&self, api_key_hash: &str) -> anyhow::Result<Option<CreatedApiKey>> {
        let Some(existing) = self.get_stored_api_key(api_key_hash).await? else {
            return Ok(None);
        };
        if !existing.active {
            return Ok(None);
        }

        let request = CreateApiKeyRequest {
            org_slug: existing.org_slug,
            project_slug: existing.project_slug,
            actor: existing.actor,
            label: existing.label,
        };

        let created = self.create_api_key(&request).await?;
        self.deactivate_api_key(api_key_hash).await?;

        Ok(Some(created))
    }

    async fn get_index_record(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        kind: &str,
        record_id: &str,
    ) -> anyhow::Result<Option<Value>> {
        let row = self
            .client
            .query_opt(
                r#"
                SELECT index_record
                FROM ingest_records
                WHERE org_slug = $1
                  AND kind = $2
                  AND record_id = $3
                  AND ($4::TEXT IS NULL OR project_slug = $4)
                "#,
                &[&org_slug, &kind, &record_id, &project_slug],
            )
            .await?;

        Ok(row.map(|row| row.get::<_, Value>(0)))
    }

    async fn get_payload_path(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        kind: &str,
        record_id: &str,
    ) -> anyhow::Result<Option<String>> {
        let row = self
            .client
            .query_opt(
                r#"
                SELECT payload_path
                FROM ingest_records
                WHERE org_slug = $1
                  AND kind = $2
                  AND record_id = $3
                  AND ($4::TEXT IS NULL OR project_slug = $4)
                "#,
                &[&org_slug, &kind, &record_id, &project_slug],
            )
            .await?;

        Ok(row.and_then(|row| row.get::<_, Option<String>>(0)))
    }

    async fn load_index_records(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        kind: &str,
        limit: Option<usize>,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = match limit {
            Some(limit) => {
                self.client
                    .query(
                        r#"
                        SELECT index_record
                        FROM ingest_records
                        WHERE org_slug = $1
                          AND kind = $2
                          AND ($3::TEXT IS NULL OR project_slug = $3)
                        ORDER BY uploaded_at DESC NULLS LAST, created_at DESC, record_id DESC
                        LIMIT $4
                        "#,
                        &[&org_slug, &kind, &project_slug, &(limit as i64)],
                    )
                    .await?
            }
            None => {
                self.client
                    .query(
                        r#"
                        SELECT index_record
                        FROM ingest_records
                        WHERE org_slug = $1
                          AND kind = $2
                          AND ($3::TEXT IS NULL OR project_slug = $3)
                        ORDER BY uploaded_at DESC NULLS LAST, created_at DESC, record_id DESC
                        "#,
                        &[&org_slug, &kind, &project_slug],
                    )
                    .await?
            }
        };

        Ok(rows.into_iter().map(|row| row.get::<_, Value>(0)).collect())
    }

    async fn load_sbom_packages(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        record_id: &str,
    ) -> anyhow::Result<Vec<SbomPackage>> {
        let rows = self
            .client
            .query(
                r#"
                SELECT
                    bom_ref,
                    package_identity,
                    ecosystem,
                    package_name,
                    package_version,
                    purl,
                    package_type,
                    direct
                FROM ingest_sbom_packages
                WHERE org_slug = $1
                  AND record_id = $2
                  AND ($3::TEXT IS NULL OR project_slug = $3)
                ORDER BY package_index ASC
                "#,
                &[&org_slug, &record_id, &project_slug],
            )
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| SbomPackage {
                bom_ref: row.get::<_, Option<String>>(0).unwrap_or_default(),
                identity: row.get::<_, String>(1),
                ecosystem: row.get::<_, String>(2),
                name: row.get::<_, String>(3),
                version: row.get::<_, Option<String>>(4).unwrap_or_default(),
                purl: row.get::<_, Option<String>>(5),
                package_type: row.get::<_, Option<String>>(6).unwrap_or_default(),
                direct: row.get::<_, bool>(7),
            })
            .collect())
    }

    async fn load_osv_cache_entry(
        &self,
        query_key: &str,
        freshness_cutoff: chrono::DateTime<Utc>,
    ) -> anyhow::Result<Option<Value>> {
        let row = self
            .client
            .query_opt(
                r#"
                SELECT advisory_result
                FROM ingest_osv_cache
                WHERE query_key = $1
                  AND fetched_at >= $2
                "#,
                &[&query_key, &freshness_cutoff],
            )
            .await?;

        Ok(row.map(|row| row.get::<_, Value>(0)))
    }

    async fn store_osv_cache_entry(
        &self,
        query_key: &str,
        package: &SbomPackage,
        advisory_result: &Value,
    ) -> anyhow::Result<()> {
        self.client
            .execute(
                r#"
                INSERT INTO ingest_osv_cache (
                    query_key,
                    package_identity,
                    ecosystem,
                    package_name,
                    package_version,
                    purl,
                    advisory_result,
                    fetched_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                ON CONFLICT (query_key) DO UPDATE
                SET
                    package_identity = EXCLUDED.package_identity,
                    ecosystem = EXCLUDED.ecosystem,
                    package_name = EXCLUDED.package_name,
                    package_version = EXCLUDED.package_version,
                    purl = EXCLUDED.purl,
                    advisory_result = EXCLUDED.advisory_result,
                    fetched_at = NOW()
                "#,
                &[
                    &query_key,
                    &package.identity,
                    &package.ecosystem,
                    &package.name,
                    &blank_string_as_none(&package.version),
                    &package.purl,
                    &advisory_result,
                ],
            )
            .await?;

        Ok(())
    }

    async fn replace_sbom_security_alerts(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        to_record_id: &str,
        alerts: &[Value],
    ) -> anyhow::Result<()> {
        self.client
            .execute(
                r#"
                DELETE FROM ingest_sbom_security_alerts
                WHERE org_slug = $1
                  AND ($2::TEXT IS NULL OR project_slug = $2)
                  AND to_record_id = $3
                "#,
                &[&org_slug, &project_slug, &to_record_id],
            )
            .await?;

        for alert in alerts {
            let alert_kind = string_field(alert, "kind");
            let package = alert.get("package").unwrap_or(&Value::Null);
            let package_identity = string_field(package, "identity");
            let alert_key = sha256_hex(&format!("{alert_kind}:{to_record_id}:{package_identity}"));
            let occurred_at = alert
                .get("uploaded_at")
                .and_then(Value::as_str)
                .and_then(parse_uploaded_at);

            self.client
                .execute(
                    r#"
                    INSERT INTO ingest_sbom_security_alerts (
                        alert_key,
                        org_slug,
                        project_slug,
                        alert_kind,
                        from_record_id,
                        to_record_id,
                        from_git_commit,
                        to_git_commit,
                        package_identity,
                        occurred_at,
                        alert_record
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                    "#,
                    &[
                        &alert_key,
                        &org_slug,
                        &project_slug,
                        &alert_kind,
                        &string_field(alert, "from_sbom_id"),
                        &to_record_id,
                        &optional_string_field(alert, "from_git_commit"),
                        &optional_string_field(alert, "to_git_commit"),
                        &package_identity,
                        &occurred_at,
                        &alert,
                    ],
                )
                .await?;
        }

        Ok(())
    }

    async fn load_recent_sbom_security_alerts(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .client
            .query(
                r#"
                SELECT alert_record
                FROM ingest_sbom_security_alerts
                WHERE org_slug = $1
                  AND ($2::TEXT IS NULL OR project_slug = $2)
                ORDER BY occurred_at DESC NULLS LAST, created_at DESC, alert_key DESC
                LIMIT $3
                "#,
                &[&org_slug, &project_slug, &(limit as i64)],
            )
            .await?;

        Ok(rows.into_iter().map(|row| row.get::<_, Value>(0)).collect())
    }

    async fn load_sbom_security_alert_history(
        &self,
        org_slug: &str,
        project_slug: Option<&str>,
        kind: Option<&str>,
        from_git_commit: Option<&str>,
        to_git_commit: Option<&str>,
        package_identity: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<Value>> {
        let rows = self
            .client
            .query(
                r#"
                SELECT alert_record
                FROM ingest_sbom_security_alerts
                WHERE org_slug = $1
                  AND ($2::TEXT IS NULL OR project_slug = $2)
                  AND ($3::TEXT IS NULL OR alert_kind = $3)
                  AND ($4::TEXT IS NULL OR from_git_commit = $4)
                  AND ($5::TEXT IS NULL OR to_git_commit = $5)
                  AND ($6::TEXT IS NULL OR package_identity = $6)
                ORDER BY occurred_at DESC NULLS LAST, created_at DESC, alert_key DESC
                LIMIT $7
                "#,
                &[
                    &org_slug,
                    &project_slug,
                    &kind,
                    &from_git_commit,
                    &to_git_commit,
                    &package_identity,
                    &(limit as i64),
                ],
            )
            .await?;

        Ok(rows.into_iter().map(|row| row.get::<_, Value>(0)).collect())
    }
}

pub fn app(state: IngestState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route(
            "/v1/admin/api-keys",
            get(list_admin_api_keys).post(create_admin_api_key),
        )
        .route("/v1/admin/api-key-events", get(list_admin_api_key_events))
        .route(
            "/v1/admin/api-keys/{api_key_hash}/rotate",
            post(rotate_admin_api_key),
        )
        .route(
            "/v1/admin/api-keys/{api_key_hash}",
            post(deactivate_admin_api_key).delete(delete_admin_api_key),
        )
        .route("/v1/ingest/audit", post(ingest_audit))
        .route("/v1/ingest/run", post(ingest_run))
        .route("/v1/ingest/sbom", post(ingest_sbom))
        .route("/v1/ingest/audit/{id}", get(get_audit))
        .route("/v1/ingest/run/{id}", get(get_run))
        .route("/v1/ingest/sbom/{id}", get(get_sbom))
        .route("/v1/ingest/audits", get(list_audits))
        .route("/v1/ingest/runs", get(list_runs))
        .route("/v1/ingest/sboms", get(list_sboms))
        .route("/v1/projects/overview", get(projects_overview))
        .route("/v1/sbom/document", get(sbom_document))
        .route("/v1/sbom/inventory", get(sbom_inventory))
        .route("/v1/sbom/timeline", get(sbom_timeline))
        .route("/v1/sbom/diff", get(sbom_diff))
        .route("/v1/sbom/alerts", get(sbom_alerts))
        .route("/v1/sbom/advisories", get(sbom_advisories))
        .route(
            "/v1/sbom/security-alerts/history",
            get(sbom_security_alert_history),
        )
        .route("/v1/sbom/security-alerts", get(sbom_security_alerts))
        .route("/v1/dashboard/overview", get(dashboard_overview))
        .with_state(state)
}

pub async fn serve(state: IngestState, bind: SocketAddr) -> anyhow::Result<()> {
    tokio::fs::create_dir_all(state.storage_dir.as_path()).await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app(state)).await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "sandtrace-ingest",
        "timestamp": Utc::now().to_rfc3339(),
    }))
}

async fn list_admin_api_keys(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<AdminApiKeyListParams>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api keys require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    let records = match metadata_store
        .list_api_keys(
            params.org_slug.as_deref(),
            params.project_slug.as_deref(),
            params.include_inactive.unwrap_or(false),
        )
        .await
    {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to list api keys: {error}"),
            )
        }
    };

    Json(json!({
        "status": "ok",
        "count": records.len(),
        "records": records,
    }))
    .into_response()
}

async fn list_admin_api_key_events(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<AdminApiKeyEventListParams>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api key events require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    let limit = params.limit.unwrap_or(50).clamp(1, 200) as usize;
    let records = match metadata_store
        .list_api_key_events(
            params.org_slug.as_deref(),
            params.project_slug.as_deref(),
            params.api_key_hash.as_deref(),
            params.action.as_deref(),
            limit,
        )
        .await
    {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to list api key events: {error}"),
            )
        }
    };

    Json(json!({
        "status": "ok",
        "count": records.len(),
        "records": records,
    }))
    .into_response()
}

async fn create_admin_api_key(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(request): Json<CreateApiKeyRequest>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api keys require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    if request.org_slug.trim().is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "org_slug must not be empty");
    }

    let created = match metadata_store.create_api_key(&request).await {
        Ok(created) => created,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to create api key: {error}"),
            )
        }
    };

    if let Err(error) = metadata_store
        .record_api_key_event(
            "created",
            &created.api_key_hash,
            &created.org_slug,
            created.project_slug.as_deref(),
            created.actor.as_deref(),
            Some(created.label.as_str()),
            state.admin_subject.as_str(),
            &json!({}),
        )
        .await
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to record api key event: {error}"),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "status": "created",
            "record": {
                "api_key_hash": created.api_key_hash,
                "org_slug": created.org_slug,
                "project_slug": created.project_slug,
                "actor": created.actor,
                "label": created.label,
                "active": true,
            },
            "api_key": created.api_key,
        })),
    )
        .into_response()
}

async fn deactivate_admin_api_key(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(api_key_hash): AxumPath<String>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api keys require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    let deactivated = match metadata_store.deactivate_api_key(&api_key_hash).await {
        Ok(deactivated) => deactivated,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to deactivate api key: {error}"),
            )
        }
    };

    if !deactivated {
        return error_response(StatusCode::NOT_FOUND, "api key not found");
    }

    if let Some(stored) = match metadata_store.get_stored_api_key(&api_key_hash).await {
        Ok(stored) => stored,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to look up api key: {error}"),
            )
        }
    } {
        if let Err(error) = metadata_store
            .record_api_key_event(
                "deactivated",
                &api_key_hash,
                &stored.org_slug,
                stored.project_slug.as_deref(),
                stored.actor.as_deref(),
                stored.label.as_deref(),
                state.admin_subject.as_str(),
                &json!({}),
            )
            .await
        {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to record api key event: {error}"),
            );
        }
    }

    Json(json!({
        "status": "ok",
        "api_key_hash": api_key_hash,
        "active": false,
    }))
    .into_response()
}

async fn delete_admin_api_key(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(api_key_hash): AxumPath<String>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api keys require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    let Some(stored) = (match metadata_store.get_stored_api_key(&api_key_hash).await {
        Ok(stored) => stored,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to look up api key: {error}"),
            )
        }
    }) else {
        return error_response(StatusCode::NOT_FOUND, "api key not found");
    };

    if stored.active {
        return error_response(
            StatusCode::CONFLICT,
            "active api keys must be deactivated before deletion",
        );
    }

    let deleted = match metadata_store.delete_api_key(&api_key_hash).await {
        Ok(deleted) => deleted,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to delete api key: {error}"),
            )
        }
    };

    if !deleted {
        return error_response(StatusCode::NOT_FOUND, "api key not found");
    }

    if let Err(error) = metadata_store
        .record_api_key_event(
            "deleted",
            &api_key_hash,
            &stored.org_slug,
            stored.project_slug.as_deref(),
            stored.actor.as_deref(),
            stored.label.as_deref(),
            state.admin_subject.as_str(),
            &json!({}),
        )
        .await
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to record api key event: {error}"),
        );
    }

    Json(json!({
        "status": "deleted",
        "api_key_hash": api_key_hash,
    }))
    .into_response()
}

async fn rotate_admin_api_key(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(api_key_hash): AxumPath<String>,
) -> Response {
    if let Err(response) = authorize_admin(&state, &headers) {
        return response;
    }

    let Some(metadata_store) = &state.metadata_store else {
        return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin api keys require SANDTRACE_INGEST_DATABASE_URL",
        );
    };

    let created = match metadata_store.rotate_api_key(&api_key_hash).await {
        Ok(Some(created)) => created,
        Ok(None) => return error_response(StatusCode::NOT_FOUND, "api key not found"),
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to rotate api key: {error}"),
            )
        }
    };

    if let Err(error) = metadata_store
        .record_api_key_event(
            "rotated",
            &created.api_key_hash,
            &created.org_slug,
            created.project_slug.as_deref(),
            created.actor.as_deref(),
            Some(created.label.as_str()),
            state.admin_subject.as_str(),
            &json!({
                "replaced_api_key_hash": api_key_hash,
            }),
        )
        .await
    {
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to record api key event: {error}"),
        );
    }

    Json(json!({
        "status": "rotated",
        "replaced_api_key_hash": api_key_hash,
        "record": {
            "api_key_hash": created.api_key_hash,
            "org_slug": created.org_slug,
            "project_slug": created.project_slug,
            "actor": created.actor,
            "label": created.label,
            "active": true,
        },
        "api_key": created.api_key,
    }))
    .into_response()
}

async fn ingest_audit(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    ingest("audit", "aud", state, headers, payload).await
}

async fn ingest_run(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    ingest("run", "run", state, headers, payload).await
}

async fn ingest_sbom(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    ingest("sbom", "sbm", state, headers, payload).await
}

async fn get_audit(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    get_record("audit", state, headers, id).await
}

async fn get_run(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    get_record("run", state, headers, id).await
}

async fn get_sbom(
    State(state): State<IngestState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    get_record("sbom", state, headers, id).await
}

async fn list_audits(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    list_records("audit", state, headers, params).await
}

async fn list_runs(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    list_records("run", state, headers, params).await
}

async fn list_sboms(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    list_records("sbom", state, headers, params).await
}

async fn projects_overview(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ProjectOverviewParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let limit = params.limit.unwrap_or(20).clamp(1, 100) as usize;
    let audit_records = match load_index_records(&state, &principal, "audit", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load audit index: {error}"),
            )
        }
    };
    let run_records = match load_index_records(&state, &principal, "run", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load run index: {error}"),
            )
        }
    };
    let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let mut projects = BTreeMap::<String, Value>::new();
    for record in &audit_records {
        let project_slug = string_field(record, "project_slug");
        let project = projects.entry(project_slug.clone()).or_insert_with(|| {
            json!({
                "project_slug": project_slug,
                "latest_activity_at": "",
                "audit_uploads": 0,
                "run_uploads": 0,
                "sbom_uploads": 0,
                "total_findings": 0,
                "latest_audit": Value::Null,
                "latest_run": Value::Null,
                "latest_sbom": Value::Null,
                "current_package_alert_count": 0,
                "current_security_alert_count": 0,
            })
        });
        project["audit_uploads"] = json!(project["audit_uploads"].as_u64().unwrap_or(0) + 1);
        project["total_findings"] = json!(
            project["total_findings"].as_u64().unwrap_or(0)
                + record
                    .get("finding_total")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
        );
        if string_field(record, "uploaded_at")
            > string_field(&project["latest_audit"], "uploaded_at")
        {
            project["latest_audit"] = record.clone();
        }
        if string_field(record, "uploaded_at") > string_field(project, "latest_activity_at") {
            project["latest_activity_at"] =
                record.get("uploaded_at").cloned().unwrap_or(Value::Null);
        }
    }

    for record in &run_records {
        let project_slug = string_field(record, "project_slug");
        let project = projects.entry(project_slug.clone()).or_insert_with(|| {
            json!({
                "project_slug": project_slug,
                "latest_activity_at": "",
                "audit_uploads": 0,
                "run_uploads": 0,
                "sbom_uploads": 0,
                "total_findings": 0,
                "latest_audit": Value::Null,
                "latest_run": Value::Null,
                "latest_sbom": Value::Null,
                "current_package_alert_count": 0,
                "current_security_alert_count": 0,
            })
        });
        project["run_uploads"] = json!(project["run_uploads"].as_u64().unwrap_or(0) + 1);
        if string_field(record, "uploaded_at") > string_field(&project["latest_run"], "uploaded_at")
        {
            project["latest_run"] = record.clone();
        }
        if string_field(record, "uploaded_at") > string_field(project, "latest_activity_at") {
            project["latest_activity_at"] =
                record.get("uploaded_at").cloned().unwrap_or(Value::Null);
        }
    }

    let mut sbom_projects = BTreeMap::<String, Vec<&Value>>::new();
    for record in &sbom_records {
        let project_slug = string_field(record, "project_slug");
        let project = projects.entry(project_slug.clone()).or_insert_with(|| {
            json!({
                "project_slug": project_slug,
                "latest_activity_at": "",
                "audit_uploads": 0,
                "run_uploads": 0,
                "sbom_uploads": 0,
                "total_findings": 0,
                "latest_audit": Value::Null,
                "latest_run": Value::Null,
                "latest_sbom": Value::Null,
                "current_package_alert_count": 0,
                "current_security_alert_count": 0,
            })
        });
        project["sbom_uploads"] = json!(project["sbom_uploads"].as_u64().unwrap_or(0) + 1);
        if string_field(record, "uploaded_at")
            > string_field(&project["latest_sbom"], "uploaded_at")
        {
            project["latest_sbom"] = record.clone();
        }
        if string_field(record, "uploaded_at") > string_field(project, "latest_activity_at") {
            project["latest_activity_at"] =
                record.get("uploaded_at").cloned().unwrap_or(Value::Null);
        }
        sbom_projects.entry(project_slug).or_default().push(record);
    }

    let mut items = projects.into_values().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        string_field(right, "latest_activity_at")
            .cmp(&string_field(left, "latest_activity_at"))
            .then_with(|| {
                string_field(left, "project_slug").cmp(&string_field(right, "project_slug"))
            })
    });
    items.truncate(limit);

    // Keep the overview endpoint cheap and deterministic. Detailed package and
    // security alert counts are derived in the SBOM-specific endpoints instead of
    // running package diffs and OSV lookups inline during dashboard load.

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "summary": {
            "project_count": items.len(),
            "audit_uploads": audit_records.len(),
            "run_uploads": run_records.len(),
            "sbom_uploads": sbom_records.len(),
        },
        "projects": items,
    }))
    .into_response()
}

async fn sbom_document(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomRecordParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let Some(record) = resolve_sbom_record(
        &records,
        params.sbom_id.as_deref(),
        params.git_commit.as_deref(),
    ) else {
        return error_response(StatusCode::NOT_FOUND, "sbom record not found");
    };

    let record_id = record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let payload = match load_record_payload(&state, &principal, "sbom", &record_id).await {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return error_response(StatusCode::NOT_FOUND, "sbom record payload not found");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to read sbom payload: {error}"),
            )
        }
    };

    Json(json!({
        "status": "ok",
        "record": record,
        "sbom": payload.pointer("/payload/sbom").cloned().unwrap_or(Value::Null),
    }))
    .into_response()
}

async fn sbom_inventory(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomInventoryParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let Some(record) = resolve_sbom_record(
        &records,
        params.sbom_id.as_deref(),
        params.git_commit.as_deref(),
    ) else {
        return error_response(StatusCode::NOT_FOUND, "sbom record not found");
    };

    let record_id = record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let all_packages = match load_sbom_packages_for_record(&state, &principal, &record_id).await {
        Ok(packages) => packages,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom packages: {error}"),
            )
        }
    };
    let mut packages: Vec<Value> = all_packages
        .iter()
        .filter(|package| {
            params
                .ecosystem
                .as_deref()
                .is_none_or(|ecosystem| package.ecosystem == ecosystem)
                && (!params.direct_only.unwrap_or(false) || package.direct)
        })
        .map(sbom_package_json)
        .collect();
    packages.sort_by(|left, right| {
        string_field(left, "ecosystem")
            .cmp(&string_field(right, "ecosystem"))
            .then_with(|| string_field(left, "name").cmp(&string_field(right, "name")))
            .then_with(|| string_field(left, "version").cmp(&string_field(right, "version")))
    });

    let total_packages = packages.len();
    let direct_packages = packages
        .iter()
        .filter(|package| package.get("direct").and_then(Value::as_bool) == Some(true))
        .count();
    let limit = params.limit.unwrap_or(200).clamp(1, 1000) as usize;
    let packages = packages.into_iter().take(limit).collect::<Vec<_>>();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "record": record,
        "summary": {
            "package_count": total_packages,
            "direct_package_count": direct_packages,
            "ecosystem": params.ecosystem,
            "direct_only": params.direct_only.unwrap_or(false),
        },
        "packages": packages,
    }))
    .into_response()
}

async fn sbom_diff(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomDiffParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    if records.is_empty() {
        return error_response(StatusCode::NOT_FOUND, "no sbom records available");
    }

    let Some(to_record) = resolve_sbom_record(
        &records,
        params.to_sbom_id.as_deref(),
        params.to_commit.as_deref(),
    ) else {
        return error_response(StatusCode::NOT_FOUND, "target sbom record not found");
    };

    let Some(from_record) = resolve_sbom_base_record(
        &records,
        to_record,
        params.from_sbom_id.as_deref(),
        params.from_commit.as_deref(),
    ) else {
        return error_response(
            StatusCode::NOT_FOUND,
            "base sbom record not found; provide from_sbom_id/from_commit or upload an earlier sbom",
        );
    };

    let from_id = from_record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let to_id = to_record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let from_packages = match load_sbom_packages_for_record(&state, &principal, &from_id).await {
        Ok(packages) => packages,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load base sbom packages: {error}"),
            )
        }
    };
    let to_packages = match load_sbom_packages_for_record(&state, &principal, &to_id).await {
        Ok(packages) => packages,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load target sbom packages: {error}"),
            )
        }
    };
    let limit = params.limit.unwrap_or(200).clamp(1, 1000) as usize;

    let from_by_identity = from_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let to_by_identity = to_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let all_identities = from_by_identity
        .keys()
        .chain(to_by_identity.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut version_changes = Vec::new();
    let mut unchanged_count = 0u64;

    for identity in all_identities {
        match (
            from_by_identity.get(&identity),
            to_by_identity.get(&identity),
        ) {
            (Some(from_package), Some(to_package)) => {
                if from_package.version == to_package.version {
                    unchanged_count += 1;
                } else {
                    version_changes.push(json!({
                        "identity": identity,
                        "ecosystem": to_package.ecosystem,
                        "name": to_package.name,
                        "purl": to_package.purl,
                        "from_version": from_package.version,
                        "to_version": to_package.version,
                        "direct": from_package.direct || to_package.direct,
                    }));
                }
            }
            (None, Some(to_package)) => added.push(sbom_package_json(to_package)),
            (Some(from_package), None) => removed.push(sbom_package_json(from_package)),
            (None, None) => {}
        }
    }

    added.sort_by(sbom_package_sort_key);
    removed.sort_by(sbom_package_sort_key);
    version_changes.sort_by(|left, right| {
        string_field(left, "ecosystem")
            .cmp(&string_field(right, "ecosystem"))
            .then_with(|| string_field(left, "name").cmp(&string_field(right, "name")))
    });

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "from_record": from_record,
        "to_record": to_record,
        "summary": {
            "added_count": added.len(),
            "removed_count": removed.len(),
            "version_change_count": version_changes.len(),
            "unchanged_count": unchanged_count,
            "directly_added_count": added.iter().filter(|package| package.get("direct").and_then(Value::as_bool) == Some(true)).count(),
        },
        "added": added.into_iter().take(limit).collect::<Vec<_>>(),
        "removed": removed.into_iter().take(limit).collect::<Vec<_>>(),
        "version_changes": version_changes.into_iter().take(limit).collect::<Vec<_>>(),
    }))
    .into_response()
}

async fn sbom_alerts(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };
    let limit = params.limit.unwrap_or(20).clamp(1, 100) as usize;
    let alerts = match build_recent_sbom_alerts(&state, &principal, &sbom_records, limit).await {
        Ok(alerts) => alerts,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to build sbom alerts: {error}"),
            )
        }
    };

    let direct_addition_count = alerts
        .iter()
        .filter(|alert| alert.get("kind").and_then(Value::as_str) == Some("new_direct_package"))
        .count();
    let version_change_count = alerts
        .iter()
        .filter(|alert| alert.get("kind").and_then(Value::as_str) == Some("direct_version_change"))
        .count();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "summary": {
            "alert_count": alerts.len(),
            "new_direct_package_count": direct_addition_count,
            "direct_version_change_count": version_change_count,
        },
        "alerts": alerts,
    }))
    .into_response()
}

async fn sbom_advisories(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomAdvisoryParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let Some(record) = resolve_sbom_record(
        &records,
        params.sbom_id.as_deref(),
        params.git_commit.as_deref(),
    ) else {
        return error_response(StatusCode::NOT_FOUND, "sbom record not found");
    };

    let record_id = string_field(record, "id");
    let packages = match load_sbom_packages_for_record(&state, &principal, &record_id).await {
        Ok(packages) => packages,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom packages: {error}"),
            )
        }
    };

    let filtered_packages = packages
        .into_iter()
        .filter(|package| {
            params
                .ecosystem
                .as_deref()
                .is_none_or(|ecosystem| package.ecosystem == ecosystem)
                && (!params.direct_only.unwrap_or(false) || package.direct)
        })
        .collect::<Vec<_>>();
    let query_limit = params.limit.unwrap_or(100).clamp(1, 200) as usize;
    let (mut advisory_results, cache_stats) =
        match query_osv_advisories(&state, &filtered_packages, query_limit).await {
            Ok(results) => results,
            Err(error) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed to query OSV: {error}"),
                )
            }
        };

    // Enrich vulnerable packages with dependency paths from root
    if let Ok(payload) = load_record_payload(&state, &principal, "sbom", &record_id).await {
        if let Some(sbom) = payload.pointer("/payload/sbom") {
            enrich_advisories_with_paths(&mut advisory_results, sbom);
        }
    }

    let affected_package_count = advisory_results
        .iter()
        .filter(|package| {
            package
                .get("vulnerability_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
        })
        .count();
    let vulnerability_count: usize = advisory_results
        .iter()
        .map(|package| {
            package
                .get("vulnerabilities")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0)
        })
        .sum();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "record": record,
        "source": {
            "provider": "osv.dev",
            "base_url": state.osv_api_url.as_str(),
        },
        "summary": {
            "package_count": filtered_packages.len(),
            "queried_package_count": advisory_results.len(),
            "affected_package_count": affected_package_count,
            "vulnerability_count": vulnerability_count,
            "direct_only": params.direct_only.unwrap_or(false),
            "ecosystem": params.ecosystem,
            "cache_hits": cache_stats.cache_hits,
            "fresh_queries": cache_stats.fresh_queries,
        },
        "packages": advisory_results,
    }))
    .into_response()
}

async fn sbom_security_alerts(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };
    let limit = params.limit.unwrap_or(20).clamp(1, 100) as usize;
    let (alerts, cache_stats) =
        match load_or_build_recent_sbom_security_alerts(&state, &principal, &sbom_records, limit)
            .await
        {
            Ok(alerts) => alerts,
            Err(error) => {
                return error_response(
                    StatusCode::BAD_GATEWAY,
                    &format!("failed to build sbom security alerts: {error}"),
                )
            }
        };

    let new_vulnerable_direct_package_count = alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("new_vulnerable_direct_package")
        })
        .count();
    let vulnerable_direct_version_change_count = alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("vulnerable_direct_version_change")
        })
        .count();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "summary": {
            "alert_count": alerts.len(),
            "new_vulnerable_direct_package_count": new_vulnerable_direct_package_count,
            "vulnerable_direct_version_change_count": vulnerable_direct_version_change_count,
            "cache_hits": cache_stats.cache_hits,
            "fresh_queries": cache_stats.fresh_queries,
        },
        "alerts": alerts,
    }))
    .into_response()
}

async fn sbom_security_alert_history(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomSecurityAlertHistoryParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let project_slug = match resolve_project_filter(&principal, params.project_slug.as_deref()) {
        Ok(project_slug) => project_slug,
        Err(response) => return response,
    };

    let limit = params.limit.unwrap_or(50).clamp(1, 200) as usize;
    let alerts = if let Some(metadata_store) = &state.metadata_store {
        match metadata_store
            .load_sbom_security_alert_history(
                principal.org_slug.as_str(),
                project_slug.as_deref(),
                params.kind.as_deref(),
                params.from_git_commit.as_deref(),
                params.to_git_commit.as_deref(),
                params.package_identity.as_deref(),
                limit,
            )
            .await
        {
            Ok(alerts) => alerts,
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to query sbom security alert history: {error}"),
                )
            }
        }
    } else {
        let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
            Ok(records) => records,
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to load sbom index: {error}"),
                )
            }
        };
        let (alerts, cache_stats) =
            match build_recent_sbom_security_alerts(&state, &principal, &sbom_records, limit).await
            {
                Ok(result) => result,
                Err(error) => {
                    return error_response(
                        StatusCode::BAD_GATEWAY,
                        &format!("failed to build sbom security alert history: {error}"),
                    )
                }
            };
        let filtered = alerts
            .into_iter()
            .filter(|alert| {
                sbom_security_alert_matches_filters(
                    alert,
                    project_slug.as_deref(),
                    params.kind.as_deref(),
                    params.from_git_commit.as_deref(),
                    params.to_git_commit.as_deref(),
                    params.package_identity.as_deref(),
                )
            })
            .collect::<Vec<_>>();
        return Json(json!({
            "status": "ok",
            "organization": {
                "org_slug": principal.org_slug,
                "project_slug": principal.project_slug,
                "actor": principal.actor,
            },
            "filters": {
                "project_slug": project_slug,
                "kind": params.kind,
                "from_git_commit": params.from_git_commit,
                "to_git_commit": params.to_git_commit,
                "package_identity": params.package_identity,
                "limit": limit,
                "storage_mode": "derived",
            },
            "summary": summarize_sbom_security_alerts(&filtered, Some(cache_stats)),
            "alerts": filtered,
        }))
        .into_response();
    };

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "filters": {
            "project_slug": project_slug,
            "kind": params.kind,
            "from_git_commit": params.from_git_commit,
            "to_git_commit": params.to_git_commit,
            "package_identity": params.package_identity,
            "limit": limit,
            "storage_mode": "persisted",
        },
        "summary": summarize_sbom_security_alerts(&alerts, None),
        "alerts": alerts,
    }))
    .into_response()
}

async fn sbom_timeline(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<SbomTimelineParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let project_slug = match resolve_project_filter(&principal, params.project_slug.as_deref()) {
        Ok(project_slug) => project_slug,
        Err(response) => return response,
    };
    let limit = params.limit.unwrap_or(20).clamp(1, 100) as usize;
    let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let filtered_records = sbom_records
        .into_iter()
        .filter(|record| {
            project_slug.as_deref().is_none_or(|expected| {
                record.get("project_slug").and_then(Value::as_str) == Some(expected)
            })
        })
        .collect::<Vec<_>>();

    let mut projects = BTreeMap::<String, Vec<&Value>>::new();
    for record in &filtered_records {
        let key = record
            .get("project_slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        projects.entry(key).or_default().push(record);
    }

    let mut commits = Vec::new();
    for records in projects.values() {
        for (index, record) in records.iter().enumerate() {
            let from_record = records
                .iter()
                .skip(index + 1)
                .copied()
                .find(|candidate| candidate.get("git_commit") != record.get("git_commit"));
            commits.push(json!({
                "sbom_id": record.get("id").cloned().unwrap_or(Value::Null),
                "project_slug": record.get("project_slug").cloned().unwrap_or(Value::Null),
                "git_commit": record.get("git_commit").cloned().unwrap_or(Value::Null),
                "uploaded_at": record.get("uploaded_at").cloned().unwrap_or(Value::Null),
                "component_count": record.get("component_count").cloned().unwrap_or_else(|| json!(0)),
                "direct_dependency_count": record.get("direct_dependency_count").cloned().unwrap_or_else(|| json!(0)),
                "ecosystem_counts": record.get("ecosystem_counts").cloned().unwrap_or_else(|| json!({})),
                "diff_base_sbom_id": from_record.and_then(|value| value.get("id").cloned()).unwrap_or(Value::Null),
                "diff_base_git_commit": from_record.and_then(|value| value.get("git_commit").cloned()).unwrap_or(Value::Null),
                "package_alert_count": 0,
                "new_direct_package_count": 0,
                "direct_version_change_count": 0,
                "security_alert_count": 0,
                "new_vulnerable_direct_package_count": 0,
                "vulnerable_direct_version_change_count": 0,
            }));
        }
    }

    commits.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(right, "sbom_id").cmp(&string_field(left, "sbom_id")))
    });
    commits.truncate(limit);

    // Keep the timeline endpoint cheap on first paint. Detailed package and
    // security alert derivation belongs to the diff and alert-specific endpoints
    // instead of running per-commit comparisons during dashboard load.

    let project_count = commits
        .iter()
        .filter_map(|record| record.get("project_slug").and_then(Value::as_str))
        .collect::<BTreeSet<_>>()
        .len();
    let package_alert_count: usize = commits
        .iter()
        .map(|record| {
            record
                .get("package_alert_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize
        })
        .sum();
    let security_alert_count: usize = commits
        .iter()
        .map(|record| {
            record
                .get("security_alert_count")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize
        })
        .sum();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "filters": {
            "project_slug": project_slug,
            "limit": limit,
        },
        "summary": {
            "commit_count": commits.len(),
            "project_count": project_count,
            "package_alert_count": package_alert_count,
            "security_alert_count": security_alert_count,
        },
        "commits": commits,
    }))
    .into_response()
}

async fn dashboard_overview(
    State(state): State<IngestState>,
    headers: HeaderMap,
    Query(params): Query<ListParams>,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let limit = params.limit.unwrap_or(10).clamp(1, 100) as usize;
    let audit_records = match load_index_records(&state, &principal, "audit", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load audit index: {error}"),
            )
        }
    };
    let run_records = match load_index_records(&state, &principal, "run", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load run index: {error}"),
            )
        }
    };
    let sbom_records = match load_index_records(&state, &principal, "sbom", None).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load sbom index: {error}"),
            )
        }
    };

    let recent_suspicious_runs: Vec<Value> = run_records
        .iter()
        .filter(|record| {
            record.get("verdict").and_then(Value::as_str) == Some("suspicious")
                || record.get("verdict").and_then(Value::as_str) == Some("blocked")
        })
        .take(limit)
        .cloned()
        .collect();

    let mut verdict_counts = std::collections::BTreeMap::new();
    let mut severity_counts = std::collections::BTreeMap::new();
    for record in &run_records {
        if let Some(verdict) = record.get("verdict").and_then(Value::as_str) {
            *verdict_counts.entry(verdict.to_string()).or_insert(0u64) += 1;
        }
        if let Some(severity) = record.get("severity").and_then(Value::as_str) {
            *severity_counts.entry(severity.to_string()).or_insert(0u64) += 1;
        }
    }

    let total_findings: u64 = audit_records
        .iter()
        .map(|record| {
            record
                .get("finding_total")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    let total_critical_audits: u64 = audit_records
        .iter()
        .map(|record| record.get("critical").and_then(Value::as_u64).unwrap_or(0))
        .sum();
    let total_high_audits: u64 = audit_records
        .iter()
        .map(|record| record.get("high").and_then(Value::as_u64).unwrap_or(0))
        .sum();
    let total_sbom_components: u64 = sbom_records
        .iter()
        .map(|record| {
            record
                .get("component_count")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    let mut ecosystem_counts = std::collections::BTreeMap::new();
    for record in &sbom_records {
        if let Some(counts) = record.get("ecosystem_counts").and_then(Value::as_object) {
            for (ecosystem, count) in counts {
                *ecosystem_counts.entry(ecosystem.clone()).or_insert(0u64) +=
                    count.as_u64().unwrap_or(0);
            }
        }
    }
    let recent_sbom_alerts =
        match build_recent_sbom_alerts(&state, &principal, &sbom_records, limit).await {
            Ok(alerts) => alerts,
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to build sbom alerts: {error}"),
                )
            }
        };
    let (recent_sbom_security_alerts, security_alert_cache_stats, security_alert_error) =
        match load_or_build_recent_sbom_security_alerts(&state, &principal, &sbom_records, limit)
            .await
        {
            Ok((alerts, stats)) => (alerts, stats, None),
            Err(error) => (
                Vec::new(),
                OsvCacheStats::default(),
                Some(error.to_string()),
            ),
        };
    let new_direct_package_count = recent_sbom_alerts
        .iter()
        .filter(|alert| alert.get("kind").and_then(Value::as_str) == Some("new_direct_package"))
        .count();
    let direct_version_change_count = recent_sbom_alerts
        .iter()
        .filter(|alert| alert.get("kind").and_then(Value::as_str) == Some("direct_version_change"))
        .count();
    let new_vulnerable_direct_package_count = recent_sbom_security_alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("new_vulnerable_direct_package")
        })
        .count();
    let vulnerable_direct_version_change_count = recent_sbom_security_alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("vulnerable_direct_version_change")
        })
        .count();

    Json(json!({
        "status": "ok",
        "organization": {
            "org_slug": principal.org_slug,
            "project_slug": principal.project_slug,
            "actor": principal.actor,
        },
        "summary": {
            "audit_uploads": audit_records.len(),
            "run_uploads": run_records.len(),
            "sbom_uploads": sbom_records.len(),
            "total_findings": total_findings,
            "critical_findings": total_critical_audits,
            "high_findings": total_high_audits,
            "total_sbom_components": total_sbom_components,
            "verdict_counts": verdict_counts,
            "severity_counts": severity_counts,
            "ecosystem_counts": ecosystem_counts,
            "sbom_alert_count": recent_sbom_alerts.len(),
            "new_direct_package_count": new_direct_package_count,
            "direct_version_change_count": direct_version_change_count,
            "sbom_security_alert_count": recent_sbom_security_alerts.len(),
            "new_vulnerable_direct_package_count": new_vulnerable_direct_package_count,
            "vulnerable_direct_version_change_count": vulnerable_direct_version_change_count,
            "sbom_security_alert_cache_hits": security_alert_cache_stats.cache_hits,
            "sbom_security_alert_fresh_queries": security_alert_cache_stats.fresh_queries,
            "sbom_security_alert_error": security_alert_error,
        },
        "recent_suspicious_runs": recent_suspicious_runs,
        "recent_audits": audit_records.into_iter().take(limit).collect::<Vec<_>>(),
        "recent_sboms": sbom_records.into_iter().take(limit).collect::<Vec<_>>(),
        "recent_sbom_alerts": recent_sbom_alerts,
        "recent_sbom_security_alerts": recent_sbom_security_alerts,
    }))
    .into_response()
}

async fn ingest(
    kind: &'static str,
    id_prefix: &'static str,
    state: IngestState,
    headers: HeaderMap,
    payload: Value,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            warn!(
                kind,
                "ingest request rejected: missing or invalid bearer token"
            );
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            error!(kind, %error, "ingest authorization failed");
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    info!(
        kind,
        org = %principal.org_slug,
        project = principal.project_slug.as_deref().unwrap_or("unscoped"),
        "ingest request authorized"
    );

    if let Err(message) = validate_payload(kind, &payload) {
        warn!(kind, %message, "ingest payload validation failed");
        return error_response(StatusCode::BAD_REQUEST, &message);
    }

    let effective_project_slug = principal
        .project_slug
        .clone()
        .or_else(|| infer_project_slug_from_payload(&payload));
    let effective_principal = ApiPrincipal {
        project_slug: effective_project_slug,
        ..principal
    };

    let upload_id = payload
        .get("upload_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let provisional_record_id = generate_record_id(id_prefix, upload_id);
    let provisional_index_record =
        build_index_record(kind, &provisional_record_id, &payload, &effective_principal);
    let record_id = if kind == "sbom" {
        deterministic_sbom_record_id(&provisional_index_record)
    } else {
        provisional_record_id.clone()
    };
    let index_record = if record_id == provisional_record_id {
        provisional_index_record
    } else {
        build_index_record(kind, &record_id, &payload, &effective_principal)
    };

    if kind == "sbom" {
        match find_duplicate_sbom(&state, &effective_principal, &index_record).await {
            Ok(Some(existing_record)) => {
                let existing_id = existing_record
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                return Json(json!({
                    "sbom_id": existing_id,
                    "status": "duplicate",
                    "organization": {
                        "org_slug": effective_principal.org_slug,
                        "project_slug": effective_principal.project_slug,
                        "actor": effective_principal.actor,
                    },
                    "record": existing_record,
                }))
                .into_response();
            }
            Ok(None) => {}
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to check for duplicate sbom: {error}"),
                )
            }
        }
    }

    match persist_payload(
        &state,
        effective_principal.org_slug.as_str(),
        effective_principal.project_slug.as_deref(),
        kind,
        &record_id,
        &payload,
        &index_record,
    )
    .await
    {
        Ok(path) => {
            if kind == "sbom" {
                if let Err(error) = persist_sbom_security_alerts_for_record(
                    &state,
                    &effective_principal,
                    &record_id,
                )
                .await
                {
                    warn!(
                        %record_id,
                        %error,
                        "failed to persist sbom security alerts"
                    );
                }
            }

            Json(json!({
                format!("{}_id", kind): record_id,
                "status": "accepted",
                "stored_at": path,
                "organization": {
                    "org_slug": effective_principal.org_slug,
                    "project_slug": effective_principal.project_slug,
                    "actor": effective_principal.actor,
                },
                "record": index_record,
            }))
            .into_response()
        }
        Err(error) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("failed to persist ingest payload: {error}"),
        ),
    }
}

fn infer_project_slug_from_payload(payload: &Value) -> Option<String> {
    let repo_url = payload
        .pointer("/project/repo_url")
        .and_then(Value::as_str)?;
    infer_project_slug_from_repo_url(repo_url)
}

fn infer_project_slug_from_repo_url(repo_url: &str) -> Option<String> {
    let trimmed = repo_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    let candidate = trimmed
        .rsplit(['/', ':'])
        .next()
        .map(|value| value.trim_end_matches(".git"))?;
    let slug = candidate.trim().to_lowercase();
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

async fn find_duplicate_sbom(
    state: &IngestState,
    principal: &ApiPrincipal,
    index_record: &Value,
) -> anyhow::Result<Option<Value>> {
    let Some(sbom_hash) = index_record
        .get("sbom_hash")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    let git_commit = index_record
        .get("git_commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let existing_records = load_index_records(state, principal, "sbom", None).await?;
    for record in existing_records {
        if record
            .get("sbom_hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            != sbom_hash
        {
            continue;
        }

        let commit_matches = !git_commit.is_empty()
            && record
                .get("git_commit")
                .and_then(Value::as_str)
                .unwrap_or_default()
                == git_commit;

        if commit_matches {
            return Ok(Some(record));
        }
    }

    Ok(None)
}

async fn authorize(
    state: &IngestState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<ApiPrincipal>> {
    let Some(token) = extract_bearer_token(headers) else {
        return Ok(None);
    };

    if let Some(metadata_store) = &state.metadata_store {
        return metadata_store.find_principal_by_api_key(token).await;
    }

    Ok(state.principals.get(token).cloned())
}

fn authorize_admin(state: &IngestState, headers: &HeaderMap) -> Result<(), Response> {
    let Some(configured_token) = state.admin_token.as_deref() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "set SANDTRACE_INGEST_ADMIN_TOKEN to enable admin endpoints",
        ));
    };

    let Some(token) = extract_bearer_token(headers) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin bearer token",
        ));
    };

    if token != configured_token {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "missing or invalid admin bearer token",
        ));
    }

    Ok(())
}

fn validate_payload(expected_command: &str, payload: &Value) -> Result<(), String> {
    let upload_id = payload
        .get("upload_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing upload_id".to_string())?;
    if upload_id.trim().is_empty() {
        return Err("upload_id must not be empty".to_string());
    }

    let schema_version = payload
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing schema_version".to_string())?;
    if schema_version.trim().is_empty() {
        return Err("schema_version must not be empty".to_string());
    }

    let command = payload
        .get("tool")
        .and_then(Value::as_object)
        .and_then(|tool| tool.get("command"))
        .and_then(Value::as_str)
        .ok_or_else(|| "missing tool.command".to_string())?;
    if command != expected_command {
        return Err(format!(
            "tool.command must be `{expected_command}`, got `{command}`"
        ));
    }

    if !payload.get("payload").is_some_and(Value::is_object) {
        return Err("payload must be an object".to_string());
    }

    Ok(())
}

async fn persist_payload(
    state: &IngestState,
    org_slug: &str,
    project_slug: Option<&str>,
    kind: &str,
    record_id: &str,
    payload: &Value,
    index_record: &Value,
) -> anyhow::Result<String> {
    if state.metadata_store.is_none() {
        let storage_dir = state.storage_dir.as_path();
        let org_dir = storage_dir.join(org_slug);
        let index_dir = org_dir.join("index").join(kind);
        tokio::fs::create_dir_all(&index_dir).await?;
        let index_path = index_dir.join(format!("{record_id}.json"));
        let index_body = serde_json::to_vec_pretty(index_record)?;
        tokio::fs::write(&index_path, index_body).await?;
    }

    let storage_scope = if let Some(metadata_store) = &state.metadata_store {
        metadata_store
            .resolve_storage_scope(org_slug, project_slug)
            .await?
    } else {
        StorageScope {
            org_key: org_slug.to_string(),
            project_key: project_slug.map(|value| value.to_string()),
        }
    };

    let payload_path = state
        .payload_store
        .write_json(
            storage_scope.org_key.as_str(),
            storage_scope.project_key.as_deref(),
            kind,
            record_id,
            payload,
        )
        .await?;

    if let Some(metadata_store) = &state.metadata_store {
        metadata_store
            .ensure_org_and_project(org_slug, project_slug)
            .await?;
        metadata_store
            .persist_index_record(kind, record_id, &payload_path, index_record)
            .await?;
        if kind == "sbom" {
            metadata_store
                .persist_sbom_packages(record_id, index_record, payload)
                .await?;
        }
    }

    Ok(payload_path)
}

fn build_index_record(
    kind: &str,
    record_id: &str,
    payload: &Value,
    principal: &ApiPrincipal,
) -> Value {
    let summary = payload
        .get("payload")
        .and_then(|inner| inner.get("summary"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let base = json!({
        "id": record_id,
        "kind": kind,
        "upload_id": payload.get("upload_id").and_then(Value::as_str).unwrap_or_default(),
        "uploaded_at": payload.get("uploaded_at").and_then(Value::as_str).unwrap_or_default(),
        "org_slug": principal.org_slug,
        "project_slug": principal.project_slug,
        "actor": principal.actor,
        "environment": payload.pointer("/source/environment").and_then(Value::as_str).unwrap_or_default(),
        "tool_version": payload.pointer("/tool/version").and_then(Value::as_str).unwrap_or_default(),
        "git_branch": payload.pointer("/project/git_branch").and_then(Value::as_str).unwrap_or_default(),
        "git_commit": payload.pointer("/project/git_commit").and_then(Value::as_str).unwrap_or_default(),
        "repo_url": payload.pointer("/project/repo_url").and_then(Value::as_str).unwrap_or_default(),
    });

    match kind {
        "audit" => json!({
            "id": base["id"],
            "kind": base["kind"],
            "upload_id": base["upload_id"],
            "uploaded_at": base["uploaded_at"],
            "org_slug": base["org_slug"],
            "project_slug": base["project_slug"],
            "actor": base["actor"],
            "environment": base["environment"],
            "tool_version": base["tool_version"],
            "git_branch": base["git_branch"],
            "git_commit": base["git_commit"],
            "repo_url": base["repo_url"],
            "finding_total": summary.get("total").and_then(Value::as_u64).unwrap_or(0),
            "critical": summary.get("critical").and_then(Value::as_u64).unwrap_or(0),
            "high": summary.get("high").and_then(Value::as_u64).unwrap_or(0),
            "medium": summary.get("medium").and_then(Value::as_u64).unwrap_or(0),
            "low": summary.get("low").and_then(Value::as_u64).unwrap_or(0),
            "info": summary.get("info").and_then(Value::as_u64).unwrap_or(0),
            "file_count": payload.pointer("/payload/file_count").and_then(Value::as_u64).unwrap_or(0),
            "duration_ms": payload.pointer("/payload/duration_ms").and_then(Value::as_u64).unwrap_or(0),
        }),
        "run" => json!({
            "id": base["id"],
            "kind": base["kind"],
            "upload_id": base["upload_id"],
            "uploaded_at": base["uploaded_at"],
            "org_slug": base["org_slug"],
            "project_slug": base["project_slug"],
            "actor": base["actor"],
            "environment": base["environment"],
            "tool_version": base["tool_version"],
            "git_branch": base["git_branch"],
            "git_commit": base["git_commit"],
            "repo_url": base["repo_url"],
            "program": payload.pointer("/payload/command/program").and_then(Value::as_str).unwrap_or_default(),
            "verdict": payload.pointer("/payload/verdict").and_then(Value::as_str).unwrap_or_default(),
            "severity": payload.pointer("/payload/severity").and_then(Value::as_str).unwrap_or_default(),
            "exit_code": summary.get("exit_code").and_then(Value::as_i64).unwrap_or_default(),
            "denied_count": summary.get("denied_count").and_then(Value::as_u64).unwrap_or(0),
            "process_count": summary.get("process_count").and_then(Value::as_u64).unwrap_or(0),
            "duration_ms": summary.get("duration_ms").and_then(Value::as_u64).unwrap_or(0),
            "network_attempt_count": summary
                .get("network_attempts")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
                .unwrap_or(0),
            "suspicious_activity_count": summary
                .get("suspicious_activity")
                .and_then(Value::as_array)
                .map(|items| items.len() as u64)
                .unwrap_or(0),
        }),
        "sbom" => json!({
            "id": base["id"],
            "kind": base["kind"],
            "upload_id": base["upload_id"],
            "uploaded_at": base["uploaded_at"],
            "org_slug": base["org_slug"],
            "project_slug": base["project_slug"],
            "actor": base["actor"],
            "environment": base["environment"],
            "tool_version": base["tool_version"],
            "git_branch": base["git_branch"],
            "git_commit": base["git_commit"],
            "repo_url": base["repo_url"],
            "format": payload.pointer("/payload/format").and_then(Value::as_str).unwrap_or_default(),
            "spec_version": payload.pointer("/payload/spec_version").and_then(Value::as_str).unwrap_or_default(),
            "component_count": payload.pointer("/payload/component_count").and_then(Value::as_u64).unwrap_or(0),
            "direct_dependency_count": payload.pointer("/payload/direct_dependency_count").and_then(Value::as_u64).unwrap_or(0),
            "manifest_source_count": payload.pointer("/payload/manifest_sources").and_then(Value::as_array).map(|items| items.len() as u64).unwrap_or(0),
            "ecosystem_counts": payload.pointer("/payload/ecosystem_counts").cloned().unwrap_or_else(|| json!({})),
            "sbom_hash": stable_sbom_hash(payload.pointer("/payload/sbom")),
        }),
        _ => base,
    }
}

fn stable_sbom_hash(sbom: Option<&Value>) -> String {
    let Some(sbom) = sbom else {
        return String::new();
    };

    let mut components = sbom
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    components.sort_by(|left, right| {
        let left_key = left
            .get("bom-ref")
            .and_then(Value::as_str)
            .or_else(|| left.get("purl").and_then(Value::as_str))
            .or_else(|| left.get("name").and_then(Value::as_str))
            .unwrap_or_default();
        let right_key = right
            .get("bom-ref")
            .and_then(Value::as_str)
            .or_else(|| right.get("purl").and_then(Value::as_str))
            .or_else(|| right.get("name").and_then(Value::as_str))
            .unwrap_or_default();
        left_key.cmp(right_key)
    });

    let mut dependencies = sbom
        .get("dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for dependency in &mut dependencies {
        if let Some(depends_on) = dependency
            .get_mut("dependsOn")
            .and_then(Value::as_array_mut)
        {
            depends_on.sort_by(|left, right| {
                left.as_str()
                    .unwrap_or_default()
                    .cmp(right.as_str().unwrap_or_default())
            });
        }
    }
    dependencies.sort_by(|left, right| {
        left.get("ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .cmp(right.get("ref").and_then(Value::as_str).unwrap_or_default())
    });

    let metadata_component = sbom
        .pointer("/metadata/component")
        .and_then(Value::as_object)
        .map(|component| {
            json!({
                "type": component.get("type").and_then(Value::as_str).unwrap_or_default(),
                "name": component.get("name").and_then(Value::as_str).unwrap_or_default(),
                "version": component.get("version").and_then(Value::as_str).unwrap_or_default(),
                "purl": component.get("purl").and_then(Value::as_str).unwrap_or_default(),
            })
        })
        .unwrap_or_else(|| json!({}));

    let normalized_dependencies = dependencies
        .into_iter()
        .map(|dependency| {
            json!({
                "dependsOn": dependency
                    .get("dependsOn")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            })
        })
        .collect::<Vec<_>>();

    let stable = json!({
        "bomFormat": sbom.get("bomFormat").and_then(Value::as_str).unwrap_or_default(),
        "specVersion": sbom.get("specVersion").and_then(Value::as_str).unwrap_or_default(),
        "metadata_component": metadata_component,
        "components": components,
        "dependencies": normalized_dependencies,
    });

    serde_json::to_vec(&stable)
        .map(|bytes| sha256_bytes_hex(&bytes))
        .unwrap_or_default()
}

fn deterministic_sbom_record_id(index_record: &Value) -> String {
    let sbom_hash = index_record
        .get("sbom_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let git_commit = index_record
        .get("git_commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let repo_url = index_record
        .get("repo_url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let fingerprint = format!("{sbom_hash}:{git_commit}:{repo_url}");
    let hash = sha256_hex(&fingerprint);
    format!("sbm_{}", &hash[..16])
}

async fn get_record(
    kind: &'static str,
    state: IngestState,
    headers: HeaderMap,
    id: String,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let index_path = state
        .storage_dir
        .join(principal.org_slug.as_str())
        .join("index")
        .join(kind)
        .join(format!("{id}.json"));
    let mut payload_path = None;
    let index = if let Some(metadata_store) = &state.metadata_store {
        match metadata_store
            .get_index_record(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                kind,
                id.as_str(),
            )
            .await
        {
            Ok(Some(value)) => {
                payload_path = match metadata_store
                    .get_payload_path(
                        principal.org_slug.as_str(),
                        principal.project_slug.as_deref(),
                        kind,
                        id.as_str(),
                    )
                    .await
                {
                    Ok(value) => value,
                    Err(error) => {
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("failed to load record payload path: {error}"),
                        )
                    }
                };
                value
            }
            Ok(None) => match read_json_file(&index_path).await {
                Ok(value) => {
                    if !principal_can_access_record(&principal, &value) {
                        return error_response(StatusCode::NOT_FOUND, "record not found");
                    }
                    value
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return error_response(StatusCode::NOT_FOUND, "record not found");
                }
                Err(error) => {
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to read record index: {error}"),
                    )
                }
            },
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to query record index: {error}"),
                )
            }
        }
    } else {
        match read_json_file(&index_path).await {
            Ok(value) => {
                if !principal_can_access_record(&principal, &value) {
                    return error_response(StatusCode::NOT_FOUND, "record not found");
                }
                value
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return error_response(StatusCode::NOT_FOUND, "record not found");
            }
            Err(error) => {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("failed to read record index: {error}"),
                )
            }
        }
    };

    let payload = match state
        .payload_store
        .read_json(
            principal.org_slug.as_str(),
            principal.project_slug.as_deref(),
            kind,
            id.as_str(),
            payload_path.as_deref(),
        )
        .await
    {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return error_response(StatusCode::NOT_FOUND, "record payload not found");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to read record payload: {error}"),
            )
        }
    };

    Json(json!({
        "status": "ok",
        "record": index,
        "payload": payload,
    }))
    .into_response()
}

async fn load_record_payload(
    state: &IngestState,
    principal: &ApiPrincipal,
    kind: &str,
    id: &str,
) -> std::io::Result<Value> {
    let payload_path = if let Some(metadata_store) = &state.metadata_store {
        metadata_store
            .get_payload_path(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                kind,
                id,
            )
            .await
            .map_err(std::io::Error::other)?
    } else {
        None
    };

    state
        .payload_store
        .read_json(
            principal.org_slug.as_str(),
            principal.project_slug.as_deref(),
            kind,
            id,
            payload_path.as_deref(),
        )
        .await
}

async fn list_records(
    kind: &'static str,
    state: IngestState,
    headers: HeaderMap,
    params: ListParams,
) -> Response {
    let principal = match authorize(&state, &headers).await {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return error_response(StatusCode::UNAUTHORIZED, "missing or invalid bearer token");
        }
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to authorize request: {error}"),
            );
        }
    };

    let limit = params.limit.unwrap_or(20).clamp(1, 100);
    let records = match load_index_records(&state, &principal, kind, Some(limit as usize)).await {
        Ok(records) => records,
        Err(error) => {
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!("failed to load index records: {error}"),
            )
        }
    };

    Json(json!({
        "status": "ok",
        "count": records.len(),
        "records": records,
    }))
    .into_response()
}

async fn load_index_records(
    state: &IngestState,
    principal: &ApiPrincipal,
    kind: &str,
    limit: Option<usize>,
) -> std::io::Result<Vec<Value>> {
    if let Some(metadata_store) = &state.metadata_store {
        return metadata_store
            .load_index_records(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                kind,
                limit,
            )
            .await
            .map_err(std::io::Error::other);
    }

    let storage_dir = state.storage_dir.as_path();
    let dir = storage_dir
        .join(principal.org_slug.as_str())
        .join("index")
        .join(kind);
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };

    let mut paths = Vec::new();
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                if entry.file_type().await.ok().is_some_and(|ft| ft.is_file()) {
                    paths.push(entry.path());
                }
            }
            Ok(None) => break,
            Err(error) => return Err(error),
        }
    }

    let mut records = Vec::new();
    for path in paths {
        let record = read_json_file(&path).await?;
        if !principal_can_access_record(principal, &record) {
            continue;
        }
        records.push(record);
    }

    records.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(right, "id").cmp(&string_field(left, "id")))
    });

    if let Some(limit) = limit {
        records.truncate(limit);
    }

    Ok(records)
}

async fn read_json_file(path: &Path) -> std::io::Result<Value> {
    let bytes = tokio::fs::read(path).await?;
    serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

fn generate_record_id(prefix: &str, upload_id: &str) -> String {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let hash = sha256_hex(upload_id);
    format!("{prefix}_{timestamp}_{}", &hash[..12])
}

fn parse_uploaded_at(value: &str) -> Option<chrono::DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.with_timezone(&Utc))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::trim)
}

fn generate_api_key(org_slug: &str, project_slug: Option<&str>) -> String {
    let scope = api_key_label_parts(org_slug, project_slug)
        .replace('/', "_")
        .replace(|c: char| !c.is_ascii_alphanumeric() && c != '_', "-");
    format!("st_{scope}_{}", uuid::Uuid::new_v4().simple())
}

fn principal_can_access_record(principal: &ApiPrincipal, record: &Value) -> bool {
    if record.get("org_slug").and_then(Value::as_str) != Some(principal.org_slug.as_str()) {
        return false;
    }

    match principal.project_slug.as_deref() {
        Some(project_slug) if !project_slug.is_empty() => {
            record.get("project_slug").and_then(Value::as_str) == Some(project_slug)
        }
        _ => true,
    }
}

fn string_field(record: &Value, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn optional_string_field(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn blank_string_as_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn row_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| blank_string_as_none(&value))
}

fn generate_lowercase_ulid() -> String {
    Ulid::new().to_string().to_lowercase()
}

fn resolve_project_filter(
    principal: &ApiPrincipal,
    requested_project_slug: Option<&str>,
) -> Result<Option<String>, Response> {
    match principal.project_slug.as_deref() {
        Some(project_slug) => {
            if requested_project_slug.is_some_and(|requested| requested != project_slug) {
                Err(error_response(
                    StatusCode::FORBIDDEN,
                    "project-scoped api key cannot access a different project",
                ))
            } else {
                Ok(Some(project_slug.to_string()))
            }
        }
        None => Ok(requested_project_slug
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)),
    }
}

fn sbom_security_alert_matches_filters(
    alert: &Value,
    project_slug: Option<&str>,
    kind: Option<&str>,
    from_git_commit: Option<&str>,
    to_git_commit: Option<&str>,
    package_identity: Option<&str>,
) -> bool {
    project_slug.is_none_or(|expected| {
        alert
            .get("project_slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == expected
    }) && kind.is_none_or(|expected| {
        alert
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == expected
    }) && from_git_commit.is_none_or(|expected| {
        alert
            .get("from_git_commit")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == expected
    }) && to_git_commit.is_none_or(|expected| {
        alert
            .get("to_git_commit")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == expected
    }) && package_identity.is_none_or(|expected| {
        alert
            .pointer("/package/identity")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == expected
    })
}

fn summarize_sbom_security_alerts(alerts: &[Value], cache_stats: Option<OsvCacheStats>) -> Value {
    let new_vulnerable_direct_package_count = alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("new_vulnerable_direct_package")
        })
        .count();
    let vulnerable_direct_version_change_count = alerts
        .iter()
        .filter(|alert| {
            alert.get("kind").and_then(Value::as_str) == Some("vulnerable_direct_version_change")
        })
        .count();
    let affected_package_count = alerts
        .iter()
        .filter_map(|alert| {
            alert
                .pointer("/package/identity")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .len();

    let mut summary = json!({
        "alert_count": alerts.len(),
        "affected_package_count": affected_package_count,
        "new_vulnerable_direct_package_count": new_vulnerable_direct_package_count,
        "vulnerable_direct_version_change_count": vulnerable_direct_version_change_count,
    });
    if let Some(stats) = cache_stats {
        summary["cache_hits"] = json!(stats.cache_hits);
        summary["fresh_queries"] = json!(stats.fresh_queries);
    }
    summary
}

async fn load_sbom_packages_for_record(
    state: &IngestState,
    principal: &ApiPrincipal,
    record_id: &str,
) -> std::io::Result<Vec<SbomPackage>> {
    if let Some(metadata_store) = &state.metadata_store {
        match metadata_store
            .load_sbom_packages(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                record_id,
            )
            .await
        {
            Ok(packages) if !packages.is_empty() => return Ok(packages),
            Ok(_) => {}
            Err(error) => return Err(std::io::Error::other(error)),
        }
    }

    let payload = load_record_payload(state, principal, "sbom", record_id).await?;
    Ok(extract_sbom_packages(payload.pointer("/payload/sbom")))
}

async fn build_recent_sbom_alerts(
    state: &IngestState,
    principal: &ApiPrincipal,
    sbom_records: &[Value],
    limit: usize,
) -> std::io::Result<Vec<Value>> {
    let mut projects = BTreeMap::<String, Vec<&Value>>::new();
    for record in sbom_records {
        let project_key = record
            .get("project_slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        projects.entry(project_key).or_default().push(record);
    }

    let mut alerts = Vec::new();
    for records in projects.values() {
        if records.len() < 2 {
            continue;
        }

        let to_record = records[0];
        let from_record = match records
            .iter()
            .copied()
            .find(|record| record.get("git_commit") != to_record.get("git_commit"))
        {
            Some(record) => record,
            None => continue,
        };
        alerts.extend(build_sbom_alerts_for_pair(state, principal, from_record, to_record).await?);
    }

    alerts.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(left, "kind").cmp(&string_field(right, "kind")))
            .then_with(|| {
                string_field(left.get("package").unwrap_or(&Value::Null), "name").cmp(
                    &string_field(right.get("package").unwrap_or(&Value::Null), "name"),
                )
            })
    });
    alerts.truncate(limit);
    Ok(alerts)
}

async fn build_sbom_alerts_for_pair(
    state: &IngestState,
    principal: &ApiPrincipal,
    from_record: &Value,
    to_record: &Value,
) -> std::io::Result<Vec<Value>> {
    let from_id = string_field(from_record, "id");
    let to_id = string_field(to_record, "id");
    let from_packages = load_sbom_packages_for_record(state, principal, &from_id).await?;
    let to_packages = load_sbom_packages_for_record(state, principal, &to_id).await?;
    let from_by_identity = from_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let to_by_identity = to_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();

    let mut alerts = Vec::new();
    for (identity, to_package) in &to_by_identity {
        match from_by_identity.get(identity) {
            None if to_package.direct => alerts.push(json!({
                "kind": "new_direct_package",
                "project_slug": to_record.get("project_slug").cloned().unwrap_or(Value::Null),
                "from_sbom_id": from_id,
                "to_sbom_id": to_id,
                "from_git_commit": from_record.get("git_commit").cloned().unwrap_or(Value::Null),
                "to_git_commit": to_record.get("git_commit").cloned().unwrap_or(Value::Null),
                "uploaded_at": to_record.get("uploaded_at").cloned().unwrap_or(Value::Null),
                "package": sbom_package_json(to_package),
            })),
            Some(from_package)
                if to_package.direct && from_package.version != to_package.version =>
            {
                alerts.push(json!({
                    "kind": "direct_version_change",
                    "project_slug": to_record.get("project_slug").cloned().unwrap_or(Value::Null),
                    "from_sbom_id": from_id,
                    "to_sbom_id": to_id,
                    "from_git_commit": from_record.get("git_commit").cloned().unwrap_or(Value::Null),
                    "to_git_commit": to_record.get("git_commit").cloned().unwrap_or(Value::Null),
                    "uploaded_at": to_record.get("uploaded_at").cloned().unwrap_or(Value::Null),
                    "package": {
                        "identity": to_package.identity,
                        "ecosystem": to_package.ecosystem,
                        "name": to_package.name,
                        "purl": to_package.purl,
                        "direct": true,
                        "from_version": from_package.version,
                        "to_version": to_package.version,
                    },
                }));
            }
            _ => {}
        }
    }

    alerts.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(left, "kind").cmp(&string_field(right, "kind")))
            .then_with(|| {
                string_field(left.get("package").unwrap_or(&Value::Null), "name").cmp(
                    &string_field(right.get("package").unwrap_or(&Value::Null), "name"),
                )
            })
    });
    Ok(alerts)
}

async fn build_recent_sbom_security_alerts(
    state: &IngestState,
    principal: &ApiPrincipal,
    sbom_records: &[Value],
    limit: usize,
) -> anyhow::Result<(Vec<Value>, OsvCacheStats)> {
    let mut projects = BTreeMap::<String, Vec<&Value>>::new();
    for record in sbom_records {
        let project_key = record
            .get("project_slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        projects.entry(project_key).or_default().push(record);
    }

    let mut alerts = Vec::new();
    let mut cache_stats = OsvCacheStats::default();
    for records in projects.values() {
        if records.len() < 2 {
            continue;
        }

        let to_record = records[0];
        let from_record = match records
            .iter()
            .copied()
            .find(|record| record.get("git_commit") != to_record.get("git_commit"))
        {
            Some(record) => record,
            None => continue,
        };

        let (project_alerts, stats) =
            build_sbom_security_alerts_for_pair(state, principal, from_record, to_record).await?;
        cache_stats.cache_hits += stats.cache_hits;
        cache_stats.fresh_queries += stats.fresh_queries;
        alerts.extend(project_alerts);
    }

    alerts.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(left, "kind").cmp(&string_field(right, "kind")))
            .then_with(|| {
                string_field(left.get("package").unwrap_or(&Value::Null), "name").cmp(
                    &string_field(right.get("package").unwrap_or(&Value::Null), "name"),
                )
            })
    });
    alerts.truncate(limit);
    Ok((alerts, cache_stats))
}

async fn backfill_sbom_security_alert_history(
    state: &IngestState,
    principal: &ApiPrincipal,
    sbom_records: &[Value],
) -> anyhow::Result<OsvCacheStats> {
    let Some(metadata_store) = &state.metadata_store else {
        return Ok(OsvCacheStats::default());
    };

    let mut projects = BTreeMap::<String, Vec<&Value>>::new();
    for record in sbom_records {
        let project_key = record
            .get("project_slug")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        projects.entry(project_key).or_default().push(record);
    }

    let mut cache_stats = OsvCacheStats::default();
    for records in projects.values() {
        for (index, to_record) in records.iter().enumerate() {
            let to_id = string_field(to_record, "id");
            let from_record = records
                .iter()
                .skip(index + 1)
                .copied()
                .find(|record| record.get("git_commit") != to_record.get("git_commit"));

            let alerts = if let Some(from_record) = from_record {
                let (alerts, stats) =
                    build_sbom_security_alerts_for_pair(state, principal, from_record, to_record)
                        .await?;
                cache_stats.cache_hits += stats.cache_hits;
                cache_stats.fresh_queries += stats.fresh_queries;
                alerts
            } else {
                Vec::new()
            };

            metadata_store
                .replace_sbom_security_alerts(
                    principal.org_slug.as_str(),
                    principal.project_slug.as_deref(),
                    &to_id,
                    &alerts,
                )
                .await?;
        }
    }

    Ok(cache_stats)
}

async fn load_or_build_recent_sbom_security_alerts(
    state: &IngestState,
    principal: &ApiPrincipal,
    sbom_records: &[Value],
    limit: usize,
) -> anyhow::Result<(Vec<Value>, OsvCacheStats)> {
    if let Some(metadata_store) = &state.metadata_store {
        let mut alerts = metadata_store
            .load_recent_sbom_security_alerts(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                limit,
            )
            .await?;
        if alerts.is_empty() {
            let backfill_stats =
                backfill_sbom_security_alert_history(state, principal, sbom_records).await?;
            alerts = metadata_store
                .load_recent_sbom_security_alerts(
                    principal.org_slug.as_str(),
                    principal.project_slug.as_deref(),
                    limit,
                )
                .await?;
            if !alerts.is_empty() {
                return Ok((alerts, backfill_stats));
            }
        }
        if !alerts.is_empty() {
            return Ok((alerts, OsvCacheStats::default()));
        }
    }

    build_recent_sbom_security_alerts(state, principal, sbom_records, limit).await
}

async fn persist_sbom_security_alerts_for_record(
    state: &IngestState,
    principal: &ApiPrincipal,
    current_record_id: &str,
) -> anyhow::Result<()> {
    let Some(metadata_store) = &state.metadata_store else {
        return Ok(());
    };

    let sbom_records = load_index_records(state, principal, "sbom", None).await?;
    let Some(to_record) = sbom_records
        .iter()
        .find(|record| record.get("id").and_then(Value::as_str) == Some(current_record_id))
    else {
        return Ok(());
    };
    let Some(from_record) = resolve_sbom_base_record(&sbom_records, to_record, None, None) else {
        metadata_store
            .replace_sbom_security_alerts(
                principal.org_slug.as_str(),
                principal.project_slug.as_deref(),
                current_record_id,
                &[],
            )
            .await?;
        return Ok(());
    };

    let (alerts, _) =
        build_sbom_security_alerts_for_pair(state, principal, from_record, to_record).await?;
    metadata_store
        .replace_sbom_security_alerts(
            principal.org_slug.as_str(),
            principal.project_slug.as_deref(),
            current_record_id,
            &alerts,
        )
        .await?;
    Ok(())
}

async fn build_sbom_security_alerts_for_pair(
    state: &IngestState,
    principal: &ApiPrincipal,
    from_record: &Value,
    to_record: &Value,
) -> anyhow::Result<(Vec<Value>, OsvCacheStats)> {
    let from_id = string_field(from_record, "id");
    let to_id = string_field(to_record, "id");
    let from_packages = load_sbom_packages_for_record(state, principal, &from_id).await?;
    let to_packages = load_sbom_packages_for_record(state, principal, &to_id).await?;
    let from_by_identity = from_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();
    let to_by_identity = to_packages
        .into_iter()
        .map(|package| (package.identity.clone(), package))
        .collect::<BTreeMap<_, _>>();

    let relevant_packages = to_by_identity
        .iter()
        .filter_map(
            |(identity, to_package)| match from_by_identity.get(identity) {
                None if to_package.direct => Some(to_package.clone()),
                Some(from_package)
                    if to_package.direct && from_package.version != to_package.version =>
                {
                    Some(to_package.clone())
                }
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    if relevant_packages.is_empty() {
        return Ok((Vec::new(), OsvCacheStats::default()));
    }

    let (advisory_results, cache_stats) =
        query_osv_advisories(state, &relevant_packages, relevant_packages.len()).await?;
    let advisories_by_identity = advisory_results
        .into_iter()
        .map(|result| (string_field(&result, "identity"), result))
        .collect::<BTreeMap<_, _>>();

    let mut alerts = Vec::new();
    for (identity, to_package) in &to_by_identity {
        let Some(advisory) = advisories_by_identity.get(identity) else {
            continue;
        };
        let vulnerability_count = advisory
            .get("vulnerability_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if vulnerability_count == 0 {
            continue;
        }

        match from_by_identity.get(identity) {
            None if to_package.direct => alerts.push(json!({
                "kind": "new_vulnerable_direct_package",
                "project_slug": to_record.get("project_slug").cloned().unwrap_or(Value::Null),
                "from_sbom_id": from_id,
                "to_sbom_id": to_id,
                "from_git_commit": from_record.get("git_commit").cloned().unwrap_or(Value::Null),
                "to_git_commit": to_record.get("git_commit").cloned().unwrap_or(Value::Null),
                "uploaded_at": to_record.get("uploaded_at").cloned().unwrap_or(Value::Null),
                "package": advisory,
            })),
            Some(from_package)
                if to_package.direct && from_package.version != to_package.version =>
            {
                alerts.push(json!({
                    "kind": "vulnerable_direct_version_change",
                    "project_slug": to_record.get("project_slug").cloned().unwrap_or(Value::Null),
                    "from_sbom_id": from_id,
                    "to_sbom_id": to_id,
                    "from_git_commit": from_record.get("git_commit").cloned().unwrap_or(Value::Null),
                    "to_git_commit": to_record.get("git_commit").cloned().unwrap_or(Value::Null),
                    "uploaded_at": to_record.get("uploaded_at").cloned().unwrap_or(Value::Null),
                    "package": {
                        "identity": advisory.get("identity").cloned().unwrap_or(Value::Null),
                        "ecosystem": advisory.get("ecosystem").cloned().unwrap_or(Value::Null),
                        "name": advisory.get("name").cloned().unwrap_or(Value::Null),
                        "purl": advisory.get("purl").cloned().unwrap_or(Value::Null),
                        "direct": true,
                        "from_version": from_package.version,
                        "to_version": advisory.get("version").cloned().unwrap_or(Value::Null),
                        "vulnerability_count": advisory.get("vulnerability_count").cloned().unwrap_or(Value::Null),
                        "vulnerabilities": advisory.get("vulnerabilities").cloned().unwrap_or_else(|| json!([])),
                    },
                }));
            }
            _ => {}
        }
    }

    alerts.sort_by(|left, right| {
        string_field(right, "uploaded_at")
            .cmp(&string_field(left, "uploaded_at"))
            .then_with(|| string_field(left, "kind").cmp(&string_field(right, "kind")))
            .then_with(|| {
                string_field(left.get("package").unwrap_or(&Value::Null), "name").cmp(
                    &string_field(right.get("package").unwrap_or(&Value::Null), "name"),
                )
            })
    });
    Ok((alerts, cache_stats))
}

async fn query_osv_advisories(
    state: &IngestState,
    packages: &[SbomPackage],
    limit: usize,
) -> anyhow::Result<(Vec<Value>, OsvCacheStats)> {
    let client = reqwest::Client::new();
    let selected_packages = packages.iter().take(limit).collect::<Vec<_>>();
    if selected_packages.is_empty() {
        return Ok((Vec::new(), OsvCacheStats::default()));
    }

    let freshness_cutoff = Utc::now() - chrono::Duration::hours(state.osv_cache_ttl_hours);
    let mut stats = OsvCacheStats::default();
    let mut packages_with_results = Vec::new();
    let mut uncached_packages = Vec::new();

    for package in &selected_packages {
        let query_key = osv_query_key(package);
        if let Some(metadata_store) = &state.metadata_store {
            if let Some(result) = metadata_store
                .load_osv_cache_entry(&query_key, freshness_cutoff)
                .await?
            {
                stats.cache_hits += 1;
                packages_with_results.push(result);
                continue;
            }
        }
        uncached_packages.push((query_key, *package));
    }

    if !uncached_packages.is_empty() {
        let queries = uncached_packages
            .iter()
            .map(|(_, package)| build_osv_query(package))
            .collect::<Vec<_>>();
        let response = client
            .post(format!(
                "{}/v1/querybatch",
                state.osv_api_url.trim_end_matches('/')
            ))
            .json(&json!({ "queries": queries }))
            .send()
            .await?
            .error_for_status()?;
        let body: Value = response.json().await?;
        let results = body
            .get("results")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();

        for (index, (query_key, package)) in uncached_packages.into_iter().enumerate() {
            let result = results.get(index).cloned().unwrap_or_else(|| json!({}));
            let advisory_result = normalize_osv_result(package, &result);
            if let Some(metadata_store) = &state.metadata_store {
                metadata_store
                    .store_osv_cache_entry(&query_key, package, &advisory_result)
                    .await?;
            }
            stats.fresh_queries += 1;
            packages_with_results.push(advisory_result);
        }
    }

    packages_with_results.sort_by(|left, right| {
        right
            .get("vulnerability_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .cmp(
                &left
                    .get("vulnerability_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
            )
            .then_with(|| string_field(left, "name").cmp(&string_field(right, "name")))
    });
    Ok((packages_with_results, stats))
}

fn normalize_osv_result(package: &SbomPackage, result: &Value) -> Value {
    let mut vulnerabilities = result
        .get("vulns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|vuln| {
            vuln.get("id").and_then(Value::as_str).map(|id| {
                json!({
                    "id": id,
                    "modified": vuln.get("modified").cloned().unwrap_or(Value::Null),
                })
            })
        })
        .collect::<Vec<_>>();
    vulnerabilities.sort_by(|left, right| string_field(left, "id").cmp(&string_field(right, "id")));

    json!({
        "identity": package.identity,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "version": package.version,
        "purl": package.purl,
        "direct": package.direct,
        "vulnerability_count": vulnerabilities.len(),
        "vulnerabilities": vulnerabilities,
    })
}

fn build_osv_query(package: &SbomPackage) -> Value {
    if let Some(purl) = package.purl.as_deref() {
        let mut query = json!({
            "package": {
                "purl": strip_purl_version(purl),
            }
        });
        if let Some(version) = blank_string_as_none(&package.version) {
            query["version"] = json!(version);
        }
        return query;
    }

    let ecosystem = osv_ecosystem(&package.ecosystem).unwrap_or_else(|| package.ecosystem.clone());
    let mut query = json!({
        "package": {
            "name": package.name,
            "ecosystem": ecosystem,
        }
    });
    if let Some(version) = blank_string_as_none(&package.version) {
        query["version"] = json!(version);
    }
    query
}

fn strip_purl_version(purl: &str) -> String {
    let without_fragment = purl.split('#').next().unwrap_or(purl);
    let (base, query) = without_fragment
        .split_once('?')
        .map(|(base, query)| (base, Some(query)))
        .unwrap_or((without_fragment, None));
    let stripped_base = base.rfind('@').map(|index| &base[..index]).unwrap_or(base);

    match query {
        Some(query) => format!("{stripped_base}?{query}"),
        None => stripped_base.to_string(),
    }
}

fn osv_query_key(package: &SbomPackage) -> String {
    let query = build_osv_query(package);
    let serialized = serde_json::to_vec(&query).unwrap_or_default();
    sha256_bytes_hex(&serialized)
}

fn osv_ecosystem(ecosystem: &str) -> Option<String> {
    Some(
        match ecosystem {
            "cargo" => "crates.io",
            "npm" => "npm",
            "pypi" => "PyPI",
            "golang" => "Go",
            "nuget" => "NuGet",
            "gem" => "RubyGems",
            "composer" => "Packagist",
            "maven" => "Maven",
            "hex" => "Hex",
            other if !other.is_empty() => other,
            _ => return None,
        }
        .to_string(),
    )
}

fn resolve_sbom_record<'a>(
    records: &'a [Value],
    sbom_id: Option<&str>,
    git_commit: Option<&str>,
) -> Option<&'a Value> {
    if let Some(sbom_id) = sbom_id {
        return records
            .iter()
            .find(|record| record.get("id").and_then(Value::as_str) == Some(sbom_id));
    }

    if let Some(git_commit) = git_commit {
        return records
            .iter()
            .find(|record| record.get("git_commit").and_then(Value::as_str) == Some(git_commit));
    }

    records.first()
}

fn resolve_sbom_base_record<'a>(
    records: &'a [Value],
    to_record: &Value,
    from_sbom_id: Option<&str>,
    from_commit: Option<&str>,
) -> Option<&'a Value> {
    if let Some(record) = resolve_sbom_record(records, from_sbom_id, from_commit) {
        return Some(record);
    }

    let to_id = to_record
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let to_commit = to_record
        .get("git_commit")
        .and_then(Value::as_str)
        .unwrap_or_default();

    records.iter().find(|record| {
        record.get("id").and_then(Value::as_str) != Some(to_id)
            && record.get("git_commit").and_then(Value::as_str) != Some(to_commit)
    })
}

fn extract_sbom_packages(sbom: Option<&Value>) -> Vec<SbomPackage> {
    let Some(sbom) = sbom else {
        return Vec::new();
    };

    let root_ref = sbom
        .pointer("/metadata/component/bom-ref")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            sbom.pointer("/metadata/component/purl")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let direct_refs = root_ref
        .as_deref()
        .and_then(|root_ref| {
            sbom.get("dependencies")
                .and_then(Value::as_array)
                .and_then(|dependencies| {
                    dependencies.iter().find(|dependency| {
                        dependency.get("ref").and_then(Value::as_str) == Some(root_ref)
                    })
                })
        })
        .and_then(|dependency| dependency.get("dependsOn").and_then(Value::as_array))
        .map(|depends_on| {
            depends_on
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    sbom.get("components")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|component| {
            let bom_ref = component
                .get("bom-ref")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let purl = component
                .get("purl")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            let name = component
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let version = component
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let ecosystem = component
                .pointer("/properties")
                .and_then(Value::as_array)
                .and_then(|properties| {
                    properties.iter().find_map(|property| {
                        (property.get("name").and_then(Value::as_str)
                            == Some("sandtrace:ecosystem"))
                        .then(|| {
                            property
                                .get("value")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string()
                        })
                    })
                })
                .or_else(|| purl.as_deref().and_then(purl_type))
                .unwrap_or_else(|| "unknown".to_string());
            let identity = purl
                .as_deref()
                .map(purl_identity)
                .unwrap_or_else(|| format!("{ecosystem}:{name}"));

            SbomPackage {
                bom_ref: bom_ref.clone(),
                identity,
                ecosystem,
                name,
                version,
                purl: purl.clone(),
                package_type: component
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                direct: direct_refs.contains(&bom_ref)
                    || purl
                        .as_deref()
                        .is_some_and(|purl| direct_refs.contains(purl)),
            }
        })
        .collect()
}

fn purl_type(purl: &str) -> Option<String> {
    purl.strip_prefix("pkg:")
        .and_then(|rest| rest.split('/').next())
        .map(ToOwned::to_owned)
}

fn purl_identity(purl: &str) -> String {
    let without_fragment = purl.split('#').next().unwrap_or(purl);
    let (base, query) = without_fragment
        .split_once('?')
        .map(|(base, query)| (base, Some(query)))
        .unwrap_or((without_fragment, None));
    let stripped_base = base
        .rfind('@')
        .map(|index| &base[..index])
        .unwrap_or(base)
        .to_string();

    match query {
        Some(query) => format!("{stripped_base}?{query}"),
        None => stripped_base,
    }
}

fn sbom_package_json(package: &SbomPackage) -> Value {
    json!({
        "bom_ref": package.bom_ref,
        "identity": package.identity,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "version": package.version,
        "purl": package.purl,
        "type": package.package_type,
        "direct": package.direct,
    })
}

fn sbom_package_sort_key(left: &Value, right: &Value) -> std::cmp::Ordering {
    string_field(left, "ecosystem")
        .cmp(&string_field(right, "ecosystem"))
        .then_with(|| string_field(left, "name").cmp(&string_field(right, "name")))
        .then_with(|| string_field(left, "version").cmp(&string_field(right, "version")))
}

fn api_key_label(principal: &ApiPrincipal) -> String {
    api_key_label_parts(&principal.org_slug, principal.project_slug.as_deref())
}

fn api_key_label_parts(org_slug: &str, project_slug: Option<&str>) -> String {
    match project_slug {
        Some(project_slug) if !project_slug.is_empty() => format!("{org_slug}/{project_slug}"),
        _ => org_slug.to_string(),
    }
}

fn sha256_hex(input: &str) -> String {
    sha256_bytes_hex(input.as_bytes())
}

fn sha256_bytes_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "status": "error",
            "error": message,
        })),
    )
        .into_response()
}

#[derive(Debug, Default, Deserialize)]
struct ListParams {
    limit: Option<u32>,
}

/// Trace the shortest dependency path from root to a target package.
///
/// Given a CycloneDX SBOM `dependencies` array:
/// ```json
/// [{"ref": "root", "dependsOn": ["A"]}, {"ref": "A", "dependsOn": ["B"]}]
/// ```
/// Returns the path from root to target as a vec of bom-refs: `["root", "A", "B"]`.
fn trace_dependency_path(sbom: &Value, target_bom_ref: &str) -> Vec<String> {
    let dependencies = match sbom.get("dependencies").and_then(Value::as_array) {
        Some(deps) => deps,
        None => return Vec::new(),
    };

    // Build forward adjacency map: parent -> [children]
    let mut forward: HashMap<String, Vec<String>> = HashMap::new();
    for dep in dependencies {
        let parent = match dep.get("ref").and_then(Value::as_str) {
            Some(r) => r.to_string(),
            None => continue,
        };
        let children: Vec<String> = dep
            .get("dependsOn")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect();
        forward.insert(parent, children);
    }

    // Find root ref (from metadata/component/bom-ref)
    let root_ref = sbom
        .pointer("/metadata/component/bom-ref")
        .and_then(Value::as_str)
        .or_else(|| {
            sbom.pointer("/metadata/component/purl")
                .and_then(Value::as_str)
        })
        .unwrap_or_default()
        .to_string();

    if root_ref.is_empty() || target_bom_ref.is_empty() {
        return Vec::new();
    }

    if root_ref == target_bom_ref {
        return vec![root_ref];
    }

    // BFS from root to target
    let mut queue = std::collections::VecDeque::new();
    let mut parent_map: HashMap<String, String> = HashMap::new();
    queue.push_back(root_ref.clone());
    parent_map.insert(root_ref.clone(), String::new());

    while let Some(current) = queue.pop_front() {
        if current == target_bom_ref {
            // Reconstruct path
            let mut path = Vec::new();
            let mut node = target_bom_ref.to_string();
            while !node.is_empty() {
                path.push(node.clone());
                node = parent_map.get(&node).cloned().unwrap_or_default();
            }
            path.reverse();
            return path;
        }

        if let Some(children) = forward.get(&current) {
            for child in children {
                if !parent_map.contains_key(child) {
                    parent_map.insert(child.clone(), current.clone());
                    queue.push_back(child.clone());
                }
            }
        }
    }

    Vec::new() // No path found
}

/// Enrich advisory results with dependency paths from the SBOM.
fn enrich_advisories_with_paths(advisory_results: &mut [Value], sbom: &Value) {
    for result in advisory_results.iter_mut() {
        let vuln_count = result
            .get("vulnerability_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        if vuln_count == 0 {
            continue;
        }

        let bom_ref = result
            .get("bom_ref")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if bom_ref.is_empty() {
            continue;
        }

        let path = trace_dependency_path(sbom, &bom_ref);
        if !path.is_empty() {
            result["dependency_path"] = json!(path);
            result["dependency_depth"] = json!(path.len() - 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{self, Body};
    use axum::http::Request;
    use axum::routing::post;
    use tempfile::tempdir;
    use tower::util::ServiceExt;

    fn test_state() -> IngestState {
        let dir = tempdir().unwrap();
        let storage_dir = dir.keep();
        IngestState {
            principals: Arc::new(HashMap::from([
                (
                    String::from("test-key"),
                    ApiPrincipal {
                        api_key: String::from("test-key"),
                        org_slug: String::from("acme"),
                        project_slug: Some(String::from("web")),
                        actor: Some(String::from("ci")),
                    },
                ),
                (
                    String::from("other-key"),
                    ApiPrincipal {
                        api_key: String::from("other-key"),
                        org_slug: String::from("other"),
                        project_slug: Some(String::from("api")),
                        actor: Some(String::from("ci")),
                    },
                ),
                (
                    String::from("ops-key"),
                    ApiPrincipal {
                        api_key: String::from("ops-key"),
                        org_slug: String::from("acme"),
                        project_slug: Some(String::from("ops")),
                        actor: Some(String::from("ci")),
                    },
                ),
                (
                    String::from("org-key"),
                    ApiPrincipal {
                        api_key: String::from("org-key"),
                        org_slug: String::from("acme"),
                        project_slug: None,
                        actor: Some(String::from("ci")),
                    },
                ),
            ])),
            storage_dir: Arc::new(storage_dir.clone()),
            payload_store: Arc::new(PayloadStore::Filesystem {
                root: storage_dir.clone(),
            }),
            metadata_store: None,
            admin_token: Some(String::from("admin-token")),
            admin_subject: String::from("admin-token"),
            osv_api_url: Arc::new(String::from("http://127.0.0.1:65535")),
            osv_cache_ttl_hours: 24,
        }
    }

    async fn spawn_osv_mock(response: Value) -> String {
        let app = Router::new().route(
            "/v1/querybatch",
            post(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn auth_request(uri: &str, body: Value) -> Request<Body> {
        auth_request_with_token(uri, "test-key", body)
    }

    fn auth_request_with_token(uri: &str, token: &str, body: Value) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    fn admin_request(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer admin-token")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn health_endpoint_works() {
        let response = app(test_state())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_api_keys_require_database() {
        let response = app(test_state())
            .oneshot(admin_request("/v1/admin/api-keys"))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn admin_api_keys_require_admin_token() {
        let request = Request::builder()
            .uri("/v1/admin/api-keys")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app(test_state()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn audit_ingest_persists_payload() {
        let state = test_state();
        let storage_dir = state.storage_dir.clone();
        let payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_test123",
            "tool": { "command": "audit" },
            "payload": { "summary": { "total": 0 } }
        });

        let response = app(state)
            .oneshot(auth_request("/v1/ingest/audit", payload))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let mut entries = std::fs::read_dir(storage_dir.join("acme").join("audit"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(entries.len(), 1);
        let contents = std::fs::read_to_string(entries.pop().unwrap().path()).unwrap();
        assert!(contents.contains("\"upload_id\": \"upl_test123\""));

        let index_entries = std::fs::read_dir(storage_dir.join("acme").join("index").join("audit"))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(index_entries.len(), 1);
    }

    #[tokio::test]
    async fn ingest_requires_bearer_auth() {
        let payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_test123",
            "tool": { "command": "run" },
            "payload": { "summary": { "exit_code": 0 } }
        });

        let request = Request::builder()
            .uri("/v1/ingest/run")
            .method("POST")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let response = app(test_state()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ingest_validates_command_kind() {
        let payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_test123",
            "tool": { "command": "audit" },
            "payload": { "summary": { "exit_code": 0 } }
        });

        let response = app(test_state())
            .oneshot(auth_request("/v1/ingest/run", payload))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_and_get_audit_records() {
        let state = test_state();
        let app = app(state.clone());
        let payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_test123",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "file_count": 12,
                "duration_ms": 42,
                "summary": { "total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/audit", payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let accepted: Value = serde_json::from_slice(&body).unwrap();
        let record_id = accepted["audit_id"].as_str().unwrap().to_string();

        let list_request = Request::builder()
            .uri("/v1/ingest/audits?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(1));
        assert_eq!(
            listed["records"][0]["id"].as_str(),
            Some(record_id.as_str())
        );

        let get_request = Request::builder()
            .uri(format!("/v1/ingest/audit/{record_id}"))
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let get_response = app.oneshot(get_request).await.unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let fetched: Value = serde_json::from_slice(&get_body).unwrap();
        assert_eq!(fetched["record"]["id"].as_str(), Some(record_id.as_str()));
        assert_eq!(
            fetched["payload"]["upload_id"].as_str(),
            Some("upl_test123")
        );
    }

    #[tokio::test]
    async fn list_and_get_sbom_records() {
        let state = test_state();
        let app = app(state.clone());
        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 42,
                "direct_dependency_count": 4,
                "manifest_sources": ["package-lock.json", "uv.lock"],
                "ecosystem_counts": { "npm": 30, "pypi": 12 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [],
                    "dependencies": []
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let accepted: Value = serde_json::from_slice(&body).unwrap();
        let record_id = accepted["sbom_id"].as_str().unwrap().to_string();

        let list_request = Request::builder()
            .uri("/v1/ingest/sboms?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(1));
        assert_eq!(listed["records"][0]["component_count"].as_u64(), Some(42));

        let get_request = Request::builder()
            .uri(format!("/v1/ingest/sbom/{record_id}"))
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let get_response = app.oneshot(get_request).await.unwrap();
        assert_eq!(get_response.status(), StatusCode::OK);
        let get_body = axum::body::to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let fetched: Value = serde_json::from_slice(&get_body).unwrap();
        assert_eq!(fetched["record"]["id"].as_str(), Some(record_id.as_str()));
        assert_eq!(
            fetched["record"]["ecosystem_counts"]["npm"].as_u64(),
            Some(30)
        );
    }

    #[tokio::test]
    async fn duplicate_sboms_return_existing_record() {
        let state = test_state();
        let app = app(state.clone());
        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_dup_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 42,
                "direct_dependency_count": 4,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 42 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "serialNumber": "urn:uuid:first",
                    "specVersion": "1.5",
                    "metadata": {
                        "timestamp": "2026-03-13T01:00:00Z",
                        "component": {
                            "type": "application",
                            "bom-ref": "urn:uuid:root",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1", "type": "library" }
                    ],
                    "dependencies": []
                }
            }
        });

        let first_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload.clone()))
            .await
            .unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = axum::body::to_bytes(first_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_json: Value = serde_json::from_slice(&first_body).unwrap();
        let first_id = first_json["sbom_id"].as_str().unwrap().to_string();
        assert_eq!(first_json["status"].as_str(), Some("accepted"));

        let mut duplicate_payload = payload.clone();
        duplicate_payload["upload_id"] = json!("upl_sbom_dup_2");
        duplicate_payload["payload"]["sbom"]["serialNumber"] = json!("urn:uuid:second");
        duplicate_payload["payload"]["sbom"]["metadata"]["timestamp"] =
            json!("2026-03-13T01:05:00Z");

        let duplicate_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", duplicate_payload))
            .await
            .unwrap();
        assert_eq!(duplicate_response.status(), StatusCode::OK);
        let duplicate_body = axum::body::to_bytes(duplicate_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let duplicate_json: Value = serde_json::from_slice(&duplicate_body).unwrap();
        assert_eq!(duplicate_json["status"].as_str(), Some("duplicate"));
        assert_eq!(duplicate_json["sbom_id"].as_str(), Some(first_id.as_str()));

        let list_request = Request::builder()
            .uri("/v1/ingest/sboms?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(1));

        let overview_request = Request::builder()
            .uri("/v1/dashboard/overview?limit=5")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let overview_response = app.oneshot(overview_request).await.unwrap();
        let overview_body = axum::body::to_bytes(overview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&overview_body).unwrap();
        assert_eq!(overview["summary"]["sbom_uploads"].as_u64(), Some(1));
        assert_eq!(
            overview["summary"]["total_sbom_components"].as_u64(),
            Some(42)
        );
    }

    #[tokio::test]
    async fn sboms_with_same_repo_but_different_commits_are_not_duplicates() {
        let state = test_state();
        let app = app(state.clone());
        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_repo_commit_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 1,
                "direct_dependency_count": 1,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 1 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1", "type": "library" }
                    ],
                    "dependencies": []
                }
            }
        });

        let first_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload.clone()))
            .await
            .unwrap();
        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = axum::body::to_bytes(first_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let first_json: Value = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(first_json["status"].as_str(), Some("accepted"));

        let mut second_payload = base_payload;
        second_payload["upload_id"] = json!("upl_sbom_repo_commit_2");
        second_payload["project"]["git_commit"] = json!("def456");

        let second_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", second_payload))
            .await
            .unwrap();
        assert_eq!(second_response.status(), StatusCode::OK);
        let second_body = axum::body::to_bytes(second_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let second_json: Value = serde_json::from_slice(&second_body).unwrap();
        assert_eq!(second_json["status"].as_str(), Some("accepted"));
        assert_ne!(second_json["sbom_id"], first_json["sbom_id"]);

        let list_request = Request::builder()
            .uri("/v1/ingest/sboms?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.oneshot(list_request).await.unwrap();
        let list_body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&list_body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(2));
    }

    #[tokio::test]
    async fn sbom_inventory_lists_direct_packages() {
        let state = test_state();
        let app = app(state.clone());
        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_inventory_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 3,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json", "poetry.lock"],
                "ecosystem_counts": { "npm": 2, "pypi": 1 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" },
                        { "bom-ref": "pkg:pypi/requests@2.32.3", "type": "library", "name": "requests", "version": "2.32.3", "purl": "pkg:pypi/requests@2.32.3" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:pypi/requests@2.32.3"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let inventory_request = Request::builder()
            .uri("/v1/sbom/inventory?git_commit=abc123&direct_only=true")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let inventory_response = app.oneshot(inventory_request).await.unwrap();
        assert_eq!(inventory_response.status(), StatusCode::OK);
        let inventory_body = axum::body::to_bytes(inventory_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let inventory: Value = serde_json::from_slice(&inventory_body).unwrap();

        assert_eq!(inventory["summary"]["package_count"].as_u64(), Some(2));
        assert_eq!(
            inventory["summary"]["direct_package_count"].as_u64(),
            Some(2)
        );
        assert_eq!(inventory["packages"].as_array().unwrap().len(), 2);
        assert_eq!(inventory["packages"][0]["ecosystem"].as_str(), Some("npm"));
        assert_eq!(inventory["packages"][1]["ecosystem"].as_str(), Some("pypi"));
        assert_eq!(inventory["packages"][0]["direct"].as_bool(), Some(true));
    }

    #[tokio::test]
    async fn sbom_inventory_can_include_transitive_packages() {
        let state = test_state();
        let app = app(state.clone());
        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_inventory_all_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc999" },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 3,
                "direct_dependency_count": 1,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 3 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/supports-color@9.4.0", "type": "library", "name": "supports-color", "version": "9.4.0", "purl": "pkg:npm/supports-color@9.4.0" },
                        { "bom-ref": "pkg:npm/has-flag@4.0.0", "type": "library", "name": "has-flag", "version": "4.0.0", "purl": "pkg:npm/has-flag@4.0.0" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1"]
                        },
                        {
                            "ref": "pkg:npm/chalk@5.4.1",
                            "dependsOn": ["pkg:npm/supports-color@9.4.0"]
                        },
                        {
                            "ref": "pkg:npm/supports-color@9.4.0",
                            "dependsOn": ["pkg:npm/has-flag@4.0.0"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let inventory_request = Request::builder()
            .uri("/v1/sbom/inventory?git_commit=abc999&direct_only=false")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let inventory_response = app.oneshot(inventory_request).await.unwrap();
        assert_eq!(inventory_response.status(), StatusCode::OK);
        let inventory_body = axum::body::to_bytes(inventory_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let inventory: Value = serde_json::from_slice(&inventory_body).unwrap();

        assert_eq!(inventory["summary"]["package_count"].as_u64(), Some(3));
        assert_eq!(
            inventory["summary"]["direct_package_count"].as_u64(),
            Some(1)
        );
        assert_eq!(inventory["packages"].as_array().unwrap().len(), 3);
        assert_eq!(inventory["packages"][0]["direct"].as_bool(), Some(true));
        assert_eq!(inventory["packages"][1]["direct"].as_bool(), Some(false));
        assert_eq!(inventory["packages"][2]["direct"].as_bool(), Some(false));
    }

    #[tokio::test]
    async fn sbom_document_returns_stored_cyclonedx_payload() {
        let state = test_state();
        let app = app(state.clone());

        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_document_1",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "doc123",
                "repo_url": "https://example.com/acme/platform.git"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 1,
                "direct_dependency_count": 1,
                "ecosystem_counts": { "npm": 1 },
                "manifest_sources": ["package-lock.json"],
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "urn:uuid:sbom-document",
                    "version": 1,
                    "metadata": {
                        "component": {
                            "type": "application",
                            "name": "platform",
                            "purl": "pkg:generic/platform"
                        }
                    },
                    "components": [
                        {
                            "bom-ref": "pkg:npm/react@18.2.0",
                            "type": "library",
                            "name": "react",
                            "version": "18.2.0",
                            "purl": "pkg:npm/react@18.2.0"
                        }
                    ]
                }
            }
        });

        let ingest = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload))
            .await
            .unwrap();
        assert_eq!(ingest.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/sbom/document?git_commit=doc123")
                    .header(header::AUTHORIZATION, "Bearer test-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"].as_str(), Some("ok"));
        assert_eq!(json["record"]["git_commit"].as_str(), Some("doc123"));
        assert_eq!(json["sbom"]["bomFormat"].as_str(), Some("CycloneDX"));
        assert_eq!(json["sbom"]["components"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            json["sbom"]["components"][0]["name"].as_str(),
            Some("react")
        );
    }

    #[tokio::test]
    async fn sbom_diff_detects_added_removed_and_version_changes() {
        let state = test_state();
        let app = app(state.clone());

        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_diff_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let head_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_diff_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "def456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", head_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let diff_request = Request::builder()
            .uri("/v1/sbom/diff?from_commit=abc123&to_commit=def456")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let diff_response = app.oneshot(diff_request).await.unwrap();
        assert_eq!(diff_response.status(), StatusCode::OK);
        let diff_body = axum::body::to_bytes(diff_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let diff: Value = serde_json::from_slice(&diff_body).unwrap();

        assert_eq!(diff["summary"]["added_count"].as_u64(), Some(1));
        assert_eq!(diff["summary"]["removed_count"].as_u64(), Some(1));
        assert_eq!(diff["summary"]["version_change_count"].as_u64(), Some(1));
        assert_eq!(diff["summary"]["unchanged_count"].as_u64(), Some(0));
        assert_eq!(diff["added"][0]["name"].as_str(), Some("ora"));
        assert_eq!(diff["removed"][0]["name"].as_str(), Some("glob"));
        assert_eq!(diff["version_changes"][0]["name"].as_str(), Some("chalk"));
        assert_eq!(
            diff["version_changes"][0]["from_version"].as_str(),
            Some("5.4.1")
        );
        assert_eq!(
            diff["version_changes"][0]["to_version"].as_str(),
            Some("5.5.0")
        );
    }

    #[tokio::test]
    async fn sbom_alerts_surface_direct_additions_and_version_changes() {
        let state = test_state();
        let app = app(state.clone());

        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_alert_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let head_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_alert_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "def456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", head_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let alerts_request = Request::builder()
            .uri("/v1/sbom/alerts?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let alerts_response = app.clone().oneshot(alerts_request).await.unwrap();
        assert_eq!(alerts_response.status(), StatusCode::OK);
        let alerts_body = axum::body::to_bytes(alerts_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let alerts: Value = serde_json::from_slice(&alerts_body).unwrap();

        assert_eq!(alerts["summary"]["alert_count"].as_u64(), Some(2));
        assert_eq!(
            alerts["summary"]["new_direct_package_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            alerts["summary"]["direct_version_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            alerts["alerts"][0]["kind"].as_str(),
            Some("direct_version_change")
        );
        assert_eq!(
            alerts["alerts"][1]["kind"].as_str(),
            Some("new_direct_package")
        );

        let overview_request = Request::builder()
            .uri("/v1/dashboard/overview?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let overview_response = app.oneshot(overview_request).await.unwrap();
        assert_eq!(overview_response.status(), StatusCode::OK);
        let overview_body = axum::body::to_bytes(overview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&overview_body).unwrap();

        assert_eq!(overview["summary"]["sbom_alert_count"].as_u64(), Some(2));
        assert_eq!(
            overview["summary"]["new_direct_package_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            overview["summary"]["direct_version_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            overview["recent_sbom_alerts"][0]["kind"].as_str(),
            Some("direct_version_change")
        );
    }

    #[tokio::test]
    async fn sbom_advisories_queries_osv_for_selected_packages() {
        let mut state = test_state();
        state.osv_api_url = Arc::new(
            spawn_osv_mock(json!({
                "results": [
                    {
                        "vulns": [
                            { "id": "OSV-2026-0001", "modified": "2026-03-16T00:00:00Z" }
                        ]
                    },
                    {
                        "vulns": []
                    }
                ]
            }))
            .await,
        );
        let app = app(state.clone());

        let payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_adv_1",
            "uploaded_at": "2026-03-13T03:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "adv123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let advisories_request = Request::builder()
            .uri("/v1/sbom/advisories?git_commit=adv123&direct_only=true")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let advisories_response = app.oneshot(advisories_request).await.unwrap();
        assert_eq!(advisories_response.status(), StatusCode::OK);
        let advisories_body = axum::body::to_bytes(advisories_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let advisories: Value = serde_json::from_slice(&advisories_body).unwrap();

        assert_eq!(advisories["summary"]["package_count"].as_u64(), Some(2));
        assert_eq!(
            advisories["summary"]["affected_package_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            advisories["summary"]["vulnerability_count"].as_u64(),
            Some(1)
        );
        assert_eq!(advisories["packages"][0]["name"].as_str(), Some("chalk"));
        assert_eq!(
            advisories["packages"][0]["vulnerabilities"][0]["id"].as_str(),
            Some("OSV-2026-0001")
        );
        assert_eq!(
            advisories["packages"][1]["vulnerability_count"].as_u64(),
            Some(0)
        );
    }

    #[tokio::test]
    async fn sbom_security_alerts_surface_only_vulnerable_changes() {
        let mut state = test_state();
        state.osv_api_url = Arc::new(
            spawn_osv_mock(json!({
                "results": [
                    {
                        "vulns": [
                            { "id": "OSV-2026-1001", "modified": "2026-03-16T00:00:00Z" }
                        ]
                    },
                    {
                        "vulns": []
                    }
                ]
            }))
            .await,
        );
        let app = app(state.clone());

        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_sec_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "secabc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let head_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_sec_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "secdef456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", head_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let alerts_request = Request::builder()
            .uri("/v1/sbom/security-alerts?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let alerts_response = app.clone().oneshot(alerts_request).await.unwrap();
        assert_eq!(alerts_response.status(), StatusCode::OK);
        let alerts_body = axum::body::to_bytes(alerts_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let alerts: Value = serde_json::from_slice(&alerts_body).unwrap();

        assert_eq!(alerts["summary"]["alert_count"].as_u64(), Some(1));
        assert_eq!(
            alerts["summary"]["new_vulnerable_direct_package_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            alerts["summary"]["vulnerable_direct_version_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            alerts["alerts"][0]["kind"].as_str(),
            Some("vulnerable_direct_version_change")
        );
        assert_eq!(
            alerts["alerts"][0]["package"]["vulnerabilities"][0]["id"].as_str(),
            Some("OSV-2026-1001")
        );

        let overview_request = Request::builder()
            .uri("/v1/dashboard/overview?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let overview_response = app.oneshot(overview_request).await.unwrap();
        assert_eq!(overview_response.status(), StatusCode::OK);
        let overview_body = axum::body::to_bytes(overview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&overview_body).unwrap();

        assert_eq!(
            overview["summary"]["sbom_security_alert_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            overview["summary"]["vulnerable_direct_version_change_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            overview["recent_sbom_security_alerts"][0]["kind"].as_str(),
            Some("vulnerable_direct_version_change")
        );
    }

    #[tokio::test]
    async fn sbom_security_alert_history_filters_persisted_shape() {
        let mut state = test_state();
        state.osv_api_url = Arc::new(
            spawn_osv_mock(json!({
                "results": [
                    {
                        "vulns": [
                            { "id": "OSV-2026-1001", "modified": "2026-03-16T00:00:00Z" }
                        ]
                    },
                    {
                        "vulns": []
                    }
                ]
            }))
            .await,
        );
        let app = app(state.clone());

        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_security_history_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let head_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_security_history_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "def456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", head_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let history_request = Request::builder()
            .uri("/v1/sbom/security-alerts/history?kind=vulnerable_direct_version_change&to_git_commit=def456&limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let history_response = app.clone().oneshot(history_request).await.unwrap();
        assert_eq!(history_response.status(), StatusCode::OK);
        let history_body = axum::body::to_bytes(history_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: Value = serde_json::from_slice(&history_body).unwrap();

        assert_eq!(history["filters"]["storage_mode"].as_str(), Some("derived"));
        assert_eq!(history["summary"]["alert_count"].as_u64(), Some(1));
        assert_eq!(
            history["summary"]["affected_package_count"].as_u64(),
            Some(1)
        );
        assert_eq!(
            history["alerts"][0]["kind"].as_str(),
            Some("vulnerable_direct_version_change")
        );
        assert_eq!(
            history["alerts"][0]["to_git_commit"].as_str(),
            Some("def456")
        );
    }

    #[tokio::test]
    async fn sbom_security_alert_history_rejects_cross_project_filter_for_project_key() {
        let request = Request::builder()
            .uri("/v1/sbom/security-alerts/history?project_slug=ops")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();

        let response = app(test_state()).oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn sbom_timeline_surfaces_commit_level_counts() {
        let mut state = test_state();
        state.osv_api_url = Arc::new(
            spawn_osv_mock(json!({
                "results": [
                    {
                        "vulns": [
                            { "id": "OSV-2026-1001", "modified": "2026-03-16T00:00:00Z" }
                        ]
                    },
                    {
                        "vulns": []
                    }
                ]
            }))
            .await,
        );
        let app = app(state.clone());

        let base_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_timeline_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let head_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_timeline_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "def456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });

        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", base_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", head_payload))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let timeline_request = Request::builder()
            .uri("/v1/sbom/timeline?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let timeline_response = app.clone().oneshot(timeline_request).await.unwrap();
        assert_eq!(timeline_response.status(), StatusCode::OK);
        let timeline_body = axum::body::to_bytes(timeline_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let timeline: Value = serde_json::from_slice(&timeline_body).unwrap();

        assert_eq!(timeline["summary"]["commit_count"].as_u64(), Some(2));
        assert_eq!(timeline["summary"]["package_alert_count"].as_u64(), Some(0));
        assert_eq!(
            timeline["summary"]["security_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            timeline["commits"][0]["git_commit"].as_str(),
            Some("def456")
        );
        assert_eq!(
            timeline["commits"][0]["package_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            timeline["commits"][0]["security_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            timeline["commits"][1]["git_commit"].as_str(),
            Some("abc123")
        );
        assert_eq!(
            timeline["commits"][1]["package_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            timeline["commits"][1]["security_alert_count"].as_u64(),
            Some(0)
        );
    }

    #[tokio::test]
    async fn projects_overview_aggregates_visible_project_state() {
        let mut state = test_state();
        state.osv_api_url = Arc::new(
            spawn_osv_mock(json!({
                "results": [
                    {
                        "vulns": [
                            { "id": "OSV-2026-1001", "modified": "2026-03-16T00:00:00Z" }
                        ]
                    },
                    {
                        "vulns": []
                    }
                ]
            }))
            .await,
        );
        let app = app(state.clone());

        let audit_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_projects_audit_web",
            "uploaded_at": "2026-03-13T00:30:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "aud123" },
            "payload": {
                "file_count": 5,
                "duration_ms": 12,
                "summary": { "total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 }
            }
        });
        let run_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_projects_run_web",
            "uploaded_at": "2026-03-13T00:45:00Z",
            "tool": { "command": "run", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "run123" },
            "payload": {
                "summary": {
                    "exit_code": 0,
                    "files_accessed": [],
                    "network_attempts": [],
                    "spawned_processes": 1,
                    "denied_count": 0,
                    "suspicious_activity": []
                },
                "verdict": "clean",
                "severity": "low"
            }
        });
        let sbom_base = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_projects_sbom_base",
            "uploaded_at": "2026-03-13T01:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.0",
                            "name": "demo",
                            "version": "1.0.0"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.4.1", "type": "library", "name": "chalk", "version": "5.4.1", "purl": "pkg:npm/chalk@5.4.1" },
                        { "bom-ref": "pkg:npm/glob@10.4.5", "type": "library", "name": "glob", "version": "10.4.5", "purl": "pkg:npm/glob@10.4.5" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.0",
                            "dependsOn": ["pkg:npm/chalk@5.4.1", "pkg:npm/glob@10.4.5"]
                        }
                    ]
                }
            }
        });
        let sbom_head = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_projects_sbom_head",
            "uploaded_at": "2026-03-13T02:00:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "def456",
                "repo_url": "https://github.com/acme/demo"
            },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 2,
                "direct_dependency_count": 2,
                "manifest_sources": ["package-lock.json"],
                "ecosystem_counts": { "npm": 2 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "metadata": {
                        "component": {
                            "type": "application",
                            "bom-ref": "pkg:generic/acme/demo@1.0.1",
                            "name": "demo",
                            "version": "1.0.1"
                        }
                    },
                    "components": [
                        { "bom-ref": "pkg:npm/chalk@5.5.0", "type": "library", "name": "chalk", "version": "5.5.0", "purl": "pkg:npm/chalk@5.5.0" },
                        { "bom-ref": "pkg:npm/ora@8.1.1", "type": "library", "name": "ora", "version": "8.1.1", "purl": "pkg:npm/ora@8.1.1" }
                    ],
                    "dependencies": [
                        {
                            "ref": "pkg:generic/acme/demo@1.0.1",
                            "dependsOn": ["pkg:npm/chalk@5.5.0", "pkg:npm/ora@8.1.1"]
                        }
                    ]
                }
            }
        });
        let ops_audit_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_projects_audit_ops",
            "uploaded_at": "2026-03-13T03:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "ops123" },
            "payload": {
                "file_count": 2,
                "duration_ms": 8,
                "summary": { "total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0 }
            }
        });

        for payload in [audit_payload, run_payload, sbom_base, sbom_head] {
            let request_path = payload["tool"]["command"].as_str().unwrap();
            let endpoint = format!("/v1/ingest/{request_path}");
            let response = app
                .clone()
                .oneshot(auth_request(&endpoint, payload))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "ops-key",
                ops_audit_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let request = Request::builder()
            .uri("/v1/projects/overview?limit=10")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(overview["summary"]["project_count"].as_u64(), Some(1));
        assert_eq!(
            overview["projects"][0]["project_slug"].as_str(),
            Some("web")
        );
        assert_eq!(overview["projects"][0]["audit_uploads"].as_u64(), Some(1));
        assert_eq!(overview["projects"][0]["run_uploads"].as_u64(), Some(1));
        assert_eq!(overview["projects"][0]["sbom_uploads"].as_u64(), Some(2));
        assert_eq!(overview["projects"][0]["total_findings"].as_u64(), Some(2));
        assert_eq!(
            overview["projects"][0]["current_package_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            overview["projects"][0]["current_security_alert_count"].as_u64(),
            Some(0)
        );
        assert_eq!(
            overview["projects"][0]["latest_sbom"]["git_commit"].as_str(),
            Some("def456")
        );
    }

    #[tokio::test]
    async fn dashboard_overview_summarizes_indexes() {
        let state = test_state();
        let app = app(state.clone());

        let audit_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_audit_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "file_count": 12,
                "duration_ms": 42,
                "summary": { "total": 3, "critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0 }
            }
        });
        let run_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_run_1",
            "uploaded_at": "2026-03-12T22:01:00Z",
            "tool": { "command": "run", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "command": { "program": "npm" },
                "verdict": "suspicious",
                "severity": "high",
                "summary": {
                    "exit_code": 1,
                    "denied_count": 1,
                    "process_count": 2,
                    "duration_ms": 1200,
                    "network_attempts": ["198.51.100.10:443"],
                    "suspicious_activity": ["Attempted to access sensitive file: ~/.npmrc"]
                }
            }
        });
        let sbom_payload = json!({
            "schema_version": "2026-03-13",
            "upload_id": "upl_sbom_1",
            "uploaded_at": "2026-03-12T22:02:00Z",
            "tool": { "command": "sbom", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": {
                "format": "cyclonedx-json",
                "spec_version": "1.5",
                "component_count": 386,
                "direct_dependency_count": 1,
                "manifest_sources": ["package-lock.json", "uv.lock"],
                "ecosystem_counts": { "npm": 300, "pypi": 86 },
                "sbom": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "components": [],
                    "dependencies": []
                }
            }
        });

        let audit_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/audit", audit_payload))
            .await
            .unwrap();
        assert_eq!(audit_response.status(), StatusCode::OK);

        let run_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/run", run_payload))
            .await
            .unwrap();
        assert_eq!(run_response.status(), StatusCode::OK);
        let sbom_response = app
            .clone()
            .oneshot(auth_request("/v1/ingest/sbom", sbom_payload))
            .await
            .unwrap();
        assert_eq!(sbom_response.status(), StatusCode::OK);

        let overview_request = Request::builder()
            .uri("/v1/dashboard/overview?limit=5")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let overview_response = app.oneshot(overview_request).await.unwrap();
        assert_eq!(overview_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(overview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(overview["summary"]["audit_uploads"].as_u64(), Some(1));
        assert_eq!(overview["summary"]["run_uploads"].as_u64(), Some(1));
        assert_eq!(overview["summary"]["sbom_uploads"].as_u64(), Some(1));
        assert_eq!(overview["summary"]["total_findings"].as_u64(), Some(3));
        assert_eq!(
            overview["summary"]["total_sbom_components"].as_u64(),
            Some(386)
        );
        assert_eq!(overview["organization"]["org_slug"].as_str(), Some("acme"));
        assert_eq!(
            overview["summary"]["verdict_counts"]["suspicious"].as_u64(),
            Some(1)
        );
        assert_eq!(
            overview["summary"]["ecosystem_counts"]["npm"].as_u64(),
            Some(300)
        );
        assert_eq!(
            overview["recent_suspicious_runs"][0]["verdict"].as_str(),
            Some("suspicious")
        );
        assert_eq!(
            overview["recent_sboms"][0]["component_count"].as_u64(),
            Some(386)
        );
    }

    #[tokio::test]
    async fn records_are_scoped_to_the_authenticated_org() {
        let state = test_state();
        let app = app(state.clone());

        let acme_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_acme_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": { "summary": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 } }
        });
        let other_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_other_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "def456" },
            "payload": { "summary": { "total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 } }
        });

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "test-key",
                acme_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "other-key",
                other_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list_request = Request::builder()
            .uri("/v1/ingest/audits")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(1));
        assert_eq!(listed["records"][0]["org_slug"].as_str(), Some("acme"));
    }

    #[tokio::test]
    async fn project_scoped_keys_only_see_their_project_records() {
        let state = test_state();
        let app = app(state.clone());

        let web_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_acme_web_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "abc123" },
            "payload": { "summary": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 } }
        });
        let ops_payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_acme_ops_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.2.9" },
            "source": { "environment": "ci" },
            "project": { "git_branch": "main", "git_commit": "def456" },
            "payload": { "summary": { "total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0 } }
        });

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "test-key",
                web_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "ops-key",
                ops_payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let list_request = Request::builder()
            .uri("/v1/ingest/audits")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer ops-key")
            .body(Body::empty())
            .unwrap();
        let list_response = app.clone().oneshot(list_request).await.unwrap();
        assert_eq!(list_response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(list_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let listed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listed["count"].as_u64(), Some(1));
        assert_eq!(listed["records"][0]["project_slug"].as_str(), Some("ops"));

        let overview_request = Request::builder()
            .uri("/v1/dashboard/overview")
            .method("GET")
            .header(header::AUTHORIZATION, "Bearer ops-key")
            .body(Body::empty())
            .unwrap();
        let overview_response = app.oneshot(overview_request).await.unwrap();
        assert_eq!(overview_response.status(), StatusCode::OK);
        let overview_body = axum::body::to_bytes(overview_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let overview: Value = serde_json::from_slice(&overview_body).unwrap();
        assert_eq!(overview["summary"]["audit_uploads"].as_u64(), Some(1));
        assert_eq!(
            overview["recent_audits"][0]["project_slug"].as_str(),
            Some("ops")
        );
    }

    #[test]
    fn infer_project_slug_from_repo_url_handles_github_urls() {
        assert_eq!(
            infer_project_slug_from_repo_url("https://github.com/cc-consulting-nv/web.git"),
            Some(String::from("web"))
        );
        assert_eq!(
            infer_project_slug_from_repo_url("git@github.com:cc-consulting-nv/ccsdk-flutter.git"),
            Some(String::from("ccsdk-flutter"))
        );
    }

    #[tokio::test]
    async fn org_scoped_keys_infer_project_slug_from_repo_url() {
        let state = test_state();
        let app = app(state.clone());

        let payload = json!({
            "schema_version": "2026-03-12",
            "upload_id": "upl_org_scoped_1",
            "uploaded_at": "2026-03-12T22:00:00Z",
            "tool": { "command": "audit", "version": "0.3.0" },
            "source": { "environment": "ci" },
            "project": {
                "git_branch": "main",
                "git_commit": "abc123",
                "repo_url": "https://github.com/cc-consulting-nv/web"
            },
            "payload": { "summary": { "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 } }
        });

        let response = app
            .clone()
            .oneshot(auth_request_with_token(
                "/v1/ingest/audit",
                "org-key",
                payload,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let accepted: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            accepted["organization"]["project_slug"].as_str(),
            Some("web")
        );
        assert_eq!(accepted["record"]["project_slug"].as_str(), Some("web"));
    }

    #[test]
    fn trace_dependency_path_finds_shortest_path_to_vulnerable_package() {
        let sbom = json!({
            "metadata": {
                "component": {
                    "bom-ref": "pkg:npm/my-app@1.0.0",
                    "name": "my-app",
                    "version": "1.0.0"
                }
            },
            "dependencies": [
                {"ref": "pkg:npm/my-app@1.0.0", "dependsOn": ["pkg:npm/express@4.21.0"]},
                {"ref": "pkg:npm/express@4.21.0", "dependsOn": ["pkg:npm/body-parser@1.20.3", "pkg:npm/accepts@1.3.8"]},
                {"ref": "pkg:npm/body-parser@1.20.3", "dependsOn": ["pkg:npm/qs@6.13.0"]},
                {"ref": "pkg:npm/qs@6.13.0", "dependsOn": []},
                {"ref": "pkg:npm/accepts@1.3.8", "dependsOn": []}
            ]
        });

        // Direct dependency
        let path = trace_dependency_path(&sbom, "pkg:npm/express@4.21.0");
        assert_eq!(path, vec!["pkg:npm/my-app@1.0.0", "pkg:npm/express@4.21.0"]);

        // Second-level transitive
        let path = trace_dependency_path(&sbom, "pkg:npm/body-parser@1.20.3");
        assert_eq!(
            path,
            vec![
                "pkg:npm/my-app@1.0.0",
                "pkg:npm/express@4.21.0",
                "pkg:npm/body-parser@1.20.3"
            ]
        );

        // Third-level transitive (root → express → body-parser → qs)
        let path = trace_dependency_path(&sbom, "pkg:npm/qs@6.13.0");
        assert_eq!(
            path,
            vec![
                "pkg:npm/my-app@1.0.0",
                "pkg:npm/express@4.21.0",
                "pkg:npm/body-parser@1.20.3",
                "pkg:npm/qs@6.13.0"
            ]
        );

        // Nonexistent package returns empty
        let path = trace_dependency_path(&sbom, "pkg:npm/nonexistent@0.0.0");
        assert!(path.is_empty());

        // Root itself returns single-element path
        let path = trace_dependency_path(&sbom, "pkg:npm/my-app@1.0.0");
        assert_eq!(path, vec!["pkg:npm/my-app@1.0.0"]);
    }
}
