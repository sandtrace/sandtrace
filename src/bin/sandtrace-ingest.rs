use std::net::SocketAddr;
use tracing_subscriber::{fmt, EnvFilter};

#[path = "../ingest_service.rs"]
mod ingest_service;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt()
        .with_env_filter(filter)
        .with_target(true)
        .json()
        .init();

    let bind = std::env::var("SANDTRACE_INGEST_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()?;

    let state = ingest_service::IngestState::from_env().await?;

    tracing::info!(%bind, "sandtrace-ingest starting");
    ingest_service::serve(state, bind).await
}
