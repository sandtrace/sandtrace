use std::net::SocketAddr;

#[path = "../ingest_service.rs"]
mod ingest_service;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let bind = std::env::var("SANDTRACE_INGEST_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8080".to_string())
        .parse::<SocketAddr>()?;

    let state = ingest_service::IngestState::from_env().await?;

    eprintln!("sandtrace-ingest listening on {bind}");
    ingest_service::serve(state, bind).await
}
