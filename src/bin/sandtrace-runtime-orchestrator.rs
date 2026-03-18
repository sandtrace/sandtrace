use std::net::SocketAddr;

#[path = "../runtime_orchestrator.rs"]
mod runtime_orchestrator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let bind = std::env::var("SANDTRACE_RUNTIME_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
        .parse::<SocketAddr>()?;

    let state = runtime_orchestrator::RuntimeState::from_env().await?;

    eprintln!("sandtrace-runtime-orchestrator listening on {bind}");
    runtime_orchestrator::serve(state, bind).await
}
