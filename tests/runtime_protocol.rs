use reqwest::StatusCode;
use serde_json::{json, Value};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore = "requires SANDTRACE_RUNTIME_INTEGRATION_DATABASE_URL pointing at a dedicated test database"]
async fn orchestrator_and_stub_worker_complete_a_runtime_job() -> anyhow::Result<()> {
    let database_url = std::env::var("SANDTRACE_RUNTIME_INTEGRATION_DATABASE_URL")
        .expect("set SANDTRACE_RUNTIME_INTEGRATION_DATABASE_URL to a dedicated test database");
    let admin_token = "runtime-admin-test-token";
    let worker_token = "runtime-worker-test-token";
    let bind = free_local_addr()?;
    let base_url = format!("http://{bind}");

    reset_runtime_tables(&database_url).await?;

    let mut orchestrator = spawn_orchestrator(&database_url, &bind.to_string(), admin_token, worker_token)?;
    wait_for_healthz(&base_url).await?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;

    let create_response = client
        .post(format!("{base_url}/v1/runtime/jobs"))
        .bearer_auth(admin_token)
        .json(&json!({
            "org_slug": "sandtrace",
            "project_slug": "web",
            "source": {
                "kind": "github",
                "repo_url": "https://github.com/cc-consulting-nv/web.git",
                "owner": "cc-consulting-nv",
                "repo": "web",
                "ref": "refs/heads/main",
                "git_commit": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                "pull_request_number": 98
            },
            "execution": {
                "working_directory": ".",
                "command": ["pnpm", "install"],
                "timeout_seconds": 60,
                "allow_network": true,
                "allow_exec": true
            },
            "trigger": {
                "kind": "manual",
                "actor": "integration-test"
            }
        }))
        .send()
        .await?;
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let create_body: Value = create_response.json().await?;
    let job_id = create_body["job_id"]
        .as_str()
        .expect("job_id response")
        .to_string();

    let worker_status = Command::new(assert_cmd::cargo::cargo_bin!(
        "sandtrace-runtime-worker"
    ))
        .env("SANDTRACE_RUNTIME_URL", &base_url)
        .env("SANDTRACE_RUNTIME_WORKER_TOKEN", worker_token)
        .env("SANDTRACE_RUNTIME_STUB_MODE", "uploaded")
        .env("SANDTRACE_RUNTIME_STUB_DELAY_SECS", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(worker_status.success());

    let job = wait_for_uploaded_job(&client, &base_url, admin_token, &job_id).await?;
    assert_eq!(job["status"], "uploaded");
    assert_eq!(job["project_slug"], "web");
    assert!(
        job["ingest_run_id"]
            .as_str()
            .is_some_and(|value| value.starts_with("run_stub_"))
    );

    let events_response = client
        .get(format!("{base_url}/v1/runtime/jobs/{job_id}/events"))
        .bearer_auth(admin_token)
        .send()
        .await?;
    assert_eq!(events_response.status(), StatusCode::OK);
    let events: Value = events_response.json().await?;
    let event_types: Vec<&str> = events
        .as_array()
        .expect("events array")
        .iter()
        .filter_map(|event| event["event_type"].as_str())
        .collect();
    assert!(event_types.contains(&"job_created"));
    assert!(event_types.contains(&"lease_acquired"));
    assert!(event_types.contains(&"job_uploaded"));

    kill_child(&mut orchestrator);
    Ok(())
}

fn spawn_orchestrator(
    database_url: &str,
    bind: &str,
    admin_token: &str,
    worker_token: &str,
) -> anyhow::Result<Child> {
    let child = Command::new(assert_cmd::cargo::cargo_bin!(
        "sandtrace-runtime-orchestrator"
    ))
        .env("SANDTRACE_RUNTIME_DATABASE_URL", database_url)
        .env("SANDTRACE_RUNTIME_BIND", bind)
        .env("SANDTRACE_RUNTIME_ADMIN_TOKEN", admin_token)
        .env("SANDTRACE_RUNTIME_WORKER_TOKEN", worker_token)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(child)
}

async fn wait_for_healthz(base_url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(response) = client.get(format!("{base_url}/healthz")).send().await {
            if response.status() == StatusCode::OK {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("runtime orchestrator did not become healthy in time");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_for_uploaded_job(
    client: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
    job_id: &str,
) -> anyhow::Result<Value> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let response = client
            .get(format!("{base_url}/v1/runtime/jobs/{job_id}"))
            .bearer_auth(admin_token)
            .send()
            .await?;
        if response.status() == StatusCode::OK {
            let body: Value = response.json().await?;
            if body["status"] == "uploaded" {
                return Ok(body);
            }
        }
        if Instant::now() >= deadline {
            anyhow::bail!("runtime job did not reach uploaded state in time");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn reset_runtime_tables(database_url: &str) -> anyhow::Result<()> {
    let (client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    client
        .batch_execute(
            r#"
            drop table if exists runtime_worker_leases;
            drop table if exists runtime_job_events;
            drop table if exists runtime_jobs;
            "#,
        )
        .await?;
    Ok(())
}

fn free_local_addr() -> anyhow::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    drop(listener);
    Ok(addr)
}

fn kill_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
