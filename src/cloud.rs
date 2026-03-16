use crate::cli::{AuditArgs, RunArgs, SbomArgs, SbomFormat};
use crate::event::{AuditFinding, Severity, TraceSummary};
use chrono::Utc;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const DEFAULT_CLOUD_URL: &str = "https://api.sandtrace.io";
const DEFAULT_TIMEOUT_MS: u64 = 3000;
const SCHEMA_VERSION: &str = "2026-03-12";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawTracePolicy {
    Never,
    Suspicious,
    Always,
}

impl RawTracePolicy {
    fn from_env(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "always" => Self::Always,
            "suspicious" => Self::Suspicious,
            _ => Self::Never,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CloudConfig {
    api_key: String,
    base_url: String,
    timeout_ms: u64,
    environment: String,
    raw_trace_policy: RawTracePolicy,
}

impl CloudConfig {
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("SANDTRACE_API_KEY").ok()?;
        let api_key = api_key.trim().to_string();
        if api_key.is_empty() {
            return None;
        }

        let base_url = std::env::var("SANDTRACE_CLOUD_URL")
            .unwrap_or_else(|_| DEFAULT_CLOUD_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        let timeout_ms = std::env::var("SANDTRACE_CLOUD_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let environment = std::env::var("SANDTRACE_CLOUD_ENVIRONMENT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(infer_environment);
        let raw_trace_policy = std::env::var("SANDTRACE_CLOUD_RAW_TRACE")
            .map(|value| RawTracePolicy::from_env(&value))
            .unwrap_or(RawTracePolicy::Never);

        Some(Self {
            api_key,
            base_url,
            timeout_ms,
            environment,
            raw_trace_policy,
        })
    }
    fn client(&self) -> reqwest::Result<Client> {
        Client::builder()
            .timeout(Duration::from_millis(self.timeout_ms))
            .build()
    }
}

pub fn upload_audit(
    config: &CloudConfig,
    args: &AuditArgs,
    findings: &[AuditFinding],
    file_count: usize,
    duration_ms: u64,
) -> anyhow::Result<()> {
    let target = args
        .target
        .canonicalize()
        .unwrap_or_else(|_| args.target.clone());
    let payload = envelope(
        "audit",
        &target,
        config,
        build_audit_payload(args, findings, file_count, duration_ms, &target),
    );
    post_json(config, "/v1/ingest/audit", payload)
}

pub fn upload_run(
    config: &CloudConfig,
    args: &RunArgs,
    summary: &TraceSummary,
    working_dir: &Path,
) -> anyhow::Result<()> {
    let cwd = working_dir
        .canonicalize()
        .unwrap_or_else(|_| working_dir.to_path_buf());
    let payload = envelope(
        "run",
        &cwd,
        config,
        build_run_payload(args, summary, &cwd, config.raw_trace_policy),
    );
    post_json(config, "/v1/ingest/run", payload)
}

pub fn upload_sbom(
    config: &CloudConfig,
    args: &SbomArgs,
    target: &Path,
    bom: &Value,
    manifest_sources: &[String],
) -> anyhow::Result<()> {
    let payload = envelope(
        "sbom",
        target,
        config,
        build_sbom_payload(args, bom, target, manifest_sources),
    );
    post_json(config, "/v1/ingest/sbom", payload)
}

fn post_json(config: &CloudConfig, path: &str, payload: Value) -> anyhow::Result<()> {
    let upload_id = payload
        .get("upload_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("cloud payload missing upload_id"))?
        .to_string();
    let url = format!("{}{}", config.base_url, path);
    let response = config
        .client()?
        .post(url)
        .bearer_auth(&config.api_key)
        .header(
            "User-Agent",
            format!("sandtrace/{}", env!("CARGO_PKG_VERSION")),
        )
        .header("Idempotency-Key", upload_id)
        .header("X-Sandtrace-Schema-Version", SCHEMA_VERSION)
        .json(&payload)
        .send()?;

    let status = response.status();
    if !status.is_success() {
        anyhow::bail!("cloud upload failed with status {}", status);
    }

    Ok(())
}

fn envelope(command: &str, project_path: &Path, config: &CloudConfig, payload: Value) -> Value {
    let upload_id = generate_upload_id(command, project_path);
    json!({
        "schema_version": SCHEMA_VERSION,
        "upload_id": upload_id,
        "uploaded_at": Utc::now().to_rfc3339(),
        "tool": {
            "name": "sandtrace",
            "version": env!("CARGO_PKG_VERSION"),
            "command": command,
        },
        "source": {
            "mode": "cli",
            "environment": config.environment,
            "hostname_hash": env_hash("HOSTNAME"),
            "user_hash": env_hash("USER"),
        },
        "project": project_metadata(project_path),
        "payload": payload,
    })
}

fn build_audit_payload(
    args: &AuditArgs,
    findings: &[AuditFinding],
    file_count: usize,
    duration_ms: u64,
    target: &Path,
) -> Value {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;
    let mut rule_counts = std::collections::BTreeMap::new();

    for finding in findings {
        *rule_counts.entry(finding.rule_id.clone()).or_insert(0usize) += 1;
        match finding.severity {
            Severity::Critical => critical += 1,
            Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
            Severity::Info => info += 1,
        }
    }

    let findings_json: Vec<Value> = findings
        .iter()
        .map(|finding| {
            json!({
                "file_path_hash": sha256_hex(&finding.file_path),
                "file_name": Path::new(&finding.file_path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown"),
                "line_number": finding.line_number,
                "rule_id": finding.rule_id,
                "severity": severity_str(finding.severity),
                "description": finding.description,
                "matched_pattern": finding.matched_pattern,
                "context_lines": finding.context_lines,
            })
        })
        .collect();

    json!({
        "target_path_hash": sha256_hex(target.to_string_lossy().as_ref()),
        "severity_threshold": severity_str(args.min_severity()),
        "ruleset_version": format!("builtin@{}", env!("CARGO_PKG_VERSION")),
        "file_count": file_count,
        "duration_ms": duration_ms,
        "summary": {
            "total": findings.len(),
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        },
        "rule_counts": rule_counts,
        "findings": findings_json,
    })
}

fn build_run_payload(
    args: &RunArgs,
    summary: &TraceSummary,
    working_dir: &Path,
    raw_trace_policy: RawTracePolicy,
) -> Value {
    let normalized_files: Vec<String> = summary
        .files_accessed
        .iter()
        .map(|path| normalize_path_for_cloud(path))
        .collect();
    let suspicious_events = build_suspicious_events(summary);
    let verdict = derive_verdict(summary);
    let severity = verdict_severity(&verdict, summary);

    json!({
        "command": {
            "program": args.command.first().cloned().unwrap_or_default(),
            "argv": args.command,
            "working_dir_hash": sha256_hex(working_dir.to_string_lossy().as_ref()),
        },
        "policy": {
            "trace_only": args.trace_only,
            "allow_net": args.allow_net,
            "allow_exec": args.allow_exec,
            "follow_forks": args.follow_forks,
            "timeout_seconds": args.timeout,
        },
        "summary": {
            "timestamp": summary.timestamp.to_rfc3339(),
            "total_syscalls": summary.total_syscalls,
            "unique_syscalls": summary.unique_syscalls,
            "denied_count": summary.denied_count,
            "process_count": summary.process_count,
            "duration_ms": summary.duration_ms,
            "exit_code": summary.exit_code,
            "files_accessed": normalized_files,
            "network_attempts": summary.network_attempts,
            "suspicious_activity": summary
                .suspicious_activity
                .iter()
                .map(|item| sanitize_suspicious_activity(item))
                .collect::<Vec<_>>(),
        },
        "verdict": verdict,
        "severity": severity,
        "raw_trace_policy": raw_trace_policy_str(raw_trace_policy),
        "suspicious_events": suspicious_events,
    })
}

fn build_sbom_payload(
    args: &SbomArgs,
    bom: &Value,
    target: &Path,
    manifest_sources: &[String],
) -> Value {
    let components = bom
        .get("components")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let dependencies = bom
        .get("dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let component_count = components.len();
    let direct_dependency_count = dependencies
        .iter()
        .filter_map(|dependency| dependency.get("dependsOn").and_then(Value::as_array))
        .map(|depends_on| depends_on.len() as u64)
        .sum::<u64>();

    let mut ecosystem_counts = std::collections::BTreeMap::new();
    for component in &components {
        let ecosystem = component
            .get("purl")
            .and_then(Value::as_str)
            .and_then(parse_purl_type)
            .unwrap_or("generic");
        *ecosystem_counts
            .entry(ecosystem.to_string())
            .or_insert(0u64) += 1;
    }

    json!({
        "target_path_hash": sha256_hex(target.to_string_lossy().as_ref()),
        "format": match args.format {
            SbomFormat::CyclonedxJson => "cyclonedx-json",
        },
        "spec_version": bom.get("specVersion").and_then(Value::as_str).unwrap_or("1.5"),
        "component_count": component_count,
        "direct_dependency_count": direct_dependency_count,
        "ecosystem_counts": ecosystem_counts,
        "manifest_sources": manifest_sources,
        "sbom": bom,
    })
}

fn build_suspicious_events(summary: &TraceSummary) -> Vec<Value> {
    let mut events = Vec::new();

    for path in &summary.files_accessed {
        let normalized = normalize_path_for_cloud(path);
        if normalized != hash_label(path) {
            events.push(json!({
                "event_type": "summary_signal",
                "category": "file_access",
                "path_label": normalized,
                "action": "read",
            }));
        }
    }

    for destination in &summary.network_attempts {
        events.push(json!({
            "event_type": "summary_signal",
            "category": "network",
            "destination": destination,
            "action": "connect",
        }));
    }

    for activity in &summary.suspicious_activity {
        events.push(json!({
            "event_type": "summary_signal",
            "category": "suspicious_activity",
            "message": sanitize_suspicious_activity(activity),
        }));
    }

    events
}

fn derive_verdict(summary: &TraceSummary) -> &'static str {
    if summary.denied_count > 0 && summary.exit_code != 0 {
        "blocked"
    } else if !summary.suspicious_activity.is_empty() || !summary.network_attempts.is_empty() {
        "suspicious"
    } else if summary.exit_code != 0 {
        "failed"
    } else {
        "clean"
    }
}

fn verdict_severity<'a>(verdict: &'a str, summary: &TraceSummary) -> &'a str {
    match verdict {
        "blocked" => "high",
        "suspicious" if !summary.network_attempts.is_empty() => "high",
        "suspicious" => "medium",
        "failed" => "low",
        _ => "info",
    }
}

fn raw_trace_policy_str(policy: RawTracePolicy) -> &'static str {
    match policy {
        RawTracePolicy::Never => "never",
        RawTracePolicy::Suspicious => "suspicious",
        RawTracePolicy::Always => "always",
    }
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn generate_upload_id(command: &str, project_path: &Path) -> String {
    let stamp = Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or_else(|| Utc::now().timestamp_micros() * 1000);
    let input = format!(
        "{}:{}:{}:{}",
        command,
        project_path.display(),
        std::process::id(),
        stamp
    );
    format!("upl_{}", sha256_hex(&input)[..24].to_string())
}

fn infer_environment() -> String {
    if std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
    {
        "ci".to_string()
    } else {
        "dev".to_string()
    }
}

fn env_hash(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!("sha256:{}", sha256_hex(&value)))
        .unwrap_or_default()
}

fn project_metadata(project_path: &Path) -> Value {
    let repo_root = git_output(project_path, &["rev-parse", "--show-toplevel"])
        .map(|value| value.trim().to_string());
    let branch = git_output(project_path, &["rev-parse", "--abbrev-ref", "HEAD"]);
    let commit = git_output(project_path, &["rev-parse", "HEAD"]);
    let repo_url = git_output(project_path, &["config", "--get", "remote.origin.url"]);

    let root_ref = repo_root
        .clone()
        .unwrap_or_else(|| project_path.to_string_lossy().into_owned());

    json!({
        "repo_url": repo_url,
        "repo_root_hash": format!("sha256:{}", sha256_hex(&root_ref)),
        "git_branch": branch,
        "git_commit": commit,
        "provider": detect_provider(),
    })
}

fn git_output(project_path: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(project_path)
        .args(args)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let value = stdout.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn detect_provider() -> &'static str {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        "github_actions"
    } else if std::env::var("GITLAB_CI").is_ok() {
        "gitlab_ci"
    } else {
        "local"
    }
}

fn normalize_path_for_cloud(path: &str) -> String {
    let lower = path.to_ascii_lowercase();
    if lower.contains(".env") {
        ".env".to_string()
    } else if lower.contains(".npmrc") {
        "~/.npmrc".to_string()
    } else if lower.contains(".aws/credentials") {
        "~/.aws/credentials".to_string()
    } else if lower.contains(".ssh/") {
        "~/.ssh/*".to_string()
    } else if lower.contains(".bashrc") {
        "~/.bashrc".to_string()
    } else if lower.contains("/etc/passwd") {
        "/etc/passwd".to_string()
    } else if lower.contains("/etc/shadow") {
        "/etc/shadow".to_string()
    } else {
        hash_label(path)
    }
}

fn parse_purl_type(purl: &str) -> Option<&str> {
    purl.strip_prefix("pkg:")?.split('/').next()
}

fn sanitize_suspicious_activity(activity: &str) -> String {
    if let Some(path) = activity.strip_prefix("Attempted to access sensitive file: ") {
        format!(
            "Attempted to access sensitive file: {}",
            normalize_path_for_cloud(path)
        )
    } else {
        activity.to_string()
    }
}

fn hash_label(input: &str) -> String {
    format!("sha256:{}", sha256_hex(input))
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn cloud_config_disabled_without_api_key() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("SANDTRACE_API_KEY");
        assert!(CloudConfig::from_env().is_none());
    }

    #[test]
    fn cloud_config_reads_environment() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("SANDTRACE_API_KEY", "test-key");
        std::env::set_var("SANDTRACE_CLOUD_URL", "https://cloud.example.com/");
        std::env::set_var("SANDTRACE_CLOUD_RAW_TRACE", "suspicious");
        std::env::set_var("SANDTRACE_CLOUD_TIMEOUT_MS", "4500");
        std::env::set_var("SANDTRACE_CLOUD_ENVIRONMENT", "staging");

        let config = CloudConfig::from_env().expect("config should be enabled");
        assert_eq!(config.base_url, "https://cloud.example.com");
        assert_eq!(config.timeout_ms, 4500);
        assert_eq!(config.environment, "staging");
        assert_eq!(config.raw_trace_policy, RawTracePolicy::Suspicious);

        std::env::remove_var("SANDTRACE_API_KEY");
        std::env::remove_var("SANDTRACE_CLOUD_URL");
        std::env::remove_var("SANDTRACE_CLOUD_RAW_TRACE");
        std::env::remove_var("SANDTRACE_CLOUD_TIMEOUT_MS");
        std::env::remove_var("SANDTRACE_CLOUD_ENVIRONMENT");
    }

    #[test]
    fn path_normalization_prefers_labels_over_raw_paths() {
        assert_eq!(normalize_path_for_cloud("/home/alice/.npmrc"), "~/.npmrc");
        assert_eq!(normalize_path_for_cloud("/tmp/project/.env.local"), ".env");
        assert!(normalize_path_for_cloud("/tmp/project/src/main.rs").starts_with("sha256:"));
    }
}
