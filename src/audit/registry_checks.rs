//! Deep registry checks: verify packages exist, check version age,
//! download counts, and known vulnerabilities via registry APIs.
//!
//! Only runs when `--deep` flag is passed (requires network access).

use crate::event::{AuditFinding, Severity};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Per-registry concurrency limits. These are conservative caps based on each
/// registry's documented or observed rate limits:
/// - npm: registry.npmjs.org is CDN-backed and tolerates heavy concurrency
/// - packagist: documented at 60 req/sec for the public API
/// - api.npmjs.org/downloads: ~5 req/sec unauthenticated — handled separately
const NPM_CONCURRENCY: usize = 16;
const PACKAGIST_CONCURRENCY: usize = 32;

/// High-trust, high-frequency npm packages that publish often.
/// These skip the version-age check because they'd almost always trigger it.
const TRUSTED_NPM_PACKAGES: &[&str] = &[
    // Core frameworks
    "vue",
    "react",
    "react-dom",
    "next",
    "nuxt",
    "svelte",
    "@sveltejs/kit",
    "angular",
    "@angular/core",
    "@angular/cli",
    // TypeScript ecosystem
    "typescript",
    "typescript-eslint",
    "@typescript-eslint/parser",
    "@typescript-eslint/eslint-plugin",
    "@types/node",
    "@types/react",
    "@types/react-dom",
    // Build tools
    "vite",
    "esbuild",
    "webpack",
    "rollup",
    "@rollup/rollup-linux-x64-gnu",
    "@rollup/rollup-linux-arm64-gnu",
    "@rollup/rollup-darwin-x64",
    "@rollup/rollup-darwin-arm64",
    "@rollup/rollup-win32-x64-msvc",
    "@rollup/rollup-win32-arm64-msvc",
    "turbo",
    "laravel-vite-plugin",
    // Linting / formatting
    "eslint",
    "prettier",
    // Testing
    "vitest",
    "jest",
    "playwright",
    "@playwright/test",
    // Major ecosystem packages
    "tailwindcss",
    "@tailwindcss/vite",
    "postcss",
    "autoprefixer",
    "axios",
    "lodash",
    "date-fns",
    "zod",
];

/// High-trust composer packages that publish frequently.
const TRUSTED_COMPOSER_PACKAGES: &[&str] = &[
    "laravel/framework",
    "laravel/tinker",
    "laravel/sanctum",
    "laravel/passport",
    "laravel/horizon",
    "laravel/telescope",
    "laravel/pint",
    "symfony/console",
    "symfony/http-kernel",
    "symfony/routing",
    "phpunit/phpunit",
    "pestphp/pest",
    "nunomaduro/larastan",
    "phpstan/phpstan",
];

/// Run all registry-based deep checks on dependencies found in manifests + lockfiles.
///
/// Lockfile-first: when a lockfile is present, transitive deps are included and marked
/// `is_transitive=true`. Falls back to manifest-only (direct deps only) when no lockfile.
///
/// Sync wrapper that drives an async pipeline internally. Per-registry semaphores
/// bound concurrent HTTP requests so large monorepos (1000+ transitive deps) don't
/// thunder the registry APIs.
pub fn run_deep_checks(dir: &Path) -> Vec<AuditFinding> {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return Vec::new(),
    };
    rt.block_on(run_deep_checks_async(dir))
}

async fn run_deep_checks_async(dir: &Path) -> Vec<AuditFinding> {
    let client = match Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("sandtrace")
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let deps = collect_audit_deps(dir);
    let npm_deps: Vec<DepInfo> = deps
        .iter()
        .filter(|d| d.ecosystem == Ecosystem::Npm)
        .cloned()
        .collect();
    let composer_deps: Vec<DepInfo> = deps
        .iter()
        .filter(|d| d.ecosystem == Ecosystem::Composer)
        .cloned()
        .collect();

    let mut findings = Vec::new();

    if !npm_deps.is_empty() {
        let transitive = npm_deps.iter().filter(|d| d.is_transitive).count();
        eprintln!(
            "Deep check: verifying {} npm packages ({} direct, {} transitive)...",
            npm_deps.len(),
            npm_deps.len() - transitive,
            transitive
        );
        let sem = Arc::new(Semaphore::new(NPM_CONCURRENCY));
        findings.extend(check_npm_packages(client.clone(), npm_deps, dir, sem).await);
    }

    if !composer_deps.is_empty() {
        let transitive = composer_deps.iter().filter(|d| d.is_transitive).count();
        eprintln!(
            "Deep check: verifying {} composer packages ({} direct, {} transitive)...",
            composer_deps.len(),
            composer_deps.len() - transitive,
            transitive
        );
        let sem = Arc::new(Semaphore::new(PACKAGIST_CONCURRENCY));
        findings.extend(check_composer_packages(client.clone(), composer_deps, dir, sem).await);
    }

    findings
}

/// Walk the target directory via sbom::discover_manifests and produce a deduped
/// `Vec<DepInfo>` per ecosystem. Lockfiles take precedence over manifests:
/// when a lockfile is present for a manifest group, dependencies are taken from
/// the lockfile (including transitives). Otherwise, falls back to the manifest
/// (direct deps only, `is_transitive=false`).
fn collect_audit_deps(target: &Path) -> Vec<DepInfo> {
    use std::collections::HashSet;

    let mut deps: Vec<DepInfo> = Vec::new();
    let mut seen: HashSet<(Ecosystem, String, String)> = HashSet::new();

    let groups = match crate::sbom::discover_manifests(target) {
        Ok(g) => g,
        Err(_) => return deps,
    };

    for group in groups.values() {
        // ---- npm ecosystem ----
        let npm_deps = if let Some(lock) = group
            .package_lock_json
            .as_deref()
            .or(group.npm_shrinkwrap_json.as_deref())
        {
            parse_npm_package_lock(lock, group.package_json.as_deref())
        } else if let Some(lock) = group.pnpm_lock_yaml.as_deref() {
            parse_pnpm_lock(lock, group.package_json.as_deref())
        } else if let Some(lock) = group.yarn_lock.as_deref() {
            parse_yarn_lock(lock, group.package_json.as_deref())
        } else if let Some(pkg) = group.package_json.as_deref() {
            parse_npm_manifest(pkg)
        } else {
            Vec::new()
        };
        for d in npm_deps {
            let key = (d.ecosystem.clone(), d.name.clone(), d.version_spec.clone());
            if seen.insert(key) {
                deps.push(d);
            }
        }

        // ---- composer ecosystem ----
        let composer_deps = if let Some(lock) = group.composer_lock.as_deref() {
            parse_composer_lock(lock, group.composer_json.as_deref())
        } else if let Some(manifest) = group.composer_json.as_deref() {
            parse_composer_manifest(manifest)
        } else {
            Vec::new()
        };
        for d in composer_deps {
            let key = (d.ecosystem.clone(), d.name.clone(), d.version_spec.clone());
            if seen.insert(key) {
                deps.push(d);
            }
        }
    }

    deps
}

/// Parse package-lock.json (npm v2/v3) or npm-shrinkwrap.json.
/// Reads the `packages` map: root entry `""` lists `dependencies`/`devDependencies`;
/// nested entries under `node_modules/<name>` are transitive.
fn parse_npm_package_lock(lock_path: &Path, manifest_path: Option<&Path>) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(lock_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    let direct = direct_names_from_manifest(manifest_path);
    let direct_dev = direct_dev_names_from_manifest(manifest_path);

    if let Some(packages) = json.get("packages").and_then(Value::as_object) {
        for (path, entry) in packages {
            // Root entry: lists direct deps via dependencies/devDependencies maps; skip.
            if path.is_empty() {
                continue;
            }
            // node_modules/<scope>/<name> or node_modules/<name>
            let name = match path.rsplit_once("node_modules/") {
                Some((_, n)) => n.to_string(),
                None => continue,
            };
            // Skip workspace symlinks (no version).
            let Some(version) = entry.get("version").and_then(Value::as_str) else {
                continue;
            };
            // Direct iff the package name appears in the project manifest's deps list.
            // Transitive otherwise. Hoisted top-level node_modules/foo entries that aren't
            // in the manifest are still indirect dependencies.
            let is_transitive = !direct.contains(&name);
            let is_dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false)
                || (!is_transitive && direct_dev.contains(&name));
            deps.push(DepInfo {
                name,
                version_spec: version.to_string(),
                ecosystem: Ecosystem::Npm,
                is_dev,
                is_transitive,
            });
        }
        if !deps.is_empty() {
            return deps;
        }
    }

    // v1 fallback: top-level `dependencies` map (recursive).
    if let Some(top) = json.get("dependencies").and_then(Value::as_object) {
        collect_npm_v1_deps(top, &direct_dev, false, &mut deps);
    }
    deps
}

fn collect_npm_v1_deps(
    map: &serde_json::Map<String, Value>,
    direct_dev: &std::collections::HashSet<String>,
    is_transitive: bool,
    out: &mut Vec<DepInfo>,
) {
    for (name, entry) in map {
        let Some(version) = entry.get("version").and_then(Value::as_str) else {
            continue;
        };
        let is_dev = entry.get("dev").and_then(Value::as_bool).unwrap_or(false)
            || (!is_transitive && direct_dev.contains(name));
        out.push(DepInfo {
            name: name.clone(),
            version_spec: version.to_string(),
            ecosystem: Ecosystem::Npm,
            is_dev,
            is_transitive,
        });
        if let Some(nested) = entry.get("dependencies").and_then(Value::as_object) {
            collect_npm_v1_deps(nested, direct_dev, true, out);
        }
    }
}

/// Parse pnpm-lock.yaml. Uses `packages:` map for all resolved entries (transitive),
/// and `importers.<.>.dependencies` / `devDependencies` for direct.
fn parse_pnpm_lock(lock_path: &Path, manifest_path: Option<&Path>) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(lock_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let yaml: serde_yml::Value = match serde_yml::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    let direct_dev = direct_dev_names_from_manifest(manifest_path);

    // Collect direct dep names from importers (so we can flag direct vs transitive).
    let mut direct_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    if let Some(importers) = yaml.get("importers").and_then(serde_yml::Value::as_mapping) {
        for (_imp, val) in importers {
            for section in ["dependencies", "devDependencies", "optionalDependencies"] {
                if let Some(map) = val.get(section).and_then(serde_yml::Value::as_mapping) {
                    for (name, _) in map {
                        if let Some(n) = name.as_str() {
                            direct_names.insert(n.to_string());
                        }
                    }
                }
            }
        }
    } else if let Some(root) = yaml
        .get("dependencies")
        .and_then(serde_yml::Value::as_mapping)
    {
        for (name, _) in root {
            if let Some(n) = name.as_str() {
                direct_names.insert(n.to_string());
            }
        }
    }

    if let Some(packages) = yaml.get("packages").and_then(serde_yml::Value::as_mapping) {
        for (key, _entry) in packages {
            let Some(key_str) = key.as_str() else {
                continue;
            };
            // pnpm key formats: "/name@version" or "name@version" (v9+).
            let stripped = key_str.trim_start_matches('/');
            let (name, version) = match stripped.rsplit_once('@') {
                Some((n, v)) if !n.is_empty() => {
                    (n.to_string(), v.split('(').next().unwrap_or(v).to_string())
                }
                _ => continue,
            };
            let is_transitive = !direct_names.contains(&name);
            let is_dev = !is_transitive && direct_dev.contains(&name);
            deps.push(DepInfo {
                name,
                version_spec: version,
                ecosystem: Ecosystem::Npm,
                is_dev,
                is_transitive,
            });
        }
    }
    deps
}

/// Parse yarn.lock v1 / berry. Each entry header `pkg@spec, pkg@spec2:` followed by
/// `version "..."`. All entries are at least transitive; cross-ref against manifest
/// for direct-flag.
fn parse_yarn_lock(lock_path: &Path, manifest_path: Option<&Path>) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(lock_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let direct = direct_names_from_manifest(manifest_path);
    let direct_dev = direct_dev_names_from_manifest(manifest_path);

    let mut deps = Vec::new();
    let mut current_names: Vec<String> = Vec::new();
    for raw_line in content.lines() {
        let line = raw_line;
        if line.is_empty() || line.starts_with('#') {
            current_names.clear();
            continue;
        }
        let trimmed_left = line.trim_start();
        let indent = line.len() - trimmed_left.len();
        if indent == 0 && trimmed_left.ends_with(':') {
            // Header line like: "lodash@^4.17.0, lodash@^4.17.21:"
            let header = trimmed_left.trim_end_matches(':');
            current_names = header
                .split(',')
                .filter_map(|sel| {
                    let sel = sel.trim().trim_matches('"');
                    // Yarn berry resolution keys: name@npm:1.2.3 — strip the @<spec> part.
                    let at_idx = if sel.starts_with('@') {
                        sel[1..].find('@').map(|i| i + 1)
                    } else {
                        sel.find('@')
                    };
                    at_idx.map(|i| sel[..i].to_string())
                })
                .collect();
        } else if indent > 0 && trimmed_left.starts_with("version ") && !current_names.is_empty() {
            let ver = trimmed_left
                .trim_start_matches("version ")
                .trim()
                .trim_matches('"')
                .to_string();
            // Use the first name from the header as the canonical name.
            let name = current_names[0].clone();
            let is_transitive = !direct.contains(&name);
            let is_dev = !is_transitive && direct_dev.contains(&name);
            deps.push(DepInfo {
                name,
                version_spec: ver,
                ecosystem: Ecosystem::Npm,
                is_dev,
                is_transitive,
            });
            current_names.clear();
        }
    }
    deps
}

/// Parse the project manifest (package.json) for direct deps. Used as a fallback
/// when no lockfile exists.
fn parse_npm_manifest(manifest_path: &Path) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let is_dev = section == "devDependencies";
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, version) in obj {
                if let Some(ver) = version.as_str() {
                    deps.push(DepInfo {
                        name: name.clone(),
                        version_spec: ver.to_string(),
                        ecosystem: Ecosystem::Npm,
                        is_dev,
                        is_transitive: false,
                    });
                }
            }
        }
    }
    deps
}

/// Parse composer.lock. `packages` and `packages-dev` arrays. All entries are
/// the resolved transitive closure; cross-ref composer.json for direct-flag.
fn parse_composer_lock(lock_path: &Path, manifest_path: Option<&Path>) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(lock_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let direct = direct_names_from_composer_manifest(manifest_path);
    let mut deps = Vec::new();
    for (section, is_dev_section) in [("packages", false), ("packages-dev", true)] {
        if let Some(arr) = json.get(section).and_then(Value::as_array) {
            for entry in arr {
                let Some(name) = entry.get("name").and_then(Value::as_str) else {
                    continue;
                };
                if !name.contains('/')
                    || name == "php"
                    || name.starts_with("ext-")
                    || name.starts_with("lib-")
                {
                    continue;
                }
                let Some(version) = entry.get("version").and_then(Value::as_str) else {
                    continue;
                };
                let is_transitive = !direct.contains(name);
                deps.push(DepInfo {
                    name: name.to_string(),
                    version_spec: version.to_string(),
                    ecosystem: Ecosystem::Composer,
                    is_dev: is_dev_section,
                    is_transitive,
                });
            }
        }
    }
    deps
}

/// Parse composer.json (fallback when no lock).
fn parse_composer_manifest(manifest_path: &Path) -> Vec<DepInfo> {
    let content = match std::fs::read_to_string(manifest_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let mut deps = Vec::new();
    for section in ["require", "require-dev"] {
        let is_dev = section == "require-dev";
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, version) in obj {
                if name == "php"
                    || name.starts_with("ext-")
                    || name.starts_with("lib-")
                    || !name.contains('/')
                {
                    continue;
                }
                if let Some(ver) = version.as_str() {
                    deps.push(DepInfo {
                        name: name.clone(),
                        version_spec: ver.to_string(),
                        ecosystem: Ecosystem::Composer,
                        is_dev,
                        is_transitive: false,
                    });
                }
            }
        }
    }
    deps
}

fn direct_names_from_manifest(manifest_path: Option<&Path>) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let Some(path) = manifest_path else {
        return names;
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return names;
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return names;
    };
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, _) in obj {
                names.insert(name.clone());
            }
        }
    }
    names
}

fn direct_dev_names_from_manifest(
    manifest_path: Option<&Path>,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let Some(path) = manifest_path else {
        return names;
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return names;
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return names;
    };
    if let Some(obj) = json.get("devDependencies").and_then(Value::as_object) {
        for (name, _) in obj {
            names.insert(name.clone());
        }
    }
    names
}

fn direct_names_from_composer_manifest(
    manifest_path: Option<&Path>,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let Some(path) = manifest_path else {
        return names;
    };
    let Ok(content) = std::fs::read_to_string(path) else {
        return names;
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return names;
    };
    for section in ["require", "require-dev"] {
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, _) in obj {
                names.insert(name.clone());
            }
        }
    }
    names
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Ecosystem {
    Npm,
    Composer,
}

#[derive(Debug, Clone)]
pub(crate) struct DepInfo {
    pub name: String,
    pub version_spec: String,
    pub ecosystem: Ecosystem,
    /// True if this dep is a dev/test-only dependency (devDependencies, packages-dev).
    pub is_dev: bool,
    /// True if this dep is a transitive (indirect) dependency resolved through a lockfile.
    /// False if declared directly in the project manifest.
    pub is_transitive: bool,
}

async fn check_npm_packages(
    client: Client,
    deps: Vec<DepInfo>,
    dir: &Path,
    sem: Arc<Semaphore>,
) -> Vec<AuditFinding> {
    let file_path = dir.join("package.json").to_string_lossy().to_string();
    let mut tasks = tokio::task::JoinSet::new();
    for dep in deps {
        let client = client.clone();
        let sem = sem.clone();
        let file_path = file_path.clone();
        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return Vec::new(),
            };
            check_one_npm_package(&client, &dep, &file_path).await
        });
    }
    let mut findings = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(mut f) = res {
            findings.append(&mut f);
        }
    }
    findings
}

async fn check_one_npm_package(
    client: &Client,
    dep: &DepInfo,
    file_path: &str,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let url = format!("https://registry.npmjs.org/{}", dep.name);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    if response.status().as_u16() == 404 {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: None,
            rule_id: "deep-package-not-found".to_string(),
            severity: Severity::Critical,
            description: format!(
                "Package '{}' does not exist on the npm registry. It may be hallucinated by an AI code generator or a typosquat attempt",
                dep.name
            ),
            matched_pattern: "package not found on registry".to_string(),
            context_lines: vec![format!(
                "Remove '{}' from package.json or verify the correct package name",
                dep.name
            )],
        });
        return findings;
    }

    if !response.status().is_success() {
        return findings;
    }

    let body: Value = match response.json().await {
        Ok(v) => v,
        Err(_) => return findings,
    };

    let is_trusted = TRUSTED_NPM_PACKAGES.iter().any(|&t| t == dep.name);
    if let Some(time) = body.get("time").and_then(Value::as_object) {
        if let Some(latest_version) = body
            .get("dist-tags")
            .and_then(|d| d.get("latest"))
            .and_then(Value::as_str)
        {
            if let Some(publish_date) = time.get(latest_version).and_then(Value::as_str) {
                if let Some(age_hours) = parse_age_hours(publish_date) {
                    if age_hours < 168 && !is_trusted {
                        findings.push(AuditFinding {
                            file_path: file_path.to_string(),
                            line_number: None,
                            rule_id: "deep-version-too-new".to_string(),
                            severity: Severity::High,
                            description: format!(
                                "Latest version of '{}' (v{}) was published only {} hours ago ({} days). New versions may contain malicious code from compromised credentials",
                                dep.name,
                                latest_version,
                                age_hours,
                                age_hours / 24
                            ),
                            matched_pattern: "version published recently".to_string(),
                            context_lines: vec![format!(
                                "Pin to an older version or wait until the version is at least 7 days old"
                            )],
                        });
                    }
                }
            }
        }

        if let Some(created) = time.get("created").and_then(Value::as_str) {
            if let Some(age_hours) = parse_age_hours(created) {
                if age_hours < 720 {
                    let age_days = age_hours / 24;
                    findings.push(AuditFinding {
                        file_path: file_path.to_string(),
                        line_number: None,
                        rule_id: "deep-new-package".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "Package '{}' was first published {} days ago. New packages are higher risk — verify this is legitimate",
                            dep.name, age_days
                        ),
                        matched_pattern: "recently created package".to_string(),
                        context_lines: vec![format!(
                            "Check {} on n{}.com and its source repository before depending on it",
                            dep.name, "pmjs"
                        )],
                    });
                }
            }
        }
    }

    // Download-count check: only for direct deps. Transitive low-download isn't actionable —
    // you can't drop a transitive — and api.npmjs.org/downloads has a tighter rate limit (~5 r/s).
    if !dep.is_transitive {
        let dl_url = format!(
            "https://api.npmjs.org/downloads/point/last-week/{}",
            dep.name
        );
        if let Ok(dl_response) = client.get(&dl_url).send().await {
            if let Ok(dl_body) = dl_response.json::<Value>().await {
                if let Some(downloads) = dl_body.get("downloads").and_then(Value::as_u64) {
                    if downloads < 100 {
                        findings.push(AuditFinding {
                            file_path: file_path.to_string(),
                            line_number: None,
                            rule_id: "deep-low-downloads".to_string(),
                            severity: Severity::Medium,
                            description: format!(
                                "Package '{}' has only {} weekly downloads. Low-download packages may be typosquats or hallucinated names",
                                dep.name, downloads
                            ),
                            matched_pattern: "low download count".to_string(),
                            context_lines: vec![format!(
                                "Verify '{}' is the correct package name and not a typosquat",
                                dep.name
                            )],
                        });
                    }
                }
            }
        }
    }

    findings
}

async fn check_composer_packages(
    client: Client,
    deps: Vec<DepInfo>,
    dir: &Path,
    sem: Arc<Semaphore>,
) -> Vec<AuditFinding> {
    let file_path = dir.join("composer.json").to_string_lossy().to_string();
    let mut tasks = tokio::task::JoinSet::new();
    for dep in deps {
        let client = client.clone();
        let sem = sem.clone();
        let file_path = file_path.clone();
        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => return Vec::new(),
            };
            check_one_composer_package(&client, &dep, &file_path).await
        });
    }
    let mut findings = Vec::new();
    while let Some(res) = tasks.join_next().await {
        if let Ok(mut f) = res {
            findings.append(&mut f);
        }
    }
    findings
}

async fn check_one_composer_package(
    client: &Client,
    dep: &DepInfo,
    file_path: &str,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let url = format!("https://repo.packagist.org/p2/{}.json", dep.name);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    if response.status().as_u16() == 404 {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: None,
            rule_id: "deep-package-not-found".to_string(),
            severity: Severity::Critical,
            description: format!(
                "Package '{}' does not exist on Packagist. It may be hallucinated by an AI code generator",
                dep.name
            ),
            matched_pattern: "package not found on registry".to_string(),
            context_lines: vec![format!(
                "Remove '{}' from composer.json or verify the correct package name",
                dep.name
            )],
        });
        return findings;
    }

    if !response.status().is_success() {
        return findings;
    }

    let _body: Value = match response.json().await {
        Ok(v) => v,
        Err(_) => return findings,
    };

    // Download-count check: only for direct deps (same rationale as npm).
    if !dep.is_transitive {
        let stats_url = format!("https://packagist.org/packages/{}/stats.json", dep.name);
        if let Ok(stats_response) = client.get(&stats_url).send().await {
            if let Ok(stats_body) = stats_response.json::<Value>().await {
                if let Some(downloads) = stats_body
                    .get("downloads")
                    .and_then(|d| d.get("total"))
                    .and_then(Value::as_u64)
                {
                    if downloads < 100 {
                        findings.push(AuditFinding {
                            file_path: file_path.to_string(),
                            line_number: None,
                            rule_id: "deep-low-downloads".to_string(),
                            severity: Severity::Medium,
                            description: format!(
                                "Package '{}' has only {} total downloads on Packagist. Low-download packages may be typosquats",
                                dep.name, downloads
                            ),
                            matched_pattern: "low download count".to_string(),
                            context_lines: vec![format!(
                                "Verify '{}' is the correct package name",
                                dep.name
                            )],
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Parse an RFC 3339 / ISO 8601 date string and return the age in hours relative to now.
fn parse_age_hours(date_str: &str) -> Option<u64> {
    parse_age_hours_at(date_str, Utc::now())
}

fn parse_age_hours_at(date_str: &str, now: DateTime<Utc>) -> Option<u64> {
    let parsed = DateTime::parse_from_rfc3339(date_str.trim()).ok()?;
    let diff = now.signed_duration_since(parsed.with_timezone(&Utc));
    if diff.num_seconds() < 0 {
        return Some(0);
    }
    Some(diff.num_hours() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn now_fixed() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 13, 12, 0, 0).unwrap()
    }

    #[test]
    fn parse_age_zero_when_published_now() {
        let age = parse_age_hours_at("2026-05-13T12:00:00Z", now_fixed());
        assert_eq!(age, Some(0));
    }

    #[test]
    fn parse_age_one_day() {
        let age = parse_age_hours_at("2026-05-12T12:00:00Z", now_fixed());
        assert_eq!(age, Some(24));
    }

    #[test]
    fn parse_age_seven_days_threshold() {
        // Exactly 7 days = 168 hours — the version-age cooldown threshold.
        let age = parse_age_hours_at("2026-05-06T12:00:00Z", now_fixed());
        assert_eq!(age, Some(168));
    }

    #[test]
    fn parse_age_future_returns_zero() {
        let age = parse_age_hours_at("2026-05-14T12:00:00Z", now_fixed());
        assert_eq!(age, Some(0));
    }

    #[test]
    fn parse_age_handles_subsecond_precision() {
        // Subsecond precision is parsed correctly; truncation to whole hours rounds down.
        // 2026-05-12T11:59:59.500Z is just under 24h before now → 24h floor.
        let age = parse_age_hours_at("2026-05-12T11:59:59.500Z", now_fixed());
        assert_eq!(age, Some(24));
    }

    #[test]
    fn parse_age_handles_timezone_offset() {
        // 2026-05-12T08:00:00-04:00 == 2026-05-12T12:00:00Z
        let age = parse_age_hours_at("2026-05-12T08:00:00-04:00", now_fixed());
        assert_eq!(age, Some(24));
    }

    #[test]
    fn parse_age_rejects_malformed() {
        assert_eq!(parse_age_hours_at("not a date", now_fixed()), None);
        assert_eq!(parse_age_hours_at("", now_fixed()), None);
        assert_eq!(parse_age_hours_at("2026-05-13", now_fixed()), None);
    }

    /// REGRESSION: month boundary correctness — the old custom parser used a hand-rolled
    /// month-offset lookup with year-1969/4 leap math that mishandled centuries.
    /// chrono::DateTime handles these correctly.
    #[test]
    fn parse_age_leap_year_feb_29() {
        let now = Utc.with_ymd_and_hms(2028, 3, 1, 0, 0, 0).unwrap();
        let age = parse_age_hours_at("2028-02-29T00:00:00Z", now);
        assert_eq!(age, Some(24));
    }

    #[test]
    fn parse_age_year_boundary() {
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let age = parse_age_hours_at("2025-12-31T00:00:00Z", now);
        assert_eq!(age, Some(24));
    }

    // ---- Lockfile parser tests (A3) ----

    use std::io::Write;
    use tempfile::TempDir;

    fn write_file(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn npm_package_lock_v3_marks_transitives() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "package.json",
            r#"{"name":"x","dependencies":{"left-pad":"^1.0.0"},"devDependencies":{"jest":"^29.0.0"}}"#,
        );
        write_file(
            dir.path(),
            "package-lock.json",
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name":"x"},
                    "node_modules/left-pad": {"version":"1.3.0"},
                    "node_modules/jest": {"version":"29.5.0","dev":true},
                    "node_modules/lodash": {"version":"4.17.21"}
                }
            }"#,
        );
        let deps = parse_npm_package_lock(
            &dir.path().join("package-lock.json"),
            Some(&dir.path().join("package.json")),
        );
        assert_eq!(deps.len(), 3);
        let left_pad = deps.iter().find(|d| d.name == "left-pad").unwrap();
        assert!(!left_pad.is_transitive);
        assert!(!left_pad.is_dev);
        let jest = deps.iter().find(|d| d.name == "jest").unwrap();
        assert!(!jest.is_transitive);
        assert!(jest.is_dev);
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        // lodash is not in manifest → transitive
        assert!(lodash.is_transitive);
    }

    #[test]
    fn composer_lock_packages_dev_marked_dev() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.json",
            r#"{"require":{"laravel/framework":"^12.0"},"require-dev":{"phpunit/phpunit":"^11.0"}}"#,
        );
        write_file(
            dir.path(),
            "composer.lock",
            r#"{
                "packages": [
                    {"name":"laravel/framework","version":"v12.5.0"},
                    {"name":"symfony/console","version":"v7.1.0"}
                ],
                "packages-dev": [
                    {"name":"phpunit/phpunit","version":"11.2.0"},
                    {"name":"nikic/php-parser","version":"v5.0.0"}
                ]
            }"#,
        );
        let deps = parse_composer_lock(
            &dir.path().join("composer.lock"),
            Some(&dir.path().join("composer.json")),
        );
        assert_eq!(deps.len(), 4);

        let laravel = deps.iter().find(|d| d.name == "laravel/framework").unwrap();
        assert!(!laravel.is_dev);
        assert!(!laravel.is_transitive);

        // symfony/console is in lock packages but NOT in composer.json require → transitive prod dep
        let symfony = deps.iter().find(|d| d.name == "symfony/console").unwrap();
        assert!(!symfony.is_dev);
        assert!(symfony.is_transitive);

        // phpunit is in lock packages-dev AND in composer.json require-dev → direct dev dep
        let phpunit = deps.iter().find(|d| d.name == "phpunit/phpunit").unwrap();
        assert!(phpunit.is_dev);
        assert!(!phpunit.is_transitive);

        // nikic/php-parser is in packages-dev but NOT in composer.json require-dev → transitive dev
        let nikic = deps.iter().find(|d| d.name == "nikic/php-parser").unwrap();
        assert!(nikic.is_dev);
        assert!(nikic.is_transitive);
    }

    #[test]
    fn npm_manifest_fallback_when_no_lockfile() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"react":"^18.0.0"},"devDependencies":{"vitest":"^1.0.0"}}"#,
        );
        let deps = collect_audit_deps(dir.path());
        assert_eq!(deps.len(), 2);
        assert!(deps.iter().all(|d| !d.is_transitive));
        let vitest = deps.iter().find(|d| d.name == "vitest").unwrap();
        assert!(vitest.is_dev);
    }

    #[test]
    fn composer_skips_platform_packages() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.lock",
            r#"{
                "packages": [
                    {"name":"laravel/framework","version":"v12.0.0"},
                    {"name":"php","version":"8.4.0"},
                    {"name":"ext-mbstring","version":"*"},
                    {"name":"lib-openssl","version":"*"}
                ],
                "packages-dev": []
            }"#,
        );
        let deps = parse_composer_lock(&dir.path().join("composer.lock"), None);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].name, "laravel/framework");
    }

    #[test]
    fn yarn_lock_emits_resolved_versions() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"^4.17.0"}}"#,
        );
        write_file(
            dir.path(),
            "yarn.lock",
            "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.21:\n  version \"4.17.21\"\n  integrity sha512-x\n\nleft-pad@^1.3.0:\n  version \"1.3.0\"\n",
        );
        let deps = parse_yarn_lock(
            &dir.path().join("yarn.lock"),
            Some(&dir.path().join("package.json")),
        );
        let lodash = deps.iter().find(|d| d.name == "lodash").unwrap();
        assert_eq!(lodash.version_spec, "4.17.21");
        assert!(!lodash.is_transitive); // in manifest
        let left_pad = deps.iter().find(|d| d.name == "left-pad").unwrap();
        assert!(left_pad.is_transitive); // not in manifest
    }

    #[test]
    fn pnpm_lock_marks_transitives() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"vite":"^5.0.0"}}"#,
        );
        write_file(
            dir.path(),
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\n\nimporters:\n  .:\n    dependencies:\n      vite:\n        specifier: ^5.0.0\n        version: 5.0.10\n\npackages:\n  vite@5.0.10:\n    resolution: {integrity: sha512-x}\n  esbuild@0.19.5:\n    resolution: {integrity: sha512-y}\n",
        );
        let deps = parse_pnpm_lock(
            &dir.path().join("pnpm-lock.yaml"),
            Some(&dir.path().join("package.json")),
        );
        let vite = deps.iter().find(|d| d.name == "vite").unwrap();
        assert!(!vite.is_transitive);
        let esbuild = deps.iter().find(|d| d.name == "esbuild").unwrap();
        assert!(esbuild.is_transitive);
    }

    #[tokio::test]
    async fn semaphore_caps_concurrent_fetches() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let limit = 4;
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let sem = Arc::new(Semaphore::new(limit));

        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..50 {
            let sem = sem.clone();
            let active = active.clone();
            let peak = peak.clone();
            tasks.spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                let mut p = peak.load(Ordering::SeqCst);
                while now > p {
                    match peak.compare_exchange(p, now, Ordering::SeqCst, Ordering::SeqCst) {
                        Ok(_) => break,
                        Err(observed) => p = observed,
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                active.fetch_sub(1, Ordering::SeqCst);
            });
        }
        while let Some(res) = tasks.join_next().await {
            res.unwrap();
        }
        let observed_peak = peak.load(Ordering::SeqCst);
        assert!(
            observed_peak <= limit,
            "semaphore violation: peak={observed_peak} limit={limit}"
        );
    }

    #[test]
    fn collect_audit_deps_prefers_lockfile_over_manifest() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "package.json",
            r#"{"dependencies":{"left-pad":"^1.0.0"}}"#,
        );
        write_file(
            dir.path(),
            "package-lock.json",
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name":"x"},
                    "node_modules/left-pad": {"version":"1.3.0"},
                    "node_modules/lodash": {"version":"4.17.21"}
                }
            }"#,
        );
        let deps = collect_audit_deps(dir.path());
        // Should see lodash (transitive from lock), not just left-pad
        assert!(deps.iter().any(|d| d.name == "lodash" && d.is_transitive));
        assert!(deps
            .iter()
            .any(|d| d.name == "left-pad" && !d.is_transitive));
    }
}
