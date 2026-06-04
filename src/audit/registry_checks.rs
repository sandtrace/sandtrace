//! Deep registry checks: verify packages exist, check version age,
//! download counts, and known vulnerabilities via registry APIs.
//!
//! Only runs when `--deep` flag is passed (requires network access).

use crate::audit::registry_cache::{self, RegistryMeta};
use crate::event::{AuditFinding, Severity};
use chrono::{DateTime, Utc};
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Build a progress bar gated on stderr being a TTY. Returns a hidden bar
/// when not a terminal (CI logs, redirected output) so `.inc()` is a no-op.
fn deep_check_progress(label: &str, total: u64) -> ProgressBar {
    if !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let pb = ProgressBar::new(total);
    let style =
        ProgressStyle::with_template("  {prefix:>9.cyan} [{bar:30.green/dim}] {pos}/{len} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("=>-");
    pb.set_style(style);
    pb.set_prefix(label.to_string());
    pb
}

/// Per-registry concurrency limits. These are conservative caps based on each
/// registry's documented or observed rate limits:
/// - npm: registry.npmjs.org is CDN-backed and tolerates heavy concurrency
/// - packagist: documented at 60 req/sec for the public API
/// - api.npmjs.org/downloads: ~5 req/sec unauthenticated — handled separately
const NPM_CONCURRENCY: usize = 16;
const PACKAGIST_CONCURRENCY: usize = 32;

/// Registry base URL accessors. Tests override these via env vars to point
/// at a wiremock instance instead of the public registry.
fn npm_registry_base() -> String {
    std::env::var("SANDTRACE_NPM_REGISTRY")
        .unwrap_or_else(|_| "https://registry.npmjs.org".to_string())
}

fn npm_downloads_base() -> String {
    std::env::var("SANDTRACE_NPM_DOWNLOADS")
        .unwrap_or_else(|_| "https://api.npmjs.org/downloads/point/last-week".to_string())
}

/// Collect npm scopes that `.npmrc` maps to a non-default registry, e.g.
/// `@cc-consulting-nv:registry=https://npm.pkg.github.com`. Such scopes resolve
/// to a private registry that the public-npm existence check cannot see, so a
/// 404 there is not a typosquat — it must not produce deep-package-not-found.
/// Returns scopes WITH the leading `@` (e.g. "@cc-consulting-nv").
fn private_npm_scopes(dir: &Path) -> HashSet<String> {
    let mut scopes = HashSet::new();
    let Ok(content) = std::fs::read_to_string(dir.join(".npmrc")) else {
        return scopes;
    };
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        // Match `@scope:registry=<url>`
        if let Some((key, _val)) = line.split_once('=') {
            let key = key.trim();
            if let Some(scope) = key.strip_suffix(":registry") {
                if scope.starts_with('@') {
                    scopes.insert(scope.to_string());
                }
            }
        }
    }
    scopes
}

/// True if `pkg` belongs to one of the private scopes (matches `@scope/...`).
fn is_private_scoped(pkg: &str, private_scopes: &HashSet<String>) -> bool {
    if let Some((scope, _rest)) = pkg.split_once('/') {
        private_scopes.contains(scope)
    } else {
        false
    }
}

/// Extract a Composer `vendor/name` slug from a VCS/git/path repository URL,
/// e.g. `https://github.com/cc-consulting-nv/laravel-cc-blog.git`
/// -> `cc-consulting-nv/laravel-cc-blog`. Returns lowercase (Composer package
/// names are case-insensitive). Handles `scp`-style git URLs
/// (`git@github.com:vendor/name.git`) and trailing slashes. Returns None when
/// the last two path segments can't be recovered.
fn composer_slug_from_repo_url(url: &str) -> Option<String> {
    // Strip a scheme (`https://`, `git://`, `ssh://`) or scp-style `user@host:`.
    let rest = if let Some((_scheme, after)) = url.split_once("://") {
        after
    } else if let Some((_user_host, after)) = url.split_once(':') {
        // scp-style `git@github.com:vendor/name.git`
        after
    } else {
        url
    };
    let trimmed = rest.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let segments: Vec<&str> = trimmed.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() < 2 {
        return None;
    }
    let name = segments[segments.len() - 1];
    let vendor = segments[segments.len() - 2];
    Some(format!("{}/{}", vendor, name).to_lowercase())
}

/// Collect Composer package names sourced from a declared non-Packagist
/// `repositories` entry (vcs / git / github / gitlab / bitbucket / path /
/// inline package). Such packages resolve from a private VCS/path source that
/// the public-Packagist existence check cannot see, so a 404 there is not a
/// hallucination — it must not produce deep-package-not-found.
///
/// For URL-bearing repos (vcs/git/path/...), the `vendor/name` slug is derived
/// from the URL; for inline `{"type":"package", "package":{"name":...}}` repos
/// the declared name is used directly. Names are stored lowercased to match
/// Composer's case-insensitive package names.
fn private_composer_packages(dir: &Path) -> HashSet<String> {
    let mut names = HashSet::new();
    let Ok(content) = std::fs::read_to_string(dir.join("composer.json")) else {
        return names;
    };
    let Ok(json) = serde_json::from_str::<Value>(&content) else {
        return names;
    };

    // `repositories` may be an array of repo objects, or an object keyed by
    // repo name (Composer accepts both). Normalize to an iterator of values.
    let repos: Vec<&Value> = match json.get("repositories") {
        Some(Value::Array(arr)) => arr.iter().collect(),
        Some(Value::Object(obj)) => obj.values().collect(),
        _ => return names,
    };

    // URL-bearing repository types whose packages live outside Packagist.
    const URL_REPO_TYPES: &[&str] = &["vcs", "git", "github", "gitlab", "bitbucket", "path"];

    for repo in repos {
        // `{"packagist.org": false}` disables the default repo; it carries no
        // package of its own — skip without erroring.
        let Some(repo_type) = repo.get("type").and_then(Value::as_str) else {
            continue;
        };

        if URL_REPO_TYPES.contains(&repo_type) {
            if let Some(url) = repo.get("url").and_then(Value::as_str) {
                if let Some(slug) = composer_slug_from_repo_url(url) {
                    names.insert(slug);
                }
            }
        } else if repo_type == "package" {
            // Inline package definition declares the name directly.
            if let Some(name) = repo
                .get("package")
                .and_then(|p| p.get("name"))
                .and_then(Value::as_str)
            {
                names.insert(name.to_lowercase());
            }
        }
    }
    names
}

fn packagist_base() -> String {
    std::env::var("SANDTRACE_PACKAGIST")
        .unwrap_or_else(|_| "https://repo.packagist.org".to_string())
}

fn packagist_stats_base() -> String {
    std::env::var("SANDTRACE_PACKAGIST_STATS")
        .unwrap_or_else(|_| "https://packagist.org".to_string())
}

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

/// Per-package check result. `fetch_failed=true` indicates a transient
/// registry error (5xx, timeout, network) — NOT a 404, which is itself a
/// legitimate finding (deep-package-not-found).
struct CheckResult {
    findings: Vec<AuditFinding>,
    fetch_failed: bool,
}

async fn check_npm_packages(
    client: Client,
    deps: Vec<DepInfo>,
    dir: &Path,
    sem: Arc<Semaphore>,
) -> Vec<AuditFinding> {
    let file_path = dir.join("package.json").to_string_lossy().to_string();
    let private_scopes = Arc::new(private_npm_scopes(dir));
    let mut tasks = tokio::task::JoinSet::new();
    let total = deps.len();
    let progress = deep_check_progress("npm", total as u64);
    for dep in deps {
        let client = client.clone();
        let sem = sem.clone();
        let file_path = file_path.clone();
        let private_scopes = private_scopes.clone();
        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    return CheckResult {
                        findings: Vec::new(),
                        fetch_failed: true,
                    };
                }
            };
            check_one_npm_package(&client, &dep, &file_path, &private_scopes).await
        });
    }
    let mut findings = Vec::new();
    let mut failed = 0usize;
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(mut r) => {
                findings.append(&mut r.findings);
                if r.fetch_failed {
                    failed += 1;
                }
            }
            Err(_) => failed += 1,
        }
        progress.inc(1);
    }
    progress.finish_and_clear();
    if let Some(f) = partial_scan_finding("npm", failed, total, &file_path) {
        findings.push(f);
    }
    findings
}

async fn check_one_npm_package(
    client: &Client,
    dep: &DepInfo,
    file_path: &str,
    private_scopes: &HashSet<String>,
) -> CheckResult {
    let is_trusted = TRUSTED_NPM_PACKAGES.iter().any(|&t| t == dep.name);

    // Packages in a privately-scoped registry (per .npmrc) can't be verified
    // against public npm. Skip the deep checks entirely rather than false-flag
    // a legitimate private package as a typosquat.
    if is_private_scoped(&dep.name, private_scopes) {
        return CheckResult {
            findings: Vec::new(),
            fetch_failed: false,
        };
    }

    // Transitive + trusted: skip the registry entirely. Trust here is on volume —
    // these packages publish constantly with huge weekly downloads; the existence
    // check, age check, and download check would all be no-ops. The package
    // tarball still gets scanned for obfuscation/behavior in the non-deep audit.
    if is_trusted && dep.is_transitive {
        return CheckResult {
            findings: Vec::new(),
            fetch_failed: false,
        };
    }

    // Cache hit: use stored RFC 3339 dates, recompute age now. No HTTP.
    let meta = if let Some(cached) = registry_cache::read("npm", &dep.name) {
        cached
    } else {
        match fetch_npm_meta(client, &dep.name).await {
            FetchOutcome::Missing => {
                return CheckResult {
                    findings: vec![AuditFinding {
                        file_path: file_path.to_string(),
                        line_number: None,
                        rule_id: "deep-package-not-found".to_string(),
                        severity: demote_for_dev(Severity::Critical, dep.is_dev),
                        description: format!(
                            "Package '{}' does not exist on the npm registry. It may be hallucinated by an AI code generator or a typosquat attempt",
                            dep.name
                        ),
                        matched_pattern: "package not found on registry".to_string(),
                        context_lines: vec![format!(
                            "Remove '{}' from package.json or verify the correct package name",
                            dep.name
                        )],
                    }],
                    fetch_failed: false,
                };
            }
            FetchOutcome::Error => {
                return CheckResult {
                    findings: Vec::new(),
                    fetch_failed: true,
                };
            }
            FetchOutcome::Ok(m) => {
                registry_cache::write(&m);
                m
            }
        }
    };

    CheckResult {
        findings: findings_from_npm_meta(&meta, dep, file_path),
        fetch_failed: false,
    }
}

/// Graduated partial-scan finding. Bucketed by failure-rate:
/// - <50%: Info — registry hiccups are normal, surface for visibility
/// - >=50%: Medium — audit is half-blind, attacker timing window real
/// - >=90%: High — effectively no signal, CI should fail
fn partial_scan_finding(
    registry: &str,
    failed: usize,
    total: usize,
    file_path: &str,
) -> Option<AuditFinding> {
    if failed == 0 || total == 0 {
        return None;
    }
    let pct = (failed * 100) / total;
    let severity = if pct >= 90 {
        Severity::High
    } else if pct >= 50 {
        Severity::Medium
    } else {
        Severity::Info
    };
    Some(AuditFinding {
        file_path: file_path.to_string(),
        line_number: None,
        rule_id: "deep-partial-scan".to_string(),
        severity,
        description: format!(
            "Deep check partial scan: {}/{} {} packages unreachable ({}%). Findings below may be incomplete; transient registry errors hide real risks during the gap",
            failed, total, registry, pct
        ),
        matched_pattern: "registry fetch failures".to_string(),
        context_lines: vec![
            format!("Re-run with network access restored, or trust the partial result if registry is known-down."),
            format!("Cache (~/.cache/sandtrace/registry-meta) entries skip HTTP for fresh keys."),
        ],
    })
}

enum FetchOutcome {
    Ok(RegistryMeta),
    Missing,
    Error,
}

async fn fetch_npm_meta(client: &Client, name: &str) -> FetchOutcome {
    let url = format!("{}/{}", npm_registry_base(), name);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => return FetchOutcome::Error,
    };
    if response.status().as_u16() == 404 {
        return FetchOutcome::Missing;
    }
    if !response.status().is_success() {
        return FetchOutcome::Error;
    }
    let body: Value = match response.json().await {
        Ok(v) => v,
        Err(_) => return FetchOutcome::Error,
    };
    let mut meta = RegistryMeta {
        registry: "npm".to_string(),
        name: name.to_string(),
        cached_at: Utc::now(),
        latest_version: None,
        latest_publish_date: None,
        created_date: None,
        weekly_downloads: None,
    };
    if let Some(time) = body.get("time").and_then(Value::as_object) {
        if let Some(latest_version) = body
            .get("dist-tags")
            .and_then(|d| d.get("latest"))
            .and_then(Value::as_str)
        {
            meta.latest_version = Some(latest_version.to_string());
            if let Some(pub_date) = time.get(latest_version).and_then(Value::as_str) {
                meta.latest_publish_date = DateTime::parse_from_rfc3339(pub_date)
                    .ok()
                    .map(|d| d.with_timezone(&Utc));
            }
        }
        if let Some(created) = time.get("created").and_then(Value::as_str) {
            meta.created_date = DateTime::parse_from_rfc3339(created)
                .ok()
                .map(|d| d.with_timezone(&Utc));
        }
    }
    // Weekly downloads — only fetched here on cache miss; only used for direct deps later.
    let dl_url = format!("{}/{}", npm_downloads_base(), name);
    if let Ok(dl_response) = client.get(&dl_url).send().await {
        if let Ok(dl_body) = dl_response.json::<Value>().await {
            meta.weekly_downloads = dl_body.get("downloads").and_then(Value::as_u64);
        }
    }
    FetchOutcome::Ok(meta)
}

fn findings_from_npm_meta(
    meta: &RegistryMeta,
    dep: &DepInfo,
    file_path: &str,
) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let is_trusted = TRUSTED_NPM_PACKAGES.iter().any(|&t| t == dep.name);

    if let (Some(latest), Some(pub_date)) = (&meta.latest_version, meta.latest_publish_date) {
        let age_hours = age_hours_from(pub_date);
        // Only flag DIRECT deps. The check looks at the registry's *latest*
        // version age, not the lockfile-pinned version actually installed. For
        // transitive deps (which the user doesn't choose), a freshly-published
        // upstream release is noise — it fires on every healthy, actively
        // maintained package and is unusable as a gate.
        if age_hours < 168 && !is_trusted && !dep.is_transitive {
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: None,
                rule_id: "deep-version-too-new".to_string(),
                severity: demote_for_dev(Severity::High, dep.is_dev),
                description: format!(
                    "Latest version of '{}' (v{}) was published only {} hours ago ({} days). New versions may contain malicious code from compromised credentials",
                    dep.name,
                    latest,
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

    if let Some(created) = meta.created_date {
        let age_hours = age_hours_from(created);
        if age_hours < 720 {
            let age_days = age_hours / 24;
            findings.push(AuditFinding {
                file_path: file_path.to_string(),
                line_number: None,
                rule_id: "deep-new-package".to_string(),
                severity: demote_for_dev(Severity::Medium, dep.is_dev),
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

    if !dep.is_transitive {
        if let Some(downloads) = meta.weekly_downloads {
            if downloads < 100 {
                findings.push(AuditFinding {
                    file_path: file_path.to_string(),
                    line_number: None,
                    rule_id: "deep-low-downloads".to_string(),
                    severity: demote_for_dev(Severity::Medium, dep.is_dev),
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

    findings
}

/// Demote a finding severity one step when the dep is dev-only. Dev deps don't
/// ship to prod, so their blast radius is smaller — but they still run in CI
/// and can exfiltrate secrets via postinstall, so we don't drop them entirely.
fn demote_for_dev(sev: Severity, is_dev: bool) -> Severity {
    if !is_dev {
        return sev;
    }
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Info,
        Severity::Info => Severity::Info,
    }
}

fn age_hours_from(dt: DateTime<Utc>) -> u64 {
    let diff = Utc::now().signed_duration_since(dt);
    if diff.num_seconds() < 0 {
        0
    } else {
        diff.num_hours() as u64
    }
}

async fn check_composer_packages(
    client: Client,
    deps: Vec<DepInfo>,
    dir: &Path,
    sem: Arc<Semaphore>,
) -> Vec<AuditFinding> {
    let file_path = dir.join("composer.json").to_string_lossy().to_string();
    let private_packages = Arc::new(private_composer_packages(dir));
    let mut tasks = tokio::task::JoinSet::new();
    let total = deps.len();
    let progress = deep_check_progress("packagist", total as u64);
    for dep in deps {
        let client = client.clone();
        let sem = sem.clone();
        let file_path = file_path.clone();
        let private_packages = private_packages.clone();
        tasks.spawn(async move {
            let _permit = match sem.acquire().await {
                Ok(p) => p,
                Err(_) => {
                    return CheckResult {
                        findings: Vec::new(),
                        fetch_failed: true,
                    };
                }
            };
            check_one_composer_package(&client, &dep, &file_path, &private_packages).await
        });
    }
    let mut findings = Vec::new();
    let mut failed = 0usize;
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(mut r) => {
                findings.append(&mut r.findings);
                if r.fetch_failed {
                    failed += 1;
                }
            }
            Err(_) => failed += 1,
        }
        progress.inc(1);
    }
    progress.finish_and_clear();
    if let Some(f) = partial_scan_finding("packagist", failed, total, &file_path) {
        findings.push(f);
    }
    findings
}

async fn check_one_composer_package(
    client: &Client,
    dep: &DepInfo,
    file_path: &str,
    private_packages: &HashSet<String>,
) -> CheckResult {
    let is_trusted = TRUSTED_COMPOSER_PACKAGES.iter().any(|&t| t == dep.name);

    // Packages sourced from a declared non-Packagist `repositories` entry
    // (vcs/git/path/inline package) can't be verified against public Packagist.
    // Skip the deep checks entirely rather than false-flag a legitimate private
    // package as a hallucination. Package names are case-insensitive in Composer.
    if private_packages.contains(&dep.name.to_lowercase()) {
        return CheckResult {
            findings: Vec::new(),
            fetch_failed: false,
        };
    }

    // Transitive + trusted: skip Packagist entirely (same rationale as npm).
    if is_trusted && dep.is_transitive {
        return CheckResult {
            findings: Vec::new(),
            fetch_failed: false,
        };
    }

    let mut findings = Vec::new();
    let url = format!("{}/p2/{}.json", packagist_base(), dep.name);
    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(_) => {
            return CheckResult {
                findings,
                fetch_failed: true,
            };
        }
    };

    if response.status().as_u16() == 404 {
        findings.push(AuditFinding {
            file_path: file_path.to_string(),
            line_number: None,
            rule_id: "deep-package-not-found".to_string(),
            severity: demote_for_dev(Severity::Critical, dep.is_dev),
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
        return CheckResult {
            findings,
            fetch_failed: false,
        };
    }

    if !response.status().is_success() {
        return CheckResult {
            findings,
            fetch_failed: true,
        };
    }

    let _body: Value = match response.json().await {
        Ok(v) => v,
        Err(_) => {
            return CheckResult {
                findings,
                fetch_failed: true,
            };
        }
    };

    // Download-count check: only for direct deps (same rationale as npm).
    if !dep.is_transitive {
        let stats_url = format!(
            "{}/packages/{}/stats.json",
            packagist_stats_base(),
            dep.name
        );
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
                            severity: demote_for_dev(Severity::Medium, dep.is_dev),
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

    CheckResult {
        findings,
        fetch_failed: false,
    }
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
    fn partial_scan_no_failures_returns_none() {
        assert!(partial_scan_finding("npm", 0, 100, "package.json").is_none());
    }

    #[test]
    fn partial_scan_zero_total_returns_none() {
        assert!(partial_scan_finding("npm", 0, 0, "package.json").is_none());
    }

    #[test]
    fn partial_scan_low_failure_rate_is_info() {
        // 10/100 = 10% — under 50% threshold
        let f = partial_scan_finding("npm", 10, 100, "package.json").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert_eq!(f.rule_id, "deep-partial-scan");
    }

    #[test]
    fn partial_scan_high_failure_rate_is_medium() {
        // 60/100 = 60% — >=50%, <90%
        let f = partial_scan_finding("npm", 60, 100, "package.json").unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn partial_scan_critical_failure_rate_is_high() {
        // 95/100 = 95% — >=90%, audit is effectively blind
        let f = partial_scan_finding("packagist", 95, 100, "composer.json").unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn partial_scan_boundary_exactly_50_percent() {
        let f = partial_scan_finding("npm", 5, 10, "package.json").unwrap();
        assert_eq!(f.severity, Severity::Medium);
    }

    #[test]
    fn partial_scan_boundary_exactly_90_percent() {
        let f = partial_scan_finding("npm", 9, 10, "package.json").unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    // ---- Allowlist semantics (A7) ----

    fn meta_with_dates(
        registry: &str,
        name: &str,
        latest_publish: DateTime<Utc>,
        created: DateTime<Utc>,
        downloads: Option<u64>,
    ) -> RegistryMeta {
        RegistryMeta {
            registry: registry.to_string(),
            name: name.to_string(),
            cached_at: Utc::now(),
            latest_version: Some("1.0.0".to_string()),
            latest_publish_date: Some(latest_publish),
            created_date: Some(created),
            weekly_downloads: downloads,
        }
    }

    fn dep(name: &str, is_transitive: bool, is_dev: bool) -> DepInfo {
        DepInfo {
            name: name.to_string(),
            version_spec: "1.0.0".to_string(),
            ecosystem: Ecosystem::Npm,
            is_dev,
            is_transitive,
        }
    }

    /// REGRESSION: direct + trusted skips only the age check (not existence/downloads).
    /// Behavior preserved from pre-Lane-A code.
    #[test]
    fn direct_trusted_skips_age_only() {
        let recent = Utc::now() - chrono::Duration::hours(24); // 1d old — would trigger age
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "react", recent, old, Some(50_000_000));
        let findings = findings_from_npm_meta(&meta, &dep("react", false, false), "package.json");
        // react is trusted → no age finding even though publish is 24h ago
        assert!(
            findings.iter().all(|f| f.rule_id != "deep-version-too-new"),
            "trusted direct dep should skip age check"
        );
    }

    /// REGRESSION: direct + untrusted with recent publish gets age finding (threshold preserved).
    #[test]
    fn direct_untrusted_recent_publish_flagged() {
        let recent = Utc::now() - chrono::Duration::hours(24);
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "some-rando-pkg", recent, old, Some(5_000_000));
        let findings =
            findings_from_npm_meta(&meta, &dep("some-rando-pkg", false, false), "package.json");
        assert!(
            findings.iter().any(|f| f.rule_id == "deep-version-too-new"),
            "untrusted direct dep with <168h publish should be flagged"
        );
    }

    /// Transitive deps must NOT trigger version-too-new: the check reads the
    /// registry's latest-version age, not the lockfile-pinned version, so it is
    /// noise for deps the user doesn't choose (e.g. a fresh babel release).
    #[test]
    fn transitive_recent_publish_not_flagged() {
        let recent = Utc::now() - chrono::Duration::hours(43); // babel-7.29.7 case
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "@babel/core", recent, old, Some(50_000_000));
        let findings =
            findings_from_npm_meta(&meta, &dep("@babel/core", true, false), "package.json");
        assert!(
            findings.iter().all(|f| f.rule_id != "deep-version-too-new"),
            "transitive dep with fresh upstream release must not flag version-too-new"
        );
    }

    #[test]
    fn private_scopes_parsed_from_npmrc() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            ".npmrc",
            "@cc-consulting-nv:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}\nregistry=https://registry.npmjs.org\n",
        );
        let scopes = private_npm_scopes(dir.path());
        assert!(scopes.contains("@cc-consulting-nv"));
        assert!(is_private_scoped("@cc-consulting-nv/ccsdk", &scopes));
        assert!(!is_private_scoped("react", &scopes));
        assert!(!is_private_scoped("@babel/core", &scopes));
    }

    #[test]
    fn private_scopes_empty_without_npmrc() {
        let dir = TempDir::new().unwrap();
        let scopes = private_npm_scopes(dir.path());
        assert!(scopes.is_empty());
        assert!(!is_private_scoped("@cc-consulting-nv/ccsdk", &scopes));
    }

    #[test]
    fn composer_slug_from_vcs_url_variants() {
        assert_eq!(
            composer_slug_from_repo_url("https://github.com/cc-consulting-nv/laravel-cc-blog.git")
                .as_deref(),
            Some("cc-consulting-nv/laravel-cc-blog")
        );
        // No `.git` suffix, trailing slash.
        assert_eq!(
            composer_slug_from_repo_url("https://gitlab.com/acme/widget/").as_deref(),
            Some("acme/widget")
        );
        // scp-style git URL.
        assert_eq!(
            composer_slug_from_repo_url("git@github.com:Acme/Widget.git").as_deref(),
            Some("acme/widget")
        );
        // Relative path repo.
        assert_eq!(
            composer_slug_from_repo_url("../local/my-pkg").as_deref(),
            Some("local/my-pkg")
        );
        // Too few segments -> None.
        assert_eq!(composer_slug_from_repo_url("https://example.com"), None);
    }

    #[test]
    fn private_composer_packages_from_vcs_repository() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.json",
            r#"{
                "require": { "cc-consulting-nv/laravel-cc-blog": "^1.1.6" },
                "repositories": [
                    { "type": "vcs", "url": "https://github.com/cc-consulting-nv/laravel-cc-blog.git" }
                ]
            }"#,
        );
        let pkgs = private_composer_packages(dir.path());
        assert!(pkgs.contains("cc-consulting-nv/laravel-cc-blog"));
        // A normal Packagist package is not in the private set.
        assert!(!pkgs.contains("laravel/framework"));
    }

    #[test]
    fn private_composer_packages_inline_package_type() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.json",
            r#"{
                "repositories": [
                    { "type": "package", "package": { "name": "Acme/Special", "version": "1.0.0" } }
                ]
            }"#,
        );
        let pkgs = private_composer_packages(dir.path());
        // Stored lowercased (Composer names are case-insensitive).
        assert!(pkgs.contains("acme/special"));
    }

    #[test]
    fn private_composer_packages_object_form_repositories() {
        // Composer also accepts `repositories` keyed by name.
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.json",
            r#"{
                "repositories": {
                    "blog": { "type": "vcs", "url": "https://github.com/acme/blog.git" },
                    "packagist.org": false
                }
            }"#,
        );
        let pkgs = private_composer_packages(dir.path());
        assert!(pkgs.contains("acme/blog"));
        // The `packagist.org: false` entry must not error or add a name.
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn private_composer_packages_empty_without_repositories() {
        let dir = TempDir::new().unwrap();
        write_file(
            dir.path(),
            "composer.json",
            r#"{ "require": { "laravel/framework": "^12.0" } }"#,
        );
        assert!(private_composer_packages(dir.path()).is_empty());
    }

    /// REGRESSION: download-count check still fires for direct deps.
    #[test]
    fn direct_low_downloads_flagged() {
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "obscure-pkg", old, old, Some(42));
        let findings =
            findings_from_npm_meta(&meta, &dep("obscure-pkg", false, false), "package.json");
        assert!(
            findings.iter().any(|f| f.rule_id == "deep-low-downloads"),
            "direct dep with <100 weekly downloads should be flagged"
        );
    }

    /// Transitive low-downloads is intentionally NOT flagged (you can't drop a transitive).
    #[test]
    fn transitive_low_downloads_not_flagged() {
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "obscure-pkg", old, old, Some(42));
        let findings =
            findings_from_npm_meta(&meta, &dep("obscure-pkg", true, false), "package.json");
        assert!(
            !findings.iter().any(|f| f.rule_id == "deep-low-downloads"),
            "transitive deps should not trigger low-download finding"
        );
    }

    /// Sanity check on the trusted list — make sure react is in it, since the direct
    /// allowlist test depends on this.
    #[test]
    fn trusted_npm_packages_contains_react() {
        assert!(TRUSTED_NPM_PACKAGES.contains(&"react"));
    }

    /// Trusted composer packages list contains laravel/framework.
    #[test]
    fn trusted_composer_packages_contains_laravel() {
        assert!(TRUSTED_COMPOSER_PACKAGES.contains(&"laravel/framework"));
    }

    // ---- Dev-dep severity demotion (A8) ----

    #[test]
    fn demote_for_dev_is_noop_for_prod_dep() {
        assert_eq!(
            demote_for_dev(Severity::Critical, false),
            Severity::Critical
        );
        assert_eq!(demote_for_dev(Severity::High, false), Severity::High);
        assert_eq!(demote_for_dev(Severity::Medium, false), Severity::Medium);
    }

    #[test]
    fn demote_for_dev_drops_one_step() {
        assert_eq!(demote_for_dev(Severity::Critical, true), Severity::High);
        assert_eq!(demote_for_dev(Severity::High, true), Severity::Medium);
        assert_eq!(demote_for_dev(Severity::Medium, true), Severity::Low);
        assert_eq!(demote_for_dev(Severity::Low, true), Severity::Info);
        assert_eq!(demote_for_dev(Severity::Info, true), Severity::Info);
    }

    // ---- Progress bar (A9) ----

    #[test]
    fn progress_bar_hidden_in_non_tty_env() {
        // Tests run with stderr redirected (cargo captures it). The progress
        // bar must be hidden so it does not pollute test output and `.inc()`
        // remains a no-op.
        let pb = deep_check_progress("npm", 100);
        assert!(pb.is_hidden(), "progress bar should be hidden in tests");
        // No-op inc() must not panic.
        pb.inc(1);
        pb.finish_and_clear();
    }

    /// Findings on dev deps come back at demoted severity end-to-end.
    #[test]
    fn dev_dep_finding_severity_demoted_end_to_end() {
        let recent = Utc::now() - chrono::Duration::hours(24);
        let old = Utc::now() - chrono::Duration::days(365);
        let meta = meta_with_dates("npm", "some-rando-pkg", recent, old, Some(5_000_000));
        let findings_prod =
            findings_from_npm_meta(&meta, &dep("some-rando-pkg", false, false), "package.json");
        let findings_dev =
            findings_from_npm_meta(&meta, &dep("some-rando-pkg", false, true), "package.json");
        let prod_age = findings_prod
            .iter()
            .find(|f| f.rule_id == "deep-version-too-new")
            .unwrap();
        let dev_age = findings_dev
            .iter()
            .find(|f| f.rule_id == "deep-version-too-new")
            .unwrap();
        assert_eq!(prod_age.severity, Severity::High);
        assert_eq!(dev_age.severity, Severity::Medium);
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

    // ---- End-to-end async pipeline tests via wiremock (A11) ----

    /// Coarse mutex to serialize wiremock tests because they mutate process-wide
    /// env vars (registry URL overrides, cache dir).
    static ASYNC_TEST_LOCK: Mutex<()> = Mutex::new(());

    use serde_json::json;
    use std::sync::Mutex;
    use wiremock::matchers::{method, path as wm_path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn write_project_file(dir: &std::path::Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[tokio::test]
    async fn e2e_recent_publish_flagged_via_wiremock() {
        let _guard = ASYNC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = MockServer::start().await;
        let cache_dir = TempDir::new().unwrap();
        let project_dir = TempDir::new().unwrap();
        // left-pad is a DIRECT dep here: version-too-new only flags direct deps
        // (transitive freshness is noise — see transitive_recent_publish_not_flagged).
        write_project_file(
            project_dir.path(),
            "package.json",
            r#"{"dependencies":{"lodash":"^4.0.0","left-pad":"^1.0.0"}}"#,
        );
        write_project_file(
            project_dir.path(),
            "package-lock.json",
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name":"x"},
                    "node_modules/lodash": {"version":"4.17.21"},
                    "node_modules/left-pad": {"version":"1.3.0"}
                }
            }"#,
        );

        let now = Utc::now();
        let recent = now - chrono::Duration::hours(48);
        let old = now - chrono::Duration::days(365);

        // lodash is in TRUSTED_NPM_PACKAGES → age check should be skipped
        Mock::given(method("GET"))
            .and(wm_path("/lodash"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dist-tags": {"latest": "4.17.21"},
                "time": {"created": old.to_rfc3339(), "4.17.21": recent.to_rfc3339()}
            })))
            .mount(&server)
            .await;
        // left-pad: not trusted, transitive, 48h old → version-too-new finding
        Mock::given(method("GET"))
            .and(wm_path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "dist-tags": {"latest": "1.3.0"},
                "time": {"created": old.to_rfc3339(), "1.3.0": recent.to_rfc3339()}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/downloads/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"downloads": 50_000_000})),
            )
            .mount(&server)
            .await;

        // SAFETY: ASYNC_TEST_LOCK serializes; only this test mutates env.
        unsafe {
            std::env::set_var("SANDTRACE_NPM_REGISTRY", server.uri());
            std::env::set_var(
                "SANDTRACE_NPM_DOWNLOADS",
                format!("{}/downloads", server.uri()),
            );
            std::env::set_var("SANDTRACE_CACHE_DIR", cache_dir.path());
        }
        let findings = tokio::task::spawn_blocking({
            let p = project_dir.path().to_path_buf();
            move || run_deep_checks(&p)
        })
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("SANDTRACE_NPM_REGISTRY");
            std::env::remove_var("SANDTRACE_NPM_DOWNLOADS");
            std::env::remove_var("SANDTRACE_CACHE_DIR");
        }

        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "deep-version-too-new" && f.description.contains("lodash")),
            "trusted lodash should not be flagged"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "deep-version-too-new" && f.description.contains("left-pad")),
            "untrusted direct dep with recent publish should be flagged"
        );
    }

    #[tokio::test]
    async fn e2e_partial_scan_info_at_low_failure_rate() {
        let _guard = ASYNC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = MockServer::start().await;
        let cache_dir = TempDir::new().unwrap();
        let project_dir = TempDir::new().unwrap();
        write_project_file(
            project_dir.path(),
            "package.json",
            r#"{"dependencies":{"some-rando-a":"^1","some-rando-b":"^1","some-rando-c":"^1"}}"#,
        );
        write_project_file(
            project_dir.path(),
            "package-lock.json",
            r#"{
                "lockfileVersion": 3,
                "packages": {
                    "": {"name":"x"},
                    "node_modules/some-rando-a": {"version":"1.0.0"},
                    "node_modules/some-rando-b": {"version":"1.0.0"},
                    "node_modules/some-rando-c": {"version":"1.0.0"}
                }
            }"#,
        );
        let old = Utc::now() - chrono::Duration::days(365);
        let ok_body = json!({
            "dist-tags": {"latest": "1.0.0"},
            "time": {"created": old.to_rfc3339(), "1.0.0": old.to_rfc3339()}
        });
        Mock::given(method("GET"))
            .and(wm_path("/some-rando-a"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body.clone()))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/some-rando-b"))
            .respond_with(ResponseTemplate::new(200).set_body_json(ok_body))
            .mount(&server)
            .await;
        // 1/3 = 33% failure → Info severity
        Mock::given(method("GET"))
            .and(wm_path("/some-rando-c"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/downloads/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"downloads": 1_000_000})))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("SANDTRACE_NPM_REGISTRY", server.uri());
            std::env::set_var(
                "SANDTRACE_NPM_DOWNLOADS",
                format!("{}/downloads", server.uri()),
            );
            std::env::set_var("SANDTRACE_CACHE_DIR", cache_dir.path());
        }
        let findings = tokio::task::spawn_blocking({
            let p = project_dir.path().to_path_buf();
            move || run_deep_checks(&p)
        })
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("SANDTRACE_NPM_REGISTRY");
            std::env::remove_var("SANDTRACE_NPM_DOWNLOADS");
            std::env::remove_var("SANDTRACE_CACHE_DIR");
        }

        let partial = findings
            .iter()
            .find(|f| f.rule_id == "deep-partial-scan")
            .expect("partial-scan finding expected");
        assert_eq!(partial.severity, Severity::Info);
    }

    #[tokio::test]
    async fn e2e_package_not_found_critical_via_404() {
        let _guard = ASYNC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = MockServer::start().await;
        let cache_dir = TempDir::new().unwrap();
        let project_dir = TempDir::new().unwrap();
        write_project_file(
            project_dir.path(),
            "package.json",
            r#"{"dependencies":{"hallucinated-pkg-name":"^1"}}"#,
        );
        Mock::given(method("GET"))
            .and(wm_path("/hallucinated-pkg-name"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("SANDTRACE_NPM_REGISTRY", server.uri());
            std::env::set_var("SANDTRACE_CACHE_DIR", cache_dir.path());
        }
        let findings = tokio::task::spawn_blocking({
            let p = project_dir.path().to_path_buf();
            move || run_deep_checks(&p)
        })
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("SANDTRACE_NPM_REGISTRY");
            std::env::remove_var("SANDTRACE_CACHE_DIR");
        }

        let nf = findings
            .iter()
            .find(|f| f.rule_id == "deep-package-not-found")
            .expect("404 should produce deep-package-not-found");
        assert_eq!(nf.severity, Severity::Critical);
        assert!(nf.description.contains("hallucinated-pkg-name"));
    }

    /// REGRESSION (issue #23): a private Composer package sourced from a declared
    /// `vcs` repository returns 404 on public Packagist but must NOT be flagged
    /// as deep-package-not-found.
    #[tokio::test]
    async fn e2e_composer_vcs_package_not_flagged_on_packagist_404() {
        let _guard = ASYNC_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let server = MockServer::start().await;
        let cache_dir = TempDir::new().unwrap();
        let project_dir = TempDir::new().unwrap();
        write_project_file(
            project_dir.path(),
            "composer.json",
            r#"{
                "require": { "cc-consulting-nv/laravel-cc-blog": "^1.1.6" },
                "repositories": [
                    { "type": "vcs", "url": "https://github.com/cc-consulting-nv/laravel-cc-blog.git" }
                ]
            }"#,
        );
        // Packagist would 404 this private package; the VCS-repo guard must skip
        // the lookup before this ever fires.
        Mock::given(method("GET"))
            .and(wm_path("/p2/cc-consulting-nv/laravel-cc-blog.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        unsafe {
            std::env::set_var("SANDTRACE_PACKAGIST", server.uri());
            std::env::set_var("SANDTRACE_CACHE_DIR", cache_dir.path());
        }
        let findings = tokio::task::spawn_blocking({
            let p = project_dir.path().to_path_buf();
            move || run_deep_checks(&p)
        })
        .await
        .unwrap();
        unsafe {
            std::env::remove_var("SANDTRACE_PACKAGIST");
            std::env::remove_var("SANDTRACE_CACHE_DIR");
        }

        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "deep-package-not-found"),
            "private VCS-sourced Composer package must not be flagged as not-found, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}
