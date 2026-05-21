//! Deep registry checks: verify packages exist, check version age,
//! download counts, and known vulnerabilities via registry APIs.
//!
//! Only runs when `--deep` flag is passed (requires network access).

use crate::event::{AuditFinding, Severity};
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

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

/// Run all registry-based deep checks on dependencies found in manifests.
pub fn run_deep_checks(dir: &Path) -> Vec<AuditFinding> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("sandtrace")
        .build()
        .unwrap_or_else(|_| Client::new());

    let mut findings = Vec::new();

    // Parse dependencies from manifest files
    let npm_deps = parse_npm_deps(dir);
    let composer_deps = parse_composer_deps(dir);

    if !npm_deps.is_empty() {
        eprintln!(
            "Deep check: verifying {} npm packages against registry...",
            npm_deps.len()
        );
        findings.extend(check_npm_packages(&client, &npm_deps, dir));
    }

    if !composer_deps.is_empty() {
        eprintln!(
            "Deep check: verifying {} composer packages against registry...",
            composer_deps.len()
        );
        findings.extend(check_composer_packages(&client, &composer_deps, dir));
    }

    findings
}

#[derive(Debug, Clone)]
struct DepInfo {
    name: String,
    version_spec: String,
}

fn parse_npm_deps(dir: &Path) -> Vec<DepInfo> {
    let pkg_json = dir.join("package.json");
    if !pkg_json.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&pkg_json) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, version) in obj {
                if let Some(ver) = version.as_str() {
                    deps.push(DepInfo {
                        name: name.clone(),
                        version_spec: ver.to_string(),
                    });
                }
            }
        }
    }
    deps
}

fn parse_composer_deps(dir: &Path) -> Vec<DepInfo> {
    let composer_json = dir.join("composer.json");
    if !composer_json.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&composer_json) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let json: Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut deps = Vec::new();
    for section in ["require", "require-dev"] {
        if let Some(obj) = json.get(section).and_then(Value::as_object) {
            for (name, version) in obj {
                // Skip php, ext-*, and lib-* (platform requirements, not packages)
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
                    });
                }
            }
        }
    }
    deps
}

fn check_npm_packages(client: &Client, deps: &[DepInfo], dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let file_path = dir.join("package.json").to_string_lossy().to_string();

    for dep in deps {
        let url = format!("https://registry.npmjs.org/{}", dep.name);
        let response = match client.get(&url).send() {
            Ok(r) => r,
            Err(_) => continue,
        };

        if response.status().as_u16() == 404 {
            // Package does not exist on npm
            findings.push(AuditFinding {
                file_path: file_path.clone(),
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
            continue;
        }

        if !response.status().is_success() {
            continue;
        }

        let body: Value = match response.json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check version age — when was the latest version published?
        let is_trusted = TRUSTED_NPM_PACKAGES.iter().any(|&t| t == dep.name);
        if let Some(time) = body.get("time").and_then(Value::as_object) {
            // Get the latest version's publish time
            if let Some(latest_version) = body
                .get("dist-tags")
                .and_then(|d| d.get("latest"))
                .and_then(Value::as_str)
            {
                if let Some(publish_date) = time.get(latest_version).and_then(Value::as_str) {
                    if let Some(age_hours) = parse_age_hours(publish_date) {
                        if age_hours < 168 && !is_trusted {
                            // Less than 7 days, not a trusted high-frequency package
                            findings.push(AuditFinding {
                                file_path: file_path.clone(),
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

            // Check package creation date — how old is the package itself?
            if let Some(created) = time.get("created").and_then(Value::as_str) {
                if let Some(age_hours) = parse_age_hours(created) {
                    if age_hours < 720 {
                        // Less than 30 days
                        let age_days = age_hours / 24;
                        findings.push(AuditFinding {
                            file_path: file_path.clone(),
                            line_number: None,
                            rule_id: "deep-new-package".to_string(),
                            severity: Severity::Medium,
                            description: format!(
                                "Package '{}' was first published {} days ago. New packages are higher risk — verify this is legitimate",
                                dep.name, age_days
                            ),
                            matched_pattern: "recently created package".to_string(),
                            context_lines: vec![format!(
                                "Check {} on npmjs.com and its source repository before depending on it",
                                dep.name
                            )],
                        });
                    }
                }
            }
        }

        // Check download count (weekly downloads from npm API)
        // npm registry doesn't include downloads in the main endpoint,
        // need a separate API call
        let dl_url = format!(
            "https://api.npmjs.org/downloads/point/last-week/{}",
            dep.name
        );
        if let Ok(dl_response) = client.get(&dl_url).send() {
            if let Ok(dl_body) = dl_response.json::<Value>() {
                if let Some(downloads) = dl_body.get("downloads").and_then(Value::as_u64) {
                    if downloads < 100 {
                        findings.push(AuditFinding {
                            file_path: file_path.clone(),
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

fn check_composer_packages(client: &Client, deps: &[DepInfo], dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();
    let file_path = dir.join("composer.json").to_string_lossy().to_string();

    for dep in deps {
        let url = format!("https://repo.packagist.org/p2/{}.json", dep.name);
        let response = match client.get(&url).send() {
            Ok(r) => r,
            Err(_) => continue,
        };

        if response.status().as_u16() == 404 {
            findings.push(AuditFinding {
                file_path: file_path.clone(),
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
            continue;
        }

        if !response.status().is_success() {
            continue;
        }

        let body: Value = match response.json() {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Check download count from packagist stats
        let stats_url = format!("https://packagist.org/packages/{}/stats.json", dep.name);
        if let Ok(stats_response) = client.get(&stats_url).send() {
            if let Ok(stats_body) = stats_response.json::<Value>() {
                if let Some(downloads) = stats_body
                    .get("downloads")
                    .and_then(|d| d.get("total"))
                    .and_then(Value::as_u64)
                {
                    if downloads < 100 {
                        findings.push(AuditFinding {
                            file_path: file_path.clone(),
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
}
