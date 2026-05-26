//! Audit package-manager configuration files for supply-chain hardening gaps.
//!
//! Each package manager has its own config key + unit semantics for release-age
//! cooldown. We treat them independently — there is no shared key.
//!
//! | Manager      | File                  | Key                  | Unit    | First version |
//! |--------------|-----------------------|----------------------|---------|---------------|
//! | npm          | `.npmrc`              | `min-release-age`    | days    | 11.10.0       |
//! | pnpm         | `pnpm-workspace.yaml` | `minimumReleaseAge`  | minutes | 10.16         |
//! | pnpm legacy  | `.npmrc`              | `minimumReleaseAge`  | minutes | 10.16         |
//! | yarn (Berry) | `.yarnrc.yml`         | `npmMinimalAgeGate`  | minutes | 4.10.0        |
//! | bun          | `bunfig.toml`         | `minimumReleaseAge`  | seconds | 1.x           |
//! | uv (Python)  | `uv.toml`             | `exclude-newer`      | date    | 0.x           |
//!
//! Also enforces `ignore-scripts=true` for npm/pnpm (postinstall is the primary
//! Shai-Hulud entry point) and `allow-git=none` for npm (git-URL deps bypass
//! cooldown entirely — the TanStack vector).

use crate::event::{AuditFinding, Severity};
use std::path::{Path, PathBuf};

const NPM_THRESHOLD_DAYS: u64 = 7;
const PNPM_THRESHOLD_MINUTES: u64 = 7 * 24 * 60; // 10_080
const YARN_THRESHOLD_MINUTES: u64 = 7 * 24 * 60; // 10_080
const BUN_THRESHOLD_SECONDS: u64 = 7 * 24 * 60 * 60; // 604_800

const PNPM_MIN_VERSION_FOR_COOLDOWN: (u32, u32) = (10, 16);
/// pnpm 11.0 ships `minimumReleaseAge=1440` (1 day) ON by default. A project
/// pinned to pnpm 11+ has a baseline cooldown even with no explicit setting, so
/// "missing" is not a finding (the default is active). Below 11, the default is
/// 0 (immediate), so an explicit setting is required.
const PNPM_DEFAULT_GATE_VERSION: (u32, u32) = (11, 0);

/// Entry point: walk the target dir for config files and audit each.
pub fn check_registry_configs(target: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    let npm_present = has_npm_artifacts(target);
    let pnpm_present = has_pnpm_artifacts(target);
    let bun_present = target.join("bunfig.toml").exists() || target.join("bun.lock").exists();
    let yarn_present = target.join(".yarnrc.yml").exists() || target.join("yarn.lock").exists();
    let uv_present = target.join("uv.toml").exists() || target.join("uv.lock").exists();

    if npm_present {
        findings.extend(audit_npm(target));
    }
    if pnpm_present {
        findings.extend(audit_pnpm(target));
    }
    if yarn_present {
        findings.extend(audit_yarn(target));
    }
    if bun_present {
        findings.extend(audit_bun(&target.join("bunfig.toml")));
    }
    if uv_present {
        findings.extend(audit_uv(target));
    }

    findings
}

fn has_npm_artifacts(target: &Path) -> bool {
    target.join("package-lock.json").exists()
        || target.join("npm-shrinkwrap.json").exists()
        || (target.join("package.json").exists()
            && !target.join("pnpm-lock.yaml").exists()
            && !target.join("yarn.lock").exists()
            && !target.join("bun.lock").exists())
}

fn has_pnpm_artifacts(target: &Path) -> bool {
    target.join("pnpm-lock.yaml").exists() || target.join("pnpm-workspace.yaml").exists()
}

// ─── Generic .npmrc ini parser ───────────────────────────────────────────

fn parse_ini_lines(content: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').trim_matches('\'');
        out.push((idx + 1, key.trim().to_string(), value.to_string()));
    }
    out
}

// ─── npm audit ────────────────────────────────────────────────────────────

fn audit_npm(target: &Path) -> Vec<AuditFinding> {
    let npmrc = target.join(".npmrc");
    let file_path = npmrc.to_string_lossy().to_string();
    let mut findings = Vec::new();

    let Ok(content) = std::fs::read_to_string(&npmrc) else {
        findings.push(AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-npm-missing-npmrc".to_string(),
            severity: Severity::High,
            description: "No .npmrc found with package-lock.json. Add min-release-age=7 (days) and ignore-scripts=true to mitigate Shai-Hulud-class supply-chain attacks. Requires npm CLI 11.10.0+.".to_string(),
            matched_pattern: "missing .npmrc".to_string(),
            context_lines: vec![
                "Recommended .npmrc:".to_string(),
                "  ignore-scripts=true".to_string(),
                "  min-release-age=7   # npm 11.10+, unit: days".to_string(),
                "  allow-git=none      # block git-URL deps that bypass age".to_string(),
            ],
        });
        return findings;
    };

    let lines = parse_ini_lines(&content);
    let mut cooldown: Option<(usize, String)> = None;
    let mut wrong_pnpm_key: Option<(usize, String)> = None;
    let mut has_ignore_scripts = false;
    let mut allow_git: Option<String> = None;

    for (n, key, value) in lines {
        match key.as_str() {
            "min-release-age" => cooldown = Some((n, value)),
            // pnpm-style key in an npm project: npm ignores it entirely.
            "minimumReleaseAge" => wrong_pnpm_key = Some((n, value)),
            "ignore-scripts" => has_ignore_scripts = value.eq_ignore_ascii_case("true"),
            "allow-git" => allow_git = Some(value),
            _ => {}
        }
    }

    match cooldown {
        None => {
            if let Some((line, val)) = wrong_pnpm_key {
                let effective_hours = val.parse::<u64>().unwrap_or(0) / 60;
                findings.push(AuditFinding {
                    file_path: file_path.clone(),
                    line_number: Some(line),
                    rule_id: "config-npm-wrong-key".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "`minimumReleaseAge={val}` in .npmrc is a pnpm-only key. npm 11.10+ uses `min-release-age` (days). For pnpm 10.16+ readers, this value is {effective_hours} hours."
                    ),
                    matched_pattern: "pnpm key in npm-only project".to_string(),
                    context_lines: vec!["Use: min-release-age=7   # npm, days".to_string()],
                });
            } else {
                findings.push(AuditFinding {
                    file_path: file_path.clone(),
                    line_number: None,
                    rule_id: "config-npm-cooldown-missing".to_string(),
                    severity: Severity::High,
                    description: "No min-release-age set in .npmrc. npm 11.10+ supports this; without it, versions younger than 7 days install during a Shai-Hulud-class incident.".to_string(),
                    matched_pattern: "min-release-age unset".to_string(),
                    context_lines: vec!["Add: min-release-age=7   # days".to_string()],
                });
            }
        }
        Some((line, raw)) => {
            let days = parse_npm_release_age_days(&raw);
            match days {
                Some(d) if d < NPM_THRESHOLD_DAYS => {
                    findings.push(AuditFinding {
                        file_path: file_path.clone(),
                        line_number: Some(line),
                        rule_id: "config-npm-cooldown-too-short".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "npm min-release-age={raw} ({d}d) is below the 7-day Shai-Hulud-mitigation threshold."
                        ),
                        matched_pattern: "min-release-age below 7 days".to_string(),
                        context_lines: vec!["Change to: min-release-age=7".to_string()],
                    });
                }
                None => {
                    findings.push(AuditFinding {
                        file_path: file_path.clone(),
                        line_number: Some(line),
                        rule_id: "config-npm-cooldown-unparseable".to_string(),
                        severity: Severity::Medium,
                        description: format!(
                            "npm min-release-age={raw} is not a valid days value. Expected integer (days) or string like \"7d\"."
                        ),
                        matched_pattern: "unparseable cooldown".to_string(),
                        context_lines: vec!["Change to: min-release-age=7".to_string()],
                    });
                }
                _ => {}
            }
        }
    }

    if !has_ignore_scripts {
        findings.push(AuditFinding {
            file_path: file_path.clone(),
            line_number: None,
            rule_id: "config-ignore-scripts-missing".to_string(),
            severity: Severity::High,
            description: "ignore-scripts is not enabled in .npmrc. Package install scripts (preinstall, postinstall) are the primary Shai-Hulud entry point.".to_string(),
            matched_pattern: "ignore-scripts=true unset".to_string(),
            context_lines: vec!["Add: ignore-scripts=true".to_string()],
        });
    }

    let permissive_git = match allow_git.as_deref() {
        None => true,
        Some(v) => !v.eq_ignore_ascii_case("none") && !v.eq_ignore_ascii_case("false"),
    };
    if permissive_git {
        findings.push(AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-allow-git-permissive".to_string(),
            severity: Severity::Medium,
            description: "allow-git is not set to `none`. Git-URL dependencies (e.g. `github:user/repo#commit`) bypass version-age cooldowns entirely — the TanStack Shai-Hulud incident used this exact vector.".to_string(),
            matched_pattern: "allow-git not none".to_string(),
            context_lines: vec!["Add: allow-git=none".to_string()],
        });
    }

    findings
}

fn parse_npm_release_age_days(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    if let Some(stripped) = s.strip_suffix('d') {
        return stripped.parse::<u64>().ok();
    }
    None
}

// ─── pnpm audit ───────────────────────────────────────────────────────────

fn audit_pnpm(target: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // pnpm merges minimumReleaseAge from several sources. Scan all of them; the
    // setting is only "missing" if absent everywhere. Sources, in pnpm's own
    // precedence order (first hit wins for the *value* we report):
    //   1. pnpm-workspace.yaml         (canonical, pnpm 11+)
    //   2. package.json "pnpm" key     (most stable location for pnpm 10.x)
    //   3. .npmrc                      (legacy pnpm 10.x)
    //   4. ~/.config/pnpm/config.yaml  (user-wide, pnpm 11+)
    let workspace = target.join("pnpm-workspace.yaml");
    let npmrc = target.join(".npmrc");
    let pkg_json = target.join("package.json");
    let user_config = std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config/pnpm/config.yaml"));

    let mut resolved: Option<(PathBuf, usize, String)> = None;
    let mut take = |path: &Path, found: Option<(usize, String)>| {
        if resolved.is_none() {
            if let Some((line, val)) = found {
                resolved = Some((path.to_path_buf(), line, val));
            }
        }
    };

    if let Ok(content) = std::fs::read_to_string(&workspace) {
        take(&workspace, find_yaml_scalar(&content, "minimumReleaseAge"));
    }
    if let Ok(content) = std::fs::read_to_string(&pkg_json) {
        take(&pkg_json, find_pnpm_key_in_package_json(&content));
    }
    if let Ok(content) = std::fs::read_to_string(&npmrc) {
        let v = parse_ini_lines(&content)
            .into_iter()
            .find(|(_, k, _)| k == "minimumReleaseAge")
            .map(|(n, _, v)| (n, v));
        take(&npmrc, v);
    }
    if let Some(uc) = user_config.as_ref() {
        if let Ok(content) = std::fs::read_to_string(uc) {
            take(uc, find_yaml_scalar(&content, "minimumReleaseAge"));
        }
    }

    let value = resolved.as_ref().map(|(_, line, val)| (*line, val.clone()));
    let file_path = resolved
        .as_ref()
        .map(|(p, _, _)| p.to_string_lossy().to_string())
        .unwrap_or_else(|| workspace.to_string_lossy().to_string());

    match value {
        None => {
            // pnpm 11+ ships a 1440-minute (1 day) default gate. If the project
            // pins pnpm 11+, the cooldown is active even with no explicit value,
            // so "missing" is not a finding. Below 11 the default is 0 — flag it.
            if let Some(ver) = detect_pnpm_major_minor(target) {
                if !version_lt(ver, PNPM_DEFAULT_GATE_VERSION) {
                    return findings;
                }
            }
            findings.push(AuditFinding {
                file_path: file_path.clone(),
                line_number: None,
                rule_id: "config-pnpm-cooldown-missing".to_string(),
                severity: Severity::High,
                description: "pnpm minimumReleaseAge is not set in any config source (pnpm-workspace.yaml, package.json#pnpm, .npmrc, or ~/.config/pnpm/config.yaml). On pnpm 10.x the default is 0 (immediate), so versions younger than 7 days install during a Shai-Hulud-class incident. Set it explicitly, or pin pnpm 11+ (which defaults to a 1-day gate).".to_string(),
                matched_pattern: "minimumReleaseAge unset".to_string(),
                context_lines: vec![
                    "Recommended pnpm-workspace.yaml:".to_string(),
                    "  minimumReleaseAge: 10080   # minutes = 7 days".to_string(),
                ],
            });
        }
        Some((line, raw)) => {
            let minutes = raw.trim().parse::<u64>();
            match minutes {
                Ok(m) if m < PNPM_THRESHOLD_MINUTES => {
                    findings.push(AuditFinding {
                        file_path: file_path.clone(),
                        line_number: Some(line),
                        rule_id: "config-pnpm-cooldown-too-short".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "pnpm minimumReleaseAge={raw} ({m} minutes ≈ {:.1}h) is below the 7-day threshold ({} minutes = 10080).",
                            m as f64 / 60.0, PNPM_THRESHOLD_MINUTES
                        ),
                        matched_pattern: "pnpm cooldown below 10080 minutes".to_string(),
                        context_lines: vec!["Change to: minimumReleaseAge: 10080".to_string()],
                    });
                }
                Err(_) => {
                    findings.push(AuditFinding {
                        file_path: file_path.clone(),
                        line_number: Some(line),
                        rule_id: "config-pnpm-cooldown-not-integer".to_string(),
                        severity: Severity::High,
                        description: format!(
                            "pnpm minimumReleaseAge={raw} is not an integer. pnpm expects MINUTES as a bare integer (e.g. 10080 for 7 days). Duration strings like \"7d\" are silently ignored — the cooldown is effectively disabled."
                        ),
                        matched_pattern: "pnpm cooldown non-integer".to_string(),
                        context_lines: vec!["Change to: minimumReleaseAge: 10080".to_string()],
                    });
                }
                _ => {}
            }
        }
    }

    findings.extend(audit_pnpm_version(target));
    findings
}

fn find_yaml_scalar(content: &str, key: &str) -> Option<(usize, String)> {
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(val) = rest.strip_prefix(':') {
                let val = val.trim().trim_matches('"').trim_matches('\'').to_string();
                return Some((idx + 1, val));
            }
        }
    }
    None
}

/// Reads `minimumReleaseAge` from the `pnpm` object in package.json. pnpm 10.x
/// treats this as the most stable per-project location. Returns (line, value);
/// line is best-effort (the line the key text appears on, else 1).
fn find_pnpm_key_in_package_json(content: &str) -> Option<(usize, String)> {
    let json = serde_json::from_str::<serde_json::Value>(content).ok()?;
    let val = json.get("pnpm")?.get("minimumReleaseAge")?;
    let raw = match val {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return None,
    };
    let line = content
        .lines()
        .position(|l| l.contains("minimumReleaseAge"))
        .map(|i| i + 1)
        .unwrap_or(1);
    Some((line, raw))
}

/// Parses the pnpm version pinned by package.json#packageManager (e.g.
/// "pnpm@11.1.3" → (11, 1)). None if absent or not a pnpm pin.
fn detect_pnpm_major_minor(target: &Path) -> Option<(u32, u32)> {
    let content = std::fs::read_to_string(target.join("package.json")).ok()?;
    let json = serde_json::from_str::<serde_json::Value>(&content).ok()?;
    let pm = json.get("packageManager").and_then(|v| v.as_str())?;
    let version = pm.strip_prefix("pnpm@")?;
    parse_semver_major_minor(version)
}

fn audit_pnpm_version(target: &Path) -> Vec<AuditFinding> {
    let pkg_json = target.join("package.json");
    let Some(parsed) = detect_pnpm_major_minor(target) else {
        return Vec::new();
    };
    if version_lt(parsed, PNPM_MIN_VERSION_FOR_COOLDOWN) {
        return vec![AuditFinding {
            file_path: pkg_json.to_string_lossy().to_string(),
            line_number: None,
            rule_id: "config-pnpm-stale".to_string(),
            severity: Severity::Medium,
            description: format!(
                "package.json#packageManager pins pnpm@{}.{}. Versions before {}.{} do not support minimumReleaseAge — the cooldown setting silently does nothing.",
                parsed.0, parsed.1, PNPM_MIN_VERSION_FOR_COOLDOWN.0, PNPM_MIN_VERSION_FOR_COOLDOWN.1
            ),
            matched_pattern: "pnpm version below 10.16".to_string(),
            context_lines: vec!["Bump packageManager to pnpm@10.16.0 or later".to_string()],
        }];
    }
    Vec::new()
}

// ─── yarn audit ───────────────────────────────────────────────────────────

fn audit_yarn(target: &Path) -> Vec<AuditFinding> {
    let yarnrc = target.join(".yarnrc.yml");
    let file_path = yarnrc.to_string_lossy().to_string();
    let Ok(content) = std::fs::read_to_string(&yarnrc) else {
        return vec![AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-yarn-cooldown-missing".to_string(),
            severity: Severity::Medium,
            description: "yarn.lock present but no .yarnrc.yml. Add `npmMinimalAgeGate: 10080` (Berry 4.10+).".to_string(),
            matched_pattern: "missing .yarnrc.yml".to_string(),
            context_lines: vec![
                "Create .yarnrc.yml with: npmMinimalAgeGate: 10080   # minutes".to_string()
            ],
        }];
    };

    let value = find_yaml_scalar(&content, "npmMinimalAgeGate");
    match value {
        None => vec![AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-yarn-cooldown-missing".to_string(),
            severity: Severity::Medium,
            description: ".yarnrc.yml has no npmMinimalAgeGate. Berry 4.10+ supports this; set to 10080 (minutes = 7d).".to_string(),
            matched_pattern: "npmMinimalAgeGate unset".to_string(),
            context_lines: vec!["Add: npmMinimalAgeGate: 10080".to_string()],
        }],
        Some((line, raw)) => {
            let minutes = raw.trim().parse::<u64>();
            match minutes {
                Ok(m) if m < YARN_THRESHOLD_MINUTES => vec![AuditFinding {
                    file_path,
                    line_number: Some(line),
                    rule_id: "config-yarn-cooldown-too-short".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "yarn npmMinimalAgeGate={raw} ({m} minutes) is below the 7-day threshold (10080)."
                    ),
                    matched_pattern: "yarn cooldown below 10080 minutes".to_string(),
                    context_lines: vec!["Change to: npmMinimalAgeGate: 10080".to_string()],
                }],
                Err(_) => vec![AuditFinding {
                    file_path,
                    line_number: Some(line),
                    rule_id: "config-yarn-cooldown-not-integer".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "yarn npmMinimalAgeGate={raw} is not an integer. Yarn Berry 4.10 has a known parser bug (yarnpkg/berry#6991) where duration strings like \"7d\" are silently ignored. Use bare integer minutes."
                    ),
                    matched_pattern: "yarn cooldown non-integer".to_string(),
                    context_lines: vec!["Change to: npmMinimalAgeGate: 10080".to_string()],
                }],
                _ => Vec::new(),
            }
        }
    }
}

// ─── bun audit ────────────────────────────────────────────────────────────

fn audit_bun(path: &Path) -> Vec<AuditFinding> {
    let file_path = path.to_string_lossy().to_string();
    let Ok(content) = std::fs::read_to_string(path) else {
        return vec![AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-bun-cooldown-missing".to_string(),
            severity: Severity::Medium,
            description: "bun.lock present but no bunfig.toml. Add `[install] minimumReleaseAge = 604800` (seconds = 7 days).".to_string(),
            matched_pattern: "missing bunfig.toml".to_string(),
            context_lines: vec![
                "Create bunfig.toml with: [install]\n  minimumReleaseAge = 604800".to_string()
            ],
        }];
    };
    let mut findings = Vec::new();
    let value = find_toml_install_minimum_release_age(&content);
    match value {
        None => findings.push(AuditFinding {
            file_path,
            line_number: None,
            rule_id: "config-bun-cooldown-missing".to_string(),
            severity: Severity::Medium,
            description:
                "bunfig.toml has no [install] minimumReleaseAge. Set to 604800 (seconds = 7d)."
                    .to_string(),
            matched_pattern: "bun minimumReleaseAge unset".to_string(),
            context_lines: vec!["[install]\nminimumReleaseAge = 604800".to_string()],
        }),
        Some((line, secs)) => {
            if secs < BUN_THRESHOLD_SECONDS {
                findings.push(AuditFinding {
                    file_path,
                    line_number: Some(line),
                    rule_id: "config-bun-cooldown-too-short".to_string(),
                    severity: Severity::High,
                    description: format!(
                        "bun minimumReleaseAge={secs}s (≈{:.1}h) is below the 7-day threshold ({}s).",
                        secs as f64 / 3600.0,
                        BUN_THRESHOLD_SECONDS
                    ),
                    matched_pattern: "bun cooldown below 604800 seconds".to_string(),
                    context_lines: vec!["Change to: minimumReleaseAge = 604800".to_string()],
                });
            }
        }
    }
    findings
}

fn find_toml_install_minimum_release_age(content: &str) -> Option<(usize, u64)> {
    let mut in_install = false;
    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_install = line == "[install]";
            continue;
        }
        if !in_install {
            continue;
        }
        if let Some(rest) = line.strip_prefix("minimumReleaseAge") {
            if let Some(val) = rest.trim_start().strip_prefix('=') {
                if let Ok(n) = val.trim().parse::<u64>() {
                    return Some((idx + 1, n));
                }
            }
        }
    }
    None
}

// ─── uv audit ─────────────────────────────────────────────────────────────

fn audit_uv(target: &Path) -> Vec<AuditFinding> {
    let uv_toml = target.join("uv.toml");
    let pyproject = target.join("pyproject.toml");
    let (content, path_for_finding) = if let Ok(c) = std::fs::read_to_string(&uv_toml) {
        (c, uv_toml)
    } else if let Ok(c) = std::fs::read_to_string(&pyproject) {
        (c, pyproject)
    } else {
        return Vec::new();
    };
    if content.contains("exclude-newer") || content.contains("exclude_newer") {
        return Vec::new();
    }
    vec![AuditFinding {
        file_path: path_for_finding.to_string_lossy().to_string(),
        line_number: None,
        rule_id: "config-uv-cooldown-missing".to_string(),
        severity: Severity::Medium,
        description: "uv has no `exclude-newer` cutoff set. Pin to a date at least 7 days in the past to mitigate fast-burn supply-chain attacks on PyPI.".to_string(),
        matched_pattern: "uv exclude-newer unset".to_string(),
        context_lines: vec!["Add to uv.toml: exclude-newer = \"7 days ago\"".to_string()],
    }]
}

// ─── semver helpers ───────────────────────────────────────────────────────

fn parse_semver_major_minor(v: &str) -> Option<(u32, u32)> {
    let v = v.split('+').next()?.trim_start_matches('v');
    let mut parts = v.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn version_lt(a: (u32, u32), b: (u32, u32)) -> bool {
    a.0 < b.0 || (a.0 == b.0 && a.1 < b.1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }

    // ─── npm release-age parser ─────────────────────────────────────────

    #[test]
    fn npm_release_age_integer_days() {
        assert_eq!(parse_npm_release_age_days("7"), Some(7));
        assert_eq!(parse_npm_release_age_days("14"), Some(14));
    }

    #[test]
    fn npm_release_age_suffix_days() {
        assert_eq!(parse_npm_release_age_days("7d"), Some(7));
    }

    #[test]
    fn npm_release_age_rejects_garbage() {
        assert_eq!(parse_npm_release_age_days("nope"), None);
        assert_eq!(parse_npm_release_age_days("7m"), None);
    }

    // ─── npm audits ─────────────────────────────────────────────────────

    #[test]
    fn npm_missing_npmrc_flagged_high() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        let f = findings
            .iter()
            .find(|f| f.rule_id == "config-npm-missing-npmrc")
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn npm_correct_config_clean() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "min-release-age=7\nignore-scripts=true\nallow-git=none\n",
        );
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id.starts_with("config-npm-")),
            "expected no npm config findings, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "config-ignore-scripts-missing"));
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "config-allow-git-permissive"));
    }

    #[test]
    fn npm_cooldown_too_short_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "min-release-age=2\nignore-scripts=true\nallow-git=none\n",
        );
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-npm-cooldown-too-short"));
    }

    #[test]
    fn npm_wrong_pnpm_key_in_npm_only_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "minimumReleaseAge=10080\nignore-scripts=true\nallow-git=none\n",
        );
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings.iter().any(|f| f.rule_id == "config-npm-wrong-key"));
    }

    #[test]
    fn npm_ignore_scripts_missing_flagged() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "min-release-age=7\nallow-git=none\n");
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-ignore-scripts-missing"));
    }

    #[test]
    fn npm_allow_git_permissive_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "min-release-age=7\nignore-scripts=true\n",
        );
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-allow-git-permissive"));
    }

    // ─── pnpm audits ────────────────────────────────────────────────────

    #[test]
    fn pnpm_workspace_correct_minutes_clean() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - 'apps/*'\nminimumReleaseAge: 10080\n",
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id.starts_with("config-pnpm-cooldown-")));
    }

    #[test]
    fn pnpm_npmrc_correct_minutes_clean() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".npmrc", "minimumReleaseAge=10080\n");
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id.starts_with("config-pnpm-cooldown-")),
            "expected no pnpm cooldown findings, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pnpm_missing_cooldown_flagged_high() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        let f = findings
            .iter()
            .find(|f| f.rule_id == "config-pnpm-cooldown-missing")
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn pnpm_too_short_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "minimumReleaseAge: 2880\n",
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-pnpm-cooldown-too-short"));
    }

    #[test]
    fn pnpm_non_integer_flagged() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "pnpm-workspace.yaml", "minimumReleaseAge: 7d\n");
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-pnpm-cooldown-not-integer"));
    }

    #[test]
    fn pnpm_stale_version_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"packageManager":"pnpm@9.5.0"}"#,
        );
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "minimumReleaseAge: 10080\n",
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        let findings = check_registry_configs(dir.path());
        assert!(findings.iter().any(|f| f.rule_id == "config-pnpm-stale"));
    }

    #[test]
    fn pnpm_current_version_not_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"packageManager":"pnpm@10.16.0"}"#,
        );
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "minimumReleaseAge: 10080\n",
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        let findings = check_registry_configs(dir.path());
        assert!(!findings.iter().any(|f| f.rule_id == "config-pnpm-stale"));
    }

    #[test]
    fn pnpm_cooldown_in_npmrc_satisfies_when_workspace_present() {
        // Regression: pnpm-workspace.yaml present but WITHOUT the key, while
        // .npmrc HAS it. Old code stopped at the workspace file and falsely
        // flagged missing. pnpm merges sources — must be clean.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "pnpm-workspace.yaml",
            "packages:\n  - 'apps/*'\n",
        );
        write(dir.path(), ".npmrc", "minimumReleaseAge=10080\n");
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id.starts_with("config-pnpm-cooldown-")),
            "value in .npmrc should satisfy the gate, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pnpm_cooldown_in_package_json_pnpm_key_satisfies() {
        // package.json#pnpm.minimumReleaseAge is the canonical pnpm 10.x spot.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"pnpm":{"minimumReleaseAge":10080}}"#,
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        let findings = check_registry_configs(dir.path());
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id.starts_with("config-pnpm-cooldown-")),
            "value in package.json#pnpm should satisfy the gate, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pnpm11_default_gate_suppresses_missing() {
        // pnpm 11+ ships minimumReleaseAge=1440 ON by default. A project pinned
        // to pnpm 11+ with no explicit value has an active gate — not "missing".
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"packageManager":"pnpm@11.1.3"}"#,
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        let findings = check_registry_configs(dir.path());
        assert!(
            !findings
                .iter()
                .any(|f| f.rule_id == "config-pnpm-cooldown-missing"),
            "pnpm 11+ default gate should suppress missing finding, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn pnpm10_missing_still_flagged() {
        // pnpm 10.x default is 0 (immediate). Missing must still flag.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "package.json",
            r#"{"packageManager":"pnpm@10.16.0"}"#,
        );
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        let findings = check_registry_configs(dir.path());
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == "config-pnpm-cooldown-missing"),
            "pnpm 10.x with no gate must flag missing, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    // ─── yarn audits ────────────────────────────────────────────────────

    #[test]
    fn yarn_missing_cooldown_flagged() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".yarnrc.yml", "nodeLinker: node-modules\n");
        write(dir.path(), "yarn.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-yarn-cooldown-missing"));
    }

    #[test]
    fn yarn_correct_minutes_clean() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".yarnrc.yml", "npmMinimalAgeGate: 10080\n");
        write(dir.path(), "yarn.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id.starts_with("config-yarn-cooldown-")));
    }

    #[test]
    fn yarn_non_integer_flagged_due_to_parser_bug() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".yarnrc.yml", "npmMinimalAgeGate: 7d\n");
        write(dir.path(), "yarn.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-yarn-cooldown-not-integer"));
    }

    #[test]
    fn yarn_too_short_flagged() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), ".yarnrc.yml", "npmMinimalAgeGate: 2880\n");
        write(dir.path(), "yarn.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-yarn-cooldown-too-short"));
    }

    // ─── bun audits ─────────────────────────────────────────────────────

    #[test]
    fn bun_missing_cooldown_flagged() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "bunfig.toml", "[install]\n");
        write(dir.path(), "bun.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-bun-cooldown-missing"));
    }

    #[test]
    fn bun_correct_seconds_clean() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "bunfig.toml",
            "[install]\nminimumReleaseAge = 604800\n",
        );
        write(dir.path(), "bun.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id.starts_with("config-bun-cooldown-")));
    }

    #[test]
    fn bun_too_short_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "bunfig.toml",
            "[install]\nminimumReleaseAge = 7200\n",
        );
        write(dir.path(), "bun.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-bun-cooldown-too-short"));
    }

    // ─── uv audits ──────────────────────────────────────────────────────

    #[test]
    fn uv_missing_exclude_newer_flagged() {
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            "uv.toml",
            "[pip]\nindex-url = \"https://pypi.org/simple\"\n",
        );
        write(dir.path(), "uv.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "config-uv-cooldown-missing"));
    }

    #[test]
    fn uv_with_exclude_newer_clean() {
        let dir = TempDir::new().unwrap();
        write(dir.path(), "uv.toml", "exclude-newer = \"7 days ago\"\n");
        write(dir.path(), "uv.lock", "");
        let findings = check_registry_configs(dir.path());
        assert!(!findings
            .iter()
            .any(|f| f.rule_id == "config-uv-cooldown-missing"));
    }

    // ─── semver helpers ─────────────────────────────────────────────────

    #[test]
    fn semver_parses_basic() {
        assert_eq!(parse_semver_major_minor("10.16.0"), Some((10, 16)));
        assert_eq!(parse_semver_major_minor("v10.16.0"), Some((10, 16)));
        assert_eq!(parse_semver_major_minor("10.16.0+abc"), Some((10, 16)));
    }

    #[test]
    fn version_lt_compares() {
        assert!(version_lt((9, 5), (10, 16)));
        assert!(version_lt((10, 15), (10, 16)));
        assert!(!version_lt((10, 16), (10, 16)));
        assert!(!version_lt((10, 17), (10, 16)));
    }

    // ─── shared .npmrc with both managers ───────────────────────────────

    #[test]
    fn shared_npmrc_with_both_keys_satisfies_both_managers() {
        // The correct way to support both: separate keys, each in its own unit.
        let dir = TempDir::new().unwrap();
        write(
            dir.path(),
            ".npmrc",
            "min-release-age=7\nminimumReleaseAge=10080\nignore-scripts=true\nallow-git=none\n",
        );
        write(dir.path(), "package-lock.json", "{\"packages\":{}}");
        write(dir.path(), "pnpm-lock.yaml", "lockfileVersion: '9.0'");
        write(dir.path(), "package.json", "{}");
        let findings = check_registry_configs(dir.path());
        // No cooldown findings on either manager
        assert!(
            !findings.iter().any(|f| f.rule_id.contains("cooldown")),
            "expected no cooldown findings, got: {:?}",
            findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }
}
