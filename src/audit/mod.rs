pub mod obfuscation;
pub mod scanner;

use crate::cli::AuditArgs;
use crate::config::{self, SandtraceConfig};
use crate::error::SandtraceError;
use crate::event::{AuditFinding, Severity};
use crate::rules::RuleRegistry;
use colored::Colorize;
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::path::{Path, PathBuf};

pub fn run_audit(args: AuditArgs) -> Result<(), SandtraceError> {
    run_audit_with_config(args, &config::load_config())
}

pub fn run_audit_with_config(
    args: AuditArgs,
    config: &SandtraceConfig,
) -> Result<(), SandtraceError> {
    args.validate()
        .map_err(|e| SandtraceError::InvalidArgument(e.to_string()))?;

    // Load rules
    let mut registry = RuleRegistry::new();
    registry.load_builtins();

    let rules_dir = config::expand_tilde(&args.rules);
    if rules_dir.exists() {
        registry.load_directory(&rules_dir)?;
    }

    // Load additional rule directories from config
    for additional_dir in &config.additional_rules {
        let dir = config::expand_tilde_str(additional_dir);
        if dir.exists() {
            registry.load_directory(&dir)?;
        }
    }

    let min_severity = args.min_severity();

    eprintln!(
        "Sandtrace audit: scanning {} (min severity: {})",
        args.target.display(),
        min_severity
    );

    // Collect files to scan
    let files = collect_files(&args.target);
    eprintln!("Found {} files to scan", files.len());

    // Run all scanners in parallel
    let obfuscation_config = &config.obfuscation;
    let mut findings: Vec<AuditFinding> = files
        .par_iter()
        .flat_map(|file_path| {
            let mut file_findings = Vec::new();

            // Obfuscation scanner
            match obfuscation::scan_file(file_path, obfuscation_config) {
                Ok(f) => file_findings.extend(f),
                Err(e) => log::debug!("Skipping {}: {}", file_path.display(), e),
            }

            // Content scanner (credential patterns + custom patterns)
            match scanner::scan_file_content(file_path, config) {
                Ok(f) => file_findings.extend(f),
                Err(e) => log::debug!("Skipping {}: {}", file_path.display(), e),
            }

            file_findings
        })
        .collect();

    // Supply-chain scanner (existing)
    let mut supply_findings = scanner::scan_supply_chain(&args.target);
    findings.append(&mut supply_findings);

    // Git hook scan (Rule 7) — separate pass since .git/ is skipped by file collector
    let mut git_hook_findings = obfuscation::encoding::scan_git_hooks(&args.target);
    findings.append(&mut git_hook_findings);

    // Supply chain manifest scans (Rules 18-20)
    let mut typosquat_findings =
        obfuscation::supply_chain::check_typosquat(&args.target, obfuscation_config);
    findings.append(&mut typosquat_findings);

    let mut dep_confusion_findings =
        obfuscation::supply_chain::check_dependency_confusion(&args.target, obfuscation_config);
    findings.append(&mut dep_confusion_findings);

    let mut install_script_findings =
        obfuscation::supply_chain::check_install_scripts(&args.target);
    findings.append(&mut install_script_findings);

    // Filter by severity
    findings.retain(|f| f.severity >= min_severity);

    // Sort by severity (critical first)
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    // Output results
    match args.format {
        crate::cli::AuditFormat::Terminal => print_terminal_report(&findings),
        crate::cli::AuditFormat::Json => print_json_report(&findings)?,
        crate::cli::AuditFormat::Sarif => print_sarif_report(&findings)?,
    }

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();

    eprintln!(
        "\nAudit complete: {} findings ({} critical, {} high)",
        findings.len(),
        critical_count,
        high_count
    );

    if critical_count > 0 {
        std::process::exit(2);
    } else if high_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut builder = WalkBuilder::new(dir);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .max_depth(Some(20));

    // Load .sandtraceignore files (gitignore format)
    // Global: ~/.sandtrace/.sandtraceignore
    let global_ignore = crate::config::global_ignore_path();
    if global_ignore.exists() {
        let _ = builder.add_ignore(&global_ignore);
    }
    // Per-directory: auto-discover .sandtraceignore in any traversed directory
    builder.add_custom_ignore_filename(".sandtraceignore");

    builder
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            // Skip hidden directories (but allow hidden files)
            if name.starts_with('.') && entry.file_type().is_some_and(|ft| ft.is_dir()) {
                return false;
            }
            !matches!(
                name.as_ref(),
                "node_modules"
                    | "target"
                    | "vendor"
                    | ".git"
                    | "__pycache__"
                    | "dist"
                    | "build"
                    | ".pnpm"
                    | ".venv"
                    | "venv"
                    | ".tox"
                    | "playwright-report"
                    | "test-results"
                    | "coverage"
                    | ".cache"
                    | "logs"
                    | "storage"
                    | "public"
            )
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .map(|e| e.into_path())
        .filter(|p| is_scannable(p))
        .collect()
}

fn is_scannable(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    // Include common source/config file extensions
    matches!(
        ext,
        "js" | "ts"
            | "jsx"
            | "tsx"
            | "mjs"
            | "cjs"
            | "py"
            | "rb"
            | "php"
            | "go"
            | "rs"
            | "java"
            | "kt"
            | "swift"
            | "c"
            | "cpp"
            | "h"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "json"
            | "yaml"
            | "yml"
            | "toml"
            | "xml"
            | "ini"
            | "cfg"
            | "conf"
            | "env"
            | "env.local"
            | "env.production"
            | "txt"
            | "csv"
            | "html"
            | "css"
            | "scss"
            | "sass"
            | "less"
            | "sql"
            | "graphql"
            | "gql"
            | "dockerfile"
            | "makefile"
            | "gemfile"
            | "rakefile"
    ) || path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            matches!(
                n.to_lowercase().as_str(),
                ".env"
                    | ".npmrc"
                    | ".yarnrc"
                    | "package.json"
                    | "package-lock.json"
                    | "composer.json"
                    | "cargo.toml"
                    | "requirements.txt"
                    | "pipfile"
                    | "gemfile"
                    | "dockerfile"
                    | "makefile"
                    | ".gitignore"
            )
        })
        .unwrap_or(false)
}

fn print_terminal_report(findings: &[AuditFinding]) {
    if findings.is_empty() {
        eprintln!("{}", "No findings.".green());
        return;
    }

    eprintln!("\n{}", "AUDIT FINDINGS".bold());
    eprintln!("{}", "─".repeat(70));

    for finding in findings {
        let severity = match finding.severity {
            Severity::Info => "INFO".normal(),
            Severity::Low => "LOW".blue(),
            Severity::Medium => "MEDIUM".yellow(),
            Severity::High => "HIGH".red(),
            Severity::Critical => "CRITICAL".red().bold(),
        };

        let location = if let Some(line) = finding.line_number {
            format!("{}:{}", finding.file_path, line)
        } else {
            finding.file_path.clone()
        };

        eprintln!(
            "  {} {} — {} [{}]",
            severity,
            location.yellow(),
            finding.description,
            finding.rule_id.dimmed()
        );

        if !finding.context_lines.is_empty() {
            for line in &finding.context_lines {
                eprintln!("    {}", line.dimmed());
            }
        }
    }

    eprintln!("{}", "─".repeat(70));
}

fn print_json_report(findings: &[AuditFinding]) -> Result<(), SandtraceError> {
    let json = serde_json::to_string_pretty(findings).map_err(|e| {
        SandtraceError::InvalidArgument(format!("JSON serialization failed: {}", e))
    })?;
    println!("{}", json);
    Ok(())
}

fn print_sarif_report(findings: &[AuditFinding]) -> Result<(), SandtraceError> {
    let sarif = serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sandtrace",
                    "version": "0.2.0",
                    "informationUri": "https://github.com/example/sandtrace"
                }
            },
            "results": findings.iter().map(|f| {
                serde_json::json!({
                    "ruleId": f.rule_id,
                    "level": match f.severity {
                        Severity::Critical | Severity::High => "error",
                        Severity::Medium => "warning",
                        _ => "note",
                    },
                    "message": { "text": f.description },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.file_path },
                            "region": {
                                "startLine": f.line_number.unwrap_or(1)
                            }
                        }
                    }]
                })
            }).collect::<Vec<_>>()
        }]
    });

    let json = serde_json::to_string_pretty(&sarif).map_err(|e| {
        SandtraceError::InvalidArgument(format!("SARIF serialization failed: {}", e))
    })?;
    println!("{}", json);
    Ok(())
}
