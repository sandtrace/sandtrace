use crate::config;
use colored::Colorize;
use std::path::Path;

/// Built-in rule file contents, embedded at compile time
const CREDENTIAL_ACCESS_RULES: &str = include_str!("../rules/credential-access.yml");
const SUPPLY_CHAIN_RULES: &str = include_str!("../rules/supply-chain.yml");
const EXFILTRATION_RULES: &str = include_str!("../rules/exfiltration.yml");

struct RuleFile {
    filename: &'static str,
    content: &'static str,
}

const BUILTIN_RULE_FILES: &[RuleFile] = &[
    RuleFile {
        filename: "credential-access.yml",
        content: CREDENTIAL_ACCESS_RULES,
    },
    RuleFile {
        filename: "supply-chain.yml",
        content: SUPPLY_CHAIN_RULES,
    },
    RuleFile {
        filename: "exfiltration.yml",
        content: EXFILTRATION_RULES,
    },
];

pub fn run_init(force: bool) -> anyhow::Result<()> {
    let sandtrace_dir = config::sandtrace_dir();
    let rules_dir = sandtrace_dir.join("rules");
    let config_path = config::config_path();

    eprintln!(
        "{}",
        "Initializing SandTrace configuration...".bold()
    );

    // Create directories
    create_dir_if_needed(&sandtrace_dir)?;
    create_dir_if_needed(&rules_dir)?;

    // Write config.toml
    write_file_if_needed(&config_path, &config::default_config_toml(), force)?;

    // Copy built-in rule packs
    for rule_file in BUILTIN_RULE_FILES {
        let dest = rules_dir.join(rule_file.filename);
        write_file_if_needed(&dest, rule_file.content, force)?;
    }

    eprintln!();
    eprintln!("{}", "SandTrace initialized.".green().bold());
    eprintln!("  Config: {}", config_path.display());
    eprintln!("  Rules:  {}/", rules_dir.display());
    eprintln!();
    eprintln!("Edit {} to customize:", config_path.display());
    eprintln!("  - Redaction markers (reduce false positives)");
    eprintln!("  - Custom credential patterns");
    eprintln!("  - Shai-Hulud thresholds");
    eprintln!("  - Additional rule directories");

    Ok(())
}

fn create_dir_if_needed(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
        eprintln!("  {} {}/", "created".green(), path.display());
    } else {
        eprintln!("  {} {}/", "exists".dimmed(), path.display());
    }
    Ok(())
}

fn write_file_if_needed(path: &Path, content: &str, force: bool) -> anyhow::Result<()> {
    if path.exists() && !force {
        eprintln!("  {} {} (use --force to overwrite)", "skipped".yellow(), path.display());
    } else {
        let label = if path.exists() { "overwrote" } else { "created" };
        std::fs::write(path, content)?;
        eprintln!("  {} {}", label.green(), path.display());
    }
    Ok(())
}
