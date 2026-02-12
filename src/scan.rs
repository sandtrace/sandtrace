use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::Result;
use colored::Colorize;
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;

use crate::cli::ScanArgs;

/// File extensions to skip — data/db formats where long whitespace is normal noise
#[rustfmt::skip]
const SKIP_EXTENSIONS: &[&str] = &[
    // Data / database
    "jsonl", "ndjson", "json", "bson", "csv", "tsv", "parquet", "avro",
    // Logs / session dumps
    "log",
    // Database files
    "sqlite", "sqlite3", "db", "mdb", "ldb",
    // Binary / compiled
    "wasm", "pyc", "pyo", "class", "o", "a", "so", "dylib", "dll", "exe",
    // Archives
    "zip", "tar", "gz", "bz2", "xz", "zst", "7z", "rar",
    // Images / media
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "webp",
    "mp3", "mp4", "wav", "ogg", "webm", "avi", "mov", "flv",
    // Fonts
    "woff", "woff2", "ttf", "otf", "eot",
    // Lock files
    "lock",
    // PDF / docs / markdown
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "md",
    // Maps / minified bundles (often single huge lines)
    "map",
];

fn should_skip_extension(path: &Path) -> bool {
    path.extension().and_then(OsStr::to_str).is_some_and(|ext| {
        let lower = ext.to_ascii_lowercase();
        SKIP_EXTENSIONS.contains(&lower.as_str())
    })
}

struct Finding {
    path: PathBuf,
    line_num: usize,
    ws_count: usize,
    line_preview: String,
}

fn scan_file(path: &PathBuf, pattern: &Regex, max_size: u64) -> Vec<Finding> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return vec![],
    };

    if !meta.is_file() || meta.len() > max_size || meta.len() == 0 {
        return vec![];
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return vec![],
    };

    let reader = BufReader::new(file);
    let mut findings = Vec::new();

    for (idx, line_result) in reader.lines().enumerate() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => break,
        };

        if let Some(mat) = pattern.find(&line) {
            let ws_count = mat.end() - mat.start();
            let preview = if line.len() > 120 {
                let mut end = 120;
                while !line.is_char_boundary(end) {
                    end -= 1;
                }
                format!("{}...", &line[..end])
            } else {
                line.clone()
            };

            findings.push(Finding {
                path: path.clone(),
                line_num: idx + 1,
                ws_count,
                line_preview: preview,
            });
        }
    }

    findings
}

pub fn run_scan(args: ScanArgs) -> Result<()> {
    let start = Instant::now();
    let use_color = !args.no_color;

    let ws_min = args.min_whitespace;
    let pattern_str = format!(r"[ \t]{{{},}}", ws_min);
    let pattern = Regex::new(&pattern_str).expect("invalid regex");

    eprintln!(
        "Scanning {} for files with {}+ consecutive whitespace chars...",
        args.target, ws_min
    );

    let files_scanned = AtomicUsize::new(0);

    // Collect file paths — scan everything, skip known junk directories
    let mut builder = WalkBuilder::new(&args.target);
    builder
        .hidden(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false);

    // Load .sandtraceignore files (gitignore format)
    // Global: ~/.sandtrace/.sandtraceignore
    let global_ignore = crate::config::global_ignore_path();
    if global_ignore.exists() {
        let _ = builder.add_ignore(&global_ignore);
    }
    // Per-directory: auto-discover .sandtraceignore in any traversed directory
    builder.add_custom_ignore_filename(".sandtraceignore");

    let paths: Vec<PathBuf> = builder.filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                "node_modules"
                    | ".git"
                    | "vendor"
                    | ".pnpm"
                    | "dist"
                    | "build"
                    | ".cache"
                    | "__pycache__"
                    | ".venv"
                    | "venv"
                    | ".tox"
            )
        })
        .build()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
        .map(|e| e.into_path())
        .filter(|p| !should_skip_extension(p))
        .collect();

    eprintln!("Found {} files to scan", paths.len());

    // Scan in parallel
    let all_findings: Vec<Finding> = paths
        .par_iter()
        .flat_map(|path| {
            files_scanned.fetch_add(1, Ordering::Relaxed);
            scan_file(path, &pattern, args.max_size)
        })
        .collect();

    let elapsed = start.elapsed();
    let total_scanned = files_scanned.load(Ordering::Relaxed);

    if all_findings.is_empty() {
        eprintln!();
        eprintln!(
            "No files with {}+ consecutive whitespace chars found.",
            ws_min
        );
    } else {
        let unique_files: HashSet<&PathBuf> = all_findings.iter().map(|f| &f.path).collect();

        if args.files_only {
            let mut sorted: Vec<&&PathBuf> = unique_files.iter().collect();
            sorted.sort();
            for path in sorted {
                println!("{}", path.display());
            }
        } else {
            println!();
            if use_color {
                println!(
                    "{} {} file(s) with {}+ consecutive whitespace chars:",
                    "WORMSIGN DETECTED:".red().bold(),
                    unique_files.len(),
                    ws_min
                );
            } else {
                println!(
                    "WORMSIGN DETECTED: {} file(s) with {}+ consecutive whitespace chars:",
                    unique_files.len(),
                    ws_min
                );
            }
            println!();

            let mut current_file: Option<&PathBuf> = None;
            for finding in &all_findings {
                if current_file != Some(&finding.path) {
                    if use_color {
                        println!("  {}", finding.path.display().to_string().yellow());
                    } else {
                        println!("  {}", finding.path.display());
                    }
                    current_file = Some(&finding.path);
                }
                println!(
                    "    Line {}: {} whitespace chars",
                    finding.line_num, finding.ws_count
                );
                if args.verbose {
                    println!("      {}", finding.line_preview);
                }
            }
        }
    }

    eprintln!();
    eprintln!(
        "Scanned {} files in {:.2}s",
        total_scanned,
        elapsed.as_secs_f64()
    );

    Ok(())
}
