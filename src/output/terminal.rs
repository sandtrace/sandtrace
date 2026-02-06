use std::io::{self, Write};

use anyhow::Result;
use colored::Colorize;

use crate::event::*;
use super::OutputSink;

/// Colored terminal output sink (writes to stderr).
pub struct TerminalSink {
    verbosity: u8,
    #[allow(dead_code)]
    no_color: bool,
}

impl TerminalSink {
    pub fn new(verbosity: u8, no_color: bool) -> Self {
        if no_color {
            colored::control::set_override(false);
        }
        Self { verbosity, no_color }
    }

    fn should_show_syscall(&self, event: &SyscallEvent) -> bool {
        match self.verbosity {
            0 => event.action == PolicyAction::Deny || event.action == PolicyAction::Kill,
            1 => matches!(
                event.category,
                SyscallCategory::FileRead
                    | SyscallCategory::FileWrite
                    | SyscallCategory::Directory
                    | SyscallCategory::Network
                    | SyscallCategory::Process
            ) || event.action == PolicyAction::Deny
              || event.action == PolicyAction::Kill,
            _ => true, // -vv and above: show everything
        }
    }

    fn format_syscall(&self, event: &SyscallEvent) -> String {
        let ts = event.timestamp.format("%H:%M:%S%.3f");
        let action = match event.action {
            PolicyAction::Allow => "ALLOW".green().to_string(),
            PolicyAction::Deny => "DENY".red().bold().to_string(),
            PolicyAction::LogOnly => "LOG".yellow().to_string(),
            PolicyAction::Kill => "KILL".red().bold().to_string(),
        };
        let pid = format!("[{}]", event.pid).dimmed().to_string();
        let syscall = event.syscall.cyan().to_string();
        let category = format!("[{}]", event.category).dimmed().to_string();

        let decoded = if event.args.decoded.is_empty() {
            String::new()
        } else {
            let parts: Vec<String> = event.args.decoded.iter()
                .filter(|(k, _)| *k != "dirfd" && *k != "raw")
                .map(|(k, v)| format!("{k}: {v:?}"))
                .collect();
            if parts.is_empty() {
                String::new()
            } else {
                format!(" {{{}}}", parts.join(", "))
            }
        };

        let ret = if event.success {
            format!("= {}", event.return_value).to_string()
        } else {
            format!("= {}", event.return_value).red().to_string()
        };

        format!("{ts} {action:<5} {pid} {syscall} {category}{decoded} {ret}")
    }

    fn format_process(&self, event: &ProcessEvent) -> String {
        let ts = event.timestamp.format("%H:%M:%S%.3f");
        let pid = format!("[{}]", event.pid).dimmed().to_string();

        match &event.kind {
            ProcessEventKind::Exec { path, argv } => {
                let argv_str = if argv.is_empty() {
                    String::new()
                } else {
                    format!(" {}", argv.join(" "))
                };
                format!("{ts} {} {pid} exec {path}{argv_str}", "PROC".blue().bold())
            }
            ProcessEventKind::Fork { child_pid } => {
                format!("{ts} {} {pid} fork -> {child_pid}", "PROC".blue().bold())
            }
            ProcessEventKind::Exit { code } => {
                let status = if *code == 0 {
                    format!("exit {code}").green().to_string()
                } else {
                    format!("exit {code}").red().to_string()
                };
                format!("{ts} {} {pid} {status}", "PROC".blue().bold())
            }
            ProcessEventKind::Signal { signal } => {
                format!("{ts} {} {pid} signal {signal}", "PROC".yellow().bold())
            }
        }
    }

    fn format_summary(&self, summary: &TraceSummary) -> String {
        let mut lines = Vec::new();
        lines.push(format!("\n{}", "=== Trace Summary ===".bold()));
        lines.push(format!("Duration:      {}ms", summary.duration_ms));
        lines.push(format!("Total syscalls: {}", summary.total_syscalls));
        lines.push(format!("Unique syscalls: {}", summary.unique_syscalls));
        lines.push(format!("Denied:        {}", summary.denied_count));
        lines.push(format!("Processes:     {}", summary.process_count));
        if let Some(code) = summary.exit_code {
            lines.push(format!("Exit code:     {code}"));
        }
        if !summary.suspicious_activity.is_empty() {
            lines.push(format!("\n{}", "Suspicious Activity:".red().bold()));
            for s in &summary.suspicious_activity {
                lines.push(format!("  ! {s}"));
            }
        }
        if !summary.network_attempts.is_empty() {
            lines.push(format!("\n{}", "Network Attempts:".yellow().bold()));
            for n in &summary.network_attempts {
                lines.push(format!("  -> {n}"));
            }
        }
        lines.join("\n")
    }
}

impl OutputSink for TerminalSink {
    fn emit(&mut self, event: &TraceEvent) -> Result<()> {
        let line = match event {
            TraceEvent::Syscall(e) => {
                if !self.should_show_syscall(e) {
                    return Ok(());
                }
                self.format_syscall(e)
            }
            TraceEvent::Process(e) => self.format_process(e),
            TraceEvent::Summary(s) => self.format_summary(s),
        };
        writeln!(io::stderr(), "{line}")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        io::stderr().flush()?;
        Ok(())
    }
}
