use super::OutputSink;
use crate::error::Result;
use crate::event::{PolicyAction, ProcessEvent, SyscallCategory, SyscallEvent, TraceEvent, TraceSummary};
use colored::Colorize;
use std::io::Write;

pub struct TerminalWriter {
    verbosity: u8,
    no_color: bool,
    buffer: Vec<u8>,
}

impl TerminalWriter {
    pub fn new(verbosity: u8, no_color: bool) -> Self {
        // Disable colors if requested or if NO_COLOR env var is set
        let no_color = no_color || std::env::var("NO_COLOR").is_ok();
        
        if no_color {
            colored::control::set_override(false);
        }

        Self {
            verbosity,
            no_color,
            buffer: Vec::new(),
        }
    }

    fn format_timestamp(&self, timestamp: chrono::DateTime<chrono::Utc>) -> String {
        timestamp.format("%H:%M:%S%.3f").to_string()
    }

    fn format_action(&self, action: PolicyAction) -> String {
        match action {
            PolicyAction::Allow => "ALLOW".green().to_string(),
            PolicyAction::Deny => "DENY".red().bold().to_string(),
            PolicyAction::LogOnly => "LOG".yellow().to_string(),
            PolicyAction::Kill => "KILL".red().bold().on_black().to_string(),
        }
    }

    fn should_show_syscall(&self, event: &SyscallEvent) -> bool {
        match self.verbosity {
            0 => event.action == PolicyAction::Deny || event.action == PolicyAction::Kill,
            1 => matches!(
                event.category,
                SyscallCategory::FileRead
                    | SyscallCategory::FileWrite
                    | SyscallCategory::Network
                    | SyscallCategory::Process
            ) || event.action != PolicyAction::Allow,
            2 => true,
            _ => true,
        }
    }

    fn format_syscall_event(&self, event: &SyscallEvent) -> Option<String> {
        if !self.should_show_syscall(event) {
            return None;
        }

        let timestamp = self.format_timestamp(event.timestamp);
        let action = self.format_action(event.action);
        let pid = format!("[{}]", event.pid).cyan();
        let syscall = event.syscall.bold();
        let category = format!("[{:?}]", event.category).dimmed();

        // Build args string from decoded args if available
        let args_str = if let Some(ref decoded) = event.args.decoded {
            let pairs: Vec<String> = decoded
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            format!(" {{{}}}", pairs.join(", "))
        } else {
            String::new()
        };

        let result = if event.success {
            format!("= {}", event.return_value).normal()
        } else {
            format!("= {}", event.return_value).red()
        };

        Some(format!(
            "{} {} {} {} {} {}{} {}",
            timestamp.dimmed(),
            action,
            pid,
            syscall,
            category,
            args_str,
            result,
            if event.action == PolicyAction::Deny {
                "DENIED".red().bold().to_string()
            } else {
                String::new()
            }
        ))
    }

    fn format_process_event(&self, event: &ProcessEvent) -> String {
        match event {
            ProcessEvent::Exec { timestamp, pid, path, argv } => {
                let ts = self.format_timestamp(*timestamp);
                let args = argv.join(" ");
                format!(
                    "{} {} [{}] EXEC {} {}",
                    ts.dimmed(),
                    "PROCESS".blue().bold(),
                    pid.to_string().cyan(),
                    path.yellow(),
                    args.dimmed()
                )
            }
            ProcessEvent::Spawned { timestamp, parent_pid, child_pid } => {
                let ts = self.format_timestamp(*timestamp);
                format!(
                    "{} {} [{}] fork -> [{}]",
                    ts.dimmed(),
                    "FORK".blue(),
                    parent_pid.to_string().cyan(),
                    child_pid.to_string().cyan()
                )
            }
            ProcessEvent::Exited { timestamp, pid, exit_code } => {
                let ts = self.format_timestamp(*timestamp);
                let code_str = if *exit_code == 0 {
                    exit_code.to_string().green()
                } else {
                    exit_code.to_string().red()
                };
                format!(
                    "{} {} [{}] exit code {}",
                    ts.dimmed(),
                    "EXIT".blue(),
                    pid.to_string().cyan(),
                    code_str
                )
            }
            ProcessEvent::Signaled { timestamp, pid, signal } => {
                let ts = self.format_timestamp(*timestamp);
                format!(
                    "{} {} [{}] signal {}",
                    ts.dimmed(),
                    "SIGNAL".red().bold(),
                    pid.to_string().cyan(),
                    signal.red()
                )
            }
        }
    }

    fn format_summary(&self, summary: &TraceSummary) -> String {
        let mut lines = vec![];
        lines.push(format!("{}", "─".repeat(60)).dimmed().to_string());
        lines.push("TRACE SUMMARY".bold().to_string());
        lines.push(format!("  Total syscalls: {}", summary.total_syscalls));
        lines.push(format!("  Unique syscalls: {}", summary.unique_syscalls));
        lines.push(format!("  Denied: {}", summary.denied_count.to_string().red()));
        lines.push(format!("  Processes: {}", summary.process_count));
        lines.push(format!("  Duration: {}ms", summary.duration_ms));
        lines.push(format!("  Exit code: {}", summary.exit_code));

        if !summary.suspicious_activity.is_empty() {
            lines.push("".to_string());
            lines.push("SUSPICIOUS ACTIVITY:".red().bold().to_string());
            for activity in &summary.suspicious_activity {
                lines.push(format!("  ⚠ {}", activity.red()));
            }
        }

        lines.push(format!("{}", "─".repeat(60)).dimmed().to_string());
        lines.join("\n")
    }
}

impl OutputSink for TerminalWriter {
    fn emit_event(&mut self, event: TraceEvent) -> Result<()> {
        let output = match event {
            TraceEvent::Syscall(e) => {
                if let Some(formatted) = self.format_syscall_event(&e) {
                    formatted
                } else {
                    return Ok(());
                }
            }
            TraceEvent::Process(e) => self.format_process_event(&e),
            TraceEvent::Summary(s) => self.format_summary(&s),
        };

        writeln!(self.buffer, "{}", output)?;
        
        // Flush immediately for terminal output
        let stderr = std::io::stderr();
        let mut handle = stderr.lock();
        handle.write_all(&self.buffer)?;
        handle.flush()?;
        self.buffer.clear();

        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if !self.buffer.is_empty() {
            let stderr = std::io::stderr();
            let mut handle = stderr.lock();
            handle.write_all(&self.buffer)?;
            handle.flush()?;
            self.buffer.clear();
        }
        Ok(())
    }
}
