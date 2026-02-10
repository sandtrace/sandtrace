use crate::error::SandtraceError;
use crate::event::{AlertChannel, RuleMatchEvent, Severity};
use async_trait::async_trait;
use colored::Colorize;

pub struct StdoutAlert;

impl StdoutAlert {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl super::AlertDispatcher for StdoutAlert {
    async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError> {
        let severity = format_severity(event.severity);
        let timestamp = event.timestamp.format("%H:%M:%S%.3f");

        let pid_str = event.pid.map_or("?".to_string(), |p| p.to_string());
        let proc_name = event.process_name.as_deref().unwrap_or("unknown");

        eprintln!(
            "{} {} {} {} — {}",
            timestamp.to_string().dimmed(),
            "ALERT".red().bold(),
            severity,
            event.rule_name.bold(),
            event.description,
        );
        let access_str = event
            .access_type
            .map(|a| format!(" [{}]", a))
            .unwrap_or_default();

        eprintln!(
            "    {} {}{} | {} {}",
            "file:".dimmed(),
            event.file_path.yellow(),
            access_str.magenta(),
            "pid:".dimmed(),
            format!("{} ({})", pid_str, proc_name).cyan(),
        );
        if !event.process_lineage.is_empty() {
            let lineage: Vec<String> = event
                .process_lineage
                .iter()
                .map(|p| format!("{}[{}]", p.name, p.pid))
                .collect();
            eprintln!(
                "    {} {}",
                "lineage:".dimmed(),
                lineage.join(" > ").dimmed(),
            );
        }

        Ok(())
    }

    fn channel(&self) -> AlertChannel {
        AlertChannel::Stdout
    }
}

fn format_severity(severity: Severity) -> colored::ColoredString {
    match severity {
        Severity::Info => "INFO".normal(),
        Severity::Low => "LOW".blue(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::High => "HIGH".red(),
        Severity::Critical => "CRITICAL".red().bold(),
    }
}
