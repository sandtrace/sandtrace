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

        let proc_info = if let Some(ref name) = event.process_name {
            format!(
                " [{}:{}]",
                name,
                event.pid.map_or("?".to_string(), |p| p.to_string())
            )
        } else {
            String::new()
        };

        eprintln!(
            "{} {} {} {}{} — {}",
            timestamp.to_string().dimmed(),
            "ALERT".red().bold(),
            severity,
            event.rule_name.bold(),
            proc_info.cyan(),
            event.description,
        );

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
