use crate::error::{AlertError, SandtraceError};
use crate::event::{AlertChannel, RuleMatchEvent};
use async_trait::async_trait;

pub struct DesktopAlert;

impl DesktopAlert {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl super::AlertDispatcher for DesktopAlert {
    async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError> {
        let summary = format!("Sandtrace: {} [{}]", event.rule_name, event.severity);
        let body = format!(
            "{}\n{}",
            event.description,
            event
                .process_name
                .as_deref()
                .map(|n| format!(
                    "Process: {} (PID: {})",
                    n,
                    event.pid.map_or("?".to_string(), |p| p.to_string())
                ))
                .unwrap_or_default()
        );

        let urgency = match event.severity {
            crate::event::Severity::Critical | crate::event::Severity::High => {
                notify_rust::Urgency::Critical
            }
            crate::event::Severity::Medium => notify_rust::Urgency::Normal,
            _ => notify_rust::Urgency::Low,
        };

        notify_rust::Notification::new()
            .summary(&summary)
            .body(&body)
            .urgency(urgency)
            .timeout(notify_rust::Timeout::Milliseconds(10_000))
            .show()
            .map_err(|e| SandtraceError::Alert(AlertError::DesktopNotification(e.to_string())))?;

        Ok(())
    }

    fn channel(&self) -> AlertChannel {
        AlertChannel::Desktop
    }
}
