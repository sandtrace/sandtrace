use crate::error::{AlertError, SandtraceError};
use crate::event::{AlertChannel, RuleMatchEvent, Severity};
use async_trait::async_trait;
use std::io::Write;
use std::os::unix::net::UnixStream;

pub struct SyslogAlert;

impl SyslogAlert {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl super::AlertDispatcher for SyslogAlert {
    async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError> {
        let priority = match event.severity {
            Severity::Critical => 2, // LOG_CRIT
            Severity::High => 3,     // LOG_ERR
            Severity::Medium => 4,   // LOG_WARNING
            Severity::Low => 5,      // LOG_NOTICE
            Severity::Info => 6,     // LOG_INFO
        };

        // Facility LOG_USER (1) << 3 = 8, combined with priority
        let facility_priority = 8 + priority;

        let message = format!(
            "<{}> sandtrace[{}]: {} severity={} rule={} process={} pid={} — {}",
            facility_priority,
            std::process::id(),
            event.rule_name,
            event.severity,
            event.rule_id,
            event.process_name.as_deref().unwrap_or("unknown"),
            event.pid.map_or("?".to_string(), |p| p.to_string()),
            event.description,
        );

        // Try /dev/log first, then /var/run/syslog (macOS)
        let socket_path = if std::path::Path::new("/dev/log").exists() {
            "/dev/log"
        } else if std::path::Path::new("/var/run/syslog").exists() {
            "/var/run/syslog"
        } else {
            return Err(SandtraceError::Alert(AlertError::SyslogWrite(
                std::io::Error::new(std::io::ErrorKind::NotFound, "No syslog socket found"),
            )));
        };

        let mut stream = UnixStream::connect(socket_path)
            .map_err(|e| SandtraceError::Alert(AlertError::SyslogWrite(e)))?;

        stream
            .write_all(message.as_bytes())
            .map_err(|e| SandtraceError::Alert(AlertError::SyslogWrite(e)))?;

        Ok(())
    }

    fn channel(&self) -> AlertChannel {
        AlertChannel::Syslog
    }
}
