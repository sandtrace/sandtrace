//! Telemetry module — stub for future paid cloud dashboard.
//!
//! Feature-gated behind `#[cfg(feature = "telemetry")]`.
//! Disabled by default in the open-source build.
//!
//! **Privacy guarantee:** Never collects file contents, credential values,
//! full file paths, or user data. Only anonymized metadata.

use crate::event::Severity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub timestamp: DateTime<Utc>,
    pub process_name_hash: String,
    pub path_pattern: String,
    pub severity: Severity,
    pub rule_id: String,
}

pub trait TelemetryCollector: Send + Sync {
    fn record(&self, event: TelemetryEvent);
    fn flush(&self);
}

pub struct NoOpCollector;

impl TelemetryCollector for NoOpCollector {
    fn record(&self, _event: TelemetryEvent) {}
    fn flush(&self) {}
}
