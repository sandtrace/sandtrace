use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum TraceEvent {
    Syscall(SyscallEvent),
    Process(ProcessEvent),
    Summary(TraceSummary),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: i32,
    pub tgid: i32,
    pub syscall: String,
    pub syscall_nr: u64,
    pub args: SyscallArgs,
    pub return_value: i64,
    pub success: bool,
    pub duration_us: u64,
    pub action: PolicyAction,
    pub category: SyscallCategory,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallArgs {
    pub raw: [u64; 6],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProcessEvent {
    Exec {
        timestamp: DateTime<Utc>,
        pid: i32,
        path: String,
        argv: Vec<String>,
    },
    Spawned {
        timestamp: DateTime<Utc>,
        parent_pid: i32,
        child_pid: i32,
    },
    Exited {
        timestamp: DateTime<Utc>,
        pid: i32,
        exit_code: i32,
    },
    Signaled {
        timestamp: DateTime<Utc>,
        pid: i32,
        signal: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceSummary {
    pub timestamp: DateTime<Utc>,
    pub total_syscalls: u64,
    pub unique_syscalls: u64,
    pub denied_count: u64,
    pub process_count: u64,
    pub duration_ms: u64,
    pub exit_code: i32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files_accessed: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub network_attempts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suspicious_activity: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    LogOnly,
    Kill,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SyscallCategory {
    FileRead,
    FileWrite,
    FileMetadata,
    Directory,
    Process,
    Network,
    Memory,
    Signal,
    Ipc,
    System,
    Other,
}

impl std::fmt::Display for SyscallCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyscallCategory::FileRead => write!(f, "file_read"),
            SyscallCategory::FileWrite => write!(f, "file_write"),
            SyscallCategory::FileMetadata => write!(f, "file_metadata"),
            SyscallCategory::Directory => write!(f, "directory"),
            SyscallCategory::Process => write!(f, "process"),
            SyscallCategory::Network => write!(f, "network"),
            SyscallCategory::Memory => write!(f, "memory"),
            SyscallCategory::Signal => write!(f, "signal"),
            SyscallCategory::Ipc => write!(f, "ipc"),
            SyscallCategory::System => write!(f, "system"),
            SyscallCategory::Other => write!(f, "other"),
        }
    }
}

impl TraceEvent {
    pub fn timestamp(&self) -> DateTime<Utc> {
        match self {
            TraceEvent::Syscall(e) => e.timestamp,
            TraceEvent::Process(e) => match e {
                ProcessEvent::Exec { timestamp, .. } => *timestamp,
                ProcessEvent::Spawned { timestamp, .. } => *timestamp,
                ProcessEvent::Exited { timestamp, .. } => *timestamp,
                ProcessEvent::Signaled { timestamp, .. } => *timestamp,
            },
            TraceEvent::Summary(e) => e.timestamp,
        }
    }
}
