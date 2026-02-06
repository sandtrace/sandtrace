use super::OutputSink;
use crate::error::{OutputError, Result};
use crate::event::TraceEvent;
use std::io::Write;

pub struct JsonlWriter<W: Write + Send> {
    writer: W,
}

impl<W: Write + Send> JsonlWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write + Send> OutputSink for JsonlWriter<W> {
    fn emit_event(&mut self, event: TraceEvent) -> Result<()> {
        let json = serde_json::to_string(&event)
            .map_err(OutputError::Serialize)?;
        writeln!(self.writer, "{}", json)
            .map_err(|e| OutputError::Io(e).into())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush().map_err(|e| OutputError::Io(e).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{SyscallCategory, PolicyAction, SyscallArgs};
    use chrono::Utc;

    #[test]
    fn test_jsonl_output() {
        let mut buf = Vec::new();
        {
            let mut writer = JsonlWriter::new(&mut buf);
            let event = TraceEvent::Syscall(crate::event::SyscallEvent {
                timestamp: Utc::now(),
                pid: 1234,
                tgid: 1234,
                syscall: "openat".to_string(),
                syscall_nr: 257,
                args: SyscallArgs {
                    raw: [4294967196, 0, 0, 0, 0, 0],
                    decoded: None,
                },
                return_value: 3,
                success: true,
                duration_us: 42,
                action: PolicyAction::Allow,
                category: SyscallCategory::FileRead,
            });
            writer.emit_event(event).unwrap();
        }

        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("openat"));
        assert!(output.contains("syscall"));
    }
}
