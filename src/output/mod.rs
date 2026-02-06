use crate::error::Result;
use crate::event::TraceEvent;
use std::io::Write;

pub mod jsonl;
pub mod terminal;

pub trait OutputSink: Send {
    fn emit_event(&mut self, event: TraceEvent) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

pub struct OutputManager {
    sinks: Vec<Box<dyn OutputSink>>,
}

impl OutputManager {
    pub fn new(jsonl_output: Option<std::fs::File>, terminal_verbosity: u8, no_color: bool) -> Self {
        let mut sinks: Vec<Box<dyn OutputSink>> = Vec::new();
        let output_to_file = jsonl_output.is_some();

        // Always add JSONL output (stdout or file)
        if let Some(file) = jsonl_output {
            sinks.push(Box::new(jsonl::JsonlWriter::new(file)));
        } else {
            sinks.push(Box::new(jsonl::JsonlWriter::new(std::io::stdout())));
        }

        // Add terminal output for human readability
        if terminal_verbosity > 0 || output_to_file {
            sinks.push(Box::new(terminal::TerminalWriter::new(
                terminal_verbosity,
                no_color,
            )));
        }

        Self { sinks }
    }

    pub fn emit_event(&mut self, event: TraceEvent) -> Result<()> {
        for sink in &mut self.sinks {
            sink.emit_event(event.clone())?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        for sink in &mut self.sinks {
            sink.flush()?;
        }
        Ok(())
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new(None, 1, false)
    }
}
