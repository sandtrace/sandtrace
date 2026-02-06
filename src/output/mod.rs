pub mod jsonl;
pub mod terminal;

use std::path::Path;

use anyhow::Result;

use crate::event::TraceEvent;
use jsonl::JsonlSink;
use terminal::TerminalSink;

/// Trait for output destinations.
pub trait OutputSink {
    fn emit(&mut self, event: &TraceEvent) -> Result<()>;
    fn flush(&mut self) -> Result<()>;
}

/// Multiplexes events to multiple sinks.
pub struct OutputManager {
    sinks: Vec<Box<dyn OutputSink>>,
}

impl OutputManager {
    pub fn new(
        output_path: Option<&Path>,
        no_color: bool,
        verbosity: u8,
    ) -> Result<Self> {
        let mut sinks: Vec<Box<dyn OutputSink>> = Vec::new();

        // Terminal sink always goes to stderr
        sinks.push(Box::new(TerminalSink::new(verbosity, no_color)));

        // JSONL sink goes to file or stdout
        match output_path {
            Some(path) => {
                let file = std::fs::File::create(path)?;
                sinks.push(Box::new(JsonlSink::new_file(file)));
            }
            None => {
                sinks.push(Box::new(JsonlSink::new_stdout()));
            }
        }

        Ok(Self { sinks })
    }

    pub fn emit(&mut self, event: TraceEvent) -> Result<()> {
        for sink in &mut self.sinks {
            sink.emit(&event)?;
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
