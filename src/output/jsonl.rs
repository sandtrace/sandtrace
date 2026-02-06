use std::io::{self, BufWriter, Write};

use anyhow::Result;

use crate::event::TraceEvent;
use super::OutputSink;

/// JSONL output sink - one JSON object per line.
pub struct JsonlSink {
    writer: BufWriter<Box<dyn Write>>,
}

impl JsonlSink {
    pub fn new_file(file: std::fs::File) -> Self {
        Self {
            writer: BufWriter::new(Box::new(file)),
        }
    }

    pub fn new_stdout() -> Self {
        Self {
            writer: BufWriter::new(Box::new(io::stdout())),
        }
    }
}

impl OutputSink for JsonlSink {
    fn emit(&mut self, event: &TraceEvent) -> Result<()> {
        serde_json::to_writer(&mut self.writer, event)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }
}
