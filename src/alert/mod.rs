pub mod desktop;
pub mod stdout;
pub mod syslog;
pub mod webhook;

use crate::error::SandtraceError;
use crate::event::{AlertChannel, RuleMatchEvent};
use async_trait::async_trait;

#[async_trait]
pub trait AlertDispatcher: Send + Sync {
    async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError>;
    fn channel(&self) -> AlertChannel;
}

pub struct AlertRouter {
    dispatchers: Vec<Box<dyn AlertDispatcher>>,
}

impl AlertRouter {
    pub fn new(channels: &[AlertChannel]) -> Self {
        let mut dispatchers: Vec<Box<dyn AlertDispatcher>> = Vec::new();

        for channel in channels {
            match channel {
                AlertChannel::Stdout => {
                    dispatchers.push(Box::new(stdout::StdoutAlert::new()));
                }
                AlertChannel::Desktop => {
                    dispatchers.push(Box::new(desktop::DesktopAlert::new()));
                }
                AlertChannel::Webhook(url) => {
                    dispatchers.push(Box::new(webhook::WebhookAlert::new(url.clone())));
                }
                AlertChannel::Syslog => {
                    dispatchers.push(Box::new(syslog::SyslogAlert::new()));
                }
            }
        }

        // Default to stdout if no channels configured
        if dispatchers.is_empty() {
            dispatchers.push(Box::new(stdout::StdoutAlert::new()));
        }

        Self { dispatchers }
    }

    pub async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError> {
        for dispatcher in &self.dispatchers {
            if let Err(e) = dispatcher.dispatch(event).await {
                log::error!(
                    "Alert dispatch failed for {:?}: {}",
                    dispatcher.channel(),
                    e
                );
            }
        }
        Ok(())
    }

    pub async fn dispatch_to_channels(
        &self,
        event: &RuleMatchEvent,
        channels: &[AlertChannel],
    ) -> Result<(), SandtraceError> {
        for dispatcher in &self.dispatchers {
            if channels.contains(&dispatcher.channel()) {
                if let Err(e) = dispatcher.dispatch(event).await {
                    log::error!(
                        "Alert dispatch failed for {:?}: {}",
                        dispatcher.channel(),
                        e
                    );
                }
            }
        }
        Ok(())
    }
}
