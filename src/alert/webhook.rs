use crate::error::{AlertError, SandtraceError};
use crate::event::{AlertChannel, RuleMatchEvent};
use async_trait::async_trait;

pub struct WebhookAlert {
    url: String,
    client: reqwest::Client,
}

impl WebhookAlert {
    pub fn new(url: String) -> Self {
        Self {
            url,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
        }
    }
}

#[async_trait]
impl super::AlertDispatcher for WebhookAlert {
    async fn dispatch(&self, event: &RuleMatchEvent) -> Result<(), SandtraceError> {
        let payload = serde_json::json!({
            "rule_id": event.rule_id,
            "rule_name": event.rule_name,
            "severity": event.severity,
            "description": event.description,
            "matched_data": event.matched_data,
            "process_name": event.process_name,
            "pid": event.pid,
            "timestamp": event.timestamp.to_rfc3339(),
        });

        self.client
            .post(&self.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| SandtraceError::Alert(AlertError::WebhookSend(e.to_string())))?;

        Ok(())
    }

    fn channel(&self) -> AlertChannel {
        AlertChannel::Webhook(self.url.clone())
    }
}
