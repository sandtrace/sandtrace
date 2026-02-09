use crate::alert::AlertRouter;
use crate::event::FileAccessEvent;
use crate::process::ProcessTree;
use crate::rules::matcher::RuleMatcher;
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct EventHandler {
    matcher: RuleMatcher,
    alert_router: Arc<AlertRouter>,
    process_tree: Arc<Mutex<ProcessTree>>,
}

impl EventHandler {
    pub fn new(
        matcher: RuleMatcher,
        alert_router: Arc<AlertRouter>,
        process_tree: Arc<Mutex<ProcessTree>>,
    ) -> Self {
        Self {
            matcher,
            alert_router,
            process_tree,
        }
    }

    pub async fn handle_file_access(&self, mut event: FileAccessEvent) {
        // Enrich with process lineage
        if let Some(pid) = event.pid {
            let mut tree = self.process_tree.lock().await;
            event.process_lineage = tree.lineage(pid);
            tree.evict_stale();
        }

        // Match against rules
        let matches = self.matcher.match_file_access(&event);

        // Dispatch alerts for each match
        for rule_match in matches {
            log::debug!(
                "Rule matched: {} (severity: {})",
                rule_match.rule_id,
                rule_match.severity
            );

            let channels = rule_match.alert_channels.clone();
            if let Err(e) = self
                .alert_router
                .dispatch_to_channels(&rule_match, &channels)
                .await
            {
                log::error!("Failed to dispatch alert: {}", e);
            }
        }
    }
}
