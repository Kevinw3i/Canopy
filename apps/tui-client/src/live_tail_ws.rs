use crate::event::Action;
use shared::dto::cloudwatch::LiveTailEvent;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Connect to the live-tail endpoint and stream events into the action
/// channel. Currently a dev-mode stub that emits simulated events.
/// A production implementation requires a WebSocket client library
/// (e.g. tokio-tungstenite) which will be added when live tail exits beta.
///
/// The caller should cancel `cancel` to stop the stream gracefully.
pub async fn stream_live_tail(
    _base_url: &str,
    _token: Option<&str>,
    tx: mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    tracing::info!("Live tail: streaming simulated events (WebSocket client not yet wired)");

    for i in 1..=20 {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("Live tail stream cancelled");
                return Ok(());
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
        }

        let level = match i % 4 {
            0 => "ERROR",
            1 => "WARN",
            _ => "INFO",
        };

        let event = LiveTailEvent {
            timestamp: chrono::Utc::now().timestamp_millis(),
            message: format!(
                r#"{{"level":"{level}","msg":"Simulated log event #{i}","service":"web","request_id":"{}"}}"#,
                uuid::Uuid::new_v4(),
            ),
            log_stream_name: "web-prod-01/application".into(),
            log_group_name: "/app/web-service".into(),
        };

        if tx.send(Action::LiveTailEvent(event)).is_err() {
            break; // receiver dropped
        }
    }

    let _ = tx.send(Action::StopLiveTail);
    Ok(())
}
