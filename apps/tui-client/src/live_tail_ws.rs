use crate::event::Action;
use futures_util::{SinkExt, StreamExt};
use shared::dto::cloudwatch::{LiveTailMessage, StartLiveTailRequest};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

/// Connect to the live-tail endpoint and stream events into the action
/// channel.
///
/// The caller should cancel `cancel` to stop the stream gracefully.
pub async fn stream_live_tail(
    base_url: &str,
    token: Option<&str>,
    request: StartLiveTailRequest,
    tx: mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    let Some(token) = token else {
        let _ = tx.send(Action::ShowError("Live tail requires a login token".into()));
        let _ = tx.send(Action::StopLiveTail);
        anyhow::bail!("missing live tail auth token");
    };

    let ws_url = match live_tail_ws_url(base_url) {
        Ok(url) => url,
        Err(err) => {
            report_live_tail_error(&tx, format!("Live tail WebSocket setup failed: {err}"));
            return Err(err);
        }
    };
    let (mut socket, _) = match tokio_tungstenite::connect_async(ws_url.as_str()).await {
        Ok(socket) => socket,
        Err(err) => {
            report_live_tail_error(&tx, format!("Live tail WebSocket connection failed: {err}"));
            return Err(err.into());
        }
    };
    let start_message = serde_json::json!({
        "token": token,
        "request": request,
    });
    let start_message = serde_json::to_string(&start_message)?;
    if let Err(err) = socket.send(Message::Text(start_message)).await {
        report_live_tail_error(&tx, format!("Live tail WebSocket start failed: {err}"));
        return Err(err.into());
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = socket.close(None).await;
                return Ok(());
            }
            msg = socket.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if !handle_live_tail_message(&tx, &text)? {
                            return Ok(());
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        let _ = tx.send(Action::StopLiveTail);
                        return Ok(());
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        report_live_tail_error(&tx, format!("Live tail WebSocket error: {err}"));
                        return Err(err.into());
                    }
                }
            }
        }
    }
}

fn report_live_tail_error(tx: &mpsc::UnboundedSender<Action>, message: String) {
    let _ = tx.send(Action::ShowError(message));
    let _ = tx.send(Action::StopLiveTail);
}

fn handle_live_tail_message(
    tx: &mpsc::UnboundedSender<Action>,
    text: &str,
) -> anyhow::Result<bool> {
    match serde_json::from_str::<LiveTailMessage>(text)? {
        LiveTailMessage::SessionStart { .. } => {}
        LiveTailMessage::Event(event) => {
            let _ = tx.send(Action::LiveTailEvent(event));
        }
        LiveTailMessage::SessionUpdate {
            events_per_second, ..
        } => {
            let _ = tx.send(Action::LiveTailSessionUpdate { events_per_second });
        }
        LiveTailMessage::Error { message } => {
            let _ = tx.send(Action::ShowError(message));
            let _ = tx.send(Action::StopLiveTail);
            return Ok(false);
        }
    }
    Ok(true)
}

fn live_tail_ws_url(base_url: &str) -> anyhow::Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(base_url.trim_end_matches('/'))?;
    let scheme = match url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => anyhow::bail!("unsupported live tail URL scheme: {other}"),
    };
    url.set_scheme(scheme)
        .map_err(|_| anyhow::anyhow!("failed to set live tail WebSocket URL scheme"))?;
    url.set_path("/api/cloudwatch/live-tail");
    url.set_query(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_tail_ws_url_converts_http_base_url() {
        let url = live_tail_ws_url("http://localhost:8443/").unwrap();
        assert_eq!(url.as_str(), "ws://localhost:8443/api/cloudwatch/live-tail");
    }

    #[test]
    fn live_tail_ws_url_converts_https_base_url() {
        let url = live_tail_ws_url("https://canopy.internal/base").unwrap();
        assert_eq!(
            url.as_str(),
            "wss://canopy.internal/api/cloudwatch/live-tail"
        );
    }

    #[test]
    fn handle_live_tail_message_emits_event_action() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let text = serde_json::json!({
            "type": "event",
            "timestamp": 123,
            "message": "hello",
            "log_stream_name": "web/application",
            "log_group_name": "/app/web"
        })
        .to_string();

        assert!(handle_live_tail_message(&tx, &text).unwrap());

        let action = rx.try_recv().unwrap();
        match action {
            Action::LiveTailEvent(event) => {
                assert_eq!(event.message, "hello");
                assert_eq!(event.log_group_name, "/app/web");
            }
            other => panic!("expected live tail event, got {other:?}"),
        }
    }

    #[test]
    fn handle_live_tail_message_emits_session_update_action() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let text = serde_json::json!({
            "type": "session_update",
            "session_id": "s-1",
            "events_per_second": 0.5
        })
        .to_string();

        assert!(handle_live_tail_message(&tx, &text).unwrap());

        assert!(matches!(
            rx.try_recv().unwrap(),
            Action::LiveTailSessionUpdate {
                events_per_second: Some(0.5)
            }
        ));
    }

    #[test]
    fn handle_live_tail_message_stops_on_server_error() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let text = serde_json::json!({
            "type": "error",
            "message": "Authentication failed"
        })
        .to_string();

        assert!(!handle_live_tail_message(&tx, &text).unwrap());
        assert!(matches!(
            rx.try_recv().unwrap(),
            Action::ShowError(message) if message == "Authentication failed"
        ));
        assert!(matches!(rx.try_recv().unwrap(), Action::StopLiveTail));
    }

    #[tokio::test]
    async fn stream_live_tail_reports_setup_error_to_ui() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let request = StartLiveTailRequest {
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            log_group_arns: vec![
                "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service".into(),
            ],
            filter_pattern: None,
        };

        let err = stream_live_tail(
            "file:///tmp/canopy",
            Some("token"),
            request,
            tx,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("unsupported live tail URL scheme"));
        assert!(matches!(
            rx.try_recv().unwrap(),
            Action::ShowError(message)
                if message.contains("Live tail WebSocket setup failed")
        ));
        assert!(matches!(rx.try_recv().unwrap(), Action::StopLiveTail));
    }
}
