use crate::event::Action;
use futures_util::{SinkExt, StreamExt};
use shared::dto::cloudwatch::{LiveTailMessage, StartLiveTailRequest};
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

const LIVE_TAIL_MAX_RECONNECTS: usize = 3;
const LIVE_TAIL_INITIAL_RECONNECT_DELAY: Duration = Duration::from_millis(500);
const LIVE_TAIL_MAX_RECONNECT_DELAY: Duration = Duration::from_secs(5);

#[derive(Clone, Copy)]
struct ReconnectPolicy {
    max_reconnects: usize,
    initial_delay: Duration,
    max_delay: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            max_reconnects: LIVE_TAIL_MAX_RECONNECTS,
            initial_delay: LIVE_TAIL_INITIAL_RECONNECT_DELAY,
            max_delay: LIVE_TAIL_MAX_RECONNECT_DELAY,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum StreamExit {
    Cancelled,
    Terminal,
    Transient { reason: String },
}

#[derive(Debug, PartialEq, Eq)]
enum MessageOutcome {
    Continue,
    SessionStarted,
    Terminal,
}

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
    stream_live_tail_with_policy(
        base_url,
        token,
        request,
        tx,
        cancel,
        ReconnectPolicy::default(),
    )
    .await
}

async fn stream_live_tail_with_policy(
    base_url: &str,
    token: Option<&str>,
    request: StartLiveTailRequest,
    tx: mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
    policy: ReconnectPolicy,
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

    let mut reconnects = 0;
    let mut delay = policy.initial_delay;
    loop {
        match stream_live_tail_once(&ws_url, token, request.clone(), &tx, cancel.clone()).await {
            Ok(StreamExit::Cancelled | StreamExit::Terminal) => return Ok(()),
            Ok(StreamExit::Transient { reason }) => {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                if reconnects >= policy.max_reconnects {
                    report_live_tail_error(
                        &tx,
                        format!(
                            "Live tail WebSocket disconnected after {} reconnect attempts: {}",
                            policy.max_reconnects, reason
                        ),
                    );
                    anyhow::bail!(reason);
                }

                reconnects += 1;
                let _ = tx.send(Action::LiveTailReconnecting);
                tokio::select! {
                    _ = cancel.cancelled() => return Ok(()),
                    _ = sleep(delay) => {}
                }
                delay = delay.saturating_mul(2).min(policy.max_delay);
            }
            Err(err) => {
                if cancel.is_cancelled() {
                    return Ok(());
                }
                report_live_tail_error(&tx, format!("Live tail WebSocket protocol failed: {err}"));
                return Err(err);
            }
        }
    }
}

async fn stream_live_tail_once(
    ws_url: &reqwest::Url,
    token: &str,
    request: StartLiveTailRequest,
    tx: &mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
) -> anyhow::Result<StreamExit> {
    let (mut socket, _) = match tokio_tungstenite::connect_async(ws_url.as_str()).await {
        Ok(socket) => socket,
        Err(err) => {
            return Ok(StreamExit::Transient {
                reason: format!("connection failed: {err}"),
            });
        }
    };
    let start_message = serde_json::json!({
        "token": token,
        "request": request,
    });
    let start_message = serde_json::to_string(&start_message)?;
    if let Err(err) = socket.send(Message::Text(start_message)).await {
        return Ok(StreamExit::Transient {
            reason: format!("start failed: {err}"),
        });
    }

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                let _ = socket.close(None).await;
                return Ok(StreamExit::Cancelled);
            }
            msg = socket.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        match handle_live_tail_message(tx, &text)? {
                            MessageOutcome::Continue => {}
                            MessageOutcome::SessionStarted => {}
                            MessageOutcome::Terminal => {
                                return Ok(StreamExit::Terminal);
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        return Ok(StreamExit::Transient {
                            reason: "connection closed".into(),
                        });
                    }
                    Some(Ok(_)) => {}
                    Some(Err(err)) => {
                        return Ok(StreamExit::Transient {
                            reason: format!("socket error: {err}"),
                        });
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
) -> anyhow::Result<MessageOutcome> {
    match serde_json::from_str::<LiveTailMessage>(text)? {
        LiveTailMessage::SessionStart { .. } => {
            let _ = tx.send(Action::LiveTailConnected);
            return Ok(MessageOutcome::SessionStarted);
        }
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
            return Ok(MessageOutcome::Terminal);
        }
    }
    Ok(MessageOutcome::Continue)
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
    use futures_util::{SinkExt, StreamExt};
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

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

        assert_eq!(
            handle_live_tail_message(&tx, &text).unwrap(),
            MessageOutcome::Continue
        );

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

        assert_eq!(
            handle_live_tail_message(&tx, &text).unwrap(),
            MessageOutcome::Continue
        );

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

        assert_eq!(
            handle_live_tail_message(&tx, &text).unwrap(),
            MessageOutcome::Terminal
        );
        assert!(matches!(
            rx.try_recv().unwrap(),
            Action::ShowError(message) if message == "Authentication failed"
        ));
        assert!(matches!(rx.try_recv().unwrap(), Action::StopLiveTail));
    }

    #[test]
    fn handle_live_tail_message_marks_session_started() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let text = serde_json::json!({
            "type": "session_start",
            "session_id": "s-1"
        })
        .to_string();

        assert_eq!(
            handle_live_tail_message(&tx, &text).unwrap(),
            MessageOutcome::SessionStarted
        );
        assert!(matches!(rx.try_recv().unwrap(), Action::LiveTailConnected));
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

    #[tokio::test]
    async fn stream_live_tail_reconnects_after_transient_close() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (first_stream, _) = listener.accept().await.unwrap();
            let mut first_ws = accept_async(first_stream).await.unwrap();
            let _start = first_ws.next().await.unwrap().unwrap();
            first_ws.close(None).await.unwrap();

            let (second_stream, _) = listener.accept().await.unwrap();
            let mut second_ws = accept_async(second_stream).await.unwrap();
            let _start = second_ws.next().await.unwrap().unwrap();
            second_ws
                .send(Message::Text(
                    serde_json::json!({
                        "type": "session_start",
                        "session_id": "s-2"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            second_ws
                .send(Message::Text(
                    serde_json::json!({
                        "type": "event",
                        "timestamp": 123,
                        "message": "after reconnect",
                        "log_stream_name": "web/application",
                        "log_group_name": "/app/web"
                    })
                    .to_string(),
                ))
                .await
                .unwrap();
            let _ = second_ws.next().await;
        });

        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let request = StartLiveTailRequest {
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            log_group_arns: vec![
                "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service".into(),
            ],
            filter_pattern: None,
        };
        let base_url = format!("http://{addr}");
        let stream_task = tokio::spawn(async move {
            stream_live_tail_with_policy(
                &base_url,
                Some("token"),
                request,
                tx,
                cancel_for_task,
                ReconnectPolicy {
                    max_reconnects: 1,
                    initial_delay: Duration::ZERO,
                    max_delay: Duration::ZERO,
                },
            )
            .await
        });

        let timeout = tokio::time::sleep(Duration::from_secs(2));
        tokio::pin!(timeout);
        let mut saw_reconnecting = false;
        let mut saw_connected = false;
        let mut saw_event = false;
        while !saw_event {
            tokio::select! {
                action = rx.recv() => {
                    match action.expect("live tail action") {
                        Action::LiveTailReconnecting => saw_reconnecting = true,
                        Action::LiveTailConnected => saw_connected = true,
                        Action::LiveTailEvent(event) => {
                            assert_eq!(event.message, "after reconnect");
                            saw_event = true;
                        }
                        other => panic!("unexpected action: {other:?}"),
                    }
                }
                _ = &mut timeout => panic!("timed out waiting for reconnect event"),
            }
        }

        cancel.cancel();
        stream_task.await.unwrap().unwrap();
        server.await.unwrap();
        assert!(saw_reconnecting);
        assert!(saw_connected);
    }
}
