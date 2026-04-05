use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::cloudwatch::*;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/cloudwatch/live-tail", get(live_tail_ws))
}

async fn live_tail_ws(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Live tail is a beta feature — only available in dev_mode for now.
    if !state.config.dev_mode {
        return (
            axum::http::StatusCode::NOT_FOUND,
            "Live tail is not available in this build",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| handle_live_tail(socket, state))
        .into_response()
}

async fn handle_live_tail(mut socket: WebSocket, state: Arc<AppState>) {
    // First message should be auth token + start request
    let start_req = match socket.recv().await {
        Some(Ok(Message::Text(text))) => {
            match serde_json::from_str::<LiveTailStartMessage>(&text) {
                Ok(msg) => msg,
                Err(e) => {
                    let _ = socket
                        .send(Message::Text(
                            serde_json::to_string(&LiveTailMessage::Error {
                                message: format!("Invalid start message: {}", e),
                            })
                            .unwrap(),
                        ))
                        .await;
                    return;
                }
            }
        }
        _ => return,
    };

    // Validate token
    let auth_service = crate::services::auth::AuthService::new(state.config.clone());
    let claims = match auth_service.validate_token(&start_req.token) {
        Ok(c) => c,
        Err(_) => {
            let _ = socket
                .send(Message::Text(
                    serde_json::to_string(&LiveTailMessage::Error {
                        message: "Authentication failed".into(),
                    })
                    .unwrap(),
                ))
                .await;
            return;
        }
    };

    // Verify entitlements
    let ent_service =
        crate::services::entitlements::EntitlementService::new(state.entitlement_store.clone());
    let entitlements = ent_service.evaluate(&claims).await;

    if !entitlements.features.can_use_cloudwatch_tail {
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&LiveTailMessage::Error {
                    message: "Live tail not authorized".into(),
                })
                .unwrap(),
            ))
            .await;
        return;
    }

    // Enforce account entitlement
    if !entitlements
        .allowed_accounts
        .iter()
        .any(|a| a.account_id == start_req.request.account_id)
    {
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&LiveTailMessage::Error {
                    message: "Account not authorized".into(),
                })
                .unwrap(),
            ))
            .await;
        return;
    }

    // Enforce region entitlement
    if !entitlements
        .allowed_regions
        .contains(&start_req.request.region)
    {
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&LiveTailMessage::Error {
                    message: "Region not authorized".into(),
                })
                .unwrap(),
            ))
            .await;
        return;
    }

    // Enforce log-group ARN entitlements
    if !entitlements.allowed_log_group_arns.is_empty() {
        for lg_arn in &start_req.request.log_group_arns {
            if !entitlements
                .allowed_log_group_arns
                .iter()
                .any(|pattern| crate::services::entitlements::arn_matches_pattern(pattern, lg_arn))
            {
                let _ = socket
                    .send(Message::Text(
                        serde_json::to_string(&LiveTailMessage::Error {
                            message: format!("Log group '{}' not authorized", lg_arn),
                        })
                        .unwrap(),
                    ))
                    .await;
                return;
            }
        }
    }

    let _ = state.audit_service.log_event(
        &claims.sub,
        AuditAction::CloudwatchLiveTailStart,
        AuditOutcome::Success,
        Some(&start_req.request.account_id),
        Some(&start_req.request.region),
        Some(&start_req.request.log_group_arns.join(",")),
        None,
    );

    let session_id = uuid::Uuid::new_v4().to_string();

    // Send session start
    let _ = socket
        .send(Message::Text(
            serde_json::to_string(&LiveTailMessage::SessionStart {
                session_id: session_id.clone(),
            })
            .unwrap(),
        ))
        .await;

    // Use simulated events when mock AWS is enabled.
    // When mock AWS is not enabled but we're in dev mode, reject explicitly
    // since the real CloudWatch Live Tail integration is not yet wired.
    if !state.config.use_mock_aws() {
        let _ = socket
            .send(Message::Text(
                serde_json::to_string(&LiveTailMessage::Error {
                    message: "Live tail real-AWS streaming is not yet available. \
                              Enable mock_aws_data in config or wait for the production \
                              integration."
                        .into(),
                })
                .unwrap(),
            ))
            .await;
        let _ = state.audit_service.log_event(
            &claims.sub,
            AuditAction::CloudwatchLiveTailStop,
            AuditOutcome::Failure,
            Some(&start_req.request.account_id),
            Some(&start_req.request.region),
            Some(&session_id),
            Some("real-AWS live tail not yet implemented"),
        );
        return;
    }

    {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut count = 0u64;

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    count += 1;
                    let event = LiveTailMessage::Event(LiveTailEvent {
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        message: format!(
                            r#"{{"level":"{}","msg":"Simulated log event #{}","service":"web","request_id":"{}"}}"#,
                            match count % 4 {
                                0 => "ERROR",
                                1 => "WARN",
                                _ => "INFO",
                            },
                            count,
                            uuid::Uuid::new_v4(),
                        ),
                        log_stream_name: "web-prod-01/application".into(),
                        log_group_name: "/app/web-service".into(),
                    });

                    if socket.send(Message::Text(
                        serde_json::to_string(&event).unwrap()
                    )).await.is_err() {
                        break;
                    }

                    // Send periodic session update
                    if count.is_multiple_of(5) {
                        let update = LiveTailMessage::SessionUpdate {
                            session_id: session_id.clone(),
                            events_per_second: Some(0.5),
                        };
                        let _ = socket.send(Message::Text(
                            serde_json::to_string(&update).unwrap()
                        )).await;
                    }
                }
                msg = socket.recv() => {
                    match msg {
                        Some(Ok(Message::Close(_))) | None => break,
                        _ => {}
                    }
                }
            }
        }
    }

    let _ = state.audit_service.log_event(
        &claims.sub,
        AuditAction::CloudwatchLiveTailStop,
        AuditOutcome::Success,
        Some(&start_req.request.account_id),
        Some(&start_req.request.region),
        Some(&session_id),
        None,
    );
}

/// Internal message format for starting a live tail over WebSocket
#[derive(serde::Deserialize)]
struct LiveTailStartMessage {
    token: String,
    request: StartLiveTailRequest,
}
