use aws_sdk_cloudwatchlogs::types::StartLiveTailResponseStream;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::HeaderMap,
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::aws::clients::AwsClients;
use crate::aws::credentials::SessionContext;
use crate::services::audit::AuditRequestContext;
use crate::services::AppState;
use shared::dto::audit::{AuditAction, AuditOutcome};
use shared::dto::cloudwatch::*;
use shared::dto::entitlements::AllowedAccount;

const LIVE_TAIL_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/api/cloudwatch/live-tail", get(live_tail_ws))
}

async fn live_tail_ws(
    ws: WebSocketUpgrade,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_live_tail(socket, state, headers))
        .into_response()
}

async fn handle_live_tail(mut socket: WebSocket, state: Arc<AppState>, headers: HeaderMap) {
    // First message should be auth token + start request
    let start_req = match tokio::time::timeout(LIVE_TAIL_START_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => {
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
        Err(_) => {
            let _ = send_live_tail_message(
                &mut socket,
                &LiveTailMessage::Error {
                    message: "Live tail start message timed out".into(),
                },
            )
            .await;
            return;
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
    let audit_ctx = AuditRequestContext::from_headers_and_claims(&headers, &claims);

    if start_req.request.log_group_arns.is_empty() {
        let message = "At least one log group ARN is required";
        audit_live_tail_start(
            &state,
            &claims.sub,
            &audit_ctx,
            &start_req.request,
            AuditOutcome::Failure,
            Some(message),
        );
        let _ = send_live_tail_message(
            &mut socket,
            &LiveTailMessage::Error {
                message: message.into(),
            },
        )
        .await;
        return;
    }

    // Verify entitlements using a single matching rule for feature + scope.
    let ent_service =
        crate::services::entitlements::EntitlementService::new(state.entitlement_store.clone());
    let live_tail_accounts = ent_service
        .scoped_accounts_for_log_groups(
            &claims,
            &start_req.request.account_id,
            &start_req.request.region,
            &start_req.request.log_group_arns,
            |f| f.can_use_cloudwatch_tail,
        )
        .await;

    if live_tail_accounts.is_empty() {
        let message = "Live tail not authorized for requested scope";
        audit_live_tail_start(
            &state,
            &claims.sub,
            &audit_ctx,
            &start_req.request,
            AuditOutcome::Denied,
            Some(message),
        );
        let _ = send_live_tail_message(
            &mut socket,
            &LiveTailMessage::Error {
                message: message.into(),
            },
        )
        .await;
        return;
    }

    if state.config.use_mock_aws() {
        audit_live_tail_start(
            &state,
            &claims.sub,
            &audit_ctx,
            &start_req.request,
            AuditOutcome::Success,
            None,
        );
        let session_id = uuid::Uuid::new_v4().to_string();
        if !send_live_tail_message(
            &mut socket,
            &LiveTailMessage::SessionStart {
                session_id: session_id.clone(),
            },
        )
        .await
        {
            return;
        }
        stream_mock_live_tail(&mut socket, &session_id).await;
        audit_live_tail_stop(
            &state,
            &claims.sub,
            &audit_ctx,
            &start_req.request,
            &session_id,
            AuditOutcome::Success,
            None,
        );
        return;
    }

    let client = match live_tail_cwl_client(
        &state,
        &live_tail_accounts,
        &start_req.request.account_id,
        &start_req.request.region,
        &claims.sub,
    )
    .await
    {
        Ok(client) => client,
        Err(message) => {
            let _ = send_live_tail_message(
                &mut socket,
                &LiveTailMessage::Error {
                    message: message.clone(),
                },
            )
            .await;
            audit_live_tail_start(
                &state,
                &claims.sub,
                &audit_ctx,
                &start_req.request,
                AuditOutcome::Failure,
                Some(&message),
            );
            return;
        }
    };

    let mut builder = client
        .start_live_tail()
        .set_log_group_identifiers(Some(start_req.request.log_group_arns.clone()))
        .set_log_event_filter_pattern(start_req.request.filter_pattern.clone());
    if matches!(start_req.request.filter_pattern.as_deref(), Some(pattern) if pattern.trim().is_empty())
    {
        builder = builder.set_log_event_filter_pattern(None);
    }

    let output = match builder.send().await {
        Ok(output) => output,
        Err(err) => {
            let message = format!("Failed to start CloudWatch Live Tail: {err}");
            let _ = send_live_tail_message(
                &mut socket,
                &LiveTailMessage::Error {
                    message: message.clone(),
                },
            )
            .await;
            audit_live_tail_start(
                &state,
                &claims.sub,
                &audit_ctx,
                &start_req.request,
                AuditOutcome::Failure,
                Some(&message),
            );
            return;
        }
    };

    audit_live_tail_start(
        &state,
        &claims.sub,
        &audit_ctx,
        &start_req.request,
        AuditOutcome::Success,
        None,
    );
    let mut response_stream = output.response_stream;
    let mut session_id = uuid::Uuid::new_v4().to_string();
    let (stop_outcome, stop_error): (AuditOutcome, Option<String>) = 'stream: loop {
        tokio::select! {
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break 'stream (AuditOutcome::Success, None),
                    _ => {}
                }
            }
            event = response_stream.recv() => {
                match event {
                    Ok(Some(StartLiveTailResponseStream::SessionStart(start))) => {
                        if let Some(aws_session_id) = start.session_id() {
                            session_id = aws_session_id.to_string();
                        }
                        if !send_live_tail_message(
                            &mut socket,
                            &LiveTailMessage::SessionStart {
                                session_id: session_id.clone(),
                            },
                        )
                        .await
                        {
                            break 'stream (AuditOutcome::Success, None);
                        }
                    }
                    Ok(Some(StartLiveTailResponseStream::SessionUpdate(update))) => {
                        let results = update.session_results();
                        for result in results {
                            let message = LiveTailMessage::Event(LiveTailEvent {
                                timestamp: result
                                    .timestamp()
                                    .unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
                                message: result.message().unwrap_or_default().to_string(),
                                log_stream_name: result.log_stream_name().unwrap_or_default().to_string(),
                                log_group_name: result
                                    .log_group_identifier()
                                    .map(log_group_name_from_identifier)
                                    .unwrap_or_else(|| {
                                        start_req
                                            .request
                                            .log_group_arns
                                            .first()
                                            .map(|arn| log_group_name_from_identifier(arn))
                                            .unwrap_or_default()
                                    }),
                            });
                            if !send_live_tail_message(&mut socket, &message).await {
                                break 'stream (AuditOutcome::Success, None);
                            }
                        }

                        let update = LiveTailMessage::SessionUpdate {
                            session_id: session_id.clone(),
                            events_per_second: Some(results.len() as f64),
                        };
                        if !send_live_tail_message(&mut socket, &update).await {
                            break 'stream (AuditOutcome::Success, None);
                        }
                    }
                    Ok(Some(_)) => {
                        tracing::debug!("CloudWatch Live Tail returned an unknown event stream message");
                    }
                    Ok(None) => break 'stream (AuditOutcome::Success, None),
                    Err(err) => {
                        let message = format!("CloudWatch Live Tail stream failed: {err}");
                        let _ = send_live_tail_message(
                            &mut socket,
                            &LiveTailMessage::Error {
                                message: message.clone(),
                            },
                        )
                        .await;
                        break 'stream (AuditOutcome::Failure, Some(message));
                    }
                }
            }
        }
    };
    audit_live_tail_stop(
        &state,
        &claims.sub,
        &audit_ctx,
        &start_req.request,
        &session_id,
        stop_outcome,
        stop_error.as_deref(),
    );
}

fn live_tail_metadata(
    audit_ctx: &AuditRequestContext,
    request: &StartLiveTailRequest,
) -> serde_json::Value {
    audit_ctx.metadata(serde_json::json!({
        "filter_pattern": request.filter_pattern.as_deref(),
        "log_group_arns": &request.log_group_arns,
    }))
}

fn audit_live_tail_start(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    request: &StartLiveTailRequest,
    outcome: AuditOutcome,
    error: Option<&str>,
) {
    state
        .audit_service
        .event(actor, AuditAction::CloudwatchLiveTailStart, outcome)
        .account(Some(&request.account_id))
        .region(Some(&request.region))
        .target(Some(&request.log_group_arns.join(",")))
        .error(error)
        .optional_metadata(Some(live_tail_metadata(audit_ctx, request)))
        .commit_best_effort();
}

fn audit_live_tail_stop(
    state: &AppState,
    actor: &str,
    audit_ctx: &AuditRequestContext,
    request: &StartLiveTailRequest,
    session_id: &str,
    outcome: AuditOutcome,
    error: Option<&str>,
) {
    state
        .audit_service
        .event(actor, AuditAction::CloudwatchLiveTailStop, outcome)
        .account(Some(&request.account_id))
        .region(Some(&request.region))
        .target(Some(session_id))
        .error(error)
        .optional_metadata(Some(live_tail_metadata(audit_ctx, request)))
        .commit_best_effort();
}

async fn send_live_tail_message(socket: &mut WebSocket, message: &LiveTailMessage) -> bool {
    socket
        .send(Message::Text(serde_json::to_string(message).unwrap()))
        .await
        .is_ok()
}

async fn stream_mock_live_tail(socket: &mut WebSocket, session_id: &str) {
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

                if !send_live_tail_message(socket, &event).await {
                    break;
                }

                if count.is_multiple_of(5) {
                    let update = LiveTailMessage::SessionUpdate {
                        session_id: session_id.to_string(),
                        events_per_second: Some(0.5),
                    };
                    let _ = send_live_tail_message(socket, &update).await;
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

async fn live_tail_cwl_client(
    state: &AppState,
    accounts: &[AllowedAccount],
    account_id: &str,
    region: &str,
    user_id: &str,
) -> Result<aws_sdk_cloudwatchlogs::Client, String> {
    if accounts.is_empty() {
        return Err("Account not authorized".into());
    }

    let session_ctx = SessionContext {
        user_id: user_id.to_string(),
        team: "canopy".to_string(),
        environment: if state.config.dev_mode {
            "dev".to_string()
        } else {
            "production".to_string()
        },
        session_duration_seconds: state.config.aws.session_duration_seconds,
        sts_external_id: state.config.aws.sts_external_id.clone(),
    };

    let mut last_error = None;
    for account in accounts {
        match crate::aws::credentials::resolve_aws_config(
            &state.base_aws_config,
            account,
            region,
            &session_ctx,
        )
        .await
        {
            Ok(config) => return Ok(AwsClients::cloudwatch_logs(&config)),
            Err(err) => {
                tracing::debug!(
                    role = %account.role_arn,
                    error = ?err,
                    "CWL Live Tail client creation failed, trying next role"
                );
                last_error = Some(err.to_string());
            }
        }
    }

    Err(format!(
        "Failed to get AWS credentials for account {}{}",
        account_id,
        last_error
            .as_deref()
            .map(|err| format!(": {err}"))
            .unwrap_or_default()
    ))
}

fn log_group_name_from_identifier(identifier: &str) -> String {
    identifier
        .rsplit_once(":log-group:")
        .map(|(_, name)| name.trim_end_matches(":*").to_string())
        .unwrap_or_else(|| identifier.to_string())
}

/// Internal message format for starting a live tail over WebSocket
#[derive(serde::Deserialize)]
struct LiveTailStartMessage {
    token: String,
    request: StartLiveTailRequest,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_group_name_from_identifier_extracts_arn_name() {
        assert_eq!(
            log_group_name_from_identifier(
                "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service"
            ),
            "/app/web-service"
        );
    }

    #[test]
    fn log_group_name_from_identifier_strips_stream_suffix() {
        assert_eq!(
            log_group_name_from_identifier(
                "arn:aws:logs:us-east-1:111111111111:log-group:/app/web-service:*"
            ),
            "/app/web-service"
        );
    }

    #[test]
    fn log_group_name_from_identifier_keeps_plain_name() {
        assert_eq!(
            log_group_name_from_identifier("/app/web-service"),
            "/app/web-service"
        );
    }
}
