use crate::event::Action;
use shared::dto::cloudwatch::LiveTailEvent;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Marker that exists for one reason: to make it impossible for a
/// reader of this module — or a test — to miss the fact that the
/// current `stream_simulated_live_tail*` functions do NOT speak to
/// the real `/api/cloudwatch/live-tail` endpoint.
///
/// When the real `tokio-tungstenite` client lands, the new function
/// will be added alongside (or the simulated one renamed/removed)
/// and this constant will flip to false. Tests assert on this
/// constant explicitly so the change point is unmissable.
pub const LIVE_TAIL_IS_SIMULATED_STUB: bool = true;

/// Number of simulated events the dev-mode stub emits before
/// terminating with `Action::StopLiveTail`. Hoisted to a constant
/// so unit tests can assert the exact emission count without
/// hard-coding the literal.
pub(crate) const STUB_EVENT_COUNT: usize = 20;

/// Default tick interval between simulated events. Production code
/// uses this; tests inject a much smaller value via
/// `stream_simulated_live_tail_with_interval` so they finish in
/// milliseconds instead of 40 seconds.
const DEFAULT_TICK_INTERVAL: Duration = Duration::from_secs(2);

/// **SIMULATED STUB** — emits 20 fake `LiveTailEvent`s into the
/// action channel at `DEFAULT_TICK_INTERVAL` apart, then sends
/// `Action::LiveTailStreamEnded(generation)`. **Does NOT contact
/// the control-plane**: `_base_url` and `_token` are intentionally
/// ignored. The production implementation will be added when the
/// WebSocket client library lands (see `LIVE_TAIL_IS_SIMULATED_STUB`).
///
/// `generation` tags every emitted action so the app can drop late-
/// arriving events/end-signals from a previously-stopped stream
/// (Codex round 5).
///
/// Caller can cancel via the `CancellationToken` to stop early.
pub async fn stream_simulated_live_tail(
    base_url: &str,
    token: Option<&str>,
    tx: mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
    generation: u64,
) -> anyhow::Result<()> {
    stream_simulated_live_tail_with_interval(
        base_url,
        token,
        tx,
        cancel,
        generation,
        DEFAULT_TICK_INTERVAL,
    )
    .await
}

/// Internal variant that exposes the tick interval. Tests use this
/// directly to drive the loop in milliseconds rather than seconds.
pub(crate) async fn stream_simulated_live_tail_with_interval(
    _base_url: &str,
    _token: Option<&str>,
    tx: mpsc::UnboundedSender<Action>,
    cancel: CancellationToken,
    generation: u64,
    tick_interval: Duration,
) -> anyhow::Result<()> {
    tracing::info!("Live tail: streaming simulated events (WebSocket client not yet wired)");

    for i in 1..=STUB_EVENT_COUNT {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::info!("Live tail stream cancelled");
                return Ok(());
            }
            _ = tokio::time::sleep(tick_interval) => {}
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

        if tx
            .send(Action::LiveTailEvent { event, generation })
            .is_err()
        {
            break; // receiver dropped
        }
    }

    // Natural completion → tagged stream-ended action. Tagged so a
    // re-armed newer stream (different generation) doesn't get
    // mis-cancelled by this stale signal.
    let _ = tx.send(Action::LiveTailStreamEnded(generation));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: drain all currently-queued actions from the receiver
    /// into a Vec, returning when the channel is empty (not closed).
    fn drain(rx: &mut mpsc::UnboundedReceiver<Action>) -> Vec<Action> {
        let mut out = Vec::new();
        while let Ok(action) = rx.try_recv() {
            out.push(action);
        }
        out
    }

    /// Count how many of the actions in `actions` are `LiveTailEvent`s.
    fn count_events(actions: &[Action]) -> usize {
        actions
            .iter()
            .filter(|a| matches!(a, Action::LiveTailEvent { .. }))
            .count()
    }

    /// Returns true iff the last action in the slice is `StopLiveTail`.
    fn ends_with_stop(actions: &[Action]) -> bool {
        matches!(actions.last(), Some(Action::LiveTailStreamEnded(_)))
    }

    #[test]
    fn module_advertises_itself_as_simulated_stub_until_real_ws_client_lands() {
        // CONTRACT: the rest of the tests in this module exercise the
        // SIMULATED stub, not a real WebSocket client. If this flag
        // flips to false without the rest of this module being
        // rewritten/renamed, every other test below is at risk of
        // silently lying about what it tested.
        //
        // Tripping this assertion is the loud, unmissable signal
        // that the simulated → real-ws migration has started and
        // these tests need a redesign (probably: spawn the real
        // control-plane WS server + assert end-to-end via
        // tokio-tungstenite, like the route_tests::live_tail_*
        // integration tests already do).
        //
        // clippy::assertions_on_constants is allowed because the
        // entire point IS that this constant changes — we want a
        // runtime test to flag the moment it does.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(
                LIVE_TAIL_IS_SIMULATED_STUB,
                "If you flipped LIVE_TAIL_IS_SIMULATED_STUB to false, rewrite \
                 this module's tests against the real WS client before merging.",
            );
        }
    }

    #[tokio::test]
    async fn stub_ignores_base_url_and_token_arguments_by_design() {
        // CONTRACT: while we're in the simulated-stub phase, the
        // url/token args are decorative. Passing intentionally-bogus
        // values must NOT change behavior — proves the stub is
        // genuinely not contacting any server.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let result = stream_simulated_live_tail_with_interval(
            "https://this-host-does-not-exist.invalid.test:1/api/cloudwatch/live-tail",
            Some("not-a-real-jwt"),
            tx,
            cancel,
            // test generation; production code passes the live_tail_generation field
            0,
            Duration::from_millis(1),
        )
        .await;
        // No network, no DNS errors — stub completes happily because
        // it ignores the args.
        assert!(
            result.is_ok(),
            "stub must complete without surfacing any network error from the bogus URL",
        );
        let actions = drain(&mut rx);
        assert_eq!(
            count_events(&actions),
            STUB_EVENT_COUNT,
            "stub must emit its usual 20 events regardless of URL/token, got {actions:?}",
        );
    }

    #[tokio::test]
    async fn stub_emits_exactly_twenty_events_then_stop_signal() {
        // Normal path: with a tiny interval the stub should run to
        // completion, emit STUB_EVENT_COUNT events, and finish with
        // a single StopLiveTail action so the UI knows to clear its
        // "streaming" indicator.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        let result = stream_simulated_live_tail_with_interval(
            "https://ignored",
            None,
            tx,
            cancel,
            // test generation; production code passes the live_tail_generation field
            0,
            Duration::from_millis(1),
        )
        .await;
        assert!(result.is_ok(), "stub should never return an error");

        let actions = drain(&mut rx);
        assert_eq!(
            count_events(&actions),
            STUB_EVENT_COUNT,
            "stub must emit exactly {STUB_EVENT_COUNT} LiveTailEvent actions, got {actions:?}",
        );
        assert!(
            ends_with_stop(&actions),
            "stub must terminate with Action::StopLiveTail so the UI clears its streaming indicator, got tail = {:?}",
            actions.last(),
        );
        // Total = 20 events + 1 stop = 21 actions.
        assert_eq!(actions.len(), STUB_EVENT_COUNT + 1);
    }

    #[tokio::test]
    async fn cancellation_before_any_tick_emits_zero_events_and_no_stop_signal() {
        // Boundary: when the caller cancels before the first sleep
        // elapses, the loop must exit through the `cancel.cancelled()`
        // branch (NOT the timer branch), and that early-return path
        // intentionally does NOT send StopLiveTail — the caller who
        // cancelled already knows it stopped.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        cancel.cancel(); // Cancel BEFORE we await the stream.

        let result = stream_simulated_live_tail_with_interval(
            "https://ignored",
            None,
            tx,
            cancel,
            0, // test generation
            // Big interval so the timer branch is "never" — only the
            // cancel branch can fire, deterministically.
            Duration::from_secs(60),
        )
        .await;
        assert!(result.is_ok());

        let actions = drain(&mut rx);
        assert_eq!(
            count_events(&actions),
            0,
            "no LiveTailEvent should be emitted after pre-cancellation, got {actions:?}",
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::LiveTailStreamEnded(_))),
            "cancellation path returns early WITHOUT StopLiveTail (the caller already knows it cancelled), got {actions:?}",
        );
    }

    #[tokio::test]
    async fn cancellation_mid_stream_stops_loop_promptly_with_partial_event_count() {
        // Race-ish: cancel after a few events. The next loop iteration
        // should see `cancel.cancelled()` win the select and exit
        // before sending more events.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        // Use a 5ms tick so a few iterations happen quickly.
        let handle = tokio::spawn(async move {
            stream_simulated_live_tail_with_interval(
                "https://ignored",
                None,
                tx,
                cancel_clone,
                0, // test generation
                Duration::from_millis(5),
            )
            .await
        });

        // Let ~3 ticks pass, then cancel.
        tokio::time::sleep(Duration::from_millis(18)).await;
        cancel.cancel();

        let result = handle.await.expect("task should complete");
        assert!(result.is_ok());

        let actions = drain(&mut rx);
        let event_count = count_events(&actions);
        // We allowed ~3 ticks, and timing is not exact in CI, but we
        // can bound it: must be strictly less than the full 20 (the
        // loop was cancelled) and must be at least 0 (cancel could
        // win on the very first select if scheduler is slow).
        assert!(
            event_count < STUB_EVENT_COUNT,
            "cancellation must stop the loop before all {STUB_EVENT_COUNT} events are emitted; got {event_count}",
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::LiveTailStreamEnded(_))),
            "mid-stream cancellation also returns early WITHOUT StopLiveTail; got {actions:?}",
        );
    }

    #[tokio::test]
    async fn receiver_drop_breaks_loop_without_panic_or_lost_stop_signal() {
        // External-failure analog: if the UI side drops the receiver
        // (e.g. App was torn down while live-tail was running), the
        // loop must notice `tx.send` returned Err and break cleanly.
        // The trailing `let _ = tx.send(Action::StopLiveTail)` will
        // also fail silently — no panic.
        let (tx, rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        // Drop the receiver immediately. First `tx.send` inside the
        // loop will fail; loop must break without panicking.
        drop(rx);

        let result = stream_simulated_live_tail_with_interval(
            "https://ignored",
            None,
            tx,
            cancel,
            // test generation; production code passes the live_tail_generation field
            0,
            Duration::from_millis(1),
        )
        .await;
        assert!(
            result.is_ok(),
            "receiver drop must NOT propagate as an error — the stub silently exits",
        );
    }

    #[tokio::test]
    async fn emitted_events_carry_canonical_log_group_and_stream_identifiers() {
        // Contract: simulated events use the documented placeholder
        // group/stream names so downstream UI code (which keys on
        // these) sees stable, predictable values during dev.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        stream_simulated_live_tail_with_interval(
            "https://ignored",
            None,
            tx,
            cancel,
            // test generation; production code passes the live_tail_generation field
            0,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        let actions = drain(&mut rx);
        let events: Vec<&LiveTailEvent> = actions
            .iter()
            .filter_map(|a| {
                if let Action::LiveTailEvent { event: e, .. } = a {
                    Some(e)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(events.len(), STUB_EVENT_COUNT);

        for event in &events {
            assert_eq!(event.log_group_name, "/app/web-service");
            assert_eq!(event.log_stream_name, "web-prod-01/application");
            // Message must be valid JSON-shaped with a "level" field.
            assert!(
                event.message.contains(r#""level":"#),
                "simulated message should be JSON-shaped with a level field, got: {}",
                event.message
            );
            assert!(event.timestamp > 0, "timestamp should be a valid epoch ms");
        }
    }

    #[tokio::test]
    async fn level_field_cycles_through_info_warn_error_predictably() {
        // Contract: the i % 4 rotation produces the documented level
        // sequence. This protects against a future refactor changing
        // the modulo and silently breaking dev-mode log-color demos.
        // The match arms are: 0 → ERROR, 1 → WARN, _ → INFO. So:
        // i=1 → i%4==1 → WARN
        // i=2 → i%4==2 → INFO
        // i=3 → i%4==3 → INFO
        // i=4 → i%4==0 → ERROR
        // i=5 → i%4==1 → WARN
        let (tx, mut rx) = mpsc::unbounded_channel();
        let cancel = CancellationToken::new();

        stream_simulated_live_tail_with_interval(
            "https://ignored",
            None,
            tx,
            cancel,
            // test generation; production code passes the live_tail_generation field
            0,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        let actions = drain(&mut rx);
        let levels: Vec<&str> = actions
            .iter()
            .filter_map(|a| {
                if let Action::LiveTailEvent { event: e, .. } = a {
                    // Pull the "level":"X" value out of the message.
                    let s = &e.message;
                    let start = s.find(r#""level":""#)? + r#""level":""#.len();
                    let end = s[start..].find('"')? + start;
                    Some(&s[start..end])
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(levels.len(), STUB_EVENT_COUNT);

        // Spot-check the rotation at known indices.
        assert_eq!(levels[0], "WARN", "i=1 → i%4==1 → WARN");
        assert_eq!(levels[1], "INFO", "i=2 → i%4==2 → INFO (falls to _)");
        assert_eq!(levels[2], "INFO", "i=3 → i%4==3 → INFO (falls to _)");
        assert_eq!(levels[3], "ERROR", "i=4 → i%4==0 → ERROR");
        assert_eq!(levels[4], "WARN", "i=5 → i%4==1 → WARN");
    }
}
