use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Events that flow from the terminal and async tasks into the app
#[derive(Debug, Clone)]
pub enum Event {
    /// Terminal key press
    Key(KeyEvent),
    /// Bracketed paste payload from the terminal
    Paste(String),
    /// Terminal resize
    Resize(u16, u16),
    /// Periodic tick for animations and polling
    Tick,
    /// Error from an async operation
    Error(String),
}

/// Actions dispatched by components back to the app
#[derive(Debug, Clone)]
pub enum Action {
    // Navigation
    NavigateTo(Screen),
    GoBack,
    Quit,

    // Auth
    LoginDevMode(String),
    LoginPkce,
    LoginDeviceCode,
    Logout,
    ChangePassword,
    TokenReceived(String),
    TokenExpired,

    // EC2
    RefreshEc2,
    SearchEc2(String),
    Ec2Loaded(Vec<shared::dto::ec2::Ec2Instance>, Vec<String>, u64), // instances, failed_scopes, generation
    Ec2FetchFailed(String, u64),                                     // error message, generation
    SelectInstance(usize),
    ConnectSsm {
        instance_id: String,
        instance_name: Option<String>,
        account_id: String,
        region: String,
        os_user: Option<String>,
    },
    ConnectEic {
        instance_id: String,
        instance_name: Option<String>,
        account_id: String,
        region: String,
        os_user: Option<String>,
    },
    ConnectSsh {
        instance_id: String,
        instance_name: Option<String>,
        account_id: String,
        region: String,
        os_user: Option<String>,
    },
    ConnectSessionStdoutReady,
    ConnectSessionFailure(String),
    ConnectSessionUserDisconnect,
    ConnectSessionExit,

    // CloudWatch
    RefreshLogGroups,
    LogGroupsLoaded(Vec<shared::dto::cloudwatch::LogGroup>, u64), // log_groups, generation
    LogGroupsFetchFailed(String, u64),                            // error, generation
    RunFilterSearch,
    FilterEventsLoaded {
        events: Vec<shared::dto::cloudwatch::LogEvent>,
        next_token: Option<String>,
        append: bool,
        generation: u64,
    },
    FilterEventsFetchFailed(String, u64),
    /// Load the next page of FilterLogEvents results, appending to the
    /// existing list. Triggered by `n` in the results table when the
    /// previous response carried a next_token.
    LoadMoreFilterResults,
    CancelCloudWatchRequest,
    RunInsightsQuery,
    InsightsQueryStarted {
        query_id: String,
        generation: u64,
    },
    InsightsQueryStartFailed {
        error: String,
        generation: u64,
    },
    PollQueryResults {
        query_id: String,
        generation: u64,
    },
    InsightsQueryResultsLoaded {
        response: shared::dto::cloudwatch::GetQueryResultsResponse,
        generation: u64,
    },
    InsightsQueryResultsFailed {
        error: String,
        generation: u64,
    },
    ExportResults(ExportFormat),

    // Live Tail
    StartLiveTail,
    /// User-triggered stop. Always applies to the current stream
    /// because it originates from a keypress on the active screen.
    StopLiveTail,
    PauseLiveTail,
    ResumeLiveTail,
    /// One event from the background stream. The `generation` field
    /// identifies which streaming run produced this event so a
    /// late-arriving event from a previously-stopped stream cannot
    /// land in the buffer of a newly-started one (Codex round 5).
    LiveTailEvent {
        event: shared::dto::cloudwatch::LiveTailEvent,
        generation: u64,
    },
    /// Background stream's natural-completion signal. Carries the
    /// generation so the handler can drop it when it belongs to a
    /// stale stream — preventing the race where a stream that just
    /// finished could mis-cancel a freshly-armed replacement.
    LiveTailStreamEnded(u64),

    // MCP local server
    EnableMcp,
    LaunchMcpAiClient,
    StopMcp,
    RestartMcp,
    TestMcp,
    McpStarted(crate::mcp::McpRuntimeStatus),
    McpStartFailed(String),
    McpStopped,
    McpHealthChecked(Result<(), String>),

    // Dashboard
    FetchPublicIp,
    SetPublicIp(String, u64), // ip, generation

    // Auto-update
    CheckForUpdate,
    UpdateCheckComplete(Option<crate::updater::UpdateResult>),
    DismissUpdateBanner,

    // Generic
    ShowError(String),
    DismissError,
    Noop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    Login,
    Dashboard,
    Ec2Inventory,
    CloudWatchSearch,
    LiveTail,
    Access,
    Settings,
    Mcp,
    ConnectSession,
}

#[derive(Debug, Clone)]
pub enum ExportFormat {
    Json,
    Text,
}

/// Async event reader that converts crossterm events into our Event type.
/// Can be paused during external command execution (e.g. SSM connect)
/// to avoid competing for stdin with the child process.
pub struct EventReader {
    pub tx: mpsc::UnboundedSender<Event>,
    pub rx: mpsc::UnboundedReceiver<Event>,
    pub paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Default for EventReader {
    fn default() -> Self {
        Self::new()
    }
}

impl EventReader {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            tx,
            rx,
            paused: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Spawn the event reading loop on a background task
    pub fn spawn(&self) -> tokio::task::JoinHandle<()> {
        let tx = self.tx.clone();
        let paused = self.paused.clone();
        tokio::spawn(async move {
            let tick_rate = Duration::from_millis(250);
            loop {
                // When paused, sleep instead of polling stdin
                if paused.load(std::sync::atomic::Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }

                if event::poll(tick_rate).unwrap_or(false) {
                    if let Ok(ce) = event::read() {
                        // Reuse the SAME function the unit tests
                        // exercise, so the production dispatch path
                        // and the test path can't drift apart.
                        if !dispatch_crossterm_event(&tx, ce) {
                            break;
                        }
                    }
                } else {
                    // Tick when no events
                    if tx.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        })
    }
}

/// Map a raw `crossterm::Event` to our `Event` enum. Returns None for
/// variants we deliberately ignore (Focus/Mouse — we don't drive
/// mouse input, and focus changes don't need their own action).
///
/// Extracted from `EventReader::spawn` so the conversion logic can be
/// unit-tested independently of the stdin-poll loop. Without this
/// extraction the spawn loop's match arms would only be exercised by
/// a real terminal, which is not possible under `cargo test`.
pub(crate) fn map_crossterm_to_event(ce: CrosstermEvent) -> Option<Event> {
    match ce {
        CrosstermEvent::Key(key) => Some(Event::Key(key)),
        CrosstermEvent::Paste(text) => Some(Event::Paste(text)),
        CrosstermEvent::Resize(w, h) => Some(Event::Resize(w, h)),
        // FocusGained / FocusLost / Mouse — deliberately ignored.
        _ => None,
    }
}

/// Forward one `crossterm::Event` into the action channel,
/// converting it via `map_crossterm_to_event`. Returns false if the
/// receiver has been dropped (so the spawn loop must break); returns
/// true otherwise — including when the event was ignored (mapper
/// returned None), because that is normal flow, not a teardown.
///
/// This is the EXACT function the spawn loop calls in production.
/// Tests against this function therefore lock both the conversion
/// AND the send-or-break dispatch semantics — Codex round 2
/// pointed out that testing `map_crossterm_to_event` in isolation
/// did not prove anything about the send step.
pub(crate) fn dispatch_crossterm_event(
    tx: &mpsc::UnboundedSender<Event>,
    ce: CrosstermEvent,
) -> bool {
    if let Some(ev) = map_crossterm_to_event(ce) {
        if tx.send(ev).is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    //! Unit tests for `EventReader`'s observable contract.
    //!
    //! The reader's `spawn()` loop talks directly to the real
    //! process stdin via `crossterm::event::poll`/`read`, so we
    //! cannot drive THAT loop from a unit test without a PTY.
    //!
    //! What we can — and do — test directly:
    //!
    //!   * `map_crossterm_to_event` — the conversion fn the spawn
    //!     loop calls. Tests synthesize `crossterm::Event` values
    //!     and assert the mapping (Paste/Resize/Key → matching
    //!     `Event` variants with all fields preserved; ignored
    //!     variants like Mouse return None).
    //!   * channel wiring (tx forwards to rx)
    //!   * pause flag initial state and atomic toggling
    //!   * pause flag is genuinely shared with spawned tasks
    //!     (so flipping it from app code affects the loop)
    //!   * the Default impl matches new()
    //!   * Event payload shapes round-trip via direct channel writes
    //!     so the consumer side (rx.try_recv) is also validated.
    //!
    //! The integration of `event::poll`/`event::read` against the
    //! real terminal is covered by manual smoke testing — there is no
    //! good way to fake it in cargo test without taking over stdin.

    use super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use std::sync::atomic::Ordering;

    /// Helper: try to receive an Event without blocking. Returns
    /// None if the channel is empty, the receiver has been closed,
    /// etc. Tests use this to assert "exactly N events landed".
    fn try_recv(rx: &mut mpsc::UnboundedReceiver<Event>) -> Option<Event> {
        rx.try_recv().ok()
    }

    #[test]
    fn new_returns_reader_with_unpaused_channel_pair() {
        // Normal path: a freshly constructed reader has a usable
        // tx/rx pair and is NOT paused — the spawn loop, if started,
        // would immediately begin polling.
        let reader = EventReader::new();

        assert!(
            !reader.paused.load(Ordering::Relaxed),
            "EventReader::new() must start unpaused so the reader loop polls stdin",
        );

        // Channel is alive: send → receive works synchronously.
        reader.tx.send(Event::Tick).expect("channel must be open");
        let mut rx = reader.rx;
        assert!(
            matches!(try_recv(&mut rx), Some(Event::Tick)),
            "tx must forward Event::Tick into rx",
        );
    }

    #[test]
    fn default_impl_matches_new_constructor() {
        // Boundary: Default must not silently diverge from new().
        // We can't compare the channels by identity, but we can
        // verify that both produce an unpaused reader with an
        // open channel.
        let a = EventReader::new();
        let b = EventReader::default();
        assert_eq!(
            a.paused.load(Ordering::Relaxed),
            b.paused.load(Ordering::Relaxed)
        );
        assert!(!a.paused.load(Ordering::Relaxed));
        assert!(!b.paused.load(Ordering::Relaxed));
    }

    #[test]
    fn paused_flag_toggles_atomically_and_is_observable() {
        // App code flips `paused` to true before shelling out to ssm/eic;
        // the reader loop observes via `Ordering::Relaxed` load. Verify
        // store → load round-trips and is visible from a separate clone.
        let reader = EventReader::new();
        let flag = reader.paused.clone();

        flag.store(true, Ordering::Relaxed);
        assert!(
            reader.paused.load(Ordering::Relaxed),
            "atomic store on a clone must be visible through the original Arc",
        );

        flag.store(false, Ordering::Relaxed);
        assert!(!reader.paused.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn pause_flag_is_shared_with_a_spawned_task_via_arc() {
        // Race-condition analog: app pauses the reader from one task
        // (the main render loop) while the actual stdin poller runs
        // in another. The Arc<AtomicBool> must be the same instance
        // so the store is visible across tasks.
        let reader = EventReader::new();
        let flag_for_task = reader.paused.clone();

        // Spawn a tiny task that waits for the flag to flip to true,
        // then signals completion via a oneshot.
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            loop {
                if flag_for_task.load(Ordering::Relaxed) {
                    let _ = done_tx.send(());
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        // Flip the flag from the test (i.e. "from the app").
        reader.paused.store(true, Ordering::Relaxed);

        // The spawned task must observe the flip within a reasonable bound.
        tokio::time::timeout(Duration::from_millis(500), done_rx)
            .await
            .expect("spawned task must see the pause flag within 500ms")
            .expect("oneshot sender must not be dropped");
    }

    #[test]
    fn key_event_round_trips_through_channel_with_all_fields_preserved() {
        // Normal path: the spawn loop sends Event::Key(key) verbatim;
        // verify that a representative KeyEvent (Ctrl+C, the most
        // critical key in the app for quit/cancel) survives the
        // channel intact.
        let reader = EventReader::new();
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

        reader.tx.send(Event::Key(key)).unwrap();
        let mut rx = reader.rx;

        match try_recv(&mut rx) {
            Some(Event::Key(received)) => {
                assert_eq!(received.code, KeyCode::Char('c'));
                assert_eq!(received.modifiers, KeyModifiers::CONTROL);
                // Press kind is the default for non-kitty terminals.
                assert!(matches!(
                    received.kind,
                    KeyEventKind::Press | KeyEventKind::Repeat
                ));
            }
            other => panic!("expected Event::Key, got {other:?}"),
        }
    }

    #[test]
    fn paste_event_carries_full_payload_string_with_no_truncation() {
        // Boundary: bracketed paste can be arbitrarily large
        // (e.g. multi-line YAML). The Event variant must carry the
        // entire String — verify a >1KB payload survives intact.
        let reader = EventReader::new();
        let big_paste = "abcdef0123".repeat(200); // 2000 bytes
        assert!(big_paste.len() >= 1024);

        reader.tx.send(Event::Paste(big_paste.clone())).unwrap();
        let mut rx = reader.rx;

        match try_recv(&mut rx) {
            Some(Event::Paste(s)) => {
                assert_eq!(s.len(), big_paste.len());
                assert_eq!(s, big_paste);
            }
            other => panic!("expected Event::Paste, got {other:?}"),
        }
    }

    #[test]
    fn paste_event_preserves_embedded_newlines_and_unicode() {
        // Boundary: paste payloads commonly include newlines and
        // non-ASCII characters; these must NOT be normalized,
        // stripped, or re-encoded by the Event variant.
        let reader = EventReader::new();
        let payload = "line1\nline2\r\nzh-tw 中文 emoji 🦀\nlast";

        reader.tx.send(Event::Paste(payload.into())).unwrap();
        let mut rx = reader.rx;

        match try_recv(&mut rx) {
            Some(Event::Paste(s)) => assert_eq!(s, payload),
            other => panic!("expected Event::Paste, got {other:?}"),
        }
    }

    #[test]
    fn resize_event_preserves_both_dimensions_independently() {
        // Boundary: resize tuples can flip width/height by mistake
        // in a refactor; verify both fields land in the right slot.
        let reader = EventReader::new();
        reader.tx.send(Event::Resize(120, 40)).unwrap();
        let mut rx = reader.rx;

        match try_recv(&mut rx) {
            Some(Event::Resize(w, h)) => {
                assert_eq!(w, 120, "width must be the first tuple element");
                assert_eq!(h, 40, "height must be the second tuple element");
            }
            other => panic!("expected Event::Resize, got {other:?}"),
        }
    }

    #[test]
    fn resize_event_accepts_zero_and_max_u16_without_panic() {
        // Boundary: extreme but legal resize values. A 0x0 resize
        // can happen briefly during window minimization on some
        // terminals; u16::MAX is the variant's upper bound.
        let reader = EventReader::new();
        reader.tx.send(Event::Resize(0, 0)).unwrap();
        reader.tx.send(Event::Resize(u16::MAX, u16::MAX)).unwrap();
        let mut rx = reader.rx;

        assert!(matches!(try_recv(&mut rx), Some(Event::Resize(0, 0))));
        assert!(matches!(
            try_recv(&mut rx),
            Some(Event::Resize(u16::MAX, u16::MAX))
        ));
    }

    #[test]
    fn error_event_carries_message_for_propagation_to_error_modal() {
        // Normal path: async tasks report errors via Event::Error,
        // which the app routes into the error modal. The message
        // must survive the channel verbatim.
        let reader = EventReader::new();
        let msg = "AWS SDK: ExpiredTokenException(...)";
        reader.tx.send(Event::Error(msg.into())).unwrap();
        let mut rx = reader.rx;

        match try_recv(&mut rx) {
            Some(Event::Error(s)) => assert_eq!(s, msg),
            other => panic!("expected Event::Error, got {other:?}"),
        }
    }

    #[test]
    fn dropping_receiver_makes_tx_send_return_err_without_panic() {
        // External-failure analog: if the app's main loop tears down
        // its rx (e.g. graceful shutdown), the reader's spawn loop
        // sees `tx.send(...).is_err()` and breaks. Verify the Err
        // path is observable WITHOUT panicking.
        let reader = EventReader::new();
        // Clone the tx first so we can still send AFTER moving rx out
        // and dropping it. The cloned tx still references the same
        // channel as the (now-unreachable) original tx.
        let tx_clone = reader.tx.clone();
        drop(reader.rx); // tear down the consumer
        let result = tx_clone.send(Event::Tick);
        assert!(
            result.is_err(),
            "tx.send must return Err once rx is dropped — the spawn loop relies on this to break",
        );
    }

    #[test]
    fn channel_is_unbounded_so_many_events_queue_without_blocking() {
        // Boundary: unbounded_channel means a fast async task (e.g.
        // a burst of LiveTail events) cannot starve a slow consumer.
        // Verify we can enqueue many events before draining.
        let reader = EventReader::new();
        for _ in 0..10_000 {
            reader.tx.send(Event::Tick).unwrap();
        }
        // All 10k must be drainable.
        let mut rx = reader.rx;
        let mut count = 0usize;
        while try_recv(&mut rx).is_some() {
            count += 1;
        }
        assert_eq!(
            count, 10_000,
            "unbounded channel must queue all 10k events without dropping any",
        );
    }

    // ── map_crossterm_to_event — the *actual* spawn-loop mapping ──
    //
    // These tests exercise the conversion function the spawn loop
    // calls on every poll, so a regression that swaps Resize
    // dimensions, drops Paste payloads, or accidentally maps Mouse
    // events into the channel will fail the unit tests rather than
    // sneak past behind "channel forwards fine".

    #[test]
    fn map_key_event_preserves_code_and_modifiers() {
        // Contract: Key(crossterm) → Event::Key with all fields intact.
        // Spot-check Ctrl+C since that's the most semantically-loaded
        // key in the TUI (quit/cancel).
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        let mapped = map_crossterm_to_event(CrosstermEvent::Key(key));
        match mapped {
            Some(Event::Key(k)) => {
                assert_eq!(k.code, KeyCode::Char('c'));
                assert_eq!(k.modifiers, KeyModifiers::CONTROL);
                assert!(matches!(k.kind, KeyEventKind::Press | KeyEventKind::Repeat));
            }
            other => panic!("expected Some(Event::Key), got {other:?}"),
        }
    }

    #[test]
    fn map_paste_event_preserves_full_payload_including_unicode_and_newlines() {
        // Contract: Paste(crossterm) → Event::Paste with the string
        // verbatim — no truncation, no normalization. A regression
        // that .chars().take(N) the payload would fail this.
        let payload = "line1\nline2\r\nzh-tw 中文 emoji 🦀\nlast";
        let mapped = map_crossterm_to_event(CrosstermEvent::Paste(payload.into()));
        match mapped {
            Some(Event::Paste(s)) => assert_eq!(s, payload),
            other => panic!("expected Some(Event::Paste), got {other:?}"),
        }
    }

    #[test]
    fn map_resize_event_does_not_swap_width_and_height() {
        // Regression guard: an easy refactor mistake is to flip
        // (w, h) to (h, w) when extracting. Use asymmetric values
        // so flipping would fail.
        let mapped = map_crossterm_to_event(CrosstermEvent::Resize(120, 40));
        match mapped {
            Some(Event::Resize(w, h)) => {
                assert_eq!(w, 120, "width must be the first tuple element");
                assert_eq!(h, 40, "height must be the second tuple element");
            }
            other => panic!("expected Some(Event::Resize), got {other:?}"),
        }
    }

    #[test]
    fn map_mouse_event_returns_none_because_tui_ignores_mouse_input() {
        // Contract: we don't enable mouse capture, but crossterm can
        // still surface mouse events on some terminals. They must NOT
        // be sent into the action channel; otherwise the app would
        // need to handle Event::Mouse — which we don't model.
        let mouse = CrosstermEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 10,
            row: 5,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            map_crossterm_to_event(mouse).is_none(),
            "Mouse events must be silently dropped by the mapper",
        );
    }

    #[test]
    fn map_focus_gained_and_focus_lost_return_none() {
        // Contract: focus changes have no in-app meaning for us.
        // Returning Some(_) would put a useless event onto the
        // action channel.
        assert!(map_crossterm_to_event(CrosstermEvent::FocusGained).is_none());
        assert!(map_crossterm_to_event(CrosstermEvent::FocusLost).is_none());
    }

    #[test]
    fn map_paste_with_empty_string_still_round_trips_as_empty_paste() {
        // Boundary: zero-length paste (e.g. paste-buffer empty) is a
        // valid crossterm event. It must NOT collapse to None —
        // downstream code distinguishes "no paste" vs "empty paste".
        let mapped = map_crossterm_to_event(CrosstermEvent::Paste(String::new()));
        match mapped {
            Some(Event::Paste(s)) => assert_eq!(s, ""),
            other => panic!("empty paste must map to Some(Event::Paste(\"\")), got {other:?}"),
        }
    }

    #[test]
    fn map_resize_zero_by_zero_and_max_dimensions_pass_through_unchanged() {
        // Boundary: extreme but legal sizes the spawn loop will see
        // on edge terminals (0x0 during minimize, u16::MAX on some
        // tiling WMs).
        assert!(matches!(
            map_crossterm_to_event(CrosstermEvent::Resize(0, 0)),
            Some(Event::Resize(0, 0)),
        ));
        assert!(matches!(
            map_crossterm_to_event(CrosstermEvent::Resize(u16::MAX, u16::MAX)),
            Some(Event::Resize(w, h)) if w == u16::MAX && h == u16::MAX,
        ));
    }

    // ── dispatch_crossterm_event — the *actual* spawn-loop dispatch ──
    //
    // These tests pin the production dispatch contract: take one
    // crossterm event, optionally map+send, signal "continue" vs
    // "break" via the bool return. If a refactor reverts the spawn
    // loop to inline match arms (decoupling from this helper), these
    // tests still document what the dispatch must do — and the spawn
    // loop calls THIS function, so a divergence is impossible without
    // an explicit code change here.

    #[test]
    fn dispatch_forwards_key_event_through_channel_and_returns_true() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::empty());

        let kept = dispatch_crossterm_event(&tx, CrosstermEvent::Key(key));

        assert!(kept, "dispatch must signal continue (true) on success");
        match try_recv(&mut rx) {
            Some(Event::Key(k)) => assert_eq!(k.code, KeyCode::Char('q')),
            other => panic!("expected Event::Key on the channel, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_drops_mouse_event_silently_and_returns_true_for_continue() {
        // Ignored variants (Mouse/Focus) must NOT signal "break" —
        // the spawn loop must keep polling.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mouse = CrosstermEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 1,
            row: 1,
            modifiers: KeyModifiers::empty(),
        });

        let kept = dispatch_crossterm_event(&tx, mouse);

        assert!(
            kept,
            "dispatch must continue (true) on an ignored event — \
             returning false here would terminate the spawn loop on the first mouse hover",
        );
        assert!(
            try_recv(&mut rx).is_none(),
            "ignored events must NOT land on the channel",
        );
    }

    #[test]
    fn dispatch_returns_false_when_receiver_has_been_dropped() {
        // External-failure contract: when rx is gone, the channel
        // send fails; dispatch must report that so the spawn loop
        // can break cleanly. This is the only return-false path —
        // it is what stops the loop on graceful app shutdown.
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx); // app tore down its consumer

        let key = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::empty());
        let kept = dispatch_crossterm_event(&tx, CrosstermEvent::Key(key));

        assert!(
            !kept,
            "dispatch must return false (break) when tx.send fails — \
             otherwise the spawn loop would spin forever after shutdown",
        );
    }

    #[test]
    fn dispatch_does_not_call_send_for_ignored_events_so_receiver_drop_is_irrelevant() {
        // Subtle: if mouse events were *sent* before the mapper
        // dropped them, a closed channel would falsely return false
        // for an ignored event. Verify that ignored events stay
        // silent even when rx is dropped.
        let (tx, rx) = mpsc::unbounded_channel();
        drop(rx); // closed channel

        let mouse = CrosstermEvent::Mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        });
        let kept = dispatch_crossterm_event(&tx, mouse);

        assert!(
            kept,
            "ignored event must return true (continue) regardless of channel \
             state — the mapper produced None so tx.send was never called",
        );
    }

    #[test]
    fn dispatch_forwards_paste_resize_payloads_intact() {
        // Smoke against the multi-variant dispatch — confirms each
        // mapped variant lands on the channel verbatim, not just key.
        let (tx, mut rx) = mpsc::unbounded_channel();

        assert!(dispatch_crossterm_event(
            &tx,
            CrosstermEvent::Paste("multi-line\npaste".into()),
        ));
        assert!(dispatch_crossterm_event(
            &tx,
            CrosstermEvent::Resize(100, 50),
        ));

        match try_recv(&mut rx) {
            Some(Event::Paste(s)) => assert_eq!(s, "multi-line\npaste"),
            other => panic!("expected Event::Paste first, got {other:?}"),
        }
        match try_recv(&mut rx) {
            Some(Event::Resize(w, h)) => {
                assert_eq!(w, 100);
                assert_eq!(h, 50);
            }
            other => panic!("expected Event::Resize second, got {other:?}"),
        }
    }
}
