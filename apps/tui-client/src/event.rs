use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Events that flow from the terminal and async tasks into the app
#[derive(Debug, Clone)]
pub enum Event {
    /// Terminal key press
    Key(KeyEvent),
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
    /// Load the next page of FilterLogEvents results, appending to the
    /// existing list. Triggered by `n` in the results table when the
    /// previous response carried a next_token.
    LoadMoreFilterResults,
    RunInsightsQuery,
    PollQueryResults(String),
    ExportResults(ExportFormat),

    // Live Tail
    StartLiveTail,
    StopLiveTail,
    PauseLiveTail,
    ResumeLiveTail,
    LiveTailEvent(shared::dto::cloudwatch::LiveTailEvent),

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
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            if tx.send(Event::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Resize(w, h)) => {
                            if tx.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        _ => {}
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
