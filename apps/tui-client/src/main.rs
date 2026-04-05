use anyhow::Result;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use tui_client::{app, config, tui};

#[tokio::main]
async fn main() -> Result<()> {
    // Log to file so we don't pollute the TUI
    let log_file = std::fs::File::create("tui-client.log").unwrap_or_else(|_| {
        std::fs::File::create("/tmp/tui-client.log").expect("Cannot create log file")
    });

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "tui_client=debug".into()))
        .with(tracing_subscriber::fmt::layer().with_writer(log_file))
        .init();

    let config = config::ClientConfig::load()?;
    let mut app = app::App::new(config).await?;
    let mut terminal = tui::init()?;

    let result = app.run(&mut terminal).await;

    tui::restore()?;
    result
}
