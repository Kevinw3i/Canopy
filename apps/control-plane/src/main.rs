// Reserved public APIs for future features (OIDC helpers, query poller, etc.)
#![allow(dead_code)]

use axum::{middleware as axum_mw, Router};
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use control_plane::config;
use control_plane::middleware;
use control_plane::routes;
use control_plane::services;

use config::AppConfig;
use services::AppState;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "control_plane=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let config = AppConfig::load()?;
    let bind_addr = config.bind_address.clone();

    // Safety guard: refuse dev_mode on non-loopback addresses
    if config.dev_mode
        && !bind_addr.starts_with("127.0.0.1:")
        && !bind_addr.starts_with("localhost:")
        && !bind_addr.starts_with("[::1]:")
    {
        if std::env::var("ALLOW_DEV_MODE_REMOTE").is_ok() {
            tracing::warn!(
                "dev_mode is enabled on non-loopback bind address {} — \
                 this is UNSAFE for production (ALLOW_DEV_MODE_REMOTE override active)",
                bind_addr
            );
        } else {
            anyhow::bail!(
                "dev_mode is enabled but bind_address '{}' is not loopback. \
                 This would expose unauthenticated dev endpoints to the network. \
                 Either set bind_address to 127.0.0.1:PORT, disable dev_mode, \
                 or set ALLOW_DEV_MODE_REMOTE=1 to override.",
                bind_addr
            );
        }
    }

    // Build CORS layer from config
    let cors = if config.dev_mode && config.cors_allowed_origins.is_empty() {
        if config.mock_aws_data == Some(false) {
            // Real AWS with dev auth: restrict CORS to localhost only
            tracing::warn!("CORS: dev_mode with real AWS — restricting to localhost origins only");
            let localhost_origins: Vec<_> = ["http://localhost:8443", "http://127.0.0.1:8443"]
                .iter()
                .filter_map(|o| o.parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(localhost_origins))
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
        } else {
            tracing::warn!("CORS: allowing all origins (dev mode, mock data)");
            CorsLayer::permissive()
        }
    } else if config.cors_allowed_origins.is_empty() {
        tracing::warn!("No cors_allowed_origins configured — blocking cross-origin requests");
        CorsLayer::new()
    } else {
        let origins: Vec<_> = config
            .cors_allowed_origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        tracing::info!(origins = ?config.cors_allowed_origins, "CORS: allowing listed origins");
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(tower_http::cors::Any)
            .allow_headers(tower_http::cors::Any)
    };

    let state = Arc::new(AppState::new(config).await?);

    // Run startup preflight in background — health endpoint returns 503
    // until OIDC discovery and STS identity checks pass.
    {
        let preflight_state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = preflight_state.run_preflight().await {
                tracing::error!("Startup preflight failed: {e}");
                // Service stays not-ready; ALB will deregister it.
            }
        });
    }

    // Protected routes require auth middleware
    let protected = Router::new()
        .merge(routes::ec2::router())
        .merge(routes::cloudwatch::router())
        .merge(routes::entitlements::router())
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth::require_auth,
        ));

    // Live tail uses WebSocket with in-message auth (no middleware needed)
    // Auth routes are public
    let app = Router::new()
        .merge(routes::auth::router())
        .merge(routes::live_tail::router())
        .merge(protected)
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state);

    tracing::info!("Control-plane listening on {bind_addr}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Control-plane shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => tracing::info!("Received SIGINT, shutting down"),
            _ = sigterm.recv() => tracing::info!("Received SIGTERM, shutting down"),
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.ok();
        tracing::info!("Received SIGINT, shutting down");
    }
}
