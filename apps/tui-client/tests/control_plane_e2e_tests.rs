//! End-to-end coverage for the TUI API client against a real control-plane
//! router running with mock AWS data.

use axum::{middleware as axum_mw, Router};
use control_plane::config::{AppConfig, AwsConfig, JwtConfig, OidcConfig};
use control_plane::middleware;
use control_plane::models::entitlements::EntitlementStore;
use control_plane::routes;
use control_plane::services::audit::AuditService;
use control_plane::services::oidc::OidcClient;
use control_plane::services::AppState;
use shared::dto::cloudwatch::{FilterLogEventsRequest, LogGroupsRequest};
use shared::dto::ec2::Ec2ListRequest;
use shared::dto::ecs::{EcsTasksRequest, DEV_MOCK_CLUSTER_NAME};
use std::sync::Arc;
use tokio::net::TcpListener;
use tui_client::api_client::ApiClient;

fn dev_config() -> AppConfig {
    AppConfig {
        bind_address: "127.0.0.1:8443".into(),
        oidc: OidcConfig {
            issuer_url: "https://example.com".into(),
            client_id: "test-client".into(),
            client_secret: None,
            scopes: vec!["openid".into()],
            authorization_endpoint: None,
            token_endpoint: None,
            device_authorization_endpoint: None,
            userinfo_endpoint: None,
            jwks_uri: None,
        },
        jwt: JwtConfig {
            secret: "test-secret-at-least-32-chars-long!!".into(),
            expiry_seconds: 3600,
        },
        aws: AwsConfig {
            default_region: Some("us-east-1".into()),
            session_duration_seconds: Some(3600),
            sts_external_id: Some("canopy".into()),
        },
        dev_mode: true,
        mock_aws_data: Some(true),
        entitlements_file: None,
        audit_log: None,
        cors_allowed_origins: vec![],
    }
}

fn build_state(config: AppConfig) -> Arc<AppState> {
    let entitlement_store = EntitlementStore::dev_defaults();
    let oidc_client = OidcClient::new(config.oidc.clone());
    let base_aws_config = aws_config::SdkConfig::builder()
        .region(aws_types::region::Region::new("us-east-1"))
        .build();

    Arc::new(AppState {
        config,
        entitlement_store: Arc::new(tokio::sync::RwLock::new(entitlement_store)),
        audit_service: AuditService::new(),
        oidc_client,
        base_aws_config,
        ready: std::sync::atomic::AtomicBool::new(true),
    })
}

fn build_control_plane_app(state: Arc<AppState>) -> Router {
    let protected = Router::new()
        .merge(routes::ec2::router())
        .merge(routes::ecs::router())
        .merge(routes::cloudwatch::router())
        .merge(routes::entitlements::router())
        .route_layer(axum_mw::from_fn_with_state(
            state.clone(),
            middleware::auth::require_auth,
        ));

    Router::new()
        .merge(routes::auth::router())
        .merge(routes::live_tail::router())
        .merge(protected)
        .with_state(state)
}

async fn start_control_plane_mock_aws() -> String {
    let state = build_state(dev_config());
    let app = build_control_plane_app(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn tui_api_client_exercises_control_plane_mock_aws_e2e() {
    let base_url = start_control_plane_mock_aws().await;
    let client = ApiClient::new(&base_url).unwrap();

    let login = client.dev_login("dev-admin").await.unwrap();
    assert_eq!(login.identity.user_id, "dev-admin");
    client.set_token(login.access_token);

    let entitlements = client.get_entitlements().await.unwrap();
    assert_eq!(entitlements.user_id, "dev-admin");
    assert!(entitlements.features.can_view_ec2);
    assert!(entitlements.features.can_view_ecs);
    assert!(entitlements.features.can_use_cloudwatch_search);

    let ec2 = client
        .list_ec2(&Ec2ListRequest {
            account_id: Some("111111111111".into()),
            region: Some("us-east-1".into()),
            name_filter: Some("web-prod".into()),
            state_filter: None,
            tag_filters: None,
            next_token: None,
            page_size: 10,
        })
        .await
        .unwrap();
    assert_eq!(ec2.failed_scopes, Vec::<String>::new());
    assert_eq!(ec2.instances.len(), 1);
    assert_eq!(ec2.instances[0].instance_id, "i-0123456789abcdef0");
    assert_eq!(ec2.instances[0].name.as_deref(), Some("web-prod-01"));

    let ecs = client
        .list_ecs_tasks(&EcsTasksRequest {
            account_id: Some("111111111111".into()),
            region: Some("us-east-1".into()),
            cluster: Some(DEV_MOCK_CLUSTER_NAME.into()),
            page_size: 10,
        })
        .await
        .unwrap();
    assert!(!ecs.truncated);
    assert!(!ecs.tasks.is_empty());
    assert!(ecs
        .tasks
        .iter()
        .all(|task| task.cluster_name == DEV_MOCK_CLUSTER_NAME));
    assert!(ecs.tasks.iter().any(|task| task
        .containers
        .iter()
        .any(|container| container.name == "app")));

    let log_groups = client
        .list_log_groups(&LogGroupsRequest {
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            prefix: Some("/app/".into()),
        })
        .await
        .unwrap();
    assert!(log_groups
        .log_groups
        .iter()
        .any(|group| group.name == "/app/web-service"));

    let events = client
        .filter_log_events(&FilterLogEventsRequest {
            account_id: "111111111111".into(),
            region: "us-east-1".into(),
            log_group_name: "/app/web-service".into(),
            filter_pattern: None,
            start_time: 0,
            end_time: 9_999_999_999_999_i64,
            next_token: None,
            limit: 10,
        })
        .await
        .unwrap();
    assert!(events.events.iter().any(|event| {
        event.log_stream_name.as_deref() == Some("web-prod-01/application")
            && event.message.contains("Request received")
    }));
}
