use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_canopy-entitlements"))
}

fn smoke_cli() -> Command {
    if let Some(path) = std::env::var_os("CANOPY_ENTITLEMENTS_UI_SMOKE_BIN") {
        let path = PathBuf::from(path);
        let path = if path.is_absolute() {
            path
        } else {
            let cwd_path = std::env::current_dir().unwrap().join(&path);
            if cwd_path.exists() {
                cwd_path
            } else {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(path)
            }
        };
        Command::new(path)
    } else {
        Command::new(env!("CARGO_BIN_EXE_canopy-entitlements"))
    }
}

const CATALOG_FIXTURE: &str = r#"
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "prod-ec2"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[packages]]
id = "ec2-readonly"
features = ["ec2:view"]
scope = "prod-ec2"
role = "canopy"

[[bindings]]
group = "platform-engineering"
package = "ec2-readonly"

[[group_mappings]]
external_group = "canopy-platform-engineering"
canopy_group = "platform-engineering"
"#;

const DATABASE_CATALOG_FIXTURE: &str = r#"
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "rd-db"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "analytics"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["orders", "order_items"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 1000
max_examined_rows = 1000

[[packages]]
id = "rd-database-readonly"
features = ["mcp:use", "mcp:database"]
scope = "rd-db"
role = "canopy"

[[bindings]]
group = "RD"
package = "rd-database-readonly"

[[memberships]]
user_id = "rd@example.com"
group = "RD"
"#;

const SPLIT_DATABASE_FEATURE_SCOPE_FIXTURE: &str = r#"
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "feature-only"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes]]
id = "scope-only"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "analytics"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["orders"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 1000
max_examined_rows = 1000

[[packages]]
id = "database-feature-only"
features = ["mcp:use", "mcp:database"]
scope = "feature-only"
role = "canopy"

[[packages]]
id = "database-scope-only"
features = []
scope = "scope-only"
role = "canopy"

[[bindings]]
group = "RD"
package = "database-feature-only"

[[bindings]]
group = "RD"
package = "database-scope-only"

[[memberships]]
user_id = "rd@example.com"
group = "RD"
"#;

const AMBIGUOUS_DATABASE_CATALOG_FIXTURE: &str = r#"
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "orders-db"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "analytics"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["orders"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 1000
max_examined_rows = 1000

[[scopes]]
id = "payments-db"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "analytics"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["payments"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 1000
max_examined_rows = 1000

[[packages]]
id = "orders-db-read"
features = ["mcp:use", "mcp:database"]
scope = "orders-db"
role = "canopy"

[[packages]]
id = "payments-db-read"
features = ["mcp:use", "mcp:database"]
scope = "payments-db"
role = "canopy"

[[bindings]]
group = "RD"
package = "orders-db-read"

[[bindings]]
group = "RD"
package = "payments-db-read"

[[memberships]]
user_id = "rd@example.com"
group = "RD"
"#;

const DEFAULT_SCHEMA_DATABASE_CATALOG_FIXTURE: &str = r#"
[[accounts]]
id = "prod"
account_id = "123456789012"
name = "production"

[[roles]]
id = "canopy"
role_arn = "arn:aws:iam::{account_id}:role/CanopyRole"

[[scopes]]
id = "default-schema-db"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "analytics"
environment = "production"
allowed_tables = ["orders"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 1000
max_examined_rows = 1000

[[packages]]
id = "default-schema-db-read"
features = ["mcp:use", "mcp:database"]
scope = "default-schema-db"
role = "canopy"

[[bindings]]
group = "RD"
package = "default-schema-db-read"

[[memberships]]
user_id = "rd@example.com"
group = "RD"
"#;

#[test]
fn help_lists_catalog_commands() {
    let output = cli().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    for command in [
        "generate", "validate", "preview", "diff", "explain", "dry-run", "ui",
    ] {
        assert!(
            stdout.contains(command),
            "help output should list {command}; got:\n{stdout}"
        );
    }
}

#[test]
fn dry_run_json_error_is_machine_readable_and_nonzero() {
    let temp_dir = temp_test_dir("dry-run-error");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "not-supported",
            "--sub",
            "user-sub",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["status"], "error");
    assert_eq!(json["command"], "dry-run");

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn generate_writes_runtime_toml_and_json_status() {
    let temp_dir = temp_test_dir("generate");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    let output_path = temp_dir.join("entitlements.generated.toml");
    std::fs::write(&catalog_path, CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "generate",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "generated");
    assert_eq!(json["rules"], 1);

    let generated = std::fs::read_to_string(&output_path).unwrap();
    assert!(generated.contains("[[rules]]"));
    assert!(generated.contains("[[group_mappings]]"));

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn validate_uses_script_override_and_outputs_json() {
    let temp_dir = temp_test_dir("validate");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    let runtime_path = temp_dir.join("entitlements.generated.toml");
    let tfvars_path = temp_dir.join("terraform.tfvars");
    let script_path = temp_dir.join("validate-entitlements.sh");
    std::fs::write(&catalog_path, CATALOG_FIXTURE).unwrap();
    std::fs::write(&tfvars_path, "enable_direct_access = false\n").unwrap();

    let generate = cli()
        .args([
            "generate",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--output",
            runtime_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(generate.status.success());

    write_executable_script(&script_path, "#!/usr/bin/env bash\nexit 0\n");
    let output = cli()
        .env("CANOPY_VALIDATE_ENTITLEMENTS_SCRIPT", &script_path)
        .args([
            "validate",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--runtime-file",
            runtime_path.to_str().unwrap(),
            "--tfvars",
            tfvars_path.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "valid");
    assert_eq!(json["generated_rules"], 1);
    assert_eq!(json["runtime_rules"], 1);

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn preview_outputs_group_json() {
    let temp_dir = temp_test_dir("preview");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "preview",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--group",
            "platform-engineering",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["group"], "platform-engineering");
    assert_eq!(json["packages"][0]["package"], "ec2-readonly");

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_allows_matching_scope() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-allow");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, DATABASE_CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "mcp-database",
            "--sub",
            "rd@example.com",
            "--email",
            "rd@example.com",
            "--email-verified",
            "--scope",
            "orders_read",
            "--connection",
            "analytics",
            "--environment",
            "production",
            "--schema",
            "mart",
            "--table",
            "orders",
            "--action",
            "SELECT",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["operation"], "mcp-database");
    assert_eq!(json["allow"], true);
    assert_eq!(json["matched_rule"], "catalog-rd-rd-database-readonly");

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_denies_unmatched_scope_details() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-deny");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, DATABASE_CATALOG_FIXTURE).unwrap();

    for (flag, value, expected_reason) in [
        ("--schema", "finance", "schema 'finance' is not allowed"),
        ("--table", "payments", "table 'payments' is not allowed"),
        (
            "--action",
            "update",
            "action 'update' is not supported; only select is supported",
        ),
        (
            "--environment",
            "staging",
            "no resolved group has one rule matching the requested database scope",
        ),
        (
            "--connection",
            "warehouse",
            "no resolved group has one rule matching the requested database scope",
        ),
    ] {
        let mut args = vec![
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "mcp-database",
            "--sub",
            "rd@example.com",
            "--scope",
            "orders_read",
            "--connection",
            "analytics",
            "--environment",
            "production",
            "--schema",
            "mart",
            "--table",
            "orders",
            "--action",
            "select",
            "--format",
            "json",
        ];
        let index = args.iter().position(|arg| *arg == flag).unwrap() + 1;
        args[index] = value;

        let output = cli().args(args).output().unwrap();

        assert!(output.status.success());
        let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["allow"], false);
        let reason = json["reason"].as_str().unwrap();
        assert!(
            reason.contains(expected_reason),
            "expected reason to contain {expected_reason:?}; got {reason:?}"
        );
    }

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_rejects_missing_or_noncanonical_identifiers() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-invalid");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, DATABASE_CATALOG_FIXTURE).unwrap();

    let base_args = [
        "dry-run",
        "--catalog",
        catalog_path.to_str().unwrap(),
        "--operation",
        "mcp-database",
        "--sub",
        "rd@example.com",
        "--scope",
        "orders_read",
        "--connection",
        "analytics",
        "--environment",
        "production",
        "--schema",
        "mart",
        "--table",
        "orders",
        "--action",
        "select",
        "--format",
        "json",
    ];

    let missing_schema_args = base_args
        .iter()
        .copied()
        .filter(|arg| *arg != "--schema" && *arg != "mart")
        .collect::<Vec<_>>();
    let output = cli().args(missing_schema_args).output().unwrap();
    assert!(!output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(json["status"], "error");
    assert!(json["message"]
        .as_str()
        .unwrap()
        .contains("--schema is required"));

    for (flag, value) in [("--schema", "Mart"), ("--table", "Orders")] {
        let mut args = base_args.to_vec();
        let index = args.iter().position(|arg| *arg == flag).unwrap() + 1;
        args[index] = value;

        let output = cli().args(args).output().unwrap();

        assert!(!output.status.success());
        let json: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(json["status"], "error");
        assert!(json["message"]
            .as_str()
            .unwrap()
            .contains("must be a lowercase ASCII SQL identifier"));
    }

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_denies_cross_rule_feature_scope_merge() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-cross-rule");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, SPLIT_DATABASE_FEATURE_SCOPE_FIXTURE).unwrap();

    let output = cli()
        .args([
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "mcp-database",
            "--sub",
            "rd@example.com",
            "--scope",
            "orders_read",
            "--connection",
            "analytics",
            "--environment",
            "production",
            "--schema",
            "mart",
            "--table",
            "orders",
            "--action",
            "select",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["allow"], false);
    assert!(json["reason"]
        .as_str()
        .unwrap()
        .contains("no resolved group has one rule matching"));

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_denies_ambiguous_same_key_scope_policy() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-ambiguous");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, AMBIGUOUS_DATABASE_CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "mcp-database",
            "--sub",
            "rd@example.com",
            "--scope",
            "orders_read",
            "--connection",
            "analytics",
            "--environment",
            "production",
            "--schema",
            "mart",
            "--table",
            "orders",
            "--action",
            "select",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["allow"], false);
    assert!(json["reason"]
        .as_str()
        .unwrap()
        .contains("multiple matching database scopes disagree"));

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn dry_run_mcp_database_denies_default_schema_scopes_without_explicit_schemas() {
    let temp_dir = temp_test_dir("dry-run-mcp-database-default-schema");
    let catalog_path = temp_dir.join("entitlements.catalog.toml");
    std::fs::write(&catalog_path, DEFAULT_SCHEMA_DATABASE_CATALOG_FIXTURE).unwrap();

    let output = cli()
        .args([
            "dry-run",
            "--catalog",
            catalog_path.to_str().unwrap(),
            "--operation",
            "mcp-database",
            "--sub",
            "rd@example.com",
            "--scope",
            "orders_read",
            "--connection",
            "analytics",
            "--environment",
            "production",
            "--schema",
            "mart",
            "--table",
            "orders",
            "--action",
            "select",
            "--format",
            "json",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["allow"], false);
    assert!(json["reason"]
        .as_str()
        .unwrap()
        .contains("has no explicit allowed_schemas"));

    std::fs::remove_dir_all(temp_dir).unwrap();
}

#[test]
fn ui_binary_smoke_drives_rd_database_flow_and_apply_failure_state() {
    let temp_dir = temp_test_dir("ui-binary-smoke");
    let success_dir = temp_dir.join("success");
    let failure_dir = temp_dir.join("failure");
    std::fs::create_dir(&success_dir).unwrap();
    std::fs::create_dir(&failure_dir).unwrap();
    let os_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "operator".to_owned());

    write_ui_smoke_fixture(&success_dir, &os_user);
    generate_runtime_for_smoke(&success_dir);
    let mut success_server = UiSmokeServer::start(
        &success_dir,
        &[
            "--db-config",
            success_dir
                .join("database_connections.local.toml")
                .to_str()
                .unwrap(),
            "--deployment-mode",
            "config",
            "--deployment-config",
            success_dir.join("deployment.config.toml").to_str().unwrap(),
            "--auth-config",
            success_dir.join("auth.toml").to_str().unwrap(),
            "--identity-source",
            "os-allowlist",
        ],
    );
    let success_session = UiSmokeSession::exchange(&success_server.url);

    let html = success_session.get("/");
    assert_eq!(html.status, 200);
    assert!(html.body.contains("Entitlement Catalog"));
    let css = success_session.get("/app.css");
    assert_eq!(css.status, 200);
    assert!(css.body.contains("@media (max-width: 900px)"));
    assert!(css.body.contains(".review-change-table"));
    assert!(css.body.contains("overflow-wrap: anywhere"));
    let js = success_session.get("/app.js");
    assert_eq!(js.status, 200);
    assert!(js.body.contains("async function applyDraft()"));
    assert!(js.body.contains("/api/draft/scopes/database"));

    let state = success_session.get_json("/api/state");
    assert_eq!(state["draft"]["loaded"], true);
    assert_eq!(state["identity"]["auth_config_configured"], true);
    assert_eq!(state["database_connections"]["configured"], true);
    assert!(!serde_json::to_string(&state)
        .unwrap()
        .contains("orders-secret-ref"));

    let state = success_session.put_json(
        "/api/draft/scopes/database",
        serde_json::json!({
            "scope": "db-scope",
            "name": "customer_read",
            "connection": "orders",
            "environment": "production",
            "allowed_schemas": ["mart"],
            "allowed_tables": ["customers"],
            "allowed_actions": ["select"],
            "max_rows": 250,
            "statement_timeout_ms": 4000,
            "require_explain": true,
            "max_examined_rows": 15000,
            "allow_full_table_scan": false,
            "allow_views": false,
            "enabled": true
        }),
    );
    assert!(state["changes"]["semantic_diff"]["high_risk"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["kind"] == "database_scope_allowed_table"
            && grant["value"] == "customer_read|customers"));

    success_session.put_json(
        "/api/draft/packages",
        serde_json::json!({
            "id": "rd-customer-database",
            "scope": "db-scope",
            "role": "readonly",
            "max_session_seconds": 900,
            "enabled": true
        }),
    );
    let state = success_session.put_json(
        "/api/draft/packages/features",
        serde_json::json!({
            "package": "rd-customer-database",
            "feature": "mcp:database",
            "enabled": true
        }),
    );
    let package = state["draft"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|package| package["id"] == "rd-customer-database")
        .unwrap();
    assert!(package["features"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("mcp:use".to_owned())));
    assert!(package["features"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String("mcp:database".to_owned())));

    let state = success_session.put_json(
        "/api/draft/bindings",
        serde_json::json!({
            "group": "RD",
            "package": "rd-customer-database",
            "enabled": true
        }),
    );
    assert!(state["changes"]["semantic_diff"]["high_risk"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["group"] == "RD"
            && grant["package"] == "rd-customer-database"
            && grant["kind"] == "feature"
            && grant["value"] == "mcp:database"));

    let validation = success_session.post_empty_json("/api/validate", 200);
    assert_eq!(validation["valid"], true);
    assert_eq!(validation["generated"]["runtime_drift"], true);
    assert_eq!(validation["generated"]["temp_runtime_removed"], true);

    let preview =
        success_session.post_json("/api/preview", serde_json::json!({"group": "RD"}), 200);
    assert!(preview["packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|package| package["package"] == "rd-customer-database"
            && package["database_scopes"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("customer_read".to_owned()))));
    let explain = success_session.post_json(
        "/api/explain",
        serde_json::json!({
            "sub": "operator",
            "email": "operator@example.com",
            "email_verified": true,
            "external_groups": ["canopy-rd"]
        }),
        200,
    );
    assert!(explain["matched_packages"]
        .as_array()
        .unwrap()
        .contains(&serde_json::Value::String(
            "rd-customer-database".to_owned()
        )));
    let dry_run = success_session.post_json(
        "/api/dry-run",
        serde_json::json!({
            "operation": "mcp-database",
            "sub": "operator",
            "email": "operator@example.com",
            "email_verified": true,
            "external_groups": ["canopy-rd"],
            "scope": "customer_read",
            "connection": "orders",
            "environment": "production",
            "schema": "mart",
            "table": "customers",
            "action": "select"
        }),
        200,
    );
    assert_eq!(dry_run["allow"], true);
    assert_eq!(dry_run["matched_rule"], "catalog-rd-rd-customer-database");

    let apply = success_session.post_empty_json("/api/apply", 200);
    assert_eq!(apply["applied"], true);
    assert_eq!(apply["status"], "applied");
    assert_eq!(apply["gate"]["state"], "admin_ready");
    assert_eq!(apply["transaction"]["state"], "applied");
    assert!(apply["transaction"]["payload"]["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["artifact"] == "catalog"));
    assert!(!serde_json::to_string(&apply)
        .unwrap()
        .contains("orders-secret-ref"));
    let state = success_session.get_json("/api/state");
    assert_eq!(state["draft"]["dirty"], false);
    assert_eq!(state["database_connections"]["dirty"], false);
    assert!(
        std::fs::read_to_string(success_dir.join("entitlements.generated.toml"))
            .unwrap()
            .contains("catalog-rd-rd-customer-database")
    );
    success_server.stop();

    write_ui_smoke_fixture(&failure_dir, &os_user);
    generate_runtime_for_smoke(&failure_dir);
    let mut failure_server = UiSmokeServer::start(&failure_dir, &[]);
    let failure_session = UiSmokeSession::exchange(&failure_server.url);
    let apply = failure_session.post_empty_json("/api/apply", 409);
    assert_eq!(apply["applied"], false);
    assert_eq!(apply["status"], "blocked");
    assert_eq!(apply["gate"]["reason_code"], "validation_blocked");
    assert!(apply["validation"]["blocking_errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|issue| issue["code"] == "missing_db_config"));
    failure_server.stop();

    std::fs::remove_dir_all(temp_dir).unwrap();
}

fn temp_test_dir(name: &str) -> std::path::PathBuf {
    let temp_dir = std::env::temp_dir().join(format!(
        "canopy-entitlements-cli-{name}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&temp_dir).unwrap();
    temp_dir
}

fn write_executable_script(path: &std::path::Path, content: &str) {
    std::fs::write(path, content).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).unwrap();
    }
}

fn write_ui_smoke_fixture(dir: &Path, os_user: &str) {
    std::fs::write(
        dir.join("entitlements.catalog.toml"),
        format!(
            r#"
[[accounts]]
id = "prod"
account_id = "111"
name = "production"

[[roles]]
id = "readonly"
role_arn = "role/{{account_id}}/readonly"

[[scopes]]
id = "db-scope"
accounts = ["prod"]
regions = ["ap-northeast-1"]

[[scopes.database_scopes]]
name = "orders_read"
connection = "orders"
environment = "production"
allowed_schemas = ["mart"]
allowed_tables = ["orders"]
allowed_actions = ["select"]
max_rows = 100
statement_timeout_ms = 5000
require_explain = true
max_examined_rows = 10000
allow_full_table_scan = false
allow_views = false

[[packages]]
id = "analytics"
features = ["cloudwatch:search"]
scope = "db-scope"
role = "readonly"

[[packages]]
id = "mcp-database"
features = ["mcp:use", "mcp:database"]
scope = "db-scope"
role = "readonly"

[[bindings]]
group = "RD"
package = "analytics"

[[bindings]]
group = "admin"
package = "analytics"

[[group_mappings]]
external_group = "canopy-rd"
canopy_group = "RD"

[[memberships]]
user_id = "rd@example.com"
group = "RD"

[[memberships]]
user_id = "{os_user}"
group = "admin"
"#
        )
        .trim_start(),
    )
    .unwrap();
    std::fs::write(
        dir.join("database_connections.local.toml"),
        r#"
[database_connections.orders]
engine = "mysql"
host = "orders.example.internal"
port = 3306
database = "orders"
secret_arn = "orders-secret-ref"
readonly = true
require_tls = true
"#
        .trim_start(),
    )
    .unwrap();
    std::fs::copy(
        dir.join("database_connections.local.toml"),
        dir.join("deployment.config.toml"),
    )
    .unwrap();
    let auth_config = dir.join("auth.toml");
    std::fs::write(
        &auth_config,
        format!("admin_group = \"admin\"\n\n[os_allowlist]\nusers = [\"{os_user}\"]\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&auth_config, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn generate_runtime_for_smoke(dir: &Path) {
    let output = smoke_cli()
        .args([
            "generate",
            "--catalog",
            dir.join("entitlements.catalog.toml").to_str().unwrap(),
            "--output",
            dir.join("entitlements.generated.toml").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "generate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

struct UiSmokeServer {
    child: Child,
    url: String,
}

impl UiSmokeServer {
    fn start(dir: &Path, extra_args: &[&str]) -> Self {
        let mut child = smoke_cli()
            .args([
                "ui",
                "--catalog",
                dir.join("entitlements.catalog.toml").to_str().unwrap(),
                "--runtime",
                dir.join("entitlements.generated.toml").to_str().unwrap(),
                "--bind",
                "127.0.0.1:0",
            ])
            .args(extra_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let url = line
            .split_whitespace()
            .find(|part| part.starts_with("http://"))
            .unwrap_or_else(|| panic!("UI server did not print URL: {line}"))
            .to_owned();
        wait_for_http(&url);
        Self { child, url }
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for UiSmokeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

struct UiSmokeSession {
    addr: String,
    origin: String,
    cookie: String,
}

impl UiSmokeSession {
    fn exchange(url: &str) -> Self {
        let (addr, code) = parse_ui_url(url);
        let origin = format!("http://{addr}");
        let response = http_request(
            &addr,
            "POST",
            "/api/session/exchange",
            &[
                ("Origin", origin.as_str()),
                ("Content-Type", "application/json"),
            ],
            &format!(r#"{{"code":"{code}"}}"#),
        );
        assert_eq!(
            response.status, 200,
            "session exchange body={}",
            response.body
        );
        let cookie = response
            .header("set-cookie")
            .and_then(|value| value.split(';').next())
            .unwrap()
            .to_owned();
        Self {
            addr,
            origin,
            cookie,
        }
    }

    fn get(&self, path: &str) -> HttpResponse {
        http_request(&self.addr, "GET", path, &[("Cookie", &self.cookie)], "")
    }

    fn get_json(&self, path: &str) -> serde_json::Value {
        let response = self.get(path);
        assert_eq!(response.status, 200, "GET {path} body={}", response.body);
        serde_json::from_str(&response.body).unwrap()
    }

    fn put_json(&self, path: &str, body: serde_json::Value) -> serde_json::Value {
        let response = http_request(
            &self.addr,
            "PUT",
            path,
            &[
                ("Origin", &self.origin),
                ("Cookie", &self.cookie),
                ("Content-Type", "application/json"),
            ],
            &body.to_string(),
        );
        assert_eq!(response.status, 200, "PUT {path} body={}", response.body);
        serde_json::from_str(&response.body).unwrap()
    }

    fn post_json(&self, path: &str, body: serde_json::Value, expected: u16) -> serde_json::Value {
        let response = http_request(
            &self.addr,
            "POST",
            path,
            &[
                ("Origin", &self.origin),
                ("Cookie", &self.cookie),
                ("Content-Type", "application/json"),
            ],
            &body.to_string(),
        );
        assert_eq!(
            response.status, expected,
            "POST {path} body={}",
            response.body
        );
        serde_json::from_str(&response.body).unwrap()
    }

    fn post_empty_json(&self, path: &str, expected: u16) -> serde_json::Value {
        let response = http_request(
            &self.addr,
            "POST",
            path,
            &[("Origin", &self.origin), ("Cookie", &self.cookie)],
            "",
        );
        assert_eq!(
            response.status, expected,
            "POST {path} body={}",
            response.body
        );
        serde_json::from_str(&response.body).unwrap()
    }
}

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl HttpResponse {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn wait_for_http(url: &str) {
    let (addr, _) = parse_ui_url(url);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("UI server did not accept connections at {addr}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn parse_ui_url(url: &str) -> (String, String) {
    let rest = url.strip_prefix("http://").unwrap();
    let (addr, fragment) = rest.split_once("/#code=").unwrap();
    (addr.to_owned(), fragment.to_owned())
}

fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    )
    .unwrap();
    for (name, value) in headers {
        write!(stream, "{name}: {value}\r\n").unwrap();
    }
    write!(stream, "\r\n{body}").unwrap();
    stream.flush().unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let separator = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(raw[..separator].to_vec()).unwrap();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let headers = lines
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Vec<_>>();
    let body_bytes = raw[separator + 4..].to_vec();
    let body_bytes = if headers.iter().any(|(key, value)| {
        key.eq_ignore_ascii_case("transfer-encoding") && value.eq_ignore_ascii_case("chunked")
    }) {
        decode_chunked(&body_bytes)
    } else {
        body_bytes
    };
    HttpResponse {
        status,
        headers,
        body: String::from_utf8(body_bytes).unwrap(),
    }
}

fn decode_chunked(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut index = 0;
    loop {
        let line_end = input[index..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| index + offset)
            .unwrap();
        let size_line = std::str::from_utf8(&input[index..line_end]).unwrap();
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap();
        index = line_end + 2;
        if size == 0 {
            break;
        }
        output.extend_from_slice(&input[index..index + size]);
        index += size + 2;
    }
    output
}
