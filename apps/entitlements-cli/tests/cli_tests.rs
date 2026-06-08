use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_canopy-entitlements"))
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
        "generate", "validate", "preview", "diff", "explain", "dry-run",
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
