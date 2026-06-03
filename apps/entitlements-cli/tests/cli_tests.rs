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
