use aws_config::SdkConfig;
use aws_sdk_sts::Client as StsClient;
use shared::dto::entitlements::AllowedAccount;

/// Sanitize a string for use as STS RoleSessionName.
/// Must be 2-64 chars matching [\w+=,.@-]+.
fn sanitize_session_name(prefix: &str, raw: &str) -> String {
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "+=,.@-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let combined = format!("{}-{}", prefix, sanitized);
    // Truncate to 64 chars on a char boundary, ensure at least 2
    let truncated: String = combined.chars().take(64).collect();
    if truncated.len() < 2 {
        format!("{:_<2}", truncated)
    } else {
        truncated
    }
}

/// Assume a role in a target account with STS session tags for audit context.
/// Returns an SdkConfig scoped to the assumed role.
/// Default to 3600 if no explicit duration is given.
pub async fn assume_role_for_account(
    base_config: &SdkConfig,
    account: &AllowedAccount,
    region: &str,
    session_context: &SessionContext,
) -> anyhow::Result<SdkConfig> {
    assume_role_with_duration(
        base_config,
        account,
        region,
        session_context,
        session_context.session_duration_seconds.unwrap_or(3600),
    )
    .await
}

/// Like `assume_role_for_account` but with an explicit duration.
pub async fn assume_role_with_duration(
    base_config: &SdkConfig,
    account: &AllowedAccount,
    region: &str,
    session_context: &SessionContext,
    duration_seconds: i32,
) -> anyhow::Result<SdkConfig> {
    let sts_client = StsClient::new(base_config);

    let mut assume = sts_client
        .assume_role()
        .role_arn(&account.role_arn)
        .role_session_name(sanitize_session_name("canopy", &session_context.user_id))
        .duration_seconds(duration_seconds);

    // Set ExternalId to satisfy the target role's trust policy
    if let Some(ref external_id) = session_context.sts_external_id {
        assume = assume.external_id(external_id);
    }

    // Attach STS session tags for audit trail
    assume = assume
        .tags(
            aws_sdk_sts::types::Tag::builder()
                .key("canopy-user")
                .value(&session_context.user_id)
                .build()
                .expect("valid tag"),
        )
        .tags(
            aws_sdk_sts::types::Tag::builder()
                .key("canopy-team")
                .value(&session_context.team)
                .build()
                .expect("valid tag"),
        )
        .tags(
            aws_sdk_sts::types::Tag::builder()
                .key("canopy-environment")
                .value(&session_context.environment)
                .build()
                .expect("valid tag"),
        );

    let creds = assume.send().await?;

    let credentials = creds.credentials().ok_or_else(|| {
        anyhow::anyhow!(
            "AssumeRole returned no credentials for {}",
            account.role_arn
        )
    })?;

    let exp = credentials.expiration();
    let expiration =
        Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(exp.secs() as u64));

    let aws_creds = aws_credential_types::Credentials::new(
        credentials.access_key_id(),
        credentials.secret_access_key(),
        Some(credentials.session_token().to_string()),
        expiration,
        "canopy-assume-role",
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .credentials_provider(aws_creds)
        .load()
        .await;

    // Verify the assumed role landed in the expected account
    verify_account_identity(&config, &account.account_id).await?;

    Ok(config)
}

/// Assume a role with an inline session policy that restricts what the
/// returned credentials can do. Used by the connect handler to scope
/// credentials to only SSM/EIC operations on the target instance.
///
/// `max_session_seconds`: entitlement-derived session cap. The actual STS
/// duration is clamped to `[900, max_session_seconds]` — STS requires at
/// least 900s for AssumeRole. If the entitlement cap is below 900s, the
/// request is rejected at the caller before reaching this function.
pub async fn assume_role_scoped(
    base_config: &SdkConfig,
    account: &AllowedAccount,
    region: &str,
    session_context: &SessionContext,
    inline_policy: &str,
    max_session_seconds: Option<u64>,
) -> anyhow::Result<SdkConfig> {
    let sts_client = StsClient::new(base_config);

    // STS minimum is 900s. Use entitlement cap if set, otherwise default 900s.
    let duration = match max_session_seconds {
        Some(cap) => (cap as i32).max(900),
        None => 900,
    };

    let mut assume = sts_client
        .assume_role()
        .role_arn(&account.role_arn)
        .role_session_name(sanitize_session_name(
            "ops-connect",
            &session_context.user_id,
        ))
        .duration_seconds(duration)
        .policy(inline_policy);

    // Set ExternalId to satisfy the target role's trust policy
    if let Some(ref external_id) = session_context.sts_external_id {
        assume = assume.external_id(external_id);
    }

    assume = assume
        .tags(
            aws_sdk_sts::types::Tag::builder()
                .key("canopy-user")
                .value(&session_context.user_id)
                .build()
                .expect("valid tag"),
        )
        .tags(
            aws_sdk_sts::types::Tag::builder()
                .key("canopy-action")
                .value("connect")
                .build()
                .expect("valid tag"),
        );

    let creds = assume.send().await?;

    let credentials = creds.credentials().ok_or_else(|| {
        anyhow::anyhow!(
            "AssumeRole returned no credentials for {}",
            account.role_arn
        )
    })?;

    let exp = credentials.expiration();
    let expiration =
        Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(exp.secs() as u64));

    let aws_creds = aws_credential_types::Credentials::new(
        credentials.access_key_id(),
        credentials.secret_access_key(),
        Some(credentials.session_token().to_string()),
        expiration,
        "canopy-connect-scoped",
    );

    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new(region.to_string()))
        .credentials_provider(aws_creds)
        .load()
        .await;

    Ok(config)
}

/// Build an IAM inline policy that limits credentials to SSM/EIC
/// operations on a specific instance.
///
/// `ssm_os_user_enforced`: when true, only allow the SSH document (not the shell).
/// `os_user`: when set, add IAM conditions to bind the OS user at the credential
/// level so the client cannot reuse scoped creds with a different user.
pub fn connect_session_policy(
    instance_id: &str,
    account_id: &str,
    region: &str,
    use_ssm: bool,
    use_eic: bool,
    ssm_os_user_enforced: bool,
    os_user: Option<&str>,
) -> String {
    let mut statements: Vec<serde_json::Value> = Vec::new();

    let instance_arn = format!("arn:aws:ec2:{region}:{account_id}:instance/{instance_id}");

    if use_ssm {
        let mut resources = vec![instance_arn.clone()];
        if ssm_os_user_enforced {
            resources.push(format!(
                "arn:aws:ssm:{region}::document/AWS-StartSSHSession"
            ));
        } else {
            resources.push(format!(
                "arn:aws:ssm:{region}::document/SSM-SessionManagerRunShell"
            ));
        }

        let mut stmt = serde_json::json!({
            "Effect": "Allow",
            "Action": ["ssm:StartSession"],
            "Resource": resources
        });

        // Bind OS user via SSM RunAs condition when specified
        if let Some(user) = os_user {
            stmt["Condition"] = serde_json::json!({
                "StringEquals": {
                    "ssm:SessionDocumentAccessCheck": "true",
                    "ssm:resourceTag/SSMSessionRunAs": user
                }
            });
        }

        statements.push(stmt);
    }

    if use_eic {
        statements.push(serde_json::json!({
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": region
                }
            }
        }));

        let eic_resources = vec![
            instance_arn.clone(),
            format!("arn:aws:ec2:{region}:{account_id}:instance-connect-endpoint/*"),
        ];

        let mut stmt = serde_json::json!({
            "Effect": "Allow",
            "Action": [
                "ec2-instance-connect:SendSSHPublicKey",
                "ec2-instance-connect:OpenTunnel"
            ],
            "Resource": eic_resources
        });

        // Bind OS user via EIC condition key when specified
        if let Some(user) = os_user {
            stmt["Condition"] = serde_json::json!({
                "StringEquals": {
                    "ec2:osuser": user
                }
            });
        }

        statements.push(stmt);
    }

    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": statements
    })
    .to_string()
}

/// Build an IAM inline policy that limits credentials to ECS Exec for one task.
///
/// The local TUI still shells out to `aws ecs execute-command`; these scoped
/// credentials prevent that spawned CLI from reusing the operator's broader
/// ambient permissions.
pub fn ecs_exec_session_policy(cluster_arn: &str, task_arn: &str, region: &str) -> String {
    serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["ecs:ExecuteCommand"],
                "Resource": task_arn,
                "Condition": {
                    "ArnEquals": {
                        "ecs:cluster": cluster_arn
                    }
                }
            },
            {
                "Effect": "Allow",
                "Action": ["ecs:DescribeTasks"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": region
                    }
                }
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel"
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:RequestedRegion": region
                    }
                }
            }
        ]
    })
    .to_string()
}

pub struct SessionContext {
    pub user_id: String,
    pub team: String,
    pub environment: String,
    /// Override from config.aws.session_duration_seconds. If None, defaults to 3600.
    pub session_duration_seconds: Option<i32>,
    /// STS ExternalId for AssumeRole calls. Must match the target role trust policy.
    pub sts_external_id: Option<String>,
}

/// Verify that the credentials behind an SdkConfig actually belong to the
/// expected AWS account. Calls `sts:GetCallerIdentity` and compares the
/// returned Account to `expected_account_id`.
async fn verify_account_identity(
    config: &SdkConfig,
    expected_account_id: &str,
) -> anyhow::Result<()> {
    let sts = StsClient::new(config);
    let identity = sts.get_caller_identity().send().await?;
    let actual = identity.account().unwrap_or("");
    if actual != expected_account_id {
        anyhow::bail!(
            "Credential identity mismatch: expected account {} but GetCallerIdentity returned {}",
            expected_account_id,
            actual
        );
    }
    Ok(())
}

/// Resolve an SdkConfig for the given account based on the `role_arn` value:
///
/// - `"direct"`          → use ambient credentials (default profile)
/// - `"profile:NAME"`    → use the named AWS profile from ~/.aws/credentials
/// - any other ARN       → AssumeRole into that role
///
/// For `direct`/`profile:` modes, a `GetCallerIdentity` check ensures the
/// resolved credentials actually belong to the configured `account_id`.
pub async fn resolve_aws_config(
    base_config: &SdkConfig,
    account: &AllowedAccount,
    region: &str,
    session_context: &SessionContext,
) -> anyhow::Result<SdkConfig> {
    if account.role_arn == "direct" {
        // Use default ambient credentials
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .load()
            .await;
        verify_account_identity(&config, &account.account_id).await?;
        Ok(config)
    } else if let Some(profile_name) = account.role_arn.strip_prefix("profile:") {
        // Use a specific AWS profile
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()))
            .profile_name(profile_name)
            .load()
            .await;
        verify_account_identity(&config, &account.account_id).await?;
        Ok(config)
    } else {
        // Standard AssumeRole
        assume_role_for_account(base_config, account, region, session_context).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── sanitize_session_name ───────────────────────────

    #[test]
    fn test_sanitize_normal_email() {
        let name = sanitize_session_name("canopy", "alice@example.com");
        assert_eq!(name, "canopy-alice@example.com");
    }

    #[test]
    fn test_sanitize_replaces_invalid_chars() {
        let name = sanitize_session_name("canopy", "user name/with spaces");
        assert_eq!(name, "canopy-user_name_with_spaces");
    }

    #[test]
    fn test_sanitize_truncates_to_64_chars() {
        let long = "a".repeat(100);
        let name = sanitize_session_name("canopy", &long);
        assert_eq!(name.len(), 64);
        assert!(name.starts_with("canopy-"));
    }

    #[test]
    fn test_sanitize_pads_short_names() {
        let name = sanitize_session_name("c", "");
        assert!(name.len() >= 2);
    }

    #[test]
    fn test_sanitize_preserves_valid_special_chars() {
        let name = sanitize_session_name("p", "user+=,.@-_test");
        assert_eq!(name, "p-user+=,.@-_test");
    }

    // ── connect_session_policy ──────────────────────────

    #[test]
    fn test_policy_ssm_only() {
        let policy = connect_session_policy(
            "i-abc123",
            "111111111111",
            "us-east-1",
            true,  // use_ssm
            false, // use_eic
            true,  // ssm_os_user_enforced
            Some("ec2-user"),
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);

        let actions = stmts[0]["Action"].as_array().unwrap();
        assert!(actions.iter().any(|a| a == "ssm:StartSession"));

        // Should have OS user condition
        assert!(
            stmts[0]["Condition"]["StringEquals"]["ssm:resourceTag/SSMSessionRunAs"]
                .as_str()
                .unwrap()
                == "ec2-user"
        );
    }

    #[test]
    fn test_policy_eic_only() {
        let policy = connect_session_policy(
            "i-xyz789",
            "222222222222",
            "eu-west-1",
            false, // use_ssm
            true,  // use_eic
            false,
            Some("ubuntu"),
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 2);

        assert_eq!(stmts[0]["Action"][0], "ec2:DescribeInstances");
        assert_eq!(stmts[0]["Resource"], "*");
        assert_eq!(
            stmts[0]["Condition"]["StringEquals"]["aws:RequestedRegion"],
            "eu-west-1"
        );

        let actions = stmts[1]["Action"].as_array().unwrap();
        assert!(actions
            .iter()
            .any(|a| a == "ec2-instance-connect:SendSSHPublicKey"));
        assert!(actions
            .iter()
            .any(|a| a == "ec2-instance-connect:OpenTunnel"));

        // EIC OS user condition
        assert_eq!(
            stmts[1]["Condition"]["StringEquals"]["ec2:osuser"],
            "ubuntu"
        );
    }

    #[test]
    fn test_policy_ssm_no_os_user_allows_shell() {
        let policy = connect_session_policy(
            "i-abc",
            "111111111111",
            "us-east-1",
            true,
            false,
            false, // not enforced → include shell document
            None,
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let resources = v["Statement"][0]["Resource"].as_array().unwrap();
        let has_shell = resources.iter().any(|r| {
            r.as_str()
                .map(|s| s.contains("SSM-SessionManagerRunShell"))
                .unwrap_or(false)
        });
        let has_ssh = resources.iter().any(|r| {
            r.as_str()
                .map(|s| s.contains("AWS-StartSSHSession"))
                .unwrap_or(false)
        });
        assert!(has_shell);
        assert!(!has_ssh);
        // No Condition key when os_user is None
        assert!(v["Statement"][0].get("Condition").is_none());
    }

    #[test]
    fn test_policy_both_ssm_and_eic() {
        let policy = connect_session_policy(
            "i-both",
            "333333333333",
            "ap-northeast-1",
            true,
            true,
            true,
            Some("admin"),
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 3);
    }

    #[test]
    fn test_policy_neither_ssm_nor_eic() {
        let policy =
            connect_session_policy("i-none", "444", "us-west-2", false, false, false, None);
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmts = v["Statement"].as_array().unwrap();
        assert!(stmts.is_empty());
    }

    #[test]
    fn ecs_exec_session_policy_contains_execute_command_on_task_arn() {
        let policy = ecs_exec_session_policy(
            "arn:aws:ecs:ap-northeast-1:111111111111:cluster/prod-app",
            "arn:aws:ecs:ap-northeast-1:111111111111:task/prod-app/abc123",
            "ap-northeast-1",
        );
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let stmts = v["Statement"].as_array().unwrap();

        assert_eq!(stmts[0]["Action"][0], "ecs:ExecuteCommand");
        assert_eq!(
            stmts[0]["Resource"],
            "arn:aws:ecs:ap-northeast-1:111111111111:task/prod-app/abc123"
        );
        assert_eq!(
            stmts[0]["Condition"]["ArnEquals"]["ecs:cluster"],
            "arn:aws:ecs:ap-northeast-1:111111111111:cluster/prod-app"
        );
    }

    #[test]
    fn ecs_exec_session_policy_contains_ssmmessages_actions() {
        let policy = ecs_exec_session_policy("cluster", "task", "ap-northeast-1");
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        let statement = &v["Statement"][2];
        let actions = statement["Action"].as_array().unwrap();
        assert!(actions
            .iter()
            .any(|a| a == "ssmmessages:CreateControlChannel"));
        assert!(actions.iter().any(|a| a == "ssmmessages:OpenDataChannel"));
        assert_eq!(
            statement["Condition"]["StringEquals"]["aws:RequestedRegion"],
            "ap-northeast-1"
        );
    }

    #[test]
    fn ecs_exec_session_policy_constrains_describe_tasks_by_region() {
        let policy = ecs_exec_session_policy("cluster", "task", "ap-northeast-1");
        let v: serde_json::Value = serde_json::from_str(&policy).unwrap();
        assert_eq!(v["Statement"][1]["Action"][0], "ecs:DescribeTasks");
        assert_eq!(v["Statement"][1]["Resource"], "*");
        assert_eq!(
            v["Statement"][1]["Condition"]["StringEquals"]["aws:RequestedRegion"],
            "ap-northeast-1"
        );
    }

    #[test]
    fn ecs_exec_session_policy_excludes_ec2_or_eic_statements() {
        let policy = ecs_exec_session_policy("cluster", "task", "us-east-1");
        assert!(!policy.contains("ec2-instance-connect"));
        assert!(!policy.contains("ec2:DescribeInstances"));
        assert!(!policy.contains("ssm:StartSession"));
    }
}
