use shared::dto::ec2::{Ec2Instance, InstanceState};
use std::collections::HashMap;

/// Convert an AWS SDK `Instance` into our `Ec2Instance` DTO.
///
/// `account_id` and `region` are passed in because they are not part of the
/// SDK's `Instance` struct — they come from the caller's context (which
/// account/region the DescribeInstances call was made against).
pub fn convert_sdk_instance(
    inst: &aws_sdk_ec2::types::Instance,
    account_id: &str,
    region: &str,
) -> Ec2Instance {
    let tags: HashMap<String, String> = inst
        .tags()
        .iter()
        .filter_map(|t| {
            let key = t.key()?.to_string();
            let value = t.value()?.to_string();
            Some((key, value))
        })
        .collect();

    let name = tags.get("Name").cloned();
    let environment = tags.get("Environment").cloned();

    let state = inst
        .state()
        .and_then(|s| s.name())
        .map(|s| match s {
            aws_sdk_ec2::types::InstanceStateName::Pending => InstanceState::Pending,
            aws_sdk_ec2::types::InstanceStateName::Running => InstanceState::Running,
            aws_sdk_ec2::types::InstanceStateName::ShuttingDown => InstanceState::ShuttingDown,
            aws_sdk_ec2::types::InstanceStateName::Terminated => InstanceState::Terminated,
            aws_sdk_ec2::types::InstanceStateName::Stopping => InstanceState::Stopping,
            aws_sdk_ec2::types::InstanceStateName::Stopped => InstanceState::Stopped,
            _ => InstanceState::Pending, // unknown states default to pending
        })
        .unwrap_or(InstanceState::Pending);

    let private_ip = inst.private_ip_address().map(|s| s.to_string());
    let public_ip = inst.public_ip_address().map(|s| s.to_string());

    let platform = inst.platform_details().map(|s| s.to_string());

    let instance_type = inst
        .instance_type()
        .map(|t| t.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let launch_time = inst.launch_time().map(|t| {
        // Format as ISO-8601 string
        let secs = t.secs();
        let nanos = t.subsec_nanos();
        chrono::DateTime::from_timestamp(secs, nanos)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default()
    });

    let vpc_id = inst.vpc_id().map(|s| s.to_string());
    let subnet_id = inst.subnet_id().map(|s| s.to_string());

    let security_groups: Vec<String> = inst
        .security_groups()
        .iter()
        .filter_map(|sg| sg.group_id().map(|s| s.to_string()))
        .collect();

    let iam_role = inst
        .iam_instance_profile()
        .and_then(|p| p.arn())
        .map(|arn| {
            // Extract the role name from the instance profile ARN if possible.
            // ARN format: arn:aws:iam::123456789012:instance-profile/RoleName
            arn.rsplit('/').next().unwrap_or(arn).to_string()
        });

    // Fallback heuristic for callers that only have EC2 DescribeInstances data.
    // The real AWS list route overwrites this with SSM DescribeInstanceInformation.
    let ssm_managed = iam_role.is_some() && state == InstanceState::Running;

    // EC2 Instance Connect is available on Amazon Linux 2/2023 and Ubuntu 20.04+
    // running in a VPC. We approximate by checking the platform and vpc_id.
    let instance_connect_capable = vpc_id.is_some()
        && platform
            .as_deref()
            .map(|p| p.contains("Linux"))
            .unwrap_or(false);

    Ec2Instance {
        instance_id: inst.instance_id().unwrap_or("unknown").to_string(),
        account_id: account_id.to_string(),
        region: region.to_string(),
        name,
        private_ip,
        public_ip,
        state,
        platform,
        instance_type,
        ssm_managed,
        instance_connect_capable,
        environment,
        tags,
        launch_time,
        vpc_id,
        subnet_id,
        security_groups,
        iam_role,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_ec2::types::{
        GroupIdentifier, IamInstanceProfile, Instance, InstanceState as SdkInstanceState,
        InstanceStateName, InstanceType, Tag,
    };

    /// Helper: build a fully-populated SDK Instance.
    fn full_instance() -> Instance {
        Instance::builder()
            .instance_id("i-0abc123def456")
            .instance_type(InstanceType::T3Micro)
            .private_ip_address("10.0.1.50")
            .public_ip_address("54.1.2.3")
            .platform_details("Linux/UNIX")
            .vpc_id("vpc-aaa")
            .subnet_id("subnet-bbb")
            .state(
                SdkInstanceState::builder()
                    .name(InstanceStateName::Running)
                    .build(),
            )
            .tags(Tag::builder().key("Name").value("web-prod-1").build())
            .tags(
                Tag::builder()
                    .key("Environment")
                    .value("production")
                    .build(),
            )
            .tags(Tag::builder().key("Team").value("platform").build())
            .security_groups(
                GroupIdentifier::builder()
                    .group_id("sg-111")
                    .group_name("web-sg")
                    .build(),
            )
            .security_groups(
                GroupIdentifier::builder()
                    .group_id("sg-222")
                    .group_name("default")
                    .build(),
            )
            .iam_instance_profile(
                IamInstanceProfile::builder()
                    .arn("arn:aws:iam::123456789012:instance-profile/WebRole")
                    .build(),
            )
            .launch_time(aws_sdk_ec2::primitives::DateTime::from_secs(1700000000))
            .build()
    }

    #[test]
    fn full_instance_converts_all_fields() {
        let sdk = full_instance();
        let dto = convert_sdk_instance(&sdk, "123456789012", "us-west-2");

        assert_eq!(dto.instance_id, "i-0abc123def456");
        assert_eq!(dto.account_id, "123456789012");
        assert_eq!(dto.region, "us-west-2");
        assert_eq!(dto.name.as_deref(), Some("web-prod-1"));
        assert_eq!(dto.private_ip.as_deref(), Some("10.0.1.50"));
        assert_eq!(dto.public_ip.as_deref(), Some("54.1.2.3"));
        assert_eq!(dto.state, InstanceState::Running);
        assert_eq!(dto.platform.as_deref(), Some("Linux/UNIX"));
        assert_eq!(dto.instance_type, "t3.micro");
        assert_eq!(dto.environment.as_deref(), Some("production"));
        assert_eq!(dto.vpc_id.as_deref(), Some("vpc-aaa"));
        assert_eq!(dto.subnet_id.as_deref(), Some("subnet-bbb"));
        assert_eq!(dto.security_groups, vec!["sg-111", "sg-222"]);
        assert_eq!(dto.iam_role.as_deref(), Some("WebRole"));
        assert!(dto.launch_time.is_some());
        // Tags include all three
        assert_eq!(dto.tags.len(), 3);
        assert_eq!(dto.tags["Team"], "platform");
    }

    #[test]
    fn ssm_managed_true_when_iam_role_and_running() {
        let sdk = full_instance(); // has IAM role, state=Running
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(dto.ssm_managed);
    }

    #[test]
    fn ssm_managed_false_when_stopped_with_iam_role() {
        let sdk = Instance::builder()
            .instance_id("i-stopped")
            .state(
                SdkInstanceState::builder()
                    .name(InstanceStateName::Stopped)
                    .build(),
            )
            .iam_instance_profile(
                IamInstanceProfile::builder()
                    .arn("arn:aws:iam::111:instance-profile/Role")
                    .build(),
            )
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(!dto.ssm_managed);
    }

    #[test]
    fn ssm_managed_false_when_no_iam_role() {
        let sdk = Instance::builder()
            .instance_id("i-norole")
            .state(
                SdkInstanceState::builder()
                    .name(InstanceStateName::Running)
                    .build(),
            )
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(!dto.ssm_managed);
    }

    #[test]
    fn instance_connect_capable_requires_vpc_and_linux() {
        let sdk = full_instance(); // vpc_id=Some, platform="Linux/UNIX"
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(dto.instance_connect_capable);
    }

    #[test]
    fn instance_connect_not_capable_without_vpc() {
        let sdk = Instance::builder()
            .instance_id("i-novpc")
            .platform_details("Linux/UNIX")
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(!dto.instance_connect_capable);
    }

    #[test]
    fn instance_connect_not_capable_without_linux_platform() {
        let sdk = Instance::builder()
            .instance_id("i-win")
            .vpc_id("vpc-123")
            .platform_details("Windows")
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert!(!dto.instance_connect_capable);
    }

    #[test]
    fn minimal_instance_uses_defaults() {
        let sdk = Instance::builder().build();
        let dto = convert_sdk_instance(&sdk, "999", "ap-southeast-1");

        assert_eq!(dto.instance_id, "unknown");
        assert_eq!(dto.account_id, "999");
        assert_eq!(dto.region, "ap-southeast-1");
        assert!(dto.name.is_none());
        assert!(dto.private_ip.is_none());
        assert!(dto.public_ip.is_none());
        assert_eq!(dto.state, InstanceState::Pending); // default
        assert!(dto.platform.is_none());
        assert_eq!(dto.instance_type, "unknown");
        assert!(!dto.ssm_managed);
        assert!(!dto.instance_connect_capable);
        assert!(dto.environment.is_none());
        assert!(dto.tags.is_empty());
        assert!(dto.launch_time.is_none());
        assert!(dto.vpc_id.is_none());
        assert!(dto.subnet_id.is_none());
        assert!(dto.security_groups.is_empty());
        assert!(dto.iam_role.is_none());
    }

    #[test]
    fn all_state_mappings() {
        let cases = [
            (InstanceStateName::Pending, InstanceState::Pending),
            (InstanceStateName::Running, InstanceState::Running),
            (InstanceStateName::ShuttingDown, InstanceState::ShuttingDown),
            (InstanceStateName::Terminated, InstanceState::Terminated),
            (InstanceStateName::Stopping, InstanceState::Stopping),
            (InstanceStateName::Stopped, InstanceState::Stopped),
        ];
        for (sdk_state, expected) in cases {
            let sdk = Instance::builder()
                .instance_id("i-test")
                .state(SdkInstanceState::builder().name(sdk_state).build())
                .build();
            let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
            assert_eq!(dto.state, expected, "mismatch for {:?}", expected);
        }
    }

    #[test]
    fn iam_role_extracts_name_from_arn() {
        let sdk = Instance::builder()
            .instance_id("i-x")
            .iam_instance_profile(
                IamInstanceProfile::builder()
                    .arn("arn:aws:iam::123456789012:instance-profile/my-app/NestedRole")
                    .build(),
            )
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        // rsplit('/') picks the last segment
        assert_eq!(dto.iam_role.as_deref(), Some("NestedRole"));
    }

    #[test]
    fn tags_with_missing_key_or_value_are_skipped() {
        let sdk = Instance::builder()
            .instance_id("i-tags")
            .tags(Tag::builder().key("Good").value("yes").build())
            .tags(Tag::builder().key("NoValue").build()) // value is None
            .tags(Tag::builder().value("NoKey").build()) // key is None
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert_eq!(dto.tags.len(), 1);
        assert_eq!(dto.tags["Good"], "yes");
    }

    #[test]
    fn security_groups_without_id_are_skipped() {
        let sdk = Instance::builder()
            .instance_id("i-sg")
            .security_groups(
                GroupIdentifier::builder()
                    .group_id("sg-ok")
                    .group_name("ok")
                    .build(),
            )
            .security_groups(GroupIdentifier::builder().group_name("no-id").build())
            .build();
        let dto = convert_sdk_instance(&sdk, "111", "us-east-1");
        assert_eq!(dto.security_groups, vec!["sg-ok"]);
    }
}
