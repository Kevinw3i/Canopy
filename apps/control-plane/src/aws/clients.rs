use aws_config::SdkConfig;
use aws_sdk_cloudwatchlogs::Client as CwlClient;
use aws_sdk_ec2::Client as Ec2Client;

/// Factory for AWS SDK clients from an assumed-role SdkConfig.
///
/// Clients are created fresh each time to ensure they use the correct
/// STS session credentials. Client construction is cheap (no network
/// calls) — the real cost is the preceding AssumeRole call.
pub struct AwsClients;

impl AwsClients {
    pub fn ec2(config: &SdkConfig) -> Ec2Client {
        Ec2Client::new(config)
    }

    pub fn cloudwatch_logs(config: &SdkConfig) -> CwlClient {
        CwlClient::new(config)
    }
}
