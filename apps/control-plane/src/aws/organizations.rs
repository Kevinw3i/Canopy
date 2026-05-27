use aws_config::SdkConfig;
use aws_sdk_organizations::types::Account;

use crate::aws::clients::AwsClients;
use crate::models::entitlements::DiscoveredOrganizationAccount;

/// Discover ACTIVE AWS Organizations accounts visible to the task role.
pub async fn discover_active_accounts(
    base_config: &SdkConfig,
) -> anyhow::Result<Vec<DiscoveredOrganizationAccount>> {
    let client = AwsClients::organizations(base_config);
    let mut next_token: Option<String> = None;
    let mut accounts = Vec::new();

    loop {
        let mut request = client.list_accounts();
        if let Some(token) = next_token.as_deref() {
            request = request.next_token(token);
        }

        let response = request.send().await?;
        for account in response.accounts() {
            if is_active_account(account) {
                let account_id = account
                    .id()
                    .ok_or_else(|| anyhow::anyhow!("Organizations account is missing id"))?;
                let account_name = account.name().unwrap_or(account_id);
                accounts.push(DiscoveredOrganizationAccount {
                    account_id: account_id.to_string(),
                    account_name: account_name.to_string(),
                });
            }
        }

        next_token = response.next_token().map(str::to_string);
        if next_token.is_none() {
            break;
        }
    }

    Ok(accounts)
}

fn is_active_account(account: &Account) -> bool {
    if let Some(state) = account.state() {
        return state.as_str() == "ACTIVE";
    }

    account
        .status()
        .map(|status| status.as_str() == "ACTIVE")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_sdk_organizations::types::{AccountState, AccountStatus};

    #[test]
    fn active_account_uses_state() {
        let account = Account::builder()
            .state(AccountState::Active)
            .status(AccountStatus::Suspended)
            .build();

        assert!(is_active_account(&account));
    }

    #[test]
    fn inactive_state_overrides_legacy_status() {
        let account = Account::builder()
            .state(AccountState::Suspended)
            .status(AccountStatus::Active)
            .build();

        assert!(!is_active_account(&account));
    }

    #[test]
    fn active_account_falls_back_to_legacy_status() {
        let account = Account::builder().status(AccountStatus::Active).build();

        assert!(is_active_account(&account));
    }
}
