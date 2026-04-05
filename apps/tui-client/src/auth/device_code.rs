use crate::api_client::ApiClient;
use anyhow::Result;
use shared::dto::auth::DeviceCodePollResponse;
use std::time::Duration;

/// Device code flow for headless terminals.
/// Shows a user code and URL, polls until the user completes auth.
pub struct DeviceCodeFlow {
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    device_code: String,
    interval: Duration,
    expires_in: Duration,
}

impl DeviceCodeFlow {
    pub async fn start(api: &ApiClient) -> Result<Self> {
        let resp = api.device_code_start().await?;

        Ok(Self {
            user_code: resp.user_code,
            verification_uri: resp.verification_uri,
            verification_uri_complete: resp.verification_uri_complete,
            device_code: resp.device_code,
            interval: Duration::from_secs(resp.interval),
            expires_in: Duration::from_secs(resp.expires_in),
        })
    }

    /// Poll until the user completes authentication or the code expires.
    /// Returns the access token on success.
    pub async fn poll_until_complete(&self, api: &ApiClient) -> Result<String> {
        let deadline = tokio::time::Instant::now() + self.expires_in;
        let mut current_interval = self.interval;

        loop {
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!("Device code expired");
            }

            tokio::time::sleep(current_interval).await;

            match api.device_code_poll(&self.device_code).await? {
                DeviceCodePollResponse::Complete {
                    access_token,
                    expires_in: _,
                } => return Ok(access_token),
                DeviceCodePollResponse::Pending => continue,
                DeviceCodePollResponse::SlowDown => {
                    // RFC 8628 §3.5: increase interval by 5 seconds
                    current_interval += Duration::from_secs(5);
                    tracing::debug!(
                        "Device code slow_down, new interval: {:?}",
                        current_interval
                    );
                    continue;
                }
                DeviceCodePollResponse::Expired => anyhow::bail!("Device code expired"),
                DeviceCodePollResponse::Denied => anyhow::bail!("Authentication denied by user"),
            }
        }
    }
}

/// Reconnect logic with exponential backoff
pub struct ExponentialBackoff {
    base: Duration,
    max: Duration,
    current: Duration,
    attempt: u32,
}

impl ExponentialBackoff {
    pub fn new(base: Duration, max: Duration) -> Self {
        Self {
            base,
            max,
            current: base,
            attempt: 0,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let delay = self.current;
        self.attempt += 1;
        self.current = (self.base * 2u32.saturating_pow(self.attempt)).min(self.max);
        delay
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
        self.current = self.base;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));

        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
        assert_eq!(backoff.next_delay(), Duration::from_secs(4));
        assert_eq!(backoff.next_delay(), Duration::from_secs(8));
        assert_eq!(backoff.next_delay(), Duration::from_secs(16));
        assert_eq!(backoff.next_delay(), Duration::from_secs(30)); // capped at max
    }

    #[test]
    fn test_backoff_reset() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        backoff.next_delay();
        backoff.next_delay();
        backoff.reset();
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn test_backoff_stays_at_max() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        // Burn through to max
        for _ in 0..10 {
            backoff.next_delay();
        }
        // Should stay at max for subsequent calls
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
        assert_eq!(backoff.next_delay(), Duration::from_secs(30));
    }

    #[test]
    fn test_backoff_base_equals_max() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(5), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
        assert_eq!(backoff.next_delay(), Duration::from_secs(5));
    }

    #[test]
    fn test_backoff_very_small_base() {
        let mut backoff =
            ExponentialBackoff::new(Duration::from_millis(1), Duration::from_millis(10));
        assert_eq!(backoff.next_delay(), Duration::from_millis(1));
        assert_eq!(backoff.next_delay(), Duration::from_millis(2));
        assert_eq!(backoff.next_delay(), Duration::from_millis(4));
        assert_eq!(backoff.next_delay(), Duration::from_millis(8));
        assert_eq!(backoff.next_delay(), Duration::from_millis(10)); // capped
    }

    #[test]
    fn test_backoff_reset_after_many_attempts() {
        let mut backoff = ExponentialBackoff::new(Duration::from_secs(1), Duration::from_secs(30));
        for _ in 0..20 {
            backoff.next_delay();
        }
        assert_eq!(backoff.attempt, 20);
        backoff.reset();
        assert_eq!(backoff.attempt, 0);
        assert_eq!(backoff.next_delay(), Duration::from_secs(1));
        assert_eq!(backoff.next_delay(), Duration::from_secs(2));
    }
}
