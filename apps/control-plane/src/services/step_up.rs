use chrono::{DateTime, Duration, Utc};
use shared::dto::auth::MfaFactorKind;
use shared::errors::ApiError;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::models::mfa::MfaStoreError;
use crate::services::auth::Claims;

use super::AppState;

pub const LOCAL_STEP_UP_TTL_SECONDS: i64 = 300;

#[derive(Debug, Clone, Default)]
pub struct StepUpSessionStore {
    sessions: Arc<Mutex<HashMap<String, DateTime<Utc>>>>,
}

impl StepUpSessionStore {
    pub fn mark_verified_until(&self, session_key: &str, expires_at: DateTime<Utc>) {
        self.sessions_guard()
            .insert(session_key.to_string(), expires_at);
    }

    pub fn is_verified(&self, session_key: &str) -> bool {
        let now = Utc::now();
        let mut sessions = self.sessions_guard();
        match sessions.get(session_key) {
            Some(expires_at) if *expires_at > now => true,
            Some(_) => {
                sessions.remove(session_key);
                false
            }
            None => false,
        }
    }

    fn sessions_guard(&self) -> MutexGuard<'_, HashMap<String, DateTime<Utc>>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub fn claims_step_up_key(claims: &Claims) -> String {
    if claims.jti.is_empty() {
        format!("{}:{}:{}", claims.sub, claims.iat, claims.exp)
    } else {
        format!("{}:{}", claims.sub, claims.jti)
    }
}

pub fn local_step_up_required(
    state: &AppState,
    user_id: &str,
    session_key: &str,
) -> Result<bool, MfaStoreError> {
    let local_factor_enrolled =
        state
            .mfa_store
            .factor_statuses(user_id)?
            .into_iter()
            .any(|factor| {
                matches!(factor.kind, MfaFactorKind::Totp | MfaFactorKind::WebAuthn)
                    && factor.available
                    && factor.enrolled
            });

    Ok(local_factor_enrolled && !state.step_up_sessions.is_verified(session_key))
}

pub fn step_up_expires_at(now: DateTime<Utc>) -> DateTime<Utc> {
    now + Duration::seconds(LOCAL_STEP_UP_TTL_SECONDS)
}

pub fn step_up_required_error() -> ApiError {
    let mut err = ApiError::new(
        "STEP_UP_REQUIRED",
        "Local step-up verification is required. Open Settings and press v for TOTP, x for passkey, or u for an unused recovery code, then retry the operation.",
    );
    err.details = Some("local_mfa".into());
    err
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_up_session_expires() {
        let store = StepUpSessionStore::default();
        store.mark_verified_until("alice:1:2", Utc::now() + Duration::seconds(60));
        assert!(store.is_verified("alice:1:2"));
        assert!(!store.is_verified("alice:3:4"));

        store.mark_verified_until("alice:1:2", Utc::now() - Duration::seconds(1));
        assert!(!store.is_verified("alice:1:2"));
    }
}
