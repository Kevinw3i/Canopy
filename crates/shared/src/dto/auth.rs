use serde::{Deserialize, Serialize};

/// Initiate PKCE authorization code flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceAuthRequest {
    pub code_verifier: String,
    pub redirect_uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PkceAuthResponse {
    pub authorize_url: String,
    pub state: String,
}

/// Exchange authorization code for tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenExchangeRequest {
    pub code: String,
    pub code_verifier: String,
    pub state: String,
    pub redirect_uri: String,
}

/// Initiate device code flow (headless terminals)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeRequest {
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

/// Poll for device code completion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodePollRequest {
    pub device_code: String,
    pub client_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum DeviceCodePollResponse {
    #[serde(rename = "pending")]
    Pending,
    /// RFC 8628: server asks client to increase its poll interval by 5 seconds.
    #[serde(rename = "slow_down")]
    SlowDown,
    #[serde(rename = "complete")]
    Complete {
        access_token: String,
        expires_in: u64,
    },
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "denied")]
    Denied,
}

/// Token response from the control-plane
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Refresh token request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Current user identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub groups: Vec<String>,
    /// Whether the email was verified by the IdP.
    #[serde(default)]
    pub email_verified: bool,
}

/// Local dev mode login (NOT for production)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevLoginRequest {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevLoginResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub identity: UserIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn token_response_roundtrip() {
        let resp = TokenResponse {
            access_token: "tok-123".into(),
            token_type: "Bearer".into(),
            expires_in: 3600,
            refresh_token: Some("ref-456".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["refresh_token"], "ref-456");

        let back: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.access_token, "tok-123");
    }

    #[test]
    fn token_response_omits_none_refresh() {
        let resp = TokenResponse {
            access_token: "t".into(),
            token_type: "Bearer".into(),
            expires_in: 60,
            refresh_token: None,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("refresh_token"));
    }

    #[test]
    fn device_code_poll_pending_roundtrip() {
        let val = DeviceCodePollResponse::Pending;
        let json = serde_json::to_value(&val).unwrap();
        assert_eq!(json["status"], "pending");
        let back: DeviceCodePollResponse = serde_json::from_value(json).unwrap();
        assert!(matches!(back, DeviceCodePollResponse::Pending));
    }

    #[test]
    fn device_code_poll_complete_roundtrip() {
        let val = DeviceCodePollResponse::Complete {
            access_token: "tok".into(),
            expires_in: 3600,
        };
        let json = serde_json::to_value(&val).unwrap();
        assert_eq!(json["status"], "complete");
        assert_eq!(json["access_token"], "tok");
    }

    #[test]
    fn device_code_poll_slow_down() {
        let json = json!({"status": "slow_down"});
        let val: DeviceCodePollResponse = serde_json::from_value(json).unwrap();
        assert!(matches!(val, DeviceCodePollResponse::SlowDown));
    }

    #[test]
    fn device_code_response_omits_none_uri_complete() {
        let resp = DeviceCodeResponse {
            device_code: "dc".into(),
            user_code: "UC".into(),
            verification_uri: "https://x".into(),
            verification_uri_complete: None,
            expires_in: 300,
            interval: 5,
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("verification_uri_complete"));
    }

    #[test]
    fn user_identity_email_verified_defaults_false() {
        let json = json!({
            "user_id": "u1",
            "email": "u@x.com",
            "display_name": "U",
            "groups": []
        });
        let id: UserIdentity = serde_json::from_value(json).unwrap();
        assert!(!id.email_verified);
    }

    #[test]
    fn pkce_request_roundtrip() {
        let req = PkceAuthRequest {
            code_verifier: "cv123".into(),
            redirect_uri: "http://localhost/cb".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: PkceAuthRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.code_verifier, "cv123");
    }
}
