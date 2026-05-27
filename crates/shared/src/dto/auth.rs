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
        #[serde(default)]
        #[serde(skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactorKind {
    Totp,
    WebAuthn,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaFactorStatus {
    pub kind: MfaFactorKind,
    pub available: bool,
    pub enrolled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MfaStatusResponse {
    pub user_id: String,
    pub provider_step_up_configured: bool,
    pub local_step_up_available: bool,
    pub step_up_required: bool,
    pub factors: Vec<MfaFactorStatus>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpEnrollStartRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpEnrollStartResponse {
    pub factor_id: String,
    pub secret_base32: String,
    pub otpauth_url: String,
    pub issuer: String,
    pub account_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpEnrollConfirmRequest {
    pub factor_id: String,
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpEnrollConfirmResponse {
    pub factor_id: String,
    pub enrolled: bool,
    pub status: MfaStatusResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpVerifyRequest {
    pub code: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TotpVerifyResponse {
    pub factor_id: String,
    pub verified: bool,
    pub verified_at: String,
    pub step_up_expires_at: String,
    pub status: MfaStatusResponse,
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
    fn token_response_defaults_missing_refresh_token() {
        let json = json!({
            "access_token": "tok",
            "token_type": "Bearer",
            "expires_in": 3600
        });

        let resp: TokenResponse = serde_json::from_value(json).unwrap();

        assert_eq!(resp.access_token, "tok");
        assert_eq!(resp.refresh_token, None);
    }

    #[test]
    fn mfa_status_roundtrip() {
        let resp = MfaStatusResponse {
            user_id: "u1".into(),
            provider_step_up_configured: true,
            local_step_up_available: false,
            step_up_required: false,
            factors: vec![
                MfaFactorStatus {
                    kind: MfaFactorKind::Totp,
                    available: false,
                    enrolled: false,
                    label: Some("Authenticator app".into()),
                },
                MfaFactorStatus {
                    kind: MfaFactorKind::WebAuthn,
                    available: false,
                    enrolled: false,
                    label: Some("Security key".into()),
                },
            ],
            message: "OIDC provider MFA/re-auth controls are configured.".into(),
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["factors"][0]["kind"], "totp");
        assert_eq!(json["factors"][1]["kind"], "web_authn");

        let back: MfaStatusResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn totp_enroll_start_roundtrip() {
        let resp = TotpEnrollStartResponse {
            factor_id: "factor-1".into(),
            secret_base32: "ABCDEF234567".into(),
            otpauth_url: "otpauth://totp/Canopy:alice".into(),
            issuer: "Canopy".into(),
            account_name: "alice@example.com".into(),
        };

        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["issuer"], "Canopy");
        assert_eq!(json["account_name"], "alice@example.com");

        let back: TotpEnrollStartResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn totp_enroll_confirm_roundtrip() {
        let req = TotpEnrollConfirmRequest {
            factor_id: "factor-1".into(),
            code: "123456".into(),
        };

        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["code"], "123456");

        let back: TotpEnrollConfirmRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn totp_verify_roundtrip() {
        let req = TotpVerifyRequest {
            code: "123456".into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["code"], "123456");
        let back: TotpVerifyRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back, req);
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
            refresh_token: Some("refresh".into()),
        };
        let json = serde_json::to_value(&val).unwrap();
        assert_eq!(json["status"], "complete");
        assert_eq!(json["access_token"], "tok");
        assert_eq!(json["refresh_token"], "refresh");
    }

    #[test]
    fn device_code_poll_complete_defaults_missing_refresh_token() {
        let json = json!({
            "status": "complete",
            "access_token": "tok",
            "expires_in": 3600
        });
        let val: DeviceCodePollResponse = serde_json::from_value(json).unwrap();
        match val {
            DeviceCodePollResponse::Complete { refresh_token, .. } => {
                assert_eq!(refresh_token, None);
            }
            other => panic!("expected complete response, got {other:?}"),
        }
    }

    #[test]
    fn device_code_poll_complete_omits_none_refresh_token() {
        let val = DeviceCodePollResponse::Complete {
            access_token: "tok".into(),
            expires_in: 3600,
            refresh_token: None,
        };

        let json = serde_json::to_value(&val).unwrap();

        assert_eq!(json["status"], "complete");
        assert!(
            json.get("refresh_token").is_none(),
            "refresh_token must be omitted, not serialized as null"
        );
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
