use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ApiError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new("UNAUTHORIZED", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new("FORBIDDEN", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new("NOT_FOUND", message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("INTERNAL_ERROR", message)
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new("BAD_REQUEST", message)
    }

    pub fn service_unavailable(message: impl Into<String>) -> Self {
        Self::new("SERVICE_UNAVAILABLE", message)
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_error_serialization() {
        let err = ApiError::forbidden("not allowed");
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["code"], "FORBIDDEN");
        assert_eq!(json["message"], "not allowed");
        assert!(json.get("details").is_none()); // skip_serializing_if
    }

    #[test]
    fn api_error_with_details() {
        let mut err = ApiError::bad_request("invalid input");
        err.details = Some("field 'name' is required".into());
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["details"], "field 'name' is required");
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "code": "NOT_FOUND",
            "message": "resource missing"
        });
        let err: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, "NOT_FOUND");
        assert!(err.details.is_none());
    }

    #[test]
    fn api_error_display() {
        let err = ApiError::internal("boom");
        assert_eq!(format!("{}", err), "[INTERNAL_ERROR] boom");
    }

    #[test]
    fn api_error_constructors() {
        assert_eq!(ApiError::unauthorized("x").code, "UNAUTHORIZED");
        assert_eq!(ApiError::forbidden("x").code, "FORBIDDEN");
        assert_eq!(ApiError::not_found("x").code, "NOT_FOUND");
        assert_eq!(ApiError::internal("x").code, "INTERNAL_ERROR");
        assert_eq!(ApiError::bad_request("x").code, "BAD_REQUEST");
    }
}
