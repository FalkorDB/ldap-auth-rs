use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use once_cell::sync::Lazy;
use tracing::{info, warn};

/// Cached bearer token loaded at startup
/// Note: This is lazily initialized on first use, so test can set env var before first request
static BEARER_TOKEN: Lazy<String> = Lazy::new(|| {
    std::env::var("API_BEARER_TOKEN").unwrap_or_else(|_| {
        warn!("API_BEARER_TOKEN not set - API authentication will fail");
        String::new()
    })
});

/// Middleware to validate bearer token authentication
pub async fn validate_bearer_token(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let expected_token = BEARER_TOKEN.as_str();

    // Extract authorization header
    let auth_header = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(AuthError::MissingToken)?;

    // Check if it's a Bearer token
    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::InvalidTokenFormat);
    }

    // Extract and validate token
    let token = &auth_header[7..]; // Skip "Bearer "
    if token != expected_token {
        info!(
            event = "auth_failed",
            reason = "invalid_token",
            "Authentication attempt with invalid token"
        );
        return Err(AuthError::InvalidToken);
    }

    // Token is valid, proceed with request
    info!(
        event = "auth_success",
        "Valid authentication token provided"
    );
    Ok(next.run(request).await)
}

#[derive(Debug)]
pub enum AuthError {
    MissingToken,
    InvalidToken,
    InvalidTokenFormat,
    ConfigurationError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AuthError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing authorization token"),
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid authorization token"),
            AuthError::InvalidTokenFormat => (
                StatusCode::UNAUTHORIZED,
                "Invalid authorization format. Expected: Bearer <token>",
            ),
            AuthError::ConfigurationError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server configuration error",
            ),
        };

        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests verify the error conditions
    // Full integration tests are in tests/auth_integration_test.rs

    #[test]
    fn test_auth_error_responses() {
        let missing = AuthError::MissingToken;
        let response = missing.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let invalid = AuthError::InvalidToken;
        let response = invalid.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let format = AuthError::InvalidTokenFormat;
        let response = format.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let config = AuthError::ConfigurationError;
        let response = config.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
