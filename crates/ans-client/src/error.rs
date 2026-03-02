//! Error types for the ANS client.

use thiserror::Error;

/// Result type alias for ANS client operations.
pub type Result<T> = std::result::Result<T, ClientError>;

/// HTTP transport error wrapper.
///
/// Wraps the underlying HTTP client error to avoid exposing third-party
/// types in the public API.
#[derive(Debug)]
pub struct HttpError {
    inner: reqwest::Error,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl std::error::Error for HttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl From<reqwest::Error> for HttpError {
    fn from(err: reqwest::Error) -> Self {
        Self { inner: err }
    }
}

/// Errors that can occur when using the ANS client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// Authentication failed (401).
    #[error("[{status_code}] unauthorized: {message}")]
    Unauthorized {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Insufficient permissions (403).
    #[error("[{status_code}] forbidden: {message}")]
    Forbidden {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Resource not found (404).
    #[error("[{status_code}] not found: {message}")]
    NotFound {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Resource conflict (409).
    #[error("[{status_code}] conflict: {message}")]
    Conflict {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Invalid request (400).
    #[error("[{status_code}] invalid request: {message}")]
    InvalidRequest {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Unprocessable entity (422).
    #[error("[{status_code}] unprocessable entity: {message}")]
    UnprocessableEntity {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Rate limited (429).
    #[error("[{status_code}] rate limited: {message}")]
    RateLimited {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// Server error (5xx).
    #[error("[{status_code}] server error: {message}")]
    ServerError {
        /// HTTP status code.
        status_code: u16,
        /// Error message from the server.
        message: String,
    },

    /// HTTP transport error.
    #[error("http error: {0}")]
    Http(#[from] HttpError),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL parsing error.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),
}

/// API error response from the server.
#[derive(Debug, Clone, serde::Deserialize)]
#[non_exhaustive]
pub struct ApiErrorResponse {
    /// Error status.
    pub status: String,
    /// Error code.
    pub code: String,
    /// Error message.
    pub message: String,
    /// Additional error details.
    #[serde(default)]
    pub details: serde_json::Value,
}

impl ClientError {
    /// Create an error from an HTTP status code and response body.
    pub fn from_response(status_code: u16, body: &str) -> Self {
        let message = serde_json::from_str::<ApiErrorResponse>(body)
            .map_or_else(|_| body.to_string(), |e| e.message);

        match status_code {
            401 => Self::Unauthorized {
                status_code,
                message,
            },
            403 => Self::Forbidden {
                status_code,
                message,
            },
            404 => Self::NotFound {
                status_code,
                message,
            },
            409 => Self::Conflict {
                status_code,
                message,
            },
            400 => Self::InvalidRequest {
                status_code,
                message,
            },
            422 => Self::UnprocessableEntity {
                status_code,
                message,
            },
            429 => Self::RateLimited {
                status_code,
                message,
            },
            500..=599 => Self::ServerError {
                status_code,
                message,
            },
            _ => Self::ServerError {
                status_code,
                message: format!("unexpected status {status_code}: {message}"),
            },
        }
    }

    /// Get the HTTP status code if this error originated from an HTTP response.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::Unauthorized { status_code, .. }
            | Self::Forbidden { status_code, .. }
            | Self::NotFound { status_code, .. }
            | Self::Conflict { status_code, .. }
            | Self::InvalidRequest { status_code, .. }
            | Self::UnprocessableEntity { status_code, .. }
            | Self::RateLimited { status_code, .. }
            | Self::ServerError { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    // ── from_response: every status code branch ──────────────────────

    #[test]
    fn from_response_401() {
        let err = ClientError::from_response(401, "bad creds");
        assert!(matches!(
            err,
            ClientError::Unauthorized {
                status_code: 401,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(401));
        assert!(err.to_string().contains("unauthorized"));
    }

    #[test]
    fn from_response_403() {
        let err = ClientError::from_response(403, "denied");
        assert!(matches!(
            err,
            ClientError::Forbidden {
                status_code: 403,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(403));
    }

    #[test]
    fn from_response_404() {
        let err = ClientError::from_response(404, "gone");
        assert!(matches!(
            err,
            ClientError::NotFound {
                status_code: 404,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(404));
    }

    #[test]
    fn from_response_409() {
        let err = ClientError::from_response(409, "conflict");
        assert!(matches!(
            err,
            ClientError::Conflict {
                status_code: 409,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(409));
    }

    #[test]
    fn from_response_400() {
        let err = ClientError::from_response(400, "bad req");
        assert!(matches!(
            err,
            ClientError::InvalidRequest {
                status_code: 400,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(400));
    }

    #[test]
    fn from_response_422() {
        let err = ClientError::from_response(422, "unprocessable");
        assert!(matches!(
            err,
            ClientError::UnprocessableEntity {
                status_code: 422,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(422));
    }

    #[test]
    fn from_response_429() {
        let err = ClientError::from_response(429, "slow down");
        assert!(matches!(
            err,
            ClientError::RateLimited {
                status_code: 429,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(429));
    }

    #[test]
    fn from_response_500() {
        let err = ClientError::from_response(500, "oops");
        assert!(matches!(
            err,
            ClientError::ServerError {
                status_code: 500,
                ..
            }
        ));
        assert_eq!(err.status_code(), Some(500));
    }

    #[test]
    fn from_response_503() {
        let err = ClientError::from_response(503, "unavailable");
        assert!(matches!(
            err,
            ClientError::ServerError {
                status_code: 503,
                ..
            }
        ));
    }

    #[test]
    fn from_response_unexpected_status() {
        let err = ClientError::from_response(418, "teapot");
        assert!(matches!(
            err,
            ClientError::ServerError {
                status_code: 418,
                ..
            }
        ));
        assert!(err.to_string().contains("unexpected status 418"));
    }

    // ── from_response: JSON body parsing ─────────────────────────────

    #[test]
    fn from_response_json_body_extracts_message() {
        let body =
            r#"{"status":"error","code":"AUTH_FAILED","message":"token expired","details":{}}"#;
        let err = ClientError::from_response(401, body);
        match err {
            ClientError::Unauthorized { message, .. } => assert_eq!(message, "token expired"),
            other => panic!("expected Unauthorized, got: {other:?}"),
        }
    }

    #[test]
    fn from_response_plain_text_body() {
        let err = ClientError::from_response(401, "plain text error");
        match err {
            ClientError::Unauthorized { message, .. } => assert_eq!(message, "plain text error"),
            other => panic!("expected Unauthorized, got: {other:?}"),
        }
    }

    // ── status_code: None variants ───────────────────────────────────

    #[test]
    fn status_code_none_for_non_http_errors() {
        let err = ClientError::InvalidUrl("bad url".to_string());
        assert_eq!(err.status_code(), None);

        let err = ClientError::Configuration("missing key".to_string());
        assert_eq!(err.status_code(), None);
    }

    // ── Display output ───────────────────────────────────────────────

    #[test]
    fn display_format_includes_status_code() {
        let err = ClientError::from_response(404, "not here");
        assert!(err.to_string().contains("[404]"));
    }
}
