//! # Authentication Errors
//!
//! This module defines authentication-specific errors for the EYWA Authentication crate.
//! These errors are automatically converted to the centralized `AppError` type from `eywa-errors`.

use axum::http::StatusCode;
use eywa_errors::AppError;
use thiserror::Error;

/// Authentication-specific errors that occur during JWT, password, or TOTP operations.
#[derive(Error, Debug)]
pub enum AuthError {
    // ==================== JWT Errors ====================
    /// The JWT token is invalid or malformed
    #[error("Invalid JWT token: {0}")]
    InvalidJwt(String),

    /// The JWT token has expired
    #[error("JWT token has expired")]
    JwtExpired,

    /// The JWT token is malformed or cannot be decoded
    #[error("Malformed JWT token: {0}")]
    JwtMalformed(String),

    /// Missing required claims in the JWT token
    #[error("Missing JWT claim: {claim}")]
    MissingClaim { claim: String },

    /// JWT token issuer does not match expected issuer
    #[error("JWT issuer mismatch: expected '{expected}', got '{actual}'")]
    JwtIssuerMismatch { expected: String, actual: String },

    /// JWT token audience does not match expected audience
    #[error("JWT audience mismatch: expected '{expected}', got '{actual}'")]
    JwtAudienceMismatch { expected: String, actual: String },

    /// JWT token generation failed
    #[error("JWT generation failed: {0}")]
    JwtGenerationFailed(String),

    /// JWT validation failed
    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),

    /// Invalid token type (expected access, got refresh or vice versa)
    #[error("Invalid token type: expected {expected}, got {actual}")]
    InvalidTokenType { expected: String, actual: String },

    // ==================== Password Errors ====================
    /// Error occurred while hashing a password
    #[error("Failed to hash password: {0}")]
    PasswordHashError(String),

    /// Error occurred while verifying a password
    #[error("Failed to verify password: {0}")]
    PasswordVerificationError(String),

    /// Password does not meet security policy requirements
    #[error("Password does not meet security requirements: {0}")]
    PasswordTooWeak(String),

    // ==================== TOTP Errors ====================
    /// Error occurred while generating a TOTP secret
    #[error("Failed to generate TOTP secret: {0}")]
    TotpSecretGenerationError(String),

    /// TOTP code verification failed
    #[error("Invalid TOTP code")]
    InvalidTotpCode,

    /// TOTP code is expired (outside time window)
    #[error("TOTP code has expired")]
    TotpCodeExpired,

    /// Error occurred while generating TOTP secret
    #[error("Failed to generate TOTP secret: {0}")]
    TotpGenerationFailed(String),

    /// Invalid TOTP secret format
    #[error("Invalid TOTP secret: {0}")]
    InvalidTotpSecret(String),

    /// Invalid QR code URI
    #[error("Invalid QR code URI: {0}")]
    InvalidQrCodeUri(String),

    /// Error occurred while generating QR code for TOTP setup
    #[error("Failed to generate QR code: {0}")]
    TotpQrCodeError(String),

    /// Error occurred while generating QR code
    #[error("Failed to generate QR code: {0}")]
    QrCodeGenerationFailed(String),

    // ==================== Credentials & Account ====================
    /// Invalid email or password
    #[error("Invalid email or password")]
    InvalidCredentials,

    /// User already exists
    #[error("User already exists")]
    UserAlreadyExists,

    /// Account is locked or disabled
    #[error("Account is locked for {seconds} seconds")]
    AccountLocked { seconds: u64 },

    /// Internal error during authentication
    #[error("Internal authentication error: {0}")]
    InternalError(String),

    /// 2FA is required but not provided
    #[error("Two-factor authentication required")]
    TwoFactorRequired,

    /// Missing authentication token
    #[error("Missing authentication token")]
    MissingAuthToken,

    /// Invalid authentication format
    #[error("Invalid authentication format")]
    InvalidAuthFormat,

    /// Generic authentication flow error
    #[error("Authentication failed: {0}")]
    AuthFlowError(String),

    // ==================== Input Validation Errors ====================
    /// Invalid username format
    #[error("Invalid username: {0}")]
    InvalidUsername(String),

    /// Invalid UUID format
    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),

    /// Invalid phone number format
    #[error("Invalid phone number: {0}")]
    InvalidPhone(String),

    /// Invalid URL format
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// Dangerous content detected (XSS, SQL injection, etc.)
    #[error("Dangerous content detected: {content}")]
    DangerousContent { content: String },

    /// Input is too short
    #[error("Input is too short: minimum {min_length} characters, got {actual_length}")]
    InputTooShort {
        min_length: usize,
        actual_length: usize,
    },

    /// Input is too long
    #[error("Input is too long: maximum {max_length} characters, got {actual_length}")]
    InputTooLong {
        max_length: usize,
        actual_length: usize,
    },

    /// Required field is missing
    #[error("Missing required field: {field}")]
    MissingField { field: String },

    /// Invalid field value
    #[error("Invalid value for field '{field}': {reason}")]
    InvalidFieldValue { field: String, reason: String },

    // ==================== Configuration Errors ====================
    /// Invalid configuration for authentication
    #[error("Invalid authentication configuration: {0}")]
    ConfigError(String),

    /// Missing required configuration value
    #[error("Missing configuration: {field}")]
    MissingConfig { field: String },
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => Self::JwtExpired,
            jsonwebtoken::errors::ErrorKind::InvalidToken => Self::InvalidJwt(err.to_string()),
            jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                Self::InvalidJwt("Invalid signature".to_string())
            }
            _ => Self::JwtMalformed(err.to_string()),
        }
    }
}

impl From<argon2::Error> for AuthError {
    fn from(err: argon2::Error) -> Self {
        Self::PasswordHashError(err.to_string())
    }
}

impl From<totp_rs::TotpUrlError> for AuthError {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        Self::TotpSecretGenerationError(err.to_string())
    }
}

impl From<base64::DecodeError> for AuthError {
    fn from(err: base64::DecodeError) -> Self {
        Self::JwtMalformed(format!("Base64 decode error: {}", err))
    }
}

#[cfg(feature = "qr")]
impl From<qrcode::types::QrError> for AuthError {
    fn from(err: qrcode::types::QrError) -> Self {
        Self::TotpQrCodeError(err.to_string())
    }
}

impl From<AuthError> for AppError {
    fn from(err: AuthError) -> Self {
        match err {
            // JWT Authentication errors -> Unauthorized
            AuthError::JwtExpired
            | AuthError::InvalidCredentials
            | AuthError::InvalidTotpCode
            | AuthError::TotpCodeExpired
            | AuthError::TwoFactorRequired
            | AuthError::MissingAuthToken
            | AuthError::InvalidAuthFormat
            | AuthError::AccountLocked { .. } => Self::Unauthorized,

            // JWT errors that need logging
            AuthError::InvalidJwt(_)
            | AuthError::JwtMalformed(_)
            | AuthError::MissingClaim { .. }
            | AuthError::JwtIssuerMismatch { .. }
            | AuthError::JwtAudienceMismatch { .. }
            | AuthError::JwtGenerationFailed(_)
            | AuthError::JwtValidationFailed(_)
            | AuthError::InvalidTokenType { .. }
            | AuthError::PasswordVerificationError(_)
            | AuthError::AuthFlowError(_)
            | AuthError::InternalError(_) => {
                Self::InternalServerError(format!("Authentication error: {}", err))
            }

            // User already exists
            AuthError::UserAlreadyExists => Self::ValidationError {
                field: "email".to_string(), // could be username too
                message: "User with this email or username already exists".to_string(),
            },

            // Validation errors
            AuthError::PasswordTooWeak(msg) => Self::ValidationError {
                field: "password".to_string(),
                message: msg,
            },

            AuthError::InvalidUsername(msg) => Self::ValidationError {
                field: "username".to_string(),
                message: msg,
            },

            AuthError::InvalidUuid(msg) => Self::ValidationError {
                field: "uuid".to_string(),
                message: format!("Invalid UUID: {}", msg),
            },

            AuthError::InvalidPhone(msg) => Self::ValidationError {
                field: "phone".to_string(),
                message: format!("Invalid phone: {}", msg),
            },

            AuthError::InvalidUrl(msg) => Self::ValidationError {
                field: "url".to_string(),
                message: msg,
            },

            AuthError::DangerousContent { content } => Self::ValidationError {
                field: "input".to_string(),
                message: format!("Dangerous content detected: {}", content),
            },

            AuthError::InputTooShort {
                min_length,
                actual_length,
            } => Self::ValidationError {
                field: "input".to_string(),
                message: format!(
                    "Input too short: minimum {} characters, got {}",
                    min_length, actual_length
                ),
            },

            AuthError::InputTooLong {
                max_length,
                actual_length,
            } => Self::ValidationError {
                field: "input".to_string(),
                message: format!(
                    "Input too long: maximum {} characters, got {}",
                    max_length, actual_length
                ),
            },

            AuthError::MissingField { field } => Self::ValidationError {
                field: field.clone(),
                message: format!("Missing required field: {}", field),
            },

            AuthError::InvalidFieldValue { field, reason } => Self::ValidationError {
                field,
                message: reason,
            },

            // Internal/TOTP errors
            AuthError::PasswordHashError(_)
            | AuthError::TotpSecretGenerationError(_)
            | AuthError::TotpGenerationFailed(_)
            | AuthError::InvalidTotpSecret(_)
            | AuthError::InvalidQrCodeUri(_)
            | AuthError::TotpQrCodeError(_)
            | AuthError::QrCodeGenerationFailed(_)
            | AuthError::ConfigError(_)
            | AuthError::MissingConfig { .. } => Self::InternalServerError(err.to_string()),
        }
    }
}

impl AuthError {
    /// Returns the HTTP status code that should be returned for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidJwt(_)
            | Self::JwtExpired
            | Self::JwtMalformed(_)
            | Self::MissingClaim { .. }
            | Self::JwtIssuerMismatch { .. }
            | Self::JwtAudienceMismatch { .. }
            | Self::InvalidCredentials
            | Self::AccountLocked { .. }
            | Self::InvalidTotpCode
            | Self::TotpCodeExpired
            | Self::TwoFactorRequired => StatusCode::UNAUTHORIZED,

            Self::PasswordTooWeak(_)
            | Self::UserAlreadyExists
            | Self::InputTooShort { .. }
            | Self::InputTooLong { .. }
            | Self::InvalidFieldValue { .. } => StatusCode::BAD_REQUEST,

            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
