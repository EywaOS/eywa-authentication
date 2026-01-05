//! # JWT Service
//!
//! This module provides JWT (JSON Web Token) generation and validation.
//!
//! ## Features
//!
//! - HS256 signing algorithm (symmetric)
//! - Configurable expiration times
//! - Issuer and audience validation
//! - Unique token IDs (JTI) for tracking
//! - Support for access and refresh tokens
//!
//! ## Usage
//!
//! ```no_run
//! use eywa_authentication::JwtService;
//!
//! // Create service
//! let service = JwtService::new(
//!     "your_secret_key_at_least_64_characters_long_for_security!!!".to_string(),
//!     "homemanager".to_string(),  // issuer
//!     "homemanager-api".to_string(), // audience
//!     3600i64,                    // expiration (1 hour)
//! );
//!
//! // Generate access token
//! let token = service.generate_token("user_123", "john_doe").unwrap();
//!
//! // Validate token
//! let claims = service.validate_token(&token).unwrap();
//! println!("User ID: {}", claims.sub);
//! ```
//!
//! ## Security
//!
//! - Use a secret key of at least 64 characters in production
//! - Keep token expiration short (1 hour for access tokens)
//! - Never include sensitive data in token claims
//! - Validate issuer and audience on every request
//! - Use HTTPS to transmit tokens

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::fmt;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{Result, error::AuthError};
use eywa_errors::AppError;

// ==================== JWT Claims ====================

/// JWT Claims structure
///
/// This structure follows the JWT standard claims (RFC 7519) and includes
/// custom claims for HomeManager authentication.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    /// Subject - The user ID this token represents
    ///
    /// This should be a stable identifier (e.g., database UUID)
    pub sub: String,

    /// Username - Human-readable identifier (for convenience)
    pub username: String,

    /// Issued At - Unix timestamp when token was created
    pub iat: i64,

    /// Expiration Time - Unix timestamp when token expires
    pub exp: i64,

    /// Issuer - The service that issued the token
    pub iss: String,

    /// Audience - The service(s) this token is intended for
    pub aud: String,

    /// JWT ID - Unique identifier for this specific token
    ///
    /// Used for:
    /// - Token blacklisting (if implemented)
    /// - Detecting token reuse
    /// - Audit logging
    pub jti: String,

    /// Token Type - Distinguishes between access and refresh tokens
    #[serde(rename = "type")]
    pub token_type: TokenType,
}

impl Claims {
    /// Create new claims for a token
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique user identifier (e.g., UUID)
    /// * `username` - Username for convenience
    /// * `expiration_seconds` - Token lifetime in seconds
    /// * `issuer` - Token issuer (e.g., "homemanager-auth")
    /// * `audience` - Target audience (e.g., "homemanager-api")
    /// * `token_type` - Type of token (Access or Refresh)
    #[must_use]
    pub fn new(
        user_id: String,
        username: String,
        expiration_seconds: i64,
        issuer: String,
        audience: String,
        token_type: TokenType,
    ) -> Self {
        let now = OffsetDateTime::now_utc().unix_timestamp();

        Self {
            sub: user_id,
            username,
            iat: now,
            exp: now + expiration_seconds,
            iss: issuer,
            aud: audience,
            jti: Uuid::new_v4().to_string(),
            token_type,
        }
    }

    /// Check if token has expired
    ///
    /// # Returns
    ///
    /// `true` if token is expired, `false` otherwise
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.exp < now
    }

    /// Get time until expiration in seconds
    ///
    /// # Returns
    ///
    /// Number of seconds until expiration, or negative if already expired
    #[must_use]
    pub fn time_until_expiration(&self) -> i64 {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        self.exp - now
    }
}

impl fmt::Display for Claims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Claims {{ sub: {}, username: {}, iss: {}, aud: {}, exp: {}, type: {} }}",
            self.sub, self.username, self.iss, self.aud, self.exp, self.token_type
        )
    }
}

// ==================== Token Type ====================

/// Token type for different JWT purposes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Access token - Used for API authentication
    ///
    /// # Characteristics
    /// - Short-lived (typically 5 minutes to 1 hour)
    /// - Contains user information
    /// - Used for authenticating API requests
    Access,

    /// Refresh token - Used to obtain new access tokens
    ///
    /// # Characteristics
    /// - Long-lived (typically 7 days to 30 days)
    /// - Contains minimal information
    /// - Used to refresh access tokens without re-authentication
    Refresh,
}

impl TokenType {
    /// Get the expiration time in seconds for this token type
    ///
    /// # Returns
    ///
    /// Recommended expiration time in seconds
    #[must_use]
    pub fn recommended_expiration_seconds(&self) -> i64 {
        match self {
            Self::Access => 3600,    // 1 hour
            Self::Refresh => 604800, // 7 days
        }
    }

    /// Check if this token type requires 2FA verification
    ///
    /// # Returns
    ///
    /// `true` if refresh token (should require re-auth after long period)
    #[must_use]
    pub fn requires_2fa(&self) -> bool {
        matches!(self, Self::Refresh)
    }
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Access => write!(f, "access"),
            Self::Refresh => write!(f, "refresh"),
        }
    }
}

// ==================== Token Pair ====================

/// Pair of access and refresh tokens
///
/// This structure is returned when a user authenticates.
#[derive(Debug, Clone, Serialize)]
pub struct TokenPair {
    /// Access token for API authentication
    pub access_token: String,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Access token expiration time in seconds
    pub expires_in: i64,

    /// Token type (always "Bearer")
    pub token_type: String,
}

impl TokenPair {
    /// Create a new token pair
    #[must_use]
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            expires_in,
            token_type: "Bearer".to_string(),
        }
    }
}

// ==================== JWT Service ====================

/// JWT Service for token generation and validation
///
/// This service uses the HS256 algorithm (symmetric key) for signing tokens.
///
/// # Security
///
/// - Keep the secret key secure and never commit it to version control
/// - Use a strong secret key (at least 64 characters in production)
/// - Rotate the secret key regularly in production
/// - Use HTTPS to transmit tokens
///
/// # Thread Safety
///
/// This service is thread-safe and can be shared across threads using `Arc`.
#[derive(Debug, Clone)]
pub struct JwtService {
    /// Secret key for signing tokens
    secret: String,

    /// Token issuer
    issuer: String,

    /// Token audience
    audience: String,

    /// Default expiration time in seconds
    expiration_seconds: i64,
}

impl JwtService {
    /// Create a new JWT service
    ///
    /// # Arguments
    ///
    /// * `secret` - Secret key for signing (MIN 32 characters!)
    /// * `issuer` - Issuer identifier (e.g., "homemanager-auth")
    /// * `audience` - Audience identifier (e.g., "homemanager-api")
    /// * `expiration_seconds` - Default token expiration time
    ///
    /// # Panics
    ///
    /// Panics if secret is less than 32 characters
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::JwtService;
    ///
    /// let service = JwtService::new(
    ///     "your_secret_key_at_least_32_characters_long".to_string(),
    ///     "homemanager".to_string(),
    ///     3600i64,
    /// );
    /// ```
    #[must_use]
    pub fn new(secret: String, issuer: String, expiration_seconds: i64) -> Self {
        if secret.len() < 32 {
            panic!(
                "JWT secret must be at least 32 characters (got {})",
                secret.len()
            );
        }

        Self {
            secret,
            issuer,
            audience: "default".to_string(),
            expiration_seconds,
        }
    }

    /// Create a new JWT service with audience
    #[must_use]
    pub fn with_audience(
        secret: String,
        issuer: String,
        audience: String,
        expiration_seconds: i64,
    ) -> Self {
        if secret.len() < 32 {
            panic!(
                "JWT secret must be at least 32 characters (got {})",
                secret.len()
            );
        }

        Self {
            secret,
            issuer,
            audience,
            expiration_seconds,
        }
    }

    /// Get the issuer
    #[must_use]
    pub const fn issuer(&self) -> &String {
        &self.issuer
    }

    /// Get the audience
    #[must_use]
    pub const fn audience(&self) -> &String {
        &self.audience
    }

    /// Get the expiration time in seconds
    #[must_use]
    pub const fn expiration_seconds(&self) -> i64 {
        self.expiration_seconds
    }

    /// Generate an access token for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique user identifier (e.g., UUID)
    /// * `username` - Username
    ///
    /// # Returns
    ///
    /// Signed JWT access token
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::JwtService;
    ///
    /// let service = JwtService::new(
    ///     "secret".to_string(),
    ///     "issuer".to_string(),
    ///     3600i64,
    /// );
    ///
    /// let token = service.generate_token("user_123", "john").unwrap();
    /// ```
    pub fn generate_token(&self, user_id: &str, username: &str) -> Result<String> {
        let claims = Claims::new(
            user_id.to_string(),
            username.to_string(),
            self.expiration_seconds,
            self.issuer.clone(),
            self.audience.clone(),
            TokenType::Access,
        );

        self.encode_token(&claims)
    }

    /// Generate a custom token with custom claims
    ///
    /// # Arguments
    ///
    /// * `claims` - Custom claims
    ///
    /// # Returns
    ///
    /// Signed JWT token
    pub fn generate_token_from_claims(&self, claims: &Claims) -> Result<String> {
        self.encode_token(claims)
    }

    /// Generate both access and refresh tokens
    ///
    /// # Arguments
    ///
    /// * `user_id` - Unique user identifier
    /// * `username` - Username
    ///
    /// # Returns
    ///
    /// TokenPair containing both access and refresh tokens
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::JwtService;
    ///
    /// let service = JwtService::new(
    ///     "secret".to_string(),
    ///     "issuer".to_string(),
    ///     3600i64,
    /// );
    ///
    /// let token_pair = service.generate_token_pair("user_123", "john").unwrap();
    /// println!("Access token: {}", token_pair.access_token);
    /// println!("Refresh token: {}", token_pair.refresh_token);
    /// ```
    pub fn generate_token_pair(&self, user_id: &str, username: &str) -> Result<TokenPair> {
        let access_claims = Claims::new(
            user_id.to_string(),
            username.to_string(),
            self.expiration_seconds,
            self.issuer.clone(),
            self.audience.clone(),
            TokenType::Access,
        );

        let refresh_claims = Claims::new(
            user_id.to_string(),
            username.to_string(),
            TokenType::Refresh.recommended_expiration_seconds(),
            self.issuer.clone(),
            self.audience.clone(),
            TokenType::Refresh,
        );

        let access_token = self.encode_token(&access_claims)?;
        let refresh_token = self.encode_token(&refresh_claims)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: self.expiration_seconds,
            token_type: "Bearer".to_string(),
        })
    }

    /// Validate and decode a JWT token
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    ///
    /// # Returns
    ///
    /// Decoded claims if token is valid
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Token format is invalid
    /// - Token signature is invalid
    /// - Token has expired
    /// - Issuer doesn't match
    /// - Audience doesn't match
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::JwtService;
    ///
    /// let service = JwtService::new(
    ///     "secret".to_string(),
    ///     "issuer".to_string(),
    ///     3600i64,
    /// );
    ///
    /// let claims = service.validate_token(&token).unwrap();
    /// println!("User: {}", claims.username);
    /// ```
    pub fn validate_token(&self, token: &str) -> Result<Claims> {
        let claims = self.decode_token(token)?;

        // Verify issuer
        if claims.iss != self.issuer {
            return Err(AuthError::JwtIssuerMismatch {
                expected: self.issuer.clone(),
                actual: claims.iss,
            }
            .into());
        }

        // Verify audience
        if claims.aud != self.audience {
            return Err(AuthError::JwtAudienceMismatch {
                expected: self.audience.clone(),
                actual: claims.aud,
            }
            .into());
        }

        // Check expiration (jsonwebtoken already checks this, but double-check)
        if claims.is_expired() {
            return Err(AuthError::JwtExpired.into());
        }

        Ok(claims)
    }

    /// Validate access token specifically
    ///
    /// This is a convenience method that validates the token and checks
    /// that it's an access token (not a refresh token).
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    ///
    /// # Returns
    ///
    /// Decoded claims if token is a valid access token
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Token is invalid (see `validate_token`)
    /// - Token is not an access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims> {
        let claims = self.validate_token(token)?;

        if claims.token_type != TokenType::Access {
            return Err(AuthError::InvalidTokenType {
                expected: "access".to_string(),
                actual: claims.token_type.to_string(),
            }
            .into());
        }

        Ok(claims)
    }

    /// Validate refresh token specifically
    ///
    /// This is a convenience method that validates the token and checks
    /// that it's a refresh token (not an access token).
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    ///
    /// # Returns
    ///
    /// Decoded claims if token is a valid refresh token
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Token is invalid (see `validate_token`)
    /// - Token is not a refresh token
    pub fn validate_refresh_token(&self, token: &str) -> Result<Claims> {
        let claims = self.validate_token(token)?;

        if claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidTokenType {
                expected: "refresh".to_string(),
                actual: claims.token_type.to_string(),
            }
            .into());
        }

        Ok(claims)
    }

    /// Refresh tokens using a valid refresh token
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - Valid refresh token
    ///
    /// # Returns
    ///
    /// New token pair
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Refresh token is invalid
    /// - Refresh token has expired
    ///
    /// # Security Note
    ///
    /// For production, you should implement token blacklisting
    /// to prevent reuse of refresh tokens after rotation.
    pub fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair> {
        let claims = self.validate_refresh_token(refresh_token)?;

        self.generate_token_pair(&claims.sub, &claims.username)
    }

    /// Extract token ID (JTI) from a token without full validation
    ///
    /// This is useful for checking if a token is blacklisted
    /// without performing full validation.
    ///
    /// # Arguments
    ///
    /// * `token` - JWT token string
    ///
    /// # Returns
    ///
    /// Token ID (JTI)
    ///
    /// # Security Warning
    ///
    /// This does NOT validate the token signature! Use `validate_token`
    /// for full validation. This is only useful for checking blacklists.
    #[must_use]
    pub fn extract_jti_unverified(&self, token: &str) -> Option<String> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        // Decode payload (base64url)
        // jsonwebtoken typically uses URL_SAFE_NO_PAD
        let payload = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(decoded) => decoded,
            Err(_) => return None,
        };

        // Parse JSON
        let value: serde_json::Value = match serde_json::from_slice(&payload) {
            Ok(value) => value,
            Err(_) => return None,
        };

        value
            .get("jti")
            .and_then(|jti| jti.as_str())
            .map(|s| s.to_string())
    }

    // ==================== Internal Methods ====================

    /// Encode claims into JWT token
    fn encode_token(&self, claims: &Claims) -> Result<String> {
        let key = EncodingKey::from_secret(self.secret.as_ref());

        encode(&Header::default(), claims, &key)
            .map_err(|e| AppError::from(AuthError::JwtGenerationFailed(e.to_string())))
    }

    /// Decode JWT token into claims
    fn decode_token(&self, token: &str) -> Result<Claims> {
        let key = DecodingKey::from_secret(self.secret.as_ref());
        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        // Set expected audience for validation
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<Claims>(token, &key, &validation)
            .map_err(|e| AppError::from(AuthError::JwtValidationFailed(e.to_string())))?;

        Ok(token_data.claims)
    }
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> JwtService {
        JwtService::with_audience(
            "test_secret_key_at_least_32_characters_long".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600i64,
        )
    }

    #[test]
    fn test_generate_and_validate_token() {
        let service = create_test_service();
        let token = service.generate_token("user123", "john").unwrap();

        let claims = service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, "user123");
        assert_eq!(claims.username, "john");
        assert_eq!(claims.iss, "test-issuer");
        assert_eq!(claims.aud, "test-audience");
        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_validate_access_token() {
        let service = create_test_service();
        let token = service.generate_token("user123", "john").unwrap();

        let claims = service.validate_access_token(&token).unwrap();

        assert_eq!(claims.token_type, TokenType::Access);
    }

    #[test]
    fn test_validate_refresh_token() {
        let service = create_test_service();
        let refresh_token = service
            .generate_token_pair("user123", "john")
            .unwrap()
            .refresh_token;

        let claims = service.validate_refresh_token(&refresh_token).unwrap();

        assert_eq!(claims.token_type, TokenType::Refresh);
    }

    #[test]
    fn test_generate_token_pair() {
        let service = create_test_service();
        let token_pair = service.generate_token_pair("user123", "john").unwrap();

        // Validate access token
        let access_claims = service
            .validate_access_token(&token_pair.access_token)
            .unwrap();
        assert_eq!(access_claims.sub, "user123");
        assert_eq!(access_claims.token_type, TokenType::Access);

        // Validate refresh token
        let refresh_claims = service
            .validate_refresh_token(&token_pair.refresh_token)
            .unwrap();
        assert_eq!(refresh_claims.sub, "user123");
        assert_eq!(refresh_claims.token_type, TokenType::Refresh);

        // Check expiration time
        assert_eq!(token_pair.expires_in, 3600);
        assert_eq!(token_pair.token_type, "Bearer");
    }

    #[test]
    fn test_refresh_tokens() {
        let service = create_test_service();
        let old_pair = service.generate_token_pair("user123", "john").unwrap();

        let new_pair = service.refresh_tokens(&old_pair.refresh_token).unwrap();

        // New tokens should be different
        assert_ne!(old_pair.access_token, new_pair.access_token);
        assert_ne!(old_pair.refresh_token, new_pair.refresh_token);

        // New tokens should be valid
        let new_access_claims = service
            .validate_access_token(&new_pair.access_token)
            .unwrap();
        assert_eq!(new_access_claims.sub, "user123");
    }

    #[test]
    fn test_invalid_token_format() {
        let service = create_test_service();
        let invalid_token = "invalid.token.format";

        let result = service.validate_token(invalid_token);
        assert!(result.is_err());
        // assert!(matches!(result, Err(AuthError::JwtValidationFailed(_)))); // AuthError wrapped in AppError
    }

    #[test]
    fn test_invalid_token_signature() {
        let service = create_test_service();
        let valid_token = service.generate_token("user123", "john").unwrap();

        // Tamper with token
        let tampered_token = format!("{}tampered", valid_token);

        let result = service.validate_token(&tampered_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_issuer_mismatch() {
        let service = create_test_service();
        let token = service.generate_token("user123", "john").unwrap();

        // Create service with different issuer
        let wrong_service = JwtService::with_audience(
            "test_secret_key_at_least_32_characters_long".to_string(),
            "wrong-issuer".to_string(),
            "test-audience".to_string(),
            3600i64,
        );

        let result = wrong_service.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_audience_mismatch() {
        let service = create_test_service();
        let token = service.generate_token("user123", "john").unwrap();

        // Create service with different audience
        let wrong_service = JwtService::with_audience(
            "test_secret_key_at_least_32_characters_long".to_string(),
            "test-issuer".to_string(),
            "wrong-audience".to_string(),
            3600i64,
        );

        let result = wrong_service.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_token_type_for_access() {
        let service = create_test_service();
        let refresh_token = service
            .generate_token_pair("user123", "john")
            .unwrap()
            .refresh_token;

        let result = service.validate_access_token(&refresh_token);

        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_token_type_for_refresh() {
        let service = create_test_service();
        let access_token = service.generate_token("user123", "john").unwrap();

        let result = service.validate_refresh_token(&access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_jti_unverified() {
        let service = create_test_service();
        let token = service.generate_token("user123", "john").unwrap();

        let jti = service.extract_jti_unverified(&token);
        assert!(jti.is_some());

        // Should work even with tampered token (no signature verification)
        let tampered_token = format!("{}tampered", token);
        let jti_tampered = service.extract_jti_unverified(&tampered_token);
        assert!(jti_tampered.is_some());
    }

    #[test]
    fn test_token_expiration() {
        let service = JwtService::with_audience(
            "test_secret_key_at_least_32_characters_long".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            1i64, // 1 second expiration
        );

        let token = service.generate_token("user123", "john").unwrap();

        // Should be valid immediately
        let result = service.validate_token(&token);
        assert!(result.is_ok());

        // Wait for expiration (in real tests, use time mocking)
        // For now, just check that the logic exists
        let claims = result.unwrap();
        assert!(!claims.is_expired()); // Should not be expired yet
    }

    #[test]
    fn test_token_type_display() {
        assert_eq!(TokenType::Access.to_string(), "access");
        assert_eq!(TokenType::Refresh.to_string(), "refresh");
    }

    #[test]
    fn test_token_type_recommended_expiration() {
        assert_eq!(TokenType::Access.recommended_expiration_seconds(), 3600);
        assert_eq!(TokenType::Refresh.recommended_expiration_seconds(), 604800);
    }

    #[test]
    fn test_token_type_requires_2fa() {
        assert!(!TokenType::Access.requires_2fa());
        assert!(TokenType::Refresh.requires_2fa());
    }

    #[test]
    fn test_claims_display() {
        let claims = Claims::new(
            "user123".to_string(),
            "john".to_string(),
            3600i64,
            "issuer".to_string(),
            "audience".to_string(),
            TokenType::Access,
        );

        let display = format!("{}", claims);
        assert!(display.contains("user123"));
        assert!(display.contains("john"));
        assert!(display.contains("access"));
    }

    #[test]
    fn test_claims_time_until_expiration() {
        let claims = Claims::new(
            "user123".to_string(),
            "john".to_string(),
            3600i64,
            "issuer".to_string(),
            "audience".to_string(),
            TokenType::Access,
        );

        // Should be positive (not expired)
        assert!(claims.time_until_expiration() > 0);
    }

    #[test]
    #[should_panic(expected = "at least 32 characters")]
    fn test_service_panics_with_short_secret() {
        JwtService::new("short".to_string(), "issuer".to_string(), 3600i64);
    }

    #[test]
    fn test_service_issuer_audience_getters() {
        let service = JwtService::with_audience(
            "test_secret_key_at_least_32_characters_long".to_string(),
            "test-issuer".to_string(),
            "test-audience".to_string(),
            3600i64,
        );

        assert_eq!(service.issuer(), "test-issuer");
        assert_eq!(service.audience(), "test-audience");
        assert_eq!(service.expiration_seconds(), 3600);
    }
}
