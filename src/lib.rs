//! # EYWA Authentication Module
//!
//! EYWA (The Great Mother) Authentication - A comprehensive authentication library for HomeManager.
//!
//! This crate provides JWT-based authentication with support for:
//! - JWT token generation and validation
//! - Secure password hashing with Argon2id
//! - TOTP-based two-factor authentication (Google Authenticator compatible)
//! - Axum middleware for route protection
//! - Input validation and security utilities
//!
//! ## Architecture
//!
//! EYWA Authentication follows a modular, stateless architecture perfect for microservices:
//!
//! ```text
//! ┌─────────────────────────────────────────┐
//! │         Application Layer                │
//! │     (auth-service, gateway-service)     │
//! └──────────────┬──────────────────────────┘
//!               │
//! ┌──────────────▼──────────────────────────┐
//! │      EYWA Authentication Layer          │
//! │ │  ┌────────────────────────────────────┐  │
//! │  │  JWT Service                      │  │
//! │  │  - Token generation              │  │
//! │  │  - Token validation               │  │
//! │  │  - Stateless (no storage!)        │  │
//! │  └────────────────────────────────────┘  │
//! │  ┌────────────────────────────────────┐  │
//! │  │  Password Service                 │  │
//! │  │  - Argon2id hashing              │  │
//! │  │  - Password validation           │  │
//! │  │  - Security policies             │  │
//! │  └────────────────────────────────────┘  │
//! │  ┌────────────────────────────────────┐  │
//! │  │  TOTP Service (2FA)               │  │
//! │  │  - Generate secrets              │  │
//! │  │  - Validate codes                │  │
//! │  │  - QR code generation            │  │
//! │  └────────────────────────────────────┘  │
//! │  ┌────────────────────────────────────┐  │
//! │  │  Middleware                       │  │
//! │  │  - JWT validation                │  │
//! │  │  - Security headers              │  │
//! │  │  - Rate limiting                 │  │
//! │  └────────────────────────────────────┘  │
//! └─────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ### 1. JWT Authentication
//!
//! ```no_run
//! use eywa_authentication::JwtService;
//!
//! let service = JwtService::new(
//!     "your_secret_key_at_least_64_characters_long_for_security!!!".to_string(),
//!     "homemanager".to_string(),  // issuer
//!     3600i64,                    // expiration in seconds (1 hour)
//! );
//!
//! // Generate token
//! let token = service.generate_token("user_123", "john_doe").unwrap();
//!
//! // Validate token
//! let claims = service.validate_token(&token).unwrap();
//! println!("User ID: {}", claims.sub);
//! ```
//!
//! ### 2. Password Hashing
//!
//! ```no_run
//! use eywa_authentication::PasswordService;
//!
//! // Hash password
//! let hash = PasswordService::hash_password("secure_password_123!").unwrap();
//!
//! // Verify password
//! let is_valid = PasswordService::verify_password("secure_password_123!", &hash).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ### 3. TOTP Two-Factor Authentication
//!
//! ```no_run
//! use eywa_authentication::TotpService;
//!
//! // Generate secret for user
//! let secret = TotpService::generate_secret().unwrap();
//!
//! // Generate QR code for Google Authenticator
//! let qr_code = TotpService::generate_qr_code("john_doe", &secret).unwrap();
//!
//! // Verify TOTP code
//! let is_valid = TotpService::verify_code(&secret, "123456").unwrap();
//! ```
//!
//! ### 4. Axum Middleware
//!
//! ```no_run
//! use axum::{Router, routing::get};
//! use eywa_authentication::auth_middleware;
//!
//! let app = Router::new()
//!     .route("/protected", get(protected_handler))
//!     .route_layer(axum::middleware::from_fn_with_state(
//!         jwt_service.clone(),
//!         auth_middleware,
//!     ));
//! ```
//!
//! ## Features
//!
//! - **`qr`** (default): Enable QR code generation for TOTP setup
//! - **`rate-limit`**: Enable rate limiting utilities
//! - **`advanced-security`**: Enable advanced security features
//!
//! ## Security
//!
//! This crate follows security best practices:
//!
//! - **Argon2id** for password hashing (resistant to GPU/ASIC attacks)
//! - **HS256** for JWT signing (use RS256 for production if you need asymmetric keys)
//! - **TOTP** for 2FA with SHA-1 (RFC 6238 compliant)
//! - **Input validation** to prevent injection attacks
//! - **Security headers** for web applications
//!
//! ## Naming Convention
//!
//! Named after **EYWA** from James Cameron's Avatar - the Great Mother that connects everything.
//! Just as Eywa connects all life on Pandora, this authentication module connects all services
//! in the HomeManager ecosystem.
//!
//! ## License
//!
//! MIT License - See LICENSE file for details

// Core modules
pub mod config;
pub mod error;
pub mod jwt;
pub mod middleware;
pub mod password;
pub mod ratelimit;
pub mod totp;
pub mod validation;

// Re-export from eywa-errors ( centralized error handling)
pub use eywa_errors::AppError;

// Re-export authentication-specific errors
pub use error::AuthError;

// Result type alias that uses AppError
pub type Result<T> = std::result::Result<T, AppError>;

// Re-exports for convenience

// JWT
pub use jwt::{Claims, JwtService, TokenPair, TokenType};

// Password
pub use password::{
    PasswordPolicy, PasswordService, calculate_password_strength, hash_password, verify_password,
};

// TOTP
pub use totp::{TotpService, generate_qr_code, generate_totp_secret, verify_totp_code};

// Middleware
pub use middleware::{
    AuthExtractor, auth_middleware, rate_limit_middleware, security_headers_middleware,
};

// Rate Limiting
pub use ratelimit::{RateLimitError, RateLimiter};

// Validation
pub use validation::{
    sanitize_string, validate_email, validate_safe_string, validate_username, validate_uuid,
};

// Configuration
pub use config::{AuthConfig, JwtConfig, PasswordConfig, TotpConfig};

// For backward compatibility (using EywaResult as alias)
pub type EywaResult<T> = Result<T>;

// Prelude for easy imports
pub mod prelude {
    pub use crate::{
        // Errors
        AppError,
        // Configuration
        AuthConfig,
        AuthError,
        // JWT
        Claims,
        // Services
        JwtService,
        PasswordPolicy,

        PasswordService,

        Result,
        TokenType,

        TotpService,

        // Middleware
        auth_middleware,
        generate_qr_code,
        // TOTP
        generate_totp_secret,
        // Password
        hash_password,

        security_headers_middleware,

        // Validation
        validate_email,
        validate_username,
        validate_uuid,

        verify_password,
        verify_totp_code,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prelude_import() {
        // Verify prelude works
        use crate::prelude::*;

        let secret = "test_secret_at_least_32_characters_long";
        let service = JwtService::new(secret.to_string(), "test".to_string(), 3600);
        assert_eq!(service.issuer(), "test");
    }
}
