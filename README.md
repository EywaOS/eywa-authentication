# EYWA Authentication 🔒

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.70+--orange.svg)](https://www.rust-lang.org/)
[![Docs](https://img.shields.io/badge/Docs-Latest-green.svg)](https://docs.rs/eywa-authentication)

**EYWA Authentication** - A comprehensive, production-ready authentication library for Rust applications, inspired by James Cameron's Avatar universe.

> *"Eywa, the Great Mother, connects all life on Pandora. Just as Eywa connects all life, this authentication module connects all services in your application."*

## 🌟 Features

- **JWT Authentication**: Stateless JSON Web Tokens with configurable expiration
- **Secure Password Hashing**: Argon2id (OWASP recommended) with configurable parameters
- **Two-Factor Authentication (2FA)**: TOTP support compatible with Google Authenticator, Authy, etc.
- **Axum Middleware**: Ready-to-use middleware for route protection and security headers
- **Input Validation**: Comprehensive validation for emails, usernames, UUIDs, URLs, and more
- **Rate Limiting**: In-memory rate limiting for brute force protection
- **Security Best Practices**: HSTS, CSP, CSRF protection, XSS prevention
- **Zero-Configuration Defaults**: Sensible defaults out of the box
- **Production Ready**: Built for security, performance, and reliability

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
eywa-authentication = "0.1.0"
```

### Features

```toml
[dependencies]
eywa-authentication = { version = "0.1.0", features = ["qr"] }
```

Available features:
- `qr`: Enable QR code generation for TOTP setup (default: enabled)
- `rate-limit`: Enable rate limiting utilities
- `advanced-security`: Enable advanced security features

## 🚀 Quick Start

### 1. JWT Authentication

```rust
use eywa_authentication::prelude::*;
use axum::{Router, routing::get, Json};
use std::sync::Arc;

// Create JWT service
let jwt_service = JwtService::new(
    "your_secret_key_at_least_64_characters_long_for_security!!!".to_string(),
    "eywa-auth".to_string(),
    3600i64, // 1 hour expiration
);

// Generate token
let token = jwt_service.generate_token("user_123", "john_doe").unwrap();
println!("Token: {}", token);

// Validate token
let claims = jwt_service.validate_token(&token).unwrap();
println!("User: {}", claims.username);

// Use in Axum router
let app = Router::new()
    .route("/protected", get(protected_handler))
    .route_layer(axum::middleware::from_fn_with_state(
        Arc::new(jwt_service),
        auth_middleware,
    ));
```

### 2. Password Hashing

```rust
use eywa_authentication::prelude::*;

// Hash password (Argon2id)
let hash = PasswordService::hash_password("SecurePassword123!").unwrap();
println!("Hash: {}", hash);

// Verify password
let is_valid = PasswordService::verify_password("SecurePassword123!", &hash).unwrap();
assert!(is_valid);

// Validate password against policy
let policy = PasswordPolicy::default();
PasswordService::validate_password("SecurePassword123!", &policy).unwrap();
```

### 3. TOTP Two-Factor Authentication

```rust
use eywa_authentication::prelude::*;

// Generate TOTP secret for user
let totp_service = TotpService::new();
let secret = totp_service.generate_secret().unwrap();
println!("Secret: {}", secret);

// Generate QR code for Google Authenticator
let qr_code = totp_service.generate_qr_code("john_doe", &secret).unwrap();
println!("QR Code: {}", qr_code);

// Verify TOTP code
let is_valid = totp_service.verify_code(&secret, "123456").unwrap();
assert!(is_valid);
```

### 4. Input Validation

```rust
use eywa_authentication::prelude::*;

// Validate email
validate_email("user@example.com").unwrap();

// Validate username
validate_username("john_doe").unwrap();

// Validate UUID
validate_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();

// Validate safe string (XSS prevention)
validate_safe_string("Hello, World!").unwrap();

// Sanitize input
let sanitized = sanitize_string("<script>alert('xss')</script>Hello");
assert!(!sanitized.contains("<script>"));
```

## 📚 Detailed Usage

### JWT Service

#### Creating a JWT Service

```rust
use eywa_authentication::{JwtService, TokenPair};

// Basic configuration
let jwt_service = JwtService::new(
    "secret_key_min_32_chars".to_string(),
    "your-app-name".to_string(),
    3600i64, // 1 hour
);

// With custom audience
let jwt_service = JwtService::with_audience(
    "secret_key_min_32_chars".to_string(),
    "your-app-name".to_string(),
    "your-api-name".to_string(),
    3600i64,
);
```

#### Generating Tokens

```rust
// Single access token
let token = jwt_service.generate_token("user_123", "john").unwrap();

// Token pair (access + refresh)
let token_pair = jwt_service.generate_token_pair("user_123", "john").unwrap();
println!("Access: {}", token_pair.access_token);
println!("Refresh: {}", token_pair.refresh_token);
```

#### Validating Tokens

```rust
// Validate any token
let claims = jwt_service.validate_token(&token).unwrap();

// Validate access token specifically
let claims = jwt_service.validate_access_token(&token).unwrap();

// Validate refresh token specifically
let claims = jwt_service.validate_refresh_token(&token).unwrap();

// Refresh tokens
let new_pair = jwt_service.refresh_tokens(&refresh_token).unwrap();
```

### Password Service

#### Default Password Policy

```rust
use eywa_authentication::{PasswordService, PasswordPolicy};

let policy = PasswordPolicy::default();
// - Minimum 12 characters
// - Requires uppercase, lowercase, numbers, special chars
// - Minimum strength score: 70/100
// - Uses Argon2id

let service = PasswordService::with_policy(policy);
let hash = service.hash_password("SecurePass123!").unwrap();
```

#### Custom Password Policy

```rust
use eywa_authentication::{PasswordService, PasswordPolicy, HashingAlgorithm, Argon2Params};

let policy = PasswordPolicy {
    min_length: 16,
    max_length: 128,
    require_uppercase: true,
    require_lowercase: true,
    require_numbers: true,
    require_special_chars: true,
    min_strength_score: 85,
    hashing_algorithm: HashingAlgorithm::Argon2id,
    argon2_params: Some(Argon2Params {
        t_cost: 4,
        m_cost: 65536, // 64 MB
        parallelism: 2,
        output_length: 32,
    }),
};

let service = PasswordService::with_policy(policy);
```

#### Password Strength Scoring

```rust
use eywa_authentication::calculate_password_strength;

let score = calculate_password_strength("MySecure#Pass123!");
println!("Strength: {}/100", score);

// Scores:
// 0-30: Very Weak
// 31-50: Weak
// 51-70: Moderate
// 71-85: Strong
// 86-100: Very Strong
```

### TOTP Service

#### TOTP Configuration

```rust
use eywa_authentication::{TotpService, TotpConfig};

// Default settings (6 digits, 30 seconds, SHA1)
let service = TotpService::new();

// Custom configuration
let config = TotpConfig::with_issuer("MyApp");
let service = TotpService::with_config(config);
```

#### Setting Up 2FA

```rust
use eywa_authentication::TotpService;

let service = TotpService::new();

// 1. Generate secret
let secret = service.generate_secret().unwrap();

// 2. Generate QR code
let qr_code = service.generate_qr_code("john_doe", &secret).unwrap();

// 3. Show QR code to user (for scanning with authenticator app)
println!("Scan this QR code with Google Authenticator:");
println!("{}", qr_code);

// 4. User enters code from app to verify setup
let code = "123456"; // User input
let is_valid = service.verify_code(&secret, code).unwrap();

if is_valid {
    // Save secret to database for user
    // user.totp_secret = secret;
    // user.totp_enabled = true;
}
```

#### Verifying 2FA on Login

```rust
// User logs in with username/password
// Then enters TOTP code
let totp_code = "123456"; // From authenticator app
let is_valid = service.verify_code(&user.totp_secret, totp_code).unwrap();

if is_valid {
    // Login successful
} else {
    // Invalid code
}
```

### Middleware

#### Authentication Middleware

```rust
use axum::{Router, routing::get, extract::State};
use eywa_authentication::{JwtService, auth_middleware, AuthExtractor};
use std::sync::Arc;

let jwt_service = Arc::new(JwtService::new(
    "secret".to_string(),
    "app".to_string(),
    3600i64,
));

let app = Router::new()
    .route("/protected", get(handler))
    .route_layer(axum::middleware::from_fn_with_state(
        jwt_service.clone(),
        auth_middleware,
    ));

// Handler automatically gets claims
async fn handler(auth: AuthExtractor) -> String {
    format!("Hello, {}!", auth.claims.username)
}
```

#### Security Headers Middleware

```rust
use eywa_authentication::security_headers_middleware;

let app = Router::new()
    .route("/", get(handler))
    .layer(axum::middleware::from_fn(security_headers_middleware));

// This automatically adds:
// - Strict-Transport-Security (HSTS)
// - X-Content-Type-Options
// - X-Frame-Options
// - X-XSS-Protection
// - Content-Security-Policy (CSP)
// - Referrer-Policy
// - Permissions-Policy
```

#### Rate Limiting Middleware

```rust
use eywa_authentication::{RateLimiter, rate_limit_middleware};
use std::time::Duration;
use std::sync::Arc;

let limiter = Arc::new(RateLimiter::new(
    100, // max requests
    Duration::from_secs(60), // 1 minute window
));

let app = Router::new()
    .route("/api", get(handler))
    .route_layer(axum::middleware::from_fn_with_state(
        limiter.clone(),
        rate_limit_middleware,
    ));
```

### Validation

```rust
use eywa_authentication::prelude::*;

// Email validation
validate_email("user@example.com").unwrap();

// Username validation (3-30 chars, alphanumeric, underscore, hyphen)
validate_username("john_doe").unwrap();

// UUID validation
validate_uuid("550e8400-e29b-41d4-a716-446655440000").unwrap();

// Phone validation (E.164 format)
validate_phone("+1234567890").unwrap();

// URL validation
validate_url("https://example.com").unwrap();

// Safe string validation (XSS prevention)
validate_safe_string("Hello, World!").unwrap();

// Sanitize string
let clean = sanitize_string("<script>alert('xss')</script>Hello");

// Combined validation
validate_login("john_doe", "password123").unwrap();
validate_registration("john_doe", "user@example.com", "password123").unwrap();
validate_profile("John Doe", "user@example.com", Some("+1234567890")).unwrap();
```

## 🔐 Security Considerations

### JWT Security

- ✅ **Secret Key**: Use at least 64 characters in production
- ✅ **Expiration**: Keep access tokens short (1 hour or less)
- ✅ **HTTPS**: Always transmit tokens over HTTPS
- ✅ **Refresh Tokens**: Rotate refresh tokens regularly
- ✅ **Issuer/Audience**: Validate on every request

### Password Security

- ✅ **Argon2id**: Use Argon2id (OWASP recommended)
- ✅ **Parameters**: Tune parameters for your hardware
  - Development: t_cost=3, m_cost=32768 (32 MB)
  - Production: t_cost=4, m_cost=65536 (64 MB)
- ✅ **Password Policy**: Enforce strong passwords
- ✅ **No Plaintext**: Never store plaintext passwords

### TOTP Security

- ✅ **Time Skew**: Limit to 1-2 steps (30-60 seconds)
- ✅ **Secret Storage**: Encrypt secrets at rest in database
- ✅ **Backup Codes**: Provide backup codes for recovery
- ✅ **Rate Limiting**: Limit TOTP verification attempts

### General Security

- ✅ **HTTPS Required**: Never transmit sensitive data over HTTP
- ✅ **Security Headers**: Use security headers middleware
- ✅ **Input Validation**: Validate all inputs
- ✅ **Rate Limiting**: Prevent brute force attacks
- ✅ **CSRF Protection**: Implement CSRF tokens for web forms
- ✅ **CORS**: Configure CORS properly
- ✅ **Logging**: Log security events
- ✅ **Monitoring**: Monitor for suspicious activity

## 📖 API Reference

### Core Types

#### `JwtService`
```rust
pub struct JwtService {
    // Create new service
    pub fn new(secret: String, issuer: String, expiration_seconds: i64) -> Self;
    
    // Generate access token
    pub fn generate_token(&self, user_id: &str, username: &str) -> Result<String>;
    
    // Generate token pair
    pub fn generate_token_pair(&self, user_id: &str, username: &str) -> Result<TokenPair>;
    
    // Validate token
    pub fn validate_token(&self, token: &str) -> Result<Claims>;
    
    // Validate access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims>;
    
    // Refresh tokens
    pub fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenPair>;
}
```

#### `PasswordService`
```rust
pub struct PasswordService {
    // Create with default policy
    pub fn new() -> Self;
    
    // Create with custom policy
    pub fn with_policy(policy: PasswordPolicy) -> Self;
    
    // Hash password
    pub fn hash_password(&self, password: &str) -> Result<String>;
    
    // Verify password
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool>;
    
    // Validate password
    pub fn validate_password(&self, password: &str) -> Result<()>;
}
```

#### `TotpService`
```rust
pub struct TotpService {
    // Create with default settings
    pub fn new() -> Self;
    
    // Generate secret
    pub fn generate_secret(&self) -> Result<String>;
    
    // Verify code
    pub fn verify_code(&self, secret: &str, code: &str) -> Result<bool>;
    
    // Generate QR code
    pub fn generate_qr_code(&self, username: &str, secret: &str) -> Result<String>;
}
```

#### `RateLimiter`
```rust
pub struct RateLimiter {
    // Create new limiter
    pub fn new(max_requests: u32, window_duration: Duration) -> Self;
    
    // Check if allowed
    pub async fn check(&self, key: &str) -> Result<(), RateLimitError>;
    
    // Get remaining
    pub async fn remaining(&self, key: &str) -> u32;
}
```

### Configuration

#### Environment Variables

```bash
# JWT Configuration
JWT_SECRET=your_secret_key_at_least_64_characters_long
JWT_EXPIRATION=3600              # 1 hour
JWT_ISSUER=eywa-auth
JWT_AUDIENCE=eywa-api

# Password Policy
PASSWORD_MIN_LENGTH=12
PASSWORD_MAX_LENGTH=128
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_MIN_STRENGTH=70
PASSWORD_HASH_ALGORITHM=argon2id

# TOTP Configuration
TOTP_DIGITS=6
TOTP_TIME_STEP=30
TOTP_TIME_SKEW=1
TOTP_ISSUER=EYWA+Auth
TOTP_ALGORITHM=sha1

# Rate Limiting
RATE_LIMIT_MAX_REQUESTS=100
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_MAX_LOGIN_ATTEMPTS=5
RATE_LIMIT_LOCKOUT_SECONDS=900     # 15 minutes

# Features
REQUIRE_2FA=false
PRODUCTION=false
```

## 🧪 Testing

Run tests:

```bash
cargo test
```

Run tests with output:

```bash
cargo test -- --nocapture
```

Run specific test:

```bash
cargo test test_generate_and_validate_token
```

## 📝 Examples

See the `examples/` directory for complete examples:

- `simple_jwt.rs`: Basic JWT usage
- `password_hashing.rs`: Password hashing examples
- `totp_setup.rs`: TOTP 2FA setup
- `axum_integration.rs`: Full Axum integration
- `advanced_security.rs`: Advanced security features

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Write tests
5. Ensure all tests pass (`cargo test`)
6. Format code (`cargo fmt`)
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by James Cameron's Avatar universe
- Built with awesome Rust crates:
  - `jsonwebtoken`: JWT implementation
  - `argon2`: Password hashing
  - `totp-rs`: TOTP implementation
  - `axum`: Web framework
  - Many others...

## 📞 Support

- GitHub Issues: [Create an issue](https://github.com/yourusername/eywa-authentication/issues)
- Documentation: [Docs.rs](https://docs.rs/eywa-authentication)
- Examples: [Examples](https://github.com/yourusername/eywa-authentication/tree/main/examples)

## 🌌 EYWA Lore

> *"The Great Mother, Eywa, connects all life on Pandora through the Tree of Souls. Every living being is connected to every other living being through the network of Eywa."*

Just as Eywa connects all life on Pandora, the EYWA Authentication module connects all services in your application through secure authentication. Whether it's JWT tokens, password hashing, or TOTP 2FA, Eywa ensures that only authorized souls can access your sacred resources.

**May Eywa guide your authentication journey.** 🌿