//! # Configuration for EYWA Authentication
//!
//! This module provides configuration structures for all authentication services:
//! - JWT configuration (secret, expiration, issuer, audience)
//! - Password policy (length, complexity, hashing algorithm)
//! - TOTP configuration (digits, algorithm, window)
//!
//! ## Example
//!
//! ```no_run
//! use eywa_authentication::AuthConfig;
//!
//! // Load from environment variables
//! let config = AuthConfig::from_env().unwrap();
//!
//! // Validate configuration
//! config.validate().unwrap();
//!
//! // Access sub-configurations
//! let jwt_config = &config.jwt;
//! let password_policy = &config.password;
//! let totp_config = &config.totp;
//! ```

use serde::{Deserialize, Serialize};

// ==================== JWT Configuration ====================

/// JWT (JSON Web Token) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Secret key for signing JWT tokens (MIN 64 characters for production!)
    ///
    /// # Security
    /// - Must be at least 64 characters long for production
    /// - Use a cryptographically secure random string
    /// - Keep this secret! Never commit to version control
    /// - Rotate regularly in production
    ///
    /// # Example
    /// ```bash
    /// # Generate secure secret
    /// openssl rand -base64 64
    /// ```
    pub secret: String,

    /// Token expiration time in seconds
    ///
    /// # Recommended Values
    /// - Access tokens: 3600 (1 hour) - 86400 (1 day)
    /// - Refresh tokens (if used): 604800 (7 days) - 2592000 (30 days)
    ///
    /// # Security Trade-off
    /// - Shorter expiration = more secure but requires more frequent logins
    /// - Longer expiration = better UX but higher risk if token is compromised
    pub expiration_seconds: i64,

    /// Issuer claim for JWT tokens
    ///
    /// This identifies the principal that issued the JWT.
    /// Should be unique to your application.
    ///
    /// # Example
    /// ```text
    /// issuer = "homemanager-auth" or "your-app-name"
    /// ```
    pub issuer: String,

    /// Audience claim for JWT tokens
    ///
    /// This identifies the recipients that the JWT is intended for.
    ///
    /// # Example
    /// ```text
    /// audience = "homemanager-api" or "your-api-name"
    /// ```
    pub audience: String,
}

impl JwtConfig {
    /// Create a new JWT configuration with default values
    ///
    /// # Panics
    /// Panics if secret is too short (less than 32 characters)
    #[must_use]
    pub fn new(
        secret: impl Into<String>,
        issuer: impl Into<String>,
        expiration_seconds: i64,
    ) -> Self {
        let secret = secret.into();

        // Validate minimum length
        if secret.len() < 32 {
            panic!(
                "JWT secret must be at least 32 characters (got {} characters)",
                secret.len()
            );
        }

        Self {
            secret,
            expiration_seconds,
            issuer: issuer.into(),
            audience: "default".to_string(),
        }
    }

    /// Create a new JWT configuration with audience
    #[must_use]
    pub fn with_audience(
        secret: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        expiration_seconds: i64,
    ) -> Self {
        let mut config = Self::new(secret, issuer, expiration_seconds);
        config.audience = audience.into();
        config
    }

    /// Load JWT configuration from environment variables
    ///
    /// # Environment Variables
    /// - `JWT_SECRET`: Secret key (required)
    /// - `JWT_EXPIRATION`: Expiration in seconds (default: 3600)
    /// - `JWT_ISSUER`: Issuer claim (default: "eywa-auth")
    /// - `JWT_AUDIENCE`: Audience claim (default: "eywa-api")
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            secret: std::env::var("JWT_SECRET").map_err(|_| {
                ConfigError::MissingRequiredConfig {
                    key: "JWT_SECRET".to_string(),
                }
            })?,
            expiration_seconds: std::env::var("JWT_EXPIRATION")
                .unwrap_or_else(|_| "3600".to_string())
                .parse()
                .map_err(
                    |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                        key: "JWT_EXPIRATION".to_string(),
                        reason: e.to_string(),
                    },
                )?,
            issuer: std::env::var("JWT_ISSUER").unwrap_or_else(|_| "eywa-auth".to_string()),
            audience: std::env::var("JWT_AUDIENCE").unwrap_or_else(|_| "eywa-api".to_string()),
        })
    }

    /// Validate JWT configuration
    ///
    /// # Errors
    /// Returns error if:
    /// - Secret is too short (< 64 characters for production safety)
    /// - Expiration is too short (< 300 seconds / 5 minutes)
    /// - Issuer is empty
    /// - Audience is empty
    pub fn validate(&self, production: bool) -> Result<(), ConfigError> {
        let min_length = if production { 64 } else { 32 };

        if self.secret.len() < min_length {
            return Err(ConfigError::InvalidConfigValue {
                key: "JWT_SECRET".to_string(),
                reason: format!(
                    "must be at least {} characters (got {})",
                    min_length,
                    self.secret.len()
                ),
            });
        }

        if self.expiration_seconds < 300 {
            return Err(ConfigError::InvalidConfigValue {
                key: "JWT_EXPIRATION".to_string(),
                reason: "must be at least 300 seconds (5 minutes)".to_string(),
            });
        }

        if self.issuer.is_empty() {
            return Err(ConfigError::InvalidConfigValue {
                key: "JWT_ISSUER".to_string(),
                reason: "cannot be empty".to_string(),
            });
        }

        if self.audience.is_empty() {
            return Err(ConfigError::InvalidConfigValue {
                key: "JWT_AUDIENCE".to_string(),
                reason: "cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

// ==================== Password Configuration ====================

/// Password policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordConfig {
    /// Minimum password length
    ///
    /// # Recommendation
    /// - Development: 8 characters
    /// - Production: 12+ characters
    ///
    /// # Security Note
    /// Longer passwords are exponentially stronger against brute force attacks
    pub min_length: usize,

    /// Maximum password length (for database storage limits)
    ///
    /// # Typical Values
    /// - 64-128 characters is usually sufficient
    pub max_length: usize,

    /// Require at least one uppercase letter
    pub require_uppercase: bool,

    /// Require at least one lowercase letter
    pub require_lowercase: bool,

    /// Require at least one digit (0-9)
    pub require_numbers: bool,

    /// Require at least one special character (!@#$%^&* etc.)
    pub require_special_chars: bool,

    /// Minimum password strength score (0-100)
    ///
    /// # Scoring
    /// Passwords are scored based on:
    /// - Length (longer = higher score)
    /// - Character variety (uppercase, lowercase, numbers, special chars)
    /// - Absence of common patterns
    ///
    /// # Recommended Thresholds
    /// - 60: Weak
    /// - 70: Moderate
    /// - 80: Strong
    /// - 90+: Very Strong
    pub min_strength_score: u32,

    /// Hashing algorithm to use
    pub hashing_algorithm: HashingAlgorithm,

    /// Argon2 parameters (if using Argon2)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argon2_params: Option<Argon2Params>,
}

/// Password hashing algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HashingAlgorithm {
    /// Argon2id (recommended) - Best overall security
    Argon2id,

    /// Argon2i - Optimized against side-channel attacks
    Argon2i,

    /// Argon2d - Optimized against GPU cracking attacks
    Argon2d,

    /// Bcrypt - Good, but less resistant to GPU/ASIC attacks than Argon2
    Bcrypt,

    /// PBKDF2 - NIST approved, but slower than Argon2/Bcrypt
    Pbkdf2,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            min_strength_score: 70,
            hashing_algorithm: HashingAlgorithm::Argon2id,
            argon2_params: Some(Argon2Params::default()),
        }
    }
}

/// Argon2 parameters for password hashing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Time cost (iterations)
    ///
    /// # Recommended Values
    /// - Development: 2-3
    /// - Production: 3-4 (adjust based on hardware)
    ///
    /// # Performance Impact
    /// Higher values = more secure but slower
    pub t_cost: u32,

    /// Memory cost (in KiB)
    ///
    /// # Recommended Values
    /// - Development: 16384 (16 MB)
    /// - Production: 32768-65536 (32-64 MB)
    ///
    /// # Memory Impact
    /// Higher values = more secure but uses more memory
    pub m_cost: u32,

    /// Parallelism (number of threads/lanes)
    ///
    /// # Recommended Values
    /// - Usually 1-4
    /// - Set to number of CPU cores available
    pub parallelism: u32,

    /// Output length (in bytes)
    ///
    /// # Recommendation
    /// - 32 bytes (256 bits) is standard and secure
    pub output_length: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            t_cost: 3,
            m_cost: 32768, // 32 MB
            parallelism: 1,
            output_length: 32,
        }
    }
}

impl PasswordConfig {
    /// Create a new password configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load password configuration from environment variables
    ///
    /// # Environment Variables
    /// - `PASSWORD_MIN_LENGTH`: Minimum length (default: 12)
    /// - `PASSWORD_MAX_LENGTH`: Maximum length (default: 128)
    /// - `PASSWORD_REQUIRE_UPPERCASE`: Require uppercase (default: true)
    /// - `PASSWORD_REQUIRE_LOWERCASE`: Require lowercase (default: true)
    /// - `PASSWORD_REQUIRE_NUMBERS`: Require numbers (default: true)
    /// - `PASSWORD_REQUIRE_SPECIAL`: Require special chars (default: true)
    /// - `PASSWORD_MIN_STRENGTH`: Minimum strength score (default: 70)
    /// - `PASSWORD_HASH_ALGORITHM`: Hashing algorithm (default: argon2id)
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        config.min_length = std::env::var("PASSWORD_MIN_LENGTH")
            .unwrap_or_else(|_| config.min_length.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "PASSWORD_MIN_LENGTH".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.max_length = std::env::var("PASSWORD_MAX_LENGTH")
            .unwrap_or_else(|_| config.max_length.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "PASSWORD_MAX_LENGTH".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.require_uppercase = std::env::var("PASSWORD_REQUIRE_UPPERCASE")
            .unwrap_or_else(|_| config.require_uppercase.to_string())
            .parse()
            .unwrap_or(config.require_uppercase);

        config.require_lowercase = std::env::var("PASSWORD_REQUIRE_LOWERCASE")
            .unwrap_or_else(|_| config.require_lowercase.to_string())
            .parse()
            .unwrap_or(config.require_lowercase);

        config.require_numbers = std::env::var("PASSWORD_REQUIRE_NUMBERS")
            .unwrap_or_else(|_| config.require_numbers.to_string())
            .parse()
            .unwrap_or(config.require_numbers);

        config.require_special_chars = std::env::var("PASSWORD_REQUIRE_SPECIAL")
            .unwrap_or_else(|_| config.require_special_chars.to_string())
            .parse()
            .unwrap_or(config.require_special_chars);

        config.min_strength_score = std::env::var("PASSWORD_MIN_STRENGTH")
            .unwrap_or_else(|_| config.min_strength_score.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "PASSWORD_MIN_STRENGTH".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.hashing_algorithm = match std::env::var("PASSWORD_HASH_ALGORITHM")
            .unwrap_or_else(|_| "argon2id".to_string())
            .to_lowercase()
            .as_str()
        {
            "argon2id" => HashingAlgorithm::Argon2id,
            "argon2i" => HashingAlgorithm::Argon2i,
            "argon2d" => HashingAlgorithm::Argon2d,
            "bcrypt" => HashingAlgorithm::Bcrypt,
            "pbkdf2" => HashingAlgorithm::Pbkdf2,
            other => {
                return Err(ConfigError::InvalidConfigValue {
                    key: "PASSWORD_HASH_ALGORITHM".to_string(),
                    reason: format!("unknown algorithm: {}", other),
                });
            }
        };

        Ok(config)
    }

    /// Validate password configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.min_length < 8 {
            return Err(ConfigError::InvalidConfigValue {
                key: "PASSWORD_MIN_LENGTH".to_string(),
                reason: "must be at least 8 characters".to_string(),
            });
        }

        if self.max_length < self.min_length {
            return Err(ConfigError::InvalidConfigValue {
                key: "PASSWORD_MAX_LENGTH".to_string(),
                reason: "must be greater than min_length".to_string(),
            });
        }

        if self.min_strength_score > 100 {
            return Err(ConfigError::InvalidConfigValue {
                key: "PASSWORD_MIN_STRENGTH".to_string(),
                reason: "must be between 0 and 100".to_string(),
            });
        }

        Ok(())
    }
}

// ==================== TOTP Configuration ====================

/// TOTP (Time-based One-Time Password) configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Number of digits in TOTP code
    ///
    /// # Standard Values
    /// - 6 digits: RFC 6238 standard (most common)
    /// - 8 digits: More secure but less user-friendly
    ///
    /// # Recommendation
    /// Use 6 digits for compatibility with all authenticator apps
    pub digits: u32,

    /// Time step in seconds (how often the code changes)
    ///
    /// # Standard Value
    /// - 30 seconds: RFC 6238 standard
    ///
    /// # Security vs Usability
    /// - Shorter: More secure but less user-friendly
    /// - Longer: More user-friendly but less secure
    pub time_step: u64,

    /// Time skew tolerance (number of steps before/after to accept)
    ///
    /// # Recommended Values
    /// - 0: Strict (no tolerance)
    /// - 1: Recommended (accepts 1 step before/after)
    /// - 2: More lenient (accepts 2 steps before/after)
    ///
    /// # Security Note
    /// Higher values = more vulnerable to replay attacks
    pub time_skew: u32,

    /// Issuer name for TOTP (appears in authenticator app)
    ///
    /// # Example
    /// ```text
    /// issuer = "HomeManager" or "YourAppName"
    /// ```
    pub issuer: String,

    /// Algorithm for TOTP (RFC 6238 specifies SHA1, SHA256, or SHA512)
    ///
    /// # Standard Values
    /// - SHA1: RFC 6238 standard (most compatible)
    /// - SHA256: More secure, less compatible
    /// - SHA512: Most secure, least compatible
    ///
    /// # Recommendation
    /// Use SHA1 for maximum compatibility with authenticator apps
    pub algorithm: TotpAlgorithm,
}

/// TOTP hashing algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TotpAlgorithm {
    /// SHA-1 (RFC 6238 standard, most compatible)
    Sha1,

    /// SHA-256 (more secure, less compatible)
    Sha256,

    /// SHA-512 (most secure, least compatible)
    Sha512,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            time_step: 30,
            time_skew: 1,
            issuer: "EYWA Auth".to_string(),
            algorithm: TotpAlgorithm::Sha1,
        }
    }
}

impl TotpConfig {
    /// Create a new TOTP configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new TOTP configuration with custom issuer
    #[must_use]
    pub fn with_issuer(issuer: impl Into<String>) -> Self {
        let mut config = Self::default();
        config.issuer = issuer.into();
        config
    }

    /// Load TOTP configuration from environment variables
    ///
    /// # Environment Variables
    /// - `TOTP_DIGITS`: Number of digits (default: 6)
    /// - `TOTP_TIME_STEP`: Time step in seconds (default: 30)
    /// - `TOTP_TIME_SKEW`: Time skew tolerance (default: 1)
    /// - `TOTP_ISSUER`: Issuer name (default: "EYWA Auth")
    /// - `TOTP_ALGORITHM`: Algorithm (default: sha1)
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        config.digits = std::env::var("TOTP_DIGITS")
            .unwrap_or_else(|_| config.digits.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "TOTP_DIGITS".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.time_step = std::env::var("TOTP_TIME_STEP")
            .unwrap_or_else(|_| config.time_step.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "TOTP_TIME_STEP".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.time_skew = std::env::var("TOTP_TIME_SKEW")
            .unwrap_or_else(|_| config.time_skew.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "TOTP_TIME_SKEW".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.issuer = std::env::var("TOTP_ISSUER").unwrap_or_else(|_| config.issuer.clone());

        config.algorithm = match std::env::var("TOTP_ALGORITHM")
            .unwrap_or_else(|_| "sha1".to_string())
            .to_lowercase()
            .as_str()
        {
            "sha1" => TotpAlgorithm::Sha1,
            "sha256" => TotpAlgorithm::Sha256,
            "sha512" => TotpAlgorithm::Sha512,
            other => {
                return Err(ConfigError::InvalidConfigValue {
                    key: "TOTP_ALGORITHM".to_string(),
                    reason: format!("unknown algorithm: {}", other),
                });
            }
        };

        Ok(config)
    }

    /// Validate TOTP configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.digits != 6 && self.digits != 8 {
            return Err(ConfigError::InvalidConfigValue {
                key: "TOTP_DIGITS".to_string(),
                reason: "must be 6 or 8".to_string(),
            });
        }

        if self.time_step < 15 || self.time_step > 300 {
            return Err(ConfigError::InvalidConfigValue {
                key: "TOTP_TIME_STEP".to_string(),
                reason: "must be between 15 and 300 seconds".to_string(),
            });
        }

        if self.time_skew > 5 {
            return Err(ConfigError::InvalidConfigValue {
                key: "TOTP_TIME_SKEW".to_string(),
                reason: "should not exceed 5 (security risk)".to_string(),
            });
        }

        if self.issuer.is_empty() {
            return Err(ConfigError::InvalidConfigValue {
                key: "TOTP_ISSUER".to_string(),
                reason: "cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

// ==================== Rate Limit Configuration ====================

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per time window
    pub max_requests: u32,

    /// Time window duration in seconds
    pub window_seconds: u64,

    /// Maximum number of login attempts before lockout
    pub max_login_attempts: u32,

    /// Lockout duration in seconds after too many attempts
    pub lockout_duration_seconds: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            max_login_attempts: 5,
            lockout_duration_seconds: 900, // 15 minutes
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load rate limit configuration from environment variables
    ///
    /// # Environment Variables
    /// - `RATE_LIMIT_MAX_REQUESTS`: Max requests per window (default: 100)
    /// - `RATE_LIMIT_WINDOW_SECONDS`: Window duration (default: 60)
    /// - `RATE_LIMIT_MAX_LOGIN_ATTEMPTS`: Max login attempts (default: 5)
    /// - `RATE_LIMIT_LOCKOUT_SECONDS`: Lockout duration (default: 900)
    pub fn from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        config.max_requests = std::env::var("RATE_LIMIT_MAX_REQUESTS")
            .unwrap_or_else(|_| config.max_requests.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "RATE_LIMIT_MAX_REQUESTS".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.window_seconds = std::env::var("RATE_LIMIT_WINDOW_SECONDS")
            .unwrap_or_else(|_| config.window_seconds.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "RATE_LIMIT_WINDOW_SECONDS".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.max_login_attempts = std::env::var("RATE_LIMIT_MAX_LOGIN_ATTEMPTS")
            .unwrap_or_else(|_| config.max_login_attempts.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "RATE_LIMIT_MAX_LOGIN_ATTEMPTS".to_string(),
                    reason: e.to_string(),
                },
            )?;

        config.lockout_duration_seconds = std::env::var("RATE_LIMIT_LOCKOUT_SECONDS")
            .unwrap_or_else(|_| config.lockout_duration_seconds.to_string())
            .parse()
            .map_err(
                |e: std::num::ParseIntError| ConfigError::InvalidConfigFormat {
                    key: "RATE_LIMIT_LOCKOUT_SECONDS".to_string(),
                    reason: e.to_string(),
                },
            )?;

        Ok(config)
    }

    /// Validate rate limit configuration
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_requests == 0 {
            return Err(ConfigError::InvalidConfigValue {
                key: "RATE_LIMIT_MAX_REQUESTS".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.window_seconds == 0 {
            return Err(ConfigError::InvalidConfigValue {
                key: "RATE_LIMIT_WINDOW_SECONDS".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.max_login_attempts == 0 {
            return Err(ConfigError::InvalidConfigValue {
                key: "RATE_LIMIT_MAX_LOGIN_ATTEMPTS".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        if self.lockout_duration_seconds == 0 {
            return Err(ConfigError::InvalidConfigValue {
                key: "RATE_LIMIT_LOCKOUT_SECONDS".to_string(),
                reason: "must be greater than 0".to_string(),
            });
        }

        Ok(())
    }
}

// ==================== Main Auth Configuration ====================

/// Unified authentication configuration
///
/// This structure combines all configuration for EYWA Authentication:
/// - JWT configuration
/// - Password policy
/// - TOTP configuration
/// - Rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT configuration
    pub jwt: JwtConfig,

    /// Password policy configuration
    pub password: PasswordConfig,

    /// TOTP configuration
    pub totp: TotpConfig,

    /// Rate limiting configuration
    pub rate_limit: RateLimitConfig,

    /// Whether to require 2FA for all users
    pub require_2fa: bool,

    /// Whether this is a production environment (affects validation strictness)
    pub production: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: JwtConfig::new(
                "dev_secret_change_this_before_production_at_least_64_chars!",
                "eywa-auth",
                3600,
            ),
            password: PasswordConfig::new(),
            totp: TotpConfig::new(),
            rate_limit: RateLimitConfig::new(),
            require_2fa: false,
            production: false,
        }
    }
}

impl AuthConfig {
    /// Create a new authentication configuration with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from environment variables
    ///
    /// # Environment Variables
    /// See individual configuration structs for details:
    /// - `JWT_*`: JWT configuration
    /// - `PASSWORD_*`: Password policy
    /// - `TOTP_*`: TOTP configuration
    /// - `RATE_LIMIT_*`: Rate limiting
    /// - `REQUIRE_2FA`: Require 2FA (default: false)
    /// - `PRODUCTION`: Production mode (default: false)
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            jwt: JwtConfig::from_env()?,
            password: PasswordConfig::from_env()?,
            totp: TotpConfig::from_env()?,
            rate_limit: RateLimitConfig::from_env()?,
            require_2fa: std::env::var("REQUIRE_2FA")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
            production: std::env::var("PRODUCTION")
                .unwrap_or_else(|_| "false".to_string())
                .parse()
                .unwrap_or(false),
        })
    }

    /// Validate all configuration
    ///
    /// This validates all sub-configurations and returns the first error found.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.jwt.validate(self.production)?;
        self.password.validate()?;
        self.totp.validate()?;
        self.rate_limit.validate()?;
        Ok(())
    }

    /// Generate a secure JWT secret (for development/testing only!)
    ///
    /// # Security Warning
    /// Do NOT use this in production! Generate secrets securely using:
    /// ```bash
    /// openssl rand -base64 64
    /// ```
    #[must_use]
    pub fn generate_test_jwt_secret() -> String {
        use rand::Rng;
        let mut rng = rand::rng();
        let secret: String = (0..64)
            .map(|_| {
                let charset = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                charset[rng.random_range(0..charset.len())] as char
            })
            .collect();
        secret
    }
}

// ==================== Configuration Errors ====================

/// Configuration error types
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Required configuration key is missing
    #[error("Missing required configuration: {key}")]
    MissingRequiredConfig { key: String },

    /// Configuration value has invalid format
    #[error("Invalid configuration format for '{key}': {reason}")]
    InvalidConfigFormat { key: String, reason: String },

    /// Configuration value is invalid
    #[error("Invalid configuration value for '{key}': {reason}")]
    InvalidConfigValue { key: String, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_config_default() {
        let config = JwtConfig::new(
            "test_secret_at_least_32_characters_long",
            "test-issuer",
            3600,
        );

        assert_eq!(config.issuer, "test-issuer");
        assert_eq!(config.expiration_seconds, 3600);
    }

    #[test]
    fn test_jwt_config_validation() {
        let config = JwtConfig::new(
            "test_secret_at_least_32_characters_long",
            "test-issuer",
            3600,
        );

        // Should pass in development mode
        assert!(config.validate(false).is_ok());

        // Should fail in production mode (secret too short)
        assert!(config.validate(true).is_err());
    }

    #[test]
    fn test_password_config_default() {
        let config = PasswordConfig::default();

        assert_eq!(config.min_length, 12);
        assert_eq!(config.require_uppercase, true);
        assert_eq!(config.hashing_algorithm, HashingAlgorithm::Argon2id);
    }

    #[test]
    fn test_password_config_validation() {
        let mut config = PasswordConfig::default();
        config.min_length = 4;

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_totp_config_default() {
        let config = TotpConfig::default();

        assert_eq!(config.digits, 6);
        assert_eq!(config.time_step, 30);
        assert_eq!(config.time_skew, 1);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
    }

    #[test]
    fn test_totp_config_validation() {
        let mut config = TotpConfig::default();
        config.digits = 10;

        assert!(config.validate().is_err());
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();

        assert_eq!(config.max_requests, 100);
        assert_eq!(config.max_login_attempts, 5);
    }

    #[test]
    fn test_auth_config_default() {
        let config = AuthConfig::default();

        assert_eq!(config.production, false);
        assert_eq!(config.require_2fa, false);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_generate_test_jwt_secret() {
        let secret = AuthConfig::generate_test_jwt_secret();

        assert_eq!(secret.len(), 64);
        // Should contain only base64 characters
        assert!(
            secret
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
        );
    }
}
