//! # Password Service
//!
//! This module provides secure password hashing and validation using Argon2id.
//!
//! ## Features
//!
//! - Argon2id hashing (most secure password hashing algorithm)
//! - Configurable password policies
//! - Password strength scoring
//! - Common password detection
//! - Pattern detection (sequential, repeated characters)
//!
//! ## Usage
//!
//! ```no_run
//! use eywa_authentication::PasswordService;
//!
//! // Hash a password
//! let hash = PasswordService::hash_password("secure_password_123!").unwrap();
//!
//! // Verify a password
//! let is_valid = PasswordService::verify_password("secure_password_123!", &hash).unwrap();
//! assert!(is_valid);
//!
//! // Validate password against policy
//! let policy = PasswordPolicy::default();
//! let result = PasswordService::validate_password("secure_password_123!", &policy);
//! assert!(result.is_ok());
//! ```
//!
//! ## Security
//!
//! - Uses Argon2id (recommended by OWASP)
//! - Configurable memory and time cost
//! - Salt automatically generated
//! - Resistant to GPU/ASIC attacks
//! - Detects weak passwords

use crate::config::HashingAlgorithm;
use crate::{Result, error::AuthError};
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};

// ==================== Password Policy ====================

/// Password policy for validation
///
/// This structure defines requirements for password complexity.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length
    pub min_length: usize,

    /// Maximum password length
    pub max_length: usize,

    /// Require at least one uppercase letter
    pub require_uppercase: bool,

    /// Require at least one lowercase letter
    pub require_lowercase: bool,

    /// Require at least one digit
    pub require_numbers: bool,

    /// Require at least one special character
    pub require_special_chars: bool,

    /// Minimum password strength score (0-100)
    pub min_strength_score: u32,

    /// Hashing algorithm to use
    pub hashing_algorithm: HashingAlgorithm,

    /// Argon2 parameters
    pub argon2_params: Argon2Params,
}

/// Argon2 parameters for password hashing
#[derive(Debug, Clone)]
pub struct Argon2Params {
    /// Time cost (iterations)
    pub t_cost: u32,

    /// Memory cost (in KiB)
    pub m_cost: u32,

    /// Parallelism (number of threads/lanes)
    pub parallelism: u32,

    /// Output length (in bytes)
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

impl Default for PasswordPolicy {
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
            argon2_params: Argon2Params::default(),
        }
    }
}

impl PasswordPolicy {
    /// Create a new password policy with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a password policy with minimum requirements
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: false,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: false,
            min_strength_score: 50,
            hashing_algorithm: HashingAlgorithm::Argon2id,
            argon2_params: Argon2Params::default(),
        }
    }

    /// Create a strict password policy
    #[must_use]
    pub fn strict() -> Self {
        Self {
            min_length: 16,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_special_chars: true,
            min_strength_score: 85,
            hashing_algorithm: HashingAlgorithm::Argon2id,
            argon2_params: Argon2Params {
                t_cost: 4,
                m_cost: 65536, // 64 MB
                ..Default::default()
            },
        }
    }

    /// Validate password against this policy
    pub fn validate(&self, password: &str) -> Result<()> {
        // Check length
        if password.len() < self.min_length {
            return Err(AuthError::PasswordTooWeak(format!(
                "Password is too short (minimum {} characters)",
                self.min_length
            ))
            .into());
        }

        if password.len() > self.max_length {
            return Err(AuthError::PasswordTooWeak(format!(
                "Password is too long (maximum {} characters)",
                self.max_length
            ))
            .into());
        }

        // Check for uppercase
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err(AuthError::PasswordTooWeak(
                "Password must contain at least one uppercase letter".to_string(),
            )
            .into());
        }

        // Check for lowercase
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err(AuthError::PasswordTooWeak(
                "Password must contain at least one lowercase letter".to_string(),
            )
            .into());
        }

        // Check for numbers
        if self.require_numbers && !password.chars().any(|c| c.is_numeric()) {
            return Err(AuthError::PasswordTooWeak(
                "Password must contain at least one number".to_string(),
            )
            .into());
        }

        // Check for special characters
        if self.require_special_chars && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err(AuthError::PasswordTooWeak(
                "Password must contain at least one special character".to_string(),
            )
            .into());
        }

        // Check strength score
        let strength = PasswordService::calculate_strength(password);
        if strength < self.min_strength_score {
            return Err(AuthError::PasswordTooWeak(format!(
                "Password strength score {} is below minimum {}",
                strength, self.min_strength_score
            ))
            .into());
        }

        Ok(())
    }
}

// ==================== Password Service ====================

/// Password service for hashing and verification
///
/// This service uses Argon2id for password hashing, which is the
/// most secure password hashing algorithm recommended by OWASP.
///
/// # Thread Safety
///
/// This service is thread-safe and can be shared across threads.
#[derive(Debug, Clone)]
pub struct PasswordService {
    /// Password policy for validation
    policy: PasswordPolicy,
}

impl PasswordService {
    /// Create a new password service with default policy
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: PasswordPolicy::default(),
        }
    }

    /// Create a new password service with custom policy
    #[must_use]
    pub fn with_policy(policy: PasswordPolicy) -> Self {
        Self { policy }
    }

    /// Get the password policy
    #[must_use]
    pub const fn policy(&self) -> &PasswordPolicy {
        &self.policy
    }

    /// Hash a password using Argon2id
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password to hash
    ///
    /// # Returns
    ///
    /// Password hash string (PHC format)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::PasswordService;
    ///
    /// let service = PasswordService::new();
    /// let hash = service.hash_password("secure_password_123!").unwrap();
    /// println!("Hash: {}", hash);
    /// ```
    pub fn hash_password(&self, password: &str) -> Result<String> {
        let argon2 = self.create_argon2();
        let salt = SaltString::generate(&mut OsRng);

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| AuthError::PasswordHashError(e.to_string()).into())
    }

    /// Verify a password against a hash
    ///
    /// # Arguments
    ///
    /// * `password` - Plain text password to verify
    /// * `hash` - Password hash to verify against
    ///
    /// # Returns
    ///
    /// `true` if password matches hash, `false` otherwise
    ///
    /// # Example
    ///
    /// ```no_run
    /// use eywa_authentication::PasswordService;
    ///
    /// let service = PasswordService::new();
    /// let hash = service.hash_password("password123").unwrap();
    ///
    /// let is_valid = service.verify_password("password123", &hash).unwrap();
    /// assert!(is_valid);
    /// ```
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordVerificationError(e.to_string()))?; // Implicit conversion via ? works if Result types match, otherwise manually convert

        // Here we map Error so we need to be careful.
        // Wait, Result<bool> is Result<bool, AppError>.
        // PasswordHash::new returns argon2::password_hash::Error.
        // AuthError::PasswordVerificationError(e.to_string()) returns AuthError.
        // We need AppError.
        // So map_err must return AppError.
        // The ? operator will convert AppError to AppError.
        // But map_err closure returns AuthError.
        // AuthError implements Into<AppError>.
        // So we need to call .into() or map_err(|e| AuthError::... .into())

        let argon2 = self.create_argon2();

        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Validate a password against the service's policy
    ///
    /// # Arguments
    ///
    /// * `password` - Password to validate
    ///
    /// # Returns
    ///
    /// `Ok(())` if password meets policy, error otherwise
    pub fn validate_password(&self, password: &str) -> Result<()> {
        self.policy.validate(password)?;
        Ok(())
    }

    /// Hash and validate password in one operation
    ///
    /// # Arguments
    ///
    /// * `password` - Password to hash and validate
    ///
    /// # Returns
    ///
    /// Password hash if password meets policy
    ///
    /// # Errors
    ///
    /// Returns error if password does not meet policy
    pub fn hash_and_validate(&self, password: &str) -> Result<String> {
        self.validate_password(password)?;
        self.hash_password(password)
    }

    /// Create Argon2 instance based on policy
    fn create_argon2(&self) -> Argon2<'_> {
        match self.policy.hashing_algorithm {
            HashingAlgorithm::Argon2id => Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(
                    self.policy.argon2_params.m_cost,
                    self.policy.argon2_params.t_cost,
                    self.policy.argon2_params.parallelism,
                    Some(self.policy.argon2_params.output_length as usize),
                )
                .expect("Invalid Argon2 parameters"),
            ),
            HashingAlgorithm::Argon2i => Argon2::new(
                Algorithm::Argon2i,
                Version::V0x13,
                Params::new(
                    self.policy.argon2_params.m_cost,
                    self.policy.argon2_params.t_cost,
                    self.policy.argon2_params.parallelism,
                    Some(self.policy.argon2_params.output_length as usize),
                )
                .expect("Invalid Argon2 parameters"),
            ),
            HashingAlgorithm::Argon2d => Argon2::new(
                Algorithm::Argon2d,
                Version::V0x13,
                Params::new(
                    self.policy.argon2_params.m_cost,
                    self.policy.argon2_params.t_cost,
                    self.policy.argon2_params.parallelism,
                    Some(self.policy.argon2_params.output_length as usize),
                )
                .expect("Invalid Argon2 parameters"),
            ),
            HashingAlgorithm::Bcrypt => {
                // Fallback to Argon2id for now (bcrypt requires different crate)
                tracing::warn!("Bcrypt not fully supported, using Argon2id");
                Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(
                        self.policy.argon2_params.m_cost,
                        self.policy.argon2_params.t_cost,
                        self.policy.argon2_params.parallelism,
                        Some(self.policy.argon2_params.output_length as usize),
                    )
                    .expect("Invalid Argon2 parameters"),
                )
            }
            HashingAlgorithm::Pbkdf2 => {
                // Fallback to Argon2id for now (PBKDF2 requires different crate)
                tracing::warn!("PBKDF2 not fully supported, using Argon2id");
                Argon2::new(
                    Algorithm::Argon2id,
                    Version::V0x13,
                    Params::new(
                        self.policy.argon2_params.m_cost,
                        self.policy.argon2_params.t_cost,
                        self.policy.argon2_params.parallelism,
                        Some(self.policy.argon2_params.output_length as usize),
                    )
                    .expect("Invalid Argon2 parameters"),
                )
            }
        }
    }

    /// Calculate password strength score (0-100)
    #[must_use]
    pub fn calculate_strength(password: &str) -> u32 {
        let mut score = 0u32;

        // Length scoring (max 40 points)
        let length_score = (password.len() as u32) * 2;
        score += length_score.min(40);

        // Character variety scoring (max 40 points)
        if password.chars().any(|c| c.is_uppercase()) {
            score += 10;
        }
        if password.chars().any(|c| c.is_lowercase()) {
            score += 10;
        }
        if password.chars().any(|c| c.is_numeric()) {
            score += 10;
        }
        if password.chars().any(|c| !c.is_alphanumeric()) {
            score += 10;
        }

        // Deductions for weak patterns (max -30 points)
        if Self::has_common_pattern(password) {
            score = score.saturating_sub(20);
        }
        if Self::has_sequential_pattern(password) {
            score = score.saturating_sub(10);
        }
        if Self::has_repeated_pattern(password) {
            score = score.saturating_sub(10);
        }

        // Bonus for entropy (max 20 points)
        let entropy = Self::calculate_entropy(password);
        score += (entropy / 10.0).min(20.0) as u32;

        score.min(100)
    }

    /// Check if password contains common patterns
    fn has_common_pattern(password: &str) -> bool {
        let lower = password.to_lowercase();

        // Common passwords list (subset of most common passwords)
        let common_passwords = vec![
            "password", "123456", "qwerty", "admin", "welcome", "monkey", "letmein", "dragon",
            "master", "hello", "login", "passw0rd", "football", "superman", "iloveyou",
        ];

        for common in common_passwords {
            if lower.contains(common) {
                return true;
            }
        }

        false
    }

    /// Check for sequential character patterns (abc, 123)
    fn has_sequential_pattern(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() < 3 {
            return false;
        }

        // Check for sequences of 3+ characters
        for i in 0..=chars.len().saturating_sub(3) {
            let c1 = chars[i] as u32;
            let c2 = chars[i + 1] as u32;
            let c3 = chars[i + 2] as u32;

            // Sequential (abc, 123)
            if c1 + 1 == c2 && c2 + 1 == c3 {
                return true;
            }

            // Reverse sequential (cba, 321)
            if c1.saturating_sub(1) == c2 && c2.saturating_sub(1) == c3 {
                return true;
            }
        }

        false
    }

    /// Check for repeated character patterns (aaa, 111)
    fn has_repeated_pattern(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() < 3 {
            return false;
        }

        // Check for 3+ repeated characters
        for i in 0..=chars.len().saturating_sub(3) {
            if chars[i] == chars[i + 1] && chars[i + 1] == chars[i + 2] {
                return true;
            }
        }

        false
    }

    /// Calculate password entropy (approximate)
    fn calculate_entropy(password: &str) -> f64 {
        let charset_size = Self::estimate_charset_size(password);
        let length = password.len();

        // Entropy = log2(charset_size^length)
        length as f64 * charset_size.log2()
    }

    /// Estimate character set size for entropy calculation
    fn estimate_charset_size(password: &str) -> f64 {
        let mut charset_size = 0f64;

        if password.chars().any(|c| c.is_ascii_digit()) {
            charset_size += 10.0; // 0-9
        }
        if password.chars().any(|c| c.is_ascii_lowercase()) {
            charset_size += 26.0; // a-z
        }
        if password.chars().any(|c| c.is_ascii_uppercase()) {
            charset_size += 26.0; // A-Z
        }
        if password
            .chars()
            .any(|c| !c.is_alphanumeric() && c.is_ascii())
        {
            charset_size += 32.0; // Special characters
        }

        charset_size.max(1.0)
    }
}

// ==================== Convenience Functions ====================

/// Hash a password with default policy
pub fn hash_password(password: &str) -> Result<String> {
    let service = PasswordService::new();
    service.hash_password(password)
}

/// Verify a password against a hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let service = PasswordService::new();
    service.verify_password(password, hash)
}

/// Calculate password strength score
pub fn calculate_password_strength(password: &str) -> u32 {
    PasswordService::calculate_strength(password)
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_service() -> PasswordService {
        PasswordService::new()
    }

    #[test]
    fn test_hash_and_verify_password() {
        let service = create_test_service();
        let password = "SecurePassword123!";

        let hash = service.hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));

        let is_valid = service.verify_password(password, &hash).unwrap();
        assert!(is_valid);

        let is_invalid = service.verify_password("wrong_password", &hash).unwrap();
        assert!(!is_invalid);
    }

    #[test]
    fn test_hash_convenience_function() {
        let password = "MyPassword123!";
        let hash = hash_password(password).unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_verify_convenience_function() {
        let password = "MyPassword123!";
        let hash = hash_password(password).unwrap();

        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_password_policy_default() {
        let policy = PasswordPolicy::default();

        assert_eq!(policy.min_length, 12);
        assert_eq!(policy.max_length, 128);
        assert!(policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_numbers);
        assert!(policy.require_special_chars);
        assert_eq!(policy.min_strength_score, 70);
    }

    #[test]
    fn test_password_policy_lenient() {
        let policy = PasswordPolicy::lenient();

        assert_eq!(policy.min_length, 8);
        assert!(!policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_numbers);
        assert!(!policy.require_special_chars);
        assert_eq!(policy.min_strength_score, 50);
    }

    #[test]
    fn test_password_policy_strict() {
        let policy = PasswordPolicy::strict();

        assert_eq!(policy.min_length, 16);
        assert!(policy.require_uppercase);
        assert!(policy.require_lowercase);
        assert!(policy.require_numbers);
        assert!(policy.require_special_chars);
        assert_eq!(policy.min_strength_score, 85);
    }

    #[test]
    fn test_validate_strong_password() {
        let service = create_test_service();
        let password = "MySecure#Pass123!";

        assert!(service.validate_password(password).is_ok());
    }

    #[test]
    fn test_validate_too_short_password() {
        let service = create_test_service();
        let password = "Short1!";

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_uppercase() {
        let service = create_test_service();
        let password = "alllowercase123!";

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_lowercase() {
        let service = create_test_service();
        let password = "ALLUPPERCASE123!";

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_numbers() {
        let service = create_test_service();
        let password = "NoNumbersHere!";

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_missing_special_chars() {
        let service = create_test_service();
        let password = "NoSpecialChars123";

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_common_password() {
        let service = create_test_service();
        let password = "Password123!"; // Contains "password"

        let result = service.validate_password(password);
        assert!(result.is_err());
    }

    #[test]
    fn test_calculate_strength_very_strong() {
        let password = "Tr0ub4dor&3VeryComplexP@ssw0rd!";
        let strength = calculate_password_strength(password);
        assert!(strength >= 85);
    }

    #[test]
    fn test_calculate_strength_strong() {
        let password = "MySecure#Pass123!";
        let strength = calculate_password_strength(password);
        assert!(strength >= 70 && strength < 85);
    }

    #[test]
    fn test_calculate_strength_moderate() {
        let password = "mypassword123";
        let strength = calculate_password_strength(password);
        assert!(strength >= 50 && strength < 70);
    }

    #[test]
    fn test_calculate_strength_weak() {
        let password = "password";
        let strength = calculate_password_strength(password);
        assert!(strength < 50);
    }

    #[test]
    fn test_calculate_strength_very_weak() {
        let password = "123456";
        let strength = calculate_password_strength(password);
        assert!(strength < 30);
    }

    #[test]
    fn test_hash_and_validate() {
        let service = create_test_service();
        let password = "MySecure#Pass123!";

        // Should succeed (meets policy)
        let hash = service.hash_and_validate(password);
        assert!(hash.is_ok());

        // Should fail (doesn't meet policy)
        let weak_password = "short";
        let result = service.hash_and_validate(weak_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_common_patterns() {
        assert!(PasswordService::has_common_pattern("password123"));
        assert!(PasswordService::has_common_pattern("MyPassword123!"));
        assert!(!PasswordService::has_common_pattern("StrongP@ssw0rd!"));
    }

    #[test]
    fn test_sequential_patterns() {
        assert!(PasswordService::has_sequential_pattern("abc123"));
        assert!(PasswordService::has_sequential_pattern("xyz789"));
        assert!(!PasswordService::has_sequential_pattern("random"));
    }

    #[test]
    fn test_repeated_patterns() {
        assert!(PasswordService::has_repeated_pattern("aaa123"));
        assert!(PasswordService::has_repeated_pattern("111aaa"));
        assert!(!PasswordService::has_repeated_pattern("random"));
    }

    #[test]
    fn test_entropy_calculation() {
        let low_entropy = "aaaa";
        let high_entropy = "aA1!";

        let low_score = PasswordService::calculate_entropy(low_entropy);
        let high_score = PasswordService::calculate_entropy(high_entropy);

        assert!(high_score > low_score);
    }

    #[test]
    fn test_with_custom_policy() {
        let policy = PasswordPolicy::lenient();
        let service = PasswordService::with_policy(policy);

        // Lenient policy allows shorter passwords
        let password = "short1";
        assert!(service.validate_password(password).is_ok());

        let hash = service.hash_password(password).unwrap();
        assert!(service.verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_hash_length_consistency() {
        let service = create_test_service();
        let password1 = "Password123!";
        let password2 = "DifferentPass456@";

        let hash1 = service.hash_password(password1).unwrap();
        let hash2 = service.hash_password(password2).unwrap();

        // Hashes should be different
        assert_ne!(hash1, hash2);

        // Hashes should have reasonable length
        assert!(hash1.len() > 50);
        assert!(hash2.len() > 50);
    }

    #[test]
    fn test_verify_wrong_hash_format() {
        let service = create_test_service();
        let password = "password123";
        let invalid_hash = "invalid_hash_format";

        let result = service.verify_password(password, invalid_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_password_policy_copy() {
        let policy1 = PasswordPolicy::default();
        let policy2 = policy1.clone();

        assert_eq!(policy1.min_length, policy2.min_length);
        assert_eq!(policy1.require_uppercase, policy2.require_uppercase);
    }

    #[test]
    fn test_strength_score_boundaries() {
        let password = "x".repeat(100);
        let strength = calculate_password_strength(&password);

        // Should be capped at 100
        assert!(strength <= 100);
    }
}
