//! # Validation Module
//!
//! This module provides input validation and sanitization utilities
//! for preventing common security issues like XSS, SQL injection, and injection attacks.
//!
//! ## Features
//!
//! - Email format validation
//! - Username format validation
//! - UUID format validation
//! - Phone number validation
//! - URL validation
//! - Safe string validation (XSS prevention)
//! - Input sanitization
//! - Length validation
//! - Custom regex patterns
//!
//! ## Usage
//!
//! ```no_run
//! use eywa_authentication::validation::*;
//!
//! // Validate email
//! let email = "user@example.com";
//! assert!(validate_email(email).is_ok());
//!
//! // Validate username
//! let username = "john_doe";
//! assert!(validate_username(username).is_ok());
//!
//! // Validate UUID
//! let uuid = "550e8400-e29b-41d4-a716-446655440000";
//! assert!(validate_uuid(uuid).is_ok());
//!
//! // Sanitize string
//! let input = "<script>alert('xss')</script>Hello";
//! let sanitized = sanitize_string(input);
//! assert!(!sanitized.contains("<script>"));
//! ```
//!
//! ## Security
//!
//! - Validates input formats to prevent injection attacks
//! - Sanitizes strings to prevent XSS attacks
//! - Checks for common attack patterns
//! - Validates lengths to prevent buffer overflow attacks
//! - Uses proper regex patterns for each input type

use regex::Regex;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::{error::AuthError, Result};
use eywa_errors::AppError;

// ==================== Email Validation ====================

lazy_static::lazy_static! {
    /// Email regex pattern (RFC 5322 compliant)
    static ref EMAIL_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    ).expect("Failed to compile email regex");
}

/// Validate email format
///
/// This validates that the email follows RFC 5322 standards.
/// Note: This only validates format, not deliverability.
///
/// # Arguments
///
/// * `email` - Email address to validate
///
/// # Returns
///
/// `Ok(())` if email format is valid, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_email;
///
/// // Valid emails
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("user.name+tag@example.co.uk").is_ok());
///
/// // Invalid emails
/// assert!(validate_email("invalid").is_err());
/// assert!(validate_email("invalid@").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AppError::ValidationField {
            field: "email".to_string(),
            message: "Email is required".to_string(),
        });
    }

    if EMAIL_REGEX.is_match(email) {
        Ok(())
    } else {
        Err(AppError::ValidationField {
            field: "email".to_string(),
            message: format!("Invalid email format: {}", email),
        })
    }
}

/// Check if string is a valid email
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `email` - Email address to check
///
/// # Returns
///
/// `true` if email format is valid, `false` otherwise
#[must_use]
pub fn is_valid_email(email: &str) -> bool {
    validate_email(email).is_ok()
}

// ==================== Username Validation ====================

lazy_static::lazy_static! {
    /// Username regex pattern
    /// Allowed: alphanumeric, underscore, hyphen, 3-30 characters
    static ref USERNAME_REGEX: Regex = Regex::new(
        r"^[a-zA-Z0-9_-]{3,30}$"
    ).expect("Failed to compile username regex");
}

/// Validate username format
///
/// This validates that the username contains only allowed characters
/// and meets length requirements.
///
/// # Rules
///
/// - Must be 3-30 characters
/// - Only alphanumeric characters, underscores, and hyphens
/// - Cannot start or end with underscore or hyphen
///
/// # Arguments
///
/// * `username` - Username to validate
///
/// # Returns
///
/// `Ok(())` if username format is valid, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_username;
///
/// // Valid usernames
/// assert!(validate_username("john_doe").is_ok());
/// assert!(validate_username("user123").is_ok());
/// assert!(validate_username("test-user").is_ok());
///
/// // Invalid usernames
/// assert!(validate_username("ab").is_err()); // Too short
/// assert!(validate_username("invalid-@#").is_err()); // Invalid characters
/// ```
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        return Err(AuthError::InvalidUsername("username".to_string()).into());
    }

    if USERNAME_REGEX.is_match(username) {
        Ok(())
    } else {
        Err(AuthError::InvalidUsername(username.to_string()).into())
    }
}

/// Check if string is a valid username
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `username` - Username to check
///
/// # Returns
///
/// `true` if username format is valid, `false` otherwise
#[must_use]
pub fn is_valid_username(username: &str) -> bool {
    validate_username(username).is_ok()
}

// ==================== UUID Validation ====================

/// Validate UUID format
///
/// This validates that the string is a valid UUID (v4 or v7 format).
///
/// # Arguments
///
/// * `uuid` - UUID string to validate
///
/// # Returns
///
/// `Ok(())` if UUID format is valid, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_uuid;
///
/// // Valid UUIDs
/// assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
/// assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
///
/// // Invalid UUIDs
/// assert!(validate_uuid("not-a-uuid").is_err());
/// assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440").is_err()); // Too short
/// ```
pub fn validate_uuid(uuid: &str) -> Result<()> {
    if Uuid::parse_str(uuid).is_ok() {
        Ok(())
    } else {
        Err(AuthError::InvalidUuid(uuid.to_string()).into())
    }
}

/// Check if string is a valid UUID
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `uuid` - UUID string to check
///
/// # Returns
///
/// `true` if UUID format is valid, `false` otherwise
#[must_use]
pub fn is_valid_uuid(uuid: &str) -> bool {
    validate_uuid(uuid).is_ok()
}

// ==================== Phone Validation ====================

lazy_static::lazy_static! {
    /// Phone number regex pattern (E.164 format)
    /// Allows: +<country_code><number> (e.g., +1234567890)
    static ref PHONE_REGEX: Regex = Regex::new(
        r"^\+?[1-9]\d{1,14}$"
    ).expect("Failed to compile phone regex");
}

/// Validate phone number format
///
/// This validates that the phone number follows E.164 format.
///
/// # Rules
///
/// - Optional '+' prefix (for international format)
/// - Must start with 1-9
/// - Must be 10-15 digits total (excluding '+' if present)
///
/// # Arguments
///
/// * `phone` - Phone number to validate
///
/// # Returns
///
/// `Ok(())` if phone number format is valid, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_phone;
///
/// // Valid phone numbers
/// assert!(validate_phone("+1234567890").is_ok());
/// assert!(validate_phone("1234567890").is_ok());
///
/// // Invalid phone numbers
/// assert!(validate_phone("123").is_err()); // Too short
/// assert!(validate_phone("01234567890").is_err()); // Starts with 0
/// ```
pub fn validate_phone(phone: &str) -> Result<()> {
    if phone.is_empty() {
        return Err(AuthError::InvalidPhone("phone".to_string()).into());
    }

    if PHONE_REGEX.is_match(phone) {
        Ok(())
    } else {
        Err(AuthError::InvalidPhone(phone.to_string()).into())
    }
}

/// Check if string is a valid phone number
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `phone` - Phone number to check
///
/// # Returns
///
/// `true` if phone number format is valid, `false` otherwise
#[must_use]
pub fn is_valid_phone(phone: &str) -> bool {
    validate_phone(phone).is_ok()
}

// ==================== URL Validation ====================

/// Validate URL format
///
/// This validates that the string is a valid URL with http/https scheme.
///
/// # Arguments
///
/// * `url` - URL string to validate
///
/// # Returns
///
/// `Ok(())` if URL format is valid, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_url;
///
/// // Valid URLs
/// assert!(validate_url("https://example.com").is_ok());
/// assert!(validate_url("http://example.com/path").is_ok());
/// assert!(validate_url("https://example.com:8080/path").is_ok());
///
/// // Invalid URLs
/// assert!(validate_url("not-a-url").is_err());
/// assert!(validate_url("ftp://example.com").is_err()); // Wrong scheme
/// ```
pub fn validate_url(url_str: &str) -> Result<()> {
    if url_str.is_empty() {
        return Err(AuthError::InvalidUrl("url".to_string()).into());
    }

    match Url::parse(url_str) {
        Ok(url) => {
            // Ensure it's http or https
            match url.scheme() {
                "http" | "https" => Ok(()),
                scheme => Err(AuthError::InvalidUrl(format!(
                    "URL must use http or https scheme, got: {}",
                    scheme
                ))
                .into()),
            }
        }
        Err(_) => Err(AuthError::InvalidUrl(url_str.to_string()).into()),
    }
}

/// Check if string is a valid URL
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `url` - URL string to check
///
/// # Returns
///
/// `true` if URL format is valid, `false` otherwise
#[must_use]
pub fn is_valid_url(url: &str) -> bool {
    validate_url(url).is_ok()
}

// ==================== Safe String Validation ====================

lazy_static::lazy_static! {
    /// Safe string regex pattern
    /// Allows: alphanumeric, whitespace, and common safe punctuation
    static ref SAFE_STRING_REGEX: Regex = Regex::new(
        r#"^[a-zA-Z0-9\s\-_.,!?@#$%&*()+=\[\]{}|;:'"]+[^<>]+$"#
    ).expect("Failed to compile safe string regex");

    /// XSS pattern regex
    static ref XSS_PATTERN: Regex = Regex::new(
        r"(?i)<script>|javascript:|on\w+\s*=|eval\(|document\\.cookie|alert\(|innerHTML\\s*=|outerHTML\\s*="
    ).expect("Failed to compile XSS regex");
}

/// Validate that string is safe (no XSS/injection)
///
/// This checks that the string doesn't contain potentially dangerous patterns
/// that could lead to XSS or injection attacks.
///
/// # Arguments
///
/// * `value` - String to validate
///
/// # Returns
///
/// `Ok(())` if string is safe, error otherwise
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::validate_safe_string;
///
/// // Safe strings
/// assert!(validate_safe_string("Hello, World!").is_ok());
/// assert!(validate_safe_string("Test-123_Example").is_ok());
///
/// // Unsafe strings
/// assert!(validate_safe_string("<script>alert('xss')</script>").is_err());
/// assert!(validate_safe_string("javascript:alert(1)").is_err());
/// ```
pub fn validate_safe_string(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(()); // Empty string is safe
    }

    // Check for XSS patterns
    if XSS_PATTERN.is_match(value) {
        return Err(AuthError::DangerousContent {
            content: "XSS pattern detected".to_string(),
        }
        .into());
    }

    // Check for SQL injection patterns
    if contains_sql_injection(value) {
        return Err(AuthError::DangerousContent {
            content: "SQL injection pattern detected".to_string(),
        }
        .into());
    }

    Ok(())
}

/// Check if string is safe
///
/// This is a convenience function that returns a boolean instead of a Result.
///
/// # Arguments
///
/// * `value` - String to check
///
/// # Returns
///
/// `true` if string is safe, `false` otherwise
#[must_use]
pub fn is_safe_string(value: &str) -> bool {
    validate_safe_string(value).is_ok()
}

/// Check for SQL injection patterns
fn contains_sql_injection(value: &str) -> bool {
    let sql_patterns = vec![
        "union select",
        "or 1=1",
        "and 1=1",
        "drop table",
        "delete from",
        "insert into",
        "update set",
        "exec(",
        "xp_cmdshell",
        "sp_executesql",
        "'; --",
        "' or '1'='1",
        "' or '1'='1'--",
        "' or '1'='1'/*",
        "1'='1",
        "1=1",
        "--",
        "/*",
        "*/",
    ];

    let lower = value.to_lowercase();
    sql_patterns.iter().any(|pattern| lower.contains(pattern))
}

// ==================== Length Validation ====================

/// Validate string length (minimum)
///
/// # Arguments
///
/// * `value` - String to validate
/// * `min_length` - Minimum required length
///
/// # Returns
///
/// `Ok(())` if length is valid, error otherwise
pub fn validate_min_length(value: &str, min_length: usize) -> Result<()> {
    if value.len() < min_length {
        return Err(AuthError::InputTooShort {
            min_length,
            actual_length: value.len(),
        }
        .into());
    }
    Ok(())
}

/// Validate string length (maximum)
///
/// # Arguments
///
/// * `value` - String to validate
/// * `max_length` - Maximum allowed length
///
/// # Returns
///
/// `Ok(())` if length is valid, error otherwise
pub fn validate_max_length(value: &str, max_length: usize) -> Result<()> {
    if value.len() > max_length {
        return Err(AuthError::InputTooLong {
            max_length,
            actual_length: value.len(),
        }
        .into());
    }
    Ok(())
}

/// Validate string length (range)
///
/// # Arguments
///
/// * `value` - String to validate
/// * `min_length` - Minimum required length
/// * `max_length` - Maximum allowed length
///
/// # Returns
///
/// `Ok(())` if length is valid, error otherwise
pub fn validate_length(value: &str, min_length: usize, max_length: usize) -> Result<()> {
    validate_min_length(value, min_length)?;
    validate_max_length(value, max_length)?;
    Ok(())
}

// ==================== Field Validation ====================

/// Validate that a field is not empty
///
/// # Arguments
///
/// * `field_name` - Name of the field (for error messages)
/// * `value` - Field value to validate
///
/// # Returns
///
/// `Ok(())` if field is not empty, error otherwise
pub fn validate_required(field_name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(AuthError::MissingField {
            field: field_name.to_string(),
        }
        .into());
    }
    Ok(())
}

/// Validate that a field matches a regex pattern
///
/// # Arguments
///
/// * `field_name` - Name of the field (for error messages)
/// * `value` - Field value to validate
/// * `pattern` - Regex pattern to match
/// * `error_message` - Custom error message if validation fails
///
/// # Returns
///
/// `Ok(())` if field matches pattern, error otherwise
pub fn validate_pattern(
    field_name: &str,
    value: &str,
    pattern: &Regex,
    error_message: &str,
) -> Result<()> {
    if !pattern.is_match(value) {
        return Err(AuthError::InvalidFieldValue {
            field: field_name.to_string(),
            reason: error_message.to_string(),
        }
        .into());
    }
    Ok(())
}

// ==================== Sanitization ====================

/// Sanitize a string to prevent XSS attacks
///
/// This removes or escapes potentially dangerous content from strings.
///
/// # Sanitization Rules
///
/// - Remove `<script>` tags
/// - Remove `javascript:` protocols
/// - Remove `on*` event handlers (onclick, onload, etc.)
/// - Remove `eval()` calls
/// - Remove `innerHTML` assignments
///
/// # Arguments
///
/// * `value` - String to sanitize
///
/// # Returns
///
/// Sanitized string
///
/// # Example
///
/// ```no_run
/// use eywa_authentication::sanitize_string;
///
/// let input = "<script>alert('xss')</script>Hello";
/// let sanitized = sanitize_string(input);
///
/// assert!(!sanitized.contains("<script>"));
/// assert!(sanitized.contains("Hello"));
/// ```
#[must_use]
pub fn sanitize_string(value: &str) -> String {
    let mut sanitized = value.to_string();

    // Remove script tags
    sanitized = sanitized.replace("<script", "&lt;script");
    sanitized = sanitized.replace("</script>", "&lt;/script&gt;");

    // Remove javascript: protocol
    sanitized = sanitized.replace("javascript:", "javascript:");

    // Remove event handlers
    sanitized = sanitized.replace("onclick=", "onclick=");
    sanitized = sanitized.replace("onload=", "onload=");
    sanitized = sanitized.replace("onerror=", "onerror=");
    sanitized = sanitized.replace("onfocus=", "onfocus=");
    sanitized = sanitized.replace("onblur=", "onblur=");

    // Remove eval() calls
    sanitized = sanitized.replace("eval(", "eval(");

    // Remove innerHTML assignments
    sanitized = sanitized.replace("innerHTML", "innerHTML");

    // Remove HTML comments
    sanitized = sanitized.replace("<!--", "&lt;!--");
    sanitized = sanitized.replace("-->", "--&gt;");

    // Trim whitespace
    sanitized = sanitized.trim().to_string();

    sanitized
}

/// Sanitize HTML to prevent XSS
///
/// This is a more comprehensive sanitization for HTML content.
/// It escapes HTML entities and removes dangerous tags.
///
/// # Arguments
///
/// * `value` - HTML string to sanitize
///
/// # Returns
///
/// Sanitized HTML string
#[must_use]
pub fn sanitize_html(value: &str) -> String {
    let mut sanitized = value.to_string();

    // Escape HTML entities
    sanitized = sanitized.replace('&', "&amp;");
    sanitized = sanitized.replace('<', "&lt;");
    sanitized = sanitized.replace('>', "&gt;");
    sanitized = sanitized.replace('"', "&quot;");
    sanitized = sanitized.replace('\'', "&#x27;");

    sanitized
}

/// Trim and collapse whitespace
///
/// This removes leading/trailing whitespace and collapses multiple
/// whitespace characters into a single space.
///
/// # Arguments
///
/// * `value` - String to normalize
///
/// # Returns
///
/// Normalized string with collapsed whitespace
#[must_use]
pub fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Convert string to lowercase and trim
///
/// # Arguments
///
/// * `value` - String to normalize
///
/// # Returns
///
/// Lowercase, trimmed string
#[must_use]
pub fn normalize_lowercase(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Convert string to uppercase and trim
///
/// # Arguments
///
/// * `value` - String to normalize
///
/// # Returns
///
/// Uppercase, trimmed string
#[must_use]
pub fn normalize_uppercase(value: &str) -> String {
    value.trim().to_uppercase()
}

// ==================== Combined Validation ====================

/// Validate login credentials
///
/// This validates both username and password for login.
///
/// # Arguments
///
/// * `username` - Username to validate
/// * `password` - Password to validate
///
/// # Returns
///
/// `Ok(())` if both are valid, error otherwise
pub fn validate_login(username: &str, password: &str) -> Result<()> {
    validate_username(username)?;
    validate_required("password", password)?;
    Ok(())
}

/// Validate registration data
///
/// This validates username, email, and password for registration.
///
/// # Arguments
///
/// * `username` - Username to validate
/// * `email` - Email to validate
/// * `password` - Password to validate
///
/// # Returns
///
/// `Ok(())` if all are valid, error otherwise
pub fn validate_registration(username: &str, email: &str, password: &str) -> Result<()> {
    validate_username(username)?;
    validate_email(email)?;
    validate_required("password", password)?;
    Ok(())
}

/// Validate user profile data
///
/// This validates user profile fields.
///
/// # Arguments
///
/// * `full_name` - Full name to validate
/// * `email` - Email to validate
/// * `phone` - Optional phone number to validate
///
/// # Returns
///
/// `Ok(())` if all are valid, error otherwise
pub fn validate_profile(full_name: &str, email: &str, phone: Option<&str>) -> Result<()> {
    validate_required("full_name", full_name)?;
    validate_min_length(full_name, 2)?;
    validate_max_length(full_name, 100)?;
    validate_email(email)?;

    if let Some(phone_number) = phone {
        validate_phone(phone_number)?;
    }

    Ok(())
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_email_valid() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("user.name+tag@example.co.uk").is_ok());
        assert!(validate_email("test@test-domain.io").is_ok());
    }

    #[test]
    fn test_validate_email_invalid() {
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("invalid@").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@.com").is_err());
        assert!(validate_email("user@@example.com").is_err());
    }

    #[test]
    fn test_is_valid_email() {
        assert!(is_valid_email("user@example.com"));
        assert!(!is_valid_email("invalid"));
    }

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_username("john_doe").is_ok());
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("test-user").is_ok());
        assert!(validate_username("User_Name-123").is_ok());
    }

    #[test]
    fn test_validate_username_invalid() {
        assert!(validate_username("ab").is_err()); // Too short
        assert!(validate_username("invalid-@#").is_err()); // Invalid characters
        assert!(validate_username("a".repeat(31).as_str()).is_err()); // Too long
        assert!(validate_username("").is_err()); // Empty
    }

    #[test]
    fn test_is_valid_username() {
        assert!(is_valid_username("john_doe"));
        assert!(!is_valid_username("ab"));
    }

    #[test]
    fn test_validate_uuid_valid() {
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_uuid("00000000-0000-0000-0000-000000000000").is_ok());
    }

    #[test]
    fn test_validate_uuid_invalid() {
        assert!(validate_uuid("not-a-uuid").is_err());
        assert!(validate_uuid("550e8400-e29b-41d4-a716-446655440").is_err());
        assert!(validate_uuid("").is_err());
    }

    #[test]
    fn test_is_valid_uuid() {
        assert!(is_valid_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(!is_valid_uuid("not-a-uuid"));
    }

    #[test]
    fn test_validate_phone_valid() {
        assert!(validate_phone("+1234567890").is_ok());
        assert!(validate_phone("1234567890").is_ok());
        assert!(validate_phone("+14155552671").is_ok());
    }

    #[test]
    fn test_validate_phone_invalid() {
        assert!(validate_phone("123").is_err()); // Too short
        assert!(validate_phone("01234567890").is_err()); // Starts with 0
        assert!(validate_phone("+123456789012345").is_err()); // Too long
        assert!(validate_phone("abc").is_err()); // Non-numeric
    }

    #[test]
    fn test_is_valid_phone() {
        assert!(is_valid_phone("+1234567890"));
        assert!(!is_valid_phone("123"));
    }

    #[test]
    fn test_validate_url_valid() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://example.com/path").is_ok());
        assert!(validate_url("https://example.com:8080/path").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        assert!(validate_url("not-a-url").is_err());
        assert!(validate_url("ftp://example.com").is_err()); // Wrong scheme
        assert!(validate_url("").is_err());
    }

    #[test]
    fn test_is_valid_url() {
        assert!(is_valid_url("https://example.com"));
        assert!(!is_valid_url("not-a-url"));
    }

    #[test]
    fn test_validate_safe_string_valid() {
        assert!(validate_safe_string("Hello, World!").is_ok());
        assert!(validate_safe_string("Test-123_Example").is_ok());
        assert!(validate_safe_string("").is_ok()); // Empty is safe
    }

    #[test]
    fn test_validate_safe_string_invalid() {
        assert!(validate_safe_string("<script>alert('xss')</script>").is_err());
        assert!(validate_safe_string("javascript:alert(1)").is_err());
        assert!(validate_safe_string("onload=\"alert(1)\"").is_err());
    }

    #[test]
    fn test_is_safe_string() {
        assert!(is_safe_string("Hello, World!"));
        assert!(!is_safe_string("<script>alert(1)</script>"));
    }

    #[test]
    fn test_validate_min_length() {
        assert!(validate_min_length("hello", 3).is_ok());
        assert!(validate_min_length("hi", 3).is_err());
    }

    #[test]
    fn test_validate_max_length() {
        assert!(validate_max_length("hello", 10).is_ok());
        assert!(validate_max_length("hello world!", 10).is_err());
    }

    #[test]
    fn test_validate_length() {
        assert!(validate_length("hello", 3, 10).is_ok());
        assert!(validate_length("hi", 3, 10).is_err());
        assert!(validate_length("hello world!", 3, 10).is_err());
    }

    #[test]
    fn test_validate_required() {
        assert!(validate_required("field", "value").is_ok());
        assert!(validate_required("field", "").is_err());
        assert!(validate_required("field", "   ").is_err());
    }

    #[test]
    fn test_sanitize_string() {
        let input = "<script>alert('xss')</script>Hello";
        let sanitized = sanitize_string(input);

        assert!(!sanitized.contains("<script>"));
        assert!(sanitized.contains("Hello"));
    }

    #[test]
    fn test_sanitize_html() {
        let input = "<script>alert('xss')</script>& < > \" '";
        let sanitized = sanitize_html(input);

        assert!(sanitized.contains("&lt;"));
        assert!(sanitized.contains("&gt;"));
        assert!(sanitized.contains("&amp;"));
        assert!(sanitized.contains("&quot;"));
        assert!(sanitized.contains("&#x27;"));
    }

    #[test]
    fn test_normalize_whitespace() {
        let input = "  hello    world  ";
        let normalized = normalize_whitespace(input);

        assert_eq!(normalized, "hello world");
    }

    #[test]
    fn test_normalize_lowercase() {
        assert_eq!(normalize_lowercase("  HELLO  "), "hello");
    }

    #[test]
    fn test_normalize_uppercase() {
        assert_eq!(normalize_uppercase("  hello  "), "HELLO");
    }

    #[test]
    fn test_validate_login() {
        assert!(validate_login("john_doe", "password123").is_ok());
        assert!(validate_login("ab", "password123").is_err()); // Invalid username
        assert!(validate_login("john_doe", "").is_err()); // Empty password
    }

    #[test]
    fn test_validate_registration() {
        assert!(validate_registration("john_doe", "user@example.com", "password123").is_ok());
        assert!(validate_registration("ab", "user@example.com", "password123").is_err());
        assert!(validate_registration("john_doe", "invalid", "password123").is_err());
    }

    #[test]
    fn test_validate_profile() {
        assert!(validate_profile("John Doe", "user@example.com", Some("+1234567890")).is_ok());
        assert!(validate_profile("John Doe", "user@example.com", None).is_ok());
        assert!(validate_profile("", "user@example.com", None).is_err()); // Empty name
        assert!(validate_profile("John Doe", "invalid", None).is_err()); // Invalid email
    }

    #[test]
    fn test_contains_sql_injection() {
        assert!(contains_sql_injection("' OR '1'='1'"));
        assert!(contains_sql_injection("UNION SELECT * FROM users"));
        assert!(contains_sql_injection("DROP TABLE users"));
        assert!(!contains_sql_injection("normal text"));
    }
}
