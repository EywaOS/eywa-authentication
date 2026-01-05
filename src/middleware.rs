//! # Middleware for Authentication and Security

use axum::{
    extract::{FromRequestParts, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::Response,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::error::AuthError;
use crate::jwt::{Claims, JwtService};
use crate::ratelimit::{RateLimitError, RateLimiter};
use eywa_errors::AppError;

// ==================== Auth Extractor ====================

/// Authentication extractor for Axum handlers
///
/// This extractor retrieves the JWT claims from the request extensions.
/// It assumes that `auth_middleware` has already run and validated the token.
#[derive(Debug, Clone)]
pub struct AuthExtractor {
    pub claims: Claims,
    pub token: String,
}

impl<S> FromRequestParts<S> for AuthExtractor
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<Claims>()
            .ok_or::<AppError>(AuthError::MissingAuthToken.into())?
            .clone();

        // access token might not be stored in extensions, but we can try to extract it again if needed
        // or just store it in middleware. For now, let's re-extract or store in middleware.
        // Let's modify middleware to store the token too if we want it here.
        // But for simplicity, let's extract it from header again.
        let token =
            extract_jwt_token_from_headers(&parts.headers).map_err(|e| -> AppError { e.into() })?;

        Ok(Self { claims, token })
    }
}

// ==================== Auth Middleware ====================

/// Authentication middleware
///
/// This middleware validates the JWT token in the Authorization header.
/// If valid, it stores the claims in the request extensions.
pub async fn auth_middleware(
    State(jwt_service): State<Arc<JwtService>>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, AppError> {
    let token =
        extract_jwt_token_from_headers(request.headers()).map_err(|e| -> AppError { e.into() })?;

    let claims = jwt_service.validate_token(&token)?;

    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

// ==================== Rate Limit Middleware ====================

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    State(limiter): State<Arc<RateLimiter>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, RateLimitError> {
    // Extract IP address from connection info
    let key = extract_client_ip(&request);

    // Check rate limit
    limiter.check(&key).await?;

    debug!("Rate limit check passed for key: {}", key);

    Ok(next.run(request).await)
}

// ==================== Security Headers Middleware ====================

/// Security headers middleware
///
/// Adds common security headers to responses:
/// - X-XSS-Protection
/// - X-Content-Type-Options
/// - X-Frame-Options
/// - Strict-Transport-Security
/// - Content-Security-Policy
pub async fn security_headers_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Strict-Transport-Security",
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_static("default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
    );
    headers.insert(
        "Referrer-Policy",
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    response
}

// ==================== Login Attempt Tracker ====================

/// Login attempt tracker for brute force protection
#[derive(Debug, Clone)]
pub struct LoginAttemptTracker {
    attempts: Arc<RwLock<HashMap<String, LoginAttempts>>>,
    max_attempts: u32,
    lockout_duration: Duration,
}

#[derive(Debug, Clone)]
struct LoginAttempts {
    count: u32,
    last_attempt: Instant,
    locked_until: Option<Instant>,
}

impl LoginAttemptTracker {
    /// Create a new login attempt tracker
    pub fn new(max_attempts: u32, lockout_duration: Duration) -> Self {
        Self {
            attempts: Arc::new(RwLock::new(HashMap::new())),
            max_attempts,
            lockout_duration,
        }
    }

    /// Record a failed login attempt
    pub async fn record_failure(&self, key: &str) -> Result<(), AuthError> {
        let mut attempts = self.attempts.write().await;
        let now = Instant::now();

        let entry = attempts
            .entry(key.to_string())
            .or_insert_with(|| LoginAttempts {
                count: 0,
                last_attempt: now,
                locked_until: None,
            });

        // Check if currently locked out
        if let Some(locked_until) = entry.locked_until {
            if now < locked_until {
                let remaining = locked_until.duration_since(now).as_secs();
                return Err(AuthError::AccountLocked { seconds: remaining });
            } else {
                // Lockout expired, reset
                entry.count = 0;
                entry.locked_until = None;
            }
        }

        // Increment attempt count
        entry.count += 1;
        entry.last_attempt = now;

        // Check if should lock out
        if entry.count >= self.max_attempts {
            entry.locked_until = Some(now + self.lockout_duration);
            return Err(AuthError::AccountLocked {
                seconds: self.lockout_duration.as_secs(),
            });
        }

        Ok(())
    }

    /// Record successful login (reset attempts)
    pub async fn record_success(&self, key: &str) {
        let mut attempts = self.attempts.write().await;
        attempts.remove(key);
    }

    /// Check if key is locked out
    pub async fn is_locked_out(&self, key: &str) -> bool {
        let attempts = self.attempts.read().await;
        let now = Instant::now();

        attempts
            .get(key)
            .map(|entry| entry.locked_until.map_or(false, |locked| now < locked))
            .unwrap_or(false)
    }

    /// Get remaining attempts before lockout
    pub async fn remaining_attempts(&self, key: &str) -> u32 {
        let attempts = self.attempts.read().await;

        attempts
            .get(key)
            .map(|entry| self.max_attempts.saturating_sub(entry.count))
            .unwrap_or(self.max_attempts)
    }
}

// ==================== Security Check Middleware ====================

/// Security check middleware
pub async fn security_check_middleware(
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for suspicious headers
    let headers = request.headers();

    // Check User-Agent
    if let Some(user_agent) = headers.get("user-agent") {
        let user_agent_str = user_agent.to_str().unwrap_or("");
        if is_suspicious_user_agent(user_agent_str) {
            warn!("Suspicious User-Agent: {}", user_agent_str);
            return Err(StatusCode::FORBIDDEN);
        }
    }

    // Check for common attack patterns in URI
    let uri = request.uri().to_string();
    if is_suspicious_uri(&uri) {
        warn!("Suspicious URI: {}", uri);
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

// ==================== Helper Functions ====================

/// Extract JWT token from Authorization header
fn extract_jwt_token_from_headers(headers: &HeaderMap) -> Result<String, AuthError> {
    let auth_header = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingAuthToken)?
        .to_str()
        .map_err(|_| AuthError::InvalidAuthFormat)?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AuthError::InvalidAuthFormat);
    }

    Ok(auth_header[7..].to_string())
}

/// Extract client IP from request
fn extract_client_ip(request: &Request<axum::body::Body>) -> String {
    // Try to get IP from headers (behind proxy)
    if let Some(forwarded_for) = request.headers().get("X-Forwarded-For") {
        if let Ok(ip) = forwarded_for.to_str() {
            // Take first IP from list
            if let Some(first_ip) = ip.split(',').next() {
                return first_ip.trim().to_string();
            }
        }
    }

    if let Some(real_ip) = request.headers().get("X-Real-IP") {
        if let Ok(ip) = real_ip.to_str() {
            return ip.to_string();
        }
    }

    // Fall back to connection info (simplified)
    "unknown".to_string()
}

/// Check for suspicious user agents
fn is_suspicious_user_agent(user_agent: &str) -> bool {
    let suspicious_patterns = vec![
        "sqlmap", "nikto", "nmap", "curl", "wget", "python", "bot", "spider", "crawler", "scraper",
        "test",
    ];

    let lower = user_agent.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|pattern| lower.contains(pattern))
}

/// Check for suspicious URI patterns
fn is_suspicious_uri(uri: &str) -> bool {
    let suspicious_patterns = vec![
        "../",
        "..\\",
        "<script",
        "javascript:",
        "alert(",
        "eval(",
        "document.cookie",
        "union select",
        "or 1=1",
        "drop table",
        "exec(",
        "xp_cmdshell",
        "<iframe",
        "onerror=",
        "onload=",
        "onclick=",
        "onfocus=",
        "<!--",
        "-->",
    ];

    let lower = uri.to_lowercase();
    suspicious_patterns
        .iter()
        .any(|pattern| lower.contains(pattern))
}

// ==================== Tests ====================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_jwt_token_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer my_token".parse().unwrap());

        let token = extract_jwt_token_from_headers(&headers).unwrap();
        assert_eq!(token, "my_token");
    }

    #[test]
    fn test_extract_jwt_token_missing() {
        let headers = HeaderMap::new();

        let result = extract_jwt_token_from_headers(&headers);
        assert!(matches!(result, Err(AuthError::MissingAuthToken)));
    }

    #[test]
    fn test_extract_jwt_token_invalid_format() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "InvalidFormat".parse().unwrap());

        let result = extract_jwt_token_from_headers(&headers);
        assert!(matches!(result, Err(AuthError::InvalidAuthFormat)));
    }

    #[test]
    fn test_is_suspicious_user_agent() {
        assert!(is_suspicious_user_agent("sqlmap/1.0"));
        assert!(is_suspicious_user_agent("curl/7.0"));
        assert!(is_suspicious_user_agent(
            "Mozilla/5.0 (compatible; Googlebot/2.1)"
        ));
        assert!(!is_suspicious_user_agent("Mozilla/5.0 (Windows NT 10.0)"));
    }

    #[test]
    fn test_is_suspicious_uri() {
        assert!(is_suspicious_uri("/path/../etc/passwd"));
        assert!(is_suspicious_uri("/path<script>alert('xss')</script>"));
        assert!(is_suspicious_uri("/search?q=' OR '1'='1"));
        assert!(!is_suspicious_uri("/api/users"));
        assert!(!is_suspicious_uri("/search?q=test"));
    }

    #[tokio::test]
    async fn test_rate_limiter_middleware_logic() {
        let limiter = Arc::new(RateLimiter::new(5, Duration::from_secs(60)));
        let key = "unknown";

        // We can't easily test middleware flow here without setting up a full Axum service
        // But we can test the limiter logic which is what matters
        for _ in 0..5 {
            assert!(limiter.check(key).await.is_ok());
        }

        assert!(matches!(
            limiter.check(key).await,
            Err(RateLimitError::TooManyRequests)
        ));
    }
}
