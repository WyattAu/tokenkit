/// Extract a Bearer token from an Authorization header value.
///
/// Expects the format `"Bearer <token>"`. Returns `None` if the
/// header doesn't match.
///
/// # Example
///
/// ```rust
/// use tokenkit::extractors::extract_bearer_token;
///
/// assert_eq!(extract_bearer_token("Bearer abc123"), Some("abc123".to_string()));
/// assert_eq!(extract_bearer_token("Basic abc123"), None);
/// ```
pub fn extract_bearer_token(authorization: &str) -> Option<String> {
    authorization
        .strip_prefix("Bearer ")
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Build a Set-Cookie header value for an HTTP-only authentication cookie.
///
/// # Example
///
/// ```rust
/// use tokenkit::extractors::build_auth_cookie;
///
/// let cookie = build_auth_cookie("session", "jwt_token_here", 3600, true);
/// assert!(cookie.contains("session=jwt_token_here"));
/// assert!(cookie.contains("HttpOnly"));
/// ```
pub fn build_auth_cookie(name: &str, value: &str, max_age_secs: i64, secure: bool) -> String {
    let mut cookie = format!("{name}={value}; Max-Age={max_age_secs}; Path=/; HttpOnly; SameSite=Strict");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}
