//! HTMX request detection.
//!
//! Any request carrying `HX-Request: true` means the client wants a
//! fragment response instead of a full page render. We don't distinguish
//! `HX-Boosted` — both cases are treated the same.

use axum::http::HeaderMap;

/// Returns `true` if the request carries the `HX-Request: true` header.
pub fn is_hx_request(headers: &HeaderMap) -> bool {
    headers
        .get("HX-Request")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn missing_header_returns_false() {
        let headers = HeaderMap::new();
        assert!(!is_hx_request(&headers));
    }

    #[test]
    fn header_value_true_returns_true() {
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", HeaderValue::from_static("true"));
        assert!(is_hx_request(&headers));
    }

    #[test]
    fn header_value_false_returns_false() {
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", HeaderValue::from_static("false"));
        assert!(!is_hx_request(&headers));
    }

    #[test]
    fn header_value_mixed_case_returns_true() {
        let mut headers = HeaderMap::new();
        headers.insert("HX-Request", HeaderValue::from_static("True"));
        assert!(is_hx_request(&headers));
    }
}
