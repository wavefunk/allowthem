use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
pub use governor::Quota;
use governor::RateLimiter;
use governor::clock::{Clock, DefaultClock, QuantaInstant};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DashMapStateStore;

type KeyedLimiter =
    RateLimiter<String, DashMapStateStore<String>, DefaultClock, NoOpMiddleware<QuantaInstant>>;

/// A keyed rate limiter for IP-based throttling.
///
/// Create one per endpoint group with the desired quota, store it in your
/// app state, and call `check` at the top of the handler.
#[derive(Clone)]
pub struct AuthRateLimiter {
    inner: Arc<KeyedLimiter>,
}

impl AuthRateLimiter {
    pub fn new(quota: Quota) -> Self {
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    #[allow(clippy::result_large_err)]
    pub fn check(&self, key: &str) -> Result<(), Response> {
        match self.inner.check_key(&key.to_owned()) {
            Ok(_) => Ok(()),
            Err(not_until) => {
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                let retry_after = wait.as_secs().saturating_add(1);
                Err(rate_limit_response(retry_after))
            }
        }
    }
}

/// Extract the client IP address from request extensions.
///
/// Returns the IP as a string, or `"unknown"` if `ConnectInfo` is not present.
/// Requires the server to use `into_make_service_with_connect_info::<SocketAddr>()`.
pub fn extract_client_ip(extensions: &axum::http::Extensions) -> String {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn rate_limit_response(retry_after_secs: u64) -> Response {
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        format!(
            "Too many requests. Retry after {} seconds.",
            retry_after_secs
        ),
    )
        .into_response();
    if let Ok(val) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert("retry-after", val);
    }
    response
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::*;

    #[test]
    fn requests_within_burst_are_allowed() {
        let limiter = AuthRateLimiter::new(Quota::per_minute(NonZeroU32::new(3).unwrap()));
        let ip = "127.0.0.1";
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn requests_exceeding_burst_get_429() {
        let limiter = AuthRateLimiter::new(Quota::per_minute(NonZeroU32::new(2).unwrap()));
        let ip = "192.168.1.1";
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        let err = limiter.check(ip).unwrap_err();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(err.headers().contains_key("retry-after"));
    }

    #[test]
    fn different_keys_have_independent_limits() {
        let limiter = AuthRateLimiter::new(Quota::per_minute(NonZeroU32::new(1).unwrap()));
        assert!(limiter.check("10.0.0.1").is_ok());
        assert!(limiter.check("10.0.0.2").is_ok());
        // First IP is now limited, second is not
        assert!(limiter.check("10.0.0.1").is_err());
        assert!(limiter.check("10.0.0.3").is_ok());
    }

    #[test]
    fn extract_client_ip_returns_unknown_without_connect_info() {
        let extensions = axum::http::Extensions::new();
        assert_eq!(extract_client_ip(&extensions), "unknown");
    }
}
