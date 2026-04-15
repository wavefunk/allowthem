use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::COOKIE;
use axum::http::request::Parts;

use allowthem_core::{AllowThem, AuthError, User};

use crate::error::AuthExtractError;

/// Axum extractor that provides the authenticated user.
///
/// Reads the session cookie, validates the session (with sliding-window
/// renewal), and fetches the user. Rejects with 401 if not authenticated.
///
/// Usage: `AuthUser(user): AuthUser` in handler arguments.
pub struct AuthUser(pub User);

impl<S> FromRequestParts<S> for AuthUser
where
    AllowThem: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthExtractError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ath = AllowThem::from_ref(state);

        let cookie_header = parts
            .headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthExtractError::Unauthenticated)?;

        let token = ath
            .parse_session_cookie(cookie_header)
            .ok_or(AuthExtractError::Unauthenticated)?;

        let session = ath
            .db()
            .validate_session(&token, ath.session_config().ttl)
            .await
            .map_err(AuthExtractError::Internal)?
            .ok_or(AuthExtractError::Unauthenticated)?;

        let user = ath
            .db()
            .get_user(session.user_id)
            .await
            .map_err(|e| match e {
                AuthError::NotFound => AuthExtractError::Unauthenticated,
                other => AuthExtractError::Internal(other),
            })?;

        if !user.is_active {
            return Err(AuthExtractError::Inactive);
        }

        Ok(AuthUser(user))
    }
}

/// Axum extractor that optionally provides the authenticated user.
///
/// Same flow as [`AuthUser`] but wraps `Option<User>` and never rejects.
/// Returns `None` when not authenticated. Returns `Some(user)` when valid.
/// Internal errors (database failures) are logged and treated as `None`.
///
/// Usage: `OptionalAuthUser(user): OptionalAuthUser` in handler arguments.
pub struct OptionalAuthUser(pub Option<User>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    AllowThem: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(AuthUser(user)) => Ok(OptionalAuthUser(Some(user))),
            Err(AuthExtractError::Internal(err)) => {
                tracing::error!("auth extraction error: {err}");
                Ok(OptionalAuthUser(None))
            }
            Err(_) => Ok(OptionalAuthUser(None)),
        }
    }
}
