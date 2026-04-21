use axum::Router;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Serialize;

use allowthem_core::{AllowThem, has_scope};

use crate::oauth_bearer::{OAuthBearerError, OAuthBearerToken};

#[derive(Debug, Serialize)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_data: Option<serde_json::Value>,
}

async fn userinfo(
    OAuthBearerToken(claims): OAuthBearerToken,
    Extension(ath): Extension<AllowThem>,
) -> Response {
    // 1. Fetch user by claims.sub
    let user = match ath.db().get_user(claims.sub).await {
        Ok(u) => u,
        Err(_) => {
            return OAuthBearerError::InvalidToken("user not found".into()).into_response();
        }
    };

    // 2. Check user is active
    if !user.is_active {
        return OAuthBearerError::InvalidToken("user not found".into()).into_response();
    }

    // 3. Build response based on granted scopes
    let scope = &claims.scope;
    let mut response = UserInfoResponse {
        sub: user.id.to_string(),
        preferred_username: None,
        email: None,
        email_verified: None,
        custom_data: None,
    };

    if has_scope(scope, "profile") {
        response.preferred_username = user.username.as_ref().map(|u| u.as_str().to_owned());
        response.custom_data = user.custom_data.clone();
    }

    if has_scope(scope, "email") {
        response.email = Some(user.email.as_str().to_owned());
        response.email_verified = Some(user.email_verified);
    }

    (StatusCode::OK, axum::Json(response)).into_response()
}

pub fn userinfo_route() -> Router<()> {
    Router::new().route("/oauth/userinfo", get(userinfo).post(userinfo))
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::decrypt_private_key;
    use allowthem_core::{AllowThem, AllowThemBuilder, Email, UserId};
    use axum::http::{Request, StatusCode, header::AUTHORIZATION};
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use serde::Serialize;
    use tower::ServiceExt;

    const ENC_KEY: [u8; 32] = [0x42; 32];
    const ISSUER: &str = "https://auth.example.com";

    #[derive(Serialize)]
    struct TestClaims {
        sub: String,
        scope: String,
        iss: String,
        aud: String,
        exp: i64,
        iat: i64,
    }

    async fn sign_jwt(ath: &AllowThem, sub: &UserId, scope: &str, exp_offset: i64) -> String {
        let key = ath.db().create_signing_key(&ENC_KEY).await.unwrap();
        ath.db().activate_signing_key(key.id).await.unwrap();

        let pem = decrypt_private_key(&key, &ENC_KEY).unwrap();
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = TestClaims {
            sub: sub.to_string(),
            scope: scope.to_string(),
            iss: ISSUER.to_string(),
            aud: "ath_test_client".to_string(),
            exp: now + exp_offset,
            iat: now,
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.id.to_string());

        jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap()
    }

    async fn test_setup() -> (AllowThem, axum::Router, UserId) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(ENC_KEY)
            .base_url(ISSUER)
            .build()
            .await
            .unwrap();

        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let app = userinfo_route().layer(axum::middleware::from_fn_with_state(ath.clone(), crate::cors::inject_ath_into_extensions));

        (ath, app, user.id)
    }

    fn bearer_request(jwt: &str) -> Request<axum::body::Body> {
        Request::builder()
            .uri("/oauth/userinfo")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .unwrap()
    }

    async fn read_json(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn userinfo_returns_all_claims_for_full_scope() {
        let (ath, app, user_id) = test_setup().await;
        let jwt = sign_jwt(&ath, &user_id, "openid profile email", 300).await;

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
        assert!(body.get("email").is_some());
        assert!(body.get("email_verified").is_some());
    }

    #[tokio::test]
    async fn userinfo_openid_only_returns_sub() {
        let (ath, app, user_id) = test_setup().await;
        let jwt = sign_jwt(&ath, &user_id, "openid", 300).await;

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
        assert!(body.get("preferred_username").is_none());
        assert!(body.get("email").is_none());
        assert!(body.get("email_verified").is_none());
    }

    #[tokio::test]
    async fn userinfo_profile_without_username_omits_field() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(ENC_KEY)
            .base_url(ISSUER)
            .build()
            .await
            .unwrap();

        // Create user with no username
        let email = Email::new("nousername@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let jwt = sign_jwt(&ath, &user.id, "openid profile", 300).await;
        let app = userinfo_route().layer(axum::middleware::from_fn_with_state(ath, crate::cors::inject_ath_into_extensions));

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
        assert!(body.get("preferred_username").is_none());
    }

    #[tokio::test]
    async fn userinfo_inactive_user_returns_401() {
        let (ath, app, user_id) = test_setup().await;
        let jwt = sign_jwt(&ath, &user_id, "openid profile email", 300).await;

        // Deactivate user
        ath.db().update_user_active(user_id, false).await.unwrap();

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().contains_key("WWW-Authenticate"));
    }

    #[tokio::test]
    async fn userinfo_post_works_same_as_get() {
        let (ath, app, user_id) = test_setup().await;
        let jwt = sign_jwt(&ath, &user_id, "openid profile email", 300).await;

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/userinfo")
            .header(AUTHORIZATION, format!("Bearer {jwt}"))
            .body(axum::body::Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
    }

    #[tokio::test]
    async fn userinfo_expired_token_returns_401() {
        let (ath, app, user_id) = test_setup().await;
        let jwt = sign_jwt(&ath, &user_id, "openid", -60).await;

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("token expired"));
    }

    #[tokio::test]
    async fn userinfo_includes_custom_data_with_profile_scope() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(ENC_KEY)
            .base_url(ISSUER)
            .build()
            .await
            .unwrap();

        let email = Email::new("custom@example.com".into()).unwrap();
        let custom = serde_json::json!({"role": "admin", "plan": "pro"});
        let user = ath
            .db()
            .create_user(email, "password123", None, Some(&custom))
            .await
            .unwrap();

        let jwt = sign_jwt(&ath, &user.id, "openid profile", 300).await;
        let app = userinfo_route().layer(axum::middleware::from_fn_with_state(ath, crate::cors::inject_ath_into_extensions));

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
        assert_eq!(body["custom_data"]["role"], "admin");
        assert_eq!(body["custom_data"]["plan"], "pro");
    }

    #[tokio::test]
    async fn userinfo_omits_custom_data_without_profile_scope() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(ENC_KEY)
            .base_url(ISSUER)
            .build()
            .await
            .unwrap();

        let email = Email::new("custom2@example.com".into()).unwrap();
        let custom = serde_json::json!({"role": "admin"});
        let user = ath
            .db()
            .create_user(email, "password123", None, Some(&custom))
            .await
            .unwrap();

        let jwt = sign_jwt(&ath, &user.id, "openid email", 300).await;
        let app = userinfo_route().layer(axum::middleware::from_fn_with_state(ath, crate::cors::inject_ath_into_extensions));

        let resp = app.oneshot(bearer_request(&jwt)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = read_json(resp).await;
        assert!(body.get("sub").is_some());
        assert!(body.get("custom_data").is_none());
    }
}
