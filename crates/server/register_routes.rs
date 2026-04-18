use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use axum::Form;
use axum::extract::{Query, State};
use axum::http::header::{COOKIE, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use chrono::Utc;
use minijinja::{Environment, context};
use serde::Deserialize;

use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::ClientId;
use allowthem_core::{AllowThem, AuditEvent, AuthError, Email, Username, generate_token, hash_token};

use crate::branding::{compute_accent_variants, default_accents, lookup_branding};
use crate::browser_error::BrowserError;
use crate::csrf::CsrfToken;
use crate::custom_fields::{
    CustomFieldDescriptor, CustomSchemaConfig, extract_and_coerce_custom_data,
    format_validation_errors,
};

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Clone)]
struct RegisterConfig {
    templates: Arc<Environment<'static>>,
    is_production: bool,
    custom_schema: Option<Arc<CustomSchemaConfig>>,
}

#[derive(Deserialize)]
struct RegisterQuery {
    #[serde(default)]
    client_id: Option<ClientId>,
}

/// GET /register — render the registration form.
///
/// If the user already has a valid session, redirects to `/`.
async fn get_register(
    State(ath): State<AllowThem>,
    Extension(config): Extension<RegisterConfig>,
    headers: HeaderMap,
    csrf: CsrfToken,
    Query(query): Query<RegisterQuery>,
) -> Result<Response, BrowserError> {
    if is_authenticated(&ath, &headers).await {
        return Ok((StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, "/")]).into_response());
    }

    let branding = lookup_branding(&ath, query.client_id.as_ref()).await;
    let custom_fields = config
        .custom_schema
        .as_ref()
        .map(|s| s.fields.as_slice())
        .unwrap_or(&[]);
    let empty: HashMap<String, String> = HashMap::new();

    let html = render_register_form(
        &config,
        RegisterFormParams {
            csrf_token: csrf.as_str(),
            email: "",
            username: "",
            error: "",
            client_id: query.client_id.as_ref(),
            branding: branding.as_ref(),
            custom_fields,
            custom_values: &empty,
        },
    )?;
    Ok(html.into_response())
}

/// POST /register — validate input, create user, start session, redirect.
///
/// Uses a raw `HashMap<String, String>` form extraction to capture both
/// standard fields and custom_data[*] fields in one pass.
async fn post_register(
    State(ath): State<AllowThem>,
    Extension(config): Extension<RegisterConfig>,
    csrf: CsrfToken,
    Query(query): Query<RegisterQuery>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, BrowserError> {
    let branding = lookup_branding(&ath, query.client_id.as_ref()).await;
    let cid = query.client_id.as_ref();
    let br = branding.as_ref();

    let custom_fields = config
        .custom_schema
        .as_ref()
        .map(|s| s.fields.as_slice())
        .unwrap_or(&[]);

    // Extract standard form fields with empty defaults
    let email_raw = form.get("email").map(String::as_str).unwrap_or("");
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let password_confirm = form
        .get("password_confirm")
        .map(String::as_str)
        .unwrap_or("");
    let username_raw = form.get("username").map(String::as_str).unwrap_or("");

    // 1. Validate passwords match
    if password != password_confirm {
        return render_form_error(
            &config,
            &csrf,
            email_raw,
            username_raw,
            "Passwords do not match",
            cid,
            br,
            custom_fields,
            &form,
        );
    }

    // 2. Validate password length
    if password.len() < MIN_PASSWORD_LEN {
        return render_form_error(
            &config,
            &csrf,
            email_raw,
            username_raw,
            "Password must be at least 8 characters",
            cid,
            br,
            custom_fields,
            &form,
        );
    }

    // 3. Parse email
    let email = match Email::new(email_raw.to_string()) {
        Ok(e) => e,
        Err(_) => {
            return render_form_error(
                &config,
                &csrf,
                email_raw,
                username_raw,
                "Invalid email address",
                cid,
                br,
                custom_fields,
                &form,
            );
        }
    };

    // 4. Parse username
    let trimmed = username_raw.trim();
    let username = if trimmed.is_empty() {
        None
    } else {
        Some(Username::new(trimmed))
    };

    // 5. Handle custom fields if a schema is configured
    let custom_data = if let Some(schema_config) = &config.custom_schema {
        let coerced = extract_and_coerce_custom_data(&form, &schema_config.schema);

        // Validate against the compiled schema
        let errors: Vec<_> = schema_config.validator.iter_errors(&coerced).collect();
        if !errors.is_empty() {
            let field_errors = format_validation_errors(&errors);
            let error_msg = field_errors
                .iter()
                .map(|(field, msg)| {
                    if field.is_empty() {
                        msg.clone()
                    } else {
                        format!("{field}: {msg}")
                    }
                })
                .collect::<Vec<_>>()
                .join("; ");

            return render_form_error(
                &config,
                &csrf,
                email_raw,
                username_raw,
                &error_msg,
                cid,
                br,
                custom_fields,
                &form,
            );
        }
        Some(coerced)
    } else {
        None
    };

    // 6. Create user
    let user = match ath
        .db()
        .create_user(email, password, username, custom_data.as_ref())
        .await
    {
        Ok(u) => u,
        Err(AuthError::Conflict(ref msg)) if msg.contains("email") => {
            return render_form_error(
                &config,
                &csrf,
                email_raw,
                username_raw,
                "An account with this email already exists",
                cid,
                br,
                custom_fields,
                &form,
            );
        }
        Err(AuthError::Conflict(ref msg)) if msg.contains("username") => {
            return render_form_error(
                &config,
                &csrf,
                email_raw,
                username_raw,
                "This username is already taken",
                cid,
                br,
                custom_fields,
                &form,
            );
        }
        Err(e) => return Err(BrowserError::Auth(e)),
    };

    // 7. Create session
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + ath.session_config().ttl;
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    ath.db()
        .create_session(user.id, token_hash, ip.as_deref(), ua, expires_at)
        .await?;

    // 8. Log audit event
    if let Err(e) = ath
        .db()
        .log_audit(
            AuditEvent::Register,
            Some(&user.id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await
    {
        tracing::error!(error = %e, "failed to log registration audit event");
    }

    // 9. Set session cookie and redirect
    let cookie = ath.session_cookie(&token);
    Ok((
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, "/".to_string()),
        ],
    )
        .into_response())
}

struct RegisterFormParams<'a> {
    csrf_token: &'a str,
    email: &'a str,
    username: &'a str,
    error: &'a str,
    client_id: Option<&'a ClientId>,
    branding: Option<&'a BrandingConfig>,
    custom_fields: &'a [CustomFieldDescriptor],
    custom_values: &'a HashMap<String, String>,
}

fn render_register_form(
    config: &RegisterConfig,
    params: RegisterFormParams<'_>,
) -> Result<axum::response::Html<String>, BrowserError> {
    let (accent, accent_hover, accent_ring) = params
        .branding
        .and_then(|b| b.primary_color.as_deref())
        .map(compute_accent_variants)
        .unwrap_or_else(default_accents);

    // Build a custom_values map keyed by field name (stripping custom_data[] prefix)
    let custom_values_map: HashMap<&str, &str> = params
        .custom_values
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix("custom_data[")
                .and_then(|s| s.strip_suffix(']'))
                .map(|name| (name, v.as_str()))
        })
        .collect();

    let RegisterFormParams {
        csrf_token,
        error,
        email,
        username,
        client_id,
        branding,
        custom_fields,
        ..
    } = params;
    crate::browser_templates::render(
        &config.templates,
        "register.html",
        context! {
            csrf_token,
            error,
            email,
            username,
            client_id => client_id.map(|c| c.as_str()),
            app_name => branding.map(|b| b.application_name.as_str()),
            logo_url => branding.and_then(|b| b.logo_url.as_deref()),
            accent,
            accent_hover,
            accent_ring,
            is_production => config.is_production,
            custom_fields,
            custom_values => custom_values_map,
        },
    )
}

/// Re-render the registration form with an error message and preserved input.
#[allow(clippy::too_many_arguments)]
fn render_form_error(
    config: &RegisterConfig,
    csrf: &CsrfToken,
    email: &str,
    username: &str,
    error: &str,
    client_id: Option<&ClientId>,
    branding: Option<&BrandingConfig>,
    custom_fields: &[CustomFieldDescriptor],
    form_data: &HashMap<String, String>,
) -> Result<Response, BrowserError> {
    let html = render_register_form(
        config,
        RegisterFormParams {
            csrf_token: csrf.as_str(),
            email,
            username,
            error,
            client_id,
            branding,
            custom_fields,
            custom_values: form_data,
        },
    )?;
    Ok(html.into_response())
}

/// Returns true if the request carries a valid session cookie.
async fn is_authenticated(ath: &AllowThem, headers: &HeaderMap) -> bool {
    let Some(cookie_header) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = ath.parse_session_cookie(cookie_header) else {
        return false;
    };
    let ttl = ath.session_config().ttl;
    ath.db()
        .validate_session(&token, ttl)
        .await
        .unwrap_or(None)
        .is_some()
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
}

pub fn register_routes(
    templates: Arc<Environment<'static>>,
    is_production: bool,
    custom_schema: Option<CustomSchemaConfig>,
) -> Router<AllowThem> {
    let cfg = RegisterConfig {
        templates,
        is_production,
        custom_schema: custom_schema.map(Arc::new),
    };
    Router::new()
        .route("/register", get(get_register).post(post_register))
        .layer(Extension(cfg))
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::json;
    use tower::ServiceExt;

    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuditEvent, Email, Username, parse_session_cookie,
    };

    use crate::custom_fields::{CustomSchemaConfig, extract_field_descriptors};

    use super::{RegisterConfig, register_routes};

    async fn setup() -> (AllowThem, RegisterConfig) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();
        let templates = crate::browser_templates::build_default_browser_env();
        let config = RegisterConfig {
            templates,
            is_production: false,
            custom_schema: None,
        };
        (ath, config)
    }

    fn test_app(ath: AllowThem, config: RegisterConfig) -> Router {
        register_routes(
            config.templates.clone(),
            config.is_production,
            config
                .custom_schema
                .as_ref()
                .map(|arc| CustomSchemaConfig {
                    schema: arc.schema.clone(),
                    validator: arc.validator.clone(),
                    fields: arc.fields.clone(),
                }),
        )
        .layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::csrf::csrf_middleware,
        ))
        .with_state(ath)
    }

    fn test_app_with_schema(ath: AllowThem, config: RegisterConfig) -> Router {
        let schema = json!({
            "type": "object",
            "required": ["company"],
            "properties": {
                "company": {
                    "type": "string",
                    "title": "Company Name",
                    "minLength": 1
                },
                "age": {
                    "type": "integer",
                    "minimum": 0
                },
                "newsletter": {
                    "type": "boolean"
                }
            }
        });
        let validator = jsonschema::validator_for(&schema).expect("valid schema");
        let fields = extract_field_descriptors(&schema);
        let schema_config = CustomSchemaConfig {
            schema,
            validator,
            fields,
        };

        register_routes(config.templates.clone(), config.is_production, Some(schema_config))
            .layer(axum::middleware::from_fn_with_state(
                ath.clone(),
                crate::csrf::csrf_middleware,
            ))
            .with_state(ath)
    }

    /// Send GET /register, extract the csrf_token cookie value from Set-Cookie.
    async fn get_csrf_token(app: &Router) -> String {
        let req = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        // Parse "csrf_token=<value>; ..." -> "<value>"
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_string()
    }

    fn register_request(
        csrf: &str,
        email: &str,
        password: &str,
        confirm: &str,
        username: &str,
    ) -> Request<Body> {
        // Minimal URL-encoding: replace @ with %40 for email addresses.
        // Test values use simple ASCII, so this is sufficient.
        let enc = |s: &str| s.replace('@', "%40");
        let body = format!(
            "csrf_token={}&email={}&password={}&password_confirm={}&username={}",
            csrf,
            enc(email),
            enc(password),
            enc(confirm),
            enc(username),
        );
        Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={}", csrf))
            .body(Body::from(body))
            .unwrap()
    }

    fn register_request_with_custom(
        csrf: &str,
        email: &str,
        password: &str,
        confirm: &str,
        username: &str,
        custom_fields: &[(&str, &str)],
    ) -> Request<Body> {
        let enc = |s: &str| s.replace('@', "%40");
        let mut body = format!(
            "csrf_token={}&email={}&password={}&password_confirm={}&username={}",
            csrf,
            enc(email),
            enc(password),
            enc(confirm),
            enc(username),
        );
        for (key, value) in custom_fields {
            body.push_str(&format!(
                "&custom_data%5B{}%5D={}",
                key,
                enc(value)
            ));
        }
        Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={}", csrf))
            .body(Body::from(body))
            .unwrap()
    }

    async fn body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn get_register_renders_form() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let req = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("<form"));
        assert!(html.contains("csrf_token"));
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("name=\"password_confirm\""));
    }

    #[tokio::test]
    async fn post_register_success_redirects() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "test@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("allowthem_session"));
    }

    #[tokio::test]
    async fn post_register_creates_user() {
        let (ath, config) = setup().await;
        let app = test_app(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "new@example.com",
            "password123",
            "password123",
            "myuser",
        );
        app.oneshot(req).await.unwrap();

        let email = Email::new("new@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        assert_eq!(user.email, email);
        assert_eq!(user.username.as_ref().map(|u| u.as_str()), Some("myuser"));
    }

    #[tokio::test]
    async fn post_register_creates_session() {
        let (ath, config) = setup().await;
        let app = test_app(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "sess@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();

        // Extract session token from Set-Cookie header and verify in DB
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let token = parse_session_cookie(set_cookie, "allowthem_session")
            .expect("session cookie should be present");
        let session = ath.db().lookup_session(&token).await.unwrap();
        assert!(session.is_some(), "session should exist in DB");
    }

    #[tokio::test]
    async fn post_register_logs_audit() {
        let (ath, config) = setup().await;
        let app = test_app(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "audit@example.com", "password123", "password123", "");
        app.oneshot(req).await.unwrap();

        let entries = ath.db().get_audit_log(None, 10, 0).await.unwrap();
        let register_entry = entries
            .iter()
            .find(|e| e.event_type == AuditEvent::Register);
        assert!(
            register_entry.is_some(),
            "register audit event should be recorded"
        );
    }

    #[tokio::test]
    async fn post_register_password_mismatch() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "mismatch@example.com",
            "password123",
            "different456",
            "",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Passwords do not match"));
        assert!(html.contains("mismatch@example.com"));
    }

    #[tokio::test]
    async fn post_register_password_too_short() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "short@example.com", "abc", "abc", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Password must be at least 8 characters"));
    }

    #[tokio::test]
    async fn post_register_invalid_email() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "not-an-email", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Invalid email address"));
    }

    #[tokio::test]
    async fn post_register_duplicate_email() {
        let (ath, config) = setup().await;
        // Pre-create user with this email
        let email = Email::new("dupe@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "existing123", None, None)
            .await
            .unwrap();

        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "dupe@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("An account with this email already exists"));
    }

    #[tokio::test]
    async fn post_register_duplicate_username() {
        let (ath, config) = setup().await;
        let email = Email::new("first@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "existing123", Some(Username::new("taken")), None)
            .await
            .unwrap();

        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "second@example.com",
            "password123",
            "password123",
            "taken",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("This username is already taken"));
    }

    #[tokio::test]
    async fn post_register_session_cookie_authenticates() {
        // Verify the session cookie issued on registration is usable for auth —
        // not just that a session row exists in the DB.
        let (ath, config) = setup().await;
        let app = test_app(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "auth@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();

        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let token = parse_session_cookie(set_cookie, "allowthem_session")
            .expect("session cookie should be present");

        // validate_session should return Some(user) — cookie is live
        let ttl = ath.session_config().ttl;
        let session_result = ath.db().validate_session(&token, ttl).await.unwrap();
        assert!(
            session_result.is_some(),
            "session cookie issued at registration should be valid"
        );
    }

    #[tokio::test]
    async fn get_register_logged_in_redirects_to_root() {
        // Authenticated users hitting GET /register are sent to / instead of
        // seeing the form.
        use allowthem_core::{generate_token, hash_token};
        use chrono::{Duration, Utc};

        let (ath, config) = setup().await;

        // Create a user and an active session.
        let email = Email::new("loggedin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let token = generate_token();
        let token_hash = hash_token(&token);
        ath.db()
            .create_session(
                user.id,
                token_hash,
                None,
                None,
                Utc::now() + Duration::hours(24),
            )
            .await
            .unwrap();
        let set_cookie = ath.session_cookie(&token);
        let cookie_value = set_cookie.split(';').next().unwrap().to_string();

        let app = test_app(ath, config);
        let req = Request::builder()
            .uri("/register")
            .header(header::COOKIE, cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    #[tokio::test]
    async fn post_register_without_csrf_returns_403() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let body = "email=test%40example.com&password=password123&password_confirm=password123";
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn register_with_client_id_shows_branding() {
        let (ath, config) = setup().await;
        let (app, _) = ath
            .db()
            .create_application(
                "BrandedRegApp".into(),
                vec!["https://example.com/cb".into()],
                false,
                None,
                Some("https://cdn.example.com/logo.png".into()),
                Some("#ff6600".into()),
            )
            .await
            .unwrap();
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri(&format!("/register?client_id={}", app.client_id))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("BrandedRegApp"), "should show app name");
        assert!(html.contains("<img"), "should show logo");
        assert!(html.contains("#ff6600"), "should have accent color");
    }

    #[tokio::test]
    async fn register_without_client_id_shows_default() {
        let (ath, config) = setup().await;
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<img"), "no logo without client_id");
        assert!(html.contains("#2563eb"), "should have default blue");
    }

    #[tokio::test]
    async fn register_sign_in_link_carries_client_id() {
        let (ath, config) = setup().await;
        let (app, _) = ath
            .db()
            .create_application(
                "LinkApp".into(),
                vec!["https://example.com/cb".into()],
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri(&format!("/register?client_id={}", app.client_id))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(&format!("/login?client_id={}", app.client_id)),
            "sign-in link should carry client_id"
        );
    }

    // --- Custom fields tests ---

    #[tokio::test]
    async fn register_without_schema_works_as_before() {
        // Confirm that register with no schema config works identically
        let (ath, config) = setup().await;
        let app = test_app(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "noschema@example.com",
            "password123",
            "password123",
            "",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let email = Email::new("noschema@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        assert!(user.custom_data.is_none());
    }

    #[tokio::test]
    async fn register_with_custom_fields_stores_json() {
        let (ath, config) = setup().await;
        let app = test_app_with_schema(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        let req = register_request_with_custom(
            &csrf,
            "custom@example.com",
            "password123",
            "password123",
            "",
            &[("company", "Acme Corp"), ("age", "30"), ("newsletter", "true")],
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::SEE_OTHER,
            "should redirect on success"
        );

        let email = Email::new("custom@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        let data = user
            .custom_data
            .as_ref()
            .expect("custom_data should be stored");
        assert_eq!(data["company"], "Acme Corp");
        assert_eq!(data["age"], 30);
        assert_eq!(data["newsletter"], true);
    }

    #[tokio::test]
    async fn register_with_invalid_custom_fields_shows_error() {
        let (ath, config) = setup().await;
        let app = test_app_with_schema(ath, config);
        let csrf = get_csrf_token(&app).await;
        // Missing required "company" field
        let req = register_request_with_custom(
            &csrf,
            "invalid@example.com",
            "password123",
            "password123",
            "",
            &[("age", "25")],
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "should re-render form on validation failure"
        );
        let html = body_string(resp).await;
        // The error message should mention the missing required field
        assert!(
            html.contains("company") || html.contains("required"),
            "should show validation error about missing required field"
        );
        // Submitted values should be preserved in the re-rendered form
        assert!(
            html.contains("invalid@example.com"),
            "email should be preserved on error re-render"
        );
    }

    #[tokio::test]
    async fn register_custom_field_type_coercion() {
        let (ath, config) = setup().await;
        let app = test_app_with_schema(ath.clone(), config);
        let csrf = get_csrf_token(&app).await;
        // Submit age as string "42" — should be coerced to integer
        let req = register_request_with_custom(
            &csrf,
            "coerce@example.com",
            "password123",
            "password123",
            "",
            &[("company", "Test Co"), ("age", "42")],
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        let email = Email::new("coerce@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        let data = user.custom_data.as_ref().expect("custom_data");
        // age should be stored as a number, not a string
        assert!(data["age"].is_i64(), "age should be coerced to integer");
        assert_eq!(data["age"], 42);
        // newsletter absent = false
        assert_eq!(data["newsletter"], false);
    }

    #[tokio::test]
    async fn get_register_with_schema_renders_custom_fields() {
        let (ath, config) = setup().await;
        let app = test_app_with_schema(ath, config);
        let req = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        // Custom fields should be rendered
        assert!(
            html.contains("custom_data[company]"),
            "should render company custom field"
        );
        assert!(
            html.contains("Company Name"),
            "should render field label"
        );
    }
}
