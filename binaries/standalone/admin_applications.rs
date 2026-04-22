use axum::Router;
use axum::body::Bytes;
use axum::extract::{FromRequest, Path, Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::AuthError;
use allowthem_core::applications::{CreateApplicationParams, UpdateApplication};
use allowthem_core::types::{ApplicationId, ClientType};
use allowthem_server::{BrowserAdminUser, CsrfToken, ShellContext};
use minijinja::value::Value;

use crate::error::AppError;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct CreateApplicationForm {
    name: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    is_trusted: Option<String>,
    logo_url: Option<String>,
    primary_color: Option<String>,
    #[allow(dead_code)]
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct EditApplicationForm {
    name: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    is_trusted: Option<String>,
    #[serde(default)]
    is_active: Option<String>,
    logo_url: Option<String>,
    primary_color: Option<String>,
    #[allow(dead_code)]
    csrf_token: String,
}

/// Form extractor that uses `serde_html_form` for deserialization.
///
/// Unlike Axum's built-in `Form` (which uses `serde_urlencoded`), this
/// correctly handles repeated form fields (e.g., multiple `redirect_uris`
/// inputs) as `Vec<String>`.
pub(crate) struct HtmlForm<T>(T);

impl<S, T> FromRequest<S> for HtmlForm<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| e.into_response())?;
        let value = serde_html_form::from_bytes(&bytes)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response())?;
        Ok(HtmlForm(value))
    }
}

fn filter_uris(uris: Vec<String>) -> Vec<String> {
    uris.into_iter().filter(|u| !u.trim().is_empty()).collect()
}

fn checkbox(val: &Option<String>) -> bool {
    val.as_deref() == Some("on")
}

fn opt_string(val: &Option<String>) -> Option<String> {
    val.as_ref().and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/new", get(new_form))
        .route("/{id}", get(detail).post(update))
        .route("/{id}/edit", get(edit_form))
        .route("/{id}/regenerate-secret", post(regenerate_secret))
        .route("/{id}/delete", post(delete))
}

/// GET /admin/applications — list all registered applications.
pub async fn list(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
) -> Result<Response, AppError> {
    let applications = state.ath.db().list_applications().await?;
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    let html = crate::templates::render(
        &state.templates,
        "admin/applications_list.html",
        context! {
            shell => Value::from_serialize(&shell),
            applications => &applications,
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// GET /admin/applications/new — render the create application form.
pub async fn new_form(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let html = render_new_form(&state, csrf.as_str(), "", "", &[], false, "", "")?;
    Ok(html.into_response())
}

/// POST /admin/applications — create a new application.
pub async fn create(
    State(state): State<AppState>,
    BrowserAdminUser(user): BrowserAdminUser,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<CreateApplicationForm>,
) -> Result<Response, AppError> {
    let name = form.name.trim().to_string();
    let redirect_uris = filter_uris(form.redirect_uris);
    let is_trusted = checkbox(&form.is_trusted);
    let logo_url = opt_string(&form.logo_url);
    let primary_color = opt_string(&form.primary_color);

    if name.is_empty() {
        let html = render_new_form(
            &state,
            csrf.as_str(),
            "Application name is required",
            "",
            &redirect_uris,
            is_trusted,
            logo_url.as_deref().unwrap_or(""),
            primary_color.as_deref().unwrap_or(""),
        )?;
        return Ok(html.into_response());
    }

    // Save display strings before logo_url/primary_color are moved into create_application.
    let logo_url_display = logo_url.as_deref().unwrap_or("").to_string();
    let primary_color_display = primary_color.as_deref().unwrap_or("").to_string();

    match state
        .ath
        .db()
        .create_application(CreateApplicationParams {
            name: name.clone(),
            client_type: ClientType::Confidential,
            redirect_uris,
            is_trusted,
            created_by: Some(user.id),
            logo_url,
            primary_color,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
    {
        Ok((app, secret)) => {
            let uris = app.redirect_uri_list()?;
            let shell = ShellContext::new(true, "/admin/applications", "allowthem");
            let html = crate::templates::render(
                &state.templates,
                "admin/application_detail.html",
                context! {
                    shell => Value::from_serialize(&shell),
                    app => &app,
                    redirect_uris => &uris,
                    client_secret => secret.as_ref().map(|s| s.as_str()).unwrap_or(""),
                    csrf_token => csrf.as_str(),
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        Err(AuthError::InvalidRedirectUri(msg)) => {
            let html = render_new_form(
                &state,
                csrf.as_str(),
                &format!("Invalid redirect URI: {msg}"),
                &name,
                &[],
                is_trusted,
                &logo_url_display,
                &primary_color_display,
            )?;
            Ok(html.into_response())
        }
        Err(AuthError::Validation(msg)) => {
            let html = render_new_form(
                &state,
                csrf.as_str(),
                &msg,
                &name,
                &[],
                is_trusted,
                &logo_url_display,
                &primary_color_display,
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(AppError::Auth(e)),
    }
}

/// GET /admin/applications/:id — show application detail.
pub async fn detail(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<ApplicationId>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let app = state.ath.db().get_application(id).await?;
    let uris = app.redirect_uri_list()?;
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    let html = crate::templates::render(
        &state.templates,
        "admin/application_detail.html",
        context! {
            shell => Value::from_serialize(&shell),
            app => &app,
            redirect_uris => &uris,
            csrf_token => csrf.as_str(),
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// GET /admin/applications/:id/edit — render the edit form.
pub async fn edit_form(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<ApplicationId>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let app = state.ath.db().get_application(id).await?;
    let uris = app.redirect_uri_list()?;
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    let html = crate::templates::render(
        &state.templates,
        "admin/application_edit.html",
        context! {
            shell => Value::from_serialize(&shell),
            app => &app,
            redirect_uris => &uris,
            csrf_token => csrf.as_str(),
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// POST /admin/applications/:id — update application fields.
pub async fn update(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<ApplicationId>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<EditApplicationForm>,
) -> Result<Response, AppError> {
    let name = form.name.trim().to_string();
    let redirect_uris = filter_uris(form.redirect_uris);
    let is_trusted = checkbox(&form.is_trusted);
    let is_active = checkbox(&form.is_active);
    let logo_url = opt_string(&form.logo_url);
    let primary_color = opt_string(&form.primary_color);

    let params = UpdateApplication {
        name,
        redirect_uris,
        is_trusted,
        is_active,
        logo_url,
        primary_color,
        accent_hex: None,
        accent_ink: None,
        forced_mode: None,
        font_css_url: None,
        font_family: None,
        splash_text: None,
        splash_image_url: None,
        splash_primitive: None,
        splash_url: None,
        shader_cell_scale: None,
    };

    match state.ath.db().update_application(id, params).await {
        Ok(()) => Ok(Redirect::to(&format!("/admin/applications/{id}")).into_response()),
        Err(AuthError::InvalidRedirectUri(msg)) => {
            let app = state.ath.db().get_application(id).await?;
            let uris = app.redirect_uri_list()?;
            let shell = ShellContext::new(true, "/admin/applications", "allowthem");
            let html = crate::templates::render(
                &state.templates,
                "admin/application_edit.html",
                context! {
                    shell => Value::from_serialize(&shell),
                    app => &app,
                    redirect_uris => &uris,
                    error => format!("Invalid redirect URI: {msg}"),
                    csrf_token => csrf.as_str(),
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        Err(AuthError::Validation(msg)) => {
            let app = state.ath.db().get_application(id).await?;
            let uris = app.redirect_uri_list()?;
            let shell = ShellContext::new(true, "/admin/applications", "allowthem");
            let html = crate::templates::render(
                &state.templates,
                "admin/application_edit.html",
                context! {
                    shell => Value::from_serialize(&shell),
                    app => &app,
                    redirect_uris => &uris,
                    error => msg,
                    csrf_token => csrf.as_str(),
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(AppError::Auth(e)),
    }
}

/// POST /admin/applications/:id/regenerate-secret — generate new client secret.
pub async fn regenerate_secret(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<ApplicationId>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let (app, secret) = state.ath.db().regenerate_client_secret(id).await?;
    let uris = app.redirect_uri_list()?;
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    let html = crate::templates::render(
        &state.templates,
        "admin/application_detail.html",
        context! {
            shell => Value::from_serialize(&shell),
            app => &app,
            redirect_uris => &uris,
            client_secret => secret.as_str(),
            csrf_token => csrf.as_str(),
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// POST /admin/applications/:id/delete — permanently delete the application.
pub async fn delete(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<ApplicationId>,
    _csrf: CsrfToken,
) -> Result<Response, AppError> {
    state.ath.db().delete_application(id).await?;
    Ok(Redirect::to("/admin/applications").into_response())
}

#[allow(clippy::too_many_arguments)]
fn render_new_form(
    state: &AppState,
    csrf_token: &str,
    error: &str,
    form_name: &str,
    form_redirect_uris: &[String],
    form_is_trusted: bool,
    form_logo_url: &str,
    form_primary_color: &str,
) -> Result<axum::response::Html<String>, AppError> {
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    crate::templates::render(
        &state.templates,
        "admin/application_new.html",
        context! {
            shell => Value::from_serialize(&shell),
            csrf_token,
            error,
            form_name,
            form_redirect_uris,
            form_is_trusted,
            form_logo_url,
            form_primary_color,
        },
        state.is_production,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header::COOKIE};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use allowthem_core::applications::CreateApplicationParams;
    use allowthem_core::types::ClientType;
    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, RoleName,
        generate_token, hash_token,
    };
    use allowthem_server::{csrf_middleware, inject_ath_into_extensions};

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();

        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        // Create admin role and assign
        let role_name = RoleName::new("admin");
        let role = ath.db().create_role(&role_name, None).await.unwrap();
        ath.db().assign_role(&user.id, &role.id).await.unwrap();

        // Create session
        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            templates,
            is_production: false,
        };

        (ath, state, cookie_value)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .nest("/admin/applications", super::routes())
            .layer(axum::middleware::from_fn(csrf_middleware))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                inject_ath_into_extensions,
            ))
            .with_state(state)
    }

    fn get_csrf_token(body: &str) -> String {
        let marker = "name=\"csrf_token\" value=\"";
        let start = body.find(marker).expect("csrf_token not found") + marker.len();
        let end = body[start..].find('"').unwrap() + start;
        body[start..end].to_string()
    }

    async fn read_body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn list_page_renders_empty() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("No applications registered"));
    }

    #[tokio::test]
    async fn list_page_renders_with_apps() {
        let (ath, state, cookie) = setup().await;
        ath.db()
            .create_application(CreateApplicationParams {
                name: "Test App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/applications")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Test App"));
        assert!(body.contains("class=\"wf-app\"") || body.contains("class=\"wf-app "));
        assert!(
            !body.contains("class=\"at-app-shell\"") && !body.contains("class=\"at-app-shell ")
        );
        assert!(body.contains("&#x2f;admin&#x2f;audit"));
    }

    #[tokio::test]
    async fn new_form_renders() {
        let (_ath, state, cookie) = setup().await;

        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("NEW APPLICATION"));
    }

    #[tokio::test]
    async fn create_returns_secret() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        // GET first to get CSRF token
        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=My+App&redirect_uris=https%3A%2F%2Fexample.com%2Fcb&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("will not be shown again"));
        assert!(body.contains("My App"));
    }

    #[tokio::test]
    async fn create_empty_name_shows_error() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=&redirect_uris=https%3A%2F%2Fexample.com%2Fcb&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Application name is required"));
    }

    #[tokio::test]
    async fn detail_not_found_returns_404() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let fake_id = allowthem_core::types::ApplicationId::new();
        let req = Request::builder()
            .uri(&format!("/admin/applications/{fake_id}"))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn detail_page_renders() {
        let (ath, state, cookie) = setup().await;
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Detail App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Detail App"));
        assert!(body.contains(created_app.client_id.as_str()));
    }

    #[tokio::test]
    async fn edit_form_pre_populates() {
        let (ath, state, cookie) = setup().await;
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Edit App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: true,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}/edit", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Edit App"));
        // MiniJinja HTML-escapes `/` as `&#x2f;` in attribute values
        assert!(body.contains("example.com"));
    }

    #[tokio::test]
    async fn update_redirects_to_detail() {
        let (ath, state, cookie) = setup().await;
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Update App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);

        // GET edit form for CSRF
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}/edit", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=Updated+App&redirect_uris=https%3A%2F%2Fexample.com%2Fcb&is_active=on&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/applications/{}", created_app.id))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains(&format!("/admin/applications/{}", created_app.id)));
    }

    #[tokio::test]
    async fn regenerate_secret_shows_new_secret() {
        let (ath, state, cookie) = setup().await;
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Regen App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);

        // GET detail for CSRF
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!("csrf_token={}", csrf);
        let req = Request::builder()
            .method("POST")
            .uri(&format!(
                "/admin/applications/{}/regenerate-secret",
                created_app.id
            ))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("will not be shown again"));
    }

    #[tokio::test]
    async fn delete_redirects_to_list() {
        let (ath, state, cookie) = setup().await;
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Delete App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();

        let app = test_app(state);

        // GET detail for CSRF
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!("csrf_token={}", csrf);
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/applications/{}/delete", created_app.id))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "/admin/applications"
        );
    }

    #[tokio::test]
    async fn unauthenticated_redirects_to_login() {
        let (_ath, state, _cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
    }

    #[tokio::test]
    async fn non_admin_gets_403() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();

        let email = Email::new("nonadmin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath,
            auth_client,
            templates,
            is_production: false,
        };
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications")
            .header(COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_filters_empty_redirect_uris() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        // GET first to get CSRF token
        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        // Submit with one valid URI and one empty (simulates blank input field)
        let form_body = format!(
            "name=Filter+App&redirect_uris=https%3A%2F%2Fexample.com%2Fcb&redirect_uris=&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        // Should succeed (empty URI filtered out), not fail with validation error
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("will not be shown again"));
        assert!(body.contains("Filter App"));
    }

    #[tokio::test]
    async fn update_unchecked_checkbox_sets_false() {
        let (ath, state, cookie) = setup().await;
        // Create a trusted application
        let (created_app, _secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Trusted App".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".to_string()],
                is_trusted: true,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();
        assert!(created_app.is_trusted);

        let app = test_app(state);

        // GET edit form for CSRF
        let req = Request::builder()
            .uri(&format!("/admin/applications/{}/edit", created_app.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        // Submit without is_trusted (checkbox absent = unchecked = false)
        let form_body = format!(
            "name=Trusted+App&redirect_uris=https%3A%2F%2Fexample.com%2Fcb&is_active=on&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/applications/{}", created_app.id))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Verify the application is no longer trusted
        let updated = ath.db().get_application(created_app.id).await.unwrap();
        assert!(
            !updated.is_trusted,
            "absent checkbox must set is_trusted to false"
        );
        assert!(updated.is_active, "is_active=on must set is_active to true");
    }

    #[tokio::test]
    async fn create_rejects_invalid_logo_url() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=Bad+Logo&redirect_uris=https%3A%2F%2Fexample.com%2Fcb\
             &logo_url=http%3A%2F%2Fevil.com%2Flogo.png&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("HTTPS"), "should show HTTPS error");
    }

    #[tokio::test]
    async fn create_rejects_invalid_primary_color() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=Bad+Color&redirect_uris=https%3A%2F%2Fexample.com%2Fcb\
             &primary_color=red&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("#RRGGBB"), "should show hex format error");
    }

    #[tokio::test]
    async fn create_accepts_valid_branding() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/applications/new")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!(
            "name=Branded+App&redirect_uris=https%3A%2F%2Fexample.com%2Fcb\
             &logo_url=https%3A%2F%2Fexample.com%2Flogo.png\
             &primary_color=%233B82F6&csrf_token={}",
            csrf
        );
        let req = Request::builder()
            .method("POST")
            .uri("/admin/applications")
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(
            body.contains("will not be shown again"),
            "should show secret"
        );
        assert!(body.contains("Branded App"), "should show app name");
    }
}
