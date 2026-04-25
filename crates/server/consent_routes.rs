use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Query};
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum_htmx::{HxBoosted, HxRequest};
use minijinja::{Environment, context};
use serde::Serialize;

use allowthem_core::AllowThem;

use crate::authorize_routes::{
    AuthorizeOutcome, AuthorizeParams, ConsentNeededData, check_authorization,
};
use crate::branding::resolve_accent;
use crate::browser_error::BrowserError;
use crate::browser_templates::render;
use crate::csrf::CsrfToken;

#[derive(Clone)]
struct ConsentConfig {
    templates: Arc<Environment<'static>>,
    is_production: bool,
}

#[derive(Serialize)]
struct ScopeItem {
    description: String,
}

fn build_scope_items(scopes: &[String]) -> Vec<ScopeItem> {
    scopes
        .iter()
        .map(|s| {
            let description = match s.as_str() {
                "openid" => "Verify your identity",
                "profile" => "View your profile information (name, username)",
                "email" => "View your email address",
                other => other,
            };
            ScopeItem {
                description: description.to_string(),
            }
        })
        .collect()
}

/// Fields rendered by both the full-page `consent.html` and the HTMX
/// `_auth_main_consent.html` fragment. Keeping them in one struct prevents
/// the two render sites from drifting.
struct ConsentRenderFields {
    application_name: String,
    app_name: String,
    logo_url: Option<String>,
    accent: String,
    accent_ink: &'static str,
    accent_light: String,
    accent_ink_light: &'static str,
    scope_items: Vec<ScopeItem>,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state_param: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
    csrf_token: String,
}

/// Build the shared render fields from the consent outcome + CSRF token.
fn build_render_fields(data: &ConsentNeededData, csrf_token: &str) -> ConsentRenderFields {
    let branding = &data.context.branding;
    let (accent_hex, accent_ink_hex, accent_light_hex, accent_ink_light_hex) =
        resolve_accent(Some(branding));

    ConsentRenderFields {
        application_name: branding.application_name.clone(),
        // Thread `app_name` so the `_auth_macros` kicker renders the tenant
        // in the eyebrow. The consent page is the only auth flow where the
        // tenant name is load-bearing in the eyebrow kicker.
        app_name: branding.application_name.clone(),
        logo_url: branding.logo_url.clone(),
        accent: accent_hex,
        accent_ink: accent_ink_hex,
        accent_light: accent_light_hex,
        accent_ink_light: accent_ink_light_hex,
        scope_items: build_scope_items(&data.context.scopes),
        client_id: data.params.application.client_id.as_str().to_string(),
        redirect_uri: data.params.redirect_uri.clone(),
        scope: data.params.scopes.join(" "),
        state_param: data.params.state.clone(),
        code_challenge: data.params.code_challenge.clone(),
        code_challenge_method: data.params.code_challenge_method.clone(),
        nonce: data.params.nonce.clone(),
        csrf_token: csrf_token.to_string(),
    }
}

/// Render just the `_auth_main_consent.html` partial plus the
/// `_auth_oob_head.html` OOB head swap, for HTMX fragment responses.
fn render_consent_fragment(
    config: &ConsentConfig,
    fields: &ConsentRenderFields,
) -> Result<Html<String>, BrowserError> {
    let page_title = format!("Authorize {} — allowthem", fields.application_name);
    let ctx = context! {
        application_name => &fields.application_name,
        app_name => &fields.app_name,
        logo_url => &fields.logo_url,
        accent => &fields.accent,
        accent_ink => &fields.accent_ink,
        accent_light => &fields.accent_light,
        accent_ink_light => &fields.accent_ink_light,
        scope_items => &fields.scope_items,
        client_id => &fields.client_id,
        redirect_uri => &fields.redirect_uri,
        response_type => "code",
        scope => &fields.scope,
        state_param => &fields.state_param,
        code_challenge => &fields.code_challenge,
        code_challenge_method => &fields.code_challenge_method,
        nonce => &fields.nonce,
        csrf_token => &fields.csrf_token,
        is_production => config.is_production,
        page_title => page_title,
        status_hint => "CONSENT",
    };

    let main = render(
        &config.templates,
        "_partials/_auth_main_consent.html",
        ctx.clone(),
    )?;
    let oob = render(&config.templates, "_partials/_auth_oob_head.html", ctx)?;
    Ok(Html(format!("{}{}", main.0, oob.0)))
}

/// Render the full-page `consent.html` (shell + main).
fn render_consent_full(
    config: &ConsentConfig,
    fields: &ConsentRenderFields,
) -> Result<Html<String>, BrowserError> {
    render(
        &config.templates,
        "consent.html",
        context! {
            application_name => &fields.application_name,
            app_name => &fields.app_name,
            logo_url => &fields.logo_url,
            accent => &fields.accent,
            accent_ink => &fields.accent_ink,
            accent_light => &fields.accent_light,
            accent_ink_light => &fields.accent_ink_light,
            scope_items => &fields.scope_items,
            client_id => &fields.client_id,
            redirect_uri => &fields.redirect_uri,
            response_type => "code",
            scope => &fields.scope,
            state_param => &fields.state_param,
            code_challenge => &fields.code_challenge,
            code_challenge_method => &fields.code_challenge_method,
            nonce => &fields.nonce,
            csrf_token => &fields.csrf_token,
            is_production => config.is_production,
        },
    )
}

/// GET /oauth/authorize — render consent screen or delegate to redirect.
async fn get_authorize(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<ConsentConfig>,
    csrf: CsrfToken,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
    HxBoosted(boosted): HxBoosted,
    HxRequest(request): HxRequest,
) -> Result<Response, BrowserError> {
    match check_authorization(&ath, &headers, &params).await {
        AuthorizeOutcome::Redirect(resp) => Ok(resp),
        AuthorizeOutcome::ConsentNeeded(data) => {
            let fields = build_render_fields(&data, csrf.as_str());

            if request && !boosted {
                let html = render_consent_fragment(&config, &fields)?;
                return Ok(html.into_response());
            }

            let html = render_consent_full(&config, &fields)?;
            Ok(html.into_response())
        }
    }
}

pub fn consent_routes(templates: Arc<Environment<'static>>, is_production: bool) -> Router<()> {
    let cfg = ConsentConfig {
        templates,
        is_production,
    };
    Router::new()
        .route(
            "/oauth/authorize",
            get(get_authorize).post(crate::authorize_routes::authorize_post),
        )
        .layer(Extension(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_fields() -> ConsentRenderFields {
        ConsentRenderFields {
            application_name: "Test App".into(),
            app_name: "Test App".into(),
            logo_url: None,
            accent: "#ffffff".into(),
            accent_ink: "#000000",
            accent_light: "#000000".into(),
            accent_ink_light: "#ffffff",
            scope_items: build_scope_items(&["openid".to_string(), "email".to_string()]),
            client_id: "cid-abc".into(),
            redirect_uri: "https://example.com/cb".into(),
            scope: "openid email".into(),
            state_param: "state-xyz".into(),
            code_challenge: "chal".into(),
            code_challenge_method: "S256".into(),
            nonce: None,
            csrf_token: "tok".into(),
        }
    }

    #[test]
    fn render_consent_fragment_composes_main_and_oob_head() {
        let templates = crate::browser_templates::build_default_browser_env();
        let config = ConsentConfig {
            templates,
            is_production: false,
        };
        let fields = fixture_fields();
        let html = render_consent_fragment(&config, &fields).unwrap().0;

        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "fragment must include the <main> root"
        );
        assert!(
            html.contains("<title hx-swap-oob=\"true\">"),
            "fragment must include the OOB <title> tag"
        );
        assert!(
            html.contains("id=\"wf-screen-label\""),
            "fragment must include the OOB #wf-screen-label span"
        );
        assert!(
            html.contains("CONSENT"),
            "fragment must include the CONSENT status hint"
        );
        assert!(
            html.contains("Test App"),
            "fragment must include the tenant name in the kicker"
        );
        assert!(
            html.contains("Authorize Test App — allowthem"),
            "fragment must include the tenant-specific page_title"
        );
        assert!(
            html.contains("wf-framed"),
            "fragment must include the scope list container"
        );
        assert!(
            html.contains("Verify your identity"),
            "fragment must render the scope descriptions"
        );

        // Hidden OAuth inputs: guard against silent drops during future
        // template refactors. All 8 required inputs must render with the
        // exact name+value pairs from the fixture.
        assert!(
            html.contains(r#"name="client_id" value="cid-abc""#),
            "client_id hidden input missing"
        );
        // MiniJinja HTML-escapes `/` to `&#x2f;` in attribute values.
        assert!(
            html.contains(r#"name="redirect_uri" value="https:&#x2f;&#x2f;example.com&#x2f;cb""#),
            "redirect_uri hidden input missing"
        );
        assert!(
            html.contains(r#"name="response_type" value="code""#),
            "response_type hidden input missing"
        );
        assert!(
            html.contains(r#"name="scope" value="openid email""#),
            "scope hidden input missing"
        );
        assert!(
            html.contains(r#"name="state" value="state-xyz""#),
            "state hidden input missing"
        );
        assert!(
            html.contains(r#"name="code_challenge" value="chal""#),
            "code_challenge hidden input missing"
        );
        assert!(
            html.contains(r#"name="code_challenge_method" value="S256""#),
            "code_challenge_method hidden input missing"
        );
        assert!(
            html.contains(r#"name="csrf_token" value="tok""#),
            "csrf_token hidden input missing"
        );

        // Fixture has `nonce: None` — the optional hidden input must NOT
        // render when nonce is absent.
        assert!(
            !html.contains(r#"name="nonce""#),
            "nonce hidden input must not render when nonce is None"
        );
    }

    #[test]
    fn render_consent_fragment_renders_nonce_when_present() {
        let templates = crate::browser_templates::build_default_browser_env();
        let config = ConsentConfig {
            templates,
            is_production: false,
        };
        let mut fields = fixture_fields();
        fields.nonce = Some("nonce-123".into());
        let html = render_consent_fragment(&config, &fields).unwrap().0;

        assert!(
            html.contains(r#"name="nonce" value="nonce-123""#),
            "nonce hidden input must render when nonce is Some"
        );
    }
}
