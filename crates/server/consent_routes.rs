use std::sync::Arc;

use axum::Router;
use axum::extract::{Extension, Query};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use minijinja::{Environment, context};
use serde::Serialize;

use allowthem_core::AllowThem;

use crate::authorize_routes::{AuthorizeOutcome, AuthorizeParams, check_authorization};
use crate::branding::{compute_accent_variants, default_accents};
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

/// GET /oauth/authorize — render consent screen or delegate to redirect.
async fn get_authorize(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<ConsentConfig>,
    csrf: CsrfToken,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, BrowserError> {
    match check_authorization(&ath, &headers, &params).await {
        AuthorizeOutcome::Redirect(resp) => Ok(resp),
        AuthorizeOutcome::ConsentNeeded(data) => {
            let scope_items = build_scope_items(&data.context.scopes);

            let branding = &data.context.branding;
            let (accent, accent_hover, accent_ring) = branding
                .primary_color
                .as_deref()
                .map(compute_accent_variants)
                .unwrap_or_else(default_accents);

            let html = render(
                &config.templates,
                "consent.html",
                context! {
                    application_name => branding.application_name.clone(),
                    logo_url => branding.logo_url.clone(),
                    accent,
                    accent_hover,
                    accent_ring,
                    scope_items => scope_items,
                    client_id => data.params.application.client_id.as_str(),
                    redirect_uri => data.params.redirect_uri,
                    response_type => "code",
                    scope => data.params.scopes.join(" "),
                    state_param => data.params.state,
                    code_challenge => data.params.code_challenge,
                    code_challenge_method => data.params.code_challenge_method,
                    nonce => data.params.nonce,
                    csrf_token => csrf.as_str(),
                    is_production => config.is_production,
                },
            )?;
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
