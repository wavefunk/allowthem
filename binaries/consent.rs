use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use minijinja::context;
use serde::Serialize;

use allowthem_server::{AuthorizeOutcome, AuthorizeParams, CsrfToken, check_authorization};

use crate::error::AppError;
use crate::state::AppState;
use crate::templates::render;

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
pub async fn get_authorize(
    State(state): State<AppState>,
    csrf: CsrfToken,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Result<Response, AppError> {
    match check_authorization(&state.ath, &headers, &params).await {
        AuthorizeOutcome::Redirect(resp) => Ok(resp),
        AuthorizeOutcome::ConsentNeeded { context, params } => {
            let scope_items = build_scope_items(&context.scopes);

            let html = render(
                &state.templates,
                "consent.html",
                context! {
                    application_name => context.application_name,
                    logo_url => context.logo_url,
                    primary_color => context.primary_color,
                    scope_items => scope_items,
                    client_id => params.application.client_id.as_str(),
                    redirect_uri => params.redirect_uri,
                    response_type => "code",
                    scope => params.scopes.join(" "),
                    state_param => params.state,
                    code_challenge => params.code_challenge,
                    code_challenge_method => params.code_challenge_method,
                    nonce => params.nonce,
                    csrf_token => csrf.as_str(),
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
    }
}
