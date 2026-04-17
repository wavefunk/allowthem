//! Local simulate route for mock OAuth testing.
//! Only mounted when ALLOWTHEM_OAUTH_MOCK=true.

use axum::Router;
use axum::extract::Query;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;

use allowthem_core::AllowThem;

use crate::mock_oauth::{MockIdentity, encode_identity};

#[derive(Deserialize)]
pub struct SimulateQuery {
    pub provider: String,
    pub state: String,
    pub email: Option<String>,
    pub verified: Option<bool>,
    pub uid: Option<String>,
    pub name: Option<String>,
}

async fn simulate(Query(q): Query<SimulateQuery>) -> Response {
    let email = q.email.unwrap_or_else(|| "mock-user@example.com".into());
    let uid = q.uid.unwrap_or_else(|| email.clone());
    let identity = MockIdentity {
        email,
        verified: q.verified.unwrap_or(true),
        uid,
        name: q.name,
    };
    let code = encode_identity(&identity);
    let redirect = format!(
        "/oauth/{}/callback?code={}&state={}",
        q.provider, code, q.state
    );
    Redirect::temporary(&redirect).into_response()
}

pub fn test_oauth_routes() -> Router<AllowThem> {
    Router::new().route("/test-oauth/simulate", get(simulate))
}
