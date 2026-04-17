//! Mock OAuth provider for testing. Only used when ALLOWTHEM_OAUTH_MOCK=true.

use allowthem_core::auth_client::AuthFuture;
use allowthem_core::error::AuthError;
use allowthem_core::oauth::{OAuthProvider, OAuthUserInfo};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MockIdentity {
    pub email: String,
    pub verified: bool,
    pub uid: String,
    pub name: Option<String>,
}

pub struct MockOAuthProvider {
    pub provider_name: String,
    pub base_url: String,
}

impl OAuthProvider for MockOAuthProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn authorize_url(&self, _redirect_uri: &str, state: &str, _challenge: &str) -> String {
        format!(
            "{}/test-oauth/simulate?provider={}&state={}",
            self.base_url, self.provider_name, state
        )
    }

    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        _redirect_uri: &'a str,
        _pkce_verifier: &'a str,
    ) -> AuthFuture<'a, String> {
        let code = code.to_string();
        Box::pin(async move { Ok(code) })
    }

    fn user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, OAuthUserInfo> {
        let result = decode_identity(access_token);
        Box::pin(async move { result })
    }
}

pub fn encode_identity(identity: &MockIdentity) -> String {
    let json = serde_json::to_vec(identity).expect("MockIdentity is always serializable");
    Base64UrlUnpadded::encode_string(&json)
}

fn decode_identity(encoded: &str) -> Result<OAuthUserInfo, AuthError> {
    let bytes = Base64UrlUnpadded::decode_vec(encoded)
        .map_err(|e| AuthError::OAuthTokenExchange(e.to_string()))?;
    let identity: MockIdentity =
        serde_json::from_slice(&bytes).map_err(|e| AuthError::OAuthTokenExchange(e.to_string()))?;
    Ok(OAuthUserInfo {
        provider_user_id: identity.uid,
        email: identity.email,
        email_verified: identity.verified,
        name: identity.name,
    })
}
