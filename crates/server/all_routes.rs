use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use axum::Router;
use minijinja::Environment;

use allowthem_core::{AllowThem, AuthEventSender, EmailSender, OAuthProvider};

use crate::browser_templates::build_default_browser_env;

/// Identifies a logical group of routes that can be selectively enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteGroup {
    Login,
    Register,
    Logout,
    Settings,
    Consent,
    PasswordReset,
    Mfa,
    OAuth,
    Token,
    UserInfo,
    WellKnown,
}

/// Errors returned by [`AllRoutesBuilder::build`].
#[derive(Debug)]
pub enum AllRoutesError {
    NoRoutesSelected,
    MissingConfig(String),
    InvalidSchema(String),
}

impl fmt::Display for AllRoutesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRoutesSelected => f.write_str("no route groups selected"),
            Self::MissingConfig(msg) => write!(f, "missing config: {msg}"),
            Self::InvalidSchema(msg) => write!(f, "invalid custom fields schema: {msg}"),
        }
    }
}

impl std::error::Error for AllRoutesError {}

/// Builder that assembles allowthem route groups into a single
/// [`Router<()>`] with CSRF middleware applied to the correct subset.
pub struct AllRoutesBuilder {
    // Shared config
    templates: Option<Arc<Environment<'static>>>,
    is_production: bool,
    base_url: Option<String>,
    email_sender: Option<Arc<dyn EmailSender>>,

    // Login-specific
    max_login_attempts: u32,
    rate_limit_window_secs: u64,
    oauth_providers_list: Option<Vec<String>>,

    // OAuth-specific
    oauth_provider_impls: Option<HashMap<String, Box<dyn OAuthProvider>>>,

    // MFA-specific
    mfa_issuer: Option<String>,

    // Register-specific
    custom_fields_schema: Option<serde_json::Value>,

    // Event publishing (optional)
    events_tx: Option<AuthEventSender>,

    // Route selection
    routes: HashSet<RouteGroup>,
    all: bool,

    // CORS for OIDC endpoints
    cors_enabled: bool,
}

impl Default for AllRoutesBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AllRoutesBuilder {
    pub fn new() -> Self {
        Self {
            templates: None,
            is_production: false,
            base_url: None,
            email_sender: None,
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            oauth_providers_list: None,
            oauth_provider_impls: None,
            mfa_issuer: None,
            custom_fields_schema: None,
            events_tx: None,
            routes: HashSet::new(),
            all: false,
            cors_enabled: false,
        }
    }

    // --- Shared config ---

    pub fn templates(mut self, templates: Arc<Environment<'static>>) -> Self {
        self.templates = Some(templates);
        self
    }

    pub fn is_production(mut self, is_production: bool) -> Self {
        self.is_production = is_production;
        self
    }

    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    pub fn email_sender(mut self, sender: Arc<dyn EmailSender>) -> Self {
        self.email_sender = Some(sender);
        self
    }

    /// Attach a channel sender that receives lifecycle events (register, etc.).
    ///
    /// See `docs/superpowers/specs/2026-04-20-lifecycle-events-design.md` for
    /// the delivery contract. Called at most once; subsequent calls overwrite.
    pub fn events(mut self, tx: AuthEventSender) -> Self {
        self.events_tx = Some(tx);
        self
    }

    // --- Login config ---

    pub fn max_login_attempts(mut self, max: u32) -> Self {
        self.max_login_attempts = max;
        self
    }

    pub fn rate_limit_window_secs(mut self, secs: u64) -> Self {
        self.rate_limit_window_secs = secs;
        self
    }

    pub fn oauth_providers_list(mut self, providers: Vec<String>) -> Self {
        self.oauth_providers_list = Some(providers);
        self
    }

    // --- OAuth config ---

    pub fn oauth_providers(mut self, providers: HashMap<String, Box<dyn OAuthProvider>>) -> Self {
        self.oauth_provider_impls = Some(providers);
        self
    }

    // --- MFA config ---

    pub fn mfa_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.mfa_issuer = Some(issuer.into());
        self
    }

    // --- Register config ---

    pub fn custom_fields_schema(mut self, schema: serde_json::Value) -> Self {
        self.custom_fields_schema = Some(schema);
        self
    }

    // --- Route selectors ---

    pub fn login(mut self) -> Self {
        self.routes.insert(RouteGroup::Login);
        self
    }

    pub fn register(mut self) -> Self {
        self.routes.insert(RouteGroup::Register);
        self
    }

    pub fn logout(mut self) -> Self {
        self.routes.insert(RouteGroup::Logout);
        self
    }

    pub fn settings(mut self) -> Self {
        self.routes.insert(RouteGroup::Settings);
        self
    }

    pub fn consent(mut self) -> Self {
        self.routes.insert(RouteGroup::Consent);
        self
    }

    pub fn password_reset(mut self) -> Self {
        self.routes.insert(RouteGroup::PasswordReset);
        self
    }

    pub fn mfa(mut self) -> Self {
        self.routes.insert(RouteGroup::Mfa);
        self
    }

    pub fn oauth(mut self) -> Self {
        self.routes.insert(RouteGroup::OAuth);
        self
    }

    pub fn token(mut self) -> Self {
        self.routes.insert(RouteGroup::Token);
        self
    }

    pub fn userinfo(mut self) -> Self {
        self.routes.insert(RouteGroup::UserInfo);
        self
    }

    pub fn well_known(mut self) -> Self {
        self.routes.insert(RouteGroup::WellKnown);
        self
    }

    pub fn all_routes(mut self) -> Self {
        self.all = true;
        self
    }

    /// Enable dynamic CORS for OIDC endpoints (`/oauth/token`, `/oauth/userinfo`,
    /// `/.well-known/*`). Allowed origins are derived per-request from active
    /// application redirect URIs. Has no effect unless Token, UserInfo, or
    /// WellKnown routes are also selected.
    pub fn cors(mut self) -> Self {
        self.cors_enabled = true;
        self
    }

    // --- Build ---

    fn selected(&self, group: RouteGroup) -> bool {
        self.all || self.routes.contains(&group)
    }

    fn validate(&self) -> Result<(), AllRoutesError> {
        if !self.all && self.routes.is_empty() {
            return Err(AllRoutesError::NoRoutesSelected);
        }

        let needs_base_url = self.selected(RouteGroup::PasswordReset)
            || self.selected(RouteGroup::Mfa)
            || self.selected(RouteGroup::OAuth)
            || self.selected(RouteGroup::WellKnown);

        if needs_base_url && self.base_url.is_none() {
            return Err(AllRoutesError::MissingConfig(
                "base_url required by selected route groups".into(),
            ));
        }

        if self.events_tx.is_some() && self.base_url.is_none() {
            return Err(AllRoutesError::MissingConfig(
                "base_url required when events channel is configured".into(),
            ));
        }

        if self.selected(RouteGroup::OAuth) && self.oauth_provider_impls.is_none() {
            return Err(AllRoutesError::MissingConfig(
                "oauth_providers required when oauth routes are selected".into(),
            ));
        }

        if self.selected(RouteGroup::PasswordReset) && self.email_sender.is_none() {
            return Err(AllRoutesError::MissingConfig(
                "email_sender required when password_reset routes are selected".into(),
            ));
        }

        if self.selected(RouteGroup::Mfa) && self.mfa_issuer.is_none() {
            return Err(AllRoutesError::MissingConfig(
                "mfa_issuer required when mfa routes are selected".into(),
            ));
        }

        Ok(())
    }

    fn build_inner(mut self) -> Result<Router<()>, AllRoutesError> {
        self.validate()?;

        // --- Resolve defaults ---

        let templates = self
            .templates
            .take()
            .unwrap_or_else(build_default_browser_env);
        let is_production = self.is_production;

        // Derive oauth_providers_list from the provider map keys when not
        // explicitly set. This avoids requiring the caller to duplicate the
        // provider names.
        let oauth_providers_list = self
            .oauth_providers_list
            .take()
            .unwrap_or_else(|| match &self.oauth_provider_impls {
                Some(map) => {
                    let mut names: Vec<String> = map.keys().cloned().collect();
                    names.sort();
                    names
                }
                None => Vec::new(),
            });

        // --- CSRF-protected routes (browser routes) ---

        let mut csrf_protected: Router<()> = Router::new();

        if self.selected(RouteGroup::Login) {
            csrf_protected = csrf_protected.merge(crate::login_routes::login_routes(
                templates.clone(),
                is_production,
                self.max_login_attempts,
                self.rate_limit_window_secs,
                oauth_providers_list.clone(),
            ));
        }

        if self.selected(RouteGroup::Register) {
            let custom_schema = if let Some(schema) = self.custom_fields_schema.take() {
                crate::custom_fields::validate_custom_schema(&schema)
                    .map_err(AllRoutesError::InvalidSchema)?;
                let validator = jsonschema::validator_for(&schema)
                    .map_err(|e| AllRoutesError::InvalidSchema(e.to_string()))?;
                let fields = crate::custom_fields::extract_field_descriptors(&schema);
                Some(crate::custom_fields::CustomSchemaConfig {
                    schema,
                    validator,
                    fields,
                })
            } else {
                None
            };
            csrf_protected = csrf_protected.merge(crate::register_routes::register_routes(
                templates.clone(),
                is_production,
                custom_schema,
                self.events_tx.clone(),
                self.base_url.clone(),
                oauth_providers_list.clone(),
            ));
        }

        if self.selected(RouteGroup::Logout) {
            csrf_protected = csrf_protected.merge(crate::logout_routes::logout_routes());
        }

        if self.selected(RouteGroup::Settings) {
            csrf_protected = csrf_protected.merge(crate::settings_routes::settings_routes(
                templates.clone(),
                is_production,
            ));
        }

        if self.selected(RouteGroup::Consent) {
            csrf_protected = csrf_protected.merge(crate::consent_routes::consent_routes(
                templates.clone(),
                is_production,
            ));
        }

        if self.selected(RouteGroup::PasswordReset) {
            let email_sender = self.email_sender.clone().expect("validated above");
            let base_url = self.base_url.clone().expect("validated above");
            csrf_protected = csrf_protected.merge(
                crate::password_reset_page_routes::password_reset_page_routes(
                    templates.clone(),
                    is_production,
                    email_sender,
                    base_url,
                ),
            );
        }

        if self.selected(RouteGroup::Mfa) {
            let base_url = self.base_url.clone().expect("validated above");
            csrf_protected = csrf_protected.merge(crate::mfa_page_routes::mfa_setup_routes(
                templates.clone(),
                is_production,
                base_url,
            ));
        }

        // --- Non-CSRF routes ---

        let mut non_csrf: Router<()> = Router::new();

        if self.selected(RouteGroup::Mfa) {
            non_csrf = non_csrf.merge(crate::mfa_page_routes::mfa_challenge_routes(
                templates.clone(),
                is_production,
            ));
            let issuer = self.mfa_issuer.take().expect("validated above");
            non_csrf = non_csrf.merge(crate::mfa_routes::mfa_routes(issuer));
        }

        if self.selected(RouteGroup::OAuth) {
            let providers = self.oauth_provider_impls.take().expect("validated above");
            let base_url = self.base_url.clone().expect("validated above");
            non_csrf = non_csrf.merge(crate::oauth_routes::oauth_routes(
                providers,
                base_url,
                self.events_tx.clone(),
            ));
        }

        // --- OIDC sub-router (CORS-eligible routes) ---

        let mut oidc: Router<()> = Router::new();

        if self.selected(RouteGroup::Token) {
            oidc = oidc.merge(crate::token_route::token_route());
        }

        if self.selected(RouteGroup::UserInfo) {
            oidc = oidc.merge(crate::userinfo_route::userinfo_route());
        }

        if self.selected(RouteGroup::WellKnown) {
            let base_url = self.base_url.clone().expect("validated above");
            oidc = oidc.merge(crate::well_known_routes::well_known_routes(base_url));
        }

        // cors_middleware reads AllowThem from extensions; the inject shim is
        // applied by the caller (build/build_for_saas) at the appropriate scope.
        let oidc_final: Router<()> = if self.cors_enabled {
            oidc.layer(axum::middleware::from_fn(crate::cors::cors_middleware))
        } else {
            oidc
        };

        non_csrf = non_csrf.merge(oidc_final);

        if self.selected(RouteGroup::PasswordReset) {
            let email_sender = self.email_sender.take().expect("validated above");
            let base_url = self.base_url.expect("validated above");
            non_csrf = non_csrf.merge(crate::password_reset_routes::password_reset_routes(
                email_sender,
                base_url,
            ));
        }

        // Apply CSRF middleware to browser routes, then merge non-CSRF routes.
        // Both csrf_middleware and all handlers read AllowThem from extensions.
        // Static assets are merged unconditionally and bypass all middleware.
        Ok(csrf_protected
            .layer(axum::middleware::from_fn(crate::csrf::csrf_middleware))
            .merge(non_csrf)
            .merge(crate::static_routes::router()))
    }

    /// Build routes for standalone mode. Wraps `build_inner` with the inject
    /// shim that bridges `State<AllowThem>` into request extensions.
    pub fn build(self, ath: &AllowThem) -> Result<Router<()>, AllRoutesError> {
        let inner = self.build_inner()?;
        Ok(inner.layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::cors::inject_ath_into_extensions,
        )))
    }

    /// Build routes for SaaS mode. The tenant router injects AllowThem into
    /// extensions before dispatching, so no inject shim is added here.
    pub fn build_for_saas(self) -> Result<Router<()>, AllRoutesError> {
        self.build_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::AllowThemBuilder;

    #[tokio::test]
    async fn build_fails_no_routes_selected() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = AllRoutesBuilder::new().build(&ath);
        assert!(matches!(result, Err(AllRoutesError::NoRoutesSelected)));
    }

    #[tokio::test]
    async fn build_fails_oauth_without_providers() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = AllRoutesBuilder::new()
            .base_url("http://localhost")
            .oauth()
            .build(&ath);
        assert!(matches!(result, Err(AllRoutesError::MissingConfig(_))));
    }

    #[tokio::test]
    async fn build_fails_password_reset_without_email_sender() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = AllRoutesBuilder::new()
            .base_url("http://localhost")
            .password_reset()
            .build(&ath);
        assert!(matches!(result, Err(AllRoutesError::MissingConfig(_))));
    }

    #[tokio::test]
    async fn build_fails_mfa_without_issuer() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = AllRoutesBuilder::new()
            .base_url("http://localhost")
            .mfa()
            .build(&ath);
        assert!(matches!(result, Err(AllRoutesError::MissingConfig(_))));
    }

    #[tokio::test]
    async fn build_fails_events_without_base_url() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .csrf_key(*b"test-csrf-key-for-server-tests!!")
            .build()
            .await
            .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let result = AllRoutesBuilder::new().events(tx).register().build(&ath);
        match result {
            Err(AllRoutesError::MissingConfig(msg)) => assert!(msg.contains("base_url")),
            other => panic!("expected MissingConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_fails_missing_base_url() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = AllRoutesBuilder::new().well_known().build(&ath);
        assert!(matches!(result, Err(AllRoutesError::MissingConfig(_))));
    }

    #[tokio::test]
    async fn build_with_invalid_schema_returns_error() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .csrf_key(*b"test-csrf-key-for-server-tests!!")
            .build()
            .await
            .unwrap();
        // A schema with type "array" is not a valid custom fields schema
        let schema = serde_json::json!({"type": "array"});
        let result = AllRoutesBuilder::new()
            .register()
            .custom_fields_schema(schema)
            .build(&ath);
        assert!(matches!(result, Err(AllRoutesError::InvalidSchema(_))));
    }

    #[tokio::test]
    async fn build_succeeds_for_simple_routes() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .csrf_key(*b"test-csrf-key-for-server-tests!!")
            .build()
            .await
            .unwrap();
        // Routes that require no extra config beyond defaults
        let result = AllRoutesBuilder::new()
            .login()
            .register()
            .logout()
            .settings()
            .consent()
            .token()
            .userinfo()
            .build(&ath);
        assert!(result.is_ok());
    }
}
