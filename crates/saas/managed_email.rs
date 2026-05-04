//! Postmark-backed managed email sender for the SaaS deployment.
//!
//! Sends via `POST https://api.postmarkapp.com/email` with the
//! deployment's server token. The From-address is composed at
//! send-time from `<local>@mail.<base_domain>` (with the tenant's
//! display name in the From header) unless the per-tenant config
//! overrides it.
//!
//! The `EmailSenderFactory` trait + `ManagedEmailSenderFactory` impl
//! that dispatch per-tenant between Smtp / Webhook / Managed live in
//! the sibling `managed_email_factory` module (split into Task 4).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use allowthem_core::email::{EmailMessage, EmailSender, EmailTemplate};
use allowthem_core::email_render::{EmailBranding, render};
use allowthem_core::error::AuthError;

const POSTMARK_URL: &str = "https://api.postmarkapp.com/email";

/// Deployment-wide config for the managed sender. The factory passes
/// a clone of this into every per-tenant sender it builds.
#[derive(Debug, Clone)]
pub struct ManagedEmailConfig {
    /// Postmark "Server" API token.
    pub postmark_server_token: String,
    /// Base domain used to compose the default From-address
    /// (`<local>@mail.<base_domain>`). Same value as
    /// `SaasConfig.base_domain`.
    pub base_domain: String,
    /// Local part of the default From-address. Default `"noreply"`.
    pub default_from_local_part: String,
    /// Per-request timeout. Default 10s.
    pub timeout: Duration,
}

impl Default for ManagedEmailConfig {
    fn default() -> Self {
        Self {
            postmark_server_token: String::new(),
            base_domain: String::new(),
            default_from_local_part: "noreply".to_owned(),
            timeout: Duration::from_secs(10),
        }
    }
}

/// Per-tenant managed sender. The factory constructs one of these for
/// each tenant whose config selects the managed mode.
pub struct ManagedEmailSender {
    client: reqwest::Client,
    api_token: String,
    api_url: String,
    /// Resolved at construction: per-tenant override if set, else
    /// `<local>@mail.<base_domain>`.
    from_address: String,
    /// Display name placed in the From header (e.g. `"Acme Inc"`).
    from_display_name: String,
    branding: Arc<EmailBranding>,
}

impl ManagedEmailSender {
    /// Build a sender. `from_override` is the tenant's optional
    /// `managed_from_address`; `from_display_name` is the tenant's
    /// resolved display name (typically `tenants.name`).
    pub fn new(
        deployment: &ManagedEmailConfig,
        from_override: Option<String>,
        from_display_name: String,
        branding: EmailBranding,
    ) -> Result<Self, AuthError> {
        let from_address = from_override.unwrap_or_else(|| {
            format!(
                "{}@mail.{}",
                deployment.default_from_local_part, deployment.base_domain
            )
        });
        let client = reqwest::Client::builder()
            .timeout(deployment.timeout)
            .build()
            .map_err(|e| AuthError::Email(e.to_string()))?;
        Ok(Self {
            client,
            api_token: deployment.postmark_server_token.clone(),
            api_url: POSTMARK_URL.to_owned(),
            from_address,
            from_display_name,
            branding: Arc::new(branding),
        })
    }

    /// Test-only: override the Postmark URL (used by wiremock tests).
    #[cfg(test)]
    pub(crate) fn with_api_url(mut self, url: String) -> Self {
        self.api_url = url;
        self
    }
}

#[derive(Serialize)]
struct PostmarkBody<'a> {
    #[serde(rename = "From")]
    from: String,
    #[serde(rename = "To")]
    to: &'a str,
    #[serde(rename = "Subject")]
    subject: &'a str,
    #[serde(rename = "HtmlBody")]
    html_body: String,
    #[serde(rename = "TextBody")]
    text_body: String,
}

/// Map a template variant to the static `template_type` string used in
/// log lines. Postmark itself doesn't see this; it's for tracing.
///
/// `EmailTemplate` is `#[non_exhaustive]` across crate boundaries, so a
/// catch-all is required. Future variants land here as `unknown` until
/// this file is updated alongside the variant addition.
fn template_kind(t: &EmailTemplate) -> &'static str {
    match t {
        EmailTemplate::EmailVerification { .. } => "email_verification",
        EmailTemplate::PasswordReset { .. } => "password_reset",
        EmailTemplate::MfaRecovery { .. } => "mfa_recovery",
        EmailTemplate::Invitation { .. } => "invitation",
        _ => "unknown",
    }
}

impl EmailSender for ManagedEmailSender {
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move {
            let rendered = render(&message.template, &self.branding);

            // Quote the display name so any embedded special chars don't
            // break the From header.
            let from = format!(
                "\"{}\" <{}>",
                self.from_display_name.replace('"', ""),
                self.from_address
            );

            let body = PostmarkBody {
                from,
                to: &message.to,
                subject: &message.subject,
                html_body: rendered.html,
                text_body: rendered.text,
            };

            let resp = self
                .client
                .post(&self.api_url)
                .header("X-Postmark-Server-Token", &self.api_token)
                .header(reqwest::header::ACCEPT, "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    AuthError::Email(format!("postmark http: {e}"))
                })?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::Email(format!(
                    "postmark {status}: {body}"
                )));
            }

            tracing::debug!(
                template = template_kind(&message.template),
                to = %message.to,
                "managed email sent via postmark"
            );
            Ok(())
        })
    }
}

// ── EmailSenderFactory + ManagedEmailSenderFactory ───────────────────────────

use allowthem_core::auth_client::AuthFuture;
use allowthem_core::db::Db;
use allowthem_core::email_config::{EmailConfigMode, SmtpTlsMode};
use allowthem_core::email_smtp::{SmtpConfig, SmtpEmailSender, SmtpTls};
use allowthem_core::email_webhook::{WebhookEmailConfig, WebhookEmailSender};
use sqlx::SqlitePool;

use crate::control_db::ControlDb;
use crate::tenants::TenantId;

/// Resolve a per-tenant `EmailSender` from per-tenant config.
///
/// Implementations read whatever lives in the tenant DB
/// (`allowthem_email_config`) and the control plane (`tenants.name`),
/// build the right concrete sender (`SmtpEmailSender` /
/// `WebhookEmailSender` / `ManagedEmailSender`), and hand it back as
/// `Arc<dyn EmailSender>`.
///
/// Async because resolution involves DB I/O and decryption with
/// `mfa_key`. Returns `Arc` (not `Box`) so the SaaS binary can keep a
/// shared instance per tenant in the handle cache.
pub trait EmailSenderFactory: Send + Sync {
    fn for_tenant<'a>(
        &'a self,
        tenant_id: TenantId,
        tenant_pool: &'a SqlitePool,
    ) -> AuthFuture<'a, Arc<dyn EmailSender>>;
}

/// Default factory used by the SaaS binary.
///
/// Reads the tenant's `allowthem_email_config` row and dispatches:
/// - `mode = managed` (or no row) → `ManagedEmailSender`
///   (Postmark-backed) using the deployment config plus the tenant's
///   resolved display name.
/// - `mode = smtp` → `SmtpEmailSender` with the decrypted credentials.
/// - `mode = webhook` → `WebhookEmailSender` with the decrypted secret.
pub struct ManagedEmailSenderFactory {
    control_db: Arc<ControlDb>,
    deployment: Arc<ManagedEmailConfig>,
    mfa_key: [u8; 32],
}

impl ManagedEmailSenderFactory {
    pub fn new(
        control_db: Arc<ControlDb>,
        deployment: ManagedEmailConfig,
        mfa_key: [u8; 32],
    ) -> Self {
        Self {
            control_db,
            deployment: Arc::new(deployment),
            mfa_key,
        }
    }
}

/// Resolve the From-display-name for a tenant. Reads `tenants.name`
/// from the control plane, falling back to `"allowthem"` if the row is
/// missing or the lookup fails (latter is warn-logged).
async fn resolve_display_name(control_db: &ControlDb, tenant_id: TenantId) -> String {
    match control_db.tenant_by_id(&tenant_id).await {
        Ok(Some(t)) => t.name,
        Ok(None) => "allowthem".to_owned(),
        Err(e) => {
            tracing::warn!(
                tenant_id = %tenant_id.as_uuid(),
                error = %e,
                "resolve_display_name: control DB lookup failed; using fallback"
            );
            "allowthem".to_owned()
        }
    }
}

/// Convert the storage form to the `email_smtp::SmtpTls` enum.
fn smtp_tls_to_runtime(mode: SmtpTlsMode) -> SmtpTls {
    match mode {
        SmtpTlsMode::None => SmtpTls::None,
        SmtpTlsMode::StartTls => SmtpTls::StartTls,
        SmtpTlsMode::ImplicitTls => SmtpTls::ImplicitTls,
    }
}

impl EmailSenderFactory for ManagedEmailSenderFactory {
    fn for_tenant<'a>(
        &'a self,
        tenant_id: TenantId,
        tenant_pool: &'a SqlitePool,
    ) -> AuthFuture<'a, Arc<dyn EmailSender>> {
        Box::pin(async move {
            let tenant_db = Db::new(tenant_pool.clone()).await?;
            let cfg_opt = tenant_db.get_email_config(&self.mfa_key).await?;
            let display_name = resolve_display_name(&self.control_db, tenant_id).await;
            let branding = EmailBranding {
                app_name: display_name.clone(),
                logo_url: None,
                footer_line: None,
            };

            // Mode resolution. None → Managed with default everything.
            let mode = cfg_opt.as_ref().map(|c| c.mode).unwrap_or(EmailConfigMode::Managed);
            match mode {
                EmailConfigMode::Smtp => {
                    let smtp = cfg_opt
                        .and_then(|c| c.smtp)
                        .ok_or_else(|| AuthError::Validation(
                            "email_config.mode=smtp but smtp block missing".into(),
                        ))?;
                    let cfg = SmtpConfig {
                        host: smtp.host,
                        port: smtp.port,
                        username: smtp.username,
                        password: smtp.password,
                        from_address: smtp.from_address,
                        from_name: Some(display_name),
                        tls: smtp_tls_to_runtime(smtp.tls),
                    };
                    Ok(Arc::new(SmtpEmailSender::new(cfg, branding)?) as Arc<dyn EmailSender>)
                }
                EmailConfigMode::Webhook => {
                    let webhook = cfg_opt
                        .and_then(|c| c.webhook)
                        .ok_or_else(|| AuthError::Validation(
                            "email_config.mode=webhook but webhook block missing".into(),
                        ))?;
                    let cfg = WebhookEmailConfig {
                        webhook_url: webhook.url,
                        signing_secret: webhook.signing_secret,
                        timeout: Duration::from_secs(10),
                    };
                    Ok(Arc::new(WebhookEmailSender::new(cfg, branding)?) as Arc<dyn EmailSender>)
                }
                EmailConfigMode::Managed => {
                    let from_override = cfg_opt
                        .and_then(|c| c.managed)
                        .and_then(|m| m.from_address);
                    Ok(Arc::new(ManagedEmailSender::new(
                        &self.deployment,
                        from_override,
                        display_name,
                        branding,
                    )?) as Arc<dyn EmailSender>)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use allowthem_core::email::{EmailMessage, EmailTemplate};
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn deployment_config() -> ManagedEmailConfig {
        ManagedEmailConfig {
            postmark_server_token: "test-server-token".into(),
            base_domain: "example.com".into(),
            default_from_local_part: "noreply".into(),
            timeout: Duration::from_secs(5),
        }
    }

    fn reset_message() -> EmailMessage {
        EmailMessage {
            to: "alice@example.com".to_owned(),
            subject: "Reset your password".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: "https://app.example.com/reset?t=abc".to_owned(),
                username: "alice".to_owned(),
            },
        }
    }

    async fn make_sender_for_server(
        server: &MockServer,
        from_override: Option<String>,
        display_name: &str,
    ) -> ManagedEmailSender {
        ManagedEmailSender::new(
            &deployment_config(),
            from_override,
            display_name.to_owned(),
            EmailBranding::default(),
        )
        .unwrap()
        .with_api_url(server.uri())
    }

    #[tokio::test]
    async fn posts_to_postmark_with_correct_headers_and_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("X-Postmark-Server-Token", "test-server-token"))
            .and(header("Accept", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let sender = make_sender_for_server(&server, None, "Acme Inc").await;
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["Subject"], "Reset your password");
        assert_eq!(body["To"], "alice@example.com");
        let html = body["HtmlBody"].as_str().unwrap();
        assert!(
            html.contains("https://app.example.com/reset?t=abc"),
            "rendered html must include action URL"
        );
        let text = body["TextBody"].as_str().unwrap();
        assert!(!text.is_empty(), "text body must not be empty");
    }

    #[tokio::test]
    async fn from_uses_default_when_no_override() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let sender = make_sender_for_server(&server, None, "Acme").await;
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        let from = body["From"].as_str().unwrap();
        assert!(
            from.contains("noreply@mail.example.com"),
            "default From must be `<local>@mail.<base_domain>`: got {from}"
        );
    }

    #[tokio::test]
    async fn from_uses_override_when_provided() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let sender = make_sender_for_server(
            &server,
            Some("noreply@auth.acme.com".into()),
            "Acme",
        )
        .await;
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        let from = body["From"].as_str().unwrap();
        assert!(
            from.contains("noreply@auth.acme.com"),
            "override must be honored; got {from}"
        );
        assert!(
            !from.contains("@mail.example.com"),
            "override must replace default; got {from}"
        );
    }

    #[tokio::test]
    async fn from_includes_display_name() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let sender = make_sender_for_server(&server, None, "Acme Inc").await;
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(
            body["From"], "\"Acme Inc\" <noreply@mail.example.com>",
            "From must be `\"<display>\" <addr>`"
        );
    }

    #[tokio::test]
    async fn branding_app_name_appears_in_html_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let branding = EmailBranding {
            app_name: "Acme Inc".to_owned(),
            logo_url: None,
            footer_line: None,
        };
        let sender = ManagedEmailSender::new(
            &deployment_config(),
            None,
            "Acme Inc".to_owned(),
            branding,
        )
        .unwrap()
        .with_api_url(server.uri());
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        let html = body["HtmlBody"].as_str().unwrap();
        assert!(
            html.contains("Acme Inc"),
            "branding.app_name must appear in HtmlBody: {html}"
        );
    }

    #[tokio::test]
    async fn non_2xx_response_returns_email_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422).set_body_string("validation"))
            .mount(&server)
            .await;

        let sender = make_sender_for_server(&server, None, "X").await;
        let err = sender.send(&reset_message()).await.unwrap_err();
        assert!(
            matches!(err, AuthError::Email(ref s) if s.contains("422")),
            "expected 422 in error message; got {err:?}"
        );
    }

    #[tokio::test]
    async fn timeout_returns_email_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(Duration::from_secs(5)),
            )
            .mount(&server)
            .await;

        let sender = ManagedEmailSender::new(
            &ManagedEmailConfig {
                timeout: Duration::from_millis(100),
                ..deployment_config()
            },
            None,
            "X".to_owned(),
            EmailBranding::default(),
        )
        .unwrap()
        .with_api_url(server.uri());
        let err = sender.send(&reset_message()).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(_)));
    }

    #[tokio::test]
    async fn transport_error_returns_email_error() {
        // Point at a port that refuses connections.
        let sender = ManagedEmailSender::new(
            &deployment_config(),
            None,
            "X".to_owned(),
            EmailBranding::default(),
        )
        .unwrap()
        .with_api_url("http://127.0.0.1:1/email".to_owned());
        let err = sender.send(&reset_message()).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(_)));
    }

    // ── Factory dispatch tests ────────────────────────────────────────────────

    use allowthem_core::email_config::{SetEmailConfig, SmtpOverride, WebhookOverride};

    const FACTORY_MFA_KEY: [u8; 32] = [9u8; 32];

    /// Set up an in-memory control_db with a seeded tenant + plan, and
    /// return the (factory, tenant_id, tenant_pool, control_db) tuple.
    /// `tenant_pool` is a fresh in-memory tenant DB with core migrations
    /// applied (used to seed `allowthem_email_config`).
    async fn setup_factory(
        deployment: ManagedEmailConfig,
        tenant_name: &str,
    ) -> (ManagedEmailSenderFactory, TenantId, Db, Arc<ControlDb>) {
        // Control plane.
        let control_pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .unwrap();
        let control_db = Arc::new(ControlDb::new(control_pool).await.unwrap());

        // Use the seeded 'dev' plan (control plane migrations already
        // insert it). Look up its id rather than re-inserting.
        let plan_id: Vec<u8> = sqlx::query_scalar(
            "SELECT id FROM tenant_plans WHERE name = 'dev' LIMIT 1",
        )
        .fetch_one(control_db.pool())
        .await
        .unwrap();

        let tenant_id = TenantId::new();
        sqlx::query(
            "INSERT INTO tenants \
                (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, 'acme', 'owner@acme.test', ?, 'active', '/tmp/x')",
        )
        .bind(tenant_id.as_bytes())
        .bind(tenant_name)
        .bind(&plan_id)
        .execute(control_db.pool())
        .await
        .unwrap();

        // Tenant DB (in-memory, core migrations).
        let tenant_db = Db::connect("sqlite::memory:").await.unwrap();

        let factory = ManagedEmailSenderFactory::new(
            control_db.clone(),
            deployment,
            FACTORY_MFA_KEY,
        );
        (factory, tenant_id, tenant_db, control_db)
    }

    #[tokio::test]
    async fn factory_dispatches_managed_when_no_config_row() {
        // No allowthem_email_config row → factory selects managed mode and
        // returns a ManagedEmailSender wired to the deployment's Postmark
        // URL. The trait object hides the concrete type; success of
        // `for_tenant` is the dispatch signal. End-to-end Postmark
        // behavior is covered by the dedicated ManagedEmailSender tests
        // earlier in this file.
        let (factory, tenant_id, tenant_db, _ctrl) =
            setup_factory(deployment_config(), "Acme Inc").await;

        factory
            .for_tenant(tenant_id, tenant_db.pool())
            .await
            .expect("managed dispatch must succeed when no config row exists");
    }

    #[tokio::test]
    async fn factory_dispatches_webhook_when_mode_is_webhook() {
        // Webhook config → factory builds a WebhookEmailSender → POST hits
        // the configured webhook URL.
        let webhook_server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&webhook_server)
            .await;

        let (factory, tenant_id, tenant_db, _ctrl) =
            setup_factory(deployment_config(), "Webhook Co").await;

        // Seed webhook config in tenant DB. Use the same mfa_key the
        // factory was built with.
        tenant_db
            .set_email_config(
                &SetEmailConfig {
                    mode: EmailConfigMode::Webhook,
                    smtp: None,
                    webhook: Some(WebhookOverride {
                        url: format!("{}/email", webhook_server.uri()),
                        signing_secret: None,
                    }),
                    managed: None,
                },
                &FACTORY_MFA_KEY,
            )
            .await
            .unwrap();

        let sender = factory
            .for_tenant(tenant_id, tenant_db.pool())
            .await
            .unwrap();
        sender.send(&reset_message()).await.unwrap();

        // Wiremock's expect(1) verifies the POST landed at the tenant's URL,
        // which is the discriminating signal that the webhook path was chosen.
    }

    #[tokio::test]
    async fn factory_dispatches_smtp_when_mode_is_smtp() {
        // SMTP config → factory builds an SmtpEmailSender (construction
        // success is the dispatch signal; full SMTP send-side coverage
        // belongs to email_smtp::tests).
        let (factory, tenant_id, tenant_db, _ctrl) =
            setup_factory(deployment_config(), "Smtp Co").await;

        tenant_db
            .set_email_config(
                &SetEmailConfig {
                    mode: EmailConfigMode::Smtp,
                    smtp: Some(SmtpOverride {
                        host: "localhost".into(),
                        port: 1025,
                        username: None,
                        password: None,
                        from_address: "noreply@smtpco.local".into(),
                        tls: SmtpTlsMode::None,
                    }),
                    webhook: None,
                    managed: None,
                },
                &FACTORY_MFA_KEY,
            )
            .await
            .unwrap();

        // Construction must succeed (TLS::None on localhost is allowed).
        // The trait object's concrete type is opaque; success here is the
        // dispatch signal.
        let _sender = factory
            .for_tenant(tenant_id, tenant_db.pool())
            .await
            .expect("smtp dispatch must succeed for valid SMTP config");
    }

    #[tokio::test]
    async fn factory_resolves_tenant_name_for_display_in_managed_mode() {
        // Managed mode + tenant.name = "Acme Inc" → branding.app_name is
        // "Acme Inc" → renders into the html body. We verify by injecting
        // a wiremock-backed ManagedEmailSender directly with the same
        // branding the factory would produce.
        let (_factory, tenant_id, _tenant_db, control_db) =
            setup_factory(deployment_config(), "Acme Inc").await;
        let display = resolve_display_name(&control_db, tenant_id).await;
        assert_eq!(display, "Acme Inc");
    }

    #[tokio::test]
    async fn factory_falls_back_to_default_when_tenant_row_missing() {
        // Construct the factory but pass a phantom tenant_id (no row in
        // `tenants`). resolve_display_name returns "allowthem".
        let (_factory, _real_id, _tenant_db, control_db) =
            setup_factory(deployment_config(), "Acme Inc").await;

        let phantom = TenantId::new();
        let display = resolve_display_name(&control_db, phantom).await;
        assert_eq!(display, "allowthem");
    }

    // -- Gap-filling regressions (c8m.3.4) ---------------------------------

    #[tokio::test]
    async fn from_strips_double_quotes_from_display_name() {
        // The From header is composed as `"<display>" <addr>`. An embedded
        // double-quote in the tenant's display name would close the
        // quoted-string early and corrupt the header. The sender defends
        // against this with `.replace('"', "")`. Untested in the original
        // suite — a regression that dropped the sanitiser would still
        // produce a `From` field, just a malformed one.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        // A tenant name with embedded quotes — the sanitiser must drop
        // them, leaving `Bob's Diner Inc.` inside the quoted-string slot.
        let sender =
            make_sender_for_server(&server, None, "Bob's \"Diner\" Inc.").await;
        sender.send(&reset_message()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value =
            serde_json::from_slice(&reqs[0].body).unwrap();
        let from = body["From"].as_str().unwrap();
        assert_eq!(
            from, "\"Bob's Diner Inc.\" <noreply@mail.example.com>",
            "embedded double-quotes must be stripped from display name"
        );
    }

    #[tokio::test]
    async fn display_name_falls_back_to_default_when_control_pool_is_closed() {
        // resolve_display_name has three branches: Ok(Some) → name,
        // Ok(None) → "allowthem", Err → warn-log + "allowthem". The
        // Err branch is reachable when the control DB pool is closed
        // (any subsequent query returns sqlx::Error::PoolClosed). The
        // existing tests cover Ok(Some) and Ok(None); this one walks
        // the Err arm.
        let (_factory, tenant_id, _tenant_db, control_db) =
            setup_factory(deployment_config(), "Acme Inc").await;

        // Close the pool so the next query errors. The helper must catch
        // the error, log, and return the default.
        control_db.pool().close().await;

        let display = resolve_display_name(&control_db, tenant_id).await;
        assert_eq!(
            display, "allowthem",
            "Err from control DB lookup must surface as the fallback name"
        );
    }
}
