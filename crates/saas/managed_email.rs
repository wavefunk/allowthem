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
}
