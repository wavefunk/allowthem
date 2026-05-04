//! HTTP webhook email delivery.
//!
//! POSTs the rendered email plus structured template data to a
//! customer-supplied URL. Optionally HMAC-signs the body using the shared
//! [`crate::webhook_sig::sign_payload`] helper (plan §2.7).
//!
//! There is **no retry** in this sender. The integrator's endpoint must be
//! reliable, or they should configure a real SMTP path instead. See plan §2.7.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::email::{EmailMessage, EmailSender, EmailTemplate};
use crate::email_render::{EmailBranding, render};
use crate::error::AuthError;
use crate::webhook_sig::sign_payload;

/// Configuration for [`WebhookEmailSender`].
#[derive(Debug, Clone)]
pub struct WebhookEmailConfig {
    /// URL to POST email notifications to.
    pub webhook_url: String,
    /// HMAC-SHA256 signing secret. When `None`, no `X-Allowthem-Signature`
    /// header is sent.
    pub signing_secret: Option<Vec<u8>>,
    /// Per-request timeout. Defaults to 10 seconds.
    pub timeout: Duration,
}

impl Default for WebhookEmailConfig {
    fn default() -> Self {
        Self {
            webhook_url: String::new(),
            signing_secret: None,
            timeout: Duration::from_secs(10),
        }
    }
}

/// Email sender that POSTs rendered emails to a customer webhook endpoint.
pub struct WebhookEmailSender {
    client: reqwest::Client,
    config: Arc<WebhookEmailConfig>,
    branding: Arc<EmailBranding>,
}

impl WebhookEmailSender {
    /// Build a sender. Returns `Err` if the underlying HTTP client cannot be
    /// constructed (rare; typically only a TLS init failure).
    pub fn new(config: WebhookEmailConfig, branding: EmailBranding) -> Result<Self, AuthError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| AuthError::Email(e.to_string()))?;
        Ok(Self {
            client,
            config: Arc::new(config),
            branding: Arc::new(branding),
        })
    }
}

// ─── Payload types ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct WebhookPayload<'a> {
    to: &'a str,
    subject: &'a str,
    template_type: &'static str,
    template_data: TemplateData<'a>,
    rendered: RenderedRef<'a>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum TemplateData<'a> {
    EmailVerification {
        url: &'a str,
        username: &'a str,
    },
    PasswordReset {
        url: &'a str,
        username: &'a str,
    },
    MfaRecovery {
        codes: &'a [String],
        username: &'a str,
    },
    Invitation {
        url: &'a str,
        invited_by: &'a str,
    },
}

#[derive(Serialize)]
struct RenderedRef<'a> {
    html: &'a str,
    text: &'a str,
}

fn template_type(t: &EmailTemplate) -> &'static str {
    match t {
        EmailTemplate::EmailVerification { .. } => "email_verification",
        EmailTemplate::PasswordReset { .. } => "password_reset",
        EmailTemplate::MfaRecovery { .. } => "mfa_recovery",
        EmailTemplate::Invitation { .. } => "invitation",
    }
}

fn template_data(t: &EmailTemplate) -> TemplateData<'_> {
    match t {
        EmailTemplate::EmailVerification { url, username } => {
            TemplateData::EmailVerification { url, username }
        }
        EmailTemplate::PasswordReset { url, username } => {
            TemplateData::PasswordReset { url, username }
        }
        EmailTemplate::MfaRecovery { codes, username } => {
            TemplateData::MfaRecovery { codes, username }
        }
        EmailTemplate::Invitation { url, invited_by } => {
            TemplateData::Invitation { url, invited_by }
        }
    }
}

// ─── EmailSender impl ────────────────────────────────────────────────────────

impl EmailSender for WebhookEmailSender {
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move {
            let rendered = render(&message.template, &self.branding);

            let payload = WebhookPayload {
                to: &message.to,
                subject: &message.subject,
                template_type: template_type(&message.template),
                template_data: template_data(&message.template),
                rendered: RenderedRef {
                    html: &rendered.html,
                    text: &rendered.text,
                },
            };

            let body = serde_json::to_vec(&payload).map_err(|e| AuthError::Email(e.to_string()))?;

            let mut req = self
                .client
                .post(&self.config.webhook_url)
                .header("Content-Type", "application/json")
                .header(
                    "X-Allowthem-Email-Template",
                    template_type(&message.template),
                );

            if let Some(secret) = &self.config.signing_secret {
                let ts = chrono::Utc::now().timestamp();
                let sig = sign_payload(secret, ts, &body);
                req = req.header("X-Allowthem-Signature", sig);
            }

            let resp = req
                .body(body)
                .send()
                .await
                .map_err(|e| AuthError::Email(e.to_string()))?;

            if resp.status().is_success() {
                Ok(())
            } else {
                Err(AuthError::Email(format!(
                    "webhook responded {}",
                    resp.status()
                )))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::email::EmailTemplate;
    use crate::webhook_sig::verify_payload;

    use super::*;

    fn password_reset_msg() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".to_owned(),
            subject: "Reset your password".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: "https://app.example.com/reset?t=tok".to_owned(),
                username: "alice".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn posts_json_without_signature_when_no_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .and(header("Content-Type", "application/json"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: None,
                timeout: Duration::from_secs(5),
            },
            EmailBranding::default(),
        )
        .unwrap();

        sender.send(&password_reset_msg()).await.unwrap();

        // Assert no signature header was sent.
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        assert!(!reqs[0].headers.contains_key("x-allowthem-signature"));

        // Assert body is a well-formed JSON with expected template_type.
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["template_type"], "password_reset");
        assert_eq!(body["to"], "user@example.com");
        assert!(
            body["rendered"]["html"]
                .as_str()
                .unwrap()
                .contains("<!doctype html>")
        );
        assert!(body["rendered"]["text"].as_str().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn posts_with_valid_signature_when_secret_provided() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let secret = b"webhook-secret".to_vec();
        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: Some(secret.clone()),
                timeout: Duration::from_secs(5),
            },
            EmailBranding::default(),
        )
        .unwrap();

        sender.send(&password_reset_msg()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let sig_header = reqs[0]
            .headers
            .get("x-allowthem-signature")
            .expect("signature header must be present")
            .to_str()
            .unwrap();

        let now = chrono::Utc::now().timestamp();
        verify_payload(&secret, &reqs[0].body, sig_header, now, 60).unwrap();
    }

    #[tokio::test]
    async fn non_2xx_response_returns_email_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: None,
                timeout: Duration::from_secs(5),
            },
            EmailBranding::default(),
        )
        .unwrap();

        let err = sender.send(&password_reset_msg()).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(ref s) if s.contains("500")));
    }

    #[tokio::test]
    async fn transport_error_returns_email_error() {
        // Point at a port that refuses connections.
        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: "http://127.0.0.1:1/hook".to_owned(),
                signing_secret: None,
                timeout: Duration::from_millis(500),
            },
            EmailBranding::default(),
        )
        .unwrap();

        let err = sender.send(&password_reset_msg()).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(_)));
    }

    #[tokio::test]
    async fn timeout_returns_email_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;

        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: None,
                timeout: Duration::from_millis(100),
            },
            EmailBranding::default(),
        )
        .unwrap();

        let err = sender.send(&password_reset_msg()).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(_)));
    }

    #[tokio::test]
    async fn includes_template_header_and_full_payload_shape() {
        // The plan §2.7 wire contract: integrators rely on the
        // `X-Allowthem-Email-Template` header to dispatch by template
        // (without parsing the body) and on `template_data` to re-render
        // in their own engine. Pin both.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: None,
                timeout: Duration::from_secs(5),
            },
            EmailBranding::default(),
        )
        .unwrap();

        sender.send(&password_reset_msg()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let req = &reqs[0];
        assert_eq!(
            req.headers
                .get("x-allowthem-email-template")
                .expect("X-Allowthem-Email-Template header must be present")
                .to_str()
                .unwrap(),
            "password_reset"
        );

        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        // template_data carries the structured fields as the original
        // EmailTemplate variant — re-render fodder for integrators.
        assert_eq!(
            body["template_data"]["url"],
            "https://app.example.com/reset?t=tok"
        );
        assert_eq!(body["template_data"]["username"], "alice");
        assert_eq!(body["subject"], "Reset your password");
    }

    #[tokio::test]
    async fn branding_app_name_appears_in_rendered_html() {
        // Sender-level branding (§2.4) flows into the `rendered.html` body.
        // Webhook integrators that present the pre-rendered email keep the
        // configured app name without re-rendering.
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
        let sender = WebhookEmailSender::new(
            WebhookEmailConfig {
                webhook_url: format!("{}/hook", server.uri()),
                signing_secret: None,
                timeout: Duration::from_secs(5),
            },
            branding,
        )
        .unwrap();

        sender.send(&password_reset_msg()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        let html = body["rendered"]["html"].as_str().unwrap();
        assert!(
            html.contains("Acme Inc"),
            "branding.app_name must appear in rendered.html: {html}"
        );
    }
}
