//! SMTP email delivery via `lettre`.
//!
//! Composes branded HTML + plain-text with a multipart/alternative body.
//! [`SmtpTls`] distinguishes STARTTLS (port 587) from implicit TLS (port 465);
//! see plan §2.2 for the deviation from bd's `tls: bool`.
//!
//! # Example
//!
//! ```no_run
//! use allowthem_core::{SmtpEmailSender, SmtpConfig, SmtpTls, EmailBranding};
//! let sender = SmtpEmailSender::new(
//!     SmtpConfig {
//!         host: "smtp.example.com".to_owned(),
//!         port: 587,
//!         username: Some("user".to_owned()),
//!         password: Some("pass".to_owned()),
//!         from_address: "noreply@example.com".to_owned(),
//!         from_name: Some("Example".to_owned()),
//!         tls: SmtpTls::StartTls,
//!     },
//!     EmailBranding::default(),
//! ).unwrap();
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

use crate::email::{EmailMessage, EmailSender};
use crate::email_render::{EmailBranding, render};
use crate::error::AuthError;

/// Controls TLS mode for SMTP connections.
///
/// Use [`StartTls`](SmtpTls::StartTls) for port 587 (opportunistic STARTTLS
/// upgrade) and [`ImplicitTls`](SmtpTls::ImplicitTls) for port 465 (TLS
/// wrapper). [`None`](SmtpTls::None) is permitted only for localhost and logs
/// a warning at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// No TLS. Only allowed for `localhost` / `127.0.0.1`. Logs a warning.
    None,
    /// STARTTLS upgrade (RFC 3207). Default for port 587.
    StartTls,
    /// Implicit TLS wrapper. Default for port 465.
    ImplicitTls,
}

/// Configuration for [`SmtpEmailSender`].
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    /// SMTP username. `None` means no authentication.
    pub username: Option<String>,
    /// SMTP password. Ignored when `username` is `None`.
    pub password: Option<String>,
    /// `From` envelope address (e.g. `"noreply@example.com"`).
    pub from_address: String,
    /// Optional display name for the `From` header.
    pub from_name: Option<String>,
    pub tls: SmtpTls,
}

/// SMTP email sender backed by `lettre`.
///
/// Generic over the transport so tests can inject
/// `lettre::transport::stub::AsyncStubTransport`.
pub struct SmtpEmailSender<T = AsyncSmtpTransport<Tokio1Executor>> {
    transport: T,
    from: Mailbox,
    branding: Arc<EmailBranding>,
}

impl SmtpEmailSender {
    /// Build a production sender from `config`.
    pub fn new(config: SmtpConfig, branding: EmailBranding) -> Result<Self, AuthError> {
        let is_localhost = config.host == "localhost" || config.host == "127.0.0.1";
        if config.tls == SmtpTls::None && !is_localhost {
            return Err(AuthError::Email(
                "SmtpTls::None is only allowed for localhost hosts".to_owned(),
            ));
        }
        if config.tls == SmtpTls::None {
            tracing::warn!(
                host = %config.host,
                "SmtpEmailSender: using unencrypted SMTP (dev only)"
            );
        }

        let mut builder = match config.tls {
            SmtpTls::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.host)
                    .map_err(|e| AuthError::Email(e.to_string()))?
            }
            SmtpTls::ImplicitTls => {
                AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                    .map_err(|e| AuthError::Email(e.to_string()))?
            }
            SmtpTls::None => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
            }
        };

        builder = builder.port(config.port);

        if let (Some(user), Some(pass)) = (config.username, config.password) {
            builder = builder.credentials(Credentials::new(user, pass));
        }

        let transport = builder.build();
        let from = build_mailbox(config.from_name, &config.from_address)?;

        Ok(Self {
            transport,
            from,
            branding: Arc::new(branding),
        })
    }
}

impl<T> SmtpEmailSender<T> {
    /// Test constructor: inject any transport.
    #[cfg(test)]
    pub fn new_with_transport(transport: T, branding: EmailBranding) -> Self {
        Self {
            transport,
            from: "Test Sender <test@example.com>"
                .parse()
                .expect("hardcoded mailbox is valid"),
            branding: Arc::new(branding),
        }
    }
}

impl<T> EmailSender for SmtpEmailSender<T>
where
    T: AsyncTransport + Send + Sync,
    T::Error: std::fmt::Display,
{
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        Box::pin(async move {
            let rendered = render(&message.template, &self.branding);

            let to: Mailbox = message
                .to
                .parse()
                .map_err(|e: lettre::address::AddressError| AuthError::Email(e.to_string()))?;

            let email = Message::builder()
                .from(self.from.clone())
                .to(to)
                .subject(&message.subject)
                .multipart(
                    MultiPart::alternative()
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_PLAIN)
                                .body(rendered.text),
                        )
                        .singlepart(
                            SinglePart::builder()
                                .header(ContentType::TEXT_HTML)
                                .body(rendered.html),
                        ),
                )
                .map_err(|e| AuthError::Email(e.to_string()))?;

            self.transport
                .send(email)
                .await
                .map(|_| ())
                .map_err(|e| AuthError::Email(e.to_string()))
        })
    }
}

fn build_mailbox(name: Option<String>, address: &str) -> Result<Mailbox, AuthError> {
    let addr: lettre::Address = address
        .parse()
        .map_err(|e: lettre::address::AddressError| AuthError::Email(e.to_string()))?;
    Ok(Mailbox::new(name, addr))
}

#[cfg(test)]
mod tests {
    use lettre::transport::stub::AsyncStubTransport;

    use crate::email::EmailTemplate;

    use super::*;

    fn make_sender() -> SmtpEmailSender<AsyncStubTransport> {
        let stub = AsyncStubTransport::new_ok();
        SmtpEmailSender::new_with_transport(stub, EmailBranding::default())
    }

    fn reset_message() -> EmailMessage {
        EmailMessage {
            to: "alice@example.com".to_owned(),
            subject: "Reset your password".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: "https://example.com/reset?t=abc".to_owned(),
                username: "alice".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn send_captures_message_with_correct_headers() {
        let sender = make_sender();
        sender.send(&reset_message()).await.unwrap();

        let msgs = sender.transport.messages().await;
        assert_eq!(msgs.len(), 1);
        let (envelope, raw) = &msgs[0];
        // Recipient in envelope
        let to_addrs: Vec<_> = envelope.to().iter().map(|a| a.as_ref()).collect();
        assert!(to_addrs.contains(&"alice@example.com"));
        // Both text and HTML bodies present
        assert!(raw.contains("Reset your password"));
        assert!(raw.contains("text/plain"));
        assert!(raw.contains("text/html"));
    }

    #[tokio::test]
    async fn address_parse_failure_returns_email_error() {
        let sender = make_sender();
        let msg = EmailMessage {
            to: "not-an-email".to_owned(),
            subject: "Subject".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: "https://example.com".to_owned(),
                username: "x".to_owned(),
            },
        };
        let err = sender.send(&msg).await.unwrap_err();
        assert!(matches!(err, AuthError::Email(_)));
    }

    #[test]
    fn tls_none_refused_for_non_localhost() {
        let cfg = SmtpConfig {
            host: "smtp.example.com".to_owned(),
            port: 25,
            username: None,
            password: None,
            from_address: "x@example.com".to_owned(),
            from_name: None,
            tls: SmtpTls::None,
        };
        let result = SmtpEmailSender::new(cfg, EmailBranding::default());
        assert!(matches!(result, Err(AuthError::Email(_))));
    }

    #[test]
    fn tls_none_allowed_for_localhost() {
        let cfg = SmtpConfig {
            host: "localhost".to_owned(),
            port: 1025,
            username: None,
            password: None,
            from_address: "x@example.com".to_owned(),
            from_name: None,
            tls: SmtpTls::None,
        };
        // Should succeed (no actual connection attempt at construction time).
        assert!(SmtpEmailSender::new(cfg, EmailBranding::default()).is_ok());
    }

    #[test]
    fn no_auth_config_succeeds() {
        // username = None, password = None — no Credentials set.
        let cfg = SmtpConfig {
            host: "localhost".to_owned(),
            port: 1025,
            username: None,
            password: None,
            from_address: "x@example.com".to_owned(),
            from_name: None,
            tls: SmtpTls::None,
        };
        assert!(SmtpEmailSender::new(cfg, EmailBranding::default()).is_ok());
    }
}
