use std::future::Future;
use std::pin::Pin;

use crate::error::AuthError;

/// An email message to be sent.
pub struct EmailMessage<'a> {
    pub to: &'a str,
    pub subject: &'a str,
    pub body: &'a str,
    pub html: Option<&'a str>,
}

/// Abstraction over email delivery.
///
/// Implementors are responsible for the actual transport (SMTP, SES, SendGrid,
/// etc.). The library provides [`LogEmailSender`] for development, which
/// prints the message to the tracing log instead of delivering it.
///
/// Implement this trait and pass it to the builder when email delivery is
/// needed (password reset, email verification, etc.).
pub trait EmailSender: Send + Sync {
    fn send<'a>(
        &'a self,
        message: EmailMessage<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>>;
}

/// Development email sender that logs messages instead of delivering them.
///
/// Writes each field of the message at `info` level so they appear in
/// local dev output. Does not perform any network I/O. Returns `Ok(())`.
pub struct LogEmailSender;

impl EmailSender for LogEmailSender {
    fn send<'a>(
        &'a self,
        message: EmailMessage<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        tracing::info!(
            to = message.to,
            subject = message.subject,
            body = message.body,
            html = message.html,
            "dev email (not delivered)"
        );
        Box::pin(std::future::ready(Ok(())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that EmailSender is dyn-compatible.
    fn _assert_object_safe(_: &dyn EmailSender) {}

    #[tokio::test]
    async fn log_sender_succeeds() {
        let sender = LogEmailSender;
        let msg = EmailMessage {
            to: "user@example.com",
            subject: "Test",
            body: "Hello",
            html: None,
        };
        let result = sender.send(msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn log_sender_succeeds_with_html() {
        let sender = LogEmailSender;
        let msg = EmailMessage {
            to: "user@example.com",
            subject: "Test",
            body: "Hello",
            html: Some("<p>Hello</p>"),
        };
        let result = sender.send(msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn trait_object_dispatch_works() {
        let sender: Box<dyn EmailSender> = Box::new(LogEmailSender);
        let msg = EmailMessage {
            to: "user@example.com",
            subject: "Subject",
            body: "Body",
            html: None,
        };
        let result = sender.send(msg).await;
        assert!(result.is_ok());
    }
}
