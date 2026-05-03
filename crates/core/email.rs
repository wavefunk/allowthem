use std::future::Future;
use std::pin::Pin;

use crate::error::AuthError;

/// An email message to be sent.
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub template: EmailTemplate,
}

/// Typed email template variants.
///
/// `#[non_exhaustive]` ensures future variants (e.g. `TransferNotification`)
/// can be added in c8m.2/c8m.3 without a breaking API change. Sender
/// implementations must include a catch-all arm on exhaustive matches.
#[non_exhaustive]
pub enum EmailTemplate {
    EmailVerification {
        url: String,
        username: String,
    },
    PasswordReset {
        url: String,
        username: String,
    },
    MfaRecovery {
        codes: Vec<String>,
        username: String,
    },
    /// Workspace or service invitation.
    ///
    /// `invited_by` carries a display name — either a person's display name
    /// (standalone server context) or an organisation name (saas context).
    /// Sender implementations should render it as-is.
    Invitation {
        url: String,
        invited_by: String,
    },
}

/// Abstraction over email delivery.
///
/// Implementors are responsible for the actual transport (SMTP, SES, SendGrid,
/// etc.). The library provides [`LogEmailSender`] for development, which
/// prints the message to the tracing log instead of delivering it, and
/// [`NoopEmailSender`] as the silent default for embedded integrators that
/// do not need email.
///
/// Implement this trait and pass it to the builder when email delivery is
/// needed (password reset, email verification, etc.).
pub trait EmailSender: Send + Sync {
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>>;
}

/// Development email sender that logs messages instead of delivering them.
///
/// Writes the recipient, subject, and template at `info` level so they appear
/// in local dev output. Does not perform any network I/O. Returns `Ok(())`.
pub struct LogEmailSender;

impl EmailSender for LogEmailSender {
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        tracing::info!(
            to = %message.to,
            subject = %message.subject,
            template = ?message.template,
            "dev email (not delivered)"
        );
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Silent default email sender for embedded integrators that do not need email.
///
/// Logs the recipient and subject at `debug` level and returns `Ok(())`.
/// Does not perform any network I/O.
///
/// **Production deployments** must replace this with a real sender via
/// [`AllowThemBuilder::email_sender`]. A `tracing::warn!` is emitted at build
/// time when `NoopEmailSender` remains the default, making the omission
/// visible in startup logs.
pub struct NoopEmailSender;

impl EmailSender for NoopEmailSender {
    fn send<'a>(
        &'a self,
        message: &'a EmailMessage,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuthError>> + Send + 'a>> {
        tracing::debug!(
            to = %message.to,
            subject = %message.subject,
            "email dropped (NoopEmailSender)"
        );
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Derive a display username from a user record.
///
/// Returns `user.username` if set, otherwise falls back to the local part of
/// the email address (everything before `@`). If neither yields a non-empty
/// string, returns `"there"` so templates can safely write "Hi, there".
///
/// Place the result directly into `EmailTemplate::*::username` fields.
pub(crate) fn fallback_username(user: &crate::types::User) -> String {
    if let Some(u) = &user.username {
        return u.as_str().to_owned();
    }
    user.email
        .as_str()
        .split('@')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("there")
        .to_owned()
}

// Allow formatting EmailTemplate in log messages.
impl std::fmt::Debug for EmailTemplate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EmailTemplate::EmailVerification { url, username } => f
                .debug_struct("EmailVerification")
                .field("url", url)
                .field("username", username)
                .finish(),
            EmailTemplate::PasswordReset { url, username } => f
                .debug_struct("PasswordReset")
                .field("url", url)
                .field("username", username)
                .finish(),
            EmailTemplate::MfaRecovery { codes, username } => f
                .debug_struct("MfaRecovery")
                .field("codes_count", &codes.len())
                .field("username", username)
                .finish(),
            EmailTemplate::Invitation { url, invited_by } => f
                .debug_struct("Invitation")
                .field("url", url)
                .field("invited_by", invited_by)
                .finish(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that EmailSender is dyn-compatible.
    fn _assert_object_safe(_: &dyn EmailSender) {}

    fn make_reset_message() -> EmailMessage {
        EmailMessage {
            to: "user@example.com".to_owned(),
            subject: "Reset your password".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: "https://example.com/reset?token=abc".to_owned(),
                username: "user".to_owned(),
            },
        }
    }

    #[tokio::test]
    async fn log_sender_succeeds() {
        let sender = LogEmailSender;
        let msg = make_reset_message();
        let result = sender.send(&msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn log_sender_succeeds_with_invitation_template() {
        let sender = LogEmailSender;
        let msg = EmailMessage {
            to: "invitee@example.com".to_owned(),
            subject: "You've been invited".to_owned(),
            template: EmailTemplate::Invitation {
                url: "https://example.com/invite/tok123".to_owned(),
                invited_by: "Acme Corp".to_owned(),
            },
        };
        let result = sender.send(&msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn noop_sender_succeeds() {
        let sender = NoopEmailSender;
        let msg = make_reset_message();
        let result = sender.send(&msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn trait_object_dispatch_works() {
        let sender: Box<dyn EmailSender> = Box::new(LogEmailSender);
        let msg = make_reset_message();
        let result = sender.send(&msg).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn noop_trait_object_dispatch_works() {
        let sender: Box<dyn EmailSender> = Box::new(NoopEmailSender);
        let msg = make_reset_message();
        let result = sender.send(&msg).await;
        assert!(result.is_ok());
    }
}
