//! Render `EmailTemplate` instances to branded HTML + plain text.
//!
//! Uses plain `format!` / `write!` interpolation. HTML interpolations for
//! user-controlled strings go through [`html_escape::encode_safe`] to prevent
//! stored XSS in email clients that render rich content (see plan §2.1).
//! Text output is not escaped — clients render it literally.
//!
//! # Exhaustiveness
//!
//! The `match` in [`render`] has no wildcard arm. Because this module lives in
//! the same crate as `EmailTemplate`, `#[non_exhaustive]` does not apply here,
//! so the compiler enforces that every variant is handled. Adding a new variant
//! to `EmailTemplate` will cause a compile error in [`render`] — that is
//! intentional (plan §2.5): every variant must have an explicit branch.

use std::fmt::Write as FmtWrite;

use html_escape::encode_safe;

use crate::email::EmailTemplate;

/// Branding injected into rendered emails at sender-construction time.
///
/// Per-tenant resolution is `allowthem-c8m.3`'s responsibility.
/// Defaults produce plain `allowthem`-branded output.
#[derive(Debug, Clone)]
pub struct EmailBranding {
    /// Name of the application or service shown in the email header.
    pub app_name: String,
    /// Optional logo URL. When `Some`, an `<img>` tag is included in HTML.
    pub logo_url: Option<String>,
    /// Optional footer line rendered verbatim (e.g. "© 2026 Acme, Inc.").
    /// Omitted entirely when `None`.
    pub footer_line: Option<String>,
}

impl Default for EmailBranding {
    fn default() -> Self {
        Self {
            app_name: "allowthem".to_owned(),
            logo_url: None,
            footer_line: None,
        }
    }
}

/// HTML and plain-text output from [`render`].
#[derive(Debug, Clone)]
pub struct RenderedEmail {
    pub html: String,
    pub text: String,
}

/// Render `template` to `RenderedEmail` using `branding`.
pub fn render(template: &EmailTemplate, branding: &EmailBranding) -> RenderedEmail {
    match template {
        EmailTemplate::EmailVerification { url, username } => {
            render_email_verification(url, username, branding)
        }
        EmailTemplate::PasswordReset { url, username } => {
            render_password_reset(url, username, branding)
        }
        EmailTemplate::MfaRecovery { codes, username } => {
            render_mfa_recovery(codes, username, branding)
        }
        EmailTemplate::Invitation { url, invited_by } => {
            render_invitation(url, invited_by, branding)
        }
    }
}

// ─── Private helpers ────────────────────────────────────────────────────────

fn html_header(branding: &EmailBranding) -> String {
    let app = encode_safe(&branding.app_name);
    let logo = branding
        .logo_url
        .as_deref()
        .map(|u| format!("<img src=\"{u}\" alt=\"{app}\" style=\"max-height:48px\" /><br/>"))
        .unwrap_or_default();
    format!(
        "<!doctype html><html><body style=\"font-family:sans-serif;max-width:600px;margin:auto\">\
         <div style=\"padding:24px\">{logo}<h2>{app}</h2>"
    )
}

fn html_footer(branding: &EmailBranding) -> String {
    let footer = branding
        .footer_line
        .as_deref()
        .map(|f| {
            format!(
                "<p class=\"footer\" style=\"font-size:12px;color:#888\">{}</p>",
                encode_safe(f)
            )
        })
        .unwrap_or_default();
    format!("{footer}</div></body></html>")
}

fn text_footer(branding: &EmailBranding) -> String {
    branding
        .footer_line
        .as_deref()
        .map(|f| format!("\n\n---\n{f}"))
        .unwrap_or_default()
}

fn render_email_verification(
    url: &str,
    username: &str,
    branding: &EmailBranding,
) -> RenderedEmail {
    let app = encode_safe(&branding.app_name);
    let safe_user = encode_safe(username);

    let mut html = html_header(branding);
    write!(
        html,
        "<p>Hi {safe_user},</p>\
         <p>Please verify your email address for <strong>{app}</strong>.</p>\
         <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 20px;\
         background:#4f46e5;color:#fff;text-decoration:none;border-radius:4px\">\
         Verify email</a></p>\
         <p>Or copy this link: <code>{url}</code></p>"
    )
    .unwrap();
    html.push_str(&html_footer(branding));

    let text = format!(
        "{} — Verify your email\n\nHi {},\n\nVerify your email:\n{}{}\n",
        branding.app_name,
        username,
        url,
        text_footer(branding)
    );

    RenderedEmail { html, text }
}

fn render_password_reset(url: &str, username: &str, branding: &EmailBranding) -> RenderedEmail {
    let app = encode_safe(&branding.app_name);
    let safe_user = encode_safe(username);

    let mut html = html_header(branding);
    write!(
        html,
        "<p>Hi {safe_user},</p>\
         <p>We received a request to reset your <strong>{app}</strong> password.</p>\
         <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 20px;\
         background:#4f46e5;color:#fff;text-decoration:none;border-radius:4px\">\
         Reset password</a></p>\
         <p>Or copy this link: <code>{url}</code></p>\
         <p>If you did not request this, you can safely ignore this email.</p>"
    )
    .unwrap();
    html.push_str(&html_footer(branding));

    let text = format!(
        "{} — Reset your password\n\nHi {},\n\nReset your password:\n{}\n\n\
         If you did not request this, ignore this email.{}\n",
        branding.app_name,
        username,
        url,
        text_footer(branding)
    );

    RenderedEmail { html, text }
}

fn render_mfa_recovery(
    codes: &[String],
    username: &str,
    branding: &EmailBranding,
) -> RenderedEmail {
    let app = encode_safe(&branding.app_name);
    let safe_user = encode_safe(username);

    let codes_html: String = codes
        .iter()
        .map(|c| format!("<li><code>{}</code></li>", encode_safe(c)))
        .collect();
    let codes_text = codes.join(", ");

    let mut html = html_header(branding);
    write!(
        html,
        "<p>Hi {safe_user},</p>\
         <p>Your <strong>{app}</strong> MFA recovery codes:</p>\
         <ul>{codes_html}</ul>\
         <p>Store these in a safe place. Each code can only be used once.</p>"
    )
    .unwrap();
    html.push_str(&html_footer(branding));

    let text = format!(
        "{} — MFA recovery codes\n\nHi {},\n\nYour recovery codes:\n{}\n\n\
         Each code can only be used once.{}\n",
        branding.app_name,
        username,
        codes_text,
        text_footer(branding)
    );

    RenderedEmail { html, text }
}

fn render_invitation(url: &str, invited_by: &str, branding: &EmailBranding) -> RenderedEmail {
    let app = encode_safe(&branding.app_name);
    let safe_inviter = encode_safe(invited_by);

    let mut html = html_header(branding);
    write!(
        html,
        "<p>You have been invited to join <strong>{app}</strong> by \
         <strong>{safe_inviter}</strong>.</p>\
         <p><a href=\"{url}\" style=\"display:inline-block;padding:10px 20px;\
         background:#4f46e5;color:#fff;text-decoration:none;border-radius:4px\">\
         Accept invitation</a></p>\
         <p>Or copy this link: <code>{url}</code></p>"
    )
    .unwrap();
    html.push_str(&html_footer(branding));

    let text = format!(
        "{} — You've been invited\n\n{} has invited you to join {}.\n\
         Accept here:\n{}{}\n",
        branding.app_name,
        invited_by,
        branding.app_name,
        url,
        text_footer(branding)
    );

    RenderedEmail { html, text }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn branding_default() -> EmailBranding {
        EmailBranding::default()
    }

    fn branding_with_logo() -> EmailBranding {
        EmailBranding {
            app_name: "MyApp".to_owned(),
            logo_url: Some("https://example.com/logo.png".to_owned()),
            footer_line: None,
        }
    }

    fn branding_with_footer() -> EmailBranding {
        EmailBranding {
            app_name: "MyApp".to_owned(),
            logo_url: None,
            footer_line: Some("© 2026 Acme".to_owned()),
        }
    }

    // ─── Email verification ───────────────────────────────────────────────

    #[test]
    fn email_verification_html_contains_url_and_username() {
        let t = EmailTemplate::EmailVerification {
            url: "https://example.com/verify?token=abc".to_owned(),
            username: "alice".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.html.contains("https://example.com/verify?token=abc"));
        assert!(r.html.contains("alice"));
    }

    #[test]
    fn email_verification_text_contains_url_and_username() {
        let t = EmailTemplate::EmailVerification {
            url: "https://example.com/verify?token=abc".to_owned(),
            username: "alice".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.text.contains("https://example.com/verify?token=abc"));
        assert!(r.text.contains("alice"));
    }

    // ─── Password reset ───────────────────────────────────────────────────

    #[test]
    fn password_reset_html_contains_url_and_username() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset?token=xyz".to_owned(),
            username: "bob".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.html.contains("https://example.com/reset?token=xyz"));
        assert!(r.html.contains("bob"));
    }

    #[test]
    fn password_reset_text_contains_url_and_username() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset?token=xyz".to_owned(),
            username: "bob".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.text.contains("https://example.com/reset?token=xyz"));
        assert!(r.text.contains("bob"));
    }

    // ─── MFA recovery ────────────────────────────────────────────────────

    #[test]
    fn mfa_recovery_html_contains_codes_and_username() {
        let t = EmailTemplate::MfaRecovery {
            codes: vec!["AAAA-1111".to_owned(), "BBBB-2222".to_owned()],
            username: "carol".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.html.contains("AAAA-1111"));
        assert!(r.html.contains("BBBB-2222"));
        assert!(r.html.contains("carol"));
    }

    #[test]
    fn mfa_recovery_text_contains_codes_and_username() {
        let t = EmailTemplate::MfaRecovery {
            codes: vec!["AAAA-1111".to_owned(), "BBBB-2222".to_owned()],
            username: "carol".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.text.contains("AAAA-1111"));
        assert!(r.text.contains("BBBB-2222"));
        assert!(r.text.contains("carol"));
    }

    // ─── Invitation ───────────────────────────────────────────────────────

    #[test]
    fn invitation_html_contains_url_and_invited_by() {
        let t = EmailTemplate::Invitation {
            url: "https://example.com/invite?token=inv".to_owned(),
            invited_by: "Dave".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.html.contains("https://example.com/invite?token=inv"));
        assert!(r.html.contains("Dave"));
    }

    #[test]
    fn invitation_text_contains_url_and_invited_by() {
        let t = EmailTemplate::Invitation {
            url: "https://example.com/invite?token=inv".to_owned(),
            invited_by: "Dave".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.text.contains("https://example.com/invite?token=inv"));
        assert!(r.text.contains("Dave"));
    }

    // ─── XSS escaping ────────────────────────────────────────────────────

    #[test]
    fn username_xss_is_escaped_in_html() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset".to_owned(),
            username: "<script>alert(1)</script>".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(r.html.contains("&lt;script&gt;"));
        assert!(!r.html.contains("<script>"));
    }

    #[test]
    fn invited_by_xss_is_escaped_in_html() {
        let t = EmailTemplate::Invitation {
            url: "https://example.com/invite".to_owned(),
            invited_by: "<img src=x onerror=alert(1)>".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(!r.html.contains("<img src=x"));
        assert!(r.html.contains("&lt;img"));
    }

    #[test]
    fn mfa_code_xss_is_escaped_in_html() {
        let t = EmailTemplate::MfaRecovery {
            codes: vec!["<b>bad</b>".to_owned()],
            username: "user".to_owned(),
        };
        let r = render(&t, &branding_default());
        // encode_safe escapes '<' and '&' but not '>'; the important
        // invariant is that '<b>' is not present verbatim.
        assert!(!r.html.contains("<b>bad</b>"));
        assert!(r.html.contains("&lt;b"));
    }

    // ─── Branding ─────────────────────────────────────────────────────────

    #[test]
    fn logo_url_appears_in_html_when_some() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset".to_owned(),
            username: "user".to_owned(),
        };
        let r = render(&t, &branding_with_logo());
        assert!(r.html.contains("<img src=\"https://example.com/logo.png\""));
    }

    #[test]
    fn no_img_tag_when_logo_is_none() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset".to_owned(),
            username: "user".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(!r.html.contains("<img"));
    }

    #[test]
    fn footer_appears_in_html_and_text_when_some() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset".to_owned(),
            username: "user".to_owned(),
        };
        let r = render(&t, &branding_with_footer());
        assert!(r.html.contains("© 2026 Acme"));
        assert!(r.text.contains("© 2026 Acme"));
    }

    #[test]
    fn no_footer_block_when_none() {
        let t = EmailTemplate::PasswordReset {
            url: "https://example.com/reset".to_owned(),
            username: "user".to_owned(),
        };
        let r = render(&t, &branding_default());
        assert!(!r.html.contains("class=\"footer\""));
    }
}
