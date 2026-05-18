use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use axum::response::Html;
use html_escape::{encode_double_quoted_attribute as esc_attr, encode_text as esc_text};

use allowthem_core::OAuthAccountInfo;
use allowthem_core::applications::BrandingConfig;

use crate::branding::BrandingCtx;
use crate::browser_error::BrowserError;
use crate::custom_fields::{CustomFieldDescriptor, FieldType};
use crate::shell_context::ShellContext;
use crate::ui::{render_component, trusted_html};

use wavefunk_ui::components::{
    Alert, Checklist, ChecklistItem, CodeGrid, FeedbackKind, FormPanel, HtmlAttr, Modeline,
    ModelineSegment, PageHeader, SecretValue, Sidenav, SidenavItem, SidenavSection, StrengthMeter,
};
use wavefunk_ui::layouts::AppShell;

const READY_SCRIPT: &str = r#"<script>document.addEventListener("DOMContentLoaded",function(){document.dispatchEvent(new CustomEvent("wfEcho",{detail:{kind:"ok",msg:"Ready."}}));});</script>"#;

pub struct LoginView<'a> {
    pub csrf_token: &'a str,
    pub identifier: &'a str,
    pub next: Option<&'a str>,
    pub error: &'a str,
    pub client_id: Option<&'a str>,
    pub oauth_providers: &'a [String],
    pub signup_url: Option<&'a str>,
    pub terms_url: Option<&'a str>,
    pub privacy_url: Option<&'a str>,
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct RegisterView<'a> {
    pub csrf_token: &'a str,
    pub email: &'a str,
    pub username: &'a str,
    pub error: &'a str,
    pub client_id: Option<&'a str>,
    pub branding: Option<&'a BrandingConfig>,
    pub custom_fields: &'a [CustomFieldDescriptor],
    pub custom_values: &'a HashMap<&'a str, &'a str>,
    pub token: Option<&'a str>,
    pub email_readonly: bool,
    pub registration_disabled: bool,
    pub oauth_providers: &'a [String],
    pub is_production: bool,
}

pub struct ForgotPasswordView<'a> {
    pub csrf_token: &'a str,
    pub error: &'a str,
    pub success: bool,
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct ResetPasswordView<'a> {
    pub csrf_token: &'a str,
    pub token: &'a str,
    pub invalid_token: bool,
    pub success: bool,
    pub error: &'a str,
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct MfaSetupView<'a> {
    pub csrf_token: &'a str,
    pub totp_uri: &'a str,
    pub qr_data_uri: &'a str,
    pub secret: &'a str,
    pub error: &'a str,
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct MfaRecoveryView<'a> {
    pub recovery_codes: &'a [String],
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct MfaChallengeView<'a> {
    pub mfa_token: &'a str,
    pub error: &'a str,
    pub branding: Option<&'a BrandingConfig>,
    pub is_production: bool,
}

pub struct ConsentView<'a> {
    pub application_name: &'a str,
    pub app_name: &'a str,
    pub logo_url: Option<&'a str>,
    pub accent: &'a str,
    pub accent_ink: &'a str,
    pub accent_light: &'a str,
    pub accent_ink_light: &'a str,
    pub scope_items: &'a [ConsentScopeView],
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub response_type: &'a str,
    pub scope: &'a str,
    pub state_param: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub nonce: Option<&'a str>,
    pub csrf_token: &'a str,
    pub user_email: &'a str,
    pub is_production: bool,
}

pub struct ConsentScopeView {
    pub description: String,
}

pub struct SettingsView<'a> {
    pub csrf_token: &'a str,
    pub shell: &'a ShellContext,
    pub email: &'a str,
    pub username: &'a str,
    pub profile_error: &'a str,
    pub profile_success: &'a str,
    pub password_error: &'a str,
    pub password_success: &'a str,
    pub oauth_accounts: &'a [OAuthAccountInfo],
    pub mfa_enabled: bool,
    pub mfa_recovery_remaining: i64,
    pub is_production: bool,
}

pub fn login_page(view: &LoginView<'_>) -> Result<Html<String>, BrowserError> {
    let main = login_main(view)?;
    auth_page(
        "Log in",
        Some("to"),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn login_fragment(view: &LoginView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(&login_main(view)?, "Log in — allowthem", "SIGN IN")
}

pub fn register_page(view: &RegisterView<'_>) -> Result<Html<String>, BrowserError> {
    let main = register_main(view)?;
    auth_page(
        "Create account",
        Some("on"),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn register_fragment(view: &RegisterView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &register_main(view)?,
        "Register — allowthem",
        "CREATE ACCOUNT",
    )
}

pub fn forgot_password_page(view: &ForgotPasswordView<'_>) -> Result<Html<String>, BrowserError> {
    let main = forgot_password_main(view)?;
    auth_page(
        "Forgot password",
        Some(""),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn forgot_password_fragment(
    view: &ForgotPasswordView<'_>,
) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &forgot_password_main(view)?,
        "Forgot password — allowthem",
        "FORGOT PASSWORD",
    )
}

pub fn reset_password_page(view: &ResetPasswordView<'_>) -> Result<Html<String>, BrowserError> {
    let main = reset_password_main(view)?;
    auth_page(
        "Reset password",
        Some(""),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn reset_password_fragment(view: &ResetPasswordView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &reset_password_main(view)?,
        "Reset password — allowthem",
        "RESET PASSWORD",
    )
}

pub fn mfa_setup_page(view: &MfaSetupView<'_>) -> Result<Html<String>, BrowserError> {
    let main = mfa_setup_main(view)?;
    auth_page(
        "Enable two-factor authentication",
        Some(""),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn mfa_setup_fragment(view: &MfaSetupView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &mfa_setup_main(view)?,
        "Enable two-factor authentication — allowthem",
        "ENABLE 2FA",
    )
}

pub fn mfa_recovery_page(view: &MfaRecoveryView<'_>) -> Result<Html<String>, BrowserError> {
    let main = mfa_recovery_main(view)?;
    auth_page(
        "Recovery codes",
        Some(""),
        &main,
        view.branding,
        view.is_production,
        "",
    )
}

pub fn mfa_recovery_fragment(view: &MfaRecoveryView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &mfa_recovery_main(view)?,
        "Recovery codes — allowthem",
        "RECOVERY CODES",
    )
}

pub fn mfa_challenge_page(view: &MfaChallengeView<'_>) -> Result<Html<String>, BrowserError> {
    let main = mfa_challenge_main(view)?;
    auth_page(
        "Two-factor authentication",
        Some(""),
        &main,
        view.branding,
        view.is_production,
        mfa_challenge_head(),
    )
}

pub fn mfa_challenge_fragment(view: &MfaChallengeView<'_>) -> Result<Html<String>, BrowserError> {
    auth_fragment(
        &mfa_challenge_main(view)?,
        "Two-factor authentication — allowthem",
        "TWO-FACTOR",
    )
}

pub fn consent_page(view: &ConsentView<'_>) -> Result<Html<String>, BrowserError> {
    let main = consent_main(view)?;
    let title = format!("Authorize {} — allowthem", view.application_name);
    auth_page_with_accent(
        &title,
        "Consent",
        &main,
        AuthAccent {
            app_name: view.app_name,
            accent: view.accent,
            accent_ink: view.accent_ink,
            accent_light: view.accent_light,
            accent_ink_light: view.accent_ink_light,
            branding: None,
        },
        view.is_production,
        "",
    )
}

pub fn consent_fragment(view: &ConsentView<'_>) -> Result<Html<String>, BrowserError> {
    let title = format!("Authorize {} — allowthem", view.application_name);
    auth_fragment(&consent_main(view)?, &title, "CONSENT")
}

pub fn settings_page(view: &SettingsView<'_>) -> Result<Html<String>, BrowserError> {
    let content = settings_content(view)?;
    let nav = sidebar_nav(view.shell)?;
    let page_header = render_component(&PageHeader::new("Settings"))?.into_string();
    let footer = modeline_html(view.is_production, view.shell.status_session.as_deref())?;
    let head = r#"<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
<script>(function(){try{var m=localStorage.getItem('allowthem:mode');if((m==='dark'||m==='light')&&!document.documentElement.hasAttribute('data-mode-locked')){document.documentElement.dataset.mode=m;}}catch(_e){}})();</script>"#;
    let scripts =
        r#"<script src="/__allowthem/static/js/mode-toggle.js" defer></script>"#.to_owned();
    let shell = AppShell::new("Settings — allowthem", "allowthem", &content)
        .with_brand_href("/")
        .with_nav(&nav)
        .with_breadcrumbs(trusted_html("Account · Settings"))
        .with_page_header(trusted_html(&page_header))
        .with_footer(trusted_html(&footer))
        .with_head(trusted_html(head))
        .with_scripts(trusted_html(&scripts))
        .without_body_hx_boost();
    Ok(Html(render_component(&shell)?.into_string()))
}

fn login_main(view: &LoginView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let register_href = view
        .signup_url
        .map(str::to_owned)
        .or_else(|| {
            view.client_id
                .map(|c| format!("/register?client_id={}", url_encode(c)))
        })
        .unwrap_or_else(|| "/register".to_owned());

    let mut body = String::new();
    write!(
        body,
        r#"<div class="wf-mt-5">{}</div>"#,
        tabs("signin", &register_href)
    )
    .unwrap();
    if !view.error.is_empty() {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert("err", view.error)?
        )
        .unwrap();
    }
    write!(
        body,
        r#"<form method="post" action="/login" class="wf-f wf-col wf-gap-5 wf-mt-5">"#
    )
    .unwrap();
    hidden(&mut body, "csrf_token", view.csrf_token);
    if let Some(next) = view.next.filter(|v| !v.is_empty()) {
        hidden(&mut body, "next", next);
    }
    if let Some(client_id) = view.client_id {
        hidden(&mut body, "client_id", client_id);
    }
    field_text(
        &mut body,
        "Email or username",
        r#"<input class="wf-input" id="identifier" name="identifier" type="text" value=""#,
        view.identifier,
        r#"" autocomplete="username" required>"#,
    );
    write!(
        body,
        r#"<div class="wf-field"><div class="wf-f wf-jc-sb wf-ai-b"><label class="wf-label" for="password">Password</label><a href="/forgot-password" hx-boost="true" class="wf-fg-muted wf-caption" style="text-decoration: none">Forgot?</a></div><input class="wf-input" id="password" name="password" type="password" autocomplete="current-password" required></div>"#
    )
    .unwrap();
    write!(
        body,
        r#"<button type="submit" class="wf-btn primary lg wf-w-full">Sign in →</button></form>"#
    )
    .unwrap();
    body.push_str(&oauth_grid(view.oauth_providers, view.next));
    body.push_str(&terms_footer(view.terms_url, view.privacy_url));

    let panel = form_panel("Sign in", "Welcome back.", &body)?;
    Ok(auth_main(
        &kicker(
            app_name,
            "Sign in",
            Some(register_href.as_str()),
            "Create account",
            "New here?",
        ),
        &panel,
    ))
}

fn register_main(view: &RegisterView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let login_href = view
        .client_id
        .map(|c| format!("/login?client_id={}", url_encode(c)))
        .unwrap_or_else(|| "/login".to_owned());
    let register_href = view
        .client_id
        .map(|c| format!("/register?client_id={}", url_encode(c)))
        .unwrap_or_else(|| "/register".to_owned());
    let (panel_title, subtitle) = if view.registration_disabled {
        (
            "Registration disabled",
            "Ask an admin for an invitation link.",
        )
    } else if view.token.is_some() {
        ("Accept invitation", "Finish creating your account.")
    } else {
        ("Create account", "Let's get you set up.")
    };

    let mut body = String::new();
    write!(
        body,
        r#"<div class="wf-mt-5">{}</div>"#,
        tabs("signup", &register_href)
    )
    .unwrap();
    if !view.error.is_empty() {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert("err", view.error)?
        )
        .unwrap();
    }
    if view.registration_disabled {
        write!(
            body,
            r#"<div class="wf-mt-5"><a class="wf-btn primary lg wf-w-full" href="/login">Back to sign in →</a></div>"#
        )
        .unwrap();
    } else {
        write!(
            body,
            r#"<form class="wf-form" action="/register" method="post">"#
        )
        .unwrap();
        hidden(&mut body, "csrf_token", view.csrf_token);
        if let Some(token) = view.token {
            hidden(&mut body, "token", token);
        }
        input_field(
            &mut body,
            "Email",
            "email",
            "email",
            view.email,
            &[("id", "email"), ("autocomplete", "email")],
            true,
            view.email_readonly,
            None,
        );
        input_field(
            &mut body,
            "Username",
            "username",
            "text",
            view.username,
            &[("id", "username"), ("autocomplete", "username")],
            false,
            false,
            Some("Optional"),
        );
        for field in view.custom_fields {
            custom_field(&mut body, field, view.custom_values);
        }
        let strength = render_component(
            &StrengthMeter::new(0, 5, "Enter a password")
                .with_label("Password strength")
                .live(),
        )?
        .into_string();
        write!(
            body,
            r#"<div class="wf-field"><label class="wf-label" for="password">Password</label><input class="wf-input" type="password" name="password" id="password" required minlength="8" autocomplete="new-password"><div id="password-strength" style="display:none">{strength}</div></div>"#
        )
        .unwrap();
        write!(
            body,
            r#"<div class="wf-field"><label class="wf-label" for="password_confirm">Confirm password</label><input class="wf-input" type="password" name="password_confirm" id="password_confirm" required minlength="8" autocomplete="new-password"></div><button type="submit" class="wf-btn primary lg wf-w-full">Create account →</button></form>"#
        )
        .unwrap();
        body.push_str(&oauth_grid(view.oauth_providers, None));
        body.push_str(&terms_footer(None, None));
    }
    body.push_str(password_strength_script());

    let panel = form_panel(panel_title, subtitle, &body)?;
    Ok(auth_main(
        &kicker(app_name, "Create account", Some(&login_href), "Sign in", ""),
        &panel,
    ))
}

fn forgot_password_main(view: &ForgotPasswordView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let mut body = String::new();
    if view.success {
        write!(
            body,
            r#"<div class="wf-mt-5">{}</div>"#,
            alert(
                "ok",
                "If an account with that email exists, a password reset link has been sent.",
            )?
        )
        .unwrap();
    } else {
        if !view.error.is_empty() {
            write!(
                body,
                r#"<div class="wf-mt-4">{}</div>"#,
                alert("err", view.error)?
            )
            .unwrap();
        }
        write!(
            body,
            r#"<form method="post" action="/forgot-password" class="wf-f wf-col wf-gap-5 wf-mt-5">"#
        )
        .unwrap();
        hidden(&mut body, "csrf_token", view.csrf_token);
        write!(
            body,
            r#"<div class="wf-field"><label class="wf-label" for="email">Email</label><input class="wf-input" id="email" name="email" type="email" required autocomplete="email"></div><button type="submit" class="wf-btn primary lg wf-w-full">Send reset link →</button></form>"#
        )
        .unwrap();
    }
    write!(
        body,
        r#"<p class="wf-caption wf-mt-4">Remember your password? <a href="/login" hx-boost="true">Log in</a></p>"#
    )
    .unwrap();
    let panel = form_panel(
        "Reset password",
        "Enter your email — we'll send a reset link.",
        &body,
    )?;
    Ok(auth_main(
        &kicker(app_name, "Forgot password", None, "", ""),
        &panel,
    ))
}

fn reset_password_main(view: &ResetPasswordView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let mut body = String::new();
    if view.invalid_token {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div><p class="wf-caption wf-mt-4"><a href="/forgot-password">Request a new reset link</a></p>"#,
            alert("err", "This password reset link is invalid or has expired.")?
        )
        .unwrap();
    } else if view.success {
        write!(
            body,
            r#"<div class="wf-mt-5">{}</div><p class="wf-caption wf-mt-4"><a href="/login">Log in</a></p>"#,
            alert(
                "ok",
                "Your password has been reset. You can now log in with your new password.",
            )?
        )
        .unwrap();
    } else {
        if !view.error.is_empty() {
            write!(
                body,
                r#"<div class="wf-mt-4">{}</div>"#,
                alert("err", view.error)?
            )
            .unwrap();
        }
        write!(body, r#"<form method="post" action="/auth/reset-password" class="wf-f wf-col wf-gap-5 wf-mt-5">"#).unwrap();
        hidden(&mut body, "csrf_token", view.csrf_token);
        hidden(&mut body, "token", view.token);
        write!(
            body,
            r#"<div class="wf-field"><label class="wf-label" for="new_password">New password</label><input class="wf-input" id="new_password" name="new_password" type="password" required autocomplete="new-password"></div><div class="wf-field"><label class="wf-label" for="confirm_password">Confirm new password</label><input class="wf-input" id="confirm_password" name="confirm_password" type="password" required autocomplete="new-password"></div><button type="submit" class="wf-btn primary lg wf-w-full">Reset password →</button></form>"#
        )
        .unwrap();
    }
    let panel = form_panel(
        "Set new password",
        "Choose a new password for your account.",
        &body,
    )?;
    Ok(auth_main(
        &kicker(app_name, "Reset password", None, "", ""),
        &panel,
    ))
}

fn mfa_setup_main(view: &MfaSetupView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let secret_attrs = [HtmlAttr::new("data-testid", "totp-secret")];
    let secret = render_component(
        &SecretValue::new("Manual entry", "totp-secret", view.secret)
            .revealed()
            .copy_raw_value()
            .with_button_label("Copy secret")
            .with_attrs(&secret_attrs),
    )?
    .into_string();
    let mut body = String::new();
    write!(
        body,
        r#"<div class="wf-framed wf-f wf-col wf-ai-c wf-gap-3 wf-mt-5">"#
    )
    .unwrap();
    if !view.qr_data_uri.is_empty() {
        write!(
            body,
            r#"<img src="{}" alt="QR Code" width="200" height="200" style="image-rendering:pixelated;background:#fff;padding:8px">"#,
            esc_attr(view.qr_data_uri)
        )
        .unwrap();
    }
    write!(
        body,
        r#"<div data-testid="totp-uri" class="wf-t-xs wf-fg-muted" style="display:none">{}</div>{secret}</div>"#,
        esc_text(view.totp_uri)
    )
    .unwrap();
    if !view.error.is_empty() {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert("err", view.error)?
        )
        .unwrap();
    }
    write!(body, r#"<form method="post" action="/settings/mfa/confirm" class="wf-f wf-col wf-gap-5 wf-mt-5">"#).unwrap();
    hidden(&mut body, "csrf_token", view.csrf_token);
    write!(
        body,
        r#"<div class="wf-field"><label class="wf-label" for="code">Enter the 6-digit code</label><input class="wf-input" type="text" id="code" name="code" required autocomplete="one-time-code" inputmode="numeric" maxlength="6" pattern="[0-9]{{6}}"></div><button type="submit" class="wf-btn primary lg wf-w-full">Verify and enable →</button></form><p class="wf-caption wf-mt-4"><a href="/settings">Back to settings</a></p>"#
    )
    .unwrap();
    let panel = form_panel(
        "Enable 2FA",
        "Scan the QR or enter the secret, then verify.",
        &body,
    )?;
    Ok(auth_main(
        &kicker(app_name, "Enable 2FA", None, "", ""),
        &panel,
    ))
}

fn mfa_recovery_main(view: &MfaRecoveryView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let code_refs = view
        .recovery_codes
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let attrs = [HtmlAttr::new("data-testid", "recovery-code-grid")];
    let grid = render_component(
        &CodeGrid::new(&code_refs)
            .with_label("Recovery codes")
            .with_attrs(&attrs),
    )?
    .into_string();
    let mut body = String::new();
    write!(
        body,
        r#"<div class="wf-alert warn wf-mt-5" role="alert"><div class="wf-alert-bar"></div>Save these recovery codes in a secure location. Each code can only be used once. If you lose access to your authenticator app, you can use a recovery code to sign in.</div><div class="wf-mt-5">{grid}</div><div class="wf-f wf-gap-3 wf-mt-4"><button type="button" class="wf-btn" id="copy-codes">Copy all codes</button><button type="button" class="wf-btn" id="download-codes">Download as .txt</button></div><label class="wf-check-row wf-mt-5"><input type="checkbox" class="wf-check" id="codes-saved"> I have saved these recovery codes in a safe place</label><p class="wf-mt-4"><a class="wf-btn primary disabled" href="/settings" id="back-to-settings" aria-disabled="true" tabindex="-1">Back to settings →</a></p>"#
    )
    .unwrap();
    body.push_str(recovery_codes_script());
    let panel = form_panel(
        "Save recovery codes",
        "Save these codes somewhere safe.",
        &body,
    )?;
    Ok(auth_main(
        &kicker(app_name, "Recovery codes", None, "", ""),
        &panel,
    ))
}

fn mfa_challenge_main(view: &MfaChallengeView<'_>) -> Result<String, BrowserError> {
    let app_name = BrandingCtx::from_branding(view.branding).app_name;
    let mut body = String::new();
    if !view.error.is_empty() {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert("err", view.error)?
        )
        .unwrap();
    }
    write!(
        body,
        r#"<form method="post" action="/mfa/challenge" class="wf-f wf-col wf-gap-5 wf-mt-5">"#
    )
    .unwrap();
    hidden(&mut body, "mfa_token", view.mfa_token);
    write!(
        body,
        r#"<input type="checkbox" id="use_recovery" name="use_recovery"><div id="totp-section" class="wf-field"><label class="wf-label" for="code">Authentication code</label><input class="wf-input" type="text" id="code" name="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" pattern="[0-9]{{6}}"></div><div id="recovery-section" class="wf-field"><label class="wf-label" for="recovery_code">Recovery code</label><input class="wf-input" type="text" id="recovery_code" name="recovery_code" autocomplete="off"></div><button type="submit" class="wf-btn primary lg wf-w-full">Verify →</button><p class="wf-caption"><label for="use_recovery">Use recovery code</label></p></form>"#
    )
    .unwrap();
    let panel = form_panel(
        "Verify code",
        "Enter the 6-digit code from your authenticator app.",
        &body,
    )?;
    Ok(auth_main(
        &kicker(app_name, "Two-factor", None, "", ""),
        &panel,
    ))
}

fn consent_main(view: &ConsentView<'_>) -> Result<String, BrowserError> {
    let checklist_items = view
        .scope_items
        .iter()
        .map(|item| ChecklistItem::ok(item.description.as_str()).with_status_label("requested"))
        .collect::<Vec<_>>();
    let attrs = [HtmlAttr::new("data-testid", "consent-scopes")];
    let checklist =
        render_component(&Checklist::new(&checklist_items).with_attrs(&attrs))?.into_string();
    let mut body = String::new();
    if let Some(url) = view.logo_url.filter(|url| url.starts_with("https://")) {
        write!(
            body,
            r#"<img src="{}" alt="{}" class="wf-mb-4" height="48">"#,
            esc_attr(url),
            esc_attr(view.application_name)
        )
        .unwrap();
    }
    write!(body, r#"<div class="wf-mt-5">{checklist}</div>"#).unwrap();
    write!(
        body,
        r#"<form method="post" action="/oauth/authorize" class="wf-f wf-col wf-gap-3 wf-mt-5">"#
    )
    .unwrap();
    hidden(&mut body, "client_id", view.client_id);
    hidden(&mut body, "redirect_uri", view.redirect_uri);
    hidden(&mut body, "response_type", view.response_type);
    hidden(&mut body, "scope", view.scope);
    hidden(&mut body, "state", view.state_param);
    hidden(&mut body, "code_challenge", view.code_challenge);
    hidden(
        &mut body,
        "code_challenge_method",
        view.code_challenge_method,
    );
    if let Some(nonce) = view.nonce {
        hidden(&mut body, "nonce", nonce);
    }
    hidden(&mut body, "csrf_token", view.csrf_token);
    write!(
        body,
        r#"<button type="submit" name="consent" value="approve" class="wf-btn primary lg wf-w-full">Allow →</button><button type="submit" name="consent" value="deny" class="wf-btn wf-w-full">Deny</button></form>"#
    )
    .unwrap();
    if !view.user_email.is_empty() {
        write!(
            body,
            r#"<p class="wf-caption wf-mt-4">Authorizing as {}</p>"#,
            esc_text(view.user_email)
        )
        .unwrap();
    }
    write!(
        body,
        r#"<p class="wf-caption wf-mt-4">Authorizing will redirect you to {}</p>"#,
        esc_text(view.redirect_uri)
    )
    .unwrap();
    let panel = form_panel(
        view.application_name,
        "wants to access the following:",
        &body,
    )?;
    Ok(auth_main(
        &kicker(view.app_name, "Consent", None, "", ""),
        &panel,
    ))
}

fn settings_content(view: &SettingsView<'_>) -> Result<String, BrowserError> {
    let mut content = String::new();
    let mut profile = String::new();
    if !view.profile_error.is_empty() {
        profile.push_str(&alert("err", view.profile_error)?);
    }
    if !view.profile_success.is_empty() {
        profile.push_str(&alert("ok", view.profile_success)?);
    }
    write!(
        profile,
        r#"<form class="wf-form" action="/settings" method="post">"#
    )
    .unwrap();
    hidden(&mut profile, "csrf_token", view.csrf_token);
    input_field(
        &mut profile,
        "Email",
        "email",
        "email",
        view.email,
        &[("id", "email"), ("autocomplete", "email")],
        true,
        false,
        None,
    );
    input_field(
        &mut profile,
        "Username",
        "username",
        "text",
        view.username,
        &[("id", "username"), ("autocomplete", "username")],
        false,
        false,
        None,
    );
    write!(
        profile,
        r#"<div class="wf-form-actions"><button class="wf-btn primary" type="submit">Save profile</button></div></form>"#
    )
    .unwrap();
    content.push_str(&settings_section("Profile", &profile)?);

    let mut password = String::new();
    if !view.password_error.is_empty() {
        password.push_str(&alert("err", view.password_error)?);
    }
    if !view.password_success.is_empty() {
        password.push_str(&alert("ok", view.password_success)?);
    }
    write!(
        password,
        r#"<form class="wf-form" action="/settings/password" method="post">"#
    )
    .unwrap();
    hidden(&mut password, "csrf_token", view.csrf_token);
    password_field(
        &mut password,
        "Current password",
        "current_password",
        "current-password",
        false,
    );
    password_field(
        &mut password,
        "New password",
        "new_password",
        "new-password",
        true,
    );
    password_field(
        &mut password,
        "Confirm new password",
        "new_password_confirm",
        "new-password",
        true,
    );
    write!(
        password,
        r#"<div class="wf-form-actions"><button class="wf-btn primary" type="submit">Change password</button></div></form>"#
    )
    .unwrap();
    content.push_str(&settings_section("Change password", &password)?);

    let mut mfa = String::new();
    if view.mfa_enabled {
        write!(
            mfa,
            r#"<p>MFA is <span class="wf-tag ok"><span class="dot"></span>Enabled</span>. {} of 10 recovery codes remaining.</p><div class="wf-f wf-gap-3"><form method="post" action="/settings/mfa/recovery-codes/regenerate">"#,
            view.mfa_recovery_remaining
        )
        .unwrap();
        hidden(&mut mfa, "csrf_token", view.csrf_token);
        write!(
            mfa,
            r#"<button class="wf-btn" type="submit">Regenerate recovery codes</button></form><form method="post" action="/settings/mfa/disable">"#
        )
        .unwrap();
        hidden(&mut mfa, "csrf_token", view.csrf_token);
        write!(
            mfa,
            r#"<button class="wf-btn danger" type="submit">Disable 2FA</button></form></div>"#
        )
        .unwrap();
    } else {
        write!(
            mfa,
            r#"<p>MFA is <span class="wf-tag">Not configured</span>.</p><a class="wf-btn primary" href="/settings/mfa/setup">Enable 2FA</a>"#
        )
        .unwrap();
    }
    content.push_str(&settings_section("Two-factor authentication", &mfa)?);

    let mut linked = String::new();
    if view.oauth_accounts.is_empty() {
        linked.push_str(r#"<div class="wf-empty dense"><div class="wf-empty-title">No linked accounts</div></div>"#);
    } else {
        linked.push_str(r#"<dl class="wf-dl flush">"#);
        for account in view.oauth_accounts {
            write!(
                linked,
                r#"<div class="wf-dl-row"><dt>{}</dt><dd>{}</dd></div>"#,
                esc_text(&account.provider),
                esc_text(&account.email)
            )
            .unwrap();
        }
        linked.push_str("</dl>");
    }
    let linked_providers = view
        .oauth_accounts
        .iter()
        .map(|account| account.provider.as_str())
        .collect::<HashSet<_>>();
    linked.push_str(r#"<div class="wf-f wf-gap-3 wf-mt-4">"#);
    if !linked_providers.contains("google") {
        linked.push_str(r#"<a class="wf-btn" href="/oauth/google/link">Link Google</a>"#);
    }
    if !linked_providers.contains("github") {
        linked.push_str(r#"<a class="wf-btn" href="/oauth/github/link">Link GitHub</a>"#);
    }
    linked.push_str("</div>");
    content.push_str(&settings_section("Linked accounts", &linked)?);
    Ok(content)
}

fn auth_page(
    title: &str,
    app_title_relation: Option<&str>,
    main_html: &str,
    branding: Option<&BrandingConfig>,
    is_production: bool,
    extra_head: &str,
) -> Result<Html<String>, BrowserError> {
    let ctx = BrandingCtx::from_branding(branding);
    let title = auth_title(title, ctx.app_name, ctx.title_brand, app_title_relation);
    auth_page_with_accent(
        &title,
        "",
        main_html,
        AuthAccent {
            app_name: ctx.app_name,
            accent: &ctx.accent,
            accent_ink: ctx.accent_ink,
            accent_light: &ctx.accent_light,
            accent_ink_light: ctx.accent_ink_light,
            branding,
        },
        is_production,
        extra_head,
    )
}

fn auth_title(
    title: &str,
    app_name: &str,
    title_brand: &str,
    app_relation: Option<&str>,
) -> String {
    if app_name == title_brand {
        return format!("{title} — {title_brand}");
    }
    match app_relation {
        Some("to") => format!("{title} to {app_name} — {title_brand}"),
        Some("on") => format!("{title} on {app_name} — {title_brand}"),
        Some("") => format!("{title} — {app_name} — {title_brand}"),
        Some(relation) => format!("{title} {relation} {app_name} — {title_brand}"),
        None => format!("{title} — {title_brand}"),
    }
}

struct AuthAccent<'a> {
    app_name: &'a str,
    accent: &'a str,
    accent_ink: &'a str,
    accent_light: &'a str,
    accent_ink_light: &'a str,
    branding: Option<&'a BrandingConfig>,
}

fn auth_page_with_accent(
    title: &str,
    _section: &str,
    main_html: &str,
    accent: AuthAccent<'_>,
    is_production: bool,
    extra_head: &str,
) -> Result<Html<String>, BrowserError> {
    let visual = splash_html(accent.branding, accent.app_name);
    let footer = modeline_html(is_production, None)?;
    let mut shell = wavefunk_ui::components::SplitShell::new(trusted_html(main_html))
        .with_visual(trusted_html(&visual))
        .with_footer(trusted_html(&footer));
    if let Some(mode) = accent.branding.and_then(|b| b.forced_mode.as_ref()) {
        shell = shell.with_mode(mode.as_str()).mode_locked();
    }
    let shell_html = render_component(&shell)?.into_string();
    let mut html = String::new();
    write!(
        html,
        r#"<!DOCTYPE html><html lang="en"{}><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>"><script>(function(){{try{{var m=localStorage.getItem('allowthem:mode');if((m==='dark'||m==='light')&&!document.documentElement.hasAttribute('data-mode-locked')){{document.documentElement.dataset.mode=m;}}}}catch(_e){{}}}})();</script>{}<style>:root {{ --accent: {}; --accent-ink: {}; }}html[data-mode="light"] {{ --accent: {}; --accent-ink: {}; }}.wf-split-shell-visual{{position:relative;overflow:hidden}}.wf-split-shell-main>.wf-auth-form{{padding:0}}.wf-split-shell-footer{{display:block}}.wf-split-shell-footer>.wf-modeline,.wf-split-shell-footer>.wf-minibuffer{{width:100%}}html[data-mode-locked] [data-mode-toggle]{{display:none}}</style>{}</head><body>{}<script src="/static/wavefunk/js/htmx.min.js" defer></script><script src="/static/wavefunk/js/wavefunk.js" defer></script><script src="/__allowthem/static/js/mode-toggle.js" defer></script><script src="/__allowthem/static/js/shader-ascii.js" defer></script></body></html>"#,
        html_attrs(accent.branding),
        esc_text(&title),
        wavefunk_ui::html::stylesheet_link("/static/wavefunk"),
        esc_text(accent.accent),
        esc_text(accent.accent_ink),
        esc_text(accent.accent_light),
        esc_text(accent.accent_ink_light),
        extra_head,
        shell_html
    )
    .unwrap();
    Ok(Html(html))
}

fn auth_fragment(
    main_html: &str,
    title: &str,
    status_hint: &str,
) -> Result<Html<String>, BrowserError> {
    Ok(Html(format!(
        r#"{main_html}<title hx-swap-oob="true">{}</title><span id="wf-screen-label" hx-swap-oob="true" class="wf-ml-seg">{}</span>"#,
        esc_text(title),
        esc_text(status_hint)
    )))
}

fn auth_main(top: &str, panel: &str) -> String {
    format!(r#"<main class="wf-auth-form"><div class="wf-auth-top">{top}</div>{panel}</main>"#)
}

fn form_panel(title: &str, subtitle: &str, body: &str) -> Result<String, BrowserError> {
    Ok(
        render_component(&FormPanel::new(title, trusted_html(body)).with_subtitle(subtitle))?
            .into_string(),
    )
}

fn settings_section(title: &str, body: &str) -> Result<String, BrowserError> {
    Ok(
        render_component(&wavefunk_ui::components::SettingsSection::new(
            title,
            trusted_html(body),
        ))?
        .into_string(),
    )
}

fn alert(kind: &str, message: &str) -> Result<String, BrowserError> {
    let kind = match kind {
        "ok" => FeedbackKind::Ok,
        "warn" => FeedbackKind::Warn,
        "err" | "error" => FeedbackKind::Error,
        _ => FeedbackKind::Info,
    };
    Ok(render_component(&Alert::new(kind, message))?.into_string())
}

fn kicker(
    app_name: &str,
    section: &str,
    swap_href: Option<&str>,
    swap_label: &str,
    swap_prefix: &str,
) -> String {
    let mut out = format!(
        r#"<span>{} · {}</span>"#,
        esc_text(app_name),
        esc_text(section)
    );
    if let Some(href) = swap_href {
        write!(
            out,
            r#"<a href="{}" hx-get="{}" hx-target=".wf-auth-form" hx-swap="outerHTML" hx-push-url="true" class="wf-accent wf-text-right" style="text-decoration: none">{}{} →</a>"#,
            esc_attr(href),
            esc_attr(href),
            if swap_prefix.is_empty() {
                String::new()
            } else {
                format!("{} ", esc_text(swap_prefix))
            },
            esc_text(swap_label)
        )
        .unwrap();
    }
    out
}

fn tabs(active: &str, signup_href: &str) -> String {
    let signin = if active == "signin" { "is-active" } else { "" };
    let signup = if active == "signup" { "is-active" } else { "" };
    let signup_hx = if signup_href == "/register" {
        r#"hx-get="/register" hx-target=".wf-auth-form" hx-swap="outerHTML" hx-push-url="true""#
            .to_owned()
    } else {
        String::new()
    };
    format!(
        r#"<div class="wf-tabs" role="tablist"><a role="tab" class="{signin}" href="/login" hx-get="/login" hx-target=".wf-auth-form" hx-swap="outerHTML" hx-push-url="true">Sign in</a><a role="tab" class="{signup}" href="{}" {signup_hx}>Sign up</a></div>"#,
        esc_attr(signup_href)
    )
}

fn oauth_grid(providers: &[String], next: Option<&str>) -> String {
    if providers.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        r#"<div class="wf-divider-txt">or</div><div class="wf-grid cols-2 wf-gap-2">"#,
    );
    let next_query = next
        .filter(|n| !n.is_empty())
        .map(|n| format!("?next={}", url_encode(n)))
        .unwrap_or_default();
    for provider in providers {
        write!(
            out,
            r#"<a class="wf-btn sm" href="/oauth/{}/authorize{}">{}</a>"#,
            esc_attr(provider),
            esc_attr(&next_query),
            esc_text(provider)
        )
        .unwrap();
    }
    out.push_str("</div>");
    out
}

fn terms_footer(terms_url: Option<&str>, privacy_url: Option<&str>) -> String {
    match (terms_url, privacy_url) {
        (Some(terms), Some(privacy)) => format!(
            r#"<p class="wf-caption wf-mt-6">By continuing, you agree to our <a href="{}">Terms</a> and <a href="{}">Privacy</a>.</p>"#,
            esc_attr(terms),
            esc_attr(privacy)
        ),
        _ => String::new(),
    }
}

fn field_text(out: &mut String, label: &str, prefix: &str, value: &str, suffix: &str) {
    write!(
        out,
        r#"<div class="wf-field"><label class="wf-label" for="identifier">{}</label>"#,
        esc_text(label)
    )
    .unwrap();
    out.push_str(prefix);
    write!(out, "{}", esc_attr(value)).unwrap();
    out.push_str(suffix);
    out.push_str("</div>");
}

#[allow(clippy::too_many_arguments)]
fn input_field(
    out: &mut String,
    label: &str,
    name: &str,
    input_type: &str,
    value: &str,
    attrs: &[(&str, &str)],
    required: bool,
    readonly: bool,
    placeholder: Option<&str>,
) {
    write!(
        out,
        r#"<div class="wf-field"><label class="wf-label" for="{}">{}</label><input class="wf-input" type="{}" name="{}" value="{}""#,
        esc_attr(attrs.iter().find(|(k, _)| *k == "id").map(|(_, v)| *v).unwrap_or(name)),
        esc_text(label),
        esc_attr(input_type),
        esc_attr(name),
        esc_attr(value)
    )
    .unwrap();
    for (k, v) in attrs {
        write!(out, r#" {}="{}""#, esc_attr(k), esc_attr(v)).unwrap();
    }
    if required {
        out.push_str(" required");
    }
    if readonly {
        out.push_str(" readonly");
    }
    if let Some(placeholder) = placeholder {
        write!(out, r#" placeholder="{}""#, esc_attr(placeholder)).unwrap();
    }
    out.push_str("></div>");
}

fn password_field(out: &mut String, label: &str, name: &str, autocomplete: &str, minlength: bool) {
    write!(
        out,
        r#"<div class="wf-field"><label class="wf-label" for="{name}">{}</label><input class="wf-input" type="password" name="{name}" id="{name}" required{} autocomplete="{}"></div>"#,
        esc_text(label),
        if minlength { r#" minlength="8""# } else { "" },
        esc_attr(autocomplete)
    )
    .unwrap();
}

fn custom_field(out: &mut String, field: &CustomFieldDescriptor, values: &HashMap<&str, &str>) {
    let field_name = format!("custom_data[{}]", field.name);
    let field_id = format!("custom_data_{}", field.name);
    let value: Cow<'_, str> = values
        .get(field.name.as_str())
        .map(|value| Cow::Borrowed(*value))
        .or_else(|| {
            field
                .default_value
                .as_ref()
                .and_then(default_value_attr)
                .map(Cow::Owned)
        })
        .unwrap_or(Cow::Borrowed(""));
    let value = value.as_ref();
    let hint = field.help_text.as_deref().unwrap_or("");
    match field.field_type {
        FieldType::Checkbox => {
            write!(
                out,
                r#"<label class="wf-check-row"><input class="wf-check" type="checkbox" name="{}" value="true" id="{}"{}> {}</label>"#,
                esc_attr(&field_name),
                esc_attr(&field_id),
                if value == "true" { " checked" } else { "" },
                esc_text(if hint.is_empty() {
                    field.label.as_str()
                } else {
                    hint
                })
            )
            .unwrap();
        }
        FieldType::Textarea => {
            write!(
                out,
                r#"<div class="wf-field"><label class="wf-label" for="{}">{}</label><textarea class="wf-textarea" name="{}" id="{}"{}{}{}>{}</textarea>{}</div>"#,
                esc_attr(&field_id),
                esc_text(&field.label),
                esc_attr(&field_name),
                esc_attr(&field_id),
                if field.required { " required" } else { "" },
                opt_num_attr("minlength", field.min_length),
                opt_num_attr("maxlength", field.max_length),
                esc_text(value),
                hint_html(hint)
            )
            .unwrap();
        }
        FieldType::Select => {
            write!(
                out,
                r#"<div class="wf-field"><label class="wf-label" for="{}">{}</label><select class="wf-select" name="{}" id="{}"{}><option value="">Select…</option>"#,
                esc_attr(&field_id),
                esc_text(&field.label),
                esc_attr(&field_name),
                esc_attr(&field_id),
                if field.required { " required" } else { "" },
            )
            .unwrap();
            if let Some(values) = &field.enum_values {
                for option in values {
                    let option = default_value_attr(option).unwrap_or_default();
                    write!(
                        out,
                        r#"<option value="{}"{}>{}</option>"#,
                        esc_attr(&option),
                        if option == value { " selected" } else { "" },
                        esc_text(&option)
                    )
                    .unwrap();
                }
            }
            write!(out, r#"</select>{}</div>"#, hint_html(hint)).unwrap();
        }
        FieldType::Number => {
            let min = field.minimum.map(number_attr);
            let max = field.maximum.map(number_attr);
            let mut attrs = vec![("id", field_id.as_str())];
            if let Some(min) = min.as_deref() {
                attrs.push(("min", min));
            }
            if let Some(max) = max.as_deref() {
                attrs.push(("max", max));
            }
            input_field(
                out,
                &field.label,
                &field_name,
                "number",
                value,
                &attrs,
                field.required,
                false,
                if field.required {
                    None
                } else {
                    Some("Optional")
                },
            );
        }
        FieldType::Email | FieldType::Url | FieldType::Text => {
            let input_type = match field.field_type {
                FieldType::Email => "email",
                FieldType::Url => "url",
                _ => "text",
            };
            let min_length = field.min_length.map(|value| value.to_string());
            let max_length = field.max_length.map(|value| value.to_string());
            let mut attrs = vec![("id", field_id.as_str())];
            if let Some(min_length) = min_length.as_deref() {
                attrs.push(("minlength", min_length));
            }
            if let Some(max_length) = max_length.as_deref() {
                attrs.push(("maxlength", max_length));
            }
            input_field(
                out,
                &field.label,
                &field_name,
                input_type,
                value,
                &attrs,
                field.required,
                false,
                if field.required {
                    None
                } else {
                    Some("Optional")
                },
            );
        }
    }
}

fn default_value_attr(value: &serde_json::Value) -> Option<String> {
    if let Some(value) = value.as_str() {
        Some(value.to_owned())
    } else if let Some(value) = value.as_bool() {
        Some(if value { "true" } else { "false" }.to_owned())
    } else {
        value.as_f64().map(number_attr)
    }
}

fn number_attr(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

fn opt_num_attr(name: &str, value: Option<u64>) -> String {
    value
        .map(|v| format!(r#" {name}="{v}""#))
        .unwrap_or_default()
}

fn hint_html(hint: &str) -> String {
    if hint.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="wf-field-hint">{}</span>"#, esc_text(hint))
    }
}

fn hidden(out: &mut String, name: &str, value: &str) {
    write!(
        out,
        r#"<input type="hidden" name="{}" value="{}">"#,
        esc_attr(name),
        esc_attr(value)
    )
    .unwrap();
}

fn modeline_html(is_production: bool, session: Option<&str>) -> Result<String, BrowserError> {
    let env = if is_production { "PROD" } else { "DEV" };
    let session = session.unwrap_or("ANON");
    let screen_label =
        ModelineSegment::text("").with_html(trusted_html(r#"<span id="wf-screen-label"></span>"#));
    let left = [
        ModelineSegment::chevron("AT"),
        ModelineSegment::text(env),
        screen_label,
    ];
    let logout_attrs = [
        HtmlAttr::new("title", "Sign out"),
        HtmlAttr::new("aria-label", "Sign out"),
    ];
    let mode_attrs = [
        HtmlAttr::new("data-mode-toggle", ""),
        HtmlAttr::new("title", "Toggle color mode"),
        HtmlAttr::new("aria-label", "Toggle color mode"),
    ];
    let mut right = vec![ModelineSegment::text(session)];
    if session != "ANON" {
        right.push(ModelineSegment::link("⏻", "/logout").with_attrs(&logout_attrs));
    }
    right.push(
        ModelineSegment::button("")
            .with_kbd("m")
            .with_attrs(&mode_attrs),
    );
    let modeline_attrs = [
        HtmlAttr::new("role", "status"),
        HtmlAttr::new("aria-label", "Modeline"),
    ];
    let modeline = render_component(
        &Modeline::new(&left)
            .with_right(&right)
            .with_attrs(&modeline_attrs),
    )?
    .into_string();
    let minibuffer = render_component(&wavefunk_ui::components::Minibuffer::new())?.into_string();
    Ok(format!("{modeline}{minibuffer}{READY_SCRIPT}"))
}

fn splash_html(branding: Option<&BrandingConfig>, application_name: &str) -> String {
    if let Some(url) = branding.and_then(|b| b.splash_url.as_deref()) {
        return format!(
            r#"<iframe src="{}" sandbox="allow-scripts" referrerpolicy="no-referrer" allow="" loading="lazy" style="position: absolute; inset: 0; width: 100%; height: 100%; border: 0;" title="{} splash"></iframe>"#,
            esc_attr(url),
            esc_attr(application_name)
        );
    }
    if let Some(image) = branding.and_then(|b| b.splash_image_url.as_deref()) {
        return format!(
            r#"<canvas data-shader-ascii data-cell-scale="{}" data-shape-source="image" data-shape-image="{}" aria-hidden="true"></canvas><pre class="wf-ascii" style="display:none">{}</pre>"#,
            branding.and_then(|b| b.shader_cell_scale).unwrap_or(22),
            esc_attr(image),
            esc_text(application_name)
        );
    }
    if let Some(primitive) = branding.and_then(|b| b.splash_primitive.as_ref()) {
        return format!(
            r#"<canvas data-shader-ascii data-cell-scale="{}" data-shape-source="primitive" data-shape-primitive="{}" aria-hidden="true"></canvas><pre class="wf-ascii" style="display:none">{}</pre>"#,
            branding.and_then(|b| b.shader_cell_scale).unwrap_or(22),
            primitive.as_str(),
            esc_text(application_name)
        );
    }
    let text = branding
        .and_then(|b| b.splash_text.as_deref())
        .unwrap_or(application_name);
    format!(
        r#"<canvas data-shader-ascii data-cell-scale="{}" data-shape-source="text" data-shape-text="{}" aria-hidden="true"></canvas><pre class="wf-ascii" style="display:none">{}</pre>"#,
        branding.and_then(|b| b.shader_cell_scale).unwrap_or(22),
        esc_attr(text),
        esc_text(text)
    )
}

fn html_attrs(branding: Option<&BrandingConfig>) -> String {
    branding
        .and_then(|b| b.forced_mode.as_ref())
        .map(|mode| format!(r#" data-mode="{}" data-mode-locked"#, mode.as_str()))
        .unwrap_or_default()
}

fn sidebar_nav(shell: &ShellContext) -> Result<String, BrowserError> {
    let mut admin = Vec::new();
    let mut account = Vec::new();
    for item in &shell.nav_items {
        let mut sidenav = SidenavItem::link(item.label.as_str(), item.href.as_str());
        if item.active {
            sidenav = sidenav.active();
        }
        match item.group {
            crate::nav::NavGroup::Admin => admin.push(sidenav),
            crate::nav::NavGroup::Account => account.push(sidenav),
        }
    }
    let mut sections = Vec::new();
    if !admin.is_empty() {
        sections.push(SidenavSection::new("Admin", &admin));
    }
    if !account.is_empty() {
        sections.push(SidenavSection::new("Account", &account));
    }
    Ok(render_component(&Sidenav::new(&sections).embedded())?.into_string())
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn mfa_challenge_head() -> &'static str {
    r#"<style>#recovery-section{display:none}#use_recovery:checked~#recovery-section{display:block}#use_recovery:checked~#totp-section{display:none}#use_recovery{position:absolute;left:-9999px}</style>"#
}

fn password_strength_script() -> &'static str {
    r#"<script>
(function(){
  var pw=document.getElementById("password");
  var box=document.getElementById("password-strength");
  if(!pw||!box)return;
  var meter=box.querySelector(".wf-strength-meter");
  var text=box.querySelector(".wf-strength-text");
  if(!meter||!text)return;
  pw.addEventListener("input",function(){
    var v=pw.value;
    if(!v.length){box.style.display="none";return}
    box.style.display="block";
    var score=0;
    if(v.length>=8)score++;
    if(v.length>=12)score++;
    if(/[a-z]/.test(v)&&/[A-Z]/.test(v))score++;
    if(/[0-9]/.test(v))score++;
    if(/[^a-zA-Z0-9]/.test(v))score++;
    var s,t;
    if(score<2){s="weak";t="Weak"}
    else if(score<4){s="medium";t="Medium"}
    else{s="strong";t="Strong"}
    meter.style.setProperty("--strength", Math.min(score,5)*20+"%");
    meter.setAttribute("aria-valuenow", String(score));
    meter.className="wf-strength-meter is-"+(s==="weak"?"err":s==="medium"?"warn":"ok");
    text.textContent=t+(v.length<8?" — min 8 characters":"");
  });
})();
</script>"#
}

fn recovery_codes_script() -> &'static str {
    r#"<script>
(function(){
  function getCodes(){
    var els=document.querySelectorAll('[data-testid="recovery-code-grid"] .wf-code-grid-item');
    var codes=[];
    for(var i=0;i<els.length;i++)codes.push(els[i].textContent.trim());
    return codes;
  }
  var copyBtn=document.getElementById("copy-codes");
  if(copyBtn)copyBtn.addEventListener("click",function(){
    var text=getCodes().join("\n");
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(function(){
        copyBtn.textContent="Copied!";
        setTimeout(function(){copyBtn.textContent="Copy all codes"},2000);
      });
    }else{
      var ta=document.createElement("textarea");
      ta.value=text;ta.style.position="fixed";ta.style.left="-9999px";
      document.body.appendChild(ta);ta.select();
      document.execCommand("copy");document.body.removeChild(ta);
      copyBtn.textContent="Copied!";
      setTimeout(function(){copyBtn.textContent="Copy all codes"},2000);
    }
  });
  var dlBtn=document.getElementById("download-codes");
  if(dlBtn)dlBtn.addEventListener("click",function(){
    var text="allowthem recovery codes\n"+new Date().toISOString()+"\n\n"+getCodes().join("\n")+"\n";
    var blob=new Blob([text],{type:"text/plain"});
    var a=document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download="allowthem-recovery-codes.txt";
    a.click();URL.revokeObjectURL(a.href);
  });
  var chk=document.getElementById("codes-saved");
  var back=document.getElementById("back-to-settings");
  if(chk&&back){
    chk.addEventListener("change",function(){
      if(chk.checked){
        back.classList.remove("disabled");
        back.removeAttribute("aria-disabled");
        back.removeAttribute("tabindex");
      }else{
        back.classList.add("disabled");
        back.setAttribute("aria-disabled","true");
        back.setAttribute("tabindex","-1");
      }
    });
    back.addEventListener("click",function(e){
      if(!chk.checked)e.preventDefault();
    });
  }
})();
</script>"#
}
