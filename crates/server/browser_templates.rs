use std::sync::Arc;

use axum::response::Html;
use minijinja::Environment;

use crate::browser_error::BrowserError;

const BASE_HTML: &str = include_str!("templates/base.html");
const LOGIN_HTML: &str = include_str!("templates/login.html");
const REGISTER_HTML: &str = include_str!("templates/register.html");
const SETTINGS_HTML: &str = include_str!("templates/settings.html");
const CONSENT_HTML: &str = include_str!("templates/consent.html");
const FORGOT_PASSWORD_HTML: &str = include_str!("templates/forgot_password.html");
const RESET_PASSWORD_HTML: &str = include_str!("templates/reset_password.html");
const MFA_SETUP_HTML: &str = include_str!("templates/mfa_setup.html");
const MFA_RECOVERY_HTML: &str = include_str!("templates/mfa_recovery.html");
const MFA_CHALLENGE_HTML: &str = include_str!("templates/mfa_challenge.html");
const MODELINE_PARTIAL: &str = include_str!("templates/_partials/_modeline.html");
const FLASH_PARTIAL: &str = include_str!("templates/_partials/_flash.html");
const SPLASH_PARTIAL: &str = include_str!("templates/_partials/_splash.html");
const AUTH_SHELL_PARTIAL: &str = include_str!("templates/_partials/_auth_shell.html");
const APP_SHELL_PARTIAL: &str = include_str!("templates/_partials/_app_shell.html");
const SIDEBAR_NAV_PARTIAL: &str = include_str!("templates/_partials/_sidebar_nav.html");
const AUTH_MACROS_PARTIAL: &str = include_str!("templates/_partials/_auth_macros.html");
const AUTH_OOB_HEAD_PARTIAL: &str = include_str!("templates/_partials/_auth_oob_head.html");
const AUTH_MAIN_LOGIN_PARTIAL: &str = include_str!("templates/_partials/_auth_main_login.html");
const AUTH_MAIN_REGISTER_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_register.html");
const AUTH_MAIN_FORGOT_PW_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_forgot_password.html");
const AUTH_MAIN_RESET_PW_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_reset_password.html");
const AUTH_MAIN_MFA_CHALLENGE_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_challenge.html");
const AUTH_MAIN_MFA_SETUP_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_setup.html");
const AUTH_MAIN_MFA_RECOVERY_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_recovery.html");
const AUTH_MAIN_CONSENT_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_consent.html");

/// Register the default browser templates into an existing environment.
///
/// Useful for consumers (like the standalone binary) that need to extend
/// the default template set with additional templates of their own.
///
/// # Integrator-overridable blocks (auth shell)
///
/// `_partials/_auth_shell.html` exposes two named blocks that integrators
/// can override from a child template without forking the shell:
///
/// - `splash_content` — replaces the splash aside's body (left column).
///   Default includes `_partials/_splash.html`, which renders a shader
///   canvas (or sandboxed iframe when `branding.splash_url` is set).
/// - `auth_main` — replaces the entire `<main class="wf-auth-form">`
///   subtree. During the z3c migration (C3–C10) the default body of this
///   block contains a transitional bridge that re-exposes
///   `{% block auth_top %}` and `{% block form %}` sub-blocks so
///   un-migrated pages keep working. Once all pages have migrated to their
///   `_auth_main_<page>.html` partials, the bridge and its sub-blocks will
///   be removed and `auth_main` becomes the sole integrator entry point.
///
/// Both blocks are safe to override in integrator templates that
/// `{% extends "_partials/_auth_shell.html" %}` — the surrounding
/// `<aside class="wf-auth-splash">` wrapper and the auth_main slot are
/// owned by the shell and remain stable.
///
/// # Integrator-overridable blocks (app shell)
///
/// `_partials/_app_shell.html` exposes six named blocks on the
/// post-auth surface for pageheader / panel / layout customisation.
/// Each default is empty (or a safe passthrough); built-in admin and
/// settings pages override them as appropriate:
///
/// - `pagetitle` — page title inside `<h1 class="wf-pagetitle">`.
///   Default: empty.
/// - `crumbs` — breadcrumb line inside `<div class="wf-crumbs">`.
///   Default: empty.
/// - `page_meta` — right-aligned status cluster inside
///   `<div class="wf-page-meta">` within `.wf-pageheader`. Default: empty.
/// - `topbar` — row above the pageheader, typically a search or
///   command-K bar inside `.wf-topbar`. Default: empty.
/// - `main_class` — modifier class on `<div class="wf-main">`.
///   Default: `has-header`. List pages override to `has-tablewrap` so
///   the grid makes room for a `.wf-tablewrap` region below the header.
/// - `page_content` — replaces the `.wf-scroll > {% block content %}`
///   body wholesale. Default: passthrough that renders `{% block content %}`
///   unchanged, so templates predating the pageheader chrome keep working.
///
/// All six blocks are safe to override from any child template that
/// `{% extends "_partials/_app_shell.html" %}`. The surrounding
/// `.wf-shell` / `.wf-sidebar` / `.wf-main` structure is owned by the
/// shell and remains stable.
pub fn add_default_browser_templates(env: &mut Environment<'static>) {
    env.add_template_owned("base.html", BASE_HTML)
        .expect("base.html");
    env.add_template_owned("login.html", LOGIN_HTML)
        .expect("login.html");
    env.add_template_owned("register.html", REGISTER_HTML)
        .expect("register.html");
    env.add_template_owned("settings.html", SETTINGS_HTML)
        .expect("settings.html");
    env.add_template_owned("consent.html", CONSENT_HTML)
        .expect("consent.html");
    env.add_template_owned("forgot_password.html", FORGOT_PASSWORD_HTML)
        .expect("forgot_password.html");
    env.add_template_owned("reset_password.html", RESET_PASSWORD_HTML)
        .expect("reset_password.html");
    env.add_template_owned("mfa_setup.html", MFA_SETUP_HTML)
        .expect("mfa_setup.html");
    env.add_template_owned("mfa_recovery.html", MFA_RECOVERY_HTML)
        .expect("mfa_recovery.html");
    env.add_template_owned("mfa_challenge.html", MFA_CHALLENGE_HTML)
        .expect("mfa_challenge.html");
    env.add_template_owned("_partials/_modeline.html", MODELINE_PARTIAL)
        .expect("_partials/_modeline.html");
    env.add_template_owned("_partials/_flash.html", FLASH_PARTIAL)
        .expect("_partials/_flash.html");
    env.add_template_owned("_partials/_splash.html", SPLASH_PARTIAL)
        .expect("_partials/_splash.html");
    env.add_template_owned("_partials/_auth_shell.html", AUTH_SHELL_PARTIAL)
        .expect("_partials/_auth_shell.html");
    env.add_template_owned("_partials/_app_shell.html", APP_SHELL_PARTIAL)
        .expect("_partials/_app_shell.html");
    env.add_template_owned("_partials/_sidebar_nav.html", SIDEBAR_NAV_PARTIAL)
        .expect("_partials/_sidebar_nav.html");
    env.add_template_owned("_partials/_auth_macros.html", AUTH_MACROS_PARTIAL)
        .expect("_partials/_auth_macros.html");
    env.add_template_owned("_partials/_auth_oob_head.html", AUTH_OOB_HEAD_PARTIAL)
        .expect("_partials/_auth_oob_head.html");
    env.add_template_owned("_partials/_auth_main_login.html", AUTH_MAIN_LOGIN_PARTIAL)
        .expect("_partials/_auth_main_login.html");
    env.add_template_owned(
        "_partials/_auth_main_register.html",
        AUTH_MAIN_REGISTER_PARTIAL,
    )
    .expect("_partials/_auth_main_register.html");
    env.add_template_owned(
        "_partials/_auth_main_forgot_password.html",
        AUTH_MAIN_FORGOT_PW_PARTIAL,
    )
    .expect("_partials/_auth_main_forgot_password.html");
    env.add_template_owned(
        "_partials/_auth_main_reset_password.html",
        AUTH_MAIN_RESET_PW_PARTIAL,
    )
    .expect("_partials/_auth_main_reset_password.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_challenge.html",
        AUTH_MAIN_MFA_CHALLENGE_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_challenge.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_setup.html",
        AUTH_MAIN_MFA_SETUP_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_setup.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_recovery.html",
        AUTH_MAIN_MFA_RECOVERY_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_recovery.html");
    env.add_template_owned(
        "_partials/_auth_main_consent.html",
        AUTH_MAIN_CONSENT_PARTIAL,
    )
    .expect("_partials/_auth_main_consent.html");
}

pub fn build_default_browser_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    Arc::new(env)
}

pub fn render(
    env: &Environment<'_>,
    template_name: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = env.get_template(template_name)?;
    let rendered = tmpl.render(ctx)?;
    Ok(Html(rendered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_env_loads_all_browser_templates() {
        let env = build_default_browser_env();
        for name in [
            "base.html",
            "login.html",
            "register.html",
            "settings.html",
            "consent.html",
            "forgot_password.html",
            "reset_password.html",
            "mfa_setup.html",
            "mfa_recovery.html",
            "mfa_challenge.html",
            "_partials/_modeline.html",
            "_partials/_flash.html",
            "_partials/_splash.html",
            "_partials/_auth_shell.html",
            "_partials/_app_shell.html",
            "_partials/_sidebar_nav.html",
            "_partials/_auth_macros.html",
            "_partials/_auth_oob_head.html",
            "_partials/_auth_main_login.html",
            "_partials/_auth_main_register.html",
            "_partials/_auth_main_forgot_password.html",
            "_partials/_auth_main_reset_password.html",
            "_partials/_auth_main_mfa_challenge.html",
            "_partials/_auth_main_mfa_setup.html",
            "_partials/_auth_main_mfa_recovery.html",
            "_partials/_auth_main_consent.html",
        ] {
            assert!(
                env.get_template(name).is_ok(),
                "template {name} should be loadable"
            );
        }
    }

    #[test]
    fn render_produces_html() {
        let env = build_default_browser_env();
        let result = render(
            &env,
            "login.html",
            minijinja::context! {
                csrf_token => "test",
                is_production => false,
            },
        );
        assert!(result.is_ok());
    }
}
