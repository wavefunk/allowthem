use std::sync::Arc;

use axum::response::Html;
use minijinja::value::{Kwargs, Value};
use minijinja::{Environment, Error, ErrorKind};
use wavefunk_ui::Template;
use wavefunk_ui::components::{
    Alert, FeedbackKind, FormPanel, HtmlAttr, Minibuffer, Modeline, ModelineSegment, NavItem,
    NavSection, PageHeader, SplitShell,
};
use wavefunk_ui::layouts::AppShell;

use crate::browser_error::BrowserError;
use crate::ui::{render_component, trusted_html};

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
const AUTH_MAIN_CONSENT_PARTIAL: &str = include_str!("templates/_partials/_auth_main_consent.html");
const ERROR_HTML: &str = include_str!("templates/error.html");

fn component_error(component: &str, err: impl std::fmt::Display) -> Error {
    Error::new(
        ErrorKind::InvalidOperation,
        format!("failed to render {component}: {err}"),
    )
}

fn safe_component_value<T>(component: &T, name: &str) -> Result<Value, Error>
where
    T: Template + ?Sized,
{
    render_component(component)
        .map(|rendered| Value::from_safe_string(rendered.into_string()))
        .map_err(|err| component_error(name, err))
}

fn wf_form_panel(title: String, body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let subtitle: Option<String> = kwargs.get("subtitle")?;
    let meta_html: Option<String> = kwargs.get("meta_html")?;
    let actions_html: Option<String> = kwargs.get("actions_html")?;
    kwargs.assert_all_used()?;

    let mut panel = FormPanel::new(&title, trusted_html(&body_html));
    if let Some(subtitle) = subtitle.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_subtitle(subtitle);
    }
    if let Some(meta_html) = meta_html.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_meta(trusted_html(meta_html));
    }
    if let Some(actions_html) = actions_html.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_actions(trusted_html(actions_html));
    }

    safe_component_value(&panel, "FormPanel")
}

fn wf_split_shell(content_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let visual_html: Option<String> = kwargs.get("visual_html")?;
    let top_html: Option<String> = kwargs.get("top_html")?;
    let footer_html: Option<String> = kwargs.get("footer_html")?;
    let mode: Option<String> = kwargs.get("mode")?;
    let mode_locked = kwargs.get::<Option<bool>>("mode_locked")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut shell = SplitShell::new(trusted_html(&content_html));
    if let Some(visual_html) = visual_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_visual(trusted_html(visual_html));
    }
    if let Some(top_html) = top_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_top(trusted_html(top_html));
    }
    if let Some(footer_html) = footer_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_footer(trusted_html(footer_html));
    }
    if let Some(mode) = mode.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_mode(mode);
    }
    if mode_locked {
        shell = shell.mode_locked();
    }

    safe_component_value(&shell, "SplitShell")
}

fn wf_app_shell(
    title: String,
    app_name: String,
    content_html: String,
    kwargs: Kwargs,
) -> Result<Value, Error> {
    let nav_html: Option<String> = kwargs.get("nav_html")?;
    let nav_aria_label: Option<String> = kwargs.get("nav_aria_label")?;
    let breadcrumbs_html: Option<String> = kwargs.get("breadcrumbs_html")?;
    let topbar_html: Option<String> = kwargs.get("topbar_html")?;
    let page_header_html: Option<String> = kwargs.get("page_header_html")?;
    let footer_html: Option<String> = kwargs.get("footer_html")?;
    let main_class: Option<String> = kwargs.get("main_class")?;
    let brand_href: Option<String> = kwargs.get("brand_href")?;
    let head_html: Option<String> = kwargs.get("head_html")?;
    let scripts_html: Option<String> = kwargs.get("scripts_html")?;
    let mode: Option<String> = kwargs.get("mode")?;
    let mode_locked = kwargs.get::<Option<bool>>("mode_locked")?.unwrap_or(false);
    let body_hx_boost = kwargs.get::<Option<bool>>("body_hx_boost")?.unwrap_or(true);
    kwargs.assert_all_used()?;

    let title = title.trim().to_owned();
    let app_name = app_name.trim().to_owned();
    let mut shell = AppShell::new(&title, &app_name, &content_html);
    if let Some(nav_html) = nav_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_nav(nav_html);
    }
    if let Some(nav_aria_label) = nav_aria_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_nav_aria_label(nav_aria_label);
    }
    if let Some(breadcrumbs_html) = breadcrumbs_html
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_breadcrumbs(trusted_html(breadcrumbs_html));
    }
    if let Some(topbar_html) = topbar_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_topbar(trusted_html(topbar_html));
    }
    if let Some(page_header_html) = page_header_html
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_page_header(trusted_html(page_header_html));
    }
    if let Some(footer_html) = footer_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_footer(trusted_html(footer_html));
    }
    if let Some(main_class) = main_class
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_main_class(main_class);
    }
    if let Some(brand_href) = brand_href
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_brand_href(brand_href);
    }
    if let Some(head_html) = head_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_head(trusted_html(head_html));
    }
    if let Some(scripts_html) = scripts_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_scripts(trusted_html(scripts_html));
    }
    if let Some(mode) = mode.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_mode(mode);
    }
    if mode_locked {
        shell = shell.mode_locked();
    }
    if !body_hx_boost {
        shell = shell.without_body_hx_boost();
    }

    safe_component_value(&shell, "AppShell")
}

fn wf_page_header(title: String, kwargs: Kwargs) -> Result<Value, Error> {
    let subtitle: Option<String> = kwargs.get("subtitle")?;
    let meta_html: Option<String> = kwargs.get("meta_html")?;
    let primary_html: Option<String> = kwargs.get("primary_html")?;
    let secondary_html: Option<String> = kwargs.get("secondary_html")?;
    kwargs.assert_all_used()?;

    let title = title.trim().to_owned();
    let mut header = PageHeader::new(&title);
    if let Some(subtitle) = subtitle.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_subtitle(subtitle);
    }
    if let Some(meta_html) = meta_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_meta(trusted_html(meta_html));
    }
    if let Some(primary_html) = primary_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_primary(trusted_html(primary_html));
    }
    if let Some(secondary_html) = secondary_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_secondary(trusted_html(secondary_html));
    }

    safe_component_value(&header, "PageHeader")
}

fn feedback_kind(kind: &str) -> FeedbackKind {
    match kind {
        "ok" | "success" => FeedbackKind::Ok,
        "warn" | "warning" => FeedbackKind::Warn,
        "err" | "error" | "danger" => FeedbackKind::Error,
        _ => FeedbackKind::Info,
    }
}

fn wf_alert(kind: String, message: String, kwargs: Kwargs) -> Result<Value, Error> {
    let title: Option<String> = kwargs.get("title")?;
    kwargs.assert_all_used()?;

    let mut alert = Alert::new(feedback_kind(kind.trim()), &message);
    if let Some(title) = title.as_deref().filter(|value| !value.is_empty()) {
        alert = alert.with_title(title);
    }
    safe_component_value(&alert, "Alert")
}

fn wf_modeline(status_env: String, status_session: Option<String>) -> Result<Value, Error> {
    let screen_label =
        ModelineSegment::text("").with_html(trusted_html(r#"<span id="wf-screen-label"></span>"#));
    let left = [
        ModelineSegment::chevron("AT"),
        ModelineSegment::text(status_env.trim()),
        screen_label,
    ];

    let session_label = status_session
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ANON");
    let logout_attrs = [
        HtmlAttr::new("title", "Sign out"),
        HtmlAttr::new("aria-label", "Sign out"),
    ];
    let mode_attrs = [
        HtmlAttr::new("data-mode-toggle", ""),
        HtmlAttr::new("title", "Toggle color mode"),
        HtmlAttr::new("aria-label", "Toggle color mode"),
    ];
    let mut right = vec![ModelineSegment::text(session_label)];
    if session_label != "ANON" {
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
    let modeline = Modeline::new(&left)
        .with_right(&right)
        .with_attrs(&modeline_attrs);
    safe_component_value(&modeline, "Modeline")
}

fn wf_minibuffer() -> Result<Value, Error> {
    let minibuffer = Minibuffer::new().with_prompt("λ");
    safe_component_value(&minibuffer, "Minibuffer")
}

fn wf_nav_section(label: String) -> Result<Value, Error> {
    let label = label.trim().to_owned();
    safe_component_value(&NavSection::new(&label), "NavSection")
}

fn wf_nav_item(label: String, href: String, active: Option<bool>) -> Result<Value, Error> {
    let label = label.trim().to_owned();
    let href = href.trim().to_owned();
    let mut item = NavItem::new(&label, &href);
    if active.unwrap_or(false) {
        item = item.active();
    }
    safe_component_value(&item, "NavItem")
}

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
/// `SplitShell` visual/content slots are owned by the shell and remain
/// stable.
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
    env.add_function("wf_alert", wf_alert);
    env.add_function("wf_app_shell", wf_app_shell);
    env.add_function("wf_form_panel", wf_form_panel);
    env.add_function("wf_minibuffer", wf_minibuffer);
    env.add_function("wf_modeline", wf_modeline);
    env.add_function("wf_nav_item", wf_nav_item);
    env.add_function("wf_nav_section", wf_nav_section);
    env.add_function("wf_page_header", wf_page_header);
    env.add_function("wf_split_shell", wf_split_shell);

    env.add_filter("datefmt", |value: String| -> String {
        if value.len() >= 16 {
            let date = &value[..10];
            let time = &value[11..16];
            format!("{date} {time} UTC")
        } else {
            value
        }
    });

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
    env.add_template_owned("error.html", ERROR_HTML)
        .expect("error.html");
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
            "error.html",
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
