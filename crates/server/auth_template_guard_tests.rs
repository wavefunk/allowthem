//! Guard tests that enumerate the migrated auth templates and assert each
//! one extends `_auth_shell.html` (stamping `at-auth-shell` on <body>) and
//! contains no Tailwind utility classes or the retired at-* compat classes.
//!
//! Add a template here when M3 lands its migration; remove an entry if the
//! page is deleted. The explicit list beats globbing — it fails loud if a
//! template name changes.

use minijinja::Environment;

use crate::browser_templates::add_default_browser_templates;

/// Substrings that MUST NOT appear in a migrated auth template's rendered
/// output. Hits are reported with the template name so failures point at the
/// specific page that regressed.
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    // Tailwind utility classes most commonly found in the pre-M3 templates.
    // This is a "did a utility class sneak back in?" probe, not an exhaustive ban.
    "bg-gray-50",
    "bg-red-50",
    "bg-green-50",
    "bg-yellow-50",
    "bg-white",
    "bg-blue-600",
    "text-gray-900",
    "text-gray-700",
    "text-gray-600",
    "text-gray-500",
    "text-gray-400",
    "text-blue-600",
    "text-white",
    "min-h-screen",
    "max-w-sm",
    "max-w-md",
    "focus:ring-blue-500",
    // at-* compat shim classes — deleted from base.html in Task 8 Step 5.
    "at-btn-primary",
    "at-input-focus",
    "at-link",
];

/// Structural assertion: every migrated auth page inherits `_auth_shell.html`
/// (which stamps `at-auth-shell` on `<body>`) and pulls the splash aside.
const REQUIRED_SUBSTRINGS: &[&str] = &[
    "at-auth-shell",   // body class from the shell
    "wf-splash",       // splash aside from the shell
    "wf-statusbar",    // status bar at the bottom
];

use std::collections::BTreeMap;
use minijinja::Value;

/// Non-default accent fixture used by the accent-vars tests below. Pairs
/// a Catppuccin Mauve hex with black ink; no bearing on production branding.
fn non_default_accent_fixture() -> (&'static str, &'static str) {
    ("#cba6f7", "#000000")
}

/// Build a merged context from a set of `(name, Value)` pairs on top of a
/// base map that carries every optional `{% if ... %}` key the auth
/// templates branch on. Strict-undefined (if enabled in
/// `add_default_browser_templates`) would otherwise panic on absent keys.
fn ctx_with(extras: &[(&str, Value)]) -> Value {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("csrf_token".into(), Value::from("tok"));
    map.insert("accent".into(), Value::from("#ffffff"));
    map.insert("accent_ink".into(), Value::from("#000000"));
    map.insert("is_production".into(), Value::from(false));
    map.insert("error".into(), Value::from(""));
    map.insert("success".into(), Value::from(false));
    map.insert("invalid_token".into(), Value::from(false));
    map.insert("logo_url".into(), Value::from(""));
    map.insert("app_name".into(), Value::from(""));
    map.insert("next".into(), Value::from(""));
    map.insert("client_id".into(), Value::from(""));
    for (k, v) in extras {
        map.insert((*k).to_string(), v.clone());
    }
    Value::from_serialize(&map)
}

#[test]
fn login_has_no_tailwind_or_at_classes() {
    check_template(
        "login.html",
        ctx_with(&[
            ("identifier", Value::from("")),
            ("oauth_providers", Value::from(Vec::<String>::new())),
        ]),
    );
}

#[test]
fn register_has_no_tailwind_or_at_classes() {
    check_template(
        "register.html",
        ctx_with(&[
            ("email", Value::from("")),
            ("username", Value::from("")),
            ("custom_fields", Value::from(Vec::<Value>::new())),
            ("custom_values", Value::from_serialize(&BTreeMap::<String, String>::new())),
        ]),
    );
}

#[test]
fn forgot_password_has_no_tailwind_or_at_classes() {
    check_template("forgot_password.html", ctx_with(&[]));
}

#[test]
fn reset_password_has_no_tailwind_or_at_classes() {
    check_template(
        "reset_password.html",
        ctx_with(&[("token", Value::from("reset-token-abc"))]),
    );
}

#[test]
fn mfa_challenge_has_no_tailwind_or_at_classes() {
    check_template(
        "mfa_challenge.html",
        ctx_with(&[("mfa_token", Value::from("mfa-token-abc"))]),
    );
}

#[test]
fn mfa_setup_has_no_tailwind_or_at_classes() {
    check_template(
        "mfa_setup.html",
        ctx_with(&[
            ("totp_uri", Value::from("otpauth://totp/foo")),
            ("secret", Value::from("JBSWY3DPEHPK3PXP")),
        ]),
    );
}

#[test]
fn mfa_recovery_has_no_tailwind_or_at_classes() {
    check_template(
        "mfa_recovery.html",
        ctx_with(&[("recovery_codes", Value::from(vec!["AAAA-BBBB", "CCCC-DDDD"]))]),
    );
}

#[test]
fn consent_has_no_tailwind_or_at_classes() {
    check_template(
        "consent.html",
        ctx_with(&[
            ("application_name", Value::from("Test App")),
            ("scope_items", Value::from(Vec::<Value>::new())),
            ("redirect_uri", Value::from("https://example.com/cb")),
            ("response_type", Value::from("code")),
            ("scope", Value::from("openid")),
            ("state_param", Value::from("state")),
            ("code_challenge", Value::from("chal")),
            ("code_challenge_method", Value::from("S256")),
        ]),
    );
}

fn check_template(name: &'static str, ctx: Value) {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    let html = env
        .get_template(name)
        .unwrap_or_else(|e| panic!("load {name}: {e}"))
        .render(ctx)
        .unwrap_or_else(|e| panic!("render {name}: {e}"));

    for needle in REQUIRED_SUBSTRINGS {
        assert!(
            html.contains(needle),
            "{name}: expected to contain `{needle}` (is it extending _auth_shell.html?)"
        );
    }
    for needle in FORBIDDEN_SUBSTRINGS {
        assert!(
            !html.contains(needle),
            "{name}: contains forbidden substring `{needle}` — kit migration regressed"
        );
    }
}

/// Render `template_name` with the non-default accent fixture merged onto
/// `extra_ctx`, then assert base.html's <style> block emitted the pair
/// verbatim. Shields against a template accidentally overriding
/// `{% block theme %}` and swallowing the accent vars.
fn assert_accent_vars_render(template_name: &'static str, extra_ctx: Value) {
    let (accent, accent_ink) = non_default_accent_fixture();
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    let ctx = minijinja::context! {
        accent => accent,
        accent_ink => accent_ink,
        ..extra_ctx
    };
    let html = env
        .get_template(template_name)
        .unwrap_or_else(|e| panic!("load {template_name}: {e}"))
        .render(ctx)
        .unwrap_or_else(|e| panic!("render {template_name}: {e}"));
    assert!(
        html.contains(&format!("--accent: {accent};")),
        "{template_name}: missing `--accent: {accent};` in rendered output"
    );
    assert!(
        html.contains(&format!("--accent-ink: {accent_ink};")),
        "{template_name}: missing `--accent-ink: {accent_ink};` in rendered output"
    );
}

#[test]
fn login_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "login.html",
        ctx_with(&[
            ("identifier", Value::from("")),
            ("oauth_providers", Value::from(Vec::<String>::new())),
        ]),
    );
}

#[test]
fn register_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "register.html",
        ctx_with(&[
            ("email", Value::from("")),
            ("username", Value::from("")),
            ("custom_fields", Value::from(Vec::<Value>::new())),
            ("custom_values", Value::from_serialize(&BTreeMap::<String, String>::new())),
        ]),
    );
}

#[test]
fn forgot_password_emits_non_default_accent_vars() {
    assert_accent_vars_render("forgot_password.html", ctx_with(&[]));
}

#[test]
fn reset_password_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "reset_password.html",
        ctx_with(&[("token", Value::from("reset-token-abc"))]),
    );
}

#[test]
fn mfa_challenge_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "mfa_challenge.html",
        ctx_with(&[("mfa_token", Value::from("mfa-token-abc"))]),
    );
}

#[test]
fn mfa_setup_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "mfa_setup.html",
        ctx_with(&[
            ("totp_uri", Value::from("otpauth://totp/foo")),
            ("secret", Value::from("JBSWY3DPEHPK3PXP")),
        ]),
    );
}

#[test]
fn mfa_recovery_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "mfa_recovery.html",
        ctx_with(&[("recovery_codes", Value::from(vec!["AAAA-BBBB", "CCCC-DDDD"]))]),
    );
}

#[test]
fn consent_emits_non_default_accent_vars() {
    assert_accent_vars_render(
        "consent.html",
        ctx_with(&[
            ("application_name", Value::from("Test App")),
            ("scope_items", Value::from(Vec::<Value>::new())),
            ("redirect_uri", Value::from("https://example.com/cb")),
            ("response_type", Value::from("code")),
            ("scope", Value::from("openid")),
            ("state_param", Value::from("state")),
            ("code_challenge", Value::from("chal")),
            ("code_challenge_method", Value::from("S256")),
        ]),
    );
}
