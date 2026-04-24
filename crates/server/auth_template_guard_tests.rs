//! Design-system guard tests for auth templates.
//!
//! Every auth page renders exclusively with Wave Funk design system
//! primitives. These tests enforce structural contracts (required
//! classes), forbid legacy / non-system classes, verify accent theming,
//! and assert CSS cascade order.

use minijinja::{Environment, Value};
use std::collections::BTreeMap;

use crate::browser_templates::add_default_browser_templates;

/// Design system classes that every full-page auth render must contain.
const REQUIRED_PAGE: &[&str] = &[
    "wf-auth",
    "wf-auth-splash",
    "wf-statusbar",
    "wf-auth-form",
    "wf-auth-top",
    "wf-auth-wrap",
];

/// Classes that every auth partial (HTMX fragment) must contain.
const REQUIRED_PARTIAL: &[&str] = &[
    "wf-auth-form",
    "wf-auth-top",
    "wf-auth-wrap",
];

/// Substrings that must never appear in rendered auth output.
const FORBIDDEN: &[&str] = &[
    "bg-gray-", "bg-red-", "bg-green-", "bg-yellow-",
    "bg-white", "bg-blue-",
    "text-gray-", "text-blue-", "text-white",
    "min-h-screen", "max-w-sm", "max-w-md", "focus:ring-",
    "at-btn-primary", "at-input-focus", "at-link",
    "at-auth-shell", "at-form-pane", "at-form-wrap",
    "class=\"wf-splash\"",
    "class=\"wf-splash ",
    "border-radius",
];

// ── Context builder ──────────────────────────────────────────────────────

fn ctx(extras: &[(&str, Value)]) -> Value {
    let mut map: BTreeMap<String, Value> = BTreeMap::new();
    map.insert("csrf_token".into(), Value::from("tok"));
    map.insert("accent".into(), Value::from("#ffffff"));
    map.insert("accent_ink".into(), Value::from("#000000"));
    map.insert("accent_light".into(), Value::from("#000000"));
    map.insert("accent_ink_light".into(), Value::from("#ffffff"));
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

fn login_ctx() -> Value {
    ctx(&[
        ("identifier", Value::from("")),
        ("oauth_providers", Value::from(Vec::<String>::new())),
    ])
}

fn register_ctx() -> Value {
    ctx(&[
        ("email", Value::from("")),
        ("username", Value::from("")),
        ("custom_fields", Value::from(Vec::<Value>::new())),
        (
            "custom_values",
            Value::from_serialize(&BTreeMap::<String, String>::new()),
        ),
    ])
}

fn consent_ctx() -> Value {
    ctx(&[
        ("application_name", Value::from("Test App")),
        ("scope_items", Value::from(Vec::<Value>::new())),
        ("redirect_uri", Value::from("https://example.com/cb")),
        ("response_type", Value::from("code")),
        ("scope", Value::from("openid")),
        ("state_param", Value::from("state")),
        ("code_challenge", Value::from("chal")),
        ("code_challenge_method", Value::from("S256")),
    ])
}

fn mfa_setup_ctx() -> Value {
    ctx(&[
        ("totp_uri", Value::from("otpauth://totp/foo")),
        ("secret", Value::from("JBSWY3DPEHPK3PXP")),
    ])
}

fn mfa_recovery_ctx() -> Value {
    ctx(&[("recovery_codes", Value::from(vec!["AAAA-BBBB", "CCCC-DDDD"]))])
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn render(name: &str, context: Value) -> String {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.get_template(name)
        .unwrap_or_else(|e| panic!("load {name}: {e}"))
        .render(context)
        .unwrap_or_else(|e| panic!("render {name}: {e}"))
}

fn assert_page(name: &str, context: Value) {
    let html = render(name, context);
    for needle in REQUIRED_PAGE {
        assert!(html.contains(needle), "{name}: missing required `{needle}`");
    }
    for needle in FORBIDDEN {
        assert!(!html.contains(needle), "{name}: contains forbidden `{needle}`");
    }
}

fn assert_partial(name: &str, context: Value) {
    let html = render(name, context);
    for needle in REQUIRED_PARTIAL {
        assert!(html.contains(needle), "{name}: missing required `{needle}`");
    }
    for needle in FORBIDDEN {
        assert!(!html.contains(needle), "{name}: contains forbidden `{needle}`");
    }
}

fn assert_accent(name: &str, context: Value) {
    let html = render(
        name,
        minijinja::context! {
            accent => "#cba6f7",
            accent_ink => "#000000",
            ..context
        },
    );
    assert!(
        html.contains("--accent: #cba6f7;"),
        "{name}: missing --accent in rendered output"
    );
    assert!(
        html.contains("--accent-ink: #000000;"),
        "{name}: missing --accent-ink in rendered output"
    );
}

// ── Full-page design system guards ───────────────────────────────────────

#[test]
fn page_login() {
    assert_page("login.html", login_ctx());
}

#[test]
fn page_register() {
    assert_page("register.html", register_ctx());
}

#[test]
fn page_forgot_password() {
    assert_page("forgot_password.html", ctx(&[]));
}

#[test]
fn page_reset_password() {
    assert_page("reset_password.html", ctx(&[("token", Value::from("tok"))]));
}

#[test]
fn page_mfa_challenge() {
    assert_page(
        "mfa_challenge.html",
        ctx(&[("mfa_token", Value::from("tok"))]),
    );
}

#[test]
fn page_mfa_setup() {
    assert_page("mfa_setup.html", mfa_setup_ctx());
}

#[test]
fn page_mfa_recovery() {
    assert_page("mfa_recovery.html", mfa_recovery_ctx());
}

#[test]
fn page_consent() {
    assert_page("consent.html", consent_ctx());
}

// ── Partial (HTMX fragment) guards ───────────────────────────────────────

#[test]
fn partial_login() {
    assert_partial("_partials/_auth_main_login.html", login_ctx());
}

#[test]
fn partial_register() {
    assert_partial("_partials/_auth_main_register.html", register_ctx());
}

#[test]
fn partial_forgot_password() {
    assert_partial("_partials/_auth_main_forgot_password.html", ctx(&[]));
}

#[test]
fn partial_reset_password() {
    assert_partial(
        "_partials/_auth_main_reset_password.html",
        ctx(&[("token", Value::from("tok"))]),
    );
}

#[test]
fn partial_mfa_challenge() {
    assert_partial(
        "_partials/_auth_main_mfa_challenge.html",
        ctx(&[("mfa_token", Value::from("tok"))]),
    );
}

#[test]
fn partial_mfa_setup() {
    assert_partial("_partials/_auth_main_mfa_setup.html", mfa_setup_ctx());
}

#[test]
fn partial_mfa_recovery() {
    assert_partial("_partials/_auth_main_mfa_recovery.html", mfa_recovery_ctx());
}

#[test]
fn partial_consent() {
    assert_partial("_partials/_auth_main_consent.html", consent_ctx());
}

// ── Accent theming ───────────────────────────────────────────────────────

#[test]
fn accent_login() {
    assert_accent("login.html", login_ctx());
}

#[test]
fn accent_register() {
    assert_accent("register.html", register_ctx());
}

#[test]
fn accent_forgot_password() {
    assert_accent("forgot_password.html", ctx(&[]));
}

#[test]
fn accent_reset_password() {
    assert_accent(
        "reset_password.html",
        ctx(&[("token", Value::from("tok"))]),
    );
}

#[test]
fn accent_mfa_challenge() {
    assert_accent(
        "mfa_challenge.html",
        ctx(&[("mfa_token", Value::from("tok"))]),
    );
}

#[test]
fn accent_mfa_setup() {
    assert_accent("mfa_setup.html", mfa_setup_ctx());
}

#[test]
fn accent_mfa_recovery() {
    assert_accent("mfa_recovery.html", mfa_recovery_ctx());
}

#[test]
fn accent_consent() {
    assert_accent("consent.html", consent_ctx());
}

// ── CSS cascade order ────────────────────────────────────────────────────

#[test]
fn css_cascade_order() {
    let html = render("login.html", login_ctx());
    let ordered = [
        "/__allowthem/static/css/01-tokens.css",
        "/__allowthem/static/css/02-base.css",
        "/__allowthem/static/css/03-layout.css",
        "/__allowthem/static/css/04-components.css",
        "/__allowthem/static/css/05-utilities.css",
    ];
    let indices: Vec<usize> = ordered
        .iter()
        .map(|needle| {
            html.find(needle)
                .unwrap_or_else(|| panic!("missing stylesheet link `{needle}`"))
        })
        .collect();
    for w in indices.windows(2) {
        assert!(
            w[0] < w[1],
            "CSS link order broken — expected {:?}, got indices {:?}",
            ordered,
            indices
        );
    }
}

// ── OOB head fragment ────────────────────────────────────────────────────

#[test]
fn oob_head_renders_title_and_screen_label() {
    let html = render(
        "_partials/_auth_oob_head.html",
        minijinja::context! {
            page_title => "Log in — allowthem",
            status_hint => "SIGN IN",
        }
        .into(),
    );
    assert!(html.contains(r#"<title hx-swap-oob="true">Log in — allowthem</title>"#));
    assert!(html.contains(r#"id="wf-screen-label""#));
    assert!(html.contains(r#"hx-swap-oob="true""#));
    assert!(html.contains(">SIGN IN<"));
}

// ── Form component usage guards ──────────────────────────────────────────

#[test]
fn login_uses_design_system_form_components() {
    let html = render("_partials/_auth_main_login.html", login_ctx());
    assert!(html.contains("wf-field"), "login: missing wf-field wrapper");
    assert!(html.contains("wf-input"), "login: missing wf-input");
    assert!(html.contains("wf-label"), "login: missing wf-label");
    assert!(html.contains("wf-btn primary"), "login: missing primary button");
    assert!(html.contains("wf-tabs"), "login: missing wf-tabs switcher");
}

#[test]
fn register_uses_design_system_form_components() {
    let html = render("_partials/_auth_main_register.html", register_ctx());
    assert!(html.contains("wf-field"), "register: missing wf-field wrapper");
    assert!(html.contains("wf-input"), "register: missing wf-input");
    assert!(html.contains("wf-label"), "register: missing wf-label");
    assert!(html.contains("wf-btn primary"), "register: missing primary button");
    assert!(html.contains("wf-tabs"), "register: missing wf-tabs switcher");
}
