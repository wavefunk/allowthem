//! Guardrail: every migrated post-auth template must extend _app_shell.html,
//! render at least one wf-* kit class, include the FOUC bootstrap + status bar,
//! surface all expected sidebar hrefs, and contain no Tailwind utility classes.

use minijinja::context;
use minijinja::value::Value;
use regex::Regex;

use allowthem_server::ShellContext;

/// Non-default accent fixture used by the accent-vars tests below. Kept
/// in sync with the auth-template guard in crates/server (identical pair).
fn non_default_accent_fixture() -> (&'static str, &'static str) {
    ("#cba6f7", "#000000")
}

fn tailwind_re() -> Regex {
    // Matches class tokens starting with any of the Tailwind utility prefixes
    // the 9 migrated templates previously used.
    Regex::new(
        r#"class="[^"]*\b(bg-|text-|flex|px-|py-|space-|rounded|shadow-|hover:|focus:|grid-cols-|col-span-)[^"]*""#,
    )
    .unwrap()
}

fn admin_templates() -> &'static [&'static str] {
    &[
        "admin/applications_list.html",
        "admin/application_detail.html",
        "admin/application_new.html",
        "admin/application_edit.html",
        "admin/users_list.html",
        "admin/user_detail.html",
        "admin/sessions_list.html",
        "admin/audit_log.html",
    ]
}

fn app_obj() -> minijinja::Value {
    context! {
        id => "app-id",
        name => "Example App",
        client_id => "cid",
        is_active => true,
        is_trusted => false,
        logo_url => "",
        primary_color => "",
        created_by => None::<String>,
        created_at => "2026-01-01",
        updated_at => "2026-01-02",
    }
}

fn user_obj() -> minijinja::Value {
    context! {
        id => "user-id",
        email => "user@example.com",
        username => None::<String>,
        is_active => true,
        email_verified => false,
        created_at => "2026-01-01",
        updated_at => "2026-01-02",
    }
}

fn ambient_ctx_for(template: &str, shell: &ShellContext) -> minijinja::Value {
    // The audit log uses `user` as a bare query-string, while user_detail
    // uses `user` as an object. Dispatch per template to avoid conflicts.
    match template {
        "admin/application_detail.html" | "admin/application_edit.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            app => app_obj(),
            client_secret => None::<String>,
            redirect_uris => Vec::<String>::new(),
            error => None::<String>,
            created_by_email => None::<String>,
        },
        "admin/application_new.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            form_name => "",
            form_redirect_uris => Vec::<String>::new(),
            form_is_trusted => false,
            form_logo_url => "",
            form_primary_color => "",
            error => None::<String>,
        },
        "admin/applications_list.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            applications => Vec::<()>::new(),
        },
        "admin/users_list.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            users => Vec::<()>::new(),
            total => 0_u32,
            page => 1_u32,
            total_pages => 0_u32,
            q => "",
            status => "",
            mfa => "",
        },
        "admin/user_detail.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            user => user_obj(),
            roles => Vec::<()>::new(),
            oauth_accounts => Vec::<()>::new(),
            sessions => Vec::<()>::new(),
            mfa_enabled => false,
            last_login => None::<String>,
            error => None::<String>,
        },
        "admin/sessions_list.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            sessions => Vec::<()>::new(),
            total => 0_u32,
            page => 1_u32,
            total_pages => 0_u32,
            filter_user_email => None::<String>,
            filter_user_id => None::<String>,
            current_session_id => None::<String>,
        },
        "admin/audit_log.html" => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
            entries => Vec::<()>::new(),
            total => 0_u32,
            page => 1_u32,
            total_pages => 0_u32,
            page_numbers => Vec::<u32>::new(),
            user => "",
            event => "",
            outcome => "",
            from => "",
            to => "",
        },
        _ => context! {
            shell => Value::from_serialize(shell),
            csrf_token => "test",
            is_production => false,
        },
    }
}

fn has_nav_href(body: &str, href: &str) -> bool {
    [
        format!("class=\"wf-nav-item\" href=\"{href}\""),
        format!("class=\"wf-nav-item is-active\" href=\"{href}\""),
    ]
    .into_iter()
    .any(|needle| body.contains(&needle))
}

fn assert_guardrails(name: &str, body: &str, expect_admin_nav: bool) {
    let tw = tailwind_re();
    assert!(
        !tw.is_match(body),
        "{name}: leftover Tailwind utility classes"
    );
    assert!(
        body.contains("class=\"wf-app\"") || body.contains("class=\"wf-app "),
        "{name}: missing wf-app shell body class"
    );
    assert!(
        body.contains("class=\"wf-shell\"") || body.contains("class=\"wf-shell "),
        "{name}: missing wf-shell wrapper"
    );
    assert!(
        !body.contains("class=\"at-app-shell\"") && !body.contains("class=\"at-app-shell "),
        "{name}: stale at-app-shell class"
    );
    assert!(
        !body.contains("class=\"at-sidebar\"") && !body.contains("class=\"at-sidebar "),
        "{name}: stale at-sidebar class"
    );
    assert!(
        !body.contains("class=\"at-main\"") && !body.contains("class=\"at-main "),
        "{name}: stale at-main class"
    );
    assert!(
        body.contains("allowthem:mode"),
        "{name}: missing FOUC bootstrap"
    );
    assert!(body.contains("wf-modeline"), "{name}: missing modeline");
    assert!(body.contains("wf-"), "{name}: no wf-* kit class found");
    assert!(
        body.contains(r#"<nav class="wf-nav-list" id="app-nav" aria-label="primary navigation">"#),
        "{name}: missing primary navigation aria-label"
    );
    assert!(
        !body.contains(r#"hx-boost="true""#),
        "{name}: post-auth shell unexpectedly enables body-level htmx boost"
    );
    assert!(
        has_nav_href(body, "/settings"),
        "{name}: missing /settings nav href"
    );
    assert!(
        has_nav_href(body, "/logout"),
        "{name}: missing /logout nav href"
    );
    for admin_href in ["/admin/applications", "/admin/sessions", "/admin/audit"] {
        if expect_admin_nav {
            assert!(
                has_nav_href(body, admin_href),
                "{name}: expected admin nav href {admin_href}"
            );
        }
    }
    // /admin/users is not in the sidebar nav (reachable via inline links only).
    assert!(
        !has_nav_href(body, "/admin/users"),
        "{name}: /admin/users link present in sidebar but route is reachable via inline links only"
    );
}

/// Render `template` with the non-default accent fixture merged into its
/// ambient context and assert the pair lands verbatim in base.html's
/// <style> block.
fn assert_accent_vars_render(template: &str, base_ctx: minijinja::Value) {
    let env = crate::templates::build_template_env().expect("template env");
    let (accent, accent_ink) = non_default_accent_fixture();
    let ctx = context! {
        accent => accent,
        accent_ink => accent_ink,
        ..base_ctx
    };
    let body = env
        .get_template(template)
        .unwrap_or_else(|e| panic!("{template}: {e}"))
        .render(ctx)
        .unwrap_or_else(|e| panic!("{template}: {e}"));
    assert!(
        body.contains(&format!("--accent: {accent};")),
        "{template}: missing `--accent: {accent};` in rendered output"
    );
    assert!(
        body.contains(&format!("--accent-ink: {accent_ink};")),
        "{template}: missing `--accent-ink: {accent_ink};` in rendered output"
    );
}

/// Verify the audit log template renders when entries use truncate filter
/// (user_id present but user_email absent triggers `| truncate(length=12)`).
#[test]
fn audit_log_truncate_filter_renders() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(true, "/admin/audit", "allowthem");
    let entry = context! {
        event_label => "Login",
        is_failure => false,
        user_id => "01970c0e-2345-7890-abcd-ef0123456789",
        user_email => None::<String>,
        ip_address => "127.0.0.1",
        detail => None::<String>,
        created_at => "2026-04-29 15:45:00",
    };
    let tmpl = env.get_template("admin/audit_log.html").unwrap();
    let body = tmpl
        .render(context! {
            shell => Value::from_serialize(&shell),
            is_production => false,
            entries => vec![entry],
            total => 1_u32,
            page => 1_u32,
            total_pages => 1_u32,
            page_numbers => vec![1_u32],
            user => "",
            event => "",
            outcome => "",
            from => "",
            to => "",
        })
        .unwrap_or_else(|e| panic!("audit_log.html render failed: {e}"));
    // The user_id should be sliced to 12 chars with ellipsis
    assert!(
        body.contains("01970c0e-234"),
        "truncated user_id not found in rendered audit log"
    );
}

#[test]
fn admin_templates_emit_non_default_accent_vars() {
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    for name in admin_templates() {
        assert_accent_vars_render(name, ambient_ctx_for(name, &shell));
    }
}

#[test]
fn settings_template_admin_context_emits_non_default_accent_vars() {
    let shell = ShellContext::new(true, "/settings", "allowthem");
    assert_accent_vars_render(
        "settings.html",
        context! {
            shell => Value::from_serialize(&shell),
            csrf_token => "test",
            is_production => false,
            email => "a@b.c",
            username => "user",
            profile_error => "",
            profile_success => "",
            password_error => "",
            password_success => "",
            oauth_accounts => Vec::<()>::new(),
            mfa_enabled => false,
            mfa_recovery_remaining => 0,
        },
    );
}

#[test]
fn admin_templates_pass_guardrail() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(true, "/admin/applications", "allowthem");
    for name in admin_templates() {
        let tmpl = env
            .get_template(name)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let body = tmpl
            .render(ambient_ctx_for(name, &shell))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_guardrails(name, &body, true);
    }
}

#[test]
fn settings_template_admin_context_passes_guardrail() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(true, "/settings", "allowthem");
    let body = env
        .get_template("settings.html")
        .unwrap()
        .render(context! {
            shell => Value::from_serialize(&shell),
            csrf_token => "test",
            is_production => false,
            email => "a@b.c",
            username => "user",
            profile_error => "",
            profile_success => "",
            password_error => "",
            password_success => "",
            oauth_accounts => Vec::<()>::new(),
            mfa_enabled => false,
            mfa_recovery_remaining => 0,
        })
        .unwrap();
    assert_guardrails("settings.html", &body, true);
}

#[test]
fn settings_template_user_context_passes_guardrail() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(false, "/settings", "allowthem");
    let body = env
        .get_template("settings.html")
        .unwrap()
        .render(context! {
            shell => Value::from_serialize(&shell),
            csrf_token => "test",
            is_production => false,
            email => "a@b.c",
            username => "user",
            profile_error => "",
            profile_success => "",
            password_error => "",
            password_success => "",
            oauth_accounts => Vec::<()>::new(),
            mfa_enabled => false,
            mfa_recovery_remaining => 0,
        })
        .unwrap();
    assert_guardrails("settings.html", &body, false);
}

// --- Standalone page template render tests ---

#[test]
fn dashboard_template_renders_and_passes_guardrail() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(true, "/", "allowthem");
    let body = env
        .get_template("dashboard.html")
        .unwrap()
        .render(context! {
            shell => Value::from_serialize(&shell),
            is_production => false,
            email => "user@example.com",
            is_active => true,
            is_admin => true,
            mfa_enabled => false,
            oauth_account_count => 0usize,
        })
        .unwrap();
    assert_guardrails("dashboard.html", &body, true);
    assert!(
        body.contains("user@example.com"),
        "dashboard: email not rendered"
    );
}

#[test]
fn dashboard_template_hides_admin_link_for_non_admin() {
    let env = crate::templates::build_template_env().expect("template env");
    let shell = ShellContext::new(false, "/", "allowthem");
    let body = env
        .get_template("dashboard.html")
        .unwrap()
        .render(context! {
            shell => Value::from_serialize(&shell),
            is_production => false,
            email => "user@example.com",
            is_active => true,
            is_admin => false,
            mfa_enabled => false,
            oauth_account_count => 2usize,
        })
        .unwrap();
    assert_guardrails("dashboard.html", &body, false);
    assert!(
        !body.contains("Admin panel"),
        "dashboard: admin panel link visible for non-admin"
    );
}

#[test]
fn welcome_template_renders() {
    let env = crate::templates::build_template_env().expect("template env");
    let body = env
        .get_template("welcome.html")
        .unwrap()
        .render(context! { is_production => false })
        .unwrap();
    assert!(body.contains("allowthem"), "welcome: missing app name");
    assert!(body.contains("Log in"), "welcome: missing login link");
    assert!(
        body.contains("Create account"),
        "welcome: missing register link"
    );
}

#[test]
fn terms_template_renders() {
    let env = crate::templates::build_template_env().expect("template env");
    let body = env
        .get_template("terms.html")
        .unwrap()
        .render(context! { is_production => false })
        .unwrap();
    assert!(body.contains("Terms of Service"), "terms: missing heading");
}

#[test]
fn privacy_template_renders() {
    let env = crate::templates::build_template_env().expect("template env");
    let body = env
        .get_template("privacy.html")
        .unwrap()
        .render(context! { is_production => false })
        .unwrap();
    assert!(body.contains("Privacy Policy"), "privacy: missing heading");
}
