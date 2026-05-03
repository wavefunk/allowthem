//! MiniJinja environment composition for the dashboard.
//!
//! The pattern mirrors `crates/server/browser_templates.rs:95-177`:
//! one fresh `Environment`, default browser templates layered first, then
//! dashboard-specific templates layered on top via `include_str!` +
//! `add_template_owned`. No `include_dir!` / no runtime fs lookups.
//!
//! Dashboard templates land in Steps 6 (signup) and 10 (quickstart) of
//! 99c.2 — the calls are added incrementally as those files arrive.

use std::sync::Arc;

use minijinja::Environment;

use allowthem_server::browser_templates::add_default_browser_templates;

const SIGNUP_HTML: &str = include_str!("templates/signup.html");
const SIGNUP_FORM_PARTIAL: &str = include_str!("templates/_partials/_signup_form.html");
const SLUG_CHECK_OK_PARTIAL: &str = include_str!("templates/_partials/_slug_check_ok.html");
const SLUG_CHECK_ERR_PARTIAL: &str = include_str!("templates/_partials/_slug_check_err.html");
const QUICKSTART_HTML: &str = include_str!("templates/quickstart.html");
const QS_CREDENTIALS_PARTIAL: &str =
    include_str!("templates/_partials/_quickstart_credentials.html");
const QS_SNIPPETS_PARTIAL: &str = include_str!("templates/_partials/_quickstart_snippets.html");
const QS_SNIPPET_CURL_PARTIAL: &str =
    include_str!("templates/_partials/_quickstart_snippet_curl.html");
const QS_SNIPPET_BROWSER_PARTIAL: &str =
    include_str!("templates/_partials/_quickstart_snippet_browser.html");
const QS_SNIPPET_SERVER_PARTIAL: &str =
    include_str!("templates/_partials/_quickstart_snippet_server.html");
const QS_SNIPPET_RUST_PARTIAL: &str =
    include_str!("templates/_partials/_quickstart_snippet_rust.html");
const DASHBOARD_SHELL_PARTIAL: &str = include_str!("templates/_partials/_dashboard_shell.html");
const SUSPENDED_PARTIAL: &str = include_str!("templates/_partials/_suspended.html");
const WORKSPACE_SWITCHER_PARTIAL: &str =
    include_str!("templates/_partials/_workspace_switcher.html");
const APPLICATION_FORM_PARTIAL: &str = include_str!("templates/_partials/_application_form.html");
const APPLICATION_SECRET_PANEL_PARTIAL: &str =
    include_str!("templates/_partials/_application_secret_panel.html");
const APPLICATIONS_LIST_HTML: &str = include_str!("templates/applications/list.html");
const APPLICATIONS_NEW_HTML: &str = include_str!("templates/applications/new.html");
const APPLICATIONS_DETAIL_HTML: &str = include_str!("templates/applications/detail.html");
const APPLICATIONS_EDIT_HTML: &str = include_str!("templates/applications/edit.html");
const AUDIT_LIST_HTML: &str = include_str!("templates/audit/list.html");
const USERS_LIST_HTML: &str = include_str!("templates/users/list.html");
const USERS_DETAIL_HTML: &str = include_str!("templates/users/detail.html");
const USER_ACTIONS_PARTIAL: &str = include_str!("templates/_partials/_user_actions.html");
const USER_ROLES_PARTIAL: &str = include_str!("templates/_partials/_user_roles.html");
const USER_PERMISSIONS_PARTIAL: &str = include_str!("templates/_partials/_user_permissions.html");
const USER_SESSIONS_PARTIAL: &str = include_str!("templates/_partials/_user_sessions.html");
const USER_AUDIT_PARTIAL: &str = include_str!("templates/_partials/_user_audit.html");

pub fn build_dashboard_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();

    // 1. Default browser templates (login, register, _auth_shell, _app_shell, ...).
    add_default_browser_templates(&mut env);

    // 2. Dashboard-specific templates layered on top.
    env.add_template_owned("signup.html", SIGNUP_HTML)
        .expect("signup.html");
    env.add_template_owned("_partials/_signup_form.html", SIGNUP_FORM_PARTIAL)
        .expect("_partials/_signup_form.html");
    env.add_template_owned("_partials/_slug_check_ok.html", SLUG_CHECK_OK_PARTIAL)
        .expect("_partials/_slug_check_ok.html");
    env.add_template_owned("_partials/_slug_check_err.html", SLUG_CHECK_ERR_PARTIAL)
        .expect("_partials/_slug_check_err.html");

    env.add_template_owned("quickstart.html", QUICKSTART_HTML)
        .expect("quickstart.html");
    env.add_template_owned(
        "_partials/_quickstart_credentials.html",
        QS_CREDENTIALS_PARTIAL,
    )
    .expect("_partials/_quickstart_credentials.html");
    env.add_template_owned("_partials/_quickstart_snippets.html", QS_SNIPPETS_PARTIAL)
        .expect("_partials/_quickstart_snippets.html");
    env.add_template_owned(
        "_partials/_quickstart_snippet_curl.html",
        QS_SNIPPET_CURL_PARTIAL,
    )
    .expect("_partials/_quickstart_snippet_curl.html");
    env.add_template_owned(
        "_partials/_quickstart_snippet_browser.html",
        QS_SNIPPET_BROWSER_PARTIAL,
    )
    .expect("_partials/_quickstart_snippet_browser.html");
    env.add_template_owned(
        "_partials/_quickstart_snippet_server.html",
        QS_SNIPPET_SERVER_PARTIAL,
    )
    .expect("_partials/_quickstart_snippet_server.html");
    env.add_template_owned(
        "_partials/_quickstart_snippet_rust.html",
        QS_SNIPPET_RUST_PARTIAL,
    )
    .expect("_partials/_quickstart_snippet_rust.html");

    // Dashboard shell + tenant-status partials (99c.3+).
    env.add_template_owned("_partials/_dashboard_shell.html", DASHBOARD_SHELL_PARTIAL)
        .expect("_partials/_dashboard_shell.html");
    env.add_template_owned("_partials/_suspended.html", SUSPENDED_PARTIAL)
        .expect("_partials/_suspended.html");
    env.add_template_owned(
        "_partials/_workspace_switcher.html",
        WORKSPACE_SWITCHER_PARTIAL,
    )
    .expect("_partials/_workspace_switcher.html");

    // Application CRUD pages (99c.3).
    env.add_template_owned("_partials/_application_form.html", APPLICATION_FORM_PARTIAL)
        .expect("_partials/_application_form.html");
    env.add_template_owned(
        "_partials/_application_secret_panel.html",
        APPLICATION_SECRET_PANEL_PARTIAL,
    )
    .expect("_partials/_application_secret_panel.html");
    env.add_template_owned("applications/list.html", APPLICATIONS_LIST_HTML)
        .expect("applications/list.html");
    env.add_template_owned("applications/new.html", APPLICATIONS_NEW_HTML)
        .expect("applications/new.html");
    env.add_template_owned("applications/detail.html", APPLICATIONS_DETAIL_HTML)
        .expect("applications/detail.html");
    env.add_template_owned("applications/edit.html", APPLICATIONS_EDIT_HTML)
        .expect("applications/edit.html");

    // Audit log page (99c.5).
    env.add_template_owned("audit/list.html", AUDIT_LIST_HTML)
        .expect("audit/list.html");

    // User management (99c.4).
    env.add_template_owned("users/list.html", USERS_LIST_HTML)
        .expect("users/list.html");
    env.add_template_owned("users/detail.html", USERS_DETAIL_HTML)
        .expect("users/detail.html");
    env.add_template_owned("_partials/_user_actions.html", USER_ACTIONS_PARTIAL)
        .expect("_partials/_user_actions.html");
    env.add_template_owned("_partials/_user_roles.html", USER_ROLES_PARTIAL)
        .expect("_partials/_user_roles.html");
    env.add_template_owned(
        "_partials/_user_permissions.html",
        USER_PERMISSIONS_PARTIAL,
    )
    .expect("_partials/_user_permissions.html");
    env.add_template_owned("_partials/_user_sessions.html", USER_SESSIONS_PARTIAL)
        .expect("_partials/_user_sessions.html");
    env.add_template_owned("_partials/_user_audit.html", USER_AUDIT_PARTIAL)
        .expect("_partials/_user_audit.html");

    Arc::new(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dashboard_env_loads_default_partials() {
        let env = build_dashboard_env();
        // Sanity check — the shared `_auth_shell.html` partial that signup
        // and friends extend resolves through the dashboard env.
        env.get_template("_partials/_auth_shell.html")
            .expect("_auth_shell.html should resolve via add_default_browser_templates");
    }

    #[test]
    fn signup_template_renders() {
        let env = build_dashboard_env();
        let tmpl = env.get_template("signup.html").expect("signup.html");
        let html = tmpl
            .render(minijinja::context! {
                csrf_token => "csrf123",
                email => "owner@acme.com",
                tenant_name => "Acme",
                slug => "acme",
                error => "" as &str,
            })
            .expect("render");
        assert!(html.contains("Create your workspace"));
        assert!(html.contains("name=\"csrf_token\""));
        assert!(html.contains("owner@acme.com"));
    }

    #[test]
    fn slug_check_ok_renders_with_slug() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_slug_check_ok.html")
            .expect("ok partial");
        let html = tmpl
            .render(minijinja::context! { slug => "acme" })
            .expect("render");
        assert!(html.contains("acme"));
        assert!(html.contains("ok"));
    }

    #[test]
    fn slug_check_err_renders_with_msg() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_slug_check_err.html")
            .expect("err partial");
        let html = tmpl
            .render(minijinja::context! { msg => "Reserved" })
            .expect("render");
        assert!(html.contains("Reserved"));
    }

    #[test]
    fn quickstart_template_renders_with_full_context() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("quickstart.html")
            .expect("quickstart.html");
        let html = tmpl
            .render(minijinja::context! {
                csrf_token => "csrf",
                token => "abc",
                slug => "acme",
                issuer => "https://acme.example.com",
                client_id => "ath_test",
                client_secret => "very-secret",
                redirect_uri => "http://localhost/callback",
            })
            .expect("render");
        assert!(html.contains("ath_test"), "client_id rendered");
        assert!(html.contains("very-secret"), "client_secret rendered");
        assert!(html.contains("/quickstart/abc/dismiss"), "dismiss form");
    }

    #[test]
    fn dashboard_shell_renders() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_dashboard_shell.html")
            .expect("_dashboard_shell.html");
        let body = tmpl
            .render(minijinja::context! {})
            .expect("render dashboard shell");
        assert!(
            body.contains("wf-sidenav"),
            "dashboard shell should expose sidebar nav block"
        );
    }

    #[test]
    fn suspended_partial_renders_with_tenant() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_suspended.html")
            .expect("_suspended.html");
        let body = tmpl
            .render(minijinja::context! {
                tenant => minijinja::context! { name => "Acme", slug => "acme" },
            })
            .expect("render suspended");
        assert!(body.contains("Workspace suspended"));
        assert!(body.contains("Acme"));
    }

    #[test]
    fn application_templates_register() {
        let env = build_dashboard_env();
        for name in [
            "applications/list.html",
            "applications/new.html",
            "applications/detail.html",
            "applications/edit.html",
            "_partials/_application_form.html",
            "_partials/_application_secret_panel.html",
            "_partials/_workspace_switcher.html",
        ] {
            env.get_template(name)
                .unwrap_or_else(|_| panic!("{name} should resolve in dashboard env"));
        }
    }

    #[test]
    fn applications_list_renders_with_role_admin() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("applications/list.html")
            .expect("applications/list.html");
        let body = tmpl
            .render(minijinja::context! {
                tenant => minijinja::context! { name => "Acme", slug => "acme" },
                role => "admin",
                applications => Vec::<minijinja::Value>::new(),
                workspaces => Vec::<minijinja::Value>::new(),
            })
            .expect("render list");
        assert!(body.contains("New application"), "admin sees create button");
        assert!(body.contains("ALLOWTHEM") || body.contains("Acme"));
    }

    #[test]
    fn applications_list_hides_create_button_for_viewer() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("applications/list.html")
            .expect("applications/list.html");
        let body = tmpl
            .render(minijinja::context! {
                tenant => minijinja::context! { name => "Acme", slug => "acme" },
                role => "viewer",
                applications => Vec::<minijinja::Value>::new(),
                workspaces => Vec::<minijinja::Value>::new(),
            })
            .expect("render list");
        assert!(
            !body.contains("New application"),
            "viewer should NOT see the create button"
        );
    }

    #[test]
    fn application_secret_panel_renders_secret() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_application_secret_panel.html")
            .expect("_application_secret_panel.html");
        let body = tmpl
            .render(minijinja::context! { client_secret => "shh-very-secret" })
            .expect("render secret panel");
        assert!(body.contains("shh-very-secret"));
        assert!(body.contains("Copy"));
    }

    #[test]
    fn quickstart_snippets_substitute_values() {
        let env = build_dashboard_env();
        for name in [
            "_partials/_quickstart_snippet_curl.html",
            "_partials/_quickstart_snippet_browser.html",
            "_partials/_quickstart_snippet_server.html",
            "_partials/_quickstart_snippet_rust.html",
        ] {
            let tmpl = env.get_template(name).unwrap_or_else(|_| panic!("{name}"));
            let html = tmpl
                .render(minijinja::context! {
                    issuer => "https://acme.example.com",
                    client_id => "ath_test",
                    client_secret => "very-secret",
                    redirect_uri => "http://localhost/callback",
                })
                .unwrap_or_else(|_| panic!("render {name}"));
            assert!(
                html.contains("ath_test") || html.contains("acme.example.com"),
                "snippet {name} should substitute issuer/client_id"
            );
        }
    }
}
