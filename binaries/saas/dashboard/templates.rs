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

    // Quickstart templates land in Step 10.

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
}
