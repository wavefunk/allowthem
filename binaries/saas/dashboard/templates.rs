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

use minijinja::value::Value;
use minijinja::{Environment, Error, ErrorKind};
use wavefunk_ui::Template;
use wavefunk_ui::components::{
    ContextSwitcher, ContextSwitcherItem, HtmlAttr, Sidenav, SidenavItem, SidenavSection,
};

use allowthem_server::browser_templates::add_default_browser_templates;
use allowthem_server::render_component;

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

// Invite accept flow (99c.5 Step 15).
const INVITE_REGISTER_HTML: &str = include_str!("templates/invite/register.html");
const INVITE_ACCEPT_HTML: &str = include_str!("templates/invite/accept.html");
const INVITE_EXPIRED_HTML: &str = include_str!("templates/invite/expired.html");

// Team members list (99c.5 Step 13).
const SETTINGS_TEAM_LIST_HTML: &str = include_str!("templates/settings/team/list.html");

// Plan & billing page (99c.5 Step 12).
const SETTINGS_BILLING_HTML: &str = include_str!("templates/settings/billing.html");

// API key management page (99c.5 Step 11).
const SETTINGS_API_KEYS_LIST_HTML: &str = include_str!("templates/settings/api_keys/list.html");

// General settings page (99c.5 Step 10).
const SETTINGS_GENERAL_HTML: &str = include_str!("templates/settings/general.html");

// Permissions CRUD pages (99c.5 Step 9).
const PERMISSIONS_LIST_HTML: &str = include_str!("templates/permissions/list.html");
const PERMISSIONS_NEW_HTML: &str = include_str!("templates/permissions/new.html");

// Roles CRUD pages (99c.5 Step 8).
const ROLE_FORM_PARTIAL: &str = include_str!("templates/_partials/_role_form.html");
const ROLES_LIST_HTML: &str = include_str!("templates/roles/list.html");
const ROLES_NEW_HTML: &str = include_str!("templates/roles/new.html");
const ROLES_DETAIL_HTML: &str = include_str!("templates/roles/detail.html");

// Super-admin panel (99c.6).
const ADMIN_OVERVIEW_HTML: &str = include_str!("templates/admin/overview.html");
const ADMIN_TENANT_DETAIL_HTML: &str = include_str!("templates/admin/tenant_detail.html");
const ADMIN_USAGE_HTML: &str = include_str!("templates/admin/usage.html");
const ADMIN_REVENUE_HTML: &str = include_str!("templates/admin/revenue.html");
const ADMIN_HEALTH_HTML: &str = include_str!("templates/admin/health.html");

// Coming-soon stub pages (99c.5 Step 6).
const COMING_SOON_PARTIAL: &str = include_str!("templates/_partials/_coming_soon.html");
const SETTINGS_WEBHOOKS_HTML: &str = include_str!("templates/settings/webhooks.html");
const SETTINGS_EMAIL_HTML: &str = include_str!("templates/settings/email.html");
const SETTINGS_SOCIAL_HTML: &str = include_str!("templates/settings/social.html");
const SETTINGS_DOMAIN_HTML: &str = include_str!("templates/settings/domain.html");

// Custom domain settings page (38y.1).
const SETTINGS_DOMAINS_HTML: &str = include_str!("templates/settings/domains.html");

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

fn attr_value(value: &Value, key: &str) -> Result<Value, Error> {
    value
        .get_attr(key)
        .map_err(|err| component_error("dashboard nav data", err))
}

fn attr_text(value: &Value, key: &str) -> Result<Option<String>, Error> {
    let attr = attr_value(value, key)?;
    if attr.is_undefined() || attr.is_none() {
        return Ok(None);
    }
    Ok(Some(
        attr.as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| attr.to_string()),
    ))
}

fn attr_bool(value: &Value, key: &str) -> Result<bool, Error> {
    let attr = attr_value(value, key)?;
    Ok(!attr.is_undefined() && !attr.is_none() && attr.is_true())
}

fn wf_context_switcher(workspaces: Value, current_tenant: Value) -> Result<Value, Error> {
    if workspaces.is_undefined() || workspaces.is_none() || workspaces.len().unwrap_or(0) == 0 {
        return Ok(Value::from_safe_string(String::new()));
    }

    struct OwnedWorkspace {
        label: String,
        href: String,
        role: String,
        active: bool,
    }

    let current_slug = if current_tenant.is_undefined() || current_tenant.is_none() {
        None
    } else {
        attr_text(&current_tenant, "slug")?
    };
    let current = if current_tenant.is_undefined() || current_tenant.is_none() {
        "Workspaces".to_owned()
    } else {
        attr_text(&current_tenant, "name")?.unwrap_or_else(|| "Workspaces".to_owned())
    };

    let mut owned = Vec::new();
    for workspace in workspaces.try_iter()? {
        let tenant = attr_value(&workspace, "tenant")?;
        let label = attr_text(&tenant, "name")?.unwrap_or_else(|| "Workspace".to_owned());
        let slug = attr_text(&tenant, "slug")?.unwrap_or_default();
        let role = attr_text(&workspace, "role")?.unwrap_or_default();
        let active = current_slug
            .as_deref()
            .is_some_and(|current| slug.as_str() == current);
        owned.push(OwnedWorkspace {
            label,
            href: format!("/t/{slug}/applications"),
            role,
            active,
        });
    }

    if owned.is_empty() {
        return Ok(Value::from_safe_string(String::new()));
    }

    let items = owned
        .iter()
        .map(|workspace| {
            let mut item = ContextSwitcherItem::link(&workspace.label, &workspace.href)
                .with_meta(&workspace.role);
            if workspace.active {
                item = item.active();
            }
            item
        })
        .collect::<Vec<_>>();
    let attrs = [HtmlAttr::new("aria-label", "Workspace switcher")];
    let switcher = ContextSwitcher::new("Workspace", &current, &items).with_attrs(&attrs);
    safe_component_value(&switcher, "ContextSwitcher")
}

fn wf_dashboard_sidenav(nav_sections: Value) -> Result<Value, Error> {
    if nav_sections.is_undefined() || nav_sections.is_none() || nav_sections.len().unwrap_or(0) == 0
    {
        return Ok(Value::from_safe_string(String::new()));
    }

    struct OwnedSection {
        heading: String,
        items: Vec<OwnedItem>,
    }

    struct OwnedItem {
        label: String,
        href: String,
        active: bool,
        muted: bool,
        coming_soon: bool,
    }

    let mut owned_sections = Vec::new();
    for section in nav_sections.try_iter()? {
        let heading = attr_text(&section, "heading")?.unwrap_or_default();
        let items_value = attr_value(&section, "items")?;
        let mut items = Vec::new();
        for item in items_value.try_iter()? {
            items.push(OwnedItem {
                label: attr_text(&item, "label")?.unwrap_or_default(),
                href: attr_text(&item, "href")?.unwrap_or_default(),
                active: attr_bool(&item, "active")?,
                muted: attr_bool(&item, "muted")?,
                coming_soon: attr_bool(&item, "coming_soon")?,
            });
        }
        owned_sections.push(OwnedSection { heading, items });
    }

    let item_groups = owned_sections
        .iter()
        .map(|section| {
            section
                .items
                .iter()
                .map(|owned| {
                    let mut item = SidenavItem::link(&owned.label, &owned.href);
                    if owned.active {
                        item = item.active();
                    }
                    if owned.muted {
                        item = item.muted();
                    }
                    if owned.coming_soon {
                        item = item.with_coming_soon("Coming soon");
                    }
                    item
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let sections = owned_sections
        .iter()
        .zip(item_groups.iter())
        .map(|(owned, items)| SidenavSection::new(&owned.heading, items))
        .collect::<Vec<_>>();
    let sidenav = Sidenav::new(&sections).embedded();
    safe_component_value(&sidenav, "Sidenav")
}

pub fn build_dashboard_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();

    // 1. Default browser templates (login, register, _auth_shell, _app_shell, ...).
    add_default_browser_templates(&mut env);
    env.add_function("wf_context_switcher", wf_context_switcher);
    env.add_function("wf_dashboard_sidenav", wf_dashboard_sidenav);

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
    env.add_template_owned("_partials/_user_permissions.html", USER_PERMISSIONS_PARTIAL)
        .expect("_partials/_user_permissions.html");
    env.add_template_owned("_partials/_user_sessions.html", USER_SESSIONS_PARTIAL)
        .expect("_partials/_user_sessions.html");
    env.add_template_owned("_partials/_user_audit.html", USER_AUDIT_PARTIAL)
        .expect("_partials/_user_audit.html");

    // Invite accept flow (99c.5 Step 15).
    env.add_template_owned("invite/register.html", INVITE_REGISTER_HTML)
        .expect("invite/register.html");
    env.add_template_owned("invite/accept.html", INVITE_ACCEPT_HTML)
        .expect("invite/accept.html");
    env.add_template_owned("invite/expired.html", INVITE_EXPIRED_HTML)
        .expect("invite/expired.html");

    // Team members list (99c.5 Step 13).
    env.add_template_owned("settings/team/list.html", SETTINGS_TEAM_LIST_HTML)
        .expect("settings/team/list.html");

    // Plan & billing page (99c.5 Step 12).
    env.add_template_owned("settings/billing.html", SETTINGS_BILLING_HTML)
        .expect("settings/billing.html");

    // API key management page (99c.5 Step 11).
    env.add_template_owned("settings/api_keys/list.html", SETTINGS_API_KEYS_LIST_HTML)
        .expect("settings/api_keys/list.html");

    // General settings page (99c.5 Step 10).
    env.add_template_owned("settings/general.html", SETTINGS_GENERAL_HTML)
        .expect("settings/general.html");

    // Permissions CRUD pages (99c.5 Step 9).
    env.add_template_owned("permissions/list.html", PERMISSIONS_LIST_HTML)
        .expect("permissions/list.html");
    env.add_template_owned("permissions/new.html", PERMISSIONS_NEW_HTML)
        .expect("permissions/new.html");

    // Roles CRUD pages (99c.5 Step 8).
    env.add_template_owned("_partials/_role_form.html", ROLE_FORM_PARTIAL)
        .expect("_partials/_role_form.html");
    env.add_template_owned("roles/list.html", ROLES_LIST_HTML)
        .expect("roles/list.html");
    env.add_template_owned("roles/new.html", ROLES_NEW_HTML)
        .expect("roles/new.html");
    env.add_template_owned("roles/detail.html", ROLES_DETAIL_HTML)
        .expect("roles/detail.html");

    // Coming-soon stub pages (99c.5 Step 6).
    env.add_template_owned("_partials/_coming_soon.html", COMING_SOON_PARTIAL)
        .expect("_partials/_coming_soon.html");
    env.add_template_owned("settings/webhooks.html", SETTINGS_WEBHOOKS_HTML)
        .expect("settings/webhooks.html");
    env.add_template_owned("settings/email.html", SETTINGS_EMAIL_HTML)
        .expect("settings/email.html");
    env.add_template_owned("settings/social.html", SETTINGS_SOCIAL_HTML)
        .expect("settings/social.html");
    env.add_template_owned("settings/domain.html", SETTINGS_DOMAIN_HTML)
        .expect("settings/domain.html");
    env.add_template_owned("settings/domains.html", SETTINGS_DOMAINS_HTML)
        .expect("settings/domains.html");

    // Super-admin panel (99c.6).
    env.add_template_owned("admin/overview.html", ADMIN_OVERVIEW_HTML)
        .expect("admin/overview.html");
    env.add_template_owned("admin/tenant_detail.html", ADMIN_TENANT_DETAIL_HTML)
        .expect("admin/tenant_detail.html");
    env.add_template_owned("admin/usage.html", ADMIN_USAGE_HTML)
        .expect("admin/usage.html");
    env.add_template_owned("admin/revenue.html", ADMIN_REVENUE_HTML)
        .expect("admin/revenue.html");
    env.add_template_owned("admin/health.html", ADMIN_HEALTH_HTML)
        .expect("admin/health.html");

    Arc::new(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_saas::TenantRole;

    use crate::dashboard::nav::tenant_nav_items;

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
            .render(minijinja::context! {
                nav_sections => tenant_nav_items("acme", "/t/acme/applications", TenantRole::Admin),
            })
            .expect("render dashboard shell");
        assert!(
            body.contains("wf-sidenav"),
            "dashboard shell should expose sidebar nav block"
        );
        assert!(
            body.contains(r#"aria-label="Dashboard navigation""#),
            "dashboard shell should label sidenav"
        );
        assert!(
            body.contains(r#"<div class="wf-sidenav""#),
            "dashboard shell should embed the sidenav inside the app-shell nav landmark"
        );
        assert!(
            !body.contains(r#"<nav class="wf-sidenav""#),
            "dashboard shell must not nest a sidenav landmark inside the app-shell nav landmark"
        );
        assert!(
            !body.contains("wf-sidenav-items"),
            "dashboard shell should render through wavefunk-ui sidenav component"
        );
    }

    #[test]
    fn workspace_switcher_uses_context_switcher_component() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_workspace_switcher.html")
            .expect("_workspace_switcher.html");
        let body = tmpl
            .render(minijinja::context! {
                current_tenant => minijinja::context! {
                    id => vec![1_u8; 16],
                    name => "Acme",
                    slug => "acme",
                },
                workspaces => vec![
                    minijinja::context! {
                        tenant => minijinja::context! {
                            id => vec![1_u8; 16],
                            name => "Acme",
                            slug => "acme",
                        },
                        role => "owner",
                    },
                    minijinja::context! {
                        tenant => minijinja::context! {
                            id => vec![2_u8; 16],
                            name => "Beta",
                            slug => "beta",
                        },
                        role => "viewer",
                    },
                ],
            })
            .expect("render workspace switcher");

        assert!(body.contains("wf-context-switcher"));
        assert!(body.contains(r#"aria-label="Workspace switcher""#));
        assert!(body.contains(
            r#"class="wf-context-switcher-item is-active" href="/t/acme/applications" aria-current="page""#
        ));
        assert!(body.contains(r#"class="wf-context-switcher-item" href="/t/beta/applications">"#));
        assert!(!body.contains(r#"href="/t/beta/applications" aria-current="page""#));
        assert!(body.contains(">owner<"));
        assert!(body.contains(">viewer<"));
        assert!(!body.contains("wf-workspace-switcher"));
    }

    #[test]
    fn dashboard_sidenav_preserves_active_muted_and_coming_soon_states() {
        let env = build_dashboard_env();
        let tmpl = env
            .get_template("_partials/_dashboard_shell.html")
            .expect("_dashboard_shell.html");
        let body = tmpl
            .render(minijinja::context! {
                nav_sections => tenant_nav_items(
                    "acme",
                    "/t/acme/settings/team",
                    TenantRole::Viewer,
                ),
            })
            .expect("render dashboard shell");

        assert!(body.contains(r#"class="wf-sidenav-item is-active is-muted""#));
        assert!(body.contains(r#"href="/t/acme/settings/team""#));
        assert!(body.contains(">Team<"));
        assert!(body.contains(">Coming soon<"));
        assert!(body.contains(r#"href="/t/acme/settings/webhooks""#));
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
