use std::fmt::Write as _;

use axum::response::Html;
use html_escape::encode_text as esc_text;

use allowthem_saas::TenantRole;
use allowthem_server::BrowserError;
use allowthem_server::ui::{render_component, trusted_html};
use wavefunk_ui::components::{
    ContextSwitcher, ContextSwitcherItem, HtmlAttr, Modeline, ModelineSegment, PageHeader, Sidenav,
    SidenavItem, SidenavSection,
};
use wavefunk_ui::layouts::AppShell;

use super::nav::NavSection;

const HEAD_HTML: &str = r#"<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
<script>(function(){try{var m=localStorage.getItem('allowthem:mode');if((m==='dark'||m==='light')&&!document.documentElement.hasAttribute('data-mode-locked')){document.documentElement.dataset.mode=m;}}catch(_e){}})();</script>
<style>html[data-mode-locked] [data-mode-toggle]{display:none}</style>"#;
const MODE_SCRIPT: &str = r#"<script src="/__allowthem/static/js/mode-toggle.js" defer></script>"#;
const READY_SCRIPT: &str = r#"<script>document.addEventListener("DOMContentLoaded",function(){document.dispatchEvent(new CustomEvent("wfEcho",{detail:{kind:"ok",msg:"Ready."}}));});</script>"#;

pub struct WorkspaceView<'a> {
    pub name: &'a str,
    pub slug: &'a str,
    pub role: TenantRole,
    pub active: bool,
}

pub struct DashboardShellView<'a> {
    pub title: &'a str,
    pub app_name: &'a str,
    pub brand_href: &'a str,
    pub logout_href: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub current_workspace: Option<&'a str>,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
    pub content_html: &'a str,
    pub page_title: Option<&'a str>,
    pub main_class: &'a str,
}

pub struct SuspendedPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub logout_href: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

fn render<T>(component: &T) -> Result<String, BrowserError>
where
    T: wavefunk_ui::Template + ?Sized,
{
    Ok(render_component(component)?.into_string())
}

fn role_label(role: TenantRole) -> &'static str {
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

fn dashboard_nav(view: &DashboardShellView<'_>) -> Result<String, BrowserError> {
    let mut nav = workspace_switcher(
        view.workspaces,
        view.current_workspace.unwrap_or(view.app_name),
    )?;
    let side_item_groups: Vec<Vec<SidenavItem<'_>>> = view
        .nav_sections
        .iter()
        .map(|section| {
            section
                .items
                .iter()
                .map(|item| {
                    let mut sidenav_item = SidenavItem::link(item.label, item.href.as_str());
                    if item.active {
                        sidenav_item = sidenav_item.active();
                    }
                    if item.muted {
                        sidenav_item = sidenav_item.muted();
                    }
                    if item.coming_soon {
                        sidenav_item = sidenav_item.with_coming_soon("Coming soon");
                    }
                    sidenav_item
                })
                .collect()
        })
        .collect();
    let side_sections: Vec<SidenavSection<'_>> = view
        .nav_sections
        .iter()
        .zip(side_item_groups.iter())
        .map(|(section, items)| SidenavSection::new(section.heading, items))
        .collect();
    nav.push_str(&render(&Sidenav::new(&side_sections).embedded())?);
    Ok(nav)
}

fn workspace_switcher(
    workspaces: &[WorkspaceView<'_>],
    current: &str,
) -> Result<String, BrowserError> {
    if workspaces.is_empty() {
        return Ok(String::new());
    }
    let hrefs: Vec<String> = workspaces
        .iter()
        .map(|workspace| format!("/t/{}/applications", workspace.slug))
        .collect();
    let items: Vec<ContextSwitcherItem<'_>> = workspaces
        .iter()
        .zip(hrefs.iter())
        .map(|(workspace, href)| {
            let mut item = ContextSwitcherItem::link(workspace.name, href)
                .with_meta(role_label(workspace.role));
            if workspace.active {
                item = item.active();
            }
            item
        })
        .collect();
    render(
        &ContextSwitcher::new("Workspace", current, &items)
            .with_attrs(&[HtmlAttr::new("aria-label", "Workspace switcher")]),
    )
}

fn modeline_html(
    is_production: bool,
    session: Option<&str>,
    logout_href: &str,
) -> Result<String, BrowserError> {
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
        right.push(ModelineSegment::link("⏻", logout_href).with_attrs(&logout_attrs));
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
    let modeline = render(
        &Modeline::new(&left)
            .with_right(&right)
            .with_attrs(&modeline_attrs),
    )?;
    let minibuffer = render(&wavefunk_ui::components::Minibuffer::new())?;
    Ok(format!("{modeline}{minibuffer}{READY_SCRIPT}"))
}

pub fn dashboard_page(view: &DashboardShellView<'_>) -> Result<Html<String>, BrowserError> {
    let nav = dashboard_nav(view)?;
    let footer = modeline_html(view.is_production, view.status_session, view.logout_href)?;
    let page_header = match view.page_title {
        Some(title) if !title.is_empty() => Some(render(&PageHeader::new(title))?),
        _ => None,
    };
    let mut shell = AppShell::new(view.title, view.app_name, view.content_html)
        .with_brand_href(view.brand_href)
        .with_nav(&nav)
        .with_nav_aria_label("Dashboard navigation")
        .with_head(trusted_html(HEAD_HTML))
        .with_scripts(trusted_html(MODE_SCRIPT))
        .with_footer(trusted_html(&footer))
        .with_main_class(view.main_class)
        .without_body_hx_boost();
    if let Some(page_header) = page_header.as_deref() {
        shell = shell.with_page_header(trusted_html(page_header));
    }
    Ok(Html(render(&shell)?))
}

pub fn suspended_page(view: &SuspendedPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    write!(
        content,
        r#"<div class="wf-panel wf-pad-5" style="text-align:center; max-width:48rem; margin:4rem auto;"><h1>Workspace suspended</h1><p class="wf-mt-3">The workspace <strong>{}</strong> can't be managed right now.</p><p class="wf-mt-3">Contact <a class="wf-link" href="mailto:support@allowthem.io">support@allowthem.io</a> for help.</p></div>"#,
        esc_text(view.tenant_name),
    )
    .unwrap();
    let brand_href = format!("/t/{}/applications", view.tenant_slug);
    dashboard_page(&DashboardShellView {
        title: "Workspace suspended",
        app_name: "allowthem",
        brand_href: &brand_href,
        logout_href: view.logout_href,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        current_workspace: Some(view.tenant_name),
        status_session: view.status_session,
        is_production: view.is_production,
        content_html: &content,
        page_title: None,
        main_class: "",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::nav::tenant_nav_items;

    fn workspaces<'a>() -> [WorkspaceView<'a>; 2] {
        [
            WorkspaceView {
                name: "Acme",
                slug: "acme",
                role: TenantRole::Owner,
                active: true,
            },
            WorkspaceView {
                name: "Beta",
                slug: "beta",
                role: TenantRole::Viewer,
                active: false,
            },
        ]
    }

    #[test]
    fn dashboard_page_renders_context_switcher_sidenav_and_modeline() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/team", TenantRole::Viewer);
        let workspaces = workspaces();
        let html = dashboard_page(&DashboardShellView {
            title: "Dashboard",
            app_name: "allowthem",
            brand_href: "/t/acme/applications",
            logout_href: "/t/acme/logout",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            current_workspace: Some("Acme"),
            status_session: Some("viewer@example.com"),
            is_production: false,
            content_html: r#"<section>Body</section>"#,
            page_title: Some("Settings"),
            main_class: "has-header",
        })
        .expect("render dashboard page")
        .0;

        assert!(html.contains(r#"aria-label="Dashboard navigation""#));
        assert!(html.contains(r#"<div class="wf-sidenav""#));
        assert!(!html.contains(r#"<nav class="wf-sidenav""#));
        assert!(html.contains(r#"class="wf-context-switcher-item is-active" href="/t/acme/applications" aria-current="page""#));
        assert!(html.contains(r#"class="wf-context-switcher-item" href="/t/beta/applications">"#));
        assert!(html.contains(">owner<"));
        assert!(html.contains(">viewer<"));
        assert!(html.contains(
            r#"class="wf-sidenav-item is-active is-muted" href="/t/acme/settings/team""#
        ));
        assert!(html.contains(r#"href="/t/acme/logout""#));
        assert!(html.contains(r#"data-mode-toggle"#));
    }

    #[test]
    fn suspended_page_renders_shell_and_copy() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/applications", TenantRole::Owner);
        let workspaces = workspaces();
        let html = suspended_page(&SuspendedPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            logout_href: "/t/acme/logout",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            status_session: Some("owner@acme.com"),
            is_production: false,
        })
        .expect("render suspended page")
        .0;

        assert!(html.contains("Workspace suspended"));
        assert!(html.contains("The workspace <strong>Acme</strong>"));
        assert!(html.contains("support@allowthem.io"));
        assert!(html.contains(r#"class="wf-context-switcher-item is-active" href="/t/acme/applications" aria-current="page""#));
    }
}
