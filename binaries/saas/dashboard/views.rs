use std::fmt::Write as _;

use axum::response::Html;
use chrono::{DateTime, Utc};
use html_escape::{encode_double_quoted_attribute as esc_attr, encode_text as esc_text};

use allowthem_core::applications::Application;
use allowthem_core::audit::{AuditEvent, AuditListEntry};
use allowthem_core::sessions::SessionListEntry;
use allowthem_core::types::{ClientType, Permission, Role, User};
use allowthem_core::users::UserListEntry;
use allowthem_saas::{DomainStatus, TenantRole};
use allowthem_server::BrowserError;
use allowthem_server::ui::{render_component, trusted_html};
use wavefunk_ui::components::{
    Alert, Badge, Button, ButtonSize, ButtonVariant, CheckRow, CodeBlock, CodeGrid,
    ContextSwitcher, ContextSwitcherItem, CopyableValue, CredentialStatusItem,
    CredentialStatusList, DataTable, DataTableCell, DataTableHeader, DataTableRow, FeedbackKind,
    Field, FilterBar, Form, FormActions, FormPanel, FormSection, HtmlAttr, Input, Modeline,
    ModelineSegment, PageHeader, PageLink, Pagination, Panel, RepeatableArray, RepeatableItem,
    SecretValue, Select, SelectOption, SettingsSection, Sidenav, SidenavItem, SidenavSection,
    SnippetTab, SnippetTabs, SplitShell, TableColumnWidth, TableFooter, TableWrap, Tag,
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

pub struct SignupPageView<'a> {
    pub csrf_token: &'a str,
    pub email: &'a str,
    pub tenant_name: &'a str,
    pub slug: &'a str,
    pub error: Option<&'a str>,
    pub is_production: bool,
}

pub struct QuickstartSnippetView<'a> {
    pub label: &'a str,
    pub code: &'a str,
    pub language: &'a str,
    pub active: bool,
}

pub struct QuickstartPageView<'a> {
    pub csrf_token: &'a str,
    pub token: &'a str,
    pub slug: &'a str,
    pub issuer: &'a str,
    pub base_domain: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub redirect_uri: &'a str,
    pub snippets: &'a [QuickstartSnippetView<'a>],
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

#[derive(Clone, Copy)]
pub struct InviteTenantView<'a> {
    pub name: &'a str,
    pub slug: &'a str,
}

pub struct InviteRegisterPageView<'a> {
    pub tenant: InviteTenantView<'a>,
    pub email: &'a str,
    pub role: &'a str,
    pub token: &'a str,
    pub error: Option<&'a str>,
    pub csrf_token: &'a str,
    pub is_production: bool,
}

pub struct InviteAcceptPageView<'a> {
    pub tenant: InviteTenantView<'a>,
    pub email: &'a str,
    pub role: &'a str,
    pub token: &'a str,
    pub csrf_token: &'a str,
    pub is_production: bool,
}

pub struct InviteWrongUserPageView<'a> {
    pub signed_in_email: &'a str,
    pub invite_email: &'a str,
    pub token: &'a str,
    pub is_production: bool,
}

pub struct ApplicationListPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub applications: &'a [Application],
    pub csrf_token: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct ApplicationDetailPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub app: &'a Application,
    pub redirect_uris: &'a [String],
    pub connected_users: u64,
    pub csrf_token: &'a str,
    pub client_secret: Option<&'a str>,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct ApplicationNewPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub name: &'a str,
    pub client_type: &'a str,
    pub redirect_uris: &'a [String],
    pub logo_url: &'a str,
    pub error: Option<&'a str>,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct ApplicationEditPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub app: &'a Application,
    pub redirect_uris: &'a [String],
    pub csrf_token: &'a str,
    pub error: Option<&'a str>,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct UserListPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub users: &'a [UserListEntry],
    pub total: u32,
    pub page: u32,
    pub total_pages: u32,
    pub q: &'a str,
    pub status: &'a str,
    pub mfa: &'a str,
    pub verified: &'a str,
    pub has_filters: bool,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct UserDetailPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub user: &'a User,
    pub roles: &'a [Role],
    pub direct_permissions: &'a [Permission],
    pub mfa_enabled: bool,
    pub sessions: &'a [SessionListEntry],
    pub last_login: Option<&'a str>,
    pub audit_entries: &'a [AuditListEntry],
    pub all_roles: &'a [Role],
    pub all_permissions: &'a [Permission],
    pub csrf_token: &'a str,
    pub flash_info: &'a str,
    pub flash_error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct AuditListPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub entries: &'a [AuditListEntry],
    pub total: u32,
    pub page: u32,
    pub total_pages: u32,
    pub event_type: &'a str,
    pub user_email: &'a str,
    pub outcome: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub has_filters: bool,
    pub no_user: bool,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct RoleListItemView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub permission_count: usize,
}

pub struct RoleListPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub roles: &'a [RoleListItemView],
    pub csrf_token: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct RoleNewPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct RolePermissionOptionView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub assigned: bool,
}

pub struct RoleDetailPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub actor_role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub role_id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub permissions: &'a [RolePermissionOptionView],
    pub csrf_token: &'a str,
    pub error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct PermissionListPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub permissions: &'a [Permission],
    pub csrf_token: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct PermissionNewPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct TeamMemberView {
    pub id: String,
    pub email: String,
    pub role: TenantRole,
    pub accepted: bool,
    pub invited_at: String,
    pub accepted_at: Option<String>,
}

pub struct TeamSettingsPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub members: &'a [TeamMemberView],
    pub invite_error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct ApiKeyView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

pub struct ApiKeySettingsPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub keys: &'a [ApiKeyView],
    pub new_key_secret: Option<&'a str>,
    pub error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct BillingPlanView {
    pub name: String,
    pub mau_limit: i64,
    pub price_cents: i64,
}

pub struct BillingUsageView {
    pub period: String,
    pub mau_count: i64,
    pub limit_reached_at: Option<String>,
}

pub struct BillingSettingsPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub plan: Option<&'a BillingPlanView>,
    pub current_usage: i64,
    pub usage: &'a [BillingUsageView],
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct DomainEntryView {
    pub id: String,
    pub domain: String,
    pub status: DomainStatus,
    pub status_label: &'static str,
    pub verified_at: Option<String>,
    pub last_error: Option<String>,
}

pub struct DomainSettingsPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub domains: &'a [DomainEntryView],
    pub dns_target: &'a str,
    pub error: &'a str,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct GeneralSettingsPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub role: TenantRole,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub csrf_token: &'a str,
    pub error: &'a str,
    pub saved: bool,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

pub struct ComingSoonPageView<'a> {
    pub tenant_name: &'a str,
    pub tenant_slug: &'a str,
    pub nav_sections: &'a [NavSection],
    pub workspaces: &'a [WorkspaceView<'a>],
    pub title: &'a str,
    pub epic_ref: &'a str,
    pub description: &'a str,
    pub wireframe: Option<&'a str>,
    pub status_session: Option<&'a str>,
    pub is_production: bool,
}

fn render<T>(component: &T) -> Result<String, BrowserError>
where
    T: wavefunk_ui::Template + ?Sized,
{
    Ok(render_component(component)?.into_string())
}

fn text(value: &str) -> String {
    esc_text(value).into_owned()
}

fn attr(value: &str) -> String {
    esc_attr(value).into_owned()
}

fn url_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn hidden_input(name: &str, value: &str) -> String {
    format!(
        r#"<input type="hidden" name="{}" value="{}">"#,
        attr(name),
        attr(value)
    )
}

fn field(label: &str, control: &Input<'_>, hint: Option<&str>) -> Result<String, BrowserError> {
    let control = render(control)?;
    let mut field = Field::new(label, trusted_html(&control));
    if let Some(hint) = hint {
        field = field.with_hint(hint);
    }
    render(&field)
}

fn alert(kind: FeedbackKind, message: &str) -> Result<String, BrowserError> {
    render(&Alert::new(kind, message))
}

fn submit_button(label: &str) -> Result<String, BrowserError> {
    render(
        &Button::primary(label)
            .with_button_type("submit")
            .with_size(ButtonSize::Large),
    )
}

fn auth_main(kicker: &str, panel_html: &str) -> String {
    format!(
        r#"<main class="wf-auth-form"><div class="wf-auth-top"><p class="wf-kicker">{}</p></div><div class="wf-auth-wrap">{panel_html}</div></main>"#,
        text(kicker)
    )
}

fn auth_visual(section: &str) -> String {
    format!(
        r#"<div class="wf-auth-splash"><pre class="wf-auth-ascii" aria-hidden="true">allowthem</pre><blockquote class="wf-auth-quote"><p>{}</p><p class="attr">Wave Funk authentication</p></blockquote></div>"#,
        text(section)
    )
}

fn auth_page(
    title: &str,
    section: &str,
    main_html: &str,
    is_production: bool,
) -> Result<Html<String>, BrowserError> {
    let visual = auth_visual(section);
    let footer = modeline_html(is_production, None, "/logout")?;
    let shell = render(
        &SplitShell::new(trusted_html(main_html))
            .with_visual(trusted_html(&visual))
            .with_footer(trusted_html(&footer)),
    )?;
    Ok(Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title>{}{}<style>.wf-split-shell-visual{{position:relative;overflow:hidden}}.wf-split-shell-main>.wf-auth-form{{padding:0}}.wf-split-shell-footer{{display:block}}.wf-split-shell-footer>.wf-modeline,.wf-split-shell-footer>.wf-minibuffer{{width:100%}}</style></head><body>{}<script src="/static/wavefunk/js/htmx.min.js" defer></script><script src="/static/wavefunk/js/wavefunk.js" defer></script>{}<script src="/__allowthem/static/js/shader-ascii.js" defer></script></body></html>"#,
        text(title),
        HEAD_HTML,
        wavefunk_ui::html::stylesheet_link("/static/wavefunk"),
        shell,
        MODE_SCRIPT,
    )))
}

fn simple_app_page(
    title: &str,
    content_html: &str,
    status_session: Option<&str>,
    is_production: bool,
) -> Result<Html<String>, BrowserError> {
    let footer = modeline_html(is_production, status_session, "/logout")?;
    let shell = AppShell::new(title, "allowthem", content_html)
        .with_brand_href("/")
        .with_head(trusted_html(HEAD_HTML))
        .with_scripts(trusted_html(MODE_SCRIPT))
        .with_footer(trusted_html(&footer))
        .without_body_hx_boost();
    Ok(Html(render(&shell)?))
}

fn datefmt(dt: &DateTime<Utc>) -> String {
    dt.format("%b %d, %Y %l:%M %p").to_string()
}

fn can_manage(role: TenantRole) -> bool {
    matches!(role, TenantRole::Owner | TenantRole::Admin)
}

struct TenantDashboardPage<'a> {
    tenant_name: &'a str,
    tenant_slug: &'a str,
    nav_sections: &'a [NavSection],
    workspaces: &'a [WorkspaceView<'a>],
    status_session: Option<&'a str>,
    is_production: bool,
    title: &'a str,
    page_title: &'a str,
    content_html: &'a str,
}

fn tenant_dashboard_page(view: TenantDashboardPage<'_>) -> Result<Html<String>, BrowserError> {
    let brand_href = format!("/t/{}/applications", view.tenant_slug);
    let logout_href = format!("/t/{}/logout", view.tenant_slug);
    dashboard_page(&DashboardShellView {
        title: view.title,
        app_name: "allowthem",
        brand_href: &brand_href,
        logout_href: &logout_href,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        current_workspace: Some(view.tenant_name),
        status_session: view.status_session,
        is_production: view.is_production,
        content_html: view.content_html,
        page_title: Some(view.page_title),
        main_class: "has-header",
    })
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

pub fn signup_page(view: &SignupPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut body = String::new();
    if let Some(error) = view.error.filter(|error| !error.is_empty()) {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert(FeedbackKind::Error, error)?
        )
        .unwrap();
    }
    body.push_str(&hidden_input("csrf_token", view.csrf_token));
    let email_attrs = [
        HtmlAttr::new("id", "email"),
        HtmlAttr::new("autocomplete", "email"),
    ];
    let password_attrs = [
        HtmlAttr::new("id", "password"),
        HtmlAttr::new("minlength", "8"),
        HtmlAttr::new("autocomplete", "new-password"),
    ];
    let password_confirm_attrs = [
        HtmlAttr::new("id", "password_confirm"),
        HtmlAttr::new("minlength", "8"),
        HtmlAttr::new("autocomplete", "new-password"),
    ];
    let tenant_attrs = [
        HtmlAttr::new("id", "tenant_name"),
        HtmlAttr::new("maxlength", "80"),
    ];
    let slug_attrs = [
        HtmlAttr::new("id", "slug"),
        HtmlAttr::new("pattern", "[a-z][-a-z0-9]{2,39}"),
        HtmlAttr::new("minlength", "3"),
        HtmlAttr::new("maxlength", "40"),
        HtmlAttr::hx_get("/signup/slug-check"),
        HtmlAttr::hx_target("#slug-check"),
        HtmlAttr::hx_trigger("keyup changed delay:400ms, blur"),
    ];
    body.push_str(&field(
        "Email",
        &Input::email("email")
            .with_value(view.email)
            .with_attrs(&email_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Password",
        &Input::new("password")
            .with_type("password")
            .with_attrs(&password_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Confirm password",
        &Input::new("password_confirm")
            .with_type("password")
            .with_attrs(&password_confirm_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Workspace name",
        &Input::new("tenant_name")
            .with_value(view.tenant_name)
            .with_placeholder("Acme Inc")
            .with_attrs(&tenant_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Workspace URL",
        &Input::new("slug")
            .with_value(view.slug)
            .with_placeholder("acme")
            .with_attrs(&slug_attrs)
            .required(),
        Some("3-40 lowercase letters, digits, or `-`."),
    )?);
    body.push_str(r#"<div id="slug-check" class="wf-mt-2"></div>"#);
    body.push_str(&submit_button("Create workspace")?);
    body.push_str(
        r#"<p class="wf-auth-sub wf-mt-2">Already have an account? <a href="/login">Sign in</a>.</p>"#,
    );

    let form_attrs = [
        HtmlAttr::new("id", "signup-form"),
        HtmlAttr::new("autocomplete", "on"),
    ];
    let form = render(
        &Form::new(trusted_html(&body))
            .with_action("/signup")
            .with_attrs(&form_attrs),
    )?;
    let panel = render(
        &FormPanel::new("Create your workspace", trusted_html(&form))
            .with_subtitle("One signup, one workspace. You can add more later."),
    )?;
    let main = auth_main("Allowthem · Create workspace", &panel);
    auth_page(
        "Create your workspace - Allowthem",
        "Create workspace",
        &main,
        view.is_production,
    )
}

pub fn slug_check_ok(slug: &str) -> Html<String> {
    Html(format!(
        r#"<span class="wf-text-ok" data-slug-check="ok">&#10003; <code>{}</code> is available</span>"#,
        text(slug)
    ))
}

pub fn slug_check_err(message: &str) -> Html<String> {
    Html(format!(
        r#"<span class="wf-text-err" data-slug-check="err">&#10007; {}</span>"#,
        text(message)
    ))
}

pub fn quickstart_page(view: &QuickstartPageView<'_>) -> Result<Html<String>, BrowserError> {
    let workspace_url = render(&CopyableValue::new(
        "Workspace URL",
        "quickstart-issuer",
        view.issuer,
    ))?;
    let client_id = render(&CopyableValue::new(
        "Client ID",
        "quickstart-client-id",
        view.client_id,
    ))?;
    let secret_attrs = [HtmlAttr::new("data-testid", "quickstart-secret")];
    let client_secret = render(
        &SecretValue::new(
            "Client secret",
            "quickstart-client-secret",
            view.client_secret,
        )
        .revealed()
        .copy_raw_value()
        .with_button_label("Copy secret")
        .with_warning(
            "This is the only time you'll see this secret. Save it somewhere safe before continuing.",
        )
        .with_attrs(&secret_attrs),
    )?;
    let credentials = format!(
        r#"<section class="wf-card wf-pad-5"><h1>Your workspace is ready</h1><p class="wf-auth-sub">Save your client credentials before continuing. You won't see the client secret again.</p><div class="wf-mt-5">{workspace_url}{client_id}{client_secret}</div></section>"#
    );

    let tabs: Vec<SnippetTab<'_>> = view
        .snippets
        .iter()
        .map(|snippet| {
            let tab = SnippetTab::new(snippet.label, snippet.code).with_language(snippet.language);
            if snippet.active { tab.active() } else { tab }
        })
        .collect();
    let snippets = render(&SnippetTabs::new("quickstart-snippets", &tabs))?;
    let snippets = format!(
        r#"<section class="wf-card wf-pad-5 wf-mt-6"><h2>Integrate</h2><p class="wf-auth-sub">The <code>curl</code> flow works against any allowthem tenant today. The SDK snippets are the shape of the API; <code>@allowthem/js</code> and the standalone <code>allowthem-client</code> crate ship with Epic h6d.</p><p class="wf-auth-sub">Workspace <code>{}</code> is hosted under <code>{}</code>; the default redirect URI is <code>{}</code>.</p><div class="wf-mt-5">{snippets}</div></section>"#,
        text(view.slug),
        text(view.base_domain),
        text(view.redirect_uri),
    );

    let action = format!("/quickstart/{}/dismiss", view.token);
    let mut dismiss_body = hidden_input("csrf_token", view.csrf_token);
    dismiss_body.push_str(&submit_button("I've saved my credentials")?);
    let dismiss = render(&Form::new(trusted_html(&dismiss_body)).with_action(&action))?;
    let content = format!(
        r#"<div class="wf-quickstart">{credentials}{snippets}<div class="wf-mt-6">{dismiss}</div></div>"#
    );
    simple_app_page(
        "Quickstart - Allowthem",
        &content,
        view.status_session,
        view.is_production,
    )
}

pub fn invite_register_page(
    view: &InviteRegisterPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut body = String::new();
    write!(
        body,
        r#"<p class="wf-auth-sub">You've been invited as <strong>{}</strong>. Create a password to accept the invite.</p>"#,
        text(view.role)
    )
    .unwrap();
    if let Some(error) = view.error.filter(|error| !error.is_empty()) {
        write!(
            body,
            r#"<div class="wf-mt-4">{}</div>"#,
            alert(FeedbackKind::Error, error)?
        )
        .unwrap();
    }
    body.push_str(&hidden_input("csrf_token", view.csrf_token));
    let email_attrs = [
        HtmlAttr::new("id", "invite-email"),
        HtmlAttr::new("readonly", ""),
    ];
    let password_attrs = [
        HtmlAttr::new("id", "invite-password"),
        HtmlAttr::new("minlength", "8"),
        HtmlAttr::new("autocomplete", "new-password"),
    ];
    body.push_str(&field(
        "Email",
        &Input::email("email")
            .with_value(view.email)
            .with_attrs(&email_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Password",
        &Input::new("password")
            .with_type("password")
            .with_attrs(&password_attrs)
            .required(),
        None,
    )?);
    body.push_str(&submit_button("Create account & accept")?);
    let action = format!("/invite/{}", view.token);
    let form = render(&Form::new(trusted_html(&body)).with_action(&action))?;
    let next = url_encode(&format!("/invite/{}", view.token));
    let actions = format!(
        r#"<p class="wf-auth-sub">Already have an account? <a href="/login?next={next}">Sign in</a>.</p>"#
    );
    let panel_attrs = [HtmlAttr::new("data-tenant-slug", view.tenant.slug)];
    let panel = render(
        &FormPanel::new(&format!("Join {}", view.tenant.name), trusted_html(&form))
            .with_actions(trusted_html(&actions))
            .with_attrs(&panel_attrs),
    )?;
    let main = auth_main("Allowthem · Accept invite", &panel);
    auth_page(
        &format!("Accept invite - {}", view.tenant.name),
        "Accept invite",
        &main,
        view.is_production,
    )
}

pub fn invite_accept_page(view: &InviteAcceptPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut body = String::new();
    write!(
        body,
        r#"<p class="wf-auth-sub">Accept the invite to join as <strong>{}</strong>?</p><p class="wf-auth-sub">Signed in as {}.</p>"#,
        text(view.role),
        text(view.email)
    )
    .unwrap();
    body.push_str(&hidden_input("csrf_token", view.csrf_token));
    body.push_str(&submit_button("Accept invite")?);
    let action = format!("/invite/{}", view.token);
    let form = render(&Form::new(trusted_html(&body)).with_action(&action))?;
    let actions = r#"<p class="wf-auth-sub"><a href="/">Cancel</a></p>"#;
    let panel_attrs = [HtmlAttr::new("data-tenant-slug", view.tenant.slug)];
    let panel = render(
        &FormPanel::new(&format!("Join {}", view.tenant.name), trusted_html(&form))
            .with_actions(trusted_html(actions))
            .with_attrs(&panel_attrs),
    )?;
    let main = auth_main("Allowthem · Accept invite", &panel);
    auth_page(
        &format!("Accept invite - {}", view.tenant.name),
        "Accept invite",
        &main,
        view.is_production,
    )
}

pub fn invite_expired_page(is_production: bool) -> Result<Html<String>, BrowserError> {
    let body = r#"<p class="wf-auth-sub">This invite link has expired or has already been used. Ask the workspace owner to send a new one.</p>"#;
    let actions = r#"<p class="wf-auth-sub"><a href="/">Go home</a></p>"#;
    let panel = render(
        &FormPanel::new("Invite not found", trusted_html(body)).with_actions(trusted_html(actions)),
    )?;
    let main = auth_main("Allowthem · Invite", &panel);
    auth_page("Invite expired", "Invite", &main, is_production)
}

pub fn invite_wrong_user_page(
    view: &InviteWrongUserPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let next = url_encode(&format!("/invite/{}", view.token));
    let body = format!(
        r#"<p class="wf-auth-sub">You're signed in as <strong>{}</strong>, but this invite is for <strong>{}</strong>.</p>"#,
        text(view.signed_in_email),
        text(view.invite_email)
    );
    let actions = format!(
        r#"<p class="wf-auth-sub"><a href="/logout?next={next}">Sign out</a> and try again.</p>"#
    );
    let panel = render(
        &FormPanel::new("Use the invited account", trusted_html(&body))
            .with_actions(trusted_html(&actions)),
    )?;
    let main = auth_main("Allowthem · Invite mismatch", &panel);
    auth_page(
        "Invite mismatch",
        "Invite mismatch",
        &main,
        view.is_production,
    )
}

pub fn application_list_page(
    view: &ApplicationListPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let _csrf_token = view.csrf_token;
    let mut content = String::new();
    let action = if can_manage(view.role) {
        let href = format!("/t/{}/applications/new", view.tenant_slug);
        render(
            &Button::link("New application", &href)
                .with_variant(ButtonVariant::Primary)
                .with_size(ButtonSize::Small),
        )?
    } else {
        String::new()
    };
    write!(
        content,
        r#"<div class="wf-panel" style="margin:16px 24px 0"><div class="wf-panel-head" style="display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap;"><div class="wf-panel-title">Registered applications</div>{action}</div></div>"#
    )
    .unwrap();

    if view.applications.is_empty() {
        content.push_str(r#"<p class="wf-empty">No applications registered yet.</p>"#);
    } else {
        let headers = [
            DataTableHeader::new("Name").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Client ID").with_width(TableColumnWidth::Id),
            DataTableHeader::new("Type").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Status").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Created").with_width(TableColumnWidth::Medium),
        ];
        let links: Vec<String> = view
            .applications
            .iter()
            .map(|app| {
                format!(
                    r#"<a class="wf-link" href="/t/{}/applications/{}">{}</a>"#,
                    attr(view.tenant_slug),
                    app.id,
                    text(&app.name)
                )
            })
            .collect();
        let client_ids: Vec<String> = view
            .applications
            .iter()
            .map(|app| {
                format!(
                    r#"<code title="{}">{}</code>"#,
                    attr(app.client_id.as_str()),
                    text(app.client_id.as_str())
                )
            })
            .collect();
        let type_tags: Vec<String> = view
            .applications
            .iter()
            .map(|app| match app.client_type {
                ClientType::Public => render(&Tag::new("Public")),
                ClientType::Confidential => render(&Tag::new("Confidential")),
            })
            .collect::<Result<_, _>>()?;
        let status_tags: Vec<String> = view
            .applications
            .iter()
            .map(|app| {
                if app.is_active {
                    render(&Tag::status(FeedbackKind::Ok, "Active"))
                } else {
                    render(&Tag::new("Inactive"))
                }
            })
            .collect::<Result<_, _>>()?;
        let created: Vec<String> = view
            .applications
            .iter()
            .map(|app| datefmt(&app.created_at))
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .applications
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                vec![
                    DataTableCell::html(trusted_html(&links[idx])),
                    DataTableCell::html(trusted_html(&client_ids[idx])),
                    DataTableCell::html(trusted_html(&type_tags[idx])),
                    DataTableCell::html(trusted_html(&status_tags[idx])),
                    DataTableCell::new(created[idx].as_str()),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        content.push_str(&render(&TableWrap::new(trusted_html(&table)))?);
    }

    let title = format!("Applications - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Applications",
        content_html: &content,
    })
}

pub fn application_detail_page(
    view: &ApplicationDetailPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    if let Some(secret) = view.client_secret {
        let secret = render(
            &SecretValue::new("Client secret", "client-secret", secret)
                .revealed()
                .copy_raw_value()
                .with_warning("Save this client secret now - it won't be shown again.")
                .with_button_label("Copy secret"),
        )?;
        content.push_str(&secret);
    }

    let actions = if can_manage(view.role) {
        application_detail_actions(view)?
    } else {
        String::new()
    };
    write!(
        content,
        r#"<div class="wf-panel" style="margin:16px 24px 0"><div class="wf-panel-head" style="display:flex; align-items:center; justify-content:space-between; gap:16px;"><div class="wf-panel-title">{}</div>{actions}</div></div>"#,
        text(&view.app.name),
    )
    .unwrap();

    let type_item = match view.app.client_type {
        ClientType::Public => CredentialStatusItem::info("Type", "Public client"),
        ClientType::Confidential => CredentialStatusItem::warn("Type", "Confidential client"),
    };
    let status_item = if view.app.is_active {
        CredentialStatusItem::ok("Status", "Accepting authorization requests")
    } else {
        CredentialStatusItem::error("Status", "Blocked from authorization requests")
    };
    let connected_users = view.connected_users.to_string();
    let created = datefmt(&view.app.created_at);
    let statuses = [
        type_item,
        status_item,
        CredentialStatusItem::info("Connected users", connected_users.as_str()),
        CredentialStatusItem::info("Created", created.as_str()),
    ];
    let client_id = render(&CopyableValue::new(
        "Client ID",
        "application-client-id",
        view.app.client_id.as_str(),
    ))?;
    let status_list = render(&CredentialStatusList::new(&statuses))?;
    write!(
        content,
        r#"<div class="wf-panel-body" style="margin:0 24px;">{client_id}{status_list}"#
    )
    .unwrap();
    if view.app.client_type == ClientType::Public {
        content.push_str(
            r#"<p class="wf-caption wf-mt-3">PKCE required; no client_secret issued.</p>"#,
        );
    }
    if !view.redirect_uris.is_empty() {
        let redirect_refs: Vec<&str> = view.redirect_uris.iter().map(String::as_str).collect();
        let grid = render(&CodeGrid::new(&redirect_refs).with_label("Redirect URIs"))?;
        write!(content, r#"<div class="wf-mt-5">{grid}</div>"#).unwrap();
    }
    if let Some(logo_url) = view
        .app
        .logo_url
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        write!(
            content,
            r#"<p class="wf-mt-4"><a class="wf-link" href="{}" target="_blank" rel="noopener">{}</a></p>"#,
            attr(logo_url),
            text(logo_url)
        )
        .unwrap();
    }
    content.push_str("</div>");

    let title = format!("{} - {}", view.app.name, view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: &view.app.name,
        content_html: &content,
    })
}

fn application_detail_actions(
    view: &ApplicationDetailPageView<'_>,
) -> Result<String, BrowserError> {
    let edit_href = format!("/t/{}/applications/{}/edit", view.tenant_slug, view.app.id);
    let edit = render(&Button::link("Edit", &edit_href).with_size(ButtonSize::Small))?;
    let mut actions = format!(r#"<div class="wf-actions" style="display:flex; gap:8px;">{edit}"#);
    if view.app.client_type != ClientType::Public {
        let action = format!(
            "/t/{}/applications/{}/regenerate-secret",
            view.tenant_slug, view.app.id
        );
        let button = render(
            &Button::new("Regenerate secret")
                .with_button_type("submit")
                .with_size(ButtonSize::Small),
        )?;
        write!(
            actions,
            r#"<form method="POST" action="{}" onsubmit="return confirm('Regenerate the client secret? The current secret will stop working immediately.');">{}{button}</form>"#,
            attr(&action),
            hidden_input("csrf_token", view.csrf_token),
        )
        .unwrap();
    }
    let action = format!(
        "/t/{}/applications/{}/delete",
        view.tenant_slug, view.app.id
    );
    let button = render(
        &Button::new("Delete")
            .with_button_type("submit")
            .with_variant(ButtonVariant::Danger)
            .with_size(ButtonSize::Small),
    )?;
    write!(
        actions,
        r#"<form method="POST" action="{}" onsubmit="return confirm('Delete this application? This cannot be undone.');">{}{button}</form></div>"#,
        attr(&action),
        hidden_input("csrf_token", view.csrf_token),
    )
    .unwrap();
    Ok(actions)
}

pub fn new_application_page(
    view: &ApplicationNewPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    debug_assert!(can_manage(view.role));
    let body = application_form_body(ApplicationFormBody {
        csrf_token: view.csrf_token,
        name: view.name,
        client_type: view.client_type,
        redirect_uris: view.redirect_uris,
        logo_url: view.logo_url,
        is_edit: false,
        is_active: true,
        error: view.error,
    })?;
    let action = format!("/t/{}/applications", view.tenant_slug);
    let cancel_href = format!("/t/{}/applications", view.tenant_slug);
    let form = application_form(&body, &action, "Create application", &cancel_href)?;
    let title = format!("New application - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "New application",
        content_html: &form,
    })
}

pub fn edit_application_page(
    view: &ApplicationEditPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    debug_assert!(can_manage(view.role));
    let logo_url = view.app.logo_url.as_deref().unwrap_or("");
    let body = application_form_body(ApplicationFormBody {
        csrf_token: view.csrf_token,
        name: &view.app.name,
        client_type: match view.app.client_type {
            ClientType::Public => "public",
            ClientType::Confidential => "confidential",
        },
        redirect_uris: view.redirect_uris,
        logo_url,
        is_edit: true,
        is_active: view.app.is_active,
        error: view.error,
    })?;
    let action = format!("/t/{}/applications/{}", view.tenant_slug, view.app.id);
    let cancel_href = format!("/t/{}/applications/{}", view.tenant_slug, view.app.id);
    let form = application_form(&body, &action, "Save changes", &cancel_href)?;
    let title = format!("Edit {} - {}", view.app.name, view.tenant_name);
    let page_title = format!("Edit {}", view.app.name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: &page_title,
        content_html: &form,
    })
}

struct ApplicationFormBody<'a> {
    csrf_token: &'a str,
    name: &'a str,
    client_type: &'a str,
    redirect_uris: &'a [String],
    logo_url: &'a str,
    is_edit: bool,
    is_active: bool,
    error: Option<&'a str>,
}

fn application_form_body(view: ApplicationFormBody<'_>) -> Result<String, BrowserError> {
    let mut body = String::new();
    if let Some(error) = view.error.filter(|error| !error.is_empty()) {
        body.push_str(&alert(FeedbackKind::Warn, error)?);
    }
    let name_attrs = [HtmlAttr::new("id", "name")];
    body.push_str(&field(
        "Name",
        &Input::new("name")
            .with_type("text")
            .with_value(view.name)
            .with_attrs(&name_attrs)
            .required(),
        None,
    )?);
    if !view.is_edit {
        let confidential = render(&{
            let row = CheckRow::radio("client_type", "confidential", "Confidential");
            if view.client_type != "public" {
                row.checked()
            } else {
                row
            }
        })?;
        let public = render(&{
            let row = CheckRow::radio("client_type", "public", "Public");
            if view.client_type == "public" {
                row.checked()
            } else {
                row
            }
        })?;
        let client_type = format!(
            r#"{confidential}<p class="wf-help">Server-side apps that can keep a secret. We'll generate a <code>client_secret</code> you exchange for tokens at <code>/oauth/token</code>.</p>{public}<p class="wf-help">Browser/mobile apps that can't safely store a secret. PKCE required; no secret will be issued.</p>"#
        );
        body.push_str(&render(&FormSection::new(
            "Client type",
            trusted_html(&client_type),
        ))?);
    }

    let rows: Vec<&str> = if view.redirect_uris.is_empty() {
        vec![""]
    } else {
        view.redirect_uris.iter().map(String::as_str).collect()
    };
    let mut items = String::new();
    for (idx, uri) in rows.iter().enumerate() {
        let input = render(
            &Input::url("redirect_uris")
                .with_value(uri)
                .with_placeholder("https://app.example.com/callback"),
        )?;
        items.push_str(&render(&RepeatableItem::new(
            &format!("URI {}", idx + 1),
            trusted_html(&input),
        ))?);
    }
    let input =
        render(&Input::url("redirect_uris").with_placeholder("https://app.example.com/callback"))?;
    items.push_str(&render(&RepeatableItem::new(
        "New URI",
        trusted_html(&input),
    ))?);
    body.push_str(&render(
        &RepeatableArray::new("Redirect URIs", trusted_html(&items))
            .with_description("One URL per row. We'll redirect users back to these after sign-in."),
    )?);

    let logo_attrs = [HtmlAttr::new("id", "logo_url")];
    body.push_str(&field(
        "Logo URL (optional)",
        &Input::url("logo_url")
            .with_value(view.logo_url)
            .with_placeholder("https://example.com/logo.svg")
            .with_attrs(&logo_attrs),
        None,
    )?);
    if view.is_edit {
        let row = CheckRow::checkbox(
            "is_active",
            "on",
            "Active - when off, the app cannot start new authorization flows.",
        );
        let row = if view.is_active { row.checked() } else { row };
        body.push_str(&render(&row)?);
    }
    body.push_str(&hidden_input("csrf_token", view.csrf_token));
    Ok(body)
}

fn application_form(
    body: &str,
    action: &str,
    submit_label: &str,
    cancel_href: &str,
) -> Result<String, BrowserError> {
    let primary = submit_button(submit_label)?;
    let cancel = render(&Button::link("Cancel", cancel_href))?;
    let actions =
        render(&FormActions::new(trusted_html(&primary)).with_secondary(trusted_html(&cancel)))?;
    let body = format!("{body}{actions}");
    render(&Form::new(trusted_html(&body)).with_action(action))
}

fn field_html(label: &str, control_html: &str, hint: Option<&str>) -> Result<String, BrowserError> {
    let mut field = Field::new(label, trusted_html(control_html));
    if let Some(hint) = hint {
        field = field.with_hint(hint);
    }
    render(&field)
}

fn selected_option<'a>(value: &'a str, label: &'a str, current: &str) -> SelectOption<'a> {
    let option = SelectOption::new(value, label);
    if value == current {
        option.selected()
    } else {
        option
    }
}

fn pagination_footer(
    label: &str,
    page: u32,
    total_pages: u32,
    prev_href: &str,
    next_href: &str,
) -> Result<String, BrowserError> {
    let current = page.to_string();
    let prev = if page > 1 {
        PageLink::link("Previous", prev_href)
    } else {
        PageLink::disabled("Previous")
    };
    let next = if page < total_pages {
        PageLink::link("Next", next_href)
    } else {
        PageLink::disabled("Next")
    };
    let pages = [prev, PageLink::disabled(&current).active(), next];
    let pagination = render(&Pagination::new(&pages))?;
    let escaped_label = text(label);
    render(&TableFooter::new(trusted_html(&escaped_label)).with_actions(trusted_html(&pagination)))
}

fn filter_form(action: &str, body_html: &str) -> Result<String, BrowserError> {
    let attrs = [HtmlAttr::new(
        "style",
        "display:flex; gap:12px; flex-wrap:wrap; align-items:flex-end;",
    )];
    render(
        &Form::new(trusted_html(body_html))
            .with_action(action)
            .with_method("get")
            .with_attrs(&attrs),
    )
}

pub fn user_list_page(view: &UserListPageView<'_>) -> Result<Html<String>, BrowserError> {
    let action = format!("/t/{}/users", view.tenant_slug);
    let search = field(
        "Search",
        &Input::new("q")
            .with_type("text")
            .with_value(view.q)
            .with_placeholder("email or username"),
        None,
    )?;
    let status_options = [
        selected_option("", "Any", view.status),
        selected_option("active", "Active", view.status),
        selected_option("blocked", "Blocked", view.status),
    ];
    let status = field_html(
        "Status",
        &render(&Select::new("status", &status_options))?,
        None,
    )?;
    let mfa_options = [
        selected_option("", "Any", view.mfa),
        selected_option("yes", "Enrolled", view.mfa),
        selected_option("no", "Not enrolled", view.mfa),
    ];
    let mfa = field_html("MFA", &render(&Select::new("mfa", &mfa_options))?, None)?;
    let verified_options = [
        selected_option("", "Any", view.verified),
        selected_option("yes", "Verified", view.verified),
        selected_option("no", "Unverified", view.verified),
    ];
    let verified = field_html(
        "Email verified",
        &render(&Select::new("verified", &verified_options))?,
        None,
    )?;
    let filter_button = render(
        &Button::primary("Filter")
            .with_button_type("submit")
            .with_size(ButtonSize::Small),
    )?;
    let mut controls =
        format!("{search}{status}{mfa}{verified}<div class=\"wf-actions\">{filter_button}");
    if view.has_filters {
        let reset = render(&Button::link("Reset", &action).with_size(ButtonSize::Small))?;
        controls.push_str(&reset);
    }
    controls.push_str("</div>");
    let form = filter_form(&action, &controls)?;
    let filterbar = render(&FilterBar::new(trusted_html(&form)))?;
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let filter_panel = render(
        &Panel::new(&format!("Users ({})", view.total), trusted_html(&filterbar))
            .with_attrs(&panel_attrs),
    )?;

    let mut content = filter_panel;
    if view.users.is_empty() {
        let empty = if view.has_filters {
            "No users match these filters."
        } else {
            "No users yet."
        };
        write!(
            content,
            r#"<p class="wf-empty" style="margin:12px 24px;">{}</p>"#,
            text(empty),
        )
        .unwrap();
    } else {
        let headers = [
            DataTableHeader::new("Email").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Username").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Status").with_width(TableColumnWidth::Small),
            DataTableHeader::new("MFA").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Created").with_width(TableColumnWidth::Medium),
        ];
        let links: Vec<String> = view
            .users
            .iter()
            .map(|user| {
                format!(
                    r#"<a class="wf-link" href="/t/{}/users/{}">{}</a>"#,
                    attr(view.tenant_slug),
                    user.id,
                    text(user.email.as_str())
                )
            })
            .collect();
        let usernames: Vec<String> = view
            .users
            .iter()
            .map(|user| {
                user.username
                    .as_ref()
                    .map(|username| format!("@{}", username.as_str()))
                    .unwrap_or_else(|| "-".to_owned())
            })
            .collect();
        let statuses: Vec<String> = view
            .users
            .iter()
            .map(|user| {
                if user.is_active {
                    render(&Tag::status(FeedbackKind::Ok, "Active"))
                } else {
                    render(&Tag::status(FeedbackKind::Error, "Blocked"))
                }
            })
            .collect::<Result<_, _>>()?;
        let mfa_tags: Vec<String> = view
            .users
            .iter()
            .map(|user| {
                if user.has_mfa {
                    render(&Tag::new("Enrolled"))
                } else {
                    render(&Badge::muted("-"))
                }
            })
            .collect::<Result<_, _>>()?;
        let created: Vec<String> = view
            .users
            .iter()
            .map(|user| datefmt(&user.created_at))
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .users
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                vec![
                    DataTableCell::html(trusted_html(&links[idx])),
                    DataTableCell::new(usernames[idx].as_str()),
                    DataTableCell::html(trusted_html(&statuses[idx])),
                    DataTableCell::html(trusted_html(&mfa_tags[idx])),
                    DataTableCell::new(created[idx].as_str()),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let query = format!(
            "q={}&status={}&mfa={}&verified={}&page=",
            url_encode(view.q),
            url_encode(view.status),
            url_encode(view.mfa),
            url_encode(view.verified)
        );
        let prev_href = format!(
            "/t/{}/users?{}{}",
            view.tenant_slug,
            query,
            view.page.saturating_sub(1)
        );
        let next_href = format!("/t/{}/users?{}{}", view.tenant_slug, query, view.page + 1);
        let footer_label = format!(
            "Page {} of {} - {} users",
            view.page, view.total_pages, view.total
        );
        let footer = pagination_footer(
            &footer_label,
            view.page,
            view.total_pages,
            &prev_href,
            &next_href,
        )?;
        content.push_str(&render(
            &TableWrap::new(trusted_html(&table)).with_footer_component(trusted_html(&footer)),
        )?);
    }

    let title = format!("Users - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Users",
        content_html: &content,
    })
}

pub fn user_detail_page(view: &UserDetailPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    if !view.flash_info.is_empty() {
        write!(
            content,
            r#"<div style="margin:16px 24px 0;">{}</div>"#,
            alert(FeedbackKind::Ok, view.flash_info)?
        )
        .unwrap();
    }
    if !view.flash_error.is_empty() {
        write!(
            content,
            r#"<div style="margin:16px 24px 0;">{}</div>"#,
            alert(FeedbackKind::Error, view.flash_error)?
        )
        .unwrap();
    }

    content.push_str(&user_summary_panel(view)?);
    if can_manage(view.role) {
        content.push_str(&user_actions_panel(view)?);
    }
    content.push_str(&user_roles_panel(view)?);
    content.push_str(&user_permissions_panel(view)?);
    content.push_str(&user_sessions_panel(view)?);
    content.push_str(&user_recent_audit_panel(view)?);

    let title = format!("{} - {}", view.user.email.as_str(), view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: view.user.email.as_str(),
        content_html: &content,
    })
}

fn user_summary_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let mut body = String::from(r#"<dl class="wf-dl">"#);
    if let Some(username) = view.user.username.as_ref() {
        write!(
            body,
            r#"<div class="wf-dl-row"><dt>Username</dt><dd>@{}</dd></div>"#,
            text(username.as_str())
        )
        .unwrap();
    }
    let status = if view.user.is_active {
        render(&Tag::status(FeedbackKind::Ok, "Active"))?
    } else {
        render(&Tag::status(FeedbackKind::Error, "Blocked"))?
    };
    let email_verified = if view.user.email_verified {
        "Yes"
    } else {
        "No"
    };
    let mfa = if view.mfa_enabled {
        "Enabled"
    } else {
        "Not enabled"
    };
    let last_login = view.last_login.unwrap_or("Never");
    write!(
        body,
        r#"<div class="wf-dl-row"><dt>Status</dt><dd>{status}</dd></div><div class="wf-dl-row"><dt>Email verified</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>MFA</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>Last login</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>Registered</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>Updated</dt><dd>{}</dd></div></dl>"#,
        text(email_verified),
        text(mfa),
        text(last_login),
        text(&datefmt(&view.user.created_at)),
        text(&datefmt(&view.user.updated_at)),
    )
    .unwrap();
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new(view.user.email.as_str(), trusted_html(&body)).with_attrs(&panel_attrs))
}

fn user_action_form(action: &str, csrf_token: &str, confirm: &str, button_html: &str) -> String {
    format!(
        r#"<form method="POST" action="{}" onsubmit="return confirm('{}');">{}{button_html}</form>"#,
        attr(action),
        attr(confirm),
        hidden_input("csrf_token", csrf_token),
    )
}

fn user_actions_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let base = format!("/t/{}/users/{}", view.tenant_slug, view.user.id);
    let mut body = String::from(
        r#"<div class="wf-actions" style="display:flex; flex-wrap:wrap; gap:8px; align-items:flex-start;">"#,
    );
    if view.user.is_active {
        let button = render(
            &Button::new("Block")
                .with_variant(ButtonVariant::Danger)
                .with_size(ButtonSize::Small)
                .with_button_type("submit"),
        )?;
        body.push_str(&user_action_form(
            &format!("{base}/block"),
            view.csrf_token,
            "Block this user? Their sessions will be terminated.",
            &button,
        ));
    } else {
        let button = render(
            &Button::primary("Unblock")
                .with_size(ButtonSize::Small)
                .with_button_type("submit"),
        )?;
        body.push_str(&user_action_form(
            &format!("{base}/unblock"),
            view.csrf_token,
            "Unblock this user?",
            &button,
        ));
    }
    let reset = render(
        &Button::new("Force password reset")
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    body.push_str(&user_action_form(
        &format!("{base}/force-password-reset"),
        view.csrf_token,
        "Force a password reset for this user? Their sessions will be terminated and a reset email will be sent.",
        &reset,
    ));
    let revoke = render(
        &Button::new("Revoke all sessions")
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    body.push_str(&user_action_form(
        &format!("{base}/revoke-sessions"),
        view.csrf_token,
        "Revoke all sessions for this user?",
        &revoke,
    ));
    if view.role == TenantRole::Owner {
        let delete = render(
            &Button::new("Delete user")
                .with_variant(ButtonVariant::Danger)
                .with_size(ButtonSize::Small)
                .with_button_type("submit"),
        )?;
        let action = format!("{base}/delete");
        write!(
            body,
            r#"<form method="POST" action="{}" onsubmit="return confirm('Permanently delete this user? This cannot be undone.');">{}{}{delete}</form>"#,
            attr(&action),
            hidden_input("csrf_token", view.csrf_token),
            hidden_input("confirm", "DELETE"),
        )
        .unwrap();
    }
    body.push_str("</div>");
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new("Actions", trusted_html(&body)).with_attrs(&panel_attrs))
}

fn removable_tag(
    label: &str,
    action: &str,
    csrf_token: &str,
    confirm: &str,
) -> Result<String, BrowserError> {
    Ok(format!(
        r#"<span class="wf-tag accent">{}<form method="POST" action="{}" style="display:inline; margin-left:4px;" onsubmit="return confirm('{}');">{}<button type="submit" class="wf-tag-remove" title="Remove">&times;</button></form></span>"#,
        text(label),
        attr(action),
        attr(confirm),
        hidden_input("csrf_token", csrf_token)
    ))
}

fn user_roles_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let mut body = String::new();
    if view.roles.is_empty() {
        body.push_str(r#"<p class="wf-empty">No roles assigned.</p>"#);
    } else {
        body.push_str(
            r#"<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px;">"#,
        );
        for role in view.roles {
            if can_manage(view.role) {
                let action = format!(
                    "/t/{}/users/{}/roles/{}/remove",
                    view.tenant_slug, view.user.id, role.id
                );
                body.push_str(&removable_tag(
                    role.name.as_str(),
                    &action,
                    view.csrf_token,
                    "Remove this role?",
                )?);
            } else {
                write!(
                    body,
                    r#"<span class="wf-tag accent">{}</span>"#,
                    text(role.name.as_str())
                )
                .unwrap();
            }
        }
        body.push_str("</div>");
    }

    if can_manage(view.role) {
        if view.all_roles.is_empty() {
            body.push_str(
                r#"<p class="wf-empty" style="font-size:0.85em;">No roles defined yet.</p>"#,
            );
        } else {
            let option_values: Vec<String> = view
                .all_roles
                .iter()
                .map(|role| role.id.to_string())
                .collect();
            let options: Vec<SelectOption<'_>> = view
                .all_roles
                .iter()
                .zip(option_values.iter())
                .map(|(role, value)| SelectOption::new(value, role.name.as_str()))
                .collect();
            let select = render(&Select::new("role_id", &options))?;
            let button = render(
                &Button::primary("Assign role")
                    .with_size(ButtonSize::Small)
                    .with_button_type("submit"),
            )?;
            let action = format!("/t/{}/users/{}/roles", view.tenant_slug, view.user.id);
            let form_body = format!(
                "{}{select}{button}",
                hidden_input("csrf_token", view.csrf_token)
            );
            let attrs = [HtmlAttr::new(
                "style",
                "display:flex; gap:8px; align-items:center; margin-top:8px;",
            )];
            body.push_str(&render(
                &Form::new(trusted_html(&form_body))
                    .with_action(&action)
                    .with_attrs(&attrs),
            )?);
        }
    }

    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new("Roles", trusted_html(&body)).with_attrs(&panel_attrs))
}

fn user_permissions_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let mut body = String::new();
    if view.direct_permissions.is_empty() {
        body.push_str(r#"<p class="wf-empty">No direct permissions assigned.</p>"#);
    } else {
        body.push_str(
            r#"<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px;">"#,
        );
        for permission in view.direct_permissions {
            if can_manage(view.role) {
                let action = format!(
                    "/t/{}/users/{}/permissions/{}/remove",
                    view.tenant_slug, view.user.id, permission.id
                );
                body.push_str(&removable_tag(
                    permission.name.as_str(),
                    &action,
                    view.csrf_token,
                    "Revoke this permission?",
                )?);
            } else {
                write!(
                    body,
                    r#"<span class="wf-tag">{}</span>"#,
                    text(permission.name.as_str())
                )
                .unwrap();
            }
        }
        body.push_str("</div>");
    }

    if can_manage(view.role) {
        if view.all_permissions.is_empty() {
            body.push_str(
                r#"<p class="wf-empty" style="font-size:0.85em;">No permissions defined yet.</p>"#,
            );
        } else {
            let option_values: Vec<String> = view
                .all_permissions
                .iter()
                .map(|permission| permission.id.to_string())
                .collect();
            let options: Vec<SelectOption<'_>> = view
                .all_permissions
                .iter()
                .zip(option_values.iter())
                .map(|(permission, value)| SelectOption::new(value, permission.name.as_str()))
                .collect();
            let select = render(&Select::new("permission_id", &options))?;
            let button = render(
                &Button::primary("Grant permission")
                    .with_size(ButtonSize::Small)
                    .with_button_type("submit"),
            )?;
            let action = format!("/t/{}/users/{}/permissions", view.tenant_slug, view.user.id);
            let form_body = format!(
                "{}{select}{button}",
                hidden_input("csrf_token", view.csrf_token)
            );
            let attrs = [HtmlAttr::new(
                "style",
                "display:flex; gap:8px; align-items:center; margin-top:8px;",
            )];
            body.push_str(&render(
                &Form::new(trusted_html(&form_body))
                    .with_action(&action)
                    .with_attrs(&attrs),
            )?);
        }
    }

    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new("Direct permissions", trusted_html(&body)).with_attrs(&panel_attrs))
}

fn user_sessions_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let body = if view.sessions.is_empty() {
        r#"<p class="wf-empty" style="margin:8px 16px 12px;">No active sessions.</p>"#.to_owned()
    } else {
        let headers = [
            DataTableHeader::new("IP address").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("User agent").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Created").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Expires").with_width(TableColumnWidth::Medium),
        ];
        let ip_values: Vec<&str> = view
            .sessions
            .iter()
            .map(|session| session.ip_address.as_deref().unwrap_or("Unknown"))
            .collect();
        let agent_values: Vec<&str> = view
            .sessions
            .iter()
            .map(|session| session.user_agent.as_deref().unwrap_or("Unknown"))
            .collect();
        let created: Vec<String> = view
            .sessions
            .iter()
            .map(|session| datefmt(&session.created_at))
            .collect();
        let expires: Vec<String> = view
            .sessions
            .iter()
            .map(|session| datefmt(&session.expires_at))
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .sessions
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                vec![
                    DataTableCell::new(ip_values[idx]),
                    DataTableCell::new(agent_values[idx]),
                    DataTableCell::new(created[idx].as_str()),
                    DataTableCell::new(expires[idx].as_str()),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows))?;
        render(&TableWrap::new(trusted_html(&table)))?
    };
    let title = format!("Active sessions ({})", view.sessions.len());
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new(&title, trusted_html(&body)).with_attrs(&panel_attrs))
}

fn user_recent_audit_panel(view: &UserDetailPageView<'_>) -> Result<String, BrowserError> {
    let body = if view.audit_entries.is_empty() {
        r#"<p class="wf-empty" style="margin:8px 16px 12px;">No audit events recorded.</p>"#
            .to_owned()
    } else {
        let headers = [
            DataTableHeader::new("Event").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("IP").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Detail").with_width(TableColumnWidth::Large),
            DataTableHeader::new("When").with_width(TableColumnWidth::Medium),
        ];
        let labels: Vec<&str> = view
            .audit_entries
            .iter()
            .map(|entry| audit_event_label(&entry.event_type))
            .collect();
        let ips: Vec<&str> = view
            .audit_entries
            .iter()
            .map(|entry| entry.ip_address.as_deref().unwrap_or("-"))
            .collect();
        let details: Vec<&str> = view
            .audit_entries
            .iter()
            .map(|entry| entry.detail.as_deref().unwrap_or("-"))
            .collect();
        let created: Vec<String> = view
            .audit_entries
            .iter()
            .map(|entry| datefmt(&entry.created_at))
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .audit_entries
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                vec![
                    DataTableCell::new(labels[idx]),
                    DataTableCell::new(ips[idx]),
                    DataTableCell::new(details[idx]),
                    DataTableCell::new(created[idx].as_str()),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows))?;
        let wrapped = render(&TableWrap::new(trusted_html(&table)))?;
        format!(
            r#"{wrapped}<p style="padding:4px 16px 8px; font-size:0.85em; color:var(--wf-muted);">Showing last {} events. <a class="wf-link" href="/t/{}/audit">View full audit log &rarr;</a></p>"#,
            view.audit_entries.len(),
            attr(view.tenant_slug)
        )
    };
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new("Recent activity", trusted_html(&body)).with_attrs(&panel_attrs))
}

pub fn audit_list_page(view: &AuditListPageView<'_>) -> Result<Html<String>, BrowserError> {
    let action = format!("/t/{}/audit", view.tenant_slug);
    let event_options = [
        selected_option("", "Any", view.event_type),
        selected_option("login", "Login", view.event_type),
        selected_option("login_failed", "Login failed", view.event_type),
        selected_option("logout", "Logout", view.event_type),
        selected_option("register", "Register", view.event_type),
        selected_option("password_change", "Password change", view.event_type),
        selected_option("password_reset", "Password reset", view.event_type),
        selected_option("session_created", "Session created", view.event_type),
        selected_option("session_expired", "Session expired", view.event_type),
        selected_option("user_updated", "User updated", view.event_type),
        selected_option("user_deleted", "User deleted", view.event_type),
        selected_option("mfa_enabled", "MFA enabled", view.event_type),
        selected_option("mfa_disabled", "MFA disabled", view.event_type),
        selected_option("mfa_challenge_success", "MFA challenge OK", view.event_type),
        selected_option(
            "mfa_challenge_failed",
            "MFA challenge failed",
            view.event_type,
        ),
    ];
    let outcome_options = [
        selected_option("", "Any", view.outcome),
        selected_option("success", "Success", view.outcome),
        selected_option("failure", "Failure", view.outcome),
    ];
    let event = field_html(
        "Event",
        &render(&Select::new("event_type", &event_options))?,
        None,
    )?;
    let user_email = field(
        "User email",
        &Input::new("user_email")
            .with_type("text")
            .with_value(view.user_email)
            .with_placeholder("exact match"),
        None,
    )?;
    let outcome = field_html(
        "Outcome",
        &render(&Select::new("outcome", &outcome_options))?,
        None,
    )?;
    let from = field(
        "From",
        &Input::new("from").with_type("date").with_value(view.from),
        None,
    )?;
    let to = field(
        "To",
        &Input::new("to").with_type("date").with_value(view.to),
        None,
    )?;
    let filter_button = render(
        &Button::primary("Filter")
            .with_button_type("submit")
            .with_size(ButtonSize::Small),
    )?;
    let export_href = format!(
        "/t/{}/audit/export.csv?event_type={}&user_email={}&outcome={}&from={}&to={}",
        view.tenant_slug,
        url_encode(view.event_type),
        url_encode(view.user_email),
        url_encode(view.outcome),
        url_encode(view.from),
        url_encode(view.to)
    );
    let export = render(&Button::link("Export CSV", &export_href).with_size(ButtonSize::Small))?;
    let mut controls =
        format!("{event}{user_email}{outcome}{from}{to}<div class=\"wf-actions\">{filter_button}");
    if view.has_filters {
        let reset = render(&Button::link("Reset", &action).with_size(ButtonSize::Small))?;
        controls.push_str(&reset);
    }
    controls.push_str(&export);
    controls.push_str("</div>");
    let form = filter_form(&action, &controls)?;
    let filterbar = render(&FilterBar::new(trusted_html(&form)))?;
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let mut content =
        render(&Panel::new("Audit log", trusted_html(&filterbar)).with_attrs(&panel_attrs))?;
    if view.no_user {
        write!(
            content,
            r#"<p class="wf-flash" style="margin:12px 24px;">{}</p>"#,
            text("No user found with that email. Showing zero results.")
        )
        .unwrap();
    }

    if view.entries.is_empty() {
        if !view.no_user {
            content.push_str(
                r#"<p class="wf-empty" style="margin:12px 24px;">No audit entries match.</p>"#,
            );
        }
    } else {
        let headers = [
            DataTableHeader::new("Time").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Event").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("User").with_width(TableColumnWidth::Large),
            DataTableHeader::new("IP").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Detail").with_width(TableColumnWidth::Large),
        ];
        let times: Vec<String> = view
            .entries
            .iter()
            .map(|entry| {
                format!(
                    r#"<time datetime="{}">{}</time>"#,
                    attr(
                        &entry
                            .created_at
                            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                            .to_string()
                    ),
                    text(&entry.created_at.format("%Y-%m-%d %H:%M:%S").to_string())
                )
            })
            .collect();
        let events: Vec<String> = view
            .entries
            .iter()
            .map(|entry| {
                let label = audit_event_label(&entry.event_type);
                if audit_event_is_failure(&entry.event_type) {
                    render(&Tag::status(FeedbackKind::Error, label))
                } else {
                    render(&Tag::new(label))
                }
            })
            .collect::<Result<_, _>>()?;
        let users: Vec<String> = view
            .entries
            .iter()
            .map(|entry| {
                if let Some(email) = entry.user_email.as_deref() {
                    text(email)
                } else if let Some(user_id) = entry.user_id {
                    format!(r#"<code title="{}">{}</code>"#, user_id, user_id)
                } else {
                    render(&Badge::muted("-")).unwrap_or_else(|_| "-".to_owned())
                }
            })
            .collect();
        let ips: Vec<String> = view
            .entries
            .iter()
            .map(|entry| text(entry.ip_address.as_deref().unwrap_or("-")))
            .collect();
        let details: Vec<String> = view
            .entries
            .iter()
            .map(|entry| {
                entry
                    .detail
                    .as_deref()
                    .map(|detail| format!(r#"<code class="wf-detail">{}</code>"#, text(detail)))
                    .unwrap_or_else(|| "-".to_owned())
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .entries
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                vec![
                    DataTableCell::html(trusted_html(&times[idx])),
                    DataTableCell::html(trusted_html(&events[idx])),
                    DataTableCell::html(trusted_html(&users[idx])),
                    DataTableCell::html(trusted_html(&ips[idx])),
                    DataTableCell::html(trusted_html(&details[idx])),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let query = format!(
            "event_type={}&user_email={}&outcome={}&from={}&to={}&page=",
            url_encode(view.event_type),
            url_encode(view.user_email),
            url_encode(view.outcome),
            url_encode(view.from),
            url_encode(view.to)
        );
        let prev_href = format!(
            "/t/{}/audit?{}{}",
            view.tenant_slug,
            query,
            view.page.saturating_sub(1)
        );
        let next_href = format!("/t/{}/audit?{}{}", view.tenant_slug, query, view.page + 1);
        let footer_label = format!(
            "Page {} of {} - {} entries",
            view.page, view.total_pages, view.total
        );
        let footer = pagination_footer(
            &footer_label,
            view.page,
            view.total_pages,
            &prev_href,
            &next_href,
        )?;
        content.push_str(&render(
            &TableWrap::new(trusted_html(&table)).with_footer_component(trusted_html(&footer)),
        )?);
    }

    let title = format!("Audit log - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Audit log",
        content_html: &content,
    })
}

pub fn role_list_page(view: &RoleListPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    let action = if can_manage(view.role) {
        let href = format!("/t/{}/roles/new", view.tenant_slug);
        Some(render(
            &Button::primary("+ New role")
                .with_href(&href)
                .with_size(ButtonSize::Small),
        )?)
    } else {
        None
    };
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let empty_body = "";
    let panel_title = format!("Roles ({})", view.roles.len());
    let mut panel = Panel::new(&panel_title, trusted_html(empty_body)).with_attrs(&panel_attrs);
    if let Some(action) = action.as_deref() {
        panel = panel.with_action(trusted_html(action));
    }
    content.push_str(&render(&panel)?);

    if view.roles.is_empty() {
        content.push_str(r#"<p class="wf-empty" style="margin:12px 24px;">No roles yet.</p>"#);
    } else {
        let mut headers = vec![
            DataTableHeader::new("Name").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Description").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Permissions").with_width(TableColumnWidth::Small),
        ];
        if can_manage(view.role) {
            headers.push(DataTableHeader::new("Actions").action_column());
        }
        let links: Vec<String> = view
            .roles
            .iter()
            .map(|role| {
                format!(
                    r#"<a class="wf-link" href="/t/{}/roles/{}">{}</a>"#,
                    attr(view.tenant_slug),
                    attr(&role.id),
                    text(&role.name)
                )
            })
            .collect();
        let descriptions: Vec<String> = view
            .roles
            .iter()
            .map(|role| role.description.clone().unwrap_or_else(|| "-".to_owned()))
            .collect();
        let counts: Vec<String> = view
            .roles
            .iter()
            .map(|role| role.permission_count.to_string())
            .collect();
        let actions: Vec<String> = view
            .roles
            .iter()
            .map(|role| {
                let action = format!("/t/{}/roles/{}/delete", view.tenant_slug, role.id);
                let button = render(
                    &Button::new("Delete")
                        .with_variant(ButtonVariant::Danger)
                        .with_size(ButtonSize::Small)
                        .with_button_type("submit"),
                )?;
                Ok(format!(
                    r#"<form method="post" action="{}" style="display:inline" onsubmit="return confirm('Delete this role?');">{}{button}</form>"#,
                    attr(&action),
                    hidden_input("csrf_token", view.csrf_token),
                ))
            })
            .collect::<Result<Vec<_>, BrowserError>>()?;
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .roles
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                let mut cells = vec![
                    DataTableCell::html(trusted_html(&links[idx])),
                    DataTableCell::new(descriptions[idx].as_str()),
                    DataTableCell::numeric(counts[idx].as_str()),
                ];
                if can_manage(view.role) {
                    cells.push(DataTableCell::html(trusted_html(&actions[idx])));
                }
                cells
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        content.push_str(&render(&TableWrap::new(trusted_html(&table)))?);
    }

    let title = format!("Roles - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Roles",
        content_html: &content,
    })
}

pub fn role_new_page(view: &RoleNewPageView<'_>) -> Result<Html<String>, BrowserError> {
    let action = format!("/t/{}/roles", view.tenant_slug);
    let cancel = format!("/t/{}/roles", view.tenant_slug);
    let body = role_or_permission_form_body(RolePermissionFormBody {
        csrf_token: view.csrf_token,
        name: view.name,
        description: view.description,
        error: view.error,
        name_max_len: "80",
        name_placeholder: "e.g. editor",
        submit_label: "Create role",
        cancel_href: &cancel,
    })?;
    let form = render(
        &Form::new(trusted_html(&body))
            .with_action(&action)
            .with_attrs(&[HtmlAttr::new("style", "max-width:480px")]),
    )?;
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let content = render(&Panel::new("New Role", trusted_html(&form)).with_attrs(&panel_attrs))?;
    let title = format!("New Role - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "New Role",
        content_html: &content,
    })
}

pub fn role_detail_page(view: &RoleDetailPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    if can_manage(view.actor_role) {
        let action = format!("/t/{}/roles/{}", view.tenant_slug, view.role_id);
        let cancel = format!("/t/{}/roles", view.tenant_slug);
        let body = role_or_permission_form_body(RolePermissionFormBody {
            csrf_token: view.csrf_token,
            name: view.name,
            description: view.description,
            error: view.error,
            name_max_len: "80",
            name_placeholder: "e.g. editor",
            submit_label: "Save changes",
            cancel_href: &cancel,
        })?;
        let form = render(
            &Form::new(trusted_html(&body))
                .with_action(&action)
                .with_attrs(&[HtmlAttr::new("style", "max-width:480px")]),
        )?;
        content.push_str(&render(
            &Panel::new(view.name, trusted_html(&form)).with_attrs(&panel_attrs),
        )?);
    } else {
        let mut body = String::from(r#"<dl class="wf-dl">"#);
        write!(
            body,
            r#"<div class="wf-dl-row"><dt>Name</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>Description</dt><dd>{}</dd></div></dl>"#,
            text(view.name),
            text(if view.description.is_empty() {
                "-"
            } else {
                view.description
            })
        )
        .unwrap();
        content.push_str(&render(
            &Panel::new(view.name, trusted_html(&body)).with_attrs(&panel_attrs),
        )?);
    }
    content.push_str(&role_permissions_panel(view)?);

    let title = format!("{} - {}", view.name, view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: view.name,
        content_html: &content,
    })
}

struct RolePermissionFormBody<'a> {
    csrf_token: &'a str,
    name: &'a str,
    description: &'a str,
    error: &'a str,
    name_max_len: &'a str,
    name_placeholder: &'a str,
    submit_label: &'a str,
    cancel_href: &'a str,
}

fn role_or_permission_form_body(view: RolePermissionFormBody<'_>) -> Result<String, BrowserError> {
    let mut body = String::new();
    body.push_str(&hidden_input("csrf_token", view.csrf_token));
    if !view.error.is_empty() {
        body.push_str(&alert(FeedbackKind::Error, view.error)?);
    }
    let name_attrs = [HtmlAttr::new("maxlength", view.name_max_len)];
    body.push_str(&field(
        "Name",
        &Input::new("name")
            .with_type("text")
            .with_value(view.name)
            .with_placeholder(view.name_placeholder)
            .with_attrs(&name_attrs)
            .required(),
        None,
    )?);
    body.push_str(&field(
        "Description",
        &Input::new("description")
            .with_type("text")
            .with_value(view.description)
            .with_placeholder("Optional description"),
        None,
    )?);
    let primary = render(
        &Button::primary(view.submit_label)
            .with_button_type("submit")
            .with_size(ButtonSize::Small),
    )?;
    let cancel = render(&Button::link("Cancel", view.cancel_href))?;
    body.push_str(&render(
        &FormActions::new(trusted_html(&primary)).with_secondary(trusted_html(&cancel)),
    )?);
    Ok(body)
}

fn role_permissions_panel(view: &RoleDetailPageView<'_>) -> Result<String, BrowserError> {
    let body = if view.permissions.is_empty() {
        r#"<p class="wf-empty">No permissions defined for this tenant yet.</p>"#.to_owned()
    } else if can_manage(view.actor_role) {
        let mut rows = String::new();
        for permission in view.permissions {
            let row = CheckRow::checkbox(
                "permission_id",
                permission.id.as_str(),
                permission.name.as_str(),
            );
            let row = if permission.assigned {
                row.checked()
            } else {
                row
            };
            rows.push_str(&render(&row)?);
            if let Some(description) = permission.description.as_deref() {
                write!(
                    rows,
                    r#"<p class="wf-help" style="margin-left:28px;">{}</p>"#,
                    text(description)
                )
                .unwrap();
            }
        }
        let action = format!("/t/{}/roles/{}/permissions", view.tenant_slug, view.role_id);
        rows.push_str(&hidden_input("csrf_token", view.csrf_token));
        rows.push_str(&render(
            &Button::primary("Update permissions")
                .with_button_type("submit")
                .with_size(ButtonSize::Small),
        )?);
        render(&Form::new(trusted_html(&rows)).with_action(&action))?
    } else {
        let mut list = String::from(
            r#"<ul style="list-style:none; padding:0; margin:0; display:grid; gap:8px;">"#,
        );
        for permission in view
            .permissions
            .iter()
            .filter(|permission| permission.assigned)
        {
            let tag = render(&Tag::status(FeedbackKind::Ok, permission.name.as_str()))?;
            write!(list, "<li>{tag}").unwrap();
            if let Some(description) = permission.description.as_deref() {
                write!(
                    list,
                    r#"<span class="wf-text-muted"> - {}</span>"#,
                    text(description)
                )
                .unwrap();
            }
            list.push_str("</li>");
        }
        list.push_str("</ul>");
        list
    };
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    render(&Panel::new("Permissions", trusted_html(&body)).with_attrs(&panel_attrs))
}

pub fn permission_list_page(
    view: &PermissionListPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    let action = if can_manage(view.role) {
        let href = format!("/t/{}/permissions/new", view.tenant_slug);
        Some(render(
            &Button::primary("+ New permission")
                .with_href(&href)
                .with_size(ButtonSize::Small),
        )?)
    } else {
        None
    };
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let panel_title = format!("Permissions ({})", view.permissions.len());
    let mut panel = Panel::new(&panel_title, trusted_html("")).with_attrs(&panel_attrs);
    if let Some(action) = action.as_deref() {
        panel = panel.with_action(trusted_html(action));
    }
    content.push_str(&render(&panel)?);

    if view.permissions.is_empty() {
        content
            .push_str(r#"<p class="wf-empty" style="margin:12px 24px;">No permissions yet.</p>"#);
    } else {
        let mut headers = vec![
            DataTableHeader::new("Name").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Description").with_width(TableColumnWidth::Large),
        ];
        if can_manage(view.role) {
            headers.push(DataTableHeader::new("Actions").action_column());
        }
        let names: Vec<String> = view
            .permissions
            .iter()
            .map(|permission| format!(r#"<code>{}</code>"#, text(permission.name.as_str())))
            .collect();
        let descriptions: Vec<String> = view
            .permissions
            .iter()
            .map(|permission| {
                permission
                    .description
                    .clone()
                    .unwrap_or_else(|| "-".to_owned())
            })
            .collect();
        let actions: Vec<String> = view
            .permissions
            .iter()
            .map(|permission| {
                let action = format!(
                    "/t/{}/permissions/{}/delete",
                    view.tenant_slug, permission.id
                );
                let button = render(
                    &Button::new("Delete")
                        .with_variant(ButtonVariant::Danger)
                        .with_size(ButtonSize::Small)
                        .with_button_type("submit"),
                )?;
                Ok(format!(
                    r#"<form method="post" action="{}" style="display:inline" onsubmit="return confirm('Delete this permission?');">{}{button}</form>"#,
                    attr(&action),
                    hidden_input("csrf_token", view.csrf_token),
                ))
            })
            .collect::<Result<Vec<_>, BrowserError>>()?;
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .permissions
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                let mut cells = vec![
                    DataTableCell::html(trusted_html(&names[idx])),
                    DataTableCell::new(descriptions[idx].as_str()),
                ];
                if can_manage(view.role) {
                    cells.push(DataTableCell::html(trusted_html(&actions[idx])));
                }
                cells
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        content.push_str(&render(&TableWrap::new(trusted_html(&table)))?);
    }

    let title = format!("Permissions - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Permissions",
        content_html: &content,
    })
}

pub fn permission_new_page(view: &PermissionNewPageView<'_>) -> Result<Html<String>, BrowserError> {
    let action = format!("/t/{}/permissions", view.tenant_slug);
    let cancel = format!("/t/{}/permissions", view.tenant_slug);
    let body = role_or_permission_form_body(RolePermissionFormBody {
        csrf_token: view.csrf_token,
        name: view.name,
        description: view.description,
        error: view.error,
        name_max_len: "120",
        name_placeholder: "e.g. posts:write",
        submit_label: "Create permission",
        cancel_href: &cancel,
    })?;
    let form = render(
        &Form::new(trusted_html(&body))
            .with_action(&action)
            .with_attrs(&[HtmlAttr::new("style", "max-width:480px")]),
    )?;
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let content =
        render(&Panel::new("New Permission", trusted_html(&form)).with_attrs(&panel_attrs))?;
    let title = format!("New Permission - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "New Permission",
        content_html: &content,
    })
}

fn team_role_tag(role: TenantRole) -> Result<String, BrowserError> {
    match role {
        TenantRole::Owner => render(&Tag::status(FeedbackKind::Ok, role_label(role))),
        TenantRole::Admin => render(&Tag::status(FeedbackKind::Warn, role_label(role))),
        TenantRole::Viewer => render(&Badge::muted(role_label(role))),
    }
}

fn team_status_tag(accepted: bool) -> Result<String, BrowserError> {
    if accepted {
        render(&Tag::status(FeedbackKind::Ok, "accepted"))
    } else {
        render(&Badge::muted("invited"))
    }
}

fn team_role_options(current: TenantRole, include_owner: bool) -> Vec<SelectOption<'static>> {
    let current = role_label(current);
    let mut options = vec![
        selected_option("viewer", "viewer", current),
        selected_option("admin", "admin", current),
    ];
    if include_owner {
        options.insert(0, selected_option("owner", "owner", current));
    }
    options
}

fn team_member_actions(
    view: &TeamSettingsPageView<'_>,
    member: &TeamMemberView,
    sole_owner: bool,
) -> Result<String, BrowserError> {
    if !can_manage(view.role) {
        return Ok(String::new());
    }

    let mut actions =
        String::from(r#"<div style="display:flex; gap:8px; align-items:center; flex-wrap:wrap;">"#);
    let disabled_title = "Workspace must have at least one owner";
    if view.role == TenantRole::Owner {
        if sole_owner {
            let options = [SelectOption::new("owner", "owner").selected()];
            let attrs = [
                HtmlAttr::new("title", disabled_title),
                HtmlAttr::new("style", "opacity:0.5;cursor:not-allowed"),
            ];
            actions.push_str(&render(
                &Select::new("role", &options).with_attrs(&attrs).disabled(),
            )?);
        } else {
            let options = team_role_options(member.role, true);
            let attrs = [HtmlAttr::new("onchange", "this.form.submit()")];
            let select = render(&Select::new("role", &options).with_attrs(&attrs))?;
            let action = format!("/t/{}/settings/team/{}/role", view.tenant_slug, member.id);
            write!(
                actions,
                r#"<form method="post" action="{}" style="display:inline">{}{select}</form>"#,
                attr(&action),
                hidden_input("csrf_token", view.csrf_token)
            )
            .unwrap();
        }
    }

    if sole_owner {
        let attrs = [HtmlAttr::new("title", disabled_title)];
        actions.push_str(&render(
            &Button::new("Remove")
                .with_variant(ButtonVariant::Danger)
                .with_size(ButtonSize::Small)
                .with_button_type("button")
                .with_attrs(&attrs)
                .disabled(),
        )?);
    } else if member.role != TenantRole::Owner || view.role == TenantRole::Owner {
        let button = render(
            &Button::new("Remove")
                .with_variant(ButtonVariant::Danger)
                .with_size(ButtonSize::Small)
                .with_button_type("submit"),
        )?;
        let action = format!("/t/{}/settings/team/{}/remove", view.tenant_slug, member.id);
        write!(
            actions,
            r#"<form method="post" action="{}" style="display:inline" onsubmit="return confirm('Remove this member from this workspace?')">{}{button}</form>"#,
            attr(&action),
            hidden_input("csrf_token", view.csrf_token)
        )
        .unwrap();
    }

    actions.push_str("</div>");
    Ok(actions)
}

fn team_invite_form(view: &TeamSettingsPageView<'_>) -> Result<String, BrowserError> {
    let email_attrs = [
        HtmlAttr::new("maxlength", "254"),
        HtmlAttr::new("placeholder", "colleague@example.com"),
    ];
    let email = field(
        "Email",
        &Input::email("email").with_attrs(&email_attrs).required(),
        None,
    )?;
    let role_options = team_role_options(TenantRole::Viewer, view.role == TenantRole::Owner);
    let role = field_html("Role", &render(&Select::new("role", &role_options))?, None)?;
    let invite = render(
        &Button::primary("Invite")
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    let body = format!(
        "{}{email}{role}{invite}",
        hidden_input("csrf_token", view.csrf_token)
    );
    let action = format!("/t/{}/settings/team/invite", view.tenant_slug);
    let attrs = [HtmlAttr::new(
        "style",
        "display:flex; gap:12px; align-items:flex-end; padding:12px 16px; flex-wrap:wrap;",
    )];
    render(
        &Form::new(trusted_html(&body))
            .with_action(&action)
            .with_attrs(&attrs),
    )
}

pub fn team_settings_page(view: &TeamSettingsPageView<'_>) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    let mut panel_body = String::new();
    if can_manage(view.role) {
        panel_body.push_str(&team_invite_form(view)?);
        if !view.invite_error.is_empty() {
            write!(
                panel_body,
                r#"<div style="margin:0 16px 12px;">{}</div>"#,
                alert(FeedbackKind::Error, view.invite_error)?
            )
            .unwrap();
        }
    }
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    content.push_str(&render(
        &Panel::new("Team Members", trusted_html(&panel_body)).with_attrs(&panel_attrs),
    )?);

    if view.members.is_empty() {
        content.push_str(
            r#"<p class="wf-empty" style="margin:12px 24px;">No team members found.</p>"#,
        );
    } else {
        let owner_count = view
            .members
            .iter()
            .filter(|member| member.role == TenantRole::Owner)
            .count();
        let mut headers = vec![
            DataTableHeader::new("Email").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Role").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Status").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Invited").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Accepted").with_width(TableColumnWidth::Medium),
        ];
        if can_manage(view.role) {
            headers.push(DataTableHeader::new("Actions").action_column());
        }

        let role_tags: Vec<String> = view
            .members
            .iter()
            .map(|member| team_role_tag(member.role))
            .collect::<Result<_, _>>()?;
        let status_tags: Vec<String> = view
            .members
            .iter()
            .map(|member| team_status_tag(member.accepted))
            .collect::<Result<_, _>>()?;
        let accepted: Vec<String> = view
            .members
            .iter()
            .map(|member| member.accepted_at.clone().unwrap_or_else(|| "-".to_owned()))
            .collect();
        let actions: Vec<String> = if can_manage(view.role) {
            view.members
                .iter()
                .map(|member| {
                    team_member_actions(
                        view,
                        member,
                        member.role == TenantRole::Owner && owner_count <= 1,
                    )
                })
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .members
            .iter()
            .enumerate()
            .map(|(idx, member)| {
                let mut cells = vec![
                    DataTableCell::new(member.email.as_str()),
                    DataTableCell::html(trusted_html(&role_tags[idx])),
                    DataTableCell::html(trusted_html(&status_tags[idx])),
                    DataTableCell::new(member.invited_at.as_str()),
                    DataTableCell::new(accepted[idx].as_str()),
                ];
                if can_manage(view.role) {
                    cells.push(DataTableCell::html(trusted_html(&actions[idx])));
                }
                cells
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        content.push_str(&render(&TableWrap::new(trusted_html(&table)))?);
    }

    let title = format!("Team - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Team",
        content_html: &content,
    })
}

fn api_key_mint_form(view: &ApiKeySettingsPageView<'_>) -> Result<String, BrowserError> {
    let name_attrs = [
        HtmlAttr::new("maxlength", "80"),
        HtmlAttr::new("placeholder", "e.g. CI/CD pipeline"),
    ];
    let name = field(
        "Key name",
        &Input::new("name")
            .with_type("text")
            .with_attrs(&name_attrs)
            .required(),
        None,
    )?;
    let button = render(
        &Button::primary("Mint key")
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    let body = format!(
        "{}{name}{button}",
        hidden_input("csrf_token", view.csrf_token)
    );
    let action = format!("/t/{}/settings/api-keys", view.tenant_slug);
    let attrs = [HtmlAttr::new(
        "style",
        "display:flex; gap:12px; align-items:flex-end; padding:12px 16px; flex-wrap:wrap;",
    )];
    render(
        &Form::new(trusted_html(&body))
            .with_action(&action)
            .with_attrs(&attrs),
    )
}

fn api_key_revoke_form(
    view: &ApiKeySettingsPageView<'_>,
    key: &ApiKeyView,
) -> Result<String, BrowserError> {
    let button = render(
        &Button::new("Revoke")
            .with_variant(ButtonVariant::Danger)
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    let action = format!(
        "/t/{}/settings/api-keys/{}/revoke",
        view.tenant_slug, key.id
    );
    Ok(format!(
        r#"<form method="post" action="{}" style="display:inline" onsubmit="return confirm('Revoke this API key? This cannot be undone.')">{}{button}</form>"#,
        attr(&action),
        hidden_input("csrf_token", view.csrf_token)
    ))
}

pub fn api_key_settings_page(
    view: &ApiKeySettingsPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut content = String::new();
    if let Some(secret) = view.new_key_secret {
        let secret = render(
            &SecretValue::new("New API key", "new-api-key-secret", secret)
                .revealed()
                .copy_raw_value()
                .with_warning(
                    "This is the only time you'll see this key. Copy it now - it will not be shown again.",
                )
                .with_button_label("Copy key"),
        )?;
        write!(
            content,
            r#"<div style="margin:16px 24px 0;">{secret}</div>"#
        )
        .unwrap();
    }

    let mut panel_body = String::new();
    if can_manage(view.role) {
        panel_body.push_str(&api_key_mint_form(view)?);
        if !view.error.is_empty() {
            write!(
                panel_body,
                r#"<div style="margin:0 16px 12px;">{}</div>"#,
                alert(FeedbackKind::Error, view.error)?
            )
            .unwrap();
        }
    }
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    content.push_str(&render(
        &Panel::new("API Keys", trusted_html(&panel_body)).with_attrs(&panel_attrs),
    )?);

    if view.keys.is_empty() {
        content.push_str(r#"<p class="wf-empty" style="margin:12px 24px;">No API keys yet.</p>"#);
    } else {
        let mut headers = vec![
            DataTableHeader::new("Name").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Created").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Expires").with_width(TableColumnWidth::Medium),
        ];
        if can_manage(view.role) {
            headers.push(DataTableHeader::new("Actions").action_column());
        }
        let expires: Vec<String> = view
            .keys
            .iter()
            .map(|key| key.expires_at.clone().unwrap_or_else(|| "Never".to_owned()))
            .collect();
        let actions: Vec<String> = if can_manage(view.role) {
            view.keys
                .iter()
                .map(|key| api_key_revoke_form(view, key))
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .keys
            .iter()
            .enumerate()
            .map(|(idx, key)| {
                let mut cells = vec![
                    DataTableCell::new(key.name.as_str()),
                    DataTableCell::new(key.created_at.as_str()),
                    DataTableCell::new(expires[idx].as_str()),
                ];
                if can_manage(view.role) {
                    cells.push(DataTableCell::html(trusted_html(&actions[idx])));
                }
                cells
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        content.push_str(&render(&TableWrap::new(trusted_html(&table)))?);
    }

    let title = format!("API Keys - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "API Keys",
        content_html: &content,
    })
}

fn billing_plan_panel(view: &BillingSettingsPageView<'_>) -> Result<String, BrowserError> {
    let mut body = String::new();
    if let Some(plan) = view.plan {
        let pct = if plan.mau_limit > 0 {
            view.current_usage.saturating_mul(100) / plan.mau_limit
        } else {
            0
        };
        let pct_kind = if pct >= 90 {
            FeedbackKind::Error
        } else if pct >= 75 {
            FeedbackKind::Warn
        } else {
            FeedbackKind::Ok
        };
        let pct_tag = render(&Tag::status(pct_kind, &format!("{pct}%")))?;
        let price = if plan.price_cents == 0 {
            "Free".to_owned()
        } else {
            format!("${}/mo", plan.price_cents / 100)
        };
        write!(
            body,
            r#"<dl class="wf-dl"><div class="wf-dl-row"><dt>Plan</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>MAU this month</dt><dd>{} / {} {pct_tag}</dd></div><div class="wf-dl-row"><dt>Price</dt><dd>{}</dd></div></dl>"#,
            text(plan.name.as_str()),
            view.current_usage,
            plan.mau_limit,
            text(&price)
        )
        .unwrap();
    } else {
        body.push_str(r#"<p class="wf-empty">Plan information unavailable.</p>"#);
    }

    let actions = if view.role == TenantRole::Owner {
        let button = render(
            &Button::primary("Upgrade plan")
                .with_size(ButtonSize::Small)
                .with_button_type("submit"),
        )?;
        let action = format!("/t/{}/settings/billing/upgrade", view.tenant_slug);
        format!(
            r#"<form method="post" action="{}" style="display:inline">{}{button}</form>"#,
            attr(&action),
            hidden_input("csrf_token", view.csrf_token)
        )
    } else {
        String::new()
    };
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let mut panel = Panel::new("Plan & Usage", trusted_html(&body)).with_attrs(&panel_attrs);
    if !actions.is_empty() {
        panel = panel.with_action(trusted_html(&actions));
    }
    render(&panel)
}

pub fn billing_settings_page(
    view: &BillingSettingsPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut content = billing_plan_panel(view)?;
    if !view.usage.is_empty() {
        let headers = [
            DataTableHeader::new("Period").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("MAU").with_width(TableColumnWidth::Small),
            DataTableHeader::new("Limit reached").with_width(TableColumnWidth::Medium),
        ];
        let limit_reached: Vec<String> = view
            .usage
            .iter()
            .map(|usage| {
                usage
                    .limit_reached_at
                    .clone()
                    .unwrap_or_else(|| "-".to_owned())
            })
            .collect();
        let mau_counts: Vec<String> = view
            .usage
            .iter()
            .map(|usage| usage.mau_count.to_string())
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .usage
            .iter()
            .enumerate()
            .map(|(idx, usage)| {
                vec![
                    DataTableCell::new(usage.period.as_str()),
                    DataTableCell::numeric(mau_counts[idx].as_str()),
                    DataTableCell::new(limit_reached[idx].as_str()),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows))?;
        let table = render(&TableWrap::new(trusted_html(&table)))?;
        let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
        content.push_str(&render(
            &Panel::new("Usage history", trusted_html(&table)).with_attrs(&panel_attrs),
        )?);
    }

    let title = format!("Billing - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Billing",
        content_html: &content,
    })
}

fn domain_status_badge(domain: &DomainEntryView) -> Result<String, BrowserError> {
    match domain.status {
        DomainStatus::Failed => render(&Badge::error(domain.status_label)),
        DomainStatus::Verified | DomainStatus::Active => render(&Badge::new(domain.status_label)),
        DomainStatus::PendingVerification => render(&Badge::muted(domain.status_label)),
    }
}

fn domain_actions(
    view: &DomainSettingsPageView<'_>,
    domain: &DomainEntryView,
) -> Result<String, BrowserError> {
    if !can_manage(view.role) {
        return Ok(String::new());
    }
    let verify = render(
        &Button::new("Verify")
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    let remove = render(
        &Button::new("Remove")
            .with_variant(ButtonVariant::Danger)
            .with_size(ButtonSize::Small)
            .with_button_type("submit"),
    )?;
    let verify_action = format!(
        "/t/{}/settings/domains/{}/verify",
        view.tenant_slug, domain.id
    );
    let delete_action = format!(
        "/t/{}/settings/domains/{}/delete",
        view.tenant_slug, domain.id
    );
    Ok(format!(
        r#"<form method="post" action="{}" style="display:inline;">{}{verify}</form><form method="post" action="{}" style="display:inline;margin-left:6px;" onsubmit="return confirm('Remove this custom domain?')">{}{remove}</form>"#,
        attr(&verify_action),
        hidden_input("csrf_token", view.csrf_token),
        attr(&delete_action),
        hidden_input("csrf_token", view.csrf_token)
    ))
}

fn domain_registration_form(view: &DomainSettingsPageView<'_>) -> Result<String, BrowserError> {
    let input_attrs = [
        HtmlAttr::new("autocomplete", "off"),
        HtmlAttr::new("spellcheck", "false"),
    ];
    let input = Input::new("domain")
        .with_type("text")
        .with_placeholder("auth.example.com")
        .with_attrs(&input_attrs);
    let mut body = hidden_input("csrf_token", view.csrf_token);
    body.push_str(&field("Add custom domain", &input, None)?);
    let button = render(
        &Button::primary("Register domain")
            .with_button_type("submit")
            .with_size(ButtonSize::Small),
    )?;
    body.push_str(&render(&FormActions::new(trusted_html(&button)))?);
    let action = format!("/t/{}/settings/domains", view.tenant_slug);
    render(
        &Form::new(trusted_html(&body))
            .with_action(&action)
            .with_attrs(&[HtmlAttr::new("style", "max-width:480px")]),
    )
}

pub fn domain_settings_page(
    view: &DomainSettingsPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let code = render(
        &CodeBlock::new(view.dns_target)
            .with_label("CNAME target")
            .with_copy_target("domain-dns-target"),
    )?;
    let mut body = format!(
        r#"<div style="margin-bottom:24px;"><p style="margin:0 0 8px;font-size:14px;">To use a custom domain, add a <strong>CNAME</strong> record in your DNS provider pointing to:</p>{code}<p class="wf-hint" style="margin-top:6px;font-size:12px;color:var(--wf-text-muted)">DNS propagation can take up to 48 hours. Use the Verify button once the record is live.</p></div>"#
    );
    if !view.error.is_empty() {
        body.push_str(&alert(FeedbackKind::Error, view.error)?);
    }

    if view.domains.is_empty() {
        body.push_str(
            r#"<p style="color:var(--wf-text-muted);font-size:14px;margin-bottom:24px;">No custom domains registered yet.</p>"#,
        );
    } else {
        let mut headers = vec![
            DataTableHeader::new("Domain").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Status").with_width(TableColumnWidth::Medium),
            DataTableHeader::new("Verified at").with_width(TableColumnWidth::Medium),
        ];
        if can_manage(view.role) {
            headers.push(DataTableHeader::new("Actions").action_column());
        }
        let domains: Vec<String> = view
            .domains
            .iter()
            .map(|domain| format!(r#"<code>{}</code>"#, text(domain.domain.as_str())))
            .collect();
        let statuses: Vec<String> = view
            .domains
            .iter()
            .map(|domain| {
                let mut status = domain_status_badge(domain)?;
                if let Some(error) = domain.last_error.as_deref().filter(|error| !error.is_empty())
                {
                    write!(
                        status,
                        r#"<span class="wf-hint" style="font-size:11px;color:var(--wf-text-muted);display:block;margin-top:2px;">{}</span>"#,
                        text(error)
                    )
                    .unwrap();
                }
                Ok(status)
            })
            .collect::<Result<Vec<_>, BrowserError>>()?;
        let verified: Vec<String> = view
            .domains
            .iter()
            .map(|domain| domain.verified_at.clone().unwrap_or_else(|| "-".to_owned()))
            .collect();
        let actions: Vec<String> = if can_manage(view.role) {
            view.domains
                .iter()
                .map(|domain| domain_actions(view, domain))
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = view
            .domains
            .iter()
            .enumerate()
            .map(|(idx, _)| {
                let mut cells = vec![
                    DataTableCell::html(trusted_html(&domains[idx])),
                    DataTableCell::html(trusted_html(&statuses[idx])),
                    DataTableCell::new(verified[idx].as_str()),
                ];
                if can_manage(view.role) {
                    cells.push(DataTableCell::html(trusted_html(&actions[idx])));
                }
                cells
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows))?;
        write!(
            body,
            r#"<div style="margin-bottom:24px;">{}</div>"#,
            render(&TableWrap::new(trusted_html(&table)))?
        )
        .unwrap();
    }

    if can_manage(view.role) {
        body.push_str(&domain_registration_form(view)?);
    }

    let section = render(&SettingsSection::new("Custom Domain", trusted_html(&body)))?;
    let content = format!(r#"<div style="margin:16px 24px 0">{section}</div>"#);
    let title = format!("Custom Domain - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "Custom Domain",
        content_html: &content,
    })
}

pub fn general_settings_page(
    view: &GeneralSettingsPageView<'_>,
) -> Result<Html<String>, BrowserError> {
    let mut body = String::new();
    if view.saved {
        body.push_str(r#"<script>document.addEventListener("DOMContentLoaded",function(){document.dispatchEvent(new CustomEvent("wfEcho",{detail:{kind:"ok",msg:"Settings saved."}}));});</script>"#);
    }
    if !view.error.is_empty() {
        body.push_str(&alert(FeedbackKind::Error, view.error)?);
    }
    if can_manage(view.role) {
        let name_attrs = [HtmlAttr::new("maxlength", "80")];
        let slug_attrs = [
            HtmlAttr::new("readonly", ""),
            HtmlAttr::new("disabled", ""),
            HtmlAttr::new("style", "opacity:0.6;cursor:not-allowed"),
        ];
        let mut form_body = hidden_input("csrf_token", view.csrf_token);
        form_body.push_str(&field(
            "Workspace name",
            &Input::new("name")
                .with_type("text")
                .with_value(view.tenant_name)
                .with_attrs(&name_attrs)
                .required(),
            None,
        )?);
        form_body.push_str(&field(
            "Slug",
            &Input::new("slug")
                .with_type("text")
                .with_value(view.tenant_slug)
                .with_attrs(&slug_attrs),
            Some("The slug is permanent. Contact support if you need to change it."),
        )?);
        let save = render(
            &Button::primary("Save changes")
                .with_button_type("submit")
                .with_size(ButtonSize::Small),
        )?;
        form_body.push_str(&render(&FormActions::new(trusted_html(&save)))?);
        let action = format!("/t/{}/settings", view.tenant_slug);
        body.push_str(&render(
            &Form::new(trusted_html(&form_body))
                .with_action(&action)
                .with_attrs(&[HtmlAttr::new("style", "max-width:480px")]),
        )?);
    } else {
        write!(
            body,
            r#"<dl class="wf-dl"><div class="wf-dl-row"><dt>Workspace name</dt><dd>{}</dd></div><div class="wf-dl-row"><dt>Slug</dt><dd><code>{}</code></dd></div></dl>"#,
            text(view.tenant_name),
            text(view.tenant_slug)
        )
        .unwrap();
    }
    let section = render(&SettingsSection::new("General", trusted_html(&body)))?;
    let content = format!(r#"<div style="margin:16px 24px 0">{section}</div>"#);
    let title = format!("General Settings - {}", view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: "General Settings",
        content_html: &content,
    })
}

pub fn coming_soon_page(view: &ComingSoonPageView<'_>) -> Result<Html<String>, BrowserError> {
    let tag = render(&Tag::new(&format!("Coming soon - Epic {}", view.epic_ref)))?;
    let mut body = format!(r#"<p>{tag}</p><p>{}</p>"#, text(view.description));
    if let Some(wireframe) = view.wireframe.filter(|wireframe| !wireframe.is_empty()) {
        write!(
            body,
            r#"<pre class="wf-wireframe" style="margin-top:16px;font-size:12px;color:var(--wf-text-muted)">{}</pre>"#,
            text(wireframe)
        )
        .unwrap();
    }
    let panel_attrs = [HtmlAttr::new("style", "margin:16px 24px 0")];
    let content = render(&Panel::new(view.title, trusted_html(&body)).with_attrs(&panel_attrs))?;
    let title = format!("{} - {}", view.title, view.tenant_name);
    tenant_dashboard_page(TenantDashboardPage {
        tenant_name: view.tenant_name,
        tenant_slug: view.tenant_slug,
        nav_sections: view.nav_sections,
        workspaces: view.workspaces,
        status_session: view.status_session,
        is_production: view.is_production,
        title: &title,
        page_title: view.title,
        content_html: &content,
    })
}

fn audit_event_label(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::Login => "Login",
        AuditEvent::LoginFailed => "Login failed",
        AuditEvent::Logout => "Logout",
        AuditEvent::Register => "Register",
        AuditEvent::PasswordChange => "Password change",
        AuditEvent::PasswordReset => "Password reset",
        AuditEvent::RoleAssigned => "Role assigned",
        AuditEvent::RoleUnassigned => "Role unassigned",
        AuditEvent::PermissionAssigned => "Permission assigned",
        AuditEvent::PermissionUnassigned => "Permission unassigned",
        AuditEvent::SessionCreated => "Session created",
        AuditEvent::SessionExpired => "Session expired",
        AuditEvent::UserUpdated => "User updated",
        AuditEvent::UserDeleted => "User deleted",
        AuditEvent::MfaEnabled => "MFA enabled",
        AuditEvent::MfaDisabled => "MFA disabled",
        AuditEvent::MfaChallengeSuccess => "MFA challenge success",
        AuditEvent::MfaChallengeFailed => "MFA challenge failed",
        AuditEvent::OrgCreated => "Org created",
        AuditEvent::OrgUpdated => "Org updated",
        AuditEvent::OrgDeleted => "Org deleted",
        AuditEvent::OrgMemberAdded => "Org member added",
        AuditEvent::OrgMemberRemoved => "Org member removed",
        AuditEvent::OrgMemberRoleChanged => "Org member role changed",
        AuditEvent::OrgOwnershipTransferred => "Org ownership transferred",
        AuditEvent::TeamCreated => "Team created",
        AuditEvent::TeamUpdated => "Team updated",
        AuditEvent::TeamDeleted => "Team deleted",
        AuditEvent::TeamMemberAdded => "Team member added",
        AuditEvent::TeamMemberRemoved => "Team member removed",
        AuditEvent::TeamMemberRoleChanged => "Team member role changed",
        AuditEvent::OrgInvitationCreated => "Org invitation created",
        AuditEvent::OrgInvitationAccepted => "Org invitation accepted",
        AuditEvent::OrgInvitationDeclined => "Org invitation declined",
        AuditEvent::OrgInvitationRevoked => "Org invitation revoked",
    }
}

fn audit_event_is_failure(event: &AuditEvent) -> bool {
    matches!(
        event,
        AuditEvent::LoginFailed | AuditEvent::MfaChallengeFailed
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::nav::tenant_nav_items;
    use allowthem_core::applications::{Application, generate_client_id};
    use allowthem_core::audit::{AuditEvent, AuditListEntry};
    use allowthem_core::sessions::SessionListEntry;
    use allowthem_core::types::{
        AuditEntryId, Email, Permission, PermissionId, PermissionName, Role, RoleId, RoleName,
        SessionId, User, UserId, Username,
    };
    use allowthem_core::users::UserListEntry;
    use allowthem_core::{ApplicationId, ClientType};

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

    #[test]
    fn signup_page_renders_slug_htmx_controls_and_escapes_values() {
        let html = signup_page(&SignupPageView {
            csrf_token: "csrf-123",
            email: "owner+<tag>@example.com",
            tenant_name: "Acme <Ops>",
            slug: "acme",
            error: Some("Use a different <slug>."),
            is_production: false,
        })
        .expect("render signup page")
        .0;

        assert!(html.contains("Create your workspace"));
        assert!(html.contains(r#"name="csrf_token" value="csrf-123""#));
        assert!(html.contains(r#"id="signup-form""#));
        assert!(html.contains(r#"hx-get="/signup/slug-check""#));
        assert!(html.contains(r##"hx-target="#slug-check""##));
        assert!(html.contains("Use a different"));
        assert!(!html.contains("owner+<tag>@example.com"));
        assert!(!html.contains("Acme <Ops>"));
        assert!(!html.contains("Use a different <slug>."));
    }

    #[test]
    fn slug_check_fragments_preserve_htmx_contract() {
        let ok = slug_check_ok("acme<prod>").0;
        let err = slug_check_err("Already <taken>").0;

        assert!(ok.contains(r#"data-slug-check="ok""#));
        assert!(ok.contains("is available"));
        assert!(!ok.contains("acme<prod>"));
        assert!(err.contains(r#"data-slug-check="err""#));
        assert!(err.contains("Already"));
        assert!(!err.contains("Already <taken>"));
    }

    #[test]
    fn quickstart_page_renders_credentials_snippets_and_dismiss_form() {
        let snippets = [
            QuickstartSnippetView {
                label: "curl",
                code: "curl https://acme.example.test",
                language: "shell",
                active: true,
            },
            QuickstartSnippetView {
                label: "Rust",
                code: "let secret = \"client-secret\";",
                language: "rust",
                active: false,
            },
        ];
        let html = quickstart_page(&QuickstartPageView {
            csrf_token: "csrf-quick",
            token: "quick-token",
            slug: "acme",
            issuer: "https://acme.example.test",
            base_domain: "example.test",
            client_id: "client-id",
            client_secret: "client-secret",
            redirect_uri: "http://localhost/callback",
            snippets: &snippets,
            status_session: Some("owner@example.test"),
            is_production: false,
        })
        .expect("render quickstart page")
        .0;

        assert!(html.contains("Your workspace is ready"));
        assert!(html.contains("Client ID"));
        assert!(html.contains("Client secret"));
        assert!(html.contains(r#"data-testid="quickstart-secret""#));
        assert!(html.contains(r#"data-wf-copy-value="client-secret""#));
        assert!(html.contains(r#"id="quickstart-snippets""#));
        assert!(html.contains(r#"action="/quickstart/quick-token/dismiss""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-quick""#));
        assert!(html.contains("saved my credentials"));
        assert!(html.contains("owner@example.test"));
    }

    #[test]
    fn invite_pages_render_expected_flows_and_escape_user_data() {
        let tenant = InviteTenantView {
            name: "Acme <Ops>",
            slug: "acme",
        };
        let register = invite_register_page(&InviteRegisterPageView {
            tenant,
            email: "new+<tag>@example.test",
            role: "admin",
            token: "tok/123",
            error: Some("Account creation <failed>."),
            csrf_token: "csrf-invite",
            is_production: false,
        })
        .expect("render invite register page")
        .0;

        assert!(register.contains("Create account"));
        assert!(register.contains(r#"action="/invite/tok/123""#));
        assert!(register.contains(r#"readonly"#));
        assert!(register.contains(r#"name="csrf_token" value="csrf-invite""#));
        assert!(register.contains(r#"href="/login?next=%2Finvite%2Ftok%2F123""#));
        assert!(!register.contains("Acme <Ops>"));
        assert!(!register.contains("new+<tag>@example.test"));
        assert!(!register.contains("Account creation <failed>."));

        let accept = invite_accept_page(&InviteAcceptPageView {
            tenant,
            email: "owner@example.test",
            role: "viewer",
            token: "tok/123",
            csrf_token: "csrf-invite",
            is_production: false,
        })
        .expect("render invite accept page")
        .0;

        assert!(accept.contains("Accept invite"));
        assert!(accept.contains(r#"action="/invite/tok/123""#));
        assert!(!accept.contains("Create account"));

        let expired = invite_expired_page(false)
            .expect("render invite expired page")
            .0;
        assert!(expired.contains("Invite not found"));

        let wrong_user = invite_wrong_user_page(&InviteWrongUserPageView {
            signed_in_email: "signed-in+<tag>@example.test",
            invite_email: "invitee+<tag>@example.test",
            token: "tok/123",
            is_production: false,
        })
        .expect("render wrong-user invite page")
        .0;
        assert!(wrong_user.contains("this invite is for"));
        assert!(wrong_user.contains(r#"href="/logout?next=%2Finvite%2Ftok%2F123""#));
        assert!(!wrong_user.contains("signed-in+<tag>@example.test"));
        assert!(!wrong_user.contains("invitee+<tag>@example.test"));
    }

    #[test]
    fn application_list_page_uses_data_table_and_role_actions() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/applications", TenantRole::Owner);
        let workspaces = workspaces();
        let apps = [test_application(
            "Default <OIDC>",
            ClientType::Confidential,
            true,
        )];
        let html = application_list_page(&ApplicationListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            applications: &apps,
            csrf_token: "csrf-apps",
            status_session: Some("owner@example.test"),
            is_production: false,
        })
        .expect("render application list page")
        .0;

        assert!(html.contains("Registered applications"));
        assert!(html.contains("New application"));
        assert!(html.contains(r#"class="wf-table sticky""#));
        assert!(html.contains(r#"href="/t/acme/applications/"#));
        assert!(html.contains("Confidential"));
        assert!(html.contains("Active"));
        assert!(!html.contains("Default <OIDC>"));
    }

    #[test]
    fn application_detail_page_renders_secret_once_and_admin_actions() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/applications", TenantRole::Owner);
        let workspaces = workspaces();
        let app = test_application("Portal 'quoted' <App>", ClientType::Confidential, true);
        let redirect_uris = vec!["https://portal.example.test/callback".to_owned()];
        let html = application_detail_page(&ApplicationDetailPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            app: &app,
            redirect_uris: &redirect_uris,
            connected_users: 2,
            csrf_token: "csrf-detail",
            client_secret: Some("raw-secret"),
            status_session: Some("owner@example.test"),
            is_production: false,
        })
        .expect("render application detail page")
        .0;

        assert!(html.contains("Save this client secret now"));
        assert!(html.contains(r#"data-wf-copy-value="raw-secret""#));
        assert!(html.contains("Connected users"));
        assert!(html.contains(">2<"));
        assert!(html.contains("Regenerate secret"));
        assert!(html.contains("Delete"));
        assert!(html.contains("Delete this application? This cannot be undone."));
        assert!(!html.contains("Delete Portal"));
        assert!(html.contains(r#"name="csrf_token" value="csrf-detail""#));
    }

    #[test]
    fn application_form_pages_preserve_values_and_csrf() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/applications", TenantRole::Owner);
        let workspaces = workspaces();
        let redirect_uris = vec!["https://app.example.test/callback".to_owned()];
        let new_html = new_application_page(&ApplicationNewPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-new",
            name: "New <App>",
            client_type: "public",
            redirect_uris: &redirect_uris,
            logo_url: "https://cdn.example.test/logo.svg",
            error: Some("Invalid redirect <uri>."),
            status_session: Some("owner@example.test"),
            is_production: false,
        })
        .expect("render new application page")
        .0;

        assert!(new_html.contains("New application"));
        assert!(new_html.contains(r#"action="/t/acme/applications""#));
        assert!(new_html.contains(r#"name="csrf_token" value="csrf-new""#));
        assert!(new_html.contains(r#"name="client_type" value="public" checked"#));
        assert!(new_html.contains("https://app.example.test/callback"));
        assert!(!new_html.contains("New <App>"));
        assert!(!new_html.contains("Invalid redirect <uri>."));

        let app = test_application("Existing <App>", ClientType::Confidential, false);
        let edit_html = edit_application_page(&ApplicationEditPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            app: &app,
            redirect_uris: &redirect_uris,
            csrf_token: "csrf-edit",
            error: None,
            status_session: Some("owner@example.test"),
            is_production: false,
        })
        .expect("render edit application page")
        .0;

        assert!(edit_html.contains("Edit Existing"));
        assert!(edit_html.contains(r#"name="csrf_token" value="csrf-edit""#));
        assert!(edit_html.contains(r#"name="is_active" value="on""#));
        assert!(!edit_html.contains(r#"name="client_type""#));
        assert!(!edit_html.contains("Existing <App>"));
    }

    fn test_application(name: &str, client_type: ClientType, is_active: bool) -> Application {
        Application {
            id: ApplicationId::new(),
            name: name.to_owned(),
            client_id: generate_client_id(),
            client_type,
            client_secret_hash: None,
            redirect_uris: r#"["https://app.example.test/callback"]"#.to_owned(),
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
            is_trusted: false,
            created_by: None,
            is_active,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn user_list_page_uses_filters_table_and_escapes_values() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/users", TenantRole::Owner);
        let workspaces = workspaces();
        let users = [test_user_list_entry(
            "alice@example.com",
            Some("<boss>"),
            true,
            true,
        )];
        let html = user_list_page(&UserListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            users: &users,
            total: 26,
            page: 2,
            total_pages: 3,
            q: "alice@example.com",
            status: "active",
            mfa: "yes",
            verified: "no",
            has_filters: true,
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render user list page")
        .0;

        assert!(html.contains("Users (26)"));
        assert!(html.contains(r#"name="q" value="alice@example.com""#));
        assert!(html.contains(r#"name="status""#));
        assert!(html.contains(r#"href="/t/acme/users/"#));
        assert!(html.contains(r#"class="wf-table sticky""#));
        assert!(html.contains("Active"));
        assert!(html.contains("Enrolled"));
        assert!(html.contains("Page 2 of 3 - 26 users"));
        assert!(html.contains("q=alice%40example.com"));
        assert!(!html.contains("@<boss>"));
    }

    #[test]
    fn user_detail_page_renders_actions_and_avoids_dynamic_inline_confirm_text() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/users", TenantRole::Owner);
        let workspaces = workspaces();
        let user = test_user("quoted@example.com", Some("<admin>"), true);
        let roles = [test_role("owner's <role>")];
        let permissions = [test_permission("reports:<read>")];
        let sessions = [test_session(user.id, "quoted@example.com")];
        let audit_entries = [test_audit_entry(
            user.id,
            AuditEvent::Logout,
            Some("revoked <all>"),
        )];
        let html = user_detail_page(&UserDetailPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            user: &user,
            roles: &roles,
            direct_permissions: &permissions,
            mfa_enabled: true,
            sessions: &sessions,
            last_login: Some("2026-05-18T12:00:00Z"),
            audit_entries: &audit_entries,
            all_roles: &roles,
            all_permissions: &permissions,
            csrf_token: "csrf-user",
            flash_info: "Updated",
            flash_error: "",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render user detail page")
        .0;

        assert!(html.contains("Actions"));
        assert!(html.contains("Roles"));
        assert!(html.contains("Direct permissions"));
        assert!(html.contains("Active sessions (1)"));
        assert!(html.contains("Recent activity"));
        assert!(html.contains(r#"name="csrf_token" value="csrf-user""#));
        assert!(html.contains(r#"name="confirm" value="DELETE""#));
        assert!(html.contains("Block this user? Their sessions will be terminated."));
        assert!(!html.contains("Block quoted@example.com"));
        assert!(!html.contains("@<admin>"));
        assert!(!html.contains("owner's <role>"));
        assert!(!html.contains("revoked <all>"));
    }

    #[test]
    fn audit_list_page_uses_filter_table_export_and_empty_state() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Owner);
        let workspaces = workspaces();
        let entry = test_audit_entry(
            UserId::new(),
            AuditEvent::LoginFailed,
            Some("bad password <script>"),
        );
        let html = audit_list_page(&AuditListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            entries: &[entry],
            total: 1,
            page: 1,
            total_pages: 1,
            event_type: "login_failed",
            user_email: "alice@example.com",
            outcome: "failure",
            from: "2026-05-01",
            to: "2026-05-18",
            has_filters: true,
            no_user: false,
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render audit list page")
        .0;

        assert!(html.contains("Audit log"));
        assert!(html.contains(r#"name="event_type""#));
        assert!(html.contains("Login failed"));
        assert!(html.contains(r#"class="wf-table sticky""#));
        assert!(html.contains("Export CSV"));
        assert!(html.contains("user_email=alice%40example.com"));
        assert!(!html.contains("bad password <script>"));

        let empty = audit_list_page(&AuditListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            entries: &[],
            total: 0,
            page: 1,
            total_pages: 1,
            event_type: "",
            user_email: "missing@example.com",
            outcome: "",
            from: "",
            to: "",
            has_filters: true,
            no_user: true,
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render empty audit page")
        .0;
        assert!(empty.contains("No user found with that email. Showing zero results."));
        assert!(!empty.contains("No audit entries match."));
    }

    #[test]
    fn role_pages_render_tables_forms_and_permission_assignments() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/roles", TenantRole::Owner);
        let workspaces = workspaces();
        let roles = [RoleListItemView {
            id: RoleId::new().to_string(),
            name: "owner's <role>".to_owned(),
            description: Some("Can edit <everything>".to_owned()),
            permission_count: 2,
        }];
        let list_html = role_list_page(&RoleListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            roles: &roles,
            csrf_token: "csrf-role",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render role list page")
        .0;

        assert!(list_html.contains("Roles (1)"));
        assert!(list_html.contains("+ New role"));
        assert!(list_html.contains(r#"class="wf-table sticky""#));
        assert!(list_html.contains("Delete this role?"));
        assert!(list_html.contains(r#"name="csrf_token" value="csrf-role""#));
        assert!(!list_html.contains("owner's <role>"));

        let permissions = [RolePermissionOptionView {
            id: PermissionId::new().to_string(),
            name: "posts:<write>".to_owned(),
            description: Some("Write <posts>".to_owned()),
            assigned: true,
        }];
        let detail_html = role_detail_page(&RoleDetailPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            actor_role: TenantRole::Admin,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            role_id: roles[0].id.as_str(),
            name: "editor <role>",
            description: "Edits things",
            permissions: &permissions,
            csrf_token: "csrf-detail-role",
            error: "Role name must be 1-80 characters.",
            status_session: Some("admin@example.com"),
            is_production: false,
        })
        .expect("render role detail page")
        .0;

        assert!(detail_html.contains("Save changes"));
        assert!(detail_html.contains("Update permissions"));
        assert!(detail_html.contains(r#"name="permission_id""#));
        assert!(detail_html.contains(r#"checked"#));
        assert!(detail_html.contains(r#"name="csrf_token" value="csrf-detail-role""#));
        assert!(!detail_html.contains("editor <role>"));
        assert!(!detail_html.contains("posts:<write>"));
    }

    #[test]
    fn permission_pages_render_table_and_create_form() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/permissions", TenantRole::Owner);
        let workspaces = workspaces();
        let permissions = [test_permission("posts:<read>")];
        let list_html = permission_list_page(&PermissionListPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            permissions: &permissions,
            csrf_token: "csrf-perm",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render permission list page")
        .0;

        assert!(list_html.contains("Permissions (1)"));
        assert!(list_html.contains("+ New permission"));
        assert!(list_html.contains(r#"class="wf-table sticky""#));
        assert!(list_html.contains("Delete this permission?"));
        assert!(list_html.contains(r#"name="csrf_token" value="csrf-perm""#));
        assert!(!list_html.contains("posts:<read>"));

        let form_html = permission_new_page(&PermissionNewPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-new-perm",
            name: "reports:<write>",
            description: "Write reports",
            error: "A permission with that name already exists.",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render permission form")
        .0;

        assert!(form_html.contains("New Permission"));
        assert!(form_html.contains(r#"action="/t/acme/permissions""#));
        assert!(form_html.contains(r#"name="csrf_token" value="csrf-new-perm""#));
        assert!(form_html.contains("Create permission"));
        assert!(!form_html.contains("reports:<write>"));
    }

    #[test]
    fn team_settings_page_preserves_invite_actions_and_escaping() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/team", TenantRole::Owner);
        let workspaces = workspaces();
        let members = [
            TeamMemberView {
                id: "owner-id".to_owned(),
                email: "owner@example.com".to_owned(),
                role: TenantRole::Owner,
                accepted: true,
                invited_at: "2026-05-18 10:00 UTC".to_owned(),
                accepted_at: Some("2026-05-18 10:01 UTC".to_owned()),
            },
            TeamMemberView {
                id: "admin-id".to_owned(),
                email: "admin<ops>@example.com".to_owned(),
                role: TenantRole::Admin,
                accepted: false,
                invited_at: "2026-05-18 11:00 UTC".to_owned(),
                accepted_at: None,
            },
        ];
        let html = team_settings_page(&TeamSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-team",
            members: &members,
            invite_error: "Email is required.",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render team settings page")
        .0;

        assert!(html.contains("Team Members"));
        assert!(html.contains(r#"action="/t/acme/settings/team/invite""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-team""#));
        assert!(html.contains("Email is required."));
        assert!(html.contains(r#"action="/t/acme/settings/team/admin-id/role""#));
        assert!(html.contains(r#"action="/t/acme/settings/team/admin-id/remove""#));
        assert!(html.contains("Remove this member from this workspace?"));
        assert!(!html.contains("admin<ops>@example.com"));

        let viewer_html = team_settings_page(&TeamSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Viewer,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-team",
            members: &members,
            invite_error: "",
            status_session: Some("viewer@example.com"),
            is_production: false,
        })
        .expect("render viewer team settings page")
        .0;
        assert!(viewer_html.contains("Team Members"));
        assert!(!viewer_html.contains(r#"settings/team/invite"#));
        assert!(!viewer_html.contains("Actions"));
        assert!(!viewer_html.contains("Remove this member"));
    }

    #[test]
    fn api_key_settings_page_preserves_secret_table_and_role_actions() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/api-keys", TenantRole::Owner);
        let workspaces = workspaces();
        let keys = [ApiKeyView {
            id: "key-id".to_owned(),
            name: "CI key <unsafe>".to_owned(),
            created_at: "2026-05-18 10:00 UTC".to_owned(),
            expires_at: None,
        }];
        let html = api_key_settings_page(&ApiKeySettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-key",
            keys: &keys,
            new_key_secret: Some("sak_secret"),
            error: "Key name must be 1-80 characters.",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render api key settings page")
        .0;

        assert!(html.contains("New API key"));
        assert!(html.contains("sak_secret"));
        assert!(html.contains("Copy key"));
        assert!(html.contains(r#"action="/t/acme/settings/api-keys""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-key""#));
        assert!(html.contains("Key name must be 1-80 characters."));
        assert!(html.contains(r#"action="/t/acme/settings/api-keys/key-id/revoke""#));
        assert!(html.contains("Revoke this API key? This cannot be undone."));
        assert!(!html.contains("CI key <unsafe>"));

        let viewer_html = api_key_settings_page(&ApiKeySettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Viewer,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-key",
            keys: &keys,
            new_key_secret: None,
            error: "",
            status_session: Some("viewer@example.com"),
            is_production: false,
        })
        .expect("render viewer api key settings page")
        .0;
        assert!(viewer_html.contains("API Keys"));
        assert!(viewer_html.contains("CI key"));
        assert!(!viewer_html.contains("CI key <unsafe>"));
        assert!(!viewer_html.contains("Mint key"));
        assert!(!viewer_html.contains("Revoke this API key"));
    }

    #[test]
    fn billing_settings_page_preserves_plan_usage_and_owner_action() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/billing", TenantRole::Owner);
        let workspaces = workspaces();
        let plan = BillingPlanView {
            name: "Launch <Plan>".to_owned(),
            mau_limit: 100,
            price_cents: 1900,
        };
        let usage = [BillingUsageView {
            period: "2026-05".to_owned(),
            mau_count: 50,
            limit_reached_at: None,
        }];
        let html = billing_settings_page(&BillingSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-billing",
            plan: Some(&plan),
            current_usage: 50,
            usage: &usage,
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render billing settings page")
        .0;

        assert!(html.contains("Plan"));
        assert!(html.contains("Usage"));
        assert!(html.contains("50%"));
        assert!(html.contains("$19/mo"));
        assert!(html.contains(r#"action="/t/acme/settings/billing/upgrade""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-billing""#));
        assert!(html.contains("Usage history"));
        assert!(!html.contains("Launch <Plan>"));

        let viewer_html = billing_settings_page(&BillingSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Viewer,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-billing",
            plan: Some(&plan),
            current_usage: 50,
            usage: &usage,
            status_session: Some("viewer@example.com"),
            is_production: false,
        })
        .expect("render viewer billing settings page")
        .0;
        assert!(viewer_html.contains("Plan"));
        assert!(viewer_html.contains("Usage"));
        assert!(!viewer_html.contains("Upgrade plan"));
    }

    #[test]
    fn domain_settings_page_preserves_dns_actions_and_viewer_readonly() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/domains", TenantRole::Owner);
        let workspaces = workspaces();
        let domains = [DomainEntryView {
            id: "domain-id".to_owned(),
            domain: "auth<bad>.example.com".to_owned(),
            status: DomainStatus::Failed,
            status_label: "Failed",
            verified_at: None,
            last_error: Some("Missing <CNAME>".to_owned()),
        }];
        let html = domain_settings_page(&DomainSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-domain",
            domains: &domains,
            dns_target: "acme.example.test",
            error: "That domain is already registered.",
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render domain settings page")
        .0;

        assert!(html.contains("Custom Domain"));
        assert!(html.contains("CNAME"));
        assert!(html.contains("acme.example.test"));
        assert!(html.contains("That domain is already registered."));
        assert!(html.contains(r#"action="/t/acme/settings/domains/domain-id/verify""#));
        assert!(html.contains(r#"action="/t/acme/settings/domains/domain-id/delete""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-domain""#));
        assert!(html.contains("Register domain"));
        assert!(!html.contains("auth<bad>.example.com"));
        assert!(!html.contains("Missing <CNAME>"));

        let viewer_html = domain_settings_page(&DomainSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Viewer,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-domain",
            domains: &domains,
            dns_target: "acme.example.test",
            error: "",
            status_session: Some("viewer@example.com"),
            is_production: false,
        })
        .expect("render viewer domain settings page")
        .0;
        assert!(viewer_html.contains("Custom Domain"));
        assert!(viewer_html.contains("acme.example.test"));
        assert!(!viewer_html.contains("Register domain"));
        assert!(!viewer_html.contains("/settings/domains/domain-id/verify"));
        assert!(!viewer_html.contains("/settings/domains/domain-id/delete"));
    }

    #[test]
    fn general_settings_page_preserves_form_readonly_and_saved_feedback() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings", TenantRole::Owner);
        let workspaces = workspaces();
        let html = general_settings_page(&GeneralSettingsPageView {
            tenant_name: "Acme <Ops>",
            tenant_slug: "acme",
            role: TenantRole::Owner,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-settings",
            error: "Workspace name must be 1-80 characters.",
            saved: true,
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render general settings page")
        .0;

        assert!(html.contains("General Settings"));
        assert!(html.contains(r#"action="/t/acme/settings""#));
        assert!(html.contains(r#"name="csrf_token" value="csrf-settings""#));
        assert!(html.contains("Settings saved."));
        assert!(html.contains(r#"name="slug""#));
        assert!(html.contains(r#"value="acme""#));
        assert!(html.contains("disabled"));
        assert!(!html.contains("Acme <Ops>"));

        let viewer_html = general_settings_page(&GeneralSettingsPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            role: TenantRole::Viewer,
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            csrf_token: "csrf-settings",
            error: "",
            saved: false,
            status_session: Some("viewer@example.com"),
            is_production: false,
        })
        .expect("render viewer general settings page")
        .0;
        assert!(viewer_html.contains(r#"<dt>Workspace name</dt>"#));
        assert!(!viewer_html.contains("Save changes"));
    }

    #[test]
    fn coming_soon_page_renders_copy_and_escapes_wireframe() {
        let nav_sections = tenant_nav_items("acme", "/t/acme/settings/webhooks", TenantRole::Owner);
        let workspaces = workspaces();
        let html = coming_soon_page(&ComingSoonPageView {
            tenant_name: "Acme",
            tenant_slug: "acme",
            nav_sections: &nav_sections,
            workspaces: &workspaces,
            title: "Webhooks",
            epic_ref: "7xw",
            description: "Configure <hooks> soon.",
            wireframe: Some("[<endpoint>]"),
            status_session: Some("owner@example.com"),
            is_production: false,
        })
        .expect("render coming soon page")
        .0;

        assert!(html.contains("Webhooks"));
        assert!(html.contains("Coming soon - Epic 7xw"));
        assert!(!html.contains("Configure <hooks> soon."));
        assert!(!html.contains("[<endpoint>]"));
    }

    fn test_user_list_entry(
        email: &str,
        username: Option<&str>,
        is_active: bool,
        has_mfa: bool,
    ) -> UserListEntry {
        UserListEntry {
            id: UserId::new(),
            email: Email::new(email.to_owned()).unwrap(),
            username: username.map(Username::new),
            is_active,
            has_mfa,
            created_at: chrono::Utc::now(),
        }
    }

    fn test_user(email: &str, username: Option<&str>, is_active: bool) -> User {
        User {
            id: UserId::new(),
            email: Email::new(email.to_owned()).unwrap(),
            username: username.map(Username::new),
            password_hash: None,
            email_verified: true,
            is_active,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            custom_data: None,
        }
    }

    fn test_role(name: &str) -> Role {
        Role {
            id: RoleId::new(),
            name: RoleName::new(name),
            description: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn test_permission(name: &str) -> Permission {
        Permission {
            id: PermissionId::new(),
            name: PermissionName::new(name),
            description: None,
            created_at: chrono::Utc::now(),
        }
    }

    fn test_session(user_id: UserId, email: &str) -> SessionListEntry {
        SessionListEntry {
            id: SessionId::new(),
            user_id,
            user_email: Email::new(email.to_owned()).unwrap(),
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: Some("test-agent".to_owned()),
            expires_at: chrono::Utc::now(),
            created_at: chrono::Utc::now(),
        }
    }

    fn test_audit_entry(
        user_id: UserId,
        event_type: AuditEvent,
        detail: Option<&str>,
    ) -> AuditListEntry {
        AuditListEntry {
            id: AuditEntryId::new(),
            event_type,
            user_id: Some(user_id),
            user_email: Some("alice@example.com".to_owned()),
            target_id: None,
            ip_address: Some("127.0.0.1".to_owned()),
            user_agent: None,
            detail: detail.map(str::to_owned),
            created_at: chrono::Utc::now(),
        }
    }
}
