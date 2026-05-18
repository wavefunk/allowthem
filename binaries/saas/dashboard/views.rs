use std::fmt::Write as _;

use axum::response::Html;
use chrono::{DateTime, Utc};
use html_escape::{encode_double_quoted_attribute as esc_attr, encode_text as esc_text};

use allowthem_core::applications::Application;
use allowthem_core::types::ClientType;
use allowthem_saas::TenantRole;
use allowthem_server::BrowserError;
use allowthem_server::ui::{render_component, trusted_html};
use wavefunk_ui::components::{
    Alert, Button, ButtonSize, ButtonVariant, CheckRow, CodeGrid, ContextSwitcher,
    ContextSwitcherItem, CopyableValue, CredentialStatusItem, CredentialStatusList, DataTable,
    DataTableCell, DataTableHeader, DataTableRow, FeedbackKind, Field, Form, FormActions,
    FormPanel, FormSection, HtmlAttr, Input, Modeline, ModelineSegment, PageHeader,
    RepeatableArray, RepeatableItem, SecretValue, Sidenav, SidenavItem, SidenavSection, SnippetTab,
    SnippetTabs, SplitShell, TableColumnWidth, TableWrap, Tag,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dashboard::nav::tenant_nav_items;
    use allowthem_core::applications::{Application, generate_client_id};
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
}
