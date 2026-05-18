use std::fmt::Write as _;

use axum::response::Html;
use html_escape::{encode_double_quoted_attribute as esc_attr, encode_text as esc_text};

use allowthem_saas::TenantRole;
use allowthem_server::BrowserError;
use allowthem_server::ui::{render_component, trusted_html};
use wavefunk_ui::components::{
    Alert, Button, ButtonSize, ContextSwitcher, ContextSwitcherItem, CopyableValue, FeedbackKind,
    Field, Form, FormPanel, HtmlAttr, Input, Modeline, ModelineSegment, PageHeader, SecretValue,
    Sidenav, SidenavItem, SidenavSection, SnippetTab, SnippetTabs, SplitShell,
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
}
