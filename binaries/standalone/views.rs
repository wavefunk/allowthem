use std::fmt::Write as _;

use axum::response::Html;
use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use html_escape::{encode_double_quoted_attribute as esc_attr, encode_text as esc_text};

use allowthem_core::applications::Application;
use allowthem_core::sessions::SessionListEntry;
use allowthem_core::users::UserListEntry;
use allowthem_core::{OAuthAccountInfo, Role, User};
use allowthem_server::ui::{render_component, trusted_html};
use allowthem_server::{BrowserError, NavGroup, ShellContext};
use wavefunk_ui::components::{
    Alert, Badge, Button, ButtonSize, ButtonVariant, CheckRow, DataTable, DataTableCell,
    DataTableHeader, DataTableRow, FeedbackKind, Field, FilterBar, Form, FormActions, FormPanel,
    HtmlAttr, Input, Modeline, ModelineSegment, PageHeader, PageLink, Pagination, RepeatableArray,
    RepeatableItem, SecretValue, Select, SelectOption, Sidenav, SidenavItem, SidenavSection,
    TableColumnWidth, TableFooter, TableWrap, Tag,
};
use wavefunk_ui::layouts::AppShell;

const READY_SCRIPT: &str = r#"<script>document.addEventListener("DOMContentLoaded",function(){document.dispatchEvent(new CustomEvent("wfEcho",{detail:{kind:"ok",msg:"Ready."}}));});</script>"#;
const HEAD_HTML: &str = r#"<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">
<script>(function(){try{var m=localStorage.getItem('allowthem:mode');if((m==='dark'||m==='light')&&!document.documentElement.hasAttribute('data-mode-locked')){document.documentElement.dataset.mode=m;}}catch(_e){}})();</script>"#;
const MODE_SCRIPT: &str = r#"<script src="/__allowthem/static/js/mode-toggle.js" defer></script>"#;

type ViewResult<T> = Result<T, BrowserError>;

pub struct DashboardView<'a> {
    pub email: &'a str,
    pub is_active: bool,
    pub is_admin: bool,
    pub mfa_enabled: bool,
    pub oauth_account_count: usize,
    pub is_production: bool,
}

pub struct ApplicationFormView<'a> {
    pub shell: &'a ShellContext,
    pub title: String,
    pub page_title: String,
    pub crumbs: String,
    pub action: String,
    pub submit_label: &'a str,
    pub csrf_token: &'a str,
    pub error: Option<&'a str>,
    pub name: &'a str,
    pub redirect_uris: &'a [String],
    pub is_trusted: bool,
    pub is_active: Option<bool>,
    pub logo_url: &'a str,
    pub primary_color: &'a str,
    pub cancel_href: String,
    pub is_production: bool,
}

pub struct SessionsPageView<'a> {
    pub shell: &'a ShellContext,
    pub sessions: &'a [SessionListEntry],
    pub total: u32,
    pub page: u32,
    pub total_pages: u32,
    pub filter_user_email: Option<&'a str>,
    pub filter_user_id: Option<&'a str>,
    pub csrf_token: &'a str,
    pub current_session_id: Option<&'a str>,
    pub is_production: bool,
}

pub struct UsersPageView<'a> {
    pub shell: &'a ShellContext,
    pub users: &'a [UserListEntry],
    pub total: u32,
    pub page: u32,
    pub total_pages: u32,
    pub q: &'a str,
    pub status: &'a str,
    pub mfa: &'a str,
    pub is_production: bool,
}

pub struct AuditEntryView {
    pub event_label: String,
    pub is_failure: bool,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub ip_address: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

pub struct AuditPageView<'a> {
    pub shell: &'a ShellContext,
    pub entries: &'a [AuditEntryView],
    pub total: u32,
    pub page: u32,
    pub total_pages: u32,
    pub user: &'a str,
    pub event: &'a str,
    pub outcome: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub is_production: bool,
}

pub struct UserDetailView<'a> {
    pub shell: &'a ShellContext,
    pub user: &'a User,
    pub roles: &'a [Role],
    pub oauth_accounts: &'a [OAuthAccountInfo],
    pub sessions: &'a [SessionListEntry],
    pub mfa_enabled: bool,
    pub last_login: Option<&'a str>,
    pub csrf_token: &'a str,
    pub is_production: bool,
}

fn render<T>(component: &T) -> ViewResult<String>
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

fn datefmt(dt: &DateTime<Utc>) -> String {
    dt.format("%b %d, %Y %l:%M %p").to_string()
}

fn datefmt_str(value: &str) -> String {
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return dt.format("%b %d, %Y %l:%M %p").to_string();
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return dt.format("%b %d, %Y %l:%M %p").to_string();
    }
    if let Ok(d) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return d.format("%b %d, %Y").to_string();
    }
    value.to_owned()
}

fn ready_footer(is_production: bool, session: Option<&str>) -> ViewResult<String> {
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
        right.push(ModelineSegment::link("⏻", "/logout").with_attrs(&logout_attrs));
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

fn sidebar_nav(shell: &ShellContext) -> ViewResult<String> {
    let mut admin = Vec::new();
    let mut account = Vec::new();
    for item in &shell.nav_items {
        let mut nav_item = SidenavItem::link(item.label.as_str(), item.href.as_str());
        if item.active {
            nav_item = nav_item.active();
        }
        match item.group {
            NavGroup::Admin => admin.push(nav_item),
            NavGroup::Account => account.push(nav_item),
        }
    }

    let mut sections = Vec::new();
    if !admin.is_empty() {
        sections.push(SidenavSection::new("Admin", &admin));
    }
    if !account.is_empty() {
        sections.push(SidenavSection::new("Account", &account));
    }
    render(&Sidenav::new(&sections).embedded())
}

struct AppPage<'a> {
    shell: &'a ShellContext,
    title: &'a str,
    page_title: &'a str,
    crumbs_html: &'a str,
    meta_html: Option<&'a str>,
    content_html: &'a str,
    is_production: bool,
    main_class: &'a str,
    extra_scripts: Option<&'a str>,
}

fn app_page(view: AppPage<'_>) -> ViewResult<Html<String>> {
    let nav = sidebar_nav(view.shell)?;
    let mut page_header = PageHeader::new(view.page_title);
    if let Some(meta) = view.meta_html {
        page_header = page_header.with_meta(trusted_html(meta));
    }
    let page_header = render(&page_header)?;
    let footer = ready_footer(view.is_production, view.shell.status_session.as_deref())?;
    let scripts = match view.extra_scripts {
        Some(extra) => format!("{MODE_SCRIPT}{extra}"),
        None => MODE_SCRIPT.to_owned(),
    };
    let shell = AppShell::new(view.title, "allowthem", view.content_html)
        .with_brand_href("/")
        .with_nav(&nav)
        .with_breadcrumbs(trusted_html(view.crumbs_html))
        .with_page_header(trusted_html(&page_header))
        .with_footer(trusted_html(&footer))
        .with_head(trusted_html(HEAD_HTML))
        .with_scripts(trusted_html(&scripts))
        .with_main_class(view.main_class)
        .without_body_hx_boost();
    Ok(Html(render(&shell)?))
}

fn public_document(title: &str, body_html: &str) -> Html<String> {
    Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{}</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">{}<style>.wf-prose{{max-width:42rem;margin:var(--space-6) auto;padding:0 var(--space-4);line-height:1.6}}.wf-prose h1{{margin-bottom:var(--space-2)}}.wf-prose h2{{margin-top:var(--space-5);margin-bottom:var(--space-2)}}.wf-prose p{{margin-bottom:var(--space-3)}}.wf-prose-meta{{opacity:.6;margin-bottom:var(--space-4)}}.wf-prose-back{{display:inline-block;margin-bottom:var(--space-4)}}</style></head><body>{}<script src="/static/wavefunk/js/htmx.min.js" defer></script><script src="/static/wavefunk/js/wavefunk.js" defer></script></body></html>"#,
        text(title),
        wavefunk_ui::html::stylesheet_link("/static/wavefunk"),
        body_html
    ))
}

fn panel(title: Option<&str>, body: &str) -> String {
    match title {
        Some(title) => format!(
            r#"<section class="wf-panel"><div class="wf-panel-head"><div class="wf-panel-title">{}</div></div><div class="wf-panel-body">{}</div></section>"#,
            text(title),
            body
        ),
        None => format!(
            r#"<section class="wf-panel"><div class="wf-panel-body">{body}</div></section>"#
        ),
    }
}

fn alert(kind: FeedbackKind, message: &str) -> ViewResult<String> {
    render(&Alert::new(kind, message))
}

fn status_tag(kind: FeedbackKind, label: &str) -> ViewResult<String> {
    render(&Tag::status(kind, label))
}

fn muted_badge(label: &str) -> ViewResult<String> {
    render(&Badge::muted(label))
}

pub fn welcome_page(is_production: bool) -> ViewResult<Html<String>> {
    let login = render(
        &Button::link("Log in", "/login")
            .with_variant(ButtonVariant::Primary)
            .with_size(ButtonSize::Large),
    )?;
    let register =
        render(&Button::link("Create account", "/register").with_size(ButtonSize::Large))?;
    let body = format!(
        r#"<p class="wf-fg-muted wf-mt-5">Sign in to manage your account, or create a new one to get started.</p><div class="wf-f wf-col wf-gap-3 wf-mt-5">{login}{register}</div>"#
    );
    let panel = render(
        &FormPanel::new("allowthem", trusted_html(&body)).with_subtitle("Authentication service"),
    )?;
    let main = format!(r#"<main class="wf-auth-form">{panel}</main>"#);
    let footer = ready_footer(is_production, None)?;
    let shell = render(
        &wavefunk_ui::components::SplitShell::new(trusted_html(&main))
            .with_footer(trusted_html(&footer)),
    )?;
    Ok(Html(format!(
        r#"<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>allowthem - authentication service</title><link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🔐</text></svg>">{}<style>.wf-split-shell-main>.wf-auth-form{{padding:0}}.wf-split-shell-footer{{display:block}}.wf-split-shell-footer>.wf-modeline,.wf-split-shell-footer>.wf-minibuffer{{width:100%}}</style></head><body>{}<script src="/static/wavefunk/js/htmx.min.js" defer></script><script src="/static/wavefunk/js/wavefunk.js" defer></script>{}</body></html>"#,
        wavefunk_ui::html::stylesheet_link("/static/wavefunk"),
        shell,
        MODE_SCRIPT
    )))
}

pub fn dashboard_page(view: &DashboardView<'_>) -> ViewResult<Html<String>> {
    let shell = ShellContext::new(view.is_admin, "/", "allowthem");
    let status = if view.is_active {
        status_tag(FeedbackKind::Ok, "Active")?
    } else {
        render(&Tag::new("Inactive"))?
    };
    let mfa = if view.mfa_enabled {
        status_tag(FeedbackKind::Ok, "Enabled")?
    } else {
        render(&Tag::new("Not configured"))?
    };
    let mut dl = String::from(r#"<dl class="wf-dl flush">"#);
    write!(
        dl,
        r#"<div class="wf-dl-row"><dt>Email</dt><dd>{}</dd></div>"#,
        text(view.email)
    )
    .unwrap();
    write!(
        dl,
        r#"<div class="wf-dl-row"><dt>Status</dt><dd>{status}</dd></div>"#
    )
    .unwrap();
    write!(
        dl,
        r#"<div class="wf-dl-row"><dt>Two-factor authentication</dt><dd>{mfa}</dd></div>"#
    )
    .unwrap();
    write!(
        dl,
        r#"<div class="wf-dl-row"><dt>Linked accounts</dt><dd>{}</dd></div></dl>"#,
        view.oauth_account_count
    )
    .unwrap();
    let mut content = panel(Some("Account overview"), &dl);
    let settings =
        render(&Button::link("Settings", "/settings").with_variant(ButtonVariant::Primary))?;
    let admin = if view.is_admin {
        render(&Button::link("Admin panel", "/admin/applications"))?
    } else {
        String::new()
    };
    write!(
        content,
        r#"<div class="wf-f wf-gap-3" style="margin-top: var(--sp-4);">{settings}{admin}</div>"#
    )
    .unwrap();
    app_page(AppPage {
        shell: &shell,
        title: "Dashboard - allowthem",
        page_title: "Dashboard",
        crumbs_html: "Home",
        meta_html: None,
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header",
        extra_scripts: None,
    })
}

pub fn terms_page(_is_production: bool) -> ViewResult<Html<String>> {
    Ok(public_document(
        "Terms of Service - allowthem",
        r#"<article class="wf-prose">
  <a class="wf-prose-back" href="/">&larr; Back</a>
  <h1>Terms of Service</h1>
  <p class="wf-prose-meta">Last updated: April 2026</p>
  <h2>1. Acceptance of terms</h2>
  <p>By accessing or using the allowthem authentication service, you agree to be bound by these Terms of Service. If you do not agree, do not use the service.</p>
  <h2>2. Description of service</h2>
  <p>allowthem provides authentication and identity management. The service is offered as-is for use by authorized applications.</p>
  <h2>3. User accounts</h2>
  <p>You are responsible for maintaining the confidentiality of your account credentials. You agree to notify the administrator immediately of any unauthorized use of your account.</p>
  <h2>4. Acceptable use</h2>
  <p>You agree not to misuse the service. This includes attempting to gain unauthorized access, interfering with the service, or using the service for any unlawful purpose.</p>
  <h2>5. Limitation of liability</h2>
  <p>The service is provided without warranties of any kind. In no event shall the operators be liable for any damages arising from your use of the service.</p>
  <h2>6. Changes to terms</h2>
  <p>These terms may be updated from time to time. Continued use of the service after changes constitutes acceptance of the revised terms.</p>
</article>"#,
    ))
}

pub fn privacy_page(_is_production: bool) -> ViewResult<Html<String>> {
    Ok(public_document(
        "Privacy Policy - allowthem",
        r#"<article class="wf-prose">
  <a class="wf-prose-back" href="/">&larr; Back</a>
  <h1>Privacy Policy</h1>
  <p class="wf-prose-meta">Last updated: April 2026</p>
  <h2>1. Information we collect</h2>
  <p>allowthem collects your email address and, optionally, a username when you create an account. If you link third-party accounts, we store the provider name and associated email.</p>
  <h2>2. How we use your information</h2>
  <p>Your information is used solely for authentication and account management. We do not sell, share, or distribute your personal data to third parties.</p>
  <h2>3. Data storage</h2>
  <p>Account data is stored in a local database managed by the service operator. Session tokens are used for authentication and expire according to the configured session policy.</p>
  <h2>4. Security</h2>
  <p>Passwords are hashed using industry-standard algorithms. Two-factor authentication is available for additional account security. Session data is transmitted over encrypted connections when configured.</p>
  <h2>5. Your rights</h2>
  <p>You may update or delete your account information through the settings page. Contact the service administrator for data export or deletion requests.</p>
  <h2>6. Changes to this policy</h2>
  <p>This policy may be updated from time to time. Changes will be reflected in the Last updated date above.</p>
</article>"#,
    ))
}

pub fn applications_list_page(
    shell: &ShellContext,
    applications: &[Application],
    is_production: bool,
) -> ViewResult<Html<String>> {
    let new_button = render(
        &Button::link("New application", "/admin/applications/new")
            .with_variant(ButtonVariant::Primary)
            .with_size(ButtonSize::Small),
    )?;
    let mut content = format!(
        r#"<section class="wf-panel" style="margin:16px 24px 0"><div class="wf-panel-head" style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;"><div class="wf-panel-title">Registered applications</div>{new_button}</div></section>"#
    );

    if applications.is_empty() {
        content.push_str(r#"<p class="wf-empty">No applications registered.</p>"#);
    } else {
        let headers = [
            DataTableHeader::new("Name").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Client ID").with_width(TableColumnWidth::Id),
            DataTableHeader::new("Status"),
            DataTableHeader::new("Trusted"),
            DataTableHeader::new("Created"),
        ];
        let row_values: Vec<[String; 5]> = applications
            .iter()
            .map(|app| {
                let href = format!("/admin/applications/{}", app.id);
                [
                    format!(
                        r#"<a class="wf-link" href="{}">{}</a>"#,
                        attr(&href),
                        text(&app.name)
                    ),
                    format!(
                        r#"<code title="{}">{}</code>"#,
                        attr(app.client_id.as_str()),
                        text(app.client_id.as_str())
                    ),
                    if app.is_active {
                        status_tag(FeedbackKind::Ok, "Active")
                            .unwrap_or_else(|_| "Active".to_owned())
                    } else {
                        render(&Tag::new("Inactive")).unwrap_or_else(|_| "Inactive".to_owned())
                    },
                    if app.is_trusted {
                        "Yes".to_owned()
                    } else {
                        "No".to_owned()
                    },
                    datefmt(&app.created_at),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::html(trusted_html(&v[0])),
                    DataTableCell::html(trusted_html(&v[1])),
                    DataTableCell::html(trusted_html(&v[2])),
                    DataTableCell::new(&v[3]),
                    DataTableCell::new(&v[4]),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let wrap = render(&TableWrap::new(trusted_html(&table)))?;
        content.push_str(&wrap);
    }

    app_page(AppPage {
        shell,
        title: "Applications - allowthem",
        page_title: "APPLICATIONS",
        crumbs_html: "ALLOWTHEM &middot; ADMIN &middot; APPLICATIONS",
        meta_html: None,
        content_html: &content,
        is_production,
        main_class: "has-header has-tablewrap",
        extra_scripts: None,
    })
}

pub fn application_detail_page(
    shell: &ShellContext,
    app: &Application,
    redirect_uris: &[String],
    client_secret: Option<&str>,
    csrf_token: &str,
    created_by_email: Option<&str>,
    is_production: bool,
) -> ViewResult<Html<String>> {
    let mut body = String::new();
    if let Some(secret) = client_secret.filter(|s| !s.is_empty()) {
        let secret = render(
            &SecretValue::new("Client secret", "client-secret", secret)
                .revealed()
                .copy_raw_value()
                .with_warning("Copy now - it will not be shown again.")
                .with_button_label("Copy secret"),
        )?;
        body.push_str(&secret);
    }

    let status = if app.is_active {
        status_tag(FeedbackKind::Ok, "Active")?
    } else {
        muted_badge("Inactive")?
    };
    let redirect_html = if redirect_uris.is_empty() {
        muted_badge("None")?
    } else {
        let mut list = String::from("<ul>");
        for uri in redirect_uris {
            write!(list, "<li>{}</li>", text(uri)).unwrap();
        }
        list.push_str("</ul>");
        list
    };
    let logo = app
        .logo_url
        .as_deref()
        .map(text)
        .unwrap_or(muted_badge("Not set")?);
    let primary = app
        .primary_color
        .as_deref()
        .map(text)
        .unwrap_or(muted_badge("Not set")?);
    let created_by = if let Some(email) = created_by_email {
        text(email)
    } else if let Some(id) = app.created_by {
        let raw = id.to_string();
        let short = if raw.len() > 12 {
            format!("{}&hellip;", text(&raw[..12]))
        } else {
            text(&raw)
        };
        format!(r#"<span title="{}">{short}</span>"#, attr(&raw))
    } else {
        muted_badge("Unknown")?
    };
    write!(
        body,
        r#"<dl class="wf-dl">
<div class="wf-dl-row"><dt>Client ID</dt><dd><code>{}</code></dd></div>
<div class="wf-dl-row"><dt>Status</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Trusted</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Redirect URIs</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Logo URL</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Primary color</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Created by</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Created</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Updated</dt><dd>{}</dd></div>
</dl>"#,
        text(app.client_id.as_str()),
        status,
        if app.is_trusted { "Yes" } else { "No" },
        redirect_html,
        logo,
        primary,
        created_by,
        datefmt(&app.created_at),
        datefmt(&app.updated_at)
    )
    .unwrap();

    let edit = render(
        &Button::link("Edit", &format!("/admin/applications/{}/edit", app.id))
            .with_variant(ButtonVariant::Primary),
    )?;
    let regen = render(
        &Button::new("Regenerate secret")
            .with_variant(ButtonVariant::Ghost)
            .with_button_type("submit"),
    )?;
    let delete = render(
        &Button::new("Delete")
            .with_variant(ButtonVariant::Danger)
            .with_button_type("submit"),
    )?;
    write!(
        body,
        r#"<p>{edit}
<form method="post" action="/admin/applications/{}/regenerate-secret" style="display:inline" onsubmit="return confirm('Regenerate client secret? The old secret will be permanently invalidated and all integrations using it will break.')"><input type="hidden" name="csrf_token" value="{}">{regen}</form>
<form method="post" action="/admin/applications/{}/delete" style="display:inline" onsubmit="return confirm('Permanently delete this application? This will revoke all associated authorization codes, refresh tokens, and consents.')"><input type="hidden" name="csrf_token" value="{}">{delete}</form></p>
<p><a class="wf-link-quiet" href="/admin/applications">Back to applications</a></p>"#,
        app.id,
        attr(csrf_token),
        app.id,
        attr(csrf_token)
    )
    .unwrap();

    let content = panel(None, &body);
    let title = format!("{} - allowthem", app.name);
    let page_title = app.name.to_uppercase();
    let crumbs = format!(
        "ALLOWTHEM &middot; ADMIN &middot; APPLICATIONS &middot; {}",
        text(app.client_id.as_str())
    );
    app_page(AppPage {
        shell,
        title: &title,
        page_title: &page_title,
        crumbs_html: &crumbs,
        meta_html: None,
        content_html: &content,
        is_production,
        main_class: "has-header",
        extra_scripts: None,
    })
}

pub fn application_form_page(view: &ApplicationFormView<'_>) -> ViewResult<Html<String>> {
    let mut body = String::new();
    if let Some(error) = view.error.filter(|s| !s.is_empty()) {
        body.push_str(&alert(FeedbackKind::Error, error)?);
    }
    write!(
        body,
        r#"<input type="hidden" name="csrf_token" value="{}">"#,
        attr(view.csrf_token)
    )
    .unwrap();

    let name_attrs = [HtmlAttr::new("id", "name")];
    let name_input = render(
        &Input::new("name")
            .with_value(view.name)
            .with_attrs(&name_attrs)
            .required(),
    )?;
    body.push_str(&render(&Field::new("Name", trusted_html(&name_input)))?);

    let mut items_html = String::from(r#"<div id="uri-list">"#);
    let uris: Vec<&str> = if view.redirect_uris.is_empty() {
        vec![""]
    } else {
        view.redirect_uris.iter().map(String::as_str).collect()
    };
    for (idx, uri) in uris.iter().enumerate() {
        let input = render(
            &Input::new("redirect_uris")
                .with_value(uri)
                .with_placeholder("https://example.com/callback"),
        )?;
        let remove = r#"<button class="wf-btn ghost sm remove-btn" type="button" onclick="removeUri(this)">Remove</button>"#;
        let item = render(
            &RepeatableItem::new(&format!("URI {}", idx + 1), trusted_html(&input))
                .with_actions(trusted_html(remove)),
        )?;
        items_html.push_str(&item);
    }
    items_html.push_str("</div>");
    let add_attrs = [HtmlAttr::new("onclick", "addUri()")];
    let add = render(
        &Button::new("Add URI")
            .with_variant(ButtonVariant::Ghost)
            .with_size(ButtonSize::Small)
            .with_attrs(&add_attrs),
    )?;
    body.push_str(&render(
        &RepeatableArray::new("Redirect URIs", trusted_html(&items_html))
            .with_action(trusted_html(&add)),
    )?);

    let trusted_attrs = [HtmlAttr::new("id", "is_trusted")];
    let mut trusted = CheckRow::checkbox("is_trusted", "on", "Trusted (skip consent screen)")
        .with_attrs(&trusted_attrs);
    if view.is_trusted {
        trusted = trusted.checked();
    }
    body.push_str(&render(&trusted)?);
    if let Some(is_active) = view.is_active {
        let active_attrs = [HtmlAttr::new("id", "is_active")];
        let mut active = CheckRow::checkbox("is_active", "on", "Active").with_attrs(&active_attrs);
        if is_active {
            active = active.checked();
        }
        body.push_str(&render(&active)?);
    }

    let logo_attrs = [HtmlAttr::new("id", "logo_url")];
    let logo = render(
        &Input::new("logo_url")
            .with_value(view.logo_url)
            .with_attrs(&logo_attrs),
    )?;
    body.push_str(&render(&Field::new(
        "Logo URL (optional)",
        trusted_html(&logo),
    ))?);

    let color_attrs = [HtmlAttr::new("id", "primary_color")];
    let color = render(
        &Input::new("primary_color")
            .with_value(view.primary_color)
            .with_placeholder("#3B82F6")
            .with_attrs(&color_attrs),
    )?;
    body.push_str(&render(&Field::new(
        "Primary color (optional)",
        trusted_html(&color),
    ))?);

    let submit = render(&Button::primary(view.submit_label).with_button_type("submit"))?;
    let cancel = format!(
        r#"<a class="wf-link-quiet" href="{}">{}</a>"#,
        attr(&view.cancel_href),
        if view.is_active.is_some() {
            "Cancel"
        } else {
            "Back to applications"
        }
    );
    body.push_str(&render(
        &FormActions::new(trusted_html(&submit)).with_secondary(trusted_html(&cancel)),
    )?);
    let form = render(&Form::new(trusted_html(&body)).with_action(&view.action))?;
    let content = panel(None, &form);
    app_page(AppPage {
        shell: view.shell,
        title: &view.title,
        page_title: &view.page_title,
        crumbs_html: &view.crumbs,
        meta_html: None,
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header",
        extra_scripts: Some(application_form_script()),
    })
}

fn application_form_script() -> &'static str {
    r#"<script>
function addUri(){var container=document.getElementById('uri-list');var div=document.createElement('div');div.className='wf-repeatable-item';var head=document.createElement('div');head.className='wf-repeatable-item-head';var label=document.createElement('span');label.className='wf-repeatable-item-label';label.textContent='New URI';var input=document.createElement('input');input.type='text';input.name='redirect_uris';input.placeholder='https://example.com/callback';input.className='wf-input';var body=document.createElement('div');body.className='wf-repeatable-item-body';var btn=document.createElement('button');btn.type='button';btn.textContent='Remove';btn.className='wf-btn ghost sm remove-btn';btn.addEventListener('click',function(){removeUri(this);});head.appendChild(label);head.appendChild(btn);body.appendChild(input);div.appendChild(head);div.appendChild(body);container.appendChild(div);updateRemoveButtons();}
function removeUri(btn){btn.closest('.wf-repeatable-item').remove();updateRemoveButtons();}
function updateRemoveButtons(){var buttons=document.querySelectorAll('#uri-list .remove-btn');for(var i=0;i<buttons.length;i++){buttons[i].style.display=buttons.length<=1?'none':'';}}
updateRemoveButtons();
</script>"#
}

pub fn sessions_page(view: &SessionsPageView<'_>) -> ViewResult<Html<String>> {
    let meta = format!(
        "{} active session{}",
        view.total,
        if view.total == 1 { "" } else { "s" }
    );
    let mut content = String::from(
        r#"<style>.sessions-table{min-width:800px;width:100%}.sessions-table td:nth-child(3){max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}</style>"#,
    );
    if let Some(email) = view.filter_user_email {
        write!(
            content,
            r#"<div style="margin:16px 24px 0"><div class="wf-alert info"><div class="wf-alert-bar"></div><div><div class="wf-alert-kicker">Filtered</div><div>Showing sessions for <strong>{}</strong> <a class="wf-link" href="/admin/sessions">Show all</a></div></div></div></div>"#,
            text(email)
        )
        .unwrap();
    }

    if view.sessions.is_empty() {
        content.push_str(if view.filter_user_id.is_some() {
            r#"<p class="wf-empty">No active sessions for this user.</p>"#
        } else {
            r#"<p class="wf-empty">No active sessions.</p>"#
        });
    } else {
        let headers = [
            DataTableHeader::new("User").with_width(TableColumnWidth::Large),
            DataTableHeader::new("IP address"),
            DataTableHeader::new("User agent").with_width(TableColumnWidth::ExtraLarge),
            DataTableHeader::new("Created"),
            DataTableHeader::new("Expires"),
            DataTableHeader::new("").action_column(),
        ];
        let row_values: Vec<[String; 6]> = view
            .sessions
            .iter()
            .map(|session| {
                let id = session.id.to_string();
                let is_current = view.current_session_id == Some(id.as_str());
                let you = if is_current {
                    status_tag(FeedbackKind::Info, "You").unwrap_or_default()
                } else {
                    String::new()
                };
                let filter_user = view
                    .filter_user_id
                    .map(|uid| {
                        format!(
                            r#"<input type="hidden" name="user_id" value="{}">"#,
                            attr(uid)
                        )
                    })
                    .unwrap_or_default();
                let page = format!(
                    r#"<input type="hidden" name="page" value="{}">"#,
                    view.page
                );
                let revoke = render(
                    &Button::new("Revoke")
                        .with_variant(ButtonVariant::Danger)
                        .with_size(ButtonSize::Small)
                        .with_button_type("submit"),
                )
                .unwrap_or_else(|_| "Revoke".to_owned());
                [
                    format!(
                        r#"<a class="wf-link" href="/admin/users/{}">{}</a>{}"#,
                        session.user_id,
                        text(session.user_email.as_str()),
                        you
                    ),
                    session
                        .ip_address
                        .as_deref()
                        .map(text)
                        .unwrap_or_else(|| muted_badge("Unknown").unwrap_or_default()),
                    session
                        .user_agent
                        .as_deref()
                        .map(|ua| format!(r#"<span title="{}">{}</span>"#, attr(ua), text(ua)))
                        .unwrap_or_else(|| muted_badge("Unknown").unwrap_or_default()),
                    datefmt(&session.created_at),
                    datefmt(&session.expires_at),
                    format!(
                        r#"<form method="POST" action="/admin/sessions/{}/revoke" onsubmit="return confirm('This will end this session immediately.')"><input type="hidden" name="csrf_token" value="{}">{}{page}{revoke}</form>"#,
                        session.id,
                        attr(view.csrf_token),
                        filter_user
                    ),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::html(trusted_html(&v[0])),
                    DataTableCell::html(trusted_html(&v[1])),
                    DataTableCell::html(trusted_html(&v[2])),
                    DataTableCell::new(&v[3]),
                    DataTableCell::new(&v[4]),
                    DataTableCell::html(trusted_html(&v[5])),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .zip(view.sessions.iter())
            .map(|(cells, session)| {
                let id = session.id.to_string();
                let row = DataTableRow::new(cells);
                if view.current_session_id == Some(id.as_str()) {
                    row.selected()
                } else {
                    row
                }
            })
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let mut footer_html = None;
        if view.total_pages > 1 {
            let prev = if let Some(uid) = view.filter_user_id {
                format!(
                    "/admin/sessions?user_id={}&page={}",
                    url_encode(uid),
                    view.page - 1
                )
            } else {
                format!("/admin/sessions?page={}", view.page - 1)
            };
            let next = if let Some(uid) = view.filter_user_id {
                format!(
                    "/admin/sessions?user_id={}&page={}",
                    url_encode(uid),
                    view.page + 1
                )
            } else {
                format!("/admin/sessions?page={}", view.page + 1)
            };
            let pager = pagination(view.page, view.total_pages, prev, next)?;
            footer_html = Some(render(
                &TableFooter::new(trusted_html(&format!(
                    "Showing page {} of {} &middot; {} sessions",
                    view.page, view.total_pages, view.total
                )))
                .with_actions(trusted_html(&pager)),
            )?);
        }
        let mut wrap = TableWrap::new(trusted_html(&table));
        if let Some(footer) = footer_html.as_deref() {
            wrap = wrap.with_footer_component(trusted_html(footer));
        }
        content.push_str(&render(&wrap)?);
        let action = if let Some(uid) = view.filter_user_id {
            format!("/admin/sessions/revoke-all/{uid}")
        } else {
            "/admin/sessions/revoke-all".to_owned()
        };
        let label = if view.filter_user_id.is_some() {
            "Revoke all sessions for this user"
        } else {
            "Revoke all sessions"
        };
        let confirm = if view.filter_user_id.is_some() {
            "This will end all sessions for this user. They will be logged out immediately."
        } else {
            "This will end ALL active sessions for ALL users. Every user will be logged out immediately. Are you sure?"
        };
        let button = render(
            &Button::new(label)
                .with_variant(ButtonVariant::Danger)
                .with_button_type("submit"),
        )?;
        write!(
            content,
            r#"<div style="padding:16px 24px"><form method="POST" action="{}" onsubmit="return confirm('{}')"><input type="hidden" name="csrf_token" value="{}">{button}</form></div>"#,
            attr(&action),
            attr(confirm),
            attr(view.csrf_token)
        )
        .unwrap();
    }

    app_page(AppPage {
        shell: view.shell,
        title: "Sessions - allowthem",
        page_title: "SESSIONS",
        crumbs_html: "ALLOWTHEM &middot; ADMIN &middot; SESSIONS",
        meta_html: Some(&meta),
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header has-tablewrap",
        extra_scripts: None,
    })
}

pub fn users_page(view: &UsersPageView<'_>) -> ViewResult<Html<String>> {
    let meta = format!(
        "{} user{}",
        view.total,
        if view.total == 1 { "" } else { "s" }
    );
    let controls = user_filter_controls(view)?;
    let filter_bar = render(&FilterBar::new(trusted_html(&controls)))?;
    let mut content = panel(Some("Filter users"), &filter_bar);

    if view.users.is_empty() {
        content.push_str(r#"<p class="wf-empty">No users found.</p>"#);
    } else {
        let headers = [
            DataTableHeader::new("Email").with_width(TableColumnWidth::Large),
            DataTableHeader::new("Username"),
            DataTableHeader::new("Status"),
            DataTableHeader::new("MFA"),
            DataTableHeader::new("Registered"),
        ];
        let row_values: Vec<[String; 5]> = view
            .users
            .iter()
            .map(|user| {
                [
                    format!(
                        r#"<a class="wf-link" href="/admin/users/{}">{}</a>"#,
                        user.id,
                        text(user.email.as_str())
                    ),
                    user.username
                        .as_ref()
                        .map(|u| text(u.as_str()))
                        .unwrap_or_else(|| "&mdash;".to_owned()),
                    if user.is_active {
                        status_tag(FeedbackKind::Ok, "Active").unwrap_or_default()
                    } else {
                        muted_badge("Deactivated").unwrap_or_default()
                    },
                    if user.has_mfa {
                        status_tag(FeedbackKind::Ok, "Enabled").unwrap_or_default()
                    } else {
                        muted_badge("-").unwrap_or_default()
                    },
                    datefmt(&user.created_at),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::html(trusted_html(&v[0])),
                    DataTableCell::html(trusted_html(&v[1])),
                    DataTableCell::html(trusted_html(&v[2])),
                    DataTableCell::html(trusted_html(&v[3])),
                    DataTableCell::new(&v[4]),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let mut footer_html = None;
        if view.total_pages > 1 {
            let query = format!(
                "q={}&status={}&mfa={}&page=",
                url_encode(view.q),
                url_encode(view.status),
                url_encode(view.mfa)
            );
            let pager = pagination(
                view.page,
                view.total_pages,
                format!("/admin/users?{}{}", query, view.page - 1),
                format!("/admin/users?{}{}", query, view.page + 1),
            )?;
            footer_html = Some(render(
                &TableFooter::new(trusted_html(&format!(
                    "Showing page {} of {} &middot; {} users",
                    view.page, view.total_pages, view.total
                )))
                .with_actions(trusted_html(&pager)),
            )?);
        }
        let mut wrap = TableWrap::new(trusted_html(&table));
        if let Some(footer) = footer_html.as_deref() {
            wrap = wrap.with_footer_component(trusted_html(footer));
        }
        content.push_str(&render(&wrap)?);
    }

    app_page(AppPage {
        shell: view.shell,
        title: "Users - allowthem",
        page_title: "USERS",
        crumbs_html: "ALLOWTHEM &middot; ADMIN &middot; USERS",
        meta_html: Some(&meta),
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header has-tablewrap",
        extra_scripts: None,
    })
}

fn user_filter_controls(view: &UsersPageView<'_>) -> ViewResult<String> {
    let q_attrs = [HtmlAttr::new("id", "q")];
    let q = render(
        &Input::new("q")
            .with_value(view.q)
            .with_placeholder("Search email or username...")
            .with_attrs(&q_attrs),
    )?;
    let status_options = [
        SelectOption::new("", "All status"),
        if view.status == "active" {
            SelectOption::new("active", "Active").selected()
        } else {
            SelectOption::new("active", "Active")
        },
        if view.status == "deactivated" {
            SelectOption::new("deactivated", "Deactivated").selected()
        } else {
            SelectOption::new("deactivated", "Deactivated")
        },
    ];
    let status_attrs = [HtmlAttr::new("id", "status")];
    let status = render(&Select::new("status", &status_options).with_attrs(&status_attrs))?;
    let mfa_options = [
        SelectOption::new("", "All MFA"),
        if view.mfa == "yes" {
            SelectOption::new("yes", "MFA enabled").selected()
        } else {
            SelectOption::new("yes", "MFA enabled")
        },
        if view.mfa == "no" {
            SelectOption::new("no", "MFA not enabled").selected()
        } else {
            SelectOption::new("no", "MFA not enabled")
        },
    ];
    let mfa_attrs = [HtmlAttr::new("id", "mfa")];
    let mfa = render(&Select::new("mfa", &mfa_options).with_attrs(&mfa_attrs))?;
    let submit = render(&Button::primary("Search").with_button_type("submit"))?;
    Ok(format!(
        r#"<form method="GET" action="/admin/users" style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;"><div><label class="wf-label" for="q">Search</label>{q}</div><div><label class="wf-label" for="status">Status</label>{status}</div><div><label class="wf-label" for="mfa">MFA</label>{mfa}</div><div>{submit}</div></form>"#
    ))
}

pub fn audit_page(view: &AuditPageView<'_>) -> ViewResult<Html<String>> {
    let meta = format!(
        "{} event{}",
        view.total,
        if view.total == 1 { "" } else { "s" }
    );
    let controls = audit_filter_controls(view)?;
    let filter_bar = render(&FilterBar::new(trusted_html(&controls)))?;
    let mut head_actions = String::new();
    if view.total > 0 {
        let csv = audit_export_href(view, "csv");
        let json = audit_export_href(view, "json");
        let csv_button = render(
            &Button::link("CSV", &csv)
                .with_variant(ButtonVariant::Ghost)
                .with_size(ButtonSize::Small),
        )?;
        let json_button = render(
            &Button::link("JSON", &json)
                .with_variant(ButtonVariant::Ghost)
                .with_size(ButtonSize::Small),
        )?;
        head_actions = format!(
            r#"<span style="display:inline-flex;gap:8px;">{csv_button}{json_button}</span>"#
        );
    }
    let mut content = format!(
        r#"<section class="wf-panel" style="margin:16px 24px 24px;position:relative;z-index:1"><div class="wf-panel-head"><div class="wf-panel-title">Filter events</div>{head_actions}</div><div class="wf-panel-body">{filter_bar}</div></section>"#
    );

    if view.entries.is_empty() {
        content.push_str(r#"<p class="wf-empty">No audit events found.</p>"#);
    } else {
        let headers = [
            DataTableHeader::new("Time"),
            DataTableHeader::new("Event"),
            DataTableHeader::new("User").with_width(TableColumnWidth::Large),
            DataTableHeader::new("IP"),
            DataTableHeader::new("Detail").with_width(TableColumnWidth::ExtraLarge),
        ];
        let row_values: Vec<[String; 5]> = view
            .entries
            .iter()
            .map(|entry| {
                let event = if entry.is_failure {
                    render(&Tag::status(
                        FeedbackKind::Error,
                        entry.event_label.as_str(),
                    ))
                    .unwrap_or_else(|_| text(&entry.event_label))
                } else {
                    text(&entry.event_label)
                };
                let user = if let Some(email) = entry.user_email.as_deref() {
                    let href = entry
                        .user_id
                        .as_deref()
                        .map(|id| format!("/admin/users/{id}"))
                        .unwrap_or_else(|| "/admin/users".to_owned());
                    format!(
                        r#"<a class="wf-link" href="{}">{}</a>"#,
                        attr(&href),
                        text(email)
                    )
                } else if let Some(id) = entry.user_id.as_deref() {
                    short_id_html(id)
                } else {
                    "&mdash;".to_owned()
                };
                [
                    datefmt_str(&entry.created_at),
                    event,
                    user,
                    entry
                        .ip_address
                        .as_deref()
                        .map(text)
                        .unwrap_or_else(|| "&mdash;".to_owned()),
                    entry
                        .detail
                        .as_deref()
                        .map(|d| format!("<code>{}</code>", text(d)))
                        .unwrap_or_else(|| "&mdash;".to_owned()),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::new(&v[0]),
                    DataTableCell::html(trusted_html(&v[1])),
                    DataTableCell::html(trusted_html(&v[2])),
                    DataTableCell::html(trusted_html(&v[3])),
                    DataTableCell::html(trusted_html(&v[4])),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        let table = render(&DataTable::new(&headers, &rows).sticky())?;
        let mut footer_html = None;
        if view.total_pages > 1 {
            let query = audit_query_prefix(view);
            let pager = pagination(
                view.page,
                view.total_pages,
                format!("/admin/audit?{}{}", query, view.page - 1),
                format!("/admin/audit?{}{}", query, view.page + 1),
            )?;
            footer_html = Some(render(
                &TableFooter::new(trusted_html(&format!(
                    "Showing page {} of {} &middot; {} events",
                    view.page, view.total_pages, view.total
                )))
                .with_actions(trusted_html(&pager)),
            )?);
        }
        let mut wrap = TableWrap::new(trusted_html(&table));
        if let Some(footer) = footer_html.as_deref() {
            wrap = wrap.with_footer_component(trusted_html(footer));
        }
        content.push_str(&render(&wrap)?);
    }

    app_page(AppPage {
        shell: view.shell,
        title: "Audit log - allowthem",
        page_title: "AUDIT LOG",
        crumbs_html: "ALLOWTHEM &middot; ADMIN &middot; AUDIT",
        meta_html: Some(&meta),
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header has-tablewrap",
        extra_scripts: None,
    })
}

fn audit_filter_controls(view: &AuditPageView<'_>) -> ViewResult<String> {
    let user_attrs = [HtmlAttr::new("id", "user")];
    let user = render(
        &Input::new("user")
            .with_value(view.user)
            .with_placeholder("User ID...")
            .with_attrs(&user_attrs),
    )?;
    let event_options = [
        ("", "All events"),
        ("login", "Login"),
        ("login_failed", "Login failed"),
        ("logout", "Logout"),
        ("register", "Register"),
        ("password_change", "Password change"),
        ("password_reset", "Password reset"),
        ("role_assigned", "Role assigned"),
        ("role_unassigned", "Role unassigned"),
        ("permission_assigned", "Permission assigned"),
        ("permission_unassigned", "Permission unassigned"),
        ("session_created", "Session created"),
        ("session_expired", "Session expired"),
        ("user_updated", "User updated"),
        ("user_deleted", "User deleted"),
    ];
    let event_options: Vec<SelectOption<'_>> = event_options
        .iter()
        .map(|(value, label)| {
            let opt = SelectOption::new(value, label);
            if *value == view.event {
                opt.selected()
            } else {
                opt
            }
        })
        .collect();
    let event_attrs = [HtmlAttr::new("id", "event")];
    let event = render(&Select::new("event", &event_options).with_attrs(&event_attrs))?;
    let outcome_options = [
        if view.outcome.is_empty() {
            SelectOption::new("", "All").selected()
        } else {
            SelectOption::new("", "All")
        },
        if view.outcome == "success" {
            SelectOption::new("success", "Success").selected()
        } else {
            SelectOption::new("success", "Success")
        },
        if view.outcome == "failure" {
            SelectOption::new("failure", "Failure").selected()
        } else {
            SelectOption::new("failure", "Failure")
        },
    ];
    let outcome_attrs = [HtmlAttr::new("id", "outcome")];
    let outcome = render(&Select::new("outcome", &outcome_options).with_attrs(&outcome_attrs))?;
    let from_attrs = [HtmlAttr::new("id", "from")];
    let from = render(
        &Input::new("from")
            .with_type("date")
            .with_value(view.from)
            .with_attrs(&from_attrs),
    )?;
    let to_attrs = [HtmlAttr::new("id", "to")];
    let to = render(
        &Input::new("to")
            .with_type("date")
            .with_value(view.to)
            .with_attrs(&to_attrs),
    )?;
    let submit = render(&Button::primary("Search").with_button_type("submit"))?;
    Ok(format!(
        r#"<form method="GET" action="/admin/audit" style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;"><div><label class="wf-label" for="user">User ID</label>{user}</div><div><label class="wf-label" for="event">Event</label>{event}</div><div><label class="wf-label" for="outcome">Outcome</label>{outcome}</div><div><label class="wf-label" for="from">From</label>{from}</div><div><label class="wf-label" for="to">To</label>{to}</div><div>{submit}</div></form>"#
    ))
}

fn audit_query_prefix(view: &AuditPageView<'_>) -> String {
    format!(
        "user={}&event={}&outcome={}&from={}&to={}&page=",
        url_encode(view.user),
        url_encode(view.event),
        url_encode(view.outcome),
        url_encode(view.from),
        url_encode(view.to)
    )
}

fn audit_export_href(view: &AuditPageView<'_>, format: &str) -> String {
    format!(
        "/admin/audit?user={}&event={}&outcome={}&from={}&to={}&format={}",
        url_encode(view.user),
        url_encode(view.event),
        url_encode(view.outcome),
        url_encode(view.from),
        url_encode(view.to),
        format
    )
}

fn pagination(
    page: u32,
    total_pages: u32,
    prev_href: String,
    next_href: String,
) -> ViewResult<String> {
    let prev_href = prev_href.into_boxed_str();
    let next_href = next_href.into_boxed_str();
    let current = page.to_string();
    let mut links = Vec::with_capacity(3);
    if page > 1 {
        links.push(PageLink::link("Previous", &prev_href));
    } else {
        links.push(PageLink::disabled("Previous"));
    }
    links.push(PageLink::disabled(&current).active());
    if page < total_pages {
        links.push(PageLink::link("Next", &next_href));
    } else {
        links.push(PageLink::disabled("Next"));
    }
    render(&Pagination::new(&links))
}

fn short_id_html(raw: &str) -> String {
    let short = if raw.len() > 12 {
        format!("{}&hellip;", text(&raw[..12]))
    } else {
        text(raw)
    };
    format!(r#"<span title="{}">{short}</span>"#, attr(raw))
}

pub fn user_detail_page(view: &UserDetailView<'_>) -> ViewResult<Html<String>> {
    let username_meta = view
        .user
        .username
        .as_ref()
        .map(|u| format!(r#"<p class="wf-meta">@{}</p>"#, text(u.as_str())))
        .unwrap_or_default();
    let status = if view.user.is_active {
        status_tag(FeedbackKind::Ok, "Active")?
    } else {
        muted_badge("Deactivated")?
    };
    let username = view
        .user
        .username
        .as_ref()
        .map(|u| text(u.as_str()))
        .unwrap_or(muted_badge("Not set")?);
    let last_login = view
        .last_login
        .map(datefmt_str)
        .unwrap_or_else(|| "Never".to_owned());
    let mut profile = username_meta;
    write!(
        profile,
        r#"<dl class="wf-dl">
<div class="wf-dl-row"><dt>Email</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Username</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Status</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Email verified</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>MFA</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Registered</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Last login</dt><dd>{}</dd></div>
<div class="wf-dl-row"><dt>Updated</dt><dd>{}</dd></div>
</dl>"#,
        text(view.user.email.as_str()),
        username,
        status,
        if view.user.email_verified {
            "Yes"
        } else {
            "No"
        },
        if view.mfa_enabled {
            "Enabled"
        } else {
            "Not enabled"
        },
        datefmt(&view.user.created_at),
        last_login,
        datefmt(&view.user.updated_at)
    )
    .unwrap();

    let mut content = panel(None, &profile);

    let roles = if view.roles.is_empty() {
        r#"<p class="wf-empty">No roles assigned</p>"#.to_owned()
    } else {
        let mut html = String::from("<p>");
        for role in view.roles {
            html.push_str(&render(
                &Tag::new(role.name.as_str()).with_kind(FeedbackKind::Info),
            )?);
        }
        html.push_str("</p>");
        html
    };
    content.push_str(&panel(Some("Roles"), &roles));

    let oauth = if view.oauth_accounts.is_empty() {
        r#"<p class="wf-empty">No linked accounts</p>"#.to_owned()
    } else {
        let headers = [
            DataTableHeader::new("Provider"),
            DataTableHeader::new("Email"),
            DataTableHeader::new("Linked"),
        ];
        let row_values: Vec<[String; 3]> = view
            .oauth_accounts
            .iter()
            .map(|acct| {
                [
                    text(&acct.provider),
                    text(&acct.email),
                    datefmt(&acct.created_at),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::new(&v[0]),
                    DataTableCell::new(&v[1]),
                    DataTableCell::new(&v[2]),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        render(&DataTable::new(&headers, &rows))?
    };
    content.push_str(&panel(Some("OAuth accounts"), &oauth));

    let sessions = if view.sessions.is_empty() {
        r#"<p class="wf-empty">No active sessions</p>"#.to_owned()
    } else {
        let headers = [
            DataTableHeader::new("IP address"),
            DataTableHeader::new("User agent").with_width(TableColumnWidth::ExtraLarge),
            DataTableHeader::new("Created"),
            DataTableHeader::new("Expires"),
        ];
        let row_values: Vec<[String; 4]> = view
            .sessions
            .iter()
            .map(|session| {
                [
                    session
                        .ip_address
                        .as_deref()
                        .map(text)
                        .unwrap_or_else(|| "Unknown".to_owned()),
                    session
                        .user_agent
                        .as_deref()
                        .map(|ua| format!(r#"<span title="{}">{}</span>"#, attr(ua), text(ua)))
                        .unwrap_or_else(|| "Unknown".to_owned()),
                    datefmt(&session.created_at),
                    datefmt(&session.expires_at),
                ]
            })
            .collect();
        let cell_rows: Vec<Vec<DataTableCell<'_>>> = row_values
            .iter()
            .map(|v| {
                vec![
                    DataTableCell::new(&v[0]),
                    DataTableCell::html(trusted_html(&v[1])),
                    DataTableCell::new(&v[2]),
                    DataTableCell::new(&v[3]),
                ]
            })
            .collect();
        let rows: Vec<DataTableRow<'_>> = cell_rows
            .iter()
            .map(|cells| DataTableRow::new(cells))
            .collect();
        render(&DataTable::new(&headers, &rows))?
    };
    content.push_str(&panel(Some("Active sessions"), &sessions));

    let action_buttons = user_action_buttons(view)?;
    content.push_str(&panel(None, &action_buttons));

    let title = format!("{} - allowthem", view.user.email.as_str());
    let crumb_label = view
        .user
        .username
        .as_ref()
        .map(|u| u.as_str())
        .unwrap_or_else(|| view.user.email.as_str());
    let crumbs = format!(
        "ALLOWTHEM &middot; ADMIN &middot; USERS &middot; {}",
        text(crumb_label)
    );
    app_page(AppPage {
        shell: view.shell,
        title: &title,
        page_title: view.user.email.as_str(),
        crumbs_html: &crumbs,
        meta_html: None,
        content_html: &content,
        is_production: view.is_production,
        main_class: "has-header",
        extra_scripts: None,
    })
}

fn user_action_buttons(view: &UserDetailView<'_>) -> ViewResult<String> {
    let mut html = String::from("<p>");
    if view.user.is_active {
        let deactivate = render(
            &Button::new("Deactivate")
                .with_variant(ButtonVariant::Danger)
                .with_button_type("submit"),
        )?;
        let force = render(&Button::new("Force password reset").with_button_type("submit"))?;
        write!(
            html,
            r#"<form method="POST" action="/admin/users/{}/deactivate" style="display:inline" onsubmit="return confirm('This will deactivate the user and end all their sessions.')"><input type="hidden" name="csrf_token" value="{}">{deactivate}</form>
<form method="POST" action="/admin/users/{}/force-password-reset" style="display:inline" onsubmit="return confirm('This will invalidate the user password, end all sessions, and send a password reset email.')"><input type="hidden" name="csrf_token" value="{}">{force}</form>"#,
            view.user.id,
            attr(view.csrf_token),
            view.user.id,
            attr(view.csrf_token)
        )
        .unwrap();
    } else {
        let reactivate = render(
            &Button::new("Reactivate")
                .with_variant(ButtonVariant::Primary)
                .with_button_type("submit"),
        )?;
        write!(
            html,
            r#"<form method="POST" action="/admin/users/{}/reactivate" style="display:inline"><input type="hidden" name="csrf_token" value="{}">{reactivate}</form>"#,
            view.user.id,
            attr(view.csrf_token)
        )
        .unwrap();
    }
    html.push_str(r#"</p><p><a class="wf-link-quiet" href="/admin/users">Back to users</a></p>"#);
    Ok(html)
}
