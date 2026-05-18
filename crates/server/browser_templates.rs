use std::sync::Arc;

use axum::response::Html;
use minijinja::value::{Kwargs, Value};
use minijinja::{Environment, Error, ErrorKind};
use wavefunk_ui::Template;
use wavefunk_ui::components::{
    Alert, Button, ButtonSize, ButtonVariant, CheckRow, FeedbackKind, Field, Form, FormActions,
    FormPanel, FormSection, HtmlAttr, InlineFormRow, Input, Minibuffer, Modeline, ModelineSegment,
    NavItem, NavSection, PageHeader, RepeatableArray, RepeatableItem, Select, SelectOption,
    SettingsSection, SplitShell, Switch, Textarea,
};
use wavefunk_ui::layouts::AppShell;

use crate::browser_error::BrowserError;
use crate::ui::{render_component, trusted_html};

const BASE_HTML: &str = include_str!("templates/base.html");
const LOGIN_HTML: &str = include_str!("templates/login.html");
const REGISTER_HTML: &str = include_str!("templates/register.html");
const SETTINGS_HTML: &str = include_str!("templates/settings.html");
const CONSENT_HTML: &str = include_str!("templates/consent.html");
const FORGOT_PASSWORD_HTML: &str = include_str!("templates/forgot_password.html");
const RESET_PASSWORD_HTML: &str = include_str!("templates/reset_password.html");
const MFA_SETUP_HTML: &str = include_str!("templates/mfa_setup.html");
const MFA_RECOVERY_HTML: &str = include_str!("templates/mfa_recovery.html");
const MFA_CHALLENGE_HTML: &str = include_str!("templates/mfa_challenge.html");
const MODELINE_PARTIAL: &str = include_str!("templates/_partials/_modeline.html");
const FLASH_PARTIAL: &str = include_str!("templates/_partials/_flash.html");
const SPLASH_PARTIAL: &str = include_str!("templates/_partials/_splash.html");
const AUTH_SHELL_PARTIAL: &str = include_str!("templates/_partials/_auth_shell.html");
const APP_SHELL_PARTIAL: &str = include_str!("templates/_partials/_app_shell.html");
const SIDEBAR_NAV_PARTIAL: &str = include_str!("templates/_partials/_sidebar_nav.html");
const AUTH_MACROS_PARTIAL: &str = include_str!("templates/_partials/_auth_macros.html");
const AUTH_OOB_HEAD_PARTIAL: &str = include_str!("templates/_partials/_auth_oob_head.html");
const AUTH_MAIN_LOGIN_PARTIAL: &str = include_str!("templates/_partials/_auth_main_login.html");
const AUTH_MAIN_REGISTER_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_register.html");
const AUTH_MAIN_FORGOT_PW_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_forgot_password.html");
const AUTH_MAIN_RESET_PW_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_reset_password.html");
const AUTH_MAIN_MFA_CHALLENGE_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_challenge.html");
const AUTH_MAIN_MFA_SETUP_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_setup.html");
const AUTH_MAIN_MFA_RECOVERY_PARTIAL: &str =
    include_str!("templates/_partials/_auth_main_mfa_recovery.html");
const AUTH_MAIN_CONSENT_PARTIAL: &str = include_str!("templates/_partials/_auth_main_consent.html");
const ERROR_HTML: &str = include_str!("templates/error.html");

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

fn attr_pairs<'a>(pairs: &'a [(&'static str, String)]) -> Vec<HtmlAttr<'a>> {
    pairs
        .iter()
        .map(|(name, value)| HtmlAttr::new(*name, value.as_str()))
        .collect()
}

fn push_attr(pairs: &mut Vec<(&'static str, String)>, name: &'static str, value: Option<String>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        pairs.push((name, value));
    }
}

fn push_bool_attr(pairs: &mut Vec<(&'static str, String)>, name: &'static str, value: bool) {
    if value {
        pairs.push((name, String::new()));
    }
}

fn button_variant(value: Option<&str>) -> ButtonVariant {
    match value {
        Some("primary") => ButtonVariant::Primary,
        Some("ghost") => ButtonVariant::Ghost,
        Some("danger") => ButtonVariant::Danger,
        _ => ButtonVariant::Default,
    }
}

fn button_size(value: Option<&str>) -> ButtonSize {
    match value {
        Some("sm") | Some("small") => ButtonSize::Small,
        Some("lg") | Some("large") => ButtonSize::Large,
        _ => ButtonSize::Default,
    }
}

fn wf_button(label: String, kwargs: Kwargs) -> Result<Value, Error> {
    let href: Option<String> = kwargs.get("href")?;
    let variant: Option<String> = kwargs.get("variant")?;
    let size: Option<String> = kwargs.get("size")?;
    let button_type: Option<String> = kwargs.get("type")?;
    let id: Option<String> = kwargs.get("id")?;
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    let attrs = attr_pairs(&attr_values);

    let mut button = Button::new(&label)
        .with_variant(button_variant(variant.as_deref()))
        .with_size(button_size(size.as_deref()))
        .with_attrs(&attrs);
    if let Some(href) = href.as_deref().filter(|value| !value.is_empty()) {
        button = button.with_href(href);
    }
    if let Some(button_type) = button_type.as_deref().filter(|value| !value.is_empty()) {
        button = button.with_button_type(button_type);
    }
    if disabled {
        button = button.disabled();
    }

    safe_component_value(&button, "Button")
}

fn wf_input(name: String, kwargs: Kwargs) -> Result<Value, Error> {
    let input_type: Option<String> = kwargs.get("type")?;
    let value: Option<String> = kwargs.get("value")?;
    let placeholder: Option<String> = kwargs.get("placeholder")?;
    let id: Option<String> = kwargs.get("id")?;
    let autocomplete: Option<String> = kwargs.get("autocomplete")?;
    let minlength: Option<String> = kwargs.get("minlength")?;
    let maxlength: Option<String> = kwargs.get("maxlength")?;
    let min: Option<String> = kwargs.get("min")?;
    let max: Option<String> = kwargs.get("max")?;
    let pattern: Option<String> = kwargs.get("pattern")?;
    let spellcheck: Option<String> = kwargs.get("spellcheck")?;
    let style: Option<String> = kwargs.get("style")?;
    let hx_get: Option<String> = kwargs.get("hx_get")?;
    let hx_target: Option<String> = kwargs.get("hx_target")?;
    let hx_trigger: Option<String> = kwargs.get("hx_trigger")?;
    let required = kwargs.get::<Option<bool>>("required")?.unwrap_or(false);
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    let readonly = kwargs.get::<Option<bool>>("readonly")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    push_attr(&mut attr_values, "autocomplete", autocomplete);
    push_attr(&mut attr_values, "minlength", minlength);
    push_attr(&mut attr_values, "maxlength", maxlength);
    push_attr(&mut attr_values, "min", min);
    push_attr(&mut attr_values, "max", max);
    push_attr(&mut attr_values, "pattern", pattern);
    push_attr(&mut attr_values, "spellcheck", spellcheck);
    push_attr(&mut attr_values, "style", style);
    push_attr(&mut attr_values, "hx-get", hx_get);
    push_attr(&mut attr_values, "hx-target", hx_target);
    push_attr(&mut attr_values, "hx-trigger", hx_trigger);
    push_bool_attr(&mut attr_values, "readonly", readonly);
    let attrs = attr_pairs(&attr_values);

    let mut input = Input::new(&name).with_attrs(&attrs);
    if let Some(input_type) = input_type.as_deref().filter(|value| !value.is_empty()) {
        input = input.with_type(input_type);
    }
    if let Some(value) = value.as_deref() {
        input = input.with_value(value);
    }
    if let Some(placeholder) = placeholder.as_deref().filter(|value| !value.is_empty()) {
        input = input.with_placeholder(placeholder);
    }
    if required {
        input = input.required();
    }
    if disabled {
        input = input.disabled();
    }

    safe_component_value(&input, "Input")
}

fn wf_textarea(name: String, kwargs: Kwargs) -> Result<Value, Error> {
    let value: Option<String> = kwargs.get("value")?;
    let placeholder: Option<String> = kwargs.get("placeholder")?;
    let rows = kwargs.get::<Option<u16>>("rows")?;
    let id: Option<String> = kwargs.get("id")?;
    let minlength: Option<String> = kwargs.get("minlength")?;
    let maxlength: Option<String> = kwargs.get("maxlength")?;
    let autocomplete: Option<String> = kwargs.get("autocomplete")?;
    let required = kwargs.get::<Option<bool>>("required")?.unwrap_or(false);
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    push_attr(&mut attr_values, "minlength", minlength);
    push_attr(&mut attr_values, "maxlength", maxlength);
    push_attr(&mut attr_values, "autocomplete", autocomplete);
    let attrs = attr_pairs(&attr_values);

    let mut textarea = Textarea::new(&name).with_attrs(&attrs);
    if let Some(value) = value.as_deref() {
        textarea = textarea.with_value(value);
    }
    if let Some(placeholder) = placeholder.as_deref().filter(|value| !value.is_empty()) {
        textarea = textarea.with_placeholder(placeholder);
    }
    if let Some(rows) = rows {
        textarea = textarea.with_rows(rows);
    }
    if required {
        textarea = textarea.required();
    }
    if disabled {
        textarea = textarea.disabled();
    }

    safe_component_value(&textarea, "Textarea")
}

fn wf_field(label: String, control_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let hint: Option<String> = kwargs.get("hint")?;
    kwargs.assert_all_used()?;

    let mut field = Field::new(&label, trusted_html(&control_html));
    if let Some(hint) = hint.as_deref().filter(|value| !value.is_empty()) {
        field = field.with_hint(hint);
    }

    safe_component_value(&field, "Field")
}

fn wf_check_row(
    name: String,
    value: String,
    label: String,
    kwargs: Kwargs,
) -> Result<Value, Error> {
    let kind: Option<String> = kwargs.get("kind")?;
    let id: Option<String> = kwargs.get("id")?;
    let checked = kwargs.get::<Option<bool>>("checked")?.unwrap_or(false);
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    let attrs = attr_pairs(&attr_values);

    let mut row = if kind.as_deref() == Some("radio") {
        CheckRow::radio(&name, &value, &label)
    } else {
        CheckRow::checkbox(&name, &value, &label)
    }
    .with_attrs(&attrs);
    if checked {
        row = row.checked();
    }
    if disabled {
        row = row.disabled();
    }

    safe_component_value(&row, "CheckRow")
}

fn wf_select(name: String, options: Vec<String>, kwargs: Kwargs) -> Result<Value, Error> {
    let selected: Option<String> = kwargs.get("selected")?;
    let placeholder: Option<String> = kwargs.get("placeholder")?;
    let id: Option<String> = kwargs.get("id")?;
    let required = kwargs.get::<Option<bool>>("required")?.unwrap_or(false);
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    let attrs = attr_pairs(&attr_values);

    let selected_value = selected.as_deref().unwrap_or("");
    let mut select_options = Vec::new();
    if let Some(placeholder) = placeholder.as_deref().filter(|value| !value.is_empty()) {
        let mut option = SelectOption::new("", placeholder);
        if selected_value.is_empty() {
            option = option.selected();
        }
        if required {
            option = option.disabled();
        }
        select_options.push(option);
    }
    for option in &options {
        let mut select_option = SelectOption::new(option, option);
        if selected_value == option {
            select_option = select_option.selected();
        }
        select_options.push(select_option);
    }

    let mut select = Select::new(&name, &select_options).with_attrs(&attrs);
    if required {
        select = select.required();
    }
    if disabled {
        select = select.disabled();
    }

    safe_component_value(&select, "Select")
}

fn wf_switch(name: String, kwargs: Kwargs) -> Result<Value, Error> {
    let value: Option<String> = kwargs.get("value")?;
    let id: Option<String> = kwargs.get("id")?;
    let checked = kwargs.get::<Option<bool>>("checked")?.unwrap_or(false);
    let disabled = kwargs.get::<Option<bool>>("disabled")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    let attrs = attr_pairs(&attr_values);

    let mut switch = Switch::new(&name).with_attrs(&attrs);
    if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
        switch = switch.with_value(value);
    }
    if checked {
        switch = switch.checked();
    }
    if disabled {
        switch = switch.disabled();
    }

    safe_component_value(&switch, "Switch")
}

fn wf_form(body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let action: Option<String> = kwargs.get("action")?;
    let method: Option<String> = kwargs.get("method")?;
    let id: Option<String> = kwargs.get("id")?;
    let autocomplete: Option<String> = kwargs.get("autocomplete")?;
    let style: Option<String> = kwargs.get("style")?;
    kwargs.assert_all_used()?;

    let mut attr_values = Vec::new();
    push_attr(&mut attr_values, "id", id);
    push_attr(&mut attr_values, "autocomplete", autocomplete);
    push_attr(&mut attr_values, "style", style);
    let attrs = attr_pairs(&attr_values);

    let mut form = Form::new(trusted_html(&body_html)).with_attrs(&attrs);
    if let Some(action) = action.as_deref().filter(|value| !value.is_empty()) {
        form = form.with_action(action);
    }
    if let Some(method) = method.as_deref().filter(|value| !value.is_empty()) {
        form = form.with_method(method);
    }

    safe_component_value(&form, "Form")
}

fn wf_form_section(title: String, body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let description: Option<String> = kwargs.get("description")?;
    let actions_html: Option<String> = kwargs.get("actions_html")?;
    kwargs.assert_all_used()?;

    let mut section = FormSection::new(&title, trusted_html(&body_html));
    if let Some(description) = description.as_deref().filter(|value| !value.is_empty()) {
        section = section.with_description(description);
    }
    if let Some(actions_html) = actions_html.as_deref().filter(|value| !value.is_empty()) {
        section = section.with_actions(trusted_html(actions_html));
    }

    safe_component_value(&section, "FormSection")
}

fn wf_form_actions(primary_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let secondary_html: Option<String> = kwargs.get("secondary_html")?;
    kwargs.assert_all_used()?;

    let mut actions = FormActions::new(trusted_html(&primary_html));
    if let Some(secondary_html) = secondary_html.as_deref().filter(|value| !value.is_empty()) {
        actions = actions.with_secondary(trusted_html(secondary_html));
    }

    safe_component_value(&actions, "FormActions")
}

fn wf_settings_section(title: String, body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let description: Option<String> = kwargs.get("description")?;
    let action_html: Option<String> = kwargs.get("action_html")?;
    let danger = kwargs.get::<Option<bool>>("danger")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut section = SettingsSection::new(&title, trusted_html(&body_html));
    if let Some(description) = description.as_deref().filter(|value| !value.is_empty()) {
        section = section.with_description(description);
    }
    if let Some(action_html) = action_html.as_deref().filter(|value| !value.is_empty()) {
        section = section.with_action(trusted_html(action_html));
    }
    if danger {
        section = section.danger();
    }

    safe_component_value(&section, "SettingsSection")
}

fn wf_inline_form_row(label: String, control_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let hint: Option<String> = kwargs.get("hint")?;
    let action_html: Option<String> = kwargs.get("action_html")?;
    kwargs.assert_all_used()?;

    let mut row = InlineFormRow::new(&label, trusted_html(&control_html));
    if let Some(hint) = hint.as_deref().filter(|value| !value.is_empty()) {
        row = row.with_hint(hint);
    }
    if let Some(action_html) = action_html.as_deref().filter(|value| !value.is_empty()) {
        row = row.with_action(trusted_html(action_html));
    }

    safe_component_value(&row, "InlineFormRow")
}

fn wf_repeatable_array(label: String, items_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let description: Option<String> = kwargs.get("description")?;
    let action_html: Option<String> = kwargs.get("action_html")?;
    kwargs.assert_all_used()?;

    let mut array = RepeatableArray::new(&label, trusted_html(&items_html));
    if let Some(description) = description.as_deref().filter(|value| !value.is_empty()) {
        array = array.with_description(description);
    }
    if let Some(action_html) = action_html.as_deref().filter(|value| !value.is_empty()) {
        array = array.with_action(trusted_html(action_html));
    }

    safe_component_value(&array, "RepeatableArray")
}

fn wf_repeatable_item(label: String, body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let actions_html: Option<String> = kwargs.get("actions_html")?;
    kwargs.assert_all_used()?;

    let mut item = RepeatableItem::new(&label, trusted_html(&body_html));
    if let Some(actions_html) = actions_html.as_deref().filter(|value| !value.is_empty()) {
        item = item.with_actions(trusted_html(actions_html));
    }

    safe_component_value(&item, "RepeatableItem")
}

fn wf_form_panel(title: String, body_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let subtitle: Option<String> = kwargs.get("subtitle")?;
    let meta_html: Option<String> = kwargs.get("meta_html")?;
    let actions_html: Option<String> = kwargs.get("actions_html")?;
    kwargs.assert_all_used()?;

    let mut panel = FormPanel::new(&title, trusted_html(&body_html));
    if let Some(subtitle) = subtitle.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_subtitle(subtitle);
    }
    if let Some(meta_html) = meta_html.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_meta(trusted_html(meta_html));
    }
    if let Some(actions_html) = actions_html.as_deref().filter(|value| !value.is_empty()) {
        panel = panel.with_actions(trusted_html(actions_html));
    }

    safe_component_value(&panel, "FormPanel")
}

fn wf_split_shell(content_html: String, kwargs: Kwargs) -> Result<Value, Error> {
    let visual_html: Option<String> = kwargs.get("visual_html")?;
    let top_html: Option<String> = kwargs.get("top_html")?;
    let footer_html: Option<String> = kwargs.get("footer_html")?;
    let mode: Option<String> = kwargs.get("mode")?;
    let mode_locked = kwargs.get::<Option<bool>>("mode_locked")?.unwrap_or(false);
    kwargs.assert_all_used()?;

    let mut shell = SplitShell::new(trusted_html(&content_html));
    if let Some(visual_html) = visual_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_visual(trusted_html(visual_html));
    }
    if let Some(top_html) = top_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_top(trusted_html(top_html));
    }
    if let Some(footer_html) = footer_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_footer(trusted_html(footer_html));
    }
    if let Some(mode) = mode.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_mode(mode);
    }
    if mode_locked {
        shell = shell.mode_locked();
    }

    safe_component_value(&shell, "SplitShell")
}

fn wf_app_shell(
    title: String,
    app_name: String,
    content_html: String,
    kwargs: Kwargs,
) -> Result<Value, Error> {
    let nav_html: Option<String> = kwargs.get("nav_html")?;
    let nav_aria_label: Option<String> = kwargs.get("nav_aria_label")?;
    let breadcrumbs_html: Option<String> = kwargs.get("breadcrumbs_html")?;
    let topbar_html: Option<String> = kwargs.get("topbar_html")?;
    let page_header_html: Option<String> = kwargs.get("page_header_html")?;
    let footer_html: Option<String> = kwargs.get("footer_html")?;
    let main_class: Option<String> = kwargs.get("main_class")?;
    let brand_href: Option<String> = kwargs.get("brand_href")?;
    let head_html: Option<String> = kwargs.get("head_html")?;
    let scripts_html: Option<String> = kwargs.get("scripts_html")?;
    let mode: Option<String> = kwargs.get("mode")?;
    let mode_locked = kwargs.get::<Option<bool>>("mode_locked")?.unwrap_or(false);
    let body_hx_boost = kwargs.get::<Option<bool>>("body_hx_boost")?.unwrap_or(true);
    kwargs.assert_all_used()?;

    let title = title.trim().to_owned();
    let app_name = app_name.trim().to_owned();
    let mut shell = AppShell::new(&title, &app_name, &content_html);
    if let Some(nav_html) = nav_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_nav(nav_html);
    }
    if let Some(nav_aria_label) = nav_aria_label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_nav_aria_label(nav_aria_label);
    }
    if let Some(breadcrumbs_html) = breadcrumbs_html
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_breadcrumbs(trusted_html(breadcrumbs_html));
    }
    if let Some(topbar_html) = topbar_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_topbar(trusted_html(topbar_html));
    }
    if let Some(page_header_html) = page_header_html
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_page_header(trusted_html(page_header_html));
    }
    if let Some(footer_html) = footer_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_footer(trusted_html(footer_html));
    }
    if let Some(main_class) = main_class
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_main_class(main_class);
    }
    if let Some(brand_href) = brand_href
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        shell = shell.with_brand_href(brand_href);
    }
    if let Some(head_html) = head_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_head(trusted_html(head_html));
    }
    if let Some(scripts_html) = scripts_html.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_scripts(trusted_html(scripts_html));
    }
    if let Some(mode) = mode.as_deref().filter(|value| !value.is_empty()) {
        shell = shell.with_mode(mode);
    }
    if mode_locked {
        shell = shell.mode_locked();
    }
    if !body_hx_boost {
        shell = shell.without_body_hx_boost();
    }

    safe_component_value(&shell, "AppShell")
}

fn wf_page_header(title: String, kwargs: Kwargs) -> Result<Value, Error> {
    let subtitle: Option<String> = kwargs.get("subtitle")?;
    let meta_html: Option<String> = kwargs.get("meta_html")?;
    let primary_html: Option<String> = kwargs.get("primary_html")?;
    let secondary_html: Option<String> = kwargs.get("secondary_html")?;
    kwargs.assert_all_used()?;

    let title = title.trim().to_owned();
    let mut header = PageHeader::new(&title);
    if let Some(subtitle) = subtitle.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_subtitle(subtitle);
    }
    if let Some(meta_html) = meta_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_meta(trusted_html(meta_html));
    }
    if let Some(primary_html) = primary_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_primary(trusted_html(primary_html));
    }
    if let Some(secondary_html) = secondary_html.as_deref().filter(|value| !value.is_empty()) {
        header = header.with_secondary(trusted_html(secondary_html));
    }

    safe_component_value(&header, "PageHeader")
}

fn feedback_kind(kind: &str) -> FeedbackKind {
    match kind {
        "ok" | "success" => FeedbackKind::Ok,
        "warn" | "warning" => FeedbackKind::Warn,
        "err" | "error" | "danger" => FeedbackKind::Error,
        _ => FeedbackKind::Info,
    }
}

fn wf_alert(kind: String, message: String, kwargs: Kwargs) -> Result<Value, Error> {
    let title: Option<String> = kwargs.get("title")?;
    kwargs.assert_all_used()?;

    let mut alert = Alert::new(feedback_kind(kind.trim()), &message);
    if let Some(title) = title.as_deref().filter(|value| !value.is_empty()) {
        alert = alert.with_title(title);
    }
    safe_component_value(&alert, "Alert")
}

fn wf_modeline(status_env: String, status_session: Option<String>) -> Result<Value, Error> {
    let screen_label =
        ModelineSegment::text("").with_html(trusted_html(r#"<span id="wf-screen-label"></span>"#));
    let left = [
        ModelineSegment::chevron("AT"),
        ModelineSegment::text(status_env.trim()),
        screen_label,
    ];

    let session_label = status_session
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("ANON");
    let logout_attrs = [
        HtmlAttr::new("title", "Sign out"),
        HtmlAttr::new("aria-label", "Sign out"),
    ];
    let mode_attrs = [
        HtmlAttr::new("data-mode-toggle", ""),
        HtmlAttr::new("title", "Toggle color mode"),
        HtmlAttr::new("aria-label", "Toggle color mode"),
    ];
    let mut right = vec![ModelineSegment::text(session_label)];
    if session_label != "ANON" {
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
    let modeline = Modeline::new(&left)
        .with_right(&right)
        .with_attrs(&modeline_attrs);
    safe_component_value(&modeline, "Modeline")
}

fn wf_minibuffer() -> Result<Value, Error> {
    let minibuffer = Minibuffer::new().with_prompt("λ");
    safe_component_value(&minibuffer, "Minibuffer")
}

fn wf_nav_section(label: String) -> Result<Value, Error> {
    let label = label.trim().to_owned();
    safe_component_value(&NavSection::new(&label), "NavSection")
}

fn wf_nav_item(label: String, href: String, active: Option<bool>) -> Result<Value, Error> {
    let label = label.trim().to_owned();
    let href = href.trim().to_owned();
    let mut item = NavItem::new(&label, &href);
    if active.unwrap_or(false) {
        item = item.active();
    }
    safe_component_value(&item, "NavItem")
}

/// Register the default browser templates into an existing environment.
///
/// Useful for consumers (like the standalone binary) that need to extend
/// the default template set with additional templates of their own.
///
/// # Integrator-overridable blocks (auth shell)
///
/// `_partials/_auth_shell.html` exposes two named blocks that integrators
/// can override from a child template without forking the shell:
///
/// - `splash_content` — replaces the splash aside's body (left column).
///   Default includes `_partials/_splash.html`, which renders a shader
///   canvas (or sandboxed iframe when `branding.splash_url` is set).
/// - `auth_main` — replaces the entire `<main class="wf-auth-form">`
///   subtree. During the z3c migration (C3–C10) the default body of this
///   block contains a transitional bridge that re-exposes
///   `{% block auth_top %}` and `{% block form %}` sub-blocks so
///   un-migrated pages keep working. Once all pages have migrated to their
///   `_auth_main_<page>.html` partials, the bridge and its sub-blocks will
///   be removed and `auth_main` becomes the sole integrator entry point.
///
/// Both blocks are safe to override in integrator templates that
/// `{% extends "_partials/_auth_shell.html" %}` — the surrounding
/// `SplitShell` visual/content slots are owned by the shell and remain
/// stable.
///
/// # Integrator-overridable blocks (app shell)
///
/// `_partials/_app_shell.html` exposes six named blocks on the
/// post-auth surface for pageheader / panel / layout customisation.
/// Each default is empty (or a safe passthrough); built-in admin and
/// settings pages override them as appropriate:
///
/// - `pagetitle` — page title inside `<h1 class="wf-pagetitle">`.
///   Default: empty.
/// - `crumbs` — breadcrumb line inside `<div class="wf-crumbs">`.
///   Default: empty.
/// - `page_meta` — right-aligned status cluster inside
///   `<div class="wf-page-meta">` within `.wf-pageheader`. Default: empty.
/// - `topbar` — row above the pageheader, typically a search or
///   command-K bar inside `.wf-topbar`. Default: empty.
/// - `main_class` — modifier class on `<div class="wf-main">`.
///   Default: `has-header`. List pages override to `has-tablewrap` so
///   the grid makes room for a `.wf-tablewrap` region below the header.
/// - `page_content` — replaces the `.wf-scroll > {% block content %}`
///   body wholesale. Default: passthrough that renders `{% block content %}`
///   unchanged, so templates predating the pageheader chrome keep working.
///
/// All six blocks are safe to override from any child template that
/// `{% extends "_partials/_app_shell.html" %}`. The surrounding
/// `.wf-shell` / `.wf-sidebar` / `.wf-main` structure is owned by the
/// shell and remains stable.
pub fn add_default_browser_templates(env: &mut Environment<'static>) {
    env.add_function("wf_alert", wf_alert);
    env.add_function("wf_app_shell", wf_app_shell);
    env.add_function("wf_button", wf_button);
    env.add_function("wf_check_row", wf_check_row);
    env.add_function("wf_field", wf_field);
    env.add_function("wf_form", wf_form);
    env.add_function("wf_form_actions", wf_form_actions);
    env.add_function("wf_form_panel", wf_form_panel);
    env.add_function("wf_form_section", wf_form_section);
    env.add_function("wf_inline_form_row", wf_inline_form_row);
    env.add_function("wf_input", wf_input);
    env.add_function("wf_minibuffer", wf_minibuffer);
    env.add_function("wf_modeline", wf_modeline);
    env.add_function("wf_nav_item", wf_nav_item);
    env.add_function("wf_nav_section", wf_nav_section);
    env.add_function("wf_page_header", wf_page_header);
    env.add_function("wf_repeatable_array", wf_repeatable_array);
    env.add_function("wf_repeatable_item", wf_repeatable_item);
    env.add_function("wf_select", wf_select);
    env.add_function("wf_settings_section", wf_settings_section);
    env.add_function("wf_split_shell", wf_split_shell);
    env.add_function("wf_switch", wf_switch);
    env.add_function("wf_textarea", wf_textarea);

    env.add_filter("datefmt", |value: String| -> String {
        if value.len() >= 16 {
            let date = &value[..10];
            let time = &value[11..16];
            format!("{date} {time} UTC")
        } else {
            value
        }
    });

    env.add_template_owned("base.html", BASE_HTML)
        .expect("base.html");
    env.add_template_owned("login.html", LOGIN_HTML)
        .expect("login.html");
    env.add_template_owned("register.html", REGISTER_HTML)
        .expect("register.html");
    env.add_template_owned("settings.html", SETTINGS_HTML)
        .expect("settings.html");
    env.add_template_owned("consent.html", CONSENT_HTML)
        .expect("consent.html");
    env.add_template_owned("forgot_password.html", FORGOT_PASSWORD_HTML)
        .expect("forgot_password.html");
    env.add_template_owned("reset_password.html", RESET_PASSWORD_HTML)
        .expect("reset_password.html");
    env.add_template_owned("mfa_setup.html", MFA_SETUP_HTML)
        .expect("mfa_setup.html");
    env.add_template_owned("mfa_recovery.html", MFA_RECOVERY_HTML)
        .expect("mfa_recovery.html");
    env.add_template_owned("mfa_challenge.html", MFA_CHALLENGE_HTML)
        .expect("mfa_challenge.html");
    env.add_template_owned("_partials/_modeline.html", MODELINE_PARTIAL)
        .expect("_partials/_modeline.html");
    env.add_template_owned("_partials/_flash.html", FLASH_PARTIAL)
        .expect("_partials/_flash.html");
    env.add_template_owned("_partials/_splash.html", SPLASH_PARTIAL)
        .expect("_partials/_splash.html");
    env.add_template_owned("_partials/_auth_shell.html", AUTH_SHELL_PARTIAL)
        .expect("_partials/_auth_shell.html");
    env.add_template_owned("_partials/_app_shell.html", APP_SHELL_PARTIAL)
        .expect("_partials/_app_shell.html");
    env.add_template_owned("_partials/_sidebar_nav.html", SIDEBAR_NAV_PARTIAL)
        .expect("_partials/_sidebar_nav.html");
    env.add_template_owned("_partials/_auth_macros.html", AUTH_MACROS_PARTIAL)
        .expect("_partials/_auth_macros.html");
    env.add_template_owned("_partials/_auth_oob_head.html", AUTH_OOB_HEAD_PARTIAL)
        .expect("_partials/_auth_oob_head.html");
    env.add_template_owned("_partials/_auth_main_login.html", AUTH_MAIN_LOGIN_PARTIAL)
        .expect("_partials/_auth_main_login.html");
    env.add_template_owned(
        "_partials/_auth_main_register.html",
        AUTH_MAIN_REGISTER_PARTIAL,
    )
    .expect("_partials/_auth_main_register.html");
    env.add_template_owned(
        "_partials/_auth_main_forgot_password.html",
        AUTH_MAIN_FORGOT_PW_PARTIAL,
    )
    .expect("_partials/_auth_main_forgot_password.html");
    env.add_template_owned(
        "_partials/_auth_main_reset_password.html",
        AUTH_MAIN_RESET_PW_PARTIAL,
    )
    .expect("_partials/_auth_main_reset_password.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_challenge.html",
        AUTH_MAIN_MFA_CHALLENGE_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_challenge.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_setup.html",
        AUTH_MAIN_MFA_SETUP_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_setup.html");
    env.add_template_owned(
        "_partials/_auth_main_mfa_recovery.html",
        AUTH_MAIN_MFA_RECOVERY_PARTIAL,
    )
    .expect("_partials/_auth_main_mfa_recovery.html");
    env.add_template_owned(
        "_partials/_auth_main_consent.html",
        AUTH_MAIN_CONSENT_PARTIAL,
    )
    .expect("_partials/_auth_main_consent.html");
    env.add_template_owned("error.html", ERROR_HTML)
        .expect("error.html");
}

pub fn build_default_browser_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    Arc::new(env)
}

pub fn render(
    env: &Environment<'_>,
    template_name: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = env.get_template(template_name)?;
    let rendered = tmpl.render(ctx)?;
    Ok(Html(rendered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_env_loads_all_browser_templates() {
        let env = build_default_browser_env();
        for name in [
            "base.html",
            "login.html",
            "register.html",
            "settings.html",
            "consent.html",
            "forgot_password.html",
            "reset_password.html",
            "mfa_setup.html",
            "mfa_recovery.html",
            "mfa_challenge.html",
            "_partials/_modeline.html",
            "_partials/_flash.html",
            "_partials/_splash.html",
            "_partials/_auth_shell.html",
            "_partials/_app_shell.html",
            "_partials/_sidebar_nav.html",
            "_partials/_auth_macros.html",
            "_partials/_auth_oob_head.html",
            "_partials/_auth_main_login.html",
            "_partials/_auth_main_register.html",
            "_partials/_auth_main_forgot_password.html",
            "_partials/_auth_main_reset_password.html",
            "_partials/_auth_main_mfa_challenge.html",
            "_partials/_auth_main_mfa_setup.html",
            "_partials/_auth_main_mfa_recovery.html",
            "_partials/_auth_main_consent.html",
            "error.html",
        ] {
            assert!(
                env.get_template(name).is_ok(),
                "template {name} should be loadable"
            );
        }
    }

    #[test]
    fn render_produces_html() {
        let env = build_default_browser_env();
        let result = render(
            &env,
            "login.html",
            minijinja::context! {
                csrf_token => "test",
                is_production => false,
            },
        );
        assert!(result.is_ok());
    }

    #[test]
    fn form_component_helpers_render_through_minijinja() {
        let mut env = Environment::new();
        add_default_browser_templates(&mut env);
        env.add_template(
            "form_helpers.html",
            r##"
{{ wf_form(
    wf_form_section(
        "Account",
        wf_field(
            "Email",
            wf_input(
                "email",
                type="email",
                value="user@example.com",
                required=true,
                autocomplete="email"
            ),
            hint="Work address"
        ) ~
        wf_check_row("enabled", "yes", "Enabled", checked=true) ~
        wf_field(
            "Plan",
            wf_select(
                "plan",
                ["free", "team"],
                selected="team",
                placeholder="Select…",
                required=true,
                id="plan"
            )
        ) ~
        wf_field(
            "Limit",
            wf_input("limit", type="number", value="3", min="1", max="5")
        ) ~
        wf_field(
            "Notes",
            wf_textarea("notes", value="Hello", minlength="2", maxlength="200")
        ),
        description="Profile details",
        actions_html=wf_form_actions(
            wf_button("Save", variant="primary", type="submit"),
            secondary_html=wf_button("Cancel", href="/settings")
        )
    ),
    action="/settings",
    method="post"
) }}
{{ wf_settings_section(
    "Workspace",
    wf_inline_form_row(
        "Name",
        wf_input("name", value="Acme", id="workspace-name")
    )
) }}
{{ wf_repeatable_array(
    "Redirect URIs",
    wf_repeatable_item(
        "URI 1",
        wf_input("redirect_uris[]", type="url", value="https://example.test/callback")
    )
) }}
"##,
        )
        .expect("add form helper test template");

        let rendered = env
            .get_template("form_helpers.html")
            .expect("form helper template")
            .render(minijinja::context! {})
            .expect("render form helper template");

        assert!(rendered.contains(r#"<form"#));
        assert!(rendered.contains(r#"action="/settings""#));
        assert!(rendered.contains(r#"method="post""#));
        assert!(rendered.contains(r#"<button class="wf-btn primary" type="submit">Save</button>"#));
        assert!(rendered.contains(r#"<a class="wf-btn" href="/settings">Cancel</a>"#));
        assert!(rendered.contains(r#"class="wf-field""#));
        assert!(rendered.contains(r#"name="email""#));
        assert!(rendered.contains(r#"type="email""#));
        assert!(rendered.contains(r#"autocomplete="email""#));
        assert!(rendered.contains("Work address"));
        assert!(rendered.contains(r#"name="enabled""#));
        assert!(rendered.contains(r#"checked"#));
        assert!(rendered.contains(r#"name="plan""#));
        assert!(rendered.contains(r#"value="team" selected"#));
        assert!(rendered.contains(r#"name="limit""#));
        assert!(rendered.contains(r#"min="1""#));
        assert!(rendered.contains(r#"max="5""#));
        assert!(rendered.contains(r#"name="notes""#));
        assert!(rendered.contains(r#"minlength="2""#));
        assert!(rendered.contains(r#"maxlength="200""#));
        assert!(rendered.contains("wf-settings-section"));
        assert!(rendered.contains(r#"id="workspace-name""#));
        assert!(rendered.contains(r#"Redirect URIs"#));
        assert!(rendered.contains(r#"redirect_uris[]"#));
    }
}
