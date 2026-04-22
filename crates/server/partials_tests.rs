//! Render tests for the shared partial set in `templates/_partials/`.
//!
//! Each test builds a minijinja environment via `build_default_browser_env`,
//! renders a tiny inline wrapper template that `{% include %}`s the partial,
//! and asserts on the produced HTML. Partials that accept a typed `field`
//! or `flash` struct are driven via the `context!` macro with ad-hoc objects.

use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::{Mode, SplashPrimitive};
use minijinja::value::Value;
use minijinja::{Environment, context};

use crate::browser_templates::add_default_browser_templates;
use crate::shell_context::ShellContext;

fn env_with_wrapper(wrapper_name: &'static str, wrapper_src: &'static str) -> Environment<'static> {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(wrapper_name, wrapper_src)
        .expect("wrapper");
    env
}

#[test]
fn status_bar_renders_defaults() {
    let env = env_with_wrapper(
        "wrap_status.html",
        r#"{% include "_partials/_status_bar.html" %}"#,
    );
    let html = env
        .get_template("wrap_status.html")
        .unwrap()
        .render(context! {})
        .unwrap();
    assert!(html.contains("wf-statusbar"), "missing wf-statusbar class");
    assert!(html.contains("MODE DARK"));
    assert!(html.contains("ENV DEV"));
    assert!(html.contains("SESSION ANON"));
    // mode toggle is composed in.
    assert!(html.contains("data-mode-toggle"));
}

#[test]
fn status_bar_honors_overrides() {
    let env = env_with_wrapper(
        "wrap_status_over.html",
        r#"{% include "_partials/_status_bar.html" %}"#,
    );
    let html = env
        .get_template("wrap_status_over.html")
        .unwrap()
        .render(context! {
            status_mode => "LIGHT",
            status_env  => "PROD",
            status_session => "u:42",
            status_hint => "press ? for help",
        })
        .unwrap();
    assert!(html.contains("MODE LIGHT"));
    assert!(html.contains("ENV PROD"));
    assert!(html.contains("SESSION u:42"));
    assert!(html.contains("press ? for help"));
}

#[test]
fn mode_toggle_renders_button() {
    let env = env_with_wrapper(
        "wrap_toggle.html",
        r#"{% include "_partials/_mode_toggle.html" %}"#,
    );
    let html = env
        .get_template("wrap_toggle.html")
        .unwrap()
        .render(context! {})
        .unwrap();
    assert!(html.contains("data-mode-toggle"));
    assert!(html.contains("wf-mode-toggle"));
    assert!(html.contains("aria-label=\"toggle color mode\""));
}

#[test]
fn flash_renders_error_variant() {
    let env = env_with_wrapper(
        "wrap_flash_err.html",
        r#"{% include "_partials/_flash.html" %}"#,
    );
    let html = env
        .get_template("wrap_flash_err.html")
        .unwrap()
        .render(context! {
            flash => context! { kind => "err", message => "bad password" },
        })
        .unwrap();
    assert!(html.contains("wf-alert"));
    assert!(
        html.contains(" err\""),
        "expected ' err\"' variant token in class attr"
    );
    assert!(html.contains("bad password"));
    assert!(html.contains("role=\"alert\""));
}

#[test]
fn flash_renders_nothing_when_unset() {
    let env = env_with_wrapper(
        "wrap_flash_none.html",
        r#"<root>{% include "_partials/_flash.html" %}</root>"#,
    );
    let html = env
        .get_template("wrap_flash_none.html")
        .unwrap()
        .render(context! {})
        .unwrap();
    assert!(!html.contains("wf-alert"));
    assert!(html.contains("<root></root>"));
}

#[test]
fn form_field_renders_label_and_input() {
    let env = env_with_wrapper(
        "wrap_field.html",
        r#"{% include "_partials/_form_field.html" %}"#,
    );
    let html = env
        .get_template("wrap_field.html")
        .unwrap()
        .render(context! {
            field => context! {
                name => "email",
                label => "Email",
                type => "email",
                required => true,
                autocomplete => "email",
            },
        })
        .unwrap();
    assert!(html.contains("for=\"fld-email\""));
    assert!(html.contains("name=\"email\""));
    assert!(html.contains("type=\"email\""));
    assert!(html.contains("required"));
    assert!(html.contains("autocomplete=\"email\""));
    assert!(html.contains("wf-label"));
    assert!(html.contains("wf-input"));
}

#[test]
fn form_field_surfaces_error_below_input() {
    let env = env_with_wrapper(
        "wrap_field_err.html",
        r#"{% include "_partials/_form_field.html" %}"#,
    );
    let html = env
        .get_template("wrap_field_err.html")
        .unwrap()
        .render(context! {
            field => context! {
                name => "email",
                label => "Email",
                error => "not a valid email",
            },
        })
        .unwrap();
    assert!(html.contains("wf-alert"));
    assert!(
        html.contains(" err\""),
        "expected ' err\"' variant token in class attr"
    );
    assert!(html.contains("not a valid email"));
    assert!(html.contains("aria-describedby=\"fld-email-err\""));
    assert!(html.contains("aria-invalid=\"true\""));
    assert!(html.contains("id=\"fld-email-err\""));
}

#[test]
fn flash_partial_reads_locally_set_flash_from_including_template() {
    // Contract check for M3 auth templates: `{% set flash = {...} %} {% include "_partials/_flash.html" %}`
    // must surface the message. If this breaks, every migrated auth page silently drops errors.
    let env = env_with_wrapper(
        "wrap_local_flash.html",
        r#"{% set flash = {"kind": "err", "message": "local error"} %}{% include "_partials/_flash.html" %}"#,
    );
    let html = env
        .get_template("wrap_local_flash.html")
        .unwrap()
        .render(context! {})
        .unwrap();
    assert!(
        html.contains("local error"),
        "_flash.html did not see locally-set flash: {html}"
    );
    assert!(html.contains("wf-alert"));
}

fn mock_branding() -> BrandingConfig {
    BrandingConfig {
        application_name: "acme".into(),
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
    }
}

#[test]
fn splash_url_wins_and_renders_iframe() {
    let env = env_with_wrapper(
        "wrap_splash_url.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let mut b = mock_branding();
    b.splash_url = Some("https://example.com/splash".into());
    // Populate lower-priority too; iframe should still win.
    b.splash_image_url = Some("https://example.com/logo.png".into());
    b.splash_primitive = Some(SplashPrimitive::Wordmark);
    b.splash_text = Some("ignored".into());
    let html = env
        .get_template("wrap_splash_url.html")
        .unwrap()
        .render(context! { branding => &b })
        .unwrap();
    assert!(html.contains("<iframe"));
    assert!(html.contains("https://example.com/splash"));
    assert!(html.contains("sandbox=\"allow-scripts\""));
    assert!(html.contains("referrerpolicy=\"no-referrer\""));
    assert!(html.contains("allow=\"\""));
    assert!(!html.contains("data-shader-ascii"));
}

#[test]
fn splash_empty_branding_falls_back_to_application_name() {
    // Branding struct present but every splash field is None; no
    // branding.application_name surfaces in the template — the fallback
    // is the context-level application_name var.
    let env = env_with_wrapper(
        "wrap_splash_empty_branding.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let b = mock_branding();
    let html = env
        .get_template("wrap_splash_empty_branding.html")
        .unwrap()
        .render(context! { branding => &b, application_name => "immersiq" })
        .unwrap();
    assert!(html.contains("data-shape-source=\"text\""));
    assert!(html.contains("data-shape-text=\"immersiq\""));
    // branding.application_name ("acme") must NOT leak into the template.
    assert!(!html.contains("acme"));
}

#[test]
fn splash_image_beats_primitive_and_text() {
    let env = env_with_wrapper(
        "wrap_splash_image.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let mut b = mock_branding();
    b.splash_image_url = Some("https://cdn.example.com/mark.png".into());
    b.splash_primitive = Some(SplashPrimitive::Circle);
    b.splash_text = Some("ignored".into());
    let html = env
        .get_template("wrap_splash_image.html")
        .unwrap()
        .render(context! { branding => &b })
        .unwrap();
    assert!(html.contains("data-shape-source=\"image\""));
    assert!(html.contains("data-shape-image=\"https://cdn.example.com/mark.png\""));
    assert!(!html.contains("<iframe"));
}

#[test]
fn splash_primitive_beats_text() {
    let env = env_with_wrapper(
        "wrap_splash_prim.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let mut b = mock_branding();
    b.splash_primitive = Some(SplashPrimitive::Wave);
    b.splash_text = Some("ignored".into());
    let html = env
        .get_template("wrap_splash_prim.html")
        .unwrap()
        .render(context! { branding => &b })
        .unwrap();
    assert!(html.contains("data-shape-source=\"primitive\""));
    assert!(html.contains("data-shape-primitive=\"wave\""));
}

#[test]
fn splash_text_is_the_default_when_nothing_else_set() {
    let env = env_with_wrapper(
        "wrap_splash_text.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let mut b = mock_branding();
    b.splash_text = Some("FUNKCORP".into());
    let html = env
        .get_template("wrap_splash_text.html")
        .unwrap()
        .render(context! { branding => &b })
        .unwrap();
    assert!(html.contains("data-shape-source=\"text\""));
    assert!(html.contains("data-shape-text=\"FUNKCORP\""));
}

#[test]
fn splash_falls_back_to_application_name_when_no_branding() {
    let env = env_with_wrapper(
        "wrap_splash_appname.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let html = env
        .get_template("wrap_splash_appname.html")
        .unwrap()
        .render(context! { application_name => "substrukt" })
        .unwrap();
    assert!(html.contains("data-shape-source=\"text\""));
    assert!(html.contains("data-shape-text=\"substrukt\""));
}

#[test]
fn splash_cell_scale_is_pluggable() {
    let env = env_with_wrapper(
        "wrap_splash_scale.html",
        r#"{% include "_partials/_splash.html" %}"#,
    );
    let mut b = mock_branding();
    b.splash_primitive = Some(SplashPrimitive::Grid);
    b.shader_cell_scale = Some(40);
    let html = env
        .get_template("wrap_splash_scale.html")
        .unwrap()
        .render(context! { branding => &b })
        .unwrap();
    assert!(html.contains("data-cell-scale=\"40\""));
}

#[test]
fn auth_shell_wraps_form_block_and_includes_splash_and_status_bar() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "auth_child.html",
        r#"{% extends "_partials/_auth_shell.html" %}
           {% block form %}<section id="the-form">hi</section>{% endblock %}"#,
    )
    .unwrap();
    let html = env
        .get_template("auth_child.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            application_name => "acme",
        })
        .unwrap();
    assert!(html.contains("wf-auth"));
    assert!(html.contains("wf-auth-splash"));
    assert!(html.contains("wf-statusbar"));
    assert!(html.contains("id=\"the-form\""));
    // Exactly one <body> opening tag — the shell overrides body_content +
    // body_class, NOT the inner body block, so no nested body materializes.
    assert_eq!(html.matches("<body").count(), 1);
    // JS scripts linked.
    assert!(html.contains("/__allowthem/static/js/mode-toggle.js"));
    assert!(html.contains("/__allowthem/static/js/shader-ascii.js"));
}

#[test]
fn auth_shell_without_forced_mode_emits_no_html_attrs() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "auth_child_nofm.html",
        r#"{% extends "_partials/_auth_shell.html" %}
           {% block form %}<section>x</section>{% endblock %}"#,
    )
    .unwrap();
    let html = env
        .get_template("auth_child_nofm.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            application_name => "acme",
        })
        .unwrap();
    // No forced_mode → no data-mode / data-mode-locked on <html>.
    // Scope to html_open (before <head) to avoid matching the FOUC JS in base.html
    // which contains hasAttribute('data-mode-locked') as a literal substring.
    let html_open = html.split_once("<head").map(|(h, _)| h).unwrap_or("");
    assert!(
        !html_open.contains("data-mode-locked"),
        "no data-mode-locked attr on <html> when branding.forced_mode unset: {html_open}"
    );
    assert!(
        !html_open.contains("data-mode="),
        "no data-mode attr on <html> when branding.forced_mode unset: {html_open}"
    );
}

#[test]
fn auth_shell_with_forced_mode_emits_locked_attrs() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "auth_child_fm.html",
        r#"{% extends "_partials/_auth_shell.html" %}
           {% block form %}<section>x</section>{% endblock %}"#,
    )
    .unwrap();
    let mut b = mock_branding();
    b.forced_mode = Some(Mode::Light);
    let html = env
        .get_template("auth_child_fm.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            application_name => "acme",
            branding => &b,
        })
        .unwrap();
    let html_open = html.split_once("<head").map(|(h, _)| h).unwrap_or("");
    assert!(
        html_open.contains("data-mode=\"light\""),
        "<html> must carry data-mode=\"light\": {html_open}"
    );
    assert!(
        html_open.contains("data-mode-locked"),
        "<html> must carry data-mode-locked: {html_open}"
    );
}

#[test]
fn app_shell_wraps_content_block_and_renders_sidebar() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "app_child.html",
        r#"{% extends "_partials/_app_shell.html" %}
           {% block sidebar_nav %}<a class="wf-link" href="/x">x</a>{% endblock %}
           {% block content %}<section id="page">payload</section>{% endblock %}"#,
    )
    .unwrap();
    let shell = ShellContext::new(false, "/app", "acme");
    let html = env
        .get_template("app_child.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            shell => Value::from_serialize(&shell),
        })
        .unwrap();
    assert!(html.contains("class=\"wf-app\"") || html.contains("class=\"wf-app "));
    assert!(html.contains("class=\"wf-shell\"") || html.contains("class=\"wf-shell "));
    assert!(html.contains("class=\"wf-sidebar\"") || html.contains("class=\"wf-sidebar "));
    assert!(!html.contains("class=\"at-app-shell\"") && !html.contains("class=\"at-app-shell "));
    assert!(!html.contains("class=\"at-sidebar\"") && !html.contains("class=\"at-sidebar "));
    assert!(!html.contains("class=\"at-main\"") && !html.contains("class=\"at-main "));
    assert!(html.contains("wf-statusbar"));
    assert!(html.contains("href=\"/x\""));
    assert!(html.contains("id=\"page\""));
    // Exactly one <body> opening tag — shell overrides body_content + body_class.
    assert_eq!(html.matches("<body").count(), 1);
    // Shader JS is NOT pulled in for app shell — only mode-toggle.
    assert!(html.contains("/__allowthem/static/js/mode-toggle.js"));
    assert!(!html.contains("/__allowthem/static/js/shader-ascii.js"));
}

#[test]
fn app_shell_without_forced_mode_emits_no_html_attrs() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "app_child_nofm.html",
        r#"{% extends "_partials/_app_shell.html" %}
           {% block content %}<section>x</section>{% endblock %}"#,
    )
    .unwrap();
    let shell = ShellContext::new(false, "/app", "acme");
    let html = env
        .get_template("app_child_nofm.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            shell => Value::from_serialize(&shell),
        })
        .unwrap();
    let html_open = html.split_once("<head").map(|(h, _)| h).unwrap_or("");
    assert!(!html_open.contains("data-mode-locked"));
    assert!(!html_open.contains("data-mode="));
}

#[test]
fn app_shell_with_forced_mode_emits_locked_attrs() {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.add_template(
        "app_child_fm.html",
        r#"{% extends "_partials/_app_shell.html" %}
           {% block content %}<section>x</section>{% endblock %}"#,
    )
    .unwrap();
    let mut b = mock_branding();
    b.forced_mode = Some(Mode::Dark);
    let shell = ShellContext::new(false, "/app", "acme");
    let html = env
        .get_template("app_child_fm.html")
        .unwrap()
        .render(context! {
            csrf_token => "_",
            is_production => false,
            shell => Value::from_serialize(&shell),
            branding => &b,
        })
        .unwrap();
    let html_open = html.split_once("<head").map(|(h, _)| h).unwrap_or("");
    assert!(
        html_open.contains("data-mode=\"dark\""),
        "<html> must carry data-mode=\"dark\": {html_open}"
    );
    assert!(html_open.contains("data-mode-locked"));
}
