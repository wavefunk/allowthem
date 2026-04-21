//! Render tests for the shared partial set in `templates/_partials/`.
//!
//! Each test builds a minijinja environment via `build_default_browser_env`,
//! renders a tiny inline wrapper template that `{% include %}`s the partial,
//! and asserts on the produced HTML. Partials that accept a typed `field`
//! or `flash` struct are driven via the `context!` macro with ad-hoc objects.

use minijinja::{Environment, context};

use crate::browser_templates::add_default_browser_templates;

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
    assert!(html.contains("wf-alert--err"));
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
    assert!(html.contains("wf-alert--err"));
    assert!(html.contains("not a valid email"));
}
