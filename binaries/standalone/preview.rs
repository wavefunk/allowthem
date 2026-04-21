//! Standalone-only `/__allowthem/preview` debug gallery.
//!
//! Mounted only when `config.debug_preview` is `true`. Renders a page
//! that exercises each partial with 3–4 mock `BrandingConfig` variants
//! so developers can eyeball the partials without bouncing between
//! auth routes. Production builds leave the flag off, so this route
//! is inaccessible.

use std::sync::Arc;

use axum::{Router, extract::State, response::IntoResponse, routing::get};
use minijinja::{Environment, context};

use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::SplashPrimitive;

#[derive(Clone)]
pub struct PreviewState {
    pub templates: Arc<Environment<'static>>,
}

pub fn routes(state: PreviewState) -> Router {
    Router::new()
        .route("/__allowthem/preview", get(render_gallery))
        .with_state(state)
}

async fn render_gallery(State(state): State<PreviewState>) -> impl IntoResponse {
    let branding_accent = BrandingConfig {
        application_name: "acme".into(),
        logo_url: None,
        primary_color: None,
        accent_hex: Some("#cba6f7".into()),
        accent_ink: None,
        forced_mode: None,
        font_css_url: None,
        font_family: None,
        splash_text: Some("ACME".into()),
        splash_image_url: None,
        splash_primitive: None,
        splash_url: None,
        shader_cell_scale: Some(22),
    };

    let branding_primitive = BrandingConfig {
        application_name: "acme".into(),
        logo_url: None,
        primary_color: None,
        accent_hex: Some("#a6e3a1".into()),
        accent_ink: None,
        forced_mode: None,
        font_css_url: None,
        font_family: None,
        splash_text: None,
        splash_image_url: None,
        splash_primitive: Some(SplashPrimitive::Wave),
        splash_url: None,
        shader_cell_scale: Some(26),
    };

    let branding_image = BrandingConfig {
        application_name: "acme".into(),
        logo_url: None,
        primary_color: None,
        accent_hex: Some("#fab387".into()),
        accent_ink: None,
        forced_mode: None,
        font_css_url: None,
        font_family: None,
        splash_text: None,
        splash_image_url: Some("https://placehold.co/600x400/png".into()),
        splash_primitive: None,
        splash_url: None,
        shader_cell_scale: Some(24),
    };

    let tmpl = match state.templates.get_template("preview.html") {
        Ok(t) => t,
        Err(e) => {
            return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    let rendered = tmpl.render(context! {
        flash_err  => context!{ kind => "err",  message => "something went wrong" },
        flash_warn => context!{ kind => "warn", message => "heads up" },
        flash_ok   => context!{ kind => "ok",   message => "saved" },
        field_ok   => context!{ name => "email", label => "Email", type => "email", autocomplete => "email" },
        field_err  => context!{ name => "email", label => "Email", type => "email",
                                error => "not a valid email address" },
        branding_accent    => &branding_accent,
        branding_primitive => &branding_primitive,
        branding_image     => &branding_image,
    });
    match rendered {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(e) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    fn env_with_partials() -> Arc<Environment<'static>> {
        let mut env = Environment::new();
        allowthem_server::browser_templates::add_default_browser_templates(&mut env);
        env.add_template_owned(
            "preview.html",
            include_str!("templates/preview.html").to_string(),
        )
        .expect("preview.html");
        Arc::new(env)
    }

    #[tokio::test]
    async fn gallery_renders_each_partial() {
        let app = routes(PreviewState {
            templates: env_with_partials(),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/preview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(res.into_body(), 1 << 20)
            .await
            .unwrap();
        let html = std::str::from_utf8(&bytes).unwrap();
        assert!(html.contains("wf-alert"));
        assert!(html.contains("wf-input"));
        assert!(html.contains("wf-statusbar"));
        assert!(html.contains("data-shader-ascii"));
        assert_eq!(html.matches("data-shader-ascii").count(), 4);
    }

    #[tokio::test]
    async fn unknown_path_below_preview_is_404() {
        let app = routes(PreviewState {
            templates: env_with_partials(),
        });
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/preview/not-a-thing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn preview_route_is_404_when_debug_preview_flag_is_false() {
        // Mirrors the conditional mount from binaries/standalone/main.rs:
        // when config.debug_preview = false, preview::routes() is not merged
        // into the root router, so the path 404s at the outer axum matcher.
        let debug_preview = false;

        let app = axum::Router::new();
        let app = if debug_preview {
            app.merge(routes(PreviewState {
                templates: env_with_partials(),
            }))
        } else {
            app
        };

        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/preview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }
}
