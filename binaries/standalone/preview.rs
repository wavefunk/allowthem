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

/// Mount the preview gallery onto `app` iff `debug_preview` is true.
///
/// Kept in this module (not main.rs) so the debug_preview=false → 404
/// contract can be tested without duplicating the wiring logic.
pub fn mount(app: Router, debug_preview: bool, templates: Arc<Environment<'static>>) -> Router {
    if debug_preview {
        app.merge(routes(PreviewState { templates }))
    } else {
        app
    }
}

fn base_branding() -> BrandingConfig {
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

async fn render_gallery(State(state): State<PreviewState>) -> impl IntoResponse {
    let branding_accent = BrandingConfig {
        accent_hex: Some("#cba6f7".into()),
        splash_text: Some("ACME".into()),
        shader_cell_scale: Some(22),
        ..base_branding()
    };

    let branding_primitive = BrandingConfig {
        accent_hex: Some("#a6e3a1".into()),
        splash_primitive: Some(SplashPrimitive::Wave),
        shader_cell_scale: Some(26),
        ..base_branding()
    };

    let branding_image = BrandingConfig {
        accent_hex: Some("#fab387".into()),
        splash_image_url: Some("https://placehold.co/600x400/png".into()),
        shader_cell_scale: Some(24),
        ..base_branding()
    };

    let tmpl = match state.templates.get_template("preview.html") {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "preview gallery render failed");
            return (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "preview render failed",
            )
                .into_response();
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
        Err(e) => {
            tracing::error!(error = %e, "preview gallery render failed");
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "preview render failed",
            )
                .into_response()
        }
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
        // 4 = text-fallback + accent-text + primitive + image variants in preview.html.
        const SPLASH_VARIANT_COUNT: usize = 4;
        assert_eq!(
            html.matches("data-shader-ascii").count(),
            SPLASH_VARIANT_COUNT
        );
    }

    #[tokio::test]
    async fn preview_route_is_404_when_debug_preview_flag_is_false() {
        // Uses the same helper main.rs uses, so the flag-off contract is
        // tested against the real wiring rather than a replica.
        let app = mount(axum::Router::new(), false, env_with_partials());
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
