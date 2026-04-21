use std::sync::Arc;

use allowthem_server::browser_templates::add_default_browser_templates;
use axum::response::Html;
use eyre::Result;
use minijinja::{Environment, context, path_loader};

use crate::error::AppError;

/// Build the template environment.
///
/// Base/browser templates are embedded in the `allowthem-server` crate via
/// `include_str!`; admin templates are loaded from disk via `path_loader`
/// so admin UI can be iterated on without rebuilding. Owned templates take
/// precedence over the loader, so admin templates that `{% extends "base.html" %}`
/// resolve the bundled base, not a disk copy.
///
/// Eagerly resolves `base.html` to fail fast if the bundle is broken.
pub fn build_template_env() -> Result<Arc<Environment<'static>>> {
    let mut env = Environment::new();
    add_default_browser_templates(&mut env);
    env.set_loader(path_loader(admin_template_dir()));
    env.get_template("base.html")?;
    Ok(Arc::new(env))
}

fn admin_template_dir() -> std::path::PathBuf {
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        std::path::PathBuf::from(manifest_dir).join("standalone/templates")
    } else {
        std::path::PathBuf::from("binaries/standalone/templates")
    }
}

/// Render a template with shared context injected.
///
/// Injects `is_production` into every render. Route handlers pass their
/// page-specific context via `ctx`; the shared globals are merged in.
pub fn render(
    env: &Environment<'_>,
    template_name: &str,
    ctx: minijinja::value::Value,
    is_production: bool,
) -> Result<Html<String>, AppError> {
    let tmpl = env.get_template(template_name)?;
    let rendered = tmpl.render(context! {
        is_production,
        ..ctx
    })?;
    Ok(Html(rendered))
}
