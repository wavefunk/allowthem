use std::sync::Arc;

use axum::response::Html;
use eyre::Result;
use minijinja::{Environment, context, path_loader};

use crate::error::AppError;

/// Build the template environment, loading templates from `binaries/templates/`.
///
/// Eagerly loads `base.html` to fail fast at startup if the template directory
/// is missing or the base template is broken.
pub fn build_template_env() -> Result<Arc<Environment<'static>>> {
    let mut env = Environment::new();
    env.set_loader(path_loader("binaries/templates"));
    // Fail fast: verify base.html is loadable at startup
    env.get_template("base.html")?;
    Ok(Arc::new(env))
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
