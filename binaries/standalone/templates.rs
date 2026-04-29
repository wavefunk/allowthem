use std::sync::Arc;

use allowthem_server::browser_templates::add_default_browser_templates;
use axum::response::Html;
use eyre::Result;
use minijinja::{Environment, context, path_loader};

use crate::error::AppError;

/// Truncate a string to `length` characters, appending "..." if truncated.
///
/// Registered as the `truncate` filter because minijinja does not include
/// it without the `builtins` feature.
fn truncate_filter(value: &str, length: usize) -> String {
    if value.len() <= length {
        value.to_string()
    } else {
        let mut s = String::with_capacity(length + 3);
        s.push_str(&value[..length]);
        s.push_str("...");
        s
    }
}

/// Format an ISO-8601/RFC-3339 timestamp into a human-readable string.
///
/// Accepts either a full datetime (`2026-04-29T15:45:00Z`) or the
/// `YYYY-MM-DD HH:MM:SS` format used by `EntryDisplay::created_at`.
/// Falls back to the original value if parsing fails.
fn datefmt_filter(value: &str) -> String {
    // Try RFC 3339 first (e.g. "2026-04-29T15:45:00Z")
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(value) {
        return dt.format("%b %d, %Y %l:%M %p").to_string();
    }
    // Try "YYYY-MM-DD HH:MM:SS" (EntryDisplay format)
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return dt.format("%b %d, %Y %l:%M %p").to_string();
    }
    // Try bare date "YYYY-MM-DD"
    if let Ok(d) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        return d.format("%b %d, %Y").to_string();
    }
    value.to_string()
}

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
    env.add_filter("truncate", truncate_filter);
    env.add_filter("datefmt", datefmt_filter);
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
