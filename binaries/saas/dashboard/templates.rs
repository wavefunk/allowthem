//! MiniJinja environment composition for the dashboard.
//!
//! The pattern mirrors `crates/server/browser_templates.rs:95-177`:
//! one fresh `Environment`, default browser templates layered first, then
//! dashboard-specific templates layered on top via `include_str!` +
//! `add_template_owned`. No `include_dir!` / no runtime fs lookups.
//!
//! Dashboard templates land in Steps 6 (signup) and 10 (quickstart) of
//! 99c.2 — the calls are added incrementally as those files arrive.

use std::sync::Arc;

use minijinja::Environment;

use allowthem_server::browser_templates::add_default_browser_templates;

pub fn build_dashboard_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();

    // 1. Default browser templates (login, register, _auth_shell, _app_shell, ...).
    add_default_browser_templates(&mut env);

    // 2. Dashboard-specific templates layered on top. Added by Steps 6 + 10.

    Arc::new(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_dashboard_env_loads_default_partials() {
        let env = build_dashboard_env();
        // Sanity check — the shared `_auth_shell.html` partial that signup
        // and friends extend resolves through the dashboard env.
        env.get_template("_partials/_auth_shell.html")
            .expect("_auth_shell.html should resolve via add_default_browser_templates");
    }
}
