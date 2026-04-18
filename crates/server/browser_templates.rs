use std::sync::Arc;

use axum::response::Html;
use minijinja::Environment;

use crate::browser_error::BrowserError;

const BASE_HTML: &str = include_str!("../../binaries/templates/base.html");
const LOGIN_HTML: &str = include_str!("../../binaries/templates/login.html");
const REGISTER_HTML: &str = include_str!("../../binaries/templates/register.html");
const SETTINGS_HTML: &str = include_str!("../../binaries/templates/settings.html");
const CONSENT_HTML: &str = include_str!("../../binaries/templates/consent.html");
const FORGOT_PASSWORD_HTML: &str = include_str!("../../binaries/templates/forgot_password.html");
const RESET_PASSWORD_HTML: &str = include_str!("../../binaries/templates/reset_password.html");
const MFA_SETUP_HTML: &str = include_str!("../../binaries/templates/mfa_setup.html");
const MFA_RECOVERY_HTML: &str = include_str!("../../binaries/templates/mfa_recovery.html");
const MFA_CHALLENGE_HTML: &str = include_str!("../../binaries/templates/mfa_challenge.html");

pub fn build_default_browser_env() -> Arc<Environment<'static>> {
    let mut env = Environment::new();
    env.add_template_owned("base.html", BASE_HTML).expect("base.html");
    env.add_template_owned("login.html", LOGIN_HTML).expect("login.html");
    env.add_template_owned("register.html", REGISTER_HTML).expect("register.html");
    env.add_template_owned("settings.html", SETTINGS_HTML).expect("settings.html");
    env.add_template_owned("consent.html", CONSENT_HTML).expect("consent.html");
    env.add_template_owned("forgot_password.html", FORGOT_PASSWORD_HTML).expect("forgot_password.html");
    env.add_template_owned("reset_password.html", RESET_PASSWORD_HTML).expect("reset_password.html");
    env.add_template_owned("mfa_setup.html", MFA_SETUP_HTML).expect("mfa_setup.html");
    env.add_template_owned("mfa_recovery.html", MFA_RECOVERY_HTML).expect("mfa_recovery.html");
    env.add_template_owned("mfa_challenge.html", MFA_CHALLENGE_HTML).expect("mfa_challenge.html");
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
        let result = render(&env, "login.html", minijinja::context! {
            csrf_token => "test",
            is_production => false,
        });
        assert!(result.is_ok());
    }
}
