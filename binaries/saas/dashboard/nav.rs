//! Tenant-scoped sidebar nav model (99c.5 Step 5).
//!
//! Pure function `tenant_nav_items` — deterministic from `(slug,
//! current_path, role)`. Pages render the result through the
//! `nav_sections` context variable consumed by
//! `_partials/_dashboard_shell.html`.

use serde::Serialize;

use allowthem_saas::TenantRole;

#[derive(Clone, Debug, Serialize)]
pub struct NavItem {
    pub label: &'static str,
    pub href: String,
    pub active: bool,
    /// Visible to the user but role lacks the capability — render dim.
    pub muted: bool,
    /// Page is a stub awaiting a later epic; render with a "Coming soon" badge.
    pub coming_soon: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct NavSection {
    pub heading: &'static str,
    pub items: Vec<NavItem>,
}

/// Build the sidebar sections for a tenant-scoped dashboard page.
///
/// `current_path` is matched against the `href` of each item to derive
/// the `active` flag. Settings sub-routes prefix-match (so nested URLs
/// keep the parent settings link active).
pub fn tenant_nav_items(slug: &str, current_path: &str, role: TenantRole) -> Vec<NavSection> {
    let p = |suffix: &str| format!("/t/{slug}{suffix}");
    let active = |href: &str| {
        if href.contains("/settings") {
            current_path == href || current_path.starts_with(&format!("{href}/"))
        } else {
            current_path == href
        }
    };

    let writer = matches!(role, TenantRole::Admin | TenantRole::Owner);
    let owner = matches!(role, TenantRole::Owner);

    let item = |label: &'static str, href: String, muted: bool, coming_soon: bool| -> NavItem {
        let act = active(&href);
        NavItem {
            label,
            href,
            active: act,
            muted,
            coming_soon,
        }
    };

    let tenant_section = NavSection {
        heading: "TENANT",
        items: vec![
            item("Applications", p("/applications"), false, false),
            item("Users", p("/users"), false, false),
            item("Roles", p("/roles"), !writer, false),
            item("Permissions", p("/permissions"), !writer, false),
            item("Audit", p("/audit"), false, false),
        ],
    };

    let settings_section = NavSection {
        heading: "SETTINGS",
        items: vec![
            item("General", p("/settings"), !writer, false),
            item("Team", p("/settings/team"), !writer, false),
            item("API Keys", p("/settings/api-keys"), !writer, false),
            item("Billing", p("/settings/billing"), !owner, false),
            item("Webhooks", p("/settings/webhooks"), !writer, true),
            item("Email", p("/settings/email"), !writer, true),
            item("Social providers", p("/settings/social"), !writer, true),
            item("Custom domain", p("/settings/domain"), !writer, true),
        ],
    };

    vec![tenant_section, settings_section]
}

/// Build the sidebar sections for the super-admin panel.
///
/// `current_path` is the path of the current page (e.g. `"/admin"`,
/// `"/admin/usage"`). Used to set the `active` flag on the matching item.
pub fn admin_nav_items(current_path: &str) -> Vec<NavSection> {
    let active = |href: &str| current_path == href || current_path.starts_with(&format!("{href}/"));

    let item =
        |label: &'static str, href: &'static str| -> NavItem {
            NavItem {
                label,
                href: href.to_string(),
                active: active(href),
                muted: false,
                coming_soon: false,
            }
        };

    vec![NavSection {
        heading: "ADMIN",
        items: vec![
            item("Tenants", "/admin"),
            item("Usage", "/admin/usage"),
            item("Revenue", "/admin/revenue"),
            item("Health", "/admin/health"),
        ],
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_active_when_path_matches() {
        let sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Viewer);
        let item = sections[0]
            .items
            .iter()
            .find(|i| i.label == "Audit")
            .expect("Audit item present");
        assert!(item.active);
        // Other items in the same section are not active.
        assert!(
            !sections[0]
                .items
                .iter()
                .any(|i| i.label == "Users" && i.active)
        );
    }

    #[test]
    fn settings_team_active_for_subroute() {
        let sections =
            tenant_nav_items("acme", "/t/acme/settings/team/abc/role", TenantRole::Owner);
        let item = sections[1]
            .items
            .iter()
            .find(|i| i.label == "Team")
            .expect("Team item present");
        assert!(item.active);
    }

    #[test]
    fn billing_muted_for_admin() {
        let sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Admin);
        let item = sections[1]
            .items
            .iter()
            .find(|i| i.label == "Billing")
            .expect("Billing item present");
        assert!(item.muted);
    }

    #[test]
    fn billing_unmuted_for_owner() {
        let sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Owner);
        let item = sections[1]
            .items
            .iter()
            .find(|i| i.label == "Billing")
            .unwrap();
        assert!(!item.muted);
    }

    #[test]
    fn coming_soon_flag_set_on_stubs() {
        let sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Owner);
        let stubs = ["Webhooks", "Email", "Social providers", "Custom domain"];
        for label in stubs {
            let item = sections[1]
                .items
                .iter()
                .find(|i| i.label == label)
                .unwrap_or_else(|| panic!("missing nav item {label}"));
            assert!(item.coming_soon, "{label} should be coming_soon");
        }
    }

    #[test]
    fn writer_only_items_muted_for_viewer() {
        let sections = tenant_nav_items("acme", "/t/acme/audit", TenantRole::Viewer);
        let muted_for_viewer = ["Roles", "Permissions", "General", "Team", "API Keys"];
        for label in muted_for_viewer {
            let item = sections
                .iter()
                .flat_map(|s| s.items.iter())
                .find(|i| i.label == label)
                .unwrap();
            assert!(item.muted, "{label} should be muted for viewer");
        }
    }
}
