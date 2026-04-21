use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NavGroup {
    Account,
    Admin,
}

#[derive(Debug, Clone, Serialize)]
pub struct NavItem {
    pub href: String,
    pub label: String,
    pub group: NavGroup,
    pub active: bool,
}

pub fn nav_items_for(is_admin: bool, current_path: &str) -> Vec<NavItem> {
    // "/admin/users" intentionally omitted: the route is not yet wired in
    // binaries/standalone/main.rs. Add the entry here when the route lands,
    // not before — a dead nav link is a user-visible regression.
    let mut items = Vec::with_capacity(if is_admin { 5 } else { 2 });
    if is_admin {
        for (href, label) in [
            ("/admin/applications", "Applications"),
            ("/admin/sessions", "Sessions"),
            ("/admin/audit", "Audit log"),
        ] {
            items.push(NavItem {
                href: href.into(),
                label: label.into(),
                group: NavGroup::Admin,
                active: current_path.starts_with(href),
            });
        }
    }
    for (href, label) in [("/settings", "Settings"), ("/logout", "Sign out")] {
        items.push(NavItem {
            href: href.into(),
            label: label.into(),
            group: NavGroup::Account,
            active: current_path.starts_with(href),
        });
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_gets_account_group_only_settings_active() {
        let items = nav_items_for(false, "/settings");
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| i.group == NavGroup::Account));
        assert!(items.iter().find(|i| i.href == "/settings").unwrap().active);
        assert!(!items.iter().find(|i| i.href == "/logout").unwrap().active);
    }

    #[test]
    fn admin_deep_path_highlights_applications() {
        let items = nav_items_for(true, "/admin/applications/abc123");
        assert_eq!(items.len(), 5);
        let apps = items
            .iter()
            .find(|i| i.href == "/admin/applications")
            .unwrap();
        assert!(apps.active);
        assert_eq!(apps.group, NavGroup::Admin);
    }

    #[test]
    fn admin_nav_omits_users_until_route_lands() {
        let items = nav_items_for(true, "/admin/applications");
        assert!(items.iter().all(|i| i.href != "/admin/users"));
    }

    #[test]
    fn logout_path_marks_sign_out_active() {
        let items = nav_items_for(true, "/logout");
        let signout = items.iter().find(|i| i.href == "/logout").unwrap();
        assert!(signout.active);
        assert_eq!(signout.group, NavGroup::Account);
    }

    #[test]
    fn unrelated_path_has_no_active_item() {
        let items = nav_items_for(true, "/totally-unrelated");
        assert!(items.iter().all(|i| !i.active));
    }
}
