use serde::Serialize;

use crate::nav::{NavItem, nav_items_for};

#[derive(Debug, Clone, Serialize)]
pub struct ShellContext {
    pub is_admin: bool,
    pub current_path: String,
    pub application_name: String,
    pub nav_items: Vec<NavItem>,
}

impl ShellContext {
    pub fn new(is_admin: bool, current_path: &str, application_name: &str) -> Self {
        let nav_items = nav_items_for(is_admin, current_path);
        Self {
            is_admin,
            current_path: current_path.to_string(),
            application_name: application_name.to_string(),
            nav_items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_admin_shell_with_five_items() {
        let s = ShellContext::new(true, "/admin/sessions", "allowthem");
        assert!(s.is_admin);
        assert_eq!(s.application_name, "allowthem");
        assert_eq!(s.nav_items.len(), 5);
    }

    #[test]
    fn builds_user_shell_with_two_items() {
        let s = ShellContext::new(false, "/settings", "allowthem");
        assert!(!s.is_admin);
        assert_eq!(s.nav_items.len(), 2);
    }
}
