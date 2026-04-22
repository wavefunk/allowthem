//! Walks every `.html` under binaries/standalone/templates/ and asserts no
//! Tailwind utility class tokens remain. Glob-enumerated at test runtime
//! so new templates are audited automatically (see M5 design D2).

use std::path::{Path, PathBuf};

// Tailwind utility-class matcher. Keep this verbatim-identical to the copy
// in the sibling crate's all_*_templates_guard_tests.rs — the two are the
// canonical definition. Any per-template guard (auth_template_guard_tests.rs,
// admin_template_render_tests.rs) that needs the same check must import or
// re-state this pattern; drift between sites is a bug.
fn tailwind_re() -> regex::Regex {
    regex::Regex::new(
        r#"class="[^"]*\b(bg-|text-|border-|rounded|shadow|p-\d|px-\d|py-\d|m-\d|mx-\d|my-\d|flex|grid-cols-|gap-\d|w-\d|h-\d|min-h-|min-w-|max-w-|hover:|focus:|dark:|space-x-|space-y-|opacity-|items-|justify-|font-|tracking-|leading-)"#,
    )
    .expect("regex compiles")
}

fn walk_html(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(it) => it,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if file_name.starts_with('.') {
                continue;
            }
            let ty = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ty.is_dir() {
                stack.push(path);
            } else if ty.is_file() && path.extension().and_then(|s| s.to_str()) == Some("html") {
                out.push(path);
            }
        }
    }
    out
}

#[test]
fn all_standalone_templates_are_tailwind_free() {
    // CARGO_MANIFEST_DIR is `binaries/` (see binaries/Cargo.toml), so nest
    // into `standalone/templates` to hit this binary's template root.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("standalone")
        .join("templates");
    let re = tailwind_re();
    let mut audited = 0;
    let mut failures = Vec::new();
    for path in walk_html(&root) {
        let body = std::fs::read_to_string(&path).expect("read template");
        if re.is_match(&body) {
            failures.push(path);
        }
        audited += 1;
    }
    // Floor — keeps a silent empty-walk failure from appearing green.
    // After commit 2 deletes preview.html, standalone ships 8 admin templates.
    assert!(
        audited >= 8,
        "expected to audit at least 8 templates, got {audited}"
    );
    assert!(
        failures.is_empty(),
        "tailwind utility classes in: {failures:?}"
    );
}
