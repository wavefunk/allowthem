//! Super-admin platform health page.
//!
//! - `GET /admin/health` — cache sizes, DB file sizes, system info (Step 12 of 99c.6)
//!
//! File-system stats are cached for 60 s in `state.fs_stats_cache` and
//! recomputed lazily on first GET or when the cache is stale.

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use minijinja::context;

use allowthem_server::browser_error::BrowserError;

use crate::dashboard::extractors::RequireSuperAdmin;
use crate::dashboard::nav::admin_nav_items;
use crate::dashboard::state::{DashboardRouterState, FsStats};

const FS_CACHE_TTL: Duration = Duration::from_secs(60);

/// Walk `dir`, collect total bytes and top-10 files by size.
fn compute_fs_stats(dir: &std::path::Path) -> FsStats {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => {
            return FsStats {
                total_bytes: 0,
                top: Vec::new(),
            };
        }
    };

    let mut files: Vec<(String, u64)> = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file()
            && let Ok(meta) = std::fs::metadata(&path)
        {
            let size = meta.len();
            total_bytes += size;
            let name = path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            files.push((name, size));
        }
    }

    files.sort_by(|a, b| b.1.cmp(&a.1));
    files.truncate(10);

    FsStats {
        total_bytes,
        top: files,
    }
}

pub async fn page(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    // Read fs_stats from cache or recompute.
    let fs_stats = {
        let read = state.fs_stats_cache.read().await;
        if let Some((at, ref stats)) = *read {
            if at.elapsed() < FS_CACHE_TTL {
                stats.clone()
            } else {
                drop(read);
                let fresh = compute_fs_stats(&state.tenant_data_dir);
                *state.fs_stats_cache.write().await = Some((Instant::now(), fresh.clone()));
                fresh
            }
        } else {
            drop(read);
            let fresh = compute_fs_stats(&state.tenant_data_dir);
            *state.fs_stats_cache.write().await = Some((Instant::now(), fresh.clone()));
            fresh
        }
    };

    let slug_cache_entries = state.slug_cache.entry_count();
    let handle_cache_entries = state.handle_cache.entry_count();

    let nav = admin_nav_items("/admin/health");

    let tmpl = state
        .templates
        .get_template("admin/health.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! {
            status_session => scope.user.email.as_str(),
            nav_sections => nav,
            total_bytes => fs_stats.total_bytes,
            top_files => fs_stats.top,
            slug_cache_entries => slug_cache_entries,
            handle_cache_entries => handle_cache_entries,
        })
        .map_err(BrowserError::from)?;
    Ok(Html(body).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `compute_fs_stats` must sum total bytes and return files sorted
    /// descending by size.
    #[test]
    fn compute_fs_stats_happy_path() {
        let dir = tempfile::tempdir().expect("tempdir");

        std::fs::write(dir.path().join("alpha.db"), vec![0u8; 100]).expect("alpha");
        std::fs::write(dir.path().join("beta.db"), vec![0u8; 200]).expect("beta");
        std::fs::write(dir.path().join("gamma.db"), vec![0u8; 50]).expect("gamma");

        let stats = compute_fs_stats(dir.path());

        assert_eq!(
            stats.total_bytes, 350,
            "total_bytes must be the sum of all file sizes"
        );
        assert_eq!(stats.top.len(), 3, "all three files must appear in top");
        // Sorted descending: beta(200), alpha(100), gamma(50).
        assert_eq!(stats.top[0].0, "beta");
        assert_eq!(stats.top[0].1, 200);
        assert_eq!(stats.top[1].0, "alpha");
        assert_eq!(stats.top[1].1, 100);
        assert_eq!(stats.top[2].0, "gamma");
        assert_eq!(stats.top[2].1, 50);
    }

    /// A non-existent directory must return an empty `FsStats` rather than
    /// panicking.
    #[test]
    fn compute_fs_stats_missing_dir() {
        let stats = compute_fs_stats(std::path::Path::new("/this/path/does/not/exist"));
        assert_eq!(
            stats.total_bytes, 0,
            "missing dir must yield total_bytes = 0"
        );
        assert!(
            stats.top.is_empty(),
            "missing dir must yield an empty top list"
        );
    }

    /// When there are more than 10 files, `top` must be truncated to 10
    /// entries (the largest ones).
    #[test]
    fn compute_fs_stats_truncates_to_10() {
        let dir = tempfile::tempdir().expect("tempdir");

        for i in 0..12u64 {
            let name = format!("file{i:02}.db");
            // Give each file a distinct size so sort order is deterministic.
            std::fs::write(dir.path().join(&name), vec![0u8; (i + 1) as usize])
                .expect("write file");
        }

        let stats = compute_fs_stats(dir.path());

        assert_eq!(stats.top.len(), 10, "top must be capped at 10 entries");
        // The top entry must be the largest file (file11, size 12).
        assert_eq!(
            stats.top[0].1, 12,
            "largest file must be first; got {} bytes",
            stats.top[0].1
        );
    }
}
