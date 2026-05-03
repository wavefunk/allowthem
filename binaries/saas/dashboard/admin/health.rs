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
            }
        }
    };

    let mut files: Vec<(String, u64)> = Vec::new();
    let mut total_bytes: u64 = 0;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Ok(meta) = std::fs::metadata(&path) {
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
    }

    files.sort_by(|a, b| b.1.cmp(&a.1));
    files.truncate(10);

    FsStats {
        total_bytes,
        top: files,
    }
}

pub async fn page(
    RequireSuperAdmin(_scope): RequireSuperAdmin,
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
            nav_sections => nav,
            total_bytes => fs_stats.total_bytes,
            top_files => fs_stats.top,
            slug_cache_entries => slug_cache_entries,
            handle_cache_entries => handle_cache_entries,
        })
        .map_err(BrowserError::from)?;
    Ok(Html(body).into_response())
}
