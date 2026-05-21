//! Disk cache for registry metadata responses.
//!
//! Cache key: `(registry, pkg_name)`. Cache value: a small JSON record containing
//! the latest version, its publish date (RFC 3339), and the package creation
//! date. The age-in-hours is recomputed from the stored RFC 3339 date at every
//! read, so a cached "published 6h ago" record correctly becomes "published
//! 30h ago" the next day. The cache exists to skip HTTP, not to freeze time.
//!
//! TTL: 7 days. Publish dates do not move retroactively; refreshing weekly
//! catches new releases without thundering the registry every audit run.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// 7 days, matching the version-age threshold so the cache rolls fresh enough
/// to detect a newly published version on its next install.
const CACHE_TTL: chrono::Duration = chrono::Duration::days(7);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryMeta {
    pub registry: String,
    pub name: String,
    pub cached_at: DateTime<Utc>,
    pub latest_version: Option<String>,
    pub latest_publish_date: Option<DateTime<Utc>>,
    pub created_date: Option<DateTime<Utc>>,
    pub weekly_downloads: Option<u64>,
}

impl RegistryMeta {
    pub fn is_fresh(&self) -> bool {
        self.is_fresh_at(Utc::now())
    }

    fn is_fresh_at(&self, now: DateTime<Utc>) -> bool {
        now.signed_duration_since(self.cached_at) < CACHE_TTL
    }
}

/// Compute the cache file path for (registry, pkg_name). Override the base
/// directory with $SANDTRACE_CACHE_DIR for tests / sandboxed CI.
pub fn cache_path(registry: &str, pkg_name: &str) -> Option<PathBuf> {
    let base = cache_base_dir()?;
    // Scope keys live one directory deep so `@scope/name` does not collide
    // with `name`. Replace path-unsafe `/` with `__` to keep one file per pkg.
    let safe = pkg_name.replace('/', "__");
    Some(base.join(registry).join(format!("{safe}.json")))
}

fn cache_base_dir() -> Option<PathBuf> {
    if let Ok(custom) = std::env::var("SANDTRACE_CACHE_DIR") {
        return Some(PathBuf::from(custom));
    }
    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".cache/sandtrace/registry-meta"))
}

/// Read a cached registry record. Returns None on miss, corrupt JSON, or
/// expired TTL.
pub fn read(registry: &str, pkg_name: &str) -> Option<RegistryMeta> {
    let path = cache_path(registry, pkg_name)?;
    let bytes = std::fs::read(&path).ok()?;
    let meta: RegistryMeta = serde_json::from_slice(&bytes).ok()?;
    if !meta.is_fresh() {
        return None;
    }
    Some(meta)
}

/// Persist a registry record to disk. Failures are silent (best-effort cache;
/// a write failure should never break the audit).
pub fn write(meta: &RegistryMeta) {
    let Some(path) = cache_path(&meta.registry, &meta.name) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec(meta) {
        let _ = std::fs::write(&path, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Serializes cache tests because SANDTRACE_CACHE_DIR is a process-wide env var.
    /// cargo's default parallel test runner would otherwise let two tests race
    /// on set_var/remove_var.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn with_cache_dir<F: FnOnce()>(dir: &std::path::Path, f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: ENV_LOCK serializes access; only one test mutates the env at a time.
        unsafe { std::env::set_var("SANDTRACE_CACHE_DIR", dir) };
        f();
        unsafe { std::env::remove_var("SANDTRACE_CACHE_DIR") };
    }

    fn fixture_meta(cached_at: DateTime<Utc>) -> RegistryMeta {
        RegistryMeta {
            registry: "npm".to_string(),
            name: "left-pad".to_string(),
            cached_at,
            latest_version: Some("1.3.0".to_string()),
            latest_publish_date: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            created_date: Some(Utc.with_ymd_and_hms(2014, 4, 1, 0, 0, 0).unwrap()),
            weekly_downloads: Some(15_000_000),
        }
    }

    #[test]
    fn round_trip_write_read() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            let meta = fixture_meta(Utc::now());
            write(&meta);
            let read_back = read("npm", "left-pad").expect("cache hit");
            assert_eq!(read_back.latest_version, meta.latest_version);
            assert_eq!(read_back.weekly_downloads, meta.weekly_downloads);
        });
    }

    #[test]
    fn miss_when_no_entry() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            assert!(read("npm", "no-such-package").is_none());
        });
    }

    #[test]
    fn ttl_expiry_invalidates() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            // Cached 30 days ago — well past the 7d TTL.
            let stale = fixture_meta(Utc::now() - chrono::Duration::days(30));
            write(&stale);
            assert!(read("npm", "left-pad").is_none(), "expired cache returned");
        });
    }

    #[test]
    fn ttl_fresh_within_window() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            let fresh = fixture_meta(Utc::now() - chrono::Duration::hours(36));
            write(&fresh);
            assert!(read("npm", "left-pad").is_some(), "fresh cache missing");
        });
    }

    #[test]
    fn scoped_package_name_safe_path() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            let mut meta = fixture_meta(Utc::now());
            meta.name = "@scope/pkg".to_string();
            write(&meta);
            let read_back = read("npm", "@scope/pkg").expect("scoped cache hit");
            assert_eq!(read_back.name, "@scope/pkg");
        });
    }

    #[test]
    fn corrupt_json_returns_none() {
        let dir = TempDir::new().unwrap();
        with_cache_dir(dir.path(), || {
            let path = cache_path("npm", "broken").unwrap();
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "{not json}").unwrap();
            assert!(read("npm", "broken").is_none());
        });
    }
}
