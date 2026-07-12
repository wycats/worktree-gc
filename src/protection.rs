use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fs::{self, File, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTRY_VERSION: u64 = 1;
pub const DEFAULT_PROTECTION_TTL_DAYS: u64 = 7;
pub const MAX_PROTECTION_TTL_DAYS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionLease {
    pub id: String,
    pub path: PathBuf,
    pub reason: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
}

impl ProtectionLease {
    pub fn is_active(&self, now: SystemTime) -> bool {
        self.expires_at_unix > unix_seconds(now)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProtectionMatch {
    pub id: String,
    pub path: PathBuf,
    pub reason: String,
    pub expires_at_unix: u64,
}

impl From<&ProtectionLease> for ProtectionMatch {
    fn from(lease: &ProtectionLease) -> Self {
        Self {
            id: lease.id.clone(),
            path: lease.path.clone(),
            reason: lease.reason.clone(),
            expires_at_unix: lease.expires_at_unix,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectionRegistry {
    version: u64,
    leases: Vec<ProtectionLease>,
}

pub fn protection_registry_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path).join("worktree-gc/protections.json"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/state/worktree-gc/protections.json"))
}

#[cfg(test)]
pub fn active_protections(now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let _ = now;
    Ok(Vec::new())
}

#[cfg(not(test))]
pub fn active_protections(now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let registry_path = protection_registry_path()?;
    if !registry_path.exists() {
        return Ok(Vec::new());
    }
    with_registry_lock(&registry_path, || {
        Ok(read_registry(&registry_path)?
            .leases
            .into_iter()
            .filter(|lease| lease.is_active(now))
            .collect())
    })
}

pub fn add_protection(
    path: &Path,
    reason: String,
    ttl_days: u64,
    now: SystemTime,
) -> Result<ProtectionLease> {
    let registry_path = protection_registry_path()?;
    with_registry_lock(&registry_path, || {
        add_protection_at(&registry_path, path, reason, ttl_days, now)
    })
}

fn add_protection_at(
    registry_path: &Path,
    path: &Path,
    reason: String,
    ttl_days: u64,
    now: SystemTime,
) -> Result<ProtectionLease> {
    validate_ttl(ttl_days)?;
    if reason.trim().is_empty() {
        bail!("protection reason must not be empty");
    }
    let path = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve protection path {}", path.display()))?;
    let mut registry = read_registry(registry_path)?;
    registry.leases.retain(|lease| lease.is_active(now));
    if registry.leases.iter().any(|lease| lease.path == path) {
        bail!(
            "{} already has an active protection; use `protect renew`",
            path.display()
        );
    }
    let created_at_unix = unix_seconds(now);
    let expires_at_unix = created_at_unix.saturating_add(ttl_days.saturating_mul(86_400));
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    created_at_unix.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    let lease = ProtectionLease {
        id: format!("p-{:016x}", hasher.finish()),
        path,
        reason: reason.trim().to_string(),
        created_at_unix,
        expires_at_unix,
    };
    registry.leases.push(lease.clone());
    registry
        .leases
        .sort_by(|left, right| left.path.cmp(&right.path));
    write_registry(registry_path, &registry)?;
    Ok(lease)
}

pub fn renew_protection(selector: &str, ttl_days: u64, now: SystemTime) -> Result<ProtectionLease> {
    let registry_path = protection_registry_path()?;
    with_registry_lock(&registry_path, || {
        renew_protection_at(&registry_path, selector, ttl_days, now)
    })
}

fn renew_protection_at(
    registry_path: &Path,
    selector: &str,
    ttl_days: u64,
    now: SystemTime,
) -> Result<ProtectionLease> {
    validate_ttl(ttl_days)?;
    let mut registry = read_registry(registry_path)?;
    registry.leases.retain(|lease| lease.is_active(now));
    let index = find_lease(&registry.leases, selector)?;
    registry.leases[index].expires_at_unix =
        unix_seconds(now).saturating_add(ttl_days.saturating_mul(86_400));
    let lease = registry.leases[index].clone();
    write_registry(registry_path, &registry)?;
    Ok(lease)
}

pub fn remove_protection(selector: &str, now: SystemTime) -> Result<ProtectionLease> {
    let registry_path = protection_registry_path()?;
    with_registry_lock(&registry_path, || {
        remove_protection_at(&registry_path, selector, now)
    })
}

fn remove_protection_at(
    registry_path: &Path,
    selector: &str,
    now: SystemTime,
) -> Result<ProtectionLease> {
    let mut registry = read_registry(registry_path)?;
    registry.leases.retain(|lease| lease.is_active(now));
    let index = find_lease(&registry.leases, selector)?;
    let lease = registry.leases.remove(index);
    write_registry(registry_path, &registry)?;
    Ok(lease)
}

pub fn list_protections(now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let registry_path = protection_registry_path()?;
    with_registry_lock(&registry_path, || list_protections_at(&registry_path, now))
}

fn list_protections_at(registry_path: &Path, now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let mut registry = read_registry(registry_path)?;
    let original_len = registry.leases.len();
    registry.leases.retain(|lease| lease.is_active(now));
    if registry.leases.len() != original_len {
        write_registry(registry_path, &registry)?;
    }
    Ok(registry.leases)
}

pub fn protection_for_path(
    path: &Path,
    protections: &[ProtectionLease],
) -> Option<ProtectionMatch> {
    let candidate = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    protections
        .iter()
        .filter(|lease| candidate.starts_with(&lease.path) || lease.path.starts_with(&candidate))
        .max_by_key(|lease| lease.path.components().count())
        .map(ProtectionMatch::from)
}

fn validate_ttl(ttl_days: u64) -> Result<()> {
    if ttl_days == 0 {
        bail!("protection TTL must be at least 1 day");
    }
    if ttl_days > MAX_PROTECTION_TTL_DAYS {
        bail!(
            "protection TTL cannot exceed {MAX_PROTECTION_TTL_DAYS} days; renew it when intent is still active"
        );
    }
    Ok(())
}

fn find_lease(leases: &[ProtectionLease], selector: &str) -> Result<usize> {
    if let Some(index) = leases.iter().position(|lease| lease.id == selector) {
        return Ok(index);
    }
    let selected_path = fs::canonicalize(selector).unwrap_or_else(|_| PathBuf::from(selector));
    leases
        .iter()
        .position(|lease| lease.path == selected_path)
        .with_context(|| format!("no active protection matches '{selector}'"))
}

fn read_registry(path: &Path) -> Result<ProtectionRegistry> {
    let contents = match fs::read(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: Vec::new(),
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read protection registry {}", path.display()));
        }
    };
    let registry: ProtectionRegistry = serde_json::from_slice(&contents)
        .with_context(|| format!("failed to parse protection registry {}", path.display()))?;
    if registry.version != REGISTRY_VERSION {
        bail!(
            "unsupported protection registry version {} in {}",
            registry.version,
            path.display()
        );
    }
    Ok(registry)
}

fn with_registry_lock<T>(path: &Path, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let parent = path
        .parent()
        .context("protection registry path has no parent")?;
    fs::create_dir_all(parent)?;
    let lock_path = parent.join("protections.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open protection lock {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("failed to lock protection registry {}", path.display()))?;
    let result = operation();
    File::unlock(&lock)
        .with_context(|| format!("failed to unlock protection registry {}", path.display()))?;
    result
}

fn write_registry(path: &Path, registry: &ProtectionRegistry) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("failed to open protection registry {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(registry)?)
        .with_context(|| format!("failed to write protection registry {}", path.display()))?;
    file.commit()
        .with_context(|| format!("failed to commit protection registry {}", path.display()))
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn recursive_matching_protects_ancestors_and_descendants() -> Result<()> {
        let temp = TempDir::new()?;
        let worktree = temp.path().join("worktree");
        let target = worktree.join("target");
        fs::create_dir_all(&target)?;
        let worktree = fs::canonicalize(worktree)?;
        let target = fs::canonicalize(target)?;
        let lease = ProtectionLease {
            id: "p-test".into(),
            path: worktree.clone(),
            reason: "active work".into(),
            created_at_unix: 1,
            expires_at_unix: u64::MAX,
        };
        assert!(protection_for_path(&target, std::slice::from_ref(&lease)).is_some());

        let nested = ProtectionLease {
            path: target,
            ..lease
        };
        assert!(protection_for_path(&worktree, &[nested]).is_some());
        Ok(())
    }

    #[test]
    fn expiration_is_strict() {
        let lease = ProtectionLease {
            id: "p-test".into(),
            path: PathBuf::from("/tmp/example"),
            reason: "fixture".into(),
            created_at_unix: 10,
            expires_at_unix: 20,
        };
        assert!(lease.is_active(UNIX_EPOCH + std::time::Duration::from_secs(19)));
        assert!(!lease.is_active(UNIX_EPOCH + std::time::Duration::from_secs(20)));
    }

    #[test]
    fn ttl_is_bounded() {
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(DEFAULT_PROTECTION_TTL_DAYS).is_ok());
        assert!(validate_ttl(MAX_PROTECTION_TTL_DAYS + 1).is_err());
    }

    #[test]
    fn registry_add_renew_list_remove_and_prune_expired() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let start = UNIX_EPOCH + std::time::Duration::from_secs(1_000);

        let lease = add_protection_at(&registry, &protected, "active packaging".into(), 2, start)?;
        assert_eq!(list_protections_at(&registry, start)?.len(), 1);
        assert!(registry.exists());

        let renewed = renew_protection_at(&registry, &lease.id, 7, start)?;
        assert_eq!(renewed.expires_at_unix, unix_seconds(start) + 7 * 86_400);

        let removed = remove_protection_at(&registry, &lease.id, start)?;
        assert_eq!(removed.path, fs::canonicalize(&protected)?);
        assert!(list_protections_at(&registry, start)?.is_empty());

        add_protection_at(&registry, &protected, "short lease".into(), 1, start)?;
        let expired = start + std::time::Duration::from_secs(86_400);
        assert!(list_protections_at(&registry, expired)?.is_empty());
        assert!(read_registry(&registry)?.leases.is_empty());
        Ok(())
    }

    #[test]
    fn duplicate_active_paths_require_renewal() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "first".into(), 7, now)?;
        let error = add_protection_at(&registry, &protected, "second".into(), 7, now)
            .expect_err("duplicate active protection should fail");
        assert!(error.to_string().contains("protect renew"));
        Ok(())
    }
}
