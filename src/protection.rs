use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::DefaultHasher, HashSet};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTRY_VERSION: u64 = 1;
pub const DEFAULT_PROTECTION_TTL_DAYS: u64 = 7;
pub const MAX_PROTECTION_TTL_DAYS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug)]
pub enum ProtectionGuardOutcome<T> {
    Protected(ProtectionMatch),
    Executed(T),
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
    optional_protection_registry_path().context("neither XDG_STATE_HOME nor HOME is set")
}

fn optional_protection_registry_path() -> Option<PathBuf> {
    protection_registry_path_from(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
}

#[cfg(not(test))]
fn required_protection_registry_path() -> Result<PathBuf> {
    required_registry_path_from(optional_protection_registry_path())
}

fn required_registry_path_from(path: Option<PathBuf>) -> Result<PathBuf> {
    path.context(
        "cannot execute destructive cleanup without XDG_STATE_HOME or HOME to enforce protections",
    )
}

fn protection_registry_path_from(
    xdg_state_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    if let Some(path) = xdg_state_home.filter(|path| !path.is_empty()) {
        return Some(PathBuf::from(path).join("worktree-gc/protections.json"));
    }
    home.filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .map(|home| home.join(".local/state/worktree-gc/protections.json"))
}

#[cfg(test)]
pub fn active_protections(now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let _ = now;
    Ok(Vec::new())
}

#[cfg(not(test))]
pub fn active_protections(now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let Some(registry_path) = optional_protection_registry_path() else {
        return Ok(Vec::new());
    };
    active_protections_at(&registry_path, now)
}

fn active_protections_at(path: &Path, now: SystemTime) -> Result<Vec<ProtectionLease>> {
    with_registry_lock(path, || read_active_protections(path, now))
}

#[cfg(test)]
pub fn with_protection_guard<T>(
    path: &Path,
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    let _ = (path, now);
    Ok(ProtectionGuardOutcome::Executed(operation()))
}

#[cfg(test)]
pub fn with_protection_guard_for_paths<T>(
    paths: &[PathBuf],
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    let _ = (paths, now);
    Ok(ProtectionGuardOutcome::Executed(operation()))
}

#[cfg(not(test))]
pub fn with_protection_guard<T>(
    path: &Path,
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    let registry_path = required_protection_registry_path()?;
    with_protection_guard_at(&registry_path, path, now, operation)
}

#[cfg(not(test))]
pub fn with_protection_guard_for_paths<T>(
    paths: &[PathBuf],
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    let registry_path = required_protection_registry_path()?;
    with_protection_guards_at(&registry_path, paths, now, operation)
}

fn with_protection_guard_at<T>(
    registry_path: &Path,
    path: &Path,
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    with_protection_guards_at(
        registry_path,
        std::slice::from_ref(&path.to_path_buf()),
        now,
        operation,
    )
}

fn with_protection_guards_at<T>(
    registry_path: &Path,
    paths: &[PathBuf],
    now: SystemTime,
    operation: impl FnOnce() -> T,
) -> Result<ProtectionGuardOutcome<T>> {
    with_registry_lock(registry_path, || {
        let protections = read_active_protections(registry_path, now)?;
        if let Some(lease) = paths
            .iter()
            .find_map(|path| protection_for_path(path, &protections))
        {
            return Ok(ProtectionGuardOutcome::Protected(lease));
        }
        Ok(ProtectionGuardOutcome::Executed(operation()))
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
    let reason = reason.trim();
    validate_reason(reason)?;
    let path = fs::canonicalize(path)
        .with_context(|| format!("failed to resolve protection path {path:?}"))?;
    validate_stored_path(&path).with_context(|| format!("invalid protection path {path:?}"))?;
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
        reason: reason.to_string(),
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
    registry.leases[index].expires_at_unix = registry.leases[index]
        .expires_at_unix
        .max(unix_seconds(now).saturating_add(ttl_days.saturating_mul(86_400)));
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
    read_active_protections(registry_path, now)
}

fn read_active_protections(registry_path: &Path, now: SystemTime) -> Result<Vec<ProtectionLease>> {
    let mut registry = read_registry(registry_path)?;
    let original_len = registry.leases.len();
    registry.leases.retain(|lease| lease.is_active(now));
    let max_expiry =
        unix_seconds(now).saturating_add(MAX_PROTECTION_TTL_DAYS.saturating_mul(86_400));
    if let Some(lease) = registry
        .leases
        .iter()
        .find(|lease| lease.expires_at_unix > max_expiry)
    {
        bail!(
            "protection {} in {} expires beyond the {MAX_PROTECTION_TTL_DAYS}-day limit",
            lease.id,
            registry_path.display()
        );
    }
    for lease in &registry.leases {
        let mut dormant = false;
        for prefix in lease.path.ancestors().collect::<Vec<_>>().into_iter().rev() {
            match fs::symlink_metadata(prefix) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    bail!(
                        "active protection path {} for lease {} in {} is not canonical",
                        lease.path.display(),
                        lease.id,
                        registry_path.display()
                    );
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    dormant = true;
                    break;
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to inspect active protection path {} for lease {} in {}",
                            lease.path.display(),
                            lease.id,
                            registry_path.display()
                        )
                    });
                }
            }
        }
        if dormant {
            continue;
        }
        let canonical = match fs::canonicalize(&lease.path) {
            Ok(canonical) => canonical,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // A component disappeared after the prefix walk. Treat this
                // TOCTOU window like an ordinary dormant path: there is no
                // resolved candidate to mutate now, and the stored canonical
                // path is protected again if it reappears before expiry.
                continue;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to resolve active protection path {} for lease {} in {}",
                        lease.path.display(),
                        lease.id,
                        registry_path.display()
                    )
                });
            }
        };
        if canonical != lease.path {
            bail!(
                "active protection path {} for lease {} in {} is not canonical",
                lease.path.display(),
                lease.id,
                registry_path.display()
            );
        }
    }
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

fn validate_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("protection reason must not be empty");
    }
    if reason.chars().any(char::is_control) {
        bail!("protection reason must not contain control characters");
    }
    Ok(())
}

fn validate_lease_id(id: &str) -> Result<()> {
    let Some(hash) = id.strip_prefix("p-") else {
        bail!("protection id must start with 'p-'");
    };
    if hash.len() != 16
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("protection id must contain 16 lowercase hexadecimal digits");
    }
    Ok(())
}

fn validate_stored_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("protection path must be absolute");
    }
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        bail!("protection path must not contain '.' or '..' components");
    }
    if path.to_string_lossy().chars().any(char::is_control) {
        bail!("protection path must not contain control characters");
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
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    for lease in &registry.leases {
        validate_lease_id(&lease.id)
            .with_context(|| format!("invalid protection id in {}", path.display()))?;
        validate_reason(&lease.reason).with_context(|| {
            format!(
                "invalid protection reason for lease {} in {}",
                lease.id,
                path.display()
            )
        })?;
        validate_stored_path(&lease.path).with_context(|| {
            format!(
                "invalid protection path for lease {} in {}",
                lease.id,
                path.display()
            )
        })?;
        if lease.created_at_unix > lease.expires_at_unix {
            bail!(
                "protection {} in {} expires before it was created",
                lease.id,
                path.display()
            );
        }
        if !ids.insert(&lease.id) {
            bail!("duplicate protection id {} in {}", lease.id, path.display());
        }
        if !paths.insert(&lease.path) {
            bail!(
                "duplicate protection path {} in {}",
                lease.path.display(),
                path.display()
            );
        }
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
    let unlock = lock
        .unlock()
        .with_context(|| format!("failed to unlock protection registry {}", path.display()));
    finish_registry_operation(result, unlock)
}

fn finish_registry_operation<T>(operation: Result<T>, unlock: Result<()>) -> Result<T> {
    match operation {
        Err(error) => {
            if let Err(unlock_error) = unlock {
                eprintln!(
                    "warning: protection registry unlock also failed after an operation error: {unlock_error:#}"
                );
            }
            Err(error)
        }
        Ok(value) => {
            unlock?;
            Ok(value)
        }
    }
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
    use std::cell::Cell;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn missing_state_home_means_no_optional_registry() {
        assert!(protection_registry_path_from(None, None).is_none());
        assert!(protection_registry_path_from(Some(OsString::new()), None).is_none());
        assert_eq!(
            protection_registry_path_from(
                Some(OsString::new()),
                Some(OsString::from("/home/example"))
            ),
            Some(PathBuf::from(
                "/home/example/.local/state/worktree-gc/protections.json"
            ))
        );
    }

    #[test]
    fn destructive_guards_require_a_registry_location() {
        let error = required_registry_path_from(None)
            .expect_err("destructive operations must fail closed without state home");
        assert!(error
            .to_string()
            .contains("cannot execute destructive cleanup"));
    }

    #[test]
    fn operation_errors_take_precedence_over_unlock_errors() {
        let operation = finish_registry_operation::<()>(
            Err(anyhow::anyhow!("operation failed")),
            Err(anyhow::anyhow!("unlock failed")),
        )
        .expect_err("operation should fail");
        assert_eq!(operation.to_string(), "operation failed");

        let unlock = finish_registry_operation(Ok(()), Err(anyhow::anyhow!("unlock failed")))
            .expect_err("unlock should fail after a successful operation");
        assert_eq!(unlock.to_string(), "unlock failed");
    }

    #[test]
    fn registry_reads_reject_reason_injection() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut lease = add_protection_at(&registry, &protected, "safe reason".into(), 7, now)?;
        lease.reason = "forged\nlog entry".into();
        write_registry(
            &registry,
            &ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: vec![lease],
            },
        )?;

        let error = read_registry(&registry).expect_err("forged reasons should fail closed");
        assert!(error.to_string().contains("invalid protection reason"));
        Ok(())
    }

    #[test]
    fn registry_reads_reject_invalid_ids() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut lease = add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        lease.id = "p-forged\nentry".into();
        write_registry(
            &registry,
            &ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: vec![lease],
            },
        )?;

        let error = read_registry(&registry).expect_err("invalid ids should fail closed");
        assert!(error.to_string().contains("invalid protection id"));
        Ok(())
    }

    #[test]
    fn registry_reads_reject_noncanonical_paths() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut lease = add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        lease.path = PathBuf::from("../forged");
        write_registry(
            &registry,
            &ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: vec![lease],
            },
        )?;

        let error = read_registry(&registry).expect_err("relative paths should fail closed");
        assert!(error.to_string().contains("invalid protection path"));
        Ok(())
    }

    #[test]
    fn registry_reads_reject_unknown_lease_fields() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        fs::write(
            &registry,
            serde_json::to_vec_pretty(&serde_json::json!({
                "version": REGISTRY_VERSION,
                "leases": [{
                    "id": "p-fixture",
                    "path": "/tmp/protected",
                    "reason": "fixture",
                    "created_at_unix": 1,
                    "expires_at_unix": 2,
                    "unexpected": true
                }]
            }))?,
        )?;

        let error = read_registry(&registry).expect_err("unknown fields should fail closed");
        assert!(format!("{error:#}").contains("unknown field"));
        Ok(())
    }

    #[test]
    fn active_reads_reject_expiry_beyond_the_ttl_cap() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut lease = add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        lease.expires_at_unix = u64::MAX;
        write_registry(
            &registry,
            &ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: vec![lease],
            },
        )?;

        let error = active_protections_at(&registry, now)
            .expect_err("out-of-policy expiry should fail closed");
        assert!(error.to_string().contains("expires beyond"));
        Ok(())
    }

    #[test]
    fn active_reads_retain_missing_paths_as_dormant_leases() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let lease = add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        fs::remove_dir(&protected)?;

        assert_eq!(active_protections_at(&registry, now)?, vec![lease.clone()]);

        fs::create_dir(&protected)?;
        assert_eq!(active_protections_at(&registry, now)?, vec![lease]);
        let ran = Cell::new(false);
        let outcome = with_protection_guard_at(&registry, &protected, now, || ran.set(true))?;
        assert!(matches!(outcome, ProtectionGuardOutcome::Protected(_)));
        assert!(!ran.get());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn active_reads_reject_symlinked_paths() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        let linked = temp.path().join("linked");
        fs::create_dir_all(&protected)?;
        std::os::unix::fs::symlink(&protected, &linked)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let mut lease = add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        lease.path = linked;
        write_registry(
            &registry,
            &ProtectionRegistry {
                version: REGISTRY_VERSION,
                leases: vec![lease],
            },
        )?;

        let error = active_protections_at(&registry, now)
            .expect_err("symlinked active paths should fail closed");
        assert!(error.to_string().contains("is not canonical"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn active_reads_reject_dangling_symlink_replacements() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        fs::remove_dir(&protected)?;
        std::os::unix::fs::symlink(temp.path().join("missing"), &protected)?;

        let error = active_protections_at(&registry, now)
            .expect_err("a dangling symlink replacement must fail closed");
        assert!(error.to_string().contains("is not canonical"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn active_reads_reject_dangling_intermediate_symlink_replacements() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let parent = temp.path().join("parent");
        let protected = parent.join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "fixture".into(), 7, now)?;
        fs::remove_dir(&protected)?;
        fs::remove_dir(&parent)?;
        std::os::unix::fs::symlink(temp.path().join("missing"), &parent)?;

        let error = active_protections_at(&registry, now)
            .expect_err("a dangling intermediate symlink replacement must fail closed");
        assert!(error.to_string().contains("is not canonical"));
        Ok(())
    }

    #[test]
    fn active_reads_lock_even_when_the_registry_is_missing_and_fail_closed() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        assert!(active_protections_at(&registry, now)?.is_empty());
        assert!(registry.parent().unwrap().join("protections.lock").exists());

        fs::write(&registry, b"not json")?;
        let error = active_protections_at(&registry, now)
            .expect_err("an unreadable registry must stop cleanup planning");
        assert!(error.to_string().contains("failed to parse"));
        Ok(())
    }

    #[test]
    fn active_reads_compact_expired_leases() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let start = UNIX_EPOCH + Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "short lease".into(), 1, start)?;

        let expired = start + Duration::from_secs(86_400);
        assert!(active_protections_at(&registry, expired)?.is_empty());
        assert!(read_registry(&registry)?.leases.is_empty());
        Ok(())
    }

    #[test]
    fn guard_blocks_a_protected_operation() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "active gate".into(), 7, now)?;
        let ran = Cell::new(false);

        let outcome = with_protection_guard_at(&registry, &protected, now, || ran.set(true))?;
        assert!(matches!(outcome, ProtectionGuardOutcome::Protected(_)));
        assert!(!ran.get());
        Ok(())
    }

    #[test]
    fn multi_path_guard_blocks_global_repo_mutations() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        let sibling = temp.path().join("sibling");
        fs::create_dir_all(&protected)?;
        fs::create_dir_all(&sibling)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        add_protection_at(&registry, &protected, "active gate".into(), 7, now)?;
        let ran = Cell::new(false);

        let outcome =
            with_protection_guards_at(&registry, &[sibling, protected], now, || ran.set(true))?;
        assert!(matches!(outcome, ProtectionGuardOutcome::Protected(_)));
        assert!(!ran.get());
        Ok(())
    }

    #[test]
    fn guard_holds_the_registry_lock_through_the_operation() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let (entered_tx, entered_rx) = mpsc::sync_channel(0);
        let (release_tx, release_rx) = mpsc::sync_channel(0);
        let worker_registry = registry.clone();
        let worker_protected = protected.clone();
        let worker = thread::spawn(move || {
            with_protection_guard_at(&worker_registry, &worker_protected, now, || {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            })
        });
        entered_rx.recv()?;

        let (added_tx, added_rx) = mpsc::sync_channel(0);
        let add_registry = registry.clone();
        let add_protected = protected.clone();
        let adder = thread::spawn(move || {
            let result = with_registry_lock(&add_registry, || {
                add_protection_at(&add_registry, &add_protected, "late lease".into(), 7, now)
            });
            added_tx.send(result).unwrap();
        });

        assert!(matches!(
            added_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(())?;
        assert!(matches!(
            worker.join().unwrap()?,
            ProtectionGuardOutcome::Executed(())
        ));
        added_rx.recv_timeout(Duration::from_secs(2))??;
        adder.join().unwrap();
        Ok(())
    }

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
    fn renewal_never_shortens_an_active_lease() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("state/protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let lease = add_protection_at(&registry, &protected, "fixture".into(), 30, now)?;

        let renewed = renew_protection_at(&registry, &lease.id, DEFAULT_PROTECTION_TTL_DAYS, now)?;
        assert_eq!(renewed.expires_at_unix, lease.expires_at_unix);
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

    #[test]
    fn reasons_reject_structured_output_injection() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("protected");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        for reason in ["line one\nline two", "column one\tcolumn two"] {
            let error = add_protection_at(&registry, &protected, reason.into(), 7, now)
                .expect_err("control characters should be rejected");
            assert!(error.to_string().contains("control characters"));
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn add_rejects_path_output_injection() -> Result<()> {
        let temp = TempDir::new()?;
        let registry = temp.path().join("protections.json");
        let protected = temp.path().join("forged\npath");
        fs::create_dir_all(&protected)?;
        let now = UNIX_EPOCH + Duration::from_secs(1_000);

        let error = add_protection_at(&registry, &protected, "fixture".into(), 7, now)
            .expect_err("control characters in paths should be rejected before writing");
        let rendered = format!("{error:#}");
        assert!(rendered.contains("invalid protection path"));
        assert!(rendered.contains("forged\\npath"));
        assert!(!rendered.contains("forged\npath"));
        assert!(!registry.exists());
        Ok(())
    }
}
