use anyhow::{bail, Context, Result};
use cargo_metadata::MetadataCommand;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use walkdir::WalkDir;

pub const TRASH_DIR_NAME: &str = ".worktree-gc-trash";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SweepCandidateAction {
    Delete,
    Keep,
    RecoverTrash,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepCandidateDecision {
    pub path: PathBuf,
    pub incremental_dir: PathBuf,
    pub profile_dir: PathBuf,
    pub lock_path: PathBuf,
    pub last_activity_unix: Option<i64>,
    pub last_activity: Option<String>,
    pub activity_age_days: Option<u64>,
    pub logical_bytes: u64,
    pub action: SweepCandidateAction,
    pub reason: String,
}

pub(crate) struct IncrementalPlan {
    pub candidates: Vec<SweepCandidateDecision>,
    pub reason: String,
}

pub(crate) fn plan_incremental_sweep(
    target_dir: &Path,
    worktree: &Path,
    days: u64,
    now: SystemTime,
) -> Result<IncrementalPlan> {
    let target_dir = fs::canonicalize(target_dir)
        .with_context(|| format!("failed to canonicalize {}", target_dir.display()))?;
    let worktree = fs::canonicalize(worktree)
        .with_context(|| format!("failed to canonicalize {}", worktree.display()))?;

    if !target_dir.starts_with(&worktree) {
        return Ok(unsupported(format!(
            "Cargo target directory is outside the worktree: {}",
            target_dir.display()
        )));
    }

    let Some(manifest_path) = nearest_manifest(&target_dir, &worktree) else {
        return Ok(unsupported(format!(
            "no Cargo.toml owns {}",
            target_dir.display()
        )));
    };

    let mut command = MetadataCommand::new();
    command
        .current_dir(
            manifest_path
                .parent()
                .context("Cargo manifest has no parent directory")?,
        )
        .manifest_path(&manifest_path)
        .no_deps();
    // A metadata failure is a planning failure, not an unsupported layout: we
    // cannot prove target ownership while Cargo considers the manifest invalid.
    let metadata = command.exec().with_context(|| {
        format!(
            "cargo metadata failed for incremental sweep at {}",
            manifest_path.display()
        )
    })?;

    let reported_target = canonicalize_if_present(metadata.target_directory.as_std_path());
    let reported_build = metadata
        .build_directory
        .as_ref()
        .and_then(|path| canonicalize_if_present(path.as_std_path()))
        .or_else(|| reported_target.clone());

    if reported_target.as_deref() != Some(target_dir.as_path())
        && reported_build.as_deref() != Some(target_dir.as_path())
    {
        return Ok(unsupported(format!(
            "{} does not match Cargo's reported target/build directory",
            target_dir.display()
        )));
    }

    let Some(build_dir) = reported_build else {
        return Ok(unsupported(
            "Cargo build directory does not exist".to_string(),
        ));
    };
    if build_dir != target_dir {
        return Ok(unsupported(format!(
            "Cargo uses a separate build directory outside this target candidate: {}",
            build_dir.display()
        )));
    }
    if !build_dir.starts_with(&worktree) {
        return Ok(unsupported(format!(
            "Cargo build directory is outside the worktree: {}",
            build_dir.display()
        )));
    }

    let mut candidates = Vec::new();
    let mut seen_incremental_dirs = HashSet::new();
    for entry in WalkDir::new(&build_dir)
        .follow_links(false)
        .min_depth(1)
        .max_depth(3)
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect Cargo build directory {}",
                build_dir.display()
            )
        })?;
        if entry.file_name() != "incremental" {
            continue;
        }

        let entry_path = entry.path().to_path_buf();
        let profile_dir = entry_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| build_dir.clone());
        let lock_path = profile_dir.join(".cargo-lock");
        if entry.depth() != 2 && entry.depth() != 3 {
            candidates.push(skipped_candidate(
                entry_path.clone(),
                &entry_path,
                &profile_dir,
                &lock_path,
                "incremental directory has an unsupported Cargo profile layout",
            ));
            continue;
        }
        if entry.file_type().is_symlink() || !entry.file_type().is_dir() {
            candidates.push(skipped_candidate(
                entry_path.clone(),
                &entry_path,
                &profile_dir,
                &lock_path,
                "incremental directory is not a real directory",
            ));
            continue;
        }

        let incremental_dir = fs::canonicalize(entry.path()).with_context(|| {
            format!(
                "failed to canonicalize incremental directory {}",
                entry.path().display()
            )
        })?;
        if !incremental_dir.starts_with(&build_dir)
            || !seen_incremental_dirs.insert(incremental_dir.clone())
        {
            continue;
        }

        let Some(profile_dir) = incremental_dir.parent().map(Path::to_path_buf) else {
            continue;
        };
        let lock_path = profile_dir.join(".cargo-lock");
        if !lock_path.is_file() {
            candidates.push(SweepCandidateDecision {
                path: incremental_dir.clone(),
                incremental_dir,
                profile_dir,
                lock_path,
                last_activity_unix: None,
                last_activity: None,
                activity_age_days: None,
                logical_bytes: 0,
                action: SweepCandidateAction::Skip,
                reason: "Cargo profile has no .cargo-lock coordination file".to_string(),
            });
            continue;
        }

        for child in fs::read_dir(&incremental_dir).with_context(|| {
            format!(
                "failed to read incremental directory {}",
                incremental_dir.display()
            )
        })? {
            let child = child?;
            let path = child.path();
            let metadata = fs::symlink_metadata(&path)?;
            let name = child.file_name();

            if name == TRASH_DIR_NAME && metadata.is_dir() && !metadata.file_type().is_symlink() {
                candidates.push(SweepCandidateDecision {
                    logical_bytes: logical_size(&path)?,
                    path,
                    incremental_dir: incremental_dir.clone(),
                    profile_dir: profile_dir.clone(),
                    lock_path: lock_path.clone(),
                    last_activity_unix: None,
                    last_activity: None,
                    activity_age_days: None,
                    action: SweepCandidateAction::RecoverTrash,
                    reason: "recover tool-owned quarantine from an interrupted run".to_string(),
                });
                continue;
            }

            if metadata.file_type().is_symlink() {
                candidates.push(skipped_candidate(
                    path,
                    &incremental_dir,
                    &profile_dir,
                    &lock_path,
                    "incremental root is a symlink",
                ));
                continue;
            }
            if !metadata.is_dir() {
                candidates.push(skipped_candidate(
                    path,
                    &incremental_dir,
                    &profile_dir,
                    &lock_path,
                    "incremental entry is not a directory",
                ));
                continue;
            }

            let metrics = match incremental_metrics(&path) {
                Ok(metrics) => metrics,
                Err(error) if is_not_found_error(&error) => {
                    candidates.push(skipped_candidate(
                        path,
                        &incremental_dir,
                        &profile_dir,
                        &lock_path,
                        "incremental root changed while it was being inspected",
                    ));
                    continue;
                }
                Err(error) => return Err(error),
            };
            let last_activity_unix = metrics.last_activity_unix;
            let activity_age_days = last_activity_unix.and_then(|unix| age_days(now, unix));
            let action = if activity_age_days.is_some_and(|age| age >= days) {
                SweepCandidateAction::Delete
            } else {
                SweepCandidateAction::Keep
            };
            let reason = match action {
                SweepCandidateAction::Delete => {
                    format!("incremental root has been inactive for at least {days} days")
                }
                SweepCandidateAction::Keep => {
                    format!("incremental root activity is newer than {days} days")
                }
                _ => unreachable!(),
            };

            candidates.push(SweepCandidateDecision {
                logical_bytes: metrics.logical_bytes,
                path,
                incremental_dir: incremental_dir.clone(),
                profile_dir: profile_dir.clone(),
                lock_path: lock_path.clone(),
                last_activity_unix,
                last_activity: last_activity_unix.map(format_unix_time),
                activity_age_days,
                action,
                reason,
            });
        }
    }

    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let profile_count = seen_incremental_dirs.len();
    let delete_count = candidates
        .iter()
        .filter(|candidate| candidate.action == SweepCandidateAction::Delete)
        .count();
    Ok(IncrementalPlan {
        candidates,
        reason: format!(
            "inspected {profile_count} Cargo incremental profiles; {delete_count} stale roots"
        ),
    })
}

pub(crate) fn execute_incremental_sweep(
    candidates: &[SweepCandidateDecision],
    days: u64,
    run_id: &str,
) -> Result<()> {
    let mut groups: BTreeMap<(PathBuf, PathBuf), Vec<&SweepCandidateDecision>> = BTreeMap::new();
    for candidate in candidates {
        if matches!(
            candidate.action,
            SweepCandidateAction::Delete | SweepCandidateAction::RecoverTrash
        ) {
            groups
                .entry((
                    candidate.lock_path.clone(),
                    candidate.incremental_dir.clone(),
                ))
                .or_default()
                .push(candidate);
        }
    }

    for ((lock_path, incremental_dir), candidates) in groups {
        if !incremental_dir.exists() {
            continue;
        }
        let lock = wait_for_profile_lock(&lock_path)?;
        if !validate_planned_incremental_dir(&incremental_dir)? {
            continue;
        }
        let trash_root = incremental_dir.join(TRASH_DIR_NAME);
        let run_trash = trash_root.join(run_id);
        let mut quarantined = Vec::new();
        let mut old_quarantine_entries = Vec::new();
        let mut removed_bytes = candidates
            .iter()
            .filter(|candidate| candidate.action == SweepCandidateAction::RecoverTrash)
            .map(|candidate| candidate.logical_bytes)
            .sum::<u64>();
        let recovered_trash = candidates
            .iter()
            .filter(|candidate| candidate.action == SweepCandidateAction::RecoverTrash)
            .count();

        if trash_root.exists() {
            let metadata = fs::symlink_metadata(&trash_root)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!(
                    "refusing to recover invalid quarantine path {}",
                    trash_root.display()
                );
            }
            old_quarantine_entries = fs::read_dir(&trash_root)?
                .map(|entry| entry.map(|entry| entry.path()))
                .collect::<std::io::Result<Vec<_>>>()?;
        }

        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.action == SweepCandidateAction::Delete)
        {
            if !candidate.path.exists() || !is_direct_real_child(&candidate.path, &incremental_dir)?
            {
                continue;
            }
            let activity = newest_session_activity(&candidate.path)?;
            let still_stale = activity
                .and_then(|unix| age_days(SystemTime::now(), unix))
                .is_some_and(|age| age >= days);
            if !still_stale {
                eprintln!(
                    "  keeping refreshed incremental root {}",
                    candidate.path.display()
                );
                continue;
            }

            fs::create_dir_all(&run_trash)?;
            let file_name = candidate
                .path
                .file_name()
                .context("incremental root has no file name")?;
            let destination = run_trash.join(file_name);
            if destination.exists() {
                bail!(
                    "quarantine destination already exists: {}",
                    destination.display()
                );
            }
            fs::rename(&candidate.path, &destination).with_context(|| {
                format!(
                    "failed to quarantine incremental root {}",
                    candidate.path.display()
                )
            })?;
            removed_bytes = removed_bytes.saturating_add(candidate.logical_bytes);
            quarantined.push(destination);
        }

        drop(lock);

        for path in &old_quarantine_entries {
            remove_quarantine_entry(path)?;
        }
        if !quarantined.is_empty() {
            remove_quarantine_entry(&run_trash)?;
        }
        match fs::remove_dir(&trash_root) {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to remove quarantine directory {}",
                        trash_root.display()
                    )
                });
            }
        }
        if !quarantined.is_empty() || recovered_trash > 0 {
            eprintln!(
                "  removed {} incremental roots ({})",
                quarantined.len() + recovered_trash,
                format_bytes(removed_bytes)
            );
        }
    }

    Ok(())
}

pub(crate) fn with_cargo_profile_locks<T>(
    target_dir: &Path,
    worktree: &Path,
    action: impl FnOnce() -> T,
) -> Result<T> {
    loop {
        let lock_paths = cargo_profile_lock_paths(target_dir, worktree)?;
        let locks = wait_for_profile_locks(&lock_paths)?;
        let refreshed_lock_paths = cargo_profile_lock_paths(target_dir, worktree)?;
        if refreshed_lock_paths != lock_paths {
            eprintln!("  Cargo profile set changed while locking; retrying sweep coordination");
            drop(locks);
            continue;
        }
        let result = action();
        drop(locks);
        return Ok(result);
    }
}

fn cargo_profile_lock_paths(target_dir: &Path, worktree: &Path) -> Result<Vec<PathBuf>> {
    let target_dir = fs::canonicalize(target_dir)
        .with_context(|| format!("failed to canonicalize {}", target_dir.display()))?;
    let worktree = fs::canonicalize(worktree)
        .with_context(|| format!("failed to canonicalize {}", worktree.display()))?;
    if !target_dir.starts_with(&worktree) {
        bail!(
            "Cargo target directory is outside the worktree: {}",
            target_dir.display()
        );
    }

    let manifest_path = nearest_manifest(&target_dir, &worktree)
        .with_context(|| format!("no Cargo.toml owns {}", target_dir.display()))?;
    let mut command = MetadataCommand::new();
    command
        .current_dir(
            manifest_path
                .parent()
                .context("Cargo manifest has no parent directory")?,
        )
        .manifest_path(&manifest_path)
        .no_deps();
    let metadata = command.exec().with_context(|| {
        format!(
            "cargo metadata failed while coordinating {}",
            manifest_path.display()
        )
    })?;
    let reported_target = canonicalize_if_present(metadata.target_directory.as_std_path());
    let reported_build = metadata
        .build_directory
        .as_ref()
        .and_then(|path| canonicalize_if_present(path.as_std_path()))
        .or_else(|| reported_target.clone());
    if reported_target.as_deref() != Some(target_dir.as_path())
        && reported_build.as_deref() != Some(target_dir.as_path())
    {
        bail!(
            "{} does not match Cargo's reported target/build directory",
            target_dir.display()
        );
    }
    let build_dir = reported_build.context("Cargo build directory does not exist")?;
    if build_dir != target_dir || !build_dir.starts_with(&worktree) {
        bail!(
            "Cargo build directory cannot be coordinated inside this worktree: {}",
            build_dir.display()
        );
    }

    let mut lock_paths = BTreeSet::new();
    for entry in WalkDir::new(&build_dir)
        .follow_links(false)
        .min_depth(2)
        .max_depth(3)
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect Cargo profile locks under {}",
                build_dir.display()
            )
        })?;
        if entry.file_name() != ".cargo-lock"
            || entry.file_type().is_symlink()
            || !entry.file_type().is_file()
        {
            continue;
        }
        let profile_dir = fs::canonicalize(
            entry
                .path()
                .parent()
                .context("Cargo profile lock has no parent")?,
        )?;
        if profile_dir.starts_with(&build_dir) {
            lock_paths.insert(entry.path().to_path_buf());
        }
    }
    if lock_paths.is_empty() {
        bail!(
            "no Cargo profile locks found under {}; refusing an uncoordinated sweep",
            build_dir.display()
        );
    }
    Ok(lock_paths.into_iter().collect())
}

fn wait_for_profile_locks(lock_paths: &[PathBuf]) -> Result<Vec<File>> {
    let started = Instant::now();
    let mut backoff = Duration::from_millis(100);
    let mut next_progress = Duration::ZERO;

    loop {
        let mut locks = Vec::with_capacity(lock_paths.len());
        let mut contended = None;
        for lock_path in lock_paths {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(lock_path)
                .with_context(|| {
                    format!("failed to open Cargo profile lock {}", lock_path.display())
                })?;
            match file.try_lock() {
                Ok(()) => locks.push(file),
                Err(TryLockError::WouldBlock) => {
                    contended = Some(lock_path);
                    break;
                }
                Err(TryLockError::Error(error)) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to acquire Cargo profile lock {}",
                            lock_path.display()
                        )
                    });
                }
            }
        }

        if let Some(lock_path) = contended {
            drop(locks);
            if started.elapsed() >= next_progress {
                eprintln!(
                    "  waiting for Cargo build locks; contended at {} ({:.0}s)",
                    lock_path.display(),
                    started.elapsed().as_secs_f64()
                );
                let _ = io::stderr().flush();
                next_progress = started.elapsed() + Duration::from_secs(10);
            }
            thread::sleep(backoff);
            backoff = backoff.saturating_mul(2).min(Duration::from_secs(2));
            continue;
        }

        return Ok(locks);
    }
}

fn remove_quarantine_entry(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .with_context(|| format!("failed to remove quarantine entry {}", path.display()))
}

fn validate_planned_incremental_dir(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "refusing to sweep replaced incremental directory {}",
            path.display()
        );
    }
    if fs::canonicalize(path)? != path {
        bail!(
            "refusing to sweep incremental directory whose resolved path changed: {}",
            path.display()
        );
    }
    Ok(true)
}

fn wait_for_profile_lock(lock_path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(lock_path)
        .with_context(|| format!("failed to open Cargo profile lock {}", lock_path.display()))?;
    let started = Instant::now();
    let mut backoff = Duration::from_millis(100);
    let mut next_progress = Duration::ZERO;

    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {
                if started.elapsed() >= next_progress {
                    eprintln!(
                        "  waiting for Cargo build lock {} ({:.0}s)",
                        lock_path.display(),
                        started.elapsed().as_secs_f64()
                    );
                    let _ = io::stderr().flush();
                    next_progress = started.elapsed() + Duration::from_secs(10);
                }
                thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(Duration::from_secs(2));
            }
            Err(TryLockError::Error(error)) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to acquire Cargo profile lock {}",
                        lock_path.display()
                    )
                });
            }
        }
    }
}

fn nearest_manifest(target_dir: &Path, worktree: &Path) -> Option<PathBuf> {
    for ancestor in target_dir.parent()?.ancestors() {
        if !ancestor.starts_with(worktree) {
            break;
        }
        let manifest = ancestor.join("Cargo.toml");
        if manifest.is_file() {
            return Some(manifest);
        }
        if ancestor == worktree {
            break;
        }
    }
    None
}

fn canonicalize_if_present(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        fs::canonicalize(path).ok()
    } else {
        None
    }
}

fn unsupported(reason: String) -> IncrementalPlan {
    IncrementalPlan {
        candidates: Vec::new(),
        reason,
    }
}

fn skipped_candidate(
    path: PathBuf,
    incremental_dir: &Path,
    profile_dir: &Path,
    lock_path: &Path,
    reason: &str,
) -> SweepCandidateDecision {
    SweepCandidateDecision {
        path,
        incremental_dir: incremental_dir.to_path_buf(),
        profile_dir: profile_dir.to_path_buf(),
        lock_path: lock_path.to_path_buf(),
        last_activity_unix: None,
        last_activity: None,
        activity_age_days: None,
        logical_bytes: 0,
        action: SweepCandidateAction::Skip,
        reason: reason.to_string(),
    }
}

fn newest_session_activity(path: &Path) -> Result<Option<i64>> {
    Ok(incremental_metrics(path)?.last_activity_unix)
}

fn logical_size(path: &Path) -> Result<u64> {
    Ok(incremental_metrics(path)?.logical_bytes)
}

#[derive(Debug)]
struct IncrementalMetrics {
    last_activity_unix: Option<i64>,
    logical_bytes: u64,
}

fn incremental_metrics(path: &Path) -> Result<IncrementalMetrics> {
    let mut newest = None;
    let mut bytes = 0u64;
    for entry in WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        newest = max_time(newest, modified_unix(&metadata));
        if metadata.is_file() {
            bytes = bytes.saturating_add(metadata.len());
        }
    }
    Ok(IncrementalMetrics {
        last_activity_unix: newest,
        logical_bytes: bytes,
    })
}

fn is_not_found_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
    })
}

fn is_direct_real_child(path: &Path, incremental_dir: &Path) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(false);
    }
    let parent = path.parent().context("incremental root has no parent")?;
    Ok(fs::canonicalize(parent)? == fs::canonicalize(incremental_dir)?)
}

fn modified_unix(metadata: &fs::Metadata) -> Option<i64> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| duration.as_secs().try_into().ok())
}

fn max_time(left: Option<i64>, right: Option<i64>) -> Option<i64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn age_days(now: SystemTime, unix: i64) -> Option<u64> {
    let then = UNIX_EPOCH.checked_add(Duration::from_secs(unix.try_into().ok()?))?;
    Some(now.duration_since(then).unwrap_or(Duration::ZERO).as_secs() / 86_400)
}

fn format_unix_time(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

fn format_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB)
    } else {
        format!("{:.1} MiB", bytes as f64 / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use tempfile::TempDir;

    fn cargo_project() -> Result<(TempDir, PathBuf, PathBuf)> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("src"))?;
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )?;
        fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let target = repo.join("target");
        Ok((temp, repo, target))
    }

    fn profile(target: &Path, relative: &str) -> Result<PathBuf> {
        let profile = target.join(relative);
        fs::create_dir_all(profile.join("incremental"))?;
        fs::write(profile.join(".cargo-lock"), "")?;
        Ok(profile)
    }

    fn incremental_root(profile: &Path, name: &str, modified: SystemTime) -> Result<PathBuf> {
        let root = profile.join("incremental").join(name);
        let session = root.join("s-session-hash");
        fs::create_dir_all(&session)?;
        let dep_graph = session.join("dep-graph.bin");
        fs::write(&dep_graph, vec![0u8; 1024])?;
        set_modified(&dep_graph, modified)?;
        set_modified(&session, modified)?;
        set_modified(&root, modified)?;
        Ok(root)
    }

    fn set_modified(path: &Path, modified: SystemTime) -> Result<()> {
        File::options()
            .read(true)
            .open(path)?
            .set_modified(modified)?;
        Ok(())
    }

    #[test]
    fn missing_incremental_metrics_are_transient() -> Result<()> {
        let temp = TempDir::new()?;
        let error = incremental_metrics(&temp.path().join("removed-root"))
            .expect_err("missing root should fail its metrics walk");
        assert!(is_not_found_error(&error));
        Ok(())
    }

    #[test]
    fn plans_stale_roots_across_host_and_cross_profiles() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let host = profile(&target, "debug")?;
        let cross = profile(&target, "aarch64-unknown-linux-musl/debug")?;
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let old = now - Duration::from_secs(20 * 86_400);
        let recent = now - Duration::from_secs(2 * 86_400);
        let stale = fs::canonicalize(incremental_root(&host, "fixture-old", old)?)?;
        let fresh = fs::canonicalize(incremental_root(&cross, "fixture-new", recent)?)?;

        let plan = plan_incremental_sweep(&target, &repo, 14, now)?;
        let stale_decision = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == stale)
            .context("missing stale candidate")?;
        let fresh_decision = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fresh)
            .context("missing fresh candidate")?;

        assert_eq!(stale_decision.action, SweepCandidateAction::Delete);
        assert_eq!(fresh_decision.action, SweepCandidateAction::Keep);
        assert!(stale_decision.logical_bytes >= 1024);
        assert!(plan.reason.contains("2 Cargo incremental profiles"));
        Ok(())
    }

    #[test]
    fn metadata_mismatch_is_reported_without_candidates() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        fs::create_dir_all(&target)?;
        let unrelated = repo.join("nested/target");
        fs::create_dir_all(&unrelated)?;

        let plan = plan_incremental_sweep(&unrelated, &repo, 14, SystemTime::now())?;
        assert!(plan.candidates.is_empty());
        assert!(
            plan.reason.contains("does not match Cargo's reported"),
            "{}",
            plan.reason
        );
        Ok(())
    }

    #[test]
    fn external_cargo_target_directory_is_reported_without_candidates() -> Result<()> {
        let (temp, repo, target) = cargo_project()?;
        fs::create_dir_all(repo.join(".cargo"))?;
        fs::write(
            repo.join(".cargo/config.toml"),
            format!(
                "[build]\ntarget-dir = {:?}\n",
                temp.path().join("shared-target")
            ),
        )?;
        fs::create_dir_all(&target)?;

        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        assert!(plan.candidates.is_empty());
        assert!(
            plan.reason.contains("does not match Cargo's reported"),
            "{}",
            plan.reason
        );
        Ok(())
    }

    #[test]
    fn unsupported_incremental_layout_is_reported() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        fs::create_dir_all(target.join("incremental/root"))?;
        fs::write(target.join(".cargo-lock"), "")?;

        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path.ends_with("target/incremental"))
            .context("missing unsupported-layout candidate")?;
        assert_eq!(candidate.action, SweepCandidateAction::Skip);
        assert!(candidate
            .reason
            .contains("unsupported Cargo profile layout"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_roots_are_reported_and_kept() -> Result<()> {
        use std::os::unix::fs::symlink;

        let (_temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let outside = repo.join("outside");
        fs::create_dir_all(&outside)?;
        let link = profile.join("incremental/linked-root");
        symlink(&outside, &link)?;
        let planned_link = fs::canonicalize(profile.join("incremental"))?.join("linked-root");

        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == planned_link)
            .context("missing symlink candidate")?;
        assert_eq!(candidate.action, SweepCandidateAction::Skip);
        assert!(candidate.reason.contains("symlink"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn execution_rejects_an_incremental_directory_replaced_by_a_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;

        let (temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        let root = incremental_root(&profile, "fixture-old", old)?;
        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;

        let incremental = profile.join("incremental");
        let moved_incremental = profile.join("incremental-before-swap");
        fs::rename(&incremental, &moved_incremental)?;
        let outside = temp.path().join("outside-incremental");
        fs::create_dir_all(outside.join("fixture-old"))?;
        symlink(&outside, &incremental)?;

        let error = execute_incremental_sweep(&plan.candidates, 14, "symlink-swap-test")
            .expect_err("a replaced incremental directory must stop execution");
        assert!(error
            .to_string()
            .contains("refusing to sweep replaced incremental directory"));
        assert!(outside.join("fixture-old").exists());
        assert!(moved_incremental
            .join(root.file_name().context("incremental root has no name")?)
            .exists());
        Ok(())
    }

    #[test]
    fn execution_waits_for_cargo_and_revalidates_activity() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        let root = incremental_root(&profile, "fixture-old", old)?;
        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        let candidates = plan.candidates;

        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(profile.join(".cargo-lock"))?;
        lock.lock()?;
        let (started_tx, started_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            started_tx.send(()).unwrap();
            execute_incremental_sweep(&candidates, 14, "wait-test")
        });
        started_rx.recv()?;
        thread::sleep(Duration::from_millis(250));
        fs::write(root.join("fresh-session"), "fresh")?;
        lock.unlock()?;

        handle.join().expect("sweep thread panicked")?;
        assert!(root.exists());
        Ok(())
    }

    #[test]
    fn file_activity_inside_an_existing_session_keeps_the_root() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        let root = incremental_root(&profile, "fixture-old", old)?;
        set_modified(
            &root.join("s-session-hash/dep-graph.bin"),
            SystemTime::now(),
        )?;

        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        let canonical_root = fs::canonicalize(&root)?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == canonical_root)
            .context("missing incremental root")?;
        assert_eq!(candidate.action, SweepCandidateAction::Keep);
        Ok(())
    }

    #[test]
    fn execution_refuses_to_recreate_a_missing_profile_lock() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        let root = incremental_root(&profile, "fixture-old", old)?;
        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        fs::remove_file(profile.join(".cargo-lock"))?;

        let error = execute_incremental_sweep(&plan.candidates, 14, "missing-lock-test")
            .expect_err("a missing Cargo lock must stop execution");
        assert!(error
            .to_string()
            .contains("failed to open Cargo profile lock"));
        assert!(root.exists());
        assert!(!profile.join(".cargo-lock").exists());
        Ok(())
    }

    #[test]
    fn coordinated_external_sweep_retries_when_a_profile_appears() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let host = profile(&target, "debug")?;
        let host_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(host.join(".cargo-lock"))?;
        host_lock.lock()?;

        let (action_tx, action_rx) = mpsc::channel();
        let thread_target = target.clone();
        let thread_repo = repo.clone();
        let handle = thread::spawn(move || {
            with_cargo_profile_locks(&thread_target, &thread_repo, || action_tx.send(()).unwrap())
        });
        thread::sleep(Duration::from_millis(500));
        let cross = profile(&target, "aarch64-unknown-linux-musl/debug")?;
        let cross_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(cross.join(".cargo-lock"))?;
        cross_lock.lock()?;
        host_lock.unlock()?;
        thread::sleep(Duration::from_millis(500));
        assert!(matches!(
            action_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));

        cross_lock.unlock()?;
        action_rx.recv_timeout(Duration::from_secs(5))?;
        handle.join().expect("lock coordination thread panicked")?;

        for profile in [host, cross] {
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(profile.join(".cargo-lock"))?;
            lock.try_lock()?;
        }
        Ok(())
    }

    #[test]
    fn execution_quarantines_stale_roots_and_recovers_old_trash() -> Result<()> {
        let (_temp, repo, target) = cargo_project()?;
        let profile = profile(&target, "debug")?;
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        let root = incremental_root(&profile, "fixture-old", old)?;
        let old_trash = profile
            .join("incremental")
            .join(TRASH_DIR_NAME)
            .join("old-run");
        fs::create_dir_all(&old_trash)?;
        fs::write(old_trash.join("artifact"), "old")?;

        let plan = plan_incremental_sweep(&target, &repo, 14, SystemTime::now())?;
        assert!(plan
            .candidates
            .iter()
            .any(|candidate| candidate.action == SweepCandidateAction::RecoverTrash));
        execute_incremental_sweep(&plan.candidates, 14, "delete-test")?;

        assert!(!root.exists());
        assert!(!profile.join("incremental").join(TRASH_DIR_NAME).exists());
        Ok(())
    }
}
