use anyhow::{bail, Context, Result};
use cargo_metadata::MetadataCommand;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use walkdir::WalkDir;

use crate::cargo_incremental::{with_cargo_profile_locks_timeout, TRASH_DIR_NAME};
use crate::{
    process_ownership_evidence_for_paths, ProcessOwnershipEvidence, ProcessOwnershipEvidenceKind,
    SweepCandidateAction,
};

// Cargo build-script outputs commonly live below build/<unit>/out, and
// generated files can add another directory or two. Keep this bounded while
// sampling deeply enough that rewriting an existing output is visible.
const PROFILE_ACTIVITY_SAMPLE_DEPTH: usize = 6;
type CargoProfileOwnershipProbe<'a> =
    dyn Fn(&[PathBuf], &[PathBuf]) -> (HashSet<PathBuf>, bool) + 'a;
type CargoProfilePlanner<'a> =
    dyn Fn(&Path, &Path, u64, SystemTime) -> Result<CargoProfilePlan> + 'a;

struct CargoProfileExecutionProbes<'a> {
    ownership: &'a CargoProfileOwnershipProbe<'a>,
    planner: &'a CargoProfilePlanner<'a>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfileCandidateDecision {
    pub path: PathBuf,
    pub lock_path: PathBuf,
    pub cargo_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cargo_target: Option<String>,
    pub last_activity_unix: Option<i64>,
    pub last_activity: Option<String>,
    pub activity_age_days: Option<u64>,
    pub action: SweepCandidateAction,
    pub reason: String,
}

pub(crate) struct CargoProfilePlan {
    pub candidates: Vec<CargoProfileCandidateDecision>,
    pub reason: String,
}

pub(crate) fn plan_cargo_profile_sweep(
    target_dir: &Path,
    worktree: &Path,
    days: u64,
    now: SystemTime,
) -> Result<CargoProfilePlan> {
    let context = match resolve_build_context(target_dir, worktree)? {
        BuildContextResolution::Supported(context) => context,
        BuildContextResolution::Unsupported(reason) => {
            return Ok(CargoProfilePlan {
                candidates: Vec::new(),
                reason,
            });
        }
    };

    let mut candidates = Vec::new();
    let trash_root = context.build_dir.join(TRASH_DIR_NAME);
    if trash_root.exists() {
        let metadata = fs::symlink_metadata(&trash_root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("invalid Cargo profile quarantine {}", trash_root.display());
        }
        for entry in fs::read_dir(&trash_root)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                bail!("invalid Cargo profile quarantine entry {}", path.display());
            }
            let last_activity_unix = metadata.modified().ok().and_then(system_time_to_unix);
            candidates.push(CargoProfileCandidateDecision {
                path,
                lock_path: trash_root.clone(),
                cargo_profile: None,
                cargo_target: None,
                last_activity_unix,
                last_activity: last_activity_unix.map(format_unix_time),
                activity_age_days: last_activity_unix.and_then(|unix| age_days(now, unix)),
                action: SweepCandidateAction::RecoverTrash,
                reason: "recover profile quarantine from an interrupted run".to_string(),
            });
        }
    }
    for entry in WalkDir::new(&context.build_dir)
        .follow_links(false)
        .min_depth(2)
        .max_depth(3)
    {
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect Cargo profiles under {}",
                context.build_dir.display()
            )
        })?;
        if entry.file_name() != ".cargo-lock" {
            continue;
        }

        let profile_dir = entry
            .path()
            .parent()
            .context("Cargo profile lock has no parent")?
            .to_path_buf();
        let lock_path = entry.path().to_path_buf();
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            candidates.push(skipped_candidate(
                profile_dir,
                lock_path,
                "Cargo profile lock is not a real file",
            ));
            continue;
        }
        if entry.depth() != 2 && entry.depth() != 3 {
            candidates.push(skipped_candidate(
                profile_dir,
                lock_path,
                "Cargo profile has an unsupported output layout",
            ));
            continue;
        }

        let profile_dir = match fs::canonicalize(&profile_dir) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to resolve Cargo profile {}", profile_dir.display())
                });
            }
        };
        if !profile_dir.starts_with(&context.build_dir) {
            candidates.push(skipped_candidate(
                profile_dir,
                lock_path,
                "Cargo profile resolves outside the build directory",
            ));
            continue;
        }

        let relative = profile_dir
            .strip_prefix(&context.build_dir)
            .context("Cargo profile is outside the build directory")?;
        let components = relative.components().collect::<Vec<_>>();
        let cargo_target = match components.as_slice() {
            [_profile] => None,
            [target, _profile] => Some(
                target
                    .as_os_str()
                    .to_str()
                    .context("Cargo target directory has no UTF-8 name")?
                    .to_string(),
            ),
            _ => {
                candidates.push(skipped_candidate(
                    profile_dir,
                    lock_path,
                    "Cargo profile has an unsupported output layout",
                ));
                continue;
            }
        };
        if cargo_target.as_deref() == Some(TRASH_DIR_NAME) {
            continue;
        }
        let output_name = components
            .last()
            .and_then(|component| component.as_os_str().to_str())
            .context("Cargo profile directory has no UTF-8 name")?;
        let cargo_profile = match output_name {
            "debug" => "dev",
            "release" => "release",
            _ => {
                candidates.push(skipped_candidate(
                    profile_dir,
                    lock_path,
                    "custom Cargo profile directories cannot be mapped to a currently defined profile",
                ));
                continue;
            }
        }
        .to_string();
        let last_activity_unix = sampled_activity(&profile_dir)?;
        let activity_age_days = last_activity_unix.and_then(|unix| age_days(now, unix));
        let action = if activity_age_days.is_some_and(|age| age >= days) {
            SweepCandidateAction::Delete
        } else {
            SweepCandidateAction::Keep
        };
        let reason = match action {
            SweepCandidateAction::Delete => {
                format!("Cargo profile has been inactive for at least {days} days")
            }
            SweepCandidateAction::Keep => {
                format!("Cargo profile activity is newer than {days} days")
            }
            _ => unreachable!(),
        };
        candidates.push(CargoProfileCandidateDecision {
            path: profile_dir,
            lock_path,
            cargo_profile: Some(cargo_profile),
            cargo_target,
            last_activity_unix,
            last_activity: last_activity_unix.map(format_unix_time),
            activity_age_days,
            action,
            reason,
        });
    }

    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let delete_count = candidates
        .iter()
        .filter(|candidate| candidate.action == SweepCandidateAction::Delete)
        .count();
    Ok(CargoProfilePlan {
        reason: format!(
            "inspected {} Cargo profiles; {delete_count} stale profiles",
            candidates.len()
        ),
        candidates,
    })
}

pub(crate) fn execute_cargo_profile_reset(
    target_dir: &Path,
    worktree: &Path,
    candidates: &[CargoProfileCandidateDecision],
    days: u64,
    run_id: &str,
    timeout: Option<Duration>,
) -> Result<()> {
    execute_cargo_profile_reset_with_ownership(
        target_dir,
        worktree,
        candidates,
        days,
        run_id,
        timeout,
        &profile_ownership_evidence_ignoring_held_locks,
    )
}

fn execute_cargo_profile_reset_with_ownership(
    target_dir: &Path,
    worktree: &Path,
    candidates: &[CargoProfileCandidateDecision],
    days: u64,
    run_id: &str,
    timeout: Option<Duration>,
    ownership_probe: &CargoProfileOwnershipProbe<'_>,
) -> Result<()> {
    execute_cargo_profile_reset_with_probes(
        target_dir,
        worktree,
        candidates,
        days,
        run_id,
        timeout,
        CargoProfileExecutionProbes {
            ownership: ownership_probe,
            planner: &plan_cargo_profile_sweep,
        },
    )
}

fn execute_cargo_profile_reset_with_probes(
    target_dir: &Path,
    worktree: &Path,
    candidates: &[CargoProfileCandidateDecision],
    days: u64,
    run_id: &str,
    timeout: Option<Duration>,
    probes: CargoProfileExecutionProbes<'_>,
) -> Result<()> {
    let target_dir = fs::canonicalize(target_dir)
        .with_context(|| format!("failed to resolve {}", target_dir.display()))?;
    let trash_root = target_dir.join(TRASH_DIR_NAME);
    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.action == SweepCandidateAction::RecoverTrash)
    {
        if candidate.path.parent() != Some(trash_root.as_path()) {
            bail!(
                "profile quarantine candidate is outside {}: {}",
                trash_root.display(),
                candidate.path.display()
            );
        }
        remove_quarantine_entry(&candidate.path)?;
    }
    remove_empty_trash_root(&trash_root)?;

    let planned = candidates
        .iter()
        .filter(|candidate| candidate.action == SweepCandidateAction::Delete)
        .filter(|candidate| candidate.cargo_profile.is_some() && candidate.path.exists())
        .collect::<Vec<_>>();
    if planned.is_empty() {
        return Ok(());
    }

    let quarantined = with_cargo_profile_locks_timeout(
        &target_dir,
        worktree,
        timeout,
        |held_lock_paths| -> Result<Vec<(PathBuf, PathBuf)>> {
            let refreshed = (probes.planner)(&target_dir, worktree, days, SystemTime::now())?;
            let mut stale = Vec::new();
            for candidate in &planned {
                let profile = candidate
                    .cargo_profile
                    .as_deref()
                    .context("Cargo profile candidate has no profile identity")?;
                let remains_stale = refreshed.candidates.iter().any(|refreshed| {
                    refreshed.path == candidate.path
                        && refreshed.cargo_profile.as_deref() == Some(profile)
                        && refreshed.action == SweepCandidateAction::Delete
                });
                if !remains_stale {
                    eprintln!(
                        "  keeping Cargo profile refreshed while waiting for its lock {}",
                        candidate.path.display()
                    );
                    continue;
                }
                stale.push((*candidate, profile));
            }
            if stale.is_empty() {
                return Ok(Vec::new());
            }

            let stale_paths = stale
                .iter()
                .map(|(candidate, _)| candidate.path.clone())
                .collect::<Vec<_>>();
            let (open_profiles, complete) = (probes.ownership)(&stale_paths, held_lock_paths);
            if !complete {
                for (candidate, _) in stale {
                    eprintln!(
                        "  keeping Cargo profile with incomplete ownership evidence {}",
                        candidate.path.display()
                    );
                }
                return Ok(Vec::new());
            }

            let mut eligible = Vec::new();
            for (candidate, profile) in stale {
                if open_profiles.contains(&candidate.path) {
                    eprintln!(
                        "  keeping Cargo profile owned by a running process {}",
                        candidate.path.display()
                    );
                    continue;
                }
                eligible.push((candidate, profile));
            }

            let mut quarantined = Vec::new();
            for (candidate, profile) in eligible {
                let metadata = fs::symlink_metadata(&candidate.path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "refusing to reset replaced Cargo profile {}",
                        candidate.path.display()
                    );
                }
                let relative = validated_profile_relative_path(
                    &target_dir,
                    &candidate.path,
                    profile,
                    candidate.cargo_target.as_deref(),
                )?;
                let run_trash = trash_root.join(run_id);
                fs::create_dir_all(&run_trash)?;
                let run_trash = fs::canonicalize(&run_trash)?;
                let destination = run_trash.join(relative);
                let destination_parent = destination
                    .parent()
                    .context("profile quarantine has no parent")?;
                fs::create_dir_all(destination_parent)?;
                let destination_parent = fs::canonicalize(destination_parent)?;
                if !destination_parent.starts_with(&run_trash) {
                    bail!(
                        "profile quarantine resolves outside {}: {}",
                        run_trash.display(),
                        destination.display()
                    );
                }
                if destination.exists() {
                    bail!(
                        "profile quarantine already exists: {}",
                        destination.display()
                    );
                }
                fs::rename(&candidate.path, &destination).with_context(|| {
                    format!(
                        "failed to quarantine stale Cargo profile {}",
                        candidate.path.display()
                    )
                })?;
                quarantined.push((candidate.path.clone(), destination));
            }
            Ok(quarantined)
        },
    )??;
    for (original, quarantined) in quarantined {
        remove_quarantine_entry(&quarantined)?;
        remove_empty_ancestors(&quarantined, &trash_root)?;
        eprintln!("  reset stale Cargo profile {}", original.display());
    }
    Ok(())
}

fn remove_quarantine_entry(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    }
    .with_context(|| format!("failed to remove profile quarantine {}", path.display()))
}

fn remove_empty_ancestors(path: &Path, trash_root: &Path) -> Result<()> {
    let mut current = path.parent();
    while let Some(directory) = current {
        if directory == trash_root {
            break;
        }
        match fs::remove_dir(directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        current = directory.parent();
    }
    remove_empty_trash_root(trash_root)
}

fn remove_empty_trash_root(trash_root: &Path) -> Result<()> {
    match fs::remove_dir(trash_root) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::DirectoryNotEmpty | io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn profile_ownership_evidence_ignoring_held_locks(
    paths: &[PathBuf],
    held_lock_paths: &[PathBuf],
) -> (HashSet<PathBuf>, bool) {
    let evidence = process_ownership_evidence_for_paths(paths);
    profile_ownership_from_evidence(evidence, held_lock_paths, std::process::id())
}

fn profile_ownership_from_evidence(
    evidence: ProcessOwnershipEvidence,
    held_lock_paths: &[PathBuf],
    current_pid: u32,
) -> (HashSet<PathBuf>, bool) {
    if !evidence.complete {
        return (HashSet::new(), false);
    }

    let open_profiles = evidence
        .observations
        .into_iter()
        .filter(|observation| {
            !(observation.pid == Some(current_pid)
                && observation.evidence_kind == ProcessOwnershipEvidenceKind::OpenFile
                && held_lock_paths.contains(&observation.observed_path))
        })
        .map(|observation| observation.matched_path)
        .collect();
    (open_profiles, true)
}

fn validated_profile_relative_path(
    target_dir: &Path,
    candidate_path: &Path,
    cargo_profile: &str,
    cargo_target: Option<&str>,
) -> Result<PathBuf> {
    let output_name = match cargo_profile {
        "dev" => "debug",
        "release" => "release",
        other => bail!("unsupported Cargo profile {other}"),
    };
    let expected = match cargo_target {
        Some(target) => PathBuf::from(target).join(output_name),
        None => PathBuf::from(output_name),
    };
    let relative = candidate_path.strip_prefix(target_dir).with_context(|| {
        format!(
            "Cargo profile is outside {}: {}",
            target_dir.display(),
            candidate_path.display()
        )
    })?;
    if relative != expected {
        bail!(
            "Cargo profile identity changed: expected {}, found {}",
            expected.display(),
            relative.display()
        );
    }
    Ok(expected)
}

struct BuildContext {
    build_dir: PathBuf,
}

enum BuildContextResolution {
    Supported(BuildContext),
    Unsupported(String),
}

fn resolve_build_context(target_dir: &Path, worktree: &Path) -> Result<BuildContextResolution> {
    let target_dir = fs::canonicalize(target_dir)
        .with_context(|| format!("failed to canonicalize {}", target_dir.display()))?;
    let worktree = fs::canonicalize(worktree)
        .with_context(|| format!("failed to canonicalize {}", worktree.display()))?;
    if !target_dir.starts_with(&worktree) {
        return Ok(BuildContextResolution::Unsupported(format!(
            "Cargo target directory is outside the worktree: {}",
            target_dir.display()
        )));
    }

    let Some(manifest_path) = nearest_manifest(&target_dir, &worktree) else {
        return Ok(BuildContextResolution::Unsupported(format!(
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
    let metadata = command.exec().with_context(|| {
        format!(
            "cargo metadata failed for profile reset at {}",
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
        return Ok(BuildContextResolution::Unsupported(format!(
            "{} does not match Cargo's reported target/build directory",
            target_dir.display()
        )));
    }
    let Some(build_dir) = reported_build else {
        return Ok(BuildContextResolution::Unsupported(
            "Cargo build directory does not exist".to_string(),
        ));
    };
    if build_dir != target_dir || !build_dir.starts_with(&worktree) {
        return Ok(BuildContextResolution::Unsupported(format!(
            "Cargo build directory cannot be cleaned inside this worktree: {}",
            build_dir.display()
        )));
    }
    Ok(BuildContextResolution::Supported(BuildContext {
        build_dir,
    }))
}

fn sampled_activity(profile_dir: &Path) -> Result<Option<i64>> {
    let mut newest: Option<i64> = None;
    for entry in WalkDir::new(profile_dir)
        .follow_links(false)
        .max_depth(PROFILE_ACTIVITY_SAMPLE_DEPTH)
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if walkdir_not_found(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(error) if walkdir_not_found(&error) => continue,
            Err(error) => return Err(error.into()),
        };
        let modified = metadata.modified().ok().and_then(system_time_to_unix);
        newest = match (newest, modified) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, right) => right,
            (left, None) => left,
        };
    }
    Ok(newest)
}

fn walkdir_not_found(error: &walkdir::Error) -> bool {
    error
        .io_error()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

fn skipped_candidate(
    path: PathBuf,
    lock_path: PathBuf,
    reason: &str,
) -> CargoProfileCandidateDecision {
    CargoProfileCandidateDecision {
        path,
        lock_path,
        cargo_profile: None,
        cargo_target: None,
        last_activity_unix: None,
        last_activity: None,
        activity_age_days: None,
        action: SweepCandidateAction::Skip,
        reason: reason.to_string(),
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
    path.exists().then(|| fs::canonicalize(path).ok()).flatten()
}

fn age_days(now: SystemTime, unix: i64) -> Option<u64> {
    let then = if unix >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_secs(unix as u64))?
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_secs(unix.unsigned_abs()))?
    };
    Some(now.duration_since(then).unwrap_or(Duration::ZERO).as_secs() / 86_400)
}

fn system_time_to_unix(time: SystemTime) -> Option<i64> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).ok(),
        Err(error) => i64::try_from(error.duration().as_secs()).ok().map(|v| -v),
    }
}

fn format_unix_time(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|date| date.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::fs::File;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use tempfile::TempDir;

    fn fixture() -> Result<(TempDir, PathBuf, PathBuf)> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("fixture");
        fs::create_dir_all(repo.join("src"))?;
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"profile-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )?;
        fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let profile = repo.join("target/debug");
        fs::create_dir_all(profile.join("deps"))?;
        fs::write(profile.join(".cargo-lock"), "")?;
        fs::write(profile.join("deps/libfixture-old.rlib"), "old artifact")?;
        Ok((temp, repo, profile))
    }

    fn set_old(path: &Path) -> Result<()> {
        let old = SystemTime::now() - Duration::from_secs(20 * 86_400);
        File::options().read(true).open(path)?.set_modified(old)?;
        Ok(())
    }

    fn age_fixture(profile: &Path) -> Result<()> {
        set_old(&profile.join("deps/libfixture-old.rlib"))?;
        set_old(&profile.join("deps"))?;
        set_old(&profile.join(".cargo-lock"))?;
        set_old(profile)
    }

    #[test]
    fn plans_stale_host_profiles_without_interpreting_fingerprints() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;

        let plan = plan_cargo_profile_sweep(&repo.join("target"), &repo, 7, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fs::canonicalize(&profile).unwrap())
            .context("missing debug profile")?;
        assert_eq!(candidate.cargo_profile.as_deref(), Some("dev"));
        assert_eq!(candidate.action, SweepCandidateAction::Delete);
        assert!(candidate.activity_age_days.is_some_and(|days| days >= 7));
        Ok(())
    }

    fn execute_profile_reset_for_test(
        target_dir: &Path,
        worktree: &Path,
        candidates: &[CargoProfileCandidateDecision],
        days: u64,
        run_id: &str,
        timeout: Option<Duration>,
    ) -> Result<()> {
        execute_cargo_profile_reset_with_ownership(
            target_dir,
            worktree,
            candidates,
            days,
            run_id,
            timeout,
            &|_, _| (HashSet::new(), true),
        )
    }

    #[test]
    fn atomically_resets_a_stale_profile() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;

        execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(!profile.exists());
        assert!(repo.join("Cargo.toml").is_file());
        Ok(())
    }

    #[test]
    fn refreshed_profiles_survive_execution_revalidation() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        fs::write(profile.join("deps/new.rlib"), "new artifact")?;

        execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/new.rlib").is_file());
        Ok(())
    }

    #[test]
    fn owned_profiles_survive_execution_revalidation() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let _open_artifact = File::open(profile.join("deps/libfixture-old.rlib"))?;

        let owned_profile = fs::canonicalize(&profile)?;
        execute_cargo_profile_reset_with_ownership(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
            &move |_, _| (HashSet::from([owned_profile.clone()]), true),
        )?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/libfixture-old.rlib").is_file());
        Ok(())
    }

    #[test]
    fn incomplete_ownership_evidence_preserves_profiles() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;

        execute_cargo_profile_reset_with_ownership(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
            &|_, _| (HashSet::new(), false),
        )?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/libfixture-old.rlib").is_file());
        Ok(())
    }

    #[test]
    fn nested_build_output_activity_keeps_a_profile() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        let output_dir = profile.join("build/fixture-hash/out/nested");
        fs::create_dir_all(&output_dir)?;
        let output = output_dir.join("generated.rs");
        fs::write(&output, "old output")?;
        age_fixture(&profile)?;
        for path in [
            profile.join("build"),
            profile.join("build/fixture-hash"),
            profile.join("build/fixture-hash/out"),
            output_dir,
            output.clone(),
        ] {
            set_old(&path)?;
        }

        // Rewriting an existing output does not refresh its ancestors.
        fs::write(&output, "fresh output")?;
        let plan = plan_cargo_profile_sweep(&repo.join("target"), &repo, 7, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fs::canonicalize(&profile).unwrap())
            .context("missing debug profile")?;
        assert_eq!(candidate.action, SweepCandidateAction::Keep);
        Ok(())
    }

    #[test]
    fn vanished_profile_activity_is_transient() -> Result<()> {
        let temp = TempDir::new()?;
        assert_eq!(sampled_activity(&temp.path().join("vanished"))?, None);
        Ok(())
    }

    #[test]
    fn profiles_refreshed_while_waiting_for_a_lock_survive() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let held = File::options()
            .read(true)
            .write(true)
            .open(profile.join(".cargo-lock"))?;
        held.lock()?;
        let refreshed_artifact = profile.join("deps/refreshed.rlib");
        let refresher = thread::spawn(move || -> Result<()> {
            thread::sleep(Duration::from_millis(50));
            fs::write(&refreshed_artifact, "fresh artifact")?;
            held.unlock()?;
            Ok(())
        });

        execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(2)),
        )?;
        refresher.join().expect("refresher thread panicked")?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/refreshed.rlib").is_file());
        Ok(())
    }

    #[test]
    fn profiles_opened_while_waiting_for_locks_are_retained() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let held = File::options()
            .read(true)
            .write(true)
            .open(profile.join(".cargo-lock"))?;
        held.lock()?;
        let owner_live = Arc::new(AtomicBool::new(false));
        let owner_live_from_thread = Arc::clone(&owner_live);
        let releaser = thread::spawn(move || -> Result<()> {
            thread::sleep(Duration::from_millis(50));
            owner_live_from_thread.store(true, Ordering::SeqCst);
            held.unlock()?;
            Ok(())
        });
        let owned_profile = fs::canonicalize(&profile)?;

        execute_cargo_profile_reset_with_ownership(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(2)),
            &move |_, _| {
                let open = owner_live
                    .load(Ordering::SeqCst)
                    .then(|| owned_profile.clone())
                    .into_iter()
                    .collect();
                (open, true)
            },
        )?;
        releaser.join().expect("releaser thread panicked")?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/libfixture-old.rlib").is_file());
        Ok(())
    }

    #[test]
    fn profile_reset_obeys_the_scheduled_lock_timeout() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let held = File::options()
            .read(true)
            .write(true)
            .open(profile.join(".cargo-lock"))?;
        held.lock()?;

        let error = execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_millis(20)),
        )
        .expect_err("contended Cargo profile should time out");
        assert!(crate::cargo_incremental::is_cargo_lock_timeout(&error));
        assert!(profile.is_dir());
        held.unlock()?;
        Ok(())
    }

    #[test]
    fn interrupted_profile_quarantine_is_recovered() -> Result<()> {
        let (_temp, repo, _profile) = fixture()?;
        let trash = repo.join("target/.worktree-gc-trash/interrupted/debug");
        fs::create_dir_all(&trash)?;
        fs::write(trash.join("artifact"), "old")?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        assert!(plan
            .candidates
            .iter()
            .any(|candidate| candidate.action == SweepCandidateAction::RecoverTrash));

        execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;
        assert!(!repo.join("target/.worktree-gc-trash").exists());
        Ok(())
    }

    #[test]
    fn plans_and_atomically_resets_stale_cross_target_profiles() -> Result<()> {
        let (_temp, repo, host_profile) = fixture()?;
        let cross_profile = repo.join("target/aarch64-unknown-linux-musl/debug");
        fs::create_dir_all(cross_profile.join("deps"))?;
        fs::write(cross_profile.join(".cargo-lock"), "")?;
        fs::write(cross_profile.join("deps/libfixture-old.rlib"), "old")?;
        age_fixture(&cross_profile)?;

        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fs::canonicalize(&cross_profile).unwrap())
            .context("missing cross-target debug profile")?;
        assert_eq!(candidate.cargo_profile.as_deref(), Some("dev"));
        assert_eq!(
            candidate.cargo_target.as_deref(),
            Some("aarch64-unknown-linux-musl")
        );
        assert_eq!(candidate.action, SweepCandidateAction::Delete);

        execute_profile_reset_for_test(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(!cross_profile.exists());
        assert!(host_profile.exists());
        assert!(!target.join(TRASH_DIR_NAME).exists());
        Ok(())
    }

    #[test]
    fn cross_target_profiles_have_distinct_quarantine_paths() -> Result<()> {
        let (_temp, repo, host_profile) = fixture()?;
        let target = repo.join("target");
        let mut cross_profiles = Vec::new();
        for target_name in ["aarch64-unknown-linux-musl", "x86_64-pc-windows-msvc"] {
            let profile = target.join(target_name).join("debug");
            fs::create_dir_all(profile.join("deps"))?;
            fs::write(profile.join(".cargo-lock"), "")?;
            fs::write(profile.join("deps/libfixture-old.rlib"), "old")?;
            age_fixture(&profile)?;
            cross_profiles.push(profile);
        }
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;
        let probe_calls = Cell::new(0);
        let planner_calls = Cell::new(0);
        let observed_profiles = Cell::new(0);

        execute_cargo_profile_reset_with_probes(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
            CargoProfileExecutionProbes {
                ownership: &|paths, _| {
                    probe_calls.set(probe_calls.get() + 1);
                    observed_profiles.set(paths.len());
                    (HashSet::new(), true)
                },
                planner: &|target_dir, worktree, days, now| {
                    planner_calls.set(planner_calls.get() + 1);
                    plan_cargo_profile_sweep(target_dir, worktree, days, now)
                },
            },
        )?;

        assert_eq!(probe_calls.get(), 1);
        assert_eq!(planner_calls.get(), 1);
        assert_eq!(observed_profiles.get(), 2);
        assert!(cross_profiles.iter().all(|profile| !profile.exists()));
        assert!(host_profile.exists());
        assert!(!target.join(TRASH_DIR_NAME).exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn real_ownership_probe_ignores_held_profile_locks() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let plan = plan_cargo_profile_sweep(&target, &repo, 7, SystemTime::now())?;

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            7,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(
            !profile.exists(),
            "the reset process must ignore only its own held Cargo lock"
        );
        Ok(())
    }

    #[test]
    fn held_lock_filter_preserves_every_other_ownership_kind() {
        let held_profile = PathBuf::from("/tmp/target/debug");
        let mapped_profile = PathBuf::from("/tmp/target/release");
        let foreign_profile = PathBuf::from("/tmp/target/triple/debug");
        let held_lock = held_profile.join(".cargo-lock");
        let evidence = ProcessOwnershipEvidence {
            observed_at_unix: 1,
            backend: "test".to_string(),
            complete: true,
            error: None,
            observations: vec![
                crate::ProcessOwnershipObservation {
                    pid: Some(42),
                    command: Some("worktree-gc".to_string()),
                    evidence_kind: ProcessOwnershipEvidenceKind::OpenFile,
                    observed_path: held_lock.clone(),
                    matched_path: held_profile,
                },
                crate::ProcessOwnershipObservation {
                    pid: Some(42),
                    command: Some("worktree-gc".to_string()),
                    evidence_kind: ProcessOwnershipEvidenceKind::MappedFile,
                    observed_path: mapped_profile.join("deps/tool"),
                    matched_path: mapped_profile.clone(),
                },
                crate::ProcessOwnershipObservation {
                    pid: Some(99),
                    command: Some("cargo".to_string()),
                    evidence_kind: ProcessOwnershipEvidenceKind::OpenFile,
                    observed_path: foreign_profile.join(".cargo-lock"),
                    matched_path: foreign_profile.clone(),
                },
            ],
        };

        let (open, complete) = profile_ownership_from_evidence(evidence, &[held_lock], 42);

        assert!(complete);
        assert_eq!(open, HashSet::from([mapped_profile, foreign_profile]));
    }

    #[test]
    fn recent_cross_target_profiles_are_retained() -> Result<()> {
        let (_temp, repo, _host_profile) = fixture()?;
        let profile = repo.join("target/aarch64-apple-darwin/release");
        fs::create_dir_all(profile.join("deps"))?;
        fs::write(profile.join(".cargo-lock"), "")?;
        fs::write(profile.join("deps/libfixture.rlib"), "fresh")?;

        let plan = plan_cargo_profile_sweep(&repo.join("target"), &repo, 7, SystemTime::now())?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fs::canonicalize(&profile).unwrap())
            .context("missing cross-target release profile")?;
        assert_eq!(candidate.cargo_profile.as_deref(), Some("release"));
        assert_eq!(
            candidate.cargo_target.as_deref(),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(candidate.action, SweepCandidateAction::Keep);
        Ok(())
    }

    #[test]
    fn custom_profile_names_remain_fail_closed() -> Result<()> {
        let (_temp, repo, _profile) = fixture()?;
        for relative in ["target/custom", "target/aarch64-apple-darwin/custom"] {
            let profile = repo.join(relative);
            fs::create_dir_all(&profile)?;
            fs::write(profile.join(".cargo-lock"), "")?;
        }

        let plan = plan_cargo_profile_sweep(&repo.join("target"), &repo, 0, SystemTime::now())?;
        let skipped = plan
            .candidates
            .iter()
            .filter(|candidate| candidate.action == SweepCandidateAction::Skip)
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 2);
        assert!(skipped
            .iter()
            .all(|candidate| candidate.reason.contains("custom Cargo profile")));
        Ok(())
    }
}
