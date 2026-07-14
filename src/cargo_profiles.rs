use anyhow::{bail, Context, Result};
use cargo_metadata::MetadataCommand;
use serde::Serialize;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use walkdir::WalkDir;

use crate::activity_age::{elapsed_age_days, system_local_activity_age};
use crate::cargo_incremental::{with_cargo_profile_locks_timeout, TRASH_DIR_NAME};
use crate::{ActivityAgeEvidence, SweepCandidateAction, SweepLimit};

// Cargo build-script outputs commonly live below build/<unit>/out, and
// generated files can add another directory or two. Keep this bounded while
// sampling deeply enough that rewriting an existing output is visible.
const PROFILE_ACTIVITY_SAMPLE_DEPTH: usize = 6;

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfileCandidateDecision {
    pub path: PathBuf,
    pub lock_path: PathBuf,
    pub cargo_profile: Option<String>,
    pub last_activity_unix: Option<i64>,
    pub last_activity: Option<String>,
    pub activity_age_days: Option<u64>,
    pub workday_age: Option<ActivityAgeEvidence>,
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
    limit: &SweepLimit,
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
                last_activity_unix,
                last_activity: last_activity_unix.map(format_unix_time),
                activity_age_days: last_activity_unix.and_then(|unix| elapsed_age_days(now, unix)),
                workday_age: last_activity_unix
                    .and_then(|unix| system_local_activity_age(now, unix)),
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
        if entry.depth() != 2 {
            candidates.push(skipped_candidate(
                profile_dir,
                lock_path,
                "cross-target Cargo profiles are not yet mapped to a stable profile reset boundary",
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

        let output_name = profile_dir
            .file_name()
            .and_then(|name| name.to_str())
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
        let activity_age_days = last_activity_unix.and_then(|unix| elapsed_age_days(now, unix));
        let workday_age = last_activity_unix.and_then(|unix| system_local_activity_age(now, unix));
        let (action, reason) = retention_decision(limit, activity_age_days, workday_age.as_ref())?;
        candidates.push(CargoProfileCandidateDecision {
            path: profile_dir,
            lock_path,
            cargo_profile: Some(cargo_profile),
            last_activity_unix,
            last_activity: last_activity_unix.map(format_unix_time),
            activity_age_days,
            workday_age,
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
    limit: &SweepLimit,
    run_id: &str,
    timeout: Option<Duration>,
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

    for candidate in candidates
        .iter()
        .filter(|candidate| candidate.action == SweepCandidateAction::Delete)
    {
        let Some(profile) = candidate.cargo_profile.as_deref() else {
            continue;
        };
        if !candidate.path.exists() {
            continue;
        }
        if !profile_is_stale(&target_dir, worktree, &candidate.path, profile, limit)? {
            eprintln!(
                "  keeping refreshed Cargo profile {}",
                candidate.path.display()
            );
            continue;
        }

        let quarantined = with_cargo_profile_locks_timeout(
            &target_dir,
            worktree,
            timeout,
            || -> Result<Option<PathBuf>> {
                if !profile_is_stale(&target_dir, worktree, &candidate.path, profile, limit)? {
                    eprintln!(
                        "  keeping Cargo profile refreshed while waiting for its lock {}",
                        candidate.path.display()
                    );
                    return Ok(None);
                }
                let metadata = fs::symlink_metadata(&candidate.path)?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!(
                        "refusing to reset replaced Cargo profile {}",
                        candidate.path.display()
                    );
                }
                if candidate.path.parent() != Some(target_dir.as_path()) {
                    bail!(
                        "Cargo profile is not a direct child of {}: {}",
                        target_dir.display(),
                        candidate.path.display()
                    );
                }
                let run_trash = trash_root.join(run_id);
                fs::create_dir_all(&run_trash)?;
                let destination = run_trash.join(
                    candidate
                        .path
                        .file_name()
                        .context("Cargo profile has no directory name")?,
                );
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
                Ok(Some(destination))
            },
        )??;
        if let Some(quarantined) = quarantined {
            remove_quarantine_entry(&quarantined)?;
            remove_empty_ancestors(&quarantined, &trash_root)?;
            eprintln!("  reset stale Cargo profile {}", candidate.path.display());
        }
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
    if let Some(run_trash) = path.parent() {
        match fs::remove_dir(run_trash) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
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

fn profile_is_stale(
    target_dir: &Path,
    worktree: &Path,
    candidate_path: &Path,
    profile: &str,
    limit: &SweepLimit,
) -> Result<bool> {
    let refreshed = plan_cargo_profile_sweep(target_dir, worktree, limit, SystemTime::now())?;
    Ok(refreshed.candidates.iter().any(|refreshed| {
        refreshed.path == candidate_path
            && refreshed.cargo_profile.as_deref() == Some(profile)
            && refreshed.action == SweepCandidateAction::Delete
    }))
}

fn retention_decision(
    limit: &SweepLimit,
    elapsed_days: Option<u64>,
    workday_age: Option<&ActivityAgeEvidence>,
) -> Result<(SweepCandidateAction, String)> {
    match limit {
        SweepLimit::AgeDays { days } => {
            let stale = elapsed_days.is_some_and(|age| age >= *days);
            Ok(if stale {
                (
                    SweepCandidateAction::Delete,
                    format!("Cargo profile has been inactive for at least {days} elapsed days"),
                )
            } else {
                (
                    SweepCandidateAction::Keep,
                    format!("Cargo profile activity is newer than {days} elapsed days"),
                )
            })
        }
        SweepLimit::AgeWorkdays { workdays } => {
            let Some(age) = workday_age else {
                return Ok((
                    SweepCandidateAction::Keep,
                    "Cargo profile workday age is unavailable; keeping it".to_string(),
                ));
            };
            Ok(if age.workdays >= *workdays {
                (
                    SweepCandidateAction::Delete,
                    format!("Cargo profile has been inactive for at least {workdays} workdays"),
                )
            } else {
                (
                    SweepCandidateAction::Keep,
                    format!("Cargo profile activity is newer than {workdays} workdays"),
                )
            })
        }
        SweepLimit::MaxSize { .. } => bail!("Cargo profile reset requires an age limit"),
    }
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
        last_activity_unix: None,
        last_activity: None,
        activity_age_days: None,
        workday_age: None,
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
    use std::fs::File;
    use std::thread;
    use tempfile::TempDir;

    fn elapsed_days(days: u64) -> SweepLimit {
        SweepLimit::AgeDays { days }
    }

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

        let plan = plan_cargo_profile_sweep(
            &repo.join("target"),
            &repo,
            &elapsed_days(7),
            SystemTime::now(),
        )?;
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

    #[test]
    fn plans_workday_retention_with_reproducible_evidence() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;

        let plan = plan_cargo_profile_sweep(
            &repo.join("target"),
            &repo,
            &SweepLimit::AgeWorkdays { workdays: 3 },
            SystemTime::now(),
        )?;
        let candidate = plan
            .candidates
            .iter()
            .find(|candidate| candidate.path == fs::canonicalize(&profile).unwrap())
            .context("missing debug profile")?;
        let evidence = candidate
            .workday_age
            .as_ref()
            .context("missing local workday evidence")?;

        assert_eq!(candidate.action, SweepCandidateAction::Delete);
        assert!(evidence.workdays >= 3);
        assert_eq!(evidence.calendar, crate::WEEKDAY_CALENDAR_ID);
        assert!(!evidence.timezone.is_empty());
        assert!(!evidence.activity_local_date.is_empty());
        assert!(!evidence.observation_local_date.is_empty());
        let serialized = serde_json::to_value(candidate)?;
        assert_eq!(serialized["workday_age"]["calendar"], "weekday-v1");
        assert!(serialized["workday_age"]["workdays"].is_u64());
        assert!(serialized["workday_age"]["timezone"].is_string());
        Ok(())
    }

    #[test]
    fn workday_retention_fails_closed_without_calendar_evidence() -> Result<()> {
        let (action, reason) =
            retention_decision(&SweepLimit::AgeWorkdays { workdays: 3 }, Some(30), None)?;

        assert_eq!(action, SweepCandidateAction::Keep);
        assert!(reason.contains("unavailable"));
        Ok(())
    }

    #[test]
    fn atomically_resets_a_stale_profile() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let limit = elapsed_days(7);
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(!profile.exists());
        assert!(repo.join("Cargo.toml").is_file());
        Ok(())
    }

    #[test]
    fn atomically_resets_a_stale_workday_profile() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let limit = SweepLimit::AgeWorkdays { workdays: 3 };
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
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
        let limit = elapsed_days(7);
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;
        fs::write(profile.join("deps/new.rlib"), "new artifact")?;

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/new.rlib").is_file());
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
        let plan = plan_cargo_profile_sweep(
            &repo.join("target"),
            &repo,
            &elapsed_days(7),
            SystemTime::now(),
        )?;
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
        let limit = elapsed_days(7);
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;
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

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
            "test-run",
            Some(Duration::from_secs(2)),
        )?;
        refresher.join().expect("refresher thread panicked")?;

        assert!(profile.is_dir());
        assert!(profile.join("deps/refreshed.rlib").is_file());
        Ok(())
    }

    #[test]
    fn profile_reset_obeys_the_scheduled_lock_timeout() -> Result<()> {
        let (_temp, repo, profile) = fixture()?;
        age_fixture(&profile)?;
        let target = repo.join("target");
        let limit = elapsed_days(7);
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;
        let held = File::options()
            .read(true)
            .write(true)
            .open(profile.join(".cargo-lock"))?;
        held.lock()?;

        let error = execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
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
        let limit = elapsed_days(7);
        let plan = plan_cargo_profile_sweep(&target, &repo, &limit, SystemTime::now())?;
        assert!(plan
            .candidates
            .iter()
            .any(|candidate| candidate.action == SweepCandidateAction::RecoverTrash));

        execute_cargo_profile_reset(
            &target,
            &repo,
            &plan.candidates,
            &limit,
            "test-run",
            Some(Duration::from_secs(10)),
        )?;
        assert!(!repo.join("target/.worktree-gc-trash").exists());
        Ok(())
    }

    #[test]
    fn custom_and_cross_target_profiles_are_reported_and_retained() -> Result<()> {
        let (_temp, repo, _profile) = fixture()?;
        for relative in ["target/custom", "target/aarch64-apple-darwin/debug"] {
            let profile = repo.join(relative);
            fs::create_dir_all(&profile)?;
            fs::write(profile.join(".cargo-lock"), "")?;
        }

        let plan = plan_cargo_profile_sweep(
            &repo.join("target"),
            &repo,
            &elapsed_days(0),
            SystemTime::now(),
        )?;
        let skipped = plan
            .candidates
            .iter()
            .filter(|candidate| candidate.action == SweepCandidateAction::Skip)
            .collect::<Vec<_>>();
        assert_eq!(skipped.len(), 2);
        assert!(skipped
            .iter()
            .any(|candidate| candidate.reason.contains("custom Cargo profile")));
        assert!(skipped
            .iter()
            .any(|candidate| candidate.reason.contains("cross-target")));
        Ok(())
    }
}
