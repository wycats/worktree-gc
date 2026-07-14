use crate::cargo_profiles::{
    cargo_profile_file_identity, execute_cargo_profile_reset, plan_cargo_profile_sweep,
};
use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::protection::{
    active_protections, protection_for_path, with_protection_guard_for_paths,
    ProtectionGuardOutcome, ProtectionMatch,
};
use crate::{
    format_bytes, open_handle_evidence_for_paths, CleanupMode, SweepCandidateAction, SweepLimit,
};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use fs4::FileExt;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MANIFEST_VERSION: u64 = 1;
const APPROVAL_CONTRACT: &[u8] = b"worktree-gc:cargo-profile-opportunities:approval:v1";
const MAX_SOURCE_ARTIFACTS: usize = 100_000;
const MAX_SOURCE_TARGETS: usize = 10_000;

#[derive(Debug, Clone)]
pub struct CargoProfileCollectOptions {
    pub execute: bool,
    pub approved_digest: Option<String>,
    pub generated_manifest: PathBuf,
    pub max_entries: u64,
    pub now: SystemTime,
}

#[derive(Debug, Serialize)]
pub struct CargoProfileCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: CargoProfileCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct CargoProfileCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub source: CargoProfileSource,
    pub policy: CargoProfilePolicy,
    pub plan: CargoProfileCollectPlan,
    pub outcome: Option<CargoProfileCollectOutcome>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfileSource {
    pub generated_manifest: PathBuf,
    pub generated_manifest_sha256: String,
    pub generated_manifest_version: u64,
    pub generated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfilePolicy {
    pub owner_contract: &'static str,
    pub execution: &'static str,
    pub unattended_execution_supported: bool,
    pub max_entries: u64,
    pub lock_timeout_milliseconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CargoProfileCollectAction {
    NoWork,
    ReportOnly,
    InUse,
    Protected,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfileCollectPlan {
    pub action: CargoProfileCollectAction,
    pub reason: String,
    pub complete: bool,
    pub eligibility_digest: String,
    pub source_target_count: usize,
    pub candidates: Vec<CargoProfileResetCandidate>,
    pub expected_reclaim: InventoryMetrics,
    pub open_paths: Vec<PathBuf>,
    pub open_handle_check_complete: bool,
    pub protections: Vec<ProtectionMatch>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CargoProfileResetCandidate {
    pub target_path: PathBuf,
    pub worktree_path: PathBuf,
    pub worktree_head: String,
    pub worktree_git_dir: PathBuf,
    pub profile_path: PathBuf,
    pub cargo_profile: String,
    pub file_identity: String,
    pub filesystem: String,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoProfileCollectOutcome {
    pub profiles_reset: usize,
    pub reset_paths: Vec<PathBuf>,
    pub remaining_paths: Vec<PathBuf>,
    pub available_bytes_before: u64,
    pub available_bytes_after: u64,
    pub realized_reclaim_bytes: u64,
    pub verification_complete: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
struct SourceTarget {
    target_path: PathBuf,
    worktree_path: PathBuf,
}

#[derive(Debug)]
struct LiveTargetOwner {
    head: String,
    git_dir: PathBuf,
    worktree_path: PathBuf,
    target_path: PathBuf,
}

pub fn collect_cargo_profiles(
    options: CargoProfileCollectOptions,
) -> Result<CargoProfileCollectRun> {
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    anyhow::ensure!(
        options.execute || options.approved_digest.is_none(),
        "--approved-digest is only valid with --execute"
    );
    if options.execute {
        let digest = options
            .approved_digest
            .as_deref()
            .context("Cargo profile execution requires --approved-digest from a dry-run")?;
        anyhow::ensure!(
            valid_sha256_digest(digest),
            "--approved-digest must be a sha256: digest"
        );
    }

    let source_bytes = fs::read(&options.generated_manifest).with_context(|| {
        format!(
            "read generated collector manifest {}",
            options.generated_manifest.display()
        )
    })?;
    let source_sha256 = format!("sha256:{:x}", Sha256::digest(&source_bytes));
    let source_json: Value = serde_json::from_slice(&source_bytes).with_context(|| {
        format!(
            "parse generated collector manifest {}",
            options.generated_manifest.display()
        )
    })?;
    let source = CargoProfileSource {
        generated_manifest: options.generated_manifest.clone(),
        generated_manifest_sha256: source_sha256,
        generated_manifest_version: u64_at(&source_json, &["manifest_version"])?,
        generated_at_unix: u64_at(&source_json, &["generated_at_unix"])?,
    };
    anyhow::ensure!(
        string_at(&source_json, &["collector"])? == "generated",
        "Cargo profile opportunities require a generated collector manifest"
    );
    anyhow::ensure!(
        source.generated_manifest_version >= 2,
        "generated collector manifest predates rebuildable-opportunity evidence"
    );
    let source_targets = source_targets(&source_json)?;
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let plan = plan_profiles(&source_targets, &source, &options)?;
    let mut manifest = CargoProfileCollectManifest {
        manifest_version: MANIFEST_VERSION,
        collector: "cargo-profile-opportunities",
        run_id,
        mode: if options.execute {
            CleanupMode::Execute
        } else {
            CleanupMode::DryRun
        },
        generated_at_unix: unix_seconds(options.now),
        source,
        policy: CargoProfilePolicy {
            owner_contract: "complete owner-free, unprotected Cargo target opportunities from an explicit generated manifest; only direct debug/release profiles are eligible",
            execution: "manual digest-bound atomic profile quarantine under Cargo profile locks with open-handle and protection revalidation",
            unattended_execution_supported: false,
            max_entries: options.max_entries,
            lock_timeout_milliseconds: 0,
        },
        plan,
        outcome: None,
    };
    let manifest_path = write_manifest(&manifest)?;
    if let Some(approved) = options.approved_digest.as_deref() {
        anyhow::ensure!(
            approved == manifest.plan.eligibility_digest,
            "approved Cargo profile plan {approved} does not match current plan {}; review {} before trying again",
            manifest.plan.eligibility_digest,
            manifest_path.display()
        );
    }
    if options.execute {
        let observation_path = manifest
            .plan
            .candidates
            .first()
            .map(|candidate| candidate.target_path.clone())
            .context("Cargo profile execution has no observation path")?;
        let available_bytes_before = fs4::available_space(&observation_path)?;
        match execute_plan(&source_targets, &options, &manifest, available_bytes_before) {
            Ok(outcome) => {
                manifest.outcome = Some(outcome);
                write_manifest_at(&manifest_path, &manifest)?;
            }
            Err(error) => {
                let available_bytes_after =
                    fs4::available_space(&observation_path).unwrap_or(available_bytes_before);
                let remaining_paths = manifest
                    .plan
                    .candidates
                    .iter()
                    .map(|candidate| candidate.profile_path.clone())
                    .filter(|path| path_exists_no_follow(path).unwrap_or(true))
                    .collect::<Vec<_>>();
                manifest.outcome = Some(CargoProfileCollectOutcome {
                    profiles_reset: manifest
                        .plan
                        .candidates
                        .len()
                        .saturating_sub(remaining_paths.len()),
                    reset_paths: manifest
                        .plan
                        .candidates
                        .iter()
                        .map(|candidate| candidate.profile_path.clone())
                        .filter(|path| !remaining_paths.contains(path))
                        .collect(),
                    remaining_paths,
                    available_bytes_before,
                    available_bytes_after,
                    realized_reclaim_bytes: available_bytes_after
                        .saturating_sub(available_bytes_before),
                    verification_complete: false,
                    error: Some(format!("{error:#}")),
                });
                write_manifest_at(&manifest_path, &manifest)?;
                return Err(error).with_context(|| {
                    format!(
                        "Cargo profile execution failed; inspect manifest {}",
                        manifest_path.display()
                    )
                });
            }
        }
    }
    Ok(CargoProfileCollectRun {
        manifest_path,
        manifest,
    })
}

fn source_targets(source: &Value) -> Result<Vec<SourceTarget>> {
    let artifacts = array_at(source, &["plan", "artifacts"])?;
    anyhow::ensure!(
        artifacts.len() <= MAX_SOURCE_ARTIFACTS,
        "generated manifest exposes more than {MAX_SOURCE_ARTIFACTS} artifacts"
    );
    let mut targets = Vec::new();
    for artifact in artifacts {
        if string_at(artifact, &["name"])? != "target"
            || !bool_at(artifact, &["rebuildable_opportunity"])?
            || !bool_at(artifact, &["measurement", "complete"])?
            || !bool_at(
                artifact,
                &["measurement", "metrics", "private_reclaimable_complete"],
            )?
            || bool_at(artifact, &["in_use"])?
            || !value_at(artifact, &["protection"])?.is_null()
            || bool_at(artifact, &["has_tracked_files"])?
            || !bool_at(artifact, &["ignored"])?
            || string_at(artifact, &["open_handle_evidence"])? != "complete"
        {
            continue;
        }
        let target_path = path_at(artifact, &["path"])?;
        let worktree_path = path_at(artifact, &["worktree_path"])?;
        ensure_normal_absolute_path(&target_path, "generated target")?;
        ensure_normal_absolute_path(&worktree_path, "generated worktree")?;
        if target_path != worktree_path.join("target") {
            continue;
        }
        targets.push(SourceTarget {
            target_path,
            worktree_path,
        });
    }
    targets.sort_by(|left, right| left.target_path.cmp(&right.target_path));
    targets.dedup_by(|left, right| left.target_path == right.target_path);
    anyhow::ensure!(
        targets.len() <= MAX_SOURCE_TARGETS,
        "generated manifest exposes more than {MAX_SOURCE_TARGETS} direct target opportunities"
    );
    Ok(targets)
}

fn live_target_owner(target: &SourceTarget) -> Result<LiveTargetOwner> {
    let canonical_worktree = fs::canonicalize(&target.worktree_path).with_context(|| {
        format!(
            "resolve generated worktree {}",
            target.worktree_path.display()
        )
    })?;
    let top_level = PathBuf::from(git_output(
        &target.worktree_path,
        &["rev-parse", "--show-toplevel"],
    )?);
    let canonical_top_level = fs::canonicalize(&top_level)
        .with_context(|| format!("resolve Git top level {}", top_level.display()))?;
    anyhow::ensure!(
        canonical_top_level == canonical_worktree,
        "{} is no longer the root of the expected Git worktree",
        target.worktree_path.display()
    );

    let relative = target
        .target_path
        .strip_prefix(&target.worktree_path)
        .with_context(|| {
            format!(
                "Cargo target {} is outside worktree {}",
                target.target_path.display(),
                target.worktree_path.display()
            )
        })?;
    anyhow::ensure!(
        relative == Path::new("target"),
        "Cargo target is not the direct target root"
    );
    let canonical_target = fs::canonicalize(&target.target_path)
        .with_context(|| format!("resolve Cargo target {}", target.target_path.display()))?;
    anyhow::ensure!(
        canonical_target == canonical_worktree.join("target"),
        "Cargo target {} does not resolve to the direct target root of {}",
        target.target_path.display(),
        target.worktree_path.display()
    );

    let ignored = Command::new("git")
        .args(["check-ignore", "-q", "--"])
        .arg(relative)
        .current_dir(&target.worktree_path)
        .status()
        .with_context(|| format!("run git check-ignore in {}", target.worktree_path.display()))?;
    anyhow::ensure!(
        ignored.success(),
        "Cargo target {} is no longer ignored",
        target.target_path.display()
    );

    let tracked = Command::new("git")
        .args(["ls-files", "-z", "--"])
        .arg(relative)
        .current_dir(&target.worktree_path)
        .output()
        .with_context(|| format!("run git ls-files in {}", target.worktree_path.display()))?;
    anyhow::ensure!(
        tracked.status.success(),
        "git ls-files failed in {}: {}",
        target.worktree_path.display(),
        String::from_utf8_lossy(&tracked.stderr).trim()
    );
    anyhow::ensure!(
        tracked.stdout.is_empty(),
        "Cargo target {} now contains tracked paths",
        target.target_path.display()
    );

    let git_dir = PathBuf::from(git_output(
        &target.worktree_path,
        &["rev-parse", "--path-format=absolute", "--git-dir"],
    )?);
    let git_dir = fs::canonicalize(&git_dir)
        .with_context(|| format!("resolve Git directory {}", git_dir.display()))?;
    let head_output = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .current_dir(&target.worktree_path)
        .output()
        .with_context(|| format!("inspect Git HEAD in {}", target.worktree_path.display()))?;
    let head = if head_output.status.success() {
        let head = String::from_utf8(head_output.stdout)
            .context("Git HEAD output is not UTF-8")?
            .trim()
            .to_owned();
        anyhow::ensure!(
            !head.is_empty() && head.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Git HEAD is not a hexadecimal object id"
        );
        head
    } else {
        let symbolic = git_output(&target.worktree_path, &["symbolic-ref", "-q", "HEAD"])
            .context("Git repository has neither a commit nor an unborn symbolic HEAD")?;
        format!("unborn:{symbolic}")
    };
    Ok(LiveTargetOwner {
        head,
        git_dir,
        worktree_path: canonical_worktree,
        target_path: canonical_target,
    })
}

fn git_output(worktree: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(worktree)
        .output()
        .with_context(|| format!("run git {} in {}", args.join(" "), worktree.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "git {} failed in {}: {}",
        args.join(" "),
        worktree.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8(output.stdout)
        .context("Git output is not UTF-8")
        .map(|value| value.trim().to_owned())
}

fn plan_profiles(
    source_targets: &[SourceTarget],
    source: &CargoProfileSource,
    options: &CargoProfileCollectOptions,
) -> Result<CargoProfileCollectPlan> {
    let protections = active_protections(options.now)?;
    plan_profiles_with_protections(source_targets, source, options, &protections)
}

fn plan_profiles_with_protections(
    source_targets: &[SourceTarget],
    source: &CargoProfileSource,
    options: &CargoProfileCollectOptions,
    protections: &[crate::protection::ProtectionLease],
) -> Result<CargoProfileCollectPlan> {
    let mut errors = Vec::new();
    let mut unmeasured = Vec::new();
    for target in source_targets {
        let metadata = match fs::symlink_metadata(&target.target_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                errors.push(format!("inspect {}: {error}", target.target_path.display()));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            errors.push(format!(
                "Cargo target is not a non-symlink directory: {}",
                target.target_path.display()
            ));
            continue;
        }
        let owner = match live_target_owner(target) {
            Ok(owner) => owner,
            Err(error) => {
                errors.push(format!(
                    "revalidate Git ownership for {}: {error:#}",
                    target.target_path.display()
                ));
                continue;
            }
        };
        let reset_limit = SweepLimit::AgeDays { days: 0 };
        let profile_plan = match plan_cargo_profile_sweep(
            &owner.target_path,
            &owner.worktree_path,
            &reset_limit,
            options.now,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                errors.push(format!(
                    "plan Cargo profiles under {}: {error:#}",
                    target.target_path.display()
                ));
                continue;
            }
        };
        if profile_plan
            .candidates
            .iter()
            .any(|candidate| candidate.action == SweepCandidateAction::RecoverTrash)
        {
            errors.push(format!(
                "interrupted Cargo profile quarantine requires recovery review under {}",
                target.target_path.display()
            ));
            continue;
        }
        for candidate in profile_plan.candidates.into_iter().filter(|candidate| {
            candidate.action == SweepCandidateAction::Delete
                && candidate.cargo_profile.is_some()
                && candidate.path.parent() == Some(owner.target_path.as_path())
        }) {
            let metadata = match fs::symlink_metadata(&candidate.path) {
                Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
                Ok(_) => {
                    errors.push(format!(
                        "Cargo profile is not a non-symlink directory: {}",
                        candidate.path.display()
                    ));
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    errors.push(format!("inspect {}: {error}", candidate.path.display()));
                    continue;
                }
            };
            unmeasured.push((
                owner.target_path.clone(),
                owner.worktree_path.clone(),
                owner.head.clone(),
                owner.git_dir.clone(),
                candidate.path,
                candidate.cargo_profile.expect("filtered above"),
                file_identity(&metadata),
            ));
        }
    }

    let profile_paths = unmeasured
        .iter()
        .map(|(_, _, _, _, profile, _, _)| profile.clone())
        .collect::<Vec<_>>();
    let (measurements, measurement_complete, measurement_error) =
        measure_profiles(&profile_paths, options.max_entries);
    if let Some(error) = measurement_error {
        errors.push(error);
    }
    let mut candidates = unmeasured
        .into_iter()
        .map(
            |(
                target_path,
                worktree_path,
                worktree_head,
                worktree_git_dir,
                profile_path,
                cargo_profile,
                identity,
            )| {
                let (filesystem, metrics) =
                    measurements.get(&profile_path).cloned().unwrap_or_else(|| {
                        (
                            "unknown".into(),
                            InventoryMetrics {
                                private_reclaimable_complete: false,
                                ..InventoryMetrics::default()
                            },
                        )
                    });
                CargoProfileResetCandidate {
                    target_path,
                    worktree_path,
                    worktree_head,
                    worktree_git_dir,
                    profile_path,
                    cargo_profile,
                    file_identity: identity,
                    filesystem,
                    metrics,
                }
            },
        )
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.profile_path.cmp(&right.profile_path));
    let paths = candidates
        .iter()
        .map(|candidate| candidate.profile_path.clone())
        .collect::<Vec<_>>();
    let (open, open_handle_check_complete) = open_handle_evidence_for_paths(&paths);
    let mut open_paths = open.into_iter().collect::<Vec<_>>();
    open_paths.sort();
    let mut candidate_protections = candidates
        .iter()
        .filter_map(|candidate| protection_for_path(&candidate.profile_path, protections))
        .collect::<Vec<_>>();
    candidate_protections.sort_by(|left, right| left.id.cmp(&right.id));
    candidate_protections.dedup_by(|left, right| left.id == right.id);
    let identities_stable = candidates.iter().all(candidate_identity_is_current);
    if !identities_stable {
        errors.push("one or more Cargo profile identities changed during planning".into());
    }
    let complete = errors.is_empty()
        && measurement_complete
        && open_handle_check_complete
        && identities_stable
        && candidates
            .iter()
            .all(|candidate| candidate.metrics.private_reclaimable_complete);
    let expected_reclaim = sum_metrics(candidates.iter().map(|candidate| &candidate.metrics));
    let (action, reason) = if !complete {
        (
            CargoProfileCollectAction::Incomplete,
            "Cargo profile discovery, APFS measurement, identity, or open-handle evidence is incomplete".into(),
        )
    } else if candidates.is_empty() {
        (
            CargoProfileCollectAction::NoWork,
            "the generated manifest contains no complete direct Cargo profile opportunities".into(),
        )
    } else if !candidate_protections.is_empty() {
        (
            CargoProfileCollectAction::Protected,
            "one or more Cargo profiles intersect an active protection".into(),
        )
    } else if !open_paths.is_empty() {
        (
            CargoProfileCollectAction::InUse,
            "one or more Cargo profiles have open owners".into(),
        )
    } else {
        (
            CargoProfileCollectAction::ReportOnly,
            "complete rebuildable Cargo profiles are eligible for explicit digest-bound atomic reset".into(),
        )
    };
    let eligibility_digest = eligibility_digest(source, &candidates, options.max_entries);
    Ok(CargoProfileCollectPlan {
        action,
        reason,
        complete,
        eligibility_digest,
        source_target_count: source_targets.len(),
        candidates,
        expected_reclaim,
        open_paths,
        open_handle_check_complete,
        protections: candidate_protections,
        errors,
    })
}

fn execute_plan(
    source_targets: &[SourceTarget],
    options: &CargoProfileCollectOptions,
    manifest: &CargoProfileCollectManifest,
    available_bytes_before: u64,
) -> Result<CargoProfileCollectOutcome> {
    anyhow::ensure!(
        manifest.plan.action == CargoProfileCollectAction::ReportOnly && manifest.plan.complete,
        "Cargo profile plan is not executable: {}",
        manifest.plan.reason
    );
    let _lock = acquire_collector_lock()?;
    let candidate_paths = manifest
        .plan
        .candidates
        .iter()
        .map(|candidate| candidate.profile_path.clone())
        .collect::<Vec<_>>();
    let guarded = with_protection_guard_for_paths(&candidate_paths, SystemTime::now(), || {
        let mut refreshed_options = options.clone();
        refreshed_options.execute = false;
        refreshed_options.approved_digest = None;
        refreshed_options.now = SystemTime::now();
        // The protection guard holds the registry lock and has already
        // verified every candidate path. Re-reading active protections here
        // would recursively acquire the same lock.
        let refreshed = plan_profiles_with_protections(
            source_targets,
            &manifest.source,
            &refreshed_options,
            &[],
        )?;
        anyhow::ensure!(
            refreshed.action == CargoProfileCollectAction::ReportOnly
                && refreshed.complete
                && refreshed.eligibility_digest == manifest.plan.eligibility_digest
                && refreshed.candidates == manifest.plan.candidates,
            "Cargo profile eligibility changed after approval; rerun without --execute"
        );
        let filesystems = refreshed
            .candidates
            .iter()
            .map(|candidate| candidate.filesystem.as_str())
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            filesystems.len() == 1 && !filesystems.contains("unknown"),
            "Cargo profile execution requires one known filesystem"
        );
        let observation_path = refreshed
            .candidates
            .first()
            .map(|candidate| candidate.target_path.as_path())
            .context("Cargo profile execution has no observation path")?;
        let mut by_target = BTreeMap::<(PathBuf, PathBuf), BTreeSet<PathBuf>>::new();
        for candidate in &refreshed.candidates {
            by_target
                .entry((
                    candidate.target_path.clone(),
                    candidate.worktree_path.clone(),
                ))
                .or_default()
                .insert(candidate.profile_path.clone());
        }
        for ((target_path, worktree_path), selected_paths) in by_target {
            let reset_limit = SweepLimit::AgeDays { days: 0 };
            let current = plan_cargo_profile_sweep(
                &target_path,
                &worktree_path,
                &reset_limit,
                SystemTime::now(),
            )?;
            let decisions = current
                .candidates
                .into_iter()
                .filter(|candidate| selected_paths.contains(&candidate.path))
                .collect::<Vec<_>>();
            anyhow::ensure!(
                decisions.len() == selected_paths.len()
                    && decisions
                        .iter()
                        .all(|candidate| candidate.action == SweepCandidateAction::Delete),
                "Cargo profile set changed before lock acquisition"
            );
            let expected_identities = refreshed
                .candidates
                .iter()
                .filter(|candidate| selected_paths.contains(&candidate.profile_path))
                .map(|candidate| {
                    (
                        candidate.profile_path.clone(),
                        candidate.file_identity.clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            execute_cargo_profile_reset(
                &target_path,
                &worktree_path,
                &decisions,
                &reset_limit,
                &manifest.run_id,
                Some(Duration::ZERO),
                Some(&expected_identities),
            )?;
        }
        let remaining_paths = candidate_paths
            .iter()
            .filter(|path| path_exists_no_follow(path).unwrap_or(true))
            .cloned()
            .collect::<Vec<_>>();
        let available_bytes_after = fs4::available_space(observation_path)?;
        Ok(CargoProfileCollectOutcome {
            profiles_reset: candidate_paths.len().saturating_sub(remaining_paths.len()),
            reset_paths: candidate_paths
                .iter()
                .filter(|path| !remaining_paths.contains(path))
                .cloned()
                .collect(),
            remaining_paths,
            available_bytes_before,
            available_bytes_after,
            realized_reclaim_bytes: available_bytes_after.saturating_sub(available_bytes_before),
            verification_complete: true,
            error: None,
        })
    })?;
    match guarded {
        ProtectionGuardOutcome::Protected(protection) => bail!(
            "Cargo profile candidate became protected by lease {} ({})",
            protection.id,
            protection.reason
        ),
        ProtectionGuardOutcome::Executed(outcome) => {
            let outcome = outcome?;
            anyhow::ensure!(
                outcome.remaining_paths.is_empty(),
                "Cargo profile reset left approved paths present"
            );
            Ok(outcome)
        }
    }
}

pub fn print_cargo_profile_collect(run: &CargoProfileCollectRun) {
    println!("collector: cargo-profile-opportunities");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "action: {:?} — {}",
        run.manifest.plan.action, run.manifest.plan.reason
    );
    println!(
        "{} profiles from {} target roots | {} private{} | {} allocated",
        run.manifest.plan.candidates.len(),
        run.manifest.plan.source_target_count,
        format_bytes(run.manifest.plan.expected_reclaim.private_reclaimable_bytes),
        if run
            .manifest
            .plan
            .expected_reclaim
            .private_reclaimable_complete
        {
            ""
        } else {
            " (lower bound)"
        },
        format_bytes(run.manifest.plan.expected_reclaim.allocated_bytes)
    );
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "reset: {} profiles | {} realized free-space gain | verification {}",
            outcome.profiles_reset,
            format_bytes(outcome.realized_reclaim_bytes),
            if outcome.verification_complete && outcome.remaining_paths.is_empty() {
                "complete"
            } else {
                "incomplete"
            }
        );
    }
}

fn measure_profiles(
    paths: &[PathBuf],
    max_entries: u64,
) -> (
    BTreeMap<PathBuf, (String, InventoryMetrics)>,
    bool,
    Option<String>,
) {
    if paths.is_empty() {
        return (BTreeMap::new(), true, None);
    }
    match inventory(
        paths,
        InventoryOptions {
            display_depth: 0,
            top: 1,
            max_entries,
            one_filesystem: true,
        },
    ) {
        Ok(report) => {
            let mut complete = report.roots.len() == paths.len();
            let measurements = paths
                .iter()
                .cloned()
                .zip(report.roots)
                .map(|(requested, root)| {
                    let root_complete = root.complete
                        && root.errors.is_empty()
                        && root.metrics.private_reclaimable_complete;
                    complete &= root_complete;
                    let mut metrics = root.metrics;
                    metrics.private_reclaimable_complete = root_complete;
                    (requested, (root.filesystem, metrics))
                })
                .collect();
            (measurements, complete, None)
        }
        Err(error) => (
            BTreeMap::new(),
            false,
            Some(format!("measure Cargo profiles: {error:#}")),
        ),
    }
}

fn candidate_identity_is_current(candidate: &CargoProfileResetCandidate) -> bool {
    fs::symlink_metadata(&candidate.profile_path).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && file_identity(&metadata) == candidate.file_identity
    })
}

fn eligibility_digest(
    source: &CargoProfileSource,
    candidates: &[CargoProfileResetCandidate],
    max_entries: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(APPROVAL_CONTRACT);
    hasher.update(source.generated_manifest_sha256.as_bytes());
    hasher.update(max_entries.to_le_bytes());
    for candidate in candidates {
        for value in [
            candidate.target_path.to_string_lossy().as_bytes(),
            candidate.worktree_path.to_string_lossy().as_bytes(),
            candidate.worktree_head.as_bytes(),
            candidate.worktree_git_dir.to_string_lossy().as_bytes(),
            candidate.profile_path.to_string_lossy().as_bytes(),
            candidate.cargo_profile.as_bytes(),
            candidate.file_identity.as_bytes(),
            candidate.filesystem.as_bytes(),
        ] {
            hasher.update((value.len() as u64).to_le_bytes());
            hasher.update(value);
        }
        hasher.update(candidate.metrics.private_reclaimable_bytes.to_le_bytes());
        hasher.update(candidate.metrics.allocated_bytes.to_le_bytes());
        hasher.update(candidate.metrics.logical_bytes.to_le_bytes());
        hasher.update(candidate.metrics.files.to_le_bytes());
        hasher.update(candidate.metrics.directories.to_le_bytes());
        hasher.update(candidate.metrics.hardlink_duplicates.to_le_bytes());
        hasher.update(candidate.metrics.errors.to_le_bytes());
        hasher.update([u8::from(candidate.metrics.private_reclaimable_complete)]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn sum_metrics<'a>(metrics: impl Iterator<Item = &'a InventoryMetrics>) -> InventoryMetrics {
    metrics.fold(
        InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        },
        |mut total, metrics| {
            total.logical_bytes = total.logical_bytes.saturating_add(metrics.logical_bytes);
            total.allocated_bytes = total
                .allocated_bytes
                .saturating_add(metrics.allocated_bytes);
            total.private_reclaimable_bytes = total
                .private_reclaimable_bytes
                .saturating_add(metrics.private_reclaimable_bytes);
            total.private_reclaimable_complete &= metrics.private_reclaimable_complete;
            total.files = total.files.saturating_add(metrics.files);
            total.directories = total.directories.saturating_add(metrics.directories);
            total.hardlink_duplicates = total
                .hardlink_duplicates
                .saturating_add(metrics.hardlink_duplicates);
            total.errors = total.errors.saturating_add(metrics.errors);
            total
        },
    )
}

fn file_identity(metadata: &fs::Metadata) -> String {
    cargo_profile_file_identity(metadata)
}

fn acquire_collector_lock() -> Result<File> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("cargo-profile-opportunities.lock"))?;
    FileExt::lock(&lock).context("lock Cargo profile opportunity collector")?;
    Ok(lock)
}

fn state_directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path).join("worktree-gc"));
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?)
            .join(".local/state/worktree-gc"),
    )
}

fn write_manifest(manifest: &CargoProfileCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!(
        "{}-cargo-profile-opportunities-{mode}.json",
        manifest.run_id
    ));
    write_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_manifest_at(path: &Path, manifest: &CargoProfileCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic Cargo profile manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Cargo profile manifest {}", path.display()))?;
    Ok(())
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut current = value;
    for component in path {
        current = current
            .get(*component)
            .with_context(|| format!("missing field {}", path.join(".")))?;
    }
    Ok(current)
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Vec<Value>> {
    value_at(value, path)?
        .as_array()
        .with_context(|| format!("field {} is not an array", path.join(".")))
}

fn string_at(value: &Value, path: &[&str]) -> Result<String> {
    value_at(value, path)?
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("field {} is not a string", path.join(".")))
}

fn bool_at(value: &Value, path: &[&str]) -> Result<bool> {
    value_at(value, path)?
        .as_bool()
        .with_context(|| format!("field {} is not a boolean", path.join(".")))
}

fn u64_at(value: &Value, path: &[&str]) -> Result<u64> {
    value_at(value, path)?
        .as_u64()
        .with_context(|| format!("field {} is not an unsigned integer", path.join(".")))
}

fn path_at(value: &Value, path: &[&str]) -> Result<PathBuf> {
    string_at(value, path).map(PathBuf::from)
}

fn ensure_normal_absolute_path(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "{label} {} is not absolute",
        path.display()
    );
    anyhow::ensure!(
        !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir)),
        "{label} {} contains lexical traversal",
        path.display()
    );
    Ok(())
}

fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_nanos(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn approval_digest_binds_source_and_profile_identity() {
        let source = CargoProfileSource {
            generated_manifest: PathBuf::from("/tmp/generated.json"),
            generated_manifest_sha256: format!("sha256:{}", "a".repeat(64)),
            generated_manifest_version: 2,
            generated_at_unix: 1,
        };
        let candidate = CargoProfileResetCandidate {
            target_path: PathBuf::from("/tmp/repo/target"),
            worktree_path: PathBuf::from("/tmp/repo"),
            worktree_head: "0123456789abcdef".into(),
            worktree_git_dir: PathBuf::from("/tmp/repo/.git"),
            profile_path: PathBuf::from("/tmp/repo/target/debug"),
            cargo_profile: "dev".into(),
            file_identity: "identity".into(),
            filesystem: "device:1".into(),
            metrics: InventoryMetrics {
                allocated_bytes: 20,
                private_reclaimable_bytes: 10,
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            },
        };
        let first = eligibility_digest(&source, std::slice::from_ref(&candidate), 100);
        let repeated = eligibility_digest(&source, std::slice::from_ref(&candidate), 100);
        let mut changed = candidate;
        changed.file_identity = "other".into();
        assert_eq!(first, repeated);
        assert_ne!(first, eligibility_digest(&source, &[changed], 100));
    }

    #[test]
    fn source_selection_keeps_only_complete_direct_target_opportunities() {
        let source = serde_json::json!({
            "plan": {"artifacts": [
                {
                    "name": "target",
                    "path": "/tmp/repo/target",
                    "worktree_path": "/tmp/repo",
                    "rebuildable_opportunity": true,
                    "measurement": {"complete": true, "metrics": {"private_reclaimable_complete": true}},
                    "in_use": false,
                    "protection": null,
                    "has_tracked_files": false,
                    "ignored": true,
                    "open_handle_evidence": "complete"
                },
                {
                    "name": "target",
                    "path": "/tmp/repo/nested/target",
                    "worktree_path": "/tmp/repo",
                    "rebuildable_opportunity": true,
                    "measurement": {"complete": true, "metrics": {"private_reclaimable_complete": true}},
                    "in_use": false,
                    "protection": null,
                    "has_tracked_files": false,
                    "ignored": true,
                    "open_handle_evidence": "complete"
                }
            ]}
        });
        let targets = source_targets(&source).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].target_path, Path::new("/tmp/repo/target"));
    }

    #[test]
    fn unborn_worktree_identity_changes_when_the_first_commit_appears() -> Result<()> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("target/debug"))?;
        fs::write(repo.join(".gitignore"), "/target\n")?;
        let git = |args: &[&str]| -> Result<()> {
            let output = Command::new("git").args(args).current_dir(&repo).output()?;
            anyhow::ensure!(
                output.status.success(),
                "git {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(())
        };
        git(&["init", "-q"])?;
        git(&["config", "user.email", "collector@example.invalid"])?;
        git(&["config", "user.name", "Collector Test"])?;
        let target = SourceTarget {
            target_path: repo.join("target"),
            worktree_path: repo.clone(),
        };
        let unborn = live_target_owner(&target)?;
        assert!(unborn.head.starts_with("unborn:refs/heads/"));

        git(&["add", ".gitignore"])?;
        git(&["commit", "-qm", "first commit"])?;
        let committed = live_target_owner(&target)?;
        assert_ne!(committed.head, unborn.head);
        assert!(committed.head.bytes().all(|byte| byte.is_ascii_hexdigit()));
        Ok(())
    }
}
