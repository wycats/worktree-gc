use crate::inventory::inventory_with_root_limit;
use crate::{
    cargo_profile_locks_present, generated_dir_identity, open_handle_evidence_for_paths,
    with_cargo_profile_locks_timeout, with_protection_guard_for_paths, CleanupClass, CleanupMode,
    GeneratedDirAction, GeneratedDirIdentity, GeneratedDirMeasurement, InventoryOptions,
    ProtectionGuardOutcome, MANIFEST_VERSION,
};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const APPROVAL_DIGEST_PREFIX: &str = "sha256:";

#[derive(Debug, Serialize)]
pub struct ApprovedGeneratedExecutionRun {
    pub result_path: PathBuf,
    pub result: ApprovedGeneratedExecutionResult,
}

#[derive(Debug, Serialize)]
pub struct ApprovedGeneratedExecutionResult {
    pub manifest_version: u64,
    pub completed_at_unix: u64,
    pub approval_manifest: PathBuf,
    pub approval_digest: String,
    pub candidate: PathBuf,
    pub worktree: PathBuf,
    pub quarantine: PathBuf,
    pub recovered_quarantine: bool,
    pub available_bytes_before: u64,
    pub available_bytes_after: u64,
    pub realized_available_bytes: u64,
    pub source_head: String,
    pub source_status_sha256: String,
    pub measurement: GeneratedDirMeasurement,
}

#[derive(Debug, Deserialize)]
struct ApprovedCleanupManifest {
    manifest_version: u64,
    mode: CleanupMode,
    current_worktree: PathBuf,
    git_common_dir: PathBuf,
    check_in_use: bool,
    cargo_lock_timeout_secs: Option<u64>,
    pressure: Option<ApprovedPressurePolicy>,
    worktrees: Vec<ApprovedWorktreeDecision>,
    generated_dirs: Vec<ApprovedGeneratedDecision>,
}

#[derive(Debug, Deserialize)]
struct ApprovedRootCleanupManifest {
    manifest_version: u64,
    mode: CleanupMode,
    repositories: Vec<ApprovedCleanupRun>,
}

#[derive(Debug, Deserialize)]
struct ApprovedCleanupRun {
    manifest: ApprovedCleanupManifest,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ApprovedManifestEnvelope {
    Root(ApprovedRootCleanupManifest),
    Repository(ApprovedCleanupManifest),
}

impl ApprovedManifestEnvelope {
    fn repositories(&self) -> Vec<&ApprovedCleanupManifest> {
        match self {
            Self::Root(root) => root.repositories.iter().map(|run| &run.manifest).collect(),
            Self::Repository(manifest) => vec![manifest],
        }
    }

    fn validate(&self) -> Result<()> {
        if let Self::Root(root) = self {
            anyhow::ensure!(
                root.manifest_version == MANIFEST_VERSION,
                "exact generated execution requires root manifest version {MANIFEST_VERSION}, got {}",
                root.manifest_version
            );
            anyhow::ensure!(
                root.mode == CleanupMode::DryRun,
                "exact generated execution requires a dry-run root manifest"
            );
        }
        for manifest in self.repositories() {
            validate_manifest_boundary(manifest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct ApprovedWorktreeDecision {
    path: PathBuf,
    head: Option<String>,
    dirty_count: Option<usize>,
    status_sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ApprovedGeneratedDecision {
    path: PathBuf,
    worktree_path: PathBuf,
    name: String,
    in_use: bool,
    ownership_evidence_complete: bool,
    worktree_in_use: bool,
    owner_free_pressure: bool,
    protection: serde_json::Value,
    cleanup_class: CleanupClass,
    identity: Option<GeneratedDirIdentity>,
    measurement: Option<GeneratedDirMeasurement>,
    source_dirty_count_without_candidate: Option<usize>,
    source_status_sha256_without_candidate: Option<String>,
    action: GeneratedDirAction,
}

#[derive(Debug, Deserialize)]
struct ApprovedPressurePolicy {
    target_bytes: u64,
    owner_free_generated: bool,
    active: bool,
    entered_filesystems: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SourceIdentity {
    head: String,
    dirty_count: usize,
    status_sha256: String,
}

pub fn execute_approved_generated(
    manifest_path: &Path,
    approval_digest: &str,
    candidate: &Path,
    result_path: Option<&Path>,
) -> Result<ApprovedGeneratedExecutionRun> {
    execute_approved_generated_with_ownership(
        manifest_path,
        approval_digest,
        candidate,
        result_path,
        None,
        None,
    )
}

fn execute_approved_generated_with_ownership(
    manifest_path: &Path,
    approval_digest: &str,
    candidate: &Path,
    result_path: Option<&Path>,
    ownership_override: Option<&dyn Fn() -> (HashSet<PathBuf>, bool)>,
    measurement_override: Option<&GeneratedDirMeasurement>,
) -> Result<ApprovedGeneratedExecutionRun> {
    anyhow::ensure!(
        manifest_path.is_absolute(),
        "approval manifest path is not absolute"
    );
    let manifest_bytes = fs::read(manifest_path).with_context(|| {
        format!(
            "failed to read approved cleanup manifest {}",
            manifest_path.display()
        )
    })?;
    let expected_digest = parse_approval_digest(approval_digest)?;
    let actual_digest = format!("{:x}", Sha256::digest(&manifest_bytes));
    anyhow::ensure!(
        actual_digest == expected_digest,
        "approval digest mismatch for {}: expected sha256:{expected_digest}, got sha256:{actual_digest}",
        manifest_path.display()
    );
    let envelope: ApprovedManifestEnvelope = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("invalid cleanup manifest {}", manifest_path.display()))?;
    envelope.validate()?;

    let decisions = envelope
        .repositories()
        .into_iter()
        .flat_map(|manifest| {
            manifest
                .generated_dirs
                .iter()
                .filter(move |decision| decision.path == candidate)
                .map(move |decision| (manifest, decision))
        })
        .collect::<Vec<_>>();
    anyhow::ensure!(
        decisions.len() == 1,
        "approved manifest must contain candidate exactly once, found {} entries for {}",
        decisions.len(),
        candidate.display()
    );
    let (manifest, decision) = decisions[0];
    validate_approved_decision(decision)?;

    let approved_worktree = manifest
        .worktrees
        .iter()
        .find(|worktree| worktree.path == decision.worktree_path)
        .with_context(|| {
            format!(
                "approved manifest has no worktree identity for {}",
                decision.worktree_path.display()
            )
        })?;
    let approved_source = approved_source_identity(approved_worktree)?;
    let approved_source_without_candidate =
        approved_source_identity_without_candidate(approved_worktree, decision)?;
    let identity = decision
        .identity
        .as_ref()
        .context("approved candidate has no filesystem identity")?;
    anyhow::ensure!(
        decision.path == identity.canonical_path,
        "approved candidate path is not canonical"
    );
    let approved_measurement = decision
        .measurement
        .as_ref()
        .context("approved candidate has no bounded measurement")?;
    validate_approved_measurement(approved_measurement)?;
    anyhow::ensure!(
        approved_measurement.filesystem == identity.filesystem,
        "approved identity and measurement refer to different filesystems"
    );
    let pressure = manifest
        .pressure
        .as_ref()
        .context("approved pressure candidate has no pressure policy")?;
    anyhow::ensure!(pressure.active, "approved pressure policy was not active");
    anyhow::ensure!(
        pressure.owner_free_generated,
        "approved pressure policy did not enable owner-free generated cleanup"
    );
    anyhow::ensure!(
        pressure
            .entered_filesystems
            .iter()
            .any(|filesystem| filesystem == &identity.filesystem),
        "approved pressure policy did not enter the candidate filesystem"
    );

    let worktree = canonical_existing_directory(&decision.worktree_path, "worktree")?;
    anyhow::ensure!(
        worktree == decision.worktree_path,
        "approved worktree path is not canonical: {} resolves to {}",
        decision.worktree_path.display(),
        worktree.display()
    );
    anyhow::ensure!(
        manifest.current_worktree.is_absolute(),
        "approved current worktree is not absolute"
    );
    let git_common_dir = canonical_existing_directory(&manifest.git_common_dir, "Git common")?;
    anyhow::ensure!(
        git_common_dir == manifest.git_common_dir,
        "approved Git common path is not canonical"
    );
    let live_git_common = canonical_existing_directory(
        &resolve_git_path(
            &worktree,
            &git_output(&worktree, ["rev-parse", "--git-common-dir"])?,
        ),
        "live Git common",
    )?;
    anyhow::ensure!(
        git_common_dir == live_git_common,
        "Git common directory changed: approved {}, live {}",
        git_common_dir.display(),
        live_git_common.display()
    );
    anyhow::ensure!(
        generated_dir_identity(&git_common_dir)?.filesystem == identity.filesystem,
        "Git state and candidate are on different filesystems"
    );
    validate_candidate_lexical_boundary(candidate, decision, &worktree)?;
    validate_git_generated_boundary(&worktree, candidate)?;
    let quarantine = quarantine_path(&git_common_dir, candidate, &actual_digest)?;
    let candidate_exists = candidate.try_exists()?;
    let quarantine_exists = quarantine.try_exists()?;
    anyhow::ensure!(
        candidate_exists ^ quarantine_exists,
        "expected exactly one of candidate or quarantine to exist (candidate={}, quarantine={})",
        candidate_exists,
        quarantine_exists
    );
    let recovered_quarantine = quarantine_exists;
    let active_path = if recovered_quarantine {
        quarantine.as_path()
    } else {
        candidate
    };
    let source_before = source_identity(&worktree)?;
    let source_without_candidate_before = source_identity_excluding(&worktree, candidate)?;
    anyhow::ensure!(
        source_without_candidate_before == approved_source_without_candidate,
        "worktree filtered source identity changed since approval"
    );
    anyhow::ensure!(
        if recovered_quarantine {
            source_before.head == approved_source.head
        } else {
            source_before == approved_source
        },
        "worktree source identity changed since approval"
    );
    if !recovered_quarantine {
        ensure_pressure_still_needed(active_path, pressure.target_bytes)?;
    }

    let live_identity = generated_dir_identity(active_path)?;
    validate_live_identity(identity, &live_identity, recovered_quarantine)?;
    let live_measurement = match measurement_override {
        Some(measurement) => measurement.clone(),
        None => measure_exact_candidate(active_path)?,
    };
    anyhow::ensure!(
        measurements_match(approved_measurement, &live_measurement),
        "candidate measurement changed since approval"
    );

    let ownership_paths = vec![worktree.clone(), active_path.to_path_buf()];
    validate_current_ownership(&ownership_paths, ownership_override)?;

    let result_path = match result_path {
        Some(path) => path.to_path_buf(),
        None => default_result_path(manifest_path, &actual_digest, candidate)?,
    };
    validate_result_path(&result_path, &worktree, &git_common_dir, &quarantine)?;

    let target_lock_timeout = if decision.name == "target" && !recovered_quarantine {
        let lock_timeout = manifest
            .cargo_lock_timeout_secs
            .map(Duration::from_secs)
            .context("exact target execution requires a Cargo lock timeout in the manifest")?;
        anyhow::ensure!(
            cargo_profile_locks_present(candidate)?,
            "exact target execution requires existing Cargo profile locks"
        );
        Some(lock_timeout)
    } else {
        None
    };

    let available_before = fs4::available_space(&worktree)?;
    let guard_paths = vec![
        worktree.clone(),
        candidate.to_path_buf(),
        quarantine.clone(),
    ];
    let execution = with_protection_guard_for_paths(&guard_paths, SystemTime::now(), || {
        if let Some(lock_timeout) = target_lock_timeout {
            validate_current_ownership(&ownership_paths, ownership_override)?;
            with_cargo_profile_locks_timeout(candidate, &worktree, Some(lock_timeout), || {
                CandidateExecution {
                    candidate,
                    quarantine: &quarantine,
                    approved_identity: identity,
                    approved_measurement,
                    worktree: &worktree,
                    approved_source: &approved_source,
                    approved_source_without_candidate: &approved_source_without_candidate,
                    recovered_quarantine,
                    pressure_target_bytes: pressure.target_bytes,
                    recheck_ownership: true,
                    ownership_override,
                    measurement_override,
                    result_path: &result_path,
                }
                .execute()
            })?
        } else {
            CandidateExecution {
                candidate,
                quarantine: &quarantine,
                approved_identity: identity,
                approved_measurement,
                worktree: &worktree,
                approved_source: &approved_source,
                approved_source_without_candidate: &approved_source_without_candidate,
                recovered_quarantine,
                pressure_target_bytes: pressure.target_bytes,
                recheck_ownership: true,
                ownership_override,
                measurement_override,
                result_path: &result_path,
            }
            .execute()
        }
    })?;
    let (execution_measurement, result_file) = match execution {
        ProtectionGuardOutcome::Protected(lease) => bail!(
            "exact generated execution is protected by {} for {} until {}: {}",
            lease.id,
            lease.path.display(),
            lease.expires_at_unix,
            lease.reason
        ),
        ProtectionGuardOutcome::Executed(result) => result?,
    };

    anyhow::ensure!(
        !candidate.try_exists()?,
        "candidate still exists after execution"
    );
    anyhow::ensure!(
        !quarantine.try_exists()?,
        "quarantine still exists after execution"
    );
    let source_after = source_identity(&worktree)?;
    anyhow::ensure!(
        source_after.head == approved_source.head
            && source_identity_excluding(&worktree, candidate)?
                == approved_source_without_candidate,
        "worktree source identity changed during exact generated execution"
    );
    let available_after = fs4::available_space(&worktree)?;
    let result = ApprovedGeneratedExecutionResult {
        manifest_version: MANIFEST_VERSION,
        completed_at_unix: unix_seconds(SystemTime::now()),
        approval_manifest: manifest_path.to_path_buf(),
        approval_digest: format!("{APPROVAL_DIGEST_PREFIX}{actual_digest}"),
        candidate: candidate.to_path_buf(),
        worktree,
        quarantine,
        recovered_quarantine,
        available_bytes_before: available_before,
        available_bytes_after: available_after,
        realized_available_bytes: available_after.saturating_sub(available_before),
        source_head: source_after.head,
        source_status_sha256: source_after.status_sha256,
        measurement: execution_measurement,
    };
    write_result(&result_path, result_file, &result)?;
    Ok(ApprovedGeneratedExecutionRun {
        result_path,
        result,
    })
}

fn validate_manifest_boundary(manifest: &ApprovedCleanupManifest) -> Result<()> {
    anyhow::ensure!(
        manifest.manifest_version == MANIFEST_VERSION,
        "exact generated execution requires manifest version {MANIFEST_VERSION}, got {}",
        manifest.manifest_version
    );
    anyhow::ensure!(
        manifest.mode == CleanupMode::DryRun,
        "exact generated execution requires a dry-run manifest"
    );
    anyhow::ensure!(
        manifest.check_in_use,
        "exact generated execution requires check_in_use ownership evidence"
    );
    Ok(())
}

fn validate_approved_decision(decision: &ApprovedGeneratedDecision) -> Result<()> {
    anyhow::ensure!(
        decision.path.is_absolute(),
        "candidate path is not absolute"
    );
    anyhow::ensure!(
        decision.worktree_path.is_absolute(),
        "candidate worktree path is not absolute"
    );
    anyhow::ensure!(
        decision.action == GeneratedDirAction::Delete,
        "approved candidate action is not delete"
    );
    anyhow::ensure!(
        decision.cleanup_class == CleanupClass::Pressure,
        "approved candidate is not a pressure candidate"
    );
    anyhow::ensure!(
        decision.owner_free_pressure,
        "approved candidate is not owner-free pressure cleanup"
    );
    anyhow::ensure!(
        decision.ownership_evidence_complete && !decision.in_use && !decision.worktree_in_use,
        "approved candidate lacks complete owner-free evidence"
    );
    anyhow::ensure!(
        decision.protection.is_null(),
        "approved candidate had an applicable protection"
    );
    anyhow::ensure!(
        decision.path.file_name() == Some(OsStr::new(&decision.name)),
        "candidate name does not match its path"
    );
    Ok(())
}

fn approved_source_identity(worktree: &ApprovedWorktreeDecision) -> Result<SourceIdentity> {
    Ok(SourceIdentity {
        head: worktree
            .head
            .clone()
            .context("approved worktree has no HEAD identity")?,
        dirty_count: worktree
            .dirty_count
            .context("approved worktree has no source status")?,
        status_sha256: worktree
            .status_sha256
            .clone()
            .context("approved worktree has no source status digest")?,
    })
}

fn approved_source_identity_without_candidate(
    worktree: &ApprovedWorktreeDecision,
    decision: &ApprovedGeneratedDecision,
) -> Result<SourceIdentity> {
    Ok(SourceIdentity {
        head: worktree
            .head
            .clone()
            .context("approved worktree has no HEAD identity")?,
        dirty_count: decision
            .source_dirty_count_without_candidate
            .context("approved candidate has no filtered source status")?,
        status_sha256: decision
            .source_status_sha256_without_candidate
            .clone()
            .context("approved candidate has no filtered source status digest")?,
    })
}

fn validate_approved_measurement(measurement: &GeneratedDirMeasurement) -> Result<()> {
    anyhow::ensure!(measurement.complete, "approved measurement is incomplete");
    anyhow::ensure!(
        measurement.metrics.private_reclaimable_complete,
        "approved APFS-private measurement is incomplete"
    );
    anyhow::ensure!(
        measurement.metrics.errors == 0,
        "approved measurement has errors"
    );
    anyhow::ensure!(
        measurement.visited_entries <= super::GENERATED_MEASUREMENT_MAX_ENTRIES_PER_CANDIDATE,
        "approved measurement exceeds the per-candidate traversal bound"
    );
    Ok(())
}

fn validate_candidate_lexical_boundary(
    candidate: &Path,
    decision: &ApprovedGeneratedDecision,
    worktree: &Path,
) -> Result<()> {
    anyhow::ensure!(candidate == decision.path, "candidate path is not exact");
    let relative = candidate.strip_prefix(worktree).with_context(|| {
        format!(
            "candidate {} is outside worktree {}",
            candidate.display(),
            worktree.display()
        )
    })?;
    anyhow::ensure!(
        !relative.as_os_str().is_empty(),
        "candidate is the worktree root"
    );
    anyhow::ensure!(
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "candidate contains a non-normal path component"
    );
    Ok(())
}

fn validate_git_generated_boundary(worktree: &Path, candidate: &Path) -> Result<()> {
    let relative = candidate.strip_prefix(worktree)?;
    let relative = relative
        .to_str()
        .context("candidate relative path is not valid UTF-8")?
        .replace(std::path::MAIN_SEPARATOR, "/");
    let mut literal_pathspec = std::ffi::OsString::from(":(top,literal)");
    literal_pathspec.push(relative);
    let tracked = Command::new("git")
        .args(["ls-files", "-z", "--"])
        .arg(literal_pathspec)
        .current_dir(worktree)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run git ls-files in {}", worktree.display()))?;
    anyhow::ensure!(tracked.status.success(), "git ls-files failed");
    anyhow::ensure!(
        tracked.stdout.is_empty(),
        "candidate now contains tracked content"
    );
    Ok(())
}

fn canonical_existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} path {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{label} path is not a real directory: {}",
        path.display()
    );
    fs::canonicalize(path)
        .with_context(|| format!("failed to resolve {label} path {}", path.display()))
}

fn resolve_git_path(worktree: &Path, output: &str) -> PathBuf {
    let path = PathBuf::from(output.trim());
    if path.is_absolute() {
        path
    } else {
        worktree.join(path)
    }
}

fn source_identity(worktree: &Path) -> Result<SourceIdentity> {
    let head = git_output(worktree, ["rev-parse", "HEAD"])?
        .trim()
        .to_string();
    let status = git_bytes(worktree, ["status", "--porcelain=v1", "-z"])?;
    Ok(SourceIdentity {
        head,
        dirty_count: count_status_entries(&status),
        status_sha256: format!("{:x}", Sha256::digest(&status)),
    })
}

fn source_identity_excluding(worktree: &Path, candidate: &Path) -> Result<SourceIdentity> {
    let (dirty_count, status_sha256) =
        crate::source_status_excluding_candidate(worktree, candidate)?;
    Ok(SourceIdentity {
        head: git_output(worktree, ["rev-parse", "HEAD"])?
            .trim()
            .to_string(),
        dirty_count,
        status_sha256,
    })
}

fn count_status_entries(status: &[u8]) -> usize {
    let mut count = 0;
    let mut parts = status.split(|byte| *byte == 0);
    while let Some(entry) = parts.next() {
        if entry.len() < 4 {
            continue;
        }
        count += 1;
        if matches!(entry.first(), Some(b'R' | b'C')) || matches!(entry.get(1), Some(b'R' | b'C')) {
            let _ = parts.next();
        }
    }
    count
}

fn quarantine_path(git_common_dir: &Path, candidate: &Path, digest: &str) -> Result<PathBuf> {
    let candidate_digest = candidate_path_digest(candidate)?;
    Ok(git_common_dir
        .join("worktree-gc/exact-quarantine")
        .join(digest)
        .join(candidate_digest))
}

fn candidate_path_digest(candidate: &Path) -> Result<String> {
    let candidate = candidate
        .to_str()
        .context("candidate path is not valid UTF-8")?;
    Ok(format!("{:x}", Sha256::digest(candidate.as_bytes())))
}

fn validate_live_identity(
    expected: &GeneratedDirIdentity,
    live: &GeneratedDirIdentity,
    quarantined: bool,
) -> Result<()> {
    #[cfg(unix)]
    anyhow::ensure!(
        expected.device.is_some() && expected.inode.is_some(),
        "approved Unix candidate identity lacks device/inode"
    );
    anyhow::ensure!(
        expected.filesystem == live.filesystem
            && expected.device == live.device
            && expected.inode == live.inode
            && expected.modified_unix == live.modified_unix
            && expected.modified_nanos == live.modified_nanos,
        "candidate filesystem identity changed since approval"
    );
    if !quarantined {
        anyhow::ensure!(
            expected.canonical_path == live.canonical_path,
            "candidate canonical path changed since approval"
        );
    }
    Ok(())
}

fn measure_exact_candidate(path: &Path) -> Result<GeneratedDirMeasurement> {
    let report = inventory_with_root_limit(
        &[path.to_path_buf()],
        InventoryOptions {
            display_depth: 0,
            top: 1,
            max_entries: super::GENERATED_MEASUREMENT_MAX_ENTRIES_PER_CANDIDATE,
            one_filesystem: true,
        },
        Some(super::GENERATED_MEASUREMENT_MAX_ENTRIES_PER_CANDIDATE),
    )?;
    let root = report
        .roots
        .into_iter()
        .next()
        .context("exact candidate inventory returned no root")?;
    let measurement = GeneratedDirMeasurement {
        measured_at_unix: report.generated_at_unix,
        filesystem: root.filesystem,
        complete: root.complete,
        visited_entries: root.visited_entries,
        metrics: root.metrics,
    };
    validate_approved_measurement(&measurement)?;
    Ok(measurement)
}

fn ensure_single_filesystem_tree(path: &Path, expected_filesystem: &str) -> Result<()> {
    ensure_no_nested_mount_points(path)?;
    ensure_single_filesystem_tree_with(path, expected_filesystem, crate::filesystem_key)
}

fn ensure_no_nested_mount_points(path: &Path) -> Result<()> {
    ensure_no_nested_mount_points_with(path, &system_mount_points()?)
}

fn ensure_no_nested_mount_points_with(path: &Path, mount_points: &[PathBuf]) -> Result<()> {
    let path = fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize candidate {}", path.display()))?;
    for mount_point in mount_points {
        if mount_point == &path {
            bail!(
                "candidate root is a mount point at {}",
                mount_point.display()
            );
        }
        if mount_point.starts_with(&path) {
            bail!(
                "candidate contains a nested mount point at {}",
                mount_point.display()
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn system_mount_points() -> Result<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStrExt;

    let count = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    anyhow::ensure!(count >= 0, "failed to enumerate mounted filesystems");
    let capacity = usize::try_from(count)?.saturating_add(16);
    let mut mounts = (0..capacity)
        .map(|_| unsafe { std::mem::zeroed::<libc::statfs>() })
        .collect::<Vec<_>>();
    let buffer_size = i32::try_from(
        mounts
            .len()
            .saturating_mul(std::mem::size_of::<libc::statfs>()),
    )?;
    let written = unsafe { libc::getfsstat(mounts.as_mut_ptr(), buffer_size, libc::MNT_NOWAIT) };
    anyhow::ensure!(written >= 0, "failed to read mounted filesystems");
    let written = usize::try_from(written)?;
    anyhow::ensure!(
        written < mounts.len(),
        "mounted filesystem table changed during enumeration"
    );
    mounts.truncate(written);

    mounts
        .into_iter()
        .map(|mount| {
            let raw = unsafe {
                std::slice::from_raw_parts(
                    mount.f_mntonname.as_ptr().cast::<u8>(),
                    mount.f_mntonname.len(),
                )
            };
            let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
            let path = PathBuf::from(std::ffi::OsStr::from_bytes(&raw[..end]));
            fs::canonicalize(&path)
                .with_context(|| format!("failed to canonicalize mount point {}", path.display()))
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn system_mount_points() -> Result<Vec<PathBuf>> {
    use std::os::unix::ffi::OsStringExt;

    let mountinfo = fs::read("/proc/self/mountinfo").context("failed to read Linux mount table")?;
    mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let field = line
                .split(|byte| *byte == b' ')
                .nth(4)
                .context("invalid Linux mount table entry")?;
            let mut decoded = Vec::with_capacity(field.len());
            let mut index = 0;
            while index < field.len() {
                if field[index] == b'\\' && index + 3 < field.len() {
                    let octal = &field[index + 1..index + 4];
                    if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                        decoded.push(
                            (octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'),
                        );
                        index += 4;
                        continue;
                    }
                }
                decoded.push(field[index]);
                index += 1;
            }
            let path = PathBuf::from(std::ffi::OsString::from_vec(decoded));
            fs::canonicalize(&path)
                .with_context(|| format!("failed to canonicalize mount point {}", path.display()))
        })
        .collect()
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn system_mount_points() -> Result<Vec<PathBuf>> {
    bail!("exact generated execution cannot verify mount boundaries on this Unix platform")
}

#[cfg(not(unix))]
fn system_mount_points() -> Result<Vec<PathBuf>> {
    Ok(Vec::new())
}

fn ensure_single_filesystem_tree_with(
    path: &Path,
    expected_filesystem: &str,
    filesystem_for: impl Fn(&Path) -> Result<String>,
) -> Result<()> {
    for (index, entry) in WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        anyhow::ensure!(
            index < super::GENERATED_MEASUREMENT_MAX_ENTRIES_PER_CANDIDATE as usize,
            "candidate filesystem-boundary scan exceeds the per-candidate traversal bound"
        );
        let entry = entry.with_context(|| {
            format!(
                "failed to inspect candidate filesystem boundary beneath {}",
                path.display()
            )
        })?;
        if entry.file_type().is_symlink() {
            continue;
        }
        let actual_filesystem = filesystem_for(entry.path())?;
        anyhow::ensure!(
            actual_filesystem == expected_filesystem,
            "candidate contains a nested filesystem at {}: expected {}, found {}",
            entry.path().display(),
            expected_filesystem,
            actual_filesystem
        );
    }
    Ok(())
}

fn measurements_match(approved: &GeneratedDirMeasurement, live: &GeneratedDirMeasurement) -> bool {
    approved.filesystem == live.filesystem
        && approved.complete == live.complete
        && approved.visited_entries == live.visited_entries
        && approved.metrics == live.metrics
}

fn validate_current_ownership(
    paths: &[PathBuf],
    ownership_override: Option<&dyn Fn() -> (HashSet<PathBuf>, bool)>,
) -> Result<()> {
    let (owned_paths, ownership_complete) = ownership_override
        .map(|capture| capture())
        .unwrap_or_else(|| open_handle_evidence_for_paths(paths));
    anyhow::ensure!(
        ownership_complete,
        "current ownership evidence is incomplete; refusing exact generated execution"
    );
    anyhow::ensure!(
        owned_paths.is_empty(),
        "current process ownership exists for: {}",
        owned_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

fn ensure_pressure_still_needed(path: &Path, target_bytes: u64) -> Result<()> {
    let available = fs4::available_space(path)?;
    anyhow::ensure!(
        available < target_bytes,
        "pressure target is already satisfied: {available} bytes available, target {target_bytes}"
    );
    Ok(())
}

struct CandidateExecution<'a> {
    candidate: &'a Path,
    quarantine: &'a Path,
    approved_identity: &'a GeneratedDirIdentity,
    approved_measurement: &'a GeneratedDirMeasurement,
    worktree: &'a Path,
    approved_source: &'a SourceIdentity,
    approved_source_without_candidate: &'a SourceIdentity,
    recovered_quarantine: bool,
    pressure_target_bytes: u64,
    recheck_ownership: bool,
    ownership_override: Option<&'a dyn Fn() -> (HashSet<PathBuf>, bool)>,
    measurement_override: Option<&'a GeneratedDirMeasurement>,
    result_path: &'a Path,
}

impl CandidateExecution<'_> {
    fn execute(&self) -> Result<(GeneratedDirMeasurement, AtomicWriteFile)> {
        let source = source_identity(self.worktree)?;
        let source_without_candidate = source_identity_excluding(self.worktree, self.candidate)?;
        anyhow::ensure!(
            source_without_candidate == *self.approved_source_without_candidate
                && if self.recovered_quarantine {
                    source.head == self.approved_source.head
                } else {
                    source == *self.approved_source
                },
            "worktree source identity changed immediately before quarantine"
        );
        let active_path = if self.recovered_quarantine {
            self.quarantine
        } else {
            self.candidate
        };
        let live_identity = generated_dir_identity(active_path)?;
        validate_live_identity(
            self.approved_identity,
            &live_identity,
            self.recovered_quarantine,
        )?;
        ensure_single_filesystem_tree(active_path, &self.approved_identity.filesystem)?;
        let live_measurement = match self.measurement_override {
            Some(measurement) => measurement.clone(),
            None => measure_exact_candidate(active_path)?,
        };
        anyhow::ensure!(
            measurements_match(self.approved_measurement, &live_measurement),
            "candidate changed immediately before quarantine"
        );
        if !self.recovered_quarantine {
            ensure_pressure_still_needed(active_path, self.pressure_target_bytes)?;
        }
        if self.recheck_ownership {
            validate_current_ownership(
                &[self.worktree.to_path_buf(), active_path.to_path_buf()],
                self.ownership_override,
            )?;
        }
        let result_file = AtomicWriteFile::open(self.result_path).with_context(|| {
            format!(
                "failed to prepare execution result {}",
                self.result_path.display()
            )
        })?;

        if !self.recovered_quarantine {
            let parent = self
                .quarantine
                .parent()
                .context("quarantine has no parent")?;
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create quarantine {}", parent.display()))?;
            let canonical_parent = canonical_existing_directory(parent, "quarantine parent")?;
            let quarantine_root = parent.parent().context("quarantine has no state root")?;
            anyhow::ensure!(
                quarantine_root.file_name() == Some(OsStr::new("exact-quarantine")),
                "quarantine escaped the exact-quarantine state directory"
            );
            let state_dir = quarantine_root
                .parent()
                .context("quarantine has no worktree-gc state directory")?;
            anyhow::ensure!(
                state_dir.file_name() == Some(OsStr::new("worktree-gc")),
                "quarantine escaped the worktree-gc state directory"
            );
            let canonical_common = canonical_existing_directory(state_dir, "worktree-gc state")?;
            anyhow::ensure!(
                canonical_parent.starts_with(&canonical_common),
                "quarantine parent escaped the Git state directory"
            );
            anyhow::ensure!(
                !self.quarantine.try_exists()?,
                "exact quarantine already exists"
            );
            let quarantine_identity = generated_dir_identity(parent)?;
            anyhow::ensure!(
                quarantine_identity.filesystem == self.approved_identity.filesystem,
                "quarantine and candidate are on different filesystems"
            );
            fs::rename(self.candidate, self.quarantine).with_context(|| {
                format!(
                    "failed to atomically quarantine {} as {}",
                    self.candidate.display(),
                    self.quarantine.display()
                )
            })?;
            let quarantined_identity = generated_dir_identity(self.quarantine)?;
            validate_live_identity(self.approved_identity, &quarantined_identity, true)?;
        }

        fs::remove_dir_all(self.quarantine).with_context(|| {
            format!("failed to remove quarantine {}", self.quarantine.display())
        })?;
        remove_empty_quarantine_ancestors(self.quarantine)?;
        Ok((live_measurement, result_file))
    }
}

fn remove_empty_quarantine_ancestors(quarantine: &Path) -> Result<()> {
    let Some(run_dir) = quarantine.parent() else {
        return Ok(());
    };
    match fs::remove_dir(run_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    if let Some(root) = run_dir.parent() {
        match fs::remove_dir(root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn parse_approval_digest(raw: &str) -> Result<String> {
    let digest = raw.strip_prefix(APPROVAL_DIGEST_PREFIX).with_context(|| {
        format!("approval digest must use {APPROVAL_DIGEST_PREFIX}<lowercase-hex>")
    })?;
    anyhow::ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "approval digest must contain exactly 64 lowercase hexadecimal characters"
    );
    Ok(digest.to_string())
}

fn default_result_path(manifest_path: &Path, digest: &str, candidate: &Path) -> Result<PathBuf> {
    let filename = manifest_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("cleanup-manifest.json");
    let candidate_digest = candidate_path_digest(candidate)?;
    Ok(manifest_path.with_file_name(format!(
        "{filename}.{}.{}.execution.json",
        &digest[..16],
        &candidate_digest[..32]
    )))
}

fn validate_result_path(
    path: &Path,
    worktree: &Path,
    git_common_dir: &Path,
    quarantine: &Path,
) -> Result<()> {
    anyhow::ensure!(path.is_absolute(), "execution result path is not absolute");
    anyhow::ensure!(
        !path.try_exists()?,
        "execution result already exists: {}",
        path.display()
    );
    let parent = path
        .parent()
        .context("execution result path has no parent")?;
    let canonical_parent = canonical_existing_directory(parent, "execution result parent")?;
    anyhow::ensure!(
        !canonical_parent.starts_with(worktree) || canonical_parent.starts_with(git_common_dir),
        "execution result must be outside the owner worktree or inside its Git common directory"
    );
    if quarantine.try_exists()? {
        let canonical_quarantine = canonical_existing_directory(quarantine, "exact quarantine")?;
        anyhow::ensure!(
            !canonical_parent.starts_with(&canonical_quarantine),
            "execution result must be outside the exact quarantine being removed"
        );
    }
    Ok(())
}

fn write_result(
    path: &Path,
    mut file: AtomicWriteFile,
    result: &ApprovedGeneratedExecutionResult,
) -> Result<()> {
    file.write_all(&serde_json::to_vec_pretty(result)?)
        .with_context(|| format!("failed to write execution result {}", path.display()))?;
    file.commit()
        .with_context(|| format!("failed to commit execution result {}", path.display()))
}

fn git_output<const N: usize>(cwd: &Path, args: [&str; N]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "git failed in {}: {}",
        cwd.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn git_bytes<const N: usize>(cwd: &Path, args: [&str; N]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;
    anyhow::ensure!(output.status.success(), "git failed in {}", cwd.display());
    Ok(output.stdout)
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::InventoryMetrics;
    use serde_json::json;
    use tempfile::TempDir;

    struct Fixture {
        _temp: TempDir,
        repo: PathBuf,
        candidate: PathBuf,
        manifest: PathBuf,
        digest: String,
        measurement: GeneratedDirMeasurement,
    }

    fn unowned_ownership() -> (HashSet<PathBuf>, bool) {
        (HashSet::new(), true)
    }

    fn incomplete_ownership() -> (HashSet<PathBuf>, bool) {
        (HashSet::new(), false)
    }

    impl Fixture {
        fn execute(&self) -> Result<ApprovedGeneratedExecutionRun> {
            execute_approved_generated_with_ownership(
                &self.manifest,
                &self.digest,
                &self.candidate,
                None,
                Some(&unowned_ownership),
                Some(&self.measurement),
            )
        }
    }

    fn fixture(root_manifest: bool) -> Result<Fixture> {
        fixture_for_name(root_manifest, ".next")
    }

    fn rewrite_repository_manifest(
        fixture: &mut Fixture,
        update: impl FnOnce(&mut serde_json::Value),
    ) -> Result<()> {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest)?)?;
        update(&mut manifest);
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        fs::write(&fixture.manifest, &bytes)?;
        fixture.digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        Ok(())
    }

    fn unignore_candidate(fixture: &mut Fixture) -> Result<()> {
        fs::write(fixture.repo.join(".gitignore"), "")?;
        git(&fixture.repo, ["add", ".gitignore"])?;
        git(
            &fixture.repo,
            ["commit", "-m", "unignore generated fixture"],
        )?;
        let source = source_identity(&fixture.repo)?;
        let source_without_candidate =
            source_identity_excluding(&fixture.repo, &fixture.candidate)?;
        rewrite_repository_manifest(fixture, |manifest| {
            manifest["worktrees"][0]["head"] = json!(source.head);
            manifest["worktrees"][0]["dirty_count"] = json!(source.dirty_count);
            manifest["worktrees"][0]["status_sha256"] = json!(source.status_sha256);
            manifest["generated_dirs"][0]["source_dirty_count_without_candidate"] =
                json!(source_without_candidate.dirty_count);
            manifest["generated_dirs"][0]["source_status_sha256_without_candidate"] =
                json!(source_without_candidate.status_sha256);
        })
    }

    fn fixture_for_name(root_manifest: bool, name: &str) -> Result<Fixture> {
        let temp = tempfile::tempdir()?;
        let repo = temp.path().join("repo");
        fs::create_dir_all(&repo)?;
        git(&repo, ["init"])?;
        git(&repo, ["config", "user.email", "test@example.com"])?;
        git(&repo, ["config", "user.name", "Test User"])?;
        fs::write(repo.join(".gitignore"), format!("{name}/\n"))?;
        fs::write(repo.join("tracked.txt"), "tracked\n")?;
        if name == "target" {
            fs::write(
                repo.join("Cargo.toml"),
                "[package]\nname = \"fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
            )?;
            fs::write(
                repo.join("Cargo.lock"),
                "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"fixture\"\nversion = \"0.0.0\"\n",
            )?;
            fs::create_dir_all(repo.join("src"))?;
            fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        }
        git(&repo, ["add", "."])?;
        git(&repo, ["commit", "-m", "fixture"])?;

        let repo = fs::canonicalize(repo)?;
        let candidate = if name == ".next" {
            repo.join("chat/.next")
        } else {
            repo.join(name)
        };
        fs::create_dir_all(candidate.join("cache"))?;
        if name == "target" {
            fs::create_dir_all(candidate.join("debug"))?;
        }
        fs::write(candidate.join("cache/artifact"), "generated\n")?;
        let candidate = fs::canonicalize(candidate)?;
        let source = source_identity(&repo)?;
        let source_without_candidate = source_identity_excluding(&repo, &candidate)?;
        let identity = generated_dir_identity(&candidate)?;
        let measurement = GeneratedDirMeasurement {
            measured_at_unix: 1,
            filesystem: identity.filesystem.clone(),
            complete: true,
            visited_entries: 3,
            metrics: InventoryMetrics {
                logical_bytes: 10,
                allocated_bytes: 4096,
                private_reclaimable_bytes: 4096,
                private_reclaimable_complete: true,
                files: 1,
                directories: 2,
                hardlink_duplicates: 0,
                errors: 0,
            },
        };
        let git_common_dir = fs::canonicalize(repo.join(".git"))?;
        let repository_manifest = json!({
            "manifest_version": MANIFEST_VERSION,
            "mode": "dry_run",
            "current_worktree": repo,
            "git_common_dir": git_common_dir,
            "check_in_use": true,
            "cargo_lock_timeout_secs": 5,
            "pressure": {
                "target_bytes": u64::MAX,
                "owner_free_generated": true,
                "active": true,
                "entered_filesystems": [identity.filesystem.clone()],
            },
            "worktrees": [{
                "path": repo,
                "head": source.head,
                "dirty_count": source.dirty_count,
                "status_sha256": source.status_sha256,
            }],
            "generated_dirs": [{
                "path": candidate,
                "worktree_path": repo,
                "name": name,
                "in_use": false,
                "ownership_evidence_complete": true,
                "worktree_in_use": false,
                "owner_free_pressure": true,
                "protection": null,
                "cleanup_class": "pressure",
                "identity": identity,
                "measurement": measurement,
                "source_dirty_count_without_candidate": source_without_candidate.dirty_count,
                "source_status_sha256_without_candidate": source_without_candidate.status_sha256,
                "action": "delete",
            }],
        });
        let manifest_value = if root_manifest {
            json!({
                "manifest_version": MANIFEST_VERSION,
                "mode": "dry_run",
                "repositories": [{ "manifest": repository_manifest }],
            })
        } else {
            repository_manifest
        };
        let manifest = temp.path().join("approved.json");
        let bytes = serde_json::to_vec_pretty(&manifest_value)?;
        fs::write(&manifest, &bytes)?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        Ok(Fixture {
            _temp: temp,
            repo,
            candidate,
            manifest,
            digest,
            measurement,
        })
    }

    #[test]
    fn exact_execution_removes_only_the_approved_candidate_and_preserves_source() -> Result<()> {
        let fixture = fixture(true)?;
        let source_before = source_identity(&fixture.repo)?;

        let run = fixture.execute()?;

        assert!(!fixture.candidate.exists());
        assert!(!run.result.quarantine.exists());
        assert_eq!(source_identity(&fixture.repo)?, source_before);
        assert!(run.result_path.is_file());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_manifest_digest_drift_before_mutation() -> Result<()> {
        let fixture = fixture(false)?;
        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &format!("sha256:{}", "0".repeat(64)),
            &fixture.candidate,
            None,
            Some(&unowned_ownership),
            Some(&fixture.measurement),
        )
        .expect_err("digest drift must fail closed");

        assert!(error.to_string().contains("approval digest mismatch"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_replaced_candidate_identity() -> Result<()> {
        let fixture = fixture(false)?;
        fs::remove_dir_all(&fixture.candidate)?;
        fs::create_dir_all(fixture.candidate.join("cache"))?;
        fs::write(fixture.candidate.join("cache/artifact"), "generated\n")?;

        let error = fixture
            .execute()
            .expect_err("replacement with equal logical content must fail closed");
        assert!(error.to_string().contains("filesystem identity changed"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_source_drift() -> Result<()> {
        let fixture = fixture(false)?;
        fs::write(fixture.repo.join("new-source.txt"), "dirty\n")?;

        let error = fixture
            .execute()
            .expect_err("source drift must fail before quarantine");
        assert!(error.to_string().contains("source identity changed"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_routine_and_protected_candidates() -> Result<()> {
        let mut routine = fixture(false)?;
        rewrite_repository_manifest(&mut routine, |manifest| {
            manifest["generated_dirs"][0]["cleanup_class"] = json!("routine");
        })?;
        let error = routine
            .execute()
            .expect_err("routine candidates must stay on the routine path");
        assert!(error.to_string().contains("not a pressure candidate"));
        assert!(routine.candidate.is_dir());

        let mut protected = fixture(false)?;
        rewrite_repository_manifest(&mut protected, |manifest| {
            manifest["generated_dirs"][0]["protection"] = json!({ "id": "fixture-protection" });
        })?;
        let error = protected
            .execute()
            .expect_err("approved protections must fail closed");
        assert!(error.to_string().contains("applicable protection"));
        assert!(protected.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_requires_explicit_protection_evidence() -> Result<()> {
        let mut fixture = fixture(false)?;
        rewrite_repository_manifest(&mut fixture, |manifest| {
            manifest["generated_dirs"][0]
                .as_object_mut()
                .unwrap()
                .remove("protection");
        })?;

        let error = fixture
            .execute()
            .expect_err("omitted protection evidence must fail closed");

        assert!(error.to_string().contains("invalid cleanup manifest"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_generated_trees_with_tracked_content() -> Result<()> {
        let mut fixture = fixture(false)?;
        git(&fixture.repo, ["add", "-f", "chat/.next/cache/artifact"])?;
        git(&fixture.repo, ["commit", "-m", "track generated fixture"])?;
        let source = source_identity(&fixture.repo)?;
        rewrite_repository_manifest(&mut fixture, |manifest| {
            manifest["worktrees"][0]["head"] = json!(source.head);
            manifest["worktrees"][0]["dirty_count"] = json!(source.dirty_count);
            manifest["worktrees"][0]["status_sha256"] = json!(source.status_sha256);
        })?;

        let error = fixture
            .execute()
            .expect_err("tracked generated content must fail closed");
        assert!(error.to_string().contains("tracked content"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_treats_pathspec_magic_names_as_literal() -> Result<()> {
        let mut fixture = fixture_for_name(false, ":(top)tracked")?;
        git(
            &fixture.repo,
            [
                "--literal-pathspecs",
                "add",
                "-f",
                "--",
                ":(top)tracked/cache/artifact",
            ],
        )?;
        git(&fixture.repo, ["commit", "-m", "track magic fixture"])?;
        let source = source_identity(&fixture.repo)?;
        rewrite_repository_manifest(&mut fixture, |manifest| {
            manifest["worktrees"][0]["head"] = json!(source.head);
            manifest["worktrees"][0]["dirty_count"] = json!(source.dirty_count);
            manifest["worktrees"][0]["status_sha256"] = json!(source.status_sha256);
        })?;

        let error = fixture
            .execute()
            .expect_err("tracked content in a pathspec-magic name must fail closed");

        assert!(error.to_string().contains("tracked content"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_recovers_only_its_digest_bound_quarantine() -> Result<()> {
        let fixture = fixture(false)?;
        let digest = fixture.digest.strip_prefix("sha256:").unwrap();
        let quarantine = quarantine_path(
            &fs::canonicalize(fixture.repo.join(".git"))?,
            &fixture.candidate,
            digest,
        )?;
        fs::create_dir_all(quarantine.parent().unwrap())?;
        fs::rename(&fixture.candidate, &quarantine)?;

        let run = fixture.execute()?;

        assert!(run.result.recovered_quarantine);
        assert!(!quarantine.exists());
        assert!(!fixture.candidate.exists());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_a_result_inside_the_recovered_quarantine() -> Result<()> {
        let fixture = fixture(false)?;
        let digest = fixture.digest.strip_prefix("sha256:").unwrap();
        let quarantine = quarantine_path(
            &fs::canonicalize(fixture.repo.join(".git"))?,
            &fixture.candidate,
            digest,
        )?;
        fs::create_dir_all(quarantine.parent().unwrap())?;
        fs::rename(&fixture.candidate, &quarantine)?;
        let result_dir = quarantine.join("cache");

        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            Some(&result_dir.join("execution.json")),
            Some(&unowned_ownership),
            Some(&fixture.measurement),
        )
        .expect_err("result evidence inside recovered quarantine must fail closed");

        assert!(error
            .to_string()
            .contains("outside the exact quarantine being removed"));
        assert!(quarantine.is_dir());
        assert!(!fixture.candidate.exists());
        Ok(())
    }

    #[test]
    fn quarantine_paths_distinguish_candidates_with_the_same_basename() -> Result<()> {
        let temp = TempDir::new()?;
        let git_common = temp.path().join("git-common");
        let first = temp.path().join("first/node_modules");
        let second = temp.path().join("second/node_modules");
        let digest = "a".repeat(64);

        let first_quarantine = quarantine_path(&git_common, &first, &digest)?;
        let second_quarantine = quarantine_path(&git_common, &second, &digest)?;

        assert_ne!(first_quarantine, second_quarantine);
        assert_eq!(first_quarantine.parent(), second_quarantine.parent());
        assert_eq!(first_quarantine.file_name().unwrap().len(), 64);
        assert_eq!(second_quarantine.file_name().unwrap().len(), 64);
        Ok(())
    }

    #[test]
    fn default_result_paths_distinguish_candidates_from_one_manifest() -> Result<()> {
        let temp = TempDir::new()?;
        let manifest = temp.path().join("approved.json");
        let first = temp.path().join("first/node_modules");
        let second = temp.path().join("second/node_modules");
        let digest = "a".repeat(64);

        let first_result = default_result_path(&manifest, &digest, &first)?;
        let second_result = default_result_path(&manifest, &digest, &second)?;

        assert_ne!(first_result, second_result);
        assert_eq!(first_result.parent(), second_result.parent());
        assert!(first_result
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".execution.json"));
        assert!(second_result
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(".execution.json"));
        Ok(())
    }

    #[test]
    fn exact_deletion_rejects_a_nested_filesystem() -> Result<()> {
        let temp = TempDir::new()?;
        let root = temp.path().join("candidate");
        let nested = root.join("mounted");
        fs::create_dir_all(&nested)?;
        fs::write(nested.join("artifact"), "generated\n")?;

        let error = ensure_single_filesystem_tree_with(&root, "device:1", |path| {
            if path == nested {
                Ok("device:2".to_string())
            } else {
                Ok("device:1".to_string())
            }
        })
        .expect_err("nested filesystems must fail closed before deletion");

        assert!(error.to_string().contains("contains a nested filesystem"));
        assert!(nested.join("artifact").is_file());
        Ok(())
    }

    #[test]
    fn exact_deletion_rejects_a_same_device_nested_mount_point() -> Result<()> {
        let temp = TempDir::new()?;
        let root = fs::canonicalize(temp.path())?;
        let nested = root.join("mounted");
        fs::create_dir(&nested)?;

        let error = ensure_no_nested_mount_points_with(&root, std::slice::from_ref(&nested))
            .expect_err("same-device nested mount points must fail closed");

        assert!(error.to_string().contains("contains a nested mount point"));
        assert!(nested.is_dir());
        Ok(())
    }

    #[test]
    fn exact_deletion_rejects_a_same_device_candidate_root_mount_point() -> Result<()> {
        let temp = TempDir::new()?;
        let root = fs::canonicalize(temp.path())?;

        let error = ensure_no_nested_mount_points_with(&root, std::slice::from_ref(&root))
            .expect_err("a candidate-root mount point must fail closed");

        assert!(error
            .to_string()
            .contains("candidate root is a mount point"));
        assert!(root.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_incomplete_live_ownership_evidence() -> Result<()> {
        let fixture = fixture(false)?;
        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            None,
            Some(&incomplete_ownership),
            Some(&fixture.measurement),
        )
        .expect_err("incomplete ownership evidence must fail closed");

        assert!(error
            .to_string()
            .contains("ownership evidence is incomplete"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_current_process_ownership() -> Result<()> {
        let fixture = fixture(false)?;
        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            None,
            Some(&|| (HashSet::from([fixture.candidate.clone()]), true)),
            Some(&fixture.measurement),
        )
        .expect_err("current ownership must fail closed");

        assert!(error
            .to_string()
            .contains("current process ownership exists"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_holds_existing_cargo_profile_locks_for_target() -> Result<()> {
        let fixture = fixture_for_name(false, "target")?;
        fs::write(fixture.candidate.join("debug/.cargo-lock"), "")?;

        fixture.execute()?;

        assert!(!fixture.candidate.exists());
        Ok(())
    }

    #[test]
    fn target_execution_rechecks_ownership_inside_profile_locks() -> Result<()> {
        let fixture = fixture_for_name(false, "target")?;
        fs::write(fixture.candidate.join("debug/.cargo-lock"), "")?;
        let snapshots = std::cell::Cell::new(0);
        let candidate = fixture.candidate.clone();
        let ownership = || {
            let snapshot = snapshots.get() + 1;
            snapshots.set(snapshot);
            if snapshot >= 3 {
                (HashSet::from([candidate.clone()]), true)
            } else {
                (HashSet::new(), true)
            }
        };

        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            None,
            Some(&ownership),
            Some(&fixture.measurement),
        )
        .expect_err("ownership appearing during a Cargo lock wait must fail closed");

        assert_eq!(snapshots.get(), 3);
        assert!(error
            .to_string()
            .contains("current process ownership exists"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_target_without_cargo_profile_locks() -> Result<()> {
        let fixture = fixture_for_name(false, "target")?;

        let error = fixture
            .execute()
            .expect_err("target without profile locks must fail closed");

        assert!(error
            .to_string()
            .contains("requires existing Cargo profile locks"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_rejects_result_inside_source_worktree() -> Result<()> {
        let fixture = fixture(false)?;
        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            Some(&fixture.repo.join("execution.json")),
            Some(&unowned_ownership),
            Some(&fixture.measurement),
        )
        .expect_err("execution evidence must not dirty the owner worktree");

        assert!(error.to_string().contains("outside the owner worktree"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_accepts_untracked_unignored_generated_content() -> Result<()> {
        let mut fixture = fixture(false)?;
        unignore_candidate(&mut fixture)?;

        fixture.execute()?;

        assert!(!fixture.candidate.exists());
        Ok(())
    }

    #[test]
    fn exact_execution_recovers_an_untracked_unignored_quarantine() -> Result<()> {
        let mut fixture = fixture(false)?;
        unignore_candidate(&mut fixture)?;
        let digest = fixture.digest.strip_prefix("sha256:").unwrap();
        let quarantine = quarantine_path(
            &fs::canonicalize(fixture.repo.join(".git"))?,
            &fixture.candidate,
            digest,
        )?;
        fs::create_dir_all(quarantine.parent().unwrap())?;
        fs::rename(&fixture.candidate, &quarantine)?;

        let run = fixture.execute()?;

        assert!(run.result.recovered_quarantine);
        assert!(!quarantine.exists());
        assert!(!fixture.candidate.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn exact_execution_prepares_the_result_before_deleting() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let fixture = fixture(false)?;
        let result_dir = fixture._temp.path().join("read-only-result");
        fs::create_dir(&result_dir)?;
        fs::set_permissions(&result_dir, fs::Permissions::from_mode(0o500))?;
        let result_path = result_dir.join("execution.json");

        let error = execute_approved_generated_with_ownership(
            &fixture.manifest,
            &fixture.digest,
            &fixture.candidate,
            Some(&result_path),
            Some(&unowned_ownership),
            Some(&fixture.measurement),
        )
        .expect_err("an unwritable result must fail before candidate deletion");

        fs::set_permissions(&result_dir, fs::Permissions::from_mode(0o700))?;
        assert!(error.to_string().contains("prepare execution result"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_stops_when_pressure_target_is_already_satisfied() -> Result<()> {
        let mut fixture = fixture(false)?;
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&fixture.manifest)?)?;
        manifest["pressure"]["target_bytes"] = json!(0);
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        fs::write(&fixture.manifest, &bytes)?;
        fixture.digest = format!("sha256:{:x}", Sha256::digest(&bytes));

        let error = fixture
            .execute()
            .expect_err("a satisfied pressure target must retain the candidate");

        assert!(error
            .to_string()
            .contains("pressure target is already satisfied"));
        assert!(fixture.candidate.is_dir());
        Ok(())
    }

    #[test]
    fn exact_execution_requires_an_entered_owner_free_pressure_policy() -> Result<()> {
        let mut disabled = fixture(false)?;
        rewrite_repository_manifest(&mut disabled, |manifest| {
            manifest["pressure"]["owner_free_generated"] = json!(false);
        })?;
        let error = disabled
            .execute()
            .expect_err("disabled owner-free pressure policy must retain the candidate");
        assert!(error
            .to_string()
            .contains("did not enable owner-free generated cleanup"));
        assert!(disabled.candidate.is_dir());

        let mut not_entered = fixture(false)?;
        rewrite_repository_manifest(&mut not_entered, |manifest| {
            manifest["pressure"]["entered_filesystems"] = json!([]);
        })?;
        let error = not_entered
            .execute()
            .expect_err("a filesystem outside pressure entry must retain the candidate");
        assert!(error
            .to_string()
            .contains("did not enter the candidate filesystem"));
        assert!(not_entered.candidate.is_dir());
        Ok(())
    }

    fn git<const N: usize>(cwd: &Path, args: [&str; N]) -> Result<()> {
        let output = Command::new("git").args(args).current_dir(cwd).output()?;
        anyhow::ensure!(
            output.status.success(),
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
}
