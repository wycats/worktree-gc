use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::protection::{
    active_protections, protection_for_path, with_protection_guard_for_paths,
    ProtectionGuardOutcome, ProtectionLease, ProtectionMatch,
};
use crate::{format_bytes, CleanupMode};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use fs4::FileExt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BAMBU_MANIFEST_VERSION: u64 = 4;
const BAMBU_APPROVAL_CONTRACT: &[u8] = b"worktree-gc:bambu-logs:approval:v4";
const MAX_LOG_FILES: usize = 10_000;
const MAX_ACTIVE_OWNER_PROCESSES: usize = 100;

#[derive(Debug, Clone)]
pub struct BambuCollectOptions {
    pub execute: bool,
    pub approved_digest: Option<String>,
    pub roots: Vec<PathBuf>,
    pub retention_days: u64,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for BambuCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            approved_digest: None,
            roots: Vec::new(),
            retention_days: 14,
            max_entries: 100_000,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BambuCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: BambuCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct BambuCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub bambu: BambuIdentity,
    pub policy: BambuPolicy,
    pub plan: BambuLogPlan,
    pub outcome: Option<BambuPruneOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BambuIdentity {
    /// True only when discovery used Bambu's closed, owner-declared default
    /// log roots. Custom roots are useful for report-only diagnosis, but the
    /// execution contract deliberately cannot mutate them.
    pub owner_declared_default_roots: bool,
    pub log_roots: Vec<BambuLogRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BambuLogRoot {
    pub product: String,
    pub path: PathBuf,
    pub present: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BambuPolicy {
    pub owner_contract: &'static str,
    pub execution: &'static str,
    pub unattended_execution_supported: bool,
    pub retention_days: u64,
    pub max_entries: u64,
    pub max_log_files: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BambuPruneOutcome {
    pub candidates_deleted: usize,
    pub deleted_paths: Vec<PathBuf>,
    pub quarantine_paths: Vec<PathBuf>,
    pub verification_complete: bool,
    pub error: Option<String>,
    pub remaining_original_paths: Vec<PathBuf>,
    pub remaining_quarantine_paths: Vec<PathBuf>,
    pub available_bytes_before: u64,
    pub available_bytes_after: u64,
    pub realized_reclaim_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BambuLogAction {
    NoWork,
    ReportOnly,
    CustomRoots,
    InUse,
    Protected,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct BambuLogPlan {
    pub action: BambuLogAction,
    pub reason: String,
    pub complete: bool,
    pub eligibility_digest: String,
    pub candidates: Vec<BambuLogFile>,
    pub retained: Vec<BambuLogFile>,
    pub unknown_entries: Vec<PathBuf>,
    pub root_errors: Vec<String>,
    pub expected_reclaim: InventoryMetrics,
    pub active_owner_processes: Vec<String>,
    pub process_check_complete: bool,
    pub open_paths: Vec<PathBuf>,
    pub open_handle_check_complete: bool,
    pub protections: Vec<ProtectionMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BambuLogFile {
    pub product: String,
    pub path: PathBuf,
    pub file_identity: String,
    pub filesystem: String,
    pub modified_unix: u64,
    pub age_days: u64,
    pub metrics: InventoryMetrics,
}

#[derive(Debug)]
struct BambuSnapshot {
    identity: BambuIdentity,
    candidates: Vec<UnmeasuredLogFile>,
    retained: Vec<UnmeasuredLogFile>,
    unknown_entries: Vec<PathBuf>,
    root_errors: Vec<String>,
    complete: bool,
}

#[derive(Debug)]
struct UnmeasuredLogFile {
    product: String,
    path: PathBuf,
    file_identity: String,
    modified_unix: u64,
    age_days: u64,
}

type BambuMeasurements = BTreeMap<PathBuf, (String, InventoryMetrics)>;

pub fn collect_bambu(options: BambuCollectOptions) -> Result<BambuCollectRun> {
    anyhow::ensure!(
        options.retention_days > 0,
        "retention_days must be at least 1"
    );
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    anyhow::ensure!(
        options.execute || options.approved_digest.is_none(),
        "--approved-digest is only valid with --execute"
    );
    if options.execute {
        anyhow::ensure!(
            options.roots.is_empty(),
            "Bambu execution supports only the owner-declared default log roots"
        );
        let digest = options
            .approved_digest
            .as_deref()
            .context("Bambu execution requires --approved-digest from a dry-run")?;
        anyhow::ensure!(
            valid_sha256_digest(digest),
            "--approved-digest must be a sha256: digest"
        );
    }
    let owner_declared_default_roots = options.roots.is_empty();
    let roots = if owner_declared_default_roots {
        default_log_roots()?
    } else {
        options.roots.clone()
    };
    let protections = active_protections(options.now)?;
    let (identity, plan) = plan_bambu(&roots, owner_declared_default_roots, &options, &protections);
    let mut manifest = BambuCollectManifest {
        manifest_version: BAMBU_MANIFEST_VERSION,
        collector: "bambu-logs",
        run_id: format!("{}-{}", unix_nanos(options.now), std::process::id()),
        mode: if options.execute {
            CleanupMode::Execute
        } else {
            CleanupMode::DryRun
        },
        generated_at_unix: unix_seconds(options.now),
        bambu: identity,
        policy: BambuPolicy {
            owner_contract: "Bambu Studio, Bambu Studio Beta, and legacy Bambu Suite encrypted diagnostic log roots only; presets, plugins, projects, and user state are excluded",
            execution: "manual digest-bound same-filesystem quarantine with execution-time app/open-file/protection revalidation",
            unattended_execution_supported: false,
            retention_days: options.retention_days,
            max_entries: options.max_entries,
            max_log_files: MAX_LOG_FILES,
        },
        plan,
        outcome: None,
    };
    let manifest_path = write_manifest(&manifest)?;
    if let Some(approved) = options.approved_digest.as_deref() {
        anyhow::ensure!(
            approved == manifest.plan.eligibility_digest,
            "approved Bambu plan {approved} does not match current plan {}; review {} before trying again",
            manifest.plan.eligibility_digest,
            manifest_path.display()
        );
    }
    if options.execute {
        let execution = execute_bambu_plan(&roots, &options, &mut manifest);
        write_manifest_at(&manifest_path, &manifest)?;
        execution.with_context(|| {
            format!(
                "Bambu collector execution failed; inspect manifest {}",
                manifest_path.display()
            )
        })?;
    }
    Ok(BambuCollectRun {
        manifest_path,
        manifest,
    })
}

fn plan_bambu(
    roots: &[PathBuf],
    owner_declared_default_roots: bool,
    options: &BambuCollectOptions,
    protections: &[ProtectionLease],
) -> (BambuIdentity, BambuLogPlan) {
    let snapshot = snapshot_logs(roots, owner_declared_default_roots, options);
    let BambuSnapshot {
        identity,
        candidates: unmeasured_candidates,
        retained: unmeasured_retained,
        unknown_entries,
        mut root_errors,
        complete: snapshot_complete,
    } = snapshot;
    let measured_paths = unmeasured_candidates
        .iter()
        .chain(unmeasured_retained.iter())
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let (measurements, measurement_complete, measurement_error) =
        measure_paths(&measured_paths, options.max_entries);
    let candidates = measured_files(unmeasured_candidates, &measurements);
    let retained = measured_files(unmeasured_retained, &measurements);
    let identities_stable = candidates
        .iter()
        .chain(retained.iter())
        .all(log_file_identity_is_current);
    let expected_reclaim = sum_metrics(candidates.iter().map(|file| &file.metrics));
    let (active_owner_processes, process_check_complete) = active_bambu_processes();
    let (open_paths, open_handle_check_complete) = open_bambu_paths(&identity.log_roots);
    let mut candidate_protections = candidates
        .iter()
        .filter_map(|candidate| protection_for_path(&candidate.path, protections))
        .collect::<Vec<_>>();
    candidate_protections.sort_by(|left, right| left.id.cmp(&right.id));
    candidate_protections.dedup_by(|left, right| left.id == right.id);
    if let Some(error) = measurement_error {
        root_errors.push(error);
    }
    if !identities_stable {
        root_errors.push(
            "one or more Bambu log identities changed during measurement; rerun after writers stop"
                .into(),
        );
    }
    let complete = snapshot_complete
        && measurement_complete
        && identities_stable
        && process_check_complete
        && open_handle_check_complete
        && candidates
            .iter()
            .chain(retained.iter())
            .all(|file| file.metrics.private_reclaimable_complete);
    let (mut action, mut reason) = classify_plan(
        candidates.is_empty(),
        complete,
        &active_owner_processes,
        &open_paths,
        &candidate_protections,
    );
    if action == BambuLogAction::ReportOnly && !owner_declared_default_roots {
        action = BambuLogAction::CustomRoots;
        reason = "custom Bambu log roots are inventory-only; mutation is limited to the owner-declared default roots"
            .into();
    }
    let eligibility_digest = eligibility_digest(&identity, &candidates, options);
    (
        identity,
        BambuLogPlan {
            action,
            reason,
            complete,
            eligibility_digest,
            candidates,
            retained,
            unknown_entries,
            root_errors,
            expected_reclaim,
            active_owner_processes,
            process_check_complete,
            open_paths,
            open_handle_check_complete,
            protections: candidate_protections,
        },
    )
}

fn log_file_identity_is_current(file: &BambuLogFile) -> bool {
    fs::symlink_metadata(&file.path).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && file_identity(&metadata) == file.file_identity
            && metadata.modified().map(unix_seconds).ok() == Some(file.modified_unix)
    })
}

pub fn print_bambu_collect(run: &BambuCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: bambu-logs");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    for root in &run.manifest.bambu.log_roots {
        println!(
            "{} logs: {}{}",
            root.product,
            root.path.display(),
            if root.present { "" } else { " (absent)" }
        );
    }
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!(
        "expired diagnostics: {} files, {} private{} | {} allocated",
        plan.candidates.len(),
        format_bytes(plan.expected_reclaim.private_reclaimable_bytes),
        if plan.expected_reclaim.private_reclaimable_complete {
            ""
        } else {
            " (lower bound)"
        },
        format_bytes(plan.expected_reclaim.allocated_bytes)
    );
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "deleted: {} files | {} realized free-space gain | verification {}",
            outcome.candidates_deleted,
            format_bytes(outcome.realized_reclaim_bytes),
            if outcome.verification_complete && outcome.error.is_none() {
                "complete"
            } else {
                "incomplete"
            }
        );
    }
}

fn default_log_roots() -> Result<Vec<PathBuf>> {
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?);
    let support = home.join("Library/Application Support");
    Ok(
        ["BambuStudio/log", "BambuStudioBeta/log", "Bambu Suite/log"]
            .into_iter()
            .map(|relative| support.join(relative))
            .collect(),
    )
}

fn snapshot_logs(
    roots: &[PathBuf],
    owner_declared_default_roots: bool,
    options: &BambuCollectOptions,
) -> BambuSnapshot {
    let cutoff = options
        .now
        .checked_sub(Duration::from_secs(
            options.retention_days.saturating_mul(24 * 60 * 60),
        ))
        .unwrap_or(UNIX_EPOCH);
    let mut identity_roots = Vec::new();
    let mut candidates = Vec::new();
    let mut retained = Vec::new();
    let mut unknown_entries = Vec::new();
    let mut root_errors = Vec::new();
    let mut complete = true;
    let mut visited = 0usize;
    for root in roots {
        let product = product_name(root);
        if let Err(error) = validate_product_log_root(root, owner_declared_default_roots) {
            identity_roots.push(BambuLogRoot {
                product,
                path: root.clone(),
                present: path_exists_no_follow(root).unwrap_or(true),
            });
            root_errors.push(format!(
                "reject unsafe Bambu log root {}: {error:#}",
                root.display()
            ));
            complete = false;
            continue;
        }
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                identity_roots.push(BambuLogRoot {
                    product,
                    path: root.clone(),
                    present: false,
                });
                continue;
            }
            Err(error) => {
                identity_roots.push(BambuLogRoot {
                    product,
                    path: root.clone(),
                    present: true,
                });
                root_errors.push(format!("inspect {}: {error}", root.display()));
                complete = false;
                continue;
            }
        };
        identity_roots.push(BambuLogRoot {
            product: product.clone(),
            path: root.clone(),
            present: true,
        });
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            root_errors.push(format!("{} is not a non-symlink directory", root.display()));
            complete = false;
            continue;
        }
        let entries = match fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) => {
                root_errors.push(format!("read {}: {error}", root.display()));
                complete = false;
                continue;
            }
        };
        for entry in entries {
            if visited >= MAX_LOG_FILES {
                complete = false;
                root_errors.push(format!("log entry limit of {MAX_LOG_FILES} was exhausted"));
                break;
            }
            visited += 1;
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    complete = false;
                    root_errors.push(format!("read entry below {}: {error}", root.display()));
                    continue;
                }
            };
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    complete = false;
                    root_errors.push(format!("inspect {}: {error}", path.display()));
                    continue;
                }
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || !is_owned_log_name(&entry.file_name())
            {
                if metadata.is_dir()
                    && entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".worktree-gc-trash-")
                {
                    complete = false;
                    root_errors.push(format!(
                        "interrupted Bambu quarantine requires explicit recovery review: {}",
                        path.display()
                    ));
                }
                unknown_entries.push(path);
                continue;
            }
            let modified = match metadata.modified() {
                Ok(modified) => modified,
                Err(error) => {
                    complete = false;
                    root_errors.push(format!("read mtime for {}: {error}", path.display()));
                    continue;
                }
            };
            let modified_unix = unix_seconds(modified);
            let age_days = options
                .now
                .duration_since(modified)
                .unwrap_or_default()
                .as_secs()
                / (24 * 60 * 60);
            let observation = UnmeasuredLogFile {
                product: product.clone(),
                path,
                file_identity: file_identity(&metadata),
                modified_unix,
                age_days,
            };
            if modified <= cutoff {
                candidates.push(observation);
            } else {
                retained.push(observation);
            }
        }
    }
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    retained.sort_by(|left, right| left.path.cmp(&right.path));
    unknown_entries.sort();
    identity_roots.sort_by(|left, right| left.path.cmp(&right.path));
    BambuSnapshot {
        identity: BambuIdentity {
            owner_declared_default_roots,
            log_roots: identity_roots,
        },
        candidates,
        retained,
        unknown_entries,
        root_errors,
        complete,
    }
}

fn validate_product_log_root(root: &Path, owner_declared_default_root: bool) -> Result<()> {
    if owner_declared_default_root {
        ensure_no_symlink_components(root)?;
    }
    let product_root = root
        .parent()
        .context("Bambu log root has no product-directory parent")?;
    match fs::symlink_metadata(product_root) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "product directory is not a regular non-symlink directory: {}",
            product_root.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect product directory {}", product_root.display()));
        }
    }
    match fs::symlink_metadata(root) {
        Ok(metadata) => anyhow::ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "log root is not a regular non-symlink directory: {}",
            root.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| format!("inspect log root {}", root.display()));
        }
    }
    Ok(())
}

fn ensure_no_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "owner-declared Bambu path contains a symlink component: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("inspect Bambu path component {}", current.display())
                });
            }
        }
    }
    Ok(())
}

fn is_owned_log_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    if name == "log_iotc.txt" {
        return true;
    }
    if let Some(stem) = name
        .strip_prefix("debug_network_")
        .and_then(|name| name.strip_suffix(".log.enc"))
    {
        return !stem.is_empty();
    }
    let Some((stem, rotation)) = name.rsplit_once(".log.") else {
        return false;
    };
    stem.starts_with("studio_")
        && (stem.ends_with("_enc") || stem.ends_with("_enc_dc"))
        && !rotation.is_empty()
        && rotation.bytes().all(|byte| byte.is_ascii_digit())
}

fn product_name(root: &Path) -> String {
    root.parent()
        .and_then(Path::file_name)
        .and_then(OsStr::to_str)
        .unwrap_or("Bambu Studio")
        .to_string()
}

fn measure_paths(paths: &[PathBuf], max_entries: u64) -> (BambuMeasurements, bool, Option<String>) {
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
            let metrics = paths
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
            (metrics, complete, None)
        }
        Err(error) => (
            BTreeMap::new(),
            false,
            Some(format!("measure Bambu logs: {error:#}")),
        ),
    }
}

fn measured_files(files: Vec<UnmeasuredLogFile>, metrics: &BambuMeasurements) -> Vec<BambuLogFile> {
    files
        .into_iter()
        .map(|file| BambuLogFile {
            filesystem: metrics
                .get(&file.path)
                .map(|(filesystem, _)| filesystem.clone())
                .unwrap_or_else(|| "unknown".into()),
            metrics: metrics
                .get(&file.path)
                .map(|(_, metrics)| metrics.clone())
                .unwrap_or_else(|| InventoryMetrics {
                    private_reclaimable_complete: false,
                    ..InventoryMetrics::default()
                }),
            product: file.product,
            path: file.path,
            file_identity: file.file_identity,
            modified_unix: file.modified_unix,
            age_days: file.age_days,
        })
        .collect()
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

fn classify_plan(
    candidates_empty: bool,
    complete: bool,
    active_processes: &[String],
    open_paths: &[PathBuf],
    protections: &[ProtectionMatch],
) -> (BambuLogAction, String) {
    if !complete {
        (
            BambuLogAction::Incomplete,
            "log discovery, APFS measurement, or liveness evidence is incomplete".into(),
        )
    } else if candidates_empty {
        (
            BambuLogAction::NoWork,
            "no recognized Bambu diagnostic logs exceed the retention window".into(),
        )
    } else if !protections.is_empty() {
        (
            BambuLogAction::Protected,
            "one or more expired log files intersect an active protection".into(),
        )
    } else if !active_processes.is_empty() || !open_paths.is_empty() {
        (
            BambuLogAction::InUse,
            "Bambu Studio or an open log path is active".into(),
        )
    } else {
        (
            BambuLogAction::ReportOnly,
            "expired encrypted diagnostics are measured, owner-isolated, and eligible for explicit digest-bound quarantine".into(),
        )
    }
}

fn active_bambu_processes() -> (Vec<String>, bool) {
    let output = match Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(_) | Err(_) => return (Vec::new(), false),
    };
    select_active_bambu_processes(&output.stdout, std::process::id())
}

fn select_active_bambu_processes(process_list: &[u8], self_pid: u32) -> (Vec<String>, bool) {
    let processes = String::from_utf8_lossy(process_list)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let parent_pid = fields.next()?.parse::<u32>().ok()?;
            let command = fields.collect::<Vec<_>>().join(" ");
            Some((pid, parent_pid, command))
        })
        .collect::<Vec<_>>();
    let mut owner_pids = processes
        .iter()
        .filter(|(pid, _, command)| *pid != self_pid && is_bambu_command(command))
        .map(|(pid, _, _)| *pid)
        .collect::<BTreeSet<_>>();
    loop {
        let descendants = processes
            .iter()
            .filter(|(pid, parent_pid, _)| {
                !owner_pids.contains(pid) && owner_pids.contains(parent_pid)
            })
            .map(|(pid, _, _)| *pid)
            .collect::<Vec<_>>();
        if descendants.is_empty() {
            break;
        }
        owner_pids.extend(descendants);
    }
    let mut owners = processes
        .iter()
        .filter(|(pid, _, _)| owner_pids.contains(pid))
        .map(|(pid, _, command)| owner_process_summary(*pid, command))
        .collect::<Vec<_>>();
    owners.sort();
    owners.dedup();
    let complete = owners.len() <= MAX_ACTIVE_OWNER_PROCESSES;
    owners.truncate(MAX_ACTIVE_OWNER_PROCESSES);
    (owners, complete)
}

fn is_bambu_command(command: &str) -> bool {
    let lowercase = command.to_ascii_lowercase();
    lowercase.contains(".app/contents/macos/bambustudio")
        || lowercase.contains(".app/contents/macos/bambu studio")
        || lowercase.contains(".app/contents/macos/bambusuite")
        || lowercase.contains(".app/contents/macos/bambu suite")
        || command.split_whitespace().any(|word| {
            matches!(
                Path::new(word)
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default(),
                "BambuStudio" | "BambuStudioBeta" | "BambuSuite" | "bambu-studio"
            )
        })
}

fn owner_process_summary(pid: u32, command: &str) -> String {
    let executable = command
        .split_whitespace()
        .find_map(|word| {
            let basename = Path::new(word).file_name()?.to_str()?;
            (basename.contains("Bambu") || basename.contains("bambu")).then_some(basename)
        })
        .unwrap_or("BambuStudio");
    format!("{pid} {executable}")
}

fn open_bambu_paths(roots: &[BambuLogRoot]) -> (Vec<PathBuf>, bool) {
    let candidates = roots
        .iter()
        .filter(|root| root.present)
        .map(|root| root.path.clone())
        .collect::<Vec<_>>();
    let (open, complete) = crate::open_handle_evidence_for_paths(&candidates);
    let mut paths = open.into_iter().collect::<Vec<_>>();
    paths.sort();
    (paths, complete)
}

fn eligibility_digest(
    identity: &BambuIdentity,
    candidates: &[BambuLogFile],
    options: &BambuCollectOptions,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(BAMBU_APPROVAL_CONTRACT);
    hasher.update(BAMBU_MANIFEST_VERSION.to_le_bytes());
    hasher.update(options.retention_days.to_le_bytes());
    hasher.update(options.max_entries.to_le_bytes());
    hasher.update(MAX_LOG_FILES.to_le_bytes());
    hasher.update([u8::from(identity.owner_declared_default_roots)]);
    for root in &identity.log_roots {
        hasher.update(root.product.as_bytes());
        hasher.update([0]);
        hasher.update(root.path.as_os_str().as_encoded_bytes());
        hasher.update([u8::from(root.present)]);
    }
    for candidate in candidates {
        hasher.update(candidate.product.as_bytes());
        hasher.update([0]);
        hasher.update(candidate.path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(candidate.file_identity.as_bytes());
        hasher.update([0]);
        hasher.update(candidate.filesystem.as_bytes());
        hasher.update([0]);
        hasher.update(candidate.modified_unix.to_le_bytes());
        hasher.update(candidate.metrics.logical_bytes.to_le_bytes());
        hasher.update(candidate.metrics.allocated_bytes.to_le_bytes());
        hasher.update(candidate.metrics.private_reclaimable_bytes.to_le_bytes());
        hasher.update([u8::from(candidate.metrics.private_reclaimable_complete)]);
        hasher.update(candidate.metrics.files.to_le_bytes());
        hasher.update(candidate.metrics.directories.to_le_bytes());
        hasher.update(candidate.metrics.hardlink_duplicates.to_le_bytes());
        hasher.update(candidate.metrics.errors.to_le_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "device:{}:inode:{}:len:{}:mtime:{}:{}:ctime:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec()
    )
}

#[cfg(not(unix))]
fn file_identity(metadata: &fs::Metadata) -> String {
    format!(
        "len:{}:modified:{}:created:{}",
        metadata.len(),
        metadata.modified().map(unix_nanos).unwrap_or_default(),
        metadata.created().map(unix_nanos).unwrap_or_default()
    )
}

#[derive(Debug)]
struct QuarantinedBambuLog {
    original: PathBuf,
    quarantined: PathBuf,
    expected_quarantine_identity: String,
}

fn execute_bambu_plan(
    roots: &[PathBuf],
    options: &BambuCollectOptions,
    manifest: &mut BambuCollectManifest,
) -> Result<()> {
    anyhow::ensure!(
        manifest.plan.action == BambuLogAction::ReportOnly,
        "Bambu log plan is not executable: {}",
        manifest.plan.reason
    );
    let lock = acquire_collector_lock()?;
    let candidate_paths = manifest
        .plan
        .candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    let guarded = with_protection_guard_for_paths(&candidate_paths, SystemTime::now(), || {
        execute_bambu_plan_guarded(roots, options, manifest)
    })?;
    drop(lock);
    match guarded {
        ProtectionGuardOutcome::Protected(protection) => bail!(
            "Bambu log candidate became protected by lease {} ({})",
            protection.id,
            protection.reason
        ),
        ProtectionGuardOutcome::Executed(outcome) => manifest.outcome = Some(outcome?),
    }
    let outcome = manifest
        .outcome
        .as_ref()
        .context("executed Bambu prune did not record an outcome")?;
    anyhow::ensure!(
        outcome.error.is_none()
            && outcome.verification_complete
            && outcome.remaining_original_paths.is_empty()
            && outcome.remaining_quarantine_paths.is_empty(),
        "Bambu quarantine cleanup did not prove every approved file absent: {}",
        outcome
            .error
            .as_deref()
            .unwrap_or("approved or quarantine paths remain")
    );
    Ok(())
}

fn execute_bambu_plan_guarded(
    roots: &[PathBuf],
    options: &BambuCollectOptions,
    manifest: &BambuCollectManifest,
) -> Result<BambuPruneOutcome> {
    let mut refreshed_options = options.clone();
    refreshed_options.execute = false;
    refreshed_options.approved_digest = None;
    refreshed_options.now = SystemTime::now();
    let (identity, refreshed) = plan_bambu(roots, true, &refreshed_options, &[]);
    anyhow::ensure!(
        identity == manifest.bambu,
        "Bambu log roots changed after planning; rerun without --execute"
    );
    anyhow::ensure!(
        refreshed.action == BambuLogAction::ReportOnly
            && refreshed.complete
            && refreshed.eligibility_digest == manifest.plan.eligibility_digest
            && refreshed
                .candidates
                .iter()
                .map(|candidate| &candidate.path)
                .eq(manifest
                    .plan
                    .candidates
                    .iter()
                    .map(|candidate| &candidate.path)),
        "Bambu log eligibility changed after planning; rerun without --execute"
    );
    let filesystems = refreshed
        .candidates
        .iter()
        .map(|candidate| candidate.filesystem.as_str())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        filesystems.len() == 1 && !filesystems.contains("unknown"),
        "Bambu execution currently requires all approved files on one known filesystem"
    );
    let observation_path = refreshed
        .candidates
        .first()
        .and_then(|candidate| candidate.path.parent())
        .context("Bambu execution has no candidate parent for free-space observation")?;
    let available_bytes_before = fs4::available_space(observation_path)?;
    let quarantine_paths =
        quarantine_paths(&manifest.bambu, &refreshed.candidates, &manifest.run_id)?;
    let mut moved = Vec::new();
    let move_result = (|| -> Result<()> {
        for quarantine in quarantine_paths.values() {
            create_private_directory(quarantine)
                .with_context(|| format!("create Bambu quarantine {}", quarantine.display()))?;
        }
        for candidate in &refreshed.candidates {
            let root = candidate
                .path
                .parent()
                .context("Bambu candidate has no log-root parent")?;
            let quarantine = quarantine_paths.get(root).with_context(|| {
                format!(
                    "Bambu candidate escaped the owner-declared log roots: {}",
                    candidate.path.display()
                )
            })?;
            let file_name = candidate
                .path
                .file_name()
                .context("Bambu candidate has no file name")?;
            anyhow::ensure!(
                is_owned_log_name(file_name),
                "Bambu candidate name is outside the closed owner contract: {}",
                candidate.path.display()
            );
            let metadata = fs::symlink_metadata(&candidate.path)?;
            anyhow::ensure!(
                metadata.is_file() && !metadata.file_type().is_symlink(),
                "Bambu candidate is no longer a regular non-symlink file: {}",
                candidate.path.display()
            );
            anyhow::ensure!(
                file_identity(&metadata) == candidate.file_identity
                    && metadata.modified().map(unix_seconds).ok() == Some(candidate.modified_unix),
                "Bambu candidate identity or activity changed immediately before quarantine: {}",
                candidate.path.display()
            );
            let expected_quarantine_identity = quarantine_file_identity(&metadata);
            let destination = quarantine.join(file_name);
            ensure_path_absent(&destination, "Bambu quarantine destination")?;
            fs::rename(&candidate.path, &destination).with_context(|| {
                format!(
                    "quarantine Bambu log {} as {}",
                    candidate.path.display(),
                    destination.display()
                )
            })?;
            moved.push(QuarantinedBambuLog {
                original: candidate.path.clone(),
                quarantined: destination,
                // Renaming may update ctime, so the post-rename identity keeps
                // only fields that are stable across a same-filesystem rename.
                expected_quarantine_identity,
            });
        }
        Ok(())
    })();
    if let Err(error) = move_result {
        rollback_bambu_quarantine(&moved, quarantine_paths.values())
            .context("rollback Bambu quarantine after a move failure")?;
        return Err(error);
    }

    let (owners, owner_check_complete) = active_bambu_processes();
    let quarantine_roots = quarantine_paths
        .values()
        .map(|path| BambuLogRoot {
            product: "worktree-gc quarantine".into(),
            path: path.clone(),
            present: true,
        })
        .collect::<Vec<_>>();
    let (open_paths, open_check_complete) = open_bambu_paths(&quarantine_roots);
    if !owner_check_complete || !open_check_complete || !owners.is_empty() || !open_paths.is_empty()
    {
        rollback_bambu_quarantine(&moved, quarantine_paths.values())
            .context("rollback Bambu quarantine after execution-time ownership changed")?;
        bail!("Bambu ownership changed after quarantine; approved files were restored");
    }
    for entry in &moved {
        ensure_quarantined_identity(entry).with_context(|| {
            format!(
                "Bambu quarantined file changed after rename; retained for review at {}",
                entry.quarantined.display()
            )
        })?;
    }

    let mut deletion_error = None;
    let mut deleted_paths = Vec::new();
    for entry in &moved {
        if let Err(error) = ensure_quarantined_identity(entry) {
            deletion_error = Some(format!(
                "revalidate quarantined Bambu log {}: {error:#}",
                entry.quarantined.display()
            ));
            break;
        }
        match fs::remove_file(&entry.quarantined) {
            Ok(()) => deleted_paths.push(entry.original.clone()),
            Err(error) => {
                deletion_error = Some(format!(
                    "remove quarantined Bambu log {}: {error}",
                    entry.quarantined.display()
                ));
                break;
            }
        }
    }
    if deletion_error.is_none() {
        for quarantine in quarantine_paths.values() {
            if let Err(error) = fs::remove_dir(quarantine) {
                deletion_error = Some(format!(
                    "remove empty Bambu quarantine {}: {error}",
                    quarantine.display()
                ));
                break;
            }
        }
    }
    let mut remaining_original_paths = Vec::new();
    for entry in &moved {
        if path_exists_no_follow(&entry.original)? {
            remaining_original_paths.push(entry.original.clone());
        }
    }
    let mut remaining_quarantine_paths = Vec::new();
    for path in quarantine_paths.values() {
        if path_exists_no_follow(path)? {
            remaining_quarantine_paths.push(path.clone());
        }
    }
    let available_bytes_after = fs4::available_space(observation_path)?;
    Ok(BambuPruneOutcome {
        candidates_deleted: deleted_paths.len(),
        deleted_paths,
        quarantine_paths: quarantine_paths.into_values().collect(),
        verification_complete: true,
        error: deletion_error,
        remaining_original_paths,
        remaining_quarantine_paths,
        available_bytes_before,
        available_bytes_after,
        realized_reclaim_bytes: available_bytes_after.saturating_sub(available_bytes_before),
    })
}

fn quarantine_paths(
    identity: &BambuIdentity,
    candidates: &[BambuLogFile],
    run_id: &str,
) -> Result<BTreeMap<PathBuf, PathBuf>> {
    let owner_roots = identity
        .log_roots
        .iter()
        .filter(|root| root.present)
        .map(|root| root.path.as_path())
        .collect::<BTreeSet<_>>();
    let mut paths = BTreeMap::new();
    for root in candidates
        .iter()
        .filter_map(|candidate| candidate.path.parent())
    {
        anyhow::ensure!(
            owner_roots.contains(root),
            "Bambu candidate parent is outside an owner-declared log root: {}",
            root.display()
        );
        let quarantine = root.join(format!(".worktree-gc-trash-{run_id}"));
        ensure_path_absent(&quarantine, "Bambu quarantine")?;
        paths.insert(root.to_path_buf(), quarantine);
    }
    Ok(paths)
}

fn rollback_bambu_quarantine<'a>(
    moved: &[QuarantinedBambuLog],
    quarantine_paths: impl Iterator<Item = &'a PathBuf>,
) -> Result<()> {
    for entry in moved.iter().rev() {
        if !path_exists_no_follow(&entry.quarantined)? {
            continue;
        }
        ensure_quarantined_identity(entry).with_context(|| {
            format!(
                "cannot restore {}; quarantine identity changed at {}",
                entry.original.display(),
                entry.quarantined.display()
            )
        })?;
        ensure_path_absent(&entry.original, "Bambu rollback destination").with_context(|| {
            format!(
                "cannot restore {}; quarantine retained at {}",
                entry.original.display(),
                entry.quarantined.display()
            )
        })?;
        fs::rename(&entry.quarantined, &entry.original).with_context(|| {
            format!(
                "restore Bambu log {} from {}",
                entry.original.display(),
                entry.quarantined.display()
            )
        })?;
    }
    for quarantine in quarantine_paths {
        if path_exists_no_follow(quarantine)? {
            fs::remove_dir(quarantine).with_context(|| {
                format!("remove empty Bambu quarantine {}", quarantine.display())
            })?;
        }
    }
    Ok(())
}

fn ensure_quarantined_identity(entry: &QuarantinedBambuLog) -> Result<()> {
    let metadata = fs::symlink_metadata(&entry.quarantined).with_context(|| {
        format!(
            "inspect quarantined Bambu log {}",
            entry.quarantined.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && quarantine_file_identity(&metadata) == entry.expected_quarantine_identity,
        "quarantined path no longer names the approved regular file"
    );
    Ok(())
}

#[cfg(unix)]
fn quarantine_file_identity(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "device:{}:inode:{}:len:{}:mtime:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec()
    )
}

#[cfg(not(unix))]
fn quarantine_file_identity(metadata: &fs::Metadata) -> String {
    format!(
        "len:{}:modified:{}",
        metadata.len(),
        metadata.modified().map(unix_nanos).unwrap_or_default()
    )
}

fn ensure_path_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("{label} already exists: {}", path.display()),
        Err(error) => Err(error).with_context(|| format!("inspect {label} {}", path.display())),
    }
}

fn path_exists_no_follow(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect path {}", path.display())),
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn acquire_collector_lock() -> Result<File> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("bambu-logs.lock"))?;
    FileExt::lock(&lock).context("lock Bambu collector")?;
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

fn write_manifest(manifest: &BambuCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!("{}-bambu-logs-{mode}.json", manifest.run_id));
    write_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_manifest_at(path: &Path, manifest: &BambuCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic Bambu manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Bambu manifest {}", path.display()))?;
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn symlinked_product_directory_cannot_redirect_a_log_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external_product = temp.path().join("external-product");
        let support = temp.path().join("Application Support");
        let linked_product = support.join("BambuStudio");
        fs::create_dir_all(external_product.join("log")).unwrap();
        fs::create_dir(&support).unwrap();
        symlink(&external_product, &linked_product).unwrap();
        fs::write(
            external_product.join("log/studio_fixture_enc.log.0"),
            b"diagnostic",
        )
        .unwrap();

        let snapshot = snapshot_logs(
            &[linked_product.join("log")],
            false,
            &BambuCollectOptions::default(),
        );

        assert!(!snapshot.complete);
        assert!(snapshot.candidates.is_empty());
        assert!(snapshot.retained.is_empty());
        assert!(snapshot
            .root_errors
            .iter()
            .any(|error| error.contains("product directory is not a regular non-symlink")));
        assert!(external_product
            .join("log/studio_fixture_enc.log.0")
            .is_file());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_ancestor_cannot_redirect_a_default_looking_log_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external_support = temp.path().join("external-support");
        let linked_support = temp.path().join("Library/Application Support");
        let root = linked_support.join("BambuStudio/log");
        fs::create_dir_all(external_support.join("BambuStudio/log")).unwrap();
        fs::create_dir_all(linked_support.parent().unwrap()).unwrap();
        symlink(&external_support, &linked_support).unwrap();
        let external_log = external_support.join("BambuStudio/log/studio_old_enc.log.0");
        fs::write(&external_log, b"diagnostic").unwrap();

        let snapshot = snapshot_logs(&[root], true, &BambuCollectOptions::default());

        assert!(!snapshot.complete);
        assert!(snapshot.candidates.is_empty());
        assert!(snapshot
            .root_errors
            .iter()
            .any(|error| error.contains("contains a symlink component")));
        assert!(external_log.is_file());
    }
    use filetime::{set_file_mtime, FileTime};
    use tempfile::TempDir;

    #[test]
    fn owned_log_names_are_narrow() {
        assert!(is_owned_log_name(OsStr::new("studio_Mon_enc.log.0")));
        assert!(is_owned_log_name(OsStr::new("studio_Mon_enc_dc.log.9")));
        assert!(is_owned_log_name(OsStr::new("debug_network_Mon.log.enc")));
        assert!(is_owned_log_name(OsStr::new("log_iotc.txt")));
        assert!(!is_owned_log_name(OsStr::new("presets.json")));
        assert!(!is_owned_log_name(OsStr::new("studio_notes.txt")));
        assert!(!is_owned_log_name(OsStr::new("studio_notes.log.keep")));
        assert!(!is_owned_log_name(OsStr::new("studio_Mon_enc.log.")));
        assert!(!is_owned_log_name(OsStr::new("debug_network_.log.enc")));
    }

    #[cfg(unix)]
    #[test]
    fn owned_log_names_reject_non_utf8_lookalikes() {
        use std::os::unix::ffi::OsStrExt;

        assert!(!is_owned_log_name(OsStr::from_bytes(b"studio_\xff.log.0")));
    }

    #[test]
    fn snapshot_separates_expired_recent_and_unknown_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("BambuStudio/log");
        fs::create_dir_all(&root).unwrap();
        let expired = root.join("studio_old_enc.log.0");
        let recent = root.join("debug_network_new.log.enc");
        let unknown = root.join("account.json");
        fs::write(&expired, b"old").unwrap();
        fs::write(&recent, b"new").unwrap();
        fs::write(&unknown, b"durable").unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(100 * 24 * 60 * 60);
        set_file_mtime(
            &expired,
            FileTime::from_system_time(now - Duration::from_secs(30 * 24 * 60 * 60)),
        )
        .unwrap();

        let snapshot = snapshot_logs(
            &[root],
            false,
            &BambuCollectOptions {
                retention_days: 14,
                now,
                ..BambuCollectOptions::default()
            },
        );

        assert!(snapshot.complete);
        assert_eq!(snapshot.candidates.len(), 1);
        assert_eq!(snapshot.candidates[0].path, expired);
        assert_eq!(snapshot.retained.len(), 1);
        assert_eq!(snapshot.retained[0].path, recent);
        assert_eq!(snapshot.unknown_entries, [unknown]);
    }

    #[test]
    fn interrupted_tool_quarantine_fails_the_next_plan_closed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("BambuStudio/log");
        let quarantine = root.join(".worktree-gc-trash-interrupted");
        fs::create_dir_all(&quarantine).unwrap();
        fs::write(quarantine.join("studio_old_enc.log.0"), b"retained").unwrap();

        let snapshot = snapshot_logs(
            &[root],
            false,
            &BambuCollectOptions {
                now: UNIX_EPOCH + Duration::from_secs(100 * 24 * 60 * 60),
                ..BambuCollectOptions::default()
            },
        );

        assert!(!snapshot.complete);
        assert_eq!(snapshot.unknown_entries, std::slice::from_ref(&quarantine));
        assert!(snapshot
            .root_errors
            .iter()
            .any(|error| error.contains("explicit recovery review")));
        assert!(quarantine.exists());
    }

    #[test]
    fn process_matching_includes_descendants_and_redacts_arguments() {
        let processes = b"10 1 /Applications/BambuStudio.app/Contents/MacOS/BambuStudio --token secret\n11 10 helper --private value\n12 1 unrelated\n";

        let (owners, complete) = select_active_bambu_processes(processes, 999);

        assert!(complete);
        assert_eq!(owners, ["10 BambuStudio", "11 BambuStudio"]);
        assert!(owners.iter().all(|owner| !owner.contains("secret")));
    }

    #[test]
    fn process_cap_marks_truncated_evidence_incomplete() {
        let processes = (1..=MAX_ACTIVE_OWNER_PROCESSES + 1)
            .map(|pid| {
                format!("{pid} 0 /Applications/BambuStudio.app/Contents/MacOS/BambuStudio\n")
            })
            .collect::<String>();

        let (owners, complete) = select_active_bambu_processes(processes.as_bytes(), 9999);

        assert_eq!(owners.len(), MAX_ACTIVE_OWNER_PROCESSES);
        assert!(!complete);
    }

    #[test]
    fn incomplete_evidence_does_not_become_no_work() {
        let (action, _) = classify_plan(true, false, &[], &[], &[]);

        assert_eq!(action, BambuLogAction::Incomplete);
    }

    #[test]
    fn approval_digest_binds_scan_policy_and_candidate_evidence() {
        let identity = BambuIdentity {
            owner_declared_default_roots: true,
            log_roots: vec![BambuLogRoot {
                product: "stable".into(),
                path: PathBuf::from("/logs"),
                present: true,
            }],
        };
        let candidate = BambuLogFile {
            product: "stable".into(),
            path: PathBuf::from("/logs/studio_old_enc.log.0"),
            file_identity: "identity".into(),
            filesystem: "device:1".into(),
            modified_unix: 1,
            age_days: 30,
            metrics: InventoryMetrics {
                logical_bytes: 10,
                allocated_bytes: 20,
                private_reclaimable_bytes: 20,
                private_reclaimable_complete: true,
                files: 1,
                ..InventoryMetrics::default()
            },
        };
        let options = BambuCollectOptions {
            retention_days: 14,
            max_entries: 100,
            ..BambuCollectOptions::default()
        };
        let first = eligibility_digest(&identity, std::slice::from_ref(&candidate), &options);
        let repeated = eligibility_digest(&identity, std::slice::from_ref(&candidate), &options);
        let changed_policy = eligibility_digest(
            &identity,
            std::slice::from_ref(&candidate),
            &BambuCollectOptions {
                max_entries: 101,
                ..options.clone()
            },
        );
        let mut changed_candidate = candidate;
        changed_candidate.metrics.private_reclaimable_bytes = 19;
        let changed_evidence = eligibility_digest(&identity, &[changed_candidate], &options);

        assert_eq!(first, repeated);
        assert_ne!(first, changed_policy);
        assert_ne!(first, changed_evidence);
    }

    #[test]
    fn quarantine_mapping_includes_only_roots_with_approved_candidates() {
        let temp = TempDir::new().unwrap();
        let stable = temp.path().join("stable");
        let beta = temp.path().join("beta");
        fs::create_dir(&stable).unwrap();
        fs::create_dir(&beta).unwrap();
        let candidate = BambuLogFile {
            product: "stable".into(),
            path: stable.join("studio_old_enc.log.0"),
            file_identity: "device:1:inode:2".into(),
            filesystem: "device:1".into(),
            modified_unix: 1,
            age_days: 30,
            metrics: InventoryMetrics::default(),
        };
        let identity = BambuIdentity {
            owner_declared_default_roots: true,
            log_roots: vec![
                BambuLogRoot {
                    product: "stable".into(),
                    path: stable.clone(),
                    present: true,
                },
                BambuLogRoot {
                    product: "beta".into(),
                    path: beta,
                    present: true,
                },
            ],
        };

        let paths = quarantine_paths(&identity, &[candidate], "run").unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths.get(&stable),
            Some(&stable.join(".worktree-gc-trash-run"))
        );
    }

    #[test]
    fn rollback_restores_quarantined_logs_and_removes_empty_directory() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("log");
        let quarantine = root.join(".worktree-gc-trash-run");
        let original = root.join("studio_old_enc.log.0");
        let quarantined = quarantine.join("studio_old_enc.log.0");
        fs::create_dir_all(&quarantine).unwrap();
        fs::write(&original, b"diagnostic").unwrap();
        let expected_quarantine_identity =
            quarantine_file_identity(&fs::symlink_metadata(&original).unwrap());
        fs::rename(&original, &quarantined).unwrap();
        let moved = [QuarantinedBambuLog {
            original: original.clone(),
            quarantined,
            expected_quarantine_identity,
        }];

        rollback_bambu_quarantine(&moved, std::iter::once(&quarantine)).unwrap();

        assert_eq!(fs::read(original).unwrap(), b"diagnostic");
        assert!(!quarantine.exists());
    }

    #[test]
    fn rollback_retains_a_quarantine_whose_identity_changed() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("log");
        let quarantine = root.join(".worktree-gc-trash-run");
        let original = root.join("studio_old_enc.log.0");
        let quarantined = quarantine.join("studio_old_enc.log.0");
        fs::create_dir_all(&quarantine).unwrap();
        fs::write(&quarantined, b"replacement").unwrap();
        let moved = [QuarantinedBambuLog {
            original: original.clone(),
            quarantined: quarantined.clone(),
            expected_quarantine_identity: "different identity".into(),
        }];

        let error = rollback_bambu_quarantine(&moved, std::iter::once(&quarantine)).unwrap_err();

        assert!(error.to_string().contains("quarantine identity changed"));
        assert!(!original.exists());
        assert_eq!(fs::read(quarantined).unwrap(), b"replacement");
    }

    #[test]
    fn approval_digest_requires_prefixed_sha256_hex() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_sha256_digest(&"a".repeat(64)));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "g".repeat(64))));
    }
}
