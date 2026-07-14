use crate::inventory::{self, EntryKind, InventoryMetrics, InventoryOptions};
use crate::protection::{
    active_protections, protection_for_path, with_protection_guard_for_paths,
    ProtectionGuardOutcome, ProtectionMatch,
};
use crate::{format_bytes, CleanupMode};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PNPM_MANIFEST_VERSION: u64 = 4;
const SUPPORTED_PNPM_PLANNER_VERSION: &str = "10.32.1";
const MINUTES_PER_DAY: u64 = 24 * 60;
const DEFAULT_PNPM_SCAN_THREADS: usize = 1;
const MAX_PNPM_SCAN_THREADS: usize = 64;
const PNPM_EVIDENCE_CACHE_VERSION: u64 = 1;
const PNPM_EVIDENCE_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub struct PnpmCollectOptions {
    pub execute: bool,
    pub fresh: bool,
    pub approved_digest: Option<String>,
    pub dlx_days: u64,
    pub max_entries: u64,
    pub scan_threads: usize,
    pub now: SystemTime,
}

impl Default for PnpmCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            fresh: false,
            approved_digest: None,
            dlx_days: 7,
            max_entries: 2_000_000,
            scan_threads: DEFAULT_PNPM_SCAN_THREADS,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PnpmCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: PnpmCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct PnpmCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub pnpm: PnpmIdentity,
    pub policy: PnpmPolicy,
    pub plan: PnpmPrunePlan,
    pub outcome: Option<PnpmPruneOutcome>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PnpmIdentity {
    pub executable: PathBuf,
    pub canonical_executable: PathBuf,
    pub version: String,
    pub store_path: PathBuf,
    pub cache_path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct PnpmPolicy {
    pub dlx_days: u64,
    pub max_entries: u64,
    pub scan_threads: usize,
    pub fresh_evidence_requested: bool,
    pub delegated_command: Vec<String>,
    pub planner_semantics: String,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PnpmPruneAction {
    Delegate,
    NoWork,
    ReportOnly,
    Protected,
    InUse,
    UnsupportedVersion,
    UnsupportedLayout,
}

#[derive(Debug, Clone, Serialize)]
pub struct PnpmPrunePlan {
    pub action: PnpmPruneAction,
    pub reason: String,
    pub complete: bool,
    pub visited_entries: u64,
    pub eligibility_digest: String,
    pub approval_digest: String,
    pub content_evidence: PnpmContentEvidence,
    pub planner_supported: bool,
    pub unreferenced_content_files: u64,
    pub alien_content_directories: u64,
    pub unmanaged_content_entries: u64,
    pub unsupported_content_entries: u64,
    pub metadata_directories: Vec<PathBuf>,
    pub store_tmp: Option<PathBuf>,
    pub expired_dlx_entries: Vec<PathBuf>,
    pub orphan_dlx_entries: Vec<PathBuf>,
    pub stale_dlx_children: Vec<PathBuf>,
    pub unsupported_dlx_entries: Vec<PathBuf>,
    pub package_index_cleanup_delegated: bool,
    pub global_virtual_store_present: bool,
    pub unsupported_layout_paths: Vec<PathBuf>,
    pub filesystems: Vec<PnpmFilesystemObservation>,
    pub store_expected_reclaim: InventoryMetrics,
    pub cache_expected_reclaim: InventoryMetrics,
    pub expected_reclaim: InventoryMetrics,
    pub protection: Option<ProtectionMatch>,
    pub open_handle_check_complete: bool,
    pub open_paths: Vec<PathBuf>,
    pub active_owner_processes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PnpmContentEvidence {
    pub cache_path: Option<PathBuf>,
    pub prefix_index_complete: bool,
    pub total_prefixes: u64,
    pub covered_prefixes: u64,
    pub cached_prefixes: u64,
    pub freshly_scanned_prefixes: u64,
    pub pending_prefixes: u64,
    pub coverage_complete: bool,
    pub point_in_time_complete: bool,
    pub oldest_observation_unix: Option<u64>,
    pub newest_observation_unix: Option<u64>,
    pub max_cache_age_seconds: u64,
    pub semantics: String,
}

#[derive(Debug, Serialize)]
pub struct PnpmPruneOutcome {
    pub command_succeeded: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub filesystems: Vec<PnpmFilesystemReclaim>,
    pub realized_reclaim_bytes: u64,
    pub verification_complete: bool,
    pub verification_error: Option<String>,
    pub remaining_unreferenced_content_files: Option<u64>,
    pub remaining_metadata_directories: Option<u64>,
    pub store_tmp_remaining: Option<bool>,
    pub remaining_dlx_cleanup_entries: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct PnpmFilesystemReclaim {
    pub filesystem: String,
    pub observed_at: PathBuf,
    pub available_bytes_before: u64,
    pub available_bytes_after: u64,
    pub realized_reclaim_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PnpmFilesystemObservation {
    pub filesystem: String,
    pub observed_at: PathBuf,
    pub available_bytes: u64,
}

#[derive(Debug)]
struct PnpmContext {
    identity: PnpmIdentity,
}

pub fn collect_pnpm(options: PnpmCollectOptions) -> Result<PnpmCollectRun> {
    anyhow::ensure!(
        options.dlx_days > 0,
        "pnpm dlx TTL must be at least one day"
    );
    anyhow::ensure!(
        options.max_entries > 0,
        "pnpm scan budget must be at least one entry"
    );
    anyhow::ensure!(
        (1..=MAX_PNPM_SCAN_THREADS).contains(&options.scan_threads),
        "pnpm scan threads must be between 1 and {MAX_PNPM_SCAN_THREADS}"
    );
    anyhow::ensure!(
        options.execute || options.approved_digest.is_none(),
        "--approved-digest is only valid with --execute"
    );
    if options.execute {
        let approved = options
            .approved_digest
            .as_deref()
            .context("pnpm execution requires --approved-digest from a fresh dry-run")?;
        anyhow::ensure!(
            valid_sha256_digest(approved),
            "--approved-digest must be a sha256: digest"
        );
    }

    let context = discover_pnpm()?;
    let mode = if options.execute {
        CleanupMode::Execute
    } else {
        CleanupMode::DryRun
    };
    let generated_at_unix = unix_seconds(options.now);
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let mut manifest = PnpmCollectManifest {
        manifest_version: PNPM_MANIFEST_VERSION,
        collector: "pnpm-store",
        run_id,
        mode,
        generated_at_unix,
        pnpm: context.identity.clone(),
        policy: PnpmPolicy {
            dlx_days: options.dlx_days,
            max_entries: options.max_entries,
            scan_threads: options.scan_threads,
            fresh_evidence_requested: options.fresh || options.execute,
            delegated_command: delegated_command(options.dlx_days),
            planner_semantics: format!(
                "advisory mirror of pnpm {SUPPORTED_PNPM_PLANNER_VERSION} store-prune semantics"
            ),
            unattended_execution_supported: false,
        },
        plan: plan_pnpm(&context.identity, &options)?,
        outcome: None,
    };
    let manifest_path = write_pnpm_manifest(&manifest)?;
    if let Some(approved) = options.approved_digest.as_deref() {
        anyhow::ensure!(
            approved == manifest.plan.approval_digest,
            "approved pnpm plan {} does not match current plan {}; review the fresh execution-attempt manifest {} before trying again",
            approved,
            manifest.plan.approval_digest,
            manifest_path.display()
        );
    }

    if options.execute {
        let execution = execute_pnpm_plan(&context, &options, &mut manifest);
        write_pnpm_manifest_at(&manifest_path, &manifest)?;
        execution.with_context(|| {
            format!(
                "pnpm collector execution failed; inspect manifest {}",
                manifest_path.display()
            )
        })?;
    }

    Ok(PnpmCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_pnpm_collect(run: &PnpmCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: pnpm-store");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "pnpm: {} ({})",
        run.manifest.pnpm.version,
        run.manifest.pnpm.executable.display()
    );
    println!("store: {}", run.manifest.pnpm.store_path.display());
    println!("cache: {}", run.manifest.pnpm.cache_path.display());
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!("approval digest: {}", plan.approval_digest);
    println!(
        "planner: {}{}",
        run.manifest.policy.planner_semantics,
        if plan.planner_supported {
            ""
        } else {
            " (installed version unsupported)"
        }
    );
    println!("execution: manual only; pnpm remains the deletion authority");
    println!(
        "eligible: {} content files, {} metadata dirs, {} expired dlx, {} orphan dlx, {} stale dlx children",
        plan.unreferenced_content_files,
        plan.metadata_directories.len(),
        plan.expired_dlx_entries.len(),
        plan.orphan_dlx_entries.len(),
        plan.stale_dlx_children.len()
    );
    if !plan.unsupported_dlx_entries.is_empty() {
        println!(
            "unsupported dlx entries: {}",
            plan.unsupported_dlx_entries.len()
        );
    }
    if !plan.unsupported_layout_paths.is_empty() {
        println!(
            "unsupported domain roots: {}",
            plan.unsupported_layout_paths.len()
        );
    }
    println!(
        "measured: {} private{} | {} allocated | {} entries{}",
        format_bytes(plan.expected_reclaim.private_reclaimable_bytes),
        if plan.expected_reclaim.private_reclaimable_complete {
            ""
        } else {
            " (lower bound)"
        },
        format_bytes(plan.expected_reclaim.allocated_bytes),
        plan.visited_entries,
        if plan.complete { "" } else { " | incomplete" }
    );
    println!(
        "content evidence: {}/{} prefixes covered ({} cached, {} fresh, {} pending){}",
        plan.content_evidence.covered_prefixes,
        plan.content_evidence.total_prefixes,
        plan.content_evidence.cached_prefixes,
        plan.content_evidence.freshly_scanned_prefixes,
        plan.content_evidence.pending_prefixes,
        if plan.content_evidence.point_in_time_complete {
            " | current-run complete"
        } else if plan.content_evidence.coverage_complete {
            " | historical coverage; fresh execution proof required"
        } else if !plan.content_evidence.prefix_index_complete {
            " | prefix index incomplete"
        } else {
            ""
        }
    );
    println!(
        "  store: {} private | {} allocated",
        format_bytes(plan.store_expected_reclaim.private_reclaimable_bytes),
        format_bytes(plan.store_expected_reclaim.allocated_bytes)
    );
    println!(
        "  cache: {} private | {} allocated",
        format_bytes(plan.cache_expected_reclaim.private_reclaimable_bytes),
        format_bytes(plan.cache_expected_reclaim.allocated_bytes)
    );
    for filesystem in &plan.filesystems {
        println!(
            "  filesystem {} at {}: {} available",
            filesystem.filesystem,
            filesystem.observed_at.display(),
            format_bytes(filesystem.available_bytes)
        );
    }
    if let Some(outcome) = &run.manifest.outcome {
        println!("realized: {}", format_bytes(outcome.realized_reclaim_bytes));
        for filesystem in &outcome.filesystems {
            println!(
                "  {} at {}: {} -> {}",
                filesystem.filesystem,
                filesystem.observed_at.display(),
                format_bytes(filesystem.available_bytes_before),
                format_bytes(filesystem.available_bytes_after)
            );
        }
    }
}

fn discover_pnpm() -> Result<PnpmContext> {
    let executable = find_executable(OsStr::new("pnpm")).context("pnpm was not found on PATH")?;
    let canonical_executable = executable
        .canonicalize()
        .with_context(|| format!("resolve pnpm executable {}", executable.display()))?;
    let version = command_stdout(&executable, &["--version"])?;
    let store_output = command_stdout(&executable, &["store", "path"])?;
    let store_path = PathBuf::from(store_output)
        .canonicalize()
        .context("resolve the canonical pnpm store path")?;
    let configured_cache = command_stdout(&executable, &["config", "get", "cache-dir"])?;
    let cache_path = if configured_cache.is_empty()
        || matches!(configured_cache.as_str(), "undefined" | "null")
    {
        default_pnpm_cache_dir()?
    } else {
        PathBuf::from(configured_cache)
    };
    let cache_path = canonicalize_existing_or_parent(&cache_path)?;
    Ok(PnpmContext {
        identity: PnpmIdentity {
            executable,
            canonical_executable,
            version,
            store_path,
            cache_path,
        },
    })
}

fn plan_pnpm(identity: &PnpmIdentity, options: &PnpmCollectOptions) -> Result<PnpmPrunePlan> {
    let protections = active_protections(options.now)?;
    let protection = protection_for_path(&identity.store_path, &protections)
        .or_else(|| protection_for_path(&identity.cache_path, &protections));
    let mut plan = plan_pnpm_without_protection(identity, options)?;
    plan.protection = protection;
    plan.action = classify_plan(&plan);
    plan.reason = plan_reason(&plan);
    Ok(plan)
}

fn plan_pnpm_without_protection(
    identity: &PnpmIdentity,
    options: &PnpmCollectOptions,
) -> Result<PnpmPrunePlan> {
    let mut plan = snapshot_pnpm(identity, options)?;
    plan.active_owner_processes = active_pnpm_owner_processes(identity)?;
    let (mut open_paths, process_open_handle_check_complete) =
        open_pnpm_paths(identity, &plan.active_owner_processes);
    let (cwd_paths, cwd_check_complete) = pnpm_cwd_paths(identity);
    open_paths.extend(cwd_paths);
    open_paths.sort();
    open_paths.dedup();
    plan.open_paths = open_paths;
    plan.open_handle_check_complete = process_open_handle_check_complete && cwd_check_complete;
    plan.action = classify_plan(&plan);
    plan.reason = plan_reason(&plan);
    Ok(plan)
}

fn snapshot_pnpm(identity: &PnpmIdentity, options: &PnpmCollectOptions) -> Result<PnpmPrunePlan> {
    let store_files = identity.store_path.join("files");
    let store_index = identity.store_path.join("index");
    let dlx_root = identity.cache_path.join("dlx");
    let mut unsupported_layout_paths = [&store_files, &store_index, &dlx_root]
        .into_iter()
        .map(|path| Ok((path, unsupported_control_root(path)?)))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|(_, unsupported)| *unsupported)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    unsupported_layout_paths.sort();
    let mut remaining = options.max_entries;
    let evidence_cache_path = if options.execute || options.fresh {
        None
    } else {
        Some(pnpm_evidence_cache_path(identity)?)
    };
    let content = if unsupported_layout_paths.contains(&store_files) {
        empty_content_snapshot()
    } else {
        snapshot_content(
            &store_files,
            &mut remaining,
            options.scan_threads,
            evidence_cache_path.as_deref(),
            &identity.version,
            unix_seconds(options.now),
        )?
    };
    let metadata_directories = metadata_directories(&identity.cache_path)?;
    let store_tmp_path = identity.store_path.join("tmp");
    let store_tmp = match fs::symlink_metadata(&store_tmp_path) {
        Ok(_) => Some(store_tmp_path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspect pnpm temporary store entry {}",
                    store_tmp_path.display()
                )
            })
        }
    };
    let dlx = if unsupported_layout_paths.contains(&dlx_root) {
        DlxCandidates::default()
    } else {
        dlx_candidates(&identity.cache_path, options.dlx_days, options.now)?
    };
    let global_virtual_store_present = identity.store_path.join("links").exists();

    let mut cache_side_effect_paths = metadata_directories.clone();
    cache_side_effect_paths.extend(dlx.expired_entries.iter().cloned());
    cache_side_effect_paths.extend(dlx.orphan_entries.iter().cloned());
    cache_side_effect_paths.extend(dlx.stale_children.iter().cloned());
    cache_side_effect_paths.sort();
    cache_side_effect_paths.dedup();
    let mut store_side_effect_paths = Vec::new();
    if let Some(path) = &store_tmp {
        store_side_effect_paths.push(path.clone());
    }

    let store_side_effect_metrics = measure_paths(&store_side_effect_paths, &mut remaining)?;
    let cache_expected_reclaim = measure_paths(&cache_side_effect_paths, &mut remaining)?;
    let mut store_expected_reclaim = content.metrics;
    add_metrics(&mut store_expected_reclaim, &store_side_effect_metrics);
    let mut expected_reclaim = store_expected_reclaim.clone();
    add_metrics(&mut expected_reclaim, &cache_expected_reclaim);
    let complete = content.complete && remaining > 0 && expected_reclaim.errors == 0;
    let filesystems = observe_filesystems(identity)?;

    let mut plan = PnpmPrunePlan {
        action: PnpmPruneAction::ReportOnly,
        reason: String::new(),
        complete,
        visited_entries: options.max_entries.saturating_sub(remaining),
        eligibility_digest: content.digest,
        approval_digest: String::new(),
        content_evidence: content.evidence,
        planner_supported: identity.version == SUPPORTED_PNPM_PLANNER_VERSION,
        unreferenced_content_files: content.files,
        alien_content_directories: content.alien_directories,
        unmanaged_content_entries: content.unmanaged_entries,
        unsupported_content_entries: content.unsupported_entries,
        metadata_directories,
        store_tmp,
        expired_dlx_entries: dlx.expired_entries,
        orphan_dlx_entries: dlx.orphan_entries,
        stale_dlx_children: dlx.stale_children,
        unsupported_dlx_entries: dlx.unsupported_entries,
        package_index_cleanup_delegated: true,
        global_virtual_store_present,
        unsupported_layout_paths,
        filesystems,
        store_expected_reclaim,
        cache_expected_reclaim,
        expected_reclaim,
        protection: None,
        open_handle_check_complete: false,
        open_paths: Vec::new(),
        active_owner_processes: Vec::new(),
    };
    plan.approval_digest = approval_digest(identity, options, &plan)?;
    Ok(plan)
}

#[derive(Serialize)]
struct PnpmApprovalEvidence<'a> {
    format: &'static str,
    pnpm_version: &'a str,
    canonical_executable: &'a Path,
    store_path: &'a Path,
    cache_path: &'a Path,
    dlx_days: u64,
    reviewed_planner_version: &'static str,
    complete: bool,
    planner_supported: bool,
    eligibility_digest: &'a str,
    unreferenced_content_files: u64,
    alien_content_directories: u64,
    unmanaged_content_entries: u64,
    unsupported_content_entries: u64,
    metadata_directories: &'a [PathBuf],
    store_tmp: &'a Option<PathBuf>,
    expired_dlx_entries: &'a [PathBuf],
    orphan_dlx_entries: &'a [PathBuf],
    stale_dlx_children: &'a [PathBuf],
    unsupported_dlx_entries: &'a [PathBuf],
    package_index_cleanup_delegated: bool,
    global_virtual_store_present: bool,
    unsupported_layout_paths: &'a [PathBuf],
    store_expected_reclaim: &'a InventoryMetrics,
    cache_expected_reclaim: &'a InventoryMetrics,
    expected_reclaim: &'a InventoryMetrics,
    filesystems: Vec<(&'a str, &'a Path)>,
}

fn approval_digest(
    identity: &PnpmIdentity,
    options: &PnpmCollectOptions,
    plan: &PnpmPrunePlan,
) -> Result<String> {
    let evidence = PnpmApprovalEvidence {
        format: "worktree-gc-pnpm-approval-v1",
        pnpm_version: &identity.version,
        canonical_executable: &identity.canonical_executable,
        store_path: &identity.store_path,
        cache_path: &identity.cache_path,
        dlx_days: options.dlx_days,
        reviewed_planner_version: SUPPORTED_PNPM_PLANNER_VERSION,
        complete: plan.complete,
        planner_supported: plan.planner_supported,
        eligibility_digest: &plan.eligibility_digest,
        unreferenced_content_files: plan.unreferenced_content_files,
        alien_content_directories: plan.alien_content_directories,
        unmanaged_content_entries: plan.unmanaged_content_entries,
        unsupported_content_entries: plan.unsupported_content_entries,
        metadata_directories: &plan.metadata_directories,
        store_tmp: &plan.store_tmp,
        expired_dlx_entries: &plan.expired_dlx_entries,
        orphan_dlx_entries: &plan.orphan_dlx_entries,
        stale_dlx_children: &plan.stale_dlx_children,
        unsupported_dlx_entries: &plan.unsupported_dlx_entries,
        package_index_cleanup_delegated: plan.package_index_cleanup_delegated,
        global_virtual_store_present: plan.global_virtual_store_present,
        unsupported_layout_paths: &plan.unsupported_layout_paths,
        store_expected_reclaim: &plan.store_expected_reclaim,
        cache_expected_reclaim: &plan.cache_expected_reclaim,
        expected_reclaim: &plan.expected_reclaim,
        filesystems: plan
            .filesystems
            .iter()
            .map(|filesystem| {
                (
                    filesystem.filesystem.as_str(),
                    filesystem.observed_at.as_path(),
                )
            })
            .collect(),
    };
    let encoded = serde_json::to_vec(&evidence).context("encode pnpm approval evidence")?;
    Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
}

fn valid_sha256_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

#[derive(Debug)]
struct ContentSnapshot {
    complete: bool,
    digest: String,
    files: u64,
    alien_directories: u64,
    unmanaged_entries: u64,
    unsupported_entries: u64,
    metrics: InventoryMetrics,
    evidence: PnpmContentEvidence,
}

#[derive(Debug, Serialize, Deserialize)]
struct PnpmEvidenceCache {
    cache_version: u64,
    store_files: PathBuf,
    pnpm_version: String,
    prefixes: BTreeMap<String, CachedPrefixSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedPrefixSnapshot {
    fingerprint: PrefixFingerprint,
    observed_at_unix: u64,
    digest: String,
    files: u64,
    alien_directories: u64,
    unsupported_entries: u64,
    metrics: CachedInventoryMetrics,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PrefixFingerprint {
    device: Option<u64>,
    inode: Option<u64>,
    modified_seconds: Option<i64>,
    modified_nanoseconds: Option<i64>,
    changed_seconds: Option<i64>,
    changed_nanoseconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInventoryMetrics {
    logical_bytes: u64,
    allocated_bytes: u64,
    private_reclaimable_bytes: u64,
    private_reclaimable_complete: bool,
    files: u64,
    directories: u64,
    hardlink_duplicates: u64,
    errors: u64,
}

impl From<&InventoryMetrics> for CachedInventoryMetrics {
    fn from(metrics: &InventoryMetrics) -> Self {
        Self {
            logical_bytes: metrics.logical_bytes,
            allocated_bytes: metrics.allocated_bytes,
            private_reclaimable_bytes: metrics.private_reclaimable_bytes,
            private_reclaimable_complete: metrics.private_reclaimable_complete,
            files: metrics.files,
            directories: metrics.directories,
            hardlink_duplicates: metrics.hardlink_duplicates,
            errors: metrics.errors,
        }
    }
}

impl From<&CachedInventoryMetrics> for InventoryMetrics {
    fn from(metrics: &CachedInventoryMetrics) -> Self {
        Self {
            logical_bytes: metrics.logical_bytes,
            allocated_bytes: metrics.allocated_bytes,
            private_reclaimable_bytes: metrics.private_reclaimable_bytes,
            private_reclaimable_complete: metrics.private_reclaimable_complete,
            files: metrics.files,
            directories: metrics.directories,
            hardlink_duplicates: metrics.hardlink_duplicates,
            errors: metrics.errors,
        }
    }
}

fn empty_content_snapshot() -> ContentSnapshot {
    ContentSnapshot {
        complete: true,
        digest: format!("sha256:{:x}", Sha256::new().finalize()),
        files: 0,
        alien_directories: 0,
        unmanaged_entries: 0,
        unsupported_entries: 0,
        metrics: InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        },
        evidence: PnpmContentEvidence {
            cache_path: None,
            prefix_index_complete: true,
            total_prefixes: 0,
            covered_prefixes: 0,
            cached_prefixes: 0,
            freshly_scanned_prefixes: 0,
            pending_prefixes: 0,
            coverage_complete: true,
            point_in_time_complete: true,
            oldest_observation_unix: None,
            newest_observation_unix: None,
            max_cache_age_seconds: PNPM_EVIDENCE_MAX_AGE_SECONDS,
            semantics: "empty content store observed in the current run".into(),
        },
    }
}

fn unsupported_control_root(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink() || !metadata.is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("inspect pnpm domain root {}", path.display()))
        }
    }
}

fn snapshot_content(
    root: &Path,
    remaining: &mut u64,
    scan_threads: usize,
    evidence_cache_path: Option<&Path>,
    pnpm_version: &str,
    observed_at_unix: u64,
) -> Result<ContentSnapshot> {
    let mut hasher = Sha256::new();
    let mut files = 0u64;
    let mut alien_directories = 0u64;
    let mut unmanaged_entries = 0u64;
    let mut unsupported_entries = 0u64;
    let mut link_counts_complete = true;
    let mut metrics = InventoryMetrics {
        private_reclaimable_complete: true,
        ..InventoryMetrics::default()
    };
    if !root.exists() {
        return Ok(ContentSnapshot {
            complete: true,
            digest: format!("sha256:{:x}", hasher.finalize()),
            files,
            alien_directories,
            unmanaged_entries,
            unsupported_entries,
            metrics,
            evidence: PnpmContentEvidence {
                cache_path: evidence_cache_path.map(Path::to_path_buf),
                prefix_index_complete: true,
                total_prefixes: 0,
                covered_prefixes: 0,
                cached_prefixes: 0,
                freshly_scanned_prefixes: 0,
                pending_prefixes: 0,
                coverage_complete: true,
                point_in_time_complete: true,
                oldest_observation_unix: None,
                newest_observation_unix: None,
                max_cache_age_seconds: PNPM_EVIDENCE_MAX_AGE_SECONDS,
                semantics: "content store is absent".into(),
            },
        });
    }

    let mut prefixes = Vec::new();
    let mut first_error = None;
    let visit = inventory::visit_directory(root, *remaining, &mut |entry| match entry {
        Ok(entry) if entry.kind == EntryKind::Directory => prefixes.push(entry.name),
        Ok(_) => unmanaged_entries += 1,
        Err(error) => first_error = Some(error),
    })?;
    *remaining = remaining.saturating_sub(visit.visited_entries);
    if let Some(error) = first_error {
        return Err(error).context("scan pnpm content-addressed store root");
    }
    let root_complete = visit.exhausted;
    prefixes.sort();

    let _evidence_lock = evidence_cache_path
        .map(acquire_evidence_cache_lock)
        .transpose()?;
    let mut cache = evidence_cache_path
        .map(|path| load_evidence_cache(path, root, pnpm_version))
        .transpose()?
        .unwrap_or_else(|| empty_evidence_cache(root, pnpm_version));
    let current_prefix_keys = prefixes
        .iter()
        .filter_map(|prefix| prefix.to_str().map(str::to_owned))
        .collect::<HashSet<_>>();
    if root_complete {
        cache
            .prefixes
            .retain(|prefix, _| current_prefix_keys.contains(prefix));
    }

    let total_prefixes = prefixes.len() as u64;
    let mut observed_snapshots = Vec::new();
    let mut pending = Vec::new();
    let mut cached_prefixes = 0u64;
    for prefix in prefixes {
        let fingerprint = prefix_fingerprint(&root.join(&prefix))?;
        let cache_key = prefix.to_str().map(str::to_owned);
        let cached = cache_key
            .as_ref()
            .and_then(|key| cache.prefixes.get(key))
            .filter(|cached| {
                cached.fingerprint == fingerprint
                    && cached.observed_at_unix <= observed_at_unix
                    && observed_at_unix.saturating_sub(cached.observed_at_unix)
                        <= PNPM_EVIDENCE_MAX_AGE_SECONDS
            });
        if let Some(cached) = cached {
            cached_prefixes += 1;
            observed_snapshots.push(ObservedPrefixSnapshot {
                snapshot: cached_prefix_snapshot(prefix, cached),
                observed_at_unix: cached.observed_at_unix,
            });
        } else {
            if let Some(key) = &cache_key {
                cache.prefixes.remove(key);
            }
            pending.push(PrefixToScan {
                prefix,
                cache_key,
                fingerprint,
            });
        }
    }

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(scan_threads)
        .thread_name(|index| format!("pnpm-store-scan-{index}"))
        .build()
        .context("create bounded pnpm store scan pool")?;
    let mut freshly_scanned_prefixes = 0u64;
    while !pending.is_empty() && *remaining > 0 {
        let batch_len = scan_threads.min(pending.len());
        let batch = pending.drain(..batch_len).collect::<Vec<_>>();
        let batch_count = batch.len() as u64;
        let base_budget = *remaining / batch_count;
        let extra_budget = *remaining % batch_count;
        let scans = batch
            .into_iter()
            .enumerate()
            .map(|(index, prefix)| {
                let budget = base_budget + u64::from((index as u64) < extra_budget);
                (prefix, budget)
            })
            .collect::<Vec<_>>();
        let results = pool.install(|| {
            scans
                .into_par_iter()
                .map(|(prefix, budget)| {
                    let snapshot = snapshot_content_prefix(root, prefix.prefix.clone(), budget)?;
                    Ok::<_, anyhow::Error>((prefix, snapshot))
                })
                .collect::<Vec<_>>()
        });
        let mut incomplete_batch = false;
        for result in results {
            let (prefix, mut snapshot) = result?;
            freshly_scanned_prefixes += 1;
            *remaining = remaining.saturating_sub(snapshot.visited_entries);
            if prefix_fingerprint(&root.join(&prefix.prefix))? != prefix.fingerprint {
                snapshot.complete = false;
            }
            let cacheable = snapshot.complete
                && snapshot.link_counts_complete
                && snapshot.unsupported_entries == 0;
            if cacheable {
                if let Some(key) = prefix.cache_key {
                    cache.prefixes.insert(
                        key,
                        CachedPrefixSnapshot {
                            fingerprint: prefix.fingerprint,
                            observed_at_unix,
                            digest: snapshot.digest.clone(),
                            files: snapshot.files,
                            alien_directories: snapshot.alien_directories,
                            unsupported_entries: snapshot.unsupported_entries,
                            metrics: CachedInventoryMetrics::from(&snapshot.metrics),
                        },
                    );
                }
            } else {
                incomplete_batch = true;
            }
            observed_snapshots.push(ObservedPrefixSnapshot {
                snapshot,
                observed_at_unix,
            });
        }
        // A prefix larger than its share cannot be resumed safely without
        // retaining per-entry evidence. Stop here; completed siblings are
        // cached, so the next bounded run gives the remaining prefixes a
        // larger share instead of repeating the whole store.
        if incomplete_batch {
            break;
        }
    }
    if let Some(path) = evidence_cache_path {
        write_evidence_cache(path, &cache)?;
    }

    observed_snapshots.sort_by(|left, right| {
        left.snapshot
            .prefix
            .as_os_str()
            .cmp(right.snapshot.prefix.as_os_str())
    });
    let mut covered_prefixes = 0u64;
    let mut oldest_observation_unix = None;
    let mut newest_observation_unix = None;
    for observed in observed_snapshots {
        let snapshot = observed.snapshot;
        let prefix_complete =
            snapshot.complete && snapshot.link_counts_complete && snapshot.unsupported_entries == 0;
        covered_prefixes += u64::from(prefix_complete);
        link_counts_complete &= snapshot.link_counts_complete;
        files = files.saturating_add(snapshot.files);
        alien_directories = alien_directories.saturating_add(snapshot.alien_directories);
        unsupported_entries = unsupported_entries.saturating_add(snapshot.unsupported_entries);
        if snapshot.files > 0 {
            hasher.update(snapshot.prefix.to_string_lossy().as_bytes());
            hasher.update([0]);
            hasher.update(snapshot.digest.as_bytes());
        }
        add_metrics(&mut metrics, &snapshot.metrics);
        if prefix_complete {
            oldest_observation_unix = Some(
                oldest_observation_unix.map_or(observed.observed_at_unix, |oldest: u64| {
                    oldest.min(observed.observed_at_unix)
                }),
            );
            newest_observation_unix = Some(
                newest_observation_unix.map_or(observed.observed_at_unix, |newest: u64| {
                    newest.max(observed.observed_at_unix)
                }),
            );
        }
    }
    let pending_prefixes = total_prefixes.saturating_sub(covered_prefixes);
    let coverage_complete = root_complete && pending_prefixes == 0;
    let point_in_time_complete = coverage_complete && cached_prefixes == 0;

    Ok(ContentSnapshot {
        complete: point_in_time_complete && link_counts_complete && unsupported_entries == 0,
        digest: format!("sha256:{:x}", hasher.finalize()),
        files,
        alien_directories,
        unmanaged_entries,
        unsupported_entries,
        metrics,
        evidence: PnpmContentEvidence {
            cache_path: evidence_cache_path.map(Path::to_path_buf),
            prefix_index_complete: root_complete,
            total_prefixes,
            covered_prefixes,
            cached_prefixes,
            freshly_scanned_prefixes,
            pending_prefixes,
            coverage_complete,
            point_in_time_complete,
            oldest_observation_unix,
            newest_observation_unix,
            max_cache_age_seconds: PNPM_EVIDENCE_MAX_AGE_SECONDS,
            semantics: if evidence_cache_path.is_some() {
                "cached prefixes are advisory historical observations; only a fully fresh current run is executable evidence"
            } else {
                "all reported prefixes were observed in the current run"
            }
            .into(),
        },
    })
}

#[derive(Debug)]
struct PrefixToScan {
    prefix: std::ffi::OsString,
    cache_key: Option<String>,
    fingerprint: PrefixFingerprint,
}

#[derive(Debug)]
struct ObservedPrefixSnapshot {
    snapshot: PrefixContentSnapshot,
    observed_at_unix: u64,
}

fn empty_evidence_cache(root: &Path, pnpm_version: &str) -> PnpmEvidenceCache {
    PnpmEvidenceCache {
        cache_version: PNPM_EVIDENCE_CACHE_VERSION,
        store_files: root.to_path_buf(),
        pnpm_version: pnpm_version.to_owned(),
        prefixes: BTreeMap::new(),
    }
}

fn load_evidence_cache(path: &Path, root: &Path, pnpm_version: &str) -> Result<PnpmEvidenceCache> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(empty_evidence_cache(root, pnpm_version));
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read pnpm evidence cache {}", path.display()));
        }
    };
    let Ok(cache) = serde_json::from_slice::<PnpmEvidenceCache>(&bytes) else {
        return Ok(empty_evidence_cache(root, pnpm_version));
    };
    if cache.cache_version != PNPM_EVIDENCE_CACHE_VERSION
        || cache.store_files != root
        || cache.pnpm_version != pnpm_version
    {
        return Ok(empty_evidence_cache(root, pnpm_version));
    }
    Ok(cache)
}

fn write_evidence_cache(path: &Path, cache: &PnpmEvidenceCache) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic pnpm evidence cache {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(cache)?)?;
    file.commit()
        .with_context(|| format!("commit pnpm evidence cache {}", path.display()))
}

fn acquire_evidence_cache_lock(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let lock_path = path.with_extension("lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open pnpm evidence cache lock {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("lock pnpm evidence cache {}", lock_path.display()))?;
    Ok(lock)
}

fn prefix_fingerprint(path: &Path) -> Result<PrefixFingerprint> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read pnpm prefix metadata {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "pnpm prefix is not a contained directory: {}",
        path.display()
    );
    Ok(prefix_fingerprint_from_metadata(&metadata))
}

#[cfg(unix)]
fn prefix_fingerprint_from_metadata(metadata: &fs::Metadata) -> PrefixFingerprint {
    use std::os::unix::fs::MetadataExt;
    PrefixFingerprint {
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
        modified_seconds: Some(metadata.mtime()),
        modified_nanoseconds: Some(metadata.mtime_nsec()),
        changed_seconds: Some(metadata.ctime()),
        changed_nanoseconds: Some(metadata.ctime_nsec()),
    }
}

#[cfg(not(unix))]
fn prefix_fingerprint_from_metadata(metadata: &fs::Metadata) -> PrefixFingerprint {
    let modified = metadata.modified().ok().and_then(|time| {
        time.duration_since(UNIX_EPOCH)
            .ok()
            .map(|duration| (duration.as_secs() as i64, duration.subsec_nanos() as i64))
    });
    PrefixFingerprint {
        device: None,
        inode: None,
        modified_seconds: modified.map(|(seconds, _)| seconds),
        modified_nanoseconds: modified.map(|(_, nanoseconds)| nanoseconds),
        changed_seconds: None,
        changed_nanoseconds: None,
    }
}

fn cached_prefix_snapshot(
    prefix: std::ffi::OsString,
    cached: &CachedPrefixSnapshot,
) -> PrefixContentSnapshot {
    PrefixContentSnapshot {
        prefix,
        visited_entries: 0,
        complete: true,
        link_counts_complete: true,
        digest: cached.digest.clone(),
        files: cached.files,
        alien_directories: cached.alien_directories,
        unsupported_entries: cached.unsupported_entries,
        metrics: InventoryMetrics::from(&cached.metrics),
    }
}

#[derive(Debug)]
struct PrefixContentSnapshot {
    prefix: std::ffi::OsString,
    visited_entries: u64,
    complete: bool,
    link_counts_complete: bool,
    digest: String,
    files: u64,
    alien_directories: u64,
    unsupported_entries: u64,
    metrics: InventoryMetrics,
}

fn snapshot_content_prefix(
    root: &Path,
    prefix: std::ffi::OsString,
    budget: u64,
) -> Result<PrefixContentSnapshot> {
    if budget == 0 {
        return Ok(PrefixContentSnapshot {
            prefix,
            visited_entries: 0,
            complete: false,
            link_counts_complete: true,
            digest: format!("sha256:{:x}", Sha256::new().finalize()),
            files: 0,
            alien_directories: 0,
            unsupported_entries: 0,
            metrics: InventoryMetrics {
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            },
        });
    }
    let prefix_path = root.join(&prefix);
    let mut entries = Vec::new();
    let mut first_error = None;
    let visit = inventory::visit_directory(&prefix_path, budget, &mut |entry| match entry {
        Ok(entry) => entries.push(entry),
        Err(error) => first_error = Some(error),
    })?;
    if let Some(error) = first_error {
        return Err(error)
            .with_context(|| format!("scan pnpm store prefix {}", prefix_path.display()));
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    let mut hasher = Sha256::new();
    let mut files = 0u64;
    let mut alien_directories = 0u64;
    let mut unsupported_entries = 0u64;
    let mut link_counts_complete = true;
    let mut metrics = InventoryMetrics {
        private_reclaimable_complete: true,
        ..InventoryMetrics::default()
    };
    for entry in entries {
        match entry.kind {
            EntryKind::Directory => alien_directories += 1,
            EntryKind::File if !entry.name.to_string_lossy().ends_with(".json") => {
                link_counts_complete &= entry.link_count.is_some();
                if entry.link_count == Some(1) {
                    record_content_candidate(
                        Path::new(&prefix),
                        &entry,
                        &mut hasher,
                        &mut files,
                        &mut metrics,
                    );
                }
            }
            EntryKind::Other => unsupported_entries += 1,
            _ => {}
        }
    }
    Ok(PrefixContentSnapshot {
        prefix,
        visited_entries: visit.visited_entries,
        complete: visit.exhausted,
        link_counts_complete,
        digest: format!("sha256:{:x}", hasher.finalize()),
        files,
        alien_directories,
        unsupported_entries,
        metrics,
    })
}

fn record_content_candidate(
    parent: &Path,
    entry: &inventory::DirectoryEntryMeasurement,
    hasher: &mut Sha256,
    files: &mut u64,
    metrics: &mut InventoryMetrics,
) {
    let Some(file) = &entry.file else { return };
    let relative = parent.join(&entry.name);
    hasher.update(relative.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(entry.file_id.unwrap_or_default().to_le_bytes());
    hasher.update(file.logical_bytes.to_le_bytes());
    *files += 1;
    metrics.files += 1;
    metrics.logical_bytes = metrics.logical_bytes.saturating_add(file.logical_bytes);
    metrics.allocated_bytes = metrics.allocated_bytes.saturating_add(file.allocated_bytes);
    if let Some(private) = file.private_reclaimable_bytes {
        metrics.private_reclaimable_bytes =
            metrics.private_reclaimable_bytes.saturating_add(private);
    } else {
        metrics.private_reclaimable_complete = false;
    }
}

fn metadata_directories(cache: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let entries = match fs::read_dir(cache) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(paths),
        Err(error) => {
            return Err(error).with_context(|| format!("read pnpm cache {}", cache.display()))
        }
    };
    for entry in entries {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry.file_name().to_string_lossy().starts_with("metadata")
        {
            paths.push(entry.path().canonicalize()?);
        }
    }
    paths.sort();
    Ok(paths)
}

#[derive(Debug, Default)]
struct DlxCandidates {
    expired_entries: Vec<PathBuf>,
    orphan_entries: Vec<PathBuf>,
    stale_children: Vec<PathBuf>,
    unsupported_entries: Vec<PathBuf>,
}

fn dlx_candidates(cache: &Path, dlx_days: u64, now: SystemTime) -> Result<DlxCandidates> {
    let root = cache.join("dlx");
    let entries = match fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(DlxCandidates {
                expired_entries: Vec::new(),
                orphan_entries: Vec::new(),
                stale_children: Vec::new(),
                unsupported_entries: Vec::new(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| format!("read pnpm dlx cache {}", root.display()))
        }
    };
    let cutoff = now
        .checked_sub(std::time::Duration::from_secs(
            dlx_days.saturating_mul(86_400),
        ))
        .unwrap_or(UNIX_EPOCH);
    let mut expired = Vec::new();
    let mut orphan = Vec::new();
    let mut stale_children = Vec::new();
    let mut unsupported = Vec::new();
    for entry in entries {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let path = entry.path();
        if !entry_type.is_dir() {
            unsupported.push(path);
            continue;
        }
        let pkg = path.join("pkg");
        match fs::symlink_metadata(&pkg) {
            Ok(metadata) if metadata.modified()? < cutoff => {
                // Preserve the literal cache entry path. pnpm removes this
                // path, not the destination if the entry itself is a symlink.
                expired.push(path)
            }
            Ok(_) => {
                let current_target = pkg.canonicalize().ok();
                for child in fs::read_dir(&path)? {
                    let child = child?;
                    if child.file_name() == "pkg" {
                        continue;
                    }
                    let child_path = child.path();
                    // This mirrors pnpm's literal full-path comparison. A
                    // second symlink to the current target is still stale and
                    // is removed by pnpm.
                    if Some(&child_path) != current_target.as_ref() {
                        stale_children.push(child_path);
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => orphan.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotADirectory => {
                unsupported.push(path)
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect pnpm dlx entry {}", path.display()))
            }
        }
    }
    expired.sort();
    orphan.sort();
    stale_children.sort();
    unsupported.sort();
    Ok(DlxCandidates {
        expired_entries: expired,
        orphan_entries: orphan,
        stale_children,
        unsupported_entries: unsupported,
    })
}

fn measure_paths(paths: &[PathBuf], remaining: &mut u64) -> Result<InventoryMetrics> {
    if paths.is_empty() || *remaining == 0 {
        return Ok(InventoryMetrics {
            private_reclaimable_complete: paths.is_empty(),
            ..InventoryMetrics::default()
        });
    }
    let mut metrics = InventoryMetrics {
        private_reclaimable_complete: true,
        ..InventoryMetrics::default()
    };
    let mut directories = Vec::new();
    for path in paths {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("measure pnpm side effect {}", path.display()))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            directories.push(path.clone());
        } else {
            *remaining = remaining.saturating_sub(1);
            metrics.files += 1;
            metrics.logical_bytes = metrics.logical_bytes.saturating_add(metadata.len());
            metrics.allocated_bytes = metrics
                .allocated_bytes
                .saturating_add(metadata_allocated_bytes(&metadata));
            metrics.private_reclaimable_complete = false;
        }
    }
    if !directories.is_empty() && *remaining > 0 {
        let report = inventory::inventory(
            &directories,
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: *remaining,
                one_filesystem: true,
            },
        )?;
        for root in report.roots {
            *remaining = remaining.saturating_sub(root.visited_entries);
            add_metrics(&mut metrics, &root.metrics);
            if !root.complete {
                metrics.private_reclaimable_complete = false;
            }
        }
    }
    Ok(metrics)
}

#[cfg(unix)]
fn metadata_allocated_bytes(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn metadata_allocated_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

fn add_metrics(target: &mut InventoryMetrics, source: &InventoryMetrics) {
    target.logical_bytes = target.logical_bytes.saturating_add(source.logical_bytes);
    target.allocated_bytes = target
        .allocated_bytes
        .saturating_add(source.allocated_bytes);
    target.private_reclaimable_bytes = target
        .private_reclaimable_bytes
        .saturating_add(source.private_reclaimable_bytes);
    target.private_reclaimable_complete &= source.private_reclaimable_complete;
    target.files = target.files.saturating_add(source.files);
    target.directories = target.directories.saturating_add(source.directories);
    target.hardlink_duplicates = target
        .hardlink_duplicates
        .saturating_add(source.hardlink_duplicates);
    target.errors = target.errors.saturating_add(source.errors);
}

fn classify_plan(plan: &PnpmPrunePlan) -> PnpmPruneAction {
    if plan.protection.is_some() {
        PnpmPruneAction::Protected
    } else if !plan.active_owner_processes.is_empty() || !plan.open_paths.is_empty() {
        PnpmPruneAction::InUse
    } else if !plan.open_handle_check_complete {
        PnpmPruneAction::ReportOnly
    } else if !plan.planner_supported {
        PnpmPruneAction::UnsupportedVersion
    } else if plan.global_virtual_store_present
        || plan.unsupported_content_entries > 0
        || !plan.unsupported_dlx_entries.is_empty()
        || !plan.unsupported_layout_paths.is_empty()
    {
        PnpmPruneAction::UnsupportedLayout
    } else if !plan.complete {
        PnpmPruneAction::ReportOnly
    } else if plan_has_work(plan) {
        PnpmPruneAction::Delegate
    } else {
        PnpmPruneAction::NoWork
    }
}

fn plan_reason(plan: &PnpmPrunePlan) -> String {
    match plan.action {
        PnpmPruneAction::Delegate => "pnpm can prune the complete, idle, unprotected snapshot".into(),
        PnpmPruneAction::NoWork => "pnpm has no currently eligible prune work".into(),
        PnpmPruneAction::ReportOnly if !plan.complete => {
            "the bounded eligibility snapshot is incomplete".into()
        }
        PnpmPruneAction::ReportOnly => "the open-handle check did not complete".into(),
        PnpmPruneAction::Protected => "the pnpm store or cache intersects an active protection".into(),
        PnpmPruneAction::InUse => "a pnpm process or open store/cache path is active".into(),
        PnpmPruneAction::UnsupportedVersion => format!(
            "the advisory planner is validated only for pnpm {SUPPORTED_PNPM_PLANNER_VERSION}; installed pnpm semantics must be reviewed before delegation"
        ),
        PnpmPruneAction::UnsupportedLayout if plan.global_virtual_store_present => "a pnpm global virtual store is present; its project reachability plan is not implemented yet".into(),
        PnpmPruneAction::UnsupportedLayout if !plan.unsupported_dlx_entries.is_empty() => "the pnpm dlx cache contains entries that its maintained prune operation cannot safely classify".into(),
        PnpmPruneAction::UnsupportedLayout if !plan.unsupported_layout_paths.is_empty() => "pnpm domain roots include symlinked or non-directory traversal paths outside the supported containment model".into(),
        PnpmPruneAction::UnsupportedLayout => "the pnpm content store contains special entries whose follow-stat semantics are not modeled".into(),
    }
}

fn plan_has_work(plan: &PnpmPrunePlan) -> bool {
    plan.unreferenced_content_files > 0
        || !plan.metadata_directories.is_empty()
        || plan.store_tmp.is_some()
        || !plan.expired_dlx_entries.is_empty()
        || !plan.orphan_dlx_entries.is_empty()
        || !plan.stale_dlx_children.is_empty()
}

fn execute_pnpm_plan(
    context: &PnpmContext,
    options: &PnpmCollectOptions,
    manifest: &mut PnpmCollectManifest,
) -> Result<()> {
    match manifest.plan.action {
        PnpmPruneAction::Delegate => {}
        PnpmPruneAction::NoWork => return Ok(()),
        _ => bail!("pnpm prune is not executable: {}", manifest.plan.reason),
    }

    let lock = acquire_collector_lock()?;
    let guarded_paths = vec![
        context.identity.store_path.clone(),
        context.identity.cache_path.clone(),
    ];
    let result = with_protection_guard_for_paths(
        &guarded_paths,
        SystemTime::now(),
        || -> Result<PnpmPruneOutcome> {
            revalidate_pnpm_identity(&context.identity)?;
            // The protection guard already holds the registry lock and has
            // verified both domain roots. Re-reading protections here would
            // recursively acquire the same lock.
            let mut execution_options = options.clone();
            execution_options.now = SystemTime::now();
            let refreshed = plan_pnpm_without_protection(&context.identity, &execution_options)?;
            anyhow::ensure!(
                refreshed.action == PnpmPruneAction::Delegate,
                "pnpm prune became ineligible: {}",
                refreshed.reason
            );
            anyhow::ensure!(
                refreshed.approval_digest == manifest.plan.approval_digest
                    &&
                refreshed.eligibility_digest == manifest.plan.eligibility_digest
                    && refreshed.unreferenced_content_files
                        == manifest.plan.unreferenced_content_files
                    && refreshed.metadata_directories == manifest.plan.metadata_directories
                    && refreshed.store_tmp == manifest.plan.store_tmp
                    && refreshed.expired_dlx_entries == manifest.plan.expired_dlx_entries
                    && refreshed.orphan_dlx_entries == manifest.plan.orphan_dlx_entries
                    && refreshed.stale_dlx_children == manifest.plan.stale_dlx_children
                    && refreshed.unsupported_dlx_entries
                        == manifest.plan.unsupported_dlx_entries
                    && refreshed.unsupported_layout_paths
                        == manifest.plan.unsupported_layout_paths
                    && same_filesystems(&refreshed.filesystems, &manifest.plan.filesystems),
                "pnpm prune eligibility changed after planning; rerun without --execute to review the new manifest"
            );

            let filesystems_before = filesystem_observations(&context.identity)?;
            let output = Command::new(&context.identity.canonical_executable)
                .arg(format!(
                    "--config.dlx-cache-max-age={}",
                    options.dlx_days.saturating_mul(MINUTES_PER_DAY)
                ))
                .args(["store", "prune"])
                .stdin(Stdio::null())
                .output()
                .context("run official pnpm store prune")?;
            let command_succeeded = output.status.success();
            let mut verification_options = execution_options;
            verification_options.now = SystemTime::now();
            let verification = snapshot_pnpm(&context.identity, &verification_options);
            let filesystems = finish_filesystem_observations(filesystems_before)?;
            let (
                verification_complete,
                verification_error,
                remaining_unreferenced_content_files,
                remaining_metadata_directories,
                store_tmp_remaining,
                remaining_dlx_cleanup_entries,
            ) = match verification {
                Ok(after) => (
                    after.complete,
                    None,
                    Some(after.unreferenced_content_files),
                    Some(after.metadata_directories.len() as u64),
                    Some(after.store_tmp.is_some()),
                    Some(
                        (after.expired_dlx_entries.len()
                            + after.orphan_dlx_entries.len()
                            + after.stale_dlx_children.len()) as u64,
                    ),
                ),
                Err(error) => (false, Some(format!("{error:#}")), None, None, None, None),
            };
            Ok(PnpmPruneOutcome {
                command_succeeded,
                exit_code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                realized_reclaim_bytes: filesystems
                    .iter()
                    .map(|filesystem| filesystem.realized_reclaim_bytes)
                    .sum(),
                filesystems,
                verification_complete,
                verification_error,
                remaining_unreferenced_content_files,
                remaining_metadata_directories,
                store_tmp_remaining,
                remaining_dlx_cleanup_entries,
            })
        },
    )?;
    drop(lock);
    match result {
        ProtectionGuardOutcome::Protected(protection) => bail!(
            "pnpm prune became protected by lease {} ({})",
            protection.id,
            protection.reason
        ),
        ProtectionGuardOutcome::Executed(outcome) => manifest.outcome = Some(outcome?),
    }
    let outcome = manifest
        .outcome
        .as_ref()
        .context("executed pnpm prune did not record an outcome")?;
    anyhow::ensure!(
        outcome.command_succeeded,
        "pnpm store prune failed: {}",
        outcome.stderr.trim()
    );
    anyhow::ensure!(
        outcome.verification_complete
            && outcome.verification_error.is_none()
            && outcome.remaining_unreferenced_content_files == Some(0)
            && outcome.remaining_metadata_directories == Some(0)
            && outcome.store_tmp_remaining == Some(false)
            && outcome.remaining_dlx_cleanup_entries == Some(0),
        "pnpm prune completed but post-operation verification did not prove the eligible content absent; inspect {} ({})",
        context.identity.store_path.display()
        ,
        outcome.verification_error.as_deref().unwrap_or("eligible content remains")
    );
    Ok(())
}

#[cfg(unix)]
fn open_pnpm_paths(identity: &PnpmIdentity, active_processes: &[String]) -> (Vec<PathBuf>, bool) {
    // Do not ask lsof to enumerate every task and open file on the machine.
    // `ps` has already identified the pnpm owners; scope lsof to those exact
    // PIDs only. If no pnpm owner exists, there is no owner process to probe.
    let pids = active_processes
        .iter()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|pid| pid.chars().all(|character| character.is_ascii_digit()))
        .collect::<Vec<_>>();
    if pids.is_empty() {
        return (Vec::new(), true);
    }
    let output = match Command::new("lsof")
        .args(["-nP", "-F0n", "-p", &pids.join(",")])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("warning: pnpm open-handle snapshot failed: {error}");
            return (Vec::new(), false);
        }
    };
    if !output.status.success() {
        eprintln!(
            "warning: pnpm open-handle snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return (Vec::new(), false);
    }
    (
        parse_lsof_paths(
            &output.stdout,
            &[&identity.store_path, &identity.cache_path],
        ),
        true,
    )
}

#[cfg(unix)]
fn pnpm_cwd_paths(identity: &PnpmIdentity) -> (Vec<PathBuf>, bool) {
    // A process launched through `pnpm dlx` can survive after its pnpm wrapper
    // exits. Looking only at pnpm PIDs would then classify the cache as idle.
    // Restrict this machine-wide snapshot to cwd descriptors: it catches a
    // surviving process parked anywhere below the store/cache without asking
    // lsof to enumerate every open file on the machine.
    let output = match Command::new("lsof")
        .args(["-nP", "-F0n", "-d", "cwd"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            eprintln!("warning: pnpm cwd snapshot failed: {error}");
            return (Vec::new(), false);
        }
    };
    if !output.status.success() {
        eprintln!(
            "warning: pnpm cwd snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return (Vec::new(), false);
    }
    (
        parse_lsof_paths(
            &output.stdout,
            &[&identity.store_path, &identity.cache_path],
        ),
        true,
    )
}

#[cfg(unix)]
fn parse_lsof_paths(output: &[u8], roots: &[&PathBuf]) -> Vec<PathBuf> {
    let mut paths = output
        .split(|byte| *byte == 0)
        .filter_map(|field| {
            let field = field
                .iter()
                .position(|byte| *byte != b'\n')
                .map_or(&[][..], |start| &field[start..]);
            field.strip_prefix(b"n")
        })
        .map(|path| PathBuf::from(String::from_utf8_lossy(path).into_owned()))
        .filter(|path| roots.iter().any(|root| path.starts_with(root)))
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    paths
}

#[cfg(not(unix))]
fn open_pnpm_paths(_identity: &PnpmIdentity, _active_processes: &[String]) -> (Vec<PathBuf>, bool) {
    (Vec::new(), false)
}

#[cfg(not(unix))]
fn pnpm_cwd_paths(_identity: &PnpmIdentity) -> (Vec<PathBuf>, bool) {
    (Vec::new(), false)
}

fn active_pnpm_owner_processes(identity: &PnpmIdentity) -> Result<Vec<String>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .stdin(Stdio::null())
        .output()
        .context("list processes while planning pnpm prune")?;
    anyhow::ensure!(
        output.status.success(),
        "ps failed while planning pnpm prune"
    );
    let mut matches = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(' ')?;
            let command = command.trim_start();
            (is_pnpm_command(command)
                || command_mentions_pnpm_root(
                    command,
                    [identity.store_path.as_path(), identity.cache_path.as_path()],
                ))
            .then(|| owner_process_summary(pid, command))
        })
        .take(50)
        .collect::<Vec<_>>();
    matches.sort();
    Ok(matches)
}

fn owner_process_summary(pid: &str, command: &str) -> String {
    let executable = command
        .split_whitespace()
        .next()
        .map(command_basename)
        .unwrap_or("unknown");
    format!("{pid} {executable}")
}

fn command_mentions_pnpm_root<'a>(
    command: &str,
    roots: impl IntoIterator<Item = &'a Path>,
) -> bool {
    roots.into_iter().any(|root| {
        root.to_str()
            .is_some_and(|root| !root.is_empty() && command.contains(root))
    })
}

fn is_pnpm_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let first = words.next().map(command_basename).unwrap_or("");
    let second = words.next().map(command_basename).unwrap_or("");
    first == "pnpm"
        || first == "pnpm.cjs"
        || (matches!(first, "node" | "node.exe") && second == "pnpm.cjs")
        || (matches!(first, "corepack" | "corepack.exe") && second == "pnpm")
}

fn command_basename(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(word)
}

fn delegated_command(dlx_days: u64) -> Vec<String> {
    vec![
        format!(
            "--config.dlx-cache-max-age={}",
            dlx_days.saturating_mul(MINUTES_PER_DAY)
        ),
        "store".into(),
        "prune".into(),
    ]
}

fn command_stdout(executable: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {} {}", executable.display(), args.join(" ")))?;
    anyhow::ensure!(
        output.status.success(),
        "{} {} failed: {}",
        executable.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn filesystem_observations(identity: &PnpmIdentity) -> Result<Vec<PnpmFilesystemReclaim>> {
    Ok(observe_filesystems(identity)?
        .into_iter()
        .map(|observation| PnpmFilesystemReclaim {
            filesystem: observation.filesystem,
            observed_at: observation.observed_at,
            available_bytes_before: observation.available_bytes,
            available_bytes_after: 0,
            realized_reclaim_bytes: 0,
        })
        .collect())
}

fn observe_filesystems(identity: &PnpmIdentity) -> Result<Vec<PnpmFilesystemObservation>> {
    let mut observations = Vec::new();
    for path in [&identity.store_path, &identity.cache_path] {
        let observed_at = existing_ancestor(path)?;
        let filesystem = filesystem_identity(&observed_at)?;
        if observations
            .iter()
            .any(|observation: &PnpmFilesystemObservation| observation.filesystem == filesystem)
        {
            continue;
        }
        observations.push(PnpmFilesystemObservation {
            filesystem,
            observed_at: observed_at.clone(),
            available_bytes: fs4::available_space(&observed_at)?,
        });
    }
    Ok(observations)
}

fn same_filesystems(
    left: &[PnpmFilesystemObservation],
    right: &[PnpmFilesystemObservation],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.filesystem == right.filesystem && left.observed_at == right.observed_at
        })
}

fn existing_ancestor(path: &Path) -> Result<PathBuf> {
    let mut candidate = path;
    while !candidate.exists() {
        candidate = candidate
            .parent()
            .context("path has no existing ancestor for filesystem observation")?;
    }
    Ok(candidate.to_path_buf())
}

fn finish_filesystem_observations(
    mut observations: Vec<PnpmFilesystemReclaim>,
) -> Result<Vec<PnpmFilesystemReclaim>> {
    for observation in &mut observations {
        observation.available_bytes_after = fs4::available_space(&observation.observed_at)?;
        observation.realized_reclaim_bytes = observation
            .available_bytes_after
            .saturating_sub(observation.available_bytes_before);
    }
    Ok(observations)
}

#[cfg(unix)]
fn filesystem_identity(path: &Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    Ok(format!("device:{}", fs::metadata(path)?.dev()))
}

#[cfg(not(unix))]
fn filesystem_identity(path: &Path) -> Result<String> {
    Ok(path.canonicalize()?.display().to_string())
}

fn revalidate_pnpm_identity(identity: &PnpmIdentity) -> Result<()> {
    let canonical_executable = identity
        .executable
        .canonicalize()
        .with_context(|| format!("resolve pnpm executable {}", identity.executable.display()))?;
    anyhow::ensure!(
        canonical_executable == identity.canonical_executable,
        "pnpm executable changed after planning"
    );
    anyhow::ensure!(
        command_stdout(&canonical_executable, &["--version"])? == identity.version,
        "pnpm version changed after planning"
    );
    let store = PathBuf::from(command_stdout(&canonical_executable, &["store", "path"])?)
        .canonicalize()
        .context("resolve pnpm store during execution revalidation")?;
    anyhow::ensure!(
        store == identity.store_path,
        "pnpm store changed after planning"
    );
    let configured_cache = command_stdout(&canonical_executable, &["config", "get", "cache-dir"])?;
    let cache = if configured_cache.is_empty()
        || matches!(configured_cache.as_str(), "undefined" | "null")
    {
        default_pnpm_cache_dir()?
    } else {
        PathBuf::from(configured_cache)
    };
    anyhow::ensure!(
        canonicalize_existing_or_parent(&cache)? == identity.cache_path,
        "pnpm cache changed after planning"
    );
    Ok(())
}

fn find_executable(name: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|directory| {
        let candidate = directory.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn default_pnpm_cache_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CACHE_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path).join("pnpm"));
    }
    let home = PathBuf::from(
        std::env::var_os("HOME").context("HOME is required to resolve pnpm's default cache")?,
    );
    #[cfg(target_os = "macos")]
    return Ok(home.join("Library/Caches/pnpm"));
    #[cfg(not(target_os = "macos"))]
    Ok(home.join(".cache/pnpm"))
}

fn canonicalize_existing_or_parent(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    while !existing.exists() {
        missing.push(
            existing
                .file_name()
                .context("pnpm cache path has no existing ancestor")?
                .to_os_string(),
        );
        existing = existing
            .parent()
            .context("pnpm cache path has no existing ancestor")?;
    }
    let mut canonical = existing
        .canonicalize()
        .with_context(|| format!("canonicalize {}", existing.display()))?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn acquire_collector_lock() -> Result<File> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("pnpm-store.lock"))?;
    lock.lock().context("lock pnpm collector")?;
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

fn pnpm_evidence_cache_path(identity: &PnpmIdentity) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(identity.store_path.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(identity.version.as_bytes());
    let key = format!("{:x}", hasher.finalize());
    Ok(state_directory()?
        .join("collectors")
        .join(format!("pnpm-store-evidence-{}.json", &key[..16])))
}

fn write_pnpm_manifest(manifest: &PnpmCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!("{}-pnpm-store-{mode}.json", manifest.run_id));
    write_pnpm_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_pnpm_manifest_at(path: &Path, manifest: &PnpmCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit pnpm manifest {}", path.display()))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn fresh_options() -> PnpmCollectOptions {
        PnpmCollectOptions {
            fresh: true,
            ..PnpmCollectOptions::default()
        }
    }

    #[test]
    fn process_matching_identifies_pnpm_owners_without_matching_our_subcommand() {
        assert!(is_pnpm_command("pnpm install"));
        assert!(is_pnpm_command(
            "/usr/bin/node /tools/pnpm/bin/pnpm.cjs run dev"
        ));
        assert!(is_pnpm_command("corepack pnpm install"));
        assert!(!is_pnpm_command("worktree-gc collect pnpm"));
        assert!(!is_pnpm_command("cargo test pnpm_collector"));
    }

    #[test]
    fn command_matching_identifies_surviving_dlx_children() {
        let store = Path::new("/cache/pnpm/store/v10");
        let cache = Path::new("/cache/pnpm/cache");

        assert!(command_mentions_pnpm_root(
            "node /cache/pnpm/cache/dlx/key/pkg/node_modules/tool/bin.js",
            [store, cache]
        ));
        assert!(!command_mentions_pnpm_root(
            "node /workspace/tool/bin.js",
            [store, cache]
        ));
    }

    #[test]
    fn owner_process_summaries_do_not_persist_arguments() {
        assert_eq!(
            owner_process_summary("42", "/usr/bin/node /cache/pnpm/dlx/tool.js --token secret"),
            "42 node"
        );
    }

    #[test]
    fn approval_digest_validation_requires_a_prefixed_full_sha256() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(valid_sha256_digest(&format!("sha256:{}", "A0".repeat(32))));
        assert!(!valid_sha256_digest(&"a".repeat(64)));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "a".repeat(63))));
        assert!(!valid_sha256_digest(&format!("sha256:{}g", "a".repeat(63))));
    }

    #[test]
    fn approval_digest_is_stable_and_binds_policy_and_candidates() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let store = root.join("store");
        let cache = root.join("cache");
        fs::create_dir_all(store.join("files/00"))?;
        fs::create_dir_all(&cache)?;
        fs::write(store.join("files/00/candidate"), b"candidate")?;
        let identity = PnpmIdentity {
            executable: PathBuf::from("pnpm"),
            canonical_executable: PathBuf::from("pnpm"),
            version: SUPPORTED_PNPM_PLANNER_VERSION.into(),
            store_path: store.clone(),
            cache_path: cache,
        };
        let options = PnpmCollectOptions {
            fresh: true,
            now: UNIX_EPOCH + std::time::Duration::from_secs(1_000),
            ..PnpmCollectOptions::default()
        };

        let first = snapshot_pnpm(&identity, &options)?;
        let repeated = snapshot_pnpm(&identity, &options)?;
        assert_eq!(first.approval_digest, repeated.approval_digest);
        assert!(valid_sha256_digest(&first.approval_digest));

        let mut different_policy = options.clone();
        different_policy.dlx_days += 1;
        let policy_plan = snapshot_pnpm(&identity, &different_policy)?;
        assert_ne!(first.approval_digest, policy_plan.approval_digest);

        fs::write(store.join("tmp"), b"interrupted pnpm state")?;
        let changed_candidates = snapshot_pnpm(&identity, &options)?;
        assert_ne!(first.approval_digest, changed_candidates.approval_digest);
        Ok(())
    }

    #[test]
    fn lsof_snapshot_keeps_only_paths_inside_pnpm_roots() {
        let store = PathBuf::from("/cache/pnpm/store/v10");
        let cache = PathBuf::from("/cache/pnpm/cache");
        let paths = parse_lsof_paths(
            b"p1\0fcwd\0n/cache/pnpm/store/v10/files/aa/hash\0\nf4\0n/cache/pnpm/cache/dlx/key/pkg\0n/cache/pnpm/cache/dlx/key/with\nnewline\0\np2\0n/cache/other/file\0\n",
            &[&store, &cache],
        );
        assert_eq!(
            paths,
            vec![
                PathBuf::from("/cache/pnpm/cache/dlx/key/pkg"),
                PathBuf::from("/cache/pnpm/cache/dlx/key/with\nnewline"),
                PathBuf::from("/cache/pnpm/store/v10/files/aa/hash"),
            ]
        );
    }

    #[test]
    fn content_snapshot_selects_only_single_link_non_json_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let files = temp.path().join("files");
        let prefix = files.join("ab");
        fs::create_dir_all(&prefix)?;
        fs::write(prefix.join("eligible"), b"eligible")?;
        fs::write(prefix.join("index.json"), b"{}")?;
        let linked = prefix.join("linked");
        fs::write(&linked, b"linked")?;
        fs::hard_link(&linked, temp.path().join("consumer"))?;

        let mut remaining = 100;
        let snapshot = snapshot_content(&files, &mut remaining, 1, None, "test", 1)?;
        assert!(snapshot.complete);
        assert_eq!(snapshot.files, 1);
        assert_eq!(snapshot.metrics.logical_bytes, 8);
        assert_eq!(fs::metadata(linked)?.nlink(), 2);
        Ok(())
    }

    #[test]
    fn content_snapshot_is_deterministic_across_bounded_parallelism() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let files = temp.path().join("files");
        for prefix in ["00", "01", "02", "03"] {
            let directory = files.join(prefix);
            fs::create_dir_all(&directory)?;
            fs::write(directory.join(format!("{prefix}-a")), b"alpha")?;
            fs::write(directory.join(format!("{prefix}-b")), b"beta")?;
        }

        let mut serial_remaining = 100;
        let serial = snapshot_content(&files, &mut serial_remaining, 1, None, "test", 1)?;
        let mut parallel_remaining = 100;
        let parallel = snapshot_content(&files, &mut parallel_remaining, 4, None, "test", 1)?;

        assert!(serial.complete);
        assert!(parallel.complete);
        assert_eq!(serial.digest, parallel.digest);
        assert_eq!(serial.files, parallel.files);
        assert_eq!(serial.metrics.logical_bytes, parallel.metrics.logical_bytes);
        assert_eq!(serial_remaining, parallel_remaining);
        Ok(())
    }

    #[test]
    fn content_snapshot_parallelism_preserves_the_global_entry_budget() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let files = temp.path().join("files");
        for prefix in ["00", "01"] {
            let directory = files.join(prefix);
            fs::create_dir_all(&directory)?;
            for index in 0..5 {
                fs::write(directory.join(format!("{index}")), b"candidate")?;
            }
        }

        let mut remaining = 6;
        let snapshot = snapshot_content(&files, &mut remaining, 2, None, "test", 1)?;
        assert!(!snapshot.complete);
        assert_eq!(remaining, 0);
        assert_eq!(snapshot.files, 4);
        Ok(())
    }

    #[test]
    fn bounded_content_evidence_converges_without_becoming_execution_proof() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let files = temp.path().join("files");
        let cache_path = temp.path().join("evidence.json");
        for prefix in ["00", "01", "02"] {
            let directory = files.join(prefix);
            fs::create_dir_all(&directory)?;
            for index in 0..3 {
                fs::write(directory.join(index.to_string()), b"candidate")?;
            }
        }

        let mut first_remaining = 7;
        let first = snapshot_content(
            &files,
            &mut first_remaining,
            1,
            Some(&cache_path),
            "test",
            10,
        )?;
        assert_eq!(first.evidence.covered_prefixes, 1);
        assert_eq!(first.evidence.pending_prefixes, 2);
        assert!(!first.complete);

        let mut second_remaining = 7;
        let second = snapshot_content(
            &files,
            &mut second_remaining,
            1,
            Some(&cache_path),
            "test",
            20,
        )?;
        assert_eq!(second.evidence.cached_prefixes, 1);
        assert_eq!(second.evidence.covered_prefixes, 2);
        assert_eq!(second.evidence.pending_prefixes, 1);

        let mut third_remaining = 7;
        let third = snapshot_content(
            &files,
            &mut third_remaining,
            1,
            Some(&cache_path),
            "test",
            30,
        )?;
        assert!(third.evidence.coverage_complete);
        assert!(!third.evidence.point_in_time_complete);
        assert!(!third.complete);
        assert_eq!(third.files, 9);

        // A changed prefix is rescanned, while unchanged historical evidence
        // remains reusable for advisory coverage.
        fs::write(files.join("01/new"), b"new candidate")?;
        let mut fourth_remaining = 100;
        let fourth = snapshot_content(
            &files,
            &mut fourth_remaining,
            1,
            Some(&cache_path),
            "test",
            40,
        )?;
        assert_eq!(fourth.evidence.cached_prefixes, 2);
        assert_eq!(fourth.evidence.freshly_scanned_prefixes, 1);
        assert!(fourth.evidence.coverage_complete);
        assert!(!fourth.complete);
        assert_eq!(fourth.files, 10);

        let mut expired_remaining = 100;
        let expired = snapshot_content(
            &files,
            &mut expired_remaining,
            1,
            Some(&cache_path),
            "test",
            PNPM_EVIDENCE_MAX_AGE_SECONDS + 100,
        )?;
        assert_eq!(expired.evidence.cached_prefixes, 0);
        assert_eq!(expired.evidence.freshly_scanned_prefixes, 3);
        assert!(expired.evidence.point_in_time_complete);
        assert!(expired.complete);
        Ok(())
    }

    #[test]
    fn corrupt_content_evidence_cache_is_rebuilt() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let files = temp.path().join("files/00");
        let cache_path = temp.path().join("evidence.json");
        fs::create_dir_all(&files)?;
        fs::write(files.join("candidate"), b"candidate")?;
        fs::write(&cache_path, b"not json")?;

        let mut remaining = 100;
        let snapshot = snapshot_content(
            &temp.path().join("files"),
            &mut remaining,
            1,
            Some(&cache_path),
            "test",
            1,
        )?;
        assert!(snapshot.evidence.coverage_complete);
        let rebuilt: PnpmEvidenceCache = serde_json::from_slice(&fs::read(cache_path)?)?;
        assert_eq!(rebuilt.cache_version, PNPM_EVIDENCE_CACHE_VERSION);
        assert_eq!(rebuilt.prefixes.len(), 1);
        Ok(())
    }

    #[test]
    fn dlx_candidates_use_pkg_link_age_and_detect_orphans() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cache = temp.path().canonicalize()?;
        let dlx = cache.join("dlx");
        let expired = dlx.join("expired");
        let loose = dlx.join("loose");
        let recent = dlx.join("recent");
        let orphan = dlx.join("orphan");
        fs::create_dir_all(&expired)?;
        fs::create_dir_all(&recent)?;
        fs::create_dir_all(&orphan)?;
        fs::write(&loose, b"orphan cache entry")?;
        fs::create_dir(recent.join("target"))?;
        fs::create_dir(recent.join("stale"))?;
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("target", expired.join("pkg"))?;
            std::os::unix::fs::symlink("target", recent.join("pkg"))?;
            std::os::unix::fs::symlink("target", recent.join("alias"))?;
        }
        let old = filetime::FileTime::from_unix_time(1, 0);
        filetime::set_symlink_file_times(expired.join("pkg"), old, old)?;

        let candidates = dlx_candidates(&cache, 7, SystemTime::now())?;
        assert_eq!(candidates.expired_entries, vec![expired]);
        assert_eq!(candidates.orphan_entries, vec![orphan]);
        assert_eq!(
            candidates.stale_children,
            vec![recent.join("alias"), recent.join("stale")]
        );
        assert_eq!(candidates.unsupported_entries, vec![loose]);
        Ok(())
    }

    #[test]
    fn dlx_candidates_do_not_follow_symlinked_cache_entries() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let cache = temp.path().join("cache");
        let dlx = cache.join("dlx");
        let external = temp.path().join("external");
        fs::create_dir_all(&dlx)?;
        fs::create_dir_all(&external)?;
        std::os::unix::fs::symlink(&external, dlx.join("linked"))?;

        let candidates = dlx_candidates(&cache, 7, SystemTime::now())?;
        assert_eq!(candidates.unsupported_entries, vec![dlx.join("linked")]);
        assert!(candidates.expired_entries.is_empty());
        assert!(candidates.orphan_entries.is_empty());
        assert!(candidates.stale_children.is_empty());
        Ok(())
    }

    #[test]
    fn snapshot_includes_non_directory_store_tmp_entry() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = temp.path().join("store");
        let cache = temp.path().join("cache");
        fs::create_dir_all(store.join("files"))?;
        fs::create_dir_all(&cache)?;
        fs::write(store.join("tmp"), b"interrupted pnpm temp state")?;
        let identity = PnpmIdentity {
            executable: PathBuf::from("pnpm"),
            canonical_executable: PathBuf::from("pnpm"),
            version: SUPPORTED_PNPM_PLANNER_VERSION.into(),
            store_path: store.clone(),
            cache_path: cache,
        };

        let plan = snapshot_pnpm(&identity, &fresh_options())?;
        assert!(plan.content_evidence.cache_path.is_none());
        assert_eq!(plan.store_tmp, Some(store.join("tmp")));
        Ok(())
    }

    #[test]
    fn snapshot_blocks_symlinked_domain_traversal_roots() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().canonicalize()?;
        let store = root.join("store");
        let cache = root.join("cache");
        let external_files = root.join("external-files");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&cache)?;
        fs::create_dir_all(&external_files)?;
        std::os::unix::fs::symlink(&external_files, store.join("files"))?;
        let identity = PnpmIdentity {
            executable: PathBuf::from("pnpm"),
            canonical_executable: PathBuf::from("pnpm"),
            version: SUPPORTED_PNPM_PLANNER_VERSION.into(),
            store_path: store.clone(),
            cache_path: cache,
        };

        let mut plan = snapshot_pnpm(&identity, &fresh_options())?;
        assert!(plan.content_evidence.cache_path.is_none());
        assert_eq!(plan.unsupported_layout_paths, vec![store.join("files")]);
        plan.open_handle_check_complete = true;
        assert_eq!(classify_plan(&plan), PnpmPruneAction::UnsupportedLayout);
        Ok(())
    }

    #[test]
    fn unreviewed_pnpm_version_keeps_the_collector_report_only() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = temp.path().join("store");
        let cache = temp.path().join("cache");
        fs::create_dir_all(store.join("files"))?;
        fs::create_dir_all(&cache)?;
        let identity = PnpmIdentity {
            executable: PathBuf::from("pnpm"),
            canonical_executable: PathBuf::from("pnpm"),
            version: "10.33.0".into(),
            store_path: store,
            cache_path: cache,
        };

        let mut plan = snapshot_pnpm(&identity, &fresh_options())?;
        assert!(plan.content_evidence.cache_path.is_none());
        plan.open_handle_check_complete = true;
        assert!(!plan.planner_supported);
        assert_eq!(classify_plan(&plan), PnpmPruneAction::UnsupportedVersion);
        Ok(())
    }

    #[test]
    fn filesystem_observations_deduplicate_store_and_cache_on_one_device() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let store = temp.path().join("store");
        let cache = temp.path().join("cache");
        fs::create_dir_all(&store)?;
        fs::create_dir_all(&cache)?;
        let identity = PnpmIdentity {
            executable: PathBuf::from("pnpm"),
            canonical_executable: PathBuf::from("pnpm"),
            version: SUPPORTED_PNPM_PLANNER_VERSION.into(),
            store_path: store.clone(),
            cache_path: cache,
        };

        let observations = observe_filesystems(&identity)?;
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].observed_at, store);
        assert!(observations[0].available_bytes > 0);
        Ok(())
    }
}
