use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::{format_bytes, CleanupMode};
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const CODEX_SESSION_MANIFEST_VERSION: u64 = 3;
const TOP_SESSION_LIMIT: usize = 30;
pub const DEFAULT_CODEX_SESSION_MAX_ENTRIES: u64 = 20_000;

#[derive(Debug, Clone)]
pub struct CodexSessionCollectOptions {
    pub codex_home: Option<PathBuf>,
    pub profile: Option<String>,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for CodexSessionCollectOptions {
    fn default() -> Self {
        Self {
            codex_home: None,
            profile: None,
            max_entries: DEFAULT_CODEX_SESSION_MAX_ENTRIES,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CodexSessionCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: CodexSessionCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct CodexSessionCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub identity: CodexSessionIdentity,
    pub policy: CodexSessionPolicy,
    pub compression_health: CodexCompressionHealth,
    pub plan: CodexSessionPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionIdentity {
    pub codex_home: PathBuf,
    pub sessions_root: PathBuf,
    pub archived_sessions_root: PathBuf,
    pub state_database: PathBuf,
    pub config_path: PathBuf,
    pub selected_profile: Option<String>,
    pub profile_config_path: Option<PathBuf>,
    pub discovered_profile_config_paths: Vec<PathBuf>,
    pub compression_marker_path: PathBuf,
    pub sqlite_executable: Option<PathBuf>,
    pub sqlite_version: Option<String>,
    pub state_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionPolicy {
    pub transcript_content: &'static str,
    pub execution: &'static str,
    pub configuration: &'static str,
    pub restart: &'static str,
    pub retention: &'static str,
    pub unattended_execution_supported: bool,
    pub max_entries: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexCompressionHealthStatus {
    Enabled,
    NotConfigured,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexCompressionHealth {
    pub status: CodexCompressionHealthStatus,
    pub reason: String,
    pub configured_enabled: Option<bool>,
    pub config_error: Option<String>,
    pub marker: CodexCompressionMarker,
    pub temporary_artifacts: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexCompressionMarker {
    pub present: bool,
    pub regular_file: bool,
    pub size_bytes: Option<u64>,
    pub modified_at_unix: Option<u64>,
    pub age_seconds: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSessionPlanAction {
    NoWork,
    ReportOnly,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionPlan {
    pub action: CodexSessionPlanAction,
    pub reason: String,
    pub complete: bool,
    pub discovery_visited_entries: u64,
    pub live: CodexSessionSummary,
    pub archived: CodexSessionSummary,
    pub unindexed: CodexUnindexedSummary,
    pub format_summaries: Vec<CodexSessionFormatSummary>,
    pub age_buckets: Vec<CodexSessionAgeBucket>,
    pub largest_sessions: Vec<CodexSessionObservation>,
    pub missing_files: Vec<PathBuf>,
    pub unindexed_files: Vec<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CodexUnindexedSummary {
    pub count: u64,
    pub live_count: u64,
    pub archived_count: u64,
    pub plain_count: u64,
    pub compressed_count: u64,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct CodexSessionSummary {
    pub count: u64,
    pub plain_count: u64,
    pub compressed_count: u64,
    pub metrics: InventoryMetrics,
    pub plain_metrics: InventoryMetrics,
    pub compressed_metrics: InventoryMetrics,
    pub oldest_created_at_unix: Option<u64>,
    pub newest_updated_at_unix: Option<u64>,
    pub oldest_archived_at_unix: Option<u64>,
    pub newest_archived_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexSessionFileFormat {
    Jsonl,
    JsonlZstd,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionFormatSummary {
    pub archived: bool,
    pub format: CodexSessionFileFormat,
    pub count: u64,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionAgeBucket {
    pub archived: bool,
    pub min_age_days: u64,
    pub max_age_days_exclusive: Option<u64>,
    pub count: u64,
    pub plain_count: u64,
    pub compressed_count: u64,
    pub metrics: InventoryMetrics,
    pub plain_metrics: InventoryMetrics,
    pub compressed_metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexSessionObservation {
    pub thread_id: String,
    pub path: PathBuf,
    pub archived: bool,
    pub format: CodexSessionFileFormat,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub archived_at_unix: Option<u64>,
    pub age_days: u64,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Deserialize)]
struct ThreadRow {
    id: String,
    rollout_path: PathBuf,
    created_at: u64,
    updated_at: u64,
    archived: u64,
    archived_at: Option<u64>,
}

#[derive(Debug)]
struct DiscoveredSessionStore {
    files: Vec<PathBuf>,
    temporary_artifacts: Vec<PathBuf>,
    complete: bool,
    visited_entries: u64,
    errors: Vec<String>,
}

#[derive(Debug)]
struct CompressionConfigInspection {
    configured_enabled: Option<bool>,
    error: Option<String>,
    selected_profile: Option<String>,
    profile_config_path: Option<PathBuf>,
    discovered_profile_config_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PhysicalFileIdentity {
    volume: u64,
    file: u64,
}

pub fn collect_codex_sessions(
    options: CodexSessionCollectOptions,
) -> Result<CodexSessionCollectRun> {
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    let codex_home = options.codex_home.map_or_else(default_codex_home, Ok)?;
    let codex_home = canonical_real_directory(&codex_home, "Codex home")?;
    let sessions_root =
        canonical_real_or_absent_directory(&codex_home.join("sessions"), "Codex sessions")?;
    let archived_sessions_root = canonical_real_or_absent_directory(
        &codex_home.join("archived_sessions"),
        "Codex archived sessions",
    )?;
    let state_database = codex_home.join("state_5.sqlite");
    let config_path = codex_home.join("config.toml");
    let compression_marker_path = codex_home.join(".tmp/rollout-compression.lock");
    let (rows, sqlite_executable, sqlite_version, state_error) = query_threads(&state_database);
    let config =
        inspect_compression_configuration(&codex_home, &config_path, options.profile.as_deref())?;
    let identity = CodexSessionIdentity {
        codex_home,
        sessions_root: sessions_root.clone(),
        archived_sessions_root: archived_sessions_root.clone(),
        state_database,
        config_path: config_path.clone(),
        selected_profile: config.selected_profile,
        profile_config_path: config.profile_config_path,
        discovered_profile_config_paths: config.discovered_profile_config_paths,
        compression_marker_path: compression_marker_path.clone(),
        sqlite_executable,
        sqlite_version,
        state_error: state_error.clone(),
    };
    let now_unix = unix_seconds(options.now);
    let (mut plan, temporary_artifacts) = build_plan(
        rows,
        state_error,
        &sessions_root,
        &archived_sessions_root,
        options.max_entries,
        now_unix,
    )?;
    let marker = inspect_compression_marker(&compression_marker_path, now_unix);
    let compression_health = compression_health(
        config.configured_enabled,
        config.error,
        marker,
        temporary_artifacts,
        plan.complete,
    );
    if compression_health.status == CodexCompressionHealthStatus::Incomplete {
        plan.complete = false;
        plan.action = CodexSessionPlanAction::Incomplete;
        plan.reason =
            "task storage or compression-health evidence is incomplete; report remains advisory"
                .to_string();
    }
    let manifest = CodexSessionCollectManifest {
        manifest_version: CODEX_SESSION_MANIFEST_VERSION,
        collector: "codex-sessions",
        run_id: format!("{}-{}", unix_nanos(options.now), std::process::id()),
        mode: CleanupMode::DryRun,
        generated_at_unix: now_unix,
        identity,
        policy: CodexSessionPolicy {
            transcript_content: "never_read",
            execution: "report_only",
            configuration: "owner_managed",
            restart: "owner_managed",
            retention: "owner_contract_required",
            unattended_execution_supported: false,
            max_entries: options.max_entries,
        },
        compression_health,
        plan,
    };
    let manifest_path = write_manifest(&manifest)?;
    Ok(CodexSessionCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_codex_sessions_collect(run: &CodexSessionCollectRun) {
    let plan = &run.manifest.plan;
    let health = &run.manifest.compression_health;
    println!("collector: codex-sessions");
    println!("mode: report-only (transcript contents are never read)");
    println!("manifest: {}", run.manifest_path.display());
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!("compression: {:?} — {}", health.status, health.reason);
    println!(
        "live tasks: {} total, {} compressed | {} private{} | {} allocated",
        plan.live.count,
        plan.live.compressed_count,
        format_bytes(plan.live.metrics.private_reclaimable_bytes),
        private_measurement_qualifier(&plan.live.metrics),
        format_bytes(plan.live.metrics.allocated_bytes)
    );
    println!(
        "archived tasks: {} total, {} compressed | {} private{} | {} allocated",
        plan.archived.count,
        plan.archived.compressed_count,
        format_bytes(plan.archived.metrics.private_reclaimable_bytes),
        private_measurement_qualifier(&plan.archived.metrics),
        format_bytes(plan.archived.metrics.allocated_bytes)
    );
    println!(
        "unindexed rollouts: {} total ({} live, {} archived), {} compressed | {} private{} | {} allocated",
        plan.unindexed.count,
        plan.unindexed.live_count,
        plan.unindexed.archived_count,
        plan.unindexed.compressed_count,
        format_bytes(plan.unindexed.metrics.private_reclaimable_bytes),
        private_measurement_qualifier(&plan.unindexed.metrics),
        format_bytes(plan.unindexed.metrics.allocated_bytes)
    );
    println!(
        "correlation: {} missing files | {} unindexed files | {} temporary artifacts | {} errors",
        plan.missing_files.len(),
        plan.unindexed_files.len(),
        health.temporary_artifacts.len(),
        plan.errors.len()
    );
    println!("execution: none; Codex owns compression, retention, and task lifecycle");
}

fn build_plan(
    rows: Vec<ThreadRow>,
    state_error: Option<String>,
    sessions_root: &Path,
    archived_sessions_root: &Path,
    max_entries: u64,
    now_unix: u64,
) -> Result<(CodexSessionPlan, Vec<PathBuf>)> {
    let mut errors = state_error.into_iter().collect::<Vec<_>>();
    let discovery = discover_session_files(sessions_root, archived_sessions_root, max_entries)?;
    errors.extend(discovery.errors.clone());
    let disk_paths = discovery.files.iter().cloned().collect::<BTreeSet<_>>();
    let mut valid_rows = Vec::new();
    let mut indexed_paths = BTreeSet::new();
    let mut missing_files = Vec::new();
    for row in rows {
        let archived = match row.archived {
            0 => false,
            1 => true,
            other => {
                errors.push(format!(
                    "thread {} has unsupported archived value {other}",
                    row.id
                ));
                continue;
            }
        };
        let expected_root = if archived {
            archived_sessions_root
        } else {
            sessions_root
        };
        if !row.rollout_path.starts_with(expected_root) {
            errors.push(format!(
                "thread {} rollout path is outside its expected session root",
                row.id
            ));
            continue;
        }
        match resolve_physical_rollout(&row.rollout_path, &disk_paths, expected_root, &row.id) {
            Ok(Some((path, format))) => {
                indexed_paths.insert(path.clone());
                valid_rows.push((row, path, format));
            }
            Ok(None) => missing_files.push(row.rollout_path),
            Err(error) => errors.push(format!("thread {}: {error}", row.id)),
        }
    }
    missing_files.sort();
    let mut unindexed_files = disk_paths
        .difference(&indexed_paths)
        .cloned()
        .collect::<Vec<_>>();
    unindexed_files.sort();

    let paths = disk_paths.iter().cloned().collect::<Vec<_>>();
    let (measurements, measurement_errors) = measure_session_files(&paths, max_entries);
    errors.extend(measurement_errors);
    let mut observations = Vec::with_capacity(valid_rows.len());
    for (row, path, format) in valid_rows {
        let metrics = measurements
            .get(&path)
            .cloned()
            .unwrap_or_else(incomplete_metrics);
        let archived = row.archived == 1;
        let activity = if archived {
            row.archived_at.unwrap_or(row.updated_at)
        } else {
            row.updated_at
        };
        observations.push(CodexSessionObservation {
            thread_id: row.id,
            path,
            archived,
            format,
            created_at_unix: row.created_at,
            updated_at_unix: row.updated_at,
            archived_at_unix: row.archived_at,
            age_days: now_unix.saturating_sub(activity) / 86_400,
            metrics,
        });
    }
    let unindexed = summarize_unindexed(
        &unindexed_files,
        &measurements,
        sessions_root,
        archived_sessions_root,
    );
    let live = summarize(
        observations
            .iter()
            .filter(|observation| !observation.archived),
    );
    let archived = summarize(
        observations
            .iter()
            .filter(|observation| observation.archived),
    );
    let format_summaries = summarize_formats(&observations);
    let age_buckets = age_buckets(&observations);
    let mut largest_sessions = observations;
    largest_sessions.sort_by(|left, right| {
        right
            .metrics
            .private_reclaimable_bytes
            .cmp(&left.metrics.private_reclaimable_bytes)
            .then_with(|| left.path.cmp(&right.path))
    });
    largest_sessions.truncate(TOP_SESSION_LIMIT);
    let complete = discovery.complete
        && errors.is_empty()
        && missing_files.is_empty()
        && unindexed_files.is_empty()
        && live.metrics.private_reclaimable_complete
        && archived.metrics.private_reclaimable_complete;
    let (action, reason) = if !complete {
        (
            CodexSessionPlanAction::Incomplete,
            "task index, traversal, path correlation, or APFS measurement evidence is incomplete"
                .into(),
        )
    } else if live.count == 0 && archived.count == 0 {
        (
            CodexSessionPlanAction::NoWork,
            "Codex has no indexed task files".into(),
        )
    } else {
        (
            CodexSessionPlanAction::ReportOnly,
            "Codex task storage is correlated and measured; Codex retains lifecycle authority"
                .into(),
        )
    };
    Ok((
        CodexSessionPlan {
            action,
            reason,
            complete,
            discovery_visited_entries: discovery.visited_entries,
            live,
            archived,
            unindexed,
            format_summaries,
            age_buckets,
            largest_sessions,
            missing_files,
            unindexed_files,
            errors,
        },
        discovery.temporary_artifacts,
    ))
}

fn resolve_physical_rollout(
    indexed_path: &Path,
    disk_paths: &BTreeSet<PathBuf>,
    expected_root: &Path,
    thread_id: &str,
) -> Result<Option<(PathBuf, CodexSessionFileFormat)>> {
    let mut candidates = Vec::new();
    for candidate in rollout_path_spellings(indexed_path) {
        if disk_paths.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates.sort();
    candidates.dedup();
    match candidates.len() {
        0 => return Ok(None),
        1 => {}
        count => anyhow::bail!(
            "indexed rollout has {count} physical JSONL spellings; refusing ambiguous correlation"
        ),
    }
    let path = candidates.pop().expect("one candidate remains");
    anyhow::ensure!(
        path.starts_with(expected_root),
        "physical rollout is outside its expected session root"
    );
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect rollout file {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "physical rollout is not a regular non-symlink file"
    );
    let resolved = path
        .canonicalize()
        .with_context(|| format!("resolve rollout file {}", path.display()))?;
    anyhow::ensure!(
        resolved == path,
        "physical rollout traverses a symlink or noncanonical component"
    );
    let format =
        session_file_format(&path).context("physical rollout does not use .jsonl or .jsonl.zst")?;
    anyhow::ensure!(
        path.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.contains(thread_id)),
        "physical rollout filename does not preserve its thread identity"
    );
    Ok(Some((path, format)))
}

fn rollout_path_spellings(indexed_path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![indexed_path.to_path_buf()];
    let Some(file_name) = indexed_path.file_name() else {
        return paths;
    };
    let mut name = file_name.to_os_string();
    if indexed_path.to_string_lossy().ends_with(".jsonl.zst") {
        if let Some(stripped) = file_name
            .to_str()
            .and_then(|value| value.strip_suffix(".zst"))
        {
            paths.push(indexed_path.with_file_name(stripped));
        }
    } else if indexed_path.to_string_lossy().ends_with(".jsonl") {
        name.push(".zst");
        paths.push(indexed_path.with_file_name(name));
    }
    paths
}

fn session_file_format(path: &Path) -> Option<CodexSessionFileFormat> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".jsonl.zst") {
        Some(CodexSessionFileFormat::JsonlZstd)
    } else if name.ends_with(".jsonl") {
        Some(CodexSessionFileFormat::Jsonl)
    } else {
        None
    }
}

fn summarize<'a>(
    observations: impl Iterator<Item = &'a CodexSessionObservation>,
) -> CodexSessionSummary {
    observations.fold(empty_summary(), |mut summary, observation| {
        summary.count = summary.count.saturating_add(1);
        add_metrics(&mut summary.metrics, &observation.metrics);
        match observation.format {
            CodexSessionFileFormat::Jsonl => {
                summary.plain_count = summary.plain_count.saturating_add(1);
                add_metrics(&mut summary.plain_metrics, &observation.metrics);
            }
            CodexSessionFileFormat::JsonlZstd => {
                summary.compressed_count = summary.compressed_count.saturating_add(1);
                add_metrics(&mut summary.compressed_metrics, &observation.metrics);
            }
        }
        summary.oldest_created_at_unix = Some(
            summary
                .oldest_created_at_unix
                .map_or(observation.created_at_unix, |value| {
                    value.min(observation.created_at_unix)
                }),
        );
        summary.newest_updated_at_unix = Some(
            summary
                .newest_updated_at_unix
                .map_or(observation.updated_at_unix, |value| {
                    value.max(observation.updated_at_unix)
                }),
        );
        if let Some(archived_at) = observation.archived_at_unix {
            summary.oldest_archived_at_unix = Some(
                summary
                    .oldest_archived_at_unix
                    .map_or(archived_at, |value| value.min(archived_at)),
            );
            summary.newest_archived_at_unix = Some(
                summary
                    .newest_archived_at_unix
                    .map_or(archived_at, |value| value.max(archived_at)),
            );
        }
        summary
    })
}

fn summarize_unindexed(
    paths: &[PathBuf],
    measurements: &BTreeMap<PathBuf, InventoryMetrics>,
    sessions_root: &Path,
    archived_sessions_root: &Path,
) -> CodexUnindexedSummary {
    let mut summary = CodexUnindexedSummary {
        metrics: empty_metrics(),
        ..CodexUnindexedSummary::default()
    };
    for path in paths {
        summary.count = summary.count.saturating_add(1);
        if path.starts_with(archived_sessions_root) {
            summary.archived_count = summary.archived_count.saturating_add(1);
        } else if path.starts_with(sessions_root) {
            summary.live_count = summary.live_count.saturating_add(1);
        }
        match session_file_format(path) {
            Some(CodexSessionFileFormat::Jsonl) => {
                summary.plain_count = summary.plain_count.saturating_add(1);
            }
            Some(CodexSessionFileFormat::JsonlZstd) => {
                summary.compressed_count = summary.compressed_count.saturating_add(1);
            }
            None => {}
        }
        let metrics = measurements
            .get(path)
            .cloned()
            .unwrap_or_else(incomplete_metrics);
        add_metrics(&mut summary.metrics, &metrics);
    }
    summary
}

fn empty_summary() -> CodexSessionSummary {
    CodexSessionSummary {
        metrics: empty_metrics(),
        plain_metrics: empty_metrics(),
        compressed_metrics: empty_metrics(),
        ..CodexSessionSummary::default()
    }
}

fn summarize_formats(observations: &[CodexSessionObservation]) -> Vec<CodexSessionFormatSummary> {
    let mut summaries = Vec::new();
    for archived in [false, true] {
        for format in [
            CodexSessionFileFormat::Jsonl,
            CodexSessionFileFormat::JsonlZstd,
        ] {
            let mut summary = CodexSessionFormatSummary {
                archived,
                format,
                count: 0,
                metrics: empty_metrics(),
            };
            for observation in observations
                .iter()
                .filter(|entry| entry.archived == archived && entry.format == format)
            {
                summary.count = summary.count.saturating_add(1);
                add_metrics(&mut summary.metrics, &observation.metrics);
            }
            summaries.push(summary);
        }
    }
    summaries
}

fn age_buckets(observations: &[CodexSessionObservation]) -> Vec<CodexSessionAgeBucket> {
    let ranges = [(0, Some(7)), (7, Some(30)), (30, Some(90)), (90, None)];
    let mut buckets = Vec::new();
    for archived in [false, true] {
        for (min_age_days, max_age_days_exclusive) in ranges {
            let matching = observations.iter().filter(|observation| {
                observation.archived == archived
                    && observation.age_days >= min_age_days
                    && max_age_days_exclusive.is_none_or(|maximum| observation.age_days < maximum)
            });
            let summary = summarize(matching);
            buckets.push(CodexSessionAgeBucket {
                archived,
                min_age_days,
                max_age_days_exclusive,
                count: summary.count,
                plain_count: summary.plain_count,
                compressed_count: summary.compressed_count,
                metrics: summary.metrics,
                plain_metrics: summary.plain_metrics,
                compressed_metrics: summary.compressed_metrics,
            });
        }
    }
    buckets
}

fn empty_metrics() -> InventoryMetrics {
    InventoryMetrics {
        private_reclaimable_complete: true,
        ..InventoryMetrics::default()
    }
}

fn incomplete_metrics() -> InventoryMetrics {
    InventoryMetrics {
        private_reclaimable_complete: false,
        ..InventoryMetrics::default()
    }
}

fn add_metrics(total: &mut InventoryMetrics, metrics: &InventoryMetrics) {
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
}

fn measure_session_files(
    paths: &[PathBuf],
    max_entries: u64,
) -> (BTreeMap<PathBuf, InventoryMetrics>, Vec<String>) {
    let mut remaining_entries = max_entries;
    let mut measurements = BTreeMap::new();
    let mut errors = Vec::new();
    let mut measured_files = BTreeSet::new();
    for path in paths {
        if remaining_entries == 0 {
            errors.push(format!(
                "bounded inventory did not measure {} because its shared entry budget was exhausted",
                path.display()
            ));
            continue;
        }
        let identity = match fs::symlink_metadata(path) {
            Ok(metadata) => physical_file_identity(&metadata),
            Err(error) => {
                remaining_entries = remaining_entries.saturating_sub(1);
                errors.push(format!(
                    "inspect Codex rollout identity {}: {error}",
                    path.display()
                ));
                continue;
            }
        };
        if identity.is_some_and(|identity| !measured_files.insert(identity)) {
            remaining_entries = remaining_entries.saturating_sub(1);
            let mut metrics = empty_metrics();
            metrics.hardlink_duplicates = 1;
            measurements.insert(path.clone(), metrics);
            continue;
        }
        let report = inventory(
            std::slice::from_ref(path),
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: remaining_entries,
                one_filesystem: true,
            },
        );
        match report {
            Ok(report) => {
                let Some(root) = report.roots.into_iter().next() else {
                    remaining_entries = remaining_entries.saturating_sub(1);
                    errors.push(format!(
                        "bounded inventory returned no measurement for {}",
                        path.display()
                    ));
                    continue;
                };
                remaining_entries = remaining_entries.saturating_sub(root.visited_entries.max(1));
                if !root.complete || !root.errors.is_empty() {
                    errors.push(format!(
                        "bounded inventory did not completely measure {}",
                        path.display()
                    ));
                }
                measurements.insert(path.clone(), root.metrics);
            }
            Err(error) => {
                // Codex may archive, compress, or delete a rollout after the
                // index and directory snapshots. Preserve the rest of the
                // advisory report and make this exact file incomplete.
                remaining_entries = remaining_entries.saturating_sub(1);
                errors.push(format!("measure Codex rollout {}: {error}", path.display()));
            }
        }
    }
    (measurements, errors)
}

#[cfg(unix)]
fn physical_file_identity(metadata: &fs::Metadata) -> Option<PhysicalFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(PhysicalFileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(not(unix))]
fn physical_file_identity(_metadata: &fs::Metadata) -> Option<PhysicalFileIdentity> {
    None
}

fn discover_session_files(
    sessions_root: &Path,
    archived_sessions_root: &Path,
    max_entries: u64,
) -> Result<DiscoveredSessionStore> {
    let mut queue = VecDeque::new();
    let mut files = Vec::new();
    let mut temporary_artifacts = Vec::new();
    let mut errors = Vec::new();
    let mut visited_entries = 0_u64;
    let mut complete = true;
    for (root, label) in [
        (sessions_root, "Codex sessions"),
        (archived_sessions_root, "Codex archived sessions"),
    ] {
        match fs::symlink_metadata(root) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                queue.push_back(root.to_path_buf());
            }
            Ok(_) => {
                errors.push(format!(
                    "{label} is not a non-symlink directory: {}",
                    root.display()
                ));
                complete = false;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // Codex creates each store lazily. Absence is a complete,
                // empty physical root for a fresh installation.
            }
            Err(error) => {
                errors.push(format!("inspect {label} {}: {error}", root.display()));
                complete = false;
            }
        }
    }
    while let Some(directory) = queue.pop_front() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                errors.push(format!(
                    "read Codex session directory {}: {error}",
                    directory.display()
                ));
                complete = false;
                continue;
            }
        };
        for entry in entries {
            if visited_entries >= max_entries {
                complete = false;
                break;
            }
            visited_entries = visited_entries.saturating_add(1);
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(format!("read Codex session entry: {error}"));
                    complete = false;
                    continue;
                }
            };
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    errors.push(format!("inspect {}: {error}", path.display()));
                    complete = false;
                    continue;
                }
            };
            if metadata.file_type().is_symlink() {
                errors.push(format!(
                    "session storage contains a symlink: {}",
                    path.display()
                ));
                complete = false;
            } else if metadata.is_dir() {
                queue.push_back(path);
            } else if metadata.is_file() && session_file_format(&path).is_some() {
                files.push(path);
            } else if metadata.is_file() && is_temporary_artifact(&path) {
                temporary_artifacts.push(path);
            } else {
                errors.push(format!(
                    "unrecognized session storage entry: {}",
                    path.display()
                ));
                complete = false;
            }
        }
        if visited_entries >= max_entries {
            if !queue.is_empty() {
                complete = false;
            }
            break;
        }
    }
    files.sort();
    temporary_artifacts.sort();
    Ok(DiscoveredSessionStore {
        files,
        temporary_artifacts,
        complete,
        visited_entries,
        errors,
    })
}

fn is_temporary_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|name| name.ends_with(".tmp") || name.contains(".tmp."))
}

fn inspect_compression_configuration(
    codex_home: &Path,
    config_path: &Path,
    profile: Option<&str>,
) -> Result<CompressionConfigInspection> {
    let (discovered_profile_config_paths, profile_discovery_error) =
        discover_profile_config_paths(codex_home);
    let selected_profile = profile.map(str::to_owned);
    let profile_config_path = profile
        .map(|profile| codex_profile_config_path(codex_home, profile))
        .transpose()?;
    let (configured_enabled, config_read_error) =
        read_compression_setting(config_path, profile_config_path.as_deref());
    let selection_error = if profile.is_none() && !discovered_profile_config_paths.is_empty() {
        Some(format!(
                "Codex profile selection is unknown while {} profile config file(s) exist; pass --profile NAME to inspect the effective layered configuration",
                discovered_profile_config_paths.len()
            ))
    } else {
        None
    };
    let error = [profile_discovery_error, config_read_error, selection_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    Ok(CompressionConfigInspection {
        configured_enabled,
        error: (!error.is_empty()).then(|| error.join("; ")),
        selected_profile,
        profile_config_path,
        discovered_profile_config_paths,
    })
}

fn discover_profile_config_paths(codex_home: &Path) -> (Vec<PathBuf>, Option<String>) {
    let entries = match fs::read_dir(codex_home) {
        Ok(entries) => entries,
        Err(error) => {
            return (
                Vec::new(),
                Some(format!(
                    "discover Codex profile configs in {}: {error}",
                    codex_home.display()
                )),
            )
        }
    };
    let mut paths = Vec::new();
    let mut errors = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(format!("read Codex profile config entry: {error}"));
                continue;
            }
        };
        let path = entry.path();
        if !path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| name.ends_with(".config.toml"))
        {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                match path.canonicalize() {
                    Ok(resolved) if resolved == path => paths.push(path),
                    Ok(_) => errors.push(format!(
                        "Codex profile config is noncanonical: {}",
                        path.display()
                    )),
                    Err(error) => errors.push(format!(
                        "resolve Codex profile config {}: {error}",
                        path.display()
                    )),
                }
            }
            Ok(_) => errors.push(format!(
                "Codex profile config is not a regular non-symlink file: {}",
                path.display()
            )),
            Err(error) => errors.push(format!(
                "inspect Codex profile config {}: {error}",
                path.display()
            )),
        }
    }
    paths.sort();
    (paths, (!errors.is_empty()).then(|| errors.join("; ")))
}

fn codex_profile_config_path(codex_home: &Path, profile: &str) -> Result<PathBuf> {
    // Codex CLI's CONFIG_PROFILE_V2 contract layers this sibling file over
    // config.toml; legacy in-file profile tables are not the `--profile` input.
    anyhow::ensure!(
        !profile.is_empty()
            && !profile.contains(['/', '\\', '\0'])
            && !matches!(profile, "." | ".."),
        "Codex profile must be one literal non-empty name"
    );
    Ok(codex_home.join(format!("{profile}.config.toml")))
}

fn read_compression_setting(
    config_path: &Path,
    profile_config_path: Option<&Path>,
) -> (Option<bool>, Option<String>) {
    let (base, base_error) = read_compression_setting_from_file(config_path, false);
    if base_error.is_some() {
        return (None, base_error);
    }
    let Some(profile_config_path) = profile_config_path else {
        return (base, None);
    };
    let (profile, profile_error) = read_compression_setting_from_file(profile_config_path, true);
    if profile_error.is_some() {
        (None, profile_error)
    } else {
        (profile.or(base), None)
    }
}

fn read_compression_setting_from_file(
    config_path: &Path,
    required: bool,
) -> (Option<bool>, Option<String>) {
    let metadata = match fs::symlink_metadata(config_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => {
            return (None, None);
        }
        Err(error) => {
            return (
                None,
                Some(format!(
                    "inspect Codex config {}: {error}",
                    config_path.display()
                )),
            )
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return (
            None,
            Some(format!(
                "Codex config is not a regular non-symlink file: {}",
                config_path.display()
            )),
        );
    }
    match config_path.canonicalize() {
        Ok(resolved) if resolved == config_path => {}
        Ok(_) => {
            return (
                None,
                Some(format!(
                    "Codex config is noncanonical: {}",
                    config_path.display()
                )),
            )
        }
        Err(error) => {
            return (
                None,
                Some(format!(
                    "resolve Codex config {}: {error}",
                    config_path.display()
                )),
            )
        }
    }
    let text = match fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(error) => {
            return (
                None,
                Some(format!(
                    "read Codex config {}: {error}",
                    config_path.display()
                )),
            )
        }
    };
    let config = match toml::from_str::<toml::Value>(&text) {
        Ok(config) => config,
        Err(error) => {
            return (
                None,
                Some(format!(
                    "parse Codex config {}: {error}",
                    config_path.display()
                )),
            )
        }
    };
    match config
        .get("features")
        .and_then(|features| features.get("local_thread_store_compression"))
    {
        None => (None, None),
        Some(value) => match value.as_bool() {
            Some(value) => (Some(value), None),
            None => (
                None,
                Some(format!(
                    "Codex feature local_thread_store_compression is not a boolean in {}",
                    config_path.display()
                )),
            ),
        },
    }
}

fn inspect_compression_marker(path: &Path, now_unix: u64) -> CodexCompressionMarker {
    match fs::symlink_metadata(path) {
        Ok(metadata) => compression_marker_from_metadata(&metadata, metadata.modified(), now_unix),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CodexCompressionMarker {
            present: false,
            regular_file: false,
            size_bytes: None,
            modified_at_unix: None,
            age_seconds: None,
            error: None,
        },
        Err(error) => CodexCompressionMarker {
            present: false,
            regular_file: false,
            size_bytes: None,
            modified_at_unix: None,
            age_seconds: None,
            error: Some(format!(
                "inspect compression marker {}: {error}",
                path.display()
            )),
        },
    }
}

fn compression_marker_from_metadata(
    metadata: &fs::Metadata,
    modified: io::Result<SystemTime>,
    now_unix: u64,
) -> CodexCompressionMarker {
    let regular_file = metadata.is_file() && !metadata.file_type().is_symlink();
    let (modified_at_unix, modified_error) = match modified {
        Ok(modified) => (Some(unix_seconds(modified)), None),
        Err(error) => (
            None,
            Some(format!(
                "read compression marker modification time: {error}"
            )),
        ),
    };
    let type_error =
        (!regular_file).then(|| "compression marker is not a regular non-symlink file".to_string());
    let error = [type_error, modified_error]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    CodexCompressionMarker {
        present: true,
        regular_file,
        size_bytes: Some(metadata.len()),
        modified_at_unix,
        age_seconds: modified_at_unix.map(|modified| now_unix.saturating_sub(modified)),
        error: (!error.is_empty()).then(|| error.join("; ")),
    }
}

fn compression_health(
    configured_enabled: Option<bool>,
    config_error: Option<String>,
    marker: CodexCompressionMarker,
    temporary_artifacts: Vec<PathBuf>,
    plan_complete: bool,
) -> CodexCompressionHealth {
    let incomplete = !plan_complete
        || config_error.is_some()
        || marker.error.is_some()
        || !temporary_artifacts.is_empty();
    let (status, reason) = if incomplete {
        (
            CodexCompressionHealthStatus::Incomplete,
            "compression health evidence is incomplete or temporary artifacts remain".to_string(),
        )
    } else if configured_enabled == Some(true) {
        (
            CodexCompressionHealthStatus::Enabled,
            "native Codex task-store compression is explicitly enabled".to_string(),
        )
    } else {
        (
            CodexCompressionHealthStatus::NotConfigured,
            "native Codex task-store compression is not explicitly enabled".to_string(),
        )
    };
    CodexCompressionHealth {
        status,
        reason,
        configured_enabled,
        config_error,
        marker,
        temporary_artifacts,
    }
}

fn query_threads(
    database: &Path,
) -> (
    Vec<ThreadRow>,
    Option<PathBuf>,
    Option<String>,
    Option<String>,
) {
    let database = match canonical_state_database(database) {
        Ok(database) => database,
        Err(error) => return (Vec::new(), None, None, Some(error)),
    };
    let Some(sqlite) = resolve_executable(OsStr::new("sqlite3")) else {
        return (
            Vec::new(),
            None,
            None,
            Some("sqlite3 is not available on PATH".into()),
        );
    };
    let version = sqlite_command(&sqlite)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned());
    let query = "SELECT id, rollout_path, created_at, updated_at, archived, archived_at \
                 FROM threads ORDER BY id";
    let output = sqlite_command(&sqlite)
        .args(["-readonly", "-json"])
        .arg(&database)
        .arg(query)
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => match parse_thread_rows(&output.stdout) {
            Ok(rows) => (rows, Some(sqlite), version, None),
            Err(error) => (
                Vec::new(),
                Some(sqlite),
                version,
                Some(format!("parse Codex thread index: {error}")),
            ),
        },
        Ok(output) => (
            Vec::new(),
            Some(sqlite),
            version,
            Some(format!(
                "read Codex thread index: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        ),
        Err(error) => (
            Vec::new(),
            Some(sqlite),
            version,
            Some(format!("launch sqlite3: {error}")),
        ),
    }
}

fn canonical_state_database(path: &Path) -> std::result::Result<PathBuf, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("inspect Codex state database {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Codex state database is not a regular non-symlink file: {}",
            path.display()
        ));
    }
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("resolve Codex state database {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "Codex state database is noncanonical: {}",
            path.display()
        ));
    }
    Ok(canonical)
}

fn sqlite_command(sqlite: &Path) -> Command {
    let mut command = Command::new(sqlite);
    command.arg("-init").arg(sqlite_empty_init_path());
    command
}

#[cfg(windows)]
fn sqlite_empty_init_path() -> &'static Path {
    Path::new("NUL")
}

#[cfg(not(windows))]
fn sqlite_empty_init_path() -> &'static Path {
    Path::new("/dev/null")
}

fn parse_thread_rows(output: &[u8]) -> serde_json::Result<Vec<ThreadRow>> {
    if output.iter().all(u8::is_ascii_whitespace) {
        Ok(Vec::new())
    } else {
        serde_json::from_slice(output)
    }
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{label} is not a non-symlink directory: {}",
        path.display()
    );
    path.canonicalize()
        .with_context(|| format!("resolve {label} {}", path.display()))
}

fn canonical_real_or_absent_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(path.to_path_buf());
        }
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "{label} is not a non-symlink directory: {}",
        path.display()
    );
    path.canonicalize()
        .with_context(|| format!("resolve {label} {}", path.display()))
}

fn private_measurement_qualifier(metrics: &InventoryMetrics) -> &'static str {
    if metrics.private_reclaimable_complete {
        ""
    } else {
        " (lower bound)"
    }
}

fn resolve_executable(name: &OsStr) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    resolve_executable_in_path(name, &path)
}

fn resolve_executable_in_path(name: &OsStr, path: &OsStr) -> Option<PathBuf> {
    for directory in env::split_paths(path) {
        for candidate in executable_candidates(&directory, name) {
            if is_platform_executable(&candidate) {
                return candidate.canonicalize().ok();
            }
        }
    }
    None
}

#[cfg(windows)]
fn executable_candidates(directory: &Path, name: &OsStr) -> Vec<PathBuf> {
    let name = Path::new(name);
    if name.extension().is_some() {
        return vec![directory.join(name)];
    }
    let extensions = env::var_os("PATHEXT").unwrap_or_else(|| ".COM;.EXE;.BAT;.CMD".into());
    env::split_paths(&extensions)
        .map(|extension| {
            let extension = extension.to_string_lossy();
            directory.join(format!("{}{}", name.to_string_lossy(), extension))
        })
        .collect()
}

#[cfg(not(windows))]
fn executable_candidates(directory: &Path, name: &OsStr) -> Vec<PathBuf> {
    vec![directory.join(name)]
}

#[cfg(unix)]
fn is_platform_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(windows)]
fn is_platform_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(not(any(unix, windows)))]
fn is_platform_executable(path: &Path) -> bool {
    path.is_file()
}

fn default_codex_home() -> Result<PathBuf> {
    if let Some(home) = env::var_os("CODEX_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(home));
    }
    Ok(
        PathBuf::from(env::var_os("HOME").context("neither CODEX_HOME nor HOME is set")?)
            .join(".codex"),
    )
}

fn state_directory() -> Result<PathBuf> {
    if let Some(path) = env::var_os("XDG_STATE_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path).join("worktree-gc"));
    }
    Ok(
        PathBuf::from(env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?)
            .join(".local/state/worktree-gc"),
    )
}

fn write_manifest(manifest: &CodexSessionCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}-codex-sessions-dry-run.json", manifest.run_id));
    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("open atomic manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Codex session manifest {}", path.display()))?;
    Ok(path)
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

    fn metrics(bytes: u64) -> InventoryMetrics {
        InventoryMetrics {
            logical_bytes: bytes,
            allocated_bytes: bytes,
            private_reclaimable_bytes: bytes,
            private_reclaimable_complete: true,
            files: 1,
            ..InventoryMetrics::default()
        }
    }

    fn observation(
        thread_id: &str,
        archived: bool,
        format: CodexSessionFileFormat,
        age_days: u64,
        bytes: u64,
    ) -> CodexSessionObservation {
        CodexSessionObservation {
            thread_id: thread_id.into(),
            path: PathBuf::from(format!("{thread_id}.jsonl")),
            archived,
            format,
            created_at_unix: 1,
            updated_at_unix: 2,
            archived_at_unix: archived.then_some(3),
            age_days,
            metrics: metrics(bytes),
        }
    }

    #[test]
    fn summaries_keep_live_archived_plain_and_compressed_storage_separate() {
        let observations = vec![
            observation("live", false, CodexSessionFileFormat::Jsonl, 2, 10),
            observation("archived", true, CodexSessionFileFormat::JsonlZstd, 40, 20),
        ];

        let live = summarize(observations.iter().filter(|entry| !entry.archived));
        let archived = summarize(observations.iter().filter(|entry| entry.archived));
        assert_eq!(live.count, 1);
        assert_eq!(live.plain_count, 1);
        assert_eq!(live.compressed_count, 0);
        assert_eq!(archived.count, 1);
        assert_eq!(archived.plain_count, 0);
        assert_eq!(archived.compressed_count, 1);
        assert_eq!(archived.compressed_metrics.private_reclaimable_bytes, 20);

        let buckets = age_buckets(&observations);
        let archived_30 = buckets
            .iter()
            .find(|bucket| bucket.archived && bucket.min_age_days == 30)
            .unwrap();
        assert_eq!(archived_30.compressed_count, 1);
        assert_eq!(archived_30.metrics.private_reclaimable_bytes, 20);
    }

    #[test]
    fn compressed_rollout_is_the_physical_fallback_for_an_indexed_jsonl_path() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let indexed = root.join("rollout-thread.jsonl");
        let compressed = root.join("rollout-thread.jsonl.zst");
        fs::write(&compressed, b"compressed").unwrap();
        let paths = BTreeSet::from([compressed.clone()]);

        let resolved = resolve_physical_rollout(&indexed, &paths, &root, "thread")
            .unwrap()
            .unwrap();
        assert_eq!(resolved.0, compressed);
        assert_eq!(resolved.1, CodexSessionFileFormat::JsonlZstd);
    }

    #[test]
    fn duplicate_plain_and_compressed_rollouts_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let indexed = root.join("rollout-thread.jsonl");
        let compressed = root.join("rollout-thread.jsonl.zst");
        fs::write(&indexed, b"plain").unwrap();
        fs::write(&compressed, b"compressed").unwrap();
        let paths = BTreeSet::from([indexed.clone(), compressed]);

        let error = resolve_physical_rollout(&indexed, &paths, &root, "thread").unwrap_err();
        assert!(error.to_string().contains("ambiguous correlation"));
    }

    #[test]
    fn absent_archived_sessions_directory_is_a_complete_empty_store() {
        let temp = tempfile::tempdir().unwrap();
        let live = temp.path().join("sessions");
        let archived = temp.path().join("archived_sessions");
        fs::create_dir(&live).unwrap();
        fs::write(live.join("rollout-live.jsonl"), b"live").unwrap();

        assert_eq!(
            canonical_real_or_absent_directory(&archived, "Codex archived sessions").unwrap(),
            archived
        );
        let discovery = discover_session_files(&live, &archived, 10).unwrap();
        assert!(discovery.complete);
        assert_eq!(discovery.files, vec![live.join("rollout-live.jsonl")]);
        assert!(discovery.errors.is_empty());
    }

    #[test]
    fn absent_live_and_archived_session_directories_are_a_complete_empty_store() {
        let temp = tempfile::tempdir().unwrap();
        let live = temp.path().join("sessions");
        let archived = temp.path().join("archived_sessions");

        assert_eq!(
            canonical_real_or_absent_directory(&live, "Codex sessions").unwrap(),
            live
        );
        let discovery = discover_session_files(&live, &archived, 10).unwrap();
        assert!(discovery.complete);
        assert!(discovery.files.is_empty());
        assert!(discovery.errors.is_empty());
    }

    #[test]
    fn session_discovery_is_bounded_and_keeps_symlinks_opaque() {
        let temp = tempfile::tempdir().unwrap();
        let live = temp.path().join("sessions");
        let archived = temp.path().join("archived_sessions");
        fs::create_dir_all(live.join("2026/07/13")).unwrap();
        fs::create_dir_all(&archived).unwrap();
        fs::write(live.join("2026/07/13/live.jsonl"), b"live").unwrap();
        fs::write(archived.join("archived.jsonl.zst"), b"archived").unwrap();
        fs::write(archived.join("rollout.tmp"), b"partial").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&archived, live.join("linked")).unwrap();

        let discovery = discover_session_files(&live, &archived, 100).unwrap();
        assert_eq!(discovery.files.len(), 2);
        assert_eq!(discovery.temporary_artifacts.len(), 1);
        #[cfg(unix)]
        assert!(!discovery.complete);

        let discovery = discover_session_files(&live, &archived, 1).unwrap();
        assert!(!discovery.complete);
    }

    #[test]
    fn session_discovery_marks_queued_directories_incomplete_at_the_exact_cap() {
        let temp = tempfile::tempdir().unwrap();
        let live = temp.path().join("sessions");
        let archived = temp.path().join("archived_sessions");
        fs::create_dir_all(live.join("queued")).unwrap();

        let discovery = discover_session_files(&live, &archived, 1).unwrap();
        assert_eq!(discovery.visited_entries, 1);
        assert!(!discovery.complete);
        assert!(discovery.files.is_empty());
    }

    #[test]
    fn measurement_races_preserve_surviving_metrics_and_record_the_missing_path() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("existing.jsonl");
        let missing = temp.path().join("missing.jsonl");
        fs::write(&existing, b"existing").unwrap();
        let existing = existing.canonicalize().unwrap();

        let (measurements, errors) =
            measure_session_files(&[existing.clone(), missing.clone()], 10);
        assert!(measurements.contains_key(&existing));
        assert!(!measurements.contains_key(&missing));
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains(&missing.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn session_measurements_deduplicate_hard_linked_rollouts() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.jsonl");
        let second = temp.path().join("second.jsonl");
        fs::write(&first, vec![0_u8; 4096]).unwrap();
        fs::hard_link(&first, &second).unwrap();
        let first = first.canonicalize().unwrap();
        let second = second.canonicalize().unwrap();

        let (measurements, errors) = measure_session_files(&[first.clone(), second.clone()], 10);
        assert!(errors.is_empty());
        assert_eq!(measurements[&first].files, 1);
        assert!(measurements[&first].allocated_bytes >= 4096);
        assert_eq!(measurements[&second].files, 0);
        assert_eq!(measurements[&second].allocated_bytes, 0);
        assert_eq!(measurements[&second].hardlink_duplicates, 1);
    }

    #[test]
    fn empty_sqlite_json_output_is_an_empty_thread_index() {
        assert!(parse_thread_rows(b"").unwrap().is_empty());
        assert!(parse_thread_rows(b" \n\t").unwrap().is_empty());
    }

    #[test]
    fn incomplete_private_measurements_are_labeled_as_lower_bounds() {
        assert_eq!(private_measurement_qualifier(&metrics(1)), "");
        assert_eq!(
            private_measurement_qualifier(&incomplete_metrics()),
            " (lower bound)"
        );
    }

    #[test]
    fn unindexed_rollouts_have_separate_live_archived_and_physical_totals() {
        let root = PathBuf::from("/codex");
        let live_root = root.join("sessions");
        let archived_root = root.join("archived_sessions");
        let live = live_root.join("live.jsonl");
        let archived = archived_root.join("archived.jsonl.zst");
        let measurements =
            BTreeMap::from([(live.clone(), metrics(10)), (archived.clone(), metrics(20))]);

        let summary =
            summarize_unindexed(&[live, archived], &measurements, &live_root, &archived_root);
        assert_eq!(summary.count, 2);
        assert_eq!(summary.live_count, 1);
        assert_eq!(summary.archived_count, 1);
        assert_eq!(summary.plain_count, 1);
        assert_eq!(summary.compressed_count, 1);
        assert_eq!(summary.metrics.private_reclaimable_bytes, 30);
        assert!(summary.metrics.private_reclaimable_complete);
    }

    #[test]
    fn missing_unindexed_measurements_make_the_physical_total_a_lower_bound() {
        let live_root = PathBuf::from("/codex/sessions");
        let archived_root = PathBuf::from("/codex/archived_sessions");
        let missing = live_root.join("missing.jsonl");

        let summary = summarize_unindexed(&[missing], &BTreeMap::new(), &live_root, &archived_root);
        assert_eq!(summary.count, 1);
        assert!(!summary.metrics.private_reclaimable_complete);
    }

    #[test]
    fn compression_setting_distinguishes_enabled_absent_and_invalid_values() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().canonicalize().unwrap().join("config.toml");
        fs::write(
            &config,
            "[features]\nlocal_thread_store_compression = true\n",
        )
        .unwrap();
        assert_eq!(read_compression_setting(&config, None), (Some(true), None));

        fs::write(&config, "[features]\nmemories = true\n").unwrap();
        assert_eq!(read_compression_setting(&config, None), (None, None));

        fs::write(
            &config,
            "[features]\nlocal_thread_store_compression = \"yes\"\n",
        )
        .unwrap();
        let (enabled, error) = read_compression_setting(&config, None);
        assert_eq!(enabled, None);
        assert!(error.unwrap().contains("not a boolean"));
    }

    #[test]
    fn selected_profile_layers_over_base_compression_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let base = root.join("config.toml");
        let profile = root.join("large-context.config.toml");
        fs::write(&base, "[features]\nlocal_thread_store_compression = true\n").unwrap();
        fs::write(
            &profile,
            "[features]\nlocal_thread_store_compression = false\n",
        )
        .unwrap();

        let inspection =
            inspect_compression_configuration(&root, &base, Some("large-context")).unwrap();
        assert_eq!(inspection.configured_enabled, Some(false));
        assert_eq!(
            inspection.selected_profile.as_deref(),
            Some("large-context")
        );
        assert_eq!(inspection.profile_config_path.as_ref(), Some(&profile));
        assert_eq!(inspection.discovered_profile_config_paths, vec![profile]);
        assert_eq!(inspection.error, None);
    }

    #[test]
    fn unselected_profile_files_make_configuration_evidence_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let base = root.join("config.toml");
        let profile = root.join("large-context.config.toml");
        fs::write(&base, "[features]\nlocal_thread_store_compression = true\n").unwrap();
        fs::write(&profile, "[features]\nmemories = true\n").unwrap();

        let inspection = inspect_compression_configuration(&root, &base, None).unwrap();
        assert_eq!(inspection.configured_enabled, Some(true));
        assert!(inspection
            .error
            .unwrap()
            .contains("profile selection is unknown"));
    }

    #[test]
    fn selected_profiles_reject_traversal_and_missing_layer_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let base = root.join("config.toml");
        fs::write(&base, "[features]\nmemories = true\n").unwrap();

        assert!(inspect_compression_configuration(&root, &base, Some("../other")).is_err());
        let inspection = inspect_compression_configuration(&root, &base, Some("missing")).unwrap();
        assert!(inspection.error.unwrap().contains("missing.config.toml"));
    }

    #[cfg(unix)]
    #[test]
    fn state_database_must_be_a_canonical_regular_non_symlink_file() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let real = root.join("real.sqlite");
        let linked = root.join("state_5.sqlite");
        fs::write(&real, b"database").unwrap();
        std::os::unix::fs::symlink(&real, &linked).unwrap();

        assert!(canonical_state_database(&linked)
            .unwrap_err()
            .contains("non-symlink"));
        assert_eq!(
            canonical_state_database(&real).unwrap(),
            real.canonicalize().unwrap()
        );
    }

    #[test]
    fn sqlite_commands_disable_user_startup_files() {
        let command = sqlite_command(Path::new("sqlite3"));
        let args = command.get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            vec![OsStr::new("-init"), sqlite_empty_init_path().as_os_str()]
        );
    }

    #[cfg(unix)]
    #[test]
    fn executable_resolution_skips_non_executable_path_entries() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        let blocked = first.join("sqlite3");
        let executable = second.join("sqlite3");
        fs::write(&blocked, b"not executable").unwrap();
        fs::write(&executable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let path = env::join_paths([first, second]).unwrap();

        assert_eq!(
            resolve_executable_in_path(OsStr::new("sqlite3"), &path),
            Some(executable.canonicalize().unwrap())
        );
    }

    #[test]
    fn compression_marker_timestamp_errors_are_incomplete_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("marker");
        fs::write(&marker, b"lock").unwrap();
        let metadata = fs::symlink_metadata(&marker).unwrap();

        let marker = compression_marker_from_metadata(
            &metadata,
            Err(io::Error::other("timestamp unavailable")),
            100,
        );
        assert!(marker.present);
        assert!(marker.regular_file);
        assert_eq!(marker.modified_at_unix, None);
        assert!(marker.error.unwrap().contains("timestamp unavailable"));
    }

    #[test]
    fn temporary_artifacts_make_compression_health_incomplete() {
        let health = compression_health(
            Some(true),
            None,
            CodexCompressionMarker {
                present: true,
                regular_file: true,
                size_bytes: Some(10),
                modified_at_unix: Some(1),
                age_seconds: Some(1),
                error: None,
            },
            vec![PathBuf::from("rollout.tmp")],
            true,
        );
        assert_eq!(health.status, CodexCompressionHealthStatus::Incomplete);
    }
}
