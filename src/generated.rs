use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::{
    discover_repositories_bounded, format_bytes, triage_exact_roots_with_parallelism,
    triage_roots_with_parallelism, CleanupClass, CleanupMode, GeneratedDirAction,
    GeneratedDirConfig, GeneratedDirInfo, OpenHandleEvidence, ProtectionMatch, TriageOptions,
    TriageReport, DEFAULT_GENERATED_DAYS, DEFAULT_STALE_DAYS,
};
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const GENERATED_COLLECT_MANIFEST_VERSION: u64 = 3;
const MAX_ENTRIES_PER_ARTIFACT: u64 = 250_000;

#[derive(Debug, Clone)]
pub struct GeneratedCollectOptions {
    pub roots: Vec<PathBuf>,
    pub discovery_roots: Vec<PathBuf>,
    pub generated_days: u64,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for GeneratedCollectOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            discovery_roots: Vec::new(),
            generated_days: DEFAULT_GENERATED_DAYS,
            max_entries: 2_000_000,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct GeneratedCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: GeneratedCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct GeneratedCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub roots: Vec<PathBuf>,
    pub discovery_roots: Vec<PathBuf>,
    pub policy: GeneratedCollectPolicy,
    pub plan: GeneratedCollectPlan,
}

#[derive(Debug, Serialize)]
pub struct GeneratedCollectPolicy {
    pub owner_contract: &'static str,
    pub execution: &'static str,
    pub unattended_execution_supported: bool,
    pub generated_days: u64,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub max_entries: u64,
    pub max_entries_per_artifact: u64,
    pub repository_parallelism: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedCollectAction {
    NoWork,
    ReportOnly,
    Incomplete,
}

#[derive(Debug, Serialize)]
pub struct GeneratedCollectPlan {
    pub action: GeneratedCollectAction,
    pub reason: String,
    pub complete: bool,
    pub repositories: usize,
    pub artifacts: Vec<GeneratedArtifactObservation>,
    pub observed_metrics: InventoryMetrics,
    pub delete_candidate_metrics: InventoryMetrics,
    pub rebuildable_opportunity_metrics: InventoryMetrics,
    pub summaries: Vec<GeneratedArtifactSummary>,
    pub rebuild_cost_summaries: Vec<GeneratedRebuildCostSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedRebuildCost {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedArtifactObservation {
    pub path: PathBuf,
    pub worktree_path: PathBuf,
    pub repository: PathBuf,
    pub name: String,
    pub cleanup_action: GeneratedDirAction,
    pub cleanup_class: CleanupClass,
    pub ignored: bool,
    pub has_tracked_files: bool,
    pub reason: String,
    pub mtime_unix: Option<i64>,
    pub effective_days: u64,
    pub in_use: bool,
    pub open_handle_evidence: OpenHandleEvidence,
    pub protection: Option<ProtectionMatch>,
    pub rebuildable_opportunity: bool,
    pub rebuild_cost: Option<GeneratedRebuildCost>,
    pub measurement: GeneratedArtifactMeasurement,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedArtifactMeasurement {
    pub measured_at_unix: Option<u64>,
    pub filesystem: Option<String>,
    pub complete: bool,
    pub visited_entries: u64,
    pub metrics: InventoryMetrics,
    pub error: Option<String>,
}

impl GeneratedArtifactMeasurement {
    fn pending() -> Self {
        Self {
            measured_at_unix: None,
            filesystem: None,
            complete: false,
            visited_entries: 0,
            metrics: InventoryMetrics {
                private_reclaimable_complete: false,
                ..InventoryMetrics::default()
            },
            error: None,
        }
    }

    fn fail(&mut self, error: impl Into<String>) {
        self.complete = false;
        self.metrics.private_reclaimable_complete = false;
        self.error = Some(error.into());
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedArtifactSummary {
    pub name: String,
    pub artifacts: usize,
    pub delete_candidates: usize,
    pub protected: usize,
    pub in_use: usize,
    pub rebuildable_opportunities: usize,
    pub metrics: InventoryMetrics,
    pub rebuildable_opportunity_metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedRebuildCostSummary {
    pub filesystem: String,
    pub cost: GeneratedRebuildCost,
    pub artifacts: usize,
    pub metrics: InventoryMetrics,
    pub cumulative_artifacts: usize,
    pub cumulative_metrics: InventoryMetrics,
}

pub fn collect_generated(options: GeneratedCollectOptions) -> Result<GeneratedCollectRun> {
    anyhow::ensure!(
        !options.roots.is_empty() || !options.discovery_roots.is_empty(),
        "generated collection requires an exact root or --discover-under"
    );
    anyhow::ensure!(
        options.generated_days > 0,
        "generated_days must be at least 1"
    );
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");

    anyhow::ensure!(
        options.roots.is_empty() || options.discovery_roots.is_empty(),
        "exact generated roots cannot be combined with --discover-under"
    );

    let discovery_mode = !options.discovery_roots.is_empty();
    let mut repository_roots = if discovery_mode {
        discover_repositories_bounded(&options.discovery_roots, 1)?
    } else {
        options.roots.clone()
    };
    repository_roots.sort();
    repository_roots.dedup();

    // Repository planning is deliberately serialized. The collector is a
    // background orientation surface, not a reason to fan Git and process
    // ownership work out across every checkout at once.
    let triage_options = TriageOptions {
        stale_days: DEFAULT_STALE_DAYS,
        generated_days: options.generated_days,
        generated_activity_only: true,
        check_in_use: true,
        generated_config: GeneratedDirConfig::default(),
        now: options.now,
    };
    let triage = if discovery_mode {
        // Discovered paths identify repository families, not just the checkout
        // that happened to contain the .git marker. Include every linked
        // worktree so large generated roots beside the primary checkout remain
        // visible and retain their own activity and protection evidence.
        triage_roots_with_parallelism(&repository_roots, triage_options, 1)?
    } else {
        triage_exact_roots_with_parallelism(&repository_roots, triage_options, 1)?
    };
    let roots = triage.roots;
    let repositories = triage.repositories.len();
    let mut artifacts = observations_from_triage(triage.repositories);
    measure_artifacts(&mut artifacts, options.max_entries)?;
    artifacts.sort_by_key(|artifact| {
        (
            std::cmp::Reverse(artifact.measurement.metrics.private_reclaimable_bytes),
            std::cmp::Reverse(artifact.measurement.metrics.allocated_bytes),
            artifact.path.clone(),
        )
    });

    let complete = artifacts.iter().all(|artifact| {
        artifact.measurement.complete
            && artifact.measurement.error.is_none()
            && artifact.measurement.metrics.private_reclaimable_complete
    });
    let observed_metrics = sum_metrics(
        artifacts
            .iter()
            .map(|artifact| &artifact.measurement.metrics),
    );
    let delete_candidate_metrics = sum_metrics(
        artifacts
            .iter()
            .filter(|artifact| artifact.cleanup_action == GeneratedDirAction::Delete)
            .map(|artifact| &artifact.measurement.metrics),
    );
    let rebuildable_opportunity_metrics = sum_metrics(
        artifacts
            .iter()
            .filter(|artifact| artifact.rebuildable_opportunity)
            .map(|artifact| &artifact.measurement.metrics),
    );
    let summaries = summarize_artifacts(&artifacts);
    let rebuild_cost_summaries = summarize_rebuild_costs(&artifacts);
    let (action, reason) = if artifacts.is_empty() {
        (
            GeneratedCollectAction::NoWork,
            "repository discovery found no configured generated directories".to_string(),
        )
    } else if complete {
        (
            GeneratedCollectAction::ReportOnly,
            "generated roots are classified and APFS-measured; use cleanup dry-run for an executable mutation manifest".to_string(),
        )
    } else {
        (
            GeneratedCollectAction::Incomplete,
            "generated-root inventory is a lower bound because one or more bounded measurements were incomplete".to_string(),
        )
    };

    let manifest = GeneratedCollectManifest {
        manifest_version: GENERATED_COLLECT_MANIFEST_VERSION,
        collector: "generated",
        run_id: format!("{}-{}", unix_nanos(options.now), std::process::id()),
        mode: CleanupMode::DryRun,
        generated_at_unix: unix_seconds(options.now),
        roots,
        discovery_roots: options.discovery_roots,
        policy: GeneratedCollectPolicy {
            owner_contract: "Git worktree ownership plus tracked/ignored state, domain-shaped activity, open handles, and recursive protection leases",
            execution: "report-only; generate a fresh cleanup manifest before any mutation",
            unattended_execution_supported: false,
            generated_days: options.generated_days,
            generated_activity_only: true,
            check_in_use: true,
            max_entries: options.max_entries,
            max_entries_per_artifact: MAX_ENTRIES_PER_ARTIFACT,
            repository_parallelism: 1,
        },
        plan: GeneratedCollectPlan {
            action,
            reason,
            complete,
            repositories,
            artifacts,
            observed_metrics,
            delete_candidate_metrics,
            rebuildable_opportunity_metrics,
            summaries,
            rebuild_cost_summaries,
        },
    };
    let manifest_path = write_manifest(&manifest)?;
    Ok(GeneratedCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_generated_collect(run: &GeneratedCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: generated");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!(
        "{} repositories | {} generated roots | {} private{} | {} summed path allocation",
        plan.repositories,
        plan.artifacts.len(),
        format_bytes(plan.observed_metrics.private_reclaimable_bytes),
        if plan.complete { "" } else { " (lower bound)" },
        format_bytes(plan.observed_metrics.allocated_bytes)
    );
    for summary in &plan.rebuild_cost_summaries {
        println!(
            "  {:?} rebuild cost on {}: {} roots, {} private{}; cumulative through this tier: {} roots, {} private{}",
            summary.cost,
            summary.filesystem,
            summary.artifacts,
            format_bytes(summary.metrics.private_reclaimable_bytes),
            if summary.metrics.private_reclaimable_complete {
                ""
            } else {
                " (lower bound)"
            },
            summary.cumulative_artifacts,
            format_bytes(summary.cumulative_metrics.private_reclaimable_bytes),
            if summary.cumulative_metrics.private_reclaimable_complete {
                ""
            } else {
                " (lower bound)"
            }
        );
    }
    println!(
        "{} private{} is rebuildable now under review-only pressure policy",
        format_bytes(
            plan.rebuildable_opportunity_metrics
                .private_reclaimable_bytes
        ),
        if plan
            .rebuildable_opportunity_metrics
            .private_reclaimable_complete
        {
            ""
        } else {
            " (lower bound)"
        }
    );
    for summary in &plan.summaries {
        println!(
            "  {}: {} roots, {} private{} | {} allocated | {} deletion candidates | {} rebuildable-now opportunities ({} private{}) | {} protected | {} in use",
            summary.name,
            summary.artifacts,
            format_bytes(summary.metrics.private_reclaimable_bytes),
            if summary.metrics.private_reclaimable_complete { "" } else { " (lower bound)" },
            format_bytes(summary.metrics.allocated_bytes),
            summary.delete_candidates,
            summary.rebuildable_opportunities,
            format_bytes(
                summary
                    .rebuildable_opportunity_metrics
                    .private_reclaimable_bytes
            ),
            if summary
                .rebuildable_opportunity_metrics
                .private_reclaimable_complete
            {
                ""
            } else {
                " lower bound"
            },
            summary.protected,
            summary.in_use
        );
    }
    println!("largest generated roots:");
    for artifact in plan.artifacts.iter().take(30) {
        println!(
            "  {} private{} | {} allocated | {:?} | {}",
            format_bytes(artifact.measurement.metrics.private_reclaimable_bytes),
            if artifact.measurement.complete {
                ""
            } else {
                " (lower bound)"
            },
            format_bytes(artifact.measurement.metrics.allocated_bytes),
            artifact.cleanup_action,
            artifact.path.display()
        );
    }
}

fn observations_from_triage(reports: Vec<TriageReport>) -> Vec<GeneratedArtifactObservation> {
    let mut seen = BTreeSet::new();
    let mut artifacts = Vec::new();
    for report in reports {
        for artifact in report.generated_dirs {
            if !seen.insert(artifact.path.clone()) {
                continue;
            }
            artifacts.push(observation(report.repo_root.clone(), artifact));
        }
    }
    artifacts
}

fn observation(repository: PathBuf, artifact: GeneratedDirInfo) -> GeneratedArtifactObservation {
    let rebuildable_opportunity = artifact.action != GeneratedDirAction::ReportOnly
        && !artifact.has_tracked_files
        && !artifact.in_use
        && artifact.open_handle_evidence == OpenHandleEvidence::Complete
        && artifact.protection.is_none();
    let rebuild_cost = rebuildable_opportunity.then(|| rebuild_cost(&artifact.name));
    GeneratedArtifactObservation {
        path: artifact.path,
        worktree_path: artifact.worktree_path,
        repository,
        name: artifact.name,
        cleanup_action: artifact.action,
        cleanup_class: artifact.cleanup_class,
        ignored: artifact.ignored,
        has_tracked_files: artifact.has_tracked_files,
        reason: artifact.reason,
        mtime_unix: artifact.mtime_unix,
        effective_days: artifact.effective_days,
        in_use: artifact.in_use,
        open_handle_evidence: artifact.open_handle_evidence,
        protection: artifact.protection,
        rebuildable_opportunity,
        rebuild_cost,
        measurement: GeneratedArtifactMeasurement::pending(),
    }
}

fn rebuild_cost(name: &str) -> GeneratedRebuildCost {
    match crate::generated_rebuild_rank(name) {
        0 | 1 => GeneratedRebuildCost::Low,
        2 => GeneratedRebuildCost::Medium,
        _ => GeneratedRebuildCost::High,
    }
}

fn measure_artifacts(
    artifacts: &mut [GeneratedArtifactObservation],
    max_entries: u64,
) -> Result<()> {
    let mut targets: BTreeMap<PathBuf, Vec<usize>> = BTreeMap::new();
    for (index, artifact) in artifacts.iter_mut().enumerate() {
        let metadata = match fs::symlink_metadata(&artifact.path) {
            Ok(metadata) => metadata,
            Err(error) => {
                artifact
                    .measurement
                    .fail(format!("inspect generated root: {error}"));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            artifact
                .measurement
                .fail("generated root is not a non-symlink directory");
            continue;
        }
        let canonical = match fs::canonicalize(&artifact.path) {
            Ok(path) => path,
            Err(error) => {
                artifact
                    .measurement
                    .fail(format!("resolve generated root: {error}"));
                continue;
            }
        };
        let canonical_worktree = match fs::canonicalize(&artifact.worktree_path) {
            Ok(path) => path,
            Err(error) => {
                artifact
                    .measurement
                    .fail(format!("resolve owning worktree: {error}"));
                continue;
            }
        };
        if !canonical.starts_with(&canonical_worktree) {
            artifact.measurement.fail(format!(
                "generated root escaped owning worktree {}",
                canonical_worktree.display()
            ));
            continue;
        }
        targets.entry(canonical).or_default().push(index);
    }
    if targets.is_empty() {
        return Ok(());
    }

    let mut remaining_entries = max_entries;
    let target_count = targets.len();
    for (position, (path, indexes)) in targets.iter().enumerate() {
        let remaining_roots = u64::try_from(target_count - position).unwrap_or(u64::MAX);
        let fair_share =
            remaining_entries.saturating_add(remaining_roots.saturating_sub(1)) / remaining_roots;
        let root_budget = MAX_ENTRIES_PER_ARTIFACT.min(fair_share);
        if root_budget == 0 {
            for index in indexes {
                artifacts[*index]
                    .measurement
                    .fail("global generated-root measurement budget exhausted");
            }
            continue;
        }
        let report = match inventory(
            std::slice::from_ref(path),
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: root_budget,
                one_filesystem: true,
            },
        ) {
            Ok(report) => report,
            Err(error) => {
                for index in indexes {
                    artifacts[*index]
                        .measurement
                        .fail(format!("measure generated root: {error:#}"));
                }
                continue;
            }
        };
        let measured_at_unix = report.generated_at_unix;
        let Some(root) = report.roots.into_iter().next() else {
            for index in indexes {
                artifacts[*index]
                    .measurement
                    .fail("generated-root inventory returned no root");
            }
            continue;
        };
        remaining_entries = remaining_entries.saturating_sub(root.visited_entries);
        let complete =
            root.complete && root.errors.is_empty() && root.metrics.private_reclaimable_complete;
        let error = if root.errors.is_empty() {
            None
        } else {
            Some(
                root.errors
                    .iter()
                    .map(|error| format!("{}: {}", error.path.display(), error.message))
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        };
        let mut metrics = root.metrics;
        metrics.private_reclaimable_complete = complete && metrics.private_reclaimable_complete;
        for index in indexes {
            artifacts[*index].measurement = GeneratedArtifactMeasurement {
                measured_at_unix: Some(measured_at_unix),
                filesystem: Some(root.filesystem.clone()),
                complete,
                visited_entries: root.visited_entries,
                metrics: metrics.clone(),
                error: error.clone(),
            };
        }
    }
    Ok(())
}

fn summarize_artifacts(
    artifacts: &[GeneratedArtifactObservation],
) -> Vec<GeneratedArtifactSummary> {
    let mut summaries: BTreeMap<String, GeneratedArtifactSummary> = BTreeMap::new();
    for artifact in artifacts {
        let summary =
            summaries
                .entry(artifact.name.clone())
                .or_insert_with(|| GeneratedArtifactSummary {
                    name: artifact.name.clone(),
                    artifacts: 0,
                    delete_candidates: 0,
                    protected: 0,
                    in_use: 0,
                    rebuildable_opportunities: 0,
                    metrics: InventoryMetrics {
                        private_reclaimable_complete: true,
                        ..InventoryMetrics::default()
                    },
                    rebuildable_opportunity_metrics: InventoryMetrics {
                        private_reclaimable_complete: true,
                        ..InventoryMetrics::default()
                    },
                });
        summary.artifacts += 1;
        summary.delete_candidates +=
            usize::from(artifact.cleanup_action == GeneratedDirAction::Delete);
        summary.protected += usize::from(artifact.protection.is_some());
        summary.in_use += usize::from(artifact.in_use);
        summary.rebuildable_opportunities += usize::from(artifact.rebuildable_opportunity);
        add_metrics(&mut summary.metrics, &artifact.measurement.metrics);
        if artifact.rebuildable_opportunity {
            add_metrics(
                &mut summary.rebuildable_opportunity_metrics,
                &artifact.measurement.metrics,
            );
        }
    }
    let mut summaries = summaries.into_values().collect::<Vec<_>>();
    summaries.sort_by_key(|summary| {
        (
            std::cmp::Reverse(summary.metrics.private_reclaimable_bytes),
            std::cmp::Reverse(summary.metrics.allocated_bytes),
            summary.name.clone(),
        )
    });
    summaries
}

fn summarize_rebuild_costs(
    artifacts: &[GeneratedArtifactObservation],
) -> Vec<GeneratedRebuildCostSummary> {
    let mut by_filesystem_cost =
        BTreeMap::<(String, GeneratedRebuildCost), (usize, InventoryMetrics)>::new();
    let mut filesystems = BTreeSet::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.rebuildable_opportunity)
    {
        let cost = artifact
            .rebuild_cost
            .expect("rebuildable opportunities always have a rebuild cost");
        let filesystem = artifact
            .measurement
            .filesystem
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        filesystems.insert(filesystem.clone());
        let entry = by_filesystem_cost
            .entry((filesystem, cost))
            .or_insert_with(|| {
                (
                    0,
                    InventoryMetrics {
                        private_reclaimable_complete: true,
                        ..InventoryMetrics::default()
                    },
                )
            });
        entry.0 += 1;
        add_metrics(&mut entry.1, &artifact.measurement.metrics);
    }

    let mut summaries = Vec::new();
    for filesystem in filesystems {
        let mut cumulative_artifacts = 0;
        let mut cumulative_metrics = InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        };
        for cost in [
            GeneratedRebuildCost::Low,
            GeneratedRebuildCost::Medium,
            GeneratedRebuildCost::High,
        ] {
            let (artifacts, metrics) = by_filesystem_cost
                .remove(&(filesystem.clone(), cost))
                .unwrap_or_else(|| {
                    (
                        0,
                        InventoryMetrics {
                            private_reclaimable_complete: true,
                            ..InventoryMetrics::default()
                        },
                    )
                });
            cumulative_artifacts += artifacts;
            add_metrics(&mut cumulative_metrics, &metrics);
            summaries.push(GeneratedRebuildCostSummary {
                filesystem: filesystem.clone(),
                cost,
                artifacts,
                metrics,
                cumulative_artifacts,
                cumulative_metrics: cumulative_metrics.clone(),
            });
        }
    }
    summaries
}

fn sum_metrics<'a>(metrics: impl Iterator<Item = &'a InventoryMetrics>) -> InventoryMetrics {
    metrics.fold(
        InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        },
        |mut total, metrics| {
            add_metrics(&mut total, metrics);
            total
        },
    )
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

fn state_directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path).join("worktree-gc"));
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?)
            .join(".local/state/worktree-gc"),
    )
}

fn write_manifest(manifest: &GeneratedCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}-generated-dry-run.json", manifest.run_id));
    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("open atomic manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit generated collector manifest {}", path.display()))?;
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

    fn generated_dir(
        path: &std::path::Path,
        open_handle_evidence: OpenHandleEvidence,
    ) -> GeneratedDirInfo {
        GeneratedDirInfo {
            path: path.to_path_buf(),
            worktree_path: path.parent().unwrap().to_path_buf(),
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            ignored: true,
            has_tracked_files: false,
            mtime_unix: None,
            mtime: None,
            effective_days: 3,
            in_use: false,
            open_handle_evidence,
            protection: None,
            cleanup_class: CleanupClass::Routine,
            sweeps: Vec::new(),
            action: GeneratedDirAction::Skip,
            reason: "fixture".to_string(),
        }
    }

    fn artifact(
        path: &std::path::Path,
        action: GeneratedDirAction,
    ) -> GeneratedArtifactObservation {
        GeneratedArtifactObservation {
            path: path.to_path_buf(),
            worktree_path: path.parent().unwrap().to_path_buf(),
            repository: path.parent().unwrap().to_path_buf(),
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            cleanup_action: action,
            cleanup_class: CleanupClass::Routine,
            ignored: true,
            has_tracked_files: false,
            reason: "fixture".to_string(),
            mtime_unix: None,
            effective_days: 3,
            in_use: false,
            open_handle_evidence: OpenHandleEvidence::Complete,
            protection: None,
            rebuildable_opportunity: true,
            rebuild_cost: Some(rebuild_cost(
                path.file_name().unwrap().to_string_lossy().as_ref(),
            )),
            measurement: GeneratedArtifactMeasurement::pending(),
        }
    }

    #[test]
    fn active_or_skipped_generated_roots_are_still_measured() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("artifact"), vec![0_u8; 16 * 1024]).unwrap();
        let mut artifacts = vec![artifact(&target, GeneratedDirAction::Skip)];

        measure_artifacts(&mut artifacts, 100).unwrap();

        assert!(artifacts[0].measurement.complete);
        assert!(artifacts[0].measurement.metrics.allocated_bytes > 0);
    }

    #[test]
    fn escaped_generated_root_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let owner = temp.path().join("owner");
        let target = temp.path().join("target");
        fs::create_dir(&owner).unwrap();
        fs::create_dir(&target).unwrap();
        let mut observation = artifact(&target, GeneratedDirAction::Skip);
        observation.worktree_path = owner;
        let mut artifacts = vec![observation];

        measure_artifacts(&mut artifacts, 100).unwrap();

        assert!(!artifacts[0].measurement.complete);
        assert!(artifacts[0]
            .measurement
            .error
            .as_deref()
            .unwrap()
            .contains("escaped owning worktree"));
    }

    #[test]
    fn missing_generated_root_does_not_block_other_measurements() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("artifact"), vec![0_u8; 16 * 1024]).unwrap();
        let mut artifacts = vec![
            artifact(&missing, GeneratedDirAction::Skip),
            artifact(&target, GeneratedDirAction::Skip),
        ];

        measure_artifacts(&mut artifacts, 100).unwrap();

        assert!(!artifacts[0].measurement.complete);
        assert!(artifacts[0].measurement.error.is_some());
        assert!(artifacts[1].measurement.complete);
        assert!(artifacts[1].measurement.metrics.allocated_bytes > 0);
    }

    #[test]
    fn global_budget_gives_each_generated_root_a_fair_slice() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        fs::create_dir(&first).unwrap();
        fs::create_dir(&second).unwrap();
        for index in 0..4 {
            fs::write(first.join(format!("artifact-{index}")), vec![0_u8; 1024]).unwrap();
            fs::write(second.join(format!("artifact-{index}")), vec![0_u8; 1024]).unwrap();
        }
        let mut artifacts = vec![
            artifact(&first, GeneratedDirAction::Skip),
            artifact(&second, GeneratedDirAction::Skip),
        ];

        measure_artifacts(&mut artifacts, 2).unwrap();

        assert_eq!(artifacts[0].measurement.visited_entries, 1);
        assert_eq!(artifacts[1].measurement.visited_entries, 1);
        assert!(!artifacts[0].measurement.complete);
        assert!(!artifacts[1].measurement.complete);
    }

    #[test]
    fn rebuildable_opportunities_require_complete_owner_evidence() {
        let path = std::path::Path::new("/tmp/repo/.next");
        let complete = observation(
            PathBuf::from("/tmp/repo"),
            generated_dir(path, OpenHandleEvidence::Complete),
        );
        assert!(complete.rebuildable_opportunity);

        for evidence in [
            OpenHandleEvidence::Unavailable,
            OpenHandleEvidence::Indeterminate,
            OpenHandleEvidence::NotChecked,
            OpenHandleEvidence::NotCaptured,
        ] {
            let artifact = observation(PathBuf::from("/tmp/repo"), generated_dir(path, evidence));
            assert!(!artifact.rebuildable_opportunity, "{evidence:?}");
            assert_eq!(artifact.rebuild_cost, None);
        }
    }

    #[test]
    fn rebuild_cost_curve_is_cumulative() {
        let mut next = artifact(
            std::path::Path::new("/tmp/repo/.next"),
            GeneratedDirAction::Skip,
        );
        next.measurement.metrics.private_reclaimable_bytes = 100;
        next.measurement.metrics.private_reclaimable_complete = true;
        next.measurement.filesystem = Some("fs".to_string());
        let mut target = artifact(
            std::path::Path::new("/tmp/repo/target"),
            GeneratedDirAction::Skip,
        );
        target.measurement.metrics.private_reclaimable_bytes = 300;
        target.measurement.metrics.private_reclaimable_complete = true;
        target.measurement.filesystem = Some("fs".to_string());
        let mut node_modules = artifact(
            std::path::Path::new("/tmp/repo/node_modules"),
            GeneratedDirAction::Skip,
        );
        node_modules.measurement.metrics.private_reclaimable_bytes = 500;
        node_modules
            .measurement
            .metrics
            .private_reclaimable_complete = true;
        node_modules.measurement.filesystem = Some("fs".to_string());
        let mut turbo = artifact(
            std::path::Path::new("/tmp/other/.turbo"),
            GeneratedDirAction::Skip,
        );
        turbo.measurement.metrics.private_reclaimable_bytes = 50;
        turbo.measurement.metrics.private_reclaimable_complete = true;
        turbo.measurement.filesystem = Some("other".to_string());

        let summaries = summarize_rebuild_costs(&[next, target, node_modules, turbo]);

        assert_eq!(summaries.len(), 6);
        assert_eq!(summaries[0].filesystem, "fs");
        assert_eq!(summaries[0].cost, GeneratedRebuildCost::Low);
        assert_eq!(summaries[0].metrics.private_reclaimable_bytes, 100);
        assert_eq!(summaries[0].cumulative_artifacts, 1);
        assert_eq!(
            summaries[0].cumulative_metrics.private_reclaimable_bytes,
            100
        );
        assert_eq!(summaries[1].cost, GeneratedRebuildCost::Medium);
        assert_eq!(summaries[1].metrics.private_reclaimable_bytes, 300);
        assert_eq!(summaries[1].cumulative_artifacts, 2);
        assert_eq!(
            summaries[1].cumulative_metrics.private_reclaimable_bytes,
            400
        );
        assert_eq!(summaries[2].cost, GeneratedRebuildCost::High);
        assert_eq!(summaries[2].metrics.private_reclaimable_bytes, 500);
        assert_eq!(summaries[2].cumulative_artifacts, 3);
        assert_eq!(
            summaries[2].cumulative_metrics.private_reclaimable_bytes,
            900
        );
        assert_eq!(summaries[3].filesystem, "other");
        assert_eq!(summaries[3].cost, GeneratedRebuildCost::Low);
        assert_eq!(summaries[3].cumulative_artifacts, 1);
        assert_eq!(
            summaries[3].cumulative_metrics.private_reclaimable_bytes,
            50
        );
    }
}
