use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::{
    discover_repositories, format_bytes, skip_repository_discovery_dir,
    triage_repositories_serial_with_errors, CleanupClass, CleanupMode, GeneratedDirAction,
    GeneratedDirConfig, GeneratedDirInfo, ProtectionMatch, TriageOptions, TriageReport,
    DEFAULT_GENERATED_DAYS, DEFAULT_STALE_DAYS,
};
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

const GENERATED_COLLECT_MANIFEST_VERSION: u64 = 3;
const MAX_ENTRIES_PER_ARTIFACT: u64 = 250_000;
const MAX_DISCOVERY_ENTRIES_PER_ROOT: u64 = 250_000;
pub const DEFAULT_GENERATED_DISCOVERY_MAX_ENTRIES: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct GeneratedCollectOptions {
    pub roots: Vec<PathBuf>,
    pub generated_days: u64,
    pub max_discovery_entries: u64,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for GeneratedCollectOptions {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            generated_days: DEFAULT_GENERATED_DAYS,
            max_discovery_entries: DEFAULT_GENERATED_DISCOVERY_MAX_ENTRIES,
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
    pub max_discovery_entries: u64,
    pub max_discovery_entries_per_root: u64,
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
    pub discovery_complete: bool,
    pub ownership_complete: bool,
    pub measurement_complete: bool,
    pub repositories: usize,
    pub linked_worktrees: usize,
    pub root_coverage: Vec<GeneratedRootCoverage>,
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
pub struct GeneratedRootCoverage {
    pub requested_root: PathBuf,
    pub canonical_root: Option<PathBuf>,
    pub complete: bool,
    pub discovery_complete: bool,
    pub ownership_complete: bool,
    pub measurement_complete: bool,
    pub discovery_visited_entries: u64,
    pub errors: Vec<String>,
    pub repositories: Vec<PathBuf>,
    pub linked_worktrees: Vec<PathBuf>,
    pub generated_roots: usize,
    pub safe: usize,
    pub active: usize,
    pub protected: usize,
    pub tracked: usize,
    pub incomplete: usize,
    pub report_only: usize,
    pub metrics: InventoryMetrics,
    pub safe_metrics: InventoryMetrics,
    pub byte_totals_additive_across_roots: bool,
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
    pub recent_activity: bool,
    pub in_use: bool,
    pub worktree_in_use: bool,
    pub ownership_evidence_complete: bool,
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
    pub active: usize,
    pub tracked: usize,
    pub incomplete: usize,
    pub report_only: usize,
    pub safe: usize,
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

#[derive(Debug)]
struct RootDiscovery {
    requested_root: PathBuf,
    canonical_root: Option<PathBuf>,
    discovery_complete: bool,
    visited_entries: u64,
    discovery_errors: Vec<String>,
    classification_errors: Vec<String>,
    repositories: Vec<PathBuf>,
}

fn discover_requested_roots(
    requested_roots: &[PathBuf],
    max_entries: u64,
) -> (Vec<RootDiscovery>, Vec<PathBuf>, Vec<PathBuf>) {
    let mut requested = requested_roots.to_vec();
    requested.sort();
    requested.dedup();

    let mut remaining_entries = max_entries;
    let mut discoveries = Vec::new();
    let mut canonical_roots = BTreeSet::new();
    let mut all_repositories = BTreeSet::new();
    for (position, requested_root) in requested.iter().enumerate() {
        let remaining_roots = u64::try_from(requested.len() - position).unwrap_or(u64::MAX);
        let fair_share =
            remaining_entries.saturating_add(remaining_roots.saturating_sub(1)) / remaining_roots;
        let root_budget = fair_share.min(MAX_DISCOVERY_ENTRIES_PER_ROOT);
        let discovery = discover_one_root(requested_root, root_budget);
        remaining_entries = remaining_entries.saturating_sub(discovery.visited_entries);
        if let Some(root) = discovery.canonical_root.clone() {
            canonical_roots.insert(root);
        }
        for repository in &discovery.repositories {
            all_repositories.insert(repository.clone());
        }
        discoveries.push(discovery);
    }

    (
        discoveries,
        canonical_roots.into_iter().collect(),
        all_repositories.into_iter().collect(),
    )
}

fn discover_one_root(requested_root: &Path, max_entries: u64) -> RootDiscovery {
    let mut discovery = RootDiscovery {
        requested_root: requested_root.to_path_buf(),
        canonical_root: None,
        discovery_complete: true,
        visited_entries: 0,
        discovery_errors: Vec::new(),
        classification_errors: Vec::new(),
        repositories: Vec::new(),
    };
    if max_entries == 0 {
        discovery.discovery_complete = false;
        discovery
            .discovery_errors
            .push("global repository-discovery entry budget exhausted".to_string());
        return discovery;
    }

    let canonical = match fs::canonicalize(requested_root) {
        Ok(path) => path,
        Err(error) => {
            discovery.discovery_complete = false;
            discovery.discovery_errors.push(format!(
                "resolve requested root {}: {error}",
                requested_root.display()
            ));
            return discovery;
        }
    };
    if !canonical.is_dir() {
        discovery.discovery_complete = false;
        discovery.discovery_errors.push(format!(
            "requested root {} is not a directory",
            canonical.display()
        ));
        discovery.canonical_root = Some(canonical);
        return discovery;
    }
    discovery.canonical_root = Some(canonical.clone());

    let mut candidates = Vec::new();
    let mut walker = WalkDir::new(&canonical)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();
    while let Some(next) = walker.next() {
        if discovery.visited_entries >= max_entries {
            discovery.discovery_complete = false;
            discovery.discovery_errors.push(format!(
                "repository discovery reached its {max_entries}-entry root budget"
            ));
            break;
        }
        discovery.visited_entries += 1;
        let entry = match next {
            Ok(entry) => entry,
            Err(error) => {
                discovery.discovery_complete = false;
                discovery
                    .discovery_errors
                    .push(format!("walk repository root: {error}"));
                continue;
            }
        };
        if !entry.file_type().is_dir() {
            continue;
        }
        if entry.depth() > 0 && skip_repository_discovery_dir(entry.path()) {
            walker.skip_current_dir();
            continue;
        }
        if entry.path().join(".git").exists() {
            candidates.push(entry.path().to_path_buf());
            walker.skip_current_dir();
        }
    }

    if !candidates.is_empty() {
        match discover_repositories(&candidates) {
            Ok(repositories) => discovery.repositories = repositories,
            Err(error) => {
                discovery.discovery_complete = false;
                discovery
                    .discovery_errors
                    .push(format!("resolve discovered repositories: {error:#}"));
            }
        }
    }
    discovery.repositories.sort();
    discovery.repositories.dedup();
    discovery
}

pub fn collect_generated(options: GeneratedCollectOptions) -> Result<GeneratedCollectRun> {
    anyhow::ensure!(
        !options.roots.is_empty(),
        "generated collection requires at least one root"
    );
    anyhow::ensure!(
        options.generated_days > 0,
        "generated_days must be at least 1"
    );
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    anyhow::ensure!(
        options.max_discovery_entries > 0,
        "max_discovery_entries must be at least 1"
    );

    let (mut discoveries, roots, repository_paths) =
        discover_requested_roots(&options.roots, options.max_discovery_entries);
    let triage_options = TriageOptions {
        stale_days: DEFAULT_STALE_DAYS,
        generated_days: options.generated_days,
        generated_activity_only: true,
        check_in_use: true,
        generated_config: GeneratedDirConfig::default(),
        now: options.now,
    };
    let reports = if repository_paths.is_empty() {
        Vec::new()
    } else {
        match triage_repositories_serial_with_errors(&roots, &repository_paths, triage_options) {
            Ok((triage, errors)) => {
                record_repository_errors(&mut discoveries, errors);
                triage.repositories
            }
            Err(error) => {
                let message = format!("classify discovered repositories: {error:#}");
                for discovery in discoveries
                    .iter_mut()
                    .filter(|discovery| !discovery.repositories.is_empty())
                {
                    discovery.classification_errors.push(message.clone());
                }
                Vec::new()
            }
        }
    };
    let repository_worktrees = reports
        .iter()
        .map(|report| {
            (
                report.repo_root.clone(),
                report
                    .worktrees
                    .iter()
                    .filter(|worktree| {
                        worktree.exists
                            && worktree.prunable.is_none()
                            && worktree.path != report.repo_root
                    })
                    .map(|worktree| worktree.path.clone())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let linked_worktrees = repository_worktrees
        .values()
        .flatten()
        .collect::<BTreeSet<_>>()
        .len();
    let repositories = repository_paths.len();
    let mut artifacts = observations_from_triage(reports, options.now);
    measure_artifacts(&mut artifacts, options.max_entries)?;
    artifacts.sort_by_key(|artifact| {
        (
            std::cmp::Reverse(artifact.measurement.metrics.private_reclaimable_bytes),
            std::cmp::Reverse(artifact.measurement.metrics.allocated_bytes),
            artifact.path.clone(),
        )
    });

    let discovery_complete = discoveries.iter().all(|root| root.discovery_complete);
    let ownership_complete = discoveries
        .iter()
        .all(|root| root.classification_errors.is_empty())
        && artifacts
            .iter()
            .all(|artifact| artifact.ownership_evidence_complete);
    let measurement_complete = artifacts.iter().all(|artifact| {
        artifact.measurement.complete
            && artifact.measurement.error.is_none()
            && artifact.measurement.metrics.private_reclaimable_complete
    });
    let complete = discovery_complete && ownership_complete && measurement_complete;
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
    let root_coverage = summarize_roots(&discoveries, &repository_worktrees, &artifacts);
    let (action, reason) = if !complete {
        (
            GeneratedCollectAction::Incomplete,
            "generated coverage is a lower bound because discovery, ownership, or APFS measurement evidence is incomplete".to_string(),
        )
    } else if artifacts.is_empty() {
        (
            GeneratedCollectAction::NoWork,
            "repository discovery found no configured generated directories".to_string(),
        )
    } else {
        (
            GeneratedCollectAction::ReportOnly,
            "generated roots are classified and APFS-measured; use cleanup dry-run for an executable mutation manifest".to_string(),
        )
    };

    let manifest = GeneratedCollectManifest {
        manifest_version: GENERATED_COLLECT_MANIFEST_VERSION,
        collector: "generated",
        run_id: format!("{}-{}", unix_nanos(options.now), std::process::id()),
        mode: CleanupMode::DryRun,
        generated_at_unix: unix_seconds(options.now),
        roots,
        policy: GeneratedCollectPolicy {
            owner_contract: "Git worktree ownership plus tracked/ignored state, domain-shaped activity, open handles, and recursive protection leases",
            execution: "report-only; generate a fresh cleanup manifest before any mutation",
            unattended_execution_supported: false,
            generated_days: options.generated_days,
            generated_activity_only: true,
            check_in_use: true,
            max_entries: options.max_entries,
            max_entries_per_artifact: MAX_ENTRIES_PER_ARTIFACT,
            max_discovery_entries: options.max_discovery_entries,
            max_discovery_entries_per_root: MAX_DISCOVERY_ENTRIES_PER_ROOT,
            repository_parallelism: 1,
        },
        plan: GeneratedCollectPlan {
            action,
            reason,
            complete,
            discovery_complete,
            ownership_complete,
            measurement_complete,
            repositories,
            linked_worktrees,
            root_coverage,
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

fn record_repository_errors(discoveries: &mut [RootDiscovery], errors: Vec<(PathBuf, String)>) {
    for (repository, error) in errors {
        for discovery in discoveries
            .iter_mut()
            .filter(|discovery| discovery.repositories.contains(&repository))
        {
            discovery.classification_errors.push(format!(
                "classify repository {}: {error}",
                repository.display()
            ));
        }
    }
}

pub fn print_generated_collect(run: &GeneratedCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: generated");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!(
        "{} repositories | {} linked worktrees | {} generated roots | {} private{} | {} summed path allocation",
        plan.repositories,
        plan.linked_worktrees,
        plan.artifacts.len(),
        format_bytes(plan.observed_metrics.private_reclaimable_bytes),
        if plan.complete { "" } else { " (lower bound)" },
        format_bytes(plan.observed_metrics.allocated_bytes)
    );
    println!(
        "coverage: discovery={} ownership={} measurement={}",
        plan.discovery_complete, plan.ownership_complete, plan.measurement_complete
    );
    for root in &plan.root_coverage {
        println!(
            "  root {}: {} repositories, {} worktrees, {} generated roots, {} safe, {} active, {} protected, {} tracked, {} incomplete, {} report-only{}",
            root.requested_root.display(),
            root.repositories.len(),
            root.linked_worktrees.len(),
            root.generated_roots,
            root.safe,
            root.active,
            root.protected,
            root.tracked,
            root.incomplete,
            root.report_only,
            if root.complete { "" } else { " (incomplete)" }
        );
    }
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
            "  {}: {} roots, {} private{} | {} allocated | {} deletion candidates | {} safe / {} rebuildable opportunities ({} private{}) | {} active | {} protected | {} tracked | {} incomplete | {} report-only",
            summary.name,
            summary.artifacts,
            format_bytes(summary.metrics.private_reclaimable_bytes),
            if summary.metrics.private_reclaimable_complete { "" } else { " (lower bound)" },
            format_bytes(summary.metrics.allocated_bytes),
            summary.delete_candidates,
            summary.safe,
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
            summary.active,
            summary.protected,
            summary.tracked,
            summary.incomplete,
            summary.report_only
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

fn observations_from_triage(
    reports: Vec<TriageReport>,
    now: SystemTime,
) -> Vec<GeneratedArtifactObservation> {
    let mut seen = BTreeSet::new();
    let mut artifacts = Vec::new();
    for report in reports {
        for artifact in report.generated_dirs {
            if !seen.insert(artifact.path.clone()) {
                continue;
            }
            artifacts.push(observation(report.repo_root.clone(), artifact, now));
        }
    }
    artifacts
}

fn observation(
    repository: PathBuf,
    artifact: GeneratedDirInfo,
    now: SystemTime,
) -> GeneratedArtifactObservation {
    let rebuildable_opportunity = artifact.action != GeneratedDirAction::ReportOnly
        && !artifact.has_tracked_files
        && !artifact.in_use
        && !artifact.worktree_in_use
        && artifact.ownership_evidence_complete
        && artifact.protection.is_none();
    let rebuild_cost = rebuildable_opportunity.then(|| rebuild_cost(&artifact.name));
    let recent_activity = artifact
        .mtime_unix
        .is_some_and(|mtime| age_days(now, mtime) < artifact.effective_days);
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
        recent_activity,
        in_use: artifact.in_use,
        worktree_in_use: artifact.worktree_in_use,
        ownership_evidence_complete: artifact.ownership_evidence_complete,
        protection: artifact.protection,
        rebuildable_opportunity,
        rebuild_cost,
        measurement: GeneratedArtifactMeasurement::pending(),
    }
}

fn age_days(now: SystemTime, then_unix: i64) -> u64 {
    let now = i64::try_from(unix_seconds(now)).unwrap_or(i64::MAX);
    u64::try_from(now.saturating_sub(then_unix).max(0)).unwrap_or(u64::MAX) / 86_400
}

fn artifact_is_incomplete(artifact: &GeneratedArtifactObservation) -> bool {
    !artifact.ownership_evidence_complete
        || !artifact.measurement.complete
        || artifact.measurement.error.is_some()
        || !artifact.measurement.metrics.private_reclaimable_complete
}

fn artifact_is_safe(artifact: &GeneratedArtifactObservation) -> bool {
    artifact.rebuildable_opportunity && !artifact_is_incomplete(artifact)
}

fn artifact_is_active(artifact: &GeneratedArtifactObservation) -> bool {
    artifact.recent_activity || artifact.in_use || artifact.worktree_in_use
}

fn summarize_roots(
    discoveries: &[RootDiscovery],
    repository_worktrees: &BTreeMap<PathBuf, Vec<PathBuf>>,
    artifacts: &[GeneratedArtifactObservation],
) -> Vec<GeneratedRootCoverage> {
    discoveries
        .iter()
        .map(|discovery| {
            let repositories = discovery
                .repositories
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let linked_worktrees = repositories
                .iter()
                .flat_map(|repository| {
                    repository_worktrees
                        .get(repository)
                        .into_iter()
                        .flatten()
                        .cloned()
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            let root_artifacts = artifacts
                .iter()
                .filter(|artifact| repositories.contains(&artifact.repository))
                .collect::<Vec<_>>();
            let ownership_complete = discovery.classification_errors.is_empty()
                && root_artifacts
                    .iter()
                    .all(|artifact| artifact.ownership_evidence_complete);
            let measurement_complete = root_artifacts.iter().all(|artifact| {
                artifact.measurement.complete
                    && artifact.measurement.error.is_none()
                    && artifact.measurement.metrics.private_reclaimable_complete
            });
            let mut errors = discovery.discovery_errors.clone();
            errors.extend(discovery.classification_errors.clone());
            errors.extend(root_artifacts.iter().filter_map(|artifact| {
                artifact
                    .measurement
                    .error
                    .as_ref()
                    .map(|error| format!("measure {}: {error}", artifact.path.display()))
            }));
            let metrics = sum_metrics(
                root_artifacts
                    .iter()
                    .map(|artifact| &artifact.measurement.metrics),
            );
            let safe_metrics = sum_metrics(
                root_artifacts
                    .iter()
                    .filter(|artifact| artifact_is_safe(artifact))
                    .map(|artifact| &artifact.measurement.metrics),
            );
            let complete =
                discovery.discovery_complete && ownership_complete && measurement_complete;
            GeneratedRootCoverage {
                requested_root: discovery.requested_root.clone(),
                canonical_root: discovery.canonical_root.clone(),
                complete,
                discovery_complete: discovery.discovery_complete,
                ownership_complete,
                measurement_complete,
                discovery_visited_entries: discovery.visited_entries,
                errors,
                repositories: discovery.repositories.clone(),
                linked_worktrees,
                generated_roots: root_artifacts.len(),
                safe: root_artifacts
                    .iter()
                    .filter(|artifact| artifact_is_safe(artifact))
                    .count(),
                active: root_artifacts
                    .iter()
                    .filter(|artifact| artifact_is_active(artifact))
                    .count(),
                protected: root_artifacts
                    .iter()
                    .filter(|artifact| artifact.protection.is_some())
                    .count(),
                tracked: root_artifacts
                    .iter()
                    .filter(|artifact| artifact.has_tracked_files)
                    .count(),
                incomplete: root_artifacts
                    .iter()
                    .filter(|artifact| artifact_is_incomplete(artifact))
                    .count(),
                report_only: root_artifacts
                    .iter()
                    .filter(|artifact| artifact.cleanup_action == GeneratedDirAction::ReportOnly)
                    .count(),
                metrics,
                safe_metrics,
                byte_totals_additive_across_roots: false,
            }
        })
        .collect()
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
        let error = if !root.complete && root.errors.is_empty() {
            Some(format!(
                "generated-root inventory stopped after {} entries within its {root_budget}-entry budget",
                root.visited_entries
            ))
        } else if root.errors.is_empty() {
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
                    active: 0,
                    tracked: 0,
                    incomplete: 0,
                    report_only: 0,
                    safe: 0,
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
        summary.active += usize::from(artifact_is_active(artifact));
        summary.tracked += usize::from(artifact.has_tracked_files);
        summary.incomplete += usize::from(artifact_is_incomplete(artifact));
        summary.report_only +=
            usize::from(artifact.cleanup_action == GeneratedDirAction::ReportOnly);
        summary.safe += usize::from(artifact_is_safe(artifact));
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
    use std::process::Command;

    fn run_git(directory: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(directory)
            .args(args)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "git {args:?} failed in {}",
            directory.display()
        );
    }

    fn init_repo(path: &Path) {
        fs::create_dir_all(path).unwrap();
        let status = Command::new("git")
            .arg("init")
            .arg("-q")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    fn commit_fixture(repo: &Path) {
        run_git(repo, &["config", "user.email", "test@example.com"]);
        run_git(repo, &["config", "user.name", "Test"]);
        fs::write(repo.join("README.md"), "fixture\n").unwrap();
        run_git(repo, &["add", "README.md"]);
        run_git(repo, &["commit", "-q", "-m", "fixture"]);
    }

    fn generated_dir(
        path: &std::path::Path,
        ownership_evidence_complete: bool,
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
            ownership_evidence_complete,
            worktree_in_use: false,
            owner_free_pressure: false,
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
            recent_activity: false,
            in_use: false,
            worktree_in_use: false,
            ownership_evidence_complete: true,
            protection: None,
            rebuildable_opportunity: true,
            rebuild_cost: Some(rebuild_cost(
                path.file_name().unwrap().to_string_lossy().as_ref(),
            )),
            measurement: GeneratedArtifactMeasurement::pending(),
        }
    }

    fn assert_filesystem_measurement_succeeded(measurement: &GeneratedArtifactMeasurement) {
        assert!(measurement.measured_at_unix.is_some());
        assert!(measurement.filesystem.is_some());
        assert!(measurement.visited_entries > 0);
        assert!(measurement.metrics.logical_bytes > 0);
        assert!(measurement.metrics.allocated_bytes > 0);
        assert!(measurement.error.is_none());
        assert_eq!(
            measurement.complete,
            measurement.metrics.private_reclaimable_complete
        );
    }

    #[test]
    fn active_or_skipped_generated_roots_are_still_measured() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("artifact"), vec![0_u8; 16 * 1024]).unwrap();
        let mut artifacts = vec![artifact(&target, GeneratedDirAction::Skip)];

        measure_artifacts(&mut artifacts, 100).unwrap();

        assert_filesystem_measurement_succeeded(&artifacts[0].measurement);
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
        assert_filesystem_measurement_succeeded(&artifacts[1].measurement);
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
        assert!(artifacts[0]
            .measurement
            .error
            .as_deref()
            .unwrap()
            .contains("1-entry budget"));
        assert!(artifacts[1]
            .measurement
            .error
            .as_deref()
            .unwrap()
            .contains("1-entry budget"));
    }

    #[test]
    fn repository_discovery_is_deterministic_and_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("a");
        let second = temp.path().join("b");
        init_repo(&first);
        init_repo(&second);

        let first_run = discover_one_root(temp.path(), 2);
        let second_run = discover_one_root(temp.path(), 2);

        assert!(!first_run.discovery_complete);
        assert_eq!(first_run.visited_entries, 2);
        assert_eq!(first_run.repositories, [first.canonicalize().unwrap()]);
        assert_eq!(first_run.repositories, second_run.repositories);
        assert_eq!(first_run.discovery_errors, second_run.discovery_errors);
    }

    #[test]
    fn missing_requested_root_is_reported_as_incomplete() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");

        let discovery = discover_one_root(&missing, 100);

        assert!(!discovery.discovery_complete);
        assert_eq!(discovery.canonical_root, None);
        assert!(discovery.repositories.is_empty());
        assert!(discovery.discovery_errors[0].contains("resolve requested root"));
    }

    #[test]
    fn repository_discovery_finds_hidden_linked_worktree_git_files() {
        let temp = tempfile::tempdir().unwrap();
        let primary = temp.path().join("primary");
        init_repo(&primary);
        commit_fixture(&primary);
        let hidden_root = temp.path().join("scan/.codex/worktrees");
        let linked = hidden_root.join("linked");
        fs::create_dir_all(&hidden_root).unwrap();
        let status = Command::new("git")
            .arg("-C")
            .arg(&primary)
            .args(["worktree", "add", "-q", "-b", "linked"])
            .arg(&linked)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(linked.join(".git").is_file());

        let discovery = discover_one_root(&hidden_root, 100);

        assert!(
            discovery.discovery_complete,
            "{:?}",
            discovery.discovery_errors
        );
        assert_eq!(discovery.repositories, [primary.canonicalize().unwrap()]);
    }

    #[test]
    fn repository_discovery_finds_nested_codex_repositories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("Documents/Codex");
        let first = root.join("2026-07-15/first");
        let second = root.join("2026-07-16/second");
        init_repo(&first);
        init_repo(&second);

        let discovery = discover_one_root(&root, 100);

        assert!(
            discovery.discovery_complete,
            "{:?}",
            discovery.discovery_errors
        );
        assert_eq!(
            discovery.repositories,
            [
                first.canonicalize().unwrap(),
                second.canonicalize().unwrap()
            ]
        );
    }

    #[test]
    fn repository_discovery_stops_at_repository_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outer = root.join("outer");
        let nested = outer.join("nested");
        init_repo(&outer);
        init_repo(&nested);

        let discovery = discover_one_root(&root, 100);

        assert!(
            discovery.discovery_complete,
            "{:?}",
            discovery.discovery_errors
        );
        assert_eq!(discovery.repositories, [outer.canonicalize().unwrap()]);
    }

    #[test]
    fn repository_classification_errors_are_scoped_to_containing_roots() {
        let good = PathBuf::from("/tmp/good");
        let bad = PathBuf::from("/tmp/bad");
        let mut discoveries = vec![
            RootDiscovery {
                requested_root: PathBuf::from("/tmp/first"),
                canonical_root: Some(PathBuf::from("/tmp/first")),
                discovery_complete: true,
                visited_entries: 2,
                discovery_errors: Vec::new(),
                classification_errors: Vec::new(),
                repositories: vec![good],
            },
            RootDiscovery {
                requested_root: PathBuf::from("/tmp/second"),
                canonical_root: Some(PathBuf::from("/tmp/second")),
                discovery_complete: true,
                visited_entries: 2,
                discovery_errors: Vec::new(),
                classification_errors: Vec::new(),
                repositories: vec![bad.clone()],
            },
        ];

        record_repository_errors(
            &mut discoveries,
            vec![(bad, "repository disappeared".to_string())],
        );

        assert!(discoveries[0].discovery_complete);
        assert!(discoveries[0].classification_errors.is_empty());
        assert!(discoveries[1].discovery_complete);
        assert_eq!(discoveries[1].classification_errors.len(), 1);
        assert!(discoveries[1].classification_errors[0].contains("repository disappeared"));

        let coverage = summarize_roots(&discoveries, &BTreeMap::new(), &[]);
        assert!(coverage[0].discovery_complete);
        assert!(coverage[0].ownership_complete);
        assert!(coverage[0].measurement_complete);
        assert!(coverage[0].complete);
        assert!(coverage[1].discovery_complete);
        assert!(!coverage[1].ownership_complete);
        assert!(coverage[1].measurement_complete);
        assert!(!coverage[1].complete);
    }

    #[test]
    fn per_root_byte_totals_are_explicitly_non_additive() {
        let repository = PathBuf::from("/tmp/repo");
        let discoveries = vec![
            RootDiscovery {
                requested_root: PathBuf::from("/tmp/one"),
                canonical_root: Some(PathBuf::from("/tmp/one")),
                discovery_complete: true,
                visited_entries: 1,
                discovery_errors: Vec::new(),
                classification_errors: Vec::new(),
                repositories: vec![repository.clone()],
            },
            RootDiscovery {
                requested_root: PathBuf::from("/tmp/two"),
                canonical_root: Some(PathBuf::from("/tmp/two")),
                discovery_complete: true,
                visited_entries: 1,
                discovery_errors: Vec::new(),
                classification_errors: Vec::new(),
                repositories: vec![repository.clone()],
            },
        ];
        let mut generated = artifact(Path::new("/tmp/repo/.next"), GeneratedDirAction::Skip);
        generated.measurement.complete = true;
        generated.measurement.metrics.private_reclaimable_bytes = 100;
        generated.measurement.metrics.private_reclaimable_complete = true;
        let coverage = summarize_roots(
            &discoveries,
            &BTreeMap::from([(repository, vec![PathBuf::from("/tmp/repo")])]),
            &[generated],
        );

        assert_eq!(coverage.len(), 2);
        assert_eq!(coverage[0].metrics.private_reclaimable_bytes, 100);
        assert_eq!(coverage[1].metrics.private_reclaimable_bytes, 100);
        assert!(!coverage[0].byte_totals_additive_across_roots);
        assert!(!coverage[1].byte_totals_additive_across_roots);
    }

    #[test]
    fn root_coverage_reports_each_classification_without_granting_authority() {
        let repository = PathBuf::from("/tmp/repo");
        let discovery = RootDiscovery {
            requested_root: repository.clone(),
            canonical_root: Some(repository.clone()),
            discovery_complete: true,
            visited_entries: 1,
            discovery_errors: Vec::new(),
            classification_errors: Vec::new(),
            repositories: vec![repository.clone()],
        };
        let mut safe = artifact(Path::new("/tmp/repo/safe/.next"), GeneratedDirAction::Skip);
        safe.repository = repository.clone();
        safe.measurement.complete = true;
        safe.measurement.metrics.private_reclaimable_complete = true;
        let mut active = safe.clone();
        active.path = PathBuf::from("/tmp/repo/active/.next");
        active.recent_activity = true;
        let mut protected = safe.clone();
        protected.path = PathBuf::from("/tmp/repo/protected/.next");
        protected.protection = Some(ProtectionMatch {
            id: "p-test".to_string(),
            path: protected.path.clone(),
            reason: "fixture".to_string(),
            expires_at_unix: 99,
        });
        protected.rebuildable_opportunity = false;
        protected.rebuild_cost = None;
        let mut tracked = safe.clone();
        tracked.path = PathBuf::from("/tmp/repo/tracked/.next");
        tracked.has_tracked_files = true;
        tracked.rebuildable_opportunity = false;
        tracked.rebuild_cost = None;
        let mut incomplete = safe.clone();
        incomplete.path = PathBuf::from("/tmp/repo/incomplete/.next");
        incomplete.measurement.complete = false;
        incomplete.measurement.metrics.private_reclaimable_complete = false;
        let mut report_only = safe.clone();
        report_only.path = PathBuf::from("/tmp/repo/dist");
        report_only.cleanup_action = GeneratedDirAction::ReportOnly;
        report_only.rebuildable_opportunity = false;
        report_only.rebuild_cost = None;

        let coverage = summarize_roots(
            &[discovery],
            &BTreeMap::from([(repository, vec![PathBuf::from("/tmp/repo")])]),
            &[safe, active, protected, tracked, incomplete, report_only],
        );

        assert_eq!(coverage[0].generated_roots, 6);
        assert_eq!(coverage[0].safe, 2);
        assert_eq!(coverage[0].active, 1);
        assert_eq!(coverage[0].protected, 1);
        assert_eq!(coverage[0].tracked, 1);
        assert_eq!(coverage[0].incomplete, 1);
        assert_eq!(coverage[0].report_only, 1);
        assert!(coverage[0].discovery_complete);
        assert!(coverage[0].ownership_complete);
        assert!(!coverage[0].measurement_complete);
        assert!(!coverage[0].complete);
    }

    #[test]
    fn rebuildable_opportunities_require_complete_owner_evidence() {
        let path = std::path::Path::new("/tmp/repo/.next");
        let complete = observation(
            PathBuf::from("/tmp/repo"),
            generated_dir(path, true),
            UNIX_EPOCH + std::time::Duration::from_secs(1),
        );
        assert!(complete.rebuildable_opportunity);

        let artifact = observation(
            PathBuf::from("/tmp/repo"),
            generated_dir(path, false),
            UNIX_EPOCH + std::time::Duration::from_secs(1),
        );
        assert!(!artifact.rebuildable_opportunity);
        assert_eq!(artifact.rebuild_cost, None);
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
