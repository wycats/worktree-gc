mod cargo_incremental;

use anyhow::{bail, Context, Result};
use cargo_incremental::{
    cargo_project_dir, execute_incremental_sweep_with_timeout, is_cargo_lock_timeout,
    plan_incremental_sweep, with_cargo_profile_locks_timeout,
};
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use walkdir::WalkDir;

pub use cargo_incremental::{SweepCandidateAction, SweepCandidateDecision};

pub const DEFAULT_STALE_DAYS: u64 = 30;
pub const DEFAULT_GENERATED_DAYS: u64 = 7;
pub const DEFAULT_GENERATED_DELETE_NAMES: &[&str] = &["node_modules", ".next", ".turbo", "target"];
pub const DEFAULT_GENERATED_REPORT_NAMES: &[&str] = &["dist"];
pub const DEFAULT_INCREMENTAL_SWEEP_DAYS: u64 = 14;
pub const MANIFEST_VERSION: u64 = 2;

// Build caches are cheap to regenerate compared to dependency installs, so
// they default to a tighter window than --generated-days.
pub const DEFAULT_BUILD_CACHE_DAYS: u64 = 3;
pub const DEFAULT_BUILD_CACHE_NAMES: &[&str] = &[".next", ".turbo", "target"];

// A generated directory's own mtime only reflects direct-child changes, so
// activity is sampled to this depth to catch churn in nested subtrees.
// Depth 6 is grounded in observed live traffic: an active Next.js dev
// session rewrites files like .next/cache/webpack/client-development/N.pack
// (depth 4-5 below the candidate), and rewriting an existing file updates
// no ancestor directory mtime at all. Sampling shallower than the real
// write depth makes a live cache look idle.
const GENERATED_MTIME_SAMPLE_DEPTH: usize = 6;

#[derive(Debug, Clone)]
pub struct TriageOptions {
    pub stale_days: u64,
    pub generated_days: u64,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub generated_config: GeneratedDirConfig,
    pub now: SystemTime,
}

#[derive(Debug, Clone)]
pub struct CleanupOptions {
    pub execute: bool,
    pub stale_days: u64,
    pub generated_days: u64,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub generated_config: GeneratedDirConfig,
    pub cargo_lock_timeout: Option<Duration>,
    pub defer_lock_timeouts: bool,
    pub now: SystemTime,
}

#[derive(Debug, Serialize)]
pub struct TriageReport {
    pub repo_root: PathBuf,
    pub current_worktree: PathBuf,
    pub git_common_dir: PathBuf,
    pub stale_days: u64,
    pub generated_days: u64,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub generated_delete_names: Vec<String>,
    pub generated_report_only_names: Vec<String>,
    pub worktrees: Vec<WorktreeInfo>,
    pub worktree_decisions: Vec<WorktreeDecision>,
    pub generated_dirs: Vec<GeneratedDirInfo>,
}

pub type AuditReport = TriageReport;

#[derive(Debug, Serialize)]
pub struct CleanupRun {
    pub manifest_path: PathBuf,
    pub manifest: CleanupManifest,
}

#[derive(Debug, Serialize)]
pub struct RootTriageReport {
    pub roots: Vec<PathBuf>,
    pub repositories: Vec<TriageReport>,
}

#[derive(Debug, Serialize)]
pub struct RootCleanupRun {
    pub manifest_path: PathBuf,
    pub manifest: RootCleanupManifest,
}

#[derive(Debug, Serialize)]
pub struct RootCleanupManifest {
    pub manifest_version: u64,
    pub mode: CleanupMode,
    pub generated_at: String,
    pub roots: Vec<PathBuf>,
    pub repositories: Vec<CleanupRun>,
}

#[derive(Debug, Serialize)]
pub struct CleanupManifest {
    pub manifest_version: u64,
    pub mode: CleanupMode,
    pub generated_at: String,
    pub repo_root: PathBuf,
    pub current_worktree: PathBuf,
    pub git_common_dir: PathBuf,
    pub stale_days: u64,
    pub generated_days: u64,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub cargo_lock_timeout_secs: Option<u64>,
    pub defer_lock_timeouts: bool,
    pub generated_delete_names: Vec<String>,
    pub generated_report_only_names: Vec<String>,
    pub prune_output: String,
    pub worktrees: Vec<WorktreeDecision>,
    pub generated_dirs: Vec<GeneratedDirDecision>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupMode {
    DryRun,
    Execute,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorktreeInfo {
    pub path: PathBuf,
    pub head: Option<String>,
    pub branch: Option<String>,
    pub detached: bool,
    pub prunable: Option<String>,
    pub exists: bool,
    pub is_current: bool,
    pub dirty_count: Option<usize>,
    pub upstream: Option<String>,
    pub ahead: Option<u64>,
    pub behind: Option<u64>,
    pub last_commit_unix: Option<i64>,
    pub last_commit: Option<String>,
    pub activity_unix: Option<i64>,
    pub activity_age_days: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedDirInfo {
    pub path: PathBuf,
    pub worktree_path: PathBuf,
    pub name: String,
    pub ignored: bool,
    pub has_tracked_files: bool,
    pub mtime_unix: Option<i64>,
    pub mtime: Option<String>,
    pub effective_days: u64,
    pub in_use: bool,
    pub sweeps: Vec<SweepDecision>,
    pub action: GeneratedDirAction,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneratedDirAction {
    Delete,
    Sweep,
    ReportOnly,
    Skip,
}

#[derive(Debug, Clone, Serialize)]
pub struct WorktreeDecision {
    pub path: PathBuf,
    pub branch: Option<String>,
    pub action: WorktreeAction,
    pub reason: String,
    pub dirty_count: Option<usize>,
    pub last_commit: Option<String>,
    pub activity_age_days: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeAction {
    Remove,
    Keep,
    PruneMetadata,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedDirDecision {
    pub path: PathBuf,
    pub worktree_path: PathBuf,
    pub name: String,
    pub mtime: Option<String>,
    pub effective_days: u64,
    pub in_use: bool,
    pub sweeps: Vec<SweepDecision>,
    pub action: GeneratedDirAction,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedDirConfig {
    pub delete_names: Vec<String>,
    pub report_only_names: Vec<String>,
    pub window_overrides: Vec<GeneratedWindowOverride>,
    pub sweep_strategies: Vec<SweepStrategy>,
}

// An in-place pruning strategy for generated dirs that are too active to
// delete wholesale but accumulate stale artifacts internally (e.g. Cargo
// fingerprint-associated build outputs in `target/`). Each sweep tool defines
// which artifacts it can identify and remove.
#[derive(Debug, Clone, Serialize)]
pub struct SweepStrategy {
    pub name: String,
    pub tool: SweepTool,
    pub limit: SweepLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SweepTool {
    RustcIncremental,
    CargoSweep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SweepLimit {
    AgeDays { days: u64 },
    MaxSize { bytes: u64 },
}

impl SweepLimit {
    fn age_days(&self) -> Option<u64> {
        match self {
            Self::AgeDays { days } => Some(*days),
            Self::MaxSize { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SweepDecision {
    pub tool: SweepTool,
    pub limit: SweepLimit,
    pub delegated: bool,
    pub project_dir: Option<PathBuf>,
    pub reason: String,
    pub candidates: Vec<SweepCandidateDecision>,
}

impl SweepDecision {
    fn has_work(&self) -> bool {
        self.delegated
            || self.candidates.iter().any(|candidate| {
                matches!(
                    candidate.action,
                    SweepCandidateAction::Delete | SweepCandidateAction::RecoverTrash
                )
            })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GeneratedWindowOverride {
    pub name: String,
    pub days: u64,
}

impl Default for GeneratedDirConfig {
    fn default() -> Self {
        Self::from_names_with_default_sweeps(
            true,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }
}

impl GeneratedDirConfig {
    pub fn from_names(
        include_defaults: bool,
        delete_names: Vec<String>,
        report_only_names: Vec<String>,
        window_overrides: Vec<(String, u64)>,
        sweep_strategies: Vec<SweepStrategy>,
    ) -> Self {
        Self::from_names_with_default_sweeps(
            include_defaults,
            include_defaults,
            delete_names,
            report_only_names,
            window_overrides,
            sweep_strategies,
        )
    }

    pub fn from_names_with_default_sweeps(
        include_defaults: bool,
        include_default_sweeps: bool,
        delete_names: Vec<String>,
        report_only_names: Vec<String>,
        window_overrides: Vec<(String, u64)>,
        sweep_strategies: Vec<SweepStrategy>,
    ) -> Self {
        let mut delete = Vec::new();
        let mut report_only = Vec::new();
        let mut windows = Vec::new();
        let mut sweeps = Vec::new();

        if include_defaults {
            delete.extend(
                DEFAULT_GENERATED_DELETE_NAMES
                    .iter()
                    .map(|name| name.to_string()),
            );
            report_only.extend(
                DEFAULT_GENERATED_REPORT_NAMES
                    .iter()
                    .map(|name| name.to_string()),
            );
            windows.extend(
                DEFAULT_BUILD_CACHE_NAMES
                    .iter()
                    .map(|name| GeneratedWindowOverride {
                        name: name.to_string(),
                        days: DEFAULT_BUILD_CACHE_DAYS,
                    }),
            );
        }

        if include_defaults && include_default_sweeps {
            sweeps.push(SweepStrategy {
                name: "target".to_string(),
                tool: SweepTool::RustcIncremental,
                limit: SweepLimit::AgeDays {
                    days: DEFAULT_INCREMENTAL_SWEEP_DAYS,
                },
            });
        }

        delete.extend(delete_names);
        report_only.extend(report_only_names);
        windows.extend(
            window_overrides
                .into_iter()
                .map(|(name, days)| GeneratedWindowOverride { name, days }),
        );
        sweeps.extend(sweep_strategies);

        Self {
            delete_names: normalize_names(delete),
            report_only_names: normalize_names(report_only),
            window_overrides: windows,
            sweep_strategies: normalize_sweep_strategies(sweeps),
        }
    }

    // Later entries win so custom overrides shadow the build-cache defaults.
    pub fn effective_days(&self, name: &str, generated_days: u64) -> u64 {
        self.window_overrides
            .iter()
            .rev()
            .find(|override_| override_.name == name)
            .map(|override_| override_.days)
            .unwrap_or(generated_days)
    }

    pub fn sweep_strategies(&self, name: &str) -> Vec<&SweepStrategy> {
        self.sweep_strategies
            .iter()
            .filter(|strategy| strategy.name == name)
            .collect()
    }

    fn candidate_action(&self, name: &str) -> Option<GeneratedCandidateAction> {
        if self
            .report_only_names
            .iter()
            .any(|candidate| candidate == name)
        {
            Some(GeneratedCandidateAction::ReportOnly)
        } else if self.delete_names.iter().any(|candidate| candidate == name) {
            Some(GeneratedCandidateAction::Delete)
        } else if self
            .sweep_strategies
            .iter()
            .any(|strategy| strategy.name == name)
        {
            Some(GeneratedCandidateAction::SweepOnly)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct RepoContext {
    current_worktree: PathBuf,
    git_common_dir: PathBuf,
}

#[derive(Debug, Default)]
struct RawWorktree {
    path: PathBuf,
    head: Option<String>,
    branch: Option<String>,
    bare: bool,
    detached: bool,
    prunable: Option<String>,
}

#[derive(Debug)]
struct GeneratedCandidate {
    path: PathBuf,
    relative: PathBuf,
    name: String,
    action: GeneratedCandidateAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GeneratedCandidateAction {
    Delete,
    ReportOnly,
    SweepOnly,
}

pub fn triage(repo: Option<&Path>, options: TriageOptions) -> Result<TriageReport> {
    let context = repo_context(repo)?;
    let worktrees = inspect_worktrees(&context, options.now)?;
    let worktree_decisions = plan_worktree_cleanup(&worktrees, options.stale_days, options.now);
    let generated_dirs = scan_generated_dirs(
        &worktrees,
        options.generated_days,
        options.generated_activity_only,
        options.check_in_use,
        options.now,
        &options.generated_config,
    )?;

    Ok(TriageReport {
        repo_root: context.current_worktree.clone(),
        current_worktree: context.current_worktree,
        git_common_dir: context.git_common_dir,
        stale_days: options.stale_days,
        generated_days: options.generated_days,
        generated_activity_only: options.generated_activity_only,
        check_in_use: options.check_in_use,
        generated_delete_names: options.generated_config.delete_names,
        generated_report_only_names: options.generated_config.report_only_names,
        worktrees,
        worktree_decisions,
        generated_dirs,
    })
}

pub fn audit(repo: Option<&Path>, generated_days: u64, now: SystemTime) -> Result<AuditReport> {
    triage(
        repo,
        TriageOptions {
            stale_days: DEFAULT_STALE_DAYS,
            generated_days,
            generated_activity_only: false,
            check_in_use: false,
            generated_config: GeneratedDirConfig::default(),
            now,
        },
    )
}

pub fn cleanup(repo: Option<&Path>, options: CleanupOptions) -> Result<CleanupRun> {
    let execute = options.execute;
    let run = plan_cleanup(repo, options)?;
    if execute {
        execute_cleanup_manifest(&run.manifest)?;
    }
    Ok(run)
}

fn plan_cleanup(repo: Option<&Path>, options: CleanupOptions) -> Result<CleanupRun> {
    let context = repo_context(repo)?;
    let worktrees = inspect_worktrees(&context, options.now)?;
    let generated_dirs = scan_generated_dirs(
        &worktrees,
        options.generated_days,
        options.generated_activity_only,
        options.check_in_use,
        options.now,
        &options.generated_config,
    )?;
    let prune_output = run_worktree_prune(&context.current_worktree, false)?;

    let worktree_decisions = plan_worktree_cleanup(&worktrees, options.stale_days, options.now);
    let generated_decisions = generated_dirs
        .iter()
        .map(|dir| GeneratedDirDecision {
            path: dir.path.clone(),
            worktree_path: dir.worktree_path.clone(),
            name: dir.name.clone(),
            mtime: dir.mtime.clone(),
            effective_days: dir.effective_days,
            in_use: dir.in_use,
            sweeps: dir.sweeps.clone(),
            action: dir.action.clone(),
            reason: dir.reason.clone(),
        })
        .collect::<Vec<_>>();

    let manifest = CleanupManifest {
        manifest_version: MANIFEST_VERSION,
        mode: if options.execute {
            CleanupMode::Execute
        } else {
            CleanupMode::DryRun
        },
        generated_at: format_system_time(options.now),
        repo_root: context.current_worktree.clone(),
        current_worktree: context.current_worktree.clone(),
        git_common_dir: context.git_common_dir.clone(),
        stale_days: options.stale_days,
        generated_days: options.generated_days,
        generated_activity_only: options.generated_activity_only,
        check_in_use: options.check_in_use,
        cargo_lock_timeout_secs: options.cargo_lock_timeout.map(|timeout| timeout.as_secs()),
        defer_lock_timeouts: options.defer_lock_timeouts,
        generated_delete_names: options.generated_config.delete_names,
        generated_report_only_names: options.generated_config.report_only_names,
        prune_output,
        worktrees: worktree_decisions,
        generated_dirs: generated_decisions,
    };

    let manifest_path = write_manifest(&context.git_common_dir, &manifest)?;

    Ok(CleanupRun {
        manifest_path,
        manifest,
    })
}

pub fn triage_roots(roots: &[PathBuf], options: TriageOptions) -> Result<RootTriageReport> {
    let roots = canonicalize_roots(roots)?;
    let repositories = discover_repositories(&roots)?;
    let repositories = repositories
        .par_iter()
        .map(|repo| triage(Some(repo), options.clone()))
        .collect::<Result<Vec<_>>>()?;

    Ok(RootTriageReport {
        roots,
        repositories,
    })
}

pub fn cleanup_roots(roots: &[PathBuf], options: CleanupOptions) -> Result<RootCleanupRun> {
    let roots = canonicalize_roots(roots)?;
    let repositories = discover_repositories(&roots)?;
    cleanup_repositories(&roots, &repositories, options)
}

pub fn cleanup_repositories(
    roots: &[PathBuf],
    repositories: &[PathBuf],
    options: CleanupOptions,
) -> Result<RootCleanupRun> {
    let roots = canonicalize_roots(roots)?;
    let generated_at = format_system_time(options.now);
    let mode = if options.execute {
        CleanupMode::Execute
    } else {
        CleanupMode::DryRun
    };
    let repositories = repositories
        .par_iter()
        .map(|repo| plan_cleanup(Some(repo), options.clone()))
        .collect::<Result<Vec<_>>>()?;
    let mut manifest = RootCleanupManifest {
        manifest_version: MANIFEST_VERSION,
        mode,
        generated_at,
        roots,
        repositories,
    };
    let manifest_path = write_root_manifest(&manifest)?;

    if options.execute {
        for index in 0..manifest.repositories.len() {
            let repo_root = manifest.repositories[index].manifest.repo_root.clone();
            let mut refreshed_options = options.clone();
            refreshed_options.now = SystemTime::now();
            let refreshed = plan_cleanup(Some(&repo_root), refreshed_options)?;
            manifest.repositories[index] = refreshed;
            write_root_manifest(&manifest)?;
            execute_cleanup_manifest(&manifest.repositories[index].manifest)?;
        }
    }

    Ok(RootCleanupRun {
        manifest_path,
        manifest,
    })
}

fn execute_cleanup_manifest(manifest: &CleanupManifest) -> Result<()> {
    run_worktree_prune(&manifest.current_worktree, true)?;
    execute_cleanup(manifest)
}

pub fn discover_repositories(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let roots = canonicalize_roots(roots)?;
    let mut candidates = Vec::new();

    for root in roots {
        if root.join(".git").exists() {
            candidates.push(root);
            continue;
        }

        if let Some(discovered) = discover_repositories_with_ripgrep(&root)? {
            candidates.extend(discovered);
            continue;
        }

        let mut walker = WalkDir::new(&root)
            .follow_links(false)
            .sort_by_file_name()
            .into_iter();
        while let Some(entry) = walker.next() {
            let entry = entry.with_context(|| {
                format!("failed to discover repositories under {}", root.display())
            })?;
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
    }

    let mut hinted_repositories = BTreeMap::new();
    for candidate in candidates {
        let key = git_common_dir_hint(&candidate).unwrap_or_else(|| candidate.clone());
        hinted_repositories.entry(key).or_insert(candidate);
    }

    let mut repositories = BTreeMap::new();
    for candidate in hinted_repositories.into_values() {
        let common_dir = git_output(
            &candidate,
            ["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?;
        let common_dir = fs::canonicalize(common_dir.trim()).with_context(|| {
            format!(
                "failed to resolve Git common directory for {}",
                candidate.display()
            )
        })?;
        if repositories.contains_key(&common_dir) {
            continue;
        }
        let worktrees = parse_worktree_list(&git_output(
            &candidate,
            ["worktree", "list", "--porcelain"],
        )?);
        let primary = worktrees
            .iter()
            .find(|worktree| {
                !worktree.bare && worktree.prunable.is_none() && worktree.path.exists()
            })
            .map(|worktree| worktree.path.as_path())
            .unwrap_or(candidate.as_path());
        let primary = fs::canonicalize(primary)
            .with_context(|| format!("failed to resolve primary worktree {}", primary.display()))?;
        repositories.insert(common_dir, primary);
    }

    let mut repositories = repositories.into_values().collect::<Vec<_>>();
    repositories.sort();
    Ok(repositories)
}

fn git_common_dir_hint(worktree: &Path) -> Option<PathBuf> {
    let dot_git = worktree.join(".git");
    if dot_git.is_dir() {
        return fs::canonicalize(dot_git).ok();
    }
    let contents = fs::read_to_string(&dot_git).ok()?;
    let git_dir = contents.trim().strip_prefix("gitdir: ")?;
    let git_dir = fs::canonicalize(resolve_relative(worktree, Path::new(git_dir))).ok()?;
    let parent = git_dir.parent()?;
    if parent.file_name() == Some(OsStr::new("worktrees")) {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(git_dir)
    }
}

fn discover_repositories_with_ripgrep(root: &Path) -> Result<Option<Vec<PathBuf>>> {
    let sibling_rg = std::env::current_exe()
        .ok()
        .and_then(|executable| executable.parent().map(|parent| parent.join("rg")))
        .filter(|path| path.is_file());
    let output = match Command::new(sibling_rg.as_deref().unwrap_or_else(|| Path::new("rg")))
        .args([
            "--files",
            "--hidden",
            "--no-ignore",
            "-g",
            "**/.git",
            "-g",
            "**/.git/HEAD",
            "-g",
            "!**/node_modules/**",
            "-g",
            "!**/target/**",
            "-g",
            "!**/.next/**",
            "-g",
            "!**/.turbo/**",
            "-g",
            "!**/dist/**",
        ])
        .arg(root)
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("failed to run ripgrep repository discovery"),
    };
    if !output.status.success() && output.status.code() != Some(1) {
        bail!(
            "ripgrep repository discovery failed under {}: {}",
            root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut repositories = split_nul_or_line_paths(&output.stdout)
        .into_iter()
        .filter_map(|path| {
            if path.file_name() == Some(OsStr::new("HEAD"))
                && path.parent()?.file_name() == Some(OsStr::new(".git"))
            {
                path.parent()?.parent().map(Path::to_path_buf)
            } else if path.file_name() == Some(OsStr::new(".git")) {
                path.parent().map(Path::to_path_buf)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    repositories.sort();
    repositories.dedup();
    let mut top_level = Vec::<PathBuf>::new();
    for repository in repositories {
        let excluded = repository
            .ancestors()
            .take_while(|ancestor| *ancestor != root)
            .any(skip_repository_discovery_dir);
        if excluded {
            continue;
        }
        if !top_level
            .iter()
            .any(|parent| repository.starts_with(parent))
        {
            top_level.push(repository);
        }
    }
    Ok(Some(top_level))
}

fn split_nul_or_line_paths(output: &[u8]) -> Vec<PathBuf> {
    output
        .split(|byte| *byte == b'\0' || *byte == b'\n')
        .filter(|path| !path.is_empty())
        .map(|path| PathBuf::from(String::from_utf8_lossy(path).into_owned()))
        .collect()
}

fn canonicalize_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if roots.is_empty() {
        bail!("at least one discovery root is required");
    }
    let mut canonical = roots
        .iter()
        .map(|root| {
            fs::canonicalize(root)
                .with_context(|| format!("failed to resolve discovery root {}", root.display()))
        })
        .collect::<Result<Vec<_>>>()?;
    canonical.sort();
    canonical.dedup();
    Ok(canonical)
}

fn skip_repository_discovery_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(OsStr::to_str).unwrap_or_default();
    matches!(
        name,
        ".git" | "node_modules" | "target" | ".next" | ".turbo" | "dist" | ".worktree-gc-trash"
    ) || name.contains(".materialized-backup-")
}

pub fn print_triage(report: &TriageReport) {
    let live = report
        .worktrees
        .iter()
        .filter(|w| w.prunable.is_none())
        .count();
    let prunable = report
        .worktrees
        .iter()
        .filter(|w| w.prunable.is_some())
        .count();
    let dirty = report
        .worktrees
        .iter()
        .filter(|w| w.dirty_count.unwrap_or_default() > 0)
        .count();
    let removable = report
        .worktree_decisions
        .iter()
        .filter(|d| d.action == WorktreeAction::Remove)
        .count();
    let generated_delete = report
        .generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::Delete)
        .count();
    let generated_sweep = report
        .generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::Sweep)
        .count();
    let dist_report = report
        .generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::ReportOnly)
        .count();

    println!("repo: {}", report.repo_root.display());
    println!(
        "worktrees: {} live, {} prunable metadata, {} dirty, {} stale clean removal candidates",
        live, prunable, dirty, removable
    );
    println!(
        "generated dirs: {} delete candidates, {} sweep candidates, {} report-only",
        generated_delete, generated_sweep, dist_report
    );

    print_prunable(&report.worktrees);
    print_worktree_removals(&report.worktree_decisions);
    print_dirty(&report.worktrees);
    print_generated(&report.generated_dirs);
}

pub fn print_audit(report: &AuditReport) {
    print_triage(report);
}

pub fn print_cleanup(run: &CleanupRun) {
    let remove = run
        .manifest
        .worktrees
        .iter()
        .filter(|d| d.action == WorktreeAction::Remove)
        .count();
    let prune = run
        .manifest
        .worktrees
        .iter()
        .filter(|d| d.action == WorktreeAction::PruneMetadata)
        .count();
    let generated_delete = run
        .manifest
        .generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::Delete)
        .count();
    let generated_sweep = run
        .manifest
        .generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::Sweep)
        .count();

    match run.manifest.mode {
        CleanupMode::DryRun => println!("mode: dry-run"),
        CleanupMode::Execute => println!("mode: execute"),
    }
    println!("manifest: {}", run.manifest_path.display());
    println!("prunable metadata records: {}", prune);
    println!("stale clean worktrees to remove: {}", remove);
    println!("generated dirs to delete: {}", generated_delete);
    println!("generated dirs to sweep in place: {}", generated_sweep);

    if !run.manifest.prune_output.trim().is_empty() {
        println!();
        println!("git worktree prune:");
        print!("{}", run.manifest.prune_output);
    }

    let removals = run
        .manifest
        .worktrees
        .iter()
        .filter(|d| d.action == WorktreeAction::Remove)
        .collect::<Vec<_>>();
    if !removals.is_empty() {
        println!();
        println!("worktree removals:");
        for decision in removals {
            println!(
                "- {} ({})",
                decision.path.display(),
                decision.branch.as_deref().unwrap_or("detached")
            );
        }
    }

    print_sweep_candidates(
        run.manifest
            .generated_dirs
            .iter()
            .map(|dir| (dir.path.as_path(), dir.sweeps.as_slice())),
    );
}

pub fn print_root_triage(report: &RootTriageReport) {
    println!(
        "discovery roots: {}, repositories: {}",
        report.roots.len(),
        report.repositories.len()
    );
    for repository in &report.repositories {
        println!();
        println!("=== {} ===", repository.repo_root.display());
        print_triage(repository);
    }
}

pub fn print_root_cleanup(run: &RootCleanupRun) {
    let removed_worktrees = run
        .manifest
        .repositories
        .iter()
        .flat_map(|run| &run.manifest.worktrees)
        .filter(|decision| decision.action == WorktreeAction::Remove)
        .count();
    let deleted_dirs = run
        .manifest
        .repositories
        .iter()
        .flat_map(|run| &run.manifest.generated_dirs)
        .filter(|decision| decision.action == GeneratedDirAction::Delete)
        .count();
    let swept_dirs = run
        .manifest
        .repositories
        .iter()
        .flat_map(|run| &run.manifest.generated_dirs)
        .filter(|decision| decision.action == GeneratedDirAction::Sweep)
        .count();

    println!("aggregate manifest: {}", run.manifest_path.display());
    println!(
        "discovery roots: {}, repositories: {}",
        run.manifest.roots.len(),
        run.manifest.repositories.len()
    );
    println!(
        "aggregate plan: {} worktrees, {} generated dirs, {} in-place sweeps",
        removed_worktrees, deleted_dirs, swept_dirs
    );
    for repository in &run.manifest.repositories {
        println!();
        println!("=== {} ===", repository.manifest.repo_root.display());
        print_cleanup(repository);
    }
}

fn repo_context(repo: Option<&Path>) -> Result<RepoContext> {
    let cwd = repo.unwrap_or_else(|| Path::new("."));
    let current_worktree = git_output(cwd, ["rev-parse", "--show-toplevel"])?
        .trim()
        .to_string();
    let current_worktree =
        fs::canonicalize(current_worktree).context("failed to canonicalize current worktree")?;

    let git_common_dir = git_output(&current_worktree, ["rev-parse", "--git-common-dir"])?
        .trim()
        .to_string();
    let git_common_dir = resolve_relative(&current_worktree, Path::new(&git_common_dir));

    Ok(RepoContext {
        current_worktree,
        git_common_dir,
    })
}

fn inspect_worktrees(context: &RepoContext, now: SystemTime) -> Result<Vec<WorktreeInfo>> {
    let raw = parse_worktree_list(&git_output(
        &context.current_worktree,
        ["worktree", "list", "--porcelain"],
    )?);
    let current_canonical = fs::canonicalize(&context.current_worktree)?;

    raw.into_par_iter()
        .filter(|entry| !entry.bare)
        .map(|entry| inspect_worktree(entry, &current_canonical, now))
        .collect()
}

fn inspect_worktree(
    entry: RawWorktree,
    current_canonical: &Path,
    now: SystemTime,
) -> Result<WorktreeInfo> {
    let exists = entry.path.exists();
    let canonical = if exists {
        fs::canonicalize(&entry.path).ok()
    } else {
        None
    };
    let is_current = canonical.as_deref() == Some(current_canonical);

    if entry.prunable.is_some() || !exists {
        return Ok(WorktreeInfo {
            path: entry.path,
            head: entry.head,
            branch: entry.branch,
            detached: entry.detached,
            prunable: entry.prunable,
            exists,
            is_current,
            dirty_count: None,
            upstream: None,
            ahead: None,
            behind: None,
            last_commit_unix: None,
            last_commit: None,
            activity_unix: None,
            activity_age_days: None,
        });
    }

    let status = dirty_status(&entry.path)?;
    let upstream = git_output_allow_failure(&entry.path, ["rev-parse", "--abbrev-ref", "@{u}"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (behind, ahead) = upstream
        .as_deref()
        .and_then(|upstream| ahead_behind(&entry.path, upstream).ok())
        .unwrap_or((None, None));
    let last_commit_unix = git_output(&entry.path, ["log", "-1", "--format=%ct"])
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok());
    let activity_unix = max_time(last_commit_unix, status.newest_dirty_mtime_unix);

    Ok(WorktreeInfo {
        path: entry.path,
        head: entry.head,
        branch: entry.branch,
        detached: entry.detached,
        prunable: None,
        exists,
        is_current,
        dirty_count: Some(status.dirty_count),
        upstream,
        ahead,
        behind,
        last_commit_unix,
        last_commit: last_commit_unix.map(format_unix_time),
        activity_unix,
        activity_age_days: activity_unix.and_then(|unix| age_days(now, unix)),
    })
}

fn parse_worktree_list(output: &str) -> Vec<RawWorktree> {
    let mut entries = Vec::new();
    let mut current: Option<RawWorktree> = None;

    for line in output.lines() {
        if line.is_empty() {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            continue;
        }

        if let Some(path) = line.strip_prefix("worktree ") {
            if let Some(entry) = current.take() {
                entries.push(entry);
            }
            current = Some(RawWorktree {
                path: PathBuf::from(path),
                ..RawWorktree::default()
            });
            continue;
        }

        let Some(entry) = current.as_mut() else {
            continue;
        };

        if let Some(head) = line.strip_prefix("HEAD ") {
            entry.head = Some(head.to_string());
        } else if let Some(branch) = line.strip_prefix("branch ") {
            entry.branch = Some(
                branch
                    .strip_prefix("refs/heads/")
                    .unwrap_or(branch)
                    .to_string(),
            );
        } else if line == "detached" {
            entry.detached = true;
        } else if line == "bare" {
            entry.bare = true;
        } else if let Some(reason) = line.strip_prefix("prunable ") {
            entry.prunable = Some(reason.to_string());
        }
    }

    if let Some(entry) = current {
        entries.push(entry);
    }

    entries
}

fn dirty_status(path: &Path) -> Result<DirtyStatus> {
    let output = git_bytes(path, ["status", "--porcelain=v1", "-z"])?;
    let mut dirty_count = 0;
    let mut newest_dirty_mtime_unix = None;
    let mut parts = output.split(|byte| *byte == 0);

    while let Some(entry) = parts.next() {
        if entry.is_empty() || entry.len() < 4 {
            continue;
        }

        dirty_count += 1;
        let status = &entry[0..2];
        let relative = String::from_utf8_lossy(&entry[3..]).to_string();
        let dirty_path = path.join(relative);
        if let Ok(metadata) = fs::symlink_metadata(dirty_path) {
            if let Ok(modified) = metadata.modified() {
                newest_dirty_mtime_unix =
                    max_time(newest_dirty_mtime_unix, system_time_to_unix(modified));
            }
        }

        if status[0] == b'R' || status[0] == b'C' {
            let _ = parts.next();
        }
    }

    Ok(DirtyStatus {
        dirty_count,
        newest_dirty_mtime_unix,
    })
}

#[derive(Debug)]
struct DirtyStatus {
    dirty_count: usize,
    newest_dirty_mtime_unix: Option<i64>,
}

fn ahead_behind(path: &Path, upstream: &str) -> Result<(Option<u64>, Option<u64>)> {
    let range = format!("{upstream}...HEAD");
    let output = git_output(path, ["rev-list", "--left-right", "--count", &range])?;
    let mut parts = output.split_whitespace();
    let behind = parts.next().and_then(|s| s.parse::<u64>().ok());
    let ahead = parts.next().and_then(|s| s.parse::<u64>().ok());

    Ok((behind, ahead))
}

fn scan_generated_dirs(
    worktrees: &[WorktreeInfo],
    generated_days: u64,
    generated_activity_only: bool,
    check_in_use: bool,
    now: SystemTime,
    config: &GeneratedDirConfig,
) -> Result<Vec<GeneratedDirInfo>> {
    let mut dirs: Vec<GeneratedDirInfo> = worktrees
        .par_iter()
        .map(|worktree| {
            scan_generated_dirs_for_worktree(
                worktree,
                generated_days,
                generated_activity_only,
                check_in_use,
                now,
                config,
            )
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();

    dirs.sort_by(|left, right| left.path.cmp(&right.path));
    let mut seen = HashSet::new();
    for dir in &mut dirs {
        for sweep in &mut dir.sweeps {
            let roots = sweep
                .candidates
                .iter()
                .map(|candidate| candidate.incremental_dir.clone())
                .collect::<HashSet<_>>();
            let owned_roots = roots
                .into_iter()
                .filter(|root| seen.insert((sweep.tool.clone(), root.clone())))
                .collect::<HashSet<_>>();
            sweep
                .candidates
                .retain(|candidate| owned_roots.contains(&candidate.incremental_dir));
        }
        if dir.action == GeneratedDirAction::Sweep
            && !dir.sweeps.iter().any(SweepDecision::has_work)
        {
            dir.action = GeneratedDirAction::Skip;
            dir.reason = "no stale sweep candidates remain after deduplication".to_string();
        }
    }

    Ok(dirs)
}

fn scan_generated_dirs_for_worktree(
    worktree: &WorktreeInfo,
    generated_days: u64,
    generated_activity_only: bool,
    check_in_use: bool,
    now: SystemTime,
    config: &GeneratedDirConfig,
) -> Result<Vec<GeneratedDirInfo>> {
    let mut dirs = Vec::new();

    if worktree.prunable.is_some() || !worktree.exists {
        return Ok(dirs);
    }

    let candidates = generated_candidates(worktree, config)?;
    let ignored_paths = git_ignored_paths(&worktree.path, &candidates)?;
    let tracked_paths = git_tracked_paths(&worktree.path, &candidates)?;
    let open_generated_dirs = if check_in_use {
        dirs_with_open_handles(candidates.iter().map(|candidate| candidate.path.as_path()))
    } else {
        HashSet::new()
    };

    for candidate in candidates {
        let effective_days = config.effective_days(&candidate.name, generated_days);
        let worktree_recent = !generated_activity_only
            && (worktree.is_current
                || worktree
                    .activity_age_days
                    .is_some_and(|days| days < effective_days));
        let relative_key = path_key(&candidate.relative);
        let ignored = ignored_paths.contains(&relative_key);
        let has_tracked_files = tracked_paths
            .iter()
            .any(|tracked| path_is_under(tracked, &relative_key));
        let mtime_unix = sampled_mtime_unix(&candidate.path, GENERATED_MTIME_SAMPLE_DEPTH);
        let dir_recent = mtime_unix
            .and_then(|unix| age_days(now, unix))
            .is_some_and(|days| days < effective_days);

        // Only pay for the open-handle probe when the directory would
        // otherwise be deleted.
        let deletable_so_far = candidate.action == GeneratedCandidateAction::Delete
            && !worktree_recent
            && !dir_recent
            && !has_tracked_files;
        let in_use = deletable_so_far && open_generated_dirs.contains(&candidate.path);
        let sweep_strategies = config.sweep_strategies(&candidate.name);
        let active = worktree_recent || dir_recent;
        let sweeps = if candidate.action != GeneratedCandidateAction::ReportOnly
            && (active || candidate.action == GeneratedCandidateAction::SweepOnly)
            && !has_tracked_files
            && !sweep_strategies.is_empty()
        {
            plan_sweep_decisions(&candidate.path, &worktree.path, sweep_strategies, now)?
        } else {
            Vec::new()
        };
        let has_sweep_work = sweeps.iter().any(SweepDecision::has_work);

        let (action, reason) = if candidate.action == GeneratedCandidateAction::ReportOnly {
            (
                GeneratedDirAction::ReportOnly,
                format!("{} is configured as report-only", candidate.name),
            )
        } else if in_use {
            (
                GeneratedDirAction::Skip,
                "a running process has open files in this directory".to_string(),
            )
        } else if candidate.action == GeneratedCandidateAction::SweepOnly {
            if has_tracked_files {
                (
                    GeneratedDirAction::Skip,
                    "directory contains tracked files".to_string(),
                )
            } else if has_sweep_work {
                let descriptions = sweeps
                    .iter()
                    .filter(|sweep| sweep.has_work())
                    .map(|sweep| format!("{}: {}", sweep_tool_name(&sweep.tool), sweep.reason))
                    .collect::<Vec<_>>()
                    .join("; ");
                (
                    GeneratedDirAction::Sweep,
                    format!("explicit in-place sweep: {descriptions}"),
                )
            } else {
                let planned_reason = sweeps
                    .iter()
                    .map(|sweep| sweep.reason.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                (
                    GeneratedDirAction::Skip,
                    if planned_reason.is_empty() {
                        "explicit sweep found no eligible artifacts".to_string()
                    } else {
                        planned_reason
                    },
                )
            }
        } else if active {
            if has_sweep_work {
                let descriptions = sweeps
                    .iter()
                    .filter(|sweep| sweep.has_work())
                    .map(|sweep| format!("{}: {}", sweep_tool_name(&sweep.tool), sweep.reason))
                    .collect::<Vec<_>>()
                    .join("; ");
                (
                    GeneratedDirAction::Sweep,
                    format!("active directory with sweep work: {descriptions}"),
                )
            } else {
                let planned_reason = sweeps
                    .iter()
                    .map(|sweep| sweep.reason.as_str())
                    .collect::<Vec<_>>()
                    .join("; ");
                (
                    GeneratedDirAction::Skip,
                    if !planned_reason.is_empty() {
                        planned_reason
                    } else if generated_activity_only {
                        format!("generated directory activity is newer than {effective_days} days")
                    } else {
                        format!(
                            "worktree or generated directory activity is newer than {effective_days} days"
                        )
                    },
                )
            }
        } else if has_tracked_files {
            (
                GeneratedDirAction::Skip,
                "directory contains tracked files".to_string(),
            )
        } else if ignored {
            (
                GeneratedDirAction::Delete,
                "ignored generated directory".to_string(),
            )
        } else {
            (
                GeneratedDirAction::Delete,
                "untracked generated directory".to_string(),
            )
        };

        dirs.push(GeneratedDirInfo {
            path: candidate.path,
            worktree_path: worktree.path.clone(),
            name: candidate.name,
            ignored,
            has_tracked_files,
            mtime_unix,
            mtime: mtime_unix.map(format_unix_time),
            effective_days,
            in_use,
            sweeps,
            action,
            reason,
        });
    }

    Ok(dirs)
}

fn plan_sweep_decisions(
    target_dir: &Path,
    worktree: &Path,
    mut strategies: Vec<&SweepStrategy>,
    now: SystemTime,
) -> Result<Vec<SweepDecision>> {
    strategies.sort_by_key(|strategy| strategy.tool.clone());
    strategies
        .into_iter()
        .map(|strategy| match strategy.tool {
            SweepTool::RustcIncremental => {
                let days = strategy
                    .limit
                    .age_days()
                    .context("rustc-incremental requires an age-days limit")?;
                let plan = plan_incremental_sweep(target_dir, worktree, days, now)?;
                Ok(SweepDecision {
                    tool: SweepTool::RustcIncremental,
                    limit: strategy.limit.clone(),
                    delegated: false,
                    project_dir: cargo_project_dir(target_dir, worktree),
                    reason: plan.reason,
                    candidates: plan.candidates,
                })
            }
            SweepTool::CargoSweep => Ok(SweepDecision {
                tool: SweepTool::CargoSweep,
                limit: strategy.limit.clone(),
                delegated: true,
                project_dir: cargo_project_dir(target_dir, worktree),
                reason: match strategy.limit {
                    SweepLimit::AgeDays { days } => {
                        format!("delegate fingerprint-associated outputs older than {days} days")
                    }
                    SweepLimit::MaxSize { bytes } => format!(
                        "delegate oldest fingerprint-associated outputs above {}",
                        format_bytes(bytes)
                    ),
                },
                candidates: Vec::new(),
            }),
        })
        .collect()
}

// Newest mtime among the directory itself and its descendants up to
// `depth` levels below it. A directory's own mtime only changes when a
// direct child is added or removed, so an actively-written build cache
// (e.g. .next/server/app during a dev session) can look stale from the
// top-level stat alone.
fn sampled_mtime_unix(path: &Path, depth: usize) -> Option<i64> {
    let mut newest = None;

    for entry in WalkDir::new(path)
        .follow_links(false)
        .max_depth(depth)
        .into_iter()
        .flatten()
    {
        let modified = entry
            .metadata()
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(system_time_to_unix);
        newest = max_time(newest, modified);
    }

    newest
}

// Best-effort open-handle probe. `lsof +D` walks the whole tree, which is
// too slow for multi-gigabyte caches, so this probes the directory and its
// immediate children (`+d`). That catches the common live-dev-server shapes
// (a held lockfile, trace file, or cache subdirectory handle) without the
// full walk. Candidate sets are chunked below the OS argument limit. A failed
// batch retries one directory at a time and keeps any individually unprobeable
// directory protected; an unavailable lsof still degrades to mtime-only
// judgment on supported platforms.
#[cfg(unix)]
fn dirs_with_open_handles<'a>(paths: impl Iterator<Item = &'a Path>) -> HashSet<PathBuf> {
    const LSOF_PATH_CHUNK_SIZE: usize = 64;

    let paths = paths.map(Path::to_path_buf).collect::<Vec<_>>();
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut open = HashSet::new();
    for chunk in paths.chunks(LSOF_PATH_CHUNK_SIZE) {
        match probe_open_handles(chunk) {
            Ok(found) => open.extend(found),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return HashSet::new(),
            Err(error) => {
                eprintln!(
                    "warning: batched lsof probe failed ({error}); retrying {} paths individually",
                    chunk.len()
                );
                for path in chunk {
                    match probe_open_handles(std::slice::from_ref(path)) {
                        Ok(found) => open.extend(found),
                        Err(individual_error)
                            if individual_error.kind() == io::ErrorKind::NotFound =>
                        {
                            return HashSet::new();
                        }
                        Err(individual_error) => {
                            eprintln!(
                                "warning: lsof probe failed for {}; keeping it protected: {individual_error}",
                                path.display()
                            );
                            open.insert(path.clone());
                        }
                    }
                }
            }
        }
    }
    open
}

#[cfg(unix)]
fn probe_open_handles(paths: &[PathBuf]) -> io::Result<HashSet<PathBuf>> {
    let mut command = Command::new("lsof");
    command.arg("-Fn");
    for path in paths {
        command.arg("+d").arg(path);
    }
    let output = command
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()?;

    Ok(output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.strip_prefix(b"n"))
        .filter_map(|line| std::str::from_utf8(line).ok())
        .filter_map(|open_path| {
            let open_path = Path::new(open_path);
            paths
                .iter()
                .find(|candidate| open_path.starts_with(candidate))
                .cloned()
        })
        .collect())
}

#[cfg(not(unix))]
fn dirs_with_open_handles<'a>(_paths: impl Iterator<Item = &'a Path>) -> HashSet<PathBuf> {
    HashSet::new()
}

fn generated_candidates(
    worktree: &WorktreeInfo,
    config: &GeneratedDirConfig,
) -> Result<Vec<GeneratedCandidate>> {
    let mut paths = Vec::new();
    paths.extend(git_generated_path_listing(
        &worktree.path,
        &["ls-files", "-z", "--cached"],
        config,
    )?);
    paths.extend(git_generated_path_listing(
        &worktree.path,
        &[
            "ls-files",
            "-z",
            "--others",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
        ],
        config,
    )?);
    paths.extend(git_generated_path_listing(
        &worktree.path,
        &[
            "ls-files",
            "-z",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "--no-empty-directory",
        ],
        config,
    )?);

    let mut candidates = BTreeMap::new();
    for listed in paths {
        let listed = Path::new(&listed);
        let mut relative = PathBuf::new();
        let mut matched = false;
        for component in listed.components() {
            relative.push(component.as_os_str());
            let name = component.as_os_str().to_string_lossy();
            let Some(action) = config.candidate_action(&name) else {
                continue;
            };
            let path = worktree.path.join(&relative);
            let is_real_dir = fs::symlink_metadata(&path)
                .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
                .unwrap_or(false);
            if is_real_dir {
                candidates
                    .entry(relative.clone())
                    .or_insert_with(|| GeneratedCandidate {
                        path,
                        relative: relative.clone(),
                        name: name.into_owned(),
                        action,
                    });
            }
            matched = true;
            break;
        }
        if !matched {
            discover_generated_descendants(&worktree.path, listed, config, &mut candidates)?;
        }
    }

    Ok(candidates.into_values().collect())
}

fn discover_generated_descendants(
    worktree: &Path,
    listed: &Path,
    config: &GeneratedDirConfig,
    candidates: &mut BTreeMap<PathBuf, GeneratedCandidate>,
) -> Result<()> {
    let root = worktree.join(listed);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(());
    }

    let mut stack = vec![(root, listed.to_path_buf())];
    while let Some((directory, relative)) = stack.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect ignored directory {}",
                        directory.display()
                    )
                });
            }
        };
        for entry in entries {
            let entry = entry?;
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".git" {
                continue;
            }
            let child_relative = relative.join(entry.file_name());
            if let Some(action) = config.candidate_action(&name) {
                candidates
                    .entry(child_relative.clone())
                    .or_insert_with(|| GeneratedCandidate {
                        path: entry.path(),
                        relative: child_relative,
                        name,
                        action,
                    });
            } else {
                stack.push((entry.path(), child_relative));
            }
        }
    }
    Ok(())
}

fn git_generated_path_listing(
    worktree: &Path,
    args: &[&str],
    config: &GeneratedDirConfig,
) -> Result<Vec<String>> {
    let mut command = Command::new("git");
    command.args(args).arg("--");
    for name in config
        .delete_names
        .iter()
        .chain(&config.report_only_names)
        .chain(
            config
                .sweep_strategies
                .iter()
                .map(|strategy| &strategy.name),
        )
    {
        command.arg(format!(":(glob)**/{}/**", git_glob_escape(name)));
    }
    let output = command
        .current_dir(worktree)
        .output()
        .with_context(|| format!("failed to list Git paths in {}", worktree.display()))?;
    if !output.status.success() {
        bail!(
            "git path listing failed in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(split_nul_strings(&output.stdout))
}

fn git_glob_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if matches!(character, '\\' | '*' | '?' | '[' | ']') {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn plan_worktree_cleanup(
    worktrees: &[WorktreeInfo],
    stale_days: u64,
    now: SystemTime,
) -> Vec<WorktreeDecision> {
    worktrees
        .iter()
        .map(|worktree| {
            let (action, reason) = if worktree.prunable.is_some() || !worktree.exists {
                (
                    WorktreeAction::PruneMetadata,
                    worktree
                        .prunable
                        .clone()
                        .unwrap_or_else(|| "worktree path does not exist".to_string()),
                )
            } else if worktree.is_current {
                (
                    WorktreeAction::Keep,
                    "current worktree is never removed".to_string(),
                )
            } else if worktree.dirty_count.unwrap_or_default() > 0 {
                (
                    WorktreeAction::Keep,
                    "dirty worktree is reserved for a second pass".to_string(),
                )
            } else if worktree.detached || worktree.branch.is_none() {
                (
                    WorktreeAction::Keep,
                    "detached worktree is kept to preserve commit reachability".to_string(),
                )
            } else if worktree
                .last_commit_unix
                .and_then(|unix| age_days(now, unix))
                .is_some_and(|days| days >= stale_days)
            {
                (
                    WorktreeAction::Remove,
                    format!("clean worktree last committed at least {stale_days} days ago"),
                )
            } else {
                (
                    WorktreeAction::Keep,
                    format!("not older than {stale_days} days"),
                )
            };

            WorktreeDecision {
                path: worktree.path.clone(),
                branch: worktree.branch.clone(),
                action,
                reason,
                dirty_count: worktree.dirty_count,
                last_commit: worktree.last_commit.clone(),
                activity_age_days: worktree.activity_age_days,
            }
        })
        .collect()
}

fn execute_cleanup(manifest: &CleanupManifest) -> Result<()> {
    let worktree_removals = manifest
        .worktrees
        .iter()
        .filter(|decision| decision.action == WorktreeAction::Remove)
        .collect::<Vec<_>>();
    let generated_deletions = manifest
        .generated_dirs
        .iter()
        .filter(|decision| decision.action == GeneratedDirAction::Delete)
        .collect::<Vec<_>>();
    let generated_sweeps = manifest
        .generated_dirs
        .iter()
        .filter(|decision| decision.action == GeneratedDirAction::Sweep)
        .collect::<Vec<_>>();

    eprintln!(
        "executing cleanup: {} worktrees, {} generated dirs, {} sweeps",
        worktree_removals.len(),
        generated_deletions.len(),
        generated_sweeps.len()
    );

    for (index, decision) in worktree_removals.iter().enumerate() {
        eprintln!(
            "[worktree {}/{}] removing {}",
            index + 1,
            worktree_removals.len(),
            decision.path.display()
        );
        flush_stderr();
        if decision.action != WorktreeAction::Remove {
            continue;
        }

        git_status_command(
            &manifest.current_worktree,
            [
                "worktree".as_ref(),
                "remove".as_ref(),
                decision.path.as_os_str(),
            ],
        )
        .with_context(|| format!("failed to remove {}", decision.path.display()))?;
    }

    for (index, decision) in generated_deletions.iter().enumerate() {
        if index == 0 || index % 25 == 0 {
            eprintln!(
                "[generated {}/{}] deleting {}",
                index + 1,
                generated_deletions.len(),
                decision.path.display()
            );
            flush_stderr();
        }

        if decision.action != GeneratedDirAction::Delete {
            continue;
        }

        if decision.path.exists() {
            fs::remove_dir_all(&decision.path)
                .with_context(|| format!("failed to remove {}", decision.path.display()))?;
        }
    }

    for (index, decision) in generated_sweeps.iter().enumerate() {
        eprintln!(
            "[sweep {}/{}] sweeping {}",
            index + 1,
            generated_sweeps.len(),
            decision.path.display()
        );
        flush_stderr();
        let run_id = format!(
            "{}-{}",
            manifest.generated_at.replace([':', '.'], "-"),
            std::process::id()
        );
        if let Err(error) = run_sweeps(
            decision,
            &run_id,
            manifest.cargo_lock_timeout_secs.map(Duration::from_secs),
        ) {
            if manifest.defer_lock_timeouts && is_cargo_lock_timeout(&error) {
                write_deferred_sweep(decision, &run_id, &error)?;
                eprintln!(
                    "  deferred {} until a later run: {error:#}",
                    decision.path.display()
                );
                continue;
            }
            return Err(error);
        }
    }

    Ok(())
}

fn write_deferred_sweep(
    decision: &GeneratedDirDecision,
    run_id: &str,
    error: &anyhow::Error,
) -> Result<()> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .context("neither XDG_STATE_HOME nor HOME is set")?;
    let inbox = state_home.join("worktree-gc/inbox");
    fs::create_dir_all(&inbox)?;
    let mut hasher = DefaultHasher::new();
    decision.path.hash(&mut hasher);
    let path = inbox.join(format!("{run_id}-{:016x}.json", hasher.finish()));
    let event = serde_json::json!({
        "manifest_version": MANIFEST_VERSION,
        "kind": "cargo_lock_timeout",
        "deferred_at": run_id,
        "path": decision.path,
        "worktree_path": decision.worktree_path,
        "reason": format!("{error:#}"),
    });
    fs::write(&path, serde_json::to_vec_pretty(&event)?)?;
    Ok(())
}

fn run_sweeps(
    decision: &GeneratedDirDecision,
    run_id: &str,
    cargo_lock_timeout: Option<Duration>,
) -> Result<()> {
    for sweep in &decision.sweeps {
        match sweep.tool {
            SweepTool::RustcIncremental => {
                let days = sweep
                    .limit
                    .age_days()
                    .context("rustc-incremental requires an age-days limit")?;
                execute_incremental_sweep_with_timeout(
                    &sweep.candidates,
                    days,
                    run_id,
                    cargo_lock_timeout,
                )?;
            }
            // External cargo-sweep failures remain non-fatal so the rest of
            // the planned cleanup can continue.
            SweepTool::CargoSweep => {
                // Pass the project directory containing the matched target dir
                // explicitly: the scan can match nested `target/` dirs
                // (workspace members, vendored crates), and without a path
                // cargo-sweep defaults to the project it happens to run in,
                // which could silently sweep the wrong target.
                let project_dir = sweep
                    .project_dir
                    .as_deref()
                    .unwrap_or(&decision.worktree_path);
                let result = with_cargo_profile_locks_timeout(
                    &decision.path,
                    &decision.worktree_path,
                    cargo_lock_timeout,
                    || {
                        let mut command = Command::new("cargo");
                        command.arg("sweep");
                        match sweep.limit {
                            SweepLimit::AgeDays { days } => {
                                command.arg("--time").arg(days.to_string());
                            }
                            SweepLimit::MaxSize { bytes } => {
                                command.arg("--maxsize").arg(format!("{bytes}B"));
                            }
                        }
                        command
                            .arg(project_dir)
                            .current_dir(&decision.worktree_path)
                            .stdin(Stdio::null())
                            .output()
                    },
                );
                match result {
                    Ok(Ok(output)) if output.status.success() => {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        if let Some(line) = stderr
                            .lines()
                            .rev()
                            .find(|line| line.contains("Cleaned"))
                            .or_else(|| stdout.lines().rev().find(|line| line.contains("Cleaned")))
                        {
                            eprintln!("  {}", line.trim_start_matches("[INFO] "));
                        }
                    }
                    Ok(Ok(output)) => {
                        eprintln!(
                            "  sweep failed (exit {:?}); is cargo-sweep installed? (cargo install cargo-sweep)",
                            output.status.code()
                        );
                    }
                    Ok(Err(error)) => {
                        eprintln!("  sweep failed to launch: {error}");
                    }
                    Err(error) if is_cargo_lock_timeout(&error) => return Err(error),
                    Err(error) => eprintln!("  sweep skipped: {error:#}"),
                }
            }
        }
    }
    Ok(())
}

fn flush_stderr() {
    let _ = io::stderr().flush();
}

fn write_manifest(git_common_dir: &Path, manifest: &CleanupManifest) -> Result<PathBuf> {
    let manifest_dir = git_common_dir.join("worktree-gc");
    fs::create_dir_all(&manifest_dir).context("failed to create manifest directory")?;

    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let filename = format!(
        "{}-{mode}.json",
        manifest.generated_at.replace([':', '.'], "-")
    );
    let path = manifest_dir.join(filename);
    let json = serde_json::to_vec_pretty(manifest)?;
    fs::write(&path, json).context("failed to write cleanup manifest")?;

    Ok(path)
}

fn write_root_manifest(manifest: &RootCleanupManifest) -> Result<PathBuf> {
    let state_home = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|home| home.join(".local/state"))
        })
        .context("neither XDG_STATE_HOME nor HOME is set")?;
    let manifest_dir = state_home.join("worktree-gc");
    fs::create_dir_all(&manifest_dir)
        .with_context(|| format!("failed to create {}", manifest_dir.display()))?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = manifest_dir.join(format!(
        "{}-roots-{mode}.json",
        manifest.generated_at.replace([':', '.'], "-")
    ));
    let json = serde_json::to_vec_pretty(manifest)?;
    fs::write(&path, json)
        .with_context(|| format!("failed to write aggregate manifest {}", path.display()))?;
    Ok(path)
}

fn run_worktree_prune(repo: &Path, execute: bool) -> Result<String> {
    let args: &[&str] = if execute {
        &["worktree", "prune", "--verbose"]
    } else {
        &["worktree", "prune", "--dry-run", "--verbose"]
    };
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .with_context(|| format!("failed to run git worktree prune in {}", repo.display()))?;

    if !output.status.success() {
        bail!(
            "git worktree prune failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(combined)
}

fn print_prunable(worktrees: &[WorktreeInfo]) {
    let prunable = worktrees
        .iter()
        .filter(|w| w.prunable.is_some())
        .collect::<Vec<_>>();
    if prunable.is_empty() {
        return;
    }

    println!();
    println!("prunable metadata:");
    for worktree in prunable {
        println!(
            "- {} ({})",
            worktree.path.display(),
            worktree.prunable.as_deref().unwrap_or("prunable")
        );
    }
}

fn print_worktree_removals(decisions: &[WorktreeDecision]) {
    let removals = decisions
        .iter()
        .filter(|d| d.action == WorktreeAction::Remove)
        .take(25)
        .collect::<Vec<_>>();
    if removals.is_empty() {
        return;
    }

    println!();
    println!("stale clean worktree removal candidates (first 25):");
    for decision in removals {
        println!(
            "- {} {} ({})",
            decision.branch.as_deref().unwrap_or("detached"),
            decision.path.display(),
            decision.reason
        );
    }
}

fn print_dirty(worktrees: &[WorktreeInfo]) {
    let dirty = worktrees
        .iter()
        .filter(|w| w.dirty_count.unwrap_or_default() > 0)
        .collect::<Vec<_>>();
    if dirty.is_empty() {
        return;
    }

    println!();
    println!("dirty worktrees kept:");
    for worktree in dirty {
        println!(
            "- dirty={} {} {}",
            worktree.dirty_count.unwrap_or_default(),
            worktree.branch.as_deref().unwrap_or("detached"),
            worktree.path.display()
        );
    }
}

fn print_generated(generated_dirs: &[GeneratedDirInfo]) {
    let delete = generated_dirs
        .iter()
        .filter(|d| d.action == GeneratedDirAction::Delete)
        .take(25)
        .collect::<Vec<_>>();
    if !delete.is_empty() {
        println!();
        println!("generated delete candidates (first 25):");
        for dir in delete {
            println!("- {} ({})", dir.path.display(), dir.reason);
        }
    }

    print_sweep_candidates(
        generated_dirs
            .iter()
            .map(|dir| (dir.path.as_path(), dir.sweeps.as_slice())),
    );
}

fn print_sweep_candidates<'a>(dirs: impl IntoIterator<Item = (&'a Path, &'a [SweepDecision])>) {
    let candidates = dirs
        .into_iter()
        .flat_map(|(target, sweeps)| {
            sweeps.iter().flat_map(move |sweep| {
                sweep
                    .candidates
                    .iter()
                    .filter(|candidate| {
                        matches!(
                            candidate.action,
                            SweepCandidateAction::Delete | SweepCandidateAction::RecoverTrash
                        )
                    })
                    .map(move |candidate| (target, sweep, candidate))
            })
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return;
    }

    let bytes = candidates
        .iter()
        .map(|(_, _, candidate)| candidate.logical_bytes)
        .sum::<u64>();
    println!();
    println!(
        "generated sweep artifacts: {} entries, {} logical",
        candidates.len(),
        format_bytes(bytes)
    );
    for (target, sweep, candidate) in candidates.iter().take(50) {
        let activity = candidate
            .activity_age_days
            .map(|days| format!("{days}d old"))
            .unwrap_or_else(|| "interrupted-run quarantine".to_string());
        println!(
            "- {} [{} in {}; {}, {}]",
            candidate.path.display(),
            sweep_tool_name(&sweep.tool),
            target.display(),
            activity,
            format_bytes(candidate.logical_bytes)
        );
    }
    if candidates.len() > 50 {
        println!("- ... and {} more (see manifest)", candidates.len() - 50);
    }
}

fn sweep_tool_name(tool: &SweepTool) -> &'static str {
    match tool {
        SweepTool::RustcIncremental => "rustc-incremental",
        SweepTool::CargoSweep => "cargo-sweep",
    }
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

fn git_output<const N: usize>(cwd: &Path, args: [&str; N]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;

    if !output.status.success() {
        bail!(
            "git failed in {}: {}",
            cwd.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn git_output_allow_failure<const N: usize>(cwd: &Path, args: [&str; N]) -> Option<String> {
    git_output(cwd, args).ok()
}

fn git_bytes<const N: usize>(cwd: &Path, args: [&str; N]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;

    if !output.status.success() {
        bail!(
            "git failed in {}: {}",
            cwd.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(output.stdout)
}

fn git_status_command<const N: usize>(cwd: &Path, args: [&OsStr; N]) -> Result<()> {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .with_context(|| format!("failed to run git in {}", cwd.display()))?;

    if !status.success() {
        bail!("git command failed in {}", cwd.display());
    }

    Ok(())
}

fn git_ignored_paths(
    worktree: &Path,
    candidates: &[GeneratedCandidate],
) -> Result<HashSet<String>> {
    if candidates.is_empty() {
        return Ok(HashSet::new());
    }

    let mut child = Command::new("git")
        .args(["check-ignore", "-z", "--stdin"])
        .current_dir(worktree)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run git check-ignore in {}", worktree.display()))?;

    {
        let stdin = child
            .stdin
            .as_mut()
            .context("failed to open git check-ignore stdin")?;
        for candidate in candidates {
            stdin.write_all(path_key(&candidate.relative).as_bytes())?;
            stdin.write_all(&[0])?;
        }
    }

    let output = child.wait_with_output()?;
    if !output.status.success() && output.status.code() != Some(1) {
        bail!(
            "git check-ignore failed in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(split_nul_strings(&output.stdout).into_iter().collect())
}

fn git_tracked_paths(
    worktree: &Path,
    candidates: &[GeneratedCandidate],
) -> Result<HashSet<String>> {
    if candidates.is_empty() {
        return Ok(HashSet::new());
    }

    let mut command = Command::new("git");
    command
        .arg("ls-files")
        .arg("-z")
        .arg("--")
        .current_dir(worktree);
    for candidate in candidates {
        command.arg(&candidate.relative);
    }

    let output = command
        .output()
        .with_context(|| format!("failed to run git ls-files in {}", worktree.display()))?;

    if !output.status.success() {
        bail!(
            "git ls-files failed in {}: {}",
            worktree.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    Ok(split_nul_strings(&output.stdout).into_iter().collect())
}

fn split_nul_strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect()
}

fn normalize_names(names: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for name in names {
        let name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }

        if seen.insert(name.clone()) {
            normalized.push(name);
        }
    }

    normalized
}

fn normalize_sweep_strategies(strategies: Vec<SweepStrategy>) -> Vec<SweepStrategy> {
    let mut normalized: Vec<SweepStrategy> = Vec::new();
    for strategy in strategies {
        if let Some(existing) = normalized
            .iter_mut()
            .find(|existing| existing.name == strategy.name && existing.tool == strategy.tool)
        {
            *existing = strategy;
        } else {
            normalized.push(strategy);
        }
    }
    normalized
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn path_is_under(path: &str, directory: &str) -> bool {
    path == directory
        || path
            .strip_prefix(directory)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
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
    // A file written while the scan is running (or under clock skew) can
    // carry an mtime newer than the captured `now`. That is the most
    // recent activity possible, not an error: treat it as age zero rather
    // than letting duration_since fail and the entry read as "no activity".
    let duration = now.duration_since(then).unwrap_or(Duration::ZERO);
    Some(duration.as_secs() / 86_400)
}

fn format_unix_time(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|dt| dt.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

fn format_system_time(time: SystemTime) -> String {
    system_time_to_unix(time)
        .map(format_unix_time)
        .unwrap_or_else(|| "unknown-time".to_string())
}

fn system_time_to_unix(time: SystemTime) -> Option<i64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_secs().try_into().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn init_repo() -> Result<(TempDir, PathBuf)> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("repo");
        fs::create_dir(&repo)?;
        git_output(&repo, ["init"])?;
        git_output(&repo, ["config", "user.email", "test@example.com"])?;
        git_output(&repo, ["config", "user.name", "Test User"])?;
        fs::write(
            repo.join(".gitignore"),
            "node_modules\n.next\n.turbo\ntarget\n",
        )?;
        fs::write(repo.join("README.md"), "hello\n")?;
        git_output(&repo, ["add", "."])?;
        commit_with_date(&repo, "initial", "2025-01-01T00:00:00Z")?;
        Ok((temp, repo))
    }

    fn commit_with_date(repo: &Path, message: &str, date: &str) -> Result<()> {
        let output = Command::new("git")
            .args(["commit", "-m", message])
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_DATE", date)
            .current_dir(repo)
            .output()?;
        if !output.status.success() {
            bail!(
                "commit failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn add_worktree(repo: &Path, path: &Path, branch: &str) -> Result<()> {
        git_output(
            repo,
            [
                "worktree",
                "add",
                "-b",
                branch,
                path.to_str().context("non-utf8 path")?,
                "HEAD",
            ],
        )?;
        Ok(())
    }

    fn set_mtime(path: &Path, unix: i64) -> Result<()> {
        let time = UNIX_EPOCH + Duration::from_secs(u64::try_from(unix)?);
        let file = fs::File::options().read(true).open(path)?;
        file.set_modified(time)?;
        Ok(())
    }

    fn unix_days_before_now(days: u64) -> i64 {
        system_time_to_unix(now()).expect("test now fits in unix time") - (days * 86_400) as i64
    }

    #[test]
    fn effective_days_prefers_later_overrides() {
        let config = GeneratedDirConfig::from_names(
            true,
            Vec::new(),
            Vec::new(),
            vec![(".next".to_string(), 10)],
            Vec::new(),
        );

        // Custom override shadows the build-cache default for .next.
        assert_eq!(config.effective_days(".next", 7), 10);
        // Build-cache defaults still apply to the other cache names.
        assert_eq!(config.effective_days(".turbo", 7), DEFAULT_BUILD_CACHE_DAYS);
        assert_eq!(config.effective_days("target", 7), DEFAULT_BUILD_CACHE_DAYS);
        // Installs fall through to the generic window.
        assert_eq!(config.effective_days("node_modules", 7), 7);
    }

    #[test]
    fn default_and_explicit_sweep_strategies_compose_by_tool() {
        let config = GeneratedDirConfig::from_names_with_default_sweeps(
            true,
            true,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![
                SweepStrategy {
                    name: "target".to_string(),
                    tool: SweepTool::RustcIncremental,
                    limit: SweepLimit::AgeDays { days: 7 },
                },
                SweepStrategy {
                    name: "target".to_string(),
                    tool: SweepTool::CargoSweep,
                    limit: SweepLimit::AgeDays { days: 30 },
                },
            ],
        );

        let target_sweeps = config.sweep_strategies("target");
        assert_eq!(target_sweeps.len(), 2);
        assert_eq!(
            target_sweeps
                .iter()
                .find(|strategy| strategy.tool == SweepTool::RustcIncremental)
                .map(|strategy| &strategy.limit),
            Some(&SweepLimit::AgeDays { days: 7 })
        );
        assert_eq!(
            target_sweeps
                .iter()
                .find(|strategy| strategy.tool == SweepTool::CargoSweep)
                .map(|strategy| &strategy.limit),
            Some(&SweepLimit::AgeDays { days: 30 })
        );

        let without_sweeps = GeneratedDirConfig::from_names_with_default_sweeps(
            true,
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(without_sweeps.sweep_strategies("target").is_empty());
        assert!(without_sweeps
            .delete_names
            .iter()
            .any(|name| name == "target"));

        let without_generated_defaults = GeneratedDirConfig::from_names_with_default_sweeps(
            false,
            false,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(without_generated_defaults.delete_names.is_empty());
        assert!(without_generated_defaults.sweep_strategies.is_empty());
    }

    #[test]
    fn repository_discovery_stops_at_repo_boundaries_and_deduplicates_worktrees() -> Result<()> {
        let (temp, repo) = init_repo()?;
        let worktrees_dir = temp.path().join("repo.worktrees");
        fs::create_dir(&worktrees_dir)?;
        let linked = worktrees_dir.join("feature");
        add_worktree(&repo, &linked, "discovery-feature")?;

        let nested = repo.join("vendor/nested-repository");
        fs::create_dir_all(&nested)?;
        git_output(&nested, ["init"])?;

        let other = temp.path().join("other");
        fs::create_dir(&other)?;
        git_output(&other, ["init"])?;

        let backup = temp.path().join("old.materialized-backup-20260709");
        fs::create_dir(&backup)?;
        git_output(&backup, ["init"])?;

        let repositories = discover_repositories(&[temp.path().to_path_buf()])?;
        assert_eq!(
            repositories,
            vec![fs::canonicalize(&other)?, fs::canonicalize(&repo)?]
        );

        let linked_only = discover_repositories(&[linked])?;
        assert_eq!(linked_only, vec![fs::canonicalize(repo)?]);
        Ok(())
    }

    #[test]
    fn repository_discovery_uses_a_worktree_for_bare_common_repositories() -> Result<()> {
        let (temp, repo) = init_repo()?;
        let bare = temp.path().join("repo.git");
        let stale = temp.path().join("aaa-stale-worktree");
        let linked = temp.path().join("zzz-valid-worktree");
        let clone = Command::new("git")
            .arg("clone")
            .arg("--bare")
            .arg(&repo)
            .arg(&bare)
            .output()?;
        if !clone.status.success() {
            bail!(
                "bare clone failed: {}",
                String::from_utf8_lossy(&clone.stderr).trim()
            );
        }
        git_output(
            &bare,
            [
                "worktree",
                "add",
                stale.to_str().context("non-utf8 stale worktree path")?,
            ],
        )?;
        fs::remove_dir_all(&stale)?;
        git_output(
            &bare,
            [
                "worktree",
                "add",
                linked.to_str().context("non-utf8 worktree path")?,
            ],
        )?;

        let repositories = discover_repositories(std::slice::from_ref(&linked))?;
        assert_eq!(repositories, vec![fs::canonicalize(&linked)?]);

        let report = triage(
            Some(&linked),
            TriageOptions {
                stale_days: 30,
                generated_days: 7,
                generated_activity_only: false,
                check_in_use: false,
                generated_config: GeneratedDirConfig::default(),
                now: now(),
            },
        )?;
        assert!(report.worktrees.iter().any(|worktree| worktree.is_current));
        assert!(report
            .worktrees
            .iter()
            .any(|worktree| worktree.prunable.is_some()));
        Ok(())
    }

    #[test]
    fn default_incremental_sweep_activates_and_manifest_is_v2() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        fs::create_dir_all(repo.join("src"))?;
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )?;
        fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let profile = repo.join("target/debug");
        let root = profile.join("incremental/fixture-old");
        let session = root.join("s-session-hash");
        fs::create_dir_all(&session)?;
        fs::write(profile.join(".cargo-lock"), "")?;
        let dep_graph = session.join("dep-graph.bin");
        fs::write(&dep_graph, "old")?;
        let old = unix_days_before_now(20);
        set_mtime(&dep_graph, old)?;
        set_mtime(&session, old)?;
        set_mtime(&root, old)?;

        let run = cleanup(
            Some(&repo),
            CleanupOptions {
                execute: false,
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: false,
                check_in_use: false,
                generated_config: GeneratedDirConfig::default(),
                cargo_lock_timeout: None,
                defer_lock_timeouts: false,
                now: now(),
            },
        )?;

        let expected_target = fs::canonicalize(repo.join("target"))?;
        let target = run
            .manifest
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_target)
            .context("missing target decision")?;
        assert_eq!(target.action, GeneratedDirAction::Sweep);
        let sweep = target
            .sweeps
            .iter()
            .find(|sweep| sweep.tool == SweepTool::RustcIncremental)
            .context("missing default incremental sweep")?;
        assert_eq!(
            sweep.limit,
            SweepLimit::AgeDays {
                days: DEFAULT_INCREMENTAL_SWEEP_DAYS
            }
        );
        assert!(sweep
            .candidates
            .iter()
            .any(|candidate| candidate.action == SweepCandidateAction::Delete));

        let json = serde_json::to_value(&run.manifest)?;
        assert_eq!(json["manifest_version"], MANIFEST_VERSION);
        assert!(json["generated_dirs"][0].get("sweeps").is_some());
        assert!(json["generated_dirs"][0].get("sweep_tool").is_none());
        assert!(json["generated_dirs"][0].get("sweep_days").is_none());

        let explicit_only = cleanup(
            Some(&repo),
            CleanupOptions {
                execute: false,
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: false,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names_with_default_sweeps(
                    false,
                    false,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    vec![SweepStrategy {
                        name: "target".to_string(),
                        tool: SweepTool::RustcIncremental,
                        limit: SweepLimit::AgeDays { days: 14 },
                    }],
                ),
                cargo_lock_timeout: None,
                defer_lock_timeouts: false,
                now: now(),
            },
        )?;
        let target = explicit_only
            .manifest
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_target)
            .context("explicit sweep did not discover target")?;
        assert_eq!(target.action, GeneratedDirAction::Sweep);
        assert!(explicit_only.manifest.generated_delete_names.is_empty());
        Ok(())
    }

    #[test]
    fn deep_activity_in_generated_dir_prevents_deletion() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("deep-activity");
        add_worktree(&repo, &worktree, "deep-activity-branch")?;
        fs::create_dir_all(worktree.join("node_modules/pkg/dist/chunks/deep"))?;
        fs::write(
            worktree.join("node_modules/pkg/dist/chunks/deep/index.js"),
            "module.exports = 1\n",
        )?;
        let expected = fs::canonicalize(worktree.join("node_modules"))?;

        // The directory itself looks ancient, but a deeply nested file
        // (five levels below the candidate, like webpack's
        // .next/cache/webpack/client-development/N.pack rewrites) was
        // written recently — as during a live build. Rewriting an existing
        // file updates no ancestor mtimes, so only deep sampling sees it.
        // Age every ancestor explicitly to prove the deep file alone keeps
        // the directory alive.
        set_mtime(&worktree.join("node_modules"), unix_days_before_now(400))?;
        set_mtime(
            &worktree.join("node_modules/pkg"),
            unix_days_before_now(400),
        )?;
        set_mtime(
            &worktree.join("node_modules/pkg/dist"),
            unix_days_before_now(400),
        )?;
        set_mtime(
            &worktree.join("node_modules/pkg/dist/chunks"),
            unix_days_before_now(400),
        )?;
        set_mtime(
            &worktree.join("node_modules/pkg/dist/chunks/deep"),
            unix_days_before_now(400),
        )?;
        set_mtime(
            &worktree.join("node_modules/pkg/dist/chunks/deep/index.js"),
            unix_days_before_now(1),
        )?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names(
                    false,
                    vec!["node_modules".to_string()],
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                ),
                now: now(),
            },
        )?;

        let dir = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected)
            .context("missing node_modules entry")?;

        assert_eq!(dir.action, GeneratedDirAction::Skip);
        Ok(())
    }

    #[test]
    fn active_dirs_with_sweep_strategy_are_swept_not_skipped() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("sweepable");
        add_worktree(&repo, &worktree, "sweepable-branch")?;
        fs::create_dir_all(worktree.join("target/debug"))?;
        fs::write(worktree.join("target/debug/binary"), "bits\n")?;
        let expected = fs::canonicalize(worktree.join("target"))?;

        // Recent activity: without a sweep strategy this would be a skip.
        set_mtime(
            &worktree.join("target/debug/binary"),
            unix_days_before_now(1),
        )?;

        let strategy = SweepStrategy {
            name: "target".to_string(),
            tool: SweepTool::CargoSweep,
            limit: SweepLimit::AgeDays { days: 3 },
        };

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names(
                    false,
                    vec!["target".to_string()],
                    Vec::new(),
                    Vec::new(),
                    vec![strategy],
                ),
                now: now(),
            },
        )?;

        let dir = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected)
            .context("missing target entry")?;

        assert_eq!(dir.action, GeneratedDirAction::Sweep);
        let sweep = dir
            .sweeps
            .iter()
            .find(|sweep| sweep.tool == SweepTool::CargoSweep)
            .context("missing cargo-sweep plan")?;
        assert_eq!(sweep.limit, SweepLimit::AgeDays { days: 3 });

        // Stale dirs with a sweep strategy still prefer wholesale deletion.
        set_mtime(
            &worktree.join("target/debug/binary"),
            unix_days_before_now(400),
        )?;
        set_mtime(&worktree.join("target/debug"), unix_days_before_now(400))?;
        set_mtime(&worktree.join("target"), unix_days_before_now(400))?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names(
                    false,
                    vec!["target".to_string()],
                    Vec::new(),
                    Vec::new(),
                    vec![SweepStrategy {
                        name: "target".to_string(),
                        tool: SweepTool::CargoSweep,
                        limit: SweepLimit::AgeDays { days: 3 },
                    }],
                ),
                now: now(),
            },
        )?;

        let dir = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected)
            .context("missing target entry")?;

        assert_eq!(dir.action, GeneratedDirAction::Delete);
        Ok(())
    }

    #[test]
    fn cargo_sweep_uses_the_manifest_owner_for_nested_target_directories() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        fs::create_dir_all(repo.join("src"))?;
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )?;
        fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        fs::create_dir_all(repo.join(".cargo"))?;
        fs::write(
            repo.join(".cargo/config.toml"),
            "[build]\ntarget-dir = \"build/target\"\n",
        )?;
        fs::create_dir_all(repo.join("build/target/debug"))?;
        fs::write(repo.join("build/target/debug/binary"), "bits\n")?;
        set_mtime(
            &repo.join("build/target/debug/binary"),
            unix_days_before_now(1),
        )?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names(
                    false,
                    vec!["target".to_string()],
                    Vec::new(),
                    Vec::new(),
                    vec![SweepStrategy {
                        name: "target".to_string(),
                        tool: SweepTool::CargoSweep,
                        limit: SweepLimit::AgeDays { days: 3 },
                    }],
                ),
                now: now(),
            },
        )?;

        let target = fs::canonicalize(repo.join("build/target"))?;
        let decision = report
            .generated_dirs
            .iter()
            .find(|decision| decision.path == target)
            .context("missing nested target decision")?;
        let sweep = decision
            .sweeps
            .iter()
            .find(|sweep| sweep.tool == SweepTool::CargoSweep)
            .context("missing cargo-sweep decision")?;
        assert_eq!(sweep.project_dir, Some(fs::canonicalize(repo)?));
        Ok(())
    }

    #[test]
    fn generated_dirs_under_collapsed_ignored_ancestors_are_discovered() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        fs::write(repo.join(".gitignore"), "build/\n")?;
        fs::create_dir_all(repo.join("build/node_modules/pkg"))?;
        fs::write(
            repo.join("build/node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::default(),
                now: now(),
            },
        )?;

        let expected = fs::canonicalize(repo.join("build/node_modules"))?;
        let decision = report
            .generated_dirs
            .iter()
            .find(|decision| decision.path == expected)
            .context("missing node_modules below ignored build ancestor")?;
        assert_eq!(decision.action, GeneratedDirAction::Delete);
        Ok(())
    }

    #[test]
    fn build_caches_use_tighter_default_window() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("class-windows");
        add_worktree(&repo, &worktree, "class-windows-branch")?;
        fs::create_dir_all(worktree.join(".next/cache"))?;
        fs::write(worktree.join(".next/cache/entry"), "cache\n")?;
        fs::create_dir_all(worktree.join("node_modules/pkg"))?;
        fs::write(
            worktree.join("node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )?;
        let expected_next = fs::canonicalize(worktree.join(".next"))?;
        let expected_node_modules = fs::canonicalize(worktree.join("node_modules"))?;

        // Both trees were last touched 5 days ago: outside the 3-day
        // build-cache window, inside the 7-day install window.
        let five_days_ago = unix_days_before_now(5);
        for relative in [
            ".next/cache/entry",
            ".next/cache",
            ".next",
            "node_modules/pkg/index.js",
            "node_modules/pkg",
            "node_modules",
        ] {
            set_mtime(&worktree.join(relative), five_days_ago)?;
        }

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: false,
                generated_config: GeneratedDirConfig::default(),
                now: now(),
            },
        )?;

        let next = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_next)
            .context("missing .next entry")?;
        let node_modules = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_node_modules)
            .context("missing node_modules entry")?;

        assert_eq!(next.action, GeneratedDirAction::Delete);
        assert_eq!(next.effective_days, DEFAULT_BUILD_CACHE_DAYS);
        assert_eq!(node_modules.action, GeneratedDirAction::Skip);
        assert_eq!(node_modules.effective_days, 7);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn open_handles_prevent_deletion() -> Result<()> {
        if Command::new("lsof")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping: lsof unavailable");
            return Ok(());
        }

        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("in-use");
        add_worktree(&repo, &worktree, "in-use-branch")?;
        fs::create_dir_all(worktree.join("node_modules"))?;
        fs::write(worktree.join("node_modules/.lock"), "held\n")?;
        fs::create_dir_all(worktree.join(".next"))?;
        fs::write(worktree.join(".next/cache"), "idle\n")?;
        let expected = fs::canonicalize(worktree.join("node_modules"))?;
        let idle = fs::canonicalize(worktree.join(".next"))?;

        // Simulate a package manager holding its lockfile: real mtimes are
        // far older than the fixed test clock, so without the handle probe
        // this directory would be deleted.
        let _held = fs::File::open(worktree.join("node_modules/.lock"))?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: true,
                check_in_use: true,
                generated_config: GeneratedDirConfig::default(),
                now: now(),
            },
        )?;

        let dir = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected)
            .context("missing node_modules entry")?;

        assert_eq!(dir.action, GeneratedDirAction::Skip);
        assert!(dir.in_use);
        let idle = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == idle)
            .context("missing idle .next entry")?;
        assert_eq!(idle.action, GeneratedDirAction::Delete);
        assert!(!idle.in_use);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn open_handle_probe_chunks_large_candidate_sets() -> Result<()> {
        if Command::new("lsof")
            .arg("-v")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("skipping: lsof unavailable");
            return Ok(());
        }

        let temp = TempDir::new()?;
        let mut paths = Vec::new();
        for index in 0..129 {
            let path = temp.path().join(format!("candidate-{index}"));
            fs::create_dir(&path)?;
            paths.push(fs::canonicalize(path)?);
        }
        let held_path = paths.last().context("missing final candidate")?;
        fs::write(held_path.join("held.lock"), "held")?;
        let _held = fs::File::open(held_path.join("held.lock"))?;

        let open = dirs_with_open_handles(paths.iter().map(PathBuf::as_path));
        assert!(open.contains(held_path));
        Ok(())
    }

    #[test]
    fn cargo_sweep_lock_timeouts_propagate_for_scheduled_deferral() -> Result<()> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("repo");
        fs::create_dir_all(repo.join("src"))?;
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )?;
        fs::write(repo.join("src/lib.rs"), "pub fn fixture() {}\n")?;
        let profile = repo.join("target/debug");
        fs::create_dir_all(profile.join("incremental"))?;
        let lock_path = profile.join(".cargo-lock");
        fs::write(&lock_path, "")?;
        let held = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&lock_path)?;
        held.lock()?;

        let target = fs::canonicalize(repo.join("target"))?;
        let repo = fs::canonicalize(repo)?;
        let decision = GeneratedDirDecision {
            path: target,
            worktree_path: repo.clone(),
            name: "target".to_string(),
            mtime: None,
            effective_days: 3,
            in_use: false,
            sweeps: vec![SweepDecision {
                tool: SweepTool::CargoSweep,
                limit: SweepLimit::MaxSize { bytes: 1_000_000 },
                delegated: true,
                project_dir: Some(repo),
                reason: "test delegated sweep".to_string(),
                candidates: Vec::new(),
            }],
            action: GeneratedDirAction::Sweep,
            reason: "test sweep".to_string(),
        };

        let error = run_sweeps(
            &decision,
            "cargo-sweep-timeout-test",
            Some(Duration::from_millis(20)),
        )
        .expect_err("cargo-sweep coordination timeout should propagate");
        assert!(is_cargo_lock_timeout(&error));
        held.unlock()?;
        Ok(())
    }

    #[test]
    fn dry_run_does_not_mutate() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("stale");
        add_worktree(&repo, &worktree, "stale-branch")?;

        let options = CleanupOptions {
            execute: false,
            stale_days: 30,
            generated_days: 7,
            generated_activity_only: false,
            check_in_use: false,
            generated_config: GeneratedDirConfig::default(),
            cargo_lock_timeout: None,
            defer_lock_timeouts: false,
            now: now(),
        };
        let run = cleanup(Some(&repo), options)?;
        let expected_worktree = fs::canonicalize(&worktree)?;

        assert!(worktree.exists());
        assert!(run
            .manifest
            .worktrees
            .iter()
            .any(|d| d.path == expected_worktree && d.action == WorktreeAction::Remove));
        Ok(())
    }

    #[test]
    fn dirty_worktrees_are_preserved() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("dirty");
        add_worktree(&repo, &worktree, "dirty-branch")?;
        fs::write(worktree.join("README.md"), "changed\n")?;
        let expected_worktree = fs::canonicalize(&worktree)?;

        let report = audit(Some(&repo), 7, now())?;
        let decisions = plan_worktree_cleanup(&report.worktrees, 30, now());
        let decision = decisions
            .iter()
            .find(|decision| decision.path == expected_worktree)
            .context("missing dirty worktree decision")?;

        assert_eq!(decision.action, WorktreeAction::Keep);
        assert!(decision.reason.contains("dirty"));
        Ok(())
    }

    #[test]
    fn branch_ref_survives_worktree_removal() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("remove-me");
        add_worktree(&repo, &worktree, "remove-me-branch")?;

        let options = CleanupOptions {
            execute: true,
            stale_days: 30,
            generated_days: 7,
            generated_activity_only: false,
            check_in_use: false,
            generated_config: GeneratedDirConfig::default(),
            cargo_lock_timeout: None,
            defer_lock_timeouts: false,
            now: now(),
        };
        cleanup(Some(&repo), options)?;

        assert!(!worktree.exists());
        let refs = git_output(&repo, ["show-ref", "--heads", "remove-me-branch"])?;
        assert!(refs.contains("refs/heads/remove-me-branch"));
        Ok(())
    }

    #[test]
    fn generated_dirs_are_removed_only_when_untracked() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("generated");
        add_worktree(&repo, &worktree, "generated-branch")?;
        fs::create_dir_all(worktree.join("node_modules/pkg"))?;
        fs::write(
            worktree.join("node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )?;

        fs::create_dir_all(worktree.join("tracked-target"))?;
        fs::write(worktree.join("tracked-target/file.txt"), "tracked\n")?;
        git_output(&worktree, ["add", "tracked-target/file.txt"])?;
        commit_with_date(&worktree, "tracked target", "2025-01-02T00:00:00Z")?;
        fs::create_dir_all(worktree.join("target"))?;
        fs::write(worktree.join("target/cache"), "cache\n")?;

        let options = CleanupOptions {
            execute: true,
            stale_days: 10_000,
            generated_days: 7,
            generated_activity_only: false,
            check_in_use: false,
            generated_config: GeneratedDirConfig::default(),
            cargo_lock_timeout: None,
            defer_lock_timeouts: false,
            now: now(),
        };
        cleanup(Some(&repo), options)?;

        assert!(!worktree.join("node_modules").exists());
        assert!(!worktree.join("target").exists());
        assert!(worktree.join("tracked-target/file.txt").exists());
        Ok(())
    }

    #[test]
    fn current_worktree_generated_dirs_are_preserved_by_default() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        fs::create_dir_all(repo.join("node_modules/pkg"))?;
        fs::write(
            repo.join("node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )?;
        let expected_node_modules = fs::canonicalize(repo.join("node_modules"))?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 3,
                generated_activity_only: false,
                check_in_use: false,
                generated_config: GeneratedDirConfig::default(),
                now: now(),
            },
        )?;

        let node_modules = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_node_modules)
            .context("missing node_modules entry")?;

        assert_eq!(node_modules.action, GeneratedDirAction::Skip);
        assert!(node_modules.reason.contains("worktree"));
        Ok(())
    }

    #[test]
    fn generated_activity_only_allows_current_worktree_generated_cleanup() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        fs::create_dir_all(repo.join("node_modules/pkg"))?;
        fs::write(
            repo.join("node_modules/pkg/index.js"),
            "module.exports = 1\n",
        )?;

        let options = CleanupOptions {
            execute: true,
            stale_days: 10_000,
            generated_days: 3,
            generated_activity_only: true,
            check_in_use: false,
            generated_config: GeneratedDirConfig::default(),
            cargo_lock_timeout: None,
            defer_lock_timeouts: false,
            now: now(),
        };
        cleanup(Some(&repo), options)?;

        assert!(!repo.join("node_modules").exists());
        Ok(())
    }

    #[test]
    fn dist_is_report_only() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("dist-report");
        add_worktree(&repo, &worktree, "dist-report-branch")?;
        fs::create_dir_all(worktree.join("dist"))?;
        fs::write(worktree.join("dist/bundle.js"), "console.log(1)\n")?;
        let expected_dist = fs::canonicalize(worktree.join("dist"))?;

        let report = audit(Some(&repo), 7, now())?;
        let dist = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_dist)
            .context("missing dist entry")?;

        assert_eq!(dist.action, GeneratedDirAction::ReportOnly);
        Ok(())
    }

    #[test]
    fn custom_generated_names_are_supported() -> Result<()> {
        let (_temp, repo) = init_repo()?;
        let worktree = repo.with_file_name("custom-generated");
        add_worktree(&repo, &worktree, "custom-generated-branch")?;
        fs::create_dir_all(worktree.join("coverage"))?;
        fs::write(worktree.join("coverage/index.html"), "coverage\n")?;
        fs::create_dir_all(worktree.join("logs"))?;
        fs::write(worktree.join("logs/run.log"), "log\n")?;
        let expected_coverage = fs::canonicalize(worktree.join("coverage"))?;
        let expected_logs = fs::canonicalize(worktree.join("logs"))?;

        let report = triage(
            Some(&repo),
            TriageOptions {
                stale_days: 10_000,
                generated_days: 7,
                generated_activity_only: false,
                check_in_use: false,
                generated_config: GeneratedDirConfig::from_names(
                    false,
                    vec!["coverage".to_string()],
                    vec!["logs".to_string()],
                    Vec::new(),
                    Vec::new(),
                ),
                now: now(),
            },
        )?;

        let coverage = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_coverage)
            .context("missing coverage entry")?;
        let logs = report
            .generated_dirs
            .iter()
            .find(|dir| dir.path == expected_logs)
            .context("missing logs entry")?;

        assert_eq!(coverage.action, GeneratedDirAction::Delete);
        assert_eq!(logs.action, GeneratedDirAction::ReportOnly);
        Ok(())
    }
}
