use crate::inventory::{inventory, InventoryMetrics, InventoryOptions, InventoryScanError};
use crate::protection::{active_protections, protection_for_path, ProtectionMatch};
use crate::{format_bytes, CleanupMode};
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const CODEX_MANIFEST_VERSION: u64 = 1;

#[derive(Debug, Clone)]
pub struct CodexCollectOptions {
    pub codex_home: Option<PathBuf>,
    pub review_days: u64,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for CodexCollectOptions {
    fn default() -> Self {
        Self {
            codex_home: None,
            review_days: 7,
            max_entries: 500_000,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CodexCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: CodexCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct CodexCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub identity: CodexIdentity,
    pub policy: CodexPolicy,
    pub plan: CodexWorktreePlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexIdentity {
    pub codex_home: PathBuf,
    pub worktrees_root: PathBuf,
    pub state_database: PathBuf,
    pub sqlite_executable: Option<PathBuf>,
    pub sqlite_version: Option<String>,
    pub state_schema_supported: bool,
    pub state_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexPolicy {
    pub review_days: u64,
    pub max_entries: u64,
    pub whole_worktree_removal: &'static str,
    pub task_state: &'static str,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexWorktreePlan {
    pub complete: bool,
    pub worktrees: Vec<CodexWorktreeObservation>,
    pub review_candidates: Vec<PathBuf>,
    pub total_metrics: InventoryMetrics,
    pub review_candidate_metrics: InventoryMetrics,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexWorktreeAction {
    InUse,
    Protected,
    Dirty,
    Recent,
    ReviewArchived,
    ReviewUnmatched,
    ReportOnly,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodexWorktreeObservation {
    pub container: PathBuf,
    pub path: PathBuf,
    pub branch: Option<String>,
    pub detached: bool,
    pub upstream: Option<String>,
    pub upstream_gone: bool,
    pub dirty_entries: Option<u64>,
    pub last_commit_unix: Option<u64>,
    pub last_activity_unix: Option<u64>,
    pub activity_age_days: Option<u64>,
    pub task_state: Option<CodexTaskState>,
    pub process_owners: Vec<CodexProcessOwner>,
    pub protection: Option<ProtectionMatch>,
    pub measurement_complete: bool,
    pub visited_entries: u64,
    pub metrics: InventoryMetrics,
    pub inventory_errors: Vec<InventoryScanError>,
    pub action: CodexWorktreeAction,
    pub reason: String,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodexTaskState {
    pub cwd: PathBuf,
    pub unarchived_threads: u64,
    pub archived_threads: u64,
    pub unarchived_thread_ids: Vec<String>,
    pub archived_thread_ids: Vec<String>,
    pub latest_updated_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CodexProcessOwner {
    pub pid: u32,
    pub cwd_match: bool,
    pub argv_match: bool,
}

#[derive(Debug, Deserialize)]
struct ThreadStateRow {
    id: String,
    cwd: PathBuf,
    archived: u64,
    updated_at: u64,
}

#[derive(Debug)]
struct GitState {
    branch: Option<String>,
    detached: bool,
    upstream: Option<String>,
    upstream_gone: bool,
    dirty_entries: Option<u64>,
    last_commit_unix: Option<u64>,
    errors: Vec<String>,
}

pub fn collect_codex(options: CodexCollectOptions) -> Result<CodexCollectRun> {
    anyhow::ensure!(options.review_days > 0, "review_days must be at least 1");
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    let codex_home = options.codex_home.map_or_else(default_codex_home, Ok)?;
    let codex_home = canonical_real_directory(&codex_home, "Codex home")?;
    let worktrees_root =
        canonical_real_directory(&codex_home.join("worktrees"), "Codex worktrees")?;
    let state_database = codex_home.join("state_5.sqlite");
    let (task_states, sqlite_executable, sqlite_version, state_error) =
        discover_task_states(&state_database, &worktrees_root);
    let identity = CodexIdentity {
        codex_home,
        worktrees_root: worktrees_root.clone(),
        state_database,
        sqlite_executable,
        sqlite_version,
        state_schema_supported: state_error.is_none(),
        state_error: state_error.clone(),
    };

    let discovered = discover_worktree_repositories(&worktrees_root)?;
    let paths = discovered
        .iter()
        .map(|(_, path)| path.clone())
        .collect::<Vec<_>>();
    let inventory = if paths.is_empty() {
        None
    } else {
        Some(inventory(
            &paths,
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: options.max_entries,
                one_filesystem: true,
            },
        )?)
    };
    let mut measurements = inventory
        .as_ref()
        .into_iter()
        .flat_map(|report| &report.roots)
        .map(|root| (root.path.clone(), root))
        .collect::<HashMap<_, _>>();
    let (process_owners, process_errors) = discover_process_owners(&paths);
    let protections = active_protections(options.now)?;
    let now_unix = unix_seconds(options.now);
    let mut worktrees = Vec::with_capacity(discovered.len());
    for (container, path) in discovered {
        let git = inspect_git(&path);
        let task_state = task_states.get(&path).cloned();
        let owners = process_owners.get(&path).cloned().unwrap_or_default();
        let protection = protection_for_path(&path, &protections);
        let directory_activity = fs::metadata(&path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .map(unix_seconds);
        let last_activity_unix = [
            git.last_commit_unix,
            directory_activity,
            task_state
                .as_ref()
                .and_then(|state| state.latest_updated_unix),
        ]
        .into_iter()
        .flatten()
        .max();
        let activity_age_days =
            last_activity_unix.map(|activity| now_unix.saturating_sub(activity) / 86_400);
        let measurement = measurements.remove(&path);
        let metrics = measurement
            .as_ref()
            .map(|root| root.metrics.clone())
            .unwrap_or_default();
        let measurement_complete = measurement.as_ref().is_some_and(|root| root.complete);
        let visited_entries = measurement.as_ref().map_or(0, |root| root.visited_entries);
        let inventory_errors = measurement.as_ref().map_or_else(
            || {
                vec![InventoryScanError {
                    path: path.clone(),
                    message: "bounded inventory did not return an observation for this root"
                        .to_string(),
                }]
            },
            |root| root.errors.clone(),
        );
        let (action, reason) = classify_worktree(
            &git,
            task_state.as_ref(),
            &owners,
            protection.as_ref(),
            activity_age_days,
            options.review_days,
            state_error
                .as_deref()
                .or_else(|| process_errors.first().map(String::as_str)),
        );
        worktrees.push(CodexWorktreeObservation {
            container,
            path,
            branch: git.branch,
            detached: git.detached,
            upstream: git.upstream,
            upstream_gone: git.upstream_gone,
            dirty_entries: git.dirty_entries,
            last_commit_unix: git.last_commit_unix,
            last_activity_unix,
            activity_age_days,
            task_state,
            process_owners: owners,
            protection,
            measurement_complete,
            visited_entries,
            metrics,
            inventory_errors,
            action,
            reason,
            errors: git.errors,
        });
    }
    worktrees.sort_by_key(|worktree| std::cmp::Reverse(worktree.metrics.private_reclaimable_bytes));
    let review_candidates = worktrees
        .iter()
        .filter(|worktree| {
            matches!(
                worktree.action,
                CodexWorktreeAction::ReviewArchived | CodexWorktreeAction::ReviewUnmatched
            )
        })
        .map(|worktree| worktree.path.clone())
        .collect::<Vec<_>>();
    let total_metrics = sum_metrics(worktrees.iter().map(|worktree| &worktree.metrics));
    let review_candidate_metrics = sum_metrics(
        worktrees
            .iter()
            .filter(|worktree| review_candidates.contains(&worktree.path))
            .map(|worktree| &worktree.metrics),
    );
    let mut errors = process_errors;
    if let Some(error) = state_error {
        errors.push(error);
    }
    let complete = errors.is_empty()
        && worktrees.iter().all(|worktree| {
            worktree.errors.is_empty()
                && worktree.inventory_errors.is_empty()
                && worktree.measurement_complete
        });
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let manifest = CodexCollectManifest {
        manifest_version: CODEX_MANIFEST_VERSION,
        collector: "codex-worktrees",
        run_id,
        mode: CleanupMode::DryRun,
        generated_at_unix: now_unix,
        identity,
        policy: CodexPolicy {
            review_days: options.review_days,
            max_entries: options.max_entries,
            whole_worktree_removal: "human_review_only",
            task_state: "codex_state_database_read_only",
            unattended_execution_supported: false,
        },
        plan: CodexWorktreePlan {
            complete,
            worktrees,
            review_candidates,
            total_metrics,
            review_candidate_metrics,
            errors,
        },
    };
    let manifest_path = write_manifest(&manifest)?;
    Ok(CodexCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_codex_collect(run: &CodexCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: codex-worktrees");
    println!("mode: DryRun (whole worktree removal is human-review-only)");
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "task state: {}{}",
        if run.manifest.identity.state_schema_supported {
            "available"
        } else {
            "unavailable"
        },
        run.manifest
            .identity
            .state_error
            .as_deref()
            .map(|error| format!(" — {error}"))
            .unwrap_or_default()
    );
    println!(
        "worktrees: {} observed, {} review candidates, {} private observed",
        plan.worktrees.len(),
        plan.review_candidates.len(),
        format_bytes(plan.total_metrics.private_reclaimable_bytes)
    );
    println!(
        "review candidate private reclaim: {}{}",
        format_bytes(plan.review_candidate_metrics.private_reclaimable_bytes),
        if plan.complete {
            ""
        } else {
            " (lower bound; scan incomplete)"
        }
    );
    for worktree in plan.worktrees.iter().take(30) {
        let task = worktree.task_state.as_ref().map_or_else(
            || "task=unmatched".to_string(),
            |state| {
                format!(
                    "task={} unarchived/{} archived{}",
                    state.unarchived_threads,
                    state.archived_threads,
                    state
                        .unarchived_thread_ids
                        .first()
                        .map(|id| format!(", newest={id}"))
                        .unwrap_or_default()
                )
            },
        );
        println!(
            "  {} private | {:?} | {} | {}",
            format_bytes(worktree.metrics.private_reclaimable_bytes),
            worktree.action,
            task,
            worktree.path.display()
        );
    }
    if plan.worktrees.len() > 30 {
        println!(
            "  ... and {} more (see manifest)",
            plan.worktrees.len() - 30
        );
    }
}

fn classify_worktree(
    git: &GitState,
    task: Option<&CodexTaskState>,
    process_owners: &[CodexProcessOwner],
    protection: Option<&ProtectionMatch>,
    age_days: Option<u64>,
    review_days: u64,
    state_error: Option<&str>,
) -> (CodexWorktreeAction, String) {
    if !git.errors.is_empty() || git.dirty_entries.is_none() {
        return (
            CodexWorktreeAction::Error,
            "Git state is incomplete; retain the worktree".to_string(),
        );
    }
    if let Some(protection) = protection {
        return (
            CodexWorktreeAction::Protected,
            format!(
                "protected by lease {}: {}",
                protection.id, protection.reason
            ),
        );
    }
    if task.is_some_and(|task| task.unarchived_threads > 0) || !process_owners.is_empty() {
        return (
            CodexWorktreeAction::InUse,
            "an unarchived Codex task or live process owns this worktree".to_string(),
        );
    }
    if git.dirty_entries.unwrap_or_default() > 0 {
        return (
            CodexWorktreeAction::Dirty,
            "worktree has tracked or untracked changes".to_string(),
        );
    }
    if age_days.is_none_or(|days| days < review_days) {
        return (
            CodexWorktreeAction::Recent,
            format!("activity is newer than the {review_days}-day review window"),
        );
    }
    if state_error.is_some() {
        return (
            CodexWorktreeAction::ReportOnly,
            "Codex task or process ownership state is unavailable; retain pending owner review"
                .to_string(),
        );
    }
    if let Some(task) = task {
        if task.archived_threads > 0 {
            return (
                CodexWorktreeAction::ReviewArchived,
                "all matching Codex tasks are archived; whole removal requires review".to_string(),
            );
        }
        return (
            CodexWorktreeAction::ReportOnly,
            "Codex task state is inconclusive".to_string(),
        );
    }
    (
        CodexWorktreeAction::ReviewUnmatched,
        if git.upstream_gone {
            "no Codex task matches this clean worktree and its upstream is gone; whole removal requires review"
                .to_string()
        } else {
            "no Codex task matches this clean worktree; whole removal requires review".to_string()
        },
    )
}

fn discover_worktree_repositories(root: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut repositories = Vec::new();
    for entry in read_real_directories(root)? {
        if has_git_marker(&entry)? {
            repositories.push((entry.clone(), entry));
            continue;
        }
        for child in read_real_directories(&entry)? {
            if has_git_marker(&child)? {
                repositories.push((entry.clone(), child));
            }
        }
    }
    repositories.sort_by(|left, right| left.1.cmp(&right.1));
    repositories.dedup_by(|left, right| left.1 == right.1);
    Ok(repositories)
}

fn read_real_directories(root: &Path) -> Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    for entry in fs::read_dir(root).with_context(|| format!("read {}", root.display()))? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            directories.push(entry.path());
        }
    }
    directories.sort();
    Ok(directories)
}

fn has_git_marker(path: &Path) -> Result<bool> {
    let marker = path.join(".git");
    match fs::symlink_metadata(marker) {
        Ok(metadata) => {
            Ok(!metadata.file_type().is_symlink() && (metadata.is_file() || metadata.is_dir()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn inspect_git(path: &Path) -> GitState {
    let mut errors = Vec::new();
    let dirty_entries = match git_output_bytes(path, &["status", "--porcelain=v1", "-z"]) {
        Ok(output) => Some(
            output
                .split(|byte| *byte == 0)
                .filter(|entry| !entry.is_empty())
                .count() as u64,
        ),
        Err(error) => {
            errors.push(error);
            None
        }
    };
    let branch = git_output(path, &["symbolic-ref", "--short", "-q", "HEAD"])
        .ok()
        .filter(|branch| !branch.is_empty());
    let detached = branch.is_none();
    let (upstream, upstream_gone) = branch.as_deref().map_or((None, false), |branch| {
        git_output(
            path,
            &[
                "for-each-ref",
                "--format=%(upstream:short)|%(upstream:track)",
                &format!("refs/heads/{branch}"),
            ],
        )
        .ok()
        .and_then(|line| {
            let (upstream, track) = line.split_once('|')?;
            (!upstream.is_empty()).then(|| (Some(upstream.to_string()), track == "[gone]"))
        })
        .unwrap_or((None, false))
    });
    let last_commit_unix = git_output(path, &["log", "-1", "--format=%ct"])
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    GitState {
        branch,
        detached,
        upstream,
        upstream_gone,
        dirty_entries,
        last_commit_unix,
        errors,
    }
}

fn discover_task_states(
    database: &Path,
    worktrees_root: &Path,
) -> (
    BTreeMap<PathBuf, CodexTaskState>,
    Option<PathBuf>,
    Option<String>,
    Option<String>,
) {
    let Some(sqlite) = find_executable(OsStr::new("sqlite3")) else {
        return (
            BTreeMap::new(),
            None,
            None,
            Some("sqlite3 is not available on PATH".to_string()),
        );
    };
    let sqlite = sqlite.canonicalize().unwrap_or(sqlite);
    let version = Command::new(&sqlite)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string());
    if !database.is_file() {
        return (
            BTreeMap::new(),
            Some(sqlite),
            version,
            Some(format!(
                "Codex state database is missing: {}",
                database.display()
            )),
        );
    }
    let root = worktrees_root.to_string_lossy().replace('\'', "''");
    let query = format!(
        "SELECT id, cwd, archived, updated_at FROM threads \
         WHERE instr(cwd, '{root}/') = 1 ORDER BY cwd, updated_at DESC, id"
    );
    let output = Command::new(&sqlite)
        .args(["-readonly", "-json"])
        .arg(database)
        .arg(query)
        .stdin(Stdio::null())
        .output();
    let output = match output {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            return (
                BTreeMap::new(),
                Some(sqlite),
                version,
                Some(format!(
                    "read Codex task state: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                )),
            );
        }
        Err(error) => {
            return (
                BTreeMap::new(),
                Some(sqlite),
                version,
                Some(format!("launch sqlite3: {error}")),
            );
        }
    };
    let rows = match serde_json::from_slice::<Vec<ThreadStateRow>>(&output.stdout) {
        Ok(rows) => rows,
        Err(error) => {
            return (
                BTreeMap::new(),
                Some(sqlite),
                version,
                Some(format!("parse Codex task state: {error}")),
            );
        }
    };
    let mut states = BTreeMap::<PathBuf, CodexTaskState>::new();
    for row in rows {
        let state = states
            .entry(row.cwd.clone())
            .or_insert_with(|| CodexTaskState {
                cwd: row.cwd,
                unarchived_threads: 0,
                archived_threads: 0,
                unarchived_thread_ids: Vec::new(),
                archived_thread_ids: Vec::new(),
                latest_updated_unix: None,
            });
        state.latest_updated_unix = Some(
            state
                .latest_updated_unix
                .map_or(row.updated_at, |latest| latest.max(row.updated_at)),
        );
        if row.archived == 0 {
            state.unarchived_threads += 1;
            state.unarchived_thread_ids.push(row.id);
        } else {
            state.archived_threads += 1;
            state.archived_thread_ids.push(row.id);
        }
    }
    (states, Some(sqlite), version, None)
}

fn discover_process_owners(
    paths: &[PathBuf],
) -> (BTreeMap<PathBuf, Vec<CodexProcessOwner>>, Vec<String>) {
    let mut owners = paths
        .iter()
        .cloned()
        .map(|path| (path, BTreeMap::<u32, CodexProcessOwner>::new()))
        .collect::<BTreeMap<_, _>>();
    let mut errors = Vec::new();

    match Command::new("lsof")
        .args(["-a", "-d", "cwd", "-Fn"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            let mut pid = None;
            for line in output.stdout.split(|byte| *byte == b'\n') {
                if let Some(raw) = line.strip_prefix(b"p") {
                    pid = std::str::from_utf8(raw)
                        .ok()
                        .and_then(|raw| raw.parse().ok());
                } else if let (Some(pid), Some(raw)) = (pid, line.strip_prefix(b"n")) {
                    if let Ok(cwd) = std::str::from_utf8(raw) {
                        let cwd = Path::new(cwd);
                        for (path, entries) in &mut owners {
                            if cwd.starts_with(path) {
                                entries
                                    .entry(pid)
                                    .and_modify(|owner| owner.cwd_match = true)
                                    .or_insert(CodexProcessOwner {
                                        pid,
                                        cwd_match: true,
                                        argv_match: false,
                                    });
                            }
                        }
                    }
                }
            }
        }
        Ok(output) => errors.push(format!(
            "lsof cwd snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => errors.push(format!("launch lsof cwd snapshot: {error}")),
    }

    match Command::new("ps")
        .args(["-axo", "pid=,command="])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => {
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let mut parts = line.trim_start().splitn(2, char::is_whitespace);
                let Some(pid) = parts.next().and_then(|pid| pid.parse::<u32>().ok()) else {
                    continue;
                };
                let command = parts.next().unwrap_or_default();
                for (path, entries) in &mut owners {
                    if command.contains(path.to_string_lossy().as_ref()) {
                        entries
                            .entry(pid)
                            .and_modify(|owner| owner.argv_match = true)
                            .or_insert(CodexProcessOwner {
                                pid,
                                cwd_match: false,
                                argv_match: true,
                            });
                    }
                }
            }
        }
        Ok(output) => errors.push(format!(
            "ps argv snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) => errors.push(format!("launch ps argv snapshot: {error}")),
    }

    (
        owners
            .into_iter()
            .map(|(path, entries)| (path, entries.into_values().collect()))
            .collect(),
        errors,
    )
}

fn sum_metrics<'a>(metrics: impl Iterator<Item = &'a InventoryMetrics>) -> InventoryMetrics {
    let mut total = InventoryMetrics {
        private_reclaimable_complete: true,
        ..InventoryMetrics::default()
    };
    for metrics in metrics {
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
    total
}

fn git_output(path: &Path, args: &[&str]) -> std::result::Result<String, String> {
    let output = git_command(path, args)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_output_bytes(path: &Path, args: &[&str]) -> std::result::Result<Vec<u8>, String> {
    Ok(git_command(path, args)?.stdout)
}

fn git_command(path: &Path, args: &[&str]) -> std::result::Result<Output, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("launch git in {}: {error}", path.display()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "git {} failed in {}: {}",
            args.join(" "),
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn canonical_real_directory(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("read {label} metadata for {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "{label} is not a directory: {}",
        path.display()
    );
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "{label} is a symlink: {}",
        path.display()
    );
    path.canonicalize()
        .with_context(|| format!("canonicalize {label} {}", path.display()))
}

fn default_codex_home() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CODEX_HOME").filter(|path| !path.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    Ok(
        PathBuf::from(std::env::var_os("HOME").context("neither CODEX_HOME nor HOME is set")?)
            .join(".codex"),
    )
}

fn find_executable(name: &OsStr) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
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

fn write_manifest(manifest: &CodexCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}-codex-worktrees-dry-run.json", manifest.run_id));
    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("open atomic Codex worktree manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Codex worktree manifest {}", path.display()))?;
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
    use tempfile::TempDir;

    fn clean_git() -> GitState {
        GitState {
            branch: Some("wycats/test".to_string()),
            detached: false,
            upstream: Some("origin/wycats/test".to_string()),
            upstream_gone: false,
            dirty_entries: Some(0),
            last_commit_unix: Some(1),
            errors: Vec::new(),
        }
    }

    #[test]
    fn unarchived_tasks_outrank_cleanliness_and_age() {
        let task = CodexTaskState {
            cwd: PathBuf::from("/tmp/worktree"),
            unarchived_threads: 1,
            archived_threads: 0,
            unarchived_thread_ids: vec!["thread-open".to_string()],
            archived_thread_ids: Vec::new(),
            latest_updated_unix: Some(1),
        };
        let (action, _) =
            classify_worktree(&clean_git(), Some(&task), &[], None, Some(30), 7, None);
        assert_eq!(action, CodexWorktreeAction::InUse);
    }

    #[test]
    fn archived_and_unmatched_clean_worktrees_remain_review_only() {
        let archived = CodexTaskState {
            cwd: PathBuf::from("/tmp/worktree"),
            unarchived_threads: 0,
            archived_threads: 1,
            unarchived_thread_ids: Vec::new(),
            archived_thread_ids: vec!["thread-archived".to_string()],
            latest_updated_unix: Some(1),
        };
        assert_eq!(
            classify_worktree(&clean_git(), Some(&archived), &[], None, Some(30), 7, None,).0,
            CodexWorktreeAction::ReviewArchived
        );
        assert_eq!(
            classify_worktree(&clean_git(), None, &[], None, Some(30), 7, None).0,
            CodexWorktreeAction::ReviewUnmatched
        );
    }

    #[test]
    fn unavailable_task_state_fails_closed() {
        assert_eq!(
            classify_worktree(
                &clean_git(),
                None,
                &[],
                None,
                Some(30),
                7,
                Some("schema mismatch"),
            )
            .0,
            CodexWorktreeAction::ReportOnly
        );
    }

    #[test]
    fn discovery_is_shallow_and_does_not_follow_symlinks() -> Result<()> {
        let temp = TempDir::new()?;
        let root = temp.path().join("worktrees");
        let container = root.join("abcd");
        let repo = container.join("repo");
        fs::create_dir_all(repo.join(".git"))?;
        fs::create_dir_all(container.join("not-a-repo/nested/.git"))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&repo, root.join("linked"))?;

        let found = discover_worktree_repositories(&root)?;

        assert_eq!(found, vec![(container, repo)]);
        Ok(())
    }
}
