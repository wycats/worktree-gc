use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::protection::{
    active_protections, protection_for_path, with_protection_guard_for_paths,
    ProtectionGuardOutcome, ProtectionMatch,
};
use crate::{format_bytes, CleanupMode};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const LIMA_MANIFEST_VERSION: u64 = 1;
const CANDIDATE_MEASUREMENT_MAX_ENTRIES: u64 = 10_000;
const SUPPORTED_LIMA_VERSION: &str = "2.1.0";

#[derive(Debug, Clone)]
pub struct LimaCollectOptions {
    pub execute: bool,
    pub now: SystemTime,
}

impl Default for LimaCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LimaCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: LimaCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct LimaCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub lima: LimaIdentity,
    pub policy: LimaPolicy,
    pub plan: LimaPrunePlan,
    pub outcome: Option<LimaPruneOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimaIdentity {
    pub executable: PathBuf,
    pub canonical_executable: PathBuf,
    pub version: String,
    pub lima_home: PathBuf,
    pub cache_path: PathBuf,
    pub instances: Vec<LimaInstance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimaInstance {
    pub name: String,
    pub status: String,
    pub directory: PathBuf,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimaPolicy {
    pub reviewed_lima_version: &'static str,
    pub delegated_command: Vec<String>,
    pub simulation: &'static str,
    pub instance_cleanup: &'static str,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimaPruneAction {
    DelegateDownloadCache,
    NoWork,
    ReportOnly,
    InUse,
    Protected,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimaPrunePlan {
    pub action: LimaPruneAction,
    pub reason: String,
    pub complete: bool,
    pub version_supported: bool,
    pub eligibility_digest: String,
    pub candidates: Vec<LimaDownloadCandidate>,
    pub expected_reclaim: InventoryMetrics,
    pub active_processes: Vec<String>,
    pub running_instances: Vec<String>,
    pub errored_instances: Vec<String>,
    pub protections: Vec<ProtectionMatch>,
    pub host_available_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimaDownloadCandidate {
    pub cache_key: String,
    pub path: PathBuf,
    pub url: String,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Serialize)]
pub struct LimaPruneOutcome {
    pub command_succeeded: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub host_available_bytes_before: u64,
    pub host_available_bytes_after: u64,
    pub realized_host_reclaim_bytes: u64,
    pub verification_complete: bool,
    pub remaining_candidates: Vec<PathBuf>,
}

#[derive(Debug)]
struct LimaContext {
    identity: LimaIdentity,
}

#[derive(Debug, Deserialize)]
struct LimaListInstance {
    name: String,
    status: String,
    dir: PathBuf,
    #[serde(default)]
    errors: Option<Vec<String>>,
}

pub fn collect_lima(options: LimaCollectOptions) -> Result<LimaCollectRun> {
    let context = discover_lima()?;
    let mode = if options.execute {
        CleanupMode::Execute
    } else {
        CleanupMode::DryRun
    };
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let mut manifest = LimaCollectManifest {
        manifest_version: LIMA_MANIFEST_VERSION,
        collector: "lima",
        run_id,
        mode,
        generated_at_unix: unix_seconds(options.now),
        lima: context.identity.clone(),
        policy: LimaPolicy {
            reviewed_lima_version: SUPPORTED_LIMA_VERSION,
            delegated_command: vec!["prune".into(), "--keep-referred".into()],
            simulation: "apfs_clone_then_lima_prune_keep_referred",
            instance_cleanup: "report_only",
            unattended_execution_supported: false,
        },
        plan: plan_lima(&context.identity, options.now)?,
        outcome: None,
    };
    let manifest_path = write_lima_manifest(&manifest)?;
    if options.execute {
        let execution = execute_lima_plan(&context, &mut manifest, options.now);
        write_lima_manifest_at(&manifest_path, &manifest)?;
        execution.with_context(|| {
            format!(
                "Lima collector execution failed; inspect manifest {}",
                manifest_path.display()
            )
        })?;
    }
    Ok(LimaCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_lima_collect(run: &LimaCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: lima");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "lima: {} at {}",
        run.manifest.lima.version,
        run.manifest.lima.lima_home.display()
    );
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!("simulation: APFS clone + Lima prune --keep-referred; execution is manual only");
    println!(
        "download cache: {} candidates, {} private | {} allocated",
        plan.candidates.len(),
        format_bytes(plan.expected_reclaim.private_reclaimable_bytes),
        format_bytes(plan.expected_reclaim.allocated_bytes)
    );
    for candidate in &plan.candidates {
        println!(
            "  {} private | {} allocated | {}",
            format_bytes(candidate.metrics.private_reclaimable_bytes),
            format_bytes(candidate.metrics.allocated_bytes),
            candidate.path.display()
        );
    }
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "realized host reclaim: {}",
            format_bytes(outcome.realized_host_reclaim_bytes)
        );
    }
}

fn discover_lima() -> Result<LimaContext> {
    let executable =
        find_executable(OsStr::new("limactl")).context("limactl was not found on PATH")?;
    let canonical_executable = executable
        .canonicalize()
        .with_context(|| format!("resolve limactl executable {}", executable.display()))?;
    let version = command_stdout(&executable, &["--version"])?;
    let lima_home = PathBuf::from(command_stdout(&executable, &["info", "--yq", ".limaHome"])?);
    let lima_home = lima_home
        .canonicalize()
        .with_context(|| format!("resolve Lima home {}", lima_home.display()))?;
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required for Lima")?);
    let cache_path = home.join("Library/Caches/lima");
    let cache_path = cache_path
        .canonicalize()
        .with_context(|| format!("resolve Lima cache {}", cache_path.display()))?;
    let output = command_output(&executable, &["list", "--all-fields", "--format", "json"])?;
    anyhow::ensure!(
        output.status.success(),
        "{} list failed: {}",
        executable.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stream = serde_json::Deserializer::from_slice(&output.stdout).into_iter();
    let mut instances = stream
        .map(|instance| {
            let instance: LimaListInstance = instance.context("parse Lima instance")?;
            Ok(LimaInstance {
                name: instance.name,
                status: instance.status,
                directory: instance.dir,
                errors: instance.errors.unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    instances.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(LimaContext {
        identity: LimaIdentity {
            executable,
            canonical_executable,
            version,
            lima_home,
            cache_path,
            instances,
        },
    })
}

fn plan_lima(identity: &LimaIdentity, now: SystemTime) -> Result<LimaPrunePlan> {
    let mut plan = plan_lima_without_protections(identity)?;
    let protections = active_protections(now)?;
    plan.protections = plan
        .candidates
        .iter()
        .filter_map(|candidate| protection_for_path(&candidate.path, &protections))
        .collect();
    plan.protections
        .sort_by(|left, right| left.id.cmp(&right.id));
    plan.protections.dedup_by(|left, right| left.id == right.id);
    classify_lima_plan(&mut plan);
    Ok(plan)
}

fn plan_lima_without_protections(identity: &LimaIdentity) -> Result<LimaPrunePlan> {
    let active_processes = active_lima_processes()?;
    let running_instances = identity
        .instances
        .iter()
        .filter(|instance| !instance.status.eq_ignore_ascii_case("stopped"))
        .map(|instance| format!("{} ({})", instance.name, instance.status))
        .collect::<Vec<_>>();
    let errored_instances = identity
        .instances
        .iter()
        .filter(|instance| !instance.errors.is_empty())
        .map(|instance| format!("{}: {}", instance.name, instance.errors.join("; ")))
        .collect::<Vec<_>>();
    let (candidate_keys, simulation_complete) = simulate_prune(identity)?;
    let mut candidates = candidate_keys
        .into_iter()
        .map(|cache_key| candidate(identity, cache_key))
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let measurement_complete = candidates
        .iter()
        .all(|candidate| candidate.metrics.private_reclaimable_complete);
    let expected_reclaim = candidates.iter().fold(
        InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        },
        |mut total, candidate| {
            add_metrics(&mut total, &candidate.metrics);
            total
        },
    );
    let mut plan = LimaPrunePlan {
        action: LimaPruneAction::ReportOnly,
        reason: String::new(),
        complete: simulation_complete && measurement_complete,
        version_supported: installed_version(&identity.version) == Some(SUPPORTED_LIMA_VERSION),
        eligibility_digest: candidate_digest(&candidates),
        candidates,
        expected_reclaim,
        active_processes,
        running_instances,
        errored_instances,
        protections: Vec::new(),
        host_available_bytes: fs4::available_space(&identity.cache_path)?,
    };
    classify_lima_plan(&mut plan);
    Ok(plan)
}

fn classify_lima_plan(plan: &mut LimaPrunePlan) {
    let (action, reason) = if !plan.version_supported {
        (
            LimaPruneAction::ReportOnly,
            format!(
                "collector semantics were reviewed for Lima {SUPPORTED_LIMA_VERSION}; installed version differs"
            ),
        )
    } else if !cfg!(target_os = "macos") {
        (
            LimaPruneAction::UnsupportedPlatform,
            "safe owner-tool simulation currently requires APFS clonefile support".to_string(),
        )
    } else if !plan.complete {
        (
            LimaPruneAction::ReportOnly,
            "the clone rehearsal or candidate measurement was incomplete".to_string(),
        )
    } else if !plan.protections.is_empty() {
        (
            LimaPruneAction::Protected,
            "one or more exact Lima cache candidates has an active lease".to_string(),
        )
    } else if !plan.errored_instances.is_empty() {
        (
            LimaPruneAction::ReportOnly,
            "Lima reported instance inspection errors and skips their references during prune"
                .to_string(),
        )
    } else if !plan.active_processes.is_empty() || !plan.running_instances.is_empty() {
        (
            LimaPruneAction::InUse,
            "a Lima process or non-stopped instance is active".to_string(),
        )
    } else if plan.candidates.is_empty() {
        (
            LimaPruneAction::NoWork,
            "Lima retained every download cache entry in the clone rehearsal".to_string(),
        )
    } else {
        (
            LimaPruneAction::DelegateDownloadCache,
            "Lima removed these exact entries from the isolated clone rehearsal".to_string(),
        )
    };
    plan.action = action;
    plan.reason = reason;
}

fn installed_version(output: &str) -> Option<&str> {
    output.split_whitespace().find(|part| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
    })
}

fn candidate(identity: &LimaIdentity, cache_key: String) -> Result<LimaDownloadCandidate> {
    anyhow::ensure!(
        valid_cache_key(&cache_key),
        "invalid Lima cache key {cache_key:?}"
    );
    let path = identity
        .cache_path
        .join("download/by-url-sha256")
        .join(&cache_key);
    let mut url = String::new();
    let url_path = path.join("url");
    let url_metadata = fs::symlink_metadata(&url_path)
        .with_context(|| format!("inspect Lima cache URL for {cache_key}"))?;
    anyhow::ensure!(
        url_metadata.file_type().is_file() && url_metadata.len() <= 4096,
        "Lima cache URL metadata is not a small regular file for {cache_key}"
    );
    File::open(&url_path)
        .with_context(|| format!("open Lima cache URL for {cache_key}"))?
        .read_to_string(&mut url)?;
    let report = inventory(
        std::slice::from_ref(&path),
        InventoryOptions {
            display_depth: 0,
            top: 1,
            max_entries: CANDIDATE_MEASUREMENT_MAX_ENTRIES,
            one_filesystem: true,
        },
    )?;
    let root = report
        .roots
        .into_iter()
        .next()
        .context("missing Lima inventory root")?;
    anyhow::ensure!(
        root.complete,
        "Lima cache measurement exceeded its entry budget"
    );
    Ok(LimaDownloadCandidate {
        cache_key,
        path,
        url: url.trim().to_string(),
        metrics: root.metrics,
    })
}

fn simulate_prune(identity: &LimaIdentity) -> Result<(Vec<String>, bool)> {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = identity;
        return Ok((Vec::new(), false));
    }
    #[cfg(target_os = "macos")]
    {
        simulate_prune_macos(identity)
    }
}

#[cfg(target_os = "macos")]
fn simulate_prune_macos(identity: &LimaIdentity) -> Result<(Vec<String>, bool)> {
    let parent = identity
        .cache_path
        .parent()
        .context("Lima cache has no parent")?;
    let temporary = parent.join(format!(
        ".worktree-gc-lima-plan.{}.{}",
        std::process::id(),
        unix_nanos(SystemTime::now())
    ));
    fs::create_dir(&temporary)
        .with_context(|| format!("create Lima clone rehearsal {}", temporary.display()))?;
    let result = simulate_prune_in(identity, &temporary);
    let cleanup = fs::remove_dir_all(&temporary)
        .with_context(|| format!("remove Lima clone rehearsal {}", temporary.display()));
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => {
            Err(primary.context(format!("cleanup also failed: {cleanup:#}")))
        }
    }
}

#[cfg(target_os = "macos")]
fn simulate_prune_in(identity: &LimaIdentity, temporary: &Path) -> Result<(Vec<String>, bool)> {
    let home = temporary.join("home");
    let cloned_cache_parent = home.join("Library/Caches");
    let cloned_lima_home = home.join(".lima");
    fs::create_dir_all(&cloned_cache_parent)?;
    fs::create_dir_all(&cloned_lima_home)?;
    let output = Command::new("/bin/cp")
        .args([
            OsStr::new("-cR"),
            identity.cache_path.as_os_str(),
            cloned_cache_parent.as_os_str(),
        ])
        .stdin(Stdio::null())
        .output()
        .context("clone Lima download cache with APFS clonefile")?;
    anyhow::ensure!(
        output.status.success(),
        "APFS clone of Lima cache failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    copy_instance_metadata(identity, &cloned_lima_home)?;
    let cloned_cache = cloned_cache_parent.join("lima");
    let before = cache_keys(&cloned_cache)?;
    let real_before = cache_keys(&identity.cache_path)?;
    anyhow::ensure!(
        before == real_before,
        "cloned Lima cache did not match the real cache"
    );
    let output = Command::new(&identity.executable)
        .args(["prune", "--keep-referred"])
        .env("HOME", &home)
        .env("LIMA_HOME", &cloned_lima_home)
        .stdin(Stdio::null())
        .output()
        .context("run Lima prune against APFS clone rehearsal")?;
    anyhow::ensure!(
        output.status.success(),
        "Lima clone rehearsal failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let after = cache_keys(&cloned_cache)?;
    let real_after = cache_keys(&identity.cache_path)?;
    anyhow::ensure!(
        real_after == real_before,
        "real Lima cache changed during clone rehearsal"
    );
    Ok((before.difference(&after).cloned().collect(), true))
}

#[cfg(target_os = "macos")]
fn copy_instance_metadata(identity: &LimaIdentity, cloned_lima_home: &Path) -> Result<()> {
    for directory in identity
        .instances
        .iter()
        .map(|instance| &instance.directory)
        .chain(std::iter::once(&identity.lima_home.join("_config")))
    {
        let target = cloned_lima_home.join(
            directory
                .file_name()
                .context("Lima metadata directory has no name")?,
        );
        fs::create_dir_all(&target)?;
        for entry in fs::read_dir(directory)
            .with_context(|| format!("read Lima metadata directory {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }
            let metadata = entry.metadata()?;
            let name = entry.file_name();
            let name_lossy = name.to_string_lossy();
            if metadata.len() <= 1024 * 1024 && !name_lossy.ends_with(".log") {
                fs::copy(entry.path(), target.join(name))?;
            }
        }
    }
    let templates = identity.lima_home.join("_templates");
    if templates.is_dir() {
        copy_small_metadata_tree(&templates, &cloned_lima_home.join("_templates"))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_small_metadata_tree(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("read Lima template directory {}", source.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            copy_small_metadata_tree(&entry.path(), &destination)?;
        } else if file_type.is_file() {
            let metadata = entry.metadata()?;
            anyhow::ensure!(
                metadata.len() <= 1024 * 1024,
                "Lima user template {} exceeds the clone rehearsal metadata bound",
                entry.path().display()
            );
            fs::copy(entry.path(), destination)?;
        } else {
            bail!(
                "Lima user template {} is not a regular file or directory",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn cache_keys(cache_path: &Path) -> Result<BTreeSet<String>> {
    let root = cache_path.join("download/by-url-sha256");
    match fs::read_dir(&root) {
        Ok(entries) => entries
            .map(|entry| {
                let entry = entry?;
                let file_type = entry.file_type()?;
                anyhow::ensure!(
                    file_type.is_dir(),
                    "unexpected Lima cache entry {}",
                    entry.path().display()
                );
                let key = entry.file_name().to_string_lossy().into_owned();
                anyhow::ensure!(valid_cache_key(&key), "invalid Lima cache key {key:?}");
                Ok(key)
            })
            .collect(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(error) => Err(error).with_context(|| format!("read Lima cache {}", root.display())),
    }
}

fn valid_cache_key(key: &str) -> bool {
    key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit())
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

fn candidate_digest(candidates: &[LimaDownloadCandidate]) -> String {
    let mut digest = Sha256::new();
    for candidate in candidates {
        digest.update(candidate.cache_key.as_bytes());
        digest.update([0]);
        digest.update(candidate.url.as_bytes());
        digest.update([0]);
        digest.update(candidate.metrics.private_reclaimable_bytes.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn execute_lima_plan(
    context: &LimaContext,
    manifest: &mut LimaCollectManifest,
    now: SystemTime,
) -> Result<()> {
    anyhow::ensure!(
        manifest.plan.action == LimaPruneAction::DelegateDownloadCache,
        "Lima prune is not executable: {}",
        manifest.plan.reason
    );
    let lock = acquire_collector_lock()?;
    let candidate_paths = manifest
        .plan
        .candidates
        .iter()
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    let outcome = with_protection_guard_for_paths(&candidate_paths, now, || {
        execute_lima_plan_guarded(context, manifest)
    })?;
    drop(lock);
    match outcome {
        ProtectionGuardOutcome::Protected(protection) => bail!(
            "Lima cache became protected by lease {} ({})",
            protection.id,
            protection.reason
        ),
        ProtectionGuardOutcome::Executed(outcome) => manifest.outcome = Some(outcome?),
    }
    let outcome = manifest
        .outcome
        .as_ref()
        .context("missing Lima prune outcome")?;
    anyhow::ensure!(
        outcome.command_succeeded
            && outcome.verification_complete
            && outcome.remaining_candidates.is_empty(),
        "Lima prune completed without proving every candidate absent"
    );
    Ok(())
}

fn execute_lima_plan_guarded(
    context: &LimaContext,
    manifest: &LimaCollectManifest,
) -> Result<LimaPruneOutcome> {
    let refreshed = discover_lima()?.identity;
    anyhow::ensure!(
        refreshed == context.identity,
        "Lima identity changed after planning"
    );
    let plan = plan_lima_without_protections(&refreshed)?;
    anyhow::ensure!(
        plan.action == LimaPruneAction::DelegateDownloadCache
            && plan.eligibility_digest == manifest.plan.eligibility_digest,
        "Lima eligibility changed after planning; rerun without --execute"
    );
    let before = fs4::available_space(&refreshed.cache_path)?;
    let output = command_output(&refreshed.executable, &["prune", "--keep-referred"])?;
    let after = fs4::available_space(&refreshed.cache_path)?;
    let remaining_candidates = manifest
        .plan
        .candidates
        .iter()
        .filter(|candidate| candidate.path.exists())
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();
    Ok(LimaPruneOutcome {
        command_succeeded: output.status.success(),
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        host_available_bytes_before: before,
        host_available_bytes_after: after,
        realized_host_reclaim_bytes: after.saturating_sub(before),
        verification_complete: true,
        remaining_candidates,
    })
}

fn active_lima_processes() -> Result<Vec<String>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .stdin(Stdio::null())
        .output()
        .context("list processes while planning Lima prune")?;
    anyhow::ensure!(
        output.status.success(),
        "ps failed while planning Lima prune"
    );
    let mut matches = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            let command = line
                .trim_start()
                .split_once(' ')
                .map(|(_, command)| command)
                .unwrap_or("");
            is_lima_command(command)
        })
        .take(50)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    matches.sort();
    Ok(matches)
}

fn is_lima_command(command: &str) -> bool {
    let mut words = command.split_whitespace();
    let executable = words.next().map(command_basename).unwrap_or("");
    matches!(
        executable,
        "limactl"
            | "lima"
            | "lima-guestagent"
            | "lima-hostagent"
            | "qemu-system-aarch64"
            | "qemu-system-x86_64"
    )
}

fn command_basename(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(word)
}

fn command_stdout(executable: &Path, args: &[&str]) -> Result<String> {
    let output = command_output(executable, args)?;
    anyhow::ensure!(
        output.status.success(),
        "{} {} failed: {}",
        executable.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_output(executable: &Path, args: &[&str]) -> Result<Output> {
    Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {} {}", executable.display(), args.join(" ")))
}

fn find_executable(name: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?).find_map(|directory| {
        let candidate = directory.join(name);
        candidate.is_file().then_some(candidate)
    })
}

fn acquire_collector_lock() -> Result<File> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("lima.lock"))?;
    lock.lock().context("lock Lima collector")?;
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

fn write_lima_manifest(manifest: &LimaCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!("{}-lima-{mode}.json", manifest.run_id));
    write_lima_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_lima_manifest_at(path: &Path, manifest: &LimaCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic Lima manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Lima manifest {}", path.display()))
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

    fn metrics(private: u64) -> InventoryMetrics {
        InventoryMetrics {
            logical_bytes: private,
            allocated_bytes: private,
            private_reclaimable_bytes: private,
            private_reclaimable_complete: true,
            files: 1,
            directories: 1,
            hardlink_duplicates: 0,
            errors: 0,
        }
    }

    fn plan() -> LimaPrunePlan {
        LimaPrunePlan {
            action: LimaPruneAction::ReportOnly,
            reason: String::new(),
            complete: true,
            version_supported: true,
            eligibility_digest: String::new(),
            candidates: vec![LimaDownloadCandidate {
                cache_key: "a".repeat(64),
                path: "/tmp/lima/cache/a".into(),
                url: "https://example.com/a".into(),
                metrics: metrics(10),
            }],
            expected_reclaim: metrics(10),
            active_processes: Vec::new(),
            running_instances: Vec::new(),
            errored_instances: Vec::new(),
            protections: Vec::new(),
            host_available_bytes: 100,
        }
    }

    #[test]
    fn candidate_digest_covers_owner_identity_and_private_reclaim() {
        let plan = plan();
        let first = candidate_digest(&plan.candidates);
        let mut changed = plan.candidates;
        changed[0].metrics.private_reclaimable_bytes += 1;
        assert_ne!(first, candidate_digest(&changed));
    }

    #[test]
    fn classifier_blocks_active_instances() {
        let mut plan = plan();
        plan.running_instances.push("default (Running)".into());
        classify_lima_plan(&mut plan);
        assert_eq!(plan.action, LimaPruneAction::InUse);
    }

    #[test]
    fn classifier_fails_closed_for_errored_instances() {
        let mut plan = plan();
        plan.errored_instances.push("default: broken config".into());
        classify_lima_plan(&mut plan);
        assert_eq!(plan.action, LimaPruneAction::ReportOnly);
    }

    #[test]
    fn process_matching_is_narrow() {
        assert!(is_lima_command("/opt/homebrew/bin/limactl start default"));
        assert!(is_lima_command(
            "/opt/homebrew/bin/lima-hostagent --pidfile x"
        ));
        assert!(!is_lima_command("rg lima src"));
        assert!(!is_lima_command("worktree-gc collect lima"));
    }

    #[test]
    fn cache_keys_require_sha256_names() {
        assert!(valid_cache_key(&"a".repeat(64)));
        assert!(!valid_cache_key("not-a-key"));
    }

    #[test]
    fn reviewed_version_is_extracted_from_lima_output() {
        assert_eq!(installed_version("limactl version 2.1.0"), Some("2.1.0"));
        assert_eq!(installed_version("unexpected"), None);
    }
}
