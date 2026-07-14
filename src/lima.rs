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
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(target_os = "macos")]
use std::os::unix::fs::DirBuilderExt;

const LIMA_MANIFEST_VERSION: u64 = 4;
const CACHE_MEASUREMENT_MAX_ENTRIES: u64 = 100_000;
const INSTANCE_MEASUREMENT_MAX_ENTRIES: u64 = 100_000;
const MAX_CACHE_KEYS: usize = 4_096;
const MAX_METADATA_ENTRIES: u64 = 4_096;
const MAX_METADATA_BYTES: u64 = 64 * 1024 * 1024;
const MAX_METADATA_DEPTH: usize = 32;
const MAX_METADATA_FILE_BYTES: u64 = 1024 * 1024;
const SUPPORTED_LIMA_VERSION: &str = "2.1.0";

#[derive(Debug, Clone)]
pub struct LimaCollectOptions {
    pub execute: bool,
    pub retire: bool,
    pub approved_digest: Option<String>,
    pub now: SystemTime,
}

impl Default for LimaCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            retire: false,
            approved_digest: None,
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
    pub templates_path: Option<String>,
    pub instances: Vec<LimaInstance>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimaInstance {
    pub name: String,
    pub status: String,
    pub directory: PathBuf,
    pub owner_protected: bool,
    pub error_count: u64,
    pub metrics: InventoryMetrics,
    pub measurement_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimaPolicy {
    pub reviewed_lima_version: &'static str,
    pub delegated_commands: Vec<Vec<String>>,
    pub simulation: Option<&'static str>,
    pub instance_cleanup: &'static str,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LimaPruneAction {
    DelegateDownloadCache,
    RetireDomain,
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
    pub retire_domain: bool,
    pub complete: bool,
    pub version_supported: bool,
    pub eligibility_digest: String,
    pub approval_digest: String,
    pub candidates: Vec<LimaDownloadCandidate>,
    pub retired_instances: Vec<String>,
    pub instance_reclaim: InventoryMetrics,
    pub download_cache_present: bool,
    pub download_cache_reclaim: InventoryMetrics,
    pub expected_reclaim: InventoryMetrics,
    pub active_processes: Vec<String>,
    pub running_instances: Vec<String>,
    pub errored_instances: Vec<String>,
    pub owner_protected_instances: Vec<String>,
    pub protections: Vec<ProtectionMatch>,
    pub host_available_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LimaDownloadCandidate {
    pub cache_key: String,
    pub path: PathBuf,
    pub url_sha256: String,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Serialize)]
pub struct LimaPruneOutcome {
    pub command_succeeded: bool,
    pub commands: Vec<LimaCommandOutcome>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub host_available_bytes_before: u64,
    pub host_available_bytes_after: u64,
    pub realized_host_reclaim_bytes: u64,
    pub verification_complete: bool,
    pub remaining_candidates: Vec<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct LimaCommandOutcome {
    pub command: Vec<String>,
    pub succeeded: bool,
    pub exit_code: Option<i32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
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
    protected: bool,
    #[serde(default)]
    errors: Option<Vec<String>>,
}

#[derive(Debug)]
struct CacheKeyInventory {
    keys: BTreeSet<String>,
    complete: bool,
}

#[derive(Debug)]
struct CacheMeasurement {
    candidates: BTreeMap<String, InventoryMetrics>,
    present: bool,
    root_metrics: InventoryMetrics,
    complete: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
struct MetadataCopyBudget {
    entries: u64,
    bytes: u64,
}

#[cfg(target_os = "macos")]
impl MetadataCopyBudget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.entries = self.entries.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        anyhow::ensure!(
            self.entries <= MAX_METADATA_ENTRIES,
            "Lima clone rehearsal metadata exceeds {MAX_METADATA_ENTRIES} entries"
        );
        anyhow::ensure!(
            self.bytes <= MAX_METADATA_BYTES,
            "Lima clone rehearsal metadata exceeds {MAX_METADATA_BYTES} bytes"
        );
        Ok(())
    }

    fn check_depth(depth: usize) -> Result<()> {
        anyhow::ensure!(
            depth <= MAX_METADATA_DEPTH,
            "Lima clone rehearsal metadata exceeds depth {MAX_METADATA_DEPTH}"
        );
        Ok(())
    }
}

pub fn collect_lima(options: LimaCollectOptions) -> Result<LimaCollectRun> {
    anyhow::ensure!(
        options.execute || options.approved_digest.is_none(),
        "--approved-digest is only valid with --execute"
    );
    if options.execute {
        let approved = options
            .approved_digest
            .as_deref()
            .context("Lima execution requires --approved-digest from a fresh dry-run")?;
        anyhow::ensure!(
            valid_sha256_digest(approved),
            "--approved-digest must be a sha256: digest"
        );
    }
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
        policy: lima_policy(options.retire),
        plan: plan_lima(&context.identity, options.retire, options.now)?,
        outcome: None,
    };
    let manifest_path = write_lima_manifest(&manifest)?;
    if let Some(approved) = options.approved_digest.as_deref() {
        anyhow::ensure!(
            approved == manifest.plan.approval_digest,
            "approved Lima plan {} does not match current plan {}; review the fresh execution-attempt manifest {} before trying again",
            approved,
            manifest.plan.approval_digest,
            manifest_path.display()
        );
    }
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
    println!("approval digest: {}", plan.approval_digest);
    if plan.retire_domain {
        println!("owner plan: delete stopped instances, then prune the full Lima download cache");
    } else {
        println!("simulation: APFS clone + Lima prune --keep-referred; execution is manual only");
    }
    for instance in &run.manifest.lima.instances {
        println!(
            "instance {} ({}): {} private{} | {} allocated | {}",
            instance.name,
            instance.status,
            format_bytes(instance.metrics.private_reclaimable_bytes),
            if instance.measurement_complete {
                ""
            } else {
                " (lower bound)"
            },
            format_bytes(instance.metrics.allocated_bytes),
            if plan.retire_domain {
                "retirement candidate"
            } else {
                "advisory only"
            },
        );
    }
    println!(
        "download cache: {} candidates, {} private | {} allocated",
        plan.candidates.len(),
        format_bytes(plan.download_cache_reclaim.private_reclaimable_bytes),
        format_bytes(plan.download_cache_reclaim.allocated_bytes)
    );
    for candidate in &plan.candidates {
        println!(
            "  {} private | {} allocated | {}",
            format_bytes(candidate.metrics.private_reclaimable_bytes),
            format_bytes(candidate.metrics.allocated_bytes),
            candidate.path.display()
        );
    }
    println!(
        "combined owner plan: {} private | {} allocated",
        format_bytes(plan.expected_reclaim.private_reclaimable_bytes),
        format_bytes(plan.expected_reclaim.allocated_bytes)
    );
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "realized host reclaim: {}",
            format_bytes(outcome.realized_host_reclaim_bytes)
        );
    }
}

fn lima_policy(retire: bool) -> LimaPolicy {
    if retire {
        LimaPolicy {
            reviewed_lima_version: SUPPORTED_LIMA_VERSION,
            delegated_commands: vec![
                vec!["delete".into(), "--tty=false".into()],
                vec!["prune".into(), "--tty=false".into()],
            ],
            simulation: None,
            instance_cleanup: "explicit_owner_domain_retirement",
            unattended_execution_supported: false,
        }
    } else {
        LimaPolicy {
            reviewed_lima_version: SUPPORTED_LIMA_VERSION,
            delegated_commands: vec![vec![
                "prune".into(),
                "--keep-referred".into(),
                "--tty=false".into(),
            ]],
            simulation: Some("apfs_clone_then_lima_prune_keep_referred"),
            instance_cleanup: "report_only",
            unattended_execution_supported: false,
        }
    }
}

fn discover_lima() -> Result<LimaContext> {
    let executable =
        find_executable(OsStr::new("limactl")).context("limactl was not found on PATH")?;
    let canonical_executable = executable
        .canonicalize()
        .with_context(|| format!("resolve limactl executable {}", executable.display()))?;
    let version = command_stdout(&canonical_executable, &["--version"])?;
    let lima_home = PathBuf::from(command_stdout(
        &canonical_executable,
        &["info", "--yq", ".limaHome"],
    )?);
    let lima_home = lima_home
        .canonicalize()
        .with_context(|| format!("resolve Lima home {}", lima_home.display()))?;
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME is required for Lima")?);
    let cache_path = resolve_optional_directory(&home.join("Library/Caches/lima"))?;
    let templates_path = std::env::var_os("LIMA_TEMPLATES_PATH")
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("LIMA_TEMPLATES_PATH is not valid UTF-8"))
        })
        .transpose()?;
    let output = command_output(
        &canonical_executable,
        &["list", "--all-fields", "--format", "json"],
    )?;
    anyhow::ensure!(
        output.status.success(),
        "{} list failed: {}",
        canonical_executable.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let stream = serde_json::Deserializer::from_slice(&output.stdout).into_iter();
    let mut instances = stream
        .map(|instance| {
            let instance: LimaListInstance = instance.context("parse Lima instance")?;
            let directory = instance.dir.canonicalize().with_context(|| {
                format!("resolve Lima instance directory {}", instance.dir.display())
            })?;
            anyhow::ensure!(
                directory.starts_with(&lima_home),
                "Lima instance directory {} is outside Lima home {}",
                directory.display(),
                lima_home.display()
            );
            anyhow::ensure!(
                directory.file_name() == Some(OsStr::new(&instance.name)),
                "Lima instance {} resolves to an unexpected directory {}",
                instance.name,
                directory.display()
            );
            Ok(LimaInstance {
                name: instance.name,
                status: instance.status,
                directory,
                owner_protected: instance.protected,
                error_count: instance.errors.map_or(0, |errors| errors.len() as u64),
                metrics: InventoryMetrics::default(),
                measurement_complete: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    instances.sort_by(|left, right| left.name.cmp(&right.name));
    let mut names = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for instance in &instances {
        anyhow::ensure!(
            names.insert(instance.name.clone()),
            "Lima listed duplicate instance name {}",
            instance.name
        );
        anyhow::ensure!(
            directories.insert(instance.directory.clone()),
            "Lima listed duplicate instance directory {}",
            instance.directory.display()
        );
    }
    measure_instances(&mut instances)?;
    Ok(LimaContext {
        identity: LimaIdentity {
            executable,
            canonical_executable,
            version,
            lima_home,
            cache_path,
            templates_path,
            instances,
        },
    })
}

fn resolve_optional_directory(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir(),
                "Lima path {} is not a directory",
                path.display()
            );
            path.canonicalize()
                .with_context(|| format!("resolve Lima directory {}", path.display()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .context("optional Lima directory has no parent")?
                .canonicalize()
                .with_context(|| format!("resolve Lima directory parent for {}", path.display()))?;
            Ok(parent.join(
                path.file_name()
                    .context("optional Lima directory has no name")?,
            ))
        }
        Err(error) => Err(error)
            .with_context(|| format!("inspect optional Lima directory {}", path.display())),
    }
}

fn measure_instances(instances: &mut [LimaInstance]) -> Result<()> {
    if instances.is_empty() {
        return Ok(());
    }
    let roots = instances
        .iter()
        .map(|instance| instance.directory.clone())
        .collect::<Vec<_>>();
    let report = inventory(
        &roots,
        InventoryOptions {
            display_depth: 0,
            top: 1,
            max_entries: INSTANCE_MEASUREMENT_MAX_ENTRIES,
            one_filesystem: true,
        },
    )?;
    let mut measurements = report
        .roots
        .into_iter()
        .map(|root| (root.path.clone(), root))
        .collect::<BTreeMap<_, _>>();
    for instance in instances {
        let root = measurements.remove(&instance.directory).with_context(|| {
            format!(
                "missing Lima instance inventory root {}",
                instance.directory.display()
            )
        })?;
        instance.measurement_complete =
            root.complete && root.metrics.private_reclaimable_complete && root.errors.is_empty();
        instance.metrics = root.metrics;
        instance.metrics.private_reclaimable_complete &= instance.measurement_complete;
    }
    Ok(())
}

fn plan_lima(identity: &LimaIdentity, retire: bool, now: SystemTime) -> Result<LimaPrunePlan> {
    let mut plan = plan_lima_without_protections(identity, retire)?;
    let protections = active_protections(now)?;
    plan.protections = mutation_paths(identity, &plan)
        .iter()
        .filter_map(|path| protection_for_path(path, &protections))
        .collect();
    plan.protections
        .sort_by(|left, right| left.id.cmp(&right.id));
    plan.protections.dedup_by(|left, right| left.id == right.id);
    classify_lima_plan(&mut plan);
    plan.approval_digest = approval_digest(identity, &plan)?;
    Ok(plan)
}

fn plan_lima_without_protections(identity: &LimaIdentity, retire: bool) -> Result<LimaPrunePlan> {
    let version_supported = installed_version(&identity.version) == Some(SUPPORTED_LIMA_VERSION);
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
        .filter(|instance| instance.error_count > 0)
        .map(|instance| {
            format!(
                "{} ({} inspection errors)",
                instance.name, instance.error_count
            )
        })
        .collect::<Vec<_>>();
    let owner_protected_instances = identity
        .instances
        .iter()
        .filter(|instance| instance.owner_protected)
        .map(|instance| instance.name.clone())
        .collect::<Vec<_>>();
    let measurement = measure_download_cache(identity)?;
    let owner_idle =
        active_processes.is_empty() && running_instances.is_empty() && errored_instances.is_empty();
    let (candidate_keys, owner_plan_complete) = if retire {
        (
            measurement.candidates.keys().cloned().collect::<Vec<_>>(),
            measurement.complete,
        )
    } else if version_supported && measurement.complete && owner_idle {
        simulate_prune(identity)?
    } else {
        (Vec::new(), false)
    };
    let mut candidates = candidate_keys
        .into_iter()
        .map(|cache_key| {
            let metrics = measurement
                .candidates
                .get(&cache_key)
                .cloned()
                .with_context(|| format!("missing Lima measurement for cache key {cache_key}"))?;
            candidate(identity, cache_key, metrics)
        })
        .collect::<Result<Vec<_>>>()?;
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    let measurement_complete = measurement.complete
        && candidates
            .iter()
            .all(|candidate| candidate.metrics.private_reclaimable_complete);
    let download_cache_reclaim = if retire {
        measurement.root_metrics.clone()
    } else {
        candidates.iter().fold(
            InventoryMetrics {
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            },
            |mut total, candidate| {
                add_metrics(&mut total, &candidate.metrics);
                total
            },
        )
    };
    let instance_measurement_complete = identity.instances.iter().all(|instance| {
        instance.measurement_complete && instance.metrics.private_reclaimable_complete
    });
    let instance_reclaim = if retire {
        identity.instances.iter().fold(
            InventoryMetrics {
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            },
            |mut total, instance| {
                add_metrics(&mut total, &instance.metrics);
                total
            },
        )
    } else {
        InventoryMetrics::default()
    };
    let mut expected_reclaim = download_cache_reclaim.clone();
    add_metrics(&mut expected_reclaim, &instance_reclaim);
    let mut plan = LimaPrunePlan {
        action: LimaPruneAction::ReportOnly,
        reason: String::new(),
        retire_domain: retire,
        complete: owner_plan_complete
            && measurement_complete
            && (!retire || instance_measurement_complete),
        version_supported,
        eligibility_digest: candidate_digest(&candidates),
        approval_digest: String::new(),
        candidates,
        retired_instances: if retire {
            identity
                .instances
                .iter()
                .map(|instance| instance.name.clone())
                .collect()
        } else {
            Vec::new()
        },
        instance_reclaim,
        download_cache_present: measurement.present,
        download_cache_reclaim,
        expected_reclaim,
        active_processes,
        running_instances,
        errored_instances,
        owner_protected_instances,
        protections: Vec::new(),
        host_available_bytes: available_space_at(&identity.cache_path)?,
    };
    classify_lima_plan(&mut plan);
    plan.approval_digest = approval_digest(identity, &plan)?;
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
    } else if !plan.retire_domain && !cfg!(target_os = "macos") {
        (
            LimaPruneAction::UnsupportedPlatform,
            "safe owner-tool simulation currently requires APFS clonefile support".to_string(),
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
    } else if plan.retire_domain && !plan.owner_protected_instances.is_empty() {
        (
            LimaPruneAction::Protected,
            "one or more instances is protected by Lima itself".to_string(),
        )
    } else if !plan.complete {
        (
            LimaPruneAction::ReportOnly,
            if plan.retire_domain {
                "the instance or download-cache measurement was incomplete".to_string()
            } else {
                "the clone rehearsal or candidate measurement was incomplete".to_string()
            },
        )
    } else if plan.retire_domain
        && plan.retired_instances.is_empty()
        && !plan.download_cache_present
    {
        (
            LimaPruneAction::NoWork,
            "Lima has no instances or download-cache entries to retire".to_string(),
        )
    } else if !plan.protections.is_empty() {
        (
            LimaPruneAction::Protected,
            "one or more exact Lima mutation targets has an active lease".to_string(),
        )
    } else if plan.retire_domain {
        (
            LimaPruneAction::RetireDomain,
            "explicit retirement deletes the stopped instances and full Lima download cache"
                .to_string(),
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

fn mutation_paths(identity: &LimaIdentity, plan: &LimaPrunePlan) -> Vec<PathBuf> {
    if plan.retire_domain {
        identity
            .instances
            .iter()
            .map(|instance| instance.directory.clone())
            .chain(std::iter::once(identity.cache_path.clone()))
            .chain(
                plan.candidates
                    .iter()
                    .map(|candidate| candidate.path.clone()),
            )
            .collect()
    } else {
        plan.candidates
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect()
    }
}

fn installed_version(output: &str) -> Option<&str> {
    output.split_whitespace().find(|part| {
        part.bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
    })
}

fn measure_download_cache(identity: &LimaIdentity) -> Result<CacheMeasurement> {
    let key_root = identity.cache_path.join("download/by-url-sha256");
    match fs::symlink_metadata(&identity.cache_path) {
        Ok(metadata) => anyhow::ensure!(
            metadata.file_type().is_dir(),
            "Lima cache {} is not a directory",
            identity.cache_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CacheMeasurement {
                candidates: BTreeMap::new(),
                present: false,
                root_metrics: InventoryMetrics {
                    private_reclaimable_complete: true,
                    ..InventoryMetrics::default()
                },
                complete: true,
            });
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Lima cache {}", identity.cache_path.display()));
        }
    }
    let report = inventory(
        std::slice::from_ref(&identity.cache_path),
        InventoryOptions {
            display_depth: 3,
            top: MAX_CACHE_KEYS,
            max_entries: CACHE_MEASUREMENT_MAX_ENTRIES,
            one_filesystem: true,
        },
    )?;
    let root = report
        .roots
        .into_iter()
        .next()
        .context("missing Lima cache inventory root")?;
    let mut complete =
        root.complete && root.metrics.private_reclaimable_complete && root.errors.is_empty();
    let mut root_metrics = root.metrics;
    let mut candidates = root
        .entries
        .into_iter()
        .filter(|entry| entry.path.parent() == Some(key_root.as_path()))
        .map(|entry| {
            let key = entry
                .path
                .file_name()
                .and_then(OsStr::to_str)
                .context("Lima cache inventory entry has no UTF-8 key")?
                .to_owned();
            anyhow::ensure!(valid_cache_key(&key), "invalid Lima cache key {key:?}");
            let mut metrics = entry.metrics;
            metrics.private_reclaimable_complete &= complete;
            Ok((key, metrics))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let keys = cache_keys(&identity.cache_path)?;
    complete &=
        keys.complete && keys.keys == candidates.keys().cloned().collect::<BTreeSet<String>>();
    if !complete {
        root_metrics.private_reclaimable_complete = false;
        for metrics in candidates.values_mut() {
            metrics.private_reclaimable_complete = false;
        }
    }
    Ok(CacheMeasurement {
        candidates,
        present: true,
        root_metrics,
        complete,
    })
}

fn candidate(
    identity: &LimaIdentity,
    cache_key: String,
    metrics: InventoryMetrics,
) -> Result<LimaDownloadCandidate> {
    anyhow::ensure!(
        valid_cache_key(&cache_key),
        "invalid Lima cache key {cache_key:?}"
    );
    let path = identity
        .cache_path
        .join("download/by-url-sha256")
        .join(&cache_key);
    let url_path = path.join("url");
    let url = String::from_utf8(read_small_regular_file(&url_path, 4096)?)
        .with_context(|| format!("Lima cache URL is not UTF-8 for {cache_key}"))?;
    let url_sha256 = format!("sha256:{:x}", Sha256::digest(url.trim().as_bytes()));
    Ok(LimaDownloadCandidate {
        cache_key,
        path,
        url_sha256,
        metrics,
    })
}

fn read_small_regular_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect bounded Lima metadata {}", path.display()))?;
    anyhow::ensure!(
        before.file_type().is_file() && before.len() <= maximum_bytes,
        "Lima metadata {} is not a small regular file",
        path.display()
    );
    let file = File::open(path)
        .with_context(|| format!("open bounded Lima metadata {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect opened Lima metadata {}", path.display()))?;
    anyhow::ensure!(
        opened.file_type().is_file() && opened.len() <= maximum_bytes,
        "opened Lima metadata {} is not a small regular file",
        path.display()
    );
    #[cfg(unix)]
    anyhow::ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "Lima metadata {} changed while opening it",
        path.display()
    );
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("read bounded Lima metadata {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() as u64 <= maximum_bytes,
        "Lima metadata {} exceeded its read bound",
        path.display()
    );
    Ok(bytes)
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
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(&temporary)
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
    let real_before = cache_keys(&identity.cache_path)?;
    if !real_before.complete {
        return Ok((Vec::new(), false));
    }
    let home = temporary.join("home");
    let cloned_cache_parent = home.join("Library/Caches");
    let cloned_cache = cloned_cache_parent.join("lima");
    let cloned_lima_home = home.join(".lima");
    fs::create_dir_all(&cloned_cache)?;
    fs::create_dir_all(&cloned_lima_home)?;
    let download = identity.cache_path.join("download");
    match fs::symlink_metadata(&download) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir(),
                "Lima download root {} is not a directory",
                download.display()
            );
            let output = Command::new("/bin/cp")
                .args([
                    OsStr::new("-cR"),
                    download.as_os_str(),
                    cloned_cache.as_os_str(),
                ])
                .stdin(Stdio::null())
                .output()
                .context("clone Lima download cache with APFS clonefile")?;
            if !output.status.success() {
                // Never fall back to an ordinary recursive copy merely to
                // obtain a plan. Unsupported clonefile semantics, permissions,
                // or concurrent cache churn all leave this run report-only.
                return Ok((Vec::new(), false));
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(cloned_cache.join("download/by-url-sha256"))?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Lima download root {}", download.display()));
        }
    }
    copy_instance_metadata(identity, &cloned_lima_home)?;
    let before = cache_keys(&cloned_cache)?;
    anyhow::ensure!(
        before.complete,
        "cloned Lima cache enumeration was incomplete"
    );
    anyhow::ensure!(
        before.keys == real_before.keys,
        "cloned Lima cache did not match the real cache"
    );
    let mut command = Command::new(&identity.canonical_executable);
    command
        .args(["prune", "--keep-referred"])
        .env("HOME", &home)
        .env("LIMA_HOME", &cloned_lima_home)
        .env_remove("LIMA_TEMPLATES_PATH")
        .stdin(Stdio::null());
    if let Some(templates_path) = &identity.templates_path {
        command.env("LIMA_TEMPLATES_PATH", templates_path);
    }
    let output = command
        .output()
        .context("run Lima prune against APFS clone rehearsal")?;
    anyhow::ensure!(
        output.status.success(),
        "Lima clone rehearsal failed with status {:?} ({} stderr bytes)",
        output.status.code(),
        output.stderr.len()
    );
    let after = cache_keys(&cloned_cache)?;
    let real_after = cache_keys(&identity.cache_path)?;
    anyhow::ensure!(
        after.complete && real_after.complete,
        "Lima cache enumeration became incomplete during clone rehearsal"
    );
    anyhow::ensure!(
        real_after.keys == real_before.keys,
        "real Lima cache changed during clone rehearsal"
    );
    Ok((before.keys.difference(&after.keys).cloned().collect(), true))
}

#[cfg(target_os = "macos")]
fn copy_instance_metadata(identity: &LimaIdentity, cloned_lima_home: &Path) -> Result<()> {
    let mut budget = MetadataCopyBudget::default();
    for instance in &identity.instances {
        let source = instance.directory.join("lima.yaml");
        let contents = read_small_regular_file(&source, MAX_METADATA_FILE_BYTES)?;
        budget.charge(contents.len() as u64)?;
        let target = cloned_lima_home.join(
            instance
                .directory
                .file_name()
                .context("Lima instance directory has no name")?,
        );
        fs::create_dir_all(&target)?;
        fs::write(target.join("lima.yaml"), contents)?;
    }
    let templates = identity.lima_home.join("_templates");
    match fs::symlink_metadata(&templates) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.file_type().is_dir(),
                "Lima template root {} is not a directory",
                templates.display()
            );
            copy_small_metadata_tree(
                &templates,
                &cloned_lima_home.join("_templates"),
                0,
                &mut budget,
            )?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect Lima template root {}", templates.display()));
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn copy_small_metadata_tree(
    source: &Path,
    target: &Path,
    depth: usize,
    budget: &mut MetadataCopyBudget,
) -> Result<()> {
    MetadataCopyBudget::check_depth(depth)?;
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)
        .with_context(|| format!("read Lima template directory {}", source.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let destination = target.join(entry.file_name());
        if file_type.is_dir() {
            budget.charge(0)?;
            copy_small_metadata_tree(&entry.path(), &destination, depth + 1, budget)?;
        } else if file_type.is_file() {
            let name = entry.file_name();
            if name.to_string_lossy().starts_with('.')
                || entry.path().extension() != Some(OsStr::new("yaml"))
            {
                continue;
            }
            let contents = read_small_regular_file(&entry.path(), MAX_METADATA_FILE_BYTES)?;
            budget.charge(contents.len() as u64)?;
            fs::write(destination, contents)?;
        } else {
            bail!(
                "Lima user template {} is not a regular file or directory",
                entry.path().display()
            );
        }
    }
    Ok(())
}

fn cache_keys(cache_path: &Path) -> Result<CacheKeyInventory> {
    let root = cache_path.join("download/by-url-sha256");
    match fs::read_dir(&root) {
        Ok(entries) => {
            let mut keys = BTreeSet::new();
            for entry in entries {
                let entry = entry?;
                if keys.len() == MAX_CACHE_KEYS {
                    return Ok(CacheKeyInventory {
                        keys,
                        complete: false,
                    });
                }
                let file_type = entry.file_type()?;
                anyhow::ensure!(
                    file_type.is_dir(),
                    "unexpected Lima cache entry {}",
                    entry.path().display()
                );
                let key = entry.file_name().to_string_lossy().into_owned();
                anyhow::ensure!(valid_cache_key(&key), "invalid Lima cache key {key:?}");
                keys.insert(key);
            }
            Ok(CacheKeyInventory {
                keys,
                complete: true,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(CacheKeyInventory {
            keys: BTreeSet::new(),
            complete: true,
        }),
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
        digest.update(candidate.url_sha256.as_bytes());
        digest.update([0]);
        digest.update(candidate.metrics.private_reclaimable_bytes.to_le_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[derive(Serialize)]
struct LimaApprovalEvidence<'a> {
    format: &'static str,
    identity: &'a LimaIdentity,
    reviewed_lima_version: &'static str,
    delegated_commands: Vec<Vec<String>>,
    retire_domain: bool,
    complete: bool,
    version_supported: bool,
    eligibility_digest: &'a str,
    candidates: &'a [LimaDownloadCandidate],
    retired_instances: &'a [String],
    instance_reclaim: &'a InventoryMetrics,
    download_cache_present: bool,
    download_cache_reclaim: &'a InventoryMetrics,
    expected_reclaim: &'a InventoryMetrics,
    active_processes: &'a [String],
    running_instances: &'a [String],
    errored_instances: &'a [String],
    owner_protected_instances: &'a [String],
    protections: &'a [ProtectionMatch],
}

fn approval_digest(identity: &LimaIdentity, plan: &LimaPrunePlan) -> Result<String> {
    let evidence = LimaApprovalEvidence {
        format: "worktree-gc-lima-approval-v2",
        identity,
        reviewed_lima_version: SUPPORTED_LIMA_VERSION,
        delegated_commands: owner_commands(plan),
        retire_domain: plan.retire_domain,
        complete: plan.complete,
        version_supported: plan.version_supported,
        eligibility_digest: &plan.eligibility_digest,
        candidates: &plan.candidates,
        retired_instances: &plan.retired_instances,
        instance_reclaim: &plan.instance_reclaim,
        download_cache_present: plan.download_cache_present,
        download_cache_reclaim: &plan.download_cache_reclaim,
        expected_reclaim: &plan.expected_reclaim,
        active_processes: &plan.active_processes,
        running_instances: &plan.running_instances,
        errored_instances: &plan.errored_instances,
        owner_protected_instances: &plan.owner_protected_instances,
        protections: &plan.protections,
    };
    let encoded = serde_json::to_vec(&evidence).context("encode Lima approval evidence")?;
    Ok(format!("sha256:{:x}", Sha256::digest(encoded)))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn execute_lima_plan(
    context: &LimaContext,
    manifest: &mut LimaCollectManifest,
    now: SystemTime,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            manifest.plan.action,
            LimaPruneAction::DelegateDownloadCache | LimaPruneAction::RetireDomain
        ),
        "Lima owner plan is not executable: {}",
        manifest.plan.reason
    );
    let lock = acquire_collector_lock()?;
    let candidate_paths = mutation_paths(&context.identity, &manifest.plan);
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
        "Lima owner plan completed without proving every mutation target absent"
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
    let plan = plan_lima_without_protections(&refreshed, manifest.plan.retire_domain)?;
    anyhow::ensure!(
        plan.action == manifest.plan.action
            && plan.approval_digest == manifest.plan.approval_digest
            && plan.eligibility_digest == manifest.plan.eligibility_digest,
        "Lima eligibility changed after planning; rerun without --execute"
    );
    let before = available_space_at(&refreshed.cache_path)?;
    let planned_commands = owner_commands(&manifest.plan);
    let mut commands = Vec::new();
    for arguments in planned_commands {
        let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
        let output = command_output(&refreshed.canonical_executable, &argument_refs)?;
        let outcome = LimaCommandOutcome {
            command: arguments,
            succeeded: output.status.success(),
            exit_code: output.status.code(),
            stdout_bytes: output.stdout.len() as u64,
            stderr_bytes: output.stderr.len() as u64,
        };
        let succeeded = outcome.succeeded;
        commands.push(outcome);
        if !succeeded {
            break;
        }
    }
    let after = available_space_at(&refreshed.cache_path)?;
    let remaining_candidates = existing_paths(
        verification_paths(&refreshed, &manifest.plan)
            .iter()
            .map(PathBuf::as_path),
    )?;
    let command_succeeded = commands.len() == owner_commands(&manifest.plan).len()
        && commands.iter().all(|command| command.succeeded);
    Ok(LimaPruneOutcome {
        command_succeeded,
        stdout_bytes: commands.iter().map(|command| command.stdout_bytes).sum(),
        stderr_bytes: commands.iter().map(|command| command.stderr_bytes).sum(),
        commands,
        host_available_bytes_before: before,
        host_available_bytes_after: after,
        realized_host_reclaim_bytes: after.saturating_sub(before),
        verification_complete: true,
        remaining_candidates,
    })
}

fn owner_commands(plan: &LimaPrunePlan) -> Vec<Vec<String>> {
    if plan.retire_domain {
        let mut commands = plan
            .retired_instances
            .iter()
            .map(|instance| vec!["delete".into(), "--tty=false".into(), instance.clone()])
            .collect::<Vec<_>>();
        commands.push(vec!["prune".into(), "--tty=false".into()]);
        commands
    } else {
        vec![vec![
            "prune".into(),
            "--keep-referred".into(),
            "--tty=false".into(),
        ]]
    }
}

fn verification_paths(identity: &LimaIdentity, plan: &LimaPrunePlan) -> Vec<PathBuf> {
    if plan.retire_domain {
        identity
            .instances
            .iter()
            .map(|instance| instance.directory.clone())
            .chain(std::iter::once(identity.cache_path.clone()))
            .collect()
    } else {
        plan.candidates
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect()
    }
}

fn available_space_at(path: &Path) -> Result<u64> {
    let mut observed = path;
    loop {
        match fs::symlink_metadata(observed) {
            Ok(_) => {
                return fs4::available_space(observed)
                    .with_context(|| format!("observe available space at {}", observed.display()));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect filesystem path {}", observed.display()));
            }
        }
        observed = observed
            .parent()
            .with_context(|| format!("find existing parent for {}", path.display()))?;
    }
}

fn existing_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Vec<PathBuf>> {
    let mut existing = Vec::new();
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => existing.push(path.to_path_buf()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("verify Lima candidate {}", path.display()));
            }
        }
    }
    Ok(existing)
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
        .filter_map(|line| {
            let (pid, command) = line.trim_start().split_once(' ')?;
            let command = command.trim_start();
            is_lima_command(command).then(|| owner_process_summary(pid, command))
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
            retire_domain: false,
            complete: true,
            version_supported: true,
            eligibility_digest: String::new(),
            approval_digest: String::new(),
            candidates: vec![LimaDownloadCandidate {
                cache_key: "a".repeat(64),
                path: "/tmp/lima/cache/a".into(),
                url_sha256: "sha256:fixture".into(),
                metrics: metrics(10),
            }],
            retired_instances: Vec::new(),
            instance_reclaim: InventoryMetrics::default(),
            download_cache_present: true,
            download_cache_reclaim: metrics(10),
            expected_reclaim: metrics(10),
            active_processes: Vec::new(),
            running_instances: Vec::new(),
            errored_instances: Vec::new(),
            owner_protected_instances: Vec::new(),
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
        plan.complete = false;
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
    fn classifier_respects_lima_owner_protection() {
        let mut plan = plan();
        plan.retire_domain = true;
        plan.retired_instances.push("default".into());
        plan.owner_protected_instances.push("default".into());
        classify_lima_plan(&mut plan);
        assert_eq!(plan.action, LimaPruneAction::Protected);
    }

    #[test]
    fn classifier_keeps_incomplete_measurement_report_only() {
        let mut plan = plan();
        plan.complete = false;
        classify_lima_plan(&mut plan);
        assert_eq!(plan.action, LimaPruneAction::ReportOnly);
        assert!(plan.reason.contains("incomplete"));
    }

    #[test]
    fn classifier_requires_explicit_retirement_before_deleting_instances() {
        let mut ordinary = plan();
        ordinary.retired_instances.push("default".into());
        classify_lima_plan(&mut ordinary);
        assert_eq!(ordinary.action, LimaPruneAction::DelegateDownloadCache);

        let mut retirement = ordinary;
        retirement.retire_domain = true;
        classify_lima_plan(&mut retirement);
        assert_eq!(retirement.action, LimaPruneAction::RetireDomain);
    }

    #[test]
    fn retirement_treats_an_owner_cache_root_as_work_without_known_download_keys() {
        let mut retirement = plan();
        retirement.retire_domain = true;
        retirement.retired_instances.clear();
        retirement.candidates.clear();
        retirement.download_cache_present = true;

        classify_lima_plan(&mut retirement);

        assert_eq!(retirement.action, LimaPruneAction::RetireDomain);
    }

    #[test]
    fn retirement_is_empty_only_when_instances_and_the_cache_root_are_absent() {
        let mut retirement = plan();
        retirement.retire_domain = true;
        retirement.retired_instances.clear();
        retirement.candidates.clear();
        retirement.download_cache_present = false;

        classify_lima_plan(&mut retirement);

        assert_eq!(retirement.action, LimaPruneAction::NoWork);
    }

    #[test]
    fn retirement_owner_commands_name_exact_instances_and_drop_all_downloads() {
        let mut plan = plan();
        plan.retire_domain = true;
        plan.retired_instances = vec!["default".into(), "legacy".into()];

        assert_eq!(
            owner_commands(&plan),
            vec![
                vec!["delete", "--tty=false", "default"],
                vec!["delete", "--tty=false", "legacy"],
                vec!["prune", "--tty=false"]
            ]
        );
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
    fn owner_process_summaries_do_not_persist_arguments() {
        assert_eq!(
            owner_process_summary(
                "42",
                "/opt/homebrew/bin/limactl start https://user:secret@example.invalid/template"
            ),
            "42 limactl"
        );
    }

    #[test]
    fn candidate_digest_uses_redacted_url_identity() {
        let mut plan = plan();
        let first = candidate_digest(&plan.candidates);
        plan.candidates[0].url_sha256 = "sha256:changed".into();
        assert_ne!(first, candidate_digest(&plan.candidates));
    }

    #[test]
    fn approval_digest_requires_a_prefixed_full_sha256() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_sha256_digest(&"a".repeat(64)));
        assert!(!valid_sha256_digest("sha256:short"));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "z".repeat(64))));
    }

    #[test]
    fn approval_digest_is_stable_and_binds_identity_and_candidates() -> Result<()> {
        let identity = LimaIdentity {
            executable: "/opt/homebrew/bin/limactl".into(),
            canonical_executable: "/opt/homebrew/Cellar/lima/2.1.0/bin/limactl".into(),
            version: "limactl version 2.1.0".into(),
            lima_home: "/Users/example/.lima".into(),
            cache_path: "/Users/example/Library/Caches/lima".into(),
            templates_path: None,
            instances: vec![LimaInstance {
                name: "default".into(),
                status: "Stopped".into(),
                directory: "/Users/example/.lima/default".into(),
                owner_protected: false,
                error_count: 0,
                metrics: metrics(20),
                measurement_complete: true,
            }],
        };
        let plan = plan();
        let first = approval_digest(&identity, &plan)?;
        assert_eq!(first, approval_digest(&identity, &plan)?);
        assert!(valid_sha256_digest(&first));

        let mut changed_identity = identity.clone();
        changed_identity.version = "limactl version 2.1.1".into();
        assert_ne!(first, approval_digest(&changed_identity, &plan)?);

        let mut changed_templates = identity.clone();
        changed_templates.templates_path = Some("/Users/example/custom-templates".into());
        assert_ne!(first, approval_digest(&changed_templates, &plan)?);

        let mut retirement = plan.clone();
        retirement.retire_domain = true;
        retirement.retired_instances = vec!["default".into()];
        assert_ne!(first, approval_digest(&identity, &retirement)?);

        let mut missing_cache = plan.clone();
        missing_cache.download_cache_present = false;
        assert_ne!(first, approval_digest(&identity, &missing_cache)?);

        let mut changed_plan = plan;
        changed_plan.candidates[0].metrics.private_reclaimable_bytes += 1;
        assert_ne!(first, approval_digest(&identity, &changed_plan)?);
        Ok(())
    }

    #[test]
    fn cache_keys_require_sha256_names() {
        assert!(valid_cache_key(&"a".repeat(64)));
        assert!(!valid_cache_key("not-a-key"));
    }

    #[test]
    fn whole_cache_measurement_includes_non_download_owner_state() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let cache_path = temporary.path().join("cache");
        fs::create_dir_all(cache_path.join("owner-metadata"))?;
        fs::write(cache_path.join("owner-metadata/state.json"), b"{}")?;
        let identity = LimaIdentity {
            executable: "/opt/homebrew/bin/limactl".into(),
            canonical_executable: "/opt/homebrew/Cellar/lima/2.1.0/bin/limactl".into(),
            version: "limactl version 2.1.0".into(),
            lima_home: temporary.path().join("lima-home"),
            cache_path,
            templates_path: None,
            instances: Vec::new(),
        };

        let measurement = measure_download_cache(&identity)?;

        assert!(measurement.present);
        assert!(measurement.candidates.is_empty());
        assert_eq!(measurement.root_metrics.files, 1);
        assert!(measurement.root_metrics.allocated_bytes > 0);
        Ok(())
    }

    #[test]
    fn absent_cache_measurement_is_complete_and_not_present() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let identity = LimaIdentity {
            executable: "/opt/homebrew/bin/limactl".into(),
            canonical_executable: "/opt/homebrew/Cellar/lima/2.1.0/bin/limactl".into(),
            version: "limactl version 2.1.0".into(),
            lima_home: temporary.path().join("lima-home"),
            cache_path: temporary.path().join("missing-cache"),
            templates_path: None,
            instances: Vec::new(),
        };

        let measurement = measure_download_cache(&identity)?;

        assert!(!measurement.present);
        assert!(measurement.complete);
        assert!(measurement.candidates.is_empty());
        assert_eq!(
            measurement.root_metrics,
            InventoryMetrics {
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            }
        );
        Ok(())
    }

    #[test]
    fn bounded_metadata_reader_rejects_oversized_files() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let path = temporary.path().join("url");
        fs::write(&path, vec![b'x'; 4097])?;

        assert!(read_small_regular_file(&path, 4096).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn bounded_metadata_reader_rejects_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("target");
        let path = temporary.path().join("url");
        fs::write(&target, b"https://example.invalid")?;
        symlink(&target, &path)?;

        assert!(read_small_regular_file(&path, 4096).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn dangling_candidate_symlinks_are_not_treated_as_absent() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let candidate = temporary.path().join("candidate");
        symlink(temporary.path().join("missing"), &candidate)?;

        assert_eq!(existing_paths([candidate.as_path()])?, vec![candidate]);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metadata_copy_budget_bounds_entries_bytes_and_depth() {
        let mut budget = MetadataCopyBudget::default();
        budget
            .charge(MAX_METADATA_BYTES)
            .expect("the exact byte budget should be accepted");
        assert!(budget.charge(1).is_err());

        let mut entries = MetadataCopyBudget::default();
        for _ in 0..MAX_METADATA_ENTRIES {
            entries
                .charge(0)
                .expect("the exact entry budget should be accepted");
        }
        assert!(entries.charge(0).is_err());

        MetadataCopyBudget::check_depth(MAX_METADATA_DEPTH)
            .expect("the exact depth budget should be accepted");
        assert!(MetadataCopyBudget::check_depth(MAX_METADATA_DEPTH + 1).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rehearsal_copies_instance_configuration_without_vm_storage() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let lima_home = temporary.path().join("real-lima");
        let instance = lima_home.join("default");
        let cloned = temporary.path().join("cloned-lima");
        fs::create_dir_all(&instance)?;
        fs::write(instance.join("lima.yaml"), b"vmType: vz\n")?;
        File::create(instance.join("disk"))?.set_len(2 * MAX_METADATA_FILE_BYTES)?;
        let templates = lima_home.join("_templates");
        fs::create_dir_all(&templates)?;
        fs::write(templates.join("keep.yaml"), b"vmType: vz\n")?;
        fs::write(templates.join("ignore.txt"), b"not a Lima template\n")?;
        fs::write(templates.join(".hidden.yaml"), b"vmType: vz\n")?;

        let identity = LimaIdentity {
            executable: "/opt/homebrew/bin/limactl".into(),
            canonical_executable: "/opt/homebrew/Cellar/lima/2.1.0/bin/limactl".into(),
            version: "limactl version 2.1.0".into(),
            lima_home,
            cache_path: temporary.path().join("cache"),
            templates_path: None,
            instances: vec![LimaInstance {
                name: "default".into(),
                status: "Stopped".into(),
                directory: instance,
                owner_protected: false,
                error_count: 0,
                metrics: InventoryMetrics::default(),
                measurement_complete: true,
            }],
        };

        copy_instance_metadata(&identity, &cloned)?;

        assert_eq!(fs::read(cloned.join("default/lima.yaml"))?, b"vmType: vz\n");
        assert!(!cloned.join("default/disk").exists());
        assert_eq!(
            fs::read(cloned.join("_templates/keep.yaml"))?,
            b"vmType: vz\n"
        );
        assert!(!cloned.join("_templates/ignore.txt").exists());
        assert!(!cloned.join("_templates/.hidden.yaml").exists());
        Ok(())
    }

    #[test]
    fn instance_inventory_is_advisory_and_bounded() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("default");
        fs::create_dir(&directory)?;
        fs::write(directory.join("disk.raw"), vec![0_u8; 4096])?;
        let mut instances = vec![LimaInstance {
            name: "default".into(),
            status: "Stopped".into(),
            directory: directory.canonicalize()?,
            owner_protected: false,
            error_count: 0,
            metrics: InventoryMetrics::default(),
            measurement_complete: false,
        }];

        measure_instances(&mut instances)?;

        assert_eq!(instances[0].metrics.files, 1);
        assert_eq!(instances[0].metrics.logical_bytes, 4096);
        assert!(instances[0].metrics.allocated_bytes > 0);
        Ok(())
    }

    #[test]
    fn reviewed_version_is_extracted_from_lima_output() {
        assert_eq!(installed_version("limactl version 2.1.0"), Some("2.1.0"));
        assert_eq!(installed_version("unexpected"), None);
    }
}
