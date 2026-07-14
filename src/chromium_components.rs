use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::protection::{
    active_protections, protection_for_path, with_protection_guard_for_paths,
    ProtectionGuardOutcome, ProtectionLease, ProtectionMatch,
};
use crate::{format_bytes, CleanupMode};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const CHROMIUM_COMPONENT_MANIFEST_VERSION: u64 = 3;
const CHROMIUM_APPROVAL_CONTRACT: &[u8] = b"worktree-gc:chromium-components:approval:v3";
const MAX_ACTIVE_OWNER_PROCESSES: usize = 200;
const MAX_PROFILE_PATHS: usize = 16;
const QUARANTINE_PREFIX: &str = ".worktree-gc-chromium-trash-";

// These roots are downloaded component/model state at the user-data root.
// Deliberately excluded: Default, Local State, cookies, history, sessions,
// service workers, extension state, and every unrecognized directory.
const MANAGED_COMPONENT_NAMES: &[&str] = &[
    "OnDeviceHeadSuggestModel",
    "OptGuideOnDeviceClassifierModel",
    "OptGuideOnDeviceModel",
    "WasmTtsEngine",
    "optimization_guide_model_store",
];

#[derive(Debug, Clone)]
pub struct ChromiumComponentCollectOptions {
    pub execute: bool,
    pub approved_digest: Option<String>,
    pub profile_paths: Vec<PathBuf>,
    pub max_entries: u64,
    pub now: SystemTime,
}

impl Default for ChromiumComponentCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            approved_digest: None,
            profile_paths: Vec::new(),
            max_entries: 500_000,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ChromiumComponentCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: ChromiumComponentCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct ChromiumComponentCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub chromium: ChromiumComponentIdentity,
    pub policy: ChromiumComponentPolicy,
    pub plan: ChromiumComponentPlan,
    pub outcome: Option<ChromiumComponentPruneOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChromiumComponentIdentity {
    pub profiles: Vec<ChromiumProfileIdentity>,
    pub managed_component_names: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChromiumProfileIdentity {
    pub requested_path: PathBuf,
    pub path: PathBuf,
    pub marker_path: PathBuf,
    pub marker_identity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChromiumComponentPolicy {
    pub owner_contract: &'static str,
    pub execution: &'static str,
    pub unattended_execution_supported: bool,
    pub rebuild_cost: &'static str,
    pub max_entries: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChromiumComponentPruneOutcome {
    pub components_deleted: usize,
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
pub enum ChromiumComponentAction {
    NoWork,
    ReportOnly,
    InUse,
    Protected,
    Incomplete,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChromiumComponentPlan {
    pub action: ChromiumComponentAction,
    pub reason: String,
    pub complete: bool,
    pub eligibility_digest: String,
    pub components: Vec<ChromiumComponentObservation>,
    pub expected_reclaim: InventoryMetrics,
    pub profile_errors: Vec<String>,
    pub active_owner_processes: Vec<String>,
    pub process_check_complete: bool,
    pub open_paths: Vec<PathBuf>,
    pub open_handle_check_complete: bool,
    pub protections: Vec<ProtectionMatch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChromiumComponentObservation {
    pub profile_path: PathBuf,
    pub name: String,
    pub requested_path: PathBuf,
    pub path: PathBuf,
    pub root_identity: String,
    pub modified_unix_nanos: u64,
    pub filesystem: String,
    pub metrics: InventoryMetrics,
}

#[derive(Debug)]
struct ComponentSnapshot {
    identity: ChromiumComponentIdentity,
    paths: Vec<UnmeasuredComponent>,
    profile_errors: Vec<String>,
    complete: bool,
}

#[derive(Debug)]
struct UnmeasuredComponent {
    profile_path: PathBuf,
    name: String,
    requested_path: PathBuf,
    path: PathBuf,
    root_identity: String,
    modified_unix_nanos: u64,
}

type ComponentMeasurements = BTreeMap<PathBuf, (String, InventoryMetrics)>;

pub fn collect_chromium_components(
    options: ChromiumComponentCollectOptions,
) -> Result<ChromiumComponentCollectRun> {
    anyhow::ensure!(
        !options.profile_paths.is_empty(),
        "Chromium component collection requires at least one explicit profile path"
    );
    anyhow::ensure!(
        options.profile_paths.len() <= MAX_PROFILE_PATHS,
        "Chromium component collection accepts at most {MAX_PROFILE_PATHS} profile paths"
    );
    anyhow::ensure!(options.max_entries > 0, "max_entries must be at least 1");
    anyhow::ensure!(
        options.execute || options.approved_digest.is_none(),
        "--approved-digest is only valid with --execute"
    );
    if options.execute {
        let digest = options
            .approved_digest
            .as_deref()
            .context("Chromium component execution requires --approved-digest from a dry-run")?;
        anyhow::ensure!(
            valid_sha256_digest(digest),
            "--approved-digest must be a sha256: digest"
        );
    }
    let protections = active_protections(options.now)?;
    let (identity, plan) = plan_chromium_components(&options, &protections);
    let mut manifest = ChromiumComponentCollectManifest {
        manifest_version: CHROMIUM_COMPONENT_MANIFEST_VERSION,
        collector: "chromium-components",
        run_id: format!("{}-{}", unix_nanos(options.now), std::process::id()),
        mode: if options.execute {
            CleanupMode::Execute
        } else {
            CleanupMode::DryRun
        },
        generated_at_unix: unix_seconds(options.now),
        chromium: identity,
        policy: ChromiumComponentPolicy {
            owner_contract: "explicit Chromium user-data roots plus a closed list of whole re-downloadable on-device component/model directories; this resets installed component revisions rather than pruning stale revisions, and browser profile state is excluded",
            execution: "manual digest-bound same-filesystem quarantine with execution-time browser/open-file/protection revalidation",
            unattended_execution_supported: false,
            rebuild_cost: "full component redownload",
            max_entries: options.max_entries,
        },
        plan,
        outcome: None,
    };
    let manifest_path = write_manifest(&manifest)?;
    if let Some(approved) = options.approved_digest.as_deref() {
        anyhow::ensure!(
            approved == manifest.plan.eligibility_digest,
            "approved Chromium component plan {approved} does not match current plan {}; review {} before trying again",
            manifest.plan.eligibility_digest,
            manifest_path.display()
        );
    }
    if options.execute {
        let execution = execute_chromium_component_plan(&options, &mut manifest);
        write_manifest_at(&manifest_path, &manifest)?;
        execution.with_context(|| {
            format!(
                "Chromium component execution failed; inspect manifest {}",
                manifest_path.display()
            )
        })?;
    }
    Ok(ChromiumComponentCollectRun {
        manifest_path,
        manifest,
    })
}

fn plan_chromium_components(
    options: &ChromiumComponentCollectOptions,
    protections: &[ProtectionLease],
) -> (ChromiumComponentIdentity, ChromiumComponentPlan) {
    let snapshot = snapshot_components(&options.profile_paths);
    let ComponentSnapshot {
        identity,
        paths,
        mut profile_errors,
        complete: snapshot_complete,
    } = snapshot;
    let component_paths = paths
        .iter()
        .map(|component| component.path.clone())
        .collect::<Vec<_>>();
    let (measurements, measurement_complete, measurement_error) =
        measure_paths(&component_paths, options.max_entries);
    if let Some(error) = measurement_error {
        profile_errors.push(error);
    }
    let components = measured_components(paths, &measurements);
    let profiles_stable = identity.profiles.iter().all(profile_identity_is_current);
    if !profiles_stable {
        profile_errors.push(
            "one or more Chromium profile markers changed during measurement; rerun after browser writers stop"
                .into(),
        );
    }
    let identities_stable = components.iter().all(component_identity_is_current);
    if !identities_stable {
        profile_errors.push(
            "one or more Chromium component roots changed during measurement; rerun after browser writers stop"
                .into(),
        );
    }
    let expected_reclaim = sum_metrics(components.iter().map(|component| &component.metrics));
    let mut component_protections = components
        .iter()
        .flat_map(|component| [&component.requested_path, &component.path])
        .filter_map(|path| protection_for_path(path, protections))
        .collect::<Vec<_>>();
    component_protections.sort_by(|left, right| left.id.cmp(&right.id));
    component_protections.dedup_by(|left, right| left.id == right.id);
    let (active_owner_processes, process_check_complete) =
        active_chromium_processes(&identity.profiles);
    let (open_paths, open_handle_check_complete) = if process_check_complete
        && active_owner_processes.is_empty()
        && component_protections.is_empty()
        && snapshot_complete
        && measurement_complete
        && profiles_stable
        && identities_stable
    {
        open_component_paths(&components)
    } else if process_check_complete
        && (!active_owner_processes.is_empty() || !component_protections.is_empty())
    {
        // A profile-owning browser or recursive protection is already a
        // definitive block. Do not take another machine-wide ownership
        // snapshot merely to prove the same decision.
        (Vec::new(), true)
    } else {
        // Do not take ownership evidence after the bounded inventory or
        // process evidence has already failed closed.
        (Vec::new(), false)
    };
    let complete = snapshot_complete
        && measurement_complete
        && profiles_stable
        && identities_stable
        && process_check_complete
        && open_handle_check_complete
        && components
            .iter()
            .all(|component| component.metrics.private_reclaimable_complete);
    let (action, reason) = classify_plan(
        components.is_empty(),
        complete,
        &active_owner_processes,
        &open_paths,
        &component_protections,
    );
    let eligibility_digest = eligibility_digest(&identity, &components, options);
    (
        identity,
        ChromiumComponentPlan {
            action,
            reason,
            complete,
            eligibility_digest,
            components,
            expected_reclaim,
            profile_errors,
            active_owner_processes,
            process_check_complete,
            open_paths,
            open_handle_check_complete,
            protections: component_protections,
        },
    )
}

fn profile_identity_is_current(profile: &ChromiumProfileIdentity) -> bool {
    fs::symlink_metadata(&profile.marker_path).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && file_identity(&metadata) == profile.marker_identity
    })
}

fn component_identity_is_current(component: &ChromiumComponentObservation) -> bool {
    fs::symlink_metadata(&component.path).is_ok_and(|metadata| {
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && file_identity(&metadata) == component.root_identity
            && metadata.modified().map(unix_nanos_u64).ok() == Some(component.modified_unix_nanos)
    })
}

pub fn print_chromium_component_collect(run: &ChromiumComponentCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: chromium-components");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    for profile in &run.manifest.chromium.profiles {
        println!("profile: {}", profile.path.display());
    }
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!(
        "re-downloadable components: {} roots, {} private{} | {} allocated",
        plan.components.len(),
        format_bytes(plan.expected_reclaim.private_reclaimable_bytes),
        if plan.expected_reclaim.private_reclaimable_complete {
            ""
        } else {
            " (lower bound)"
        },
        format_bytes(plan.expected_reclaim.allocated_bytes)
    );
    for component in &plan.components {
        println!(
            "  {} private{} | {} allocated | {}",
            format_bytes(component.metrics.private_reclaimable_bytes),
            if component.metrics.private_reclaimable_complete {
                ""
            } else {
                " (lower bound)"
            },
            format_bytes(component.metrics.allocated_bytes),
            component.path.display()
        );
    }
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "deleted: {} component roots | {} realized free-space gain | verification {}",
            outcome.components_deleted,
            format_bytes(outcome.realized_reclaim_bytes),
            if outcome.verification_complete && outcome.error.is_none() {
                "complete"
            } else {
                "incomplete"
            }
        );
    }
}

fn snapshot_components(requested_profiles: &[PathBuf]) -> ComponentSnapshot {
    let mut profiles = Vec::new();
    let mut paths = Vec::new();
    let mut profile_errors = Vec::new();
    let mut complete = true;
    for requested_path in requested_profiles {
        if !requested_path.is_absolute() {
            complete = false;
            profile_errors.push(format!(
                "Chromium profile path is not absolute: {}",
                requested_path.display()
            ));
            continue;
        }
        if requested_path
            .to_str()
            .is_none_or(|path| path.contains('\n') || path.contains('\r'))
        {
            complete = false;
            profile_errors.push(format!(
                "Chromium profile path is not safely representable in process evidence: {}",
                requested_path.display()
            ));
            continue;
        }
        let metadata = match fs::symlink_metadata(requested_path) {
            Ok(metadata) => metadata,
            Err(error) => {
                complete = false;
                profile_errors.push(format!("inspect {}: {error}", requested_path.display()));
                continue;
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            complete = false;
            profile_errors.push(format!(
                "{} is not a non-symlink Chromium profile directory",
                requested_path.display()
            ));
            continue;
        }
        let path = match requested_path.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                complete = false;
                profile_errors.push(format!(
                    "canonicalize {}: {error}",
                    requested_path.display()
                ));
                continue;
            }
        };
        let marker_path = path.join("Local State");
        let marker_metadata = match fs::symlink_metadata(&marker_path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                complete = false;
                profile_errors.push(format!(
                    "{} is not a regular non-symlink Chromium Local State marker",
                    marker_path.display()
                ));
                continue;
            }
            Err(error) => {
                complete = false;
                profile_errors.push(format!(
                    "inspect Chromium Local State marker {}: {error}",
                    marker_path.display()
                ));
                continue;
            }
        };
        profiles.push(ChromiumProfileIdentity {
            requested_path: requested_path.clone(),
            path: path.clone(),
            marker_path,
            marker_identity: file_identity(&marker_metadata),
        });
        match fs::read_dir(&path) {
            Ok(entries) => {
                for entry in entries {
                    match entry {
                        Ok(entry)
                            if entry
                                .file_name()
                                .to_string_lossy()
                                .starts_with(QUARANTINE_PREFIX) =>
                        {
                            complete = false;
                            profile_errors.push(format!(
                                "interrupted Chromium component quarantine requires explicit recovery review: {}",
                                entry.path().display()
                            ));
                        }
                        Ok(_) => {}
                        Err(error) => {
                            complete = false;
                            profile_errors.push(format!(
                                "read Chromium profile entry in {}: {error}",
                                path.display()
                            ));
                        }
                    }
                }
            }
            Err(error) => {
                complete = false;
                profile_errors.push(format!("read Chromium profile {}: {error}", path.display()));
            }
        }
        for name in MANAGED_COMPONENT_NAMES {
            let component_path = path.join(name);
            let metadata = match fs::symlink_metadata(&component_path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    complete = false;
                    profile_errors.push(format!("inspect {}: {error}", component_path.display()));
                    continue;
                }
            };
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                complete = false;
                profile_errors.push(format!(
                    "{} is not a non-symlink component directory",
                    component_path.display()
                ));
                continue;
            }
            let modified_unix_nanos = match metadata.modified() {
                Ok(modified) => unix_nanos_u64(modified),
                Err(error) => {
                    complete = false;
                    profile_errors.push(format!(
                        "read modification time for {}: {error}",
                        component_path.display()
                    ));
                    continue;
                }
            };
            paths.push(UnmeasuredComponent {
                profile_path: path.clone(),
                name: (*name).to_string(),
                requested_path: requested_path.join(name),
                path: component_path,
                root_identity: file_identity(&metadata),
                modified_unix_nanos,
            });
        }
    }
    profiles.sort_by(|left, right| left.path.cmp(&right.path));
    profiles.dedup_by(|left, right| left.path == right.path);
    paths.sort_by(|left, right| left.path.cmp(&right.path));
    paths.dedup_by(|left, right| left.path == right.path);
    ComponentSnapshot {
        identity: ChromiumComponentIdentity {
            profiles,
            managed_component_names: MANAGED_COMPONENT_NAMES.to_vec(),
        },
        paths,
        profile_errors,
        complete,
    }
}

fn measure_paths(
    paths: &[PathBuf],
    max_entries: u64,
) -> (ComponentMeasurements, bool, Option<String>) {
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
            let measurements = paths
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
            (measurements, complete, None)
        }
        Err(error) => (
            BTreeMap::new(),
            false,
            Some(format!("measure Chromium components: {error:#}")),
        ),
    }
}

fn measured_components(
    components: Vec<UnmeasuredComponent>,
    measurements: &ComponentMeasurements,
) -> Vec<ChromiumComponentObservation> {
    components
        .into_iter()
        .map(|component| ChromiumComponentObservation {
            filesystem: measurements
                .get(&component.path)
                .map(|(filesystem, _)| filesystem.clone())
                .unwrap_or_else(|| "unknown".into()),
            metrics: measurements
                .get(&component.path)
                .map(|(_, metrics)| metrics.clone())
                .unwrap_or_else(|| InventoryMetrics {
                    private_reclaimable_complete: false,
                    ..InventoryMetrics::default()
                }),
            profile_path: component.profile_path,
            name: component.name,
            requested_path: component.requested_path,
            path: component.path,
            root_identity: component.root_identity,
            modified_unix_nanos: component.modified_unix_nanos,
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
    components_empty: bool,
    complete: bool,
    active_processes: &[String],
    open_paths: &[PathBuf],
    protections: &[ProtectionMatch],
) -> (ChromiumComponentAction, String) {
    if !complete {
        (
            ChromiumComponentAction::Incomplete,
            "profile discovery, APFS measurement, or liveness evidence is incomplete".into(),
        )
    } else if components_empty {
        (
            ChromiumComponentAction::NoWork,
            "none of the recognized re-downloadable component roots are present".into(),
        )
    } else if !protections.is_empty() {
        (
            ChromiumComponentAction::Protected,
            "one or more component roots intersect an active protection".into(),
        )
    } else if !active_processes.is_empty() || !open_paths.is_empty() {
        (
            ChromiumComponentAction::InUse,
            "a Chromium process or open component path is active".into(),
        )
    } else {
        (
            ChromiumComponentAction::ReportOnly,
            "whole re-downloadable component roots are isolated, measured, and eligible for an explicit digest-bound cache reset".into(),
        )
    }
}

fn active_chromium_processes(profiles: &[ChromiumProfileIdentity]) -> (Vec<String>, bool) {
    let output = match Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(_) | Err(_) => return (Vec::new(), false),
    };
    select_active_chromium_processes(&output.stdout, profiles, std::process::id())
}

fn select_active_chromium_processes(
    process_list: &[u8],
    profiles: &[ChromiumProfileIdentity],
    self_pid: u32,
) -> (Vec<String>, bool) {
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
        .filter(|(pid, _, command)| {
            *pid != self_pid
                && is_chromium_command(command)
                && profiles.iter().any(|profile| {
                    command.contains(profile.requested_path.to_string_lossy().as_ref())
                        || command.contains(profile.path.to_string_lossy().as_ref())
                        || (is_default_chromium_profile(&profile.path)
                            && !command.contains("--user-data-dir"))
                })
        })
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

fn is_chromium_command(command: &str) -> bool {
    let lowercase = command.to_ascii_lowercase();
    lowercase.contains(".app/contents/macos/google chrome")
        || lowercase.contains(".app/contents/macos/chromium")
        || command.split_whitespace().any(|word| {
            matches!(
                Path::new(word)
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default(),
                "chrome"
                    | "chromium"
                    | "chrome-headless-shell"
                    | "Google Chrome"
                    | "Google Chrome Canary"
            )
        })
}

fn is_default_chromium_profile(path: &Path) -> bool {
    let text = path.to_string_lossy();
    [
        "/Library/Application Support/Google/Chrome",
        "/Library/Application Support/Google/Chrome Canary",
        "/Library/Application Support/Google/Chrome Beta",
        "/Library/Application Support/Google/Chrome Dev",
        "/Library/Application Support/Chromium",
    ]
    .iter()
    .any(|suffix| text.ends_with(suffix))
}

fn owner_process_summary(pid: u32, command: &str) -> String {
    let executable = command
        .split_whitespace()
        .find_map(|word| {
            let basename = Path::new(word).file_name()?.to_str()?;
            let lowercase = basename.to_ascii_lowercase();
            (lowercase.contains("chrome") || lowercase.contains("chromium")).then_some(basename)
        })
        .unwrap_or("chromium");
    format!("{pid} {executable}")
}

fn open_component_paths(components: &[ChromiumComponentObservation]) -> (Vec<PathBuf>, bool) {
    let roots = components
        .iter()
        .map(|component| component.path.as_path())
        .collect::<Vec<_>>();
    open_paths_under_roots(&roots)
}

fn open_paths_under_roots(roots: &[&Path]) -> (Vec<PathBuf>, bool) {
    let candidates = roots
        .iter()
        .map(|root| root.to_path_buf())
        .collect::<Vec<_>>();
    let (open, complete) = crate::open_handle_evidence_for_paths(&candidates);
    let mut paths = open.into_iter().collect::<Vec<_>>();
    paths.sort();
    (paths, complete)
}

fn eligibility_digest(
    identity: &ChromiumComponentIdentity,
    components: &[ChromiumComponentObservation],
    options: &ChromiumComponentCollectOptions,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CHROMIUM_APPROVAL_CONTRACT);
    hasher.update(CHROMIUM_COMPONENT_MANIFEST_VERSION.to_le_bytes());
    hasher.update(options.max_entries.to_le_bytes());
    hasher.update((MAX_PROFILE_PATHS as u64).to_le_bytes());
    for name in &identity.managed_component_names {
        hasher.update(name.as_bytes());
        hasher.update([0]);
    }
    for profile in &identity.profiles {
        hasher.update(profile.requested_path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(profile.path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(profile.marker_path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(profile.marker_identity.as_bytes());
        hasher.update([0]);
    }
    for component in components {
        hasher.update(component.name.as_bytes());
        hasher.update([0]);
        hasher.update(component.requested_path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(component.path.as_os_str().as_encoded_bytes());
        hasher.update([0]);
        hasher.update(component.root_identity.as_bytes());
        hasher.update([0]);
        hasher.update(component.modified_unix_nanos.to_le_bytes());
        hasher.update(component.filesystem.as_bytes());
        hasher.update([0]);
        hasher.update(component.metrics.logical_bytes.to_le_bytes());
        hasher.update(component.metrics.allocated_bytes.to_le_bytes());
        hasher.update(component.metrics.private_reclaimable_bytes.to_le_bytes());
        hasher.update([u8::from(component.metrics.private_reclaimable_complete)]);
        hasher.update(component.metrics.files.to_le_bytes());
        hasher.update(component.metrics.directories.to_le_bytes());
        hasher.update(component.metrics.hardlink_duplicates.to_le_bytes());
        hasher.update(component.metrics.errors.to_le_bytes());
    }
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "dev:{}:ino:{}:len:{}:mtime:{}:{}:ctime:{}:{}",
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
        metadata.modified().map(unix_nanos_u64).unwrap_or_default(),
        metadata.created().map(unix_nanos_u64).unwrap_or_default()
    )
}

#[derive(Debug)]
struct QuarantinedChromiumComponent {
    original: PathBuf,
    quarantined: PathBuf,
    expected_quarantine_identity: String,
}

fn execute_chromium_component_plan(
    options: &ChromiumComponentCollectOptions,
    manifest: &mut ChromiumComponentCollectManifest,
) -> Result<()> {
    anyhow::ensure!(
        manifest.plan.action == ChromiumComponentAction::ReportOnly,
        "Chromium component plan is not executable: {}",
        manifest.plan.reason
    );
    let lock = acquire_collector_lock()?;
    let candidate_paths = manifest
        .plan
        .components
        .iter()
        .map(|component| component.path.clone())
        .collect::<Vec<_>>();
    let guarded = with_protection_guard_for_paths(&candidate_paths, SystemTime::now(), || {
        execute_chromium_component_plan_guarded(options, manifest)
    })?;
    drop(lock);
    match guarded {
        ProtectionGuardOutcome::Protected(protection) => bail!(
            "Chromium component candidate became protected by lease {} ({})",
            protection.id,
            protection.reason
        ),
        ProtectionGuardOutcome::Executed(outcome) => manifest.outcome = Some(outcome?),
    }
    let outcome = manifest
        .outcome
        .as_ref()
        .context("executed Chromium component prune did not record an outcome")?;
    anyhow::ensure!(
        outcome.error.is_none()
            && outcome.verification_complete
            && outcome.remaining_original_paths.is_empty()
            && outcome.remaining_quarantine_paths.is_empty(),
        "Chromium component quarantine did not prove every approved root absent: {}",
        outcome
            .error
            .as_deref()
            .unwrap_or("approved or quarantine paths remain")
    );
    Ok(())
}

fn execute_chromium_component_plan_guarded(
    options: &ChromiumComponentCollectOptions,
    manifest: &ChromiumComponentCollectManifest,
) -> Result<ChromiumComponentPruneOutcome> {
    let mut refreshed_options = options.clone();
    refreshed_options.execute = false;
    refreshed_options.approved_digest = None;
    refreshed_options.now = SystemTime::now();
    let (identity, refreshed) = plan_chromium_components(&refreshed_options, &[]);
    anyhow::ensure!(
        identity == manifest.chromium,
        "Chromium profile roots changed after planning; rerun without --execute"
    );
    anyhow::ensure!(
        refreshed.action == ChromiumComponentAction::ReportOnly
            && refreshed.complete
            && refreshed.eligibility_digest == manifest.plan.eligibility_digest
            && refreshed.components == manifest.plan.components,
        "Chromium component eligibility changed after planning; rerun without --execute"
    );
    let filesystems = refreshed
        .components
        .iter()
        .map(|component| component.filesystem.as_str())
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        filesystems.len() == 1 && !filesystems.contains("unknown"),
        "Chromium execution currently requires all approved roots on one known filesystem"
    );
    let observation_path = refreshed
        .components
        .first()
        .map(|component| component.profile_path.as_path())
        .context("Chromium execution has no profile for free-space observation")?;
    let available_bytes_before = fs4::available_space(observation_path)?;
    let quarantine_paths =
        quarantine_paths(&manifest.chromium, &refreshed.components, &manifest.run_id)?;
    let mut moved = Vec::new();
    let move_result = (|| -> Result<()> {
        for quarantine in quarantine_paths.values() {
            create_private_directory(quarantine)
                .with_context(|| format!("create Chromium quarantine {}", quarantine.display()))?;
        }
        for component in &refreshed.components {
            let parent = component
                .path
                .parent()
                .context("Chromium component has no profile parent")?;
            anyhow::ensure!(
                parent == component.profile_path,
                "Chromium component escaped its approved profile: {}",
                component.path.display()
            );
            anyhow::ensure!(
                MANAGED_COMPONENT_NAMES.contains(&component.name.as_str()),
                "Chromium component name is outside the closed owner contract: {}",
                component.path.display()
            );
            let quarantine = quarantine_paths.get(parent).with_context(|| {
                format!(
                    "Chromium component escaped the owner-declared profiles: {}",
                    component.path.display()
                )
            })?;
            let metadata = fs::symlink_metadata(&component.path)?;
            anyhow::ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "Chromium component is no longer a non-symlink directory: {}",
                component.path.display()
            );
            anyhow::ensure!(
                file_identity(&metadata) == component.root_identity
                    && metadata.modified().map(unix_nanos_u64).ok()
                        == Some(component.modified_unix_nanos),
                "Chromium component identity or activity changed immediately before quarantine: {}",
                component.path.display()
            );
            let expected_quarantine_identity = quarantine_root_identity(&metadata);
            let destination = quarantine.join(&component.name);
            ensure_path_absent(&destination, "Chromium quarantine destination")?;
            fs::rename(&component.path, &destination).with_context(|| {
                format!(
                    "quarantine Chromium component {} as {}",
                    component.path.display(),
                    destination.display()
                )
            })?;
            moved.push(QuarantinedChromiumComponent {
                original: component.path.clone(),
                quarantined: destination,
                expected_quarantine_identity,
            });
        }
        Ok(())
    })();
    if let Err(error) = move_result {
        rollback_chromium_quarantine(&moved, quarantine_paths.values())
            .context("rollback Chromium quarantine after a move failure")?;
        return Err(error);
    }

    let (owners, owner_check_complete) = active_chromium_processes(&manifest.chromium.profiles);
    let quarantine_roots = moved
        .iter()
        .map(|entry| entry.quarantined.as_path())
        .collect::<Vec<_>>();
    let (open_paths, open_check_complete) = open_paths_under_roots(&quarantine_roots);
    if !owner_check_complete || !open_check_complete || !owners.is_empty() || !open_paths.is_empty()
    {
        rollback_chromium_quarantine(&moved, quarantine_paths.values())
            .context("rollback Chromium quarantine after execution-time ownership changed")?;
        bail!("Chromium ownership changed after quarantine; approved roots were restored");
    }
    for entry in &moved {
        ensure_quarantined_identity(entry).with_context(|| {
            format!(
                "Chromium quarantined component changed after rename; retained for review at {}",
                entry.quarantined.display()
            )
        })?;
    }

    let mut deletion_error = None;
    let mut deleted_paths = Vec::new();
    for entry in &moved {
        if let Err(error) = ensure_quarantined_identity(entry) {
            deletion_error = Some(format!(
                "revalidate quarantined Chromium component {}: {error:#}",
                entry.quarantined.display()
            ));
            break;
        }
        if let Err(error) = ensure_tree_on_one_filesystem(&entry.quarantined, options.max_entries) {
            deletion_error = Some(format!(
                "verify quarantined Chromium component {}: {error:#}",
                entry.quarantined.display()
            ));
            break;
        }
        match fs::remove_dir_all(&entry.quarantined) {
            Ok(()) => deleted_paths.push(entry.original.clone()),
            Err(error) => {
                deletion_error = Some(format!(
                    "remove quarantined Chromium component {}: {error}",
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
                    "remove empty Chromium quarantine {}: {error}",
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
    Ok(ChromiumComponentPruneOutcome {
        components_deleted: deleted_paths.len(),
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
    identity: &ChromiumComponentIdentity,
    components: &[ChromiumComponentObservation],
    run_id: &str,
) -> Result<BTreeMap<PathBuf, PathBuf>> {
    let profile_roots = identity
        .profiles
        .iter()
        .map(|profile| profile.path.as_path())
        .collect::<BTreeSet<_>>();
    let mut paths = BTreeMap::new();
    for profile in components
        .iter()
        .map(|component| component.profile_path.as_path())
    {
        anyhow::ensure!(
            profile_roots.contains(profile),
            "Chromium component profile is outside an owner-declared root: {}",
            profile.display()
        );
        let quarantine = profile.join(format!("{QUARANTINE_PREFIX}{run_id}"));
        ensure_path_absent(&quarantine, "Chromium quarantine")?;
        paths.insert(profile.to_path_buf(), quarantine);
    }
    Ok(paths)
}

fn rollback_chromium_quarantine<'a>(
    moved: &[QuarantinedChromiumComponent],
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
        ensure_path_absent(&entry.original, "Chromium rollback destination").with_context(
            || {
                format!(
                    "cannot restore {}; quarantine retained at {}",
                    entry.original.display(),
                    entry.quarantined.display()
                )
            },
        )?;
        fs::rename(&entry.quarantined, &entry.original).with_context(|| {
            format!(
                "restore Chromium component {} from {}",
                entry.original.display(),
                entry.quarantined.display()
            )
        })?;
    }
    for quarantine in quarantine_paths {
        if path_exists_no_follow(quarantine)? {
            fs::remove_dir(quarantine).with_context(|| {
                format!("remove empty Chromium quarantine {}", quarantine.display())
            })?;
        }
    }
    Ok(())
}

fn ensure_quarantined_identity(entry: &QuarantinedChromiumComponent) -> Result<()> {
    let metadata = fs::symlink_metadata(&entry.quarantined).with_context(|| {
        format!(
            "inspect quarantined Chromium component {}",
            entry.quarantined.display()
        )
    })?;
    anyhow::ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && quarantine_root_identity(&metadata) == entry.expected_quarantine_identity,
        "quarantined path no longer names the approved component root"
    );
    Ok(())
}

#[cfg(unix)]
fn quarantine_root_identity(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("dev:{}:ino:{}", metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn quarantine_root_identity(metadata: &fs::Metadata) -> String {
    format!(
        "created:{}",
        metadata.created().map(unix_nanos_u64).unwrap_or_default()
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
fn ensure_tree_on_one_filesystem(root: &Path, max_entries: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let root_metadata = fs::symlink_metadata(root)?;
    anyhow::ensure!(
        root_metadata.is_dir() && !root_metadata.file_type().is_symlink(),
        "quarantined component root is not a non-symlink directory"
    );
    let root_device = root_metadata.dev();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0u64;
    while let Some(directory) = stack.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            visited = visited.saturating_add(1);
            anyhow::ensure!(
                visited <= max_entries,
                "quarantined component exceeded the approved entry budget"
            );
            let metadata = fs::symlink_metadata(entry.path())?;
            anyhow::ensure!(
                metadata.dev() == root_device,
                "nested filesystem boundary at {}",
                entry.path().display()
            );
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                stack.push(entry.path());
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_tree_on_one_filesystem(_root: &Path, _max_entries: u64) -> Result<()> {
    bail!("Chromium recursive quarantine removal requires Unix device identity")
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
        .open(directory.join("chromium-components.lock"))?;
    lock.lock().context("lock Chromium component collector")?;
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

fn write_manifest(manifest: &ChromiumComponentCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!(
        "{}-chromium-components-{mode}.json",
        manifest.run_id,
    ));
    write_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_manifest_at(path: &Path, manifest: &ChromiumComponentCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic Chromium manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Chromium manifest {}", path.display()))?;
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

fn unix_nanos_u64(time: SystemTime) -> u64 {
    unix_nanos(time).min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn initialize_profile(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("Local State"), b"{}").unwrap();
    }

    #[test]
    fn snapshot_includes_only_the_closed_component_set() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        initialize_profile(&profile);
        fs::create_dir_all(profile.join("OptGuideOnDeviceModel")).unwrap();
        fs::create_dir_all(profile.join("Default")).unwrap();
        fs::create_dir_all(profile.join("Service Worker")).unwrap();

        let snapshot = snapshot_components(std::slice::from_ref(&profile));

        assert!(snapshot.complete);
        assert_eq!(snapshot.paths.len(), 1);
        assert_eq!(snapshot.paths[0].name, "OptGuideOnDeviceModel");
        assert_eq!(
            snapshot.paths[0].profile_path,
            profile.canonicalize().unwrap()
        );
    }

    #[test]
    fn uninitialized_directory_is_not_a_chromium_profile() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        fs::create_dir_all(profile.join("OptGuideOnDeviceModel")).unwrap();

        let snapshot = snapshot_components(&[profile]);

        assert!(!snapshot.complete);
        assert!(snapshot.paths.is_empty());
        assert!(snapshot
            .profile_errors
            .iter()
            .any(|error| error.contains("Local State")));
    }

    #[test]
    fn symlinked_component_fails_closed() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        initialize_profile(&profile);
        #[cfg(unix)]
        std::os::unix::fs::symlink(temp.path(), profile.join("OptGuideOnDeviceModel")).unwrap();

        let snapshot = snapshot_components(&[profile]);

        #[cfg(unix)]
        {
            assert!(!snapshot.complete);
            assert!(snapshot.paths.is_empty());
        }
    }

    #[test]
    fn interrupted_quarantine_fails_the_next_plan_closed() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        initialize_profile(&profile);
        fs::create_dir_all(profile.join("OptGuideOnDeviceModel")).unwrap();
        let quarantine = profile.join(format!("{QUARANTINE_PREFIX}interrupted"));
        fs::create_dir_all(quarantine.join("WasmTtsEngine")).unwrap();

        let snapshot = snapshot_components(&[profile]);

        assert!(!snapshot.complete);
        assert!(snapshot
            .profile_errors
            .iter()
            .any(|error| error.contains("explicit recovery review")));
        assert!(quarantine.exists());
    }

    #[test]
    fn process_matching_is_profile_specific_and_includes_descendants() {
        let profile = ChromiumProfileIdentity {
            requested_path: PathBuf::from("/tmp/profile-a"),
            path: PathBuf::from("/tmp/profile-a"),
            marker_path: PathBuf::from("/tmp/profile-a/Local State"),
            marker_identity: "identity".into(),
        };
        let processes = b"10 1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/profile-a\n11 10 chrome --type=renderer\n12 1 /Applications/Google Chrome.app/Contents/MacOS/Google Chrome --user-data-dir=/tmp/profile-b\n";

        let (owners, complete) = select_active_chromium_processes(processes, &[profile], 999);

        assert!(complete);
        assert_eq!(owners, ["10 Chrome", "11 chrome"]);
    }

    #[test]
    fn standard_chromium_profiles_include_release_channels() {
        for suffix in [
            "Google/Chrome",
            "Google/Chrome Canary",
            "Google/Chrome Beta",
            "Google/Chrome Dev",
            "Chromium",
        ] {
            assert!(is_default_chromium_profile(&PathBuf::from(format!(
                "/Users/example/Library/Application Support/{suffix}"
            ))));
        }
        assert!(!is_default_chromium_profile(Path::new(
            "/tmp/explicit-profile"
        )));
    }

    #[test]
    fn incomplete_evidence_does_not_become_no_work() {
        let (action, _) = classify_plan(true, false, &[], &[], &[]);

        assert_eq!(action, ChromiumComponentAction::Incomplete);
    }

    #[test]
    fn approval_digest_binds_scan_policy_and_component_evidence() {
        let identity = ChromiumComponentIdentity {
            profiles: vec![ChromiumProfileIdentity {
                requested_path: PathBuf::from("/profile"),
                path: PathBuf::from("/profile"),
                marker_path: PathBuf::from("/profile/Local State"),
                marker_identity: "identity".into(),
            }],
            managed_component_names: MANAGED_COMPONENT_NAMES.to_vec(),
        };
        let component = ChromiumComponentObservation {
            profile_path: PathBuf::from("/profile"),
            name: "OptGuideOnDeviceModel".into(),
            requested_path: PathBuf::from("/profile/OptGuideOnDeviceModel"),
            path: PathBuf::from("/profile/OptGuideOnDeviceModel"),
            root_identity: "identity".into(),
            modified_unix_nanos: 1,
            filesystem: "device:1".into(),
            metrics: InventoryMetrics {
                logical_bytes: 10,
                allocated_bytes: 20,
                private_reclaimable_bytes: 20,
                private_reclaimable_complete: true,
                directories: 1,
                ..InventoryMetrics::default()
            },
        };
        let options = ChromiumComponentCollectOptions {
            max_entries: 100,
            ..ChromiumComponentCollectOptions::default()
        };
        let first = eligibility_digest(&identity, std::slice::from_ref(&component), &options);
        let repeated = eligibility_digest(&identity, std::slice::from_ref(&component), &options);
        let changed_policy = eligibility_digest(
            &identity,
            std::slice::from_ref(&component),
            &ChromiumComponentCollectOptions {
                max_entries: 101,
                ..options.clone()
            },
        );
        let mut changed_component = component;
        changed_component.metrics.private_reclaimable_bytes = 19;
        let changed_evidence = eligibility_digest(&identity, &[changed_component], &options);

        assert_eq!(first, repeated);
        assert_ne!(first, changed_policy);
        assert_ne!(first, changed_evidence);
    }

    #[test]
    fn quarantine_mapping_includes_only_profiles_with_approved_components() {
        let temp = TempDir::new().unwrap();
        let profile_a = temp.path().join("profile-a");
        let profile_b = temp.path().join("profile-b");
        fs::create_dir_all(&profile_a).unwrap();
        fs::create_dir_all(&profile_b).unwrap();
        let identity = ChromiumComponentIdentity {
            profiles: vec![
                ChromiumProfileIdentity {
                    requested_path: profile_a.clone(),
                    path: profile_a.clone(),
                    marker_path: profile_a.join("Local State"),
                    marker_identity: "identity-a".into(),
                },
                ChromiumProfileIdentity {
                    requested_path: profile_b.clone(),
                    path: profile_b.clone(),
                    marker_path: profile_b.join("Local State"),
                    marker_identity: "identity-b".into(),
                },
            ],
            managed_component_names: MANAGED_COMPONENT_NAMES.to_vec(),
        };
        let component = ChromiumComponentObservation {
            profile_path: profile_a.clone(),
            name: "OptGuideOnDeviceModel".into(),
            requested_path: profile_a.join("OptGuideOnDeviceModel"),
            path: profile_a.join("OptGuideOnDeviceModel"),
            root_identity: "dev:1:ino:2".into(),
            modified_unix_nanos: 1,
            filesystem: "device:1".into(),
            metrics: InventoryMetrics::default(),
        };

        let paths = quarantine_paths(&identity, &[component], "run").unwrap();

        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths.get(&profile_a),
            Some(&profile_a.join(format!("{QUARANTINE_PREFIX}run")))
        );
        assert!(!paths.contains_key(&profile_b));
    }

    #[test]
    fn rollback_restores_quarantined_component_and_removes_empty_directory() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        let original = profile.join("OptGuideOnDeviceModel");
        let quarantine = profile.join(format!("{QUARANTINE_PREFIX}run"));
        let quarantined = quarantine.join("OptGuideOnDeviceModel");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir(&quarantine).unwrap();
        let expected_quarantine_identity =
            quarantine_root_identity(&fs::symlink_metadata(&original).unwrap());
        fs::rename(&original, &quarantined).unwrap();
        let moved = [QuarantinedChromiumComponent {
            original: original.clone(),
            quarantined,
            expected_quarantine_identity,
        }];

        rollback_chromium_quarantine(&moved, std::iter::once(&quarantine)).unwrap();

        assert!(original.is_dir());
        assert!(!quarantine.exists());
    }

    #[test]
    fn rollback_retains_a_quarantine_whose_root_identity_changed() {
        let temp = TempDir::new().unwrap();
        let profile = temp.path().join("profile");
        let original = profile.join("OptGuideOnDeviceModel");
        let quarantine = profile.join(format!("{QUARANTINE_PREFIX}run"));
        let quarantined = quarantine.join("OptGuideOnDeviceModel");
        fs::create_dir_all(&quarantined).unwrap();
        let moved = [QuarantinedChromiumComponent {
            original: original.clone(),
            quarantined: quarantined.clone(),
            expected_quarantine_identity: "different identity".into(),
        }];

        let error = rollback_chromium_quarantine(&moved, std::iter::once(&quarantine)).unwrap_err();

        assert!(error.to_string().contains("quarantine identity changed"));
        assert!(!original.exists());
        assert!(quarantined.is_dir());
    }

    #[test]
    fn approval_digest_requires_prefixed_sha256_hex() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_sha256_digest(&"a".repeat(64)));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "g".repeat(64))));
    }

    #[cfg(unix)]
    #[test]
    fn recursive_quarantine_verification_does_not_follow_symlinks() {
        let temp = TempDir::new().unwrap();
        let quarantine = temp.path().join("quarantine");
        let external = temp.path().join("external");
        fs::create_dir(&quarantine).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(external.join("retained"), b"durable").unwrap();
        std::os::unix::fs::symlink(&external, quarantine.join("link")).unwrap();

        ensure_tree_on_one_filesystem(&quarantine, 1).unwrap();
        fs::remove_dir_all(&quarantine).unwrap();

        assert_eq!(fs::read(external.join("retained")).unwrap(), b"durable");
    }
}
