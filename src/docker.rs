use crate::protection::{
    active_protections, protection_for_path, with_protection_guard, ProtectionGuardOutcome,
    ProtectionMatch,
};
use crate::{format_bytes, CleanupMode};
use anyhow::{bail, Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DOCKER_MANIFEST_VERSION: u64 = 2;
const HOURS_PER_DAY: u64 = 24;
const MAX_DOCKER_SELECTOR_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
pub struct DockerCollectOptions {
    pub execute: bool,
    pub build_cache_days: u64,
    pub now: SystemTime,
}

impl Default for DockerCollectOptions {
    fn default() -> Self {
        Self {
            execute: false,
            build_cache_days: 7,
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DockerCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: DockerCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct DockerCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub docker: DockerIdentity,
    pub policy: DockerPolicy,
    pub plan: DockerPrunePlan,
    pub outcome: Option<DockerPruneOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerIdentity {
    pub executable: PathBuf,
    pub canonical_executable: PathBuf,
    pub client_version: String,
    pub buildx_version: String,
    pub context: String,
    pub endpoint: String,
    pub server_id: String,
    pub server_name: String,
    pub server_version: String,
    pub operating_system: String,
    pub docker_root_dir: PathBuf,
    pub builder: DockerBuilderIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerBuilderIdentity {
    pub name: String,
    pub driver: String,
    pub nodes: Vec<DockerBuilderNodeIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerBuilderNodeIdentity {
    pub name: String,
    pub endpoint: String,
    pub worker_ids: Vec<String>,
    pub status: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerPolicy {
    pub build_cache_days: u64,
    pub delegated_command: Vec<String>,
    pub image_cleanup: &'static str,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DockerPruneAction {
    DelegateBuildCache,
    NoWork,
    ReportOnly,
    InUse,
    Protected,
    UnsupportedContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerPrunePlan {
    pub action: DockerPruneAction,
    pub reason: String,
    pub complete: bool,
    pub eligibility_digest: String,
    pub build_cache_selector: Option<String>,
    pub build_cache_candidates: Vec<DockerBuildCacheCandidate>,
    pub build_cache_report_only: Vec<DockerBuildCacheCandidate>,
    pub image_candidates: Vec<DockerImageCandidate>,
    pub active_containers: u64,
    pub active_build_records: u64,
    pub active_build_processes: Vec<String>,
    pub protection: Option<ProtectionMatch>,
    pub build_cache_candidate_bytes: u64,
    pub build_cache_expected_reclaim_bytes: Option<u64>,
    pub build_cache_report_only_bytes: u64,
    pub image_unique_reclaim_bytes: u64,
    pub docker_build_cache_reclaimable_bytes: u64,
    pub docker_image_reclaimable_bytes: u64,
    pub host_observation: DockerHostObservation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerBuildCacheCandidate {
    pub id: String,
    pub cache_type: String,
    pub created_at: String,
    pub last_used_at: String,
    pub description: String,
    pub size_bytes: u64,
    pub shared: bool,
    pub mutable: bool,
    pub usage_count: u64,
    pub parents: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerImageCandidate {
    pub id: String,
    pub references: Vec<DockerImageReference>,
    pub created_at: String,
    pub size_bytes: u64,
    pub shared_size_bytes: u64,
    pub unique_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DockerImageReference {
    pub repository: String,
    pub tag: String,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerHostObservation {
    pub observed_at: PathBuf,
    pub filesystem: String,
    pub available_bytes: u64,
    pub domain_storage_path: Option<PathBuf>,
    pub orbstack_sparse_disk: Option<DockerSparseDiskObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DockerSparseDiskObservation {
    pub path: PathBuf,
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct DockerPruneOutcome {
    pub command_succeeded: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub host_available_bytes_before: u64,
    pub host_available_bytes_after: u64,
    pub realized_host_reclaim_bytes: u64,
    pub docker_build_cache_reclaimable_before: u64,
    pub docker_build_cache_reclaimable_after: Option<u64>,
    pub verification_complete: bool,
    pub verification_error: Option<String>,
    pub remaining_build_cache_candidates: Option<u64>,
}

#[derive(Debug)]
struct DockerContext {
    identity: DockerIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerInfo {
    #[serde(rename = "ID")]
    id: String,
    name: String,
    server_version: String,
    operating_system: String,
    docker_root_dir: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerUsageSummary {
    r#type: String,
    active: String,
    reclaimable: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerVerboseUsage {
    #[serde(default)]
    images: Vec<DockerVerboseImage>,
    #[serde(default)]
    build_cache: Vec<DockerVerboseBuildCache>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerVerboseImage {
    containers: String,
    created_at: String,
    digest: String,
    #[serde(rename = "ID")]
    id: String,
    repository: String,
    shared_size: String,
    size: String,
    tag: String,
    unique_size: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct DockerVerboseBuildCache {
    #[serde(rename = "ID")]
    id: String,
    in_use: String,
    last_used_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BuildxDiskUsage {
    #[serde(rename = "ID")]
    id: String,
    created_at: String,
    description: String,
    mutable: bool,
    parents: Option<Vec<String>>,
    reclaimable: bool,
    shared: bool,
    size: String,
    r#type: String,
    usage_count: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BuildxBuilder {
    current: bool,
    #[serde(default)]
    driver: String,
    name: String,
    #[serde(default)]
    nodes: Vec<BuildxBuilderNode>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BuildxBuilderNode {
    #[serde(default)]
    endpoint: String,
    #[serde(rename = "IDs", default)]
    ids: Vec<String>,
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    version: String,
}

pub fn collect_docker(options: DockerCollectOptions) -> Result<DockerCollectRun> {
    anyhow::ensure!(
        options.build_cache_days > 0,
        "Docker build-cache TTL must be at least one day"
    );
    let context = discover_docker()?;
    let mode = if options.execute {
        CleanupMode::Execute
    } else {
        CleanupMode::DryRun
    };
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let plan = plan_docker(&context.identity, &options)?;
    let delegated_command = plan
        .build_cache_selector
        .as_deref()
        .map(|selector| exact_delegated_command(&context.identity.builder.name, selector))
        .unwrap_or_default();
    let mut manifest = DockerCollectManifest {
        manifest_version: DOCKER_MANIFEST_VERSION,
        collector: "docker",
        run_id,
        mode,
        generated_at_unix: unix_seconds(options.now),
        docker: context.identity.clone(),
        policy: DockerPolicy {
            build_cache_days: options.build_cache_days,
            delegated_command,
            image_cleanup: "report_only",
            unattended_execution_supported: false,
        },
        plan,
        outcome: None,
    };
    let manifest_path = write_docker_manifest(&manifest)?;
    if options.execute {
        let execution = execute_docker_plan(&context, &options, &mut manifest);
        write_docker_manifest_at(&manifest_path, &manifest)?;
        execution.with_context(|| {
            format!(
                "Docker collector execution failed; inspect manifest {}",
                manifest_path.display()
            )
        })?;
    }
    Ok(DockerCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_docker_collect(run: &DockerCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: docker");
    println!("mode: {:?}", run.manifest.mode);
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "docker: client {}, server {} on {} ({})",
        run.manifest.docker.client_version,
        run.manifest.docker.server_version,
        run.manifest.docker.context,
        run.manifest.docker.operating_system
    );
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!("execution: manual only; Docker remains the deletion authority");
    if let Some(protection) = &plan.protection {
        println!(
            "protected by {} at {} until {}: {}",
            protection.id,
            protection.path.display(),
            protection.expires_at_unix,
            protection.reason
        );
    }
    println!(
        "build cache: {} candidates, reclaim unknown, {} overlapping record bytes",
        plan.build_cache_candidates.len(),
        format_bytes(plan.build_cache_candidate_bytes)
    );
    println!(
        "build cache report-only: {} shared/internal records, {} overlapping bytes",
        plan.build_cache_report_only.len(),
        format_bytes(plan.build_cache_report_only_bytes)
    );
    println!(
        "images: {} unused, {} unique reclaim (report-only)",
        plan.image_candidates.len(),
        format_bytes(plan.image_unique_reclaim_bytes)
    );
    println!(
        "host: {} available at {}",
        format_bytes(plan.host_observation.available_bytes),
        plan.host_observation.observed_at.display()
    );
    if let Some(sparse) = &plan.host_observation.orbstack_sparse_disk {
        println!(
            "OrbStack sparse disk: {} allocated / {} logical at {}",
            format_bytes(sparse.allocated_bytes),
            format_bytes(sparse.logical_bytes),
            sparse.path.display()
        );
    }
    if let Some(outcome) = &run.manifest.outcome {
        println!(
            "realized host reclaim: {}",
            format_bytes(outcome.realized_host_reclaim_bytes)
        );
    }
}

fn discover_docker() -> Result<DockerContext> {
    let executable =
        find_executable(OsStr::new("docker")).context("docker was not found on PATH")?;
    let canonical_executable = executable
        .canonicalize()
        .with_context(|| format!("resolve Docker executable {}", executable.display()))?;
    let client_version =
        command_stdout(&executable, &["version", "--format", "{{.Client.Version}}"])?;
    let buildx_version = command_stdout(&executable, &["buildx", "version"])?;
    let context = command_stdout(&executable, &["context", "show"])?;
    let endpoint = command_stdout(
        &executable,
        &[
            "context",
            "inspect",
            &context,
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
    )?;
    let endpoint: String =
        serde_json::from_str(&endpoint).context("parse Docker context endpoint")?;
    let info: DockerInfo =
        serde_json::from_str(&command_stdout(&executable, &["info", "--format", "json"])?)
            .context("parse Docker server identity")?;
    let builder = current_builder(&executable)?;
    Ok(DockerContext {
        identity: DockerIdentity {
            executable,
            canonical_executable,
            client_version,
            buildx_version,
            context,
            endpoint,
            server_id: info.id,
            server_name: info.name,
            server_version: info.server_version,
            operating_system: info.operating_system,
            docker_root_dir: info.docker_root_dir,
            builder,
        },
    })
}

fn plan_docker(
    identity: &DockerIdentity,
    options: &DockerCollectOptions,
) -> Result<DockerPrunePlan> {
    plan_docker_impl(identity, options, true)
}

fn plan_docker_without_protection(
    identity: &DockerIdentity,
    options: &DockerCollectOptions,
) -> Result<DockerPrunePlan> {
    plan_docker_impl(identity, options, false)
}

fn plan_docker_impl(
    identity: &DockerIdentity,
    options: &DockerCollectOptions,
    enforce_protections: bool,
) -> Result<DockerPrunePlan> {
    // Preserve the discovered executable's argv[0]. Multi-call distributions such as
    // OrbStack select their Docker frontend from that name; invoking the resolved target
    // directly changes its behavior. The canonical path remains part of the identity we
    // revalidate before execution.
    let summaries = docker_summaries(&identity.executable)?;
    let verbose = docker_verbose_usage(&identity.executable)?;
    let buildx = buildx_disk_usage(
        &identity.executable,
        &identity.builder.name,
        options.build_cache_days,
    )?;
    let build_cache_summary = summary(&summaries, "Build Cache")?;
    let image_summary = summary(&summaries, "Images")?;
    let container_summary = summary(&summaries, "Containers")?;

    let exact_build_cache = verbose
        .build_cache
        .into_iter()
        .map(|entry| (entry.id.clone(), entry))
        .collect::<std::collections::HashMap<_, _>>();
    let mut build_cache_candidates = Vec::new();
    let mut build_cache_report_only = Vec::new();
    let mut build_cache_ids = std::collections::HashSet::new();
    for entry in buildx.into_iter().filter(|entry| entry.reclaimable) {
        anyhow::ensure!(
            build_cache_ids.insert(entry.id.clone()),
            "BuildKit disk usage repeated record {}",
            entry.id
        );
        let exact = exact_build_cache.get(&entry.id).with_context(|| {
            format!("BuildKit record {} disappeared from Docker usage", entry.id)
        })?;
        if parse_bool(&exact.in_use, "BuildKit in-use flag")? {
            continue;
        }
        let candidate = DockerBuildCacheCandidate {
            id: entry.id,
            cache_type: entry.r#type,
            created_at: entry.created_at,
            last_used_at: exact.last_used_at.clone(),
            description: entry.description,
            size_bytes: parse_bytes(&entry.size)?,
            shared: entry.shared,
            mutable: entry.mutable,
            usage_count: entry.usage_count,
            parents: entry.parents.unwrap_or_default(),
        };
        if default_prune_can_remove(&candidate) {
            build_cache_candidates.push(candidate);
        } else {
            build_cache_report_only.push(candidate);
        }
    }
    build_cache_candidates.sort_by(|left, right| left.id.cmp(&right.id));
    build_cache_report_only.sort_by(|left, right| left.id.cmp(&right.id));

    let image_candidates = image_candidates(verbose.images)?;

    let active_build_records = exact_build_cache.values().try_fold(0_u64, |count, entry| {
        Ok::<_, anyhow::Error>(
            count + u64::from(parse_bool(&entry.in_use, "BuildKit in-use flag")?),
        )
    })?;
    let active_containers = container_summary.active.parse::<u64>().with_context(|| {
        format!(
            "parse Docker active container count {}",
            container_summary.active
        )
    })?;
    let active_build_processes = active_docker_build_processes()?;
    let (build_cache_candidate_bytes, build_cache_expected_reclaim_bytes) =
        build_cache_measurement(&build_cache_candidates);
    let build_cache_report_only_bytes = build_cache_report_only
        .iter()
        .map(|candidate| candidate.size_bytes)
        .sum();
    let image_unique_reclaim_bytes = image_candidates
        .iter()
        .map(|candidate| candidate.unique_size_bytes)
        .sum();
    let docker_build_cache_reclaimable_bytes = parse_reclaimable(&build_cache_summary.reclaimable)?;
    let docker_image_reclaimable_bytes = parse_reclaimable(&image_summary.reclaimable)?;
    let host_observation = host_observation(identity)?;
    let protection = if enforce_protections {
        let protections = active_protections(options.now)?;
        host_observation
            .domain_storage_path
            .as_deref()
            .and_then(|path| protection_for_path(path, &protections))
    } else {
        None
    };
    let eligibility_digest = docker_digest(&build_cache_candidates);
    let build_cache_selector = if build_cache_candidates.is_empty() {
        None
    } else {
        exact_id_filter(&build_cache_candidates).ok()
    };
    let local_context = identity.endpoint.starts_with("unix://")
        && integrated_local_builder(identity)
        && host_observation.domain_storage_path.is_some();

    let action = if !local_context {
        DockerPruneAction::UnsupportedContext
    } else if protection.is_some() {
        DockerPruneAction::Protected
    } else if active_containers > 0
        || active_build_records > 0
        || !active_build_processes.is_empty()
    {
        DockerPruneAction::InUse
    } else if build_cache_candidates.is_empty() && build_cache_report_only.is_empty() {
        DockerPruneAction::NoWork
    } else if build_cache_candidates.is_empty() || build_cache_selector.is_none() {
        DockerPruneAction::ReportOnly
    } else {
        DockerPruneAction::DelegateBuildCache
    };
    let reason = match action {
        DockerPruneAction::DelegateBuildCache => {
            "BuildKit can prune the stable, idle build-cache candidate set".to_string()
        }
        DockerPruneAction::NoWork => {
            "BuildKit has no build-cache records beyond the configured TTL".to_string()
        }
        DockerPruneAction::ReportOnly => {
            if build_cache_candidates.is_empty() {
                "only shared, internal, or frontend BuildKit records exceed the TTL; default prune leaves them in place"
                    .to_string()
            } else {
                "the exact BuildKit ID selector exceeds the safe command-size bound".to_string()
            }
        }
        DockerPruneAction::InUse => {
            "a Docker container, build record, or local build process is active".to_string()
        }
        DockerPruneAction::Protected => {
            "the Docker host storage domain has an active lease".to_string()
        }
        DockerPruneAction::UnsupportedContext => {
            "the selected Docker context, current Buildx builder, and known host storage path are not one integrated local storage domain; host reclaim cannot be verified".to_string()
        }
    };

    Ok(DockerPrunePlan {
        action,
        reason,
        complete: true,
        eligibility_digest,
        build_cache_selector,
        build_cache_candidates,
        build_cache_report_only,
        image_candidates,
        active_containers,
        active_build_records,
        active_build_processes,
        protection,
        build_cache_candidate_bytes,
        build_cache_expected_reclaim_bytes,
        build_cache_report_only_bytes,
        image_unique_reclaim_bytes,
        docker_build_cache_reclaimable_bytes,
        docker_image_reclaimable_bytes,
        host_observation,
    })
}

fn execute_docker_plan(
    context: &DockerContext,
    options: &DockerCollectOptions,
    manifest: &mut DockerCollectManifest,
) -> Result<()> {
    match manifest.plan.action {
        DockerPruneAction::DelegateBuildCache => {}
        DockerPruneAction::NoWork => return Ok(()),
        _ => bail!(
            "Docker build-cache prune is not executable: {}",
            manifest.plan.reason
        ),
    }
    let lock = acquire_collector_lock()?;
    let guarded_path = manifest
        .plan
        .host_observation
        .domain_storage_path
        .clone()
        .context("Docker plan omitted its host storage path")?;
    let guarded = with_protection_guard(&guarded_path, SystemTime::now(), || {
        execute_docker_plan_guarded(context, options, manifest)
    })?;
    match guarded {
        ProtectionGuardOutcome::Protected(protection) => {
            bail!(
                "Docker host storage became protected by {}: {}",
                protection.id,
                protection.reason
            )
        }
        ProtectionGuardOutcome::Executed(outcome) => manifest.outcome = Some(outcome?),
    }
    drop(lock);

    let outcome = manifest
        .outcome
        .as_ref()
        .context("missing Docker outcome")?;
    anyhow::ensure!(
        outcome.command_succeeded,
        "docker buildx prune failed: {}",
        outcome.stderr.trim()
    );
    anyhow::ensure!(
        outcome.verification_complete && outcome.remaining_build_cache_candidates == Some(0),
        "Docker build-cache prune completed but verification did not prove the eligible records absent: {}",
        outcome.verification_error.as_deref().unwrap_or("eligible records remain")
    );
    Ok(())
}

fn execute_docker_plan_guarded(
    context: &DockerContext,
    options: &DockerCollectOptions,
    manifest: &DockerCollectManifest,
) -> Result<DockerPruneOutcome> {
    let identity = discover_docker()?.identity;
    anyhow::ensure!(
        identity == context.identity,
        "Docker identity changed after planning"
    );
    let mut execution_options = options.clone();
    execution_options.now = SystemTime::now();
    let refreshed = plan_docker_without_protection(&context.identity, &execution_options)?;
    anyhow::ensure!(
        refreshed.action == DockerPruneAction::DelegateBuildCache
            && refreshed.eligibility_digest == manifest.plan.eligibility_digest
            && refreshed.build_cache_candidates == manifest.plan.build_cache_candidates,
        "Docker build-cache eligibility changed after planning; rerun without --execute"
    );

    let host_before = refreshed.host_observation.available_bytes;
    let docker_before = refreshed.docker_build_cache_reclaimable_bytes;
    let args = &manifest.policy.delegated_command;
    anyhow::ensure!(
        !args.is_empty(),
        "Docker manifest omitted its exact prune command"
    );
    let output = command_output(
        &context.identity.executable,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    )?;
    let command_succeeded = output.status.success();
    let original_ids = manifest
        .plan
        .build_cache_candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    let selector = manifest
        .plan
        .build_cache_selector
        .as_deref()
        .context("Docker plan omitted its exact BuildKit selector")?;
    let exact_verification = buildx_disk_usage_with_filter(
        &context.identity.executable,
        &context.identity.builder.name,
        selector,
    )
    .and_then(|records| {
        anyhow::ensure!(
            records
                .iter()
                .all(|record| original_ids.contains(record.id.as_str())),
            "BuildKit exact verification returned an unplanned record"
        );
        Ok(records.len() as u64)
    });
    let summary_verification =
        plan_docker_without_protection(&context.identity, &execution_options);
    let host_after = host_available_bytes(&refreshed.host_observation.observed_at)?;
    let (
        verification_complete,
        verification_error,
        remaining_build_cache_candidates,
        docker_build_cache_reclaimable_after,
    ) = match (exact_verification, summary_verification) {
        (Ok(remaining), Ok(after)) => (
            remaining == 0,
            None,
            Some(remaining),
            Some(after.docker_build_cache_reclaimable_bytes),
        ),
        (exact, summary) => {
            let mut errors = Vec::new();
            let remaining = match exact {
                Ok(remaining) => Some(remaining),
                Err(error) => {
                    errors.push(format!("exact ID verification: {error:#}"));
                    None
                }
            };
            let reclaimable = match summary {
                Ok(after) => Some(after.docker_build_cache_reclaimable_bytes),
                Err(error) => {
                    errors.push(format!("Docker summary verification: {error:#}"));
                    None
                }
            };
            (false, Some(errors.join("; ")), remaining, reclaimable)
        }
    };
    Ok(DockerPruneOutcome {
        command_succeeded,
        exit_code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        host_available_bytes_before: host_before,
        host_available_bytes_after: host_after,
        realized_host_reclaim_bytes: host_after.saturating_sub(host_before),
        docker_build_cache_reclaimable_before: docker_before,
        docker_build_cache_reclaimable_after,
        verification_complete,
        verification_error,
        remaining_build_cache_candidates,
    })
}

fn docker_summaries(executable: &Path) -> Result<Vec<DockerUsageSummary>> {
    command_stdout(executable, &["system", "df", "--format", "json"])?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("parse Docker disk-usage summary"))
        .collect()
}

fn current_builder(executable: &Path) -> Result<DockerBuilderIdentity> {
    parse_current_builder(&command_stdout(
        executable,
        &["buildx", "ls", "--format", "json"],
    )?)
}

fn parse_current_builder(output: &str) -> Result<DockerBuilderIdentity> {
    let builders = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<BuildxBuilder>(line).context("parse Buildx builder identity")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut current = builders.into_iter().filter(|builder| builder.current);
    let builder = current.next().context("Buildx has no current builder")?;
    anyhow::ensure!(
        current.next().is_none(),
        "Buildx reported multiple current builders"
    );
    let mut nodes = builder
        .nodes
        .into_iter()
        .map(|mut node| {
            node.ids.sort();
            DockerBuilderNodeIdentity {
                name: node.name,
                endpoint: node.endpoint,
                worker_ids: node.ids,
                status: node.status,
                version: node.version,
            }
        })
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(DockerBuilderIdentity {
        name: builder.name,
        driver: builder.driver,
        nodes,
    })
}

fn docker_verbose_usage(executable: &Path) -> Result<DockerVerboseUsage> {
    serde_json::from_str(&command_stdout(
        executable,
        &["system", "df", "-v", "--format", "json"],
    )?)
    .context("parse verbose Docker disk usage")
}

fn buildx_disk_usage(executable: &Path, builder: &str, days: u64) -> Result<Vec<BuildxDiskUsage>> {
    let filter = format!("until={}h", days.saturating_mul(HOURS_PER_DAY));
    buildx_disk_usage_with_filter(executable, builder, &filter)
}

fn buildx_disk_usage_with_filter(
    executable: &Path,
    builder: &str,
    filter: &str,
) -> Result<Vec<BuildxDiskUsage>> {
    command_stdout(
        executable,
        &[
            "buildx",
            "du",
            "--builder",
            builder,
            "--filter",
            filter,
            "--format",
            "json",
        ],
    )?
    .lines()
    .filter(|line| !line.trim().is_empty())
    .map(|line| serde_json::from_str(line).context("parse BuildKit disk-usage record"))
    .collect()
}

fn summary<'a>(summaries: &'a [DockerUsageSummary], kind: &str) -> Result<&'a DockerUsageSummary> {
    summaries
        .iter()
        .find(|summary| summary.r#type == kind)
        .with_context(|| format!("Docker disk usage omitted {kind}"))
}

fn parse_bool(value: &str, field: &str) -> Result<bool> {
    value
        .parse::<bool>()
        .with_context(|| format!("parse {field} {value}"))
}

fn parse_bytes(value: &str) -> Result<u64> {
    if value == "N/A" || value.is_empty() {
        return Ok(0);
    }
    parse_size::parse_size(value).with_context(|| format!("parse Docker byte size {value}"))
}

fn parse_reclaimable(value: &str) -> Result<u64> {
    parse_bytes(value.split_whitespace().next().unwrap_or(value))
}

fn image_candidates(images: Vec<DockerVerboseImage>) -> Result<Vec<DockerImageCandidate>> {
    let mut candidates = std::collections::BTreeMap::<String, DockerImageCandidate>::new();
    for image in images {
        let containers = image
            .containers
            .parse::<u64>()
            .with_context(|| format!("parse container count for Docker image {}", image.id))?;
        if containers != 0 {
            continue;
        }
        let reference = DockerImageReference {
            repository: image.repository,
            tag: image.tag,
            digest: image.digest,
        };
        let size_bytes = parse_bytes(&image.size)?;
        let shared_size_bytes = parse_bytes(&image.shared_size)?;
        let unique_size_bytes = parse_bytes(&image.unique_size)?;
        if let Some(candidate) = candidates.get_mut(&image.id) {
            anyhow::ensure!(
                candidate.created_at == image.created_at
                    && candidate.size_bytes == size_bytes
                    && candidate.shared_size_bytes == shared_size_bytes
                    && candidate.unique_size_bytes == unique_size_bytes,
                "Docker reported inconsistent accounting for image {}",
                image.id
            );
            candidate.references.push(reference);
        } else {
            candidates.insert(
                image.id.clone(),
                DockerImageCandidate {
                    id: image.id,
                    references: vec![reference],
                    created_at: image.created_at,
                    size_bytes,
                    shared_size_bytes,
                    unique_size_bytes,
                },
            );
        }
    }
    let mut candidates = candidates.into_values().collect::<Vec<_>>();
    for candidate in &mut candidates {
        candidate.references.sort_by(|left, right| {
            (&left.repository, &left.tag, &left.digest).cmp(&(
                &right.repository,
                &right.tag,
                &right.digest,
            ))
        });
        candidate.references.dedup();
    }
    Ok(candidates)
}

fn default_prune_can_remove(candidate: &DockerBuildCacheCandidate) -> bool {
    !candidate.shared && !matches!(candidate.cache_type.as_str(), "internal" | "frontend")
}

fn build_cache_measurement(candidates: &[DockerBuildCacheCandidate]) -> (u64, Option<u64>) {
    let overlapping_record_bytes = candidates
        .iter()
        .map(|candidate| candidate.size_bytes)
        .sum();
    // BuildKit record sizes overlap through parent relationships and shared
    // snapshots. The CLI does not expose a selected-set physical reclaim
    // estimate, so do not relabel their sum as private or reclaimable bytes.
    (overlapping_record_bytes, None)
}

fn integrated_local_builder(identity: &DockerIdentity) -> bool {
    let [node] = identity.builder.nodes.as_slice() else {
        return false;
    };
    identity.builder.driver == "docker"
        && node.status == "running"
        && node.endpoint == identity.context
        && node.worker_ids.len() == 1
        && node.worker_ids[0] == identity.server_id
}

fn docker_digest(candidates: &[DockerBuildCacheCandidate]) -> String {
    let mut hasher = Sha256::new();
    for candidate in candidates {
        hasher.update(candidate.id.as_bytes());
        hasher.update([0]);
        hasher.update(candidate.size_bytes.to_le_bytes());
        hasher.update([u8::from(candidate.shared), u8::from(candidate.mutable)]);
        hasher.update(candidate.last_used_at.as_bytes());
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn host_observation(identity: &DockerIdentity) -> Result<DockerHostObservation> {
    let orbstack_sparse_disk = if identity.operating_system == "OrbStack" {
        orbstack_sparse_disk().transpose()?
    } else {
        None
    };
    let domain_storage_path = orbstack_sparse_disk
        .as_ref()
        .map(|observation| observation.path.clone())
        .or_else(|| local_docker_root(identity));
    let observed_at = domain_storage_path
        .clone()
        .unwrap_or(PathBuf::from(
            std::env::var_os("HOME").context("HOME is required for Docker host observation")?,
        ))
        .canonicalize()
        .context("resolve Docker host observation path")?;
    let filesystem = filesystem_identity(&observed_at)?;
    let available_bytes = host_available_bytes(&observed_at)?;
    Ok(DockerHostObservation {
        observed_at,
        filesystem,
        available_bytes,
        domain_storage_path,
        orbstack_sparse_disk,
    })
}

fn local_docker_root(identity: &DockerIdentity) -> Option<PathBuf> {
    cfg!(target_os = "linux")
        .then(|| identity.docker_root_dir.canonicalize().ok())
        .flatten()
}

fn orbstack_sparse_disk() -> Option<Result<DockerSparseDiskObservation>> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    let path = home.join("Library/Group Containers/HUAQ24HBR6.dev.orbstack/data/data.img.raw");
    match fs::metadata(&path) {
        Ok(metadata) => Some(Ok(DockerSparseDiskObservation {
            path,
            logical_bytes: metadata.len(),
            allocated_bytes: metadata_allocated_bytes(&metadata),
        })),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => Some(Err(error).context("inspect OrbStack sparse disk")),
    }
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

fn host_available_bytes(path: &Path) -> Result<u64> {
    fs4::available_space(path).with_context(|| format!("read free space at {}", path.display()))
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

fn active_docker_build_processes() -> Result<Vec<String>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,command="])
        .stdin(Stdio::null())
        .output()
        .context("list processes while planning Docker cleanup")?;
    anyhow::ensure!(
        output.status.success(),
        "ps failed while planning Docker cleanup"
    );
    let mut matches = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| {
            let command = line
                .trim_start()
                .split_once(' ')
                .map(|(_, command)| command)
                .unwrap_or("");
            is_docker_build_command(command)
        })
        .take(50)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    matches.sort();
    Ok(matches)
}

fn is_docker_build_command(command: &str) -> bool {
    let words = command.split_whitespace().collect::<Vec<_>>();
    if command_basename(words.first().copied().unwrap_or("")) == "buildctl" {
        return words.iter().skip(1).any(|word| *word == "build");
    }
    if let Some(index) = words
        .iter()
        .position(|word| command_basename(word) == "docker-compose")
    {
        return words[index + 1..]
            .iter()
            .any(|word| matches!(*word, "build" | "--build"));
    }
    let Some(index) = words
        .iter()
        .position(|word| command_basename(word) == "docker")
    else {
        return false;
    };
    words[index + 1..]
        .iter()
        .any(|word| matches!(*word, "build" | "--build" | "builder" | "buildx"))
}

fn command_basename(word: &str) -> &str {
    Path::new(word)
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(word)
}

fn exact_id_filter(candidates: &[DockerBuildCacheCandidate]) -> Result<String> {
    let ids = candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        ids.iter().all(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        }),
        "BuildKit returned an ID outside the exact-selector alphabet"
    );
    let selector = format!("id~=^({})$", ids.join("|"));
    anyhow::ensure!(
        selector.len() <= MAX_DOCKER_SELECTOR_BYTES,
        "BuildKit exact selector is {} bytes, above the {} byte bound",
        selector.len(),
        MAX_DOCKER_SELECTOR_BYTES
    );
    Ok(selector)
}

fn exact_delegated_command(builder: &str, selector: &str) -> Vec<String> {
    vec![
        "buildx".into(),
        "prune".into(),
        "--builder".into(),
        builder.into(),
        "--filter".into(),
        selector.into(),
        "--force".into(),
    ]
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
        .open(directory.join("docker.lock"))?;
    lock.lock().context("lock Docker collector")?;
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

fn write_docker_manifest(manifest: &DockerCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let mode = match manifest.mode {
        CleanupMode::DryRun => "dry-run",
        CleanupMode::Execute => "execute",
    };
    let path = directory.join(format!("{}-docker-{mode}.json", manifest.run_id));
    write_docker_manifest_at(&path, manifest)?;
    Ok(path)
}

fn write_docker_manifest_at(path: &Path, manifest: &DockerCollectManifest) -> Result<()> {
    let mut file = AtomicWriteFile::open(path)
        .with_context(|| format!("open atomic Docker manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Docker manifest {}", path.display()))
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

    fn candidate(id: &str) -> DockerBuildCacheCandidate {
        DockerBuildCacheCandidate {
            id: id.into(),
            cache_type: "regular".into(),
            created_at: "created".into(),
            last_used_at: "used".into(),
            description: "fixture".into(),
            size_bytes: 10,
            shared: false,
            mutable: false,
            usage_count: 1,
            parents: Vec::new(),
        }
    }

    fn local_identity() -> DockerIdentity {
        DockerIdentity {
            executable: "/usr/local/bin/docker".into(),
            canonical_executable: "/opt/docker-tools".into(),
            client_version: "1".into(),
            buildx_version: "buildx-v1".into(),
            context: "local".into(),
            endpoint: "unix:///tmp/docker.sock".into(),
            server_id: "server-id".into(),
            server_name: "docker".into(),
            server_version: "1".into(),
            operating_system: "fixture".into(),
            docker_root_dir: "/var/lib/docker".into(),
            builder: DockerBuilderIdentity {
                name: "local".into(),
                driver: "docker".into(),
                nodes: vec![DockerBuilderNodeIdentity {
                    name: "local".into(),
                    endpoint: "local".into(),
                    worker_ids: vec!["server-id".into()],
                    status: "running".into(),
                    version: "v1".into(),
                }],
            },
        }
    }

    #[test]
    fn docker_process_matching_is_narrow() {
        assert!(is_docker_build_command("docker build ."));
        assert!(is_docker_build_command(
            "/usr/local/bin/docker buildx build ."
        ));
        assert!(is_docker_build_command("docker compose build web"));
        assert!(is_docker_build_command(
            "docker --context orbstack compose up --build"
        ));
        assert!(is_docker_build_command("docker image build ."));
        assert!(is_docker_build_command(
            "docker-compose --profile dev build"
        ));
        assert!(is_docker_build_command(
            "buildctl build --frontend dockerfile.v0"
        ));
        assert!(!is_docker_build_command("worktree-gc collect docker"));
        assert!(!is_docker_build_command("docker system df"));
    }

    #[test]
    fn docker_sizes_and_reclaimable_percentages_parse() -> Result<()> {
        assert_eq!(parse_bytes("3.528GB")?, 3_528_000_000);
        assert_eq!(parse_bytes("38.24kB")?, 38_240);
        assert_eq!(parse_reclaimable("16.63GB (93%)")?, 16_630_000_000);
        assert_eq!(parse_bytes("N/A")?, 0);
        Ok(())
    }

    #[test]
    fn docker_digest_is_deterministic() {
        assert_eq!(
            docker_digest(&[candidate("a"), candidate("b")]),
            docker_digest(&[candidate("a"), candidate("b")])
        );
        assert_ne!(
            docker_digest(&[candidate("a"), candidate("b")]),
            docker_digest(&[candidate("b"), candidate("a")])
        );
    }

    #[test]
    fn exact_selector_names_only_planned_buildkit_ids() -> Result<()> {
        assert_eq!(
            exact_id_filter(&[candidate("abc123"), candidate("def456")])?,
            "id~=^(abc123|def456)$"
        );
        assert!(exact_id_filter(&[candidate("not/safe")]).is_err());
        Ok(())
    }

    #[test]
    fn default_prune_scope_excludes_shared_and_internal_records() {
        let mut private = candidate("private");
        assert!(default_prune_can_remove(&private));

        private.shared = true;
        assert!(!default_prune_can_remove(&private));

        let mut internal = candidate("internal");
        internal.cache_type = "internal".into();
        assert!(!default_prune_can_remove(&internal));

        let mut frontend = candidate("frontend");
        frontend.cache_type = "frontend".into();
        assert!(!default_prune_can_remove(&frontend));
    }

    #[test]
    fn buildkit_record_sizes_are_not_claimed_as_physical_reclaim() {
        let mut first = candidate("first");
        first.size_bytes = 10;
        let mut second = candidate("second");
        second.size_bytes = 20;

        let (overlapping_bytes, expected_reclaim) = build_cache_measurement(&[first, second]);
        assert_eq!(overlapping_bytes, 30);
        assert_eq!(expected_reclaim, None);
    }

    #[test]
    fn execution_requires_the_integrated_local_builder() {
        let mut identity = local_identity();
        assert!(integrated_local_builder(&identity));

        identity.builder.driver = "docker-container".into();
        assert!(!integrated_local_builder(&identity));

        identity = local_identity();
        identity.builder.nodes[0].worker_ids = vec!["other-server".into()];
        assert!(!integrated_local_builder(&identity));
    }

    #[test]
    fn current_builder_preserves_worker_identity() -> Result<()> {
        let builder = parse_current_builder(
            r#"{"Current":true,"Driver":"docker","Name":"local","Nodes":[{"Endpoint":"local","IDs":["server-id"],"Name":"local","Status":"running","Version":"v1"}]}"#,
        )?;
        assert_eq!(builder, local_identity().builder);
        Ok(())
    }

    #[test]
    fn unused_images_are_accounted_once_across_multiple_tags() -> Result<()> {
        let image = |tag: &str| DockerVerboseImage {
            containers: "0".into(),
            created_at: "created".into(),
            digest: format!("digest-{tag}"),
            id: "sha256:same-image".into(),
            repository: "example/image".into(),
            shared_size: "3GB".into(),
            size: "5GB".into(),
            tag: tag.into(),
            unique_size: "2GB".into(),
        };
        let candidates = image_candidates(vec![image("latest"), image("stable")])?;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].unique_size_bytes, 2_000_000_000);
        assert_eq!(candidates[0].references.len(), 2);
        Ok(())
    }
}
