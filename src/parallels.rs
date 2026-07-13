use crate::inventory::{inventory, InventoryMetrics, InventoryOptions};
use crate::protection::{active_protections, protection_for_path, ProtectionMatch};
use crate::{format_bytes, CleanupMode};
use anyhow::{Context, Result};
use atomic_write_file::AtomicWriteFile;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const PARALLELS_MANIFEST_VERSION: u64 = 1;
const SUPPORTED_PARALLELS_VERSION: &str = "26.4.0";
const VM_MEASUREMENT_MAX_ENTRIES: u64 = 200_000;

#[derive(Debug, Clone)]
pub struct ParallelsCollectOptions {
    pub now: SystemTime,
}

impl Default for ParallelsCollectOptions {
    fn default() -> Self {
        Self {
            now: SystemTime::now(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ParallelsCollectRun {
    pub manifest_path: PathBuf,
    pub manifest: ParallelsCollectManifest,
}

#[derive(Debug, Serialize)]
pub struct ParallelsCollectManifest {
    pub manifest_version: u64,
    pub collector: &'static str,
    pub run_id: String,
    pub mode: CleanupMode,
    pub generated_at_unix: u64,
    pub parallels: ParallelsIdentity,
    pub policy: ParallelsPolicy,
    pub plan: ParallelsPlan,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParallelsIdentity {
    pub prlctl: PathBuf,
    pub canonical_prlctl: PathBuf,
    pub disk_tool: PathBuf,
    pub canonical_disk_tool: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParallelsPolicy {
    pub reviewed_version: &'static str,
    pub vm_deletion: &'static str,
    pub disk_compaction: &'static str,
    pub unattended_execution_supported: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParallelsAction {
    ReviewVmStorage,
    NoWork,
    InUse,
    Protected,
    ReportOnly,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParallelsPlan {
    pub action: ParallelsAction,
    pub reason: String,
    pub complete: bool,
    pub version_supported: bool,
    pub vms: Vec<ParallelsVmObservation>,
    pub total_vm_metrics: InventoryMetrics,
    pub estimated_host_reclaim_bytes: u64,
    pub protections: Vec<ProtectionMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParallelsVmObservation {
    pub uuid: String,
    pub name: String,
    pub status: String,
    pub home: PathBuf,
    pub metrics: InventoryMetrics,
    pub disks: Vec<ParallelsDiskObservation>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParallelsDiskObservation {
    pub device: String,
    pub path: PathBuf,
    pub metrics: InventoryMetrics,
    pub virtual_size_bytes: Option<u64>,
    pub compaction: Option<ParallelsCompactionEstimate>,
    pub estimated_host_reclaim_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParallelsCompactionEstimate {
    pub sector_size_bytes: u64,
    pub block_size_sectors: u64,
    pub total_blocks: u64,
    pub allocated_blocks: u64,
    pub used_blocks: u64,
    pub operation_supported: bool,
    pub estimated_reclaim_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct PrlListVm {
    uuid: String,
    status: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct PrlVmInfo {
    #[serde(rename = "ID")]
    uuid: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "State")]
    status: String,
    #[serde(rename = "Home")]
    home: PathBuf,
    #[serde(rename = "Hardware", default)]
    hardware: BTreeMap<String, serde_json::Value>,
}

pub fn collect_parallels(options: ParallelsCollectOptions) -> Result<ParallelsCollectRun> {
    let identity = discover_parallels()?;
    let vms = discover_vms(&identity)?;
    let protections = active_protections(options.now)?;
    let mut plan = build_plan(&identity, vms, &protections);
    classify_plan(&mut plan);
    let run_id = format!("{}-{}", unix_nanos(options.now), std::process::id());
    let manifest = ParallelsCollectManifest {
        manifest_version: PARALLELS_MANIFEST_VERSION,
        collector: "parallels",
        run_id,
        mode: CleanupMode::DryRun,
        generated_at_unix: unix_seconds(options.now),
        parallels: identity,
        policy: ParallelsPolicy {
            reviewed_version: SUPPORTED_PARALLELS_VERSION,
            vm_deletion: "report_only",
            disk_compaction: "manual_owner_tool_only",
            unattended_execution_supported: false,
        },
        plan,
    };
    let manifest_path = write_manifest(&manifest)?;
    Ok(ParallelsCollectRun {
        manifest_path,
        manifest,
    })
}

pub fn print_parallels_collect(run: &ParallelsCollectRun) {
    let plan = &run.manifest.plan;
    println!("collector: parallels");
    println!("mode: DryRun");
    println!("manifest: {}", run.manifest_path.display());
    println!(
        "parallels: {} ({})",
        run.manifest.parallels.version,
        run.manifest.parallels.prlctl.display()
    );
    println!("action: {:?} — {}", plan.action, plan.reason);
    println!(
        "VM storage: {} private | {} allocated; conservative host reclaim {}",
        format_bytes(plan.total_vm_metrics.private_reclaimable_bytes),
        format_bytes(plan.total_vm_metrics.allocated_bytes),
        format_bytes(plan.estimated_host_reclaim_bytes)
    );
    println!("execution: report-only; VM deletion and disk compaction are never automatic");
    for vm in &plan.vms {
        println!(
            "  {} ({}) — {} private | {} allocated | {}",
            vm.name,
            vm.status,
            format_bytes(vm.metrics.private_reclaimable_bytes),
            format_bytes(vm.metrics.allocated_bytes),
            vm.home.display()
        );
        for disk in &vm.disks {
            println!(
                "    {} — {} private | conservative host reclaim {} | {}",
                disk.device,
                format_bytes(disk.metrics.private_reclaimable_bytes),
                format_bytes(disk.estimated_host_reclaim_bytes),
                disk.path.display()
            );
        }
    }
}

fn discover_parallels() -> Result<ParallelsIdentity> {
    let prlctl = find_executable(OsStr::new("prlctl")).context("prlctl was not found on PATH")?;
    let disk_tool = find_executable(OsStr::new("prl_disk_tool"))
        .context("prl_disk_tool was not found on PATH")?;
    let canonical_prlctl = prlctl
        .canonicalize()
        .with_context(|| format!("resolve prlctl executable {}", prlctl.display()))?;
    let canonical_disk_tool = disk_tool
        .canonicalize()
        .with_context(|| format!("resolve prl_disk_tool executable {}", disk_tool.display()))?;
    let version_output = command_output(&prlctl, &["version"])?;
    anyhow::ensure!(
        version_output.status.success(),
        "{} version failed: {}",
        prlctl.display(),
        String::from_utf8_lossy(&version_output.stderr).trim()
    );
    let version_text = output_text(&version_output);
    let version = parse_version(&version_text)
        .with_context(|| format!("parse Parallels version from {version_text:?}"))?;
    Ok(ParallelsIdentity {
        prlctl,
        canonical_prlctl,
        disk_tool,
        canonical_disk_tool,
        version,
    })
}

fn discover_vms(identity: &ParallelsIdentity) -> Result<Vec<ParallelsVmObservation>> {
    let output = command_output(&identity.prlctl, &["list", "--all", "--json"])?;
    anyhow::ensure!(
        output.status.success(),
        "{} list failed: {}",
        identity.prlctl.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut listed: Vec<PrlListVm> =
        serde_json::from_slice(&output.stdout).context("parse Parallels VM list")?;
    listed.sort_by(|left, right| left.uuid.cmp(&right.uuid));
    listed
        .into_iter()
        .map(|listed_vm| observe_vm(identity, listed_vm))
        .collect()
}

fn observe_vm(identity: &ParallelsIdentity, listed: PrlListVm) -> Result<ParallelsVmObservation> {
    let output = command_output(
        &identity.prlctl,
        &["list", "--info", "--json", &listed.uuid],
    )?;
    anyhow::ensure!(
        output.status.success(),
        "{} info failed for {}: {}",
        identity.prlctl.display(),
        listed.uuid,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let mut infos: Vec<PrlVmInfo> =
        serde_json::from_slice(&output.stdout).context("parse Parallels VM info")?;
    anyhow::ensure!(infos.len() == 1, "Parallels returned multiple VM info rows");
    let info = infos.pop().expect("one VM info row was checked");
    anyhow::ensure!(
        info.uuid == listed.uuid && info.name == listed.name && info.status == listed.status,
        "Parallels VM list and info identity differ for {}",
        listed.uuid
    );
    let home = info
        .home
        .canonicalize()
        .with_context(|| format!("resolve Parallels VM home {}", info.home.display()))?;
    let (metrics, mut errors) = measure_path(&home, VM_MEASUREMENT_MAX_ENTRIES);
    let mut disks = info
        .hardware
        .iter()
        .filter(|(device, value)| device.starts_with("hdd") && hardware_enabled(value))
        .filter_map(|(device, value)| {
            value
                .get("image")
                .and_then(serde_json::Value::as_str)
                .filter(|path| !path.is_empty())
                .map(|path| (device.clone(), PathBuf::from(path), hardware_size(value)))
        })
        .map(|(device, path, virtual_size_bytes)| {
            observe_disk(identity, device, path, virtual_size_bytes)
        })
        .collect::<Vec<_>>();
    disks.sort_by(|left, right| left.device.cmp(&right.device));
    for disk in &disks {
        if let Some(error) = &disk.error {
            errors.push(format!("{}: {error}", disk.path.display()));
        }
    }
    Ok(ParallelsVmObservation {
        uuid: info.uuid,
        name: info.name,
        status: info.status,
        home,
        metrics,
        disks,
        errors,
    })
}

fn observe_disk(
    identity: &ParallelsIdentity,
    device: String,
    path: PathBuf,
    virtual_size_bytes: Option<u64>,
) -> ParallelsDiskObservation {
    let canonical = match path.canonicalize() {
        Ok(path) => path,
        Err(error) => {
            return ParallelsDiskObservation {
                device,
                path,
                metrics: incomplete_metrics(),
                virtual_size_bytes,
                compaction: None,
                estimated_host_reclaim_bytes: 0,
                error: Some(format!("resolve disk: {error}")),
            };
        }
    };
    let (metrics, measurement_errors) = measure_path(&canonical, VM_MEASUREMENT_MAX_ENTRIES);
    let error = (!measurement_errors.is_empty()).then(|| measurement_errors.join("; "));
    let output = command_output(
        &identity.disk_tool,
        &[
            "compact",
            "--info",
            "--hdd",
            canonical.to_string_lossy().as_ref(),
            "--details",
        ],
    );
    let (compaction, compact_error) = match output {
        Ok(output) if output.status.success() => match parse_compaction(&output_text(&output)) {
            Ok(compaction) => match validate_virtual_capacity(&compaction, virtual_size_bytes) {
                Ok(()) => (Some(compaction), None),
                Err(error) => (
                    None,
                    Some(format!("validate compaction geometry: {error:#}")),
                ),
            },
            Err(error) => (None, Some(format!("parse compaction estimate: {error:#}"))),
        },
        Ok(output) => (
            None,
            Some(format!(
                "compaction estimate failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )),
        ),
        Err(error) => (None, Some(format!("run compaction estimate: {error:#}"))),
    };
    let estimated_host_reclaim_bytes = conservative_host_reclaim(&metrics, compaction.as_ref());
    ParallelsDiskObservation {
        device,
        path: canonical,
        metrics,
        virtual_size_bytes,
        compaction,
        estimated_host_reclaim_bytes,
        error: error.or(compact_error),
    }
}

fn build_plan(
    identity: &ParallelsIdentity,
    vms: Vec<ParallelsVmObservation>,
    protections: &[crate::ProtectionLease],
) -> ParallelsPlan {
    let mut matches = vms
        .iter()
        .flat_map(|vm| std::iter::once(&vm.home).chain(vm.disks.iter().map(|disk| &disk.path)))
        .filter_map(|path| protection_for_path(path, protections))
        .collect::<Vec<_>>();
    matches.sort_by(|left, right| left.id.cmp(&right.id));
    matches.dedup_by(|left, right| left.id == right.id);
    let total_vm_metrics = vms.iter().fold(
        InventoryMetrics {
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        },
        |mut total, vm| {
            add_metrics(&mut total, &vm.metrics);
            for disk in &vm.disks {
                if !disk.path.starts_with(&vm.home) {
                    add_metrics(&mut total, &disk.metrics);
                }
            }
            total
        },
    );
    let estimated_host_reclaim_bytes = vms
        .iter()
        .flat_map(|vm| &vm.disks)
        .fold(0u64, |total, disk| {
            total.saturating_add(disk.estimated_host_reclaim_bytes)
        });
    let complete = total_vm_metrics.private_reclaimable_complete
        && vms.iter().all(|vm| vm.errors.is_empty())
        && vms
            .iter()
            .flat_map(|vm| &vm.disks)
            .all(|disk| disk.error.is_none());
    ParallelsPlan {
        action: ParallelsAction::ReportOnly,
        reason: String::new(),
        complete,
        version_supported: identity.version == SUPPORTED_PARALLELS_VERSION,
        vms,
        total_vm_metrics,
        estimated_host_reclaim_bytes,
        protections: matches,
    }
}

fn classify_plan(plan: &mut ParallelsPlan) {
    let (action, reason) = if !cfg!(target_os = "macos") {
        (
            ParallelsAction::UnsupportedPlatform,
            "Parallels Desktop storage inspection is currently macOS-only".to_string(),
        )
    } else if !plan.version_supported {
        (
            ParallelsAction::ReportOnly,
            format!(
                "collector parsing was reviewed for Parallels {SUPPORTED_PARALLELS_VERSION}; installed version differs"
            ),
        )
    } else if !plan.complete {
        (
            ParallelsAction::ReportOnly,
            "VM discovery, APFS measurement, or owner compaction estimates were incomplete"
                .to_string(),
        )
    } else if !plan.protections.is_empty() {
        (
            ParallelsAction::Protected,
            "one or more VM homes has an active protection lease".to_string(),
        )
    } else if plan.vms.is_empty() {
        (
            ParallelsAction::NoWork,
            "Parallels has no registered virtual machines".to_string(),
        )
    } else if plan
        .vms
        .iter()
        .any(|vm| !vm.status.eq_ignore_ascii_case("stopped"))
    {
        (
            ParallelsAction::InUse,
            "a VM is running, paused, or suspended; storage remains report-only".to_string(),
        )
    } else {
        (
            ParallelsAction::ReviewVmStorage,
            "VM retention and optional owner-tool compaction require human review".to_string(),
        )
    };
    plan.action = action;
    plan.reason = reason;
}

fn measure_path(path: &Path, max_entries: u64) -> (InventoryMetrics, Vec<String>) {
    match inventory(
        std::slice::from_ref(&path.to_path_buf()),
        InventoryOptions {
            display_depth: 0,
            top: 1,
            max_entries,
            one_filesystem: true,
        },
    ) {
        Ok(report) => {
            let root = report.roots.into_iter().next().expect("one inventory root");
            let mut errors = root
                .errors
                .into_iter()
                .map(|error| format!("{}: {}", error.path.display(), error.message))
                .collect::<Vec<_>>();
            if !root.complete {
                errors.push(format!(
                    "measurement exceeded the {max_entries}-entry bound"
                ));
            }
            (root.metrics, errors)
        }
        Err(error) => (
            incomplete_metrics(),
            vec![format!("measure path: {error:#}")],
        ),
    }
}

fn incomplete_metrics() -> InventoryMetrics {
    InventoryMetrics {
        private_reclaimable_complete: false,
        ..InventoryMetrics::default()
    }
}

fn conservative_host_reclaim(
    metrics: &InventoryMetrics,
    compaction: Option<&ParallelsCompactionEstimate>,
) -> u64 {
    compaction
        .filter(|estimate| estimate.operation_supported)
        .map(|estimate| {
            estimate
                .estimated_reclaim_bytes
                .min(metrics.private_reclaimable_bytes)
        })
        .unwrap_or(0)
}

fn parse_compaction(output: &str) -> Result<ParallelsCompactionEstimate> {
    let sector_size_bytes = numeric_field(output, "Sector size")?;
    let block_size_sectors = numeric_field(output, "Block size")?;
    let total_blocks = numeric_field(output, "Total blocks")?;
    let allocated_blocks = numeric_field(output, "Allocated blocks")?;
    let used_blocks = numeric_field(output, "Used blocks")?;
    let operation_supported =
        text_field(output, "Operation supported")?.eq_ignore_ascii_case("yes");
    let bytes_per_block = sector_size_bytes
        .checked_mul(block_size_sectors)
        .context("Parallels block geometry overflow")?;
    let estimated_reclaim_bytes = allocated_blocks
        .saturating_sub(used_blocks)
        .checked_mul(bytes_per_block)
        .context("Parallels compaction estimate overflow")?;
    Ok(ParallelsCompactionEstimate {
        sector_size_bytes,
        block_size_sectors,
        total_blocks,
        allocated_blocks,
        used_blocks,
        operation_supported,
        estimated_reclaim_bytes,
    })
}

fn validate_virtual_capacity(
    estimate: &ParallelsCompactionEstimate,
    virtual_size_bytes: Option<u64>,
) -> Result<()> {
    let Some(expected) = virtual_size_bytes else {
        return Ok(());
    };
    let observed = estimate
        .total_blocks
        .checked_mul(estimate.block_size_sectors)
        .and_then(|blocks| blocks.checked_mul(estimate.sector_size_bytes))
        .context("Parallels virtual capacity overflow")?;
    anyhow::ensure!(
        observed == expected,
        "Parallels disk geometry reports {observed} bytes but VM hardware reports {expected} bytes"
    );
    Ok(())
}

fn numeric_field(output: &str, name: &str) -> Result<u64> {
    text_field(output, name)?
        .parse()
        .with_context(|| format!("parse Parallels {name}"))
}

fn text_field<'a>(output: &'a str, name: &str) -> Result<&'a str> {
    output
        .lines()
        .map(str::trim)
        .find_map(|line| {
            line.strip_prefix(name)
                .and_then(|value| value.trim_start().strip_prefix(':'))
                .map(str::trim)
        })
        .with_context(|| format!("Parallels output omitted {name:?}"))
}

fn parse_version(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|part| {
            part.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_digit())
                && part.contains('.')
        })
        .map(ToOwned::to_owned)
}

fn hardware_enabled(value: &serde_json::Value) -> bool {
    value
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

fn hardware_size(value: &serde_json::Value) -> Option<u64> {
    let size = value.get("size")?.as_str()?;
    let mebibytes: u64 = size.strip_suffix("Mb")?.parse().ok()?;
    mebibytes.checked_mul(1024 * 1024)
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

fn command_output(executable: &Path, args: &[&str]) -> Result<Output> {
    Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("run {} {}", executable.display(), args.join(" ")))
}

fn output_text(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.trim().is_empty() {
        stderr.trim().to_string()
    } else if stderr.trim().is_empty() {
        stdout.trim().to_string()
    } else {
        format!("{stdout}\n{stderr}")
    }
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

fn write_manifest(manifest: &ParallelsCollectManifest) -> Result<PathBuf> {
    let directory = state_directory()?.join("collectors");
    fs::create_dir_all(&directory)?;
    let path = directory.join(format!("{}-parallels-dry-run.json", manifest.run_id));
    let mut file = AtomicWriteFile::open(&path)
        .with_context(|| format!("open atomic Parallels manifest {}", path.display()))?;
    file.write_all(&serde_json::to_vec_pretty(manifest)?)?;
    file.commit()
        .with_context(|| format!("commit Parallels manifest {}", path.display()))?;
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

    #[test]
    fn parses_owner_compaction_geometry_into_bytes() {
        let output = r#"
Disk information:
        Sector size:                  512
        Block size:                  2048
        Total blocks:              262144
        Allocated blocks:          178596
        Used blocks:               177405
        Operation supported:          YES
"#;
        let estimate = parse_compaction(output).unwrap();
        assert_eq!(estimate.estimated_reclaim_bytes, 1_248_854_016);
        assert!(estimate.operation_supported);
    }

    #[test]
    fn parses_reviewed_parallels_version() {
        assert_eq!(
            parse_version("prlctl version 26.4.0 (57513)"),
            Some("26.4.0".to_string())
        );
    }

    #[test]
    fn parses_hardware_size_in_megabytes() {
        let value = serde_json::json!({"enabled": true, "size": "262144Mb"});
        assert!(hardware_enabled(&value));
        assert_eq!(hardware_size(&value), Some(274_877_906_944));
    }

    #[test]
    fn host_reclaim_is_capped_by_apfs_private_bytes() {
        let metrics = InventoryMetrics {
            private_reclaimable_bytes: 100,
            private_reclaimable_complete: true,
            ..InventoryMetrics::default()
        };
        let estimate = ParallelsCompactionEstimate {
            sector_size_bytes: 512,
            block_size_sectors: 2048,
            total_blocks: 100,
            allocated_blocks: 10,
            used_blocks: 0,
            operation_supported: true,
            estimated_reclaim_bytes: 10 * 1024 * 1024,
        };
        assert_eq!(conservative_host_reclaim(&metrics, Some(&estimate)), 100);
    }

    #[test]
    fn compaction_geometry_must_match_vm_virtual_capacity() {
        let estimate = ParallelsCompactionEstimate {
            sector_size_bytes: 512,
            block_size_sectors: 2048,
            total_blocks: 262_144,
            allocated_blocks: 178_596,
            used_blocks: 177_405,
            operation_supported: true,
            estimated_reclaim_bytes: 1_248_854_016,
        };
        validate_virtual_capacity(&estimate, Some(256 * 1024 * 1024 * 1024)).unwrap();
        assert!(validate_virtual_capacity(&estimate, Some(1)).is_err());
    }

    #[test]
    fn external_disk_metrics_are_added_without_double_counting_bundled_disks() {
        let identity = identity();
        let mut vm = vm("stopped");
        vm.home = PathBuf::from("/vm");
        vm.metrics = metrics(100);
        vm.disks = vec![disk("/vm/bundled.hdd", 80), disk("/external/disk.hdd", 50)];
        let plan = build_plan(&identity, vec![vm], &[]);
        assert_eq!(plan.total_vm_metrics.private_reclaimable_bytes, 150);
    }

    #[test]
    fn suspended_vms_remain_in_use_even_with_a_compaction_estimate() {
        let mut plan = plan("suspended");
        classify_plan(&mut plan);
        assert_eq!(plan.action, ParallelsAction::InUse);
    }

    #[test]
    fn stopped_vms_are_human_review_only() {
        let mut plan = plan("stopped");
        classify_plan(&mut plan);
        assert_eq!(plan.action, ParallelsAction::ReviewVmStorage);
    }

    fn plan(status: &str) -> ParallelsPlan {
        ParallelsPlan {
            action: ParallelsAction::ReportOnly,
            reason: String::new(),
            complete: true,
            version_supported: true,
            vms: vec![vm(status)],
            total_vm_metrics: InventoryMetrics {
                private_reclaimable_complete: true,
                ..InventoryMetrics::default()
            },
            estimated_host_reclaim_bytes: 0,
            protections: Vec::new(),
        }
    }

    fn identity() -> ParallelsIdentity {
        ParallelsIdentity {
            prlctl: PathBuf::from("/prlctl"),
            canonical_prlctl: PathBuf::from("/prlctl"),
            disk_tool: PathBuf::from("/prl_disk_tool"),
            canonical_disk_tool: PathBuf::from("/prl_disk_tool"),
            version: SUPPORTED_PARALLELS_VERSION.into(),
        }
    }

    fn vm(status: &str) -> ParallelsVmObservation {
        ParallelsVmObservation {
            uuid: "uuid".into(),
            name: "vm".into(),
            status: status.into(),
            home: PathBuf::from("/vm"),
            metrics: metrics(0),
            disks: Vec::new(),
            errors: Vec::new(),
        }
    }

    fn disk(path: &str, private: u64) -> ParallelsDiskObservation {
        ParallelsDiskObservation {
            device: "hdd0".into(),
            path: PathBuf::from(path),
            metrics: metrics(private),
            virtual_size_bytes: None,
            compaction: None,
            estimated_host_reclaim_bytes: 0,
            error: None,
        }
    }

    fn metrics(private: u64) -> InventoryMetrics {
        InventoryMetrics {
            logical_bytes: private,
            allocated_bytes: private,
            private_reclaimable_bytes: private,
            private_reclaimable_complete: true,
            files: 1,
            directories: 0,
            hardlink_duplicates: 0,
            errors: 0,
        }
    }
}
