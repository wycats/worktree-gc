use crate::inventory::inventory_with_root_limit;
use crate::{
    InventoryMetrics, InventoryOptions, InventoryReport, InventoryReportOptions, INVENTORY_VERSION,
};
use anyhow::{ensure, Context, Result};
use percent_encoding::percent_decode_str;
#[cfg(test)]
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(test)]
const FILE_URI_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'`')
    .add(b'{')
    .add(b'}');

const GATEWAY_SCHEMA_VERSION: &str = "vercel-ai-gateway/storage-inventory/v1";
const GATEWAY_CONNECTOR_VERSION: u64 = 1;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_MANIFEST_DIRS: usize = 16;
const MAX_DIRECTORY_ENTRIES: usize = 1_024;
const MAX_MANIFESTS: usize = 1_024;
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TOTAL_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INVENTORY_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ROOTS_PER_MANIFEST: usize = 4_096;
const MAX_UNITS_PER_MANIFEST: usize = 4_096;
const MAX_TOTAL_ROOTS: usize = 16_384;
const MAX_TOTAL_UNITS: usize = 65_536;

pub const DEFAULT_GATEWAY_EXACT_MAX_ENTRIES: u64 = 2_000_000;
pub const DEFAULT_GATEWAY_EXACT_MAX_ENTRIES_PER_UNIT: u64 = 250_000;

#[derive(Debug, Clone)]
pub struct GatewayStorageOptions {
    pub inventory_manifest: PathBuf,
    pub gateway_manifests: Vec<PathBuf>,
    pub gateway_manifest_dirs: Vec<PathBuf>,
    pub exact_max_entries: u64,
    pub exact_max_entries_per_unit: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayStorageInventoryV1 {
    pub schema_version: String,
    pub report_id: String,
    pub generated_at: String,
    pub roots: Vec<GatewayRoot>,
    pub units: Vec<GatewayUnit>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayRoot {
    pub root_id: String,
    pub product: GatewayProduct,
    pub local_root_uri: String,
    pub enumeration_completeness: GatewayCompleteness,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayUnit {
    pub domain: GatewayDomain,
    pub classification: GatewayClassification,
    pub owner: GatewayOwner,
    pub activity: GatewayActivity,
    pub protection: GatewayProtection,
    pub metrics: GatewayMetrics,
    pub eligibility: GatewayEligibility,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayOwner {
    pub root_id: String,
    pub store_id: String,
    pub store_id_basis: GatewayStoreIdBasis,
    pub local_unit_uri: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayActivity {
    pub state: GatewayActivityState,
    pub evidence_completeness: GatewayCompleteness,
    pub evidence: Vec<String>,
    pub closed_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayProtection {
    pub pin: GatewayPinState,
    pub export: GatewayExportState,
    pub export_evidence_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayMetrics {
    pub logical: GatewayMetric,
    pub allocated: GatewayMetric,
    pub private: GatewayMetric,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayMetric {
    pub bytes: Option<u64>,
    pub basis: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayEligibility {
    pub authority: String,
    pub state: GatewayEligibilityState,
    pub reason_codes: Vec<String>,
    pub dry_run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayProduct {
    Code,
    CodeInsiders,
    Shared,
    Other,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayCompleteness {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayDomain {
    WorkspacePglite,
    InvestigationLogs,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayClassification {
    CanonicalDurable,
    Diagnostic,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayStoreIdBasis {
    WorkspaceId,
    InvestigationId,
    LegacyRoot,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayActivityState {
    Active,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayPinState {
    Present,
    Absent,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayExportState {
    Pending,
    Completed,
    None,
    Unknown,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayEligibilityState {
    ReportCandidate,
    Ineligible,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayStorageReport {
    pub connector_version: u64,
    pub mode: String,
    pub generated_at_unix: u64,
    pub inventory: GatewayInventorySource,
    pub manifests: Vec<GatewayManifestEvidence>,
    pub duplicate_roots: Vec<GatewayDuplicateRootGroup>,
    pub physical_overlaps: Vec<GatewayPhysicalOverlapGroup>,
    pub exact_measurement: Option<GatewayExactMeasurementSummary>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayInventorySource {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
    pub inventory_version: u64,
    pub generated_at_unix: u64,
    pub root_count: usize,
    pub options: InventoryReportOptions,
    pub roots: Vec<GatewayBroadInventoryRoot>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayBroadInventoryRoot {
    pub path: PathBuf,
    pub filesystem: String,
    pub traversal_complete: bool,
    pub private_measurement_complete: bool,
    pub visited_entries: u64,
    pub scan_error_count: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayManifestEvidence {
    pub source: GatewayManifestSource,
    pub owner_report: GatewayStorageInventoryV1,
    pub roots: Vec<GatewayRootResolution>,
    pub units: Vec<GatewayUnitEvidence>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayManifestSource {
    pub path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayRootResolution {
    pub root_id: String,
    pub product: GatewayProduct,
    pub canonical_path: Option<PathBuf>,
    pub state: GatewayResolutionState,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayUnitEvidence {
    pub root_id: String,
    pub store_id: String,
    pub domain: GatewayDomain,
    pub canonical_path: Option<PathBuf>,
    pub containment: GatewayContainment,
    pub selected_measurement_source: GatewayMeasurementSource,
    pub broad_measurement: Option<GatewayFilesystemMeasurement>,
    pub exact_measurement: Option<GatewayFilesystemMeasurement>,
    pub unavailable_reason: Option<String>,
    /// Display-only age derived from the immutable owner snapshot and elapsed
    /// time; the source value remains unchanged in owner_report.
    pub derived_closed_age_ms: Option<u64>,
    pub derived_closed_age_basis: Option<String>,
    pub additive: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayResolutionState {
    Validated,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayContainment {
    CanonicallyContained,
    Unavailable,
    IdentityConflict,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayFilesystemMeasurement {
    pub source: GatewayMeasurementSource,
    pub inventory_generated_at_unix: u64,
    pub filesystem: String,
    pub traversal_complete: bool,
    pub private_measurement_complete: bool,
    pub visited_entries: Option<u64>,
    pub scan_error_count: u64,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayMeasurementSource {
    Unavailable,
    InventoryManifestExact,
    ExactUnitSubpass,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayDuplicateRootGroup {
    pub root_id: String,
    pub relation: GatewayDuplicateRootRelation,
    pub additive: bool,
    pub observations: Vec<GatewayDuplicateRootObservation>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayDuplicateRootRelation {
    SameCanonicalRoot,
    IdentityConflict,
    Unavailable,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayDuplicateRootObservation {
    pub manifest_path: PathBuf,
    pub report_id: String,
    pub product: GatewayProduct,
    pub local_root_uri: String,
    pub canonical_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayPhysicalOverlapGroup {
    pub canonical_path: PathBuf,
    pub additive: bool,
    pub observations: Vec<GatewayDuplicateRootObservation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GatewayExactMeasurementSummary {
    pub generated_at_unix: u64,
    pub requested_unique_paths: usize,
    pub visited_entries: u64,
    pub complete_roots: usize,
    pub root_count: usize,
    pub max_entries: u64,
    pub max_entries_per_unit: u64,
    pub one_filesystem: bool,
}

struct ParsedManifest {
    source: GatewayManifestSource,
    report: GatewayStorageInventoryV1,
    roots: Vec<GatewayRootResolution>,
    units: Vec<GatewayUnitEvidence>,
}

#[derive(Debug, Clone)]
struct DirectorySnapshot {
    canonical_dir: PathBuf,
    files: Vec<ManifestFileSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestFileSnapshot {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    created: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

pub fn gateway_storage_report(options: GatewayStorageOptions) -> Result<GatewayStorageReport> {
    let connector_generated_at_ms = now_unix_millis();
    ensure!(
        options.exact_max_entries > 0,
        "exact max entries must be positive"
    );
    ensure!(
        options.exact_max_entries_per_unit > 0,
        "exact max entries per unit must be positive"
    );
    ensure!(
        !options.gateway_manifests.is_empty() || !options.gateway_manifest_dirs.is_empty(),
        "pass at least one --gateway-manifest or --gateway-manifest-dir"
    );

    let inventory_path = canonical_regular_file(&options.inventory_manifest, "inventory manifest")?;
    let inventory_bytes = read_bounded_file(&inventory_path, MAX_INVENTORY_MANIFEST_BYTES)?;
    let inventory: InventoryReport = serde_json::from_slice(&inventory_bytes)
        .with_context(|| format!("parse inventory manifest {}", inventory_path.display()))?;
    ensure!(
        inventory.inventory_version == INVENTORY_VERSION,
        "unsupported inventory version {} (expected {INVENTORY_VERSION})",
        inventory.inventory_version
    );
    let inventory_measurements = inventory
        .options
        .one_filesystem
        .then(|| index_inventory_measurements(&inventory));

    let (manifest_paths, snapshots) = discover_manifest_paths(
        &options.gateway_manifests,
        &options.gateway_manifest_dirs,
        MAX_DIRECTORY_ENTRIES,
    )?;
    let mut total_bytes = 0_u64;
    let mut total_roots = 0_usize;
    let mut total_units = 0_usize;
    let mut manifests = Vec::with_capacity(manifest_paths.len());
    for path in manifest_paths {
        let bytes = read_bounded_file(&path, MAX_MANIFEST_BYTES)?;
        total_bytes = total_bytes
            .checked_add(bytes.len() as u64)
            .context("gateway manifest byte total overflow")?;
        ensure!(
            total_bytes <= MAX_TOTAL_MANIFEST_BYTES,
            "gateway manifests exceed the {MAX_TOTAL_MANIFEST_BYTES}-byte total limit"
        );
        let raw_report: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse gateway manifest {}", path.display()))?;
        validate_required_nullable_fields(&raw_report)
            .with_context(|| format!("validate required fields in {}", path.display()))?;
        let report: GatewayStorageInventoryV1 = serde_json::from_value(raw_report)
            .with_context(|| format!("decode gateway manifest {}", path.display()))?;
        validate_owner_report(&report)
            .with_context(|| format!("validate gateway manifest {}", path.display()))?;
        total_roots = total_roots
            .checked_add(report.roots.len())
            .context("gateway root total overflow")?;
        total_units = total_units
            .checked_add(report.units.len())
            .context("gateway unit total overflow")?;
        ensure!(
            total_roots <= MAX_TOTAL_ROOTS,
            "gateway manifests exceed the {MAX_TOTAL_ROOTS}-root total limit"
        );
        ensure!(
            total_units <= MAX_TOTAL_UNITS,
            "gateway manifests exceed the {MAX_TOTAL_UNITS}-unit total limit"
        );
        let (roots, units) = resolve_owner_paths(&report, connector_generated_at_ms)
            .with_context(|| format!("resolve gateway paths from {}", path.display()))?;
        manifests.push(ParsedManifest {
            source: GatewayManifestSource {
                path,
                sha256: hex_sha256(&bytes),
                bytes: bytes.len() as u64,
            },
            report,
            roots,
            units,
        });
    }
    verify_directory_snapshots(&snapshots, MAX_DIRECTORY_ENTRIES)?;

    let (duplicate_roots, physical_overlaps, identity_conflicts) =
        classify_root_relationships(&manifests);
    for (manifest_index, root_id) in &identity_conflicts {
        for unit in manifests[*manifest_index]
            .units
            .iter_mut()
            .filter(|unit| &unit.root_id == root_id)
        {
            unit.containment = GatewayContainment::IdentityConflict;
            unit.canonical_path = None;
            unit.selected_measurement_source = GatewayMeasurementSource::Unavailable;
            unit.broad_measurement = None;
            unit.exact_measurement = None;
            unit.unavailable_reason =
                Some("root identity observations disagree across owner reports".to_string());
        }
    }

    let mut subpass_paths = BTreeSet::new();
    for manifest in &mut manifests {
        for unit in &mut manifest.units {
            let Some(path) = unit.canonical_path.as_ref() else {
                continue;
            };
            if let Some(measurement) = inventory_measurements
                .as_ref()
                .and_then(|measurements| measurements.get(path))
            {
                unit.broad_measurement = Some(measurement.clone());
                if measurement.traversal_complete && measurement.private_measurement_complete {
                    unit.selected_measurement_source =
                        GatewayMeasurementSource::InventoryManifestExact;
                    continue;
                }
            }
            subpass_paths.insert(path.clone());
        }
    }

    let exact_report = if subpass_paths.is_empty() {
        None
    } else {
        Some(inventory_units_tolerating_disappearance(
            &subpass_paths.iter().cloned().collect::<Vec<_>>(),
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: options.exact_max_entries,
                one_filesystem: true,
            },
            options.exact_max_entries_per_unit,
        )?)
    };

    if let Some(exact) = exact_report.as_ref() {
        let exact_measurements = index_inventory_measurements(exact);
        for manifest in &mut manifests {
            for unit in &mut manifest.units {
                if unit.broad_measurement.as_ref().is_some_and(|measurement| {
                    measurement.traversal_complete && measurement.private_measurement_complete
                }) {
                    continue;
                }
                if let Some(path) = unit.canonical_path.as_ref() {
                    unit.exact_measurement =
                        exact_measurements.get(path).cloned().map(|mut value| {
                            value.source = GatewayMeasurementSource::ExactUnitSubpass;
                            value
                        });
                    if unit.exact_measurement.is_some() {
                        unit.selected_measurement_source =
                            GatewayMeasurementSource::ExactUnitSubpass;
                    } else {
                        unit.unavailable_reason = Some(
                            "the bounded exact-path inventory did not retain this unit".to_string(),
                        );
                    }
                }
            }
        }
    }

    let exact_measurement = exact_report
        .as_ref()
        .map(|report| GatewayExactMeasurementSummary {
            generated_at_unix: report.generated_at_unix,
            requested_unique_paths: subpass_paths.len(),
            visited_entries: report.roots.iter().map(|root| root.visited_entries).sum(),
            complete_roots: report
                .roots
                .iter()
                .filter(|root| root.complete && root.errors.is_empty())
                .count(),
            root_count: report.roots.len(),
            max_entries: options.exact_max_entries,
            max_entries_per_unit: options.exact_max_entries_per_unit,
            one_filesystem: true,
        });

    let mut warnings = Vec::new();
    if !duplicate_roots.is_empty() {
        warnings.push(
            "duplicate rootId observations are preserved independently and are never additive"
                .to_string(),
        );
    }
    if !identity_conflicts.is_empty() {
        warnings.push(
            "APFS correlation is suppressed where owner root identity observations disagree"
                .to_string(),
        );
    }
    if !physical_overlaps.is_empty() {
        warnings.push(
            "different owner root IDs resolve to shared physical roots; their measurements are non-additive"
                .to_string(),
        );
    }

    Ok(GatewayStorageReport {
        connector_version: GATEWAY_CONNECTOR_VERSION,
        mode: "report-only".to_string(),
        generated_at_unix: connector_generated_at_ms / 1_000,
        inventory: GatewayInventorySource {
            path: inventory_path,
            sha256: hex_sha256(&inventory_bytes),
            bytes: inventory_bytes.len() as u64,
            inventory_version: inventory.inventory_version,
            generated_at_unix: inventory.generated_at_unix,
            root_count: inventory.roots.len(),
            options: inventory.options.clone(),
            roots: inventory
                .roots
                .iter()
                .map(|root| GatewayBroadInventoryRoot {
                    path: root.path.clone(),
                    filesystem: root.filesystem.clone(),
                    traversal_complete: root.complete && root.errors.is_empty(),
                    private_measurement_complete: root.metrics.private_reclaimable_complete,
                    visited_entries: root.visited_entries,
                    scan_error_count: root.metrics.errors,
                })
                .collect(),
        },
        manifests: manifests
            .into_iter()
            .map(|manifest| GatewayManifestEvidence {
                source: manifest.source,
                owner_report: manifest.report,
                roots: manifest.roots,
                units: manifest.units,
            })
            .collect(),
        duplicate_roots,
        physical_overlaps,
        exact_measurement,
        warnings,
    })
}

pub fn print_gateway_storage_report(report: &GatewayStorageReport) {
    println!(
        "Gateway storage report (report-only): {} owner manifest(s)",
        report.manifests.len()
    );
    for manifest in &report.manifests {
        println!(
            "  {}: {} root(s), {} unit(s)",
            manifest.owner_report.report_id,
            manifest.roots.len(),
            manifest.units.len()
        );
        for unit in &manifest.units {
            println!(
                "    {}/{} ({:?}, source={:?})",
                unit.root_id, unit.store_id, unit.domain, unit.selected_measurement_source
            );
            let mut printed = false;
            for (label, measurement) in [
                ("broad", unit.broad_measurement.as_ref()),
                ("exact", unit.exact_measurement.as_ref()),
            ] {
                if let Some(measurement) = measurement {
                    printed = true;
                    println!(
                        "      {label}: logical={} allocated={} private={} traversal_complete={} private_complete={}",
                        measurement.metrics.logical_bytes,
                        measurement.metrics.allocated_bytes,
                        measurement.metrics.private_reclaimable_bytes,
                        measurement.traversal_complete,
                        measurement.private_measurement_complete
                    );
                }
            }
            if !printed {
                println!("      filesystem evidence unavailable");
            }
        }
    }
    for warning in &report.warnings {
        println!("  warning: {warning}");
    }
}

fn validate_required_nullable_fields(report: &serde_json::Value) -> Result<()> {
    let units = report
        .get("units")
        .and_then(serde_json::Value::as_array)
        .context("units must be an array")?;
    for (index, unit) in units.iter().enumerate() {
        let unit = unit
            .as_object()
            .with_context(|| format!("units[{index}] must be an object"))?;
        for (object_name, field_name) in [
            ("activity", "closedAgeMs"),
            ("protection", "exportEvidenceId"),
            ("eligibility", "dryRunId"),
        ] {
            let object = unit
                .get(object_name)
                .and_then(serde_json::Value::as_object)
                .with_context(|| format!("units[{index}].{object_name} must be an object"))?;
            ensure!(
                object.contains_key(field_name),
                "units[{index}].{object_name}.{field_name} is required even when null"
            );
        }
        let metrics = unit
            .get("metrics")
            .and_then(serde_json::Value::as_object)
            .with_context(|| format!("units[{index}].metrics must be an object"))?;
        for metric_name in ["logical", "allocated", "private"] {
            let metric = metrics
                .get(metric_name)
                .and_then(serde_json::Value::as_object)
                .with_context(|| {
                    format!("units[{index}].metrics.{metric_name} must be an object")
                })?;
            ensure!(
                metric.contains_key("bytes"),
                "units[{index}].metrics.{metric_name}.bytes is required even when null"
            );
        }
    }
    Ok(())
}

fn validate_owner_report(report: &GatewayStorageInventoryV1) -> Result<()> {
    ensure!(
        report.schema_version == GATEWAY_SCHEMA_VERSION,
        "unsupported schemaVersion {:?}",
        report.schema_version
    );
    validate_nonempty("reportId", &report.report_id)?;
    OffsetDateTime::parse(&report.generated_at, &Rfc3339)
        .context("generatedAt must be an RFC 3339 timestamp")?;
    ensure!(!report.roots.is_empty(), "roots must not be empty");
    ensure!(
        report.roots.len() <= MAX_ROOTS_PER_MANIFEST,
        "too many roots in one manifest"
    );
    ensure!(
        report.units.len() <= MAX_UNITS_PER_MANIFEST,
        "too many units in one manifest"
    );

    let mut root_ids = BTreeSet::new();
    for root in &report.roots {
        validate_nonempty("rootId", &root.root_id)?;
        ensure!(
            root_ids.insert(root.root_id.as_str()),
            "duplicate rootId {:?}",
            root.root_id
        );
        local_file_uri_path(&root.local_root_uri, "localRootUri")?;
    }

    let mut unit_ids = BTreeSet::new();
    for unit in &report.units {
        validate_nonempty("owner.rootId", &unit.owner.root_id)?;
        validate_nonempty("owner.storeId", &unit.owner.store_id)?;
        ensure!(
            root_ids.contains(unit.owner.root_id.as_str()),
            "unit references undeclared rootId {:?}",
            unit.owner.root_id
        );
        ensure!(
            unit_ids.insert((unit.owner.root_id.as_str(), unit.owner.store_id.as_str())),
            "duplicate unit identity {}/{}",
            unit.owner.root_id,
            unit.owner.store_id
        );
        local_file_uri_path(&unit.owner.local_unit_uri, "localUnitUri")?;
        ensure!(
            matches!(
                (unit.domain, unit.classification),
                (
                    GatewayDomain::WorkspacePglite,
                    GatewayClassification::CanonicalDurable
                ) | (
                    GatewayDomain::InvestigationLogs,
                    GatewayClassification::Diagnostic
                )
            ),
            "domain and classification disagree for {}/{}",
            unit.owner.root_id,
            unit.owner.store_id
        );
        if unit.owner.store_id_basis == GatewayStoreIdBasis::LegacyRoot {
            ensure!(
                unit.activity.evidence_completeness != GatewayCompleteness::Complete,
                "legacy-root units cannot claim complete activity evidence"
            );
        }
        validate_activity(&unit.activity)?;
        validate_protection(&unit.protection)?;
        validate_metric("logical", &unit.metrics.logical)?;
        validate_metric("allocated", &unit.metrics.allocated)?;
        validate_metric("private", &unit.metrics.private)?;
        validate_eligibility(unit)?;
    }
    Ok(())
}

fn validate_activity(activity: &GatewayActivity) -> Result<()> {
    validate_unique_nonempty("activity evidence", &activity.evidence)?;
    match activity.state {
        GatewayActivityState::Closed => {
            ensure!(
                activity.closed_age_ms.is_some(),
                "closed activity requires closedAgeMs"
            );
        }
        GatewayActivityState::Active | GatewayActivityState::Unknown => ensure!(
            activity.closed_age_ms.is_none(),
            "closedAgeMs is only valid for closed activity"
        ),
    }
    if let Some(value) = activity.closed_age_ms {
        ensure!(
            value <= MAX_SAFE_INTEGER,
            "closedAgeMs exceeds the JSON safe integer range"
        );
    }
    Ok(())
}

fn validate_protection(protection: &GatewayProtection) -> Result<()> {
    if protection.export == GatewayExportState::Completed {
        ensure!(
            protection
                .export_evidence_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "completed export requires exportEvidenceId"
        );
    } else {
        ensure!(
            protection.export_evidence_id.is_none(),
            "exportEvidenceId is only valid for a completed export"
        );
    }
    Ok(())
}

fn validate_metric(label: &str, metric: &GatewayMetric) -> Result<()> {
    validate_nonempty(&format!("metrics.{label}.basis"), &metric.basis)?;
    if let Some(bytes) = metric.bytes {
        ensure!(
            bytes <= MAX_SAFE_INTEGER,
            "metrics.{label}.bytes exceeds the JSON safe integer range"
        );
    }
    Ok(())
}

fn validate_eligibility(unit: &GatewayUnit) -> Result<()> {
    ensure!(
        unit.eligibility.authority == "extension-mediated",
        "eligibility.authority must be extension-mediated"
    );
    validate_unique_nonempty("eligibility reasonCodes", &unit.eligibility.reason_codes)?;
    if unit.eligibility.state == GatewayEligibilityState::ReportCandidate {
        ensure!(
            unit.eligibility
                .dry_run_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "report-candidate eligibility requires dryRunId"
        );
        ensure!(
            unit.activity.state == GatewayActivityState::Closed,
            "report candidates must be closed"
        );
        ensure!(
            unit.activity.evidence_completeness == GatewayCompleteness::Complete
                && !unit.activity.evidence.is_empty(),
            "report candidates require complete, nonempty activity evidence"
        );
        ensure!(
            unit.protection.pin == GatewayPinState::Absent,
            "report candidates must have no pin"
        );
        ensure!(
            matches!(
                unit.protection.export,
                GatewayExportState::Completed | GatewayExportState::None
            ),
            "report candidates cannot have a pending or unknown export"
        );
        ensure!(
            !unit.eligibility.reason_codes.is_empty(),
            "report candidates require reasonCodes"
        );
        match unit.domain {
            GatewayDomain::WorkspacePglite => ensure!(
                unit.protection.export == GatewayExportState::Completed
                    && unit.protection.export_evidence_id.is_some(),
                "workspace-pglite report candidates require a completed export"
            ),
            GatewayDomain::InvestigationLogs => ensure!(
                unit.activity
                    .evidence
                    .iter()
                    .any(|code| code == "sealed-index"),
                "investigation-logs report candidates require sealed-index evidence"
            ),
        }
    } else {
        ensure!(
            unit.eligibility.dry_run_id.is_none(),
            "dryRunId is only valid for report-candidate eligibility"
        );
    }
    Ok(())
}

fn resolve_owner_paths(
    report: &GatewayStorageInventoryV1,
    observed_at_ms: u64,
) -> Result<(Vec<GatewayRootResolution>, Vec<GatewayUnitEvidence>)> {
    let mut root_lexical_paths = BTreeMap::new();
    let mut root_paths = BTreeMap::new();
    let mut roots = Vec::with_capacity(report.roots.len());
    for root in &report.roots {
        let lexical = local_file_uri_path(&root.local_root_uri, "localRootUri")?;
        root_lexical_paths.insert(root.root_id.clone(), lexical.clone());
        match canonical_existing_path(&lexical, true, "owner root") {
            Ok(canonical) => {
                root_paths.insert(root.root_id.clone(), Some(canonical.clone()));
                roots.push(GatewayRootResolution {
                    root_id: root.root_id.clone(),
                    product: root.product,
                    canonical_path: Some(canonical),
                    state: GatewayResolutionState::Validated,
                    reason: None,
                });
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                root_paths.insert(root.root_id.clone(), None);
                roots.push(GatewayRootResolution {
                    root_id: root.root_id.clone(),
                    product: root.product,
                    canonical_path: None,
                    state: GatewayResolutionState::Unavailable,
                    reason: Some("owner root does not exist".to_string()),
                });
            }
            Err(error) => {
                return Err(error).with_context(|| format!("validate root {}", root.root_id))
            }
        }
    }

    let mut units = Vec::with_capacity(report.units.len());
    for unit in &report.units {
        let derived_closed_age_ms = derive_closed_age_ms(report, unit, observed_at_ms)?;
        let derived_closed_age_basis =
            derived_closed_age_ms.map(|_| "owner-snapshot-plus-manifest-elapsed".to_string());
        let lexical = local_file_uri_path(&unit.owner.local_unit_uri, "localUnitUri")?;
        let root_lexical = root_lexical_paths
            .get(&unit.owner.root_id)
            .expect("validated owner root reference");
        ensure!(
            lexical == *root_lexical || lexical.starts_with(root_lexical),
            "unit {}/{} is lexically outside its owner root",
            unit.owner.root_id,
            unit.owner.store_id
        );
        let Some(root) = root_paths.get(&unit.owner.root_id).and_then(Option::as_ref) else {
            units.push(GatewayUnitEvidence {
                root_id: unit.owner.root_id.clone(),
                store_id: unit.owner.store_id.clone(),
                domain: unit.domain,
                canonical_path: None,
                containment: GatewayContainment::Unavailable,
                selected_measurement_source: GatewayMeasurementSource::Unavailable,
                broad_measurement: None,
                exact_measurement: None,
                unavailable_reason: Some("owner root is unavailable".to_string()),
                derived_closed_age_ms,
                derived_closed_age_basis,
                additive: false,
            });
            continue;
        };
        match canonical_existing_path(&lexical, true, "owner unit") {
            Ok(canonical) => {
                ensure!(
                    canonical == *root || canonical.starts_with(root),
                    "unit {}/{} escapes canonical owner root",
                    unit.owner.root_id,
                    unit.owner.store_id
                );
                units.push(GatewayUnitEvidence {
                    root_id: unit.owner.root_id.clone(),
                    store_id: unit.owner.store_id.clone(),
                    domain: unit.domain,
                    canonical_path: Some(canonical),
                    containment: GatewayContainment::CanonicallyContained,
                    selected_measurement_source: GatewayMeasurementSource::Unavailable,
                    broad_measurement: None,
                    exact_measurement: None,
                    unavailable_reason: None,
                    derived_closed_age_ms,
                    derived_closed_age_basis,
                    additive: false,
                });
            }
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                units.push(GatewayUnitEvidence {
                    root_id: unit.owner.root_id.clone(),
                    store_id: unit.owner.store_id.clone(),
                    domain: unit.domain,
                    canonical_path: None,
                    containment: GatewayContainment::Unavailable,
                    selected_measurement_source: GatewayMeasurementSource::Unavailable,
                    broad_measurement: None,
                    exact_measurement: None,
                    unavailable_reason: Some(
                        "owner unit does not exist; canonical containment is unavailable"
                            .to_string(),
                    ),
                    derived_closed_age_ms,
                    derived_closed_age_basis,
                    additive: false,
                })
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "validate unit {}/{}",
                        unit.owner.root_id, unit.owner.store_id
                    )
                })
            }
        }
    }
    Ok((roots, units))
}

fn derive_closed_age_ms(
    report: &GatewayStorageInventoryV1,
    unit: &GatewayUnit,
    observed_at_ms: u64,
) -> Result<Option<u64>> {
    let Some(owner_age_ms) = unit.activity.closed_age_ms else {
        return Ok(None);
    };
    let generated_at = OffsetDateTime::parse(&report.generated_at, &Rfc3339)
        .context("generatedAt must be an RFC 3339 timestamp")?;
    let generated_at_ms = u64::try_from(generated_at.unix_timestamp_nanos() / 1_000_000)
        .context("generatedAt predates the Unix epoch")?;
    let elapsed_ms = observed_at_ms.saturating_sub(generated_at_ms);
    let derived = owner_age_ms
        .checked_add(elapsed_ms)
        .context("derived closed age overflow")?;
    ensure!(
        derived <= MAX_SAFE_INTEGER,
        "derived closed age exceeds the JSON safe integer range"
    );
    Ok(Some(derived))
}

fn classify_root_relationships(
    manifests: &[ParsedManifest],
) -> (
    Vec<GatewayDuplicateRootGroup>,
    Vec<GatewayPhysicalOverlapGroup>,
    BTreeSet<(usize, String)>,
) {
    let mut by_id: BTreeMap<String, Vec<(usize, usize)>> = BTreeMap::new();
    let mut by_canonical_path: BTreeMap<PathBuf, Vec<(usize, usize)>> = BTreeMap::new();
    for (manifest_index, manifest) in manifests.iter().enumerate() {
        for root_index in 0..manifest.roots.len() {
            by_id
                .entry(manifest.roots[root_index].root_id.clone())
                .or_default()
                .push((manifest_index, root_index));
            if let Some(path) = manifest.roots[root_index].canonical_path.as_ref() {
                by_canonical_path
                    .entry(path.clone())
                    .or_default()
                    .push((manifest_index, root_index));
            }
        }
    }
    let mut conflicts = BTreeSet::new();
    let duplicate_roots = by_id
        .into_iter()
        .filter(|(_, observations)| observations.len() > 1)
        .map(|(root_id, locations)| {
            let owner_uris = locations
                .iter()
                .map(|(manifest, root)| {
                    manifests[*manifest].report.roots[*root]
                        .local_root_uri
                        .as_str()
                })
                .collect::<BTreeSet<_>>();
            let canonical_paths = locations
                .iter()
                .filter_map(|(manifest, root)| {
                    manifests[*manifest].roots[*root].canonical_path.as_ref()
                })
                .collect::<BTreeSet<_>>();
            let relation = if owner_uris.len() > 1 || canonical_paths.len() > 1 {
                for (manifest, _) in &locations {
                    conflicts.insert((*manifest, root_id.clone()));
                }
                GatewayDuplicateRootRelation::IdentityConflict
            } else if locations
                .iter()
                .all(|(manifest, root)| manifests[*manifest].roots[*root].canonical_path.is_some())
            {
                GatewayDuplicateRootRelation::SameCanonicalRoot
            } else {
                GatewayDuplicateRootRelation::Unavailable
            };
            let observations = locations
                .into_iter()
                .map(|location| root_observation(manifests, location))
                .collect();
            GatewayDuplicateRootGroup {
                root_id,
                relation,
                additive: false,
                observations,
            }
        })
        .collect();

    let physical_overlaps = by_canonical_path
        .into_iter()
        .filter_map(|(canonical_path, locations)| {
            let root_ids = locations
                .iter()
                .map(|(manifest, root)| manifests[*manifest].roots[*root].root_id.as_str())
                .collect::<BTreeSet<_>>();
            (root_ids.len() > 1).then(|| GatewayPhysicalOverlapGroup {
                canonical_path,
                additive: false,
                observations: locations
                    .into_iter()
                    .map(|location| root_observation(manifests, location))
                    .collect(),
            })
        })
        .collect();

    (duplicate_roots, physical_overlaps, conflicts)
}

fn root_observation(
    manifests: &[ParsedManifest],
    (manifest_index, root_index): (usize, usize),
) -> GatewayDuplicateRootObservation {
    let manifest = &manifests[manifest_index];
    let root = &manifest.roots[root_index];
    GatewayDuplicateRootObservation {
        manifest_path: manifest.source.path.clone(),
        report_id: manifest.report.report_id.clone(),
        product: root.product,
        local_root_uri: manifest.report.roots[root_index].local_root_uri.clone(),
        canonical_path: root.canonical_path.clone(),
    }
}

fn index_inventory_measurements(
    inventory: &InventoryReport,
) -> HashMap<PathBuf, GatewayFilesystemMeasurement> {
    let mut measurements = HashMap::new();
    for root in &inventory.roots {
        measurements.insert(
            root.path.clone(),
            GatewayFilesystemMeasurement {
                source: GatewayMeasurementSource::InventoryManifestExact,
                inventory_generated_at_unix: inventory.generated_at_unix,
                filesystem: root.filesystem.clone(),
                traversal_complete: root.complete && root.errors.is_empty(),
                private_measurement_complete: root.metrics.private_reclaimable_complete,
                visited_entries: Some(root.visited_entries),
                scan_error_count: root.metrics.errors,
                metrics: root.metrics.clone(),
            },
        );
        for entry in &root.entries {
            measurements.insert(
                entry.path.clone(),
                GatewayFilesystemMeasurement {
                    source: GatewayMeasurementSource::InventoryManifestExact,
                    inventory_generated_at_unix: inventory.generated_at_unix,
                    filesystem: root.filesystem.clone(),
                    traversal_complete: root.complete && root.errors.is_empty(),
                    private_measurement_complete: entry.metrics.private_reclaimable_complete,
                    visited_entries: None,
                    scan_error_count: root.metrics.errors,
                    metrics: entry.metrics.clone(),
                },
            );
        }
    }
    measurements
}

fn inventory_units_tolerating_disappearance(
    paths: &[PathBuf],
    options: InventoryOptions,
    max_entries_per_unit: u64,
) -> Result<InventoryReport> {
    let mut roots = Vec::with_capacity(paths.len());
    let mut remaining_entries = options.max_entries;
    let mut generated_at_unix = now_unix_millis() / 1_000;
    for (index, path) in paths.iter().enumerate() {
        if remaining_entries == 0 {
            break;
        }
        let remaining_roots = u64::try_from(paths.len() - index).unwrap_or(u64::MAX);
        let fair_share =
            remaining_entries.saturating_add(remaining_roots.saturating_sub(1)) / remaining_roots;
        let root_budget = max_entries_per_unit.min(fair_share);
        let report = inventory_with_root_limit(
            std::slice::from_ref(path),
            InventoryOptions {
                max_entries: root_budget,
                ..options.clone()
            },
            Some(root_budget),
        );
        match report {
            Ok(report) => {
                generated_at_unix = generated_at_unix.max(report.generated_at_unix);
                if let Some(root) = report.roots.into_iter().next() {
                    remaining_entries = remaining_entries.saturating_sub(root.visited_entries);
                    roots.push(root);
                }
            }
            Err(error) if error_chain_contains_not_found(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(InventoryReport {
        inventory_version: INVENTORY_VERSION,
        generated_at_unix,
        options: InventoryReportOptions {
            display_depth: options.display_depth,
            top: options.top,
            max_entries: options.max_entries,
            one_filesystem: options.one_filesystem,
        },
        roots,
    })
}

fn error_chain_contains_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
    })
}

fn discover_manifest_paths(
    explicit: &[PathBuf],
    directories: &[PathBuf],
    max_directory_entries: usize,
) -> Result<(Vec<PathBuf>, Vec<DirectorySnapshot>)> {
    ensure!(
        directories.len() <= MAX_MANIFEST_DIRS,
        "too many gateway manifest directories"
    );
    let mut paths = BTreeSet::new();
    for path in explicit {
        paths.insert(canonical_regular_file(path, "gateway manifest")?);
    }
    let mut snapshots = Vec::with_capacity(directories.len());
    for directory in directories {
        let snapshot = snapshot_manifest_directory(directory, max_directory_entries)?;
        paths.extend(snapshot.files.iter().map(|file| file.path.clone()));
        snapshots.push(snapshot);
    }
    ensure!(!paths.is_empty(), "no gateway JSON manifests were found");
    ensure!(paths.len() <= MAX_MANIFESTS, "too many gateway manifests");
    Ok((paths.into_iter().collect(), snapshots))
}

fn snapshot_manifest_directory(path: &Path, max_entries: usize) -> Result<DirectorySnapshot> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect gateway manifest directory {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "gateway manifest directory must not be a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_dir(),
        "gateway manifest directory is not a directory: {}",
        path.display()
    );
    let canonical_dir = fs::canonicalize(path)
        .with_context(|| format!("canonicalize gateway manifest directory {}", path.display()))?;
    let mut files = Vec::new();
    let mut entries = 0_usize;
    for entry in fs::read_dir(&canonical_dir).with_context(|| {
        format!(
            "read gateway manifest directory {}",
            canonical_dir.display()
        )
    })? {
        let entry = entry.with_context(|| format!("read entry in {}", canonical_dir.display()))?;
        entries += 1;
        ensure!(
            entries <= max_entries,
            "gateway manifest directory {} exceeds its {}-entry bound",
            canonical_dir.display(),
            max_entries
        );
        if entry
            .path()
            .extension()
            .and_then(|extension| extension.to_str())
            != Some("json")
        {
            continue;
        }
        let entry_metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            !entry_metadata.file_type().is_symlink(),
            "gateway JSON manifest must not be a symlink: {}",
            entry.path().display()
        );
        ensure!(
            entry_metadata.is_file(),
            "gateway JSON manifest is not a regular file: {}",
            entry.path().display()
        );
        let canonical = fs::canonicalize(entry.path())?;
        ensure!(
            canonical.parent() == Some(canonical_dir.as_path()),
            "gateway manifest escaped its directory: {}",
            entry.path().display()
        );
        files.push(manifest_file_snapshot(canonical, &entry_metadata));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(DirectorySnapshot {
        canonical_dir,
        files,
    })
}

fn manifest_file_snapshot(path: PathBuf, metadata: &fs::Metadata) -> ManifestFileSnapshot {
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    ManifestFileSnapshot {
        path,
        len: metadata.len(),
        modified: metadata.modified().ok(),
        created: metadata.created().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
    }
}

fn verify_directory_snapshots(snapshots: &[DirectorySnapshot], max_entries: usize) -> Result<()> {
    for before in snapshots {
        let after = snapshot_manifest_directory(&before.canonical_dir, max_entries)?;
        ensure!(
            before.files == after.files,
            "gateway manifest directory changed while it was being read: {}",
            before.canonical_dir.display()
        );
    }
    Ok(())
}

fn canonical_regular_file(path: &Path, label: &str) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{label} must not be a symlink: {}",
        path.display()
    );
    ensure!(
        metadata.is_file(),
        "{label} is not a regular file: {}",
        path.display()
    );
    fs::canonicalize(path).with_context(|| format!("canonicalize {label} {}", path.display()))
}

fn canonical_existing_path(path: &Path, require_directory: bool, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let metadata = fs::metadata(&canonical)?;
    if require_directory {
        ensure!(
            metadata.is_dir(),
            "{label} is not a directory: {}",
            canonical.display()
        );
    }
    Ok(canonical)
}

fn read_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let path_before = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {} before reading", path.display()))?;
    ensure!(
        !path_before.file_type().is_symlink() && path_before.is_file(),
        "manifest source is no longer a regular file: {}",
        path.display()
    );
    ensure!(
        path_before.len() <= max_bytes,
        "{} exceeds the {}-byte limit",
        path.display(),
        max_bytes
    );
    let mut bytes = Vec::new();
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let opened_before = file
        .metadata()
        .with_context(|| format!("inspect opened file {}", path.display()))?;
    ensure!(
        opened_before.is_file() && same_file_identity(&path_before, &opened_before),
        "manifest source changed while it was opened: {}",
        path.display()
    );
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {}", path.display()))?;
    ensure!(
        bytes.len() as u64 <= max_bytes,
        "{} exceeds the {}-byte limit",
        path.display(),
        max_bytes
    );
    let path_after = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {} after reading", path.display()))?;
    ensure!(
        !path_after.file_type().is_symlink()
            && path_after.is_file()
            && same_file_identity(&opened_before, &path_after)
            && stable_file_metadata(&opened_before, &path_after),
        "manifest source changed while it was read: {}",
        path.display()
    );
    Ok(bytes)
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    stable_file_metadata(left, right)
}

fn stable_file_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

fn local_file_uri_path(uri: &str, label: &str) -> Result<PathBuf> {
    ensure!(
        uri.starts_with("file:///"),
        "{label} must be an absolute local file URI"
    );
    let encoded_path = uri
        .strip_prefix("file://")
        .context("local file URI lost its file scheme")?;
    ensure!(
        encoded_path.starts_with('/') && !encoded_path.starts_with("//"),
        "{label} must have an empty authority"
    );
    ensure!(
        !encoded_path[1..].contains("//"),
        "{label} must not contain repeated path separators"
    );
    ensure!(
        !encoded_path.contains('?') && !encoded_path.contains('#'),
        "{label} must not contain a query or fragment"
    );
    ensure!(
        !encoded_path.chars().any(|character| {
            character.is_ascii_control()
                || character == ' '
                || matches!(
                    character,
                    '"' | '<' | '>' | '\\' | '^' | '`' | '{' | '|' | '}'
                )
        }),
        "{label} contains a character that must be percent-encoded"
    );
    validate_percent_escapes(encoded_path, label)?;
    let decoded = percent_decode_str(encoded_path)
        .decode_utf8()
        .with_context(|| format!("{label} path is not UTF-8"))?;
    ensure!(!decoded.contains('\0'), "{label} must not contain NUL");
    let path = decoded_file_uri_path(&decoded, label)?;
    ensure!(
        path.is_absolute(),
        "{label} must resolve to an absolute path"
    );
    ensure!(
        path.components().all(|component| !matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )),
        "{label} must not contain dot segments"
    );
    Ok(path)
}

#[cfg(not(windows))]
fn decoded_file_uri_path(decoded: &str, _label: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(decoded))
}

#[cfg(windows)]
fn decoded_file_uri_path(decoded: &str, label: &str) -> Result<PathBuf> {
    let bytes = decoded.as_bytes();
    ensure!(
        bytes.len() >= 4
            && bytes[0] == b'/'
            && bytes[1].is_ascii_alphabetic()
            && bytes[2] == b':'
            && bytes[3] == b'/',
        "{label} must identify an absolute local drive path"
    );
    Ok(PathBuf::from(decoded[1..].replace('/', "\\")))
}

fn validate_percent_escapes(value: &str, label: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            index += 1;
            continue;
        }
        ensure!(
            index + 2 < bytes.len(),
            "{label} has an incomplete percent escape"
        );
        let high = bytes[index + 1];
        let low = bytes[index + 2];
        ensure!(
            is_uppercase_hex(high) && is_uppercase_hex(low),
            "{label} percent escapes must use uppercase hexadecimal"
        );
        let decoded = (hex_value(high) << 4) | hex_value(low);
        ensure!(
            decoded != b'/' && decoded != b'\\',
            "{label} must not percent-encode a path separator"
        );
        index += 3;
    }
    Ok(())
}

fn is_uppercase_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn hex_value(byte: u8) -> u8 {
    if byte.is_ascii_digit() {
        byte - b'0'
    } else {
        byte - b'A' + 10
    }
}

fn validate_nonempty(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

fn validate_unique_nonempty(label: &str, values: &[String]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for value in values {
        validate_nonempty(label, value)?;
        ensure!(
            seen.insert(value),
            "{label} contains a duplicate value {value:?}"
        );
    }
    Ok(())
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InventoryReportOptions, InventoryRoot};
    use serde_json::{json, Value};
    use tempfile::TempDir;

    fn file_uri(path: &Path) -> String {
        #[cfg(windows)]
        let normalized = format!("/{}", path.to_str().unwrap().replace('\\', "/"));
        #[cfg(not(windows))]
        let normalized = path.to_str().unwrap().to_string();
        format!(
            "file://{}",
            utf8_percent_encode(&normalized, FILE_URI_ENCODE_SET)
        )
    }

    fn unit(
        root_id: &str,
        store_id: &str,
        path: &Path,
        domain: &str,
        classification: &str,
        store_id_basis: &str,
    ) -> Value {
        json!({
            "domain": domain,
            "owner": {
                "rootId": root_id,
                "storeId": store_id,
                "storeIdBasis": store_id_basis,
                "localUnitUri": file_uri(path)
            },
            "classification": classification,
            "activity": {
                "state": "closed",
                "evidenceCompleteness": "complete",
                "evidence": ["owner-closed"],
                "closedAgeMs": 1000
            },
            "protection": {
                "pin": "absent",
                "export": "none",
                "exportEvidenceId": null
            },
            "metrics": {
                "logical": { "bytes": 11, "basis": "owner-logical" },
                "allocated": { "bytes": 22, "basis": "owner-allocated" },
                "private": { "bytes": null, "basis": "owner-private-unavailable" }
            },
            "eligibility": {
                "authority": "extension-mediated",
                "state": "ineligible",
                "reasonCodes": ["retained-by-owner"],
                "dryRunId": null
            }
        })
    }

    fn report(report_id: &str, root_id: &str, root: &Path, units: Vec<Value>) -> Value {
        json!({
            "schemaVersion": GATEWAY_SCHEMA_VERSION,
            "reportId": report_id,
            "generatedAt": "2026-07-15T12:00:00Z",
            "roots": [{
                "product": "code",
                "rootId": root_id,
                "localRootUri": file_uri(root),
                "enumerationCompleteness": "complete"
            }],
            "units": units
        })
    }

    fn write_json(path: &Path, value: &impl Serialize) {
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    fn inventory_manifest(path: &Path, roots: Vec<InventoryRoot>) {
        write_json(
            path,
            &InventoryReport {
                inventory_version: INVENTORY_VERSION,
                generated_at_unix: 123,
                options: InventoryReportOptions {
                    display_depth: 0,
                    top: 1,
                    max_entries: 1000,
                    one_filesystem: true,
                },
                roots,
            },
        );
    }

    fn empty_inventory(path: &Path) {
        inventory_manifest(path, Vec::new());
    }

    fn options(inventory: &Path, manifests: Vec<PathBuf>) -> GatewayStorageOptions {
        GatewayStorageOptions {
            inventory_manifest: inventory.to_path_buf(),
            gateway_manifests: manifests,
            gateway_manifest_dirs: Vec::new(),
            exact_max_entries: 10_000,
            exact_max_entries_per_unit: 5_000,
        }
    }

    #[test]
    fn closed_age_derivation_preserves_owner_snapshot_and_adds_elapsed_time() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let parsed: GatewayStorageInventoryV1 = serde_json::from_value(report(
            "age",
            "root",
            &root,
            vec![unit(
                "root",
                "workspace",
                &root,
                "workspace-pglite",
                "canonical-durable",
                "workspace-id",
            )],
        ))
        .unwrap();
        let observed_at_ms = u64::try_from(
            OffsetDateTime::parse("2026-07-15T12:00:05Z", &Rfc3339)
                .unwrap()
                .unix_timestamp_nanos()
                / 1_000_000,
        )
        .unwrap();

        expect_closed_age(&parsed, observed_at_ms, 6_000);
        assert_eq!(parsed.units[0].activity.closed_age_ms, Some(1_000));
    }

    fn expect_closed_age(report: &GatewayStorageInventoryV1, observed_at_ms: u64, expected: u64) {
        assert_eq!(
            derive_closed_age_ms(report, &report.units[0], observed_at_ms).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn exact_subpass_correlates_both_domains_without_overwriting_owner_metrics() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("gateway");
        let workspace = root.join("workspace");
        let logs = root.join("investigation");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&logs).unwrap();
        fs::write(workspace.join("db"), b"workspace").unwrap();
        fs::write(logs.join("events.jsonl"), b"logs").unwrap();
        let inventory = temp.path().join("inventory.json");
        inventory_manifest(
            &inventory,
            vec![InventoryRoot {
                path: fs::canonicalize(&root).unwrap(),
                filesystem: "testfs".to_string(),
                complete: true,
                visited_entries: 2,
                metrics: InventoryMetrics {
                    logical_bytes: 999_999,
                    allocated_bytes: 999_999,
                    private_reclaimable_bytes: 999_999,
                    private_reclaimable_complete: true,
                    files: 2,
                    directories: 3,
                    hardlink_duplicates: 0,
                    errors: 0,
                },
                entries: Vec::new(),
                errors: Vec::new(),
            }],
        );
        let manifest = temp.path().join("gateway.json");
        write_json(
            &manifest,
            &report(
                "report-code",
                "code-root",
                &root,
                vec![
                    unit(
                        "code-root",
                        "workspace-a",
                        &workspace,
                        "workspace-pglite",
                        "canonical-durable",
                        "workspace-id",
                    ),
                    unit(
                        "code-root",
                        "logs-a",
                        &logs,
                        "investigation-logs",
                        "diagnostic",
                        "investigation-id",
                    ),
                ],
            ),
        );

        let result = gateway_storage_report(options(&inventory, vec![manifest])).unwrap();
        assert_eq!(result.manifests[0].units.len(), 2);
        for evidence in &result.manifests[0].units {
            assert!(evidence.broad_measurement.is_none());
            let measurement = evidence.exact_measurement.as_ref().unwrap();
            assert_eq!(
                measurement.source,
                GatewayMeasurementSource::ExactUnitSubpass
            );
            assert_eq!(
                evidence.selected_measurement_source,
                GatewayMeasurementSource::ExactUnitSubpass
            );
            assert!(measurement.traversal_complete);
            assert!(measurement.metrics.logical_bytes > 0);
            assert!(!evidence.additive);
        }
        assert_eq!(
            result.manifests[0].owner_report.units[0]
                .metrics
                .logical
                .bytes,
            Some(11)
        );
        assert_eq!(
            result
                .exact_measurement
                .as_ref()
                .unwrap()
                .requested_unique_paths,
            2
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("executionCommand"));
        assert!(!serialized.contains("approvalCommand"));
        assert!(!serialized.contains("cleanupAction"));
        let persisted: GatewayStorageReport = serde_json::from_str(&serialized).unwrap();
        assert_eq!(persisted.connector_version, GATEWAY_CONNECTOR_VERSION);
        assert_eq!(persisted.mode, "report-only");
    }

    #[test]
    fn exact_retained_inventory_entry_is_used_without_a_subpass() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("gateway");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("db"), b"workspace").unwrap();
        let metrics = InventoryMetrics {
            logical_bytes: 99,
            allocated_bytes: 4096,
            private_reclaimable_bytes: 4096,
            private_reclaimable_complete: true,
            files: 1,
            directories: 1,
            hardlink_duplicates: 0,
            errors: 0,
        };
        let inventory = temp.path().join("inventory.json");
        inventory_manifest(
            &inventory,
            vec![InventoryRoot {
                path: fs::canonicalize(&workspace).unwrap(),
                filesystem: "testfs".to_string(),
                complete: true,
                visited_entries: 1,
                metrics,
                entries: Vec::new(),
                errors: Vec::new(),
            }],
        );
        let manifest = temp.path().join("gateway.json");
        write_json(
            &manifest,
            &report(
                "report-code",
                "code-root",
                &root,
                vec![unit(
                    "code-root",
                    "workspace-a",
                    &workspace,
                    "workspace-pglite",
                    "canonical-durable",
                    "workspace-id",
                )],
            ),
        );

        let result = gateway_storage_report(options(&inventory, vec![manifest])).unwrap();
        let measurement = result.manifests[0].units[0]
            .broad_measurement
            .as_ref()
            .unwrap();
        assert_eq!(
            measurement.source,
            GatewayMeasurementSource::InventoryManifestExact
        );
        assert_eq!(measurement.metrics.logical_bytes, 99);
        assert_eq!(
            result.manifests[0].units[0].selected_measurement_source,
            GatewayMeasurementSource::InventoryManifestExact
        );
        assert!(result.manifests[0].units[0].exact_measurement.is_none());
        assert!(result.exact_measurement.is_none());
    }

    #[test]
    fn cross_filesystem_retained_inventory_is_remeasured_with_one_filesystem() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("gateway");
        let workspace = root.join("workspace");
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("db"), b"workspace").unwrap();
        let inventory = temp.path().join("inventory.json");
        write_json(
            &inventory,
            &InventoryReport {
                inventory_version: INVENTORY_VERSION,
                generated_at_unix: 123,
                options: InventoryReportOptions {
                    display_depth: 0,
                    top: 1,
                    max_entries: 1000,
                    one_filesystem: false,
                },
                roots: vec![InventoryRoot {
                    path: fs::canonicalize(&workspace).unwrap(),
                    filesystem: "cross-filesystem".to_string(),
                    complete: true,
                    visited_entries: 1,
                    metrics: InventoryMetrics {
                        logical_bytes: 99_999,
                        allocated_bytes: 99_999,
                        private_reclaimable_bytes: 99_999,
                        private_reclaimable_complete: true,
                        files: 1,
                        directories: 1,
                        hardlink_duplicates: 0,
                        errors: 0,
                    },
                    entries: Vec::new(),
                    errors: Vec::new(),
                }],
            },
        );
        let manifest = temp.path().join("gateway.json");
        write_json(
            &manifest,
            &report(
                "report-code",
                "code-root",
                &root,
                vec![unit(
                    "code-root",
                    "workspace-a",
                    &workspace,
                    "workspace-pglite",
                    "canonical-durable",
                    "workspace-id",
                )],
            ),
        );

        let result = gateway_storage_report(options(&inventory, vec![manifest])).unwrap();
        let evidence = &result.manifests[0].units[0];
        assert!(evidence.broad_measurement.is_none());
        assert_eq!(
            evidence.selected_measurement_source,
            GatewayMeasurementSource::ExactUnitSubpass
        );
        assert_eq!(
            evidence.exact_measurement.as_ref().unwrap().source,
            GatewayMeasurementSource::ExactUnitSubpass
        );
        assert!(result.exact_measurement.as_ref().unwrap().one_filesystem);
    }

    #[test]
    fn exact_subpass_keeps_existing_units_when_another_unit_disappears() {
        let temp = TempDir::new().unwrap();
        let existing = temp.path().join("existing");
        let missing = temp.path().join("missing");
        fs::create_dir_all(&existing).unwrap();
        fs::write(existing.join("data"), b"data").unwrap();

        let result = inventory_units_tolerating_disappearance(
            &[existing.clone(), missing],
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: 100,
                one_filesystem: true,
            },
            50,
        )
        .unwrap();

        assert_eq!(result.roots.len(), 1);
        assert_eq!(result.roots[0].path, fs::canonicalize(existing).unwrap());
        assert!(result.options.one_filesystem);
    }

    #[test]
    fn exact_subpass_preserves_a_fair_budget_for_later_units() {
        let temp = TempDir::new().unwrap();
        let paths = (0..3)
            .map(|unit_index| {
                let path = temp.path().join(format!("unit-{unit_index}"));
                fs::create_dir_all(&path).unwrap();
                for file_index in 0..8 {
                    fs::write(path.join(format!("file-{file_index}")), b"data").unwrap();
                }
                path
            })
            .collect::<Vec<_>>();

        let result = inventory_units_tolerating_disappearance(
            &paths,
            InventoryOptions {
                display_depth: 0,
                top: 1,
                max_entries: 6,
                one_filesystem: true,
            },
            6,
        )
        .unwrap();

        assert_eq!(result.roots.len(), 3);
        assert!(result.roots.iter().all(|root| root.visited_entries <= 2));
    }

    #[test]
    fn retained_inventory_uses_the_full_scanner_error_count() {
        let root_path = PathBuf::from("/gateway/root");
        let report = InventoryReport {
            inventory_version: INVENTORY_VERSION,
            generated_at_unix: 123,
            options: InventoryReportOptions {
                display_depth: 0,
                top: 1,
                max_entries: 100,
                one_filesystem: true,
            },
            roots: vec![InventoryRoot {
                path: root_path.clone(),
                filesystem: "testfs".to_string(),
                complete: false,
                visited_entries: 100,
                metrics: InventoryMetrics {
                    errors: 143,
                    ..InventoryMetrics::default()
                },
                entries: Vec::new(),
                errors: Vec::new(),
            }],
        };

        let measurements = index_inventory_measurements(&report);
        assert_eq!(measurements[&root_path].scan_error_count, 143);
    }

    #[test]
    fn incomplete_retained_evidence_is_preserved_beside_the_exact_subpass() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("gateway");
        let logs = root.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("events"), b"events").unwrap();
        let inventory = temp.path().join("inventory.json");
        inventory_manifest(
            &inventory,
            vec![InventoryRoot {
                path: fs::canonicalize(&logs).unwrap(),
                filesystem: "testfs".to_string(),
                complete: false,
                visited_entries: 1,
                metrics: InventoryMetrics {
                    logical_bytes: 77,
                    allocated_bytes: 4096,
                    private_reclaimable_bytes: 0,
                    private_reclaimable_complete: false,
                    files: 1,
                    directories: 1,
                    hardlink_duplicates: 0,
                    errors: 1,
                },
                entries: Vec::new(),
                errors: Vec::new(),
            }],
        );
        let manifest = temp.path().join("gateway.json");
        write_json(
            &manifest,
            &report(
                "report-code",
                "code-root",
                &root,
                vec![unit(
                    "code-root",
                    "logs",
                    &logs,
                    "investigation-logs",
                    "diagnostic",
                    "investigation-id",
                )],
            ),
        );

        let result = gateway_storage_report(options(&inventory, vec![manifest])).unwrap();
        let evidence = &result.manifests[0].units[0];
        let broad = evidence.broad_measurement.as_ref().unwrap();
        assert_eq!(
            broad.source,
            GatewayMeasurementSource::InventoryManifestExact
        );
        assert!(!broad.traversal_complete);
        assert!(!broad.private_measurement_complete);
        assert_eq!(broad.metrics.logical_bytes, 77);
        let exact = evidence.exact_measurement.as_ref().unwrap();
        assert_eq!(exact.source, GatewayMeasurementSource::ExactUnitSubpass);
        assert!(exact.traversal_complete);
        assert_eq!(
            evidence.selected_measurement_source,
            GatewayMeasurementSource::ExactUnitSubpass
        );
    }

    #[test]
    fn duplicate_root_observations_are_independent_and_exact_paths_are_measured_once() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("shared");
        let logs = root.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("events"), b"events").unwrap();
        let inventory = temp.path().join("inventory.json");
        empty_inventory(&inventory);
        let stable = temp.path().join("stable.json");
        let insiders = temp.path().join("insiders.json");
        for (path, report_id, product) in [
            (&stable, "stable", "code"),
            (&insiders, "insiders", "code-insiders"),
        ] {
            let mut owner_report = report(
                report_id,
                "shared-logs",
                &root,
                vec![unit(
                    "shared-logs",
                    report_id,
                    &logs,
                    "investigation-logs",
                    "diagnostic",
                    "investigation-id",
                )],
            );
            owner_report["roots"][0]["product"] = json!(product);
            write_json(path, &owner_report);
        }

        let result = gateway_storage_report(options(&inventory, vec![stable, insiders])).unwrap();
        assert_eq!(result.manifests.len(), 2);
        assert_eq!(result.duplicate_roots.len(), 1);
        assert_eq!(
            result.duplicate_roots[0].relation,
            GatewayDuplicateRootRelation::SameCanonicalRoot
        );
        let products = result.duplicate_roots[0]
            .observations
            .iter()
            .map(|observation| observation.product)
            .collect::<Vec<_>>();
        assert!(products.contains(&GatewayProduct::Code));
        assert!(products.contains(&GatewayProduct::CodeInsiders));
        assert!(!result.duplicate_roots[0].additive);
        assert_eq!(
            result
                .exact_measurement
                .as_ref()
                .unwrap()
                .requested_unique_paths,
            1
        );
        assert!(result.manifests.iter().all(|manifest| {
            manifest.units[0].exact_measurement.is_some() && !manifest.units[0].additive
        }));
    }

    #[test]
    fn conflicting_duplicate_root_identity_suppresses_filesystem_correlation() {
        let temp = TempDir::new().unwrap();
        let stable_root = temp.path().join("stable");
        let insiders_root = temp.path().join("insiders");
        fs::create_dir_all(&stable_root).unwrap();
        fs::create_dir_all(&insiders_root).unwrap();
        let inventory = temp.path().join("inventory.json");
        empty_inventory(&inventory);
        let stable = temp.path().join("stable.json");
        let insiders = temp.path().join("insiders.json");
        for (path, report_id, root) in [
            (&stable, "stable", &stable_root),
            (&insiders, "insiders", &insiders_root),
        ] {
            write_json(
                path,
                &report(
                    report_id,
                    "shared-id",
                    root,
                    vec![unit(
                        "shared-id",
                        report_id,
                        root,
                        "investigation-logs",
                        "diagnostic",
                        "investigation-id",
                    )],
                ),
            );
        }

        let result = gateway_storage_report(options(&inventory, vec![stable, insiders])).unwrap();
        assert_eq!(
            result.duplicate_roots[0].relation,
            GatewayDuplicateRootRelation::IdentityConflict
        );
        assert!(result.exact_measurement.is_none());
        assert!(result.manifests.iter().all(|manifest| {
            manifest.units[0].broad_measurement.is_none()
                && manifest.units[0].exact_measurement.is_none()
                && manifest.units[0].containment == GatewayContainment::IdentityConflict
                && manifest.units[0].selected_measurement_source
                    == GatewayMeasurementSource::Unavailable
        }));
    }

    #[cfg(unix)]
    #[test]
    fn one_root_id_with_distinct_owner_uris_conflicts_even_when_paths_resolve_together() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let alias = temp.path().join("alias");
        fs::create_dir_all(&root).unwrap();
        symlink(&root, &alias).unwrap();
        let inventory = temp.path().join("inventory.json");
        empty_inventory(&inventory);
        let stable = temp.path().join("stable.json");
        let insiders = temp.path().join("insiders.json");
        write_json(
            &stable,
            &report(
                "stable",
                "shared-id",
                &root,
                vec![unit(
                    "shared-id",
                    "stable",
                    &root,
                    "investigation-logs",
                    "diagnostic",
                    "investigation-id",
                )],
            ),
        );
        write_json(
            &insiders,
            &report(
                "insiders",
                "shared-id",
                &alias,
                vec![unit(
                    "shared-id",
                    "insiders",
                    &alias,
                    "investigation-logs",
                    "diagnostic",
                    "investigation-id",
                )],
            ),
        );

        let result = gateway_storage_report(options(&inventory, vec![stable, insiders])).unwrap();
        assert_eq!(
            result.duplicate_roots[0].relation,
            GatewayDuplicateRootRelation::IdentityConflict
        );
        assert!(result.exact_measurement.is_none());
        assert!(result.manifests.iter().all(|manifest| {
            manifest.units[0].containment == GatewayContainment::IdentityConflict
                && manifest.units[0].selected_measurement_source
                    == GatewayMeasurementSource::Unavailable
        }));
    }

    #[test]
    fn distinct_root_ids_at_one_physical_root_are_grouped_and_measured_once() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("shared");
        let logs = root.join("logs");
        fs::create_dir_all(&logs).unwrap();
        fs::write(logs.join("events"), b"events").unwrap();
        let inventory = temp.path().join("inventory.json");
        empty_inventory(&inventory);
        let stable = temp.path().join("stable.json");
        let insiders = temp.path().join("insiders.json");
        for (path, report_id, root_id, product) in [
            (&stable, "stable", "stable-root", "code"),
            (&insiders, "insiders", "insiders-root", "code-insiders"),
        ] {
            let mut owner_report = report(
                report_id,
                root_id,
                &root,
                vec![unit(
                    root_id,
                    "shared-logs",
                    &logs,
                    "investigation-logs",
                    "diagnostic",
                    "investigation-id",
                )],
            );
            owner_report["roots"][0]["product"] = json!(product);
            write_json(path, &owner_report);
        }

        let result = gateway_storage_report(options(&inventory, vec![stable, insiders])).unwrap();
        assert!(result.duplicate_roots.is_empty());
        assert_eq!(result.physical_overlaps.len(), 1);
        assert!(!result.physical_overlaps[0].additive);
        assert_eq!(result.physical_overlaps[0].observations.len(), 2);
        assert_eq!(
            result
                .exact_measurement
                .as_ref()
                .unwrap()
                .requested_unique_paths,
            1
        );
        assert!(result.manifests.iter().all(|manifest| {
            manifest.units[0].selected_measurement_source
                == GatewayMeasurementSource::ExactUnitSubpass
        }));
    }

    #[test]
    fn manifest_directory_is_sorted_deduplicated_and_non_recursive() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let inventory = temp.path().join("inventory.json");
        empty_inventory(&inventory);
        let directory = temp.path().join("manifests");
        fs::create_dir_all(directory.join("nested")).unwrap();
        let a = directory.join("a.json");
        let b = directory.join("b.json");
        write_json(&b, &report("b", "b-root", &root, Vec::new()));
        write_json(&a, &report("a", "a-root", &root, Vec::new()));
        write_json(
            &directory.join("nested").join("ignored.json"),
            &report("ignored", "ignored-root", &root, Vec::new()),
        );
        fs::write(directory.join("scratch.tmp"), b"ignored").unwrap();

        let mut run_options = options(&inventory, vec![b.clone()]);
        run_options.gateway_manifest_dirs.push(directory);
        let result = gateway_storage_report(run_options).unwrap();
        assert_eq!(
            result
                .manifests
                .iter()
                .map(|manifest| manifest.owner_report.report_id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
    }

    #[test]
    fn owner_contract_rejects_legacy_complete_activity_and_invalid_candidates() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let mut legacy = report(
            "legacy",
            "root",
            &root,
            vec![unit(
                "root",
                "legacy",
                &root,
                "workspace-pglite",
                "canonical-durable",
                "legacy-root",
            )],
        );
        let parsed: GatewayStorageInventoryV1 = serde_json::from_value(legacy.clone()).unwrap();
        assert!(validate_owner_report(&parsed)
            .unwrap_err()
            .to_string()
            .contains("legacy-root"));

        legacy["units"][0]["owner"]["storeIdBasis"] = json!("workspace-id");
        legacy["units"][0]["eligibility"] = json!({
            "authority": "extension-mediated",
            "state": "report-candidate",
            "reasonCodes": ["old"],
            "dryRunId": "dry-run"
        });
        let parsed: GatewayStorageInventoryV1 = serde_json::from_value(legacy).unwrap();
        assert!(validate_owner_report(&parsed)
            .unwrap_err()
            .to_string()
            .contains("completed export"));
    }

    #[test]
    fn owner_contract_requires_nullable_schema_fields_to_be_present() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let base = report(
            "required-nullables",
            "root",
            &root,
            vec![unit(
                "root",
                "workspace",
                &root,
                "workspace-pglite",
                "canonical-durable",
                "workspace-id",
            )],
        );
        for (object_name, field_name) in [
            ("activity", "closedAgeMs"),
            ("protection", "exportEvidenceId"),
            ("eligibility", "dryRunId"),
        ] {
            let mut missing = base.clone();
            missing["units"][0][object_name]
                .as_object_mut()
                .unwrap()
                .remove(field_name);
            assert!(
                validate_required_nullable_fields(&missing)
                    .unwrap_err()
                    .to_string()
                    .contains("required even when null"),
                "missing {object_name}.{field_name} should be rejected"
            );
        }
        for metric_name in ["logical", "allocated", "private"] {
            let mut missing = base.clone();
            missing["units"][0]["metrics"][metric_name]
                .as_object_mut()
                .unwrap()
                .remove("bytes");
            assert!(
                validate_required_nullable_fields(&missing)
                    .unwrap_err()
                    .to_string()
                    .contains("required even when null"),
                "missing metrics.{metric_name}.bytes should be rejected"
            );
        }
    }

    #[test]
    fn owner_contract_requires_evidence_and_reason_code_arrays() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let base = report(
            "required-arrays",
            "root",
            &root,
            vec![unit(
                "root",
                "workspace",
                &root,
                "workspace-pglite",
                "canonical-durable",
                "workspace-id",
            )],
        );
        for (object_name, field_name) in [("activity", "evidence"), ("eligibility", "reasonCodes")]
        {
            let mut missing = base.clone();
            missing["units"][0][object_name]
                .as_object_mut()
                .unwrap()
                .remove(field_name);
            let error = serde_json::from_value::<GatewayStorageInventoryV1>(missing)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("missing field"),
                "missing {object_name}.{field_name} should be rejected: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn canonical_containment_rejects_a_unit_symlink_that_escapes_its_root() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let escaped = root.join("escaped");
        symlink(&outside, &escaped).unwrap();
        let report: GatewayStorageInventoryV1 = serde_json::from_value(report(
            "escape",
            "root",
            &root,
            vec![unit(
                "root",
                "escape",
                &escaped,
                "investigation-logs",
                "diagnostic",
                "investigation-id",
            )],
        ))
        .unwrap();
        validate_owner_report(&report).unwrap();
        assert!(resolve_owner_paths(&report, 0)
            .unwrap_err()
            .to_string()
            .contains("escapes canonical owner root"));
    }

    #[test]
    fn missing_unit_outside_its_owner_root_is_rejected_before_unavailable_reporting() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let outside = temp.path().join("missing-outside");
        let report: GatewayStorageInventoryV1 = serde_json::from_value(report(
            "outside",
            "root",
            &root,
            vec![unit(
                "root",
                "outside",
                &outside,
                "investigation-logs",
                "diagnostic",
                "investigation-id",
            )],
        ))
        .unwrap();

        assert!(resolve_owner_paths(&report, 0)
            .unwrap_err()
            .to_string()
            .contains("lexically outside its owner root"));
    }

    #[test]
    fn missing_unit_inside_its_owner_root_has_explicit_unavailable_measurement() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let missing = root.join("missing-inside");
        let report: GatewayStorageInventoryV1 = serde_json::from_value(report(
            "inside",
            "root",
            &root,
            vec![unit(
                "root",
                "inside",
                &missing,
                "investigation-logs",
                "diagnostic",
                "investigation-id",
            )],
        ))
        .unwrap();

        let (_, units) = resolve_owner_paths(&report, 0).unwrap();
        assert_eq!(units[0].containment, GatewayContainment::Unavailable);
        assert_eq!(
            units[0].selected_measurement_source,
            GatewayMeasurementSource::Unavailable
        );
        assert!(units[0]
            .unavailable_reason
            .as_deref()
            .unwrap()
            .contains("canonical containment is unavailable"));
    }

    #[cfg(unix)]
    #[test]
    fn manifest_directory_rejects_json_symlinks() {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("manifests");
        fs::create_dir_all(&directory).unwrap();
        let target = temp.path().join("target.json");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, directory.join("linked.json")).unwrap();
        assert!(
            snapshot_manifest_directory(&directory, MAX_DIRECTORY_ENTRIES)
                .unwrap_err()
                .to_string()
                .contains("must not be a symlink")
        );
    }

    #[test]
    fn manifest_directory_entry_budget_counts_non_json_entries() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("manifests");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("one.tmp"), b"one").unwrap();
        fs::write(directory.join("two.tmp"), b"two").unwrap();
        assert!(snapshot_manifest_directory(&directory, 1)
            .unwrap_err()
            .to_string()
            .contains("entry bound"));
    }

    #[test]
    fn manifest_file_size_is_rejected_before_content_is_read() {
        let temp = TempDir::new().unwrap();
        let manifest = temp.path().join("large.json");
        fs::write(&manifest, b"1234").unwrap();
        assert!(read_bounded_file(&manifest, 3)
            .unwrap_err()
            .to_string()
            .contains("exceeds the 3-byte limit"));
    }

    #[test]
    fn manifest_directory_changes_fail_closed() {
        let temp = TempDir::new().unwrap();
        let directory = temp.path().join("manifests");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("stable.json"), b"{}").unwrap();
        let snapshot = snapshot_manifest_directory(&directory, MAX_DIRECTORY_ENTRIES).unwrap();
        fs::write(directory.join("insiders.json"), b"{}").unwrap();
        assert!(
            verify_directory_snapshots(&[snapshot], MAX_DIRECTORY_ENTRIES)
                .unwrap_err()
                .to_string()
                .contains("changed while it was being read")
        );
    }

    #[test]
    fn owner_file_uris_reject_authorities_dot_segments_and_encoded_separators() {
        for uri in [
            "file://host/tmp/unit",
            "file:////server/share",
            "file:///tmp/../unit",
            "file:///tmp//unit",
            "file:///tmp/%2Funit",
            "file:///tmp/unit?query",
        ] {
            assert!(
                local_file_uri_path(uri, "localUnitUri").is_err(),
                "{uri} should be rejected"
            );
        }
        assert!(local_file_uri_path("file:///tmp/%😀", "localUnitUri").is_err());
        #[cfg(not(windows))]
        assert_eq!(
            local_file_uri_path("file:///tmp/space%20name", "localUnitUri").unwrap(),
            PathBuf::from("/tmp/space name")
        );
        #[cfg(windows)]
        assert_eq!(
            local_file_uri_path("file:///C:/space%20name", "localUnitUri").unwrap(),
            PathBuf::from(r"C:\space name")
        );
    }
}
