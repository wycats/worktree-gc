use crate::{format_bytes, InventoryEntry, InventoryMetrics, InventoryReport, INVENTORY_VERSION};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const STORAGE_SURVEY_VERSION: u64 = 2;
pub const DEFAULT_APPROVAL_MAX_AGE_SECONDS: u64 = 15 * 60;

#[derive(Debug, Clone)]
pub struct StorageSurveyOptions {
    pub inventory_manifest: PathBuf,
    pub collector_manifests: Vec<PathBuf>,
    pub target_free_bytes: Vec<u64>,
    pub approval_max_age_seconds: u64,
    pub now: SystemTime,
}

#[derive(Debug, Serialize)]
pub struct StorageSurveyReport {
    pub survey_version: u64,
    pub generated_at_unix: u64,
    pub approval_max_age_seconds: u64,
    pub inventory: StorageInventoryEvidence,
    pub collectors: Vec<StorageCollectorEvidence>,
    pub overlap_groups: Vec<StorageOverlapGroup>,
    pub filesystem_goals: Vec<StorageFilesystemGoal>,
    pub approval_ready_reclaim_bytes: u64,
    pub review_required_reclaim_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageInventoryEvidence {
    pub manifest_path: PathBuf,
    pub generated_at_unix: u64,
    pub age_seconds: u64,
    pub complete: bool,
    pub roots: Vec<StorageInventoryRoot>,
}

#[derive(Debug, Serialize)]
pub struct StorageInventoryRoot {
    pub path: PathBuf,
    pub filesystem: String,
    pub complete: bool,
    pub visited_entries: u64,
    pub metrics: InventoryMetrics,
    pub entries: Vec<InventoryEntry>,
    pub scan_errors: u64,
}

#[derive(Debug, Serialize)]
pub struct StorageCollectorEvidence {
    pub collector: String,
    pub manifest_path: PathBuf,
    pub manifest_version: u64,
    pub generated_at_unix: u64,
    pub age_seconds: u64,
    pub mode: String,
    pub complete: bool,
    pub action: String,
    pub reason: String,
    pub owner_paths: Vec<PathBuf>,
    pub inventory_matches: Vec<StorageInventoryMatch>,
    pub claims: Vec<StorageClaim>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct StorageInventoryMatch {
    pub owner_path: PathBuf,
    pub observed_path: PathBuf,
    pub relation: String,
    pub complete: bool,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClaimKind {
    ApfsPrivateReclaim,
    OwnerReportedReclaim,
    AllocatedStorage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClaimReadiness {
    ApprovalReady,
    ReviewRequired,
    ReportOnly,
}

#[derive(Debug, Clone, Serialize)]
pub struct StorageClaim {
    pub id: String,
    pub label: String,
    pub bytes: u64,
    pub kind: StorageClaimKind,
    pub readiness: StorageClaimReadiness,
    pub additive: bool,
    pub overlap_group: Option<String>,
    pub filesystem: Option<String>,
    pub approval_digest: Option<String>,
    pub execution_command: Option<Vec<String>>,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct StorageOverlapGroup {
    pub id: String,
    pub claim_ids: Vec<String>,
    pub largest_claim_bytes: u64,
    pub warning: String,
}

#[derive(Debug, Serialize)]
pub struct StorageFilesystemGoal {
    pub filesystem: String,
    pub observed_at: PathBuf,
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub target_free_bytes: u64,
    pub current_shortfall_bytes: u64,
    pub approval_ready_reclaim_bytes: u64,
    pub projected_after_approval_bytes: u64,
    pub shortfall_after_approval_bytes: u64,
    pub review_required_reclaim_bytes: u64,
    pub projected_after_review_bytes: u64,
    pub shortfall_after_review_bytes: u64,
}

#[derive(Debug, Deserialize)]
struct CollectorEnvelope {
    manifest_version: u64,
    collector: String,
    generated_at_unix: u64,
    mode: String,
    #[serde(default)]
    bambu: Value,
    #[serde(default)]
    chromium: Value,
    #[serde(default)]
    pnpm: Value,
    #[serde(default)]
    lima: Value,
    #[serde(default)]
    identity: Value,
    #[serde(default)]
    policy: Value,
    #[serde(default)]
    source: Value,
    plan: Value,
}

pub fn storage_survey(options: StorageSurveyOptions) -> Result<StorageSurveyReport> {
    anyhow::ensure!(
        !options.target_free_bytes.is_empty(),
        "storage survey requires at least one free-space target"
    );
    anyhow::ensure!(
        options.approval_max_age_seconds > 0,
        "storage survey approval evidence max age must be at least 1 second"
    );
    let now_unix = unix_seconds(options.now);
    let inventory: InventoryReport = read_json(&options.inventory_manifest, "inventory manifest")?;
    anyhow::ensure!(
        inventory.inventory_version == INVENTORY_VERSION,
        "unsupported inventory manifest version {} in {}",
        inventory.inventory_version,
        options.inventory_manifest.display()
    );
    let inventory_roots = inventory
        .roots
        .iter()
        .map(|root| StorageInventoryRoot {
            path: root.path.clone(),
            filesystem: root.filesystem.clone(),
            complete: root.complete
                && root.errors.is_empty()
                && root.metrics.private_reclaimable_complete,
            visited_entries: root.visited_entries,
            metrics: root.metrics.clone(),
            entries: root.entries.clone(),
            scan_errors: root.errors.len() as u64,
        })
        .collect::<Vec<_>>();
    let inventory_complete = inventory.roots.iter().all(|root| {
        root.complete && root.errors.is_empty() && root.metrics.private_reclaimable_complete
    });
    let inventory_evidence = StorageInventoryEvidence {
        manifest_path: options.inventory_manifest.clone(),
        generated_at_unix: inventory.generated_at_unix,
        age_seconds: now_unix.saturating_sub(inventory.generated_at_unix),
        complete: inventory_complete,
        roots: inventory_roots,
    };

    let mut collectors = options
        .collector_manifests
        .iter()
        .map(|path| parse_collector_manifest(path, &inventory, now_unix))
        .collect::<Result<Vec<_>>>()?;
    for collector in &mut collectors {
        downgrade_unfresh_additive_claims(collector, now_unix, options.approval_max_age_seconds);
        collector.inventory_matches = collector
            .owner_paths
            .iter()
            .filter_map(|path| inventory_match(path, &inventory))
            .collect();
    }
    collectors.sort_by(|left, right| {
        left.collector
            .cmp(&right.collector)
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
    });
    for pair in collectors.windows(2) {
        anyhow::ensure!(
            pair[0].collector != pair[1].collector,
            "storage survey accepts exactly one explicit manifest per collector; received multiple {:?} manifests",
            pair[0].collector
        );
    }
    downgrade_overlapping_additive_owner_paths(&mut collectors);

    let overlap_groups = overlap_groups(&collectors);
    let approval_ready_reclaim_bytes =
        additive_reclaim(&collectors, StorageClaimReadiness::ApprovalReady, None);
    let review_required_reclaim_bytes =
        additive_reclaim(&collectors, StorageClaimReadiness::ReviewRequired, None);
    let filesystem_goals = filesystem_goals(&inventory, &collectors, &options.target_free_bytes)?;
    let mut warnings = Vec::new();
    if !inventory_evidence.complete {
        warnings.push(
            "inventory evidence is incomplete; reported owner totals and unclassified space are lower bounds"
                .into(),
        );
    }
    if !overlap_groups.is_empty() {
        warnings.push(
            "claims sharing an overlap group are alternative views of one backing store and must not be summed"
                .into(),
        );
    }

    Ok(StorageSurveyReport {
        survey_version: STORAGE_SURVEY_VERSION,
        generated_at_unix: now_unix,
        approval_max_age_seconds: options.approval_max_age_seconds,
        inventory: inventory_evidence,
        collectors,
        overlap_groups,
        filesystem_goals,
        approval_ready_reclaim_bytes,
        review_required_reclaim_bytes,
        warnings,
    })
}

pub fn print_storage_survey(report: &StorageSurveyReport) {
    println!("storage survey v{}", report.survey_version);
    println!(
        "inventory: {} | {}",
        report.inventory.manifest_path.display(),
        if report.inventory.complete {
            "complete"
        } else {
            "incomplete lower bound"
        }
    );
    for root in &report.inventory.roots {
        println!(
            "root {}: {} private{} | {} allocated",
            root.path.display(),
            format_bytes(root.metrics.private_reclaimable_bytes),
            if root.complete { "" } else { " (lower bound)" },
            format_bytes(root.metrics.allocated_bytes)
        );
        for entry in root
            .entries
            .iter()
            .filter(|entry| entry.depth == 1)
            .take(15)
        {
            println!(
                "  {} private{} | {} allocated | {}",
                format_bytes(entry.metrics.private_reclaimable_bytes),
                if root.complete && entry.metrics.private_reclaimable_complete {
                    ""
                } else {
                    " (lower bound)"
                },
                format_bytes(entry.metrics.allocated_bytes),
                entry.relative_path.display()
            );
        }
    }
    for goal in &report.filesystem_goals {
        println!(
            "target {} on {}: {} free now | {} short now | {} short after approval-ready | {} short after review-required",
            format_bytes(goal.target_free_bytes),
            goal.filesystem,
            format_bytes(goal.available_bytes),
            format_bytes(goal.current_shortfall_bytes),
            format_bytes(goal.shortfall_after_approval_bytes),
            format_bytes(goal.shortfall_after_review_bytes)
        );
    }
    for collector in &report.collectors {
        println!(
            "collector {}: {} — {} ({})",
            collector.collector,
            collector.action,
            collector.reason,
            collector.manifest_path.display()
        );
        for claim in &collector.claims {
            println!(
                "  {:?}: {} | {}{}{}",
                claim.readiness,
                format_bytes(claim.bytes),
                claim.label,
                if claim.additive {
                    ""
                } else {
                    " | non-additive"
                },
                claim
                    .overlap_group
                    .as_ref()
                    .map(|group| format!(" | overlap {group}"))
                    .unwrap_or_default()
            );
        }
        for matched in &collector.inventory_matches {
            println!(
                "  owner {} -> {} {}: {} private{} | {} allocated",
                matched.owner_path.display(),
                matched.relation,
                matched.observed_path.display(),
                format_bytes(matched.metrics.private_reclaimable_bytes),
                if matched.complete {
                    ""
                } else {
                    " (lower bound)"
                },
                format_bytes(matched.metrics.allocated_bytes)
            );
        }
        for warning in &collector.warnings {
            println!("  warning: {warning}");
        }
    }
    for warning in &report.warnings {
        println!("warning: {warning}");
    }
}

fn downgrade_unfresh_additive_claims(
    collector: &mut StorageCollectorEvidence,
    now_unix: u64,
    approval_max_age_seconds: u64,
) {
    let reason = if collector.generated_at_unix > now_unix {
        Some(format!(
            "this manifest is timestamped {}s in the future",
            collector.generated_at_unix - now_unix
        ))
    } else if collector.age_seconds > approval_max_age_seconds {
        Some(format!(
            "this manifest is {}s old; the survey limit is {approval_max_age_seconds}s",
            collector.age_seconds
        ))
    } else {
        None
    };
    let Some(reason) = reason else {
        return;
    };
    let mut downgraded = 0usize;
    for claim in &mut collector.claims {
        if claim.additive {
            claim.readiness = StorageClaimReadiness::ReportOnly;
            claim.additive = false;
            claim.execution_command = None;
            downgraded += 1;
        }
    }
    if downgraded > 0 {
        collector.warnings.push(format!(
            "{downgraded} additive claim(s) were downgraded because {reason}"
        ));
    }
}

fn valid_sha256_digest(digest: &str) -> bool {
    digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn downgrade_overlapping_additive_owner_paths(collectors: &mut [StorageCollectorEvidence]) {
    let mut warnings = BTreeMap::<usize, Vec<String>>::new();
    for (index, left) in collectors.iter().enumerate() {
        if !left.claims.iter().any(|claim| claim.additive) {
            continue;
        }
        for (right_index, right) in collectors.iter().enumerate().skip(index + 1) {
            if !right.claims.iter().any(|claim| claim.additive) {
                continue;
            }
            for left_path in &left.owner_paths {
                for right_path in &right.owner_paths {
                    if left_path.starts_with(right_path) || right_path.starts_with(left_path) {
                        warnings.entry(index).or_default().push(format!(
                            "additive claim overlaps collector {:?} at owner paths {} and {}; produce non-overlapping owner plans before projecting reclaim",
                            right.collector,
                            left_path.display(),
                            right_path.display()
                        ));
                        warnings.entry(right_index).or_default().push(format!(
                            "additive claim overlaps collector {:?} at owner paths {} and {}; produce non-overlapping owner plans before projecting reclaim",
                            left.collector,
                            right_path.display(),
                            left_path.display()
                        ));
                    }
                }
            }
        }
    }
    for (index, collector_warnings) in warnings {
        let collector = &mut collectors[index];
        for claim in &mut collector.claims {
            if claim.additive {
                claim.readiness = StorageClaimReadiness::ReportOnly;
                claim.additive = false;
                claim.execution_command = None;
            }
        }
        collector.warnings.extend(collector_warnings);
    }
}

fn parse_collector_manifest(
    path: &Path,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    let envelope: CollectorEnvelope = read_json(path, "collector manifest")?;
    match envelope.collector.as_str() {
        "bambu-logs" => bambu_evidence(path, envelope, inventory, now_unix),
        "chromium-components" => chromium_component_evidence(path, envelope, now_unix),
        "cargo-profile-opportunities" => {
            cargo_profile_evidence(path, envelope, inventory, now_unix)
        }
        "generated" => generated_evidence(path, envelope, inventory, now_unix),
        "pnpm-store" => pnpm_evidence(path, envelope, now_unix),
        "lima" => lima_evidence(path, envelope, inventory, now_unix),
        "parallels" => parallels_evidence(path, envelope, inventory, now_unix),
        "codex-sessions" => codex_session_evidence(path, envelope, inventory, now_unix),
        "codex-worktrees" => codex_worktree_evidence(path, envelope, inventory, now_unix),
        "docker" => docker_evidence(path, envelope, now_unix),
        other => bail!(
            "unsupported collector {other:?} in {}; add an explicit survey adapter before composing its claims",
            path.display()
        ),
    }
}

fn chromium_component_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 3,
        "Chromium component manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let components = array_at(&envelope.plan, &["components"])?;
    let max_entries = u64_at(&envelope.policy, &["max_entries"])?;
    let mut by_filesystem = BTreeMap::<String, (u64, usize, usize)>::new();
    let mut owner_paths = Vec::new();
    for component in components {
        let filesystem = string_at(component, &["filesystem"])?;
        let bytes = u64_at(component, &["metrics", "private_reclaimable_bytes"])?;
        let private_complete = bool_at(component, &["metrics", "private_reclaimable_complete"])?;
        owner_paths.push(path_at(component, &["requested_path"])?);
        owner_paths.push(path_at(component, &["path"])?);
        let entry = by_filesystem.entry(filesystem).or_default();
        entry.0 = entry.0.saturating_add(bytes);
        entry.1 += 1;
        entry.2 += usize::from(!private_complete);
    }
    owner_paths.sort();
    owner_paths.dedup();

    let profiles = array_at(&envelope.chromium, &["profiles"])?;
    let mut requested_profile_paths = profiles
        .iter()
        .map(|profile| path_at(profile, &["requested_path"]))
        .collect::<Result<Vec<_>>>()?;
    requested_profile_paths.sort();
    requested_profile_paths.dedup();
    let reviewable = envelope.mode == "dry_run" && complete && action == "report_only";
    let raw_approval_digest = optional_string_at(&envelope.plan, &["eligibility_digest"]);
    let approval_digest = raw_approval_digest
        .as_deref()
        .filter(|digest| valid_sha256_digest(digest))
        .map(str::to_owned);
    let approval_ready = reviewable
        && by_filesystem.len() == 1
        && !by_filesystem.contains_key("unknown")
        && approval_digest.is_some();
    let execution_command = approval_digest.as_ref().map(|digest| {
        let mut command = vec![
            "worktree-gc".into(),
            "collect".into(),
            "chromium-components".into(),
            "--execute".into(),
            "--max-entries".into(),
            max_entries.to_string(),
        ];
        for profile in &requested_profile_paths {
            command.push("--profile".into());
            command.push(profile.display().to_string());
        }
        command.push("--approved-digest".into());
        command.push(digest.clone());
        command
    });
    let claims = by_filesystem
        .into_iter()
        .enumerate()
        .map(|(index, (filesystem, (bytes, roots, incomplete)))| {
            let claim_ready = approval_ready && incomplete == 0 && bytes > 0;
            let claim_reviewable = reviewable && incomplete == 0 && bytes > 0;
            StorageClaim {
                id: format!("chromium-components-{index}"),
                label: format!("Chromium whole-component cache resets ({roots} roots)"),
                bytes,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: if claim_ready {
                    StorageClaimReadiness::ApprovalReady
                } else if claim_reviewable {
                    StorageClaimReadiness::ReviewRequired
                } else {
                    StorageClaimReadiness::ReportOnly
                },
                additive: claim_reviewable,
                overlap_group: None,
                filesystem: Some(filesystem),
                approval_digest: approval_digest.clone(),
                execution_command: claim_ready
                    .then(|| execution_command.clone())
                    .flatten(),
                evidence: "closed-list whole Chromium on-device component/model roots under explicit user-data directories, with APFS-private measurement, profile-specific browser ownership, open-path evidence, and recursive protections"
                    .into(),
            }
        })
        .collect();
    let mut warnings = vec![
        "browser profile state is excluded; only the manifest's closed component-root list contributes reclaim"
            .into(),
        "this is a whole-component cache reset, not stale-revision pruning; currently installed revisions are removed and must be downloaded again"
            .into(),
        "execution remains manual: approve one exact dry-run digest, then revalidate profile identity, browser/open-file liveness, protections, and same-filesystem quarantine"
            .into(),
    ];
    if raw_approval_digest.is_some() && approval_digest.is_none() {
        warnings.push("Chromium approval digest is not a full sha256 digest".into());
    }
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims,
        warnings,
    })
}

fn generated_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    _inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let artifacts = array_at(&envelope.plan, &["artifacts"])?;
    let mut owner_paths = Vec::new();
    let mut by_filesystem = BTreeMap::<String, (u64, u64, usize, usize, usize)>::new();
    let mut rebuildable_by_filesystem_cost =
        BTreeMap::<(String, String), (u64, usize, usize)>::new();
    for artifact in artifacts {
        owner_paths.push(path_at(artifact, &["path"])?);
        let measurement = value_at(artifact, &["measurement"])?;
        let Some(filesystem) = measurement.get("filesystem").and_then(Value::as_str) else {
            continue;
        };
        let allocated = u64_at(measurement, &["metrics", "allocated_bytes"])?;
        let private = u64_at(measurement, &["metrics", "private_reclaimable_bytes"])?;
        let measurement_complete = bool_at(measurement, &["complete"])?
            && bool_at(measurement, &["metrics", "private_reclaimable_complete"])?;
        let cleanup_action = string_at(artifact, &["cleanup_action"])?;
        let rebuildable_opportunity =
            envelope.manifest_version >= 2 && bool_at(artifact, &["rebuildable_opportunity"])?;
        let totals = by_filesystem.entry(filesystem.to_owned()).or_default();
        totals.0 = totals.0.saturating_add(allocated);
        totals.2 += 1;
        totals.4 += usize::from(!measurement_complete);
        if cleanup_action == "delete" {
            totals.1 = totals.1.saturating_add(private);
            totals.3 += 1;
        }
        if rebuildable_opportunity {
            let rebuild_cost = string_at(artifact, &["rebuild_cost"])?;
            anyhow::ensure!(
                matches!(rebuild_cost.as_str(), "low" | "medium" | "high"),
                "generated artifact has unsupported rebuild cost {rebuild_cost:?}"
            );
            let opportunity = rebuildable_by_filesystem_cost
                .entry((filesystem.to_owned(), rebuild_cost))
                .or_default();
            opportunity.0 = opportunity.0.saturating_add(private);
            opportunity.1 += 1;
            opportunity.2 += usize::from(!measurement_complete);
        }
    }
    owner_paths.sort();
    owner_paths.dedup();

    let mut claims = Vec::new();
    for (index, (filesystem, (allocated, stale_private, artifacts, stale, incomplete))) in
        by_filesystem.into_iter().enumerate()
    {
        claims.push(StorageClaim {
            id: format!("generated-allocation-{index}"),
            label: format!("Generated-root allocation on {filesystem}"),
            bytes: allocated,
            kind: StorageClaimKind::AllocatedStorage,
            readiness: StorageClaimReadiness::ReportOnly,
            additive: false,
            overlap_group: None,
            filesystem: Some(filesystem.clone()),
            approval_digest: None,
            execution_command: None,
            evidence: format!(
                "{artifacts} Git-owned generated roots measured under a bounded APFS inventory; {incomplete} measurements are lower bounds"
            ),
        });
        for cost in ["low", "medium", "high"] {
            let Some((private, opportunities, incomplete_opportunities)) =
                rebuildable_by_filesystem_cost.remove(&(filesystem.clone(), cost.to_string()))
            else {
                continue;
            };
            claims.push(StorageClaim {
                id: format!("generated-rebuildable-{cost}-private-{index}"),
                label: format!(
                    "Review-only {cost} rebuild-cost generated roots on {filesystem}"
                ),
                bytes: private,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: None,
                filesystem: Some(filesystem.clone()),
                approval_digest: None,
                execution_command: None,
                evidence: format!(
                    "{opportunities} configured roots have no tracked files, protection, or open owner; {incomplete_opportunities} measurements are lower bounds; accepting rebuild cost still requires a fresh cleanup plan and explicit review"
                ),
            });
        }
        claims.push(StorageClaim {
            id: format!("generated-stale-private-{index}"),
            label: format!("Generated roots classified stale on {filesystem}"),
            bytes: stale_private,
            kind: StorageClaimKind::ApfsPrivateReclaim,
            readiness: StorageClaimReadiness::ReportOnly,
            additive: false,
            overlap_group: None,
            filesystem: Some(filesystem),
            approval_digest: None,
            execution_command: None,
            evidence: format!(
                "{stale} roots met cleanup's current classification; private bytes remain a lower bound when measurements are incomplete, and this inventory is not an executable mutation manifest"
            ),
        });
    }

    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims,
        warnings: vec![
            "generated-root allocation overlaps the broad inventory and may overlap owner-specific collectors"
                .into(),
            "generated-root allocation is summed per root and is non-additive because hard-linked or shared content can overlap across roots"
                .into(),
            "cleanup classifications are orientation evidence; produce and approve a fresh cleanup manifest before mutation"
                .into(),
            "rebuildable opportunities are owner-free observations, not stale classifications or deletion permission; each accepted rebuild cost still needs an exact reviewed action"
                .into(),
        ],
    })
}

fn cargo_profile_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 1,
        "Cargo profile opportunity manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let candidates = array_at(&envelope.plan, &["candidates"])?;
    let private_complete = bool_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_complete"],
    )?;
    let bytes = u64_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_bytes"],
    )?;
    let approval_digest = optional_string_at(&envelope.plan, &["eligibility_digest"]);
    let valid_approval_digest = approval_digest.as_deref().is_some_and(valid_sha256_digest);
    let invalid_approval_digest = approval_digest.is_some() && !valid_approval_digest;
    let generated_manifest = path_at(&envelope.source, &["generated_manifest"])?;
    let source_sha256 = string_at(&envelope.source, &["generated_manifest_sha256"])?;
    let max_entries = u64_at(&envelope.policy, &["max_entries"])?;
    let mut owner_paths = candidates
        .iter()
        .map(|candidate| path_at(candidate, &["profile_path"]))
        .collect::<Result<Vec<_>>>()?;
    owner_paths.sort();
    owner_paths.dedup();
    let filesystems = candidates
        .iter()
        .map(|candidate| string_at(candidate, &["filesystem"]))
        .collect::<Result<BTreeSet<_>>>()?;
    let filesystem = filesystems.iter().next().cloned().or_else(|| {
        owner_paths
            .first()
            .and_then(|owner_path| filesystem_for_path(owner_path, inventory))
    });
    let reviewable = envelope.mode == "dry_run"
        && complete
        && private_complete
        && action == "report_only"
        && bytes > 0
        && filesystems.len() == 1
        && !filesystems.contains("unknown")
        && valid_approval_digest;
    let execution_command = approval_digest.as_ref().map(|digest| {
        vec![
            "worktree-gc".into(),
            "collect".into(),
            "cargo-profiles".into(),
            "--generated-manifest".into(),
            generated_manifest.display().to_string(),
            "--max-entries".into(),
            max_entries.to_string(),
            "--execute".into(),
            "--approved-digest".into(),
            digest.clone(),
        ]
    });
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![StorageClaim {
            id: "cargo-profile-opportunity-reset".into(),
            label: "Explicitly reviewed rebuildable Cargo profiles".into(),
            bytes,
            kind: StorageClaimKind::ApfsPrivateReclaim,
            readiness: if reviewable {
                StorageClaimReadiness::ApprovalReady
            } else {
                StorageClaimReadiness::ReportOnly
            },
            additive: reviewable,
            overlap_group: None,
            filesystem,
            approval_digest,
            execution_command: reviewable.then_some(execution_command).flatten(),
            evidence: format!(
                "{} direct debug/release profiles derived from generated manifest {} ({source_sha256}); profile identities, APFS measurements, open handles, protections, and Cargo locks are revalidated",
                candidates.len(),
                generated_manifest.display()
            ),
        }],
        warnings: {
            let mut warnings = vec![
                "profile bytes are a precise executable subset of the broader generated-root report and must not be added to that report-only observation"
                    .into(),
                "explicit approval accepts rebuild cost even when profile activity is newer than routine TTL policy"
                    .into(),
                "execution remains manual: approve one exact dry-run digest, then revalidate source-manifest identity, Git ownership, profile identity, open handles, protections, and Cargo locks"
                    .into(),
            ];
            if invalid_approval_digest {
                warnings.push("Cargo profile approval digest is not a full sha256 digest".into());
            }
            warnings
        },
    })
}

fn bambu_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 4,
        "Bambu manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let owner_declared_default_roots = bool_at(&envelope.bambu, &["owner_declared_default_roots"])?;
    let log_roots = array_at(&envelope.bambu, &["log_roots"])?;
    let candidates = array_at(&envelope.plan, &["candidates"])?;
    let retained = array_at(&envelope.plan, &["retained"])?;
    let private_complete = bool_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_complete"],
    )?;
    let bytes = u64_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_bytes"],
    )?;
    let approval_digest = optional_string_at(&envelope.plan, &["eligibility_digest"]);
    let valid_approval_digest = approval_digest.as_deref().is_some_and(valid_sha256_digest);

    let mut owner_paths = log_roots
        .iter()
        .map(|root| path_at(root, &["path"]))
        .collect::<Result<Vec<_>>>()?;
    owner_paths.extend(
        candidates
            .iter()
            .chain(retained.iter())
            .map(|candidate| path_at(candidate, &["path"]))
            .collect::<Result<Vec<_>>>()?,
    );
    owner_paths.sort();
    owner_paths.dedup();

    let candidate_filesystems = candidates
        .iter()
        .map(|candidate| string_at(candidate, &["filesystem"]))
        .collect::<Result<BTreeSet<_>>>()?;
    let filesystem = candidate_filesystems.iter().next().cloned();
    let execution_compatible = candidate_filesystems.len() == 1
        && !candidate_filesystems.contains("unknown")
        && owner_declared_default_roots;
    let reviewable = envelope.mode == "dry_run"
        && complete
        && private_complete
        && action == "report_only"
        && bytes > 0
        && execution_compatible
        && valid_approval_digest;
    let mut warnings = vec![
        "only recognized encrypted diagnostic-log names are included; application state, presets, plugins, projects, and printers are excluded"
            .into(),
        "this stack can compose Bambu diagnostics evidence but does not yet include the Bambu owner executor; claims remain review-required"
            .into(),
    ];
    if !owner_declared_default_roots {
        warnings.push(
            "custom Bambu roots are inventory-only and cannot enter a reclaim projection".into(),
        );
    }
    if candidate_filesystems.len() > 1 {
        warnings.push("Bambu execution currently requires one candidate filesystem".into());
    }
    if approval_digest.is_some() && !valid_approval_digest {
        warnings.push("Bambu approval digest is not a full sha256 digest".into());
    }
    let claim_filesystem = filesystem.or_else(|| {
        owner_paths
            .first()
            .and_then(|owner_path| filesystem_for_path(owner_path, inventory))
    });

    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![StorageClaim {
            id: "bambu-expired-diagnostics".into(),
            label: "Expired Bambu Studio encrypted diagnostic logs".into(),
            bytes,
            kind: StorageClaimKind::ApfsPrivateReclaim,
            readiness: if reviewable {
                StorageClaimReadiness::ReviewRequired
            } else {
                StorageClaimReadiness::ReportOnly
            },
            additive: reviewable,
            overlap_group: None,
            filesystem: claim_filesystem,
            approval_digest,
            execution_command: None,
            evidence: format!(
                "{} exact expired files, complete process/open-handle/protection/APFS evidence required",
                candidates.len()
            ),
        }],
        warnings,
    })
}

/// Compose exact owner classification without turning it into cleanup authority.
fn pnpm_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let point_in_time = bool_at(
        &envelope.plan,
        &["content_evidence", "point_in_time_complete"],
    )?;
    let approval_digest = optional_string_at(&envelope.plan, &["approval_digest"]);
    let valid_approval_digest = approval_digest.as_deref().is_some_and(valid_sha256_digest);
    let private_complete = bool_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_complete"],
    )?;
    let bytes = u64_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_bytes"],
    )?;
    let filesystem_ids = array_at(&envelope.plan, &["filesystems"])?
        .iter()
        .map(|filesystem| string_at(filesystem, &["filesystem"]))
        .collect::<Result<BTreeSet<_>>>()?;
    let filesystem = (filesystem_ids.len() == 1 && !filesystem_ids.contains("unknown"))
        .then(|| filesystem_ids.iter().next().cloned())
        .flatten();
    let store_path = path_at(&envelope.pnpm, &["store_path"])?;
    let cache_path = path_at(&envelope.pnpm, &["cache_path"])?;
    let dlx_days = u64_at(&envelope.policy, &["dlx_days"])?;
    let max_entries = u64_at(&envelope.policy, &["max_entries"])?;
    let scan_threads = u64_at(&envelope.policy, &["scan_threads"])?;
    let approval_ready = envelope.mode == "dry_run"
        && envelope.manifest_version >= 4
        && complete
        && point_in_time
        && private_complete
        && action == "delegate"
        && valid_approval_digest
        && filesystem.is_some();
    let mut warnings = Vec::new();
    if !point_in_time {
        warnings.push("pnpm evidence includes historical prefix observations".into());
    }
    if envelope.manifest_version < 4 {
        warnings.push("pnpm manifest predates the digest-bound approval contract".into());
    }
    if approval_digest.is_some() && !valid_approval_digest {
        warnings.push("pnpm approval digest is not a full sha256 digest".into());
    }
    if filesystem.is_none() {
        warnings.push(
            "pnpm reclaim does not map to exactly one known filesystem and cannot enter a free-space projection"
                .into(),
        );
    }
    let execution_command = approval_digest.as_ref().map(|digest| {
        vec![
            "worktree-gc".into(),
            "collect".into(),
            "pnpm".into(),
            "--execute".into(),
            "--dlx-days".into(),
            dlx_days.to_string(),
            "--max-entries".into(),
            max_entries.to_string(),
            "--scan-threads".into(),
            scan_threads.to_string(),
            "--approved-digest".into(),
            digest.clone(),
        ]
    });
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths: vec![store_path, cache_path],
        inventory_matches: Vec::new(),
        claims: vec![StorageClaim {
            id: "pnpm-store-prune".into(),
            label: "pnpm-maintained store and cache prune plan".into(),
            bytes,
            kind: StorageClaimKind::ApfsPrivateReclaim,
            readiness: if approval_ready {
                StorageClaimReadiness::ApprovalReady
            } else {
                StorageClaimReadiness::ReportOnly
            },
            additive: approval_ready,
            overlap_group: None,
            filesystem,
            approval_digest,
            execution_command: approval_ready.then_some(execution_command).flatten(),
            evidence: if point_in_time {
                "current-run APFS-private candidate measurement".into()
            } else {
                "historical lower-bound candidate measurement".into()
            },
        }],
        warnings,
    })
}

fn lima_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        matches!(envelope.manifest_version, 3 | 4),
        "Lima manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let private_complete = bool_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_complete"],
    )?;
    let bytes = u64_at(
        &envelope.plan,
        &["expected_reclaim", "private_reclaimable_bytes"],
    )?;
    let cache_path = path_at(&envelope.lima, &["cache_path"])?;
    let _lima_home = path_at(&envelope.lima, &["lima_home"])?;
    let mut owner_paths = vec![cache_path.clone()];
    if action == "retire_domain" {
        if let Ok(instances) = array_at(&envelope.lima, &["instances"]) {
            for instance in instances {
                owner_paths.push(path_at(instance, &["directory"])?);
            }
        }
    }
    owner_paths.sort();
    owner_paths.dedup();

    let retirement_reviewable = envelope.mode == "dry_run"
        && complete
        && private_complete
        && bytes > 0
        && action == "retire_domain";
    let raw_approval_digest = optional_string_at(&envelope.plan, &["approval_digest"]);
    let approval_digest = raw_approval_digest
        .as_deref()
        .filter(|digest| valid_sha256_digest(digest))
        .map(str::to_owned);
    let legacy_reviewable = envelope.mode == "dry_run"
        && complete
        && private_complete
        && bytes > 0
        && action == "delegate_download_cache"
        && approval_digest.is_some();
    let observed_filesystems = owner_paths
        .iter()
        .map(|owner_path| filesystem_for_path(owner_path, inventory))
        .collect::<Vec<_>>();
    let filesystems = observed_filesystems
        .iter()
        .filter_map(|filesystem| filesystem.clone())
        .collect::<BTreeSet<_>>();
    let all_owner_filesystems_observed = observed_filesystems.iter().all(Option::is_some);
    let filesystem = if all_owner_filesystems_observed && filesystems.len() == 1 {
        filesystems.iter().next().cloned()
    } else {
        None
    };
    let retirement_digest_bound = retirement_reviewable && approval_digest.is_some();
    let approval_ready = retirement_digest_bound && filesystem.is_some();
    let reviewable = legacy_reviewable || retirement_reviewable;
    let execution_command = if retirement_digest_bound {
        approval_digest.as_ref().map(|digest| {
            vec![
                "worktree-gc".into(),
                "collect".into(),
                "lima".into(),
                "--retire".into(),
                "--execute".into(),
                "--approved-digest".into(),
                digest.clone(),
            ]
        })
    } else if legacy_reviewable {
        approval_digest.as_ref().map(|digest| {
            vec![
                "worktree-gc".into(),
                "collect".into(),
                "lima".into(),
                "--execute".into(),
                "--approved-digest".into(),
                digest.clone(),
            ]
        })
    } else {
        None
    };
    let mut warnings = reviewable
        .then(|| "review the Lima manifest immediately before separate execution approval".into())
        .into_iter()
        .collect::<Vec<_>>();
    if raw_approval_digest.is_some() && approval_digest.is_none() {
        warnings.push("Lima approval digest is not a full sha256 digest".into());
    }
    if retirement_reviewable && !all_owner_filesystems_observed {
        warnings.push(
            "Lima retirement owner paths are not all covered by the inventory manifest".into(),
        );
    } else if retirement_reviewable && filesystem.is_none() {
        warnings.push(
            "Lima retirement owner paths do not map to exactly one observed filesystem".into(),
        );
    }
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![StorageClaim {
            id: if retirement_reviewable {
                "lima-domain-retirement".into()
            } else {
                "lima-download-cache".into()
            },
            label: if retirement_reviewable {
                "Lima stopped-instance and download-cache retirement".into()
            } else {
                "Lima-rehearsed unreferenced download cache".into()
            },
            bytes,
            kind: StorageClaimKind::ApfsPrivateReclaim,
            readiness: if approval_ready {
                StorageClaimReadiness::ApprovalReady
            } else if reviewable {
                StorageClaimReadiness::ReviewRequired
            } else {
                StorageClaimReadiness::ReportOnly
            },
            additive: reviewable && filesystem.is_some(),
            overlap_group: None,
            filesystem,
            approval_digest,
            execution_command,
            evidence: if retirement_reviewable {
                "current APFS-private stopped-instance and download-cache measurement with exact digest-bound owner retirement"
                    .into()
            } else {
                "current APFS-private candidate measurement with digest-bound owner execution; Lima exposes no atomic download/prune lock"
                    .into()
            },
        }],
        warnings,
    })
}

fn docker_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let host_path = path_at(&envelope.plan, &["host_observation", "domain_storage_path"])?;
    let filesystem = optional_string_at(&envelope.plan, &["host_observation", "filesystem"]);
    let overlap_group = format!("docker-backing-store:{}", host_path.display());
    let build_cache = u64_at(&envelope.plan, &["docker_build_cache_reclaimable_bytes"])?;
    let images = u64_at(&envelope.plan, &["image_unique_reclaim_bytes"])?;
    let backing = u64_at(
        &envelope.plan,
        &[
            "host_observation",
            "orbstack_sparse_disk",
            "allocated_bytes",
        ],
    )?;
    let claims = vec![
        StorageClaim {
            id: "docker-build-cache".into(),
            label: "Docker-reported reclaimable BuildKit records".into(),
            bytes: build_cache,
            kind: StorageClaimKind::OwnerReportedReclaim,
            readiness: StorageClaimReadiness::ReviewRequired,
            additive: false,
            overlap_group: Some(overlap_group.clone()),
            filesystem: filesystem.clone(),
            approval_digest: optional_string_at(&envelope.plan, &["eligibility_digest"]),
            execution_command: None,
            evidence: "Docker record sizes overlap and are not a physical reclaim guarantee".into(),
        },
        StorageClaim {
            id: "docker-unused-images".into(),
            label: "Docker-reported unique unused-image content".into(),
            bytes: images,
            kind: StorageClaimKind::OwnerReportedReclaim,
            readiness: StorageClaimReadiness::ReportOnly,
            additive: false,
            overlap_group: Some(overlap_group.clone()),
            filesystem: filesystem.clone(),
            approval_digest: None,
            execution_command: None,
            evidence: "image cleanup remains report-only and overlaps the same sparse disk".into(),
        },
        StorageClaim {
            id: "docker-backing-storage".into(),
            label: "OrbStack sparse-disk host allocation".into(),
            bytes: backing,
            kind: StorageClaimKind::AllocatedStorage,
            readiness: StorageClaimReadiness::ReportOnly,
            additive: false,
            overlap_group: Some(overlap_group),
            filesystem,
            approval_digest: None,
            execution_command: None,
            evidence: "observed owner storage, not a deletion claim".into(),
        },
    ];
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths: vec![host_path],
        inventory_matches: Vec::new(),
        claims,
        warnings: vec![
            "Docker build-cache, image, and sparse-disk values are non-additive views of one backing store"
                .into(),
            "this stack can compose historical Docker evidence but does not include a Docker owner executor; all Docker claims remain non-additive"
                .into(),
        ],
    })
}

fn parallels_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 2,
        "Parallels manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let action = string_at(&envelope.plan, &["action"])?;
    let vms = array_at(&envelope.plan, &["vms"])?;
    let private_bytes = u64_at(
        &envelope.plan,
        &["total_vm_metrics", "private_reclaimable_bytes"],
    )?;
    let allocated_bytes = u64_at(&envelope.plan, &["total_vm_metrics", "allocated_bytes"])?;
    let private_complete = bool_at(
        &envelope.plan,
        &["total_vm_metrics", "private_reclaimable_complete"],
    )?;
    let compactable_bytes = u64_at(&envelope.plan, &["estimated_host_reclaim_bytes"])?;
    let mut owner_paths = Vec::new();
    let mut statuses = BTreeSet::new();
    let mut non_stopped = 0usize;
    for vm in vms {
        owner_paths.push(path_at(vm, &["home"])?);
        let status = string_at(vm, &["status"])?;
        if !status.eq_ignore_ascii_case("stopped") {
            non_stopped += 1;
        }
        statuses.insert(status);
        for disk in array_at(vm, &["disks"])? {
            owner_paths.push(path_at(disk, &["path"])?);
        }
    }
    owner_paths.sort();
    owner_paths.dedup();
    let filesystems = owner_paths
        .iter()
        .map(|owner_path| filesystem_for_path(owner_path, inventory))
        .collect::<Option<BTreeSet<_>>>();
    let filesystem = filesystems
        .as_ref()
        .filter(|filesystems| filesystems.len() == 1)
        .and_then(|filesystems| filesystems.iter().next().cloned());
    let overlap_group = "parallels-vm-storage".to_string();
    let mut warnings = vec![
        "Parallels VM disks are durable owner state; this collector never stops, resumes, compacts, or deletes a VM".into(),
        format!("{non_stopped} VMs are not stopped, so even owner-estimated compaction remains held"),
        "APFS-private bytes, path allocation, and owner-estimated compactable bytes are overlapping evidence, not additive reclaim".into(),
    ];
    if !statuses.is_empty() {
        warnings.push(format!(
            "observed Parallels VM states: {}",
            statuses.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }
    if filesystem.is_none() {
        warnings.push(
            "not every Parallels owner path maps to one observed inventory filesystem".into(),
        );
    }
    if !private_complete {
        warnings.push("Parallels APFS-private storage is an incomplete lower bound".into());
    }
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![
            StorageClaim {
                id: "parallels-vm-private-storage".into(),
                label: format!("Parallels VM APFS-private storage ({} VMs)", vms.len()),
                bytes: private_bytes,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group.clone()),
                filesystem: filesystem.clone(),
                approval_digest: None,
                execution_command: None,
                evidence: "bounded APFS measurement of durable Parallels-owned VM homes and disks; private storage is not deletion permission".into(),
            },
            StorageClaim {
                id: "parallels-vm-allocated-storage".into(),
                label: "Parallels VM path allocation".into(),
                bytes: allocated_bytes,
                kind: StorageClaimKind::AllocatedStorage,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group.clone()),
                filesystem: filesystem.clone(),
                approval_digest: None,
                execution_command: None,
                evidence: "path allocation is an orientation view of the same durable VM backing store and must not be added to APFS-private bytes".into(),
            },
            StorageClaim {
                id: "parallels-owner-compaction-estimate".into(),
                label: "Parallels owner-estimated compactable VM storage".into(),
                bytes: compactable_bytes,
                kind: StorageClaimKind::OwnerReportedReclaim,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group),
                filesystem,
                approval_digest: None,
                execution_command: None,
                evidence: "prl_disk_tool compact --info estimate capped by APFS-private bytes; no stop, compact, or delete operation is delegated".into(),
            },
        ],
        warnings,
    })
}

fn codex_session_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 1,
        "Codex session manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let action = string_at(&envelope.plan, &["action"])?;
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let sessions_root = path_at(&envelope.identity, &["sessions_root"])?;
    let archived_root = path_at(&envelope.identity, &["archived_sessions_root"])?;
    let owner_paths = vec![sessions_root.clone(), archived_root.clone()];
    let live_bytes = u64_at(&envelope.plan, &["live", "metrics", "allocated_bytes"])?;
    let archived_bytes = u64_at(&envelope.plan, &["archived", "metrics", "allocated_bytes"])?;
    let live_count = u64_at(&envelope.plan, &["live", "count"])?;
    let archived_count = u64_at(&envelope.plan, &["archived", "count"])?;
    let mut warnings = vec![
        "Codex session transcripts are canonical user conversation state; file age and archive state do not authorize deletion"
            .into(),
        "the owner collector does not read transcript content and has no deletion executor; retention requires a Codex export or retention contract"
            .into(),
    ];
    if !complete {
        warnings.push("Codex session inventory is incomplete and remains a lower bound".into());
    }
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action,
        reason: string_at(&envelope.plan, &["reason"])?,
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![
            StorageClaim {
                id: "codex-live-sessions".into(),
                label: format!("Codex live session storage ({live_count} sessions)"),
                bytes: live_bytes,
                kind: StorageClaimKind::AllocatedStorage,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: None,
                filesystem: filesystem_for_path(&sessions_root, inventory),
                approval_digest: None,
                execution_command: None,
                evidence: format!("allocated transcript storage below {}; transcript content was not read", sessions_root.display()),
            },
            StorageClaim {
                id: "codex-archived-sessions".into(),
                label: format!("Codex archived session storage ({archived_count} sessions)"),
                bytes: archived_bytes,
                kind: StorageClaimKind::AllocatedStorage,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: None,
                filesystem: filesystem_for_path(&archived_root, inventory),
                approval_digest: None,
                execution_command: None,
                evidence: format!("allocated archived transcript storage below {}; archive state is not deletion permission", archived_root.display()),
            },
        ],
        warnings,
    })
}

fn codex_worktree_evidence(
    path: &Path,
    envelope: CollectorEnvelope,
    inventory: &InventoryReport,
    now_unix: u64,
) -> Result<StorageCollectorEvidence> {
    anyhow::ensure!(
        envelope.manifest_version == 1,
        "Codex worktree manifest {} has unsupported version {}",
        path.display(),
        envelope.manifest_version
    );
    let complete = bool_at(&envelope.plan, &["complete"])?;
    let worktrees = array_at(&envelope.plan, &["worktrees"])?;
    let review_candidates = array_at(&envelope.plan, &["review_candidates"])?;
    let mut owner_paths = worktrees
        .iter()
        .map(|worktree| path_at(worktree, &["path"]))
        .collect::<Result<Vec<_>>>()?;
    owner_paths.sort();
    owner_paths.dedup();
    let total_private = u64_at(
        &envelope.plan,
        &["total_metrics", "private_reclaimable_bytes"],
    )?;
    let total_allocated = u64_at(&envelope.plan, &["total_metrics", "allocated_bytes"])?;
    let review_private = u64_at(
        &envelope.plan,
        &["review_candidate_metrics", "private_reclaimable_bytes"],
    )?;
    let filesystems = owner_paths
        .iter()
        .map(|owner_path| filesystem_for_path(owner_path, inventory))
        .collect::<Option<BTreeSet<_>>>();
    let filesystem = filesystems
        .as_ref()
        .filter(|filesystems| filesystems.len() == 1)
        .and_then(|filesystems| filesystems.iter().next().cloned());
    let overlap_group = "codex-worktree-storage".to_string();
    let action = if !complete {
        "incomplete"
    } else if review_candidates.is_empty() {
        "report_only"
    } else {
        "review_only"
    };
    let reason = if !complete {
        "bounded Codex worktree evidence is incomplete; totals are lower bounds"
    } else if review_candidates.is_empty() {
        "Codex task, Git, process, and age evidence found no whole-worktree review candidates"
    } else {
        "clean Codex worktrees without active task or process ownership require human review"
    };
    Ok(StorageCollectorEvidence {
        collector: envelope.collector,
        manifest_path: path.to_path_buf(),
        manifest_version: envelope.manifest_version,
        generated_at_unix: envelope.generated_at_unix,
        age_seconds: now_unix.saturating_sub(envelope.generated_at_unix),
        mode: envelope.mode,
        complete,
        action: action.into(),
        reason: reason.into(),
        owner_paths,
        inventory_matches: Vec::new(),
        claims: vec![
            StorageClaim {
                id: "codex-worktree-private-storage".into(),
                label: format!("Codex-managed worktree APFS-private storage ({} worktrees)", worktrees.len()),
                bytes: total_private,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group.clone()),
                filesystem: filesystem.clone(),
                approval_digest: None,
                execution_command: None,
                evidence: "Codex state, Git, process, protection, and bounded APFS inventory evidence; total storage is not deletion permission".into(),
            },
            StorageClaim {
                id: "codex-worktree-allocated-storage".into(),
                label: "Codex-managed worktree path allocation".into(),
                bytes: total_allocated,
                kind: StorageClaimKind::AllocatedStorage,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group.clone()),
                filesystem: filesystem.clone(),
                approval_digest: None,
                execution_command: None,
                evidence: "path allocation is retained for orientation and may overstate APFS reclaim because of clones and hard links".into(),
            },
            StorageClaim {
                id: "codex-worktree-review-private-storage".into(),
                label: format!("Whole Codex worktrees eligible for human review ({})", review_candidates.len()),
                bytes: review_private,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ReportOnly,
                additive: false,
                overlap_group: Some(overlap_group),
                filesystem,
                approval_digest: None,
                execution_command: None,
                evidence: "task state, Git state, activity, open owners, protections, and measurement completeness are advisory inputs; whole removal remains owner-mediated".into(),
            },
        ],
        warnings: vec![
            "Codex worktree age and archive state are review signals, not unattended deletion authority".into(),
            "generated artifacts inside retained worktrees belong to the generated/Cargo profile collectors and must not be added to this allocation"
                .into(),
            "all claims overlap and remain report-only until Codex owns a worktree release contract".into(),
        ],
    })
}

fn filesystem_goals(
    inventory: &InventoryReport,
    collectors: &[StorageCollectorEvidence],
    targets: &[u64],
) -> Result<Vec<StorageFilesystemGoal>> {
    let mut roots = BTreeMap::<String, PathBuf>::new();
    for root in &inventory.roots {
        roots
            .entry(root.filesystem.clone())
            .or_insert_with(|| root.path.clone());
    }
    let mut targets = targets.to_vec();
    targets.sort_unstable();
    targets.dedup();
    let mut goals = Vec::new();
    for (filesystem, observed_at) in roots {
        let available = fs4::available_space(&observed_at)
            .with_context(|| format!("observe free space at {}", observed_at.display()))?;
        let total = fs4::total_space(&observed_at)
            .with_context(|| format!("observe total space at {}", observed_at.display()))?;
        let approval = additive_reclaim(
            collectors,
            StorageClaimReadiness::ApprovalReady,
            Some(&filesystem),
        );
        let review = additive_reclaim(
            collectors,
            StorageClaimReadiness::ReviewRequired,
            Some(&filesystem),
        );
        for target in &targets {
            let projected_after_approval = available.saturating_add(approval).min(total);
            let projected_after_review = projected_after_approval.saturating_add(review).min(total);
            goals.push(StorageFilesystemGoal {
                filesystem: filesystem.clone(),
                observed_at: observed_at.clone(),
                available_bytes: available,
                total_bytes: total,
                target_free_bytes: *target,
                current_shortfall_bytes: target.saturating_sub(available),
                approval_ready_reclaim_bytes: approval,
                projected_after_approval_bytes: projected_after_approval,
                shortfall_after_approval_bytes: target.saturating_sub(projected_after_approval),
                review_required_reclaim_bytes: review,
                projected_after_review_bytes: projected_after_review,
                shortfall_after_review_bytes: target.saturating_sub(projected_after_review),
            });
        }
    }
    Ok(goals)
}

fn additive_reclaim(
    collectors: &[StorageCollectorEvidence],
    readiness: StorageClaimReadiness,
    filesystem: Option<&str>,
) -> u64 {
    collectors
        .iter()
        .flat_map(|collector| &collector.claims)
        .filter(|claim| {
            claim.additive
                && claim.readiness == readiness
                && filesystem.is_none_or(|expected| claim.filesystem.as_deref() == Some(expected))
        })
        .fold(0_u64, |total, claim| total.saturating_add(claim.bytes))
}

fn overlap_groups(collectors: &[StorageCollectorEvidence]) -> Vec<StorageOverlapGroup> {
    let mut groups = BTreeMap::<String, Vec<&StorageClaim>>::new();
    for claim in collectors.iter().flat_map(|collector| &collector.claims) {
        if let Some(group) = &claim.overlap_group {
            groups.entry(group.clone()).or_default().push(claim);
        }
    }
    groups
        .into_iter()
        .map(|(id, claims)| StorageOverlapGroup {
            id,
            claim_ids: claims.iter().map(|claim| claim.id.clone()).collect(),
            largest_claim_bytes: claims.iter().map(|claim| claim.bytes).max().unwrap_or(0),
            warning:
                "largest claim shown for orientation only; claims overlap and must not be summed"
                    .into(),
        })
        .collect()
}

fn filesystem_for_path(path: &Path, inventory: &InventoryReport) -> Option<String> {
    inventory
        .roots
        .iter()
        .filter(|root| path.starts_with(&root.path))
        .max_by_key(|root| root.path.components().count())
        .map(|root| root.filesystem.clone())
}

fn inventory_match(path: &Path, inventory: &InventoryReport) -> Option<StorageInventoryMatch> {
    let mut candidates = inventory
        .roots
        .iter()
        .flat_map(|root| {
            let root_complete = root.complete
                && root.errors.is_empty()
                && root.metrics.private_reclaimable_complete;
            std::iter::once((root.path.as_path(), &root.metrics, root_complete)).chain(
                root.entries.iter().map(move |entry| {
                    (
                        entry.path.as_path(),
                        &entry.metrics,
                        root_complete && entry.metrics.private_reclaimable_complete,
                    )
                }),
            )
        })
        .filter(|(observed, _, _)| path.starts_with(observed))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(observed, _, _)| observed.components().count());
    let (observed_path, metrics, complete) = candidates.pop()?;
    Some(StorageInventoryMatch {
        owner_path: path.to_path_buf(),
        observed_path: observed_path.to_path_buf(),
        relation: if observed_path == path {
            "exact".into()
        } else {
            "within".into()
        },
        complete,
        metrics: metrics.clone(),
    })
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path, kind: &str) -> Result<T> {
    serde_json::from_slice(
        &fs::read(path).with_context(|| format!("read {kind} {}", path.display()))?,
    )
    .with_context(|| format!("parse {kind} {}", path.display()))
}

fn value_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut current = value;
    for component in path {
        current = if let Ok(index) = component.parse::<usize>() {
            current
                .as_array()
                .and_then(|array| array.get(index))
                .with_context(|| {
                    format!(
                        "missing array element {} in collector manifest",
                        path.join(".")
                    )
                })?
        } else {
            current.get(*component).with_context(|| {
                format!("missing field {} in collector manifest", path.join("."))
            })?
        };
    }
    Ok(current)
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Vec<Value>> {
    value_at(value, path)?
        .as_array()
        .with_context(|| format!("field {} is not an array", path.join(".")))
}

fn string_at(value: &Value, path: &[&str]) -> Result<String> {
    value_at(value, path)?
        .as_str()
        .map(str::to_owned)
        .with_context(|| format!("field {} is not a string", path.join(".")))
}

fn optional_string_at(value: &Value, path: &[&str]) -> Option<String> {
    value_at(value, path).ok()?.as_str().map(str::to_owned)
}

fn bool_at(value: &Value, path: &[&str]) -> Result<bool> {
    value_at(value, path)?
        .as_bool()
        .with_context(|| format!("field {} is not a boolean", path.join(".")))
}

fn u64_at(value: &Value, path: &[&str]) -> Result<u64> {
    value_at(value, path)?
        .as_u64()
        .with_context(|| format!("field {} is not an unsigned integer", path.join(".")))
}

fn path_at(value: &Value, path: &[&str]) -> Result<PathBuf> {
    string_at(value, path).map(PathBuf::from)
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approval_collector(name: &str, owner_path: &str) -> StorageCollectorEvidence {
        StorageCollectorEvidence {
            collector: name.into(),
            manifest_path: PathBuf::from(format!("{name}.json")),
            manifest_version: 1,
            generated_at_unix: 100,
            age_seconds: 10,
            mode: "dry_run".into(),
            complete: true,
            action: "report_only".into(),
            reason: "test".into(),
            owner_paths: vec![PathBuf::from(owner_path)],
            inventory_matches: Vec::new(),
            claims: vec![StorageClaim {
                id: format!("{name}-claim"),
                label: name.into(),
                bytes: 10,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ApprovalReady,
                additive: true,
                overlap_group: None,
                filesystem: Some("fs".into()),
                approval_digest: Some(format!("sha256:{}", "a".repeat(64))),
                execution_command: Some(vec!["worktree-gc".into()]),
                evidence: "test".into(),
            }],
            warnings: Vec::new(),
        }
    }

    fn complete_inventory(path: &str) -> InventoryReport {
        InventoryReport {
            inventory_version: INVENTORY_VERSION,
            generated_at_unix: 1,
            options: crate::InventoryReportOptions {
                display_depth: 2,
                top: 20,
                max_entries: 100,
                one_filesystem: true,
            },
            roots: vec![crate::InventoryRoot {
                path: PathBuf::from(path),
                filesystem: "fs".into(),
                complete: true,
                visited_entries: 1,
                metrics: InventoryMetrics {
                    private_reclaimable_complete: true,
                    ..InventoryMetrics::default()
                },
                entries: Vec::new(),
                errors: Vec::new(),
            }],
        }
    }

    #[test]
    fn overlap_groups_never_sum_backing_store_views() {
        let collector = StorageCollectorEvidence {
            collector: "docker".into(),
            manifest_path: PathBuf::from("docker.json"),
            manifest_version: 1,
            generated_at_unix: 1,
            age_seconds: 1,
            mode: "dry_run".into(),
            complete: true,
            action: "report_only".into(),
            reason: "test".into(),
            owner_paths: Vec::new(),
            inventory_matches: Vec::new(),
            claims: vec![
                StorageClaim {
                    id: "cache".into(),
                    label: "cache".into(),
                    bytes: 4,
                    kind: StorageClaimKind::OwnerReportedReclaim,
                    readiness: StorageClaimReadiness::ReviewRequired,
                    additive: false,
                    overlap_group: Some("disk".into()),
                    filesystem: Some("fs".into()),
                    approval_digest: None,
                    execution_command: None,
                    evidence: "test".into(),
                },
                StorageClaim {
                    id: "images".into(),
                    label: "images".into(),
                    bytes: 9,
                    kind: StorageClaimKind::OwnerReportedReclaim,
                    readiness: StorageClaimReadiness::ReportOnly,
                    additive: false,
                    overlap_group: Some("disk".into()),
                    filesystem: Some("fs".into()),
                    approval_digest: None,
                    execution_command: None,
                    evidence: "test".into(),
                },
            ],
            warnings: Vec::new(),
        };

        let collectors = vec![collector];
        assert_eq!(
            additive_reclaim(&collectors, StorageClaimReadiness::ReviewRequired, None),
            0
        );
        let groups = overlap_groups(&collectors);
        assert_eq!(groups[0].largest_claim_bytes, 9);
        assert_eq!(groups[0].claim_ids, ["cache", "images"]);
    }

    #[test]
    fn additive_reclaim_is_partitioned_by_readiness_and_filesystem() {
        let claims = vec![
            StorageClaim {
                id: "approved".into(),
                label: "approved".into(),
                bytes: 10,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ApprovalReady,
                additive: true,
                overlap_group: None,
                filesystem: Some("fs-a".into()),
                approval_digest: None,
                execution_command: None,
                evidence: "test".into(),
            },
            StorageClaim {
                id: "review".into(),
                label: "review".into(),
                bytes: 20,
                kind: StorageClaimKind::ApfsPrivateReclaim,
                readiness: StorageClaimReadiness::ReviewRequired,
                additive: true,
                overlap_group: None,
                filesystem: Some("fs-b".into()),
                approval_digest: None,
                execution_command: None,
                evidence: "test".into(),
            },
        ];
        let collector = StorageCollectorEvidence {
            collector: "test".into(),
            manifest_path: PathBuf::from("test.json"),
            manifest_version: 1,
            generated_at_unix: 1,
            age_seconds: 1,
            mode: "dry_run".into(),
            complete: true,
            action: "test".into(),
            reason: "test".into(),
            owner_paths: Vec::new(),
            inventory_matches: Vec::new(),
            claims,
            warnings: Vec::new(),
        };
        assert_eq!(
            additive_reclaim(
                &[collector],
                StorageClaimReadiness::ApprovalReady,
                Some("fs-a")
            ),
            10
        );
    }

    #[test]
    fn stale_and_future_additive_claims_fail_closed() {
        let mut stale = approval_collector("stale", "/tmp/stale");
        stale.age_seconds = 901;
        downgrade_unfresh_additive_claims(&mut stale, 1_001, 900);
        assert_eq!(stale.claims[0].readiness, StorageClaimReadiness::ReportOnly);
        assert!(!stale.claims[0].additive);
        assert!(stale.claims[0].execution_command.is_none());

        let mut future = approval_collector("future", "/tmp/future");
        future.generated_at_unix = 1_002;
        downgrade_unfresh_additive_claims(&mut future, 1_001, 900);
        assert_eq!(
            future.claims[0].readiness,
            StorageClaimReadiness::ReportOnly
        );
        assert!(!future.claims[0].additive);

        let mut stale_review = approval_collector("stale-review", "/tmp/stale-review");
        stale_review.claims[0].readiness = StorageClaimReadiness::ReviewRequired;
        stale_review.claims[0].execution_command = None;
        stale_review.age_seconds = 901;
        downgrade_unfresh_additive_claims(&mut stale_review, 1_001, 900);
        assert_eq!(
            stale_review.claims[0].readiness,
            StorageClaimReadiness::ReportOnly
        );
        assert!(!stale_review.claims[0].additive);
    }

    #[test]
    fn overlapping_additive_collectors_fail_closed_but_remain_visible() {
        let parent = approval_collector("parent", "/tmp/cache");
        let child = approval_collector("child", "/tmp/cache/profile");
        let mut overlapping = vec![parent, child];
        downgrade_overlapping_additive_owner_paths(&mut overlapping);
        assert!(overlapping
            .iter()
            .all(|collector| !collector.claims[0].additive));
        assert!(overlapping.iter().all(|collector| {
            collector.claims[0].readiness == StorageClaimReadiness::ReportOnly
                && collector.claims[0].execution_command.is_none()
        }));
        assert!(overlapping
            .iter()
            .all(|collector| collector.warnings[0].contains("overlaps collector")));

        let left = approval_collector("left", "/tmp/left");
        let right = approval_collector("right", "/tmp/right");
        let mut disjoint = vec![left, right];
        downgrade_overlapping_additive_owner_paths(&mut disjoint);
        assert!(disjoint
            .iter()
            .all(|collector| collector.claims[0].additive));
    }

    #[test]
    fn approval_digest_must_be_a_full_sha256() {
        assert!(valid_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_sha256_digest(&"a".repeat(64)));
        assert!(!valid_sha256_digest("sha256:abc"));
        assert!(!valid_sha256_digest(&format!("sha256:{}", "g".repeat(64))));
    }

    #[test]
    fn owner_paths_correlate_to_the_most_specific_retained_inventory_node() {
        let inventory = InventoryReport {
            inventory_version: INVENTORY_VERSION,
            generated_at_unix: 1,
            options: crate::InventoryReportOptions {
                display_depth: 2,
                top: 20,
                max_entries: 100,
                one_filesystem: true,
            },
            roots: vec![crate::InventoryRoot {
                path: PathBuf::from("/Users/example/Library"),
                filesystem: "fs".into(),
                complete: true,
                visited_entries: 2,
                metrics: InventoryMetrics {
                    private_reclaimable_bytes: 100,
                    private_reclaimable_complete: true,
                    ..InventoryMetrics::default()
                },
                entries: vec![InventoryEntry {
                    path: PathBuf::from("/Users/example/Library/pnpm"),
                    relative_path: PathBuf::from("pnpm"),
                    parent: PathBuf::from("/Users/example/Library"),
                    depth: 1,
                    metrics: InventoryMetrics {
                        private_reclaimable_bytes: 40,
                        private_reclaimable_complete: true,
                        ..InventoryMetrics::default()
                    },
                }],
                errors: Vec::new(),
            }],
        };

        let matched = inventory_match(
            Path::new("/Users/example/Library/pnpm/store/v10"),
            &inventory,
        )
        .unwrap();
        assert_eq!(
            matched.observed_path,
            Path::new("/Users/example/Library/pnpm")
        );
        assert_eq!(matched.relation, "within");
        assert!(matched.complete);
        assert_eq!(matched.metrics.private_reclaimable_bytes, 40);
    }

    #[test]
    fn inventory_matches_preserve_entry_level_private_size_incompleteness() {
        let mut inventory = complete_inventory("/Users/example/Library");
        inventory.roots[0].entries.push(InventoryEntry {
            path: PathBuf::from("/Users/example/Library/cache"),
            relative_path: PathBuf::from("cache"),
            parent: PathBuf::from("/Users/example/Library"),
            depth: 1,
            metrics: InventoryMetrics {
                private_reclaimable_bytes: 40,
                private_reclaimable_complete: false,
                ..InventoryMetrics::default()
            },
        });

        let matched = inventory_match(
            Path::new("/Users/example/Library/cache/component"),
            &inventory,
        )
        .unwrap();

        assert_eq!(
            matched.observed_path,
            Path::new("/Users/example/Library/cache")
        );
        assert!(!matched.complete);
    }

    #[test]
    fn fresh_digest_bound_pnpm_manifest_is_approval_ready() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 4,
            "collector": "pnpm-store",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "pnpm": {
                "store_path": "/tmp/store",
                "cache_path": "/tmp/cache"
            },
            "policy": {
                "dlx_days": 7,
                "max_entries": 1000,
                "scan_threads": 1
            },
            "plan": {
                "action": "delegate",
                "reason": "complete",
                "complete": true,
                "approval_digest": format!("sha256:{}", "a".repeat(64)),
                "content_evidence": { "point_in_time_complete": true },
                "expected_reclaim": {
                    "private_reclaimable_bytes": 42,
                    "private_reclaimable_complete": true
                },
                "filesystems": [{ "filesystem": "fs" }]
            }
        }))?;

        let evidence = pnpm_evidence(Path::new("pnpm.json"), envelope, 200)?;
        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ApprovalReady
        );
        assert!(evidence.claims[0].additive);
        assert_eq!(evidence.claims[0].bytes, 42);
        assert_eq!(
            evidence.claims[0]
                .execution_command
                .as_ref()
                .unwrap()
                .last(),
            evidence.claims[0].approval_digest.as_ref()
        );
        Ok(())
    }

    #[test]
    fn pnpm_reclaim_with_multiple_filesystems_is_not_projected() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 4,
            "collector": "pnpm-store",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "pnpm": {
                "store_path": "/Volumes/store/pnpm",
                "cache_path": "/Users/example/Library/Caches/pnpm"
            },
            "policy": {
                "dlx_days": 7,
                "max_entries": 1000,
                "scan_threads": 1
            },
            "plan": {
                "action": "delegate",
                "reason": "complete but split across volumes",
                "complete": true,
                "approval_digest": format!("sha256:{}", "a".repeat(64)),
                "content_evidence": {"point_in_time_complete": true},
                "expected_reclaim": {
                    "private_reclaimable_bytes": 42,
                    "private_reclaimable_complete": true
                },
                "filesystems": [
                    {"filesystem": "fs-a"},
                    {"filesystem": "fs-b"}
                ]
            }
        }))?;

        let evidence = pnpm_evidence(Path::new("pnpm.json"), envelope, 200)?;

        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ReportOnly
        );
        assert!(!evidence.claims[0].additive);
        assert!(evidence.claims[0].filesystem.is_none());
        assert!(evidence.claims[0].execution_command.is_none());
        Ok(())
    }

    #[test]
    fn chromium_components_contribute_exact_approval_ready_reclaim() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 3,
            "collector": "chromium-components",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "policy": { "max_entries": 123 },
            "chromium": {
                "profiles": [{
                    "requested_path": "/Users/example/Chrome",
                    "path": "/Users/example/Chrome"
                }]
            },
            "plan": {
                "action": "report_only",
                "reason": "closed model roots are reviewable",
                "complete": true,
                "eligibility_digest": format!("sha256:{}", "a".repeat(64)),
                "components": [{
                    "requested_path": "/Users/example/Chrome/OptGuideOnDeviceModel",
                    "path": "/Users/example/Chrome/OptGuideOnDeviceModel",
                    "filesystem": "device:1",
                    "metrics": {
                        "private_reclaimable_bytes": 4_000,
                        "private_reclaimable_complete": true
                    }
                }]
            }
        }))?;

        let evidence = chromium_component_evidence(Path::new("chromium.json"), envelope, 200)?;

        assert_eq!(
            evidence.owner_paths,
            [PathBuf::from("/Users/example/Chrome/OptGuideOnDeviceModel")]
        );
        assert_eq!(evidence.claims.len(), 1);
        assert_eq!(evidence.claims[0].bytes, 4_000);
        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ApprovalReady
        );
        assert!(evidence.claims[0].additive);
        assert!(evidence.claims[0].execution_command.is_some());
        Ok(())
    }

    #[test]
    fn lima_retirement_contributes_digest_bound_owner_reclaim() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 4,
            "collector": "lima",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "lima": {
                "lima_home": "/Users/example/.lima",
                "cache_path": "/Users/example/Library/Caches/lima",
                "instances": [{
                    "directory": "/Users/example/.lima/default"
                }]
            },
            "plan": {
                "action": "retire_domain",
                "reason": "the owner domain is retired",
                "complete": true,
                "approval_digest": format!("sha256:{}", "a".repeat(64)),
                "expected_reclaim": {
                    "private_reclaimable_bytes": 7_000,
                    "private_reclaimable_complete": true
                }
            }
        }))?;

        let evidence = lima_evidence(
            Path::new("lima.json"),
            envelope,
            &complete_inventory("/Users/example"),
            200,
        )?;

        assert_eq!(evidence.claims[0].id, "lima-domain-retirement");
        assert_eq!(evidence.claims[0].bytes, 7_000);
        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ApprovalReady
        );
        assert!(evidence.claims[0].additive);
        let command = evidence.claims[0].execution_command.as_ref().unwrap();
        assert!(command.iter().any(|argument| argument == "--retire"));
        assert_eq!(command.last(), evidence.claims[0].approval_digest.as_ref());
        assert!(evidence
            .owner_paths
            .contains(&PathBuf::from("/Users/example/.lima/default")));
        Ok(())
    }

    #[test]
    fn lima_retirement_requires_inventory_coverage_for_every_owner_root() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 4,
            "collector": "lima",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "lima": {
                "lima_home": "/Users/example/.lima",
                "cache_path": "/Users/example/Library/Caches/lima",
                "instances": [{
                    "directory": "/Users/example/.lima/default"
                }]
            },
            "plan": {
                "action": "retire_domain",
                "reason": "the owner domain is retired",
                "complete": true,
                "approval_digest": format!("sha256:{}", "a".repeat(64)),
                "expected_reclaim": {
                    "private_reclaimable_bytes": 7_000,
                    "private_reclaimable_complete": true
                }
            }
        }))?;

        let evidence = lima_evidence(
            Path::new("lima.json"),
            envelope,
            &complete_inventory("/Users/example/Library"),
            200,
        )?;

        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ReviewRequired
        );
        assert!(!evidence.claims[0].additive);
        assert!(evidence.claims[0].execution_command.is_some());
        assert!(evidence
            .warnings
            .iter()
            .any(|warning| warning.contains("not all covered")));
        Ok(())
    }

    #[test]
    fn lima_download_cache_remains_review_required_despite_digest_handoff() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 3,
            "collector": "lima",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "lima": {
                "lima_home": "/Users/example/.lima",
                "cache_path": "/Users/example/Library/Caches/lima",
                "instances": []
            },
            "plan": {
                "action": "delegate_download_cache",
                "reason": "unreferenced cache keys are reviewable",
                "complete": true,
                "approval_digest": format!("sha256:{}", "a".repeat(64)),
                "expected_reclaim": {
                    "private_reclaimable_bytes": 3_000,
                    "private_reclaimable_complete": true
                }
            }
        }))?;

        let evidence = lima_evidence(
            Path::new("lima.json"),
            envelope,
            &complete_inventory("/Users/example"),
            200,
        )?;

        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ReviewRequired
        );
        let command = evidence.claims[0].execution_command.as_ref().unwrap();
        assert!(!command.iter().any(|argument| argument == "--retire"));
        assert_eq!(command.last(), evidence.claims[0].approval_digest.as_ref());
        Ok(())
    }

    #[test]
    fn bambu_diagnostics_remain_review_required_without_the_owner_executor() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 4,
            "collector": "bambu-logs",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "bambu": {
                "owner_declared_default_roots": true,
                "log_roots": [{"product": "BambuStudio", "path": "/logs", "present": true}]
            },
            "policy": {"retention_days": 14, "max_entries": 100000},
            "plan": {
                "action": "report_only",
                "reason": "expired diagnostics are owner-isolated",
                "complete": true,
                "eligibility_digest": format!("sha256:{}", "a".repeat(64)),
                "candidates": [{"path": "/logs/studio_old_enc.log.0", "filesystem": "fs"}],
                "retained": [],
                "expected_reclaim": {
                    "private_reclaimable_bytes": 800,
                    "private_reclaimable_complete": true
                }
            }
        }))?;

        let evidence = bambu_evidence(
            Path::new("/tmp/bambu.json"),
            envelope,
            &complete_inventory("/logs"),
            200,
        )?;

        assert_eq!(evidence.claims[0].bytes, 800);
        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ReviewRequired
        );
        assert!(evidence.claims[0].additive);
        assert!(evidence.claims[0].execution_command.is_none());
        Ok(())
    }

    #[test]
    fn cargo_profiles_become_approval_ready_with_the_profile_executor() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 1,
            "collector": "cargo-profile-opportunities",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "source": {
                "generated_manifest": "/tmp/generated.json",
                "generated_manifest_sha256": format!("sha256:{}", "b".repeat(64))
            },
            "policy": {"max_entries": 100000},
            "plan": {
                "action": "report_only",
                "reason": "complete profiles are ready for review",
                "complete": true,
                "eligibility_digest": format!("sha256:{}", "a".repeat(64)),
                "candidates": [{"profile_path": "/repo/target/debug", "filesystem": "fs"}],
                "expected_reclaim": {
                    "private_reclaimable_bytes": 900,
                    "private_reclaimable_complete": true
                }
            }
        }))?;

        let evidence = cargo_profile_evidence(
            Path::new("/tmp/cargo-profiles.json"),
            envelope,
            &complete_inventory("/repo"),
            200,
        )?;

        assert_eq!(
            evidence.claims[0].readiness,
            StorageClaimReadiness::ApprovalReady
        );
        assert!(evidence.claims[0].additive);
        assert_eq!(evidence.claims[0].bytes, 900);
        assert_eq!(
            evidence.claims[0].execution_command.as_deref(),
            Some(
                [
                    "worktree-gc",
                    "collect",
                    "cargo-profiles",
                    "--generated-manifest",
                    "/tmp/generated.json",
                    "--max-entries",
                    "100000",
                    "--execute",
                    "--approved-digest",
                    concat!(
                        "sha256:",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ),
                ]
                .map(str::to_owned)
                .as_slice()
            )
        );
        Ok(())
    }

    #[test]
    fn generated_manifest_is_non_additive_rebuild_evidence() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "collector": "generated",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "plan": {
                "action": "report_only",
                "reason": "complete generated inventory",
                "complete": true,
                "artifacts": [{
                    "path": "/repo/target",
                    "cleanup_action": "skip",
                    "rebuildable_opportunity": true,
                    "rebuild_cost": "medium",
                    "measurement": {
                        "complete": true,
                        "filesystem": "fs",
                        "metrics": {
                            "allocated_bytes": 1000,
                            "private_reclaimable_bytes": 800,
                            "private_reclaimable_complete": true
                        }
                    }
                }]
            }
        }))?;

        let evidence = generated_evidence(
            Path::new("generated.json"),
            envelope,
            &complete_inventory("/repo"),
            200,
        )?;

        assert_eq!(evidence.claims[0].kind, StorageClaimKind::AllocatedStorage);
        assert_eq!(evidence.claims[1].bytes, 800);
        assert!(evidence.claims.iter().all(|claim| !claim.additive));
        Ok(())
    }

    #[test]
    fn historical_docker_evidence_never_invents_an_absent_executor() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 3,
            "collector": "docker",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "plan": {
                "action": "delegate_build_cache",
                "reason": "historical owner report",
                "complete": true,
                "eligibility_digest": format!("sha256:{}", "a".repeat(64)),
                "docker_build_cache_reclaimable_bytes": 1_000,
                "image_unique_reclaim_bytes": 2_000,
                "host_observation": {
                    "domain_storage_path": "/Users/example/.orbstack/data/data.img",
                    "filesystem": "fs",
                    "orbstack_sparse_disk": {"allocated_bytes": 3_000}
                }
            }
        }))?;

        let evidence = docker_evidence(Path::new("docker.json"), envelope, 200)?;

        assert!(evidence.claims.iter().all(|claim| !claim.additive));
        assert!(evidence
            .claims
            .iter()
            .all(|claim| claim.execution_command.is_none()));
        Ok(())
    }

    #[test]
    fn parallels_keeps_vm_allocation_separate_from_compaction_estimates() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "collector": "parallels",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "plan": {
                "action": "in_use",
                "reason": "the VM is suspended",
                "complete": true,
                "vms": [{
                    "name": "Windows 11",
                    "status": "suspended",
                    "home": "/Users/test/Parallels/Windows 11.pvm",
                    "disks": [{
                        "path": "/Users/test/Parallels/Windows 11.pvm/harddisk.hdd"
                    }]
                }],
                "total_vm_metrics": {
                    "private_reclaimable_bytes": 180_000,
                    "allocated_bytes": 190_000,
                    "private_reclaimable_complete": true
                },
                "estimated_host_reclaim_bytes": 1_200
            }
        }))?;

        let evidence = parallels_evidence(
            Path::new("/tmp/parallels.json"),
            envelope,
            &complete_inventory("/Users/test"),
            200,
        )?;

        assert_eq!(evidence.claims.len(), 3);
        assert_eq!(
            evidence.claims[0].kind,
            StorageClaimKind::ApfsPrivateReclaim
        );
        assert_eq!(evidence.claims[0].bytes, 180_000);
        assert_eq!(evidence.claims[1].kind, StorageClaimKind::AllocatedStorage);
        assert_eq!(evidence.claims[1].bytes, 190_000);
        assert_eq!(
            evidence.claims[2].kind,
            StorageClaimKind::OwnerReportedReclaim
        );
        assert_eq!(evidence.claims[2].bytes, 1_200);
        assert!(evidence
            .claims
            .iter()
            .all(|claim| claim.readiness == StorageClaimReadiness::ReportOnly));
        assert!(!evidence.claims.iter().any(|claim| claim.additive));
        assert_eq!(
            evidence.claims[0].overlap_group,
            evidence.claims[1].overlap_group
        );
        assert!(evidence
            .claims
            .iter()
            .all(|claim| claim.execution_command.is_none()));
        Ok(())
    }

    #[test]
    fn codex_sessions_are_durable_report_only_storage() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 1,
            "collector": "codex-sessions",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "identity": {
                "sessions_root": "/Users/test/.codex/sessions",
                "archived_sessions_root": "/Users/test/.codex/archived_sessions"
            },
            "plan": {
                "action": "report_only",
                "reason": "retention requires an owner contract",
                "complete": true,
                "live": {"count": 3, "metrics": {
                    "allocated_bytes": 300,
                    "private_reclaimable_bytes": 300,
                    "private_reclaimable_complete": true
                }},
                "archived": {"count": 4, "metrics": {
                    "allocated_bytes": 400,
                    "private_reclaimable_bytes": 400,
                    "private_reclaimable_complete": true
                }}
            }
        }))?;

        let evidence = codex_session_evidence(
            Path::new("/tmp/codex-sessions.json"),
            envelope,
            &complete_inventory("/Users/test"),
            200,
        )?;

        assert_eq!(evidence.claims[0].bytes, 300);
        assert_eq!(evidence.claims[1].bytes, 400);
        assert!(evidence.claims.iter().all(|claim| claim.kind
            == StorageClaimKind::AllocatedStorage
            && claim.readiness == StorageClaimReadiness::ReportOnly
            && !claim.additive
            && claim.execution_command.is_none()));
        Ok(())
    }

    #[test]
    fn codex_worktree_candidates_overlap_total_allocation_and_have_no_executor() -> Result<()> {
        let envelope: CollectorEnvelope = serde_json::from_value(serde_json::json!({
            "manifest_version": 1,
            "collector": "codex-worktrees",
            "generated_at_unix": 100,
            "mode": "dry_run",
            "plan": {
                "complete": true,
                "worktrees": [{"path": "/Users/test/.codex/worktrees/a/repo"}],
                "review_candidates": [{"path": "/Users/test/.codex/worktrees/a/repo"}],
                "total_metrics": {
                    "private_reclaimable_bytes": 900,
                    "allocated_bytes": 1_000
                },
                "review_candidate_metrics": {"private_reclaimable_bytes": 500}
            }
        }))?;

        let evidence = codex_worktree_evidence(
            Path::new("/tmp/codex-worktrees.json"),
            envelope,
            &complete_inventory("/Users/test"),
            200,
        )?;

        assert_eq!(evidence.claims[0].bytes, 900);
        assert_eq!(evidence.claims[1].bytes, 1_000);
        assert_eq!(evidence.claims[2].bytes, 500);
        assert!(evidence
            .claims
            .iter()
            .all(|claim| claim.readiness == StorageClaimReadiness::ReportOnly));
        assert_eq!(
            evidence.claims[0].overlap_group,
            evidence.claims[1].overlap_group
        );
        assert!(evidence
            .claims
            .iter()
            .all(|claim| !claim.additive && claim.execution_command.is_none()));
        Ok(())
    }
}
