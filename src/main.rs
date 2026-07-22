mod config;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;
use worktree_gc::{
    add_protection, cleanup, cleanup_repositories, cleanup_roots, collect_generated,
    discover_repositories, execute_approved_generated, gateway_storage_report, inventory,
    list_protections, print_cleanup, print_gateway_storage_report, print_generated_collect,
    print_inventory, print_root_cleanup, print_root_triage, print_triage, remove_protection,
    renew_protection, triage, triage_roots, CleanupOptions, GatewayStorageOptions,
    GeneratedCollectOptions, GeneratedDirConfig, InventoryOptions, PressurePolicy,
    PullRequestPolicy, SweepLimit, SweepStrategy, SweepTool, TriageOptions,
    DEFAULT_GATEWAY_EXACT_MAX_ENTRIES, DEFAULT_GATEWAY_EXACT_MAX_ENTRIES_PER_UNIT,
    DEFAULT_GENERATED_DAYS, DEFAULT_GENERATED_DELETE_NAMES,
    DEFAULT_GENERATED_DISCOVERY_MAX_ENTRIES, DEFAULT_PROTECTION_TTL_DAYS, DEFAULT_STALE_DAYS,
    MAX_PROTECTION_TTL_DAYS,
};

#[derive(Debug, Parser)]
#[command(version, about = "Triage and clean stale Git worktrees")]
struct Cli {
    #[arg(long, global = true, value_name = "PATH", conflicts_with = "root")]
    repo: Option<PathBuf>,

    #[arg(
        long,
        global = true,
        value_name = "PATH",
        help = "Recursively discover repositories under this root; repeat for multiple roots"
    )]
    root: Vec<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Measure files or directories with bounded, clone-aware accounting
    Inventory {
        #[arg(value_name = "PATH", required = true)]
        paths: Vec<PathBuf>,

        #[arg(
            long,
            default_value_t = 2,
            help = "Directory levels to retain while still measuring all descendants"
        )]
        depth: usize,

        #[arg(
            long,
            default_value_t = 20,
            help = "Largest children to retain beneath each displayed directory"
        )]
        top: usize,

        #[arg(
            long,
            default_value_t = 2_000_000,
            help = "Maximum file or directory entries to visit across all roots"
        )]
        max_entries: u64,

        #[arg(long, help = "Allow traversal into mounted filesystems below a root")]
        cross_filesystems: bool,

        #[arg(long, help = "Write the complete structured report as JSON")]
        json: bool,
    },
    /// Correlate extension-owned Gateway storage reports with bounded filesystem evidence
    GatewayStorageReport {
        #[arg(long, value_name = "PATH")]
        inventory_manifest: PathBuf,

        #[arg(long = "gateway-manifest", value_name = "PATH")]
        gateway_manifests: Vec<PathBuf>,

        #[arg(long = "gateway-manifest-dir", value_name = "PATH")]
        gateway_manifest_dirs: Vec<PathBuf>,

        #[arg(long, default_value_t = DEFAULT_GATEWAY_EXACT_MAX_ENTRIES)]
        exact_max_entries: u64,

        #[arg(long, default_value_t = DEFAULT_GATEWAY_EXACT_MAX_ENTRIES_PER_UNIT)]
        exact_max_entries_per_unit: u64,

        #[arg(long, help = "Write the complete report-only correlation as JSON")]
        json: bool,
    },
    /// Run a report-only domain collector
    Collect {
        #[command(subcommand)]
        command: CollectorCommand,
    },
    #[command(visible_alias = "audit")]
    Triage {
        #[arg(long, default_value_t = DEFAULT_STALE_DAYS)]
        stale_days: u64,

        #[arg(long, default_value_t = DEFAULT_GENERATED_DAYS)]
        generated_days: u64,

        #[arg(
            long,
            help = "Clean generated dirs using only their own activity, ignoring worktree-level recency"
        )]
        generated_activity_only: bool,

        #[arg(
            long,
            help = "Skip wholesale generated dirs owned by running processes; granular Cargo profile resets always require complete ownership evidence"
        )]
        check_in_use: bool,

        #[command(flatten)]
        generated: GeneratedArgs,
    },
    Cleanup {
        #[arg(long)]
        execute: bool,

        #[arg(long, default_value_t = DEFAULT_STALE_DAYS)]
        stale_days: u64,

        #[arg(long, default_value_t = DEFAULT_GENERATED_DAYS)]
        generated_days: u64,

        #[arg(
            long,
            help = "Clean generated dirs using only their own activity, ignoring worktree-level recency"
        )]
        generated_activity_only: bool,

        #[arg(
            long,
            help = "Skip wholesale generated dirs owned by running processes; granular Cargo profile resets always require complete ownership evidence"
        )]
        check_in_use: bool,

        #[arg(
            long,
            value_name = "DAYS",
            requires = "check_in_use",
            value_parser = clap::value_parser!(u64).range(1..),
            help = "Remove clean exact-head GitHub PR worktrees after this many days merged"
        )]
        github_merged_pr_grace_days: Option<u64>,

        #[command(flatten)]
        generated: GeneratedArgs,
    },
    /// Execute exactly one approved owner-free generated candidate
    ExecuteGenerated {
        #[arg(long, value_name = "PATH")]
        manifest: PathBuf,

        #[arg(long, value_name = "SHA256")]
        approval_digest: String,

        #[arg(long, value_name = "PATH")]
        candidate: PathBuf,

        #[arg(long, value_name = "PATH")]
        result: Option<PathBuf>,
    },
    /// Run configured multi-root cleanup for a scheduler such as launchd or cron
    Scheduled {
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,

        #[arg(long, help = "Plan and record the run without deleting anything")]
        dry_run: bool,

        #[arg(long, help = "Refresh the cached repository index before running")]
        refresh_repositories: bool,
    },
    /// List recent structured run manifests
    History {
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Show old dirty worktrees and protected generated directories needing review
    Inbox {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Manage expiring recursive cleanup protections
    Protect {
        #[command(subcommand)]
        command: ProtectCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CollectorCommand {
    /// Inventory generated build and dependency roots across Git repositories
    Generated {
        #[arg(value_name = "PATH", required = true)]
        roots: Vec<PathBuf>,

        #[arg(
            long,
            default_value_t = DEFAULT_GENERATED_DAYS,
            help = "Retain the cleanup activity classification alongside opportunity coverage"
        )]
        generated_days: u64,

        #[arg(
            long,
            default_value_t = DEFAULT_GENERATED_DISCOVERY_MAX_ENTRIES,
            help = "Maximum entries to visit while discovering repositories across all roots"
        )]
        max_discovery_entries: u64,

        #[arg(
            long,
            default_value_t = 2_000_000,
            help = "Maximum entries to APFS-measure across all generated roots"
        )]
        max_entries: u64,
    },
}

#[derive(Debug, Subcommand)]
enum ProtectCommand {
    /// Protect a path and everything below it
    Add {
        path: PathBuf,
        #[arg(
            long,
            value_parser = parse_protection_ttl,
            default_value_t = DEFAULT_PROTECTION_TTL_DAYS
        )]
        ttl: u64,
        #[arg(long)]
        reason: String,
    },
    /// Extend an active protection by id or exact path
    Renew {
        selector: String,
        #[arg(
            long,
            value_parser = parse_protection_ttl,
            default_value_t = DEFAULT_PROTECTION_TTL_DAYS
        )]
        ttl: u64,
    },
    /// Remove an active protection by id or exact path
    Remove { selector: String },
    /// List active protections
    List,
}

fn parse_protection_ttl(raw: &str) -> Result<u64, String> {
    let days = raw
        .strip_suffix('d')
        .unwrap_or(raw)
        .parse::<u64>()
        .map_err(|_| format!("invalid TTL '{raw}'; expected a day count such as 7 or 7d"))?;
    if days == 0 {
        return Err("protection TTL must be at least 1 day".to_string());
    }
    if days > MAX_PROTECTION_TTL_DAYS {
        return Err(format!(
            "protection TTL cannot exceed {MAX_PROTECTION_TTL_DAYS} days"
        ));
    }
    Ok(days)
}

#[derive(Debug, Clone, Args)]
struct GeneratedArgs {
    #[arg(
        long = "delete-generated",
        value_name = "NAME",
        value_delimiter = ',',
        value_parser = parse_generated_name,
        help = "Generated directory name to delete when stale; repeat or comma-separate"
    )]
    delete_generated: Vec<String>,

    #[arg(
        long = "report-generated",
        value_name = "NAME",
        value_delimiter = ',',
        value_parser = parse_generated_name,
        help = "Generated directory name to report but not delete; repeat or comma-separate"
    )]
    report_generated: Vec<String>,

    #[arg(
        long = "generated-window",
        value_name = "NAME=DAYS",
        value_delimiter = ',',
        value_parser = parse_window_override,
        help = "Per-name staleness window override (e.g. .next=2); repeat or comma-separate"
    )]
    generated_window: Vec<(String, u64)>,

    #[arg(
        long = "sweep",
        value_name = "NAME=TOOL:LIMIT",
        value_delimiter = ',',
        value_parser = parse_sweep_strategy,
        help = "In-place pruning for active dirs (e.g. target=rustc-incremental:14, target=cargo-profile-reset:7, or target=cargo-sweep:max-size=50GB); repeat or comma-separate"
    )]
    sweep: Vec<SweepStrategy>,

    #[arg(
        long = "sweep-path",
        value_name = "ABSOLUTE_PATH",
        value_parser = parse_absolute_sweep_path,
        help = "Restrict in-place sweeps to an exact generated-directory path; repeat for multiple paths"
    )]
    sweep_paths: Vec<PathBuf>,

    #[arg(
        long,
        help = "Disable built-in sweep strategies while keeping generated-directory defaults"
    )]
    no_default_sweeps: bool,

    #[arg(
        long,
        help = "Start with no default generated directory names before applying custom names"
    )]
    no_default_generated: bool,
}

fn parse_generated_name(raw: &str) -> Result<String, String> {
    let normalized = raw.trim();
    let mut components = Path::new(normalized).components();
    let is_literal_component = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(component)), None)
            if component == OsStr::new(normalized)
    );
    if normalized.is_empty()
        || !is_literal_component
        || normalized == ".git"
        || normalized.contains('\0')
    {
        return Err(format!(
            "invalid generated directory name {raw:?}: name must be one literal directory-name component"
        ));
    }
    Ok(normalized.to_string())
}

fn parse_absolute_sweep_path(raw: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    if !path.is_absolute()
        || raw
            .split(['/', '\\'])
            .any(|component| matches!(component, "." | ".."))
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(format!(
            "invalid sweep path {raw:?}: path must be absolute and contain no '.' or '..' components"
        ));
    }
    Ok(path)
}

fn parse_window_override(raw: &str) -> Result<(String, u64), String> {
    let (name, days) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=DAYS, got '{raw}'"))?;
    let name = parse_generated_name(name)?;
    let days = days
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid day count in '{raw}'"))?;
    Ok((name, days))
}

fn parse_sweep_strategy(raw: &str) -> Result<SweepStrategy, String> {
    let (name, spec) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=TOOL:LIMIT, got '{raw}'"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("expected NAME=TOOL:LIMIT, got '{raw}'"));
    }
    let (tool, limit) = spec
        .split_once(':')
        .ok_or_else(|| format!("expected TOOL:LIMIT in '{raw}'"))?;
    let tool = match tool.trim() {
        "rustc-incremental" => SweepTool::RustcIncremental,
        "cargo-profile-reset" => SweepTool::CargoProfileReset,
        "cargo-sweep" => SweepTool::CargoSweep,
        other => {
            return Err(format!(
                "unknown sweep tool '{other}' (supported: rustc-incremental, cargo-profile-reset, cargo-sweep)"
            ))
        }
    };
    // Both Cargo sweep implementations operate on Cargo target directories.
    if name != "target" {
        return Err(format!(
            "{} only supports 'target' dirs, got '{name}'",
            tool_name(&tool)
        ));
    }
    let limit = if let Some(size) = limit.trim().strip_prefix("max-size=") {
        if tool != SweepTool::CargoSweep {
            return Err(format!(
                "max-size is only supported by cargo-sweep in '{raw}'"
            ));
        }
        let bytes = parse_size::parse_size(size)
            .map_err(|error| format!("invalid max size in '{raw}': {error}"))?;
        SweepLimit::MaxSize { bytes }
    } else {
        let days = limit
            .trim()
            .parse::<u64>()
            .map_err(|_| format!("invalid day count in '{raw}'"))?;
        SweepLimit::AgeDays { days }
    };
    Ok(SweepStrategy {
        name: name.to_string(),
        tool,
        limit,
    })
}

impl GeneratedArgs {
    fn config(&self) -> GeneratedDirConfig {
        GeneratedDirConfig::from_names_with_default_sweeps(
            !self.no_default_generated,
            !self.no_default_generated && !self.no_default_sweeps,
            self.delete_generated.clone(),
            self.report_generated.clone(),
            self.generated_window.clone(),
            self.sweep.clone(),
        )
        .with_sweep_paths(self.sweep_paths.clone())
    }
}

fn tool_name(tool: &SweepTool) -> &'static str {
    match tool {
        SweepTool::RustcIncremental => "rustc-incremental",
        SweepTool::CargoProfileReset => "cargo-profile-reset",
        SweepTool::CargoSweep => "cargo-sweep",
    }
}

fn scheduled_generated_config(cleanup: &config::CleanupConfig) -> Result<GeneratedDirConfig> {
    let mut delete_generated = Vec::new();
    for name in &cleanup.delete_generated {
        let normalized = parse_generated_name(name).map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            !delete_generated
                .iter()
                .any(|existing| existing == &normalized),
            "delete_generated names normalize to duplicate name {normalized:?}"
        );
        delete_generated.push(normalized);
    }

    let mut generated_windows = std::collections::BTreeMap::new();
    for (name, days) in &cleanup.generated_windows {
        let normalized = name.trim();
        anyhow::ensure!(
            !normalized.is_empty(),
            "invalid generated_windows key {name:?}: name must not be empty"
        );
        anyhow::ensure!(
            (!cleanup.no_default_generated
                && DEFAULT_GENERATED_DELETE_NAMES.contains(&normalized))
                || delete_generated.iter().any(|configured| configured == normalized),
            "invalid generated_windows key {name:?}: name is not an active default or configured delete_generated root; defaults may be disabled by no_default_generated"
        );
        anyhow::ensure!(
            generated_windows
                .insert(normalized.to_string(), *days)
                .is_none(),
            "generated_windows keys normalize to duplicate name {normalized:?}"
        );
    }
    let mut sweeps = Vec::new();
    if let Some(size) = &cleanup.cargo_sweep_max_size {
        anyhow::ensure!(
            !cleanup.no_default_generated
                || delete_generated.iter().any(|configured| configured == "target"),
            "cargo_sweep_max_size requires target in delete_generated when no_default_generated = true"
        );
        let bytes = parse_size::parse_size(size)?;
        sweeps.push(SweepStrategy {
            name: "target".to_string(),
            tool: SweepTool::CargoSweep,
            limit: SweepLimit::MaxSize { bytes },
        });
    }
    Ok(GeneratedDirConfig::from_names_with_default_sweeps(
        !cleanup.no_default_generated,
        !cleanup.no_default_generated,
        delete_generated,
        Vec::new(),
        generated_windows.into_iter().collect(),
        sweeps,
    ))
}

fn scheduled_pressure_policy(
    pressure: &config::PressureConfig,
    cleanup: &config::CleanupConfig,
) -> Result<Option<PressurePolicy>> {
    if !pressure.enabled() {
        return Ok(None);
    }
    let enter = pressure
        .enter_free_space
        .as_deref()
        .context("pressure.enter_free_space is required when pressure cleanup is configured")?;
    let target = pressure
        .target_free_space
        .as_deref()
        .context("pressure.target_free_space is required when pressure cleanup is configured")?;
    let enter_bytes = parse_size::parse_size(enter)?;
    let target_bytes = parse_size::parse_size(target)?;
    anyhow::ensure!(
        target_bytes > enter_bytes,
        "pressure.target_free_space must be greater than pressure.enter_free_space"
    );
    anyhow::ensure!(
        pressure.generated_days <= cleanup.generated_days,
        "pressure.generated_days must not exceed cleanup.generated_days"
    );
    anyhow::ensure!(
        pressure.generated_days > 0,
        "pressure.generated_days must be at least 1"
    );
    anyhow::ensure!(
        !pressure.owner_free_generated || cleanup.check_in_use,
        "pressure.owner_free_generated requires cleanup.check_in_use = true"
    );
    anyhow::ensure!(
        pressure.stale_days <= cleanup.stale_days,
        "pressure.stale_days must not exceed cleanup.stale_days"
    );
    anyhow::ensure!(
        pressure.stale_days > 0,
        "pressure.stale_days must be at least 1"
    );
    Ok(Some(PressurePolicy {
        enter_bytes,
        target_bytes,
        generated_days: pressure.generated_days,
        stale_days: pressure.stale_days,
        owner_free_generated: pressure.owner_free_generated,
        active: false,
        entered_filesystems: Vec::new(),
    }))
}

fn scheduled_pull_request_policy(
    cleanup: &config::CleanupConfig,
) -> Result<Option<PullRequestPolicy>> {
    let config = &cleanup.pull_requests;
    if config.provider.is_none() {
        return Ok(None);
    }
    anyhow::ensure!(
        cleanup.check_in_use,
        "cleanup.pull_requests requires cleanup.check_in_use = true"
    );
    anyhow::ensure!(
        config.merged_grace_days > 0,
        "cleanup.pull_requests.merged_grace_days must be at least 1"
    );
    Ok(Some(PullRequestPolicy {
        merged_grace_days: config.merged_grace_days,
    }))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let now = SystemTime::now();
    let repo = cli.repo;
    let roots = cli.root;

    match cli.command {
        Command::Inventory {
            paths,
            depth,
            top,
            max_entries,
            cross_filesystems,
            json,
        } => {
            anyhow::ensure!(
                repo.is_none() && roots.is_empty(),
                "inventory takes paths as positional arguments; do not pass --repo or --root"
            );
            let report = inventory(
                &paths,
                InventoryOptions {
                    display_depth: depth,
                    top,
                    max_entries,
                    one_filesystem: !cross_filesystems,
                },
            )?;
            if json {
                serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
                println!();
            } else {
                print_inventory(&report);
            }
        }
        Command::GatewayStorageReport {
            inventory_manifest,
            gateway_manifests,
            gateway_manifest_dirs,
            exact_max_entries,
            exact_max_entries_per_unit,
            json,
        } => {
            anyhow::ensure!(
                repo.is_none() && roots.is_empty(),
                "gateway-storage-report consumes manifests directly; do not pass --repo or --root"
            );
            let report = gateway_storage_report(GatewayStorageOptions {
                inventory_manifest,
                gateway_manifests,
                gateway_manifest_dirs,
                exact_max_entries,
                exact_max_entries_per_unit,
            })?;
            if json {
                serde_json::to_writer_pretty(std::io::stdout().lock(), &report)?;
                println!();
            } else {
                print_gateway_storage_report(&report);
            }
        }
        Command::Collect { command } => {
            anyhow::ensure!(
                repo.is_none() && roots.is_empty(),
                "collect takes domain roots as positional arguments; do not pass --repo or --root"
            );
            match command {
                CollectorCommand::Generated {
                    roots,
                    generated_days,
                    max_discovery_entries,
                    max_entries,
                } => {
                    let run = collect_generated(GeneratedCollectOptions {
                        roots,
                        generated_days,
                        max_discovery_entries,
                        max_entries,
                        now,
                    })?;
                    print_generated_collect(&run);
                }
            }
        }
        Command::Triage {
            stale_days,
            generated_days,
            generated_activity_only,
            check_in_use,
            generated,
        } => {
            let options = TriageOptions {
                stale_days,
                generated_days,
                generated_activity_only,
                check_in_use,
                generated_config: generated.config(),
                now,
            };
            if roots.is_empty() {
                let report = triage(repo.as_deref(), options)?;
                print_triage(&report);
            } else {
                let report = triage_roots(&roots, options)?;
                print_root_triage(&report);
            }
        }
        Command::Cleanup {
            execute,
            stale_days,
            generated_days,
            generated_activity_only,
            check_in_use,
            github_merged_pr_grace_days,
            generated,
        } => {
            let options = CleanupOptions {
                execute,
                stale_days,
                generated_days,
                generated_activity_only,
                check_in_use,
                generated_config: generated.config(),
                cargo_lock_timeout: None,
                defer_lock_timeouts: false,
                pressure: None,
                pull_requests: github_merged_pr_grace_days
                    .map(|merged_grace_days| PullRequestPolicy { merged_grace_days }),
                now,
            };
            if roots.is_empty() {
                let run = cleanup(repo.as_deref(), options)?;
                print_cleanup(&run);
            } else {
                let run = cleanup_roots(&roots, options)?;
                print_root_cleanup(&run);
            }
        }
        Command::ExecuteGenerated {
            manifest,
            approval_digest,
            candidate,
            result,
        } => {
            anyhow::ensure!(
                repo.is_none() && roots.is_empty(),
                "execute-generated consumes an approved manifest directly; do not pass --repo or --root"
            );
            let run = execute_approved_generated(
                &manifest,
                &approval_digest,
                &candidate,
                result.as_deref(),
            )?;
            serde_json::to_writer_pretty(std::io::stdout().lock(), &run)?;
            println!();
        }
        Command::Scheduled {
            config,
            dry_run,
            refresh_repositories,
        } => {
            let (config_path, scheduled) = config::load(config.as_deref())?;
            anyhow::ensure!(
                !scheduled.roots.is_empty(),
                "{} must configure at least one root",
                config_path.display()
            );
            anyhow::ensure!(
                repo.is_none() && roots.is_empty(),
                "scheduled mode reads roots from {}; do not pass --repo or --root",
                config_path.display()
            );
            let options = CleanupOptions {
                execute: !dry_run,
                stale_days: scheduled.cleanup.stale_days,
                generated_days: scheduled.cleanup.generated_days,
                generated_activity_only: scheduled.cleanup.generated_activity_only,
                check_in_use: scheduled.cleanup.check_in_use,
                generated_config: scheduled_generated_config(&scheduled.cleanup)?,
                cargo_lock_timeout: Some(std::time::Duration::from_secs(
                    scheduled
                        .cleanup
                        .cargo_lock_timeout_minutes
                        .saturating_mul(60),
                )),
                defer_lock_timeouts: true,
                pressure: scheduled_pressure_policy(&scheduled.pressure, &scheduled.cleanup)?,
                pull_requests: scheduled_pull_request_policy(&scheduled.cleanup)?,
                now,
            };
            let repositories = scheduled_repositories(
                &scheduled.roots,
                scheduled.history.repository_refresh_days,
                refresh_repositories,
                now,
            )?;
            let run = cleanup_repositories(&scheduled.roots, &repositories, options)?;
            print_root_cleanup(&run);
            if !dry_run {
                let removed = config::prune_history(scheduled.history.retention_days, now)?;
                if removed > 0 {
                    eprintln!("pruned {removed} expired run manifests");
                }
            }
        }
        Command::History { limit } => {
            for path in config::history_files()?.into_iter().take(limit) {
                println!("{}", path.display());
            }
        }
        Command::Inbox { limit } => print_inbox(limit)?,
        Command::Protect { command } => match command {
            ProtectCommand::Add { path, ttl, reason } => {
                let lease = add_protection(&path, reason, ttl, now)?;
                println!(
                    "protected {} as {} until {}",
                    lease.path.display(),
                    lease.id,
                    format_expiry(lease.expires_at_unix)
                );
            }
            ProtectCommand::Renew { selector, ttl } => {
                let lease = renew_protection(&selector, ttl, now)?;
                println!(
                    "renewed {} ({}) until {}",
                    lease.path.display(),
                    lease.id,
                    format_expiry(lease.expires_at_unix)
                );
            }
            ProtectCommand::Remove { selector } => {
                let lease = remove_protection(&selector, now)?;
                println!(
                    "removed protection {} for {}",
                    lease.id,
                    lease.path.display()
                );
            }
            ProtectCommand::List => {
                let leases = list_protections(now)?;
                if leases.is_empty() {
                    println!("no active protections");
                }
                for lease in leases {
                    println!(
                        "{}\t{}\t{}\t{}",
                        lease.id,
                        format_expiry(lease.expires_at_unix),
                        lease.path.display(),
                        lease.reason
                    );
                }
            }
        },
    }

    Ok(())
}

fn format_expiry(unix: u64) -> String {
    i64::try_from(unix)
        .ok()
        .and_then(|unix| time::OffsetDateTime::from_unix_timestamp(unix).ok())
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct RepositoryIndex {
    generated_at_unix: u64,
    roots: Vec<PathBuf>,
    repositories: Vec<PathBuf>,
}

fn scheduled_repositories(
    roots: &[PathBuf],
    refresh_days: u64,
    force_refresh: bool,
    now: SystemTime,
) -> Result<Vec<PathBuf>> {
    let mut canonical_roots = roots
        .iter()
        .map(std::fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    canonical_roots.sort();
    canonical_roots.dedup();
    let index_path = config::state_dir()?.join("repositories.json");
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if !force_refresh {
        match read_repository_index(&index_path) {
            Ok(Some(index)) => {
                let fresh = now_unix.saturating_sub(index.generated_at_unix)
                    < refresh_days.saturating_mul(86_400);
                if fresh
                    && index.roots == canonical_roots
                    && index
                        .repositories
                        .iter()
                        .all(|repository| repository.is_dir() && is_git_repository(repository))
                {
                    return Ok(index.repositories);
                }
            }
            Ok(None) => {}
            Err(error) => eprintln!(
                "warning: ignoring unreadable repository index {}: {error:#}",
                index_path.display()
            ),
        }
    }

    let repositories = discover_repositories(&canonical_roots)?;
    let index = RepositoryIndex {
        generated_at_unix: now_unix,
        roots: canonical_roots,
        repositories: repositories.clone(),
    };
    write_repository_index(&index_path, &index)?;
    Ok(repositories)
}

fn read_repository_index(path: &std::path::Path) -> Result<Option<RepositoryIndex>> {
    match std::fs::read(path) {
        Ok(contents) => Ok(Some(serde_json::from_slice(&contents)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_repository_index(path: &std::path::Path, index: &RepositoryIndex) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    let result = (|| -> Result<()> {
        std::fs::write(&temp, serde_json::to_vec_pretty(index)?)?;
        replace_repository_index(&temp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(not(windows))]
fn replace_repository_index(temp: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    std::fs::rename(temp, path)
}

#[cfg(windows)]
fn replace_repository_index(temp: &std::path::Path, path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(temp, path)
}

fn is_git_repository(path: &std::path::Path) -> bool {
    let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return false;
    };
    output.status.success()
        && std::fs::canonicalize(path).ok()
            == std::fs::canonicalize(String::from_utf8_lossy(&output.stdout).trim()).ok()
}

fn print_inbox(limit: usize) -> Result<()> {
    let mut printed = 0;
    for event_path in config::inbox_files()? {
        if printed >= limit {
            break;
        }
        let Some(event) = read_json_record(&event_path, "inbox event") else {
            continue;
        };
        println!(
            "- deferred: {} ({})",
            event["path"].as_str().unwrap_or("<unknown>"),
            event["reason"].as_str().unwrap_or("Cargo lock timeout")
        );
        printed += 1;
    }
    let Some((path, value)) = config::history_files()?
        .into_iter()
        .find_map(|path| read_json_record(&path, "run manifest").map(|value| (path, value)))
    else {
        if printed == 0 {
            println!("inbox is empty: no scheduled run records found");
        }
        return Ok(());
    };
    let mut entries = Vec::new();
    if let Some(repositories) = value["repositories"].as_array() {
        for repository in repositories {
            let manifest = &repository["manifest"];
            let stale_days = manifest["stale_days"].as_u64().unwrap_or_default();
            if let Some(worktrees) = manifest["worktrees"].as_array() {
                for worktree in worktrees {
                    if worktree
                        .get("protection")
                        .is_some_and(|value| value.is_object())
                    {
                        entries.push(format!(
                            "worktree: {} ({})",
                            worktree["path"].as_str().unwrap_or("<unknown>"),
                            worktree["reason"].as_str().unwrap_or("protected")
                        ));
                        continue;
                    }
                    let dirty = worktree["dirty_count"].as_u64().unwrap_or_default();
                    let age = worktree["activity_age_days"].as_u64().unwrap_or_default();
                    if worktree.get("action").and_then(|value| value.as_str()) == Some("keep")
                        && dirty > 0
                        && age >= stale_days
                    {
                        entries.push(format!(
                            "worktree: {} (dirty files: {dirty}, inactive: {age} days)",
                            worktree["path"].as_str().unwrap_or("<unknown>")
                        ));
                    }
                }
            }
            if let Some(dirs) = manifest["generated_dirs"].as_array() {
                for dir in dirs {
                    let protected = dir.get("in_use").and_then(|value| value.as_bool())
                        == Some(true)
                        || dir.get("protection").is_some_and(|value| value.is_object())
                        || dir["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("tracked files"));
                    if dir.get("action").and_then(|value| value.as_str()) == Some("skip")
                        && protected
                    {
                        entries.push(format!(
                            "generated: {} ({})",
                            dir["path"].as_str().unwrap_or("<unknown>"),
                            dir["reason"].as_str().unwrap_or("protected")
                        ));
                    }
                }
            }
        }
    }
    println!("inbox from {}", path.display());
    for entry in entries.into_iter().take(limit.saturating_sub(printed)) {
        println!("- {entry}");
    }
    Ok(())
}

fn read_json_record(path: &std::path::Path, kind: &str) -> Option<serde_json::Value> {
    match std::fs::read(path)
        .map_err(anyhow::Error::from)
        .and_then(|contents| serde_json::from_slice(&contents).map_err(anyhow::Error::from))
    {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!(
                "warning: skipping malformed {kind} {}: {error:#}",
                path.display()
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use tempfile::TempDir;

    fn cleanup_config(args: &[&str]) -> GeneratedDirConfig {
        let cli = Cli::try_parse_from(
            std::iter::once("worktree-gc")
                .chain(std::iter::once("cleanup"))
                .chain(args.iter().copied()),
        )
        .expect("CLI should parse");
        match cli.command {
            Command::Cleanup { generated, .. } => generated.config(),
            _ => unreachable!(),
        }
    }

    #[test]
    fn merged_pr_grace_requires_process_ownership_checks() {
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "cleanup",
            "--github-merged-pr-grace-days",
            "1",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "cleanup",
            "--check-in-use",
            "--github-merged-pr-grace-days",
            "1",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "cleanup",
            "--check-in-use",
            "--github-merged-pr-grace-days",
            "0",
        ])
        .is_err());
    }

    #[test]
    fn inventory_cli_accepts_bounded_multi_root_options() {
        let cli = Cli::try_parse_from([
            "worktree-gc",
            "inventory",
            "/tmp/one",
            "/tmp/two",
            "--depth",
            "3",
            "--top",
            "7",
            "--max-entries",
            "99",
            "--json",
        ])
        .expect("inventory CLI should parse");
        match cli.command {
            Command::Inventory {
                paths,
                depth,
                top,
                max_entries,
                cross_filesystems,
                json,
            } => {
                assert_eq!(
                    paths,
                    [PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")]
                );
                assert_eq!(depth, 3);
                assert_eq!(top, 7);
                assert_eq!(max_entries, 99);
                assert!(!cross_filesystems);
                assert!(json);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn gateway_storage_cli_accepts_explicit_and_directory_manifests() {
        let cli = Cli::try_parse_from([
            "worktree-gc",
            "gateway-storage-report",
            "--inventory-manifest",
            "/tmp/inventory.json",
            "--gateway-manifest",
            "/tmp/code.json",
            "--gateway-manifest-dir",
            "/tmp/insiders",
            "--exact-max-entries",
            "1000",
            "--exact-max-entries-per-unit",
            "100",
            "--json",
        ])
        .expect("Gateway storage CLI should parse");
        match cli.command {
            Command::GatewayStorageReport {
                inventory_manifest,
                gateway_manifests,
                gateway_manifest_dirs,
                exact_max_entries,
                exact_max_entries_per_unit,
                json,
            } => {
                assert_eq!(inventory_manifest, PathBuf::from("/tmp/inventory.json"));
                assert_eq!(gateway_manifests, [PathBuf::from("/tmp/code.json")]);
                assert_eq!(gateway_manifest_dirs, [PathBuf::from("/tmp/insiders")]);
                assert_eq!(exact_max_entries, 1000);
                assert_eq!(exact_max_entries_per_unit, 100);
                assert!(json);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn generated_collector_accepts_bounded_multi_root_options() {
        let cli = Cli::try_parse_from([
            "worktree-gc",
            "collect",
            "generated",
            "/tmp/one",
            "/tmp/two",
            "--generated-days",
            "3",
            "--max-discovery-entries",
            "77",
            "--max-entries",
            "99",
        ])
        .expect("generated collector CLI should parse");
        match cli.command {
            Command::Collect {
                command:
                    CollectorCommand::Generated {
                        roots,
                        generated_days,
                        max_discovery_entries,
                        max_entries,
                    },
            } => {
                assert_eq!(
                    roots,
                    [PathBuf::from("/tmp/one"), PathBuf::from("/tmp/two")]
                );
                assert_eq!(generated_days, 3);
                assert_eq!(max_discovery_entries, 77);
                assert_eq!(max_entries, 99);
            }
            _ => unreachable!(),
        }
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "collect",
            "generated",
            "/tmp/one",
            "--execute",
        ])
        .is_err());
    }

    #[test]
    fn default_sweep_can_be_overridden_and_composed() {
        let config = cleanup_config(&[
            "--sweep",
            "target=rustc-incremental:7",
            "--sweep",
            "target=cargo-sweep:30",
        ]);
        let sweeps = config.sweep_strategies("target");
        assert_eq!(sweeps.len(), 3);
        assert_eq!(
            sweeps
                .iter()
                .find(|strategy| strategy.tool == SweepTool::CargoProfileReset)
                .map(|strategy| &strategy.limit),
            Some(&SweepLimit::AgeDays {
                days: worktree_gc::DEFAULT_CARGO_PROFILE_SWEEP_DAYS
            })
        );
        assert_eq!(
            sweeps
                .iter()
                .find(|strategy| strategy.tool == SweepTool::RustcIncremental)
                .map(|strategy| &strategy.limit),
            Some(&SweepLimit::AgeDays { days: 7 })
        );
        assert_eq!(
            sweeps
                .iter()
                .find(|strategy| strategy.tool == SweepTool::CargoSweep)
                .map(|strategy| &strategy.limit),
            Some(&SweepLimit::AgeDays { days: 30 })
        );
    }

    #[test]
    fn cargo_sweep_accepts_a_max_size_limit() {
        let strategy = parse_sweep_strategy("target=cargo-sweep:max-size=50GB")
            .expect("max-size strategy should parse");
        assert_eq!(strategy.tool, SweepTool::CargoSweep);
        assert_eq!(
            strategy.limit,
            SweepLimit::MaxSize {
                bytes: 50_000_000_000
            }
        );
    }

    #[test]
    fn cargo_profile_reset_accepts_an_age_limit() {
        let strategy = parse_sweep_strategy("target=cargo-profile-reset:9")
            .expect("Cargo profile strategy should parse");
        assert_eq!(strategy.tool, SweepTool::CargoProfileReset);
        assert_eq!(strategy.limit, SweepLimit::AgeDays { days: 9 });
        assert!(parse_sweep_strategy("target=cargo-profile-reset:max-size=1GB").is_err());
    }

    #[test]
    fn scheduled_generated_windows_override_build_cache_defaults() -> Result<()> {
        let cleanup: config::CleanupConfig = toml::from_str(
            r#"
generated_days = 14
generated_windows = { ".next" = 7, ".turbo" = 8, target = 9, node_modules = 10 }
"#,
        )?;
        let generated = scheduled_generated_config(&cleanup)?;

        assert_eq!(generated.effective_days(".next", cleanup.generated_days), 7);
        assert_eq!(
            generated.effective_days(".turbo", cleanup.generated_days),
            8
        );
        assert_eq!(
            generated.effective_days("target", cleanup.generated_days),
            9
        );
        assert_eq!(
            generated.effective_days("node_modules", cleanup.generated_days),
            10
        );
        assert_eq!(
            generated.effective_days("other", cleanup.generated_days),
            14
        );
        Ok(())
    }

    #[test]
    fn scheduled_custom_generated_roots_support_window_overrides() -> Result<()> {
        let cleanup: config::CleanupConfig = toml::from_str(
            r#"
generated_days = 14
delete_generated = ["node_modules.partial-install"]
generated_windows = { "node_modules.partial-install" = 1 }
"#,
        )?;
        let generated = scheduled_generated_config(&cleanup)?;

        assert!(generated
            .delete_names
            .iter()
            .any(|name| name == "node_modules.partial-install"));
        assert_eq!(
            generated.effective_days("node_modules.partial-install", cleanup.generated_days),
            1
        );
        Ok(())
    }

    #[test]
    fn scheduled_cleanup_can_select_only_explicit_generated_roots() -> Result<()> {
        let cleanup: config::CleanupConfig = toml::from_str(
            r#"
no_default_generated = true
delete_generated = [".next", "target", "node_modules.partial-install"]
generated_windows = { ".next" = 1, target = 1, "node_modules.partial-install" = 1 }
"#,
        )?;
        let generated = scheduled_generated_config(&cleanup)?;

        assert_eq!(
            generated.delete_names,
            [".next", "target", "node_modules.partial-install"]
        );
        assert!(generated.report_only_names.is_empty());
        assert!(generated.sweep_strategies.is_empty());
        assert!(!generated
            .delete_names
            .iter()
            .any(|name| name == "node_modules"));
        assert!(!generated.delete_names.iter().any(|name| name == ".turbo"));

        let inactive_window: config::CleanupConfig = toml::from_str(
            "no_default_generated = true\ngenerated_windows = { node_modules = 1 }",
        )?;
        let error = scheduled_generated_config(&inactive_window)
            .expect_err("window overrides for excluded defaults must fail");
        assert!(error
            .to_string()
            .contains("generated_windows key \"node_modules\""));
        assert!(error
            .to_string()
            .contains("not an active default or configured"));
        assert!(error
            .to_string()
            .contains("defaults may be disabled by no_default_generated"));

        let unselected_sweep: config::CleanupConfig = toml::from_str(
            "no_default_generated = true\ndelete_generated = ['.next']\ncargo_sweep_max_size = '1GB'",
        )?;
        let error = scheduled_generated_config(&unselected_sweep)
            .expect_err("focused Cargo sweeps must select target explicitly");
        assert!(error
            .to_string()
            .contains("requires target in delete_generated"));

        let selected_sweep: config::CleanupConfig = toml::from_str(
            "no_default_generated = true\ndelete_generated = ['target']\ncargo_sweep_max_size = '1GB'",
        )?;
        let generated = scheduled_generated_config(&selected_sweep)?;
        assert_eq!(generated.delete_names, ["target"]);
        assert_eq!(generated.sweep_strategies.len(), 1);
        assert_eq!(generated.sweep_strategies[0].tool, SweepTool::CargoSweep);
        Ok(())
    }

    #[test]
    fn scheduled_pressure_policy_uses_free_space_hysteresis() -> Result<()> {
        let pressure: config::PressureConfig = toml::from_str(
            r#"
enter_free_space = "100GiB"
target_free_space = "150GiB"
generated_days = 1
stale_days = 7
owner_free_generated = true
"#,
        )?;
        let cleanup = config::CleanupConfig::default();
        let policy = scheduled_pressure_policy(&pressure, &cleanup)?.context("missing policy")?;
        assert_eq!(policy.enter_bytes, 100 * 1024 * 1024 * 1024);
        assert_eq!(policy.target_bytes, 150 * 1024 * 1024 * 1024);
        assert_eq!(policy.generated_days, 1);
        assert_eq!(policy.stale_days, 7);
        assert!(policy.owner_free_generated);
        assert!(!policy.active);
        Ok(())
    }

    #[test]
    fn scheduled_pressure_policy_validates_thresholds() {
        let cleanup = config::CleanupConfig::default();
        let missing_target: config::PressureConfig =
            toml::from_str("enter_free_space = '100GiB'").unwrap();
        assert!(scheduled_pressure_policy(&missing_target, &cleanup).is_err());

        let reversed: config::PressureConfig =
            toml::from_str("enter_free_space = '150GiB'\ntarget_free_space = '100GiB'").unwrap();
        assert!(scheduled_pressure_policy(&reversed, &cleanup).is_err());

        let zero_days: config::PressureConfig = toml::from_str(
            "enter_free_space = '100GiB'\ntarget_free_space = '150GiB'\ngenerated_days = 0",
        )
        .unwrap();
        assert!(scheduled_pressure_policy(&zero_days, &cleanup).is_err());

        let owner_free: config::PressureConfig = toml::from_str(
            "enter_free_space = '100GiB'\ntarget_free_space = '150GiB'\nowner_free_generated = true",
        )
        .unwrap();
        let mut unsafe_cleanup = cleanup;
        unsafe_cleanup.check_in_use = false;
        assert!(scheduled_pressure_policy(&owner_free, &unsafe_cleanup).is_err());
    }

    #[test]
    fn scheduled_pull_request_policy_requires_complete_ownership_and_a_grace_period() -> Result<()>
    {
        let mut cleanup: config::CleanupConfig = toml::from_str(
            r#"
check_in_use = true

[pull_requests]
provider = "github"
merged_grace_days = 1
"#,
        )?;
        assert_eq!(
            scheduled_pull_request_policy(&cleanup)?,
            Some(PullRequestPolicy {
                merged_grace_days: 1,
            })
        );

        cleanup.check_in_use = false;
        assert!(scheduled_pull_request_policy(&cleanup).is_err());
        cleanup.check_in_use = true;
        cleanup.pull_requests.merged_grace_days = 0;
        assert!(scheduled_pull_request_policy(&cleanup).is_err());
        Ok(())
    }

    #[test]
    fn scheduled_generated_windows_normalize_names_and_report_invalid_keys() -> Result<()> {
        let cleanup: config::CleanupConfig =
            toml::from_str("generated_windows = { ' target ' = 7 }")?;
        let generated = scheduled_generated_config(&cleanup)?;
        assert_eq!(generated.effective_days("target", 14), 7);

        let empty: config::CleanupConfig = toml::from_str("generated_windows = { '' = 7 }")?;
        let error = scheduled_generated_config(&empty).expect_err("empty names must be rejected");
        assert!(error.to_string().contains("generated_windows key \"\""));

        let duplicate: config::CleanupConfig =
            toml::from_str("generated_windows = { target = 7, ' target ' = 8 }")?;
        let error = scheduled_generated_config(&duplicate)
            .expect_err("normalized duplicate names must be rejected");
        assert!(error.to_string().contains("duplicate name \"target\""));

        let typo: config::CleanupConfig = toml::from_str("generated_windows = { '.nex' = 7 }")?;
        let error = scheduled_generated_config(&typo)
            .expect_err("inactive scheduled names must be rejected");
        assert!(error.to_string().contains("generated_windows key \".nex\""));
        assert!(error
            .to_string()
            .contains("not an active default or configured"));

        for invalid in [
            "",
            ".",
            "..",
            ".git",
            "nested/name",
            "trailing/",
            "repeated//separator",
            "nul\0byte",
        ] {
            let cleanup: config::CleanupConfig = toml::from_str(&format!(
                "delete_generated = [{}]",
                toml::Value::String(invalid.to_string())
            ))?;
            let error = scheduled_generated_config(&cleanup)
                .expect_err("invalid custom generated names must be rejected");
            assert!(error.to_string().contains("generated directory name"));
        }
        Ok(())
    }

    #[test]
    fn cli_generated_names_require_literal_directory_components() {
        let valid = cleanup_config(&[
            "--delete-generated",
            "node_modules.partial-install",
            "--report-generated",
            "coverage",
            "--generated-window",
            "node_modules.partial-install=1",
        ]);
        assert!(valid
            .delete_names
            .iter()
            .any(|name| name == "node_modules.partial-install"));
        assert!(valid
            .report_only_names
            .iter()
            .any(|name| name == "coverage"));
        assert_eq!(valid.effective_days("node_modules.partial-install", 7), 1);

        for option in [
            "--delete-generated",
            "--report-generated",
            "--generated-window",
        ] {
            let value = if option == "--generated-window" {
                "nested/name=1"
            } else {
                "nested/name"
            };
            let result = Cli::try_parse_from(["worktree-gc", "cleanup", option, value]);
            assert!(result.is_err(), "{option} accepted a path-like name");
        }
    }

    #[test]
    fn both_default_opt_out_flags_disable_default_sweeps() {
        let no_sweeps = cleanup_config(&["--no-default-sweeps"]);
        assert!(no_sweeps.sweep_strategies("target").is_empty());
        assert!(no_sweeps.delete_names.iter().any(|name| name == "target"));

        let no_generated = cleanup_config(&["--no-default-generated"]);
        assert!(no_generated.sweep_strategies("target").is_empty());
        assert!(!no_generated
            .delete_names
            .iter()
            .any(|name| name == "target"));
    }

    #[test]
    fn sweep_cli_rejects_unsupported_tools_and_directories() {
        assert!(parse_sweep_strategy("target=unknown:14").is_err());
        assert!(parse_sweep_strategy("node_modules=rustc-incremental:14").is_err());
        assert!(parse_sweep_strategy("target=rustc-incremental:nope").is_err());
        assert!(parse_sweep_strategy("target=rustc-incremental:max-size=50GB").is_err());
        assert!(parse_sweep_strategy("target=cargo-sweep:max-size=nope").is_err());
    }

    #[test]
    fn sweep_path_cli_requires_an_absolute_traversal_free_path() {
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "cleanup",
            "--sweep-path",
            "/tmp/repo/target",
        ])
        .is_ok());
        for invalid in ["target", "/tmp/repo/../other/target", "/tmp/./repo/target"] {
            assert!(
                Cli::try_parse_from(["worktree-gc", "cleanup", "--sweep-path", invalid]).is_err(),
                "accepted invalid exact sweep path {invalid:?}"
            );
        }
    }

    #[test]
    fn protection_cli_parses_expiring_add_and_renew_commands() {
        let default_add = Cli::try_parse_from([
            "worktree-gc",
            "protect",
            "add",
            "/tmp/worktree",
            "--reason",
            "active packaging",
        ])
        .expect("protect add default should parse");
        assert!(matches!(
            default_add.command,
            Command::Protect {
                command: ProtectCommand::Add {
                    ttl: DEFAULT_PROTECTION_TTL_DAYS,
                    ..
                }
            }
        ));

        let add = Cli::try_parse_from([
            "worktree-gc",
            "protect",
            "add",
            "/tmp/worktree",
            "--ttl",
            "14d",
            "--reason",
            "active packaging",
        ])
        .expect("protect add should parse");
        match add.command {
            Command::Protect {
                command: ProtectCommand::Add { ttl, reason, .. },
            } => {
                assert_eq!(ttl, 14);
                assert_eq!(reason, "active packaging");
            }
            _ => panic!("unexpected command"),
        }

        let renew = Cli::try_parse_from([
            "worktree-gc",
            "protect",
            "renew",
            "p-fixture",
            "--ttl",
            "30d",
        ])
        .expect("protect renew should parse");
        assert!(matches!(
            renew.command,
            Command::Protect {
                command: ProtectCommand::Renew { ttl: 30, .. }
            }
        ));
        assert!(parse_protection_ttl("0d").is_err());
        assert!(parse_protection_ttl("31d").is_err());
        assert!(parse_protection_ttl("forever").is_err());
        assert_eq!(parse_protection_ttl("7"), Ok(7));
        assert_eq!(parse_protection_ttl("7d"), Ok(7));
        assert_eq!(format_expiry(u64::MAX), u64::MAX.to_string());
    }

    #[test]
    fn root_discovery_is_repeatable_and_conflicts_with_single_repo_mode() {
        let cli = Cli::try_parse_from([
            "worktree-gc",
            "--root",
            "/tmp/code",
            "--root",
            "/tmp/plugins",
            "cleanup",
        ])
        .expect("multiple roots should parse");
        assert_eq!(
            cli.root,
            vec![PathBuf::from("/tmp/code"), PathBuf::from("/tmp/plugins")]
        );
        assert!(Cli::try_parse_from([
            "worktree-gc",
            "--repo",
            "/tmp/repo",
            "--root",
            "/tmp/code",
            "cleanup",
        ])
        .is_err());
    }

    #[test]
    fn repository_index_is_atomic_and_validates_git_repositories() -> Result<()> {
        let temp = TempDir::new()?;
        let repo = temp.path().join("repo");
        std::fs::create_dir(&repo)?;
        let status = std::process::Command::new("git")
            .arg("init")
            .arg(&repo)
            .status()?;
        assert!(status.success());
        let index_path = temp.path().join("state/repositories.json");
        let index = RepositoryIndex {
            generated_at_unix: 42,
            roots: vec![temp.path().to_path_buf()],
            repositories: vec![repo.clone()],
        };

        write_repository_index(&index_path, &index)?;
        write_repository_index(&index_path, &index)?;
        let loaded = read_repository_index(&index_path)?.context("missing index")?;
        assert_eq!(loaded.generated_at_unix, 42);
        assert!(is_git_repository(&repo));
        assert!(!is_git_repository(temp.path()));
        let nested = repo.join("nested");
        std::fs::create_dir(&nested)?;
        assert!(!is_git_repository(&nested));
        assert!(!index_path
            .with_extension(format!("json.{}.tmp", std::process::id()))
            .exists());
        Ok(())
    }

    #[test]
    fn malformed_state_records_are_skipped() -> Result<()> {
        let temp = TempDir::new()?;
        let record = temp.path().join("truncated.json");
        std::fs::write(&record, b"{\"path\":")?;

        assert!(read_repository_index(&record).is_err());
        assert!(read_json_record(&record, "test record").is_none());
        Ok(())
    }
}
