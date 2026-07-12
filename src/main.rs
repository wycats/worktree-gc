mod config;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use worktree_gc::{
    add_protection, cleanup, cleanup_repositories, cleanup_roots, discover_repositories,
    list_protections, print_cleanup, print_root_cleanup, print_root_triage, print_triage,
    remove_protection, renew_protection, triage, triage_roots, CleanupOptions, GeneratedDirConfig,
    SweepLimit, SweepStrategy, SweepTool, TriageOptions, DEFAULT_GENERATED_DAYS,
    DEFAULT_PROTECTION_TTL_DAYS, DEFAULT_STALE_DAYS, MAX_PROTECTION_TTL_DAYS,
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
            help = "Skip generated dirs that a running process has open files in (uses lsof)"
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
            help = "Skip generated dirs that a running process has open files in (uses lsof)"
        )]
        check_in_use: bool,

        #[command(flatten)]
        generated: GeneratedArgs,
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
        help = "Generated directory name to delete when stale; repeat or comma-separate"
    )]
    delete_generated: Vec<String>,

    #[arg(
        long = "report-generated",
        value_name = "NAME",
        value_delimiter = ',',
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
        help = "In-place pruning for active dirs (e.g. target=rustc-incremental:14 or target=cargo-sweep:max-size=50GB); repeat or comma-separate"
    )]
    sweep: Vec<SweepStrategy>,

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

fn parse_window_override(raw: &str) -> Result<(String, u64), String> {
    let (name, days) = raw
        .split_once('=')
        .ok_or_else(|| format!("expected NAME=DAYS, got '{raw}'"))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(format!("expected NAME=DAYS, got '{raw}'"));
    }
    let days = days
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid day count in '{raw}'"))?;
    Ok((name.to_string(), days))
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
        "cargo-sweep" => SweepTool::CargoSweep,
        other => {
            return Err(format!(
                "unknown sweep tool '{other}' (supported: rustc-incremental, cargo-sweep)"
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
    }
}

fn tool_name(tool: &SweepTool) -> &'static str {
    match tool {
        SweepTool::RustcIncremental => "rustc-incremental",
        SweepTool::CargoSweep => "cargo-sweep",
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let now = SystemTime::now();
    let repo = cli.repo;
    let roots = cli.root;

    match cli.command {
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
            let mut sweeps = Vec::new();
            if let Some(size) = &scheduled.cleanup.cargo_sweep_max_size {
                let bytes = parse_size::parse_size(size)?;
                sweeps.push(SweepStrategy {
                    name: "target".to_string(),
                    tool: SweepTool::CargoSweep,
                    limit: SweepLimit::MaxSize { bytes },
                });
            }
            let options = CleanupOptions {
                execute: !dry_run,
                stale_days: scheduled.cleanup.stale_days,
                generated_days: scheduled.cleanup.generated_days,
                generated_activity_only: scheduled.cleanup.generated_activity_only,
                check_in_use: scheduled.cleanup.check_in_use,
                generated_config: GeneratedDirConfig::from_names_with_default_sweeps(
                    true,
                    true,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                    sweeps,
                ),
                cargo_lock_timeout: Some(std::time::Duration::from_secs(
                    scheduled
                        .cleanup
                        .cargo_lock_timeout_minutes
                        .saturating_mul(60),
                )),
                defer_lock_timeouts: true,
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
    UNIX_EPOCH
        .checked_add(std::time::Duration::from_secs(unix))
        .map(time::OffsetDateTime::from)
        .and_then(|time| {
            time.format(&time::format_description::well_known::Rfc3339)
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
    fn default_sweep_can_be_overridden_and_composed() {
        let config = cleanup_config(&[
            "--sweep",
            "target=rustc-incremental:7",
            "--sweep",
            "target=cargo-sweep:30",
        ]);
        let sweeps = config.sweep_strategies("target");
        assert_eq!(sweeps.len(), 2);
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
