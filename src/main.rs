mod config;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::SystemTime;
use worktree_gc::{
    cleanup, cleanup_repositories, cleanup_roots, discover_repositories, print_cleanup,
    print_root_cleanup, print_root_triage, print_triage, triage, triage_roots, CleanupOptions,
    GeneratedDirConfig, SweepLimit, SweepStrategy, SweepTool, TriageOptions,
    DEFAULT_GENERATED_DAYS, DEFAULT_STALE_DAYS,
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
            let removed = config::prune_history(scheduled.history.retention_days, now)?;
            if removed > 0 {
                eprintln!("pruned {removed} expired run manifests");
            }
        }
        Command::History { limit } => {
            for path in config::history_files()?.into_iter().take(limit) {
                println!("{}", path.display());
            }
        }
        Command::Inbox { limit } => print_inbox(limit)?,
    }

    Ok(())
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
    if !force_refresh && index_path.exists() {
        let index: RepositoryIndex = serde_json::from_slice(&std::fs::read(&index_path)?)?;
        let fresh =
            now_unix.saturating_sub(index.generated_at_unix) < refresh_days.saturating_mul(86_400);
        if fresh
            && index.roots == canonical_roots
            && index
                .repositories
                .iter()
                .all(|repository| repository.exists())
        {
            return Ok(index.repositories);
        }
    }

    let repositories = discover_repositories(&canonical_roots)?;
    let index = RepositoryIndex {
        generated_at_unix: now_unix,
        roots: canonical_roots,
        repositories: repositories.clone(),
    };
    if let Some(parent) = index_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&index_path, serde_json::to_vec_pretty(&index)?)?;
    Ok(repositories)
}

fn print_inbox(limit: usize) -> Result<()> {
    let mut printed = 0;
    for event_path in config::inbox_files()? {
        if printed >= limit {
            break;
        }
        let event: serde_json::Value = serde_json::from_slice(&std::fs::read(&event_path)?)?;
        println!(
            "- deferred: {} ({})",
            event["path"].as_str().unwrap_or("<unknown>"),
            event["reason"].as_str().unwrap_or("Cargo lock timeout")
        );
        printed += 1;
    }
    let Some(path) = config::history_files()?.into_iter().next() else {
        if printed == 0 {
            println!("inbox is empty: no scheduled run records found");
        }
        return Ok(());
    };
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    let mut entries = Vec::new();
    if let Some(repositories) = value["repositories"].as_array() {
        for repository in repositories {
            let manifest = &repository["manifest"];
            let stale_days = manifest["stale_days"].as_u64().unwrap_or_default();
            if let Some(worktrees) = manifest["worktrees"].as_array() {
                for worktree in worktrees {
                    let dirty = worktree["dirty_count"].as_u64().unwrap_or_default();
                    let age = worktree["activity_age_days"].as_u64().unwrap_or_default();
                    if worktree["action"] == "keep" && dirty > 0 && age >= stale_days {
                        entries.push(format!(
                            "worktree: {} (dirty files: {dirty}, inactive: {age} days)",
                            worktree["path"].as_str().unwrap_or("<unknown>")
                        ));
                    }
                }
            }
            if let Some(dirs) = manifest["generated_dirs"].as_array() {
                for dir in dirs {
                    let protected = dir["in_use"] == true
                        || dir["reason"]
                            .as_str()
                            .is_some_and(|reason| reason.contains("tracked files"));
                    if dir["action"] == "skip" && protected {
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
