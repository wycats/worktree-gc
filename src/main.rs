use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::SystemTime;
use worktree_gc::{
    cleanup, cleanup_roots, print_cleanup, print_root_cleanup, print_root_triage, print_triage,
    triage, triage_roots, CleanupOptions, GeneratedDirConfig, SweepLimit, SweepStrategy, SweepTool,
    TriageOptions, DEFAULT_GENERATED_DAYS, DEFAULT_STALE_DAYS,
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
            Command::Triage { .. } => unreachable!(),
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
