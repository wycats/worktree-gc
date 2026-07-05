use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::SystemTime;
use worktree_gc::{
    cleanup, print_cleanup, print_triage, triage, CleanupOptions, GeneratedDirConfig,
    TriageOptions, DEFAULT_GENERATED_DAYS, DEFAULT_STALE_DAYS,
};

#[derive(Debug, Parser)]
#[command(version, about = "Triage and clean stale Git worktrees")]
struct Cli {
    #[arg(long, global = true, value_name = "PATH")]
    repo: Option<PathBuf>,

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
        long,
        help = "Start with no default generated directory names before applying custom names"
    )]
    no_default_generated: bool,
}

impl GeneratedArgs {
    fn config(&self) -> GeneratedDirConfig {
        GeneratedDirConfig::from_names(
            !self.no_default_generated,
            self.delete_generated.clone(),
            self.report_generated.clone(),
        )
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let now = SystemTime::now();

    match cli.command {
        Command::Triage {
            stale_days,
            generated_days,
            generated_activity_only,
            generated,
        } => {
            let report = triage(
                cli.repo.as_deref(),
                TriageOptions {
                    stale_days,
                    generated_days,
                    generated_activity_only,
                    generated_config: generated.config(),
                    now,
                },
            )?;
            print_triage(&report);
        }
        Command::Cleanup {
            execute,
            stale_days,
            generated_days,
            generated_activity_only,
            generated,
        } => {
            let options = CleanupOptions {
                execute,
                stale_days,
                generated_days,
                generated_activity_only,
                generated_config: generated.config(),
                now,
            };
            let run = cleanup(cli.repo.as_deref(), options)?;
            print_cleanup(&run);
        }
    }

    Ok(())
}
