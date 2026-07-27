use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use worktree_gc::ownership_helper::{
    capture_from_helper, install, serve, status, uninstall, HelperInstallOptions,
    DEFAULT_HELPER_CONFIG, DEFAULT_HELPER_SOCKET,
};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Evidence-only privileged process ownership service for worktree-gc"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install and bootstrap the root LaunchDaemon (requires sudo)
    Install {
        #[arg(long, value_name = "UID")]
        client_uid: u32,
        #[arg(long, value_name = "GID")]
        client_gid: u32,
        #[arg(long, value_name = "PATH", required = true)]
        root: Vec<PathBuf>,
        #[arg(long, value_name = "PATH")]
        source_binary: Option<PathBuf>,
    },
    /// Serve bounded ownership requests (normally launched by launchd)
    Serve {
        #[arg(long, default_value = DEFAULT_HELPER_CONFIG)]
        config: PathBuf,
        #[arg(long, default_value = DEFAULT_HELPER_SOCKET)]
        socket: PathBuf,
    },
    /// Inspect the installed service and perform a protocol probe
    Status,
    /// Request bounded evidence for exact allowlisted roots
    Probe {
        #[arg(long, value_name = "PATH", required = true)]
        root: Vec<PathBuf>,
        #[arg(long, default_value = DEFAULT_HELPER_SOCKET)]
        socket: PathBuf,
    },
    /// Boot out and remove only the helper-owned installation files (requires sudo)
    Uninstall,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Install {
            client_uid,
            client_gid,
            root,
            source_binary,
        } => {
            let source_binary = source_binary
                .map(Ok)
                .unwrap_or_else(std::env::current_exe)
                .context("failed to resolve helper executable")?;
            install(HelperInstallOptions {
                source_binary,
                client_uid,
                client_gid,
                roots: root,
            })
        }
        Command::Serve { config, socket } => serve(&config, &socket),
        Command::Status => {
            serde_json::to_writer_pretty(std::io::stdout().lock(), &status())?;
            println!();
            Ok(())
        }
        Command::Probe { root, socket } => {
            serde_json::to_writer_pretty(
                std::io::stdout().lock(),
                &capture_from_helper(&socket, &root)?,
            )?;
            println!();
            Ok(())
        }
        Command::Uninstall => uninstall(),
    }
}
