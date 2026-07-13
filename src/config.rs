use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    pub roots: Vec<PathBuf>,
    pub cleanup: CleanupConfig,
    pub pressure: PressureConfig,
    pub history: HistoryConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct CleanupConfig {
    pub max_parallelism: usize,
    pub execute_worktree_removals: bool,
    pub execute_generated_deletions: bool,
    pub stale_days: u64,
    pub generated_days: u64,
    pub generated_windows: BTreeMap<String, u64>,
    pub generated_activity_only: bool,
    pub check_in_use: bool,
    pub cargo_lock_timeout_minutes: u64,
    pub cargo_sweep_max_size: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct HistoryConfig {
    pub retention_days: u64,
    pub repository_refresh_days: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct PressureConfig {
    pub enter_free_space: Option<String>,
    pub target_free_space: Option<String>,
    pub generated_days: u64,
    pub stale_days: u64,
}

impl PressureConfig {
    pub(crate) fn enabled(&self) -> bool {
        self.enter_free_space.is_some() || self.target_free_space.is_some()
    }
}

impl Default for PressureConfig {
    fn default() -> Self {
        Self {
            enter_free_space: None,
            target_free_space: None,
            generated_days: 1,
            stale_days: 7,
        }
    }
}

impl Default for CleanupConfig {
    fn default() -> Self {
        Self {
            max_parallelism: 1,
            execute_worktree_removals: false,
            execute_generated_deletions: false,
            stale_days: 14,
            generated_days: 7,
            generated_windows: BTreeMap::new(),
            generated_activity_only: true,
            check_in_use: true,
            cargo_lock_timeout_minutes: 30,
            cargo_sweep_max_size: None,
        }
    }
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            retention_days: 90,
            repository_refresh_days: 7,
        }
    }
}

pub(crate) fn default_config_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("worktree-gc/config.toml"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".config/worktree-gc/config.toml"))
}

pub(crate) fn load(path: Option<&Path>) -> Result<(PathBuf, Config)> {
    let path = path
        .map(Path::to_path_buf)
        .map_or_else(default_config_path, Ok)?;
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("failed to read configuration {}", path.display()))?;
    let config = toml::from_str(&contents)
        .with_context(|| format!("failed to parse configuration {}", path.display()))?;
    Ok((path, config))
}

pub(crate) fn state_dir() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        return Ok(PathBuf::from(path).join("worktree-gc"));
    }
    let home = std::env::var_os("HOME").context("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(PathBuf::from(home).join(".local/state/worktree-gc"))
}

pub(crate) fn history_files() -> Result<Vec<PathBuf>> {
    let state = state_dir()?;
    if !state.exists() {
        return Ok(Vec::new());
    }
    let mut files = fs::read_dir(&state)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json") && name.contains("-roots-"))
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| right.cmp(left));
    Ok(files)
}

pub(crate) fn inbox_files() -> Result<Vec<PathBuf>> {
    let inbox = state_dir()?.join("inbox");
    if !inbox.exists() {
        return Ok(Vec::new());
    }
    let mut files = fs::read_dir(inbox)?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort_by(|left, right| right.cmp(left));
    Ok(files)
}

pub(crate) fn prune_history(retention_days: u64, now: SystemTime) -> Result<usize> {
    let cutoff = now
        .checked_sub(Duration::from_secs(retention_days.saturating_mul(86_400)))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut removed = 0;
    for path in history_files()? {
        let modified = fs::metadata(&path)?.modified()?;
        if modified < cutoff {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    for path in inbox_files()? {
        let modified = fs::metadata(&path)?.modified()?;
        if modified < cutoff {
            fs::remove_file(&path)?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_roots_and_scheduled_policy() -> Result<()> {
        let config: Config = toml::from_str(
            r#"
roots = ["/code", "/plugins"]

[cleanup]
max_parallelism = 3
execute_worktree_removals = true
execute_generated_deletions = true
stale_days = 12
generated_days = 9
generated_windows = { ".next" = 7, ".turbo" = 8, target = 9, node_modules = 10 }
cargo_lock_timeout_minutes = 45
cargo_sweep_max_size = "50GB"

[pressure]
enter_free_space = "100GiB"
target_free_space = "150GiB"
generated_days = 1
stale_days = 7

[history]
retention_days = 120
"#,
        )?;

        assert_eq!(config.roots.len(), 2);
        assert_eq!(config.cleanup.max_parallelism, 3);
        assert!(config.cleanup.execute_worktree_removals);
        assert!(config.cleanup.execute_generated_deletions);
        assert_eq!(config.cleanup.stale_days, 12);
        assert_eq!(config.cleanup.generated_days, 9);
        assert_eq!(config.cleanup.generated_windows[".next"], 7);
        assert_eq!(config.cleanup.generated_windows[".turbo"], 8);
        assert_eq!(config.cleanup.generated_windows["target"], 9);
        assert_eq!(config.cleanup.generated_windows["node_modules"], 10);
        assert_eq!(config.cleanup.cargo_lock_timeout_minutes, 45);
        let pressure = config.pressure;
        assert_eq!(pressure.enter_free_space.as_deref(), Some("100GiB"));
        assert_eq!(pressure.target_free_space.as_deref(), Some("150GiB"));
        assert_eq!(pressure.generated_days, 1);
        assert_eq!(pressure.stale_days, 7);
        assert_eq!(config.history.retention_days, 120);
        assert_eq!(config.history.repository_refresh_days, 7);
        Ok(())
    }

    #[test]
    fn rejects_unknown_configuration() {
        assert!(toml::from_str::<Config>("root = ['/code']").is_err());
    }

    #[test]
    fn scheduled_cleanup_defaults_to_one_worker() {
        assert_eq!(CleanupConfig::default().max_parallelism, 1);
    }

    #[test]
    fn scheduled_cleanup_defaults_whole_removals_to_review_only() {
        let cleanup = CleanupConfig::default();
        assert!(!cleanup.execute_worktree_removals);
        assert!(!cleanup.execute_generated_deletions);
    }
}
