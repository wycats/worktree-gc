//! Opt-in bounded native migration. Codex is the sole live rollout/index writer.
pub(crate) mod io;
mod native;
mod preflight;
pub use native::rehearse;
pub use preflight::preflight;
#[cfg(test)]
mod tests;

use crate::protection::MigrationProtectionGuard;
use anyhow::{bail, ensure, Context, Result};
use io::{canonical, identity, Identity, OUTPUT_LIMIT};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const GIB: u64 = 1024 * 1024 * 1024;
const INDEX_LIMIT: usize = 20_000;
const LINE_LIMIT: usize = 64 * 1024 * 1024;
const NATIVE_VERSION: &str = "codex-cli 0.153.4";
const DEFAULT_CODEX: &str = "/Applications/ChatGPT.app/Contents/Resources/codex";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub codex_home: PathBuf,
    pub codex_binary: PathBuf,
    pub codex_sha256: String,
    pub zstd_binary: PathBuf,
    pub backup_root: PathBuf,
    pub backup_volume_uuid: String,
    pub journal_root: PathBuf,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_grace")]
    pub grace_hours: u64,
    #[serde(default = "default_tasks")]
    pub max_tasks: usize,
    #[serde(default = "default_source")]
    pub max_source_bytes: u64,
    #[serde(default = "default_raw")]
    pub max_raw_bytes_per_task: u64,
    #[serde(default = "default_seconds")]
    pub max_seconds: u64,
    #[serde(default = "default_free")]
    pub min_free_bytes: u64,
    #[serde(default)]
    pub exclude_threads: Vec<String>,
    #[serde(skip)]
    pub policy_sha256: String,
}
fn default_grace() -> u64 {
    24
}
fn default_tasks() -> usize {
    4
}
fn default_source() -> u64 {
    4 * GIB
}
fn default_raw() -> u64 {
    30 * GIB
}
fn default_seconds() -> u64 {
    1800
}
fn default_free() -> u64 {
    30 * GIB
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Policy {
    fn native_headroom(&self, raw_bytes: u64) -> Result<u64> {
        self.min_free_bytes
            .checked_add(raw_bytes.checked_mul(2).context("raw headroom overflow")?)
            .context("raw headroom overflow")
    }
    pub fn load(path: &Path) -> Result<Self> {
        let value = Self::parse(path)?;
        value.validate()?;
        Ok(value)
    }
    fn parse(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.uid() == unsafe { libc::getuid() } && metadata.mode() & 0o077 == 0,
            "migration policy must be user-owned mode 0600"
        );
        let bytes = io::read_bound(path, 65536)?;
        let mut value: Self = toml::from_str(std::str::from_utf8(&bytes)?)?;
        value.policy_sha256 = format!("{:x}", Sha256::digest(&bytes));
        Ok(value)
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            (24..=8760).contains(&self.grace_hours) && (1..=25).contains(&self.max_tasks),
            "grace/task bounds"
        );
        ensure!(
            (1..=3600).contains(&self.max_seconds) && self.min_free_bytes >= GIB,
            "time/free-space bounds"
        );
        ensure!(
            (1..=100 * GIB).contains(&self.max_source_bytes)
                && (1..=100 * GIB).contains(&self.max_raw_bytes_per_task),
            "source/raw bounds"
        );
        ensure!(
            sha(&self.codex_sha256) && !self.backup_volume_uuid.is_empty(),
            "invalid pinned identity"
        );
        ensure!(
            self.exclude_threads.iter().all(|id| uuid(id)),
            "invalid excluded task ID"
        );
        for directory in [&self.codex_home, &self.backup_root, &self.journal_root] {
            canonical(directory, true)?;
        }
        for binary in [&self.codex_binary, &self.zstd_binary] {
            identity(binary)?;
        }
        for (a, b) in [
            (&self.codex_home, &self.backup_root),
            (&self.codex_home, &self.journal_root),
            (&self.backup_root, &self.journal_root),
        ] {
            ensure!(
                !io::intersects(a, b),
                "store, journal and backup must be disjoint"
            );
        }
        ensure!(
            fs::metadata(&self.codex_home)?.dev() != fs::metadata(&self.backup_root)?.dev(),
            "backup requires a separate volume"
        );
        let journal = fs::metadata(&self.journal_root)?;
        ensure!(
            journal.uid() == unsafe { libc::getuid() } && journal.mode() & 0o077 == 0,
            "journal root must be user-owned mode 0700"
        );
        Ok(())
    }
    fn surfaces(&self) -> Vec<PathBuf> {
        vec![
            self.codex_home.clone(),
            self.backup_root.clone(),
            self.journal_root.clone(),
        ]
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Row {
    id: String,
    rollout_path: String,
    source: String,
    history_mode: String,
    archived: i64,
    archived_at: Option<i64>,
    updated_at: i64,
    is_pinned: i64,
}
type Edges = Vec<(String, String)>;
type Parents = BTreeMap<String, BTreeSet<String>>;

fn index_files(home: &Path) -> Result<Vec<Identity>> {
    canonical(home, true)?;
    let mut evidence = vec![identity(&home.join("state_5.sqlite"))?];
    for name in [
        "state_5.sqlite-wal",
        "state_5.sqlite-shm",
        "state_5.sqlite-journal",
    ] {
        let path = home.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => evidence.push(identity(&path)?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(evidence)
}

fn index_snapshot(home: &Path) -> Result<(Vec<Row>, Edges)> {
    // Never let SQLite follow a hardlinked index or writable sidecar into a
    // different store, even for the first read-only observation.
    let before = index_files(home)?;
    let database = home.join("state_5.sqlite");
    // SQLite READ_ONLY protects the main DB but can still create/truncate SHM.
    // The bundled Unix VFS supports readonly_shm=1. Keep WAL visible and fail
    // closed when its read-only shared-memory view cannot be established.
    let encoded = percent_encoding::utf8_percent_encode(
        database.to_str().context("SQLite path")?,
        percent_encoding::NON_ALPHANUMERIC,
    );
    let uri = format!("file:{encoded}?mode=ro&readonly_shm=1");
    let connection = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI,
    )?;
    connection.busy_timeout(Duration::from_secs(2))?;
    connection.execute_batch("PRAGMA query_only=ON; BEGIN;")?;
    let rows = connection.prepare("SELECT id,rollout_path,source,history_mode,archived,archived_at,updated_at,is_pinned FROM threads LIMIT 20001")?.query_map([], |row| Ok(Row {
        id: row.get(0)?, rollout_path: row.get(1)?, source: row.get(2)?, history_mode: row.get(3)?, archived: row.get(4)?, archived_at: row.get(5)?, updated_at: row.get(6)?, is_pinned: row.get(7)?,
    }))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let edges = connection
        .prepare("SELECT parent_thread_id,child_thread_id FROM thread_spawn_edges LIMIT 20001")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    ensure!(
        rows.len() <= INDEX_LIMIT && edges.len() <= INDEX_LIMIT,
        "task index cap exceeded"
    );
    let after = index_files(home)?;
    ensure!(
        before.first().map(|i| (&i.device, &i.inode))
            == after.first().map(|i| (&i.device, &i.inode)),
        "index replaced during observation"
    );
    Ok((rows, edges))
}

fn lineage(rows: &[Row], edges: &Edges) -> Result<(Parents, BTreeSet<String>)> {
    let mut parents = Parents::new();
    for (parent, child) in edges {
        ensure!(uuid(parent) && uuid(child), "invalid indexed parent edge");
        parents
            .entry(child.clone())
            .or_default()
            .insert(parent.clone());
    }
    let mut seen = BTreeSet::new();
    for row in rows {
        ensure!(
            uuid(&row.id) && seen.insert(&row.id),
            "invalid or duplicate indexed task ID"
        );
        let text = row.source.trim();
        ensure!(!text.is_empty(), "empty task source");
        if text.starts_with(['{', '[', '"']) {
            let source: Value = serde_json::from_str(text)?;
            if let Some(spawn) = source.pointer("/subagent/thread_spawn") {
                let parent = spawn
                    .get("parent_thread_id")
                    .and_then(Value::as_str)
                    .context("incomplete spawn lineage")?;
                ensure!(uuid(parent), "invalid spawn parent");
                parents
                    .entry(row.id.clone())
                    .or_default()
                    .insert(parent.to_owned());
            }
        }
    }
    let children = parents
        .values()
        .flat_map(|ids| ids.iter().cloned())
        .collect();
    Ok((parents, children))
}

fn eligibility(
    row: &Row,
    parents: &Parents,
    children: &BTreeSet<String>,
    ids: &BTreeSet<&str>,
    policy: &Policy,
    time: u64,
) -> Option<&'static str> {
    if row.history_mode != "legacy" {
        return Some("already_paginated");
    }
    if row.archived != 1 {
        return Some("not_archived");
    }
    if row.is_pinned != 0 || policy.exclude_threads.contains(&row.id) {
        return Some("protected_task");
    }
    let Some(parent) = parents.get(&row.id) else {
        return Some("incomplete_or_conflicting_parent");
    };
    if parent.len() != 1
        || parent.contains(&row.id)
        || !parent.iter().all(|p| ids.contains(p.as_str()))
    {
        return Some("incomplete_or_conflicting_parent");
    }
    if children.contains(&row.id) {
        return Some("has_children");
    }
    if [row.archived_at, Some(row.updated_at)].iter().any(|t| {
        t.is_none_or(|t| t <= 0 || time.saturating_sub(t as u64) < policy.grace_hours * 3600)
    }) {
        return Some("archive_or_activity_grace");
    }
    None
}

fn rollout_path(home: &Path, row: &Row) -> Result<PathBuf> {
    let root = home.join("archived_sessions");
    canonical(&root, true)?;
    let logical = Path::new(&row.rollout_path);
    io::path_syntax(logical)?;
    ensure!(logical.starts_with(&root), "rollout outside archive root");
    let name = logical
        .file_name()
        .and_then(|s| s.to_str())
        .context("rollout filename")?;
    let plain_name = name.strip_suffix(".zst").unwrap_or(name);
    ensure!(
        plain_name.ends_with(&format!("{}.jsonl", row.id)),
        "unexpected rollout name"
    );
    let plain = logical.with_file_name(plain_name);
    let compressed = logical.with_file_name(format!("{plain_name}.zst"));
    let mut found = Vec::new();
    for path in [plain, compressed] {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                canonical(&path, false)?;
                ensure!(
                    path.canonicalize()?.starts_with(&root),
                    "canonical rollout escape"
                );
                found.push(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    ensure!(found.len() == 1, "missing or ambiguous rollout spelling");
    let path = found.pop().context("rollout")?;
    ensure!(
        identity(&path)?.device == fs::metadata(home)?.dev(),
        "nested rollout mount"
    );
    Ok(path)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Candidate {
    row: Row,
    path: PathBuf,
    identity: Identity,
    parent_id: String,
    parent_row: Row,
}
#[derive(Debug, Serialize)]
struct Plan {
    selected: Vec<Candidate>,
    eligible_count: usize,
    eligible_file_bytes: u64,
    selected_file_bytes: u64,
    refusals: BTreeMap<String, usize>,
    byte_currency: &'static str,
}

fn plan(rows: &[Row], edges: &Edges, policy: &Policy, time: u64) -> Result<Plan> {
    let (parents, children) = lineage(rows, edges)?;
    let ids = rows.iter().map(|r| r.id.as_str()).collect();
    let mut result = Plan {
        selected: Vec::new(),
        eligible_count: 0,
        eligible_file_bytes: 0,
        selected_file_bytes: 0,
        refusals: BTreeMap::new(),
        byte_currency: "stored_file_bytes_not_apfs_private_reclaim",
    };
    let mut candidates = Vec::new();
    for row in rows {
        let candidate: Result<Candidate> = (|| {
            if let Some(reason) = eligibility(row, &parents, &children, &ids, policy, time) {
                bail!("{reason}");
            }
            let path = rollout_path(&policy.codex_home, row)?;
            let identity = identity(&path)?;
            ensure!(
                identity.modified_seconds > 0
                    && time.saturating_sub(identity.modified_seconds as u64)
                        >= policy.grace_hours * 3600,
                "recent_file_activity"
            );
            let parent_id = parents[&row.id].first().context("parent")?.clone();
            let parent_row = rows
                .iter()
                .find(|r| r.id == parent_id)
                .context("parent row")?
                .clone();
            Ok(Candidate {
                row: row.clone(),
                path,
                identity,
                parent_id,
                parent_row,
            })
        })();
        match candidate {
            Ok(candidate) => candidates.push(candidate),
            Err(error) => {
                *result.refusals.entry(format!("{error}")).or_default() += 1;
            }
        }
    }
    candidates.sort_by(|a, b| {
        b.identity
            .bytes
            .cmp(&a.identity.bytes)
            .then(a.row.id.cmp(&b.row.id))
    });
    result.eligible_count = candidates.len();
    for candidate in candidates {
        result.eligible_file_bytes = result
            .eligible_file_bytes
            .checked_add(candidate.identity.bytes)
            .context("file byte overflow")?;
        if result.selected.len() < policy.max_tasks
            && candidate.identity.bytes
                <= policy
                    .max_source_bytes
                    .saturating_sub(result.selected_file_bytes)
        {
            result.selected_file_bytes += candidate.identity.bytes;
            result.selected.push(candidate);
        }
    }
    Ok(result)
}

fn refresh(candidate: &Candidate, policy: &Policy, migrated: bool) -> Result<()> {
    let (rows, edges) = index_snapshot(&policy.codex_home)?;
    let (parents, children) = lineage(&rows, &edges)?;
    let row = rows
        .iter()
        .find(|row| row.id == candidate.row.id)
        .context("task disappeared")?;
    let mut expected = candidate.row.clone();
    if migrated {
        expected.history_mode = "paginated".into();
    }
    ensure!(*row == expected, "task index state changed");
    ensure!(
        parents.get(&row.id) == Some(&BTreeSet::from([candidate.parent_id.clone()]))
            && !children.contains(&row.id),
        "parent lineage or leaf status changed"
    );
    ensure!(
        rows.iter().find(|r| r.id == candidate.parent_id) == Some(&candidate.parent_row),
        "parent index state changed"
    );
    ensure!(
        rollout_path(&policy.codex_home, row)? == candidate.path,
        "rollout path changed"
    );
    if !migrated {
        ensure!(
            identity(&candidate.path)? == candidate.identity,
            "rollout identity changed"
        );
        ensure!(
            eligibility(
                row,
                &parents,
                &children,
                &rows.iter().map(|r| r.id.as_str()).collect(),
                policy,
                now()
            )
            .is_none(),
            "task no longer eligible"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Continuation {
    session_meta: String,
    checkpoint: String,
    responses: String,
    state: String,
    ordered_continuation: String,
    responses_count: u64,
}
struct ContextParser {
    pending: Vec<u8>,
    raw: u64,
    max: u64,
    tid: String,
    head: Option<Value>,
    checkpoint: Option<String>,
    responses: Sha256,
    state: Sha256,
    ordered: Sha256,
    count: u64,
}
impl ContextParser {
    fn new(tid: &str, max: u64) -> Self {
        Self {
            pending: Vec::new(),
            raw: 0,
            max,
            tid: tid.into(),
            head: None,
            checkpoint: None,
            responses: Sha256::new(),
            state: Sha256::new(),
            ordered: Sha256::new(),
            count: 0,
        }
    }
    fn feed(&mut self, block: &[u8]) -> Result<()> {
        self.raw = self
            .raw
            .checked_add(block.len() as u64)
            .context("raw byte overflow")?;
        ensure!(self.raw <= self.max, "decompressed byte budget exceeded");
        for piece in block.split_inclusive(|b| *b == b'\n') {
            ensure!(
                self.pending.len() + piece.len() < LINE_LIMIT,
                "rollout record bound"
            );
            self.pending.extend_from_slice(piece);
            if self.pending.last() == Some(&b'\n') {
                let bytes = std::mem::take(&mut self.pending);
                self.record(serde_json::from_slice(&bytes)?)?;
            }
        }
        Ok(())
    }
    fn record(&mut self, record: Value) -> Result<()> {
        let kind = record
            .get("type")
            .and_then(Value::as_str)
            .context("record type")?;
        let mut payload = record.get("payload").cloned().context("record payload")?;
        if self.head.is_none() {
            ensure!(
                kind == "session_meta"
                    && payload.get("id").and_then(Value::as_str) == Some(&self.tid),
                "rollout task identity mismatch"
            );
            let mut head = payload.as_object().context("session metadata")?.clone();
            ensure!(
                head.get("history_mode")
                    .is_none_or(|v| v == "legacy" || v == "paginated"),
                "unsupported history mode"
            );
            ensure!(
                head.get("subagent_history_start_ordinal")
                    .is_none_or(|v| v.is_null() || v.as_u64().is_some()),
                "invalid history boundary"
            );
            head.remove("history_mode");
            head.remove("subagent_history_start_ordinal");
            self.head = Some(Value::Object(head));
        }
        if kind == "compacted" {
            let value = payload.as_object_mut().context("checkpoint")?;
            ensure!(
                value
                    .get("replacement_history")
                    .is_some_and(|v| !v.is_null()),
                "unsupported continuation checkpoint"
            );
            for key in ["compaction_response_id", "latest_token_usage_record"] {
                if value.get(key).is_none_or(Value::is_null) {
                    value.remove(key);
                }
            }
            self.checkpoint = Some(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&payload)?)
            ));
            self.responses = Sha256::new();
            self.state = Sha256::new();
            self.ordered = Sha256::new();
            self.count = 0;
        } else if self.checkpoint.is_some() && kind == "response_item" {
            let value = payload.as_object_mut().context("response item")?;
            if value.get("type").is_some_and(|v| v == "reasoning")
                && value.get("content").is_none_or(Value::is_null)
            {
                value.remove("content");
            }
            self.responses.update(serde_json::to_vec(&payload)?);
            self.responses.update(b"\n");
            self.ordered
                .update(serde_json::to_vec(&json!({"type":kind,"payload":payload}))?);
            self.ordered.update(b"\n");
            self.count += 1;
        } else if self.checkpoint.is_some()
            && [
                "world_state",
                "turn_context",
                "token_usage_record",
                "inter_agent_communication_metadata",
            ]
            .contains(&kind)
        {
            let bytes = serde_json::to_vec(&json!({"type":kind,"payload":payload}))?;
            self.state.update(&bytes);
            self.state.update(b"\n");
            self.ordered.update(&bytes);
            self.ordered.update(b"\n");
        }
        Ok(())
    }
    fn finish(self) -> Result<(Continuation, u64)> {
        ensure!(self.pending.is_empty(), "unterminated rollout record");
        Ok((
            Continuation {
                session_meta: format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(
                        &self.head.context("session metadata missing")?
                    )?)
                ),
                checkpoint: self
                    .checkpoint
                    .context("no supported bounded continuation checkpoint")?,
                responses: format!("{:x}", self.responses.finalize()),
                state: format!("{:x}", self.state.finalize()),
                ordered_continuation: format!("{:x}", self.ordered.finalize()),
                responses_count: self.count,
            },
            self.raw,
        ))
    }
}

trait Runtime {
    fn guard(&self) -> Result<()>;
    fn volume(&self) -> Result<()>;
    fn quiet(&self, path: Option<&Path>) -> Result<()>;
    fn verify_binary(&self) -> Result<()>;
    fn verify_decompressor(&self) -> Result<()>;
    fn context(&self, path: &Path, tid: &str) -> Result<(Continuation, u64)>;
    fn native(&self, tid: &str, apply: bool) -> Result<Value>;
    fn free(&self, path: &Path) -> Result<u64> {
        io::free(path)
    }
}

fn write_journal(path: &Path, value: &Value) -> Result<()> {
    io::canonical_prefixes(path)?;
    let temporary = path.with_extension("pending");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= OUTPUT_LIMIT, "journal bound");
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    io::sync_dir(path.parent().context("journal parent")?)
}

fn pending_journals(root: &Path) -> Result<()> {
    for (i, entry) in fs::read_dir(root)?.enumerate() {
        ensure!(i < INDEX_LIMIT, "journal enumeration bound");
        let path = entry?.path();
        if path.file_name().is_some_and(|s| s == "runner.lock") {
            identity(&path)?;
            continue;
        }
        ensure!(
            path.extension().is_some_and(|s| s == "json"),
            "pending or unknown migration evidence"
        );
        let journal: Value = serde_json::from_slice(&io::read_bound(&path, OUTPUT_LIMIT)?)?;
        ensure!(
            journal.get("version") == Some(&json!(1))
                && journal
                    .get("phase")
                    .and_then(Value::as_str)
                    .is_some_and(|s| ["verified", "refused_before_apply"].contains(&s)),
            "migration recovery pending"
        );
    }
    Ok(())
}

fn migrate_one(
    candidate: &Candidate,
    policy: &Policy,
    runtime: &dyn Runtime,
    protections: &MigrationProtectionGuard,
) -> Result<Value> {
    let surfaces = policy.surfaces();
    protections.check(&surfaces, SystemTime::now())?;
    runtime.volume()?;
    runtime.quiet(Some(&candidate.path))?;
    refresh(candidate, policy, false)?;
    let (before, raw) = runtime
        .context(&candidate.path, &candidate.row.id)
        .context("verifying original continuation before backup")?;
    ensure!(
        runtime.free(&policy.codex_home)? >= policy.native_headroom(raw)?,
        "insufficient native decompression/rewrite headroom"
    );
    ensure!(
        runtime.free(&policy.backup_root)? >= candidate.identity.bytes + GIB,
        "external backup capacity"
    );
    let run_id = io::unique_id()?;
    let journal_path = policy.journal_root.join(format!("{run_id}.json"));
    let backup_dir = policy.backup_root.join(&run_id);
    io::exclusive_dir(&backup_dir)?;
    let backup = backup_dir.join(candidate.path.file_name().context("source name")?);
    let mut journal = json!({"version":1,"run_id":run_id,"phase":"backing_up","candidate":candidate,"backup":backup,"backup_volume_uuid":policy.backup_volume_uuid,"backup_root":policy.backup_root,"codex_home":policy.codex_home,"codex_binary":policy.codex_binary,"codex_sha256":policy.codex_sha256,"policy_sha256":policy.policy_sha256,"started_at":now(),"before_context":before,"raw_bytes":raw});
    write_journal(&journal_path, &journal)?;
    let mut applying = false;
    let operation: Result<()> = (|| {
        let digest = io::copy_verified(&candidate.path, &backup, &mut || runtime.guard())?;
        let backup_identity = identity(&backup)?;
        journal["backup_sha256"] = json!(digest);
        journal["backup_identity"] = json!(backup_identity);
        journal["phase"] = json!("backed_up");
        write_journal(&journal_path, &journal)?;
        protections.check(&surfaces, SystemTime::now())?;
        index_files(&policy.codex_home)?;
        runtime
            .native(&candidate.row.id, false)
            .context("planning native migration")?;
        runtime.volume()?;
        runtime.quiet(Some(&candidate.path))?;
        refresh(candidate, policy, false)?;
        protections.check(&surfaces, SystemTime::now())?;
        index_files(&policy.codex_home)?;
        ensure!(
            io::hash(&candidate.path, &mut || runtime.guard())? == digest
                && identity(&backup)? == backup_identity
                && io::hash(&backup, &mut || runtime.guard())? == digest,
            "pre-apply backup/source drift"
        );
        journal["phase"] = json!("applying");
        journal["free_before"] = json!(runtime.free(&policy.codex_home)?);
        write_journal(&journal_path, &journal)?;
        applying = true;
        journal["native_report"] = runtime
            .native(&candidate.row.id, true)
            .context("applying native migration")?;
        let (after, _) = runtime
            .context(&candidate.path, &candidate.row.id)
            .context("verifying migrated continuation")?;
        ensure!(after == before, "continuation mismatch; recovery required");
        journal["after_context"] = json!(after);
        journal["after_sha256"] = json!(io::hash(&candidate.path, &mut || runtime.guard())?);
        refresh(candidate, policy, true)?;
        runtime.quiet(Some(&candidate.path))?;
        runtime.volume()?;
        protections.check(&surfaces, SystemTime::now())?;
        // Revalidate the exact external original after native apply, immediately
        // before committing the verified outcome. A replacement with same bytes
        // still fails the inode/ctime identity check.
        ensure!(
            identity(&backup)? == backup_identity
                && io::hash(&backup, &mut || runtime.guard())? == digest,
            "post-apply original backup drift"
        );
        let after_bytes = identity(&candidate.path)?.bytes;
        journal["phase"] = json!("verified");
        journal["after_bytes"] = json!(after_bytes);
        journal["file_bytes_reduced"] =
            json!(candidate.identity.bytes as i128 - after_bytes as i128);
        journal["free_after"] = json!(runtime.free(&policy.codex_home)?);
        journal["finished_at"] = json!(now());
        write_journal(&journal_path, &journal)?;
        Ok(())
    })();
    if let Err(error) = operation {
        journal["phase"] = json!(if applying {
            "recovery_required"
        } else {
            "refused_before_apply"
        });
        journal["error"] = json!(format!("{error:#}"));
        journal["finished_at"] = json!(now());
        // Cancellation blocks further native work, but never suppresses durable
        // journal unwinding after the owned process group has been torn down.
        write_journal(&journal_path, &journal).context("persist migration failure")?;
        return Err(error);
    }
    Ok(
        json!({"journal":journal_path,"thread_id":candidate.row.id,"phase":"verified","file_bytes_reduced":journal["file_bytes_reduced"],"filesystem_available_delta":journal["free_after"].as_u64().context("free after")? as i128 - journal["free_before"].as_u64().context("free before")? as i128}),
    )
}

fn batch(policy: &Policy, apply: bool, runtime: &dyn Runtime, registry: &Path) -> Result<Value> {
    runtime.guard()?;
    let (rows, edges) = index_snapshot(&policy.codex_home)?;
    let plan = plan(&rows, &edges, policy, now())?;
    let mut results = Vec::new();
    if apply {
        ensure!(policy.enabled, "migration policy is disabled");
        io::writable_directory(&policy.journal_root).context("checking journal destination")?;
        io::writable_directory(&policy.backup_root).context("checking backup destination")?;
        let protections = MigrationProtectionGuard::acquire(registry)?;
        protections.check(&policy.surfaces(), SystemTime::now())?;
        let _lock = io::lock_file(&policy.journal_root.join("runner.lock"), false)?;
        pending_journals(&policy.journal_root)?;
        runtime
            .quiet(None)
            .context("checking quiet Codex store before batch")?;
        runtime
            .volume()
            .context("verifying external backup topology before batch")?;
        runtime
            .verify_binary()
            .context("verifying native Codex binary before batch")?;
        if plan
            .selected
            .iter()
            .any(|candidate| candidate.path.extension().is_some_and(|ext| ext == "zst"))
        {
            runtime
                .verify_decompressor()
                .context("verifying configured zstd before batch")?;
        }
        for candidate in &plan.selected {
            runtime.guard()?;
            results.push(migrate_one(candidate, policy, runtime, &protections)?);
        }
    }
    Ok(
        json!({"version":1,"mode":if apply {"apply"} else {"dry_run"},"observed_at":now(),"plan":plan,"results":results}),
    )
}

pub fn run(config: &Path, apply: bool) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "native archived-child migration currently supports macOS"
    );
    let policy = Policy::load(config)?;
    let cancellation = io::Cancellation::install()?;
    let runtime = native::NativeRuntime::new(&policy, &cancellation);
    batch(
        &policy,
        apply,
        &runtime,
        &crate::protection::protection_registry_path()?,
    )
}

pub fn recover(journal: &Path, destination: &Path) -> Result<Value> {
    native::recover(journal, destination)
}
