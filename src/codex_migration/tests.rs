//! Disposable Rust fixtures; the runtime double never invokes Codex or a model.
use super::*;
use std::cell::RefCell;
use std::os::unix::fs::{symlink, PermissionsExt};

const PARENT: &str = "00000000-0000-4000-8000-000000000001";
const CHILD: &str = "00000000-0000-4000-8000-000000000002";
const OTHER: &str = "00000000-0000-4000-8000-000000000003";

fn records(tid: &str, padding: &str) -> Vec<Value> {
    vec![
        json!({"type":"session_meta","payload":{"id":tid,"history_mode":"legacy"}}),
        json!({"type":"response_item","payload":{"type":"message","text":padding}}),
        json!({"type":"compacted","payload":{"replacement_history":[{"type":"message","text":"checkpoint"}]}}),
        json!({"type":"response_item","payload":{"type":"reasoning"}}),
        json!({"type":"turn_context","payload":{"cwd":"/repo"}}),
    ]
}

fn encode(records: &[Value]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for record in records {
        bytes.extend(serde_json::to_vec(record).unwrap());
        bytes.push(b'\n');
    }
    bytes
}

fn proof(bytes: &[u8], tid: &str, cap: u64) -> Result<(Continuation, u64)> {
    let mut parser = ContextParser::new(tid, cap);
    parser.feed(bytes)?;
    parser.finish()
}

fn row(id: &str, parent: Option<&str>) -> Row {
    Row {
        id: id.into(),
        rollout_path: "/unused".into(),
        source: parent.map_or_else(
            || "cli".into(),
            |parent| json!({"subagent":{"thread_spawn":{"parent_thread_id":parent}}}).to_string(),
        ),
        history_mode: "legacy".into(),
        archived: 1,
        archived_at: Some(100),
        updated_at: 100,
        is_pinned: 0,
    }
}

fn old_file(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(100)))
        .unwrap();
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    policy: Policy,
    registry: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        for directory in ["home", "backup", "journals", "home/archived_sessions"] {
            fs::create_dir(root.join(directory)).unwrap();
        }
        fs::set_permissions(root.join("journals"), fs::Permissions::from_mode(0o700)).unwrap();
        let policy = Policy {
            codex_home: root.join("home"),
            backup_root: root.join("backup"),
            journal_root: root.join("journals"),
            codex_binary: root.join("codex"),
            zstd_binary: root.join("zstd"),
            codex_sha256: "0".repeat(64),
            backup_volume_uuid: "fixture".into(),
            enabled: true,
            grace_hours: 24,
            max_tasks: 4,
            max_source_bytes: GIB,
            max_raw_bytes_per_task: GIB,
            max_seconds: 1800,
            min_free_bytes: GIB,
            exclude_threads: Vec::new(),
            policy_sha256: "1".repeat(64),
        };
        let source = policy
            .codex_home
            .join("archived_sessions")
            .join(format!("rollout-{CHILD}.jsonl"));
        old_file(
            &source,
            &encode(&records(CHILD, &"old inherited ".repeat(100))),
        );
        let database = Connection::open(policy.codex_home.join("state_5.sqlite")).unwrap();
        database.execute_batch("CREATE TABLE threads(id TEXT PRIMARY KEY,rollout_path TEXT,source TEXT,history_mode TEXT,archived INTEGER,archived_at INTEGER,updated_at INTEGER,is_pinned INTEGER); CREATE TABLE thread_spawn_edges(parent_thread_id TEXT,child_thread_id TEXT);").unwrap();
        let mut child = row(CHILD, Some(PARENT));
        child.rollout_path = source.to_str().unwrap().into();
        for row in [row(PARENT, None), child] {
            Self::insert(&database, &row);
        }
        drop(database);
        Self {
            _temp: temp,
            registry: root.join("state/worktree-gc/protections.json"),
            root,
            source,
            policy,
        }
    }
    fn insert(database: &Connection, row: &Row) {
        database
            .execute(
                "INSERT INTO threads VALUES (?,?,?,?,?,?,?,?)",
                rusqlite::params![
                    row.id,
                    row.rollout_path,
                    row.source,
                    row.history_mode,
                    row.archived,
                    row.archived_at,
                    row.updated_at,
                    row.is_pinned
                ],
            )
            .unwrap();
    }
    fn db(&self) -> Connection {
        Connection::open(self.policy.codex_home.join("state_5.sqlite")).unwrap()
    }
    fn candidate(&self) -> Candidate {
        let (rows, edges) = index_snapshot(&self.policy.codex_home).unwrap();
        plan(&rows, &edges, &self.policy, now())
            .unwrap()
            .selected
            .remove(0)
    }
    fn run(&self, apply: bool, runtime: &FakeRuntime<'_>) -> Result<Value> {
        batch(&self.policy, apply, runtime, &self.registry)
    }
    fn runtime(&self) -> FakeRuntime<'_> {
        FakeRuntime {
            fixture: self,
            effect: Effect::Normal,
            calls: RefCell::new(Vec::new()),
            free: 100 * GIB,
            raw_override: None,
        }
    }
    fn journal(&self) -> Value {
        let path = fs::read_dir(&self.policy.journal_root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|e| e == "json"))
            .unwrap();
        serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
    }
    fn protect(&self, path: Value) {
        fs::create_dir_all(self.registry.parent().unwrap()).unwrap();
        fs::write(&self.registry,serde_json::to_vec(&json!({"version":1,"leases":[{"id":"p-0123456789abcdef","path":path,"reason":"fixture","created_at_unix":100,"expires_at_unix":now()+3600}]})).unwrap()).unwrap();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Effect {
    Normal,
    NativeFailure,
    CorruptContinuation,
    RemoveEdge,
    ConflictingEdge,
    MetadataDrift,
    QuietFailure,
    VolumeFailure,
    BackupDrift,
    BackupReplacement,
    Interrupted,
    Signal,
}

struct FakeRuntime<'a> {
    fixture: &'a Fixture,
    effect: Effect,
    calls: RefCell<Vec<(String, bool)>>,
    free: u64,
    raw_override: Option<u64>,
}
impl Runtime for FakeRuntime<'_> {
    fn guard(&self) -> Result<()> {
        Ok(())
    }
    fn volume(&self) -> Result<()> {
        ensure!(self.effect != Effect::VolumeFailure, "volume mismatch");
        Ok(())
    }
    fn quiet(&self, _: Option<&Path>) -> Result<()> {
        ensure!(self.effect != Effect::QuietFailure, "store active");
        Ok(())
    }
    fn verify_binary(&self) -> Result<()> {
        Ok(())
    }
    fn context(&self, path: &Path, tid: &str) -> Result<(Continuation, u64)> {
        let (context, raw) = proof(
            &fs::read(path)?,
            tid,
            self.fixture.policy.max_raw_bytes_per_task,
        )?;
        Ok((context, self.raw_override.unwrap_or(raw)))
    }
    fn free(&self, _: &Path) -> Result<u64> {
        Ok(self.free)
    }
    fn native(&self, tid: &str, apply: bool) -> Result<Value> {
        self.calls.borrow_mut().push((tid.into(), apply));
        if apply {
            if self.effect == Effect::Signal {
                let cancellation = io::Cancellation::install()?;
                let ready = PathBuf::from(
                    std::env::var_os("WORKTREE_GC_SIGNAL_FIXTURE")
                        .context("signal fixture root")?,
                );
                io::capture(
                    std::process::Command::new("/bin/sleep").arg("30"),
                    &mut |pid| {
                        if !ready.exists() {
                            fs::write(&ready, pid.to_string())?;
                        }
                        cancellation.check()
                    },
                )?;
                bail!("signal fixture reached native timeout unexpectedly");
            }
            ensure!(self.effect != Effect::NativeFailure, "native failure");
            ensure!(self.effect != Effect::Interrupted, "operator interrupted");
            let bytes = fs::read(&self.fixture.source)?;
            let mut records = bytes
                .split(|b| *b == b'\n')
                .filter(|line| !line.is_empty())
                .map(serde_json::from_slice)
                .collect::<serde_json::Result<Vec<Value>>>()?;
            records.remove(1);
            if self.effect == Effect::CorruptContinuation {
                records.push(
                    json!({"type":"response_item","payload":{"type":"message","text":"drift"}}),
                );
            }
            if self.effect == Effect::MetadataDrift {
                records[0]["payload"]["base_instructions"] =
                    json!({"text":"unexpected replacement"});
            }
            fs::write(&self.fixture.source, encode(&records))?;
            let database = self.fixture.db();
            database.execute(
                "UPDATE threads SET history_mode='paginated' WHERE id=?",
                [tid],
            )?;
            if self.effect == Effect::RemoveEdge {
                database.execute(
                    "DELETE FROM thread_spawn_edges WHERE child_thread_id=?",
                    [tid],
                )?;
            }
            if self.effect == Effect::ConflictingEdge {
                database.execute("INSERT INTO thread_spawn_edges VALUES (?,?)", [OTHER, tid])?;
            }
            if matches!(self.effect, Effect::BackupDrift | Effect::BackupReplacement) {
                let journal = self.fixture.journal();
                let backup = Path::new(journal["backup"].as_str().unwrap());
                if self.effect == Effect::BackupReplacement {
                    let original = fs::read(backup)?;
                    fs::rename(backup, backup.with_extension("saved"))?;
                    fs::write(backup, original)?;
                } else {
                    fs::write(backup, b"corrupted original")?;
                }
            }
        }
        Ok(json!({"outcomes":[{"thread_id":tid,"status":if apply {"migrated"} else {"eligible"}}]}))
    }
}

#[test]
fn dry_run_has_no_write_or_native_surface() {
    let f = Fixture::new();
    let rt = f.runtime();
    let before = fs::read(&f.source).unwrap();
    let report = f.run(false, &rt).unwrap();
    assert_eq!(report["plan"]["selected"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read_dir(&f.policy.journal_root).unwrap().count(), 0);
    assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
    assert!(!f.registry.parent().unwrap().exists());
    assert!(rt.calls.borrow().is_empty());
    assert_eq!(before, fs::read(&f.source).unwrap());
}

#[test]
fn scalar_root_sources_preserve_structured_child_lineage() {
    let f = Fixture::new();
    for source in ["cli", "vscode", "exec", "mcp", "unknown", "\"cli\""] {
        f.db()
            .execute("UPDATE threads SET source=? WHERE id=?", [source, PARENT])
            .unwrap();
        let candidate = f.candidate();
        assert_eq!(candidate.parent_id, PARENT);
        assert_eq!(candidate.row.id, CHILD);
    }
}

#[test]
fn malformed_structured_lineage_still_refuses() {
    let f = Fixture::new();
    f.db()
        .execute(
            "UPDATE threads SET source=? WHERE id=?",
            ["{\"subagent\":", PARENT],
        )
        .unwrap();
    assert!(f.run(false, &f.runtime()).is_err());
}

#[test]
fn batch_native_backup_continuation_and_parent_parity() {
    let f = Fixture::new();
    let rt = f.runtime();
    let before = fs::read(&f.source).unwrap();
    let report = f.run(true, &rt).unwrap();
    let j = f.journal();
    assert_eq!(j["phase"], "verified");
    assert_eq!(fs::read(j["backup"].as_str().unwrap()).unwrap(), before);
    assert_eq!(j["before_context"], j["after_context"]);
    assert!(j["file_bytes_reduced"].as_i64().unwrap() > 0);
    assert_eq!(report["results"][0]["filesystem_available_delta"], 0);
    let (rows, _) = index_snapshot(&f.policy.codex_home).unwrap();
    assert_eq!(
        rows.iter().find(|r| r.id == PARENT).unwrap(),
        &row(PARENT, None)
    );
    assert_eq!(
        *rt.calls.borrow(),
        vec![(CHILD.into(), false), (CHILD.into(), true)]
    );
    assert!(f.run(true, &rt).unwrap()["results"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn disabled_policy_does_not_create_journal_or_native_call() {
    let mut f = Fixture::new();
    f.policy.enabled = false;
    let rt = f.runtime();
    assert!(format!("{:#}", f.run(true, &rt).unwrap_err()).contains("disabled"));
    assert_eq!(fs::read_dir(&f.policy.journal_root).unwrap().count(), 0);
    assert!(rt.calls.borrow().is_empty());
}

#[test]
fn native_failure_preserves_backup_and_blocks_next_batch() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::NativeFailure;
    assert!(f.run(true, &rt).is_err());
    let j = f.journal();
    assert_eq!(j["phase"], "recovery_required");
    assert!(Path::new(j["backup"].as_str().unwrap()).is_file());
    assert!(format!("{:#}", f.run(true, &rt).unwrap_err()).contains("recovery pending"));
    assert_eq!(rt.calls.borrow().len(), 2);
}

#[test]
fn continuation_mismatch_is_durable_and_never_auto_restores() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::CorruptContinuation;
    assert!(format!("{:#}", f.run(true, &rt).unwrap_err()).contains("continuation mismatch"));
    let j = f.journal();
    assert_eq!(j["phase"], "recovery_required");
    assert!(String::from_utf8(fs::read(&f.source).unwrap())
        .unwrap()
        .contains("drift"));
    assert!(
        !String::from_utf8(fs::read(j["backup"].as_str().unwrap()).unwrap())
            .unwrap()
            .contains("drift")
    );
}

#[test]
fn removed_edge_only_parent_requires_recovery() {
    let f = Fixture::new();
    f.db()
        .execute("UPDATE threads SET source='cli' WHERE id=?", [CHILD])
        .unwrap();
    f.db()
        .execute(
            "INSERT INTO thread_spawn_edges VALUES (?,?)",
            [PARENT, CHILD],
        )
        .unwrap();
    let mut rt = f.runtime();
    rt.effect = Effect::RemoveEdge;
    assert!(f.run(true, &rt).is_err());
    assert_eq!(f.journal()["phase"], "recovery_required");
}

#[test]
fn conflicting_parent_edge_requires_recovery() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::ConflictingEdge;
    assert!(f.run(true, &rt).is_err());
    assert_eq!(f.journal()["phase"], "recovery_required");
}

#[test]
fn session_metadata_drift_is_durable() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::MetadataDrift;
    assert!(format!("{:#}", f.run(true, &rt).unwrap_err()).contains("continuation mismatch"));
    assert_eq!(f.journal()["phase"], "recovery_required");
}

#[test]
fn quiet_store_refusal_precedes_backup() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::QuietFailure;
    assert!(f.run(true, &rt).is_err());
    assert!(rt.calls.borrow().is_empty());
    assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
}

#[test]
fn external_volume_refusal_precedes_backup() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::VolumeFailure;
    assert!(f.run(true, &rt).is_err());
    assert!(rt.calls.borrow().is_empty());
    assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
}

#[test]
fn unarchive_between_plan_and_apply_refuses() {
    let f = Fixture::new();
    let candidate = f.candidate();
    let rt = f.runtime();
    f.db()
        .execute("UPDATE threads SET archived=0 WHERE id=?", [CHILD])
        .unwrap();
    let guard = MigrationProtectionGuard::acquire(&f.registry).unwrap();
    assert!(migrate_one(&candidate, &f.policy, &rt, &guard).is_err());
    assert!(rt.calls.borrow().is_empty());
}

#[test]
fn source_identity_drift_refuses() {
    let f = Fixture::new();
    let candidate = f.candidate();
    fs::write(&f.source, encode(&records(CHILD, "changed"))).unwrap();
    assert!(
        format!("{:#}", refresh(&candidate, &f.policy, false).unwrap_err())
            .contains("identity changed")
    );
}

#[test]
fn rollout_traversal_outside_archive_refuses_before_native() {
    let f = Fixture::new();
    let path = f
        .policy
        .codex_home
        .join("archived_sessions/../outside.jsonl");
    f.db()
        .execute(
            "UPDATE threads SET rollout_path=? WHERE id=?",
            [path.to_str().unwrap(), CHILD],
        )
        .unwrap();
    let rt = f.runtime();
    let report = f.run(true, &rt).unwrap();
    assert!(report["plan"]["selected"].as_array().unwrap().is_empty());
    assert!(rt.calls.borrow().is_empty());
    assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
}

#[test]
fn rollout_archive_symlink_escape_refuses() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::create_dir(&outside).unwrap();
    let alias = f.policy.codex_home.join("archived_sessions/alias");
    symlink(&outside, &alias).unwrap();
    let mut changed = f.candidate().row;
    changed.rollout_path = alias
        .join(f.source.file_name().unwrap())
        .to_str()
        .unwrap()
        .into();
    fs::write(outside.join(f.source.file_name().unwrap()), b"original").unwrap();
    assert!(rollout_path(&f.policy.codex_home, &changed).is_err());
}

#[test]
fn parent_state_drift_refuses() {
    let f = Fixture::new();
    let candidate = f.candidate();
    f.db()
        .execute("UPDATE threads SET updated_at=101 WHERE id=?", [PARENT])
        .unwrap();
    assert!(
        format!("{:#}", refresh(&candidate, &f.policy, false).unwrap_err())
            .contains("parent index state changed")
    );
}

#[test]
fn new_child_in_source_or_edge_prevents_migration() {
    let f = Fixture::new();
    let candidate = f.candidate();
    f.db()
        .execute(
            "INSERT INTO thread_spawn_edges VALUES (?,?)",
            [CHILD, OTHER],
        )
        .unwrap();
    assert!(refresh(&candidate, &f.policy, false).is_err());
}

#[test]
fn recursive_protection_prevents_native_call() {
    let f = Fixture::new();
    f.protect(json!(f.policy.codex_home));
    let rt = f.runtime();
    assert!(format!("{:#}", f.run(true, &rt).unwrap_err()).contains("recursive protection"));
    assert!(rt.calls.borrow().is_empty());
}

#[test]
fn pending_partial_journal_blocks_batch() {
    let f = Fixture::new();
    fs::write(f.policy.journal_root.join("broken.pending"), b"partial").unwrap();
    assert!(format!("{:#}", f.run(true, &f.runtime()).unwrap_err()).contains("pending or unknown"));
}

#[test]
fn native_scratch_budget_uses_raw_bytes() {
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.raw_override = Some(60 * GIB);
    let guard = MigrationProtectionGuard::acquire(&f.registry).unwrap();
    assert!(format!(
        "{:#}",
        migrate_one(&f.candidate(), &f.policy, &rt, &guard).unwrap_err()
    )
    .contains("headroom"));
    assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
}

#[test]
fn no_eligible_tasks_does_not_count_parent_as_child() {
    let mut f = Fixture::new();
    f.policy.exclude_threads.push(CHILD.into());
    assert!(f.run(false, &f.runtime()).unwrap()["plan"]["selected"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn ambiguous_compressed_spelling_symlink_and_hardlink_refuse() {
    let f = Fixture::new();
    let child = f.candidate().row;
    let compressed = f.source.with_extension("jsonl.zst");
    fs::write(&compressed, b"fake").unwrap();
    assert!(rollout_path(&f.policy.codex_home, &child).is_err());
    fs::remove_file(compressed).unwrap();
    let link = f.root.join("link");
    fs::hard_link(&f.source, &link).unwrap();
    assert!(identity(&f.source).is_err());
    fs::remove_file(&link).unwrap();
    fs::rename(&f.source, &link).unwrap();
    symlink(&link, &f.source).unwrap();
    assert!(rollout_path(&f.policy.codex_home, &child).is_err());
}

#[test]
fn grace_uses_archive_updated_and_file_times() {
    let f = Fixture::new();
    let (rows, edges) = index_snapshot(&f.policy.codex_home).unwrap();
    let (parents, children) = lineage(&rows, &edges).unwrap();
    let ids = rows.iter().map(|r| r.id.as_str()).collect();
    for archived in [true, false] {
        let mut child = f.candidate().row;
        if archived {
            child.archived_at = Some(now() as i64);
        } else {
            child.updated_at = now() as i64;
        }
        assert_eq!(
            eligibility(&child, &parents, &children, &ids, &f.policy, now()),
            Some("archive_or_activity_grace")
        );
    }
    std::fs::File::options()
        .write(true)
        .open(&f.source)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    assert!(f.run(false, &f.runtime()).unwrap()["plan"]["selected"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn active_parent_does_not_hold_archived_leaf() {
    let f = Fixture::new();
    f.db()
        .execute("UPDATE threads SET archived=0 WHERE id=?", [PARENT])
        .unwrap();
    assert_eq!(
        f.run(false, &f.runtime()).unwrap()["plan"]["selected"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn parent_conflict_retains_candidate() {
    let f = Fixture::new();
    f.db()
        .execute(
            "INSERT INTO thread_spawn_edges VALUES (?,?)",
            [OTHER, CHILD],
        )
        .unwrap();
    assert!(f.run(false, &f.runtime()).unwrap()["plan"]["selected"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn byte_and_task_bounds() {
    let mut f = Fixture::new();
    f.policy.max_source_bytes = 1;
    let report = f.run(false, &f.runtime()).unwrap();
    assert_eq!(report["plan"]["eligible_count"], 1);
    assert!(report["plan"]["selected"].as_array().unwrap().is_empty());
}

#[test]
fn selection_obeys_count_with_many_candidates() {
    let f = Fixture::new();
    let database = f.db();
    for n in 3..12 {
        let id = format!("00000000-0000-4000-8000-{n:012}");
        let mut row = row(&id, Some(PARENT));
        let path = f.source.with_file_name(format!("rollout-{id}.jsonl"));
        old_file(&path, &encode(&records(&id, "")));
        row.rollout_path = path.to_str().unwrap().into();
        Fixture::insert(&database, &row);
    }
    drop(database);
    let report = f.run(false, &f.runtime()).unwrap();
    assert_eq!(report["plan"]["eligible_count"], 10);
    assert_eq!(report["plan"]["selected"].as_array().unwrap().len(), 4);
    assert_eq!(report["plan"]["selected"][0]["row"]["id"], CHILD);
}

#[test]
fn index_cap_is_explicit() {
    let f = Fixture::new();
    let mut db = f.db();
    let tx = db.transaction().unwrap();
    for _ in 0..=INDEX_LIMIT {
        tx.execute(
            "INSERT INTO thread_spawn_edges VALUES (?,?)",
            [PARENT, CHILD],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    assert!(
        format!("{:#}", index_snapshot(&f.policy.codex_home).unwrap_err()).contains("cap exceeded")
    );
}

#[test]
fn malformed_protection_paths_fail_closed_before_normalization() {
    let f = Fixture::new();
    for path in [
        json!(format!("{}/.", f.policy.codex_home.display())),
        json!(format!("{}/../archive", f.policy.codex_home.display())),
        json!(format!("{}/./archive", f.policy.codex_home.display())),
        json!(format!("{}/\narchive", f.policy.codex_home.display())),
        json!(format!("{}/\u{7f}archive", f.policy.codex_home.display())),
        json!(3),
    ] {
        f.protect(path);
        let before = fs::read(&f.registry).unwrap();
        let guard = MigrationProtectionGuard::acquire(&f.registry).unwrap();
        let error = guard
            .check(&f.policy.surfaces(), SystemTime::now())
            .unwrap_err();
        assert!(format!("{error:#}").contains("protection"));
        assert_eq!(fs::read(&f.registry).unwrap(), before);
    }
}

#[test]
fn first_use_creates_and_locks_missing_state_directory() {
    let f = Fixture::new();
    let guard = MigrationProtectionGuard::acquire(&f.registry).unwrap();
    guard
        .check(&f.policy.surfaces(), SystemTime::now())
        .unwrap();
    assert!(io::lock_file(&f.registry.with_file_name("protections.lock"), false).is_err());
    assert!(!f.registry.exists());
}

#[test]
fn existing_registry_retains_active_protections() {
    let f = Fixture::new();
    f.protect(json!(f.root));
    let before = fs::read(&f.registry).unwrap();
    let guard = MigrationProtectionGuard::acquire(&f.registry).unwrap();
    assert!(guard
        .check(&f.policy.surfaces(), SystemTime::now())
        .is_err());
    assert_eq!(before, fs::read(&f.registry).unwrap());
}

#[test]
fn symlinked_state_is_rejected_before_creation() {
    let f = Fixture::new();
    let alias = f.root.join("alias");
    let real = f.root.join("real");
    fs::create_dir(&real).unwrap();
    symlink(&real, &alias).unwrap();
    assert!(
        MigrationProtectionGuard::acquire(&alias.join("worktree-gc/protections.json")).is_err()
    );
    assert_eq!(fs::read_dir(real).unwrap().count(), 0);
}

#[test]
fn state_creation_error_remains_a_refusal() {
    let f = Fixture::new();
    let obstacle = f.root.join("file");
    fs::write(&obstacle, b"not a directory").unwrap();
    assert!(
        MigrationProtectionGuard::acquire(&obstacle.join("worktree-gc/protections.json")).is_err()
    );
}

#[test]
fn session_metadata_normalizes_only_native_representation_fields() {
    let mut records = records(CHILD, "");
    let before = proof(&encode(&records), CHILD, GIB).unwrap().0;
    records[0]["payload"]["history_mode"] = json!("paginated");
    records[0]["payload"]["subagent_history_start_ordinal"] = json!(5);
    assert_eq!(before, proof(&encode(&records), CHILD, GIB).unwrap().0);
    for (field, value) in [
        ("cwd", json!("/changed")),
        ("model_provider", json!("different")),
        ("base_instructions", json!({"text":"changed"})),
        ("git", json!({"commit_hash":"different"})),
        ("future_field", Value::Null),
    ] {
        records[0]["payload"][field] = value;
        assert_ne!(
            before.session_meta,
            proof(&encode(&records), CHILD, GIB).unwrap().0.session_meta
        );
        records[0]["payload"].as_object_mut().unwrap().remove(field);
    }
}

#[test]
fn state_and_response_interleaving_is_preserved() {
    let mut records = records(CHILD, "");
    let before = proof(&encode(&records), CHILD, GIB).unwrap().0;
    records.swap(3, 4);
    let after = proof(&encode(&records), CHILD, GIB).unwrap().0;
    assert_eq!(before.state, after.state);
    assert_eq!(before.responses, after.responses);
    assert_ne!(before.ordered_continuation, after.ordered_continuation);
}

#[test]
fn normal_shutdown_raises_through_the_journal_boundary() {
    let cancellation = io::Cancellation::fixture();
    cancellation
        .flag
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(cancellation.check().is_err());
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::Interrupted;
    assert!(f.run(true, &rt).is_err());
    assert_eq!(f.journal()["phase"], "recovery_required");
}

#[test]
fn streaming_and_exact_optional_null_normalization() {
    let mut records = records(CHILD, "");
    let expected = proof(&encode(&records), CHILD, GIB).unwrap().0;
    records[2]["payload"]["compaction_response_id"] = Value::Null;
    records[2]["payload"]["latest_token_usage_record"] = Value::Null;
    records[3]["payload"]["content"] = Value::Null;
    let bytes = encode(&records);
    let mut parser = ContextParser::new(CHILD, GIB);
    for chunk in bytes.chunks(7) {
        parser.feed(chunk).unwrap();
    }
    assert_eq!(parser.finish().unwrap().0, expected);
    records[2]["payload"]["unknown"] = Value::Null;
    assert_ne!(proof(&encode(&records), CHILD, GIB).unwrap().0, expected);
}

#[test]
fn identity_truncation_and_decompression_caps() {
    let bytes = encode(&records(CHILD, ""));
    assert!(proof(&bytes, OTHER, GIB).is_err());
    assert!(proof(&bytes[..bytes.len() - 1], CHILD, GIB).is_err());
    assert!(proof(&bytes, CHILD, 10).is_err());
}

#[test]
fn latest_checkpoint_replaces_prior_suffix() {
    let records = records(CHILD, "");
    let before = encode(&records);
    let mut after = before.clone();
    after.extend(encode(&records[2..]));
    assert_eq!(
        proof(&before, CHILD, GIB).unwrap(),
        proof(&after, CHILD, GIB)
            .map(|(p, _)| (p, before.len() as u64))
            .unwrap()
    );
}

#[test]
fn backup_readback_and_exclusive_destination() {
    let f = Fixture::new();
    let destination = f.root.join("copy");
    let before = fs::read(&f.source).unwrap();
    assert_eq!(
        io::copy_verified(&f.source, &destination, &mut || Ok(())).unwrap(),
        format!("{:x}", Sha256::digest(&before))
    );
    assert_eq!(fs::read(&destination).unwrap(), before);
    assert!(io::copy_verified(&f.source, &destination, &mut || Ok(())).is_err());
}

#[test]
fn hardlinked_index_and_each_existing_sidecar_refuse_before_native() {
    for name in [
        "state_5.sqlite",
        "state_5.sqlite-wal",
        "state_5.sqlite-shm",
        "state_5.sqlite-journal",
    ] {
        let f = Fixture::new();
        let path = f.policy.codex_home.join(name);
        if name != "state_5.sqlite" {
            fs::write(&path, b"sidecar").unwrap();
        }
        fs::hard_link(&path, f.root.join("linked")).unwrap();
        let rt = f.runtime();
        assert!(f.run(true, &rt).is_err());
        assert!(rt.calls.borrow().is_empty());
        assert_eq!(fs::read_dir(&f.policy.backup_root).unwrap().count(), 0);
    }
}

#[test]
fn protected_index_and_sidecars_cover_complete_native_mutation_surface() {
    for name in [
        "state_5.sqlite",
        "state_5.sqlite-wal",
        "state_5.sqlite-shm",
        "state_5.sqlite-journal",
    ] {
        let f = Fixture::new();
        f.protect(json!(f.policy.codex_home.join(name)));
        let rt = f.runtime();
        assert!(f.run(true, &rt).is_err());
        assert!(rt.calls.borrow().is_empty());
    }
}

#[test]
fn lease_replaced_by_symlink_refuses_even_when_lexically_disjoint() {
    let f = Fixture::new();
    let lease = f.root.join("lease");
    fs::create_dir(&lease).unwrap();
    f.protect(json!(lease));
    fs::remove_dir(&lease).unwrap();
    symlink(&f.policy.codex_home, &lease).unwrap();
    let rt = f.runtime();
    assert!(f.run(true, &rt).is_err());
    assert!(rt.calls.borrow().is_empty());
}

#[test]
fn final_backup_corruption_and_same_bytes_replacement_require_recovery() {
    for effect in [Effect::BackupDrift, Effect::BackupReplacement] {
        let f = Fixture::new();
        let mut rt = f.runtime();
        rt.effect = effect;
        assert!(format!("{:#}", f.run(true, &rt).unwrap_err())
            .contains("post-apply original backup drift"));
        assert_eq!(f.journal()["phase"], "recovery_required");
    }
}

#[test]
fn native_process_probe_allows_only_exact_owned_pid() {
    let evidence = "123 /Applications/ChatGPT.app/Contents/Resources/codex\n456 /usr/bin/other\n";
    assert!(native::validate_processes(evidence, &[]).is_err());
    native::validate_processes(evidence, &[123]).unwrap();
    assert!(native::validate_processes(
        &format!("{evidence}789 /Applications/ChatGPT.app/Contents/Resources/codex\n"),
        &[123]
    )
    .is_err());
    assert!(native::validate_processes("", &[]).is_err());
    assert!(native::validate_processes("incomplete", &[]).is_err());
}

#[test]
fn preflight_protection_observation_never_creates_state() {
    let f = Fixture::new();
    let registry = f.root.join("absent-state/protections.json");
    MigrationProtectionGuard::observe(&registry, &f.policy.surfaces(), SystemTime::now()).unwrap();
    assert!(!registry.parent().unwrap().exists());
    f.protect(json!(f.policy.codex_home));
    let before = fs::read(&f.registry).unwrap();
    assert!(MigrationProtectionGuard::observe(
        &f.registry,
        &f.policy.surfaces(),
        SystemTime::now()
    )
    .is_err());
    assert_eq!(fs::read(&f.registry).unwrap(), before);
    assert!(!f
        .registry
        .parent()
        .unwrap()
        .join("protections.lock")
        .exists());
}

#[test]
fn child_output_limit_and_timeout_teardown() {
    let started = Instant::now();
    let mut output = std::process::Command::new("/usr/bin/yes");
    output.arg("fixture");
    let error = io::capture(&mut output, &mut |_| {
        ensure!(started.elapsed() < Duration::from_secs(10), "deadline");
        Ok(())
    })
    .unwrap_err();
    assert!(format!("{error:#}").contains("stdout cap"));
    let started = Instant::now();
    let pid = std::cell::Cell::new(0);
    let error = io::capture(
        std::process::Command::new("/bin/sleep").arg("30"),
        &mut |child| {
            pid.set(child);
            ensure!(started.elapsed() < Duration::from_millis(100), "deadline");
            Ok(())
        },
    )
    .unwrap_err();
    assert!(format!("{error:#}").contains("deadline"));
    assert_ne!(pid.get(), 0);
    assert_eq!(unsafe { libc::kill(pid.get() as i32, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[test]
fn signal_fixture_child() {
    let Some(ready) = std::env::var_os("WORKTREE_GC_SIGNAL_FIXTURE") else {
        return;
    };
    let f = Fixture::new();
    let mut rt = f.runtime();
    rt.effect = Effect::Signal;
    let error = f.run(true, &rt).unwrap_err();
    assert!(format!("{error:#}").contains("interrupted"));
    let journal = f.journal();
    assert_eq!(journal["phase"], "recovery_required");
    assert!(Path::new(journal["backup"].as_str().unwrap()).is_file());
    let child: i32 = fs::read_to_string(&ready).unwrap().parse().unwrap();
    assert_eq!(unsafe { libc::kill(child, 0) }, -1);
    fs::write(
        Path::new(&ready).with_extension("result"),
        serde_json::to_vec(&journal).unwrap(),
    )
    .unwrap();
}

#[test]
fn term_and_hup_teardown_owned_native_group_and_persist_journal() {
    for signal in [libc::SIGTERM, libc::SIGHUP] {
        let temp = tempfile::tempdir().unwrap();
        let ready = temp.path().join("ready");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "codex_migration::tests::signal_fixture_child",
                "--nocapture",
            ])
            .env("WORKTREE_GC_SIGNAL_FIXTURE", &ready);
        let mut child = io::OwnedProcess::spawn(&mut command, false).unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut sent = false;
        let mut output = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "signal fixture deadline");
            if !sent && fs::read_to_string(&ready).is_ok_and(|s| s.parse::<u32>().is_ok()) {
                assert_eq!(unsafe { libc::kill(child.id() as i32, signal) }, 0);
                sent = true;
            }
            if let Some(status) = child
                .poll(&mut |block| {
                    ensure!(
                        output.len() + block.len() < OUTPUT_LIMIT,
                        "fixture output cap"
                    );
                    output.extend_from_slice(block);
                    Ok(())
                })
                .unwrap()
            {
                assert!(status.success(), "{}", String::from_utf8_lossy(&output));
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        child.stop().unwrap();
        assert!(sent);
        let journal: Value =
            serde_json::from_slice(&fs::read(ready.with_extension("result")).unwrap()).unwrap();
        assert_eq!(journal["phase"], "recovery_required");
    }
}

#[test]
fn backup_requires_known_disjoint_physical_external_disks() {
    let disks = |names: &[&str]| {
        names
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<BTreeSet<_>>()
    };
    native::physical_disjoint(&disks(&["disk0"]), &disks(&["disk4"]), &disks(&["disk4"])).unwrap();
    for (source, backup, external) in [
        (disks(&["disk0"]), disks(&["disk0"]), disks(&["disk0"])),
        (disks(&["disk0"]), disks(&["disk4"]), disks(&[])),
        (disks(&[]), disks(&["disk4"]), disks(&["disk4"])),
        (disks(&["disk0"]), disks(&[]), disks(&[])),
        (
            disks(&["disk0"]),
            disks(&["disk4", "disk5"]),
            disks(&["disk4"]),
        ),
    ] {
        assert!(native::physical_disjoint(&source, &backup, &external).is_err());
    }
}

#[derive(Default)]
struct FakeRecovery {
    fail_register: bool,
    empty_history: bool,
    calls: RefCell<Vec<PathBuf>>,
}
impl native::RecoveryRuntime for FakeRecovery {
    fn guard(&self) -> Result<()> {
        Ok(())
    }
    fn volume(&self, _: &Path, _: &Path, _: &str) -> Result<()> {
        Ok(())
    }
    fn verify_binary(&self, _: &Path, _: &str) -> Result<()> {
        Ok(())
    }
    fn free(&self, _: &Path) -> Result<u64> {
        Ok(100 * GIB)
    }
    fn register(&self, _: &Path, home: &Path, tid: &str, _: &Path) -> Result<Value> {
        assert!(
            !home.join("state_5.sqlite").exists(),
            "native registration must start with absent index"
        );
        self.calls.borrow_mut().push(home.to_owned());
        ensure!(!self.fail_register, "registration failed");
        let source = fs::read_dir(home.join("archived_sessions"))?
            .next()
            .context("archive original")??
            .path();
        let original = fs::read(&source)?;
        let database = Connection::open(home.join("state_5.sqlite"))?;
        database.execute_batch(
            "CREATE TABLE threads(id TEXT PRIMARY KEY, rollout_path TEXT, archived INTEGER);",
        )?;
        let sessions = home.join("sessions");
        fs::create_dir(&sessions)?;
        let restored = sessions.join(source.file_name().unwrap());
        fs::rename(source, &restored)?;
        database.execute(
            "INSERT INTO threads VALUES (?,?,0)",
            rusqlite::params![tid, restored.to_str().unwrap()],
        )?;
        Ok(
            json!({"restored":restored,"history_turns":if self.empty_history {0} else {1},"history_sha256":format!("{:x}",Sha256::digest(original)),"native_registered":true}),
        )
    }
}

#[test]
fn missing_backup_cannot_be_recovered() {
    let f = Fixture::new();
    f.run(true, &f.runtime()).unwrap();
    let journal = f.journal();
    fs::remove_file(journal["backup"].as_str().unwrap()).unwrap();
    let destination = f.root.join("recovered");
    let runtime = FakeRecovery::default();
    assert!(native::recover_with(&journal, &destination, &f.registry, &runtime).is_err());
    assert!(!destination.exists());
    assert!(runtime.calls.borrow().is_empty());
}

#[test]
fn recovery_registers_original_and_preserves_live_newer_data() {
    let f = Fixture::new();
    let original = fs::read(&f.source).unwrap();
    f.run(true, &f.runtime()).unwrap();
    let journal = f.journal();
    let live_after = fs::read(&f.source).unwrap();
    let destination = f.root.join("recovered");
    let runtime = FakeRecovery::default();
    let report = native::recover_with(&journal, &destination, &f.registry, &runtime).unwrap();
    assert_eq!(
        fs::read(report["restored"].as_str().unwrap()).unwrap(),
        original
    );
    assert_eq!(fs::read(&f.source).unwrap(), live_after);
    assert_eq!(*runtime.calls.borrow(), vec![destination.clone()]);
    let database = Connection::open(destination.join("state_5.sqlite")).unwrap();
    let archived: i64 = database
        .query_row("SELECT archived FROM threads WHERE id=?", [CHILD], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(archived, 0);
    assert!(native::recover_with(&journal, &destination, &f.registry, &runtime).is_err());
    assert!(native::recover_with(
        &journal,
        &f.policy.codex_home.join("danger"),
        &f.registry,
        &runtime
    )
    .is_err());
}

#[test]
fn partial_recovery_is_retained_off_destination_and_same_destination_can_retry() {
    let f = Fixture::new();
    f.run(true, &f.runtime()).unwrap();
    let journal = f.journal();
    let original = fs::read(journal["backup"].as_str().unwrap()).unwrap();
    let live_after = fs::read(&f.source).unwrap();
    let destination = f.root.join("recovered");
    let failing = FakeRecovery {
        fail_register: true,
        ..Default::default()
    };
    assert!(format!(
        "{:#}",
        native::recover_with(&journal, &destination, &f.registry, &failing).unwrap_err()
    )
    .contains("registration failed"));
    assert!(!destination.exists());
    assert!(fs::read_dir(&f.root).unwrap().any(|entry| entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".worktree-gc-recovery-")));
    let result = native::recover_with(
        &journal,
        &destination,
        &f.registry,
        &FakeRecovery::default(),
    )
    .unwrap();
    assert_eq!(
        fs::read(result["restored"].as_str().unwrap()).unwrap(),
        original
    );
    assert_eq!(fs::read(&f.source).unwrap(), live_after);
}

#[test]
fn recovery_rejects_backup_drift() {
    let f = Fixture::new();
    f.run(true, &f.runtime()).unwrap();
    let journal = f.journal();
    fs::write(journal["backup"].as_str().unwrap(), b"corrupt").unwrap();
    let destination = f.root.join("recovered");
    let runtime = FakeRecovery::default();
    assert!(native::recover_with(&journal, &destination, &f.registry, &runtime).is_err());
    assert!(!destination.exists());
    assert!(runtime.calls.borrow().is_empty());
}

#[test]
fn recovery_requires_nonempty_native_history_before_success() {
    let f = Fixture::new();
    f.run(true, &f.runtime()).unwrap();
    let runtime = FakeRecovery {
        empty_history: true,
        ..Default::default()
    };
    let destination = f.root.join("recovered");
    assert!(native::recover_with(&f.journal(), &destination, &f.registry, &runtime).is_err());
    assert!(!destination.exists());
}
#[test]
fn wal_writer_fixture_child() {
    let Some(home) = std::env::var_os("WORKTREE_GC_WAL_FIXTURE") else {
        return;
    };
    let home = PathBuf::from(home);
    let writer = Connection::open(home.join("state_5.sqlite")).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
    writer
        .execute("UPDATE threads SET updated_at=200 WHERE id=?", [CHILD])
        .unwrap();
    fs::write(home.join("writer-ready"), b"ready").unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    while !home.join("writer-release").exists() {
        assert!(Instant::now() < deadline, "WAL writer release deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(writer);
}

#[test]
fn wal_observation_is_readonly_before_dry_run_and_protection_refusal() {
    let fixture = Fixture::new();
    // A distinct process matches Codex ownership. SQLite shares a writable
    // unixShmNode across connections in one process, bypassing readonly_shm
    // evaluation on subsequent connections to that inode.
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "codex_migration::tests::wal_writer_fixture_child",
            "--nocapture",
        ])
        .env("WORKTREE_GC_WAL_FIXTURE", &fixture.policy.codex_home);
    let mut writer = io::OwnedProcess::spawn(&mut command, false).unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut output = Vec::new();
    let mut collect = |block: &[u8]| -> Result<()> {
        ensure!(
            output.len() + block.len() <= 16 * 1024,
            "WAL writer output cap"
        );
        output.extend_from_slice(block);
        Ok(())
    };
    while !fixture.policy.codex_home.join("writer-ready").exists() {
        assert!(Instant::now() < deadline, "WAL writer ready deadline");
        assert!(
            writer.poll(&mut collect).unwrap().is_none(),
            "WAL writer exited before ready"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let paths = ["state_5.sqlite", "state_5.sqlite-wal", "state_5.sqlite-shm"]
        .map(|name| fixture.policy.codex_home.join(name));
    let before: Vec<_> = paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                identity(path).unwrap(),
                io::hash(path, &mut || Ok(())).unwrap(),
            )
        })
        .collect();
    let result = fixture.run(false, &fixture.runtime()).unwrap();
    assert_eq!(result["plan"]["selected"][0]["row"]["updated_at"], 200);
    fixture.protect(json!(paths[2]));
    assert!(fixture.run(true, &fixture.runtime()).is_err());
    let after: Vec<_> = paths
        .iter()
        .map(|path| {
            (
                path.clone(),
                identity(path).unwrap(),
                io::hash(path, &mut || Ok(())).unwrap(),
            )
        })
        .collect();
    assert_eq!(before, after);
    fs::write(fixture.policy.codex_home.join("writer-release"), b"release").unwrap();
    loop {
        assert!(Instant::now() < deadline, "WAL writer teardown deadline");
        if let Some(status) = writer.poll(&mut collect).unwrap() {
            assert!(status.success(), "WAL writer failed: {status}");
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    writer.stop().unwrap();
}
