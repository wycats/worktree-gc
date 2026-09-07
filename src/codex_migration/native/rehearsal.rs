//! Fresh synthetic stores only; no caller-provided store can acquire isolation.
use super::*;

const FIXTURE_LIMIT: u64 = 1024 * 1024;

fn destination(policy: &Policy, workspace: &Path) -> Result<()> {
    validate_destination(workspace, &policy.surfaces())
}

fn validate_destination(workspace: &Path, surfaces: &[PathBuf]) -> Result<()> {
    io::path_syntax(workspace)?;
    canonical(workspace.parent().context("rehearsal parent")?, true)?;
    io::absent(workspace)?;
    for path in surfaces {
        ensure!(
            !io::intersects(workspace, path),
            "rehearsal overlaps configured store, backup or journal"
        );
    }
    Ok(())
}

fn fixture(home: &Path, id: &str, parent: Option<&str>) -> Result<Vec<u8>> {
    let timestamp = "2026-01-01T00:00:00Z";
    let message = json!({"type":"message","role":"user","content":[{"type":"input_text","text":"WORKTREE_GC_SYNTHETIC_HISTORY"}]});
    let source = parent.map_or(
        json!("cli"),
        |parent| json!({"subagent":{"thread_spawn":{"parent_thread_id":parent,"depth":1,"agent_path":null,"agent_nickname":null,"agent_role":null}}}),
    );
    let mut metadata = json!({"session_id":id,"id":id,"timestamp":timestamp,"cwd":home,"originator":"codex","cli_version":"0.153.4","model_provider":"openai","base_instructions":null,"history_mode":"legacy","source":source});
    if let Some(parent) = parent {
        metadata["parent_thread_id"] = json!(parent);
    }
    let records = [
        json!({"timestamp":timestamp,"type":"session_meta","payload":metadata}),
        json!({"timestamp":timestamp,"type":"response_item","payload":message}),
        json!({"timestamp":timestamp,"type":"event_msg","payload":{"type":"user_message","message":"WORKTREE_GC_SYNTHETIC_HISTORY","text_elements":[],"local_images":[]}}),
        json!({"timestamp":timestamp,"type":"compacted","payload":{"message":"synthetic checkpoint","replacement_history":[message]}}),
    ];
    let bytes = records
        .iter()
        .map(|r| format!("{r}\n"))
        .collect::<String>()
        .into_bytes();
    ensure!(
        bytes.len() as u64 <= FIXTURE_LIMIT,
        "synthetic fixture size bound"
    );
    Ok(bytes)
}

fn create_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn age_fixture(home: &Path, child_path: &Path, child: &str) -> Result<()> {
    let connection = Connection::open(home.join("state_5.sqlite"))?;
    connection.execute("UPDATE threads SET archived=1, archived_at=1, updated_at=1, history_mode='legacy', rollout_path=?1 WHERE id=?2", rusqlite::params![child_path.to_str().context("fixture path")?, child])?;
    // The fixture writer is the last writer after native registration ends.
    // Finish its WAL and use a closed rollback-journal database, so production
    // readonly_shm inspection does not need to create a missing SHM sidecar.
    // This changes only freshly created synthetic state, never the live store.
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")?;
    connection.close().map_err(|(_, error)| error)?;
    OpenOptions::new()
        .write(true)
        .open(child_path)?
        .set_times(fs::FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(1)))?;
    index_snapshot(home).context("checking closed synthetic index readability")?;
    Ok(())
}

struct Recovery<'a> {
    native: NativeRecovery<'a>,
    scope: &'a RehearsalScope,
}
impl RecoveryRuntime for Recovery<'_> {
    fn guard(&self) -> Result<()> {
        self.scope.check()?;
        self.native.guard()
    }
    fn volume(&self, source: &Path, backup: &Path, uuid: &str) -> Result<()> {
        volume(source, backup, uuid, &mut || self.guard())
    }
    fn verify_binary(&self, binary: &Path, sha: &str) -> Result<()> {
        self.native.verify_binary(binary, sha)
    }
    fn register(&self, binary: &Path, home: &Path, tid: &str, _live: &Path) -> Result<Value> {
        register_history(binary, home, tid, &self.scope.live, &mut || self.guard())
    }
}

pub fn rehearse(config: &Path, workspace: &Path) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "migration rehearsal requires macOS"
    );
    let policy = Policy::load(config)?;
    destination(&policy, workspace)?;
    let cancel = Cancellation::install()?;
    let deadline = Instant::now() + Duration::from_secs(600);
    let guard = || {
        cancel.check()?;
        ensure!(Instant::now() < deadline, "rehearsal ten-minute deadline");
        ensure!(
            io::free(workspace.parent().context("workspace parent")?)?
                >= policy.min_free_bytes.max(8 * GIB),
            "rehearsal capacity floor"
        );
        Ok(())
    };
    guard()?;
    let verifier = NativeRuntime {
        policy: &policy,
        cancel: &cancel,
        deadline,
        advisory: false,
        isolation: None,
    };
    verifier
        .volume()
        .context("rehearsal physical external disk preflight")?;
    verifier
        .verify_binary()
        .context("rehearsal native binary preflight")?;
    let registry = crate::protection::protection_registry_path()?;
    let external = policy
        .backup_root
        .join(format!("rehearsal-{}", io::unique_id()?));
    MigrationProtectionGuard::observe(
        &registry,
        &[workspace.to_owned(), external.clone()],
        SystemTime::now(),
    )?;
    // This is the sole creation site for the concurrent-Codex capability.
    io::exclusive_dir(workspace)?;
    io::exclusive_dir(&external)?;
    let root_meta = fs::metadata(workspace)?;
    let ext_meta = fs::metadata(&external)?;
    let scope = RehearsalScope {
        root: workspace.to_owned(),
        external,
        live: policy.codex_home.clone(),
        registry,
        root_id: (root_meta.dev(), root_meta.ino()),
        external_id: (ext_meta.dev(), ext_meta.ino()),
    };
    for name in ["user", "tmp", "state", "cache", "config"] {
        io::exclusive_dir(&workspace.join(name))?;
    }
    // Production lock/journal code operates entirely inside synthetic state.
    // scope.check independently observes current real protections read-only.
    let registry = workspace.join("state/protections.json");
    let mut reports = Vec::new();
    let operation = (|| {
        for compressed in [false, true] {
            guard()?;
            scope.check()?;
            let label = if compressed { "compressed" } else { "plain" };
            let home = workspace.join(label);
            io::exclusive_dir(&home)?;
            let archive = home.join("archived_sessions");
            io::exclusive_dir(&archive)?;
            let child = io::unique_id()?;
            let parent = io::unique_id()?;
            let child_plain = archive.join(format!("rollout-2026-01-01T00-00-00-{child}.jsonl"));
            create_file(
                &archive.join(format!("rollout-2026-01-01T00-00-00-{parent}.jsonl")),
                &fixture(&home, &parent, None)?,
            )
            .context("creating synthetic parent fixture")?;
            create_file(&child_plain, &fixture(&home, &child, Some(&parent))?)?;
            let child_path = if compressed {
                let path = child_plain.with_extension("jsonl.zst");
                io::success(
                    scope
                        .command(&policy.zstd_binary, &home)?
                        .args(["-q", "--rm"])
                        .arg(&child_plain)
                        .arg("-o")
                        .arg(&path),
                    &mut |_| guard(),
                )
                .context("compressing confined synthetic fixture")?;
                path
            } else {
                child_plain
            };
            // Native startup creates the real schema and indexes both fixtures.
            let initial = register_history(
                &policy.codex_binary,
                &home,
                &child,
                &scope.live,
                &mut || guard(),
            )
            .context("registering initial synthetic history")?;
            let restored = PathBuf::from(
                initial["restored"]
                    .as_str()
                    .context("fixture registered path")?,
            );
            ensure!(
                restored.starts_with(home.join("sessions")),
                "fixture registration path escape"
            );
            fs::rename(&restored, &child_path)?;
            // Only the freshly created synthetic store is aged for eligibility.
            age_fixture(&home, &child_path, &child)
                .context("preparing archived synthetic index")?;
            let journals = workspace.join(format!("{label}-journals"));
            io::exclusive_dir(&journals)?;
            let mut synthetic = policy.clone();
            synthetic.codex_home = home;
            synthetic.backup_root = scope.external.clone();
            synthetic.journal_root = journals;
            synthetic.enabled = true;
            synthetic.max_tasks = 1;
            synthetic.max_source_bytes = FIXTURE_LIMIT;
            synthetic.max_raw_bytes_per_task = FIXTURE_LIMIT;
            synthetic.exclude_threads.clear();
            synthetic.policy_sha256 =
                format!("{:x}", Sha256::digest(serde_json::to_vec(&synthetic)?));
            synthetic.validate()?;
            let runtime = NativeRuntime {
                policy: &synthetic,
                cancel: &cancel,
                deadline,
                advisory: false,
                isolation: Some(&scope),
            };
            let result = batch(&synthetic, true, &runtime, &registry)
                .context("rehearsing shared migration batch")?;
            ensure!(
                result["results"].as_array().is_some_and(|r| r.len() == 1)
                    && result["results"][0]["thread_id"] == child,
                "synthetic batch selection mismatch"
            );
            let journal_path = Path::new(
                result["results"][0]["journal"]
                    .as_str()
                    .context("rehearsal journal")?,
            );
            let journal: Value =
                serde_json::from_slice(&io::read_bound(journal_path, OUTPUT_LIMIT)?)?;
            let destination = workspace.join(format!("{label}-recovered"));
            let recovery = Recovery {
                native: NativeRecovery {
                    cancel: &cancel,
                    deadline,
                    parent: workspace,
                },
                scope: &scope,
            };
            let recovered = recover_with(&journal, &destination, &registry, &recovery)
                .context("rehearsing original-history recovery")?;
            ensure!(
                recovered["history_sha256"] == initial["history_sha256"],
                "rehearsal history differs from original"
            );
            reports.push(json!({"fixture":label,"migration":result,"recovery":recovered}));
        }
        Ok(
            json!({"version":1,"mode":"rehearsal","workspace":workspace,"external":scope.external,"reports":reports,"synthetic_only":true}),
        )
    })();
    let evidence = match &operation {
        Ok(report) => report.clone(),
        Err(error) => {
            json!({"version":1,"mode":"rehearsal","status":"failed","error":format!("{error:#}"),"completed":reports,"external":scope.external})
        }
    };
    write_journal(&workspace.join("rehearsal-result.json"), &evidence)?;
    operation
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn synthetic_metadata_matches_native_serialization_contract() {
        let id = "00000000-0000-4000-8000-000000000002";
        let parent = "00000000-0000-4000-8000-000000000001";
        for lineage in [None, Some(parent)] {
            let bytes = fixture(Path::new("/synthetic"), id, lineage).unwrap();
            let first = bytes.split(|byte| *byte == b'\n').next().unwrap();
            let record: Value = serde_json::from_slice(first).unwrap();
            let metadata = &record["payload"];
            assert_eq!(metadata["id"], id);
            assert_eq!(metadata["session_id"], id);
            assert_eq!(metadata["history_mode"], "legacy");
            if lineage.is_some() {
                assert_eq!(metadata["parent_thread_id"], parent);
                assert_eq!(
                    metadata["source"],
                    json!({"subagent":{"thread_spawn":{
                        "parent_thread_id":parent,"depth":1,
                        "agent_path":null,"agent_nickname":null,"agent_role":null
                    }}})
                );
            } else {
                assert_eq!(metadata["source"], "cli");
                assert!(metadata.get("parent_thread_id").is_none());
            }
        }
    }

    #[test]
    fn fixture_writer_leaves_an_index_readable_without_creating_shm() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().canonicalize().unwrap();
        let database = home.join("state_5.sqlite");
        let child = home.join("child.jsonl");
        fs::write(&child, b"synthetic").unwrap();
        let connection = Connection::open(&database).unwrap();
        connection.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE threads(id TEXT, rollout_path TEXT, source TEXT, history_mode TEXT, archived INTEGER, archived_at INTEGER, updated_at INTEGER, is_pinned INTEGER); CREATE TABLE thread_spawn_edges(parent_thread_id TEXT, child_thread_id TEXT); INSERT INTO threads VALUES('child','','cli','legacy',0,NULL,0,0);").unwrap();
        connection.close().unwrap();
        // Reproduce the retained native fixture's empty WAL / missing SHM.
        fs::write(home.join("state_5.sqlite-wal"), b"").unwrap();
        assert!(!home.join("state_5.sqlite-shm").exists());
        assert!(index_snapshot(&home).is_err());
        age_fixture(&home, &child, "child").unwrap();
        let (rows, _) = index_snapshot(&home).unwrap();
        assert_eq!(rows[0].archived, 1);
        assert_eq!(rows[0].archived_at, Some(1));
        assert!(!home.join("state_5.sqlite-shm").exists());
    }
    #[test]
    fn rehearsal_fixtures_are_bounded_and_have_continuation() {
        let bytes = fixture(
            Path::new("/synthetic"),
            "00000000-0000-4000-8000-000000000002",
            Some("00000000-0000-4000-8000-000000000001"),
        )
        .unwrap();
        assert!(bytes.len() < FIXTURE_LIMIT as usize);
        let mut parser = ContextParser::new("00000000-0000-4000-8000-000000000002", FIXTURE_LIMIT);
        parser.feed(&bytes).unwrap();
        parser.finish().unwrap();
    }
    #[test]
    fn rehearsal_rejects_existing_alias_and_live_overlap() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let live = root.join("live");
        fs::create_dir(&live).unwrap();
        validate_destination(&root.join("fresh"), std::slice::from_ref(&live)).unwrap();
        assert!(validate_destination(&live, std::slice::from_ref(&live)).is_err());
        assert!(validate_destination(&live.join("child"), std::slice::from_ref(&live)).is_err());
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&live, &alias).unwrap();
        assert!(validate_destination(&alias.join("fresh"), &[live]).is_err());
    }
    #[test]
    fn rehearsal_scope_rechecks_identity_and_pins_confinement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let store = root.join("store");
        let external = root.join("external");
        fs::create_dir(&store).unwrap();
        fs::create_dir(&external).unwrap();
        let a = fs::metadata(&store).unwrap();
        let b = fs::metadata(&external).unwrap();
        let scope = RehearsalScope {
            root: store.clone(),
            external,
            live: root.join("live"),
            registry: root.join("protections.json"),
            root_id: (a.dev(), a.ino()),
            external_id: (b.dev(), b.ino()),
        };
        let profile = scope.profile().unwrap();
        assert!(
            profile.contains("deny network*")
                && profile.contains("deny file-read*")
                && profile.contains("deny file-write*")
        );
        let command = scope
            .command(Path::new("/configured/zstd"), &store)
            .unwrap();
        assert_eq!(command.get_program(), "/usr/bin/sandbox-exec");
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        assert_eq!(args, ["-p", &profile, "/configured/zstd"]);
        assert_eq!(command.get_current_dir(), Some(store.join("tmp").as_path()));
        let environment: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .map(|(key, value)| (key.to_str().unwrap(), value.unwrap().to_owned()))
            .collect();
        assert_eq!(environment["CODEX_HOME"], store.as_os_str());
        assert_eq!(environment["HOME"], store.join("user").as_os_str());
        assert_eq!(environment["TMPDIR"], store.join("tmp").as_os_str());
        for name in ["XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"] {
            assert!(Path::new(&environment[name]).starts_with(store.join("tmp")));
        }
        assert!(scope.command(Path::new("/configured/zstd"), &root).is_err());
        let probe =
            zstd_probe_command(Path::new("/configured/zstd"), &store, Some(&scope)).unwrap();
        let args: Vec<_> = probe.get_args().map(|arg| arg.to_str().unwrap()).collect();
        let probe_profile = args[1];
        for denied in [&store, &scope.live] {
            assert!(probe_profile.contains(&format!(
                "(deny file-read* (subpath {}))",
                serde_json::to_string(denied).unwrap()
            )));
        }
        assert!(probe_profile.contains("(deny file-write*)"));
        assert!(probe_profile.contains("(deny network*)"));
        assert!(!probe_profile.contains("allow file-write"));
        assert_eq!(probe.get_program(), "/usr/bin/sandbox-exec");
        assert_eq!(probe.get_current_dir(), Some(Path::new("/")));
        fs::rename(&store, root.join("old")).unwrap();
        fs::create_dir(&store).unwrap();
        assert!(scope.check().is_err());
        assert!(zstd_probe_command(Path::new("/configured/zstd"), &store, Some(&scope)).is_err());
    }
}
