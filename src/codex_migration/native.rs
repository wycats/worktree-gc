use super::*;
use io::{Cancellation, OwnedProcess};
use std::process::Command;

pub(super) struct NativeRuntime<'a> {
    policy: &'a Policy,
    cancel: &'a Cancellation,
    deadline: Instant,
}
impl<'a> NativeRuntime<'a> {
    pub(super) fn new(policy: &'a Policy, cancel: &'a Cancellation) -> Self {
        Self {
            policy,
            cancel,
            deadline: Instant::now() + Duration::from_secs(policy.max_seconds),
        }
    }
    fn capture(&self, command: &mut Command) -> Result<Vec<u8>> {
        io::success(command, &mut |_| self.guard())
    }
    fn quiet_pids(&self, allowed: &[u32]) -> Result<()> {
        let bytes = self.capture(Command::new("/bin/ps").args(["-axo", "pid=,comm="]))?;
        validate_processes(std::str::from_utf8(&bytes)?, allowed)
    }
}

pub(super) fn validate_processes(text: &str, allowed: &[u32]) -> Result<()> {
    ensure!(!text.trim().is_empty(), "empty process evidence");
    for line in text.lines() {
        let line = line.trim();
        let split = line
            .find(char::is_whitespace)
            .context("malformed process evidence")?;
        let pid: u32 = line[..split].parse()?;
        let name = Path::new(line[split..].trim())
            .file_name()
            .and_then(|s| s.to_str())
            .context("process executable")?
            .to_lowercase();
        ensure!(
            allowed.contains(&pid)
                || !["codex", "chatgpt", "codex-app-server"].contains(&name.as_str()),
            "Codex store is active (PID {pid})"
        );
    }
    Ok(())
}

fn plist_capture(
    command: &mut Command,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<plist::Value> {
    let bytes = io::success(command, &mut |_| guard())?;
    plist::Value::from_reader(std::io::Cursor::new(bytes)).context("diskutil plist")
}
fn field<'a>(info: &'a plist::Value, key: &str) -> Result<&'a str> {
    info.as_dictionary()
        .and_then(|map| map.get(key))
        .and_then(plist::Value::as_string)
        .with_context(|| format!("missing disk topology field {key}"))
}
fn boolean(info: &plist::Value, key: &str) -> Option<bool> {
    info.as_dictionary()
        .and_then(|map| map.get(key))
        .and_then(plist::Value::as_boolean)
}
fn disk_info(path: &Path, guard: &mut dyn FnMut() -> Result<()>) -> Result<plist::Value> {
    plist_capture(
        Command::new("/usr/sbin/diskutil")
            .args(["info", "-plist"])
            .arg(path),
        guard,
    )
}
fn device(value: &str) -> Result<()> {
    ensure!(
        value.starts_with("disk")
            && value.len() < 40
            && value[4..].bytes().all(|b| b.is_ascii_digit() || b == b's'),
        "unknown disk identifier"
    );
    Ok(())
}

fn pin_native_store(command: &mut Command, home: &Path) -> Result<()> {
    io::path_syntax(home)?;
    // Codex core config resolves explicit sqlite_home before its environment or
    // CODEX_HOME default. Pin the observed/protected index even if the user's
    // home configuration or selected profile names another SQLite directory.
    command
        .arg("-c")
        .arg(format!("sqlite_home={}", serde_json::to_string(home)?));
    command.arg("-c").arg(format!(
        "log_dir={}",
        serde_json::to_string(&home.join("log"))?
    ));
    Ok(())
}

fn physical_inventory(value: &plist::Value) -> Result<BTreeSet<String>> {
    let dictionary = value
        .as_dictionary()
        .context("physical inventory dictionary")?;
    let whole = dictionary
        .get("WholeDisks")
        .and_then(plist::Value::as_array)
        .context("physical whole-disk inventory unavailable")?;
    let entries = dictionary
        .get("AllDisksAndPartitions")
        .and_then(plist::Value::as_array)
        .context("physical disk entries unavailable")?;
    ensure!(
        !whole.is_empty() && whole.len() <= 64 && entries.len() <= 64,
        "physical inventory bound"
    );
    let mut names = BTreeSet::new();
    for value in whole {
        let name = value.as_string().context("physical disk name")?;
        device(name)?;
        ensure!(
            names.insert(name.to_owned()),
            "duplicate physical whole disk"
        );
    }
    let mut confirmed = BTreeSet::new();
    for entry in entries {
        let name = field(entry, "DeviceIdentifier")?;
        device(name)?;
        ensure!(
            confirmed.insert(name.to_owned()),
            "duplicate physical disk entry"
        );
    }
    ensure!(
        names == confirmed,
        "physical inventory membership incomplete"
    );
    Ok(names)
}

fn physical_disk_evidence(
    info: &plist::Value,
    inventory: &BTreeSet<String>,
) -> Result<(String, bool)> {
    let name = field(info, "DeviceIdentifier")?;
    device(name)?;
    ensure!(
        boolean(info, "WholeDisk") == Some(true) && inventory.contains(name),
        "whole disk lacks physical inventory confirmation"
    );
    // AppleFabric internal storage can report VirtualOrPhysical=Unknown.
    // Explicit `diskutil list ... physical` membership establishes physicality;
    // Internal independently establishes attachment, and must be known.
    let internal = boolean(info, "Internal").context("unknown physical disk attachment")?;
    Ok((name.to_owned(), !internal))
}

fn physical_stores(
    info: &plist::Value,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let inventory = physical_inventory(&plist_capture(
        Command::new("/usr/sbin/diskutil").args(["list", "-plist", "physical"]),
        guard,
    )?)?;
    let mut stores = Vec::new();
    if let Ok(container) = field(info, "APFSContainerReference") {
        device(container)?;
        let all = plist_capture(
            Command::new("/usr/sbin/diskutil").args(["apfs", "list", "-plist", container]),
            guard,
        )?;
        let containers = all
            .as_dictionary()
            .and_then(|v| v.get("Containers"))
            .and_then(plist::Value::as_array)
            .context("unknown APFS containers")?;
        let matching: Vec<_> = containers
            .iter()
            .filter(|v| field(v, "ContainerReference").ok() == Some(container))
            .collect();
        ensure!(matching.len() == 1, "ambiguous APFS physical topology");
        let physical = matching[0]
            .as_dictionary()
            .and_then(|v| v.get("PhysicalStores"))
            .and_then(plist::Value::as_array)
            .context("APFS physical stores unavailable")?;
        ensure!(
            !physical.is_empty() && physical.len() <= 16,
            "APFS physical-store bound"
        );
        for store in physical {
            stores.push(field(store, "DeviceIdentifier")?.to_owned());
        }
    } else {
        stores.push(field(info, "DeviceIdentifier")?.to_owned());
    }
    let mut disks = BTreeSet::new();
    let mut external = BTreeSet::new();
    for store in stores {
        device(&store)?;
        let partition = disk_info(Path::new(&store), guard)?;
        let whole = if boolean(&partition, "WholeDisk") == Some(true) {
            field(&partition, "DeviceIdentifier")?
        } else {
            field(&partition, "ParentWholeDisk")?
        };
        device(whole)?;
        let info = disk_info(Path::new(whole), guard)?;
        let (disk, is_external) = physical_disk_evidence(&info, &inventory)?;
        ensure!(disk == whole, "physical disk identity drift");
        disks.insert(disk.clone());
        if is_external {
            external.insert(disk);
        }
    }
    Ok((disks, external))
}

pub(super) fn physical_disjoint(
    source: &BTreeSet<String>,
    backup: &BTreeSet<String>,
    external: &BTreeSet<String>,
) -> Result<()> {
    ensure!(
        !source.is_empty() && !backup.is_empty(),
        "unknown physical storage topology"
    );
    ensure!(
        source.is_disjoint(backup),
        "backup shares a physical source disk"
    );
    ensure!(
        backup.is_subset(external),
        "backup must reside on physically external disks"
    );
    Ok(())
}

fn volume(
    source: &Path,
    backup: &Path,
    uuid: &str,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    canonical(backup, backup.is_dir())?;
    let info = disk_info(backup, guard)?;
    ensure!(
        field(&info, "VolumeUUID")? == uuid,
        "backup volume identity changed"
    );
    let mount = Path::new(field(&info, "MountPoint")?);
    canonical(mount, true)?;
    ensure!(
        mount != Path::new("/") && backup.starts_with(mount),
        "backup mount missing"
    );
    ensure!(
        fs::metadata(source)?.dev() != fs::metadata(backup)?.dev(),
        "backup is source filesystem"
    );
    let (backup_disks, external) = physical_stores(&info, guard)?;
    let (source_disks, _) = physical_stores(&disk_info(source, guard)?, guard)?;
    physical_disjoint(&source_disks, &backup_disks, &external)
}

impl Runtime for NativeRuntime<'_> {
    fn guard(&self) -> Result<()> {
        self.cancel.check()?;
        ensure!(Instant::now() < self.deadline, "batch time limit");
        ensure!(
            io::free(&self.policy.codex_home)? >= self.policy.min_free_bytes,
            "Data free-space floor"
        );
        Ok(())
    }
    fn volume(&self) -> Result<()> {
        volume(
            &self.policy.codex_home,
            &self.policy.backup_root,
            &self.policy.backup_volume_uuid,
            &mut || self.guard(),
        )
    }
    fn quiet(&self, path: Option<&Path>) -> Result<()> {
        self.guard()?;
        self.quiet_pids(&[])?;
        if let Some(path) = path {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut process = OwnedProcess::spawn(
                Command::new("/usr/sbin/lsof")
                    .args(["-nP", "-t", "--"])
                    .arg(path),
                false,
            )?;
            let mut out = Vec::new();
            let result = (|| loop {
                self.guard()?;
                ensure!(Instant::now() < deadline, "exact-file ownership deadline");
                if let Some(status) = process.poll(&mut |block| {
                    ensure!(out.len() + block.len() <= OUTPUT_LIMIT, "lsof cap");
                    out.extend_from_slice(block);
                    Ok(())
                })? {
                    ensure!(
                        status.code() == Some(1) && out.is_empty() && process.stderr_empty(),
                        "rollout owner or incomplete exact-file evidence"
                    );
                    break Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            })();
            let teardown = process.stop();
            result?;
            teardown?;
        }
        Ok(())
    }
    fn verify_binary(&self) -> Result<()> {
        ensure!(
            io::hash(&self.policy.codex_binary, &mut || self.guard())? == self.policy.codex_sha256,
            "native Codex binary identity changed"
        );
        self.capture(
            Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(&self.policy.codex_binary),
        )?;
        let mut command = Command::new(&self.policy.codex_binary);
        command
            .arg("--version")
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        ensure!(
            String::from_utf8(self.capture(&mut command)?)?.trim() == NATIVE_VERSION,
            "native version requires new compatibility proof"
        );
        Ok(())
    }
    fn context(&self, path: &Path, tid: &str) -> Result<(Continuation, u64)> {
        let before = identity(path)?;
        let mut parser = ContextParser::new(tid, self.policy.max_raw_bytes_per_task);
        if path.extension().is_some_and(|s| s == "zst") {
            let status = io::stream(
                Command::new(&self.policy.zstd_binary)
                    .args(["-dc", "--"])
                    .arg(path),
                &mut |_| self.guard(),
                &mut |block| parser.feed(block),
            )?;
            ensure!(status.success(), "decompression failed");
        } else {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let mut block = [0; 65536];
            loop {
                self.guard()?;
                let count = file.read(&mut block)?;
                if count == 0 {
                    break;
                }
                parser.feed(&block[..count])?;
            }
        }
        ensure!(
            identity(path)? == before,
            "rollout changed during continuation proof"
        );
        parser.finish()
    }
    fn native(&self, tid: &str, apply: bool) -> Result<Value> {
        self.verify_binary()?;
        self.quiet(None)?;
        index_files(&self.policy.codex_home)?;
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .args(["-p", "(version 1)(allow default)(deny network*)"])
            .arg(&self.policy.codex_binary)
            .args([
                "migrate-rollouts",
                "--thread",
                tid,
                "--json",
                "--max-mib-per-second",
                "100",
                "-c",
                "analytics.enabled=false",
                "--disable",
                "local_thread_store_compression",
                "--disable",
                "background_paginated_rollout_migration",
            ]);
        pin_native_store(&mut command, &self.policy.codex_home)?;
        if apply {
            command.arg("--apply");
        }
        // The only writable live state is delegated to first-party migration.
        // No inherited credentials, feature toggles, or alternate Codex home.
        let user = std::env::var_os("HOME").context("HOME unavailable")?;
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", user)
            .env("CODEX_HOME", &self.policy.codex_home)
            .env("LANG", "en_US.UTF-8")
            .env("RUST_LOG", "error");
        let mut last_probe = Instant::now() - Duration::from_secs(1);
        let bytes = io::success(&mut command, &mut |pid| {
            self.guard()?;
            if last_probe.elapsed() >= Duration::from_millis(500) {
                self.quiet_pids(&[pid])?;
                last_probe = Instant::now();
            }
            Ok(())
        })?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let outcomes = value
            .get("outcomes")
            .and_then(Value::as_array)
            .context("native outcomes")?;
        ensure!(
            outcomes.len() == 1
                && outcomes[0].get("thread_id") == Some(&json!(tid))
                && outcomes[0].get("status")
                    == Some(&json!(if apply { "migrated" } else { "eligible" })),
            "native migration refused or changed scope"
        );
        Ok(value)
    }
}

fn rpc(
    process: &mut OwnedProcess,
    pending: &mut Vec<u8>,
    id: u64,
    method: &str,
    params: Value,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    process.write_json(&json!({"id":id,"method":method,"params":params}), guard)?;
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        guard()?;
        ensure!(Instant::now() < deadline, "native recovery RPC deadline");
        let status = process.poll(&mut |block| {
            ensure!(
                pending.len() + block.len() <= 256 * 1024 * 1024,
                "recovery history RPC cap"
            );
            pending.extend_from_slice(block);
            Ok(())
        })?;
        while let Some(end) = pending.iter().position(|b| *b == b'\n') {
            let line: Vec<_> = pending.drain(..=end).collect();
            let reply: Value = serde_json::from_slice(&line)?;
            if reply.get("id") == Some(&json!(id)) {
                ensure!(
                    reply.get("error").is_none(),
                    "native {method} returned error"
                );
                return reply
                    .get("result")
                    .cloned()
                    .context("native result missing");
            }
        }
        ensure!(status.is_none(), "native app-server exited before {method}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn register_history(
    binary: &Path,
    home: &Path,
    tid: &str,
    live: &Path,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<Value> {
    let support = home.join(".recovery-runtime");
    io::exclusive_dir(&support)?;
    for name in ["user", "tmp", "cache", "state", "config"] {
        io::exclusive_dir(&support.join(name))?;
    }
    let profile = format!("(version 1)(allow default)(deny network*)(deny file-write* (require-not (subpath {})))(allow file-write* (literal \"/dev/null\"))(deny file-read* (subpath {}))",serde_json::to_string(home)?,serde_json::to_string(live)?);
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command.args(["-p", &profile]).arg(binary).args([
        "app-server",
        "--stdio",
        "-c",
        "analytics.enabled=false",
        "--disable",
        "local_thread_store_compression",
        "--disable",
        "background_paginated_rollout_migration",
    ]);
    pin_native_store(&mut command, home)?;
    io::command_env(
        &mut command,
        home,
        &support.join("user"),
        &support.join("tmp"),
    );
    let mut process = OwnedProcess::spawn(&mut command, true)?;
    let mut pending = Vec::new();
    let operation = (|| {
        rpc(
            &mut process,
            &mut pending,
            1,
            "initialize",
            json!({"clientInfo":{"name":"worktree-gc-recovery","version":"1"},"capabilities":{"experimentalApi":true}}),
            guard,
        )?;
        process.write_json(&json!({"method":"initialized"}), guard)?;
        let backfill_deadline = Instant::now() + Duration::from_secs(30);
        loop {
            guard()?;
            ensure!(
                Instant::now() < backfill_deadline,
                "native archive registration deadline"
            );
            match fs::symlink_metadata(home.join("state_5.sqlite")) {
                Ok(_) => {
                    let (rows, _) = index_snapshot(home)?;
                    if let Some(row) = rows.iter().find(|r| r.id == tid) {
                        ensure!(
                            row.archived == 1
                                && Path::new(&row.rollout_path)
                                    .starts_with(home.join("archived_sessions")),
                            "unexpected native recovered index row"
                        );
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let before = rpc(
            &mut process,
            &mut pending,
            2,
            "thread/read",
            json!({"threadId":tid,"includeTurns":true}),
            guard,
        )?;
        let turns = before
            .pointer("/thread/turns")
            .and_then(Value::as_array)
            .context("recovered native turns missing")?;
        ensure!(
            !turns.is_empty()
                && turns.iter().any(|turn| turn
                    .get("items")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty())),
            "recovery returned empty history"
        );
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(turns)?));
        rpc(
            &mut process,
            &mut pending,
            3,
            "thread/unarchive",
            json!({"threadId":tid}),
            guard,
        )?;
        let after = rpc(
            &mut process,
            &mut pending,
            4,
            "thread/read",
            json!({"threadId":tid,"includeTurns":true}),
            guard,
        )?;
        ensure!(
            after.pointer("/thread/turns").and_then(Value::as_array) == Some(turns),
            "recovered history changed after unarchive"
        );
        let (rows, _) = index_snapshot(home)?;
        let row = rows
            .iter()
            .find(|r| r.id == tid)
            .context("native recovered index row absent")?;
        ensure!(row.archived == 0, "native unarchive did not persist");
        let restored = Path::new(&row.rollout_path);
        canonical(restored, false)?;
        ensure!(
            restored.starts_with(home.join("sessions")),
            "native recovery path escaped isolated home"
        );
        Ok(
            json!({"restored":restored,"history_turns":turns.len(),"history_sha256":digest,"native_registered":true}),
        )
    })();
    let teardown = process.stop();
    let result = operation?;
    teardown?;
    Ok(result)
}

pub(super) trait RecoveryRuntime {
    fn guard(&self) -> Result<()>;
    fn volume(&self, source: &Path, backup: &Path, uuid: &str) -> Result<()>;
    fn verify_binary(&self, binary: &Path, sha: &str) -> Result<()>;
    fn register(&self, binary: &Path, home: &Path, tid: &str, live: &Path) -> Result<Value>;
    fn free(&self, path: &Path) -> Result<u64> {
        io::free(path)
    }
}
struct NativeRecovery<'a> {
    cancel: &'a Cancellation,
    deadline: Instant,
    parent: &'a Path,
}
impl RecoveryRuntime for NativeRecovery<'_> {
    fn guard(&self) -> Result<()> {
        self.cancel.check()?;
        ensure!(Instant::now() < self.deadline, "recovery deadline");
        ensure!(io::free(self.parent)? >= GIB, "recovery free-space floor");
        Ok(())
    }
    fn volume(&self, source: &Path, backup: &Path, uuid: &str) -> Result<()> {
        volume(source, backup, uuid, &mut || self.guard())
    }
    fn verify_binary(&self, binary: &Path, sha: &str) -> Result<()> {
        ensure!(
            io::hash(binary, &mut || self.guard())? == sha,
            "native binary identity changed"
        );
        io::success(
            Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(binary),
            &mut |_| self.guard(),
        )?;
        ensure!(
            String::from_utf8(io::success(
                Command::new(binary).arg("--version"),
                &mut |_| self.guard()
            )?)?
            .trim()
                == NATIVE_VERSION,
            "native recovery needs new compatibility proof"
        );
        Ok(())
    }
    fn register(&self, binary: &Path, home: &Path, tid: &str, live: &Path) -> Result<Value> {
        register_history(binary, home, tid, live, &mut || self.guard())
    }
}

pub(super) fn recover_with(
    journal: &Value,
    destination: &Path,
    registry: &Path,
    runtime: &dyn RecoveryRuntime,
) -> Result<Value> {
    ensure!(
        journal.get("version") == Some(&json!(1)),
        "unsupported journal version"
    );
    let text = |key: &str| {
        journal
            .get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("journal missing {key}"))
    };
    let backup = PathBuf::from(text("backup")?);
    let live = PathBuf::from(text("codex_home")?);
    let expected = text("backup_sha256")?;
    ensure!(sha(expected), "invalid backup digest");
    let tid = journal
        .pointer("/candidate/row/id")
        .and_then(Value::as_str)
        .context("journal task ID")?;
    ensure!(uuid(tid), "invalid journal task ID");
    let binary = PathBuf::from(
        journal
            .get("codex_binary")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_CODEX),
    );
    let binary_sha = text("codex_sha256")?;
    ensure!(sha(binary_sha), "invalid native digest");
    let volume_uuid = text("backup_volume_uuid")?;
    let parent = destination.parent().context("recovery parent")?;
    canonical(parent, true)?;
    io::absent(destination)?;
    ensure!(
        !io::intersects(destination, &live) && !io::intersects(destination, &backup),
        "recovery must be outside originals/live"
    );
    let mut guard = || runtime.guard();
    let stage = parent.join(format!(".worktree-gc-recovery-{}", io::unique_id()?));
    let protections = MigrationProtectionGuard::acquire(registry)?;
    protections.check(&[destination.to_owned(), stage.clone()], SystemTime::now())?;
    runtime.volume(parent, &backup, volume_uuid)?;
    let original_identity = identity(&backup)?;
    ensure!(
        io::hash(&backup, &mut guard)? == expected,
        "backup identity mismatch"
    );
    ensure!(
        runtime.free(parent)? >= original_identity.bytes + GIB,
        "recovery capacity"
    );
    runtime.verify_binary(&binary, binary_sha)?;
    // Stage beside the requested home. Failure preserves diagnostic evidence
    // here, with the requested destination still absent and therefore retryable.
    io::exclusive_dir(&stage)?;
    let stage_identity = fs::metadata(&stage)?;
    let mut published = false;
    let operation = (|| {
        let archive = stage.join("archived_sessions");
        io::exclusive_dir(&archive)?;
        let restored = archive.join(backup.file_name().context("backup filename")?);
        ensure!(
            io::copy_verified(&backup, &restored, &mut guard)? == expected,
            "restoration mismatch"
        );
        protections.check(&[destination.to_owned(), stage.clone()], SystemTime::now())?;
        // Native SQLite uses absolute rollout paths. Move the unindexed bytes
        // to their final spelling before first-party registration, and move the
        // whole run-owned home back to staging if registration fails.
        io::absent(destination)?;
        fs::rename(&stage, destination)?;
        io::sync_dir(parent)?;
        published = true;
        protections.check(&[destination.to_owned(), stage.clone()], SystemTime::now())?;
        let mut result = runtime.register(&binary, destination, tid, &live)?;
        let native_path = PathBuf::from(result["restored"].as_str().context("restored path")?);
        ensure!(
            io::hash(&native_path, &mut guard)? == expected,
            "native recovery altered original bytes"
        );
        ensure!(
            identity(&backup)? == original_identity && io::hash(&backup, &mut guard)? == expected,
            "original changed during recovery"
        );
        runtime.volume(parent, &backup, volume_uuid)?;
        ensure!(
            result.get("native_registered") == Some(&json!(true))
                && result
                    .get("history_turns")
                    .and_then(Value::as_u64)
                    .is_some_and(|v| v > 0),
            "native recovery registration unverified"
        );
        canonical(&native_path, false)?;
        ensure!(
            native_path.starts_with(destination.join("sessions")),
            "restored path outside recovery home"
        );
        result["isolated_codex_home"] = json!(destination);
        result["sha256"] = json!(expected);
        result["live_store_unchanged"] = json!(true);
        Ok(result)
    })();
    if operation.is_err() && published {
        canonical(destination, true)?;
        let current = fs::metadata(destination)?;
        ensure!(
            current.dev() == stage_identity.dev() && current.ino() == stage_identity.ino(),
            "recovery destination changed; retained for diagnosis"
        );
        io::absent(&stage)?;
        fs::rename(destination, &stage)?;
        io::sync_dir(parent)?;
    }
    operation.with_context(|| {
        format!(
            "recovery evidence retained at {}; requested destination remains retryable on failure",
            stage.display()
        )
    })
}

pub(super) fn recover(journal_path: &Path, destination: &Path) -> Result<Value> {
    ensure!(
        cfg!(target_os = "macos"),
        "native recovery currently supports macOS"
    );
    ensure!(
        !io::intersects(destination, journal_path),
        "recovery overlaps journal"
    );
    let journal: Value = serde_json::from_slice(&io::read_bound(journal_path, OUTPUT_LIMIT)?)?;
    let cancellation = Cancellation::install()?;
    let runtime = NativeRecovery {
        cancel: &cancellation,
        deadline: Instant::now() + Duration::from_secs(1800),
        parent: destination.parent().context("recovery parent")?,
    };
    recover_with(
        &journal,
        destination,
        &crate::protection::protection_registry_path()?,
        &runtime,
    )
}

#[cfg(test)]
mod topology_tests {
    use super::*;
    fn value(xml: &str) -> plist::Value {
        plist::Value::from_reader_xml(xml.as_bytes()).unwrap()
    }
    fn inventory() -> BTreeSet<String> {
        physical_inventory(&value(r#"<plist version="1.0"><dict><key>WholeDisks</key><array><string>disk0</string><string>disk4</string></array><key>AllDisksAndPartitions</key><array><dict><key>DeviceIdentifier</key><string>disk0</string></dict><dict><key>DeviceIdentifier</key><string>disk4</string></dict></array></dict></plist>"#)).unwrap()
    }
    #[test]
    fn apple_fabric_unknown_is_physical_only_with_inventory_membership() {
        let info = value(
            r#"<plist version="1.0"><dict><key>DeviceIdentifier</key><string>disk0</string><key>WholeDisk</key><true/><key>VirtualOrPhysical</key><string>Unknown</string><key>Internal</key><true/><key>BusProtocol</key><string>AppleFabric</string></dict></plist>"#,
        );
        assert_eq!(
            physical_disk_evidence(&info, &inventory()).unwrap(),
            ("disk0".into(), false)
        );
        assert!(physical_disk_evidence(&info, &BTreeSet::from(["disk4".into()])).is_err());
    }
    #[test]
    fn apfs_volumes_sharing_confirmed_disk_cannot_be_external_backup() {
        let source = BTreeSet::from(["disk0".into()]);
        let same_backing = BTreeSet::from(["disk0".into()]);
        assert!(physical_disjoint(&source, &same_backing, &BTreeSet::new()).is_err());
        let external = value(
            r#"<plist version="1.0"><dict><key>DeviceIdentifier</key><string>disk4</string><key>WholeDisk</key><true/><key>Internal</key><false/></dict></plist>"#,
        );
        let (name, is_external) = physical_disk_evidence(&external, &inventory()).unwrap();
        assert!(is_external);
        let backup = BTreeSet::from([name]);
        physical_disjoint(&source, &backup, &backup).unwrap();
    }
    #[test]
    fn physical_inventory_missing_disk_or_attachment_refuses() {
        let incomplete = value(
            r#"<plist version="1.0"><dict><key>WholeDisks</key><array><string>disk0</string><string>disk4</string></array><key>AllDisksAndPartitions</key><array><dict><key>DeviceIdentifier</key><string>disk0</string></dict></array></dict></plist>"#,
        );
        assert!(physical_inventory(&incomplete).is_err());
        let unknown = value(
            r#"<plist version="1.0"><dict><key>DeviceIdentifier</key><string>disk4</string><key>WholeDisk</key><true/></dict></plist>"#,
        );
        assert!(physical_disk_evidence(&unknown, &inventory()).is_err());
    }
    #[test]
    fn native_store_overrides_pin_sqlite_and_logs_with_quoted_paths() {
        let home = Path::new("/safe/home with \"quotes\"");
        let mut command = Command::new("native-fixture");
        pin_native_store(&mut command, home).unwrap();
        let arguments: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(arguments.len(), 4);
        assert_eq!(arguments[0], "-c");
        assert_eq!(arguments[2], "-c");
        let sqlite: toml::Value = toml::from_str(arguments[1]).unwrap();
        let logs: toml::Value = toml::from_str(arguments[3]).unwrap();
        assert_eq!(sqlite["sqlite_home"].as_str(), home.to_str());
        assert_eq!(logs["log_dir"].as_str(), home.join("log").to_str());
    }
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires explicit isolated pinned Codex native qualification lane"]
    fn production_registration_preserves_plain_and_compressed_history() -> Result<()> {
        let temporary = tempfile::Builder::new()
            .prefix("gc-production-recovery-")
            .tempdir()?;
        let root = temporary.path().canonicalize()?;
        let deadline = Instant::now() + Duration::from_secs(300);
        let mut guard = || {
            ensure!(
                Instant::now() < deadline,
                "production registration qualification deadline"
            );
            ensure!(io::free(&root)? >= 8 * GIB, "qualification capacity floor");
            Ok(())
        };
        let binary = Path::new(DEFAULT_CODEX);
        ensure!(
            io::hash(binary, &mut guard)?
                == "4ca47945439f9251fe35f4cbe071369192cd9a6c5a3a17b75c7a11ad548a9c7f",
            "qualification binary changed"
        );
        io::success(
            Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(binary),
            &mut |_| guard(),
        )?;
        let tid = "019fe295-7969-7502-bf8f-0b1eb4b0127b";
        let timestamp = "2026-08-08T11:14:34Z";
        for compressed in [false, true] {
            let label = if compressed { "compressed" } else { "plain" };
            let home = root.join(label);
            io::exclusive_dir(&home)?;
            let archive = home.join("archived_sessions");
            io::exclusive_dir(&archive)?;
            let records = [
                json!({"timestamp":timestamp,"type":"session_meta","payload":{"id":tid,"timestamp":timestamp,"cwd":home,"originator":"codex","cli_version":"0.153.4","model_provider":"openai","base_instructions":null,"history_mode":"legacy","parent_thread_id":"019fdec0-2f64-7e41-8b05-b91253ce2f06","source":{"subagent":{"thread_spawn":{"parent_thread_id":"019fdec0-2f64-7e41-8b05-b91253ce2f06","depth":1}}}}}),
                json!({"timestamp":timestamp,"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"PRODUCTION_RECOVERY_SENTINEL"}]}}),
                json!({"timestamp":timestamp,"type":"event_msg","payload":{"type":"user_message","message":"PRODUCTION_RECOVERY_SENTINEL","text_elements":[],"local_images":[]}}),
            ];
            let original = root.join(format!("{label}.original.jsonl"));
            fs::write(
                &original,
                records
                    .iter()
                    .map(|record| format!("{record}\n"))
                    .collect::<String>(),
            )?;
            let original_hash = io::hash(&original, &mut guard)?;
            let source = archive.join(format!(
                "rollout-2026-08-08T11-14-34-{tid}.jsonl{}",
                if compressed { ".zst" } else { "" }
            ));
            if compressed {
                io::success(
                    Command::new("/opt/homebrew/bin/zstd")
                        .arg("-q")
                        .arg(&original)
                        .arg("-o")
                        .arg(&source),
                    &mut |_| guard(),
                )?;
            } else {
                io::copy_verified(&original, &source, &mut guard)?;
            }
            let stored_hash = io::hash(&source, &mut guard)?;
            io::absent(&home.join("state_5.sqlite"))?;
            let report = register_history(
                binary,
                &home,
                tid,
                Path::new("/Users/wycats/.codex"),
                &mut guard,
            )?;
            let restored = Path::new(report["restored"].as_str().context("restored path")?);
            ensure!(
                io::hash(restored, &mut guard)? == stored_hash
                    && io::hash(&original, &mut guard)? == original_hash,
                "production qualification changed original bytes"
            );
            let (rows, _) = index_snapshot(&home)?;
            ensure!(
                rows.iter().any(|row| row.id == tid
                    && row.archived == 0
                    && Path::new(&row.rollout_path) == restored),
                "production registration row mismatch"
            );
            eprintln!("production registration qualified {label}: {report}");
        }
        Ok(())
    }
}
