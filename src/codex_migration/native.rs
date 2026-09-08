use super::*;
use io::{Cancellation, OwnedProcess};
use std::process::Command;
mod rehearsal;
pub use rehearsal::rehearse;

/// Qualify the production continuation reader on a verified external original.
/// No index access, native Codex invocation, backup/journal creation or live apply.
pub(super) fn benchmark(config: &Path, journal_path: &Path) -> Result<Value> {
    ensure!(cfg!(target_os = "macos"), "benchmark requires macOS");
    let policy = Policy::load(config)?;
    let journal_bytes = io::read_bound(journal_path, OUTPUT_LIMIT)?;
    let journal: Value = serde_json::from_slice(&journal_bytes)?;
    let (backup, expected, tid) = benchmark_input(&policy, &journal)?;
    let cancellation = Cancellation::install()?;
    let mut runtime = NativeRuntime::for_preflight(&policy, &cancellation);
    runtime.deadline = Instant::now() + Duration::from_secs(600);
    runtime.enable_progress(true);
    runtime.task(1, 1, &tid);
    runtime.volume()?;
    runtime.verify_zstd()?;
    runtime.stage("verifying external backup hash");
    let digest = io::hash(&backup, &mut || runtime.guard())?;
    ensure!(
        journal["backup_sha256"].as_str() == Some(&digest),
        "backup hash mismatch"
    );
    ensure!(identity(&backup)? == expected, "backup identity drift");
    // Deny writes/network and live-home reads for the decompressor. The host
    // parser reads only the exact backup, never a live rollout or task index.
    runtime.stage("benchmarking original continuation");
    let started = Instant::now();
    let mut parser = ContextParser::new(&tid, policy.max_raw_bytes_per_task);
    let mut command = zstd_probe_command(&policy.zstd_binary, &policy.codex_home, None)?;
    command.args(["--"]).arg(&backup);
    io::stream_success(&mut command, &mut |_| runtime.guard(), &mut |block| {
        parser.feed(block)?;
        runtime.progress.bytes(block.len() as u64);
        Ok(())
    })?;
    let (context, raw) = parser.finish()?;
    let seconds = started.elapsed().as_secs_f64();
    ensure!(
        serde_json::to_value(&context)? == journal["before_context"],
        "backup continuation mismatch"
    );
    ensure!(
        identity(&backup)? == expected,
        "backup changed during benchmark"
    );
    runtime.volume()?;
    runtime.stage("benchmark verified");
    Ok(
        json!({"version":1,"mode":"benchmark","observed_at":now(),"thread_id":tid,"backup_identity":expected,"backup_sha256":digest,"raw_bytes":raw,"reader_seconds":seconds,"reader_mib_per_second":raw as f64 / 1048576.0 / seconds.max(0.001),"continuation_verified":true,"live_store_accessed":false}),
    )
}

pub(super) fn benchmark_input(
    policy: &Policy,
    journal: &Value,
) -> Result<(PathBuf, Identity, String)> {
    ensure!(
        journal["version"] == 1 && journal["phase"] == "verified",
        "benchmark requires verified journal"
    );
    ensure!(
        journal["backup_volume_uuid"].as_str() == Some(&policy.backup_volume_uuid),
        "benchmark volume mismatch"
    );
    let backup = PathBuf::from(journal["backup"].as_str().context("backup path")?);
    canonical(&backup, false)?;
    ensure!(
        backup.starts_with(&policy.backup_root) && !io::intersects(&backup, &policy.codex_home),
        "benchmark input must be an external original"
    );
    let expected: Identity = serde_json::from_value(journal["backup_identity"].clone())?;
    ensure!(identity(&backup)? == expected, "backup identity mismatch");
    ensure!(
        expected.bytes <= policy.max_source_bytes,
        "benchmark source bound"
    );
    let tid = journal["candidate"]["row"]["id"]
        .as_str()
        .context("thread ID")?
        .to_owned();
    ensure!(uuid(&tid), "invalid benchmark thread ID");
    ensure!(
        backup.extension().is_some_and(|e| e == "zst"),
        "benchmark requires compressed original"
    );
    Ok((backup, expected, tid))
}

struct RehearsalScope {
    root: PathBuf,
    external: PathBuf,
    live: PathBuf,
    registry: PathBuf,
    root_id: (u64, u64),
    external_id: (u64, u64),
}
impl RehearsalScope {
    fn check(&self) -> Result<()> {
        for (path, expected) in [
            (&self.root, self.root_id),
            (&self.external, self.external_id),
        ] {
            canonical(path, true)?;
            let metadata = fs::metadata(path)?;
            ensure!(
                (metadata.dev(), metadata.ino()) == expected,
                "rehearsal directory identity changed"
            );
        }
        MigrationProtectionGuard::observe(
            &self.registry,
            &[self.root.clone(), self.external.clone()],
            SystemTime::now(),
        )?;
        Ok(())
    }
    fn profile(&self) -> Result<String> {
        self.check()?;
        Ok(format!("(version 1)(allow default)(deny network*)(deny file-write* (require-not (require-any (subpath {}) (subpath {}))))(allow file-write* (literal \"/dev/null\"))(deny file-read* (subpath {}))", serde_json::to_string(&self.root)?, serde_json::to_string(&self.external)?, serde_json::to_string(&self.live)?))
    }
    fn command(&self, program: &Path, home: &Path) -> Result<Command> {
        ensure!(
            home.starts_with(&self.root),
            "rehearsal command home escape"
        );
        canonical(home, true)?;
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.args(["-p", &self.profile()?]).arg(program);
        io::command_env(
            &mut command,
            home,
            &self.root.join("user"),
            &self.root.join("tmp"),
        );
        Ok(command)
    }
}

pub(super) struct NativeRuntime<'a> {
    policy: &'a Policy,
    cancel: &'a Cancellation,
    deadline: Instant,
    advisory: bool,
    isolation: Option<&'a RehearsalScope>,
    progress: progress::Progress,
}
impl<'a> NativeRuntime<'a> {
    pub(super) fn new(policy: &'a Policy, cancel: &'a Cancellation) -> Self {
        Self {
            policy,
            cancel,
            deadline: Instant::now() + Duration::from_secs(policy.max_seconds),
            advisory: false,
            isolation: None,
            progress: progress::Progress::new(false),
        }
    }
    pub(super) fn for_preflight(policy: &'a Policy, cancel: &'a Cancellation) -> Self {
        Self {
            policy,
            cancel,
            deadline: Instant::now() + Duration::from_secs(120),
            advisory: true,
            isolation: None,
            progress: progress::Progress::new(false),
        }
    }
    pub(super) fn enable_progress(&mut self, enabled: bool) {
        self.progress = progress::Progress::new(enabled);
    }
    pub(super) fn active_codex_pids(&self) -> Result<Vec<u32>> {
        let bytes = self.capture(Command::new("/bin/ps").args(["-axo", "pid=,comm="]))?;
        active_codex_pids(std::str::from_utf8(&bytes)?)
    }
    pub(super) fn sandbox_probe(&self) -> Result<()> {
        self.capture(Command::new("/usr/bin/sandbox-exec").args([
            "-p",
            "(version 1)(allow default)(deny network*)(deny file-write*)",
            "/usr/bin/true",
        ]))
        .context("checking sandbox execution capability")?;
        Ok(())
    }
    pub(super) fn verify_zstd(&self) -> Result<Value> {
        let before = identity(&self.policy.zstd_binary)?;
        let mut command = zstd_probe_command(
            &self.policy.zstd_binary,
            &self.policy.codex_home,
            self.isolation,
        )?;
        zstd_decompression_probe(&mut command, &mut || self.guard())
            .context("verifying configured zstd decompression")?;
        ensure!(
            before == identity(&self.policy.zstd_binary)?,
            "zstd executable identity changed during preflight"
        );
        Ok(
            json!({"path":self.policy.zstd_binary,"identity":before,"synthetic_decompression_verified":true}),
        )
    }
    fn capture(&self, command: &mut Command) -> Result<Vec<u8>> {
        io::success(command, &mut |_| self.guard())
    }
    fn quiet_pids(&self, allowed: &[u32]) -> Result<()> {
        if let Some(scope) = self.isolation {
            scope.check()?;
            for root in [&scope.root, &scope.external] {
                let deadline = Instant::now() + Duration::from_secs(10);
                let (status, bytes, stderr) =
                    io::capture_with_stderr(&mut rehearsal_owner_command(root), &mut |_| {
                        self.guard()?;
                        ensure!(Instant::now() < deadline, "rehearsal ownership deadline");
                        Ok(())
                    })?;
                validate_rehearsal_owners(
                    status.code(),
                    &bytes,
                    &stderr,
                    std::process::id(),
                    allowed,
                )?;
            }
            return Ok(());
        }
        let bytes = self.capture(Command::new("/bin/ps").args(["-axo", "pid=,comm="]))?;
        validate_processes(std::str::from_utf8(&bytes)?, allowed)
    }
}

fn zstd_probe_command(
    binary: &Path,
    home: &Path,
    isolation: Option<&RehearsalScope>,
) -> Result<Command> {
    let mut profile = format!(
        "(version 1)(allow default)(deny network*)(deny file-write*)(deny file-read* (subpath {}))",
        serde_json::to_string(home)?
    );
    if let Some(scope) = isolation {
        scope.check()?;
        profile.push_str(&format!(
            "(deny file-read* (subpath {}))",
            serde_json::to_string(&scope.live)?
        ));
    }
    let mut command = Command::new("/usr/bin/sandbox-exec");
    command
        .args(["-p", &profile])
        .arg(binary)
        .args(["-dc"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .current_dir("/");
    Ok(command)
}

fn zstd_decompression_probe(
    command: &mut Command,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    // One standard Zstandard frame with a single last, uncompressed block.
    // Input is synthetic and stays in pipes; preflight never reads rollouts.
    const EXPECTED: &[u8] = b"worktree-gc-preflight\n";
    let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, EXPECTED.len() as u8];
    frame.extend_from_slice(&((EXPECTED.len() as u32) << 3 | 1).to_le_bytes()[..3]);
    frame.extend_from_slice(EXPECTED);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut check = || {
        guard()?;
        ensure!(Instant::now() < deadline, "zstd preflight deadline");
        Ok(())
    };
    check()?;
    let mut process = OwnedProcess::spawn(command, true)?;
    let operation = (|| {
        process.write_input(&frame, &mut check)?;
        process.close_input();
        let mut output = Vec::new();
        loop {
            check()?;
            if let Some(status) = process.poll(&mut |block| {
                ensure!(
                    output.len() + block.len() <= EXPECTED.len(),
                    "zstd probe output cap"
                );
                output.extend_from_slice(block);
                Ok(())
            })? {
                ensure!(status.success(), "zstd probe exited {status}");
                ensure!(output == EXPECTED, "zstd probe decoded unexpected bytes");
                break Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    process.finish(operation)
}

fn rehearsal_owner_command(root: &Path) -> Command {
    let mut command = Command::new("/usr/sbin/lsof");
    // -t suppresses warnings. Field output plus +w preserves warnings so
    // traversal/access errors remain refusals alongside partial matches.
    command.args(["-nP", "+w", "-F", "pf", "+D"]).arg(root);
    command
}

fn validate_rehearsal_owners(
    status: Option<i32>,
    bytes: &[u8],
    stderr: &[u8],
    current: u32,
    allowed: &[u32],
) -> Result<()> {
    // macOS lsof +D expands all files into search arguments. Its documented
    // status 1 includes closed/unmatched files, even when other matches exist.
    // This interpretation is limited to freshly created rehearsal stores.
    ensure!(
        matches!(status, Some(0 | 1)) && stderr.is_empty(),
        "rehearsal ownership subprocess lsof exit {status:?}; stderr: {}",
        io::stderr_diagnostic(stderr)
    );
    let text = std::str::from_utf8(bytes).context("invalid rehearsal ownership PID encoding")?;
    ensure!(
        text.is_empty() || text.ends_with('\n'),
        "unterminated rehearsal ownership record"
    );
    ensure!(
        status != Some(0) || !text.is_empty(),
        "empty successful rehearsal ownership evidence"
    );
    let mut awaiting_file = false;
    let mut saw_pid = false;
    for (index, line) in text.lines().enumerate() {
        ensure!(index < 65536, "rehearsal ownership record bound");
        if let Some(value) = line.strip_prefix('p') {
            ensure!(!awaiting_file, "incomplete rehearsal process record");
            ensure!(
                !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
                "invalid rehearsal ownership PID"
            );
            let pid: u32 = value.parse().context("invalid rehearsal ownership PID")?;
            ensure!(pid > 0, "invalid zero rehearsal ownership PID");
            ensure!(
                pid == current || allowed.contains(&pid),
                "foreign process {pid} owns rehearsal data"
            );
            saw_pid = true;
            awaiting_file = true;
        } else if let Some(value) = line.strip_prefix('f') {
            ensure!(
                saw_pid
                    && ((!value.is_empty()
                        && value.bytes().all(|byte| byte.is_ascii_digit())
                        && value.parse::<u32>().is_ok())
                        || ["cwd", "rtd", "txt", "mem"].contains(&value)),
                "invalid rehearsal file record"
            );
            awaiting_file = false;
        } else {
            bail!("unknown rehearsal ownership record");
        }
    }
    ensure!(!awaiting_file, "incomplete rehearsal process record");
    Ok(())
}

pub(super) fn validate_processes(text: &str, allowed: &[u32]) -> Result<()> {
    for pid in active_codex_pids(text)? {
        ensure!(allowed.contains(&pid), "Codex store is active (PID {pid})");
    }
    Ok(())
}

fn active_codex_pids(text: &str) -> Result<Vec<u32>> {
    ensure!(!text.trim().is_empty(), "empty process evidence");
    let mut pids = Vec::new();
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
        if ["codex", "chatgpt", "codex-app-server"].contains(&name.as_str()) {
            pids.push(pid);
        }
    }
    Ok(pids)
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
    guard()?;
    let argument = if path.is_absolute() {
        filesystem_mount(path)?
    } else {
        device(path.to_str().context("disk identifier encoding")?)?;
        path.to_owned()
    };
    plist_capture(
        Command::new("/usr/sbin/diskutil")
            .args(["info", "-plist"])
            .arg(argument),
        guard,
    )
    .context("reading disk metadata")
}

/// diskutil accepts a device or mount point, not an arbitrary directory/file.
/// Resolve through an open descriptor so nested backup files and APFS firmlinks
/// use the kernel's filesystem identity, rather than lexical ancestor guesses.
#[cfg(target_os = "macos")]
fn filesystem_mount(path: &Path) -> Result<PathBuf> {
    use std::os::fd::AsRawFd;
    io::canonical_prefixes(path)?;
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file() || before.is_dir(),
        "unsupported filesystem probe path"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        (before.dev(), before.ino()) == (opened.dev(), opened.ino()),
        "filesystem probe identity changed"
    );
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: fd is live and the output points to a correctly sized statfs.
    let result = unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("resolving filesystem mount");
    }
    // SAFETY: successful fstatfs initialized the structure.
    let info = unsafe { info.assume_init() };
    let bytes: Vec<u8> = info.f_mntonname.iter().map(|c| *c as u8).collect();
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .context("unterminated mount point")?;
    let mount = PathBuf::from(std::str::from_utf8(&bytes[..end])?);
    canonical(&mount, true)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        (after.dev(), after.ino()) == (opened.dev(), opened.ino())
            && fs::metadata(&mount)?.dev() == opened.dev(),
        "filesystem mount identity changed"
    );
    Ok(mount)
}

#[cfg(not(target_os = "macos"))]
fn filesystem_mount(_path: &Path) -> Result<PathBuf> {
    bail!("filesystem topology inspection requires macOS")
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
    fn task(&self, index: usize, total: usize, id: &str) {
        self.progress.task(index, total, id);
    }
    fn stage(&self, stage: &'static str) {
        self.progress.stage(stage);
    }
    fn verify_decompressor(&self) -> Result<()> {
        self.verify_zstd().map(|_| ())
    }
    fn guard(&self) -> Result<()> {
        self.cancel.check()?;
        self.progress.tick();
        ensure!(Instant::now() < self.deadline, "batch time limit");
        if let Some(scope) = self.isolation {
            scope.check()?;
        }
        if self.advisory {
            return Ok(());
        }
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
            process
                .finish(result)
                .context("checking exact rollout ownership")?;
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
        )
        .context("verifying native code signature")?;
        let mut command = Command::new(&self.policy.codex_binary);
        command
            .arg("--version")
            .env_clear()
            .env("PATH", "/usr/bin:/bin");
        ensure!(
            String::from_utf8(
                self.capture(&mut command)
                    .context("reading native Codex version")?
            )?
            .trim()
                == NATIVE_VERSION,
            "native version requires new compatibility proof"
        );
        Ok(())
    }
    fn context(&self, path: &Path, tid: &str) -> Result<(Continuation, u64)> {
        let before = identity(path)?;
        let mut parser = ContextParser::new(tid, self.policy.max_raw_bytes_per_task);
        if path.extension().is_some_and(|s| s == "zst") {
            let mut command = match self.isolation {
                Some(scope) => scope.command(&self.policy.zstd_binary, &self.policy.codex_home)?,
                None => Command::new(&self.policy.zstd_binary),
            };
            io::stream_success(
                command.args(["-dc", "--"]).arg(path),
                &mut |_| self.guard(),
                &mut |block| {
                    parser.feed(block)?;
                    self.progress.bytes(block.len() as u64);
                    Ok(())
                },
            )
            .context("decompressing continuation input")?;
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
                self.progress.bytes(count as u64);
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
        let profile = match self.isolation {
            Some(scope) => scope.profile()?,
            None => "(version 1)(allow default)(deny network*)".to_owned(),
        };
        command
            .args(["-p", &profile])
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
        if let Some(scope) = self.isolation {
            io::command_env(
                &mut command,
                &self.policy.codex_home,
                &scope.root.join("user"),
                &scope.root.join("tmp"),
            );
        }
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
    process
        .finish(operation)
        .context("registering and verifying recovered native history")
}

pub(super) trait RecoveryRuntime {
    fn stage(&self, _stage: &'static str) {}
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
    progress: progress::Progress,
}
impl RecoveryRuntime for NativeRecovery<'_> {
    fn stage(&self, stage: &'static str) {
        self.progress.stage(stage);
    }
    fn guard(&self) -> Result<()> {
        self.cancel.check()?;
        self.progress.tick();
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
    runtime.stage("checking recovery prerequisites");
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
        runtime.stage("copying and verifying recovery original");
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
        runtime.stage("registering and reading recovered history");
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
        progress: progress::Progress::new(true),
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
    #[test]
    fn zstd_preflight_probe_checks_output_and_execution_failures() {
        zstd_decompression_probe(
            Command::new("/bin/sh")
                .args(["-c", "cat >/dev/null; printf 'worktree-gc-preflight\\n'"]),
            &mut || Ok(()),
        )
        .unwrap();
        for script in [
            "cat >/dev/null; exit 7",
            "cat >/dev/null; printf wrong",
            "cat >/dev/null; printf 'worktree-gc-preflight plus unexpected bytes'",
        ] {
            assert!(zstd_decompression_probe(
                Command::new("/bin/sh").args(["-c", script]),
                &mut || Ok(()),
            )
            .is_err());
        }
        let temp = tempfile::tempdir().unwrap();
        let non_executable = temp.path().join("zstd");
        fs::write(&non_executable, "fixture").unwrap();
        for path in [non_executable, temp.path().join("missing")] {
            assert!(zstd_decompression_probe(&mut Command::new(path), &mut || Ok(())).is_err());
        }
    }

    #[test]
    fn zstd_preflight_probe_preserves_cancellation_and_teardown() {
        let calls = std::cell::Cell::new(0);
        let error = zstd_decompression_probe(
            Command::new("/bin/sh").args(["-c", "cat >/dev/null; sleep 30"]),
            &mut || {
                calls.set(calls.get() + 1);
                ensure!(calls.get() < 3, "fixture cancellation");
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("fixture cancellation"));
    }

    #[test]
    fn rehearsal_lsof_explicitly_requests_pid_and_descriptor_fields() {
        let command = rehearsal_owner_command(Path::new("/synthetic"));
        let args: Vec<_> = command.get_args().collect();
        assert!(args.windows(2).any(|pair| pair == ["-F", "pf"]));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn rehearsal_lsof_command_preserves_matches_and_real_warnings() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let _file = fs::File::create(root.join("held")).unwrap();
        fs::File::create(root.join("closed")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut guard = |_| {
            ensure!(Instant::now() < deadline, "test ownership deadline");
            Ok(())
        };
        let (status, bytes, stderr) =
            io::capture_with_stderr(&mut rehearsal_owner_command(&root), &mut guard).unwrap();
        validate_rehearsal_owners(status.code(), &bytes, &stderr, std::process::id(), &[]).unwrap();
        assert!(!bytes.is_empty());
        assert!(validate_rehearsal_owners(status.code(), &bytes, &stderr, u32::MAX, &[]).is_err());
        let (status, bytes, stderr) = io::capture_with_stderr(
            &mut rehearsal_owner_command(&root.join("missing")),
            &mut guard,
        )
        .unwrap();
        assert!(
            !stderr.is_empty(),
            "warning control must expose real traversal failures"
        );
        assert!(
            validate_rehearsal_owners(status.code(), &bytes, &stderr, std::process::id(), &[])
                .is_err()
        );
    }
    #[test]
    fn rehearsal_partial_search_matches_preserve_foreign_owner_refusals() {
        for status in [0, 1] {
            validate_rehearsal_owners(Some(status), b"p10\nf9\np20\nfcwd\n", b"", 10, &[20])
                .unwrap();
            assert!(validate_rehearsal_owners(Some(status), b"p30\nf9\n", b"", 10, &[20]).is_err());
        }
        validate_rehearsal_owners(Some(1), b"", b"", 10, &[]).unwrap();
        for (status, output, stderr) in [
            (Some(0), b"".as_slice(), b"".as_slice()),
            (Some(1), b"10\n".as_slice(), b"warning\x1b\n".as_slice()),
            (Some(2), b"10\n".as_slice(), b"".as_slice()),
            (None, b"10\n".as_slice(), b"".as_slice()),
            (Some(1), b"bad\n".as_slice(), b"".as_slice()),
            (Some(1), b"\xff".as_slice(), b"".as_slice()),
            (Some(1), b"0\n".as_slice(), b"".as_slice()),
            (Some(1), b"p10\n".as_slice(), b"".as_slice()),
            (Some(1), b"f9\n".as_slice(), b"".as_slice()),
            (Some(1), b"p10\nfNOFD\n".as_slice(), b"".as_slice()),
            (Some(1), b"p10\nf9".as_slice(), b"".as_slice()),
            (Some(1), b"p+10\nf9\n".as_slice(), b"".as_slice()),
            (Some(1), b"p10\nf+9\n".as_slice(), b"".as_slice()),
            (Some(1), b"p-10\nf9\n".as_slice(), b"".as_slice()),
            (Some(1), b"p10\nf-9\n".as_slice(), b"".as_slice()),
        ] {
            assert!(validate_rehearsal_owners(status, output, stderr, 10, &[]).is_err());
        }
        let error = validate_rehearsal_owners(Some(1), b"STDOUT_SECRET", b"warning\x1b\n", 10, &[])
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("lsof exit Some(1)") && text.contains("warning\\u{1b}\\n"));
        assert!(!text.contains("STDOUT_SECRET"));
        let command = rehearsal_owner_command(Path::new("/synthetic"));
        let args: Vec<_> = command.get_args().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(args, ["-nP", "+w", "-F", "pf", "+D", "/synthetic"]);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn nested_files_and_directories_resolve_to_the_kernel_mount() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let nested = root.join("nested");
        fs::create_dir(&nested).unwrap();
        let file = nested.join("backup.jsonl");
        fs::write(&file, b"synthetic").unwrap();
        let mount = filesystem_mount(&nested).unwrap();
        assert_ne!(mount, nested);
        assert_eq!(filesystem_mount(&file).unwrap(), mount);
        assert_eq!(
            fs::metadata(&mount).unwrap().dev(),
            fs::metadata(&file).unwrap().dev()
        );
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&nested, &alias).unwrap();
        assert!(filesystem_mount(&alias).is_err());
        assert!(filesystem_mount(&alias.join("backup.jsonl")).is_err());
        assert!(filesystem_mount(&root.join("missing")).is_err());
    }
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
