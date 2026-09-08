//! Bounded file and owned-process operations. No live-state policy lives here.
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

pub const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const DIAGNOSTIC_LIMIT: usize = 4096;

pub(super) fn stderr_diagnostic(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_owned();
    }
    // Escape terminal controls, and bound the rendered text as well as input.
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(DIAGNOSTIC_LIMIT)]);
    let mut escaped: String = text
        .chars()
        .flat_map(char::escape_default)
        .take(DIAGNOSTIC_LIMIT + 1)
        .collect();
    let truncated = bytes.len() > DIAGNOSTIC_LIMIT || escaped.len() > DIAGNOSTIC_LIMIT;
    escaped.truncate(DIAGNOSTIC_LIMIT);
    if truncated {
        escaped.push_str(" [truncated]");
    }
    escaped
}

fn command_name(command: &Command) -> String {
    // Arguments and environment can contain credentials or task content.
    let name = Path::new(command.get_program())
        .file_name()
        .unwrap_or_default();
    stderr_diagnostic(name.as_encoded_bytes())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
    pub bytes: u64,
    pub modified_seconds: i64,
    pub modified_nanos: i64,
    pub changed_seconds: i64,
    pub changed_nanos: i64,
}

pub fn path_syntax(path: &Path) -> Result<()> {
    let text = path.to_str().context("non-UTF8 path")?;
    ensure!(
        path.is_absolute() && !text.chars().any(char::is_control),
        "absolute path without control characters required"
    );
    ensure!(
        !text.split('/').any(|part| part == "." || part == ".."),
        "dot path component refused"
    );
    Ok(())
}

/// Validate all existing prefixes, including when the final path is absent.
pub fn canonical_prefixes(path: &Path) -> Result<()> {
    path_syntax(path)?;
    for prefix in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        match fs::symlink_metadata(prefix) {
            Ok(meta) => {
                ensure!(
                    !meta.file_type().is_symlink(),
                    "symlink/alias refused: {}",
                    prefix.display()
                );
                ensure!(
                    prefix.canonicalize()? == prefix,
                    "noncanonical path: {}",
                    prefix.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

pub fn canonical(path: &Path, directory: bool) -> Result<()> {
    canonical_prefixes(path)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        if directory {
            meta.is_dir()
        } else {
            meta.is_file()
        },
        "unexpected path type: {}",
        path.display()
    );
    ensure!(
        path.canonicalize()? == path,
        "path changed canonical identity"
    );
    Ok(())
}

pub fn identity(path: &Path) -> Result<Identity> {
    canonical(path, false)?;
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.nlink() == 1,
        "hardlinked rollout/index/artifact refused: {}",
        path.display()
    );
    Ok(Identity {
        device: meta.dev(),
        inode: meta.ino(),
        bytes: meta.len(),
        modified_seconds: meta.mtime(),
        modified_nanos: meta.mtime_nsec(),
        changed_seconds: meta.ctime(),
        changed_nanos: meta.ctime_nsec(),
    })
}

fn opened(path: &Path) -> Result<File> {
    let before = identity(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.dev() == before.device && meta.ino() == before.inode && meta.nlink() == 1,
        "file replaced while opening"
    );
    Ok(file)
}

pub fn hash(path: &Path, guard: &mut dyn FnMut() -> Result<()>) -> Result<String> {
    let before = identity(path)?;
    let mut file = opened(path)?;
    let mut digest = Sha256::new();
    let mut block = [0; 65536];
    loop {
        guard()?;
        let count = file.read(&mut block)?;
        if count == 0 {
            break;
        }
        digest.update(&block[..count]);
    }
    ensure!(identity(path)? == before, "file changed while hashing");
    Ok(format!("{:x}", digest.finalize()))
}

pub fn read_bound(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let before = identity(path)?;
    ensure!(before.bytes <= limit as u64, "file exceeds read bound");
    let mut bytes = Vec::new();
    opened(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit && identity(path)? == before,
        "file changed during bounded read"
    );
    Ok(bytes)
}

pub fn copy_verified(
    source: &Path,
    target: &Path,
    guard: &mut dyn FnMut() -> Result<()>,
) -> Result<String> {
    canonical_prefixes(target)?;
    let before = identity(source)?;
    let mut input = opened(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(target)?;
    let mut digest = Sha256::new();
    let mut block = [0; 65536];
    loop {
        guard()?;
        let count = input.read(&mut block)?;
        if count == 0 {
            break;
        }
        output.write_all(&block[..count])?;
        digest.update(&block[..count]);
    }
    output.sync_all()?;
    ensure!(identity(source)? == before, "source changed during copy");
    let digest = format!("{:x}", digest.finalize());
    ensure!(hash(target, guard)? == digest, "backup readback mismatch");
    sync_dir(target.parent().context("copy parent")?)?;
    Ok(digest)
}

pub fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all().context("sync directory")
}

pub fn free(path: &Path) -> Result<u64> {
    let value = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: valid nul-terminated path and writable output; initialized on success.
    ensure!(
        unsafe { libc::statvfs(value.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed: {}",
        std::io::Error::last_os_error()
    );
    let stat = unsafe { stat.assume_init() };
    // libc field widths vary across Unix targets; widen before multiplication.
    u64::try_from(u128::from(stat.f_bavail) * u128::from(stat.f_frsize))
        .context("free-space overflow")
}

pub fn writable_directory(path: &Path) -> Result<()> {
    canonical(path, true)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let before = directory.metadata()?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: owned directory descriptor and writable output, initialized on success.
    ensure!(
        unsafe { libc::fstatvfs(directory.as_raw_fd(), stat.as_mut_ptr()) } == 0,
        "destination filesystem inspection failed: {}",
        std::io::Error::last_os_error()
    );
    let stat = unsafe { stat.assume_init() };
    ensure!(
        stat.f_flag & libc::ST_RDONLY == 0,
        "destination filesystem is read-only"
    );
    // Effective credentials and ACLs must permit both creation and directory
    // search. Checking the open directory avoids probing a replaced path.
    ensure!(
        unsafe {
            libc::faccessat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::W_OK | libc::X_OK,
                libc::AT_EACCESS,
            )
        } == 0,
        "destination is not writable/searchable: {}",
        std::io::Error::last_os_error()
    );
    canonical(path, true)?;
    let after = fs::metadata(path)?;
    ensure!(
        (before.dev(), before.ino(), before.mode(), before.uid())
            == (after.dev(), after.ino(), after.mode(), after.uid()),
        "destination identity or permissions changed during observation"
    );
    Ok(())
}

pub struct Cancellation {
    pub flag: Arc<AtomicBool>,
    ids: Vec<signal_hook::SigId>,
}
impl Cancellation {
    pub fn install() -> Result<Self> {
        let mut value = Self {
            flag: Arc::new(AtomicBool::new(false)),
            ids: Vec::new(),
        };
        for signal in [libc::SIGTERM, libc::SIGHUP, libc::SIGINT] {
            value.ids.push(signal_hook::flag::register(
                signal,
                Arc::clone(&value.flag),
            )?);
        }
        Ok(value)
    }
    pub fn check(&self) -> Result<()> {
        ensure!(!self.flag.load(Ordering::Relaxed), "operator interrupted");
        Ok(())
    }
    #[cfg(test)]
    pub fn fixture() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            ids: Vec::new(),
        }
    }
}
impl Drop for Cancellation {
    fn drop(&mut self) {
        for id in self.ids.drain(..) {
            signal_hook::low_level::unregister(id);
        }
    }
}

pub struct OwnedProcess {
    name: String,
    child: Child,
    stderr: Vec<u8>,
    stdout_eof: bool,
    stderr_eof: bool,
    stopped: bool,
}
impl OwnedProcess {
    pub fn spawn(command: &mut Command, stdin: bool) -> Result<Self> {
        // SAFETY: umask is the only operation in the post-fork hook; no Rust
        // allocation or locking occurs. Native diagnostic files stay private.
        unsafe {
            command.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        command
            .process_group(0)
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let name = command_name(command);
        let child = command
            .spawn()
            .with_context(|| format!("spawning bounded subprocess {name}"))?;
        let value = Self {
            name,
            child,
            stderr: Vec::new(),
            stdout_eof: false,
            stderr_eof: false,
            stopped: false,
        };
        let mut descriptors = vec![
            value.child.stdout.as_ref().context("stdout")?.as_raw_fd(),
            value.child.stderr.as_ref().context("stderr")?.as_raw_fd(),
        ];
        if let Some(input) = value.child.stdin.as_ref() {
            descriptors.push(input.as_raw_fd());
        }
        for fd in descriptors {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            ensure!(
                flags >= 0
                    && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
                "nonblocking pipe setup failed"
            );
        }
        Ok(value)
    }
    pub fn id(&self) -> u32 {
        self.child.id()
    }
    pub fn stderr_empty(&self) -> bool {
        self.stderr.is_empty()
    }
    pub fn finish<T>(&mut self, result: Result<T>) -> Result<T> {
        let teardown = self.stop();
        let status = match self.child.try_wait() {
            Ok(Some(status)) => status.to_string(),
            _ => "exit status unavailable".into(),
        };
        finish_process(
            result,
            teardown,
            format!(
                "bounded subprocess {}; {}; stderr: {}",
                self.name,
                status,
                stderr_diagnostic(&self.stderr)
            ),
        )
    }
    pub fn write_json(
        &mut self,
        value: &serde_json::Value,
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() < 65536, "native request bound");
        bytes.push(b'\n');
        self.write_input(&bytes, guard)
    }
    pub fn write_input(
        &mut self,
        bytes: &[u8],
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        ensure!(bytes.len() <= 65536, "native request bound");
        let stream = self.child.stdin.as_mut().context("native stdin absent")?;
        let mut offset = 0;
        while offset < bytes.len() {
            guard()?;
            match stream.write(&bytes[offset..]) {
                Ok(0) => bail!("native stdin closed"),
                Ok(count) => offset += count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    pub fn close_input(&mut self) {
        self.child.stdin.take();
    }
    pub fn poll(
        &mut self,
        consume: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<ExitStatus>> {
        let mut block = [0; 65536];
        // Bound each drain turn so callers can check cancellation/deadlines.
        // Service both pipes every round: a busy stdout must not starve stderr.
        for _ in 0..32 {
            let mut progressed = false;
            if !self.stderr_eof {
                match self
                    .child
                    .stderr
                    .as_mut()
                    .context("stderr")?
                    .read(&mut block)
                {
                    Ok(0) => {
                        self.stderr_eof = true;
                        progressed = true;
                    }
                    Ok(count) => {
                        progressed = true;
                        ensure!(
                            self.stderr.len() + count <= OUTPUT_LIMIT,
                            "child stderr cap"
                        );
                        self.stderr.extend_from_slice(&block[..count]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !self.stdout_eof {
                match self
                    .child
                    .stdout
                    .as_mut()
                    .context("stdout")?
                    .read(&mut block)
                {
                    Ok(0) => {
                        self.stdout_eof = true;
                        progressed = true;
                    }
                    Ok(count) => {
                        consume(&block[..count])?;
                        progressed = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
            }
            if !progressed {
                break;
            }
        }
        if self.stderr_eof && self.stdout_eof {
            return Ok(self.child.try_wait()?);
        }
        Ok(None)
    }
    pub fn wait_ready(&self) -> Result<()> {
        let mut fds = Vec::with_capacity(2);
        if !self.stdout_eof {
            fds.push(libc::pollfd {
                fd: self.child.stdout.as_ref().context("stdout")?.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if !self.stderr_eof {
            fds.push(libc::pollfd {
                fd: self.child.stderr.as_ref().context("stderr")?.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // Ready data (or EOF) returns immediately. Ten milliseconds is a maximum
        // idle wait, not a per-buffer delay. With both pipes closed this also
        // bounds waiting for the process to exit without spinning.
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 10) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        ensure!(
            fds.iter().all(|fd| fd.revents & libc::POLLNVAL == 0),
            "invalid subprocess pipe"
        );
        Ok(())
    }
    pub fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        let pgid = -(self.child.id() as i32);
        unsafe {
            libc::kill(pgid, libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if unsafe { libc::kill(pgid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                break;
            }
            let _ = self.child.try_wait();
            std::thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(pgid, libc::SIGKILL);
        }
        self.child.wait()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if unsafe { libc::kill(pgid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                self.stopped = true;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        bail!("owned subprocess group {} remains after teardown", -pgid)
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub fn stream_success(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
    consume: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let name = command_name(command);
    let (status, stderr) = stream_with_stderr(command, guard, consume)?;
    ensure!(
        status.success(),
        "bounded subprocess {name} failed: {status}; stderr: {}",
        stderr_diagnostic(&stderr)
    );
    Ok(())
}

fn stream_with_stderr(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
    consume: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<(ExitStatus, Vec<u8>)> {
    let mut process = OwnedProcess::spawn(command, false)?;
    let result: Result<ExitStatus> = (|| loop {
        guard(process.id())?;
        if let Some(status) = process.poll(consume)? {
            break Ok(status);
        }
        process.wait_ready()?;
    })();
    let status = process.finish(result)?;
    Ok((status, std::mem::take(&mut process.stderr)))
}

fn finish_process<T>(result: Result<T>, teardown: Result<()>, diagnostic: String) -> Result<T> {
    match (result, teardown) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(error), Ok(())) => Err(error.context(diagnostic)),
        (Ok(_), Err(error)) => Err(error.context(diagnostic)),
        (Err(error), Err(teardown)) => {
            Err(error.context(format!("{diagnostic}; teardown also failed: {teardown:#}")))
        }
    }
}

#[cfg(test)]
pub fn capture(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
) -> Result<(ExitStatus, Vec<u8>)> {
    capture_with_stderr(command, guard).map(|(status, stdout, _)| (status, stdout))
}

pub fn capture_with_stderr(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let (status, stderr) = stream_with_stderr(command, guard, &mut |block| {
        ensure!(
            result.len() + block.len() <= OUTPUT_LIMIT,
            "child stdout cap"
        );
        result.extend_from_slice(block);
        Ok(())
    })?;
    Ok((status, result, stderr))
}

pub fn success(command: &mut Command, guard: &mut dyn FnMut(u32) -> Result<()>) -> Result<Vec<u8>> {
    let name = command_name(command);
    let (status, value, stderr) = capture_with_stderr(command, guard)?;
    ensure!(
        status.success(),
        "bounded subprocess {name} failed: {status}; stderr: {}",
        stderr_diagnostic(&stderr)
    );
    Ok(value)
}

pub fn exclusive_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    canonical_prefixes(path)?;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    sync_dir(path.parent().context("directory parent")?)
}

pub fn unique_id() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

pub fn intersects(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

pub struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // A concurrent fork can inherit this open file description until exec.
        // Explicit unlock ends our scope's authority even while that inherited
        // descriptor remains open; closing our descriptor alone cannot do so.
        let _ = fs4::FileExt::unlock(&self.file);
    }
}

pub fn lock_file(path: &Path, shared: bool) -> Result<FileLock> {
    canonical_prefixes(path)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(meta.is_file() && meta.nlink() == 1, "unsafe lock file");
    if shared {
        fs4::FileExt::try_lock_shared(&file)?;
    } else {
        fs4::FileExt::try_lock(&file)?;
    }
    Ok(FileLock { file })
}

pub fn command_env(command: &mut Command, home: &Path, user: &Path, temp: &Path) {
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", user)
        .env("CODEX_HOME", home)
        .env("TMPDIR", temp)
        .env("XDG_CACHE_HOME", temp.join("cache"))
        .env("XDG_STATE_HOME", temp.join("state"))
        .env("XDG_CONFIG_HOME", temp.join("config"))
        .env("LANG", "en_US.UTF-8")
        .env("RUST_LOG", "error")
        .current_dir(temp);
}

pub fn absent(path: &Path) -> Result<()> {
    canonical_prefixes(path)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!("destination already exists: {}", path.display()),
    }
}

#[cfg(test)]
mod diagnostic_tests {
    #[test]
    fn large_stream_is_not_throttled_by_poll_intervals() {
        let start = std::time::Instant::now();
        let mut bytes = 0;
        super::stream_success(
            std::process::Command::new("/bin/dd").args(["if=/dev/zero", "bs=1048576", "count=128"]),
            &mut |_| {
                anyhow::ensure!(start.elapsed().as_secs() < 15, "stream test deadline");
                Ok(())
            },
            &mut |block| {
                bytes += block.len();
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(bytes, 128 * 1024 * 1024);
        // The previous 64KiB/10ms implementation requires at least20.48s.
        assert!(
            start.elapsed() < std::time::Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn busy_stream_returns_to_cancellation_guard_and_reaps_child() {
        let observed = std::cell::Cell::new(0usize);
        let mut previous = 0usize;
        let mut pid = 0;
        let error = super::stream_success(
            std::process::Command::new("/bin/dd").args(["if=/dev/zero", "bs=1048576", "count=128"]),
            &mut |child| {
                pid = child;
                let now = observed.get();
                assert!(now - previous <= 32 * 65536);
                previous = now;
                anyhow::ensure!(now < 4 * 1024 * 1024, "fixture cancellation");
                Ok(())
            },
            &mut |block| {
                observed.set(observed.get() + block.len());
                Ok(())
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("fixture cancellation"));
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
    }

    #[test]
    fn stdout_and_stderr_are_drained_fairly() {
        let mut bytes = 0;
        let (status, stderr) = super::stream_with_stderr(
            std::process::Command::new("/bin/sh").args(["-c", "dd if=/dev/zero bs=65536 count=8 >&2 2>/dev/null & dd if=/dev/zero bs=65536 count=128 2>/dev/null; wait"]),
            &mut |_| Ok(()), &mut |block| { bytes += block.len(); Ok(()) },
        ).unwrap();
        assert!(status.success());
        assert_eq!(bytes, 128 * 65536);
        assert_eq!(stderr.len(), 8 * 65536);
    }
    use super::*;
    #[test]
    fn lock_scope_releases_while_an_inherited_description_remains_open() {
        for shared in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().canonicalize().unwrap().join("lock");
            let guard = lock_file(&path, shared).unwrap();
            // dup and fork retain the same flock open-file description. Keep
            // that description alive deterministically instead of racing exec.
            let inherited = guard.file.try_clone().unwrap();
            assert!(lock_file(&path, false).is_err());
            drop(guard);
            let successor = lock_file(&path, false).unwrap();
            drop(inherited);
            assert!(lock_file(&path, false).is_err());
            drop(successor);
            assert!(lock_file(&path, false).is_ok());
        }
    }

    #[test]
    fn child_created_diagnostics_are_private() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("diagnostic");
        success(
            Command::new("/bin/sh")
                .args(["-c", "printf diagnostic > \"$1\"", "fixture"])
                .arg(&path),
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, 0o600);
    }
    #[test]
    fn failure_identifies_executable_exit_and_stderr_without_command_secrets() {
        let error = success(
            Command::new("/bin/sh")
                .args([
                    "-c",
                    "printf STDOUT_SECRET; printf 'permission denied\\n' >&2; exit 7",
                    "ARG_SECRET",
                ])
                .env("ENV_SECRET", "ENV_VALUE"),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("subprocess sh failed")
                && text.contains('7')
                && text.contains("permission denied\\n"),
            "{text}"
        );
        for secret in [
            "STDOUT_SECRET",
            "ARG_SECRET",
            "ENV_SECRET",
            "ENV_VALUE",
            "printf",
        ] {
            assert!(!text.contains(secret));
        }
    }
    #[test]
    fn diagnostics_escape_invalid_bytes_controls_and_cap_rendering() {
        assert_eq!(stderr_diagnostic(&[]), "<empty>");
        let text = stderr_diagnostic(b"\xff\x1b[31m\n\r\t");
        assert!(!text.chars().any(char::is_control));
        assert!(text.contains("\\u{fffd}") && text.contains("\\u{1b}"));
        let text = stderr_diagnostic(&vec![0xff; 5000]);
        assert!(text.len() <= DIAGNOSTIC_LIMIT + " [truncated]".len());
        assert!(text.ends_with(" [truncated]"));
    }
    #[test]
    fn empty_stderr_and_successful_stdout_are_preserved() {
        let error = success(Command::new("/bin/sh").args(["-c", "exit 2"]), &mut |_| {
            Ok(())
        })
        .unwrap_err();
        assert!(format!("{error:#}").contains("stderr: <empty>"));
        assert_eq!(
            success(
                Command::new("/bin/sh").args(["-c", "printf output; printf warning >&2"]),
                &mut |_| Ok(())
            )
            .unwrap(),
            b"output"
        );
    }
    #[test]
    fn spawn_failure_does_not_echo_arguments() {
        let error = success(
            Command::new("/absent-gc-fixture/executable").arg("ARG_SECRET"),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("spawning bounded subprocess executable"));
        assert!(!text.contains("ARG_SECRET"));
    }
    #[test]
    fn preserves_primary_failure_and_teardown_failure() {
        let error = finish_process::<()>(
            Err(anyhow::anyhow!("primary failure")),
            Err(anyhow::anyhow!("cleanup failure")),
            "stage".into(),
        )
        .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("primary failure") && text.contains("cleanup failure"));
    }

    #[test]
    fn streamed_and_rpc_failures_retain_diagnostics() {
        let error = stream_success(
            Command::new("/bin/sh").args(["-c", "printf stream-error >&2; exit 7"]),
            &mut |_| Ok(()),
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("stream-error"));
        assert!(format!("{error:#}").contains("7"));
        let mut process = OwnedProcess::spawn(
            Command::new("/bin/sh").args(["-c", "printf rpc-error >&2; exit 8"]),
            true,
        )
        .unwrap();
        while process.poll(&mut |_| Ok(())).unwrap().is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
        let error = process
            .finish::<()>(Err(anyhow::anyhow!("recovery stage")))
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("rpc-error") && text.contains("8") && text.contains("recovery stage")
        );
    }
}
