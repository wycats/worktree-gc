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
    child: Child,
    stderr: Vec<u8>,
    stdout_eof: bool,
    stderr_eof: bool,
    stopped: bool,
}
impl OwnedProcess {
    pub fn spawn(command: &mut Command, stdin: bool) -> Result<Self> {
        command
            .process_group(0)
            .stdin(if stdin { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn()?;
        let value = Self {
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
    pub fn write_json(
        &mut self,
        value: &serde_json::Value,
        guard: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let stream = self.child.stdin.as_mut().context("native stdin absent")?;
        let mut bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() < 65536, "native request bound");
        bytes.push(b'\n');
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
    pub fn poll(
        &mut self,
        consume: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<Option<ExitStatus>> {
        let mut block = [0; 65536];
        if !self.stderr_eof {
            match self
                .child
                .stderr
                .as_mut()
                .context("stderr")?
                .read(&mut block)
            {
                Ok(0) => self.stderr_eof = true,
                Ok(count) => {
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
                Ok(0) => self.stdout_eof = true,
                Ok(count) => consume(&block[..count])?,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
        }
        if self.stderr_eof && self.stdout_eof {
            return Ok(self.child.try_wait()?);
        }
        Ok(None)
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

pub fn stream(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
    consume: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<ExitStatus> {
    let mut process = OwnedProcess::spawn(command, false)?;
    let result: Result<ExitStatus> = (|| loop {
        guard(process.id())?;
        if let Some(status) = process.poll(consume)? {
            break Ok(status);
        }
        std::thread::sleep(Duration::from_millis(10));
    })();
    let teardown = process.stop();
    let status = result?;
    teardown?;
    Ok(status)
}

pub fn capture(
    command: &mut Command,
    guard: &mut dyn FnMut(u32) -> Result<()>,
) -> Result<(ExitStatus, Vec<u8>)> {
    let mut result = Vec::new();
    let status = stream(command, guard, &mut |block| {
        ensure!(
            result.len() + block.len() <= OUTPUT_LIMIT,
            "child stdout cap"
        );
        result.extend_from_slice(block);
        Ok(())
    })?;
    Ok((status, result))
}

pub fn success(command: &mut Command, guard: &mut dyn FnMut(u32) -> Result<()>) -> Result<Vec<u8>> {
    let (status, value) = capture(command, guard)?;
    ensure!(status.success(), "bounded command failed: {status}");
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

pub fn lock_file(path: &Path, shared: bool) -> Result<File> {
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
    Ok(file)
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
