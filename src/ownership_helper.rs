use crate::ownership_protocol::{
    read_message, write_message, OwnershipRequest, OwnershipResponse, WirePath, MAX_REQUEST_ROOTS,
    OWNERSHIP_PROTOCOL_VERSION,
};
#[cfg(any(target_os = "macos", test))]
use crate::ownership_protocol::{OwnershipObservation, OwnershipPathKind};
use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "macos", test))]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};

pub const HELPER_LABEL: &str = "com.wycats.worktree-gc.ownership-helper";
pub const DEFAULT_HELPER_BINARY: &str =
    "/Library/PrivilegedHelperTools/com.wycats.worktree-gc.ownership-helper";
pub const DEFAULT_HELPER_CONFIG: &str =
    "/Library/Application Support/worktree-gc/ownership-helper.toml";
pub const DEFAULT_HELPER_PLIST: &str =
    "/Library/LaunchDaemons/com.wycats.worktree-gc.ownership-helper.plist";
pub const DEFAULT_HELPER_SOCKET: &str =
    "/Library/Application Support/worktree-gc/run/ownership.sock";
#[cfg(any(target_os = "macos", test))]
const HELPER_CONFIG_VERSION: u64 = 1;
const HELPER_IO_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(target_os = "macos")]
const MAX_MATCHED_OBSERVATIONS: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperConfig {
    pub config_version: u64,
    pub allowed_uid: u32,
    pub allowed_gid: u32,
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct HelperInstallOptions {
    pub source_binary: PathBuf,
    pub client_uid: u32,
    pub client_gid: u32,
    pub roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HelperStatus {
    pub installed: bool,
    pub loaded: bool,
    pub protocol_version: u64,
    pub client_uid: Option<u32>,
    pub roots: Vec<PathBuf>,
    pub socket: PathBuf,
    pub probe_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[cfg(unix)]
pub fn capture_from_helper(socket: &Path, roots: &[PathBuf]) -> Result<OwnershipResponse> {
    ensure!(
        roots.len() <= MAX_REQUEST_ROOTS,
        "ownership request has {} roots; limit is {MAX_REQUEST_ROOTS}",
        roots.len()
    );
    let request_id = request_id();
    let request = OwnershipRequest::new(request_id, roots);
    let mut stream = UnixStream::connect(socket)
        .with_context(|| format!("failed to connect to ownership helper {}", socket.display()))?;
    stream.set_read_timeout(Some(HELPER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_IO_TIMEOUT))?;
    write_message(&mut stream, &request)?;
    let response: OwnershipResponse = read_message(&mut stream)?;
    validate_response(&request, &response)?;
    Ok(response)
}

#[cfg(not(unix))]
pub fn capture_from_helper(_socket: &Path, _roots: &[PathBuf]) -> Result<OwnershipResponse> {
    bail!("the privileged ownership helper requires Unix")
}

#[cfg(target_os = "macos")]
pub fn serve(config_path: &Path, socket_path: &Path) -> Result<()> {
    ensure_root()?;
    let config = load_root_owned_config(config_path)?;
    let socket_parent = socket_path
        .parent()
        .context("ownership helper socket has no parent directory")?;
    ensure_root_owned_directory_chain(&socket_parent.canonicalize()?)?;
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        ensure!(
            metadata.file_type().is_socket() && metadata.uid() == 0,
            "refusing to replace non-helper socket path {}",
            socket_path.display()
        );
        fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    chown(socket_path, 0, config.allowed_gid)?;

    for connection in listener.incoming() {
        let mut stream = match connection {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("ownership helper accept failed: {error}");
                continue;
            }
        };
        if let Err(error) = handle_connection(&mut stream, &config) {
            eprintln!("ownership helper request failed: {error:#}");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn serve(_config_path: &Path, _socket_path: &Path) -> Result<()> {
    bail!("the privileged ownership helper service requires macOS")
}

#[cfg(target_os = "macos")]
fn handle_connection(stream: &mut UnixStream, config: &HelperConfig) -> Result<()> {
    stream.set_read_timeout(Some(HELPER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_IO_TIMEOUT))?;
    let peer_uid = peer_uid(stream)?;
    ensure!(
        peer_uid == config.allowed_uid,
        "peer uid {peer_uid} is not the configured client uid {}",
        config.allowed_uid
    );
    let request: OwnershipRequest = read_message(stream)?;
    let response = match validated_request_roots(&request, config) {
        Ok(roots) => capture_privileged_ownership(request.request_id, &roots),
        Err(error) => OwnershipResponse::refusal(request.request_id, format!("{error:#}")),
    };
    write_message(stream, &response)
}

#[cfg(target_os = "macos")]
fn capture_privileged_ownership(request_id: u64, roots: &[PathBuf]) -> OwnershipResponse {
    if roots.is_empty() {
        return OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id,
            backend: "macos_privileged_libproc".to_string(),
            complete: true,
            error: None,
            observations: Vec::new(),
        };
    }
    let capture = match crate::macos_open_handles::capture_with_evidence() {
        Ok(capture) => capture,
        Err(error) => {
            return OwnershipResponse::refusal(
                request_id,
                format!("privileged libproc capture failed: {error}"),
            );
        }
    };
    privileged_response_from_capture(request_id, roots, capture)
}

#[cfg(target_os = "macos")]
fn privileged_response_from_capture(
    request_id: u64,
    roots: &[PathBuf],
    capture: crate::macos_open_handles::Capture,
) -> OwnershipResponse {
    if !capture.permission_denied_pids.is_empty() {
        return OwnershipResponse::refusal(
            request_id,
            format!(
                "privileged libproc capture was incomplete for PIDs {:?}",
                capture.permission_denied_pids
            ),
        );
    }
    let mut observations = Vec::new();
    for observation in capture.observations {
        for root in roots
            .iter()
            .filter(|root| observation.path.starts_with(root))
        {
            if observations.len() >= MAX_MATCHED_OBSERVATIONS {
                return OwnershipResponse::refusal(
                    request_id,
                    format!(
                        "privileged ownership response exceeded {MAX_MATCHED_OBSERVATIONS} matched observations"
                    ),
                );
            }
            observations.push(OwnershipObservation {
                pid: observation.pid,
                kind: match observation.kind {
                    crate::macos_open_handles::ProcessPathKind::Cwd => OwnershipPathKind::Cwd,
                    crate::macos_open_handles::ProcessPathKind::Root => OwnershipPathKind::Root,
                    crate::macos_open_handles::ProcessPathKind::MappedFile => {
                        OwnershipPathKind::MappedFile
                    }
                    crate::macos_open_handles::ProcessPathKind::OpenFile => {
                        OwnershipPathKind::OpenFile
                    }
                },
                observed_path: WirePath::from_path(&observation.path),
                matched_root: WirePath::from_path(root),
            });
        }
    }
    OwnershipResponse {
        protocol_version: OWNERSHIP_PROTOCOL_VERSION,
        request_id,
        backend: "macos_privileged_libproc".to_string(),
        complete: true,
        error: None,
        observations,
    }
}

#[cfg(any(target_os = "macos", test))]
fn validated_request_roots(
    request: &OwnershipRequest,
    config: &HelperConfig,
) -> Result<Vec<PathBuf>> {
    ensure!(
        request.protocol_version == OWNERSHIP_PROTOCOL_VERSION,
        "unsupported ownership protocol version {}",
        request.protocol_version
    );
    ensure!(
        request.roots.len() <= MAX_REQUEST_ROOTS,
        "ownership request has {} roots; limit is {MAX_REQUEST_ROOTS}",
        request.roots.len()
    );
    let allowed = canonical_config_roots(config)?;
    let mut roots = Vec::with_capacity(request.roots.len());
    for wire_root in &request.roots {
        let requested = wire_root.to_path_buf()?;
        ensure!(
            requested.is_absolute(),
            "ownership request root {} is not absolute",
            requested.display()
        );
        let canonical = requested.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize ownership request root {}",
                requested.display()
            )
        })?;
        ensure!(
            canonical == requested,
            "ownership request root {} is not canonical (resolved to {})",
            requested.display(),
            canonical.display()
        );
        ensure!(
            allowed.iter().any(|root| canonical.starts_with(root)),
            "ownership request root {} is outside the configured allowlist",
            canonical.display()
        );
        roots.push(canonical);
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

#[cfg(any(target_os = "macos", test))]
fn canonical_config_roots(config: &HelperConfig) -> Result<Vec<PathBuf>> {
    ensure!(
        config.config_version == HELPER_CONFIG_VERSION,
        "unsupported ownership helper config version {}",
        config.config_version
    );
    ensure!(
        config.allowed_uid != 0,
        "ownership helper client uid must not be root"
    );
    ensure!(
        !config.roots.is_empty(),
        "ownership helper requires at least one allowed root"
    );
    let mut roots = Vec::with_capacity(config.roots.len());
    for root in &config.roots {
        ensure!(
            root.is_absolute(),
            "ownership helper allowlist root {} is not absolute",
            root.display()
        );
        let canonical = root.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize ownership helper allowlist root {}",
                root.display()
            )
        })?;
        ensure!(
            canonical == *root,
            "ownership helper allowlist root {} is not canonical (resolved to {})",
            root.display(),
            canonical.display()
        );
        ensure!(
            canonical.is_dir(),
            "ownership helper allowlist root {} is not a directory",
            canonical.display()
        );
        roots.push(canonical);
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn validate_response(request: &OwnershipRequest, response: &OwnershipResponse) -> Result<()> {
    ensure!(
        response.protocol_version == OWNERSHIP_PROTOCOL_VERSION,
        "ownership helper returned protocol version {}",
        response.protocol_version
    );
    ensure!(
        response.request_id == request.request_id,
        "ownership helper response id does not match request"
    );
    if !response.complete {
        ensure!(
            response.observations.is_empty(),
            "incomplete ownership helper response included observations"
        );
        return Ok(());
    }
    ensure!(
        response.error.is_none(),
        "complete ownership helper response included an error"
    );
    let requested = request
        .roots
        .iter()
        .map(WirePath::to_path_buf)
        .collect::<Result<Vec<_>>>()?;
    for observation in &response.observations {
        let matched = observation.matched_root.to_path_buf()?;
        let observed = observation.observed_path.to_path_buf()?;
        ensure!(
            requested.contains(&matched),
            "ownership helper matched an unrequested root {}",
            matched.display()
        );
        ensure!(
            observed.starts_with(&matched),
            "ownership helper observation {} escapes matched root {}",
            observed.display(),
            matched.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn install(options: HelperInstallOptions) -> Result<()> {
    ensure_root()?;
    ensure!(
        options.source_binary.is_absolute(),
        "helper source binary must be absolute"
    );
    let source_binary = options.source_binary.canonicalize()?;
    ensure!(
        source_binary.is_file(),
        "helper source binary {} is not a file",
        source_binary.display()
    );
    let config = HelperConfig {
        config_version: HELPER_CONFIG_VERSION,
        allowed_uid: options.client_uid,
        allowed_gid: options.client_gid,
        roots: options
            .roots
            .iter()
            .map(|root| root.canonicalize())
            .collect::<std::io::Result<Vec<_>>>()?,
    };
    canonical_config_roots(&config)?;

    let helper_binary = Path::new(DEFAULT_HELPER_BINARY);
    let helper_config = Path::new(DEFAULT_HELPER_CONFIG);
    let helper_plist = Path::new(DEFAULT_HELPER_PLIST);
    for parent in [helper_binary.parent(), helper_plist.parent()]
        .into_iter()
        .flatten()
    {
        ensure_root_owned_directory_chain(parent)?;
    }
    for parent in [
        helper_config.parent(),
        Path::new(DEFAULT_HELPER_SOCKET).parent(),
    ]
    .into_iter()
    .flatten()
    {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        chown(parent, 0, 0)?;
        ensure_root_owned_directory_chain(parent)?;
    }

    let backup = backup_existing_installation()?;
    if service_loaded() {
        bootout_service(true)?;
    }
    let result = (|| {
        atomic_copy(&source_binary, helper_binary, 0o755)?;
        ensure!(
            fs::read(&source_binary)? == fs::read(helper_binary)?,
            "installed ownership helper bytes do not match the source binary"
        );
        atomic_write(
            helper_config,
            toml::to_string_pretty(&config)?.as_bytes(),
            0o600,
        )?;
        atomic_write(
            helper_plist,
            render_launchd_plist(helper_binary, helper_config).as_bytes(),
            0o644,
        )?;
        ensure_root_owned_regular_file(helper_binary, 0o755)?;
        ensure_root_owned_regular_file(helper_config, 0o600)?;
        ensure_root_owned_regular_file(helper_plist, 0o644)?;
        bootstrap_service(helper_plist)?;
        wait_for_service_socket(Path::new(DEFAULT_HELPER_SOCKET))
    })();
    if let Err(error) = result {
        let _ = bootout_service(false);
        restore_installation(&backup)?;
        if helper_plist.exists() {
            let _ = bootstrap_service(helper_plist);
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn install(_options: HelperInstallOptions) -> Result<()> {
    bail!("the privileged ownership helper requires macOS")
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    ensure_root()?;
    bootout_service(false)?;
    for (path, expected_socket) in [
        (Path::new(DEFAULT_HELPER_SOCKET), true),
        (Path::new(DEFAULT_HELPER_PLIST), false),
        (Path::new(DEFAULT_HELPER_CONFIG), false),
        (Path::new(DEFAULT_HELPER_BINARY), false),
    ] {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            ensure!(
                metadata.uid() == 0
                    && !metadata.file_type().is_symlink()
                    && (metadata.file_type().is_socket() == expected_socket),
                "refusing to remove unexpected helper path {}",
                path.display()
            );
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<()> {
    bail!("the privileged ownership helper requires macOS")
}

#[cfg(target_os = "macos")]
pub fn status() -> HelperStatus {
    let loaded = service_loaded();
    let probe = capture_from_helper(Path::new(DEFAULT_HELPER_SOCKET), &[]);
    let installed = Path::new(DEFAULT_HELPER_BINARY).exists()
        && Path::new(DEFAULT_HELPER_CONFIG).exists()
        && Path::new(DEFAULT_HELPER_PLIST).exists();
    let config = fs::read_to_string(DEFAULT_HELPER_CONFIG)
        .ok()
        .and_then(|contents| toml::from_str::<HelperConfig>(&contents).ok());
    match probe {
        Ok(response) => HelperStatus {
            installed,
            loaded,
            protocol_version: response.protocol_version,
            client_uid: config.as_ref().map(|config| config.allowed_uid),
            roots: config.map(|config| config.roots).unwrap_or_default(),
            socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
            probe_complete: response.complete,
            error: response.error,
        },
        Err(error) => HelperStatus {
            installed,
            loaded,
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            client_uid: config.as_ref().map(|config| config.allowed_uid),
            roots: config.map(|config| config.roots).unwrap_or_default(),
            socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
            probe_complete: false,
            error: Some(format!("{error:#}")),
        },
    }
}

#[cfg(not(target_os = "macos"))]
pub fn status() -> HelperStatus {
    HelperStatus {
        installed: false,
        loaded: false,
        protocol_version: OWNERSHIP_PROTOCOL_VERSION,
        client_uid: None,
        roots: Vec::new(),
        socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
        probe_complete: false,
        error: Some("the privileged ownership helper requires macOS".to_string()),
    }
}

#[cfg(target_os = "macos")]
fn load_root_owned_config(path: &Path) -> Result<HelperConfig> {
    ensure_root_owned_regular_file(path, 0o600)?;
    ensure_root_owned_directory_chain(
        path.parent()
            .context("ownership helper config has no parent")?,
    )?;
    let config: HelperConfig = toml::from_str(
        &fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?,
    )?;
    canonical_config_roots(&config)?;
    Ok(config)
}

#[cfg(target_os = "macos")]
fn ensure_root_owned_regular_file(path: &Path, mode: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "{} is not a regular file",
        path.display()
    );
    ensure!(
        metadata.uid() == 0,
        "{} is not owned by root",
        path.display()
    );
    ensure!(
        metadata.mode() & 0o777 == mode,
        "{} has mode {:o}, expected {mode:o}",
        path.display(),
        metadata.mode() & 0o777
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_root_owned_directory_chain(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("failed to inspect {}", ancestor.display()))?;
        ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "{} is not a real directory",
            ancestor.display()
        );
        ensure!(
            metadata.uid() == 0,
            "{} is not owned by root",
            ancestor.display()
        );
        ensure!(
            metadata.mode() & 0o022 == 0,
            "{} is group- or world-writable",
            ancestor.display()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn ensure_root() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "ownership helper management requires root"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut uid = 0_u32;
    let mut gid = 0_u32;
    let result = unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("getpeereid failed");
    }
    Ok(uid)
}

#[cfg(target_os = "macos")]
fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())?;
    let result = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("chown failed");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn atomic_copy(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let bytes = fs::read(source)?;
    atomic_write(destination, &bytes, mode)
}

#[cfg(target_os = "macos")]
fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let mut file = atomic_write_file::AtomicWriteFile::open(path)?;
    file.write_all(contents)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(mode))?;
    file.commit()?;
    chown(path, 0, 0)?;
    Ok(())
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct InstallationBackup {
    directory: PathBuf,
    files: Vec<(PathBuf, PathBuf)>,
}

#[cfg(target_os = "macos")]
fn backup_existing_installation() -> Result<InstallationBackup> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let directory = Path::new(DEFAULT_HELPER_CONFIG)
        .parent()
        .context("helper config path has no parent")?
        .join("backups")
        .join(format!("{timestamp}-{}", std::process::id()));
    fs::create_dir_all(
        directory
            .parent()
            .context("helper backup directory has no parent")?,
    )?;
    fs::create_dir(&directory)?;
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
    chown(&directory, 0, 0)?;
    let mut files = Vec::new();
    for source in [
        Path::new(DEFAULT_HELPER_BINARY),
        Path::new(DEFAULT_HELPER_CONFIG),
        Path::new(DEFAULT_HELPER_PLIST),
    ] {
        if source.exists() {
            let destination = directory.join(
                source
                    .file_name()
                    .context("helper installation path has no file name")?,
            );
            fs::copy(source, &destination)?;
            files.push((source.to_path_buf(), destination));
        }
    }
    Ok(InstallationBackup { directory, files })
}

#[cfg(target_os = "macos")]
fn restore_installation(backup: &InstallationBackup) -> Result<()> {
    for destination in [
        Path::new(DEFAULT_HELPER_BINARY),
        Path::new(DEFAULT_HELPER_CONFIG),
        Path::new(DEFAULT_HELPER_PLIST),
    ] {
        if destination.exists() {
            fs::remove_file(destination)?;
        }
    }
    for (destination, source) in &backup.files {
        fs::copy(source, destination)?;
        chown(destination, 0, 0)?;
    }
    eprintln!(
        "restored previous ownership helper installation from {}",
        backup.directory.display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn render_launchd_plist(binary: &Path, config: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{HELPER_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{}</string>
    <string>serve</string>
    <string>--config</string>
    <string>{}</string>
    <string>--socket</string>
    <string>{DEFAULT_HELPER_SOCKET}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StandardOutPath</key>
  <string>/var/log/worktree-gc-ownership-helper.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/worktree-gc-ownership-helper.log</string>
</dict>
</plist>
"#,
        xml_escape(binary),
        xml_escape(config)
    )
}

#[cfg(target_os = "macos")]
fn xml_escape(path: &Path) -> String {
    path.to_string_lossy()
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "macos")]
fn bootout_service(required: bool) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{HELPER_LABEL}")])
        .stdin(Stdio::null())
        .output()?;
    if required && !output.status.success() {
        bail!(
            "launchctl bootout failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn bootstrap_service(plist: &Path) -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .arg("bootstrap")
        .arg("system")
        .arg(plist)
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "launchctl bootstrap failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn wait_for_service_socket(socket: &Path) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(metadata) = fs::symlink_metadata(socket) {
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == 0
                    && metadata.mode() & 0o777 == 0o660,
                "ownership helper created an unexpected socket at {}",
                socket.display()
            );
            if let Ok(response) = capture_from_helper(socket, &[]) {
                ensure!(
                    response.complete,
                    "ownership helper readiness probe was incomplete: {}",
                    response.error.as_deref().unwrap_or("unspecified error")
                );
                return Ok(());
            }
        }
        ensure!(
            std::time::Instant::now() < deadline,
            "ownership helper did not become ready at {} within 5 seconds",
            socket.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "macos")]
fn service_loaded() -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &format!("system/{HELPER_LABEL}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn request_id() -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    now.as_secs()
        .rotate_left(17)
        .wrapping_add(u64::from(now.subsec_nanos()))
        .wrapping_add(u64::from(std::process::id()))
}

#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn getpeereid(socket: std::ffi::c_int, uid: *mut u32, gid: *mut u32) -> std::ffi::c_int;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn config(root: &Path) -> HelperConfig {
        HelperConfig {
            config_version: HELPER_CONFIG_VERSION,
            allowed_uid: 501,
            allowed_gid: 20,
            roots: vec![root.to_path_buf()],
        }
    }

    #[test]
    fn request_requires_canonical_allowlisted_roots() -> Result<()> {
        let temp = TempDir::new()?;
        let allowed = temp.path().join("allowed");
        let candidate = allowed.join("repo/target");
        fs::create_dir_all(&candidate)?;
        let config = config(&allowed.canonicalize()?);
        let request = OwnershipRequest::new(9, &[candidate.canonicalize()?]);
        assert_eq!(
            validated_request_roots(&request, &config)?,
            [candidate.canonicalize()?]
        );

        let outside = temp.path().join("outside");
        fs::create_dir(&outside)?;
        let request = OwnershipRequest::new(10, &[outside.canonicalize()?]);
        assert!(validated_request_roots(&request, &config).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn request_rejects_aliases_even_when_they_resolve_inside_allowlist() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new()?;
        let allowed = temp.path().join("allowed");
        let candidate = allowed.join("repo/target");
        fs::create_dir_all(&candidate)?;
        let alias = temp.path().join("alias");
        symlink(&candidate, &alias)?;
        let request = OwnershipRequest::new(11, &[alias]);
        assert!(validated_request_roots(&request, &config(&allowed.canonicalize()?)).is_err());
        Ok(())
    }

    #[test]
    fn client_rejects_observations_outside_the_matched_root() -> Result<()> {
        let root = PathBuf::from("/tmp/candidate");
        let request = OwnershipRequest::new(12, std::slice::from_ref(&root));
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 12,
            backend: "macos_privileged_libproc".to_string(),
            complete: true,
            error: None,
            observations: vec![OwnershipObservation {
                pid: 1,
                kind: OwnershipPathKind::OpenFile,
                observed_path: WirePath::from_path(Path::new("/tmp/other")),
                matched_root: WirePath::from_path(&root),
            }],
        };
        assert!(validate_response(&request, &response).is_err());
        Ok(())
    }

    #[test]
    fn client_rejects_incomplete_responses_with_observations() {
        let root = PathBuf::from("/tmp/candidate");
        let request = OwnershipRequest::new(13, std::slice::from_ref(&root));
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 13,
            backend: "macos_privileged_libproc".to_string(),
            complete: false,
            error: Some("incomplete".to_string()),
            observations: vec![OwnershipObservation {
                pid: 1,
                kind: OwnershipPathKind::OpenFile,
                observed_path: WirePath::from_path(&root.join("open")),
                matched_root: WirePath::from_path(&root),
            }],
        };
        assert!(validate_response(&request, &response).is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn privileged_capture_returns_only_allowlisted_matches() {
        use crate::macos_open_handles::{Capture, ProcessPathEvidence, ProcessPathKind};

        let roots = vec![PathBuf::from("/allowed/repo/target")];
        let response = privileged_response_from_capture(
            14,
            &roots,
            Capture {
                observations: vec![
                    ProcessPathEvidence {
                        pid: 7,
                        path: roots[0].join("debug/app"),
                        kind: ProcessPathKind::MappedFile,
                    },
                    ProcessPathEvidence {
                        pid: 8,
                        path: PathBuf::from("/outside/secret"),
                        kind: ProcessPathKind::OpenFile,
                    },
                ],
                permission_denied_pids: Vec::new(),
            },
        );
        assert!(response.complete);
        assert_eq!(response.observations.len(), 1);
        assert_eq!(response.observations[0].pid, 7);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn privileged_capture_rejects_any_permission_denial() {
        use crate::macos_open_handles::Capture;

        let response = privileged_response_from_capture(
            15,
            &[PathBuf::from("/allowed")],
            Capture {
                observations: Vec::new(),
                permission_denied_pids: vec![1],
            },
        );
        assert!(!response.complete);
        assert!(response.observations.is_empty());
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("PIDs [1]")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_is_valid_and_has_only_the_evidence_service_command() -> Result<()> {
        let plist = render_launchd_plist(
            Path::new(DEFAULT_HELPER_BINARY),
            Path::new(DEFAULT_HELPER_CONFIG),
        );
        assert!(plist.contains("<string>serve</string>"));
        assert!(!plist.contains("cleanup"));
        assert!(!plist.contains("execute"));
        assert!(!plist.contains("scheduled"));
        let temp = TempDir::new()?;
        let path = temp.path().join("helper.plist");
        fs::write(&path, plist)?;
        let status = Command::new("/usr/bin/plutil")
            .args(["-lint", "--"])
            .arg(path)
            .status()?;
        assert!(status.success());
        Ok(())
    }
}
