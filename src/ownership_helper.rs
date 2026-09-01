#[cfg(any(unix, test))]
use crate::ownership_protocol::{
    read_message, write_message, OwnershipRequest, OwnershipServiceMetadata, MAX_REQUEST_ROOTS,
    PRIVILEGED_OWNERSHIP_BACKEND,
};
#[cfg(any(target_os = "macos", test))]
use crate::ownership_protocol::{OwnershipObservation, OwnershipPathKind};
use crate::ownership_protocol::{OwnershipResponse, WirePath, OWNERSHIP_PROTOCOL_VERSION};
use anyhow::{bail, Result};
#[cfg(any(unix, test))]
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
#[cfg(any(target_os = "macos", test))]
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "macos", test))]
use std::fs;
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::sync::OnceLock;
#[cfg(unix)]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const HELPER_LABEL: &str = "com.wycats.worktree-gc.ownership-helper";
pub const DEFAULT_HELPER_BINARY: &str =
    "/Library/PrivilegedHelperTools/com.wycats.worktree-gc.ownership-helper";
pub const DEFAULT_HELPER_CONFIG: &str =
    "/Library/Application Support/worktree-gc/ownership-helper.toml";
pub const DEFAULT_HELPER_PLIST: &str =
    "/Library/LaunchDaemons/com.wycats.worktree-gc.ownership-helper.plist";
pub const DEFAULT_HELPER_SOCKET: &str =
    "/Library/Application Support/worktree-gc/run/ownership.sock";
pub const DEFAULT_HELPER_STARTUP_ERROR: &str =
    "/Library/Application Support/worktree-gc/last-startup-error";
#[cfg(any(target_os = "macos", test))]
const HELPER_CONFIG_VERSION: u64 = 1;
#[cfg(any(target_os = "macos", test))]
const MAX_STARTUP_ERROR_BYTES: usize = 4096;
#[cfg(any(target_os = "macos", test))]
const RUNTIME_DIRECTORY_MODE: u32 = 0o755;
#[cfg(unix)]
const HELPER_IO_TIMEOUT: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "macos", test))]
pub const MAX_MATCHED_OBSERVATIONS: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperConfig {
    pub config_version: u64,
    pub allowed_uid: u32,
    pub allowed_gid: u32,
    pub roots: Vec<WirePath>,
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
    pub helper_build_sha256: Option<String>,
    pub client_uid: Option<u32>,
    pub roots: Vec<WirePath>,
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
    #[cfg(target_os = "macos")]
    validate_helper_server(socket, &stream)?;
    stream.set_read_timeout(Some(HELPER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_IO_TIMEOUT))?;
    write_message(&mut stream, &request)?;
    let response: OwnershipResponse = read_message(&mut stream)?;
    validate_response(&request, &response)?;
    Ok(response)
}

#[cfg(target_os = "macos")]
fn validate_helper_server(socket: &Path, stream: &UnixStream) -> Result<()> {
    let metadata = fs::symlink_metadata(socket)
        .with_context(|| format!("failed to inspect helper socket {}", socket.display()))?;
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == 0,
        "ownership helper socket {} is not a root-owned socket",
        socket.display()
    );
    ensure_root_owned_directory_chain(
        socket
            .parent()
            .context("ownership helper socket has no parent directory")?,
    )?;
    ensure!(
        peer_uid(stream)? == 0,
        "ownership helper peer is not running as root"
    );
    Ok(())
}

#[cfg(not(unix))]
pub fn capture_from_helper(_socket: &Path, _roots: &[PathBuf]) -> Result<OwnershipResponse> {
    bail!("the privileged ownership helper requires Unix")
}

#[cfg(target_os = "macos")]
pub fn serve(config_path: &Path, socket_path: &Path) -> Result<()> {
    let startup = prepare_listener(config_path, socket_path);
    let (listener, config) = match startup {
        Ok(ready) => ready,
        Err(error) => return Err(record_startup_failure(config_path, error)),
    };

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

#[cfg(target_os = "macos")]
fn prepare_listener(
    config_path: &Path,
    socket_path: &Path,
) -> Result<(UnixListener, HelperConfig)> {
    ensure_root()?;
    let config = load_root_owned_config(config_path)?;
    let socket_parent = socket_path
        .parent()
        .context("ownership helper socket has no parent directory")?;
    recover_socket_parent(socket_parent)?;
    remove_stale_socket(socket_path)?;
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o660))?;
    chown(socket_path, 0, config.allowed_gid)?;
    validate_ready_socket(socket_path, config.allowed_gid)?;
    clear_startup_error(&startup_error_path(config_path)?)?;
    Ok((listener, config))
}

#[cfg(not(target_os = "macos"))]
pub fn serve(_config_path: &Path, _socket_path: &Path) -> Result<()> {
    bail!("the privileged ownership helper service requires macOS")
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedPathKind {
    Directory,
    RegularFile,
    Socket,
    Symlink,
    Other,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManagedPathMetadata {
    kind: ManagedPathKind,
    uid: u32,
    gid: u32,
    mode: u32,
    len: u64,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeLeafAction {
    Create,
    Reuse,
}

#[cfg(any(target_os = "macos", test))]
fn runtime_leaf_action(
    path: &Path,
    metadata: Option<ManagedPathMetadata>,
) -> Result<RuntimeLeafAction> {
    let Some(metadata) = metadata else {
        return Ok(RuntimeLeafAction::Create);
    };
    ensure!(
        metadata.kind == ManagedPathKind::Directory,
        "{} is not a real directory",
        path.display()
    );
    ensure!(metadata.uid == 0, "{} is not owned by root", path.display());
    ensure!(
        metadata.mode == RUNTIME_DIRECTORY_MODE,
        "{} has mode {:o}, expected 755",
        path.display(),
        metadata.mode
    );
    ensure!(
        metadata.mode & 0o022 == 0,
        "{} is group- or world-writable",
        path.display()
    );
    Ok(RuntimeLeafAction::Reuse)
}

#[cfg(any(target_os = "macos", test))]
fn normalized_runtime_leaf_mode(path: &Path, metadata: ManagedPathMetadata) -> Result<u32> {
    ensure!(
        metadata.kind == ManagedPathKind::Directory,
        "new ownership helper runtime path {} is not a real directory",
        path.display()
    );
    ensure!(
        metadata.uid == 0,
        "new ownership helper runtime directory {} is not owned by root",
        path.display()
    );
    ensure!(
        metadata.mode & !RUNTIME_DIRECTORY_MODE == 0,
        "new ownership helper runtime directory {} has mode {:o}, broader than requested {:o}",
        path.display(),
        metadata.mode,
        RUNTIME_DIRECTORY_MODE
    );
    Ok(RUNTIME_DIRECTORY_MODE)
}

#[cfg(any(target_os = "macos", test))]
fn canonical_runtime_leaf_spelling(
    runtime_leaf: &Path,
    durable_parent: &Path,
    canonical_durable_parent: &Path,
) -> Result<()> {
    ensure!(
        durable_parent.as_os_str() == canonical_durable_parent.as_os_str(),
        "ownership helper durable parent {} is not canonically spelled (resolved to {})",
        durable_parent.display(),
        canonical_durable_parent.display()
    );
    let leaf_name = runtime_leaf
        .file_name()
        .context("ownership helper runtime directory has no leaf name")?;
    let canonical_runtime_leaf = canonical_durable_parent.join(leaf_name);
    ensure!(
        runtime_leaf.as_os_str() == canonical_runtime_leaf.as_os_str(),
        "ownership helper runtime directory {} is not a canonical one-leaf child of {}",
        runtime_leaf.display(),
        canonical_durable_parent.display()
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn stale_socket_is_removable(path: &Path, metadata: ManagedPathMetadata) -> Result<()> {
    ensure!(
        metadata.kind == ManagedPathKind::Socket && metadata.uid == 0,
        "refusing to replace non-helper socket path {}",
        path.display()
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn ready_socket_is_valid(
    path: &Path,
    metadata: ManagedPathMetadata,
    allowed_gid: u32,
) -> Result<()> {
    ensure!(
        metadata.kind == ManagedPathKind::Socket
            && metadata.uid == 0
            && metadata.gid == allowed_gid
            && metadata.mode == 0o660,
        "ownership helper socket {} has unexpected identity or permissions",
        path.display()
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn startup_error_file_is_valid(path: &Path, metadata: ManagedPathMetadata) -> Result<()> {
    ensure!(
        metadata.kind == ManagedPathKind::RegularFile
            && metadata.uid == 0
            && metadata.gid == 0
            && metadata.mode == 0o644
            && metadata.len <= MAX_STARTUP_ERROR_BYTES as u64,
        "ownership helper startup error record {} has unexpected identity, permissions, or size",
        path.display()
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn sanitize_startup_error(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len().min(MAX_STARTUP_ERROR_BYTES));
    for character in value.chars() {
        let character = if character.is_control() || character.is_whitespace() {
            ' '
        } else {
            character
        };
        if sanitized.len() + character.len_utf8() + 1 > MAX_STARTUP_ERROR_BYTES {
            break;
        }
        sanitized.push(character);
    }
    let sanitized = sanitized.trim();
    let sanitized = if sanitized.is_empty() {
        "ownership helper startup failed"
    } else {
        sanitized
    };
    format!("{sanitized}\n")
}

#[cfg(target_os = "macos")]
fn optional_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    optional_metadata_result(path, fs::symlink_metadata(path))
}

#[cfg(any(target_os = "macos", test))]
fn optional_metadata_result<T>(path: &Path, result: std::io::Result<T>) -> Result<Option<T>> {
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", path.display())),
    }
}

#[cfg(target_os = "macos")]
fn managed_metadata(metadata: &fs::Metadata) -> ManagedPathMetadata {
    let file_type = metadata.file_type();
    let kind = if file_type.is_symlink() {
        ManagedPathKind::Symlink
    } else if file_type.is_dir() {
        ManagedPathKind::Directory
    } else if file_type.is_file() {
        ManagedPathKind::RegularFile
    } else if file_type.is_socket() {
        ManagedPathKind::Socket
    } else {
        ManagedPathKind::Other
    };
    ManagedPathMetadata {
        kind,
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o777,
        len: metadata.len(),
    }
}

#[cfg(target_os = "macos")]
fn recover_socket_parent(socket_parent: &Path) -> Result<()> {
    let ancestor = socket_parent
        .parent()
        .context("ownership helper socket parent has no parent directory")?;
    let canonical_ancestor = ancestor.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize ownership helper durable parent {}",
            ancestor.display()
        )
    })?;
    canonical_runtime_leaf_spelling(socket_parent, ancestor, &canonical_ancestor)?;
    ensure_root_owned_directory_chain(ancestor)?;
    match runtime_leaf_action(
        socket_parent,
        optional_metadata(socket_parent)?
            .as_ref()
            .map(managed_metadata),
    )? {
        RuntimeLeafAction::Create => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(RUNTIME_DIRECTORY_MODE);
            builder.create(socket_parent).with_context(|| {
                format!(
                    "failed to create ownership helper runtime directory {} with mode {:o}",
                    socket_parent.display(),
                    RUNTIME_DIRECTORY_MODE
                )
            })?;
            let created = fs::symlink_metadata(socket_parent)
                .with_context(|| format!("failed to inspect {}", socket_parent.display()))?;
            let final_mode =
                normalized_runtime_leaf_mode(socket_parent, managed_metadata(&created))?;
            fs::set_permissions(socket_parent, fs::Permissions::from_mode(final_mode))?;
            chown(socket_parent, 0, 0)?;
        }
        RuntimeLeafAction::Reuse => {}
    }
    let metadata = fs::symlink_metadata(socket_parent)
        .with_context(|| format!("failed to inspect {}", socket_parent.display()))?;
    runtime_leaf_action(socket_parent, Some(managed_metadata(&metadata)))?;
    ensure_root_owned_directory_chain(socket_parent)
}

#[cfg(target_os = "macos")]
fn remove_stale_socket(socket_path: &Path) -> Result<()> {
    let Some(metadata) = optional_metadata(socket_path)? else {
        return Ok(());
    };
    stale_socket_is_removable(socket_path, managed_metadata(&metadata))?;
    fs::remove_file(socket_path)
        .with_context(|| format!("failed to remove stale socket {}", socket_path.display()))
}

#[cfg(target_os = "macos")]
fn validate_ready_socket(socket_path: &Path, allowed_gid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(socket_path)
        .with_context(|| format!("failed to inspect helper socket {}", socket_path.display()))?;
    ready_socket_is_valid(socket_path, managed_metadata(&metadata), allowed_gid)?;
    ensure_root_owned_directory_chain(
        socket_path
            .parent()
            .context("ownership helper socket has no parent directory")?,
    )
}

#[cfg(target_os = "macos")]
fn startup_error_path(config_path: &Path) -> Result<PathBuf> {
    Ok(config_path
        .parent()
        .context("ownership helper config has no parent")?
        .join("last-startup-error"))
}

#[cfg(target_os = "macos")]
fn record_startup_failure(config_path: &Path, error: anyhow::Error) -> anyhow::Error {
    let message = sanitize_startup_error(&format!("{error:#}"));
    startup_failure_with_recording(error, || {
        let path = startup_error_path(config_path)?;
        write_startup_error(&path, &message)
    })
}

#[cfg(any(target_os = "macos", test))]
fn startup_failure_with_recording(
    error: anyhow::Error,
    record: impl FnOnce() -> Result<()>,
) -> anyhow::Error {
    match record() {
        Ok(()) => error,
        Err(record_error) => error.context(format!(
            "failed to record ownership helper startup error: {record_error:#}"
        )),
    }
}

#[cfg(target_os = "macos")]
fn write_startup_error(path: &Path, message: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("ownership helper startup error path has no parent")?;
    ensure_root_owned_directory_chain(parent)?;
    if let Some(metadata) = optional_metadata(path)? {
        startup_error_file_is_valid(path, managed_metadata(&metadata))?;
        let existing = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        ensure!(
            sanitize_startup_error(existing.trim_end()) == existing,
            "ownership helper startup error record {} is not sanitized",
            path.display()
        );
    }
    let message = sanitize_startup_error(message.trim_end());
    atomic_write(path, message.as_bytes(), 0o644)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    startup_error_file_is_valid(path, managed_metadata(&metadata))?;
    ensure!(
        fs::read(path)? == message.as_bytes(),
        "ownership helper startup error record changed during publication"
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_startup_error(path: &Path) -> Result<Option<String>> {
    let Some(metadata) = optional_metadata(path)? else {
        return Ok(None);
    };
    startup_error_file_is_valid(path, managed_metadata(&metadata))?;
    let evidence =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    ensure!(
        sanitize_startup_error(evidence.trim_end()) == evidence,
        "ownership helper startup error record {} is not sanitized",
        path.display()
    );
    Ok(Some(evidence.trim_end().to_string()))
}

#[cfg(target_os = "macos")]
fn clear_startup_error(path: &Path) -> Result<()> {
    let Some(metadata) = optional_metadata(path)? else {
        return Ok(());
    };
    startup_error_file_is_valid(path, managed_metadata(&metadata))?;
    fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))
}

#[cfg(target_os = "macos")]
fn handle_connection(stream: &mut UnixStream, config: &HelperConfig) -> Result<()> {
    stream.set_read_timeout(Some(HELPER_IO_TIMEOUT))?;
    stream.set_write_timeout(Some(HELPER_IO_TIMEOUT))?;
    let peer_uid = peer_uid(stream)?;
    if !peer_is_authorized(peer_uid, config.allowed_uid) {
        return Ok(());
    }
    let request: OwnershipRequest = read_message(stream)?;
    let helper_build_sha256 = current_helper_build_sha256()?;
    let response = match validated_request_roots(&request, config) {
        Ok(roots) if roots.is_empty() => OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: request.request_id,
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: Some(helper_build_sha256),
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: config.allowed_uid,
                roots: config.roots.clone(),
            }),
        },
        Ok(roots) => capture_privileged_ownership(request.request_id, &roots, helper_build_sha256),
        Err(error) => OwnershipResponse::refusal(request.request_id, format!("{error:#}")),
    };
    write_message(stream, &response)
}

#[cfg(target_os = "macos")]
fn current_helper_build_sha256() -> Result<String> {
    static HELPER_BUILD_SHA256: OnceLock<std::result::Result<String, String>> = OnceLock::new();
    HELPER_BUILD_SHA256
        .get_or_init(|| {
            let executable = std::env::current_exe()
                .map_err(|error| format!("failed to resolve helper executable: {error}"))?;
            let mut file = fs::File::open(&executable).map_err(|error| {
                format!(
                    "failed to open helper executable {}: {error}",
                    executable.display()
                )
            })?;
            let mut digest = Sha256::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    format!(
                        "failed to hash helper executable {}: {error}",
                        executable.display()
                    )
                })?;
                if read == 0 {
                    break;
                }
                digest.update(&buffer[..read]);
            }
            Ok(format!("{:x}", digest.finalize()))
        })
        .clone()
        .map_err(anyhow::Error::msg)
}

#[cfg(any(target_os = "macos", test))]
fn peer_is_authorized(peer_uid: u32, allowed_uid: u32) -> bool {
    peer_uid == allowed_uid
}

#[cfg(target_os = "macos")]
fn capture_privileged_ownership(
    request_id: u64,
    roots: &[PathBuf],
    helper_build_sha256: String,
) -> OwnershipResponse {
    let capture = crate::capture_global_lsof_raw(None);
    privileged_response_from_capture(request_id, roots, capture, helper_build_sha256)
}

#[cfg(any(target_os = "macos", test))]
fn privileged_response_from_capture(
    request_id: u64,
    roots: &[PathBuf],
    capture: crate::RawOwnershipCapture,
    helper_build_sha256: String,
) -> OwnershipResponse {
    if !capture.complete {
        return OwnershipResponse::refusal(
            request_id,
            format!(
                "privileged global lsof capture was incomplete: {}",
                capture.error.as_deref().unwrap_or("unknown error")
            ),
        );
    }
    if capture.backend != "lsof_global" {
        return OwnershipResponse::refusal(
            request_id,
            format!(
                "privileged ownership capture returned unexpected backend {:?}",
                capture.backend
            ),
        );
    }
    let root_indices = roots
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, root)| (root, index))
        .collect::<HashMap<_, _>>();
    let mut observations = Vec::new();
    for observation in capture.observations {
        for root_index in matching_root_indices(&observation.observed_path, &root_indices) {
            let root = &roots[root_index];
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
                kind: match observation.evidence_kind {
                    crate::ProcessOwnershipEvidenceKind::ProcessCwd => OwnershipPathKind::Cwd,
                    crate::ProcessOwnershipEvidenceKind::ProcessRoot => OwnershipPathKind::Root,
                    crate::ProcessOwnershipEvidenceKind::MappedFile => {
                        OwnershipPathKind::MappedFile
                    }
                    crate::ProcessOwnershipEvidenceKind::OpenFile
                    | crate::ProcessOwnershipEvidenceKind::LsofPath => OwnershipPathKind::OpenFile,
                    crate::ProcessOwnershipEvidenceKind::TestOverride => {
                        return OwnershipResponse::refusal(
                            request_id,
                            "privileged ownership capture returned test-only evidence",
                        );
                    }
                },
                observed_path: WirePath::from_path(&observation.observed_path),
                matched_root: WirePath::from_path(root),
            });
        }
    }
    OwnershipResponse {
        protocol_version: OWNERSHIP_PROTOCOL_VERSION,
        request_id,
        backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
        helper_build_sha256: Some(helper_build_sha256),
        complete: true,
        error: None,
        observations,
        service: None,
    }
}

#[cfg(any(target_os = "macos", test))]
fn matching_root_indices(path: &Path, root_indices: &HashMap<PathBuf, usize>) -> Vec<usize> {
    let mut matches = path
        .ancestors()
        .filter_map(|ancestor| root_indices.get(ancestor).copied())
        .collect::<Vec<_>>();
    matches.sort_unstable();
    matches
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
    for wire_root in &config.roots {
        let root = wire_root.to_path_buf()?;
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
            canonical == root,
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

#[cfg(unix)]
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
    ensure!(
        response.backend == PRIVILEGED_OWNERSHIP_BACKEND,
        "ownership helper returned unexpected backend {:?}",
        response.backend
    );
    if !response.complete {
        ensure!(
            response.observations.is_empty(),
            "incomplete ownership helper response included observations"
        );
        ensure!(
            response.service.is_none(),
            "incomplete ownership helper response included service metadata"
        );
        ensure!(
            response.helper_build_sha256.is_none(),
            "incomplete ownership helper response included a build hash"
        );
        return Ok(());
    }
    ensure!(
        response.error.is_none(),
        "complete ownership helper response included an error"
    );
    ensure!(
        response
            .helper_build_sha256
            .as_deref()
            .is_some_and(is_lower_hex_sha256),
        "complete ownership helper response omitted a valid build hash"
    );
    if request.roots.is_empty() {
        ensure!(
            response.observations.is_empty(),
            "ownership helper status response included observations"
        );
        service_metadata_paths(
            response
                .service
                .as_ref()
                .context("ownership helper status response omitted service metadata")?,
        )?;
        return Ok(());
    }
    ensure!(
        response.service.is_none(),
        "ownership helper evidence response included service metadata"
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

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(unix)]
fn service_metadata_paths(metadata: &OwnershipServiceMetadata) -> Result<Vec<PathBuf>> {
    ensure!(
        metadata.client_uid != 0,
        "ownership helper status returned root as its configured client"
    );
    ensure!(
        !metadata.roots.is_empty(),
        "ownership helper status returned an empty root allowlist"
    );
    let mut roots = metadata
        .roots
        .iter()
        .map(WirePath::to_path_buf)
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        roots.iter().all(|root| root.is_absolute()),
        "ownership helper status returned a non-absolute root"
    );
    roots.sort();
    roots.dedup();
    ensure!(
        roots.len() == metadata.roots.len(),
        "ownership helper status returned duplicate roots"
    );
    Ok(roots)
}

#[cfg(target_os = "macos")]
pub fn install(options: HelperInstallOptions) -> Result<()> {
    ensure_root()?;
    validate_client_group_membership(options.client_uid, options.client_gid)?;
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
    let canonical_roots = canonical_install_roots(&options.roots)?;
    let config = HelperConfig {
        config_version: HELPER_CONFIG_VERSION,
        allowed_uid: options.client_uid,
        allowed_gid: options.client_gid,
        roots: canonical_roots
            .iter()
            .map(|root| WirePath::from_path(root))
            .collect(),
    };

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
    let was_loaded = service_loaded()?;
    if was_loaded {
        bootout_service()?;
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
        wait_for_service_socket(
            helper_binary,
            Path::new(DEFAULT_HELPER_SOCKET),
            config.allowed_uid,
            config.allowed_gid,
            &canonical_roots,
        )
    })();
    if let Err(error) = result {
        let rollback = (|| {
            if service_loaded()? {
                bootout_service()?;
            }
            remove_helper_socket_if_present()?;
            restore_installation(&backup)?;
            if was_loaded {
                bootstrap_service(helper_plist)?;
            }
            discard_installation_backup(&backup)?;
            Ok::<(), anyhow::Error>(())
        })();
        if let Err(rollback_error) = rollback {
            return Err(error).context(format!(
                "ownership helper installation also failed to roll back: {rollback_error:#}"
            ));
        }
        return Err(error);
    }
    discard_installation_backup(&backup)?;
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn canonical_install_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut canonical = roots
        .iter()
        .map(|root| root.canonicalize())
        .collect::<std::io::Result<Vec<_>>>()?;
    canonical.sort();
    canonical.dedup();
    ensure!(
        !canonical.is_empty(),
        "ownership helper requires at least one allowed root"
    );
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn validate_client_group_membership(client_uid: u32, client_gid: u32) -> Result<()> {
    ensure!(
        client_uid != 0,
        "ownership helper client uid must not be root"
    );
    let output = Command::new("/usr/bin/id")
        .arg("-G")
        .arg(client_uid.to_string())
        .stdin(Stdio::null())
        .output()
        .context("failed to inspect ownership helper client groups")?;
    ensure!(
        output.status.success(),
        "failed to inspect groups for client uid {client_uid}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let groups = parse_client_groups(&output.stdout)?;
    ensure!(
        groups.contains(&client_gid),
        "configured gid {client_gid} does not belong to client uid {client_uid}"
    );
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn parse_client_groups(stdout: &[u8]) -> Result<Vec<u32>> {
    let stdout = std::str::from_utf8(stdout).context("id -G returned non-UTF-8 output")?;
    let groups = stdout
        .split_ascii_whitespace()
        .map(|group| {
            group
                .parse::<u32>()
                .with_context(|| format!("id -G returned invalid group id {group:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!groups.is_empty(), "id -G returned no groups");
    Ok(groups)
}

#[cfg(not(target_os = "macos"))]
pub fn install(_options: HelperInstallOptions) -> Result<()> {
    bail!("the privileged ownership helper requires macOS")
}

#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    ensure_root()?;
    if service_loaded()? {
        bootout_service()?;
    }
    remove_helper_socket_if_present()?;
    clear_startup_error(Path::new(DEFAULT_HELPER_STARTUP_ERROR))?;
    for path in [
        Path::new(DEFAULT_HELPER_PLIST),
        Path::new(DEFAULT_HELPER_CONFIG),
        Path::new(DEFAULT_HELPER_BINARY),
    ] {
        let Some(metadata) = optional_metadata(path)? else {
            continue;
        };
        ensure!(
            metadata.uid() == 0
                && metadata.file_type().is_file()
                && !metadata.file_type().is_symlink(),
            "refusing to remove unexpected helper path {}",
            path.display()
        );
        fs::remove_file(path)?;
    }
    remove_all_installation_backups()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_helper_socket_if_present() -> Result<()> {
    let socket = Path::new(DEFAULT_HELPER_SOCKET);
    let Some(metadata) = optional_metadata(socket)? else {
        return Ok(());
    };
    stale_socket_is_removable(socket, managed_metadata(&metadata))?;
    fs::remove_file(socket)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<()> {
    bail!("the privileged ownership helper requires macOS")
}

#[cfg(target_os = "macos")]
pub fn status() -> HelperStatus {
    let installed = Path::new(DEFAULT_HELPER_BINARY).exists()
        && Path::new(DEFAULT_HELPER_CONFIG).exists()
        && Path::new(DEFAULT_HELPER_PLIST).exists();
    let loaded = match service_loaded() {
        Ok(loaded) => loaded,
        Err(error) => {
            return HelperStatus {
                installed,
                loaded: false,
                protocol_version: OWNERSHIP_PROTOCOL_VERSION,
                helper_build_sha256: None,
                client_uid: None,
                roots: Vec::new(),
                socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
                probe_complete: false,
                error: Some(status_error_with_startup_evidence(&error)),
            };
        }
    };
    let probe = capture_from_helper(Path::new(DEFAULT_HELPER_SOCKET), &[]);
    match probe.and_then(|response| status_from_response(installed, loaded, response)) {
        Ok(status) => status,
        Err(error) => HelperStatus {
            installed,
            loaded,
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            helper_build_sha256: None,
            client_uid: None,
            roots: Vec::new(),
            socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
            probe_complete: false,
            error: Some(status_error_with_startup_evidence(&error)),
        },
    }
}

#[cfg(target_os = "macos")]
fn status_error_with_startup_evidence(error: &anyhow::Error) -> String {
    let error = sanitize_startup_error(&format!("{error:#}"));
    match read_startup_error(Path::new(DEFAULT_HELPER_STARTUP_ERROR)) {
        Ok(Some(startup)) => format!("{}; last startup error: {startup}", error.trim_end()),
        Ok(None) => error.trim_end().to_string(),
        Err(evidence_error) => format!(
            "{}; startup error evidence unavailable: {}",
            error.trim_end(),
            sanitize_startup_error(&format!("{evidence_error:#}")).trim_end()
        ),
    }
}

#[cfg(any(target_os = "macos", test))]
fn status_from_response(
    installed: bool,
    loaded: bool,
    response: OwnershipResponse,
) -> Result<HelperStatus> {
    ensure!(
        response
            .helper_build_sha256
            .as_deref()
            .is_some_and(is_lower_hex_sha256),
        "ownership helper status omitted a valid build hash"
    );
    let metadata = response
        .service
        .as_ref()
        .context("ownership helper status omitted service metadata")?;
    service_metadata_paths(metadata)?;
    Ok(HelperStatus {
        installed,
        loaded,
        protocol_version: response.protocol_version,
        helper_build_sha256: response.helper_build_sha256,
        client_uid: Some(metadata.client_uid),
        roots: metadata.roots.clone(),
        socket: PathBuf::from(DEFAULT_HELPER_SOCKET),
        probe_complete: response.complete,
        error: response.error,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn status() -> HelperStatus {
    HelperStatus {
        installed: false,
        loaded: false,
        protocol_version: OWNERSHIP_PROTOCOL_VERSION,
        helper_build_sha256: None,
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
    let backup_root = installation_backup_root()?;
    fs::create_dir_all(&backup_root)?;
    fs::set_permissions(&backup_root, fs::Permissions::from_mode(0o700))?;
    chown(&backup_root, 0, 0)?;
    ensure_root_owned_directory_chain(&backup_root)?;
    let directory = backup_root.join(format!("{timestamp}-{}", std::process::id()));
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
fn installation_backup_root() -> Result<PathBuf> {
    Ok(Path::new(DEFAULT_HELPER_CONFIG)
        .parent()
        .context("helper config path has no parent")?
        .join("backups"))
}

#[cfg(target_os = "macos")]
fn discard_installation_backup(backup: &InstallationBackup) -> Result<()> {
    let backup_root = installation_backup_root()?;
    ensure!(
        backup.directory.parent() == Some(backup_root.as_path()),
        "refusing to remove backup outside {}",
        backup_root.display()
    );
    validate_backup_directory(&backup.directory)?;
    fs::remove_dir_all(&backup.directory)?;
    if backup_root
        .read_dir()
        .with_context(|| format!("failed to inspect {}", backup_root.display()))?
        .next()
        .is_none()
    {
        fs::remove_dir(&backup_root)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_all_installation_backups() -> Result<()> {
    let backup_root = installation_backup_root()?;
    let metadata = match fs::symlink_metadata(&backup_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "refusing to remove unexpected helper backup root {}",
        backup_root.display()
    );
    for entry in backup_root.read_dir()? {
        validate_backup_directory(&entry?.path())?;
    }
    fs::remove_dir_all(&backup_root)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn validate_backup_directory(directory: &Path) -> Result<()> {
    let backup_root = installation_backup_root()?;
    ensure!(
        directory.parent() == Some(backup_root.as_path())
            && directory
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(is_backup_directory_name),
        "unexpected helper backup directory {}",
        directory.display()
    );
    let metadata = fs::symlink_metadata(directory)?;
    ensure!(
        metadata.file_type().is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "refusing to remove unexpected helper backup directory {}",
        directory.display()
    );
    let expected_names = [
        Path::new(DEFAULT_HELPER_BINARY).file_name(),
        Path::new(DEFAULT_HELPER_CONFIG).file_name(),
        Path::new(DEFAULT_HELPER_PLIST).file_name(),
    ];
    for entry in directory.read_dir()? {
        let entry = entry?;
        let entry_name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            expected_names
                .iter()
                .flatten()
                .any(|expected| *expected == entry_name.as_os_str())
                && metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0,
            "refusing to remove unexpected helper backup entry {}",
            entry.path().display()
        );
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn is_backup_directory_name(name: &str) -> bool {
    let Some((timestamp, pid)) = name.split_once('-') else {
        return false;
    };
    !timestamp.is_empty()
        && !pid.is_empty()
        && timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && pid.bytes().all(|byte| byte.is_ascii_digit())
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
  <string>/dev/null</string>
  <key>StandardErrorPath</key>
  <string>/dev/null</string>
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
fn bootout_service() -> Result<()> {
    let output = Command::new("/bin/launchctl")
        .args(["bootout", &format!("system/{HELPER_LABEL}")])
        .stdin(Stdio::null())
        .output()?;
    ensure!(
        output.status.success(),
        "launchctl bootout failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
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
fn wait_for_service_socket(
    helper_binary: &Path,
    socket: &Path,
    client_uid: u32,
    client_gid: u32,
    expected_roots: &[PathBuf],
) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut last_probe_error = None;
    loop {
        if let Ok(metadata) = fs::symlink_metadata(socket) {
            if helper_socket_is_ready(
                metadata.file_type().is_socket(),
                metadata.uid(),
                metadata.mode() & 0o777,
            )? {
                match probe_service_as_client(
                    helper_binary,
                    socket,
                    client_uid,
                    client_gid,
                    expected_roots,
                ) {
                    Ok(response) => {
                        ensure!(
                            response.complete,
                            "ownership helper readiness probe was incomplete: {}",
                            response.error.as_deref().unwrap_or("unspecified error")
                        );
                        return Ok(());
                    }
                    Err(error) => last_probe_error = Some(error),
                }
            } else {
                last_probe_error = Some(anyhow::anyhow!(
                    "ownership helper socket {} has transient mode {:o}, expected 660",
                    socket.display(),
                    metadata.mode() & 0o777
                ));
            }
        }
        if std::time::Instant::now() >= deadline {
            let mut error = anyhow::anyhow!(
                "ownership helper did not become ready at {} within 5 seconds",
                socket.display()
            );
            if let Some(last_probe_error) = last_probe_error {
                error = error.context(format!("last readiness probe: {last_probe_error:#}"));
            }
            return Err(error);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(any(target_os = "macos", test))]
fn helper_socket_is_ready(is_socket: bool, uid: u32, mode: u32) -> Result<bool> {
    ensure!(
        is_socket && uid == 0,
        "ownership helper created an unexpected socket"
    );
    Ok(mode == 0o660)
}

#[cfg(target_os = "macos")]
fn probe_service_as_client(
    helper_binary: &Path,
    socket: &Path,
    client_uid: u32,
    client_gid: u32,
    expected_roots: &[PathBuf],
) -> Result<OwnershipResponse> {
    let mut command = Command::new(helper_binary);
    command
        .arg("probe")
        .arg("--socket")
        .arg(socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_client_identity(&mut command, client_uid, client_gid);
    let output = command
        .output()
        .context("failed to run ownership helper readiness probe as the configured client")?;
    ensure!(
        output.status.success(),
        "ownership helper readiness probe failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let response: OwnershipResponse = serde_json::from_slice(&output.stdout)
        .context("ownership helper readiness probe returned invalid JSON")?;
    ensure!(
        response.protocol_version == OWNERSHIP_PROTOCOL_VERSION,
        "ownership helper readiness probe returned protocol version {}",
        response.protocol_version
    );
    ensure!(
        response.complete,
        "ownership helper readiness probe was incomplete: {}",
        response.error.as_deref().unwrap_or("unspecified error")
    );
    let metadata = response
        .service
        .as_ref()
        .context("ownership helper readiness probe omitted service metadata")?;
    ensure!(
        metadata.client_uid == client_uid,
        "ownership helper readiness probe returned client uid {}, expected {client_uid}",
        metadata.client_uid
    );
    ensure!(
        service_metadata_paths(metadata)? == expected_roots,
        "ownership helper readiness probe returned a different root allowlist"
    );
    Ok(response)
}

#[cfg(target_os = "macos")]
fn configure_client_identity(command: &mut Command, client_uid: u32, client_gid: u32) {
    // macOS setgid(2) can leave the effective GID unchanged, and CommandExt::uid
    // clears supplementary groups. Drop every credential explicitly so the
    // readiness child can authenticate as the configured client and access the
    // root:group 0660 helper socket without retaining root authority.
    unsafe {
        command.pre_exec(move || drop_client_credentials(client_uid, client_gid));
    }
}

#[cfg(target_os = "macos")]
fn drop_client_credentials(client_uid: u32, client_gid: u32) -> std::io::Result<()> {
    drop_client_credentials_with(
        client_uid,
        client_gid,
        |groups| {
            let result = unsafe {
                libc::setgroups(
                    groups.len().try_into().expect("one group fits in c_int"),
                    groups.as_ptr(),
                )
            };
            cvt_identity_call(result)
        },
        |real, effective| cvt_identity_call(unsafe { libc::setregid(real, effective) }),
        |real, effective| cvt_identity_call(unsafe { libc::setreuid(real, effective) }),
    )
}

#[cfg(any(target_os = "macos", test))]
fn drop_client_credentials_with(
    client_uid: u32,
    client_gid: u32,
    set_groups: impl FnOnce(&[u32]) -> std::io::Result<()>,
    set_gids: impl FnOnce(u32, u32) -> std::io::Result<()>,
    set_uids: impl FnOnce(u32, u32) -> std::io::Result<()>,
) -> std::io::Result<()> {
    set_groups(std::slice::from_ref(&client_gid))?;
    set_gids(client_gid, client_gid)?;
    set_uids(client_uid, client_uid)
}

#[cfg(target_os = "macos")]
fn cvt_identity_call(result: libc::c_int) -> std::io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "macos")]
fn service_loaded() -> Result<bool> {
    let output = Command::new("/bin/launchctl")
        .args(["print", &format!("system/{HELPER_LABEL}")])
        .stdin(Stdio::null())
        .output()
        .context("failed to inspect ownership helper launchd state")?;
    classify_service_state(
        output.status.success(),
        output.status.code(),
        &output.stderr,
    )
}

#[cfg(any(target_os = "macos", test))]
fn classify_service_state(success: bool, code: Option<i32>, stderr: &[u8]) -> Result<bool> {
    if success {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(stderr);
    if code == Some(113)
        && stderr.contains("Could not find service")
        && stderr.contains(HELPER_LABEL)
    {
        return Ok(false);
    }
    bail!(
        "launchctl print failed with status {}: {}",
        code.map_or_else(|| "signal".to_string(), |code| code.to_string()),
        stderr.trim()
    )
}

#[cfg(unix)]
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

    const TEST_HELPER_BUILD_SHA256: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn config(root: &Path) -> HelperConfig {
        HelperConfig {
            config_version: HELPER_CONFIG_VERSION,
            allowed_uid: 501,
            allowed_gid: 20,
            roots: vec![WirePath::from_path(root)],
        }
    }

    #[cfg(unix)]
    #[test]
    fn config_round_trips_non_utf8_allowlist_roots() -> Result<()> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = PathBuf::from(OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()));
        let encoded = toml::to_string_pretty(&config(&root))?;
        let decoded: HelperConfig = toml::from_str(&encoded)?;
        assert_eq!(decoded.roots[0].to_path_buf()?, root);
        Ok(())
    }

    #[test]
    fn configured_client_group_parser_is_strict() -> Result<()> {
        assert_eq!(parse_client_groups(b"20 12 61\n")?, vec![20, 12, 61]);
        assert!(parse_client_groups(b"").is_err());
        assert!(parse_client_groups(b"20 staff").is_err());
        assert!(parse_client_groups(&[0xff]).is_err());
        Ok(())
    }

    #[test]
    fn readiness_child_sets_group_authority_before_dropping_user_identity() -> Result<()> {
        let calls = std::cell::RefCell::new(Vec::new());
        drop_client_credentials_with(
            501,
            20,
            |groups| {
                calls.borrow_mut().push(format!("groups:{groups:?}"));
                Ok(())
            },
            |real, effective| {
                calls.borrow_mut().push(format!("gids:{real}:{effective}"));
                Ok(())
            },
            |real, effective| {
                calls.borrow_mut().push(format!("uids:{real}:{effective}"));
                Ok(())
            },
        )?;

        assert_eq!(
            calls.into_inner(),
            ["groups:[20]", "gids:20:20", "uids:501:501"]
        );
        Ok(())
    }

    #[test]
    fn readiness_retries_a_root_socket_until_owner_only_group_access_is_set() -> Result<()> {
        assert!(!helper_socket_is_ready(true, 0, 0o755)?);
        assert!(helper_socket_is_ready(true, 0, 0o660)?);
        assert!(helper_socket_is_ready(false, 0, 0o660).is_err());
        assert!(helper_socket_is_ready(true, 501, 0o660).is_err());
        Ok(())
    }

    fn managed_path(
        kind: ManagedPathKind,
        uid: u32,
        gid: u32,
        mode: u32,
        len: u64,
    ) -> ManagedPathMetadata {
        ManagedPathMetadata {
            kind,
            uid,
            gid,
            mode,
            len,
        }
    }

    #[test]
    fn runtime_recovery_creates_only_an_absent_leaf() -> Result<()> {
        let path = Path::new("/Library/Application Support/worktree-gc/run");
        assert_eq!(RUNTIME_DIRECTORY_MODE, 0o755);
        assert_eq!(runtime_leaf_action(path, None)?, RuntimeLeafAction::Create);
        assert_eq!(
            runtime_leaf_action(
                path,
                Some(managed_path(ManagedPathKind::Directory, 0, 0, 0o755, 0,)),
            )?,
            RuntimeLeafAction::Reuse
        );
        Ok(())
    }

    #[test]
    fn runtime_creation_and_reuse_share_the_exact_final_mode_policy() -> Result<()> {
        let path = Path::new("/durable/run");
        assert_eq!(RUNTIME_DIRECTORY_MODE, 0o755);
        assert_eq!(
            runtime_leaf_action(
                path,
                Some(managed_path(
                    ManagedPathKind::Directory,
                    0,
                    0,
                    RUNTIME_DIRECTORY_MODE,
                    0,
                )),
            )?,
            RuntimeLeafAction::Reuse
        );
        assert!(runtime_leaf_action(
            path,
            Some(managed_path(
                ManagedPathKind::Directory,
                0,
                0,
                RUNTIME_DIRECTORY_MODE | 0o022,
                0,
            )),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn restrictive_umask_result_is_normalized_to_the_exact_runtime_mode() -> Result<()> {
        let path = Path::new("/durable/run");
        for initial_mode in [0o700, 0o711, 0o750, RUNTIME_DIRECTORY_MODE] {
            assert_eq!(
                normalized_runtime_leaf_mode(
                    path,
                    managed_path(ManagedPathKind::Directory, 0, 0, initial_mode, 0),
                )?,
                RUNTIME_DIRECTORY_MODE
            );
        }
        assert!(normalized_runtime_leaf_mode(
            path,
            managed_path(ManagedPathKind::Directory, 0, 0, 0o775, 0),
        )
        .is_err());
        assert!(normalized_runtime_leaf_mode(
            path,
            managed_path(ManagedPathKind::Symlink, 0, 0, 0o700, 0),
        )
        .is_err());
        assert!(normalized_runtime_leaf_mode(
            path,
            managed_path(ManagedPathKind::Directory, 501, 0, 0o700, 0),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn runtime_recovery_requires_canonical_one_leaf_spelling() -> Result<()> {
        canonical_runtime_leaf_spelling(
            Path::new("/durable/run"),
            Path::new("/durable"),
            Path::new("/durable"),
        )?;
        assert!(canonical_runtime_leaf_spelling(
            Path::new("/durable/./run"),
            Path::new("/durable/."),
            Path::new("/durable"),
        )
        .is_err());
        assert!(canonical_runtime_leaf_spelling(
            Path::new("/durable/nested/../run"),
            Path::new("/durable/nested/.."),
            Path::new("/durable"),
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn runtime_recovery_rejects_aliases_wrong_owners_and_wrong_modes() {
        let path = Path::new("/Library/Application Support/worktree-gc/run");
        for metadata in [
            managed_path(ManagedPathKind::Symlink, 0, 0, 0o755, 0),
            managed_path(ManagedPathKind::RegularFile, 0, 0, 0o755, 0),
            managed_path(ManagedPathKind::Directory, 501, 0, 0o755, 0),
            managed_path(ManagedPathKind::Directory, 0, 0, 0o700, 0),
            managed_path(ManagedPathKind::Directory, 0, 0, 0o775, 0),
        ] {
            assert!(runtime_leaf_action(path, Some(metadata)).is_err());
        }
    }

    #[test]
    fn optional_path_inspection_propagates_every_error_except_not_found() -> Result<()> {
        let path = Path::new("/expected/path");
        assert_eq!(
            optional_metadata_result::<()>(
                path,
                Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            )?,
            None
        );
        let error = optional_metadata_result::<()>(
            path,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("failed to inspect /expected/path"));
        Ok(())
    }

    #[test]
    fn stale_socket_removal_requires_a_root_owned_socket() -> Result<()> {
        let path = Path::new("/runtime/ownership.sock");
        stale_socket_is_removable(path, managed_path(ManagedPathKind::Socket, 0, 20, 0o660, 0))?;
        for metadata in [
            managed_path(ManagedPathKind::Socket, 501, 20, 0o660, 0),
            managed_path(ManagedPathKind::RegularFile, 0, 20, 0o660, 0),
            managed_path(ManagedPathKind::Symlink, 0, 20, 0o660, 0),
        ] {
            assert!(stale_socket_is_removable(path, metadata).is_err());
        }
        Ok(())
    }

    #[test]
    fn ready_socket_requires_exact_identity_and_permissions() -> Result<()> {
        let path = Path::new("/runtime/ownership.sock");
        ready_socket_is_valid(
            path,
            managed_path(ManagedPathKind::Socket, 0, 20, 0o660, 0),
            20,
        )?;
        for metadata in [
            managed_path(ManagedPathKind::Socket, 501, 20, 0o660, 0),
            managed_path(ManagedPathKind::Socket, 0, 21, 0o660, 0),
            managed_path(ManagedPathKind::Socket, 0, 20, 0o666, 0),
            managed_path(ManagedPathKind::RegularFile, 0, 20, 0o660, 0),
        ] {
            assert!(ready_socket_is_valid(path, metadata, 20).is_err());
        }
        Ok(())
    }

    #[test]
    fn startup_error_record_requires_bounded_root_controlled_public_evidence() -> Result<()> {
        let path = Path::new(DEFAULT_HELPER_STARTUP_ERROR);
        startup_error_file_is_valid(
            path,
            managed_path(ManagedPathKind::RegularFile, 0, 0, 0o644, 4096),
        )?;
        for metadata in [
            managed_path(ManagedPathKind::Symlink, 0, 0, 0o644, 1),
            managed_path(ManagedPathKind::RegularFile, 501, 0, 0o644, 1),
            managed_path(ManagedPathKind::RegularFile, 0, 20, 0o644, 1),
            managed_path(ManagedPathKind::RegularFile, 0, 0, 0o600, 1),
            managed_path(ManagedPathKind::RegularFile, 0, 0, 0o644, 4097),
        ] {
            assert!(startup_error_file_is_valid(path, metadata).is_err());
        }
        Ok(())
    }

    #[test]
    fn startup_error_evidence_is_single_line_and_bounded() {
        let evidence = sanitize_startup_error(&format!(
            "failed\nwith\tcontrol\rcharacters {}",
            "x".repeat(MAX_STARTUP_ERROR_BYTES * 2)
        ));
        assert!(evidence.ends_with('\n'));
        assert_eq!(evidence.matches('\n').count(), 1);
        assert!(evidence.len() <= MAX_STARTUP_ERROR_BYTES);
        assert!(!evidence.contains('\t'));
        assert!(!evidence.contains('\r'));
    }

    #[test]
    fn startup_failure_preserves_the_original_cause_when_recording_fails() {
        let error =
            startup_failure_with_recording(anyhow::anyhow!("socket parent is missing"), || {
                bail!("diagnostic path is unsafe")
            });
        let chain = format!("{error:#}");
        assert!(chain.contains("socket parent is missing"));
        assert!(chain.contains("diagnostic path is unsafe"));
    }

    #[test]
    fn startup_error_record_is_a_durable_sibling_of_the_runtime_leaf() {
        assert_eq!(
            Path::new(DEFAULT_HELPER_STARTUP_ERROR).parent(),
            Path::new(DEFAULT_HELPER_CONFIG).parent()
        );
        assert_eq!(
            Path::new(DEFAULT_HELPER_SOCKET)
                .parent()
                .and_then(Path::parent),
            Path::new(DEFAULT_HELPER_STARTUP_ERROR).parent()
        );
    }

    #[cfg(unix)]
    #[test]
    fn install_roots_are_canonical_and_deduplicated_before_persistence() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new()?;
        let root = temp.path().join("root");
        fs::create_dir(&root)?;
        let alias = temp.path().join("alias");
        symlink(&root, &alias)?;

        assert_eq!(
            canonical_install_roots(&[root.clone(), alias, root.clone()])?,
            vec![root.canonicalize()?]
        );
        assert!(canonical_install_roots(&[]).is_err());
        Ok(())
    }

    #[test]
    fn helper_authentication_accepts_only_the_configured_uid() {
        assert!(peer_is_authorized(501, 501));
        assert!(!peer_is_authorized(502, 501));
        assert!(!peer_is_authorized(0, 501));
    }

    #[test]
    fn ownership_matching_is_bounded_by_path_depth_not_root_count() {
        let mut roots = (0..(MAX_REQUEST_ROOTS - 1))
            .map(|index| PathBuf::from(format!("/allowed/sibling-{index}")))
            .collect::<Vec<_>>();
        roots.push(PathBuf::from("/allowed"));
        let root_indices = roots
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, root)| (root, index))
            .collect::<HashMap<_, _>>();

        assert_eq!(
            matching_root_indices(
                Path::new("/allowed/sibling-1024/target/debug/app"),
                &root_indices
            ),
            vec![1024, MAX_REQUEST_ROOTS - 1]
        );
        assert!(matching_root_indices(Path::new("/outside/target"), &root_indices).is_empty());
    }

    #[test]
    fn backup_names_are_exact_timestamp_pid_pairs() {
        assert!(is_backup_directory_name("1721600000000000000-1234"));
        assert!(!is_backup_directory_name(""));
        assert!(!is_backup_directory_name("1721600000000000000"));
        assert!(!is_backup_directory_name("1721600000000000000-"));
        assert!(!is_backup_directory_name("-1234"));
        assert!(!is_backup_directory_name("1721600000000000000-1234-extra"));
        assert!(!is_backup_directory_name("latest-1234"));
    }

    #[test]
    fn status_uses_authenticated_service_metadata() -> Result<()> {
        let root = PathBuf::from("/tmp/allowed");
        let request = OwnershipRequest::new(8, &[]);
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 8,
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: Some(TEST_HELPER_BUILD_SHA256.to_string()),
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: 501,
                roots: vec![WirePath::from_path(&root)],
            }),
        };
        validate_response(&request, &response)?;
        let status = status_from_response(true, true, response)?;
        assert_eq!(status.client_uid, Some(501));
        assert_eq!(
            status.helper_build_sha256.as_deref(),
            Some(TEST_HELPER_BUILD_SHA256)
        );
        assert_eq!(status.roots, vec![WirePath::from_path(&root)]);
        assert!(status.probe_complete);
        Ok(())
    }

    #[test]
    fn client_rejects_complete_responses_without_a_build_hash() {
        let request = OwnershipRequest::new(82, &[]);
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 82,
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: None,
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: 501,
                roots: vec![WirePath::from_path(Path::new("/tmp/allowed"))],
            }),
        };
        assert!(validate_response(&request, &response).is_err());
    }

    #[test]
    fn client_rejects_the_evidence_only_v1_protocol() {
        let request = OwnershipRequest::new(83, &[]);
        let response = OwnershipResponse {
            protocol_version: 1,
            request_id: 83,
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: Some(TEST_HELPER_BUILD_SHA256.to_string()),
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: 501,
                roots: vec![WirePath::from_path(Path::new("/tmp/allowed"))],
            }),
        };
        assert!(validate_response(&request, &response).is_err());
    }

    #[test]
    fn client_rejects_an_unexpected_helper_backend() {
        let request = OwnershipRequest::new(84, &[]);
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 84,
            backend: "macos_privileged_libproc".to_string(),
            helper_build_sha256: Some(TEST_HELPER_BUILD_SHA256.to_string()),
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: 501,
                roots: vec![WirePath::from_path(Path::new("/tmp/allowed"))],
            }),
        };
        assert!(validate_response(&request, &response).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn status_serializes_non_utf8_roots_without_loss() -> Result<()> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let root = PathBuf::from(OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()));
        let response = OwnershipResponse {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id: 81,
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: Some(TEST_HELPER_BUILD_SHA256.to_string()),
            complete: true,
            error: None,
            observations: Vec::new(),
            service: Some(OwnershipServiceMetadata {
                client_uid: 501,
                roots: vec![WirePath::from_path(&root)],
            }),
        };
        let status = status_from_response(true, true, response)?;
        let encoded = serde_json::to_vec(&status)?;
        assert!(String::from_utf8(encoded)?.contains("2f746d702f6e6f6e2d757466382dff"));
        Ok(())
    }

    #[test]
    fn launchd_state_tolerates_only_the_explicit_missing_service_result() -> Result<()> {
        assert!(classify_service_state(true, Some(0), b"")?);
        let missing = format!(
            "Bad request.\nCould not find service \"{HELPER_LABEL}\" in domain for system\n"
        );
        assert!(!classify_service_state(
            false,
            Some(113),
            missing.as_bytes()
        )?);
        assert!(classify_service_state(false, Some(113), b"permission denied").is_err());
        assert!(classify_service_state(false, Some(1), missing.as_bytes()).is_err());
        Ok(())
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
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: Some(TEST_HELPER_BUILD_SHA256.to_string()),
            complete: true,
            error: None,
            observations: vec![OwnershipObservation {
                pid: 1,
                kind: OwnershipPathKind::OpenFile,
                observed_path: WirePath::from_path(Path::new("/tmp/other")),
                matched_root: WirePath::from_path(&root),
            }],
            service: None,
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
            backend: PRIVILEGED_OWNERSHIP_BACKEND.to_string(),
            helper_build_sha256: None,
            complete: false,
            error: Some("incomplete".to_string()),
            observations: vec![OwnershipObservation {
                pid: 1,
                kind: OwnershipPathKind::OpenFile,
                observed_path: WirePath::from_path(&root.join("open")),
                matched_root: WirePath::from_path(&root),
            }],
            service: None,
        };
        assert!(validate_response(&request, &response).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn privileged_capture_returns_only_allowlisted_matches() {
        let roots = vec![PathBuf::from("/allowed/repo/target")];
        let response = privileged_response_from_capture(
            14,
            &roots,
            crate::RawOwnershipCapture {
                backend: "lsof_global",
                protocol_version: None,
                helper_build_sha256: None,
                complete: true,
                error: None,
                observations: vec![
                    crate::RawProcessOwnershipObservation {
                        pid: 7,
                        command: Some("fixture".to_string()),
                        observed_path: roots[0].join("debug/app"),
                        evidence_kind: crate::ProcessOwnershipEvidenceKind::MappedFile,
                    },
                    crate::RawProcessOwnershipObservation {
                        pid: 8,
                        command: Some("fixture".to_string()),
                        observed_path: PathBuf::from("/outside/secret"),
                        evidence_kind: crate::ProcessOwnershipEvidenceKind::OpenFile,
                    },
                ],
            },
            TEST_HELPER_BUILD_SHA256.to_string(),
        );
        assert!(response.complete);
        assert_eq!(response.backend, PRIVILEGED_OWNERSHIP_BACKEND);
        assert_eq!(response.observations.len(), 1);
        assert_eq!(response.observations[0].pid, 7);
    }

    #[cfg(unix)]
    #[test]
    fn privileged_capture_rejects_incomplete_global_lsof_evidence() {
        let response = privileged_response_from_capture(
            15,
            &[PathBuf::from("/allowed")],
            crate::RawOwnershipCapture {
                backend: "lsof_global",
                protocol_version: None,
                helper_build_sha256: None,
                complete: false,
                error: Some("permission warning".to_string()),
                observations: Vec::new(),
            },
            TEST_HELPER_BUILD_SHA256.to_string(),
        );
        assert!(!response.complete);
        assert!(response.observations.is_empty());
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("permission warning")));
    }

    #[cfg(unix)]
    #[test]
    fn privileged_capture_rejects_an_unexpected_capture_backend() {
        let response = privileged_response_from_capture(
            16,
            &[PathBuf::from("/allowed")],
            crate::RawOwnershipCapture {
                backend: "macos_libproc",
                protocol_version: None,
                helper_build_sha256: None,
                complete: true,
                error: None,
                observations: Vec::new(),
            },
            TEST_HELPER_BUILD_SHA256.to_string(),
        );
        assert!(!response.complete);
        assert!(response.observations.is_empty());
        assert!(response
            .error
            .as_deref()
            .is_some_and(|error| error.contains("unexpected backend")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchd_plist_is_valid_and_has_only_the_evidence_service_command() -> Result<()> {
        let plist = render_launchd_plist(
            Path::new(DEFAULT_HELPER_BINARY),
            Path::new(DEFAULT_HELPER_CONFIG),
        );
        assert!(plist.contains("<string>serve</string>"));
        assert!(plist.contains("<string>/dev/null</string>"));
        assert!(!plist.contains(DEFAULT_HELPER_STARTUP_ERROR));
        assert!(!plist.contains("/var/log/"));
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
