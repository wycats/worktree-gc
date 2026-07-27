use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};

// Version 2 adds the required helper executable SHA-256 to every complete
// response. A v1 helper is intentionally rejected so strict helper mode fails
// closed until the client and root-owned service are upgraded as a pair.
pub const OWNERSHIP_PROTOCOL_VERSION: u64 = 2;
pub const MAX_REQUEST_ROOTS: usize = 2_048;
pub const MAX_PROTOCOL_MESSAGE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePath {
    bytes_hex: String,
}

impl WirePath {
    pub fn from_path(path: &Path) -> Self {
        Self {
            bytes_hex: encode_hex(path_bytes(path)),
        }
    }

    pub fn to_path_buf(&self) -> Result<PathBuf> {
        let bytes = decode_hex(&self.bytes_hex)?;
        Ok(PathBuf::from(os_string_from_bytes(bytes)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipRequest {
    pub protocol_version: u64,
    pub request_id: u64,
    pub roots: Vec<WirePath>,
}

impl OwnershipRequest {
    pub fn new(request_id: u64, roots: &[PathBuf]) -> Self {
        Self {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id,
            roots: roots.iter().map(|path| WirePath::from_path(path)).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipPathKind {
    Cwd,
    Root,
    MappedFile,
    OpenFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipObservation {
    pub pid: u32,
    pub kind: OwnershipPathKind,
    pub observed_path: WirePath,
    pub matched_root: WirePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipServiceMetadata {
    pub client_uid: u32,
    pub roots: Vec<WirePath>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipResponse {
    pub protocol_version: u64,
    pub request_id: u64,
    pub backend: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_build_sha256: Option<String>,
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub observations: Vec<OwnershipObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<OwnershipServiceMetadata>,
}

impl OwnershipResponse {
    pub fn refusal(request_id: u64, error: impl Into<String>) -> Self {
        Self {
            protocol_version: OWNERSHIP_PROTOCOL_VERSION,
            request_id,
            backend: "macos_privileged_libproc".to_string(),
            helper_build_sha256: None,
            complete: false,
            error: Some(error.into()),
            observations: Vec::new(),
            service: None,
        }
    }
}

pub fn write_message<T: Serialize>(writer: &mut impl Write, message: &T) -> Result<()> {
    let payload = serialize_message_with_limit(message, MAX_PROTOCOL_MESSAGE_BYTES)?;
    let length = u32::try_from(payload.len()).context("ownership helper message exceeds u32")?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

pub fn read_message<T: for<'de> Deserialize<'de>>(reader: &mut impl Read) -> Result<T> {
    let mut length = [0_u8; 4];
    reader.read_exact(&mut length)?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .context("ownership helper frame length exceeds usize")?;
    if length > MAX_PROTOCOL_MESSAGE_BYTES {
        bail!("ownership helper message is {length} bytes; limit is {MAX_PROTOCOL_MESSAGE_BYTES}");
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

fn serialize_message_with_limit<T: Serialize>(message: &T, limit: usize) -> Result<Vec<u8>> {
    let mut payload = BoundedPayload::new(limit);
    serde_json::to_writer(&mut payload, message)
        .context("ownership helper message exceeds limit")?;
    Ok(payload.into_inner())
}

struct BoundedPayload {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedPayload {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedPayload {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("ownership helper message length overflow"))?;
        if new_len > self.limit {
            return Err(std::io::Error::other(format!(
                "ownership helper message is larger than the {limit}-byte limit",
                limit = self.limit
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(encoded: &str) -> Result<Vec<u8>> {
    if !encoded.len().is_multiple_of(2) {
        bail!("ownership helper path has an odd-length hex encoding");
    }
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => bail!("ownership helper path contains non-lowercase-hex data"),
    }
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().to_str().unwrap_or_default().as_bytes()
}

#[cfg(unix)]
fn os_string_from_bytes(bytes: Vec<u8>) -> Result<OsString> {
    Ok(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn os_string_from_bytes(bytes: Vec<u8>) -> Result<OsString> {
    Ok(OsString::from(
        String::from_utf8(bytes).context("ownership helper path is not UTF-8")?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_round_trips_paths_and_frames() -> Result<()> {
        #[cfg(unix)]
        let path = PathBuf::from(OsString::from_vec(b"/tmp/non-utf8-\xff".to_vec()));
        #[cfg(not(unix))]
        let path = PathBuf::from("/tmp/ordinary");

        let request = OwnershipRequest::new(42, std::slice::from_ref(&path));
        let mut bytes = Vec::new();
        write_message(&mut bytes, &request)?;
        let decoded: OwnershipRequest = read_message(&mut bytes.as_slice())?;
        assert_eq!(decoded, request);
        assert_eq!(decoded.roots[0].to_path_buf()?, path);
        Ok(())
    }

    #[test]
    fn protocol_rejects_noncanonical_hex() {
        assert!(WirePath {
            bytes_hex: "ABCDEF".to_string()
        }
        .to_path_buf()
        .is_err());
        assert!(WirePath {
            bytes_hex: "0".to_string()
        }
        .to_path_buf()
        .is_err());
    }

    #[test]
    fn response_refusal_is_incomplete_and_empty() {
        let response = OwnershipResponse::refusal(7, "denied");
        assert_eq!(response.request_id, 7);
        assert!(!response.complete);
        assert_eq!(response.error.as_deref(), Some("denied"));
        assert!(response.helper_build_sha256.is_none());
        assert!(response.observations.is_empty());
        assert!(response.service.is_none());
    }

    #[test]
    fn frame_reader_rejects_oversized_payload_before_allocation() {
        let oversized = u32::try_from(MAX_PROTOCOL_MESSAGE_BYTES + 1)
            .expect("protocol limit should fit in u32")
            .to_be_bytes();
        assert!(read_message::<OwnershipRequest>(&mut oversized.as_slice()).is_err());
    }

    #[test]
    fn frame_writer_enforces_the_limit_during_serialization() -> Result<()> {
        let message = serde_json::json!({"payload": "x".repeat(128)});
        assert!(serialize_message_with_limit(&message, 64).is_err());
        assert!(serialize_message_with_limit(&message, 256)?.len() <= 256);
        Ok(())
    }
}
