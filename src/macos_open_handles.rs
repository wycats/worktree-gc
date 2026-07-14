use std::collections::HashSet;
use std::ffi::{c_int, c_void, OsString};
use std::io;
use std::mem::size_of;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;
use std::time::{Duration, Instant};

const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDREGIONPATHINFO: c_int = 8;
const PROC_PIDVNODEPATHINFO: c_int = 9;
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
const PROX_FDTYPE_VNODE: u32 = 1;
const MAXPATHLEN: usize = 1024;

// These are evidence-completeness limits, not tuning hints. Crossing one
// rejects the native snapshot and makes the caller fail closed without
// starting a second machine-wide scan.
const MAX_PROCESSES: usize = 4_096;
const MAX_FDS_PER_PROCESS: usize = 65_536;
const MAX_REGIONS_PER_PROCESS: usize = 131_072;
const MAX_REGIONS_TOTAL: usize = 2_000_000;
const MAX_OPEN_PATHS: usize = 1_000_000;
const MAX_CAPTURE_DURATION: Duration = Duration::from_secs(5);
const PID_GROWTH_SLACK: usize = 64;
const FD_GROWTH_SLACK: usize = 32;
// `sizeof(struct proc_regionwithpathinfo)` in the public macOS SDK. The
// record is `proc_regioninfo` followed by `vnode_info_path`; the path remains
// the trailing MAXPATHLEN bytes, so the vnode metadata can stay opaque here.
const REGION_PATH_BUFFER_BYTES: usize = 1_272;
const VNODE_PATH_BUFFER_BYTES: usize = 4_096;
const PROCESS_VNODE_PATH_BUFFER_BYTES: usize = 4_096;

const ESRCH: c_int = 3;
const EBADF: c_int = 9;
const EINVAL: c_int = 22;

#[derive(Debug)]
struct ResourceLimitError(String);

impl std::fmt::Display for ResourceLimitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ResourceLimitError {}

pub(crate) fn is_resource_limit(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.downcast_ref::<ResourceLimitError>().is_some())
}

fn resource_limit(message: impl Into<String>) -> io::Error {
    io::Error::other(ResourceLimitError(message.into()))
}

fn ensure_time_budget(started: Instant) -> io::Result<()> {
    if started.elapsed() >= MAX_CAPTURE_DURATION {
        return Err(resource_limit(format!(
            "native open-handle snapshot exceeded its {:?} time budget",
            MAX_CAPTURE_DURATION
        )));
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct ProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    object_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

#[link(name = "proc")]
extern "C" {
    fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn __error() -> *mut c_int;
}

/// Capture path-bearing vnode references for recursive in-memory candidate
/// matching.
///
/// `libproc` also exposes `proc_listpidspath`, but its SDK contract matches one
/// specified path or an entire volume; it does not promise recursive directory
/// subtree matching. Cache collectors need to detect an open descendant beneath
/// a candidate root without treating every process on the volume as an owner,
/// so this shared snapshot enumerates process paths once and matches all
/// candidate ancestors in memory.
pub(crate) fn capture() -> io::Result<HashSet<PathBuf>> {
    let started = Instant::now();
    let pids = list_all_pids()?;
    capture_pids(pids, started)
}

fn capture_pids(
    pids: impl IntoIterator<Item = c_int>,
    started: Instant,
) -> io::Result<HashSet<PathBuf>> {
    let mut paths = HashSet::new();
    let mut regions_seen = 0_usize;
    for pid in pids {
        ensure_time_budget(started)?;
        let Some(process_paths) = process_vnode_paths(pid)? else {
            continue;
        };
        paths.extend(process_paths.into_iter().flatten());
        if paths.len() > MAX_OPEN_PATHS {
            return Err(resource_limit(format!(
                "native open-handle snapshot exceeded {MAX_OPEN_PATHS} paths"
            )));
        }
        let Some(region_paths) = mapped_vnode_paths(pid, &mut regions_seen, started)? else {
            continue;
        };
        paths.extend(region_paths);
        if paths.len() > MAX_OPEN_PATHS {
            return Err(resource_limit(format!(
                "native open-handle snapshot exceeded {MAX_OPEN_PATHS} paths"
            )));
        }
        let Some(fds) = list_process_fds(pid)? else {
            continue;
        };
        for fd in fds {
            ensure_time_budget(started)?;
            if fd.proc_fdtype != PROX_FDTYPE_VNODE {
                continue;
            }
            if let Some(path) = vnode_path(pid, fd.proc_fd)? {
                paths.insert(path);
                if paths.len() > MAX_OPEN_PATHS {
                    return Err(resource_limit(format!(
                        "native open-handle snapshot exceeded {MAX_OPEN_PATHS} paths"
                    )));
                }
            }
        }
    }
    Ok(paths)
}

/// Capture file-backed virtual-memory regions. `lsof` reports these mappings
/// even after the descriptor used to create the mapping has been closed, so a
/// descriptor-only native backend would otherwise weaken the existing
/// ownership check for executables, dynamic libraries, and mapped databases.
fn mapped_vnode_paths(
    pid: c_int,
    regions_seen: &mut usize,
    started: Instant,
) -> io::Result<Option<Vec<PathBuf>>> {
    let mut address = 0_u64;
    let mut paths = Vec::new();
    for _ in 0..MAX_REGIONS_PER_PROCESS {
        ensure_time_budget(started)?;
        if *regions_seen >= MAX_REGIONS_TOTAL {
            return Err(resource_limit(format!(
                "native open-handle snapshot exceeded {MAX_REGIONS_TOTAL} memory regions"
            )));
        }
        let mut buffer = [0_u8; REGION_PATH_BUFFER_BYTES];
        reset_errno();
        let returned = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDREGIONPATHINFO,
                address,
                buffer.as_mut_ptr().cast(),
                c_int::try_from(buffer.len())
                    .map_err(|_| io::Error::other("region path buffer exceeds c_int"))?,
            )
        };
        if returned == 0 {
            return match zero_region_result(pid)? {
                true => Ok(None),
                false => Ok(Some(paths)),
            };
        }
        let returned = usize::try_from(returned).unwrap_or(0);
        let Some((next_address, path)) =
            parse_region_path_payload(pid, address, &buffer, returned)?
        else {
            return Ok(Some(paths));
        };
        address = next_address;
        *regions_seen += 1;
        if let Some(path) = path {
            paths.push(path);
        }
    }
    Err(resource_limit(format!(
        "process {pid} exceeded {MAX_REGIONS_PER_PROCESS} memory regions"
    )))
}

fn parse_region_path_payload(
    pid: c_int,
    requested_address: u64,
    buffer: &[u8],
    returned: usize,
) -> io::Result<Option<(u64, Option<PathBuf>)>> {
    if returned > buffer.len() || returned < size_of::<ProcRegionInfo>().saturating_add(MAXPATHLEN)
    {
        return Err(io::Error::other(format!(
            "process {pid} returned invalid region path payload length {returned}"
        )));
    }
    let region = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<ProcRegionInfo>()) };
    let path = trailing_vnode_path(buffer, returned)?;
    if region.size == 0 {
        if path.is_some() {
            return Err(io::Error::other(format!(
                "process {pid} returned a zero-length memory region with a vnode path"
            )));
        }
        return Ok(None);
    }
    let next_address = region.address.checked_add(region.size).ok_or_else(|| {
        io::Error::other(format!(
            "process {pid} returned overflowing memory region at {} with size {}",
            region.address, region.size
        ))
    })?;
    if next_address <= requested_address {
        return Err(io::Error::other(format!(
            "process {pid} returned a non-advancing memory region at {} with size {}",
            region.address, region.size
        )));
    }
    Ok(Some((next_address, path)))
}

/// Capture the process cwd and root vnode paths. Cwd is liveness evidence even
/// when the process has no ordinary descriptor open beneath the candidate.
///
/// `proc_vnodepathinfo` is two consecutive `vnode_info_path` records (cwd,
/// root), and each record ends with `char vip_path[MAXPATHLEN]`. Splitting the
/// returned payload in half lets us read the two public trailing path fields
/// without duplicating the private stat layout that precedes them.
fn process_vnode_paths(pid: c_int) -> io::Result<Option<[Option<PathBuf>; 2]>> {
    let mut buffer = [0_u8; PROCESS_VNODE_PATH_BUFFER_BYTES];
    reset_errno();
    let returned = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDVNODEPATHINFO,
            0,
            buffer.as_mut_ptr().cast(),
            c_int::try_from(buffer.len())
                .map_err(|_| io::Error::other("process vnode path buffer exceeds c_int"))?,
        )
    };
    if returned == 0 {
        return match zero_result(pid, "read process vnode paths")? {
            true => Ok(None),
            false => Err(io::Error::other(format!(
                "read process vnode paths for process {pid} returned no evidence"
            ))),
        };
    }
    let returned = usize::try_from(returned).unwrap_or(0);
    if returned > buffer.len() || returned < 2 * MAXPATHLEN || returned % 2 != 0 {
        return Err(io::Error::other(format!(
            "process {pid} returned invalid vnode path payload length {returned}"
        )));
    }
    let record_bytes = returned / 2;
    Ok(Some([
        trailing_vnode_path(&buffer, record_bytes)?,
        trailing_vnode_path(&buffer, returned)?,
    ]))
}

fn list_all_pids() -> io::Result<Vec<c_int>> {
    reset_errno();
    let initial = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    if initial < 0 {
        return Err(last_os_error("count processes"));
    }
    let mut capacity = usize::try_from(initial)
        .unwrap_or(MAX_PROCESSES)
        .saturating_add(PID_GROWTH_SLACK)
        .max(PID_GROWTH_SLACK);
    for _ in 0..3 {
        if capacity > MAX_PROCESSES {
            return Err(resource_limit(format!(
                "native open-handle snapshot exceeded {MAX_PROCESSES} processes"
            )));
        }
        let mut pids = vec![0_i32; capacity];
        reset_errno();
        let count =
            unsafe { proc_listallpids(pids.as_mut_ptr().cast(), byte_len::<c_int>(pids.len())?) };
        if count < 0 {
            return Err(last_os_error("list processes"));
        }
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        if count < capacity {
            pids.truncate(count);
            pids.retain(|pid| *pid > 0);
            return Ok(pids);
        }
        capacity = capacity.saturating_mul(2);
    }
    Err(resource_limit(
        "native process list kept growing during the bounded snapshot",
    ))
}

/// `None` means the process vanished during the snapshot. Other failures are
/// returned so the caller cannot mistake inaccessible evidence for no handles.
fn list_process_fds(pid: c_int) -> io::Result<Option<Vec<ProcFdInfo>>> {
    reset_errno();
    let required_bytes = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    if required_bytes == 0 {
        return zero_result(pid, "count file descriptors").map(|vanished| {
            if vanished {
                None
            } else {
                Some(Vec::new())
            }
        });
    }
    let required_bytes = usize::try_from(required_bytes).unwrap_or(usize::MAX);
    let mut capacity = required_bytes
        .div_ceil(size_of::<ProcFdInfo>())
        .saturating_add(FD_GROWTH_SLACK)
        .max(FD_GROWTH_SLACK);
    for _ in 0..3 {
        if capacity > MAX_FDS_PER_PROCESS {
            return Err(resource_limit(format!(
                "process {pid} exceeded {MAX_FDS_PER_PROCESS} file descriptors"
            )));
        }
        let mut fds = vec![ProcFdInfo::default(); capacity];
        reset_errno();
        let returned_bytes = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDLISTFDS,
                0,
                fds.as_mut_ptr().cast(),
                byte_len::<ProcFdInfo>(fds.len())?,
            )
        };
        if returned_bytes == 0 {
            return match zero_result(pid, "list file descriptors")? {
                true => Ok(None),
                false => Err(io::Error::other(format!(
                    "list file descriptors for process {pid} returned no evidence"
                ))),
            };
        }
        let returned_bytes = usize::try_from(returned_bytes).unwrap_or(usize::MAX);
        if returned_bytes > fds.len().saturating_mul(size_of::<ProcFdInfo>())
            || returned_bytes % size_of::<ProcFdInfo>() != 0
        {
            return Err(io::Error::other(format!(
                "process {pid} returned invalid file descriptor payload length {returned_bytes}"
            )));
        }
        let count = returned_bytes / size_of::<ProcFdInfo>();
        if count < capacity {
            fds.truncate(count);
            return Ok(Some(fds));
        }
        capacity = capacity.saturating_mul(2);
    }
    Err(resource_limit(format!(
        "file descriptor list for process {pid} kept growing during the bounded snapshot"
    )))
}

fn vnode_path(pid: c_int, fd: c_int) -> io::Result<Option<PathBuf>> {
    let mut buffer = [0_u8; VNODE_PATH_BUFFER_BYTES];
    reset_errno();
    let returned = unsafe {
        proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            buffer.as_mut_ptr().cast(),
            c_int::try_from(buffer.len())
                .map_err(|_| io::Error::other("vnode path buffer exceeds c_int"))?,
        )
    };
    if returned == 0 {
        return match zero_result(pid, "read vnode path")? {
            true => Ok(None),
            false => Err(io::Error::other(format!(
                "read vnode path for process {pid} fd {fd} returned no evidence"
            ))),
        };
    }
    let returned = usize::try_from(returned).unwrap_or(0);
    if returned < MAXPATHLEN || returned > buffer.len() {
        return Err(io::Error::other(format!(
            "process {pid} fd {fd} returned invalid vnode path payload length {returned}"
        )));
    }
    // `vnode_fdinfowithpath` ends with `char vip_path[MAXPATHLEN]`. Reading the
    // trailing field avoids duplicating private layout details that precede it.
    trailing_vnode_path(&buffer, returned)
}

fn trailing_vnode_path(buffer: &[u8], record_end: usize) -> io::Result<Option<PathBuf>> {
    if record_end < MAXPATHLEN || record_end > buffer.len() {
        return Err(io::Error::other(format!(
            "invalid vnode path field ending at byte {record_end}"
        )));
    }
    let field = &buffer[record_end - MAXPATHLEN..record_end];
    let length = field.iter().position(|byte| *byte == 0).ok_or_else(|| {
        io::Error::other("vnode path field was not NUL-terminated and may be truncated")
    })?;
    if length == 0 {
        return Ok(None);
    }
    let path = PathBuf::from(OsString::from_vec(field[..length].to_vec()));
    Ok(path.is_absolute().then_some(path))
}

fn zero_result(pid: c_int, operation: &str) -> io::Result<bool> {
    let errno = current_errno();
    if errno == 0 {
        return Ok(false);
    }
    if matches!(errno, ESRCH | EBADF) {
        return Ok(true);
    }
    Err(io::Error::other(format!(
        "{operation} for process {pid}: {}",
        io::Error::from_raw_os_error(errno)
    )))
}

fn zero_region_result(pid: c_int) -> io::Result<bool> {
    // `PROC_PIDREGIONPATHINFO` uses EINVAL with a zero return as its normal
    // end-of-address-space sentinel. Keep that exception local to this flavor;
    // the other libproc queries still treat EINVAL as an evidence failure.
    if current_errno() == EINVAL {
        return Ok(false);
    }
    zero_result(pid, "read mapped vnode paths")
}

fn byte_len<T>(elements: usize) -> io::Result<c_int> {
    c_int::try_from(elements.saturating_mul(size_of::<T>()))
        .map_err(|_| resource_limit("native open-handle buffer exceeds c_int"))
}

fn reset_errno() {
    unsafe {
        *__error() = 0;
    }
}

fn current_errno() -> c_int {
    unsafe { *__error() }
}

fn last_os_error(operation: &str) -> io::Error {
    io::Error::other(format!("{operation}: {}", io::Error::last_os_error()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_fd_info_layout_matches_the_sdk_contract() {
        assert_eq!(size_of::<ProcFdInfo>(), 8);
    }

    #[test]
    fn proc_region_info_layout_matches_the_sdk_contract() {
        assert_eq!(size_of::<ProcRegionInfo>(), 96);
        assert_eq!(REGION_PATH_BUFFER_BYTES, 1_272);
    }

    #[test]
    fn mapped_region_payload_advances_and_extracts_its_trailing_path() {
        let returned = REGION_PATH_BUFFER_BYTES;
        let mut payload = vec![0_u8; returned];
        let region = ProcRegionInfo {
            address: 0x1_000,
            size: 0x2_000,
            ..ProcRegionInfo::default()
        };
        unsafe {
            ptr::write_unaligned(payload.as_mut_ptr().cast::<ProcRegionInfo>(), region);
        }
        let path_start = returned - MAXPATHLEN;
        payload[path_start..path_start + 7].copy_from_slice(b"/mapped");

        let (next, path) = parse_region_path_payload(42, 0, &payload, returned)
            .unwrap()
            .expect("ordinary region should advance");

        assert_eq!(next, 0x3_000);
        assert_eq!(path, Some(PathBuf::from("/mapped")));
    }

    #[test]
    fn mapped_region_payload_must_advance_past_the_requested_address() {
        let returned = REGION_PATH_BUFFER_BYTES;
        let mut payload = vec![0_u8; returned];
        let region = ProcRegionInfo {
            address: 0x1_000,
            size: 0x1_000,
            ..ProcRegionInfo::default()
        };
        unsafe {
            ptr::write_unaligned(payload.as_mut_ptr().cast::<ProcRegionInfo>(), region);
        }

        let error = parse_region_path_payload(42, 0x2_000, &payload, returned).unwrap_err();

        assert!(error.to_string().contains("non-advancing"));
    }

    #[test]
    fn zero_length_mapped_region_without_a_path_is_end_of_address_space() {
        let returned = REGION_PATH_BUFFER_BYTES;
        let mut payload = vec![0_u8; returned];
        let region = ProcRegionInfo {
            address: 0x1_000,
            size: 0,
            ..ProcRegionInfo::default()
        };
        unsafe {
            ptr::write_unaligned(payload.as_mut_ptr().cast::<ProcRegionInfo>(), region);
        }

        assert_eq!(
            parse_region_path_payload(42, 0x1_000, &payload, returned).unwrap(),
            None
        );
    }

    #[test]
    fn zero_length_mapped_region_with_a_path_fails_closed() {
        let returned = REGION_PATH_BUFFER_BYTES;
        let mut payload = vec![0_u8; returned];
        let region = ProcRegionInfo {
            address: 0x1_000,
            size: 0,
            ..ProcRegionInfo::default()
        };
        unsafe {
            ptr::write_unaligned(payload.as_mut_ptr().cast::<ProcRegionInfo>(), region);
        }
        let path_start = returned - MAXPATHLEN;
        payload[path_start..path_start + 7].copy_from_slice(b"/mapped");

        let error = parse_region_path_payload(42, 0x1_000, &payload, returned).unwrap_err();

        assert!(error.to_string().contains("zero-length memory region"));
    }

    #[test]
    fn process_vnode_payload_extracts_both_trailing_paths() {
        let record_bytes = MAXPATHLEN + 16;
        let mut payload = vec![0_u8; record_bytes * 2];
        payload[16..16 + 4].copy_from_slice(b"/cwd");
        payload[record_bytes + 16..record_bytes + 16 + 5].copy_from_slice(b"/root");

        assert_eq!(
            trailing_vnode_path(&payload, record_bytes).unwrap(),
            Some(PathBuf::from("/cwd"))
        );
        assert_eq!(
            trailing_vnode_path(&payload, record_bytes * 2).unwrap(),
            Some(PathBuf::from("/root"))
        );
    }

    #[test]
    fn unterminated_vnode_path_is_rejected() {
        let payload = vec![b'x'; MAXPATHLEN];
        let error = trailing_vnode_path(&payload, MAXPATHLEN).unwrap_err();
        assert!(error.to_string().contains("not NUL-terminated"));
    }

    #[test]
    fn resource_limits_are_classified_without_string_matching() {
        let limit = resource_limit("bounded snapshot exhausted");
        let ordinary = io::Error::other("bounded snapshot exhausted");

        assert!(is_resource_limit(&limit));
        assert!(!is_resource_limit(&ordinary));
    }

    #[test]
    fn mapped_region_end_of_address_space_accepts_einval_only_for_that_flavor() {
        reset_errno();
        unsafe {
            *__error() = EINVAL;
        }

        assert!(!zero_region_result(42).unwrap());
        assert!(zero_result(42, "read vnode paths").is_err());
        reset_errno();
    }

    #[test]
    fn native_snapshot_observes_this_process_cwd_and_executable_mapping() -> io::Result<()> {
        let pid = c_int::try_from(std::process::id())
            .map_err(|_| io::Error::other("test pid exceeds c_int"))?;
        let paths = capture_pids([pid], Instant::now())?;
        let cwd = std::env::current_dir()?.canonicalize()?;
        let executable = std::env::current_exe()?.canonicalize()?;

        assert!(paths.contains(&cwd), "native snapshot omitted cwd {cwd:?}");
        assert!(
            paths.contains(&executable),
            "native snapshot omitted executable mapping {executable:?}"
        );
        Ok(())
    }
}
