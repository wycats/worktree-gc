use anyhow::{Context, Result};
use serde::Serialize;
use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const INVENTORY_VERSION: u64 = 1;

#[derive(Debug, Clone)]
pub struct InventoryOptions {
    /// Number of directory levels to retain in the report. The scanner still
    /// visits deeper descendants so each retained directory has a recursive
    /// total.
    pub display_depth: usize,
    /// Maximum number of children retained beneath each displayed directory.
    pub top: usize,
    /// Hard bound on directory entries visited across all roots.
    pub max_entries: u64,
    /// Stay on the root's filesystem. This is the safe default for both
    /// accounting and traversal cost.
    pub one_filesystem: bool,
}

impl Default for InventoryOptions {
    fn default() -> Self {
        Self {
            display_depth: 2,
            top: 20,
            max_entries: 2_000_000,
            one_filesystem: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryReport {
    pub inventory_version: u64,
    pub generated_at_unix: u64,
    pub options: InventoryReportOptions,
    pub roots: Vec<InventoryRoot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryReportOptions {
    pub display_depth: usize,
    pub top: usize,
    pub max_entries: u64,
    pub one_filesystem: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryRoot {
    pub path: PathBuf,
    pub filesystem: String,
    pub complete: bool,
    pub visited_entries: u64,
    pub metrics: InventoryMetrics,
    pub entries: Vec<InventoryEntry>,
    pub errors: Vec<InventoryScanError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryEntry {
    pub path: PathBuf,
    pub relative_path: PathBuf,
    pub parent: PathBuf,
    pub depth: usize,
    pub metrics: InventoryMetrics,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct InventoryMetrics {
    pub logical_bytes: u64,
    pub allocated_bytes: u64,
    /// Conservative bytes private to the files visited beneath this path.
    /// On APFS this comes from ATTR_CMNEXT_PRIVATESIZE and is the immediately
    /// reclaimable floor. Shared clone extents can make whole-tree reclaim
    /// larger than this value.
    pub private_reclaimable_bytes: u64,
    pub private_reclaimable_complete: bool,
    pub files: u64,
    pub directories: u64,
    pub hardlink_duplicates: u64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InventoryScanError {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
struct MetricsAccumulator {
    logical_bytes: u64,
    allocated_bytes: u64,
    private_reclaimable_bytes: u64,
    private_unknown_files: u64,
    files: u64,
    directories: u64,
    hardlink_duplicates: u64,
    errors: u64,
}

impl MetricsAccumulator {
    fn finish(&self) -> InventoryMetrics {
        InventoryMetrics {
            logical_bytes: self.logical_bytes,
            allocated_bytes: self.allocated_bytes,
            private_reclaimable_bytes: self.private_reclaimable_bytes,
            private_reclaimable_complete: self.private_unknown_files == 0,
            files: self.files,
            directories: self.directories,
            hardlink_duplicates: self.hardlink_duplicates,
            errors: self.errors,
        }
    }
}

#[derive(Debug)]
struct FileMeasurement {
    logical_bytes: u64,
    allocated_bytes: u64,
    private_reclaimable_bytes: Option<u64>,
}

#[derive(Debug)]
struct DirectoryEntryMeasurement {
    name: std::ffi::OsString,
    kind: EntryKind,
    file_id: Option<u64>,
    link_count: Option<u64>,
    file: Option<FileMeasurement>,
}

#[derive(Debug)]
struct PendingHardlink {
    expected_links: u64,
    observed_links: u64,
    common_parent: PathBuf,
    private_reclaimable_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryKind {
    File,
    Directory,
    Other,
}

#[derive(Debug)]
struct DirectoryVisit {
    visited_entries: u64,
    truncated: bool,
}

pub fn inventory(paths: &[PathBuf], options: InventoryOptions) -> Result<InventoryReport> {
    anyhow::ensure!(!paths.is_empty(), "inventory requires at least one path");
    anyhow::ensure!(options.top > 0, "inventory top must be at least 1");
    anyhow::ensure!(
        options.max_entries > 0,
        "inventory max_entries must be at least 1"
    );

    let generated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let report_options = InventoryReportOptions {
        display_depth: options.display_depth,
        top: options.top,
        max_entries: options.max_entries,
        one_filesystem: options.one_filesystem,
    };
    let mut remaining_entries = options.max_entries;
    let mut roots = Vec::with_capacity(paths.len());
    for path in paths {
        roots.push(scan_root(path, &options, &mut remaining_entries)?);
    }

    Ok(InventoryReport {
        inventory_version: INVENTORY_VERSION,
        generated_at_unix,
        options: report_options,
        roots,
    })
}

fn scan_root(
    requested: &Path,
    options: &InventoryOptions,
    remaining_entries: &mut u64,
) -> Result<InventoryRoot> {
    let root = requested
        .canonicalize()
        .with_context(|| format!("canonicalize inventory root {}", requested.display()))?;
    let metadata = fs::metadata(&root)
        .with_context(|| format!("read inventory root metadata for {}", root.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "inventory root is not a directory: {}",
        root.display()
    );

    let root_device = metadata_device(&metadata);
    let filesystem = root_device
        .map(|device| format!("device:{device}"))
        .unwrap_or_else(|| "unknown".to_string());
    let mut queue = VecDeque::from([root.clone()]);
    let mut seen_files = HashSet::new();
    let mut pending_hardlinks: HashMap<(u64, u64), PendingHardlink> = HashMap::new();
    let mut aggregates = BTreeMap::new();
    aggregates.insert(root.clone(), MetricsAccumulator::default());
    add_directory(&mut aggregates, &root);
    let mut visited_entries = 0u64;
    let mut complete = true;
    let mut errors = Vec::new();

    while let Some(directory) = queue.pop_front() {
        if *remaining_entries == 0 {
            complete = false;
            break;
        }

        let directory_metadata = match fs::metadata(&directory) {
            Ok(metadata) => metadata,
            Err(error) => {
                record_error(&mut aggregates, &directory, &error.to_string());
                push_error(&mut errors, &directory, error.to_string());
                complete = false;
                continue;
            }
        };
        let directory_device = metadata_device(&directory_metadata);
        if options.one_filesystem && directory_device != root_device {
            continue;
        }

        let visit = visit_directory(&directory, *remaining_entries, &mut |result: io::Result<
            DirectoryEntryMeasurement,
        >| {
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    record_error(&mut aggregates, &directory, &error.to_string());
                    push_error(&mut errors, &directory, error.to_string());
                    complete = false;
                    return;
                }
            };
            let path = directory.join(&entry.name);
            match entry.kind {
                EntryKind::Directory => {
                    let depth = relative_depth(&root, &path);
                    if depth <= options.display_depth {
                        aggregates.entry(path.clone()).or_default();
                    }
                    add_directory(&mut aggregates, &path);
                    queue.push_back(path);
                }
                EntryKind::File => {
                    let file_key = entry
                        .file_id
                        .map(|file_id| (directory_device.unwrap_or(0), file_id));
                    let duplicate = file_key
                        .map(|file_key| !seen_files.insert(file_key))
                        .unwrap_or(false);
                    if duplicate {
                        add_hardlink_duplicate(&mut aggregates, &path);
                        if let Some(pending) =
                            file_key.and_then(|key| pending_hardlinks.get_mut(&key))
                        {
                            pending.observed_links += 1;
                            narrow_common_parent(&mut pending.common_parent, &path);
                        }
                    } else if let Some(file) = entry.file {
                        if entry.link_count.unwrap_or(1) > 1 {
                            let private_reclaimable_bytes = file.private_reclaimable_bytes;
                            add_file(
                                &mut aggregates,
                                &path,
                                &FileMeasurement {
                                    private_reclaimable_bytes: private_reclaimable_bytes.map(|_| 0),
                                    ..file
                                },
                            );
                            if let Some(file_key) = file_key {
                                pending_hardlinks.insert(
                                    file_key,
                                    PendingHardlink {
                                        expected_links: entry.link_count.unwrap_or(1),
                                        observed_links: 1,
                                        common_parent: path
                                            .parent()
                                            .expect("file has a parent")
                                            .to_path_buf(),
                                        private_reclaimable_bytes,
                                    },
                                );
                            }
                        } else {
                            add_file(&mut aggregates, &path, &file);
                        }
                    } else {
                        let message = "file attributes were unavailable";
                        record_error(&mut aggregates, &path, message);
                        push_error(&mut errors, &path, message.to_string());
                        complete = false;
                    }
                }
                EntryKind::Other => {}
            }
        });
        let visit = match visit {
            Ok(visit) => visit,
            Err(error) => {
                record_error(&mut aggregates, &directory, &error.to_string());
                push_error(&mut errors, &directory, error.to_string());
                complete = false;
                continue;
            }
        };
        visited_entries = visited_entries.saturating_add(visit.visited_entries);
        *remaining_entries = remaining_entries.saturating_sub(visit.visited_entries);
        if visit.truncated {
            complete = false;
            queue.clear();
        }
    }

    for pending in pending_hardlinks.into_values() {
        if pending.observed_links >= pending.expected_links {
            if let Some(private) = pending.private_reclaimable_bytes {
                add_private_reclaimable(&mut aggregates, &pending.common_parent, private);
            }
        }
    }

    let root_metrics = aggregates
        .get(&root)
        .expect("root aggregate exists")
        .finish();
    let entries = retained_entries(&root, aggregates, options.top);
    Ok(InventoryRoot {
        path: root,
        filesystem,
        complete,
        visited_entries,
        metrics: root_metrics,
        entries,
        errors,
    })
}

fn add_directory(aggregates: &mut BTreeMap<PathBuf, MetricsAccumulator>, path: &Path) {
    for key in aggregate_keys(aggregates, path) {
        aggregates
            .get_mut(&key)
            .expect("aggregate key exists")
            .directories += 1;
    }
}

fn add_file(
    aggregates: &mut BTreeMap<PathBuf, MetricsAccumulator>,
    path: &Path,
    file: &FileMeasurement,
) {
    for key in aggregate_keys(aggregates, path) {
        let metrics = aggregates.get_mut(&key).expect("aggregate key exists");
        metrics.logical_bytes = metrics.logical_bytes.saturating_add(file.logical_bytes);
        metrics.allocated_bytes = metrics.allocated_bytes.saturating_add(file.allocated_bytes);
        metrics.files += 1;
        if let Some(private) = file.private_reclaimable_bytes {
            metrics.private_reclaimable_bytes =
                metrics.private_reclaimable_bytes.saturating_add(private);
        } else {
            metrics.private_unknown_files += 1;
        }
    }
}

fn add_private_reclaimable(
    aggregates: &mut BTreeMap<PathBuf, MetricsAccumulator>,
    path: &Path,
    bytes: u64,
) {
    for key in aggregate_keys(aggregates, path) {
        let metrics = aggregates.get_mut(&key).expect("aggregate key exists");
        metrics.private_reclaimable_bytes = metrics.private_reclaimable_bytes.saturating_add(bytes);
    }
}

fn narrow_common_parent(common: &mut PathBuf, path: &Path) {
    while !path.starts_with(&*common) {
        if !common.pop() {
            break;
        }
    }
}

fn add_hardlink_duplicate(aggregates: &mut BTreeMap<PathBuf, MetricsAccumulator>, path: &Path) {
    for key in aggregate_keys(aggregates, path) {
        aggregates
            .get_mut(&key)
            .expect("aggregate key exists")
            .hardlink_duplicates += 1;
    }
}

fn record_error(
    aggregates: &mut BTreeMap<PathBuf, MetricsAccumulator>,
    path: &Path,
    _message: &str,
) {
    for key in aggregate_keys(aggregates, path) {
        aggregates
            .get_mut(&key)
            .expect("aggregate key exists")
            .errors += 1;
    }
}

fn aggregate_keys(aggregates: &BTreeMap<PathBuf, MetricsAccumulator>, path: &Path) -> Vec<PathBuf> {
    path.ancestors()
        .filter(|ancestor| aggregates.contains_key(*ancestor))
        .map(Path::to_path_buf)
        .collect()
}

fn push_error(errors: &mut Vec<InventoryScanError>, path: &Path, message: String) {
    const MAX_RECORDED_ERRORS: usize = 100;
    if errors.len() < MAX_RECORDED_ERRORS {
        errors.push(InventoryScanError {
            path: path.to_path_buf(),
            message,
        });
    }
}

fn retained_entries(
    root: &Path,
    aggregates: BTreeMap<PathBuf, MetricsAccumulator>,
    top: usize,
) -> Vec<InventoryEntry> {
    let mut by_parent: BTreeMap<PathBuf, Vec<InventoryEntry>> = BTreeMap::new();
    for (path, metrics) in aggregates {
        if path == root {
            continue;
        }
        let Some(parent) = path.parent().map(Path::to_path_buf) else {
            continue;
        };
        by_parent
            .entry(parent.clone())
            .or_default()
            .push(InventoryEntry {
                relative_path: path.strip_prefix(root).unwrap_or(&path).to_path_buf(),
                depth: relative_depth(root, &path),
                path,
                parent,
                metrics: metrics.finish(),
            });
    }
    for entries in by_parent.values_mut() {
        entries.sort_by_key(|entry| {
            let preferred_bytes = if entry.metrics.private_reclaimable_complete {
                entry.metrics.private_reclaimable_bytes
            } else {
                entry.metrics.allocated_bytes
            };
            (
                Reverse(preferred_bytes),
                Reverse(entry.metrics.allocated_bytes),
                entry.path.clone(),
            )
        });
        entries.truncate(top);
    }

    let mut retained = Vec::new();
    let mut parents = VecDeque::from([root.to_path_buf()]);
    while let Some(parent) = parents.pop_front() {
        if let Some(children) = by_parent.remove(&parent) {
            for child in children {
                parents.push_back(child.path.clone());
                retained.push(child);
            }
        }
    }
    retained
}

fn relative_depth(root: &Path, path: &Path) -> usize {
    path.strip_prefix(root)
        .map(|relative| relative.components().count())
        .unwrap_or(0)
}

pub fn print_inventory(report: &InventoryReport) {
    for root in &report.roots {
        println!("{}", root.path.display());
        println!(
            "  private {}{} | allocated {} | logical {} | {} files | {} dirs | {} entries scanned{}",
            format_bytes(root.metrics.private_reclaimable_bytes),
            if root.metrics.private_reclaimable_complete {
                ""
            } else {
                " (lower bound)"
            },
            format_bytes(root.metrics.allocated_bytes),
            format_bytes(root.metrics.logical_bytes),
            root.metrics.files,
            root.metrics.directories,
            root.visited_entries,
            if root.complete { "" } else { " | incomplete" }
        );
        for entry in &root.entries {
            println!(
                "  {:indent$}{} private{} | {} allocated | {}",
                "",
                format_bytes(entry.metrics.private_reclaimable_bytes),
                if entry.metrics.private_reclaimable_complete {
                    ""
                } else {
                    " (lower bound)"
                },
                format_bytes(entry.metrics.allocated_bytes),
                entry.relative_path.display(),
                indent = entry.depth.saturating_sub(1) * 2
            );
        }
        if !root.errors.is_empty() {
            println!("  {} scan errors recorded", root.metrics.errors);
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    const TIB: f64 = GIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= TIB {
        format!("{:.2} TiB", bytes / TIB)
    } else if bytes >= GIB {
        format!("{:.2} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

#[cfg(unix)]
fn metadata_device(metadata: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.dev())
}

#[cfg(not(unix))]
fn metadata_device(_metadata: &fs::Metadata) -> Option<u64> {
    None
}

#[cfg(target_os = "macos")]
fn visit_directory<F>(path: &Path, max_entries: u64, visitor: &mut F) -> io::Result<DirectoryVisit>
where
    F: FnMut(io::Result<DirectoryEntryMeasurement>),
{
    match macos::visit_directory(path, max_entries, visitor) {
        Ok(visit) => Ok(visit),
        // EINVAL, ENOTSUP, and ENOSYS cover filesystems or older kernels that
        // cannot vend the extended common attributes. Preserve inventory
        // coverage and mark private-byte accounting incomplete via fallback.
        Err(error) if matches!(error.raw_os_error(), Some(22 | 45 | 78)) => {
            portable::visit_directory(path, max_entries, visitor)
        }
        Err(error) => Err(error),
    }
}

#[cfg(not(target_os = "macos"))]
fn visit_directory<F>(path: &Path, max_entries: u64, visitor: &mut F) -> io::Result<DirectoryVisit>
where
    F: FnMut(io::Result<DirectoryEntryMeasurement>),
{
    portable::visit_directory(path, max_entries, visitor)
}

mod portable {
    use super::*;

    pub(super) fn visit_directory<F>(
        path: &Path,
        max_entries: u64,
        visitor: &mut F,
    ) -> io::Result<DirectoryVisit>
    where
        F: FnMut(io::Result<DirectoryEntryMeasurement>),
    {
        let mut visited_entries = 0;
        let mut truncated = false;
        for result in fs::read_dir(path)? {
            if visited_entries == max_entries {
                truncated = true;
                break;
            }
            visited_entries += 1;
            let entry = match result {
                Ok(entry) => entry,
                Err(error) => {
                    visitor(Err(error));
                    continue;
                }
            };
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) => {
                    visitor(Err(io::Error::new(
                        error.kind(),
                        format!("{}: {error}", entry.path().display()),
                    )));
                    continue;
                }
            };
            let kind = if metadata.is_dir() {
                EntryKind::Directory
            } else if metadata.is_file() {
                EntryKind::File
            } else {
                EntryKind::Other
            };
            visitor(Ok(DirectoryEntryMeasurement {
                name: entry.file_name(),
                kind,
                file_id: metadata_file_id(&metadata),
                link_count: metadata_link_count(&metadata),
                file: (kind == EntryKind::File).then(|| FileMeasurement {
                    logical_bytes: metadata.len(),
                    allocated_bytes: metadata_allocated_bytes(&metadata),
                    private_reclaimable_bytes: None,
                }),
            }));
        }
        Ok(DirectoryVisit {
            visited_entries,
            truncated,
        })
    }

    #[cfg(unix)]
    fn metadata_file_id(metadata: &fs::Metadata) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.ino())
    }

    #[cfg(not(unix))]
    fn metadata_file_id(_metadata: &fs::Metadata) -> Option<u64> {
        None
    }

    #[cfg(unix)]
    fn metadata_link_count(metadata: &fs::Metadata) -> Option<u64> {
        use std::os::unix::fs::MetadataExt;
        Some(metadata.nlink())
    }

    #[cfg(not(unix))]
    fn metadata_link_count(_metadata: &fs::Metadata) -> Option<u64> {
        None
    }

    #[cfg(unix)]
    fn metadata_allocated_bytes(metadata: &fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        metadata.blocks().saturating_mul(512)
    }

    #[cfg(not(unix))]
    fn metadata_allocated_bytes(metadata: &fs::Metadata) -> u64 {
        metadata.len()
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::OsString;
    use std::fs::File;
    use std::mem::size_of;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_void};
    use std::os::unix::ffi::OsStringExt;

    #[repr(C)]
    #[derive(Default)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct AttributeSet {
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AttrReference {
        data_offset: i32,
        length: u32,
    }

    unsafe extern "C" {
        fn getattrlistbulk(
            dirfd: c_int,
            attr_list: *mut AttrList,
            attr_buf: *mut c_void,
            attr_buf_size: usize,
            options: u64,
        ) -> c_int;
    }

    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_NAME: u32 = 0x0000_0001;
    const ATTR_CMN_OBJTYPE: u32 = 0x0000_0008;
    const ATTR_CMN_FILEID: u32 = 0x0200_0000;
    const ATTR_CMN_ERROR: u32 = 0x2000_0000;
    const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const ATTR_FILE_LINKCOUNT: u32 = 0x0000_0001;
    const ATTR_FILE_TOTALSIZE: u32 = 0x0000_0002;
    const ATTR_FILE_ALLOCSIZE: u32 = 0x0000_0004;
    const ATTR_CMNEXT_PRIVATESIZE: u32 = 0x0000_0008;
    const FSOPT_ATTR_CMN_EXTENDED: u64 = 0x0000_0020;
    const VREG: u32 = 1;
    const VDIR: u32 = 2;

    pub(super) fn visit_directory<F>(
        path: &Path,
        max_entries: u64,
        visitor: &mut F,
    ) -> io::Result<DirectoryVisit>
    where
        F: FnMut(io::Result<DirectoryEntryMeasurement>),
    {
        let directory = File::open(path)?;
        let mut attrs = AttrList {
            bitmapcount: ATTR_BIT_MAP_COUNT,
            commonattr: ATTR_CMN_NAME
                | ATTR_CMN_OBJTYPE
                | ATTR_CMN_FILEID
                | ATTR_CMN_ERROR
                | ATTR_CMN_RETURNED_ATTRS,
            fileattr: ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE,
            forkattr: ATTR_CMNEXT_PRIVATESIZE,
            ..AttrList::default()
        };
        let mut buffer = vec![0u8; 64 * 1024];
        let mut visited_entries = 0u64;
        let mut truncated = false;

        loop {
            if visited_entries == max_entries {
                truncated = true;
                break;
            }
            let count = unsafe {
                getattrlistbulk(
                    directory.as_raw_fd(),
                    &mut attrs,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    FSOPT_ATTR_CMN_EXTENDED,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            if count == 0 {
                break;
            }

            let mut entry_offset = 0usize;
            for _ in 0..count {
                let length = read_value::<u32>(&buffer, &mut entry_offset)? as usize;
                if length < size_of::<u32>()
                    || entry_offset - size_of::<u32>() + length > buffer.len()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid getattrlistbulk entry length",
                    ));
                }
                let start = entry_offset - size_of::<u32>();
                let end = start + length;
                if visited_entries < max_entries {
                    visited_entries += 1;
                    visitor(parse_entry(&buffer[start..end]));
                } else {
                    truncated = true;
                }
                entry_offset = end;
            }
            if truncated {
                break;
            }
        }
        Ok(DirectoryVisit {
            visited_entries,
            truncated,
        })
    }

    fn parse_entry(buffer: &[u8]) -> io::Result<DirectoryEntryMeasurement> {
        let mut offset = size_of::<u32>();
        let returned = read_value::<AttributeSet>(buffer, &mut offset)?;
        let entry_error = if returned.commonattr & ATTR_CMN_ERROR != 0 {
            read_value::<u32>(buffer, &mut offset)?
        } else {
            0
        };
        let name = if returned.commonattr & ATTR_CMN_NAME != 0 {
            let reference_position = offset;
            let reference = read_value::<AttrReference>(buffer, &mut offset)?;
            let start = reference_position
                .checked_add_signed(reference.data_offset as isize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid name offset"))?;
            let end = start
                .checked_add(reference.length as usize)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid name length"))?;
            let bytes = buffer.get(start..end).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "name lies outside attribute buffer",
                )
            })?;
            OsString::from_vec(bytes.strip_suffix(&[0]).unwrap_or(bytes).to_vec())
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "getattrlistbulk omitted required name",
            ));
        };
        if entry_error != 0 {
            return Err(io::Error::from_raw_os_error(entry_error as i32));
        }

        let object_type = if returned.commonattr & ATTR_CMN_OBJTYPE != 0 {
            read_value::<u32>(buffer, &mut offset)?
        } else {
            0
        };
        let file_id = if returned.commonattr & ATTR_CMN_FILEID != 0 {
            Some(read_value::<u64>(buffer, &mut offset)?)
        } else {
            None
        };
        let link_count = if returned.fileattr & ATTR_FILE_LINKCOUNT != 0 {
            Some(read_value::<u32>(buffer, &mut offset)? as u64)
        } else {
            None
        };
        let logical_bytes = if returned.fileattr & ATTR_FILE_TOTALSIZE != 0 {
            read_value::<i64>(buffer, &mut offset)?.max(0) as u64
        } else {
            0
        };
        let allocated_bytes = if returned.fileattr & ATTR_FILE_ALLOCSIZE != 0 {
            read_value::<i64>(buffer, &mut offset)?.max(0) as u64
        } else {
            0
        };
        let private_reclaimable_bytes = if returned.forkattr & ATTR_CMNEXT_PRIVATESIZE != 0 {
            Some(read_value::<i64>(buffer, &mut offset)?.max(0) as u64)
        } else {
            None
        };
        let kind = match object_type {
            VREG => EntryKind::File,
            VDIR => EntryKind::Directory,
            _ => EntryKind::Other,
        };
        Ok(DirectoryEntryMeasurement {
            name,
            kind,
            file_id,
            link_count,
            file: (kind == EntryKind::File).then_some(FileMeasurement {
                logical_bytes,
                allocated_bytes,
                private_reclaimable_bytes,
            }),
        })
    }

    fn read_value<T: Copy>(buffer: &[u8], offset: &mut usize) -> io::Result<T> {
        let end = offset.checked_add(size_of::<T>()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "attribute offset overflow")
        })?;
        if end > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated attribute buffer",
            ));
        }
        let value = unsafe { (buffer.as_ptr().add(*offset) as *const T).read_unaligned() };
        *offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn inventory_aggregates_and_ranks_shallow_directories() {
        let temp = tempfile::tempdir().unwrap();
        let large = temp.path().join("large");
        let small = temp.path().join("small");
        fs::create_dir_all(large.join("nested")).unwrap();
        fs::create_dir_all(&small).unwrap();
        write_bytes(&large.join("nested/data"), 32 * 1024);
        write_bytes(&small.join("data"), 4 * 1024);

        let report = inventory(
            &[temp.path().to_path_buf()],
            InventoryOptions {
                display_depth: 2,
                top: 1,
                ..InventoryOptions::default()
            },
        )
        .unwrap();

        let root = &report.roots[0];
        assert!(root.complete);
        assert_eq!(root.metrics.files, 2);
        assert_eq!(root.metrics.directories, 4);
        assert_eq!(root.entries.len(), 2);
        assert_eq!(root.entries[0].relative_path, Path::new("large"));
        assert_eq!(root.entries[1].relative_path, Path::new("large/nested"));
    }

    #[test]
    fn inventory_stops_at_the_entry_budget() {
        let temp = tempfile::tempdir().unwrap();
        for index in 0..10 {
            write_bytes(&temp.path().join(format!("file-{index}")), 1);
        }
        let report = inventory(
            &[temp.path().to_path_buf()],
            InventoryOptions {
                max_entries: 3,
                ..InventoryOptions::default()
            },
        )
        .unwrap();
        assert!(!report.roots[0].complete);
        assert_eq!(report.roots[0].visited_entries, 3);
    }

    #[cfg(unix)]
    #[test]
    fn inventory_deduplicates_hardlinks() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        write_bytes(&first, 4096);
        fs::hard_link(&first, &second).unwrap();

        let report = inventory(&[temp.path().to_path_buf()], InventoryOptions::default()).unwrap();
        let metrics = &report.roots[0].metrics;
        assert_eq!(metrics.files, 1);
        assert_eq!(metrics.hardlink_duplicates, 1);
        #[cfg(target_os = "macos")]
        assert_eq!(metrics.private_reclaimable_bytes, metrics.allocated_bytes);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inventory_does_not_claim_private_bytes_for_an_external_hardlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let inside = root.join("inside");
        write_bytes(&inside, 4096);
        fs::hard_link(&inside, temp.path().join("outside")).unwrap();

        let report = inventory(&[root], InventoryOptions::default()).unwrap();
        let metrics = &report.roots[0].metrics;
        assert!(metrics.allocated_bytes >= 4096);
        assert_eq!(metrics.private_reclaimable_bytes, 0);
        assert!(metrics.private_reclaimable_complete);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn inventory_reports_apfs_private_bytes_for_an_ordinary_file() {
        let temp = tempfile::tempdir().unwrap();
        write_bytes(&temp.path().join("data"), 4096);

        let report = inventory(&[temp.path().to_path_buf()], InventoryOptions::default()).unwrap();
        let metrics = &report.roots[0].metrics;
        assert!(metrics.private_reclaimable_complete);
        assert!(metrics.private_reclaimable_bytes >= 4096);
        assert_eq!(metrics.private_reclaimable_bytes, metrics.allocated_bytes);
    }

    fn write_bytes(path: &Path, length: usize) {
        let mut file = File::create(path).unwrap();
        file.write_all(&vec![b'x'; length]).unwrap();
        file.sync_all().unwrap();
    }
}
