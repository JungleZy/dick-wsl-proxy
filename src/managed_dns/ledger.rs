use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{ALIAS_BLOCK, ALIAS_SPACE, ALIAS_START};
/// Serialized across processes by the controller's current-user exclusive
/// lock, and across the takeovers of one backend (decision 40) by
/// [`exclusive`]: each takeover's resolver has its own view and reloads the
/// map whenever another one appended to it. The
/// ledger contains a version marker and an allocated-address count. The
/// digest map contains no domain names or real IP addresses, only stable
/// name/IP digests and their reserved aliases. A leftover pending file is an
/// uncertain commit: it forbids every allocation. Only the explicit, confirmed
/// idle reset discards it, together with the whole ledger.
const MAP_MAGIC: &[u8; 4] = b"WDM1";
const MAP_RECORD_BYTES: usize = 36;
const MAX_MAP_BYTES: usize = 4 + MAP_RECORD_BYTES * ALIAS_SPACE as usize;
type AliasMaps = (HashMap<[u8; 32], u32>, HashMap<u32, [u8; 32]>);
#[cfg_attr(not(test), derive(Default))]
pub(super) struct AliasLedger {
    pub(super) path: Option<PathBuf>,
    pub(super) mapping_path: Option<PathBuf>,
    pub(super) next: u32,
    pub(super) end: u32,
    /// Offsets this session may allocate below; the rest of the range is
    /// left to fake-ip. `None` means the whole range.
    pub(super) limit: Option<u32>,
    assignments: HashMap<[u8; 32], u32>,
    used: HashMap<u32, [u8; 32]>,
    loaded: bool,
    /// The mapping file's length when this view read it.
    loaded_len: u64,
    #[cfg(test)]
    pub(super) cleanup: Option<PathBuf>,
}

/// Held from a lookup through the allocation to the record of new aliases,
/// so two takeovers never record the same name and address twice (a
/// duplicate makes every later load refuse the map).
pub(super) fn exclusive() -> std::sync::MutexGuard<'static, ()> {
    static LEDGER: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LEDGER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn file_len(path: &Path) -> Result<u64, String> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(format!("inspect DNS alias mapping: {error}")),
    }
}

#[cfg(test)]
impl Default for AliasLedger {
    fn default() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "wsl-proxyctl-dns-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            path: Some(root.join("dns-alias.highwater")),
            mapping_path: Some(root.join("dns-alias.map")),
            next: 0,
            end: 0,
            limit: None,
            assignments: HashMap::new(),
            used: HashMap::new(),
            loaded: false,
            loaded_len: 0,
            cleanup: Some(root),
        }
    }
}

impl AliasLedger {
    #[cfg(test)]
    pub(super) fn at(path: PathBuf) -> Self {
        Self {
            mapping_path: Some(path.with_extension("map")),
            path: Some(path),
            next: 0,
            end: 0,
            limit: None,
            assignments: HashMap::new(),
            used: HashMap::new(),
            loaded: false,
            loaded_len: 0,
            cleanup: None,
        }
    }

    fn ensure_loaded(&mut self) -> Result<(), String> {
        // The map only grows, by appends: a longer file means another
        // takeover recorded aliases since this view read it.
        if self.loaded
            && file_len(
                self.mapping_path
                    .as_deref()
                    .ok_or("DNS alias mapping path unavailable")?,
            )? == self.loaded_len
        {
            return Ok(());
        }
        if self.path.is_none() {
            self.path = Some(crate::host::state_dir()?.join("dns-alias.highwater"));
        }
        if self.mapping_path.is_none() {
            self.mapping_path = Some(crate::host::state_dir()?.join("dns-alias.map"));
        }
        let high = read_alias_highwater(
            self.path
                .as_deref()
                .ok_or("DNS alias ledger path unavailable")?,
        )?;
        let mapping = self
            .mapping_path
            .as_deref()
            .ok_or("DNS alias mapping path unavailable")?;
        let length = file_len(mapping)?;
        let (assignments, used) = read_alias_map(mapping, high)?;
        self.assignments = assignments;
        self.used = used;
        self.loaded = true;
        self.loaded_len = length;
        Ok(())
    }

    pub(super) fn key(name: &str, ip: Ipv4Addr) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"WPL-DNS-ALIAS-V1\0");
        digest.update((name.len() as u32).to_be_bytes());
        digest.update(name.as_bytes());
        digest.update(ip.octets());
        digest.finalize().into()
    }

    pub(super) fn lookup(&mut self, key: [u8; 32]) -> Result<Option<Ipv4Addr>, String> {
        self.ensure_loaded()?;
        Ok(self
            .assignments
            .get(&key)
            .map(|offset| Ipv4Addr::from(ALIAS_START + *offset)))
    }

    pub(super) fn record(
        &mut self,
        assignments: impl IntoIterator<Item = ([u8; 32], Ipv4Addr)>,
    ) -> Result<(), String> {
        self.ensure_loaded()?;
        let assignments: Vec<_> = assignments.into_iter().collect();
        if assignments.is_empty() {
            return Ok(());
        }
        let mut records = Vec::with_capacity(assignments.len());
        for (key, alias) in &assignments {
            let offset = u32::from(*alias)
                .checked_sub(ALIAS_START)
                .filter(|offset| *offset < ALIAS_SPACE)
                .ok_or("DNS alias mapping outside reserved range")?;
            if let Some(existing) = self.assignments.get(key)
                && *existing != offset
            {
                return Err("DNS alias mapping key changed unexpectedly".into());
            }
            if let Some(existing) = self.used.get(&offset)
                && existing != key
            {
                return Err("DNS alias mapping has an ambiguous address".into());
            }
            if offset >= self.end {
                return Err("DNS alias mapping exceeds durable high-water mark".into());
            }
            records.push((*key, offset));
        }
        let path = self
            .mapping_path
            .as_deref()
            .ok_or("DNS alias mapping path unavailable")?;
        let parent = path.parent().ok_or("DNS alias mapping has no parent")?;
        fs::create_dir_all(parent)
            .map_err(|e| format!("create DNS alias mapping directory: {e}"))?;
        let existing_len = match fs::metadata(path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("inspect DNS alias mapping: {error}")),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("open DNS alias mapping: {e}"))?;
        if existing_len == 0 {
            file.write_all(MAP_MAGIC)
                .map_err(|e| format!("write DNS alias mapping header: {e}"))?;
        }
        for (key, offset) in &records {
            file.write_all(key)
                .and_then(|_| file.write_all(&offset.to_be_bytes()))
                .map_err(|e| format!("write DNS alias mapping: {e}"))?;
        }
        file.sync_all()
            .map_err(|e| format!("sync DNS alias mapping: {e}"))?;
        for (key, offset) in records {
            self.assignments.insert(key, offset);
            self.used.insert(offset, key);
        }
        self.loaded_len = file_len(path)?;
        Ok(())
    }

    pub(super) fn allocate(&mut self, count: usize) -> Result<Vec<Ipv4Addr>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }
        self.ensure_loaded()?;
        let count = u32::try_from(count).map_err(|_| "DNS alias allocation exceeds range")?;
        if self.end - self.next < count {
            if self.path.is_none() {
                self.path = Some(crate::host::state_dir()?.join("dns-alias.highwater"));
            }
            let path = self
                .path
                .as_deref()
                .ok_or("DNS alias ledger path unavailable")?;
            let parent = path.parent().ok_or("DNS alias ledger has no parent")?;
            fs::create_dir_all(parent)
                .map_err(|e| format!("create DNS alias ledger directory: {e}"))?;
            let pending = path.with_extension("pending");
            match fs::symlink_metadata(&pending) {
                Ok(_) => return Err(
                    "DNS alias ledger has an uncertain pending commit; manual recovery required"
                        .into(),
                ),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("inspect DNS alias ledger pending commit: {e}")),
            }
            let high = read_alias_highwater(path)?;
            let space = self.limit.unwrap_or(ALIAS_SPACE).min(ALIAS_SPACE);
            if high > space || count > space - high {
                return Err(
                    "durable DNS alias range exhausted; automatic reset is forbidden".into(),
                );
            }
            let end = high
                + count
                    .div_ceil(ALIAS_BLOCK)
                    .saturating_mul(ALIAS_BLOCK)
                    .min(space - high);
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&pending)
                .map_err(|e| format!("create DNS alias ledger pending commit: {e}"))?;
            let mut bytes = *b"WDA1\0\0\0\0";
            bytes[4..].copy_from_slice(&end.to_be_bytes());
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| format!("sync DNS alias ledger commit: {e}"))?;
            drop(file);
            replace_alias_ledger(&pending, path)
                .map_err(|e| format!("commit DNS alias high-water ledger: {e}"))?;
            self.next = high;
            self.end = end;
        }
        let result = (self.next..self.next + count)
            .map(|offset| Ipv4Addr::from(ALIAS_START + offset))
            .collect();
        self.next += count;
        Ok(result)
    }

    pub(super) fn reset() -> Result<(), String> {
        let directory = crate::host::state_dir()?;
        let highwater = directory.join("dns-alias.highwater");
        let mapping = directory.join("dns-alias.map");
        let pending = directory.join("dns-alias.pending");
        Self::reset_paths(&highwater, &mapping, &pending)
    }

    #[cfg(test)]
    pub(super) fn reset_at(highwater: &Path) -> Result<(), String> {
        let mapping = highwater.with_extension("map");
        let pending = highwater.with_extension("pending");
        Self::reset_paths(highwater, &mapping, &pending)
    }

    /// Removes the ledger. The pending commit goes last: until it is gone, a
    /// crash midway still leaves a ledger that refuses every allocation.
    fn reset_paths(highwater: &Path, mapping: &Path, pending: &Path) -> Result<(), String> {
        let files = [
            (highwater, "high-water"),
            (mapping, "mapping"),
            (pending, "pending commit"),
        ];
        // Check all three before deleting any, so a foreign entry changes nothing.
        let mut present = Vec::with_capacity(files.len());
        for (path, label) in files {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("inspect DNS alias {label}: {error}")),
            };
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes()
                    & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
                {
                    return Err(format!("DNS alias {label} is a reparse point"));
                }
            }
            if !metadata.is_file() {
                return Err(format!("DNS alias {label} is not a regular file"));
            }
            present.push((path, label));
        }
        for (path, label) in present {
            fs::remove_file(path).map_err(|error| format!("remove DNS alias {label}: {error}"))?;
        }
        Ok(())
    }
}

fn read_alias_map(path: &Path, high: u32) -> Result<AliasMaps, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok((HashMap::new(), HashMap::new()));
        }
        Err(error) => return Err(format!("open DNS alias mapping: {error}")),
    };
    let mut bytes = Vec::new();
    file.take((MAX_MAP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("read DNS alias mapping: {e}"))?;
    if bytes.len() > MAX_MAP_BYTES || bytes.len() < MAP_MAGIC.len() || &bytes[..4] != MAP_MAGIC {
        return Err("corrupt DNS alias mapping; automatic reset is forbidden".into());
    }
    if !(bytes.len() - MAP_MAGIC.len()).is_multiple_of(MAP_RECORD_BYTES) {
        return Err("truncated DNS alias mapping; automatic reset is forbidden".into());
    }
    let mut assignments = HashMap::new();
    let mut used = HashMap::new();
    let (records, remainder) = bytes[MAP_MAGIC.len()..].as_chunks::<MAP_RECORD_BYTES>();
    debug_assert!(remainder.is_empty());
    for record in records {
        let key: [u8; 32] = record[..32]
            .try_into()
            .map_err(|_| "invalid DNS alias mapping key")?;
        let offset = u32::from_be_bytes(record[32..].try_into().unwrap());
        if offset >= high || offset >= ALIAS_SPACE {
            return Err(
                "DNS alias mapping is ahead of durable high-water; automatic reset is forbidden"
                    .into(),
            );
        }
        if assignments.insert(key, offset).is_some() || used.insert(offset, key).is_some() {
            return Err("duplicate DNS alias mapping; automatic reset is forbidden".into());
        }
    }
    Ok((assignments, used))
}

/// The ledger's current high-water offset from the controller's state
/// directory, 0 when there is no ledger yet.
pub(super) fn current_high() -> Result<u32, String> {
    // Tests never read the real controller's ledger.
    if cfg!(test) {
        return Ok(0);
    }
    read_alias_highwater(&crate::host::state_dir()?.join("dns-alias.highwater"))
}

pub(super) fn read_alias_highwater(path: &Path) -> Result<u32, String> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("open DNS alias ledger: {e}")),
    };
    let mut bytes = [0u8; 9];
    let mut read = 0;
    while read < bytes.len() {
        let count = file
            .read(&mut bytes[read..])
            .map_err(|e| format!("read DNS alias ledger: {e}"))?;
        if count == 0 {
            break;
        }
        read += count;
    }
    if read != 8 || &bytes[..4] != b"WDA1" {
        return Err("corrupt DNS alias ledger; automatic reset is forbidden".into());
    }
    let high = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if high == 0 || high > ALIAS_SPACE {
        return Err(
            "DNS alias ledger high-water outside range; automatic reset is forbidden".into(),
        );
    }
    Ok(high)
}

#[cfg(windows)]
fn replace_alias_ledger(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let source: Vec<_> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_alias_ledger(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    File::open(
        destination
            .parent()
            .ok_or_else(|| io::Error::other("DNS ledger parent missing"))?,
    )?
    .sync_all()
}

#[cfg(test)]
impl Drop for AliasLedger {
    fn drop(&mut self) {
        if let Some(root) = &self.cleanup {
            let _ = fs::remove_dir_all(root);
        }
    }
}
