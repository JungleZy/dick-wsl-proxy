use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{ALIAS_BLOCK, ALIAS_SPACE, ALIAS_START};
/// Serialized by the controller's existing current-user exclusive lock. The
/// ledger contains a version marker and an allocated-address count. The
/// digest map contains no domain names or real IP addresses, only stable
/// name/IP digests and their reserved aliases. A leftover pending file is an
/// uncertain commit, never permission to reset.
const MAP_MAGIC: &[u8; 4] = b"WDM1";
const MAP_RECORD_BYTES: usize = 36;
const MAX_MAP_BYTES: usize = 4 + MAP_RECORD_BYTES * ALIAS_SPACE as usize;
#[cfg_attr(not(test), derive(Default))]
pub(super) struct AliasLedger {
    pub(super) path: Option<PathBuf>,
    pub(super) mapping_path: Option<PathBuf>,
    pub(super) next: u32,
    pub(super) end: u32,
    assignments: HashMap<[u8; 32], u32>,
    used: HashMap<u32, [u8; 32]>,
    loaded: bool,
    #[cfg(test)]
    pub(super) cleanup: Option<PathBuf>,
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
            assignments: HashMap::new(),
            used: HashMap::new(),
            loaded: false,
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
            assignments: HashMap::new(),
            used: HashMap::new(),
            loaded: false,
            cleanup: None,
        }
    }

    fn ensure_loaded(&mut self) -> Result<(), String> {
        if self.loaded {
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
        let (assignments, used) = read_alias_map(
            self.mapping_path
                .as_deref()
                .ok_or("DNS alias mapping path unavailable")?,
            high,
        )?;
        self.assignments = assignments;
        self.used = used;
        self.loaded = true;
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
            if count > ALIAS_SPACE - high {
                return Err(
                    "durable DNS alias range exhausted; automatic reset is forbidden".into(),
                );
            }
            let end = high
                + count
                    .div_ceil(ALIAS_BLOCK)
                    .saturating_mul(ALIAS_BLOCK)
                    .min(ALIAS_SPACE - high);
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
}

fn read_alias_map(
    path: &Path,
    high: u32,
) -> Result<(HashMap<[u8; 32], u32>, HashMap<u32, [u8; 32]>), String> {
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
    if (bytes.len() - MAP_MAGIC.len()) % MAP_RECORD_BYTES != 0 {
        return Err("truncated DNS alias mapping; automatic reset is forbidden".into());
    }
    let mut assignments = HashMap::new();
    let mut used = HashMap::new();
    for record in bytes[MAP_MAGIC.len()..].chunks_exact(MAP_RECORD_BYTES) {
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
