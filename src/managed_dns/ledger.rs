use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use super::{ALIAS_BLOCK, ALIAS_SPACE, ALIAS_START};
/// Serialized by the controller's existing current-user exclusive lock. The
/// ledger contains only a version marker and an allocated-address count. A
/// leftover pending file is an uncertain commit, never permission to reset.
#[cfg_attr(not(test), derive(Default))]
pub(super) struct AliasLedger {
    pub(super) path: Option<PathBuf>,
    pub(super) next: u32,
    pub(super) end: u32,
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
            next: 0,
            end: 0,
            cleanup: Some(root),
        }
    }
}

impl AliasLedger {
    #[cfg(test)]
    pub(super) fn at(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            next: 0,
            end: 0,
            cleanup: None,
        }
    }

    pub(super) fn allocate(&mut self, count: usize) -> Result<Vec<Ipv4Addr>, String> {
        if count == 0 {
            return Ok(Vec::new());
        }
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
