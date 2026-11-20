use crate::{host, plan::Plan};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

fn journal() -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join("m1-active.json"))
}
fn read_regular(path: &Path) -> Result<Option<File>, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("journal_open:{e}")),
    };
    let meta = f.metadata().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err("journal_reparse_point".into());
        }
    }
    if !meta.is_file() || meta.len() > 16384 {
        return Err("journal_not_regular_or_too_large".into());
    }
    Ok(Some(f))
}
pub fn load() -> Result<Option<Plan>, String> {
    let Some(f) = read_regular(&journal()?)? else {
        return Ok(None);
    };
    let plan: Plan =
        serde_json::from_reader(f.take(16385)).map_err(|e| format!("invalid_journal:{e}"))?;
    plan.validate()?;
    Ok(Some(plan))
}
pub(super) fn persist(plan: &Plan) -> Result<(), String> {
    if load()?.is_some() {
        return Err("recover_or_stop_existing_target_first".into());
    }
    let path = journal()?;
    let tmp = path.with_file_name(format!("m1-{:08x}.tmp", plan.cookie));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(|e| format!("journal_create:{e}"))?;
    let result = (|| {
        serde_json::to_writer(&mut f, plan)?;
        f.flush()?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(tmp);
        return Err(format!("journal_commit:{e}"));
    }
    Ok(())
}
pub(super) fn forget(plan: &Plan) -> Result<(), String> {
    if load()?.as_ref() != Some(plan) {
        return Err("journal_ownership_changed".into());
    }
    fs::remove_file(journal()?).map_err(|e| format!("journal_remove:{e}"))
}
