//! The owner journal: the plan of a takeover whose rules may be in the target.
//! One per environment (decision 40), `m1-active-<scope>.json`; see
//! `transition::scope`.

use crate::{host, plan::Plan};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub(crate) const FILE_PREFIX: &str = "m1-active-";
const LEGACY_FILE_NAME: &str = "m1-active.json";

fn journal(scope: &str) -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join(format!("{FILE_PREFIX}{scope}.json")))
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
fn load_at(path: &Path) -> Result<Option<Plan>, String> {
    let Some(f) = read_regular(path)? else {
        return Ok(None);
    };
    let plan: Plan =
        serde_json::from_reader(f.take(16385)).map_err(|e| format!("invalid_journal:{e}"))?;
    plan.validate()?;
    Ok(Some(plan))
}
pub fn load(scope: &str) -> Result<Option<Plan>, String> {
    let plan = load_at(&journal(scope)?)?;
    if let Some(plan) = &plan
        && crate::transition::scope(&plan.target.id)? != scope
    {
        return Err("journal_scope_mismatch".into());
    }
    Ok(plan)
}
/// The single journal of a release before decision 40, if one is left.
pub(crate) fn load_legacy() -> Result<Option<Plan>, String> {
    load_legacy_in(&host::state_dir()?)
}
pub(crate) fn load_legacy_in(directory: &Path) -> Result<Option<Plan>, String> {
    load_at(&directory.join(LEGACY_FILE_NAME))
}
/// Moves the legacy journal in `directory` to `scope`'s; see
/// `transition::migrate_legacy`.
pub(crate) fn adopt_legacy_in(directory: &Path, scope: &str) -> Result<(), String> {
    let path = directory.join(format!("{FILE_PREFIX}{scope}.json"));
    if load_at(&path)?.is_some() {
        return Err("journal_legacy_conflict".into());
    }
    fs::rename(directory.join(LEGACY_FILE_NAME), path)
        .map_err(|e| format!("journal_legacy_move:{e}"))
}
pub(super) fn persist(plan: &Plan) -> Result<(), String> {
    let scope = crate::transition::scope(&plan.target.id)?;
    if load(&scope)?.is_some() {
        return Err("recover_or_stop_existing_target_first".into());
    }
    let path = journal(&scope)?;
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
    let scope = crate::transition::scope(&plan.target.id)?;
    if load(&scope)?.as_ref() != Some(plan) {
        return Err("journal_ownership_changed".into());
    }
    fs::remove_file(journal(&scope)?).map_err(|e| format!("journal_remove:{e}"))
}
