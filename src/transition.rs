//! Durable transition intent, independent of the immutable active-session journal.
//! Callers hold the current-user controller lock and mutate guests only after a write succeeds.
use crate::{host, m1::Plan};
use serde::{Deserialize, Deserializer, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_BYTES: usize = 64 * 1024;
const FILE_NAME: &str = "m3-operation.json";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub generation: u64,
    #[serde(deserialize_with = "required_option")]
    pub pending: Option<Intent>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub kind: Kind,
    pub stage: Stage,
    #[serde(deserialize_with = "required_option")]
    pub old: Option<Plan>,
    #[serde(deserialize_with = "required_option")]
    pub new: Option<Plan>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Start,
    Stop,
    Switch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    ReleasingOld,
    OldRestored,
    StartingNew,
}

// Unlike serde's default Option handling, missing durable fields are not an idle state.
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

fn validate(record: &Record) -> Result<(), String> {
    let Some(intent) = &record.pending else {
        return Ok(());
    };
    if record.generation == 0 {
        return Err("transition_pending_without_generation".into());
    }
    let valid = match intent.kind {
        Kind::Start => {
            intent.old.is_none() && intent.new.is_some() && intent.stage == Stage::StartingNew
        }
        Kind::Stop => {
            intent.old.is_some() && intent.new.is_none() && intent.stage != Stage::StartingNew
        }
        Kind::Switch => matches!((&intent.old,&intent.new),(Some(old),Some(new))
            if !old.target.id.eq_ignore_ascii_case(&new.target.id) && old.cookie!=new.cookie),
    };
    if !valid {
        return Err("transition_invalid_intent".into());
    }
    for plan in intent.old.iter().chain(intent.new.iter()) {
        plan.validate()
            .map_err(|error| format!("transition_invalid_plan:{error}"))?;
    }
    Ok(())
}

fn journal() -> Result<PathBuf, String> {
    Ok(host::state_dir()?.join(FILE_NAME))
}

fn is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn directory(path: &Path, create: bool) -> Result<bool, String> {
    let parent = path.parent().ok_or("transition_parent_missing")?;
    if create {
        match fs::create_dir(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("transition_directory_create:{error}")),
        }
    }
    let metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("transition_directory_metadata:{error}")),
    };
    if !metadata.is_dir() || is_reparse(&metadata) {
        return Err("transition_directory_not_regular".into());
    }
    Ok(true)
}

fn load_at(path: &Path) -> Result<Record, String> {
    if !directory(path, false)? {
        return Ok(Record::default());
    }
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Record::default()),
        Err(error) => return Err(format!("transition_metadata:{error}")),
    };
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_BYTES as u64 {
        return Err("transition_not_regular_or_too_large".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("transition_open:{error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("transition_handle_metadata:{error}"))?;
    if !metadata.is_file() || is_reparse(&metadata) || metadata.len() > MAX_BYTES as u64 {
        return Err("transition_not_regular_or_too_large".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("transition_read:{error}"))?;
    if bytes.len() > MAX_BYTES {
        return Err("transition_too_large".into());
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|error| format!("transition_invalid_json:{error}"))?;
    validate(&record)?;
    Ok(record)
}

/// Absence is the legacy, generation-zero idle state; malformed state is never ignored.
pub fn load() -> Result<Record, String> {
    load_at(&journal()?)
}

struct BoundedBytes(Vec<u8>);

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::Error::other("transition_too_large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(windows)]
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let wide = |path: &Path| -> io::Result<Vec<u16>> {
        let mut value: Vec<u16> = path.as_os_str().encode_wide().collect();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path_contains_nul",
            ));
        }
        value.push(0);
        Ok(value)
    };
    let source = wide(source)?;
    let destination = wide(destination)?;
    // This also handles the first publication: no non-durable bootstrap rename exists.
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
pub(crate) fn atomic_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    fs::File::open(
        destination
            .parent()
            .ok_or_else(|| io::Error::other("parent_missing"))?,
    )?
    .sync_all()
}

fn persist_with(
    path: &Path,
    expected: &Record,
    next: &Record,
    replace: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<(), String> {
    validate(expected)?;
    validate(next)?;
    directory(path, true)?;
    if load_at(path)? != *expected {
        return Err("transition_stale_record".into());
    }
    let mut bytes = BoundedBytes(Vec::new());
    serde_json::to_writer(&mut bytes, next)
        .map_err(|error| format!("transition_encode:{error}"))?;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let temporary = path.with_file_name(format!(
        "m3-transition-{}-{}.tmp",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("transition_create:{error}"))?;
    let result = (|| {
        file.write_all(&bytes.0)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("transition_write:{error}"))?;
        drop(file);
        // Any failure here is ambiguous: publication may have succeeded before durability failed.
        replace(&temporary, path)
            .map_err(|error| format!("transition_commit_ambiguous_reload_required:{error}"))
    })();
    if let Err(error) = result {
        return match fs::remove_file(&temporary) {
            Ok(()) => Err(error),
            Err(cleanup) if cleanup.kind() == io::ErrorKind::NotFound => Err(error),
            Err(cleanup) => Err(format!("{error};transition_temporary_cleanup:{cleanup}")),
        };
    }
    Ok(())
}

fn persist(path: &Path, expected: &Record, next: &Record) -> Result<(), String> {
    persist_with(path, expected, next, atomic_replace)
}

fn begin_at(
    path: &Path,
    expected: &Record,
    kind: Kind,
    old: Option<&Plan>,
    new: Option<&Plan>,
) -> Result<Record, String> {
    if expected.pending.is_some() {
        return Err("transition_pending_intent".into());
    }
    let next = Record {
        generation: expected
            .generation
            .checked_add(1)
            .ok_or("transition_generation_exhausted")?,
        pending: Some(Intent {
            kind,
            stage: if kind == Kind::Start {
                Stage::StartingNew
            } else {
                Stage::ReleasingOld
            },
            old: old.cloned(),
            new: new.cloned(),
        }),
    };
    persist(path, expected, &next)?;
    Ok(next)
}

/// Persist the next generation before any release, install, or activation of ownership.
pub fn begin(
    expected: &Record,
    kind: Kind,
    old: Option<&Plan>,
    new: Option<&Plan>,
) -> Result<Record, String> {
    begin_at(&journal()?, expected, kind, old, new)
}

fn advance_at(path: &Path, expected: &Record, stage: Stage) -> Result<Record, String> {
    let mut next = expected.clone();
    let intent = next
        .pending
        .as_mut()
        .ok_or("transition_no_pending_intent")?;
    if !matches!(
        (intent.kind, intent.stage, stage),
        (_, Stage::ReleasingOld, Stage::OldRestored)
            | (Kind::Switch, Stage::OldRestored, Stage::StartingNew)
    ) {
        return Err("transition_invalid_stage_change".into());
    }
    intent.stage = stage;
    persist(path, expected, &next)?;
    Ok(next)
}

/// Record old ownership restored before opening the gap or starting the next owner.
pub fn advance(expected: &Record, stage: Stage) -> Result<Record, String> {
    advance_at(&journal()?, expected, stage)
}

fn finish_at(path: &Path, expected: &Record) -> Result<Record, String> {
    validate(expected)?;
    if expected
        .pending
        .as_ref()
        .is_some_and(|intent| intent.stage == Stage::ReleasingOld)
    {
        return Err("transition_old_not_restored".into());
    }
    let actual = load_at(path)?;
    let next = Record {
        generation: expected.generation,
        pending: None,
    };
    if actual == next {
        return Ok(next);
    }
    if actual != *expected {
        return Err("transition_stale_record".into());
    }
    persist(path, expected, &next)?;
    Ok(next)
}

/// Clear completed or safely rolled-back intent, retaining its generation for stale callers.
/// Retrying a successful finish is harmless; an old-owner release cannot be finished early.
pub fn finish(expected: &Record) -> Result<Record, String> {
    finish_at(&journal()?, expected)
}
#[cfg(test)]
#[path = "transition/tests.rs"]
mod tests;
