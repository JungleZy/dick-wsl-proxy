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
mod tests {
    use super::*;
    use crate::host::Distro;
    use std::net::{Ipv4Addr, SocketAddrV4};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "wsl-proxy-transition-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn journal(&self) -> PathBuf {
            self.0.join(FILE_NAME)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn plan(cookie: u32) -> Plan {
        Plan {
            target: Distro {
                id: format!("{{00000000-0000-0000-0000-{cookie:012x}}}"),
                name: "TransitionFixture".into(),
                base_path: r"D:\WSL\TransitionFixture".into(),
                version: 2,
            },
            cgroup_ns: "cgroup:[100]".into(),
            cgroup_root: "1:2".into(),
            boot_id: "00000000-0000-0000-0000-000000000001".into(),
            guest: Ipv4Addr::new(172, 20, 0, 2),
            ingress: SocketAddrV4::new(Ipv4Addr::new(172, 20, 0, 1), 1080),
            origins: vec![SocketAddrV4::new(Ipv4Addr::new(172, 20, 0, 2), 18080)],
            cookie,
            system_dns: None,
        }
    }

    fn start(path: &Path) -> Record {
        begin_at(
            path,
            &load_at(path).unwrap(),
            Kind::Start,
            None,
            Some(&plan(1)),
        )
        .unwrap()
    }

    #[test]
    fn legacy_absence_and_bootstrap_are_durable_idle_then_pending() {
        let dir = TempDir::new();
        let path = dir.0.join("new-state-directory").join(FILE_NAME);
        assert_eq!(load_at(&path).unwrap(), Record::default());
        assert_eq!(
            finish_at(&path, &Record::default()).unwrap(),
            Record::default()
        );
        assert!(!path.exists());
        let next = start(&path);
        assert_eq!(next.generation, 1);
        assert_eq!(load_at(&path).unwrap(), next);
        assert_eq!(fs::read_dir(path.parent().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn stale_generation_and_pending_intent_cannot_be_overwritten() {
        let dir = TempDir::new();
        let path = dir.journal();
        let initial = load_at(&path).unwrap();
        let pending = start(&path);
        assert_eq!(
            begin_at(&path, &initial, Kind::Start, None, Some(&plan(2))).unwrap_err(),
            "transition_stale_record"
        );
        let same_generation_idle = Record {
            generation: pending.generation,
            pending: None,
        };
        assert_eq!(
            begin_at(
                &path,
                &same_generation_idle,
                Kind::Start,
                None,
                Some(&plan(2))
            )
            .unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(
            begin_at(&path, &pending, Kind::Start, None, Some(&plan(2))).unwrap_err(),
            "transition_pending_intent"
        );
        let idle = finish_at(&path, &pending).unwrap();
        let newer = begin_at(&path, &idle, Kind::Start, None, Some(&plan(2))).unwrap();
        assert_eq!(
            finish_at(&path, &pending).unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(load_at(&path).unwrap(), newer);
    }

    #[test]
    fn switch_preserves_the_old_restored_gap_and_rejects_duplicate_stages() {
        let dir = TempDir::new();
        let path = dir.journal();
        let releasing = begin_at(
            &path,
            &Record::default(),
            Kind::Switch,
            Some(&plan(1)),
            Some(&plan(2)),
        )
        .unwrap();
        assert!(advance_at(&path, &releasing, Stage::StartingNew).is_err());
        assert_eq!(
            finish_at(&path, &releasing).unwrap_err(),
            "transition_old_not_restored"
        );
        let gap = advance_at(&path, &releasing, Stage::OldRestored).unwrap();
        assert_eq!(load_at(&path).unwrap(), gap);
        assert_eq!(gap.pending.as_ref().unwrap().old, Some(plan(1)));
        assert_eq!(gap.pending.as_ref().unwrap().new, Some(plan(2)));
        assert_eq!(
            advance_at(&path, &releasing, Stage::OldRestored).unwrap_err(),
            "transition_stale_record"
        );
        assert!(advance_at(&path, &gap, Stage::OldRestored).is_err());
        let starting = advance_at(&path, &gap, Stage::StartingNew).unwrap();
        assert!(advance_at(&path, &starting, Stage::OldRestored).is_err());
        assert_eq!(load_at(&path).unwrap(), starting);
        assert_eq!(
            finish_at(&path, &gap).unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(finish_at(&path, &starting).unwrap().generation, 1);
    }

    #[test]
    fn stop_and_cancelled_switch_finish_only_after_old_restored() {
        for kind in [Kind::Stop, Kind::Switch] {
            let dir = TempDir::new();
            let path = dir.journal();
            let new = plan(2);
            let releasing = begin_at(
                &path,
                &Record::default(),
                kind,
                Some(&plan(1)),
                (kind == Kind::Switch).then_some(&new),
            )
            .unwrap();
            let restored = advance_at(&path, &releasing, Stage::OldRestored).unwrap();
            if kind == Kind::Stop {
                assert!(advance_at(&path, &restored, Stage::StartingNew).is_err());
            }
            assert!(finish_at(&path, &restored).unwrap().pending.is_none());
        }
    }

    #[test]
    fn finish_is_idempotent_and_generation_increments_only_at_begin() {
        let dir = TempDir::new();
        let path = dir.journal();
        let pending = start(&path);
        let idle = finish_at(&path, &pending).unwrap();
        assert_eq!(finish_at(&path, &pending).unwrap(), idle);
        assert_eq!(finish_at(&path, &idle).unwrap(), idle);
        let next = begin_at(&path, &idle, Kind::Start, None, Some(&plan(2))).unwrap();
        assert_eq!(next.generation, 2);
        assert_eq!(
            begin_at(&path, &idle, Kind::Start, None, Some(&plan(2))).unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(load_at(&path).unwrap(), next);
    }

    #[test]
    fn generation_overflow_does_not_change_disk() {
        let dir = TempDir::new();
        let path = dir.journal();
        let exhausted = Record {
            generation: u64::MAX,
            pending: None,
        };
        fs::write(&path, serde_json::to_vec(&exhausted).unwrap()).unwrap();
        assert_eq!(
            begin_at(&path, &exhausted, Kind::Start, None, Some(&plan(1))).unwrap_err(),
            "transition_generation_exhausted"
        );
        assert_eq!(load_at(&path).unwrap(), exhausted);
    }

    #[test]
    fn corrupt_incomplete_and_invalid_states_are_refused() {
        let dir = TempDir::new();
        let path = dir.journal();
        for bytes in [
            "",
            "{",
            "{}",
            r#"{"generation":1}"#,
            r#"{"pending":null}"#,
            r#"{"generation":1,"pending":null,"extra":true}"#,
            r#"{"generation":1,"pending":null} trailing"#,
            r#"{"generation":1,"pending":{"kind":"stop","stage":"releasing_old","old":null}}"#,
        ] {
            fs::write(&path, bytes).unwrap();
            assert!(load_at(&path).is_err(), "accepted {bytes:?}");
            assert!(
                begin_at(&path, &Record::default(), Kind::Start, None, Some(&plan(1))).is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), bytes.as_bytes());
        }
        for (generation, kind, stage, old, new) in [
            (0, Kind::Start, Stage::StartingNew, None, Some(plan(1))),
            (1, Kind::Start, Stage::ReleasingOld, None, Some(plan(1))),
            (1, Kind::Stop, Stage::StartingNew, Some(plan(1)), None),
            (1, Kind::Switch, Stage::OldRestored, Some(plan(1)), None),
            (1, Kind::Start, Stage::StartingNew, None, Some(plan(0))),
        ] {
            let record = Record {
                generation,
                pending: Some(Intent {
                    kind,
                    stage,
                    old,
                    new,
                }),
            };
            fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
            assert!(load_at(&path).is_err());
        }
    }

    #[test]
    fn missing_nullable_intent_fields_are_not_treated_as_null() {
        let dir = TempDir::new();
        let path = dir.journal();
        for (kind, field) in [(Kind::Start, "old"), (Kind::Stop, "new")] {
            let record = Record {
                generation: 1,
                pending: Some(Intent {
                    kind,
                    stage: if kind == Kind::Start {
                        Stage::StartingNew
                    } else {
                        Stage::ReleasingOld
                    },
                    old: (kind == Kind::Stop).then(|| plan(1)),
                    new: (kind == Kind::Start).then(|| plan(1)),
                }),
            };
            let mut value = serde_json::to_value(record).unwrap();
            value["pending"].as_object_mut().unwrap().remove(field);
            fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            assert!(load_at(&path).is_err(), "missing {field} accepted");
        }
    }

    #[test]
    fn oversized_state_and_oversized_new_intent_do_not_publish() {
        let dir = TempDir::new();
        let path = dir.journal();
        fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap();
        assert!(load_at(&path).is_err());
        fs::remove_file(&path).unwrap();
        let mut oversized_old = plan(1);
        oversized_old.target.base_path = "x".repeat(32768);
        let mut oversized_new = plan(2);
        oversized_new.target.base_path = "x".repeat(32768);
        let error = begin_at(
            &path,
            &Record::default(),
            Kind::Switch,
            Some(&oversized_old),
            Some(&oversized_new),
        )
        .unwrap_err();
        assert!(error.contains("transition_too_large"));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
    }

    #[test]
    fn same_generation_changed_plan_cannot_finish_current_intent() {
        let dir = TempDir::new();
        let path = dir.journal();
        let pending = start(&path);
        let mut stale = pending.clone();
        stale.pending.as_mut().unwrap().new = Some(plan(2));
        assert_eq!(
            finish_at(&path, &stale).unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(load_at(&path).unwrap(), pending);
    }

    #[test]
    fn failed_atomic_bootstrap_does_not_publish_or_consume_generation() {
        let dir = TempDir::new();
        let path = dir.journal();
        let idle = Record::default();
        let pending = Record {
            generation: 1,
            pending: Some(Intent {
                kind: Kind::Start,
                stage: Stage::StartingNew,
                old: None,
                new: Some(plan(1)),
            }),
        };
        let error = persist_with(&path, &idle, &pending, |_, _| {
            Err(io::Error::other("injected_bootstrap_failure"))
        })
        .unwrap_err();
        assert!(error.starts_with("transition_commit_ambiguous_reload_required:"));
        assert_eq!(load_at(&path).unwrap(), idle);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 0);
        assert_eq!(start(&path).generation, 1);
    }

    #[test]
    fn atomic_failure_preserves_prior_state_and_cleans_temporary() {
        let dir = TempDir::new();
        let path = dir.journal();
        let pending = start(&path);
        let idle = Record {
            generation: pending.generation,
            pending: None,
        };
        let error = persist_with(&path, &pending, &idle, |_, _| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected_before_replace",
            ))
        })
        .unwrap_err();
        assert!(error.starts_with("transition_commit_ambiguous_reload_required:"));
        assert_eq!(load_at(&path).unwrap(), pending);
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn ambiguous_commit_requires_reload_and_never_replays_stale_expected() {
        let dir = TempDir::new();
        let path = dir.journal();
        let idle = Record::default();
        let pending = Record {
            generation: 1,
            pending: Some(Intent {
                kind: Kind::Start,
                stage: Stage::StartingNew,
                old: None,
                new: Some(plan(1)),
            }),
        };
        let error = persist_with(&path, &idle, &pending, |temporary, destination| {
            atomic_replace(temporary, destination)?;
            Err(io::Error::other("injected_after_replace"))
        })
        .unwrap_err();
        assert!(error.starts_with("transition_commit_ambiguous_reload_required:"));
        assert_eq!(load_at(&path).unwrap(), pending);
        assert_eq!(
            begin_at(&path, &idle, Kind::Start, None, Some(&plan(2))).unwrap_err(),
            "transition_stale_record"
        );
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }

    #[test]
    fn directory_or_journal_non_regular_state_is_refused() {
        let dir = TempDir::new();
        let path = dir.journal();
        fs::create_dir(&path).unwrap();
        assert!(load_at(&path).is_err());
        assert!(begin_at(&path, &Record::default(), Kind::Start, None, Some(&plan(1))).is_err());
        let file_parent = dir.0.join("file-parent");
        fs::write(&file_parent, b"not a directory").unwrap();
        assert!(load_at(&file_parent.join(FILE_NAME)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_journal_and_directory_are_refused_without_following() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new();
        let target = dir.0.join("target.json");
        fs::write(&target, br#"{"generation":7,"pending":null}"#).unwrap();
        let path = dir.journal();
        symlink(&target, &path).unwrap();
        assert!(load_at(&path).is_err());
        assert!(begin_at(&path, &Record::default(), Kind::Start, None, Some(&plan(1))).is_err());
        assert_eq!(
            fs::read(&target).unwrap(),
            br#"{"generation":7,"pending":null}"#
        );
        let directory_link = dir.0.join("directory-link");
        symlink(&dir.0, &directory_link).unwrap();
        assert!(load_at(&directory_link.join(FILE_NAME)).is_err());
    }
}
