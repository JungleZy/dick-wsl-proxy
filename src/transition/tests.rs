// Transition state-machine tests.
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
        ipv6: None,
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
        assert!(begin_at(&path, &Record::default(), Kind::Start, None, Some(&plan(1))).is_err());
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

#[test]
fn abandon_clears_an_intent_at_any_stage_but_never_a_stale_one() {
    let directory = TempDir::new();
    let path = directory.journal();
    let idle = load_at(&path).unwrap();
    let releasing = begin_at(&path, &idle, Kind::Stop, Some(&plan(1)), None).unwrap();
    // A normal finish refuses to skip the old owner's release ...
    assert_eq!(
        finish_at(&path, &releasing).unwrap_err(),
        "transition_old_not_restored"
    );
    // ... the explicit abandon of an unregistered target does not.
    let cleared = abandon_at(&path, &releasing).unwrap();
    assert_eq!(cleared.pending, None);
    assert_eq!(cleared.generation, releasing.generation);
    assert_eq!(load_at(&path).unwrap(), cleared);
    // Repeating it is harmless; an outdated record is refused.
    assert_eq!(abandon_at(&path, &releasing).unwrap(), cleared);
    let next = begin_at(&path, &cleared, Kind::Stop, Some(&plan(2)), None).unwrap();
    assert_eq!(
        abandon_at(&path, &releasing).unwrap_err(),
        "transition_stale_record"
    );
    assert_eq!(load_at(&path).unwrap(), next);
}
