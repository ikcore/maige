//! One durable journal holds both encrypted generations. Until the committed
//! journal is durable, recovery always restores the old generation. Recovery
//! never consumes backups, so it can itself be interrupted and safely retried.
use crate::{
    atomic_file, crypto,
    store::{validate_realm_name, Store, VarMap},
};
use anyhow::{bail, Context, Result};
use blake2::{Blake2s256, Digest};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, path::Path};
use zeroize::{Zeroize, Zeroizing};

const JOURNAL: &str = ".rotation.json";

/// Detect accidental corruption before replaying any backup. This checksum is
/// not authentication against someone who can rewrite the store directory.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    checksum: Vec<u8>,
    payload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    old: String,
    new: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    state: State,
    realms: BTreeMap<String, Replacement>,
    verify: Replacement,
}

#[derive(Serialize, Deserialize, PartialEq)]
enum State {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Staged,
    Realm(usize),
    Verify,
    Committed,
    Restored(usize),
}

fn read_journal(store: &Store) -> Result<Option<Journal>> {
    let bytes = match fs::read(store.root().join(JOURNAL)) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let envelope: Envelope = serde_json::from_slice(&bytes).context("Invalid rotation journal")?;
    if Blake2s256::digest(envelope.payload.as_bytes()).as_slice() != envelope.checksum {
        bail!("Rotation journal checksum mismatch");
    }
    let journal: Journal =
        serde_json::from_str(&envelope.payload).context("Invalid rotation journal")?;
    if journal.version != 1 {
        bail!("Unsupported rotation journal version");
    }
    // Validate the entire manifest before modifying any destination.
    for name in journal.realms.keys() {
        validate_realm_name(name)?;
    }
    Ok(Some(journal))
}

fn save_journal(store: &Store, journal: &Journal) -> Result<()> {
    let payload = serde_json::to_string(journal)?;
    let envelope = Envelope {
        checksum: Blake2s256::digest(payload.as_bytes()).to_vec(),
        payload,
    };
    atomic_file::write(&store.root().join(JOURNAL), &serde_json::to_vec(&envelope)?)
        .context("Failed to persist key rotation journal")
}

fn restore(path: &Path, contents: &str) -> Result<()> {
    // Do not require another write when a prior attempt already restored it.
    match fs::read(path) {
        Ok(existing) if existing == contents.as_bytes() => {
            atomic_file::sync_dir(path.parent().context("Missing parent directory")?)?;
            return Ok(());
        }
        Ok(_) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    atomic_file::write(path, contents.as_bytes())
        .with_context(|| format!("Failed to restore {}", path.display()))
}

pub(crate) fn recover(store: &Store) -> Result<()> {
    recover_with(store, |_| Ok(()))
}

fn recover_with(store: &Store, mut checkpoint: impl FnMut(Step) -> Result<()>) -> Result<()> {
    let Some(mut journal) = read_journal(store)? else {
        return Ok(());
    };
    if journal.state == State::Prepared {
        for (index, (name, replacement)) in journal.realms.iter().enumerate() {
            restore(&store.realm_path(name), &replacement.old)?;
            checkpoint(Step::Restored(index))?;
        }
        restore(&store.verify_path(), &journal.verify.old)?;
        // Persist a terminal state before deletion. Even if deletion is lost on
        // power failure, a reappearing journal cannot undo subsequent writes.
        journal.state = State::RolledBack;
        save_journal(store, &journal)?;
    }
    // All replacements were flushed before commit. A committed journal needs
    // only cleanup; replaying it could overwrite later legitimate changes.
    fs::remove_file(store.root().join(JOURNAL))?;
    atomic_file::sync_dir(store.root())?;
    Ok(())
}

fn stage(
    path: &Path,
    old_passphrase: &str,
    new_passphrase: &str,
    realm: bool,
) -> Result<Replacement> {
    let old = fs::read_to_string(path)?;
    let plaintext = Zeroizing::new(crypto::decrypt(old.trim(), old_passphrase)?);
    if realm {
        let vars = serde_json::from_slice::<VarMap>(&plaintext).context("Invalid realm JSON")?;
        for (mut key, mut value) in vars {
            key.zeroize();
            value.zeroize();
        }
    } else if plaintext.as_slice() != b"maige-verify" {
        bail!("Invalid verification token");
    }
    let new = crypto::encrypt(&plaintext, new_passphrase)?;
    Ok(Replacement { old, new })
}

pub(crate) fn rotate(store: &Store, old_passphrase: &str, new_passphrase: &str) -> Result<()> {
    rotate_with(store, old_passphrase, new_passphrase, |_| Ok(()))
        .context("Key rotation did not finish cleanly. Retry a store command to recover; use the old passphrase if rotation was not committed, otherwise the new passphrase")
}

fn rotate_with(
    store: &Store,
    old_passphrase: &str,
    new_passphrase: &str,
    mut checkpoint: impl FnMut(Step) -> Result<()>,
) -> Result<()> {
    if new_passphrase.is_empty() {
        bail!("New passphrase cannot be empty");
    }
    if !store.verify_passphrase_unlocked(old_passphrase)? {
        bail!("Incorrect current passphrase");
    }
    let mut journal = Journal {
        version: 1,
        state: State::Prepared,
        realms: BTreeMap::new(),
        verify: stage(&store.verify_path(), old_passphrase, new_passphrase, false)?,
    };
    for name in store.list_realms_unlocked()? {
        validate_realm_name(&name)?;
        let replacement = stage(
            &store.realm_path(&name),
            old_passphrase,
            new_passphrase,
            true,
        )
        .with_context(|| format!("Failed to stage realm '{}'", name))?;
        journal.realms.insert(name, replacement);
    }
    save_journal(store, &journal)?;
    // Verify the staged ciphertext as read from disk before touching live files.
    journal = read_journal(store)?.context("Rotation journal disappeared")?;
    for replacement in journal
        .realms
        .values()
        .chain(std::iter::once(&journal.verify))
    {
        let old = Zeroizing::new(crypto::decrypt(replacement.old.trim(), old_passphrase)?);
        let new = Zeroizing::new(crypto::decrypt(&replacement.new, new_passphrase)?);
        if old.as_slice() != new.as_slice() {
            bail!("Staged rotation data does not match original");
        }
    }
    checkpoint(Step::Staged)?;
    for (index, (name, replacement)) in journal.realms.iter().enumerate() {
        atomic_file::write(&store.realm_path(name), replacement.new.as_bytes())?;
        checkpoint(Step::Realm(index))?;
    }
    atomic_file::write(&store.verify_path(), journal.verify.new.as_bytes())?;
    checkpoint(Step::Verify)?;
    journal.state = State::Committed;
    save_journal(store, &journal)?;
    checkpoint(Step::Committed)?;
    recover(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    const OLD: &str = "old-rotation-test-passphrase";
    const NEW: &str = "new-rotation-test-passphrase";

    fn setup() -> (tempfile::TempDir, Store, VarMap) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf());
        store.initialize(OLD).unwrap();
        let vars = BTreeMap::from([("SECRET".to_string(), "preserved secret value".to_string())]);
        store.save_realm("a", &vars, OLD).unwrap();
        store.save_realm("b", &vars, OLD).unwrap();
        (dir, store, vars)
    }

    fn interrupt(store: &Store, step: Step) {
        let _lock = store.lock_and_recover().unwrap();
        let result = rotate_with(store, OLD, NEW, |at| {
            if at == step {
                bail!("simulated interruption");
            }
            Ok(())
        });
        assert!(result.is_err());
        assert!(store.root().join(JOURNAL).exists());
    }

    fn assert_generation(store: &Store, passphrase: &str, vars: &VarMap) {
        assert!(store.verify_passphrase(passphrase).unwrap());
        assert_eq!(&store.load_realm("a", passphrase).unwrap(), vars);
        assert_eq!(&store.load_realm("b", passphrase).unwrap(), vars);
        assert!(!store.root().join(JOURNAL).exists());
    }

    // Executed only by the child-process test below. Exit without unwinding to
    // model abrupt process death, including the OS releasing the store lock.
    #[test]
    fn crash_worker() {
        let Ok(root) = std::env::var("MAIGE_TEST_CRASH_ROOT") else {
            return;
        };
        let target = std::env::var("MAIGE_TEST_CRASH_STEP").unwrap();
        let store = Store::new(root.into());
        let _lock = store.lock_and_recover().unwrap();
        rotate_with(&store, OLD, NEW, |at| {
            if format!("{at:?}") == target {
                std::process::exit(86);
            }
            Ok(())
        })
        .unwrap();
        panic!("Crash checkpoint was not reached");
    }

    #[test]
    fn process_death_at_every_rotation_boundary_recovers_one_complete_generation() {
        for step in [
            Step::Staged,
            Step::Realm(0),
            Step::Realm(1),
            Step::Verify,
            Step::Committed,
        ] {
            let (_dir, store, vars) = setup();
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "rotation::tests::crash_worker", "--nocapture"])
                .env("MAIGE_TEST_CRASH_ROOT", store.root())
                .env("MAIGE_TEST_CRASH_STEP", format!("{step:?}"))
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(86), "{step:?}: {output:?}");
            let journal = fs::read_to_string(store.root().join(JOURNAL)).unwrap();
            assert!(!journal.contains("preserved secret value"));
            assert!(!journal.contains(OLD));
            assert!(!journal.contains(NEW));
            // A new Store instance represents the next invocation of Maige.
            let reopened = Store::new(store.root().to_path_buf());
            let (accepted, rejected) = if step == Step::Committed {
                (NEW, OLD)
            } else {
                (OLD, NEW)
            };
            assert_generation(&reopened, accepted, &vars);
            assert!(!reopened.verify_passphrase(rejected).unwrap());
        }
    }

    #[test]
    fn interrupted_recovery_can_be_retried_without_consuming_backups() {
        let (_dir, store, vars) = setup();
        interrupt(&store, Step::Verify);
        let original_journal = fs::read(store.root().join(JOURNAL)).unwrap();
        for _ in 0..2 {
            assert!(recover_with(&store, |at| {
                if at == Step::Restored(0) {
                    bail!("recovery interrupted");
                }
                Ok(())
            })
            .is_err());
            assert_eq!(
                fs::read(store.root().join(JOURNAL)).unwrap(),
                original_journal
            );
        }
        assert_generation(&store, OLD, &vars);
    }

    #[test]
    fn failed_recovery_retains_journal_and_blocks_store_operations() {
        let (_dir, store, vars) = setup();
        interrupt(&store, Step::Realm(0));
        let path = store.realm_path("a");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        let original_permissions = permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let result = store.save_realm("unrelated", &vars, OLD);
        fs::set_permissions(&path, original_permissions).unwrap();
        assert!(result.is_err());
        assert!(store.root().join(JOURNAL).exists());
        assert!(!store.realm_path("unrelated").exists());
        assert_generation(&store, OLD, &vars);
    }

    #[test]
    fn actual_replacement_error_rolls_back_completed_realm_writes() {
        let (_dir, store, vars) = setup();
        let path = store.realm_path("b");
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        let original_permissions = permissions.clone();
        permissions.set_readonly(true);
        fs::set_permissions(&path, permissions).unwrap();
        let result = store.rotate_key(OLD, NEW);
        fs::set_permissions(&path, original_permissions).unwrap();
        assert!(result.is_err());
        // The first realm really was replaced before the second write failed.
        assert!(crypto::decrypt_from_file(&store.realm_path("a"), NEW).is_ok());
        assert_generation(&store, OLD, &vars);
    }

    #[test]
    fn staging_failure_never_changes_live_files() {
        let (_dir, store, _) = setup();
        fs::write(store.realm_path("b"), b"broken ciphertext").unwrap();
        let original = fs::read(store.realm_path("a")).unwrap();
        let verify = fs::read(store.verify_path()).unwrap();
        assert!(store.rotate_key(OLD, NEW).is_err());
        assert_eq!(fs::read(store.realm_path("a")).unwrap(), original);
        assert_eq!(fs::read(store.verify_path()).unwrap(), verify);
        assert_eq!(
            fs::read(store.realm_path("b")).unwrap(),
            b"broken ciphertext"
        );
        assert!(!store.root().join(JOURNAL).exists());
    }

    #[test]
    fn stale_writer_cannot_restore_old_key_after_successful_rotation() {
        let (_dir, store, vars) = setup();
        store.rotate_key(OLD, NEW).unwrap();
        let original = fs::read(store.realm_path("a")).unwrap();
        assert!(store.save_realm("a", &vars, OLD).is_err());
        assert!(store.save_realm("new-realm", &vars, OLD).is_err());
        assert_eq!(fs::read(store.realm_path("a")).unwrap(), original);
        assert!(!store.realm_path("new-realm").exists());
        assert_generation(&store, NEW, &vars);
    }

    #[test]
    fn empty_store_rotation_requires_correct_old_and_nonempty_new_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().to_path_buf());
        store.initialize(OLD).unwrap();
        let verify = fs::read(store.verify_path()).unwrap();
        assert!(store.rotate_key("wrong", NEW).is_err());
        assert!(store.rotate_key(OLD, "").is_err());
        assert_eq!(fs::read(store.verify_path()).unwrap(), verify);
    }

    #[test]
    fn malformed_journal_is_retained_without_modifying_realms() {
        let (_dir, store, _) = setup();
        let original = fs::read(store.realm_path("a")).unwrap();
        for invalid in [
            "broken JSON",
            r#"{"version":1,"state":"Prepared","realms":{"../outside":{"old":"x","new":"y"}},"verify":{"old":"x","new":"y"}}"#,
        ] {
            fs::write(store.root().join(JOURNAL), invalid).unwrap();
            assert!(store.list_realms().is_err());
            assert_eq!(fs::read(store.realm_path("a")).unwrap(), original);
            assert_eq!(
                fs::read_to_string(store.root().join(JOURNAL)).unwrap(),
                invalid
            );
        }
    }

    #[test]
    fn journal_checksum_failure_blocks_recovery_before_any_writes() {
        let (_dir, store, _) = setup();
        interrupt(&store, Step::Verify);
        let original = fs::read(store.realm_path("a")).unwrap();
        let path = store.root().join(JOURNAL);
        let mut envelope: Envelope = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.payload = envelope.payload.replace("Prepared", "Committed");
        let damaged = serde_json::to_vec(&envelope).unwrap();
        fs::write(&path, &damaged).unwrap();
        let error = store.list_realms().unwrap_err();
        assert!(format!("{error:#}").contains("checksum mismatch"));
        assert_eq!(fs::read(store.realm_path("a")).unwrap(), original);
        assert_eq!(fs::read(&path).unwrap(), damaged);
    }

    #[test]
    fn journal_with_unsafe_realm_name_is_rejected_before_any_writes() {
        let (_dir, store, _) = setup();
        interrupt(&store, Step::Verify);
        let original = fs::read(store.realm_path("a")).unwrap();
        let mut journal = read_journal(&store).unwrap().unwrap();
        let replacement = journal.realms.remove("b").unwrap();
        journal.realms.insert("../outside".to_string(), replacement);
        save_journal(&store, &journal).unwrap();
        let error = store.list_realms().unwrap_err();
        assert!(format!("{error:#}").contains("Invalid realm name"));
        assert_eq!(fs::read(store.realm_path("a")).unwrap(), original);
        assert!(store.root().join(JOURNAL).exists());
    }

    #[test]
    fn terminal_journal_reappearing_after_cleanup_does_not_undo_later_writes() {
        for committed in [false, true] {
            let (_dir, store, mut vars) = setup();
            interrupt(
                &store,
                if committed {
                    Step::Committed
                } else {
                    Step::Verify
                },
            );
            let mut journal = read_journal(&store).unwrap().unwrap();
            let passphrase = if committed { NEW } else { OLD };
            assert_generation(&store, passphrase, &vars);
            journal.state = if committed {
                State::Committed
            } else {
                State::RolledBack
            };
            vars.insert("LATER".to_string(), "new edit".to_string());
            store.save_realm("a", &vars, passphrase).unwrap();
            save_journal(&store, &journal).unwrap();
            assert_eq!(store.load_realm("a", passphrase).unwrap(), vars);
        }
    }

    #[test]
    fn store_lock_excludes_another_process_handle_and_is_released_on_drop() {
        let (_dir, store, _) = setup();
        let guard = store.lock_and_recover().unwrap();
        let other = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(store.root().join(".lock"))
            .unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&other).is_err());
        drop(guard);
        fs2::FileExt::try_lock_exclusive(&other).unwrap();
    }
}
