// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::writer_head_chirho::issue_elected_writer_fence_for_root_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

fn root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let root_chirho = std::env::temp_dir().join(format!(
        "run-admission-scope-{}-{}-chirho",
        std::process::id(),
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

#[test]
fn the_scope_takes_no_append_lock_and_refuses_another_root_chirho() {
    let root_chirho = root_chirho();
    let other_root_chirho = root_chirho.join("other-chirho");
    std::fs::create_dir_all(&other_root_chirho).unwrap();
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
        1,
        Some(&fence_chirho),
        &|| Ok(()),
        |scope_chirho| {
            scope_chirho.validate_sink_chirho(&root_chirho)?;
            assert!(scope_chirho
                .validate_sink_chirho(&other_root_chirho)
                .is_err());
            cairn_seqlog_chirho::seqlog_chirho::with_append_log_lock_chirho(&root_chirho, || Ok(()))
        },
    );
    outcome_chirho.into_result_chirho().unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_local_root_is_not_activated_by_the_admission_door_chirho() {
    let root_chirho = root_chirho();
    let group_chirho = consistency_group_for_root_chirho(&root_chirho).unwrap();
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &group_chirho,
        1,
        None,
        &|| Ok(()),
        |_scope_chirho| -> Result<()> { panic!("local era must not invoke") },
    );
    assert!(outcome_chirho.observed_fence_chirho().is_none());
    assert!(outcome_chirho.into_result_chirho().is_err());
    assert_eq!(
        writer_authority_era_chirho(&root_chirho).unwrap(),
        WriterAuthorityEraChirho::LocalChirho
    );
    assert_eq!(std::fs::read_dir(&root_chirho).unwrap().count(), 0);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_stale_cached_fence_never_reaches_the_sink_chirho() {
    let root_chirho = root_chirho();
    let stale_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 2).unwrap();
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &stale_chirho.group_chirho,
        1,
        Some(&stale_chirho),
        &|| Ok(()),
        |_scope_chirho| -> Result<()> { panic!("stale fence must not invoke") },
    );
    assert!(outcome_chirho.into_result_chirho().is_err());
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn rebinding_the_root_after_prepare_refuses_at_the_sink_chirho() {
    let root_chirho = root_chirho();
    let held_root_chirho = root_chirho.with_extension("held-chirho");
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
        1,
        Some(&fence_chirho),
        &|| Ok(()),
        |scope_chirho| {
            std::fs::rename(&root_chirho, &held_root_chirho)?;
            std::fs::create_dir(&root_chirho)?;
            // A byte-identical fence at the old path is not the originally admitted root.
            let source_chirho = crate::writer_head_chirho::writer_fence_path_chirho(
                &held_root_chirho,
                &fence_chirho.group_chirho,
            )?;
            let replacement_chirho = crate::writer_head_chirho::writer_fence_path_chirho(
                &root_chirho,
                &fence_chirho.group_chirho,
            )?;
            std::fs::create_dir_all(replacement_chirho.parent().unwrap())?;
            std::fs::copy(source_chirho, replacement_chirho)?;
            verify_writer_fence_for_root_chirho(&root_chirho, &fence_chirho)?;
            assert!(scope_chirho.validate_sink_chirho(&root_chirho).is_err());
            Ok(())
        },
    );
    outcome_chirho.into_result_chirho().unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
    std::fs::remove_dir_all(held_root_chirho).unwrap();
}

#[test]
fn every_scope_validation_rechecks_the_borrowed_authority_chirho() {
    let root_chirho = root_chirho();
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let expired_chirho = std::cell::Cell::new(false);
    let validate_chirho = || {
        if expired_chirho.get() {
            bail!("TestHeldAuthorityExpiredChirho");
        }
        Ok(())
    };
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
        1,
        Some(&fence_chirho),
        &validate_chirho,
        |scope_chirho| {
            scope_chirho.validate_sink_chirho(&root_chirho)?;
            expired_chirho.set(true);
            scope_chirho.validate_sink_chirho(&root_chirho)
        },
    );
    assert_eq!(
        outcome_chirho.into_result_chirho().unwrap_err().to_string(),
        "TestHeldAuthorityExpiredChirho"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// A SINK CHECKS ITS ROOT AND FENCE BEFORE THE LEASE, so the time their I/O spends counts against it, as
/// `validate_sink_chirho` says (the carry's independent review: an arm the reviewer chose). The control: with only the
/// held authority expired, the refusal is the lease's. Then, with the root rebound as well, it is the root's: a check
/// that ran the lease first would answer with the lease instead.
#[test]
fn a_sink_checks_its_root_and_fence_before_the_lease_chirho() {
    let root_chirho = root_chirho();
    let held_root_chirho = root_chirho.with_extension("held-chirho");
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let expired_chirho = std::cell::Cell::new(false);
    let validate_chirho = || {
        if expired_chirho.get() {
            bail!("TestHeldAuthorityExpiredChirho");
        }
        Ok(())
    };
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
        1,
        Some(&fence_chirho),
        &validate_chirho,
        |scope_chirho| {
            expired_chirho.set(true);
            assert_eq!(
                scope_chirho
                    .validate_sink_chirho(&root_chirho)
                    .unwrap_err()
                    .to_string(),
                "TestHeldAuthorityExpiredChirho",
                "the control: only the lease is wrong"
            );
            std::fs::rename(&root_chirho, &held_root_chirho)?;
            std::fs::create_dir(&root_chirho)?;
            assert_eq!(
                scope_chirho
                    .validate_sink_chirho(&root_chirho)
                    .unwrap_err()
                    .to_string(),
                "RunAdmissionWrongRootChirho",
                "the root is checked before the lease"
            );
            Ok(())
        },
    );
    outcome_chirho.into_result_chirho().unwrap();
    std::fs::remove_dir_all(root_chirho).unwrap();
    std::fs::remove_dir_all(held_root_chirho).unwrap();
}

#[test]
fn expired_authority_does_not_enter_the_fence_scope_chirho() {
    let root_chirho = root_chirho();
    let fence_chirho = issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let fence_path_chirho = crate::writer_head_chirho::writer_fence_path_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
    )
    .unwrap();
    let before_chirho = std::fs::read(&fence_path_chirho).unwrap();
    let outcome_chirho = with_elected_run_admission_scope_chirho(
        &root_chirho,
        &fence_chirho.group_chirho,
        1,
        None,
        &|| bail!("TestHeldAuthorityExpiredChirho"),
        |_scope_chirho| -> Result<()> {
            panic!("expired authority must not invoke");
        },
    );
    assert!(outcome_chirho.observed_fence_chirho().is_none());
    assert_eq!(
        outcome_chirho.into_result_chirho().unwrap_err().to_string(),
        "TestHeldAuthorityExpiredChirho"
    );
    assert_eq!(std::fs::read(fence_path_chirho).unwrap(), before_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}
