// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The reviewed-principal registration takes only a drawn principal's exact shape, refuses a
//! principal already in the identity log, at the key directory or carrying attribution rows, and
//! otherwise registers exactly the principal it was given, on any number of roots. The precheck
//! refuses everything the registration refuses, and claims nothing when it passes: no identity, key-file
//! or attribution state.

use super::super::{
    identity_key_path_chirho, load_identities_chirho, login_identity_with_credential_chirho,
    register_identity_chirho, PrincipalKindChirho, IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO,
};
use super::{
    precheck_reviewed_principal_chirho, refuse_unless_key_path_absent_chirho,
    register_identity_with_reviewed_principal_chirho,
};
use cairn_account_attribution_chirho::{
    account_attribution_snapshot_unlocked_chirho, append_account_attribution_unlocked_chirho,
    with_account_attribution_lock_chirho, AccountCoordinateChirho,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const PAYER_CHIRHO: &str = "user/0a1b2c3d4e5f6a7b";
const CREDENTIAL_CHIRHO: &str = "reviewed-principal-credential-chirho";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!("cairn-reviewed-principal-{n_chirho}"));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn identity_count_chirho(root_chirho: &std::path::Path) -> usize {
    load_identities_chirho(root_chirho).unwrap().len()
}

#[test]
fn a_reviewed_principal_is_registered_exactly_and_can_log_in_chirho() {
    let root_chirho = tmp_root_chirho();
    let record_chirho = register_identity_with_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        PAYER_CHIRHO,
        Some(CREDENTIAL_CHIRHO),
    )
    .unwrap();
    assert_eq!(record_chirho.principal_chirho, PAYER_CHIRHO);
    assert_eq!(identity_count_chirho(&root_chirho), 1);
    login_identity_with_credential_chirho(&root_chirho, PAYER_CHIRHO, CREDENTIAL_CHIRHO)
        .expect("the reviewed principal logs in with its credential");
}

#[test]
fn a_reviewed_principal_refuses_every_other_shape_chirho() {
    let root_chirho = tmp_root_chirho();
    for (kind_chirho, principal_chirho) in [
        (PrincipalKindChirho::UserChirho, "owner/0a1b2c3d4e5f6a7b"),
        (PrincipalKindChirho::OwnerChirho, "user/0a1b2c3d4e5f6a7b"),
        (PrincipalKindChirho::UserChirho, "user/0a1b2c3d4e5f6a7"),
        (PrincipalKindChirho::UserChirho, "user/0a1b2c3d4e5f6a7b8"),
        (PrincipalKindChirho::UserChirho, "user/0A1B2C3D4E5F6A7B"),
        (PrincipalKindChirho::UserChirho, "user/0a1b2c3d4e5f6a7g"),
        (PrincipalKindChirho::UserChirho, "user/0123456789012345"),
        (PrincipalKindChirho::UserChirho, "user//0a1b2c3d4e5f6a7"),
        (PrincipalKindChirho::UserChirho, "user0a1b2c3d4e5f6a7b"),
        (PrincipalKindChirho::UserChirho, ""),
    ] {
        let precheck_error_chirho = precheck_reviewed_principal_chirho(
            &root_chirho,
            kind_chirho.clone(),
            principal_chirho,
            None,
        )
        .expect_err(principal_chirho);
        assert_eq!(
            precheck_error_chirho.to_string(),
            "ReviewedPrincipalShapeRefusedChirho",
            "precheck {principal_chirho:?}"
        );
        let error_chirho = register_identity_with_reviewed_principal_chirho(
            &root_chirho,
            kind_chirho,
            principal_chirho,
            None,
        )
        .expect_err(principal_chirho);
        assert_eq!(
            error_chirho.to_string(),
            "ReviewedPrincipalShapeRefusedChirho",
            "{principal_chirho:?}"
        );
    }
    assert_eq!(identity_count_chirho(&root_chirho), 0);
}

#[test]
fn a_principal_already_in_the_log_refuses_and_appends_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let drawn_chirho = register_identity_chirho(&root_chirho, PrincipalKindChirho::OwnerChirho)
        .unwrap()
        .principal_chirho;
    assert_eq!(
        precheck_reviewed_principal_chirho(
            &root_chirho,
            PrincipalKindChirho::OwnerChirho,
            &drawn_chirho,
            None,
        )
        .unwrap_err()
        .to_string(),
        "ReviewedPrincipalAlreadyRegisteredChirho"
    );
    let error_chirho = register_identity_with_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::OwnerChirho,
        &drawn_chirho,
        None,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ReviewedPrincipalAlreadyRegisteredChirho"
    );
    assert_eq!(identity_count_chirho(&root_chirho), 1);
}

#[test]
fn a_stray_key_file_refuses_a_reviewed_principal_chirho() {
    let root_chirho = tmp_root_chirho();
    let key_path_chirho = identity_key_path_chirho(&root_chirho, PAYER_CHIRHO);
    std::fs::create_dir_all(key_path_chirho.parent().unwrap()).unwrap();
    std::fs::write(&key_path_chirho, b"{}").unwrap();
    assert_eq!(
        precheck_reviewed_principal_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            PAYER_CHIRHO,
            None,
        )
        .unwrap_err()
        .to_string(),
        "ReviewedPrincipalKeyFileExistsChirho"
    );
    let error_chirho = register_identity_with_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        PAYER_CHIRHO,
        None,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ReviewedPrincipalKeyFileExistsChirho"
    );
    assert_eq!(identity_count_chirho(&root_chirho), 0);
}

#[test]
fn a_coordinate_with_attribution_rows_refuses_chirho() {
    let root_chirho = tmp_root_chirho();
    let account_chirho = AccountCoordinateChirho::from_principal_chirho(PAYER_CHIRHO).unwrap();
    with_account_attribution_lock_chirho(&root_chirho, || {
        append_account_attribution_unlocked_chirho(
            &root_chirho,
            &account_chirho,
            "app/a/raw",
            &format!("{:032x}", 1_u8),
        )
    })
    .unwrap();
    assert_eq!(
        precheck_reviewed_principal_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            PAYER_CHIRHO,
            None,
        )
        .unwrap_err()
        .to_string(),
        "ReviewedPrincipalHasAttributionChirho"
    );
    let error_chirho = register_identity_with_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        PAYER_CHIRHO,
        None,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "ReviewedPrincipalHasAttributionChirho"
    );
    assert_eq!(identity_count_chirho(&root_chirho), 0);
}

#[test]
fn two_roots_register_the_same_reviewed_principal_chirho() {
    let (first_chirho, second_chirho) = (tmp_root_chirho(), tmp_root_chirho());
    for root_chirho in [&first_chirho, &second_chirho] {
        let record_chirho = register_identity_with_reviewed_principal_chirho(
            root_chirho,
            PrincipalKindChirho::UserChirho,
            PAYER_CHIRHO,
            Some(CREDENTIAL_CHIRHO),
        )
        .unwrap();
        assert_eq!(record_chirho.principal_chirho, PAYER_CHIRHO);
    }
}

#[test]
fn the_key_path_probe_refuses_anything_but_proven_absence_chirho() {
    let root_chirho = tmp_root_chirho();
    let absent_chirho = root_chirho.join("absent-key-chirho.json");
    refuse_unless_key_path_absent_chirho(&absent_chirho).expect("NotFound proves absence");
    let present_chirho = root_chirho.join("present-key-chirho.json");
    std::fs::write(&present_chirho, b"{}").unwrap();
    assert_eq!(
        refuse_unless_key_path_absent_chirho(&present_chirho)
            .unwrap_err()
            .to_string(),
        "ReviewedPrincipalKeyFileExistsChirho"
    );
    // A path under a regular file fails with NotADirectory, not NotFound: an error that is not
    // proof of absence must refuse, never proceed.
    let under_a_file_chirho = present_chirho.join("child-key-chirho.json");
    assert_eq!(
        refuse_unless_key_path_absent_chirho(&under_a_file_chirho)
            .unwrap_err()
            .to_string(),
        "ReviewedPrincipalKeyFileUnreadableChirho"
    );
}

#[test]
fn a_passing_precheck_claims_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    precheck_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        PAYER_CHIRHO,
        Some(CREDENTIAL_CHIRHO),
    )
    .unwrap();
    assert_eq!(identity_count_chirho(&root_chirho), 0);
    let key_probe_chirho =
        std::fs::symlink_metadata(identity_key_path_chirho(&root_chirho, PAYER_CHIRHO));
    assert_eq!(
        key_probe_chirho
            .map(|_metadata_chirho| ())
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::NotFound,
        "the precheck must not claim the key-file path"
    );
    let account_chirho = AccountCoordinateChirho::from_principal_chirho(PAYER_CHIRHO).unwrap();
    let snapshot_chirho = with_account_attribution_lock_chirho(&root_chirho, || {
        account_attribution_snapshot_unlocked_chirho(&root_chirho, &account_chirho)
    })
    .unwrap();
    assert!(snapshot_chirho.freeze_chirho().is_none());
    assert!(snapshot_chirho.entries_chirho().is_empty());
    register_identity_with_reviewed_principal_chirho(
        &root_chirho,
        PrincipalKindChirho::UserChirho,
        PAYER_CHIRHO,
        Some(CREDENTIAL_CHIRHO),
    )
    .expect("a passed precheck leaves the principal free to register");
}

#[test]
fn a_credential_below_the_floor_refuses_both_chirho() {
    let root_chirho = tmp_root_chirho();
    for result_chirho in [
        precheck_reviewed_principal_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            PAYER_CHIRHO,
            Some("short-chirho"),
        ),
        register_identity_with_reviewed_principal_chirho(
            &root_chirho,
            PrincipalKindChirho::UserChirho,
            PAYER_CHIRHO,
            Some("short-chirho"),
        )
        .map(|_record_chirho| ()),
    ] {
        assert_eq!(
            result_chirho.unwrap_err().to_string(),
            IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO
        );
    }
    assert_eq!(identity_count_chirho(&root_chirho), 0);
}
