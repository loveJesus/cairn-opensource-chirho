// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)
//! Arms for revision 2's interruption contract, one cut at each step of a redemption: before the key-record rename,
//! after it, and before the `used-chirho` event. Before the rename the code stays live and a retry works; after it the
//! code is gone for good and nothing can re-authorize it, and a missing reset record is named by the inventory.
//! These need a non-root runner: they cut the act with file permissions.

use super::recovery_code_tests_chirho::{
    code_tmp_root_chirho, refusal_token_chirho, signs_in_chirho, FIRST_CHIRHO, SECOND_CHIRHO,
    THIRD_CHIRHO,
};
use super::*;
use std::os::unix::fs::PermissionsExt;

fn credentialed_with_code_in_chirho(root_chirho: &Path) -> (String, IssuedRecoveryCodeChirho) {
    let principal_chirho = register_identity_with_credential_chirho(
        root_chirho,
        PrincipalKindChirho::UserChirho,
        FIRST_CHIRHO,
    )
    .unwrap()
    .principal_chirho;
    let issued_chirho = mint_operator_recovery_code_chirho(root_chirho, &principal_chirho).unwrap();
    (principal_chirho, issued_chirho)
}

fn held_code_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
) -> Option<StoredRecoveryCodeChirho> {
    stored_recovery_code_chirho(
        &load_identity_key_record_chirho(root_chirho, principal_chirho).unwrap(),
    )
    .unwrap()
}

fn set_mode_chirho(path_chirho: &Path, mode_chirho: u32) {
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(mode_chirho)).unwrap();
}

#[test]
fn a_cut_before_the_rename_leaves_the_code_live_records_no_use_and_a_retry_works_chirho() {
    let mut fixture_chirho = super::super::key_write_tests_chirho::KeyWriteRootChirho::new_chirho();
    let root_chirho = fixture_chirho.path_chirho.clone();
    let (principal_chirho, issued_chirho) = credentialed_with_code_in_chirho(&root_chirho);
    let held_before_chirho = held_code_chirho(&root_chirho, &principal_chirho);
    let events_before_chirho = load_recovery_code_events_chirho(&root_chirho)
        .unwrap()
        .len();
    fixture_chirho.obstruct_key_directory_chirho();
    let error_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    fixture_chirho.restore_key_directory_chirho().unwrap();
    assert_eq!(
        refusal_token_chirho(&error_chirho),
        None,
        "an engine failure, never a refusal"
    );
    // Before the rename, nothing but session revocations may have moved.
    assert_eq!(
        held_code_chirho(&root_chirho, &principal_chirho),
        held_before_chirho,
        "the code is still live"
    );
    assert!(
        signs_in_chirho(&root_chirho, &principal_chirho, FIRST_CHIRHO),
        "the old credential is in force"
    );
    assert_eq!(
        verify_credential_resets_chirho(&root_chirho).unwrap(),
        0,
        "no reset record"
    );
    assert_eq!(
        load_recovery_code_events_chirho(&root_chirho)
            .unwrap()
            .len(),
        events_before_chirho,
        "no use is recorded for a code that was not used"
    );
    // She retries with the same code, and it works.
    redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap();
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
}

#[test]
fn a_cut_after_the_rename_never_revives_the_code_and_the_missing_record_is_named_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_in_chirho(&root_chirho);
    // The reset log refuses its next append, which comes AFTER the key-record rename.
    let resets_chirho = root_chirho.join("identity-credential-resets-chirho.jsonl");
    std::fs::write(&resets_chirho, "").unwrap();
    set_mode_chirho(&resets_chirho, 0o400);
    let error_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    set_mode_chirho(&resets_chirho, 0o600);
    assert_eq!(
        refusal_token_chirho(&error_chirho),
        None,
        "an engine failure after the commit point"
    );
    // The change applied: the code is consumed, and the new credential works.
    assert_eq!(held_code_chirho(&root_chirho, &principal_chirho), None);
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
    // Nothing can re-authorize the consumed code.
    let retry_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        THIRD_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_token_chirho(&retry_chirho),
        Some("recovery-refused-chirho")
    );
    // The gap is named, not silent.
    let inventory_chirho = credential_inventory_chirho(&root_chirho).unwrap();
    assert_eq!(inventory_chirho.generation_ahead_of_reset_records_chirho, 1);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn a_cut_before_the_use_event_leaves_the_change_applied_and_the_code_gone_chirho() {
    let root_chirho = code_tmp_root_chirho();
    let (principal_chirho, issued_chirho) = credentialed_with_code_in_chirho(&root_chirho);
    // The events log refuses its next append, which comes after the reset record.
    let events_path_chirho = root_chirho.join("identity-recovery-code-events-chirho.jsonl");
    set_mode_chirho(&events_path_chirho, 0o400);
    let error_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        SECOND_CHIRHO,
    )
    .unwrap_err();
    set_mode_chirho(&events_path_chirho, 0o600);
    assert_eq!(refusal_token_chirho(&error_chirho), None);
    assert_eq!(
        held_code_chirho(&root_chirho, &principal_chirho),
        None,
        "the code is consumed"
    );
    assert!(signs_in_chirho(
        &root_chirho,
        &principal_chirho,
        SECOND_CHIRHO
    ));
    assert_eq!(
        verify_credential_resets_chirho(&root_chirho).unwrap(),
        1,
        "the reset is recorded"
    );
    assert_eq!(
        verify_recovery_code_events_chirho(&root_chirho).unwrap(),
        1,
        "only the mint; the log still verifies"
    );
    let retry_chirho = redeem_recovery_code_chirho(
        &root_chirho,
        &principal_chirho,
        &issued_chirho.recovery_code_chirho,
        THIRD_CHIRHO,
    )
    .unwrap_err();
    assert_eq!(
        refusal_token_chirho(&retry_chirho),
        Some("recovery-refused-chirho")
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
