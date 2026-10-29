// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The key chokepoint, end to end: every key's container and actor reach admission, a principal's namespace cannot be squatted, a frozen actor cannot write into an open container, a coverage debt is bound into its subject's signed owner, and a subject whose owner record goes missing is not reclaimed.

use super::*;
use cairn_account_attribution_chirho::{
    account_attribution_snapshot_unlocked_chirho, coverage_debts_unlocked_chirho,
    freeze_account_unlocked_chirho, subject_owner_unlocked_chirho, AccountAttributionErrorChirho,
    AccountAttributionRefusalChirho, AccountCoordinateChirho, AttributionRoleChirho,
    CoverageDebtChirho, SubjectOwnerChirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};

const INTAKE_SUBJECT_CHIRHO: &str = "contact-chirho/intake";

fn coordinate_chirho(principal_chirho: &str) -> AccountCoordinateChirho {
    AccountCoordinateChirho::from_principal_chirho(principal_chirho).unwrap()
}

fn identity_chirho(error_chirho: &anyhow::Error) -> AccountAttributionRefusalChirho {
    error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named attribution refusal: {error_chirho}"))
        .identity_chirho
}

fn key_count_chirho(root_chirho: &Path) -> usize {
    std::fs::read_dir(keys_dir_chirho(root_chirho))
        .map(|entries_chirho| entries_chirho.count())
        .unwrap_or(0)
}

fn roles_chirho(root_chirho: &Path, principal_chirho: &str) -> Vec<AttributionRoleChirho> {
    with_account_attribution_lock_chirho(root_chirho, || {
        account_attribution_snapshot_unlocked_chirho(
            root_chirho,
            &coordinate_chirho(principal_chirho),
        )
    })
    .unwrap()
    .entries_chirho()
    .iter()
    .map(|entry_chirho| entry_chirho.role_chirho.clone())
    .collect()
}

fn owner_of_chirho(root_chirho: &Path, subject_chirho: &str) -> Result<Option<SubjectOwnerChirho>> {
    with_account_attribution_lock_chirho(root_chirho, || {
        subject_owner_unlocked_chirho(root_chirho, subject_chirho)
    })
}

fn debts_chirho(root_chirho: &Path) -> Vec<CoverageDebtChirho> {
    with_account_attribution_lock_chirho(root_chirho, || {
        coverage_debts_unlocked_chirho(root_chirho)
    })
    .unwrap()
}

fn attribution_dir_chirho(root_chirho: &Path, name_chirho: &str) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(name_chirho)
}

/// gpt #28929's arm through the real chokepoint: owner A's container, signed-in submitters B and C.
#[test]
fn a_frozen_submitter_cannot_write_into_an_open_container_and_creates_no_key_chirho() {
    let root_chirho = tmp_root_chirho();
    let from_b_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/a", Some("user/b")).unwrap();
    let from_c_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/a", Some("user/c")).unwrap();
    store_private_blob_chirho(
        &root_chirho,
        &from_b_chirho,
        INTAKE_SUBJECT_CHIRHO,
        b"from b",
    )
    .unwrap();
    store_private_blob_chirho(
        &root_chirho,
        &from_c_chirho,
        INTAKE_SUBJECT_CHIRHO,
        b"from c",
    )
    .unwrap();
    assert_eq!(
        roles_chirho(&root_chirho, "user/b"),
        [AttributionRoleChirho::ContributionChirho {
            container_chirho: SubjectOwnerChirho::AccountChirho(coordinate_chirho("owner/a"))
        }]
    );
    with_account_attribution_lock_chirho(&root_chirho, || {
        freeze_account_unlocked_chirho(&root_chirho, &coordinate_chirho("user/b"), "account-close")
    })
    .unwrap();
    let keys_before_chirho = key_count_chirho(&root_chirho);
    let error_chirho = store_private_blob_chirho(
        &root_chirho,
        &from_b_chirho,
        INTAKE_SUBJECT_CHIRHO,
        b"late b",
    )
    .unwrap_err();
    assert_eq!(
        identity_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AccountFrozenChirho
    );
    assert_eq!(
        key_count_chirho(&root_chirho),
        keys_before_chirho,
        "a refused store made a key"
    );
    // C, and the open container, are untouched by B's close.
    store_private_blob_chirho(
        &root_chirho,
        &from_c_chirho,
        INTAKE_SUBJECT_CHIRHO,
        b"later c",
    )
    .unwrap();
    assert_eq!(roles_chirho(&root_chirho, "owner/a").len(), 3);
}

/// gpt #28929's namespace-squat negative, through the real chokepoint.
#[test]
fn no_app_can_squat_a_users_canonical_subject_chirho() {
    let root_chirho = tmp_root_chirho();
    let squatter_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/a", None).unwrap();
    let error_chirho =
        store_private_blob_chirho(&root_chirho, &squatter_chirho, "user/b", b"squat").unwrap_err();
    assert_eq!(
        identity_chirho(&error_chirho),
        AccountAttributionRefusalChirho::SubjectNamespaceReservedChirho
    );
    assert_eq!(key_count_chirho(&root_chirho), 0);
    let own_chirho = PrivateBlobAttributionChirho::account_owned_chirho("user/b").unwrap();
    store_private_blob_chirho(&root_chirho, &own_chirho, "user/b", b"mine").unwrap();
}

/// gpt #29035 and #29054: a coverage-debt reason marks the root and binds the debt into the subject's
/// signed owner record; an operator reason does neither; deleting the marker leaves the owner record naming
/// the debt, so an empty marker list is no proof that no debt-class key survives.
#[test]
fn a_coverage_debt_is_bound_into_its_subjects_owner_and_survives_the_markers_deletion_chirho() {
    let root_chirho = tmp_root_chirho();
    let operator_chirho = PrivateBlobAttributionChirho::not_account_scoped_chirho(
        NotAccountScopedReasonChirho::OperatorRunChirho,
    );
    store_private_blob_chirho(
        &root_chirho,
        &operator_chirho,
        "operator-chirho/fixture",
        b"op",
    )
    .unwrap();
    assert!(debts_chirho(&root_chirho).is_empty());
    assert_eq!(
        owner_of_chirho(&root_chirho, "operator-chirho/fixture").unwrap(),
        Some(SubjectOwnerChirho::NoAccountChirho)
    );
    let pending_chirho = PrivateBlobAttributionChirho::not_account_scoped_chirho(
        NotAccountScopedReasonChirho::PostgresEvidencePendingAttributionChirho,
    );
    let debt_subject_chirho = "e".repeat(64);
    for value_chirho in [b"one".as_slice(), b"two".as_slice()] {
        store_private_blob_chirho(
            &root_chirho,
            &pending_chirho,
            &debt_subject_chirho,
            value_chirho,
        )
        .unwrap();
    }
    let debt_chirho = CoverageDebtChirho::PostgresEvidencePendingAttributionChirho;
    assert_eq!(debts_chirho(&root_chirho), [debt_chirho]);
    std::fs::remove_dir_all(attribution_dir_chirho(
        &root_chirho,
        "coverage-debts-chirho",
    ))
    .unwrap();
    assert!(debts_chirho(&root_chirho).is_empty());
    assert_eq!(
        owner_of_chirho(&root_chirho, &debt_subject_chirho).unwrap(),
        Some(SubjectOwnerChirho::CoverageDebtChirho(debt_chirho))
    );
}

/// gpt #29068's trace through the real chokepoint: owner A's key survives for a subject whose owner record
/// is then deleted; owner B's later store of that subject refuses and makes no key, rather than claiming
/// it afresh, which would let B's erasure shred A's key.
#[test]
fn a_subject_whose_owner_record_is_missing_is_not_reclaimed_by_another_owner_chirho() {
    let root_chirho = tmp_root_chirho();
    let from_a_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/a", Some("user/x")).unwrap();
    store_private_blob_chirho(&root_chirho, &from_a_chirho, INTAKE_SUBJECT_CHIRHO, b"a's").unwrap();
    std::fs::remove_dir_all(attribution_dir_chirho(&root_chirho, "subjects-chirho")).unwrap();
    let keys_before_chirho = key_count_chirho(&root_chirho);
    let from_b_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/b", None).unwrap();
    let error_chirho =
        store_private_blob_chirho(&root_chirho, &from_b_chirho, INTAKE_SUBJECT_CHIRHO, b"b's")
            .unwrap_err();
    assert_eq!(
        identity_chirho(&error_chirho),
        AccountAttributionRefusalChirho::SubjectOwnerRecordMissingChirho
    );
    assert_eq!(
        key_count_chirho(&root_chirho),
        keys_before_chirho,
        "a refused store made a key"
    );
    assert!(roles_chirho(&root_chirho, "owner/b").is_empty());
    // Control: B may still claim a subject nobody claimed.
    store_private_blob_chirho(
        &root_chirho,
        &from_b_chirho,
        "contact-chirho/b-only",
        b"b's",
    )
    .unwrap();
}

/// R-C5-4a, forced rather than hoped for: a store parked between its admission and its key file holds the
/// attribution lock, so an erasure of the same subject cannot finish until the store's key exists, and then
/// erases it. The timing check can only fail a broken build: a correct one never lets the erasure through.
#[test]
fn a_store_and_an_erasure_of_one_subject_are_ordered_chirho() {
    let root_chirho = tmp_root_chirho();
    let attribution_chirho =
        PrivateBlobAttributionChirho::app_container_chirho("owner/a", None).unwrap();
    let (reached_chirho, release_chirho) = super::store_hold_chirho::arm_chirho(&root_chirho);
    let store_root_chirho = root_chirho.clone();
    let store_attribution_chirho = attribution_chirho.clone();
    let store_chirho = std::thread::spawn(move || {
        store_private_blob_chirho(
            &store_root_chirho,
            &store_attribution_chirho,
            INTAKE_SUBJECT_CHIRHO,
            b"stored while an erasure waits",
        )
    });
    reached_chirho
        .recv_timeout(std::time::Duration::from_secs(30))
        .expect("the store reached its hold");
    let (done_tx_chirho, done_rx_chirho) = std::sync::mpsc::channel();
    let erase_root_chirho = root_chirho.clone();
    let erase_chirho = std::thread::spawn(move || {
        let record_chirho = erase_subject_data_chirho(
            &erase_root_chirho,
            INTAKE_SUBJECT_CHIRHO,
            "owner/a",
            "ordering-proof",
        );
        let _ = done_tx_chirho.send(());
        record_chirho
    });
    assert!(
        done_rx_chirho
            .recv_timeout(std::time::Duration::from_millis(300))
            .is_err(),
        "an erasure finished while a store of its subject sat between admission and key file"
    );
    release_chirho.send(()).unwrap();
    let blob_chirho = store_chirho.join().unwrap().unwrap();
    let record_chirho = erase_chirho.join().unwrap().unwrap();
    assert!(
        record_chirho
            .key_ids_chirho
            .contains(&blob_chirho.key_id_chirho),
        "the erasure ran after the store and must name its key"
    );
    assert!(!key_path_chirho(&root_chirho, &blob_chirho.key_id_chirho).exists());
}
