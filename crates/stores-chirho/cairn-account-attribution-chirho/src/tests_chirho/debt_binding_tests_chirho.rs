// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A debt-class key's debt lives in its subject's signed owner record and survives the marker's deletion, every owner label round-trips through the one parser, and a subject whose owner record goes missing cannot be reclaimed by another owner (gpt #29054, #29068).

use crate::subject_owner_chirho::SubjectOwnerChirho;
use crate::{
    account_attribution_snapshot_unlocked_chirho, admit_private_key_unlocked_chirho,
    coverage_debts_unlocked_chirho, freeze_account_unlocked_chirho,
    frozen_account_inventory_unlocked_chirho, subject_owner_unlocked_chirho,
    with_account_attribution_lock_chirho, AccountAttributionErrorChirho,
    AccountAttributionRefusalChirho, AccountCoordinateChirho, AttributionRoleChirho,
    CoverageDebtChirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};
use std::path::Path;

const DEBT_CHIRHO: CoverageDebtChirho =
    CoverageDebtChirho::PostgresEvidencePendingAttributionChirho;
const SUBJECT_CHIRHO: &str = "postgres-evidence-chirho/0123456789abcdef";

fn coordinate_chirho(principal_chirho: &str) -> AccountCoordinateChirho {
    AccountCoordinateChirho::from_principal_chirho(principal_chirho).unwrap()
}

fn admit_chirho(
    root_chirho: &Path,
    container_chirho: &SubjectOwnerChirho,
    actor_chirho: Option<&str>,
    subject_chirho: &str,
    seed_chirho: u8,
) -> anyhow::Result<()> {
    let actor_chirho = actor_chirho.map(coordinate_chirho);
    with_account_attribution_lock_chirho(root_chirho, || {
        admit_private_key_unlocked_chirho(
            root_chirho,
            container_chirho,
            actor_chirho.as_ref(),
            subject_chirho,
            &format!("{seed_chirho:032x}"),
        )
    })
}

fn owner_of_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
) -> anyhow::Result<Option<SubjectOwnerChirho>> {
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

fn identity_chirho(error_chirho: &anyhow::Error) -> AccountAttributionRefusalChirho {
    error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"))
        .identity_chirho
}

/// Remove every subject owner record, leaving the claim witnesses and the keys' rows.
fn delete_owner_records_chirho(root_chirho: &Path) -> usize {
    let mut deleted_chirho = 0;
    let owners_chirho = root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join("subjects-chirho");
    for shard_chirho in std::fs::read_dir(owners_chirho).unwrap() {
        for record_chirho in std::fs::read_dir(shard_chirho.unwrap().path()).unwrap() {
            std::fs::remove_file(record_chirho.unwrap().path()).unwrap();
            deleted_chirho += 1;
        }
    }
    deleted_chirho
}

#[test]
fn a_debt_keys_subject_still_names_the_debt_after_its_marker_is_deleted_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let debt_owner_chirho = SubjectOwnerChirho::CoverageDebtChirho(DEBT_CHIRHO);
    admit_chirho(
        root_path_chirho,
        &debt_owner_chirho,
        None,
        SUBJECT_CHIRHO,
        1,
    )
    .unwrap();
    assert_eq!(debts_chirho(root_path_chirho), [DEBT_CHIRHO]);
    assert_eq!(
        owner_of_chirho(root_path_chirho, SUBJECT_CHIRHO).unwrap(),
        Some(debt_owner_chirho.clone())
    );
    std::fs::remove_dir_all(
        root_path_chirho
            .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
            .join("coverage-debts-chirho"),
    )
    .unwrap();
    // The marker list is now empty, and that proves nothing: the surviving signed owner record names it.
    assert!(debts_chirho(root_path_chirho).is_empty());
    assert_eq!(
        owner_of_chirho(root_path_chirho, SUBJECT_CHIRHO).unwrap(),
        Some(debt_owner_chirho)
    );
}

#[test]
fn a_subject_whose_owner_record_is_missing_cannot_be_reclaimed_by_another_owner_chirho() {
    for (label_chirho, earlier_chirho, earlier_actor_chirho) in [
        (
            "account",
            SubjectOwnerChirho::AccountChirho(coordinate_chirho("owner/a")),
            Some("owner/a"),
        ),
        (
            "debt",
            SubjectOwnerChirho::CoverageDebtChirho(DEBT_CHIRHO),
            None,
        ),
    ] {
        let root_chirho = tempfile::tempdir().unwrap();
        let root_path_chirho = root_chirho.path();
        admit_chirho(
            root_path_chirho,
            &earlier_chirho,
            earlier_actor_chirho,
            SUBJECT_CHIRHO,
            1,
        )
        .unwrap();
        assert_eq!(
            delete_owner_records_chirho(root_path_chirho),
            1,
            "{label_chirho}"
        );
        let _ = std::fs::remove_dir_all(
            root_path_chirho
                .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
                .join("coverage-debts-chirho"),
        );
        let later_chirho = SubjectOwnerChirho::AccountChirho(coordinate_chirho("owner/b"));
        let error_chirho = admit_chirho(
            root_path_chirho,
            &later_chirho,
            Some("owner/b"),
            SUBJECT_CHIRHO,
            2,
        )
        .unwrap_err();
        assert_eq!(
            identity_chirho(&error_chirho),
            AccountAttributionRefusalChirho::SubjectOwnerRecordMissingChirho,
            "{label_chirho}"
        );
        // The read refuses too, so nothing can take the missing record as "unclaimed".
        assert_eq!(
            identity_chirho(&owner_of_chirho(root_path_chirho, SUBJECT_CHIRHO).unwrap_err()),
            AccountAttributionRefusalChirho::SubjectOwnerRecordMissingChirho,
            "{label_chirho}"
        );
        let b_rows_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
            account_attribution_snapshot_unlocked_chirho(
                root_path_chirho,
                &coordinate_chirho("owner/b"),
            )
        })
        .unwrap();
        assert!(
            b_rows_chirho.entries_chirho().is_empty(),
            "{label_chirho}: B got a row"
        );
        // Control: the refusal is about that subject, not a blanket one.
        admit_chirho(
            root_path_chirho,
            &later_chirho,
            Some("owner/b"),
            "contact-chirho/never-claimed",
            3,
        )
        .unwrap();
    }
}

#[test]
fn a_contribution_into_a_debt_container_reads_back_and_is_bound_by_the_freeze_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let debt_owner_chirho = SubjectOwnerChirho::CoverageDebtChirho(DEBT_CHIRHO);
    admit_chirho(
        root_path_chirho,
        &debt_owner_chirho,
        Some("user/b"),
        SUBJECT_CHIRHO,
        1,
    )
    .unwrap();
    let b_chirho = coordinate_chirho("user/b");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &b_chirho, "account-close")
    })
    .unwrap();
    let inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &b_chirho)
    })
    .unwrap();
    let roles_chirho: Vec<_> = inventory_chirho
        .entries_chirho()
        .iter()
        .map(|entry_chirho| entry_chirho.role_chirho.clone())
        .collect();
    assert_eq!(
        roles_chirho,
        [AttributionRoleChirho::ContributionChirho {
            container_chirho: debt_owner_chirho
        }]
    );
}

#[test]
fn every_owner_label_round_trips_through_the_one_parser_and_unknown_labels_refuse_chirho() {
    let mut owners_chirho = vec![
        SubjectOwnerChirho::AccountChirho(coordinate_chirho("owner/a")),
        SubjectOwnerChirho::NoAccountChirho,
    ];
    owners_chirho.extend(
        CoverageDebtChirho::ALL_CHIRHO
            .into_iter()
            .map(SubjectOwnerChirho::CoverageDebtChirho),
    );
    let mut labels_chirho = std::collections::BTreeSet::new();
    for owner_chirho in &owners_chirho {
        let label_chirho = owner_chirho.label_chirho().to_string();
        assert_eq!(
            &SubjectOwnerChirho::from_label_chirho(&label_chirho).unwrap(),
            owner_chirho
        );
        assert!(
            labels_chirho.insert(label_chirho),
            "two owner classes share a label"
        );
    }
    for unknown_chirho in [
        "",
        "coverage-debt-unknown-chirho",
        "postgres-evidence-pending-attribution",
        "NO-ACCOUNT-CHIRHO",
    ] {
        assert!(
            SubjectOwnerChirho::from_label_chirho(unknown_chirho).is_err(),
            "{unknown_chirho:?} parsed"
        );
    }
}

#[test]
fn a_no_account_subject_cannot_take_a_debt_key_or_the_reverse_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let debt_owner_chirho = SubjectOwnerChirho::CoverageDebtChirho(DEBT_CHIRHO);
    let no_account_chirho = SubjectOwnerChirho::NoAccountChirho;
    for (first_chirho, second_chirho, subject_chirho) in [
        (&no_account_chirho, &debt_owner_chirho, "operator-chirho/s"),
        (&debt_owner_chirho, &no_account_chirho, "operator-chirho/t"),
    ] {
        admit_chirho(root_path_chirho, first_chirho, None, subject_chirho, 1).unwrap();
        assert_eq!(
            identity_chirho(
                &admit_chirho(root_path_chirho, second_chirho, None, subject_chirho, 2)
                    .unwrap_err()
            ),
            AccountAttributionRefusalChirho::SubjectOwnedElsewhereChirho
        );
    }
}
