// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! R3 consumer controls by CAIRN gpt_chirho (#28903, #28915): three were red on the 2c46c13d baseline and
//! green on the af36be56 fix, so they now run as ordinary regressions beside the empty-account control.
//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/
//! elected-control-chirho/r3-attribution-consumer-review-chirho.md.

use crate::{
    account_attribution_snapshot_unlocked_chirho, admit_private_key_unlocked_chirho,
    append_account_attribution_unlocked_chirho, freeze_account_unlocked_chirho,
    frozen_account_inventory_unlocked_chirho, with_account_attribution_lock_chirho,
    AccountAttributionErrorChirho, AccountAttributionRefusalChirho, AccountCoordinateChirho,
    AttributionRoleChirho, SubjectOwnerChirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};
use std::path::{Path, PathBuf};

fn log_path_chirho(root_chirho: &Path, account_chirho: &AccountCoordinateChirho) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(account_chirho.as_hex_chirho())
        .join("attribution-chirho.jsonl")
}

fn frozen_fixture_chirho() -> (tempfile::TempDir, AccountCoordinateChirho, Vec<u8>) {
    let root_chirho = tempfile::tempdir().unwrap();
    let account_chirho = AccountCoordinateChirho::from_principal_chirho("r3/actor-chirho").unwrap();
    let first_row_chirho = with_account_attribution_lock_chirho(root_chirho.path(), || {
        append_account_attribution_unlocked_chirho(
            root_chirho.path(),
            &account_chirho,
            "r3/first-subject-chirho",
            &format!("{:032x}", 1),
        )?;
        let first_row_chirho = std::fs::read(log_path_chirho(root_chirho.path(), &account_chirho))?;
        append_account_attribution_unlocked_chirho(
            root_chirho.path(),
            &account_chirho,
            "r3/interrupted-subject-chirho",
            &format!("{:032x}", 2),
        )?;
        freeze_account_unlocked_chirho(root_chirho.path(), &account_chirho, "r3-review-chirho")?;
        let inventory_chirho =
            frozen_account_inventory_unlocked_chirho(root_chirho.path(), &account_chirho)?;
        assert_eq!(inventory_chirho.entries_chirho().len(), 2);
        assert_eq!(
            inventory_chirho.entries_chirho()[1].subject_chirho,
            "r3/interrupted-subject-chirho"
        );
        Ok(first_row_chirho)
    })
    .unwrap();
    (root_chirho, account_chirho, first_row_chirho)
}

fn assert_inventory_refused_chirho(root_chirho: &Path, account_chirho: &AccountCoordinateChirho) {
    let result_chirho = with_account_attribution_lock_chirho(root_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_chirho, account_chirho)
    });
    let error_chirho = match result_chirho {
        Ok(inventory_chirho) => panic!(
            "lost frozen attribution was accepted as a verified inventory of {} keys",
            inventory_chirho.entries_chirho().len()
        ),
        Err(error_chirho) => error_chirho,
    };
    assert_eq!(
        error_chirho
            .downcast_ref::<AccountAttributionErrorChirho>()
            .unwrap_or_else(|| panic!("not the intended named refusal: {error_chirho}"))
            .identity_chirho,
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}

#[test]
fn r3_consumer_frozen_inventory_refuses_missing_nonempty_log_chirho() {
    let (root_chirho, account_chirho, _) = frozen_fixture_chirho();
    std::fs::remove_file(log_path_chirho(root_chirho.path(), &account_chirho)).unwrap();
    assert_inventory_refused_chirho(root_chirho.path(), &account_chirho);
}

#[test]
fn r3_consumer_frozen_inventory_refuses_a_valid_signed_prefix_chirho() {
    let (root_chirho, account_chirho, first_row_chirho) = frozen_fixture_chirho();
    std::fs::write(
        log_path_chirho(root_chirho.path(), &account_chirho),
        first_row_chirho,
    )
    .unwrap();
    assert_inventory_refused_chirho(root_chirho.path(), &account_chirho);
}

#[test]
fn r3_consumer_coordinate_deserialization_cannot_bypass_hex_validation_chirho() {
    let account_chirho = AccountCoordinateChirho::from_principal_chirho("r3/actor-chirho").unwrap();
    let encoded_chirho = serde_json::to_string(&account_chirho).unwrap();
    assert_eq!(
        serde_json::from_str::<AccountCoordinateChirho>(&encoded_chirho).unwrap(),
        account_chirho
    );
    for invalid_chirho in ["../escaped-chirho", "", "not-a-coordinate-chirho"] {
        let encoded_chirho = serde_json::to_string(invalid_chirho).unwrap();
        assert!(
            serde_json::from_str::<AccountCoordinateChirho>(&encoded_chirho).is_err(),
            "a non-hex coordinate bypassed the validating constructor"
        );
    }
}

#[test]
fn r3_consumer_a_genuinely_empty_frozen_account_has_an_empty_inventory_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let account_chirho = AccountCoordinateChirho::from_principal_chirho("r3/empty-chirho").unwrap();
    with_account_attribution_lock_chirho(root_chirho.path(), || {
        freeze_account_unlocked_chirho(root_chirho.path(), &account_chirho, "r3-review-chirho")?;
        let inventory_chirho =
            frozen_account_inventory_unlocked_chirho(root_chirho.path(), &account_chirho)?;
        assert!(inventory_chirho.entries_chirho().is_empty());
        Ok(())
    })
    .unwrap();
}

fn root_snapshot_chirho(root_chirho: &Path) -> std::collections::BTreeMap<PathBuf, String> {
    fn walk_chirho(
        root_chirho: &Path,
        path_chirho: &Path,
        entries_chirho: &mut std::collections::BTreeMap<PathBuf, String>,
    ) {
        let metadata_chirho = std::fs::symlink_metadata(path_chirho).unwrap();
        let key_chirho = path_chirho.strip_prefix(root_chirho).unwrap().to_path_buf();
        if metadata_chirho.is_dir() {
            entries_chirho.insert(key_chirho, "directory-chirho".to_string());
            for entry_chirho in std::fs::read_dir(path_chirho).unwrap() {
                walk_chirho(root_chirho, &entry_chirho.unwrap().path(), entries_chirho);
            }
        } else {
            assert!(
                metadata_chirho.is_file(),
                "fixture contains a non-regular leaf"
            );
            // Failure diagnostics expose only digests, never the fixture signing key's bytes.
            entries_chirho.insert(
                key_chirho,
                blake3::hash(&std::fs::read(path_chirho).unwrap())
                    .to_hex()
                    .to_string(),
            );
        }
    }
    let mut entries_chirho = std::collections::BTreeMap::new();
    walk_chirho(root_chirho, root_chirho, &mut entries_chirho);
    entries_chirho
}

#[test]
fn r3_consumer_unavailable_contribution_preflight_never_repairs_a_torn_log_chirho() {
    use std::io::Write as _;

    let root_chirho = tempfile::tempdir().unwrap();
    let container_chirho =
        AccountCoordinateChirho::from_principal_chirho("r3/container-chirho").unwrap();
    let actor_chirho =
        AccountCoordinateChirho::from_principal_chirho("r3/contributor-chirho").unwrap();
    with_account_attribution_lock_chirho(root_chirho.path(), || {
        admit_private_key_unlocked_chirho(
            root_chirho.path(),
            &SubjectOwnerChirho::AccountChirho(container_chirho.clone()),
            Some(&actor_chirho),
            "r3/shared-container-subject-chirho",
            &format!("{:032x}", 7),
        )?;
        Ok(())
    })
    .unwrap();
    let clean_before_chirho = root_snapshot_chirho(root_chirho.path());
    let clean_chirho = with_account_attribution_lock_chirho(root_chirho.path(), || {
        account_attribution_snapshot_unlocked_chirho(root_chirho.path(), &actor_chirho)
    })
    .unwrap();
    assert!(clean_chirho.freeze_chirho().is_none());
    assert_eq!(clean_chirho.entries_chirho().len(), 1);
    assert_eq!(
        clean_chirho.entries_chirho()[0].role_chirho,
        AttributionRoleChirho::ContributionChirho {
            container_chirho: SubjectOwnerChirho::AccountChirho(container_chirho),
        }
    );
    assert_eq!(
        root_snapshot_chirho(root_chirho.path()),
        clean_before_chirho,
        "even a clean eligibility read must write nothing"
    );

    let log_chirho = log_path_chirho(root_chirho.path(), &actor_chirho);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log_chirho)
        .unwrap()
        .write_all(b"{")
        .unwrap();
    let torn_before_chirho = root_snapshot_chirho(root_chirho.path());
    let result_chirho = with_account_attribution_lock_chirho(root_chirho.path(), || {
        account_attribution_snapshot_unlocked_chirho(root_chirho.path(), &actor_chirho)
    });
    assert_eq!(
        root_snapshot_chirho(root_chirho.path()),
        torn_before_chirho,
        "R3 cannot repair the log or sidecar merely to refuse unresolved contribution coverage"
    );
    let error_chirho = result_chirho.expect_err("a torn preflight must refuse without repair");
    assert_eq!(
        error_chirho
            .downcast_ref::<AccountAttributionErrorChirho>()
            .unwrap()
            .identity_chirho,
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}
