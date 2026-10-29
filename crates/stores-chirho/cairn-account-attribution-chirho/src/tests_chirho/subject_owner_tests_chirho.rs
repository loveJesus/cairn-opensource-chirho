// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A subject's first key claims it for one owner; later keys must share that owner; an actor writing into another owner's container leaves a contribution row in its own log, and either account's freeze stops the write.

use crate::record_chirho::AccountAttributionRecordChirho;
use crate::{
    account_attribution_snapshot_unlocked_chirho, admit_private_key_unlocked_chirho,
    freeze_account_unlocked_chirho, frozen_account_inventory_unlocked_chirho,
    subject_owner_unlocked_chirho, with_account_attribution_lock_chirho,
    AccountAttributionErrorChirho, AccountAttributionRefusalChirho, AccountCoordinateChirho,
    AttributionRoleChirho, SubjectOwnerChirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::sign_message_chirho;
use std::path::{Path, PathBuf};

fn coordinate_chirho(principal_chirho: &str) -> AccountCoordinateChirho {
    AccountCoordinateChirho::from_principal_chirho(principal_chirho).unwrap()
}

fn owner_chirho(principal_chirho: &str) -> SubjectOwnerChirho {
    SubjectOwnerChirho::AccountChirho(coordinate_chirho(principal_chirho))
}

fn key_id_chirho(seed_chirho: u8) -> String {
    format!("{seed_chirho:032x}")
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
            &key_id_chirho(seed_chirho),
        )
    })
}

fn refusal_chirho(error_chirho: &anyhow::Error) -> AccountAttributionRefusalChirho {
    error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"))
        .identity_chirho
}

fn log_path_chirho(root_chirho: &Path, principal_chirho: &str) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(coordinate_chirho(principal_chirho).as_hex_chirho())
        .join("attribution-chirho.jsonl")
}

fn log_text_chirho(root_chirho: &Path, principal_chirho: &str) -> String {
    std::fs::read_to_string(log_path_chirho(root_chirho, principal_chirho)).unwrap_or_default()
}

fn owner_files_chirho(root_chirho: &Path) -> Vec<PathBuf> {
    let base_chirho = root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join("subjects-chirho");
    let mut files_chirho = Vec::new();
    let Ok(shards_chirho) = std::fs::read_dir(&base_chirho) else {
        return files_chirho;
    };
    for shard_chirho in shards_chirho {
        for file_chirho in std::fs::read_dir(shard_chirho.unwrap().path()).unwrap() {
            files_chirho.push(file_chirho.unwrap().path());
        }
    }
    files_chirho
}

fn snapshot_roles_chirho(root_chirho: &Path, principal_chirho: &str) -> Vec<AttributionRoleChirho> {
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

#[test]
fn a_subject_holds_keys_of_one_owner_only_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = owner_chirho("owner/alpha");
    admit_chirho(root_path_chirho, &alpha_chirho, None, "app/shared", 1).unwrap();
    admit_chirho(root_path_chirho, &alpha_chirho, None, "app/shared", 2).unwrap();
    assert_eq!(
        subject_owner_unlocked_chirho(root_path_chirho, "app/shared").unwrap(),
        Some(alpha_chirho.clone())
    );
    for intruder_chirho in [
        owner_chirho("owner/beta"),
        SubjectOwnerChirho::NoAccountChirho,
    ] {
        let error_chirho =
            admit_chirho(root_path_chirho, &intruder_chirho, None, "app/shared", 3).unwrap_err();
        assert_eq!(
            refusal_chirho(&error_chirho),
            AccountAttributionRefusalChirho::SubjectOwnedElsewhereChirho
        );
    }
    // The reverse direction: a no-account subject takes no account's key.
    admit_chirho(
        root_path_chirho,
        &SubjectOwnerChirho::NoAccountChirho,
        None,
        "app/anon",
        4,
    )
    .unwrap();
    let error_chirho =
        admit_chirho(root_path_chirho, &alpha_chirho, None, "app/anon", 5).unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::SubjectOwnedElsewhereChirho
    );
    // Only alpha's two admitted keys are in alpha's inventory; refused admissions wrote no row.
    let alpha_coordinate_chirho = coordinate_chirho("owner/alpha");
    let inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(
            root_path_chirho,
            &alpha_coordinate_chirho,
            "account-close",
        )?;
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_coordinate_chirho)
    })
    .unwrap();
    let keys_chirho: Vec<&str> = inventory_chirho
        .entries_chirho()
        .iter()
        .map(|entry_chirho| entry_chirho.key_id_chirho.as_str())
        .collect();
    assert_eq!(keys_chirho, [key_id_chirho(1), key_id_chirho(2)]);
}

#[test]
fn a_frozen_account_claims_no_new_subject_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_coordinate_chirho = coordinate_chirho("owner/alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_coordinate_chirho, "account-close")
    })
    .unwrap();
    let error_chirho = admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/alpha"),
        None,
        "app/new",
        1,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AccountFrozenChirho
    );
    assert!(
        owner_files_chirho(root_path_chirho).is_empty(),
        "a refused admission left a subject claim behind"
    );
    assert_eq!(
        subject_owner_unlocked_chirho(root_path_chirho, "app/new").unwrap(),
        None
    );
}

/// gpt #28929's arm: owner A holds a shared container that signed-in B and C both write into.
#[test]
fn a_retained_actor_cannot_write_into_an_open_container_after_its_own_close_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let container_chirho = owner_chirho("owner/a");
    admit_chirho(
        root_path_chirho,
        &container_chirho,
        Some("user/b"),
        "app/a/shared",
        1,
    )
    .unwrap();
    admit_chirho(
        root_path_chirho,
        &container_chirho,
        Some("user/c"),
        "app/a/shared",
        2,
    )
    .unwrap();
    // B closes: its own freeze, while A's container stays open.
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(
            root_path_chirho,
            &coordinate_chirho("user/b"),
            "account-close",
        )
    })
    .unwrap();
    let (owner_log_chirho, claims_chirho) = (
        log_text_chirho(root_path_chirho, "owner/a"),
        owner_files_chirho(root_path_chirho),
    );
    // A retained B context writes into A's container: refused before any row, claim or key.
    let error_chirho = admit_chirho(
        root_path_chirho,
        &container_chirho,
        Some("user/b"),
        "app/a/shared",
        3,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AccountFrozenChirho
    );
    assert_eq!(
        log_text_chirho(root_path_chirho, "owner/a"),
        owner_log_chirho
    );
    assert_eq!(owner_files_chirho(root_path_chirho), claims_chirho);
    // C is unaffected by B's close.
    admit_chirho(
        root_path_chirho,
        &container_chirho,
        Some("user/c"),
        "app/a/shared",
        4,
    )
    .unwrap();
    // B's frozen inventory names its key as a CONTRIBUTION to A's container, never an owned subject, so a
    // close of B can neither shred A's container nor claim B's key in it is gone.
    let b_chirho = coordinate_chirho("user/b");
    let b_inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &b_chirho)
    })
    .unwrap();
    assert_eq!(b_inventory_chirho.entries_chirho().len(), 1);
    assert_eq!(
        b_inventory_chirho.entries_chirho()[0].role_chirho,
        AttributionRoleChirho::ContributionChirho {
            container_chirho: container_chirho.clone()
        }
    );
    // A's log holds every key in its container as OWNED, each naming the account that wrote it.
    assert_eq!(
        snapshot_roles_chirho(root_path_chirho, "owner/a"),
        [
            AttributionRoleChirho::OwnedChirho {
                actor_chirho: Some(coordinate_chirho("user/b"))
            },
            AttributionRoleChirho::OwnedChirho {
                actor_chirho: Some(coordinate_chirho("user/c"))
            },
            AttributionRoleChirho::OwnedChirho {
                actor_chirho: Some(coordinate_chirho("user/c"))
            },
        ]
    );
    // And A's own freeze stops C as well: the container's barrier holds for every actor.
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(
            root_path_chirho,
            &coordinate_chirho("owner/a"),
            "account-close",
        )
    })
    .unwrap();
    let error_chirho = admit_chirho(
        root_path_chirho,
        &container_chirho,
        Some("user/c"),
        "app/a/shared",
        5,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AccountFrozenChirho
    );
    assert_eq!(snapshot_roles_chirho(root_path_chirho, "user/c").len(), 2);
}

/// gpt #28929's namespace-squat negative.
#[test]
fn no_owner_can_pre_claim_a_principals_namespace_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    for (squatter_chirho, subject_chirho) in [
        (owner_chirho("owner/a"), "user/b"),
        (owner_chirho("owner/a"), "user/b/notes"),
        (SubjectOwnerChirho::NoAccountChirho, "user/b"),
        (owner_chirho("user/c"), "owner/a"),
    ] {
        let error_chirho =
            admit_chirho(root_path_chirho, &squatter_chirho, None, subject_chirho, 1).unwrap_err();
        assert_eq!(
            refusal_chirho(&error_chirho),
            AccountAttributionRefusalChirho::SubjectNamespaceReservedChirho,
            "{subject_chirho}"
        );
    }
    assert!(
        owner_files_chirho(root_path_chirho).is_empty(),
        "a refused squat left a claim behind"
    );
    // B's own store under its canonical subject, and under a path below it, still works.
    admit_chirho(
        root_path_chirho,
        &owner_chirho("user/b"),
        Some("user/b"),
        "user/b",
        2,
    )
    .unwrap();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("user/b"),
        None,
        "user/b/notes",
        3,
    )
    .unwrap();
    // A self-written key leaves one OWNED row, not an extra contribution.
    assert_eq!(
        snapshot_roles_chirho(root_path_chirho, "user/b"),
        [
            AttributionRoleChirho::OwnedChirho {
                actor_chirho: Some(coordinate_chirho("user/b"))
            },
            AttributionRoleChirho::OwnedChirho { actor_chirho: None },
        ]
    );
}

#[test]
fn the_snapshot_shows_contributions_before_any_freeze_chirho() {
    // R3's preflight: an unresolved contribution is visible while the account is still open, so a close
    // that must refuse can refuse without freezing (gpt #28945).
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/a"),
        Some("user/b"),
        "app/a/shared",
        1,
    )
    .unwrap();
    let snapshot_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        account_attribution_snapshot_unlocked_chirho(root_path_chirho, &coordinate_chirho("user/b"))
    })
    .unwrap();
    assert!(snapshot_chirho.freeze_chirho().is_none());
    assert_eq!(
        snapshot_chirho.entries_chirho()[0].role_chirho,
        AttributionRoleChirho::ContributionChirho {
            container_chirho: owner_chirho("owner/a")
        }
    );
}

#[test]
fn a_row_binds_its_role_container_and_actor_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/a"),
        Some("user/b"),
        "app/a/shared",
        1,
    )
    .unwrap();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/d"),
        Some("user/b"),
        "app/d/shared",
        2,
    )
    .unwrap();
    let b_log_chirho = log_path_chirho(root_path_chirho, "user/b");
    let original_chirho = std::fs::read_to_string(&b_log_chirho).unwrap();
    let rows_chirho: Vec<AccountAttributionRecordChirho> = original_chirho
        .lines()
        .map(|line_chirho| serde_json::from_str(line_chirho).unwrap())
        .collect();
    let rewrite_chirho = |rows_chirho: &[AccountAttributionRecordChirho]| {
        let text_chirho: String = rows_chirho
            .iter()
            .map(|row_chirho| serde_json::to_string(row_chirho).unwrap() + "\n")
            .collect();
        std::fs::write(&b_log_chirho, text_chirho).unwrap();
    };
    let detail_chirho = |root_path_chirho: &Path| {
        let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
            account_attribution_snapshot_unlocked_chirho(
                root_path_chirho,
                &coordinate_chirho("user/b"),
            )
        })
        .unwrap_err();
        let refusal_chirho = error_chirho
            .downcast_ref::<AccountAttributionErrorChirho>()
            .unwrap()
            .clone();
        assert_eq!(
            refusal_chirho.identity_chirho,
            AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
        );
        refusal_chirho.detail_chirho
    };
    // A contribution relabelled OWNED, even re-signed by the root, is out of form: B does not hold A's subject.
    let mut owned_chirho = rows_chirho.clone();
    owned_chirho[0].role_chirho = "owned-chirho".to_string();
    owned_chirho[0].sig_chirho =
        sign_message_chirho(root_path_chirho, &owned_chirho[0].message_chirho()).unwrap();
    rewrite_chirho(&owned_chirho);
    assert_eq!(
        detail_chirho(root_path_chirho),
        "the attribution row's role, container or actor is not in form"
    );
    // An unsigned change of container fails the signature.
    let mut moved_chirho = rows_chirho.clone();
    moved_chirho[0].container_chirho = rows_chirho[1].container_chirho.clone();
    rewrite_chirho(&moved_chirho);
    assert_eq!(
        detail_chirho(root_path_chirho),
        "a record's signature does not verify"
    );
    // After a freeze, a well-formed re-signed swap of the two containers still breaks the bound extent.
    std::fs::write(&b_log_chirho, &original_chirho).unwrap();
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(
            root_path_chirho,
            &coordinate_chirho("user/b"),
            "account-close",
        )
    })
    .unwrap();
    let mut swapped_chirho = rows_chirho.clone();
    swapped_chirho[0].container_chirho = rows_chirho[1].container_chirho.clone();
    swapped_chirho[1].container_chirho = rows_chirho[0].container_chirho.clone();
    for row_chirho in &mut swapped_chirho {
        row_chirho.sig_chirho =
            sign_message_chirho(root_path_chirho, &row_chirho.message_chirho()).unwrap();
    }
    rewrite_chirho(&swapped_chirho);
    assert_eq!(
        detail_chirho(root_path_chirho),
        "the attribution log does not match the extent its freeze bound"
    );
}

#[test]
fn a_tampered_or_moved_owner_record_refuses_rather_than_reading_as_unclaimed_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/alpha"),
        None,
        "app/one",
        1,
    )
    .unwrap();
    admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/beta"),
        None,
        "app/two",
        2,
    )
    .unwrap();
    let files_chirho = owner_files_chirho(root_path_chirho);
    assert_eq!(files_chirho.len(), 2);
    let alpha_hex_chirho = coordinate_chirho("owner/alpha");
    let beta_hex_chirho = coordinate_chirho("owner/beta");
    let one_chirho = files_chirho
        .iter()
        .find(|path_chirho| {
            std::fs::read_to_string(path_chirho)
                .unwrap()
                .contains(alpha_hex_chirho.as_hex_chirho())
        })
        .unwrap()
        .clone();
    let two_chirho = files_chirho
        .iter()
        .find(|path_chirho| **path_chirho != one_chirho)
        .unwrap()
        .clone();
    // Beta's validly signed record copied over alpha's subject: it names another subject.
    let original_chirho = std::fs::read(&one_chirho).unwrap();
    std::fs::copy(&two_chirho, &one_chirho).unwrap();
    let error_chirho = subject_owner_unlocked_chirho(root_path_chirho, "app/one").unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    // Alpha's own record with its owner rewritten to beta: the signature no longer covers it.
    let forged_chirho = String::from_utf8(original_chirho).unwrap().replace(
        alpha_hex_chirho.as_hex_chirho(),
        beta_hex_chirho.as_hex_chirho(),
    );
    std::fs::write(&one_chirho, forged_chirho).unwrap();
    let error_chirho = subject_owner_unlocked_chirho(root_path_chirho, "app/one").unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    // And the admission path refuses with it rather than re-claiming the subject.
    let error_chirho = admit_chirho(
        root_path_chirho,
        &owner_chirho("owner/beta"),
        None,
        "app/one",
        3,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho(&error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}
