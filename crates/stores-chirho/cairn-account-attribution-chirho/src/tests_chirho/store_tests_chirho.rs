// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Attribution, freeze and inventory against a real temporary root: the order, the refusals, and tamper.

use crate::coordinate_chirho::AccountCoordinateChirho;
use crate::refusal_chirho::{AccountAttributionErrorChirho, AccountAttributionRefusalChirho};
use crate::store_chirho::{
    account_freeze_unlocked_chirho, append_account_attribution_unlocked_chirho,
    freeze_account_unlocked_chirho, frozen_account_inventory_unlocked_chirho,
    with_account_attribution_lock_chirho, ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};
use std::path::{Path, PathBuf};

fn identity_chirho(error_chirho: anyhow::Error) -> AccountAttributionRefusalChirho {
    error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"))
        .identity_chirho
}

fn key_id_chirho(number_chirho: u8) -> String {
    format!("{number_chirho:032x}")
}

fn account_chirho(principal_chirho: &str) -> AccountCoordinateChirho {
    AccountCoordinateChirho::from_principal_chirho(principal_chirho).unwrap()
}

fn log_path_chirho(root_chirho: &Path, account_chirho: &AccountCoordinateChirho) -> PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(account_chirho.as_hex_chirho())
        .join("attribution-chirho.jsonl")
}

#[test]
fn the_coordinate_is_one_digest_per_principal_and_refuses_bad_principals_chirho() {
    let first_chirho = account_chirho("user:alpha");
    assert_eq!(first_chirho, account_chirho("user:alpha"));
    assert_ne!(first_chirho, account_chirho("user:beta"));
    assert_eq!(first_chirho.as_hex_chirho().len(), 64);
    for bad_chirho in ["", "   ", "user:\nalpha"] {
        assert_eq!(
            identity_chirho(
                AccountCoordinateChirho::from_principal_chirho(bad_chirho).unwrap_err()
            ),
            AccountAttributionRefusalChirho::AccountCoordinateInvalidChirho
        );
    }
    assert_eq!(
        identity_chirho(
            AccountCoordinateChirho::from_principal_chirho(&"p".repeat(513)).unwrap_err()
        ),
        AccountAttributionRefusalChirho::AccountCoordinateInvalidChirho
    );
}

#[test]
fn an_inventory_is_readable_only_after_the_freeze_and_lists_every_row_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "viewer/derived",
            &key_id_chirho(2),
        )?;
        Ok(())
    })
    .unwrap();
    let before_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap_err();
    assert_eq!(
        identity_chirho(before_chirho),
        AccountAttributionRefusalChirho::AccountNotFrozenChirho
    );
    let inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap();
    let rows_chirho = inventory_chirho
        .entries_chirho()
        .iter()
        .map(|entry_chirho| {
            (
                entry_chirho.seq_chirho,
                entry_chirho.subject_chirho.as_str(),
                entry_chirho.key_id_chirho.clone(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows_chirho,
        vec![
            (0, "app/a/raw", key_id_chirho(1)),
            (1, "viewer/derived", key_id_chirho(2))
        ]
    );
}

#[test]
fn a_frozen_account_takes_no_new_key_and_others_are_untouched_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let (alpha_chirho, beta_chirho) = (account_chirho("user:alpha"), account_chirho("user:beta"));
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        Ok(())
    })
    .unwrap();
    // A retained request context for alpha tries to mint a new key after the freeze.
    let refused_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "viewer/new",
            &key_id_chirho(2),
        )
    })
    .unwrap_err();
    assert_eq!(
        identity_chirho(refused_chirho),
        AccountAttributionRefusalChirho::AccountFrozenChirho
    );
    // Beta is another account: it is neither frozen nor refused.
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &beta_chirho,
            "app/a/raw",
            &key_id_chirho(3),
        )
    })
    .expect("another account still attributes");
    assert!(
        account_freeze_unlocked_chirho(root_path_chirho, &beta_chirho)
            .unwrap()
            .is_none()
    );
    // The frozen inventory holds only alpha's one row from before the freeze.
    let inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap();
    assert_eq!(inventory_chirho.entries_chirho().len(), 1);
}

#[test]
fn a_second_freeze_returns_the_first_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    let (first_chirho, second_chirho) =
        with_account_attribution_lock_chirho(root_path_chirho, || {
            let first_chirho =
                freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
            let second_chirho =
                freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "retry")?;
            Ok((first_chirho, second_chirho))
        })
        .unwrap();
    assert_eq!(first_chirho, second_chirho);
    assert_eq!(second_chirho.record_chirho().reason_chirho, "account-close");
}

#[test]
fn a_tampered_row_or_freeze_refuses_the_inventory_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        Ok(())
    })
    .unwrap();
    // Re-point the signed row at another subject, keeping its signature.
    let log_chirho = log_path_chirho(root_path_chirho, &alpha_chirho);
    let original_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    std::fs::write(
        &log_chirho,
        original_chirho.replace("app/a/raw", "app/a/xyz"),
    )
    .unwrap();
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap_err();
    assert_eq!(
        identity_chirho(error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    std::fs::write(&log_chirho, &original_chirho).unwrap();
    // A freeze file re-pointed at another account reads as unverified, never as "not frozen".
    let freeze_chirho = log_chirho.with_file_name("freeze-chirho.json");
    let freeze_text_chirho = std::fs::read_to_string(&freeze_chirho).unwrap();
    let other_chirho = account_chirho("user:beta");
    std::fs::write(
        &freeze_chirho,
        freeze_text_chirho.replace(alpha_chirho.as_hex_chirho(), other_chirho.as_hex_chirho()),
    )
    .unwrap();
    let error_chirho = account_freeze_unlocked_chirho(root_path_chirho, &alpha_chirho).unwrap_err();
    assert_eq!(
        identity_chirho(error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}

#[test]
fn bad_subjects_key_ids_and_reasons_are_refused_before_any_write_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    let invalid_chirho = AccountAttributionRefusalChirho::AttributionFieldInvalidChirho;
    for (subject_chirho, key_id_value_chirho) in [
        ("a subject with spaces", key_id_chirho(1)),
        ("app/a/raw", "AB".repeat(16)),
        ("app/a/raw", "ab".repeat(32)),
    ] {
        let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
            append_account_attribution_unlocked_chirho(
                root_path_chirho,
                &alpha_chirho,
                subject_chirho,
                &key_id_value_chirho,
            )
        })
        .unwrap_err();
        assert_eq!(identity_chirho(error_chirho), invalid_chirho);
    }
    assert!(
        !log_path_chirho(root_path_chirho, &alpha_chirho).exists(),
        "nothing was written"
    );
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "Free text, not a label")
    })
    .unwrap_err();
    assert_eq!(identity_chirho(error_chirho), invalid_chirho);
}

#[test]
fn a_freeze_file_that_is_not_a_plain_file_refuses_rather_than_reading_as_not_frozen_chirho() {
    // A symlinked freeze is refused by the bounded read with an error that is NOT NotFound. If that
    // error read as "absent", a frozen account would silently take new keys again.
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let (alpha_chirho, beta_chirho) = (account_chirho("user:alpha"), account_chirho("user:beta"));
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &beta_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        Ok(())
    })
    .unwrap();
    let alpha_freeze_chirho =
        log_path_chirho(root_path_chirho, &alpha_chirho).with_file_name("freeze-chirho.json");
    let moved_chirho = alpha_freeze_chirho.with_file_name("freeze-moved-chirho.json");
    std::fs::rename(&alpha_freeze_chirho, &moved_chirho).unwrap();
    std::os::unix::fs::symlink(&moved_chirho, &alpha_freeze_chirho).unwrap();
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "viewer/new",
            &key_id_chirho(2),
        )
    })
    .unwrap_err();
    assert_eq!(
        identity_chirho(error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}

#[test]
fn another_accounts_signed_row_in_this_log_refuses_the_inventory_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let (alpha_chirho, beta_chirho) = (account_chirho("user:alpha"), account_chirho("user:beta"));
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &beta_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        Ok(())
    })
    .unwrap();
    // Beta's genuinely signed row, placed as seq 0 of alpha's log: the signature verifies, the account does not.
    let beta_row_chirho =
        std::fs::read_to_string(log_path_chirho(root_path_chirho, &beta_chirho)).unwrap();
    std::fs::write(
        log_path_chirho(root_path_chirho, &alpha_chirho),
        beta_row_chirho,
    )
    .unwrap();
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap_err();
    let detail_chirho = error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap()
        .detail_chirho;
    assert_eq!(
        identity_chirho(error_chirho),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    assert_eq!(detail_chirho, "an attribution row names another account");
}

/// Two rows for alpha, then the freeze, so the freeze binds an extent of two.
fn frozen_with_two_rows_chirho(root_path_chirho: &Path) -> AccountCoordinateChirho {
    let alpha_chirho = account_chirho("user:alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "viewer/derived",
            &key_id_chirho(2),
        )?;
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        Ok(())
    })
    .unwrap();
    alpha_chirho
}

fn inventory_refusal_detail_chirho(
    root_path_chirho: &Path,
    alpha_chirho: &AccountCoordinateChirho,
) -> &'static str {
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        frozen_account_inventory_unlocked_chirho(root_path_chirho, alpha_chirho)
    })
    .unwrap_err();
    let refusal_chirho = error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"));
    assert_eq!(
        refusal_chirho.identity_chirho,
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    refusal_chirho.detail_chirho
}

#[test]
fn a_log_deleted_after_the_freeze_refuses_rather_than_reading_as_empty_chirho() {
    // gpt #28899 (1): a missing log used to read as zero rows under a valid freeze.
    let root_chirho = tempfile::tempdir().unwrap();
    let alpha_chirho = frozen_with_two_rows_chirho(root_chirho.path());
    std::fs::remove_file(log_path_chirho(root_chirho.path(), &alpha_chirho)).unwrap();
    assert_eq!(
        inventory_refusal_detail_chirho(root_chirho.path(), &alpha_chirho),
        "the attribution log does not match the extent its freeze bound"
    );
}

#[test]
fn a_log_truncated_after_the_freeze_refuses_chirho() {
    // The first row alone is still validly signed and in sequence; only the frozen extent catches it.
    let root_chirho = tempfile::tempdir().unwrap();
    let alpha_chirho = frozen_with_two_rows_chirho(root_chirho.path());
    let log_chirho = log_path_chirho(root_chirho.path(), &alpha_chirho);
    let first_row_chirho = std::fs::read_to_string(&log_chirho)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string();
    std::fs::write(&log_chirho, format!("{first_row_chirho}\n")).unwrap();
    assert_eq!(
        inventory_refusal_detail_chirho(root_chirho.path(), &alpha_chirho),
        "the attribution log does not match the extent its freeze bound"
    );
}

#[test]
fn a_coordinate_deserializes_only_from_canonical_hex_chirho() {
    // gpt #28899 (2): a transparent Deserialize let a path-shaped value bypass from_hex.
    for bad_chirho in ["\"../../etc\"", "\"ABC\"", "\"\""] {
        assert!(
            serde_json::from_str::<AccountCoordinateChirho>(bad_chirho).is_err(),
            "{bad_chirho}"
        );
    }
    let good_chirho = account_chirho("user:alpha");
    let round_chirho: AccountCoordinateChirho =
        serde_json::from_str(&serde_json::to_string(&good_chirho).unwrap()).unwrap();
    assert_eq!(round_chirho, good_chirho);
}

#[test]
fn a_substituted_history_of_the_same_length_refuses_chirho() {
    // An older, validly signed log of the same length and account: every row verifies and the count
    // matches, so only the frozen extent digest can tell it is not the history the freeze bound.
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    let log_chirho = log_path_chirho(root_path_chirho, &alpha_chirho);
    let append_two_chirho = |first_chirho: u8| {
        with_account_attribution_lock_chirho(root_path_chirho, || {
            append_account_attribution_unlocked_chirho(
                root_path_chirho,
                &alpha_chirho,
                "app/a/raw",
                &key_id_chirho(first_chirho),
            )?;
            append_account_attribution_unlocked_chirho(
                root_path_chirho,
                &alpha_chirho,
                "app/a/raw",
                &key_id_chirho(first_chirho + 1),
            )?;
            Ok(())
        })
        .unwrap();
    };
    append_two_chirho(1);
    let older_chirho = std::fs::read(&log_chirho).unwrap();
    for entry_chirho in std::fs::read_dir(log_chirho.parent().unwrap()).unwrap() {
        std::fs::remove_file(entry_chirho.unwrap().path()).unwrap();
    }
    append_two_chirho(5);
    with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")
    })
    .unwrap();
    std::fs::write(&log_chirho, older_chirho).unwrap();
    assert_eq!(
        inventory_refusal_detail_chirho(root_path_chirho, &alpha_chirho),
        "the attribution log does not match the extent its freeze bound"
    );
}

#[test]
fn a_row_tampered_before_the_freeze_refuses_the_freeze_itself_chirho() {
    // The freeze binds the extent it reads, so a row altered BEFORE the freeze would be bound and then
    // match forever. Only the per-row signature check, run while the freeze reads the log, refuses it.
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )
    })
    .unwrap();
    let log_chirho = log_path_chirho(root_path_chirho, &alpha_chirho);
    let text_chirho = std::fs::read_to_string(&log_chirho).unwrap();
    std::fs::write(&log_chirho, text_chirho.replace("app/a/raw", "app/a/xyz")).unwrap();
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")
    })
    .unwrap_err();
    let refusal_chirho = error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap();
    assert_eq!(
        refusal_chirho.identity_chirho,
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    assert_eq!(
        refusal_chirho.detail_chirho,
        "a record's signature does not verify"
    );
    assert!(
        account_freeze_unlocked_chirho(root_path_chirho, &alpha_chirho)
            .unwrap()
            .is_none(),
        "no freeze was written"
    );
}

/// Every file under the account's attribution directory, with its bytes.
fn account_dir_bytes_chirho(
    root_path_chirho: &Path,
    account_chirho: &AccountCoordinateChirho,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    let dir_chirho = root_path_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join(account_chirho.as_hex_chirho());
    std::fs::read_dir(&dir_chirho)
        .unwrap()
        .map(|entry_chirho| {
            let path_chirho = entry_chirho.unwrap().path();
            (
                path_chirho
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
                std::fs::read(&path_chirho).unwrap(),
            )
        })
        .collect()
}

#[test]
fn a_snapshot_writes_nothing_and_refuses_a_torn_tail_unrepaired_chirho() {
    // gpt #29003: R3's preflight must not repair durable bytes before it holds authority to close.
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    let alpha_chirho = account_chirho("user:alpha");
    with_account_attribution_lock_chirho(root_path_chirho, || {
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(1),
        )?;
        append_account_attribution_unlocked_chirho(
            root_path_chirho,
            &alpha_chirho,
            "app/a/raw",
            &key_id_chirho(2),
        )?;
        Ok(())
    })
    .unwrap();
    let clean_chirho = account_dir_bytes_chirho(root_path_chirho, &alpha_chirho);
    let snapshot_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        crate::account_attribution_snapshot_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap();
    assert_eq!(snapshot_chirho.entries_chirho().len(), 2);
    assert_eq!(
        account_dir_bytes_chirho(root_path_chirho, &alpha_chirho),
        clean_chirho
    );

    let log_chirho = log_path_chirho(root_path_chirho, &alpha_chirho);
    let mut torn_chirho = std::fs::read(&log_chirho).unwrap();
    torn_chirho.extend_from_slice(b"{\"schema_chirho\":\"account-attri");
    std::fs::write(&log_chirho, &torn_chirho).unwrap();
    let torn_dir_chirho = account_dir_bytes_chirho(root_path_chirho, &alpha_chirho);
    let error_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        crate::account_attribution_snapshot_unlocked_chirho(root_path_chirho, &alpha_chirho)
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
    assert_eq!(
        refusal_chirho.detail_chirho,
        "the attribution log has a torn tail, which a snapshot does not repair"
    );
    assert_eq!(
        account_dir_bytes_chirho(root_path_chirho, &alpha_chirho),
        torn_dir_chirho,
        "a refused snapshot changed the log or a sidecar"
    );

    // The authority path still recovers it: the freeze truncates the torn tail and binds the two rows.
    let inventory_chirho = with_account_attribution_lock_chirho(root_path_chirho, || {
        freeze_account_unlocked_chirho(root_path_chirho, &alpha_chirho, "account-close")?;
        frozen_account_inventory_unlocked_chirho(root_path_chirho, &alpha_chirho)
    })
    .unwrap();
    assert_eq!(inventory_chirho.entries_chirho().len(), 2);
}
