// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A coverage debt's marker is recorded once and read back verified, and a tampered, unknown or misnamed marker refuses rather than reading as no debt.

use crate::coverage_debt_chirho::record_coverage_debt_unlocked_chirho;
use crate::{
    coverage_debts_unlocked_chirho, with_account_attribution_lock_chirho,
    AccountAttributionErrorChirho, AccountAttributionRefusalChirho, CoverageDebtChirho,
    ACCOUNT_ATTRIBUTION_DIR_CHIRHO,
};

const DEBT_CHIRHO: CoverageDebtChirho =
    CoverageDebtChirho::PostgresEvidencePendingAttributionChirho;

fn debts_chirho(root_chirho: &std::path::Path) -> anyhow::Result<Vec<CoverageDebtChirho>> {
    with_account_attribution_lock_chirho(root_chirho, || {
        coverage_debts_unlocked_chirho(root_chirho)
    })
}

fn marker_chirho(root_chirho: &std::path::Path, name_chirho: &str) -> std::path::PathBuf {
    root_chirho
        .join(ACCOUNT_ATTRIBUTION_DIR_CHIRHO)
        .join("coverage-debts-chirho")
        .join(format!("{name_chirho}.json"))
}

fn identity_chirho(error_chirho: &anyhow::Error) -> AccountAttributionRefusalChirho {
    error_chirho
        .downcast_ref::<AccountAttributionErrorChirho>()
        .unwrap_or_else(|| panic!("not a named refusal: {error_chirho}"))
        .identity_chirho
}

#[test]
fn a_debt_is_recorded_once_and_read_back_verified_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    assert!(
        debts_chirho(root_path_chirho).unwrap().is_empty(),
        "no directory is no marker"
    );
    for _ in 0..2 {
        with_account_attribution_lock_chirho(root_path_chirho, || {
            record_coverage_debt_unlocked_chirho(root_path_chirho, DEBT_CHIRHO)
        })
        .unwrap();
    }
    assert_eq!(debts_chirho(root_path_chirho).unwrap(), [DEBT_CHIRHO]);
}

#[test]
fn a_tampered_unknown_or_misnamed_marker_refuses_rather_than_reading_as_no_debt_chirho() {
    let root_chirho = tempfile::tempdir().unwrap();
    let root_path_chirho = root_chirho.path();
    with_account_attribution_lock_chirho(root_path_chirho, || {
        record_coverage_debt_unlocked_chirho(root_path_chirho, DEBT_CHIRHO)
    })
    .unwrap();
    let marker_path_chirho = marker_chirho(root_path_chirho, DEBT_CHIRHO.label_chirho());
    let original_chirho = std::fs::read(&marker_path_chirho).unwrap();
    // A changed timestamp is outside the signature.
    let tampered_chirho = String::from_utf8(original_chirho.clone())
        .unwrap()
        .replacen("\"at_ms_chirho\":", "\"at_ms_chirho\":1", 1);
    std::fs::write(&marker_path_chirho, tampered_chirho).unwrap();
    assert_eq!(
        identity_chirho(&debts_chirho(root_path_chirho).unwrap_err()),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
    // A valid marker under a name outside the closed set.
    std::fs::write(&marker_path_chirho, &original_chirho).unwrap();
    std::fs::rename(
        &marker_path_chirho,
        marker_chirho(root_path_chirho, "another-debt"),
    )
    .unwrap();
    assert_eq!(
        identity_chirho(&debts_chirho(root_path_chirho).unwrap_err()),
        AccountAttributionRefusalChirho::AttributionRecordUnverifiedChirho
    );
}
