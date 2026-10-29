// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::issuer_chirho::OfflineKindIssuerSignerChirho;
use crate::plan_chirho::load_verified_plan_chirho;
use cairn_ledger_host_chirho::{
    host_ledger_signer_refs_from_config_chirho, HostLedgerSignersChirho, LedgerSignerRoleChirho,
};
use cairn_ledger_log_chirho::ports_chirho::LedgerSignerPortChirho;

fn load_signer_inputs_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
) -> (
    crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho,
    HostLedgerSignersChirho,
) {
    let verified_chirho = load_verified_plan_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        &fixture_chirho.plan_path_chirho,
        &fixture_chirho.expected_digest_chirho,
    )
    .unwrap();
    let refs_chirho = host_ledger_signer_refs_from_config_chirho(
        &verified_chirho.config_chirho.signer_secrets_chirho,
    )
    .unwrap();
    let signers_chirho =
        HostLedgerSignersChirho::load_existing_chirho(&fixture_chirho.root_chirho, &refs_chirho)
            .unwrap();
    (verified_chirho, signers_chirho)
}

#[test]
fn seventh_secret_name_must_differ_from_all_runtime_roles_chirho() {
    let fixture_chirho = fixture_with_issuer_chirho(1, RUNTIME_SECRET_NAMES_CHIRHO[0], false);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let (verified_chirho, signers_chirho) = load_signer_inputs_chirho(&fixture_chirho);
    let error_chirho = OfflineKindIssuerSignerChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.issuer_secret_name_chirho,
        &verified_chirho.config_chirho.kind_issuer_chirho,
        &signers_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::JournalChirho,
        }
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn seventh_identity_must_differ_even_under_a_distinct_secret_name_chirho() {
    let fixture_chirho = fixture_with_issuer_chirho(1, ISSUER_SECRET_NAME_CHIRHO, false);
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let (verified_chirho, signers_chirho) = load_signer_inputs_chirho(&fixture_chirho);
    let error_chirho = OfflineKindIssuerSignerChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.issuer_secret_name_chirho,
        &verified_chirho.config_chirho.kind_issuer_chirho,
        &signers_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::IssuerIdentityCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::JournalChirho,
        }
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn issuer_pin_mismatch_refuses_before_any_create_chirho() {
    let fixture_chirho = fixture_chirho();
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.issuer_secret_name_chirho,
        &[8_u8; 32],
    )
    .unwrap();
    let before_chirho = snapshot_tree_chirho(&fixture_chirho.root_chirho);
    let (verified_chirho, signers_chirho) = load_signer_inputs_chirho(&fixture_chirho);
    let error_chirho = OfflineKindIssuerSignerChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.issuer_secret_name_chirho,
        &verified_chirho.config_chirho.kind_issuer_chirho,
        &signers_chirho,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho,
        LedgerRegenesisRefusalChirho::IssuerPinMismatchChirho
    );
    assert_eq!(
        snapshot_tree_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn offline_issuer_refuses_every_foreign_canonical_schema_chirho() {
    let fixture_chirho = fixture_chirho();
    let (verified_chirho, signers_chirho) = load_signer_inputs_chirho(&fixture_chirho);
    let signer_chirho = OfflineKindIssuerSignerChirho::load_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.issuer_secret_name_chirho,
        &verified_chirho.config_chirho.kind_issuer_chirho,
        &signers_chirho,
    )
    .unwrap();
    let error_chirho = signer_chirho
        .sign_chirho(r#"{"schema_chirho":"cairn-ledger-record-v1-chirho"}"#)
        .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("foreign canonical message class"));
}
