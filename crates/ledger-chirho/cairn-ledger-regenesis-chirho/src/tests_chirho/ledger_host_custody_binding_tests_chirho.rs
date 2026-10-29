// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Adversarial arms for brick #3, the custody binding. Every arm here asks the question the design
//! says this brick can fail quietly on: **what wrong-but-plausible key would this accept?**
//!
//! Three conventions make a green here mean something.
//! 1. **Refusal IDENTITY, never merely "an error".** Each arm asserts the exact refusal AND asserts
//!    the neighbouring refusal did NOT fire, because several fences here refuse with similar shapes
//!    and a fixture can otherwise pass for the wrong reason.
//! 2. **A positive control per arm.** Every arm mutates one thing off a fixture it has just proven
//!    binds, so no arm can pass because the fixture went bad.
//! 3. **The document is reused, not re-authored.** The reviewed input document comes from brick #2's
//!    fixture rather than a copy written by this brick's author, so these arms cannot be tuned to a
//!    document shaped to satisfy them.

use super::ledger_host_artifact_derivation_tests_chirho::{
    example_policy_chirho, valid_inputs_chirho,
};
use super::{hex_encode_chirho, temp_root_chirho};
use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::ledger_host_authoring_inputs_chirho::{
    canonical_ledger_host_authoring_inputs_bytes_chirho, LedgerHostAuthoringInputsV1Chirho,
    LedgerHostAuthoringSignerRefsInputChirho,
};
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::ledger_host_custody_binding_chirho::{
    bind_custody_and_derive_ledger_host_artifacts_chirho, LedgerHostCustodyBoundArtifactsChirho,
    LedgerHostCustodyRequestChirho,
};
use cairn_config_chirho::config_chirho::{
    LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
};
use cairn_ledger_host_chirho::LedgerSignerRoleChirho;
use cairn_secret_chirho::secret_chirho::{set_secret_chirho, SECRETS_DIR_CHIRHO};
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};

const ISSUER_SECRET_NAME_CHIRHO: &str = "custody-offline-issuer-chirho";
const ACTIVATION_SECRET_NAME_CHIRHO: &str = "custody-offline-activation-chirho";
/// Distinct seed bytes per role, so any arm that plants one role's value under another name is
/// making a real collision rather than an accidental one.
const JOURNAL_SEED_CHIRHO: u8 = 1;
const CONFIG_SEED_CHIRHO: u8 = 2;
const FEEDER_SEED_CHIRHO: u8 = 3;
const KIND_ROOT_SEED_CHIRHO: u8 = 4;
const EFFECT_INTENT_SEED_CHIRHO: u8 = 5;
const EFFECT_TERMINAL_SEED_CHIRHO: u8 = 6;
const ISSUER_SEED_CHIRHO: u8 = 7;
const ACTIVATION_SEED_CHIRHO: u8 = 8;

struct CustodyFixtureChirho {
    root_chirho: PathBuf,
}

impl Drop for CustodyFixtureChirho {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_chirho);
    }
}

/// A root whose eight secrets are all pre-provisioned, well formed, and pairwise distinct. Nothing
/// in this module ever creates a key through the code under test; a secret exists here only because
/// this fixture wrote it, exactly as an operator would with `secret-set`.
fn fixture_chirho() -> CustodyFixtureChirho {
    let root_chirho = temp_root_chirho();
    fs::create_dir(&root_chirho).unwrap();
    let signer_secrets_chirho = valid_inputs_chirho().signer_secrets_chirho;
    for (name_chirho, seed_chirho) in role_seeds_chirho(&signer_secrets_chirho) {
        set_secret_chirho(&root_chirho, &name_chirho, &[seed_chirho; 32]).unwrap();
    }
    set_secret_chirho(
        &root_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        &[ISSUER_SEED_CHIRHO; 32],
    )
    .unwrap();
    set_secret_chirho(
        &root_chirho,
        ACTIVATION_SECRET_NAME_CHIRHO,
        &[ACTIVATION_SEED_CHIRHO; 32],
    )
    .unwrap();
    CustodyFixtureChirho { root_chirho }
}

fn role_seeds_chirho(
    signer_secrets_chirho: &LedgerHostAuthoringSignerRefsInputChirho,
) -> Vec<(String, u8)> {
    vec![
        (
            signer_secrets_chirho.journal_chirho.clone(),
            JOURNAL_SEED_CHIRHO,
        ),
        (
            signer_secrets_chirho.config_chirho.clone(),
            CONFIG_SEED_CHIRHO,
        ),
        (
            signer_secrets_chirho.feeder_chirho.clone(),
            FEEDER_SEED_CHIRHO,
        ),
        (
            signer_secrets_chirho.kind_root_chirho.clone(),
            KIND_ROOT_SEED_CHIRHO,
        ),
        (
            signer_secrets_chirho.effect_intent_chirho.clone(),
            EFFECT_INTENT_SEED_CHIRHO,
        ),
        (
            signer_secrets_chirho.effect_terminal_chirho.clone(),
            EFFECT_TERMINAL_SEED_CHIRHO,
        ),
    ]
}

fn bind_chirho(
    root_chirho: &Path,
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_secret_name_chirho: &str,
    activation_secret_name_chirho: Option<&str>,
) -> Result<LedgerHostCustodyBoundArtifactsChirho, LedgerRegenesisRefusalChirho> {
    bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
        selected_root_chirho: root_chirho,
        inputs_chirho,
        destination_authority_enrollment_chirho:
            crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
        issuer_secret_name_chirho,
        activation_secret_name_chirho,
        // Custody arms are about keys, not about brick #5's posture; the mode's own laws are pinned
        // in `ledger_host_authoring_mode_tests_chirho`.
        mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
    })
}

/// The unmutated call every arm runs first as its positive control.
fn bind_default_chirho(
    fixture_chirho: &CustodyFixtureChirho,
) -> Result<LedgerHostCustodyBoundArtifactsChirho, LedgerRegenesisRefusalChirho> {
    bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
}

/// The public verifying key of a seed, computed by this test's OWN ed25519 call rather than by the
/// code under test. A pin assertion that reused the production derivation would prove only that the
/// function equals itself.
fn expected_pin_hex_chirho(seed_chirho: u8) -> String {
    hex_encode_chirho(
        SigningKey::from_bytes(&[seed_chirho; 32])
            .verifying_key()
            .as_bytes(),
    )
}

/// How many secret files the store holds. It RESOLVES the directory name from the secret module's
/// own constant and unwraps rather than defaulting to zero: a swallowed error here would report "no
/// key was minted" for a path that was never looked at, which is the reassuring-zero failure.
fn secret_file_count_chirho(root_chirho: &Path) -> usize {
    fs::read_dir(root_chirho.join(SECRETS_DIR_CHIRHO))
        .unwrap()
        .count()
}

// =================================================================================================
// The happy path, and the assertion that the pin is the key the operator meant.
// =================================================================================================

#[test]
fn custody_binding_pins_the_public_half_of_the_named_existing_secrets_chirho() {
    let fixture_chirho = fixture_chirho();
    let bound_chirho = bind_default_chirho(&fixture_chirho).unwrap();
    // The whole point of "derive, never accept": the pin equals the public half of the secret the
    // operator named, measured here by an independent ed25519 call.
    assert_eq!(
        bound_chirho
            .artifacts_chirho
            .config_chirho
            .kind_issuer_chirho
            .verifying_key_hex_chirho,
        expected_pin_hex_chirho(ISSUER_SEED_CHIRHO)
    );
    assert_eq!(
        bound_chirho
            .artifacts_chirho
            .config_chirho
            .activation_authority_chirho
            .as_ref()
            .unwrap()
            .verifying_key_hex_chirho,
        expected_pin_hex_chirho(ACTIVATION_SEED_CHIRHO)
    );
    assert_eq!(
        bound_chirho.artifacts_chirho.config_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
    );
    assert_eq!(
        bound_chirho
            .custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        6
    );
    assert_eq!(
        bound_chirho
            .custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        2
    );
    assert!(
        bound_chirho
            .custody_evidence_chirho
            .provider_connection_secret_checked_chirho
    );
    // Custody is a READ. Eight secrets went in and eight are still there: nothing was minted.
    assert_eq!(secret_file_count_chirho(&fixture_chirho.root_chirho), 8);
}

#[test]
fn custody_binding_without_an_activation_secret_authors_the_v1_shape_chirho() {
    let fixture_chirho = fixture_chirho();
    let bound_chirho = bind_default_chirho(&fixture_chirho).unwrap();
    assert_eq!(
        bound_chirho.artifacts_chirho.config_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
    );

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.activation_principal_chirho = None;
    let without_activation_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        None,
    )
    .unwrap();
    assert_eq!(
        without_activation_chirho
            .artifacts_chirho
            .config_chirho
            .schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO
    );
    assert!(without_activation_chirho
        .artifacts_chirho
        .config_chirho
        .activation_authority_chirho
        .is_none());
    assert_eq!(
        without_activation_chirho
            .custody_evidence_chirho
            .proven_offline_authority_count_chirho,
        1
    );
}

#[test]
fn digest_bound_test_kind_choice_derives_only_the_shared_journal_verifier_chirho() {
    let fixture_chirho = fixture_chirho();
    let test_kind_issuer_secret_chirho = "test-kind-chirho-custody-offline-issuer-chirho";
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        test_kind_issuer_secret_chirho,
        &[ISSUER_SEED_CHIRHO; 32],
    )
    .unwrap();
    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.issuer_principal_chirho =
        "test-kind-chirho-custody-kind-issuer-chirho".to_owned();
    inputs_chirho.test_kind_shared_journal_chirho = true;

    let bound_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho: &fixture_chirho.root_chirho,
            inputs_chirho: &inputs_chirho,
            destination_authority_enrollment_chirho:
                crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
            issuer_secret_name_chirho: test_kind_issuer_secret_chirho,
            activation_secret_name_chirho: Some(ACTIVATION_SECRET_NAME_CHIRHO),
            mode_chirho: LedgerHostAuthoringModeChirho::TestKindChirho,
        })
        .unwrap();
    let config_chirho = &bound_chirho.artifacts_chirho.config_chirho;
    assert_eq!(
        config_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO
    );
    let pins_chirho = config_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .expect("the reviewed shared-journal choice must derive its public verifier");
    assert_eq!(
        pins_chirho.journal_verifying_key_hex_chirho,
        expected_pin_hex_chirho(JOURNAL_SEED_CHIRHO),
        "the pin must be the public half of the already-loaded journal signer"
    );
    assert!(pins_chirho.effect_intent_verifying_key_hex_chirho.is_none());
    assert!(pins_chirho
        .effect_terminal_verifying_key_hex_chirho
        .is_none());
    assert!(config_chirho.test_kind_chirho.is_some());
    assert!(
        bound_chirho
            .custody_evidence_chirho
            .shared_journal_verifier_authored_chirho
    );
    config_chirho.validate_chirho().unwrap();
}

#[test]
fn production_shared_journal_choice_refuses_before_secret_custody_chirho() {
    let root_chirho = temp_root_chirho();
    fs::create_dir(&root_chirho).unwrap();
    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.test_kind_shared_journal_chirho = true;
    let refusal_chirho =
        bind_custody_and_derive_ledger_host_artifacts_chirho(LedgerHostCustodyRequestChirho {
            selected_root_chirho: &root_chirho,
            inputs_chirho: &inputs_chirho,
            destination_authority_enrollment_chirho:
                crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
            issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: Some(ACTIVATION_SECRET_NAME_CHIRHO),
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringSharedJournalRequiresTestKindChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretUnavailableChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::JournalChirho,
        },
        "the mode refusal must happen before the empty root is asked for a signer"
    );
    assert_eq!(fs::read_dir(&root_chirho).unwrap().count(), 0);
    fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_activation_principal_without_an_activation_secret_refuses_the_pairing_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();
    // The document asks for an activation authority; the operator named no activation secret. The
    // author must refuse rather than silently drop the authority the document reviewed.
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        None,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringActivationPinPairingRefusedChirho
    );
}

// =================================================================================================
// NEVER MINT.
// =================================================================================================

#[test]
fn an_absent_issuer_secret_refuses_and_creates_nothing_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();
    let before_chirho = secret_file_count_chirho(&fixture_chirho.root_chirho);

    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        "custody-never-provisioned-issuer-chirho",
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho
    );
    // A missing key is a hard stop, never a generated convenience.
    assert_eq!(
        secret_file_count_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

#[test]
fn an_absent_activation_secret_refuses_and_creates_nothing_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();
    let before_chirho = secret_file_count_chirho(&fixture_chirho.root_chirho);

    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some("custody-never-provisioned-activation-chirho"),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretRefusedChirho
    );
    assert_eq!(
        secret_file_count_chirho(&fixture_chirho.root_chirho),
        before_chirho
    );
}

// =================================================================================================
// The wrong-but-plausible keys. Each pair is the same defect asked twice: once by NAME, once by
// IDENTITY. The identity half is the one a config review cannot see.
// =================================================================================================

#[test]
fn an_issuer_secret_named_as_a_runtime_signer_refuses_by_name_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let kind_root_name_chirho = valid_inputs_chirho().signer_secrets_chirho.kind_root_chirho;
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        &kind_root_name_chirho,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::KindRootChirho,
        }
    );
}

/// **The headline arm of this brick.** The operator provisions a NEW secret name for the offline
/// issuer and fills it with the same 32 bytes that already sit in the runtime `kind_root_chirho`
/// secret. Every name is distinct, the document validates, the pin is well formed, the config would
/// parse and boot — and the kind registry's two-root containment (issuer signature plus runtime
/// `kind_root_chirho` signature) has silently collapsed to one root. A name comparison sees nothing.
#[test]
fn an_issuer_secret_holding_a_runtime_signer_value_refuses_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let colliding_name_chirho = "custody-issuer-with-kind-root-value-chirho";
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        colliding_name_chirho,
        &[KIND_ROOT_SEED_CHIRHO; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        colliding_name_chirho,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerIdentityCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::KindRootChirho,
        }
    );
    // The neighbouring fence must NOT be what fired: the name really is distinct here, so a green
    // that came from the name check would mean this arm never exercised the identity check at all.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::KindRootChirho,
        }
    );
}

#[test]
fn an_activation_secret_named_as_the_issuer_refuses_by_name_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ISSUER_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretMatchesIssuerChirho
    );
}

/// The activation authority under its own name, holding the issuer's bytes. Two names, one key —
/// and the config's own issuer/activation distinctness law compares the two PINS, which are then
/// equal, so this would eventually refuse. The point of catching it here is that it refuses with a
/// custody identity that names the defect instead of a config-shape identity that does not.
#[test]
fn an_activation_secret_holding_the_issuer_value_refuses_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let colliding_name_chirho = "custody-activation-with-issuer-value-chirho";
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        colliding_name_chirho,
        &[ISSUER_SEED_CHIRHO; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(colliding_name_chirho),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationIdentityMatchesIssuerChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretMatchesIssuerChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ConfigInvalidChirho
    );
}

#[test]
fn an_activation_secret_named_as_a_runtime_signer_refuses_by_name_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let feeder_name_chirho = valid_inputs_chirho().signer_secrets_chirho.feeder_chirho;
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(&feeder_name_chirho),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::FeederChirho,
        }
    );
}

#[test]
fn an_activation_secret_holding_a_runtime_signer_value_refuses_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let colliding_name_chirho = "custody-activation-with-feeder-value-chirho";
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        colliding_name_chirho,
        &[FEEDER_SEED_CHIRHO; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(colliding_name_chirho),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationIdentityCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::FeederChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::FeederChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationIdentityMatchesIssuerChirho
    );
}

// =================================================================================================
// The six runtime signers: one arm per defect, each with its own refusal identity.
// =================================================================================================

#[test]
fn an_absent_runtime_signer_secret_refuses_by_role_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.signer_secrets_chirho.effect_terminal_chirho =
        "custody-never-provisioned-terminal-chirho".to_owned();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretUnavailableChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::EffectTerminalChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho
    );
}

#[test]
fn a_short_runtime_signer_secret_refuses_by_role_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let config_name_chirho = valid_inputs_chirho().signer_secrets_chirho.config_chirho;
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        &config_name_chirho,
        &[2_u8; 31],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretLengthChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::ConfigChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretUnavailableChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::ConfigChirho,
        }
    );
}

#[test]
fn an_all_zero_runtime_signer_secret_refuses_by_role_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let journal_name_chirho = valid_inputs_chirho().signer_secrets_chirho.journal_chirho;
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        &journal_name_chirho,
        &[0_u8; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretAllZeroChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::JournalChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerSecretLengthChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::JournalChirho,
        }
    );
}

/// Two roles, two distinct names, one secret VALUE. The document's own signer-refs law cannot see
/// this — it compares names — so the only thing standing between an operator who seeded two roles
/// from one file and a cluster where `effect_intent` and `effect_terminal` are the same authority is
/// the loader's identity check.
#[test]
fn two_runtime_signer_roles_over_one_secret_value_refuse_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let terminal_name_chirho = valid_inputs_chirho()
        .signer_secrets_chirho
        .effect_terminal_chirho;
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        &terminal_name_chirho,
        &[EFFECT_INTENT_SEED_CHIRHO; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerDuplicateIdentityChirho {
            first_role_chirho: LedgerSignerRoleChirho::EffectIntentChirho,
            second_role_chirho: LedgerSignerRoleChirho::EffectTerminalChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho
    );
}

/// Duplicate signer NAMES never reach custody: the reviewed document refuses them first. This arm
/// exists so that fact is measured rather than assumed — and so a future reader does not go looking
/// for a runtime-signer duplicate-name refusal that deliberately has no named variant.
#[test]
fn duplicate_runtime_signer_names_refuse_at_the_document_before_custody_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.signer_secrets_chirho.feeder_chirho =
        inputs_chirho.signer_secrets_chirho.journal_chirho.clone();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsSignerRefsRefusedChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::RuntimeSignerRefusedChirho
    );
}

// =================================================================================================
// The provider connection secret — brick #1 checked its grammar and flagged its custody as this
// brick's question.
// =================================================================================================

#[test]
fn a_provider_connection_secret_named_as_a_runtime_signer_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    let feeder_name_chirho = inputs_chirho.signer_secrets_chirho.feeder_chirho.clone();
    inputs_chirho
        .postgres_effect_chirho
        .as_mut()
        .unwrap()
        .connection_secret_chirho = feeder_name_chirho;
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesRuntimeSignerChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::FeederChirho,
        }
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesIssuerChirho
    );
}

#[test]
fn a_provider_connection_secret_named_as_the_issuer_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho
        .postgres_effect_chirho
        .as_mut()
        .unwrap()
        .connection_secret_chirho = ISSUER_SECRET_NAME_CHIRHO.to_owned();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesIssuerChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesActivationChirho
    );
}

#[test]
fn a_provider_connection_secret_named_as_the_activation_authority_refuses_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho
        .postgres_effect_chirho
        .as_mut()
        .unwrap()
        .connection_secret_chirho = ACTIVATION_SECRET_NAME_CHIRHO.to_owned();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesActivationChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ProviderSecretNameCollidesIssuerChirho
    );
}

/// The boundary control for the three arms above: a document with NO provider block binds, and the
/// evidence says so rather than claiming a check that did not happen.
#[test]
fn a_document_without_a_provider_block_binds_and_reports_no_provider_check_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.postgres_effect_chirho = None;
    let bound_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap();
    assert!(bound_chirho
        .artifacts_chirho
        .config_chirho
        .postgres_effect_chirho
        .is_none());
    assert!(
        !bound_chirho
            .custody_evidence_chirho
            .provider_connection_secret_checked_chirho
    );
}

// =================================================================================================
// Ordering, and the reason the money-policy-unchecked parser is named that way.
// =================================================================================================

/// A defective document must refuse with a DOCUMENT identity even when a custody question would
/// also have failed. Without this the first refusal an operator sees depends on which check the
/// implementation happened to run first.
#[test]
fn a_document_defect_refuses_before_any_secret_is_read_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.monitor_cadence_ms_chirho = 1;
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        // Also name an issuer secret that does not exist, so a custody-first implementation would
        // produce a visibly different refusal here.
        "custody-never-provisioned-issuer-chirho",
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho
    );
}

/// The rename made executable. The SAME bytes that the money-policy-unchecked parser accepts in
/// full are refused by the composed custody road, because that road DERIVES and derivation runs the
/// plan's money-policy law. This is why the parser's name has to carry its limitation, and why an
/// operator surface must derive before it prints.
#[test]
fn a_mint_above_max_supply_parses_but_the_composed_custody_road_refuses_it_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.initial_policy_chirho = example_policy_chirho(2_000);
    inputs_chirho.initial_mint_amount_chirho = 10_000;
    let canonical_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&inputs_chirho).unwrap();
    let parsed_chirho =
        crate::ledger_host_authoring_inputs_chirho::parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            &canonical_bytes_chirho,
        )
        .unwrap();
    assert_eq!(parsed_chirho.initial_mint_amount_chirho, 10_000);

    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &inputs_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho
    );
}

/// Custody is proven on THIS root's secret store and nowhere else. A second root carrying the same
/// six NAMES over different VALUES binds just as cleanly here, because nothing cross-root is read —
/// which is the recorded FINDING A hazard, unresolved by this brick and named rather than implied.
#[test]
fn custody_is_per_root_and_a_peer_roots_values_are_never_consulted_chirho() {
    let first_fixture_chirho = fixture_chirho();
    let first_bound_chirho = bind_default_chirho(&first_fixture_chirho).unwrap();

    let second_root_chirho = temp_root_chirho();
    fs::create_dir(&second_root_chirho).unwrap();
    let second_fixture_chirho = CustodyFixtureChirho {
        root_chirho: second_root_chirho,
    };
    let signer_secrets_chirho = valid_inputs_chirho().signer_secrets_chirho;
    // Same names, DIFFERENT values. A real group requires identical bytes on every node; nothing in
    // this authoring path can see that, so it must not be read as having checked it.
    for (name_chirho, seed_chirho) in role_seeds_chirho(&signer_secrets_chirho) {
        set_secret_chirho(
            &second_fixture_chirho.root_chirho,
            &name_chirho,
            &[seed_chirho.wrapping_add(100); 32],
        )
        .unwrap();
    }
    set_secret_chirho(
        &second_fixture_chirho.root_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        &[ISSUER_SEED_CHIRHO; 32],
    )
    .unwrap();
    set_secret_chirho(
        &second_fixture_chirho.root_chirho,
        ACTIVATION_SECRET_NAME_CHIRHO,
        &[ACTIVATION_SEED_CHIRHO; 32],
    )
    .unwrap();

    let second_bound_chirho = bind_default_chirho(&second_fixture_chirho).unwrap();
    assert_eq!(
        first_bound_chirho.artifacts_chirho.config_chirho,
        second_bound_chirho.artifacts_chirho.config_chirho,
        "two roots whose runtime signer VALUES differ still author the same config; the divergence \
         surfaces later as a signature failure, which is the open FINDING A this brick does not close"
    );
}

// =================================================================================================
// REVIEWER-CHOSEN ARM (adversarial review of brick #3, added by the reviewer, not the builder).
//
// The builder's arms pin the SIX RUNTIME signers' length and all-zero fences by role, and pin the
// two OFFLINE authorities' ABSENCE and both COLLISION questions. They do NOT pin the two offline
// authorities' own LENGTH and ALL-ZERO fences: `IssuerSecretLengthChirho`,
// `IssuerSecretAllZeroChirho`, `ActivationSecretLengthChirho`, and `ActivationSecretAllZeroChirho`
// are raised in production at `issuer_chirho.rs:320,327,346,353` and asserted by ZERO tests.
//
// The LONG direction is the one that matters and the one an author's "too short" intuition misses:
// the fence is `!= 32`, and the very next statements are a 32-byte `copy_from_slice`. Weaken the
// fence to `< 32` — the natural-looking edit — and a 33-byte secret does not refuse, it PANICS on a
// money-authority authoring path. These arms make that a red test instead of a crash.
//
// The last arm is the discriminator that makes the all-zero fence mean something: a key whose only
// nonzero byte is the LAST one must still BIND. Without it, an all-zero arm passes just as well
// against a prefix/first-byte heuristic as against the correct `all()`.
// =================================================================================================

const REVIEW_OVERLONG_ISSUER_NAME_CHIRHO: &str = "custody-review-overlong-issuer-chirho";
const REVIEW_ZERO_ISSUER_NAME_CHIRHO: &str = "custody-review-zero-issuer-chirho";
const REVIEW_OVERLONG_ACTIVATION_NAME_CHIRHO: &str = "custody-review-overlong-activation-chirho";
const REVIEW_ZERO_ACTIVATION_NAME_CHIRHO: &str = "custody-review-zero-activation-chirho";
const REVIEW_TRAILING_BYTE_ISSUER_NAME_CHIRHO: &str = "custody-review-trailing-byte-issuer-chirho";

#[test]
fn an_over_long_offline_issuer_secret_refuses_by_length_and_never_panics_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();
    let before_chirho = secret_file_count_chirho(&fixture_chirho.root_chirho);

    set_secret_chirho(
        &fixture_chirho.root_chirho,
        REVIEW_OVERLONG_ISSUER_NAME_CHIRHO,
        &[7_u8; 33],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        REVIEW_OVERLONG_ISSUER_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretLengthChirho
    );
    // Assert the NEIGHBOURING refusal did not fire: a secret that exists but is the wrong size must
    // not present as the broad "secret refused", which is what an absent secret returns.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho
    );
    assert_eq!(
        secret_file_count_chirho(&fixture_chirho.root_chirho),
        before_chirho + 1,
        "only the arm's own planted secret may appear; the code under test must mint nothing"
    );
}

#[test]
fn an_all_zero_offline_issuer_secret_refuses_by_its_own_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    set_secret_chirho(
        &fixture_chirho.root_chirho,
        REVIEW_ZERO_ISSUER_NAME_CHIRHO,
        &[0_u8; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        REVIEW_ZERO_ISSUER_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretAllZeroChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretLengthChirho
    );
}

#[test]
fn an_over_long_offline_activation_secret_refuses_by_length_and_never_panics_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    set_secret_chirho(
        &fixture_chirho.root_chirho,
        REVIEW_OVERLONG_ACTIVATION_NAME_CHIRHO,
        &[8_u8; 33],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(REVIEW_OVERLONG_ACTIVATION_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretLengthChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretRefusedChirho
    );
}

#[test]
fn an_all_zero_offline_activation_secret_refuses_by_its_own_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    set_secret_chirho(
        &fixture_chirho.root_chirho,
        REVIEW_ZERO_ACTIVATION_NAME_CHIRHO,
        &[0_u8; 32],
    )
    .unwrap();
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        ISSUER_SECRET_NAME_CHIRHO,
        Some(REVIEW_ZERO_ACTIVATION_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretAllZeroChirho
    );
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ActivationSecretLengthChirho
    );
}

/// The discriminator. 31 zero bytes and one nonzero byte at the END is a perfectly valid ed25519
/// seed, and it must BIND — pinning the public half of exactly those bytes. A fence that read the
/// first byte, or a prefix, would refuse this while still passing the all-zero arms above, so this
/// is what proves those arms measure `all()` rather than a heuristic that merely agrees with it.
#[test]
fn a_secret_whose_only_nonzero_byte_is_last_is_a_valid_offline_issuer_key_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let mut trailing_byte_seed_chirho = [0_u8; 32];
    trailing_byte_seed_chirho[31] = 9;
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        REVIEW_TRAILING_BYTE_ISSUER_NAME_CHIRHO,
        &trailing_byte_seed_chirho,
    )
    .unwrap();
    let bound_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        REVIEW_TRAILING_BYTE_ISSUER_NAME_CHIRHO,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap();
    // Computed by this arm's OWN ed25519 call, never by the code under test.
    assert_eq!(
        bound_chirho
            .artifacts_chirho
            .config_chirho
            .kind_issuer_chirho
            .verifying_key_hex_chirho,
        hex_encode_chirho(
            SigningKey::from_bytes(&trailing_byte_seed_chirho)
                .verifying_key()
                .as_bytes()
        )
    );
    assert_eq!(
        bound_chirho
            .custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        6
    );
}

// =================================================================================================
// REVIEWER'S INDEPENDENT BUILD OF THE HEADLINE CLAIM (adversarial review; not the builder's arm).
//
// The builder's headline arm plants the `kind_root_chirho` value. These two rebuild the claim from
// scratch against a DIFFERENT role (`effect_terminal_chirho`), and add the delivery mechanism a
// filesystem gives an operator for free: a SYMLINK. `resolve_secret_ref_chirho` reads through
// `std::fs::read`, which follows links, so a link is a second name over one key's bytes — the exact
// "one key wearing two labels" this brick exists to refuse, arriving without anyone copying a file.
// =================================================================================================

/// The secrets-directory filename for a secret name, discovered by READING the directory rather
/// than by spelling the suffix constant (which is private to the secret module). Resolving beats
/// spelling: a changed suffix makes this fail loudly instead of silently planting nothing.
fn secret_file_path_chirho(root_chirho: &Path, secret_name_chirho: &str) -> PathBuf {
    let dir_chirho = root_chirho.join(SECRETS_DIR_CHIRHO);
    fs::read_dir(&dir_chirho)
        .unwrap()
        .map(|entry_chirho| entry_chirho.unwrap().path())
        .find(|path_chirho| {
            path_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str())
                .is_some_and(|name_chirho| {
                    name_chirho.starts_with(&format!("{secret_name_chirho}."))
                })
        })
        .unwrap_or_else(|| panic!("no secret file found for {secret_name_chirho}"))
}

/// **THE HEADLINE, rebuilt independently.** A NEW, distinct secret NAME is provisioned and filled
/// with the 32 bytes that already sit in the runtime `effect_terminal_chirho` secret. Every name is
/// distinct, the reviewed document validates, and the derived pin is perfectly well formed — so the
/// config would validate, parse and boot. Only an IDENTITY comparison can see that the offline
/// issuer and a runtime signer are one key, collapsing the registry's two-root containment to one.
#[test]
fn a_new_issuer_name_over_an_existing_runtime_signer_value_refuses_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    // Positive control FIRST, and it is the one that matters: the same "brand new issuer name"
    // road, with bytes that collide with nothing, BINDS and yields a well-formed pin. So when the
    // twin below refuses, the refusal cannot be blamed on the new-name road being broken.
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        "custody-review-fresh-issuer-chirho",
        &[77_u8; 32],
    )
    .unwrap();
    let control_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        "custody-review-fresh-issuer-chirho",
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap();
    let control_pin_chirho = &control_chirho
        .artifacts_chirho
        .config_chirho
        .kind_issuer_chirho
        .verifying_key_hex_chirho;
    assert_eq!(control_pin_chirho.len(), 64);
    assert!(control_pin_chirho.chars().all(|character_chirho| {
        character_chirho.is_ascii_hexdigit() && !character_chirho.is_ascii_uppercase()
    }));

    // Now the twin: a different NAME over the effect-terminal signer's exact bytes.
    set_secret_chirho(
        &fixture_chirho.root_chirho,
        "custody-review-twin-issuer-chirho",
        &[EFFECT_TERMINAL_SEED_CHIRHO; 32],
    )
    .unwrap();
    let signer_secrets_chirho = valid_inputs_chirho().signer_secrets_chirho;
    assert_ne!(
        "custody-review-twin-issuer-chirho", signer_secrets_chirho.effect_terminal_chirho,
        "the whole point is that the NAMES differ; if they matched, the name fence would fire and \
         this arm would pass for the wrong reason"
    );
    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        "custody-review-twin-issuer-chirho",
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerIdentityCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::EffectTerminalChirho,
        }
    );
    // And explicitly NOT the neighbouring name fence, which sees nothing here.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretNameCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::EffectTerminalChirho,
        }
    );
}

/// The same collapse delivered by a SYMLINK rather than by copied bytes. An operator who links a
/// convenient alias next to a real secret has created a second label over one key without ever
/// touching key material, and no name comparison anywhere can see it.
#[cfg(unix)]
#[test]
fn a_symlinked_issuer_secret_refuses_by_identity_chirho() {
    let fixture_chirho = fixture_chirho();
    bind_default_chirho(&fixture_chirho).unwrap();

    let signer_secrets_chirho = valid_inputs_chirho().signer_secrets_chirho;
    let target_chirho = secret_file_path_chirho(
        &fixture_chirho.root_chirho,
        &signer_secrets_chirho.effect_intent_chirho,
    );
    let link_name_chirho = "custody-review-symlink-issuer-chirho";
    let suffix_chirho = target_chirho
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .strip_prefix(&signer_secrets_chirho.effect_intent_chirho)
        .unwrap()
        .to_owned();
    let link_path_chirho = fixture_chirho
        .root_chirho
        .join(SECRETS_DIR_CHIRHO)
        .join(format!("{link_name_chirho}{suffix_chirho}"));
    std::os::unix::fs::symlink(&target_chirho, &link_path_chirho).unwrap();
    // Positive control on the FIXTURE, not on the code under test: the link really does deliver the
    // same bytes, so a refusal below is about identity and not about an unreadable file.
    assert_eq!(
        fs::read(&link_path_chirho).unwrap(),
        fs::read(&target_chirho).unwrap()
    );

    let refusal_chirho = bind_chirho(
        &fixture_chirho.root_chirho,
        &valid_inputs_chirho(),
        link_name_chirho,
        Some(ACTIVATION_SECRET_NAME_CHIRHO),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerIdentityCollisionChirho {
            runtime_role_chirho: LedgerSignerRoleChirho::EffectIntentChirho,
        }
    );
}
