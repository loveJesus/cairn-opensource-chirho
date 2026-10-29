// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::ledger_host_artifact_derivation_chirho::{
    derive_ledger_host_artifacts_chirho, DerivedAuthorityPinChirho, DerivedAuthorityPinRoleChirho,
};
use crate::ledger_host_authoring_inputs_chirho::{
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringMemberInputChirho,
    LedgerHostAuthoringPostgresEffectInputChirho, LedgerHostAuthoringRouteInputChirho,
    LedgerHostAuthoringSignerRefsInputChirho, LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO,
};
use crate::ledger_host_authoring_mode_chirho::LedgerHostAuthoringModeChirho;
use crate::plan_chirho::validate_config_binding_chirho;
use cairn_config_chirho::config_chirho::{
    LedgerHostActivationPinConfigChirho, LedgerHostConfigChirho,
    LedgerHostPostgresEffectPostureChirho, LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
    LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO, LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
    LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
};
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;

type LedgerHostConfigMutationChirho = Box<dyn FnOnce(&mut LedgerHostConfigChirho)>;
type AuthoringInputsMutationChirho = Box<dyn FnOnce(&mut LedgerHostAuthoringInputsV1Chirho)>;
type AuthoringInputsRefusalCaseChirho = (
    &'static str,
    AuthoringInputsMutationChirho,
    LedgerRegenesisRefusalChirho,
);
type AuthoringInputsFieldPlacementChirho = (
    &'static str,
    Box<dyn Fn(&mut LedgerHostAuthoringInputsV1Chirho, &str)>,
);

/// Every arm below is about a DERIVATION law rather than about brick #5's authoring mode, so they
/// all run in the production posture and say so once, here, instead of repeating the same argument
/// twenty-two times. The mode's own behaviour — the stamped marker and the two naming laws — is
/// pinned in `ledger_host_authoring_mode_tests_chirho`, which calls the real function directly with
/// both modes.
fn derive_production_chirho(
    inputs_chirho: &LedgerHostAuthoringInputsV1Chirho,
    issuer_pin_chirho: &DerivedAuthorityPinChirho,
    activation_pin_chirho: Option<&DerivedAuthorityPinChirho>,
) -> Result<
    crate::ledger_host_artifact_derivation_chirho::LedgerHostAuthoredArtifactsChirho,
    LedgerRegenesisRefusalChirho,
> {
    derive_ledger_host_artifacts_chirho(
        inputs_chirho,
        issuer_pin_chirho,
        activation_pin_chirho,
        crate::destination_authority_enrollment_chirho::test_verified_destination_authority_enrollment_chirho(),
        LedgerHostAuthoringModeChirho::ProductionChirho,
    )
}

/// Two distinct, well-shaped, nonzero verifier pins. They stand in for what the custody brick will
/// derive from two pre-provisioned secrets; nothing here mints or writes a key.
const ISSUER_PIN_HEX_CHIRHO: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const ACTIVATION_PIN_HEX_CHIRHO: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
/// A third well-shaped pin that carries the ISSUER role. It exists so the activation slot can be
/// offered a wrongly-roled pin whose hex still DIFFERS from the issuer's — otherwise the config's
/// issuer/activation distinctness law would fire and the role check would go untested.
const SECOND_ISSUER_ROLE_PIN_HEX_CHIRHO: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
/// Exactly 64 lowercase hex characters — the shape of a verifying-key pin.
const PIN_SHAPED_HEX_CHIRHO: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
/// One character short of a pin. The boundary control for the key-material scan: without it, an
/// arm asserting "a pin is refused" would also pass against a scanner that refused all hex.
const ONE_SHORT_OF_PIN_HEX_CHIRHO: &str =
    "333333333333333333333333333333333333333333333333333333333333333";

pub(super) fn issuer_pin_chirho() -> DerivedAuthorityPinChirho {
    DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
        DerivedAuthorityPinRoleChirho::KindIssuerChirho,
        ISSUER_PIN_HEX_CHIRHO.to_owned(),
    )
}

pub(super) fn activation_pin_chirho() -> DerivedAuthorityPinChirho {
    DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
        DerivedAuthorityPinRoleChirho::LedgerActivationChirho,
        ACTIVATION_PIN_HEX_CHIRHO.to_owned(),
    )
}

fn second_issuer_role_pin_chirho() -> DerivedAuthorityPinChirho {
    DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
        DerivedAuthorityPinRoleChirho::KindIssuerChirho,
        SECOND_ISSUER_ROLE_PIN_HEX_CHIRHO.to_owned(),
    )
}

pub(super) fn example_policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "credit-minor-chirho".to_owned(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(max_supply_chirho),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-example-chirho".to_owned(),
        settlement_owner_chirho: Some("example-settlement-chirho".to_owned()),
        idempotency_window_chirho: Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: 86_400_000,
            retry_finality_horizon_ms_chirho: 86_400_000,
        }),
    }
}

/// A complete reviewed document that derives cleanly. Every arm below mutates one coordinate of it
/// and re-asserts the unmutated fixture still derives, so no arm can pass because the fixture went bad.
pub(super) fn valid_inputs_chirho() -> LedgerHostAuthoringInputsV1Chirho {
    LedgerHostAuthoringInputsV1Chirho {
        schema_chirho: LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: "ledger-host-parent-chirho".to_owned(),
        staging_parent_chirho: "ledger-host-staging-chirho".to_owned(),
        storage_namespace_chirho: "ledger-host-parent-chirho/ledger-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "ledger-host-parent-chirho/ops-chirho".to_owned(),
        monitor_evidence_path_chirho: "monitor/cycles-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-example-chirho".to_owned(),
        cluster_id_chirho: "cluster-example-chirho".to_owned(),
        local_epoch_chirho: 7,
        journal_path_chirho: "journals/main-chirho.jsonl".to_owned(),
        kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-example-chirho".to_owned(),
        projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-example-chirho".to_owned(),
        source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-example-chirho".to_owned(),
        projection_routes_chirho: vec![
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: "balance-chirho".to_owned(),
                head_path_chirho: "published/balance-head-chirho.json".to_owned(),
            },
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: "mirror-chirho".to_owned(),
                head_path_chirho: "published/mirror-head-chirho.json".to_owned(),
            },
        ],
        monitor_cadence_ms_chirho: 60_000,
        issuer_principal_chirho: "example-kind-issuer-chirho".to_owned(),
        activation_principal_chirho: Some("example-ledger-activation-chirho".to_owned()),
        members_chirho: vec![
            LedgerHostAuthoringMemberInputChirho {
                owner_chirho: "user/0123456789abcdef".to_owned(),
                kind_id_chirho: "prepaid-credits-chirho".to_owned(),
            },
            LedgerHostAuthoringMemberInputChirho {
                owner_chirho: "example-settlement-chirho".to_owned(),
                kind_id_chirho: "prepaid-credits-chirho".to_owned(),
            },
        ],
        signer_secrets_chirho: LedgerHostAuthoringSignerRefsInputChirho {
            journal_chirho: "example-journal-secret-chirho".to_owned(),
            config_chirho: "example-config-secret-chirho".to_owned(),
            feeder_chirho: "example-feeder-secret-chirho".to_owned(),
            kind_root_chirho: "example-kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "example-effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "example-effect-terminal-secret-chirho".to_owned(),
        },
        initial_owner_chirho: "user/0123456789abcdef".to_owned(),
        kind_id_chirho: "prepaid-credits-chirho".to_owned(),
        initial_policy_chirho: example_policy_chirho(2_000),
        amended_policy_chirho: example_policy_chirho(1_500),
        initial_mint_amount_chirho: 750,
        genesis_physical_ms_chirho: 5_000,
        mint_physical_ms_chirho: 5_250,
        postgres_effect_chirho: Some(LedgerHostAuthoringPostgresEffectInputChirho {
            posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
            connection_secret_chirho: "example-pg-dsn-chirho".to_owned(),
            billing_kind_chirho: "prepaid-credits-chirho".to_owned(),
        }),
        test_kind_shared_journal_chirho: false,
    }
}

/// One mutation, one named refusal, through the real derivation entry point. Proves in order: the
/// unmutated fixture DERIVES (so the arm is never vacuous), the mutation actually CHANGED the
/// document (so it is never a silent no-op), the refusal is EXACTLY the expected identity, and it
/// is not the neighbouring identity a fixture could plausibly trip instead.
fn assert_one_mutation_refuses_derivation_chirho(
    mutate_chirho: impl FnOnce(&mut LedgerHostAuthoringInputsV1Chirho),
    expected_chirho: LedgerRegenesisRefusalChirho,
    neighbour_chirho: LedgerRegenesisRefusalChirho,
) {
    let valid_chirho = valid_inputs_chirho();
    derive_production_chirho(
        &valid_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
    let mut mutated_chirho = valid_chirho.clone();
    mutate_chirho(&mut mutated_chirho);
    assert_ne!(
        mutated_chirho, valid_chirho,
        "the mutation did not change the document, so the refusal below would prove nothing"
    );
    let refusal_chirho = derive_production_chirho(
        &mutated_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap_err();
    assert_eq!(refusal_chirho, expected_chirho);
    assert_ne!(refusal_chirho, neighbour_chirho);
    assert_ne!(
        expected_chirho.to_string(),
        neighbour_chirho.to_string(),
        "two refusals that read alike cannot tell an operator which law fired"
    );
}

#[test]
fn one_reviewed_document_derives_a_bound_config_and_plan_pair_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    let artifacts_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();

    // The issuer pin lands where the mint authority's outer trust root is read from, and the
    // activation pin lands in its own distinct position.
    assert_eq!(
        artifacts_chirho
            .config_chirho
            .kind_issuer_chirho
            .verifying_key_hex_chirho,
        ISSUER_PIN_HEX_CHIRHO
    );
    assert_eq!(
        artifacts_chirho
            .config_chirho
            .activation_authority_chirho
            .as_ref()
            .unwrap()
            .verifying_key_hex_chirho,
        ACTIVATION_PIN_HEX_CHIRHO
    );
    assert_eq!(
        artifacts_chirho
            .config_chirho
            .kind_issuer_chirho
            .principal_chirho,
        inputs_chirho.issuer_principal_chirho
    );

    // The binding the plan loader will later enforce holds on the derived pair, checked by that
    // loader's OWN function rather than by a re-statement of its 15 comparisons here.
    validate_config_binding_chirho(
        &artifacts_chirho.plan_chirho,
        &artifacts_chirho.config_chirho,
    )
    .unwrap();
    // Routes are compared pairwise IN ORDER downstream, so order is part of the binding.
    assert_eq!(
        artifacts_chirho
            .plan_chirho
            .projection_routes_chirho
            .iter()
            .map(|route_chirho| route_chirho.projection_name_chirho.as_str())
            .collect::<Vec<_>>(),
        vec!["balance-chirho", "mirror-chirho"]
    );

    // The plan digest is the review coordinate the operator will be asked to pass back.
    assert_eq!(artifacts_chirho.plan_digest_chirho.len(), 64);
    assert!(artifacts_chirho
        .plan_digest_chirho
        .bytes()
        .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')));

    // Deterministic: the same reviewed document and the same pins derive the same bytes, or a
    // review digest would mean nothing.
    let repeat_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
    assert_eq!(repeat_chirho, artifacts_chirho);
}

/// The config schema is DERIVED from what the document contains. An operator never writes a schema
/// tag, so they can never pick one that silently drops an authority they also supplied.
#[test]
fn the_config_schema_is_derived_from_the_authorities_actually_present_chirho() {
    let with_activation_chirho = derive_production_chirho(
        &valid_inputs_chirho(),
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
    assert_eq!(
        with_activation_chirho.config_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
    );
    assert!(with_activation_chirho
        .config_chirho
        .activation_authority_chirho
        .is_some());

    let mut without_activation_chirho = valid_inputs_chirho();
    without_activation_chirho.activation_principal_chirho = None;
    let derived_chirho =
        derive_production_chirho(&without_activation_chirho, &issuer_pin_chirho(), None).unwrap();
    assert_eq!(
        derived_chirho.config_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO
    );
    assert!(derived_chirho
        .config_chirho
        .activation_authority_chirho
        .is_none());
}

/// Ruling (e): held-verifier pins are another root's public halves and cannot be honestly supplied
/// here, so no reachable input can produce a config carrying them — nor a schema that requires them.
#[test]
fn no_reachable_input_can_author_held_verifier_pins_or_their_schemas_chirho() {
    let mut derived_count_chirho = 0_usize;
    for activation_present_chirho in [true, false] {
        for postgres_present_chirho in [true, false] {
            let mut inputs_chirho = valid_inputs_chirho();
            if !activation_present_chirho {
                inputs_chirho.activation_principal_chirho = None;
            }
            if !postgres_present_chirho {
                inputs_chirho.postgres_effect_chirho = None;
            }
            let activation_pin_chirho = activation_pin_chirho();
            let artifacts_chirho = derive_production_chirho(
                &inputs_chirho,
                &issuer_pin_chirho(),
                activation_present_chirho.then_some(&activation_pin_chirho),
            )
            .unwrap();
            derived_count_chirho += 1;
            assert!(
                artifacts_chirho
                    .config_chirho
                    .held_verifier_pins_chirho
                    .is_none(),
                "a held pin nobody could justify must never reach an authored config"
            );
            assert_ne!(
                artifacts_chirho.config_chirho.schema_chirho,
                LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO
            );
            assert_ne!(
                artifacts_chirho.config_chirho.schema_chirho,
                LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO
            );
        }
    }
    // Pair the assertions above with a nonzero count, so a loop that never ran cannot read as proof.
    assert_eq!(derived_count_chirho, 4);
}

/// THE MONEY ARM. The config validator proves the two pins are DISTINCT but cannot know which is
/// which, so a swapped pair would install the activation key as the mint authority's outer trust
/// root and pass every existing check. The role tag is what refuses it.
#[test]
fn a_pin_derived_for_one_authority_cannot_be_installed_as_the_other_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    // Positive control: correctly-roled pins derive.
    derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();

    // CASE 1 - the ISSUER slot alone. The document carries no activation authority, so no
    // activation pin is supplied and the activation-side check cannot fire: only the issuer-side
    // check can produce this refusal.
    //
    // Isolating this way is not tidiness. The first version of this arm tested only the full swap
    // below, and deleting the issuer-side check left it GREEN — the activation-side check was
    // catching the swap on its own. A fixture that two refusals can satisfy proves neither.
    let mut without_activation_chirho = valid_inputs_chirho();
    without_activation_chirho.activation_principal_chirho = None;
    let issuer_slot_refusal_chirho =
        derive_production_chirho(&without_activation_chirho, &activation_pin_chirho(), None)
            .unwrap_err();
    assert_eq!(
        issuer_slot_refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho
    );
    assert_ne!(
        issuer_slot_refusal_chirho,
        LedgerRegenesisRefusalChirho::ConfigInvalidChirho
    );

    // CASE 2 - the ACTIVATION slot alone. The issuer slot is correctly roled, and the pin offered
    // for activation is a DIFFERENT hex that happens to carry the issuer role, so the config's
    // issuer/activation distinctness law stays silent and only the role check can fire.
    let activation_slot_refusal_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&second_issuer_role_pin_chirho()),
    )
    .unwrap_err();
    assert_eq!(
        activation_slot_refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho
    );
    assert_ne!(
        activation_slot_refusal_chirho,
        LedgerRegenesisRefusalChirho::ConfigInvalidChirho
    );

    // CASE 3 - the realistic operator error: both pins in each other's slots.
    let refusal_chirho = derive_production_chirho(
        &inputs_chirho,
        &activation_pin_chirho(),
        Some(&issuer_pin_chirho()),
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho
    );
    // Assert the reason: this must NOT be the config's generic invalidity, or the arm would pass
    // for the wrong law and the role fence could be deleted without anything going red.
    assert_ne!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::ConfigInvalidChirho
    );

    // And prove the fence is load-bearing rather than redundant: remove the role check by building
    // the swapped config by hand, and the CONFIG'S OWN validator accepts it. Two distinct, valid,
    // nonzero pins in each other's positions is exactly what it cannot see.
    let mut swapped_config_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap()
    .config_chirho;
    swapped_config_chirho
        .kind_issuer_chirho
        .verifying_key_hex_chirho = ACTIVATION_PIN_HEX_CHIRHO.to_owned();
    swapped_config_chirho.activation_authority_chirho = Some(LedgerHostActivationPinConfigChirho {
        principal_chirho: "example-ledger-activation-chirho".to_owned(),
        verifying_key_hex_chirho: ISSUER_PIN_HEX_CHIRHO.to_owned(),
    });
    swapped_config_chirho.validate_chirho().expect(
        "the config validator proves distinctness only; if this now REFUSES, the config gained a \
         role-binding law and this brick's role fence may be retargeted at it",
    );
}

/// An activation principal with no pin would silently drop the authority the document asked for;
/// a pin with no principal would attach an authority nobody reviewed.
#[test]
fn an_activation_principal_and_its_pin_must_arrive_together_chirho() {
    let with_principal_chirho = valid_inputs_chirho();
    let mut without_principal_chirho = valid_inputs_chirho();
    without_principal_chirho.activation_principal_chirho = None;

    // Both positive controls first: together, and neither.
    derive_production_chirho(
        &with_principal_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
    derive_production_chirho(&without_principal_chirho, &issuer_pin_chirho(), None).unwrap();

    // A reviewed principal, no pin.
    assert_eq!(
        derive_production_chirho(&with_principal_chirho, &issuer_pin_chirho(), None).unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringActivationPinPairingRefusedChirho
    );
    // A pin, no reviewed principal.
    assert_eq!(
        derive_production_chirho(
            &without_principal_chirho,
            &issuer_pin_chirho(),
            Some(&activation_pin_chirho()),
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringActivationPinPairingRefusedChirho
    );
}

/// One home, no drift: the "64 lowercase hex, nonzero" law lives in the config validator and is not
/// copied here, so a malformed pin is refused by that one home when this brick runs it.
#[test]
fn a_malformed_pin_is_refused_by_the_config_s_own_key_law_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    let malformed_pins_chirho = [
        // All zero — a "valid hex" value that names no key.
        "0000000000000000000000000000000000000000000000000000000000000000",
        // Too short.
        "1111",
        // Uppercase, which the serving boundary does not accept.
        "AAAA111111111111111111111111111111111111111111111111111111111111",
    ];
    for malformed_pin_chirho in malformed_pins_chirho {
        let refusal_chirho = derive_production_chirho(
            &inputs_chirho,
            &DerivedAuthorityPinChirho::from_existing_secret_derivation_chirho(
                DerivedAuthorityPinRoleChirho::KindIssuerChirho,
                malformed_pin_chirho.to_owned(),
            ),
            Some(&activation_pin_chirho()),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::ConfigInvalidChirho,
            "malformed pin {malformed_pin_chirho} must be refused by the config's own key law"
        );
        assert_ne!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringPinRoleRefusedChirho
        );
    }
    // Positive control: the well-shaped pin derives, so the arm above is not passing because the
    // fixture is broken.
    derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
}

/// The reviewed document's own laws are RUN on the programmatic road too, so a caller that builds
/// the struct in code cannot reach derivation by skipping the document's parser.
#[test]
fn the_document_s_own_laws_are_run_before_anything_is_derived_chirho() {
    // Ruling (c)'s aliasing hazard, arriving through the derivation entry point.
    assert_one_mutation_refuses_derivation_chirho(
        |inputs_chirho| {
            inputs_chirho
                .projection_registry_path_chirho
                .clone_from(&inputs_chirho.kind_registry_path_chirho);
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    // The priced effect may only charge the kind this document creates.
    assert_one_mutation_refuses_derivation_chirho(
        |inputs_chirho| {
            inputs_chirho
                .postgres_effect_chirho
                .as_mut()
                .unwrap()
                .billing_kind_chirho = "some-other-kind-chirho".to_owned();
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsBillingKindMismatchChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    // A pin smuggled into a free-form token still cannot ride into an authored artifact.
    assert_one_mutation_refuses_derivation_chirho(
        |inputs_chirho| inputs_chirho.cluster_id_chirho = PIN_SHAPED_HEX_CHIRHO.to_owned(),
        LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
}

/// `ConfigPlanMismatchChirho` is unreachable from any INPUT, because both artifacts come from one
/// document — so the arm that keeps the binding check honest mutates the DERIVED pair instead, and
/// separately proves the checker itself fires.
#[test]
fn the_binding_check_this_brick_runs_is_live_not_ceremonial_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    let artifacts_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .unwrap();
    // Positive control: the derived pair binds.
    validate_config_binding_chirho(
        &artifacts_chirho.plan_chirho,
        &artifacts_chirho.config_chirho,
    )
    .unwrap();

    // Every scalar the binding compares, corrupted one at a time on the CONFIG side. If any of
    // these stops firing, the pair could drift with nothing detecting it.
    let corruptions_chirho: Vec<LedgerHostConfigMutationChirho> = vec![
        Box::new(|config_chirho| config_chirho.local_epoch_chirho += 1),
        Box::new(|config_chirho| {
            config_chirho.cluster_id_chirho = "other-cluster-chirho".to_owned()
        }),
        Box::new(|config_chirho| {
            config_chirho.kind_registry_id_chirho = "other-registry-chirho".to_owned()
        }),
        Box::new(|config_chirho| {
            config_chirho.kind_issuer_chirho.principal_chirho = "other-issuer-chirho".to_owned()
        }),
        Box::new(|config_chirho| config_chirho.monitor_cadence_ms_chirho += 1),
        Box::new(|config_chirho| {
            config_chirho.projection_routes_chirho.pop();
        }),
        Box::new(|config_chirho| {
            config_chirho.projection_routes_chirho.swap(0, 1);
        }),
    ];
    let mut fired_chirho = 0_usize;
    for corrupt_chirho in corruptions_chirho {
        let mut config_chirho = artifacts_chirho.config_chirho.clone();
        corrupt_chirho(&mut config_chirho);
        assert_ne!(
            config_chirho, artifacts_chirho.config_chirho,
            "the corruption did not change the config, so the refusal below would prove nothing"
        );
        assert_eq!(
            validate_config_binding_chirho(&artifacts_chirho.plan_chirho, &config_chirho)
                .unwrap_err(),
            LedgerRegenesisRefusalChirho::ConfigPlanMismatchChirho
        );
        fired_chirho += 1;
    }
    assert_eq!(fired_chirho, 7);
}

/// RECORDED GAP, deliberately not closed in this brick — measured rather than asserted.
///
/// Nothing in the reviewed document, the config validator, or the plan validators requires the
/// genesis mint's `initial_owner_chirho` to be an ADMITTED member for `kind_id_chirho`. Membership
/// is the account-scoped admission predicate, so a document naming an unadmitted initial owner
/// authors cleanly here and fails later, at the genesis mint leg.
///
/// It is left open on purpose: adding it would be a NEW money law that no reviewed home carries
/// yet, and this brick's rule is to run existing laws rather than invent them. This arm exists so
/// the gap is a measured fact with a place to land, not a paragraph in a report.
///
/// MIGRATION PATH: if this now REFUSES, the admission binding was added — that is the intended
/// hardening. Retarget this arm at the new refusal's identity WITHOUT touching the fixture, so the
/// new green is a statement about the code rather than about the test. If it still derives, the
/// gap is still open.
#[test]
fn an_unadmitted_initial_owner_still_authors_today_recorded_gap_chirho() {
    let mut inputs_chirho = valid_inputs_chirho();
    // The initial owner is admitted for NO kind at all: membership names only the settlement owner.
    inputs_chirho.members_chirho = vec![LedgerHostAuthoringMemberInputChirho {
        owner_chirho: "example-settlement-chirho".to_owned(),
        kind_id_chirho: "prepaid-credits-chirho".to_owned(),
    }];
    assert!(
        !inputs_chirho
            .members_chirho
            .iter()
            .any(|member_chirho| member_chirho.owner_chirho == inputs_chirho.initial_owner_chirho),
        "the fixture must actually leave the initial owner unadmitted, or this measures nothing"
    );
    let artifacts_chirho = derive_production_chirho(
        &inputs_chirho,
        &issuer_pin_chirho(),
        Some(&activation_pin_chirho()),
    )
    .expect(
        "MEASURED GAP: an unadmitted initial owner authors cleanly today. If this now REFUSES, an \
         admission binding was added - retarget this arm at that refusal's identity.",
    );
    // And the mismatch really is carried into both artifacts, so a later reader can see the shape.
    assert_eq!(
        artifacts_chirho.plan_chirho.initial_owner_chirho,
        "user/0123456789abcdef"
    );
    assert!(!artifacts_chirho
        .config_chirho
        .members_chirho
        .iter()
        .any(|member_chirho| member_chirho.owner_chirho
            == artifacts_chirho.plan_chirho.initial_owner_chirho));
}

// ---------------------------------------------------------------------------------------------
// ARMS AGAINST BRICK #1, CHOSEN BY THIS BRICK'S AUTHOR.
//
// All thirteen of brick #1's arms were written by its own author, so they cannot reveal a property
// that author did not think of. Both arms below probe the reviewed document's laws — not this
// brick's — and both target the same untested corner: `KindPolicyBodyChirho`'s free-text fields,
// the ONLY fields in the document that brick #1 gives no grammar at all. Brick #1's own
// pin-in-a-token arm exercises `cluster_id_chirho`, a field that is token-validated as well, so a
// pin there trips two laws; in the policy body the key-material scan is the sole defence.
// ---------------------------------------------------------------------------------------------

/// ARM 1 AGAINST BRICK #1. The reviewed document applies NO grammar and NO money law to either
/// policy body — deliberately, so the money-policy law keeps one home. This measures the size of
/// that hole rather than assuming it, then proves this brick's delegation is what closes it.
///
/// The sharpest case is the last: a document that mints MORE THAN THE DECLARED MAX SUPPLY is
/// accepted by `LedgerHostAuthoringInputsV1Chirho::validate_chirho` in full.
#[test]
fn brick1_applies_no_law_to_the_policy_bodies_and_this_brick_s_delegation_is_what_closes_it_chirho()
{
    let accepted_by_the_document_chirho: Vec<AuthoringInputsRefusalCaseChirho> = vec![
        (
            "an empty policy unit",
            Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
                inputs_chirho.initial_policy_chirho.unit_chirho = String::new();
            }),
            LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho,
        ),
        (
            "a settlement owner carrying whitespace",
            Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
                inputs_chirho.initial_policy_chirho.settlement_owner_chirho =
                    Some("settlement owner chirho".to_owned());
            }),
            LedgerRegenesisRefusalChirho::PlanCoordinateRefusedChirho,
        ),
        (
            "an amendment that amends nothing",
            Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
                inputs_chirho
                    .amended_policy_chirho
                    .clone_from(&inputs_chirho.initial_policy_chirho);
            }),
            LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho,
        ),
        (
            "a mint larger than the declared max supply",
            Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
                // The fixture's initial policy declares a max supply of 2,000.
                inputs_chirho.initial_mint_amount_chirho = 10_000;
            }),
            LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho,
        ),
    ];

    let mut measured_chirho = 0_usize;
    for (description_chirho, mutate_chirho, expected_chirho) in accepted_by_the_document_chirho {
        let valid_chirho = valid_inputs_chirho();
        valid_chirho.validate_chirho().unwrap();
        let mut mutated_chirho = valid_chirho.clone();
        mutate_chirho(&mut mutated_chirho);
        assert_ne!(
            mutated_chirho, valid_chirho,
            "{description_chirho}: the mutation did not change the document"
        );
        // MEASURED, not assumed: brick #1 accepts this document in full.
        mutated_chirho
            .validate_chirho()
            .unwrap_or_else(|refusal_chirho| {
                panic!(
                "{description_chirho}: the reviewed document REFUSED this ({refusal_chirho}). That \
                 is brick #1 gaining a policy law it did not have — retarget this arm at whatever \
                 that new law is, and check it did not become a second copy of the plan's."
            )
            });
        // And the derivation refuses it, by running the law's one home.
        let refusal_chirho = derive_production_chirho(
            &mutated_chirho,
            &issuer_pin_chirho(),
            Some(&activation_pin_chirho()),
        )
        .unwrap_err();
        assert_eq!(
            refusal_chirho, expected_chirho,
            "{description_chirho}: derivation must refuse with the plan law's own identity"
        );
        measured_chirho += 1;
    }
    assert_eq!(measured_chirho, 4);
}

/// ARM 2 AGAINST BRICK #1. The key-material scan runs over the whole canonical document, so it
/// should also cover the policy fields that have no token grammar. Brick #1 never tested a field
/// with no other law behind it, which is exactly where a gap would be invisible.
#[test]
fn brick1_key_material_scan_reaches_the_fields_it_gives_no_grammar_chirho() {
    let ungoverned_fields_chirho: Vec<AuthoringInputsFieldPlacementChirho> = vec![
        (
            "initial_policy.unit_chirho",
            Box::new(
                |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho, value_chirho: &str| {
                    inputs_chirho.initial_policy_chirho.unit_chirho = value_chirho.to_owned();
                    inputs_chirho.amended_policy_chirho.unit_chirho = value_chirho.to_owned();
                },
            ),
        ),
        (
            "initial_policy.shard_attachment_chirho",
            Box::new(
                |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho, value_chirho: &str| {
                    inputs_chirho.initial_policy_chirho.shard_attachment_chirho =
                        value_chirho.to_owned();
                    inputs_chirho.amended_policy_chirho.shard_attachment_chirho =
                        value_chirho.to_owned();
                },
            ),
        ),
        (
            "initial_policy.settlement_owner_chirho",
            Box::new(
                |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho, value_chirho: &str| {
                    inputs_chirho.initial_policy_chirho.settlement_owner_chirho =
                        Some(value_chirho.to_owned());
                    inputs_chirho.amended_policy_chirho.settlement_owner_chirho =
                        Some(value_chirho.to_owned());
                },
            ),
        ),
    ];

    let mut covered_chirho = 0_usize;
    for (field_chirho, place_chirho) in ungoverned_fields_chirho {
        // A full pin in a field with no grammar behind it: the scan is the only thing that can see it.
        let mut pinned_chirho = valid_inputs_chirho();
        place_chirho(&mut pinned_chirho, PIN_SHAPED_HEX_CHIRHO);
        assert_eq!(
            pinned_chirho.validate_chirho().unwrap_err(),
            LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho,
            "{field_chirho} has no token grammar, so a pin there is visible only to the scan"
        );
        // Derivation cannot be reached either, with the same identity.
        assert_eq!(
            derive_production_chirho(
                &pinned_chirho,
                &issuer_pin_chirho(),
                Some(&activation_pin_chirho()),
            )
            .unwrap_err(),
            LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho
        );

        // BOUNDARY CONTROL: one character short of a pin is accepted here. Without it, the arm
        // above would also pass against a scan that refused any hex at all — which would refuse
        // honest coordinates and prove nothing about pins.
        let mut one_short_chirho = valid_inputs_chirho();
        place_chirho(&mut one_short_chirho, ONE_SHORT_OF_PIN_HEX_CHIRHO);
        one_short_chirho.validate_chirho().unwrap_or_else(|refusal_chirho| {
            panic!(
                "{field_chirho}: a 63-character hex run must be ACCEPTED ({refusal_chirho}); a scan \
                 that refuses all hex is not a pin scan"
            )
        });
        covered_chirho += 1;
    }
    assert_eq!(covered_chirho, 3);
}
