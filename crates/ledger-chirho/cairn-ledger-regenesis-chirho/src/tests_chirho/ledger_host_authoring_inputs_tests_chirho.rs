// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::error_chirho::LedgerRegenesisRefusalChirho;
use crate::ledger_host_authoring_inputs_chirho::{
    canonical_ledger_host_authoring_inputs_bytes_chirho,
    ledger_host_authoring_inputs_digest_chirho,
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho,
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringMemberInputChirho,
    LedgerHostAuthoringPostgresEffectInputChirho, LedgerHostAuthoringRouteInputChirho,
    LedgerHostAuthoringSignerRefsInputChirho, LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO,
};
use cairn_config_chirho::config_chirho::LedgerHostPostgresEffectPostureChirho;
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;

type AuthoringInputsAliasMutationChirho = Box<dyn FnOnce(&mut LedgerHostAuthoringInputsV1Chirho)>;

/// Exactly 64 lowercase hex characters — the shape of a verifying-key pin.
const PIN_SHAPED_HEX_CHIRHO: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
/// One character short of a pin. It is the boundary control: this must be ACCEPTED, otherwise the
/// key-material arm would pass against a scanner that refuses any hex at all.
const ONE_SHORT_OF_PIN_HEX_CHIRHO: &str =
    "111111111111111111111111111111111111111111111111111111111111111";

fn example_policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
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

/// A complete, valid reviewed document. Every arm below mutates one coordinate of this fixture and
/// asserts the fixture itself still validates, so no arm can pass because the fixture went bad.
fn valid_inputs_chirho() -> LedgerHostAuthoringInputsV1Chirho {
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

fn canonical_text_chirho(inputs_chirho: &LedgerHostAuthoringInputsV1Chirho) -> String {
    String::from_utf8(canonical_ledger_host_authoring_inputs_bytes_chirho(inputs_chirho).unwrap())
        .unwrap()
}

/// One mutation, one named refusal. Proves in order: the unmutated fixture VALIDATES (so the arm
/// is never vacuous), the mutation actually CHANGED the document (so it is never a silent no-op),
/// the refusal is EXACTLY the expected identity, and it is not the neighbouring identity a fixture
/// could plausibly trip instead.
fn assert_one_mutation_refuses_chirho(
    mutate_chirho: impl FnOnce(&mut LedgerHostAuthoringInputsV1Chirho),
    expected_chirho: LedgerRegenesisRefusalChirho,
    neighbour_chirho: LedgerRegenesisRefusalChirho,
) {
    let valid_chirho = valid_inputs_chirho();
    valid_chirho.validate_chirho().unwrap();
    let mut mutated_chirho = valid_chirho.clone();
    mutate_chirho(&mut mutated_chirho);
    assert_ne!(
        mutated_chirho, valid_chirho,
        "the mutation did not change the document, so the refusal below would prove nothing"
    );
    let refusal_chirho = mutated_chirho.validate_chirho().unwrap_err();
    assert_eq!(refusal_chirho, expected_chirho);
    assert_ne!(refusal_chirho, neighbour_chirho);
    assert_ne!(
        expected_chirho.to_string(),
        neighbour_chirho.to_string(),
        "two refusals that read alike cannot tell an operator which law fired"
    );
}

#[test]
fn valid_reviewed_document_round_trips_through_canonical_bytes_and_digest_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    inputs_chirho.validate_chirho().unwrap();
    let canonical_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&inputs_chirho).unwrap();
    let parsed_chirho =
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(&canonical_bytes_chirho)
            .unwrap();
    assert_eq!(parsed_chirho, inputs_chirho);
    assert_eq!(
        canonical_ledger_host_authoring_inputs_bytes_chirho(&parsed_chirho).unwrap(),
        canonical_bytes_chirho
    );
    let digest_chirho = ledger_host_authoring_inputs_digest_chirho(&canonical_bytes_chirho);
    assert_eq!(digest_chirho.len(), 64);
    assert!(digest_chirho
        .bytes()
        .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f')));
    assert_eq!(
        digest_chirho,
        ledger_host_authoring_inputs_digest_chirho(
            &canonical_ledger_host_authoring_inputs_bytes_chirho(&parsed_chirho).unwrap()
        )
    );
}

/// The shared-journal choice is part of the REVIEWED bytes, not an invocation-only flag. Flipping
/// it must therefore change the digest an authoring run is required to present.
#[test]
fn shared_journal_choice_is_bound_by_the_reviewed_inputs_digest_chirho() {
    let ordinary_chirho = valid_inputs_chirho();
    let ordinary_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&ordinary_chirho).unwrap();
    assert!(
        !String::from_utf8_lossy(&ordinary_bytes_chirho)
            .contains("test_kind_shared_journal_chirho"),
        "false stays omitted so existing v1 canonical documents keep their bytes"
    );

    let mut shared_chirho = ordinary_chirho.clone();
    shared_chirho.test_kind_shared_journal_chirho = true;
    let shared_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&shared_chirho).unwrap();
    assert!(String::from_utf8_lossy(&shared_bytes_chirho)
        .contains("\"test_kind_shared_journal_chirho\":true"));
    assert_ne!(ordinary_bytes_chirho, shared_bytes_chirho);
    assert_ne!(
        ledger_host_authoring_inputs_digest_chirho(&ordinary_bytes_chirho),
        ledger_host_authoring_inputs_digest_chirho(&shared_bytes_chirho),
        "review and author must not disagree about shared-journal authoring under one digest"
    );
    assert_eq!(
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(&shared_bytes_chirho)
            .unwrap(),
        shared_chirho
    );
}

/// A document with NO activation authority is representable and valid — the later derivation brick
/// selects the config schema from what is present, so an operator can never write a schema tag that
/// silently drops an authority it also supplied.
#[test]
fn activation_authority_is_optional_and_absent_documents_still_validate_chirho() {
    let mut inputs_chirho = valid_inputs_chirho();
    inputs_chirho.activation_principal_chirho = None;
    inputs_chirho.validate_chirho().unwrap();
    let document_text_chirho = canonical_text_chirho(&inputs_chirho);
    assert!(
        !document_text_chirho.contains("activation_principal_chirho"),
        "an absent authority must not appear in the reviewed bytes at all"
    );
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        document_text_chirho.as_bytes(),
    )
    .unwrap();
}

/// THE AUTHORITY ARM the design names for this brick: a key-hex FIELD cannot round-trip into the
/// reviewed document, whichever name an operator gives it and wherever they put it.
#[test]
fn a_verifying_key_field_cannot_round_trip_into_the_reviewed_document_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    let document_text_chirho = canonical_text_chirho(&inputs_chirho);
    // Positive control: the unmodified canonical bytes DO parse, so every refusal below is caused
    // by the injected field and not by broken JSON.
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        document_text_chirho.as_bytes(),
    )
    .unwrap();

    let injections_chirho = [
        // A top-level pin beside the issuer principal.
        (
            "\"issuer_principal_chirho\":",
            format!("\"issuer_verifying_key_hex_chirho\":\"{PIN_SHAPED_HEX_CHIRHO}\",\"issuer_principal_chirho\":"),
        ),
        // The v3/v4 held-verifier pin block, which is pure key hex.
        (
            "\"monitor_cadence_ms_chirho\":",
            format!("\"held_verifier_pins_chirho\":{{\"journal_verifying_key_hex_chirho\":\"{PIN_SHAPED_HEX_CHIRHO}\"}},\"monitor_cadence_ms_chirho\":"),
        ),
        // A pin smuggled into a nested object rather than the top level.
        (
            "\"journal_chirho\":",
            format!("\"journal_verifying_key_hex_chirho\":\"{PIN_SHAPED_HEX_CHIRHO}\",\"journal_chirho\":"),
        ),
    ];
    for (anchor_chirho, replacement_chirho) in injections_chirho {
        let injected_text_chirho =
            document_text_chirho.replacen(anchor_chirho, &replacement_chirho, 1);
        assert_ne!(
            injected_text_chirho, document_text_chirho,
            "the injection anchor {anchor_chirho} did not match, so this arm would prove nothing"
        );
        let refusal_chirho = parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            injected_text_chirho.as_bytes(),
        )
        .unwrap_err();
        // Identity matters: the document refuses because the FIELD does not exist, before any
        // value-shaped scan gets a say. `deny_unknown_fields` is what makes a pin unrepresentable.
        assert_eq!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsInvalidChirho
        );
        assert_ne!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho
        );
    }
}

/// The second half of "never launder a pin": a pin hidden in a field that legitimately accepts a
/// free-form lowercase token is refused by VALUE SHAPE, on both the parsed and the programmatic road.
#[test]
fn a_pin_shaped_value_is_refused_in_a_free_form_token_chirho() {
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| inputs_chirho.cluster_id_chirho = PIN_SHAPED_HEX_CHIRHO.to_owned(),
        LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    // Uppercase is refused for the same reason, and BEFORE the lowercase-token grammar gets it —
    // an uppercase pin is a pin one `to_lowercase` away, not a mere grammar slip.
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho.cluster_id_chirho = PIN_SHAPED_HEX_CHIRHO.to_uppercase();
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    // Boundary control: one character short of a pin is ACCEPTED. Without this the arm above would
    // also pass against a scanner that simply refused hex, which would refuse honest coordinates.
    let mut one_short_chirho = valid_inputs_chirho();
    one_short_chirho.cluster_id_chirho = ONE_SHORT_OF_PIN_HEX_CHIRHO.to_owned();
    one_short_chirho.validate_chirho().unwrap();
    // The parsed road refuses it too, not only the programmatic one.
    let mut pinned_chirho = valid_inputs_chirho();
    pinned_chirho.cluster_id_chirho = PIN_SHAPED_HEX_CHIRHO.to_owned();
    let pinned_text_chirho = canonical_text_chirho(&pinned_chirho);
    assert_eq!(
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            pinned_text_chirho.as_bytes()
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringInputsKeyMaterialRefusedChirho
    );
}

/// Ruling (c): the config validator has no path-distinctness check, so two registries can point at
/// one object and validate cleanly. This document refuses that aliasing for every config the
/// generic author emits.
#[test]
fn two_coordinates_may_not_alias_one_storage_object_chirho() {
    let alias_cases_chirho: Vec<AuthoringInputsAliasMutationChirho> = vec![
        // Two registries at one object — the exact hazard ruling (c) names.
        Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho
                .projection_registry_path_chirho
                .clone_from(&inputs_chirho.kind_registry_path_chirho);
        }),
        // A registry at the journal.
        Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho
                .source_registry_path_chirho
                .clone_from(&inputs_chirho.journal_path_chirho);
        }),
        // A published projection head at the journal.
        Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.projection_routes_chirho[0]
                .head_path_chirho
                .clone_from(&inputs_chirho.journal_path_chirho);
        }),
        // Two distinct routes publishing to one head.
        Box::new(|inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            let first_head_chirho = inputs_chirho.projection_routes_chirho[0]
                .head_path_chirho
                .clone();
            inputs_chirho.projection_routes_chirho[1].head_path_chirho = first_head_chirho;
        }),
    ];
    for alias_case_chirho in alias_cases_chirho {
        assert_one_mutation_refuses_chirho(
            alias_case_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
        );
    }
    // A duplicate route NAME is a different defect and must not be reported as an alias: the config
    // validator already refuses duplicate names, so conflating the two would hide which gap fired.
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            let first_name_chirho = inputs_chirho.projection_routes_chirho[0]
                .projection_name_chirho
                .clone();
            inputs_chirho.projection_routes_chirho[1].projection_name_chirho = first_name_chirho;
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho,
    );
}

#[test]
fn namespaces_must_be_distinct_siblings_of_one_fresh_parent_chirho() {
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho
                .monitor_evidence_namespace_chirho
                .clone_from(&inputs_chirho.storage_namespace_chirho);
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsNamespaceLayoutRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho.monitor_evidence_namespace_chirho =
                "another-parent-chirho/ops-chirho".to_owned();
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsNamespaceLayoutRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho
                .staging_parent_chirho
                .clone_from(&inputs_chirho.fresh_parent_chirho);
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsNamespaceLayoutRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
}

#[test]
fn the_two_offline_authorities_must_be_separately_named_chirho() {
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho.activation_principal_chirho =
                Some(inputs_chirho.issuer_principal_chirho.clone());
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsAuthorityPrincipalRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| inputs_chirho.issuer_principal_chirho = "Not A Token".to_owned(),
        LedgerRegenesisRefusalChirho::AuthoringInputsAuthorityPrincipalRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
}

#[test]
fn membership_must_be_a_non_empty_set_of_valid_distinct_accounts_chirho() {
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| inputs_chirho.members_chirho.clear(),
        LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            let first_member_chirho = inputs_chirho.members_chirho[0].clone();
            inputs_chirho.members_chirho[1] = first_member_chirho;
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| inputs_chirho.members_chirho[0].owner_chirho = "user/nothex".to_owned(),
        LedgerRegenesisRefusalChirho::AuthoringInputsMembershipRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
}

#[test]
fn the_six_signer_secret_names_must_be_pairwise_distinct_chirho() {
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| {
            inputs_chirho
                .signer_secrets_chirho
                .effect_terminal_chirho
                .clone_from(&inputs_chirho.signer_secrets_chirho.effect_intent_chirho);
        },
        LedgerRegenesisRefusalChirho::AuthoringInputsSignerRefsRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
    assert_one_mutation_refuses_chirho(
        |inputs_chirho| inputs_chirho.signer_secrets_chirho.journal_chirho = String::new(),
        LedgerRegenesisRefusalChirho::AuthoringInputsSignerRefsRefusedChirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
    );
}

#[test]
fn the_priced_effect_may_only_charge_the_kind_this_document_creates_chirho() {
    assert_one_mutation_refuses_chirho(
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
    // Positive control on the other side: an uncomposed provider is valid.
    let mut without_provider_chirho = valid_inputs_chirho();
    without_provider_chirho.postgres_effect_chirho = None;
    without_provider_chirho.validate_chirho().unwrap();
}

#[test]
fn money_and_cadence_coordinates_carry_their_own_bounds_chirho() {
    for money_mutation_chirho in [
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.initial_mint_amount_chirho = 0;
        },
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.genesis_physical_ms_chirho = 0;
        },
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.mint_physical_ms_chirho = inputs_chirho.genesis_physical_ms_chirho;
        },
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.monitor_cadence_ms_chirho = 999;
        },
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.monitor_cadence_ms_chirho = 3_600_001;
        },
        |inputs_chirho: &mut LedgerHostAuthoringInputsV1Chirho| {
            inputs_chirho.journal_path_chirho = "../escape-chirho.jsonl".to_owned();
        },
    ] {
        assert_one_mutation_refuses_chirho(
            money_mutation_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsPathAliasRefusedChirho,
        );
    }
}

/// Reviewed bytes bind to exactly one encoding, so a digest an operator reviewed cannot be
/// re-spelled into different bytes that mean the same document.
#[test]
fn only_the_canonical_encoding_of_a_reviewed_document_is_accepted_chirho() {
    let inputs_chirho = valid_inputs_chirho();
    let document_text_chirho = canonical_text_chirho(&inputs_chirho);
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        document_text_chirho.as_bytes(),
    )
    .unwrap();

    let pretty_text_chirho = serde_json::to_string_pretty(&inputs_chirho).unwrap();
    assert_ne!(pretty_text_chirho, document_text_chirho);
    assert_eq!(
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            pretty_text_chirho.as_bytes()
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringInputsNonCanonicalChirho
    );

    // An explicit null for an absent optional parses to the same document but is not the canonical
    // spelling of absence, so it cannot carry a reviewed digest.
    let mut absent_optional_chirho = valid_inputs_chirho();
    absent_optional_chirho.postgres_effect_chirho = None;
    let absent_optional_text_chirho = canonical_text_chirho(&absent_optional_chirho);
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        absent_optional_text_chirho.as_bytes(),
    )
    .unwrap();
    let explicit_null_text_chirho = absent_optional_text_chirho.replacen(
        "\"issuer_principal_chirho\":",
        "\"postgres_effect_chirho\":null,\"issuer_principal_chirho\":",
        1,
    );
    assert_ne!(explicit_null_text_chirho, absent_optional_text_chirho);
    assert_eq!(
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            explicit_null_text_chirho.as_bytes()
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringInputsNonCanonicalChirho
    );
}

#[test]
fn a_foreign_document_schema_is_refused_before_any_coordinate_law_chirho() {
    let mut foreign_chirho = valid_inputs_chirho();
    foreign_chirho.schema_chirho = "ledger-host-config-v2-chirho".to_owned();
    assert_eq!(
        foreign_chirho.validate_chirho().unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringInputsSchemaRefusedChirho
    );
    let foreign_text_chirho = canonical_text_chirho(&foreign_chirho);
    assert_eq!(
        parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
            foreign_text_chirho.as_bytes()
        )
        .unwrap_err(),
        LedgerRegenesisRefusalChirho::AuthoringInputsSchemaRefusedChirho
    );
    // Positive control: the same bytes with this document's own schema tag are accepted.
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(
        canonical_text_chirho(&valid_inputs_chirho()).as_bytes(),
    )
    .unwrap();
}
