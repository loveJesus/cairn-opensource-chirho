// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::canonical_chirho::{
    canonical_contract_set_bytes_chirho, canonical_undo_plan_bytes_chirho,
    contract_set_digest_chirho, parse_canonical_undo_document_chirho,
    reversion_contract_digest_chirho, undo_plan_hash_chirho, UndoWireDocumentChirho,
};
use crate::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, canonical_capability_bytes_chirho,
    canonical_capability_multiset_bytes_chirho, canonicalize_capabilities_chirho,
    validate_asset_op_port_binding_chirho, validate_reversion_contract_set_chirho,
    AssetOpPortRequirementChirho, BlessedContractKeyChirho, BlessedReversionContractChirho,
    BlessedReversionContractSetChirho, ConfigPortRequirementChirho, EffectDoorSelectorChirho,
    EffectPricingSourceRequirementChirho, EffectReconciliationRequirementChirho,
    EffectResultCachePostureChirho, IrreversibleResidualChirho, ObservationReasonChirho,
    SupportingCapabilityRequirementChirho, UndoActionChirho, UndoDispositionChirho,
    UndoEvidenceKindChirho, UndoStepTemplateChirho, UndoVerificationModeChirho,
    POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO, REVERSION_CONTRACT_SCHEMA_CHIRHO,
    REVERSION_CONTRACT_SET_SCHEMA_CHIRHO,
};
use crate::derive_chirho::{derive_undo_plan_chirho, VerifiedUndoDagInputChirho};
use crate::framing_chirho::{
    compensation_step_key_chirho, door_capability_fingerprint_chirho, effect_instance_key_chirho,
    framed_blake3_hash_chirho,
};
use cairn_core_chirho::model_chirho::{
    CapabilityChirho, DagChirho, EdgeChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_core_chirho::store_chirho::hash_object_chirho;
use cairn_input_projection_chirho::field_graph_chirho::{
    canonical_field_graph_hash_chirho, parse_canonical_field_graph_chirho,
    CanonicalFieldNodeChirho, FieldRequirednessChirho, PrivacyClassChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::{
    AssetOpChirho, RoundingChirho, ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO,
    ASSET_OP_FIELD_GRAPH_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use std::collections::{BTreeMap, BTreeSet};

const AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO: &str =
    include_str!("../tests-chirho/golden-chirho/authoring-contract-set-v1-chirho.json");
const SINGLE_WRITE_PLAN_GOLDEN_CHIRHO: &str =
    include_str!("../tests-chirho/golden-chirho/single-write-plan-v1-chirho.json");
const AUTHORING_CONTRACT_SET_DIGEST_GOLDEN_CHIRHO: &str =
    "058e3ce3ca4110d11346e62d4e330520653184d0fa1f72371070d4d9942427aa";
const SINGLE_WRITE_PLAN_DIGEST_GOLDEN_CHIRHO: &str =
    "7eb0dbebd61c70eb112616f11906d888398820d4d8f242c1ab37076463b27669";

fn legacy_authoring_contract_set_chirho() -> BlessedReversionContractSetChirho {
    match parse_canonical_undo_document_chirho(AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO.trim_end())
        .unwrap()
    {
        UndoWireDocumentChirho::ContractSetChirho(contract_set_chirho) => contract_set_chirho,
        UndoWireDocumentChirho::PlanChirho(_) => {
            panic!("legacy authoring contract golden parsed as an undo plan")
        }
    }
}

fn hash_chirho(label_chirho: &str) -> HashChirho {
    HashChirho(blake3::hash(label_chirho.as_bytes()).to_hex().to_string())
}

fn step_chirho() -> UndoStepTemplateChirho {
    UndoStepTemplateChirho {
        action_chirho: UndoActionChirho::ConditionalRestoreChirho,
        required_evidence_chirho: vec![
            UndoEvidenceKindChirho::BeforeImageRefChirho,
            UndoEvidenceKindChirho::PostStateFingerprintChirho,
        ],
        verification_chirho: UndoVerificationModeChirho::VerifyPostFingerprintChirho,
    }
}

fn compensable_contract_chirho(
    key_chirho: &str,
    selector_chirho: EffectDoorSelectorChirho,
    supporting_chirho: Vec<SupportingCapabilityRequirementChirho>,
) -> BlessedReversionContractChirho {
    let (privacy_chirho, residuals_chirho, gate_chirho) = match &selector_chirho {
        EffectDoorSelectorChirho::QueryChirho => (
            PrivacyClassChirho::DirectChirho,
            vec![IrreversibleResidualChirho::CallerExposureChirho],
            Some(hash_chirho("query-gate-chirho")),
        ),
        EffectDoorSelectorChirho::PaidEffectChirho { effect_chirho }
            if effect_chirho == "llm_chirho" =>
        {
            (
                PrivacyClassChirho::DirectChirho,
                vec![IrreversibleResidualChirho::ProviderWorkConsumedChirho],
                Some(hash_chirho("llm-gate-chirho")),
            )
        }
        EffectDoorSelectorChirho::TemplateAppDeployChirho => (
            PrivacyClassChirho::SafeChirho,
            vec![
                IrreversibleResidualChirho::PublishedUrlObservedChirho,
                IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho,
            ],
            Some(hash_chirho("deploy-gate-chirho")),
        ),
        _ => (PrivacyClassChirho::SafeChirho, Vec::new(), None),
    };
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho(key_chirho.to_string()),
        effect_selector_chirho: selector_chirho,
        supporting_requirements_chirho: supporting_chirho,
        produced_evidence_chirho: vec![
            UndoEvidenceKindChirho::BeforeImageRefChirho,
            UndoEvidenceKindChirho::PostStateFingerprintChirho,
        ],
        disposition_chirho: UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![step_chirho()],
            residuals_chirho,
            admission_gate_chirho: gate_chirho,
        },
        privacy_floor_chirho: privacy_chirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: None,
    }
}

fn observation_contract_chirho(
    key_chirho: &str,
    selector_chirho: EffectDoorSelectorChirho,
) -> BlessedReversionContractChirho {
    BlessedReversionContractChirho {
        schema_chirho: REVERSION_CONTRACT_SCHEMA_CHIRHO.to_string(),
        contract_key_chirho: BlessedContractKeyChirho(key_chirho.to_string()),
        effect_selector_chirho: selector_chirho,
        supporting_requirements_chirho: Vec::new(),
        produced_evidence_chirho: Vec::new(),
        disposition_chirho: UndoDispositionChirho::ObservationOnlyChirho {
            reason_code_chirho: ObservationReasonChirho::ReadOnlyCapabilityChirho,
        },
        privacy_floor_chirho: PrivacyClassChirho::SafeChirho,
        max_depth_chirho: 8,
        config_ports_chirho: Vec::new(),
        asset_op_ports_chirho: Vec::new(),
        reconciliation_requirement_chirho: None,
        pricing_source_requirement_chirho: None,
        effect_result_cache_posture_chirho: None,
    }
}

fn set_chirho(
    mut contracts_chirho: Vec<BlessedReversionContractChirho>,
) -> BlessedReversionContractSetChirho {
    contracts_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho
            .contract_key_chirho
            .cmp(&right_chirho.contract_key_chirho)
    });
    BlessedReversionContractSetChirho {
        schema_chirho: REVERSION_CONTRACT_SET_SCHEMA_CHIRHO.to_string(),
        max_depth_chirho: 8,
        contracts_chirho,
    }
}

fn node_chirho(capabilities_chirho: Vec<CapabilityChirho>) -> (HashChirho, NodeDefChirho) {
    let node_chirho = NodeDefChirho {
        name_chirho: "fixture-node-chirho".to_string(),
        capabilities_chirho,
        ..NodeDefChirho::default()
    };
    let hash_chirho = hash_object_chirho(&node_chirho).unwrap();
    (hash_chirho, node_chirho)
}

fn input_chirho(
    nodes_chirho: Vec<(HashChirho, NodeDefChirho)>,
    edges_chirho: Vec<EdgeChirho>,
) -> VerifiedUndoDagInputChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: nodes_chirho
            .iter()
            .map(|(hash_chirho, _)| hash_chirho.clone())
            .collect(),
        edges_chirho,
    };
    VerifiedUndoDagInputChirho {
        source_dag_chirho: hash_object_chirho(&dag_chirho).unwrap(),
        dag_chirho,
        node_defs_chirho: nodes_chirho.into_iter().collect(),
        pinned_config_refs_chirho: BTreeMap::new(),
    }
}

fn edge_chirho(from_chirho: &HashChirho, to_chirho: &HashChirho) -> EdgeChirho {
    EdgeChirho {
        from_node_chirho: from_chirho.clone(),
        from_port_chirho: "out-chirho".to_string(),
        to_node_chirho: to_chirho.clone(),
        to_port_chirho: "in-chirho".to_string(),
        privacy_chirho: None,
    }
}

#[test]
fn contract_set_rejects_duplicate_patterns_chirho() {
    let set_chirho = set_chirho(vec![
        compensable_contract_chirho(
            "write-a-chirho",
            EffectDoorSelectorChirho::WriteStoreChirho,
            Vec::new(),
        ),
        compensable_contract_chirho(
            "write-b-chirho",
            EffectDoorSelectorChirho::WriteStoreChirho,
            Vec::new(),
        ),
    ]);
    assert!(validate_reversion_contract_set_chirho(&set_chirho).is_err());
}

#[test]
fn canonical_authoring_set_is_valid_and_closed_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    validate_reversion_contract_set_chirho(&set_chirho).unwrap();
    assert_eq!(set_chirho.contracts_chirho.len(), 6);
    assert_eq!(
        set_chirho
            .contracts_chirho
            .iter()
            .map(|contract_chirho| contract_chirho.contract_key_chirho.0.as_str())
            .collect::<Vec<_>>(),
        vec![
            "llm-chirho",
            "postgres-reversible-chirho",
            "query-chirho",
            "read-store-chirho",
            "template-app-deploy-chirho",
            "write-store-chirho",
        ]
    );

    let postgres_contract_chirho = &set_chirho.contracts_chirho[1];
    assert_eq!(
        postgres_contract_chirho.effect_selector_chirho,
        EffectDoorSelectorChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(),
        }
    );
    assert_eq!(
        postgres_contract_chirho.reconciliation_requirement_chirho,
        Some(EffectReconciliationRequirementChirho::QueryByEffectKeyChirho)
    );
    assert_eq!(
        postgres_contract_chirho.pricing_source_requirement_chirho,
        Some(EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho)
    );
    assert_eq!(
        postgres_contract_chirho.effect_result_cache_posture_chirho,
        Some(EffectResultCachePostureChirho::NeverReuseEffectResultChirho)
    );
    assert!(matches!(
        &postgres_contract_chirho.disposition_chirho,
        UndoDispositionChirho::CompensableChirho {
            residuals_chirho,
            admission_gate_chirho: Some(_),
            ..
        } if residuals_chirho == &[IrreversibleResidualChirho::ForwardOnlyAuthorityRecordChirho]
    ));

    let read_store_contract_chirho = &set_chirho.contracts_chirho[3];
    assert_eq!(
        read_store_contract_chirho.effect_result_cache_posture_chirho,
        Some(EffectResultCachePostureChirho::NeverReuseEffectResultChirho)
    );
}

#[test]
fn per_contract_digest_commits_to_each_contract_semantics_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let digests_chirho = set_chirho
        .contracts_chirho
        .iter()
        .map(|contract_chirho| reversion_contract_digest_chirho(contract_chirho).unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(digests_chirho.len(), set_chirho.contracts_chirho.len());

    let original_chirho = &set_chirho.contracts_chirho[0];
    let mut changed_chirho = original_chirho.clone();
    changed_chirho.max_depth_chirho -= 1;
    assert_ne!(
        reversion_contract_digest_chirho(original_chirho).unwrap(),
        reversion_contract_digest_chirho(&changed_chirho).unwrap()
    );
}

#[test]
fn contract_set_rejects_noncanonical_contract_order_chirho() {
    let mut set_chirho = canonical_authoring_reversion_contract_set_chirho();
    set_chirho.contracts_chirho.swap(0, 1);
    assert!(validate_reversion_contract_set_chirho(&set_chirho).is_err());
}

#[test]
fn literal_golden_vectors_pin_authoring_set_and_plan_chirho() {
    let contracts_chirho = legacy_authoring_contract_set_chirho();
    let expected_contract_bytes_chirho = AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO
        .strip_suffix('\n')
        .unwrap_or(AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO)
        .as_bytes();
    assert_eq!(
        canonical_contract_set_bytes_chirho(&contracts_chirho).unwrap(),
        expected_contract_bytes_chirho
    );
    assert_eq!(
        contract_set_digest_chirho(&contracts_chirho).unwrap().0,
        AUTHORING_CONTRACT_SET_DIGEST_GOLDEN_CHIRHO
    );

    let (node_hash_chirho, node_def_chirho) =
        node_chirho(vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "golden-orders-chirho".to_string(),
        }]);
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(vec![(node_hash_chirho, node_def_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .unwrap();
    let expected_plan_bytes_chirho = SINGLE_WRITE_PLAN_GOLDEN_CHIRHO
        .strip_suffix('\n')
        .unwrap_or(SINGLE_WRITE_PLAN_GOLDEN_CHIRHO)
        .as_bytes();
    assert_eq!(
        canonical_undo_plan_bytes_chirho(&plan_chirho).unwrap(),
        expected_plan_bytes_chirho
    );
    assert_eq!(
        undo_plan_hash_chirho(&plan_chirho).unwrap().0,
        SINGLE_WRITE_PLAN_DIGEST_GOLDEN_CHIRHO
    );
}

#[test]
fn optional_execution_laws_are_signed_without_moving_legacy_contract_bytes_chirho() {
    let legacy_set_chirho = legacy_authoring_contract_set_chirho();
    let expected_contract_bytes_chirho = AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO
        .strip_suffix('\n')
        .unwrap_or(AUTHORING_CONTRACT_SET_GOLDEN_CHIRHO)
        .as_bytes();
    assert_eq!(
        canonical_contract_set_bytes_chirho(&legacy_set_chirho).unwrap(),
        expected_contract_bytes_chirho
    );

    let legacy_contract_chirho = legacy_set_chirho.contracts_chirho[0].clone();
    let legacy_digest_chirho = reversion_contract_digest_chirho(&legacy_contract_chirho).unwrap();
    let mut activated_contract_chirho = legacy_contract_chirho.clone();
    activated_contract_chirho.reconciliation_requirement_chirho =
        Some(EffectReconciliationRequirementChirho::QueryByEffectKeyChirho);
    activated_contract_chirho.pricing_source_requirement_chirho =
        Some(EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho);
    activated_contract_chirho.effect_result_cache_posture_chirho =
        Some(EffectResultCachePostureChirho::NeverReuseEffectResultChirho);

    let activated_set_chirho = set_chirho(vec![activated_contract_chirho.clone()]);
    validate_reversion_contract_set_chirho(&activated_set_chirho).unwrap();
    let activated_bytes_chirho =
        canonical_contract_set_bytes_chirho(&activated_set_chirho).unwrap();
    let activated_text_chirho = String::from_utf8(activated_bytes_chirho).unwrap();
    assert!(matches!(
        parse_canonical_undo_document_chirho(&activated_text_chirho).unwrap(),
        UndoWireDocumentChirho::ContractSetChirho(parsed_chirho)
            if parsed_chirho == activated_set_chirho
    ));
    assert_ne!(
        reversion_contract_digest_chirho(&activated_contract_chirho).unwrap(),
        legacy_digest_chirho
    );

    let mut pricing_only_chirho = legacy_contract_chirho.clone();
    pricing_only_chirho.pricing_source_requirement_chirho =
        Some(EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho);
    let mut cache_only_chirho = legacy_contract_chirho;
    cache_only_chirho.effect_result_cache_posture_chirho =
        Some(EffectResultCachePostureChirho::VerifiedReuseChirho);
    assert_ne!(
        reversion_contract_digest_chirho(&pricing_only_chirho).unwrap(),
        legacy_digest_chirho
    );
    assert_ne!(
        reversion_contract_digest_chirho(&cache_only_chirho).unwrap(),
        legacy_digest_chirho
    );
}

#[test]
fn observation_legality_is_structural_chirho() {
    let invalid_chirho = set_chirho(vec![observation_contract_chirho(
        "fake-observation-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
    )]);
    assert!(validate_reversion_contract_set_chirho(&invalid_chirho).is_err());

    let valid_chirho = set_chirho(vec![observation_contract_chirho(
        "clock-chirho",
        EffectDoorSelectorChirho::ClockChirho,
    )]);
    validate_reversion_contract_set_chirho(&valid_chirho).unwrap();
}

#[test]
fn query_requires_direct_privacy_and_exposure_gate_chirho() {
    let mut query_chirho = compensable_contract_chirho(
        "query-chirho",
        EffectDoorSelectorChirho::QueryChirho,
        vec![SupportingCapabilityRequirementChirho::QueryCallerIdentityChirho],
    );
    let valid_chirho = set_chirho(vec![query_chirho.clone()]);
    validate_reversion_contract_set_chirho(&valid_chirho).unwrap();

    query_chirho.privacy_floor_chirho = PrivacyClassChirho::SafeChirho;
    assert!(validate_reversion_contract_set_chirho(&set_chirho(vec![query_chirho])).is_err());
}

#[test]
fn selected_effect_frame_separates_sibling_doors_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    )]);
    let (node_hash_chirho, node_def_chirho) = node_chirho(vec![
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "alpha-chirho".to_string(),
        },
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "beta-chirho".to_string(),
        },
    ]);
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(vec![(node_hash_chirho, node_def_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .unwrap();
    assert_eq!(plan_chirho.effect_doors_chirho.len(), 2);
    assert_ne!(
        plan_chirho.effect_doors_chirho[0]
            .door_chirho
            .capability_fingerprint_chirho,
        plan_chirho.effect_doors_chirho[1]
            .door_chirho
            .capability_fingerprint_chirho
    );

    let canonical_caps_chirho = canonicalize_capabilities_chirho(&[
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "alpha-chirho".to_string(),
        },
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "beta-chirho".to_string(),
        },
    ])
    .unwrap();
    let complete_chirho =
        canonical_capability_multiset_bytes_chirho(&canonical_caps_chirho).unwrap();
    let legacy_left_chirho =
        framed_blake3_hash_chirho(b"legacy-complete-only-chirho", &[&complete_chirho]).unwrap();
    let legacy_right_chirho =
        framed_blake3_hash_chirho(b"legacy-complete-only-chirho", &[&complete_chirho]).unwrap();
    assert_eq!(legacy_left_chirho, legacy_right_chirho);
}

#[test]
fn query_consumes_one_matching_identity_and_rejects_residue_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "query-chirho",
        EffectDoorSelectorChirho::QueryChirho,
        vec![SupportingCapabilityRequirementChirho::QueryCallerIdentityChirho],
    )]);
    let valid_caps_chirho = vec![
        CapabilityChirho::QueryChirho {
            prefix_chirho: "orders-chirho".to_string(),
            caller_chirho: "alice-chirho".to_string(),
            max_rows_chirho: 50,
        },
        CapabilityChirho::UserIdentityChirho {
            principal_chirho: "alice-chirho".to_string(),
            client_id_chirho: "client-chirho".to_string(),
            token_hash_chirho: "token-chirho".to_string(),
        },
    ];
    let (valid_hash_chirho, valid_node_chirho) = node_chirho(valid_caps_chirho.clone());
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(vec![(valid_hash_chirho, valid_node_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .unwrap();
    assert_eq!(plan_chirho.effect_doors_chirho.len(), 1);
    assert_eq!(
        plan_chirho.effect_doors_chirho[0]
            .supporting_capabilities_chirho
            .len(),
        1
    );

    let mut residue_caps_chirho = valid_caps_chirho;
    residue_caps_chirho.push(CapabilityChirho::AppContextChirho {
        app_chirho: "app-chirho".to_string(),
        owner_principal_chirho: "owner-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
    });
    let (invalid_hash_chirho, invalid_node_chirho) = node_chirho(residue_caps_chirho);
    assert!(derive_undo_plan_chirho(
        &input_chirho(vec![(invalid_hash_chirho, invalid_node_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .is_err());
}

#[test]
fn pure_bridge_preserves_nearest_effect_dependency_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    )]);
    let (first_hash_chirho, first_chirho) = node_chirho(vec![CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "first-chirho".to_string(),
    }]);
    let (pure_hash_chirho, pure_chirho) = node_chirho(Vec::new());
    let (last_hash_chirho, last_chirho) = node_chirho(vec![CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "last-chirho".to_string(),
    }]);
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(
            vec![
                (last_hash_chirho.clone(), last_chirho),
                (first_hash_chirho.clone(), first_chirho),
                (pure_hash_chirho.clone(), pure_chirho),
            ],
            vec![
                edge_chirho(&first_hash_chirho, &pure_hash_chirho),
                edge_chirho(&pure_hash_chirho, &last_hash_chirho),
            ],
        ),
        &contracts_chirho,
    )
    .unwrap();
    let last_door_chirho = plan_chirho
        .effect_doors_chirho
        .iter()
        .find(|door_chirho| door_chirho.door_chirho.effect_node_chirho == last_hash_chirho)
        .unwrap();
    assert_eq!(last_door_chirho.depends_on_doors_chirho.len(), 1);
    assert_eq!(
        last_door_chirho.depends_on_doors_chirho[0].effect_node_chirho,
        first_hash_chirho
    );
}

#[test]
fn derived_doors_are_stable_while_distinct_dag_bytes_move_plan_identity_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    )]);
    let (left_hash_chirho, left_chirho) = node_chirho(vec![CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "left-chirho".to_string(),
    }]);
    let (right_hash_chirho, right_chirho) = node_chirho(vec![CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "right-chirho".to_string(),
    }]);
    let first_input_chirho = input_chirho(
        vec![
            (left_hash_chirho.clone(), left_chirho.clone()),
            (right_hash_chirho.clone(), right_chirho.clone()),
        ],
        Vec::new(),
    );
    let second_input_chirho = input_chirho(
        vec![
            (right_hash_chirho, right_chirho),
            (left_hash_chirho, left_chirho),
        ],
        Vec::new(),
    );
    let first_chirho = derive_undo_plan_chirho(&first_input_chirho, &contracts_chirho).unwrap();
    let second_chirho = derive_undo_plan_chirho(&second_input_chirho, &contracts_chirho).unwrap();
    assert_ne!(
        first_chirho.source_dag_chirho,
        second_chirho.source_dag_chirho
    );
    assert_eq!(
        first_chirho.effect_doors_chirho,
        second_chirho.effect_doors_chirho
    );
    assert_ne!(
        undo_plan_hash_chirho(&first_chirho).unwrap(),
        undo_plan_hash_chirho(&second_chirho).unwrap()
    );
}

#[test]
fn cyclic_dag_is_rejected_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    )]);
    let (left_hash_chirho, left_chirho) = node_chirho(Vec::new());
    let (right_hash_chirho, right_chirho) = node_chirho(Vec::new());
    assert!(derive_undo_plan_chirho(
        &input_chirho(
            vec![
                (left_hash_chirho.clone(), left_chirho),
                (right_hash_chirho.clone(), right_chirho),
            ],
            vec![
                edge_chirho(&left_hash_chirho, &right_hash_chirho),
                edge_chirho(&right_hash_chirho, &left_hash_chirho),
            ],
        ),
        &contracts_chirho,
    )
    .is_err());
}

#[test]
fn schema_router_rejects_duplicate_and_noncanonical_bytes_chirho() {
    let contracts_chirho = set_chirho(vec![observation_contract_chirho(
        "clock-chirho",
        EffectDoorSelectorChirho::ClockChirho,
    )]);
    let bytes_chirho = canonical_contract_set_bytes_chirho(&contracts_chirho).unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    assert!(matches!(
        parse_canonical_undo_document_chirho(&text_chirho).unwrap(),
        UndoWireDocumentChirho::ContractSetChirho(_)
    ));
    assert!(parse_canonical_undo_document_chirho(&format!(" {text_chirho}")).is_err());
    let duplicate_chirho = text_chirho.replacen(
        "{",
        &format!(
            "{{\"schema_chirho\":\"{}\",",
            REVERSION_CONTRACT_SET_SCHEMA_CHIRHO
        ),
        1,
    );
    assert!(parse_canonical_undo_document_chirho(&duplicate_chirho).is_err());

    let unknown_unit_field_chirho = text_chirho.replacen(
        "\"effect_selector_chirho\":{\"kind_chirho\":\"clock-chirho\"}",
        "\"effect_selector_chirho\":{\"kind_chirho\":\"clock-chirho\",\"unexpected_chirho\":true}",
        1,
    );
    assert_ne!(unknown_unit_field_chirho, text_chirho);
    assert!(parse_canonical_undo_document_chirho(&unknown_unit_field_chirho).is_err());
}

#[test]
fn framed_keys_separate_legacy_ambiguous_components_chirho() {
    let old_left_chirho = [b"k1".as_slice(), b"11".as_slice()].concat();
    let old_right_chirho = [b"k11".as_slice(), b"1".as_slice()].concat();
    assert_eq!(old_left_chirho, old_right_chirho);
    let framed_left_chirho =
        framed_blake3_hash_chirho(b"test-domain-chirho", &[b"k1", b"11"]).unwrap();
    let framed_right_chirho =
        framed_blake3_hash_chirho(b"test-domain-chirho", &[b"k11", b"1"]).unwrap();
    assert_ne!(framed_left_chirho, framed_right_chirho);

    let run_chirho = hash_chirho("run-chirho");
    let idem_chirho = hash_chirho("idem-chirho");
    let instance_chirho = effect_instance_key_chirho(&run_chirho, 11, &idem_chirho).unwrap();
    let plan_chirho = hash_chirho("plan-chirho");
    let door_chirho = hash_chirho("door-chirho");
    assert_ne!(
        compensation_step_key_chirho(&plan_chirho, &door_chirho, &instance_chirho, 1).unwrap(),
        compensation_step_key_chirho(&plan_chirho, &door_chirho, &instance_chirho, 11).unwrap()
    );
}

#[test]
fn canonical_hashes_move_on_semantic_change_chirho() {
    let mut first_set_chirho = set_chirho(vec![observation_contract_chirho(
        "clock-chirho",
        EffectDoorSelectorChirho::ClockChirho,
    )]);
    let first_digest_chirho = contract_set_digest_chirho(&first_set_chirho).unwrap();
    first_set_chirho.contracts_chirho[0].privacy_floor_chirho =
        PrivacyClassChirho::AnalyticalChirho;
    let second_digest_chirho = contract_set_digest_chirho(&first_set_chirho).unwrap();
    assert_ne!(first_digest_chirho, second_digest_chirho);
}

#[test]
fn plan_codec_round_trips_and_hashes_chirho() {
    let contracts_chirho = set_chirho(vec![compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    )]);
    let (node_hash_chirho, node_def_chirho) =
        node_chirho(vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "orders-chirho".to_string(),
        }]);
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(vec![(node_hash_chirho, node_def_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .unwrap();
    let bytes_chirho = canonical_undo_plan_bytes_chirho(&plan_chirho).unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    assert!(matches!(
        parse_canonical_undo_document_chirho(&text_chirho).unwrap(),
        UndoWireDocumentChirho::PlanChirho(parsed_chirho) if parsed_chirho == plan_chirho
    ));
    assert_eq!(
        undo_plan_hash_chirho(&plan_chirho).unwrap(),
        undo_plan_hash_chirho(&plan_chirho).unwrap()
    );

    let mut dual_role_chirho = plan_chirho;
    let selected_effect_chirho = dual_role_chirho.effect_doors_chirho[0]
        .effect_capability_chirho
        .clone();
    dual_role_chirho.effect_doors_chirho[0]
        .supporting_capabilities_chirho
        .push(selected_effect_chirho);
    assert!(canonical_undo_plan_bytes_chirho(&dual_role_chirho).is_err());
}

#[test]
fn duplicate_exact_capabilities_are_rejected_chirho() {
    let capability_chirho = CapabilityChirho::WriteStoreChirho {
        prefix_chirho: "same-chirho".to_string(),
    };
    assert!(
        canonicalize_capabilities_chirho(&[capability_chirho.clone(), capability_chirho,]).is_err()
    );
}

#[test]
fn config_ports_require_exact_declared_refs_chirho() {
    let mut contract_chirho = compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    );
    contract_chirho.config_ports_chirho = vec![ConfigPortRequirementChirho {
        port_chirho: "database-config-chirho".to_string(),
        privacy_floor_chirho: PrivacyClassChirho::DirectChirho,
    }];
    let contracts_chirho = set_chirho(vec![contract_chirho]);
    let (node_hash_chirho, node_def_chirho) =
        node_chirho(vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "orders-chirho".to_string(),
        }]);
    let mut input_chirho = input_chirho(
        vec![(node_hash_chirho.clone(), node_def_chirho)],
        Vec::new(),
    );
    assert!(derive_undo_plan_chirho(&input_chirho, &contracts_chirho).is_err());
    input_chirho.pinned_config_refs_chirho.insert(
        node_hash_chirho,
        BTreeMap::from([(
            "database-config-chirho".to_string(),
            hash_chirho("database-config-chirho"),
        )]),
    );
    derive_undo_plan_chirho(&input_chirho, &contracts_chirho).unwrap();
}

#[test]
fn asset_op_schema_and_struct_fields_stay_mechanically_consistent_chirho() {
    let graph_chirho =
        parse_canonical_field_graph_chirho(ASSET_OP_FIELD_GRAPH_SCHEMA_V1_CHIRHO).unwrap();
    assert_eq!(
        canonical_field_graph_hash_chirho(&graph_chirho).unwrap().0,
        ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO
    );
    let CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } = graph_chirho.root_chirho else {
        panic!("AssetOp field graph root must stay an object");
    };
    assert!(fields_chirho
        .iter()
        .all(|field_chirho| field_chirho.requiredness_chirho
            == FieldRequirednessChirho::RequiredChirho));
    let graph_keys_chirho = fields_chirho
        .iter()
        .map(|field_chirho| field_chirho.name_chirho.clone())
        .collect::<BTreeSet<_>>();
    let value_chirho = serde_json::to_value(AssetOpChirho {
        amount_chirho: 1,
        kind_id_chirho: AssetKindIdChirho("usd-chirho".to_owned()),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            "policy-v1-digest-chirho".to_owned(),
        )),
        rounding_chirho: RoundingChirho::ExactChirho,
    })
    .unwrap();
    let struct_keys_chirho = value_chirho
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(graph_keys_chirho, struct_keys_chirho);
}

#[test]
fn asset_op_contract_port_is_exact_and_node_bound_chirho() {
    let mut contract_chirho = compensable_contract_chirho(
        "write-store-chirho",
        EffectDoorSelectorChirho::WriteStoreChirho,
        Vec::new(),
    );
    contract_chirho.asset_op_ports_chirho = vec![AssetOpPortRequirementChirho {
        port_chirho: "asset-op-chirho".to_owned(),
        schema_chirho: HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
    }];
    let node_chirho = NodeDefChirho {
        inputs_chirho: vec![PortChirho {
            name_chirho: "asset-op-chirho".to_owned(),
            schema_chirho: HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
        }],
        ..Default::default()
    };
    assert!(validate_asset_op_port_binding_chirho(&contract_chirho, &node_chirho).unwrap());

    let mut wrong_contract_chirho = contract_chirho;
    wrong_contract_chirho.asset_op_ports_chirho[0].schema_chirho = HashChirho("0".repeat(64));
    assert!(validate_asset_op_port_binding_chirho(&wrong_contract_chirho, &node_chirho).is_err());
}

#[test]
fn one_encoder_feeds_both_door_fingerprint_components_chirho() {
    let capabilities_chirho =
        canonicalize_capabilities_chirho(&[CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "orders-chirho".to_string(),
        }])
        .unwrap();
    let complete_chirho = canonical_capability_multiset_bytes_chirho(&capabilities_chirho).unwrap();
    let selected_chirho = canonical_capability_bytes_chirho(&capabilities_chirho[0]).unwrap();
    assert_eq!(
        door_capability_fingerprint_chirho(&complete_chirho, &selected_chirho).unwrap(),
        door_capability_fingerprint_chirho(&complete_chirho, &selected_chirho).unwrap()
    );
}

#[test]
fn signed_wire_vocabulary_is_literal_chirho() {
    let gate_chirho = hash_chirho("wire-gate-chirho");
    let remediation_chirho = hash_chirho("wire-remediation-chirho");
    assert_eq!(
        serde_json::to_string(&UndoDispositionChirho::ObservationOnlyChirho {
            reason_code_chirho: ObservationReasonChirho::ReadOnlyCapabilityChirho,
        })
        .unwrap(),
        r#"{"kind_chirho":"observation-only-chirho","reason_code_chirho":"read-only-capability-chirho"}"#
    );
    assert_eq!(
        serde_json::to_string(&UndoDispositionChirho::CompensableChirho {
            steps_chirho: vec![step_chirho()],
            residuals_chirho: Vec::new(),
            admission_gate_chirho: None,
        })
        .unwrap(),
        r#"{"kind_chirho":"compensable-chirho","steps_chirho":[{"action_chirho":"conditional-restore-chirho","required_evidence_chirho":[{"kind_chirho":"before-image-ref-chirho"},{"kind_chirho":"post-state-fingerprint-chirho"}],"verification_chirho":"verify-post-fingerprint-chirho"}],"residuals_chirho":[]}"#
    );
    assert_eq!(
        serde_json::to_string(&UndoDispositionChirho::IrreversibleGatedChirho {
            residuals_chirho: vec![IrreversibleResidualChirho::ExternalVisibilityChirho],
            admission_gate_chirho: gate_chirho.clone(),
            remediation_chirho: remediation_chirho.clone(),
        })
        .unwrap(),
        format!(
            r#"{{"kind_chirho":"irreversible-gated-chirho","residuals_chirho":["external-visibility-chirho"],"admission_gate_chirho":"{}","remediation_chirho":"{}"}}"#,
            gate_chirho.0, remediation_chirho.0
        )
    );

    let evidence_labels_chirho = [
        UndoEvidenceKindChirho::EffectIdempotencyKeyChirho,
        UndoEvidenceKindChirho::RequestRefChirho,
        UndoEvidenceKindChirho::ResponseRefChirho,
        UndoEvidenceKindChirho::BeforeImageRefChirho,
        UndoEvidenceKindChirho::PostStateFingerprintChirho,
        UndoEvidenceKindChirho::PreviousHeadRefChirho,
        UndoEvidenceKindChirho::ProviderReceiptRefChirho,
        UndoEvidenceKindChirho::AuthorityEvidenceRefChirho,
        UndoEvidenceKindChirho::SubjectRefChirho,
    ]
    .map(|value_chirho| serde_json::to_string(&value_chirho).unwrap());
    assert_eq!(
        evidence_labels_chirho,
        [
            r#"{"kind_chirho":"effect-idempotency-key-chirho"}"#,
            r#"{"kind_chirho":"request-ref-chirho"}"#,
            r#"{"kind_chirho":"response-ref-chirho"}"#,
            r#"{"kind_chirho":"before-image-ref-chirho"}"#,
            r#"{"kind_chirho":"post-state-fingerprint-chirho"}"#,
            r#"{"kind_chirho":"previous-head-ref-chirho"}"#,
            r#"{"kind_chirho":"provider-receipt-ref-chirho"}"#,
            r#"{"kind_chirho":"authority-evidence-ref-chirho"}"#,
            r#"{"kind_chirho":"subject-ref-chirho"}"#,
        ]
    );
    assert_eq!(
        [
            UndoVerificationModeChirho::VerifyPostFingerprintChirho,
            UndoVerificationModeChirho::VerifyProviderReceiptChirho,
            UndoVerificationModeChirho::VerifyAuthorityEvidenceChirho,
        ]
        .map(|value_chirho| serde_json::to_string(&value_chirho).unwrap()),
        [
            r#""verify-post-fingerprint-chirho""#,
            r#""verify-provider-receipt-chirho""#,
            r#""verify-authority-evidence-chirho""#,
        ]
    );
}

#[test]
#[ignore = "reviewed wire changes only: emits replacement literal golden vectors"]
fn regenerate_golden_vectors_chirho() {
    let contracts_chirho = canonical_authoring_reversion_contract_set_chirho();
    let contract_bytes_chirho = canonical_contract_set_bytes_chirho(&contracts_chirho).unwrap();
    let (node_hash_chirho, node_def_chirho) =
        node_chirho(vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "golden-orders-chirho".to_string(),
        }]);
    let plan_chirho = derive_undo_plan_chirho(
        &input_chirho(vec![(node_hash_chirho, node_def_chirho)], Vec::new()),
        &contracts_chirho,
    )
    .unwrap();
    let plan_bytes_chirho = canonical_undo_plan_bytes_chirho(&plan_chirho).unwrap();
    println!(
        "CONTRACT_BYTES_CHIRHO={}\nCONTRACT_DIGEST_CHIRHO={}\nPLAN_BYTES_CHIRHO={}\nPLAN_DIGEST_CHIRHO={}",
        String::from_utf8(contract_bytes_chirho).unwrap(),
        contract_set_digest_chirho(&contracts_chirho).unwrap().0,
        String::from_utf8(plan_bytes_chirho).unwrap(),
        undo_plan_hash_chirho(&plan_chirho).unwrap().0,
    );
}
