// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::{admit_legacy_operator_effect_chirho, admit_verified_node_effect_chirho};
use crate::model_chirho::{CapabilityChirho, HashChirho, NodeDefChirho};
use crate::store_chirho;
use cairn_undo_plan_chirho::canonical_chirho::{
    contract_set_digest_chirho, reversion_contract_digest_chirho,
};
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, EffectDoorSelectorChirho,
    EffectPricingSourceRequirementChirho, EffectReconciliationRequirementChirho,
    EffectResultCachePostureChirho, POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
};

fn paid_node_chirho(effect_chirho: &str, contract_set_chirho: Option<HashChirho>) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "admission-paid-node-chirho".into(),
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: effect_chirho.into(),
            caller_chirho: "declared-caller-chirho".into(),
        }],
        effect_contract_set_chirho: contract_set_chirho,
        ..Default::default()
    }
}

fn current_set_chirho() -> HashChirho {
    contract_set_digest_chirho(&canonical_authoring_reversion_contract_set_chirho()).unwrap()
}

#[test]
fn verified_v2_admission_refuses_unknown_subtype_and_wrong_node_hash_chirho() {
    let node_chirho = paid_node_chirho("unknown-paid-subtype-chirho", Some(current_set_chirho()));
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let capability_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "unknown-paid-subtype-chirho".into(),
        caller_chirho: "runtime-caller-chirho".into(),
    };
    let unknown_error_chirho = match admit_verified_node_effect_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
    ) {
        Ok(_) => panic!("unknown descriptor-v2 subtype should refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert!(unknown_error_chirho
        .to_string()
        .contains("not registered under blessed registry v2"));
    let hash_error_chirho = match admit_verified_node_effect_chirho(
        &node_chirho,
        &HashChirho("0".repeat(64)),
        &capability_chirho,
    ) {
        Ok(_) => panic!("mismatched NodeDefChirho identity should refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert!(hash_error_chirho
        .to_string()
        .contains("NodeDefChirho hash mismatch"));
}

#[test]
fn verified_v2_admission_refuses_stale_contract_set_chirho() {
    let node_chirho = paid_node_chirho("llm_chirho", Some(HashChirho("0".repeat(64))));
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let capability_chirho = node_chirho.capabilities_chirho[0].clone();
    let error_chirho = match admit_verified_node_effect_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
    ) {
        Ok(_) => panic!("stale descriptor-v2 contract set should refuse"),
        Err(error_chirho) => error_chirho,
    };
    assert!(error_chirho
        .to_string()
        .contains("does not name the current verified contract set"));
}

#[test]
fn token_is_bound_to_one_effective_capability_chirho() {
    let node_chirho = paid_node_chirho("llm_chirho", Some(current_set_chirho()));
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let admitted_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "llm_chirho".into(),
        caller_chirho: "runtime-caller-chirho".into(),
    };
    let token_chirho =
        admit_verified_node_effect_chirho(&node_chirho, &node_hash_chirho, &admitted_chirho)
            .unwrap();
    token_chirho.authorize_chirho(&admitted_chirho).unwrap();
    // The llm contract now carries NeverReuse (pricing_source=VerifiedPriceBook + cache=NeverReuse),
    // so a retry must REACH the money ladder rather than short-circuit the generic effect cache:
    // this token may NOT reuse the generic effect result.
    assert!(!token_chirho
        .may_reuse_generic_effect_result_chirho()
        .unwrap());
    assert!(token_chirho
        .authorize_chirho(&CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".into(),
            caller_chirho: "sibling-caller-chirho".into(),
        })
        .is_err());
}

#[test]
fn postgres_descriptor_token_carries_every_signed_execution_law_chirho() {
    let node_chirho = paid_node_chirho(
        POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO,
        Some(current_set_chirho()),
    );
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let capability_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(),
        caller_chirho: "verified-runtime-caller-chirho".to_string(),
    };
    let token_chirho =
        admit_verified_node_effect_chirho(&node_chirho, &node_hash_chirho, &capability_chirho)
            .unwrap();
    let contract_chirho = token_chirho.contract_chirho().unwrap();

    assert_eq!(
        token_chirho.contract_set_digest_chirho(),
        Some(&current_set_chirho())
    );
    assert_eq!(
        contract_chirho.effect_selector_chirho,
        EffectDoorSelectorChirho::PaidEffectChirho {
            effect_chirho: POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_string(),
        }
    );
    assert_eq!(
        token_chirho.contract_digest_chirho(),
        Some(&reversion_contract_digest_chirho(contract_chirho).unwrap())
    );
    assert_eq!(
        token_chirho.door_chirho().unwrap().effect_node_chirho,
        node_hash_chirho
    );
    assert_eq!(
        token_chirho.reconciliation_requirement_chirho(),
        Some(&EffectReconciliationRequirementChirho::QueryByEffectKeyChirho)
    );
    assert_eq!(
        token_chirho.pricing_source_requirement_chirho(),
        Some(&EffectPricingSourceRequirementChirho::VerifiedPriceBookChirho)
    );
    assert_eq!(
        token_chirho.effect_result_cache_posture_chirho(),
        Some(&EffectResultCachePostureChirho::NeverReuseEffectResultChirho)
    );
    assert!(!token_chirho
        .may_reuse_generic_effect_result_chirho()
        .unwrap());
}

#[test]
fn verified_pre_v2_paid_refuses_while_explicit_operator_preserves_legacy_fallback_chirho() {
    let node_chirho = paid_node_chirho("legacy-unknown-subtype-chirho", None);
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let capability_chirho = node_chirho.capabilities_chirho[0].clone();
    let error_chirho = match admit_verified_node_effect_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
    ) {
        Ok(_) => panic!("verified pre-v2 paid node should refuse before pricing"),
        Err(error_chirho) => error_chirho,
    };
    assert!(error_chirho
        .to_string()
        .contains("cannot admit charge-bearing PaidEffectChirho"));
    assert!(admit_legacy_operator_effect_chirho(&capability_chirho)
        .unwrap()
        .may_reuse_generic_effect_result_chirho()
        .unwrap());
}
