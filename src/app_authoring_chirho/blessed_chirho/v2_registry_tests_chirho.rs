// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_tree_build_chirho::check_chirho::check_app_tree_chirho;
use cairn_tree_build_chirho::tree_chirho::{
    walk_app_tree_chirho, AppTreeChirho, RoleBindingChirho,
};
use cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho;
use cairn_undo_plan_chirho::contract_chirho::{
    canonical_authoring_reversion_contract_set_chirho, EffectDoorSelectorChirho,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const AUTHORING_REGISTRY_V2_MESSAGE_GOLDEN_CHIRHO: &str =
    include_str!("golden-chirho/authoring-registry-v2-message-chirho.json");

#[test]
fn authoring_registry_v2_message_is_canonical_and_exact_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let bytes_chirho =
        canonical_registry_v2_message_bytes_chirho(&message_chirho, &set_chirho).unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let golden_chirho = AUTHORING_REGISTRY_V2_MESSAGE_GOLDEN_CHIRHO
        .strip_suffix('\n')
        .unwrap_or(AUTHORING_REGISTRY_V2_MESSAGE_GOLDEN_CHIRHO);
    assert_eq!(text_chirho, golden_chirho);
    assert_eq!(
        parse_canonical_registry_v2_message_chirho(golden_chirho, &set_chirho).unwrap(),
        message_chirho
    );
    assert_eq!(message_chirho.effect_bindings_chirho.len(), 6);
}

#[test]
fn registry_v2_has_exact_paid_subtype_and_preserves_pre_v2_fallback_chirho() {
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    assert!(message_chirho
        .effect_bindings_chirho
        .iter()
        .any(|binding_chirho| matches!(
            &binding_chirho.coordinate_chirho,
            BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
                effect_subtype_chirho,
            } if effect_subtype_chirho == "llm_chirho"
        ) && binding_chirho.contract_key_chirho.0 == "llm-chirho"));
    assert!(message_chirho
        .effect_bindings_chirho
        .iter()
        .any(|binding_chirho| matches!(
            &binding_chirho.coordinate_chirho,
            BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
                effect_subtype_chirho,
            } if effect_subtype_chirho == "postgres_reversible_chirho"
        ) && binding_chirho.contract_key_chirho.0
            == "postgres-reversible-chirho"));

    let unknown_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "echo_paid_chirho".to_string(),
        caller_chirho: "user/demo-chirho".to_string(),
    };
    assert!(!message_chirho
        .effect_bindings_chirho
        .iter()
        .any(|binding_chirho| matches!(
            &binding_chirho.coordinate_chirho,
            BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
                effect_subtype_chirho,
            } if effect_subtype_chirho == "echo_paid_chirho"
        )));
    assert!(compensation_kind_for_capability_chirho(&unknown_chirho).is_some());
}

#[test]
fn subtype_injection_requires_a_new_contract_set_digest_chirho() {
    let original_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let original_message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let mut forged_message_chirho = original_message_chirho.clone();
    let paid_binding_chirho = forged_message_chirho
        .effect_bindings_chirho
        .iter_mut()
        .find(|binding_chirho| {
            matches!(
                binding_chirho.coordinate_chirho,
                BlessedEffectCoordinateV2Chirho::PaidEffectChirho { .. }
            )
        })
        .unwrap();
    paid_binding_chirho.coordinate_chirho = BlessedEffectCoordinateV2Chirho::PaidEffectChirho {
        effect_subtype_chirho: "image_generate_chirho".to_string(),
    };
    assert!(
        validate_registry_v2_message_chirho(&forged_message_chirho, &original_set_chirho).is_err()
    );

    let mut changed_set_chirho = original_set_chirho.clone();
    let llm_contract_chirho = changed_set_chirho
        .contracts_chirho
        .iter_mut()
        .find(|contract_chirho| contract_chirho.contract_key_chirho.0 == "llm-chirho")
        .unwrap();
    llm_contract_chirho.effect_selector_chirho = EffectDoorSelectorChirho::PaidEffectChirho {
        effect_chirho: "image_generate_chirho".to_string(),
    };
    assert_ne!(
        contract_set_digest_chirho(&original_set_chirho).unwrap(),
        contract_set_digest_chirho(&changed_set_chirho).unwrap()
    );
    let changed_message_chirho =
        registry_v2_message_from_contract_set_chirho(&changed_set_chirho).unwrap();
    assert_ne!(
        original_message_chirho.contract_set_digest_chirho,
        changed_message_chirho.contract_set_digest_chirho
    );
}

#[test]
fn registry_v2_rejects_duplicate_schema_and_noncanonical_bytes_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let text_chirho = String::from_utf8(
        canonical_registry_v2_message_bytes_chirho(&message_chirho, &set_chirho).unwrap(),
    )
    .unwrap();
    assert!(
        parse_canonical_registry_v2_message_chirho(&format!(" {text_chirho}"), &set_chirho)
            .is_err()
    );
    let duplicate_chirho = text_chirho.replacen(
        "{",
        &format!(
            "{{\"schema_chirho\":\"{}\",",
            BLESSED_REGISTRY_V2_MESSAGE_SCHEMA_CHIRHO
        ),
        1,
    );
    assert!(parse_canonical_registry_v2_message_chirho(&duplicate_chirho, &set_chirho).is_err());

    let unknown_unit_field_chirho = text_chirho.replacen(
        "\"kind_chirho\":\"query-chirho\"}",
        "\"kind_chirho\":\"query-chirho\",\"extra_chirho\":true}",
        1,
    );
    assert_ne!(unknown_unit_field_chirho, text_chirho);
    assert!(
        parse_canonical_registry_v2_message_chirho(&unknown_unit_field_chirho, &set_chirho)
            .is_err()
    );
}

fn complete_legacy_transition_inventory_chirho(
    message_chirho: &BlessedRegistryV2MessageChirho,
) -> Vec<BlessedRegistryTransitionCoordinateChirho> {
    let mut inventory_chirho = message_chirho
        .effect_bindings_chirho
        .iter()
        .map(|binding_chirho| {
            BlessedRegistryTransitionCoordinateChirho::V2CoordinateChirho(
                binding_chirho.coordinate_chirho.clone(),
            )
        })
        .collect::<Vec<_>>();
    inventory_chirho.extend(named_unreachable_registry_v1_retirements_chirho());
    inventory_chirho
}

const REVIEWED_EXECUTABLE_TREE_ROOTS_CHIRHO: &[&str] = &[
    "examples-chirho/tree-app-builder-chirho",
    "examples-chirho/tree-credits-demo-chirho",
    "examples-chirho/tree-pizzeria-chirho",
    "examples-chirho/tree-viewer-state-chirho",
];

fn reviewed_tree_root_chirho(relative_chirho: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_chirho)
}

fn reviewed_card_transition_inventory_chirho(
    roots_chirho: &[&str],
    message_chirho: &BlessedRegistryV2MessageChirho,
) -> Vec<BlessedRegistryTransitionCoordinateChirho> {
    let mut active_coordinates_chirho = BTreeSet::new();
    for relative_chirho in roots_chirho {
        let root_chirho = reviewed_tree_root_chirho(relative_chirho);
        let tree_chirho = walk_app_tree_chirho(&root_chirho);
        let findings_chirho = check_app_tree_chirho(&tree_chirho);
        assert!(
            findings_chirho.is_empty(),
            "reviewed executable tree {relative_chirho} must pass the real strict checker: {findings_chirho:?}"
        );
        append_reviewed_tree_coordinates_chirho(
            &tree_chirho,
            message_chirho,
            &mut active_coordinates_chirho,
        );
    }
    let mut inventory_chirho = active_coordinates_chirho.into_iter().collect::<Vec<_>>();
    inventory_chirho.extend(named_unreachable_registry_v1_retirements_chirho());
    inventory_chirho
}

fn append_reviewed_tree_coordinates_chirho(
    tree_chirho: &AppTreeChirho,
    message_chirho: &BlessedRegistryV2MessageChirho,
    inventory_chirho: &mut BTreeSet<BlessedRegistryTransitionCoordinateChirho>,
) {
    for dag_chirho in &tree_chirho.dags_chirho {
        for role_chirho in &dag_chirho.roles_chirho {
            let RoleBindingChirho::BlessedContractChirho(binding_chirho) =
                &role_chirho.binding_chirho
            else {
                continue;
            };
            let entry_chirho =
                cairn_tree_build_chirho::blessed_catalog_chirho::resolve_blessed_contract_chirho(
                    &binding_chirho.contract_chirho,
                    binding_chirho.contract_hash_chirho.as_deref(),
                )
                .expect("the real checker already verified this reviewed card");
            let contract_key_chirho = entry_chirho.reversion_contract_key_chirho();
            let binding_chirho = message_chirho
                .effect_bindings_chirho
                .iter()
                .find(|binding_chirho| binding_chirho.contract_key_chirho.0 == contract_key_chirho)
                .unwrap_or_else(|| {
                    panic!(
                        "reviewed card {} has no registry-v2 binding",
                        role_chirho.dir_chirho.display()
                    )
                });
            inventory_chirho.insert(
                BlessedRegistryTransitionCoordinateChirho::V2CoordinateChirho(
                    binding_chirho.coordinate_chirho.clone(),
                ),
            );
        }
    }
}

#[test]
fn reviewed_executable_cards_exactly_cover_registry_v2_activation_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let inventory_chirho = reviewed_card_transition_inventory_chirho(
        REVIEWED_EXECUTABLE_TREE_ROOTS_CHIRHO,
        &message_chirho,
    );
    let retired_chirho = named_unreachable_registry_v1_retirements_chirho();

    validate_registry_v2_transition_parity_chirho(
        &inventory_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .unwrap();
    assert_eq!(
        inventory_chirho.len(),
        message_chirho.effect_bindings_chirho.len() + retired_chirho.len(),
        "the reviewed executable inventory must account for every active binding and named retirement"
    );

    let partial_inventory_chirho = reviewed_card_transition_inventory_chirho(
        &REVIEWED_EXECUTABLE_TREE_ROOTS_CHIRHO[..1],
        &message_chirho,
    );
    assert!(validate_registry_v2_transition_parity_chirho(
        &partial_inventory_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());
}

#[test]
fn registry_v2_transition_parity_is_an_exact_partition_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let legacy_chirho = complete_legacy_transition_inventory_chirho(&message_chirho);
    let retired_chirho = named_unreachable_registry_v1_retirements_chirho();

    validate_registry_v2_transition_parity_chirho(
        &legacy_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .unwrap();

    let mut missing_active_chirho = legacy_chirho.clone();
    missing_active_chirho.remove(0);
    assert!(validate_registry_v2_transition_parity_chirho(
        &missing_active_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());

    let mut unnamed_extra_chirho = legacy_chirho.clone();
    unnamed_extra_chirho.push(
        BlessedRegistryTransitionCoordinateChirho::V2CoordinateChirho(
            BlessedEffectCoordinateV2Chirho::NetChirho,
        ),
    );
    assert!(validate_registry_v2_transition_parity_chirho(
        &unnamed_extra_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());
}

#[test]
fn registry_v2_transition_parity_rejects_duplicates_and_false_retirements_chirho() {
    let set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let message_chirho = inert_authoring_registry_v2_message_chirho().unwrap();
    let legacy_chirho = complete_legacy_transition_inventory_chirho(&message_chirho);
    let retired_chirho = named_unreachable_registry_v1_retirements_chirho();

    let mut duplicate_legacy_chirho = legacy_chirho.clone();
    duplicate_legacy_chirho.push(legacy_chirho[0].clone());
    assert!(validate_registry_v2_transition_parity_chirho(
        &duplicate_legacy_chirho,
        &retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());

    let mut duplicate_retired_chirho = retired_chirho.clone();
    duplicate_retired_chirho.push(retired_chirho[0].clone());
    assert!(validate_registry_v2_transition_parity_chirho(
        &legacy_chirho,
        &duplicate_retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());

    let false_retirement_chirho = vec![
        BlessedRegistryTransitionCoordinateChirho::LegacyKindChirho {
            kind_chirho: "never-published-chirho".to_owned(),
        },
    ];
    assert!(validate_registry_v2_transition_parity_chirho(
        &legacy_chirho,
        &false_retirement_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());

    let active_as_retired_chirho = vec![
        BlessedRegistryTransitionCoordinateChirho::V2CoordinateChirho(
            message_chirho.effect_bindings_chirho[0]
                .coordinate_chirho
                .clone(),
        ),
    ];
    assert!(validate_registry_v2_transition_parity_chirho(
        &legacy_chirho,
        &active_as_retired_chirho,
        &message_chirho,
        &set_chirho,
    )
    .is_err());
}
