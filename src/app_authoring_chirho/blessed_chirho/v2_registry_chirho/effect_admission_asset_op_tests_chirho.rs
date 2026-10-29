// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::PortChirho;
use cairn_ledger_model_chirho::asset_op_chirho::{
    canonical_asset_op_bytes_chirho, AssetOpChirho, RoundingChirho,
    ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindIdChirho, AssetKindRefChirho, DigestChirho};
use cairn_undo_plan_chirho::contract_chirho::{
    AssetOpPortRequirementChirho, BlessedContractKeyChirho,
};

fn asset_authority_chirho() -> (
    BlessedReversionContractSetChirho,
    BlessedRegistryV2MessageChirho,
    HashChirho,
) {
    let mut contract_set_chirho = canonical_authoring_reversion_contract_set_chirho();
    let contract_chirho = contract_set_chirho
        .contracts_chirho
        .iter_mut()
        .find(|contract_chirho| {
            contract_chirho.contract_key_chirho == BlessedContractKeyChirho("llm-chirho".to_owned())
        })
        .unwrap();
    contract_chirho.asset_op_ports_chirho = vec![AssetOpPortRequirementChirho {
        port_chirho: "asset-op-chirho".to_owned(),
        schema_chirho: HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
    }];
    let set_digest_chirho = contract_set_digest_chirho(&contract_set_chirho).unwrap();
    let registry_chirho =
        registry_v2_message_from_contract_set_chirho(&contract_set_chirho).unwrap();
    (contract_set_chirho, registry_chirho, set_digest_chirho)
}

fn asset_node_chirho(set_digest_chirho: HashChirho, schema_chirho: HashChirho) -> NodeDefChirho {
    NodeDefChirho {
        name_chirho: "asset-op-admission-node-chirho".to_owned(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "asset-op-chirho".to_owned(),
            schema_chirho,
        }],
        capabilities_chirho: vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "llm_chirho".to_owned(),
            caller_chirho: "declared-caller-chirho".to_owned(),
        }],
        effect_contract_set_chirho: Some(set_digest_chirho),
        ..Default::default()
    }
}

fn canonical_request_chirho() -> Vec<u8> {
    canonical_asset_op_bytes_chirho(&AssetOpChirho {
        amount_chirho: 125,
        kind_id_chirho: AssetKindIdChirho("usd-chirho".to_owned()),
        kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
            "policy-v1-digest-chirho".to_owned(),
        )),
        rounding_chirho: RoundingChirho::ExactChirho,
    })
    .unwrap()
}

#[test]
fn admitted_money_door_parses_asset_op_before_use_chirho() {
    let (contract_set_chirho, registry_chirho, set_digest_chirho) = asset_authority_chirho();
    let node_chirho = asset_node_chirho(
        set_digest_chirho,
        HashChirho(ASSET_OP_FIELD_GRAPH_DIGEST_V1_CHIRHO.to_owned()),
    );
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let capability_chirho = node_chirho.capabilities_chirho[0].clone();
    let admission_chirho = admit_verified_node_effect_against_authority_chirho(
        &node_chirho,
        &node_hash_chirho,
        &capability_chirho,
        &contract_set_chirho,
        &registry_chirho,
    )
    .unwrap();
    assert!(admission_chirho.requires_asset_op_request_chirho());
    admission_chirho
        .authorize_request_chirho(&canonical_request_chirho())
        .unwrap();

    for bad_request_chirho in [
        br#"1"#.as_slice(),
        br#"{"amount_chirho":1.0,"kind_id_chirho":"usd-chirho","kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#.as_slice(),
        br#"{"kind_id_chirho":"usd-chirho","amount_chirho":1,"kind_policy_ref_chirho":"policy-v1-digest-chirho","rounding_chirho":"exact-chirho"}"#.as_slice(),
    ] {
        assert!(admission_chirho
            .authorize_request_chirho(bad_request_chirho)
            .is_err());
    }
}

#[test]
fn admitted_money_door_refuses_wrong_node_schema_chirho() {
    let (contract_set_chirho, registry_chirho, set_digest_chirho) = asset_authority_chirho();
    let node_chirho = asset_node_chirho(set_digest_chirho, HashChirho("0".repeat(64)));
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    let error_chirho = match admit_verified_node_effect_against_authority_chirho(
        &node_chirho,
        &node_hash_chirho,
        &node_chirho.capabilities_chirho[0],
        &contract_set_chirho,
        &registry_chirho,
    ) {
        Ok(_) => panic!("wrong AssetOp node schema should refuse runtime admission"),
        Err(error_chirho) => error_chirho,
    };
    assert!(error_chirho
        .to_string()
        .contains("does not name the canonical schema"));
}

#[test]
fn explicit_legacy_operator_does_not_claim_asset_op_validation_chirho() {
    let capability_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "legacy-operator-subtype-chirho".to_owned(),
        caller_chirho: "operator-chirho".to_owned(),
    };
    let admission_chirho = admit_legacy_operator_effect_chirho(&capability_chirho).unwrap();
    assert!(!admission_chirho.requires_asset_op_request_chirho());
    admission_chirho
        .authorize_request_chirho(b"not-json")
        .unwrap();
}
