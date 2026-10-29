// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::{
    AppSourceDeployTargetChirho, AppSourceManifestChirho, APP_SOURCE_MANIFEST_SCHEMA_CHIRHO,
};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_input_projection_chirho::{
    contract_chirho::{
        InputProjectionChirho, NodeInputProjectionBindingChirho,
        NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO,
    },
    field_graph_chirho::FieldGraphValidationPolicyChirho,
};

const HASH_CHIRHO: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn manifest_chirho() -> AppSourceManifestV2Chirho {
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: HashChirho(HASH_CHIRHO.to_string()),
        guest_schema_chirho: HashChirho(HASH_CHIRHO.to_string()),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    AppSourceManifestV2Chirho {
        schema_chirho: APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO.to_string(),
        app_chirho: "projection-app-chirho".to_string(),
        owner_chirho: "owner-projection-chirho".to_string(),
        nodes_chirho: vec![AppSourceNodeManifestV2Chirho {
            id_chirho: "project_chirho".to_string(),
            name_chirho: "project_chirho".to_string(),
            entry_chirho: Some("project_chirho".to_string()),
            fuel_chirho: 1,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::BuiltinNodeTemplateChirho {
                template_chirho: "node-template-chirho".to_string(),
            },
            input_contracts_chirho: BTreeMap::from([("in_chirho".to_string(), binding_chirho)]),
        }],
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    }
}

#[test]
fn strict_v2_round_trips_and_carries_a_non_v1_schema_chirho() {
    let manifest_chirho = manifest_chirho();
    let bytes_chirho = canonical_app_source_manifest_v2_bytes_chirho(&manifest_chirho).unwrap();
    assert_eq!(
        parse_canonical_app_source_manifest_v2_chirho(&bytes_chirho).unwrap(),
        manifest_chirho
    );

    let legacy_chirho: AppSourceManifestChirho = serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        legacy_chirho.schema_chirho,
        APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO
    );
    assert_ne!(
        legacy_chirho.schema_chirho,
        APP_SOURCE_MANIFEST_SCHEMA_CHIRHO
    );
}

#[test]
fn missing_unknown_and_noncanonical_v2_bytes_fail_chirho() {
    let bytes_chirho = canonical_app_source_manifest_v2_bytes_chirho(&manifest_chirho()).unwrap();
    let text_chirho = String::from_utf8(bytes_chirho).unwrap();
    let mut missing_value_chirho: serde_json::Value = serde_json::from_str(&text_chirho).unwrap();
    missing_value_chirho["nodes_chirho"][0]
        .as_object_mut()
        .unwrap()
        .remove("input_contracts_chirho");
    let missing_chirho = serde_json::to_string(&missing_value_chirho).unwrap();
    let unknown_chirho = text_chirho.replacen(
        "{\"schema_chirho\":",
        "{\"unknown_chirho\":true,\"schema_chirho\":",
        1,
    );
    let nested_unknown_chirho = text_chirho.replacen(
        "\"fuel_chirho\":1,",
        "\"fuel_chirho\":1,\"unknown_nested_chirho\":true,",
        1,
    );
    let reordered_chirho = serde_json::to_string_pretty(&manifest_chirho()).unwrap();
    for candidate_chirho in [
        missing_chirho,
        unknown_chirho,
        nested_unknown_chirho,
        reordered_chirho,
    ] {
        assert!(
            parse_canonical_app_source_manifest_v2_chirho(candidate_chirho.as_bytes()).is_err()
        );
    }
}
