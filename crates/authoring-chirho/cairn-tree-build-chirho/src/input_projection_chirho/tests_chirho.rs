// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_input_projection_chirho::{
    attestation_chirho::{
        canonical_input_schema_attestation_bytes_chirho, InputSchemaAttestationChirho,
        INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO, INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO,
    },
    contract_chirho::{InputProjectionChirho, NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO},
    field_graph_chirho::{
        CanonicalFieldChirho, CanonicalFieldNodeChirho, FieldGraphValidationPolicyChirho,
        FieldRequirednessChirho, FieldVariabilityChirho, PrivacyClassChirho,
        CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO,
    },
    path_chirho::JsonFieldPathChirho,
};

fn source_graph_chirho() -> CanonicalFieldGraphChirho {
    CanonicalFieldGraphChirho {
        schema_chirho: CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO.to_string(),
        root_chirho: CanonicalFieldNodeChirho::ObjectChirho {
            fields_chirho: vec![
                CanonicalFieldChirho {
                    name_chirho: "drop_chirho".to_string(),
                    node_chirho: CanonicalFieldNodeChirho::StringChirho,
                    requiredness_chirho: FieldRequirednessChirho::RequiredChirho,
                    variability_chirho: FieldVariabilityChirho::InvocationVaryingChirho,
                    privacy_class_chirho: PrivacyClassChirho::DirectChirho,
                    generalization_chirho: None,
                    indexed_chirho: false,
                },
                CanonicalFieldChirho {
                    name_chirho: "keep_chirho".to_string(),
                    node_chirho: CanonicalFieldNodeChirho::StringChirho,
                    requiredness_chirho: FieldRequirednessChirho::RequiredChirho,
                    variability_chirho: FieldVariabilityChirho::StableChirho,
                    privacy_class_chirho: PrivacyClassChirho::SafeChirho,
                    generalization_chirho: None,
                    indexed_chirho: false,
                },
            ],
        },
    }
}

struct MetadataChirho {
    graph_chirho: CanonicalFieldGraphChirho,
}

impl ProjectionFieldMetadataPortChirho for MetadataChirho {
    fn verified_field_graph_chirho(
        &self,
        schema_hash_chirho: &HashChirho,
    ) -> anyhow::Result<CanonicalFieldGraphChirho> {
        if canonical_field_graph_hash_chirho(&self.graph_chirho)? != *schema_hash_chirho {
            anyhow::bail!("unknown field graph")
        }
        Ok(self.graph_chirho.clone())
    }
}

fn encode_u32_leb_chirho(mut value_chirho: u32, output_chirho: &mut Vec<u8>) {
    loop {
        let mut byte_chirho = (value_chirho & 0x7f) as u8;
        value_chirho >>= 7;
        if value_chirho != 0 {
            byte_chirho |= 0x80;
        }
        output_chirho.push(byte_chirho);
        if value_chirho == 0 {
            break;
        }
    }
}

fn wasm_with_attestation_chirho(payload_chirho: Option<&[u8]>) -> Vec<u8> {
    let mut wasm_chirho = b"\0asm\x01\0\0\0".to_vec();
    let Some(payload_chirho) = payload_chirho else {
        return wasm_chirho;
    };
    let mut body_chirho = Vec::new();
    encode_u32_leb_chirho(
        INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO.len() as u32,
        &mut body_chirho,
    );
    body_chirho.extend_from_slice(INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO.as_bytes());
    body_chirho.extend_from_slice(payload_chirho);
    wasm_chirho.push(0);
    encode_u32_leb_chirho(body_chirho.len() as u32, &mut wasm_chirho);
    wasm_chirho.extend_from_slice(&body_chirho);
    wasm_chirho
}

fn fixture_chirho() -> (MetadataChirho, NodeInputProjectionBindingChirho, Vec<u8>) {
    let source_graph_chirho = source_graph_chirho();
    let consumed_chirho = vec![JsonFieldPathChirho::parse_chirho("/keep_chirho").unwrap()];
    let projected_chirho =
        derive_projected_field_graph_chirho(&source_graph_chirho, &consumed_chirho).unwrap();
    let source_hash_chirho = canonical_field_graph_hash_chirho(&source_graph_chirho).unwrap();
    let guest_hash_chirho = canonical_field_graph_hash_chirho(&projected_chirho).unwrap();
    let payload_chirho =
        canonical_input_schema_attestation_bytes_chirho(&InputSchemaAttestationChirho {
            schema_chirho: INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO.to_string(),
            projected_schema_hash_chirho: guest_hash_chirho.clone(),
        })
        .unwrap();
    (
        MetadataChirho {
            graph_chirho: source_graph_chirho,
        },
        NodeInputProjectionBindingChirho {
            schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
            source_schema_chirho: source_hash_chirho,
            guest_schema_chirho: guest_hash_chirho,
            policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
            projection_chirho: InputProjectionChirho::JsonFieldsChirho {
                consumed_fields_chirho: consumed_chirho,
            },
        },
        payload_chirho,
    )
}

#[test]
fn checker_uses_the_shared_derivation_and_exact_guest_attestation_chirho() {
    let (metadata_chirho, binding_chirho, payload_chirho) = fixture_chirho();
    let wasm_chirho = wasm_with_attestation_chirho(Some(&payload_chirho));
    let checked_chirho = check_inert_input_projection_chirho(
        &metadata_chirho,
        &binding_chirho,
        &wasm_chirho,
        ProjectionNodeClassChirho::PureWasmChirho,
        ProjectionInputShapeChirho::StructuredJsonChirho,
    )
    .unwrap();
    assert_eq!(
        canonical_field_graph_hash_chirho(&checked_chirho.projected_graph_chirho).unwrap(),
        binding_chirho.guest_schema_chirho
    );
}

#[test]
fn missing_stripped_malformed_and_mismatched_attestations_fail_chirho() {
    let (metadata_chirho, binding_chirho, payload_chirho) = fixture_chirho();
    let other_hash_chirho = HashChirho("f".repeat(64));
    let mismatch_chirho =
        canonical_input_schema_attestation_bytes_chirho(&InputSchemaAttestationChirho {
            schema_chirho: INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO.to_string(),
            projected_schema_hash_chirho: other_hash_chirho,
        })
        .unwrap();
    for wasm_chirho in [
        wasm_with_attestation_chirho(None),
        wasm_with_attestation_chirho(Some(b"not-json")),
        wasm_with_attestation_chirho(Some(&mismatch_chirho)),
    ] {
        assert!(check_inert_input_projection_chirho(
            &metadata_chirho,
            &binding_chirho,
            &wasm_chirho,
            ProjectionNodeClassChirho::PureWasmChirho,
            ProjectionInputShapeChirho::StructuredJsonChirho,
        )
        .is_err());
    }
    assert!(check_inert_input_projection_chirho(
        &metadata_chirho,
        &binding_chirho,
        &wasm_with_attestation_chirho(Some(&payload_chirho)),
        ProjectionNodeClassChirho::PureWasmChirho,
        ProjectionInputShapeChirho::StructuredJsonChirho,
    )
    .is_ok());
}

#[test]
fn executor_and_input_classes_enforce_field_vs_whole_value_chirho() {
    let (metadata_chirho, field_binding_chirho, field_payload_chirho) = fixture_chirho();
    let field_wasm_chirho = wasm_with_attestation_chirho(Some(&field_payload_chirho));
    for node_class_chirho in [
        ProjectionNodeClassChirho::EffectChirho,
        ProjectionNodeClassChirho::NativeChirho,
        ProjectionNodeClassChirho::ScalarChirho,
        ProjectionNodeClassChirho::BuiltinPhiChirho,
    ] {
        let error_chirho = check_inert_input_projection_chirho(
            &metadata_chirho,
            &field_binding_chirho,
            &field_wasm_chirho,
            node_class_chirho,
            ProjectionInputShapeChirho::StructuredJsonChirho,
        )
        .unwrap_err();
        assert!(error_chirho.to_string().contains("require whole-value"));
    }
    assert!(check_inert_input_projection_chirho(
        &metadata_chirho,
        &field_binding_chirho,
        &field_wasm_chirho,
        ProjectionNodeClassChirho::PureWasmChirho,
        ProjectionInputShapeChirho::OpaqueOrScalarChirho,
    )
    .unwrap_err()
    .to_string()
    .contains("opaque inputs require whole-value"));

    let source_hash_chirho = canonical_field_graph_hash_chirho(&metadata_chirho.graph_chirho)
        .expect("source graph hashes");
    let whole_binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: source_hash_chirho.clone(),
        guest_schema_chirho: source_hash_chirho.clone(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let whole_payload_chirho =
        canonical_input_schema_attestation_bytes_chirho(&InputSchemaAttestationChirho {
            schema_chirho: INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO.to_string(),
            projected_schema_hash_chirho: source_hash_chirho,
        })
        .unwrap();
    let whole_wasm_chirho = wasm_with_attestation_chirho(Some(&whole_payload_chirho));
    assert!(check_inert_input_projection_chirho(
        &metadata_chirho,
        &whole_binding_chirho,
        &whole_wasm_chirho,
        ProjectionNodeClassChirho::PureWasmChirho,
        ProjectionInputShapeChirho::StructuredJsonChirho,
    )
    .unwrap_err()
    .to_string()
    .contains("pure structured inputs require field projection"));
    for node_class_chirho in [
        ProjectionNodeClassChirho::EffectChirho,
        ProjectionNodeClassChirho::NativeChirho,
        ProjectionNodeClassChirho::ScalarChirho,
        ProjectionNodeClassChirho::BuiltinPhiChirho,
    ] {
        check_inert_input_projection_chirho(
            &metadata_chirho,
            &whole_binding_chirho,
            &whole_wasm_chirho,
            node_class_chirho,
            ProjectionInputShapeChirho::OpaqueOrScalarChirho,
        )
        .unwrap();
    }
}
