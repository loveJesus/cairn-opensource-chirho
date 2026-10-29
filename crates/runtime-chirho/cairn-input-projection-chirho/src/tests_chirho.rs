// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::contract_chirho::{
    canonical_node_input_projection_binding_bytes_chirho,
    parse_canonical_node_input_projection_binding_chirho,
    validate_node_input_projection_binding_chirho, InputProjectionChirho,
    NodeInputProjectionBindingChirho, NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO,
};
use crate::coordinate_chirho::{
    parse_canonical_projected_input_coordinate_chirho, private_projected_coordinate_chirho,
    public_projected_coordinate_chirho, validate_projected_input_coordinate_chirho,
    PrivateInputKeyChirho, ProjectedInputCoordinateChirho,
};
use crate::field_graph_chirho::{
    canonical_field_graph_bytes_chirho, canonical_field_graph_hash_chirho,
    parse_canonical_field_graph_chirho, validate_canonical_field_graph_chirho,
    validate_field_graph_binding_policy_chirho, CanonicalFieldChirho, CanonicalFieldGraphChirho,
    CanonicalFieldNodeChirho, FieldGeneralizationChirho, FieldGraphBindingSiteChirho,
    FieldGraphValidationPolicyChirho, FieldRequirednessChirho, FieldVariabilityChirho,
    PrivacyClassChirho, ProjectionFieldMetadataPortChirho, CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO,
};
use crate::materialize_chirho::{
    derive_projected_field_graph_chirho, materialize_exact_node_input_chirho,
    PrivateCoordinateMaterialChirho, ProjectionCoordinateContextChirho,
};
use crate::path_chirho::{validate_consumed_fields_chirho, JsonFieldPathChirho};
use anyhow::{bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;

fn hash_chirho(byte_chirho: u8) -> HashChirho {
    HashChirho(format!("{byte_chirho:02x}").repeat(32))
}

fn field_chirho(
    name_chirho: &str,
    node_chirho: CanonicalFieldNodeChirho,
    requiredness_chirho: FieldRequirednessChirho,
    variability_chirho: FieldVariabilityChirho,
    privacy_class_chirho: PrivacyClassChirho,
) -> CanonicalFieldChirho {
    CanonicalFieldChirho {
        name_chirho: name_chirho.to_string(),
        node_chirho,
        requiredness_chirho,
        variability_chirho,
        privacy_class_chirho,
        generalization_chirho: None,
        indexed_chirho: false,
    }
}

fn private_source_graph_chirho() -> CanonicalFieldGraphChirho {
    CanonicalFieldGraphChirho {
        schema_chirho: CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO.to_string(),
        root_chirho: CanonicalFieldNodeChirho::ObjectChirho {
            fields_chirho: vec![
                field_chirho(
                    "amount_chirho",
                    CanonicalFieldNodeChirho::SignedIntegerChirho { bits_chirho: 64 },
                    FieldRequirednessChirho::RequiredChirho,
                    FieldVariabilityChirho::StableChirho,
                    PrivacyClassChirho::SafeChirho,
                ),
                field_chirho(
                    "customer_chirho",
                    CanonicalFieldNodeChirho::ObjectChirho {
                        fields_chirho: vec![
                            field_chirho(
                                "email_chirho",
                                CanonicalFieldNodeChirho::StringChirho,
                                FieldRequirednessChirho::RequiredChirho,
                                FieldVariabilityChirho::StableChirho,
                                PrivacyClassChirho::DirectChirho,
                            ),
                            field_chirho(
                                "id_chirho",
                                CanonicalFieldNodeChirho::StringChirho,
                                FieldRequirednessChirho::RequiredChirho,
                                FieldVariabilityChirho::StableChirho,
                                PrivacyClassChirho::SafeChirho,
                            ),
                            field_chirho(
                                "nickname_chirho",
                                CanonicalFieldNodeChirho::StringChirho,
                                FieldRequirednessChirho::OptionalChirho,
                                FieldVariabilityChirho::StableChirho,
                                PrivacyClassChirho::SafeChirho,
                            ),
                        ],
                    },
                    FieldRequirednessChirho::RequiredChirho,
                    FieldVariabilityChirho::StableChirho,
                    PrivacyClassChirho::SafeChirho,
                ),
                field_chirho(
                    "items_chirho",
                    CanonicalFieldNodeChirho::ArrayChirho {
                        element_chirho: Box::new(CanonicalFieldNodeChirho::ObjectChirho {
                            fields_chirho: vec![field_chirho(
                                "sku_chirho",
                                CanonicalFieldNodeChirho::StringChirho,
                                FieldRequirednessChirho::RequiredChirho,
                                FieldVariabilityChirho::StableChirho,
                                PrivacyClassChirho::SafeChirho,
                            )],
                        }),
                    },
                    FieldRequirednessChirho::RequiredChirho,
                    FieldVariabilityChirho::StableChirho,
                    PrivacyClassChirho::SafeChirho,
                ),
                field_chirho(
                    "request_id_chirho",
                    CanonicalFieldNodeChirho::StringChirho,
                    FieldRequirednessChirho::RequiredChirho,
                    FieldVariabilityChirho::InvocationVaryingChirho,
                    PrivacyClassChirho::SafeChirho,
                ),
                field_chirho(
                    "safe_chirho",
                    CanonicalFieldNodeChirho::BooleanChirho,
                    FieldRequirednessChirho::RequiredChirho,
                    FieldVariabilityChirho::StableChirho,
                    PrivacyClassChirho::SafeChirho,
                ),
            ],
        },
    }
}

fn public_source_graph_chirho() -> CanonicalFieldGraphChirho {
    CanonicalFieldGraphChirho {
        schema_chirho: CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO.to_string(),
        root_chirho: CanonicalFieldNodeChirho::ObjectChirho {
            fields_chirho: vec![field_chirho(
                "message_chirho",
                CanonicalFieldNodeChirho::StringChirho,
                FieldRequirednessChirho::RequiredChirho,
                FieldVariabilityChirho::StableChirho,
                PrivacyClassChirho::SafeChirho,
            )],
        },
    }
}

struct FakeMetadataPortChirho {
    hash_chirho: HashChirho,
    graph_chirho: CanonicalFieldGraphChirho,
}

impl ProjectionFieldMetadataPortChirho for FakeMetadataPortChirho {
    fn verified_field_graph_chirho(
        &self,
        schema_hash_chirho: &HashChirho,
    ) -> Result<CanonicalFieldGraphChirho> {
        if schema_hash_chirho != &self.hash_chirho {
            bail!("fake metadata port has no requested graph");
        }
        Ok(self.graph_chirho.clone())
    }
}

fn binding_for_fields_chirho(
    graph_chirho: &CanonicalFieldGraphChirho,
    paths_chirho: &[&str],
) -> NodeInputProjectionBindingChirho {
    let consumed_fields_chirho: Vec<JsonFieldPathChirho> = paths_chirho
        .iter()
        .map(|path_chirho| JsonFieldPathChirho::parse_chirho(path_chirho).unwrap())
        .collect();
    let projected_chirho =
        derive_projected_field_graph_chirho(graph_chirho, &consumed_fields_chirho).unwrap();
    NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: canonical_field_graph_hash_chirho(graph_chirho).unwrap(),
        guest_schema_chirho: canonical_field_graph_hash_chirho(&projected_chirho).unwrap(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::JsonFieldsChirho {
            consumed_fields_chirho,
        },
    }
}

fn private_source_bytes_chirho() -> &'static [u8] {
    br#"{
      "safe_chirho": true,
      "request_id_chirho": "req-9",
      "items_chirho": [{"sku_chirho":"sku-1"}],
      "customer_chirho": {
        "id_chirho": "c-1",
        "email_chirho": "private@example.test"
      },
      "amount_chirho": -7
    }"#
}

#[test]
fn json_field_paths_round_trip_canonical_pointer_escapes_chirho() {
    let path_chirho = JsonFieldPathChirho::parse_chirho("/customer_chirho/a~1b/~0tag_chirho")
        .expect("canonical path");
    assert_eq!(
        path_chirho.segments_chirho(),
        &["customer_chirho", "a/b", "~tag_chirho"]
    );
    assert_eq!(
        serde_json::to_string(&path_chirho).unwrap(),
        "\"/customer_chirho/a~1b/~0tag_chirho\""
    );
    let decoded_chirho: JsonFieldPathChirho =
        serde_json::from_str("\"/customer_chirho/a~1b/~0tag_chirho\"").unwrap();
    assert_eq!(decoded_chirho, path_chirho);
}

#[test]
fn json_field_paths_reject_root_empty_and_bad_escape_chirho() {
    for value_chirho in ["", "/", "customer_chirho", "/a~2b", "/a~"] {
        assert!(
            JsonFieldPathChirho::parse_chirho(value_chirho).is_err(),
            "accepted {value_chirho:?}"
        );
    }
}

#[test]
fn consumed_fields_require_strict_order_without_overlap_chirho() {
    let a_chirho = JsonFieldPathChirho::parse_chirho("/a_chirho").unwrap();
    let ab_chirho = JsonFieldPathChirho::parse_chirho("/a_chirho/b_chirho").unwrap();
    let b_chirho = JsonFieldPathChirho::parse_chirho("/b_chirho").unwrap();

    assert!(validate_consumed_fields_chirho(&[a_chirho.clone(), b_chirho.clone()]).is_ok());
    assert!(validate_consumed_fields_chirho(&[]).is_err());
    assert!(validate_consumed_fields_chirho(&[b_chirho.clone(), a_chirho.clone()]).is_err());
    assert!(validate_consumed_fields_chirho(&[a_chirho.clone(), a_chirho.clone()]).is_err());
    assert!(validate_consumed_fields_chirho(&[a_chirho, ab_chirho]).is_err());
}

#[test]
fn public_coordinate_is_the_exact_projected_byte_hash_chirho() {
    let bytes_chirho = br#"{"safe_chirho":true}"#;
    assert_eq!(
        public_projected_coordinate_chirho(bytes_chirho),
        ProjectedInputCoordinateChirho::PublicHashChirho {
            hash_chirho: HashChirho(blake3::hash(bytes_chirho).to_hex().to_string())
        }
    );
}

#[test]
fn private_coordinate_is_subject_keyed_and_context_bound_chirho() {
    let node_chirho = hash_chirho(0x11);
    let contract_chirho = hash_chirho(0x22);
    let key_a_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x33; 32]).unwrap();
    let key_b_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x44; 32]).unwrap();
    let bytes_chirho = br#"{"private_flag_chirho":true}"#;

    let first_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "input_chirho",
        &contract_chirho,
        "subject-key-v1-chirho",
        &key_a_chirho,
        bytes_chirho,
    )
    .unwrap();
    let repeat_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "input_chirho",
        &contract_chirho,
        "subject-key-v1-chirho",
        &key_a_chirho,
        bytes_chirho,
    )
    .unwrap();
    let other_subject_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "input_chirho",
        &contract_chirho,
        "subject-key-v1-chirho",
        &key_b_chirho,
        bytes_chirho,
    )
    .unwrap();

    assert_eq!(first_chirho, repeat_chirho);
    assert_ne!(first_chirho, other_subject_chirho);
    assert_ne!(
        first_chirho,
        public_projected_coordinate_chirho(bytes_chirho)
    );
}

#[test]
fn low_entropy_private_value_has_no_bare_dictionary_coordinate_chirho() {
    let node_chirho = hash_chirho(0x55);
    let contract_chirho = hash_chirho(0x66);
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x77; 32]).unwrap();
    let private_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "input_chirho",
        &contract_chirho,
        "subject-key-v1-chirho",
        &key_chirho,
        b"true",
    )
    .unwrap();

    for candidate_chirho in [b"true".as_slice(), b"false".as_slice()] {
        assert_ne!(
            private_chirho,
            public_projected_coordinate_chirho(candidate_chirho)
        );
    }
}

#[test]
fn private_coordinate_framing_separates_concat_ambiguous_contexts_chirho() {
    let node_chirho = hash_chirho(0x88);
    let contract_chirho = hash_chirho(0x99);
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0xaa; 32]).unwrap();
    let left_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "a",
        &contract_chirho,
        "bc",
        &key_chirho,
        b"d",
    )
    .unwrap();
    let right_chirho = private_projected_coordinate_chirho(
        &node_chirho,
        "ab",
        &contract_chirho,
        "c",
        &key_chirho,
        b"d",
    )
    .unwrap();
    assert_ne!(left_chirho, right_chirho);
}

#[test]
fn private_coordinate_rejects_unbounded_or_unshaped_context_chirho() {
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0xbb; 32]).unwrap();
    assert!(private_projected_coordinate_chirho(
        &HashChirho("not-a-hash".to_string()),
        "input_chirho",
        &hash_chirho(0xcc),
        "subject-key-v1-chirho",
        &key_chirho,
        b"value"
    )
    .is_err());
    assert!(private_projected_coordinate_chirho(
        &hash_chirho(0xdd),
        "input/chirho",
        &hash_chirho(0xee),
        "subject-key-v1-chirho",
        &key_chirho,
        b"value"
    )
    .is_err());
}

#[test]
fn private_input_key_rejects_the_all_zero_sentinel_chirho() {
    assert!(PrivateInputKeyChirho::try_from_bytes_chirho([0; 32]).is_err());
}

#[test]
fn private_coordinate_wire_bytes_never_include_key_material_chirho() {
    let coordinate_chirho = private_projected_coordinate_chirho(
        &hash_chirho(0x12),
        "input_chirho",
        &hash_chirho(0x34),
        "subject-key-v1-chirho",
        &PrivateInputKeyChirho::try_from_bytes_chirho([0xab; 32]).unwrap(),
        b"true",
    )
    .unwrap();
    let encoded_chirho = serde_json::to_string(&coordinate_chirho).unwrap();
    assert_eq!(
        encoded_chirho,
        format!(
            "{{\"kind_chirho\":\"private-keyed-digest-chirho\",\"key_generation_chirho\":\"subject-key-v1-chirho\",\"digest_chirho\":\"{}\"}}",
            match coordinate_chirho {
                ProjectedInputCoordinateChirho::PrivateKeyedDigestChirho {
                    ref digest_chirho, ..
                } => digest_chirho,
                ProjectedInputCoordinateChirho::PublicHashChirho { .. } => unreachable!(),
            }
        )
    );
    assert!(!encoded_chirho.contains(&"ab".repeat(32)));
    assert_eq!(
        parse_canonical_projected_input_coordinate_chirho(&encoded_chirho).unwrap(),
        coordinate_chirho
    );
    assert!(validate_projected_input_coordinate_chirho(&coordinate_chirho).is_ok());
}

#[test]
fn coordinate_parser_rejects_reordered_unknown_and_noncanonical_digest_chirho() {
    let canonical_chirho = serde_json::to_string(&public_projected_coordinate_chirho(b"value"))
        .expect("encode canonical coordinate");
    let ProjectedInputCoordinateChirho::PublicHashChirho { hash_chirho } =
        public_projected_coordinate_chirho(b"value")
    else {
        unreachable!()
    };
    let reordered_chirho = format!(
        "{{\"hash_chirho\":\"{}\",\"kind_chirho\":\"public-hash-chirho\"}}",
        hash_chirho.0
    );
    assert!(serde_json::from_str::<ProjectedInputCoordinateChirho>(&reordered_chirho).is_ok());
    assert!(parse_canonical_projected_input_coordinate_chirho(&reordered_chirho).is_err());
    assert!(
        parse_canonical_projected_input_coordinate_chirho(&canonical_chirho.replacen(
            "}",
            ",\"unknown_chirho\":true}",
            1
        ))
        .is_err()
    );
    assert!(validate_projected_input_coordinate_chirho(
        &ProjectedInputCoordinateChirho::PrivateKeyedDigestChirho {
            key_generation_chirho: "subject-key-v1-chirho".to_string(),
            digest_chirho: "A0".repeat(32),
        }
    )
    .is_err());
}

#[test]
fn canonical_field_graph_has_stable_bytes_and_hash_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let bytes_chirho = canonical_field_graph_bytes_chirho(&graph_chirho).unwrap();
    assert_eq!(
        String::from_utf8(bytes_chirho.clone()).unwrap(),
        "{\"schema_chirho\":\"canonical-field-graph-v1-chirho\",\"root_chirho\":{\"kind_chirho\":\"object-chirho\",\"fields_chirho\":[{\"name_chirho\":\"message_chirho\",\"node_chirho\":{\"kind_chirho\":\"string-chirho\"},\"requiredness_chirho\":\"required-chirho\",\"variability_chirho\":\"stable-chirho\",\"privacy_class_chirho\":\"safe-chirho\",\"indexed_chirho\":false}]}}"
    );
    assert_eq!(
        canonical_field_graph_hash_chirho(&graph_chirho).unwrap().0,
        blake3::hash(&bytes_chirho).to_hex().to_string()
    );
    assert_eq!(
        parse_canonical_field_graph_chirho(std::str::from_utf8(&bytes_chirho).unwrap()).unwrap(),
        graph_chirho
    );
}

#[test]
fn canonical_field_graph_rejects_wrong_root_order_width_and_generalization_chirho() {
    let mut scalar_root_chirho = public_source_graph_chirho();
    scalar_root_chirho.root_chirho = CanonicalFieldNodeChirho::StringChirho;
    assert!(validate_canonical_field_graph_chirho(&scalar_root_chirho).is_err());

    let mut unsorted_chirho = private_source_graph_chirho();
    let CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } = &mut unsorted_chirho.root_chirho
    else {
        unreachable!()
    };
    fields_chirho.swap(0, 1);
    assert!(validate_canonical_field_graph_chirho(&unsorted_chirho).is_err());

    let mut bad_width_chirho = public_source_graph_chirho();
    let CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } =
        &mut bad_width_chirho.root_chirho
    else {
        unreachable!()
    };
    fields_chirho[0].node_chirho =
        CanonicalFieldNodeChirho::UnsignedIntegerChirho { bits_chirho: 24 };
    assert!(validate_canonical_field_graph_chirho(&bad_width_chirho).is_err());

    let mut bad_generalization_chirho = public_source_graph_chirho();
    let CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } =
        &mut bad_generalization_chirho.root_chirho
    else {
        unreachable!()
    };
    fields_chirho[0].generalization_chirho =
        Some(FieldGeneralizationChirho::NumericBandChirho { width_chirho: 5 });
    assert!(validate_canonical_field_graph_chirho(&bad_generalization_chirho).is_err());
}

#[test]
fn field_graph_parser_rejects_unknown_reordered_and_noncanonical_bytes_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let canonical_chirho =
        String::from_utf8(canonical_field_graph_bytes_chirho(&graph_chirho).unwrap()).unwrap();
    let unknown_chirho = canonical_chirho.replacen(
        "\"schema_chirho\":",
        "\"unknown_chirho\":1,\"schema_chirho\":",
        1,
    );
    assert!(parse_canonical_field_graph_chirho(&unknown_chirho).is_err());
    assert!(parse_canonical_field_graph_chirho(&format!(" {canonical_chirho}")).is_err());
    let reordered_chirho = format!(
        "{{\"root_chirho\":{},\"schema_chirho\":\"{}\"}}",
        serde_json::to_string(&graph_chirho.root_chirho).unwrap(),
        CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO
    );
    assert!(serde_json::from_str::<CanonicalFieldGraphChirho>(&reordered_chirho).is_ok());
    assert!(parse_canonical_field_graph_chirho(&reordered_chirho).is_err());
}

#[test]
fn public_whole_value_materializes_one_canonical_coordinate_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let graph_hash_chirho = canonical_field_graph_hash_chirho(&graph_chirho).unwrap();
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: graph_hash_chirho.clone(),
        guest_schema_chirho: graph_hash_chirho.clone(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: graph_hash_chirho,
        graph_chirho,
    };
    let materialized_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        b"{ \"message_chirho\" : \"hello\" }",
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0xf1),
            port_chirho: "input_chirho",
            private_chirho: None,
        },
    )
    .unwrap();
    assert_eq!(
        materialized_chirho.bytes_chirho,
        br#"{"message_chirho":"hello"}"#
    );
    assert_eq!(
        materialized_chirho.coordinate_chirho,
        public_projected_coordinate_chirho(&materialized_chirho.bytes_chirho)
    );
}

#[test]
fn validation_policy_is_bound_to_its_only_lawful_site_chirho() {
    assert!(validate_field_graph_binding_policy_chirho(
        FieldGraphBindingSiteChirho::NodeInputChirho,
        FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho
    )
    .is_ok());
    assert!(validate_field_graph_binding_policy_chirho(
        FieldGraphBindingSiteChirho::RecordProjectionChirho,
        FieldGraphValidationPolicyChirho::TolerantRecordProjectionPolicyChirho
    )
    .is_ok());
    assert!(validate_field_graph_binding_policy_chirho(
        FieldGraphBindingSiteChirho::NodeInputChirho,
        FieldGraphValidationPolicyChirho::TolerantRecordProjectionPolicyChirho
    )
    .is_err());
}

#[test]
fn node_input_binding_rejects_tolerant_policy_and_whole_schema_mismatch_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let graph_hash_chirho = canonical_field_graph_hash_chirho(&graph_chirho).unwrap();
    let mut binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: graph_hash_chirho.clone(),
        guest_schema_chirho: graph_hash_chirho,
        policy_chirho: FieldGraphValidationPolicyChirho::TolerantRecordProjectionPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    assert!(validate_node_input_projection_binding_chirho(&binding_chirho).is_err());
    binding_chirho.policy_chirho = FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho;
    binding_chirho.guest_schema_chirho = hash_chirho(0xfe);
    assert!(validate_node_input_projection_binding_chirho(&binding_chirho).is_err());
}

#[test]
fn node_input_binding_parser_requires_exact_canonical_bytes_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let graph_hash_chirho = canonical_field_graph_hash_chirho(&graph_chirho).unwrap();
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: graph_hash_chirho.clone(),
        guest_schema_chirho: graph_hash_chirho,
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let canonical_chirho = String::from_utf8(
        canonical_node_input_projection_binding_bytes_chirho(&binding_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(
        parse_canonical_node_input_projection_binding_chirho(&canonical_chirho).unwrap(),
        binding_chirho
    );
    let mut value_chirho: serde_json::Value = serde_json::from_str(&canonical_chirho).unwrap();
    let object_chirho = value_chirho.as_object_mut().unwrap();
    object_chirho.insert("unknown_chirho".to_string(), serde_json::Value::Bool(true));
    assert!(parse_canonical_node_input_projection_binding_chirho(
        &serde_json::to_string(&value_chirho).unwrap()
    )
    .is_err());
    assert!(
        parse_canonical_node_input_projection_binding_chirho(&format!(" {canonical_chirho}"))
            .is_err()
    );
}

#[test]
fn nested_projection_derives_exact_closed_guest_graph_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let paths_chirho = [
        JsonFieldPathChirho::parse_chirho("/customer_chirho/id_chirho").unwrap(),
        JsonFieldPathChirho::parse_chirho("/safe_chirho").unwrap(),
    ];
    let projected_chirho =
        derive_projected_field_graph_chirho(&graph_chirho, &paths_chirho).unwrap();
    let CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } = projected_chirho.root_chirho
    else {
        unreachable!()
    };
    assert_eq!(
        fields_chirho
            .iter()
            .map(|field_chirho| field_chirho.name_chirho.as_str())
            .collect::<Vec<_>>(),
        ["customer_chirho", "safe_chirho"]
    );
    let CanonicalFieldNodeChirho::ObjectChirho {
        fields_chirho: customer_fields_chirho,
    } = &fields_chirho[0].node_chirho
    else {
        unreachable!()
    };
    assert_eq!(customer_fields_chirho.len(), 1);
    assert_eq!(customer_fields_chirho[0].name_chirho, "id_chirho");
}

#[test]
fn projection_rejects_array_traversal_and_unknown_path_chirho() {
    let graph_chirho = private_source_graph_chirho();
    assert!(derive_projected_field_graph_chirho(
        &graph_chirho,
        &[JsonFieldPathChirho::parse_chirho("/items_chirho/sku_chirho").unwrap()]
    )
    .is_err());
    assert!(derive_projected_field_graph_chirho(
        &graph_chirho,
        &[JsonFieldPathChirho::parse_chirho("/missing_chirho").unwrap()]
    )
    .is_err());
}

#[test]
fn exact_materializer_collapses_dropped_fields_and_uses_subject_coordinate_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(
        &graph_chirho,
        &["/customer_chirho/id_chirho", "/safe_chirho"],
    );
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x41; 32]).unwrap();
    let materialized_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        private_source_bytes_chirho(),
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0x42),
            port_chirho: "input_chirho",
            private_chirho: Some(PrivateCoordinateMaterialChirho {
                key_generation_chirho: "subject-key-v1-chirho",
                key_chirho: &key_chirho,
            }),
        },
    )
    .unwrap();
    assert_eq!(
        materialized_chirho.bytes_chirho,
        br#"{"customer_chirho":{"id_chirho":"c-1"},"safe_chirho":true}"#
    );
    assert!(materialized_chirho.verify_integrity_chirho());
    assert_eq!(
        materialized_chirho.source_privacy_class_chirho,
        PrivacyClassChirho::DirectChirho
    );
    assert_eq!(
        materialized_chirho.projected_privacy_class_chirho,
        PrivacyClassChirho::SafeChirho
    );
    assert!(matches!(
        materialized_chirho.coordinate_chirho,
        ProjectedInputCoordinateChirho::PrivateKeyedDigestChirho { .. }
    ));
}

#[test]
fn exact_materializer_is_stable_over_source_key_order_and_dropped_values_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(&graph_chirho, &["/safe_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x43; 32]).unwrap();
    let node_chirho = hash_chirho(0x44);
    let first_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        private_source_bytes_chirho(),
        ProjectionCoordinateContextChirho {
            node_chirho: &node_chirho,
            port_chirho: "input_chirho",
            private_chirho: Some(PrivateCoordinateMaterialChirho {
                key_generation_chirho: "subject-key-v1-chirho",
                key_chirho: &key_chirho,
            }),
        },
    )
    .unwrap();
    let changed_dropped_chirho = br#"{"amount_chirho":-9,"customer_chirho":{"email_chirho":"other@example.test","id_chirho":"other"},"items_chirho":[{"sku_chirho":"other"}],"request_id_chirho":"req-other","safe_chirho":true}"#;
    let second_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        changed_dropped_chirho,
        ProjectionCoordinateContextChirho {
            node_chirho: &node_chirho,
            port_chirho: "input_chirho",
            private_chirho: Some(PrivateCoordinateMaterialChirho {
                key_generation_chirho: "subject-key-v1-chirho",
                key_chirho: &key_chirho,
            }),
        },
    )
    .unwrap();
    assert_eq!(first_chirho.bytes_chirho, second_chirho.bytes_chirho);
    assert_eq!(
        first_chirho.coordinate_chirho,
        second_chirho.coordinate_chirho
    );
}

#[test]
fn selected_array_is_validated_and_materialized_whole_in_source_order_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(&graph_chirho, &["/items_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0xf2; 32]).unwrap();
    let source_chirho = br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":"e","id_chirho":"i"},"items_chirho":[{"sku_chirho":"second"},{"sku_chirho":"first"}],"request_id_chirho":"r","safe_chirho":true}"#;
    let materialized_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        source_chirho,
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0xf3),
            port_chirho: "input_chirho",
            private_chirho: Some(PrivateCoordinateMaterialChirho {
                key_generation_chirho: "subject-key-v1-chirho",
                key_chirho: &key_chirho,
            }),
        },
    )
    .unwrap();
    assert_eq!(
        materialized_chirho.bytes_chirho,
        br#"{"items_chirho":[{"sku_chirho":"second"},{"sku_chirho":"first"}]}"#
    );
}

#[test]
fn absent_optional_selected_field_stays_absent_without_null_materialization_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho =
        binding_for_fields_chirho(&graph_chirho, &["/customer_chirho/nickname_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0xf4; 32]).unwrap();
    let materialized_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        private_source_bytes_chirho(),
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0xf5),
            port_chirho: "input_chirho",
            private_chirho: Some(PrivateCoordinateMaterialChirho {
                key_generation_chirho: "subject-key-v1-chirho",
                key_chirho: &key_chirho,
            }),
        },
    )
    .unwrap();
    assert_eq!(
        materialized_chirho.bytes_chirho,
        br#"{"customer_chirho":{}}"#
    );
    assert!(!materialized_chirho
        .bytes_chirho
        .windows(4)
        .any(|window_chirho| window_chirho == b"null"));
}

#[test]
fn exact_materializer_rejects_missing_unknown_null_and_wrong_types_even_when_dropped_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(&graph_chirho, &["/safe_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0x45; 32]).unwrap();
    let node_chirho = hash_chirho(0x46);
    for source_chirho in [
        br#"{"customer_chirho":{"email_chirho":"e","id_chirho":"i"},"items_chirho":[],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
        br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":"e","id_chirho":"i","unknown_chirho":1},"items_chirho":[],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
        br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":null,"id_chirho":"i"},"items_chirho":[],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
        br#"{"amount_chirho":"1","customer_chirho":{"email_chirho":"e","id_chirho":"i"},"items_chirho":[],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
    ] {
        assert!(materialize_exact_node_input_chirho(
            &port_chirho,
            &binding_chirho,
            source_chirho,
            ProjectionCoordinateContextChirho {
                node_chirho: &node_chirho,
                port_chirho: "input_chirho",
                private_chirho: Some(PrivateCoordinateMaterialChirho {
                    key_generation_chirho: "subject-key-v1-chirho",
                    key_chirho: &key_chirho,
                }),
            },
        )
        .is_err());
    }
}

#[test]
fn exact_materializer_rejects_duplicate_keys_at_every_object_depth_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(&graph_chirho, &["/safe_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    let key_chirho = PrivateInputKeyChirho::try_from_bytes_chirho([0xf6; 32]).unwrap();
    let node_chirho = hash_chirho(0xf7);
    for source_chirho in [
        br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":"e","id_chirho":"i"},"items_chirho":[],"request_id_chirho":"r","request_id_chirho":"other","safe_chirho":true}"#.as_slice(),
        br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":"e","email_chirho":"other","id_chirho":"i"},"items_chirho":[],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
        br#"{"amount_chirho":1,"customer_chirho":{"email_chirho":"e","id_chirho":"i"},"items_chirho":[{"sku_chirho":"a","sku_chirho":"b"}],"request_id_chirho":"r","safe_chirho":true}"#.as_slice(),
    ] {
        let error_chirho = match materialize_exact_node_input_chirho(
            &port_chirho,
            &binding_chirho,
            source_chirho,
            ProjectionCoordinateContextChirho {
                node_chirho: &node_chirho,
                port_chirho: "input_chirho",
                private_chirho: Some(PrivateCoordinateMaterialChirho {
                    key_generation_chirho: "subject-key-v1-chirho",
                    key_chirho: &key_chirho,
                }),
            },
        ) {
            Ok(_) => panic!("duplicate object key was accepted"),
            Err(error_chirho) => error_chirho,
        };
        assert!(format!("{error_chirho:#}").contains("duplicate key"));
    }
}

#[test]
fn exact_materializer_rejects_noncanonical_or_out_of_range_integer_forms_chirho() {
    let graph_chirho = CanonicalFieldGraphChirho {
        schema_chirho: CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO.to_string(),
        root_chirho: CanonicalFieldNodeChirho::ObjectChirho {
            fields_chirho: vec![field_chirho(
                "number_chirho",
                CanonicalFieldNodeChirho::SignedIntegerChirho { bits_chirho: 8 },
                FieldRequirednessChirho::RequiredChirho,
                FieldVariabilityChirho::StableChirho,
                PrivacyClassChirho::SafeChirho,
            )],
        },
    };
    let graph_hash_chirho = canonical_field_graph_hash_chirho(&graph_chirho).unwrap();
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: graph_hash_chirho.clone(),
        guest_schema_chirho: graph_hash_chirho.clone(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: graph_hash_chirho,
        graph_chirho,
    };
    let node_chirho = hash_chirho(0x47);
    for source_chirho in [
        br#"{"number_chirho":-0}"#.as_slice(),
        br#"{"number_chirho":1e0}"#.as_slice(),
        br#"{"number_chirho":128}"#.as_slice(),
    ] {
        assert!(materialize_exact_node_input_chirho(
            &port_chirho,
            &binding_chirho,
            source_chirho,
            ProjectionCoordinateContextChirho {
                node_chirho: &node_chirho,
                port_chirho: "input_chirho",
                private_chirho: None,
            },
        )
        .is_err());
    }
}

#[test]
fn canonical_string_encoding_has_one_escape_policy_and_no_unicode_normalization_chirho() {
    let graph_chirho = public_source_graph_chirho();
    let graph_hash_chirho = canonical_field_graph_hash_chirho(&graph_chirho).unwrap();
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: graph_hash_chirho.clone(),
        guest_schema_chirho: graph_hash_chirho.clone(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: graph_hash_chirho,
        graph_chirho,
    };
    let node_chirho = hash_chirho(0x48);
    let materialized_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        br#"{"message_chirho":"a\/b\u0000\n\u00e9"}"#,
        ProjectionCoordinateContextChirho {
            node_chirho: &node_chirho,
            port_chirho: "input_chirho",
            private_chirho: None,
        },
    )
    .unwrap();
    assert_eq!(
        materialized_chirho.bytes_chirho,
        b"{\"message_chirho\":\"a/b\\u0000\\n\xc3\xa9\"}"
    );

    let decomposed_chirho = materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        "{\"message_chirho\":\"e\\u0301\"}".as_bytes(),
        ProjectionCoordinateContextChirho {
            node_chirho: &node_chirho,
            port_chirho: "input_chirho",
            private_chirho: None,
        },
    )
    .unwrap();
    assert_ne!(
        materialized_chirho.bytes_chirho,
        decomposed_chirho.bytes_chirho
    );
}

#[test]
fn private_source_requires_key_even_when_selected_projection_is_safe_chirho() {
    let graph_chirho = private_source_graph_chirho();
    let binding_chirho = binding_for_fields_chirho(&graph_chirho, &["/safe_chirho"]);
    let port_chirho = FakeMetadataPortChirho {
        hash_chirho: binding_chirho.source_schema_chirho.clone(),
        graph_chirho,
    };
    assert!(materialize_exact_node_input_chirho(
        &port_chirho,
        &binding_chirho,
        private_source_bytes_chirho(),
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0x49),
            port_chirho: "input_chirho",
            private_chirho: None,
        },
    )
    .is_err());
}

#[test]
fn metadata_port_cannot_substitute_a_different_graph_chirho() {
    let requested_graph_chirho = public_source_graph_chirho();
    let requested_hash_chirho = canonical_field_graph_hash_chirho(&requested_graph_chirho).unwrap();
    let binding_chirho = NodeInputProjectionBindingChirho {
        schema_chirho: NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO.to_string(),
        source_schema_chirho: requested_hash_chirho.clone(),
        guest_schema_chirho: requested_hash_chirho.clone(),
        policy_chirho: FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        projection_chirho: InputProjectionChirho::WholeValueChirho,
    };
    let substituting_port_chirho = FakeMetadataPortChirho {
        hash_chirho: requested_hash_chirho,
        graph_chirho: private_source_graph_chirho(),
    };
    assert!(materialize_exact_node_input_chirho(
        &substituting_port_chirho,
        &binding_chirho,
        br#"{"message_chirho":"hello"}"#,
        ProjectionCoordinateContextChirho {
            node_chirho: &hash_chirho(0x50),
            port_chirho: "input_chirho",
            private_chirho: None,
        },
    )
    .is_err());
}
