// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The packet-0 canonical recursive field graph: one model, two binding policies.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
pub use cairn_model_privacy_chirho::{join_privacy_class_chirho, PrivacyClassChirho};
use serde::{Deserialize, Serialize};

pub const CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO: &str = "canonical-field-graph-v1-chirho";
pub const MAX_FIELD_GRAPH_DEPTH_CHIRHO: usize = 64;
pub const MAX_FIELD_GRAPH_FIELDS_CHIRHO: usize = 4_096;
pub const MAX_FIELD_NAME_BYTES_CHIRHO: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFieldGraphChirho {
    pub schema_chirho: String,
    pub root_chirho: CanonicalFieldNodeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum CanonicalFieldNodeChirho {
    #[serde(rename = "object-chirho")]
    ObjectChirho {
        fields_chirho: Vec<CanonicalFieldChirho>,
    },
    #[serde(rename = "array-chirho")]
    ArrayChirho {
        element_chirho: Box<CanonicalFieldNodeChirho>,
    },
    #[serde(rename = "boolean-chirho")]
    BooleanChirho,
    #[serde(rename = "string-chirho")]
    StringChirho,
    #[serde(rename = "signed-integer-chirho")]
    SignedIntegerChirho { bits_chirho: u8 },
    #[serde(rename = "unsigned-integer-chirho")]
    UnsignedIntegerChirho { bits_chirho: u8 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFieldChirho {
    pub name_chirho: String,
    pub node_chirho: CanonicalFieldNodeChirho,
    pub requiredness_chirho: FieldRequirednessChirho,
    pub variability_chirho: FieldVariabilityChirho,
    pub privacy_class_chirho: PrivacyClassChirho,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generalization_chirho: Option<FieldGeneralizationChirho>,
    pub indexed_chirho: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldRequirednessChirho {
    #[serde(rename = "required-chirho")]
    RequiredChirho,
    #[serde(rename = "optional-chirho")]
    OptionalChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldVariabilityChirho {
    #[serde(rename = "stable-chirho")]
    StableChirho,
    #[serde(rename = "invocation-varying-chirho")]
    InvocationVaryingChirho,
    #[serde(rename = "ambient-chirho")]
    AmbientChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum FieldGeneralizationChirho {
    #[serde(rename = "numeric-band-chirho")]
    NumericBandChirho { width_chirho: u64 },
    #[serde(rename = "string-prefix-chirho")]
    StringPrefixChirho { chars_chirho: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldGraphValidationPolicyChirho {
    #[serde(rename = "tolerant-record-projection-policy-chirho")]
    TolerantRecordProjectionPolicyChirho,
    #[serde(rename = "exact-node-input-policy-chirho")]
    ExactNodeInputPolicyChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldGraphBindingSiteChirho {
    RecordProjectionChirho,
    NodeInputChirho,
}

/// The authority boundary supplies a graph only after resolving and verifying its content address.
/// Packet 2 intentionally provides no production implementation.
pub trait ProjectionFieldMetadataPortChirho {
    fn verified_field_graph_chirho(
        &self,
        schema_hash_chirho: &HashChirho,
    ) -> Result<CanonicalFieldGraphChirho>;
}

pub fn validate_field_graph_binding_policy_chirho(
    site_chirho: FieldGraphBindingSiteChirho,
    policy_chirho: FieldGraphValidationPolicyChirho,
) -> Result<()> {
    match (site_chirho, policy_chirho) {
        (
            FieldGraphBindingSiteChirho::RecordProjectionChirho,
            FieldGraphValidationPolicyChirho::TolerantRecordProjectionPolicyChirho,
        )
        | (
            FieldGraphBindingSiteChirho::NodeInputChirho,
            FieldGraphValidationPolicyChirho::ExactNodeInputPolicyChirho,
        ) => Ok(()),
        (FieldGraphBindingSiteChirho::RecordProjectionChirho, _) => {
            bail!("record projection binding requires the tolerant record policy")
        }
        (FieldGraphBindingSiteChirho::NodeInputChirho, _) => {
            bail!("node input binding requires the exact node-input policy")
        }
    }
}

pub fn validate_canonical_field_graph_chirho(
    graph_chirho: &CanonicalFieldGraphChirho,
) -> Result<()> {
    if graph_chirho.schema_chirho != CANONICAL_FIELD_GRAPH_SCHEMA_CHIRHO {
        bail!("unsupported canonical field-graph schema");
    }
    if !matches!(
        &graph_chirho.root_chirho,
        CanonicalFieldNodeChirho::ObjectChirho { .. }
    ) {
        bail!("canonical field-graph root must be an object");
    }
    let mut field_count_chirho = 0_usize;
    validate_node_chirho(&graph_chirho.root_chirho, 1, &mut field_count_chirho)
}

pub fn canonical_field_graph_bytes_chirho(
    graph_chirho: &CanonicalFieldGraphChirho,
) -> Result<Vec<u8>> {
    validate_canonical_field_graph_chirho(graph_chirho)?;
    serde_json::to_vec(graph_chirho).context("encode canonical field graph")
}

pub fn canonical_field_graph_hash_chirho(
    graph_chirho: &CanonicalFieldGraphChirho,
) -> Result<HashChirho> {
    let bytes_chirho = canonical_field_graph_bytes_chirho(graph_chirho)?;
    Ok(HashChirho(blake3::hash(&bytes_chirho).to_hex().to_string()))
}

pub fn parse_canonical_field_graph_chirho(text_chirho: &str) -> Result<CanonicalFieldGraphChirho> {
    let graph_chirho: CanonicalFieldGraphChirho =
        serde_json::from_str(text_chirho).context("decode canonical field graph")?;
    validate_canonical_field_graph_chirho(&graph_chirho)?;
    let canonical_chirho = serde_json::to_string(&graph_chirho)?;
    if canonical_chirho != text_chirho {
        bail!("canonical field graph has a byte-canonical mismatch");
    }
    Ok(graph_chirho)
}

pub fn field_graph_privacy_class_chirho(
    graph_chirho: &CanonicalFieldGraphChirho,
) -> Result<PrivacyClassChirho> {
    validate_canonical_field_graph_chirho(graph_chirho)?;
    Ok(node_privacy_class_chirho(&graph_chirho.root_chirho))
}

fn validate_node_chirho(
    node_chirho: &CanonicalFieldNodeChirho,
    depth_chirho: usize,
    field_count_chirho: &mut usize,
) -> Result<()> {
    if depth_chirho > MAX_FIELD_GRAPH_DEPTH_CHIRHO {
        bail!("canonical field graph exceeds the depth limit");
    }
    match node_chirho {
        CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } => {
            for pair_chirho in fields_chirho.windows(2) {
                if pair_chirho[0].name_chirho.as_bytes() >= pair_chirho[1].name_chirho.as_bytes() {
                    bail!("object fields must be unique and in strict UTF-8 byte order");
                }
            }
            for field_chirho in fields_chirho {
                *field_count_chirho += 1;
                if *field_count_chirho > MAX_FIELD_GRAPH_FIELDS_CHIRHO {
                    bail!("canonical field graph exceeds the field-count limit");
                }
                validate_field_chirho(field_chirho, depth_chirho + 1, field_count_chirho)?;
            }
        }
        CanonicalFieldNodeChirho::ArrayChirho { element_chirho } => {
            validate_node_chirho(element_chirho, depth_chirho + 1, field_count_chirho)?;
        }
        CanonicalFieldNodeChirho::SignedIntegerChirho { bits_chirho }
        | CanonicalFieldNodeChirho::UnsignedIntegerChirho { bits_chirho } => {
            if !matches!(*bits_chirho, 8 | 16 | 32 | 64) {
                bail!("integer bit width must be one of 8, 16, 32, or 64");
            }
        }
        CanonicalFieldNodeChirho::BooleanChirho | CanonicalFieldNodeChirho::StringChirho => {}
    }
    Ok(())
}

fn validate_field_chirho(
    field_chirho: &CanonicalFieldChirho,
    depth_chirho: usize,
    field_count_chirho: &mut usize,
) -> Result<()> {
    if field_chirho.name_chirho.is_empty()
        || field_chirho.name_chirho.len() > MAX_FIELD_NAME_BYTES_CHIRHO
    {
        bail!("canonical field name must be nonempty and bounded");
    }
    if field_chirho.name_chirho.chars().any(char::is_control) {
        bail!("canonical field name must not contain control characters");
    }
    if let Some(generalization_chirho) = &field_chirho.generalization_chirho {
        if field_chirho.privacy_class_chirho != PrivacyClassChirho::QuasiChirho {
            bail!("field generalization is valid only for a QuasiChirho field");
        }
        match (generalization_chirho, &field_chirho.node_chirho) {
            (
                FieldGeneralizationChirho::NumericBandChirho { width_chirho },
                CanonicalFieldNodeChirho::SignedIntegerChirho { .. }
                | CanonicalFieldNodeChirho::UnsignedIntegerChirho { .. },
            ) if *width_chirho > 0 => {}
            (
                FieldGeneralizationChirho::StringPrefixChirho { chars_chirho },
                CanonicalFieldNodeChirho::StringChirho,
            ) if *chars_chirho > 0 => {}
            _ => bail!("field generalization does not match its exact field type"),
        }
    }
    validate_node_chirho(&field_chirho.node_chirho, depth_chirho, field_count_chirho)
}

fn node_privacy_class_chirho(node_chirho: &CanonicalFieldNodeChirho) -> PrivacyClassChirho {
    match node_chirho {
        CanonicalFieldNodeChirho::ObjectChirho { fields_chirho } => fields_chirho.iter().fold(
            PrivacyClassChirho::SafeChirho,
            |joined_chirho, field_chirho| {
                join_privacy_class_chirho(
                    join_privacy_class_chirho(joined_chirho, field_chirho.privacy_class_chirho),
                    node_privacy_class_chirho(&field_chirho.node_chirho),
                )
            },
        ),
        CanonicalFieldNodeChirho::ArrayChirho { element_chirho } => {
            node_privacy_class_chirho(element_chirho)
        }
        CanonicalFieldNodeChirho::BooleanChirho
        | CanonicalFieldNodeChirho::StringChirho
        | CanonicalFieldNodeChirho::SignedIntegerChirho { .. }
        | CanonicalFieldNodeChirho::UnsignedIntegerChirho { .. } => PrivacyClassChirho::SafeChirho,
    }
}
