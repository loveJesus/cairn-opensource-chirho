// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Standalone packet-2 node-input projection binding. Live node DTOs remain unchanged.

use crate::field_graph_chirho::{
    validate_field_graph_binding_policy_chirho, FieldGraphBindingSiteChirho,
    FieldGraphValidationPolicyChirho,
};
use crate::path_chirho::{validate_consumed_fields_chirho, JsonFieldPathChirho};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

pub const NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO: &str =
    "node-input-projection-binding-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInputProjectionBindingChirho {
    pub schema_chirho: String,
    pub source_schema_chirho: HashChirho,
    pub guest_schema_chirho: HashChirho,
    pub policy_chirho: FieldGraphValidationPolicyChirho,
    pub projection_chirho: InputProjectionChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode_chirho", deny_unknown_fields)]
pub enum InputProjectionChirho {
    #[serde(rename = "whole-value-chirho")]
    WholeValueChirho,
    #[serde(rename = "json-fields-chirho")]
    JsonFieldsChirho {
        consumed_fields_chirho: Vec<JsonFieldPathChirho>,
    },
}

pub fn validate_node_input_projection_binding_chirho(
    binding_chirho: &NodeInputProjectionBindingChirho,
) -> Result<()> {
    if binding_chirho.schema_chirho != NODE_INPUT_PROJECTION_BINDING_SCHEMA_CHIRHO {
        bail!("unsupported node-input projection binding schema");
    }
    validate_hash_chirho(&binding_chirho.source_schema_chirho, "source schema")?;
    validate_hash_chirho(&binding_chirho.guest_schema_chirho, "guest schema")?;
    validate_field_graph_binding_policy_chirho(
        FieldGraphBindingSiteChirho::NodeInputChirho,
        binding_chirho.policy_chirho,
    )?;
    match &binding_chirho.projection_chirho {
        InputProjectionChirho::WholeValueChirho => {
            if binding_chirho.source_schema_chirho != binding_chirho.guest_schema_chirho {
                bail!("whole-value projection requires identical source and guest schemas");
            }
        }
        InputProjectionChirho::JsonFieldsChirho {
            consumed_fields_chirho,
        } => validate_consumed_fields_chirho(consumed_fields_chirho)?,
    }
    Ok(())
}

pub fn canonical_node_input_projection_binding_bytes_chirho(
    binding_chirho: &NodeInputProjectionBindingChirho,
) -> Result<Vec<u8>> {
    validate_node_input_projection_binding_chirho(binding_chirho)?;
    serde_json::to_vec(binding_chirho).context("encode canonical node-input projection binding")
}

pub fn parse_canonical_node_input_projection_binding_chirho(
    text_chirho: &str,
) -> Result<NodeInputProjectionBindingChirho> {
    let binding_chirho: NodeInputProjectionBindingChirho =
        serde_json::from_str(text_chirho).context("decode node-input projection binding")?;
    validate_node_input_projection_binding_chirho(&binding_chirho)?;
    if serde_json::to_string(&binding_chirho)? != text_chirho {
        bail!("node-input projection binding has a byte-canonical mismatch");
    }
    Ok(binding_chirho)
}

pub fn node_input_projection_binding_hash_chirho(
    binding_chirho: &NodeInputProjectionBindingChirho,
) -> Result<HashChirho> {
    let bytes_chirho = canonical_node_input_projection_binding_bytes_chirho(binding_chirho)?;
    Ok(HashChirho(blake3::hash(&bytes_chirho).to_hex().to_string()))
}

fn validate_hash_chirho(hash_chirho: &HashChirho, label_chirho: &str) -> Result<()> {
    if hash_chirho.0.len() != 64
        || !hash_chirho
            .0
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("{label_chirho} must be a lower-case 64-hex BLAKE3 digest");
    }
    Ok(())
}
