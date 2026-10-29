// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Inert projection-aware authoring checks. Existing manifest emission remains v1-only.

use anyhow::{bail, Context, Result};
use cairn_input_projection_chirho::{
    attestation_chirho::InputSchemaAttestationChirho,
    contract_chirho::{
        validate_node_input_projection_binding_chirho, InputProjectionChirho,
        NodeInputProjectionBindingChirho,
    },
    field_graph_chirho::{
        canonical_field_graph_hash_chirho, CanonicalFieldGraphChirho,
        ProjectionFieldMetadataPortChirho,
    },
    materialize_chirho::derive_projected_field_graph_chirho,
};
use cairn_model_app_chirho::{validate_app_source_manifest_v2_chirho, AppSourceManifestV2Chirho};
use cairn_wasmtime_runner_chirho::input_attestation_chirho::read_input_schema_attestation_chirho;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckedInputProjectionChirho {
    pub binding_chirho: NodeInputProjectionBindingChirho,
    pub projected_graph_chirho: CanonicalFieldGraphChirho,
    pub attestation_chirho: InputSchemaAttestationChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionNodeClassChirho {
    PureWasmChirho,
    EffectChirho,
    NativeChirho,
    ScalarChirho,
    BuiltinPhiChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectionInputShapeChirho {
    StructuredJsonChirho,
    OpaqueOrScalarChirho,
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn check_inert_input_projection_chirho<P: ProjectionFieldMetadataPortChirho + ?Sized>(
    metadata_chirho: &P,
    binding_chirho: &NodeInputProjectionBindingChirho,
    guest_wasm_chirho: &[u8],
    node_class_chirho: ProjectionNodeClassChirho,
    input_shape_chirho: ProjectionInputShapeChirho,
) -> Result<CheckedInputProjectionChirho> {
    validate_node_input_projection_binding_chirho(binding_chirho)?;
    match (
        node_class_chirho,
        input_shape_chirho,
        &binding_chirho.projection_chirho,
    ) {
        (
            ProjectionNodeClassChirho::PureWasmChirho,
            ProjectionInputShapeChirho::StructuredJsonChirho,
            InputProjectionChirho::JsonFieldsChirho { .. },
        )
        | (
            ProjectionNodeClassChirho::PureWasmChirho,
            ProjectionInputShapeChirho::OpaqueOrScalarChirho,
            InputProjectionChirho::WholeValueChirho,
        ) => {}
        (ProjectionNodeClassChirho::PureWasmChirho, _, _) => {
            bail!("pure structured inputs require field projection; opaque inputs require whole-value")
        }
        (_, _, InputProjectionChirho::WholeValueChirho) => {}
        (_, _, InputProjectionChirho::JsonFieldsChirho { .. }) => {
            bail!("effect, native, scalar, and builtin-phi inputs require whole-value projection")
        }
    }
    let source_graph_chirho = metadata_chirho
        .verified_field_graph_chirho(&binding_chirho.source_schema_chirho)
        .context("load verified source field graph for tree-build")?;
    if canonical_field_graph_hash_chirho(&source_graph_chirho)?
        != binding_chirho.source_schema_chirho
    {
        bail!("tree-build metadata returned a source graph outside its content address");
    }
    let projected_graph_chirho = match &binding_chirho.projection_chirho {
        InputProjectionChirho::WholeValueChirho => source_graph_chirho,
        InputProjectionChirho::JsonFieldsChirho {
            consumed_fields_chirho,
        } => derive_projected_field_graph_chirho(&source_graph_chirho, consumed_fields_chirho)?,
    };
    if canonical_field_graph_hash_chirho(&projected_graph_chirho)?
        != binding_chirho.guest_schema_chirho
    {
        bail!("tree-build derived schema does not equal the guest schema binding");
    }

    let attestation_chirho = read_input_schema_attestation_chirho(guest_wasm_chirho)?;
    if attestation_chirho.projected_schema_hash_chirho != binding_chirho.guest_schema_chirho {
        bail!("guest input-schema attestation does not equal the derived schema");
    }
    Ok(CheckedInputProjectionChirho {
        binding_chirho: binding_chirho.clone(),
        projected_graph_chirho,
        attestation_chirho,
    })
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn check_inert_source_manifest_v2_chirho(
    manifest_chirho: &AppSourceManifestV2Chirho,
) -> Result<()> {
    validate_app_source_manifest_v2_chirho(manifest_chirho)
}

#[cfg(test)]
mod tests_chirho;
