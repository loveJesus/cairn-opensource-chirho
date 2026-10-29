// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only extraction of the canonical node-input schema attestation from a WASM module.

use anyhow::{anyhow, bail, Context, Result};
use cairn_input_projection_chirho::attestation_chirho::{
    parse_canonical_input_schema_attestation_chirho, InputSchemaAttestationChirho,
    INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO,
};
use wasmparser::{Parser, Payload};

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn read_input_schema_attestation_chirho(
    wasm_chirho: &[u8],
) -> Result<InputSchemaAttestationChirho> {
    let mut sections_chirho = Vec::new();
    for payload_chirho in Parser::new(0).parse_all(wasm_chirho) {
        let payload_chirho = payload_chirho
            .map_err(|error_chirho| anyhow!("parse guest for input attestation: {error_chirho}"))?;
        if let Payload::CustomSection(section_chirho) = payload_chirho {
            if section_chirho.name() == INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO {
                sections_chirho.push(section_chirho.data());
            }
        }
    }
    if sections_chirho.len() != 1 {
        bail!(
            "guest must carry exactly one {INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO} custom section; found {}",
            sections_chirho.len()
        );
    }
    parse_canonical_input_schema_attestation_chirho(sections_chirho[0])
        .context("validate guest input-schema custom section")
}

#[cfg(test)]
mod tests_chirho;
