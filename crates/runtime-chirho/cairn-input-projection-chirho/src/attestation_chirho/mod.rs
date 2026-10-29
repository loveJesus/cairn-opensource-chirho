// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Canonical guest-schema attestation carried in one inert WASM custom section.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};

pub const INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO: &str = "input-schema-attestation-v1-chirho";
pub const INPUT_SCHEMA_CUSTOM_SECTION_CHIRHO: &str = "cairn-input-schema-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSchemaAttestationChirho {
    pub schema_chirho: String,
    pub projected_schema_hash_chirho: HashChirho,
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn validate_input_schema_attestation_chirho(
    attestation_chirho: &InputSchemaAttestationChirho,
) -> Result<()> {
    if attestation_chirho.schema_chirho != INPUT_SCHEMA_ATTESTATION_SCHEMA_CHIRHO {
        bail!("unsupported input-schema attestation schema");
    }
    let hash_chirho = &attestation_chirho.projected_schema_hash_chirho.0;
    if hash_chirho.len() != 64
        || !hash_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit() && !byte_chirho.is_ascii_uppercase())
    {
        bail!("projected schema hash must be a lower-case 64-hex BLAKE3 digest");
    }
    Ok(())
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn canonical_input_schema_attestation_bytes_chirho(
    attestation_chirho: &InputSchemaAttestationChirho,
) -> Result<Vec<u8>> {
    validate_input_schema_attestation_chirho(attestation_chirho)?;
    serde_json::to_vec(attestation_chirho).context("encode canonical input-schema attestation")
}

/// Workflow: `spec-chirho/workflows-chirho/projection-chirho/input-projection-design-chirho.md`.
pub fn parse_canonical_input_schema_attestation_chirho(
    bytes_chirho: &[u8],
) -> Result<InputSchemaAttestationChirho> {
    let attestation_chirho: InputSchemaAttestationChirho =
        serde_json::from_slice(bytes_chirho).context("decode input-schema attestation")?;
    validate_input_schema_attestation_chirho(&attestation_chirho)?;
    if serde_json::to_vec(&attestation_chirho)? != bytes_chirho {
        bail!("input-schema attestation has a byte-canonical mismatch");
    }
    Ok(attestation_chirho)
}

#[cfg(test)]
mod tests_chirho;
