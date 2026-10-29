// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The registry wire: ONE canonical byte encoding per record, sign-then-attach, and the derived
//! policy ref. J0a discipline (these records parameterize money law — the wire rigor is the money
//! bar): strict typed parse + exact byte reserialization, so one logical record has exactly one
//! content identity and any malleation (reorder, duplicate, unknown field, whitespace, trailing
//! bytes) is refused at parse.

use crate::record_chirho::{
    KindPolicyBodyChirho, KindRegistryRecordChirho, KIND_REGISTRY_CHAIN_DOMAIN_CHIRHO,
    KIND_REGISTRY_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_model_chirho::ids_chirho::{AssetKindRefChirho, DigestChirho};

/// Why registry wire bytes were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryWireErrorChirho {
    /// Malformed JSON, unknown/duplicate/missing fields, wrong types, or a wrong schema tag.
    MalformedChirho { detail_chirho: String },
    /// Typed parse succeeded but exact canonical reserialization differs byte-for-byte.
    NonCanonicalBytesChirho,
    /// Serialization failed before canonical bytes could be emitted.
    SerializeChirho { detail_chirho: String },
}

impl std::fmt::Display for RegistryWireErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "malformed registry record: {detail_chirho}"
                )
            }
            Self::NonCanonicalBytesChirho => {
                write!(formatter_chirho, "registry record bytes are not canonical")
            }
            Self::SerializeChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "serialize registry record: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for RegistryWireErrorChirho {}

/// Emit the ONE canonical line (no trailing LF) for a record.
pub fn canonical_registry_line_chirho(
    record_chirho: &KindRegistryRecordChirho,
) -> Result<String, RegistryWireErrorChirho> {
    serde_json::to_string(record_chirho).map_err(|error_chirho| {
        RegistryWireErrorChirho::SerializeChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

/// Strict typed parse + exact reserialize-byte-equality + schema-tag check.
pub fn parse_canonical_registry_line_chirho(
    line_chirho: &str,
) -> Result<KindRegistryRecordChirho, RegistryWireErrorChirho> {
    let record_chirho: KindRegistryRecordChirho =
        serde_json::from_str(line_chirho).map_err(|error_chirho| {
            RegistryWireErrorChirho::MalformedChirho {
                detail_chirho: error_chirho.to_string(),
            }
        })?;
    if record_chirho.schema_chirho != KIND_REGISTRY_SCHEMA_V1_CHIRHO {
        return Err(RegistryWireErrorChirho::MalformedChirho {
            detail_chirho: format!(
                "unknown registry schema tag {}",
                record_chirho.schema_chirho
            ),
        });
    }
    let reserialized_chirho = canonical_registry_line_chirho(&record_chirho)?;
    if reserialized_chirho != line_chirho {
        return Err(RegistryWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(record_chirho)
}

/// The ISSUER's signed content: the canonical record with BOTH signature fields emptied. The
/// issuer authorizes the operation itself, independent of which registry root notarizes it.
pub fn issuer_signed_content_chirho(
    record_chirho: &KindRegistryRecordChirho,
) -> Result<String, RegistryWireErrorChirho> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.issuer_sig_chirho = String::new();
    unsigned_chirho.registry_sig_chirho = String::new();
    canonical_registry_line_chirho(&unsigned_chirho)
}

/// The REGISTRY root's signed content: the canonical record with the issuer signature ATTACHED and
/// only the registry signature emptied (sign-then-attach — the root notarizes the issuer-signed
/// operation, so neither signature can be swapped independently).
pub fn registry_signed_content_chirho(
    record_chirho: &KindRegistryRecordChirho,
) -> Result<String, RegistryWireErrorChirho> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.registry_sig_chirho = String::new();
    canonical_registry_line_chirho(&unsigned_chirho)
}

/// The stored-line digest — the chain coordinate `prev_chirho` binds.
pub fn stored_registry_line_digest_chirho(line_chirho: &str) -> DigestChirho {
    DigestChirho(blake3::hash(line_chirho.as_bytes()).to_hex().to_string())
}

/// Record 0's `prev` anchor: the domain-separated digest of the registry identity, so two
/// registries can never splice each other's chains.
pub fn chain_anchor_chirho(registry_id_chirho: &str) -> DigestChirho {
    let mut hasher_chirho = blake3::Hasher::new();
    hasher_chirho.update(KIND_REGISTRY_CHAIN_DOMAIN_CHIRHO.as_bytes());
    hasher_chirho.update(b":");
    hasher_chirho.update(registry_id_chirho.as_bytes());
    DigestChirho(hasher_chirho.finalize().to_hex().to_string())
}

/// Derive the IMMUTABLE kind-policy ref: the blake3 digest of the policy body's canonical bytes.
/// This is the `AssetKindRefChirho` money legs carry forever (R5b) — content-addressed, so the ref
/// can never drift from the policy it names.
pub fn derive_policy_ref_chirho(
    policy_chirho: &KindPolicyBodyChirho,
) -> Result<AssetKindRefChirho, RegistryWireErrorChirho> {
    let canonical_chirho = serde_json::to_string(policy_chirho).map_err(|error_chirho| {
        RegistryWireErrorChirho::SerializeChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })?;
    Ok(AssetKindRefChirho(DigestChirho(
        blake3::hash(canonical_chirho.as_bytes())
            .to_hex()
            .to_string(),
    )))
}
