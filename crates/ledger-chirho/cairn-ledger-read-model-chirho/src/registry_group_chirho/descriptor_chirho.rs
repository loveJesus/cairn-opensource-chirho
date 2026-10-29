// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Content-addressed projection descriptor and source/privacy validation.

use anyhow::{bail, Context, Result};
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_model_privacy_chirho::{join_privacy_class_chirho, PrivacyClassChirho};
use serde::{Deserialize, Serialize};

pub const PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO: &str = "ledger-projection-descriptor-v1-chirho";
pub const MAX_PROJECTION_NAME_BYTES_CHIRHO: usize = 128;
pub const MAX_PROJECTION_SOURCE_FAMILIES_CHIRHO: usize = 64;
pub const MAX_PROJECTION_SOURCE_FAMILY_ID_BYTES_CHIRHO: usize = 128;

const PROJECTION_DESCRIPTOR_DIGEST_DOMAIN_CHIRHO: &[u8] =
    b"cairn-ledger-projection-descriptor-v1-chirho";
const PROJECTION_PRIVACY_EVIDENCE_DOMAIN_CHIRHO: &[u8] =
    b"cairn-ledger-projection-privacy-evidence-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionSourceBindingChirho {
    pub family_id_chirho: String,
    pub source_schema_ref_chirho: DigestChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionReadPolicyChirho {
    #[serde(rename = "refuse-when-stale-chirho")]
    RefuseWhenStaleChirho,
    #[serde(rename = "serve-degraded-with-lag-chirho")]
    ServeDegradedWithLagChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StalenessContractChirho {
    pub max_owner_hlc_lag_ms_chirho: u64,
    pub read_policy_chirho: ProjectionReadPolicyChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionCostClassChirho {
    #[serde(rename = "standing-write-rate-chirho")]
    StandingWriteRateChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProjectionRebuildLawChirho {
    #[serde(rename = "drop-and-refold-chirho")]
    DropAndRefoldChirho,
}

/// Immutable projection contract. Identity is the domain-separated digest of its canonical bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionDescriptorChirho {
    pub schema_chirho: String,
    pub name_chirho: String,
    pub source_families_chirho: Vec<ProjectionSourceBindingChirho>,
    pub fold_fn_ref_chirho: DigestChirho,
    pub staleness_contract_chirho: StalenessContractChirho,
    pub cost_class_chirho: ProjectionCostClassChirho,
    pub privacy_floor_chirho: PrivacyClassChirho,
    pub privacy_floor_evidence_ref_chirho: DigestChirho,
    pub rebuild_law_chirho: ProjectionRebuildLawChirho,
}

/// Source-registry evidence after the owning adapter has verified its signature and content address.
///
/// This DTO is not an authority token: the adapter remains responsible for obtaining it from the
/// signed registry and proving that `privacy_floor_chirho` exactly equals the floor attested by
/// `privacy_evidence_ref_chirho`. The pure validator checks exact coverage, privacy domination, and
/// the derived evidence coordinate without gaining any registry read capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjectionSourceChirho {
    pub binding_chirho: ProjectionSourceBindingChirho,
    pub privacy_floor_chirho: PrivacyClassChirho,
    pub privacy_evidence_ref_chirho: DigestChirho,
}

/// A descriptor whose canonical identity, exact source set, and privacy floor have been checked.
/// Fields are private so consumers cannot pair one descriptor digest with another staleness policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProjectionDescriptorChirho {
    descriptor_chirho: ProjectionDescriptorChirho,
    digest_chirho: DigestChirho,
}

impl VerifiedProjectionDescriptorChirho {
    pub fn descriptor_chirho(&self) -> &ProjectionDescriptorChirho {
        &self.descriptor_chirho
    }

    pub fn digest_chirho(&self) -> &DigestChirho {
        &self.digest_chirho
    }
}

#[derive(Deserialize)]
struct ProjectionDescriptorSchemaProbeChirho {
    schema_chirho: String,
}

pub fn validate_projection_descriptor_chirho(
    descriptor_chirho: &ProjectionDescriptorChirho,
) -> Result<()> {
    if descriptor_chirho.schema_chirho != PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO {
        bail!("unsupported projection descriptor schema");
    }
    validate_bounded_text_chirho(
        "projection name",
        &descriptor_chirho.name_chirho,
        MAX_PROJECTION_NAME_BYTES_CHIRHO,
    )?;
    validate_source_bindings_chirho(&descriptor_chirho.source_families_chirho)?;
    validate_digest_chirho("fold function", &descriptor_chirho.fold_fn_ref_chirho)?;
    validate_digest_chirho(
        "privacy-floor evidence",
        &descriptor_chirho.privacy_floor_evidence_ref_chirho,
    )?;
    Ok(())
}

pub fn projection_descriptor_bytes_chirho(
    descriptor_chirho: &ProjectionDescriptorChirho,
) -> Result<Vec<u8>> {
    validate_projection_descriptor_chirho(descriptor_chirho)?;
    serde_json::to_vec(descriptor_chirho).context("encode canonical projection descriptor")
}

pub fn parse_canonical_projection_descriptor_chirho(
    bytes_chirho: &[u8],
) -> Result<ProjectionDescriptorChirho> {
    let probe_chirho: ProjectionDescriptorSchemaProbeChirho =
        serde_json::from_slice(bytes_chirho).context("probe projection descriptor schema")?;
    if probe_chirho.schema_chirho != PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO {
        bail!("unsupported projection descriptor schema");
    }
    let descriptor_chirho: ProjectionDescriptorChirho =
        serde_json::from_slice(bytes_chirho).context("decode projection descriptor")?;
    validate_projection_descriptor_chirho(&descriptor_chirho)?;
    let canonical_chirho = serde_json::to_vec(&descriptor_chirho)?;
    if canonical_chirho != bytes_chirho {
        bail!("projection descriptor has a byte-canonical mismatch");
    }
    Ok(descriptor_chirho)
}

pub fn projection_descriptor_digest_chirho(
    descriptor_chirho: &ProjectionDescriptorChirho,
) -> Result<DigestChirho> {
    let bytes_chirho = projection_descriptor_bytes_chirho(descriptor_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new();
    frame_field_chirho(
        &mut hasher_chirho,
        PROJECTION_DESCRIPTOR_DIGEST_DOMAIN_CHIRHO,
    );
    frame_field_chirho(&mut hasher_chirho, &bytes_chirho);
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

/// Derive the evidence coordinate over a strictly ordered, already verified source-registry view.
pub fn derive_projection_privacy_evidence_ref_chirho(
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
) -> Result<DigestChirho> {
    if verified_sources_chirho.is_empty()
        || verified_sources_chirho.len() > MAX_PROJECTION_SOURCE_FAMILIES_CHIRHO
    {
        bail!("verified projection source set must be nonempty and bounded");
    }
    let bindings_chirho = verified_sources_chirho
        .iter()
        .map(|source_chirho| source_chirho.binding_chirho.clone())
        .collect::<Vec<_>>();
    validate_source_bindings_chirho(&bindings_chirho)?;

    let mut hasher_chirho = blake3::Hasher::new();
    frame_field_chirho(
        &mut hasher_chirho,
        PROJECTION_PRIVACY_EVIDENCE_DOMAIN_CHIRHO,
    );
    for source_chirho in verified_sources_chirho {
        validate_digest_chirho(
            "source privacy evidence",
            &source_chirho.privacy_evidence_ref_chirho,
        )?;
        frame_field_chirho(
            &mut hasher_chirho,
            source_chirho.binding_chirho.family_id_chirho.as_bytes(),
        );
        frame_field_chirho(
            &mut hasher_chirho,
            source_chirho
                .binding_chirho
                .source_schema_ref_chirho
                .0
                .as_bytes(),
        );
        frame_field_chirho(
            &mut hasher_chirho,
            privacy_class_wire_label_chirho(source_chirho.privacy_floor_chirho).as_bytes(),
        );
        frame_field_chirho(
            &mut hasher_chirho,
            source_chirho.privacy_evidence_ref_chirho.0.as_bytes(),
        );
    }
    Ok(DigestChirho(hasher_chirho.finalize().to_hex().to_string()))
}

/// Implements the descriptor/source/privacy gate documented in
/// `spec-chirho/workflows-chirho/projection-chirho/cf4-read-model-foundation-chirho.md`.
pub fn validate_projection_descriptor_against_verified_sources_chirho(
    descriptor_chirho: &ProjectionDescriptorChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
) -> Result<()> {
    validate_projection_descriptor_chirho(descriptor_chirho)?;
    if descriptor_chirho.source_families_chirho.len() != verified_sources_chirho.len() {
        bail!("verified source registry does not exactly cover descriptor sources");
    }
    for (declared_chirho, verified_chirho) in descriptor_chirho
        .source_families_chirho
        .iter()
        .zip(verified_sources_chirho)
    {
        if declared_chirho != &verified_chirho.binding_chirho {
            bail!("verified source registry binding diverges from descriptor");
        }
    }

    let required_floor_chirho = verified_sources_chirho
        .iter()
        .map(|source_chirho| source_chirho.privacy_floor_chirho)
        .fold(PrivacyClassChirho::SafeChirho, join_privacy_class_chirho);
    if descriptor_chirho.privacy_floor_chirho < required_floor_chirho {
        bail!("projection privacy floor is lower than a verified source floor");
    }
    let expected_evidence_chirho =
        derive_projection_privacy_evidence_ref_chirho(verified_sources_chirho)?;
    if descriptor_chirho.privacy_floor_evidence_ref_chirho != expected_evidence_chirho {
        bail!("projection privacy-floor evidence does not bind verified sources");
    }
    Ok(())
}

/// Construct the private-field descriptor input used by follower classification.
pub fn verify_projection_descriptor_chirho(
    descriptor_chirho: ProjectionDescriptorChirho,
    verified_sources_chirho: &[VerifiedProjectionSourceChirho],
) -> Result<VerifiedProjectionDescriptorChirho> {
    validate_projection_descriptor_against_verified_sources_chirho(
        &descriptor_chirho,
        verified_sources_chirho,
    )?;
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho)?;
    Ok(VerifiedProjectionDescriptorChirho {
        descriptor_chirho,
        digest_chirho,
    })
}

fn validate_source_bindings_chirho(
    bindings_chirho: &[ProjectionSourceBindingChirho],
) -> Result<()> {
    if bindings_chirho.is_empty() || bindings_chirho.len() > MAX_PROJECTION_SOURCE_FAMILIES_CHIRHO {
        bail!("projection source-family set must be nonempty and bounded");
    }
    for binding_chirho in bindings_chirho {
        validate_bounded_text_chirho(
            "source-family id",
            &binding_chirho.family_id_chirho,
            MAX_PROJECTION_SOURCE_FAMILY_ID_BYTES_CHIRHO,
        )?;
        validate_digest_chirho("source schema", &binding_chirho.source_schema_ref_chirho)?;
    }
    for pair_chirho in bindings_chirho.windows(2) {
        if pair_chirho[0].family_id_chirho.as_bytes() >= pair_chirho[1].family_id_chirho.as_bytes()
        {
            bail!("projection source families must be unique and in strict UTF-8 byte order");
        }
    }
    Ok(())
}

fn validate_bounded_text_chirho(
    label_chirho: &str,
    value_chirho: &str,
    max_bytes_chirho: usize,
) -> Result<()> {
    if value_chirho.is_empty() || value_chirho.len() > max_bytes_chirho {
        bail!("{label_chirho} must be nonempty and bounded");
    }
    Ok(())
}

pub(crate) fn validate_digest_chirho(
    label_chirho: &str,
    digest_chirho: &DigestChirho,
) -> Result<()> {
    let bytes_chirho = digest_chirho.0.as_bytes();
    if bytes_chirho.len() != 64
        || !bytes_chirho
            .iter()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(byte_chirho))
    {
        bail!("{label_chirho} must be a lowercase 64-character BLAKE3 digest");
    }
    Ok(())
}

fn privacy_class_wire_label_chirho(class_chirho: PrivacyClassChirho) -> &'static str {
    match class_chirho {
        PrivacyClassChirho::SafeChirho => "safe-chirho",
        PrivacyClassChirho::AnalyticalChirho => "analytical-chirho",
        PrivacyClassChirho::QuasiChirho => "quasi-chirho",
        PrivacyClassChirho::DirectChirho => "direct-chirho",
    }
}

fn frame_field_chirho(hasher_chirho: &mut blake3::Hasher, bytes_chirho: &[u8]) {
    let len_chirho = u64::try_from(bytes_chirho.len()).expect("in-memory field length fits u64");
    hasher_chirho.update(&len_chirho.to_le_bytes());
    hasher_chirho.update(bytes_chirho);
}

#[cfg(test)]
mod wire_label_tests_chirho {
    use super::*;

    #[test]
    fn privacy_evidence_labels_match_the_canonical_serde_wire_chirho() {
        for class_chirho in [
            PrivacyClassChirho::SafeChirho,
            PrivacyClassChirho::AnalyticalChirho,
            PrivacyClassChirho::QuasiChirho,
            PrivacyClassChirho::DirectChirho,
        ] {
            assert_eq!(
                serde_json::to_string(&class_chirho).unwrap(),
                format!("\"{}\"", privacy_class_wire_label_chirho(class_chirho))
            );
        }
    }
}
