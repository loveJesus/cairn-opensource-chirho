// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The custody non-equivalence predicate (coordinator ruling 1): two typed custody-evidence
//! attestations, each authenticating a custody-DOMAIN identity (device/storage/restore path, never a
//! human identity) for one dedicated authority key, verified against the externally pinned custody
//! authority. Missing, unverifiable, self-selected, wrong-subject, or same-domain evidence refuses.
//!
//! Residual, stated honestly (design section 8): two domains under one custodian contain DEVICE
//! compromise — losing or compromising one device cannot produce both signatures — but NOT custodian
//! compromise: one coerced, mistaken, or unavailable custodian still reaches both. This predicate
//! establishes two verified custody boundaries; it is NOT two-party control or independent human
//! judgment, and must never be described as such. A second independently protected device held by one
//! custodian qualifies as a distinct domain; a second PERSON is not required.

use crate::codec_chirho::{canonical_record_bytes_chirho, geo_hex_newtype_chirho};
use crate::error_chirho::{GeoGenesisRefusalChirho, GeoGenesisResultChirho};
use crate::scalar_chirho::{GeoEd25519PublicKeyChirho, GeoEd25519SignatureChirho};
use crate::trust_chirho::{
    verify_class_signature_chirho, GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho,
};
use serde::{Deserialize, Serialize};

geo_hex_newtype_chirho!(
    /// A custody-DOMAIN identity: a device/storage/restore-path boundary, not a human identity and not
    /// derived from any subject key. All-zero refuses.
    GeoCustodyDomainIdChirho,
    32,
    reject_zero
);

/// Closed custody-attestation schema token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoCustodyAttestationSchemaChirho {
    V1Chirho,
}

/// One signed custody attestation: the custody authority attests that a specific dedicated authority
/// public key is held under a specific custody domain. Signed by the externally pinned custody
/// authority; the embedded signer key is bound to that pin, never used to select the verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeoCustodyAttestationV1Chirho {
    pub schema_chirho: GeoCustodyAttestationSchemaChirho,
    pub custody_domain_chirho: GeoCustodyDomainIdChirho,
    pub protected_key_chirho: GeoEd25519PublicKeyChirho,
    pub attestation_signer_key_chirho: GeoEd25519PublicKeyChirho,
    pub signature_chirho: GeoEd25519SignatureChirho,
}

/// The explicit unsigned companion of the custody attestation (design section 10 discipline).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedGeoCustodyAttestationV1Chirho {
    pub schema_chirho: GeoCustodyAttestationSchemaChirho,
    pub custody_domain_chirho: GeoCustodyDomainIdChirho,
    pub protected_key_chirho: GeoEd25519PublicKeyChirho,
    pub attestation_signer_key_chirho: GeoEd25519PublicKeyChirho,
}

impl GeoCustodyAttestationV1Chirho {
    /// The explicit unsigned view whose canonical bytes are the signing/verification input.
    pub fn to_unsigned_chirho(&self) -> UnsignedGeoCustodyAttestationV1Chirho {
        UnsignedGeoCustodyAttestationV1Chirho {
            schema_chirho: self.schema_chirho,
            custody_domain_chirho: self.custody_domain_chirho,
            protected_key_chirho: self.protected_key_chirho,
            attestation_signer_key_chirho: self.attestation_signer_key_chirho,
        }
    }
}

/// Two authenticated, distinct custody-domain identities — one per dedicated authority key. Its fields
/// are private and there is no public constructor, so the two-boundary property can only be OBTAINED
/// through `verify_custody_non_equivalence_chirho`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCustodyNonEquivalenceChirho {
    plan_domain_chirho: GeoCustodyDomainIdChirho,
    acceptance_domain_chirho: GeoCustodyDomainIdChirho,
}

impl VerifiedCustodyNonEquivalenceChirho {
    /// The authenticated custody domain of the plan-authority key.
    pub fn plan_domain_chirho(&self) -> GeoCustodyDomainIdChirho {
        self.plan_domain_chirho
    }

    /// The authenticated custody domain of the acceptance-authority key.
    pub fn acceptance_domain_chirho(&self) -> GeoCustodyDomainIdChirho {
        self.acceptance_domain_chirho
    }
}

/// Authenticate one custody attestation against the pinned custody authority and the expected subject
/// key, returning its custody-domain identity. Self-selected (embedded signer not the pin),
/// wrong-subject, and unverifiable attestations refuse by their own reason.
fn authenticate_attestation_chirho(
    attestation_chirho: &GeoCustodyAttestationV1Chirho,
    custody_authority_pin_chirho: &GeoEd25519PublicKeyChirho,
    expected_subject_key_chirho: &GeoEd25519PublicKeyChirho,
) -> GeoGenesisResultChirho<GeoCustodyDomainIdChirho> {
    // Self-selected: the attestation must not choose its own trust anchor. Its embedded signer key must
    // equal the externally pinned custody authority.
    if attestation_chirho.attestation_signer_key_chirho != *custody_authority_pin_chirho {
        return Err(GeoGenesisRefusalChirho::CustodySelfSelectedChirho);
    }
    // Subject binding: the attestation must protect exactly the expected pinned authority key.
    if attestation_chirho.protected_key_chirho != *expected_subject_key_chirho {
        return Err(GeoGenesisRefusalChirho::CustodySubjectMismatchChirho);
    }
    // Verify the attestation signature against the pinned custody authority over the custody class. A
    // bad signature or non-curve authority key collapses into an unverifiable attestation.
    let unsigned_bytes_chirho =
        canonical_record_bytes_chirho(&attestation_chirho.to_unsigned_chirho())?;
    verify_class_signature_chirho(
        custody_authority_pin_chirho,
        GeoGenesisMessageClassChirho::CustodyAttestationChirho,
        &unsigned_bytes_chirho,
        &attestation_chirho.signature_chirho,
    )
    .map_err(|_error_chirho| GeoGenesisRefusalChirho::CustodyAttestationUnverifiableChirho)?;
    Ok(attestation_chirho.custody_domain_chirho)
}

/// Verify the custody non-equivalence of the two dedicated authority keys. Each attestation is
/// authenticated against the pinned custody authority and bound to its dedicated key (plan then
/// acceptance, from the trust pins); the two authenticated custody DOMAINS must be distinct. A missing
/// attestation, a same-domain pair, an unverifiable or self-selected attestation, or a wrong subject
/// refuses. Returns a private two-boundary token — device compromise only, never custodian compromise.
pub fn verify_custody_non_equivalence_chirho(
    plan_attestation_chirho: Option<&GeoCustodyAttestationV1Chirho>,
    acceptance_attestation_chirho: Option<&GeoCustodyAttestationV1Chirho>,
    custody_authority_pin_chirho: &GeoEd25519PublicKeyChirho,
    pins_chirho: &GeoGenesisTrustPinsChirho,
) -> GeoGenesisResultChirho<VerifiedCustodyNonEquivalenceChirho> {
    let plan_attestation_chirho =
        plan_attestation_chirho.ok_or(GeoGenesisRefusalChirho::CustodyEvidenceMissingChirho)?;
    let acceptance_attestation_chirho = acceptance_attestation_chirho
        .ok_or(GeoGenesisRefusalChirho::CustodyEvidenceMissingChirho)?;

    let plan_domain_chirho = authenticate_attestation_chirho(
        plan_attestation_chirho,
        custody_authority_pin_chirho,
        &pins_chirho.plan_authority_key_chirho(),
    )?;
    let acceptance_domain_chirho = authenticate_attestation_chirho(
        acceptance_attestation_chirho,
        custody_authority_pin_chirho,
        &pins_chirho.acceptance_authority_key_chirho(),
    )?;

    // The non-equivalence predicate: distinct custody domains, keyed on the domain identity, not on
    // human identity. Same-domain evidence cannot contain device compromise.
    if plan_domain_chirho == acceptance_domain_chirho {
        return Err(GeoGenesisRefusalChirho::CustodySameDomainChirho);
    }
    Ok(VerifiedCustodyNonEquivalenceChirho {
        plan_domain_chirho,
        acceptance_domain_chirho,
    })
}
