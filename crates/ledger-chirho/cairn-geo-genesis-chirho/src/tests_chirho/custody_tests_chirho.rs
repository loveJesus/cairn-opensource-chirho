// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Custody non-equivalence arms (8.2b, ruling 1): two custody attestations under the pinned custody
//! authority must name DISTINCT custody domains for the two dedicated keys. Missing, same-domain,
//! unverifiable/forged, self-selected, and wrong-subject evidence each refuse by a distinct reason;
//! the domain predicate is mutation-proven. The residual (device compromise, not custodian
//! compromise) is documented in `custody_chirho`; these arms test the mechanism, not the residual.

use crate::codec_chirho::canonical_record_bytes_chirho;
use crate::custody_chirho::{
    verify_custody_non_equivalence_chirho, GeoCustodyAttestationSchemaChirho,
    GeoCustodyAttestationV1Chirho, GeoCustodyDomainIdChirho, UnsignedGeoCustodyAttestationV1Chirho,
};
use crate::error_chirho::GeoGenesisRefusalChirho;
use crate::scalar_chirho::{GeoEd25519PublicKeyChirho, GeoEd25519SignatureChirho};
use crate::trust_chirho::{
    GeoGenesisMessageClassChirho, GeoGenesisTrustPinsChirho, GeoRoleSignerChirho,
    GeoSignerRoleChirho,
};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const PLAN_AUTHORITY_SEED_CHIRHO: u8 = 201;
const ACCEPTANCE_AUTHORITY_SEED_CHIRHO: u8 = 202;
const CUSTODY_AUTHORITY_SEED_CHIRHO: u8 = 210;
const ROGUE_CUSTODY_SEED_CHIRHO: u8 = 211;

fn derived_pk_chirho(seed_chirho: u8) -> GeoEd25519PublicKeyChirho {
    let signing_key_chirho = SigningKey::from_bytes(&[seed_chirho; 32]);
    GeoEd25519PublicKeyChirho::new_chirho(*signing_key_chirho.verifying_key().as_bytes()).unwrap()
}

fn write_seed_file_chirho(seed_chirho: u8) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ordinal_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let path_chirho = std::env::temp_dir().join(format!(
        "cairn-geo-82b-custody-{nanos_chirho}-{ordinal_chirho}"
    ));
    std::fs::write(&path_chirho, [seed_chirho; 32]).unwrap();
    path_chirho
}

fn provision_signer_chirho(
    role_chirho: GeoSignerRoleChirho,
    seed_chirho: u8,
) -> GeoRoleSignerChirho {
    let pin_chirho = derived_pk_chirho(seed_chirho);
    let key_file_chirho = write_seed_file_chirho(seed_chirho);
    GeoRoleSignerChirho::load_existing_pinned_chirho(role_chirho, &key_file_chirho, &pin_chirho)
        .unwrap()
}

fn split_pins_chirho() -> GeoGenesisTrustPinsChirho {
    GeoGenesisTrustPinsChirho::new_split_chirho(
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
    )
    .unwrap()
}

fn domain_chirho(seed_chirho: u8) -> GeoCustodyDomainIdChirho {
    GeoCustodyDomainIdChirho::new_chirho([seed_chirho; 32]).unwrap()
}

/// Author a custody attestation: the throwaway fixture custody authority (`signer`) attests that
/// `protected_key` lives under `domain`, with `attestation_signer` as the embedded attester identity.
fn author_attestation_chirho(
    signer_chirho: &GeoRoleSignerChirho,
    domain_chirho: GeoCustodyDomainIdChirho,
    protected_key_chirho: GeoEd25519PublicKeyChirho,
    attestation_signer_key_chirho: GeoEd25519PublicKeyChirho,
) -> GeoCustodyAttestationV1Chirho {
    let unsigned_chirho = UnsignedGeoCustodyAttestationV1Chirho {
        schema_chirho: GeoCustodyAttestationSchemaChirho::V1Chirho,
        custody_domain_chirho: domain_chirho,
        protected_key_chirho,
        attestation_signer_key_chirho,
    };
    let bytes_chirho = canonical_record_bytes_chirho(&unsigned_chirho).unwrap();
    let signature_chirho = signer_chirho
        .sign_class_chirho(
            GeoGenesisMessageClassChirho::CustodyAttestationChirho,
            &bytes_chirho,
        )
        .unwrap();
    GeoCustodyAttestationV1Chirho {
        schema_chirho: GeoCustodyAttestationSchemaChirho::V1Chirho,
        custody_domain_chirho: domain_chirho,
        protected_key_chirho,
        attestation_signer_key_chirho,
        signature_chirho,
    }
}

/// The valid pair: the custody authority attests the plan and acceptance keys under DISTINCT domains.
fn valid_pair_chirho() -> (
    GeoCustodyAttestationV1Chirho,
    GeoCustodyAttestationV1Chirho,
    GeoEd25519PublicKeyChirho,
) {
    let custody_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        CUSTODY_AUTHORITY_SEED_CHIRHO,
    );
    let custody_pin_chirho = custody_signer_chirho.public_key_chirho();
    let plan_attestation_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(1),
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    let acceptance_attestation_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(2),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    (
        plan_attestation_chirho,
        acceptance_attestation_chirho,
        custody_pin_chirho,
    )
}

#[test]
fn distinct_domain_evidence_verifies_and_returns_two_boundaries_chirho() {
    let (plan_chirho, acceptance_chirho, custody_pin_chirho) = valid_pair_chirho();
    let verified_chirho = verify_custody_non_equivalence_chirho(
        Some(&plan_chirho),
        Some(&acceptance_chirho),
        &custody_pin_chirho,
        &split_pins_chirho(),
    )
    .unwrap();
    assert_eq!(verified_chirho.plan_domain_chirho(), domain_chirho(1));
    assert_eq!(verified_chirho.acceptance_domain_chirho(), domain_chirho(2));
    assert_ne!(
        verified_chirho.plan_domain_chirho(),
        verified_chirho.acceptance_domain_chirho()
    );
}

#[test]
fn missing_evidence_refuses_chirho() {
    let (plan_chirho, acceptance_chirho, custody_pin_chirho) = valid_pair_chirho();
    let pins_chirho = split_pins_chirho();
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            None,
            Some(&acceptance_chirho),
            &custody_pin_chirho,
            &pins_chirho
        ),
        Err(GeoGenesisRefusalChirho::CustodyEvidenceMissingChirho)
    );
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&plan_chirho),
            None,
            &custody_pin_chirho,
            &pins_chirho
        ),
        Err(GeoGenesisRefusalChirho::CustodyEvidenceMissingChirho)
    );
}

#[test]
fn same_domain_evidence_refuses_chirho() {
    // Both dedicated keys attested under the SAME custody domain: no device-compromise containment.
    let custody_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        CUSTODY_AUTHORITY_SEED_CHIRHO,
    );
    let custody_pin_chirho = custody_signer_chirho.public_key_chirho();
    let plan_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(5),
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    let acceptance_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(5),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&plan_chirho),
            Some(&acceptance_chirho),
            &custody_pin_chirho,
            &split_pins_chirho()
        ),
        Err(GeoGenesisRefusalChirho::CustodySameDomainChirho)
    );
}

#[test]
fn self_selected_attestation_refuses_chirho() {
    // A rogue custody key attests, naming ITSELF as the attester. Verified against the real pinned
    // custody authority, the embedded attester is not the pin, so it refuses as self-selected.
    let rogue_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        ROGUE_CUSTODY_SEED_CHIRHO,
    );
    let real_custody_pin_chirho = derived_pk_chirho(CUSTODY_AUTHORITY_SEED_CHIRHO);
    let plan_chirho = author_attestation_chirho(
        &rogue_signer_chirho,
        domain_chirho(1),
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        rogue_signer_chirho.public_key_chirho(),
    );
    let acceptance_chirho = author_attestation_chirho(
        &rogue_signer_chirho,
        domain_chirho(2),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        rogue_signer_chirho.public_key_chirho(),
    );
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&plan_chirho),
            Some(&acceptance_chirho),
            &real_custody_pin_chirho,
            &split_pins_chirho()
        ),
        Err(GeoGenesisRefusalChirho::CustodySelfSelectedChirho)
    );
}

#[test]
fn forged_and_tampered_attestation_refuse_as_unverifiable_chirho() {
    let real_custody_pin_chirho = derived_pk_chirho(CUSTODY_AUTHORITY_SEED_CHIRHO);
    let acceptance_chirho = {
        let (_, acceptance_chirho, _) = valid_pair_chirho();
        acceptance_chirho
    };

    // Forged: a rogue key signs but claims the REAL custody authority as its embedded attester. The
    // embedded key matches the pin (passes self-selected), but the signature is by the wrong key.
    let rogue_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        ROGUE_CUSTODY_SEED_CHIRHO,
    );
    let forged_chirho = author_attestation_chirho(
        &rogue_signer_chirho,
        domain_chirho(1),
        derived_pk_chirho(PLAN_AUTHORITY_SEED_CHIRHO),
        real_custody_pin_chirho,
    );
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&forged_chirho),
            Some(&acceptance_chirho),
            &real_custody_pin_chirho,
            &split_pins_chirho()
        ),
        Err(GeoGenesisRefusalChirho::CustodyAttestationUnverifiableChirho)
    );

    // Tampered: a genuine attestation with one signature byte flipped.
    let (plan_chirho, _, custody_pin_chirho) = valid_pair_chirho();
    let mut tampered_chirho = plan_chirho;
    let mut sig_bytes_chirho = *tampered_chirho.signature_chirho.as_bytes_chirho();
    sig_bytes_chirho[7] ^= 0x01;
    tampered_chirho.signature_chirho =
        GeoEd25519SignatureChirho::new_chirho(sig_bytes_chirho).unwrap();
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&tampered_chirho),
            Some(&acceptance_chirho),
            &custody_pin_chirho,
            &split_pins_chirho()
        ),
        Err(GeoGenesisRefusalChirho::CustodyAttestationUnverifiableChirho)
    );
}

#[test]
fn wrong_subject_attestation_refuses_chirho() {
    // An attestation that protects a key OTHER than the dedicated plan-authority key refuses.
    let custody_signer_chirho = provision_signer_chirho(
        GeoSignerRoleChirho::CustodyAuthorityChirho,
        CUSTODY_AUTHORITY_SEED_CHIRHO,
    );
    let custody_pin_chirho = custody_signer_chirho.public_key_chirho();
    let wrong_subject_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(1),
        derived_pk_chirho(99), // not the pinned plan-authority key
        custody_pin_chirho,
    );
    let acceptance_chirho = author_attestation_chirho(
        &custody_signer_chirho,
        domain_chirho(2),
        derived_pk_chirho(ACCEPTANCE_AUTHORITY_SEED_CHIRHO),
        custody_pin_chirho,
    );
    assert_eq!(
        verify_custody_non_equivalence_chirho(
            Some(&wrong_subject_chirho),
            Some(&acceptance_chirho),
            &custody_pin_chirho,
            &split_pins_chirho()
        ),
        Err(GeoGenesisRefusalChirho::CustodySubjectMismatchChirho)
    );
}
