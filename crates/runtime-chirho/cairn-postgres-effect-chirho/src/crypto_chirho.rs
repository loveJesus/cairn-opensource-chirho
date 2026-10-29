// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Domain-separated keyed fingerprints and database-receipt authentication.

use crate::model_chirho::{
    canonical_compensation_receipt_bytes_chirho, canonical_forward_receipt_bytes_chirho,
    canonical_request_bytes_chirho, EffectAbsenceDecisionChirho,
    ReversiblePostgresAbsenceWitnessChirho, ReversiblePostgresCompensationReceiptChirho,
    ReversiblePostgresEffectCoordinateChirho, ReversiblePostgresForwardReceiptChirho,
    ReversiblePostgresRequestChirho, EFFECT_ABSENCE_DECISION_KIND_CHIRHO,
    EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO,
};
use cairn_core_chirho::model_chirho::HashChirho;
use zeroize::Zeroize;

const ROW_FINGERPRINT_KEY_CONTEXT_CHIRHO: &str =
    "cairn-chirho reversible-postgres row-fingerprint key v1";
const FORWARD_RECEIPT_KEY_CONTEXT_CHIRHO: &str =
    "cairn-chirho reversible-postgres forward-receipt key v1";
const COMPENSATION_RECEIPT_KEY_CONTEXT_CHIRHO: &str =
    "cairn-chirho reversible-postgres compensation-receipt key v1";
const ABSENCE_WITNESS_KEY_CONTEXT_CHIRHO: &str =
    "cairn-chirho reversible-postgres absence-witness key v1";
const REQUEST_DIGEST_CONTEXT_CHIRHO: &str =
    "cairn-chirho reversible-postgres canonical-request digest v1";

/// Host-held adapter evidence key. It is never serialized, logged, or written to PostgreSQL.
pub struct AdapterEvidenceKeyChirho([u8; 32]);

impl AdapterEvidenceKeyChirho {
    pub fn new_chirho(bytes_chirho: [u8; 32]) -> Result<Self, EvidenceKeyErrorChirho> {
        if bytes_chirho.iter().all(|byte_chirho| *byte_chirho == 0) {
            return Err(EvidenceKeyErrorChirho::AllZeroChirho);
        }
        Ok(Self(bytes_chirho))
    }

    fn derive_chirho(&self, context_chirho: &str) -> [u8; 32] {
        blake3::derive_key(context_chirho, &self.0)
    }
}

impl Drop for AdapterEvidenceKeyChirho {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for AdapterEvidenceKeyChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str("AdapterEvidenceKeyChirho([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceKeyErrorChirho {
    AllZeroChirho,
}

impl std::fmt::Display for EvidenceKeyErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllZeroChirho => formatter_chirho.write_str("adapter evidence key is all zero"),
        }
    }
}

impl std::error::Error for EvidenceKeyErrorChirho {}

pub fn row_fingerprint_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    subject_chirho: &HashChirho,
    row_key_chirho: &HashChirho,
    value_chirho: &[u8],
) -> HashChirho {
    let subkey_chirho = key_chirho.derive_chirho(ROW_FINGERPRINT_KEY_CONTEXT_CHIRHO);
    let mut hasher_chirho = blake3::Hasher::new_keyed(&subkey_chirho);
    update_frame_chirho(&mut hasher_chirho, subject_chirho.0.as_bytes());
    update_frame_chirho(&mut hasher_chirho, row_key_chirho.0.as_bytes());
    update_frame_chirho(&mut hasher_chirho, value_chirho);
    HashChirho(hasher_chirho.finalize().to_hex().to_string())
}

pub fn request_digest_chirho(
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<HashChirho, crate::model_chirho::PostgresWireErrorChirho> {
    let bytes_chirho = canonical_request_bytes_chirho(request_chirho)?;
    let mut hasher_chirho = blake3::Hasher::new_derive_key(REQUEST_DIGEST_CONTEXT_CHIRHO);
    update_frame_chirho(&mut hasher_chirho, &bytes_chirho);
    Ok(HashChirho(hasher_chirho.finalize().to_hex().to_string()))
}

pub fn forward_receipt_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
) -> Result<HashChirho, crate::model_chirho::PostgresWireErrorChirho> {
    let bytes_chirho = canonical_forward_receipt_bytes_chirho(receipt_chirho)?;
    Ok(authenticate_bytes_chirho(
        &key_chirho.derive_chirho(FORWARD_RECEIPT_KEY_CONTEXT_CHIRHO),
        &bytes_chirho,
    ))
}

pub fn compensation_receipt_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    receipt_chirho: &ReversiblePostgresCompensationReceiptChirho,
) -> Result<HashChirho, crate::model_chirho::PostgresWireErrorChirho> {
    let bytes_chirho = canonical_compensation_receipt_bytes_chirho(receipt_chirho)?;
    Ok(authenticate_bytes_chirho(
        &key_chirho.derive_chirho(COMPENSATION_RECEIPT_KEY_CONTEXT_CHIRHO),
        &bytes_chirho,
    ))
}

/// The durable negative decision is authenticated over every canonical row field in the ruled
/// order. Each field is length-framed, so no delimiter or field-split ambiguity can move a witness
/// across an effect K, signed contract revision, or adapter journal instance.
pub fn absence_witness_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    coordinate_chirho: &ReversiblePostgresEffectCoordinateChirho,
) -> HashChirho {
    let subkey_chirho = key_chirho.derive_chirho(ABSENCE_WITNESS_KEY_CONTEXT_CHIRHO);
    let mut hasher_chirho = blake3::Hasher::new_keyed(&subkey_chirho);
    for field_chirho in [
        EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO.as_bytes(),
        coordinate_chirho.effect_intent_key_chirho().as_bytes(),
        EFFECT_ABSENCE_DECISION_KIND_CHIRHO.as_bytes(),
        coordinate_chirho.contract_digest_chirho().0.as_bytes(),
        coordinate_chirho.journal_binding_chirho().0.as_bytes(),
    ] {
        update_frame_chirho(&mut hasher_chirho, field_chirho);
    }
    HashChirho(hasher_chirho.finalize().to_hex().to_string())
}

pub fn verify_forward_receipt_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
    actual_mac_chirho: &HashChirho,
) -> bool {
    forward_receipt_mac_chirho(key_chirho, receipt_chirho).is_ok_and(|expected_chirho| {
        constant_time_hash_eq_chirho(&expected_chirho, actual_mac_chirho)
    })
}

pub fn verify_compensation_receipt_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    receipt_chirho: &ReversiblePostgresCompensationReceiptChirho,
    actual_mac_chirho: &HashChirho,
) -> bool {
    compensation_receipt_mac_chirho(key_chirho, receipt_chirho).is_ok_and(|expected_chirho| {
        constant_time_hash_eq_chirho(&expected_chirho, actual_mac_chirho)
    })
}

pub fn verify_absence_witness_mac_chirho(
    key_chirho: &AdapterEvidenceKeyChirho,
    witness_chirho: &ReversiblePostgresAbsenceWitnessChirho,
) -> bool {
    if witness_chirho.decision_chirho != EffectAbsenceDecisionChirho::DefiniteNoEffectChirho {
        return false;
    }
    let Ok(coordinate_chirho) = ReversiblePostgresEffectCoordinateChirho::new_chirho(
        witness_chirho.k_chirho.clone(),
        witness_chirho.contract_digest_chirho.clone(),
        witness_chirho.journal_binding_chirho.clone(),
    ) else {
        return false;
    };
    constant_time_hash_eq_chirho(
        &absence_witness_mac_chirho(key_chirho, &coordinate_chirho),
        &witness_chirho.witness_mac_chirho,
    )
}

fn authenticate_bytes_chirho(key_chirho: &[u8; 32], bytes_chirho: &[u8]) -> HashChirho {
    let mut hasher_chirho = blake3::Hasher::new_keyed(key_chirho);
    update_frame_chirho(&mut hasher_chirho, bytes_chirho);
    HashChirho(hasher_chirho.finalize().to_hex().to_string())
}

fn update_frame_chirho(hasher_chirho: &mut blake3::Hasher, bytes_chirho: &[u8]) {
    hasher_chirho.update(&(bytes_chirho.len() as u64).to_be_bytes());
    hasher_chirho.update(bytes_chirho);
}

fn constant_time_hash_eq_chirho(left_chirho: &HashChirho, right_chirho: &HashChirho) -> bool {
    let Ok(left_bytes_chirho) = blake3::Hash::from_hex(&left_chirho.0) else {
        return false;
    };
    let Ok(right_bytes_chirho) = blake3::Hash::from_hex(&right_chirho.0) else {
        return false;
    };
    left_bytes_chirho
        .as_bytes()
        .iter()
        .zip(right_bytes_chirho.as_bytes())
        .fold(
            0u8,
            |difference_chirho, (left_byte_chirho, right_byte_chirho)| {
                difference_chirho | (left_byte_chirho ^ right_byte_chirho)
            },
        )
        == 0
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::{
        DesiredPostgresStateChirho, ExpectedPostgresStateChirho, ReversiblePostgresRequestChirho,
        REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO,
        REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO,
    };
    use cairn_model_privacy_chirho::PrivateBlobRefChirho;

    fn hash_chirho(marker_chirho: char) -> HashChirho {
        HashChirho(marker_chirho.to_string().repeat(64))
    }

    fn receipt_chirho() -> ReversiblePostgresForwardReceiptChirho {
        ReversiblePostgresForwardReceiptChirho {
            schema_chirho: REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO.to_string(),
            effect_idem_key_chirho: hash_chirho('a'),
            request_digest_chirho: hash_chirho('b'),
            subject_chirho: hash_chirho('c'),
            row_key_chirho: hash_chirho('d'),
            before_state_chirho: ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: hash_chirho('f'),
            },
            before_image_ref_chirho: Some(PrivateBlobRefChirho {
                ciphertext_chirho: hash_chirho('e'),
                key_id_chirho: "key-chirho".to_string(),
                nonce_chirho: "nonce-chirho".to_string(),
                mac_chirho: "mac-chirho".to_string(),
                alg_chirho: "algorithm-chirho".to_string(),
            }),
            post_state_chirho: ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: hash_chirho('f'),
            },
        }
    }

    fn request_chirho() -> ReversiblePostgresRequestChirho {
        ReversiblePostgresRequestChirho {
            schema_chirho: REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO.to_string(),
            subject_chirho: hash_chirho('a'),
            row_key_chirho: hash_chirho('b'),
            expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            desired_chirho: DesiredPostgresStateChirho::AbsentChirho,
        }
    }

    #[test]
    fn key_is_redacted_and_all_zero_refuses_chirho() {
        assert!(matches!(
            AdapterEvidenceKeyChirho::new_chirho([0; 32]),
            Err(EvidenceKeyErrorChirho::AllZeroChirho)
        ));
        let key_chirho = AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap();
        assert_eq!(
            format!("{key_chirho:?}"),
            "AdapterEvidenceKeyChirho([REDACTED])"
        );
    }

    #[test]
    fn row_fingerprint_is_keyed_and_coordinate_bound_chirho() {
        let key_chirho = AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap();
        let value_chirho = b"false";
        let fingerprint_chirho = row_fingerprint_chirho(
            &key_chirho,
            &hash_chirho('a'),
            &hash_chirho('b'),
            value_chirho,
        );
        assert_ne!(
            fingerprint_chirho.0,
            blake3::hash(value_chirho).to_hex().to_string()
        );
        assert_ne!(
            fingerprint_chirho,
            row_fingerprint_chirho(
                &key_chirho,
                &hash_chirho('c'),
                &hash_chirho('b'),
                value_chirho
            )
        );
        assert_ne!(
            fingerprint_chirho,
            row_fingerprint_chirho(
                &key_chirho,
                &hash_chirho('a'),
                &hash_chirho('d'),
                value_chirho
            )
        );
    }

    #[test]
    fn request_digest_is_canonical_and_domain_separated_chirho() {
        let request_chirho = request_chirho();
        let digest_chirho = request_digest_chirho(&request_chirho).unwrap();
        let canonical_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
        assert_ne!(
            digest_chirho.0,
            blake3::hash(&canonical_chirho).to_hex().to_string()
        );

        let mut changed_chirho = request_chirho;
        changed_chirho.row_key_chirho = hash_chirho('c');
        assert_ne!(
            digest_chirho,
            request_digest_chirho(&changed_chirho).unwrap()
        );
    }

    #[test]
    fn receipt_mac_rejects_mutation_wrong_key_and_bad_hex_chirho() {
        let key_chirho = AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap();
        let wrong_key_chirho = AdapterEvidenceKeyChirho::new_chirho([8; 32]).unwrap();
        let receipt_chirho = receipt_chirho();
        let mac_chirho = forward_receipt_mac_chirho(&key_chirho, &receipt_chirho).unwrap();
        assert!(verify_forward_receipt_mac_chirho(
            &key_chirho,
            &receipt_chirho,
            &mac_chirho
        ));
        assert!(!verify_forward_receipt_mac_chirho(
            &wrong_key_chirho,
            &receipt_chirho,
            &mac_chirho
        ));
        let mut mutated_chirho = receipt_chirho.clone();
        mutated_chirho.row_key_chirho = hash_chirho('9');
        assert!(!verify_forward_receipt_mac_chirho(
            &key_chirho,
            &mutated_chirho,
            &mac_chirho
        ));
        assert!(!verify_forward_receipt_mac_chirho(
            &key_chirho,
            &receipt_chirho,
            &HashChirho("not-hex-chirho".to_string())
        ));
    }

    #[test]
    fn absence_witness_mac_is_framed_keyed_and_binds_every_decision_coordinate_chirho() {
        let key_chirho = AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap();
        let wrong_key_chirho = AdapterEvidenceKeyChirho::new_chirho([8; 32]).unwrap();
        let coordinate_chirho = ReversiblePostgresEffectCoordinateChirho::new_chirho(
            format!("cf3-intent-v1-chirho:{}", "a".repeat(64)),
            hash_chirho('b'),
            hash_chirho('c'),
        )
        .unwrap();
        let witness_chirho = ReversiblePostgresAbsenceWitnessChirho {
            schema_chirho: EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO.to_string(),
            k_chirho: coordinate_chirho.effect_intent_key_chirho().to_string(),
            decision_chirho: EffectAbsenceDecisionChirho::DefiniteNoEffectChirho,
            contract_digest_chirho: coordinate_chirho.contract_digest_chirho().clone(),
            journal_binding_chirho: coordinate_chirho.journal_binding_chirho().clone(),
            witness_mac_chirho: absence_witness_mac_chirho(&key_chirho, &coordinate_chirho),
        };
        assert!(verify_absence_witness_mac_chirho(
            &key_chirho,
            &witness_chirho
        ));
        assert!(!verify_absence_witness_mac_chirho(
            &wrong_key_chirho,
            &witness_chirho
        ));

        let mut changed_contract_chirho = witness_chirho.clone();
        changed_contract_chirho.contract_digest_chirho = hash_chirho('d');
        assert!(!verify_absence_witness_mac_chirho(
            &key_chirho,
            &changed_contract_chirho
        ));
        let mut changed_journal_chirho = witness_chirho.clone();
        changed_journal_chirho.journal_binding_chirho = hash_chirho('e');
        assert!(!verify_absence_witness_mac_chirho(
            &key_chirho,
            &changed_journal_chirho
        ));
        let mut changed_key_chirho = witness_chirho;
        changed_key_chirho.k_chirho = format!("cf3-intent-v1-chirho:{}", "f".repeat(64));
        assert!(!verify_absence_witness_mac_chirho(
            &key_chirho,
            &changed_key_chirho
        ));
    }
}
