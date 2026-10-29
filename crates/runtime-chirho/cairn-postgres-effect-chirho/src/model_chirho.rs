// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Strict canonical wires for the reversible PostgreSQL effect boundary.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_effect_commit_chirho::intent_chirho::parse_effect_intent_key_chirho;
use cairn_model_privacy_chirho::PrivateBlobRefChirho;
use serde::{Deserialize, Serialize};

pub const REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO: &str = "reversible-postgres-request-v1-chirho";
pub const REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO: &str =
    "reversible-postgres-forward-receipt-v1-chirho";
pub const REVERSIBLE_POSTGRES_COMPENSATION_RECEIPT_SCHEMA_CHIRHO: &str =
    "reversible-postgres-compensation-receipt-v1-chirho";
pub const REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO: &str =
    "reversible-postgres-committed-decision-v1-chirho";
pub const EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO: &str = "cairn-effect-absence-witness-v1-chirho";
pub const EFFECT_ABSENCE_DECISION_KIND_CHIRHO: &str = "definite-no-effect-chirho";
const MAX_PRIVATE_REF_TEXT_BYTES_CHIRHO: usize = 512;

/// Exact signed-intent coordinate under which PostgreSQL reaches one durable terminal decision.
/// The full K binds payer, price, request context, cut, and contract content by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReversiblePostgresEffectCoordinateChirho {
    effect_intent_key_chirho: String,
    effect_idem_key_chirho: HashChirho,
    contract_digest_chirho: HashChirho,
    journal_binding_chirho: HashChirho,
}

impl ReversiblePostgresEffectCoordinateChirho {
    pub fn from_verified_intent_chirho(
        intent_chirho: &cairn_effect_commit_chirho::intent_chirho::VerifiedEffectIntentChirho,
    ) -> Result<Self, PostgresWireErrorChirho> {
        Self::new_chirho(
            intent_chirho.key_chirho().to_string(),
            HashChirho(
                intent_chirho
                    .intent_chirho()
                    .reversion_contract_digest_chirho
                    .0
                    .clone(),
            ),
            HashChirho(
                intent_chirho
                    .intent_chirho()
                    .journal_cut_chirho
                    .journal_genesis_digest_chirho
                    .0
                    .clone(),
            ),
        )
    }

    pub fn new_chirho(
        effect_intent_key_chirho: String,
        contract_digest_chirho: HashChirho,
        journal_binding_chirho: HashChirho,
    ) -> Result<Self, PostgresWireErrorChirho> {
        let effect_idem_key_chirho = parse_effect_intent_key_chirho(&effect_intent_key_chirho)
            .map_err(|_| PostgresWireErrorChirho::InvalidChirho {
                detail_chirho: "effect intent K is not a canonical CF3 forward coordinate"
                    .to_string(),
            })?;
        validate_digest_chirho("contract_digest_chirho", &contract_digest_chirho)?;
        validate_digest_chirho("journal_binding_chirho", &journal_binding_chirho)?;
        Ok(Self {
            effect_intent_key_chirho,
            effect_idem_key_chirho: HashChirho(effect_idem_key_chirho.0),
            contract_digest_chirho,
            journal_binding_chirho,
        })
    }

    pub fn effect_intent_key_chirho(&self) -> &str {
        &self.effect_intent_key_chirho
    }

    pub fn effect_idem_key_chirho(&self) -> &HashChirho {
        &self.effect_idem_key_chirho
    }

    pub fn contract_digest_chirho(&self) -> &HashChirho {
        &self.contract_digest_chirho
    }

    pub fn journal_binding_chirho(&self) -> &HashChirho {
        &self.journal_binding_chirho
    }
}

/// The caller's compare-and-set expectation. Fingerprints are opaque keyed concurrency tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum ExpectedPostgresStateChirho {
    #[serde(rename = "absent-chirho")]
    AbsentChirho,
    #[serde(rename = "keyed-fingerprint-chirho")]
    KeyedFingerprintChirho { fingerprint_chirho: HashChirho },
}

/// The requested world-state transition. Plaintext stays behind the subject-bound private ref.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum DesiredPostgresStateChirho {
    #[serde(rename = "present-chirho")]
    PresentChirho {
        value_ref_chirho: PrivateBlobRefChirho,
    },
    #[serde(rename = "absent-chirho")]
    AbsentChirho,
}

/// The only app-selectable request shape. SQL and compensation mode are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresRequestChirho {
    pub schema_chirho: String,
    pub subject_chirho: HashChirho,
    pub row_key_chirho: HashChirho,
    pub expected_before_chirho: ExpectedPostgresStateChirho,
    pub desired_chirho: DesiredPostgresStateChirho,
}

/// Canonical evidence returned by a committed forward database transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresForwardReceiptChirho {
    pub schema_chirho: String,
    pub effect_idem_key_chirho: HashChirho,
    pub request_digest_chirho: HashChirho,
    pub subject_chirho: HashChirho,
    pub row_key_chirho: HashChirho,
    pub before_state_chirho: ExpectedPostgresStateChirho,
    pub before_image_ref_chirho: Option<PrivateBlobRefChirho>,
    pub post_state_chirho: ExpectedPostgresStateChirho,
}

/// The authenticated positive terminal decision stored under the exact effect-intent K.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresCommittedDecisionChirho {
    pub schema_chirho: String,
    pub k_chirho: String,
    pub contract_digest_chirho: HashChirho,
    pub journal_binding_chirho: HashChirho,
    pub forward_receipt_chirho: ReversiblePostgresForwardReceiptChirho,
    pub receipt_mac_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EffectAbsenceDecisionChirho {
    #[serde(rename = "definite-no-effect-chirho")]
    DefiniteNoEffectChirho,
}

/// Canonical durable negative terminal decision. Every MAC input is carried in this row so either
/// door can verify it from stored bytes plus the injected secret key, with no clock or lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresAbsenceWitnessChirho {
    pub schema_chirho: String,
    pub k_chirho: String,
    pub decision_chirho: EffectAbsenceDecisionChirho,
    pub contract_digest_chirho: HashChirho,
    pub journal_binding_chirho: HashChirho,
    pub witness_mac_chirho: HashChirho,
}

/// A compensation decision is persisted once so replay never reinterprets later world state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", deny_unknown_fields)]
pub enum PostgresCompensationOutcomeChirho {
    #[serde(rename = "restored-chirho")]
    RestoredChirho {
        restored_state_chirho: ExpectedPostgresStateChirho,
    },
    #[serde(rename = "superseded-chirho")]
    SupersededChirho {
        observed_state_chirho: ExpectedPostgresStateChirho,
    },
}

/// Canonical evidence returned by an internally authorized compensation transaction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReversiblePostgresCompensationReceiptChirho {
    pub schema_chirho: String,
    pub compensation_idem_key_chirho: HashChirho,
    pub original_effect_idem_key_chirho: HashChirho,
    pub original_request_digest_chirho: HashChirho,
    pub subject_chirho: HashChirho,
    pub row_key_chirho: HashChirho,
    pub outcome_chirho: PostgresCompensationOutcomeChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostgresWireErrorChirho {
    MalformedChirho { detail_chirho: String },
    InvalidChirho { detail_chirho: String },
    NonCanonicalBytesChirho,
    SerializeChirho { detail_chirho: String },
}

impl std::fmt::Display for PostgresWireErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "malformed reversible-Postgres wire: {detail_chirho}"
                )
            }
            Self::InvalidChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "invalid reversible-Postgres wire: {detail_chirho}"
                )
            }
            Self::NonCanonicalBytesChirho => {
                write!(
                    formatter_chirho,
                    "reversible-Postgres bytes are not canonical"
                )
            }
            Self::SerializeChirho { detail_chirho } => {
                write!(
                    formatter_chirho,
                    "serialize reversible-Postgres wire: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for PostgresWireErrorChirho {}

pub fn canonical_request_bytes_chirho(
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    validate_request_chirho(request_chirho)?;
    serialize_chirho(request_chirho)
}

pub fn parse_canonical_request_chirho(
    bytes_chirho: &[u8],
) -> Result<ReversiblePostgresRequestChirho, PostgresWireErrorChirho> {
    parse_exact_chirho(bytes_chirho, canonical_request_bytes_chirho)
}

pub fn canonical_forward_receipt_bytes_chirho(
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    validate_forward_receipt_chirho(receipt_chirho)?;
    serialize_chirho(receipt_chirho)
}

pub fn parse_canonical_forward_receipt_chirho(
    bytes_chirho: &[u8],
) -> Result<ReversiblePostgresForwardReceiptChirho, PostgresWireErrorChirho> {
    parse_exact_chirho(bytes_chirho, canonical_forward_receipt_bytes_chirho)
}

pub fn canonical_compensation_receipt_bytes_chirho(
    receipt_chirho: &ReversiblePostgresCompensationReceiptChirho,
) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    validate_compensation_receipt_chirho(receipt_chirho)?;
    serialize_chirho(receipt_chirho)
}

pub fn parse_canonical_compensation_receipt_chirho(
    bytes_chirho: &[u8],
) -> Result<ReversiblePostgresCompensationReceiptChirho, PostgresWireErrorChirho> {
    parse_exact_chirho(bytes_chirho, canonical_compensation_receipt_bytes_chirho)
}

pub fn canonical_committed_decision_bytes_chirho(
    decision_chirho: &ReversiblePostgresCommittedDecisionChirho,
) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    validate_committed_decision_chirho(decision_chirho)?;
    serialize_chirho(decision_chirho)
}

pub fn parse_canonical_committed_decision_chirho(
    bytes_chirho: &[u8],
) -> Result<ReversiblePostgresCommittedDecisionChirho, PostgresWireErrorChirho> {
    parse_exact_chirho(bytes_chirho, canonical_committed_decision_bytes_chirho)
}

pub fn canonical_absence_witness_bytes_chirho(
    witness_chirho: &ReversiblePostgresAbsenceWitnessChirho,
) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    validate_absence_witness_chirho(witness_chirho)?;
    serialize_chirho(witness_chirho)
}

pub fn parse_canonical_absence_witness_chirho(
    bytes_chirho: &[u8],
) -> Result<ReversiblePostgresAbsenceWitnessChirho, PostgresWireErrorChirho> {
    parse_exact_chirho(bytes_chirho, canonical_absence_witness_bytes_chirho)
}

fn parse_exact_chirho<T>(
    bytes_chirho: &[u8],
    canonical_chirho: impl FnOnce(&T) -> Result<Vec<u8>, PostgresWireErrorChirho>,
) -> Result<T, PostgresWireErrorChirho>
where
    T: for<'de> Deserialize<'de>,
{
    let value_chirho: T = serde_json::from_slice(bytes_chirho).map_err(|error_chirho| {
        PostgresWireErrorChirho::MalformedChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })?;
    if canonical_chirho(&value_chirho)? != bytes_chirho {
        return Err(PostgresWireErrorChirho::NonCanonicalBytesChirho);
    }
    Ok(value_chirho)
}

fn serialize_chirho(value_chirho: &impl Serialize) -> Result<Vec<u8>, PostgresWireErrorChirho> {
    serde_json::to_vec(value_chirho).map_err(|error_chirho| {
        PostgresWireErrorChirho::SerializeChirho {
            detail_chirho: error_chirho.to_string(),
        }
    })
}

fn validate_request_chirho(
    request_chirho: &ReversiblePostgresRequestChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_schema_chirho(
        &request_chirho.schema_chirho,
        REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO,
    )?;
    validate_digest_chirho("subject_chirho", &request_chirho.subject_chirho)?;
    validate_digest_chirho("row_key_chirho", &request_chirho.row_key_chirho)?;
    validate_expected_state_chirho(&request_chirho.expected_before_chirho)?;
    if let DesiredPostgresStateChirho::PresentChirho { value_ref_chirho } =
        &request_chirho.desired_chirho
    {
        validate_private_ref_chirho(value_ref_chirho)?;
    }
    Ok(())
}

fn validate_forward_receipt_chirho(
    receipt_chirho: &ReversiblePostgresForwardReceiptChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_schema_chirho(
        &receipt_chirho.schema_chirho,
        REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO,
    )?;
    validate_digest_chirho(
        "effect_idem_key_chirho",
        &receipt_chirho.effect_idem_key_chirho,
    )?;
    validate_digest_chirho(
        "request_digest_chirho",
        &receipt_chirho.request_digest_chirho,
    )?;
    validate_digest_chirho("subject_chirho", &receipt_chirho.subject_chirho)?;
    validate_digest_chirho("row_key_chirho", &receipt_chirho.row_key_chirho)?;
    validate_expected_state_chirho(&receipt_chirho.before_state_chirho)?;
    match (
        &receipt_chirho.before_state_chirho,
        &receipt_chirho.before_image_ref_chirho,
    ) {
        (ExpectedPostgresStateChirho::AbsentChirho, None) => {}
        (
            ExpectedPostgresStateChirho::KeyedFingerprintChirho { .. },
            Some(before_image_ref_chirho),
        ) => validate_private_ref_chirho(before_image_ref_chirho)?,
        _ => {
            return Err(PostgresWireErrorChirho::InvalidChirho {
                detail_chirho:
                    "before-image ref must be absent exactly when the prior row was absent"
                        .to_string(),
            });
        }
    }
    validate_expected_state_chirho(&receipt_chirho.post_state_chirho)
}

fn validate_compensation_receipt_chirho(
    receipt_chirho: &ReversiblePostgresCompensationReceiptChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_schema_chirho(
        &receipt_chirho.schema_chirho,
        REVERSIBLE_POSTGRES_COMPENSATION_RECEIPT_SCHEMA_CHIRHO,
    )?;
    validate_digest_chirho(
        "compensation_idem_key_chirho",
        &receipt_chirho.compensation_idem_key_chirho,
    )?;
    validate_digest_chirho(
        "original_effect_idem_key_chirho",
        &receipt_chirho.original_effect_idem_key_chirho,
    )?;
    validate_digest_chirho(
        "original_request_digest_chirho",
        &receipt_chirho.original_request_digest_chirho,
    )?;
    validate_digest_chirho("subject_chirho", &receipt_chirho.subject_chirho)?;
    validate_digest_chirho("row_key_chirho", &receipt_chirho.row_key_chirho)?;
    match &receipt_chirho.outcome_chirho {
        PostgresCompensationOutcomeChirho::RestoredChirho {
            restored_state_chirho,
        } => validate_expected_state_chirho(restored_state_chirho),
        PostgresCompensationOutcomeChirho::SupersededChirho {
            observed_state_chirho,
        } => validate_expected_state_chirho(observed_state_chirho),
    }
}

fn validate_committed_decision_chirho(
    decision_chirho: &ReversiblePostgresCommittedDecisionChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_schema_chirho(
        &decision_chirho.schema_chirho,
        REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO,
    )?;
    let coordinate_chirho = ReversiblePostgresEffectCoordinateChirho::new_chirho(
        decision_chirho.k_chirho.clone(),
        decision_chirho.contract_digest_chirho.clone(),
        decision_chirho.journal_binding_chirho.clone(),
    )?;
    validate_forward_receipt_chirho(&decision_chirho.forward_receipt_chirho)?;
    validate_digest_chirho("receipt_mac_chirho", &decision_chirho.receipt_mac_chirho)?;
    if decision_chirho
        .forward_receipt_chirho
        .effect_idem_key_chirho
        != *coordinate_chirho.effect_idem_key_chirho()
    {
        return Err(PostgresWireErrorChirho::InvalidChirho {
            detail_chirho: "committed decision receipt does not bind its exact effect K"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_absence_witness_chirho(
    witness_chirho: &ReversiblePostgresAbsenceWitnessChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_schema_chirho(
        &witness_chirho.schema_chirho,
        EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO,
    )?;
    ReversiblePostgresEffectCoordinateChirho::new_chirho(
        witness_chirho.k_chirho.clone(),
        witness_chirho.contract_digest_chirho.clone(),
        witness_chirho.journal_binding_chirho.clone(),
    )?;
    validate_digest_chirho("witness_mac_chirho", &witness_chirho.witness_mac_chirho)
}

fn validate_expected_state_chirho(
    state_chirho: &ExpectedPostgresStateChirho,
) -> Result<(), PostgresWireErrorChirho> {
    if let ExpectedPostgresStateChirho::KeyedFingerprintChirho { fingerprint_chirho } = state_chirho
    {
        validate_digest_chirho("fingerprint_chirho", fingerprint_chirho)?;
    }
    Ok(())
}

fn validate_private_ref_chirho(
    ref_chirho: &PrivateBlobRefChirho,
) -> Result<(), PostgresWireErrorChirho> {
    validate_digest_chirho("ciphertext_chirho", &ref_chirho.ciphertext_chirho)?;
    for (label_chirho, value_chirho) in [
        ("key_id_chirho", ref_chirho.key_id_chirho.as_str()),
        ("nonce_chirho", ref_chirho.nonce_chirho.as_str()),
        ("mac_chirho", ref_chirho.mac_chirho.as_str()),
        ("alg_chirho", ref_chirho.alg_chirho.as_str()),
    ] {
        if value_chirho.is_empty()
            || value_chirho.len() > MAX_PRIVATE_REF_TEXT_BYTES_CHIRHO
            || value_chirho.contains('\0')
        {
            return Err(PostgresWireErrorChirho::InvalidChirho {
                detail_chirho: format!("{label_chirho} must be nonempty, bounded, and NUL-free"),
            });
        }
    }
    Ok(())
}

fn validate_schema_chirho(
    actual_chirho: &str,
    expected_chirho: &str,
) -> Result<(), PostgresWireErrorChirho> {
    if actual_chirho != expected_chirho {
        return Err(PostgresWireErrorChirho::InvalidChirho {
            detail_chirho: format!("unsupported schema '{actual_chirho}'"),
        });
    }
    Ok(())
}

pub(crate) fn validate_digest_chirho(
    label_chirho: &str,
    digest_chirho: &HashChirho,
) -> Result<(), PostgresWireErrorChirho> {
    if digest_chirho.0.len() != 64
        || !digest_chirho
            .0
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        return Err(PostgresWireErrorChirho::InvalidChirho {
            detail_chirho: format!("{label_chirho} must be 64 lowercase hex bytes"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    const A_HASH_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B_HASH_CHIRHO: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const C_HASH_CHIRHO: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const D_HASH_CHIRHO: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const F_HASH_CHIRHO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    fn hash_chirho(value_chirho: &str) -> HashChirho {
        HashChirho(value_chirho.to_string())
    }

    fn blob_ref_chirho() -> PrivateBlobRefChirho {
        PrivateBlobRefChirho {
            ciphertext_chirho: hash_chirho(C_HASH_CHIRHO),
            key_id_chirho: "subject-key-chirho".to_string(),
            nonce_chirho: "nonce-chirho".to_string(),
            mac_chirho: "mac-chirho".to_string(),
            alg_chirho: "xchacha20poly1305+blake3-keyed-mac/v1".to_string(),
        }
    }

    fn request_chirho() -> ReversiblePostgresRequestChirho {
        ReversiblePostgresRequestChirho {
            schema_chirho: REVERSIBLE_POSTGRES_REQUEST_SCHEMA_CHIRHO.to_string(),
            subject_chirho: hash_chirho(A_HASH_CHIRHO),
            row_key_chirho: hash_chirho(B_HASH_CHIRHO),
            expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            desired_chirho: DesiredPostgresStateChirho::PresentChirho {
                value_ref_chirho: blob_ref_chirho(),
            },
        }
    }

    fn forward_receipt_chirho() -> ReversiblePostgresForwardReceiptChirho {
        ReversiblePostgresForwardReceiptChirho {
            schema_chirho: REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO.to_string(),
            effect_idem_key_chirho: hash_chirho(A_HASH_CHIRHO),
            request_digest_chirho: hash_chirho(B_HASH_CHIRHO),
            subject_chirho: hash_chirho(C_HASH_CHIRHO),
            row_key_chirho: hash_chirho(D_HASH_CHIRHO),
            before_state_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            before_image_ref_chirho: None,
            post_state_chirho: ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: hash_chirho(F_HASH_CHIRHO),
            },
        }
    }

    fn compensation_receipt_chirho() -> ReversiblePostgresCompensationReceiptChirho {
        ReversiblePostgresCompensationReceiptChirho {
            schema_chirho: REVERSIBLE_POSTGRES_COMPENSATION_RECEIPT_SCHEMA_CHIRHO.to_string(),
            compensation_idem_key_chirho: hash_chirho(A_HASH_CHIRHO),
            original_effect_idem_key_chirho: hash_chirho(B_HASH_CHIRHO),
            original_request_digest_chirho: hash_chirho(C_HASH_CHIRHO),
            subject_chirho: hash_chirho(D_HASH_CHIRHO),
            row_key_chirho: hash_chirho(A_HASH_CHIRHO),
            outcome_chirho: PostgresCompensationOutcomeChirho::RestoredChirho {
                restored_state_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            },
        }
    }

    #[test]
    fn request_wire_is_literal_and_exact_chirho() {
        let request_chirho = request_chirho();
        let bytes_chirho = canonical_request_bytes_chirho(&request_chirho).unwrap();
        assert_eq!(
            std::str::from_utf8(&bytes_chirho).unwrap(),
            r#"{"schema_chirho":"reversible-postgres-request-v1-chirho","subject_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","row_key_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","expected_before_chirho":{"kind_chirho":"absent-chirho"},"desired_chirho":{"kind_chirho":"present-chirho","value_ref_chirho":{"ciphertext_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","key_id_chirho":"subject-key-chirho","nonce_chirho":"nonce-chirho","mac_chirho":"mac-chirho","alg_chirho":"xchacha20poly1305+blake3-keyed-mac/v1"}}}"#
        );
        assert_eq!(
            parse_canonical_request_chirho(&bytes_chirho).unwrap(),
            request_chirho
        );
    }

    #[test]
    fn request_malleability_and_app_selected_authority_refuse_chirho() {
        let canonical_chirho =
            String::from_utf8(canonical_request_bytes_chirho(&request_chirho()).unwrap()).unwrap();
        for bytes_chirho in [
            format!(" {canonical_chirho}"),
            format!("{canonical_chirho}\n"),
            canonical_chirho.replacen(
                "\"schema_chirho\"",
                "\"extra_chirho\":true,\"schema_chirho\"",
                1,
            ),
            canonical_chirho.replacen(
                "\"subject_chirho\"",
                "\"subject_chirho\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"subject_chirho\"",
                1,
            ),
            canonical_chirho.replacen(
                "\"schema_chirho\"",
                "\"sql_chirho\":\"drop table x\",\"schema_chirho\"",
                1,
            ),
            canonical_chirho.replacen(
                "\"schema_chirho\"",
                "\"compensation_chirho\":true,\"schema_chirho\"",
                1,
            ),
        ] {
            assert!(parse_canonical_request_chirho(bytes_chirho.as_bytes()).is_err());
        }
        let reordered_chirho = canonical_chirho.replacen(
            r#""schema_chirho":"reversible-postgres-request-v1-chirho","subject_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#,
            r#""subject_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_chirho":"reversible-postgres-request-v1-chirho""#,
            1,
        );
        assert_eq!(
            parse_canonical_request_chirho(reordered_chirho.as_bytes()),
            Err(PostgresWireErrorChirho::NonCanonicalBytesChirho)
        );
    }

    #[test]
    fn invalid_digest_and_private_ref_shapes_refuse_chirho() {
        let mut invalid_digest_request_chirho = request_chirho();
        invalid_digest_request_chirho.subject_chirho = HashChirho("A".repeat(64));
        assert!(matches!(
            canonical_request_bytes_chirho(&invalid_digest_request_chirho),
            Err(PostgresWireErrorChirho::InvalidChirho { .. })
        ));
        let mut malformed_ref_request_chirho = request_chirho();
        let DesiredPostgresStateChirho::PresentChirho { value_ref_chirho } =
            &mut malformed_ref_request_chirho.desired_chirho
        else {
            unreachable!();
        };
        value_ref_chirho.key_id_chirho.clear();
        assert!(matches!(
            canonical_request_bytes_chirho(&malformed_ref_request_chirho),
            Err(PostgresWireErrorChirho::InvalidChirho { .. })
        ));
    }

    #[test]
    fn forward_and_compensation_receipts_have_literal_goldens_chirho() {
        let forward_chirho = forward_receipt_chirho();
        let forward_bytes_chirho = canonical_forward_receipt_bytes_chirho(&forward_chirho).unwrap();
        assert_eq!(
            std::str::from_utf8(&forward_bytes_chirho).unwrap(),
            r#"{"schema_chirho":"reversible-postgres-forward-receipt-v1-chirho","effect_idem_key_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_digest_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","subject_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","row_key_chirho":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","before_state_chirho":{"kind_chirho":"absent-chirho"},"before_image_ref_chirho":null,"post_state_chirho":{"kind_chirho":"keyed-fingerprint-chirho","fingerprint_chirho":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}}"#
        );
        assert_eq!(
            parse_canonical_forward_receipt_chirho(&forward_bytes_chirho).unwrap(),
            forward_chirho
        );

        let compensation_chirho = compensation_receipt_chirho();
        let compensation_bytes_chirho =
            canonical_compensation_receipt_bytes_chirho(&compensation_chirho).unwrap();
        assert_eq!(
            std::str::from_utf8(&compensation_bytes_chirho).unwrap(),
            r#"{"schema_chirho":"reversible-postgres-compensation-receipt-v1-chirho","compensation_idem_key_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","original_effect_idem_key_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","original_request_digest_chirho":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","subject_chirho":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","row_key_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","outcome_chirho":{"kind_chirho":"restored-chirho","restored_state_chirho":{"kind_chirho":"absent-chirho"}}}"#
        );
        assert_eq!(
            parse_canonical_compensation_receipt_chirho(&compensation_bytes_chirho).unwrap(),
            compensation_chirho
        );
    }

    #[test]
    fn forward_terminal_decisions_are_canonical_and_exactly_coordinate_bound_chirho() {
        let effect_key_chirho = format!("cf3-intent-v1-chirho:{A_HASH_CHIRHO}");
        let committed_chirho = ReversiblePostgresCommittedDecisionChirho {
            schema_chirho: REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO.to_string(),
            k_chirho: effect_key_chirho.clone(),
            contract_digest_chirho: hash_chirho(B_HASH_CHIRHO),
            journal_binding_chirho: hash_chirho(C_HASH_CHIRHO),
            forward_receipt_chirho: forward_receipt_chirho(),
            receipt_mac_chirho: hash_chirho(D_HASH_CHIRHO),
        };
        let committed_bytes_chirho =
            canonical_committed_decision_bytes_chirho(&committed_chirho).unwrap();
        assert_eq!(
            parse_canonical_committed_decision_chirho(&committed_bytes_chirho).unwrap(),
            committed_chirho
        );

        let witness_chirho = ReversiblePostgresAbsenceWitnessChirho {
            schema_chirho: EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO.to_string(),
            k_chirho: effect_key_chirho,
            decision_chirho: EffectAbsenceDecisionChirho::DefiniteNoEffectChirho,
            contract_digest_chirho: hash_chirho(B_HASH_CHIRHO),
            journal_binding_chirho: hash_chirho(C_HASH_CHIRHO),
            witness_mac_chirho: hash_chirho(D_HASH_CHIRHO),
        };
        let witness_bytes_chirho = canonical_absence_witness_bytes_chirho(&witness_chirho).unwrap();
        assert_eq!(
            std::str::from_utf8(&witness_bytes_chirho).unwrap(),
            format!(
                r#"{{"schema_chirho":"cairn-effect-absence-witness-v1-chirho","k_chirho":"cf3-intent-v1-chirho:{A_HASH_CHIRHO}","decision_chirho":"definite-no-effect-chirho","contract_digest_chirho":"{B_HASH_CHIRHO}","journal_binding_chirho":"{C_HASH_CHIRHO}","witness_mac_chirho":"{D_HASH_CHIRHO}"}}"#
            )
        );
        assert_eq!(
            parse_canonical_absence_witness_chirho(&witness_bytes_chirho).unwrap(),
            witness_chirho
        );

        let mut mismatched_chirho = committed_chirho;
        mismatched_chirho
            .forward_receipt_chirho
            .effect_idem_key_chirho = hash_chirho(B_HASH_CHIRHO);
        assert!(matches!(
            canonical_committed_decision_bytes_chirho(&mismatched_chirho),
            Err(PostgresWireErrorChirho::InvalidChirho { .. })
        ));
    }

    #[test]
    fn before_image_presence_is_exactly_bound_to_prior_state_chirho() {
        let mut receipt_chirho = forward_receipt_chirho();
        receipt_chirho.before_image_ref_chirho = Some(blob_ref_chirho());
        assert!(matches!(
            canonical_forward_receipt_bytes_chirho(&receipt_chirho),
            Err(PostgresWireErrorChirho::InvalidChirho { .. })
        ));

        receipt_chirho.before_state_chirho = ExpectedPostgresStateChirho::KeyedFingerprintChirho {
            fingerprint_chirho: hash_chirho(F_HASH_CHIRHO),
        };
        assert!(canonical_forward_receipt_bytes_chirho(&receipt_chirho).is_ok());

        receipt_chirho.before_image_ref_chirho = None;
        assert!(matches!(
            canonical_forward_receipt_bytes_chirho(&receipt_chirho),
            Err(PostgresWireErrorChirho::InvalidChirho { .. })
        ));
    }

    #[test]
    fn superseded_compensation_outcome_round_trips_durably_chirho() {
        let mut receipt_chirho = compensation_receipt_chirho();
        receipt_chirho.outcome_chirho = PostgresCompensationOutcomeChirho::SupersededChirho {
            observed_state_chirho: ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: hash_chirho(F_HASH_CHIRHO),
            },
        };
        let bytes_chirho = canonical_compensation_receipt_bytes_chirho(&receipt_chirho).unwrap();
        assert_eq!(
            parse_canonical_compensation_receipt_chirho(&bytes_chirho).unwrap(),
            receipt_chirho
        );
    }
}
