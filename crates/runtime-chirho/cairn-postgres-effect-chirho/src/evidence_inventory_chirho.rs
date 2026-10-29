// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Read-only VERIFIED provider-outcome inventory for evidence consumers (#6058): the stored
//! `decision_kind` column is only a dispatch label, so every forward-decision row's canonical
//! decision bytes are parsed and MAC-verified under the adapter evidence key with embedded-K /
//! row-idempotency binding, and every compensation receipt row is canonically parsed and
//! MAC-verified — a tampered kind, bytes, or MAC fails the inventory instead of false-greening a
//! raw `GROUP BY` count.

use crate::crypto_chirho::{
    verify_absence_witness_mac_chirho, verify_compensation_receipt_mac_chirho,
    AdapterEvidenceKeyChirho,
};
use crate::engine_chirho::verify_committed_decision_row_chirho;
use crate::model_chirho::{
    parse_canonical_absence_witness_chirho, parse_canonical_compensation_receipt_chirho,
    ReversiblePostgresEffectCoordinateChirho,
};
use crate::ports_chirho::{
    AuthenticatedForwardDecisionRowChirho, PostgresForwardDecisionKindChirho,
};
use cairn_core_chirho::model_chirho::HashChirho;

/// Exact VERIFIED outcome counts — every counted row passed canonical parse + MAC + binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderOutcomeInventoryChirho {
    pub committed_decisions_chirho: u64,
    pub definite_no_effect_decisions_chirho: u64,
    pub compensation_receipts_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderOutcomeInventoryErrorChirho {
    DatabaseChirho(String),
    EvidenceChirho(String),
}

impl std::fmt::Display for ProviderOutcomeInventoryErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DatabaseChirho(detail_chirho) => {
                write!(
                    formatter_chirho,
                    "provider inventory database error: {detail_chirho}"
                )
            }
            Self::EvidenceChirho(detail_chirho) => {
                write!(
                    formatter_chirho,
                    "provider inventory evidence refused: {detail_chirho}"
                )
            }
        }
    }
}

impl std::error::Error for ProviderOutcomeInventoryErrorChirho {}

fn database_chirho(error_chirho: postgres::Error) -> ProviderOutcomeInventoryErrorChirho {
    ProviderOutcomeInventoryErrorChirho::DatabaseChirho(error_chirho.to_string())
}

fn evidence_chirho(detail_chirho: &str) -> ProviderOutcomeInventoryErrorChirho {
    ProviderOutcomeInventoryErrorChirho::EvidenceChirho(detail_chirho.to_string())
}

/// Walk EVERY forward-decision and compensation-receipt row and verify each one before counting
/// it. Committed rows reuse the engine's own committed-decision verification (kind vs canonical
/// body, receipt MAC, row/receipt idempotency binding) plus the embedded-K == row-intent-key bind;
/// definite-no-effect rows verify the absence witness MAC and its embedded K; compensation rows
/// verify the receipt MAC and the original-effect binding.
pub fn verified_provider_outcome_inventory_chirho(
    client_chirho: &mut postgres::Client,
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
) -> Result<ProviderOutcomeInventoryChirho, ProviderOutcomeInventoryErrorChirho> {
    let mut committed_chirho: u64 = 0;
    let mut definite_no_effect_chirho: u64 = 0;
    let forward_rows_chirho = client_chirho
        .query(
            "SELECT effect_intent_key_chirho, effect_idem_key_chirho, decision_kind_chirho, \
             decision_bytes_chirho FROM cairn_reversible_forward_decisions_chirho \
             ORDER BY effect_intent_key_chirho",
            &[],
        )
        .map_err(database_chirho)?;
    for row_chirho in forward_rows_chirho {
        let intent_key_chirho: String = row_chirho
            .try_get("effect_intent_key_chirho")
            .map_err(database_chirho)?;
        let idem_key_chirho: String = row_chirho
            .try_get("effect_idem_key_chirho")
            .map_err(database_chirho)?;
        let kind_chirho: String = row_chirho
            .try_get("decision_kind_chirho")
            .map_err(database_chirho)?;
        let decision_bytes_chirho: Vec<u8> = row_chirho
            .try_get("decision_bytes_chirho")
            .map_err(database_chirho)?;
        match kind_chirho.as_str() {
            "committed-chirho" => {
                verify_committed_forward_row_chirho(
                    evidence_key_chirho,
                    &intent_key_chirho,
                    &idem_key_chirho,
                    &decision_bytes_chirho,
                )?;
                committed_chirho = committed_chirho
                    .checked_add(1)
                    .ok_or_else(|| evidence_chirho("committed decision count overflow"))?;
            }
            "definite-no-effect-chirho" => {
                verify_definite_no_effect_forward_row_chirho(
                    evidence_key_chirho,
                    &intent_key_chirho,
                    &idem_key_chirho,
                    &decision_bytes_chirho,
                )?;
                definite_no_effect_chirho = definite_no_effect_chirho
                    .checked_add(1)
                    .ok_or_else(|| evidence_chirho("definite-no-effect count overflow"))?;
            }
            other_chirho => {
                return Err(evidence_chirho(&format!(
                    "unknown forward decision kind '{other_chirho}'"
                )))
            }
        }
    }

    let mut compensation_receipts_chirho: u64 = 0;
    let receipt_rows_chirho = client_chirho
        .query(
            "SELECT compensation_idem_key_chirho, original_effect_idem_key_chirho, \
             receipt_bytes_chirho, receipt_mac_chirho FROM cairn_reversible_comp_receipts_chirho \
             ORDER BY compensation_idem_key_chirho",
            &[],
        )
        .map_err(database_chirho)?;
    for row_chirho in receipt_rows_chirho {
        let compensation_idem_chirho: String = row_chirho
            .try_get("compensation_idem_key_chirho")
            .map_err(database_chirho)?;
        let original_idem_chirho: String = row_chirho
            .try_get("original_effect_idem_key_chirho")
            .map_err(database_chirho)?;
        let receipt_bytes_chirho: Vec<u8> = row_chirho
            .try_get("receipt_bytes_chirho")
            .map_err(database_chirho)?;
        let receipt_mac_chirho: String = row_chirho
            .try_get("receipt_mac_chirho")
            .map_err(database_chirho)?;
        let receipt_chirho = parse_canonical_compensation_receipt_chirho(&receipt_bytes_chirho)
            .map_err(|error_chirho| evidence_chirho(&error_chirho.to_string()))?;
        if !verify_compensation_receipt_mac_chirho(
            evidence_key_chirho,
            &receipt_chirho,
            &HashChirho(receipt_mac_chirho),
        ) {
            return Err(evidence_chirho("compensation receipt MAC mismatch"));
        }
        if receipt_chirho.original_effect_idem_key_chirho.0 != original_idem_chirho {
            return Err(evidence_chirho(
                "compensation receipt original-effect binding does not equal the row column",
            ));
        }
        // Row-PK binding (#6063): the receipt's embedded compensation idempotency key must equal
        // the SELECTED row key — a PK swap preserving bytes+MAC refuses.
        if receipt_chirho.compensation_idem_key_chirho.0 != compensation_idem_chirho {
            return Err(evidence_chirho(
                "compensation receipt embedded idempotency key does not equal the row key",
            ));
        }
        compensation_receipts_chirho = compensation_receipts_chirho
            .checked_add(1)
            .ok_or_else(|| evidence_chirho("compensation receipt count overflow"))?;
    }

    Ok(ProviderOutcomeInventoryChirho {
        committed_decisions_chirho: committed_chirho,
        definite_no_effect_decisions_chirho: definite_no_effect_chirho,
        compensation_receipts_chirho,
    })
}

/// ONE committed forward row's full verification law (#6119, factored so the tamper pins run
/// without PostgreSQL): the engine's canonical-parse + receipt-MAC + row/receipt idem binding,
/// the embedded-K == row intent key bind, and the CANONICAL K->idem derivation == row idem.
pub(crate) fn verify_committed_forward_row_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    intent_key_chirho: &str,
    idem_key_chirho: &str,
    decision_bytes_chirho: &[u8],
) -> Result<(), ProviderOutcomeInventoryErrorChirho> {
    let authenticated_chirho = AuthenticatedForwardDecisionRowChirho {
        effect_idem_key_chirho: HashChirho(idem_key_chirho.to_string()),
        decision_kind_chirho: PostgresForwardDecisionKindChirho::CommittedChirho,
        decision_bytes_chirho: decision_bytes_chirho.to_vec(),
    };
    let (decision_chirho, _, _) =
        verify_committed_decision_row_chirho(evidence_key_chirho, &authenticated_chirho)
            .map_err(|error_chirho| evidence_chirho(&error_chirho.to_string()))?;
    if decision_chirho.k_chirho != intent_key_chirho {
        return Err(evidence_chirho(
            "committed decision embedded K does not equal the row intent key",
        ));
    }
    let coordinate_chirho = ReversiblePostgresEffectCoordinateChirho::new_chirho(
        decision_chirho.k_chirho.clone(),
        decision_chirho.contract_digest_chirho.clone(),
        decision_chirho.journal_binding_chirho.clone(),
    )
    .map_err(|error_chirho| evidence_chirho(&error_chirho.to_string()))?;
    if coordinate_chirho.effect_idem_key_chirho().0 != idem_key_chirho {
        return Err(evidence_chirho(
            "committed row idempotency key does not equal the canonical coordinate derivation",
        ));
    }
    Ok(())
}

/// ONE definite-no-effect forward row's full verification law (#6119, factored): canonical
/// witness parse + MAC, embedded-K == row intent key, and the CANONICAL K->idem derivation ==
/// row idem — a count-preserving idem-column tamper refuses.
pub(crate) fn verify_definite_no_effect_forward_row_chirho(
    evidence_key_chirho: &AdapterEvidenceKeyChirho,
    intent_key_chirho: &str,
    idem_key_chirho: &str,
    decision_bytes_chirho: &[u8],
) -> Result<(), ProviderOutcomeInventoryErrorChirho> {
    let witness_chirho = parse_canonical_absence_witness_chirho(decision_bytes_chirho)
        .map_err(|error_chirho| evidence_chirho(&error_chirho.to_string()))?;
    if !verify_absence_witness_mac_chirho(evidence_key_chirho, &witness_chirho) {
        return Err(evidence_chirho("definite-no-effect witness MAC mismatch"));
    }
    if witness_chirho.k_chirho != intent_key_chirho {
        return Err(evidence_chirho(
            "absence witness embedded K does not equal the row intent key",
        ));
    }
    let coordinate_chirho = ReversiblePostgresEffectCoordinateChirho::new_chirho(
        witness_chirho.k_chirho.clone(),
        witness_chirho.contract_digest_chirho.clone(),
        witness_chirho.journal_binding_chirho.clone(),
    )
    .map_err(|error_chirho| evidence_chirho(&error_chirho.to_string()))?;
    if coordinate_chirho.effect_idem_key_chirho().0 != idem_key_chirho {
        return Err(evidence_chirho(
            "definite-no-effect row idempotency key does not equal the canonical coordinate \
             derivation",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod inventory_row_tests_chirho {
    use super::*;
    use crate::crypto_chirho::{absence_witness_mac_chirho, forward_receipt_mac_chirho};
    use crate::model_chirho::{
        canonical_absence_witness_bytes_chirho, canonical_committed_decision_bytes_chirho,
        EffectAbsenceDecisionChirho, ExpectedPostgresStateChirho,
        ReversiblePostgresAbsenceWitnessChirho, ReversiblePostgresCommittedDecisionChirho,
        ReversiblePostgresForwardReceiptChirho, EFFECT_ABSENCE_WITNESS_DOMAIN_V1_CHIRHO,
        REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO,
        REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO,
    };

    fn hash_chirho(marker_chirho: char) -> HashChirho {
        HashChirho(marker_chirho.to_string().repeat(64))
    }

    fn evidence_key_chirho() -> AdapterEvidenceKeyChirho {
        AdapterEvidenceKeyChirho::new_chirho([7; 32]).unwrap()
    }

    fn authentic_dne_row_chirho() -> (String, String, Vec<u8>) {
        let key_chirho = evidence_key_chirho();
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
        (
            coordinate_chirho.effect_intent_key_chirho().to_string(),
            coordinate_chirho.effect_idem_key_chirho().0.clone(),
            canonical_absence_witness_bytes_chirho(&witness_chirho).unwrap(),
        )
    }

    /// Build a committed row whose RECEIPT carries `idem_override_chirho` (validly MAC'd for that
    /// mutated receipt, decision K unchanged). Source truth (#6128 threading, live-observed): the
    /// CANONICAL CODEC (`validate_committed_decision_chirho`) refuses a receipt idem diverging
    /// from its exact K, so the override variant returns the codec ERROR — the committed branch's
    /// K->idem binding is codec-enforced, and this builder surfaces that refusal for the pin.
    fn committed_row_with_receipt_idem_chirho(
        idem_override_chirho: Option<HashChirho>,
    ) -> (
        String,
        String,
        Result<Vec<u8>, crate::model_chirho::PostgresWireErrorChirho>,
    ) {
        let key_chirho = evidence_key_chirho();
        let coordinate_chirho = ReversiblePostgresEffectCoordinateChirho::new_chirho(
            format!("cf3-intent-v1-chirho:{}", "d".repeat(64)),
            hash_chirho('e'),
            hash_chirho('f'),
        )
        .unwrap();
        let receipt_idem_chirho = idem_override_chirho
            .unwrap_or_else(|| coordinate_chirho.effect_idem_key_chirho().clone());
        let receipt_chirho = ReversiblePostgresForwardReceiptChirho {
            schema_chirho: REVERSIBLE_POSTGRES_FORWARD_RECEIPT_SCHEMA_CHIRHO.to_string(),
            effect_idem_key_chirho: receipt_idem_chirho.clone(),
            request_digest_chirho: hash_chirho('1'),
            subject_chirho: hash_chirho('2'),
            row_key_chirho: hash_chirho('3'),
            before_state_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            before_image_ref_chirho: None,
            post_state_chirho: ExpectedPostgresStateChirho::KeyedFingerprintChirho {
                fingerprint_chirho: hash_chirho('4'),
            },
        };
        let receipt_mac_chirho = forward_receipt_mac_chirho(&key_chirho, &receipt_chirho).unwrap();
        let decision_chirho = ReversiblePostgresCommittedDecisionChirho {
            schema_chirho: REVERSIBLE_POSTGRES_COMMITTED_DECISION_SCHEMA_CHIRHO.to_string(),
            k_chirho: coordinate_chirho.effect_intent_key_chirho().to_string(),
            contract_digest_chirho: coordinate_chirho.contract_digest_chirho().clone(),
            journal_binding_chirho: coordinate_chirho.journal_binding_chirho().clone(),
            forward_receipt_chirho: receipt_chirho,
            receipt_mac_chirho,
        };
        (
            coordinate_chirho.effect_intent_key_chirho().to_string(),
            receipt_idem_chirho.0,
            canonical_committed_decision_bytes_chirho(&decision_chirho),
        )
    }

    fn flipped_hex_chirho(value_chirho: &str) -> String {
        let flipped_chirho = if value_chirho.starts_with('0') {
            "1"
        } else {
            "0"
        };
        format!("{flipped_chirho}{}", &value_chirho[1..])
    }

    /// #6119 sealed mutations, per source truth: an authentic row VERIFIES on both branches; the
    /// DNE row-idem tamper refuses on the NEW inventory derivation (the witness carries no idem —
    /// the real gap); the committed idem tamper is UNREPRESENTABLE as canonical bytes and refuses
    /// at the CODEC ("does not bind its exact effect K"); plus the committed K/intent mismatch.
    #[test]
    fn idem_column_tampers_refuse_on_both_branches_chirho() {
        let key_chirho = evidence_key_chirho();

        let (dne_intent_chirho, dne_idem_chirho, dne_bytes_chirho) = authentic_dne_row_chirho();
        verify_definite_no_effect_forward_row_chirho(
            &key_chirho,
            &dne_intent_chirho,
            &dne_idem_chirho,
            &dne_bytes_chirho,
        )
        .unwrap();
        let tampered_chirho = verify_definite_no_effect_forward_row_chirho(
            &key_chirho,
            &dne_intent_chirho,
            &flipped_hex_chirho(&dne_idem_chirho),
            &dne_bytes_chirho,
        )
        .unwrap_err();
        assert!(tampered_chirho.to_string().contains("canonical coordinate"));

        let (committed_intent_chirho, committed_idem_chirho, committed_bytes_chirho) =
            committed_row_with_receipt_idem_chirho(None);
        let committed_bytes_chirho = committed_bytes_chirho.unwrap();
        verify_committed_forward_row_chirho(
            &key_chirho,
            &committed_intent_chirho,
            &committed_idem_chirho,
            &committed_bytes_chirho,
        )
        .unwrap();
        // #6128 threading, resolved at the SOURCE (live run): on the COMMITTED branch the
        // K->idem binding is enforced by the CANONICAL CODEC itself — a decision whose receipt
        // idem diverges from its K derivation cannot even be constructed/parsed as canonical
        // bytes ("does not bind its exact effect K"). The pin proves that codec guard fires; the
        // DNE branch (whose witness carries NO idem — the real #6119 gap) is pinned below on the
        // NEW inventory derivation.
        let wrong_idem_chirho = HashChirho(flipped_hex_chirho(&committed_idem_chirho));
        let (_intent_chirho, _idem_chirho, tampered_bytes_chirho) =
            committed_row_with_receipt_idem_chirho(Some(wrong_idem_chirho));
        let codec_refusal_chirho = tampered_bytes_chirho.unwrap_err();
        assert!(codec_refusal_chirho
            .to_string()
            .contains("does not bind its exact effect K"));

        // Committed K/intent mismatch (#6119's second mutation) against the authentic bytes.
        let mismatch_chirho = verify_committed_forward_row_chirho(
            &key_chirho,
            &format!("cf3-intent-v1-chirho:{}", "9".repeat(64)),
            &committed_idem_chirho,
            &committed_bytes_chirho,
        )
        .unwrap_err();
        assert!(mismatch_chirho
            .to_string()
            .contains("does not equal the row intent key"));
    }
}
