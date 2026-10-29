// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Transport-neutral F1 verified-prefix bootstrap and recovery source port.
//!
//! The adapter selects a candidate from two holder-signed heads and serves immutable canonical
//! record bytes. A candidate is deliberately not named `Verified`: the resident host still must
//! replay the dense journal chain under its own registry, money laws, genesis, and local base before
//! any staged byte becomes authority-bearing state.

use crate::append_mirror_chirho::LedgerAppendMirrorPortChirho;
use crate::append_mirror_chirho::LedgerAppendMirrorTailChirho;
use crate::journal_chirho::LedgerJournalChirho;
use crate::losing_suffix_chirho::LosingSuffixReaderChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

const MAX_RECOVERY_RECEIPT_BYTES_CHIRHO: usize = 16 * 1024;
const RECOVERY_CANDIDATE_BINDING_DOMAIN_V1_CHIRHO: &[u8] =
    b"ledger-mirror-recovery-candidate-binding-v1-chirho";
const ORDINARY_TERM_ACCEPTANCE_RECEIPT_SCHEMA_V1_CHIRHO: &str =
    "ledger-mirror-ordinary-term-acceptance-receipt-v1-chirho";
const ORDINARY_TERM_ACCEPTANCE_RECEIPT_DOMAIN_V1_CHIRHO: &[u8] =
    b"ledger-mirror-ordinary-term-acceptance-receipt-v1-chirho";
pub const ORDINARY_TERM_ACCEPTANCE_RECEIPT_MAX_BYTES_CHIRHO: usize = 16 * 1024;

/// The inseparable runtime capability set for one F1 mirror composition.
///
/// Shipping composition mints this only after the append, recovery, and ordinary-term adapters have
/// been built over the same placement, elector, follower store, and mesh directory. Keeping the set
/// opaque prevents
/// a resident opener from accidentally retaining mirror-before-ACK while dropping the recovery path,
/// or selecting recovery evidence from a different mirror population.
#[derive(Clone)]
pub struct LedgerMirrorRuntimePortsChirho {
    append_mirror_chirho: Arc<dyn LedgerAppendMirrorPortChirho>,
    recovery_source_chirho: Arc<dyn LedgerMirrorRecoveryPortChirho>,
    ordinary_term_acceptance_source_chirho:
        Arc<dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho>,
    ordinary_term_acceptance_placement_binding_chirho:
        LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
}

impl LedgerMirrorRuntimePortsChirho {
    pub fn new_chirho(
        append_mirror_chirho: Arc<dyn LedgerAppendMirrorPortChirho>,
        recovery_source_chirho: Arc<dyn LedgerMirrorRecoveryPortChirho>,
        ordinary_term_acceptance_source_chirho: Arc<
            dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho,
        >,
        ordinary_term_acceptance_placement_binding_chirho: LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
    ) -> Self {
        Self {
            append_mirror_chirho,
            recovery_source_chirho,
            ordinary_term_acceptance_source_chirho,
            ordinary_term_acceptance_placement_binding_chirho,
        }
    }

    pub fn append_mirror_chirho(&self) -> Arc<dyn LedgerAppendMirrorPortChirho> {
        Arc::clone(&self.append_mirror_chirho)
    }

    pub fn recovery_source_chirho(&self) -> Arc<dyn LedgerMirrorRecoveryPortChirho> {
        Arc::clone(&self.recovery_source_chirho)
    }

    pub fn ordinary_term_acceptance_source_chirho(
        &self,
    ) -> Arc<dyn LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho> {
        Arc::clone(&self.ordinary_term_acceptance_source_chirho)
    }

    pub fn ordinary_term_acceptance_placement_binding_chirho(
        &self,
    ) -> LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho {
        self.ordinary_term_acceptance_placement_binding_chirho
            .clone()
    }
}

/// Raw BLAKE3 digest of a placement-canonical group-id string.
///
/// This mirror-evidence coordinate is intentionally not interchangeable with the tagged
/// writer-fence digest carried by canary evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawCanonicalGroupIdDigestChirho(String);

impl RawCanonicalGroupIdDigestChirho {
    pub fn from_canonical_group_id_chirho(canonical_group_id_chirho: &str) -> Self {
        Self(
            blake3::hash(canonical_group_id_chirho.as_bytes())
                .to_hex()
                .to_string(),
        )
    }

    pub fn from_mirror_evidence_chirho(
        digest_chirho: String,
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        if !is_lower_hex_digest_chirho(&digest_chirho) {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "RawCanonicalGroupIdDigestShapeRefusedChirho",
            ));
        }
        Ok(Self(digest_chirho))
    }

    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }
}

/// One attempt-local nonce minted by the resident before it asks the mirror population for proof.
///
/// The nonce is not authority. Its private representation prevents a transport adapter from
/// replacing the resident's challenge with a convenient old value, and receipts must echo it under
/// both holder signatures. A prior recovery or term-acceptance receipt therefore cannot be replayed
/// into a new fence advance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorOrdinaryTermAcceptanceChallengeChirho(String);

impl LedgerMirrorOrdinaryTermAcceptanceChallengeChirho {
    pub fn from_entropy_chirho(entropy_chirho: [u8; 32]) -> Self {
        Self(lower_hex_bytes_chirho(&entropy_chirho))
    }

    pub fn as_str_chirho(&self) -> &str {
        &self.0
    }
}

/// Immutable local placement coordinates that the receipt pair must match independently.
///
/// Production composition derives this from one verified tenant-placement record and passes it
/// beside the byte-only receipt source. A transport adapter therefore cannot choose a convenient
/// historical assignment and make that assignment authoritative merely because two signatures
/// agree with each other.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho {
    assignment_digest_chirho: String,
    assigned_node_ids_chirho: [String; 3],
}

impl LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho {
    pub fn new_chirho(
        assignment_digest_chirho: String,
        assigned_node_ids_chirho: [String; 3],
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        let unique_nodes_chirho = assigned_node_ids_chirho.iter().collect::<BTreeSet<_>>();
        if !is_lower_hex_digest_chirho(&assignment_digest_chirho)
            || unique_nodes_chirho.len() != 3
            || assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermPlacementBindingShapeRefusedChirho",
            ));
        }
        Ok(Self {
            assignment_digest_chirho,
            assigned_node_ids_chirho,
        })
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn assigned_node_ids_chirho(&self) -> &[String; 3] {
        &self.assigned_node_ids_chirho
    }
}

/// Fields one current holder signs after independently joining election, placement, and its
/// verified live high-water.
///
/// Current and acknowledged coordinates are deliberately separate. The signer must state both,
/// and the transport-neutral verifier requires equality; a current-leader observation cannot hide
/// that the durable ACK belonged to another term, view, assignment, or leader.
pub struct LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho {
    pub challenge_nonce_hex_chirho: String,
    pub current_consistency_group_digest_chirho: String,
    pub current_assignment_digest_chirho: String,
    pub current_assigned_node_ids_chirho: [String; 3],
    pub current_leader_node_id_chirho: String,
    pub current_membership_view_digest_chirho: String,
    pub current_term_chirho: u64,
    pub acknowledged_consistency_group_digest_chirho: String,
    pub acknowledged_assignment_digest_chirho: String,
    pub acknowledged_assigned_node_ids_chirho: [String; 3],
    pub acknowledged_leader_node_id_chirho: String,
    pub acknowledged_membership_view_digest_chirho: String,
    pub acknowledged_term_chirho: u64,
    pub holder_node_id_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: String,
    pub tail_epoch_chirho: u64,
    pub tail_hlc_physical_ms_chirho: u64,
    pub tail_hlc_logical_chirho: u32,
}

/// Fresh, domain-separated holder statement used only to derive an ordinary-election sink proof.
///
/// This is not a recovery receipt and no recovery decoder accepts it. It carries no signer, mesh,
/// append, effect, resident, or fence capability. Its only semantic claim is that this holder,
/// while independently observing the named current leader/view, retains the exact live high-water
/// that authorized the acknowledged tail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerMirrorOrdinaryTermAcceptanceReceiptChirho {
    schema_chirho: String,
    challenge_nonce_hex_chirho: String,
    current_consistency_group_digest_chirho: String,
    current_assignment_digest_chirho: String,
    current_assigned_node_ids_chirho: [String; 3],
    current_leader_node_id_chirho: String,
    current_membership_view_digest_chirho: String,
    current_term_chirho: u64,
    acknowledged_consistency_group_digest_chirho: String,
    acknowledged_assignment_digest_chirho: String,
    acknowledged_assigned_node_ids_chirho: [String; 3],
    acknowledged_leader_node_id_chirho: String,
    acknowledged_membership_view_digest_chirho: String,
    acknowledged_term_chirho: u64,
    holder_node_id_chirho: String,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: String,
    tail_epoch_chirho: u64,
    tail_hlc_physical_ms_chirho: u64,
    tail_hlc_logical_chirho: u32,
    receipt_digest_chirho: String,
    sig_hex_chirho: String,
}

impl LedgerMirrorOrdinaryTermAcceptanceReceiptChirho {
    pub fn sign_chirho(
        input_chirho: LedgerMirrorOrdinaryTermAcceptanceReceiptInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        let mut receipt_chirho = Self {
            schema_chirho: ORDINARY_TERM_ACCEPTANCE_RECEIPT_SCHEMA_V1_CHIRHO.to_owned(),
            challenge_nonce_hex_chirho: input_chirho.challenge_nonce_hex_chirho,
            current_consistency_group_digest_chirho: input_chirho
                .current_consistency_group_digest_chirho,
            current_assignment_digest_chirho: input_chirho.current_assignment_digest_chirho,
            current_assigned_node_ids_chirho: input_chirho.current_assigned_node_ids_chirho,
            current_leader_node_id_chirho: input_chirho.current_leader_node_id_chirho,
            current_membership_view_digest_chirho: input_chirho
                .current_membership_view_digest_chirho,
            current_term_chirho: input_chirho.current_term_chirho,
            acknowledged_consistency_group_digest_chirho: input_chirho
                .acknowledged_consistency_group_digest_chirho,
            acknowledged_assignment_digest_chirho: input_chirho
                .acknowledged_assignment_digest_chirho,
            acknowledged_assigned_node_ids_chirho: input_chirho
                .acknowledged_assigned_node_ids_chirho,
            acknowledged_leader_node_id_chirho: input_chirho.acknowledged_leader_node_id_chirho,
            acknowledged_membership_view_digest_chirho: input_chirho
                .acknowledged_membership_view_digest_chirho,
            acknowledged_term_chirho: input_chirho.acknowledged_term_chirho,
            holder_node_id_chirho: input_chirho.holder_node_id_chirho,
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            tail_seq_chirho: input_chirho.tail_seq_chirho,
            tail_record_digest_chirho: input_chirho.tail_record_digest_chirho,
            tail_epoch_chirho: input_chirho.tail_epoch_chirho,
            tail_hlc_physical_ms_chirho: input_chirho.tail_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: input_chirho.tail_hlc_logical_chirho,
            receipt_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        receipt_chirho.validate_shape_chirho()?;
        let digest_chirho = receipt_chirho.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )
            .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptSigningRefusedChirho"))?;
        if possession_chirho.key_id_chirho() != receipt_chirho.holder_node_id_chirho {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptSignerIdentityRefusedChirho",
            ));
        }
        receipt_chirho.receipt_digest_chirho = digest_chirho.to_hex().to_string();
        receipt_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(receipt_chirho)
    }

    pub fn decode_and_verify_chirho(
        bytes_chirho: &[u8],
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        if bytes_chirho.len() > ORDINARY_TERM_ACCEPTANCE_RECEIPT_MAX_BYTES_CHIRHO {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTooLargeChirho",
            ));
        }
        let receipt_chirho: Self = serde_json::from_slice(bytes_chirho)
            .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptMalformedChirho"))?;
        let canonical_chirho = serde_json::to_vec(&receipt_chirho)
            .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptEncodingRefusedChirho"))?;
        if canonical_chirho != bytes_chirho {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptNonCanonicalChirho",
            ));
        }
        receipt_chirho.validate_shape_chirho()?;
        let digest_chirho = receipt_chirho.compute_digest_chirho()?;
        let signature_valid_chirho = cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
            &receipt_chirho.holder_node_id_chirho,
            digest_chirho.as_bytes(),
            &receipt_chirho.sig_hex_chirho,
        )
        .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptSignatureRefusedChirho"))?;
        if receipt_chirho.receipt_digest_chirho != digest_chirho.to_hex().as_str()
            || !signature_valid_chirho
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptSignatureRefusedChirho",
            ));
        }
        Ok(receipt_chirho)
    }

    pub fn to_wire_bytes_chirho(&self) -> Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho> {
        let bytes_chirho = serde_json::to_vec(self)
            .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptEncodingRefusedChirho"))?;
        if bytes_chirho.len() > ORDINARY_TERM_ACCEPTANCE_RECEIPT_MAX_BYTES_CHIRHO {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTooLargeChirho",
            ));
        }
        Ok(bytes_chirho)
    }

    fn validate_shape_chirho(&self) -> Result<(), LedgerMirrorRecoveryPortErrorChirho> {
        let current_nodes_chirho = self
            .current_assigned_node_ids_chirho
            .iter()
            .collect::<BTreeSet<_>>();
        let acknowledged_nodes_chirho = self
            .acknowledged_assigned_node_ids_chirho
            .iter()
            .collect::<BTreeSet<_>>();
        if self.schema_chirho != ORDINARY_TERM_ACCEPTANCE_RECEIPT_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.challenge_nonce_hex_chirho)
            || !is_lower_hex_digest_chirho(&self.current_consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.current_assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.current_membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.acknowledged_consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.acknowledged_assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.acknowledged_membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.current_leader_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.acknowledged_leader_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.holder_node_id_chirho)
            || !is_lower_hex_digest_chirho(&self.journal_genesis_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.tail_record_digest_chirho)
            || self.current_term_chirho == 0
            || self.acknowledged_term_chirho == 0
            || self.cluster_id_chirho.is_empty()
            || self.cluster_id_chirho.len() > 256
            || self.tail_seq_chirho == 0
            || self.tail_epoch_chirho == 0
            || self.tail_hlc_physical_ms_chirho == 0
            || current_nodes_chirho.len() != 3
            || acknowledged_nodes_chirho.len() != 3
            || !current_nodes_chirho.contains(&self.current_leader_node_id_chirho)
            || !current_nodes_chirho.contains(&self.holder_node_id_chirho)
            || !acknowledged_nodes_chirho.contains(&self.acknowledged_leader_node_id_chirho)
            || !acknowledged_nodes_chirho.contains(&self.holder_node_id_chirho)
            || self.current_leader_node_id_chirho == self.holder_node_id_chirho
            || self.acknowledged_leader_node_id_chirho == self.holder_node_id_chirho
            || (!self.receipt_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.receipt_digest_chirho))
            || (self.receipt_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptShapeRefusedChirho",
            ));
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash, LedgerMirrorRecoveryPortErrorChirho> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.receipt_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)
            .map_err(|_| ordinary_term_error_chirho("OrdinaryTermReceiptEncodingRefusedChirho"))?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(ORDINARY_TERM_ACCEPTANCE_RECEIPT_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }
}

pub struct LedgerMirrorOrdinaryTermAcceptanceExpectationChirho<'expectation_chirho> {
    pub challenge_chirho: &'expectation_chirho LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
    pub consistency_group_digest_chirho: &'expectation_chirho RawCanonicalGroupIdDigestChirho,
    pub placement_binding_chirho:
        &'expectation_chirho LedgerMirrorOrdinaryTermAcceptancePlacementBindingChirho,
    pub local_leader_node_id_chirho: &'expectation_chirho str,
    pub published_raft_term_chirho: u64,
    pub local_tail_chirho: &'expectation_chirho LedgerAppendMirrorTailChirho,
}

/// Private-field proof that the complete two-holder ACK population freshly re-attested the exact
/// current local tail while the resident held one local leadership generation.
///
/// The receipts alone do not grant current authority. The resident supplies the nonce, expected
/// leader, exact tail, and held generation term, and this constructor verifies every signature and
/// equality before minting the value. There is no deserializer, `From`, default, or public field.
pub struct VerifiedOrdinaryElectionSinkTermAcceptanceChirho {
    consistency_group_digest_chirho: RawCanonicalGroupIdDigestChirho,
    accepted_term_chirho: u64,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: String,
    holder_receipt_digests_chirho: [String; 2],
}

impl VerifiedOrdinaryElectionSinkTermAcceptanceChirho {
    pub fn verify_chirho(
        receipt_wires_chirho: &[Vec<u8>; 2],
        expectation_chirho: LedgerMirrorOrdinaryTermAcceptanceExpectationChirho<'_>,
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        let first_chirho =
            LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::decode_and_verify_chirho(
                &receipt_wires_chirho[0],
            )?;
        let second_chirho =
            LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::decode_and_verify_chirho(
                &receipt_wires_chirho[1],
            )?;
        let common_binding_chirho = first_chirho.challenge_nonce_hex_chirho
            == second_chirho.challenge_nonce_hex_chirho
            && first_chirho.current_consistency_group_digest_chirho
                == second_chirho.current_consistency_group_digest_chirho
            && first_chirho.current_assignment_digest_chirho
                == second_chirho.current_assignment_digest_chirho
            && first_chirho.current_assigned_node_ids_chirho
                == second_chirho.current_assigned_node_ids_chirho
            && first_chirho.current_leader_node_id_chirho
                == second_chirho.current_leader_node_id_chirho
            && first_chirho.current_membership_view_digest_chirho
                == second_chirho.current_membership_view_digest_chirho
            && first_chirho.current_term_chirho == second_chirho.current_term_chirho
            && first_chirho.acknowledged_consistency_group_digest_chirho
                == second_chirho.acknowledged_consistency_group_digest_chirho
            && first_chirho.acknowledged_assignment_digest_chirho
                == second_chirho.acknowledged_assignment_digest_chirho
            && first_chirho.acknowledged_assigned_node_ids_chirho
                == second_chirho.acknowledged_assigned_node_ids_chirho
            && first_chirho.acknowledged_leader_node_id_chirho
                == second_chirho.acknowledged_leader_node_id_chirho
            && first_chirho.acknowledged_membership_view_digest_chirho
                == second_chirho.acknowledged_membership_view_digest_chirho
            && first_chirho.acknowledged_term_chirho == second_chirho.acknowledged_term_chirho
            && first_chirho.cluster_id_chirho == second_chirho.cluster_id_chirho
            && first_chirho.journal_genesis_digest_chirho
                == second_chirho.journal_genesis_digest_chirho
            && first_chirho.tail_seq_chirho == second_chirho.tail_seq_chirho
            && first_chirho.tail_record_digest_chirho == second_chirho.tail_record_digest_chirho
            && first_chirho.tail_epoch_chirho == second_chirho.tail_epoch_chirho
            && first_chirho.tail_hlc_physical_ms_chirho
                == second_chirho.tail_hlc_physical_ms_chirho
            && first_chirho.tail_hlc_logical_chirho == second_chirho.tail_hlc_logical_chirho;
        if !common_binding_chirho {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptPairBindingMismatchRefusedChirho",
            ));
        }
        if first_chirho.current_consistency_group_digest_chirho
            != first_chirho.acknowledged_consistency_group_digest_chirho
            || first_chirho.current_assignment_digest_chirho
                != first_chirho.acknowledged_assignment_digest_chirho
            || first_chirho.current_assigned_node_ids_chirho
                != first_chirho.acknowledged_assigned_node_ids_chirho
            || first_chirho.current_leader_node_id_chirho
                != first_chirho.acknowledged_leader_node_id_chirho
            || first_chirho.current_membership_view_digest_chirho
                != first_chirho.acknowledged_membership_view_digest_chirho
            || first_chirho.current_term_chirho != first_chirho.acknowledged_term_chirho
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptCurrentAcknowledgedAuthorityMismatchRefusedChirho",
            ));
        }
        if first_chirho.current_assignment_digest_chirho
            != expectation_chirho
                .placement_binding_chirho
                .assignment_digest_chirho()
            || &first_chirho.current_assigned_node_ids_chirho
                != expectation_chirho
                    .placement_binding_chirho
                    .assigned_node_ids_chirho()
            || !expectation_chirho
                .placement_binding_chirho
                .assigned_node_ids_chirho()
                .iter()
                .any(|node_id_chirho| {
                    node_id_chirho == expectation_chirho.local_leader_node_id_chirho
                })
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptExpectedPlacementBindingRefusedChirho",
            ));
        }
        let expected_holders_chirho = expectation_chirho
            .placement_binding_chirho
            .assigned_node_ids_chirho()
            .iter()
            .filter(|node_id_chirho| {
                node_id_chirho.as_str() != expectation_chirho.local_leader_node_id_chirho
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let observed_holders_chirho = [
            first_chirho.holder_node_id_chirho.clone(),
            second_chirho.holder_node_id_chirho.clone(),
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        if expected_holders_chirho.len() != 2 || observed_holders_chirho != expected_holders_chirho
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptHolderPopulationRefusedChirho",
            ));
        }
        if first_chirho.challenge_nonce_hex_chirho
            != expectation_chirho.challenge_chirho.as_str_chirho()
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptChallengeMismatchRefusedChirho",
            ));
        }
        if first_chirho.current_consistency_group_digest_chirho
            != expectation_chirho
                .consistency_group_digest_chirho
                .as_str_chirho()
            || first_chirho.current_leader_node_id_chirho
                != expectation_chirho.local_leader_node_id_chirho
            || first_chirho.current_term_chirho != expectation_chirho.published_raft_term_chirho
            || first_chirho.cluster_id_chirho
                != expectation_chirho.local_tail_chirho.cluster_id_chirho().0
            || first_chirho.journal_genesis_digest_chirho
                != expectation_chirho
                    .local_tail_chirho
                    .journal_genesis_digest_chirho()
                    .0
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptExpectedAuthorityBindingRefusedChirho",
            ));
        }
        let local_tail_chirho = expectation_chirho.local_tail_chirho;
        if first_chirho.tail_seq_chirho < local_tail_chirho.tail_seq_chirho() {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTailBehindRefusedChirho",
            ));
        }
        if first_chirho.tail_seq_chirho > local_tail_chirho.tail_seq_chirho() {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTailAheadRefusedChirho",
            ));
        }
        if first_chirho.tail_record_digest_chirho != local_tail_chirho.tail_record_digest_chirho().0
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTailDivergenceRefusedChirho",
            ));
        }
        if first_chirho.tail_epoch_chirho != local_tail_chirho.tail_record_epoch_chirho()
            || first_chirho.tail_hlc_physical_ms_chirho
                != local_tail_chirho.tail_hlc_chirho().physical_ms_chirho
            || first_chirho.tail_hlc_logical_chirho
                != local_tail_chirho.tail_hlc_chirho().logical_chirho
        {
            return Err(ordinary_term_error_chirho(
                "OrdinaryTermReceiptTailCoordinateRefusedChirho",
            ));
        }
        Ok(Self {
            consistency_group_digest_chirho: expectation_chirho
                .consistency_group_digest_chirho
                .clone(),
            accepted_term_chirho: first_chirho.current_term_chirho,
            tail_seq_chirho: first_chirho.tail_seq_chirho,
            tail_record_digest_chirho: first_chirho.tail_record_digest_chirho,
            holder_receipt_digests_chirho: [
                first_chirho.receipt_digest_chirho,
                second_chirho.receipt_digest_chirho,
            ],
        })
    }

    pub fn consistency_group_digest_chirho(&self) -> &RawCanonicalGroupIdDigestChirho {
        &self.consistency_group_digest_chirho
    }

    pub fn accepted_term_chirho(&self) -> u64 {
        self.accepted_term_chirho
    }

    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }

    pub fn tail_record_digest_chirho(&self) -> &str {
        &self.tail_record_digest_chirho
    }

    pub fn holder_receipt_digests_chirho(&self) -> &[String; 2] {
        &self.holder_receipt_digests_chirho
    }
}

/// Narrow transport boundary for a fresh exact two-holder receipt pair.
///
/// The implementor receives no fence, signer, writer lock, resident, or proof constructor. It can
/// return only bytes. The resident independently verifies those bytes before the fourth mover can
/// name a private proof.
pub trait LedgerMirrorOrdinaryTermAcceptanceEvidenceSourceChirho: Send + Sync {
    fn read_ordinary_term_acceptance_receipts_chirho(
        &self,
        challenge_chirho: &LedgerMirrorOrdinaryTermAcceptanceChallengeChirho,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
    ) -> Result<[Vec<u8>; 2], LedgerMirrorRecoveryPortErrorChirho>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorRecoveryCandidateChirho {
    consistency_group_digest_chirho: RawCanonicalGroupIdDigestChirho,
    assignment_digest_chirho: String,
    historical_leader_node_id_chirho: String,
    holder_node_ids_chirho: [String; 2],
    historical_term_chirho: u64,
    historical_membership_view_digest_chirho: String,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    tail_seq_chirho: u64,
    tail_record_digest_chirho: String,
    tail_epoch_chirho: u64,
    tail_hlc_chirho: HlcChirho,
    current_term_chirho: u64,
    current_membership_view_digest_chirho: String,
    holder_receipt_digests_chirho: [String; 2],
    holder_receipt_wires_chirho: [Vec<u8>; 2],
}

pub struct LedgerMirrorRecoveryCandidateInputChirho {
    pub consistency_group_digest_chirho: RawCanonicalGroupIdDigestChirho,
    pub assignment_digest_chirho: String,
    pub historical_leader_node_id_chirho: String,
    pub holder_node_ids_chirho: [String; 2],
    pub historical_term_chirho: u64,
    pub historical_membership_view_digest_chirho: String,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub tail_seq_chirho: u64,
    pub tail_record_digest_chirho: String,
    pub tail_epoch_chirho: u64,
    pub tail_hlc_chirho: HlcChirho,
    pub current_term_chirho: u64,
    pub current_membership_view_digest_chirho: String,
    pub holder_receipt_digests_chirho: [String; 2],
    pub holder_receipt_wires_chirho: [Vec<u8>; 2],
}

impl LedgerMirrorRecoveryCandidateChirho {
    /// Construct a still-untrusted host candidate from adapter-verified evidence.
    ///
    /// Production relies on exact implementation selection for the adapter checks. The host then
    /// independently replay-verifies the records; this constructor intentionally grants no cut.
    pub fn from_port_evidence_chirho(
        input_chirho: LedgerMirrorRecoveryCandidateInputChirho,
    ) -> Result<Self, LedgerMirrorRecoveryPortErrorChirho> {
        if !is_lower_hex_digest_chirho(&input_chirho.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&input_chirho.historical_leader_node_id_chirho)
            || input_chirho
                .holder_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || input_chirho.holder_node_ids_chirho[0] == input_chirho.holder_node_ids_chirho[1]
            || input_chirho
                .holder_node_ids_chirho
                .iter()
                .any(|node_id_chirho| {
                    node_id_chirho == &input_chirho.historical_leader_node_id_chirho
                })
            || input_chirho.historical_term_chirho == 0
            || !is_lower_hex_digest_chirho(&input_chirho.historical_membership_view_digest_chirho)
            || input_chirho.cluster_id_chirho.is_empty()
            || input_chirho.cluster_id_chirho.len() > 256
            || !is_lower_hex_digest_chirho(&input_chirho.journal_genesis_digest_chirho)
            || input_chirho.tail_seq_chirho == 0
            || !is_lower_hex_digest_chirho(&input_chirho.tail_record_digest_chirho)
            || input_chirho.tail_epoch_chirho == 0
            || input_chirho.tail_hlc_chirho.physical_ms_chirho == 0
            || input_chirho.current_term_chirho == 0
            || !is_lower_hex_digest_chirho(&input_chirho.current_membership_view_digest_chirho)
            || input_chirho
                .holder_receipt_digests_chirho
                .iter()
                .any(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || input_chirho.holder_receipt_digests_chirho[0]
                == input_chirho.holder_receipt_digests_chirho[1]
            || input_chirho
                .holder_receipt_wires_chirho
                .iter()
                .any(|wire_chirho| {
                    wire_chirho.is_empty() || wire_chirho.len() > MAX_RECOVERY_RECEIPT_BYTES_CHIRHO
                })
        {
            return Err(LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorRecoveryCandidateShapeRefusedChirho",
            ));
        }
        Ok(Self {
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            historical_leader_node_id_chirho: input_chirho.historical_leader_node_id_chirho,
            holder_node_ids_chirho: input_chirho.holder_node_ids_chirho,
            historical_term_chirho: input_chirho.historical_term_chirho,
            historical_membership_view_digest_chirho: input_chirho
                .historical_membership_view_digest_chirho,
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            tail_seq_chirho: input_chirho.tail_seq_chirho,
            tail_record_digest_chirho: input_chirho.tail_record_digest_chirho,
            tail_epoch_chirho: input_chirho.tail_epoch_chirho,
            tail_hlc_chirho: input_chirho.tail_hlc_chirho,
            current_term_chirho: input_chirho.current_term_chirho,
            current_membership_view_digest_chirho: input_chirho
                .current_membership_view_digest_chirho,
            holder_receipt_digests_chirho: input_chirho.holder_receipt_digests_chirho,
            holder_receipt_wires_chirho: input_chirho.holder_receipt_wires_chirho,
        })
    }

    pub fn consistency_group_digest_chirho(&self) -> &RawCanonicalGroupIdDigestChirho {
        &self.consistency_group_digest_chirho
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn historical_leader_node_id_chirho(&self) -> &str {
        &self.historical_leader_node_id_chirho
    }

    pub fn holder_node_ids_chirho(&self) -> &[String; 2] {
        &self.holder_node_ids_chirho
    }

    pub fn historical_term_chirho(&self) -> u64 {
        self.historical_term_chirho
    }

    pub fn historical_membership_view_digest_chirho(&self) -> &str {
        &self.historical_membership_view_digest_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &str {
        &self.journal_genesis_digest_chirho
    }

    pub fn cluster_id_chirho(&self) -> &str {
        &self.cluster_id_chirho
    }

    pub fn tail_seq_chirho(&self) -> u64 {
        self.tail_seq_chirho
    }

    pub fn tail_record_digest_chirho(&self) -> &str {
        &self.tail_record_digest_chirho
    }

    pub fn tail_epoch_chirho(&self) -> u64 {
        self.tail_epoch_chirho
    }

    pub fn tail_hlc_chirho(&self) -> &HlcChirho {
        &self.tail_hlc_chirho
    }

    pub fn current_term_chirho(&self) -> u64 {
        self.current_term_chirho
    }

    pub fn current_membership_view_digest_chirho(&self) -> &str {
        &self.current_membership_view_digest_chirho
    }

    pub fn holder_receipt_wires_chirho(&self) -> &[Vec<u8>; 2] {
        &self.holder_receipt_wires_chirho
    }

    pub fn holder_receipt_digests_chirho(&self) -> &[String; 2] {
        &self.holder_receipt_digests_chirho
    }

    /// Stable historical-content binding for inert candidate paths and the later signed canary
    /// generation. Current election term/view are deliberately excluded: they authorize an attempt,
    /// but they do not change which imported bytes and holder evidence that attempt names. A restart
    /// in a newer term must be able to revalidate authority and finish the same committed candidate.
    pub fn binding_digest_chirho(&self) -> String {
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(RECOVERY_CANDIDATE_BINDING_DOMAIN_V1_CHIRHO);
        update_binding_field_chirho(
            &mut hasher_chirho,
            self.consistency_group_digest_chirho
                .as_str_chirho()
                .as_bytes(),
        );
        update_binding_field_chirho(&mut hasher_chirho, self.assignment_digest_chirho.as_bytes());
        update_binding_field_chirho(
            &mut hasher_chirho,
            self.historical_leader_node_id_chirho.as_bytes(),
        );
        for holder_node_id_chirho in &self.holder_node_ids_chirho {
            update_binding_field_chirho(&mut hasher_chirho, holder_node_id_chirho.as_bytes());
        }
        hasher_chirho.update(&self.historical_term_chirho.to_le_bytes());
        update_binding_field_chirho(
            &mut hasher_chirho,
            self.historical_membership_view_digest_chirho.as_bytes(),
        );
        update_binding_field_chirho(&mut hasher_chirho, self.cluster_id_chirho.as_bytes());
        update_binding_field_chirho(
            &mut hasher_chirho,
            self.journal_genesis_digest_chirho.as_bytes(),
        );
        hasher_chirho.update(&self.tail_seq_chirho.to_le_bytes());
        update_binding_field_chirho(
            &mut hasher_chirho,
            self.tail_record_digest_chirho.as_bytes(),
        );
        hasher_chirho.update(&self.tail_epoch_chirho.to_le_bytes());
        hasher_chirho.update(&self.tail_hlc_chirho.physical_ms_chirho.to_le_bytes());
        hasher_chirho.update(&self.tail_hlc_chirho.logical_chirho.to_le_bytes());
        for receipt_digest_chirho in &self.holder_receipt_digests_chirho {
            update_binding_field_chirho(&mut hasher_chirho, receipt_digest_chirho.as_bytes());
        }
        for receipt_wire_chirho in &self.holder_receipt_wires_chirho {
            update_binding_field_chirho(&mut hasher_chirho, receipt_wire_chirho);
        }
        hasher_chirho.finalize().to_hex().to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMirrorRecoveryPortErrorChirho {
    detail_chirho: String,
}

impl LedgerMirrorRecoveryPortErrorChirho {
    pub fn new_chirho(detail_chirho: impl Into<String>) -> Self {
        Self {
            detail_chirho: detail_chirho.into(),
        }
    }

    pub fn detail_chirho(&self) -> &str {
        &self.detail_chirho
    }
}

impl std::fmt::Display for LedgerMirrorRecoveryPortErrorChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str(&self.detail_chirho)
    }
}

impl std::error::Error for LedgerMirrorRecoveryPortErrorChirho {}

/// Read/bootstrap-only recovery boundary. It grants no journal signer, append, effect, or resident
/// authority. Imported bytes stay inert until the host replay-verifies and commits continuity.
pub trait LedgerMirrorRecoveryPortChirho: Send + Sync {
    /// Select evidence relative to the exact full-open journal that minted `local_tail_chirho`.
    /// The read-only source lets an adapter prove that a strictly older local holder head is an
    /// authenticated canonical anchor before excluding that head as stale.
    fn select_recovery_candidate_chirho(
        &self,
        local_tail_chirho: &LedgerAppendMirrorTailChirho,
        local_source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<Option<LedgerMirrorRecoveryCandidateChirho>, LedgerMirrorRecoveryPortErrorChirho>;

    /// Refuse unless the candidate's authority still matches the current elected view.
    ///
    /// A recovery attempt calls this before it acquires the local leadership guard and again while it
    /// holds that guard (A6-c). It must only read. Anything that waits for local append admission, such
    /// as a Raft transition or an authenticated-roster update, would wait for the caller's own guard.
    fn revalidate_recovery_authority_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho>;

    fn read_recovery_record_chirho(
        &self,
        candidate_chirho: &LedgerMirrorRecoveryCandidateChirho,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> Result<Vec<u8>, LedgerMirrorRecoveryPortErrorChirho>;

    fn ensure_verified_prefix_bootstrapped_chirho(
        &self,
        source_tail_chirho: &LedgerAppendMirrorTailChirho,
        source_chirho: &dyn LedgerMirrorPrefixSourceChirho,
    ) -> Result<(), LedgerMirrorRecoveryPortErrorChirho>;
}

/// Full-open read source for one complete mirror prefix. Fast-open journals intentionally cannot
/// mint this capability because a rotated fast path does not re-read the canonical genesis bytes.
pub trait LedgerMirrorPrefixSourceChirho: LosingSuffixReaderChirho {
    fn canonical_genesis_line_chirho(&self) -> Result<String, LedgerMirrorRecoveryPortErrorChirho>;
}

impl LedgerMirrorPrefixSourceChirho for LedgerJournalChirho<'_> {
    fn canonical_genesis_line_chirho(&self) -> Result<String, LedgerMirrorRecoveryPortErrorChirho> {
        self.canonical_genesis_line_chirho.clone().ok_or_else(|| {
            LedgerMirrorRecoveryPortErrorChirho::new_chirho(
                "LedgerMirrorPrefixSourceRequiresFullOpenChirho",
            )
        })
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn lower_hex_bytes_chirho(bytes_chirho: &[u8]) -> String {
    const HEX_CHIRHO: &[u8; 16] = b"0123456789abcdef";
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho >> 4) as usize] as char);
        encoded_chirho.push(HEX_CHIRHO[(byte_chirho & 0x0f) as usize] as char);
    }
    encoded_chirho
}

fn ordinary_term_error_chirho(detail_chirho: &'static str) -> LedgerMirrorRecoveryPortErrorChirho {
    LedgerMirrorRecoveryPortErrorChirho::new_chirho(detail_chirho)
}

fn update_binding_field_chirho(hasher_chirho: &mut blake3::Hasher, bytes_chirho: &[u8]) {
    hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
    hasher_chirho.update(bytes_chirho);
}
