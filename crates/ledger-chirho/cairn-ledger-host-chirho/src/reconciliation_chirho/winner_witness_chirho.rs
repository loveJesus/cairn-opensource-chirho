// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! O(1)-addressed winner term-first records and identity-bound GD7 fork witnesses.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf8-gd7-deposed-fork-reconciliation-design-chirho.md`.

use super::contract_chirho::{
    consistency_group_digest_suffix_chirho, is_lower_hex_digest_chirho, validate_identity_chirho,
    Gd7LedgerRecordVerifierPortChirho, Gd7ReconciliationIdentityChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
};
use super::store_chirho::gd7_reconciliation_identity_digest_chirho;
use cairn_ledger_log_chirho::epoch_first_record_chirho::{
    EpochFirstRecordEvidenceChirho, MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::VerifiedLosingJournalTailChirho;
use cairn_ledger_log_chirho::ports_chirho::{
    CreateDurableOutcomeChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::record_chirho::LedgerRecordChirho;
use cairn_ledger_model_chirho::wire_chirho::{
    canonical_ledger_record_line_chirho, ledger_record_signed_content_line_chirho,
    stored_line_digest_chirho,
};
use cairn_writer_head_chirho::writer_head_chirho::split_writer_epoch_chirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub const GD7_WINNER_FIRST_RECORD_SCHEMA_V1_CHIRHO: &str = "gd7-winner-first-record-v1-chirho";
pub const GD7_WINNER_FORK_WITNESS_SCHEMA_V1_CHIRHO: &str = "gd7-winner-fork-witness-v1-chirho";
const GD7_WINNER_OBSERVATION_SLOT_SCHEMA_V1_CHIRHO: &str = "gd7-winner-observation-slot-v1-chirho";
pub const MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO: usize = 272 * 1024;
pub const MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO: usize = 16 * 1024;
const MAX_GD7_WINNER_OBSERVATION_SLOT_BYTES_CHIRHO: usize = 4 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerFirstRecordCoordinateChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    winner_journal_genesis_digest_chirho: String,
    winner_term_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerObservationSlotCoordinateChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    winner_node_chirho: String,
    winner_term_chirho: u64,
    held_node_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gd7WinnerObservationSlotChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    winner_node_chirho: String,
    winner_term_chirho: u64,
    held_node_chirho: String,
    selected_reconciliation_identity_digest_chirho: String,
    key_id_chirho: String,
    sig_chirho: String,
}

/// One node-signed O(1) lookup of the exact first committed record in a geo term.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerFirstRecordIndexChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub winner_term_chirho: u64,
    pub winner_journal_genesis_digest_chirho: String,
    pub first_record_digest_chirho: String,
    pub first_record_chirho: LedgerRecordChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

/// One winner-signed binding from an authoritative term-first record to a losing fork identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7WinnerForkWitnessChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7ReconciliationIdentityChirho,
    pub winner_first_record_index_coordinate_digest_chirho: String,
    pub winner_first_record_index_object_digest_chirho: String,
    pub winner_first_record_epoch_chirho: u64,
    pub winner_first_record_seq_chirho: u64,
    pub winner_first_record_digest_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7WinnerFirstRecordIndexChirho {
    coordinate_digest_chirho: String,
    object_digest_chirho: String,
    index_chirho: Gd7WinnerFirstRecordIndexChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedGd7WinnerForkWitnessChirho {
    object_digest_chirho: String,
    witness_chirho: Gd7WinnerForkWitnessChirho,
}

impl VerifiedGd7WinnerFirstRecordIndexChirho {
    pub fn coordinate_digest_chirho(&self) -> &str {
        &self.coordinate_digest_chirho
    }

    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn index_chirho(&self) -> &Gd7WinnerFirstRecordIndexChirho {
        &self.index_chirho
    }
}

impl VerifiedGd7WinnerForkWitnessChirho {
    pub fn object_digest_chirho(&self) -> &str {
        &self.object_digest_chirho
    }

    pub fn witness_chirho(&self) -> &Gd7WinnerForkWitnessChirho {
        &self.witness_chirho
    }
}

/// Opaque proof that one held node reloaded the exact winner index and fork witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedGd7DeposedForkObservationChirho {
    identity_chirho: Gd7ReconciliationIdentityChirho,
    winner_first_record_index_chirho: VerifiedGd7WinnerFirstRecordIndexChirho,
    winner_fork_witness_chirho: VerifiedGd7WinnerForkWitnessChirho,
}

impl AuthenticatedGd7DeposedForkObservationChirho {
    pub fn identity_chirho(&self) -> &Gd7ReconciliationIdentityChirho {
        &self.identity_chirho
    }

    pub fn winner_first_record_index_chirho(&self) -> &VerifiedGd7WinnerFirstRecordIndexChirho {
        &self.winner_first_record_index_chirho
    }

    pub fn winner_fork_witness_chirho(&self) -> &VerifiedGd7WinnerForkWitnessChirho {
        &self.winner_fork_witness_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7WinnerWitnessRefusalChirho {
    InvalidCoordinateChirho,
    InvalidEpochFirstEvidenceChirho,
    SameTermAnchorWithoutIndexChirho,
    MalformedIndexChirho,
    MalformedWitnessChirho,
    NonCanonicalIndexChirho,
    NonCanonicalWitnessChirho,
    OversizedIndexChirho,
    OversizedWitnessChirho,
    OversizedObservationSlotChirho,
    InvalidIndexSignatureChirho,
    InvalidWitnessSignatureChirho,
    InvalidObservationSlotSignatureChirho,
    InvalidLedgerSignatureChirho,
    WrongSignerChirho,
    WrongIndexCoordinateChirho,
    WrongWitnessIdentityChirho,
    WrongObservationSlotChirho,
    WrongLosingTailChirho,
    ForkAnchorMismatchChirho,
    MissingIndexChirho,
    MissingWitnessChirho,
    MissingObservationSlotChirho,
    ObservationSlotCollisionChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
}

impl fmt::Display for Gd7WinnerWitnessRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(match self {
            Self::InvalidCoordinateChirho => "GD7 winner coordinate is invalid",
            Self::InvalidEpochFirstEvidenceChirho => {
                "GD7 winner epoch-first record evidence is invalid"
            }
            Self::SameTermAnchorWithoutIndexChirho => {
                "GD7 term-first index is absent and the available anchor is only a same-term regrant"
            }
            Self::MalformedIndexChirho => "GD7 winner first-record index is malformed",
            Self::MalformedWitnessChirho => "GD7 winner fork witness is malformed",
            Self::NonCanonicalIndexChirho => "GD7 winner first-record index is not canonical",
            Self::NonCanonicalWitnessChirho => "GD7 winner fork witness is not canonical",
            Self::OversizedIndexChirho => "GD7 winner first-record index exceeds its fixed bound",
            Self::OversizedWitnessChirho => "GD7 winner fork witness exceeds its fixed bound",
            Self::OversizedObservationSlotChirho => {
                "GD7 winner observation slot exceeds its fixed bound"
            }
            Self::InvalidIndexSignatureChirho => {
                "GD7 winner first-record index signature is invalid"
            }
            Self::InvalidWitnessSignatureChirho => "GD7 winner fork witness signature is invalid",
            Self::InvalidObservationSlotSignatureChirho => {
                "GD7 winner observation slot signature is invalid"
            }
            Self::InvalidLedgerSignatureChirho => {
                "GD7 winner first record ledger signature is invalid"
            }
            Self::WrongSignerChirho => "GD7 winner signer does not match the elected node",
            Self::WrongIndexCoordinateChirho => {
                "GD7 winner first-record index has the wrong coordinate"
            }
            Self::WrongWitnessIdentityChirho => "GD7 winner fork witness has the wrong identity",
            Self::WrongObservationSlotChirho => {
                "GD7 winner observation slot has the wrong coordinate"
            }
            Self::WrongLosingTailChirho => {
                "GD7 losing tail differs from the verified local journal"
            }
            Self::ForkAnchorMismatchChirho => {
                "GD7 winner first record does not bind the exact losing fork"
            }
            Self::MissingIndexChirho => "GD7 winner first-record index is missing",
            Self::MissingWitnessChirho => "GD7 winner fork witness is missing",
            Self::MissingObservationSlotChirho => "GD7 winner observation slot is missing",
            Self::ObservationSlotCollisionChirho => {
                "GD7 winner observation slot is already bound to another reconciliation identity"
            }
            Self::ImmutableCollisionChirho => "GD7 immutable winner evidence collided",
            Self::SerializationChirho => "GD7 winner evidence serialization failed",
            Self::SigningChirho => "GD7 winner evidence signing failed",
            Self::StorageChirho => "GD7 winner evidence storage operation failed",
        })
    }
}

impl Error for Gd7WinnerWitnessRefusalChirho {}

/// Ports for O(1) winner evidence creation and verification.
pub struct Gd7WinnerWitnessStoreChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    control_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    ledger_signer_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
}

struct LocalLedgerSignerVerifierChirho<'signer_chirho> {
    signer_chirho: &'signer_chirho dyn LedgerSignerPortChirho,
}

impl Gd7LedgerRecordVerifierPortChirho for LocalLedgerSignerVerifierChirho<'_> {
    fn key_id_chirho(&self) -> String {
        self.signer_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.signer_chirho
            .verify_chirho(signed_content_line_chirho, sig_chirho)
    }
}

/// Read-only winner-evidence verifier used by a held/deposed node.
pub struct Gd7WinnerWitnessReaderChirho<'ports_chirho> {
    storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    control_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
}

impl<'ports_chirho> Gd7WinnerWitnessReaderChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        control_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
        ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    ) -> Self {
        Self {
            storage_chirho,
            control_verifier_chirho,
            ledger_verifier_chirho,
        }
    }

    pub fn load_winner_first_record_chirho(
        &self,
        consistency_group_digest_chirho: &str,
        winner_node_chirho: &str,
        winner_term_chirho: u64,
        winner_journal_genesis_digest_chirho: &str,
    ) -> Result<Option<VerifiedGd7WinnerFirstRecordIndexChirho>, Gd7WinnerWitnessRefusalChirho>
    {
        validate_winner_coordinate_chirho(
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
            self.control_verifier_chirho,
        )?;
        let coordinate_digest_chirho = winner_first_record_coordinate_digest_chirho(
            consistency_group_digest_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
        )?;
        let path_chirho =
            winner_first_record_path_from_coordinate_chirho(&coordinate_digest_chirho)?;
        let Some(bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &path_chirho,
            MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO,
            Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho,
        )?
        else {
            return Ok(None);
        };
        verify_index_bytes_chirho(
            &bytes_chirho,
            &coordinate_digest_chirho,
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
            self.control_verifier_chirho,
            self.ledger_verifier_chirho,
        )
        .map(Some)
    }

    pub fn load_winner_fork_witness_chirho(
        &self,
        identity_chirho: &Gd7ReconciliationIdentityChirho,
        verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
    ) -> Result<Option<VerifiedGd7WinnerForkWitnessChirho>, Gd7WinnerWitnessRefusalChirho> {
        if !validate_identity_chirho(identity_chirho) {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
        }
        validate_index_for_identity_chirho(identity_chirho, verified_index_chirho)?;
        let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(identity_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho)?;
        let path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho)?;
        let Some(bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &path_chirho,
            MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
            Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho,
        )?
        else {
            return Ok(None);
        };
        verify_witness_bytes_chirho(
            &bytes_chirho,
            &identity_digest_chirho,
            verified_index_chirho,
            self.control_verifier_chirho,
        )
        .map(Some)
    }

    /// Verify and durably import one winner observation before minting its opaque proof.
    pub fn import_authenticated_deposed_fork_observation_chirho(
        &self,
        expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
        winner_first_record_index_bytes_chirho: &[u8],
        winner_fork_witness_bytes_chirho: &[u8],
        verified_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    ) -> Result<AuthenticatedGd7DeposedForkObservationChirho, Gd7WinnerWitnessRefusalChirho> {
        if winner_first_record_index_bytes_chirho.len()
            > MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO
        {
            return Err(Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho);
        }
        if winner_fork_witness_bytes_chirho.len() > MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO {
            return Err(Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho);
        }
        if !validate_identity_chirho(expected_identity_chirho) {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
        }
        validate_losing_tail_for_identity_chirho(
            expected_identity_chirho,
            verified_losing_tail_chirho,
        )?;
        validate_winner_coordinate_chirho(
            &expected_identity_chirho.consistency_group_digest_chirho,
            &expected_identity_chirho.winner_node_chirho,
            expected_identity_chirho.winner_term_chirho,
            &expected_identity_chirho.winner_journal_genesis_digest_chirho,
            self.control_verifier_chirho,
        )?;
        let coordinate_digest_chirho = winner_first_record_coordinate_digest_chirho(
            &expected_identity_chirho.consistency_group_digest_chirho,
            expected_identity_chirho.winner_term_chirho,
            &expected_identity_chirho.winner_journal_genesis_digest_chirho,
        )?;
        let verified_index_chirho = verify_index_bytes_chirho(
            winner_first_record_index_bytes_chirho,
            &coordinate_digest_chirho,
            &expected_identity_chirho.consistency_group_digest_chirho,
            &expected_identity_chirho.winner_node_chirho,
            expected_identity_chirho.winner_term_chirho,
            &expected_identity_chirho.winner_journal_genesis_digest_chirho,
            self.control_verifier_chirho,
            self.ledger_verifier_chirho,
        )?;
        validate_index_for_identity_chirho(expected_identity_chirho, &verified_index_chirho)?;
        validate_winner_tail_for_identity_chirho(expected_identity_chirho, &verified_index_chirho)?;
        let identity_digest_chirho =
            gd7_reconciliation_identity_digest_chirho(expected_identity_chirho)
                .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho)?;
        let verified_witness_chirho = verify_witness_bytes_chirho(
            winner_fork_witness_bytes_chirho,
            &identity_digest_chirho,
            &verified_index_chirho,
            self.control_verifier_chirho,
        )?;
        if verified_witness_chirho.witness_chirho().identity_chirho != *expected_identity_chirho {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
        }

        let index_path_chirho =
            winner_first_record_path_from_coordinate_chirho(&coordinate_digest_chirho)?;
        let witness_path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho)?;
        create_verified_immutable_chirho(
            self.storage_chirho,
            &index_path_chirho,
            winner_first_record_index_bytes_chirho,
            MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO,
            Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho,
            Gd7WinnerWitnessRefusalChirho::MissingIndexChirho,
        )?;
        create_verified_immutable_chirho(
            self.storage_chirho,
            &witness_path_chirho,
            winner_fork_witness_bytes_chirho,
            MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
            Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho,
            Gd7WinnerWitnessRefusalChirho::MissingWitnessChirho,
        )?;

        self.load_authenticated_deposed_fork_observation_chirho(
            expected_identity_chirho,
            verified_losing_tail_chirho,
        )
    }

    /// Reload both exact-addressed objects and return an opaque authenticated observation.
    pub fn load_authenticated_deposed_fork_observation_chirho(
        &self,
        identity_chirho: &Gd7ReconciliationIdentityChirho,
        verified_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
    ) -> Result<AuthenticatedGd7DeposedForkObservationChirho, Gd7WinnerWitnessRefusalChirho> {
        validate_losing_tail_for_identity_chirho(identity_chirho, verified_losing_tail_chirho)?;
        let verified_index_chirho = self
            .load_winner_first_record_chirho(
                &identity_chirho.consistency_group_digest_chirho,
                &identity_chirho.winner_node_chirho,
                identity_chirho.winner_term_chirho,
                &identity_chirho.winner_journal_genesis_digest_chirho,
            )?
            .ok_or(Gd7WinnerWitnessRefusalChirho::MissingIndexChirho)?;
        validate_winner_tail_for_identity_chirho(identity_chirho, &verified_index_chirho)?;
        let verified_witness_chirho = self
            .load_winner_fork_witness_chirho(identity_chirho, &verified_index_chirho)?
            .ok_or(Gd7WinnerWitnessRefusalChirho::MissingWitnessChirho)?;
        Ok(AuthenticatedGd7DeposedForkObservationChirho {
            identity_chirho: identity_chirho.clone(),
            winner_first_record_index_chirho: verified_index_chirho,
            winner_fork_witness_chirho: verified_witness_chirho,
        })
    }
}

impl<'ports_chirho> Gd7WinnerWitnessStoreChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        control_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        ledger_signer_chirho: &'ports_chirho dyn LedgerSignerPortChirho,
    ) -> Self {
        Self {
            storage_chirho,
            control_signer_chirho,
            ledger_signer_chirho,
        }
    }

    fn ledger_verifier_chirho(&self) -> LocalLedgerSignerVerifierChirho<'_> {
        LocalLedgerSignerVerifierChirho {
            signer_chirho: self.ledger_signer_chirho,
        }
    }

    /// Create or verify the exact first record for one `(group, genesis, geo term)` coordinate.
    ///
    /// Same-term local regrant anchors may reuse an already-present index, but can never create one.
    pub fn ensure_winner_first_record_chirho(
        &self,
        consistency_group_digest_chirho: &str,
        winner_node_chirho: &str,
        winner_term_chirho: u64,
        winner_journal_genesis_digest_chirho: &str,
        evidence_chirho: &EpochFirstRecordEvidenceChirho,
    ) -> Result<VerifiedGd7WinnerFirstRecordIndexChirho, Gd7WinnerWitnessRefusalChirho> {
        validate_winner_coordinate_chirho(
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
            self.control_signer_chirho,
        )?;
        let coordinate_digest_chirho = winner_first_record_coordinate_digest_chirho(
            consistency_group_digest_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
        )?;
        let path_chirho =
            winner_first_record_path_from_coordinate_chirho(&coordinate_digest_chirho)?;
        if let Some(existing_chirho) = self.load_winner_first_record_chirho(
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
        )? {
            let incoming_chirho = evidence_chirho
                .verify_chirho(self.ledger_signer_chirho)
                .map_err(|_| Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho)?;
            validate_record_term_chirho(&incoming_chirho, evidence_chirho, winner_term_chirho)?;
            let incoming_anchor_term_chirho = u64::from(
                split_writer_epoch_chirho(
                    incoming_chirho
                        .anchor_chirho
                        .as_ref()
                        .expect("validated epoch-first evidence has an anchor")
                        .inherited_epoch_chirho,
                )
                .geo_term_chirho,
            );
            if incoming_anchor_term_chirho < winner_term_chirho
                && (incoming_chirho.seq_chirho
                    != existing_chirho.index_chirho.first_record_chirho.seq_chirho
                    || evidence_chirho.record_digest_chirho().0
                        != existing_chirho.index_chirho.first_record_digest_chirho)
            {
                return Err(Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho);
            }
            return Ok(existing_chirho);
        }

        let first_record_chirho = evidence_chirho
            .verify_chirho(self.ledger_signer_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho)?;
        validate_record_term_chirho(&first_record_chirho, evidence_chirho, winner_term_chirho)?;
        let anchor_chirho = first_record_chirho
            .anchor_chirho
            .as_ref()
            .expect("validated epoch-first evidence has an anchor");
        if u64::from(
            split_writer_epoch_chirho(anchor_chirho.inherited_epoch_chirho).geo_term_chirho,
        ) >= winner_term_chirho
        {
            return Err(Gd7WinnerWitnessRefusalChirho::SameTermAnchorWithoutIndexChirho);
        }
        if first_record_chirho.seq_chirho
            != anchor_chirho
                .inherited_seq_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho)?
            || first_record_chirho.prev_chirho != anchor_chirho.inherited_digest_chirho
        {
            return Err(Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho);
        }

        let mut index_chirho = Gd7WinnerFirstRecordIndexChirho {
            schema_chirho: GD7_WINNER_FIRST_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: consistency_group_digest_chirho.to_owned(),
            winner_node_chirho: winner_node_chirho.to_owned(),
            winner_term_chirho,
            winner_journal_genesis_digest_chirho: winner_journal_genesis_digest_chirho.to_owned(),
            first_record_digest_chirho: evidence_chirho.record_digest_chirho().0.clone(),
            first_record_chirho,
            key_id_chirho: self.control_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        index_chirho.sig_chirho = sign_record_chirho(&index_chirho, self.control_signer_chirho)?;
        let bytes_chirho = canonical_json_chirho(&index_chirho)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO {
            return Err(Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho);
        }
        match self
            .storage_chirho
            .create_durable_chirho(&path_chirho, &bytes_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?
        {
            CreateDurableOutcomeChirho::CreatedChirho => {}
            CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_bytes_chirho = read_bounded_chirho(
                    self.storage_chirho,
                    &path_chirho,
                    MAX_GD7_WINNER_FIRST_RECORD_INDEX_BYTES_CHIRHO,
                    Gd7WinnerWitnessRefusalChirho::OversizedIndexChirho,
                )?
                .ok_or(Gd7WinnerWitnessRefusalChirho::MissingIndexChirho)?;
                if existing_bytes_chirho != bytes_chirho {
                    return Err(Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho);
                }
            }
        }
        let ledger_verifier_chirho = self.ledger_verifier_chirho();
        verify_index_bytes_chirho(
            &bytes_chirho,
            &coordinate_digest_chirho,
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
            self.control_signer_chirho,
            &ledger_verifier_chirho,
        )
    }

    pub fn load_winner_first_record_chirho(
        &self,
        consistency_group_digest_chirho: &str,
        winner_node_chirho: &str,
        winner_term_chirho: u64,
        winner_journal_genesis_digest_chirho: &str,
    ) -> Result<Option<VerifiedGd7WinnerFirstRecordIndexChirho>, Gd7WinnerWitnessRefusalChirho>
    {
        let ledger_verifier_chirho = self.ledger_verifier_chirho();
        Gd7WinnerWitnessReaderChirho::new_chirho(
            self.storage_chirho,
            self.control_signer_chirho,
            &ledger_verifier_chirho,
        )
        .load_winner_first_record_chirho(
            consistency_group_digest_chirho,
            winner_node_chirho,
            winner_term_chirho,
            winner_journal_genesis_digest_chirho,
        )
    }

    pub fn seal_winner_fork_witness_chirho(
        &self,
        identity_chirho: Gd7ReconciliationIdentityChirho,
        verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
    ) -> Result<VerifiedGd7WinnerForkWitnessChirho, Gd7WinnerWitnessRefusalChirho> {
        if !validate_identity_chirho(&identity_chirho) {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
        }
        validate_index_for_identity_chirho(&identity_chirho, verified_index_chirho)?;
        self.reserve_deposed_fork_observation_slot_chirho(&identity_chirho)?;
        let identity_digest_chirho = gd7_reconciliation_identity_digest_chirho(&identity_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho)?;
        let path_chirho = winner_fork_witness_path_chirho(&identity_digest_chirho)?;
        let mut witness_chirho = Gd7WinnerForkWitnessChirho {
            schema_chirho: GD7_WINNER_FORK_WITNESS_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho,
            winner_first_record_index_coordinate_digest_chirho: verified_index_chirho
                .coordinate_digest_chirho
                .clone(),
            winner_first_record_index_object_digest_chirho: verified_index_chirho
                .object_digest_chirho
                .clone(),
            winner_first_record_epoch_chirho: verified_index_chirho
                .index_chirho
                .first_record_chirho
                .epoch_chirho,
            winner_first_record_seq_chirho: verified_index_chirho
                .index_chirho
                .first_record_chirho
                .seq_chirho,
            winner_first_record_digest_chirho: verified_index_chirho
                .index_chirho
                .first_record_digest_chirho
                .clone(),
            key_id_chirho: self.control_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        witness_chirho.sig_chirho =
            sign_record_chirho(&witness_chirho, self.control_signer_chirho)?;
        let bytes_chirho = canonical_json_chirho(&witness_chirho)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO {
            return Err(Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho);
        }
        match self
            .storage_chirho
            .create_durable_chirho(&path_chirho, &bytes_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?
        {
            CreateDurableOutcomeChirho::CreatedChirho => {}
            CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_chirho = read_bounded_chirho(
                    self.storage_chirho,
                    &path_chirho,
                    MAX_GD7_WINNER_FORK_WITNESS_BYTES_CHIRHO,
                    Gd7WinnerWitnessRefusalChirho::OversizedWitnessChirho,
                )?
                .ok_or(Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho)?;
                if existing_chirho != bytes_chirho {
                    return Err(Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho);
                }
            }
        }
        verify_witness_bytes_chirho(
            &bytes_chirho,
            &identity_digest_chirho,
            verified_index_chirho,
            self.control_signer_chirho,
        )
    }

    /// Reserve the one durable losing-fork observation allowed for a held node in a winner term.
    ///
    /// The O(1)-addressed slot is created before any tail-addressed witness. Exact identity replay
    /// is idempotent; a different identity at the same coordinate fails closed.
    pub fn reserve_deposed_fork_observation_slot_chirho(
        &self,
        identity_chirho: &Gd7ReconciliationIdentityChirho,
    ) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
        if !validate_identity_chirho(identity_chirho) {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
        }
        validate_winner_coordinate_chirho(
            &identity_chirho.consistency_group_digest_chirho,
            &identity_chirho.winner_node_chirho,
            identity_chirho.winner_term_chirho,
            &identity_chirho.winner_journal_genesis_digest_chirho,
            self.control_signer_chirho,
        )?;
        let selected_identity_digest_chirho =
            gd7_reconciliation_identity_digest_chirho(identity_chirho)
                .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho)?;
        let coordinate_digest_chirho =
            winner_observation_slot_coordinate_digest_chirho(identity_chirho)?;
        let path_chirho =
            winner_observation_slot_path_from_coordinate_chirho(&coordinate_digest_chirho)?;
        let mut slot_chirho = Gd7WinnerObservationSlotChirho {
            schema_chirho: GD7_WINNER_OBSERVATION_SLOT_SCHEMA_V1_CHIRHO.to_owned(),
            consistency_group_digest_chirho: identity_chirho
                .consistency_group_digest_chirho
                .clone(),
            winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
            winner_term_chirho: identity_chirho.winner_term_chirho,
            held_node_chirho: identity_chirho.held_node_chirho.clone(),
            selected_reconciliation_identity_digest_chirho: selected_identity_digest_chirho.clone(),
            key_id_chirho: self.control_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        slot_chirho.sig_chirho = sign_record_chirho(&slot_chirho, self.control_signer_chirho)?;
        let bytes_chirho = canonical_json_chirho(&slot_chirho)?;
        if bytes_chirho.len() > MAX_GD7_WINNER_OBSERVATION_SLOT_BYTES_CHIRHO {
            return Err(Gd7WinnerWitnessRefusalChirho::OversizedObservationSlotChirho);
        }
        match self
            .storage_chirho
            .create_durable_chirho(&path_chirho, &bytes_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?
        {
            CreateDurableOutcomeChirho::CreatedChirho => {}
            CreateDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_bytes_chirho = read_bounded_chirho(
                    self.storage_chirho,
                    &path_chirho,
                    MAX_GD7_WINNER_OBSERVATION_SLOT_BYTES_CHIRHO,
                    Gd7WinnerWitnessRefusalChirho::OversizedObservationSlotChirho,
                )?
                .ok_or(Gd7WinnerWitnessRefusalChirho::MissingObservationSlotChirho)?;
                let existing_slot_chirho = verify_observation_slot_bytes_chirho(
                    &existing_bytes_chirho,
                    identity_chirho,
                    self.control_signer_chirho,
                )?;
                if existing_slot_chirho.selected_reconciliation_identity_digest_chirho
                    != selected_identity_digest_chirho
                {
                    return Err(Gd7WinnerWitnessRefusalChirho::ObservationSlotCollisionChirho);
                }
                return Ok(());
            }
        }
        let created_slot_chirho = verify_observation_slot_bytes_chirho(
            &bytes_chirho,
            identity_chirho,
            self.control_signer_chirho,
        )?;
        if created_slot_chirho.selected_reconciliation_identity_digest_chirho
            != selected_identity_digest_chirho
        {
            return Err(Gd7WinnerWitnessRefusalChirho::WrongObservationSlotChirho);
        }
        Ok(())
    }

    /// Reload and verify one exact identity-bound witness without listing reconciliation history.
    pub fn load_winner_fork_witness_chirho(
        &self,
        identity_chirho: &Gd7ReconciliationIdentityChirho,
        verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
    ) -> Result<Option<VerifiedGd7WinnerForkWitnessChirho>, Gd7WinnerWitnessRefusalChirho> {
        let ledger_verifier_chirho = self.ledger_verifier_chirho();
        Gd7WinnerWitnessReaderChirho::new_chirho(
            self.storage_chirho,
            self.control_signer_chirho,
            &ledger_verifier_chirho,
        )
        .load_winner_fork_witness_chirho(identity_chirho, verified_index_chirho)
    }
}

pub fn winner_first_record_coordinate_digest_chirho(
    consistency_group_digest_chirho: &str,
    winner_term_chirho: u64,
    winner_journal_genesis_digest_chirho: &str,
) -> Result<String, Gd7WinnerWitnessRefusalChirho> {
    if consistency_group_digest_suffix_chirho(consistency_group_digest_chirho).is_none()
        || winner_term_chirho == 0
        || !is_lower_hex_digest_chirho(winner_journal_genesis_digest_chirho)
    {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidCoordinateChirho);
    }
    let coordinate_chirho = Gd7WinnerFirstRecordCoordinateChirho {
        schema_chirho: GD7_WINNER_FIRST_RECORD_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: consistency_group_digest_chirho.to_owned(),
        winner_journal_genesis_digest_chirho: winner_journal_genesis_digest_chirho.to_owned(),
        winner_term_chirho,
    };
    Ok(digest_bytes_chirho(&canonical_json_chirho(
        &coordinate_chirho,
    )?))
}

pub fn winner_first_record_path_chirho(
    consistency_group_digest_chirho: &str,
    winner_term_chirho: u64,
    winner_journal_genesis_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerWitnessRefusalChirho> {
    let coordinate_digest_chirho = winner_first_record_coordinate_digest_chirho(
        consistency_group_digest_chirho,
        winner_term_chirho,
        winner_journal_genesis_digest_chirho,
    )?;
    winner_first_record_path_from_coordinate_chirho(&coordinate_digest_chirho)
}

pub fn winner_fork_witness_path_chirho(
    identity_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerWitnessRefusalChirho> {
    if !is_lower_hex_digest_chirho(identity_digest_chirho) {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidCoordinateChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/winner-fork-witnesses-chirho/{}/{}/{identity_digest_chirho}.json",
        &identity_digest_chirho[..2],
        &identity_digest_chirho[2..4],
    )))
}

fn winner_first_record_path_from_coordinate_chirho(
    coordinate_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerWitnessRefusalChirho> {
    if !is_lower_hex_digest_chirho(coordinate_digest_chirho) {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidCoordinateChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/winner-first-records-chirho/{}/{}/{coordinate_digest_chirho}.json",
        &coordinate_digest_chirho[..2],
        &coordinate_digest_chirho[2..4],
    )))
}

fn winner_observation_slot_coordinate_digest_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
) -> Result<String, Gd7WinnerWitnessRefusalChirho> {
    if !validate_identity_chirho(identity_chirho) {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
    }
    let coordinate_chirho = Gd7WinnerObservationSlotCoordinateChirho {
        schema_chirho: GD7_WINNER_OBSERVATION_SLOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: identity_chirho.consistency_group_digest_chirho.clone(),
        winner_node_chirho: identity_chirho.winner_node_chirho.clone(),
        winner_term_chirho: identity_chirho.winner_term_chirho,
        held_node_chirho: identity_chirho.held_node_chirho.clone(),
    };
    Ok(digest_bytes_chirho(&canonical_json_chirho(
        &coordinate_chirho,
    )?))
}

fn winner_observation_slot_path_from_coordinate_chirho(
    coordinate_digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7WinnerWitnessRefusalChirho> {
    if !is_lower_hex_digest_chirho(coordinate_digest_chirho) {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidCoordinateChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/winner-observation-slots-chirho/{}/{}/{coordinate_digest_chirho}.json",
        &coordinate_digest_chirho[..2],
        &coordinate_digest_chirho[2..4],
    )))
}

fn validate_winner_coordinate_chirho(
    consistency_group_digest_chirho: &str,
    winner_node_chirho: &str,
    winner_term_chirho: u64,
    winner_journal_genesis_digest_chirho: &str,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    if consistency_group_digest_suffix_chirho(consistency_group_digest_chirho).is_none()
        || !is_lower_hex_digest_chirho(winner_node_chirho)
        || winner_term_chirho == 0
        || !is_lower_hex_digest_chirho(winner_journal_genesis_digest_chirho)
    {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidCoordinateChirho);
    }
    if verifier_chirho.key_id_chirho() != winner_node_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongSignerChirho);
    }
    Ok(())
}

fn validate_record_term_chirho(
    record_chirho: &LedgerRecordChirho,
    evidence_chirho: &EpochFirstRecordEvidenceChirho,
    winner_term_chirho: u64,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    if record_chirho.epoch_chirho != evidence_chirho.epoch_chirho()
        || record_chirho.seq_chirho != evidence_chirho.seq_chirho()
        || stored_line_digest_chirho(evidence_chirho.canonical_record_line_chirho())
            != *evidence_chirho.record_digest_chirho()
        || u64::from(split_writer_epoch_chirho(record_chirho.epoch_chirho).geo_term_chirho)
            != winner_term_chirho
        || record_chirho.anchor_chirho.is_none()
    {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho);
    }
    let anchor_chirho = record_chirho
        .anchor_chirho
        .as_ref()
        .expect("the preceding branch proves an anchor exists");
    if record_chirho.seq_chirho
        != anchor_chirho
            .inherited_seq_chirho
            .checked_add(1)
            .ok_or(Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho)?
        || record_chirho.prev_chirho != anchor_chirho.inherited_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidEpochFirstEvidenceChirho);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_index_bytes_chirho(
    bytes_chirho: &[u8],
    expected_coordinate_digest_chirho: &str,
    expected_group_chirho: &str,
    expected_node_chirho: &str,
    expected_term_chirho: u64,
    expected_genesis_chirho: &str,
    control_verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    ledger_verifier_chirho: &dyn Gd7LedgerRecordVerifierPortChirho,
) -> Result<VerifiedGd7WinnerFirstRecordIndexChirho, Gd7WinnerWitnessRefusalChirho> {
    let index_chirho: Gd7WinnerFirstRecordIndexChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho)?;
    if canonical_json_chirho(&index_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::NonCanonicalIndexChirho);
    }
    if index_chirho.schema_chirho != GD7_WINNER_FIRST_RECORD_SCHEMA_V1_CHIRHO
        || index_chirho.consistency_group_digest_chirho != expected_group_chirho
        || index_chirho.winner_node_chirho != expected_node_chirho
        || index_chirho.winner_term_chirho != expected_term_chirho
        || index_chirho.winner_journal_genesis_digest_chirho != expected_genesis_chirho
        || index_chirho.key_id_chirho != expected_node_chirho
        || control_verifier_chirho.key_id_chirho() != expected_node_chirho
        || index_chirho.first_record_chirho.key_id_chirho != ledger_verifier_chirho.key_id_chirho()
        || !is_lower_hex_digest_chirho(&index_chirho.first_record_digest_chirho)
    {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongIndexCoordinateChirho);
    }
    verify_control_signature_chirho(
        &index_chirho,
        &index_chirho.sig_chirho,
        control_verifier_chirho,
        Gd7WinnerWitnessRefusalChirho::InvalidIndexSignatureChirho,
    )?;
    let canonical_record_chirho =
        canonical_ledger_record_line_chirho(&index_chirho.first_record_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho)?;
    if canonical_record_chirho.len() > MAX_EPOCH_FIRST_RECORD_EVIDENCE_BYTES_CHIRHO
        || stored_line_digest_chirho(&canonical_record_chirho).0
            != index_chirho.first_record_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho);
    }
    let signed_content_chirho =
        ledger_record_signed_content_line_chirho(&index_chirho.first_record_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho)?;
    if !ledger_verifier_chirho.verify_chirho(
        &signed_content_chirho,
        &index_chirho.first_record_chirho.sig_chirho,
    ) {
        return Err(Gd7WinnerWitnessRefusalChirho::InvalidLedgerSignatureChirho);
    }
    let anchor_chirho = index_chirho
        .first_record_chirho
        .anchor_chirho
        .as_ref()
        .ok_or(Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho)?;
    if u64::from(
        split_writer_epoch_chirho(index_chirho.first_record_chirho.epoch_chirho).geo_term_chirho,
    ) != expected_term_chirho
        || u64::from(
            split_writer_epoch_chirho(anchor_chirho.inherited_epoch_chirho).geo_term_chirho,
        ) >= expected_term_chirho
        || index_chirho.first_record_chirho.seq_chirho
            != anchor_chirho
                .inherited_seq_chirho
                .checked_add(1)
                .ok_or(Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho)?
        || index_chirho.first_record_chirho.prev_chirho != anchor_chirho.inherited_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::MalformedIndexChirho);
    }
    let actual_coordinate_digest_chirho = winner_first_record_coordinate_digest_chirho(
        &index_chirho.consistency_group_digest_chirho,
        index_chirho.winner_term_chirho,
        &index_chirho.winner_journal_genesis_digest_chirho,
    )?;
    if actual_coordinate_digest_chirho != expected_coordinate_digest_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongIndexCoordinateChirho);
    }
    Ok(VerifiedGd7WinnerFirstRecordIndexChirho {
        coordinate_digest_chirho: actual_coordinate_digest_chirho,
        object_digest_chirho: digest_bytes_chirho(bytes_chirho),
        index_chirho,
    })
}

fn validate_index_for_identity_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    let index_chirho = &verified_index_chirho.index_chirho;
    let anchor_chirho = index_chirho
        .first_record_chirho
        .anchor_chirho
        .as_ref()
        .ok_or(Gd7WinnerWitnessRefusalChirho::ForkAnchorMismatchChirho)?;
    if index_chirho.consistency_group_digest_chirho
        != identity_chirho.consistency_group_digest_chirho
        || index_chirho.winner_node_chirho != identity_chirho.winner_node_chirho
        || index_chirho.winner_term_chirho != identity_chirho.winner_term_chirho
        || index_chirho.winner_journal_genesis_digest_chirho
            != identity_chirho.winner_journal_genesis_digest_chirho
        || anchor_chirho.inherited_epoch_chirho != identity_chirho.fork_chirho.epoch_chirho
        || anchor_chirho.inherited_seq_chirho != identity_chirho.fork_chirho.seq_chirho
        || anchor_chirho.inherited_digest_chirho.0
            != identity_chirho.fork_chirho.record_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::ForkAnchorMismatchChirho);
    }
    Ok(())
}

fn validate_winner_tail_for_identity_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    if verified_index_chirho
        .index_chirho
        .first_record_chirho
        .epoch_chirho
        != identity_chirho.winner_journal_tail_chirho.epoch_chirho
        || verified_index_chirho
            .index_chirho
            .first_record_chirho
            .seq_chirho
            != identity_chirho.winner_journal_tail_chirho.seq_chirho
        || verified_index_chirho
            .index_chirho
            .first_record_digest_chirho
            != identity_chirho
                .winner_journal_tail_chirho
                .record_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
    }
    Ok(())
}

fn validate_losing_tail_for_identity_chirho(
    identity_chirho: &Gd7ReconciliationIdentityChirho,
    verified_losing_tail_chirho: &VerifiedLosingJournalTailChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    if identity_chirho.losing_journal_genesis_digest_chirho
        != verified_losing_tail_chirho
            .identity_chirho()
            .genesis_digest_chirho()
            .0
        || identity_chirho.losing_journal_tail_chirho.epoch_chirho
            != verified_losing_tail_chirho.record_epoch_chirho()
        || identity_chirho.losing_journal_tail_chirho.seq_chirho
            != verified_losing_tail_chirho.coordinate_chirho().seq_chirho()
        || identity_chirho
            .losing_journal_tail_chirho
            .record_digest_chirho
            != verified_losing_tail_chirho
                .coordinate_chirho()
                .record_digest_chirho()
                .0
    {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongLosingTailChirho);
    }
    Ok(())
}

fn verify_witness_bytes_chirho(
    bytes_chirho: &[u8],
    expected_identity_digest_chirho: &str,
    verified_index_chirho: &VerifiedGd7WinnerFirstRecordIndexChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<VerifiedGd7WinnerForkWitnessChirho, Gd7WinnerWitnessRefusalChirho> {
    let witness_chirho: Gd7WinnerForkWitnessChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::MalformedWitnessChirho)?;
    if canonical_json_chirho(&witness_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::NonCanonicalWitnessChirho);
    }
    if witness_chirho.schema_chirho != GD7_WINNER_FORK_WITNESS_SCHEMA_V1_CHIRHO
        || !validate_identity_chirho(&witness_chirho.identity_chirho)
        || witness_chirho.key_id_chirho != witness_chirho.identity_chirho.winner_node_chirho
        || verifier_chirho.key_id_chirho() != witness_chirho.identity_chirho.winner_node_chirho
        || witness_chirho.winner_first_record_index_coordinate_digest_chirho
            != verified_index_chirho.coordinate_digest_chirho
        || witness_chirho.winner_first_record_index_object_digest_chirho
            != verified_index_chirho.object_digest_chirho
        || witness_chirho.winner_first_record_epoch_chirho
            != verified_index_chirho
                .index_chirho
                .first_record_chirho
                .epoch_chirho
        || witness_chirho.winner_first_record_seq_chirho
            != verified_index_chirho
                .index_chirho
                .first_record_chirho
                .seq_chirho
        || witness_chirho.winner_first_record_digest_chirho
            != verified_index_chirho
                .index_chirho
                .first_record_digest_chirho
    {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
    }
    let actual_identity_digest_chirho =
        gd7_reconciliation_identity_digest_chirho(&witness_chirho.identity_chirho)
            .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho)?;
    if actual_identity_digest_chirho != expected_identity_digest_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongWitnessIdentityChirho);
    }
    validate_index_for_identity_chirho(&witness_chirho.identity_chirho, verified_index_chirho)?;
    verify_control_signature_chirho(
        &witness_chirho,
        &witness_chirho.sig_chirho,
        verifier_chirho,
        Gd7WinnerWitnessRefusalChirho::InvalidWitnessSignatureChirho,
    )?;
    Ok(VerifiedGd7WinnerForkWitnessChirho {
        object_digest_chirho: digest_bytes_chirho(bytes_chirho),
        witness_chirho,
    })
}

fn verify_observation_slot_bytes_chirho(
    bytes_chirho: &[u8],
    expected_identity_chirho: &Gd7ReconciliationIdentityChirho,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
) -> Result<Gd7WinnerObservationSlotChirho, Gd7WinnerWitnessRefusalChirho> {
    let slot_chirho: Gd7WinnerObservationSlotChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::WrongObservationSlotChirho)?;
    if canonical_json_chirho(&slot_chirho)?.as_slice() != bytes_chirho {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongObservationSlotChirho);
    }
    if slot_chirho.schema_chirho != GD7_WINNER_OBSERVATION_SLOT_SCHEMA_V1_CHIRHO
        || slot_chirho.consistency_group_digest_chirho
            != expected_identity_chirho.consistency_group_digest_chirho
        || slot_chirho.winner_node_chirho != expected_identity_chirho.winner_node_chirho
        || slot_chirho.winner_term_chirho != expected_identity_chirho.winner_term_chirho
        || slot_chirho.held_node_chirho != expected_identity_chirho.held_node_chirho
        || slot_chirho.key_id_chirho != expected_identity_chirho.winner_node_chirho
        || verifier_chirho.key_id_chirho() != expected_identity_chirho.winner_node_chirho
        || !is_lower_hex_digest_chirho(&slot_chirho.selected_reconciliation_identity_digest_chirho)
    {
        return Err(Gd7WinnerWitnessRefusalChirho::WrongObservationSlotChirho);
    }
    verify_control_signature_chirho(
        &slot_chirho,
        &slot_chirho.sig_chirho,
        verifier_chirho,
        Gd7WinnerWitnessRefusalChirho::InvalidObservationSlotSignatureChirho,
    )?;
    Ok(slot_chirho)
}

fn sign_record_chirho<RecordChirho>(
    record_chirho: &RecordChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
) -> Result<String, Gd7WinnerWitnessRefusalChirho>
where
    RecordChirho: Serialize + Clone + ClearSignatureChirho,
{
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.clear_signature_chirho();
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::SerializationChirho)?;
    signer_chirho
        .sign_chirho(unsigned_line_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::SigningChirho)
}

fn verify_control_signature_chirho<RecordChirho>(
    record_chirho: &RecordChirho,
    signature_chirho: &str,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    invalid_chirho: Gd7WinnerWitnessRefusalChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho>
where
    RecordChirho: Serialize + Clone + ClearSignatureChirho,
{
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.clear_signature_chirho();
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::SerializationChirho)?;
    if verifier_chirho.verify_chirho(unsigned_line_chirho, signature_chirho) {
        Ok(())
    } else {
        Err(invalid_chirho)
    }
}

trait ClearSignatureChirho {
    fn clear_signature_chirho(&mut self);
}

impl ClearSignatureChirho for Gd7WinnerFirstRecordIndexChirho {
    fn clear_signature_chirho(&mut self) {
        self.sig_chirho.clear();
    }
}

impl ClearSignatureChirho for Gd7WinnerForkWitnessChirho {
    fn clear_signature_chirho(&mut self) {
        self.sig_chirho.clear();
    }
}

impl ClearSignatureChirho for Gd7WinnerObservationSlotChirho {
    fn clear_signature_chirho(&mut self) {
        self.sig_chirho.clear();
    }
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7WinnerWitnessRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7WinnerWitnessRefusalChirho> {
    let Some(len_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if len_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    if len_chirho == 0 {
        return Ok(Some(Vec::new()));
    }
    let bytes_chirho = storage_chirho
        .read_exact_range_chirho(path_chirho, 0, len_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?;
    if bytes_chirho.len() != len_chirho as usize {
        return Err(Gd7WinnerWitnessRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}

fn create_verified_immutable_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    verified_bytes_chirho: &[u8],
    maximum_chirho: usize,
    oversized_chirho: Gd7WinnerWitnessRefusalChirho,
    missing_chirho: Gd7WinnerWitnessRefusalChirho,
) -> Result<(), Gd7WinnerWitnessRefusalChirho> {
    match storage_chirho
        .create_durable_chirho(path_chirho, verified_bytes_chirho)
        .map_err(|_| Gd7WinnerWitnessRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_bytes_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                maximum_chirho,
                oversized_chirho,
            )?
            .ok_or(missing_chirho)?;
            if existing_bytes_chirho == verified_bytes_chirho {
                Ok(())
            } else {
                Err(Gd7WinnerWitnessRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn canonical_json_chirho(
    value_chirho: &impl Serialize,
) -> Result<Vec<u8>, Gd7WinnerWitnessRefusalChirho> {
    serde_json::to_vec(value_chirho).map_err(|_| Gd7WinnerWitnessRefusalChirho::SerializationChirho)
}

fn digest_bytes_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}
