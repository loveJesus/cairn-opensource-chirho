// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::super::{
    canonical_json_chirho, consistency_group_digest_suffix_chirho, digest_bytes_chirho,
    gd7_fork_baseline_page_path_chirho, gd7_fork_baseline_root_path_chirho,
    gd7_winner_history_page_path_chirho, gd7_winner_history_root_path_chirho,
    is_lower_hex_digest_chirho, load_verified_gd7_fork_baseline_root_chirho,
    load_verified_gd7_winner_history_root_chirho, validate_key_and_signature_chirho,
    verify_complete_gd7_fork_baseline_chirho, verify_complete_gd7_winner_history_chain_chirho,
    CreateDurableOutcomeChirho, Gd7ForkBaselineIdentityChirho, Gd7ForkBaselineRefusalChirho,
    Gd7ReconciliationSignerPortChirho, Gd7ReconciliationVerifierPortChirho,
    Gd7WinnerHistoryIdentityChirho, Gd7WinnerHistoryRefusalChirho, LedgerStoragePortChirho,
    StoragePathChirho, MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO,
    MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO, MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO,
    MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO,
};
use super::account_net_composition_chirho::{
    verify_gd7_account_net_composition_chirho, Gd7AccountNetCompositionInputsChirho,
    Gd7AccountNetCompositionRefusalChirho, VerifiedGd7AccountNetCompositionChirho,
};
use super::contract_chirho::{
    gd7_held_evidence_transfer_identity_digest_chirho, verify_gd7_winner_evidence_manifest_chirho,
    verify_gd7_winner_evidence_page_transfer_chirho, Gd7HeldEvidenceTransferIdentityChirho,
    Gd7WinnerEvidenceFamilyChirho, Gd7WinnerEvidenceManifestChirho,
    Gd7WinnerEvidencePageGrantChirho, Gd7WinnerEvidencePageTransferChirho,
    Gd7WinnerEvidenceTransferRefusalChirho, MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
};
use crate::reconciliation_chirho::Gd7LedgerRecordVerifierPortChirho;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

const GD7_RECONCILIATION_NAMESPACE_CHIRHO: &str = "gd7-reconciliation-chirho";
pub const GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "gd7-held-evidence-transfer-checkpoint-v1-chirho";
pub const GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO: &str =
    "gd7-held-evidence-transfer-head-v1-chirho";
pub const MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO: usize = 32 * 1024;
pub const MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldEvidenceTransferPhaseChirho {
    ReceivingChirho,
    CompleteChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldEvidenceTransferCheckpointChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    pub manifest_object_digest_chirho: String,
    pub transition_seq_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_ref_chirho: Option<String>,
    pub phase_chirho: Gd7HeldEvidenceTransferPhaseChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_winner_history_grant_chirho: Option<Gd7WinnerEvidencePageGrantChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_fork_baseline_grant_chirho: Option<Gd7WinnerEvidencePageGrantChirho>,
    pub received_winner_history_pages_chirho: u64,
    pub received_fork_baseline_pages_chirho: u64,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

impl Gd7HeldEvidenceTransferCheckpointChirho {
    pub fn next_grant_chirho(&self) -> Option<&Gd7WinnerEvidencePageGrantChirho> {
        self.next_winner_history_grant_chirho
            .as_ref()
            .or(self.next_fork_baseline_grant_chirho.as_ref())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7HeldEvidenceTransferHeadChirho {
    pub schema_chirho: String,
    pub transfer_identity_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub transition_seq_chirho: u64,
    pub phase_chirho: Gd7HeldEvidenceTransferPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveGd7HeldEvidenceTransferChirho {
    pub checkpoint_ref_chirho: String,
    pub checkpoint_chirho: Gd7HeldEvidenceTransferCheckpointChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7HeldEvidenceTransferStoreRefusalChirho {
    InvalidIdentityChirho,
    WrongHeldSignerChirho,
    WrongWinnerVerifierChirho,
    InvalidManifestChirho,
    InvalidTransferChirho,
    InvalidTransitionChirho,
    WrongExpectedPriorChirho,
    MissingObjectChirho,
    MalformedHeadChirho,
    MalformedCheckpointChirho,
    MalformedManifestChirho,
    NonCanonicalHeadChirho,
    NonCanonicalCheckpointChirho,
    NonCanonicalManifestChirho,
    InvalidHeadSignatureChirho,
    InvalidCheckpointSignatureChirho,
    OversizedHeadChirho,
    OversizedCheckpointChirho,
    OversizedManifestChirho,
    DigestMismatchChirho,
    ImmutableCollisionChirho,
    SerializationChirho,
    SigningChirho,
    StorageChirho,
    TransferChirho(Gd7WinnerEvidenceTransferRefusalChirho),
    WinnerHistoryChirho(Gd7WinnerHistoryRefusalChirho),
    ForkBaselineChirho(Gd7ForkBaselineRefusalChirho),
}

impl fmt::Display for Gd7HeldEvidenceTransferStoreRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentityChirho => {
                formatter_chirho.write_str("GD7 held evidence-transfer identity is invalid")
            }
            Self::WrongHeldSignerChirho => {
                formatter_chirho.write_str("GD7 held evidence transfer used the wrong held signer")
            }
            Self::WrongWinnerVerifierChirho => formatter_chirho
                .write_str("GD7 held evidence transfer used the wrong winner verifier"),
            Self::InvalidManifestChirho => {
                formatter_chirho.write_str("GD7 held evidence manifest is invalid")
            }
            Self::InvalidTransferChirho => {
                formatter_chirho.write_str("GD7 held evidence page transfer is invalid")
            }
            Self::InvalidTransitionChirho => {
                formatter_chirho.write_str("GD7 held evidence transition is invalid")
            }
            Self::WrongExpectedPriorChirho => formatter_chirho
                .write_str("GD7 held evidence transition expected a different prior checkpoint"),
            Self::MissingObjectChirho => {
                formatter_chirho.write_str("GD7 held evidence object is missing")
            }
            Self::MalformedHeadChirho => {
                formatter_chirho.write_str("GD7 held evidence head is malformed")
            }
            Self::MalformedCheckpointChirho => {
                formatter_chirho.write_str("GD7 held evidence checkpoint is malformed")
            }
            Self::MalformedManifestChirho => {
                formatter_chirho.write_str("GD7 held evidence manifest is malformed")
            }
            Self::NonCanonicalHeadChirho => {
                formatter_chirho.write_str("GD7 held evidence head is non-canonical")
            }
            Self::NonCanonicalCheckpointChirho => {
                formatter_chirho.write_str("GD7 held evidence checkpoint is non-canonical")
            }
            Self::NonCanonicalManifestChirho => {
                formatter_chirho.write_str("GD7 held evidence manifest is non-canonical")
            }
            Self::InvalidHeadSignatureChirho => {
                formatter_chirho.write_str("GD7 held evidence head signature is invalid")
            }
            Self::InvalidCheckpointSignatureChirho => {
                formatter_chirho.write_str("GD7 held evidence checkpoint signature is invalid")
            }
            Self::OversizedHeadChirho => {
                formatter_chirho.write_str("GD7 held evidence head is oversized")
            }
            Self::OversizedCheckpointChirho => {
                formatter_chirho.write_str("GD7 held evidence checkpoint is oversized")
            }
            Self::OversizedManifestChirho => {
                formatter_chirho.write_str("GD7 held evidence manifest is oversized")
            }
            Self::DigestMismatchChirho => {
                formatter_chirho.write_str("GD7 held evidence object digest differs")
            }
            Self::ImmutableCollisionChirho => {
                formatter_chirho.write_str("GD7 held evidence immutable object collided")
            }
            Self::SerializationChirho => {
                formatter_chirho.write_str("GD7 held evidence serialization failed")
            }
            Self::SigningChirho => formatter_chirho.write_str("GD7 held evidence signing failed"),
            Self::StorageChirho => formatter_chirho.write_str("GD7 held evidence storage failed"),
            Self::TransferChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held evidence transfer refused: {error_chirho}"
                )
            }
            Self::WinnerHistoryChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held winner-history refused: {error_chirho}"
                )
            }
            Self::ForkBaselineChirho(error_chirho) => {
                write!(
                    formatter_chirho,
                    "GD7 held fork baseline refused: {error_chirho}"
                )
            }
        }
    }
}

impl Error for Gd7HeldEvidenceTransferStoreRefusalChirho {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TransferChirho(error_chirho) => Some(error_chirho),
            Self::WinnerHistoryChirho(error_chirho) => Some(error_chirho),
            Self::ForkBaselineChirho(error_chirho) => Some(error_chirho),
            _ => None,
        }
    }
}

impl From<Gd7WinnerEvidenceTransferRefusalChirho> for Gd7HeldEvidenceTransferStoreRefusalChirho {
    fn from(error_chirho: Gd7WinnerEvidenceTransferRefusalChirho) -> Self {
        Self::TransferChirho(error_chirho)
    }
}

impl From<Gd7WinnerHistoryRefusalChirho> for Gd7HeldEvidenceTransferStoreRefusalChirho {
    fn from(error_chirho: Gd7WinnerHistoryRefusalChirho) -> Self {
        Self::WinnerHistoryChirho(error_chirho)
    }
}

impl From<Gd7ForkBaselineRefusalChirho> for Gd7HeldEvidenceTransferStoreRefusalChirho {
    fn from(error_chirho: Gd7ForkBaselineRefusalChirho) -> Self {
        Self::ForkBaselineChirho(error_chirho)
    }
}

pub fn gd7_held_evidence_transfer_head_path_chirho(
    identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<StoragePathChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    let identity_digest_chirho = gd7_held_evidence_transfer_identity_digest_chirho(identity_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidIdentityChirho)?;
    let group_suffix_chirho = consistency_group_digest_suffix_chirho(
        &identity_chirho
            .reconciliation_identity_chirho
            .consistency_group_digest_chirho,
    )
    .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidIdentityChirho)?;
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/groups-chirho/{}/{}/{group_suffix_chirho}/held-evidence-transfer-chirho/{}/{}/{identity_digest_chirho}/active-head-chirho.json",
        &group_suffix_chirho[..2],
        &group_suffix_chirho[2..4],
        &identity_digest_chirho[..2],
        &identity_digest_chirho[2..4],
    )))
}

pub fn gd7_held_evidence_transfer_checkpoint_path_chirho(
    checkpoint_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    digest_sharded_path_chirho(
        "held-evidence-transfer-checkpoints-chirho",
        checkpoint_ref_chirho,
    )
}

fn gd7_held_evidence_manifest_path_chirho(
    manifest_ref_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    digest_sharded_path_chirho(
        "held-evidence-transfer-manifests-chirho",
        manifest_ref_chirho,
    )
}

pub struct Gd7HeldEvidenceTransferStoreChirho<'ports_chirho> {
    pub(super) storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
    pub(super) held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
    pub(super) winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
    pub(super) winner_ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
    pub(super) identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    identity_digest_chirho: String,
    head_path_chirho: StoragePathChirho,
}

impl<'ports_chirho> Gd7HeldEvidenceTransferStoreChirho<'ports_chirho> {
    pub fn new_chirho(
        storage_chirho: &'ports_chirho dyn LedgerStoragePortChirho,
        held_signer_chirho: &'ports_chirho dyn Gd7ReconciliationSignerPortChirho,
        winner_verifier_chirho: &'ports_chirho dyn Gd7ReconciliationVerifierPortChirho,
        winner_ledger_verifier_chirho: &'ports_chirho dyn Gd7LedgerRecordVerifierPortChirho,
        identity_chirho: Gd7HeldEvidenceTransferIdentityChirho,
    ) -> Result<Self, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let identity_digest_chirho =
            gd7_held_evidence_transfer_identity_digest_chirho(&identity_chirho)
                .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidIdentityChirho)?;
        let winner_node_chirho = &identity_chirho
            .reconciliation_identity_chirho
            .winner_node_chirho;
        let held_node_chirho = &identity_chirho
            .reconciliation_identity_chirho
            .held_node_chirho;
        if held_signer_chirho.key_id_chirho() != *held_node_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongHeldSignerChirho);
        }
        if winner_verifier_chirho.key_id_chirho() != *winner_node_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongWinnerVerifierChirho);
        }
        let head_path_chirho = gd7_held_evidence_transfer_head_path_chirho(&identity_chirho)?;
        Ok(Self {
            storage_chirho,
            held_signer_chirho,
            winner_verifier_chirho,
            winner_ledger_verifier_chirho,
            identity_chirho,
            identity_digest_chirho,
            head_path_chirho,
        })
    }

    pub fn begin_chirho(
        &self,
        manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    ) -> Result<ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferStoreRefusalChirho>
    {
        if let Some(active_chirho) = self.load_active_chirho()? {
            let retained_manifest_chirho = self.load_manifest_chirho(
                &active_chirho
                    .checkpoint_chirho
                    .manifest_object_digest_chirho,
            )?;
            if retained_manifest_chirho != *manifest_chirho {
                return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidManifestChirho);
            }
            return Ok(active_chirho);
        }
        if manifest_chirho.transfer_identity_chirho != self.identity_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidManifestChirho);
        }
        verify_gd7_winner_evidence_manifest_chirho(manifest_chirho, self.winner_verifier_chirho)?;
        let manifest_bytes_chirho = canonical_json_chirho(manifest_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        if manifest_bytes_chirho.len() > MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedManifestChirho);
        }
        let manifest_object_digest_chirho = digest_bytes_chirho(&manifest_bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &gd7_held_evidence_manifest_path_chirho(&manifest_object_digest_chirho)?,
            &manifest_bytes_chirho,
            MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
        )?;
        self.retain_and_verify_roots_chirho(manifest_chirho)?;
        let checkpoint_chirho = Gd7HeldEvidenceTransferCheckpointChirho {
            schema_chirho: GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO.to_owned(),
            identity_chirho: self.identity_chirho.clone(),
            manifest_object_digest_chirho,
            transition_seq_chirho: 0,
            previous_checkpoint_ref_chirho: None,
            phase_chirho: Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho,
            next_winner_history_grant_chirho: Some(
                manifest_chirho.winner_history_first_grant_chirho.clone(),
            ),
            next_fork_baseline_grant_chirho: manifest_chirho
                .fork_baseline_first_grant_chirho
                .clone(),
            received_winner_history_pages_chirho: 0,
            received_fork_baseline_pages_chirho: 0,
            key_id_chirho: String::new(),
            sig_chirho: String::new(),
        };
        self.commit_checkpoint_chirho(None, checkpoint_chirho)
    }

    pub fn receive_page_chirho(
        &self,
        expected_prior_ref_chirho: &str,
        evidence_page_transfer_chirho: &Gd7WinnerEvidencePageTransferChirho,
    ) -> Result<ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferStoreRefusalChirho>
    {
        let active_chirho = self.load_exact_prior_chirho(expected_prior_ref_chirho)?;
        if active_chirho.checkpoint_chirho.phase_chirho
            != Gd7HeldEvidenceTransferPhaseChirho::ReceivingChirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        let expected_grant_chirho = active_chirho
            .checkpoint_chirho
            .next_grant_chirho()
            .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho)?;
        if expected_grant_chirho != &evidence_page_transfer_chirho.grant_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransferChirho);
        }
        let manifest_chirho = self.load_manifest_chirho(
            &active_chirho
                .checkpoint_chirho
                .manifest_object_digest_chirho,
        )?;
        verify_gd7_winner_evidence_page_transfer_chirho(
            &manifest_chirho,
            evidence_page_transfer_chirho,
            self.winner_verifier_chirho,
        )?;
        self.retain_page_chirho(evidence_page_transfer_chirho)?;
        let mut checkpoint_chirho = active_chirho.checkpoint_chirho;
        checkpoint_chirho.transition_seq_chirho = checkpoint_chirho
            .transition_seq_chirho
            .checked_add(1)
            .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho)?;
        checkpoint_chirho.previous_checkpoint_ref_chirho =
            Some(expected_prior_ref_chirho.to_owned());
        checkpoint_chirho.sig_chirho.clear();
        match evidence_page_transfer_chirho.grant_chirho.family_chirho {
            Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => {
                checkpoint_chirho.next_winner_history_grant_chirho =
                    evidence_page_transfer_chirho.next_grant_chirho.clone();
                checkpoint_chirho.received_winner_history_pages_chirho = checkpoint_chirho
                    .received_winner_history_pages_chirho
                    .checked_add(1)
                    .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho)?;
            }
            Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => {
                if checkpoint_chirho.next_winner_history_grant_chirho.is_some() {
                    return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho);
                }
                checkpoint_chirho.next_fork_baseline_grant_chirho =
                    evidence_page_transfer_chirho.next_grant_chirho.clone();
                checkpoint_chirho.received_fork_baseline_pages_chirho = checkpoint_chirho
                    .received_fork_baseline_pages_chirho
                    .checked_add(1)
                    .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho)?;
            }
        }
        if checkpoint_chirho.next_grant_chirho().is_none() {
            self.verify_complete_chains_chirho(&manifest_chirho, &checkpoint_chirho)?;
            checkpoint_chirho.phase_chirho = Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho;
        }
        self.commit_checkpoint_chirho(Some(expected_prior_ref_chirho), checkpoint_chirho)
    }

    pub fn load_active_chirho(
        &self,
    ) -> Result<
        Option<ActiveGd7HeldEvidenceTransferChirho>,
        Gd7HeldEvidenceTransferStoreRefusalChirho,
    > {
        let Some(head_bytes_chirho) = read_bounded_chirho(
            self.storage_chirho,
            &self.head_path_chirho,
            MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO,
            Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedHeadChirho,
        )?
        else {
            return Ok(None);
        };
        let head_chirho: Gd7HeldEvidenceTransferHeadChirho =
            serde_json::from_slice(&head_bytes_chirho)
                .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::MalformedHeadChirho)?;
        self.verify_head_chirho(&head_chirho, &head_bytes_chirho)?;
        let checkpoint_path_chirho = gd7_held_evidence_transfer_checkpoint_path_chirho(
            &head_chirho.active_checkpoint_ref_chirho,
        )?;
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &checkpoint_path_chirho,
            MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
            Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::MissingObjectChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != head_chirho.active_checkpoint_ref_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::DigestMismatchChirho);
        }
        let checkpoint_chirho: Gd7HeldEvidenceTransferCheckpointChirho =
            serde_json::from_slice(&checkpoint_bytes_chirho).map_err(|_| {
                Gd7HeldEvidenceTransferStoreRefusalChirho::MalformedCheckpointChirho
            })?;
        self.verify_checkpoint_chirho(&checkpoint_chirho, &checkpoint_bytes_chirho)?;
        if checkpoint_chirho.transition_seq_chirho != head_chirho.transition_seq_chirho
            || checkpoint_chirho.phase_chirho != head_chirho.phase_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        Ok(Some(ActiveGd7HeldEvidenceTransferChirho {
            checkpoint_ref_chirho: head_chirho.active_checkpoint_ref_chirho,
            checkpoint_chirho,
        }))
    }

    /// Point-load and verify one exact immutable transfer checkpoint without consulting its head.
    pub(crate) fn load_checkpoint_by_ref_chirho(
        &self,
        checkpoint_ref_chirho: &str,
    ) -> Result<ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferStoreRefusalChirho>
    {
        let checkpoint_bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &gd7_held_evidence_transfer_checkpoint_path_chirho(checkpoint_ref_chirho)?,
            MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
            Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedCheckpointChirho,
        )?
        .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::MissingObjectChirho)?;
        if digest_bytes_chirho(&checkpoint_bytes_chirho) != checkpoint_ref_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::DigestMismatchChirho);
        }
        let checkpoint_chirho: Gd7HeldEvidenceTransferCheckpointChirho =
            serde_json::from_slice(&checkpoint_bytes_chirho).map_err(|_| {
                Gd7HeldEvidenceTransferStoreRefusalChirho::MalformedCheckpointChirho
            })?;
        self.verify_checkpoint_chirho(&checkpoint_chirho, &checkpoint_bytes_chirho)?;
        Ok(ActiveGd7HeldEvidenceTransferChirho {
            checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            checkpoint_chirho,
        })
    }

    /// Reverify and compose the exact immutable artifact set retained by this completed transfer.
    ///
    /// This is evidence-only. The method cannot install a journal, move a ref, adopt, compensate,
    /// or enable writes.
    pub fn verify_account_net_composition_chirho(
        &self,
    ) -> Result<VerifiedGd7AccountNetCompositionChirho, Gd7AccountNetCompositionRefusalChirho> {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7AccountNetCompositionRefusalChirho::IncompleteEvidenceChirho)?;
        let proof_chirho = self.verify_account_net_composition_at_checkpoint_chirho(
            &active_chirho.checkpoint_ref_chirho,
        )?;
        if self.load_active_chirho()?.as_ref() != Some(&active_chirho) {
            return Err(Gd7AccountNetCompositionRefusalChirho::StaleEvidenceChirho);
        }
        Ok(proof_chirho)
    }

    /// Reverify the immutable evidence family pinned by one exact completed checkpoint.
    pub(crate) fn verify_account_net_composition_at_checkpoint_chirho(
        &self,
        checkpoint_ref_chirho: &str,
    ) -> Result<VerifiedGd7AccountNetCompositionChirho, Gd7AccountNetCompositionRefusalChirho> {
        let checkpoint_chirho = self.load_checkpoint_by_ref_chirho(checkpoint_ref_chirho)?;
        if checkpoint_chirho.checkpoint_chirho.phase_chirho
            != Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
        {
            return Err(Gd7AccountNetCompositionRefusalChirho::IncompleteEvidenceChirho);
        }
        let manifest_chirho = self.load_manifest_chirho(
            &checkpoint_chirho
                .checkpoint_chirho
                .manifest_object_digest_chirho,
        )?;
        verify_gd7_account_net_composition_chirho(Gd7AccountNetCompositionInputsChirho {
            storage_chirho: self.storage_chirho,
            held_signer_chirho: self.held_signer_chirho,
            winner_verifier_chirho: self.winner_verifier_chirho,
            winner_ledger_verifier_chirho: self.winner_ledger_verifier_chirho,
            identity_chirho: &self.identity_chirho,
            evidence_checkpoint_ref_chirho: checkpoint_ref_chirho,
            manifest_chirho: &manifest_chirho,
        })
    }

    fn retain_and_verify_roots_chirho(
        &self,
        manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    ) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let history_root_bytes_chirho =
            canonical_json_chirho(&manifest_chirho.winner_history_root_chirho)
                .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        create_exact_chirho(
            self.storage_chirho,
            &gd7_winner_history_root_path_chirho(
                &manifest_chirho.winner_history_root_object_digest_chirho,
            )?,
            &history_root_bytes_chirho,
            MAX_GD7_WINNER_HISTORY_ROOT_BYTES_CHIRHO,
        )?;
        let baseline_root_bytes_chirho =
            canonical_json_chirho(&manifest_chirho.fork_baseline_root_chirho)
                .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        create_exact_chirho(
            self.storage_chirho,
            &gd7_fork_baseline_root_path_chirho(
                &manifest_chirho.fork_baseline_root_object_digest_chirho,
            )?,
            &baseline_root_bytes_chirho,
            MAX_GD7_FORK_BASELINE_ROOT_BYTES_CHIRHO,
        )?;
        let history_identity_chirho = self.history_identity_chirho()?;
        let baseline_identity_chirho = self.baseline_identity_chirho()?;
        load_verified_gd7_winner_history_root_chirho(
            self.storage_chirho,
            &manifest_chirho.winner_history_root_object_digest_chirho,
            &history_identity_chirho,
            self.winner_verifier_chirho,
        )?;
        load_verified_gd7_fork_baseline_root_chirho(
            self.storage_chirho,
            &manifest_chirho.fork_baseline_root_object_digest_chirho,
            &baseline_identity_chirho,
            self.winner_verifier_chirho,
        )?;
        Ok(())
    }

    fn retain_page_chirho(
        &self,
        evidence_page_transfer_chirho: &Gd7WinnerEvidencePageTransferChirho,
    ) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let (path_chirho, maximum_chirho) =
            match evidence_page_transfer_chirho.grant_chirho.family_chirho {
                Gd7WinnerEvidenceFamilyChirho::WinnerHistoryChirho => (
                    gd7_winner_history_page_path_chirho(
                        &evidence_page_transfer_chirho
                            .grant_chirho
                            .page_object_digest_chirho,
                    )?,
                    MAX_GD7_WINNER_HISTORY_PAGE_BYTES_CHIRHO,
                ),
                Gd7WinnerEvidenceFamilyChirho::ForkBaselineChirho => (
                    gd7_fork_baseline_page_path_chirho(
                        &evidence_page_transfer_chirho
                            .grant_chirho
                            .page_object_digest_chirho,
                    )?,
                    MAX_GD7_FORK_BASELINE_PAGE_BYTES_CHIRHO,
                ),
            };
        create_exact_chirho(
            self.storage_chirho,
            &path_chirho,
            &evidence_page_transfer_chirho.canonical_page_bytes_chirho,
            maximum_chirho,
        )
    }

    fn verify_complete_chains_chirho(
        &self,
        manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
        checkpoint_chirho: &Gd7HeldEvidenceTransferCheckpointChirho,
    ) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
        if checkpoint_chirho.received_winner_history_pages_chirho
            != manifest_chirho.winner_history_root_chirho.page_count_chirho
            || checkpoint_chirho.received_fork_baseline_pages_chirho
                != manifest_chirho.fork_baseline_root_chirho.page_count_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho);
        }
        verify_complete_gd7_winner_history_chain_chirho(
            self.storage_chirho,
            &manifest_chirho.winner_history_root_object_digest_chirho,
            &self.history_identity_chirho()?,
            self.winner_verifier_chirho,
            self.winner_ledger_verifier_chirho,
        )?;
        verify_complete_gd7_fork_baseline_chirho(
            self.storage_chirho,
            &manifest_chirho.fork_baseline_root_object_digest_chirho,
            &self.baseline_identity_chirho()?,
            self.winner_verifier_chirho,
        )?;
        Ok(())
    }

    fn load_manifest_chirho(
        &self,
        manifest_ref_chirho: &str,
    ) -> Result<Gd7WinnerEvidenceManifestChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let bytes_chirho = read_bounded_chirho(
            self.storage_chirho,
            &gd7_held_evidence_manifest_path_chirho(manifest_ref_chirho)?,
            MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
            Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedManifestChirho,
        )?
        .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::MissingObjectChirho)?;
        if digest_bytes_chirho(&bytes_chirho) != manifest_ref_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::DigestMismatchChirho);
        }
        let manifest_chirho: Gd7WinnerEvidenceManifestChirho =
            serde_json::from_slice(&bytes_chirho)
                .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::MalformedManifestChirho)?;
        if canonical_json_chirho(&manifest_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?
            != bytes_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::NonCanonicalManifestChirho);
        }
        if manifest_chirho.transfer_identity_chirho != self.identity_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidManifestChirho);
        }
        verify_gd7_winner_evidence_manifest_chirho(&manifest_chirho, self.winner_verifier_chirho)?;
        Ok(manifest_chirho)
    }

    #[cfg(test)]
    pub(super) fn retain_then_load_manifest_for_test_chirho(
        &self,
        manifest_chirho: &Gd7WinnerEvidenceManifestChirho,
    ) -> Result<Gd7WinnerEvidenceManifestChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let bytes_chirho = canonical_json_chirho(manifest_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        let manifest_ref_chirho = digest_bytes_chirho(&bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &gd7_held_evidence_manifest_path_chirho(&manifest_ref_chirho)?,
            &bytes_chirho,
            MAX_GD7_WINNER_EVIDENCE_MANIFEST_BYTES_CHIRHO,
        )?;
        self.load_manifest_chirho(&manifest_ref_chirho)
    }

    fn history_identity_chirho(
        &self,
    ) -> Result<Gd7WinnerHistoryIdentityChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        Gd7WinnerHistoryIdentityChirho::new_chirho(
            self.identity_chirho.reconciliation_identity_chirho.clone(),
            self.identity_chirho
                .winner_handoff_attempt_digest_chirho
                .clone(),
        )
        .map_err(Into::into)
    }

    fn baseline_identity_chirho(
        &self,
    ) -> Result<Gd7ForkBaselineIdentityChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        Gd7ForkBaselineIdentityChirho::new_chirho(
            self.identity_chirho.reconciliation_identity_chirho.clone(),
            self.identity_chirho
                .winner_handoff_attempt_digest_chirho
                .clone(),
        )
        .map_err(Into::into)
    }

    fn load_exact_prior_chirho(
        &self,
        expected_prior_ref_chirho: &str,
    ) -> Result<ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferStoreRefusalChirho>
    {
        let active_chirho = self
            .load_active_chirho()?
            .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongExpectedPriorChirho)?;
        if active_chirho.checkpoint_ref_chirho != expected_prior_ref_chirho {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        Ok(active_chirho)
    }

    fn commit_checkpoint_chirho(
        &self,
        expected_prior_ref_chirho: Option<&str>,
        mut checkpoint_chirho: Gd7HeldEvidenceTransferCheckpointChirho,
    ) -> Result<ActiveGd7HeldEvidenceTransferChirho, Gd7HeldEvidenceTransferStoreRefusalChirho>
    {
        if checkpoint_chirho.previous_checkpoint_ref_chirho.as_deref() != expected_prior_ref_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        checkpoint_chirho.key_id_chirho = self.held_signer_chirho.key_id_chirho();
        checkpoint_chirho.sig_chirho.clear();
        checkpoint_chirho.sig_chirho = sign_value_chirho(
            &checkpoint_chirho,
            self.held_signer_chirho,
            |checkpoint_chirho| &mut checkpoint_chirho.sig_chirho,
        )?;
        validate_checkpoint_shape_chirho(&checkpoint_chirho, &self.identity_chirho)?;
        let checkpoint_bytes_chirho = canonical_json_chirho(&checkpoint_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        if checkpoint_bytes_chirho.len() > MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedCheckpointChirho);
        }
        let checkpoint_ref_chirho = digest_bytes_chirho(&checkpoint_bytes_chirho);
        create_exact_chirho(
            self.storage_chirho,
            &gd7_held_evidence_transfer_checkpoint_path_chirho(&checkpoint_ref_chirho)?,
            &checkpoint_bytes_chirho,
            MAX_GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_BYTES_CHIRHO,
        )?;
        let actual_prior_chirho = self.load_active_chirho()?;
        if actual_prior_chirho
            .as_ref()
            .map(|active_chirho| active_chirho.checkpoint_ref_chirho.as_str())
            != expected_prior_ref_chirho
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::WrongExpectedPriorChirho);
        }
        let head_bytes_chirho =
            self.signed_head_chirho(&checkpoint_ref_chirho, &checkpoint_chirho)?;
        self.storage_chirho
            .atomic_write_chirho(&self.head_path_chirho, &head_bytes_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho)?;
        Ok(ActiveGd7HeldEvidenceTransferChirho {
            checkpoint_ref_chirho,
            checkpoint_chirho,
        })
    }

    fn signed_head_chirho(
        &self,
        checkpoint_ref_chirho: &str,
        checkpoint_chirho: &Gd7HeldEvidenceTransferCheckpointChirho,
    ) -> Result<Vec<u8>, Gd7HeldEvidenceTransferStoreRefusalChirho> {
        let mut head_chirho = Gd7HeldEvidenceTransferHeadChirho {
            schema_chirho: GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO.to_owned(),
            transfer_identity_digest_chirho: self.identity_digest_chirho.clone(),
            active_checkpoint_ref_chirho: checkpoint_ref_chirho.to_owned(),
            transition_seq_chirho: checkpoint_chirho.transition_seq_chirho,
            phase_chirho: checkpoint_chirho.phase_chirho,
            key_id_chirho: self.held_signer_chirho.key_id_chirho(),
            sig_chirho: String::new(),
        };
        head_chirho.sig_chirho =
            sign_value_chirho(&head_chirho, self.held_signer_chirho, |head_chirho| {
                &mut head_chirho.sig_chirho
            })?;
        let bytes_chirho = canonical_json_chirho(&head_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
        if bytes_chirho.len() > MAX_GD7_HELD_EVIDENCE_TRANSFER_HEAD_BYTES_CHIRHO {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedHeadChirho);
        }
        Ok(bytes_chirho)
    }

    fn verify_head_chirho(
        &self,
        head_chirho: &Gd7HeldEvidenceTransferHeadChirho,
        bytes_chirho: &[u8],
    ) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
        if head_chirho.schema_chirho != GD7_HELD_EVIDENCE_TRANSFER_HEAD_SCHEMA_V1_CHIRHO
            || head_chirho.transfer_identity_digest_chirho != self.identity_digest_chirho
            || !is_lower_hex_digest_chirho(&head_chirho.active_checkpoint_ref_chirho)
            || head_chirho.key_id_chirho != self.held_signer_chirho.key_id_chirho()
            || !validate_key_and_signature_chirho(
                &head_chirho.key_id_chirho,
                &head_chirho.sig_chirho,
            )
        {
            return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::NonCanonicalHeadChirho);
        }
        verify_value_chirho(
            head_chirho,
            bytes_chirho,
            &head_chirho.sig_chirho,
            self.held_signer_chirho,
            |head_chirho| &mut head_chirho.sig_chirho,
            Gd7HeldEvidenceTransferStoreRefusalChirho::NonCanonicalHeadChirho,
            Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidHeadSignatureChirho,
        )
    }

    fn verify_checkpoint_chirho(
        &self,
        checkpoint_chirho: &Gd7HeldEvidenceTransferCheckpointChirho,
        bytes_chirho: &[u8],
    ) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
        validate_checkpoint_shape_chirho(checkpoint_chirho, &self.identity_chirho)?;
        verify_value_chirho(
            checkpoint_chirho,
            bytes_chirho,
            &checkpoint_chirho.sig_chirho,
            self.held_signer_chirho,
            |checkpoint_chirho| &mut checkpoint_chirho.sig_chirho,
            Gd7HeldEvidenceTransferStoreRefusalChirho::NonCanonicalCheckpointChirho,
            Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidCheckpointSignatureChirho,
        )
    }
}

fn validate_checkpoint_shape_chirho(
    checkpoint_chirho: &Gd7HeldEvidenceTransferCheckpointChirho,
    expected_identity_chirho: &Gd7HeldEvidenceTransferIdentityChirho,
) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
    if checkpoint_chirho.schema_chirho != GD7_HELD_EVIDENCE_TRANSFER_CHECKPOINT_SCHEMA_V1_CHIRHO
        || checkpoint_chirho.identity_chirho != *expected_identity_chirho
        || !is_lower_hex_digest_chirho(&checkpoint_chirho.manifest_object_digest_chirho)
        || checkpoint_chirho.key_id_chirho
            != checkpoint_chirho
                .identity_chirho
                .reconciliation_identity_chirho
                .held_node_chirho
        || !validate_key_and_signature_chirho(
            &checkpoint_chirho.key_id_chirho,
            &checkpoint_chirho.sig_chirho,
        )
        || (checkpoint_chirho.phase_chirho == Gd7HeldEvidenceTransferPhaseChirho::CompleteChirho
            && checkpoint_chirho.next_grant_chirho().is_some())
    {
        return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidTransitionChirho);
    }
    Ok(())
}

fn sign_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &ValueChirho,
    signer_chirho: &dyn Gd7ReconciliationSignerPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
) -> Result<String, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    let mut unsigned_chirho = value_chirho.clone();
    signature_chirho(&mut unsigned_chirho).clear();
    let bytes_chirho = canonical_json_chirho(&unsigned_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
    let line_chirho = std::str::from_utf8(&bytes_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
    signer_chirho
        .sign_chirho(line_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SigningChirho)
}

#[allow(clippy::too_many_arguments)]
fn verify_value_chirho<ValueChirho: Clone + Serialize>(
    value_chirho: &ValueChirho,
    bytes_chirho: &[u8],
    signature_value_chirho: &str,
    verifier_chirho: &dyn Gd7ReconciliationVerifierPortChirho,
    signature_chirho: impl Fn(&mut ValueChirho) -> &mut String,
    noncanonical_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho,
    invalid_signature_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho,
) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
    if canonical_json_chirho(value_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?
        != bytes_chirho
    {
        return Err(noncanonical_chirho);
    }
    let mut unsigned_chirho = value_chirho.clone();
    signature_chirho(&mut unsigned_chirho).clear();
    let unsigned_bytes_chirho = canonical_json_chirho(&unsigned_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
    let unsigned_line_chirho = std::str::from_utf8(&unsigned_bytes_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::SerializationChirho)?;
    if !verifier_chirho.verify_chirho(unsigned_line_chirho, signature_value_chirho) {
        return Err(invalid_signature_chirho);
    }
    Ok(())
}

fn digest_sharded_path_chirho(
    family_chirho: &str,
    digest_chirho: &str,
) -> Result<StoragePathChirho, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    if !is_lower_hex_digest_chirho(digest_chirho) {
        return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::InvalidIdentityChirho);
    }
    Ok(StoragePathChirho::new_chirho(format!(
        "{GD7_RECONCILIATION_NAMESPACE_CHIRHO}/{family_chirho}/{}/{}/{digest_chirho}.json",
        &digest_chirho[..2],
        &digest_chirho[2..4],
    )))
}

fn create_exact_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    bytes_chirho: &[u8],
    maximum_chirho: usize,
) -> Result<(), Gd7HeldEvidenceTransferStoreRefusalChirho> {
    if bytes_chirho.len() > maximum_chirho {
        return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::OversizedCheckpointChirho);
    }
    match storage_chirho
        .create_durable_chirho(path_chirho, bytes_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho)?
    {
        CreateDurableOutcomeChirho::CreatedChirho => Ok(()),
        CreateDurableOutcomeChirho::AlreadyExistsChirho => {
            let existing_chirho = read_bounded_chirho(
                storage_chirho,
                path_chirho,
                maximum_chirho,
                Gd7HeldEvidenceTransferStoreRefusalChirho::ImmutableCollisionChirho,
            )?
            .ok_or(Gd7HeldEvidenceTransferStoreRefusalChirho::ImmutableCollisionChirho)?;
            if existing_chirho == bytes_chirho {
                Ok(())
            } else {
                Err(Gd7HeldEvidenceTransferStoreRefusalChirho::ImmutableCollisionChirho)
            }
        }
    }
}

fn read_bounded_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    path_chirho: &StoragePathChirho,
    maximum_chirho: usize,
    oversized_chirho: Gd7HeldEvidenceTransferStoreRefusalChirho,
) -> Result<Option<Vec<u8>>, Gd7HeldEvidenceTransferStoreRefusalChirho> {
    let Some(length_chirho) = storage_chirho
        .object_len_chirho(path_chirho)
        .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho)?
    else {
        return Ok(None);
    };
    if length_chirho > maximum_chirho as u64 {
        return Err(oversized_chirho);
    }
    let bytes_chirho = if length_chirho == 0 {
        Vec::new()
    } else {
        storage_chirho
            .read_exact_range_chirho(path_chirho, 0, length_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho)?
    };
    if bytes_chirho.len() != length_chirho as usize
        || storage_chirho
            .object_len_chirho(path_chirho)
            .map_err(|_| Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho)?
            != Some(length_chirho)
    {
        return Err(Gd7HeldEvidenceTransferStoreRefusalChirho::StorageChirho);
    }
    Ok(Some(bytes_chirho))
}
