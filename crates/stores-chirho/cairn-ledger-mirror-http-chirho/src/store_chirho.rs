// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Inert F1 follower durability and leader reconciliation state.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/zone-mirror-before-ack-contract-chirho.md`.

#[path = "bootstrap_reuse_chirho.rs"]
mod bootstrap_reuse_chirho;

use crate::family_chirho::{LedgerMirrorJournalVerifierBindingChirho, LedgerMirrorRecordChirho};
use crate::recovery_chirho::{
    LedgerMirrorDenseChainHasherChirho, LedgerMirrorVerifiedPrefixManifestChirho,
    LedgerMirrorVerifiedPrefixPageChirho,
};
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::{
    create_file_durable_chirho, fsync_dir_chirho, read_identity_stable_bounded_regular_file_chirho,
    write_file_durable_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_mirror_chirho::{
    MirrorRefusalIdentityChirho, PrepareMirrorClosureFrameV1Chirho, VerifiedMirrorFinalizeChirho,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bootstrap_reuse_chirho::bootstrap_reuses_manifest_chirho;

const MIRROR_STATE_MAX_BYTES_CHIRHO: u64 = 1024 * 1024;
const MIRROR_OBJECT_MAX_BYTES_CHIRHO: u64 = 256 * 1024 + 1;
const FOLLOWER_DIR_CHIRHO: &str = "follower-f1-chirho";
const FOLLOWER_RECORDS_DIR_CHIRHO: &str = "records-chirho";
const FOLLOWER_PREPARED_FILE_CHIRHO: &str = "prepared-chirho.json";
const FOLLOWER_HIGH_WATER_FILE_CHIRHO: &str = "high-water-chirho.json";
const FOLLOWER_BOOTSTRAP_HEAD_FILE_CHIRHO: &str = "bootstrap-head-chirho.json";
const FOLLOWER_BOOTSTRAP_STAGING_DIR_CHIRHO: &str = "bootstrap-staging-chirho";
const FOLLOWER_BOOTSTRAP_STAGE_FILE_CHIRHO: &str = "state-chirho.json";
const FOLLOWER_BOOTSTRAP_PAGES_DIR_CHIRHO: &str = "pages-chirho";
const LEADER_DIR_CHIRHO: &str = "leader-f1-chirho";
const LEADER_PENDING_FILE_CHIRHO: &str = "pending-chirho.json";
const HIGH_WATER_SCHEMA_V2_CHIRHO: &str = "ledger-mirror-f1-high-water-v2-chirho";
const HIGH_WATER_DIGEST_DOMAIN_V2_CHIRHO: &[u8] = b"ledger-mirror-f1-high-water-v2-chirho";
const BOOTSTRAP_HEAD_SCHEMA_V1_CHIRHO: &str = "ledger-mirror-f1-bootstrap-head-v1-chirho";
const BOOTSTRAP_HEAD_DIGEST_DOMAIN_V1_CHIRHO: &[u8] = b"ledger-mirror-f1-bootstrap-head-v1-chirho";

/// Signed follower continuity point. Its signature detects corruption and replacement by unsigned
/// bytes; like the other signed fixed-head stores, replacement by an older valid head remains an
/// availability exposure owed to the shared monotonic-head substrate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorHighWaterChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    origin_leader_node_id_chirho: String,
    holder_node_id_chirho: String,
    assignment_digest_chirho: String,
    assigned_node_ids_chirho: [String; 3],
    membership_view_digest_chirho: String,
    historical_term_chirho: u64,
    mirror_closure_id_chirho: String,
    prepare_frame_digest_chirho: String,
    caller_idempotency_key_digest_chirho: String,
    record_chirho: LedgerMirrorRecordChirho,
    state_digest_chirho: String,
    sig_hex_chirho: String,
}

pub(crate) struct LedgerMirrorHighWaterInputChirho {
    pub consistency_group_digest_chirho: String,
    pub origin_leader_node_id_chirho: String,
    pub holder_node_id_chirho: String,
    pub assignment_digest_chirho: String,
    pub assigned_node_ids_chirho: [String; 3],
    pub membership_view_digest_chirho: String,
    pub historical_term_chirho: u64,
    pub mirror_closure_id_chirho: String,
    pub prepare_frame_digest_chirho: String,
    pub caller_idempotency_key_digest_chirho: String,
    pub record_chirho: LedgerMirrorRecordChirho,
}

impl LedgerMirrorHighWaterChirho {
    pub(crate) fn sign_chirho(
        input_chirho: LedgerMirrorHighWaterInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut state_chirho = Self {
            schema_chirho: HIGH_WATER_SCHEMA_V2_CHIRHO.to_string(),
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            origin_leader_node_id_chirho: input_chirho.origin_leader_node_id_chirho,
            holder_node_id_chirho: input_chirho.holder_node_id_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            assigned_node_ids_chirho: input_chirho.assigned_node_ids_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            historical_term_chirho: input_chirho.historical_term_chirho,
            mirror_closure_id_chirho: input_chirho.mirror_closure_id_chirho,
            prepare_frame_digest_chirho: input_chirho.prepare_frame_digest_chirho,
            caller_idempotency_key_digest_chirho: input_chirho.caller_idempotency_key_digest_chirho,
            record_chirho: input_chirho.record_chirho,
            state_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        let digest_chirho = state_chirho.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )?;
        if possession_chirho.key_id_chirho() != state_chirho.holder_node_id_chirho {
            bail!("LedgerMirrorHighWaterSignerIdentityRefusedChirho");
        }
        state_chirho.state_digest_chirho = digest_chirho.to_hex().to_string();
        state_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(state_chirho)
    }

    fn verify_chirho(
        &self,
        expected_holder_node_id_chirho: &str,
        journal_verifier_chirho: &LedgerMirrorJournalVerifierBindingChirho,
    ) -> Result<()> {
        if self.schema_chirho != HIGH_WATER_SCHEMA_V2_CHIRHO
            || self.holder_node_id_chirho != expected_holder_node_id_chirho
            || self.historical_term_chirho == 0
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.membership_view_digest_chirho)
            || self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || self
                .assigned_node_ids_chirho
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.assigned_node_ids_chirho.len()
            || !self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| node_id_chirho == &self.origin_leader_node_id_chirho)
            || !self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| node_id_chirho == &self.holder_node_id_chirho)
        {
            bail!("LedgerMirrorHighWaterIdentityRefusedChirho");
        }
        self.record_chirho
            .verify_with_journal_chirho(journal_verifier_chirho)?;
        let digest_chirho = self.compute_digest_chirho()?;
        if self.state_digest_chirho != digest_chirho.to_hex().as_str()
            || !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
                expected_holder_node_id_chirho,
                digest_chirho.as_bytes(),
                &self.sig_hex_chirho,
            )?
        {
            bail!("LedgerMirrorHighWaterSignatureRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.state_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(HIGH_WATER_DIGEST_DOMAIN_V2_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub(crate) fn record_chirho(&self) -> &LedgerMirrorRecordChirho {
        &self.record_chirho
    }

    pub(crate) fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub(crate) fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }

    pub(crate) fn assigned_node_ids_chirho(&self) -> &[String; 3] {
        &self.assigned_node_ids_chirho
    }

    pub(crate) fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub(crate) fn historical_term_chirho(&self) -> u64 {
        self.historical_term_chirho
    }

    pub(crate) fn origin_leader_node_id_chirho(&self) -> &str {
        &self.origin_leader_node_id_chirho
    }

    pub(crate) fn holder_node_id_chirho(&self) -> &str {
        &self.holder_node_id_chirho
    }

    pub(crate) fn state_digest_chirho(&self) -> &str {
        &self.state_digest_chirho
    }

    /// Enforces finalized PREPARE replay from the zone mirror-before-ack workflow.
    pub(crate) fn matches_prepare_replay_chirho(
        &self,
        prepare_chirho: &PrepareMirrorClosureFrameV1Chirho,
        record_chirho: &LedgerMirrorRecordChirho,
    ) -> bool {
        let Self {
            schema_chirho: _,
            consistency_group_digest_chirho,
            origin_leader_node_id_chirho,
            holder_node_id_chirho,
            assignment_digest_chirho: _,
            assigned_node_ids_chirho: _,
            membership_view_digest_chirho: _,
            historical_term_chirho: _,
            mirror_closure_id_chirho,
            prepare_frame_digest_chirho,
            caller_idempotency_key_digest_chirho,
            record_chirho: persisted_record_chirho,
            state_digest_chirho: _,
            sig_hex_chirho: _,
        } = self;

        consistency_group_digest_chirho == prepare_chirho.consistency_group_digest_chirho()
            && origin_leader_node_id_chirho == prepare_chirho.origin_node_id_chirho()
            && holder_node_id_chirho == prepare_chirho.target_node_id_chirho()
            && mirror_closure_id_chirho == prepare_chirho.mirror_closure_id_chirho()
            && prepare_frame_digest_chirho == prepare_chirho.prepare_frame_digest_chirho()
            && caller_idempotency_key_digest_chirho
                == prepare_chirho.caller_idempotency_key_digest_chirho()
            && persisted_record_chirho == record_chirho
    }

    /// Enforces finalized FINALIZE replay from the zone mirror-before-ack workflow.
    pub(crate) fn matches_finalize_replay_chirho(
        &self,
        finalize_chirho: &VerifiedMirrorFinalizeChirho,
    ) -> bool {
        let Self {
            schema_chirho: _,
            consistency_group_digest_chirho,
            origin_leader_node_id_chirho,
            holder_node_id_chirho,
            assignment_digest_chirho: _,
            assigned_node_ids_chirho: _,
            membership_view_digest_chirho: _,
            historical_term_chirho: _,
            mirror_closure_id_chirho,
            prepare_frame_digest_chirho,
            caller_idempotency_key_digest_chirho,
            record_chirho: persisted_record_chirho,
            state_digest_chirho: _,
            sig_hex_chirho: _,
        } = self;

        consistency_group_digest_chirho == finalize_chirho.consistency_group_digest_chirho()
            && origin_leader_node_id_chirho == finalize_chirho.origin_node_id_chirho()
            && holder_node_id_chirho == finalize_chirho.target_node_id_chirho()
            && mirror_closure_id_chirho == finalize_chirho.mirror_closure_id_chirho()
            && prepare_frame_digest_chirho == finalize_chirho.prepare_frame_digest_chirho()
            && caller_idempotency_key_digest_chirho
                == finalize_chirho.caller_idempotency_key_digest_chirho()
            && persisted_record_chirho.record_digest_chirho
                == finalize_chirho.local_commit_binding_chirho()
    }
}

/// Signed commit point for one fully verified historical prefix.
///
/// Prefix pages and immutable objects remain inert until this head is durable. Like the live
/// high-water, a signature does not prevent replacement with an older valid head; adoption binds
/// this store to the shared monotonic-head substrate before it may become authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorBootstrapHeadChirho {
    schema_chirho: String,
    consistency_group_digest_chirho: String,
    origin_leader_node_id_chirho: String,
    holder_node_id_chirho: String,
    assignment_digest_chirho: String,
    assigned_node_ids_chirho: [String; 3],
    membership_view_digest_chirho: String,
    historical_term_chirho: u64,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    record_count_chirho: u64,
    dense_chain_digest_chirho: String,
    manifest_digest_chirho: String,
    tail_record_chirho: LedgerMirrorRecordChirho,
    state_digest_chirho: String,
    sig_hex_chirho: String,
}

pub(crate) struct LedgerMirrorBootstrapHeadInputChirho {
    pub consistency_group_digest_chirho: String,
    pub origin_leader_node_id_chirho: String,
    pub holder_node_id_chirho: String,
    pub assignment_digest_chirho: String,
    pub assigned_node_ids_chirho: [String; 3],
    pub membership_view_digest_chirho: String,
    pub historical_term_chirho: u64,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub record_count_chirho: u64,
    pub dense_chain_digest_chirho: String,
    pub manifest_digest_chirho: String,
    pub tail_record_chirho: LedgerMirrorRecordChirho,
}

impl LedgerMirrorBootstrapHeadChirho {
    pub(crate) fn sign_chirho(
        input_chirho: LedgerMirrorBootstrapHeadInputChirho,
        sign_root_chirho: &Path,
    ) -> Result<Self> {
        let mut head_chirho = Self {
            schema_chirho: BOOTSTRAP_HEAD_SCHEMA_V1_CHIRHO.to_string(),
            consistency_group_digest_chirho: input_chirho.consistency_group_digest_chirho,
            origin_leader_node_id_chirho: input_chirho.origin_leader_node_id_chirho,
            holder_node_id_chirho: input_chirho.holder_node_id_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            assigned_node_ids_chirho: input_chirho.assigned_node_ids_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            historical_term_chirho: input_chirho.historical_term_chirho,
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            record_count_chirho: input_chirho.record_count_chirho,
            dense_chain_digest_chirho: input_chirho.dense_chain_digest_chirho,
            manifest_digest_chirho: input_chirho.manifest_digest_chirho,
            tail_record_chirho: input_chirho.tail_record_chirho,
            state_digest_chirho: String::new(),
            sig_hex_chirho: String::new(),
        };
        head_chirho.validate_shape_chirho()?;
        let digest_chirho = head_chirho.compute_digest_chirho()?;
        let possession_chirho =
            cairn_signer_chirho::signer_chirho::sign_with_existing_key_possession_chirho(
                sign_root_chirho,
                digest_chirho.as_bytes(),
            )?;
        if possession_chirho.key_id_chirho() != head_chirho.holder_node_id_chirho {
            bail!("LedgerMirrorBootstrapHeadSignerIdentityRefusedChirho");
        }
        head_chirho.state_digest_chirho = digest_chirho.to_hex().to_string();
        head_chirho.sig_hex_chirho = possession_chirho.into_signature_hex_chirho();
        Ok(head_chirho)
    }

    fn verify_chirho(
        &self,
        expected_holder_node_id_chirho: &str,
        journal_verifier_chirho: &LedgerMirrorJournalVerifierBindingChirho,
    ) -> Result<()> {
        self.validate_shape_chirho()?;
        if self.holder_node_id_chirho != expected_holder_node_id_chirho {
            bail!("LedgerMirrorBootstrapHeadHolderIdentityRefusedChirho");
        }
        self.tail_record_chirho
            .verify_with_journal_chirho(journal_verifier_chirho)?;
        let digest_chirho = self.compute_digest_chirho()?;
        if self.state_digest_chirho != digest_chirho.to_hex().as_str()
            || !cairn_signer_chirho::signer_chirho::verify_with_pubkey_chirho(
                expected_holder_node_id_chirho,
                digest_chirho.as_bytes(),
                &self.sig_hex_chirho,
            )?
        {
            bail!("LedgerMirrorBootstrapHeadSignatureRefusedChirho");
        }
        Ok(())
    }

    fn validate_shape_chirho(&self) -> Result<()> {
        let assigned_chirho = self
            .assigned_node_ids_chirho
            .iter()
            .collect::<std::collections::BTreeSet<_>>();
        if self.schema_chirho != BOOTSTRAP_HEAD_SCHEMA_V1_CHIRHO
            || !is_lower_hex_digest_chirho(&self.consistency_group_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.journal_genesis_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.dense_chain_digest_chirho)
            || !is_lower_hex_digest_chirho(&self.manifest_digest_chirho)
            || self.historical_term_chirho == 0
            || self.cluster_id_chirho.is_empty()
            || self.cluster_id_chirho.len() > 256
            || self.record_count_chirho == 0
            || self.record_count_chirho != self.tail_record_chirho.record_seq_chirho
            || self.cluster_id_chirho != self.tail_record_chirho.cluster_id_chirho
            || self.journal_genesis_digest_chirho
                != self.tail_record_chirho.journal_genesis_digest_chirho
            || assigned_chirho.len() != 3
            || self
                .assigned_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || !assigned_chirho.contains(&self.origin_leader_node_id_chirho)
            || !assigned_chirho.contains(&self.holder_node_id_chirho)
            || self.origin_leader_node_id_chirho == self.holder_node_id_chirho
            || (!self.state_digest_chirho.is_empty()
                && !is_lower_hex_digest_chirho(&self.state_digest_chirho))
            || (self.state_digest_chirho.is_empty() != self.sig_hex_chirho.is_empty())
        {
            bail!("LedgerMirrorBootstrapHeadShapeRefusedChirho");
        }
        Ok(())
    }

    fn compute_digest_chirho(&self) -> Result<blake3::Hash> {
        let mut unsigned_chirho = self.clone();
        unsigned_chirho.state_digest_chirho.clear();
        unsigned_chirho.sig_hex_chirho.clear();
        let bytes_chirho = serde_json::to_vec(&unsigned_chirho)?;
        let mut hasher_chirho = blake3::Hasher::new();
        hasher_chirho.update(BOOTSTRAP_HEAD_DIGEST_DOMAIN_V1_CHIRHO);
        hasher_chirho.update(&(bytes_chirho.len() as u64).to_le_bytes());
        hasher_chirho.update(&bytes_chirho);
        Ok(hasher_chirho.finalize())
    }

    pub(crate) fn consistency_group_digest_chirho(&self) -> &str {
        &self.consistency_group_digest_chirho
    }
    pub(crate) fn origin_leader_node_id_chirho(&self) -> &str {
        &self.origin_leader_node_id_chirho
    }
    pub(crate) fn holder_node_id_chirho(&self) -> &str {
        &self.holder_node_id_chirho
    }
    pub(crate) fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }
    pub(crate) fn assigned_node_ids_chirho(&self) -> &[String; 3] {
        &self.assigned_node_ids_chirho
    }
    pub(crate) fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }
    pub(crate) fn historical_term_chirho(&self) -> u64 {
        self.historical_term_chirho
    }
    pub(crate) fn cluster_id_chirho(&self) -> &str {
        &self.cluster_id_chirho
    }
    pub(crate) fn journal_genesis_digest_chirho(&self) -> &str {
        &self.journal_genesis_digest_chirho
    }
    pub(crate) fn tail_record_chirho(&self) -> &LedgerMirrorRecordChirho {
        &self.tail_record_chirho
    }
    pub(crate) fn state_digest_chirho(&self) -> &str {
        &self.state_digest_chirho
    }
    pub(crate) fn manifest_digest_chirho(&self) -> &str {
        &self.manifest_digest_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerMirrorPrefixStageStateChirho {
    manifest_chirho: LedgerMirrorVerifiedPrefixManifestChirho,
    next_page_index_chirho: u64,
    next_seq_chirho: u64,
    next_record_digest_chirho: String,
    received_record_count_chirho: u64,
}

pub(crate) enum LedgerMirrorBootstrapCommitPreparationChirho {
    AlreadyCommittedChirho,
    SignChirho(Box<LedgerMirrorBootstrapHeadInputChirho>),
}

pub(crate) enum LedgerMirrorRecoverySourceHeadChirho {
    LiveChirho(LedgerMirrorHighWaterChirho),
    BootstrapChirho(LedgerMirrorBootstrapHeadChirho),
}

impl LedgerMirrorRecoverySourceHeadChirho {
    pub(crate) fn tail_record_chirho(&self) -> &LedgerMirrorRecordChirho {
        match self {
            Self::LiveChirho(head_chirho) => head_chirho.record_chirho(),
            Self::BootstrapChirho(head_chirho) => head_chirho.tail_record_chirho(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorPreparedSlotChirho {
    pub(crate) prepare_chirho: PrepareMirrorClosureFrameV1Chirho,
    pub(crate) record_chirho: LedgerMirrorRecordChirho,
}

pub(crate) enum LedgerMirrorPrepareOutcomeChirho {
    PreparedChirho,
    AlreadyFinalizedChirho,
}

/// Follower-only native store. No method exposes a ledger journal or mutation handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LedgerMirrorLiveHeadStoreOpenRefusalChirho {
    TypeRefusedChirho,
    UnreadableChirho,
}

impl LedgerMirrorLiveHeadStoreOpenRefusalChirho {
    pub(crate) const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::TypeRefusedChirho => "LedgerMirrorLiveHeadStoreTypeRefusedChirho",
            Self::UnreadableChirho => "LedgerMirrorLiveHeadStoreUnreadableChirho",
        }
    }
}

impl std::fmt::Display for LedgerMirrorLiveHeadStoreOpenRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl std::error::Error for LedgerMirrorLiveHeadStoreOpenRefusalChirho {}

pub(crate) struct LedgerMirrorFollowerStoreChirho {
    root_chirho: PathBuf,
    local_node_id_chirho: String,
    journal_verifier_chirho: Arc<LedgerMirrorJournalVerifierBindingChirho>,
    operation_lock_chirho: Mutex<()>,
}

/// Fixed refusal text raised before any prepared slot is written.
pub(crate) const FOLLOWER_CONTINUITY_REFUSED_CHIRHO: &str =
    "LedgerMirrorFollowerContinuityRefusedChirho";
/// Fixed refusal text raised before any prepared slot is written.
pub(crate) const FOLLOWER_HIGH_WATER_MISSING_CHIRHO: &str =
    "LedgerMirrorFollowerHighWaterMissingChirho";
/// Fixed refusal text raised before any prepared slot is written.
pub(crate) const FOLLOWER_GENESIS_CONTINUITY_REFUSED_CHIRHO: &str =
    "LedgerMirrorFollowerGenesisContinuityRefusedChirho";
/// Fixed refusal text raised before any prepared slot is written.
pub(crate) const FINALIZED_PREPARE_REPLAY_BINDING_REFUSED_CHIRHO: &str =
    "LedgerMirrorFinalizedPrepareReplayBindingRefusedChirho";

/// The holder-store prepare refusals raised STRICTLY BEFORE `write_json_chirho` puts a prepared slot
/// on disk. Each one is deterministic and proves nothing was written, so the server may report it as
/// definitely-not-executed instead of collapsing it into an in-doubt outcome.
///
/// Deliberately EXCLUDED, and this is the safety edge of the whole family: a poisoned lock or an
/// unreadable store. A previous holder of that lock may have panicked mid-write, so absence of a
/// write cannot be proven and those must stay conservatively in-doubt.
///
/// The `bail!` sites below use these same constants, so the refusal text and the classifier cannot
/// drift apart into a guard that silently matches nothing.
pub(crate) const PREPARE_PRE_DURABLE_REFUSALS_CHIRHO: &[(&str, MirrorRefusalIdentityChirho)] = &[
    (
        FOLLOWER_CONTINUITY_REFUSED_CHIRHO,
        MirrorRefusalIdentityChirho::MirrorPrepareFollowerContinuityRefusedChirho,
    ),
    (
        FOLLOWER_HIGH_WATER_MISSING_CHIRHO,
        MirrorRefusalIdentityChirho::MirrorPrepareFollowerHighWaterMissingChirho,
    ),
    (
        FOLLOWER_GENESIS_CONTINUITY_REFUSED_CHIRHO,
        MirrorRefusalIdentityChirho::MirrorPrepareFollowerGenesisContinuityRefusedChirho,
    ),
    (
        FINALIZED_PREPARE_REPLAY_BINDING_REFUSED_CHIRHO,
        MirrorRefusalIdentityChirho::MirrorPrepareFinalizedReplayBindingRefusedChirho,
    ),
];

/// Resolve a holder-store prepare error to its pre-durable identity, or `None` when the error is not
/// a recognized pre-write refusal. FAILS CLOSED BY CONSTRUCTION: an unrecognized error returns
/// `None`, and the caller keeps the conservative in-doubt identity. Widening this set is therefore
/// the only way to weaken the report, and each addition must be a refusal proven to precede the
/// durable write.
pub(crate) fn prepare_pre_durable_identity_chirho(
    error_chirho: &anyhow::Error,
) -> Option<MirrorRefusalIdentityChirho> {
    let text_chirho = error_chirho.to_string();
    PREPARE_PRE_DURABLE_REFUSALS_CHIRHO
        .iter()
        .find(|(refusal_text_chirho, _)| *refusal_text_chirho == text_chirho)
        .map(|(_, identity_chirho)| *identity_chirho)
}

impl LedgerMirrorFollowerStoreChirho {
    pub(crate) fn open_chirho(
        root_chirho: &Path,
        local_node_id_chirho: String,
        journal_verifier_chirho: Arc<LedgerMirrorJournalVerifierBindingChirho>,
    ) -> Result<Self> {
        let root_chirho = root_chirho.join(FOLLOWER_DIR_CHIRHO);
        fs::create_dir_all(root_chirho.join(FOLLOWER_RECORDS_DIR_CHIRHO))
            .context("create inert follower mirror namespace")?;
        Ok(Self {
            root_chirho,
            local_node_id_chirho,
            journal_verifier_chirho,
            operation_lock_chirho: Mutex::new(()),
        })
    }

    /// Open only an already-created follower store. This evidence path must never create, repair, or
    /// chmod a mirror coordinate while deciding whether a live high-water exists.
    pub(crate) fn open_existing_read_only_chirho(
        root_chirho: &Path,
        local_node_id_chirho: String,
        journal_verifier_chirho: Arc<LedgerMirrorJournalVerifierBindingChirho>,
    ) -> std::result::Result<Option<Self>, LedgerMirrorLiveHeadStoreOpenRefusalChirho> {
        match fs::symlink_metadata(root_chirho) {
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(_) => return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho),
            Ok(metadata_chirho) if !metadata_chirho.file_type().is_dir() => {
                return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::TypeRefusedChirho)
            }
            Ok(_) => {}
        }
        let root_chirho = root_chirho.join(FOLLOWER_DIR_CHIRHO);
        match fs::symlink_metadata(&root_chirho) {
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(_) => return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho),
            Ok(metadata_chirho) if !metadata_chirho.file_type().is_dir() => {
                return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::TypeRefusedChirho)
            }
            Ok(_) => {}
        }
        match fs::symlink_metadata(root_chirho.join(FOLLOWER_RECORDS_DIR_CHIRHO)) {
            Err(_) => return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho),
            Ok(metadata_chirho) if !metadata_chirho.file_type().is_dir() => {
                return Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::TypeRefusedChirho)
            }
            Ok(_) => {}
        }
        Ok(Some(Self {
            root_chirho,
            local_node_id_chirho,
            journal_verifier_chirho,
            operation_lock_chirho: Mutex::new(()),
        }))
    }

    pub(crate) fn verify_record_chirho(
        &self,
        record_chirho: &LedgerMirrorRecordChirho,
    ) -> Result<()> {
        record_chirho.verify_with_journal_chirho(&self.journal_verifier_chirho)
    }

    pub(crate) fn prepare_chirho(
        &self,
        prepare_chirho: PrepareMirrorClosureFrameV1Chirho,
        record_chirho: LedgerMirrorRecordChirho,
    ) -> Result<LedgerMirrorPrepareOutcomeChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        let continuity_chirho = self.load_recovery_source_head_unlocked_chirho()?;
        if let Some(continuity_chirho) = &continuity_chirho {
            let current_chirho = continuity_chirho.tail_record_chirho();
            if current_chirho.record_seq_chirho == record_chirho.record_seq_chirho
                && current_chirho.record_digest_chirho == record_chirho.record_digest_chirho
            {
                // EXHAUSTIVE ON PURPOSE. This was an `if let` on the Live arm, which the compiler
                // does not flag when the enum grows: a future source-head kind would fall silently
                // to the refusal below, which names a REPLAY-BINDING failure and would therefore be
                // misdiagnosed as a tampered replay rather than an unhandled kind. Behaviour is
                // byte-identical today; what changes is that adding a variant now fails to compile
                // here instead of failing closed under the wrong name.
                match continuity_chirho {
                    LedgerMirrorRecoverySourceHeadChirho::LiveChirho(high_water_chirho) => {
                        if high_water_chirho
                            .matches_prepare_replay_chirho(&prepare_chirho, &record_chirho)
                        {
                            return Ok(LedgerMirrorPrepareOutcomeChirho::AlreadyFinalizedChirho);
                        }
                    }
                    // A bootstrap head carries no prepare-frame artifacts, so it can never satisfy
                    // the replay oracle. Stated rather than folded into a wildcard, so a new kind
                    // cannot inherit this arm by accident.
                    LedgerMirrorRecoverySourceHeadChirho::BootstrapChirho(_) => {}
                }
                bail!("{}", FINALIZED_PREPARE_REPLAY_BINDING_REFUSED_CHIRHO);
            }
            if current_chirho.cluster_id_chirho != record_chirho.cluster_id_chirho
                || current_chirho.journal_genesis_digest_chirho
                    != record_chirho.journal_genesis_digest_chirho
                || current_chirho.record_seq_chirho != record_chirho.predecessor_seq_chirho
                || current_chirho.record_digest_chirho != record_chirho.predecessor_digest_chirho
            {
                bail!("{}", FOLLOWER_CONTINUITY_REFUSED_CHIRHO);
            }
        } else {
            if self.has_finalized_object_chirho()? {
                bail!("{}", FOLLOWER_HIGH_WATER_MISSING_CHIRHO);
            }
            if record_chirho.predecessor_seq_chirho != 0
                || record_chirho.predecessor_digest_chirho
                    != record_chirho.journal_genesis_digest_chirho
            {
                bail!("{}", FOLLOWER_GENESIS_CONTINUITY_REFUSED_CHIRHO);
            }
        }

        // Any prepare already passed current-leader authority. It may therefore replace one abandoned
        // uncommitted slot left by a prior leader; the finalized high-water is never replaced here.
        write_json_chirho(
            &self.prepared_path_chirho(),
            &LedgerMirrorPreparedSlotChirho {
                prepare_chirho,
                record_chirho,
            },
        )?;
        Ok(LedgerMirrorPrepareOutcomeChirho::PreparedChirho)
    }

    pub(crate) fn load_prepared_chirho(&self) -> Result<Option<LedgerMirrorPreparedSlotChirho>> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        read_optional_json_chirho(&self.prepared_path_chirho(), MIRROR_STATE_MAX_BYTES_CHIRHO)
    }
    pub(crate) fn load_high_water_chirho(&self) -> Result<Option<LedgerMirrorHighWaterChirho>> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        self.load_high_water_unlocked_chirho()
    }
    pub(crate) fn live_high_water_coordinate_exists_chirho(
        &self,
    ) -> std::result::Result<bool, LedgerMirrorLiveHeadStoreOpenRefusalChirho> {
        match fs::symlink_metadata(self.high_water_path_chirho()) {
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho),
            Ok(metadata_chirho) if !metadata_chirho.file_type().is_file() => {
                Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::TypeRefusedChirho)
            }
            Ok(_) => Ok(true),
        }
    }
    /// A bootstrap head is never an acceptable healthy-window source. When no live high-water
    /// exists, any coordinate at the bootstrap path is a refusal rather than "live absent".
    pub(crate) fn bootstrap_head_coordinate_exists_chirho(
        &self,
    ) -> std::result::Result<bool, LedgerMirrorLiveHeadStoreOpenRefusalChirho> {
        match fs::symlink_metadata(self.bootstrap_head_path_chirho()) {
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(LedgerMirrorLiveHeadStoreOpenRefusalChirho::UnreadableChirho),
            Ok(_) => Ok(true),
        }
    }

    /// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/item7-f1-mirror-recovery-adoption-chirho.md`.
    pub(crate) fn begin_verified_prefix_chirho(
        &self,
        manifest_chirho: LedgerMirrorVerifiedPrefixManifestChirho,
        previous_assignment_digest_chirho: Option<&str>,
    ) -> Result<bool> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        manifest_chirho.verify_chirho()?;
        if let Some(head_chirho) = self.load_bootstrap_head_unlocked_chirho()? {
            if head_chirho.manifest_digest_chirho() == manifest_chirho.manifest_digest_chirho()
                || bootstrap_reuses_manifest_chirho(
                    &head_chirho,
                    &manifest_chirho,
                    previous_assignment_digest_chirho,
                )?
            {
                self.clear_bootstrap_stage_dir_unlocked_chirho()?;
                return Ok(true);
            }
        }
        if let Some(stage_chirho) = self.load_prefix_stage_unlocked_chirho()? {
            if stage_chirho.manifest_chirho == manifest_chirho {
                return Ok(false);
            }
        }
        self.reset_bootstrap_stage_dir_unlocked_chirho()?;
        let tail_seq_chirho = manifest_chirho.tail_seq_chirho();
        let tail_record_digest_chirho = manifest_chirho.tail_record_digest_chirho().to_string();
        write_json_chirho(
            &self.bootstrap_stage_path_chirho(),
            &LedgerMirrorPrefixStageStateChirho {
                manifest_chirho,
                next_page_index_chirho: 0,
                next_seq_chirho: tail_seq_chirho,
                next_record_digest_chirho: tail_record_digest_chirho,
                received_record_count_chirho: 0,
            },
        )?;
        Ok(false)
    }

    pub(crate) fn store_verified_prefix_page_chirho(
        &self,
        page_chirho: LedgerMirrorVerifiedPrefixPageChirho,
    ) -> Result<()> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        page_chirho.verify_chirho()?;
        let mut stage_chirho = self
            .load_prefix_stage_unlocked_chirho()?
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixStageUnavailableChirho"))?;
        if page_chirho.manifest_digest_chirho()
            != stage_chirho.manifest_chirho.manifest_digest_chirho()
        {
            bail!("LedgerMirrorPrefixPageManifestBindingRefusedChirho");
        }
        if page_chirho.page_index_chirho() < stage_chirho.next_page_index_chirho {
            let stored_chirho =
                self.read_prefix_page_unlocked_chirho(page_chirho.page_index_chirho())?;
            if stored_chirho == page_chirho {
                return Ok(());
            }
            bail!("LedgerMirrorPrefixPageReplayConflictChirho");
        }
        if page_chirho.page_index_chirho() != stage_chirho.next_page_index_chirho {
            bail!("LedgerMirrorPrefixPageOrderRefusedChirho");
        }
        let records_chirho = page_chirho.records_newest_first_chirho();
        let first_chirho = records_chirho
            .first()
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixPageEmptyChirho"))?;
        if first_chirho.record_seq_chirho != stage_chirho.next_seq_chirho
            || first_chirho.record_digest_chirho != stage_chirho.next_record_digest_chirho
        {
            bail!("LedgerMirrorPrefixPageCrossContinuityRefusedChirho");
        }
        for record_chirho in records_chirho {
            if record_chirho.cluster_id_chirho != stage_chirho.manifest_chirho.cluster_id_chirho()
                || record_chirho.journal_genesis_digest_chirho
                    != stage_chirho.manifest_chirho.journal_genesis_digest_chirho()
            {
                bail!("LedgerMirrorPrefixRecordIdentityRefusedChirho");
            }
            record_chirho.verify_with_journal_chirho(&self.journal_verifier_chirho)?;
        }
        let received_record_count_chirho = stage_chirho
            .received_record_count_chirho
            .checked_add(records_chirho.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixRecordCountExhaustedChirho"))?;
        if received_record_count_chirho > stage_chirho.manifest_chirho.record_count_chirho() {
            bail!("LedgerMirrorPrefixRecordPopulationRefusedChirho");
        }
        let last_chirho = records_chirho
            .last()
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixPageEmptyChirho"))?;
        let page_path_chirho = self.bootstrap_page_path_chirho(page_chirho.page_index_chirho());
        let page_bytes_chirho = page_chirho.to_wire_bytes_chirho()?;
        match create_file_durable_chirho(&page_path_chirho, &page_bytes_chirho)? {
            CreateFileDurableOutcomeChirho::CreatedChirho => {}
            CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_chirho = read_identity_stable_bounded_regular_file_chirho(
                    &page_path_chirho,
                    crate::recovery_chirho::PREFIX_PAGE_MAX_BYTES_CHIRHO as u64,
                )?;
                if existing_chirho != page_bytes_chirho {
                    bail!("LedgerMirrorPrefixPageImmutableConflictChirho");
                }
            }
        }
        stage_chirho.next_page_index_chirho = stage_chirho
            .next_page_index_chirho
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixPageIndexExhaustedChirho"))?;
        stage_chirho.next_seq_chirho = last_chirho.predecessor_seq_chirho;
        stage_chirho.next_record_digest_chirho = last_chirho.predecessor_digest_chirho.clone();
        stage_chirho.received_record_count_chirho = received_record_count_chirho;
        write_json_chirho(&self.bootstrap_stage_path_chirho(), &stage_chirho)
    }

    pub(crate) fn prepare_bootstrap_commit_chirho(
        &self,
        manifest_digest_chirho: &str,
    ) -> Result<LedgerMirrorBootstrapCommitPreparationChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        if let Some(head_chirho) = self.load_bootstrap_head_unlocked_chirho()? {
            if head_chirho.manifest_digest_chirho() == manifest_digest_chirho {
                return Ok(LedgerMirrorBootstrapCommitPreparationChirho::AlreadyCommittedChirho);
            }
        }
        self.validated_bootstrap_head_input_unlocked_chirho(manifest_digest_chirho)
            .map(Box::new)
            .map(LedgerMirrorBootstrapCommitPreparationChirho::SignChirho)
    }

    pub(crate) fn commit_bootstrap_chirho(
        &self,
        signed_head_chirho: LedgerMirrorBootstrapHeadChirho,
    ) -> Result<LedgerMirrorBootstrapHeadChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        if let Some(existing_chirho) = self.load_bootstrap_head_unlocked_chirho()? {
            if existing_chirho == signed_head_chirho {
                return Ok(existing_chirho);
            }
            if existing_chirho.tail_record_chirho().record_seq_chirho
                >= signed_head_chirho.tail_record_chirho().record_seq_chirho
            {
                bail!("LedgerMirrorBootstrapHeadRollbackOrConflictRefusedChirho");
            }
        }
        signed_head_chirho
            .verify_chirho(&self.local_node_id_chirho, &self.journal_verifier_chirho)?;
        let expected_chirho = self.validated_bootstrap_head_input_unlocked_chirho(
            signed_head_chirho.manifest_digest_chirho(),
        )?;
        if signed_head_chirho.consistency_group_digest_chirho
            != expected_chirho.consistency_group_digest_chirho
            || signed_head_chirho.origin_leader_node_id_chirho
                != expected_chirho.origin_leader_node_id_chirho
            || signed_head_chirho.holder_node_id_chirho != expected_chirho.holder_node_id_chirho
            || signed_head_chirho.assignment_digest_chirho
                != expected_chirho.assignment_digest_chirho
            || signed_head_chirho.assigned_node_ids_chirho
                != expected_chirho.assigned_node_ids_chirho
            || signed_head_chirho.membership_view_digest_chirho
                != expected_chirho.membership_view_digest_chirho
            || signed_head_chirho.historical_term_chirho != expected_chirho.historical_term_chirho
            || signed_head_chirho.cluster_id_chirho != expected_chirho.cluster_id_chirho
            || signed_head_chirho.journal_genesis_digest_chirho
                != expected_chirho.journal_genesis_digest_chirho
            || signed_head_chirho.record_count_chirho != expected_chirho.record_count_chirho
            || signed_head_chirho.dense_chain_digest_chirho
                != expected_chirho.dense_chain_digest_chirho
            || signed_head_chirho.manifest_digest_chirho != expected_chirho.manifest_digest_chirho
            || signed_head_chirho.tail_record_chirho != expected_chirho.tail_record_chirho
        {
            bail!("LedgerMirrorBootstrapHeadStageBindingRefusedChirho");
        }
        let stage_chirho = self
            .load_prefix_stage_unlocked_chirho()?
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixStageUnavailableChirho"))?;
        for page_index_chirho in 0..stage_chirho.next_page_index_chirho {
            let page_chirho = self.read_prefix_page_unlocked_chirho(page_index_chirho)?;
            for record_chirho in page_chirho.records_newest_first_chirho() {
                let object_path_chirho = self.mirror_record_path_chirho(
                    record_chirho.record_seq_chirho,
                    &record_chirho.record_digest_chirho,
                );
                let mut object_bytes_chirho = record_chirho
                    .canonical_record_line_chirho
                    .as_bytes()
                    .to_vec();
                object_bytes_chirho.push(b'\n');
                match create_file_durable_chirho(&object_path_chirho, &object_bytes_chirho)? {
                    CreateFileDurableOutcomeChirho::CreatedChirho => {}
                    CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                        let existing_chirho = read_identity_stable_bounded_regular_file_chirho(
                            &object_path_chirho,
                            MIRROR_OBJECT_MAX_BYTES_CHIRHO,
                        )?;
                        if existing_chirho != object_bytes_chirho {
                            bail!("LedgerMirrorImmutableObjectConflictChirho");
                        }
                    }
                }
            }
        }
        write_json_chirho(&self.bootstrap_head_path_chirho(), &signed_head_chirho)?;
        self.clear_bootstrap_stage_dir_unlocked_chirho()?;
        Ok(signed_head_chirho)
    }

    pub(crate) fn load_recovery_source_head_chirho(
        &self,
    ) -> Result<Option<LedgerMirrorRecoverySourceHeadChirho>> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        self.load_recovery_source_head_unlocked_chirho()
    }

    pub(crate) fn read_recovery_record_chirho(
        &self,
        cluster_id_chirho: &str,
        journal_genesis_digest_chirho: &str,
        seq_chirho: u64,
        record_digest_chirho: &str,
    ) -> Result<Vec<u8>> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        let bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
            &self.mirror_record_path_chirho(seq_chirho, record_digest_chirho),
            MIRROR_OBJECT_MAX_BYTES_CHIRHO,
        )?;
        let line_bytes_chirho = bytes_chirho
            .strip_suffix(b"\n")
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorRecoveryRecordFramingRefusedChirho"))?;
        if line_bytes_chirho.contains(&b'\n') {
            bail!("LedgerMirrorRecoveryRecordFramingRefusedChirho");
        }
        let line_chirho = std::str::from_utf8(line_bytes_chirho)
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecoveryRecordUtf8RefusedChirho"))?;
        let parsed_chirho =
            cairn_ledger_model_chirho::wire_chirho::parse_canonical_ledger_journal_line_chirho(
                line_chirho,
            )
            .map_err(|_| anyhow::anyhow!("LedgerMirrorRecoveryRecordParseRefusedChirho"))?;
        let cairn_ledger_model_chirho::wire_chirho::LedgerJournalLineChirho::RecordChirho(
            record_chirho,
        ) = parsed_chirho
        else {
            bail!("LedgerMirrorRecoveryRecordKindRefusedChirho");
        };
        let candidate_chirho = LedgerMirrorRecordChirho {
            cluster_id_chirho: cluster_id_chirho.to_string(),
            journal_genesis_digest_chirho: journal_genesis_digest_chirho.to_string(),
            predecessor_seq_chirho: seq_chirho.checked_sub(1).ok_or_else(|| {
                anyhow::anyhow!("LedgerMirrorRecoveryRecordSequenceRefusedChirho")
            })?,
            predecessor_digest_chirho: record_chirho.prev_chirho.0,
            record_seq_chirho: record_chirho.seq_chirho,
            record_digest_chirho: record_digest_chirho.to_string(),
            record_epoch_chirho: record_chirho.epoch_chirho,
            record_hlc_physical_ms_chirho: record_chirho.hlc_chirho.physical_ms_chirho,
            record_hlc_logical_chirho: record_chirho.hlc_chirho.logical_chirho,
            canonical_record_line_chirho: line_chirho.to_string(),
        };
        candidate_chirho.verify_with_journal_chirho(&self.journal_verifier_chirho)?;
        Ok(line_bytes_chirho.to_vec())
    }

    pub(crate) fn finalize_chirho(
        &self,
        expected_prepare_digest_chirho: &str,
        expected_record_chirho: &LedgerMirrorRecordChirho,
        signed_high_water_chirho: &LedgerMirrorHighWaterChirho,
    ) -> Result<LedgerMirrorHighWaterChirho> {
        let _guard_chirho = self
            .operation_lock_chirho
            .lock()
            .map_err(|_| anyhow::anyhow!("LedgerMirrorFollowerStorePoisonedChirho"))?;
        if let Some(high_water_chirho) = self.load_high_water_unlocked_chirho()? {
            if high_water_chirho.record_chirho().record_seq_chirho
                == expected_record_chirho.record_seq_chirho
                && high_water_chirho.record_chirho().record_digest_chirho
                    == expected_record_chirho.record_digest_chirho
            {
                if high_water_chirho == *signed_high_water_chirho {
                    return Ok(high_water_chirho);
                }
                bail!("LedgerMirrorFinalizedStoreReplayBindingRefusedChirho");
            }
        }
        let slot_chirho: LedgerMirrorPreparedSlotChirho =
            read_json_chirho(&self.prepared_path_chirho(), MIRROR_STATE_MAX_BYTES_CHIRHO)
                .context("LedgerMirrorPreparedSlotUnavailableChirho")?;
        if slot_chirho.prepare_chirho.prepare_frame_digest_chirho()
            != expected_prepare_digest_chirho
            || &slot_chirho.record_chirho != expected_record_chirho
        {
            bail!("LedgerMirrorFinalizePreparedBindingRefusedChirho");
        }
        signed_high_water_chirho
            .verify_chirho(&self.local_node_id_chirho, &self.journal_verifier_chirho)?;
        let object_path_chirho = self.mirror_record_path_chirho(
            expected_record_chirho.record_seq_chirho,
            &expected_record_chirho.record_digest_chirho,
        );
        let mut object_bytes_chirho = expected_record_chirho
            .canonical_record_line_chirho
            .as_bytes()
            .to_vec();
        object_bytes_chirho.push(b'\n');
        match create_file_durable_chirho(&object_path_chirho, &object_bytes_chirho)? {
            CreateFileDurableOutcomeChirho::CreatedChirho => {}
            CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_chirho = read_identity_stable_bounded_regular_file_chirho(
                    &object_path_chirho,
                    MIRROR_OBJECT_MAX_BYTES_CHIRHO,
                )?;
                if existing_chirho != object_bytes_chirho {
                    bail!("LedgerMirrorImmutableObjectConflictChirho");
                }
            }
        }
        write_json_chirho(&self.high_water_path_chirho(), signed_high_water_chirho)?;
        remove_file_durable_chirho(&self.prepared_path_chirho())?;
        Ok(signed_high_water_chirho.clone())
    }

    fn load_high_water_unlocked_chirho(&self) -> Result<Option<LedgerMirrorHighWaterChirho>> {
        let state_chirho: Option<LedgerMirrorHighWaterChirho> = read_optional_json_chirho(
            &self.high_water_path_chirho(),
            MIRROR_STATE_MAX_BYTES_CHIRHO,
        )?;
        if let Some(state_chirho) = &state_chirho {
            state_chirho
                .verify_chirho(&self.local_node_id_chirho, &self.journal_verifier_chirho)?;
            let object_path_chirho = self.mirror_record_path_chirho(
                state_chirho.record_chirho.record_seq_chirho,
                &state_chirho.record_chirho.record_digest_chirho,
            );
            let bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
                &object_path_chirho,
                MIRROR_OBJECT_MAX_BYTES_CHIRHO,
            )?;
            let mut expected_chirho = state_chirho
                .record_chirho
                .canonical_record_line_chirho
                .as_bytes()
                .to_vec();
            expected_chirho.push(b'\n');
            if bytes_chirho != expected_chirho {
                bail!("LedgerMirrorFinalizedObjectVerificationRefusedChirho");
            }
        }
        Ok(state_chirho)
    }

    fn load_bootstrap_head_unlocked_chirho(
        &self,
    ) -> Result<Option<LedgerMirrorBootstrapHeadChirho>> {
        let state_chirho: Option<LedgerMirrorBootstrapHeadChirho> = read_optional_json_chirho(
            &self.bootstrap_head_path_chirho(),
            MIRROR_STATE_MAX_BYTES_CHIRHO,
        )?;
        if let Some(state_chirho) = &state_chirho {
            state_chirho
                .verify_chirho(&self.local_node_id_chirho, &self.journal_verifier_chirho)?;
            let tail_chirho = state_chirho.tail_record_chirho();
            let bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
                &self.mirror_record_path_chirho(
                    tail_chirho.record_seq_chirho,
                    &tail_chirho.record_digest_chirho,
                ),
                MIRROR_OBJECT_MAX_BYTES_CHIRHO,
            )?;
            let mut expected_chirho = tail_chirho.canonical_record_line_chirho.as_bytes().to_vec();
            expected_chirho.push(b'\n');
            if bytes_chirho != expected_chirho {
                bail!("LedgerMirrorBootstrapTailObjectVerificationRefusedChirho");
            }
        }
        Ok(state_chirho)
    }

    fn load_recovery_source_head_unlocked_chirho(
        &self,
    ) -> Result<Option<LedgerMirrorRecoverySourceHeadChirho>> {
        let live_chirho = self.load_high_water_unlocked_chirho()?;
        let bootstrap_chirho = self.load_bootstrap_head_unlocked_chirho()?;
        match (live_chirho, bootstrap_chirho) {
            (None, None) => Ok(None),
            (Some(live_chirho), None) => Ok(Some(
                LedgerMirrorRecoverySourceHeadChirho::LiveChirho(live_chirho),
            )),
            (None, Some(bootstrap_chirho)) => Ok(Some(
                LedgerMirrorRecoverySourceHeadChirho::BootstrapChirho(bootstrap_chirho),
            )),
            (Some(live_chirho), Some(bootstrap_chirho)) => {
                let live_record_chirho = live_chirho.record_chirho();
                let bootstrap_record_chirho = bootstrap_chirho.tail_record_chirho();
                if live_record_chirho.cluster_id_chirho != bootstrap_record_chirho.cluster_id_chirho
                    || live_record_chirho.journal_genesis_digest_chirho
                        != bootstrap_record_chirho.journal_genesis_digest_chirho
                    || (live_record_chirho.record_seq_chirho
                        == bootstrap_record_chirho.record_seq_chirho
                        && live_record_chirho.record_digest_chirho
                            != bootstrap_record_chirho.record_digest_chirho)
                {
                    bail!("LedgerMirrorRecoverySourceHeadDivergenceRefusedChirho");
                }
                if live_record_chirho.record_seq_chirho >= bootstrap_record_chirho.record_seq_chirho
                {
                    Ok(Some(LedgerMirrorRecoverySourceHeadChirho::LiveChirho(
                        live_chirho,
                    )))
                } else {
                    Ok(Some(LedgerMirrorRecoverySourceHeadChirho::BootstrapChirho(
                        bootstrap_chirho,
                    )))
                }
            }
        }
    }

    fn load_prefix_stage_unlocked_chirho(
        &self,
    ) -> Result<Option<LedgerMirrorPrefixStageStateChirho>> {
        let stage_chirho: Option<LedgerMirrorPrefixStageStateChirho> = read_optional_json_chirho(
            &self.bootstrap_stage_path_chirho(),
            MIRROR_STATE_MAX_BYTES_CHIRHO,
        )?;
        if let Some(stage_chirho) = &stage_chirho {
            stage_chirho.manifest_chirho.verify_chirho()?;
            if stage_chirho.next_seq_chirho > stage_chirho.manifest_chirho.tail_seq_chirho()
                || stage_chirho.received_record_count_chirho
                    > stage_chirho.manifest_chirho.record_count_chirho()
                || !is_lower_hex_digest_chirho(&stage_chirho.next_record_digest_chirho)
            {
                bail!("LedgerMirrorPrefixStageShapeRefusedChirho");
            }
        }
        Ok(stage_chirho)
    }

    fn read_prefix_page_unlocked_chirho(
        &self,
        page_index_chirho: u64,
    ) -> Result<LedgerMirrorVerifiedPrefixPageChirho> {
        let bytes_chirho = read_identity_stable_bounded_regular_file_chirho(
            &self.bootstrap_page_path_chirho(page_index_chirho),
            crate::recovery_chirho::PREFIX_PAGE_MAX_BYTES_CHIRHO as u64,
        )?;
        let page_chirho = LedgerMirrorVerifiedPrefixPageChirho::decode_chirho(&bytes_chirho)?;
        if page_chirho.page_index_chirho() != page_index_chirho {
            bail!("LedgerMirrorPrefixPagePathBindingRefusedChirho");
        }
        Ok(page_chirho)
    }

    fn validated_bootstrap_head_input_unlocked_chirho(
        &self,
        manifest_digest_chirho: &str,
    ) -> Result<LedgerMirrorBootstrapHeadInputChirho> {
        let stage_chirho = self
            .load_prefix_stage_unlocked_chirho()?
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixStageUnavailableChirho"))?;
        let manifest_chirho = &stage_chirho.manifest_chirho;
        if manifest_chirho.manifest_digest_chirho() != manifest_digest_chirho
            || stage_chirho.received_record_count_chirho != manifest_chirho.record_count_chirho()
            || stage_chirho.next_seq_chirho != 0
            || stage_chirho.next_record_digest_chirho
                != manifest_chirho.journal_genesis_digest_chirho()
        {
            bail!("LedgerMirrorPrefixStageIncompleteChirho");
        }
        let mut hasher_chirho = LedgerMirrorDenseChainHasherChirho::new_chirho();
        let mut expected_seq_chirho = manifest_chirho.tail_seq_chirho();
        let mut expected_digest_chirho = manifest_chirho.tail_record_digest_chirho().to_string();
        let mut tail_record_chirho = None;
        for page_index_chirho in 0..stage_chirho.next_page_index_chirho {
            let page_chirho = self.read_prefix_page_unlocked_chirho(page_index_chirho)?;
            if page_chirho.manifest_digest_chirho() != manifest_digest_chirho {
                bail!("LedgerMirrorPrefixPageManifestBindingRefusedChirho");
            }
            for record_chirho in page_chirho.records_newest_first_chirho() {
                if record_chirho.record_seq_chirho != expected_seq_chirho
                    || record_chirho.record_digest_chirho != expected_digest_chirho
                    || record_chirho.cluster_id_chirho != manifest_chirho.cluster_id_chirho()
                    || record_chirho.journal_genesis_digest_chirho
                        != manifest_chirho.journal_genesis_digest_chirho()
                {
                    bail!("LedgerMirrorPrefixSealContinuityRefusedChirho");
                }
                record_chirho.verify_with_journal_chirho(&self.journal_verifier_chirho)?;
                if tail_record_chirho.is_none() {
                    tail_record_chirho = Some(record_chirho.clone());
                }
                hasher_chirho.update_chirho(record_chirho)?;
                expected_seq_chirho = record_chirho.predecessor_seq_chirho;
                expected_digest_chirho = record_chirho.predecessor_digest_chirho.clone();
            }
        }
        let (record_count_chirho, dense_chain_digest_chirho) = hasher_chirho.finish_chirho();
        if expected_seq_chirho != 0
            || expected_digest_chirho != manifest_chirho.journal_genesis_digest_chirho()
            || record_count_chirho != manifest_chirho.record_count_chirho()
            || dense_chain_digest_chirho != manifest_chirho.dense_chain_digest_chirho()
        {
            bail!("LedgerMirrorPrefixSealClosureRefusedChirho");
        }
        let tail_record_chirho = tail_record_chirho
            .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPrefixTailRecordUnavailableChirho"))?;
        if tail_record_chirho.record_epoch_chirho != manifest_chirho.tail_epoch_chirho()
            || tail_record_chirho.record_hlc_physical_ms_chirho
                != manifest_chirho.tail_hlc_physical_ms_chirho()
            || tail_record_chirho.record_hlc_logical_chirho
                != manifest_chirho.tail_hlc_logical_chirho()
        {
            bail!("LedgerMirrorPrefixManifestTailMetadataRefusedChirho");
        }
        Ok(LedgerMirrorBootstrapHeadInputChirho {
            consistency_group_digest_chirho: manifest_chirho
                .consistency_group_digest_chirho()
                .to_string(),
            origin_leader_node_id_chirho: manifest_chirho
                .origin_leader_node_id_chirho()
                .to_string(),
            holder_node_id_chirho: self.local_node_id_chirho.clone(),
            assignment_digest_chirho: manifest_chirho.assignment_digest_chirho().to_string(),
            assigned_node_ids_chirho: manifest_chirho.assigned_node_ids_chirho().clone(),
            membership_view_digest_chirho: manifest_chirho
                .membership_view_digest_chirho()
                .to_string(),
            historical_term_chirho: manifest_chirho.expected_term_chirho(),
            cluster_id_chirho: manifest_chirho.cluster_id_chirho().to_string(),
            journal_genesis_digest_chirho: manifest_chirho
                .journal_genesis_digest_chirho()
                .to_string(),
            record_count_chirho,
            dense_chain_digest_chirho,
            manifest_digest_chirho: manifest_digest_chirho.to_string(),
            tail_record_chirho,
        })
    }

    fn reset_bootstrap_stage_dir_unlocked_chirho(&self) -> Result<()> {
        self.clear_bootstrap_stage_dir_unlocked_chirho()?;
        fs::create_dir(self.bootstrap_stage_dir_chirho())
            .context("create inert mirror prefix stage")?;
        fs::create_dir(self.bootstrap_pages_dir_chirho())
            .context("create inert mirror prefix pages")?;
        fsync_dir_chirho(&self.root_chirho)?;
        Ok(())
    }

    fn clear_bootstrap_stage_dir_unlocked_chirho(&self) -> Result<()> {
        let stage_dir_chirho = self.bootstrap_stage_dir_chirho();
        match fs::symlink_metadata(&stage_dir_chirho) {
            Ok(metadata_chirho) if metadata_chirho.file_type().is_symlink() => {
                bail!("LedgerMirrorPrefixStageSymlinkRefusedChirho");
            }
            Ok(metadata_chirho) if !metadata_chirho.is_dir() => {
                bail!("LedgerMirrorPrefixStageKindRefusedChirho");
            }
            Ok(_) => {
                fs::remove_dir_all(&stage_dir_chirho)
                    .context("remove prior inert mirror prefix stage")?;
                fsync_dir_chirho(&self.root_chirho)?;
            }
            Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {}
            Err(error_chirho) => return Err(error_chirho.into()),
        }
        Ok(())
    }

    fn has_finalized_object_chirho(&self) -> Result<bool> {
        fs::read_dir(self.root_chirho.join(FOLLOWER_RECORDS_DIR_CHIRHO))?
            .next()
            .transpose()
            .map(|entry_chirho| entry_chirho.is_some())
            .map_err(Into::into)
    }

    fn prepared_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(FOLLOWER_PREPARED_FILE_CHIRHO)
    }

    fn high_water_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(FOLLOWER_HIGH_WATER_FILE_CHIRHO)
    }

    fn bootstrap_head_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(FOLLOWER_BOOTSTRAP_HEAD_FILE_CHIRHO)
    }

    fn bootstrap_stage_dir_chirho(&self) -> PathBuf {
        self.root_chirho.join(FOLLOWER_BOOTSTRAP_STAGING_DIR_CHIRHO)
    }

    fn bootstrap_stage_path_chirho(&self) -> PathBuf {
        self.bootstrap_stage_dir_chirho()
            .join(FOLLOWER_BOOTSTRAP_STAGE_FILE_CHIRHO)
    }

    fn bootstrap_pages_dir_chirho(&self) -> PathBuf {
        self.bootstrap_stage_dir_chirho()
            .join(FOLLOWER_BOOTSTRAP_PAGES_DIR_CHIRHO)
    }

    fn bootstrap_page_path_chirho(&self, page_index_chirho: u64) -> PathBuf {
        self.bootstrap_pages_dir_chirho()
            .join(format!("{page_index_chirho:020}.json"))
    }

    fn mirror_record_path_chirho(&self, seq_chirho: u64, digest_chirho: &str) -> PathBuf {
        self.root_chirho
            .join(FOLLOWER_RECORDS_DIR_CHIRHO)
            .join(format!("{seq_chirho:020}-{digest_chirho}.jsonl"))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LedgerMirrorLeaderPendingChirho {
    pub(crate) prepare_frames_chirho: [PrepareMirrorClosureFrameV1Chirho; 2],
}

pub(crate) struct LedgerMirrorLeaderStoreChirho {
    root_chirho: PathBuf,
}

impl LedgerMirrorLeaderStoreChirho {
    pub(crate) fn open_chirho(root_chirho: &Path) -> Result<Self> {
        let root_chirho = root_chirho.join(LEADER_DIR_CHIRHO);
        fs::create_dir_all(&root_chirho)?;
        Ok(Self { root_chirho })
    }

    pub(crate) fn load_pending_chirho(&self) -> Result<Option<LedgerMirrorLeaderPendingChirho>> {
        read_optional_json_chirho(&self.pending_path_chirho(), MIRROR_STATE_MAX_BYTES_CHIRHO)
    }

    pub(crate) fn write_pending_chirho(
        &self,
        pending_chirho: &LedgerMirrorLeaderPendingChirho,
    ) -> Result<()> {
        write_json_chirho(&self.pending_path_chirho(), pending_chirho)
    }

    pub(crate) fn clear_pending_chirho(&self) -> Result<()> {
        remove_file_durable_chirho(&self.pending_path_chirho())
    }

    fn pending_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(LEADER_PENDING_FILE_CHIRHO)
    }
}

fn write_json_chirho<T: Serialize>(path_chirho: &Path, value_chirho: &T) -> Result<()> {
    let bytes_chirho = serde_json::to_vec(value_chirho)?;
    if bytes_chirho.len() as u64 > MIRROR_STATE_MAX_BYTES_CHIRHO {
        bail!("LedgerMirrorStateTooLargeChirho");
    }
    write_file_durable_chirho(path_chirho, &bytes_chirho)?;
    Ok(())
}

fn read_json_chirho<T: for<'de> Deserialize<'de>>(
    path_chirho: &Path,
    maximum_chirho: u64,
) -> Result<T> {
    let bytes_chirho =
        read_identity_stable_bounded_regular_file_chirho(path_chirho, maximum_chirho)?;
    Ok(serde_json::from_slice(&bytes_chirho)?)
}

fn read_optional_json_chirho<T: for<'de> Deserialize<'de>>(
    path_chirho: &Path,
    maximum_chirho: u64,
) -> Result<Option<T>> {
    match read_json_chirho(path_chirho, maximum_chirho) {
        Ok(value_chirho) => Ok(Some(value_chirho)),
        Err(error_chirho)
            if error_chirho
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_chirho| io_chirho.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error_chirho) => Err(error_chirho),
    }
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn remove_file_durable_chirho(path_chirho: &Path) -> Result<()> {
    match fs::remove_file(path_chirho) {
        Ok(()) => {
            let parent_chirho = path_chirho
                .parent()
                .ok_or_else(|| anyhow::anyhow!("LedgerMirrorPathHasNoParentChirho"))?;
            fsync_dir_chirho(parent_chirho)?;
            Ok(())
        }
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error_chirho) => Err(error_chirho.into()),
    }
}
