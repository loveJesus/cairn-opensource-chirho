// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Path-free, bounded shadow-canary evidence for offline recomputation.
//!
//! The owning store first verifies its raw signed records under the filesystem lock. This module
//! projects every current-generation member into bounded non-identifying coordinates, binds the
//! complete projection with the existing node key, and independently derives the window summary
//! during offline verification. A signed summary alone is deliberately insufficient: it constrains
//! an endpoint but cannot prove the interval between endpoints.

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_chirho::{
    evidence_digest_chirho, evidence_digest_has_shape_chirho,
    VerifiedShadowCanaryWindowSourceChirho, SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO,
    SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO,
};
use crate::shadow_canary_generation_chirho::ShadowCanaryLedgerCutChirho;
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{consistency_group_digest_chirho, ConsistencyGroupIdChirho};
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;

pub const SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V1_CHIRHO: &str =
    "writer-elector-shadow-canary-window-proof-v1-chirho";
pub const SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V2_CHIRHO: &str =
    "writer-elector-shadow-canary-window-proof-v2-chirho";
pub const SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V3_CHIRHO: &str =
    "writer-elector-shadow-canary-window-proof-v3-chirho";
pub const SHADOW_CANARY_ADOPTION_PROOF_PROJECTION_SCHEMA_V1_CHIRHO: &str =
    "writer-elector-shadow-canary-adoption-proof-projection-v1-chirho";
pub const MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO: usize = 512 * 1024;
const SHADOW_CANARY_PROJECTION_WINDOW_GENESIS_DIGEST_CHIRHO: &str =
    "shadow-canary-projection-window-genesis-chirho";
const SHADOW_CANARY_PROJECTION_DIGEST_PREFIX_CHIRHO: &str =
    "shadow-canary-projection-blake3-v1-chirho:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryProofLedgerCutChirho {
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: String,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub record_epoch_chirho: u64,
    pub consistency_group_digest_chirho: String,
}

impl ShadowCanaryProofLedgerCutChirho {
    pub(crate) fn from_generation_cut_chirho(cut_chirho: &ShadowCanaryLedgerCutChirho) -> Self {
        Self {
            append_seq_chirho: cut_chirho.append_seq_chirho(),
            append_record_digest_chirho: cut_chirho.append_record_digest_chirho().to_owned(),
            append_hlc_physical_ms_chirho: cut_chirho.append_hlc_physical_ms_chirho(),
            append_hlc_logical_chirho: cut_chirho.append_hlc_logical_chirho(),
            record_epoch_chirho: cut_chirho.record_epoch_chirho(),
            consistency_group_digest_chirho: cut_chirho
                .consistency_group_digest_chirho()
                .as_str_chirho()
                .to_owned(),
        }
    }
}

/// The wire-free part of one committed adoption descriptor.
///
/// The descriptor retains private holder receipt wires. This separately signed projection is
/// created in the same commit path and lets an offline verifier authenticate the adoption cut,
/// authority transition, and history binding without publishing those wires. The full descriptor
/// digest remains a locator; this inner signature is the independently verifiable commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedShadowCanaryAdoptionProofProjectionChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub generation_chirho: u64,
    pub prior_generation_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_descriptor_digest_chirho: Option<String>,
    pub prior_latest_evidence_digest_chirho: Option<String>,
    pub prior_latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub adopted_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub historical_leader_node_id_chirho: String,
    pub holder_node_ids_chirho: [String; 2],
    pub historical_term_chirho: u64,
    pub historical_membership_view_digest_chirho: String,
    pub elected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub candidate_journal_binding_digest_chirho: String,
    pub candidate_journal_digest_chirho: String,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub(crate) struct ShadowCanaryAdoptionProofProjectionInputChirho {
    pub node_id_chirho: NodeIdChirho,
    pub group_chirho: ConsistencyGroupIdChirho,
    pub generation_chirho: u64,
    pub prior_generation_chirho: u64,
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_descriptor_digest_chirho: Option<String>,
    pub prior_latest_evidence_digest_chirho: Option<String>,
    pub prior_latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub adopted_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub historical_leader_node_id_chirho: String,
    pub holder_node_ids_chirho: [String; 2],
    pub historical_term_chirho: u64,
    pub historical_membership_view_digest_chirho: String,
    pub elected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub candidate_journal_binding_digest_chirho: String,
    pub candidate_journal_digest_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowCanaryAdoptionProofProjectionRefusalChirho {
    ShapeRefusedChirho,
    SignatureRefusedChirho,
    BindingRefusedChirho,
    TermStrictnessRefusedChirho,
}

impl ShadowCanaryAdoptionProofProjectionRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::ShapeRefusedChirho => "ShadowCanaryAdoptionProjectionShapeRefusedChirho",
            Self::SignatureRefusedChirho => "ShadowCanaryAdoptionProjectionSignatureRefusedChirho",
            Self::BindingRefusedChirho => "ShadowCanaryAdoptionProjectionBindingRefusedChirho",
            Self::TermStrictnessRefusedChirho => "ShadowCanaryAdoptionTermStrictnessRefusedChirho",
        }
    }
}

impl fmt::Display for ShadowCanaryAdoptionProofProjectionRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl std::error::Error for ShadowCanaryAdoptionProofProjectionRefusalChirho {}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryProofHeadChirho {
    pub latest_seq_chirho: u64,
    pub latest_source_evidence_digest_chirho: String,
    pub latest_projection_digest_chirho: String,
    pub window_len_chirho: u64,
    pub permit_count_chirho: u64,
    pub refusal_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryProofRecordChirho {
    pub generation_chirho: u64,
    pub evidence_seq_chirho: u64,
    pub source_evidence_digest_chirho: String,
    pub previous_source_evidence_digest_chirho: String,
    pub projection_digest_chirho: String,
    pub previous_projection_digest_chirho: String,
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: String,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub process_generation_chirho: u64,
    pub durable_term_chirho: u64,
    pub fence_epoch_chirho: u64,
    pub consistency_group_digest_chirho: String,
    pub raft_term_chirho: u64,
    pub minter_matches_elected_leader_chirho: bool,
    pub raft_lease_valid_chirho: bool,
    pub cutover_would_permit_chirho: bool,
    pub observed_at_ms_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedShadowCanaryWindowProofChirho {
    pub schema_chirho: String,
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub generation_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_chirho: Option<u64>,
    pub generation_descriptor_digest_chirho: Option<String>,
    pub prior_latest_evidence_digest_chirho: Option<String>,
    pub adopted_ledger_cut_chirho: Option<ShadowCanaryProofLedgerCutChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adoption_proof_projection_chirho: Option<SignedShadowCanaryAdoptionProofProjectionChirho>,
    pub latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub head_chirho: Option<ShadowCanaryProofHeadChirho>,
    pub records_chirho: Vec<ShadowCanaryProofRecordChirho>,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub(crate) struct ShadowCanaryWindowProofInputChirho {
    pub node_id_chirho: NodeIdChirho,
    pub group_chirho: ConsistencyGroupIdChirho,
    pub generation_chirho: u64,
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_chirho: Option<u64>,
    pub generation_descriptor_digest_chirho: Option<String>,
    pub prior_latest_evidence_digest_chirho: Option<String>,
    pub adopted_ledger_cut_chirho: Option<ShadowCanaryLedgerCutChirho>,
    pub adoption_proof_projection_chirho: Option<SignedShadowCanaryAdoptionProofProjectionChirho>,
    pub latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
    pub window_source_chirho: Option<VerifiedShadowCanaryWindowSourceChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryProjectedWindowChirho {
    pub latest_seq_chirho: u64,
    pub latest_evidence_digest_chirho: String,
    pub latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub window_len_chirho: u64,
    pub permit_count_chirho: u64,
    pub refusal_count_chirho: u64,
    pub oldest_observed_at_ms_chirho: u64,
    pub latest_observed_at_ms_chirho: u64,
    pub oldest_fence_epoch_chirho: u64,
    pub latest_fence_epoch_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryWindowProofChirho {
    pub node_id_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub generation_chirho: u64,
    pub activation_anchor_digest_chirho: Option<String>,
    pub prior_generation_chirho: Option<u64>,
    pub generation_descriptor_digest_chirho: Option<String>,
    pub prior_latest_evidence_digest_chirho: Option<String>,
    pub adopted_ledger_cut_chirho: Option<ShadowCanaryProofLedgerCutChirho>,
    pub adoption_proof_projection_chirho: Option<SignedShadowCanaryAdoptionProofProjectionChirho>,
    pub latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
    pub window_chirho: Option<VerifiedShadowCanaryProjectedWindowChirho>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowCanaryWriterWindowRequirementsChirho {
    pub minimum_observation_count_chirho: u64,
    pub minimum_interval_millis_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryWriterWindowChirho {
    pub observation_count_chirho: u64,
    pub interval_millis_chirho: u64,
    pub latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowCanaryWindowProofRefusalChirho {
    BytesRefusedChirho,
    DecodeRefusedChirho,
    ShapeRefusedChirho,
    SignatureRefusedChirho,
    ActivationAnchorRefusedChirho,
    GenerationRefusedChirho,
    PopulationRefusedChirho,
    ChainRefusedChirho,
    CoordinateRefusedChirho,
    CountRefusedChirho,
    LedgerCutRefusedChirho,
    AdoptionProjectionRefusedChirho(ShadowCanaryAdoptionProofProjectionRefusalChirho),
    WriterRequirementRefusedChirho,
    WriterPopulationRefusedChirho,
    WriterRefusalObservedChirho,
    WriterIntervalRefusedChirho,
}

impl ShadowCanaryWindowProofRefusalChirho {
    pub const fn as_str_chirho(self) -> &'static str {
        match self {
            Self::BytesRefusedChirho => "ShadowCanaryWindowProofBytesRefusedChirho",
            Self::DecodeRefusedChirho => "ShadowCanaryWindowProofDecodeRefusedChirho",
            Self::ShapeRefusedChirho => "ShadowCanaryWindowProofShapeRefusedChirho",
            Self::SignatureRefusedChirho => "ShadowCanaryWindowProofSignatureRefusedChirho",
            Self::ActivationAnchorRefusedChirho => {
                "ShadowCanaryWindowProofActivationAnchorRefusedChirho"
            }
            Self::GenerationRefusedChirho => "ShadowCanaryWindowProofGenerationRefusedChirho",
            Self::PopulationRefusedChirho => "ShadowCanaryWindowProofPopulationRefusedChirho",
            Self::ChainRefusedChirho => "ShadowCanaryWindowProofChainRefusedChirho",
            Self::CoordinateRefusedChirho => "ShadowCanaryWindowProofCoordinateRefusedChirho",
            Self::CountRefusedChirho => "ShadowCanaryWindowProofCountRefusedChirho",
            Self::LedgerCutRefusedChirho => "ShadowCanaryWindowProofLedgerCutRefusedChirho",
            Self::AdoptionProjectionRefusedChirho(refusal_chirho) => refusal_chirho.as_str_chirho(),
            Self::WriterRequirementRefusedChirho => {
                "ShadowCanaryWriterWindowRequirementRefusedChirho"
            }
            Self::WriterPopulationRefusedChirho => {
                "ShadowCanaryWriterWindowPopulationRefusedChirho"
            }
            Self::WriterRefusalObservedChirho => "ShadowCanaryWriterWindowRefusalObservedChirho",
            Self::WriterIntervalRefusedChirho => "ShadowCanaryWriterWindowIntervalRefusedChirho",
        }
    }
}

impl fmt::Display for ShadowCanaryWindowProofRefusalChirho {
    fn fmt(&self, formatter_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter_chirho.write_str(self.as_str_chirho())
    }
}

impl std::error::Error for ShadowCanaryWindowProofRefusalChirho {}

pub(crate) fn build_signed_shadow_canary_adoption_proof_projection_chirho(
    input_chirho: ShadowCanaryAdoptionProofProjectionInputChirho,
    sign_root_chirho: &Path,
) -> Result<SignedShadowCanaryAdoptionProofProjectionChirho> {
    let group_digest_chirho = consistency_group_digest_chirho(&input_chirho.group_chirho)?;
    let node_id_chirho = input_chirho.node_id_chirho.0;
    let mut projection_chirho = SignedShadowCanaryAdoptionProofProjectionChirho {
        schema_chirho: SHADOW_CANARY_ADOPTION_PROOF_PROJECTION_SCHEMA_V1_CHIRHO.to_owned(),
        node_id_chirho: node_id_chirho.clone(),
        consistency_group_digest_chirho: group_digest_chirho,
        generation_chirho: input_chirho.generation_chirho,
        prior_generation_chirho: input_chirho.prior_generation_chirho,
        activation_anchor_digest_chirho: input_chirho.activation_anchor_digest_chirho,
        prior_generation_descriptor_digest_chirho: input_chirho
            .prior_generation_descriptor_digest_chirho,
        prior_latest_evidence_digest_chirho: input_chirho.prior_latest_evidence_digest_chirho,
        prior_latest_ledger_cut_chirho: input_chirho.prior_latest_ledger_cut_chirho,
        adopted_ledger_cut_chirho: input_chirho.adopted_ledger_cut_chirho,
        cluster_id_chirho: input_chirho.cluster_id_chirho,
        journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
        assignment_digest_chirho: input_chirho.assignment_digest_chirho,
        historical_leader_node_id_chirho: input_chirho.historical_leader_node_id_chirho,
        holder_node_ids_chirho: input_chirho.holder_node_ids_chirho,
        historical_term_chirho: input_chirho.historical_term_chirho,
        historical_membership_view_digest_chirho: input_chirho
            .historical_membership_view_digest_chirho,
        elected_term_chirho: input_chirho.elected_term_chirho,
        membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
        candidate_journal_binding_digest_chirho: input_chirho
            .candidate_journal_binding_digest_chirho,
        candidate_journal_digest_chirho: input_chirho.candidate_journal_digest_chirho,
        key_id_chirho: node_id_chirho,
        sig_chirho: String::new(),
    };
    projection_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
        sign_root_chirho,
        &unsigned_adoption_projection_message_chirho(&projection_chirho)?,
    )?;
    verify_shadow_canary_adoption_proof_projection_chirho(&projection_chirho)
        .map_err(anyhow::Error::new)?;
    Ok(projection_chirho)
}

pub fn verify_shadow_canary_adoption_proof_projection_chirho(
    projection_chirho: &SignedShadowCanaryAdoptionProofProjectionChirho,
) -> std::result::Result<(), ShadowCanaryAdoptionProofProjectionRefusalChirho> {
    if projection_chirho.schema_chirho != SHADOW_CANARY_ADOPTION_PROOF_PROJECTION_SCHEMA_V1_CHIRHO
        || !is_lower_hex_chirho(&projection_chirho.node_id_chirho, 64)
        || projection_chirho.key_id_chirho != projection_chirho.node_id_chirho
        || projection_chirho.sig_chirho.is_empty()
        || !writer_fence_group_digest_has_shape_chirho(
            &projection_chirho.consistency_group_digest_chirho,
        )
        || projection_chirho.generation_chirho == 0
        || projection_chirho.prior_generation_chirho.checked_add(1)
            != Some(projection_chirho.generation_chirho)
        || projection_chirho
            .activation_anchor_digest_chirho
            .as_deref()
            .is_none_or(|digest_chirho| !is_lower_hex_chirho(digest_chirho, 64))
        || (projection_chirho.prior_generation_chirho == 0
            && projection_chirho
                .prior_generation_descriptor_digest_chirho
                .is_some())
        || (projection_chirho.prior_generation_chirho > 0
            && !projection_chirho
                .prior_generation_descriptor_digest_chirho
                .as_deref()
                .is_some_and(|digest_chirho| is_lower_hex_chirho(digest_chirho, 64)))
        || projection_chirho
            .prior_latest_evidence_digest_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !evidence_digest_has_shape_chirho(digest_chirho))
        || (projection_chirho.prior_generation_chirho == 0
            && projection_chirho
                .prior_latest_evidence_digest_chirho
                .is_none())
        || projection_chirho.cluster_id_chirho.is_empty()
        || projection_chirho.cluster_id_chirho.len() > 256
        || !is_lower_hex_chirho(&projection_chirho.journal_genesis_digest_chirho, 64)
        || !is_lower_hex_chirho(&projection_chirho.assignment_digest_chirho, 64)
        || !is_lower_hex_chirho(&projection_chirho.historical_leader_node_id_chirho, 64)
        || projection_chirho
            .holder_node_ids_chirho
            .iter()
            .any(|node_id_chirho| !is_lower_hex_chirho(node_id_chirho, 64))
        || projection_chirho.holder_node_ids_chirho[0]
            == projection_chirho.holder_node_ids_chirho[1]
        || projection_chirho
            .holder_node_ids_chirho
            .iter()
            .any(|node_id_chirho| {
                node_id_chirho == &projection_chirho.historical_leader_node_id_chirho
            })
        || !is_lower_hex_chirho(
            &projection_chirho.historical_membership_view_digest_chirho,
            64,
        )
        || !is_lower_hex_chirho(&projection_chirho.membership_view_digest_chirho, 64)
        || !is_lower_hex_chirho(
            &projection_chirho.candidate_journal_binding_digest_chirho,
            64,
        )
        || !is_lower_hex_chirho(&projection_chirho.candidate_journal_digest_chirho, 64)
    {
        return Err(ShadowCanaryAdoptionProofProjectionRefusalChirho::ShapeRefusedChirho);
    }
    if projection_chirho.historical_term_chirho == 0
        || projection_chirho.elected_term_chirho <= projection_chirho.historical_term_chirho
    {
        return Err(ShadowCanaryAdoptionProofProjectionRefusalChirho::TermStrictnessRefusedChirho);
    }
    verify_ledger_cut_shape_chirho(
        &projection_chirho.prior_latest_ledger_cut_chirho,
        &projection_chirho.consistency_group_digest_chirho,
    )
    .map_err(|_| ShadowCanaryAdoptionProofProjectionRefusalChirho::ShapeRefusedChirho)?;
    verify_ledger_cut_shape_chirho(
        &projection_chirho.adopted_ledger_cut_chirho,
        &projection_chirho.consistency_group_digest_chirho,
    )
    .map_err(|_| ShadowCanaryAdoptionProofProjectionRefusalChirho::ShapeRefusedChirho)?;
    if projection_chirho
        .adopted_ledger_cut_chirho
        .append_seq_chirho
        < projection_chirho
            .prior_latest_ledger_cut_chirho
            .append_seq_chirho
    {
        return Err(ShadowCanaryAdoptionProofProjectionRefusalChirho::BindingRefusedChirho);
    }
    let signature_valid_chirho = signer_chirho::verify_with_pubkey_chirho(
        &projection_chirho.node_id_chirho,
        &unsigned_adoption_projection_message_chirho(projection_chirho).map_err(|_| {
            ShadowCanaryAdoptionProofProjectionRefusalChirho::SignatureRefusedChirho
        })?,
        &projection_chirho.sig_chirho,
    )
    .map_err(|_| ShadowCanaryAdoptionProofProjectionRefusalChirho::SignatureRefusedChirho)?;
    if !signature_valid_chirho {
        return Err(ShadowCanaryAdoptionProofProjectionRefusalChirho::SignatureRefusedChirho);
    }
    Ok(())
}

/// Build the report defined by
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/cf8-canary-window-loss-sequence-chirho.md`.
pub(crate) fn build_signed_shadow_canary_window_proof_chirho(
    input_chirho: ShadowCanaryWindowProofInputChirho,
    sign_root_chirho: &Path,
) -> Result<SignedShadowCanaryWindowProofChirho> {
    let group_digest_chirho = consistency_group_digest_chirho(&input_chirho.group_chirho)?;
    let (head_chirho, records_chirho) = match input_chirho.window_source_chirho {
        None => (None, Vec::new()),
        Some(source_chirho) => {
            if source_chirho.head_chirho.activation_anchor_digest_chirho
                != input_chirho.activation_anchor_digest_chirho
            {
                bail!(ShadowCanaryWindowProofRefusalChirho::ActivationAnchorRefusedChirho);
            }
            let mut records_chirho = Vec::with_capacity(source_chirho.records_chirho.len());
            let mut previous_projection_digest_chirho =
                SHADOW_CANARY_PROJECTION_WINDOW_GENESIS_DIGEST_CHIRHO.to_owned();
            for record_chirho in source_chirho.records_chirho {
                let source_evidence_digest_chirho = evidence_digest_chirho(&record_chirho)?;
                let observation_chirho = record_chirho.observation_chirho;
                let append_cut_chirho = observation_chirho.append_cut_chirho;
                let mut projected_chirho = ShadowCanaryProofRecordChirho {
                    generation_chirho: input_chirho.generation_chirho,
                    evidence_seq_chirho: record_chirho.seq_chirho,
                    source_evidence_digest_chirho,
                    previous_source_evidence_digest_chirho: record_chirho.previous_digest_chirho,
                    projection_digest_chirho: String::new(),
                    previous_projection_digest_chirho,
                    append_seq_chirho: append_cut_chirho.append_seq_chirho,
                    append_record_digest_chirho: append_cut_chirho.append_record_digest_chirho,
                    append_hlc_physical_ms_chirho: append_cut_chirho.append_hlc_physical_ms_chirho,
                    append_hlc_logical_chirho: append_cut_chirho.append_hlc_logical_chirho,
                    process_generation_chirho: append_cut_chirho.process_generation_chirho,
                    durable_term_chirho: append_cut_chirho.durable_term_chirho,
                    fence_epoch_chirho: append_cut_chirho.fence_epoch_chirho,
                    consistency_group_digest_chirho: append_cut_chirho.fence_group_digest_chirho,
                    raft_term_chirho: observation_chirho.raft_term_chirho,
                    minter_matches_elected_leader_chirho: observation_chirho
                        .raft_leader_id_chirho
                        .as_ref()
                        == Some(&observation_chirho.minter_node_id_chirho),
                    raft_lease_valid_chirho: observation_chirho.raft_lease_valid_chirho,
                    cutover_would_permit_chirho: observation_chirho.cutover_would_permit_chirho,
                    observed_at_ms_chirho: observation_chirho.at_ms_chirho,
                };
                projected_chirho.projection_digest_chirho =
                    projected_record_digest_chirho(&projected_chirho)?;
                previous_projection_digest_chirho =
                    projected_chirho.projection_digest_chirho.clone();
                records_chirho.push(projected_chirho);
            }
            let latest_projection_digest_chirho = records_chirho
                .last()
                .map(|record_chirho| record_chirho.projection_digest_chirho.clone())
                .ok_or_else(|| anyhow::anyhow!("shadow canary proof source is empty"))?;
            let head_chirho = ShadowCanaryProofHeadChirho {
                latest_seq_chirho: source_chirho.head_chirho.latest_seq_chirho,
                latest_source_evidence_digest_chirho: source_chirho
                    .head_chirho
                    .latest_digest_chirho,
                latest_projection_digest_chirho,
                window_len_chirho: source_chirho.head_chirho.window_len_chirho,
                permit_count_chirho: source_chirho.head_chirho.permit_count_chirho,
                refusal_count_chirho: source_chirho.head_chirho.refusal_count_chirho,
            };
            (Some(head_chirho), records_chirho)
        }
    };
    let node_id_chirho = input_chirho.node_id_chirho.0;
    let has_adoption_projection_chirho = input_chirho.adoption_proof_projection_chirho.is_some();
    let mut proof_chirho = SignedShadowCanaryWindowProofChirho {
        schema_chirho: if has_adoption_projection_chirho {
            SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V3_CHIRHO.to_owned()
        } else if input_chirho.activation_anchor_digest_chirho.is_some() {
            SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V2_CHIRHO.to_owned()
        } else {
            SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V1_CHIRHO.to_owned()
        },
        node_id_chirho: node_id_chirho.clone(),
        consistency_group_digest_chirho: group_digest_chirho,
        generation_chirho: input_chirho.generation_chirho,
        activation_anchor_digest_chirho: input_chirho.activation_anchor_digest_chirho,
        prior_generation_chirho: input_chirho.prior_generation_chirho,
        generation_descriptor_digest_chirho: input_chirho.generation_descriptor_digest_chirho,
        prior_latest_evidence_digest_chirho: input_chirho.prior_latest_evidence_digest_chirho,
        adopted_ledger_cut_chirho: input_chirho
            .adopted_ledger_cut_chirho
            .as_ref()
            .map(ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho),
        adoption_proof_projection_chirho: input_chirho.adoption_proof_projection_chirho,
        latest_ledger_cut_chirho: ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho(
            &input_chirho.latest_ledger_cut_chirho,
        ),
        head_chirho,
        records_chirho,
        key_id_chirho: node_id_chirho,
        sig_chirho: String::new(),
    };
    proof_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
        sign_root_chirho,
        &unsigned_proof_message_chirho(&proof_chirho)?,
    )?;
    let bytes_chirho = serde_json::to_vec(&proof_chirho)?;
    if bytes_chirho.len() > MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO {
        bail!(ShadowCanaryWindowProofRefusalChirho::BytesRefusedChirho);
    }
    verify_shadow_canary_window_proof_bytes_chirho(&bytes_chirho)
        .context("self-verify shadow canary window proof")?;
    Ok(proof_chirho)
}

pub fn shadow_canary_window_proof_bytes_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
) -> std::result::Result<Vec<u8>, ShadowCanaryWindowProofRefusalChirho> {
    let bytes_chirho = serde_json::to_vec(proof_chirho)
        .map_err(|_| ShadowCanaryWindowProofRefusalChirho::DecodeRefusedChirho)?;
    if bytes_chirho.is_empty() || bytes_chirho.len() > MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO {
        return Err(ShadowCanaryWindowProofRefusalChirho::BytesRefusedChirho);
    }
    verify_shadow_canary_window_proof_bytes_chirho(&bytes_chirho)?;
    Ok(bytes_chirho)
}

pub fn verify_shadow_canary_window_proof_bytes_chirho(
    bytes_chirho: &[u8],
) -> std::result::Result<VerifiedShadowCanaryWindowProofChirho, ShadowCanaryWindowProofRefusalChirho>
{
    if bytes_chirho.is_empty() || bytes_chirho.len() > MAX_SHADOW_CANARY_WINDOW_PROOF_BYTES_CHIRHO {
        return Err(ShadowCanaryWindowProofRefusalChirho::BytesRefusedChirho);
    }
    let proof_chirho: SignedShadowCanaryWindowProofChirho = serde_json::from_slice(bytes_chirho)
        .map_err(|_| ShadowCanaryWindowProofRefusalChirho::DecodeRefusedChirho)?;
    verify_shadow_canary_window_proof_chirho(&proof_chirho)
}

pub fn verify_shadow_canary_window_proof_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
) -> std::result::Result<VerifiedShadowCanaryWindowProofChirho, ShadowCanaryWindowProofRefusalChirho>
{
    let schema_matches_anchor_and_projection_chirho = matches!(
        (
            proof_chirho.schema_chirho.as_str(),
            &proof_chirho.activation_anchor_digest_chirho,
            &proof_chirho.adoption_proof_projection_chirho,
        ),
        (SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V1_CHIRHO, None, None)
            | (SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V2_CHIRHO, Some(_), None)
            | (
                SHADOW_CANARY_WINDOW_PROOF_SCHEMA_V3_CHIRHO,
                Some(_),
                Some(_)
            )
    );
    if !schema_matches_anchor_and_projection_chirho
        || !is_lower_hex_chirho(&proof_chirho.node_id_chirho, 64)
        || proof_chirho.key_id_chirho != proof_chirho.node_id_chirho
        || proof_chirho.sig_chirho.is_empty()
        || !writer_fence_group_digest_has_shape_chirho(
            &proof_chirho.consistency_group_digest_chirho,
        )
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::ShapeRefusedChirho);
    }
    if proof_chirho
        .activation_anchor_digest_chirho
        .as_deref()
        .is_some_and(|digest_chirho| !is_lower_hex_chirho(digest_chirho, 64))
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::ActivationAnchorRefusedChirho);
    }
    let signature_valid_chirho = signer_chirho::verify_with_pubkey_chirho(
        &proof_chirho.node_id_chirho,
        &unsigned_proof_message_chirho(proof_chirho)
            .map_err(|_| ShadowCanaryWindowProofRefusalChirho::SignatureRefusedChirho)?,
        &proof_chirho.sig_chirho,
    )
    .map_err(|_| ShadowCanaryWindowProofRefusalChirho::SignatureRefusedChirho)?;
    if !signature_valid_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::SignatureRefusedChirho);
    }
    verify_generation_shape_chirho(proof_chirho)?;
    verify_ledger_cut_shape_chirho(
        &proof_chirho.latest_ledger_cut_chirho,
        &proof_chirho.consistency_group_digest_chirho,
    )?;
    if let Some(adopted_cut_chirho) = &proof_chirho.adopted_ledger_cut_chirho {
        verify_ledger_cut_shape_chirho(
            adopted_cut_chirho,
            &proof_chirho.consistency_group_digest_chirho,
        )?;
    }
    if let Some(projection_chirho) = &proof_chirho.adoption_proof_projection_chirho {
        verify_shadow_canary_adoption_proof_projection_chirho(projection_chirho)
            .map_err(ShadowCanaryWindowProofRefusalChirho::AdoptionProjectionRefusedChirho)?;
        if projection_chirho.node_id_chirho != proof_chirho.node_id_chirho
            || projection_chirho.consistency_group_digest_chirho
                != proof_chirho.consistency_group_digest_chirho
            || projection_chirho.generation_chirho != proof_chirho.generation_chirho
            || Some(projection_chirho.prior_generation_chirho)
                != proof_chirho.prior_generation_chirho
            || projection_chirho.activation_anchor_digest_chirho
                != proof_chirho.activation_anchor_digest_chirho
            || projection_chirho.prior_latest_evidence_digest_chirho
                != proof_chirho.prior_latest_evidence_digest_chirho
            || Some(&projection_chirho.adopted_ledger_cut_chirho)
                != proof_chirho.adopted_ledger_cut_chirho.as_ref()
        {
            return Err(
                ShadowCanaryWindowProofRefusalChirho::AdoptionProjectionRefusedChirho(
                    ShadowCanaryAdoptionProofProjectionRefusalChirho::BindingRefusedChirho,
                ),
            );
        }
    }
    let window_chirho = verify_window_members_chirho(proof_chirho)?;
    Ok(VerifiedShadowCanaryWindowProofChirho {
        node_id_chirho: proof_chirho.node_id_chirho.clone(),
        consistency_group_digest_chirho: proof_chirho.consistency_group_digest_chirho.clone(),
        generation_chirho: proof_chirho.generation_chirho,
        activation_anchor_digest_chirho: proof_chirho.activation_anchor_digest_chirho.clone(),
        prior_generation_chirho: proof_chirho.prior_generation_chirho,
        generation_descriptor_digest_chirho: proof_chirho
            .generation_descriptor_digest_chirho
            .clone(),
        prior_latest_evidence_digest_chirho: proof_chirho
            .prior_latest_evidence_digest_chirho
            .clone(),
        adopted_ledger_cut_chirho: proof_chirho.adopted_ledger_cut_chirho.clone(),
        adoption_proof_projection_chirho: proof_chirho.adoption_proof_projection_chirho.clone(),
        latest_ledger_cut_chirho: proof_chirho.latest_ledger_cut_chirho.clone(),
        window_chirho,
    })
}

pub fn require_green_shadow_canary_writer_window_chirho(
    proof_chirho: &VerifiedShadowCanaryWindowProofChirho,
    requirements_chirho: ShadowCanaryWriterWindowRequirementsChirho,
) -> std::result::Result<VerifiedShadowCanaryWriterWindowChirho, ShadowCanaryWindowProofRefusalChirho>
{
    if requirements_chirho.minimum_observation_count_chirho < 2
        || requirements_chirho.minimum_interval_millis_chirho == 0
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::WriterRequirementRefusedChirho);
    }
    let window_chirho = proof_chirho
        .window_chirho
        .as_ref()
        .ok_or(ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho)?;
    if window_chirho.window_len_chirho < requirements_chirho.minimum_observation_count_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::WriterPopulationRefusedChirho);
    }
    if window_chirho.refusal_count_chirho != 0
        || window_chirho.permit_count_chirho != window_chirho.window_len_chirho
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::WriterRefusalObservedChirho);
    }
    let interval_millis_chirho = window_chirho
        .latest_observed_at_ms_chirho
        .checked_sub(window_chirho.oldest_observed_at_ms_chirho)
        .ok_or(ShadowCanaryWindowProofRefusalChirho::WriterIntervalRefusedChirho)?;
    if interval_millis_chirho < requirements_chirho.minimum_interval_millis_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::WriterIntervalRefusedChirho);
    }
    Ok(VerifiedShadowCanaryWriterWindowChirho {
        observation_count_chirho: window_chirho.window_len_chirho,
        interval_millis_chirho,
        latest_ledger_cut_chirho: window_chirho.latest_ledger_cut_chirho.clone(),
    })
}

fn verify_generation_shape_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
) -> std::result::Result<(), ShadowCanaryWindowProofRefusalChirho> {
    if proof_chirho.generation_chirho == 0 {
        if proof_chirho.prior_generation_chirho.is_some()
            || proof_chirho.generation_descriptor_digest_chirho.is_some()
            || proof_chirho.prior_latest_evidence_digest_chirho.is_some()
            || proof_chirho.adopted_ledger_cut_chirho.is_some()
        {
            return Err(ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho);
        }
        return Ok(());
    }
    if proof_chirho
        .prior_generation_chirho
        .and_then(|prior_chirho| prior_chirho.checked_add(1))
        != Some(proof_chirho.generation_chirho)
        || !proof_chirho
            .generation_descriptor_digest_chirho
            .as_deref()
            .is_some_and(|digest_chirho| is_lower_hex_chirho(digest_chirho, 64))
        || proof_chirho
            .prior_latest_evidence_digest_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !evidence_digest_has_shape_chirho(digest_chirho))
        || (proof_chirho.prior_generation_chirho == Some(0)
            && proof_chirho.prior_latest_evidence_digest_chirho.is_none())
        || proof_chirho.adopted_ledger_cut_chirho.is_none()
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho);
    }
    Ok(())
}

fn verify_window_members_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
) -> std::result::Result<
    Option<VerifiedShadowCanaryProjectedWindowChirho>,
    ShadowCanaryWindowProofRefusalChirho,
> {
    if proof_chirho.records_chirho.len() > SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO as usize {
        return Err(ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho);
    }
    if proof_chirho.records_chirho.is_empty() {
        if proof_chirho.head_chirho.is_some()
            || proof_chirho.generation_chirho == 0
            || proof_chirho.adopted_ledger_cut_chirho.as_ref()
                != Some(&proof_chirho.latest_ledger_cut_chirho)
        {
            return Err(ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho);
        }
        return Ok(None);
    }
    let head_chirho = proof_chirho
        .head_chirho
        .as_ref()
        .ok_or(ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho)?;
    let window_len_chirho = u64::try_from(proof_chirho.records_chirho.len())
        .map_err(|_| ShadowCanaryWindowProofRefusalChirho::CountRefusedChirho)?;
    let expected_window_len_chirho = head_chirho
        .latest_seq_chirho
        .min(SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO);
    let first_chirho = proof_chirho.records_chirho.first().unwrap();
    let last_chirho = proof_chirho.records_chirho.last().unwrap();
    let mut permit_count_chirho = 0_u64;
    let mut refusal_count_chirho = 0_u64;
    let mut prior_record_chirho: Option<&ShadowCanaryProofRecordChirho> = None;
    for record_chirho in &proof_chirho.records_chirho {
        verify_record_shape_chirho(proof_chirho, record_chirho)?;
        if let Some(adopted_cut_chirho) = &proof_chirho.adopted_ledger_cut_chirho {
            let expected_append_seq_chirho = adopted_cut_chirho
                .append_seq_chirho
                .checked_add(record_chirho.evidence_seq_chirho)
                .ok_or(ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho)?;
            if record_chirho.append_seq_chirho != expected_append_seq_chirho {
                return Err(ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho);
            }
        }
        if let Some(prior_chirho) = prior_record_chirho {
            if prior_chirho.evidence_seq_chirho.checked_add(1)
                != Some(record_chirho.evidence_seq_chirho)
                || prior_chirho.append_seq_chirho.checked_add(1)
                    != Some(record_chirho.append_seq_chirho)
                || record_chirho.previous_source_evidence_digest_chirho
                    != prior_chirho.source_evidence_digest_chirho
                || record_chirho.previous_projection_digest_chirho
                    != prior_chirho.projection_digest_chirho
                || record_chirho.fence_epoch_chirho < prior_chirho.fence_epoch_chirho
                || record_chirho.raft_term_chirho < prior_chirho.raft_term_chirho
                || record_chirho.observed_at_ms_chirho < prior_chirho.observed_at_ms_chirho
            {
                return Err(ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho);
            }
        } else if (record_chirho.evidence_seq_chirho == 1
            && record_chirho.previous_source_evidence_digest_chirho
                != SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO)
            || (record_chirho.evidence_seq_chirho > 1
                && !evidence_digest_has_shape_chirho(
                    &record_chirho.previous_source_evidence_digest_chirho,
                ))
            || record_chirho.previous_projection_digest_chirho
                != SHADOW_CANARY_PROJECTION_WINDOW_GENESIS_DIGEST_CHIRHO
        {
            return Err(ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho);
        }
        if projected_record_digest_chirho(record_chirho)
            .map_err(|_| ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho)?
            != record_chirho.projection_digest_chirho
        {
            return Err(ShadowCanaryWindowProofRefusalChirho::ChainRefusedChirho);
        }
        if record_chirho.cutover_would_permit_chirho {
            permit_count_chirho = permit_count_chirho
                .checked_add(1)
                .ok_or(ShadowCanaryWindowProofRefusalChirho::CountRefusedChirho)?;
        } else {
            refusal_count_chirho = refusal_count_chirho
                .checked_add(1)
                .ok_or(ShadowCanaryWindowProofRefusalChirho::CountRefusedChirho)?;
        }
        prior_record_chirho = Some(record_chirho);
    }
    if window_len_chirho != expected_window_len_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::PopulationRefusedChirho);
    }
    if head_chirho.latest_seq_chirho != last_chirho.evidence_seq_chirho
        || head_chirho.latest_source_evidence_digest_chirho
            != last_chirho.source_evidence_digest_chirho
        || head_chirho.latest_projection_digest_chirho != last_chirho.projection_digest_chirho
        || head_chirho.window_len_chirho != window_len_chirho
        || head_chirho.permit_count_chirho != permit_count_chirho
        || head_chirho.refusal_count_chirho != refusal_count_chirho
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::CountRefusedChirho);
    }
    let derived_latest_cut_chirho = proof_ledger_cut_from_record_chirho(last_chirho);
    if proof_chirho.latest_ledger_cut_chirho != derived_latest_cut_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::LedgerCutRefusedChirho);
    }
    Ok(Some(VerifiedShadowCanaryProjectedWindowChirho {
        latest_seq_chirho: last_chirho.evidence_seq_chirho,
        latest_evidence_digest_chirho: last_chirho.source_evidence_digest_chirho.clone(),
        latest_ledger_cut_chirho: derived_latest_cut_chirho,
        window_len_chirho,
        permit_count_chirho,
        refusal_count_chirho,
        oldest_observed_at_ms_chirho: first_chirho.observed_at_ms_chirho,
        latest_observed_at_ms_chirho: last_chirho.observed_at_ms_chirho,
        oldest_fence_epoch_chirho: first_chirho.fence_epoch_chirho,
        latest_fence_epoch_chirho: last_chirho.fence_epoch_chirho,
    }))
}

fn verify_record_shape_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
    record_chirho: &ShadowCanaryProofRecordChirho,
) -> std::result::Result<(), ShadowCanaryWindowProofRefusalChirho> {
    if record_chirho.generation_chirho != proof_chirho.generation_chirho {
        return Err(ShadowCanaryWindowProofRefusalChirho::GenerationRefusedChirho);
    }
    if record_chirho.evidence_seq_chirho == 0
        || !evidence_digest_has_shape_chirho(&record_chirho.source_evidence_digest_chirho)
        || !projection_digest_has_shape_chirho(&record_chirho.projection_digest_chirho)
        || record_chirho.append_seq_chirho == 0
        || !is_lower_hex_chirho(&record_chirho.append_record_digest_chirho, 64)
        || record_chirho.append_hlc_physical_ms_chirho == 0
        || record_chirho.process_generation_chirho == 0
        || record_chirho.durable_term_chirho != record_chirho.raft_term_chirho
        || record_chirho.fence_epoch_chirho == 0
        || record_chirho.consistency_group_digest_chirho
            != proof_chirho.consistency_group_digest_chirho
        || record_chirho.cutover_would_permit_chirho
            != (record_chirho.minter_matches_elected_leader_chirho
                && record_chirho.raft_lease_valid_chirho)
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::CoordinateRefusedChirho);
    }
    Ok(())
}

fn verify_ledger_cut_shape_chirho(
    cut_chirho: &ShadowCanaryProofLedgerCutChirho,
    group_digest_chirho: &str,
) -> std::result::Result<(), ShadowCanaryWindowProofRefusalChirho> {
    if cut_chirho.append_seq_chirho == 0
        || !is_lower_hex_chirho(&cut_chirho.append_record_digest_chirho, 64)
        || cut_chirho.append_hlc_physical_ms_chirho == 0
        || cut_chirho.record_epoch_chirho == 0
        || cut_chirho.consistency_group_digest_chirho != group_digest_chirho
    {
        return Err(ShadowCanaryWindowProofRefusalChirho::LedgerCutRefusedChirho);
    }
    Ok(())
}

fn proof_ledger_cut_from_record_chirho(
    record_chirho: &ShadowCanaryProofRecordChirho,
) -> ShadowCanaryProofLedgerCutChirho {
    ShadowCanaryProofLedgerCutChirho {
        append_seq_chirho: record_chirho.append_seq_chirho,
        append_record_digest_chirho: record_chirho.append_record_digest_chirho.clone(),
        append_hlc_physical_ms_chirho: record_chirho.append_hlc_physical_ms_chirho,
        append_hlc_logical_chirho: record_chirho.append_hlc_logical_chirho,
        record_epoch_chirho: record_chirho.fence_epoch_chirho,
        consistency_group_digest_chirho: record_chirho.consistency_group_digest_chirho.clone(),
    }
}

pub(crate) fn projected_record_digest_chirho(
    record_chirho: &ShadowCanaryProofRecordChirho,
) -> Result<String> {
    let mut unsigned_chirho = record_chirho.clone();
    unsigned_chirho.projection_digest_chirho.clear();
    Ok(format!(
        "{SHADOW_CANARY_PROJECTION_DIGEST_PREFIX_CHIRHO}{}",
        blake3::hash(&serde_json::to_vec(&unsigned_chirho)?).to_hex()
    ))
}

fn projection_digest_has_shape_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix(SHADOW_CANARY_PROJECTION_DIGEST_PREFIX_CHIRHO)
        .is_some_and(|digest_chirho| is_lower_hex_chirho(digest_chirho, 64))
}

pub(crate) fn unsigned_proof_message_chirho(
    proof_chirho: &SignedShadowCanaryWindowProofChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = proof_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub(crate) fn unsigned_adoption_projection_message_chirho(
    projection_chirho: &SignedShadowCanaryAdoptionProofProjectionChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = projection_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn writer_fence_group_digest_has_shape_chirho(value_chirho: &str) -> bool {
    value_chirho
        .strip_prefix("writer-fence-group-blake3-chirho:")
        .is_some_and(|digest_chirho| is_lower_hex_chirho(digest_chirho, 64))
}

fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
