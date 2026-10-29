// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Explicit canary generations after an F1 recovery adoption.
//!
//! Generation zero remains the original shadow-mode cutover-decision chain. Adoption never
//! fabricates a local mint event into that chain. Instead, one node-signed descriptor names the
//! imported cut and prior generation, then real local observations continue in a fresh bounded
//! chain. Consumers can therefore never mistake post-adoption evidence for lifetime evidence.

use crate::elector_port_chirho::NodeIdChirho;
use crate::shadow_canary_chirho::{
    evidence_digest_has_shape_chirho, optional_shadow_canary_path_metadata_chirho,
    ShadowCanaryAppendCutChirho, ShadowCanaryChirho, ShadowCanaryEvidenceStoreChirho,
    SignedShadowCanaryEvidenceChirho, VerifiedShadowCanaryWindowChirho,
};
use crate::shadow_canary_proof_chirho::{
    build_signed_shadow_canary_adoption_proof_projection_chirho,
    build_signed_shadow_canary_window_proof_chirho,
    verify_shadow_canary_adoption_proof_projection_chirho,
    ShadowCanaryAdoptionProofProjectionInputChirho,
    ShadowCanaryAdoptionProofProjectionRefusalChirho, ShadowCanaryProofLedgerCutChirho,
    ShadowCanaryWindowProofInputChirho, SignedShadowCanaryAdoptionProofProjectionChirho,
    SignedShadowCanaryWindowProofChirho,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{
    tagged_writer_fence_group_digest_chirho, ConsistencyGroupIdChirho,
    TaggedWriterFenceGroupDigestChirho,
};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const CANARY_GENERATION_SCHEMA_V1_CHIRHO: &str = "writer-canary-generation-v1-chirho";
const CANARY_GENERATION_SCHEMA_V2_CHIRHO: &str = "writer-canary-generation-v2-chirho";
const CANARY_GENERATION_SCHEMA_V3_CHIRHO: &str = "writer-canary-generation-v3-chirho";
const CANARY_GENERATION_HEAD_FILE_CHIRHO: &str = "generation-head-chirho.json";
const CANARY_GENERATION_DESCRIPTOR_FILE_CHIRHO: &str = "adoption-generation-chirho.json";
const CANARY_GENERATIONS_DIR_CHIRHO: &str = "generations-chirho";
const CANARY_GENERATION_LOCK_CHIRHO: &str = "shadow-canary-generation-chirho";
const CANARY_GENERATION_MAX_BYTES_CHIRHO: u64 = 256 * 1024;
const CANARY_GENERATION_RECEIPT_MAX_BYTES_CHIRHO: usize = 16 * 1024;

/// One verified ledger coordinate without any claim about which process minted it.
///
/// Generation-zero observations derive this from a real local append receipt. An adoption
/// descriptor instead binds the imported record coordinate after the host has replay-verified the
/// complete journal. This type deliberately has no process-generation or current-term field: those
/// would falsely describe a historical append as a local mint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryLedgerCutChirho {
    append_seq_chirho: u64,
    append_record_digest_chirho: String,
    append_hlc_physical_ms_chirho: u64,
    append_hlc_logical_chirho: u32,
    record_epoch_chirho: u64,
    consistency_group_digest_chirho: TaggedWriterFenceGroupDigestChirho,
}

impl ShadowCanaryLedgerCutChirho {
    pub fn new_chirho(
        append_seq_chirho: u64,
        append_record_digest_chirho: String,
        append_hlc_physical_ms_chirho: u64,
        append_hlc_logical_chirho: u32,
        record_epoch_chirho: u64,
        group_chirho: &ConsistencyGroupIdChirho,
    ) -> Result<Self> {
        let cut_chirho = Self {
            append_seq_chirho,
            append_record_digest_chirho,
            append_hlc_physical_ms_chirho,
            append_hlc_logical_chirho,
            record_epoch_chirho,
            consistency_group_digest_chirho: tagged_writer_fence_group_digest_chirho(group_chirho)?,
        };
        if !valid_ledger_cut_chirho(&cut_chirho) {
            bail!("shadow canary ledger cut shape invalid");
        }
        Ok(cut_chirho)
    }

    pub fn from_append_cut_chirho(
        cut_chirho: &ShadowCanaryAppendCutChirho,
        group_chirho: &ConsistencyGroupIdChirho,
    ) -> Result<Self> {
        let consistency_group_digest_chirho =
            tagged_writer_fence_group_digest_chirho(group_chirho)?;
        if cut_chirho.fence_group_digest_chirho != consistency_group_digest_chirho.as_str_chirho() {
            bail!("ShadowCanaryAppendCutGroupBindingRefusedChirho");
        }
        Ok(Self {
            append_seq_chirho: cut_chirho.append_seq_chirho,
            append_record_digest_chirho: cut_chirho.append_record_digest_chirho.clone(),
            append_hlc_physical_ms_chirho: cut_chirho.append_hlc_physical_ms_chirho,
            append_hlc_logical_chirho: cut_chirho.append_hlc_logical_chirho,
            record_epoch_chirho: cut_chirho.fence_epoch_chirho,
            consistency_group_digest_chirho,
        })
    }

    pub fn append_seq_chirho(&self) -> u64 {
        self.append_seq_chirho
    }

    pub fn append_record_digest_chirho(&self) -> &str {
        &self.append_record_digest_chirho
    }

    pub fn append_hlc_physical_ms_chirho(&self) -> u64 {
        self.append_hlc_physical_ms_chirho
    }

    pub fn append_hlc_logical_chirho(&self) -> u32 {
        self.append_hlc_logical_chirho
    }

    pub fn record_epoch_chirho(&self) -> u64 {
        self.record_epoch_chirho
    }

    pub fn consistency_group_digest_chirho(&self) -> &TaggedWriterFenceGroupDigestChirho {
        &self.consistency_group_digest_chirho
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryAdoptionGenerationChirho {
    schema_chirho: String,
    group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    generation_chirho: u64,
    prior_generation_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    activation_anchor_digest_chirho: Option<String>,
    prior_generation_descriptor_digest_chirho: Option<String>,
    prior_latest_evidence_digest_chirho: Option<String>,
    prior_latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
    adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
    cluster_id_chirho: String,
    journal_genesis_digest_chirho: String,
    assignment_digest_chirho: String,
    historical_leader_node_id_chirho: String,
    holder_node_ids_chirho: [String; 2],
    #[serde(default)]
    historical_term_chirho: u64,
    #[serde(default)]
    historical_membership_view_digest_chirho: String,
    /// This is populated from the recovery candidate's current term at descriptor commit.
    elected_term_chirho: u64,
    membership_view_digest_chirho: String,
    holder_receipt_digests_chirho: [String; 2],
    holder_receipt_wires_chirho: [Vec<u8>; 2],
    candidate_journal_binding_digest_chirho: String,
    candidate_journal_digest_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adoption_proof_projection_chirho: Option<SignedShadowCanaryAdoptionProofProjectionChirho>,
    key_id_chirho: String,
    sig_chirho: String,
}

pub struct ShadowCanaryAdoptionGenerationInputChirho {
    pub adopted_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
    pub cluster_id_chirho: String,
    pub journal_genesis_digest_chirho: String,
    pub assignment_digest_chirho: String,
    pub historical_leader_node_id_chirho: String,
    pub holder_node_ids_chirho: [String; 2],
    pub historical_term_chirho: u64,
    pub historical_membership_view_digest_chirho: String,
    pub elected_term_chirho: u64,
    pub membership_view_digest_chirho: String,
    pub holder_receipt_digests_chirho: [String; 2],
    pub holder_receipt_wires_chirho: [Vec<u8>; 2],
    pub candidate_journal_binding_digest_chirho: String,
    pub candidate_journal_digest_chirho: String,
}

impl ShadowCanaryAdoptionGenerationChirho {
    pub fn generation_chirho(&self) -> u64 {
        self.generation_chirho
    }

    pub fn prior_generation_chirho(&self) -> u64 {
        self.prior_generation_chirho
    }

    pub fn activation_anchor_digest_chirho(&self) -> Option<&str> {
        self.activation_anchor_digest_chirho.as_deref()
    }

    pub fn prior_generation_descriptor_digest_chirho(&self) -> Option<&str> {
        self.prior_generation_descriptor_digest_chirho.as_deref()
    }

    pub fn prior_latest_evidence_digest_chirho(&self) -> Option<&str> {
        self.prior_latest_evidence_digest_chirho.as_deref()
    }

    pub fn prior_latest_ledger_cut_chirho(&self) -> &ShadowCanaryLedgerCutChirho {
        &self.prior_latest_ledger_cut_chirho
    }

    pub fn adopted_ledger_cut_chirho(&self) -> &ShadowCanaryLedgerCutChirho {
        &self.adopted_ledger_cut_chirho
    }

    pub fn candidate_journal_binding_digest_chirho(&self) -> &str {
        &self.candidate_journal_binding_digest_chirho
    }

    pub fn candidate_journal_digest_chirho(&self) -> &str {
        &self.candidate_journal_digest_chirho
    }

    pub fn cluster_id_chirho(&self) -> &str {
        &self.cluster_id_chirho
    }

    pub fn journal_genesis_digest_chirho(&self) -> &str {
        &self.journal_genesis_digest_chirho
    }

    pub fn historical_leader_node_id_chirho(&self) -> &str {
        &self.historical_leader_node_id_chirho
    }

    pub fn holder_node_ids_chirho(&self) -> &[String; 2] {
        &self.holder_node_ids_chirho
    }

    pub fn assignment_digest_chirho(&self) -> &str {
        &self.assignment_digest_chirho
    }

    pub fn elected_term_chirho(&self) -> u64 {
        self.elected_term_chirho
    }

    pub fn historical_term_chirho(&self) -> Option<u64> {
        (self.historical_term_chirho > 0).then_some(self.historical_term_chirho)
    }

    pub fn historical_membership_view_digest_chirho(&self) -> Option<&str> {
        (!self.historical_membership_view_digest_chirho.is_empty())
            .then_some(self.historical_membership_view_digest_chirho.as_str())
    }

    pub fn membership_view_digest_chirho(&self) -> &str {
        &self.membership_view_digest_chirho
    }

    pub fn holder_receipt_digests_chirho(&self) -> &[String; 2] {
        &self.holder_receipt_digests_chirho
    }

    pub fn holder_receipt_wires_chirho(&self) -> &[Vec<u8>; 2] {
        &self.holder_receipt_wires_chirho
    }

    pub fn adoption_proof_projection_chirho(
        &self,
    ) -> Option<&SignedShadowCanaryAdoptionProofProjectionChirho> {
        self.adoption_proof_projection_chirho.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryCurrentGenerationChirho {
    generation_chirho: u64,
    prior_generation_chirho: Option<u64>,
    adoption_chirho: Option<ShadowCanaryAdoptionGenerationChirho>,
    window_chirho: Option<VerifiedShadowCanaryWindowChirho>,
    latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
}

impl VerifiedShadowCanaryCurrentGenerationChirho {
    pub fn generation_chirho(&self) -> u64 {
        self.generation_chirho
    }

    pub fn prior_generation_chirho(&self) -> Option<u64> {
        self.prior_generation_chirho
    }

    pub fn adoption_chirho(&self) -> Option<&ShadowCanaryAdoptionGenerationChirho> {
        self.adoption_chirho.as_ref()
    }

    pub fn window_chirho(&self) -> Option<&VerifiedShadowCanaryWindowChirho> {
        self.window_chirho.as_ref()
    }

    /// Require the original shadow-mode cutover-evidence chain.
    ///
    /// Adopted generations are truthful local continuations, but they are not lifetime cutover
    /// evidence and must never satisfy a consumer that specifically requires generation zero.
    pub fn require_generation_zero_window_chirho(
        &self,
    ) -> Result<&VerifiedShadowCanaryWindowChirho> {
        if self.generation_chirho != 0
            || self.prior_generation_chirho.is_some()
            || self.adoption_chirho.is_some()
        {
            bail!("ShadowCanaryGenerationZeroRequiredChirho");
        }
        self.window_chirho
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ShadowCanaryGenerationZeroRequiredChirho"))
    }

    pub fn latest_ledger_cut_chirho(&self) -> &ShadowCanaryLedgerCutChirho {
        &self.latest_ledger_cut_chirho
    }
}

/// Signed selector for the current canary generation.
///
/// The signature rejects corruption and wrong-node substitution but does not stop a durable-store
/// writer from restoring an older valid selector. Cross-restart rollback resistance remains owed to
/// the shared monotonic-head substrate; this store must not be cited as providing it.
pub struct ShadowCanaryGenerationStoreChirho {
    evidence_root_chirho: PathBuf,
    sign_root_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
}

struct PriorCanaryGenerationBindingChirho {
    generation_chirho: u64,
    activation_anchor_digest_chirho: Option<String>,
    descriptor_digest_chirho: Option<String>,
    latest_evidence_digest_chirho: Option<String>,
    latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho,
}

impl ShadowCanaryGenerationStoreChirho {
    pub fn open_existing_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
    ) -> Result<Self> {
        ShadowCanaryEvidenceStoreChirho::open_existing_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho.clone(),
            node_id_chirho.clone(),
        )?;
        if signer_chirho::existing_pubkey_hex_chirho(sign_root_chirho)? != node_id_chirho.0 {
            bail!("shadow canary generation node identity mismatch");
        }
        Ok(Self {
            evidence_root_chirho: evidence_root_chirho.to_path_buf(),
            sign_root_chirho: sign_root_chirho.to_path_buf(),
            group_chirho,
            node_id_chirho,
        })
    }

    pub fn verify_current_read_only_chirho(
        &self,
    ) -> Result<VerifiedShadowCanaryCurrentGenerationChirho> {
        let adoption_chirho = self.load_verified_adoption_chirho()?;
        let store_chirho = self.current_store_chirho(adoption_chirho.as_ref())?;
        let window_chirho = store_chirho.verify_existing_window_read_only_chirho()?;
        match adoption_chirho {
            None => {
                let window_chirho = window_chirho
                    .ok_or_else(|| anyhow::anyhow!("shadow canary generation zero is empty"))?;
                Ok(VerifiedShadowCanaryCurrentGenerationChirho {
                    generation_chirho: 0,
                    prior_generation_chirho: None,
                    adoption_chirho: None,
                    latest_ledger_cut_chirho: ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                        &window_chirho.latest_append_cut_chirho,
                        &self.group_chirho,
                    )?,
                    window_chirho: Some(window_chirho),
                })
            }
            Some(adoption_chirho) => {
                if let Some(window_chirho) = &window_chirho {
                    let first_allowed_chirho = adoption_chirho
                        .adopted_ledger_cut_chirho
                        .append_seq_chirho
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("shadow canary adopted cut exhausted"))?;
                    if window_chirho.latest_append_cut_chirho.append_seq_chirho
                        < first_allowed_chirho
                    {
                        bail!("shadow canary adopted generation precedes its imported cut");
                    }
                }
                let latest_ledger_cut_chirho = window_chirho
                    .as_ref()
                    .map(|window_chirho| {
                        ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                            &window_chirho.latest_append_cut_chirho,
                            &self.group_chirho,
                        )
                    })
                    .transpose()?
                    .unwrap_or_else(|| adoption_chirho.adopted_ledger_cut_chirho.clone());
                Ok(VerifiedShadowCanaryCurrentGenerationChirho {
                    generation_chirho: adoption_chirho.generation_chirho,
                    prior_generation_chirho: Some(adoption_chirho.prior_generation_chirho),
                    adoption_chirho: Some(adoption_chirho),
                    window_chirho,
                    latest_ledger_cut_chirho,
                })
            }
        }
    }

    /// Export the current generation as one path-free, bounded, independently verifiable proof.
    ///
    /// This is the node-local source step in
    /// `cf8-canary-window-loss-sequence-chirho.md`. The current selector is checked before and after
    /// the evidence snapshot so an adoption cannot splice two generations into one report.
    pub fn export_current_window_proof_read_only_chirho(
        &self,
    ) -> Result<SignedShadowCanaryWindowProofChirho> {
        let adoption_before_chirho = self.load_verified_adoption_chirho()?;
        let store_chirho = self.current_store_chirho(adoption_before_chirho.as_ref())?;
        let window_source_chirho = store_chirho.verified_window_source_read_only_chirho()?;
        let adoption_after_chirho = self.load_verified_adoption_chirho()?;
        if adoption_before_chirho != adoption_after_chirho {
            bail!("ShadowCanaryWindowProofGenerationChangedChirho");
        }
        let generation_chirho = adoption_before_chirho
            .as_ref()
            .map(ShadowCanaryAdoptionGenerationChirho::generation_chirho)
            .unwrap_or(0);
        let latest_ledger_cut_chirho = window_source_chirho
            .as_ref()
            .and_then(|source_chirho| source_chirho.records_chirho.last())
            .map(|record_chirho| {
                ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                    &record_chirho.observation_chirho.append_cut_chirho,
                    &self.group_chirho,
                )
            })
            .transpose()?
            .or_else(|| {
                adoption_before_chirho
                    .as_ref()
                    .map(|adoption_chirho| adoption_chirho.adopted_ledger_cut_chirho.clone())
            })
            .ok_or_else(|| anyhow::anyhow!("shadow canary proof current generation is empty"))?;
        let generation_descriptor_digest_chirho = adoption_before_chirho
            .as_ref()
            .map(adoption_descriptor_digest_chirho)
            .transpose()?;
        build_signed_shadow_canary_window_proof_chirho(
            ShadowCanaryWindowProofInputChirho {
                node_id_chirho: self.node_id_chirho.clone(),
                group_chirho: self.group_chirho.clone(),
                generation_chirho,
                activation_anchor_digest_chirho: adoption_before_chirho
                    .as_ref()
                    .and_then(ShadowCanaryAdoptionGenerationChirho::activation_anchor_digest_chirho)
                    .map(str::to_owned)
                    .or_else(|| {
                        store_chirho
                            .activation_anchor_digest_chirho()
                            .map(str::to_owned)
                    }),
                prior_generation_chirho: adoption_before_chirho
                    .as_ref()
                    .map(ShadowCanaryAdoptionGenerationChirho::prior_generation_chirho),
                generation_descriptor_digest_chirho,
                prior_latest_evidence_digest_chirho: adoption_before_chirho
                    .as_ref()
                    .and_then(
                        ShadowCanaryAdoptionGenerationChirho::prior_latest_evidence_digest_chirho,
                    )
                    .map(str::to_owned),
                adopted_ledger_cut_chirho: adoption_before_chirho
                    .as_ref()
                    .map(|adoption_chirho| adoption_chirho.adopted_ledger_cut_chirho.clone()),
                adoption_proof_projection_chirho: adoption_before_chirho.as_ref().and_then(
                    |adoption_chirho| adoption_chirho.adoption_proof_projection_chirho.clone(),
                ),
                latest_ledger_cut_chirho,
                window_source_chirho,
            },
            &self.sign_root_chirho,
        )
    }

    pub fn append_observation_chirho(
        &self,
        observation_chirho: ShadowCanaryChirho,
    ) -> Result<SignedShadowCanaryEvidenceChirho> {
        let adoption_chirho = self.load_verified_adoption_chirho()?;
        let store_chirho = self.current_store_chirho(adoption_chirho.as_ref())?;
        if let Some(adoption_chirho) = &adoption_chirho {
            if store_chirho.verify_window_chirho()?.is_none()
                && observation_chirho.append_cut_chirho.append_seq_chirho
                    != adoption_chirho
                        .adopted_ledger_cut_chirho
                        .append_seq_chirho
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("shadow canary adopted cut exhausted"))?
            {
                bail!("shadow canary first post-adoption observation is not dense");
            }
        }
        store_chirho.append_observation_chirho(observation_chirho)
    }

    pub fn commit_adoption_generation_chirho(
        &self,
        input_chirho: ShadowCanaryAdoptionGenerationInputChirho,
    ) -> Result<ShadowCanaryAdoptionGenerationChirho> {
        seqlog_chirho::with_named_lock_chirho(
            &self.evidence_root_chirho,
            CANARY_GENERATION_LOCK_CHIRHO,
            || self.commit_adoption_generation_unlocked_chirho(input_chirho),
        )
    }

    fn commit_adoption_generation_unlocked_chirho(
        &self,
        input_chirho: ShadowCanaryAdoptionGenerationInputChirho,
    ) -> Result<ShadowCanaryAdoptionGenerationChirho> {
        if input_chirho.historical_term_chirho == 0
            || input_chirho.elected_term_chirho <= input_chirho.historical_term_chirho
        {
            bail!(ShadowCanaryAdoptionProofProjectionRefusalChirho::TermStrictnessRefusedChirho);
        }
        let prior_adoption_chirho = self.load_verified_adoption_chirho()?;
        if let Some(prior_adoption_chirho) = &prior_adoption_chirho {
            if adoption_retry_matches_chirho(prior_adoption_chirho, &input_chirho) {
                return Ok(prior_adoption_chirho.clone());
            }
        }
        let prior_binding_chirho =
            self.generation_binding_chirho(prior_adoption_chirho.as_ref())?;
        if prior_adoption_chirho.is_some()
            && input_chirho.adopted_ledger_cut_chirho.append_seq_chirho
                <= prior_binding_chirho
                    .latest_ledger_cut_chirho
                    .append_seq_chirho
        {
            bail!("shadow canary adoption retry does not match the committed generation");
        }
        let prior_generation_chirho = prior_binding_chirho.generation_chirho;
        let generation_chirho = prior_generation_chirho
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("shadow canary generation exhausted"))?;
        let carries_public_projection_chirho = prior_binding_chirho
            .activation_anchor_digest_chirho
            .is_some();
        let mut head_chirho = ShadowCanaryAdoptionGenerationChirho {
            schema_chirho: if carries_public_projection_chirho {
                CANARY_GENERATION_SCHEMA_V3_CHIRHO.to_string()
            } else {
                CANARY_GENERATION_SCHEMA_V1_CHIRHO.to_string()
            },
            group_chirho: self.group_chirho.clone(),
            node_id_chirho: self.node_id_chirho.clone(),
            generation_chirho,
            prior_generation_chirho,
            activation_anchor_digest_chirho: prior_binding_chirho.activation_anchor_digest_chirho,
            prior_generation_descriptor_digest_chirho: prior_binding_chirho
                .descriptor_digest_chirho,
            prior_latest_evidence_digest_chirho: prior_binding_chirho.latest_evidence_digest_chirho,
            prior_latest_ledger_cut_chirho: prior_binding_chirho.latest_ledger_cut_chirho,
            adopted_ledger_cut_chirho: input_chirho.adopted_ledger_cut_chirho,
            cluster_id_chirho: input_chirho.cluster_id_chirho,
            journal_genesis_digest_chirho: input_chirho.journal_genesis_digest_chirho,
            assignment_digest_chirho: input_chirho.assignment_digest_chirho,
            historical_leader_node_id_chirho: input_chirho.historical_leader_node_id_chirho,
            holder_node_ids_chirho: input_chirho.holder_node_ids_chirho,
            historical_term_chirho: if carries_public_projection_chirho {
                input_chirho.historical_term_chirho
            } else {
                0
            },
            historical_membership_view_digest_chirho: if carries_public_projection_chirho {
                input_chirho.historical_membership_view_digest_chirho
            } else {
                String::new()
            },
            elected_term_chirho: input_chirho.elected_term_chirho,
            membership_view_digest_chirho: input_chirho.membership_view_digest_chirho,
            holder_receipt_digests_chirho: input_chirho.holder_receipt_digests_chirho,
            holder_receipt_wires_chirho: input_chirho.holder_receipt_wires_chirho,
            candidate_journal_binding_digest_chirho: input_chirho
                .candidate_journal_binding_digest_chirho,
            candidate_journal_digest_chirho: input_chirho.candidate_journal_digest_chirho,
            adoption_proof_projection_chirho: None,
            key_id_chirho: self.node_id_chirho.0.clone(),
            sig_chirho: String::new(),
        };
        if carries_public_projection_chirho {
            head_chirho.adoption_proof_projection_chirho =
                Some(build_signed_shadow_canary_adoption_proof_projection_chirho(
                    ShadowCanaryAdoptionProofProjectionInputChirho {
                        node_id_chirho: head_chirho.node_id_chirho.clone(),
                        group_chirho: head_chirho.group_chirho.clone(),
                        generation_chirho: head_chirho.generation_chirho,
                        prior_generation_chirho: head_chirho.prior_generation_chirho,
                        activation_anchor_digest_chirho: head_chirho
                            .activation_anchor_digest_chirho
                            .clone(),
                        prior_generation_descriptor_digest_chirho: head_chirho
                            .prior_generation_descriptor_digest_chirho
                            .clone(),
                        prior_latest_evidence_digest_chirho: head_chirho
                            .prior_latest_evidence_digest_chirho
                            .clone(),
                        prior_latest_ledger_cut_chirho:
                            ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho(
                                &head_chirho.prior_latest_ledger_cut_chirho,
                            ),
                        adopted_ledger_cut_chirho:
                            ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho(
                                &head_chirho.adopted_ledger_cut_chirho,
                            ),
                        cluster_id_chirho: head_chirho.cluster_id_chirho.clone(),
                        journal_genesis_digest_chirho: head_chirho
                            .journal_genesis_digest_chirho
                            .clone(),
                        assignment_digest_chirho: head_chirho.assignment_digest_chirho.clone(),
                        historical_leader_node_id_chirho: head_chirho
                            .historical_leader_node_id_chirho
                            .clone(),
                        holder_node_ids_chirho: head_chirho.holder_node_ids_chirho.clone(),
                        historical_term_chirho: head_chirho.historical_term_chirho,
                        historical_membership_view_digest_chirho: head_chirho
                            .historical_membership_view_digest_chirho
                            .clone(),
                        elected_term_chirho: head_chirho.elected_term_chirho,
                        membership_view_digest_chirho: head_chirho
                            .membership_view_digest_chirho
                            .clone(),
                        candidate_journal_binding_digest_chirho: head_chirho
                            .candidate_journal_binding_digest_chirho
                            .clone(),
                        candidate_journal_digest_chirho: head_chirho
                            .candidate_journal_digest_chirho
                            .clone(),
                    },
                    &self.sign_root_chirho,
                )?);
        }
        self.validate_adoption_shape_chirho(&head_chirho, false)?;
        head_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
            &self.sign_root_chirho,
            &unsigned_adoption_message_chirho(&head_chirho)?,
        )?;
        self.validate_adoption_shape_chirho(&head_chirho, true)?;
        let head_bytes_chirho = serde_json::to_vec(&head_chirho)?;
        if head_bytes_chirho.len() as u64 > CANARY_GENERATION_MAX_BYTES_CHIRHO {
            bail!("shadow canary generation head exceeds its durable bound");
        }
        let generation_root_chirho = self.generation_root_chirho(generation_chirho);
        let generation_store_chirho = match &head_chirho.activation_anchor_digest_chirho {
            Some(anchor_digest_chirho) => {
                ShadowCanaryEvidenceStoreChirho::create_generation_chirho(
                    &generation_root_chirho,
                    &self.sign_root_chirho,
                    self.group_chirho.clone(),
                    self.node_id_chirho.clone(),
                    anchor_digest_chirho.clone(),
                )?
            }
            None => ShadowCanaryEvidenceStoreChirho::open_chirho(
                &generation_root_chirho,
                &self.sign_root_chirho,
                self.group_chirho.clone(),
                self.node_id_chirho.clone(),
            )?,
        };
        if generation_store_chirho.verify_window_chirho()?.is_some() {
            bail!("shadow canary adoption generation is not empty before commit");
        }
        let descriptor_path_chirho = self.generation_descriptor_path_chirho(generation_chirho);
        match optional_shadow_canary_path_metadata_chirho(
            &descriptor_path_chirho,
            "inspect immutable shadow canary adoption generation",
        )? {
            Some(_) => {
                let existing_chirho =
                    self.load_verified_generation_descriptor_chirho(generation_chirho)?;
                if existing_chirho != head_chirho {
                    bail!("shadow canary orphaned generation does not match the adoption retry");
                }
            }
            None => {
                write_file_durable_chirho(&descriptor_path_chirho, &head_bytes_chirho)
                    .context("commit immutable shadow canary adoption generation")?;
            }
        }
        // The selector is deliberately last: an orphaned empty generation is inert and retryable.
        write_file_durable_chirho(&self.generation_head_path_chirho(), &head_bytes_chirho)
            .context("commit shadow canary adoption generation")?;
        Ok(head_chirho)
    }

    fn current_store_chirho(
        &self,
        adoption_chirho: Option<&ShadowCanaryAdoptionGenerationChirho>,
    ) -> Result<ShadowCanaryEvidenceStoreChirho> {
        let root_chirho = adoption_chirho
            .map(|head_chirho| self.generation_root_chirho(head_chirho.generation_chirho))
            .unwrap_or_else(|| self.evidence_root_chirho.clone());
        match adoption_chirho
            .and_then(|head_chirho| head_chirho.activation_anchor_digest_chirho.as_ref())
        {
            Some(anchor_digest_chirho) => {
                ShadowCanaryEvidenceStoreChirho::open_existing_generation_chirho(
                    &root_chirho,
                    &self.sign_root_chirho,
                    self.group_chirho.clone(),
                    self.node_id_chirho.clone(),
                    anchor_digest_chirho.clone(),
                )
            }
            None => ShadowCanaryEvidenceStoreChirho::open_existing_chirho(
                &root_chirho,
                &self.sign_root_chirho,
                self.group_chirho.clone(),
                self.node_id_chirho.clone(),
            ),
        }
    }

    fn load_verified_adoption_chirho(
        &self,
    ) -> Result<Option<ShadowCanaryAdoptionGenerationChirho>> {
        let path_chirho = self.generation_head_path_chirho();
        if optional_shadow_canary_path_metadata_chirho(
            &path_chirho,
            "inspect shadow canary generation head",
        )?
        .is_none()
        {
            return Ok(None);
        }
        let head_bytes_chirho = read_bounded_regular_file_chirho(&path_chirho)?;
        let head_chirho = self.decode_and_verify_adoption_chirho(
            &head_bytes_chirho,
            "decode shadow canary generation head",
        )?;
        let descriptor_bytes_chirho = read_bounded_regular_file_chirho(
            &self.generation_descriptor_path_chirho(head_chirho.generation_chirho),
        )?;
        if head_bytes_chirho != descriptor_bytes_chirho {
            bail!("shadow canary selector does not match its immutable generation");
        }
        self.verify_prior_generation_binding_chirho(&head_chirho)?;
        Ok(Some(head_chirho))
    }

    fn load_verified_generation_descriptor_chirho(
        &self,
        generation_chirho: u64,
    ) -> Result<ShadowCanaryAdoptionGenerationChirho> {
        let descriptor_chirho = self.decode_and_verify_adoption_chirho(
            &read_bounded_regular_file_chirho(
                &self.generation_descriptor_path_chirho(generation_chirho),
            )?,
            "decode immutable shadow canary generation",
        )?;
        if descriptor_chirho.generation_chirho != generation_chirho {
            bail!("shadow canary immutable generation path does not match its descriptor");
        }
        Ok(descriptor_chirho)
    }

    fn decode_and_verify_adoption_chirho(
        &self,
        bytes_chirho: &[u8],
        context_chirho: &'static str,
    ) -> Result<ShadowCanaryAdoptionGenerationChirho> {
        let head_chirho: ShadowCanaryAdoptionGenerationChirho =
            serde_json::from_slice(bytes_chirho).context(context_chirho)?;
        self.validate_adoption_shape_chirho(&head_chirho, true)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &self.node_id_chirho.0,
            &unsigned_adoption_message_chirho(&head_chirho)?,
            &head_chirho.sig_chirho,
        )? {
            bail!("shadow canary generation signature invalid");
        }
        Ok(head_chirho)
    }

    fn generation_binding_chirho(
        &self,
        adoption_chirho: Option<&ShadowCanaryAdoptionGenerationChirho>,
    ) -> Result<PriorCanaryGenerationBindingChirho> {
        let generation_chirho = adoption_chirho
            .map(|head_chirho| head_chirho.generation_chirho)
            .unwrap_or(0);
        let descriptor_digest_chirho = adoption_chirho
            .map(adoption_descriptor_digest_chirho)
            .transpose()?;
        let store_chirho = self.current_store_chirho(adoption_chirho)?;
        let window_chirho = store_chirho.verify_existing_window_read_only_chirho()?;
        if adoption_chirho.is_none() && window_chirho.is_none() {
            bail!("shadow canary generation zero is empty");
        }
        let latest_evidence_digest_chirho = window_chirho
            .as_ref()
            .map(|window_chirho| window_chirho.latest_evidence_digest_chirho.clone());
        let latest_ledger_cut_chirho = window_chirho
            .as_ref()
            .map(|window_chirho| {
                ShadowCanaryLedgerCutChirho::from_append_cut_chirho(
                    &window_chirho.latest_append_cut_chirho,
                    &self.group_chirho,
                )
            })
            .transpose()?
            .or_else(|| {
                adoption_chirho.map(|head_chirho| head_chirho.adopted_ledger_cut_chirho.clone())
            })
            .ok_or_else(|| anyhow::anyhow!("shadow canary prior generation has no ledger cut"))?;
        Ok(PriorCanaryGenerationBindingChirho {
            generation_chirho,
            activation_anchor_digest_chirho: store_chirho
                .activation_anchor_digest_chirho()
                .map(str::to_owned),
            descriptor_digest_chirho,
            latest_evidence_digest_chirho,
            latest_ledger_cut_chirho,
        })
    }

    fn verify_prior_generation_binding_chirho(
        &self,
        head_chirho: &ShadowCanaryAdoptionGenerationChirho,
    ) -> Result<()> {
        let prior_adoption_chirho =
            if head_chirho.prior_generation_chirho == 0 {
                None
            } else {
                Some(self.load_verified_generation_descriptor_chirho(
                    head_chirho.prior_generation_chirho,
                )?)
            };
        let binding_chirho = self.generation_binding_chirho(prior_adoption_chirho.as_ref())?;
        if binding_chirho.generation_chirho != head_chirho.prior_generation_chirho
            || binding_chirho.activation_anchor_digest_chirho
                != head_chirho.activation_anchor_digest_chirho
            || binding_chirho.descriptor_digest_chirho
                != head_chirho.prior_generation_descriptor_digest_chirho
            || binding_chirho.latest_evidence_digest_chirho
                != head_chirho.prior_latest_evidence_digest_chirho
            || binding_chirho.latest_ledger_cut_chirho != head_chirho.prior_latest_ledger_cut_chirho
        {
            bail!("shadow canary generation does not bind its exact prior generation");
        }
        Ok(())
    }

    fn validate_adoption_shape_chirho(
        &self,
        head_chirho: &ShadowCanaryAdoptionGenerationChirho,
        require_signature_chirho: bool,
    ) -> Result<()> {
        let group_digest_chirho = tagged_writer_fence_group_digest_chirho(&self.group_chirho)?;
        let schema_matches_anchor_and_projection_chirho = matches!(
            (
                head_chirho.schema_chirho.as_str(),
                &head_chirho.activation_anchor_digest_chirho,
                &head_chirho.adoption_proof_projection_chirho,
            ),
            (CANARY_GENERATION_SCHEMA_V1_CHIRHO, None, None)
                | (CANARY_GENERATION_SCHEMA_V2_CHIRHO, Some(_), None)
                | (CANARY_GENERATION_SCHEMA_V3_CHIRHO, Some(_), Some(_))
        );
        if !schema_matches_anchor_and_projection_chirho
            || head_chirho
                .activation_anchor_digest_chirho
                .as_deref()
                .is_some_and(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || head_chirho.group_chirho != self.group_chirho
            || head_chirho.node_id_chirho != self.node_id_chirho
            || head_chirho.generation_chirho == 0
            || head_chirho.prior_generation_chirho.checked_add(1)
                != Some(head_chirho.generation_chirho)
        {
            bail!("ShadowCanaryGenerationIdentityShapeRefusedChirho");
        }
        let descriptor_digest_valid_chirho = head_chirho
            .prior_generation_descriptor_digest_chirho
            .as_deref()
            .is_some_and(is_lower_hex_digest_chirho);
        if (head_chirho.prior_generation_chirho == 0
            && head_chirho
                .prior_generation_descriptor_digest_chirho
                .is_some())
            || (head_chirho.prior_generation_chirho > 0 && !descriptor_digest_valid_chirho)
            || head_chirho
                .prior_latest_evidence_digest_chirho
                .as_deref()
                .is_some_and(|digest_chirho| !evidence_digest_has_shape_chirho(digest_chirho))
            || (head_chirho.prior_generation_chirho == 0
                && head_chirho.prior_latest_evidence_digest_chirho.is_none())
            || !valid_ledger_cut_chirho(&head_chirho.prior_latest_ledger_cut_chirho)
            || head_chirho
                .prior_latest_ledger_cut_chirho
                .consistency_group_digest_chirho
                != group_digest_chirho
        {
            bail!("ShadowCanaryPriorGenerationShapeRefusedChirho");
        }
        if !valid_ledger_cut_chirho(&head_chirho.adopted_ledger_cut_chirho)
            || head_chirho
                .adopted_ledger_cut_chirho
                .consistency_group_digest_chirho
                != group_digest_chirho
            || head_chirho.adopted_ledger_cut_chirho.append_seq_chirho
                < head_chirho.prior_latest_ledger_cut_chirho.append_seq_chirho
            || head_chirho.cluster_id_chirho.is_empty()
            || head_chirho.cluster_id_chirho.len() > 256
            || !is_lower_hex_digest_chirho(&head_chirho.journal_genesis_digest_chirho)
            || head_chirho.elected_term_chirho == 0
            || !is_lower_hex_digest_chirho(&head_chirho.assignment_digest_chirho)
            || !is_lower_hex_digest_chirho(&head_chirho.membership_view_digest_chirho)
            || !is_lower_hex_digest_chirho(&head_chirho.candidate_journal_binding_digest_chirho)
            || !is_lower_hex_digest_chirho(&head_chirho.candidate_journal_digest_chirho)
        {
            bail!("ShadowCanaryAdoptedCutBindingShapeRefusedChirho");
        }
        if !is_lower_hex_digest_chirho(&head_chirho.historical_leader_node_id_chirho)
            || head_chirho
                .holder_node_ids_chirho
                .iter()
                .any(|node_id_chirho| !is_lower_hex_digest_chirho(node_id_chirho))
            || head_chirho.holder_node_ids_chirho[0] == head_chirho.holder_node_ids_chirho[1]
            || head_chirho
                .holder_node_ids_chirho
                .iter()
                .any(|node_id_chirho| {
                    node_id_chirho == &head_chirho.historical_leader_node_id_chirho
                })
            || head_chirho
                .holder_receipt_digests_chirho
                .iter()
                .any(|digest_chirho| !is_lower_hex_digest_chirho(digest_chirho))
            || head_chirho.holder_receipt_digests_chirho[0]
                == head_chirho.holder_receipt_digests_chirho[1]
            || head_chirho
                .holder_receipt_wires_chirho
                .iter()
                .any(|wire_chirho| {
                    wire_chirho.is_empty()
                        || wire_chirho.len() > CANARY_GENERATION_RECEIPT_MAX_BYTES_CHIRHO
                })
            || head_chirho.holder_receipt_wires_chirho[0]
                == head_chirho.holder_receipt_wires_chirho[1]
        {
            bail!("ShadowCanaryHolderReceiptPopulationShapeRefusedChirho");
        }
        if head_chirho.schema_chirho == CANARY_GENERATION_SCHEMA_V3_CHIRHO {
            let projection_chirho = head_chirho
                .adoption_proof_projection_chirho
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        ShadowCanaryAdoptionProofProjectionRefusalChirho::ShapeRefusedChirho
                    )
                })?;
            verify_shadow_canary_adoption_proof_projection_chirho(projection_chirho)
                .map_err(anyhow::Error::new)?;
            let prior_cut_chirho = ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho(
                &head_chirho.prior_latest_ledger_cut_chirho,
            );
            let adopted_cut_chirho = ShadowCanaryProofLedgerCutChirho::from_generation_cut_chirho(
                &head_chirho.adopted_ledger_cut_chirho,
            );
            if projection_chirho.node_id_chirho != head_chirho.node_id_chirho.0
                || projection_chirho.consistency_group_digest_chirho
                    != group_digest_chirho.as_str_chirho()
                || projection_chirho.generation_chirho != head_chirho.generation_chirho
                || projection_chirho.prior_generation_chirho != head_chirho.prior_generation_chirho
                || projection_chirho.activation_anchor_digest_chirho
                    != head_chirho.activation_anchor_digest_chirho
                || projection_chirho.prior_generation_descriptor_digest_chirho
                    != head_chirho.prior_generation_descriptor_digest_chirho
                || projection_chirho.prior_latest_evidence_digest_chirho
                    != head_chirho.prior_latest_evidence_digest_chirho
                || projection_chirho.prior_latest_ledger_cut_chirho != prior_cut_chirho
                || projection_chirho.adopted_ledger_cut_chirho != adopted_cut_chirho
                || projection_chirho.cluster_id_chirho != head_chirho.cluster_id_chirho
                || projection_chirho.journal_genesis_digest_chirho
                    != head_chirho.journal_genesis_digest_chirho
                || projection_chirho.assignment_digest_chirho
                    != head_chirho.assignment_digest_chirho
                || projection_chirho.historical_leader_node_id_chirho
                    != head_chirho.historical_leader_node_id_chirho
                || projection_chirho.holder_node_ids_chirho != head_chirho.holder_node_ids_chirho
                || projection_chirho.historical_term_chirho != head_chirho.historical_term_chirho
                || projection_chirho.historical_membership_view_digest_chirho
                    != head_chirho.historical_membership_view_digest_chirho
                || projection_chirho.elected_term_chirho != head_chirho.elected_term_chirho
                || projection_chirho.membership_view_digest_chirho
                    != head_chirho.membership_view_digest_chirho
                || projection_chirho.candidate_journal_binding_digest_chirho
                    != head_chirho.candidate_journal_binding_digest_chirho
                || projection_chirho.candidate_journal_digest_chirho
                    != head_chirho.candidate_journal_digest_chirho
            {
                bail!(ShadowCanaryAdoptionProofProjectionRefusalChirho::BindingRefusedChirho);
            }
        } else if head_chirho.historical_term_chirho != 0
            || !head_chirho
                .historical_membership_view_digest_chirho
                .is_empty()
        {
            bail!(ShadowCanaryAdoptionProofProjectionRefusalChirho::ShapeRefusedChirho);
        }
        if head_chirho.key_id_chirho != self.node_id_chirho.0
            || (require_signature_chirho && head_chirho.sig_chirho.is_empty())
            || (!require_signature_chirho && !head_chirho.sig_chirho.is_empty())
        {
            bail!("ShadowCanaryGenerationSignatureShapeRefusedChirho");
        }
        Ok(())
    }

    fn generation_head_path_chirho(&self) -> PathBuf {
        self.evidence_root_chirho
            .join(CANARY_GENERATION_HEAD_FILE_CHIRHO)
    }

    fn generation_descriptor_path_chirho(&self, generation_chirho: u64) -> PathBuf {
        self.generation_root_chirho(generation_chirho)
            .join(CANARY_GENERATION_DESCRIPTOR_FILE_CHIRHO)
    }

    fn generation_root_chirho(&self, generation_chirho: u64) -> PathBuf {
        self.evidence_root_chirho
            .join(CANARY_GENERATIONS_DIR_CHIRHO)
            .join(format!("generation-{generation_chirho:020}-chirho"))
    }
}

fn adoption_retry_matches_chirho(
    head_chirho: &ShadowCanaryAdoptionGenerationChirho,
    input_chirho: &ShadowCanaryAdoptionGenerationInputChirho,
) -> bool {
    head_chirho.adopted_ledger_cut_chirho == input_chirho.adopted_ledger_cut_chirho
        && head_chirho.cluster_id_chirho == input_chirho.cluster_id_chirho
        && head_chirho.journal_genesis_digest_chirho == input_chirho.journal_genesis_digest_chirho
        && head_chirho.assignment_digest_chirho == input_chirho.assignment_digest_chirho
        && head_chirho.historical_leader_node_id_chirho
            == input_chirho.historical_leader_node_id_chirho
        && head_chirho.holder_node_ids_chirho == input_chirho.holder_node_ids_chirho
        && (head_chirho.schema_chirho != CANARY_GENERATION_SCHEMA_V3_CHIRHO
            || (head_chirho.historical_term_chirho == input_chirho.historical_term_chirho
                && head_chirho.historical_membership_view_digest_chirho
                    == input_chirho.historical_membership_view_digest_chirho))
        && head_chirho.elected_term_chirho == input_chirho.elected_term_chirho
        && head_chirho.membership_view_digest_chirho == input_chirho.membership_view_digest_chirho
        && head_chirho.holder_receipt_digests_chirho == input_chirho.holder_receipt_digests_chirho
        && head_chirho.holder_receipt_wires_chirho == input_chirho.holder_receipt_wires_chirho
        && head_chirho.candidate_journal_binding_digest_chirho
            == input_chirho.candidate_journal_binding_digest_chirho
        && head_chirho.candidate_journal_digest_chirho
            == input_chirho.candidate_journal_digest_chirho
}

fn valid_ledger_cut_chirho(cut_chirho: &ShadowCanaryLedgerCutChirho) -> bool {
    cut_chirho.append_seq_chirho > 0
        && is_lower_hex_digest_chirho(&cut_chirho.append_record_digest_chirho)
        && cut_chirho.append_hlc_physical_ms_chirho > 0
        && cut_chirho.record_epoch_chirho > 0
        && !cut_chirho
            .consistency_group_digest_chirho
            .as_str_chirho()
            .is_empty()
        && cut_chirho
            .consistency_group_digest_chirho
            .as_str_chirho()
            .len()
            <= 256
}

fn unsigned_adoption_message_chirho(
    head_chirho: &ShadowCanaryAdoptionGenerationChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = head_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn adoption_descriptor_digest_chirho(
    head_chirho: &ShadowCanaryAdoptionGenerationChirho,
) -> Result<String> {
    Ok(blake3::hash(&serde_json::to_vec(head_chirho)?)
        .to_hex()
        .to_string())
}

fn read_bounded_regular_file_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let path_metadata_chirho =
        std::fs::symlink_metadata(path_chirho).context("inspect shadow canary generation file")?;
    if !path_metadata_chirho.file_type().is_file()
        || path_metadata_chirho.len() == 0
        || path_metadata_chirho.len() > CANARY_GENERATION_MAX_BYTES_CHIRHO
    {
        bail!("shadow canary generation file is not a bounded regular file");
    }
    let file_chirho =
        std::fs::File::open(path_chirho).context("open shadow canary generation file")?;
    let opened_metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened shadow canary generation file")?;
    if opened_metadata_chirho.dev() != path_metadata_chirho.dev()
        || opened_metadata_chirho.ino() != path_metadata_chirho.ino()
        || opened_metadata_chirho.len() != path_metadata_chirho.len()
    {
        bail!("shadow canary generation file changed before read");
    }
    let mut bytes_chirho = Vec::with_capacity(opened_metadata_chirho.len() as usize);
    file_chirho
        .take(CANARY_GENERATION_MAX_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .context("read shadow canary generation file")?;
    let final_metadata_chirho = std::fs::symlink_metadata(path_chirho)
        .context("reinspect shadow canary generation file")?;
    if bytes_chirho.len() as u64 != opened_metadata_chirho.len()
        || final_metadata_chirho.dev() != opened_metadata_chirho.dev()
        || final_metadata_chirho.ino() != opened_metadata_chirho.ino()
        || final_metadata_chirho.len() != opened_metadata_chirho.len()
    {
        bail!("shadow canary generation file changed during read");
    }
    Ok(bytes_chirho)
}

fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}
