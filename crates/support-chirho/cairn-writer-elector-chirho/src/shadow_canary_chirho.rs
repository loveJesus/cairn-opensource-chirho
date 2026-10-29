// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The shadow-mode canary (D4 shadow-first). At a fence mint for a consistency group, it OBSERVES —
//! never enforces — whether the minting node also held the Raft election leadership with a valid lease.
//! In shadow mode the local node always mints (it is the sole writer); this records whether the future
//! P5 cutover mint gate (`is_leader && lease_valid` for the minting node) WOULD have permitted that
//! mint. Over many mints, all-`cutover_would_permit == true` is the evidence that flipping the mint
//! admission from the local lock to Raft leadership would not have blocked any real write.
//!
//! It is a pure read: it takes the already-minted `fence_epoch_chirho` as input and reads the elector's
//! leadership — it calls no mint/commit function, so the election plane still mints nothing.

use crate::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use crate::shadow_canary_activation_anchor_chirho::{
    create_new_shadow_canary_activation_anchor_chirho,
    load_optional_shadow_canary_activation_anchor_chirho, ShadowCanaryActivationAnchorInputChirho,
    VerifiedShadowCanaryActivationAnchorChirho,
};
use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::{consistency_group_digest_chirho, ConsistencyGroupIdChirho};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_seqlog_chirho::seqlog_chirho;
use cairn_signer_chirho::signer_chirho;
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const SHADOW_CANARY_SCHEMA_CHIRHO: &str = "writer-elector-shadow-canary-v2-chirho";
pub const SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO: &str =
    "writer-elector-shadow-canary-evidence-v2-chirho";
pub const SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO: &str =
    "writer-elector-shadow-canary-evidence-head-v1-chirho";
pub const SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V2_CHIRHO: &str =
    "writer-elector-shadow-canary-evidence-head-v2-chirho";
pub const SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO: u64 = 256;
pub const SHADOW_CANARY_EVIDENCE_DIR_CHIRHO: &str = "writer-canary-chirho";
const SHADOW_CANARY_SLOT_COUNT_CHIRHO: u64 = SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO + 1;
const SHADOW_CANARY_EVIDENCE_LOCK_CHIRHO: &str = "shadow-canary-evidence-chirho";
const SHADOW_CANARY_EVIDENCE_HEAD_FILE_CHIRHO: &str = "head-chirho.json";
const SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO: &str = "records-chirho";
pub(crate) const SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO: &str =
    "shadow-canary-evidence-genesis-chirho";
const SHADOW_CANARY_EVIDENCE_DIGEST_PREFIX_CHIRHO: &str =
    "shadow-canary-evidence-blake3-v1-chirho:";
const MAX_SHADOW_CANARY_EVIDENCE_FILE_BYTES_CHIRHO: u64 = 64 * 1024;

/// One shadow observation comparing a fence mint against the Raft election. Schema-tagged and made of
/// bounded, non-identifying fields (group id, node pubkeys, epoch/term counters) — safe to persist as
/// operator evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryAppendCutChirho {
    pub append_seq_chirho: u64,
    pub append_record_digest_chirho: String,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub process_generation_chirho: u64,
    pub durable_term_chirho: u64,
    pub fence_epoch_chirho: u64,
    pub fence_group_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowCanaryChirho {
    pub schema_chirho: String,
    pub group_chirho: ConsistencyGroupIdChirho,
    /// The node that actually minted the fence (the local sole writer, in shadow).
    pub minter_node_id_chirho: NodeIdChirho,
    /// The fence epoch that was minted.
    pub append_cut_chirho: ShadowCanaryAppendCutChirho,
    /// The Raft-elected leader for the group at observation time (if any).
    pub raft_leader_id_chirho: Option<NodeIdChirho>,
    pub raft_term_chirho: u64,
    pub raft_lease_valid_chirho: bool,
    /// True iff the minter is the current Raft-elected leader AND holds a valid lease — i.e., the P5
    /// cutover mint gate would have permitted this mint. `false` flags a divergence to review before
    /// cutover (the local node minted while it was not the elected leader).
    pub cutover_would_permit_chirho: bool,
    pub at_ms_chirho: u64,
}

/// Observe (do not enforce) whether a fence mint by `minter_node_id_chirho` for `group_chirho` at
/// receipt cut aligns with the Raft election. Reads the elector only; mints nothing.
pub fn observe_shadow_canary_chirho<E>(
    elector_chirho: &E,
    group_chirho: &ConsistencyGroupIdChirho,
    minter_node_id_chirho: &NodeIdChirho,
    append_cut_chirho: ShadowCanaryAppendCutChirho,
    at_ms_chirho: u64,
) -> ShadowCanaryChirho
where
    E: WriterElectorChirho + ?Sized,
{
    let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
    let cutover_would_permit_chirho = leadership_chirho.leader_id_chirho.as_ref()
        == Some(minter_node_id_chirho)
        && leadership_chirho.lease_valid_chirho;
    ShadowCanaryChirho {
        schema_chirho: SHADOW_CANARY_SCHEMA_CHIRHO.to_string(),
        group_chirho: group_chirho.clone(),
        minter_node_id_chirho: minter_node_id_chirho.clone(),
        append_cut_chirho,
        raft_leader_id_chirho: leadership_chirho.leader_id_chirho,
        raft_term_chirho: leadership_chirho.term_chirho,
        raft_lease_valid_chirho: leadership_chirho.lease_valid_chirho,
        cutover_would_permit_chirho,
        at_ms_chirho,
    }
}

/// One node-signed observation in the bounded evidence chain. The slot files are a fixed ring;
/// `seq_chirho` and `previous_digest_chirho` prevent a stale slot from impersonating the current
/// window, while the signed head names the exact latest record and rolling permit/refusal counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedShadowCanaryEvidenceChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub previous_digest_chirho: String,
    pub observation_chirho: ShadowCanaryChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedShadowCanaryEvidenceHeadChirho {
    pub(crate) schema_chirho: String,
    pub(crate) group_chirho: ConsistencyGroupIdChirho,
    pub(crate) latest_seq_chirho: u64,
    pub(crate) latest_digest_chirho: String,
    pub(crate) window_len_chirho: u64,
    pub(crate) permit_count_chirho: u64,
    pub(crate) refusal_count_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) activation_anchor_digest_chirho: Option<String>,
    pub(crate) key_id_chirho: String,
    pub(crate) sig_chirho: String,
}

/// Store-verified source material used to build the path-free offline proof.
///
/// This never crosses the public boundary directly because the signed observations contain the raw
/// consistency-group coordinate. The proof module projects only bounded non-identifying fields.
pub(crate) struct VerifiedShadowCanaryWindowSourceChirho {
    pub(crate) head_chirho: SignedShadowCanaryEvidenceHeadChirho,
    pub(crate) records_chirho: Vec<SignedShadowCanaryEvidenceChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedShadowCanaryWindowChirho {
    pub activation_anchor_digest_chirho: Option<String>,
    pub group_chirho: ConsistencyGroupIdChirho,
    pub latest_seq_chirho: u64,
    pub latest_evidence_digest_chirho: String,
    pub latest_append_cut_chirho: ShadowCanaryAppendCutChirho,
    pub window_len_chirho: u64,
    pub permit_count_chirho: u64,
    pub refusal_count_chirho: u64,
    pub oldest_at_ms_chirho: u64,
    pub latest_at_ms_chirho: u64,
    pub oldest_fence_epoch_chirho: u64,
    pub latest_fence_epoch_chirho: u64,
}

/// Fixed-space signed canary evidence. Hot append reads/verifies only the signed head, the latest
/// record, and (when full) the one evicted record, then writes one ring slot plus the head: O(1)
/// CPU, memory, and file count as history grows. Explicit verification walks at most the fixed
/// 256-record activation window, also O(1) with respect to lifetime history. The extra 257th slot
/// keeps the old head's full window valid if a crash lands a record before its replacement head.
/// This is the evidence substrate described by
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/p4-embedded-raft-shadow-design-chirho.md`.
/// The reviewed offline H3 activation records one receipt-bound observation here; served-runtime
/// canary accumulation and GD7 remain separate boundaries.
pub struct ShadowCanaryEvidenceStoreChirho {
    evidence_root_chirho: PathBuf,
    sign_root_chirho: PathBuf,
    group_chirho: ConsistencyGroupIdChirho,
    node_id_chirho: NodeIdChirho,
    activation_anchor_digest_chirho: Option<String>,
    activation_append_cut_chirho: Option<ShadowCanaryAppendCutChirho>,
}

impl ShadowCanaryEvidenceStoreChirho {
    pub fn create_activation_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
        input_chirho: ShadowCanaryActivationAnchorInputChirho,
    ) -> Result<Self> {
        let anchor_chirho = create_new_shadow_canary_activation_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            &group_chirho,
            &node_id_chirho,
            input_chirho,
        )?;
        std::fs::create_dir(evidence_root_chirho.join(SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO))
            .context("create anchored shadow canary records directory")?;
        Self::checked_with_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
            Some(anchor_chirho),
            None,
        )
    }

    pub fn open_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
    ) -> Result<Self> {
        std::fs::create_dir_all(
            evidence_root_chirho.join(SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO),
        )
        .context("create shadow canary evidence directory")?;
        Self::checked_auto_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
        )
    }

    pub fn open_existing_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
    ) -> Result<Self> {
        Self::checked_auto_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
        )
    }

    pub(crate) fn create_generation_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
        activation_anchor_digest_chirho: String,
    ) -> Result<Self> {
        std::fs::create_dir_all(
            evidence_root_chirho.join(SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO),
        )
        .context("create anchored shadow canary generation directory")?;
        Self::checked_with_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
            None,
            Some(activation_anchor_digest_chirho),
        )
    }

    pub(crate) fn open_existing_generation_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
        activation_anchor_digest_chirho: String,
    ) -> Result<Self> {
        Self::checked_with_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
            None,
            Some(activation_anchor_digest_chirho),
        )
    }

    fn checked_auto_anchor_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
    ) -> Result<Self> {
        let anchor_chirho = load_optional_shadow_canary_activation_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            &group_chirho,
            &node_id_chirho,
        )?;
        Self::checked_with_anchor_chirho(
            evidence_root_chirho,
            sign_root_chirho,
            group_chirho,
            node_id_chirho,
            anchor_chirho,
            None,
        )
    }

    fn checked_with_anchor_chirho(
        evidence_root_chirho: &Path,
        sign_root_chirho: &Path,
        group_chirho: ConsistencyGroupIdChirho,
        node_id_chirho: NodeIdChirho,
        anchor_chirho: Option<VerifiedShadowCanaryActivationAnchorChirho>,
        expected_anchor_digest_chirho: Option<String>,
    ) -> Result<Self> {
        require_regular_directory_chirho(evidence_root_chirho)?;
        require_regular_directory_chirho(
            &evidence_root_chirho.join(SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO),
        )?;
        let existing_key_chirho = signer_chirho::existing_pubkey_hex_chirho(sign_root_chirho)
            .context("shadow canary requires an existing node signing key")?;
        if existing_key_chirho != node_id_chirho.0 {
            bail!("shadow canary node id does not match the existing signing key");
        }
        let activation_anchor_digest_chirho = anchor_chirho
            .as_ref()
            .map(|anchor_chirho| anchor_chirho.digest_chirho().to_owned())
            .or(expected_anchor_digest_chirho);
        if activation_anchor_digest_chirho
            .as_deref()
            .is_some_and(|digest_chirho| !is_lower_hex_chirho(digest_chirho, 64))
        {
            bail!("ShadowCanaryActivationAnchorDigestRefusedChirho");
        }
        let activation_append_cut_chirho = anchor_chirho.as_ref().map(|anchor_chirho| {
            anchor_chirho
                .anchor_chirho()
                .activation_append_cut_chirho
                .clone()
        });
        Ok(Self {
            evidence_root_chirho: evidence_root_chirho.to_path_buf(),
            sign_root_chirho: sign_root_chirho.to_path_buf(),
            group_chirho,
            node_id_chirho,
            activation_anchor_digest_chirho,
            activation_append_cut_chirho,
        })
    }

    pub fn append_observation_chirho(
        &self,
        observation_chirho: ShadowCanaryChirho,
    ) -> Result<SignedShadowCanaryEvidenceChirho> {
        self.validate_observation_chirho(&observation_chirho)?;
        seqlog_chirho::with_named_lock_chirho(
            &self.evidence_root_chirho,
            SHADOW_CANARY_EVIDENCE_LOCK_CHIRHO,
            || self.append_unlocked_chirho(observation_chirho),
        )
    }

    pub(crate) fn activation_anchor_digest_chirho(&self) -> Option<&str> {
        self.activation_anchor_digest_chirho.as_deref()
    }

    pub fn verify_window_chirho(&self) -> Result<Option<VerifiedShadowCanaryWindowChirho>> {
        seqlog_chirho::with_named_lock_chirho(
            &self.evidence_root_chirho,
            SHADOW_CANARY_EVIDENCE_LOCK_CHIRHO,
            || self.verify_window_unlocked_chirho(),
        )
    }

    /// Verify a quiescent evidence window under its existing lock without creating any durable
    /// artifact. Missing lock state is a refusal, never repaired during publication verification.
    pub fn verify_existing_window_read_only_chirho(
        &self,
    ) -> Result<Option<VerifiedShadowCanaryWindowChirho>> {
        seqlog_chirho::with_existing_named_read_lock_chirho(
            &self.evidence_root_chirho,
            SHADOW_CANARY_EVIDENCE_LOCK_CHIRHO,
            || self.verify_window_unlocked_chirho(),
        )
    }

    /// Export one internally verified source window under the existing evidence lock.
    ///
    /// See `cf8-canary-window-loss-sequence-chirho.md`. The returned source is crate-private because
    /// it still contains the raw group coordinate; only the path-free proof projection may leave the
    /// owning node.
    pub(crate) fn verified_window_source_read_only_chirho(
        &self,
    ) -> Result<Option<VerifiedShadowCanaryWindowSourceChirho>> {
        seqlog_chirho::with_existing_named_read_lock_chirho(
            &self.evidence_root_chirho,
            SHADOW_CANARY_EVIDENCE_LOCK_CHIRHO,
            || {
                let Some(_window_chirho) = self.verify_window_unlocked_chirho()? else {
                    return Ok(None);
                };
                let head_chirho = self.load_verified_head_chirho()?.ok_or_else(|| {
                    anyhow::anyhow!("shadow canary verified window lost its head")
                })?;
                let oldest_seq_chirho = head_chirho
                    .latest_seq_chirho
                    .checked_sub(head_chirho.window_len_chirho - 1)
                    .ok_or_else(|| anyhow::anyhow!("shadow canary proof window underflow"))?;
                let records_chirho = (oldest_seq_chirho..=head_chirho.latest_seq_chirho)
                    .map(|seq_chirho| self.load_verified_record_chirho(seq_chirho))
                    .collect::<Result<Vec<_>>>()?;
                Ok(Some(VerifiedShadowCanaryWindowSourceChirho {
                    head_chirho,
                    records_chirho,
                }))
            },
        )
    }

    fn append_unlocked_chirho(
        &self,
        observation_chirho: ShadowCanaryChirho,
    ) -> Result<SignedShadowCanaryEvidenceChirho> {
        self.verify_signing_identity_chirho()?;
        let head_chirho = self.load_verified_head_chirho()?;
        if head_chirho.is_none()
            && self
                .activation_append_cut_chirho
                .as_ref()
                .is_some_and(|cut_chirho| cut_chirho != &observation_chirho.append_cut_chirho)
        {
            bail!("ShadowCanaryActivationAnchorCutBindingRefusedChirho");
        }
        if let Some(head_chirho) = &head_chirho {
            let record_chirho = self.load_verified_record_chirho(head_chirho.latest_seq_chirho)?;
            if evidence_digest_chirho(&record_chirho)? != head_chirho.latest_digest_chirho {
                bail!("shadow canary head does not bind the latest record");
            }
            if observation_chirho == record_chirho.observation_chirho {
                return Ok(record_chirho);
            }
            if observation_chirho.append_cut_chirho.append_seq_chirho
                <= record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .append_seq_chirho
            {
                bail!("shadow canary append sequence did not advance");
            }
            let expected_append_seq_chirho = record_chirho
                .observation_chirho
                .append_cut_chirho
                .append_seq_chirho
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("shadow canary append sequence exhausted"))?;
            if observation_chirho.append_cut_chirho.append_seq_chirho != expected_append_seq_chirho
            {
                bail!("shadow canary append sequence is not dense");
            }
            if observation_chirho.append_cut_chirho.fence_epoch_chirho
                < record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .fence_epoch_chirho
            {
                bail!("shadow canary fence epoch regressed");
            }
            if observation_chirho.raft_term_chirho
                < record_chirho.observation_chirho.raft_term_chirho
            {
                bail!("shadow canary observed a regressed Raft term");
            }
            if observation_chirho.at_ms_chirho < record_chirho.observation_chirho.at_ms_chirho {
                bail!("shadow canary observed a regressed timestamp");
            }
        }
        let next_seq_chirho = head_chirho
            .as_ref()
            .map(|head_chirho| head_chirho.latest_seq_chirho)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("shadow canary evidence sequence exhausted"))?;
        let previous_digest_chirho = head_chirho
            .as_ref()
            .map(|head_chirho| head_chirho.latest_digest_chirho.clone())
            .unwrap_or_else(|| SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO.to_string());
        let mut evidence_chirho = SignedShadowCanaryEvidenceChirho {
            schema_chirho: SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO.to_string(),
            seq_chirho: next_seq_chirho,
            previous_digest_chirho,
            observation_chirho,
            key_id_chirho: self.node_id_chirho.0.clone(),
            sig_chirho: String::new(),
        };
        evidence_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
            &self.sign_root_chirho,
            &unsigned_evidence_message_chirho(&evidence_chirho)?,
        )?;
        let evidence_digest_chirho = evidence_digest_chirho(&evidence_chirho)?;

        let old_window_len_chirho = head_chirho
            .as_ref()
            .map(|head_chirho| head_chirho.window_len_chirho)
            .unwrap_or(0);
        let mut permit_count_chirho = head_chirho
            .as_ref()
            .map(|head_chirho| head_chirho.permit_count_chirho)
            .unwrap_or(0);
        let mut refusal_count_chirho = head_chirho
            .as_ref()
            .map(|head_chirho| head_chirho.refusal_count_chirho)
            .unwrap_or(0);
        if old_window_len_chirho == SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO {
            let evicted_seq_chirho = next_seq_chirho - SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO;
            let evicted_chirho = self.load_verified_record_chirho(evicted_seq_chirho)?;
            if evicted_chirho
                .observation_chirho
                .cutover_would_permit_chirho
            {
                permit_count_chirho = permit_count_chirho
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("shadow canary permit count underflow"))?;
            } else {
                refusal_count_chirho = refusal_count_chirho
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("shadow canary refusal count underflow"))?;
            }
        }
        if evidence_chirho
            .observation_chirho
            .cutover_would_permit_chirho
        {
            permit_count_chirho = permit_count_chirho
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("shadow canary permit count overflow"))?;
        } else {
            refusal_count_chirho = refusal_count_chirho
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("shadow canary refusal count overflow"))?;
        }
        let window_len_chirho = old_window_len_chirho
            .saturating_add(1)
            .min(SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO);

        write_file_durable_chirho(
            &self.record_path_chirho(next_seq_chirho),
            &serde_json::to_vec(&evidence_chirho)?,
        )
        .context("durably write shadow canary evidence record")?;
        let mut next_head_chirho = SignedShadowCanaryEvidenceHeadChirho {
            schema_chirho: if self.activation_anchor_digest_chirho.is_some() {
                SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V2_CHIRHO.to_string()
            } else {
                SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO.to_string()
            },
            group_chirho: self.group_chirho.clone(),
            latest_seq_chirho: next_seq_chirho,
            latest_digest_chirho: evidence_digest_chirho,
            window_len_chirho,
            permit_count_chirho,
            refusal_count_chirho,
            activation_anchor_digest_chirho: self.activation_anchor_digest_chirho.clone(),
            key_id_chirho: self.node_id_chirho.0.clone(),
            sig_chirho: String::new(),
        };
        next_head_chirho.sig_chirho = signer_chirho::sign_message_with_existing_key_chirho(
            &self.sign_root_chirho,
            &unsigned_head_message_chirho(&next_head_chirho)?,
        )?;
        write_file_durable_chirho(
            &self.head_path_chirho(),
            &serde_json::to_vec(&next_head_chirho)?,
        )
        .context("durably write shadow canary evidence head")?;
        Ok(evidence_chirho)
    }

    fn verify_window_unlocked_chirho(&self) -> Result<Option<VerifiedShadowCanaryWindowChirho>> {
        self.verify_signing_identity_chirho()?;
        let Some(head_chirho) = self.load_verified_head_chirho()? else {
            return Ok(None);
        };
        let mut expected_digest_chirho = head_chirho.latest_digest_chirho.clone();
        let oldest_seq_chirho = head_chirho
            .latest_seq_chirho
            .checked_sub(head_chirho.window_len_chirho - 1)
            .ok_or_else(|| anyhow::anyhow!("shadow canary window underflow"))?;
        let mut permit_count_chirho = 0;
        let mut refusal_count_chirho = 0;
        let mut newest_append_seq_chirho = None;
        let mut newest_fence_chirho = None;
        let mut newest_term_chirho = None;
        let mut newest_at_ms_chirho = None;
        let mut oldest_record_chirho = None;
        let mut latest_record_chirho = None;
        for seq_chirho in (oldest_seq_chirho..=head_chirho.latest_seq_chirho).rev() {
            let record_chirho = self.load_verified_record_chirho(seq_chirho)?;
            if evidence_digest_chirho(&record_chirho)? != expected_digest_chirho {
                bail!("shadow canary evidence chain digest mismatch");
            }
            if let Some(newer_append_seq_chirho) = newest_append_seq_chirho {
                if record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .append_seq_chirho
                    .checked_add(1)
                    != Some(newer_append_seq_chirho)
                {
                    bail!("shadow canary evidence append sequences are not dense");
                }
            }
            if let Some(newer_fence_chirho) = newest_fence_chirho {
                if record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .fence_epoch_chirho
                    > newer_fence_chirho
                {
                    bail!("shadow canary evidence contains a regressed fence epoch");
                }
            }
            if let Some(newer_term_chirho) = newest_term_chirho {
                if record_chirho.observation_chirho.raft_term_chirho > newer_term_chirho {
                    bail!("shadow canary evidence contains a regressed Raft term");
                }
            }
            if let Some(newer_at_ms_chirho) = newest_at_ms_chirho {
                if record_chirho.observation_chirho.at_ms_chirho > newer_at_ms_chirho {
                    bail!("shadow canary evidence contains a regressed timestamp");
                }
            }
            newest_append_seq_chirho = Some(
                record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .append_seq_chirho,
            );
            newest_fence_chirho = Some(
                record_chirho
                    .observation_chirho
                    .append_cut_chirho
                    .fence_epoch_chirho,
            );
            newest_term_chirho = Some(record_chirho.observation_chirho.raft_term_chirho);
            newest_at_ms_chirho = Some(record_chirho.observation_chirho.at_ms_chirho);
            if record_chirho.observation_chirho.cutover_would_permit_chirho {
                permit_count_chirho += 1;
            } else {
                refusal_count_chirho += 1;
            }
            expected_digest_chirho = record_chirho.previous_digest_chirho.clone();
            if latest_record_chirho.is_none() {
                latest_record_chirho = Some(record_chirho.clone());
            }
            oldest_record_chirho = Some(record_chirho);
        }
        if oldest_seq_chirho == 1
            && expected_digest_chirho != SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO
        {
            bail!("shadow canary evidence does not bind its genesis");
        }
        if permit_count_chirho != head_chirho.permit_count_chirho
            || refusal_count_chirho != head_chirho.refusal_count_chirho
            || permit_count_chirho + refusal_count_chirho != head_chirho.window_len_chirho
        {
            bail!("shadow canary head counts do not match its signed window");
        }
        let oldest_record_chirho = oldest_record_chirho.unwrap();
        let latest_record_chirho = latest_record_chirho.unwrap();
        Ok(Some(VerifiedShadowCanaryWindowChirho {
            activation_anchor_digest_chirho: head_chirho.activation_anchor_digest_chirho.clone(),
            group_chirho: self.group_chirho.clone(),
            latest_seq_chirho: head_chirho.latest_seq_chirho,
            latest_evidence_digest_chirho: head_chirho.latest_digest_chirho,
            latest_append_cut_chirho: latest_record_chirho
                .observation_chirho
                .append_cut_chirho
                .clone(),
            window_len_chirho: head_chirho.window_len_chirho,
            permit_count_chirho,
            refusal_count_chirho,
            oldest_at_ms_chirho: oldest_record_chirho.observation_chirho.at_ms_chirho,
            latest_at_ms_chirho: latest_record_chirho.observation_chirho.at_ms_chirho,
            oldest_fence_epoch_chirho: oldest_record_chirho
                .observation_chirho
                .append_cut_chirho
                .fence_epoch_chirho,
            latest_fence_epoch_chirho: latest_record_chirho
                .observation_chirho
                .append_cut_chirho
                .fence_epoch_chirho,
        }))
    }

    fn validate_observation_chirho(&self, observation_chirho: &ShadowCanaryChirho) -> Result<()> {
        if observation_chirho.minter_node_id_chirho != self.node_id_chirho {
            bail!("ShadowCanaryObservationMinterIdentityRefusedChirho");
        }
        if observation_chirho.schema_chirho != SHADOW_CANARY_SCHEMA_CHIRHO
            || observation_chirho.group_chirho != self.group_chirho
            || observation_chirho.append_cut_chirho.append_seq_chirho == 0
            || !is_lower_hex_chirho(
                &observation_chirho
                    .append_cut_chirho
                    .append_record_digest_chirho,
                64,
            )
            || observation_chirho
                .append_cut_chirho
                .append_hlc_physical_ms_chirho
                == 0
            || observation_chirho
                .append_cut_chirho
                .process_generation_chirho
                == 0
            || observation_chirho.append_cut_chirho.durable_term_chirho
                != observation_chirho.raft_term_chirho
            || observation_chirho.append_cut_chirho.fence_epoch_chirho == 0
            || observation_chirho
                .append_cut_chirho
                .fence_group_digest_chirho
                != consistency_group_digest_chirho(&self.group_chirho)?
            || (observation_chirho.raft_lease_valid_chirho
                && observation_chirho.raft_leader_id_chirho.is_none())
            || observation_chirho.cutover_would_permit_chirho
                != (observation_chirho.raft_leader_id_chirho.as_ref() == Some(&self.node_id_chirho)
                    && observation_chirho.raft_lease_valid_chirho)
        {
            bail!("shadow canary observation does not match the evidence store");
        }
        Ok(())
    }

    fn verify_signing_identity_chirho(&self) -> Result<()> {
        let existing_key_chirho =
            signer_chirho::existing_pubkey_hex_chirho(&self.sign_root_chirho)?;
        if existing_key_chirho != self.node_id_chirho.0 {
            bail!("shadow canary signing key changed or does not match the node id");
        }
        Ok(())
    }

    fn load_verified_head_chirho(&self) -> Result<Option<SignedShadowCanaryEvidenceHeadChirho>> {
        let path_chirho = self.head_path_chirho();
        if optional_shadow_canary_path_metadata_chirho(
            &path_chirho,
            "inspect shadow canary evidence head",
        )?
        .is_none()
        {
            return Ok(None);
        }
        let head_chirho: SignedShadowCanaryEvidenceHeadChirho =
            serde_json::from_slice(&read_bounded_regular_file_chirho(&path_chirho)?)
                .context("decode shadow canary evidence head")?;
        let count_total_chirho = head_chirho
            .permit_count_chirho
            .checked_add(head_chirho.refusal_count_chirho)
            .ok_or_else(|| anyhow::anyhow!("shadow canary evidence head count overflow"))?;
        let schema_matches_anchor_chirho = matches!(
            (
                head_chirho.schema_chirho.as_str(),
                &head_chirho.activation_anchor_digest_chirho,
                &self.activation_anchor_digest_chirho,
            ),
            (SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V1_CHIRHO, None, None)
                | (
                    SHADOW_CANARY_EVIDENCE_HEAD_SCHEMA_V2_CHIRHO,
                    Some(_),
                    Some(_)
                )
        );
        if !schema_matches_anchor_chirho
            || head_chirho.activation_anchor_digest_chirho != self.activation_anchor_digest_chirho
            || head_chirho
                .activation_anchor_digest_chirho
                .as_deref()
                .is_some_and(|digest_chirho| !is_lower_hex_chirho(digest_chirho, 64))
            || head_chirho.group_chirho != self.group_chirho
            || head_chirho.latest_seq_chirho == 0
            || head_chirho.window_len_chirho == 0
            || head_chirho.window_len_chirho > SHADOW_CANARY_WINDOW_CAPACITY_CHIRHO
            || head_chirho.window_len_chirho > head_chirho.latest_seq_chirho
            || count_total_chirho != head_chirho.window_len_chirho
            || head_chirho.key_id_chirho != self.node_id_chirho.0
            || !evidence_digest_has_shape_chirho(&head_chirho.latest_digest_chirho)
            || head_chirho.sig_chirho.is_empty()
        {
            bail!("shadow canary evidence head has an invalid shape");
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &self.node_id_chirho.0,
            &unsigned_head_message_chirho(&head_chirho)?,
            &head_chirho.sig_chirho,
        )? {
            bail!("shadow canary evidence head signature invalid");
        }
        Ok(Some(head_chirho))
    }

    fn load_verified_record_chirho(
        &self,
        seq_chirho: u64,
    ) -> Result<SignedShadowCanaryEvidenceChirho> {
        let record_chirho: SignedShadowCanaryEvidenceChirho = serde_json::from_slice(
            &read_bounded_regular_file_chirho(&self.record_path_chirho(seq_chirho))
                .with_context(|| format!("read shadow canary evidence seq {seq_chirho}"))?,
        )
        .with_context(|| format!("decode shadow canary evidence seq {seq_chirho}"))?;
        if record_chirho.schema_chirho != SHADOW_CANARY_EVIDENCE_SCHEMA_CHIRHO
            || record_chirho.seq_chirho != seq_chirho
            || record_chirho.observation_chirho.schema_chirho != SHADOW_CANARY_SCHEMA_CHIRHO
            || record_chirho.observation_chirho.group_chirho != self.group_chirho
            || record_chirho.observation_chirho.minter_node_id_chirho != self.node_id_chirho
            || record_chirho
                .observation_chirho
                .append_cut_chirho
                .fence_epoch_chirho
                == 0
            || (record_chirho.seq_chirho == 1
                && record_chirho.previous_digest_chirho
                    != SHADOW_CANARY_EVIDENCE_GENESIS_DIGEST_CHIRHO)
            || (record_chirho.seq_chirho > 1
                && !evidence_digest_has_shape_chirho(&record_chirho.previous_digest_chirho))
            || record_chirho.key_id_chirho != self.node_id_chirho.0
            || record_chirho.sig_chirho.is_empty()
        {
            bail!("shadow canary evidence record has an invalid shape");
        }
        self.validate_observation_chirho(&record_chirho.observation_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &self.node_id_chirho.0,
            &unsigned_evidence_message_chirho(&record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!("shadow canary evidence record signature invalid");
        }
        Ok(record_chirho)
    }

    fn head_path_chirho(&self) -> PathBuf {
        self.evidence_root_chirho
            .join(SHADOW_CANARY_EVIDENCE_HEAD_FILE_CHIRHO)
    }

    fn record_path_chirho(&self, seq_chirho: u64) -> PathBuf {
        self.evidence_root_chirho
            .join(SHADOW_CANARY_EVIDENCE_RECORDS_DIR_CHIRHO)
            .join(format!(
                "slot-{:04}-chirho.json",
                seq_chirho % SHADOW_CANARY_SLOT_COUNT_CHIRHO
            ))
    }
}

fn require_regular_directory_chirho(path_chirho: &Path) -> Result<()> {
    let Some(metadata_chirho) = optional_shadow_canary_path_metadata_chirho(
        path_chirho,
        "inspect shadow canary evidence directory",
    )?
    else {
        bail!("shadow canary evidence store does not exist");
    };
    if !metadata_chirho.file_type().is_dir() {
        bail!("shadow canary evidence directory is not a regular directory");
    }
    Ok(())
}

pub(crate) fn optional_shadow_canary_path_metadata_chirho(
    path_chirho: &Path,
    context_chirho: &'static str,
) -> Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(metadata_chirho) => Ok(Some(metadata_chirho)),
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(None),
        Err(error_chirho) => Err(error_chirho).context(context_chirho),
    }
}

fn read_bounded_regular_file_chirho(path_chirho: &Path) -> Result<Vec<u8>> {
    let path_metadata_chirho =
        std::fs::symlink_metadata(path_chirho).context("inspect shadow canary evidence file")?;
    if !path_metadata_chirho.file_type().is_file()
        || path_metadata_chirho.len() == 0
        || path_metadata_chirho.len() > MAX_SHADOW_CANARY_EVIDENCE_FILE_BYTES_CHIRHO
    {
        bail!("shadow canary evidence file is not a bounded regular file");
    }
    let file_chirho =
        std::fs::File::open(path_chirho).context("open shadow canary evidence file")?;
    let opened_metadata_chirho = file_chirho
        .metadata()
        .context("inspect opened shadow canary evidence file")?;
    if !opened_metadata_chirho.is_file()
        || opened_metadata_chirho.len() != path_metadata_chirho.len()
        || opened_metadata_chirho.dev() != path_metadata_chirho.dev()
        || opened_metadata_chirho.ino() != path_metadata_chirho.ino()
    {
        bail!("shadow canary evidence file changed before bounded read");
    }
    let capacity_chirho = usize::try_from(opened_metadata_chirho.len())
        .context("shadow canary evidence length exceeds usize")?;
    let mut bytes_chirho = Vec::with_capacity(capacity_chirho);
    file_chirho
        .take(MAX_SHADOW_CANARY_EVIDENCE_FILE_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .context("read bounded shadow canary evidence file")?;
    let final_metadata_chirho =
        std::fs::symlink_metadata(path_chirho).context("reinspect shadow canary evidence file")?;
    if u64::try_from(bytes_chirho.len()).ok() != Some(opened_metadata_chirho.len())
        || !final_metadata_chirho.file_type().is_file()
        || final_metadata_chirho.len() != opened_metadata_chirho.len()
        || final_metadata_chirho.dev() != opened_metadata_chirho.dev()
        || final_metadata_chirho.ino() != opened_metadata_chirho.ino()
    {
        bail!("shadow canary evidence file changed during bounded read");
    }
    Ok(bytes_chirho)
}

fn is_lower_hex_chirho(value_chirho: &str, len_chirho: usize) -> bool {
    value_chirho.len() == len_chirho
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

fn unsigned_evidence_message_chirho(
    evidence_chirho: &SignedShadowCanaryEvidenceChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = evidence_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

fn unsigned_head_message_chirho(
    head_chirho: &SignedShadowCanaryEvidenceHeadChirho,
) -> Result<Vec<u8>> {
    let mut unsigned_chirho = head_chirho.clone();
    unsigned_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&unsigned_chirho)?)
}

pub(crate) fn evidence_digest_chirho(
    evidence_chirho: &SignedShadowCanaryEvidenceChirho,
) -> Result<String> {
    Ok(format!(
        "{}{}",
        SHADOW_CANARY_EVIDENCE_DIGEST_PREFIX_CHIRHO,
        blake3::hash(&serde_json::to_vec(evidence_chirho)?).to_hex()
    ))
}

pub(crate) fn evidence_digest_has_shape_chirho(digest_chirho: &str) -> bool {
    let Some(hex_chirho) = digest_chirho.strip_prefix(SHADOW_CANARY_EVIDENCE_DIGEST_PREFIX_CHIRHO)
    else {
        return false;
    };
    hex_chirho.len() == 64
        && hex_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}
