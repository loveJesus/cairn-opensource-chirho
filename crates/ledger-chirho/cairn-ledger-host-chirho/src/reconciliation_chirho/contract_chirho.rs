// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded signed wire contracts for the first durable GD7 reconciliation slice.

use cairn_writer_head_chirho::writer_head_chirho::split_writer_epoch_chirho;
use serde::{Deserialize, Serialize};

pub const GD7_RECONCILIATION_HEAD_SCHEMA_V1_CHIRHO: &str = "gd7-reconciliation-head-v1-chirho";
pub const GD7_RECONCILIATION_CHECKPOINT_SCHEMA_V1_CHIRHO: &str =
    "gd7-reconciliation-checkpoint-v1-chirho";
pub const GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO: &str =
    "gd7-adoption-checkpoint-binding-v1-chirho";
pub const MAX_GD7_RECONCILIATION_HEAD_BYTES_CHIRHO: usize = 4 * 1024;
pub const MAX_GD7_RECONCILIATION_CHECKPOINT_BYTES_CHIRHO: usize = 16 * 1024;

pub(crate) const MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO: usize = 256;
pub(crate) const MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO: usize = 1024;

/// Injected verification root for one node's GD7 control-plane records.
pub trait Gd7ReconciliationVerifierPortChirho {
    fn key_id_chirho(&self) -> String;
    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool;
}

/// Injected signer for locally-owned GD7 control-plane records.
///
/// This is deliberately separate from `LedgerSignerPortChirho`: the production journal signer
/// admits only ledger schemas and must not be weakened to sign reconciliation metadata.
pub trait Gd7ReconciliationSignerPortChirho: Gd7ReconciliationVerifierPortChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String>;
}

/// Injected verification root for one winner journal's signed ledger records.
pub trait Gd7LedgerRecordVerifierPortChirho {
    fn key_id_chirho(&self) -> String;
    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool;
}

pub(crate) const WRITER_FENCE_GROUP_DIGEST_PREFIX_CHIRHO: &str =
    "writer-fence-group-blake3-chirho:";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(
    clippy::enum_variant_names,
    reason = "repository-owned enum variants must carry the Chirho suffix"
)]
pub enum Gd7ReconciliationPhaseChirho {
    ObservedHeldChirho,
    ManifestingChirho,
    PlanSealedChirho,
    AdoptedHeldChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ForkCoordinateChirho {
    pub epoch_chirho: u64,
    pub seq_chirho: u64,
    pub record_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7JournalTailCoordinateChirho {
    pub epoch_chirho: u64,
    pub seq_chirho: u64,
    pub record_digest_chirho: String,
}

/// Immutable identity of one loser-to-winner reconciliation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReconciliationIdentityChirho {
    pub consistency_group_digest_chirho: String,
    pub winner_node_chirho: String,
    pub held_node_chirho: String,
    pub winner_term_chirho: u64,
    pub losing_term_chirho: u64,
    pub winner_journal_genesis_digest_chirho: String,
    pub winner_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
    pub fork_chirho: Gd7ForkCoordinateChirho,
    pub losing_journal_genesis_digest_chirho: String,
    pub losing_journal_tail_chirho: Gd7JournalTailCoordinateChirho,
}

/// Exact immutable Cut A inputs selected by one held adoption checkpoint.
///
/// This binding proves which `PlanSealedChirho` checkpoint was active at commit. It deliberately
/// does not rely on that phase having only one producer today: a future reseal must still satisfy
/// the exact prior-link and active-at-commit checks before it can be adopted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7AdoptionCheckpointBindingChirho {
    pub schema_chirho: String,
    pub plan_checkpoint_ref_chirho: String,
    pub materialization_input_binding_digest_chirho: String,
    pub evidence_checkpoint_ref_chirho: String,
    pub evidence_manifest_ref_chirho: String,
    pub held_view_checkpoint_ref_chirho: String,
    pub held_view_bundle_root_ref_chirho: String,
    pub read_only_branch_checkpoint_ref_chirho: String,
    pub prefix_root_ref_chirho: String,
    pub winner_history_root_ref_chirho: String,
    pub fork_baseline_root_ref_chirho: String,
    pub winner_handoff_attempt_digest_chirho: String,
    pub projection_fold_ref_chirho: String,
    pub accepted_projection_digest_chirho: String,
    pub candidate_journal_digest_chirho: String,
    pub candidate_journal_byte_len_chirho: u64,
    pub candidate_record_count_chirho: u64,
    pub candidate_projection_digest_chirho: String,
    pub candidate_projection_byte_len_chirho: u64,
    pub candidate_projection_row_count_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReconciliationCheckpointStateChirho {
    pub phase_chirho: Gd7ReconciliationPhaseChirho,
    pub transition_seq_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint_ref_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_head_ref_chirho: Option<String>,
    pub manifest_page_count_chirho: u64,
    pub manifest_record_count_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_head_ref_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero_u64_chirho")]
    pub plan_page_count_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sealed_plan_ref_chirho: Option<String>,
    pub effect_obligation_count_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_object_ref_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adoption_binding_chirho: Option<Gd7AdoptionCheckpointBindingChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReconciliationCheckpointChirho {
    pub schema_chirho: String,
    pub identity_chirho: Gd7ReconciliationIdentityChirho,
    pub winner_fork_witness_object_digest_chirho: String,
    pub state_chirho: Gd7ReconciliationCheckpointStateChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gd7ReconciliationHeadChirho {
    pub schema_chirho: String,
    pub consistency_group_digest_chirho: String,
    pub reconciliation_identity_digest_chirho: String,
    pub active_checkpoint_ref_chirho: String,
    pub transition_seq_chirho: u64,
    pub phase_chirho: Gd7ReconciliationPhaseChirho,
    pub key_id_chirho: String,
    pub sig_chirho: String,
}

pub(crate) fn is_lower_hex_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
}

pub(crate) fn consistency_group_digest_suffix_chirho(value_chirho: &str) -> Option<&str> {
    let suffix_chirho = value_chirho.strip_prefix(WRITER_FENCE_GROUP_DIGEST_PREFIX_CHIRHO)?;
    is_lower_hex_digest_chirho(suffix_chirho).then_some(suffix_chirho)
}

pub(crate) fn is_bounded_label_chirho(value_chirho: &str, maximum_chirho: usize) -> bool {
    !value_chirho.is_empty()
        && value_chirho.len() <= maximum_chirho
        && value_chirho
            .chars()
            .all(|character_chirho| !character_chirho.is_control())
}

fn is_zero_u64_chirho(value_chirho: &u64) -> bool {
    *value_chirho == 0
}

pub(crate) fn validate_identity_chirho(identity_chirho: &Gd7ReconciliationIdentityChirho) -> bool {
    let winner_tail_epoch_chirho =
        split_writer_epoch_chirho(identity_chirho.winner_journal_tail_chirho.epoch_chirho);
    let fork_epoch_chirho = split_writer_epoch_chirho(identity_chirho.fork_chirho.epoch_chirho);
    let losing_tail_epoch_chirho =
        split_writer_epoch_chirho(identity_chirho.losing_journal_tail_chirho.epoch_chirho);
    consistency_group_digest_suffix_chirho(&identity_chirho.consistency_group_digest_chirho)
        .is_some()
        && is_lower_hex_digest_chirho(&identity_chirho.winner_node_chirho)
        && is_lower_hex_digest_chirho(&identity_chirho.held_node_chirho)
        && identity_chirho.winner_node_chirho != identity_chirho.held_node_chirho
        && identity_chirho.winner_term_chirho > identity_chirho.losing_term_chirho
        && is_lower_hex_digest_chirho(&identity_chirho.winner_journal_genesis_digest_chirho)
        && identity_chirho.winner_journal_genesis_digest_chirho
            == identity_chirho.losing_journal_genesis_digest_chirho
        && is_lower_hex_digest_chirho(
            &identity_chirho
                .winner_journal_tail_chirho
                .record_digest_chirho,
        )
        && is_lower_hex_digest_chirho(&identity_chirho.fork_chirho.record_digest_chirho)
        && is_lower_hex_digest_chirho(&identity_chirho.losing_journal_genesis_digest_chirho)
        && is_lower_hex_digest_chirho(
            &identity_chirho
                .losing_journal_tail_chirho
                .record_digest_chirho,
        )
        && u64::from(winner_tail_epoch_chirho.geo_term_chirho) == identity_chirho.winner_term_chirho
        && u64::from(fork_epoch_chirho.geo_term_chirho) == identity_chirho.losing_term_chirho
        && u64::from(losing_tail_epoch_chirho.geo_term_chirho) == identity_chirho.losing_term_chirho
        && identity_chirho.fork_chirho.seq_chirho
            < identity_chirho.winner_journal_tail_chirho.seq_chirho
        && identity_chirho.fork_chirho.seq_chirho
            < identity_chirho.losing_journal_tail_chirho.seq_chirho
        && identity_chirho.fork_chirho.epoch_chirho
            <= identity_chirho.winner_journal_tail_chirho.epoch_chirho
        && identity_chirho.fork_chirho.epoch_chirho
            <= identity_chirho.losing_journal_tail_chirho.epoch_chirho
        && (identity_chirho.fork_chirho.seq_chirho
            != identity_chirho.winner_journal_tail_chirho.seq_chirho
            || identity_chirho.fork_chirho.record_digest_chirho
                == identity_chirho
                    .winner_journal_tail_chirho
                    .record_digest_chirho)
        && (identity_chirho.fork_chirho.seq_chirho
            != identity_chirho.losing_journal_tail_chirho.seq_chirho
            || identity_chirho.fork_chirho.record_digest_chirho
                == identity_chirho
                    .losing_journal_tail_chirho
                    .record_digest_chirho)
}

pub(crate) fn observed_held_state_chirho() -> Gd7ReconciliationCheckpointStateChirho {
    Gd7ReconciliationCheckpointStateChirho {
        phase_chirho: Gd7ReconciliationPhaseChirho::ObservedHeldChirho,
        transition_seq_chirho: 0,
        previous_checkpoint_ref_chirho: None,
        manifest_head_ref_chirho: None,
        manifest_page_count_chirho: 0,
        manifest_record_count_chirho: 0,
        plan_head_ref_chirho: None,
        plan_page_count_chirho: 0,
        sealed_plan_ref_chirho: None,
        effect_obligation_count_chirho: 0,
        cursor_object_ref_chirho: None,
        adoption_binding_chirho: None,
    }
}

pub(crate) fn validate_adoption_checkpoint_binding_chirho(
    binding_chirho: &Gd7AdoptionCheckpointBindingChirho,
) -> bool {
    binding_chirho.schema_chirho == GD7_ADOPTION_CHECKPOINT_BINDING_SCHEMA_V1_CHIRHO
        && [
            &binding_chirho.plan_checkpoint_ref_chirho,
            &binding_chirho.materialization_input_binding_digest_chirho,
            &binding_chirho.evidence_checkpoint_ref_chirho,
            &binding_chirho.evidence_manifest_ref_chirho,
            &binding_chirho.held_view_checkpoint_ref_chirho,
            &binding_chirho.held_view_bundle_root_ref_chirho,
            &binding_chirho.read_only_branch_checkpoint_ref_chirho,
            &binding_chirho.prefix_root_ref_chirho,
            &binding_chirho.winner_history_root_ref_chirho,
            &binding_chirho.fork_baseline_root_ref_chirho,
            &binding_chirho.winner_handoff_attempt_digest_chirho,
            &binding_chirho.projection_fold_ref_chirho,
            &binding_chirho.accepted_projection_digest_chirho,
            &binding_chirho.candidate_journal_digest_chirho,
            &binding_chirho.candidate_projection_digest_chirho,
        ]
        .into_iter()
        .all(|digest_chirho| is_lower_hex_digest_chirho(digest_chirho))
        && binding_chirho.candidate_journal_byte_len_chirho > 0
        && binding_chirho.candidate_record_count_chirho > 0
        && binding_chirho.candidate_projection_byte_len_chirho > 0
}

pub(crate) fn validate_checkpoint_state_chirho(
    state_chirho: &Gd7ReconciliationCheckpointStateChirho,
) -> bool {
    let references_valid_chirho = state_chirho
        .previous_checkpoint_ref_chirho
        .as_deref()
        .map(is_lower_hex_digest_chirho)
        .unwrap_or(true)
        && state_chirho
            .manifest_head_ref_chirho
            .as_deref()
            .map(is_lower_hex_digest_chirho)
            .unwrap_or(true)
        && state_chirho
            .plan_head_ref_chirho
            .as_deref()
            .map(is_lower_hex_digest_chirho)
            .unwrap_or(true)
        && state_chirho
            .sealed_plan_ref_chirho
            .as_deref()
            .map(is_lower_hex_digest_chirho)
            .unwrap_or(true)
        && state_chirho
            .cursor_object_ref_chirho
            .as_deref()
            .map(is_lower_hex_digest_chirho)
            .unwrap_or(true)
        && state_chirho
            .adoption_binding_chirho
            .as_ref()
            .map(validate_adoption_checkpoint_binding_chirho)
            .unwrap_or(true);
    let chain_shape_valid_chirho = (state_chirho.transition_seq_chirho == 0)
        == state_chirho.previous_checkpoint_ref_chirho.is_none();
    let manifest_shape_valid_chirho = (state_chirho.manifest_page_count_chirho == 0)
        == state_chirho.manifest_head_ref_chirho.is_none()
        && (state_chirho.plan_page_count_chirho == 0)
            == state_chirho.plan_head_ref_chirho.is_none()
        && state_chirho.plan_page_count_chirho <= state_chirho.manifest_page_count_chirho
        && (state_chirho.manifest_page_count_chirho != 0
            || (state_chirho.manifest_record_count_chirho == 0
                && state_chirho.plan_page_count_chirho == 0
                && state_chirho.effect_obligation_count_chirho == 0));
    let phase_shape_valid_chirho = match state_chirho.phase_chirho {
        Gd7ReconciliationPhaseChirho::ObservedHeldChirho => {
            state_chirho.transition_seq_chirho == 0
                && state_chirho.previous_checkpoint_ref_chirho.is_none()
                && state_chirho.manifest_head_ref_chirho.is_none()
                && state_chirho.manifest_page_count_chirho == 0
                && state_chirho.manifest_record_count_chirho == 0
                && state_chirho.plan_head_ref_chirho.is_none()
                && state_chirho.plan_page_count_chirho == 0
                && state_chirho.sealed_plan_ref_chirho.is_none()
                && state_chirho.effect_obligation_count_chirho == 0
                && state_chirho.cursor_object_ref_chirho.is_none()
                && state_chirho.adoption_binding_chirho.is_none()
        }
        Gd7ReconciliationPhaseChirho::ManifestingChirho => {
            state_chirho.transition_seq_chirho > 0
                && state_chirho.previous_checkpoint_ref_chirho.is_some()
                && state_chirho.manifest_page_count_chirho > 0
                && state_chirho.sealed_plan_ref_chirho.is_none()
                && state_chirho.effect_obligation_count_chirho == 0
                && (if state_chirho.cursor_object_ref_chirho.is_some() {
                    state_chirho.plan_page_count_chirho == state_chirho.manifest_page_count_chirho
                        || state_chirho.plan_page_count_chirho.checked_add(1)
                            == Some(state_chirho.manifest_page_count_chirho)
                } else {
                    state_chirho.plan_page_count_chirho.checked_add(1)
                        == Some(state_chirho.manifest_page_count_chirho)
                })
                && state_chirho.adoption_binding_chirho.is_none()
        }
        Gd7ReconciliationPhaseChirho::PlanSealedChirho => {
            state_chirho.transition_seq_chirho > 0
                && state_chirho.previous_checkpoint_ref_chirho.is_some()
                && state_chirho.cursor_object_ref_chirho.is_none()
                && state_chirho.manifest_page_count_chirho > 0
                && state_chirho.plan_page_count_chirho == state_chirho.manifest_page_count_chirho
                && state_chirho.plan_head_ref_chirho.is_some()
                && state_chirho.sealed_plan_ref_chirho == state_chirho.plan_head_ref_chirho
                && state_chirho.adoption_binding_chirho.is_none()
        }
        Gd7ReconciliationPhaseChirho::AdoptedHeldChirho => {
            state_chirho.transition_seq_chirho > 0
                && state_chirho.previous_checkpoint_ref_chirho.is_some()
                && state_chirho.cursor_object_ref_chirho.is_none()
                && state_chirho.manifest_page_count_chirho > 0
                && state_chirho.plan_page_count_chirho == state_chirho.manifest_page_count_chirho
                && state_chirho.plan_head_ref_chirho.is_some()
                && state_chirho.sealed_plan_ref_chirho == state_chirho.plan_head_ref_chirho
                && state_chirho
                    .adoption_binding_chirho
                    .as_ref()
                    .is_some_and(|binding_chirho| {
                        Some(binding_chirho.plan_checkpoint_ref_chirho.as_str())
                            == state_chirho.previous_checkpoint_ref_chirho.as_deref()
                    })
        }
    };
    references_valid_chirho
        && chain_shape_valid_chirho
        && manifest_shape_valid_chirho
        && phase_shape_valid_chirho
}

pub(crate) fn validate_key_and_signature_chirho(
    key_id_chirho: &str,
    signature_chirho: &str,
) -> bool {
    is_bounded_label_chirho(key_id_chirho, MAX_GD7_RECONCILIATION_LABEL_BYTES_CHIRHO)
        && is_bounded_label_chirho(
            signature_chirho,
            MAX_GD7_RECONCILIATION_SIGNATURE_BYTES_CHIRHO,
        )
}
