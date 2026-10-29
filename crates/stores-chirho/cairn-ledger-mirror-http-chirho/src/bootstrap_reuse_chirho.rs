// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exact historical-prefix equivalence for same-leader and signed-successor bootstrap reuse.

use crate::recovery_chirho::{
    LedgerMirrorPrefixReuseBindingChirho, LedgerMirrorVerifiedPrefixManifestChirho,
    PREFIX_MANIFEST_SCHEMA_V1_CHIRHO,
};
use anyhow::{bail, Result};

use super::{LedgerMirrorBootstrapHeadChirho, BOOTSTRAP_HEAD_SCHEMA_V1_CHIRHO};

/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/item7-f1-mirror-recovery-adoption-chirho.md`.
pub(super) fn bootstrap_reuses_manifest_chirho(
    head_chirho: &LedgerMirrorBootstrapHeadChirho,
    manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
    previous_assignment_digest_chirho: Option<&str>,
) -> Result<bool> {
    let LedgerMirrorBootstrapHeadChirho {
        schema_chirho,
        consistency_group_digest_chirho,
        origin_leader_node_id_chirho,
        holder_node_id_chirho: _,
        assignment_digest_chirho,
        assigned_node_ids_chirho,
        membership_view_digest_chirho: _,
        historical_term_chirho,
        cluster_id_chirho,
        journal_genesis_digest_chirho,
        record_count_chirho,
        dense_chain_digest_chirho,
        manifest_digest_chirho: _,
        tail_record_chirho,
        state_digest_chirho: _,
        sig_hex_chirho: _,
    } = head_chirho;
    if schema_chirho != BOOTSTRAP_HEAD_SCHEMA_V1_CHIRHO {
        return Ok(false);
    }
    let head_binding_chirho = LedgerMirrorPrefixReuseBindingChirho {
        manifest_schema_chirho: PREFIX_MANIFEST_SCHEMA_V1_CHIRHO.to_string(),
        origin_leader_node_id_chirho: origin_leader_node_id_chirho.clone(),
        consistency_group_digest_chirho: consistency_group_digest_chirho.clone(),
        assignment_digest_chirho: assignment_digest_chirho.clone(),
        assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
        cluster_id_chirho: cluster_id_chirho.clone(),
        journal_genesis_digest_chirho: journal_genesis_digest_chirho.clone(),
        tail_seq_chirho: tail_record_chirho.record_seq_chirho,
        tail_record_digest_chirho: tail_record_chirho.record_digest_chirho.clone(),
        tail_epoch_chirho: tail_record_chirho.record_epoch_chirho,
        tail_hlc_physical_ms_chirho: tail_record_chirho.record_hlc_physical_ms_chirho,
        tail_hlc_logical_chirho: tail_record_chirho.record_hlc_logical_chirho,
        record_count_chirho: *record_count_chirho,
        dense_chain_digest_chirho: dense_chain_digest_chirho.clone(),
    };
    let current_binding_chirho = manifest_chirho.reuse_binding_chirho();
    if head_binding_chirho != current_binding_chirho {
        let Some(previous_assignment_digest_chirho) = previous_assignment_digest_chirho else {
            return Ok(false);
        };
        let mut predecessor_binding_chirho = current_binding_chirho;
        predecessor_binding_chirho.assignment_digest_chirho =
            previous_assignment_digest_chirho.to_string();
        if head_binding_chirho != predecessor_binding_chirho {
            return Ok(false);
        }
    }
    if *historical_term_chirho > manifest_chirho.expected_term_chirho() {
        bail!("LedgerMirrorBootstrapHeadAuthorityRollbackRefusedChirho");
    }
    Ok(true)
}
