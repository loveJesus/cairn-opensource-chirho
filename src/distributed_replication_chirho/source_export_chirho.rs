// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Writer-region preparation for the P3/B2 replication source.
//!
//! This is the only R1-C component allowed to mutate the source root. It uses the existing Gate 1
//! anchor/head machinery and the signed ref-snapshot exporter; it does not manufacture an
//! exemption for roots whose Ring-A logs are empty. The HTTP source remains independently
//! read-only and can serve only the artifacts this preparation step has durably produced.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/b2-replica-serve-design-chirho.md`.

use crate::gate1_anchor_chirho::{
    append_gate1_ring_a_anchors_chirho, canonical_gate1_anchor_head_replication_text_chirho,
    export_gate1_anchor_head_replication_chirho,
};
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::write_file_durable_chirho;
use cairn_replication_chirho::ref_snapshot_chirho::export_ref_snapshot_chirho;
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use serde::Serialize;
use std::path::Path;

pub const REPLICATION_SOURCE_EXPORT_REPORT_SCHEMA_CHIRHO: &str =
    "replication-source-export-report-v1-chirho";

/// Safe operator evidence for one source preparation. No key material or signed bytes are printed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplicationSourceExportReportChirho {
    pub schema_chirho: String,
    pub source_key_id_chirho: String,
    pub gate1_anchor_records_appended_chirho: u64,
    pub gate1_anchor_record_count_chirho: u64,
    pub ref_snapshot_seq_chirho: u64,
    pub ref_snapshot_hash_chirho: String,
    pub ref_snapshot_ref_count_chirho: u64,
    pub ref_snapshot_appended_chirho: bool,
    pub source_time_unix_chirho: u64,
}

/// Produce every signed source-side input required by the full verified pull.
///
/// Empty Ring-A families are anchored through the real Gate 1 machinery as zero-row prefixes; they
/// are not exempted. An existing keypair is mandatory so an operator cannot accidentally create a
/// new replication identity merely by running export tooling against the wrong root.
pub fn prepare_replication_source_chirho(
    source_root_chirho: &Path,
    gate1_head_output_path_chirho: &Path,
    source_time_unix_chirho: u64,
) -> Result<ReplicationSourceExportReportChirho> {
    if !source_root_chirho.is_dir() {
        bail!("ReplicationSourceRootRefusedChirho: source root is not an existing directory");
    }
    let source_key_id_chirho = existing_keypair_pubkey_hex_chirho(source_root_chirho)
        .context("ReplicationSourceExistingKeyRefusedChirho")?;

    let appended_anchors_chirho = append_gate1_ring_a_anchors_chirho(source_root_chirho)
        .context("ReplicationSourceGate1AnchorRefusedChirho")?;
    let gate1_head_chirho = export_gate1_anchor_head_replication_chirho(source_root_chirho)
        .context("ReplicationSourceGate1HeadRefusedChirho")?;
    if gate1_head_chirho.key_id_chirho != source_key_id_chirho {
        bail!("ReplicationSourceGate1KeyBindingRefusedChirho");
    }

    let snapshot_export_chirho =
        export_ref_snapshot_chirho(source_root_chirho, source_time_unix_chirho)
            .context("ReplicationSourceRefSnapshotRefusedChirho")?;
    if snapshot_export_chirho.head_chirho.key_id_chirho != source_key_id_chirho {
        bail!("ReplicationSourceSnapshotKeyBindingRefusedChirho");
    }

    if let Some(parent_chirho) = gate1_head_output_path_chirho.parent() {
        std::fs::create_dir_all(parent_chirho)
            .context("ReplicationSourceHeadParentRefusedChirho")?;
    }
    let gate1_head_text_chirho =
        canonical_gate1_anchor_head_replication_text_chirho(&gate1_head_chirho)
            .context("ReplicationSourceHeadCanonicalizationRefusedChirho")?;
    write_file_durable_chirho(
        gate1_head_output_path_chirho,
        gate1_head_text_chirho.as_bytes(),
    )
    .context("ReplicationSourceHeadWriteRefusedChirho")?;

    Ok(ReplicationSourceExportReportChirho {
        schema_chirho: REPLICATION_SOURCE_EXPORT_REPORT_SCHEMA_CHIRHO.to_string(),
        source_key_id_chirho,
        gate1_anchor_records_appended_chirho: appended_anchors_chirho.len() as u64,
        gate1_anchor_record_count_chirho: gate1_head_chirho.anchor_record_count_chirho,
        ref_snapshot_seq_chirho: snapshot_export_chirho.head_chirho.seq_chirho,
        ref_snapshot_hash_chirho: snapshot_export_chirho.head_chirho.snapshot_hash_chirho.0,
        ref_snapshot_ref_count_chirho: snapshot_export_chirho.head_chirho.ref_count_chirho,
        ref_snapshot_appended_chirho: snapshot_export_chirho.appended_chirho,
        source_time_unix_chirho,
    })
}
