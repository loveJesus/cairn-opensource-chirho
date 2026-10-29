// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Read-only pre-rename H3 resident proof. The non-live staging tree must contain the exact signed
//! resident identity, verified journal tail, and canary cut that activation produced.

use crate::bounded_file_chirho::read_bounded_regular_file_chirho;
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::money_stage_chirho::LedgerRegenesisMoneyStageChirho;
use cairn_durable_chirho::fsync_dir_chirho;
use cairn_kind_registry_chirho::chain_chirho::{
    load_verified_registry_chirho, KindRegistryPortsChirho,
};
use cairn_ledger_host_chirho::{
    FsLedgerStorageChirho, PinnedKindIssuerVerifierChirho, PlatformPolicyMintAuthorityChirho,
    ResidentLedgerClockChirho, StaticClusterMembershipChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::shadow_canary_generation_chirho::ShadowCanaryGenerationStoreChirho;
use cairn_writer_head_chirho::resident_writer_chirho::inspect_resident_writer_identity_chirho;
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

const H3_CANARY_EVIDENCE_DIR_CHIRHO: &str = "writer-canary-chirho";
pub const MAX_LEDGER_REGENESIS_PUBLICATION_MANIFEST_BYTES_CHIRHO: u64 = 64 * 1024;
pub const LEDGER_REGENESIS_PUBLICATION_MANIFEST_SCHEMA_V1_CHIRHO: &str =
    "ledger-regenesis-publication-manifest-v1-chirho";
pub const LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO: &str =
    "ledger-regenesis-publication-manifest-v1-chirho.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisPublicationProofChirho {
    pub activation_authorization_digest_chirho: String,
    pub canary_evidence_digest_chirho: String,
    pub resident_identity_digest_chirho: String,
    pub journal_tail_seq_chirho: u64,
    pub journal_tail_digest_chirho: DigestChirho,
    pub append_hlc_physical_ms_chirho: u64,
    pub append_hlc_logical_chirho: u32,
    pub durable_term_chirho: u64,
    pub process_generation_chirho: u64,
    pub fence_epoch_chirho: u64,
    pub fence_group_digest_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRegenesisPublicationManifestV1Chirho {
    pub schema_chirho: String,
    pub plan_digest_chirho: String,
    pub packet_digest_chirho: String,
    pub publication_proof_chirho: LedgerRegenesisPublicationProofChirho,
}

pub(crate) struct WrittenLedgerRegenesisPublicationManifestChirho {
    pub(crate) manifest_digest_chirho: String,
    pub(crate) publication_proof_chirho: LedgerRegenesisPublicationProofChirho,
}

pub fn canonical_ledger_regenesis_publication_manifest_chirho(
    manifest_chirho: &LedgerRegenesisPublicationManifestV1Chirho,
) -> LedgerRegenesisResultChirho<Vec<u8>> {
    validate_publication_manifest_chirho(manifest_chirho)?;
    serde_json::to_vec(manifest_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)
}

pub fn parse_canonical_ledger_regenesis_publication_manifest_chirho(
    bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<LedgerRegenesisPublicationManifestV1Chirho> {
    let manifest_chirho: LedgerRegenesisPublicationManifestV1Chirho =
        serde_json::from_slice(bytes_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    if canonical_ledger_regenesis_publication_manifest_chirho(&manifest_chirho)? != bytes_chirho {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    Ok(manifest_chirho)
}

pub fn ledger_regenesis_publication_manifest_digest_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

pub(crate) fn write_staged_publication_manifest_chirho(
    money_stage_chirho: &LedgerRegenesisMoneyStageChirho,
    packet_digest_chirho: &str,
) -> LedgerRegenesisResultChirho<WrittenLedgerRegenesisPublicationManifestChirho> {
    let publication_proof_chirho = verify_staged_resident_chirho(money_stage_chirho)?;
    let manifest_chirho = LedgerRegenesisPublicationManifestV1Chirho {
        schema_chirho: LEDGER_REGENESIS_PUBLICATION_MANIFEST_SCHEMA_V1_CHIRHO.to_owned(),
        plan_digest_chirho: money_stage_chirho.plan_digest_chirho.clone(),
        packet_digest_chirho: packet_digest_chirho.to_owned(),
        publication_proof_chirho: publication_proof_chirho.clone(),
    };
    let manifest_bytes_chirho =
        canonical_ledger_regenesis_publication_manifest_chirho(&manifest_chirho)?;
    let manifest_path_chirho = money_stage_chirho
        .monitor_namespace_root_chirho
        .join(LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO);
    write_new_manifest_durable_chirho(&manifest_path_chirho, &manifest_bytes_chirho)?;
    let (reread_manifest_chirho, manifest_digest_chirho) =
        load_canonical_ledger_regenesis_publication_manifest_chirho(&manifest_path_chirho)?;
    if reread_manifest_chirho != manifest_chirho {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    Ok(WrittenLedgerRegenesisPublicationManifestChirho {
        manifest_digest_chirho,
        publication_proof_chirho,
    })
}

pub(crate) fn verify_staged_publication_manifest_chirho(
    money_stage_chirho: &LedgerRegenesisMoneyStageChirho,
    packet_digest_chirho: &str,
    expected_manifest_digest_chirho: &str,
    expected_publication_proof_chirho: &LedgerRegenesisPublicationProofChirho,
) -> LedgerRegenesisResultChirho<()> {
    let manifest_path_chirho = money_stage_chirho
        .monitor_namespace_root_chirho
        .join(LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO);
    let (manifest_chirho, manifest_digest_chirho) =
        load_canonical_ledger_regenesis_publication_manifest_chirho(&manifest_path_chirho)?;
    if manifest_digest_chirho != expected_manifest_digest_chirho {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    if manifest_chirho.plan_digest_chirho != money_stage_chirho.plan_digest_chirho
        || manifest_chirho.packet_digest_chirho != packet_digest_chirho
        || &manifest_chirho.publication_proof_chirho != expected_publication_proof_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    Ok(())
}

pub fn load_canonical_ledger_regenesis_publication_manifest_chirho(
    path_chirho: &Path,
) -> LedgerRegenesisResultChirho<(LedgerRegenesisPublicationManifestV1Chirho, String)> {
    let bytes_chirho = read_bounded_regular_file_chirho(
        path_chirho,
        MAX_LEDGER_REGENESIS_PUBLICATION_MANIFEST_BYTES_CHIRHO,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let manifest_chirho =
        parse_canonical_ledger_regenesis_publication_manifest_chirho(&bytes_chirho)?;
    let digest_chirho = ledger_regenesis_publication_manifest_digest_chirho(&bytes_chirho);
    Ok((manifest_chirho, digest_chirho))
}

/// Verify one completed, non-live stage without creating or advancing any durable state.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cf6-regenesis-boundary-chirho.md`.
pub(crate) fn verify_staged_resident_chirho(
    money_stage_chirho: &LedgerRegenesisMoneyStageChirho,
) -> LedgerRegenesisResultChirho<LedgerRegenesisPublicationProofChirho> {
    require_final_namespace_absent_chirho(&money_stage_chirho.final_parent_chirho)?;
    let storage_child_chirho =
        child_name_chirho(money_stage_chirho.storage_chirho.namespace_root_chirho())?;
    let monitor_child_chirho =
        child_name_chirho(&money_stage_chirho.monitor_namespace_root_chirho)?;
    let staged_storage_root_chirho = money_stage_chirho
        .staging_parent_chirho
        .join(storage_child_chirho);
    let staged_monitor_root_chirho = money_stage_chirho
        .staging_parent_chirho
        .join(monitor_child_chirho);
    if staged_storage_root_chirho != money_stage_chirho.storage_chirho.namespace_root_chirho()
        || staged_monitor_root_chirho != money_stage_chirho.monitor_namespace_root_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&staged_storage_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let issuer_verify_chirho = PinnedKindIssuerVerifierChirho::from_config_chirho(
        &money_stage_chirho.config_chirho.kind_issuer_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let registry_path_chirho =
        StoragePathChirho::new_chirho(&money_stage_chirho.plan_chirho.kind_registry_path_chirho);
    let registry_ports_chirho = KindRegistryPortsChirho {
        storage_chirho: &storage_chirho,
        registry_root_chirho: money_stage_chirho
            .runtime_signers_chirho
            .kind_root_signer_chirho(),
        issuer_verify_chirho: &issuer_verify_chirho,
    };
    let registry_chirho = load_verified_registry_chirho(
        registry_ports_chirho,
        &registry_path_chirho,
        &money_stage_chirho.plan_chirho.kind_registry_id_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let authority_chirho = PlatformPolicyMintAuthorityChirho::new_chirho(&registry_chirho);
    let membership_chirho = StaticClusterMembershipChirho::from_config_chirho(
        money_stage_chirho.config_chirho.local_epoch_chirho,
        &money_stage_chirho.config_chirho.members_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let clock_chirho = ResidentLedgerClockChirho::reviewed_chirho(
        money_stage_chirho.plan_chirho.mint_physical_ms_chirho,
    );
    let journal_chirho = LedgerJournalChirho::open_read_only_full_chirho(
        JournalPortsChirho {
            storage_chirho: &storage_chirho,
            signer_chirho: money_stage_chirho
                .runtime_signers_chirho
                .journal_signer_chirho(),
            clock_chirho: &clock_chirho,
            membership_chirho: &membership_chirho,
            kind_registry_chirho: &registry_chirho,
            authority_chirho: &authority_chirho,
        },
        StoragePathChirho::new_chirho(&money_stage_chirho.plan_chirho.journal_path_chirho),
        &ClusterIdChirho(money_stage_chirho.plan_chirho.cluster_id_chirho.clone()),
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let activation_receipt_chirho = &money_stage_chirho.activation_receipt_chirho;
    if activation_receipt_chirho.plan_digest_chirho != money_stage_chirho.plan_digest_chirho
        || journal_chirho.tail_seq_chirho() != activation_receipt_chirho.append_seq_chirho
        || journal_chirho.tail_line_digest_chirho()
            != &activation_receipt_chirho.append_record_digest_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    let identity_chirho =
        inspect_resident_writer_identity_chirho(&money_stage_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    if identity_chirho.identity_digest_chirho()
        != activation_receipt_chirho.resident_identity_digest_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    let node_chirho = NodeIdChirho(
        existing_keypair_pubkey_hex_chirho(&money_stage_chirho.selected_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?,
    );
    let group_chirho = consistency_group_for_root_chirho(&money_stage_chirho.selected_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let canary_store_chirho = ShadowCanaryGenerationStoreChirho::open_existing_chirho(
        &staged_monitor_root_chirho.join(H3_CANARY_EVIDENCE_DIR_CHIRHO),
        &money_stage_chirho.selected_root_chirho,
        group_chirho,
        node_chirho,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let current_generation_chirho = canary_store_chirho
        .verify_current_read_only_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    let canary_window_chirho = current_generation_chirho
        .require_generation_zero_window_chirho()
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    if canary_window_chirho.latest_seq_chirho != 1
        || canary_window_chirho.window_len_chirho != 1
        || canary_window_chirho.permit_count_chirho != 1
        || canary_window_chirho.refusal_count_chirho != 0
        || canary_window_chirho.latest_fence_epoch_chirho
            != activation_receipt_chirho.fence_epoch_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .append_seq_chirho
            != activation_receipt_chirho.append_seq_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .append_record_digest_chirho
            .as_str()
            != activation_receipt_chirho
                .append_record_digest_chirho
                .0
                .as_str()
        || canary_window_chirho
            .latest_append_cut_chirho
            .append_hlc_physical_ms_chirho
            != activation_receipt_chirho.append_hlc_physical_ms_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .append_hlc_logical_chirho
            != activation_receipt_chirho.append_hlc_logical_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .process_generation_chirho
            != activation_receipt_chirho.process_generation_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .durable_term_chirho
            != activation_receipt_chirho.durable_term_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .fence_epoch_chirho
            != activation_receipt_chirho.fence_epoch_chirho
        || canary_window_chirho
            .latest_append_cut_chirho
            .fence_group_digest_chirho
            != activation_receipt_chirho.fence_group_digest_chirho
        || canary_window_chirho.latest_evidence_digest_chirho
            != money_stage_chirho.canary_evidence_digest_chirho
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    Ok(LedgerRegenesisPublicationProofChirho {
        activation_authorization_digest_chirho: activation_receipt_chirho
            .authorization_digest_chirho
            .clone(),
        canary_evidence_digest_chirho: canary_window_chirho.latest_evidence_digest_chirho.clone(),
        resident_identity_digest_chirho: identity_chirho.identity_digest_chirho().to_owned(),
        journal_tail_seq_chirho: journal_chirho.tail_seq_chirho(),
        journal_tail_digest_chirho: journal_chirho.tail_line_digest_chirho().clone(),
        append_hlc_physical_ms_chirho: activation_receipt_chirho.append_hlc_physical_ms_chirho,
        append_hlc_logical_chirho: activation_receipt_chirho.append_hlc_logical_chirho,
        durable_term_chirho: activation_receipt_chirho.durable_term_chirho,
        process_generation_chirho: activation_receipt_chirho.process_generation_chirho,
        fence_epoch_chirho: activation_receipt_chirho.fence_epoch_chirho,
        fence_group_digest_chirho: activation_receipt_chirho.fence_group_digest_chirho.clone(),
    })
}

fn require_final_namespace_absent_chirho(path_chirho: &Path) -> LedgerRegenesisResultChirho<()> {
    match fs::symlink_metadata(path_chirho) {
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho),
    }
}

fn child_name_chirho(path_chirho: &Path) -> LedgerRegenesisResultChirho<&str> {
    path_chirho
        .file_name()
        .and_then(|name_chirho| name_chirho.to_str())
        .ok_or(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)
}

fn validate_publication_manifest_chirho(
    manifest_chirho: &LedgerRegenesisPublicationManifestV1Chirho,
) -> LedgerRegenesisResultChirho<()> {
    let proof_chirho = &manifest_chirho.publication_proof_chirho;
    if manifest_chirho.schema_chirho != LEDGER_REGENESIS_PUBLICATION_MANIFEST_SCHEMA_V1_CHIRHO
        || !is_digest_chirho(&manifest_chirho.plan_digest_chirho)
        || !is_digest_chirho(&manifest_chirho.packet_digest_chirho)
        || !is_tagged_digest_chirho(&proof_chirho.activation_authorization_digest_chirho)
        || !is_tagged_digest_chirho(&proof_chirho.canary_evidence_digest_chirho)
        || !is_tagged_digest_chirho(&proof_chirho.resident_identity_digest_chirho)
        || proof_chirho.journal_tail_seq_chirho == 0
        || !is_digest_chirho(&proof_chirho.journal_tail_digest_chirho.0)
        || proof_chirho.append_hlc_physical_ms_chirho == 0
        || proof_chirho.process_generation_chirho == 0
        || proof_chirho.durable_term_chirho == 0
        || proof_chirho.fence_epoch_chirho == 0
        || !is_tagged_digest_chirho(&proof_chirho.fence_group_digest_chirho)
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    Ok(())
}

fn write_new_manifest_durable_chirho(
    manifest_path_chirho: &Path,
    manifest_bytes_chirho: &[u8],
) -> LedgerRegenesisResultChirho<()> {
    if u64::try_from(manifest_bytes_chirho.len())
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?
        > MAX_LEDGER_REGENESIS_PUBLICATION_MANIFEST_BYTES_CHIRHO
    {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    let mut manifest_file_chirho = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(manifest_path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    manifest_file_chirho
        .write_all(manifest_bytes_chirho)
        .and_then(|()| manifest_file_chirho.sync_all())
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?;
    fsync_dir_chirho(
        manifest_path_chirho
            .parent()
            .ok_or(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)?,
    )
    .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho)
}

fn is_digest_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || matches!(byte_chirho, b'a'..=b'f'))
}

fn is_tagged_digest_chirho(value_chirho: &str) -> bool {
    let Some((domain_chirho, digest_chirho)) = value_chirho.rsplit_once(':') else {
        return false;
    };
    !domain_chirho.is_empty()
        && domain_chirho.len() <= 192
        && domain_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_lowercase()
                || byte_chirho.is_ascii_digit()
                || matches!(byte_chirho, b'-' | b'_' | b':' | b'.')
        })
        && is_digest_chirho(digest_chirho)
}
