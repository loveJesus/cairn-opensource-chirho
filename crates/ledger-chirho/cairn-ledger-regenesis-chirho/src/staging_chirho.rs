// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Crash-isolated staging. H3-A can create only a non-live sibling; publication requires the
//! private H3-B completion token, fsyncs the bounded staged tree, performs one no-replace rename,
//! then fsyncs the directory that owns both names.

use crate::completion_chirho::{
    load_canonical_ledger_regenesis_evidence_packet_chirho,
    LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO,
};
use crate::error_chirho::{LedgerRegenesisRefusalChirho, LedgerRegenesisResultChirho};
use crate::money_stage_chirho::LedgerRegenesisMoneyStageChirho;
use crate::plan_chirho::VerifiedLedgerRegenesisPlanChirho;
use crate::publication_verify_chirho::{
    verify_staged_publication_manifest_chirho, verify_staged_resident_chirho,
    LedgerRegenesisPublicationProofChirho,
};
use cairn_durable_chirho::{fsync_dir_chirho, rename_no_replace_chirho};
use cairn_ledger_host_chirho::FsLedgerStorageChirho;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

const MAX_PUBLICATION_TREE_ENTRIES_CHIRHO: u64 = 16_384;
const MAX_PUBLICATION_TREE_DEPTH_CHIRHO: u16 = 32;
const MAX_PUBLICATION_SINGLE_FILE_BYTES_CHIRHO: u64 = 64 * 1024 * 1024;
const MAX_PUBLICATION_TOTAL_FILE_BYTES_CHIRHO: u64 = 512 * 1024 * 1024;
pub(crate) struct BegunLedgerRegenesisStageChirho {
    pub(crate) storage_chirho: FsLedgerStorageChirho,
    pub(crate) monitor_namespace_root_chirho: PathBuf,
}

/// H3-B alone can construct this token after projections, monitor evidence, and the packet exist.
/// Keeping every field private makes publishing an H3-A-only tree impossible outside this crate.
pub struct CompletedLedgerRegenesisStageChirho {
    pub(crate) money_stage_chirho: LedgerRegenesisMoneyStageChirho,
    pub(crate) packet_digest_chirho: String,
    pub(crate) publication_manifest_digest_chirho: String,
    pub(crate) publication_proof_chirho: LedgerRegenesisPublicationProofChirho,
}

/// The path-free publication receipt. Absolute paths and key coordinates never enter evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedLedgerRegenesisStageChirho {
    pub plan_digest_chirho: String,
    pub packet_digest_chirho: String,
    pub publication_manifest_digest_chirho: String,
    pub final_parent_name_chirho: String,
    pub publication_proof_chirho: LedgerRegenesisPublicationProofChirho,
}

pub(crate) fn begin_staging_chirho(
    verified_plan_chirho: &VerifiedLedgerRegenesisPlanChirho,
) -> LedgerRegenesisResultChirho<BegunLedgerRegenesisStageChirho> {
    refuse_if_path_exists_chirho(
        &verified_plan_chirho.final_parent_chirho,
        LedgerRegenesisRefusalChirho::FinalNamespaceExistsChirho,
    )?;
    refuse_if_path_exists_chirho(
        &verified_plan_chirho.staging_parent_chirho,
        LedgerRegenesisRefusalChirho::StagingNamespaceExistsChirho,
    )?;

    fs::create_dir(&verified_plan_chirho.staging_parent_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    fsync_dir_chirho(&verified_plan_chirho.selected_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    let storage_namespace_root_chirho = verified_plan_chirho
        .staging_parent_chirho
        .join(&verified_plan_chirho.storage_child_chirho);
    let monitor_namespace_root_chirho = verified_plan_chirho
        .staging_parent_chirho
        .join(&verified_plan_chirho.monitor_child_chirho);
    fs::create_dir(&storage_namespace_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    fs::create_dir(&monitor_namespace_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    fsync_dir_chirho(&verified_plan_chirho.staging_parent_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    let storage_chirho =
        FsLedgerStorageChirho::open_existing_chirho(&storage_namespace_root_chirho)
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    Ok(BegunLedgerRegenesisStageChirho {
        storage_chirho,
        monitor_namespace_root_chirho,
    })
}

/// Publish one H3-B-complete tree. The recursive file+directory fsync and the post-rename fsync of
/// the selected root are the durable-rename law; a crash before rename leaves only staging, while
/// a successful return makes the final directory entry durable.
pub fn publish_completed_stage_chirho(
    completed_stage_chirho: CompletedLedgerRegenesisStageChirho,
) -> LedgerRegenesisResultChirho<PublishedLedgerRegenesisStageChirho> {
    let money_stage_chirho = completed_stage_chirho.money_stage_chirho;
    refuse_if_path_exists_chirho(
        &money_stage_chirho.final_parent_chirho,
        LedgerRegenesisRefusalChirho::FinalNamespaceExistsChirho,
    )?;
    bounded_recursive_fsync_chirho(&money_stage_chirho.staging_parent_chirho)?;
    let publication_proof_chirho = verify_staged_resident_chirho(&money_stage_chirho)?;
    if publication_proof_chirho != completed_stage_chirho.publication_proof_chirho {
        return Err(LedgerRegenesisRefusalChirho::PublicationProofRefusedChirho);
    }
    let packet_path_chirho = money_stage_chirho
        .monitor_namespace_root_chirho
        .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO);
    let (_packet_chirho, packet_digest_chirho) =
        load_canonical_ledger_regenesis_evidence_packet_chirho(&packet_path_chirho)?;
    if packet_digest_chirho != completed_stage_chirho.packet_digest_chirho {
        return Err(LedgerRegenesisRefusalChirho::EvidencePacketRefusedChirho);
    }
    verify_staged_publication_manifest_chirho(
        &money_stage_chirho,
        &completed_stage_chirho.packet_digest_chirho,
        &completed_stage_chirho.publication_manifest_digest_chirho,
        &publication_proof_chirho,
    )?;
    let final_parent_name_chirho = money_stage_chirho
        .final_parent_chirho
        .file_name()
        .and_then(|name_chirho| name_chirho.to_str())
        .ok_or(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?
        .to_owned();
    let selected_root_chirho = money_stage_chirho.selected_root_chirho.clone();
    no_replace_rename_chirho(
        &money_stage_chirho.staging_parent_chirho,
        &money_stage_chirho.final_parent_chirho,
    )
    .map_err(|error_chirho| {
        if error_chirho.kind() == io::ErrorKind::AlreadyExists {
            LedgerRegenesisRefusalChirho::FinalNamespaceExistsChirho
        } else {
            LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho
        }
    })?;
    fsync_dir_chirho(&selected_root_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    Ok(PublishedLedgerRegenesisStageChirho {
        plan_digest_chirho: money_stage_chirho.plan_digest_chirho,
        packet_digest_chirho: completed_stage_chirho.packet_digest_chirho,
        publication_manifest_digest_chirho: completed_stage_chirho
            .publication_manifest_digest_chirho,
        final_parent_name_chirho,
        publication_proof_chirho,
    })
}

fn refuse_if_path_exists_chirho(
    path_chirho: &Path,
    refusal_chirho: LedgerRegenesisRefusalChirho,
) -> LedgerRegenesisResultChirho<()> {
    match fs::symlink_metadata(path_chirho) {
        Ok(_metadata_chirho) => Err(refusal_chirho),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_error_chirho) => Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho),
    }
}

#[derive(Default)]
struct PublicationTraversalBudgetChirho {
    entries_chirho: u64,
    file_bytes_chirho: u64,
}

pub(crate) fn bounded_recursive_fsync_chirho(
    path_chirho: &Path,
) -> LedgerRegenesisResultChirho<()> {
    let mut budget_chirho = PublicationTraversalBudgetChirho::default();
    bounded_recursive_fsync_at_depth_chirho(path_chirho, 0, &mut budget_chirho)
}

fn bounded_recursive_fsync_at_depth_chirho(
    path_chirho: &Path,
    depth_chirho: u16,
    budget_chirho: &mut PublicationTraversalBudgetChirho,
) -> LedgerRegenesisResultChirho<()> {
    if depth_chirho > MAX_PUBLICATION_TREE_DEPTH_CHIRHO {
        return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
    }
    budget_chirho.entries_chirho = budget_chirho
        .entries_chirho
        .checked_add(1)
        .ok_or(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    if budget_chirho.entries_chirho > MAX_PUBLICATION_TREE_ENTRIES_CHIRHO {
        return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
    }
    let metadata_chirho = fs::symlink_metadata(path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
    if metadata_chirho.file_type().is_symlink() {
        return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
    }
    if metadata_chirho.is_file() {
        if metadata_chirho.len() > MAX_PUBLICATION_SINGLE_FILE_BYTES_CHIRHO {
            return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
        }
        budget_chirho.file_bytes_chirho = budget_chirho
            .file_bytes_chirho
            .checked_add(metadata_chirho.len())
            .ok_or(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
        if budget_chirho.file_bytes_chirho > MAX_PUBLICATION_TOTAL_FILE_BYTES_CHIRHO {
            return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
        }
        return File::open(path_chirho)
            .and_then(|file_chirho| file_chirho.sync_all())
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
    }
    if !metadata_chirho.is_dir() {
        return Err(LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho);
    }
    for entry_chirho in fs::read_dir(path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?
    {
        let entry_chirho = entry_chirho
            .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)?;
        bounded_recursive_fsync_at_depth_chirho(
            &entry_chirho.path(),
            depth_chirho + 1,
            budget_chirho,
        )?;
    }
    fsync_dir_chirho(path_chirho)
        .map_err(|_error_chirho| LedgerRegenesisRefusalChirho::StageFilesystemRefusedChirho)
}

pub(crate) fn no_replace_rename_chirho(from_chirho: &Path, to_chirho: &Path) -> io::Result<()> {
    rename_no_replace_chirho(from_chirho, to_chirho)
}
