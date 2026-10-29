// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Bounded content-addressed move-stage records outside the carried payload CAS.
//!
//! The public resolver re-hashes and re-verifies every record. The writer is crate-private, accepts
//! only [`VerifiedMoveControlRecordChirho`], and has no namespace argument: unknown bytes cannot be
//! routed here by choosing a path. The five move stages are closed grammar, so each active move shard
//! admits at most five complete signed records and never scans sibling move history. The writer's
//! per-move named lock makes the count check and publication one operation. Tenant-stage callers take
//! their stage lock first and this control lock second; no control-store path acquires the stage lock.

use cairn_durable_chirho::content_addressed_namespace_chirho::{
    list_content_addressed_namespace_files_chirho,
    publish_content_addressed_namespace_file_no_replace_chirho,
    read_content_addressed_namespace_file_chirho, ContentAddressedNamespaceErrorKindChirho,
};
use cairn_tenant_chirho::move_chirho::move_attestation_chirho::{
    verify_move_control_record_chirho, MoveAuthorityPortChirho, MoveStageAttestationChirho,
    VerifiedMoveControlRecordChirho,
};
use cairn_tenant_chirho::surface_disposition_chirho::TENANT_MOVE_CONTROL_SURFACE_CHIRHO;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;

pub const MOVE_CONTROL_STAGE_RECORDS_DIR_CHIRHO: &str = "stage-records-chirho";
pub const MOVE_CONTROL_STAGE_RECORD_MAX_BYTES_CHIRHO: usize = 32 * 1024;
pub const MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO: usize = 5;
const MOVE_CONTROL_WRITE_LOCK_PREFIX_CHIRHO: &str = "tenant-root-move-control-write-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoveControlStoreRefusalChirho {
    EncodeChirho,
    DecodeChirho,
    UnavailableChirho,
    BoundExceededChirho,
    CorruptObjectChirho,
    NotFoundChirho,
    NotVerifiedChirho,
    RecordSetMismatchChirho {
        expected_count_chirho: usize,
        found_count_chirho: usize,
    },
}

/// Persist a complete signed stage record that has already passed authority verification.
///
/// Crate-private by design. Callers outside this store can resolve or verify control evidence but
/// cannot acquire a general control-namespace writer.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub(super) fn store_verified_move_control_record_chirho(
    root_chirho: &Path,
    verified_record_chirho: &VerifiedMoveControlRecordChirho,
) -> Result<(), MoveControlStoreRefusalChirho> {
    let move_id_chirho = verified_record_chirho
        .verified_stage_chirho()
        .move_id_chirho();
    let lock_name_chirho = format!(
        "{MOVE_CONTROL_WRITE_LOCK_PREFIX_CHIRHO}-{}",
        move_digest_chirho(move_id_chirho)
    );
    cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho(
        root_chirho,
        &lock_name_chirho,
        || {
            Ok(store_verified_move_control_record_unlocked_chirho(
                root_chirho,
                verified_record_chirho,
            ))
        },
    )
    .map_err(|_error_chirho| MoveControlStoreRefusalChirho::UnavailableChirho)?
}

fn store_verified_move_control_record_unlocked_chirho(
    root_chirho: &Path,
    verified_record_chirho: &VerifiedMoveControlRecordChirho,
) -> Result<(), MoveControlStoreRefusalChirho> {
    let move_id_chirho = verified_record_chirho
        .verified_stage_chirho()
        .move_id_chirho();
    let existing_chirho = list_record_addresses_chirho(root_chirho, move_id_chirho)?;
    if !existing_chirho
        .iter()
        .any(|digest_chirho| digest_chirho == verified_record_chirho.record_digest_chirho())
        && existing_chirho.len() == MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO
    {
        return Err(MoveControlStoreRefusalChirho::BoundExceededChirho);
    }
    let bytes_chirho = serde_json::to_vec(verified_record_chirho.record_chirho())
        .map_err(|_error_chirho| MoveControlStoreRefusalChirho::EncodeChirho)?;
    with_record_components_chirho(move_id_chirho, |components_chirho| {
        publish_content_addressed_namespace_file_no_replace_chirho(
            root_chirho,
            components_chirho,
            verified_record_chirho.record_digest_chirho(),
            &bytes_chirho,
            MOVE_CONTROL_STAGE_RECORD_MAX_BYTES_CHIRHO,
        )
        .map_err(map_namespace_error_chirho)
    })
}

/// Resolve, re-hash, decode, and authority-verify one complete signed stage record.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn resolve_move_control_record_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    record_digest_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<VerifiedMoveControlRecordChirho, MoveControlStoreRefusalChirho> {
    let bytes_chirho = with_record_components_chirho(move_id_chirho, |components_chirho| {
        read_content_addressed_namespace_file_chirho(
            root_chirho,
            components_chirho,
            record_digest_chirho,
            MOVE_CONTROL_STAGE_RECORD_MAX_BYTES_CHIRHO,
        )
        .map_err(map_namespace_error_chirho)
    })?
    .ok_or(MoveControlStoreRefusalChirho::NotFoundChirho)?;
    let record_chirho: MoveStageAttestationChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| MoveControlStoreRefusalChirho::DecodeChirho)?;
    let verified_chirho =
        verify_move_control_record_chirho(&record_chirho, authority_chirho, move_id_chirho)
            .map_err(|_error_chirho| MoveControlStoreRefusalChirho::NotVerifiedChirho)?;
    if verified_chirho.record_digest_chirho() != record_digest_chirho {
        return Err(MoveControlStoreRefusalChirho::CorruptObjectChirho);
    }
    Ok(verified_chirho)
}

/// Require the active move shard to contain exactly the expected complete signed records.
///
/// This is the closed-grammar verifier. It rejects both a missing referenced record and an orphan
/// record left by a conflicting retry, then resolves every expected address through the typed
/// verifier rather than treating filename equality as evidence.
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn verify_move_control_record_set_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    expected_record_digests_chirho: &BTreeSet<String>,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<Vec<VerifiedMoveControlRecordChirho>, MoveControlStoreRefusalChirho> {
    if expected_record_digests_chirho.len() > MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO {
        return Err(MoveControlStoreRefusalChirho::BoundExceededChirho);
    }
    let found_chirho = list_record_addresses_chirho(root_chirho, move_id_chirho)?;
    let expected_chirho: Vec<&str> = expected_record_digests_chirho
        .iter()
        .map(String::as_str)
        .collect();
    if found_chirho
        .iter()
        .map(String::as_str)
        .ne(expected_chirho.iter().copied())
    {
        return Err(MoveControlStoreRefusalChirho::RecordSetMismatchChirho {
            expected_count_chirho: expected_record_digests_chirho.len(),
            found_count_chirho: found_chirho.len(),
        });
    }
    expected_record_digests_chirho
        .iter()
        .map(|digest_chirho| {
            resolve_move_control_record_chirho(
                root_chirho,
                move_id_chirho,
                digest_chirho,
                authority_chirho,
            )
        })
        .collect()
}

/// Load every record from exactly one bounded active-move shard through hash and authority checks.
///
/// Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/tenant-migration-chirho/authority-contract-chirho.md`
/// under "Isolated Signed Stage Log Substrate".
pub fn load_bounded_move_control_records_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
    authority_chirho: &dyn MoveAuthorityPortChirho,
) -> Result<Vec<VerifiedMoveControlRecordChirho>, MoveControlStoreRefusalChirho> {
    list_record_addresses_chirho(root_chirho, move_id_chirho)?
        .iter()
        .map(|digest_chirho| {
            resolve_move_control_record_chirho(
                root_chirho,
                move_id_chirho,
                digest_chirho,
                authority_chirho,
            )
        })
        .collect()
}

pub(super) fn list_record_addresses_chirho(
    root_chirho: &Path,
    move_id_chirho: &str,
) -> Result<Vec<String>, MoveControlStoreRefusalChirho> {
    with_record_components_chirho(move_id_chirho, |components_chirho| {
        list_content_addressed_namespace_files_chirho(
            root_chirho,
            components_chirho,
            MOVE_CONTROL_STAGE_RECORD_MAX_COUNT_CHIRHO,
        )
        .map_err(map_namespace_error_chirho)
    })
}

fn with_record_components_chirho<ValueChirho>(
    move_id_chirho: &str,
    operation_chirho: impl FnOnce(&[&str]) -> ValueChirho,
) -> ValueChirho {
    let move_digest_chirho = move_digest_chirho(move_id_chirho);
    let components_chirho = [
        TENANT_MOVE_CONTROL_SURFACE_CHIRHO,
        &move_digest_chirho[..2],
        &move_digest_chirho[2..],
        MOVE_CONTROL_STAGE_RECORDS_DIR_CHIRHO,
    ];
    operation_chirho(&components_chirho)
}

fn move_digest_chirho(move_id_chirho: &str) -> String {
    blake3::hash(move_id_chirho.as_bytes()).to_hex().to_string()
}

fn map_namespace_error_chirho(
    error_chirho: cairn_durable_chirho::content_addressed_namespace_chirho::ContentAddressedNamespaceErrorChirho,
) -> MoveControlStoreRefusalChirho {
    match error_chirho.kind_chirho() {
        ContentAddressedNamespaceErrorKindChirho::InvalidCoordinateChirho
        | ContentAddressedNamespaceErrorKindChirho::CorruptObjectChirho => {
            MoveControlStoreRefusalChirho::CorruptObjectChirho
        }
        ContentAddressedNamespaceErrorKindChirho::BoundExceededChirho => {
            MoveControlStoreRefusalChirho::BoundExceededChirho
        }
        ContentAddressedNamespaceErrorKindChirho::UnavailableChirho => {
            MoveControlStoreRefusalChirho::UnavailableChirho
        }
    }
}

#[cfg(test)]
#[path = "move_control_store_tests_chirho.rs"]
mod move_control_store_tests_chirho;
