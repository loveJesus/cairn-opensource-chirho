// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Reads a root's control-plane law evidence (its era, its genesis marker and its law marker) and
//! publishes the law marker, so the signer crate's pure selector can choose which key the root's
//! control-plane records carry.
//!
//! Every probe treats only "not found" as absent. Any other failure refuses, because an unreadable
//! marker is not evidence that the root is not geo: reading it as absent would select the node key on a
//! geo root. The law marker is read as a bounded regular file and parsed strictly. Its publication is
//! create-new and durable: bytes synced under a temp name, an atomic no-replace rename, and a directory
//! barrier, including on an equal replay, because an earlier crashed publication can be visible without
//! being durable (gpt #29485).
//!
//! Design: `spec-chirho/workstream-state-chirho/c2-durability-chirho/brick1-control-plane-signer-design-chirho.md`
//! (C2.1 brick 1a-ii).

use crate::writer_head_chirho::{writer_authority_era_chirho, WriterAuthorityEraChirho};
use anyhow::{bail, Context, Result};
use cairn_durable_chirho::{
    create_complete_file_durable_with_mode_chirho, fsync_dir_chirho, CreateFileDurableOutcomeChirho,
};
use cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho;
use cairn_signer_chirho::control_plane_signer_chirho::{
    ControlPlaneEvidenceChirho, ControlPlaneLawMarkerChirho, ControlPlaneLineageChirho,
    ControlPlanePinChirho,
};
use cairn_tenant_chirho::tenant_chirho::{
    CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO, GEO_GENESIS_GUARD_DIR_CHIRHO,
};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read};
use std::path::Path;

/// The schema tag every law marker carries.
pub const CONTROL_PLANE_LAW_MARKER_SCHEMA_CHIRHO: &str = "control-plane-law-marker-v1-chirho";

/// The named lock that orders the marker's publication. C2.1 brick 1b's family appends take it before
/// their own append lock, so a law re-checked at commit cannot race a marker being published.
pub const CONTROL_PLANE_LAW_LOCK_CHIRHO: &str = "control-plane-law-chirho";

/// The largest law marker a reader accepts, in bytes.
const CONTROL_PLANE_LAW_MARKER_MAX_BYTES_CHIRHO: u64 = 4096;

/// The marker's mode: world-readable, because it names only a public key id and a lineage.
const CONTROL_PLANE_LAW_MARKER_MODE_CHIRHO: u32 = 0o644;

/// The law marker's on-disk record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlPlaneLawMarkerRecordChirho {
    schema_chirho: String,
    key_id_hex_chirho: String,
    tenant_id_chirho: String,
    genesis_instance_id_chirho: String,
}

/// Read a root's control-plane law evidence, refusing on any read failure other than "not found".
pub fn read_control_plane_evidence_chirho(
    root_chirho: &Path,
) -> Result<ControlPlaneEvidenceChirho> {
    let era_elected_chirho = writer_authority_era_chirho(root_chirho)
        .context("ControlPlaneEvidenceEraUnreadableChirho")?
        == WriterAuthorityEraChirho::ElectedChirho;
    let genesis_marker_present_chirho =
        root_entry_present_chirho(&root_chirho.join(GEO_GENESIS_GUARD_DIR_CHIRHO))?;
    let law_marker_chirho = read_control_plane_law_marker_chirho(root_chirho)?;
    Ok(ControlPlaneEvidenceChirho {
        era_elected_chirho,
        genesis_marker_present_chirho,
        law_marker_chirho,
    })
}

/// Any entry at the path counts as present, whatever its type. Only "not found" is absent.
fn root_entry_present_chirho(path_chirho: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path_chirho) {
        Ok(_) => Ok(true),
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => bail!("ControlPlaneEvidenceUnreadableChirho"),
    }
}

/// Read the root's law marker. Absent only on "not found". A present marker must be a regular file of
/// at most 4 KiB whose record parses strictly, with a canonical key id and a valid lineage; anything else
/// refuses.
pub fn read_control_plane_law_marker_chirho(
    root_chirho: &Path,
) -> Result<Option<ControlPlaneLawMarkerChirho>> {
    let path_chirho = root_chirho.join(CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO);
    let metadata_chirho = match std::fs::symlink_metadata(&path_chirho) {
        Ok(metadata_chirho) => metadata_chirho,
        Err(error_chirho) if error_chirho.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("ControlPlaneLawMarkerUnreadableChirho"),
    };
    if !metadata_chirho.file_type().is_file() {
        bail!("ControlPlaneLawMarkerNotRegularFileChirho");
    }
    if metadata_chirho.len() > CONTROL_PLANE_LAW_MARKER_MAX_BYTES_CHIRHO {
        bail!("ControlPlaneLawMarkerTooLargeChirho");
    }
    let file_chirho = open_no_follow_chirho(&path_chirho)?;
    let mut bytes_chirho = Vec::new();
    file_chirho
        .take(CONTROL_PLANE_LAW_MARKER_MAX_BYTES_CHIRHO + 1)
        .read_to_end(&mut bytes_chirho)
        .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerUnreadableChirho"))?;
    if bytes_chirho.len() as u64 > CONTROL_PLANE_LAW_MARKER_MAX_BYTES_CHIRHO {
        bail!("ControlPlaneLawMarkerTooLargeChirho");
    }
    let record_chirho: ControlPlaneLawMarkerRecordChirho = serde_json::from_slice(&bytes_chirho)
        .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerMalformedChirho"))?;
    if record_chirho.schema_chirho != CONTROL_PLANE_LAW_MARKER_SCHEMA_CHIRHO {
        bail!("ControlPlaneLawMarkerSchemaChirho");
    }
    let pin_chirho = ControlPlanePinChirho::from_hex_chirho(&record_chirho.key_id_hex_chirho)
        .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerKeyIdChirho"))?;
    let lineage_chirho = ControlPlaneLineageChirho::new_chirho(
        &record_chirho.tenant_id_chirho,
        &record_chirho.genesis_instance_id_chirho,
    )
    .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerLineageChirho"))?;
    Ok(Some(ControlPlaneLawMarkerChirho {
        key_id_hex_chirho: pin_chirho.key_id_hex_chirho(),
        lineage_chirho,
    }))
}

/// Proof that this thread holds the root's control-plane law lock. Only [`with_law_lock_chirho`] makes
/// one, so the unlocked marker publication cannot be reached without the lock (gpt #29602, C2.1 1b-1a).
pub(crate) struct LawLockHeldChirho {
    _held_chirho: (),
}

/// Run `action_chirho` holding the root's law lock, handing it the proof.
pub(crate) fn with_law_lock_chirho<T>(
    root_chirho: &Path,
    action_chirho: impl FnOnce(&LawLockHeldChirho) -> Result<T>,
) -> Result<T> {
    with_named_lock_chirho(root_chirho, CONTROL_PLANE_LAW_LOCK_CHIRHO, || {
        action_chirho(&LawLockHeldChirho { _held_chirho: () })
    })
}

/// Publish the root's law marker, create-new and durable, under the law lock.
///
/// A marker already present must be EQUAL to this one, or publication refuses
/// (`ControlPlaneLawMarkerMismatchChirho`). An equal replay still runs a directory barrier, since the
/// earlier publication may have crashed after its rename and before its own barrier.
pub fn publish_control_plane_law_marker_chirho(
    root_chirho: &Path,
    marker_chirho: &ControlPlaneLawMarkerChirho,
) -> Result<()> {
    with_law_lock_chirho(root_chirho, |held_chirho| {
        publish_control_plane_law_marker_unlocked_chirho(root_chirho, marker_chirho, held_chirho)
    })
}

/// The publication itself, for a caller already inside the law lock: the root handle's write scope, whose
/// first lineage signing publishes the marker before the row it signs (C2.1 1b-1a).
pub(crate) fn publish_control_plane_law_marker_unlocked_chirho(
    root_chirho: &Path,
    marker_chirho: &ControlPlaneLawMarkerChirho,
    _held_chirho: &LawLockHeldChirho,
) -> Result<()> {
    {
        let path_chirho = root_chirho.join(CONTROL_PLANE_LAW_MARKER_FILE_CHIRHO);
        let record_chirho = ControlPlaneLawMarkerRecordChirho {
            schema_chirho: CONTROL_PLANE_LAW_MARKER_SCHEMA_CHIRHO.to_string(),
            key_id_hex_chirho: marker_chirho.key_id_hex_chirho.clone(),
            tenant_id_chirho: marker_chirho.lineage_chirho.tenant_id_chirho().to_string(),
            genesis_instance_id_chirho: marker_chirho
                .lineage_chirho
                .genesis_instance_id_chirho()
                .to_string(),
        };
        let mut bytes_chirho = serde_json::to_vec(&record_chirho)?;
        bytes_chirho.push(b'\n');
        match create_complete_file_durable_with_mode_chirho(
            &path_chirho,
            &bytes_chirho,
            CONTROL_PLANE_LAW_MARKER_MODE_CHIRHO,
        )
        .context("ControlPlaneLawMarkerPublishFailedChirho")?
        {
            CreateFileDurableOutcomeChirho::CreatedChirho => Ok(()),
            CreateFileDurableOutcomeChirho::AlreadyExistsChirho => {
                let existing_chirho = read_control_plane_law_marker_chirho(root_chirho)?
                    .ok_or_else(|| anyhow::anyhow!("ControlPlaneLawMarkerVanishedChirho"))?;
                if existing_chirho != *marker_chirho {
                    bail!("ControlPlaneLawMarkerMismatchChirho");
                }
                law_marker_directory_barrier_chirho(root_chirho)
                    .context("ControlPlaneLawMarkerPublishFailedChirho")
            }
        }
    }
}

/// The equal-replay directory barrier, counted in tests so its deletion is visible. Tests can also make
/// it fail, to show a failed barrier refuses the signing that relies on it (gpt #29775).
fn law_marker_directory_barrier_chirho(root_chirho: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    tests_chirho::note_replay_barrier_chirho();
    #[cfg(test)]
    if tests_chirho::take_replay_barrier_failure_chirho() {
        return Err(std::io::Error::other("injected replay barrier failure"));
    }
    fsync_dir_chirho(root_chirho)
}

#[cfg(unix)]
fn open_no_follow_chirho(path_chirho: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path_chirho)
        .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerUnreadableChirho"))
}

#[cfg(not(unix))]
fn open_no_follow_chirho(path_chirho: &Path) -> Result<std::fs::File> {
    std::fs::File::open(path_chirho)
        .map_err(|_| anyhow::anyhow!("ControlPlaneLawMarkerUnreadableChirho"))
}

#[cfg(test)]
#[path = "control_plane_evidence_chirho/tests_chirho.rs"]
pub(crate) mod tests_chirho;
