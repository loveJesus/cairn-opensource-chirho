// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 replica receiver: the read-only flow that ties the pieces together. It (1) verifies the D3
//! roster against the pinned operator key and confirms the source is an active member, (2) pulls and
//! hash-verifies every object into the served store (quarantining mismatches), (3) copies the Gate 1
//! anchor log and the Ring-A family logs verbatim, then (4) verifies the copied authority state
//! against the source's signed head and independently reproduces the four Ring-A CLSD digests. It
//! moves no head — it depends on no head-mutation crate — and if the fold verify fails it returns the
//! error so the caller never treats an unverified replica as authoritative.

use crate::fold_plane_chirho::{verify_replicated_authority_fold_chirho, VerifiedFoldReportChirho};
use crate::membership_chirho::verify_membership_roster_lines_chirho;
use crate::{
    receive_objects_chirho, ContentStoreChirho, QuarantineSinkChirho, ReplicaPullReportChirho,
    ReplicationSourceChirho,
};
use anyhow::{anyhow, bail, Result};
use cairn_model_gate1_chirho::{GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO};
use std::path::Path;

/// The combined evidence of a full replica sync: the object pull, the log copy, and the verified
/// authority fold. Counts and a region label only — no paths or bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaSyncReportChirho {
    pub schema_chirho: String,
    pub source_region_chirho: String,
    pub logs_copied_chirho: u64,
    pub object_pull_chirho: ReplicaPullReportChirho,
    pub verified_fold_chirho: VerifiedFoldReportChirho,
}

pub const REPLICA_SYNC_REPORT_SCHEMA_CHIRHO: &str = "replica-sync-report-v1-chirho";

/// Run a full read-only replica sync and return combined verified evidence, or fail closed. The
/// `head_bytes_chirho` (the source's signed anchor head) and the roster are operator-supplied trust
/// inputs; the bulk objects and logs come over the transport and are all verified against them.
/// `min_anchor_record_count_chirho` is the caller's anti-rollback floor (its last-verified anchor
/// count, or `None` on a first sync) — a stale-but-validly-signed earlier head is rejected below it.
#[allow(clippy::too_many_arguments)]
pub fn receive_and_verify_replica_chirho<S, C, Q>(
    source_chirho: &S,
    served_chirho: &C,
    quarantine_chirho: &Q,
    replica_root_chirho: &Path,
    roster_lines_chirho: &[Vec<u8>],
    operator_pubkey_hex_chirho: &str,
    source_pubkey_hex_chirho: &str,
    head_bytes_chirho: &[u8],
    min_anchor_record_count_chirho: Option<u64>,
) -> Result<ReplicaSyncReportChirho>
where
    S: ReplicationSourceChirho + ?Sized,
    C: ContentStoreChirho + ?Sized,
    Q: QuarantineSinkChirho + ?Sized,
{
    // 1. The D3 roster, verified against the pinned operator key, must currently list the source.
    let membership_chirho =
        verify_membership_roster_lines_chirho(roster_lines_chirho, operator_pubkey_hex_chirho)?;
    if !membership_chirho.is_active_source_chirho(source_pubkey_hex_chirho) {
        bail!("replication source is not an active member of the operator-signed roster");
    }
    let source_region_chirho = membership_chirho
        .region_of_chirho(source_pubkey_hex_chirho)
        .unwrap_or("")
        .to_string();

    // 2. Pull + hash-verify objects into the served store (mismatches quarantined, never served).
    let (object_pull_chirho, _receipts_chirho) =
        receive_objects_chirho(source_chirho, served_chirho, quarantine_chirho)?;

    // 3. Copy the anchor log and the Ring-A family logs verbatim into the replica root, so the fold
    // reads byte-identical bytes. Copy is untrusted; step 4 verifies it.
    let mut logs_copied_chirho = 0u64;
    let mut names_chirho: Vec<&str> = vec![GATE1_LOG_ANCHORS_FILE_CHIRHO];
    names_chirho.extend_from_slice(&GATE1_RING_A_ANCHOR_TARGETS_CHIRHO);
    for name_chirho in names_chirho {
        if let Some(bytes_chirho) = source_chirho.fetch_named_log_chirho(name_chirho)? {
            let dest_chirho = replica_root_chirho.join(name_chirho);
            std::fs::write(&dest_chirho, &bytes_chirho).map_err(|e_chirho| {
                anyhow!("write replica log {}: {e_chirho}", dest_chirho.display())
            })?;
            logs_copied_chirho += 1;
        }
    }

    // 4. Verify the copied authority state against the source-signed head and reproduce the digests.
    let verified_fold_chirho = verify_replicated_authority_fold_chirho(
        replica_root_chirho,
        head_bytes_chirho,
        source_pubkey_hex_chirho,
        min_anchor_record_count_chirho,
    )?;

    Ok(ReplicaSyncReportChirho {
        schema_chirho: REPLICA_SYNC_REPORT_SCHEMA_CHIRHO.to_string(),
        source_region_chirho,
        logs_copied_chirho,
        object_pull_chirho,
        verified_fold_chirho,
    })
}
