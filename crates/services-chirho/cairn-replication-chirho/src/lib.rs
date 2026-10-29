// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 read-only network replication (object plane): a pull-based source port and a receiver that
//! hash-verifies every pulled object before it lands, quarantines a mismatch so it is never served,
//! and — by depending on no ref/head-mutation crate — cannot advance any head.
//!
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cairn-engine-definition-of-done-chirho.md`
//! (rung P3). Transport is a PORT so a local-filesystem adapter is testable now and a CEPH/S3 adapter
//! drops in later. Slice 1 here is the object plane (copied bytes re-hash to their source identities;
//! a corrupted object is quarantined and never served; no transport advances a head). The Gate 1
//! independent-fold / signed-head length-witness plane is P3 slice 2.

use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    verify_content_address_chirho, ContentStoreChirho, StoreErrorChirho, StoreResultChirho,
};
use cairn_model_gate1_chirho::{GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO};

pub mod fold_plane_chirho;
pub mod membership_chirho;
pub mod receiver_chirho;
pub mod ref_snapshot_chirho;
pub mod sync_floor_chirho;

/// Directory under a replica root where objects that FAIL hash verification are parked. Quarantined
/// bytes are addressed by their (wrong) blake3 so distinct corruptions do not overwrite; nothing in
/// here is ever served — the replica's served store never receives a failed object.
pub const REPLICATION_QUARANTINE_DIR_CHIRHO: &str = "replication-quarantine-chirho";

/// The ONLY named logs a replica may pull from a source: the Gate 1 anchor log, the eight Ring-A
/// family logs, and the B2 ref-snapshot log. A source adapter MUST gate `fetch_named_log_chirho`
/// on this allowlist so no signing key, pubkey, private blob, or run-result can leave the writer
/// region by name — the invariant that keys/plaintext never replicate. Raw refs still never
/// cross; the ONE structured exception is `ref-snapshot-log-chirho.jsonl`: a SIGNED, READ-ONLY,
/// app/app-route-restricted snapshot log that transfers no authority (a replica can serve from it
/// but cannot advance anything upstream — see `ref_snapshot_chirho`). This is an allowlist, NOT a
/// path-traversal denylist: the source's private key `signing-key-chirho.bin` is a plain file
/// name with no `/`, `\`, or `..`, so a denylist would happily serve it; only an allowlist of
/// known-public logs is safe.
pub fn is_replicable_log_name_chirho(name_chirho: &str) -> bool {
    name_chirho == GATE1_LOG_ANCHORS_FILE_CHIRHO
        || GATE1_RING_A_ANCHOR_TARGETS_CHIRHO.contains(&name_chirho)
        || name_chirho == ref_snapshot_chirho::REF_SNAPSHOT_LOG_FILE_CHIRHO
}

/// A pull-based, READ-ONLY replication source. It returns immutable object bytes ONLY: no head,
/// key, or private-blob type crosses this boundary, and no raw ref does either — the ONE
/// structured exception is the signed, read-only, app/app-route-restricted ref-snapshot log
/// (`ref_snapshot_chirho`), which transfers no authority: a source can hand a replica nothing
/// that advances a head. A local-filesystem adapter implements this today; a CEPH/S3 or
/// owned-network adapter implements the same trait without widening it (bytes + content
/// addresses only).
pub trait ReplicationSourceChirho {
    /// The content addresses the source offers for pull, in a deterministic order.
    fn list_object_addrs_chirho(&self) -> StoreResultChirho<Vec<HashChirho>>;
    /// Fetch one immutable object by content address; `None` if the source does not have it.
    fn fetch_object_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>>;
    /// Fetch one append-only log file's raw bytes by its relative file name (e.g. the Gate 1 anchor
    /// log or a Ring-A family log); `None` if the source does not have it. Read-only: the name is a
    /// plain file name, never a path, and the source cannot be asked to write.
    fn fetch_named_log_chirho(&self, name_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>>;
}

/// One object's outcome in a pull.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectReceiptChirho {
    /// Bytes re-hashed to the requested address and were stored in the served replica store.
    StoredChirho { addr_chirho: HashChirho },
    /// Bytes did NOT re-hash to the requested address; parked in quarantine, never served.
    QuarantinedChirho {
        requested_chirho: HashChirho,
        actual_chirho: HashChirho,
    },
    /// The source did not offer bytes for an address it listed (or a concurrent removal).
    MissingChirho { addr_chirho: HashChirho },
}

/// The evidence a pull produces: schema-tagged, counts only (no paths, no bytes) so it is safe to
/// print or persist as operator evidence.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplicaPullReportChirho {
    pub schema_chirho: String,
    pub listed_chirho: u64,
    pub stored_chirho: u64,
    pub quarantined_chirho: u64,
    pub missing_chirho: u64,
}

pub const REPLICA_PULL_REPORT_SCHEMA_CHIRHO: &str = "replica-pull-report-v1-chirho";

/// A quarantine sink for objects that fail hash verification. The receiver never lets a failed
/// object reach the served store; it hands the raw bytes here instead.
pub trait QuarantineSinkChirho {
    /// Park bytes that failed verification. `actual_chirho` is their true blake3 (the address they
    /// were requested under is the lie). Idempotent by `actual_chirho`.
    fn quarantine_chirho(
        &self,
        requested_chirho: &HashChirho,
        actual_chirho: &HashChirho,
        bytes_chirho: &[u8],
    ) -> StoreResultChirho<()>;
}

/// Pull every object the source lists into the replica's served store, verifying each object's
/// content address BEFORE it is stored. A byte that does not re-hash to its requested address is
/// quarantined (never served); a missing object is recorded. The served `sink_chirho` only ever
/// receives verified bytes, so a corrupted or substituted object cannot be served.
///
/// This function takes only a source, a served `ContentStoreChirho`, and a `QuarantineSinkChirho` —
/// it has no way to reach a ref, head, or key, so replication cannot advance authority.
pub fn receive_objects_chirho<S, C, Q>(
    source_chirho: &S,
    served_chirho: &C,
    quarantine_chirho: &Q,
) -> StoreResultChirho<(ReplicaPullReportChirho, Vec<ObjectReceiptChirho>)>
where
    S: ReplicationSourceChirho + ?Sized,
    C: ContentStoreChirho + ?Sized,
    Q: QuarantineSinkChirho + ?Sized,
{
    let addrs_chirho = source_chirho.list_object_addrs_chirho()?;
    let mut receipts_chirho = Vec::with_capacity(addrs_chirho.len());
    let mut stored_chirho = 0u64;
    let mut quarantined_chirho = 0u64;
    let mut missing_chirho = 0u64;
    for addr_chirho in &addrs_chirho {
        let Some(bytes_chirho) = source_chirho.fetch_object_chirho(addr_chirho)? else {
            missing_chirho += 1;
            receipts_chirho.push(ObjectReceiptChirho::MissingChirho {
                addr_chirho: addr_chirho.clone(),
            });
            continue;
        };
        // Verify BEFORE any write to the served store, so a corrupt object never lands.
        match verify_content_address_chirho(addr_chirho, &bytes_chirho) {
            Ok(()) => {
                let stored_addr_chirho = served_chirho.put_chirho(&bytes_chirho)?;
                if &stored_addr_chirho != addr_chirho {
                    // The served store is content-addressed; a divergence here is itself a
                    // tamper/adapter fault. Fail closed rather than serve an unexpected address.
                    return Err(StoreErrorChirho::invalid_chirho(format!(
                        "served store returned address {} for verified object {}",
                        stored_addr_chirho.0, addr_chirho.0
                    )));
                }
                stored_chirho += 1;
                receipts_chirho.push(ObjectReceiptChirho::StoredChirho {
                    addr_chirho: addr_chirho.clone(),
                });
            }
            Err(_) => {
                let actual_chirho = HashChirho(blake3::hash(&bytes_chirho).to_hex().to_string());
                quarantine_chirho.quarantine_chirho(addr_chirho, &actual_chirho, &bytes_chirho)?;
                quarantined_chirho += 1;
                receipts_chirho.push(ObjectReceiptChirho::QuarantinedChirho {
                    requested_chirho: addr_chirho.clone(),
                    actual_chirho,
                });
            }
        }
    }
    let report_chirho = ReplicaPullReportChirho {
        schema_chirho: REPLICA_PULL_REPORT_SCHEMA_CHIRHO.to_string(),
        listed_chirho: addrs_chirho.len() as u64,
        stored_chirho,
        quarantined_chirho,
        missing_chirho,
    };
    Ok((report_chirho, receipts_chirho))
}
