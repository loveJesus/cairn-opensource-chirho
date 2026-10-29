// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable home for registrar-signed node capacity grants — and the replay protection the pure verifier
//! deliberately does not provide.
//!
//! [`cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho`] verifies ONE record and says
//! so in capitals: verification is stateless, so a correctly signed OLD grant verifies exactly like a new
//! one, and replay protection needs durable state kept by the caller. **This module is that caller.** It
//! keeps the highest `registration_seq_chirho` seen per node and refuses anything at or below it.
//!
//! **Why the intent goes in CAS and only the record goes in the log.** The log is a declared surface, so
//! `verify_tenant_self_containment_chirho` scans it for 64-hex tokens and requires each to resolve as a
//! CAS object in this root — there is no exclusion list. A record carrying a bare `intent_digest_chirho`
//! would therefore report a dangling reference and refuse migration. That constraint is satisfied rather
//! than worked around, because of how the digest is defined:
//!
//! ```text
//! hash_object_chirho(v) == cas_chirho::hash_chirho(serde_json::to_vec(v))
//! put_object_chirho(root, &v) stores those bytes AT hash_object_chirho(v)
//! ```
//!
//! So storing the intent with `put_object_chirho` puts it at an address EQUAL to the digest the record
//! already names. The reference resolves, self-containment passes, and the record stays small because the
//! intent is referenced rather than inlined.
//!
//! Reads go through `cairn-durable-chirho`'s identity-stable bounded primitive, and appends through its
//! crash-safe line append. Neither is re-implemented here.

use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_placement_chirho::capacity_chirho::capacity_attestation_chirho::{
    verify_node_capacity_attestation_chirho, NodeCapacityAttestationChirho,
    NodeRegistrationAuthorityPortChirho, VerifiedNodeCapacityChirho,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The declared log surface. Registered in `static_surface_manifest_chirho`, which makes it a declared
/// LOG surface and therefore `CarriedWithTheRootChirho` by disposition automatically.
pub const NODE_CAPACITY_ATTESTATION_LOG_CHIRHO: &str = "node-capacity-attestations-chirho.jsonl";

/// One grant is small by construction; the whole log is bounded so a corrupt or hostile file cannot
/// become an unbounded allocation.
pub const NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

/// Why a durable capacity-grant operation was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CapacityAttestationStoreRefusalChirho {
    /// The log could not be read or written for an I/O reason.
    StoreUnavailableChirho,
    /// The log path is not one identity-stable single-link bounded regular file: hard-linked, or
    /// replaced or grown between the stat, the open and the read. Distinct from an I/O failure.
    StoreIdentityUnstableChirho,
    /// A line in the log is not a decodable attestation record.
    DecodeChirho { line_chirho: u64 },
    /// The intent could not be written to CAS, so its digest would not resolve.
    IntentNotStoredChirho,
    /// The record's declared digest is not the CAS address its intent actually landed at. A record whose
    /// digest does not match its own stored intent would leave a dangling reference in a declared log.
    IntentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
    /// REPLAY: a grant at or below the highest sequence already recorded for this node.
    ///
    /// This is the protection the pure verifier documents as the caller's, and it is why this module
    /// exists rather than callers each keeping their own high-water mark.
    ReplayedRegistrationChirho {
        node_id_chirho: String,
        offered_chirho: u64,
        highest_recorded_chirho: u64,
    },
    /// No grant on record for the node asked about.
    NoGrantForNodeChirho { node_id_chirho: String },
}

fn log_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO)
}

/// Every record currently in the log, in append order, decoded but NOT yet verified.
///
/// Separated from verification on purpose: the caller decides which authority to verify against, and a
/// decode failure is a different refusal from a signature failure.
fn read_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<NodeCapacityAttestationChirho>, CapacityAttestationStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::InvalidData => {
            CapacityAttestationStoreRefusalChirho::StoreIdentityUnstableChirho
        }
        _ => CapacityAttestationStoreRefusalChirho::StoreUnavailableChirho,
    })?;
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        let record_chirho = serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            CapacityAttestationStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?;
        records_chirho.push(record_chirho);
    }
    Ok(records_chirho)
}

/// The highest registration sequence already recorded for one node, if any.
pub fn highest_recorded_sequence_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
) -> Result<Option<u64>, CapacityAttestationStoreRefusalChirho> {
    Ok(read_records_chirho(root_chirho)?
        .iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        .map(|record_chirho| record_chirho.intent_chirho.registration_seq_chirho)
        .max())
}

/// Append one registrar-signed grant, after verifying it AND refusing a replay.
///
/// Order matters and is the contract: verify the signature first (an unsigned record must not move the
/// high-water mark), then refuse a replayed sequence, then store the intent in CAS, then append. The
/// append is last so a failure anywhere earlier leaves the log untouched.
pub fn append_verified_capacity_attestation_chirho(
    root_chirho: &Path,
    record_chirho: &NodeCapacityAttestationChirho,
    authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
) -> Result<VerifiedNodeCapacityChirho, CapacityAttestationStoreRefusalChirho> {
    let node_id_chirho = record_chirho.intent_chirho.node_id_chirho.clone();
    let verified_chirho =
        verify_node_capacity_attestation_chirho(record_chirho, authority_chirho, &node_id_chirho)
            .map_err(|_error_chirho| {
            // A record that does not verify is not a store problem and must not touch the log.
            CapacityAttestationStoreRefusalChirho::DecodeChirho { line_chirho: 0 }
        })?;

    let offered_chirho = verified_chirho.registration_seq_chirho();
    if let Some(highest_chirho) = highest_recorded_sequence_chirho(root_chirho, &node_id_chirho)? {
        if offered_chirho <= highest_chirho {
            return Err(
                CapacityAttestationStoreRefusalChirho::ReplayedRegistrationChirho {
                    node_id_chirho,
                    offered_chirho,
                    highest_recorded_chirho: highest_chirho,
                },
            );
        }
    }

    // The intent lands in CAS at an address that MUST equal the digest the record names, or the log
    // would carry a reference that self-containment reports as dangling.
    let stored_chirho = put_object_chirho(root_chirho, &record_chirho.intent_chirho)
        .map_err(|_error_chirho| CapacityAttestationStoreRefusalChirho::IntentNotStoredChirho)?;
    if stored_chirho.0 != record_chirho.intent_digest_chirho {
        return Err(
            CapacityAttestationStoreRefusalChirho::IntentDigestNotItsCasAddressChirho {
                declared_chirho: record_chirho.intent_digest_chirho.clone(),
                stored_at_chirho: stored_chirho.0,
            },
        );
    }

    let mut line_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| CapacityAttestationStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| CapacityAttestationStoreRefusalChirho::StoreUnavailableChirho)?;
    Ok(verified_chirho)
}

/// The current verified grant for one node: the highest-sequence record that verifies.
pub fn load_current_verified_capacity_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn NodeRegistrationAuthorityPortChirho,
) -> Result<VerifiedNodeCapacityChirho, CapacityAttestationStoreRefusalChirho> {
    let mut best_chirho: Option<(u64, VerifiedNodeCapacityChirho)> = None;
    for record_chirho in read_records_chirho(root_chirho)? {
        if record_chirho.intent_chirho.node_id_chirho != node_id_chirho {
            continue;
        }
        // A row that does not verify is SKIPPED rather than fatal: one bad row must not deny a node its
        // valid grant, and the row was already signature-checked when it was appended, so a row failing
        // now means the log was edited afterwards.
        if let Ok(verified_chirho) = verify_node_capacity_attestation_chirho(
            &record_chirho,
            authority_chirho,
            node_id_chirho,
        ) {
            let seq_chirho = verified_chirho.registration_seq_chirho();
            if best_chirho
                .as_ref()
                .map(|(best_seq_chirho, _)| seq_chirho > *best_seq_chirho)
                .unwrap_or(true)
            {
                best_chirho = Some((seq_chirho, verified_chirho));
            }
        }
    }
    best_chirho
        .map(|(_, verified_chirho)| verified_chirho)
        .ok_or(
            CapacityAttestationStoreRefusalChirho::NoGrantForNodeChirho {
                node_id_chirho: node_id_chirho.to_string(),
            },
        )
}

#[cfg(test)]
#[path = "capacity_attestation_store_tests_chirho.rs"]
mod capacity_attestation_store_tests_chirho;
