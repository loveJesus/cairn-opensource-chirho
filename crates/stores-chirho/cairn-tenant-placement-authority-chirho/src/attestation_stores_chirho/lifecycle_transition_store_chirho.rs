// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable lifecycle transitions, and the current state DERIVED by replaying them.
//!
//! **The state is never stored, only derived.** A stored "current state" field is a second recording of
//! something the log already determines, and this session has already been caught once by two records of
//! one fact disagreeing. Replaying from `ProvisionedChirho` through verified transitions means the
//! current state is provable from the log rather than asserted beside it.
//!
//! **Two independent protections, because they catch different things.** The sequence high-water mark
//! refuses a REPLAYED record — the same signed bytes offered twice. The `from_state_chirho` check
//! refuses a record signed against a STALE VIEW — authentic, never seen before, and describing a world
//! that has since moved on. A store with only the first accepts a drain signed while the node was
//! Joined and applied after it already retired.
//!
//! The intent goes to CAS for the same reason as capacity grants: this log is a declared surface, so
//! self-containment requires every 64-hex token in it to resolve as an object in this root, and
//! `hash_object_chirho` IS the CAS address of the intent's bytes.
//!
//! Reads go through `cairn-durable-chirho`'s identity-stable bounded primitive; appends through its
//! crash-safe line append.

use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_placement_chirho::node_lifecycle_chirho::lifecycle_attestation_chirho::{
    verify_lifecycle_attestation_chirho, LifecycleAuthorityPortChirho,
    LifecycleTransitionAttestationChirho, VerifiedLifecycleTransitionChirho,
};
use cairn_placement_chirho::node_lifecycle_chirho::NodeLifecycleStateChirho;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO: &str = "node-lifecycle-transitions-chirho.jsonl";
pub const NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LifecycleStoreRefusalChirho {
    StoreUnavailableChirho,
    /// Hard-linked, or replaced or grown between the stat, the open and the read.
    StoreIdentityUnstableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    /// The record did not verify, or the transition it asks for is illegal. It must not reach the log.
    NotVerifiedChirho,
    IntentNotStoredChirho,
    IntentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
    /// The same sequence, or an older one, has already been recorded for this node.
    ReplayedTransitionChirho {
        node_id_chirho: String,
        offered_chirho: u64,
        highest_recorded_chirho: u64,
    },
    /// Authentic and never seen, but signed against a state the node has since left. The protection a
    /// sequence check alone does NOT give.
    StaleViewChirho {
        node_id_chirho: String,
        signed_against_chirho: NodeLifecycleStateChirho,
        actual_chirho: NodeLifecycleStateChirho,
    },
}

fn log_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join(NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO)
}

fn read_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<LifecycleTransitionAttestationChirho>, LifecycleStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::InvalidData => LifecycleStoreRefusalChirho::StoreIdentityUnstableChirho,
        _ => LifecycleStoreRefusalChirho::StoreUnavailableChirho,
    })?;
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            LifecycleStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?);
    }
    Ok(records_chirho)
}

/// The current state for one node, DERIVED by replaying its verified transitions in sequence order
/// from the entry state.
///
/// A node with no transitions is `ProvisionedChirho` — the entry state a capacity grant establishes.
/// Whether the node exists at all is the capacity store's question, not this one's; keeping the two
/// independent is what lets either be read without the other.
pub fn current_lifecycle_state_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn LifecycleAuthorityPortChirho,
) -> Result<NodeLifecycleStateChirho, LifecycleStoreRefusalChirho> {
    let mut state_chirho = NodeLifecycleStateChirho::ProvisionedChirho;
    for verified_chirho in
        verified_transitions_in_order_chirho(root_chirho, node_id_chirho, authority_chirho)?
    {
        // Only apply a row signed against the state actually reached. This is what makes the replay a
        // CHAIN rather than a bag of independently-valid records.
        if verified_chirho.from_state_chirho() == state_chirho {
            state_chirho = verified_chirho.resulting_state_chirho();
        }
    }
    Ok(state_chirho)
}

/// One node's verified transitions, in SEQUENCE order.
///
/// Exposed so a caller that needs the transitions themselves — a registry rebuilding nodes through the
/// gated advance path — replays the same list this module derives state from, rather than reimplementing
/// the ordering and skip rules and drifting from them.
pub fn verified_transitions_in_order_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn LifecycleAuthorityPortChirho,
) -> Result<Vec<VerifiedLifecycleTransitionChirho>, LifecycleStoreRefusalChirho> {
    let mut rows_chirho: Vec<_> = read_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        .collect();
    // Sequence order, not append order: the log is append-only but a reader must not depend on the
    // writer having appended in order to be correct.
    rows_chirho.sort_by_key(|record_chirho| record_chirho.intent_chirho.transition_seq_chirho);
    Ok(rows_chirho
        .into_iter()
        // A row that fails verification is SKIPPED rather than fatal: every row was verified at append
        // time, so one failing now means the log was edited afterwards, and one bad row must not erase
        // a node's whole history.
        .filter_map(|record_chirho| {
            verify_lifecycle_attestation_chirho(&record_chirho, authority_chirho, node_id_chirho)
                .ok()
        })
        .collect())
}

fn highest_recorded_sequence_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
) -> Result<Option<u64>, LifecycleStoreRefusalChirho> {
    Ok(read_records_chirho(root_chirho)?
        .iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        .map(|record_chirho| record_chirho.intent_chirho.transition_seq_chirho)
        .max())
}

/// Append one signed transition after verifying it, refusing a replay, AND refusing a stale view.
///
/// Order is the contract: verify, then sequence, then state, then store the intent, then append — so a
/// failure anywhere earlier leaves the log untouched.
pub fn append_verified_lifecycle_transition_chirho(
    root_chirho: &Path,
    record_chirho: &LifecycleTransitionAttestationChirho,
    authority_chirho: &dyn LifecycleAuthorityPortChirho,
) -> Result<NodeLifecycleStateChirho, LifecycleStoreRefusalChirho> {
    let node_id_chirho = record_chirho.intent_chirho.node_id_chirho.clone();
    let verified_chirho =
        verify_lifecycle_attestation_chirho(record_chirho, authority_chirho, &node_id_chirho)
            .map_err(|_error_chirho| LifecycleStoreRefusalChirho::NotVerifiedChirho)?;

    let offered_chirho = verified_chirho.transition_seq_chirho();
    if let Some(highest_chirho) = highest_recorded_sequence_chirho(root_chirho, &node_id_chirho)? {
        if offered_chirho <= highest_chirho {
            return Err(LifecycleStoreRefusalChirho::ReplayedTransitionChirho {
                node_id_chirho,
                offered_chirho,
                highest_recorded_chirho: highest_chirho,
            });
        }
    }

    let actual_chirho =
        current_lifecycle_state_chirho(root_chirho, &node_id_chirho, authority_chirho)?;
    if verified_chirho.from_state_chirho() != actual_chirho {
        return Err(LifecycleStoreRefusalChirho::StaleViewChirho {
            node_id_chirho,
            signed_against_chirho: verified_chirho.from_state_chirho(),
            actual_chirho,
        });
    }

    let stored_chirho = put_object_chirho(root_chirho, &record_chirho.intent_chirho)
        .map_err(|_error_chirho| LifecycleStoreRefusalChirho::IntentNotStoredChirho)?;
    if stored_chirho.0 != record_chirho.intent_digest_chirho {
        return Err(
            LifecycleStoreRefusalChirho::IntentDigestNotItsCasAddressChirho {
                declared_chirho: record_chirho.intent_digest_chirho.clone(),
                stored_at_chirho: stored_chirho.0,
            },
        );
    }

    let mut line_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| LifecycleStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| LifecycleStoreRefusalChirho::StoreUnavailableChirho)?;
    Ok(verified_chirho.resulting_state_chirho())
}

#[cfg(test)]
#[path = "lifecycle_transition_store_tests_chirho.rs"]
mod lifecycle_transition_store_tests_chirho;
