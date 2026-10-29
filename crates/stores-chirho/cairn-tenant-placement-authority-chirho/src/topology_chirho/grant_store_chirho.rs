// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable signed topology grants, and the replay protection their stateless verifier cannot keep.
//!
//! `topology_grant_attestation_chirho` verifies a grant STATELESSLY, so a correctly signed OLD grant
//! verifies exactly as well as the current one — which matters more here than for a capacity grant,
//! because a topology grant is a CEILING. Replaying a superseded grant is how a planner gets back a
//! node count, spend rate, or provider allowlist that was deliberately reduced. The verifier cannot
//! see that; only a caller holding durable state can, and this module is that caller.
//!
//! Keyed on the PRINCIPAL rather than a node, because that is what a grant is bound to: the whole
//! point of the signed grant is that the party constrained by the bounds is not the party who sets
//! them, so "the current grant" is a question about a principal.
//!
//! This log was DECLARED in the projection manifest with nothing writing or reading it — a surface
//! that existed as a name. That is the gap this closes.
//!
//! Ordering is the contract, and it is the same one the sibling stores keep: verify the signature,
//! refuse the replay, store the intent, then append. Any earlier failure leaves the log untouched, so
//! a forged or replayed grant never becomes a row somebody later has to explain.

use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_placement_chirho::topology_chirho::topology_grant_attestation_chirho::{
    verify_topology_grant_attestation_chirho, TopologyGrantAttestationChirho,
    TopologyGrantAuthorityPortChirho, VerifiedTopologyGrantChirho,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const TOPOLOGY_GRANT_ATTESTATION_LOG_CHIRHO: &str = "topology-grant-attestations-chirho.jsonl";
pub const TOPOLOGY_GRANT_ATTESTATION_LOG_MAX_BYTES_CHIRHO: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopologyGrantStoreRefusalChirho {
    StoreUnavailableChirho,
    StoreIdentityUnstableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    NotVerifiedChirho,
    /// A grant at or below the highest issued sequence already recorded for this principal. The
    /// stateless verifier cannot refuse this, and a superseded ceiling is exactly what a planner would
    /// want back.
    ReplayedIssuedSeqChirho {
        principal_chirho: String,
        highest_recorded_chirho: u64,
        offered_chirho: u64,
    },
    IntentNotStoredChirho,
    IntentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
    NoGrantForPrincipalChirho {
        principal_chirho: String,
    },
}

fn log_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(TOPOLOGY_GRANT_ATTESTATION_LOG_CHIRHO)
}

fn read_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<TopologyGrantAttestationChirho>, TopologyGrantStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        TOPOLOGY_GRANT_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::InvalidData => {
            TopologyGrantStoreRefusalChirho::StoreIdentityUnstableChirho
        }
        _ => TopologyGrantStoreRefusalChirho::StoreUnavailableChirho,
    })?;
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            TopologyGrantStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?);
    }
    Ok(records_chirho)
}

/// The highest issued sequence VERIFIED for this principal, or `None` if it has no grant on record.
///
/// A row that fails verification is skipped rather than fatal: every row was signature-checked at
/// append time, so a row failing later means the file was edited outside this path — and letting an
/// edited row raise the high-water mark would hand an attacker a denial of service against future
/// legitimate grants.
pub fn highest_recorded_issued_seq_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    authority_chirho: &dyn TopologyGrantAuthorityPortChirho,
) -> Result<Option<u64>, TopologyGrantStoreRefusalChirho> {
    Ok(read_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.intent_chirho.principal_chirho == principal_chirho)
        .filter_map(|record_chirho| {
            verify_topology_grant_attestation_chirho(
                &record_chirho,
                authority_chirho,
                principal_chirho,
            )
            .ok()
            .map(|verified_chirho| verified_chirho.issued_seq_chirho())
        })
        .max())
}

/// Append one authority-signed topology grant.
pub fn append_verified_topology_grant_chirho(
    root_chirho: &Path,
    record_chirho: &TopologyGrantAttestationChirho,
    authority_chirho: &dyn TopologyGrantAuthorityPortChirho,
) -> Result<VerifiedTopologyGrantChirho, TopologyGrantStoreRefusalChirho> {
    let principal_chirho = record_chirho.intent_chirho.principal_chirho.clone();
    let verified_chirho = verify_topology_grant_attestation_chirho(
        record_chirho,
        authority_chirho,
        &principal_chirho,
    )
    .map_err(|_error_chirho| TopologyGrantStoreRefusalChirho::NotVerifiedChirho)?;

    if let Some(highest_chirho) =
        highest_recorded_issued_seq_chirho(root_chirho, &principal_chirho, authority_chirho)?
    {
        if verified_chirho.issued_seq_chirho() <= highest_chirho {
            return Err(TopologyGrantStoreRefusalChirho::ReplayedIssuedSeqChirho {
                principal_chirho,
                highest_recorded_chirho: highest_chirho,
                offered_chirho: verified_chirho.issued_seq_chirho(),
            });
        }
    }

    let stored_chirho = put_object_chirho(root_chirho, &record_chirho.intent_chirho)
        .map_err(|_error_chirho| TopologyGrantStoreRefusalChirho::IntentNotStoredChirho)?;
    if stored_chirho.0 != record_chirho.intent_digest_chirho {
        return Err(
            TopologyGrantStoreRefusalChirho::IntentDigestNotItsCasAddressChirho {
                declared_chirho: record_chirho.intent_digest_chirho.clone(),
                stored_at_chirho: stored_chirho.0,
            },
        );
    }

    let mut line_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| TopologyGrantStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| TopologyGrantStoreRefusalChirho::StoreUnavailableChirho)?;

    Ok(verified_chirho)
}

/// The CURRENT verified grant for a principal: the one with the highest issued sequence.
///
/// Refuses when a principal has none, rather than returning an empty or default grant. A default
/// ceiling is the most dangerous possible answer to "what may this principal do" — it would be either
/// unbounded or zero, and both are wrong for a question whose honest answer is "no grant on record".
pub fn load_current_verified_grant_chirho(
    root_chirho: &Path,
    principal_chirho: &str,
    authority_chirho: &dyn TopologyGrantAuthorityPortChirho,
) -> Result<VerifiedTopologyGrantChirho, TopologyGrantStoreRefusalChirho> {
    let mut best_chirho: Option<VerifiedTopologyGrantChirho> = None;
    for record_chirho in read_records_chirho(root_chirho)? {
        if record_chirho.intent_chirho.principal_chirho != principal_chirho {
            continue;
        }
        let Ok(verified_chirho) = verify_topology_grant_attestation_chirho(
            &record_chirho,
            authority_chirho,
            principal_chirho,
        ) else {
            continue;
        };
        let replace_chirho = best_chirho
            .as_ref()
            .map(|current_chirho| {
                verified_chirho.issued_seq_chirho() > current_chirho.issued_seq_chirho()
            })
            .unwrap_or(true);
        if replace_chirho {
            best_chirho = Some(verified_chirho);
        }
    }
    best_chirho.ok_or(TopologyGrantStoreRefusalChirho::NoGrantForPrincipalChirho {
        principal_chirho: principal_chirho.to_string(),
    })
}

#[cfg(test)]
#[path = "grant_store_tests_chirho.rs"]
mod grant_store_tests_chirho;
