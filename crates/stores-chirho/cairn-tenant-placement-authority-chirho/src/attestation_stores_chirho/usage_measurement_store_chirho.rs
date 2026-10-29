// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Durable node-signed usage reports, and the scaling posture they imply.
//!
//! **The design decision here is the subtle one, and getting it backwards would be a real defect.**
//! The clause says *"stale/replayed evidence **freezes** both scale-out and scale-in for that node."*
//! The obvious implementation refuses a stale report at append, the way the capacity and lifecycle
//! stores refuse a replay — and that would be exactly wrong. Refusing it leaves the node's last
//! good measurement standing as current, so the node keeps an UNFROZEN posture and goes on looking
//! healthy. A node offering replayed evidence is precisely a node you can no longer see.
//!
//! So an authentic stale report is **recorded**, and the posture is derived from classifying the LATEST
//! report against the accepted chain before it. Frozen means frozen until a genuinely fresh report
//! arrives, which is what "freezes" describes and what refusing would prevent.
//! Here `stale` means a replayed sequence or rewound HLC relative to the accepted chain. This module
//! has no wall-clock age window: an old report whose coordinates advance still classifies as fresh.
//!
//! Authenticity is still required: an unsigned or wrong-key report is not weak evidence, it is not
//! evidence, and it never reaches the log.
//!
//! The intent goes to CAS for the same self-containment reason as the other declared logs.

use cairn_core_chirho::store_chirho::put_object_chirho;
use cairn_placement_chirho::capacity_chirho::measurement_freshness_chirho::{
    classify_measurement_chirho, never_measured_posture_chirho, posture_for_verdict_chirho,
    MeasurementStampChirho, ScalingPostureChirho,
};
use cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::{
    verify_usage_measurement_chirho, NodeMeasurementAuthorityPortChirho,
    UsageMeasurementAttestationChirho, VerifiedUsageMeasurementChirho,
};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const NODE_USAGE_MEASUREMENT_LOG_CHIRHO: &str = "node-usage-measurements-chirho.jsonl";
pub const NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UsageStoreRefusalChirho {
    StoreUnavailableChirho,
    StoreIdentityUnstableChirho,
    DecodeChirho {
        line_chirho: u64,
    },
    /// The report did not verify against the node's key. Not weak evidence — not evidence.
    NotVerifiedChirho,
    IntentNotStoredChirho,
    IntentDigestNotItsCasAddressChirho {
        declared_chirho: String,
        stored_at_chirho: String,
    },
}

fn log_path_chirho(root_chirho: &Path) -> std::path::PathBuf {
    root_chirho.join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO)
}

fn read_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<UsageMeasurementAttestationChirho>, UsageStoreRefusalChirho> {
    let path_chirho = log_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        &path_chirho,
        NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO,
    )
    .map_err(|error_chirho| match error_chirho.kind() {
        std::io::ErrorKind::InvalidData => UsageStoreRefusalChirho::StoreIdentityUnstableChirho,
        _ => UsageStoreRefusalChirho::StoreUnavailableChirho,
    })?;
    let text_chirho = String::from_utf8_lossy(&bytes_chirho);
    let mut records_chirho = Vec::new();
    for (index_chirho, line_chirho) in text_chirho.lines().enumerate() {
        if line_chirho.trim().is_empty() {
            continue;
        }
        records_chirho.push(serde_json::from_str(line_chirho).map_err(|_error_chirho| {
            UsageStoreRefusalChirho::DecodeChirho {
                line_chirho: index_chirho as u64 + 1,
            }
        })?);
    }
    Ok(records_chirho)
}

/// One node's verified reports in APPEND order.
///
/// Append order, not sequence order — unlike lifecycle transitions. A replayed report is one whose
/// sequence does NOT advance, so sorting by sequence would reorder exactly the evidence this store
/// exists to notice, and a replay would quietly sort itself into the past.
/// This node's VERIFIED measurements in append order.
///
/// Public because the registry loader needs the records themselves, not just their stamps: it advances
/// a node through `advance_by_verified_measurement_chirho`, which takes verified evidence rather than a
/// bare stamp precisely so a caller cannot hand it a number.
pub fn verified_measurements_in_order_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
) -> Result<Vec<VerifiedUsageMeasurementChirho>, UsageStoreRefusalChirho> {
    Ok(read_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        .filter_map(|record_chirho| {
            verify_usage_measurement_chirho(&record_chirho, authority_chirho, node_id_chirho).ok()
        })
        .collect())
}

/// One node's verified reports in append order for an AUTHORITY-BEARING admission decision.
///
/// This is deliberately a distinct function from [`verified_measurements_in_order_chirho`], not a
/// strictness flag. The posture/report road skips a directly-written unverifiable row so local write
/// access cannot freeze a node by appending garbage. Admission cannot inherit that rule: skipping a
/// high-usage row would promote an older lower reading and manufacture headroom. Every matching row
/// must therefore verify or the whole admission snapshot refuses with `NotVerifiedChirho`.
pub fn verified_measurements_in_order_for_admission_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
) -> Result<Vec<VerifiedUsageMeasurementChirho>, UsageStoreRefusalChirho> {
    read_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        .map(|record_chirho| {
            verify_usage_measurement_chirho(&record_chirho, authority_chirho, node_id_chirho)
                .map_err(|_error_chirho| UsageStoreRefusalChirho::NotVerifiedChirho)
        })
        .collect()
}

fn verified_reports_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
) -> Result<Vec<MeasurementStampChirho>, UsageStoreRefusalChirho> {
    Ok(read_records_chirho(root_chirho)?
        .into_iter()
        .filter(|record_chirho| record_chirho.intent_chirho.node_id_chirho == node_id_chirho)
        // A row that does not verify is SKIPPED rather than freezing the node. That is safe only
        // because the append path refuses inauthentic reports, so a row can fail here only if someone
        // wrote to this file directly -- and freezing on it would hand anyone with write access a way
        // to freeze any node by appending garbage. The skip is deliberate, not lenient: an unverified
        // row carries no authority in either direction. It is still evidence that the file was written
        // outside the append path, which is a question for a display/verify surface rather than for a
        // posture computation, and is NOT reported here.
        .filter_map(|record_chirho| {
            verify_usage_measurement_chirho(&record_chirho, authority_chirho, node_id_chirho)
                .ok()
                .map(|verified_chirho| verified_chirho.stamp_chirho())
        })
        .collect())
}

/// The scaling posture this node's reports imply.
///
/// A node with no reports at all is FROZEN in both directions: never having been measured is not the
/// same as having been measured and found fine, and admission requires *fresh* measurement rather
/// than the absence of a bad one.
pub fn current_scaling_posture_chirho(
    root_chirho: &Path,
    node_id_chirho: &str,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
) -> Result<ScalingPostureChirho, UsageStoreRefusalChirho> {
    let stamps_chirho = verified_reports_chirho(root_chirho, node_id_chirho, authority_chirho)?;
    let Some((latest_chirho, earlier_chirho)) = stamps_chirho.split_last() else {
        return Ok(never_measured_posture_chirho());
    };
    // The accepted chain: only a FRESH report advances what the next one is judged against.
    let mut accepted_chirho: Option<MeasurementStampChirho> = None;
    for stamp_chirho in earlier_chirho {
        if classify_measurement_chirho(accepted_chirho, *stamp_chirho).is_fresh_chirho() {
            accepted_chirho = Some(*stamp_chirho);
        }
    }
    Ok(posture_for_verdict_chirho(classify_measurement_chirho(
        accepted_chirho,
        *latest_chirho,
    )))
}

/// Append one node-signed usage report.
///
/// A stale or replayed report is RECORDED, not refused — see the module header. Only an inauthentic one
/// is turned away.
pub fn append_verified_usage_measurement_chirho(
    root_chirho: &Path,
    record_chirho: &UsageMeasurementAttestationChirho,
    authority_chirho: &dyn NodeMeasurementAuthorityPortChirho,
) -> Result<ScalingPostureChirho, UsageStoreRefusalChirho> {
    let node_id_chirho = record_chirho.intent_chirho.node_id_chirho.clone();
    verify_usage_measurement_chirho(record_chirho, authority_chirho, &node_id_chirho)
        .map_err(|_error_chirho| UsageStoreRefusalChirho::NotVerifiedChirho)?;

    let stored_chirho = put_object_chirho(root_chirho, &record_chirho.intent_chirho)
        .map_err(|_error_chirho| UsageStoreRefusalChirho::IntentNotStoredChirho)?;
    if stored_chirho.0 != record_chirho.intent_digest_chirho {
        return Err(
            UsageStoreRefusalChirho::IntentDigestNotItsCasAddressChirho {
                declared_chirho: record_chirho.intent_digest_chirho.clone(),
                stored_at_chirho: stored_chirho.0,
            },
        );
    }

    let mut line_chirho = serde_json::to_vec(record_chirho)
        .map_err(|_error_chirho| UsageStoreRefusalChirho::StoreUnavailableChirho)?;
    line_chirho.push(b'\n');
    cairn_durable_chirho::append_durable_line_chirho(&log_path_chirho(root_chirho), &line_chirho)
        .map_err(|_error_chirho| UsageStoreRefusalChirho::StoreUnavailableChirho)?;

    current_scaling_posture_chirho(root_chirho, &node_id_chirho, authority_chirho)
}

#[cfg(test)]
#[path = "usage_measurement_store_tests_chirho.rs"]
mod usage_measurement_store_tests_chirho;
