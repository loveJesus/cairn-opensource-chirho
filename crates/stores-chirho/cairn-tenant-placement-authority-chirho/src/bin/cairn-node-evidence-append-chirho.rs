// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verify one signed node-evidence record and append it to a root's evidence store.
//!
//! The capacity, lifecycle and usage stores each ship an append function whose only callers are
//! tests: measured at `ccf2b341`, none of the three had a binary. So an operator could not put a
//! capacity grant, a lifecycle transition, or a usage measurement into a host evidence root by any
//! shipped command, and the evidence root the admission adapter requires could not be built at all
//! except by a test fixture. That is why a host survey found the logs absent — not a staging backlog,
//! a tooling absence.
//!
//! **One binary rather than three, and the reason is a safety property rather than tidiness.**
//! `resolve_control_plane_authorities_chirho` refuses a key arrangement where one holder speaks for
//! two authorities, and it can only do that when it sees the whole arrangement. Three single-key
//! binaries would each bypass it and stage evidence that the loader later refuses — a late failure
//! instead of an early one, with the wrong identity attached.
//!
//! **It decides nothing.** The record must already verify against its authority; this appends it or
//! refuses by identity. Replay protection, freeze semantics and ordering are the stores' own, and
//! each store's rule differs deliberately — capacity refuses a replayed registration, lifecycle
//! refuses a stale from-state, usage RECORDS a stale report and freezes rather than refusing. This
//! binary imposes no rule of its own on top of them.
//!
//! Output carries the kind, node id and the store's own accepted result only — no key material, no
//! record bodies, no filesystem paths.

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_attestation_store_chirho::{
    append_verified_capacity_attestation_chirho, NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::lifecycle_transition_store_chirho::{
    append_verified_lifecycle_transition_chirho, NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::usage_measurement_store_chirho::{
    append_verified_usage_measurement_chirho, NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO,
};
use cairn_tenant_placement_authority_chirho::control_plane_authorities_chirho::resolve_control_plane_authorities_chirho;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE_REFUSAL_CHIRHO: &str = "NodeEvidenceAppendUsageRefusedChirho";
const RECORD_UNREADABLE_REFUSAL_CHIRHO: &str = "NodeEvidenceRecordFileUnreadableChirho";
const RECORD_MALFORMED_REFUSAL_CHIRHO: &str = "NodeEvidenceRecordFileMalformedChirho";
const UNKNOWN_NODE_REFUSAL_CHIRHO: &str = "NodeEvidenceMeasurementAuthorityUnknownChirho";

fn next_utf8_chirho(
    arguments_chirho: &mut impl Iterator<Item = OsString>,
) -> Result<String, &'static str> {
    arguments_chirho
        .next()
        .ok_or(USAGE_REFUSAL_CHIRHO)?
        .into_string()
        .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO)
}

/// Read a record file through the identity-stable bounded primitive the stores themselves use.
fn read_record_chirho<RecordChirho: serde::de::DeserializeOwned>(
    path_chirho: &Path,
    maximum_chirho: u64,
) -> Result<RecordChirho, String> {
    let bytes_chirho = cairn_durable_chirho::read_identity_stable_bounded_regular_file_chirho(
        path_chirho,
        maximum_chirho,
    )
    .map_err(|_error_chirho| RECORD_UNREADABLE_REFUSAL_CHIRHO.to_string())?;
    serde_json::from_slice(&bytes_chirho)
        .map_err(|_error_chirho| RECORD_MALFORMED_REFUSAL_CHIRHO.to_string())
}

fn run_chirho() -> Result<String, String> {
    let mut arguments_chirho = std::env::args_os();
    let _program_chirho = arguments_chirho.next();
    let root_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let kind_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let record_path_chirho = PathBuf::from(next_utf8_chirho(&mut arguments_chirho)?);
    let capacity_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let lifecycle_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let topology_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;
    let budget_key_chirho = next_utf8_chirho(&mut arguments_chirho)?;

    let mut node_measurement_keys_chirho: BTreeMap<String, String> = BTreeMap::new();
    for argument_chirho in arguments_chirho {
        let argument_chirho = argument_chirho
            .into_string()
            .map_err(|_value_chirho| USAGE_REFUSAL_CHIRHO.to_string())?;
        let (node_id_chirho, key_chirho) = argument_chirho
            .split_once('=')
            .ok_or_else(|| USAGE_REFUSAL_CHIRHO.to_string())?;
        node_measurement_keys_chirho.insert(node_id_chirho.to_string(), key_chirho.to_string());
    }
    if node_measurement_keys_chirho.is_empty() {
        return Err(USAGE_REFUSAL_CHIRHO.to_string());
    }

    // Sees the WHOLE arrangement, so one holder speaking for two authorities refuses here rather
    // than at a later read.
    let authorities_chirho = resolve_control_plane_authorities_chirho(
        &capacity_key_chirho,
        &lifecycle_key_chirho,
        &topology_key_chirho,
        &budget_key_chirho,
        &node_measurement_keys_chirho,
    )
    .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;

    match kind_chirho.as_str() {
        "capacity-chirho" => {
            let record_chirho = read_record_chirho(
                &record_path_chirho,
                NODE_CAPACITY_ATTESTATION_LOG_MAX_BYTES_CHIRHO,
            )?;
            let verified_chirho = append_verified_capacity_attestation_chirho(
                &root_chirho,
                &record_chirho,
                authorities_chirho.capacity_registrar_chirho(),
            )
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
            Ok(format!(
                "kind_chirho=capacity-chirho node_chirho={} registration_seq_chirho={}",
                verified_chirho.node_id_chirho(),
                verified_chirho.registration_seq_chirho()
            ))
        }
        "lifecycle-chirho" => {
            let record_chirho = read_record_chirho(
                &record_path_chirho,
                NODE_LIFECYCLE_TRANSITION_LOG_MAX_BYTES_CHIRHO,
            )?;
            let state_chirho = append_verified_lifecycle_transition_chirho(
                &root_chirho,
                &record_chirho,
                authorities_chirho.lifecycle_chirho(),
            )
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
            Ok(format!(
                "kind_chirho=lifecycle-chirho state_chirho={state_chirho:?}"
            ))
        }
        "usage-chirho" => {
            let record_chirho: cairn_placement_chirho::capacity_chirho::usage_measurement_attestation_chirho::UsageMeasurementAttestationChirho =
                read_record_chirho(&record_path_chirho, NODE_USAGE_MEASUREMENT_LOG_MAX_BYTES_CHIRHO)?;
            let node_id_chirho = record_chirho.intent_chirho.node_id_chirho.clone();
            let authority_chirho = authorities_chirho
                .node_measurement_chirho(&node_id_chirho)
                .ok_or_else(|| UNKNOWN_NODE_REFUSAL_CHIRHO.to_string())?;
            let posture_chirho = append_verified_usage_measurement_chirho(
                &root_chirho,
                &record_chirho,
                authority_chirho,
            )
            .map_err(|refusal_chirho| format!("{refusal_chirho:?}"))?;
            Ok(format!(
                "kind_chirho=usage-chirho node_chirho={node_id_chirho} posture_chirho={posture_chirho:?}"
            ))
        }
        _ => Err(USAGE_REFUSAL_CHIRHO.to_string()),
    }
}

fn main() -> ExitCode {
    match run_chirho() {
        Ok(rendered_chirho) => {
            println!("{rendered_chirho}");
            ExitCode::SUCCESS
        }
        Err(identity_chirho) => {
            eprintln!("{identity_chirho}");
            ExitCode::FAILURE
        }
    }
}
