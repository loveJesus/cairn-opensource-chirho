// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Test-kind CF7 provider and operator sidecar behind the production-required signed placement
//! admission. Unlike the roster-wide compatibility binary, this target cannot serve a voter unless
//! the local node is assigned by the verified tenant-placement record.

use anyhow::{anyhow, Result};
use cairn_ledger_geo_node_chirho::{
    serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho,
    GeoVoterStartupOwnershipChirho,
};
use cairn_ledger_geo_node_testkind_chirho::{
    start_testkind_cf7_operator_control_chirho, testkind_resident_opener_chirho,
};
use std::path::PathBuf;

const USAGE_CHIRHO: &str = "usage: cairn-ledger-geo-node-placement-testkind-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root> [recompose-local-owner-chirho]";

const VERSION_LINE_CHIRHO: &str = cairn_build_identity_chirho::version_line_chirho!(
    "cairn-ledger-geo-node-placement-testkind-chirho"
);

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    let first_arg_chirho = args_chirho.next();
    if cairn_build_identity_chirho::is_version_request_chirho(
        first_arg_chirho
            .as_ref()
            .and_then(|arg_chirho| arg_chirho.to_str()),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }
    let cluster_config_path_chirho = first_arg_chirho
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let ledger_config_path_chirho = args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let expected_ledger_config_digest_chirho = args_chirho
        .next()
        .and_then(|value_chirho| value_chirho.into_string().ok())
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let selected_root_chirho = args_chirho
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!(USAGE_CHIRHO))?;
    let startup_ownership_chirho = match args_chirho.next() {
        None => GeoVoterStartupOwnershipChirho::FirstKnownOwnerChirho,
        Some(mode_chirho) if mode_chirho == "recompose-local-owner-chirho" => {
            GeoVoterStartupOwnershipChirho::RecomposeLocalOwnerChirho
        }
        Some(_) => return Err(anyhow!(USAGE_CHIRHO)),
    };
    if args_chirho.next().is_some() {
        return Err(anyhow!(USAGE_CHIRHO));
    }
    serve_resident_gd7_voter_geo_node_with_resident_opener_and_local_owner_sidecar_chirho(
        &cluster_config_path_chirho,
        &ledger_config_path_chirho,
        &expected_ledger_config_digest_chirho,
        &selected_root_chirho,
        startup_ownership_chirho,
        testkind_resident_opener_chirho,
        |selected_root_chirho, host_chirho, runtime_chirho, process_stop_chirho| {
            start_testkind_cf7_operator_control_chirho(
                selected_root_chirho,
                host_chirho,
                runtime_chirho,
                process_stop_chirho,
            )
            .map(Some)
        },
    )
}
