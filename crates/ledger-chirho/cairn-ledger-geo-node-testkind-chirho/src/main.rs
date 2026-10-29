// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Binary entry point for one TEST-KIND GD7 geo-election node: the same four-coordinate,
//! digest-bound argv shape as the production geo node, but the winner posture is served with a synthetic reporting-only
//! compensation provider through the winner-side door, so a hosted item-6 drill can reach
//! `CompletedChirho`. This is NOT a production node and must never serve real traffic; deploy
//! selection (a production host builds the production bin, never this one) is 6.5-e's invariant.

use anyhow::{anyhow, Result};
use cairn_ledger_geo_node_chirho::serve_testkind_roster_wide_gd7_voter_geo_node_chirho;
use cairn_ledger_geo_node_testkind_chirho::{
    start_testkind_cf7_operator_control_chirho, testkind_resident_opener_chirho,
};
use std::path::PathBuf;

const USAGE_CHIRHO: &str =
    "usage: cairn-ledger-geo-node-testkind-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>";

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// It matters most HERE: a test-kind node and a production node differ only in bytes, so an
/// operator who cannot ask a staged binary which tree it came from cannot tell them apart.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-ledger-geo-node-testkind-chirho");

fn main() -> Result<()> {
    let mut args_chirho = std::env::args_os();
    let _program_chirho = args_chirho.next();
    // BEFORE the positional parse: this same argument becomes a config path below, so a version
    // request would otherwise be consumed as one and answered with a usage error.
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
    if args_chirho.next().is_some() {
        return Err(anyhow!(USAGE_CHIRHO));
    }
    serve_testkind_roster_wide_gd7_voter_geo_node_chirho(
        &cluster_config_path_chirho,
        &ledger_config_path_chirho,
        &expected_ledger_config_digest_chirho,
        &selected_root_chirho,
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
