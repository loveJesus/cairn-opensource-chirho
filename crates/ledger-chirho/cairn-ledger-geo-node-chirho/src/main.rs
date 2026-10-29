// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Binary entry point for one GD7 geo-election node: reads a cluster config, a ledger config, and
//! the selected root from argv, then serves the HELD posture (observe + read-only coordinator).
//!
//! The compositions themselves live in this crate's `lib.rs`; this file only parses argv and calls
//! one of them, so the node's behaviour is testable without a process.

use anyhow::{anyhow, Result};
use cairn_ledger_geo_node_chirho::serve_resident_gd7_held_geo_node_chirho;
use std::path::PathBuf;

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// A shipped binary must be able to name its own source, because nothing at the destination can
/// derive it -- a sha256 on a host resolves to a tree only if the bytes carry the commit.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cairn-ledger-geo-node-chirho");

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
    let cluster_config_path_chirho = first_arg_chirho.map(PathBuf::from).ok_or_else(|| {
        anyhow!(
            "usage: cairn-ledger-geo-node-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>"
        )
    })?;
    let ledger_config_path_chirho = args_chirho.next().map(PathBuf::from).ok_or_else(|| {
        anyhow!(
            "usage: cairn-ledger-geo-node-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>"
        )
    })?;
    let expected_ledger_config_digest_chirho = args_chirho
        .next()
        .and_then(|value_chirho| value_chirho.into_string().ok())
        .ok_or_else(|| {
            anyhow!(
                "usage: cairn-ledger-geo-node-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>"
            )
        })?;
    let selected_root_chirho = args_chirho.next().map(PathBuf::from).ok_or_else(|| {
        anyhow!(
            "usage: cairn-ledger-geo-node-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>"
        )
    })?;
    if args_chirho.next().is_some() {
        return Err(anyhow!(
            "usage: cairn-ledger-geo-node-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>"
        ));
    }
    serve_resident_gd7_held_geo_node_chirho(
        &cluster_config_path_chirho,
        &ledger_config_path_chirho,
        &expected_ledger_config_digest_chirho,
        &selected_root_chirho,
    )
}
