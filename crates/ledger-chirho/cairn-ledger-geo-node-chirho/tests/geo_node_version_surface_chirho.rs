// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Drives the REAL binaries this crate ships to prove each can name its own source tree, and that
//! the positional argv contracts remain explicit when a reviewed trust input is added.
//!
//! Against the binaries rather than a helper on purpose: the claim is about what the SHIPPED bytes
//! do when an operator on a host types `--version`, and a helper cannot answer that.

use cairn_build_identity_chirho::version_line_names_a_tree_chirho;
use std::process::{Command, Output};

const GEO_NODE_BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cairn-ledger-geo-node-chirho");
const ERA_ACTIVATION_BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cairn-writer-era-activation-chirho");

const GEO_NODE_USAGE_CHIRHO: &str = "usage: cairn-ledger-geo-node-chirho <cluster-config.json> \
     <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>";

fn run_chirho(bin_chirho: &str, args_chirho: &[&str]) -> Output {
    Command::new(bin_chirho)
        .args(args_chirho)
        .output()
        .expect("the built binary runs")
}

fn assert_names_its_tree_chirho(bin_chirho: &str, expected_name_chirho: &str, flag_chirho: &str) {
    let output_chirho = run_chirho(bin_chirho, &[flag_chirho]);
    let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("utf8 version line");
    let line_chirho = stdout_chirho.trim_end();
    assert!(
        output_chirho.status.success(),
        "`{expected_name_chirho} {flag_chirho}` must exit 0; got {:?} with stdout {line_chirho:?}",
        output_chirho.status.code()
    );
    // Asserted directly as well as through the shared checker, so a bug in the checker cannot make
    // every arm in this family vacuously green at once.
    assert!(
        line_chirho.starts_with(&format!("{expected_name_chirho} ")),
        "the line must name the binary; got {line_chirho:?}"
    );
    assert!(
        line_chirho.ends_with(')'),
        "the commit is the last thing on the line, so `staged --version` output can be matched \
         against a reviewed sha; got {line_chirho:?}"
    );
    assert!(
        version_line_names_a_tree_chirho(line_chirho),
        "a staged binary must name a 40-hex commit or the honest `unknown` marker -- its sha256 is \
         otherwise its ONLY identity handle, and that resolves to no tree. Got {line_chirho:?}"
    );
}

#[test]
fn the_geo_node_version_flags_name_the_source_tree_chirho() {
    assert_names_its_tree_chirho(
        GEO_NODE_BIN_CHIRHO,
        "cairn-ledger-geo-node-chirho",
        "--version",
    );
    assert_names_its_tree_chirho(GEO_NODE_BIN_CHIRHO, "cairn-ledger-geo-node-chirho", "-V");
}

#[test]
fn the_era_activation_tool_version_flags_name_the_source_tree_chirho() {
    // It SIGNS a writer-era activation, so which bytes an operator ran belongs in the record.
    assert_names_its_tree_chirho(
        ERA_ACTIVATION_BIN_CHIRHO,
        "cairn-writer-era-activation-chirho",
        "--version",
    );
    assert_names_its_tree_chirho(
        ERA_ACTIVATION_BIN_CHIRHO,
        "cairn-writer-era-activation-chirho",
        "-V",
    );
}

#[test]
fn the_geo_node_requires_external_config_digest_in_its_four_coordinate_startup_chirho() {
    // Every short form must refuse with the reviewed-digest usage line, and five must refuse as
    // over-long. Exactly four is the shape `fleet-restage-chirho.sh` must stage against.
    for args_chirho in [
        vec![],
        vec!["cluster.json"],
        vec!["cluster.json", "ledger.toml"],
        vec!["cluster.json", "ledger.toml", "config-digest"],
        vec![
            "cluster.json",
            "ledger.toml",
            "config-digest",
            "/root",
            "extra",
        ],
    ] {
        let output_chirho = run_chirho(GEO_NODE_BIN_CHIRHO, &args_chirho);
        let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr).to_string();
        assert!(
            !output_chirho.status.success(),
            "{args_chirho:?} must still be refused"
        );
        assert!(
            stderr_chirho.contains(GEO_NODE_USAGE_CHIRHO),
            "{args_chirho:?} must be refused with the four-coordinate digest-bound usage; got \
             {stderr_chirho:?}"
        );
    }
}

#[test]
fn a_geo_node_config_path_that_merely_mentions_version_is_not_a_version_request_chirho() {
    // The flag check is EXACT for this reason: config paths are free-form, and a loose match would
    // silently swallow an operator's real file and answer with a version line instead of serving.
    let output_chirho = run_chirho(GEO_NODE_BIN_CHIRHO, &["--version-cluster.json"]);
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout).to_string();
    assert!(
        !output_chirho.status.success(),
        "a path that merely contains `--version` is a PATH; it must not be answered with a version"
    );
    assert!(
        stdout_chirho.is_empty(),
        "it must not print a version line; got stdout {stdout_chirho:?}"
    );
}

#[test]
fn the_era_activation_tool_still_requires_a_known_mode_chirho() {
    for args_chirho in [
        vec![],
        vec!["not-a-mode-chirho"],
        vec!["candidate-chirho"],
        vec!["sign-chirho", "candidate.json"],
    ] {
        let output_chirho = run_chirho(ERA_ACTIVATION_BIN_CHIRHO, &args_chirho);
        let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr).to_string();
        assert!(
            !output_chirho.status.success(),
            "{args_chirho:?} must still be refused"
        );
        assert!(
            stderr_chirho.contains("usage: cairn-writer-era-activation-chirho candidate-chirho"),
            "{args_chirho:?} must still be refused with the unchanged usage; got {stderr_chirho:?}"
        );
    }
}
