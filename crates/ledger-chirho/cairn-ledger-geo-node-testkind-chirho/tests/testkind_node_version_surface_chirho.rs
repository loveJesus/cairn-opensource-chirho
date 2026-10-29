// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Drives the REAL test-kind node binary to prove it can name its own source tree, and that its
//! reviewed config digest remains an explicit startup coordinate beside that identity surface.
//!
//! This binary is the one where naming the tree matters most: a test-kind node and a production node
//! differ only in bytes, and 6.5-e's invariant is that a production host builds the production bin.
//! An operator who cannot ask a staged binary which tree it came from cannot check that invariant.

use cairn_build_identity_chirho::version_line_names_a_tree_chirho;
use std::process::{Command, Output};

const BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cairn-ledger-geo-node-testkind-chirho");
const NAME_CHIRHO: &str = "cairn-ledger-geo-node-testkind-chirho";
const USAGE_CHIRHO: &str = "usage: cairn-ledger-geo-node-testkind-chirho <cluster-config.json> <ledger-config.toml> <expected-ledger-config-blake3> <selected-root>";

fn run_chirho(args_chirho: &[&str]) -> Output {
    Command::new(BIN_CHIRHO)
        .args(args_chirho)
        .output()
        .expect("the built test-kind node binary runs")
}

fn assert_names_its_tree_chirho(flag_chirho: &str) {
    let output_chirho = run_chirho(&[flag_chirho]);
    let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("utf8 version line");
    let line_chirho = stdout_chirho.trim_end();
    assert!(
        output_chirho.status.success(),
        "`{flag_chirho}` must exit 0; got {:?} with stdout {line_chirho:?}",
        output_chirho.status.code()
    );
    // Asserted directly as well as through the shared checker, so a bug in the checker cannot make
    // every arm in this family vacuously green at once.
    assert!(
        line_chirho.starts_with(&format!("{NAME_CHIRHO} ")),
        "the line must name the binary -- and this is the binary a reader most needs named; got \
         {line_chirho:?}"
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
fn the_long_version_flag_names_the_source_tree_chirho() {
    assert_names_its_tree_chirho("--version");
}

#[test]
fn the_short_version_flag_names_the_source_tree_chirho() {
    assert_names_its_tree_chirho("-V");
}

#[test]
fn the_version_line_says_testkind_so_it_cannot_be_mistaken_for_the_production_node_chirho() {
    let output_chirho = run_chirho(&["--version"]);
    let line_chirho = String::from_utf8(output_chirho.stdout).expect("utf8 version line");
    assert!(
        line_chirho.contains("testkind"),
        "the whole point of this binary's version line is that it distinguishes itself from the \
         production geo node; got {line_chirho:?}"
    );
}

#[test]
fn the_test_kind_node_requires_external_config_digest_in_its_four_coordinate_startup_chirho() {
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
        let output_chirho = run_chirho(&args_chirho);
        let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr).to_string();
        assert!(
            !output_chirho.status.success(),
            "{args_chirho:?} must still be refused"
        );
        assert!(
            stderr_chirho.contains(USAGE_CHIRHO),
            "{args_chirho:?} must be refused with the four-coordinate digest-bound usage; got \
             {stderr_chirho:?}"
        );
    }
}

#[test]
fn a_config_path_that_merely_mentions_version_is_not_a_version_request_chirho() {
    // The flag check is EXACT for this reason: config paths are free-form, and a loose match would
    // silently swallow an operator's real file and answer with a version line instead of serving.
    let output_chirho = run_chirho(&["--version-cluster.json"]);
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
