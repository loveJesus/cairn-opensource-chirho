// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Drives the REAL `cluster_node_chirho` binary to prove it can name its own source tree, and that
//! gaining that flag did not disturb the positional contract the deploy scripts invoke it by.
//!
//! Against the binary rather than a helper on purpose: the claim is about what the SHIPPED bytes do
//! when an operator on a host types `--version`, and a helper cannot answer that.

use cairn_build_identity_chirho::version_line_names_a_tree_chirho;
use std::process::{Command, Output};

const BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cluster_node_chirho");

fn run_chirho(args_chirho: &[&str]) -> Output {
    Command::new(BIN_CHIRHO)
        .args(args_chirho)
        .output()
        .expect("the built cluster_node_chirho binary runs")
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
        line_chirho.starts_with("cluster_node_chirho "),
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
fn the_long_version_flag_names_the_source_tree_chirho() {
    assert_names_its_tree_chirho("--version");
}

#[test]
fn the_short_version_flag_names_the_source_tree_chirho() {
    assert_names_its_tree_chirho("-V");
}

#[test]
fn keygen_still_routes_to_the_keygen_subcommand_chirho() {
    // `fleet-elector-deploy-chirho.sh` provisions every node's identity with exactly this shape.
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-cluster-node-version-surface-chirho-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    let output_chirho = run_chirho(&["keygen", dir_chirho.to_str().expect("utf8 temp path")]);
    let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("utf8 pubkey");
    let pubkey_chirho = stdout_chirho.trim().to_string();
    let _ = std::fs::remove_dir_all(&dir_chirho);
    assert!(
        output_chirho.status.success(),
        "keygen must still exit 0; stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert_eq!(
        pubkey_chirho.len(),
        64,
        "keygen still prints a hex ed25519 pubkey; got {pubkey_chirho:?}"
    );
    assert!(
        pubkey_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit()),
        "keygen still prints hex; got {pubkey_chirho:?}"
    );
}

#[test]
fn a_first_argument_that_is_not_a_version_flag_is_still_a_config_path_chirho() {
    // The systemd/setsid launch shape: `cluster_node_chirho <config.json>`. It must still be READ as
    // a path -- proven by the failure naming the missing file rather than a usage or version line.
    let missing_chirho = std::env::temp_dir()
        .join("cairn-cluster-node-absent-config-chirho.json")
        .to_str()
        .expect("utf8 temp path")
        .to_string();
    let output_chirho = run_chirho(&[&missing_chirho]);
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr).to_string();
    assert!(
        !output_chirho.status.success(),
        "an absent config must still fail; stdout: {}",
        String::from_utf8_lossy(&output_chirho.stdout)
    );
    assert!(
        stderr_chirho.contains(&missing_chirho),
        "the failure must still name the config path it tried to open; got {stderr_chirho:?}"
    );
}

#[test]
fn a_config_path_that_merely_mentions_version_is_not_a_version_request_chirho() {
    // The flag check is EXACT for this reason: config paths are free-form, and a loose match would
    // silently swallow an operator's real file and answer with a version line instead of serving.
    let named_chirho = std::env::temp_dir()
        .join("cairn-cluster-node--version-chirho.json")
        .to_str()
        .expect("utf8 temp path")
        .to_string();
    let output_chirho = run_chirho(&[&named_chirho]);
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout).to_string();
    assert!(
        !output_chirho.status.success(),
        "a path that merely contains `--version` is a PATH; it must not be answered with a version"
    );
    assert!(
        !stdout_chirho.contains("cluster_node_chirho 0."),
        "it must not print a version line; got stdout {stdout_chirho:?}"
    );
}
