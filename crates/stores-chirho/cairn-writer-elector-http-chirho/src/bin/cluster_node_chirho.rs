// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Reference deployable cluster-node binary. Two modes: `cluster_node keygen <sign_root_dir>` provisions
//! this node's signing identity and prints its pubkey; `cluster_node <config.json>` reads the JSON config,
//! builds a `ClusterNodeChirho`, and serves it. A refinable REFERENCE for the operational tool —
//! orchestration and graceful-shutdown-on-SIGTERM (via the library's stop flag) are the deployment layer
//! (see `cluster-deployment-runbook-chirho.md`). Election-only: it mints nothing.
//!
//! Config (JSON):
//! ```json
//! {
//!   "group_chirho": {"kind_chirho": "root", "root_path_chirho": "/var/lib/app"},
//!   "local_raft_id_chirho": 1,
//!   "members_chirho": [
//!     {"raft_id_chirho": 1, "pubkey_chirho": "<hex>", "url_chirho": "http://10.100.0.1:8300", "learner_chirho": false},
//!     {"raft_id_chirho": 2, "pubkey_chirho": "<hex>", "url_chirho": "http://10.100.0.2:8300", "learner_chirho": false},
//!     {"raft_id_chirho": 3, "pubkey_chirho": "<hex>", "url_chirho": "http://10.100.0.3:8300", "learner_chirho": true}
//!   ],
//!   "durable_dir_chirho": "/var/lib/cairn-raft", "sign_root_chirho": "/var/lib/cairn-key",
//!   "listen_addr_chirho": "0.0.0.0:8300", "tick_ms_chirho": 50
//! }
//! ```

use anyhow::{anyhow, Context, Result};
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::load_cluster_node_file_config_chirho;
#[cfg(test)]
use cairn_writer_elector_http_chirho::cluster_file_config_chirho::parse_cluster_node_file_config_chirho;
use cairn_writer_elector_http_chirho::cluster_node_chirho::ClusterNodeChirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `cluster_node keygen <sign_root_dir>`: provision this node's ed25519 signing identity (if absent) and
/// print its pubkey hex — the `NodeId` the roster maps this node's raft id to.
fn run_keygen_chirho(sign_root_arg_chirho: Option<&String>) -> Result<()> {
    let sign_root_chirho = sign_root_arg_chirho
        .ok_or_else(|| anyhow!("usage: cluster_node keygen <sign_root_dir>"))?;
    let root_path_chirho = PathBuf::from(sign_root_chirho);
    std::fs::create_dir_all(&root_path_chirho)
        .with_context(|| format!("create sign root {sign_root_chirho}"))?;
    // Signing once provisions the key if none exists yet (the same path the elector tests use).
    cairn_signer_chirho::signer_chirho::sign_message_chirho(
        &root_path_chirho,
        b"cluster-node-keygen-chirho",
    )
    .context("provision node signing key")?;
    let pubkey_chirho = cairn_signer_chirho::signer_chirho::pubkey_hex_chirho(&root_path_chirho)
        .context("read node pubkey")?;
    println!("{pubkey_chirho}");
    Ok(())
}

/// This binary's name PLUS the crate version PLUS the source commit that built these bytes.
///
/// The cargo bin name, not the installed name (`cairn-elector-chirho`), because the installed name
/// is a deployment choice and these bytes are what they are wherever they land.
const VERSION_LINE_CHIRHO: &str =
    cairn_build_identity_chirho::version_line_chirho!("cluster_node_chirho");

fn main() -> Result<()> {
    let args_chirho: Vec<String> = std::env::args().collect();

    // BEFORE the positional parse, and that order is the whole point: `argv[1]` below is a config
    // PATH, so `--version` used to be opened as a filename and fail `No such file or directory` --
    // leaving a staged elector whose only identity handle was its sha256, resolvable to no tree.
    if cairn_build_identity_chirho::is_version_request_chirho(
        args_chirho.get(1).map(String::as_str),
    ) {
        println!("{VERSION_LINE_CHIRHO}");
        return Ok(());
    }

    // Subcommand: provision this node's signing identity and print its pubkey (see run_keygen_chirho).
    if args_chirho.get(1).map(String::as_str) == Some("keygen") {
        return run_keygen_chirho(args_chirho.get(2));
    }

    let config_path_chirho = args_chirho.get(1).cloned().ok_or_else(|| {
        anyhow!("usage: cluster_node <config.json>  |  cluster_node keygen <sign_root_dir>")
    })?;
    let loaded_config_chirho =
        load_cluster_node_file_config_chirho(&PathBuf::from(&config_path_chirho))?;

    let node_chirho = ClusterNodeChirho::build_chirho(loaded_config_chirho.cluster_chirho)?;
    let listener_chirho = std::net::TcpListener::bind(&loaded_config_chirho.listen_addr_chirho)
        .with_context(|| format!("bind {}", loaded_config_chirho.listen_addr_chirho))?;
    eprintln!(
        "cluster node serving on {} (SIGINT/SIGTERM to drain and stop)",
        loaded_config_chirho.listen_addr_chirho
    );
    // SIGINT/SIGTERM set the stop flag; the serve loop then gracefully drains in-flight requests and
    // returns — a clean stop for restarts/rolls under an orchestrator.
    let stop_chirho = Arc::new(AtomicBool::new(false));
    let signal_stop_chirho = stop_chirho.clone();
    ctrlc::set_handler(move || signal_stop_chirho.store(true, Ordering::Relaxed))
        .context("install SIGINT/SIGTERM handler")?;
    node_chirho.serve_blocking_chirho(listener_chirho, stop_chirho)
}

#[cfg(test)]
mod tests_chirho {
    use super::*;

    #[test]
    fn config_splits_voters_learners_and_peers_chirho() {
        let json_chirho = r#"{
            "group_chirho": {"kind_chirho": "root", "root_path_chirho": "/var/lib/app"},
            "local_raft_id_chirho": 1,
            "members_chirho": [
                {"raft_id_chirho": 1, "pubkey_chirho": "aa", "url_chirho": "http://10.100.0.1:8300", "learner_chirho": false},
                {"raft_id_chirho": 2, "pubkey_chirho": "bb", "url_chirho": "http://10.100.0.2:8300", "learner_chirho": false},
                {"raft_id_chirho": 3, "pubkey_chirho": "cc", "url_chirho": "http://10.100.0.3:8300", "learner_chirho": true}
            ],
            "durable_dir_chirho": "/tmp/d", "sign_root_chirho": "/tmp/s",
            "listen_addr_chirho": "0.0.0.0:8300", "tick_ms_chirho": 50
        }"#;
        let loaded_chirho = parse_cluster_node_file_config_chirho(json_chirho.as_bytes()).unwrap();
        let config_chirho = loaded_chirho.cluster_chirho;
        assert_eq!(
            config_chirho.voters_chirho.len(),
            2,
            "ids 1 and 2 are voters"
        );
        assert_eq!(config_chirho.learners_chirho.len(), 1, "id 3 is a learner");
        assert_eq!(
            config_chirho.peers_chirho.len(),
            2,
            "peers are everyone but self (ids 2 and 3)"
        );
        assert!(config_chirho
            .peers_chirho
            .iter()
            .all(|(raft_id_chirho, _)| *raft_id_chirho != 1));
        assert_eq!(loaded_chirho.listen_addr_chirho, "0.0.0.0:8300");
        assert_eq!(config_chirho.local_raft_id_chirho, 1);
    }
}
