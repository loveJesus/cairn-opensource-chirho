// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Config parse never mints, repairs or chmods a node key: the membership-control branch reads only an existing pair (#30111).

use crate::cluster_file_config_chirho::parse_cluster_node_file_config_chirho;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const SEED_FILE_CHIRHO: &str = "signing-key-chirho.bin";
const PUBKEY_FILE_CHIRHO: &str = "pubkey-chirho.hex";
const LOAD_CONTEXT_CHIRHO: &str = "read the local node's existing key pair for membership control";

/// A membership-controlled config whose node key lives in `sign_root_chirho`. Everything else is valid, so
/// the key read is the only thing that can refuse.
fn membership_config_bytes_chirho(sign_root_chirho: &Path) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "group_chirho": {"kind_chirho": "root", "root_path_chirho": "/tmp/cairn-no-mint-chirho"},
        "local_raft_id_chirho": 1,
        "members_chirho": [{
            "raft_id_chirho": 1,
            "pubkey_chirho": "a".repeat(64),
            "url_chirho": "http://127.0.0.1:3001",
            "learner_chirho": false
        }],
        "durable_dir_chirho": "/tmp/cairn-no-mint-raft-chirho",
        "sign_root_chirho": sign_root_chirho.display().to_string(),
        "listen_addr_chirho": "127.0.0.1:3001",
        "tick_ms_chirho": 50,
        "roster_authority_chirho": {
            "roster_path_chirho": "/tmp/roster-no-mint-chirho.jsonl",
            "roster_head_path_chirho": "/tmp/roster-head-no-mint-chirho.json",
            "operator_pubkey_hex_chirho": "b".repeat(64)
        },
        "membership_control_chirho": {
            "operator_token_env_chirho": "TEST_OPERATOR_TOKEN_NO_MINT_CHIRHO",
            "target_authority_chirho": {"kind_chirho": "roster_wide"}
        }
    }))
    .unwrap()
}

/// Provision a node pair explicitly, at this setup boundary, through the signer's own creation road.
fn provisioned_sign_root_chirho(parent_chirho: &Path) -> (PathBuf, String) {
    let sign_root_chirho = parent_chirho.join("node-sign-chirho");
    cairn_signer_chirho::signer_chirho::sign_message_chirho(
        &sign_root_chirho,
        b"provision-node-chirho",
    )
    .unwrap();
    let pubkey_chirho =
        cairn_signer_chirho::signer_chirho::existing_keypair_pubkey_hex_chirho(&sign_root_chirho)
            .unwrap();
    (sign_root_chirho, pubkey_chirho)
}

/// Every entry under `path_chirho`, with its mode and bytes, so an arm can show the load wrote, repaired and
/// chmodded nothing. An absent path snapshots as empty.
fn snapshot_chirho(path_chirho: &Path) -> BTreeMap<PathBuf, (u32, Vec<u8>)> {
    let mut entries_chirho = BTreeMap::new();
    let Ok(listing_chirho) = std::fs::read_dir(path_chirho) else {
        return entries_chirho;
    };
    for entry_chirho in listing_chirho {
        let entry_path_chirho = entry_chirho.unwrap().path();
        let metadata_chirho = std::fs::symlink_metadata(&entry_path_chirho).unwrap();
        let bytes_chirho = if metadata_chirho.is_file() {
            std::fs::read(&entry_path_chirho).unwrap()
        } else {
            Vec::new()
        };
        entries_chirho.insert(
            entry_path_chirho,
            (metadata_chirho.permissions().mode(), bytes_chirho),
        );
    }
    entries_chirho
}

/// Load, require a refusal through the existing-pair read for `reason_chirho`, and require the sign root
/// unchanged.
fn assert_refused_without_change_chirho(sign_root_chirho: &Path, reason_chirho: &str) {
    let before_chirho = snapshot_chirho(sign_root_chirho);
    let existed_chirho = sign_root_chirho.exists();
    let error_chirho = match parse_cluster_node_file_config_chirho(&membership_config_bytes_chirho(
        sign_root_chirho,
    )) {
        Ok(_loaded_chirho) => {
            panic!("a config load must not succeed without an existing safe pair")
        }
        Err(error_chirho) => format!("{error_chirho:#}"),
    };
    assert!(
        error_chirho.contains(LOAD_CONTEXT_CHIRHO),
        "refused elsewhere: {error_chirho}"
    );
    assert!(
        error_chirho.contains(reason_chirho),
        "wrong reason, wanted {reason_chirho}: {error_chirho}"
    );
    assert_eq!(
        sign_root_chirho.exists(),
        existed_chirho,
        "the load created or removed the sign root"
    );
    assert_eq!(
        snapshot_chirho(sign_root_chirho),
        before_chirho,
        "the load changed the sign root"
    );
}

#[test]
fn an_absent_sign_root_refuses_and_is_not_created_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    assert_refused_without_change_chirho(
        &temp_chirho.path().join("never-provisioned-chirho"),
        "inspect existing signing-key root",
    );
}

#[test]
fn an_empty_sign_root_refuses_and_gains_no_key_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let sign_root_chirho = temp_chirho.path().join("empty-sign-chirho");
    std::fs::create_dir(&sign_root_chirho).unwrap();
    assert_refused_without_change_chirho(&sign_root_chirho, "open existing private signing key");
}

#[test]
fn a_partial_pair_refuses_without_repair_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let (sign_root_chirho, _pubkey_chirho) = provisioned_sign_root_chirho(temp_chirho.path());
    std::fs::remove_file(sign_root_chirho.join(PUBKEY_FILE_CHIRHO)).unwrap();
    assert_refused_without_change_chirho(&sign_root_chirho, "open existing public signing key");
}

#[test]
fn an_unsafe_seed_mode_refuses_without_chmod_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let (sign_root_chirho, _pubkey_chirho) = provisioned_sign_root_chirho(temp_chirho.path());
    std::fs::set_permissions(
        sign_root_chirho.join(SEED_FILE_CHIRHO),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert_refused_without_change_chirho(&sign_root_chirho, "mode must be exactly 0400 or 0600");
}

#[test]
fn a_mismatched_pair_refuses_without_replacing_the_public_key_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let (sign_root_chirho, pubkey_chirho) = provisioned_sign_root_chirho(temp_chirho.path());
    let (_other_root_chirho, other_pubkey_chirho) =
        provisioned_sign_root_chirho(&temp_chirho.path().join("other-chirho"));
    assert_ne!(pubkey_chirho, other_pubkey_chirho);
    let pubkey_path_chirho = sign_root_chirho.join(PUBKEY_FILE_CHIRHO);
    let mode_chirho = std::fs::metadata(&pubkey_path_chirho)
        .unwrap()
        .permissions()
        .mode();
    std::fs::write(&pubkey_path_chirho, &other_pubkey_chirho).unwrap();
    std::fs::set_permissions(
        &pubkey_path_chirho,
        std::fs::Permissions::from_mode(mode_chirho),
    )
    .unwrap();
    assert_refused_without_change_chirho(
        &sign_root_chirho,
        "existing signing key pair does not agree",
    );
}

/// The positive control: an explicitly provisioned pair loads, names that pair's key, and the load changes
/// nothing on disk.
#[test]
fn a_provisioned_pair_loads_its_own_key_and_changes_nothing_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let (sign_root_chirho, pubkey_chirho) = provisioned_sign_root_chirho(temp_chirho.path());
    let before_chirho = snapshot_chirho(&sign_root_chirho);
    let loaded_chirho =
        parse_cluster_node_file_config_chirho(&membership_config_bytes_chirho(&sign_root_chirho))
            .unwrap();
    assert_eq!(
        loaded_chirho
            .cluster_chirho
            .membership_control_chirho
            .expect("membership control loads")
            .local_node_pubkey_hex_chirho,
        pubkey_chirho
    );
    assert_eq!(
        snapshot_chirho(&sign_root_chirho),
        before_chirho,
        "a good load changed the sign root"
    );
}
