// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Arms for the run key's store: a cache hit leaves an equal key untouched, and an absent or
//! different key is still written, as before.

use super::*;
use crate::model_chirho::PortChirho;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DOUBLE_WAT_CHIRHO: &str = r#"
    (module
      (func (export "double_chirho") (param i64) (result i64)
        local.get 0
        i64.const 2
        i64.mul))
"#;

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-run-key-test-{nanos_chirho}-{n_chirho}"))
}

fn double_node_chirho() -> (NodeDefChirho, HashChirho) {
    let node_chirho = NodeDefChirho {
        name_chirho: "double_chirho".to_string(),
        impl_wasm_chirho: HashChirho("wasm-placeholder".to_string()),
        entry_chirho: "double_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "x".to_string(),
            schema_chirho: HashChirho("i64".to_string()),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("i64".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::hash_object_chirho(&node_chirho).unwrap();
    (node_chirho, node_hash_chirho)
}

/// Runs the node once (a miss), and returns the root and the path and bytes of the key it stored.
fn missed_run_chirho() -> (PathBuf, NodeDefChirho, HashChirho, PathBuf, Vec<u8>) {
    let root_chirho = tmp_root_chirho();
    let (node_chirho, node_hash_chirho) = double_node_chirho();
    let (result_chirho, hit_chirho) = run_node_cached_chirho(
        &root_chirho,
        &node_chirho,
        &node_hash_chirho,
        DOUBLE_WAT_CHIRHO.as_bytes(),
        21,
    )
    .unwrap();
    assert!(!hit_chirho);
    let key_path_chirho = run_key_path_chirho(&root_chirho, &result_chirho.run_chirho);
    let key_bytes_chirho = std::fs::read(&key_path_chirho).unwrap();
    (
        root_chirho,
        node_chirho,
        node_hash_chirho,
        key_path_chirho,
        key_bytes_chirho,
    )
}

fn hit_chirho(root_chirho: &Path, node_chirho: &NodeDefChirho, node_hash_chirho: &HashChirho) {
    let (_, hit_chirho) = run_node_cached_chirho(
        root_chirho,
        node_chirho,
        node_hash_chirho,
        DOUBLE_WAT_CHIRHO.as_bytes(),
        21,
    )
    .unwrap();
    assert!(hit_chirho, "the second run is a cache hit");
}

#[test]
fn a_cache_hit_leaves_an_equal_run_key_untouched_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    let before_chirho = std::fs::metadata(&key_path_chirho).unwrap();
    // A rewrite would give the key a new inode and modification time; give the clock room to show
    // it.
    std::thread::sleep(Duration::from_millis(20));
    hit_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    let after_chirho = std::fs::metadata(&key_path_chirho).unwrap();
    assert_eq!(before_chirho.ino(), after_chirho.ino());
    assert_eq!(
        (before_chirho.mtime(), before_chirho.mtime_nsec()),
        (after_chirho.mtime(), after_chirho.mtime_nsec()),
        "an equal key is not rewritten on a cache hit"
    );
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_cache_hit_stores_an_absent_run_key_again_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    std::fs::remove_file(&key_path_chirho).unwrap();
    hit_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_cache_hit_rewrites_a_different_run_key_of_the_same_length_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    let mut different_chirho = key_bytes_chirho.clone();
    let last_chirho = different_chirho.len() - 1;
    different_chirho[last_chirho] ^= 0x20;
    assert_ne!(different_chirho, key_bytes_chirho);
    std::fs::write(&key_path_chirho, &different_chirho).unwrap();
    hit_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_cache_hit_rewrites_a_longer_run_key_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    let mut longer_chirho = key_bytes_chirho.clone();
    longer_chirho.extend_from_slice(b"\n");
    std::fs::write(&key_path_chirho, &longer_chirho).unwrap();
    hit_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// Runs the cache hit on a worker thread and fails if it does not return within the deadline.
fn hit_within_deadline_chirho(
    root_chirho: &Path,
    node_chirho: &NodeDefChirho,
    node_hash_chirho: &HashChirho,
) {
    let (sender_chirho, receiver_chirho) = mpsc::channel();
    let (root_chirho, node_chirho, node_hash_chirho) = (
        root_chirho.to_path_buf(),
        node_chirho.clone(),
        node_hash_chirho.clone(),
    );
    std::thread::spawn(move || {
        let hit_chirho = run_node_cached_chirho(
            &root_chirho,
            &node_chirho,
            &node_hash_chirho,
            DOUBLE_WAT_CHIRHO.as_bytes(),
            21,
        )
        .map(|(_, hit_chirho)| hit_chirho);
        let _sent_chirho =
            sender_chirho.send(hit_chirho.map_err(|error_chirho| error_chirho.to_string()));
    });
    let hit_chirho = receiver_chirho
        .recv_timeout(Duration::from_secs(10))
        .expect("the cache hit blocked past its deadline")
        .unwrap();
    assert!(hit_chirho, "the second run is a cache hit");
}

#[test]
fn a_cache_hit_replaces_a_symlinked_run_key_and_leaves_its_target_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    // The key itself moves aside and a symlink to it takes its name, so following the link would find
    // the canonical bytes: only a comparison that follows no symlink rewrites it.
    let target_chirho = root_chirho.join("key-moved-aside-chirho");
    std::fs::rename(&key_path_chirho, &target_chirho).unwrap();
    std::os::unix::fs::symlink(&target_chirho, &key_path_chirho).unwrap();
    hit_within_deadline_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    assert!(
        std::fs::symlink_metadata(&key_path_chirho)
            .unwrap()
            .is_file(),
        "the key is a regular file again"
    );
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    assert_eq!(
        std::fs::read(&target_chirho).unwrap(),
        key_bytes_chirho,
        "the symlink's target is unchanged"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn a_cache_hit_replaces_a_fifo_run_key_without_blocking_chirho() {
    let (root_chirho, node_chirho, node_hash_chirho, key_path_chirho, key_bytes_chirho) =
        missed_run_chirho();
    std::fs::remove_file(&key_path_chirho).unwrap();
    let status_chirho = std::process::Command::new("mkfifo")
        .arg(&key_path_chirho)
        .status()
        .unwrap();
    assert!(status_chirho.success(), "mkfifo failed");
    hit_within_deadline_chirho(&root_chirho, &node_chirho, &node_hash_chirho);
    assert!(
        std::fs::symlink_metadata(&key_path_chirho)
            .unwrap()
            .is_file(),
        "the key is a regular file again"
    );
    assert_eq!(std::fs::read(&key_path_chirho).unwrap(), key_bytes_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}
