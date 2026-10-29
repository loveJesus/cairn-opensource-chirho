// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Typed object persistence over the content-addressed store.
//!
//! `cas_chirho` stores raw bytes; this layer stores *typed* objects — `NodeDefChirho`,
//! `DagChirho`, `RunKeyChirho`, `RunResultChirho` — by serializing each to a
//! deterministic byte form and content-addressing that. Identical objects therefore
//! land on identical hashes, which is the whole foundation: caching, versioning, and
//! audit are three views of one content-addressed Merkle DAG.
//!
//! Determinism note: encoding is `serde_json`. It is deterministic *for our types*
//! because struct fields serialize in declaration order and every map in the contract
//! is a `BTreeMap` (already key-ordered). We do not rely on cross-type canonicality.

use crate::cas_chirho;
use crate::model_chirho::HashChirho;
use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;

/// Deterministic byte encoding of an object (see the determinism note above).
fn encode_chirho<T: Serialize>(value_chirho: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value_chirho).context("encode object to canonical bytes")
}

/// Content-address an object *without* storing it — for run-key and capability hashing.
pub fn hash_object_chirho<T: Serialize>(value_chirho: &T) -> Result<HashChirho> {
    Ok(cas_chirho::hash_chirho(&encode_chirho(value_chirho)?))
}

/// Serialize an object to its canonical bytes and add it to the store. Idempotent:
/// the returned hash equals `hash_object_chirho(value)`.
pub fn put_object_chirho<T: Serialize>(root_chirho: &Path, value_chirho: &T) -> Result<HashChirho> {
    let bytes_chirho = encode_chirho(value_chirho)?;
    Ok(cas_chirho::add_chirho(root_chirho, &bytes_chirho)?)
}

/// Load and deserialize an object by its content address.
pub fn get_object_chirho<T: DeserializeOwned>(
    root_chirho: &Path,
    addr_chirho: &HashChirho,
) -> Result<T> {
    let bytes_chirho = cas_chirho::get_chirho(root_chirho, addr_chirho)
        .with_context(|| format!("object {} not in store", addr_chirho.0))?;
    serde_json::from_slice(&bytes_chirho)
        .with_context(|| format!("decode object {}", addr_chirho.0))
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use crate::model_chirho::RunKeyChirho;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// A unique scratch store root under the OS temp dir.
    fn tmp_root_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-store-test-{nanos_chirho}-{n_chirho}"))
    }

    fn sample_key_chirho() -> RunKeyChirho {
        let mut inputs_chirho = BTreeMap::new();
        inputs_chirho.insert("x".to_string(), HashChirho("aaaa".to_string()));
        RunKeyChirho {
            node_chirho: HashChirho("node-hash".to_string()),
            inputs_chirho,
            caps_chirho: HashChirho("caps-hash".to_string()),
        }
    }

    #[test]
    fn hash_is_stable_and_distinguishes_chirho() {
        let key_chirho = sample_key_chirho();
        // Same object ⇒ same hash (the cache-key invariant).
        assert_eq!(
            hash_object_chirho(&key_chirho).unwrap(),
            hash_object_chirho(&key_chirho).unwrap()
        );
        // A different object ⇒ a different hash.
        let mut other_chirho = key_chirho.clone();
        other_chirho.node_chirho = HashChirho("different".to_string());
        assert_ne!(
            hash_object_chirho(&key_chirho).unwrap(),
            hash_object_chirho(&other_chirho).unwrap()
        );
    }

    #[test]
    fn put_then_get_round_trips_chirho() {
        let root_chirho = tmp_root_chirho();
        let key_chirho = sample_key_chirho();

        let stored_chirho = put_object_chirho(&root_chirho, &key_chirho).unwrap();
        // The stored address is exactly the content hash.
        assert_eq!(stored_chirho, hash_object_chirho(&key_chirho).unwrap());

        let back_chirho: RunKeyChirho = get_object_chirho(&root_chirho, &stored_chirho).unwrap();
        assert_eq!(back_chirho, key_chirho);

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn get_object_rejects_tampered_address_body_chirho() {
        let root_chirho = tmp_root_chirho();
        let key_chirho = sample_key_chirho();
        let stored_chirho = put_object_chirho(&root_chirho, &key_chirho).unwrap();
        std::fs::write(
            cas_chirho::object_path_chirho(&root_chirho, &stored_chirho),
            serde_json::to_vec(&RunKeyChirho {
                node_chirho: HashChirho("tampered-node".to_string()),
                ..key_chirho
            })
            .unwrap(),
        )
        .unwrap();

        let error_chirho =
            get_object_chirho::<RunKeyChirho>(&root_chirho, &stored_chirho).unwrap_err();
        assert!(format!("{error_chirho:#}").contains("content address mismatch"));

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
