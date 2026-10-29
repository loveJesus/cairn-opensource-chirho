// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Browser **localStorage** `ContentStoreChirho` + `AuditLogChirho` adapters. localStorage is
//! *synchronous*, so these implement the existing sync ports directly — **no async refactor**. The
//! logic is generic over a tiny [`KvChirho`]: real localStorage on `wasm32` (feature
//! `browser-chirho`, `LocalStorageKvChirho`); an in-memory map for native `cargo test`
//! ([`MemoryKvChirho`]), so the adapter LOGIC is verified without a browser.
//!
//! Honest scope (per the design review):
//! - **Synchronous, small-value, main-thread** storage — for proof / local-first snapshots, not
//!   high-throughput data.
//! - **Honest-client only — NO adversarial integrity.** The user controls the browser (keys,
//!   storage, the wasm), so this is tamper-evident-*to-self* local-first computation, not a trust
//!   boundary against the user. The server adapters are the adversarial-verification tier.
//! - **Best-effort heads:** the audit log is fork-tolerant + single-writer-per-id with NO cross-tab
//!   lock. Concurrent tabs may race on a writer's head pointer; records stay content-addressed and
//!   recoverable, but `heads_chirho` returns the *observed* tips, not a globally-serialized truth.
//! - A **namespace** prefixes every key, so multiple cairn apps in one origin don't collide.
//! - Quota / security failures surface as real `Err` from the ports.
//!
//! Later bricks: IndexedDB (async), async ports, Web Locks cross-tab serialization. Live browser
//! runs use the harness near `LocalStorageKvChirho`; the crate compiles to `wasm32-unknown-unknown`.

use anyhow::{anyhow, Result};
use base64::Engine as _;
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, verify_audit_record_hash_chirho, verify_content_address_chirho,
    AuditLogChirho, AuditRecordChirho, ContentReadChirho, ContentStoreChirho, StoreErrorChirho,
    StoreResultChirho,
};

const OBJ_INFIX_CHIRHO: &str = "obj-chirho/";
const RECORD_INFIX_CHIRHO: &str = "rec-chirho/";
const HEAD_INFIX_CHIRHO: &str = "head-chirho/";

fn b64_encode_chirho(bytes_chirho: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes_chirho)
}
fn b64_decode_chirho(text_chirho: &str) -> StoreResultChirho<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(text_chirho)
        .map_err(|error_chirho| StoreErrorChirho::backend_chirho(error_chirho.to_string()))
}

/// A minimal synchronous string key-value store — the localStorage shape. The adapters are generic
/// over it so the same logic runs on a real browser and in native tests.
pub trait KvChirho {
    fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>>;
    fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()>;
    /// Keys currently present that start with `prefix_chirho` (used to enumerate audit heads).
    fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>>;
}

/// Content-addressed store over any `KvChirho` (bytes are base64-encoded; the Kv holds strings).
/// Keys are `{namespace}obj-chirho/{hash}` so apps sharing one origin don't collide.
pub struct KvContentStoreChirho<K: KvChirho> {
    kv_chirho: K,
    namespace_chirho: String,
}

impl<K: KvChirho> KvContentStoreChirho<K> {
    /// `namespace_chirho` isolates this app's keys within a shared origin (e.g. "perffection/").
    pub fn new_chirho(kv_chirho: K, namespace_chirho: &str) -> Self {
        Self {
            kv_chirho,
            namespace_chirho: namespace_chirho.to_string(),
        }
    }
    fn key_chirho(&self, addr_chirho: &HashChirho) -> String {
        format!(
            "{}{OBJ_INFIX_CHIRHO}{}",
            self.namespace_chirho, addr_chirho.0
        )
    }
}

impl<K: KvChirho> ContentStoreChirho for KvContentStoreChirho<K> {
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        let addr_chirho = hash_chirho(bytes_chirho);
        let key_chirho = self.key_chirho(&addr_chirho);
        if self.kv_chirho.get_chirho(&key_chirho)?.is_none() {
            self.kv_chirho
                .set_chirho(&key_chirho, &b64_encode_chirho(bytes_chirho))?;
        }
        Ok(addr_chirho)
    }
}

impl<K: KvChirho> ContentReadChirho for KvContentStoreChirho<K> {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        match self.kv_chirho.get_chirho(&self.key_chirho(addr_chirho))? {
            Some(text_chirho) => {
                let bytes_chirho = b64_decode_chirho(&text_chirho)?;
                verify_content_address_chirho(addr_chirho, &bytes_chirho)?;
                Ok(Some(bytes_chirho))
            }
            None => Ok(None),
        }
    }
}

/// Fork-tolerant audit log over any `KvChirho`. Single-tab; no cross-tab lock (the fork-tolerant
/// design needs none). Keys are namespaced like the content store.
pub struct KvAuditLogChirho<K: KvChirho> {
    kv_chirho: K,
    namespace_chirho: String,
}

impl<K: KvChirho> KvAuditLogChirho<K> {
    pub fn new_chirho(kv_chirho: K, namespace_chirho: &str) -> Self {
        Self {
            kv_chirho,
            namespace_chirho: namespace_chirho.to_string(),
        }
    }

    fn head_prefix_chirho(&self) -> String {
        format!("{}{HEAD_INFIX_CHIRHO}", self.namespace_chirho)
    }
    fn head_key_chirho(&self, writer_chirho: &str) -> String {
        // hash the writer id for a safe, fixed-length key segment
        let writer_key_chirho = blake3::hash(writer_chirho.as_bytes()).to_hex().to_string();
        format!("{}{writer_key_chirho}", self.head_prefix_chirho())
    }
    fn record_key_chirho(&self, record_hash_chirho: &HashChirho) -> String {
        format!(
            "{}{RECORD_INFIX_CHIRHO}{}",
            self.namespace_chirho, record_hash_chirho.0
        )
    }

    fn read_record_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        match self
            .kv_chirho
            .get_chirho(&self.record_key_chirho(record_hash_chirho))?
        {
            Some(text_chirho) => {
                let record_chirho: AuditRecordChirho = serde_json::from_str(&text_chirho)?;
                verify_audit_record_hash_chirho(record_hash_chirho, &record_chirho)?;
                Ok(Some(record_chirho))
            }
            None => Ok(None),
        }
    }
}

impl<K: KvChirho> AuditLogChirho for KvAuditLogChirho<K> {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let head_key_chirho = self.head_key_chirho(writer_chirho);
        let prev_hash_chirho = self.kv_chirho.get_chirho(&head_key_chirho)?.map(HashChirho);
        let local_seq_chirho = match &prev_hash_chirho {
            Some(head_chirho) => {
                self.read_record_chirho(head_chirho)?
                    .ok_or_else(|| anyhow!("head record {} missing", head_chirho.0))?
                    .local_seq_chirho
                    + 1
            }
            None => 0,
        };
        let record_chirho = AuditRecordChirho::new_chirho(
            writer_chirho,
            local_seq_chirho,
            prev_hash_chirho,
            payload_chirho.to_vec(),
        );
        let record_hash_value_chirho = record_hash_chirho(&record_chirho)?;
        self.kv_chirho.set_chirho(
            &self.record_key_chirho(&record_hash_value_chirho),
            &serde_json::to_string(&record_chirho)?,
        )?;
        self.kv_chirho
            .set_chirho(&head_key_chirho, &record_hash_value_chirho.0)?;
        Ok(record_hash_value_chirho)
    }

    fn get_chirho(
        &self,
        record_hash_value_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        self.read_record_chirho(record_hash_value_chirho)
    }

    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let mut heads_chirho = Vec::new();
        for key_chirho in self
            .kv_chirho
            .keys_with_prefix_chirho(&self.head_prefix_chirho())?
        {
            if let Some(hex_chirho) = self.kv_chirho.get_chirho(&key_chirho)? {
                heads_chirho.push(HashChirho(hex_chirho));
            }
        }
        Ok(heads_chirho)
    }
}

/// In-memory `KvChirho` — the native-test backend (and a usable ephemeral Kv anywhere).
#[derive(Default)]
pub struct MemoryKvChirho {
    map_chirho: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl MemoryKvChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }
}

impl KvChirho for MemoryKvChirho {
    fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
        Ok(self
            .map_chirho
            .lock()
            .map_err(|_| anyhow!("memory kv poisoned"))?
            .get(key_chirho)
            .cloned())
    }
    fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
        self.map_chirho
            .lock()
            .map_err(|_| anyhow!("memory kv poisoned"))?
            .insert(key_chirho.to_string(), value_chirho.to_string());
        Ok(())
    }
    fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
        Ok(self
            .map_chirho
            .lock()
            .map_err(|_| anyhow!("memory kv poisoned"))?
            .keys()
            .filter(|k| k.starts_with(prefix_chirho))
            .cloned()
            .collect())
    }
}

/// Real browser `localStorage` `KvChirho` — only compiled with the `browser-chirho` feature on
/// `wasm32` (it needs the wasm-bindgen/web-sys toolchain).
#[cfg(all(target_arch = "wasm32", feature = "browser-chirho"))]
pub struct LocalStorageKvChirho;

#[cfg(all(target_arch = "wasm32", feature = "browser-chirho"))]
impl LocalStorageKvChirho {
    fn storage_chirho() -> Result<web_sys::Storage> {
        web_sys::window()
            .ok_or_else(|| anyhow!("no window (not a browser context)"))?
            .local_storage()
            .map_err(|_| anyhow!("localStorage access denied"))?
            .ok_or_else(|| anyhow!("localStorage unavailable"))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "browser-chirho"))]
impl KvChirho for LocalStorageKvChirho {
    fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
        Self::storage_chirho()?
            .get_item(key_chirho)
            .map_err(|_| anyhow!("localStorage getItem failed"))
    }
    fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
        Self::storage_chirho()?
            .set_item(key_chirho, value_chirho)
            .map_err(|_| anyhow!("localStorage setItem failed (quota or security error)"))
    }
    fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
        let storage_chirho = Self::storage_chirho()?;
        let len_chirho = storage_chirho
            .length()
            .map_err(|_| anyhow!("localStorage length failed"))?;
        let mut keys_chirho = Vec::new();
        for i_chirho in 0..len_chirho {
            if let Ok(Some(key_chirho)) = storage_chirho.key(i_chirho) {
                if key_chirho.starts_with(prefix_chirho) {
                    keys_chirho.push(key_chirho);
                }
            }
        }
        Ok(keys_chirho)
    }
}

// BROWSER-HARNESS: build this crate to wasm with the `browser-chirho` feature (wasm-pack / trunk),
// then in the browser:
//   let cs = KvContentStoreChirho::new_chirho(LocalStorageKvChirho, "myapp/");
//   let al = KvAuditLogChirho::new_chirho(LocalStorageKvChirho, "myapp/");
// and drive cairn-runtime-core's run_linear_dag_chirho over them exactly as the native tests drive
// it over MemoryKvChirho — identical hashes/provenance, persisted in window.localStorage.

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::ports_chirho::StoreErrorKindChirho;
    use cairn_store_memory_chirho::{MemoryAuditLogChirho, MemoryContentStoreChirho};

    const NS_CHIRHO: &str = "test-app-chirho/";

    #[test]
    fn content_round_trip_and_idempotent_chirho() {
        let store_chirho =
            KvContentStoreChirho::new_chirho(MemoryKvChirho::new_chirho(), NS_CHIRHO);
        let addr_chirho = store_chirho.put_chirho(b"love Jesus").unwrap();
        assert_eq!(
            store_chirho.get_chirho(&addr_chirho).unwrap().as_deref(),
            Some(&b"love Jesus"[..])
        );
        assert_eq!(store_chirho.put_chirho(b"love Jesus").unwrap(), addr_chirho);
        assert!(store_chirho
            .get_chirho(&hash_chirho(b"absent"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn content_read_rejects_tampered_address_body_chirho() {
        let kv_chirho = std::rc::Rc::new(MemoryKvChirho::new_chirho());
        let store_chirho =
            KvContentStoreChirho::new_chirho(RcKvChirho(kv_chirho.clone()), NS_CHIRHO);
        let addr_chirho = store_chirho.put_chirho(b"love Jesus").unwrap();
        kv_chirho
            .set_chirho(
                &format!("{NS_CHIRHO}{OBJ_INFIX_CHIRHO}{}", addr_chirho.0),
                &b64_encode_chirho(b"tampered"),
            )
            .unwrap();

        let error_chirho = store_chirho.get_chirho(&addr_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("content address mismatch"));
    }

    #[test]
    fn audit_chain_and_heads_chirho() {
        let log_chirho = KvAuditLogChirho::new_chirho(MemoryKvChirho::new_chirho(), NS_CHIRHO);
        let h0_chirho = log_chirho.append_chirho("w-chirho", b"one").unwrap();
        let h1_chirho = log_chirho.append_chirho("w-chirho", b"two").unwrap();
        let r1_chirho = log_chirho.get_chirho(&h1_chirho).unwrap().unwrap();
        assert_eq!(r1_chirho.local_seq_chirho, 1);
        assert_eq!(r1_chirho.prev_hash_chirho, Some(h0_chirho));
        assert_eq!(log_chirho.heads_chirho().unwrap(), vec![h1_chirho]);
    }

    #[test]
    fn audit_read_rejects_tampered_record_body_chirho() {
        let kv_chirho = std::rc::Rc::new(MemoryKvChirho::new_chirho());
        let log_chirho = KvAuditLogChirho::new_chirho(RcKvChirho(kv_chirho.clone()), NS_CHIRHO);
        let head_chirho = log_chirho.append_chirho("w-chirho", b"one").unwrap();
        let tampered_chirho =
            AuditRecordChirho::new_chirho("w-chirho", 0, None, b"tampered".to_vec());
        kv_chirho
            .set_chirho(
                &format!("{NS_CHIRHO}{RECORD_INFIX_CHIRHO}{}", head_chirho.0),
                &serde_json::to_string(&tampered_chirho).unwrap(),
            )
            .unwrap();

        let error_chirho = log_chirho.get_chirho(&head_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("audit record hash mismatch"));
    }

    #[test]
    fn namespaces_do_not_collide_chirho() {
        // Two apps sharing one Kv (origin) must not see each other's heads.
        let kv_chirho = std::rc::Rc::new(MemoryKvChirho::new_chirho());
        let a_chirho = KvAuditLogChirho::new_chirho(RcKvChirho(kv_chirho.clone()), "app-a/");
        let b_chirho = KvAuditLogChirho::new_chirho(RcKvChirho(kv_chirho.clone()), "app-b/");
        a_chirho.append_chirho("w-chirho", b"a-only").unwrap();
        assert_eq!(a_chirho.heads_chirho().unwrap().len(), 1);
        assert_eq!(
            b_chirho.heads_chirho().unwrap().len(),
            0,
            "namespace leak between apps"
        );
    }

    /// The localStorage (Kv) adapter must produce byte-for-byte IDENTICAL content hashes and audit
    /// records to the memory/fs adapters — proving it is a faithful backend behind the same ports.
    /// (The namespace only affects storage keys, never the content-addressed hashes.)
    #[test]
    fn identical_to_memory_adapter_chirho() {
        let kv_cs_chirho =
            KvContentStoreChirho::new_chirho(MemoryKvChirho::new_chirho(), NS_CHIRHO);
        let kv_al_chirho = KvAuditLogChirho::new_chirho(MemoryKvChirho::new_chirho(), NS_CHIRHO);
        let mem_cs_chirho = MemoryContentStoreChirho::new_chirho();
        let mem_al_chirho = MemoryAuditLogChirho::new_chirho();

        assert_eq!(
            kv_cs_chirho.put_chirho(b"love Jesus").unwrap(),
            mem_cs_chirho.put_chirho(b"love Jesus").unwrap(),
            "content hash differs between localStorage-Kv and memory adapters"
        );
        assert_eq!(
            kv_al_chirho
                .append_chirho("runner-chirho", b"prov")
                .unwrap(),
            mem_al_chirho
                .append_chirho("runner-chirho", b"prov")
                .unwrap(),
            "audit head differs between localStorage-Kv and memory adapters"
        );
    }

    /// Lets two adapters share one in-memory Kv in a test (for the namespace-isolation check).
    struct RcKvChirho(std::rc::Rc<MemoryKvChirho>);
    impl KvChirho for RcKvChirho {
        fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
            self.0.get_chirho(key_chirho)
        }
        fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
            self.0.set_chirho(key_chirho, value_chirho)
        }
        fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
            self.0.keys_with_prefix_chirho(prefix_chirho)
        }
    }
}
