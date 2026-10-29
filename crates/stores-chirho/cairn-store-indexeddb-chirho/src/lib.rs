// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Browser **IndexedDB** `ContentStore` + `AuditLog` adapters for cairn — the **async** successor to
//! the synchronous localStorage tier (M35.4). IndexedDB and the Web Locks API are Promise-based, so
//! these implement the **async** ports (`ContentStoreAsyncChirho` / `AuditLogAsyncChirho` from
//! cairn-core, landed in M35.6a). The logic is generic over a tiny [`KvAsyncChirho`]: real IndexedDB
//! on `wasm32` (feature `browser-chirho`, `IdbKvChirho`); an in-memory async map for native
//! `cargo test` ([`MemoryKvAsyncChirho`]), so the adapter LOGIC is verified without a browser.
//!
//! Honest scope (per the design review + M35.4's candor):
//! - **Async, browser-local** storage for local-first snapshots, not a high-throughput data tier.
//! - **Honest-client only — NO adversarial integrity.** The user controls the browser (keys,
//!   storage, the wasm), so this is tamper-evident-*to-self* local-first computation, not a trust
//!   boundary against the user. The server adapters are the adversarial-verification tier.
//! - **Single-tab correct; cross-tab serialization via `with_web_lock_chirho`** (Web Locks). The
//!   generic adapter stays lock-free + portable; a browser composition root wraps the critical
//!   section in the lock when it needs cross-tab ordering. Records stay content-addressed +
//!   recoverable either way; `heads_chirho` returns observed tips, never a global total order.
//! - A **namespace** prefixes every key so multiple cairn apps in one origin don't collide.
//!
//! The ~2x wasm ceremony (the IndexedDB request→future bridge and Web Locks) is isolated in the
//! wasm-only `idb_chirho` module; the generic adapter + native mock below stay small and readable.

use anyhow::{anyhow, Result};
use base64::Engine as _;
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, verify_audit_record_hash_chirho, verify_content_address_chirho,
    AuditLogAsyncChirho, AuditRecordChirho, ContentStoreAsyncChirho, StoreErrorChirho,
    StoreResultChirho,
};
use core::future::Future;

#[cfg(all(target_arch = "wasm32", feature = "browser-chirho"))]
mod idb_chirho;
#[cfg(all(target_arch = "wasm32", feature = "browser-chirho"))]
pub use idb_chirho::{locked_idb_append_chirho, with_web_lock_chirho, IdbKvChirho};

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

/// A minimal **async** string key-value store — the IndexedDB shape (the async analog of the
/// localStorage adapter's `KvChirho`). The adapters are generic over it so the same logic runs on
/// real IndexedDB and in native tests. Return-position `impl Future` (not bare `async fn`) keeps the
/// public trait clear of the `async_fn_in_trait` lint under `-D warnings` and imposes no `Send` bound
/// (single-threaded wasm).
pub trait KvAsyncChirho {
    fn get_chirho(&self, key_chirho: &str) -> impl Future<Output = Result<Option<String>>>;
    fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> impl Future<Output = Result<()>>;
    /// Keys currently present that start with `prefix_chirho` (used to enumerate audit heads).
    fn keys_with_prefix_chirho(
        &self,
        prefix_chirho: &str,
    ) -> impl Future<Output = Result<Vec<String>>>;
}

/// Content-addressed store over any `KvAsyncChirho` (bytes base64-encoded; the Kv holds strings).
/// Keys are `{namespace}obj-chirho/{hash}` so apps sharing one origin don't collide.
pub struct KvAsyncContentStoreChirho<K: KvAsyncChirho> {
    kv_chirho: K,
    namespace_chirho: String,
}

impl<K: KvAsyncChirho> KvAsyncContentStoreChirho<K> {
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

// `async fn` in the impl satisfies the trait's return-position `impl Future` — idiomatic, and avoids
// the manual-async-fn churn while keeping the public trait lint-clean.
impl<K: KvAsyncChirho> ContentStoreAsyncChirho for KvAsyncContentStoreChirho<K> {
    async fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        let addr_chirho = hash_chirho(bytes_chirho);
        let key_chirho = self.key_chirho(&addr_chirho);
        if self.kv_chirho.get_chirho(&key_chirho).await?.is_none() {
            self.kv_chirho
                .set_chirho(&key_chirho, &b64_encode_chirho(bytes_chirho))
                .await?;
        }
        Ok(addr_chirho)
    }
    async fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        match self
            .kv_chirho
            .get_chirho(&self.key_chirho(addr_chirho))
            .await?
        {
            Some(text_chirho) => {
                let bytes_chirho = b64_decode_chirho(&text_chirho)?;
                verify_content_address_chirho(addr_chirho, &bytes_chirho)?;
                Ok(Some(bytes_chirho))
            }
            None => Ok(None),
        }
    }
}

/// Fork-tolerant audit log over any `KvAsyncChirho` (async analog of the localStorage adapter).
/// Keys are namespaced like the content store; the per-writer head pointer chains records.
pub struct KvAsyncAuditLogChirho<K: KvAsyncChirho> {
    kv_chirho: K,
    namespace_chirho: String,
}

impl<K: KvAsyncChirho> KvAsyncAuditLogChirho<K> {
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
    async fn read_record_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        match self
            .kv_chirho
            .get_chirho(&self.record_key_chirho(record_hash_chirho))
            .await?
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

impl<K: KvAsyncChirho> AuditLogAsyncChirho for KvAsyncAuditLogChirho<K> {
    async fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let head_key_chirho = self.head_key_chirho(writer_chirho);
        let prev_hash_chirho = self
            .kv_chirho
            .get_chirho(&head_key_chirho)
            .await?
            .map(HashChirho);
        let local_seq_chirho = match &prev_hash_chirho {
            Some(head_chirho) => {
                self.read_record_chirho(head_chirho)
                    .await?
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
        self.kv_chirho
            .set_chirho(
                &self.record_key_chirho(&record_hash_value_chirho),
                &serde_json::to_string(&record_chirho)?,
            )
            .await?;
        self.kv_chirho
            .set_chirho(&head_key_chirho, &record_hash_value_chirho.0)
            .await?;
        Ok(record_hash_value_chirho)
    }

    async fn get_chirho(
        &self,
        record_hash_value_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        self.read_record_chirho(record_hash_value_chirho).await
    }

    async fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let mut heads_chirho = Vec::new();
        for key_chirho in self
            .kv_chirho
            .keys_with_prefix_chirho(&self.head_prefix_chirho())
            .await?
        {
            if let Some(hex_chirho) = self.kv_chirho.get_chirho(&key_chirho).await? {
                heads_chirho.push(HashChirho(hex_chirho));
            }
        }
        Ok(heads_chirho)
    }
}

/// In-memory async `KvAsyncChirho` — the native-test backend (and a usable ephemeral async Kv). The
/// bodies are synchronous under a `Mutex`; the futures are simply already-ready.
#[derive(Default)]
pub struct MemoryKvAsyncChirho {
    map_chirho: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
}

impl MemoryKvAsyncChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }
}

impl KvAsyncChirho for MemoryKvAsyncChirho {
    async fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
        Ok(self
            .map_chirho
            .lock()
            .map_err(|_| anyhow!("memory kv poisoned"))?
            .get(key_chirho)
            .cloned())
    }
    async fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
        self.map_chirho
            .lock()
            .map_err(|_| anyhow!("memory kv poisoned"))?
            .insert(key_chirho.to_string(), value_chirho.to_string());
        Ok(())
    }
    async fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
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

// BROWSER HARNESS (feature `browser-chirho`, built to wasm via wasm-pack / trunk): in the browser,
//   let cs_kv = IdbKvChirho::open_chirho("cairn-app-chirho", "kv-chirho").await?;
//   let al_kv = IdbKvChirho::open_chirho("cairn-app-chirho", "kv-chirho").await?;
//   let cs = KvAsyncContentStoreChirho::new_chirho(cs_kv, "myapp/");
//   let al = KvAsyncAuditLogChirho::new_chirho(al_kv, "myapp/");
// then drive cairn-runtime-core's run_linear_dag_async_chirho over them exactly as the native test
// `dag_runs_identically_sync_vs_async_idb_mock_chirho` drives it over MemoryKvAsyncChirho — identical
// hashes/provenance, persisted in IndexedDB. For cross-tab append serialization, perform appends via
//   locked_idb_append_chirho(kv, "myapp/", "myapp-audit", writer, payload).await?;
// which wraps a real audit append in with_web_lock_chirho (the generic append stays lock-free).

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::ports_chirho::{
        AuditLogChirho, ContentStoreChirho, StoreErrorKindChirho,
    };
    use cairn_store_memory_chirho::{MemoryAuditLogChirho, MemoryContentStoreChirho};

    const NS_CHIRHO: &str = "test-app-chirho/";

    /// A tiny dependency-free `block_on`: the mock Kv futures are always Ready, so one poll
    /// completes them. `Waker::noop()` is stable since Rust 1.85 (toolchain is 1.93).
    fn block_on_chirho<F: core::future::Future>(future_chirho: F) -> F::Output {
        use core::task::{Context, Poll, Waker};
        let mut pinned_chirho = Box::pin(future_chirho);
        let mut cx_chirho = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out_chirho) = pinned_chirho.as_mut().poll(&mut cx_chirho) {
                return out_chirho;
            }
        }
    }

    #[test]
    fn content_round_trip_and_idempotent_chirho() {
        block_on_chirho(async {
            let store_chirho =
                KvAsyncContentStoreChirho::new_chirho(MemoryKvAsyncChirho::new_chirho(), NS_CHIRHO);
            let addr_chirho = store_chirho.put_chirho(b"love Jesus").await.unwrap();
            assert_eq!(
                store_chirho
                    .get_chirho(&addr_chirho)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(&b"love Jesus"[..])
            );
            assert_eq!(
                store_chirho.put_chirho(b"love Jesus").await.unwrap(),
                addr_chirho
            );
            assert!(store_chirho
                .get_chirho(&hash_chirho(b"absent"))
                .await
                .unwrap()
                .is_none());
        });
    }

    #[test]
    fn content_read_rejects_tampered_address_body_chirho() {
        block_on_chirho(async {
            let kv_chirho = std::rc::Rc::new(MemoryKvAsyncChirho::new_chirho());
            let store_chirho = KvAsyncContentStoreChirho::new_chirho(
                RcKvAsyncChirho(kv_chirho.clone()),
                NS_CHIRHO,
            );
            let addr_chirho = store_chirho.put_chirho(b"love Jesus").await.unwrap();
            kv_chirho
                .set_chirho(
                    &format!("{NS_CHIRHO}{OBJ_INFIX_CHIRHO}{}", addr_chirho.0),
                    &b64_encode_chirho(b"tampered"),
                )
                .await
                .unwrap();

            let error_chirho = store_chirho.get_chirho(&addr_chirho).await.unwrap_err();
            assert_eq!(
                error_chirho.kind_chirho,
                StoreErrorKindChirho::InvalidChirho
            );
            assert!(error_chirho
                .message_chirho
                .contains("content address mismatch"));
        });
    }

    #[test]
    fn audit_chain_and_heads_chirho() {
        block_on_chirho(async {
            let log_chirho =
                KvAsyncAuditLogChirho::new_chirho(MemoryKvAsyncChirho::new_chirho(), NS_CHIRHO);
            let h0_chirho = log_chirho.append_chirho("w-chirho", b"one").await.unwrap();
            let h1_chirho = log_chirho.append_chirho("w-chirho", b"two").await.unwrap();
            let r1_chirho = log_chirho.get_chirho(&h1_chirho).await.unwrap().unwrap();
            assert_eq!(r1_chirho.local_seq_chirho, 1);
            assert_eq!(r1_chirho.prev_hash_chirho, Some(h0_chirho));
            assert_eq!(log_chirho.heads_chirho().await.unwrap(), vec![h1_chirho]);
        });
    }

    #[test]
    fn audit_read_rejects_tampered_record_body_chirho() {
        block_on_chirho(async {
            let kv_chirho = std::rc::Rc::new(MemoryKvAsyncChirho::new_chirho());
            let log_chirho =
                KvAsyncAuditLogChirho::new_chirho(RcKvAsyncChirho(kv_chirho.clone()), NS_CHIRHO);
            let head_chirho = log_chirho.append_chirho("w-chirho", b"one").await.unwrap();
            let tampered_chirho =
                AuditRecordChirho::new_chirho("w-chirho", 0, None, b"tampered".to_vec());
            kv_chirho
                .set_chirho(
                    &format!("{NS_CHIRHO}{RECORD_INFIX_CHIRHO}{}", head_chirho.0),
                    &serde_json::to_string(&tampered_chirho).unwrap(),
                )
                .await
                .unwrap();

            let error_chirho = log_chirho.get_chirho(&head_chirho).await.unwrap_err();
            assert_eq!(
                error_chirho.kind_chirho,
                StoreErrorKindChirho::InvalidChirho
            );
            assert!(error_chirho
                .message_chirho
                .contains("audit record hash mismatch"));
        });
    }

    #[test]
    fn namespaces_do_not_collide_chirho() {
        block_on_chirho(async {
            // Two apps sharing one Kv (origin) must not see each other's heads.
            let kv_chirho = std::rc::Rc::new(MemoryKvAsyncChirho::new_chirho());
            let a_chirho =
                KvAsyncAuditLogChirho::new_chirho(RcKvAsyncChirho(kv_chirho.clone()), "app-a/");
            let b_chirho =
                KvAsyncAuditLogChirho::new_chirho(RcKvAsyncChirho(kv_chirho.clone()), "app-b/");
            a_chirho.append_chirho("w-chirho", b"a-only").await.unwrap();
            assert_eq!(a_chirho.heads_chirho().await.unwrap().len(), 1);
            assert_eq!(
                b_chirho.heads_chirho().await.unwrap().len(),
                0,
                "namespace leak between apps"
            );
        });
    }

    /// The IndexedDB (Kv) async adapter must produce byte-for-byte IDENTICAL content hashes and audit
    /// records to the synchronous memory/fs adapters — proving it is a faithful backend behind the
    /// same (now async) ports. The namespace only affects storage keys, never the content hashes.
    #[test]
    fn identical_to_sync_memory_adapter_chirho() {
        block_on_chirho(async {
            let kv_cs_chirho =
                KvAsyncContentStoreChirho::new_chirho(MemoryKvAsyncChirho::new_chirho(), NS_CHIRHO);
            let kv_al_chirho =
                KvAsyncAuditLogChirho::new_chirho(MemoryKvAsyncChirho::new_chirho(), NS_CHIRHO);
            let mem_cs_chirho = MemoryContentStoreChirho::new_chirho();
            let mem_al_chirho = MemoryAuditLogChirho::new_chirho();

            assert_eq!(
                kv_cs_chirho.put_chirho(b"love Jesus").await.unwrap(),
                mem_cs_chirho.put_chirho(b"love Jesus").unwrap(),
                "content hash differs between IndexedDB-Kv (async) and memory (sync) adapters"
            );
            assert_eq!(
                kv_al_chirho
                    .append_chirho("runner-chirho", b"prov")
                    .await
                    .unwrap(),
                mem_al_chirho
                    .append_chirho("runner-chirho", b"prov")
                    .unwrap(),
                "audit head differs between IndexedDB-Kv (async) and memory (sync) adapters"
            );
        });
    }

    /// The async DAG executor (`run_linear_dag_async_chirho`) running over THIS crate's async
    /// IndexedDB-Kv adapters produces the IDENTICAL output hash + audit-record payload hash as the
    /// SYNC executor over the memory adapters — the end-to-end async-path proof, no browser. (M35.6a
    /// proved the executor over a *bridged* sync store; this proves it over a genuinely-async adapter
    /// with real `.await` points.)
    #[test]
    fn dag_runs_identically_sync_vs_async_idb_mock_chirho() {
        use cairn_core_chirho::model_chirho::{DagChirho, NodeDefChirho, PortChirho};
        use cairn_core_chirho::ports_chirho::NodeRunnerChirho;
        use cairn_runtime_core_chirho::{run_linear_dag_async_chirho, run_linear_dag_chirho};

        struct IdRunnerChirho;
        impl NodeRunnerChirho for IdRunnerChirho {
            fn run_node_chirho(
                &self,
                _node_chirho: &NodeDefChirho,
                input_chirho: &[u8],
            ) -> Result<Vec<u8>> {
                Ok(input_chirho.to_vec())
            }
        }
        let schema_chirho = hash_chirho(b"bytes-schema-chirho");
        let node_chirho = NodeDefChirho {
            name_chirho: "id-chirho".to_string(),
            impl_wasm_chirho: hash_chirho(b"id-chirho"),
            entry_chirho: "run-chirho".to_string(),
            inputs_chirho: vec![PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_chirho.clone(),
            }],
            outputs_chirho: vec![PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho,
            }],
            capabilities_chirho: vec![],
            effect_contract_set_chirho: None,
            fuel_limit_chirho: 1_000,
            max_output_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_OUTPUT_BYTES_CHIRHO,
            max_memory_bytes_chirho:
                cairn_core_chirho::model_chirho::DEFAULT_NODE_MAX_MEMORY_BYTES_CHIRHO,
        };
        let node_bytes_chirho = serde_json::to_vec(&node_chirho).unwrap();
        let input_chirho = b"love Jesus";

        // sync executor over the memory adapters
        let sync_cs_chirho = MemoryContentStoreChirho::new_chirho();
        let sync_al_chirho = MemoryAuditLogChirho::new_chirho();
        let sync_node_chirho = sync_cs_chirho.put_chirho(&node_bytes_chirho).unwrap();
        let sync_dag_chirho = DagChirho {
            nodes_chirho: vec![sync_node_chirho.clone()],
            edges_chirho: vec![],
        };
        let sync_result_chirho = run_linear_dag_chirho(
            &sync_dag_chirho,
            input_chirho,
            &sync_cs_chirho,
            &sync_al_chirho,
            &IdRunnerChirho,
            "rt-chirho",
        )
        .unwrap();

        // async executor over THIS crate's IndexedDB-Kv mock adapters (genuine `.await` points)
        block_on_chirho(async {
            let async_cs_chirho = KvAsyncContentStoreChirho::new_chirho(
                MemoryKvAsyncChirho::new_chirho(),
                "dagtest/",
            );
            let async_al_chirho =
                KvAsyncAuditLogChirho::new_chirho(MemoryKvAsyncChirho::new_chirho(), "dagtest/");
            let async_node_chirho = async_cs_chirho
                .put_chirho(&node_bytes_chirho)
                .await
                .unwrap();
            assert_eq!(sync_node_chirho, async_node_chirho, "node hash differs");
            let async_dag_chirho = DagChirho {
                nodes_chirho: vec![async_node_chirho],
                edges_chirho: vec![],
            };
            let async_result_chirho = run_linear_dag_async_chirho(
                &async_dag_chirho,
                input_chirho,
                &async_cs_chirho,
                &async_al_chirho,
                &IdRunnerChirho,
                "rt-chirho",
            )
            .await
            .unwrap();
            assert_eq!(
                sync_result_chirho.output_hash_chirho, async_result_chirho.output_hash_chirho,
                "final output hash differs sync vs async"
            );
            let async_rec_chirho = async_al_chirho
                .get_chirho(&async_result_chirho.audit_head_chirho)
                .await
                .unwrap()
                .unwrap();
            let sync_rec_chirho = sync_al_chirho
                .get_chirho(&sync_result_chirho.audit_head_chirho)
                .unwrap()
                .unwrap();
            assert_eq!(
                hash_chirho(&sync_rec_chirho.payload_chirho),
                hash_chirho(&async_rec_chirho.payload_chirho),
                "audit-record payload hash differs sync vs async"
            );
        });
    }

    /// Shares one async Kv (origin) across two namespaced adapters in the namespace test.
    struct RcKvAsyncChirho(std::rc::Rc<MemoryKvAsyncChirho>);
    impl KvAsyncChirho for RcKvAsyncChirho {
        async fn get_chirho(&self, key_chirho: &str) -> Result<Option<String>> {
            self.0.get_chirho(key_chirho).await
        }
        async fn set_chirho(&self, key_chirho: &str, value_chirho: &str) -> Result<()> {
            self.0.set_chirho(key_chirho, value_chirho).await
        }
        async fn keys_with_prefix_chirho(&self, prefix_chirho: &str) -> Result<Vec<String>> {
            self.0.keys_with_prefix_chirho(prefix_chirho).await
        }
    }
}
