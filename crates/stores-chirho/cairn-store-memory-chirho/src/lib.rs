// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! In-memory `ContentStoreChirho` + `AuditLogChirho` adapters — wasm-safe (no filesystem). This
//! is the brick-1 "leak test": if the ports accidentally assumed a path or a file lock, a pure
//! `HashMap`/`Mutex` adapter couldn't satisfy them.

use anyhow::anyhow;
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, verify_audit_record_hash_chirho, verify_content_address_chirho,
    AuditLogChirho, AuditRecordChirho, ContentReadChirho, ContentStoreChirho, StateStoreChirho,
    StoreResultChirho,
};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Content-addressed store backed by a `HashMap`.
#[derive(Default)]
pub struct MemoryContentStoreChirho {
    objects_chirho: Mutex<HashMap<HashChirho, Vec<u8>>>,
}

impl MemoryContentStoreChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }
}

impl ContentStoreChirho for MemoryContentStoreChirho {
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        let addr_chirho = hash_chirho(bytes_chirho);
        self.objects_chirho
            .lock()
            .map_err(|_| anyhow!("memory content store poisoned"))?
            .insert(addr_chirho.clone(), bytes_chirho.to_vec());
        Ok(addr_chirho)
    }
}

impl ContentReadChirho for MemoryContentStoreChirho {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        let bytes_chirho = self
            .objects_chirho
            .lock()
            .map_err(|_| anyhow!("memory content store poisoned"))?
            .get(addr_chirho)
            .cloned();
        if let Some(bytes_chirho) = &bytes_chirho {
            verify_content_address_chirho(addr_chirho, bytes_chirho)?;
        }
        Ok(bytes_chirho)
    }
}

#[derive(Default)]
struct MemAuditStateChirho {
    records_chirho: HashMap<HashChirho, AuditRecordChirho>,
    heads_chirho: HashMap<String, HashChirho>,
}

/// Fork-tolerant audit log backed by in-memory maps. Each writer chains after its own head.
#[derive(Default)]
pub struct MemoryAuditLogChirho {
    state_chirho: Mutex<MemAuditStateChirho>,
}

impl MemoryAuditLogChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }
}

impl AuditLogChirho for MemoryAuditLogChirho {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let mut state_chirho = self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("memory audit log poisoned"))?;
        let prev_hash_chirho = state_chirho.heads_chirho.get(writer_chirho).cloned();
        let local_seq_chirho = match &prev_hash_chirho {
            Some(head_chirho) => state_chirho
                .records_chirho
                .get(head_chirho)
                .map(|prev_chirho| prev_chirho.local_seq_chirho + 1)
                .unwrap_or(0),
            None => 0,
        };
        let record_chirho = AuditRecordChirho::new_chirho(
            writer_chirho,
            local_seq_chirho,
            prev_hash_chirho,
            payload_chirho.to_vec(),
        );
        let record_hash_value_chirho = record_hash_chirho(&record_chirho)?;
        state_chirho
            .records_chirho
            .insert(record_hash_value_chirho.clone(), record_chirho);
        state_chirho
            .heads_chirho
            .insert(writer_chirho.to_string(), record_hash_value_chirho.clone());
        Ok(record_hash_value_chirho)
    }

    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        let record_chirho = self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("memory audit log poisoned"))?
            .records_chirho
            .get(record_hash_chirho)
            .cloned();
        if let Some(record_chirho) = &record_chirho {
            verify_audit_record_hash_chirho(record_hash_chirho, record_chirho)?;
        }
        Ok(record_chirho)
    }

    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        Ok(self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("memory audit log poisoned"))?
            .heads_chirho
            .values()
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MemStateChirho {
    kv_chirho: HashMap<String, Vec<u8>>,
    /// Mutation ids already applied — the idempotency ledger for `apply_once_chirho`.
    applied_chirho: HashSet<String>,
}

/// In-memory mutable state store — the app-state plane (one `Mutex`, wasm-safe). The single lock
/// makes `apply_once_chirho` atomic: recording the mutation id and writing the value happen together.
#[derive(Default)]
pub struct MemoryStateStoreChirho {
    state_chirho: Mutex<MemStateChirho>,
}

impl MemoryStateStoreChirho {
    pub fn new_chirho() -> Self {
        Self::default()
    }
}

impl StateStoreChirho for MemoryStateStoreChirho {
    fn get_state_chirho(&self, key_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        Ok(self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("state mutex poisoned"))?
            .kv_chirho
            .get(key_chirho)
            .cloned())
    }
    fn set_state_chirho(&self, key_chirho: &str, value_chirho: &[u8]) -> StoreResultChirho<()> {
        self.state_chirho
            .lock()
            .map_err(|_| anyhow!("state mutex poisoned"))?
            .kv_chirho
            .insert(key_chirho.to_string(), value_chirho.to_vec());
        Ok(())
    }
    fn apply_once_chirho(
        &self,
        mutation_id_chirho: &str,
        key_chirho: &str,
        value_chirho: &[u8],
    ) -> StoreResultChirho<bool> {
        let mut state_chirho = self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("state mutex poisoned"))?;
        if state_chirho.applied_chirho.contains(mutation_id_chirho) {
            return Ok(false); // already applied — replay/crash-recovery no-op
        }
        // record-id + write-value as one atomic step under the lock
        state_chirho
            .kv_chirho
            .insert(key_chirho.to_string(), value_chirho.to_vec());
        state_chirho
            .applied_chirho
            .insert(mutation_id_chirho.to_string());
        Ok(true)
    }
    fn is_applied_chirho(&self, mutation_id_chirho: &str) -> StoreResultChirho<bool> {
        Ok(self
            .state_chirho
            .lock()
            .map_err(|_| anyhow!("state mutex poisoned"))?
            .applied_chirho
            .contains(mutation_id_chirho))
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::ports_chirho::StoreErrorKindChirho;

    #[test]
    fn state_store_get_set_chirho() {
        let s_chirho = MemoryStateStoreChirho::new_chirho();
        assert!(s_chirho.get_state_chirho("counter").unwrap().is_none());
        s_chirho.set_state_chirho("counter", b"1").unwrap();
        assert_eq!(
            s_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );
    }

    #[test]
    fn apply_once_is_idempotent_chirho() {
        let s_chirho = MemoryStateStoreChirho::new_chirho();
        assert!(!s_chirho.is_applied_chirho("m1").unwrap());
        // first application of m1 writes the value and returns true
        assert!(s_chirho.apply_once_chirho("m1", "counter", b"6").unwrap());
        assert_eq!(
            s_chirho.get_state_chirho("counter").unwrap(),
            Some(b"6".to_vec())
        );
        assert!(s_chirho.is_applied_chirho("m1").unwrap());
        // re-applying m1 (even with a different value) is a no-op
        assert!(!s_chirho.apply_once_chirho("m1", "counter", b"7").unwrap());
        assert_eq!(
            s_chirho.get_state_chirho("counter").unwrap(),
            Some(b"6".to_vec()),
            "apply_once must not re-apply the same mutation id"
        );
        // a different mutation id applies again
        assert!(s_chirho.apply_once_chirho("m2", "counter", b"7").unwrap());
        assert_eq!(
            s_chirho.get_state_chirho("counter").unwrap(),
            Some(b"7".to_vec())
        );
    }

    #[test]
    fn content_round_trip_chirho() {
        let store_chirho = MemoryContentStoreChirho::new_chirho();
        let addr_chirho = store_chirho.put_chirho(b"love Jesus").unwrap();
        assert_eq!(
            store_chirho.get_chirho(&addr_chirho).unwrap().as_deref(),
            Some(&b"love Jesus"[..])
        );
        // idempotent address
        assert_eq!(store_chirho.put_chirho(b"love Jesus").unwrap(), addr_chirho);
    }

    #[test]
    fn content_read_rejects_tampered_address_body_chirho() {
        let store_chirho = MemoryContentStoreChirho::new_chirho();
        let addr_chirho = store_chirho.put_chirho(b"love Jesus").unwrap();
        store_chirho
            .objects_chirho
            .lock()
            .unwrap()
            .insert(addr_chirho.clone(), b"tampered".to_vec());

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
    fn audit_chain_increments_per_writer_chirho() {
        let log_chirho = MemoryAuditLogChirho::new_chirho();
        let h0_chirho = log_chirho.append_chirho("w-chirho", b"one").unwrap();
        let h1_chirho = log_chirho.append_chirho("w-chirho", b"two").unwrap();
        assert_ne!(h0_chirho, h1_chirho);
        let r0_chirho = log_chirho.get_chirho(&h0_chirho).unwrap().unwrap();
        let r1_chirho = log_chirho.get_chirho(&h1_chirho).unwrap().unwrap();
        assert_eq!(r0_chirho.local_seq_chirho, 0);
        assert_eq!(r1_chirho.local_seq_chirho, 1);
        assert_eq!(r1_chirho.prev_hash_chirho, Some(h0_chirho.clone()));
        assert_eq!(log_chirho.heads_chirho().unwrap(), vec![h1_chirho]);
    }

    #[test]
    fn audit_read_rejects_tampered_record_body_chirho() {
        let log_chirho = MemoryAuditLogChirho::new_chirho();
        let head_chirho = log_chirho.append_chirho("w-chirho", b"one").unwrap();
        log_chirho
            .state_chirho
            .lock()
            .unwrap()
            .records_chirho
            .insert(
                head_chirho.clone(),
                AuditRecordChirho::new_chirho("w-chirho", 0, None, b"tampered".to_vec()),
            );

        let error_chirho = log_chirho.get_chirho(&head_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("audit record hash mismatch"));
    }
}
