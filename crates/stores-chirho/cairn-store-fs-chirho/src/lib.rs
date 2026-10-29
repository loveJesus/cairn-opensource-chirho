// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Filesystem `ContentStoreChirho` + `AuditLogChirho` adapters — the server backend. Objects and
//! audit records are content-addressed files under `<root>`; a writer's appends are serialized by
//! an fs2 exclusive lock (plus an in-process mutex), keeping that writer's chain monotonic.
//! Cross-writer global ordering is a separate, optional port — not provided here.

use anyhow::{anyhow, Context};
use cairn_core_chirho::cas_chirho::hash_chirho;
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, verify_audit_record_hash_chirho, verify_content_address_chirho,
    AuditLogChirho, AuditRecordChirho, ContentReadChirho, ContentStoreChirho, StoreErrorChirho,
    StoreResultChirho,
};
use cairn_durable_chirho::write_file_durable_chirho;
use fs2::FileExt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// `<base>/ab/cdef…` — git-style sharding by the first two hex chars of the hash.
fn sharded_path_chirho(base_chirho: &Path, value_chirho: &HashChirho) -> PathBuf {
    let hex_chirho = &value_chirho.0;
    base_chirho.join(&hex_chirho[0..2]).join(&hex_chirho[2..])
}

fn write_file_sync_all_chirho(path_chirho: &Path, bytes_chirho: &[u8]) -> StoreResultChirho<()> {
    write_file_durable_chirho(path_chirho, bytes_chirho)?;
    Ok(())
}

/// Filesystem content-addressed store at `<root>/objects-chirho/`.
pub struct FsContentStoreChirho {
    root_chirho: PathBuf,
}

impl FsContentStoreChirho {
    pub fn new_chirho(root_chirho: impl Into<PathBuf>) -> Self {
        Self {
            root_chirho: root_chirho.into(),
        }
    }

    fn objects_dir_chirho(&self) -> PathBuf {
        self.root_chirho.join("objects-chirho")
    }
}

impl ContentStoreChirho for FsContentStoreChirho {
    fn put_chirho(&self, bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
        let addr_chirho = hash_chirho(bytes_chirho);
        let path_chirho = sharded_path_chirho(&self.objects_dir_chirho(), &addr_chirho);
        if !path_chirho.exists() {
            write_file_sync_all_chirho(&path_chirho, bytes_chirho).map_err(|error_chirho| {
                error_chirho.context_chirho(format!("write+sync object {}", path_chirho.display()))
            })?;
        }
        Ok(addr_chirho)
    }
}

impl ContentReadChirho for FsContentStoreChirho {
    fn get_chirho(&self, addr_chirho: &HashChirho) -> StoreResultChirho<Option<Vec<u8>>> {
        let path_chirho = sharded_path_chirho(&self.objects_dir_chirho(), addr_chirho);
        match fs::read(&path_chirho) {
            Ok(bytes_chirho) => {
                verify_content_address_chirho(addr_chirho, &bytes_chirho)?;
                Ok(Some(bytes_chirho))
            }
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e_chirho) => Err(StoreErrorChirho::from(
                anyhow::Error::from(e_chirho)
                    .context(format!("read object {}", path_chirho.display())),
            )),
        }
    }
}

/// Filesystem fork-tolerant audit log under `<root>/audit-chirho/`.
pub struct FsAuditLogChirho {
    root_chirho: PathBuf,
    append_lock_chirho: Mutex<()>,
}

impl FsAuditLogChirho {
    pub fn new_chirho(root_chirho: impl Into<PathBuf>) -> Self {
        Self {
            root_chirho: root_chirho.into(),
            append_lock_chirho: Mutex::new(()),
        }
    }

    fn audit_dir_chirho(&self) -> PathBuf {
        self.root_chirho.join("audit-chirho")
    }
    fn records_dir_chirho(&self) -> PathBuf {
        self.audit_dir_chirho().join("records-chirho")
    }
    fn heads_dir_chirho(&self) -> PathBuf {
        self.audit_dir_chirho().join("heads-chirho")
    }
    fn head_path_chirho(&self, writer_chirho: &str) -> PathBuf {
        // hash the writer id so it is always a safe, fixed-length filename
        let writer_key_chirho = blake3::hash(writer_chirho.as_bytes()).to_hex().to_string();
        self.heads_dir_chirho().join(writer_key_chirho)
    }
    fn record_path_chirho(&self, record_hash_value_chirho: &HashChirho) -> PathBuf {
        sharded_path_chirho(&self.records_dir_chirho(), record_hash_value_chirho)
    }

    fn read_record_at_chirho(
        &self,
        record_hash_value_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        let path_chirho = self.record_path_chirho(record_hash_value_chirho);
        match fs::read(&path_chirho) {
            Ok(bytes_chirho) => {
                let record_chirho: AuditRecordChirho = serde_json::from_slice(&bytes_chirho)
                    .with_context(|| format!("decode audit record {}", path_chirho.display()))?;
                verify_audit_record_hash_chirho(record_hash_value_chirho, &record_chirho)?;
                Ok(Some(record_chirho))
            }
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e_chirho) => Err(StoreErrorChirho::from(
                anyhow::Error::from(e_chirho)
                    .context(format!("read audit record {}", path_chirho.display())),
            )),
        }
    }

    fn append_locked_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let head_path_chirho = self.head_path_chirho(writer_chirho);
        let prev_hash_chirho: Option<HashChirho> = match fs::read_to_string(&head_path_chirho) {
            Ok(hex_chirho) => Some(HashChirho(hex_chirho.trim().to_string())),
            Err(e_chirho) if e_chirho.kind() == std::io::ErrorKind::NotFound => None,
            Err(e_chirho) => {
                return Err(StoreErrorChirho::from(
                    anyhow::Error::from(e_chirho)
                        .context(format!("read head {}", head_path_chirho.display())),
                ))
            }
        };
        let local_seq_chirho = match &prev_hash_chirho {
            Some(head_chirho) => {
                self.read_record_at_chirho(head_chirho)?
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

        // write the record file (idempotent — same record ⇒ same path/content)
        let record_path_chirho = self.record_path_chirho(&record_hash_value_chirho);
        let record_bytes_chirho = serde_json::to_vec(&record_chirho)?;
        write_file_sync_all_chirho(&record_path_chirho, &record_bytes_chirho).map_err(
            |error_chirho| {
                error_chirho.context_chirho(format!(
                    "write+sync audit record {}",
                    record_path_chirho.display()
                ))
            },
        )?;

        // advance this writer's head
        write_file_durable_chirho(&head_path_chirho, record_hash_value_chirho.0.as_bytes())
            .with_context(|| format!("write head {}", head_path_chirho.display()))?;
        Ok(record_hash_value_chirho)
    }
}

impl AuditLogChirho for FsAuditLogChirho {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        // in-process serialization (fs2 advisory locks don't block same-process distinct fds)
        let _local_guard_chirho = self
            .append_lock_chirho
            .lock()
            .map_err(|_| anyhow!("fs audit log lock poisoned"))?;
        fs::create_dir_all(self.audit_dir_chirho())?;
        // cross-process exclusive lock
        let lock_path_chirho = self.audit_dir_chirho().join("append.lock");
        let lock_file_chirho = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path_chirho)
            .with_context(|| format!("open lock {}", lock_path_chirho.display()))?;
        lock_file_chirho
            .lock_exclusive()
            .with_context(|| "lock audit append")?;
        let result_chirho = self.append_locked_chirho(writer_chirho, payload_chirho);
        let _ = lock_file_chirho.unlock();
        result_chirho
    }

    fn get_chirho(
        &self,
        record_hash_value_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        self.read_record_at_chirho(record_hash_value_chirho)
    }

    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let heads_dir_chirho = self.heads_dir_chirho();
        if !heads_dir_chirho.exists() {
            return Ok(vec![]);
        }
        let mut heads_chirho = Vec::new();
        for entry_chirho in fs::read_dir(&heads_dir_chirho)? {
            let hex_chirho = fs::read_to_string(entry_chirho?.path())?.trim().to_string();
            heads_chirho.push(HashChirho(hex_chirho));
        }
        Ok(heads_chirho)
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::ports_chirho::StoreErrorKindChirho;
    use cairn_store_memory_chirho::{MemoryAuditLogChirho, MemoryContentStoreChirho};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

    fn temp_root_chirho() -> PathBuf {
        let n_chirho = TEST_DIR_COUNTER_CHIRHO.fetch_add(1, Ordering::SeqCst);
        let dir_chirho = std::env::temp_dir().join(format!(
            "cairn-fs-brick1-{}-{}",
            std::process::id(),
            n_chirho
        ));
        let _ = fs::remove_dir_all(&dir_chirho);
        fs::create_dir_all(&dir_chirho).unwrap();
        dir_chirho
    }

    /// The brick-1 vertical slice: store an input, apply a pure transform, store the output,
    /// append a provenance record. Returns (input hash, output hash, audit head).
    fn run_pipeline_chirho(
        cs_chirho: &dyn ContentStoreChirho,
        al_chirho: &dyn AuditLogChirho,
    ) -> (HashChirho, HashChirho, HashChirho) {
        let input_chirho = b"love Jesus";
        let in_hash_chirho = cs_chirho.put_chirho(input_chirho).unwrap();
        let out_chirho = input_chirho.to_ascii_uppercase(); // the pure node
        let out_hash_chirho = cs_chirho.put_chirho(&out_chirho).unwrap();
        let payload_chirho = format!("{}=>{}", in_hash_chirho.0, out_hash_chirho.0);
        let audit_head_chirho = al_chirho
            .append_chirho("runner-chirho", payload_chirho.as_bytes())
            .unwrap();
        (in_hash_chirho, out_hash_chirho, audit_head_chirho)
    }

    #[test]
    fn same_dag_identical_hashes_and_provenance_across_memory_and_fs_chirho() {
        // memory backend
        let mem_cs_chirho = MemoryContentStoreChirho::new_chirho();
        let mem_al_chirho = MemoryAuditLogChirho::new_chirho();
        let (m_in_chirho, m_out_chirho, m_audit_chirho) =
            run_pipeline_chirho(&mem_cs_chirho, &mem_al_chirho);

        // fs backend
        let root_chirho = temp_root_chirho();
        let fs_cs_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
        let fs_al_chirho = FsAuditLogChirho::new_chirho(&root_chirho);
        let (f_in_chirho, f_out_chirho, f_audit_chirho) =
            run_pipeline_chirho(&fs_cs_chirho, &fs_al_chirho);

        // THE PROOF: identical content hashes + identical provenance head across both backends.
        assert_eq!(
            m_in_chirho, f_in_chirho,
            "input content hash differs across backends"
        );
        assert_eq!(
            m_out_chirho, f_out_chirho,
            "output content hash differs across backends"
        );
        assert_eq!(
            m_audit_chirho, f_audit_chirho,
            "audit provenance head differs across backends"
        );

        // the provenance records themselves are equivalent
        assert_eq!(
            mem_al_chirho.get_chirho(&m_audit_chirho).unwrap(),
            fs_al_chirho.get_chirho(&f_audit_chirho).unwrap(),
            "audit records differ across backends"
        );
        // content round-trips from fs
        assert_eq!(
            fs_cs_chirho.get_chirho(&f_out_chirho).unwrap().as_deref(),
            Some(&b"LOVE JESUS"[..])
        );

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn fs_content_read_rejects_tampered_address_body_chirho() {
        let root_chirho = temp_root_chirho();
        let store_chirho = FsContentStoreChirho::new_chirho(&root_chirho);
        let addr_chirho = store_chirho.put_chirho(b"love Jesus").unwrap();
        let path_chirho = sharded_path_chirho(&store_chirho.objects_dir_chirho(), &addr_chirho);
        write_file_sync_all_chirho(&path_chirho, b"tampered").unwrap();

        let error_chirho = store_chirho.get_chirho(&addr_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("content address mismatch"));

        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn fs_audit_read_rejects_tampered_record_body_chirho() {
        let root_chirho = temp_root_chirho();
        let log_chirho = FsAuditLogChirho::new_chirho(&root_chirho);
        let head_chirho = log_chirho.append_chirho("w-chirho", b"one").unwrap();
        let tampered_chirho =
            AuditRecordChirho::new_chirho("w-chirho", 0, None, b"tampered".to_vec());
        let path_chirho = log_chirho.record_path_chirho(&head_chirho);
        write_file_sync_all_chirho(&path_chirho, &serde_json::to_vec(&tampered_chirho).unwrap())
            .unwrap();

        let error_chirho = log_chirho.get_chirho(&head_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("audit record hash mismatch"));

        let _ = fs::remove_dir_all(&root_chirho);
    }
}
