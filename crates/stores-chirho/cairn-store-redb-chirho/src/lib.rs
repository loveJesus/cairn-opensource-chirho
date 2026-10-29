// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! redb-backed `AuditLogChirho` + `StateStoreChirho` adapter with one-backend
//! state+audit transactions.
//!
//! This is the M35.7 server durability brick: the immutable content plane can stay on the existing
//! filesystem adapter, while audit records, writer heads, mutable app state, and applied mutation ids
//! live in one redb database. `commit_state_and_audit_chirho` writes the state value, audit record,
//! writer head, and mutation id in a single redb write transaction.

mod open_lock_chirho;
pub mod versioned_chirho;
pub mod viewer_state_chirho;

use open_lock_chirho::StoreOpenGuardChirho;

use anyhow::{Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_core_chirho::ports_chirho::{
    record_hash_chirho, verify_audit_record_hash_chirho, AuditLogChirho, AuditRecordChirho,
    StateAuditCommitChirho, StateAuditUnitOfWorkChirho, StateStoreChirho, StoreErrorChirho,
    StoreResultChirho,
};
use redb::{Database, Durability, ReadableTable, TableDefinition};
use std::path::Path;

const RECORDS_CHIRHO: TableDefinition<&str, &[u8]> = TableDefinition::new("audit_records_chirho");
const HEADS_CHIRHO: TableDefinition<&str, &[u8]> = TableDefinition::new("audit_heads_chirho");
const STATE_CHIRHO: TableDefinition<&str, &[u8]> = TableDefinition::new("state_chirho");
const MUTATIONS_CHIRHO: TableDefinition<&str, &[u8]> =
    TableDefinition::new("applied_mutations_chirho");
const STATE_ONLY_MUTATION_CHIRHO: &[u8] = b"state-only-chirho";

fn backend_error_chirho(error_chirho: impl std::fmt::Display) -> StoreErrorChirho {
    StoreErrorChirho::backend_chirho(error_chirho.to_string())
}

fn invalid_utf8_chirho(error_chirho: std::string::FromUtf8Error) -> StoreErrorChirho {
    StoreErrorChirho::invalid_chirho(error_chirho.to_string())
}

fn writer_key_chirho(writer_chirho: &str) -> String {
    blake3::hash(writer_chirho.as_bytes()).to_hex().to_string()
}

fn hash_from_bytes_chirho(bytes_chirho: &[u8]) -> StoreResultChirho<HashChirho> {
    Ok(HashChirho(
        String::from_utf8(bytes_chirho.to_vec()).map_err(invalid_utf8_chirho)?,
    ))
}

/// One redb database that can serve as both an audit log and an app-state store.
pub struct RedbStateAuditStoreChirho {
    db_chirho: Database,
    /// Declared after the database, so its file lock is released before the next opener in this process proceeds.
    _open_guard_chirho: StoreOpenGuardChirho,
}

impl RedbStateAuditStoreChirho {
    pub fn open_chirho(path_chirho: &Path) -> Result<Self> {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).with_context(|| {
                format!(
                    "create redb state/audit parent directory {}",
                    parent_chirho.display()
                )
            })?;
        }
        let open_guard_chirho = StoreOpenGuardChirho::acquire_chirho(path_chirho)?;
        let db_chirho = Database::create(path_chirho)
            .with_context(|| format!("open redb state/audit store at {}", path_chirho.display()))?;
        let store_chirho = Self {
            db_chirho,
            _open_guard_chirho: open_guard_chirho,
        };
        store_chirho.init_chirho()?;
        Ok(store_chirho)
    }

    fn init_chirho(&self) -> Result<()> {
        let txn_chirho = self.begin_immediate_write_chirho()?;
        {
            let _records_chirho = txn_chirho.open_table(RECORDS_CHIRHO)?;
            let _heads_chirho = txn_chirho.open_table(HEADS_CHIRHO)?;
            let _state_chirho = txn_chirho.open_table(STATE_CHIRHO)?;
            let _mutations_chirho = txn_chirho.open_table(MUTATIONS_CHIRHO)?;
        }
        txn_chirho.commit()?;
        Ok(())
    }

    fn begin_immediate_write_chirho(&self) -> Result<redb::WriteTransaction> {
        let mut txn_chirho = self.db_chirho.begin_write()?;
        // redb defaults to Immediate today; keep the durable audit/state commit point explicit.
        txn_chirho.set_durability(Durability::Immediate);
        Ok(txn_chirho)
    }

    fn read_record_in_table_chirho(
        records_chirho: &impl ReadableTable<&'static str, &'static [u8]>,
        hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        let Some(bytes_chirho) = records_chirho
            .get(hash_chirho.0.as_str())
            .map_err(backend_error_chirho)?
        else {
            return Ok(None);
        };
        let record_chirho: AuditRecordChirho =
            serde_json::from_slice(bytes_chirho.value()).map_err(StoreErrorChirho::from)?;
        verify_audit_record_hash_chirho(hash_chirho, &record_chirho)?;
        Ok(Some(record_chirho))
    }

    fn append_audit_in_txn_chirho(
        records_chirho: &mut redb::Table<'_, &str, &[u8]>,
        heads_chirho: &mut redb::Table<'_, &str, &[u8]>,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let writer_key_chirho = writer_key_chirho(writer_chirho);
        let prev_hash_chirho = heads_chirho
            .get(writer_key_chirho.as_str())
            .map_err(backend_error_chirho)?
            .map(|value_chirho| hash_from_bytes_chirho(value_chirho.value()))
            .transpose()?;
        let local_seq_chirho = match &prev_hash_chirho {
            Some(head_chirho) => {
                Self::read_record_in_table_chirho(records_chirho, head_chirho)?
                    .ok_or_else(|| {
                        StoreErrorChirho::conflict_chirho(format!(
                            "head record {} missing",
                            head_chirho.0
                        ))
                    })?
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
        let record_hash_chirho = record_hash_chirho(&record_chirho)?;
        let record_bytes_chirho = serde_json::to_vec(&record_chirho)?;
        records_chirho
            .insert(
                record_hash_chirho.0.as_str(),
                record_bytes_chirho.as_slice(),
            )
            .map_err(backend_error_chirho)?;
        heads_chirho
            .insert(writer_key_chirho.as_str(), record_hash_chirho.0.as_bytes())
            .map_err(backend_error_chirho)?;
        Ok(record_hash_chirho)
    }
}

impl AuditLogChirho for RedbStateAuditStoreChirho {
    fn append_chirho(
        &self,
        writer_chirho: &str,
        payload_chirho: &[u8],
    ) -> StoreResultChirho<HashChirho> {
        let txn_chirho = self
            .begin_immediate_write_chirho()
            .map_err(backend_error_chirho)?;
        let record_hash_chirho;
        {
            let mut records_chirho = txn_chirho
                .open_table(RECORDS_CHIRHO)
                .map_err(backend_error_chirho)?;
            let mut heads_chirho = txn_chirho
                .open_table(HEADS_CHIRHO)
                .map_err(backend_error_chirho)?;
            record_hash_chirho = Self::append_audit_in_txn_chirho(
                &mut records_chirho,
                &mut heads_chirho,
                writer_chirho,
                payload_chirho,
            )?;
        }
        txn_chirho.commit().map_err(backend_error_chirho)?;
        Ok(record_hash_chirho)
    }

    fn get_chirho(
        &self,
        record_hash_chirho: &HashChirho,
    ) -> StoreResultChirho<Option<AuditRecordChirho>> {
        let txn_chirho = self.db_chirho.begin_read().map_err(backend_error_chirho)?;
        let records_chirho = txn_chirho
            .open_table(RECORDS_CHIRHO)
            .map_err(backend_error_chirho)?;
        Self::read_record_in_table_chirho(&records_chirho, record_hash_chirho)
    }

    fn heads_chirho(&self) -> StoreResultChirho<Vec<HashChirho>> {
        let txn_chirho = self.db_chirho.begin_read().map_err(backend_error_chirho)?;
        let heads_chirho = txn_chirho
            .open_table(HEADS_CHIRHO)
            .map_err(backend_error_chirho)?;
        let mut out_chirho = Vec::new();
        for item_chirho in heads_chirho.iter().map_err(backend_error_chirho)? {
            let (_key_chirho, value_chirho) = item_chirho.map_err(backend_error_chirho)?;
            out_chirho.push(hash_from_bytes_chirho(value_chirho.value())?);
        }
        Ok(out_chirho)
    }
}

impl StateStoreChirho for RedbStateAuditStoreChirho {
    fn get_state_chirho(&self, key_chirho: &str) -> StoreResultChirho<Option<Vec<u8>>> {
        let txn_chirho = self.db_chirho.begin_read().map_err(backend_error_chirho)?;
        let state_chirho = txn_chirho
            .open_table(STATE_CHIRHO)
            .map_err(backend_error_chirho)?;
        Ok(state_chirho
            .get(key_chirho)
            .map_err(backend_error_chirho)?
            .map(|value_chirho| value_chirho.value().to_vec()))
    }

    fn set_state_chirho(&self, key_chirho: &str, value_chirho: &[u8]) -> StoreResultChirho<()> {
        let txn_chirho = self
            .begin_immediate_write_chirho()
            .map_err(backend_error_chirho)?;
        {
            let mut state_chirho = txn_chirho
                .open_table(STATE_CHIRHO)
                .map_err(backend_error_chirho)?;
            state_chirho
                .insert(key_chirho, value_chirho)
                .map_err(backend_error_chirho)?;
        }
        txn_chirho.commit().map_err(backend_error_chirho)?;
        Ok(())
    }

    fn apply_once_chirho(
        &self,
        mutation_id_chirho: &str,
        key_chirho: &str,
        value_chirho: &[u8],
    ) -> StoreResultChirho<bool> {
        let txn_chirho = self
            .begin_immediate_write_chirho()
            .map_err(backend_error_chirho)?;
        let applied_now_chirho;
        {
            let mut state_chirho = txn_chirho
                .open_table(STATE_CHIRHO)
                .map_err(backend_error_chirho)?;
            let mut mutations_chirho = txn_chirho
                .open_table(MUTATIONS_CHIRHO)
                .map_err(backend_error_chirho)?;
            if mutations_chirho
                .get(mutation_id_chirho)
                .map_err(backend_error_chirho)?
                .is_some()
            {
                applied_now_chirho = false;
            } else {
                state_chirho
                    .insert(key_chirho, value_chirho)
                    .map_err(backend_error_chirho)?;
                mutations_chirho
                    .insert(mutation_id_chirho, STATE_ONLY_MUTATION_CHIRHO)
                    .map_err(backend_error_chirho)?;
                applied_now_chirho = true;
            }
        }
        txn_chirho.commit().map_err(backend_error_chirho)?;
        Ok(applied_now_chirho)
    }

    fn is_applied_chirho(&self, mutation_id_chirho: &str) -> StoreResultChirho<bool> {
        let txn_chirho = self.db_chirho.begin_read().map_err(backend_error_chirho)?;
        let mutations_chirho = txn_chirho
            .open_table(MUTATIONS_CHIRHO)
            .map_err(backend_error_chirho)?;
        Ok(mutations_chirho
            .get(mutation_id_chirho)
            .map_err(backend_error_chirho)?
            .is_some())
    }
}

impl StateAuditUnitOfWorkChirho for RedbStateAuditStoreChirho {
    fn commit_state_and_audit_chirho(
        &self,
        mutation_id_chirho: &str,
        state_key_chirho: &str,
        state_value_chirho: &[u8],
        audit_writer_chirho: &str,
        audit_payload_chirho: &[u8],
    ) -> StoreResultChirho<StateAuditCommitChirho> {
        let txn_chirho = self
            .begin_immediate_write_chirho()
            .map_err(backend_error_chirho)?;
        let outcome_chirho;
        {
            let mut records_chirho = txn_chirho
                .open_table(RECORDS_CHIRHO)
                .map_err(backend_error_chirho)?;
            let mut heads_chirho = txn_chirho
                .open_table(HEADS_CHIRHO)
                .map_err(backend_error_chirho)?;
            let mut state_chirho = txn_chirho
                .open_table(STATE_CHIRHO)
                .map_err(backend_error_chirho)?;
            let mut mutations_chirho = txn_chirho
                .open_table(MUTATIONS_CHIRHO)
                .map_err(backend_error_chirho)?;

            let existing_mutation_chirho = mutations_chirho
                .get(mutation_id_chirho)
                .map_err(backend_error_chirho)?
                .map(|value_chirho| value_chirho.value().to_vec());
            if let Some(bytes_chirho) = existing_mutation_chirho {
                if bytes_chirho.as_slice() == STATE_ONLY_MUTATION_CHIRHO {
                    return Err(StoreErrorChirho::conflict_chirho(format!(
                        "mutation {mutation_id_chirho} already applied without an audit commit"
                    )));
                }
                outcome_chirho = StateAuditCommitChirho {
                    state_applied_chirho: false,
                    audit_head_chirho: hash_from_bytes_chirho(&bytes_chirho)?,
                };
            } else {
                let audit_head_chirho = Self::append_audit_in_txn_chirho(
                    &mut records_chirho,
                    &mut heads_chirho,
                    audit_writer_chirho,
                    audit_payload_chirho,
                )?;
                state_chirho
                    .insert(state_key_chirho, state_value_chirho)
                    .map_err(backend_error_chirho)?;
                mutations_chirho
                    .insert(mutation_id_chirho, audit_head_chirho.0.as_bytes())
                    .map_err(backend_error_chirho)?;
                outcome_chirho = StateAuditCommitChirho {
                    state_applied_chirho: true,
                    audit_head_chirho,
                };
            }
        }
        txn_chirho.commit().map_err(backend_error_chirho)?;
        Ok(outcome_chirho)
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use cairn_core_chirho::ports_chirho::StoreErrorKindChirho;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_db_chirho() -> std::path::PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-redb-m357-{nanos_chirho}-{n_chirho}.redb"))
    }

    #[test]
    fn state_apply_once_survives_reopen_chirho() {
        let path_chirho = tmp_db_chirho();
        {
            let store_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho).unwrap();
            assert!(store_chirho
                .apply_once_chirho("m1", "counter", b"1")
                .unwrap());
            assert!(!store_chirho
                .apply_once_chirho("m1", "counter", b"2")
                .unwrap());
            assert_eq!(
                store_chirho.get_state_chirho("counter").unwrap(),
                Some(b"1".to_vec())
            );
        }
        {
            let reopened_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho).unwrap();
            assert!(reopened_chirho.is_applied_chirho("m1").unwrap());
            assert!(!reopened_chirho
                .apply_once_chirho("m1", "counter", b"2")
                .unwrap());
            assert_eq!(
                reopened_chirho.get_state_chirho("counter").unwrap(),
                Some(b"1".to_vec())
            );
        }
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn unit_of_work_commits_state_and_audit_atomically_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho).unwrap();
        let first_chirho = store_chirho
            .commit_state_and_audit_chirho("m1", "counter", b"1", "writer", b"payload")
            .unwrap();
        assert!(first_chirho.state_applied_chirho);
        assert_eq!(
            store_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );
        let record_chirho = store_chirho
            .get_chirho(&first_chirho.audit_head_chirho)
            .unwrap()
            .unwrap();
        assert_eq!(record_chirho.payload_chirho, b"payload".to_vec());

        let second_chirho = store_chirho
            .commit_state_and_audit_chirho("m1", "counter", b"2", "writer", b"payload-2")
            .unwrap();
        assert!(!second_chirho.state_applied_chirho);
        assert_eq!(
            second_chirho.audit_head_chirho,
            first_chirho.audit_head_chirho
        );
        assert_eq!(
            store_chirho.get_state_chirho("counter").unwrap(),
            Some(b"1".to_vec())
        );
        assert_eq!(
            store_chirho.heads_chirho().unwrap(),
            vec![first_chirho.audit_head_chirho]
        );
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn audit_read_rejects_tampered_record_body_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = RedbStateAuditStoreChirho::open_chirho(&path_chirho).unwrap();
        let head_chirho = store_chirho.append_chirho("w-chirho", b"one").unwrap();
        let tampered_chirho =
            AuditRecordChirho::new_chirho("w-chirho", 0, None, b"tampered".to_vec());
        let tampered_bytes_chirho = serde_json::to_vec(&tampered_chirho).unwrap();
        let txn_chirho = store_chirho.db_chirho.begin_write().unwrap();
        {
            let mut records_chirho = txn_chirho.open_table(RECORDS_CHIRHO).unwrap();
            records_chirho
                .insert(head_chirho.0.as_str(), tampered_bytes_chirho.as_slice())
                .unwrap();
        }
        txn_chirho.commit().unwrap();

        let error_chirho = store_chirho.get_chirho(&head_chirho).unwrap_err();
        assert_eq!(
            error_chirho.kind_chirho,
            StoreErrorKindChirho::InvalidChirho
        );
        assert!(error_chirho
            .message_chirho
            .contains("audit record hash mismatch"));

        let _ = std::fs::remove_file(&path_chirho);
    }
}
