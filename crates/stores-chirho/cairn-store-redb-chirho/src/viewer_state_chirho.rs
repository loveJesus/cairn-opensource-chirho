// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A bounded, per-key version store for viewer-owned application state.
//!
//! This store is deliberately separate from `versioned_chirho`: that prototype has one root-wide
//! mutable view cursor, while a customer-facing restore must append a new version for one key and
//! must never rewind an unrelated key or app.

use anyhow::{bail, Context, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use redb::{Database, Durability, ReadableTable, TableDefinition};
use std::path::Path;

const VIEWER_STATE_ENTRIES_CHIRHO: TableDefinition<(&str, u64), &[u8]> =
    TableDefinition::new("viewer_state_entries_chirho");
const VIEWER_STATE_KEY_COUNTS_CHIRHO: TableDefinition<&str, u64> =
    TableDefinition::new("viewer_state_key_counts_chirho");
const VIEWER_STATE_HEADS_CHIRHO: TableDefinition<&str, &[u8]> =
    TableDefinition::new("viewer_state_heads_chirho");
const VIEWER_STATE_WRITE_DURABILITY_CHIRHO: Durability = Durability::Immediate;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewerStateEntryChirho {
    pub version_chirho: u64,
    pub value_chirho: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewerStateHeadChirho {
    pub version_chirho: u64,
    pub receipt_digest_chirho: HashChirho,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewerStateHeadTransitionChirho {
    pub expected_chirho: Option<ViewerStateHeadChirho>,
    pub next_chirho: ViewerStateHeadChirho,
}

pub struct ViewerStateStoreChirho {
    db_chirho: Database,
    /// Declared after the database, so its file lock is released before the next opener in this process proceeds.
    _open_guard_chirho: crate::StoreOpenGuardChirho,
}

impl ViewerStateStoreChirho {
    pub fn open_chirho(path_chirho: &Path) -> Result<Self> {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).with_context(|| {
                format!(
                    "create viewer-state store parent {}",
                    parent_chirho.display()
                )
            })?;
        }
        let open_guard_chirho = crate::StoreOpenGuardChirho::acquire_chirho(path_chirho)?;
        let db_chirho = Database::create(path_chirho)
            .with_context(|| format!("open viewer-state store at {}", path_chirho.display()))?;
        let store_chirho = Self {
            db_chirho,
            _open_guard_chirho: open_guard_chirho,
        };
        let transaction_chirho = store_chirho.begin_immediate_write_chirho()?;
        {
            let _entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
            let _key_counts_chirho =
                transaction_chirho.open_table(VIEWER_STATE_KEY_COUNTS_CHIRHO)?;
            let _heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
        }
        transaction_chirho.commit()?;
        Ok(store_chirho)
    }

    /// Open a carried store without creating or upgrading it. Restore verification uses this
    /// read-only shape so a missing or malformed database cannot be repaired by the verifier.
    pub fn open_existing_chirho(path_chirho: &Path) -> Result<Self> {
        if !path_chirho.is_file() {
            bail!(
                "viewer-state store does not exist at {}",
                path_chirho.display()
            );
        }
        let open_guard_chirho = crate::StoreOpenGuardChirho::acquire_chirho(path_chirho)?;
        let db_chirho = Database::open(path_chirho).with_context(|| {
            format!(
                "open existing viewer-state store at {}",
                path_chirho.display()
            )
        })?;
        let store_chirho = Self {
            db_chirho,
            _open_guard_chirho: open_guard_chirho,
        };
        let transaction_chirho = store_chirho.db_chirho.begin_read()?;
        {
            let _entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
            let _key_counts_chirho =
                transaction_chirho.open_table(VIEWER_STATE_KEY_COUNTS_CHIRHO)?;
            let _heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
        }
        Ok(store_chirho)
    }

    fn begin_immediate_write_chirho(&self) -> Result<redb::WriteTransaction> {
        let mut transaction_chirho = self.db_chirho.begin_write()?;
        transaction_chirho.set_durability(VIEWER_STATE_WRITE_DURABILITY_CHIRHO);
        Ok(transaction_chirho)
    }

    pub fn latest_chirho(&self, key_chirho: &str) -> Result<Option<ViewerStateEntryChirho>> {
        let transaction_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
        let heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
        let head_chirho = heads_chirho
            .get(key_chirho)?
            .map(|value_chirho| decode_head_chirho(value_chirho.value()))
            .transpose()?;
        verify_entry_head_shape_chirho(&entries_chirho, key_chirho, head_chirho.as_ref())?;
        let Some(head_chirho) = head_chirho else {
            return Ok(None);
        };
        let value_chirho = entries_chirho
            .get((key_chirho, head_chirho.version_chirho))?
            .ok_or_else(|| anyhow::anyhow!("viewer-state head points to a missing latest row"))?;
        Ok(Some(ViewerStateEntryChirho {
            version_chirho: head_chirho.version_chirho,
            value_chirho: value_chirho.value().to_vec(),
        }))
    }

    pub fn head_chirho(&self, key_chirho: &str) -> Result<Option<ViewerStateHeadChirho>> {
        let transaction_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
        let heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
        let head_chirho = heads_chirho
            .get(key_chirho)?
            .map(|value_chirho| decode_head_chirho(value_chirho.value()))
            .transpose()?;
        verify_entry_head_shape_chirho(&entries_chirho, key_chirho, head_chirho.as_ref())?;
        Ok(head_chirho)
    }

    pub fn exact_chirho(
        &self,
        key_chirho: &str,
        version_chirho: u64,
    ) -> Result<Option<ViewerStateEntryChirho>> {
        let transaction_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
        Ok(entries_chirho
            .get((key_chirho, version_chirho))?
            .map(|value_chirho| ViewerStateEntryChirho {
                version_chirho,
                value_chirho: value_chirho.value().to_vec(),
            }))
    }

    /// Newest-first retained history. The caller chooses a limit no larger than the write-side
    /// retention limit; this method never scans beyond that bounded count.
    pub fn history_chirho(
        &self,
        key_chirho: &str,
        limit_chirho: usize,
    ) -> Result<Vec<ViewerStateEntryChirho>> {
        if limit_chirho == 0 {
            return Ok(Vec::new());
        }
        let transaction_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
        let heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
        let head_chirho = heads_chirho
            .get(key_chirho)?
            .map(|value_chirho| decode_head_chirho(value_chirho.value()))
            .transpose()?;
        verify_entry_head_shape_chirho(&entries_chirho, key_chirho, head_chirho.as_ref())?;
        let Some(head_chirho) = head_chirho else {
            return Ok(Vec::new());
        };
        let mut history_chirho = Vec::with_capacity(limit_chirho);
        let retained_count_chirho = usize::try_from(head_chirho.version_chirho)
            .unwrap_or(usize::MAX)
            .min(limit_chirho);
        for offset_chirho in 0..retained_count_chirho {
            let version_chirho = head_chirho.version_chirho - offset_chirho as u64;
            let value_chirho = entries_chirho
                .get((key_chirho, version_chirho))?
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "viewer-state retained history is missing version {version_chirho}"
                    )
                })?;
            history_chirho.push(ViewerStateEntryChirho {
                version_chirho,
                value_chirho: value_chirho.value().to_vec(),
            });
        }
        Ok(history_chirho)
    }

    /// Atomically compare the current per-key version, append one new version, and retire the row
    /// that fell outside the fixed hot-history window. No root-wide view cursor is read or moved.
    pub fn append_bounded_chirho(
        &self,
        viewer_scope_chirho: &str,
        key_chirho: &str,
        head_transition_chirho: &ViewerStateHeadTransitionChirho,
        value_chirho: &[u8],
        history_limit_chirho: u64,
        max_keys_chirho: u64,
    ) -> Result<u64> {
        if viewer_scope_chirho.is_empty() {
            bail!("viewer-state scope cannot be empty");
        }
        if key_chirho.is_empty() {
            bail!("viewer-state key cannot be empty");
        }
        if !key_chirho.starts_with(viewer_scope_chirho) {
            bail!("viewer-state key is outside its host-derived viewer scope");
        }
        if history_limit_chirho == 0 {
            bail!("viewer-state history limit cannot be zero");
        }
        if max_keys_chirho == 0 {
            bail!("viewer-state key limit cannot be zero");
        }
        validate_receipt_digest_chirho(&head_transition_chirho.next_chirho.receipt_digest_chirho)?;
        let transaction_chirho = self.begin_immediate_write_chirho()?;
        let next_version_chirho;
        {
            let mut entries_chirho = transaction_chirho.open_table(VIEWER_STATE_ENTRIES_CHIRHO)?;
            let mut key_counts_chirho =
                transaction_chirho.open_table(VIEWER_STATE_KEY_COUNTS_CHIRHO)?;
            let mut heads_chirho = transaction_chirho.open_table(VIEWER_STATE_HEADS_CHIRHO)?;
            let current_head_chirho = heads_chirho
                .get(key_chirho)?
                .map(|value_chirho| decode_head_chirho(value_chirho.value()))
                .transpose()?;
            verify_entry_head_shape_chirho(
                &entries_chirho,
                key_chirho,
                current_head_chirho.as_ref(),
            )?;
            if current_head_chirho != head_transition_chirho.expected_chirho {
                bail!(
                    "viewer-state authoritative head changed: expected {:?}, received {:?}",
                    head_transition_chirho.expected_chirho,
                    current_head_chirho
                );
            }
            if current_head_chirho.is_none() {
                let current_key_count_chirho = key_counts_chirho
                    .get(viewer_scope_chirho)?
                    .map(|count_chirho| count_chirho.value())
                    .unwrap_or(0);
                if current_key_count_chirho >= max_keys_chirho {
                    bail!("viewer-state key limit of {max_keys_chirho} reached");
                }
                let next_key_count_chirho = current_key_count_chirho
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("viewer-state key count exhausted"))?;
                key_counts_chirho.insert(viewer_scope_chirho, next_key_count_chirho)?;
            }
            next_version_chirho = current_head_chirho
                .as_ref()
                .map(|head_chirho| head_chirho.version_chirho)
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("viewer-state version exhausted"))?;
            if head_transition_chirho.next_chirho.version_chirho != next_version_chirho {
                bail!(
                    "viewer-state proposed next head version disagrees: expected {next_version_chirho}, received {}",
                    head_transition_chirho.next_chirho.version_chirho
                );
            }
            entries_chirho.insert((key_chirho, next_version_chirho), value_chirho)?;
            let next_head_bytes_chirho = encode_head_chirho(&head_transition_chirho.next_chirho)?;
            heads_chirho.insert(key_chirho, next_head_bytes_chirho.as_slice())?;
            if next_version_chirho > history_limit_chirho {
                let retired_version_chirho = next_version_chirho - history_limit_chirho;
                entries_chirho.remove((key_chirho, retired_version_chirho))?;
            }
        }
        transaction_chirho.commit()?;
        Ok(next_version_chirho)
    }

    /// Read the transactionally maintained logical-key count for one host-derived viewer scope.
    /// This is O(1); first-write admission never scans another viewer's rows.
    pub fn key_count_for_viewer_chirho(&self, viewer_scope_chirho: &str) -> Result<u64> {
        let transaction_chirho = self.db_chirho.begin_read()?;
        let key_counts_chirho = transaction_chirho.open_table(VIEWER_STATE_KEY_COUNTS_CHIRHO)?;
        Ok(key_counts_chirho
            .get(viewer_scope_chirho)?
            .map(|count_chirho| count_chirho.value())
            .unwrap_or(0))
    }
}

fn verify_entry_head_shape_chirho(
    entries_chirho: &impl ReadableTable<(&'static str, u64), &'static [u8]>,
    key_chirho: &str,
    head_chirho: Option<&ViewerStateHeadChirho>,
) -> Result<()> {
    let mut range_chirho = entries_chirho.range((key_chirho, 0_u64)..=(key_chirho, u64::MAX))?;
    let latest_entry_version_chirho = match range_chirho.next_back() {
        Some(entry_chirho) => {
            let (entry_key_chirho, _value_chirho) = entry_chirho?;
            let (_stored_key_chirho, version_chirho) = entry_key_chirho.value();
            Some(version_chirho)
        }
        None => None,
    };
    let head_version_chirho = head_chirho.map(|head_chirho| head_chirho.version_chirho);
    if latest_entry_version_chirho != head_version_chirho {
        bail!(
            "viewer-state authoritative head disagrees with retained entries: head {:?}, latest row {:?}",
            head_version_chirho,
            latest_entry_version_chirho
        );
    }
    Ok(())
}

fn encode_head_chirho(head_chirho: &ViewerStateHeadChirho) -> Result<Vec<u8>> {
    validate_receipt_digest_chirho(&head_chirho.receipt_digest_chirho)?;
    Ok(serde_json::to_vec(&(
        head_chirho.version_chirho,
        &head_chirho.receipt_digest_chirho,
    ))?)
}

fn decode_head_chirho(bytes_chirho: &[u8]) -> Result<ViewerStateHeadChirho> {
    let (version_chirho, receipt_digest_chirho): (u64, HashChirho) =
        serde_json::from_slice(bytes_chirho).context("decode viewer-state authoritative head")?;
    if version_chirho == 0 {
        bail!("viewer-state authoritative head version cannot be zero");
    }
    validate_receipt_digest_chirho(&receipt_digest_chirho)?;
    Ok(ViewerStateHeadChirho {
        version_chirho,
        receipt_digest_chirho,
    })
}

fn validate_receipt_digest_chirho(receipt_digest_chirho: &HashChirho) -> Result<()> {
    if receipt_digest_chirho.0.len() != 64
        || !receipt_digest_chirho
            .0
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_digit() || (b'a'..=b'f').contains(&byte_chirho))
    {
        bail!("viewer-state receipt digest shape invalid");
    }
    Ok(())
}

#[cfg(test)]
#[path = "viewer_state_chirho/tests_chirho.rs"]
mod tests_chirho;
