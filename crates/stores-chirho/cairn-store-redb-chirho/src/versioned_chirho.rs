// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Brick 2 — the versioned MVCC store, built on redb.
//!
//! `cas_chirho` is immutable truth; this is the *queryable, time-travelling* projection
//! of it. The MVCC model is the one Postgres, SQL:2011 temporal tables, and Datomic share
//! (DESIGN §14, §143): every write creates a new row-version stamped with a monotonic
//! version number; a read resolves the greatest version `<= the current view`; and
//! **rollback changes the view (V)** — it never deletes, so history stays intact.
//!
//! Two counters live in the META table:
//!   * `next_version` — only ever increases; the source of fresh version stamps.
//!   * `current_view` — the V that reads resolve against; rollback moves it back.
//!
//! A write advances both; a rollback moves only `current_view`. Because version numbers
//! are never reused, historical reads (`get_at`) stay valid after a rollback.
//!
//! Scope (honest): **linear history** — branching timelines (a put after a rollback
//! forking a new line) are deferred. `reify` commits a *set* of entries atomically at one
//! version — the storage primitive reify needs; walking a typed FK closure belongs to the
//! schema layer and is deferred. Durability / crash-safety is redb's job, never ours.

use anyhow::{Context, Result};
use redb::{Database, Durability, ReadableTable, TableDefinition};
use std::collections::BTreeSet;
use std::path::Path;

/// `(entity key, valid_from version) -> serialized value bytes`. Tuple ordering keeps a
/// key's versions contiguous and ascending, so a range scan finds the one in effect at V.
const ENTRIES_CHIRHO: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("entries_chirho");
/// `counter name -> value`. Holds `next_version` and `current_view`.
const META_CHIRHO: TableDefinition<&str, u64> = TableDefinition::new("meta_chirho");
/// `(version, key) -> ()`. Which keys were written at each version, ordered by `(version, key)`
/// so a range scan by version yields the changed-key delta between two views in O(delta) — the
/// basis for incremental read-model maintenance. Additive: the temporal store's own correctness
/// never depends on it; only the derived projection consults it.
const CHANGELOG_CHIRHO: TableDefinition<(u64, &str), ()> = TableDefinition::new("changelog_chirho");

const NEXT_VERSION_CHIRHO: &str = "next_version";
const CURRENT_VIEW_CHIRHO: &str = "current_view";
/// The lowest version whose changed-key delta CHANGELOG is trusted to hold in full. See
/// `init_meta_chirho` for why it exists and how it is pinned.
const CHANGELOG_FLOOR_CHIRHO: &str = "changelog_floor";

// A per-thread count of ENTRIES rows the reverse point-lookup in `get_at_chirho` decodes. The
// lookup takes the greatest version `<= v` via a single `next_back()`, so it decodes exactly one
// row (or zero on a miss) regardless of how deep the key's version chain is; the scaling guard
// `get_at_decodes_one_row_regardless_of_history_depth_chirho` asserts that O(1)-decode invariant.
// Thread-local so parallel tests never pollute each other's count; compiled only under `cfg(test)`,
// so no production overhead and downstream crates (e.g. cairn-query-chirho) never see it.
#[cfg(test)]
thread_local! {
    static GET_AT_ROWS_DECODED_CHIRHO: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// The durability every versioned-store write commits at. Explicit `Durability::Immediate` — never
/// redb's changeable default — because this store holds customer / money-adjacent reified data
/// (Door B's F4 surface), and the crate pins `redb = "2"` (not a patch version), so a dependency
/// bump must not be able to silently move this commit point off synchronous durability. Mirrors the
/// sibling audit store's `begin_immediate_write_chirho`.
const VERSIONED_WRITE_DURABILITY_CHIRHO: Durability = Durability::Immediate;

/// A handle to the versioned store (one redb database file).
pub struct VersionedStoreChirho {
    db_chirho: Database,
    /// Declared after the database, so its file lock is released before the next opener in this process proceeds.
    _open_guard_chirho: crate::StoreOpenGuardChirho,
}

impl VersionedStoreChirho {
    /// Open (or create) the versioned store at `path`.
    pub fn open_chirho(path_chirho: &Path) -> Result<Self> {
        if let Some(parent_chirho) = path_chirho.parent() {
            std::fs::create_dir_all(parent_chirho).ok();
        }
        let open_guard_chirho = crate::StoreOpenGuardChirho::acquire_chirho(path_chirho)?;
        let db_chirho = Database::create(path_chirho)
            .with_context(|| format!("open redb store at {}", path_chirho.display()))?;
        let store_chirho = Self {
            db_chirho,
            _open_guard_chirho: open_guard_chirho,
        };
        store_chirho.init_meta_chirho()?;
        Ok(store_chirho)
    }

    /// Begin a write transaction pinned to explicit `Durability::Immediate`.
    ///
    /// Every write to this store (init, reify, rollback) routes through here, so the commit point
    /// is synchronous-durable by construction rather than by redb's changeable default — see
    /// `VERSIONED_WRITE_DURABILITY_CHIRHO`.
    fn begin_immediate_write_chirho(&self) -> Result<redb::WriteTransaction> {
        let mut txn_chirho = self.db_chirho.begin_write()?;
        txn_chirho.set_durability(VERSIONED_WRITE_DURABILITY_CHIRHO);
        Ok(txn_chirho)
    }

    /// Ensure the counters exist (idempotent): `next_version` starts at 1, view at 0 (empty), and
    /// the changelog floor is pinned once (see the floor comment below).
    fn init_meta_chirho(&self) -> Result<()> {
        let txn_chirho = self.begin_immediate_write_chirho()?;
        {
            // Open (create) both tables so a read on a fresh store (before any write) does
            // not fail with "table does not exist".
            let _entries_chirho = txn_chirho.open_table(ENTRIES_CHIRHO)?;
            let _changelog_chirho = txn_chirho.open_table(CHANGELOG_CHIRHO)?;
            let mut meta_chirho = txn_chirho.open_table(META_CHIRHO)?;
            if meta_chirho.get(NEXT_VERSION_CHIRHO)?.is_none() {
                meta_chirho.insert(NEXT_VERSION_CHIRHO, 1u64)?;
            }
            if meta_chirho.get(CURRENT_VIEW_CHIRHO)?.is_none() {
                meta_chirho.insert(CURRENT_VIEW_CHIRHO, 0u64)?;
            }
            // Changelog floor — the lowest version whose changed-key delta CHANGELOG is trusted to
            // hold in full. `open_table` above creates CHANGELOG empty, so a root that accreted
            // ENTRIES history BEFORE this table existed (a pre-changelog "legacy" root) presents an
            // empty changelog for its entire past; an incremental projection spanning those versions
            // would silently miss changes and leave stale rows standing after a rollback. Pin the
            // floor ONCE, only when the key is absent:
            //   * fresh store -> next_version == 1, so floor == 1 (the whole future is recorded);
            //   * legacy root -> next_version > 1, so floor == next_version (only writes from here on
            //     are recorded; nothing before now is trusted).
            // A root that already wrote SOME genuine post-brick changelog rows before this fix also
            // arrives here with the key missing; we still pin floor = next_version at THIS open. That
            // is deliberately conservative — it may force one extra full reproject across the few
            // truly-recorded pre-fix versions — because never trusting a partial changelog outranks
            // reclaiming those deltas (correctness over cleverness).
            if meta_chirho.get(CHANGELOG_FLOOR_CHIRHO)?.is_none() {
                let next_version_chirho = meta_chirho
                    .get(NEXT_VERSION_CHIRHO)?
                    .map(|g_chirho| g_chirho.value())
                    .unwrap_or(1);
                meta_chirho.insert(CHANGELOG_FLOOR_CHIRHO, next_version_chirho)?;
            }
        }
        txn_chirho.commit()?;
        Ok(())
    }

    fn read_meta_chirho(&self, name_chirho: &str) -> Result<u64> {
        let txn_chirho = self.db_chirho.begin_read()?;
        let meta_chirho = txn_chirho.open_table(META_CHIRHO)?;
        Ok(meta_chirho
            .get(name_chirho)?
            .map(|g_chirho| g_chirho.value())
            .unwrap_or(0))
    }

    /// The version reads currently resolve against.
    pub fn current_view_chirho(&self) -> Result<u64> {
        self.read_meta_chirho(CURRENT_VIEW_CHIRHO)
    }

    /// The lowest version whose changed-key delta is fully recorded in CHANGELOG (pinned once by
    /// `init_meta_chirho`, then immutable). Any incremental read-model span dipping BELOW this floor
    /// cannot trust the changelog and must fall back to a full reproject; at or above it, every
    /// change is recorded. `init_meta_chirho` always seeds the key, so a fresh open never reads 0.
    pub fn changelog_floor_chirho(&self) -> Result<u64> {
        self.read_meta_chirho(CHANGELOG_FLOOR_CHIRHO)
    }

    /// Write a new value for `key`; returns the version it was stamped with.
    /// Advances both `next_version` and `current_view`.
    pub fn put_chirho(&self, key_chirho: &str, value_chirho: &[u8]) -> Result<u64> {
        self.reify_chirho(&[(key_chirho, value_chirho)])
    }

    /// Commit a *set* of entries atomically at a single new version — a referential
    /// closure, in reify terms. Either all land or none do (one redb transaction).
    /// Returns the version they were stamped with.
    pub fn reify_chirho(&self, entries_chirho: &[(&str, &[u8])]) -> Result<u64> {
        let txn_chirho = self.begin_immediate_write_chirho()?;
        let version_chirho;
        {
            let mut meta_chirho = txn_chirho.open_table(META_CHIRHO)?;
            version_chirho = meta_chirho
                .get(NEXT_VERSION_CHIRHO)?
                .map(|g_chirho| g_chirho.value())
                .unwrap_or(1);
            let mut entries_table_chirho = txn_chirho.open_table(ENTRIES_CHIRHO)?;
            let mut changelog_chirho = txn_chirho.open_table(CHANGELOG_CHIRHO)?;
            for (key_chirho, value_chirho) in entries_chirho {
                entries_table_chirho.insert((*key_chirho, version_chirho), *value_chirho)?;
                changelog_chirho.insert((version_chirho, *key_chirho), ())?;
            }
            meta_chirho.insert(NEXT_VERSION_CHIRHO, version_chirho + 1)?;
            meta_chirho.insert(CURRENT_VIEW_CHIRHO, version_chirho)?;
        }
        txn_chirho.commit()?;
        Ok(version_chirho)
    }

    /// The value of `key` at view version `v`: the greatest row-version `<= v`. `None` if
    /// the key had no version at or before `v`.
    pub fn get_at_chirho(&self, key_chirho: &str, v_chirho: u64) -> Result<Option<Vec<u8>>> {
        let txn_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = txn_chirho.open_table(ENTRIES_CHIRHO)?;
        // This key's versions in [0, v]; the greatest is the one in effect at v. redb's `Range` is
        // double-ended, so `next_back()` seeks straight to that last row in O(log n) — no forward
        // walk over every version. Semantics are identical to keeping the last of an ascending scan.
        let mut range_chirho = entries_chirho.range((key_chirho, 0u64)..=(key_chirho, v_chirho))?;
        match range_chirho.next_back() {
            Some(item_chirho) => {
                let (_key_chirho, value_chirho) = item_chirho?;
                #[cfg(test)]
                GET_AT_ROWS_DECODED_CHIRHO
                    .with(|counter_chirho| counter_chirho.set(counter_chirho.get() + 1));
                Ok(Some(value_chirho.value().to_vec()))
            }
            None => Ok(None),
        }
    }

    /// The current value of `key` (resolved at `current_view`).
    pub fn get_chirho(&self, key_chirho: &str) -> Result<Option<Vec<u8>>> {
        let view_chirho = self.current_view_chirho()?;
        self.get_at_chirho(key_chirho, view_chirho)
    }

    /// Every key's value at the current view (the greatest version `<= current_view` per key).
    /// The basis for the derived read model. Keys with no version at or before the view are
    /// omitted. ENTRIES is ordered (key, version), so a single scan suffices.
    pub fn current_entries_chirho(&self) -> Result<Vec<(String, Vec<u8>)>> {
        self.current_entries_at_chirho(self.current_view_chirho()?)
    }

    /// Every key's value as-of an explicit view version `view_chirho` — the basis for
    /// version-aware projection. Same single ordered scan as `current_entries_chirho`.
    pub fn current_entries_at_chirho(&self, view_chirho: u64) -> Result<Vec<(String, Vec<u8>)>> {
        let txn_chirho = self.db_chirho.begin_read()?;
        let entries_chirho = txn_chirho.open_table(ENTRIES_CHIRHO)?;
        let mut out_chirho: Vec<(String, Vec<u8>)> = Vec::new();
        let mut current_key_chirho: Option<String> = None;
        let mut current_val_chirho: Option<Vec<u8>> = None;
        for item_chirho in entries_chirho.iter()? {
            let (k_chirho, v_chirho) = item_chirho?;
            let (key_str_chirho, version_chirho) = k_chirho.value();
            if version_chirho > view_chirho {
                continue; // not visible at the current view
            }
            let key_owned_chirho = key_str_chirho.to_string();
            if current_key_chirho.as_deref() == Some(key_owned_chirho.as_str()) {
                current_val_chirho = Some(v_chirho.value().to_vec());
            } else {
                if let (Some(pk_chirho), Some(pv_chirho)) =
                    (current_key_chirho.take(), current_val_chirho.take())
                {
                    out_chirho.push((pk_chirho, pv_chirho));
                }
                current_key_chirho = Some(key_owned_chirho);
                current_val_chirho = Some(v_chirho.value().to_vec());
            }
        }
        if let (Some(pk_chirho), Some(pv_chirho)) = (current_key_chirho, current_val_chirho) {
            out_chirho.push((pk_chirho, pv_chirho));
        }
        Ok(out_chirho)
    }

    /// The DISTINCT keys written at any version in the half-open range `(after_chirho,
    /// through_chirho]` (i.e. `after_chirho < version <= through_chirho`). An ordered changelog
    /// scan — O(delta), not O(all rows) — giving the set a derived read model must re-apply to
    /// move its view from `after` to `through` (the caller reads each key's value at the target).
    /// Empty when `through <= after`.
    pub fn changed_keys_in_chirho(
        &self,
        after_chirho: u64,
        through_chirho: u64,
    ) -> Result<Vec<String>> {
        if through_chirho <= after_chirho {
            return Ok(Vec::new());
        }
        let txn_chirho = self.db_chirho.begin_read()?;
        let changelog_chirho = txn_chirho.open_table(CHANGELOG_CHIRHO)?;
        // Versions in [after+1, through]: from (after+1, "") up to but excluding (through+1, "").
        let start_chirho: (u64, &str) = (after_chirho + 1, "");
        let end_chirho: (u64, &str) = (through_chirho + 1, "");
        let mut seen_chirho: BTreeSet<String> = BTreeSet::new();
        for item_chirho in changelog_chirho.range(start_chirho..end_chirho)? {
            let (k_chirho, _unit_chirho) = item_chirho?;
            let (_version_chirho, key_str_chirho) = k_chirho.value();
            seen_chirho.insert(key_str_chirho.to_string());
        }
        Ok(seen_chirho.into_iter().collect())
    }

    /// Roll the store's view to version `v` (back, or forward again). This is the whole of
    /// rollback for internal state: O(1), nothing deleted, history preserved (DESIGN §143).
    pub fn rollback_to_chirho(&self, v_chirho: u64) -> Result<()> {
        let txn_chirho = self.begin_immediate_write_chirho()?;
        {
            let mut meta_chirho = txn_chirho.open_table(META_CHIRHO)?;
            meta_chirho.insert(CURRENT_VIEW_CHIRHO, v_chirho)?;
        }
        txn_chirho.commit()?;
        Ok(())
    }

    /// TEST / MIGRATION-SIMULATION ONLY. Empties the CHANGELOG table and drops the changelog-floor
    /// meta key, reproducing the on-disk shape of a "legacy" root created BEFORE the changelog
    /// existed (ENTRIES history present, changelog absent). On the next `open_chirho`,
    /// `init_meta_chirho` re-derives the floor from `next_version`, so an incremental projection
    /// spanning the now-unrecorded past is forced to full-reproject. NEVER call on a live store: it
    /// discards the changelog deltas the read model's incremental fast path relies on. Compiled only
    /// for this crate's tests or under the `test-hooks-chirho` feature (downstream crates enable it
    /// via a dev-dependency), so no production build can even name it.
    #[cfg(any(test, feature = "test-hooks-chirho"))]
    #[doc(hidden)]
    pub fn simulate_pre_changelog_legacy_root_chirho(&self) -> Result<()> {
        let txn_chirho = self.db_chirho.begin_write()?;
        {
            let mut changelog_chirho = txn_chirho.open_table(CHANGELOG_CHIRHO)?;
            // Collect the keys first (ending the read borrow) before removing — redb's `iter` holds
            // an immutable borrow that must be released before the mutable `remove`.
            let keys_chirho: Vec<(u64, String)> = {
                let mut acc_chirho: Vec<(u64, String)> = Vec::new();
                for item_chirho in changelog_chirho.iter()? {
                    let (k_chirho, _unit_chirho) = item_chirho?;
                    let (version_chirho, key_str_chirho) = k_chirho.value();
                    acc_chirho.push((version_chirho, key_str_chirho.to_string()));
                }
                acc_chirho
            };
            for (version_chirho, key_chirho) in &keys_chirho {
                changelog_chirho.remove((*version_chirho, key_chirho.as_str()))?;
            }
            let mut meta_chirho = txn_chirho.open_table(META_CHIRHO)?;
            meta_chirho.remove(CHANGELOG_FLOOR_CHIRHO)?;
        }
        txn_chirho.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_db_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-vers-test-{nanos_chirho}-{n_chirho}.redb"))
    }

    #[test]
    fn put_get_temporal_and_rollback_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();

        let v1_chirho = store_chirho.put_chirho("x", b"alpha").unwrap();
        let v2_chirho = store_chirho.put_chirho("x", b"beta").unwrap();
        assert!(v2_chirho > v1_chirho);
        assert_eq!(store_chirho.current_view_chirho().unwrap(), v2_chirho);
        assert_eq!(
            store_chirho.get_chirho("x").unwrap().as_deref(),
            Some(&b"beta"[..])
        );

        // Temporal reads resolve each version independently.
        assert_eq!(
            store_chirho
                .get_at_chirho("x", v1_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"alpha"[..])
        );
        assert_eq!(
            store_chirho
                .get_at_chirho("x", v2_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"beta"[..])
        );

        // Rollback moves the view; the current read changes, history stays intact.
        store_chirho.rollback_to_chirho(v1_chirho).unwrap();
        assert_eq!(store_chirho.current_view_chirho().unwrap(), v1_chirho);
        assert_eq!(
            store_chirho.get_chirho("x").unwrap().as_deref(),
            Some(&b"alpha"[..])
        );
        assert_eq!(
            store_chirho
                .get_at_chirho("x", v2_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"beta"[..])
        );

        // An absent key resolves to None.
        assert_eq!(store_chirho.get_chirho("missing").unwrap(), None);

        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn get_on_fresh_store_is_none_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        // Read before any write must not error (regression: missing ENTRIES table).
        assert_eq!(store_chirho.get_chirho("absent").unwrap(), None);
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn current_entries_lists_view_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        store_chirho.put_chirho("a", b"1").unwrap();
        store_chirho.put_chirho("b", b"2").unwrap();
        store_chirho.put_chirho("a", b"3").unwrap();
        let mut entries_chirho = store_chirho.current_entries_chirho().unwrap();
        entries_chirho.sort();
        assert_eq!(
            entries_chirho,
            vec![
                ("a".to_string(), b"3".to_vec()),
                ("b".to_string(), b"2".to_vec())
            ]
        );
        // Roll back to v1: only a=1 is visible (b appeared at v2).
        store_chirho.rollback_to_chirho(1).unwrap();
        assert_eq!(
            store_chirho.current_entries_chirho().unwrap(),
            vec![("a".to_string(), b"1".to_vec())]
        );
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn changed_keys_in_returns_delta_only_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        store_chirho.put_chirho("a", b"1").unwrap(); // v1
        store_chirho.put_chirho("b", b"2").unwrap(); // v2
        store_chirho
            .reify_chirho(&[("a", b"3"), ("c", b"4")])
            .unwrap(); // v3: a again + c

        // Delta since v2 is exactly {a, c} (both written at v3), never b.
        assert_eq!(
            store_chirho.changed_keys_in_chirho(2, 3).unwrap(),
            vec!["a".to_string(), "c".to_string()]
        );
        // Whole range: every distinct key ever written.
        assert_eq!(
            store_chirho.changed_keys_in_chirho(0, 3).unwrap(),
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        // Empty / inverted ranges yield nothing.
        assert!(store_chirho
            .changed_keys_in_chirho(3, 3)
            .unwrap()
            .is_empty());
        assert!(store_chirho
            .changed_keys_in_chirho(3, 1)
            .unwrap()
            .is_empty());
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn reify_commits_a_closure_atomically_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();

        // A Purchase and the User it references, committed at one version.
        let version_chirho = store_chirho
            .reify_chirho(&[("user", b"u1"), ("purchase", b"p1")])
            .unwrap();
        assert_eq!(store_chirho.current_view_chirho().unwrap(), version_chirho);
        assert_eq!(
            store_chirho
                .get_at_chirho("user", version_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"u1"[..])
        );
        assert_eq!(
            store_chirho
                .get_at_chirho("purchase", version_chirho)
                .unwrap()
                .as_deref(),
            Some(&b"p1"[..])
        );
        // Before that version, neither existed.
        assert_eq!(
            store_chirho
                .get_at_chirho("user", version_chirho - 1)
                .unwrap(),
            None
        );

        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn get_at_decodes_one_row_regardless_of_history_depth_chirho() {
        // Scaling guard for the O(1)-runtime-cost invariant on the M (history-depth) axis: a
        // point-in-time lookup must NOT scan the whole version chain. The reverse `next_back()`
        // range decodes exactly one row (or zero on a miss), independent of how many versions the
        // key has. A regression to a forward keep-last scan would decode M rows and trip this.
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        let depth_chirho: u64 = 200;
        let mut tip_chirho = 0u64;
        for i_chirho in 0..depth_chirho {
            tip_chirho = store_chirho
                .put_chirho("k", format!("v{i_chirho}").as_bytes())
                .unwrap();
        }

        // At the tip: one decode.
        GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.set(0));
        let tip_val_chirho = store_chirho.get_at_chirho("k", tip_chirho).unwrap();
        assert_eq!(
            tip_val_chirho.as_deref(),
            Some(format!("v{}", depth_chirho - 1).as_bytes())
        );
        assert_eq!(
            GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.get()),
            1,
            "reverse point-lookup must decode one row, not walk the version chain"
        );

        // At an early version: still one decode (history depth ahead of it is irrelevant).
        GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.set(0));
        assert_eq!(
            store_chirho.get_at_chirho("k", 3).unwrap().as_deref(),
            Some(&b"v2"[..])
        );
        assert_eq!(
            GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.get()),
            1
        );

        // A miss decodes zero rows.
        GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.set(0));
        assert_eq!(
            store_chirho.get_at_chirho("absent", tip_chirho).unwrap(),
            None
        );
        assert_eq!(
            GET_AT_ROWS_DECODED_CHIRHO.with(|counter_chirho| counter_chirho.get()),
            0
        );

        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn changelog_floor_is_one_on_fresh_store_chirho() {
        let path_chirho = tmp_db_chirho();
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        // A fresh store records its whole future from version 1 onward, so the floor is 1 and no
        // span can dip below it — the incremental fast path is never spuriously disabled.
        assert_eq!(store_chirho.changelog_floor_chirho().unwrap(), 1);
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn changelog_floor_pins_legacy_root_to_next_version_chirho() {
        let path_chirho = tmp_db_chirho();
        {
            let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
            store_chirho.put_chirho("a", b"1").unwrap(); // v1
            store_chirho.put_chirho("b", b"2").unwrap(); // v2
            store_chirho
                .reify_chirho(&[("a", b"3"), ("c", b"4")])
                .unwrap(); // v3 (next_version now 4)
            assert_eq!(store_chirho.changelog_floor_chirho().unwrap(), 1);
            // Reproduce a root whose history predates the changelog: empty changelog + no floor key.
            store_chirho
                .simulate_pre_changelog_legacy_root_chirho()
                .unwrap();
        }
        // Reopen: init re-derives the floor to next_version (4), so the whole pre-existing past
        // sits BELOW the floor.
        let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        assert_eq!(store_chirho.changelog_floor_chirho().unwrap(), 4);
        // The legacy gap is real: ENTRIES survive, but the changelog is empty below the floor, so a
        // delta scan there returns nothing — exactly why a sub-floor span must full-reproject.
        assert!(store_chirho
            .changed_keys_in_chirho(0, 3)
            .unwrap()
            .is_empty());
        assert_eq!(
            store_chirho.get_at_chirho("a", 3).unwrap().as_deref(),
            Some(&b"3"[..])
        );
        let _ = std::fs::remove_file(&path_chirho);
    }

    #[test]
    fn versioned_writes_commit_with_immediate_durability_chirho() {
        // Customer / money-adjacent reified data (Door B's F4 surface): the store's commit point
        // must be explicit `Durability::Immediate`, never redb's changeable default (the sibling
        // audit store already pins this). redb 2.x exposes NO getter to read a live transaction's
        // durability back, so this pins the durability CHOICE at the value level — a future edit
        // flipping it to `Eventual`/`None` fails here — while the reviewer confirms
        // `begin_immediate_write_chirho` applies it via `set_durability`. The reopen assertions
        // below confirm a committed reify is durable across a store close/reopen (Immediate can do
        // no worse than the default here; true crash durability is not reachable through redb's
        // public API).
        assert!(
            matches!(VERSIONED_WRITE_DURABILITY_CHIRHO, Durability::Immediate),
            "versioned-store writes must commit at Durability::Immediate"
        );

        let path_chirho = tmp_db_chirho();
        let version_chirho = {
            let store_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
            store_chirho.reify_chirho(&[("customer", b"paid")]).unwrap()
        }; // store dropped here -> redb database handle closed
        let reopened_chirho = VersionedStoreChirho::open_chirho(&path_chirho).unwrap();
        assert_eq!(
            reopened_chirho.current_view_chirho().unwrap(),
            version_chirho
        );
        assert_eq!(
            reopened_chirho.get_chirho("customer").unwrap().as_deref(),
            Some(&b"paid"[..])
        );
        let _ = std::fs::remove_file(&path_chirho);
    }
}
