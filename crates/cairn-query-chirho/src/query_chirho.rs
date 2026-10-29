// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Query — the derived read model (CQRS read side).
//!
//! Never query the content-addressed source directly (it is not a query engine). Instead
//! *project* reified state into a conventional fast structure — here, a SQLite table — and
//! query that. The read model is **derived & disposable**: `project_chirho` rebuilds it from
//! the versioned store's current view, so it can be dropped and regenerated at any time.
//!
//! v1 projection: one row per key (`key_chirho`, `value_chirho` as UTF-8-lossy text,
//! `value_len_chirho`). Schema-driven column projection of typed records (DESIGN §146) is a
//! later refinement; engine choice is SQLite for v1 (swappable — the model is disposable).

use anyhow::{bail, Context, Result};
use cairn_store_redb_chirho::versioned_chirho;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

fn readmodel_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("readmodel-chirho.sqlite")
}

fn versioned_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("versioned-chirho.redb")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRowChirho {
    pub key_chirho: String,
    pub value_chirho: String,
    pub value_len_chirho: i64,
}

/// Rebuild the read model from the versioned store's current view (full rebuild). The cold-start /
/// correctness-oracle path; the hot path is `refresh_incremental_chirho`. Sets the cursor.
pub fn project_chirho(root_chirho: &Path) -> Result<usize> {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let view_chirho = store_chirho.current_view_chirho()?;
    let entries_chirho = store_chirho.current_entries_chirho()?;
    drop(store_chirho);
    write_read_model_chirho(root_chirho, &entries_chirho, view_chirho)
}

/// Rebuild the read model as-of an explicit version `view_chirho` (version-aware / as-of).
pub fn project_at_chirho(root_chirho: &Path, view_chirho: u64) -> Result<usize> {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let entries_chirho = store_chirho.current_entries_at_chirho(view_chirho)?;
    drop(store_chirho);
    write_read_model_chirho(root_chirho, &entries_chirho, view_chirho)
}

/// Drop + recreate the SQLite read model from the given entries and set the projection cursor to
/// `cursor_version_chirho`. Disposable + rebuildable.
fn write_read_model_chirho(
    root_chirho: &Path,
    entries_chirho: &[(String, Vec<u8>)],
    cursor_version_chirho: u64,
) -> Result<usize> {
    let conn_chirho =
        Connection::open(readmodel_path_chirho(root_chirho)).context("open read model")?;
    conn_chirho.execute_batch(
        "DROP TABLE IF EXISTS entries_chirho;
         CREATE TABLE entries_chirho (
             key_chirho TEXT PRIMARY KEY,
             value_chirho TEXT,
             value_len_chirho INTEGER
         );",
    )?;
    for (key_chirho, value_chirho) in entries_chirho {
        conn_chirho.execute(
            "INSERT OR REPLACE INTO entries_chirho (key_chirho, value_chirho, value_len_chirho) VALUES (?1, ?2, ?3)",
            params![
                key_chirho,
                String::from_utf8_lossy(value_chirho).to_string(),
                value_chirho.len() as i64
            ],
        )?;
    }
    write_cursor_chirho(&conn_chirho, cursor_version_chirho)?;
    Ok(entries_chirho.len())
}

/// The read-model's own metadata (a separate table, so a full rebuild of `entries_chirho` never
/// loses the cursor). `cursor_version_chirho` = the versioned-store view the projection reflects.
const CURSOR_NAME_CHIRHO: &str = "cursor_version_chirho";

fn ensure_meta_table_chirho(conn_chirho: &Connection) -> Result<()> {
    conn_chirho.execute_batch(
        "CREATE TABLE IF NOT EXISTS readmodel_meta_chirho (
             name_chirho TEXT PRIMARY KEY,
             value_chirho INTEGER
         );",
    )?;
    Ok(())
}

fn read_cursor_chirho(conn_chirho: &Connection) -> Result<Option<u64>> {
    ensure_meta_table_chirho(conn_chirho)?;
    let raw_chirho: Option<i64> = conn_chirho
        .query_row(
            "SELECT value_chirho FROM readmodel_meta_chirho WHERE name_chirho = ?1",
            params![CURSOR_NAME_CHIRHO],
            |row_chirho| row_chirho.get(0),
        )
        .optional()?;
    Ok(raw_chirho.map(|v_chirho| v_chirho as u64))
}

fn write_cursor_chirho(conn_chirho: &Connection, version_chirho: u64) -> Result<()> {
    ensure_meta_table_chirho(conn_chirho)?;
    conn_chirho.execute(
        "INSERT OR REPLACE INTO readmodel_meta_chirho (name_chirho, value_chirho) VALUES (?1, ?2)",
        params![CURSOR_NAME_CHIRHO, version_chirho as i64],
    )?;
    Ok(())
}

fn entries_table_present_chirho(conn_chirho: &Connection) -> Result<bool> {
    let count_chirho: i64 = conn_chirho.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'entries_chirho'",
        [],
        |row_chirho| row_chirho.get(0),
    )?;
    Ok(count_chirho > 0)
}

/// Above this many changed keys in a rollback window, re-applying per-key point-lookups in a
/// transaction stops being cheaper than one bulk drop-and-rebuild, so the rollback branch falls back
/// to `project_at_chirho`. ~4096 = a redb page's worth of keys; the exact crossover is not load-
/// bearing (both branches yield the same rows), only that a huge delta never beats a full rebuild.
const ROLLBACK_DELTA_THRESHOLD_CHIRHO: usize = 4096;

/// Bring the read model up to the versioned store's current view INCREMENTALLY — applying only the
/// changed-key delta between the projection's cursor and the target (O(delta)), not the O(all rows)
/// full rebuild of `project_chirho`. The hot path, called after each write and each rollback.
/// Semantics:
///   * no cursor yet / missing table -> full rebuild as-of the target (sets the cursor);
///   * a span whose lower endpoint (min of cursor, target) dips BELOW the store's changelog floor ->
///     full rebuild — the changelog is not trusted before the floor, so the delta could miss changes
///     (see `versioned_chirho::VersionedStoreChirho::changelog_floor_chirho`);
///   * forward (cursor <= target) -> apply only `changed_keys_in(cursor, target)`, reading each key
///     at the target (upsert; a missing value is an append-only violation and bails LOUD);
///   * rollback (target < cursor) -> apply only `changed_keys_in(target, cursor)`, reading each key
///     at the target (upsert; a missing value here is LEGAL — the key was born after the target —
///     and DELETEs it), falling back to a full rebuild only when that delta exceeds
///     `ROLLBACK_DELTA_THRESHOLD_CHIRHO`.
///
/// The result is always identical to a full `project_at_chirho(target)` — the oracle invariant.
pub fn refresh_incremental_chirho(root_chirho: &Path) -> Result<usize> {
    let store_chirho =
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))?;
    let target_chirho = store_chirho.current_view_chirho()?;
    let mut conn_chirho =
        Connection::open(readmodel_path_chirho(root_chirho)).context("open read model")?;
    let cursor_chirho = read_cursor_chirho(&conn_chirho)?;
    let table_present_chirho = entries_table_present_chirho(&conn_chirho)?;

    if let Some(cursor_chirho) = cursor_chirho {
        // The incremental delta trusts CHANGELOG, which is complete only at or above the store's
        // changelog floor (a pre-changelog "legacy" root created its changelog empty for its whole
        // past — see versioned_chirho::VersionedStoreChirho::changelog_floor_chirho). If EITHER
        // endpoint of the span dips below the floor the delta can silently MISS changes — and on a
        // rollback that leaves stale rows STANDING (privacy-relevant: rows that must vanish at the
        // target would survive) — so fall through to the always-correct full reproject. Both
        // directions are equally incomplete below the floor: a forward delta from a pre-floor cursor
        // omits exactly the unrecorded versions a rollback into them would.
        let floor_chirho = store_chirho.changelog_floor_chirho()?;
        let span_above_floor_chirho = cursor_chirho.min(target_chirho) >= floor_chirho;
        if table_present_chirho && cursor_chirho <= target_chirho && span_above_floor_chirho {
            if cursor_chirho == target_chirho {
                return Ok(0);
            }
            let changed_chirho =
                store_chirho.changed_keys_in_chirho(cursor_chirho, target_chirho)?;
            let applied_chirho = changed_chirho.len();
            // ONE sqlite transaction: every entry apply THEN the cursor write commit atomically, so
            // a crash can never leave the cursor AHEAD of the entries (which would silently diverge
            // from a full rebuild). Invariant: entries first, cursor last, and all in one txn —
            // keep both the order and the atomicity; reordering either re-opens the divergence class.
            let tx_chirho = conn_chirho.transaction()?;
            for key_chirho in &changed_chirho {
                match store_chirho.get_at_chirho(key_chirho, target_chirho)? {
                    Some(value_chirho) => {
                        tx_chirho.execute(
                            "INSERT OR REPLACE INTO entries_chirho (key_chirho, value_chirho, value_len_chirho) VALUES (?1, ?2, ?3)",
                            params![
                                key_chirho,
                                String::from_utf8_lossy(&value_chirho).to_string(),
                                value_chirho.len() as i64
                            ],
                        )?;
                    }
                    // Unreachable via the public API: the store is append-only with no tombstone, so
                    // a key in `changed_keys_in` always has a version <= target. Fail LOUD rather than
                    // silently delete. NOTE: if tombstones are ever added, the FULL-REBUILD path
                    // (`current_entries_at_chirho`) must gain them TOO, or incremental diverges here.
                    None => bail!(
                        "changed key '{key_chirho}' has no value at target view {target_chirho}: \
                         append-only store invariant violated"
                    ),
                }
            }
            tx_chirho.execute(
                "INSERT OR REPLACE INTO readmodel_meta_chirho (name_chirho, value_chirho) VALUES (?1, ?2)",
                params![CURSOR_NAME_CHIRHO, target_chirho as i64],
            )?;
            tx_chirho.commit()?;
            return Ok(applied_chirho);
        }
        if table_present_chirho && cursor_chirho > target_chirho && span_above_floor_chirho {
            // ROLLBACK: the target view is BEHIND the cursor. A key's projected value can only
            // differ between the two views if it was written in `(target, cursor]` — an O(delta)
            // changelog scan, symmetric to the forward case. Resolve each such key AT the target:
            // Some(value) upserts (identical to the forward path); None DELETEs it — LEGAL here
            // because the key's first version is > target, so it did not exist at the target view.
            // The forward path's bail-on-None stays as-is; that asymmetry is load-bearing (forward
            // is append-only so None is impossible/corruption, rollback None is a vanished key).
            // Over a large delta a bulk rebuild is cheaper, so fall through to it past the threshold.
            let changed_chirho =
                store_chirho.changed_keys_in_chirho(target_chirho, cursor_chirho)?;
            if changed_chirho.len() <= ROLLBACK_DELTA_THRESHOLD_CHIRHO {
                let applied_chirho = changed_chirho.len();
                // Same crash-safety invariant as the forward path: every entry delta THEN the cursor
                // write, ALL in one txn, entries first and cursor last — a crash can never leave the
                // cursor AHEAD of the entries.
                let tx_chirho = conn_chirho.transaction()?;
                for key_chirho in &changed_chirho {
                    match store_chirho.get_at_chirho(key_chirho, target_chirho)? {
                        Some(value_chirho) => {
                            tx_chirho.execute(
                                "INSERT OR REPLACE INTO entries_chirho (key_chirho, value_chirho, value_len_chirho) VALUES (?1, ?2, ?3)",
                                params![
                                    key_chirho,
                                    String::from_utf8_lossy(&value_chirho).to_string(),
                                    value_chirho.len() as i64
                                ],
                            )?;
                        }
                        None => {
                            tx_chirho.execute(
                                "DELETE FROM entries_chirho WHERE key_chirho = ?1",
                                params![key_chirho],
                            )?;
                        }
                    }
                }
                tx_chirho.execute(
                    "INSERT OR REPLACE INTO readmodel_meta_chirho (name_chirho, value_chirho) VALUES (?1, ?2)",
                    params![CURSOR_NAME_CHIRHO, target_chirho as i64],
                )?;
                tx_chirho.commit()?;
                return Ok(applied_chirho);
            }
        }
    }

    // First run, missing table, or an over-threshold rollback: full rebuild as-of the target
    // (sets the cursor). Always correct — the safety net the incremental branches fall back to.
    drop(conn_chirho);
    drop(store_chirho);
    project_at_chirho(root_chirho, target_chirho)
}

fn ensure_read_model_chirho(root_chirho: &Path) -> Result<()> {
    let path_chirho = readmodel_path_chirho(root_chirho);
    if !path_chirho.exists() {
        project_chirho(root_chirho).map(|_rows_chirho| ())?;
        return Ok(());
    }
    let conn_chirho = Connection::open(&path_chirho).context("open read model")?;
    let exists_chirho: i64 = conn_chirho.query_row(
        "SELECT COUNT(*)
         FROM sqlite_master
         WHERE type = 'table' AND name = 'entries_chirho'",
        [],
        |row_chirho| row_chirho.get(0),
    )?;
    drop(conn_chirho);
    if exists_chirho == 0 {
        project_chirho(root_chirho).map(|_rows_chirho| ())?;
    }
    Ok(())
}

/// Run a read-only SQL query against the read model; rows returned as stringified cells.
pub fn query_chirho(root_chirho: &Path, sql_chirho: &str) -> Result<Vec<Vec<String>>> {
    ensure_read_model_chirho(root_chirho)?;
    let conn_chirho =
        Connection::open(readmodel_path_chirho(root_chirho)).context("open read model")?;
    let mut stmt_chirho = conn_chirho.prepare(sql_chirho).context("prepare query")?;
    let col_count_chirho = stmt_chirho.column_count();
    let mut out_chirho: Vec<Vec<String>> = Vec::new();
    let mut rows_chirho = stmt_chirho.query([])?;
    while let Some(row_chirho) = rows_chirho.next()? {
        let mut cells_chirho = Vec::with_capacity(col_count_chirho);
        for i_chirho in 0..col_count_chirho {
            cells_chirho.push(value_ref_to_string_chirho(row_chirho.get_ref(i_chirho)?));
        }
        out_chirho.push(cells_chirho);
    }
    Ok(out_chirho)
}

pub fn query_prefix_chirho(
    root_chirho: &Path,
    prefix_chirho: &str,
    limit_chirho: u64,
) -> Result<Vec<QueryRowChirho>> {
    if limit_chirho == 0 {
        bail!("query limit must be positive");
    }
    ensure_read_model_chirho(root_chirho)?;
    let limit_i64_chirho =
        i64::try_from(limit_chirho).context("query limit is too large for SQLite")?;
    let conn_chirho =
        Connection::open(readmodel_path_chirho(root_chirho)).context("open read model")?;
    let mut out_chirho = Vec::new();
    if prefix_chirho.is_empty() {
        let mut stmt_chirho = conn_chirho.prepare(
            "SELECT key_chirho, value_chirho, value_len_chirho
             FROM entries_chirho
             ORDER BY key_chirho
             LIMIT ?1",
        )?;
        let mut rows_chirho = stmt_chirho.query(params![limit_i64_chirho])?;
        while let Some(row_chirho) = rows_chirho.next()? {
            out_chirho.push(QueryRowChirho {
                key_chirho: row_chirho.get(0)?,
                value_chirho: row_chirho.get(1)?,
                value_len_chirho: row_chirho.get(2)?,
            });
        }
        return Ok(out_chirho);
    }
    let like_chirho = if prefix_chirho.ends_with('/') {
        format!("{}%", escape_like_chirho(prefix_chirho))
    } else {
        format!("{}/%", escape_like_chirho(prefix_chirho))
    };
    let mut stmt_chirho = conn_chirho.prepare(
        "SELECT key_chirho, value_chirho, value_len_chirho
         FROM entries_chirho
         WHERE key_chirho = ?1 OR key_chirho LIKE ?2 ESCAPE '\\'
         ORDER BY key_chirho
         LIMIT ?3",
    )?;
    let mut rows_chirho =
        stmt_chirho.query(params![prefix_chirho, like_chirho, limit_i64_chirho])?;
    while let Some(row_chirho) = rows_chirho.next()? {
        out_chirho.push(QueryRowChirho {
            key_chirho: row_chirho.get(0)?,
            value_chirho: row_chirho.get(1)?,
            value_len_chirho: row_chirho.get(2)?,
        });
    }
    Ok(out_chirho)
}

fn escape_like_chirho(value_chirho: &str) -> String {
    let mut out_chirho = String::with_capacity(value_chirho.len());
    for c_chirho in value_chirho.chars() {
        if matches!(c_chirho, '%' | '_' | '\\') {
            out_chirho.push('\\');
        }
        out_chirho.push(c_chirho);
    }
    out_chirho
}

fn value_ref_to_string_chirho(value_chirho: rusqlite::types::ValueRef) -> String {
    use rusqlite::types::ValueRef;
    match value_chirho {
        ValueRef::Null => String::new(),
        ValueRef::Integer(i_chirho) => i_chirho.to_string(),
        ValueRef::Real(f_chirho) => f_chirho.to_string(),
        ValueRef::Text(t_chirho) => String::from_utf8_lossy(t_chirho).to_string(),
        ValueRef::Blob(b_chirho) => format!("<blob {} bytes>", b_chirho.len()),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        std::env::temp_dir().join(format!("cairn-query-test-{nanos_chirho}-{n_chirho}"))
    }

    #[test]
    fn project_then_query_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho
                .put_chirho("user/alice", b"alice@example.com")
                .unwrap();
            store_chirho
                .put_chirho("user/bob", b"bob@example.com")
                .unwrap();
            store_chirho.put_chirho("config/theme", b"dark").unwrap();
        }

        assert_eq!(project_chirho(&root_chirho).unwrap(), 3);

        // Find keys under user/.
        let rows_chirho = query_chirho(
            &root_chirho,
            "SELECT key_chirho FROM entries_chirho WHERE key_chirho LIKE 'user/%' ORDER BY key_chirho",
        )
        .unwrap();
        assert_eq!(rows_chirho.len(), 2);
        assert_eq!(rows_chirho[0][0], "user/alice");
        assert_eq!(rows_chirho[1][0], "user/bob");

        // Find by value.
        let rows2_chirho = query_chirho(
            &root_chirho,
            "SELECT key_chirho FROM entries_chirho WHERE value_chirho = 'dark'",
        )
        .unwrap();
        assert_eq!(rows2_chirho.len(), 1);
        assert_eq!(rows2_chirho[0][0], "config/theme");

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn missing_projection_query_starts_empty_chirho() {
        let root_chirho = tmp_root_chirho();
        let rows_chirho = query_prefix_chirho(&root_chirho, "contacts-chirho", 10).unwrap();
        assert!(rows_chirho.is_empty());
        assert!(readmodel_path_chirho(&root_chirho).exists());
        let rows_chirho = query_chirho(
            &root_chirho,
            "SELECT key_chirho FROM entries_chirho ORDER BY key_chirho",
        )
        .unwrap();
        assert!(rows_chirho.is_empty());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn version_aware_projection_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.put_chirho("count", b"one").unwrap(); // v1
            store_chirho.put_chirho("count", b"two").unwrap(); // v2
            store_chirho.put_chirho("count", b"three").unwrap(); // v3
        }
        fn read_count_chirho(root_chirho: &Path) -> String {
            query_chirho(
                root_chirho,
                "SELECT value_chirho FROM entries_chirho WHERE key_chirho='count'",
            )
            .unwrap()[0][0]
                .clone()
        }

        project_at_chirho(&root_chirho, 1).unwrap();
        assert_eq!(read_count_chirho(&root_chirho), "one");

        project_chirho(&root_chirho).unwrap(); // current = v3
        assert_eq!(read_count_chirho(&root_chirho), "three");

        // Rollback to v2; a fresh project reflects it.
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.rollback_to_chirho(2).unwrap();
        }
        project_chirho(&root_chirho).unwrap();
        assert_eq!(read_count_chirho(&root_chirho), "two");

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn query_prefix_is_scoped_and_limited_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.put_chirho("user/alice", b"a").unwrap();
            store_chirho.put_chirho("user/bob", b"b").unwrap();
            store_chirho
                .put_chirho("user_secret/root", b"hidden")
                .unwrap();
            store_chirho.put_chirho("admin/root", b"c").unwrap();
        }
        project_chirho(&root_chirho).unwrap();
        let rows_chirho = query_prefix_chirho(&root_chirho, "user", 10).unwrap();
        assert_eq!(rows_chirho.len(), 2);
        assert_eq!(rows_chirho[0].key_chirho, "user/alice");
        assert_eq!(rows_chirho[1].key_chirho, "user/bob");
        let rows_chirho = query_prefix_chirho(&root_chirho, "user/", 1).unwrap();
        assert_eq!(rows_chirho.len(), 1);
        assert_eq!(rows_chirho[0].key_chirho, "user/alice");
        assert!(query_prefix_chirho(&root_chirho, "user/", 0).is_err());

        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    fn all_rows_sorted_chirho(root_chirho: &Path) -> Vec<(String, String)> {
        query_chirho(
            root_chirho,
            "SELECT key_chirho, value_chirho FROM entries_chirho ORDER BY key_chirho",
        )
        .unwrap()
        .into_iter()
        .map(|row_chirho| (row_chirho[0].clone(), row_chirho[1].clone()))
        .collect()
    }

    fn open_store_chirho(root_chirho: &Path) -> versioned_chirho::VersionedStoreChirho {
        versioned_chirho::VersionedStoreChirho::open_chirho(&versioned_path_chirho(root_chirho))
            .unwrap()
    }

    /// The oracle rows straight from the store's own full materialization at `view_chirho`, mapped
    /// exactly as the SQLite projection stores values — so the fuzz can compare the incremental
    /// projection against ground truth WITHOUT rebuilding (and clobbering) the read-model cursor.
    fn store_rows_at_chirho(root_chirho: &Path, view_chirho: u64) -> Vec<(String, String)> {
        let store_chirho = open_store_chirho(root_chirho);
        let mut rows_chirho: Vec<(String, String)> = store_chirho
            .current_entries_at_chirho(view_chirho)
            .unwrap()
            .into_iter()
            .map(|(key_chirho, value_chirho)| {
                (
                    key_chirho,
                    String::from_utf8_lossy(&value_chirho).to_string(),
                )
            })
            .collect();
        rows_chirho.sort();
        rows_chirho
    }

    /// A tiny in-test deterministic PRNG (splitmix64) — no new workspace dependency, seeded so the
    /// fuzz replays identically every run.
    fn splitmix64_next_chirho(state_chirho: &mut u64) -> u64 {
        *state_chirho = state_chirho.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z_chirho = *state_chirho;
        z_chirho = (z_chirho ^ (z_chirho >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z_chirho = (z_chirho ^ (z_chirho >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z_chirho ^ (z_chirho >> 31)
    }

    #[test]
    fn redundant_refresh_is_noop_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.put_chirho("a", b"1").unwrap();
            store_chirho.put_chirho("b", b"2").unwrap();
        }
        refresh_incremental_chirho(&root_chirho).unwrap(); // cursor now == current view
        let before_chirho = all_rows_sorted_chirho(&root_chirho);
        // A redundant refresh at cursor==target must be a true no-op — Ok(0) and rows untouched.
        // Pins the `<=` fast-path so a `<` mutant (which would fall back to an O(n) rebuild) dies.
        assert_eq!(refresh_incremental_chirho(&root_chirho).unwrap(), 0);
        assert_eq!(all_rows_sorted_chirho(&root_chirho), before_chirho);
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn incremental_matches_full_rebuild_chirho() {
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.put_chirho("user/alice", b"a1").unwrap();
            store_chirho.put_chirho("user/bob", b"b1").unwrap();
        }
        // First incremental run = full rebuild; establishes the cursor.
        refresh_incremental_chirho(&root_chirho).unwrap();
        {
            let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
                &versioned_path_chirho(&root_chirho),
            )
            .unwrap();
            store_chirho.put_chirho("user/alice", b"a2").unwrap(); // update
            store_chirho.put_chirho("config/theme", b"dark").unwrap(); // new
        }
        // Incremental applies ONLY the delta (alice + theme), never bob.
        assert_eq!(refresh_incremental_chirho(&root_chirho).unwrap(), 2);
        let incremental_chirho = all_rows_sorted_chirho(&root_chirho);

        // Oracle: a from-scratch full rebuild must be identical.
        project_chirho(&root_chirho).unwrap();
        assert_eq!(incremental_chirho, all_rows_sorted_chirho(&root_chirho));
        assert_eq!(
            incremental_chirho,
            vec![
                ("config/theme".to_string(), "dark".to_string()),
                ("user/alice".to_string(), "a2".to_string()),
                ("user/bob".to_string(), "b1".to_string()),
            ]
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn incremental_rollback_matches_full_rebuild_chirho() {
        // The oracle for incremental rollback: after a rollback, refresh_incremental applies ONLY
        // the changed-key delta and yet lands byte-identical to a from-scratch project_at_chirho at
        // the target. Covers BOTH asymmetric cases in one shot: a surviving key reverting to an
        // OLDER value (upsert) and a key born AFTER the target vanishing (DELETE).
        let root_chirho = tmp_root_chirho();
        let v1_chirho = {
            let store_chirho = open_store_chirho(&root_chirho);
            let v1_chirho = store_chirho.put_chirho("survivor-chirho", b"old").unwrap(); // v1
            store_chirho.put_chirho("survivor-chirho", b"new").unwrap(); // v2
            store_chirho
                .put_chirho("born-later-chirho", b"present")
                .unwrap(); // v3
            v1_chirho
        };
        refresh_incremental_chirho(&root_chirho).unwrap(); // cursor = 3
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            vec![
                ("born-later-chirho".to_string(), "present".to_string()),
                ("survivor-chirho".to_string(), "new".to_string()),
            ]
        );

        {
            open_store_chirho(&root_chirho)
                .rollback_to_chirho(v1_chirho)
                .unwrap();
        }
        // Incremental rollback: changed_keys_in(v1, v3) = {survivor (v2), born-later (v3)} = 2.
        let applied_chirho = refresh_incremental_chirho(&root_chirho).unwrap();
        assert_eq!(
            applied_chirho, 2,
            "rollback must apply only the delta, not all rows"
        );
        let incremental_chirho = all_rows_sorted_chirho(&root_chirho);

        // Oracle: a from-scratch full rebuild as-of v1 must be identical.
        project_at_chirho(&root_chirho, v1_chirho).unwrap();
        assert_eq!(incremental_chirho, all_rows_sorted_chirho(&root_chirho));
        assert_eq!(
            incremental_chirho,
            vec![("survivor-chirho".to_string(), "old".to_string())]
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn incremental_rollback_falls_back_then_resumes_chirho() {
        // A rollback whose changed-key delta EXCEEDS ROLLBACK_DELTA_THRESHOLD_CHIRHO falls back to
        // the full-rebuild safety net (still equal to the oracle), and a later forward write resumes
        // the incremental path. The full-rebuild fallback returns the target's row COUNT, not the
        // delta, which pins that the fallback (not the per-key branch) was taken.
        let root_chirho = tmp_root_chirho();
        let bulk_chirho = ROLLBACK_DELTA_THRESHOLD_CHIRHO + 1;
        {
            open_store_chirho(&root_chirho)
                .put_chirho("base-chirho", b"kept")
                .unwrap(); // v1
        }
        refresh_incremental_chirho(&root_chirho).unwrap(); // cursor = 1, 1 row
        {
            // v2: > threshold distinct keys in ONE atomic version (kept cheap: one txn, applied
            // forward in one txn — no per-row autocommit anywhere in this test).
            let keys_chirho: Vec<String> = (0..bulk_chirho)
                .map(|i_chirho| format!("bulk-chirho/{i_chirho}"))
                .collect();
            let entries_chirho: Vec<(&str, &[u8])> = keys_chirho
                .iter()
                .map(|k_chirho| (k_chirho.as_str(), b"x".as_ref()))
                .collect();
            open_store_chirho(&root_chirho)
                .reify_chirho(&entries_chirho)
                .unwrap();
        }
        refresh_incremental_chirho(&root_chirho).unwrap(); // forward: bulk in one txn, cursor = 2
        {
            open_store_chirho(&root_chirho)
                .rollback_to_chirho(1)
                .unwrap();
        }
        // Rollback delta = bulk > threshold -> fall back to project_at_chirho(1) (writes 1 row).
        let applied_chirho = refresh_incremental_chirho(&root_chirho).unwrap();
        assert_eq!(
            applied_chirho, 1,
            "over-threshold rollback must take the full-rebuild fallback"
        );
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            vec![("base-chirho".to_string(), "kept".to_string())]
        );
        // Oracle equivalence for the fallback.
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            store_rows_at_chirho(&root_chirho, 1)
        );

        // Resume: a forward write after the fallback refreshes incrementally again and matches the
        // store's own materialization (compared without an autocommit-heavy oracle rebuild).
        {
            open_store_chirho(&root_chirho)
                .put_chirho("resume-chirho/1", b"r")
                .unwrap(); // v3
        }
        let resumed_chirho = refresh_incremental_chirho(&root_chirho).unwrap();
        assert!(
            resumed_chirho >= 1,
            "forward resume must apply the forward delta"
        );
        let target_chirho = open_store_chirho(&root_chirho)
            .current_view_chirho()
            .unwrap();
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            store_rows_at_chirho(&root_chirho, target_chirho)
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn incremental_rollback_fuzz_matches_full_rebuild_chirho() {
        // Seeded, deterministic write/rollback interleaving fuzz. After EVERY step the incremental
        // projection must equal the store's ground-truth materialization at the current view. The
        // read-model cursor drifts naturally across steps (never clobbered), so this exercises
        // multi-step rollback deltas, rollback-then-forward, and repeated rollbacks. The DELETE and
        // upsert asymmetries, and forward re-appearance of previously-deleted keys, are all covered.
        let root_chirho = tmp_root_chirho();
        let keys_chirho = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
        let mut rng_chirho: u64 = 0xCA12_0715_5EED_F4C4; // fixed seed
                                                         // Each step commits durable fsyncs (redb op + sqlite refresh); the count is a
                                                         // speed/coverage balance, not correctness — the seed replays the same interleaving, and the
                                                         // explicit oracle test above already pins the upsert/DELETE asymmetries.
        let steps_chirho = 48usize;
        refresh_incremental_chirho(&root_chirho).unwrap(); // establish cursor=0 + empty table

        for step_chirho in 0..steps_chirho {
            // One store handle does the op AND snapshots the oracle rows (a read txn, no fsync),
            // then drops so refresh can take the exclusive lock. Refresh must NOT clobber the read
            // model here — the cursor drifts naturally so multi-step rollback deltas get exercised.
            let (target_view_chirho, oracle_chirho) = {
                let store_chirho = open_store_chirho(&root_chirho);
                let current_view_chirho = store_chirho.current_view_chirho().unwrap();
                if splitmix64_next_chirho(&mut rng_chirho).is_multiple_of(3) {
                    // Roll to some view in [0, current] (forward or backward through the timeline).
                    let target_chirho =
                        splitmix64_next_chirho(&mut rng_chirho) % (current_view_chirho + 1);
                    store_chirho.rollback_to_chirho(target_chirho).unwrap();
                } else {
                    let key_chirho = keys_chirho
                        [(splitmix64_next_chirho(&mut rng_chirho) as usize) % keys_chirho.len()];
                    let value_chirho = splitmix64_next_chirho(&mut rng_chirho) % 1000;
                    store_chirho
                        .put_chirho(key_chirho, format!("val-{value_chirho}").as_bytes())
                        .unwrap();
                }
                let view_chirho = store_chirho.current_view_chirho().unwrap();
                let mut oracle_chirho: Vec<(String, String)> = store_chirho
                    .current_entries_at_chirho(view_chirho)
                    .unwrap()
                    .into_iter()
                    .map(|(key_chirho, value_chirho)| {
                        (
                            key_chirho,
                            String::from_utf8_lossy(&value_chirho).to_string(),
                        )
                    })
                    .collect();
                oracle_chirho.sort();
                (view_chirho, oracle_chirho)
            };
            refresh_incremental_chirho(&root_chirho).unwrap();
            assert_eq!(
                all_rows_sorted_chirho(&root_chirho),
                oracle_chirho,
                "incremental projection diverged from full materialization at step {step_chirho}, view {target_view_chirho}"
            );
        }
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn rollback_work_scales_with_delta_not_history_chirho() {
        // Count-based scaling guard for the O(1)-runtime-cost invariant on the K (total-keys) axis:
        // rolling back ONE tip version applies exactly the 1-key tip delta, no matter how many total
        // keys (K) or how many tip rewrites (M) the store holds. The returned applied-count is the
        // work proxy (never wall-clock). A full-reproject mutant would return K; asserting == 1 for
        // wildly different (K, M) proves the work is bounded by the delta, not by history.
        fn rollback_one_tip_applied_chirho(
            total_keys_chirho: usize,
            tip_rewrites_chirho: usize,
        ) -> usize {
            assert!(total_keys_chirho >= 1 && tip_rewrites_chirho >= 1);
            let root_chirho = tmp_root_chirho();
            {
                open_store_chirho(&root_chirho)
                    .put_chirho("anchor-chirho", b"a")
                    .unwrap(); // v1
            }
            refresh_incremental_chirho(&root_chirho).unwrap(); // 1 row, cursor = 1
            if total_keys_chirho > 1 {
                // v2: the remaining K-1 keys in ONE atomic version (so the forward refresh applies
                // them in a single txn — the projection reaches K rows without a per-row rebuild).
                let keys_chirho: Vec<String> = (1..total_keys_chirho)
                    .map(|i_chirho| format!("seed-chirho/{i_chirho}"))
                    .collect();
                let entries_chirho: Vec<(&str, &[u8])> = keys_chirho
                    .iter()
                    .map(|k_chirho| (k_chirho.as_str(), b"s".as_ref()))
                    .collect();
                open_store_chirho(&root_chirho)
                    .reify_chirho(&entries_chirho)
                    .unwrap();
                refresh_incremental_chirho(&root_chirho).unwrap(); // forward: K-1 in one txn
            }
            {
                let store_chirho = open_store_chirho(&root_chirho);
                for i_chirho in 0..tip_rewrites_chirho {
                    store_chirho
                        .put_chirho("anchor-chirho", format!("r{i_chirho}").as_bytes())
                        .unwrap();
                }
            }
            refresh_incremental_chirho(&root_chirho).unwrap(); // forward: only anchor changed
            {
                let store_chirho = open_store_chirho(&root_chirho);
                let tip_chirho = store_chirho.current_view_chirho().unwrap();
                store_chirho.rollback_to_chirho(tip_chirho - 1).unwrap();
            }
            let applied_chirho = refresh_incremental_chirho(&root_chirho).unwrap();
            let _ = std::fs::remove_dir_all(&root_chirho);
            applied_chirho
        }

        // Tiny store and a 32x-bigger, deeper one both apply exactly the 1-key tip delta.
        assert_eq!(rollback_one_tip_applied_chirho(32, 8), 1);
        assert_eq!(rollback_one_tip_applied_chirho(1024, 64), 1);
    }

    #[test]
    fn rollback_across_changelog_floor_full_reprojects_and_purges_stale_rows_chirho() {
        // PRIVACY-RELEVANT FLOOR GUARD. A "legacy" root (ENTRIES history predating the changelog) has
        // an empty changelog below its floor. An incremental rollback that trusted that empty
        // changelog would apply only the recorded above-floor delta and leave below-floor rows
        // STANDING — rows that must vanish/revert at the target survive (a data-exposure bug).
        // refresh_incremental must detect the sub-floor span and full-reproject, landing byte-
        // identical to project_at_chirho.
        let root_chirho = tmp_root_chirho();

        // Below-floor history (versions 1..3): a secret that is overwritten, plus a key born at v2.
        {
            let store_chirho = open_store_chirho(&root_chirho);
            store_chirho
                .put_chirho("secret-chirho", b"v1-private")
                .unwrap(); // v1
            store_chirho.put_chirho("keep-chirho", b"kept").unwrap(); // v2
            store_chirho
                .put_chirho("secret-chirho", b"v3-LEAK")
                .unwrap(); // v3
                           // Reproduce a pre-changelog root: drop the changelog + floor so v1..3 look pre-recorded.
            store_chirho
                .simulate_pre_changelog_legacy_root_chirho()
                .unwrap();
        }
        // Reopen: floor is pinned to next_version (4); v1..3 are now BELOW the floor.
        {
            let store_chirho = open_store_chirho(&root_chirho);
            assert_eq!(store_chirho.changelog_floor_chirho().unwrap(), 4);
            store_chirho.put_chirho("above-chirho", b"a4").unwrap(); // v4 (recorded, at the floor)
        }
        // Build the projection at the current view (v4) — first run is a full reproject (cursor = 4).
        refresh_incremental_chirho(&root_chirho).unwrap();
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            vec![
                ("above-chirho".to_string(), "a4".to_string()),
                ("keep-chirho".to_string(), "kept".to_string()),
                ("secret-chirho".to_string(), "v3-LEAK".to_string()),
            ]
        );

        // Roll back to v1 (BELOW the floor). At v1 only secret-chirho=v1-private existed.
        {
            open_store_chirho(&root_chirho)
                .rollback_to_chirho(1)
                .unwrap();
        }
        refresh_incremental_chirho(&root_chirho).unwrap();
        let incremental_chirho = all_rows_sorted_chirho(&root_chirho);

        // Oracle: identical to a from-scratch project_at_chirho(1).
        project_at_chirho(&root_chirho, 1).unwrap();
        assert_eq!(incremental_chirho, all_rows_sorted_chirho(&root_chirho));
        // Concretely: the leaked v3 value is gone, keep-chirho (born v2) and above-chirho (born v4)
        // are gone, and only the v1 private value remains. Under the pre-fix incremental path the
        // sub-floor rows (secret=v3-LEAK, keep=kept) would have survived — the stale-row leak.
        assert_eq!(
            incremental_chirho,
            vec![("secret-chirho".to_string(), "v1-private".to_string())]
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn above_floor_forward_and_rollback_stay_incremental_chirho() {
        // On a normal (non-legacy) root the floor is 1, so every version is at/above it and the
        // O(delta) fast path must still run — the floor guard must NOT force a full reproject here.
        // The applied-count is the work proxy: an incremental step returns the DELTA size; a full
        // reproject returns the target's whole row count. Seeding 5 base rows makes those numbers
        // differ, so asserting applied == 1 proves the fast path (not a full scan) ran.
        let root_chirho = tmp_root_chirho();
        {
            let store_chirho = open_store_chirho(&root_chirho);
            assert_eq!(store_chirho.changelog_floor_chirho().unwrap(), 1);
            let base_chirho: Vec<(&str, &[u8])> = vec![
                ("base-chirho/0", b"b"),
                ("base-chirho/1", b"b"),
                ("base-chirho/2", b"b"),
                ("base-chirho/3", b"b"),
                ("base-chirho/4", b"b"),
            ];
            store_chirho.reify_chirho(&base_chirho).unwrap(); // v1: 5 keys in one version
        }
        refresh_incremental_chirho(&root_chirho).unwrap(); // first run: reproject, cursor = 1, 5 rows
        {
            open_store_chirho(&root_chirho)
                .put_chirho("hot-chirho", b"h2")
                .unwrap(); // v2
        }
        // Forward above the floor: applies ONLY the 1-key delta (not all 6 rows).
        assert_eq!(
            refresh_incremental_chirho(&root_chirho).unwrap(),
            1,
            "above-floor forward must stay incremental (delta=1), not full-reproject (=6)"
        );
        {
            open_store_chirho(&root_chirho)
                .rollback_to_chirho(1)
                .unwrap();
        }
        // Rollback above the floor: applies ONLY the 1-key delta again (deletes hot-chirho).
        assert_eq!(
            refresh_incremental_chirho(&root_chirho).unwrap(),
            1,
            "above-floor rollback must stay incremental (delta=1), not full-reproject (=5)"
        );
        // ...and lands on the correct v1 rows (hot-chirho gone).
        assert_eq!(
            all_rows_sorted_chirho(&root_chirho),
            store_rows_at_chirho(&root_chirho, 1)
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
