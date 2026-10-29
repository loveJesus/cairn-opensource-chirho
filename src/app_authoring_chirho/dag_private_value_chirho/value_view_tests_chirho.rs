// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The private-value index (checkpoint brick S2) against the whole-log resolvers it replaced: the same answers and
//! the same error chains, warm lookups and stores that do no history-sized work, and a store that refuses exactly
//! when a lookup would.

use super::super::{
    load_private_dag_value_records_chirho, private_dag_values_path_chirho,
    store_private_dag_value_chirho, verified_private_dag_value_record_chirho,
    verified_private_dag_value_record_for_subject_chirho, verify_private_dag_value_record_chirho,
    PrivateDagValueContextChirho, PrivateDagValueRecordChirho, PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO,
};
use super::private_value_view_metrics_chirho::{self as metrics_chirho, ValueRoadCountsChirho};
use crate::model_chirho::HashChirho;
use anyhow::{anyhow, Result};
use cairn_signer_chirho::signer_chirho;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-value-view-test-{}-{}-{n_chirho}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// The whole-log hash resolver S2 replaced, kept verbatim as the oracle's reference.
fn full_scan_by_hash_chirho(
    root_chirho: &Path,
    value_hash_chirho: &HashChirho,
) -> Result<Option<PrivateDagValueRecordChirho>> {
    let records_chirho = load_private_dag_value_records_chirho(root_chirho)?;
    let claiming_chirho: Vec<&PrivateDagValueRecordChirho> = records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.value_hash_chirho == *value_hash_chirho)
        .collect();
    if claiming_chirho.is_empty() {
        return Ok(None);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut last_failure_chirho = None;
    for record_chirho in claiming_chirho {
        match verify_private_dag_value_record_chirho(root_chirho, &pubkey_chirho, record_chirho) {
            Ok(()) => return Ok(Some(record_chirho.clone())),
            Err(failure_chirho) => last_failure_chirho = Some(failure_chirho),
        }
    }
    Err(last_failure_chirho
        .unwrap_or_else(|| anyhow!("private DAG value record verification produced no verdict"))
        .context(format!(
            "private DAG value {} is claimed only by records that do not verify",
            value_hash_chirho.0
        )))
}

/// The whole-log subject resolver S2 replaced (one question), kept verbatim as the oracle's reference.
fn full_scan_by_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
) -> Result<Option<PrivateDagValueRecordChirho>> {
    crate::privacy_chirho::validate_privacy_subject_chirho(subject_chirho)?;
    let records_chirho = load_private_dag_value_records_chirho(root_chirho)?;
    let claiming_chirho: Vec<&PrivateDagValueRecordChirho> = records_chirho
        .iter()
        .rev()
        .filter(|record_chirho| {
            record_chirho.subject_chirho == subject_chirho
                && record_chirho.value_hash_chirho == *value_hash_chirho
        })
        .collect();
    if claiming_chirho.is_empty() {
        return Ok(None);
    }
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut last_failure_chirho = None;
    for record_chirho in claiming_chirho {
        match verify_private_dag_value_record_chirho(root_chirho, &pubkey_chirho, record_chirho) {
            Ok(()) => return Ok(Some(record_chirho.clone())),
            Err(failure_chirho) => last_failure_chirho = Some(failure_chirho),
        }
    }
    Err(last_failure_chirho
        .unwrap_or_else(|| anyhow!("private DAG value record verification produced no verdict"))
        .context(format!(
            "private DAG value {} for subject '{}' is claimed only by records that do not verify",
            value_hash_chirho.0, subject_chirho
        )))
}

/// An answer as the oracle compares it: the record, or the WHOLE error chain.
fn answer_chirho(
    result_chirho: Result<Option<PrivateDagValueRecordChirho>>,
) -> std::result::Result<Option<PrivateDagValueRecordChirho>, String> {
    result_chirho.map_err(|error_chirho| format!("{error_chirho:#}"))
}

fn same_by_hash_chirho(root_chirho: &Path, hash_chirho: &HashChirho, context_chirho: &str) {
    assert_eq!(
        answer_chirho(verified_private_dag_value_record_chirho(root_chirho, hash_chirho)),
        answer_chirho(full_scan_by_hash_chirho(root_chirho, hash_chirho)),
        "{context_chirho}: the hash lookup must answer as the whole-log resolver, error chain included"
    );
}

fn same_by_subject_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    hash_chirho: &HashChirho,
    context_chirho: &str,
) {
    assert_eq!(
        answer_chirho(verified_private_dag_value_record_for_subject_chirho(root_chirho, subject_chirho, hash_chirho)),
        answer_chirho(full_scan_by_subject_chirho(root_chirho, subject_chirho, hash_chirho)),
        "{context_chirho}: the subject lookup must answer as the whole-log resolver, error chain included"
    );
}

fn log_bytes_chirho(root_chirho: &Path) -> Vec<u8> {
    std::fs::read(private_dag_values_path_chirho(root_chirho)).unwrap_or_default()
}

fn append_raw_chirho(root_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::create_dir_all(root_chirho).unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(private_dag_values_path_chirho(root_chirho))
        .unwrap()
        .write_all(bytes_chirho)
        .unwrap();
}

/// A record written past the store road with one field changed, as a tamper or a bug would.
fn forged_line_chirho(
    record_chirho: &PrivateDagValueRecordChirho,
    change_chirho: impl FnOnce(&mut PrivateDagValueRecordChirho),
) -> String {
    let mut forged_chirho = record_chirho.clone();
    change_chirho(&mut forged_chirho);
    format!("{}\n", serde_json::to_string(&forged_chirho).unwrap())
}

fn swap_log_inode_chirho(root_chirho: &Path) {
    let log_chirho = private_dag_values_path_chirho(root_chirho);
    let bytes_chirho = std::fs::read(&log_chirho).unwrap();
    let swap_chirho = log_chirho.with_extension("swap-chirho");
    std::fs::write(&swap_chirho, &bytes_chirho).unwrap();
    std::fs::rename(&swap_chirho, &log_chirho).unwrap();
}

fn store_chirho(root_chirho: &Path, subject_chirho: &str, value_chirho: &str) -> HashChirho {
    store_private_dag_value_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            subject_chirho,
        ),
        subject_chirho,
        value_chirho.as_bytes(),
        PrivateDagValueContextChirho::default(),
    )
    .unwrap()
}

fn record_of_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PrivateDagValueRecordChirho {
    load_private_dag_value_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .find(|record_chirho| record_chirho.value_hash_chirho == *hash_chirho)
        .unwrap()
}

fn counts_after_chirho<T>(action_chirho: impl FnOnce() -> T) -> (T, ValueRoadCountsChirho, u64) {
    metrics_chirho::reset_chirho();
    PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO.with(|count_chirho| count_chirho.set(0));
    let value_chirho = action_chirho();
    (
        value_chirho,
        metrics_chirho::counts_chirho(),
        PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO.with(|count_chirho| count_chirho.get()),
    )
}

fn road_chirho(
    lookups_chirho: u64,
    full_chirho: u64,
    folded_chirho: u64,
    copied_chirho: u64,
) -> ValueRoadCountsChirho {
    ValueRoadCountsChirho {
        lookups_chirho,
        full_log_loads_chirho: full_chirho,
        records_folded_chirho: folded_chirho,
        claims_copied_chirho: copied_chirho,
    }
}

/// THE LOOKUP GROWTH ARM, on the duplicate pattern reads produce: the store does not deduplicate, so a read that
/// re-stores the same bytes for the same subject adds a claim on that pair every time (until checkpoint brick S5). At
/// 1, 10 and 100 such reads, interleaved with as many distinct values, a warm lookup of the repeated pair, by pair or
/// by hash, reads no whole log, folds nothing and copies out ONE claim; the presence check copies none.
///
/// INSTRUMENT CONTROLS: a new inode with the same bytes makes the next lookup rebuild, and the counters see the whole
/// log; and a forged latest claim must be tried and refused before the next one verifies, so that lookup copies out
/// two claims, through the fetch-by-place path.
///
/// MIGRATION PATH: a warm count that grows with the history means the lookup is back on a whole-log road; a copy
/// count that grows with the duplicates means claims are being copied out wholesale again.
#[test]
fn a_warm_value_lookup_does_constant_work_at_any_history_chirho() {
    const READER_CHIRHO: &str = "user/value-growth";
    for history_chirho in [1_usize, 10, 100] {
        let root_chirho = tmp_root_chirho();
        let mut repeated_chirho = None;
        for i_chirho in 0..history_chirho {
            repeated_chirho = Some(store_chirho(
                &root_chirho,
                READER_CHIRHO,
                "the same read response",
            ));
            store_chirho(
                &root_chirho,
                "user/value-growth-other",
                &format!("value growth {i_chirho}"),
            );
        }
        let repeated_chirho = repeated_chirho.unwrap();
        let total_chirho = 2 * history_chirho as u64;

        swap_log_inode_chirho(&root_chirho);
        let (found_chirho, control_chirho, loader_chirho) = counts_after_chirho(|| {
            verified_private_dag_value_record_for_subject_chirho(
                &root_chirho,
                READER_CHIRHO,
                &repeated_chirho,
            )
            .unwrap()
        });
        assert!(found_chirho.is_some(), "the stored value resolves");
        assert_eq!(
            (control_chirho, loader_chirho),
            (road_chirho(1, 1, total_chirho, 1), 0),
            "control at {history_chirho}: a rebuild reads the whole log through the index, never the old loader"
        );

        let (found_chirho, warm_chirho, loader_chirho) = counts_after_chirho(|| {
            verified_private_dag_value_record_for_subject_chirho(
                &root_chirho,
                READER_CHIRHO,
                &repeated_chirho,
            )
            .unwrap()
        });
        assert!(found_chirho.is_some());
        assert_eq!(
            (warm_chirho, loader_chirho),
            (road_chirho(1, 0, 0, 1), 0),
            "a warm pair lookup with {history_chirho} claims on its pair copies out one"
        );
        let (found_chirho, warm_hash_chirho, _) = counts_after_chirho(|| {
            verified_private_dag_value_record_chirho(&root_chirho, &repeated_chirho).unwrap()
        });
        assert!(found_chirho.is_some());
        assert_eq!(
            warm_hash_chirho,
            road_chirho(1, 0, 0, 1),
            "a warm hash lookup with {history_chirho} claims on its hash copies out one"
        );
        let (present_chirho, presence_chirho, _) = counts_after_chirho(|| {
            super::super::private_dag_value_recorded_for_subject_chirho(
                &root_chirho,
                READER_CHIRHO,
                &repeated_chirho,
            )
            .unwrap()
        });
        assert!(present_chirho);
        assert_eq!(
            presence_chirho,
            road_chirho(1, 0, 0, 0),
            "the presence check copies out nothing"
        );

        let genuine_chirho = record_of_chirho(&root_chirho, &repeated_chirho);
        append_raw_chirho(
            &root_chirho,
            forged_line_chirho(&genuine_chirho, |record_chirho| {
                record_chirho.sig_chirho = "00".repeat(64)
            })
            .as_bytes(),
        );
        let (found_chirho, forged_chirho, _) = counts_after_chirho(|| {
            verified_private_dag_value_record_for_subject_chirho(
                &root_chirho,
                READER_CHIRHO,
                &repeated_chirho,
            )
            .unwrap()
        });
        assert_ne!(
            found_chirho
                .expect("a genuine claim still answers")
                .sig_chirho,
            "00".repeat(64),
            "the forged latest claim must not answer"
        );
        assert_eq!(
            forged_chirho,
            road_chirho(1, 0, 1, 2),
            "control at {history_chirho}: a refused latest claim makes the lookup copy out the next one, or the copy \
             counter is blind"
        );

        let fresh_chirho = store_chirho(&root_chirho, READER_CHIRHO, "value growth delta");
        let (found_chirho, delta_chirho, _) = counts_after_chirho(|| {
            verified_private_dag_value_record_chirho(&root_chirho, &fresh_chirho).unwrap()
        });
        assert!(found_chirho.is_some());
        assert_eq!(
            delta_chirho,
            road_chirho(1, 0, 1, 1),
            "after one store at {history_chirho}, the delta is one record"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// THE STORE GROWTH ARM (census execution-effects row A3, value half). At 1, 10 and 100 stored values, a store reads
/// no whole log: the index folds at most the previous store's record, and the seq comes from the seqlog's recovered
/// length. INSTRUMENT CONTROL: the old loader's counter still sees a whole-log load.
#[test]
fn a_warm_value_store_does_constant_work_at_any_history_chirho() {
    for history_chirho in [1_usize, 10, 100] {
        let root_chirho = tmp_root_chirho();
        let hashes_chirho: Vec<HashChirho> = (0..history_chirho)
            .map(|i_chirho| {
                store_chirho(
                    &root_chirho,
                    "user/value-store",
                    &format!("value store {i_chirho}"),
                )
            })
            .collect();
        verified_private_dag_value_record_chirho(&root_chirho, &hashes_chirho[0]).unwrap();
        let (_, first_chirho, first_loader_chirho) = counts_after_chirho(|| {
            store_chirho(
                &root_chirho,
                "user/value-store",
                "first measured value store",
            )
        });
        let (_, second_chirho, second_loader_chirho) = counts_after_chirho(|| {
            store_chirho(
                &root_chirho,
                "user/value-store",
                "second measured value store",
            )
        });
        assert_eq!(
            (first_chirho, first_loader_chirho),
            (road_chirho(0, 0, 0, 0), 0),
            "a store on a current index at {history_chirho} values reads no whole log"
        );
        assert_eq!(
            (second_chirho, second_loader_chirho),
            (road_chirho(0, 0, 1, 0), 0),
            "the next store at {history_chirho} folds only the previous store's record"
        );
        let (records_chirho, _, control_chirho) =
            counts_after_chirho(|| load_private_dag_value_records_chirho(&root_chirho).unwrap());
        assert_eq!(records_chirho.len(), history_chirho + 2);
        assert_eq!(
            control_chirho, 1,
            "control: the whole-log loader is counted, or the zeros above are blind"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// THE ORACLE. Stores for several subjects (the same value under two subjects included), forged records (a bad
/// signature, a bad schema, a bad subject, a blob belonging to another subject, an exact duplicate), then lookups by
/// hash and by (subject, hash) for every stored value and for a value nobody stored: each answers exactly as the
/// whole-log resolver, record or error chain. A garbage line then refuses every lookup in both.
#[test]
fn the_value_index_answers_as_the_whole_log_resolvers_chirho() {
    let root_chirho = tmp_root_chirho();
    let subjects_chirho = ["user/oracle-v-a", "user/oracle-v-b", "user/oracle-v-c"];
    let mut stored_chirho: Vec<(HashChirho, &str)> = Vec::new();
    for i_chirho in 0..12 {
        let subject_chirho = subjects_chirho[i_chirho % 3];
        stored_chirho.push((
            store_chirho(
                &root_chirho,
                subject_chirho,
                &format!("oracle value {i_chirho}"),
            ),
            subject_chirho,
        ));
    }
    // The same bytes under two subjects: one value hash, two claims.
    stored_chirho.push((
        store_chirho(&root_chirho, "user/oracle-v-a", "shared oracle value"),
        "user/oracle-v-a",
    ));
    stored_chirho.push((
        store_chirho(&root_chirho, "user/oracle-v-b", "shared oracle value"),
        "user/oracle-v-b",
    ));
    // The same bytes stored TWICE for one subject: two different valid claims on one pair, so the latest-first order
    // decides which record answers.
    store_chirho(&root_chirho, "user/oracle-v-c", "twice-stored oracle value");
    stored_chirho.push((
        store_chirho(&root_chirho, "user/oracle-v-c", "twice-stored oracle value"),
        "user/oracle-v-c",
    ));

    let base_chirho = record_of_chirho(&root_chirho, &stored_chirho[0].0);
    let other_chirho = record_of_chirho(&root_chirho, &stored_chirho[1].0);
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&base_chirho, |record_chirho| {
            record_chirho.sig_chirho = "00".repeat(64)
        })
        .as_bytes(),
    );
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&base_chirho, |record_chirho| {
            record_chirho.schema_chirho = "not-a-schema".into()
        })
        .as_bytes(),
    );
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&other_chirho, |record_chirho| {
            record_chirho.subject_chirho = "user/oracle-v-c".into()
        })
        .as_bytes(),
    );
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&other_chirho, |record_chirho| {
            record_chirho.blob_chirho = base_chirho.blob_chirho.clone()
        })
        .as_bytes(),
    );
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&base_chirho, |_| {}).as_bytes(),
    );
    let unstored_chirho = crate::cas_chirho::hash_chirho(b"a value nobody stored");
    // A hash claimed ONLY by a forged record (its signature covers the hash, so it fails): both lookups must refuse
    // with the same error chain as the whole-log resolvers.
    let only_forged_chirho = crate::cas_chirho::hash_chirho(b"a value only a forger claims");
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&base_chirho, |record_chirho| {
            record_chirho.value_hash_chirho = only_forged_chirho.clone()
        })
        .as_bytes(),
    );

    let mut answered_chirho = 0;
    let mut refused_chirho = 0;
    for (hash_chirho, owner_chirho) in &stored_chirho {
        same_by_hash_chirho(&root_chirho, hash_chirho, "stored value");
        for subject_chirho in subjects_chirho {
            same_by_subject_chirho(
                &root_chirho,
                subject_chirho,
                hash_chirho,
                &format!("stored value, owner {owner_chirho}"),
            );
            match verified_private_dag_value_record_for_subject_chirho(
                &root_chirho,
                subject_chirho,
                hash_chirho,
            ) {
                Ok(Some(_)) => answered_chirho += 1,
                Err(_) => refused_chirho += 1,
                Ok(None) => {}
            }
        }
    }
    same_by_hash_chirho(&root_chirho, &unstored_chirho, "unstored value");
    same_by_hash_chirho(
        &root_chirho,
        &only_forged_chirho,
        "a hash only a forged record claims",
    );
    same_by_subject_chirho(
        &root_chirho,
        &base_chirho.subject_chirho,
        &only_forged_chirho,
        "a pair only a forged record claims",
    );
    assert!(
        verified_private_dag_value_record_chirho(&root_chirho, &only_forged_chirho).is_err(),
        "fixture: the forged-only hash must refuse, or the line above compares nothing"
    );
    same_by_subject_chirho(
        &root_chirho,
        "user/oracle-v-a",
        &unstored_chirho,
        "unstored value",
    );
    same_by_subject_chirho(
        &root_chirho,
        "not a valid subject!",
        &stored_chirho[0].0,
        "invalid subject",
    );
    assert!(
        answered_chirho > 10 && refused_chirho > 0,
        "coverage: {answered_chirho} answered, {refused_chirho} refused"
    );

    append_raw_chirho(&root_chirho, b"this is not json\n");
    same_by_hash_chirho(&root_chirho, &stored_chirho[0].0, "garbage line");
    same_by_subject_chirho(
        &root_chirho,
        stored_chirho[0].1,
        &stored_chirho[0].0,
        "garbage line",
    );
    assert!(verified_private_dag_value_record_chirho(&root_chirho, &stored_chirho[0].0).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Every file under a root, path to bytes: what a refused store must leave alone.
fn tree_chirho(root_chirho: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
    let mut tree_chirho = std::collections::BTreeMap::new();
    let mut pending_chirho = vec![root_chirho.to_path_buf()];
    while let Some(dir_chirho) = pending_chirho.pop() {
        for entry_chirho in std::fs::read_dir(&dir_chirho).unwrap() {
            let path_chirho = entry_chirho.unwrap().path();
            if path_chirho.is_dir() {
                pending_chirho.push(path_chirho);
            } else {
                let bytes_chirho = std::fs::read(&path_chirho).unwrap();
                tree_chirho.insert(path_chirho, bytes_chirho);
            }
        }
    }
    tree_chirho
}

fn store_refused_chirho(root_chirho: &Path) -> String {
    let refusal_chirho = store_private_dag_value_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/value-gate",
        ),
        "user/value-gate",
        b"refused",
        PrivateDagValueContextChirho::default(),
    )
    .expect_err("the store must refuse");
    format!("{refusal_chirho:#}")
}

/// The S1 store rule on the value log: a COMPLETE bad line refuses stores as well as lookups, and the refused store
/// changes nothing under the root, byte for byte: not the value log (the index refuses before recovery runs, so a
/// torn tail after the bad line stays where it is), and not the blob store (the early check refuses before the blob
/// is written, so no orphan blob or key is left). A torn tail alone heals on the next store.
#[test]
fn a_bad_value_line_refuses_stores_and_a_torn_tail_heals_chirho() {
    let torn_chirho: &[u8] = b"{\"schema_chirho\":\"private-dag-val";
    for bad_chirho in [
        &b"{}\n"[..],
        &b"this is not json\n"[..],
        &[&b"{}\n"[..], torn_chirho].concat(),
    ] {
        let root_chirho = tmp_root_chirho();
        let first_chirho = store_chirho(&root_chirho, "user/value-gate", "value gate first");
        let blob_chirho = record_of_chirho(&root_chirho, &first_chirho).blob_chirho;
        append_raw_chirho(&root_chirho, bad_chirho);
        let before_chirho = tree_chirho(&root_chirho);
        assert!(verified_private_dag_value_record_chirho(&root_chirho, &first_chirho).is_err());
        let refusal_chirho = store_refused_chirho(&root_chirho);
        assert!(
            refusal_chirho.contains("decode PrivateDagValueRecordChirho"),
            "the index refuses the bad line, not something else: {refusal_chirho}"
        );
        assert!(
            tree_chirho(&root_chirho) == before_chirho,
            "a refused store changes nothing under the root, byte for byte ({:?})",
            String::from_utf8_lossy(bad_chirho)
        );
        // The early check above refuses first, so it would mask the append path's own order. Drive the append path
        // directly: its gate must bring the index current BEFORE recovery, so it too refuses with the torn tail
        // still in place.
        let direct_chirho = super::super::append_private_dag_value_record_chirho(
            &root_chirho,
            "user/value-gate",
            first_chirho.clone(),
            blob_chirho,
            1,
            PrivateDagValueContextChirho::default(),
        )
        .expect_err("the append path refuses a complete bad line on its own");
        assert!(
            format!("{direct_chirho:#}").contains("decode PrivateDagValueRecordChirho"),
            "the append path's index refuses, not something else: {direct_chirho:#}"
        );
        assert!(
            tree_chirho(&root_chirho) == before_chirho,
            "the append path's refusal changes nothing either, byte for byte ({:?})",
            String::from_utf8_lossy(bad_chirho)
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    let root_chirho = tmp_root_chirho();
    let first_chirho = store_chirho(&root_chirho, "user/value-gate", "value gate torn first");
    let clean_chirho = log_bytes_chirho(&root_chirho);
    append_raw_chirho(&root_chirho, torn_chirho);
    assert!(
        verified_private_dag_value_record_chirho(&root_chirho, &first_chirho)
            .unwrap()
            .is_some(),
        "the index waits out a torn tail"
    );
    let second_chirho = store_chirho(&root_chirho, "user/value-gate", "value gate after the tear");
    let healed_chirho = log_bytes_chirho(&root_chirho);
    assert!(healed_chirho.starts_with(&clean_chirho));
    let added_chirho = std::str::from_utf8(&healed_chirho[clean_chirho.len()..]).unwrap();
    assert_eq!(
        added_chirho.matches('\n').count(),
        1,
        "exactly one line follows the clean records: {added_chirho:?}"
    );
    let added_record_chirho: PrivateDagValueRecordChirho =
        serde_json::from_str(added_chirho.trim_end()).expect("the torn bytes left the log");
    assert_eq!(added_record_chirho.value_hash_chirho, second_chirho);
    same_by_hash_chirho(&root_chirho, &first_chirho, "healed");
    same_by_hash_chirho(&root_chirho, &second_chirho, "healed");
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The one line the index waits out and recovery keeps: a final line with no newline that is JSON but not a record.
/// A torn write never is one (a proper prefix of a serialized object is not JSON), so only a tamper or a bug writes
/// it. Recovery completes it with a newline and counts it; the index does not, so the store gate's count check
/// refuses, and from then on the line is complete, so every lookup refuses too. The refused store's only change to
/// the value log is that newline.
#[test]
fn a_newline_less_non_record_line_refuses_through_the_count_check_chirho() {
    let root_chirho = tmp_root_chirho();
    let first_chirho = store_chirho(&root_chirho, "user/value-gate", "value gate count first");
    append_raw_chirho(&root_chirho, b"{}");
    let before_chirho = log_bytes_chirho(&root_chirho);
    assert!(
        verified_private_dag_value_record_chirho(&root_chirho, &first_chirho)
            .unwrap()
            .is_some(),
        "the index waits out a newline-less final line it cannot parse"
    );
    let refusal_chirho = store_refused_chirho(&root_chirho);
    assert!(
        refusal_chirho.contains("by recovery but") && refusal_chirho.contains("refusing to append"),
        "the count check refuses, not something else: {refusal_chirho}"
    );
    assert_eq!(
        log_bytes_chirho(&root_chirho),
        [&before_chirho[..], b"\n"].concat(),
        "the refused store's only change to the value log is recovery's newline"
    );
    assert!(
        verified_private_dag_value_record_chirho(&root_chirho, &first_chirho).is_err(),
        "the completed line now refuses every lookup"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A claims reader fetches its later claims by their place among the key's claims, which an append-only log never
/// moves. If the log is replaced so that place is gone, the lookup refuses by name rather than skipping the claim.
#[test]
fn a_lookup_refuses_when_the_log_changes_shape_under_it_chirho() {
    use super::{claims_chirho, ClaimKeyChirho, ClaimOrderChirho};
    let root_chirho = tmp_root_chirho();
    store_chirho(
        &root_chirho,
        "user/value-shape-other",
        "value shape unrelated",
    );
    let unrelated_line_chirho = String::from_utf8(log_bytes_chirho(&root_chirho)).unwrap();
    let hash_chirho = store_chirho(&root_chirho, "user/value-shape", "value shape");
    let genuine_chirho = record_of_chirho(&root_chirho, &hash_chirho);
    append_raw_chirho(
        &root_chirho,
        forged_line_chirho(&genuine_chirho, |record_chirho| {
            record_chirho.sig_chirho = "00".repeat(64)
        })
        .as_bytes(),
    );
    let mut claims_chirho = claims_chirho(
        &root_chirho,
        ClaimKeyChirho::PairChirho(("user/value-shape".to_string(), hash_chirho.clone())),
        ClaimOrderChirho::LatestFirstChirho,
    )
    .unwrap();
    let first_chirho = claims_chirho.next().unwrap().unwrap();
    assert_eq!(
        first_chirho.sig_chirho,
        "00".repeat(64),
        "latest first: the forged claim comes out first"
    );

    let log_chirho = private_dag_values_path_chirho(&root_chirho);
    let swap_chirho = log_chirho.with_extension("swap-chirho");
    std::fs::write(&swap_chirho, unrelated_line_chirho.as_bytes()).unwrap();
    std::fs::rename(&swap_chirho, &log_chirho).unwrap();

    let refusal_chirho = claims_chirho
        .next()
        .expect("the reader still owes the genuine claim")
        .expect_err("its place is gone, so the reader must refuse");
    assert!(
        format!("{refusal_chirho:#}").contains("changed shape"),
        "the refusal names the changed log, not something else: {refusal_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A failing claim is never remembered: after its blob's key file is repaired, the next lookup verifies it again and
/// answers, as the whole-log resolver does, because the index caches no verdict.
#[test]
fn a_repaired_key_is_seen_on_the_next_lookup_chirho() {
    let root_chirho = tmp_root_chirho();
    let hash_chirho = store_chirho(&root_chirho, "user/value-repair", "value repair");
    let record_chirho = record_of_chirho(&root_chirho, &hash_chirho);
    let key_path_chirho = root_chirho
        .join("privacy-keys-chirho") // privacy_chirho::keys_dir_chirho
        .join(format!("{}.json", record_chirho.blob_chirho.key_id_chirho));
    let original_key_chirho = std::fs::read(&key_path_chirho)
        .expect("fixture: the key file lives where the store put it");
    let mut tampered_chirho: serde_json::Value =
        serde_json::from_slice(&original_key_chirho).unwrap();
    tampered_chirho["subject_chirho"] = serde_json::Value::from("user/value-intruder");
    std::fs::write(
        &key_path_chirho,
        serde_json::to_vec(&tampered_chirho).unwrap(),
    )
    .unwrap();
    same_by_hash_chirho(&root_chirho, &hash_chirho, "tampered key");
    assert!(verified_private_dag_value_record_chirho(&root_chirho, &hash_chirho).is_err());
    std::fs::write(&key_path_chirho, &original_key_chirho).unwrap();
    same_by_hash_chirho(&root_chirho, &hash_chirho, "repaired key");
    assert!(
        verified_private_dag_value_record_chirho(&root_chirho, &hash_chirho)
            .unwrap()
            .is_some()
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
