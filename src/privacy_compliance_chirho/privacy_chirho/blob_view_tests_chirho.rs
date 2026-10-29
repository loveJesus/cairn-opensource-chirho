// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The privacy blob log's verified view (checkpoint brick S1) against the full scan it replaced: the same answers and
//! refusals, warm lookups and stores that do no history-sized work, and a store that refuses exactly when a lookup
//! would.

use super::*;
use crate::privacy_chirho::blob_view_chirho::{
    blob_view_rules_chirho, logged_blob_subject_with_chirho, BLOB_FULL_VERIFY_EVERY_MS_CHIRHO,
};
use crate::privacy_chirho::private_blob_view_metrics_chirho::{
    self as metrics_chirho, BlobRoadCountsChirho,
};
use cairn_verified_prefix_view_chirho::{BackgroundJobChirho, ViewRulesChirho};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::{Duration, Instant};

/// The full scan the view replaced, kept verbatim as the oracle's reference: the ref's shape, then the whole log and
/// every key file, then the first record carrying exactly this ref.
fn full_scan_subject_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
) -> Result<String> {
    validate_private_blob_ref_shape_chirho(root_chirho, blob_chirho)?;
    let records_chirho = load_privacy_blob_records_chirho(root_chirho)?;
    validate_private_blob_key_namespace_for_records_chirho(root_chirho, &records_chirho)?;
    records_chirho
        .into_iter()
        .find(|record_chirho| record_chirho.blob_chirho == *blob_chirho)
        .map(|record_chirho| record_chirho.subject_chirho)
        .ok_or_else(|| {
            anyhow!(
                "private blob ref {} is not represented in the privacy blob log",
                blob_chirho.ciphertext_chirho.0
            )
        })
}

/// The production road: the lookup every private-value check and unseal uses.
fn view_subject_chirho(root_chirho: &Path, blob_chirho: &PrivateBlobRefChirho) -> Result<String> {
    private_blob_ref_subject_from_log_chirho(root_chirho, blob_chirho)
}

/// The view's answer, after asserting it equals the full scan's, message for message.
fn same_answer_chirho(
    root_chirho: &Path,
    blob_chirho: &PrivateBlobRefChirho,
    context_chirho: &str,
) -> std::result::Result<String, String> {
    let view_chirho =
        view_subject_chirho(root_chirho, blob_chirho).map_err(|e_chirho| e_chirho.to_string());
    let full_chirho =
        full_scan_subject_chirho(root_chirho, blob_chirho).map_err(|e_chirho| e_chirho.to_string());
    assert_eq!(
        view_chirho, full_chirho,
        "{context_chirho}: the view must answer exactly as the full scan, refusals included"
    );
    view_chirho
}

fn log_path_chirho(root_chirho: &Path) -> PathBuf {
    privacy_blob_records_path_chirho(root_chirho)
}

fn log_bytes_chirho(root_chirho: &Path) -> Vec<u8> {
    std::fs::read(log_path_chirho(root_chirho)).unwrap_or_default()
}

/// Bytes written past the store road, as a tamper or a bug would; the log is created if no store made it yet.
fn append_raw_chirho(root_chirho: &Path, bytes_chirho: &[u8]) {
    std::fs::create_dir_all(root_chirho).unwrap();
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path_chirho(root_chirho))
        .unwrap()
        .write_all(bytes_chirho)
        .unwrap();
}

/// A blob record line written past the store road, as a tamper or a bug would. Lookups never checked record
/// signatures or sequence numbers, so neither matters here.
fn forged_line_chirho(subject_chirho: &str, blob_chirho: &PrivateBlobRefChirho) -> String {
    let record_chirho = PrivacyBlobRecordChirho {
        schema_chirho: PRIVACY_BLOB_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        subject_chirho: subject_chirho.to_string(),
        blob_chirho: blob_chirho.clone(),
        bytes_chirho: 0,
        at_ms_chirho: 0,
        sig_chirho: String::new(),
    };
    format!("{}\n", serde_json::to_string(&record_chirho).unwrap())
}

fn write_key_subject_chirho(root_chirho: &Path, key_id_chirho: &str, subject_chirho: &str) {
    let key_chirho = ShredKeyChirho {
        subject_chirho: subject_chirho.to_string(),
        key_hex_chirho: "00".repeat(32),
    };
    std::fs::write(
        key_path_chirho(root_chirho, key_id_chirho),
        serde_json::to_vec_pretty(&key_chirho).unwrap(),
    )
    .unwrap();
}

/// Present but unreadable: a directory where the key file was.
fn make_key_unreadable_chirho(root_chirho: &Path, key_id_chirho: &str) {
    let path_chirho = key_path_chirho(root_chirho, key_id_chirho);
    let _ = std::fs::remove_file(&path_chirho);
    std::fs::create_dir(&path_chirho).unwrap();
}

/// The same ciphertext under a different nonce: a well-formed ref no record carries.
fn unlogged_variant_chirho(blob_chirho: &PrivateBlobRefChirho) -> PrivateBlobRefChirho {
    let mut variant_chirho = blob_chirho.clone();
    let first_chirho = if variant_chirho.nonce_chirho.starts_with('0') {
        "1"
    } else {
        "0"
    };
    variant_chirho
        .nonce_chirho
        .replace_range(0..1, first_chirho);
    variant_chirho
}

/// The same bytes under a new inode: a write-access event, so the view's next call verifies everything.
fn swap_log_inode_chirho(root_chirho: &Path) {
    let log_chirho = log_path_chirho(root_chirho);
    let bytes_chirho = std::fs::read(&log_chirho).unwrap();
    let swap_chirho = log_chirho.with_extension("swap-chirho");
    std::fs::write(&swap_chirho, &bytes_chirho).unwrap();
    std::fs::rename(&swap_chirho, &log_chirho).unwrap();
}

fn quarantine_fragments_chirho(root_chirho: &Path) -> Vec<Vec<u8>> {
    let Ok(entries_chirho) =
        std::fs::read_dir(root_chirho.join(seqlog_chirho::SEQLOG_QUARANTINE_DIR_CHIRHO))
    else {
        return Vec::new();
    };
    entries_chirho
        .map(|entry_chirho| std::fs::read(entry_chirho.unwrap().path()).unwrap())
        .collect()
}

fn store_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    label_chirho: &str,
) -> PrivateBlobRefChirho {
    store_private_blob_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            subject_chirho,
        ),
        subject_chirho,
        label_chirho.as_bytes(),
    )
    .unwrap()
}

fn counts_after_chirho<T>(action_chirho: impl FnOnce() -> T) -> (T, BlobRoadCountsChirho) {
    metrics_chirho::reset_chirho();
    let value_chirho = action_chirho();
    (value_chirho, metrics_chirho::counts_chirho())
}

fn road_chirho(
    lookups_chirho: u64,
    full_chirho: u64,
    folded_chirho: u64,
    keys_chirho: u64,
) -> BlobRoadCountsChirho {
    BlobRoadCountsChirho {
        lookups_chirho,
        full_log_loads_chirho: full_chirho,
        records_folded_chirho: folded_chirho,
        key_file_reads_chirho: keys_chirho,
    }
}

/// THE LOOKUP GROWTH ARM. At 1, 10 and 100 stored blobs, a warm lookup reads no whole log, folds nothing and reads
/// one key file, its own; after one more store, the next lookup folds exactly that record. INSTRUMENT CONTROL, on
/// each root: a new inode with the same bytes is a write-access event, and the counters then see the whole log and
/// every key file.
///
/// MIGRATION PATH: a warm count that grows with the history means the lookup is back on a full-scan road. A control
/// that does not see the whole log means the counters went blind, and the warm zeros prove nothing.
#[test]
fn a_warm_blob_lookup_does_constant_work_at_any_history_chirho() {
    for history_chirho in [1_usize, 10, 100] {
        let root_chirho = tmp_root_chirho();
        let blobs_chirho: Vec<_> = (0..history_chirho)
            .map(|i_chirho| {
                store_chirho(
                    &root_chirho,
                    &format!("user/growth-{}", i_chirho % 3),
                    &format!("growth {i_chirho}"),
                )
            })
            .collect();
        let target_index_chirho = history_chirho / 2;
        let target_chirho = &blobs_chirho[target_index_chirho];
        let target_subject_chirho = format!("user/growth-{}", target_index_chirho % 3);
        let history_u64_chirho = history_chirho as u64;

        swap_log_inode_chirho(&root_chirho);
        let (subject_chirho, control_chirho) =
            counts_after_chirho(|| view_subject_chirho(&root_chirho, target_chirho).unwrap());
        assert_eq!(subject_chirho, target_subject_chirho);
        assert_eq!(
            control_chirho,
            road_chirho(1, 1, history_u64_chirho, history_u64_chirho + 1),
            "control at {history_chirho} blobs: a rebuild must read the whole log, fold every record and read \
             every key file plus the target's; otherwise the counters are blind"
        );

        let (subject_chirho, warm_chirho) =
            counts_after_chirho(|| view_subject_chirho(&root_chirho, target_chirho).unwrap());
        assert_eq!(subject_chirho, target_subject_chirho);
        assert_eq!(
            warm_chirho,
            road_chirho(1, 0, 0, 1),
            "a warm lookup at {history_chirho} blobs must read no whole log, fold nothing and read one key file"
        );

        let fresh_chirho = store_chirho(&root_chirho, "user/growth-delta", "growth delta");
        let (subject_chirho, delta_chirho) =
            counts_after_chirho(|| view_subject_chirho(&root_chirho, &fresh_chirho).unwrap());
        assert_eq!(subject_chirho, "user/growth-delta");
        assert_eq!(
            delta_chirho,
            road_chirho(1, 0, 1, 2),
            "after one store at {history_chirho} blobs, the next lookup must fold that one record (one key file) \
             and read the target's key file"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// THE STORE GROWTH ARM (census execution-effects row A3, blob half). At 1, 10 and 100 stored blobs, a store on a
/// current view reads no whole log; the next store folds only the previous store's record. The seq comes from the
/// seqlog's recovered length, not a full typed load. INSTRUMENT CONTROL: the whole-log counter sees the typed loader.
///
/// MIGRATION PATH: a whole-log load per store means the seq is back on a full typed load (O(blob records) per
/// private store).
#[test]
fn a_warm_blob_store_does_constant_work_at_any_history_chirho() {
    for history_chirho in [1_usize, 10, 100] {
        let root_chirho = tmp_root_chirho();
        let blobs_chirho: Vec<_> = (0..history_chirho)
            .map(|i_chirho| {
                store_chirho(
                    &root_chirho,
                    "user/store-growth",
                    &format!("store growth {i_chirho}"),
                )
            })
            .collect();
        view_subject_chirho(&root_chirho, &blobs_chirho[0]).unwrap();

        let ((), first_chirho) = counts_after_chirho(|| {
            store_chirho(&root_chirho, "user/store-growth", "first measured store");
        });
        assert_eq!(
            first_chirho,
            road_chirho(0, 0, 0, 0),
            "a store on a current view at {history_chirho} blobs must read no whole log and fold nothing"
        );
        let ((), second_chirho) = counts_after_chirho(|| {
            store_chirho(&root_chirho, "user/store-growth", "second measured store");
        });
        assert_eq!(
            second_chirho,
            road_chirho(0, 0, 1, 1),
            "the next store at {history_chirho} blobs must fold only the previous store's record"
        );

        let (records_chirho, control_chirho) =
            counts_after_chirho(|| load_privacy_blob_records_chirho(&root_chirho).unwrap());
        assert_eq!(records_chirho.len(), history_chirho + 2);
        assert_eq!(
            control_chirho.full_log_loads_chirho, 1,
            "control: the typed whole-log loader must be counted, or the zeros above are blind"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// Builds the view at a write-access event, so the first lookup after `warm_private_blob_view_chirho` is warm.
#[test]
fn warming_builds_the_view_so_the_first_lookup_is_warm_chirho() {
    let root_chirho = tmp_root_chirho();
    let blobs_chirho: Vec<_> = (0..5)
        .map(|i_chirho| store_chirho(&root_chirho, "user/warm", &format!("warm {i_chirho}")))
        .collect();
    swap_log_inode_chirho(&root_chirho);
    let ((), warm_up_chirho) =
        counts_after_chirho(|| warm_private_blob_view_chirho(&root_chirho).unwrap());
    assert_eq!(
        warm_up_chirho,
        road_chirho(0, 1, 5, 5),
        "the warm-up verifies the whole log and its key files"
    );
    let (subject_chirho, first_chirho) =
        counts_after_chirho(|| view_subject_chirho(&root_chirho, &blobs_chirho[3]).unwrap());
    assert_eq!(subject_chirho, "user/warm");
    assert_eq!(
        first_chirho,
        road_chirho(1, 0, 0, 1),
        "the first lookup after the warm-up is warm"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// xorshift64*: deterministic histories, so a failing episode replays exactly.
struct OracleRngChirho(u64);

impl OracleRngChirho {
    fn new_chirho(seed_chirho: u64) -> Self {
        Self(
            seed_chirho
                .wrapping_add(1)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                | 1,
        )
    }

    fn next_chirho(&mut self) -> u64 {
        let mut x_chirho = self.0;
        x_chirho ^= x_chirho >> 12;
        x_chirho ^= x_chirho << 25;
        x_chirho ^= x_chirho >> 27;
        self.0 = x_chirho;
        x_chirho.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below_chirho(&mut self, bound_chirho: usize) -> usize {
        (self.next_chirho() % bound_chirho as u64) as usize
    }
}

const ORACLE_SUBJECTS_CHIRHO: [&str; 3] = ["user/oracle-a", "user/oracle-b", "user/oracle-c"];

/// THE ORACLE. Random histories of stores, forged duplicates, erasures and ONE injected fault per episode: a
/// multi-subject key, a bad subject, a bad key id, a garbage line, a record-shaped line, a changed key file, or an
/// unreadable one. After every step the view answers exactly as the full scan, message for message, for a logged
/// ref and for an unlogged one, and a store refuses, leaving the log untouched, once the fault is in. A changed or
/// unreadable key file is looked up at once, which is how a lookup finds it; the window before that lookup is the
/// integrity pass's arm below.
///
/// MIGRATION PATH: a mismatch names the episode and step, and the seed replays it. A fault kind that never occurred
/// fails the coverage check: the oracle then proves nothing about that kind.
#[test]
fn the_blob_view_answers_as_the_full_scan_over_random_histories_chirho() {
    let mut occurred_chirho = BTreeMap::<&str, u64>::new();
    let (mut answered_chirho, mut refused_chirho) = (0_u64, 0_u64);
    for episode_chirho in 0..48_u64 {
        let mut rng_chirho = OracleRngChirho::new_chirho(episode_chirho);
        let root_chirho = tmp_root_chirho();
        let mut stored_chirho: Vec<(PrivateBlobRefChirho, &str)> = Vec::new();
        let mut fault_chirho: Option<&str> = None;
        for step_chirho in 0..40_u64 {
            let context_chirho =
                format!("episode {episode_chirho} step {step_chirho} fault {fault_chirho:?}");
            let clean_chirho = fault_chirho.is_none();
            let pick_chirho = if stored_chirho.is_empty() {
                None
            } else {
                Some(rng_chirho.below_chirho(stored_chirho.len()))
            };
            let mut inject_chirho = |kind_chirho: &'static str| {
                *occurred_chirho.entry(kind_chirho).or_default() += 1;
                fault_chirho = Some(kind_chirho);
            };
            match (rng_chirho.below_chirho(100), pick_chirho) {
                (0..=44, _) => {
                    let subject_chirho = ORACLE_SUBJECTS_CHIRHO[rng_chirho.below_chirho(3)];
                    let before_chirho = log_bytes_chirho(&root_chirho);
                    let stored_now_chirho = store_private_blob_chirho(
                        &root_chirho,
                        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(subject_chirho),
                        subject_chirho,
                        format!("{context_chirho} oracle blob").as_bytes());
                    if clean_chirho {
                        stored_chirho.push((stored_now_chirho.unwrap(), subject_chirho));
                    } else {
                        assert!(
                            stored_now_chirho.is_err(),
                            "{context_chirho}: a store must refuse once the log is bad"
                        );
                        assert_eq!(
                            log_bytes_chirho(&root_chirho),
                            before_chirho,
                            "{context_chirho}: a refused store must leave the log untouched"
                        );
                    }
                }
                (45..=54, Some(i_chirho)) if clean_chirho => {
                    *occurred_chirho.entry("duplicate").or_default() += 1;
                    let (blob_chirho, subject_chirho) = &stored_chirho[i_chirho];
                    append_raw_chirho(
                        &root_chirho,
                        forged_line_chirho(subject_chirho, blob_chirho).as_bytes(),
                    );
                }
                (55..=59, Some(i_chirho)) if clean_chirho => {
                    let (blob_chirho, subject_chirho) = stored_chirho[i_chirho].clone();
                    let other_chirho = ORACLE_SUBJECTS_CHIRHO
                        .iter()
                        .find(|candidate_chirho| **candidate_chirho != subject_chirho)
                        .unwrap();
                    append_raw_chirho(
                        &root_chirho,
                        forged_line_chirho(other_chirho, &blob_chirho).as_bytes(),
                    );
                    inject_chirho("multi-subject");
                }
                (60..=62, Some(i_chirho)) if clean_chirho => {
                    let blob_chirho = stored_chirho[i_chirho].0.clone();
                    append_raw_chirho(
                        &root_chirho,
                        forged_line_chirho("not a valid subject!", &blob_chirho).as_bytes(),
                    );
                    inject_chirho("bad-subject");
                }
                (63..=65, Some(i_chirho)) if clean_chirho => {
                    let mut blob_chirho = stored_chirho[i_chirho].0.clone();
                    blob_chirho.key_id_chirho = "zz-not-hex".to_string();
                    append_raw_chirho(
                        &root_chirho,
                        forged_line_chirho("user/oracle-a", &blob_chirho).as_bytes(),
                    );
                    inject_chirho("bad-key-id");
                }
                (66..=68, _) if clean_chirho => {
                    append_raw_chirho(&root_chirho, b"this is not json\n");
                    inject_chirho("garbage-line");
                }
                (69..=71, _) if clean_chirho => {
                    append_raw_chirho(&root_chirho, b"{}\n");
                    inject_chirho("record-shaped-line");
                }
                (72..=76, Some(i_chirho)) if clean_chirho => {
                    let blob_chirho = stored_chirho[i_chirho].0.clone();
                    write_key_subject_chirho(
                        &root_chirho,
                        &blob_chirho.key_id_chirho,
                        "user/oracle-intruder",
                    );
                    inject_chirho("key-changed");
                    let found_chirho =
                        same_answer_chirho(&root_chirho, &blob_chirho, &context_chirho);
                    assert!(
                        found_chirho.is_err(),
                        "{context_chirho}: a changed key file must refuse its lookup"
                    );
                }
                (77..=79, Some(i_chirho)) if clean_chirho => {
                    let blob_chirho = stored_chirho[i_chirho].0.clone();
                    make_key_unreadable_chirho(&root_chirho, &blob_chirho.key_id_chirho);
                    inject_chirho("key-unreadable");
                    let found_chirho =
                        same_answer_chirho(&root_chirho, &blob_chirho, &context_chirho);
                    assert!(
                        found_chirho.is_err(),
                        "{context_chirho}: an unreadable key file must refuse its lookup"
                    );
                }
                (80..=85, Some(i_chirho)) if clean_chirho => {
                    *occurred_chirho.entry("erase").or_default() += 1;
                    erase_private_blob_key_chirho(
                        &root_chirho,
                        &stored_chirho[i_chirho].0.key_id_chirho,
                    )
                    .unwrap();
                }
                _ => {}
            }
            if let Some(i_chirho) =
                (!stored_chirho.is_empty()).then(|| rng_chirho.below_chirho(stored_chirho.len()))
            {
                let (blob_chirho, subject_chirho) = stored_chirho[i_chirho].clone();
                match same_answer_chirho(&root_chirho, &blob_chirho, &context_chirho) {
                    Ok(found_chirho) => {
                        answered_chirho += 1;
                        assert!(
                            fault_chirho.is_none(),
                            "{context_chirho}: a bad log answered"
                        );
                        assert_eq!(
                            found_chirho, subject_chirho,
                            "{context_chirho}: the logged subject"
                        );
                    }
                    Err(_) => {
                        refused_chirho += 1;
                        assert!(
                            fault_chirho.is_some(),
                            "{context_chirho}: a clean log refused"
                        );
                    }
                }
                let unlogged_chirho = same_answer_chirho(
                    &root_chirho,
                    &unlogged_variant_chirho(&blob_chirho),
                    &context_chirho,
                );
                assert!(
                    unlogged_chirho.is_err(),
                    "{context_chirho}: an unlogged ref never resolves"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
    for kind_chirho in [
        "duplicate",
        "erase",
        "multi-subject",
        "bad-subject",
        "bad-key-id",
        "garbage-line",
        "record-shaped-line",
        "key-changed",
        "key-unreadable",
    ] {
        assert!(
            occurred_chirho.get(kind_chirho).copied().unwrap_or(0) > 0,
            "coverage: the oracle never exercised '{kind_chirho}' ({occurred_chirho:?})"
        );
    }
    assert!(
        answered_chirho > 100 && refused_chirho > 100,
        "coverage: {answered_chirho} answered, {refused_chirho} refused"
    );
}

/// The target key is re-checked on every lookup, in its three states: absent (an erased key is no fault), present and
/// changed after its record was folded (refuses, and the fault closes the whole root: other lookups and stores refuse
/// as the full scan did, until it is repaired, with no flag to clear), and present but unreadable (refuses).
#[test]
fn the_target_key_is_rechecked_and_a_fault_closes_the_root_until_repaired_chirho() {
    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/target-a", "target a");
    let b_chirho = store_chirho(&root_chirho, "user/target-b", "target b");
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "warm a").unwrap(),
        "user/target-a"
    );
    assert_eq!(
        same_answer_chirho(&root_chirho, &b_chirho, "warm b").unwrap(),
        "user/target-b"
    );

    std::fs::remove_file(key_path_chirho(&root_chirho, &a_chirho.key_id_chirho)).unwrap();
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "absent key").unwrap(),
        "user/target-a"
    );

    write_key_subject_chirho(
        &root_chirho,
        &b_chirho.key_id_chirho,
        "user/target-intruder",
    );
    let changed_chirho = same_answer_chirho(&root_chirho, &b_chirho, "changed key").unwrap_err();
    assert!(
        changed_chirho.contains("belongs to subject 'user/target-intruder', not privacy blob record subject 'user/target-b'"),
        "the target check refuses with the full scan's message: {changed_chirho}"
    );
    let before_chirho = log_bytes_chirho(&root_chirho);
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "root closed").unwrap_err(),
        changed_chirho,
        "after the fault, a lookup of a CLEAN ref refuses with the same message: the view was dropped"
    );
    assert!(
        store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/target-c"
            ),
            "user/target-c",
            b"store while closed"
        )
        .is_err(),
        "a store refuses while the fault is there"
    );
    assert_eq!(
        log_bytes_chirho(&root_chirho),
        before_chirho,
        "the refused store left the log untouched"
    );

    write_key_subject_chirho(&root_chirho, &b_chirho.key_id_chirho, "user/target-b");
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "repaired").unwrap(),
        "user/target-a"
    );
    let c_chirho = store_chirho(&root_chirho, "user/target-c", "store after repair");
    assert_eq!(
        same_answer_chirho(&root_chirho, &c_chirho, "repaired store").unwrap(),
        "user/target-c"
    );

    make_key_unreadable_chirho(&root_chirho, &c_chirho.key_id_chirho);
    assert!(same_answer_chirho(&root_chirho, &c_chirho, "unreadable key").is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE WINDOW AND ITS CLOSE (option (i), agy #25778). An UNRELATED key file changed after its record was folded is
/// the one difference the view keeps: the full scan refuses every lookup at once, while the view answers other refs
/// until the integrity pass. The pass (made due at once here) re-folds the whole log, finds the key, and drops the
/// view; lookups and stores then refuse with the full scan's message.
///
/// MIGRATION PATH: if the poll times out, the integrity pass no longer re-checks key files (the fold lost check (c))
/// or no longer runs, and the window is unbounded.
#[test]
fn the_integrity_pass_closes_the_unrelated_key_window_chirho() {
    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/window-a", "window a");
    let b_chirho = store_chirho(&root_chirho, "user/window-b", "window b");
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/window-a"
    );
    assert_eq!(
        view_subject_chirho(&root_chirho, &b_chirho).unwrap(),
        "user/window-b"
    );

    write_key_subject_chirho(
        &root_chirho,
        &b_chirho.key_id_chirho,
        "user/window-intruder",
    );
    let full_chirho = full_scan_subject_chirho(&root_chirho, &a_chirho)
        .unwrap_err()
        .to_string();
    assert!(
        full_chirho.contains("user/window-intruder"),
        "the full scan refuses at once: {full_chirho}"
    );
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/window-a",
        "inside the window, the view still answers for an unrelated ref"
    );

    let due_now_chirho = ViewRulesChirho {
        full_verify_every_ms_chirho: 0,
        ..blob_view_rules_chirho()
    };
    let deadline_chirho = Instant::now() + Duration::from_secs(30);
    let refused_chirho = loop {
        match logged_blob_subject_with_chirho(
            &root_chirho,
            &a_chirho,
            &due_now_chirho,
            now_ms_chirho,
        ) {
            Err(error_chirho) => break error_chirho.to_string(),
            Ok(_) => {
                assert!(
                    Instant::now() < deadline_chirho,
                    "the integrity pass never closed the window within 30 s"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    assert_eq!(
        refused_chirho, full_chirho,
        "after the pass, the view refuses with the full scan's message"
    );
    let before_chirho = log_bytes_chirho(&root_chirho);
    assert!(store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/window-c"
        ),
        "user/window-c",
        b"store after the pass"
    )
    .is_err());
    assert_eq!(log_bytes_chirho(&root_chirho), before_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The window's bound: the integrity pass is due one hour after the view's last full verification, not before.
#[test]
fn the_integrity_pass_is_due_hourly_chirho() {
    assert_eq!(
        BLOB_FULL_VERIFY_EVERY_MS_CHIRHO,
        60 * 60 * 1000,
        "the reviewed window is one hour"
    );
    let root_chirho = tmp_root_chirho();
    // One store leaves no view (its gate saw no log), so the first lookup below builds the view at `start`.
    let a_chirho = store_chirho(&root_chirho, "user/hourly", "hourly");
    let start_chirho = now_ms_chirho() + 1_000;
    let rules_chirho = blob_view_rules_chirho();
    let started_at_chirho = |at_chirho: u64| {
        logged_blob_subject_with_chirho(&root_chirho, &a_chirho, &rules_chirho, || at_chirho)
            .unwrap()
            .1
            .started_chirho
    };
    assert_eq!(
        started_at_chirho(start_chirho),
        None,
        "the first load is itself a full verification"
    );
    assert_eq!(
        started_at_chirho(start_chirho + BLOB_FULL_VERIFY_EVERY_MS_CHIRHO - 1),
        None
    );
    assert_eq!(
        started_at_chirho(start_chirho + BLOB_FULL_VERIFY_EVERY_MS_CHIRHO),
        Some(BackgroundJobChirho::IntegrityPassChirho)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Write access to records the view already verified: a same-length rewrite in place, a new inode with changed
/// bytes, and a shrink each make the next lookup verify everything, and answer as the full scan.
#[test]
fn write_access_to_verified_records_rebuilds_and_answers_as_the_full_scan_chirho() {
    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/rewrite-aaaa", "rewrite a");
    let b_chirho = store_chirho(&root_chirho, "user/rewrite-bbbb", "rewrite b");
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/rewrite-aaaa"
    );
    let text_chirho = std::fs::read_to_string(log_path_chirho(&root_chirho)).unwrap();
    let rewritten_chirho = text_chirho.replacen("user/rewrite-aaaa", "user/rewrite-cccc", 1);
    assert_eq!(
        rewritten_chirho.len(),
        text_chirho.len(),
        "fixture: the rewrite keeps the length"
    );
    std::fs::write(log_path_chirho(&root_chirho), &rewritten_chirho).unwrap();
    let refused_chirho =
        same_answer_chirho(&root_chirho, &b_chirho, "same-length rewrite").unwrap_err();
    assert!(
        refused_chirho.contains("not privacy blob record subject 'user/rewrite-cccc'"),
        "{refused_chirho}"
    );

    let restored_chirho = log_path_chirho(&root_chirho).with_extension("restore-chirho");
    std::fs::write(&restored_chirho, &text_chirho).unwrap();
    std::fs::rename(&restored_chirho, log_path_chirho(&root_chirho)).unwrap();
    assert_eq!(
        same_answer_chirho(&root_chirho, &b_chirho, "new inode, restored").unwrap(),
        "user/rewrite-bbbb"
    );

    let first_line_len_chirho = text_chirho.find('\n').unwrap() + 1;
    std::fs::OpenOptions::new()
        .write(true)
        .open(log_path_chirho(&root_chirho))
        .unwrap()
        .set_len(first_line_len_chirho as u64)
        .unwrap();
    assert!(
        same_answer_chirho(&root_chirho, &b_chirho, "shrunk").is_err(),
        "b's record was cut off"
    );
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "shrunk").unwrap(),
        "user/rewrite-aaaa"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// PFE #25789: a crash mid-append heals on the next store. The view leaves the unterminated tail alone (the full
/// scan refused on it: the one documented difference), and the store's recovery quarantines the torn bytes and
/// truncates them, so the crash keeps its evidence too.
#[test]
fn a_torn_tail_heals_on_the_next_store_and_keeps_its_evidence_chirho() {
    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/torn-a", "torn a");
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/torn-a"
    );
    let clean_chirho = log_bytes_chirho(&root_chirho);
    let torn_chirho = b"{\"schema_chirho\":\"privacy-blob-rec";
    append_raw_chirho(&root_chirho, torn_chirho);

    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/torn-a",
        "the view waits out a tail"
    );
    assert!(
        full_scan_subject_chirho(&root_chirho, &a_chirho).is_err(),
        "the full scan refused on a torn tail"
    );

    let b_chirho = store_chirho(&root_chirho, "user/torn-b", "torn b");
    let healed_chirho = log_bytes_chirho(&root_chirho);
    assert!(
        healed_chirho.starts_with(&clean_chirho),
        "the verified records are untouched"
    );
    // The torn fragment is a prefix of every record line, so searching for it proves nothing: the bytes after the
    // verified records must be exactly one complete line, b's own record.
    let added_chirho = std::str::from_utf8(&healed_chirho[clean_chirho.len()..]).unwrap();
    assert_eq!(
        added_chirho.matches('\n').count(),
        1,
        "exactly one line follows the verified records: {added_chirho:?}"
    );
    let added_record_chirho: PrivacyBlobRecordChirho =
        serde_json::from_str(added_chirho.trim_end()).expect("the torn bytes left the log");
    assert_eq!(
        added_record_chirho.blob_chirho, b_chirho,
        "the added line is b's record"
    );
    assert_eq!(
        quarantine_fragments_chirho(&root_chirho),
        vec![torn_chirho.to_vec()],
        "they are quarantined"
    );
    assert_eq!(
        same_answer_chirho(&root_chirho, &a_chirho, "healed a").unwrap(),
        "user/torn-a"
    );
    assert_eq!(
        same_answer_chirho(&root_chirho, &b_chirho, "healed b").unwrap(),
        "user/torn-b"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// PFE #25789 and #25795: a COMPLETE bad line refuses lookups AND stores alike, and the refused store leaves the line
/// on disk byte for byte, with no quarantine fragment: recovery never ran, so the root keeps refusing until an
/// operator acts. A non-UTF-8 line refuses in both roads too (their messages differ: the full scan read the file as
/// text).
#[test]
fn a_complete_bad_line_refuses_lookups_and_stores_and_stays_on_disk_chirho() {
    for bad_line_chirho in [&b"{}\n"[..], &b"this is not json\n"[..]] {
        let root_chirho = tmp_root_chirho();
        let a_chirho = store_chirho(&root_chirho, "user/bad-line-a", "bad line a");
        assert_eq!(
            view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
            "user/bad-line-a"
        );
        append_raw_chirho(&root_chirho, bad_line_chirho);
        let before_chirho = log_bytes_chirho(&root_chirho);

        assert!(same_answer_chirho(&root_chirho, &a_chirho, "complete bad line").is_err());
        assert!(store_private_blob_chirho(
            &root_chirho,
            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                "user/bad-line-b"
            ),
            "user/bad-line-b",
            b"refused store"
        )
        .is_err());
        assert_eq!(
            log_bytes_chirho(&root_chirho),
            before_chirho,
            "the evidence line is still on disk, byte for byte, after the refused store"
        );
        assert!(
            quarantine_fragments_chirho(&root_chirho).is_empty(),
            "recovery never ran"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }

    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/bad-utf8-a", "bad utf8 a");
    append_raw_chirho(&root_chirho, b"\xff\xfe not text\n");
    assert!(view_subject_chirho(&root_chirho, &a_chirho).is_err());
    assert!(full_scan_subject_chirho(&root_chirho, &a_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// agy #25801, the one mutate-then-refuse case: an UNTERMINATED final line that is valid JSON but no blob record. The
/// view waits it out; recovery counts it and completes it with a newline; the count check then refuses. Nothing is
/// removed, and the now-complete line refuses every lookup and store, as the full scan does.
#[test]
fn an_unterminated_record_shaped_tail_is_completed_then_refused_chirho() {
    let root_chirho = tmp_root_chirho();
    let a_chirho = store_chirho(&root_chirho, "user/shaped-a", "shaped a");
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/shaped-a"
    );
    append_raw_chirho(&root_chirho, b"{}");
    let before_chirho = log_bytes_chirho(&root_chirho);
    assert_eq!(
        view_subject_chirho(&root_chirho, &a_chirho).unwrap(),
        "user/shaped-a"
    );

    let refused_chirho = store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/shaped-b",
        ),
        "user/shaped-b",
        b"refused store",
    )
    .unwrap_err()
    .to_string();
    assert!(
        refused_chirho.contains("records by recovery but"),
        "{refused_chirho}"
    );
    let mut completed_chirho = before_chirho.clone();
    completed_chirho.push(b'\n');
    assert_eq!(
        log_bytes_chirho(&root_chirho),
        completed_chirho,
        "recovery only completed the line"
    );
    assert!(
        quarantine_fragments_chirho(&root_chirho).is_empty(),
        "nothing was removed"
    );
    assert!(same_answer_chirho(&root_chirho, &a_chirho, "completed bad line").is_err());
    assert!(store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/shaped-c"
        ),
        "user/shaped-c",
        b"still refused"
    )
    .is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// Concurrent stores into one root all land, in one gapless sequence the audit verifies: the store's view update and
/// its count check run under the blob log's append lock (taken before the view's own lock, never after), so no store
/// sees another's half-finished append, and the nesting cannot deadlock.
///
/// MIGRATION PATH: a "records by recovery but" refusal here means the gate left the append lock; a hang means the
/// two locks are now taken in both orders somewhere.
#[test]
fn concurrent_stores_land_in_one_gapless_audited_sequence_chirho() {
    let root_chirho = tmp_root_chirho();
    store_chirho(&root_chirho, "user/concurrent", "seed");
    let workers_chirho: Vec<_> = (0..8)
        .map(|thread_chirho| {
            let root_chirho = root_chirho.clone();
            std::thread::spawn(move || {
                (0..10)
                    .map(|i_chirho| {
                        store_private_blob_chirho(
                            &root_chirho,
                            &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho("user/concurrent"),
                            "user/concurrent",
                            format!("thread {thread_chirho} store {i_chirho}").as_bytes())
                        .map_err(|error_chirho| error_chirho.to_string())
                    })
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let results_chirho: Vec<_> = workers_chirho
        .into_iter()
        .flat_map(|worker_chirho| worker_chirho.join().unwrap())
        .collect();
    let refused_chirho: Vec<_> = results_chirho
        .iter()
        .filter_map(|r_chirho| r_chirho.as_ref().err())
        .collect();
    assert!(
        refused_chirho.is_empty(),
        "every concurrent store lands: {refused_chirho:?}"
    );
    let (verified_chirho, _) = verify_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        verified_chirho, 81,
        "the audit verifies one gapless signed sequence"
    );
    for result_chirho in results_chirho {
        let blob_chirho = result_chirho.unwrap();
        assert_eq!(
            same_answer_chirho(&root_chirho, &blob_chirho, "concurrent").unwrap(),
            "user/concurrent"
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}
