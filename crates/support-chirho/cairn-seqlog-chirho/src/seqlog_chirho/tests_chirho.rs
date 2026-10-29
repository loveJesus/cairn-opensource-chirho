// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use serde::Deserialize;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const CHILD_ROOT_ENV_CHIRHO: &str = "CAIRN_SEQLOG_CHILD_ROOT_CHIRHO";
const CHILD_VALUE_ENV_CHIRHO: &str = "CAIRN_SEQLOG_CHILD_VALUE_CHIRHO";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SeqRecordChirho {
    seq_chirho: u64,
    value_chirho: u64,
}

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-seqlog-test-{nanos_chirho}-{n_chirho}"))
}

#[test]
fn serialized_jsonl_assigns_contiguous_seq_under_parallel_writers_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("stress-chirho.jsonl");
    let mut threads_chirho = Vec::new();
    for value_chirho in 0..48_u64 {
        let root_chirho = root_chirho.clone();
        let path_chirho = path_chirho.clone();
        threads_chirho.push(thread::spawn(move || {
            append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
                thread::sleep(Duration::from_millis(1));
                Ok(SeqRecordChirho {
                    seq_chirho,
                    value_chirho,
                })
            })
            .unwrap();
        }));
    }
    for thread_chirho in threads_chirho {
        thread_chirho.join().unwrap();
    }

    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let records_chirho: Vec<SeqRecordChirho> = text_chirho
        .lines()
        .map(|line_chirho| serde_json::from_str(line_chirho).unwrap())
        .collect();
    assert_eq!(records_chirho.len(), 48);
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        assert_eq!(record_chirho.seq_chirho, i_chirho as u64);
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn child_process_append_helper_chirho() {
    let Ok(root_chirho) = std::env::var(CHILD_ROOT_ENV_CHIRHO) else {
        return;
    };
    let value_chirho = std::env::var(CHILD_VALUE_ENV_CHIRHO)
        .unwrap()
        .parse::<u64>()
        .unwrap();
    let root_chirho = PathBuf::from(root_chirho);
    let path_chirho = root_chirho.join("process-stress-chirho.jsonl");
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        thread::sleep(Duration::from_millis(5));
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho,
        })
    })
    .unwrap();
}

#[test]
fn serialized_jsonl_assigns_contiguous_seq_across_processes_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("process-stress-chirho.jsonl");
    let exe_chirho = std::env::current_exe().unwrap();
    let mut children_chirho = Vec::new();
    for value_chirho in 0..12_u64 {
        children_chirho.push(
            Command::new(&exe_chirho)
                .arg("seqlog_chirho::tests_chirho::child_process_append_helper_chirho")
                .arg("--exact")
                .arg("--nocapture")
                .env(CHILD_ROOT_ENV_CHIRHO, &root_chirho)
                .env(CHILD_VALUE_ENV_CHIRHO, value_chirho.to_string())
                .spawn()
                .unwrap(),
        );
    }
    for mut child_chirho in children_chirho {
        assert!(child_chirho.wait().unwrap().success());
    }

    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    let records_chirho: Vec<SeqRecordChirho> = text_chirho
        .lines()
        .map(|line_chirho| serde_json::from_str(line_chirho).unwrap())
        .collect();
    assert_eq!(records_chirho.len(), 12);
    for (i_chirho, record_chirho) in records_chirho.iter().enumerate() {
        assert_eq!(record_chirho.seq_chirho, i_chirho as u64);
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn read_seq_records_chirho(path_chirho: &Path) -> Vec<SeqRecordChirho> {
    std::fs::read_to_string(path_chirho)
        .unwrap()
        .lines()
        .map(|line_chirho| serde_json::from_str(line_chirho).unwrap())
        .collect()
}

fn quarantine_path_chirho(path_chirho: &Path, removed_chirho: &[u8]) -> PathBuf {
    quarantine_path_for_removed_bytes_chirho(path_chirho, removed_chirho).unwrap()
}

#[test]
fn seqlog_quarantine_sidecar_paths_are_sorted_and_skip_private_dirs_chirho() {
    let root_chirho = tmp_root_chirho();
    let visible_chirho = root_chirho
        .join("tenants-chirho")
        .join("tenant-a-chirho")
        .join(SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join("b-chirho.jsonl-fragment-chirho");
    let visible_second_chirho = root_chirho
        .join(SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join("a-chirho.jsonl-fragment-chirho");
    let skipped_chirho = root_chirho
        .join("privacy-keys-chirho")
        .join(SEQLOG_QUARANTINE_DIR_CHIRHO)
        .join("secret-chirho.jsonl-fragment-chirho");
    for path_chirho in [&visible_chirho, &visible_second_chirho, &skipped_chirho] {
        std::fs::create_dir_all(path_chirho.parent().unwrap()).unwrap();
        std::fs::write(path_chirho, b"fragment-chirho").unwrap();
    }

    let paths_chirho = seqlog_quarantine_sidecar_paths_chirho(&root_chirho).unwrap();
    let names_chirho = paths_chirho
        .iter()
        .map(|path_chirho| {
            path_chirho
                .strip_prefix(&root_chirho)
                .unwrap()
                .display()
                .to_string()
        })
        .collect::<Vec<_>>();
    assert_eq!(
            names_chirho,
            vec![
                "seqlog-quarantine-chirho/a-chirho.jsonl-fragment-chirho",
                "tenants-chirho/tenant-a-chirho/seqlog-quarantine-chirho/b-chirho.jsonl-fragment-chirho",
            ]
        );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn serialized_jsonl_truncates_malformed_tail_before_next_seq_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("tail-recovery-chirho.jsonl");
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 10,
        })
    })
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap()
        .write_all(br#"{"seq_chirho":999,"value_chirho":"#)
        .unwrap();
    let removed_chirho = br#"{"seq_chirho":999,"value_chirho":"#;

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 11,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 1);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 10,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 11,
            }
        ]
    );
    let quarantine_chirho = quarantine_path_chirho(&path_chirho, removed_chirho);
    assert_eq!(std::fs::read(&quarantine_chirho).unwrap(), removed_chirho);
    assert!(quarantine_chirho
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with(&blake3::hash(removed_chirho).to_hex().to_string()));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn recovered_unlocked_append_supports_typed_loader_between_recover_and_append_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("locked-recovery-chirho.jsonl");
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 70,
        })
    })
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap()
        .write_all(br#"{"seq_chirho":999,"value_chirho":"#)
        .unwrap();

    with_append_log_lock_chirho(&root_chirho, || {
        let seq_chirho = recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        assert_eq!(read_seq_records_chirho(&path_chirho).len(), 1);
        let record_chirho = SeqRecordChirho {
            seq_chirho,
            value_chirho: 71,
        };
        append_recovered_jsonl_unlocked_chirho(&path_chirho, seq_chirho, &record_chirho)
    })
    .unwrap();

    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 70,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 71,
            }
        ]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn recovered_unlocked_append_rejects_stale_seq_without_writing_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("stale-recovered-seq-chirho.jsonl");
    let stale_seq_chirho = with_append_log_lock_chirho(&root_chirho, || {
        let seq_chirho = recover_jsonl_len_unlocked_chirho(&path_chirho)?;
        let record_chirho = SeqRecordChirho {
            seq_chirho,
            value_chirho: 80,
        };
        append_recovered_jsonl_unlocked_chirho(&path_chirho, seq_chirho, &record_chirho)?;
        Ok(seq_chirho)
    })
    .unwrap();

    let stale_record_chirho = SeqRecordChirho {
        seq_chirho: stale_seq_chirho,
        value_chirho: 81,
    };
    let error_chirho = with_append_log_lock_chirho(&root_chirho, || {
        append_recovered_jsonl_unlocked_chirho(&path_chirho, stale_seq_chirho, &stale_record_chirho)
    })
    .expect_err("stale recovered seq must fail closed before append");
    assert!(error_chirho
        .to_string()
        .contains("JSONL recovered sequence changed"));
    assert_eq!(
        std::fs::read_to_string(&path_chirho)
            .unwrap()
            .lines()
            .count(),
        1
    );
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![SeqRecordChirho {
            seq_chirho: 0,
            value_chirho: 80,
        }]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn serialized_jsonl_truncates_malformed_newline_tail_before_next_seq_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("newline-tail-recovery-chirho.jsonl");
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 30,
        })
    })
    .unwrap();
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap()
        .write_all(b"not-json\n")
        .unwrap();

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 31,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 1);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 30,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 31,
            }
        ]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn serialized_jsonl_fails_closed_on_malformed_middle_before_valid_suffix_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("middle-corruption-chirho.jsonl");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let original_chirho = concat!(
        r#"{"seq_chirho":0,"value_chirho":40}"#,
        "\n",
        "not-json\n",
        r#"{"seq_chirho":1,"value_chirho":41}"#,
        "\n"
    );
    std::fs::write(&path_chirho, original_chirho).unwrap();

    let mut prepare_called_chirho = false;
    let result_chirho = append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        prepare_called_chirho = true;
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 42,
        })
    });

    assert!(result_chirho
        .unwrap_err()
        .to_string()
        .contains("malformed non-tail JSONL row"));
    assert!(!prepare_called_chirho);
    assert_eq!(
        std::fs::read_to_string(&path_chirho).unwrap(),
        original_chirho
    );
    assert!(!root_chirho.join(SEQLOG_QUARANTINE_DIR_CHIRHO).exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// Warm/full-scan boundary twin for `serialized_jsonl_fails_closed_on_malformed_middle_before_valid_
// suffix_chirho` (which pins the COLD full-scan detection): this pins the WARM boundary and its
// deliberate blind spot. The head checkpoint proves only that the log TAIL is unchanged (byte length
// + last-line hash); it does NOT re-validate interior lines (seqlog_head_chirho module doc:
// "Equality-or-full-rescan only: there is no tail-delta path, which is the safety argument"). So
// (1) same-length interior corruption that leaves the tail byte-identical is TRUSTED by the warm
// fast path — an append still lands at the append-only next seq with zero rescans — while (2) the
// full-scan / typed-load verify road on the SAME log fails closed, proving detection lives exactly
// where the design places it (the scan/verify paths), never silently lost.
#[test]
fn warm_checkpoint_interior_corruption_boundary_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("warm-interior-chirho.jsonl");
    // Seed 3 appends; each reseeds the head checkpoint, so it matches a 3-record tail.
    for value_chirho in 0..3u64 {
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho,
            })
        })
        .unwrap();
    }

    // Corrupt the INTERIOR (second) line in place: overwrite only its content bytes with the same
    // number of non-JSON bytes, leaving every newline, the total byte length, AND the exact tail
    // (last line) bytes unchanged — so the checkpoint's length + tail-hash fingerprint still matches.
    let mut bytes_chirho = std::fs::read(&path_chirho).unwrap();
    let first_newline_chirho = bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho == b'\n')
        .unwrap();
    let second_newline_chirho = first_newline_chirho
        + 1
        + bytes_chirho[first_newline_chirho + 1..]
            .iter()
            .position(|byte_chirho| *byte_chirho == b'\n')
            .unwrap();
    for byte_chirho in &mut bytes_chirho[first_newline_chirho + 1..second_newline_chirho] {
        *byte_chirho = b'x'; // a bareword: invalid JSON, exactly the original interior row's length
    }
    let original_len_chirho = std::fs::metadata(&path_chirho).unwrap().len();
    std::fs::write(&path_chirho, &bytes_chirho).unwrap();
    assert_eq!(
        std::fs::metadata(&path_chirho).unwrap().len(),
        original_len_chirho,
        "corruption must preserve total byte length so the tail checkpoint still matches"
    );

    // (1) WARM boundary: the advisory fast path trusts append-only and does NOT rescan the interior,
    // so the append succeeds at the append-only next seq (3) with zero full reads.
    reset_recover_counts_chirho();
    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 3,
            })
        })
        .unwrap();
    assert_eq!(appended_chirho.seq_chirho, 3);
    assert_eq!(
        recover_full_read_count_chirho(),
        0,
        "warm append must trust the tail-equal checkpoint, not rescan the corrupted interior"
    );

    // (2) FULL-SCAN / TYPED-LOAD boundary on the SAME log: force a checkpoint miss (delete the
    // sidecar) so recovery takes the full-rescan road, which fails closed on the malformed interior
    // (a malformed non-tail row with later valid records must never be truncated away). The shared
    // typed loader is equally strict, independent of the sidecar. Detection is not lost — it lives
    // in the verify/scan paths, exactly as designed.
    let head_path_chirho = crate::seqlog_head_chirho::seqlog_head_path_chirho(&path_chirho);
    std::fs::remove_file(&head_path_chirho).unwrap();
    let recover_error_chirho =
        with_append_log_lock_chirho(&root_chirho, || recover_jsonl_len_chirho(&path_chirho))
            .expect_err("full rescan must fail closed on the malformed interior line");
    assert!(recover_error_chirho
        .to_string()
        .contains("malformed non-tail JSONL row"));
    crate::jsonl_read_chirho::load_serialized_jsonl_chirho::<SeqRecordChirho>(&path_chirho)
        .expect_err("typed load must reject the malformed interior line");

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn seqlog_scan_reports_tail_and_middle_without_mutating_chirho() {
    let root_chirho = tmp_root_chirho();
    let middle_chirho = root_chirho.join("middle-chirho.jsonl");
    let tail_chirho = root_chirho.join("tail-chirho.jsonl");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let middle_original_chirho = concat!(
        r#"{"seq_chirho":0,"value_chirho":50}"#,
        "\n",
        "not-json\n",
        r#"{"seq_chirho":1,"value_chirho":51}"#,
        "\n"
    );
    let tail_original_chirho = concat!(
        r#"{"seq_chirho":0,"value_chirho":60}"#,
        "\n",
        r#"{"seq_chirho":999,"value_chirho":"#
    );
    std::fs::write(&middle_chirho, middle_original_chirho).unwrap();
    std::fs::write(&tail_chirho, tail_original_chirho).unwrap();

    let report_chirho =
        scan_jsonl_manifest_chirho(&root_chirho, &["middle-chirho.jsonl", "tail-chirho.jsonl"])
            .unwrap();

    assert_eq!(
        report_chirho.schema_chirho,
        SEQLOG_SCAN_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.scanned_surfaces_chirho, 2);
    assert_eq!(report_chirho.total_surfaces_chirho, 2);
    assert_eq!(report_chirho.checked_records_chirho, 3);
    assert_eq!(
        report_chirho
            .findings_chirho
            .iter()
            .map(|finding_chirho| finding_chirho.kind_chirho.as_str())
            .collect::<Vec<_>>(),
        vec!["malformed-middle-chirho", "torn-tail-chirho"]
    );
    assert_eq!(
        std::fs::read_to_string(&middle_chirho).unwrap(),
        middle_original_chirho
    );
    assert_eq!(
        std::fs::read_to_string(&tail_chirho).unwrap(),
        tail_original_chirho
    );
    assert!(!root_chirho.join(SEQLOG_QUARANTINE_DIR_CHIRHO).exists());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn serialized_jsonl_repairs_complete_line_missing_newline_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("newline-recovery-chirho.jsonl");
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(&path_chirho, br#"{"seq_chirho":0,"value_chirho":20}"#).unwrap();

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 21,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 1);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 20,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 21,
            }
        ]
    );
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    assert!(text_chirho.ends_with('\n'));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// F1 head-checkpoint law: the checkpoint is provably never AHEAD of the fsync'd log tail.
// t1 — a crash between the line fsync and the checkpoint write leaves the sidecar behind; the
// next append must derive the correct seq via a full rescan and land on the true count.
#[test]
fn checkpoint_behind_after_raw_line_rescans_correct_seq_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("t1-behind-chirho.jsonl");
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 100,
        })
    })
    .unwrap();

    // Simulate the crash window: a complete valid record is durably in the log while the
    // sidecar still records one record (the checkpoint write never happened).
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path_chirho)
        .unwrap()
        .write_all(b"{\"seq_chirho\":1,\"value_chirho\":101}\n")
        .unwrap();

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 102,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 2);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 100,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 101,
            },
            SeqRecordChirho {
                seq_chirho: 2,
                value_chirho: 102,
            },
        ]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// t2 — a torn/garbage sidecar is ignored (full-scan fallback), the append lands correctly, and
// the checkpoint is re-seeded so the following derive is O(1) again.
#[test]
fn garbage_checkpoint_falls_back_to_full_scan_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("t2-garbage-chirho.jsonl");
    for value_chirho in [200u64, 201] {
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho,
            })
        })
        .unwrap();
    }

    let head_path_chirho = crate::seqlog_head_chirho::seqlog_head_path_chirho(&path_chirho);
    assert!(head_path_chirho.exists());
    std::fs::write(&head_path_chirho, b"\x00\x01 torn garbage not json").unwrap();

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 202,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 2);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 200,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 201,
            },
            SeqRecordChirho {
                seq_chirho: 2,
                value_chirho: 202,
            },
        ]
    );
    assert_eq!(
        crate::seqlog_head_chirho::try_seqlog_head_fast_path_chirho(&path_chirho).unwrap(),
        Some(3)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// t3 — a log truncated below the checkpoint leaves the sidecar pointing past EOF (ahead); it
// must be distrusted, and the full rescan derives the correct shorter count.
#[test]
fn log_truncated_below_checkpoint_falls_back_to_full_scan_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("t3-truncated-chirho.jsonl");
    for value_chirho in [300u64, 301, 302] {
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho,
            })
        })
        .unwrap();
    }

    // Keep only the first record (a valid newline-terminated prefix); the checkpoint's recorded
    // byte length now exceeds the actual file length.
    let first_line_len_chirho = {
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        (text_chirho.lines().next().unwrap().len() + 1) as u64
    };
    let file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .open(&path_chirho)
        .unwrap();
    file_chirho.set_len(first_line_len_chirho).unwrap();
    drop(file_chirho);

    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 303,
            })
        })
        .unwrap();

    assert_eq!(appended_chirho.seq_chirho, 1);
    assert_eq!(
        read_seq_records_chirho(&path_chirho),
        vec![
            SeqRecordChirho {
                seq_chirho: 0,
                value_chirho: 300,
            },
            SeqRecordChirho {
                seq_chirho: 1,
                value_chirho: 303,
            },
        ]
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// The sidecar is advisory in BOTH directions: when its path is unwritable AND unreadable (blocked
// by a directory here — reseed's temp+rename and the fast-path read both fail), every append must
// still durably commit with correct contiguous seqs via the full-rescan road, and recovery must
// fall back rather than error. A cache failure may cost O(n) work; it may never cost correctness.
#[test]
fn blocked_sidecar_never_fails_appends_or_recovery_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("blocked-head-chirho.jsonl");
    std::fs::create_dir_all(&root_chirho).unwrap();
    // Occupy the sidecar path with a directory before the log exists.
    std::fs::create_dir_all(crate::seqlog_head_chirho::seqlog_head_path_chirho(
        &path_chirho,
    ))
    .unwrap();

    for value_chirho in 0..3u64 {
        let appended_chirho =
            append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
                Ok(SeqRecordChirho {
                    seq_chirho,
                    value_chirho,
                })
            })
            .unwrap();
        assert_eq!(appended_chirho.seq_chirho, value_chirho);
    }
    assert_eq!(read_seq_records_chirho(&path_chirho).len(), 3);
    let recovered_chirho =
        with_append_log_lock_chirho(&root_chirho, || recover_jsonl_len_chirho(&path_chirho))
            .unwrap();
    assert_eq!(recovered_chirho, 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

// F1 count-based scaling guard: warm appends do equal, O(1) work regardless of history length,
// and never open the whole file. Under the pre-checkpoint code the large case would parse
// ~2*N lines and read the whole file twice, so this fails hard on regression. The N-record log
// plus its matching checkpoint are seeded in bulk — that is byte-identical to the state N real
// appends leave — so measuring the single warm append does not pay N fsyncs per size.
#[test]
fn warm_append_work_is_independent_of_log_length_chirho() {
    fn seed_then_measure_one_more_chirho(records_chirho: u64) -> (u64, u64) {
        let root_chirho = tmp_root_chirho();
        let path_chirho = root_chirho.join("scaling-chirho.jsonl");
        std::fs::create_dir_all(&root_chirho).unwrap();
        let mut body_chirho = String::new();
        for value_chirho in 0..records_chirho {
            body_chirho.push_str(
                &serde_json::to_string(&SeqRecordChirho {
                    seq_chirho: value_chirho,
                    value_chirho,
                })
                .unwrap(),
            );
            body_chirho.push('\n');
        }
        std::fs::write(&path_chirho, body_chirho.as_bytes()).unwrap();
        // Warm the checkpoint through the same locked reseed path an append uses.
        with_append_log_lock_chirho(&root_chirho, || {
            reseed_seqlog_head_chirho(&path_chirho, records_chirho)
        })
        .unwrap();

        reset_recover_counts_chirho();
        let appended_chirho =
            append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
                Ok(SeqRecordChirho {
                    seq_chirho,
                    value_chirho: 7,
                })
            })
            .unwrap();
        assert_eq!(appended_chirho.seq_chirho, records_chirho);
        let counts_chirho = (
            recover_parse_count_chirho(),
            recover_full_read_count_chirho(),
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
        counts_chirho
    }

    let (parses_small_chirho, reads_small_chirho) = seed_then_measure_one_more_chirho(16);
    let (parses_large_chirho, reads_large_chirho) = seed_then_measure_one_more_chirho(4096);

    assert_eq!(
        reads_small_chirho, 0,
        "warm append at N=16 read the whole file"
    );
    assert_eq!(
        reads_large_chirho, 0,
        "warm append at N=4096 read the whole file"
    );
    assert_eq!(
        parses_small_chirho, 0,
        "warm append at N=16 rescanned lines"
    );
    assert_eq!(
        parses_large_chirho, 0,
        "warm append at N=4096 rescanned lines"
    );
    assert_eq!(
        parses_large_chirho, parses_small_chirho,
        "per-append work must not grow with log length"
    );
}

// Liveness for the guard above: prove the counters actually register a full scan when the
// checkpoint is lost, and that re-seeding restores O(1) work — so the zero-work assertions are
// meaningful rather than vacuous.
#[test]
fn cold_append_scans_full_log_then_reseeds_to_zero_work_chirho() {
    let root_chirho = tmp_root_chirho();
    let path_chirho = root_chirho.join("cold-chirho.jsonl");
    let records_chirho = 32u64;
    for value_chirho in 0..records_chirho {
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho,
            })
        })
        .unwrap();
    }

    let head_path_chirho = crate::seqlog_head_chirho::seqlog_head_path_chirho(&path_chirho);
    std::fs::remove_file(&head_path_chirho).unwrap();

    reset_recover_counts_chirho();
    let appended_chirho =
        append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
            Ok(SeqRecordChirho {
                seq_chirho,
                value_chirho: 999,
            })
        })
        .unwrap();
    assert_eq!(appended_chirho.seq_chirho, records_chirho);
    assert_eq!(
        recover_full_read_count_chirho(),
        1,
        "a lost checkpoint must trigger exactly one full rescan"
    );
    assert!(recover_parse_count_chirho() >= records_chirho);

    reset_recover_counts_chirho();
    append_serialized_jsonl_chirho(&root_chirho, &path_chirho, |seq_chirho| {
        Ok(SeqRecordChirho {
            seq_chirho,
            value_chirho: 1000,
        })
    })
    .unwrap();
    assert_eq!(
        recover_full_read_count_chirho(),
        0,
        "the re-seeded checkpoint must make the next append O(1)"
    );
    assert_eq!(recover_parse_count_chirho(), 0);

    let _ = std::fs::remove_dir_all(&root_chirho);
}
