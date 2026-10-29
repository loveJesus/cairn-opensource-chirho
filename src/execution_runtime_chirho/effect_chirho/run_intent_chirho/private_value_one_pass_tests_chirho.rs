// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! One run-intent verification pass reads the private-value and privacy blob logs once, at any size.
//!
//! The pass used to ask the single-pair resolver once per private-request record, and every one of
//! those calls re-read the whole private-value log, the whole privacy blob log and every shred-key
//! file: O(records x (values + blob records + key files)) in reads, paid at every process start and
//! on every DAG run admitted through an intent. The scaling arm measures the loads directly, at two
//! sizes, so a per-record road coming back shows up as a count that grows with the pass.
//!
//! Remembering verdicts inside a pass is a new way to be wrong, so the other two arms pin what a
//! remembered verdict must NOT do: carry over to a different request, or to a different subject
//! asking for the same bytes.

use super::*;
use crate::dag_private_value_chirho::private_value_view_metrics_chirho::{
    self as value_view_metrics_chirho, ValueRoadCountsChirho,
};
use crate::dag_private_value_chirho::{
    self, PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO, PRIVATE_DAG_VALUE_RECORD_VERIFICATIONS_CHIRHO,
};
use crate::privacy_chirho::private_blob_view_metrics_chirho::{self, BlobRoadCountsChirho};
use std::sync::atomic::{AtomicU64, Ordering};

const SUBJECT_CHIRHO: &str = "user/run-intent-one-pass-subject-chirho";
const OTHER_SUBJECT_CHIRHO: &str = "user/run-intent-one-pass-other-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-run-intent-one-pass-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

/// A stored DAG; distinct labels give distinct DAG hashes, hence distinct run identities.
fn store_dag_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: vec![HashChirho(format!(
            "node-run-intent-one-pass-{label_chirho}"
        ))],
        edges_chirho: vec![],
    };
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

/// Appends `statuses_chirho`, in order, for one private-request run through the production append
/// door, deriving every hash with the runtime's own helpers.
fn append_private_request_run_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    request_chirho: &HashChirho,
    subject_chirho: &str,
    statuses_chirho: &[&'static str],
) {
    let scope_chirho = run_intent_scope_chirho(root_chirho, None).unwrap();
    let idempotency_context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        dag_hash_chirho,
        request_chirho,
        &scope_chirho,
        Some(subject_chirho),
        None,
        None,
    )
    .unwrap();
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho: run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap(),
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho: request_chirho.clone(),
        request_private_subject_chirho: Some(subject_chirho.to_string()),
        caller_idempotency_key_digest_chirho: None,
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    for &status_chirho in statuses_chirho {
        append_run_intent_record_chirho(
            root_chirho,
            &admission_chirho,
            RunIntentWriteStatusChirho::CraftedChirho(status_chirho),
            None,
        )
        .unwrap();
    }
}

/// Appends one UNSIGNED line claiming (subject, value hash) with a blob nothing backs — the shape an
/// attacker with append access writes — and proves it landed.
fn forge_unverifiable_claim_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
) {
    let path_chirho = root_chirho.join("private-dag-values-chirho.jsonl");
    let before_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_default();
    let forged_chirho = serde_json::json!({
        "schema_chirho": dag_private_value_chirho::PRIVATE_DAG_VALUE_SCHEMA_CHIRHO,
        "seq_chirho": before_chirho.lines().count(),
        "subject_chirho": subject_chirho,
        "value_hash_chirho": value_hash_chirho.0,
        "blob_chirho": {
            "alg_chirho": "xchacha20poly1305-chirho",
            "key_id_chirho": "forged-key-id-chirho",
            "nonce_chirho": "00".repeat(24),
            "mac_chirho": "00".repeat(32),
            "ciphertext_chirho": cas_chirho::hash_chirho(b"no such one-pass ciphertext chirho").0,
        },
        "bytes_chirho": 0,
        "at_ms_chirho": 0,
        "sig_chirho": "",
    });
    std::fs::write(&path_chirho, format!("{before_chirho}{forged_chirho}\n")).unwrap();
    let after_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    assert_eq!(
        after_chirho.lines().count(),
        before_chirho.lines().count() + 1,
        "the forged line was not appended, so the refusal below would be about an unmutated log"
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoadCountsChirho {
    value_log_loads_chirho: u64,
    record_verifications_chirho: u64,
    /// The blob road: since checkpoint brick S1, ownership resolves from the blob log's verified view.
    blob_chirho: BlobRoadCountsChirho,
    /// The value road: since checkpoint brick S2, claims come from the private-value index.
    value_chirho: ValueRoadCountsChirho,
}

fn reset_load_counts_chirho() {
    PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO.with(|count_chirho| count_chirho.set(0));
    PRIVATE_DAG_VALUE_RECORD_VERIFICATIONS_CHIRHO.with(|count_chirho| count_chirho.set(0));
    private_blob_view_metrics_chirho::reset_chirho();
    value_view_metrics_chirho::reset_chirho();
}

fn load_counts_chirho() -> LoadCountsChirho {
    LoadCountsChirho {
        value_log_loads_chirho: PRIVATE_DAG_VALUE_LOG_LOADS_CHIRHO
            .with(|count_chirho| count_chirho.get()),
        record_verifications_chirho: PRIVATE_DAG_VALUE_RECORD_VERIFICATIONS_CHIRHO
            .with(|count_chirho| count_chirho.get()),
        blob_chirho: private_blob_view_metrics_chirho::counts_chirho(),
        value_chirho: value_view_metrics_chirho::counts_chirho(),
    }
}

/// The warm value road (checkpoint brick S2): no whole-log load through either the index or the old loader, nothing
/// re-folded, `lookups` index lookups, and one claim copied out per lookup: every request here claims its pair once.
fn assert_warm_value_road_chirho(
    counts_chirho: LoadCountsChirho,
    lookups_chirho: u64,
    context_chirho: &str,
) {
    assert_eq!(
        (
            counts_chirho.value_log_loads_chirho,
            counts_chirho.value_chirho.full_log_loads_chirho,
            counts_chirho.value_chirho.records_folded_chirho,
            counts_chirho.value_chirho.lookups_chirho,
            counts_chirho.value_chirho.claims_copied_chirho,
        ),
        (0, 0, 0, lookups_chirho, lookups_chirho),
        "{context_chirho}: a warm value road loads no whole log, re-folds nothing and makes {lookups_chirho} index \
         lookups, copying out one claim each: {counts_chirho:?}"
    );
}

/// The warm blob road of a pass or a call: no whole-log read, nothing re-folded, at least one ownership lookup, and
/// exactly one key file per lookup, never a sweep of every key file (checkpoint brick S1).
fn assert_warm_blob_road_chirho(blob_chirho: BlobRoadCountsChirho, context_chirho: &str) {
    assert_eq!(
        (blob_chirho.full_log_loads_chirho, blob_chirho.records_folded_chirho),
        (0, 0),
        "{context_chirho}: a warm blob road reads no whole log and re-folds nothing: {blob_chirho:?}"
    );
    assert!(
        blob_chirho.lookups_chirho >= 1,
        "{context_chirho}: the fixture stopped reaching blob ownership, so the arm proves nothing: \
         {blob_chirho:?}"
    );
    assert_eq!(
        blob_chirho.key_file_reads_chirho, blob_chirho.lookups_chirho,
        "{context_chirho}: each lookup reads only its own key file: {blob_chirho:?}"
    );
}

/// THE SCALING ARM. With `runs` private-request runs, each carrying a pending AND a running record
/// (so every request is asked about twice in one pass), the pass reads no whole private-value log
/// (claims come from the warm private-value index, one lookup per request), verifies each request's
/// record once, and resolves blob ownership from the blob log's warm view (no whole-log read, one
/// key file per lookup) — at 3 runs and at 30.
///
/// MIGRATION PATH — if the pass loads the whole value log, or makes an index lookup per RECORD
/// instead of per request, the verifier is back on a whole-log or per-record road (checkpoint brick
/// S2 removed it). If blob lookups are 0, the fixture
/// stopped reaching blob ownership, and the arm proves nothing until it does again. If the warm pass
/// reads the whole blob log or reads more key files than it makes lookups, the blob lookup is back
/// on a full-scan road (checkpoint brick S1 removed it).
#[test]
fn one_pass_reads_each_private_log_once_at_any_intent_count_chirho() {
    for runs_chirho in [3_usize, 30] {
        let root_chirho = tmp_root_chirho("scaling");
        let dag_hash_chirho = store_dag_chirho(&root_chirho, "scaling-chirho");
        let mut requests_chirho = Vec::new();
        for run_index_chirho in 0..runs_chirho {
            let request_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
                &root_chirho,
                &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
                    SUBJECT_CHIRHO,
                ),
                SUBJECT_CHIRHO,
                format!("sealed one-pass request {run_index_chirho} chirho").as_bytes(),
                dag_private_value_chirho::PrivateDagValueContextChirho::default(),
            )
            .unwrap();
            append_private_request_run_chirho(
                &root_chirho,
                &dag_hash_chirho,
                &request_chirho,
                SUBJECT_CHIRHO,
                &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
            );
            requests_chirho.push(request_chirho);
        }

        // The blob view is process-wide and current only as of its last call: one uncounted call
        // folds the last store's record, so every blob count below is a WARM count.
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            SUBJECT_CHIRHO,
            &requests_chirho[0],
        )
        .unwrap();
        // INSTRUMENT CONTROL: the counters must SEE a per-call road, or the counts below could come
        // from a blind counter. Two single-pair calls are two index lookups, two verifications and two
        // blob lookups.
        reset_load_counts_chirho();
        for _ in 0..2 {
            assert!(
                dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
                    &root_chirho,
                    SUBJECT_CHIRHO,
                    &requests_chirho[0],
                )
                .unwrap()
                .is_some(),
                "fixture: a sealed request must resolve to a verified record ({runs_chirho} runs)"
            );
        }
        let control_chirho = load_counts_chirho();
        assert_eq!(
            (
                control_chirho.record_verifications_chirho,
                control_chirho.blob_chirho.lookups_chirho,
            ),
            (2, 2),
            "control: two single-pair calls must verify twice and look up blob ownership twice; \
             otherwise the counters are blind or the single-pair door stopped verifying \
             ({runs_chirho} runs): {control_chirho:?}"
        );
        assert_warm_value_road_chirho(control_chirho, 2, &format!("control ({runs_chirho} runs)"));
        assert_warm_blob_road_chirho(
            control_chirho.blob_chirho,
            &format!("control ({runs_chirho} runs)"),
        );

        reset_load_counts_chirho();
        assert_eq!(
            verify_run_intent_records_chirho(&root_chirho).unwrap(),
            runs_chirho * 2,
            "positive control: the pass refused genuinely sealed requests ({runs_chirho} runs)"
        );
        let pass_chirho = load_counts_chirho();
        assert_eq!(
            pass_chirho.record_verifications_chirho,
            runs_chirho as u64,
            "one pass over {} private-request records must verify each request ONCE ({runs_chirho} \
             runs): {pass_chirho:?}",
            runs_chirho * 2
        );
        assert_warm_value_road_chirho(
            pass_chirho,
            runs_chirho as u64,
            &format!("pass ({runs_chirho} runs)"),
        );
        assert_warm_blob_road_chirho(
            pass_chirho.blob_chirho,
            &format!("pass ({runs_chirho} runs)"),
        );

        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// A request that VERIFIED earlier in the pass must not lend its verdict to a different request: a
/// later request claimed only by an unverifiable line still refuses, by the verification refusal's
/// own identity, naming its own hash.
#[test]
fn one_pass_does_not_carry_a_verified_request_to_a_broken_one_chirho() {
    let root_chirho = tmp_root_chirho("carry");
    let dag_hash_chirho = store_dag_chirho(&root_chirho, "carry-chirho");
    let sealed_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            SUBJECT_CHIRHO,
        ),
        SUBJECT_CHIRHO,
        b"sealed one-pass request that verifies chirho",
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    append_private_request_run_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &sealed_chirho,
        SUBJECT_CHIRHO,
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    let forged_chirho =
        cas_chirho::hash_chirho(b"a one-pass request only a forged line claims chirho");
    forge_unverifiable_claim_chirho(&root_chirho, SUBJECT_CHIRHO, &forged_chirho);
    append_private_request_run_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &forged_chirho,
        SUBJECT_CHIRHO,
        &[RUN_INTENT_PENDING_CHIRHO],
    );

    let text_chirho = format!(
        "{:#}",
        verify_run_intent_records_chirho(&root_chirho).expect_err(
            "a verified request lent its verdict to a request only a forged line claims"
        )
    );
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the broken request must refuse by record verification: {text_chirho}"
    );
    assert!(
        text_chirho.contains(&forged_chirho.0) && !text_chirho.contains(&sealed_chirho.0),
        "the refusal must name the BROKEN request, not the one that verified: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// The pass remembers verified (subject, hash) PAIRS, never bare hashes: bytes sealed to one subject
/// must not satisfy the same request asked for under a subject that nothing claims it for.
#[test]
fn one_pass_keys_a_verified_request_by_subject_as_well_as_hash_chirho() {
    let root_chirho = tmp_root_chirho("subject-key");
    let dag_hash_chirho = store_dag_chirho(&root_chirho, "subject-key-chirho");
    // An un-keyed run's identity does not include its private subject, so the other subject's run
    // gets its own DAG: record 2 must be a fresh run that only the private check can refuse.
    let other_dag_hash_chirho = store_dag_chirho(&root_chirho, "other-subject-chirho");
    let request_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            SUBJECT_CHIRHO,
        ),
        SUBJECT_CHIRHO,
        b"one-pass request sealed to one subject only chirho",
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    append_private_request_run_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        SUBJECT_CHIRHO,
        &[RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO],
    );
    append_private_request_run_chirho(
        &root_chirho,
        &other_dag_hash_chirho,
        &request_chirho,
        OTHER_SUBJECT_CHIRHO,
        &[RUN_INTENT_PENDING_CHIRHO],
    );
    // Read off the RAW log, not through the resolver under test: a resolver keyed by hash alone
    // would otherwise trip THIS fixture check, and the arm would go red with a fixture message
    // instead of at the refusal it exists to pin.
    assert!(
        !dag_private_value_chirho::load_private_dag_value_records_chirho(&root_chirho)
            .unwrap()
            .iter()
            .any(|record_chirho| record_chirho.subject_chirho == OTHER_SUBJECT_CHIRHO),
        "fixture: no private-value line may name the other subject"
    );

    let text_chirho = format!(
        "{:#}",
        verify_run_intent_records_chirho(&root_chirho)
            .expect_err("bytes sealed to one subject satisfied a request under another subject")
    );
    assert!(
        text_chirho.contains("run intent record 2 private request value")
            && text_chirho.contains("missing"),
        "the other subject's request must refuse as ABSENT at its own record: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("claimed only by records that do not verify"),
        "nothing claims the other subject's pair, so it must not refuse as a broken claim: \
         {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
