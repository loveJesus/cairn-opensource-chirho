// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Checkpoint brick S3, the run-intent admission view: its decisions equal the whole-log pass's (a randomized oracle);
//! its one ruled difference, option (a)'s window for an UNRELATED run's tampered key, is closed by the integrity pass
//! while the run being admitted is always re-verified fresh (agy #25851); and the store rule, the fold's own refusals
//! and the startup resume's single fold hold.

use super::admission_view_chirho::{
    now_ms_chirho as view_now_ms_chirho, run_intent_view_rules_chirho, with_index_rules_chirho,
};
use super::run_intent_view_metrics_chirho as run_intent_road_chirho;
use super::*;
use crate::dag_private_value_chirho::{self, PrivateDagValueContextChirho};
use cairn_verified_prefix_view_chirho::ViewRulesChirho;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ALICE_CHIRHO: &str = "user/s3-admission-alice-chirho";
const BOB_CHIRHO: &str = "user/s3-admission-bob-chirho";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-s3-admission-view-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

/// A stored DAG; distinct labels give distinct DAG hashes, hence distinct run identities. Its node is not stored, so
/// running it fails: the resume arm uses that to record a terminal for every run it resumes.
fn store_dag_chirho(root_chirho: &Path, label_chirho: &str) -> HashChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: vec![HashChirho(format!("node-s3-admission-{label_chirho}"))],
        edges_chirho: vec![],
    };
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

/// A private request value, stored the way the runtime stores one, so its record verifies.
fn store_private_request_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    bytes_chirho: &[u8],
) -> HashChirho {
    dag_private_value_chirho::store_private_dag_value_chirho(
        root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            subject_chirho,
        ),
        subject_chirho,
        bytes_chirho,
        PrivateDagValueContextChirho::default(),
    )
    .unwrap()
}

/// An admission built with the runtime's own hash helpers.
fn admission_chirho(
    root_chirho: &Path,
    dag_chirho: &HashChirho,
    request_chirho: &HashChirho,
    subject_chirho: Option<&str>,
    caller_key_chirho: Option<&HashChirho>,
) -> RunIntentAdmissionChirho {
    let scope_chirho = run_intent_scope_chirho(root_chirho, None).unwrap();
    let idempotency_context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        dag_chirho,
        request_chirho,
        &scope_chirho,
        subject_chirho,
        caller_key_chirho,
        None,
    )
    .unwrap();
    RunIntentAdmissionChirho {
        run_chirho: run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap(),
        dag_chirho: dag_chirho.clone(),
        request_chirho: request_chirho.clone(),
        request_private_subject_chirho: subject_chirho.map(str::to_string),
        caller_idempotency_key_digest_chirho: caller_key_chirho.cloned(),
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    }
}

fn append_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
    status_chirho: &'static str,
) {
    let error_chirho = matches!(
        status_chirho,
        RUN_INTENT_FAILED_CHIRHO | RUN_INTENT_ABORTED_CHIRHO
    )
    .then(|| {
        (
            "DagPreEffectRefusedChirho",
            cas_chirho::hash_chirho(b"s3 oracle failure chirho"),
        )
    });
    append_run_intent_record_chirho(
        root_chirho,
        admission_chirho,
        RunIntentWriteStatusChirho::CraftedChirho(status_chirho),
        error_chirho,
    )
    .unwrap();
}

/// THE REFERENCE: the admission as it was before S3, the whole log verified and loaded on every call (verbatim).
fn whole_log_admission_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
) -> Result<Option<RunIntentRecordChirho>> {
    seqlog_chirho::with_append_log_lock_chirho(root_chirho, || {
        verify_run_intent_records_chirho(root_chirho)?;
        let records_chirho = load_run_intent_records_chirho(root_chirho)?;
        if let Some(caller_key_digest_chirho) =
            &admission_chirho.caller_idempotency_key_digest_chirho
        {
            for record_chirho in &records_chirho {
                if record_chirho.caller_idempotency_key_digest_chirho.as_ref()
                    == Some(caller_key_digest_chirho)
                    && record_chirho.idempotency_context_hash_chirho
                        != admission_chirho.idempotency_context_hash_chirho
                {
                    bail!(
                        "RelayCallerKeyCollisionChirho: caller idempotency key is already bound to different request evidence"
                    );
                }
            }
        }
        Ok(records_chirho
            .into_iter()
            .rev()
            .find(|record_chirho| record_chirho.run_chirho == admission_chirho.run_chirho))
    })
}

fn view_admission_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
) -> Result<Option<RunIntentRecordChirho>, String> {
    latest_verified_run_intent_record_for_admission_chirho(root_chirho, admission_chirho)
        .map_err(|error_chirho| format!("{error_chirho:#}"))
}

fn whole_admission_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
) -> Result<Option<RunIntentRecordChirho>, String> {
    whole_log_admission_chirho(root_chirho, admission_chirho)
        .map_err(|error_chirho| format!("{error_chirho:#}"))
}

/// A small deterministic generator, so a failing seed replays exactly.
struct XorshiftChirho(u64);

impl XorshiftChirho {
    fn below_chirho(&mut self, bound_chirho: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 % bound_chirho as u64) as usize
    }
}

/// THE ORACLE (agy #25851 item 3). Five seeds of sixty admissions over two DAGs, public and private requests, two
/// subjects and two caller keys (so keys collide across contexts), each run advanced as the runtime would, with a
/// random stop that leaves it PENDING or RUNNING as a crash would, and terminals both DONE and FAILED. At every step
/// the view's decision, the record it returns or its refusal, equals the whole-log pass's. And per seed the view reads
/// the whole log ONCE, on its first build: every later admission folds only the delta.
///
/// MIGRATION PATH: a differing decision names its seed and step; replay that seed. A second whole-log read means the
/// view is rebuilt on a road that should be incremental.
#[test]
fn the_view_admits_exactly_as_the_whole_log_pass_chirho() {
    // The oracle's own positive control: which decisions it actually exercised, across all seeds.
    let (mut fresh_chirho, mut existing_chirho, mut collisions_chirho, mut aborted_chirho) =
        (0_usize, 0_usize, 0_usize, 0_usize);
    for seed_chirho in [1_u64, 7, 42, 1234, 99_991] {
        let root_chirho = tmp_root_chirho(&format!("oracle-{seed_chirho}"));
        let dags_chirho = [
            store_dag_chirho(&root_chirho, "oracle-a"),
            store_dag_chirho(&root_chirho, "oracle-b"),
        ];
        let requests_chirho: Vec<(HashChirho, Option<&str>)> = vec![
            (
                cas_chirho::add_chirho(&root_chirho, b"s3 oracle public one").unwrap(),
                None,
            ),
            (
                cas_chirho::add_chirho(&root_chirho, b"s3 oracle public two").unwrap(),
                None,
            ),
            (
                store_private_request_chirho(&root_chirho, ALICE_CHIRHO, b"s3 oracle private"),
                Some(ALICE_CHIRHO),
            ),
            (
                store_private_request_chirho(&root_chirho, BOB_CHIRHO, b"s3 oracle private"),
                Some(BOB_CHIRHO),
            ),
        ];
        let keys_chirho = [
            cas_chirho::hash_chirho(b"s3 oracle caller key one"),
            cas_chirho::hash_chirho(b"s3 oracle caller key two"),
        ];
        let mut candidates_chirho = Vec::new();
        for dag_chirho in &dags_chirho {
            for (request_chirho, subject_chirho) in &requests_chirho {
                for key_chirho in [None, Some(&keys_chirho[0]), Some(&keys_chirho[1])] {
                    candidates_chirho.push(admission_chirho(
                        &root_chirho,
                        dag_chirho,
                        request_chirho,
                        *subject_chirho,
                        key_chirho,
                    ));
                }
            }
        }
        let mut random_chirho = XorshiftChirho(seed_chirho.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        run_intent_road_chirho::reset_chirho();
        for step_chirho in 0..60 {
            let candidate_chirho =
                &candidates_chirho[random_chirho.below_chirho(candidates_chirho.len())];
            let view_chirho = view_admission_chirho(&root_chirho, candidate_chirho);
            let whole_chirho = whole_admission_chirho(&root_chirho, candidate_chirho);
            assert_eq!(
                view_chirho, whole_chirho,
                "seed {seed_chirho} step {step_chirho}: the view must decide as the whole-log pass"
            );
            match &view_chirho {
                Ok(None) => fresh_chirho += 1,
                Ok(Some(_)) => existing_chirho += 1,
                Err(refusal_chirho) if refusal_chirho.contains("RelayCallerKeyCollisionChirho") => {
                    collisions_chirho += 1
                }
                Err(refusal_chirho) => panic!(
                    "seed {seed_chirho} step {step_chirho}: an oracle with no faults refuses only collisions: \
                     {refusal_chirho}"
                ),
            }
            if matches!(&view_chirho, Ok(Some(latest_chirho)) if latest_chirho.status_chirho == RUN_INTENT_ABORTED_CHIRHO)
            {
                aborted_chirho += 1;
            }
            // Advance the run as the runtime would; `stop` models a crash after any record. A run may end ABORTED
            // (crafted: this release never writes it, agy #25907), and an aborted run's retry runs it again.
            let stop_chirho = random_chirho.below_chirho(4);
            let terminal_chirho = match random_chirho.below_chirho(4) {
                0 => RUN_INTENT_FAILED_CHIRHO,
                1 => RUN_INTENT_ABORTED_CHIRHO,
                _ => RUN_INTENT_DONE_CHIRHO,
            };
            let next_chirho: &[&'static str] = match &view_chirho {
                Ok(None) => &[
                    RUN_INTENT_PENDING_CHIRHO,
                    RUN_INTENT_RUNNING_CHIRHO,
                    "terminal",
                ],
                Ok(Some(latest_chirho))
                    if latest_chirho.status_chirho == RUN_INTENT_PENDING_CHIRHO
                        || latest_chirho.status_chirho == RUN_INTENT_ABORTED_CHIRHO =>
                {
                    &[RUN_INTENT_RUNNING_CHIRHO, "terminal"]
                }
                Ok(Some(latest_chirho))
                    if latest_chirho.status_chirho == RUN_INTENT_RUNNING_CHIRHO =>
                {
                    &["terminal"]
                }
                _ => &[],
            };
            for status_chirho in next_chirho.iter().take(stop_chirho.max(1)) {
                let status_chirho: &'static str = if *status_chirho == "terminal" {
                    terminal_chirho
                } else {
                    status_chirho
                };
                append_chirho(&root_chirho, candidate_chirho, status_chirho);
            }
        }
        let counts_chirho = run_intent_road_chirho::counts_chirho();
        assert_eq!(
            counts_chirho.full_log_loads_chirho, 1,
            "seed {seed_chirho}: the view reads the whole log once, on its first build: {counts_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
    assert!(
        fresh_chirho > 0 && existing_chirho > 0 && collisions_chirho > 0 && aborted_chirho > 0,
        "the oracle exercised fresh runs ({fresh_chirho}), existing runs ({existing_chirho}), caller-key \
         collisions ({collisions_chirho}) and aborted runs ({aborted_chirho}); a zero means a decision it never \
         compared"
    );
}

fn key_file_path_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    request_chirho: &HashChirho,
) -> PathBuf {
    let record_chirho =
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            root_chirho,
            subject_chirho,
            request_chirho,
        )
        .unwrap()
        .expect("the private request is stored");
    root_chirho
        .join("privacy-keys-chirho")
        .join(format!("{}.json", record_chirho.blob_chirho.key_id_chirho))
}

/// A key file rewritten to name another subject: the tamper the blob view's own window arm uses.
fn tamper_key_chirho(path_chirho: &Path) -> Vec<u8> {
    let original_chirho = std::fs::read(path_chirho).unwrap();
    let tampered_chirho = serde_json::json!({
        "subject_chirho": "user/s3-admission-intruder-chirho",
        "key_hex_chirho": "00".repeat(32),
    });
    std::fs::write(
        path_chirho,
        serde_json::to_vec_pretty(&tampered_chirho).unwrap(),
    )
    .unwrap();
    assert_ne!(
        std::fs::read(path_chirho).unwrap(),
        original_chirho,
        "the tamper landed"
    );
    original_chirho
}

/// Two private runs, done, and the view warm on both.
fn two_done_private_runs_chirho(
    label_chirho: &str,
) -> (PathBuf, RunIntentAdmissionChirho, RunIntentAdmissionChirho) {
    let root_chirho = tmp_root_chirho(label_chirho);
    let dag_chirho = store_dag_chirho(&root_chirho, label_chirho);
    let alice_request_chirho =
        store_private_request_chirho(&root_chirho, ALICE_CHIRHO, b"alice's request");
    let bob_request_chirho =
        store_private_request_chirho(&root_chirho, BOB_CHIRHO, b"bob's request");
    let alice_chirho = admission_chirho(
        &root_chirho,
        &dag_chirho,
        &alice_request_chirho,
        Some(ALICE_CHIRHO),
        None,
    );
    let bob_chirho = admission_chirho(
        &root_chirho,
        &dag_chirho,
        &bob_request_chirho,
        Some(BOB_CHIRHO),
        None,
    );
    for admission_chirho in [&alice_chirho, &bob_chirho] {
        for status_chirho in [
            RUN_INTENT_PENDING_CHIRHO,
            RUN_INTENT_RUNNING_CHIRHO,
            RUN_INTENT_DONE_CHIRHO,
        ] {
            append_chirho(&root_chirho, admission_chirho, status_chirho);
        }
    }
    for admission_chirho in [&alice_chirho, &bob_chirho] {
        assert_eq!(
            view_admission_chirho(&root_chirho, admission_chirho)
                .unwrap()
                .map(|latest_chirho| latest_chirho.status_chirho),
            Some(RUN_INTENT_DONE_CHIRHO.to_string())
        );
    }
    (root_chirho, alice_chirho, bob_chirho)
}

/// agy's tamper arm (1), THE WINDOW AND ITS CLOSE. An UNRELATED run's key file tampered after its record was folded
/// is option (a)'s one difference: the whole-log pass refuses every admission at once, while the view still admits the
/// other run. The integrity pass (made due at once here) re-folds the whole log, meets the tamper, and drops the view;
/// every admission then refuses, the untampered run included, until the key file is repaired.
///
/// The window has a second, earlier close this arm keeps out of its way: ANY lookup that meets the tampered key, the
/// whole-log pass's included, makes the blob view (S1) drop and refuse root-wide. So the whole-log control runs on a
/// second root of the same shape, and nothing on the view's root touches the tampered key before the pass does.
///
/// MIGRATION PATH: if the poll times out, the integrity pass no longer re-verifies request values (the fold lost the
/// per-record checks) or no longer runs, and the window is bounded only by the next lookup that meets the key.
#[test]
fn an_unrelated_runs_tampered_key_is_closed_by_the_integrity_pass_chirho() {
    let (control_root_chirho, control_alice_chirho, control_bob_chirho) =
        two_done_private_runs_chirho("window-control");
    tamper_key_chirho(&key_file_path_chirho(
        &control_root_chirho,
        ALICE_CHIRHO,
        &control_alice_chirho.request_chirho,
    ));
    let whole_chirho =
        whole_admission_chirho(&control_root_chirho, &control_bob_chirho).unwrap_err();
    assert!(
        whole_chirho.contains("intruder"),
        "control: the whole-log pass refuses the unrelated run at once: {whole_chirho}"
    );
    let _ = std::fs::remove_dir_all(&control_root_chirho);

    let (root_chirho, alice_chirho, bob_chirho) = two_done_private_runs_chirho("window");
    let alice_key_chirho =
        key_file_path_chirho(&root_chirho, ALICE_CHIRHO, &alice_chirho.request_chirho);
    let original_chirho = tamper_key_chirho(&alice_key_chirho);
    assert_eq!(
        view_admission_chirho(&root_chirho, &bob_chirho)
            .unwrap()
            .map(|latest_chirho| latest_chirho.status_chirho),
        Some(RUN_INTENT_DONE_CHIRHO.to_string()),
        "inside the window, the view still admits the unrelated run (option (a))"
    );

    let due_now_chirho = ViewRulesChirho {
        full_verify_every_ms_chirho: 0,
        ..run_intent_view_rules_chirho()
    };
    let deadline_chirho = Instant::now() + Duration::from_secs(30);
    let pass_refusal_chirho = loop {
        match with_index_rules_chirho(&root_chirho, &due_now_chirho, view_now_ms_chirho, |_| ()) {
            Err(error_chirho) => break format!("{error_chirho:#}"),
            Ok(_) => {
                assert!(
                    Instant::now() < deadline_chirho,
                    "the integrity pass never closed the window within 30 s"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    };
    assert!(
        pass_refusal_chirho.contains("intruder"),
        "{pass_refusal_chirho}"
    );
    let refused_chirho = view_admission_chirho(&root_chirho, &bob_chirho).unwrap_err();
    assert!(
        refused_chirho.contains("intruder"),
        "after the pass, every admission refuses, the untampered run included: {refused_chirho}"
    );

    std::fs::write(&alice_key_chirho, original_chirho).unwrap();
    assert_eq!(
        view_admission_chirho(&root_chirho, &bob_chirho)
            .unwrap()
            .map(|latest_chirho| latest_chirho.status_chirho),
        Some(RUN_INTENT_DONE_CHIRHO.to_string()),
        "once the key is repaired, the rebuilt view admits again"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// agy's tamper arm (2): the run being ADMITTED, the only one whose effect can run, is re-verified fresh, so its own
/// tampered key refuses at once, with no integrity pass and no whole-log read, as the whole-log pass refuses.
///
/// MIGRATION PATH: an admission that succeeds here means the admitted run is decided from its folded verdict: the
/// fresh re-verify is gone.
#[test]
fn the_admitted_runs_own_tampered_key_refuses_at_once_chirho() {
    let (root_chirho, alice_chirho, _bob_chirho) = two_done_private_runs_chirho("own-key");
    let alice_key_chirho =
        key_file_path_chirho(&root_chirho, ALICE_CHIRHO, &alice_chirho.request_chirho);
    tamper_key_chirho(&alice_key_chirho);
    run_intent_road_chirho::reset_chirho();
    let refused_chirho = view_admission_chirho(&root_chirho, &alice_chirho).unwrap_err();
    let counts_chirho = run_intent_road_chirho::counts_chirho();
    assert!(refused_chirho.contains("intruder"), "{refused_chirho}");
    assert_eq!(
        (
            counts_chirho.full_log_loads_chirho,
            counts_chirho.fresh_reverifies_chirho
        ),
        (0, 1),
        "refused by the fresh re-verify alone: {counts_chirho:?}"
    );
    assert!(whole_admission_chirho(&root_chirho, &alice_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

fn log_bytes_chirho(root_chirho: &Path) -> Vec<u8> {
    std::fs::read(run_intent_records_path_chirho(root_chirho)).unwrap()
}

fn append_raw_chirho(root_chirho: &Path, bytes_chirho: &[u8]) {
    use std::io::Write;
    let before_chirho = log_bytes_chirho(root_chirho).len();
    std::fs::OpenOptions::new()
        .append(true)
        .open(run_intent_records_path_chirho(root_chirho))
        .unwrap()
        .write_all(bytes_chirho)
        .unwrap();
    assert_eq!(
        log_bytes_chirho(root_chirho).len(),
        before_chirho + bytes_chirho.len(),
        "the raw bytes landed"
    );
}

/// THE STORE RULE (S1's): a complete line that does not parse refuses admissions AND appends, and stays in the log,
/// where an append's recovery would otherwise have quarantined it as a bad suffix.
///
/// MIGRATION PATH: an append that succeeds, or a log that changed, means appends no longer bring the view current
/// before the seqlog's recovery.
#[test]
fn a_complete_bad_line_refuses_admissions_and_appends_and_stays_chirho() {
    let (root_chirho, alice_chirho, bob_chirho) = two_done_private_runs_chirho("bad-line");
    append_raw_chirho(&root_chirho, b"not a run intent record\n");
    let before_chirho = log_bytes_chirho(&root_chirho);
    let refused_chirho = view_admission_chirho(&root_chirho, &bob_chirho).unwrap_err();
    assert!(
        refused_chirho.contains("decode run intent record"),
        "{refused_chirho}"
    );
    assert!(whole_admission_chirho(&root_chirho, &bob_chirho).is_err());
    let dag_chirho = store_dag_chirho(&root_chirho, "bad-line-new");
    let new_chirho = admission_chirho(
        &root_chirho,
        &dag_chirho,
        &alice_chirho.request_chirho,
        Some(ALICE_CHIRHO),
        None,
    );
    assert!(
        append_run_intent_record_chirho(
            &root_chirho,
            &new_chirho,
            RunIntentWriteStatusChirho::PendingChirho,
            None
        )
        .is_err(),
        "an append refuses exactly when an admission would"
    );
    assert_eq!(
        log_bytes_chirho(&root_chirho),
        before_chirho,
        "the bad line stays in the log"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A final line without its newline that does not parse is waited out (a write in flight, or a torn tail), and the
/// next append's recovery repairs it, so the run's next record lands and both readers agree.
#[test]
fn a_torn_tail_is_waited_out_then_repaired_by_the_next_append_chirho() {
    let root_chirho = tmp_root_chirho("torn-tail");
    let dag_chirho = store_dag_chirho(&root_chirho, "torn-tail");
    let request_chirho = cas_chirho::add_chirho(&root_chirho, b"s3 torn tail request").unwrap();
    let run_chirho = admission_chirho(&root_chirho, &dag_chirho, &request_chirho, None, None);
    append_chirho(&root_chirho, &run_chirho, RUN_INTENT_PENDING_CHIRHO);
    append_chirho(&root_chirho, &run_chirho, RUN_INTENT_RUNNING_CHIRHO);
    append_raw_chirho(&root_chirho, br#"{"schema_chirho":"run-intent-rec"#);
    assert_eq!(
        view_admission_chirho(&root_chirho, &run_chirho)
            .unwrap()
            .map(|latest_chirho| latest_chirho.status_chirho),
        Some(RUN_INTENT_RUNNING_CHIRHO.to_string()),
        "the torn tail is waited out"
    );
    append_chirho(&root_chirho, &run_chirho, RUN_INTENT_DONE_CHIRHO);
    let expected_chirho = Ok(Some(RUN_INTENT_DONE_CHIRHO.to_string()));
    for (reader_chirho, decision_chirho) in [
        ("view", view_admission_chirho(&root_chirho, &run_chirho)),
        (
            "whole log",
            whole_admission_chirho(&root_chirho, &run_chirho),
        ),
    ] {
        assert_eq!(
            decision_chirho.map(|latest_chirho| latest_chirho.map(|record_chirho| record_chirho.status_chirho)),
            expected_chirho,
            "{reader_chirho}: the repaired log ends with the run's DONE"
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// A NEW record that does not verify refuses the next admission of ANY run, the unrelated ones included: the fold
/// verifies every record it meets. (Option (a)'s window is only for records already folded.)
///
/// MIGRATION PATH: an admission that succeeds means the fold no longer runs the per-record checks.
#[test]
fn a_new_record_that_does_not_verify_refuses_every_admission_chirho() {
    let (root_chirho, alice_chirho, bob_chirho) = two_done_private_runs_chirho("forged");
    let text_chirho = String::from_utf8(log_bytes_chirho(&root_chirho)).unwrap();
    let mut forged_chirho: serde_json::Value =
        serde_json::from_str(text_chirho.lines().last().unwrap()).unwrap();
    forged_chirho["seq_chirho"] = serde_json::Value::from(text_chirho.lines().count());
    forged_chirho["status_chirho"] = serde_json::Value::from(RUN_INTENT_DONE_CHIRHO);
    append_raw_chirho(&root_chirho, format!("{forged_chirho}\n").as_bytes());
    let refused_chirho = view_admission_chirho(&root_chirho, &alice_chirho).unwrap_err();
    assert!(
        refused_chirho.contains("signature invalid"),
        "{refused_chirho}"
    );
    assert_eq!(
        whole_admission_chirho(&root_chirho, &alice_chirho).unwrap_err(),
        refused_chirho,
        "the whole-log pass refuses with the same message"
    );
    assert!(view_admission_chirho(&root_chirho, &bob_chirho).is_err());
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// An illegal transition, signed and appended through the production door, refuses at the fold: PENDING straight to
/// DONE. The whole-log pass refuses with the same message.
///
/// MIGRATION PATH: an admission that succeeds means the fold no longer checks transitions against its run map.
#[test]
fn an_illegal_transition_refuses_at_the_fold_chirho() {
    let root_chirho = tmp_root_chirho("transition");
    let dag_chirho = store_dag_chirho(&root_chirho, "transition");
    let request_chirho = cas_chirho::add_chirho(&root_chirho, b"s3 transition request").unwrap();
    let run_chirho = admission_chirho(&root_chirho, &dag_chirho, &request_chirho, None, None);
    append_chirho(&root_chirho, &run_chirho, RUN_INTENT_PENDING_CHIRHO);
    append_chirho(&root_chirho, &run_chirho, RUN_INTENT_DONE_CHIRHO);
    let refused_chirho = view_admission_chirho(&root_chirho, &run_chirho).unwrap_err();
    assert!(
        refused_chirho.contains("invalid transition to done-chirho"),
        "{refused_chirho}"
    );
    assert_eq!(
        whole_admission_chirho(&root_chirho, &run_chirho).unwrap_err(),
        refused_chirho
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE STARTUP RESUME: one whole-log read however many runs are unfinished, then one fresh re-verify per unfinished
/// run. It was one whole-log verify and load, plus one more per unfinished run.
///
/// MIGRATION PATH: a whole-log read count that grows with the unfinished runs means resume verifies the history per run
/// again.
#[test]
fn the_startup_resume_reads_the_whole_log_once_chirho() {
    for unfinished_chirho in [2_usize, 6] {
        let root_chirho = tmp_root_chirho(&format!("resume-{unfinished_chirho}"));
        let dag_chirho = store_dag_chirho(&root_chirho, "resume");
        for index_chirho in 0..unfinished_chirho + 3 {
            let request_chirho = cas_chirho::add_chirho(
                &root_chirho,
                format!("s3 resume request {index_chirho}").as_bytes(),
            )
            .unwrap();
            let run_chirho =
                admission_chirho(&root_chirho, &dag_chirho, &request_chirho, None, None);
            append_chirho(&root_chirho, &run_chirho, RUN_INTENT_PENDING_CHIRHO);
            if index_chirho >= unfinished_chirho {
                append_chirho(&root_chirho, &run_chirho, RUN_INTENT_RUNNING_CHIRHO);
                append_chirho(&root_chirho, &run_chirho, RUN_INTENT_DONE_CHIRHO);
            }
        }
        // A restart: a new inode, so the view verifies the whole log again on its first read, as a new process would.
        let path_chirho = run_intent_records_path_chirho(&root_chirho);
        let bytes_chirho = std::fs::read(&path_chirho).unwrap();
        let swap_chirho = path_chirho.with_extension("swap-chirho");
        std::fs::write(&swap_chirho, &bytes_chirho).unwrap();
        std::fs::rename(&swap_chirho, &path_chirho).unwrap();

        run_intent_road_chirho::reset_chirho();
        let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
        let counts_chirho = run_intent_road_chirho::counts_chirho();
        assert_eq!(report_chirho.unfinished_chirho, unfinished_chirho);
        assert_eq!(
            (counts_chirho.full_log_loads_chirho, counts_chirho.fresh_reverifies_chirho),
            (1, unfinished_chirho as u64),
            "{unfinished_chirho} unfinished: one whole-log read, one fresh re-verify per unfinished run: {counts_chirho:?}"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}
