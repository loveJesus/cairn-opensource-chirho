// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! THE READER BRICK (agy #25907): this release reads `aborted-chirho` and never writes it. An aborted run is reached
//! only from RUNNING and left only to RUNNING; it carries its error fields; startup recovery leaves it alone; and its
//! identical retry runs it again in RESUME mode, so an effect it did complete is replayed, never run twice. Every
//! ABORTED record here is crafted through the test-only `CraftedChirho` door, the only way this release can write one.

use super::*;

const PENDING_CHIRHO: &str = RUN_INTENT_PENDING_CHIRHO;
const RUNNING_CHIRHO: &str = RUN_INTENT_RUNNING_CHIRHO;
const DONE_CHIRHO: &str = RUN_INTENT_DONE_CHIRHO;
const FAILED_CHIRHO: &str = RUN_INTENT_FAILED_CHIRHO;
const ABORTED_CHIRHO: &str = RUN_INTENT_ABORTED_CHIRHO;
const REQUEST_CHIRHO: &[u8] = b"aborted reader arm request chirho";

/// A stored DAG whose one node does not exist, so a run of it refuses before any side effect, and its public
/// admission for `REQUEST_CHIRHO`, with nothing appended yet.
fn aborted_arm_admission_chirho(root_chirho: &Path) -> RunIntentAdmissionChirho {
    let dag_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![HashChirho("node-aborted-reader-arm-chirho".to_string())],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    append_intent_statuses_chirho(root_chirho, &dag_hash_chirho, REQUEST_CHIRHO, None, &[])
}

/// Appends `statuses_chirho`, in order, for one run through the append door, crafted; FAILED and ABORTED records carry
/// their error fields, as the runtime's do.
fn append_crafted_chirho(
    root_chirho: &Path,
    admission_chirho: &RunIntentAdmissionChirho,
    statuses_chirho: &[&'static str],
) {
    for &status_chirho in statuses_chirho {
        let error_chirho = matches!(status_chirho, FAILED_CHIRHO | ABORTED_CHIRHO).then(|| {
            (
                DagExecutionRefusalIdentityChirho::DagPreEffectRefusedChirho.as_str_chirho(),
                cas_chirho::hash_chirho(b"aborted reader arm refusal chirho"),
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
}

/// Both readers' verdicts on a fresh root's log: the operator verifier's record count, and the admission view's latest
/// status for the run (the view folds the whole log here, its first build).
type VerdictsChirho = (Result<usize, String>, Result<Option<String>, String>);

fn verdicts_chirho(root_chirho: &Path, run_chirho: &HashChirho) -> VerdictsChirho {
    let operator_chirho = verify_run_intent_records_chirho(root_chirho)
        .map_err(|error_chirho| format!("{error_chirho:#}"));
    let view_chirho = admission_view_chirho::latest_record_for_run_chirho(root_chirho, run_chirho)
        .map(|latest_chirho| latest_chirho.map(|record_chirho| record_chirho.status_chirho))
        .map_err(|error_chirho| format!("{error_chirho:#}"));
    (operator_chirho, view_chirho)
}

fn statuses_chirho(root_chirho: &Path) -> Vec<String> {
    load_run_intent_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .map(|record_chirho| record_chirho.status_chirho)
        .collect()
}

/// Only a running run may abort, and an aborted run may only run again. Every other way into or out of ABORTED is
/// refused by the operator verifier AND by the admission view, for its transition and not for anything else.
///
/// MIGRATION PATH: an allowed order refused means this reader no longer folds a log the writer brick will write, so a
/// rollback onto it would refuse every admission; a refused order verifying means a status order the runtime never
/// produces now passes as a valid history.
#[test]
fn only_a_running_run_may_abort_and_an_aborted_run_may_only_run_again_chirho() {
    let allowed_chirho: [&[&'static str]; 4] = [
        &[PENDING_CHIRHO, RUNNING_CHIRHO, ABORTED_CHIRHO],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            RUNNING_CHIRHO,
        ],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            RUNNING_CHIRHO,
            DONE_CHIRHO,
        ],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
        ],
    ];
    for statuses_chirho in allowed_chirho {
        let root_chirho = tmp_root_chirho();
        let admission_chirho = aborted_arm_admission_chirho(&root_chirho);
        append_crafted_chirho(&root_chirho, &admission_chirho, statuses_chirho);
        assert_eq!(
            verdicts_chirho(&root_chirho, &admission_chirho.run_chirho),
            (
                Ok(statuses_chirho.len()),
                Ok(Some(statuses_chirho[statuses_chirho.len() - 1].to_string()))
            ),
            "{statuses_chirho:?} is a history the writer brick will write"
        );
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
    let refused_chirho: [&[&'static str]; 8] = [
        &[ABORTED_CHIRHO],
        &[PENDING_CHIRHO, ABORTED_CHIRHO],
        &[PENDING_CHIRHO, RUNNING_CHIRHO, DONE_CHIRHO, ABORTED_CHIRHO],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            FAILED_CHIRHO,
            ABORTED_CHIRHO,
        ],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            ABORTED_CHIRHO,
        ],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            PENDING_CHIRHO,
        ],
        &[PENDING_CHIRHO, RUNNING_CHIRHO, ABORTED_CHIRHO, DONE_CHIRHO],
        &[
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            FAILED_CHIRHO,
        ],
    ];
    for statuses_chirho in refused_chirho {
        let root_chirho = tmp_root_chirho();
        let admission_chirho = aborted_arm_admission_chirho(&root_chirho);
        append_crafted_chirho(&root_chirho, &admission_chirho, statuses_chirho);
        let (operator_chirho, view_chirho) =
            verdicts_chirho(&root_chirho, &admission_chirho.run_chirho);
        for (reader_chirho, verdict_chirho) in [
            ("operator verifier", operator_chirho.err()),
            ("admission view", view_chirho.err()),
        ] {
            let refusal_chirho = verdict_chirho
                .unwrap_or_else(|| panic!("the {reader_chirho} must refuse {statuses_chirho:?}"));
            assert!(
                refusal_chirho.contains("invalid transition"),
                "the {reader_chirho} refuses {statuses_chirho:?} for its transition: {refusal_chirho}"
            );
        }
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

/// An aborted record records why it refused: without its error fields it is refused, by the operator verifier and the
/// view alike; the same history with them verifies (the positive control).
#[test]
fn an_aborted_record_must_carry_its_error_fields_chirho() {
    let root_chirho = tmp_root_chirho();
    let admission_chirho = aborted_arm_admission_chirho(&root_chirho);
    append_crafted_chirho(
        &root_chirho,
        &admission_chirho,
        &[PENDING_CHIRHO, RUNNING_CHIRHO],
    );
    append_run_intent_record_chirho(
        &root_chirho,
        &admission_chirho,
        RunIntentWriteStatusChirho::CraftedChirho(ABORTED_CHIRHO),
        None,
    )
    .unwrap();
    let (operator_chirho, view_chirho) =
        verdicts_chirho(&root_chirho, &admission_chirho.run_chirho);
    for verdict_chirho in [operator_chirho.err(), view_chirho.err()] {
        let refusal_chirho =
            verdict_chirho.expect("an aborted record without its error fields is refused");
        assert!(
            refusal_chirho.contains("inconsistent error fields"),
            "{refusal_chirho}"
        );
    }
    let _ = std::fs::remove_dir_all(&root_chirho);

    let root_chirho = tmp_root_chirho();
    let admission_chirho = aborted_arm_admission_chirho(&root_chirho);
    append_crafted_chirho(
        &root_chirho,
        &admission_chirho,
        &[PENDING_CHIRHO, RUNNING_CHIRHO, ABORTED_CHIRHO],
    );
    assert_eq!(
        verdicts_chirho(&root_chirho, &admission_chirho.run_chirho),
        (Ok(3), Ok(Some(ABORTED_CHIRHO.to_string())))
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE MONEY ARM (agy #25909): an aborted run's identical retry re-admits it in RESUME mode, so an effect the run did
/// complete is replayed by its idempotency key and never run twice, even when its ABORTED record is wrong about it.
/// Startup recovery leaves the aborted run alone; only its own retry runs it again, in two records.
///
/// The run logged a read of "first" and then (wrongly) recorded ABORTED, and the live store then changed to "second".
/// A RESUMED retry replays "first" and writes it; a FRESH one would read "second" and log a second read.
///
/// MIGRATION PATH: "second" written, or two volatile records, means the retry ran a completed effect again, which for
/// a write or a charge is a duplicate side effect.
#[test]
fn an_aborted_runs_retry_replays_its_completed_effects_and_startup_leaves_it_alone_chirho() {
    let root_chirho = tmp_root_chirho();
    {
        let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
            &root_chirho.join("versioned-chirho.redb"),
        )
        .unwrap();
        store_chirho.put_chirho("msg", b"first").unwrap();
    }
    let (read_node_chirho, read_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "read_aborted_reader_chirho",
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: "msg".to_string(),
        },
    );
    let (_write_node_chirho, write_hash_chirho) = store_effect_node_chirho(
        &root_chirho,
        "write_aborted_reader_chirho",
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "sent".to_string(),
        },
    );
    let dag_hash_chirho = store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: vec![read_hash_chirho.clone(), write_hash_chirho.clone()],
            edges_chirho: vec![EdgeChirho {
                from_node_chirho: read_hash_chirho.clone(),
                from_port_chirho: "out".to_string(),
                to_node_chirho: write_hash_chirho,
                to_port_chirho: "in".to_string(),
                privacy_chirho: None,
            }],
        },
    )
    .unwrap();
    let admission_chirho = append_intent_statuses_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"",
        None,
        &[PENDING_CHIRHO, RUNNING_CHIRHO],
    );
    let input_hash_chirho = cas_chirho::add_chirho(&root_chirho, b"").unwrap();
    let (read_result_chirho, read_cached_chirho) =
        crate::cache_chirho::run_effect_node_cached_with_context_chirho(
            &root_chirho,
            &read_node_chirho,
            &read_hash_chirho,
            &input_hash_chirho,
            &[],
            None,
        )
        .unwrap();
    assert!(!read_cached_chirho);
    assert_eq!(
        cas_chirho::get_chirho(
            &root_chirho,
            read_result_chirho.outputs_chirho.get("out").unwrap()
        )
        .unwrap(),
        b"first"
    );
    append_crafted_chirho(&root_chirho, &admission_chirho, &[ABORTED_CHIRHO]);
    {
        let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
            &root_chirho.join("versioned-chirho.redb"),
        )
        .unwrap();
        store_chirho.put_chirho("msg", b"second").unwrap();
    }

    let report_chirho = resume_unfinished_run_intents_chirho(&root_chirho).unwrap();
    assert_eq!(
        report_chirho,
        RunIntentResumeReportChirho {
            records_chirho: 3,
            ..RunIntentResumeReportChirho::default()
        },
        "startup recovery leaves an aborted run alone"
    );
    assert_eq!(
        statuses_chirho(&root_chirho),
        [PENDING_CHIRHO, RUNNING_CHIRHO, ABORTED_CHIRHO]
    );

    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho();
    run_dag_with_intent_and_effect_runtime_chirho(
        &root_chirho,
        &dag_hash_chirho,
        b"",
        None,
        crate::effect_chirho::DagEffectRuntimePortsChirho {
            private_attribution_chirho: Some(&operator_chirho),
            ..crate::effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho()
        },
    )
    .expect("the identical retry runs the aborted run again");
    let store_chirho = crate::versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    assert_eq!(
        sealed_row_plaintext_chirho(&root_chirho, &store_chirho, "sent"),
        b"first",
        "the retry replays the read the run completed"
    );
    assert_eq!(
        crate::effect_chirho::load_volatile_effect_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1,
        "the completed read is never run twice"
    );
    assert_eq!(
        statuses_chirho(&root_chirho),
        [
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            RUNNING_CHIRHO,
            DONE_CHIRHO
        ],
        "a retry adds two records: RUNNING, then the outcome"
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// This release never writes ABORTED, even on the road the writer brick will change: an aborted run's retry that
/// refuses before any side effect AGAIN (its DAG names a node that does not exist) records FAILED, as every refusal
/// does today.
///
/// MIGRATION PATH: the writer brick changes exactly this outcome to ABORTED, one release after this reader has
/// shipped (agy #25907).
#[test]
fn a_retry_that_refuses_again_records_failed_in_this_release_chirho() {
    let root_chirho = tmp_root_chirho();
    let admission_chirho = aborted_arm_admission_chirho(&root_chirho);
    append_crafted_chirho(
        &root_chirho,
        &admission_chirho,
        &[PENDING_CHIRHO, RUNNING_CHIRHO, ABORTED_CHIRHO],
    );
    let operator_chirho =
        crate::privacy_chirho::PrivateBlobAttributionChirho::test_operator_chirho();
    run_dag_with_intent_and_effect_runtime_chirho(
        &root_chirho,
        &admission_chirho.dag_chirho,
        REQUEST_CHIRHO,
        None,
        crate::effect_chirho::DagEffectRuntimePortsChirho {
            private_attribution_chirho: Some(&operator_chirho),
            ..crate::effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho()
        },
    )
    .expect_err("the missing node refuses the retry");
    let records_chirho = load_run_intent_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        statuses_chirho(&root_chirho),
        [
            PENDING_CHIRHO,
            RUNNING_CHIRHO,
            ABORTED_CHIRHO,
            RUNNING_CHIRHO,
            FAILED_CHIRHO
        ]
    );
    let refusal_kind_chirho = records_chirho[4]
        .error_kind_chirho
        .as_deref()
        .and_then(DagExecutionRefusalIdentityChirho::from_str_chirho)
        .expect("the failure names a known refusal identity");
    assert_eq!(
        refusal_kind_chirho.execution_knowledge_chirho(),
        dag_chirho::refusal_chirho::DagExecutionKnowledgeChirho::DefinitelyNotExecutedChirho,
        "the retry refused before any side effect ({refusal_kind_chirho:?}), the road the writer brick will change"
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE TRIPWIRE (agy #25907, #25911): this release reads `aborted-chirho` and never writes it, so a rollback to the
/// previous binary always lands on one that can fold the log. The match is exhaustive, so a new write status does not
/// compile until it is listed here, beside this rule.
///
/// MIGRATION PATH: the writer brick adds `AbortedChirho` ONE RELEASE AFTER this reader has shipped, and retires this
/// assertion then. Red before that means a writer arrived in the same release as its reader: rolled back, the previous
/// binary would refuse every admission (PFE #25905).
#[test]
fn this_release_writes_no_aborted_record_chirho() {
    let written_chirho: Vec<&'static str> = [
        RunIntentWriteStatusChirho::PendingChirho,
        RunIntentWriteStatusChirho::RunningChirho,
        RunIntentWriteStatusChirho::DoneChirho,
        RunIntentWriteStatusChirho::FailedChirho,
    ]
    .into_iter()
    .map(|status_chirho| {
        match status_chirho {
            RunIntentWriteStatusChirho::PendingChirho
            | RunIntentWriteStatusChirho::RunningChirho
            | RunIntentWriteStatusChirho::DoneChirho
            | RunIntentWriteStatusChirho::FailedChirho => {}
            RunIntentWriteStatusChirho::CraftedChirho(_) => unreachable!("tests only"),
        }
        status_chirho.as_str_chirho()
    })
    .collect();
    assert_eq!(
        written_chirho,
        [PENDING_CHIRHO, RUNNING_CHIRHO, DONE_CHIRHO, FAILED_CHIRHO]
    );
    assert!(!written_chirho.contains(&ABORTED_CHIRHO));
}
