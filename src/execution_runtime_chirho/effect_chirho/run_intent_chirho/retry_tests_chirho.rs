// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::sync::{Arc, Barrier};

#[test]
fn completed_retry_replays_without_a_second_status_lifecycle_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );

    let first_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap();
    let second_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap();

    assert_eq!(first_chirho.payload_chirho, b"SAME");
    assert_eq!(second_chirho.payload_chirho, first_chirho.payload_chirho);
    assert_eq!(
        first_chirho.payload_hash_chirho,
        second_chirho.payload_hash_chirho
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn completed_retry_refreshes_volatile_reads_without_second_cached_billing_chirho() {
    let run_chirho = HashChirho("a".repeat(64));
    let completed_flags_chirho = with_run_intent_execution_mode_chirho(
        &run_chirho,
        RunIntentExecutionModeChirho::CompletedReplayChirho,
        || {
            Ok((
                run_intent_cached_billing_suppressed_chirho(),
                run_intent_volatile_replay_active_chirho(),
            ))
        },
    )
    .unwrap();
    let resume_flags_chirho = with_run_intent_execution_mode_chirho(
        &run_chirho,
        RunIntentExecutionModeChirho::ResumeChirho,
        || {
            Ok((
                run_intent_cached_billing_suppressed_chirho(),
                run_intent_volatile_replay_active_chirho(),
            ))
        },
    )
    .unwrap();

    assert_eq!(completed_flags_chirho, (true, false));
    assert_eq!(resume_flags_chirho, (true, true));
}

#[test]
fn failed_retry_refuses_manual_without_a_second_pending_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, b"not wasm");

    let _first_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();
    let retry_error_chirho =
        run_dag_with_intent_chirho(&root_chirho, &dag_hash_chirho, b"same", None).unwrap_err();

    assert!(retry_error_chirho
        .to_string()
        .contains("previously failed and requires manual review"));
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn concurrent_identical_submissions_share_one_status_lifecycle_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(
        &root_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    );
    let barrier_chirho = Arc::new(Barrier::new(3));
    let mut workers_chirho = Vec::new();
    for _worker_chirho in 0..2 {
        let worker_root_chirho = root_chirho.clone();
        let worker_dag_chirho = dag_hash_chirho.clone();
        let worker_barrier_chirho = barrier_chirho.clone();
        workers_chirho.push(std::thread::spawn(move || {
            worker_barrier_chirho.wait();
            run_dag_with_intent_chirho(&worker_root_chirho, &worker_dag_chirho, b"same", None)
        }));
    }
    barrier_chirho.wait();

    let reports_chirho = workers_chirho
        .into_iter()
        .map(|worker_chirho| worker_chirho.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(reports_chirho[0].payload_chirho, b"SAME");
    assert_eq!(reports_chirho[1].payload_chirho, b"SAME");
    assert_eq!(
        reports_chirho[0].payload_hash_chirho,
        reports_chirho[1].payload_hash_chirho
    );
    assert_eq!(
        load_run_intent_records_chirho(&root_chirho).unwrap().len(),
        3
    );
    assert_eq!(verify_run_intent_records_chirho(&root_chirho).unwrap(), 3);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn effect_invocation_ref_binds_outer_run_node_and_step_chirho() {
    let run_chirho = HashChirho("a".repeat(64));
    let other_run_chirho = HashChirho("b".repeat(64));
    let node_chirho = HashChirho("c".repeat(64));
    let first_chirho = with_run_intent_execution_chirho(&run_chirho, false, || {
        with_run_intent_effect_invocation_chirho(&node_chirho, 4, || {
            Ok(current_run_intent_effect_invocation_chirho().unwrap())
        })
    })
    .unwrap();
    let same_chirho = with_run_intent_execution_chirho(&run_chirho, true, || {
        with_run_intent_effect_invocation_chirho(&node_chirho, 4, || {
            Ok(current_run_intent_effect_invocation_chirho().unwrap())
        })
    })
    .unwrap();
    let different_step_chirho = with_run_intent_execution_chirho(&run_chirho, false, || {
        with_run_intent_effect_invocation_chirho(&node_chirho, 5, || {
            Ok(current_run_intent_effect_invocation_chirho().unwrap())
        })
    })
    .unwrap();
    let different_run_chirho = with_run_intent_execution_chirho(&other_run_chirho, false, || {
        with_run_intent_effect_invocation_chirho(&node_chirho, 4, || {
            Ok(current_run_intent_effect_invocation_chirho().unwrap())
        })
    })
    .unwrap();

    assert_eq!(
        first_chirho.invocation_ref_chirho,
        same_chirho.invocation_ref_chirho
    );
    assert_ne!(
        first_chirho.invocation_ref_chirho,
        different_step_chirho.invocation_ref_chirho
    );
    assert_ne!(
        first_chirho.invocation_ref_chirho,
        different_run_chirho.invocation_ref_chirho
    );
    assert_eq!(first_chirho.run_chirho, run_chirho);
    assert_eq!(first_chirho.node_chirho, node_chirho);
    assert_eq!(first_chirho.effect_step_chirho, 4);
    assert!(current_run_intent_effect_invocation_chirho().is_none());
}

#[test]
fn distinct_verified_payers_derive_distinct_run_and_effect_coordinates_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_chirho = HashChirho("d".repeat(64));
    let request_chirho = HashChirho("e".repeat(64));
    let node_chirho = HashChirho("f".repeat(64));
    let first_context_chirho = RequestContextChirho {
        user_principal_chirho: "user/payer-a-chirho".to_owned(),
        app_chirho: "descriptor-d-app-chirho".to_owned(),
        owner_principal_chirho: "owner/descriptor-d-chirho".to_owned(),
        client_id_chirho: "client/descriptor-d-chirho".to_owned(),
        token_hash_chirho: "token/descriptor-d-chirho".to_owned(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let mut second_context_chirho = first_context_chirho.clone();
    second_context_chirho.user_principal_chirho = "user/payer-b-chirho".to_owned();

    let first_scope_chirho =
        run_intent_scope_chirho(&root_chirho, Some(&first_context_chirho)).unwrap();
    let second_scope_chirho =
        run_intent_scope_chirho(&root_chirho, Some(&second_context_chirho)).unwrap();
    let first_context_ref_chirho =
        run_intent_context_hash_chirho(&dag_chirho, &request_chirho, &first_scope_chirho).unwrap();
    let second_context_ref_chirho =
        run_intent_context_hash_chirho(&dag_chirho, &request_chirho, &second_scope_chirho).unwrap();
    let first_run_chirho = run_intent_run_hash_chirho(&first_context_ref_chirho).unwrap();
    let second_run_chirho = run_intent_run_hash_chirho(&second_context_ref_chirho).unwrap();

    let first_invocation_chirho =
        with_run_intent_execution_chirho(&first_run_chirho, false, || {
            with_run_intent_effect_invocation_chirho(&node_chirho, 0, || {
                Ok(current_run_intent_effect_invocation_chirho().unwrap())
            })
        })
        .unwrap();
    let second_invocation_chirho =
        with_run_intent_execution_chirho(&second_run_chirho, false, || {
            with_run_intent_effect_invocation_chirho(&node_chirho, 0, || {
                Ok(current_run_intent_effect_invocation_chirho().unwrap())
            })
        })
        .unwrap();

    assert_ne!(first_scope_chirho, second_scope_chirho);
    assert_ne!(first_context_ref_chirho, second_context_ref_chirho);
    assert_ne!(first_run_chirho, second_run_chirho);
    assert_ne!(
        first_invocation_chirho.invocation_ref_chirho,
        second_invocation_chirho.invocation_ref_chirho
    );
    assert!(current_run_intent_effect_invocation_chirho().is_none());
    let _ = std::fs::remove_dir_all(root_chirho);
}
