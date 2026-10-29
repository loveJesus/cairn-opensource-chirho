// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Checkpoint brick S5a (agy #25958, option 1): an admitted private run stores its request ONCE. The DAG run reuses the
//! record its admission stored before the pending record, where it used to store the same bytes a second time, and
//! once more on every resume.
//!
//! Every count here is of the REQUEST's own records (its subject and its value hash), because the node's private
//! outputs add records of their own.

use super::*;
use crate::dag_private_value_chirho::{
    load_private_dag_value_records_chirho, store_dag_value_with_policy_chirho,
    PrivateDagValueContextChirho, ValueStoragePolicyChirho,
};

const UPCASE_WAT_CHIRHO: &str = include_str!("../../../../examples-chirho/upcase-chirho.wat");

/// How many private-value records hold these exact bytes for this subject: the request's own.
fn request_records_chirho(root_chirho: &Path, subject_chirho: &str, bytes_chirho: &[u8]) -> usize {
    let hash_chirho = cas_chirho::hash_chirho(bytes_chirho);
    load_private_dag_value_records_chirho(root_chirho)
        .unwrap()
        .iter()
        .filter(|record_chirho| {
            record_chirho.subject_chirho == subject_chirho
                && record_chirho.value_hash_chirho == hash_chirho
        })
        .count()
}

/// The request's own blob records and the key files that back them.
fn request_blob_keys_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    bytes_chirho: &[u8],
) -> Vec<String> {
    let hash_chirho = cas_chirho::hash_chirho(bytes_chirho);
    let mut keys_chirho: Vec<String> = load_private_dag_value_records_chirho(root_chirho)
        .unwrap()
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.subject_chirho == subject_chirho
                && record_chirho.value_hash_chirho == hash_chirho
        })
        .map(|record_chirho| record_chirho.blob_chirho.key_id_chirho)
        .collect();
    keys_chirho.sort();
    keys_chirho
}

/// The admission the production entry computes for an unkeyed private run of these bytes under this context
/// (`run_dag_with_private_input_intent_and_effect_runtime_optional_caller_key_chirho`), so records appended by hand
/// belong to the run that a retry of the same bytes admits.
fn private_admission_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    bytes_chirho: &[u8],
    context_chirho: &RequestContextChirho,
) -> RunIntentAdmissionChirho {
    let request_chirho = cas_chirho::hash_chirho(bytes_chirho);
    let scope_chirho = run_intent_scope_chirho(root_chirho, Some(context_chirho)).unwrap();
    let subject_chirho = context_chirho.user_principal_chirho.as_str();
    let idempotency_context_hash_chirho = run_intent_context_hash_from_digest_chirho(
        dag_hash_chirho,
        &request_chirho,
        &scope_chirho,
        Some(subject_chirho),
        None,
        None,
    )
    .unwrap();
    RunIntentAdmissionChirho {
        run_chirho: run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap(),
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho,
        request_private_subject_chirho: Some(subject_chirho.to_string()),
        caller_idempotency_key_digest_chirho: None,
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    }
}

/// A run that was admitted, stored its request as the production admission does, and whose process died mid-run: its
/// latest record is RUNNING, a state this release writes (it writes no ABORTED record yet), and a retry of the same
/// bytes resumes it.
fn running_run_with_stored_request_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    bytes_chirho: &[u8],
    context_chirho: &RequestContextChirho,
) {
    let admission_chirho =
        private_admission_chirho(root_chirho, dag_hash_chirho, bytes_chirho, context_chirho);
    let stored_chirho = store_dag_value_with_policy_chirho(
        root_chirho,
        bytes_chirho,
        &ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho: context_chirho.user_principal_chirho.clone(),
            owner_chirho:
                crate::dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
        },
        PrivateDagValueContextChirho::default(),
        None,
        &crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            Some(context_chirho),
            None,
        ),
    )
    .unwrap();
    assert_eq!(stored_chirho, admission_chirho.request_chirho);
    for status_chirho in [RUN_INTENT_PENDING_CHIRHO, RUN_INTENT_RUNNING_CHIRHO] {
        append_run_intent_record_chirho(
            root_chirho,
            &admission_chirho,
            RunIntentWriteStatusChirho::CraftedChirho(status_chirho),
            None,
        )
        .unwrap();
    }
}

fn latest_status_chirho(root_chirho: &Path) -> String {
    load_run_intent_records_chirho(root_chirho)
        .unwrap()
        .last()
        .expect("the run left records")
        .status_chirho
        .clone()
}

/// A fresh admitted private run stores its request once: the admission's store, reused by the DAG run.
///
/// MIGRATION PATH: 2 means the DAG run stores the request again (S5a undone); 0 means the admission stopped storing it
/// first, which reopens the #25853 concurrency refusal.
#[test]
fn a_fresh_admitted_private_run_stores_its_request_once_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let bytes_chirho = b"s5a fresh request chirho";
    run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &subject_chirho,
        bytes_chirho,
        Some(&context_chirho),
    )
    .unwrap();
    assert_eq!(latest_status_chirho(&root_chirho), RUN_INTENT_DONE_CHIRHO);
    assert_eq!(
        request_records_chirho(&root_chirho, &subject_chirho, bytes_chirho),
        1,
        "one record for the request: the admission's"
    );
    // The reused request still marks the run's input as this subject's, so what the node derives from it stays
    // private: a private record of the output for the subject, and no public object for it.
    let output_chirho = bytes_chirho.to_ascii_uppercase();
    assert_eq!(
        request_records_chirho(&root_chirho, &subject_chirho, &output_chirho),
        1,
        "the output is stored as the subject's private value"
    );
    assert!(
        !cas_object_path_for_test_chirho(&root_chirho, &cas_chirho::hash_chirho(&output_chirho))
            .exists(),
        "the output has no public object"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// A retried RUNNING run resumes, completes, and stores nothing new for its request: the same record, the same key.
///
/// MIGRATION PATH: a second record, or a different key, means every resume stores the request again.
#[test]
fn a_resumed_admitted_run_stores_nothing_new_for_its_request_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let bytes_chirho = b"s5a resumed request chirho";
    running_run_with_stored_request_chirho(
        &root_chirho,
        &dag_hash_chirho,
        bytes_chirho,
        &context_chirho,
    );
    let keys_before_chirho = request_blob_keys_chirho(&root_chirho, &subject_chirho, bytes_chirho);
    assert_eq!(
        keys_before_chirho.len(),
        1,
        "the control: the admission's one record"
    );
    run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &subject_chirho,
        bytes_chirho,
        Some(&context_chirho),
    )
    .unwrap();
    assert_eq!(
        latest_status_chirho(&root_chirho),
        RUN_INTENT_DONE_CHIRHO,
        "the retry resumed and completed"
    );
    assert_eq!(
        request_blob_keys_chirho(&root_chirho, &subject_chirho, bytes_chirho),
        keys_before_chirho,
        "the resume reused the admission's record and key"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The admitted entry, given a coordinate with no stored record, refuses by name and stores nothing. On the admitted
/// road the record always exists (a fresh admission stores it; a resumed run's record verified only because it
/// resolved), so absence is a broken invariant, never a reason to store.
///
/// MIGRATION PATH: a success here means absence is papered over by a store again.
#[test]
fn an_admitted_run_with_no_stored_request_refuses_and_stores_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let bytes_chirho = b"s5a request never stored chirho";
    let error_chirho = dag_chirho::run_dag_with_admitted_private_input_and_effect_runtime_chirho(
        &root_chirho,
        &dag_chirho,
        &subject_chirho,
        bytes_chirho,
        &cas_chirho::hash_chirho(bytes_chirho),
        Some(&context_chirho),
        crate::effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho(),
    )
    .expect_err("a missing request record refuses");
    assert!(
        format!("{error_chirho:#}").contains("AdmittedPrivateRequestMissingChirho"),
        "{error_chirho:#}"
    );
    assert_eq!(
        load_private_dag_value_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        0,
        "nothing was stored"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The admitted entry, given bytes that do not hash to the coordinate, refuses and stores nothing, even when the
/// coordinate's own record exists.
#[test]
fn an_admitted_run_whose_bytes_do_not_hash_to_its_request_refuses_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let stored_bytes_chirho = b"s5a the stored request chirho";
    let coordinate_chirho = store_dag_value_with_policy_chirho(
        &root_chirho,
        stored_bytes_chirho,
        &ValueStoragePolicyChirho::PrivateBlobRefChirho {
            subject_chirho: subject_chirho.clone(),
            owner_chirho:
                crate::dag_private_value_chirho::PrivateValueOwnerChirho::RequestActorChirho,
        },
        PrivateDagValueContextChirho::default(),
        None,
        &crate::dag_private_value_chirho::RunAttributionSourceChirho::new_chirho(
            Some(&context_chirho),
            None,
        ),
    )
    .unwrap();
    let records_before_chirho = load_private_dag_value_records_chirho(&root_chirho)
        .unwrap()
        .len();
    let error_chirho = dag_chirho::run_dag_with_admitted_private_input_and_effect_runtime_chirho(
        &root_chirho,
        &dag_chirho,
        &subject_chirho,
        b"s5a different bytes chirho",
        &coordinate_chirho,
        Some(&context_chirho),
        crate::effect_chirho::DagEffectRuntimePortsChirho::uncomposed_chirho(),
    )
    .expect_err("bytes that do not hash to the coordinate refuse");
    assert!(
        format!("{error_chirho:#}").contains("does not hash to its admitted request"),
        "{error_chirho:#}"
    );
    assert_eq!(
        load_private_dag_value_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        records_before_chirho,
        "nothing was stored"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The control that the counter sees stores: the private-input entry WITHOUT an admission still stores its input on
/// every call, as before (it has no production caller; S5a changes only the admitted road).
#[test]
fn the_unadmitted_private_entry_still_stores_on_every_call_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let bytes_chirho = b"s5a unadmitted input chirho";
    for _ in 0..2 {
        dag_chirho::run_dag_with_context_and_private_input_chirho(
            &root_chirho,
            &dag_chirho,
            &subject_chirho,
            bytes_chirho,
            Some(&context_chirho),
        )
        .unwrap();
    }
    assert_eq!(
        request_records_chirho(&root_chirho, &subject_chirho, bytes_chirho),
        2
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// After its subject's keys are shredded, a retried run stores its request no second time: no new record, no new key.
/// The record's verification reads the subject from the blob log, not the key file, so the run may reuse it or refuse;
/// this arm states which happened rather than assuming it.
#[test]
fn a_retry_after_its_subject_is_erased_stores_no_new_request_copy_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_one_node_dag_chirho(&root_chirho, UPCASE_WAT_CHIRHO.as_bytes());
    let context_chirho = request_context_chirho();
    let subject_chirho = context_chirho.user_principal_chirho.clone();
    let bytes_chirho = b"s5a erased subject request chirho";
    running_run_with_stored_request_chirho(
        &root_chirho,
        &dag_hash_chirho,
        bytes_chirho,
        &context_chirho,
    );
    let keys_before_chirho = request_blob_keys_chirho(&root_chirho, &subject_chirho, bytes_chirho);
    assert_eq!(
        keys_before_chirho.len(),
        1,
        "the control: the admission's one record"
    );
    assert!(
        crate::privacy_chirho::erase_subject_keys_chirho(&root_chirho, &subject_chirho).unwrap()
            >= 1
    );
    let outcome_chirho = run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &subject_chirho,
        bytes_chirho,
        Some(&context_chirho),
    );
    eprintln!(
        "S5a erasure arm: the retried run {}",
        match &outcome_chirho {
            Ok(_) => "REUSED the record and completed".to_string(),
            Err(error_chirho) => format!("REFUSED: {error_chirho:#}"),
        }
    );
    assert_eq!(
        request_blob_keys_chirho(&root_chirho, &subject_chirho, bytes_chirho),
        keys_before_chirho,
        "no second copy of the request, and no new key for it"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
