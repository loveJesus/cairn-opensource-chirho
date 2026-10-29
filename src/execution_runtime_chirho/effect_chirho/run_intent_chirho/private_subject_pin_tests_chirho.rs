// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! THE PIN (CAIRN #25777; agy #25780, #25781, #25887; scope unkeyed only, agy #25885): an unkeyed private run must name
//! its own subject as its scope's user principal, because its v1 context hash omits the subject. A keyed run binds the
//! subject in its v2/v3 context hash and is not pinned. A refused run leaves nothing behind.

use super::*;

const OTHER_SUBJECT_CHIRHO: &str = "user/pin-someone-else-chirho";
/// Another subject OUTSIDE every principal namespace. Since C5 2a, a key under another user's principal
/// subject refuses at admission (the namespace rule), a different refusal from the pin's, so the keyed arm
/// uses this subject to keep measuring the pin alone.
const KEYED_OTHER_SUBJECT_CHIRHO: &str = "pin-shared-subject-chirho";
const PIN_REFUSAL_CHIRHO: &str = "PrivateRunSubjectNotScopePrincipalChirho";

/// What runs leave behind in a root: run-intent records, private values, privacy blob records and key files.
fn footprint_chirho(root_chirho: &Path) -> (usize, usize, usize, usize) {
    let lines_chirho = |name_chirho: &str| {
        std::fs::read_to_string(root_chirho.join(name_chirho))
            .map(|text_chirho| text_chirho.lines().count())
            .unwrap_or(0)
    };
    let key_files_chirho = std::fs::read_dir(root_chirho.join("privacy-keys-chirho"))
        .map(|entries_chirho| entries_chirho.count())
        .unwrap_or(0);
    (
        lines_chirho("run-intents-chirho.jsonl"),
        lines_chirho("private-dag-values-chirho.jsonl"),
        lines_chirho("privacy-blob-records-chirho.jsonl"),
        key_files_chirho,
    )
}

/// A stored DAG whose node does not exist. An admitted run fails while it runs (and records FAILED), which is enough to
/// show the pin let it through; a refused run never gets that far.
fn pin_dag_chirho(root_chirho: &Path) -> HashChirho {
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![HashChirho("node-pin-arm-chirho".to_string())],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

fn assert_refused_by_the_pin_chirho(result_chirho: Result<dag_chirho::DagRunReportChirho>) {
    let refusal_chirho = format!("{:#}", result_chirho.expect_err("the pin refuses this run"));
    assert!(
        refusal_chirho.contains(PIN_REFUSAL_CHIRHO),
        "{refusal_chirho}"
    );
}

/// An admitted run: whatever its DAG then did, the pin did not refuse it, and its records carry its subject.
fn assert_admitted_chirho(
    root_chirho: &Path,
    result_chirho: Result<dag_chirho::DagRunReportChirho>,
    subject_chirho: &str,
) {
    if let Err(error_chirho) = &result_chirho {
        let error_chirho = format!("{error_chirho:#}");
        assert!(!error_chirho.contains(PIN_REFUSAL_CHIRHO), "{error_chirho}");
    }
    let records_chirho = load_run_intent_records_chirho(root_chirho).unwrap();
    assert!(
        !records_chirho.is_empty(),
        "admitted: its run-intent records are appended"
    );
    assert!(records_chirho.iter().all(|record_chirho| {
        record_chirho.request_private_subject_chirho.as_deref() == Some(subject_chirho)
    }));
}

/// An unkeyed private run whose subject is not the scope's user principal is refused by name, and leaves nothing: no
/// run-intent record, no private value, no blob record, no key file.
///
/// MIGRATION PATH: a run admitted here means the pin is gone, and two subjects sending the same bytes under one scope
/// would share a run id again, the second replaying the first person's result.
#[test]
fn an_unkeyed_private_run_for_another_subject_is_refused_and_leaves_nothing_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = pin_dag_chirho(&root_chirho);
    let context_chirho = request_context_chirho();
    assert_ne!(context_chirho.user_principal_chirho, OTHER_SUBJECT_CHIRHO);
    let before_chirho = footprint_chirho(&root_chirho);
    assert_refused_by_the_pin_chirho(run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        OTHER_SUBJECT_CHIRHO,
        b"pin arm request chirho",
        Some(&context_chirho),
    ));
    assert_eq!(
        footprint_chirho(&root_chirho),
        before_chirho,
        "a refused run leaves no record, value, blob record or key file"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// A public scope names no user principal, so an unkeyed private run under it is refused the same way, and leaves
/// nothing.
#[test]
fn an_unkeyed_private_run_under_a_public_scope_is_refused_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = pin_dag_chirho(&root_chirho);
    let before_chirho = footprint_chirho(&root_chirho);
    assert_refused_by_the_pin_chirho(run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        OTHER_SUBJECT_CHIRHO,
        b"pin arm request chirho",
        None,
    ));
    assert_eq!(footprint_chirho(&root_chirho), before_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// THE POSITIVE CONTROL: an unkeyed private run whose subject IS the scope's user principal, the served request-user
/// shape, passes the pin and is admitted.
#[test]
fn an_unkeyed_private_run_for_its_own_principal_is_admitted_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = pin_dag_chirho(&root_chirho);
    let context_chirho = request_context_chirho();
    let result_chirho = run_dag_with_private_input_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &context_chirho.user_principal_chirho,
        b"pin arm request chirho",
        Some(&context_chirho),
    );
    assert_admitted_chirho(
        &root_chirho,
        result_chirho,
        &context_chirho.user_principal_chirho,
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// A KEYED private run binds its subject in its v2/v3 context hash, so the pin does not apply (agy #25885): a keyed run
/// whose subject is not the scope's user principal is admitted.
///
/// MIGRATION PATH: a refusal here means the pin was widened to keyed runs, which the scope ruling chose not to do.
#[test]
fn a_keyed_private_run_for_another_subject_is_not_pinned_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = pin_dag_chirho(&root_chirho);
    let context_chirho = request_context_chirho();
    let caller_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("pin-keyed-arm-0001-chirho").unwrap();
    let result_chirho = run_dag_with_private_input_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_hash_chirho,
        KEYED_OTHER_SUBJECT_CHIRHO,
        b"pin arm request chirho",
        Some(&context_chirho),
        &caller_key_chirho,
    );
    assert_admitted_chirho(&root_chirho, result_chirho, KEYED_OTHER_SUBJECT_CHIRHO);
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// The pin leaves keyed runs alone, but the key chokepoint does not: a keyed private run under ANOTHER user's
/// principal subject refuses at key admission, before any run-intent record or key file exists.
#[test]
fn a_keyed_private_run_under_another_users_principal_subject_is_refused_at_admission_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = pin_dag_chirho(&root_chirho);
    let context_chirho = request_context_chirho();
    let caller_key_chirho =
        CallerIdempotencyKeyChirho::new_chirho("pin-keyed-arm-0002-chirho").unwrap();
    let error_chirho = run_dag_with_private_input_intent_and_caller_key_chirho(
        &root_chirho,
        &dag_hash_chirho,
        OTHER_SUBJECT_CHIRHO,
        b"pin arm request chirho",
        Some(&context_chirho),
        &caller_key_chirho,
    )
    .expect_err("another user's principal subject is not this request's to own");
    let identity_chirho = error_chirho
        .chain()
        .find_map(|cause_chirho| {
            cause_chirho
                .downcast_ref::<cairn_account_attribution_chirho::AccountAttributionErrorChirho>()
        })
        .unwrap_or_else(|| panic!("not a named attribution refusal: {error_chirho:#}"))
        .identity_chirho;
    assert_eq!(
        identity_chirho,
        cairn_account_attribution_chirho::AccountAttributionRefusalChirho::SubjectNamespaceReservedChirho
    );
    assert!(load_run_intent_records_chirho(&root_chirho)
        .unwrap()
        .is_empty());
    assert!(
        !root_chirho.join("privacy-keys-chirho").exists()
            || std::fs::read_dir(root_chirho.join("privacy-keys-chirho"))
                .unwrap()
                .next()
                .is_none(),
        "a refused admission made a key"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}
