// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Fail-closed arms for the run-intent verifier's private-request check.
//!
//! `verify_run_intent_record_chirho` used to rest on `private_dag_value_recorded_for_subject_chirho`,
//! which matches the `subject` FIELD of a line the loader never verified. A verifier may not rest on
//! an unverified line: the subject a record CLAIMS is attacker-supplied until that record's own
//! signature and privacy-log-backed blob ownership say otherwise. So a verifier reporting green was
//! reporting green over evidence that need not exist.
//!
//! THREE DISTINGUISHABLE OUTCOMES, because a two-case arm (claimed / not claimed) goes green on the
//! near-miss that swallows an `Err` into a `None`:
//!   * `Ok(None)`    — no record claims (subject, hash). The verifier keeps its own "missing".
//!   * `Ok(Some(_))` — a record claims it and VERIFIES. The verifier passes.
//!   * `Err(_)`      — a record claims it and does NOT verify. Fail closed, with its own identity.
//!
//! The fourth arm here is the ATTACK the subject-bound sibling exists for: one appended line naming
//! another subject's blob under the requested subject. Blob ownership is checked BEFORE the
//! signature inside `verify_private_dag_value_record_chirho`, so that fixture can assert the
//! ownership refusal by name rather than settling for "something failed".

use super::*;
use crate::dag_private_value_chirho;
use std::sync::atomic::{AtomicU64, Ordering};

const PRIVATE_REQUEST_SUBJECT_CHIRHO: &str = "user/run-intent-private-subject-chirho";
const OTHER_SUBJECT_CHIRHO: &str = "user/run-intent-other-subject-chirho";

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-run-intent-private-{nanos_chirho}-{n_chirho}"
    ))
}

fn store_empty_dag_chirho(root_chirho: &Path) -> HashChirho {
    let dag_chirho = DagChirho {
        nodes_chirho: vec![HashChirho("node-run-intent-private-chirho".to_string())],
        edges_chirho: vec![],
    };
    store_chirho::put_object_chirho(root_chirho, &dag_chirho).unwrap()
}

/// Appends ONE `pending-chirho` record whose request is private to `subject_chirho`.
///
/// Every hash is derived through the same production helpers the runtime uses, so the only thing
/// this fixture varies is what the private-value log does or does not hold for that request.
fn append_private_subject_intent_chirho(
    root_chirho: &Path,
    dag_hash_chirho: &HashChirho,
    request_chirho: &HashChirho,
    subject_chirho: &str,
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
    let run_chirho = run_intent_run_hash_chirho(&idempotency_context_hash_chirho).unwrap();
    let admission_chirho = RunIntentAdmissionChirho {
        run_chirho,
        dag_chirho: dag_hash_chirho.clone(),
        request_chirho: request_chirho.clone(),
        request_private_subject_chirho: Some(subject_chirho.to_string()),
        caller_idempotency_key_digest_chirho: None,
        caller_operation_digest_chirho: None,
        idempotency_context_hash_chirho,
        scope_chirho,
    };
    append_run_intent_record_chirho(
        root_chirho,
        &admission_chirho,
        RunIntentWriteStatusChirho::PendingChirho,
        None,
    )
    .unwrap();
    // Proof the fixture produced the record it claims to, before anything depends on it.
    let records_chirho = load_run_intent_records_chirho(root_chirho).unwrap();
    assert_eq!(
        records_chirho.len(),
        1,
        "fixture: expected exactly one record"
    );
    assert_eq!(
        records_chirho[0].request_private_subject_chirho.as_deref(),
        Some(subject_chirho),
        "fixture: the record must take the PRIVATE branch of the verifier"
    );
}

fn private_dag_values_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("private-dag-values-chirho.jsonl")
}

/// Appends one line claiming `(subject, value_hash)` with the supplied blob, and PROVES it landed.
///
/// `blob_json_chirho` is the whole attack surface: a blob nothing backs (case 3) or ANOTHER
/// subject's real blob (case 4).
fn forge_claiming_line_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    value_hash_chirho: &HashChirho,
    blob_json_chirho: serde_json::Value,
) {
    let path_chirho = private_dag_values_path_chirho(root_chirho);
    let before_chirho = std::fs::read_to_string(&path_chirho).unwrap_or_default();
    let forged_chirho = serde_json::json!({
        "schema_chirho": dag_private_value_chirho::PRIVATE_DAG_VALUE_SCHEMA_CHIRHO,
        "seq_chirho": before_chirho.lines().count(),
        "subject_chirho": subject_chirho,
        "value_hash_chirho": value_hash_chirho.0,
        "blob_chirho": blob_json_chirho,
        "bytes_chirho": 0,
        "at_ms_chirho": 0,
        "sig_chirho": "",
    });
    std::fs::create_dir_all(root_chirho).unwrap();
    std::fs::write(&path_chirho, format!("{before_chirho}{forged_chirho}\n")).unwrap();
    let after_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    assert_eq!(
        after_chirho.lines().count(),
        before_chirho.lines().count() + 1,
        "the forged line was not appended, so every assertion below would pass over an unmutated log"
    );
}

fn unbacked_blob_json_chirho() -> serde_json::Value {
    serde_json::json!({
        "alg_chirho": "xchacha20poly1305-chirho",
        "key_id_chirho": "forged-key-id-chirho",
        "nonce_chirho": "00".repeat(24),
        "mac_chirho": "00".repeat(32),
        "ciphertext_chirho": cas_chirho::hash_chirho(b"no such ciphertext chirho").0,
    })
}

/// POSITIVE CONTROL. A refusal from a fixture that never reached the private branch would prove
/// nothing, so first prove the verifier PASSES on a request that is genuinely sealed to its subject.
#[test]
fn run_intent_verifier_admits_a_verified_private_request_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_empty_dag_chirho(&root_chirho);
    let request_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            PRIVATE_REQUEST_SUBJECT_CHIRHO,
        ),
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
        b"sealed run intent request body chirho",
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            PRIVATE_REQUEST_SUBJECT_CHIRHO,
            &request_chirho,
        )
        .unwrap()
        .is_some(),
        "fixture: the sealed request must resolve to a VERIFIED record for its subject"
    );
    append_private_subject_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
    );

    assert_eq!(
        verify_run_intent_records_chirho(&root_chirho).unwrap(),
        1,
        "the verifier refused a private request that is genuinely sealed to its subject"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// ABSENCE — nothing claims (subject, hash). The verifier keeps its own "missing" identity, which
/// must share no phrase with the verification refusal below.
#[test]
fn run_intent_verifier_refuses_a_private_request_no_record_claims_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_empty_dag_chirho(&root_chirho);
    let request_chirho = cas_chirho::hash_chirho(b"a request body nothing ever sealed chirho");
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            PRIVATE_REQUEST_SUBJECT_CHIRHO,
            &request_chirho,
        )
        .unwrap()
        .is_none(),
        "fixture: nothing may claim this request, or this arm exercises the wrong branch"
    );
    append_private_subject_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
    );

    let error_chirho = verify_run_intent_records_chirho(&root_chirho)
        .expect_err("the verifier passed a private request nothing records");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("private request value"),
        "absence must refuse by the verifier's own identity, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains("missing"),
        "absence must refuse by the verifier's own identity, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("claimed only by records that do not verify"),
        "absence must NOT borrow the verification refusal's identity, got: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// CLAIMED-BUT-UNVERIFIABLE — one appended line, no ciphertext, no key, no signature. The verifier
/// must fail CLOSED and say so in its own words rather than reporting the record merely absent.
///
/// MIGRATION PATH — if this goes red with `Ok(1)`, the unverified subject match is back and one
/// appended line satisfies a verifier again. If it goes red on a refusal naming something other than
/// record verification, read the refusal before touching the assertion: the IDENTITY is the pin.
#[test]
fn run_intent_verifier_refuses_a_private_request_claimed_only_by_an_unverifiable_record_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_empty_dag_chirho(&root_chirho);
    let request_chirho =
        cas_chirho::hash_chirho(b"a request body only a forged line claims chirho");
    forge_claiming_line_chirho(
        &root_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
        &request_chirho,
        unbacked_blob_json_chirho(),
    );
    // Proof the forged line is SELECTED by the old, unverified predicate — i.e. that this fixture
    // really does reproduce the defect rather than failing some earlier filter.
    assert!(
        dag_private_value_chirho::private_dag_value_recorded_for_subject_chirho(
            &root_chirho,
            PRIVATE_REQUEST_SUBJECT_CHIRHO,
            &request_chirho,
        )
        .unwrap(),
        "fixture: the bare existence check must ACCEPT this line, or the arm proves nothing about \
         the signal that was replaced"
    );
    append_private_subject_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
    );

    let error_chirho = verify_run_intent_records_chirho(&root_chirho)
        .expect_err("the verifier accepted one appended line as private-request evidence");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("claimed only by records that do not verify"),
        "the verifier refused for some other reason than record verification: {text_chirho}"
    );
    // THE NEAR-MISS. A fix that swallowed the `Err` into a `None` would still refuse here — but with
    // ABSENCE's identity, because the verifier would fall through to its own "missing" bail. A
    // two-case arm goes green on that mutation; this assertion does not.
    assert!(
        !text_chirho.contains("private request value"),
        "a broken record was reported as an ABSENT one, which is the near-miss this arm exists for: \
         {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

/// THE ATTACK the subject-bound sibling exists for: one appended line rebinding ANOTHER subject's
/// real blob under the requested subject.
///
/// Everything downstream of the record still passes — the blob's MAC, the AEAD and the plaintext
/// hash are properties of the substituted blob rather than of who may read it — so the binding has
/// to be proven at the record. Blob ownership is checked BEFORE the signature inside
/// `verify_private_dag_value_record_chirho`, so the refusal can be asserted by ITS OWN name here
/// instead of settling for "something failed".
#[test]
fn run_intent_verifier_refuses_a_private_request_rebound_to_another_subjects_blob_chirho() {
    let root_chirho = tmp_root_chirho();
    let dag_hash_chirho = store_empty_dag_chirho(&root_chirho);
    // A real, verifying record — for the WRONG subject.
    let request_chirho = dag_private_value_chirho::store_private_dag_value_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            OTHER_SUBJECT_CHIRHO,
        ),
        OTHER_SUBJECT_CHIRHO,
        b"another subject's sealed request body chirho",
        dag_private_value_chirho::PrivateDagValueContextChirho::default(),
    )
    .unwrap();
    let real_records_chirho =
        dag_private_value_chirho::load_private_dag_value_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        real_records_chirho.len(),
        1,
        "fixture: expected exactly the one genuine record to copy a blob from"
    );
    let stolen_blob_chirho = serde_json::to_value(&real_records_chirho[0].blob_chirho).unwrap();
    forge_claiming_line_chirho(
        &root_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
        &request_chirho,
        stolen_blob_chirho,
    );
    assert!(
        dag_private_value_chirho::private_dag_value_recorded_for_subject_chirho(
            &root_chirho,
            PRIVATE_REQUEST_SUBJECT_CHIRHO,
            &request_chirho,
        )
        .unwrap(),
        "fixture: the bare subject match must ACCEPT the rebinding line, or the arm proves nothing"
    );
    append_private_subject_intent_chirho(
        &root_chirho,
        &dag_hash_chirho,
        &request_chirho,
        PRIVATE_REQUEST_SUBJECT_CHIRHO,
    );

    let error_chirho = verify_run_intent_records_chirho(&root_chirho)
        .expect_err("the verifier accepted a blob rebound to a subject that does not own it");
    let text_chirho = format!("{error_chirho:#}");
    assert!(
        text_chirho.contains("belongs to subject"),
        "the rebinding must refuse at blob OWNERSHIP by name, got: {text_chirho}"
    );
    assert!(
        text_chirho.contains(OTHER_SUBJECT_CHIRHO),
        "the refusal must name the subject that actually owns the blob, got: {text_chirho}"
    );
    assert!(
        !text_chirho.contains("private request value"),
        "a rebound blob was reported as an ABSENT record rather than a refused one: {text_chirho}"
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
