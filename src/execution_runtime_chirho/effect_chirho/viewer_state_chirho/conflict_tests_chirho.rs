// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A stale optimistic version answers with a typed conflict instead of a refusal: the verified
//! head comes back with the attempted draft echoed, nothing is appended, no receipt is signed,
//! the effect log replays it exactly, and every OTHER refusal is still a refusal.

use super::tests_chirho::{
    context_chirho, run_write_effect_chirho, test_root_chirho, viewer_request_chirho,
};
use super::*;
use crate::dag_private_value_chirho;
use crate::effect_chirho::verify_effect_chirho;

const KEY_CHIRHO: &str = "workspace-page-chirho";

fn write_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    idempotency_chirho: &str,
    request_chirho: &ViewerStateRequestChirho,
) -> Result<Vec<u8>> {
    run_write_chirho(
        root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        request_chirho,
        &serde_json::to_vec(request_chirho)?,
        &HashChirho(idempotency_chirho.to_string()),
        Some(context_chirho),
    )
    .map(|output_chirho| output_chirho.response_chirho)
}

fn head_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
) -> ViewerStateResponseChirho {
    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        KEY_CHIRHO,
        None,
        None,
        None,
    );
    let output_chirho = run_read_chirho(
        root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &read_chirho,
        Some(context_chirho),
    )
    .unwrap();
    serde_json::from_slice(&output_chirho.response_chirho).unwrap()
}

/// Two applied versions, so a request naming version 1 is stale against head 2.
fn two_versions_chirho(label_chirho: &str) -> (PathBuf, RequestContextChirho) {
    let root_chirho = test_root_chirho(label_chirho);
    let context_chirho = context_chirho("identity/conflict-chirho", "workspace-app-chirho");
    for (version_chirho, expected_chirho) in [(1_u64, None), (2, Some(1))] {
        let request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::WriteChirho,
            KEY_CHIRHO,
            expected_chirho,
            Some(format!("draft-{version_chirho}").as_bytes()),
            None,
        );
        let applied_chirho: ViewerStateResponseChirho = serde_json::from_slice(
            &write_chirho(
                &root_chirho,
                &context_chirho,
                &format!("idem-{version_chirho}"),
                &request_chirho,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            applied_chirho.schema_chirho,
            VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO
        );
        assert_eq!(
            applied_chirho.current_chirho.unwrap().version_chirho,
            version_chirho
        );
    }
    (root_chirho, context_chirho)
}

#[test]
fn stale_write_returns_a_typed_conflict_and_appends_nothing_chirho() {
    let (root_chirho, context_chirho) = two_versions_chirho("stale-write-chirho");
    let stale_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        KEY_CHIRHO,
        Some(1),
        Some(b"her unsaved draft"),
        None,
    );
    let bytes_chirho = write_chirho(&root_chirho, &context_chirho, "stale-chirho", &stale_chirho)
        .expect("a stale version is an answer, not an error");
    let conflict_chirho: ViewerStateConflictChirho = serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        conflict_chirho.schema_chirho,
        VIEWER_STATE_CONFLICT_SCHEMA_CHIRHO
    );
    assert_eq!(conflict_chirho.key_chirho, KEY_CHIRHO);
    assert_eq!(
        conflict_chirho.action_chirho,
        ViewerStateActionChirho::WriteChirho
    );
    assert_eq!(conflict_chirho.expected_current_version_chirho, Some(1));
    assert_eq!(conflict_chirho.current_version_chirho, Some(2));
    assert_eq!(
        conflict_chirho.attempted_value_base64_chirho.as_deref(),
        Some(BASE64_CHIRHO.encode(b"her unsaved draft").as_str()),
        "the draft comes back exactly as sent"
    );
    assert_eq!(conflict_chirho.attempted_restore_from_version_chirho, None);
    let current_chirho = &conflict_chirho.current_chirho;
    assert_eq!(
        current_chirho.schema_chirho,
        VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO
    );
    assert_eq!(current_chirho.key_chirho, KEY_CHIRHO);
    assert_eq!(
        current_chirho
            .current_chirho
            .as_ref()
            .unwrap()
            .version_chirho,
        2
    );
    assert_eq!(
        current_chirho
            .current_chirho
            .as_ref()
            .unwrap()
            .value_base64_chirho,
        BASE64_CHIRHO.encode(b"draft-2")
    );
    assert_eq!(
        current_chirho.history_chirho.len(),
        2,
        "the full retained history rides along"
    );
    assert!(
        current_chirho.mutation_receipt_chirho.is_none(),
        "nothing was signed"
    );

    let head_chirho = head_chirho(&root_chirho, &context_chirho);
    assert_eq!(
        head_chirho.current_chirho.unwrap().version_chirho,
        2,
        "nothing was appended"
    );
    assert_eq!(head_chirho.history_chirho.len(), 2);

    // The key is not poisoned: the next save at the head applies as version 3.
    let fresh_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        KEY_CHIRHO,
        Some(2),
        Some(b"merged draft"),
        None,
    );
    let applied_chirho: ViewerStateResponseChirho = serde_json::from_slice(
        &write_chirho(&root_chirho, &context_chirho, "fresh-chirho", &fresh_chirho).unwrap(),
    )
    .unwrap();
    assert_eq!(applied_chirho.current_chirho.unwrap().version_chirho, 3);
    assert!(applied_chirho.mutation_receipt_chirho.is_some());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn stale_restore_conflicts_without_an_echo_field_chirho() {
    let (root_chirho, context_chirho) = two_versions_chirho("stale-restore-chirho");
    let stale_restore_chirho = viewer_request_chirho(
        ViewerStateActionChirho::RestoreChirho,
        KEY_CHIRHO,
        Some(1),
        None,
        Some(1),
    );
    let bytes_chirho = write_chirho(
        &root_chirho,
        &context_chirho,
        "stale-restore-chirho",
        &stale_restore_chirho,
    )
    .unwrap();
    let raw_chirho: serde_json::Value = serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        raw_chirho["schema_chirho"],
        VIEWER_STATE_CONFLICT_SCHEMA_CHIRHO
    );
    assert!(
        raw_chirho.get("attempted_value_base64_chirho").is_none(),
        "a restore carries no value: the echo field is ABSENT, not empty"
    );
    assert_eq!(raw_chirho["attempted_restore_from_version_chirho"], 1);
    assert_eq!(raw_chirho["action_chirho"], "restore-chirho");
    assert_eq!(raw_chirho["current_version_chirho"], 2);
    let head_chirho = head_chirho(&root_chirho, &context_chirho);
    assert_eq!(head_chirho.current_chirho.unwrap().version_chirho, 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn every_other_refusal_is_still_a_refusal_chirho() {
    let (root_chirho, context_chirho) = two_versions_chirho("still-refuses-chirho");
    let cases_chirho: Vec<(&str, ViewerStateRequestChirho, &str)> = vec![
        (
            "oversize",
            viewer_request_chirho(
                ViewerStateActionChirho::WriteChirho,
                KEY_CHIRHO,
                Some(2),
                Some(&vec![b'x'; VIEWER_STATE_MAX_VALUE_BYTES_CHIRHO + 1]),
                None,
            ),
            "exceeds",
        ),
        (
            "retired-restore",
            viewer_request_chirho(
                ViewerStateActionChirho::RestoreChirho,
                KEY_CHIRHO,
                Some(2),
                None,
                Some(9),
            ),
            "not retained",
        ),
        (
            "restore-of-head",
            viewer_request_chirho(
                ViewerStateActionChirho::RestoreChirho,
                KEY_CHIRHO,
                Some(2),
                None,
                Some(2),
            ),
            "earlier retained version",
        ),
        (
            "read-through-write-door",
            viewer_request_chirho(
                ViewerStateActionChirho::ReadChirho,
                KEY_CHIRHO,
                Some(2),
                None,
                None,
            ),
            "write-chirho or restore-chirho",
        ),
    ];
    for (label_chirho, request_chirho, needle_chirho) in cases_chirho {
        let error_chirho =
            write_chirho(&root_chirho, &context_chirho, label_chirho, &request_chirho)
                .expect_err(label_chirho)
                .to_string();
        assert!(
            error_chirho.contains(needle_chirho),
            "{label_chirho}: {error_chirho}"
        );
        assert!(
            !error_chirho.contains(VIEWER_STATE_CONFLICT_SCHEMA_CHIRHO),
            "{label_chirho}: a refusal must not be dressed as a conflict"
        );
    }
    let head_chirho = head_chirho(&root_chirho, &context_chirho);
    assert_eq!(head_chirho.current_chirho.unwrap().version_chirho, 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn conflict_replays_exactly_from_the_effect_log_and_verifies_chirho() {
    let (root_chirho, context_chirho) = two_versions_chirho("conflict-replay-chirho");
    let stale_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        KEY_CHIRHO,
        Some(1),
        Some(b"late draft"),
        None,
    );
    let first_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "late-idem-chirho",
        &stale_chirho,
    )
    .expect("the effect layer carries a conflict as a response");
    verify_effect_chirho(&root_chirho, &first_chirho).expect("the conflict effect verifies");
    let subject_chirho = response_subject_chirho(&stale_chirho, Some(&context_chirho)).unwrap();
    let response_bytes_chirho = dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        &root_chirho,
        &subject_chirho,
        first_chirho.response_chirho.as_ref().unwrap(),
    )
    .expect("the conflict body is a private value of the viewer's key subject");
    let conflict_chirho: ViewerStateConflictChirho =
        serde_json::from_slice(&response_bytes_chirho).unwrap();
    assert_eq!(conflict_chirho.current_version_chirho, Some(2));

    let replay_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "late-idem-chirho",
        &stale_chirho,
    )
    .unwrap();
    assert_eq!(
        replay_chirho, first_chirho,
        "same key, same bytes: the logged conflict replays"
    );
    let head_chirho = head_chirho(&root_chirho, &context_chirho);
    assert_eq!(head_chirho.current_chirho.unwrap().version_chirho, 2);
    assert_eq!(head_chirho.history_chirho.len(), 2);
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// claude2's MOVE finding (#21601): swap the conflict check above the idempotency replay and this
/// arm goes red. A client that timed out and retried with the same key and bytes must be told its
/// write HAPPENED (the original receipt), even though the head has since moved past the version the
/// retry still names — that is the case idempotency keys exist for.
#[test]
fn idempotent_retry_after_apply_returns_the_original_receipt_not_a_conflict_chirho() {
    let root_chirho = test_root_chirho("idempotent-retry-chirho");
    let context_chirho = context_chirho("identity/retry-chirho", "workspace-app-chirho");
    let first_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        KEY_CHIRHO,
        None,
        Some(b"first draft"),
        None,
    );
    let applied_chirho: ViewerStateResponseChirho = serde_json::from_slice(
        &write_chirho(
            &root_chirho,
            &context_chirho,
            "retry-key-chirho",
            &first_chirho,
        )
        .unwrap(),
    )
    .unwrap();
    let original_receipt_chirho = applied_chirho.mutation_receipt_chirho.clone().unwrap();
    assert_eq!(original_receipt_chirho.after_version_chirho, 1);

    // The head moves on (a later save at version 1), so the first request's expected version
    // (None) is now stale.
    let second_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        KEY_CHIRHO,
        Some(1),
        Some(b"second draft"),
        None,
    );
    write_chirho(
        &root_chirho,
        &context_chirho,
        "second-key-chirho",
        &second_chirho,
    )
    .unwrap();

    // The timed-out client retries the FIRST request: same key, same bytes.
    let bytes_chirho = write_chirho(
        &root_chirho,
        &context_chirho,
        "retry-key-chirho",
        &first_chirho,
    )
    .unwrap();
    let raw_chirho: serde_json::Value = serde_json::from_slice(&bytes_chirho).unwrap();
    assert_eq!(
        raw_chirho["schema_chirho"], VIEWER_STATE_RESPONSE_SCHEMA_CHIRHO,
        "a retry of an APPLIED request is an applied answer, never a conflict"
    );
    let replayed_chirho: ViewerStateResponseChirho = serde_json::from_value(raw_chirho).unwrap();
    assert_eq!(
        replayed_chirho.mutation_receipt_chirho.as_ref(),
        Some(&original_receipt_chirho),
        "the retry carries the ORIGINAL receipt (after_version 1), not a new one"
    );
    let head_chirho = head_chirho(&root_chirho, &context_chirho);
    assert_eq!(
        head_chirho.current_chirho.unwrap().version_chirho,
        2,
        "the retry appended nothing"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

/// claude2 (#21601): the door owns "is the caller stale" and the store owns "is the door stale"
/// because the door passes the head it itself read as the store's expected head. That layering is
/// only sound while the door is the store's ONLY production caller — a second consumer would get
/// the store's atomicity and silently not the caller-version contract, and `append_bounded_chirho`
/// is `pub` in a separate crate where nothing would say so. Caller-set facts decay; this pins it.
#[test]
fn append_bounded_has_exactly_one_production_caller_chirho() {
    let callers_chirho: Vec<String> =
        crate::source_scan_chirho::production_source_lines_matching_chirho(
            ".append_bounded_chirho(",
        )
        .into_iter()
        .map(|(file_chirho, _line_chirho, _text_chirho)| file_chirho)
        .collect();
    assert_eq!(
        callers_chirho,
        vec!["src/execution_runtime_chirho/effect_chirho/viewer_state_chirho/mod_chirho.rs".to_string()],
        "append_bounded_chirho must have exactly one production caller, the viewer-state door; a new consumer needs its own caller-stale check and this pin retargeted"
    );
}
