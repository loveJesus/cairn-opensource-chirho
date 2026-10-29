// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::cas_chirho;
use crate::dag_private_value_chirho;
use crate::effect_chirho::{run_effect_with_context_chirho, SCOPED_WRITE_STORE_SCHEMA_CHIRHO};
use crate::model_chirho::{CapabilityChirho, EffectChirho, RequestContextChirho};
use std::sync::atomic::{AtomicU64, Ordering};

const VIEWER_STATE_ENTRIES_MUTATION_TABLE_CHIRHO: redb::TableDefinition<(&str, u64), &[u8]> =
    redb::TableDefinition::new("viewer_state_entries_chirho");

pub(super) fn test_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-viewer-state-{label_chirho}-{}-{counter_chirho}",
        std::process::id()
    ))
}

pub(super) fn context_chirho(principal_chirho: &str, app_chirho: &str) -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: principal_chirho.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_principal_chirho: "operator/viewer-state-tests-chirho".to_string(),
        client_id_chirho: "viewer-state-tests-chirho".to_string(),
        token_hash_chirho: "viewer-state-token-hash-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

pub(super) fn viewer_request_chirho(
    action_chirho: ViewerStateActionChirho,
    key_chirho: &str,
    expected_current_version_chirho: Option<u64>,
    value_chirho: Option<&[u8]>,
    restore_from_version_chirho: Option<u64>,
) -> ViewerStateRequestChirho {
    ViewerStateRequestChirho {
        schema_chirho: VIEWER_STATE_REQUEST_SCHEMA_CHIRHO.to_string(),
        action_chirho,
        key_chirho: key_chirho.to_string(),
        expected_current_version_chirho,
        value_base64_chirho: value_chirho.map(|value_chirho| BASE64_CHIRHO.encode(value_chirho)),
        restore_from_version_chirho,
    }
}

pub(super) fn run_write_effect_chirho(
    root_chirho: &Path,
    context_chirho: Option<&RequestContextChirho>,
    idempotency_chirho: &str,
    request_chirho: &ViewerStateRequestChirho,
) -> Result<EffectChirho> {
    run_effect_with_context_chirho(
        root_chirho,
        0,
        HashChirho(idempotency_chirho.to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
        &serde_json::to_vec(request_chirho)?,
        context_chirho,
    )
}

pub(super) fn run_read_effect_chirho(
    root_chirho: &Path,
    context_chirho: Option<&RequestContextChirho>,
    idempotency_chirho: &str,
    request_chirho: &ViewerStateRequestChirho,
) -> Result<EffectChirho> {
    run_effect_with_context_chirho(
        root_chirho,
        0,
        HashChirho(idempotency_chirho.to_string()),
        CapabilityChirho::ReadStoreChirho {
            prefix_chirho: VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
        &serde_json::to_vec(request_chirho)?,
        context_chirho,
    )
}

fn response_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    request_chirho: &ViewerStateRequestChirho,
    effect_chirho: &EffectChirho,
) -> ViewerStateResponseChirho {
    let subject_chirho = response_subject_chirho(request_chirho, Some(context_chirho)).unwrap();
    let response_hash_chirho = effect_chirho.response_chirho.as_ref().unwrap();
    let bytes_chirho = dag_private_value_chirho::load_private_dag_value_bytes_chirho(
        root_chirho,
        &subject_chirho,
        response_hash_chirho,
    )
    .unwrap();
    serde_json::from_slice(&bytes_chirho).unwrap()
}

fn bytes_in_files_chirho(root_chirho: &Path, needle_chirho: &[u8]) -> Vec<PathBuf> {
    let mut hits_chirho = Vec::new();
    let Ok(entries_chirho) = std::fs::read_dir(root_chirho) else {
        return hits_chirho;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            hits_chirho.extend(bytes_in_files_chirho(&path_chirho, needle_chirho));
        } else if std::fs::read(&path_chirho).is_ok_and(|bytes_chirho| {
            bytes_chirho
                .windows(needle_chirho.len())
                .any(|window_chirho| window_chirho == needle_chirho)
        }) {
            hits_chirho.push(path_chirho);
        }
    }
    hits_chirho
}

fn copy_tree_chirho(source_chirho: &Path, destination_chirho: &Path) {
    std::fs::create_dir_all(destination_chirho).unwrap();
    for entry_chirho in std::fs::read_dir(source_chirho).unwrap() {
        let entry_chirho = entry_chirho.unwrap();
        let source_path_chirho = entry_chirho.path();
        let destination_path_chirho = destination_chirho.join(entry_chirho.file_name());
        if source_path_chirho.is_dir() {
            copy_tree_chirho(&source_path_chirho, &destination_path_chirho);
        } else {
            std::fs::copy(&source_path_chirho, &destination_path_chirho).unwrap();
        }
    }
}

fn remove_viewer_state_entry_without_head_chirho(
    root_chirho: &Path,
    physical_key_chirho: &str,
    version_chirho: u64,
) {
    let database_chirho = redb::Database::create(viewer_state_path_chirho(root_chirho)).unwrap();
    let mut transaction_chirho = database_chirho.begin_write().unwrap();
    transaction_chirho.set_durability(redb::Durability::Immediate);
    {
        let mut entries_chirho = transaction_chirho
            .open_table(VIEWER_STATE_ENTRIES_MUTATION_TABLE_CHIRHO)
            .unwrap();
        assert!(entries_chirho
            .remove((physical_key_chirho, version_chirho))
            .unwrap()
            .is_some());
    }
    transaction_chirho.commit().unwrap();
}

fn head_transition_chirho(
    expected_chirho: Option<&ViewerStateHeadChirho>,
    next_version_chirho: u64,
    next_digest_chirho: HashChirho,
) -> ViewerStateHeadTransitionChirho {
    ViewerStateHeadTransitionChirho {
        expected_chirho: expected_chirho.cloned(),
        next_chirho: ViewerStateHeadChirho {
            version_chirho: next_version_chirho,
            receipt_digest_chirho: next_digest_chirho,
        },
    }
}

fn append_tampered_second_row_chirho(
    label_chirho: &str,
    mutate_chirho: impl FnOnce(&mut ViewerStateStoredRowChirho),
    resign_chirho: bool,
) -> (PathBuf, RequestContextChirho) {
    let root_chirho = test_root_chirho(label_chirho);
    let context_chirho =
        context_chirho(&format!("identity/{label_chirho}"), "workspace-app-chirho");
    let request_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(b"Original"),
        None,
    );
    run_write_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &request_chirho,
        &serde_json::to_vec(&request_chirho).unwrap(),
        &HashChirho(format!("{label_chirho}-v1-chirho")),
        Some(&context_chirho),
    )
    .unwrap();
    let physical_key_chirho =
        physical_key_chirho(&context_chirho, "workspace-profile-chirho").unwrap();
    let store_chirho = open_store_chirho(&root_chirho).unwrap();
    let mut row_chirho: ViewerStateStoredRowChirho = serde_json::from_slice(
        &store_chirho
            .exact_chirho(&physical_key_chirho, 1)
            .unwrap()
            .unwrap()
            .value_chirho,
    )
    .unwrap();
    let expected_head_chirho = store_chirho
        .head_chirho(&physical_key_chirho)
        .unwrap()
        .unwrap();
    row_chirho.receipt_chirho.before_version_chirho = Some(1);
    row_chirho.receipt_chirho.predecessor_receipt_digest_chirho =
        expected_head_chirho.receipt_digest_chirho.clone();
    row_chirho.receipt_chirho.after_version_chirho = 2;
    mutate_chirho(&mut row_chirho);
    if resign_chirho {
        row_chirho.receipt_chirho.sig_chirho = signer_chirho::sign_message_chirho(
            &root_chirho,
            &receipt_message_chirho(&row_chirho.receipt_chirho).unwrap(),
        )
        .unwrap();
    }
    let next_receipt_digest_chirho = receipt_digest_chirho(&row_chirho.receipt_chirho).unwrap();
    store_chirho
        .append_bounded_chirho(
            &viewer_prefix_chirho(&context_chirho),
            &physical_key_chirho,
            &head_transition_chirho(Some(&expected_head_chirho), 2, next_receipt_digest_chirho),
            &serde_json::to_vec(&row_chirho).unwrap(),
            VIEWER_STATE_HISTORY_LIMIT_CHIRHO,
            VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64,
        )
        .unwrap();
    drop(store_chirho);
    (root_chirho, context_chirho)
}

fn tampered_read_error_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
) -> anyhow::Error {
    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        "workspace-profile-chirho",
        None,
        None,
        None,
    );
    run_read_chirho(
        root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &read_chirho,
        Some(context_chirho),
    )
    .unwrap_err()
}

#[test]
fn anonymous_viewer_state_refuses_before_state_or_effect_persistence_chirho() {
    let root_chirho = test_root_chirho("anonymous-chirho");
    let request_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(b"private workspace"),
        None,
    );
    let error_chirho = run_write_effect_chirho(
        &root_chirho,
        None,
        "anonymous-viewer-write-chirho",
        &request_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("requires an authenticated request"));
    assert!(!viewer_state_path_chirho(&root_chirho).exists());
    assert!(!root_chirho.join("effects-chirho").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_isolated_restore_appends_and_does_not_move_global_view_chirho() {
    let root_chirho = test_root_chirho("restore-chirho");
    let alice_chirho = context_chirho("identity/alice-chirho", "workspace-app-chirho");
    let bob_chirho = context_chirho("identity/bob-chirho", "workspace-app-chirho");
    let first_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(b"First name"),
        None,
    );
    let second_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        Some(1),
        Some(b"Second name"),
        None,
    );
    run_write_effect_chirho(
        &root_chirho,
        Some(&alice_chirho),
        "alice-v1-chirho",
        &first_chirho,
    )
    .unwrap();
    run_write_effect_chirho(
        &root_chirho,
        Some(&alice_chirho),
        "alice-v2-chirho",
        &second_chirho,
    )
    .unwrap();

    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        "workspace-profile-chirho",
        None,
        None,
        None,
    );
    let bob_effect_chirho = run_read_effect_chirho(
        &root_chirho,
        Some(&bob_chirho),
        "bob-read-chirho",
        &read_chirho,
    )
    .unwrap();
    assert!(
        response_chirho(&root_chirho, &bob_chirho, &read_chirho, &bob_effect_chirho)
            .current_chirho
            .is_none()
    );
    let other_app_chirho = context_chirho("identity/alice-chirho", "other-workspace-app-chirho");
    let other_app_effect_chirho = run_read_effect_chirho(
        &root_chirho,
        Some(&other_app_chirho),
        "other-app-read-chirho",
        &read_chirho,
    )
    .unwrap();
    assert!(response_chirho(
        &root_chirho,
        &other_app_chirho,
        &read_chirho,
        &other_app_effect_chirho,
    )
    .current_chirho
    .is_none());

    let bob_write_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(b"Bob name"),
        None,
    );
    run_write_effect_chirho(
        &root_chirho,
        Some(&bob_chirho),
        "bob-v1-chirho",
        &bob_write_chirho,
    )
    .unwrap();
    let bob_foreign_restore_chirho = viewer_request_chirho(
        ViewerStateActionChirho::RestoreChirho,
        "workspace-profile-chirho",
        Some(1),
        None,
        Some(2),
    );
    assert!(run_write_effect_chirho(
        &root_chirho,
        Some(&bob_chirho),
        "bob-foreign-restore-chirho",
        &bob_foreign_restore_chirho,
    )
    .unwrap_err()
    .to_string()
    .contains("not retained"));

    let restore_chirho = viewer_request_chirho(
        ViewerStateActionChirho::RestoreChirho,
        "workspace-profile-chirho",
        Some(2),
        None,
        Some(1),
    );
    let restored_effect_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&alice_chirho),
        "alice-restore-chirho",
        &restore_chirho,
    )
    .unwrap();
    let restored_chirho = response_chirho(
        &root_chirho,
        &alice_chirho,
        &restore_chirho,
        &restored_effect_chirho,
    );
    let current_chirho = restored_chirho.current_chirho.as_ref().unwrap();
    assert_eq!(current_chirho.version_chirho, 3);
    assert_eq!(
        BASE64_CHIRHO
            .decode(&current_chirho.value_base64_chirho)
            .unwrap(),
        b"First name"
    );
    assert_eq!(
        restored_chirho
            .history_chirho
            .iter()
            .map(|version_chirho| version_chirho.version_chirho)
            .collect::<Vec<_>>(),
        vec![3, 2, 1]
    );
    let receipt_chirho = restored_chirho.mutation_receipt_chirho.as_ref().unwrap();
    assert_eq!(
        receipt_chirho.action_chirho,
        ViewerStateActionChirho::RestoreChirho
    );
    assert_eq!(receipt_chirho.before_version_chirho, Some(2));
    assert_eq!(receipt_chirho.after_version_chirho, 3);
    assert_eq!(receipt_chirho.restored_from_version_chirho, Some(1));
    assert_eq!(
        receipt_chirho.actor_principal_digest_chirho,
        actor_digest_chirho(&alice_chirho)
    );
    assert!(!receipt_chirho.sig_chirho.is_empty());

    let bob_after_restore_effect_chirho = run_read_effect_chirho(
        &root_chirho,
        Some(&bob_chirho),
        "bob-read-after-alice-restore-chirho",
        &read_chirho,
    )
    .unwrap();
    let bob_after_restore_chirho = response_chirho(
        &root_chirho,
        &bob_chirho,
        &read_chirho,
        &bob_after_restore_effect_chirho,
    );
    assert_eq!(
        BASE64_CHIRHO
            .decode(
                &bob_after_restore_chirho
                    .current_chirho
                    .as_ref()
                    .unwrap()
                    .value_base64_chirho
            )
            .unwrap(),
        b"Bob name"
    );
    assert_eq!(bob_after_restore_chirho.history_chirho.len(), 1);

    assert!(!root_chirho.join("versioned-chirho.redb").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_effect_replay_is_exact_and_conflicting_reuse_refuses_chirho() {
    let root_chirho = test_root_chirho("idempotency-chirho");
    let context_chirho = context_chirho("identity/replay-chirho", "workspace-app-chirho");
    let request_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(b"Stable name"),
        None,
    );
    let first_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "same-idem-chirho",
        &request_chirho,
    )
    .unwrap();
    let replay_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "same-idem-chirho",
        &request_chirho,
    )
    .unwrap();
    assert_eq!(replay_chirho, first_chirho);

    let changed_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        Some(1),
        Some(b"Different name"),
        None,
    );
    assert!(run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "same-idem-chirho",
        &changed_chirho,
    )
    .unwrap_err()
    .to_string()
    .contains("different request"));

    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        "workspace-profile-chirho",
        None,
        None,
        None,
    );
    let effect_chirho = run_read_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "replay-read-chirho",
        &read_chirho,
    )
    .unwrap();
    assert_eq!(
        response_chirho(&root_chirho, &context_chirho, &read_chirho, &effect_chirho)
            .history_chirho
            .len(),
        1
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn stale_write_and_retired_restore_refuse_without_mutation_chirho() {
    let root_chirho = test_root_chirho("bounded-chirho");
    let context_chirho = context_chirho("identity/bounded-chirho", "workspace-app-chirho");
    for version_chirho in 1..=17_u64 {
        let request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::WriteChirho,
            "workspace-profile-chirho",
            (version_chirho > 1).then_some(version_chirho - 1),
            Some(format!("name-{version_chirho}").as_bytes()),
            None,
        );
        run_write_chirho(
            &root_chirho,
            VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
            &request_chirho,
            &serde_json::to_vec(&request_chirho).unwrap(),
            &HashChirho(format!("bounded-{version_chirho}-chirho")),
            Some(&context_chirho),
        )
        .unwrap();
    }
    let stale_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        Some(16),
        Some(b"stale"),
        None,
    );
    // Retargeted 2026-09-08: a stale expected version is a typed CONFLICT (nothing appended),
    // not a refusal — see conflict_tests_chirho.rs. If this ever returns an Err again, the
    // conflict road regressed; if it appends, the head guard regressed.
    let stale_output_chirho = run_write_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &stale_chirho,
        &serde_json::to_vec(&stale_chirho).unwrap(),
        &HashChirho("stale-chirho".to_string()),
        Some(&context_chirho),
    )
    .unwrap();
    let stale_conflict_chirho: ViewerStateConflictChirho =
        serde_json::from_slice(&stale_output_chirho.response_chirho).unwrap();
    assert_eq!(stale_conflict_chirho.current_version_chirho, Some(17));

    let retired_restore_chirho = viewer_request_chirho(
        ViewerStateActionChirho::RestoreChirho,
        "workspace-profile-chirho",
        Some(17),
        None,
        Some(1),
    );
    assert!(run_write_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &retired_restore_chirho,
        &serde_json::to_vec(&retired_restore_chirho).unwrap(),
        &HashChirho("retired-restore-chirho".to_string()),
        Some(&context_chirho),
    )
    .unwrap_err()
    .to_string()
    .contains("not retained"));

    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        "workspace-profile-chirho",
        None,
        None,
        None,
    );
    let response_chirho = run_read_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &read_chirho,
        Some(&context_chirho),
    )
    .unwrap();
    let decoded_chirho: ViewerStateResponseChirho =
        serde_json::from_slice(&response_chirho.response_chirho).unwrap();
    assert_eq!(decoded_chirho.history_chirho.len(), 16);
    assert_eq!(decoded_chirho.current_chirho.unwrap().version_chirho, 17);
    assert_eq!(
        decoded_chirho.history_chirho.last().unwrap().version_chirho,
        2
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn tampered_receipt_refuses_the_entire_view_chirho() {
    let (root_chirho, context_chirho) =
        append_tampered_second_row_chirho("tamper-signature-chirho", |_| {}, false);
    let error_chirho = tampered_read_error_chirho(&root_chirho, &context_chirho);
    assert!(
        error_chirho.to_string().contains("signature"),
        "unexpected tamper refusal: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn signed_receipt_binding_and_restore_semantics_are_verified_chirho() {
    let (binding_root_chirho, binding_context_chirho) = append_tampered_second_row_chirho(
        "tamper-binding-chirho",
        |row_chirho| {
            row_chirho.receipt_chirho.key_digest_chirho =
                HashChirho("wrong-key-digest-chirho".to_string());
        },
        true,
    );
    assert!(
        tampered_read_error_chirho(&binding_root_chirho, &binding_context_chirho)
            .to_string()
            .contains("binding invalid")
    );
    let _ = std::fs::remove_dir_all(binding_root_chirho);

    let (restore_root_chirho, restore_context_chirho) = append_tampered_second_row_chirho(
        "tamper-restore-chirho",
        |row_chirho| {
            row_chirho.receipt_chirho.action_chirho = ViewerStateActionChirho::RestoreChirho;
            row_chirho.receipt_chirho.restored_from_version_chirho = Some(1);
        },
        true,
    );
    assert!(
        tampered_read_error_chirho(&restore_root_chirho, &restore_context_chirho)
            .to_string()
            .contains("target is not an earlier version")
    );
    let _ = std::fs::remove_dir_all(restore_root_chirho);
}

#[test]
fn tampered_sealed_value_refuses_the_entire_view_chirho() {
    let (root_chirho, context_chirho) = append_tampered_second_row_chirho(
        "tamper-seal-chirho",
        |row_chirho| {
            row_chirho.sealed_chirho.blob_chirho.mac_chirho.push('A');
        },
        true,
    );
    let error_chirho = tampered_read_error_chirho(&root_chirho, &context_chirho);
    assert!(
        error_chirho.to_string().contains("receipt binding invalid"),
        "unexpected sealed-value refusal: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn valid_sealed_envelope_substitution_refuses_the_entire_view_chirho() {
    let root_chirho = test_root_chirho("substituted-sealed-envelope-chirho");
    let context_chirho = context_chirho(
        "identity/substituted-sealed-envelope-chirho",
        "workspace-app-chirho",
    );
    for (version_chirho, value_chirho) in [(1_u64, b"Original".as_slice()), (2, b"Replacement")] {
        let request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::WriteChirho,
            "workspace-profile-chirho",
            version_chirho
                .checked_sub(1)
                .filter(|version_chirho| *version_chirho > 0),
            Some(value_chirho),
            None,
        );
        run_write_chirho(
            &root_chirho,
            VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
            &request_chirho,
            &serde_json::to_vec(&request_chirho).unwrap(),
            &HashChirho(format!("substituted-envelope-v{version_chirho}-chirho")),
            Some(&context_chirho),
        )
        .unwrap();
    }

    let physical_key_chirho =
        physical_key_chirho(&context_chirho, "workspace-profile-chirho").unwrap();
    let store_chirho = open_store_chirho(&root_chirho).unwrap();
    let first_row_chirho: ViewerStateStoredRowChirho = serde_json::from_slice(
        &store_chirho
            .exact_chirho(&physical_key_chirho, 1)
            .unwrap()
            .unwrap()
            .value_chirho,
    )
    .unwrap();
    let mut substituted_row_chirho: ViewerStateStoredRowChirho = serde_json::from_slice(
        &store_chirho
            .exact_chirho(&physical_key_chirho, 2)
            .unwrap()
            .unwrap()
            .value_chirho,
    )
    .unwrap();
    let expected_head_chirho = store_chirho
        .head_chirho(&physical_key_chirho)
        .unwrap()
        .unwrap();
    assert_ne!(
        first_row_chirho.receipt_chirho.sealed_value_digest_chirho,
        substituted_row_chirho
            .receipt_chirho
            .sealed_value_digest_chirho
    );
    substituted_row_chirho.sealed_chirho = first_row_chirho.sealed_chirho;
    substituted_row_chirho.receipt_chirho.before_version_chirho = Some(2);
    substituted_row_chirho
        .receipt_chirho
        .predecessor_receipt_digest_chirho = expected_head_chirho.receipt_digest_chirho.clone();
    substituted_row_chirho.receipt_chirho.after_version_chirho = 3;
    substituted_row_chirho.receipt_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &receipt_message_chirho(&substituted_row_chirho.receipt_chirho).unwrap(),
    )
    .unwrap();
    let next_receipt_digest_chirho =
        receipt_digest_chirho(&substituted_row_chirho.receipt_chirho).unwrap();
    store_chirho
        .append_bounded_chirho(
            &viewer_prefix_chirho(&context_chirho),
            &physical_key_chirho,
            &head_transition_chirho(Some(&expected_head_chirho), 3, next_receipt_digest_chirho),
            &serde_json::to_vec(&substituted_row_chirho).unwrap(),
            VIEWER_STATE_HISTORY_LIMIT_CHIRHO,
            VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64,
        )
        .unwrap();
    drop(store_chirho);

    let error_chirho = tampered_read_error_chirho(&root_chirho, &context_chirho);
    assert!(
        error_chirho.to_string().contains("receipt binding invalid"),
        "unexpected sealed-envelope substitution refusal: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn valid_transition_from_a_fork_cannot_splice_onto_another_predecessor_chirho() {
    let root_chirho = test_root_chirho("fork-splice-main-chirho");
    let fork_chirho = test_root_chirho("fork-splice-other-chirho");
    let context_chirho = context_chirho("identity/fork-splice-chirho", "workspace-app-chirho");
    let logical_key_chirho = "workspace-profile-chirho";

    for (version_chirho, value_chirho) in [
        (1_u64, b"common-v1".as_slice()),
        (2, b"common-v2"),
        (3, b"common-v3"),
    ] {
        let common_request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::WriteChirho,
            logical_key_chirho,
            version_chirho
                .checked_sub(1)
                .filter(|version_chirho| *version_chirho > 0),
            Some(value_chirho),
            None,
        );
        run_write_chirho(
            &root_chirho,
            VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
            &common_request_chirho,
            &serde_json::to_vec(&common_request_chirho).unwrap(),
            &HashChirho(format!("fork-splice-common-v{version_chirho}-chirho")),
            Some(&context_chirho),
        )
        .unwrap();
    }
    copy_tree_chirho(&root_chirho, &fork_chirho);

    let main_fourth_chirho = viewer_request_chirho(
        ViewerStateActionChirho::RestoreChirho,
        logical_key_chirho,
        Some(3),
        None,
        Some(1),
    );
    run_write_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &main_fourth_chirho,
        &serde_json::to_vec(&main_fourth_chirho).unwrap(),
        &HashChirho("fork-splice-main-v4-chirho".to_string()),
        Some(&context_chirho),
    )
    .unwrap();

    for (version_chirho, restore_from_chirho) in [(4_u64, 2_u64), (5, 3)] {
        let fork_request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::RestoreChirho,
            logical_key_chirho,
            Some(version_chirho - 1),
            None,
            Some(restore_from_chirho),
        );
        run_write_chirho(
            &fork_chirho,
            VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
            &fork_request_chirho,
            &serde_json::to_vec(&fork_request_chirho).unwrap(),
            &HashChirho(format!("fork-splice-fork-v{version_chirho}-chirho")),
            Some(&context_chirho),
        )
        .unwrap();
    }

    let physical_key_chirho = physical_key_chirho(&context_chirho, logical_key_chirho).unwrap();
    let fork_store_chirho = open_store_chirho(&fork_chirho).unwrap();
    let fork_fifth_row_chirho: ViewerStateStoredRowChirho = serde_json::from_slice(
        &fork_store_chirho
            .exact_chirho(&physical_key_chirho, 5)
            .unwrap()
            .unwrap()
            .value_chirho,
    )
    .unwrap();
    verify_receipt_chirho(
        &root_chirho,
        &context_chirho,
        &physical_key_chirho,
        5,
        &fork_fifth_row_chirho.sealed_chirho,
        &fork_fifth_row_chirho.receipt_chirho,
    )
    .unwrap();
    assert!(store_seal_chirho::unseal_store_value_chirho(
        &root_chirho,
        &fork_fifth_row_chirho.sealed_chirho,
    )
    .is_ok());
    drop(fork_store_chirho);
    let fork_predecessor_head_chirho = ViewerStateHeadChirho {
        version_chirho: 4,
        receipt_digest_chirho: fork_fifth_row_chirho
            .receipt_chirho
            .predecessor_receipt_digest_chirho
            .clone(),
    };
    let fork_fifth_digest_chirho =
        receipt_digest_chirho(&fork_fifth_row_chirho.receipt_chirho).unwrap();
    let main_store_chirho = open_store_chirho(&root_chirho).unwrap();
    let error_chirho = main_store_chirho
        .append_bounded_chirho(
            &viewer_prefix_chirho(&context_chirho),
            &physical_key_chirho,
            &head_transition_chirho(
                Some(&fork_predecessor_head_chirho),
                5,
                fork_fifth_digest_chirho,
            ),
            &serde_json::to_vec(&fork_fifth_row_chirho).unwrap(),
            VIEWER_STATE_HISTORY_LIMIT_CHIRHO,
            VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64,
        )
        .expect_err("a valid fork transition must not follow a different authoritative head");
    assert!(
        error_chirho
            .to_string()
            .contains("authoritative head changed"),
        "unexpected fork-splice refusal: {error_chirho:#}"
    );
    drop(main_store_chirho);

    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        logical_key_chirho,
        None,
        None,
        None,
    );
    let response_chirho = run_read_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &read_chirho,
        Some(&context_chirho),
    )
    .unwrap();
    let decoded_chirho: ViewerStateResponseChirho =
        serde_json::from_slice(&response_chirho.response_chirho).unwrap();
    assert_eq!(decoded_chirho.current_chirho.unwrap().version_chirho, 4);

    let _ = std::fs::remove_dir_all(root_chirho);
    let _ = std::fs::remove_dir_all(fork_chirho);
}

#[test]
fn truncating_to_an_older_valid_receipt_prefix_refuses_chirho() {
    let root_chirho = test_root_chirho("truncated-receipt-prefix-chirho");
    let context_chirho = context_chirho(
        "identity/truncated-receipt-prefix-chirho",
        "workspace-app-chirho",
    );
    let logical_key_chirho = "workspace-profile-chirho";
    for version_chirho in 1..=3_u64 {
        let request_chirho = viewer_request_chirho(
            ViewerStateActionChirho::WriteChirho,
            logical_key_chirho,
            version_chirho
                .checked_sub(1)
                .filter(|version_chirho| *version_chirho > 0),
            Some(format!("valid-v{version_chirho}").as_bytes()),
            None,
        );
        run_write_chirho(
            &root_chirho,
            VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
            &request_chirho,
            &serde_json::to_vec(&request_chirho).unwrap(),
            &HashChirho(format!("truncated-prefix-v{version_chirho}-chirho")),
            Some(&context_chirho),
        )
        .unwrap();
    }
    let physical_key_chirho = physical_key_chirho(&context_chirho, logical_key_chirho).unwrap();
    let store_chirho = open_store_chirho(&root_chirho).unwrap();
    assert!(store_chirho
        .exact_chirho(&physical_key_chirho, 2)
        .unwrap()
        .is_some());
    drop(store_chirho);
    remove_viewer_state_entry_without_head_chirho(&root_chirho, &physical_key_chirho, 3);

    let read_chirho = viewer_request_chirho(
        ViewerStateActionChirho::ReadChirho,
        logical_key_chirho,
        None,
        None,
        None,
    );
    let error_chirho = run_read_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &read_chirho,
        Some(&context_chirho),
    )
    .expect_err("a valid older prefix must not replace the recorded latest receipt");
    assert!(
        error_chirho
            .to_string()
            .contains("authoritative head disagrees"),
        "unexpected truncation refusal: {error_chirho:#}"
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn alternate_valid_first_receipt_with_openable_payload_cannot_reclaim_genesis_chirho() {
    let root_chirho = test_root_chirho("genesis-main-chirho");
    let context_chirho = context_chirho("identity/genesis-chirho", "workspace-app-chirho");
    let logical_key_chirho = "workspace-profile-chirho";
    let request_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        logical_key_chirho,
        None,
        Some(b"authoritative-v1"),
        None,
    );
    run_write_chirho(
        &root_chirho,
        VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO,
        &request_chirho,
        &serde_json::to_vec(&request_chirho).unwrap(),
        &HashChirho("genesis-main-v1-chirho".to_string()),
        Some(&context_chirho),
    )
    .unwrap();

    let physical_key_chirho = physical_key_chirho(&context_chirho, logical_key_chirho).unwrap();
    let main_store_chirho = open_store_chirho(&root_chirho).unwrap();
    let authoritative_head_chirho = main_store_chirho
        .head_chirho(&physical_key_chirho)
        .unwrap()
        .unwrap();
    let mut alternate_first_row_chirho: ViewerStateStoredRowChirho = serde_json::from_slice(
        &main_store_chirho
            .exact_chirho(&physical_key_chirho, 1)
            .unwrap()
            .unwrap()
            .value_chirho,
    )
    .unwrap();
    assert!(store_seal_chirho::unseal_store_value_chirho(
        &root_chirho,
        &alternate_first_row_chirho.sealed_chirho,
    )
    .is_ok());
    alternate_first_row_chirho.receipt_chirho.idempotency_chirho = HashChirho(
        blake3::hash(b"alternate-genesis-idempotency-chirho")
            .to_hex()
            .to_string(),
    );
    alternate_first_row_chirho
        .receipt_chirho
        .request_digest_chirho = HashChirho(
        blake3::hash(b"alternate-genesis-request-chirho")
            .to_hex()
            .to_string(),
    );
    alternate_first_row_chirho.receipt_chirho.at_ms_chirho = alternate_first_row_chirho
        .receipt_chirho
        .at_ms_chirho
        .checked_add(1)
        .unwrap();
    alternate_first_row_chirho.receipt_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &receipt_message_chirho(&alternate_first_row_chirho.receipt_chirho).unwrap(),
    )
    .unwrap();
    verify_receipt_chirho(
        &root_chirho,
        &context_chirho,
        &physical_key_chirho,
        1,
        &alternate_first_row_chirho.sealed_chirho,
        &alternate_first_row_chirho.receipt_chirho,
    )
    .unwrap();
    assert_eq!(
        alternate_first_row_chirho
            .receipt_chirho
            .predecessor_receipt_digest_chirho,
        genesis_receipt_digest_chirho(&context_chirho, &physical_key_chirho).unwrap()
    );
    let alternate_first_digest_chirho =
        receipt_digest_chirho(&alternate_first_row_chirho.receipt_chirho).unwrap();
    assert_ne!(
        alternate_first_digest_chirho,
        authoritative_head_chirho.receipt_digest_chirho
    );
    let error_chirho = main_store_chirho
        .append_bounded_chirho(
            &viewer_prefix_chirho(&context_chirho),
            &physical_key_chirho,
            &head_transition_chirho(None, 1, alternate_first_digest_chirho),
            &serde_json::to_vec(&alternate_first_row_chirho).unwrap(),
            VIEWER_STATE_HISTORY_LIMIT_CHIRHO,
            VIEWER_STATE_MAX_KEYS_PER_VIEWER_CHIRHO as u64,
        )
        .expect_err("a second valid first receipt must not reclaim a key's genesis");
    assert!(
        error_chirho
            .to_string()
            .contains("authoritative head changed"),
        "unexpected alternate-genesis refusal: {error_chirho:#}"
    );
    drop(main_store_chirho);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn viewer_state_request_response_and_value_never_rest_in_public_cas_chirho() {
    let root_chirho = test_root_chirho("privacy-chirho");
    let context_chirho = context_chirho("identity/privacy-chirho", "workspace-app-chirho");
    let needle_chirho = b"viewer-private-needle-845779-chirho";
    let request_chirho = viewer_request_chirho(
        ViewerStateActionChirho::WriteChirho,
        "workspace-profile-chirho",
        None,
        Some(needle_chirho),
        None,
    );
    let request_bytes_chirho = serde_json::to_vec(&request_chirho).unwrap();
    let effect_chirho = run_write_effect_chirho(
        &root_chirho,
        Some(&context_chirho),
        "private-write-chirho",
        &request_chirho,
    )
    .unwrap();
    let subject_chirho = response_subject_chirho(&request_chirho, Some(&context_chirho)).unwrap();
    assert!(cas_chirho::get_chirho(&root_chirho, &effect_chirho.request_chirho).is_err());
    assert!(cas_chirho::get_chirho(
        &root_chirho,
        effect_chirho.response_chirho.as_ref().unwrap()
    )
    .is_err());
    assert_eq!(
        dag_private_value_chirho::load_private_dag_value_bytes_chirho(
            &root_chirho,
            &subject_chirho,
            &effect_chirho.request_chirho,
        )
        .unwrap(),
        request_bytes_chirho
    );
    assert!(bytes_in_files_chirho(&root_chirho, needle_chirho).is_empty());
    assert!(
        bytes_in_files_chirho(&root_chirho, BASE64_CHIRHO.encode(needle_chirho).as_bytes())
            .is_empty()
    );
    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn reserved_viewer_namespace_cannot_fall_through_legacy_store_shapes_chirho() {
    let root_chirho = test_root_chirho("reserved-chirho");
    let raw_error_chirho = run_effect_with_context_chirho(
        &root_chirho,
        0,
        HashChirho("reserved-raw-chirho".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: VIEWER_STATE_CAPABILITY_PREFIX_CHIRHO.to_string(),
        },
        b"not a viewer-state request",
        None,
    )
    .unwrap_err();
    assert!(raw_error_chirho
        .to_string()
        .contains("reserved viewer-state capability prefix"));

    let scoped_chirho = crate::effect_chirho::ScopedWriteStoreRequestChirho {
        schema_chirho: SCOPED_WRITE_STORE_SCHEMA_CHIRHO.to_string(),
        key_chirho: "viewer-state-chirho/forged-chirho".to_string(),
        value_base64_chirho: BASE64_CHIRHO.encode(b"forged"),
    };
    assert!(run_effect_with_context_chirho(
        &root_chirho,
        0,
        HashChirho("reserved-scoped-chirho".to_string()),
        CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "".to_string(),
        },
        &serde_json::to_vec(&scoped_chirho).unwrap(),
        None,
    )
    .unwrap_err()
    .to_string()
    .contains("cannot address the viewer-state namespace"));
    let _ = std::fs::remove_dir_all(root_chirho);
}
