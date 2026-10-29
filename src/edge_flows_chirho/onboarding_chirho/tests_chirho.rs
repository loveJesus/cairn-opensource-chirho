// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::DagChirho;
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-onboarding-test-{nanos_chirho}-{n_chirho}"))
}

pub(super) fn deploy_owned_app_chirho(root_chirho: &Path, name_chirho: &str) -> String {
    let owner_chirho = crate::identity_chirho::register_identity_chirho(
        root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let marker_chirho = crate::cas_chirho::add_chirho(root_chirho, b"node marker").unwrap();
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![marker_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, name_chirho, dag_chirho, &owner_chirho).unwrap();
    owner_chirho
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn resign_onboarding_record_for_test_chirho(
    root_chirho: &Path,
    mut record_chirho: OnboardingRecordChirho,
) -> OnboardingRecordChirho {
    record_chirho.sig_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        root_chirho,
        &onboarding_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    record_chirho
}

fn onboarding_schema_fixture_chirho() -> (PathBuf, OnboardingRecordChirho) {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "schema_demo");
    let (_hash_chirho, _guide_chirho, record_chirho) = set_onboarding_guide_chirho(
        &root_chirho,
        "schema_demo",
        &owner_chirho,
        "Schema guide",
        vec![parse_onboarding_step_spec_chirho("Start=Follow the guide").unwrap()],
    )
    .unwrap();
    (root_chirho, record_chirho)
}

#[test]
fn onboarding_signed_message_bytes_stay_stable_chirho() {
    let record_chirho = OnboardingRecordChirho {
        seq_chirho: 7,
        schema_chirho: ONBOARDING_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "guideapp".to_string(),
        owner_principal_chirho: "owner/test".to_string(),
        guide_chirho: HashChirho("b".repeat(64)),
        previous_chirho: Some(HashChirho("a".repeat(64))),
        at_ms_chirho: 123_456,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "not-signed-for-message".to_string(),
    };

    assert_eq!(
        std::str::from_utf8(&onboarding_record_message_chirho(&record_chirho).unwrap()).unwrap(),
        concat!(
            r#"{"seq_chirho":7,"schema_chirho":"onboarding-record-v1-chirho","#,
            r#""app_chirho":"guideapp","owner_principal_chirho":"owner/test","#,
            r#""guide_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""at_ms_chirho":123456}"#
        )
    );
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        concat!(
            r#"{"seq_chirho":7,"schema_chirho":"onboarding-record-v1-chirho","#,
            r#""app_chirho":"guideapp","owner_principal_chirho":"owner/test","#,
            r#""guide_chirho":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","#,
            r#""previous_chirho":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","#,
            r#""at_ms_chirho":123456,"sig_chirho":"not-signed-for-message"}"#
        )
    );
}

#[test]
fn owner_sets_versioned_onboarding_guide_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "demo");
    let steps_chirho = vec![
        parse_onboarding_step_spec_chirho("Welcome@#app-root=Start here").unwrap(),
        parse_onboarding_step_spec_chirho("Finish=Ship it").unwrap(),
        OnboardingStepChirho {
            title_chirho: "Legacy script safety".to_string(),
            body_chirho: format!("line{}separator", '\u{2028}'),
            target_chirho: None,
        },
    ];

    let (hash_chirho, guide_chirho, record_chirho) = set_onboarding_guide_chirho(
        &root_chirho,
        "demo",
        &owner_chirho,
        "Demo guide",
        steps_chirho,
    )
    .unwrap();

    assert_eq!(record_chirho.seq_chirho, 0);
    assert_eq!(
        record_chirho.schema_chirho,
        ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
    );
    assert!(record_chirho
        .transition_id_chirho
        .starts_with(HEAD_TRANSITION_ID_PREFIX_CHIRHO));
    let receipts_chirho = onboarding_transition_receipts_chirho(&root_chirho);
    assert_eq!(receipts_chirho.len(), 1);
    assert_eq!(
        receipts_chirho[0].prepared_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    assert_eq!(
        receipts_chirho[0].applied_writer_fence_epoch_chirho,
        record_chirho.prepared_writer_fence_epoch_chirho
    );
    assert_eq!(guide_chirho.steps_chirho.len(), 3);
    assert_eq!(
        guide_chirho.steps_chirho[0].target_chirho.as_deref(),
        Some("#app-root")
    );
    let current_chirho = current_onboarding_guide_chirho(&root_chirho, "demo")
        .unwrap()
        .unwrap();
    assert_eq!(current_chirho.0, hash_chirho);
    assert_eq!(
        onboarding_history_chirho(&root_chirho, "demo")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 1);

    let html_chirho = onboarding_kit_html_chirho(&root_chirho, "demo");
    assert!(html_chirho.contains("cairn-onboarding-toggle-chirho"));
    assert!(html_chirho.contains("Demo guide"));
    assert!(html_chirho.contains(&hash_chirho.0));
    assert!(html_chirho.contains("\\u2028"));
    assert!(!html_chirho.contains('\u{2028}'));

    let (next_hash_chirho, next_guide_chirho, next_record_chirho) = set_onboarding_guide_chirho(
        &root_chirho,
        "demo",
        &owner_chirho,
        "Demo guide v2",
        vec![parse_onboarding_step_spec_chirho("One=Updated").unwrap()],
    )
    .unwrap();
    assert_ne!(next_hash_chirho, hash_chirho);
    assert_eq!(
        next_guide_chirho.previous_chirho.as_ref(),
        Some(&hash_chirho)
    );
    assert_eq!(
        next_record_chirho.previous_chirho.as_ref(),
        Some(&hash_chirho)
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

include!("ha2_head_commit_tests_chirho.rs");

#[test]
fn onboarding_records_are_schema_tagged_and_unknown_schema_fails_chirho() {
    let (root_chirho, record_chirho) = onboarding_schema_fixture_chirho();

    assert_eq!(
        record_chirho.schema_chirho,
        ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
    );
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 1);

    let mut bad_record_chirho = record_chirho.clone();
    bad_record_chirho.schema_chirho = "onboarding-record-v9-chirho".to_string();
    bad_record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &onboarding_record_message_chirho(&bad_record_chirho).unwrap(),
    )
    .unwrap();
    write_jsonl_chirho(
        &onboarding_records_path_chirho(&root_chirho),
        std::slice::from_ref(&bad_record_chirho),
    );
    let error_chirho = load_onboarding_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported schema"));
    assert!(verify_onboarding_chirho(&root_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_onboarding_records_without_schema_still_verify_chirho() {
    let (root_chirho, mut record_chirho) = onboarding_schema_fixture_chirho();

    record_chirho.schema_chirho.clear();
    record_chirho.transition_id_chirho.clear();
    record_chirho.prepared_writer_fence_epoch_chirho = None;
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &onboarding_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    write_jsonl_chirho(
        &onboarding_records_path_chirho(&root_chirho),
        std::slice::from_ref(&record_chirho),
    );

    let log_chirho = std::fs::read_to_string(onboarding_records_path_chirho(&root_chirho)).unwrap();
    assert!(!log_chirho.contains("schema_chirho"));
    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 1);
    assert!(load_onboarding_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn onboarding_rejects_non_owner_chirho() {
    let root_chirho = tmp_root_chirho();
    let _owner_chirho = deploy_owned_app_chirho(&root_chirho, "demo");
    let other_chirho = crate::identity_chirho::register_identity_chirho(
        &root_chirho,
        crate::identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;

    let err_chirho = set_onboarding_guide_chirho(
        &root_chirho,
        "demo",
        &other_chirho,
        "Wrong owner",
        vec![parse_onboarding_step_spec_chirho("Step=Body").unwrap()],
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("is owned by"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn onboarding_ref_cannot_authorize_shape_valid_state_outside_signed_history_chirho() {
    let root_chirho = tmp_root_chirho();
    let owner_chirho = deploy_owned_app_chirho(&root_chirho, "unloggedguide");
    let forged_guide_chirho = OnboardingGuideChirho {
        app_chirho: "unloggedguide".to_string(),
        owner_principal_chirho: owner_chirho,
        title_chirho: "Unlogged guide".to_string(),
        steps_chirho: vec![parse_onboarding_step_spec_chirho("Start=Unlogged").unwrap()],
        previous_chirho: None,
        at_ms_chirho: now_ms_chirho(),
    };
    validate_onboarding_guide_chirho(&forged_guide_chirho).unwrap();
    let forged_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &forged_guide_chirho).unwrap();
    refs_chirho::set_branch_chirho(
        &root_chirho,
        &onboarding_ref_chirho("unloggedguide"),
        forged_hash_chirho,
    )
    .unwrap();

    assert_eq!(verify_onboarding_chirho(&root_chirho).unwrap(), 0);
    let error_chirho = current_onboarding_guide_chirho(&root_chirho, "unloggedguide")
        .unwrap_err()
        .to_string();
    assert!(
        error_chirho.contains("does not select verified signed history"),
        "{error_chirho}"
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}
