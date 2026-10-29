// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::app_record_signed_message_chirho;

fn hash_chirho(byte_chirho: char) -> HashChirho {
    HashChirho(byte_chirho.to_string().repeat(64))
}

#[test]
fn reviewed_deploy_predicate_excludes_dev_and_removal_actions_chirho() {
    assert!(app_action_is_reviewed_deploy_chirho(
        &AppActionChirho::DeployChirho
    ));
    assert!(!app_action_is_reviewed_deploy_chirho(
        &AppActionChirho::DeployUnreviewedDevChirho
    ));
    assert!(!app_action_is_reviewed_deploy_chirho(
        &AppActionChirho::UndeployChirho
    ));
}

#[test]
fn legacy_app_record_json_and_signed_bytes_stay_exact_chirho() {
    let record_chirho = AppRecordChirho {
        seq_chirho: 3,
        schema_chirho: APP_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "legacyapp".to_string(),
        owner_principal_chirho: "owner/legacyapp-chirho".to_string(),
        dag_chirho: Some(hash_chirho('a')),
        action_chirho: AppActionChirho::DeployChirho,
        at_ms_chirho: 11,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "sig-app-chirho".to_string(),
    };
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        format!(
            "{{\"seq_chirho\":3,\"schema_chirho\":\"app-record-v1-chirho\",\"app_chirho\":\"legacyapp\",\"owner_principal_chirho\":\"owner/legacyapp-chirho\",\"dag_chirho\":\"{}\",\"action_chirho\":\"DeployChirho\",\"at_ms_chirho\":11,\"sig_chirho\":\"sig-app-chirho\"}}",
            "a".repeat(64)
        )
    );
    assert_eq!(
        String::from_utf8(app_record_signed_message_chirho(&record_chirho).unwrap()).unwrap(),
        format!(
            "{{\"seq_chirho\":3,\"schema_chirho\":\"app-record-v1-chirho\",\"app_chirho\":\"legacyapp\",\"owner_principal_chirho\":\"owner/legacyapp-chirho\",\"dag_chirho\":\"{}\",\"action_chirho\":\"DeployChirho\",\"at_ms_chirho\":11}}",
            "a".repeat(64)
        )
    );
}

#[test]
fn app_v2_shape_and_operation_bind_prior_head_chirho() {
    let mut record_chirho = AppRecordChirho {
        seq_chirho: 4,
        schema_chirho: APP_RECORD_V2_SCHEMA_CHIRHO.to_string(),
        app_chirho: "v2app".to_string(),
        owner_principal_chirho: "owner/v2app-chirho".to_string(),
        dag_chirho: Some(hash_chirho('b')),
        action_chirho: AppActionChirho::DeployChirho,
        at_ms_chirho: 12,
        previous_chirho: Some(hash_chirho('a')),
        transition_id_chirho: format!("head-transition-blake3-v1-chirho:{}", "c".repeat(64)),
        prepared_writer_fence_epoch_chirho: Some(7),
        sig_chirho: "sig-v2-chirho".to_string(),
    };
    validate_app_record_transition_shape_chirho(
        &record_chirho,
        "head-transition-blake3-v1-chirho:",
    )
    .unwrap();
    let operation_chirho =
        String::from_utf8(app_head_transition_operation_bytes_chirho(&record_chirho).unwrap())
            .unwrap();
    assert!(operation_chirho.contains(&"a".repeat(64)));
    assert!(operation_chirho.contains(&"b".repeat(64)));
    assert!(operation_chirho.contains("owner/v2app-chirho"));

    record_chirho.action_chirho = AppActionChirho::UndeployChirho;
    assert!(validate_app_record_transition_shape_chirho(
        &record_chirho,
        "head-transition-blake3-v1-chirho:",
    )
    .is_err());
}
