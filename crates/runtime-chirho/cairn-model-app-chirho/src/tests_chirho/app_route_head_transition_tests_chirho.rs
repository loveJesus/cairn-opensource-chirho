// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::{app_route_record_signed_message_chirho, AppRouteRequestBodyPolicyChirho};

fn legacy_route_record_chirho() -> AppRouteRecordChirho {
    AppRouteRecordChirho {
        seq_chirho: 7,
        schema_chirho: APP_ROUTE_RECORD_SCHEMA_CHIRHO.to_string(),
        app_chirho: "legacy-app".to_string(),
        route_chirho: "status".to_string(),
        owner_principal_chirho: "owner/legacy".to_string(),
        dag_chirho: Some(HashChirho("a".repeat(64))),
        action_chirho: AppRouteActionChirho::DeployRouteChirho,
        request_body_policy_chirho: None,
        at_ms_chirho: 11,
        previous_chirho: None,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: None,
        sig_chirho: "legacy-signature".to_string(),
    }
}

#[test]
fn legacy_route_json_and_signed_bytes_stay_exact_chirho() {
    let record_chirho = legacy_route_record_chirho();
    let dag_chirho = "a".repeat(64);
    assert_eq!(
        serde_json::to_string(&record_chirho).unwrap(),
        format!(
            "{{\"seq_chirho\":7,\"schema_chirho\":\"app-route-record-v1-chirho\",\"app_chirho\":\"legacy-app\",\"route_chirho\":\"status\",\"owner_principal_chirho\":\"owner/legacy\",\"dag_chirho\":\"{dag_chirho}\",\"action_chirho\":\"DeployRouteChirho\",\"at_ms_chirho\":11,\"sig_chirho\":\"legacy-signature\"}}"
        )
    );
    assert_eq!(
        String::from_utf8(app_route_record_signed_message_chirho(&record_chirho).unwrap()).unwrap(),
        format!(
            "{{\"seq_chirho\":7,\"schema_chirho\":\"app-route-record-v1-chirho\",\"app_chirho\":\"legacy-app\",\"route_chirho\":\"status\",\"owner_principal_chirho\":\"owner/legacy\",\"dag_chirho\":\"{dag_chirho}\",\"action_chirho\":\"DeployRouteChirho\",\"at_ms_chirho\":11}}"
        )
    );
}

#[test]
fn same_dag_policy_and_review_label_have_distinct_state_hashes_chirho() {
    let base_chirho = legacy_route_record_chirho();
    let mut no_body_chirho = base_chirho.clone();
    no_body_chirho.request_body_policy_chirho = Some(AppRouteRequestBodyPolicyChirho::NoBodyChirho);
    let mut unreviewed_chirho = no_body_chirho.clone();
    unreviewed_chirho.action_chirho = AppRouteActionChirho::DeployRouteUnreviewedDevChirho;
    assert_ne!(
        app_route_ref_target_from_record_chirho(&base_chirho).unwrap(),
        app_route_authority_state_hash_chirho(
            &app_route_authority_state_from_record_chirho(&no_body_chirho).unwrap()
        )
        .unwrap()
    );
    assert_ne!(
        app_route_authority_state_hash_chirho(
            &app_route_authority_state_from_record_chirho(&no_body_chirho).unwrap()
        )
        .unwrap(),
        app_route_authority_state_hash_chirho(
            &app_route_authority_state_from_record_chirho(&unreviewed_chirho).unwrap()
        )
        .unwrap()
    );
}
