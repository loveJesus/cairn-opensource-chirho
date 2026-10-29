// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Canonical signed-message bytes for app control-plane records.

use crate::{
    AppActionChirho, AppInputModeChirho, AppInputPolicyRecordChirho, AppKeyAuthorityRecordChirho,
    AppKeyAuthorityRouteChirho, AppRecordChirho, AppRequestAccessPolicyChirho,
    AppRequestAccessPolicyRecordChirho, AppResponsePolicyRecordChirho, AppRouteActionChirho,
    AppRouteRecordChirho, AppRouteRequestBodyPolicyChirho, AppRouteResponsePolicyRecordChirho,
};
use anyhow::Result;
use cairn_core_chirho::model_chirho::HashChirho;
use serde::Serialize;

pub fn app_record_signed_message_chirho(record_chirho: &AppRecordChirho) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        dag_chirho: &'a Option<HashChirho>,
        action_chirho: &'a AppActionChirho,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_chirho: Option<&'a Option<HashChirho>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    let v2_chirho = record_chirho.schema_chirho == crate::APP_RECORD_V2_SCHEMA_CHIRHO;
    Ok(serde_json::to_vec(&AppRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        dag_chirho: &record_chirho.dag_chirho,
        action_chirho: &record_chirho.action_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        previous_chirho: v2_chirho.then_some(&record_chirho.previous_chirho),
        transition_id_chirho: v2_chirho.then_some(record_chirho.transition_id_chirho.as_str()),
        prepared_writer_fence_epoch_chirho: v2_chirho
            .then_some(record_chirho.prepared_writer_fence_epoch_chirho)
            .flatten(),
    })?)
}

pub fn app_route_record_signed_message_chirho(
    record_chirho: &AppRouteRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppRouteRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        route_chirho: &'a str,
        owner_principal_chirho: &'a str,
        dag_chirho: &'a Option<HashChirho>,
        action_chirho: &'a AppRouteActionChirho,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_body_policy_chirho: &'a Option<AppRouteRequestBodyPolicyChirho>,
        at_ms_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        previous_chirho: Option<&'a Option<HashChirho>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        transition_id_chirho: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        prepared_writer_fence_epoch_chirho: Option<u64>,
    }
    let v2_chirho = record_chirho.schema_chirho == crate::APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO;
    Ok(serde_json::to_vec(&AppRouteRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        route_chirho: &record_chirho.route_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        dag_chirho: &record_chirho.dag_chirho,
        action_chirho: &record_chirho.action_chirho,
        request_body_policy_chirho: &record_chirho.request_body_policy_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
        previous_chirho: v2_chirho.then_some(&record_chirho.previous_chirho),
        transition_id_chirho: v2_chirho.then_some(record_chirho.transition_id_chirho.as_str()),
        prepared_writer_fence_epoch_chirho: v2_chirho
            .then_some(record_chirho.prepared_writer_fence_epoch_chirho)
            .flatten(),
    })?)
}

pub fn app_input_policy_record_signed_message_chirho(
    record_chirho: &AppInputPolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppInputPolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        route_chirho: &'a Option<String>,
        owner_principal_chirho: &'a str,
        mode_chirho: &'a AppInputModeChirho,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_body_policy_chirho: &'a Option<AppRouteRequestBodyPolicyChirho>,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&AppInputPolicyRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        route_chirho: &record_chirho.route_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        mode_chirho: &record_chirho.mode_chirho,
        request_body_policy_chirho: &record_chirho.request_body_policy_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

pub fn app_request_access_policy_record_signed_message_chirho(
    record_chirho: &AppRequestAccessPolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppRequestAccessPolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        schema_chirho: &'a str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        root_dag_chirho: &'a HashChirho,
        policy_chirho: &'a AppRequestAccessPolicyChirho,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(
        &AppRequestAccessPolicyRecordMessageChirho {
            seq_chirho: record_chirho.seq_chirho,
            schema_chirho: &record_chirho.schema_chirho,
            app_chirho: &record_chirho.app_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
            root_dag_chirho: &record_chirho.root_dag_chirho,
            policy_chirho: &record_chirho.policy_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?)
}

pub fn app_response_policy_record_signed_message_chirho(
    record_chirho: &AppResponsePolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppResponsePolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        response_content_type_chirho: &'a str,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&AppResponsePolicyRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        response_content_type_chirho: &record_chirho.response_content_type_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

pub fn app_route_response_policy_record_signed_message_chirho(
    record_chirho: &AppRouteResponsePolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppRouteResponsePolicyRecordMessageChirho<'a> {
        seq_chirho: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        schema_chirho: Option<&'a str>,
        app_chirho: &'a str,
        route_chirho: &'a str,
        owner_principal_chirho: &'a str,
        response_content_type_chirho: &'a str,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(
        &AppRouteResponsePolicyRecordMessageChirho {
            seq_chirho: record_chirho.seq_chirho,
            schema_chirho: nonempty_schema_chirho(&record_chirho.schema_chirho),
            app_chirho: &record_chirho.app_chirho,
            route_chirho: &record_chirho.route_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
            response_content_type_chirho: &record_chirho.response_content_type_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
    )?)
}

/// The signed bytes of an app's key-authority record: every field but the signature, routes in the order stored.
pub fn app_key_authority_record_signed_message_chirho(
    record_chirho: &AppKeyAuthorityRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct AppKeyAuthorityRecordMessageChirho<'a> {
        seq_chirho: u64,
        schema_chirho: &'a str,
        app_chirho: &'a str,
        owner_principal_chirho: &'a str,
        routes_chirho: &'a [AppKeyAuthorityRouteChirho],
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&AppKeyAuthorityRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: &record_chirho.schema_chirho,
        app_chirho: &record_chirho.app_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        routes_chirho: &record_chirho.routes_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn nonempty_schema_chirho(schema_chirho: &str) -> Option<&str> {
    (!schema_chirho.is_empty()).then_some(schema_chirho)
}
