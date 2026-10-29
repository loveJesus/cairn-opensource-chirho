// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! Pure app and route control-plane records.

use cairn_core_chirho::model_chirho::HashChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const APP_RECORD_SCHEMA_CHIRHO: &str = "app-record-v1-chirho";
pub const APP_RECORD_V2_SCHEMA_CHIRHO: &str = "app-record-v2-chirho";
pub const APP_ROUTE_RECORD_SCHEMA_CHIRHO: &str = "app-route-record-v1-chirho";
pub const APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO: &str = "app-route-record-v2-chirho";
pub const APP_ROUTE_AUTHORITY_STATE_SCHEMA_CHIRHO: &str = "app-route-authority-state-v1-chirho";
pub const APP_REQUEST_ACCESS_POLICY_RECORD_SCHEMA_CHIRHO: &str =
    "app-request-access-policy-record-v1-chirho";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppActionChirho {
    DeployChirho,
    DeployUnreviewedDevChirho,
    UndeployChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub dag_chirho: Option<HashChirho>,
    pub action_chirho: AppActionChirho,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppStatusChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: Option<String>,
    pub dag_chirho: Option<HashChirho>,
    pub routes_chirho: BTreeMap<String, HashChirho>,
    pub active_chirho: bool,
    pub records_chirho: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppRequestAccessPolicyChirho {
    #[default]
    PublicChirho,
    AuthenticatedChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRequestAccessPolicyRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub root_dag_chirho: HashChirho,
    pub policy_chirho: AppRequestAccessPolicyChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppRouteActionChirho {
    DeployRouteChirho,
    DeployRouteUnreviewedDevChirho,
    UndeployRouteChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppRouteRequestBodyPolicyChirho {
    AcceptBodyChirho,
    NoBodyChirho,
}

impl AppRouteRequestBodyPolicyChirho {
    pub fn accepts_request_body_chirho(&self) -> bool {
        matches!(self, Self::AcceptBodyChirho)
    }
}

/// A named route's opening to limited keys, as its reviewed manifest declares it: the route accepts a limited key that
/// holds a grant for `action_chirho` naming this route, and such a key may touch only the logical viewer-state
/// resources its grant consented to, which issuance takes from `resources_chirho`. Absent means closed. The signed,
/// persisted form is the app's
/// key-authority record, never the route record: engines before limited keys verify a route record over the fields
/// they know, and a new signed field would make them refuse the whole route log on a rollback.
/// Workflow: limited-key authority (K1),
/// `spec-chirho/workflows-chirho/identity-auth-chirho/limited-key-authority-chirho.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind_chirho", rename_all = "kebab-case")]
pub enum AppRouteKeyAccessChirho {
    OpenChirho {
        action_chirho: String,
        #[serde(default)]
        resources_chirho: Vec<String>,
    },
}

/// The longest action name a route may declare.
pub const KEY_ACTION_NAME_MAX_LEN_CHIRHO: usize = 64;

/// An action name is lowercase kebab: words of `a-z` and `0-9`, the first starting with a letter, joined by single
/// hyphens, at most `KEY_ACTION_NAME_MAX_LEN_CHIRHO` characters. Anything else refuses deploy.
pub fn validate_key_action_name_chirho(action_chirho: &str) -> anyhow::Result<()> {
    let well_formed_chirho = !action_chirho.is_empty()
        && action_chirho.len() <= KEY_ACTION_NAME_MAX_LEN_CHIRHO
        && action_chirho.starts_with(|c_chirho: char| c_chirho.is_ascii_lowercase())
        && action_chirho.split('-').all(|word_chirho| {
            !word_chirho.is_empty()
                && word_chirho
                    .chars()
                    .all(|c_chirho| c_chirho.is_ascii_lowercase() || c_chirho.is_ascii_digit())
        });
    if !well_formed_chirho {
        anyhow::bail!(
            "a key action name must be lowercase kebab of at most {KEY_ACTION_NAME_MAX_LEN_CHIRHO} characters"
        );
    }
    Ok(())
}

pub const APP_KEY_AUTHORITY_RECORD_SCHEMA_CHIRHO: &str = "app-key-authority-record-v1-chirho";

/// One route an app opened to limited keys, bound to the exact DAG it was reviewed with: a route whose current DAG
/// differs is closed to keys until a reviewed deploy opens it again. `resources_chirho` are the logical viewer-state
/// keys its opening declared, sorted and deduplicated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AppKeyAuthorityRouteChirho {
    pub route_chirho: String,
    pub action_chirho: String,
    pub dag_chirho: HashChirho,
    pub resources_chirho: Vec<String>,
}

/// An app's whole limited-key authority at one deploy, root-signed in its own dense log. The latest record per app is
/// authoritative. Any record puts the app in limited-key mode for good: it refuses every legacy key on every entry, and a
/// later record that opens nothing keeps it limited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppKeyAuthorityRecordChirho {
    pub seq_chirho: u64,
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub routes_chirho: Vec<AppKeyAuthorityRouteChirho>,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRouteRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub app_chirho: String,
    pub route_chirho: String,
    pub owner_principal_chirho: String,
    pub dag_chirho: Option<HashChirho>,
    pub action_chirho: AppRouteActionChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
    pub at_ms_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_chirho: Option<HashChirho>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transition_id_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared_writer_fence_epoch_chirho: Option<u64>,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRouteAuthorityStateChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub route_chirho: String,
    pub owner_principal_chirho: String,
    pub dag_chirho: HashChirho,
    pub action_chirho: AppRouteActionChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_policy_chirho: Option<AppRouteRequestBodyPolicyChirho>,
}
