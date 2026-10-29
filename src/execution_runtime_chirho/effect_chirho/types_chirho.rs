// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use crate::model_chirho::{EffectChirho, HashChirho};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// JSON request payload accepted by `NetChirho`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetRequestChirho {
    pub method_chirho: String,
    pub url_chirho: String,
    #[serde(default)]
    pub headers_chirho: BTreeMap<String, String>,
    #[serde(default)]
    pub body_base64_chirho: Option<String>,
    #[serde(default)]
    pub timeout_ms_chirho: Option<u64>,
    #[serde(default)]
    pub max_response_bytes_chirho: Option<usize>,
}

/// JSON response emitted by `NetChirho`; public Net responses include the body as the node output,
/// while host-private Net responses keep only private refs plus body hashes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetResponseChirho {
    pub status_chirho: u16,
    pub url_chirho: String,
    pub content_type_chirho: Option<String>,
    pub request_bytes_chirho: u64,
    pub request_body_bytes_chirho: u64,
    pub response_body_bytes_chirho: u64,
    pub elapsed_ms_chirho: u64,
    pub request_body_hash_chirho: HashChirho,
    pub response_body_hash_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body_private_ref_chirho: Option<crate::privacy_chirho::PrivateBlobRefChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_body_private_ref_chirho: Option<crate::privacy_chirho::PrivateBlobRefChirho>,
    #[serde(default)]
    pub body_base64_chirho: String,
}

/// Metadata response emitted by `InvokeChirho`; the cache layer unwraps `payload_hash_chirho`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvokeResponseChirho {
    pub target_node_chirho: HashChirho,
    pub target_run_chirho: HashChirho,
    pub payload_hash_chirho: HashChirho,
    pub cached_chirho: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedQueryRequestChirho {
    pub prefix_chirho: String,
    #[serde(default)]
    pub limit_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedWriteStoreRequestChirho {
    pub schema_chirho: String,
    pub key_chirho: String,
    pub value_base64_chirho: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ViewerStateActionChirho {
    ReadChirho,
    WriteChirho,
    RestoreChirho,
}

/// Schema-tagged request carried through the existing reviewed ReadStore/WriteStore doors.
/// The host derives app and viewer scope from `RequestContextChirho`; neither is caller-selectable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ViewerStateRequestChirho {
    pub schema_chirho: String,
    pub action_chirho: ViewerStateActionChirho,
    pub key_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_current_version_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_base64_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_from_version_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerStateMutationReceiptChirho {
    pub schema_chirho: String,
    pub actor_principal_digest_chirho: HashChirho,
    pub app_chirho: String,
    pub action_chirho: ViewerStateActionChirho,
    pub key_digest_chirho: HashChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_version_chirho: Option<u64>,
    pub predecessor_receipt_digest_chirho: HashChirho,
    pub after_version_chirho: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_from_version_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_chirho: Option<HashChirho>,
    pub idempotency_chirho: HashChirho,
    pub request_digest_chirho: HashChirho,
    pub sealed_value_digest_chirho: HashChirho,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerStateVersionChirho {
    pub version_chirho: u64,
    pub value_base64_chirho: String,
    pub receipt_chirho: ViewerStateMutationReceiptChirho,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerStateResponseChirho {
    pub schema_chirho: String,
    pub key_chirho: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_chirho: Option<ViewerStateVersionChirho>,
    pub history_chirho: Vec<ViewerStateVersionChirho>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_receipt_chirho: Option<ViewerStateMutationReceiptChirho>,
}

/// The typed outcome of an optimistic viewer-state mutation whose `expected_current_version_chirho`
/// no longer names the head: nothing was appended, no receipt was signed, and the caller receives
/// the verified head (the exact `viewer-state-response-v2-chirho` body a read would return) plus
/// an echo of what it tried to write, so an editor can show the newer version and keep the
/// draft. A distinct schema, not a status field, so a renderer that does not know it fails to
/// parse rather than rendering a conflict as a save. Every other refusal stays a refusal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewerStateConflictChirho {
    pub schema_chirho: String,
    pub key_chirho: String,
    pub action_chirho: ViewerStateActionChirho,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_current_version_chirho: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_version_chirho: Option<u64>,
    pub current_chirho: ViewerStateResponseChirho,
    /// Absent (not empty) on a restore conflict: a restore carries no value to echo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_value_base64_chirho: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempted_restore_from_version_chirho: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedQueryResponseChirho {
    pub rows_chirho: Vec<crate::query_chirho::QueryRowChirho>,
    pub row_count_chirho: usize,
    pub ledger_seq_chirho: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolatileEffectRecordChirho {
    pub schema_chirho: String,
    pub seq_chirho: u64,
    pub effect_chirho: EffectChirho,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolatileEffectDisplayRecordChirho {
    pub line_chirho: u64,
    pub record_chirho: Option<VolatileEffectRecordChirho>,
    pub validation_error_chirho: Option<String>,
}

impl VolatileEffectDisplayRecordChirho {
    pub fn valid_chirho(&self) -> bool {
        self.validation_error_chirho.is_none()
    }
}
