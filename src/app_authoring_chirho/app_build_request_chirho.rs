// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Owner-gated build requests for future app/source-candidate creation.
//!
//! This stores owner-authored drafts as private blobs and exposes only signed safe metadata. It does
//! not run source review, deploy apps, move refs, or call providers.

use crate::model_chirho::HashChirho;
use crate::{app_chirho, cas_chirho, privacy_chirho, resource_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::ports_chirho::StateStoreChirho;
use cairn_signer_chirho::signer_chirho;
use cairn_store_redb_chirho::RedbStateAuditStoreChirho;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const APP_BUILD_REQUEST_PRIVATE_PAYLOAD_SCHEMA_CHIRHO: &str =
    "app-build-request-private-payload-v1-chirho";
const APP_BUILD_REQUEST_RECORD_SCHEMA_CHIRHO: &str = "app-build-request-record-v1-chirho";
const APP_BUILD_REQUEST_STATUS_PENDING_CHIRHO: &str = "pending-review-chirho";
const APP_BUILD_REQUEST_RECORDS_LOCK_CHIRHO: &str = "app-build-request-records-chirho";
const APP_BUILD_REQUEST_STATE_LOCK_PREFIX_CHIRHO: &str = "app-build-request-state-chirho";
pub const APP_BUILD_REQUEST_RESOURCE_SECTION_CHIRHO: &str = "app-build-request-chirho";
pub const APP_BUILD_REQUEST_RESOURCE_ACTION_CHIRHO: &str = "create-chirho";

const ALLOWED_MODULES_CHIRHO: &[&str] = &[
    "private-intake-chirho",
    "reviewed-preview-chirho",
    "owner-admin-chirho",
    "feedback-discussions-chirho",
    "app-user-admin-chirho",
    "payments-topups-later-chirho",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBuildRequestPrivatePayloadChirho {
    pub schema_chirho: String,
    pub app_chirho: String,
    pub owner_goal_chirho: String,
    pub requested_modules_chirho: Vec<String>,
    pub notes_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBuildRequestRecordChirho {
    pub seq_chirho: u64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub schema_chirho: String,
    pub owner_principal_chirho: String,
    pub app_chirho: String,
    pub request_private_ref_chirho: privacy_chirho::PrivateBlobRefChirho,
    pub request_payload_hash_chirho: HashChirho,
    pub idempotency_key_hash_chirho: HashChirho,
    pub requested_module_ids_chirho: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_usage_seq_chirho: Option<u64>,
    pub status_chirho: String,
    pub at_ms_chirho: u64,
    pub sig_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppBuildRequestInputChirho {
    pub owner_principal_chirho: String,
    pub app_chirho: String,
    pub idempotency_key_chirho: String,
    pub owner_goal_chirho: String,
    pub requested_modules_chirho: Vec<String>,
    pub notes_chirho: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBuildRequestPreviewChirho {
    pub app_chirho: String,
    pub owner_principal_chirho: String,
    pub request_payload_hash_chirho: HashChirho,
    pub idempotency_key_hash_chirho: HashChirho,
    pub requested_module_ids_chirho: Vec<String>,
    pub candidate_request_cost_token_chirho: i64,
    pub existing_app_chirho: bool,
    pub no_store_chirho: bool,
}

fn app_build_request_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-build-request-records-chirho.jsonl")
}

fn app_build_request_state_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("app-build-request-state-chirho.redb")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn allowed_modules_chirho() -> BTreeSet<&'static str> {
    ALLOWED_MODULES_CHIRHO.iter().copied().collect()
}

fn validate_short_token_chirho(label_chirho: &str, value_chirho: &str) -> Result<()> {
    if value_chirho.trim().is_empty()
        || value_chirho.len() > 128
        || !value_chirho.chars().all(|ch_chirho| {
            ch_chirho.is_ascii_alphanumeric() || matches!(ch_chirho, '-' | '_' | ':' | '.')
        })
    {
        bail!("{label_chirho} must be a short opaque token");
    }
    Ok(())
}

fn validate_text_chirho(
    label_chirho: &str,
    value_chirho: &str,
    max_len_chirho: usize,
) -> Result<()> {
    if value_chirho.trim().is_empty() {
        bail!("{label_chirho} is required");
    }
    if value_chirho.len() > max_len_chirho {
        bail!("{label_chirho} is too long");
    }
    Ok(())
}

fn validate_modules_chirho(modules_chirho: &[String]) -> Result<Vec<String>> {
    if modules_chirho.is_empty() {
        bail!("at least one module_chirho is required");
    }
    if modules_chirho.len() > 12 {
        bail!("too many requested modules");
    }
    let allowed_chirho = allowed_modules_chirho();
    let mut normalized_chirho = Vec::new();
    let mut seen_chirho = BTreeSet::new();
    for module_chirho in modules_chirho {
        validate_short_token_chirho("module_chirho", module_chirho)?;
        if !allowed_chirho.contains(module_chirho.as_str()) {
            bail!("unknown module_chirho");
        }
        if seen_chirho.insert(module_chirho.clone()) {
            normalized_chirho.push(module_chirho.clone());
        }
    }
    Ok(normalized_chirho)
}

fn validate_owner_and_app_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
    app_chirho: &str,
) -> Result<bool> {
    app_chirho::validate_app_name_chirho(app_chirho)?;
    app_chirho::ensure_owner_principal_chirho(root_chirho, owner_principal_chirho)?;
    match app_chirho::verified_app_owner_chirho(root_chirho, app_chirho)? {
        Some(existing_owner_chirho) if existing_owner_chirho == owner_principal_chirho => Ok(true),
        Some(_) => bail!("app not found for owner"),
        None => Ok(false),
    }
}

fn private_payload_subject_chirho(owner_principal_chirho: &str, app_chirho: &str) -> String {
    let owner_hash_chirho = cas_chirho::hash_chirho(owner_principal_chirho.as_bytes());
    format!(
        "app-build-request/{}/{}",
        app_chirho,
        &owner_hash_chirho.0[..24]
    )
}

fn payload_and_hash_chirho(
    input_chirho: &AppBuildRequestInputChirho,
    normalized_modules_chirho: Vec<String>,
) -> Result<(AppBuildRequestPrivatePayloadChirho, Vec<u8>, HashChirho)> {
    let payload_chirho = AppBuildRequestPrivatePayloadChirho {
        schema_chirho: APP_BUILD_REQUEST_PRIVATE_PAYLOAD_SCHEMA_CHIRHO.to_string(),
        app_chirho: input_chirho.app_chirho.clone(),
        owner_goal_chirho: input_chirho.owner_goal_chirho.clone(),
        requested_modules_chirho: normalized_modules_chirho,
        notes_chirho: input_chirho.notes_chirho.clone(),
    };
    let bytes_chirho = serde_json::to_vec(&payload_chirho)?;
    let hash_chirho = cas_chirho::hash_chirho(&bytes_chirho);
    Ok((payload_chirho, bytes_chirho, hash_chirho))
}

fn idempotency_hash_chirho(input_chirho: &AppBuildRequestInputChirho) -> HashChirho {
    let material_chirho = format!(
        "app-build-request/v1\n{}\n{}\n{}",
        input_chirho.owner_principal_chirho,
        input_chirho.app_chirho,
        input_chirho.idempotency_key_chirho
    );
    cas_chirho::hash_chirho(material_chirho.as_bytes())
}

fn app_build_request_mutation_id_chirho(
    owner_principal_chirho: &str,
    app_chirho: &str,
    idempotency_key_hash_chirho: &HashChirho,
) -> String {
    format!(
        "app-build-request/{}/{}/{}",
        owner_principal_chirho, app_chirho, idempotency_key_hash_chirho.0
    )
}

fn app_build_request_state_key_chirho(
    owner_principal_chirho: &str,
    app_chirho: &str,
    idempotency_key_hash_chirho: &HashChirho,
) -> String {
    format!(
        "app-build-request-record/{}/{}/{}",
        owner_principal_chirho, app_chirho, idempotency_key_hash_chirho.0
    )
}

fn load_app_build_request_record_from_state_chirho(
    store_chirho: &RedbStateAuditStoreChirho,
    state_key_chirho: &str,
) -> Result<AppBuildRequestRecordChirho> {
    let bytes_chirho = store_chirho
        .get_state_chirho(state_key_chirho)
        .map_err(|error_chirho| anyhow!("read app build request state: {error_chirho}"))?
        .ok_or_else(|| anyhow!("app build request state missing after idempotency hit"))?;
    Ok(serde_json::from_slice(&bytes_chirho)?)
}

fn ensure_app_build_request_replay_matches_chirho(
    record_chirho: AppBuildRequestRecordChirho,
    payload_hash_chirho: &HashChirho,
    requested_modules_chirho: &[String],
) -> Result<AppBuildRequestRecordChirho> {
    if record_chirho.request_payload_hash_chirho != *payload_hash_chirho
        || record_chirho.requested_module_ids_chirho != requested_modules_chirho
    {
        bail!("app build request idempotency key conflict");
    }
    Ok(record_chirho)
}

fn maybe_record_app_build_request_resource_admission_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
    app_chirho: &str,
) -> Result<Option<u64>> {
    let Some((_policy_hash_chirho, policy_chirho)) =
        resource_chirho::current_resource_policy_chirho(root_chirho, app_chirho)?
    else {
        return Ok(None);
    };
    if !policy_chirho.actions_chirho.iter().any(|action_chirho| {
        action_chirho.section_chirho == APP_BUILD_REQUEST_RESOURCE_SECTION_CHIRHO
            && action_chirho.action_chirho == APP_BUILD_REQUEST_RESOURCE_ACTION_CHIRHO
            && action_chirho.effect_chirho.is_none()
    }) {
        return Ok(None);
    }
    let usage_chirho = resource_chirho::record_resource_usage_chirho(
        root_chirho,
        resource_chirho::ResourceUsageInputChirho {
            app_chirho: app_chirho.to_string(),
            user_chirho: owner_principal_chirho.to_string(),
            actor_chirho: Some(owner_principal_chirho.to_string()),
            section_chirho: APP_BUILD_REQUEST_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: APP_BUILD_REQUEST_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: None,
            run_chirho: None,
            bridges_chirho: Vec::new(),
        },
    )?;
    if let resource_chirho::ResourceDecisionChirho::RoutedChirho { .. } =
        usage_chirho.decision_chirho
    {
        bail!(
            "app build request resource admission routed this write; request body was not stored"
        );
    }
    Ok(Some(usage_chirho.seq_chirho))
}

struct ValidatedAppBuildRequestChirho {
    existing_app_chirho: bool,
    requested_module_ids_chirho: Vec<String>,
    payload_bytes_chirho: Vec<u8>,
    payload_hash_chirho: HashChirho,
    idem_hash_chirho: HashChirho,
}

fn validate_input_chirho(
    root_chirho: &Path,
    input_chirho: &AppBuildRequestInputChirho,
) -> Result<ValidatedAppBuildRequestChirho> {
    let existing_app_chirho = validate_owner_and_app_chirho(
        root_chirho,
        &input_chirho.owner_principal_chirho,
        &input_chirho.app_chirho,
    )?;
    validate_short_token_chirho(
        "idempotency_key_chirho",
        &input_chirho.idempotency_key_chirho,
    )?;
    validate_text_chirho("owner_goal_chirho", &input_chirho.owner_goal_chirho, 8192)?;
    if input_chirho.notes_chirho.len() > 32768 {
        bail!("notes_chirho is too long");
    }
    let normalized_modules_chirho =
        validate_modules_chirho(&input_chirho.requested_modules_chirho)?;
    let (_payload_chirho, payload_bytes_chirho, payload_hash_chirho) =
        payload_and_hash_chirho(input_chirho, normalized_modules_chirho.clone())?;
    let idem_hash_chirho = idempotency_hash_chirho(input_chirho);
    Ok(ValidatedAppBuildRequestChirho {
        existing_app_chirho,
        requested_module_ids_chirho: normalized_modules_chirho,
        payload_bytes_chirho,
        payload_hash_chirho,
        idem_hash_chirho,
    })
}

pub fn preview_app_build_request_chirho(
    root_chirho: &Path,
    input_chirho: AppBuildRequestInputChirho,
) -> Result<AppBuildRequestPreviewChirho> {
    let validated_chirho = validate_input_chirho(root_chirho, &input_chirho)?;
    Ok(AppBuildRequestPreviewChirho {
        app_chirho: input_chirho.app_chirho,
        owner_principal_chirho: input_chirho.owner_principal_chirho,
        request_payload_hash_chirho: validated_chirho.payload_hash_chirho,
        idempotency_key_hash_chirho: validated_chirho.idem_hash_chirho,
        requested_module_ids_chirho: validated_chirho.requested_module_ids_chirho,
        candidate_request_cost_token_chirho: 0,
        existing_app_chirho: validated_chirho.existing_app_chirho,
        no_store_chirho: true,
    })
}

pub fn create_app_build_request_chirho(
    root_chirho: &Path,
    input_chirho: AppBuildRequestInputChirho,
) -> Result<AppBuildRequestRecordChirho> {
    let ValidatedAppBuildRequestChirho {
        existing_app_chirho: _,
        requested_module_ids_chirho: requested_modules_chirho,
        payload_bytes_chirho,
        payload_hash_chirho,
        idem_hash_chirho,
    } = validate_input_chirho(root_chirho, &input_chirho)?;
    let mutation_id_chirho = app_build_request_mutation_id_chirho(
        &input_chirho.owner_principal_chirho,
        &input_chirho.app_chirho,
        &idem_hash_chirho,
    );
    let state_key_chirho = app_build_request_state_key_chirho(
        &input_chirho.owner_principal_chirho,
        &input_chirho.app_chirho,
        &idem_hash_chirho,
    );
    let lock_name_chirho = format!(
        "{APP_BUILD_REQUEST_STATE_LOCK_PREFIX_CHIRHO}-{}",
        idem_hash_chirho.0
    );

    // The request payload is the owner's own data: its key joins the owner's account, and a malformed
    // principal refuses here, before any lock, admission or write (R3, gpt #28874).
    let attribution_chirho = privacy_chirho::PrivateBlobAttributionChirho::account_owned_chirho(
        &input_chirho.owner_principal_chirho,
    )?;
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        let store_chirho = RedbStateAuditStoreChirho::open_chirho(
            &app_build_request_state_path_chirho(root_chirho),
        )?;
        if store_chirho
            .is_applied_chirho(&mutation_id_chirho)
            .map_err(|error_chirho| anyhow!("read app build request idempotency: {error_chirho}"))?
        {
            return ensure_app_build_request_replay_matches_chirho(
                load_app_build_request_record_from_state_chirho(&store_chirho, &state_key_chirho)?,
                &payload_hash_chirho,
                &requested_modules_chirho,
            );
        }

        seqlog_chirho::with_named_lock_chirho(
            root_chirho,
            APP_BUILD_REQUEST_RECORDS_LOCK_CHIRHO,
            || {
                let (owner_principal_chirho, app_chirho) = (
                    input_chirho.owner_principal_chirho.clone(),
                    input_chirho.app_chirho.clone(),
                );
                let records_chirho = load_app_build_request_records_chirho(root_chirho)?;
                if let Some(existing_chirho) = records_chirho.iter().find(|record_chirho| {
                    record_chirho.owner_principal_chirho == owner_principal_chirho
                        && record_chirho.app_chirho == app_chirho
                        && record_chirho.idempotency_key_hash_chirho == idem_hash_chirho
                }) {
                    let existing_chirho = ensure_app_build_request_replay_matches_chirho(
                        existing_chirho.clone(),
                        &payload_hash_chirho,
                        &requested_modules_chirho,
                    )?;
                    let existing_bytes_chirho = serde_json::to_vec(&existing_chirho)?;
                    let _ = store_chirho
                        .apply_once_chirho(
                            &mutation_id_chirho,
                            &state_key_chirho,
                            &existing_bytes_chirho,
                        )
                        .map_err(|error_chirho| {
                            anyhow!("apply existing app build request once: {error_chirho}")
                        })?;
                    return Ok(existing_chirho);
                }

                let resource_usage_seq_chirho =
                    maybe_record_app_build_request_resource_admission_chirho(
                        root_chirho,
                        &owner_principal_chirho,
                        &app_chirho,
                    )?;
                let subject_chirho =
                    private_payload_subject_chirho(&owner_principal_chirho, &app_chirho);
                let request_private_ref_chirho = privacy_chirho::store_private_blob_chirho(
                    root_chirho,
                    &attribution_chirho,
                    &subject_chirho,
                    &payload_bytes_chirho,
                );
                let request_private_ref_chirho = request_private_ref_chirho?;
                let mut record_chirho = AppBuildRequestRecordChirho {
                    seq_chirho: records_chirho.len() as u64,
                    schema_chirho: APP_BUILD_REQUEST_RECORD_SCHEMA_CHIRHO.to_string(),
                    owner_principal_chirho,
                    app_chirho,
                    request_private_ref_chirho,
                    request_payload_hash_chirho: payload_hash_chirho,
                    idempotency_key_hash_chirho: idem_hash_chirho,
                    requested_module_ids_chirho: requested_modules_chirho,
                    resource_usage_seq_chirho,
                    status_chirho: APP_BUILD_REQUEST_STATUS_PENDING_CHIRHO.to_string(),
                    at_ms_chirho: now_ms_chirho(),
                    sig_chirho: String::new(),
                };
                record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
                    root_chirho,
                    &app_build_request_record_message_chirho(&record_chirho)?,
                )?;
                let record_bytes_chirho = serde_json::to_vec(&record_chirho)?;
                let applied_chirho = store_chirho
                    .apply_once_chirho(&mutation_id_chirho, &state_key_chirho, &record_bytes_chirho)
                    .map_err(|error_chirho| {
                        anyhow!("apply app build request once: {error_chirho}")
                    })?;
                if !applied_chirho {
                    return ensure_app_build_request_replay_matches_chirho(
                        load_app_build_request_record_from_state_chirho(
                            &store_chirho,
                            &state_key_chirho,
                        )?,
                        &record_chirho.request_payload_hash_chirho,
                        &record_chirho.requested_module_ids_chirho,
                    );
                }
                seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
                    &app_build_request_records_path_chirho(root_chirho),
                    record_chirho.seq_chirho,
                    &record_chirho,
                )?;
                Ok(record_chirho)
            },
        )
    })
}

pub fn load_app_build_request_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppBuildRequestRecordChirho>> {
    let path_chirho = app_build_request_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| {
            serde_json::from_str(line_chirho).context("decode app build request record")
        })
        .collect()
}

pub fn verified_app_build_request_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<AppBuildRequestRecordChirho>> {
    let records_chirho = load_app_build_request_records_chirho(root_chirho)?;
    verify_app_build_request_records_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho)
}

pub fn owner_app_build_request_records_chirho(
    root_chirho: &Path,
    owner_principal_chirho: &str,
    app_chirho: &str,
) -> Result<Vec<AppBuildRequestRecordChirho>> {
    let _ = validate_owner_and_app_chirho(root_chirho, owner_principal_chirho, app_chirho)?;
    let records_chirho = verified_app_build_request_records_chirho(root_chirho)?;
    Ok(records_chirho
        .into_iter()
        .filter(|record_chirho| {
            record_chirho.owner_principal_chirho == owner_principal_chirho
                && record_chirho.app_chirho == app_chirho
        })
        .collect())
}

pub fn verify_app_build_request_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppBuildRequestRecordChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut seen_idempotency_chirho = BTreeSet::new();
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("app build request seq mismatch at {index_chirho}");
        }
        verify_app_build_request_record_schema_chirho(record_chirho)?;
        app_chirho::validate_app_name_chirho(&record_chirho.app_chirho)?;
        app_chirho::ensure_owner_principal_chirho(
            root_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let expected_subject_chirho = private_payload_subject_chirho(
            &record_chirho.owner_principal_chirho,
            &record_chirho.app_chirho,
        );
        privacy_chirho::verify_private_blob_ref_subject_chirho(
            root_chirho,
            "app build request private payload",
            &record_chirho.request_private_ref_chirho,
            &expected_subject_chirho,
        )?;
        if record_chirho.status_chirho != APP_BUILD_REQUEST_STATUS_PENDING_CHIRHO {
            bail!(
                "unsupported app build request status '{}'",
                record_chirho.status_chirho
            );
        }
        let normalized_modules_chirho =
            validate_modules_chirho(&record_chirho.requested_module_ids_chirho)?;
        if normalized_modules_chirho != record_chirho.requested_module_ids_chirho {
            bail!("app build request module ids must be normalized");
        }
        if !seen_idempotency_chirho.insert((
            record_chirho.owner_principal_chirho.clone(),
            record_chirho.app_chirho.clone(),
            record_chirho.idempotency_key_hash_chirho.clone(),
        )) {
            bail!("duplicate app build request idempotency key");
        }
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &app_build_request_record_message_chirho(record_chirho)?,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "bad app build request signature at seq {}",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn verify_app_build_request_record_schema_chirho(
    record_chirho: &AppBuildRequestRecordChirho,
) -> Result<()> {
    if !record_chirho.schema_chirho.is_empty()
        && record_chirho.schema_chirho != APP_BUILD_REQUEST_RECORD_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported app build request record schema '{}'",
            record_chirho.schema_chirho
        );
    }
    Ok(())
}

fn app_build_request_record_message_chirho(
    record_chirho: &AppBuildRequestRecordChirho,
) -> Result<Vec<u8>> {
    let mut signed_chirho = record_chirho.clone();
    signed_chirho.sig_chirho.clear();
    Ok(serde_json::to_vec(&signed_chirho)?)
}
