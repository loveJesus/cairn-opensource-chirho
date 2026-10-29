// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Narrow blessed effect for client-owned app-builder template deployment.

use super::{
    client_owner_binding_chirho, deploy_app_chirho, set_app_input_policy_chirho,
    set_app_params_chirho, set_app_response_policy_chirho, template_registry_chirho,
    validate_app_name_chirho, verified_app_owner_chirho, AppInputModeChirho,
};
use crate::model_chirho::{HashChirho, RequestContextChirho};
use crate::{identity_chirho, resource_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::ports_chirho::StateStoreChirho;
use cairn_model_app_chirho::{
    TemplateAppDeployRecordChirho, TemplateAppDeployResponseChirho,
    TEMPLATE_APP_DEPLOY_RECORD_SCHEMA_CHIRHO, TEMPLATE_APP_DEPLOY_RESPONSE_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use cairn_store_redb_chirho::RedbStateAuditStoreChirho;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const TEMPLATE_APP_DEPLOY_REQUEST_SCHEMA_CHIRHO: &str = "template-app-deploy-request-v1-chirho";
const TEMPLATE_APP_DEPLOY_STATE_LOCK_PREFIX_CHIRHO: &str = "template-app-deploy-state-chirho";
const TEMPLATE_APP_DEPLOY_STATE_KEY_PREFIX_CHIRHO: &str = "template-app-deploy-record-chirho";
const MAX_TEMPLATE_APP_DEPLOY_REQUEST_BYTES_CHIRHO: usize = 80 * 1024;
const MAX_TEMPLATE_APP_PARAMS_BYTES_CHIRHO: usize = 64 * 1024;
pub const TEMPLATE_APP_DEPLOY_RESOURCE_SECTION_CHIRHO: &str = "template-app-deploy-chirho";
pub const TEMPLATE_APP_DEPLOY_RESOURCE_ACTION_CHIRHO: &str = "create-chirho";
pub const TEMPLATE_APP_DEPLOY_EFFECT_CHIRHO: &str = "template_app_deploy_chirho";

#[derive(Clone, Debug, Deserialize)]
struct TemplateAppDeployRequestChirho {
    #[serde(default)]
    schema_chirho: String,
    slug_chirho: String,
    idem_key_chirho: String,
    params_chirho: Value,
    #[serde(default)]
    template_id_chirho: Option<String>,
    #[serde(default)]
    owner_principal_chirho: Option<String>,
}

struct ValidatedTemplateAppDeployRequestChirho {
    display_slug_chirho: String,
    idem_key_chirho: String,
    params_value_chirho: Value,
    params_hash_chirho: HashChirho,
    request_payload_hash_chirho: HashChirho,
}

pub fn run_template_app_deploy_effect_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
    request_bytes_chirho: &[u8],
    request_context_chirho: Option<&RequestContextChirho>,
) -> Result<Vec<u8>> {
    // On a TENANT root the same card means "publish this template app at the platform level":
    // a tenant root holds one customer app (G1), so a second app here would be wrong to create
    // and the honest act is a signed publication intent for the platform applier. The direct
    // deploy below is the platform-root (and dev) road. Tested in `publication_chirho`.
    if !crate::tenant_chirho::tenant_id_for_root_chirho(root_chirho)?.is_platform_root_chirho() {
        return crate::publication_chirho::run_publication_intent_effect_chirho(
            root_chirho,
            template_id_chirho,
            request_bytes_chirho,
            request_context_chirho,
        );
    }
    let context_chirho = request_context_chirho
        .ok_or_else(|| anyhow!("template_app_deploy_chirho requires a signed-in app session"))?;
    ensure_user_principal_chirho(root_chirho, &context_chirho.user_principal_chirho)?;
    template_registry_chirho::validate_template_id_chirho(template_id_chirho)?;
    let validated_chirho = validate_template_app_deploy_request_chirho(
        root_chirho,
        template_id_chirho,
        request_bytes_chirho,
    )?;
    let idem_hash_chirho = idempotency_hash_chirho(
        &context_chirho.user_principal_chirho,
        &validated_chirho.idem_key_chirho,
    );
    let lock_name_chirho = format!(
        "{TEMPLATE_APP_DEPLOY_STATE_LOCK_PREFIX_CHIRHO}-{}",
        short_hash_chirho(&context_chirho.user_principal_chirho)
    );
    seqlog_chirho::with_named_lock_chirho(root_chirho, &lock_name_chirho, || {
        run_template_app_deploy_locked_chirho(
            root_chirho,
            template_id_chirho,
            context_chirho,
            validated_chirho,
            idem_hash_chirho,
        )
    })
}

pub fn load_template_app_deploy_records_chirho(
    root_chirho: &Path,
) -> Result<Vec<TemplateAppDeployRecordChirho>> {
    let path_chirho = template_app_deploy_records_path_chirho(root_chirho);
    if !path_chirho.exists() {
        return Ok(Vec::new());
    }
    let text_chirho = std::fs::read_to_string(&path_chirho)
        .with_context(|| format!("read {}", path_chirho.display()))?;
    text_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
        .map(|line_chirho| {
            serde_json::from_str(line_chirho).context("decode template app deploy record")
        })
        .collect()
}

pub fn verify_template_app_deploy_records_chirho(root_chirho: &Path) -> Result<usize> {
    let records_chirho = load_template_app_deploy_records_chirho(root_chirho)?;
    verify_template_app_deploy_record_set_chirho(root_chirho, &records_chirho)?;
    Ok(records_chirho.len())
}

fn run_template_app_deploy_locked_chirho(
    root_chirho: &Path,
    template_id_chirho: &str,
    context_chirho: &RequestContextChirho,
    validated_chirho: ValidatedTemplateAppDeployRequestChirho,
    idem_hash_chirho: HashChirho,
) -> Result<Vec<u8>> {
    let store_chirho = RedbStateAuditStoreChirho::open_chirho(
        &template_app_deploy_state_path_chirho(root_chirho),
    )?;
    let mutation_id_chirho = template_app_deploy_mutation_id_chirho(
        &context_chirho.user_principal_chirho,
        &idem_hash_chirho,
    );
    let state_key_chirho = template_app_deploy_state_key_chirho(
        &context_chirho.user_principal_chirho,
        &idem_hash_chirho,
    );
    if store_chirho
        .is_applied_chirho(&mutation_id_chirho)
        .map_err(|error_chirho| anyhow!("read template app deploy idempotency: {error_chirho}"))?
    {
        let record_chirho = load_template_app_deploy_record_from_state_chirho(
            root_chirho,
            &store_chirho,
            &state_key_chirho,
        )?;
        ensure_template_app_deploy_replay_matches_chirho(
            &record_chirho,
            template_id_chirho,
            &validated_chirho.display_slug_chirho,
            &validated_chirho.params_hash_chirho,
            &validated_chirho.request_payload_hash_chirho,
        )?;
        return template_app_deploy_response_bytes_chirho(&record_chirho);
    }

    let template_chirho =
        template_registry_chirho::template_target_chirho(root_chirho, template_id_chirho)?;
    // Static undo-plan workflow 4.2.1: this legacy template path is pure-only until it carries
    // complete descriptor-v2 bindings, and the check precedes quota, ownership, or app mutation.
    crate::app_source_manifest_chirho::verify_descriptor_v2_deployment_chirho(
        root_chirho,
        &BTreeSet::from([template_chirho.root_dag_chirho.clone()]),
        None,
    )?;
    let resource_usage_seq_chirho = record_template_app_deploy_resource_admission_chirho(
        root_chirho,
        context_chirho,
        &idem_hash_chirho,
    )?;
    let binding_chirho = client_owner_binding_chirho::resolve_or_mint_client_owner_binding_chirho(
        root_chirho,
        &context_chirho.user_principal_chirho,
    )?;
    let app_chirho = derived_template_app_name_chirho(
        &binding_chirho.owner_principal_chirho,
        &validated_chirho.display_slug_chirho,
    );
    if verified_app_owner_chirho(root_chirho, &app_chirho)?.is_some() {
        bail!("template app slug already exists for this owner; update mode is not enabled");
    }
    deploy_app_chirho(
        root_chirho,
        &app_chirho,
        template_chirho.root_dag_chirho.clone(),
        &binding_chirho.owner_principal_chirho,
    )?;
    set_app_input_policy_chirho(
        root_chirho,
        &app_chirho,
        None,
        &binding_chirho.owner_principal_chirho,
        AppInputModeChirho::PlainChirho,
    )?;
    set_app_response_policy_chirho(
        root_chirho,
        &app_chirho,
        &binding_chirho.owner_principal_chirho,
        &template_chirho.response_content_type_chirho,
    )?;
    let params_record_chirho = set_app_params_chirho(
        root_chirho,
        &app_chirho,
        None,
        &binding_chirho.owner_principal_chirho,
        &validated_chirho.params_value_chirho,
        true,
    )?;
    if params_record_chirho.params_chirho != validated_chirho.params_hash_chirho {
        bail!("template app deploy stored params hash mismatch");
    }
    let record_chirho = append_template_app_deploy_record_chirho(
        root_chirho,
        TemplateAppDeployRecordInputChirho {
            user_principal_chirho: context_chirho.user_principal_chirho.clone(),
            owner_principal_chirho: binding_chirho.owner_principal_chirho,
            template_id_chirho: template_id_chirho.to_string(),
            app_chirho,
            display_slug_chirho: validated_chirho.display_slug_chirho,
            root_dag_chirho: template_chirho.root_dag_chirho,
            params_chirho: validated_chirho.params_hash_chirho,
            request_payload_chirho: validated_chirho.request_payload_hash_chirho,
            idempotency_key_hash_chirho: idem_hash_chirho,
            resource_usage_seq_chirho,
        },
    )?;
    let record_bytes_chirho = serde_json::to_vec(&record_chirho)?;
    let applied_chirho = store_chirho
        .apply_once_chirho(&mutation_id_chirho, &state_key_chirho, &record_bytes_chirho)
        .map_err(|error_chirho| anyhow!("apply template app deploy once: {error_chirho}"))?;
    if !applied_chirho {
        let record_chirho = load_template_app_deploy_record_from_state_chirho(
            root_chirho,
            &store_chirho,
            &state_key_chirho,
        )?;
        ensure_template_app_deploy_replay_matches_chirho(
            &record_chirho,
            template_id_chirho,
            &record_chirho.display_slug_chirho,
            &record_chirho.params_chirho,
            &record_chirho.request_payload_chirho,
        )?;
        return template_app_deploy_response_bytes_chirho(&record_chirho);
    }
    template_app_deploy_response_bytes_chirho(&record_chirho)
}

fn validate_template_app_deploy_request_chirho(
    _root_chirho: &Path,
    template_id_chirho: &str,
    request_bytes_chirho: &[u8],
) -> Result<ValidatedTemplateAppDeployRequestChirho> {
    if request_bytes_chirho.len() > MAX_TEMPLATE_APP_DEPLOY_REQUEST_BYTES_CHIRHO {
        bail!("template app deploy request too large");
    }
    let request_chirho: TemplateAppDeployRequestChirho =
        serde_json::from_slice(request_bytes_chirho)
            .context("decode TemplateAppDeployRequestChirho")?;
    if !request_chirho.schema_chirho.is_empty()
        && request_chirho.schema_chirho != TEMPLATE_APP_DEPLOY_REQUEST_SCHEMA_CHIRHO
    {
        bail!(
            "unsupported template app deploy request schema '{}'",
            request_chirho.schema_chirho
        );
    }
    if let Some(request_template_chirho) = request_chirho.template_id_chirho.as_deref() {
        if request_template_chirho != template_id_chirho {
            bail!("template_id_chirho in request does not match capability template_id_chirho");
        }
    }
    let _ignored_owner_chirho = request_chirho.owner_principal_chirho;
    validate_display_slug_chirho(&request_chirho.slug_chirho)?;
    template_registry_chirho::validate_short_id_chirho(
        "idem_key_chirho",
        &request_chirho.idem_key_chirho,
    )?;
    if !request_chirho.params_chirho.is_object() {
        bail!("params_chirho must be a JSON object");
    }
    let params_bytes_chirho = serde_json::to_vec(&request_chirho.params_chirho)?;
    if params_bytes_chirho.len() > MAX_TEMPLATE_APP_PARAMS_BYTES_CHIRHO {
        bail!("params_chirho is too large");
    }
    let params_hash_chirho =
        crate::store_chirho::hash_object_chirho(&request_chirho.params_chirho)?;
    let request_payload_hash_chirho = request_payload_hash_chirho(
        template_id_chirho,
        &request_chirho.slug_chirho,
        &request_chirho.idem_key_chirho,
        &params_hash_chirho,
    );
    Ok(ValidatedTemplateAppDeployRequestChirho {
        display_slug_chirho: request_chirho.slug_chirho,
        idem_key_chirho: request_chirho.idem_key_chirho,
        params_value_chirho: request_chirho.params_chirho,
        params_hash_chirho,
        request_payload_hash_chirho,
    })
}

fn record_template_app_deploy_resource_admission_chirho(
    root_chirho: &Path,
    context_chirho: &RequestContextChirho,
    run_chirho: &HashChirho,
) -> Result<Option<u64>> {
    let usage_chirho = resource_chirho::record_resource_usage_chirho(
        root_chirho,
        resource_chirho::ResourceUsageInputChirho {
            app_chirho: context_chirho.app_chirho.clone(),
            user_chirho: context_chirho.user_principal_chirho.clone(),
            actor_chirho: Some(context_chirho.user_principal_chirho.clone()),
            section_chirho: TEMPLATE_APP_DEPLOY_RESOURCE_SECTION_CHIRHO.to_string(),
            action_chirho: TEMPLATE_APP_DEPLOY_RESOURCE_ACTION_CHIRHO.to_string(),
            effect_chirho: Some(TEMPLATE_APP_DEPLOY_EFFECT_CHIRHO.to_string()),
            run_chirho: Some(run_chirho.clone()),
            bridges_chirho: Vec::new(),
        },
    )?;
    if let resource_chirho::ResourceDecisionChirho::RoutedChirho { .. } =
        usage_chirho.decision_chirho
    {
        bail!("template app deploy resource admission routed this deployment; no app was deployed");
    }
    Ok(Some(usage_chirho.seq_chirho))
}

struct TemplateAppDeployRecordInputChirho {
    user_principal_chirho: String,
    owner_principal_chirho: String,
    template_id_chirho: String,
    app_chirho: String,
    display_slug_chirho: String,
    root_dag_chirho: HashChirho,
    params_chirho: HashChirho,
    request_payload_chirho: HashChirho,
    idempotency_key_hash_chirho: HashChirho,
    resource_usage_seq_chirho: Option<u64>,
}

fn append_template_app_deploy_record_chirho(
    root_chirho: &Path,
    input_chirho: TemplateAppDeployRecordInputChirho,
) -> Result<TemplateAppDeployRecordChirho> {
    let path_chirho = template_app_deploy_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_chirho(root_chirho, &path_chirho, |seq_chirho| {
        let mut record_chirho = TemplateAppDeployRecordChirho {
            seq_chirho,
            schema_chirho: TEMPLATE_APP_DEPLOY_RECORD_SCHEMA_CHIRHO.to_string(),
            user_principal_chirho: input_chirho.user_principal_chirho.clone(),
            owner_principal_chirho: input_chirho.owner_principal_chirho.clone(),
            template_id_chirho: input_chirho.template_id_chirho.clone(),
            app_chirho: input_chirho.app_chirho.clone(),
            display_slug_chirho: input_chirho.display_slug_chirho.clone(),
            root_dag_chirho: input_chirho.root_dag_chirho.clone(),
            params_chirho: input_chirho.params_chirho.clone(),
            request_payload_chirho: input_chirho.request_payload_chirho.clone(),
            idempotency_key_hash_chirho: input_chirho.idempotency_key_hash_chirho.clone(),
            resource_usage_seq_chirho: input_chirho.resource_usage_seq_chirho,
            at_ms_chirho: now_ms_chirho(),
            sig_chirho: String::new(),
        };
        let message_chirho = template_app_deploy_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

fn verify_template_app_deploy_record_set_chirho(
    root_chirho: &Path,
    records_chirho: &[TemplateAppDeployRecordChirho],
) -> Result<()> {
    let pubkey_chirho = signer_chirho::pubkey_hex_chirho(root_chirho)?;
    let mut seen_idem_chirho = BTreeSet::new();
    let mut seen_apps_chirho = BTreeSet::new();
    let registry_records_chirho = super::load_template_registry_records_chirho(root_chirho)?;
    super::verify_template_registry_chirho(root_chirho)?;
    let usage_records_chirho = resource_chirho::load_resource_usage_chirho(root_chirho)?;
    if !usage_records_chirho.is_empty() {
        resource_chirho::verify_resource_usage_chirho(root_chirho)?;
    }
    for (index_chirho, record_chirho) in records_chirho.iter().enumerate() {
        if record_chirho.seq_chirho != index_chirho as u64 {
            bail!("template app deploy seq gap at index {index_chirho}");
        }
        if record_chirho.schema_chirho != TEMPLATE_APP_DEPLOY_RECORD_SCHEMA_CHIRHO {
            bail!(
                "unsupported template app deploy schema '{}'",
                record_chirho.schema_chirho
            );
        }
        ensure_user_principal_chirho(root_chirho, &record_chirho.user_principal_chirho)?;
        let binding_chirho =
            client_owner_binding_chirho::active_client_owner_binding_for_user_chirho(
                root_chirho,
                &record_chirho.user_principal_chirho,
            )?
            .ok_or_else(|| {
                anyhow!("template app deploy record has no active client owner binding")
            })?;
        if binding_chirho.owner_principal_chirho != record_chirho.owner_principal_chirho {
            bail!("template app deploy owner does not match active client owner binding");
        }
        if !registry_records_chirho.iter().any(|template_chirho| {
            template_chirho.template_id_chirho == record_chirho.template_id_chirho
                && template_chirho.root_dag_chirho == record_chirho.root_dag_chirho
        }) {
            bail!(
                "template app deploy record {} references an unregistered template target",
                record_chirho.seq_chirho
            );
        }
        super::ensure_app_owner_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
        )?;
        let selected_input_policy_chirho = super::app_input_mode_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            None,
            &record_chirho.owner_principal_chirho,
        )?;
        if !matches!(
            selected_input_policy_chirho,
            AppInputModeChirho::PlainChirho
        ) {
            bail!("template app deploy app input policy mismatch");
        }
        let selected_params_chirho = super::app_params_chirho(
            root_chirho,
            &record_chirho.app_chirho,
            None,
            &record_chirho.owner_principal_chirho,
        )?
        .ok_or_else(|| anyhow!("template app deploy record has no app params record"))?;
        if selected_params_chirho.params_chirho != record_chirho.params_chirho
            || !selected_params_chirho.required_chirho
        {
            bail!("template app deploy app params mismatch");
        }
        if let Some(resource_seq_chirho) = record_chirho.resource_usage_seq_chirho {
            let usage_chirho = usage_records_chirho
                .get(resource_seq_chirho as usize)
                .ok_or_else(|| anyhow!("template app deploy resource usage seq missing"))?;
            if usage_chirho.user_chirho != record_chirho.user_principal_chirho
                || usage_chirho.section_chirho != TEMPLATE_APP_DEPLOY_RESOURCE_SECTION_CHIRHO
                || usage_chirho.action_chirho != TEMPLATE_APP_DEPLOY_RESOURCE_ACTION_CHIRHO
                || usage_chirho.effect_chirho.as_deref() != Some(TEMPLATE_APP_DEPLOY_EFFECT_CHIRHO)
            {
                bail!("template app deploy resource usage mismatch");
            }
        } else {
            bail!("template app deploy record missing resource usage admission");
        }
        if !seen_idem_chirho.insert((
            record_chirho.user_principal_chirho.clone(),
            record_chirho.idempotency_key_hash_chirho.clone(),
        )) {
            bail!("duplicate template app deploy idempotency key");
        }
        if !seen_apps_chirho.insert(record_chirho.app_chirho.clone()) {
            bail!("duplicate template app deployment for app");
        }
        let message_chirho = template_app_deploy_record_message_chirho(record_chirho)?;
        if !signer_chirho::verify_with_pubkey_chirho(
            &pubkey_chirho,
            &message_chirho,
            &record_chirho.sig_chirho,
        )? {
            bail!(
                "template app deploy record {} signature invalid",
                record_chirho.seq_chirho
            );
        }
    }
    Ok(())
}

fn ensure_template_app_deploy_replay_matches_chirho(
    record_chirho: &TemplateAppDeployRecordChirho,
    template_id_chirho: &str,
    display_slug_chirho: &str,
    params_chirho: &HashChirho,
    request_payload_chirho: &HashChirho,
) -> Result<()> {
    if record_chirho.template_id_chirho != template_id_chirho
        || record_chirho.display_slug_chirho != display_slug_chirho
        || record_chirho.params_chirho != *params_chirho
        || record_chirho.request_payload_chirho != *request_payload_chirho
    {
        bail!("template app deploy idempotency key conflict");
    }
    Ok(())
}

fn load_template_app_deploy_record_from_state_chirho(
    root_chirho: &Path,
    store_chirho: &RedbStateAuditStoreChirho,
    state_key_chirho: &str,
) -> Result<TemplateAppDeployRecordChirho> {
    verify_template_app_deploy_records_chirho(root_chirho)?;
    let bytes_chirho = store_chirho
        .get_state_chirho(state_key_chirho)
        .map_err(|error_chirho| anyhow!("read template app deploy state: {error_chirho}"))?
        .ok_or_else(|| anyhow!("template app deploy state missing after idempotency hit"))?;
    let record_chirho: TemplateAppDeployRecordChirho = serde_json::from_slice(&bytes_chirho)?;
    let verified_chirho = load_template_app_deploy_records_chirho(root_chirho)?;
    if !verified_chirho.iter().any(|candidate_chirho| {
        candidate_chirho.seq_chirho == record_chirho.seq_chirho
            && candidate_chirho == &record_chirho
    }) {
        bail!("template app deploy state points at an unverified deploy record");
    }
    Ok(record_chirho)
}

fn template_app_deploy_response_bytes_chirho(
    record_chirho: &TemplateAppDeployRecordChirho,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&TemplateAppDeployResponseChirho {
        schema_chirho: TEMPLATE_APP_DEPLOY_RESPONSE_SCHEMA_CHIRHO.to_string(),
        app_chirho: record_chirho.app_chirho.clone(),
        url_chirho: format!("/app-chirho/{}/", record_chirho.app_chirho),
        owner_principal_chirho: record_chirho.owner_principal_chirho.clone(),
        user_principal_chirho: record_chirho.user_principal_chirho.clone(),
        template_id_chirho: record_chirho.template_id_chirho.clone(),
        display_slug_chirho: record_chirho.display_slug_chirho.clone(),
        params_chirho: record_chirho.params_chirho.clone(),
        deploy_record_seq_chirho: record_chirho.seq_chirho,
    })
    .context("encode TemplateAppDeployResponseChirho")
}

fn ensure_user_principal_chirho(root_chirho: &Path, principal_chirho: &str) -> Result<()> {
    let identity_chirho = identity_chirho::find_identity_chirho(root_chirho, principal_chirho)?
        .ok_or_else(|| anyhow!("unknown user principal '{principal_chirho}'"))?;
    if identity_chirho.kind_chirho != identity_chirho::PrincipalKindChirho::UserChirho {
        bail!("template_app_deploy_chirho requires a UserChirho session principal");
    }
    Ok(())
}

fn validate_display_slug_chirho(slug_chirho: &str) -> Result<()> {
    if slug_chirho.is_empty() || slug_chirho.len() > 48 {
        bail!("slug_chirho must be 1..=48 chars");
    }
    if slug_chirho.starts_with('-') || slug_chirho.ends_with('-') {
        bail!("slug_chirho must not start or end with '-'");
    }
    if !slug_chirho.chars().all(|ch_chirho| {
        ch_chirho.is_ascii_lowercase() || ch_chirho.is_ascii_digit() || ch_chirho == '-'
    }) {
        bail!("slug_chirho must contain only lowercase ascii letters, digits, and '-'");
    }
    Ok(())
}

fn derived_template_app_name_chirho(owner_principal_chirho: &str, slug_chirho: &str) -> String {
    let owner_hash_chirho = crate::cas_chirho::hash_chirho(owner_principal_chirho.as_bytes());
    let app_chirho = format!("client-{}-{slug_chirho}", &owner_hash_chirho.0[..16]);
    validate_app_name_chirho(&app_chirho).expect("derived app names are valid");
    app_chirho
}

fn idempotency_hash_chirho(user_principal_chirho: &str, idem_key_chirho: &str) -> HashChirho {
    let material_chirho =
        format!("template-app-deploy/v1\n{user_principal_chirho}\n{idem_key_chirho}");
    crate::cas_chirho::hash_chirho(material_chirho.as_bytes())
}

fn request_payload_hash_chirho(
    template_id_chirho: &str,
    slug_chirho: &str,
    idem_key_chirho: &str,
    params_chirho: &HashChirho,
) -> HashChirho {
    let material_chirho = format!(
        "template-app-deploy-request/v1\n{template_id_chirho}\n{slug_chirho}\n{idem_key_chirho}\n{}",
        params_chirho.0
    );
    crate::cas_chirho::hash_chirho(material_chirho.as_bytes())
}

fn template_app_deploy_mutation_id_chirho(
    user_principal_chirho: &str,
    idem_hash_chirho: &HashChirho,
) -> String {
    format!(
        "template-app-deploy/{user_principal_chirho}/{}",
        idem_hash_chirho.0
    )
}

fn template_app_deploy_state_key_chirho(
    user_principal_chirho: &str,
    idem_hash_chirho: &HashChirho,
) -> String {
    format!(
        "{TEMPLATE_APP_DEPLOY_STATE_KEY_PREFIX_CHIRHO}/{user_principal_chirho}/{}",
        idem_hash_chirho.0
    )
}

fn template_app_deploy_record_message_chirho(
    record_chirho: &TemplateAppDeployRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct TemplateAppDeployRecordMessageChirho<'a> {
        seq_chirho: u64,
        schema_chirho: &'a str,
        user_principal_chirho: &'a str,
        owner_principal_chirho: &'a str,
        template_id_chirho: &'a str,
        app_chirho: &'a str,
        display_slug_chirho: &'a str,
        root_dag_chirho: &'a HashChirho,
        params_chirho: &'a HashChirho,
        request_payload_chirho: &'a HashChirho,
        idempotency_key_hash_chirho: &'a HashChirho,
        resource_usage_seq_chirho: Option<u64>,
        at_ms_chirho: u64,
    }
    Ok(serde_json::to_vec(&TemplateAppDeployRecordMessageChirho {
        seq_chirho: record_chirho.seq_chirho,
        schema_chirho: &record_chirho.schema_chirho,
        user_principal_chirho: &record_chirho.user_principal_chirho,
        owner_principal_chirho: &record_chirho.owner_principal_chirho,
        template_id_chirho: &record_chirho.template_id_chirho,
        app_chirho: &record_chirho.app_chirho,
        display_slug_chirho: &record_chirho.display_slug_chirho,
        root_dag_chirho: &record_chirho.root_dag_chirho,
        params_chirho: &record_chirho.params_chirho,
        request_payload_chirho: &record_chirho.request_payload_chirho,
        idempotency_key_hash_chirho: &record_chirho.idempotency_key_hash_chirho,
        resource_usage_seq_chirho: record_chirho.resource_usage_seq_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })?)
}

fn template_app_deploy_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("template-app-deploy-records-chirho.jsonl")
}

fn template_app_deploy_state_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("template-app-deploy-state-chirho.redb")
}

fn short_hash_chirho(value_chirho: &str) -> String {
    crate::cas_chirho::hash_chirho(value_chirho.as_bytes()).0[..24].to_string()
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "template_app_deploy_chirho/tests_chirho.rs"]
mod tests_chirho;
