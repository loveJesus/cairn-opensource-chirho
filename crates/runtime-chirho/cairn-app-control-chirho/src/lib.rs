// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! App control-plane authority orchestration over caller-verified records and signatures.

pub mod app_head_removal_chirho;
pub mod app_route_head_removal_chirho;
mod elected_app_route_deploy_chirho;

use anyhow::{anyhow, bail, Context, Result};
use cairn_core_chirho::{model_chirho::HashChirho, refs_chirho, store_chirho};
use cairn_model_app_chirho::{
    app_route_head_transition_chirho as route_model_chirho, AppRouteAuthorityStateChirho,
    AppRouteRecordChirho, APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO,
};
use cairn_writer_head_chirho::{
    head_transition_authority_chirho::{
        dispatch_head_transition_chirho, HeadTransitionAuthorityPortChirho,
    },
    head_transition_chirho::{
        self as head_transition_chirho, HeadTransitionIdentityInputChirho,
        HeadTransitionRecoveryOutcomeChirho, PreparedHeadTransitionChirho,
    },
    writer_head_chirho::{self as writer_head_chirho, WriterFenceTokenChirho},
};
use std::path::{Path, PathBuf};

const APP_ROUTE_RECORDS_LOG_CHIRHO: &str = "app-route-records-chirho.jsonl";
const APP_ROUTE_HEAD_REASON_CHIRHO: &str = "app-route-deploy";

pub trait AppRouteAuthorityPortChirho {
    fn verified_app_route_records_chirho(
        &self,
        root_chirho: &Path,
    ) -> Result<Vec<AppRouteRecordChirho>>;

    fn validate_app_route_deploy_evidence_chirho(
        &self,
        root_chirho: &Path,
        state_chirho: &AppRouteAuthorityStateChirho,
    ) -> Result<()>;

    fn sign_app_route_record_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRouteRecordChirho,
    ) -> Result<String>;

    fn sign_app_route_record_with_key_possession_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRouteRecordChirho,
    ) -> Result<(String, String)>;

    fn current_root_signing_key_id_chirho(&self, root_chirho: &Path) -> Result<String>;

    fn append_signed_app_route_undeploy_record_unlocked_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        route_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<AppRouteRecordChirho>;
}

fn app_route_records_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(APP_ROUTE_RECORDS_LOG_CHIRHO)
}

fn app_route_branch_ref_name_chirho(app_chirho: &str, route_chirho: &str) -> String {
    format!("app-route/{app_chirho}/{route_chirho}")
}

pub(crate) fn app_route_ref_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&app_route_branch_ref_name_chirho(app_chirho, route_chirho))
        .cloned())
}

pub fn recover_app_route_head_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_app_route_head_unlocked_chirho(
            port_chirho,
            root_chirho,
            app_chirho,
            route_chirho,
            fence_chirho,
        )
    })
}

pub fn recover_app_route_head_unlocked_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    cairn_seqlog_chirho::seqlog_chirho::recover_jsonl_len_unlocked_chirho(
        &app_route_records_path_chirho(root_chirho),
    )?;
    let verified_records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let prepared_chirho = verified_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho == route_chirho
                && record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO
        })
        .map(|record_chirho| {
            prepared_from_verified_app_route_record_chirho(root_chirho, record_chirho)
        })
        .collect::<Result<Vec<_>>>()?;
    let current_head_chirho = app_route_ref_head_chirho(root_chirho, app_chirho, route_chirho)?;
    let Some(pending_index_chirho) =
        head_transition_chirho::pending_head_transition_index_unlocked_chirho(
            root_chirho,
            &current_head_chirho,
            &prepared_chirho,
        )?
    else {
        return Ok(None);
    };
    Ok(Some(
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho[pending_index_chirho],
            applier_fence_chirho,
        )?,
    ))
}

pub fn deploy_app_route_authority_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: AppRouteAuthorityStateChirho,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_authority_inner_chirho(port_chirho, root_chirho, state_chirho, None)
}

pub fn deploy_app_route_authority_with_head_transition_authority_chirho<
    P: AppRouteAuthorityPortChirho,
>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: AppRouteAuthorityStateChirho,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<AppRouteRecordChirho> {
    deploy_app_route_authority_inner_chirho(
        port_chirho,
        root_chirho,
        state_chirho,
        Some(authority_chirho),
    )
}

fn deploy_app_route_authority_inner_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: AppRouteAuthorityStateChirho,
    authority_chirho: Option<&dyn HeadTransitionAuthorityPortChirho>,
) -> Result<AppRouteRecordChirho> {
    let local_state_chirho = state_chirho.clone();
    dispatch_head_transition_chirho(
        root_chirho,
        authority_chirho,
        |fence_chirho| {
            deploy_app_route_authority_local_unlocked_chirho(
                port_chirho,
                root_chirho,
                local_state_chirho,
                fence_chirho,
            )
        },
        || {
            elected_app_route_deploy_chirho::prepare_elected_app_route_deploy_chirho(
                port_chirho,
                root_chirho,
                state_chirho,
            )
        },
        |prepared_chirho, scope_chirho| {
            elected_app_route_deploy_chirho::commit_elected_app_route_deploy_chirho(
                port_chirho,
                root_chirho,
                prepared_chirho,
                scope_chirho,
            )
        },
    )
}

fn deploy_app_route_authority_local_unlocked_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: AppRouteAuthorityStateChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<AppRouteRecordChirho> {
    app_route_head_removal_chirho::recover_app_route_head_removal_unlocked_chirho(
        port_chirho,
        root_chirho,
        &state_chirho.app_chirho,
        &state_chirho.route_chirho,
        fence_chirho,
    )?;
    recover_app_route_head_unlocked_chirho(
        port_chirho,
        root_chirho,
        &state_chirho.app_chirho,
        &state_chirho.route_chirho,
        fence_chirho,
    )?;
    let verified_records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let previous_chirho = app_route_ref_head_chirho(
        root_chirho,
        &state_chirho.app_chirho,
        &state_chirho.route_chirho,
    )?;
    if let Some(previous_chirho) = &previous_chirho {
        if !route_model_chirho::app_route_previous_is_verified_chirho(
            &verified_records_chirho,
            &state_chirho.app_chirho,
            &state_chirho.route_chirho,
            &state_chirho.owner_principal_chirho,
            previous_chirho,
        )? {
            bail!(
                "app route '{}/{}' ref does not select verified signed route history",
                state_chirho.app_chirho,
                state_chirho.route_chirho
            );
        }
    }
    let state_hash_chirho = store_app_route_authority_state_chirho(root_chirho, &state_chirho)?;
    if previous_chirho.as_ref() == Some(&state_hash_chirho) {
        let selected_chirho =
            route_model_chirho::selected_app_route_record_from_verified_history_chirho(
                &verified_records_chirho,
                &state_chirho.app_chirho,
                &state_chirho.route_chirho,
                &state_chirho.owner_principal_chirho,
                &state_hash_chirho,
            )?;
        require_applied_app_route_record_chirho(root_chirho, selected_chirho)?;
        return Ok(selected_chirho.clone());
    }
    let record_chirho = append_app_route_deploy_record_unlocked_chirho(
        port_chirho,
        root_chirho,
        &state_chirho,
        &state_hash_chirho,
        previous_chirho,
        fence_chirho,
    )?;
    let verified_record_chirho =
        verified_route_record_at_seq_chirho(port_chirho, root_chirho, &record_chirho)?;
    complete_verified_app_route_record_unlocked_chirho(
        root_chirho,
        &verified_record_chirho,
        fence_chirho,
    )?;
    Ok(record_chirho)
}

pub fn verified_selected_app_route_record_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    ref_target_chirho: &HashChirho,
) -> Result<AppRouteRecordChirho> {
    let records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let selected_chirho =
        route_model_chirho::selected_app_route_record_from_verified_history_chirho(
            &records_chirho,
            app_chirho,
            route_chirho,
            owner_principal_chirho,
            ref_target_chirho,
        )?;
    require_applied_app_route_record_chirho(root_chirho, selected_chirho)?;
    Ok(selected_chirho.clone())
}

fn store_app_route_authority_state_chirho(
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
) -> Result<HashChirho> {
    let stored_chirho = store_chirho::put_object_chirho(root_chirho, state_chirho)?;
    let expected_chirho = route_model_chirho::app_route_authority_state_hash_chirho(state_chirho)?;
    if stored_chirho != expected_chirho {
        bail!("stored app route authority state hash differs from its canonical identity");
    }
    Ok(stored_chirho)
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn append_pending_app_route_for_test_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
    previous_chirho: Option<HashChirho>,
) -> Result<(AppRouteRecordChirho, HashChirho, WriterFenceTokenChirho)> {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        let state_hash_chirho = store_app_route_authority_state_chirho(root_chirho, state_chirho)?;
        let record_chirho = append_app_route_deploy_record_unlocked_chirho(
            port_chirho,
            root_chirho,
            state_chirho,
            &state_hash_chirho,
            previous_chirho,
            fence_chirho,
        )?;
        Ok((record_chirho, state_hash_chirho, fence_chirho.clone()))
    })
}

#[cfg(any(test, feature = "test-hooks-chirho"))]
pub fn complete_app_route_record_for_test_chirho(
    root_chirho: &Path,
    record_chirho: &AppRouteRecordChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadTransitionRecoveryOutcomeChirho> {
    complete_verified_app_route_record_unlocked_chirho(root_chirho, record_chirho, fence_chirho)
}

fn append_app_route_deploy_record_unlocked_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    state_chirho: &AppRouteAuthorityStateChirho,
    state_hash_chirho: &HashChirho,
    previous_chirho: Option<HashChirho>,
    prepared_fence_chirho: &WriterFenceTokenChirho,
) -> Result<AppRouteRecordChirho> {
    let path_chirho = app_route_records_path_chirho(root_chirho);
    cairn_seqlog_chirho::seqlog_chirho::append_serialized_jsonl_unlocked_chirho(
        &path_chirho,
        |seq_chirho| {
            let mut record_chirho = AppRouteRecordChirho {
                seq_chirho,
                schema_chirho: APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO.to_string(),
                app_chirho: state_chirho.app_chirho.clone(),
                route_chirho: state_chirho.route_chirho.clone(),
                owner_principal_chirho: state_chirho.owner_principal_chirho.clone(),
                dag_chirho: Some(state_chirho.dag_chirho.clone()),
                action_chirho: state_chirho.action_chirho.clone(),
                request_body_policy_chirho: state_chirho.request_body_policy_chirho.clone(),
                at_ms_chirho: now_ms_chirho(),
                previous_chirho,
                transition_id_chirho: String::new(),
                prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho),
                sig_chirho: String::new(),
            };
            let operation_bytes_chirho =
                route_model_chirho::app_route_head_transition_operation_bytes_chirho(
                    &record_chirho,
                    state_hash_chirho,
                )?;
            let branch_chirho = app_route_branch_ref_name_chirho(
                &record_chirho.app_chirho,
                &record_chirho.route_chirho,
            );
            let identity_chirho = HeadTransitionIdentityInputChirho {
                family_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
                family_seq_chirho: record_chirho.seq_chirho,
                branch_chirho: &branch_chirho,
                previous_chirho: &record_chirho.previous_chirho,
                next_chirho: state_hash_chirho,
                reason_chirho: APP_ROUTE_HEAD_REASON_CHIRHO,
                operation_bytes_chirho: &operation_bytes_chirho,
                prepared_fence_chirho,
                at_ms_chirho: record_chirho.at_ms_chirho,
            };
            record_chirho.transition_id_chirho =
                head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho)?;
            record_chirho.sig_chirho =
                port_chirho.sign_app_route_record_chirho(root_chirho, &record_chirho)?;
            Ok(record_chirho)
        },
    )
}

pub fn verified_authority_state_for_app_route_record_chirho(
    root_chirho: &Path,
    record_chirho: &AppRouteRecordChirho,
) -> Result<AppRouteAuthorityStateChirho> {
    let expected_chirho =
        route_model_chirho::app_route_authority_state_from_record_chirho(record_chirho)?;
    let hash_chirho = route_model_chirho::app_route_authority_state_hash_chirho(&expected_chirho)?;
    let stored_chirho: AppRouteAuthorityStateChirho =
        store_chirho::get_object_chirho(root_chirho, &hash_chirho).with_context(|| {
            format!(
                "app route v2 record points at unavailable authority state {}",
                hash_chirho.0
            )
        })?;
    if stored_chirho != expected_chirho {
        bail!("app route authority state bytes do not match the signed route record");
    }
    Ok(stored_chirho)
}

fn prepared_from_verified_app_route_record_chirho(
    root_chirho: &Path,
    record_chirho: &AppRouteRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified app route v2 rows can become prepared head transitions");
    }
    let state_chirho =
        verified_authority_state_for_app_route_record_chirho(root_chirho, record_chirho)?;
    let state_hash_chirho =
        route_model_chirho::app_route_authority_state_hash_chirho(&state_chirho)?;
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("verified app route v2 row is missing its prepared fence epoch"))?;
    let prepared_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho: prepared_epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho =
        route_model_chirho::app_route_head_transition_operation_bytes_chirho(
            record_chirho,
            &state_hash_chirho,
        )?;
    let branch_chirho =
        app_route_branch_ref_name_chirho(&record_chirho.app_chirho, &record_chirho.route_chirho);
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &state_hash_chirho,
        reason_chirho: APP_ROUTE_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    head_transition_chirho::bind_caller_verified_head_transition_chirho(
        &identity_chirho,
        &record_chirho.transition_id_chirho,
        &serde_json::to_vec(record_chirho)?,
    )
}

pub(crate) fn require_applied_app_route_record_chirho(
    root_chirho: &Path,
    record_chirho: &AppRouteRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == APP_ROUTE_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho =
            prepared_from_verified_app_route_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("selected app route v2 record has no valid Applied receipt");
        }
    }
    Ok(())
}

fn complete_verified_app_route_record_unlocked_chirho(
    root_chirho: &Path,
    record_chirho: &AppRouteRecordChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadTransitionRecoveryOutcomeChirho> {
    let prepared_chirho =
        prepared_from_verified_app_route_record_chirho(root_chirho, record_chirho)?;
    head_transition_chirho::complete_head_transition_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )
}

fn verified_route_record_at_seq_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    expected_chirho: &AppRouteRecordChirho,
) -> Result<AppRouteRecordChirho> {
    let records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let index_chirho = usize::try_from(expected_chirho.seq_chirho)
        .context("new app route record sequence does not fit usize")?;
    records_chirho
        .get(index_chirho)
        .filter(|record_chirho| *record_chirho == expected_chirho)
        .cloned()
        .ok_or_else(|| anyhow!("new app route record did not verify at its signed sequence"))
}

fn now_ms_chirho() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
