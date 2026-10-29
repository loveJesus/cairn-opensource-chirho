// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Verifies, applies, and recovers signed app-root positive-head transitions.

use super::{
    app_record_message_chirho, app_records_path_chirho, now_ms_chirho, verified_app_records_chirho,
    AppActionChirho, AppRecordChirho, HashChirho, APP_RECORD_V2_SCHEMA_CHIRHO,
};
use crate::{refs_chirho, seqlog_chirho};
use anyhow::{anyhow, bail, Context, Result};
use cairn_model_app_chirho::app_head_transition_chirho as app_transition_model_chirho;
use cairn_signer_chirho::signer_chirho;
use cairn_writer_head_chirho::{
    head_transition_chirho::{
        self as head_transition_chirho, HeadTransitionIdentityInputChirho,
        HeadTransitionRecoveryOutcomeChirho, PreparedHeadTransitionChirho,
    },
    writer_head_chirho::{self as writer_head_chirho, WriterFenceTokenChirho},
};
use std::path::Path;

const APP_RECORDS_LOG_CHIRHO: &str = "app-records-chirho.jsonl";
const APP_HEAD_REASON_CHIRHO: &str = "app-deploy";

pub(super) fn app_ref_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HashChirho>> {
    Ok(refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&format!("app/{app_chirho}"))
        .cloned())
}

pub fn recover_app_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_app_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)
    })
}

pub(super) fn recover_app_head_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    applier_fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&app_records_path_chirho(root_chirho))?;
    let verified_records_chirho = verified_app_records_chirho(root_chirho)?;
    let prepared_chirho = verified_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.app_chirho == app_chirho
                && record_chirho.schema_chirho == APP_RECORD_V2_SCHEMA_CHIRHO
        })
        .map(|record_chirho| prepared_from_verified_app_record_chirho(root_chirho, record_chirho))
        .collect::<Result<Vec<_>>>()?;
    let current_head_chirho = app_ref_head_chirho(root_chirho, app_chirho)?;
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

pub(super) fn append_app_deploy_record_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    dag_chirho: HashChirho,
    action_chirho: AppActionChirho,
    previous_chirho: Option<HashChirho>,
    prepared_fence_chirho: &WriterFenceTokenChirho,
) -> Result<AppRecordChirho> {
    let path_chirho = app_records_path_chirho(root_chirho);
    seqlog_chirho::append_serialized_jsonl_unlocked_chirho(&path_chirho, |seq_chirho| {
        let mut record_chirho = AppRecordChirho {
            seq_chirho,
            schema_chirho: APP_RECORD_V2_SCHEMA_CHIRHO.to_string(),
            app_chirho: app_chirho.to_string(),
            owner_principal_chirho: owner_principal_chirho.to_string(),
            dag_chirho: Some(dag_chirho),
            action_chirho,
            at_ms_chirho: now_ms_chirho(),
            previous_chirho,
            transition_id_chirho: String::new(),
            prepared_writer_fence_epoch_chirho: Some(prepared_fence_chirho.epoch_chirho),
            sig_chirho: String::new(),
        };
        let operation_bytes_chirho =
            app_transition_model_chirho::app_head_transition_operation_bytes_chirho(
                &record_chirho,
            )?;
        let branch_chirho = format!("app/{app_chirho}");
        let next_chirho = record_chirho
            .dag_chirho
            .as_ref()
            .ok_or_else(|| anyhow!("app v2 deploy record is missing its DAG"))?;
        let identity_chirho = HeadTransitionIdentityInputChirho {
            family_log_chirho: APP_RECORDS_LOG_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho,
            reason_chirho: APP_HEAD_REASON_CHIRHO,
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        };
        record_chirho.transition_id_chirho =
            head_transition_chirho::derive_head_transition_id_chirho(&identity_chirho)?;
        let message_chirho = app_record_message_chirho(&record_chirho)?;
        record_chirho.sig_chirho =
            signer_chirho::sign_message_chirho(root_chirho, &message_chirho)?;
        Ok(record_chirho)
    })
}

pub(super) fn prepared_from_verified_app_record_chirho(
    root_chirho: &Path,
    record_chirho: &AppRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != APP_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified app v2 rows can become prepared head transitions");
    }
    let prepared_epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("verified app v2 row is missing its prepared fence epoch"))?;
    let prepared_fence_chirho = WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho: prepared_epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho =
        app_transition_model_chirho::app_head_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = format!("app/{}", record_chirho.app_chirho);
    let next_chirho = record_chirho
        .dag_chirho
        .as_ref()
        .ok_or_else(|| anyhow!("verified app v2 row is missing its DAG"))?;
    let identity_chirho = HeadTransitionIdentityInputChirho {
        family_log_chirho: APP_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho,
        reason_chirho: APP_HEAD_REASON_CHIRHO,
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

pub(super) fn require_applied_app_record_chirho(
    root_chirho: &Path,
    record_chirho: &AppRecordChirho,
) -> Result<()> {
    if record_chirho.schema_chirho == APP_RECORD_V2_SCHEMA_CHIRHO {
        let prepared_chirho = prepared_from_verified_app_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &prepared_chirho,
        )? {
            bail!("selected app v2 record has no valid Applied receipt");
        }
    }
    Ok(())
}

pub(super) fn complete_verified_app_record_unlocked_chirho(
    root_chirho: &Path,
    record_chirho: &AppRecordChirho,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<HeadTransitionRecoveryOutcomeChirho> {
    let prepared_chirho = prepared_from_verified_app_record_chirho(root_chirho, record_chirho)?;
    head_transition_chirho::complete_head_transition_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )
}

pub(super) fn verified_record_at_seq_chirho(
    root_chirho: &Path,
    expected_chirho: &AppRecordChirho,
) -> Result<AppRecordChirho> {
    let records_chirho = verified_app_records_chirho(root_chirho)?;
    let index_chirho = usize::try_from(expected_chirho.seq_chirho)
        .context("new app record sequence does not fit usize")?;
    records_chirho
        .get(index_chirho)
        .filter(|record_chirho| *record_chirho == expected_chirho)
        .cloned()
        .ok_or_else(|| anyhow!("new app record did not verify at its signed sequence"))
}
