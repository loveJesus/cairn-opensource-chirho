// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Workflow: spec-chirho/workflows-chirho/distributed-ha-chirho/write-forwarding-chirho/elected-control-chirho/workflow-chirho.md.

use super::*;
use crate::elected_control_prepare_chirho::PreparedControlInputsChirho;
use cairn_writer_head_chirho::{
    head_transition_authority_chirho::{
        dispatch_head_transition_chirho, HeadTransitionAuthorityPortChirho,
        HeadTransitionCommitScopeChirho,
    },
    head_transition_chirho::PreparedFenceHeadTransitionIdentityInputChirho,
    writer_head_chirho::observe_prepared_fence_lower_bound_chirho,
};

const INPUTS_CHIRHO: &[&str] = &[
    ONBOARDING_RECORDS_LOG_CHIRHO,
    "app-records-chirho.jsonl",
    "identities-chirho.jsonl",
    "refs-chirho.json",
    "reflog-chirho.jsonl",
];

struct PreparedGuideChirho {
    guide_chirho: OnboardingGuideChirho,
    record_chirho: OnboardingRecordChirho,
    head_chirho: PreparedHeadTransitionChirho,
    inputs_chirho: PreparedControlInputsChirho,
}

pub fn set_onboarding_guide_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    title_chirho: &str,
    steps_chirho: Vec<OnboardingStepChirho>,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<(HashChirho, OnboardingGuideChirho, OnboardingRecordChirho)> {
    validate_app_name_chirho(app_chirho)?;
    let local_steps_chirho = steps_chirho.clone();
    dispatch_head_transition_chirho(
        root_chirho,
        Some(authority_chirho),
        |fence_chirho| {
            set_onboarding_guide_unlocked_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                title_chirho,
                local_steps_chirho,
                fence_chirho,
            )
        },
        || {
            prepare_guide_chirho(
                root_chirho,
                app_chirho,
                owner_principal_chirho,
                title_chirho,
                steps_chirho,
            )
        },
        |prepared_chirho, scope_chirho| {
            commit_guide_chirho(root_chirho, prepared_chirho, scope_chirho)
        },
    )
}

fn prepare_guide_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    title_chirho: &str,
    steps_chirho: Vec<OnboardingStepChirho>,
) -> Result<PreparedGuideChirho> {
    let inputs_chirho = PreparedControlInputsChirho::capture_chirho(root_chirho, INPUTS_CHIRHO)?;
    app_chirho::ensure_app_owner_chirho(root_chirho, app_chirho, owner_principal_chirho)?;
    let history_chirho = verified_onboarding_records_chirho(root_chirho)?;
    for record_chirho in history_chirho.iter().filter(|record_chirho| {
        record_chirho.app_chirho == app_chirho
            && record_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
    }) {
        let head_chirho =
            prepared_from_verified_onboarding_record_chirho(root_chirho, record_chirho)?;
        if !head_transition_chirho::verified_head_transition_receipt_chirho(
            root_chirho,
            &head_chirho,
        )? {
            bail!("OnboardingHeadSettlementRequiredChirho");
        }
    }
    let previous_chirho = current_onboarding_hash_chirho(root_chirho, app_chirho)?;
    let guide_chirho = OnboardingGuideChirho {
        app_chirho: app_chirho.to_owned(),
        owner_principal_chirho: owner_principal_chirho.to_owned(),
        title_chirho: title_chirho.trim().to_owned(),
        steps_chirho,
        previous_chirho: previous_chirho.clone(),
        at_ms_chirho: now_ms_chirho(),
    };
    validate_onboarding_guide_chirho(&guide_chirho)?;
    let group_chirho = writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?;
    let fence_chirho = observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
    let mut record_chirho = OnboardingRecordChirho {
        seq_chirho: u64::try_from(history_chirho.len())?,
        schema_chirho: ONBOARDING_RECORD_V2_SCHEMA_CHIRHO.to_owned(),
        app_chirho: app_chirho.to_owned(),
        owner_principal_chirho: owner_principal_chirho.to_owned(),
        guide_chirho: store_chirho::hash_object_chirho(&guide_chirho)?,
        previous_chirho,
        at_ms_chirho: guide_chirho.at_ms_chirho,
        transition_id_chirho: String::new(),
        prepared_writer_fence_epoch_chirho: Some(fence_chirho.epoch_chirho()),
        sig_chirho: String::new(),
    };
    let operation_chirho = onboarding_transition_operation_bytes_chirho(&record_chirho)?;
    let branch_chirho = onboarding_ref_chirho(app_chirho);
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        family_log_chirho: ONBOARDING_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.guide_chirho,
        reason_chirho: ONBOARDING_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_chirho,
        prepared_fence_chirho: &fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    };
    record_chirho.transition_id_chirho =
        head_transition_chirho::derive_head_transition_id_from_prepared_fence_chirho(
            &identity_chirho,
        )?;
    record_chirho.sig_chirho = signer_chirho::sign_with_existing_key_possession_chirho(
        root_chirho,
        &onboarding_record_message_chirho(&record_chirho)?,
    )?
    .into_signature_hex_chirho();
    let operation_chirho = onboarding_transition_operation_bytes_chirho(&record_chirho)?;
    let identity_chirho = PreparedFenceHeadTransitionIdentityInputChirho {
        operation_bytes_chirho: &operation_chirho,
        ..identity_chirho
    };
    let head_chirho =
        head_transition_chirho::bind_caller_verified_head_transition_from_prepared_fence_chirho(
            &identity_chirho,
            &record_chirho.transition_id_chirho,
            &serde_json::to_vec(&record_chirho)?,
        )?;
    inputs_chirho.validate_chirho(root_chirho)?;
    Ok(PreparedGuideChirho {
        guide_chirho,
        record_chirho,
        head_chirho,
        inputs_chirho,
    })
}

fn commit_guide_chirho(
    root_chirho: &Path,
    prepared_chirho: PreparedGuideChirho,
    scope_chirho: HeadTransitionCommitScopeChirho<'_>,
) -> Result<(HashChirho, OnboardingGuideChirho, OnboardingRecordChirho)> {
    scope_chirho.preflight_head_transition_chirho(root_chirho, &prepared_chirho.head_chirho)?;
    let _lifecycle_chirho = prepared_chirho
        .inputs_chirho
        .hold_for_commit_chirho(root_chirho)?;
    let hash_chirho = store_chirho::put_object_chirho(root_chirho, &prepared_chirho.guide_chirho)?;
    seqlog_chirho::append_recovered_jsonl_unlocked_chirho(
        &onboarding_records_path_chirho(root_chirho),
        prepared_chirho.record_chirho.seq_chirho,
        &prepared_chirho.record_chirho,
    )?;
    scope_chirho.complete_head_transition_chirho(root_chirho, &prepared_chirho.head_chirho)?;
    Ok((
        hash_chirho,
        prepared_chirho.guide_chirho,
        prepared_chirho.record_chirho,
    ))
}

pub fn recover_onboarding_head_with_head_transition_authority_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    authority_chirho: &dyn HeadTransitionAuthorityPortChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    validate_app_name_chirho(app_chirho)?;
    dispatch_head_transition_chirho(
        root_chirho,
        Some(authority_chirho),
        |fence_chirho| {
            recover_onboarding_head_unlocked_chirho(root_chirho, app_chirho, fence_chirho)
        },
        || {
            let inputs_chirho =
                PreparedControlInputsChirho::capture_chirho(root_chirho, INPUTS_CHIRHO)?;
            let history_chirho = verified_onboarding_records_chirho(root_chirho)?;
            let transitions_chirho = history_chirho
                .iter()
                .filter(|record_chirho| {
                    record_chirho.app_chirho == app_chirho
                        && record_chirho.schema_chirho == ONBOARDING_RECORD_V2_SCHEMA_CHIRHO
                })
                .map(|record_chirho| {
                    prepared_from_verified_onboarding_record_chirho(root_chirho, record_chirho)
                })
                .collect::<Result<Vec<_>>>()?;
            let group_chirho = writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?;
            let fence_chirho =
                observe_prepared_fence_lower_bound_chirho(root_chirho, &group_chirho)?;
            inputs_chirho.validate_chirho(root_chirho)?;
            Ok((inputs_chirho, transitions_chirho, fence_chirho))
        },
        |(inputs_chirho, transitions_chirho, fence_chirho), scope_chirho| {
            scope_chirho.preflight_prepared_fence_chirho(root_chirho, &fence_chirho)?;
            let _lifecycle_chirho = inputs_chirho.hold_for_commit_chirho(root_chirho)?;
            let current_chirho = onboarding_ref_head_chirho(root_chirho, app_chirho)?;
            let index_chirho =
                head_transition_chirho::pending_head_transition_index_unlocked_chirho(
                    root_chirho,
                    &current_chirho,
                    &transitions_chirho,
                )?;
            let pending_chirho = index_chirho
                .and_then(|index_chirho| transitions_chirho.into_iter().nth(index_chirho));
            pending_chirho
                .map(|pending_chirho| {
                    scope_chirho.complete_head_transition_chirho(root_chirho, &pending_chirho)
                })
                .transpose()
        },
    )
}
