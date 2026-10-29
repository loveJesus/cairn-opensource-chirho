// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! App-root removal orchestration over root-verified app records.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cairn-engine-definition-of-done-chirho.md`.

use anyhow::{anyhow, bail, Result};
use cairn_core_chirho::model_chirho::HashChirho;
use cairn_head_removal_chirho::{
    head_removal_chirho::{
        self as removal_chirho, HeadRemovalKindChirho, HeadRemovalRecordChirho,
        HeadRemovalStepChirho,
    },
    head_removal_transition_chirho::{
        self as transition_chirho, HeadRemovalPreparedInputChirho, HeadRemovalPreparedRecordChirho,
        HeadRemovalRecoveryOutcomeChirho, PreparedHeadRemovalChirho,
    },
};
use cairn_model_app_chirho::{
    app_head_transition_chirho::app_action_is_deploy_chirho, AppActionChirho, AppRecordChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    self as writer_head_chirho, WriterFenceTokenChirho,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const APP_RECORDS_LOG_CHIRHO: &str = "app-records-chirho.jsonl";

pub trait AppHeadRemovalAuthorityPortChirho {
    fn verified_app_records_chirho(&self, root_chirho: &Path) -> Result<Vec<AppRecordChirho>>;

    fn append_signed_app_undeploy_record_unlocked_chirho(
        &self,
        root_chirho: &Path,
        app_chirho: &str,
        owner_principal_chirho: &str,
    ) -> Result<AppRecordChirho>;

    fn require_applied_historical_app_head_chirho(
        &self,
        root_chirho: &Path,
        record_chirho: &AppRecordChirho,
    ) -> Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppHeadRemovalRecoveryOutcomeChirho {
    LegacyV1AppliedChirho,
    TransitionChirho(HeadRemovalRecoveryOutcomeChirho),
}

pub fn recover_app_head_removal_chirho<P: AppHeadRemovalAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<AppHeadRemovalRecoveryOutcomeChirho>> {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_app_head_removal_unlocked_chirho(port_chirho, root_chirho, app_chirho, fence_chirho)
    })
}

pub fn recover_app_head_removal_unlocked_chirho<P: AppHeadRemovalAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<AppHeadRemovalRecoveryOutcomeChirho>> {
    writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
        .map_err(anyhow::Error::new)?;
    removal_chirho::verify_head_removal_records_chirho(root_chirho)?;
    let records_chirho = port_chirho.verified_app_records_chirho(root_chirho)?;
    let prepared_records_chirho =
        transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    let prepared_chirho =
        bind_app_prepared_records_chirho(root_chirho, &records_chirho, &prepared_records_chirho)?;
    let branch_chirho = app_branch_chirho(app_chirho);
    let current_chirho = removal_chirho::current_branch_hash_chirho(root_chirho, &branch_chirho)?;
    if let Some(index_chirho) = transition_chirho::pending_head_removal_index_unlocked_chirho(
        root_chirho,
        &branch_chirho,
        &current_chirho,
        &prepared_chirho,
    )? {
        return Ok(Some(AppHeadRemovalRecoveryOutcomeChirho::TransitionChirho(
            transition_chirho::complete_head_removal_unlocked_chirho(
                root_chirho,
                &prepared_chirho[index_chirho],
                fence_chirho,
            )?,
        )));
    }

    let Some(current_chirho) = current_chirho else {
        return Ok(None);
    };
    let legacy_chirho = removal_chirho::load_head_removal_records_chirho(root_chirho)?;
    if let Some(record_chirho) = legacy_pending_app_removal_chirho(
        &records_chirho,
        &legacy_chirho,
        app_chirho,
        &current_chirho,
    )? {
        writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
            .map_err(anyhow::Error::new)?;
        if !removal_chirho::remove_branch_after_evidence_chirho(root_chirho, record_chirho)? {
            bail!("legacy app removal branch disappeared before delete");
        }
        return Ok(Some(
            AppHeadRemovalRecoveryOutcomeChirho::LegacyV1AppliedChirho,
        ));
    }

    let Some(domain_chirho) = latest_domain_only_undeploy_chirho(
        &records_chirho,
        &legacy_chirho,
        &prepared_records_chirho,
        app_chirho,
    )?
    else {
        return Ok(None);
    };
    let historical_chirho = historical_head_before_domain_chirho(
        &records_chirho,
        app_chirho,
        &domain_chirho.owner_principal_chirho,
        &current_chirho,
        domain_chirho.seq_chirho,
    )?;
    port_chirho.require_applied_historical_app_head_chirho(root_chirho, historical_chirho)?;
    let canonical_line_chirho = serde_json::to_vec(domain_chirho)?;
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                app_chirho,
                route_chirho: None,
                owner_principal_chirho: &domain_chirho.owner_principal_chirho,
                domain_log_chirho: APP_RECORDS_LOG_CHIRHO,
                domain_seq_chirho: domain_chirho.seq_chirho,
                prepared_fence_chirho: fence_chirho,
                at_ms_chirho: now_ms_chirho(),
            },
            &canonical_line_chirho,
        )?;
    removal_chirho::maybe_fail_head_removal_step_chirho(
        root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    )?;
    Ok(Some(AppHeadRemovalRecoveryOutcomeChirho::TransitionChirho(
        transition_chirho::complete_head_removal_unlocked_chirho(
            root_chirho,
            &prepared_chirho,
            fence_chirho,
        )?,
    )))
}

pub fn undeploy_app_head_unlocked_chirho<P: AppHeadRemovalAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<bool> {
    if recover_app_head_removal_unlocked_chirho(port_chirho, root_chirho, app_chirho, fence_chirho)?
        .is_some()
    {
        return Ok(true);
    }
    let branch_chirho = app_branch_chirho(app_chirho);
    let Some(current_chirho) =
        removal_chirho::current_branch_hash_chirho(root_chirho, &branch_chirho)?
    else {
        return Ok(false);
    };
    let records_chirho = port_chirho.verified_app_records_chirho(root_chirho)?;
    let historical_chirho = historical_head_before_domain_chirho(
        &records_chirho,
        app_chirho,
        owner_principal_chirho,
        &current_chirho,
        u64::MAX,
    )?;
    port_chirho.require_applied_historical_app_head_chirho(root_chirho, historical_chirho)?;

    let appended_chirho = port_chirho.append_signed_app_undeploy_record_unlocked_chirho(
        root_chirho,
        app_chirho,
        owner_principal_chirho,
    )?;
    removal_chirho::maybe_fail_head_removal_step_chirho(
        root_chirho,
        HeadRemovalStepChirho::AfterDomainRecordChirho,
    )?;
    let verified_records_chirho = port_chirho.verified_app_records_chirho(root_chirho)?;
    let verified_chirho =
        verified_record_at_seq_chirho(&verified_records_chirho, &appended_chirho)?;
    let canonical_line_chirho = serde_json::to_vec(verified_chirho)?;
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: HeadRemovalKindChirho::AppUndeployChirho,
                app_chirho,
                route_chirho: None,
                owner_principal_chirho,
                domain_log_chirho: APP_RECORDS_LOG_CHIRHO,
                domain_seq_chirho: verified_chirho.seq_chirho,
                prepared_fence_chirho: fence_chirho,
                at_ms_chirho: now_ms_chirho(),
            },
            &canonical_line_chirho,
        )?;
    removal_chirho::maybe_fail_head_removal_step_chirho(
        root_chirho,
        HeadRemovalStepChirho::AfterRemovalEvidenceChirho,
    )?;
    transition_chirho::complete_head_removal_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )?;
    removal_chirho::maybe_fail_head_removal_step_chirho(
        root_chirho,
        HeadRemovalStepChirho::AfterBranchRemoveChirho,
    )?;
    Ok(true)
}

fn bind_app_prepared_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppRecordChirho],
    prepared_records_chirho: &[HeadRemovalPreparedRecordChirho],
) -> Result<Vec<PreparedHeadRemovalChirho>> {
    prepared_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.kind_chirho == HeadRemovalKindChirho::AppUndeployChirho
        })
        .map(|record_chirho| {
            let expected_branch_chirho = app_branch_chirho(&record_chirho.app_chirho);
            if record_chirho.branch_chirho != expected_branch_chirho
                || record_chirho.route_chirho.is_some()
                || record_chirho.domain_log_chirho != APP_RECORDS_LOG_CHIRHO
            {
                bail!("app removal Prepared record has mismatched family scope");
            }
            let domain_chirho =
                record_at_seq_chirho(records_chirho, record_chirho.domain_seq_chirho)?;
            validate_domain_undeploy_chirho(
                domain_chirho,
                &record_chirho.app_chirho,
                &record_chirho.owner_principal_chirho,
            )?;
            transition_chirho::bind_caller_verified_prepared_head_removal_chirho(
                root_chirho,
                record_chirho,
                &serde_json::to_vec(domain_chirho)?,
            )
        })
        .collect()
}

fn legacy_pending_app_removal_chirho<'a>(
    records_chirho: &[AppRecordChirho],
    legacy_chirho: &'a [HeadRemovalRecordChirho],
    app_chirho: &str,
    current_chirho: &HashChirho,
) -> Result<Option<&'a HeadRemovalRecordChirho>> {
    let latest_chirho = latest_app_record_chirho(records_chirho, app_chirho);
    let matching_chirho = legacy_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.kind_chirho == HeadRemovalKindChirho::AppUndeployChirho
                && record_chirho.branch_chirho == app_branch_chirho(app_chirho)
                && record_chirho.from_chirho == *current_chirho
                && record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.is_none()
                && record_chirho.domain_log_chirho == APP_RECORDS_LOG_CHIRHO
        })
        .filter(|record_chirho| {
            latest_chirho.is_some_and(|domain_chirho| {
                domain_chirho.seq_chirho == record_chirho.domain_seq_chirho
                    && validate_domain_undeploy_chirho(
                        domain_chirho,
                        app_chirho,
                        &record_chirho.owner_principal_chirho,
                    )
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    match matching_chirho.as_slice() {
        [] => Ok(None),
        [record_chirho] => Ok(Some(*record_chirho)),
        _ => bail!("multiple legacy app removals match the current branch"),
    }
}

fn latest_domain_only_undeploy_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    legacy_chirho: &[HeadRemovalRecordChirho],
    prepared_chirho: &[HeadRemovalPreparedRecordChirho],
    app_chirho: &str,
) -> Result<Option<&'a AppRecordChirho>> {
    let Some(domain_chirho) = latest_app_record_chirho(records_chirho, app_chirho) else {
        return Ok(None);
    };
    if validate_domain_undeploy_chirho(
        domain_chirho,
        app_chirho,
        &domain_chirho.owner_principal_chirho,
    )
    .is_err()
    {
        return Ok(None);
    }
    let has_legacy_chirho = legacy_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho == HeadRemovalKindChirho::AppUndeployChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.domain_seq_chirho == domain_chirho.seq_chirho
    });
    let has_prepared_chirho = prepared_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho == HeadRemovalKindChirho::AppUndeployChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.domain_seq_chirho == domain_chirho.seq_chirho
    });
    Ok((!has_legacy_chirho && !has_prepared_chirho).then_some(domain_chirho))
}

fn historical_head_before_domain_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    app_chirho: &str,
    owner_principal_chirho: &str,
    current_chirho: &HashChirho,
    before_seq_chirho: u64,
) -> Result<&'a AppRecordChirho> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| {
            record_chirho.seq_chirho < before_seq_chirho
                && record_chirho.app_chirho == app_chirho
                && record_chirho.owner_principal_chirho == owner_principal_chirho
                && app_action_is_deploy_chirho(&record_chirho.action_chirho)
                && record_chirho.dag_chirho.as_ref() == Some(current_chirho)
        })
        .ok_or_else(|| anyhow!("app removal raw head is not exact verified deploy history"))
}

fn validate_domain_undeploy_chirho(
    record_chirho: &AppRecordChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<()> {
    if record_chirho.app_chirho != app_chirho
        || record_chirho.owner_principal_chirho != owner_principal_chirho
        || record_chirho.action_chirho != AppActionChirho::UndeployChirho
        || record_chirho.dag_chirho.is_some()
    {
        bail!("app removal domain row does not match the reviewed undeploy");
    }
    Ok(())
}

fn verified_record_at_seq_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    expected_chirho: &AppRecordChirho,
) -> Result<&'a AppRecordChirho> {
    let record_chirho = record_at_seq_chirho(records_chirho, expected_chirho.seq_chirho)?;
    if record_chirho != expected_chirho {
        bail!("app undeploy append does not match exact verified record");
    }
    Ok(record_chirho)
}

fn record_at_seq_chirho(
    records_chirho: &[AppRecordChirho],
    seq_chirho: u64,
) -> Result<&AppRecordChirho> {
    records_chirho
        .get(seq_chirho as usize)
        .filter(|record_chirho| record_chirho.seq_chirho == seq_chirho)
        .ok_or_else(|| anyhow!("app removal domain sequence has no exact verified record"))
}

fn latest_app_record_chirho<'a>(
    records_chirho: &'a [AppRecordChirho],
    app_chirho: &str,
) -> Option<&'a AppRecordChirho> {
    records_chirho
        .iter()
        .rev()
        .find(|record_chirho| record_chirho.app_chirho == app_chirho)
}

fn app_branch_chirho(app_chirho: &str) -> String {
    format!("app/{app_chirho}")
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}
