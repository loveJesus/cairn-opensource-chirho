// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

//! App-route removal orchestration over root-verified mixed-version route authority.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cairn-engine-definition-of-done-chirho.md`.

use super::{
    app_route_branch_ref_name_chirho, app_route_ref_head_chirho,
    require_applied_app_route_record_chirho, AppRouteAuthorityPortChirho,
};
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
    app_route_head_transition_chirho as route_model_chirho, AppRouteActionChirho,
    AppRouteRecordChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    self as writer_head_chirho, WriterFenceTokenChirho,
};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const APP_ROUTE_RECORDS_LOG_CHIRHO: &str = "app-route-records-chirho.jsonl";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppRouteHeadRemovalRecoveryOutcomeChirho {
    LegacyV1AppliedChirho,
    TransitionChirho(HeadRemovalRecoveryOutcomeChirho),
}

pub fn recover_app_route_head_removal_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
) -> Result<Option<AppRouteHeadRemovalRecoveryOutcomeChirho>> {
    writer_head_chirho::with_head_transition_scope_chirho(root_chirho, |fence_chirho| {
        recover_app_route_head_removal_unlocked_chirho(
            port_chirho,
            root_chirho,
            app_chirho,
            route_chirho,
            fence_chirho,
        )
    })
}

pub fn recover_app_route_head_removal_unlocked_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<Option<AppRouteHeadRemovalRecoveryOutcomeChirho>> {
    writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
        .map_err(anyhow::Error::new)?;
    removal_chirho::verify_head_removal_records_chirho(root_chirho)?;
    let records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let prepared_records_chirho =
        transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    let prepared_chirho =
        bind_route_prepared_records_chirho(root_chirho, &records_chirho, &prepared_records_chirho)?;
    let branch_chirho = app_route_branch_ref_name_chirho(app_chirho, route_chirho);
    let current_chirho = app_route_ref_head_chirho(root_chirho, app_chirho, route_chirho)?;
    if let Some(index_chirho) = transition_chirho::pending_head_removal_index_unlocked_chirho(
        root_chirho,
        &branch_chirho,
        &current_chirho,
        &prepared_chirho,
    )? {
        return Ok(Some(
            AppRouteHeadRemovalRecoveryOutcomeChirho::TransitionChirho(
                transition_chirho::complete_head_removal_unlocked_chirho(
                    root_chirho,
                    &prepared_chirho[index_chirho],
                    fence_chirho,
                )?,
            ),
        ));
    }

    let Some(current_chirho) = current_chirho else {
        return Ok(None);
    };
    let legacy_chirho = removal_chirho::load_head_removal_records_chirho(root_chirho)?;
    if let Some(record_chirho) = legacy_pending_route_removal_chirho(
        &records_chirho,
        &legacy_chirho,
        app_chirho,
        route_chirho,
        &current_chirho,
    )? {
        writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
            .map_err(anyhow::Error::new)?;
        if !removal_chirho::remove_branch_after_evidence_chirho(root_chirho, record_chirho)? {
            bail!("legacy app route removal branch disappeared before delete");
        }
        return Ok(Some(
            AppRouteHeadRemovalRecoveryOutcomeChirho::LegacyV1AppliedChirho,
        ));
    }

    let Some(domain_chirho) = latest_domain_only_undeploy_chirho(
        &records_chirho,
        &legacy_chirho,
        &prepared_records_chirho,
        app_chirho,
        route_chirho,
    )?
    else {
        return Ok(None);
    };
    let historical_chirho = historical_head_before_domain_chirho(
        &records_chirho,
        app_chirho,
        route_chirho,
        &domain_chirho.owner_principal_chirho,
        &current_chirho,
        domain_chirho.seq_chirho,
    )?;
    require_applied_app_route_record_chirho(root_chirho, historical_chirho)?;
    let canonical_line_chirho = serde_json::to_vec(domain_chirho)?;
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: HeadRemovalKindChirho::AppRouteUndeployChirho,
                app_chirho,
                route_chirho: Some(route_chirho),
                owner_principal_chirho: &domain_chirho.owner_principal_chirho,
                domain_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
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
    Ok(Some(
        AppRouteHeadRemovalRecoveryOutcomeChirho::TransitionChirho(
            transition_chirho::complete_head_removal_unlocked_chirho(
                root_chirho,
                &prepared_chirho,
                fence_chirho,
            )?,
        ),
    ))
}

pub fn undeploy_app_route_head_unlocked_chirho<P: AppRouteAuthorityPortChirho>(
    port_chirho: &P,
    root_chirho: &Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    fence_chirho: &WriterFenceTokenChirho,
) -> Result<bool> {
    if recover_app_route_head_removal_unlocked_chirho(
        port_chirho,
        root_chirho,
        app_chirho,
        route_chirho,
        fence_chirho,
    )?
    .is_some()
    {
        return Ok(true);
    }
    let branch_chirho = app_route_branch_ref_name_chirho(app_chirho, route_chirho);
    let Some(current_chirho) = app_route_ref_head_chirho(root_chirho, app_chirho, route_chirho)?
    else {
        return Ok(false);
    };
    let records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let historical_chirho = historical_head_before_domain_chirho(
        &records_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
        &current_chirho,
        u64::MAX,
    )?;
    require_applied_app_route_record_chirho(root_chirho, historical_chirho)?;

    let appended_chirho = port_chirho.append_signed_app_route_undeploy_record_unlocked_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        owner_principal_chirho,
    )?;
    removal_chirho::maybe_fail_head_removal_step_chirho(
        root_chirho,
        HeadRemovalStepChirho::AfterDomainRecordChirho,
    )?;
    let verified_records_chirho = port_chirho.verified_app_route_records_chirho(root_chirho)?;
    let verified_chirho =
        verified_record_at_seq_chirho(&verified_records_chirho, &appended_chirho)?;
    let canonical_line_chirho = serde_json::to_vec(verified_chirho)?;
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: HeadRemovalKindChirho::AppRouteUndeployChirho,
                app_chirho,
                route_chirho: Some(route_chirho),
                owner_principal_chirho,
                domain_log_chirho: APP_ROUTE_RECORDS_LOG_CHIRHO,
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

fn bind_route_prepared_records_chirho(
    root_chirho: &Path,
    records_chirho: &[AppRouteRecordChirho],
    prepared_records_chirho: &[HeadRemovalPreparedRecordChirho],
) -> Result<Vec<PreparedHeadRemovalChirho>> {
    prepared_records_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.kind_chirho == HeadRemovalKindChirho::AppRouteUndeployChirho
        })
        .map(|record_chirho| {
            let route_chirho = record_chirho
                .route_chirho
                .as_deref()
                .ok_or_else(|| anyhow!("route removal Prepared record has no route"))?;
            if record_chirho.branch_chirho
                != app_route_branch_ref_name_chirho(&record_chirho.app_chirho, route_chirho)
                || record_chirho.domain_log_chirho != APP_ROUTE_RECORDS_LOG_CHIRHO
            {
                bail!("route removal Prepared record has mismatched family scope");
            }
            let domain_chirho =
                record_at_seq_chirho(records_chirho, record_chirho.domain_seq_chirho)?;
            validate_domain_undeploy_chirho(
                domain_chirho,
                &record_chirho.app_chirho,
                route_chirho,
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

fn legacy_pending_route_removal_chirho<'a>(
    records_chirho: &[AppRouteRecordChirho],
    legacy_chirho: &'a [HeadRemovalRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
    current_chirho: &HashChirho,
) -> Result<Option<&'a HeadRemovalRecordChirho>> {
    let latest_chirho = latest_route_record_chirho(records_chirho, app_chirho, route_chirho);
    let matching_chirho = legacy_chirho
        .iter()
        .filter(|record_chirho| {
            record_chirho.kind_chirho == HeadRemovalKindChirho::AppRouteUndeployChirho
                && record_chirho.branch_chirho
                    == app_route_branch_ref_name_chirho(app_chirho, route_chirho)
                && record_chirho.from_chirho == *current_chirho
                && record_chirho.app_chirho == app_chirho
                && record_chirho.route_chirho.as_deref() == Some(route_chirho)
                && record_chirho.domain_log_chirho == APP_ROUTE_RECORDS_LOG_CHIRHO
        })
        .filter(|record_chirho| {
            latest_chirho.is_some_and(|domain_chirho| {
                domain_chirho.seq_chirho == record_chirho.domain_seq_chirho
                    && validate_domain_undeploy_chirho(
                        domain_chirho,
                        app_chirho,
                        route_chirho,
                        &record_chirho.owner_principal_chirho,
                    )
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    match matching_chirho.as_slice() {
        [] => Ok(None),
        [record_chirho] => Ok(Some(*record_chirho)),
        _ => bail!("multiple legacy route removals match the current branch"),
    }
}

fn latest_domain_only_undeploy_chirho<'a>(
    records_chirho: &'a [AppRouteRecordChirho],
    legacy_chirho: &[HeadRemovalRecordChirho],
    prepared_chirho: &[HeadRemovalPreparedRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
) -> Result<Option<&'a AppRouteRecordChirho>> {
    let Some(domain_chirho) = latest_route_record_chirho(records_chirho, app_chirho, route_chirho)
    else {
        return Ok(None);
    };
    if validate_domain_undeploy_chirho(
        domain_chirho,
        app_chirho,
        route_chirho,
        &domain_chirho.owner_principal_chirho,
    )
    .is_err()
    {
        return Ok(None);
    }
    let has_legacy_chirho = legacy_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho == HeadRemovalKindChirho::AppRouteUndeployChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.as_deref() == Some(route_chirho)
            && record_chirho.domain_seq_chirho == domain_chirho.seq_chirho
    });
    let has_prepared_chirho = prepared_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho == HeadRemovalKindChirho::AppRouteUndeployChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.as_deref() == Some(route_chirho)
            && record_chirho.domain_seq_chirho == domain_chirho.seq_chirho
    });
    Ok((!has_legacy_chirho && !has_prepared_chirho).then_some(domain_chirho))
}

fn historical_head_before_domain_chirho<'a>(
    records_chirho: &'a [AppRouteRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
    current_chirho: &HashChirho,
    before_seq_chirho: u64,
) -> Result<&'a AppRouteRecordChirho> {
    for record_chirho in records_chirho.iter().rev() {
        if record_chirho.seq_chirho < before_seq_chirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho == route_chirho
            && record_chirho.owner_principal_chirho == owner_principal_chirho
            && route_model_chirho::app_route_action_is_deploy_chirho(&record_chirho.action_chirho)
            && route_model_chirho::app_route_ref_target_from_record_chirho(record_chirho)?
                == *current_chirho
        {
            return Ok(record_chirho);
        }
    }
    bail!("route removal raw head is not exact verified route authority history")
}

fn validate_domain_undeploy_chirho(
    record_chirho: &AppRouteRecordChirho,
    app_chirho: &str,
    route_chirho: &str,
    owner_principal_chirho: &str,
) -> Result<()> {
    if record_chirho.app_chirho != app_chirho
        || record_chirho.route_chirho != route_chirho
        || record_chirho.owner_principal_chirho != owner_principal_chirho
        || record_chirho.action_chirho != AppRouteActionChirho::UndeployRouteChirho
        || record_chirho.dag_chirho.is_some()
    {
        bail!("route removal domain row does not match the reviewed undeploy");
    }
    Ok(())
}

fn verified_record_at_seq_chirho<'a>(
    records_chirho: &'a [AppRouteRecordChirho],
    expected_chirho: &AppRouteRecordChirho,
) -> Result<&'a AppRouteRecordChirho> {
    let record_chirho = record_at_seq_chirho(records_chirho, expected_chirho.seq_chirho)?;
    if record_chirho != expected_chirho {
        bail!("app route undeploy append does not match exact verified record");
    }
    Ok(record_chirho)
}

fn record_at_seq_chirho(
    records_chirho: &[AppRouteRecordChirho],
    seq_chirho: u64,
) -> Result<&AppRouteRecordChirho> {
    records_chirho
        .get(seq_chirho as usize)
        .filter(|record_chirho| record_chirho.seq_chirho == seq_chirho)
        .ok_or_else(|| anyhow!("route removal domain sequence has no exact verified record"))
}

fn latest_route_record_chirho<'a>(
    records_chirho: &'a [AppRouteRecordChirho],
    app_chirho: &str,
    route_chirho: &str,
) -> Option<&'a AppRouteRecordChirho> {
    records_chirho.iter().rev().find(|record_chirho| {
        record_chirho.app_chirho == app_chirho && record_chirho.route_chirho == route_chirho
    })
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}
