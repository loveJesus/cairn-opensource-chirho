// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Receipted Prepared/Applied removal protocol for the resource-policy branch head.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cairn-engine-definition-of-done-chirho.md`.

use super::*;
use crate::head_removal_transition_chirho::{
    self as transition_chirho, HeadRemovalPreparedInputChirho, HeadRemovalPreparedRecordChirho,
    HeadRemovalRecoveryOutcomeChirho, PreparedHeadRemovalChirho,
};
use cairn_economic_governance_chirho::resource_policy_chirho::LatestPolicyEventChirho;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyHeadRemovalRecoveryOutcomeChirho {
    LegacyV1AppliedChirho {
        domain_seq_chirho: u64,
    },
    TransitionChirho {
        outcome_chirho: HeadRemovalRecoveryOutcomeChirho,
        domain_seq_chirho: u64,
    },
}

impl PolicyHeadRemovalRecoveryOutcomeChirho {
    pub fn domain_seq_chirho(&self) -> u64 {
        match self {
            Self::LegacyV1AppliedChirho { domain_seq_chirho }
            | Self::TransitionChirho {
                domain_seq_chirho, ..
            } => *domain_seq_chirho,
        }
    }
}

pub fn recover_resource_policy_head_removal_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<Option<PolicyHeadRemovalRecoveryOutcomeChirho>> {
    resource_policy_chirho::validate_app_name_chirho(app_chirho)?;
    with_resource_policy_authority_scope_chirho(root_chirho, app_chirho, |fence_chirho| {
        recover_resource_policy_head_removal_unlocked_chirho(root_chirho, app_chirho, fence_chirho)
    })
}

/// Dangling-shape probe for the set path: it recovers the unset-log tail (safe — the caller
/// holds the full authority scope), signature-verifies only the small removal log, and parses
/// the unset log, so set skips full policy-family recovery (and its whole-family verification)
/// unless removal evidence or an uncited unset row actually exists for the app.
pub(super) fn policy_removal_recovery_needed_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<bool> {
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&policy_unset_records_path_chirho(
        root_chirho,
    ))?;
    let legacy_chirho = head_removal_chirho::load_head_removal_records_chirho(root_chirho)?;
    let prepared_records_chirho =
        transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    let cited_for_app_chirho = |seq_chirho: u64| {
        cites_policy_unset_chirho(
            &legacy_chirho,
            &prepared_records_chirho,
            app_chirho,
            seq_chirho,
        )
    };
    let has_removal_rows_chirho = legacy_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho
            == head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
            && record_chirho.app_chirho == app_chirho
    }) || prepared_records_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho
            == head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
            && record_chirho.app_chirho == app_chirho
    });
    if has_removal_rows_chirho {
        return Ok(true);
    }
    Ok(load_resource_policy_unset_records_chirho(root_chirho)?
        .iter()
        .filter(|record_chirho| record_chirho.app_chirho == app_chirho)
        .any(|record_chirho| !cited_for_app_chirho(record_chirho.seq_chirho)))
}

pub(super) fn recover_resource_policy_head_removal_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Option<PolicyHeadRemovalRecoveryOutcomeChirho>> {
    writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
        .map_err(anyhow::Error::new)?;
    gate1_authority_chirho::reconcile_resource_policies_authority_prefix_unlocked_chirho(
        root_chirho,
        fence_chirho,
    )?;
    gate1_authority_chirho::reconcile_resource_policy_unsets_authority_prefix_unlocked_chirho(
        root_chirho,
        fence_chirho,
    )?;
    head_removal_chirho::verify_head_removal_records_chirho(root_chirho)?;
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    let prepared_records_chirho =
        transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
    let (prepared_chirho, prepared_domain_seqs_chirho) =
        bind_policy_prepared_records_chirho(root_chirho, &states_chirho, &prepared_records_chirho)?;
    let branch_chirho = resource_policy_ref_chirho(app_chirho);
    let current_chirho =
        head_removal_chirho::current_branch_hash_chirho(root_chirho, &branch_chirho)?;
    if let Some(index_chirho) = transition_chirho::pending_head_removal_index_unlocked_chirho(
        root_chirho,
        &branch_chirho,
        &current_chirho,
        &prepared_chirho,
    )? {
        let domain_seq_chirho = prepared_domain_seqs_chirho[index_chirho];
        return Ok(Some(
            PolicyHeadRemovalRecoveryOutcomeChirho::TransitionChirho {
                outcome_chirho: transition_chirho::complete_head_removal_unlocked_chirho(
                    root_chirho,
                    &prepared_chirho[index_chirho],
                    fence_chirho,
                )?,
                domain_seq_chirho,
            },
        ));
    }

    let Some(current_chirho) = current_chirho else {
        return Ok(None);
    };
    let legacy_chirho = head_removal_chirho::load_head_removal_records_chirho(root_chirho)?;
    if let Some(record_chirho) = legacy_pending_policy_removal_chirho(
        &states_chirho,
        &legacy_chirho,
        app_chirho,
        &current_chirho,
    )? {
        writer_head_chirho::verify_writer_fence_for_root_chirho(root_chirho, fence_chirho)
            .map_err(anyhow::Error::new)?;
        if !head_removal_chirho::remove_branch_after_evidence_chirho(root_chirho, record_chirho)? {
            bail!("legacy resource policy removal branch disappeared before delete");
        }
        return Ok(Some(
            PolicyHeadRemovalRecoveryOutcomeChirho::LegacyV1AppliedChirho {
                domain_seq_chirho: record_chirho.domain_seq_chirho,
            },
        ));
    }

    let Some((domain_seq_chirho, unset_state_chirho)) = latest_domain_only_unset_chirho(
        &states_chirho,
        &legacy_chirho,
        &prepared_records_chirho,
        app_chirho,
    ) else {
        return Ok(None);
    };
    if unset_state_chirho.previous_chirho != current_chirho {
        bail!("resource policy raw head is not exact verified set history");
    }
    historical_policy_head_chirho(
        &states_chirho,
        app_chirho,
        &unset_state_chirho.owner_principal_chirho,
        &current_chirho,
    )?;
    let canonical_line_chirho = gate1_authority_chirho::resource_policy_unset_line_at_seq_chirho(
        root_chirho,
        domain_seq_chirho,
    )?;
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho,
                app_chirho,
                route_chirho: None,
                owner_principal_chirho: &unset_state_chirho.owner_principal_chirho,
                domain_log_chirho: RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO,
                domain_seq_chirho,
                prepared_fence_chirho: fence_chirho,
                at_ms_chirho: now_ms_chirho(),
            },
            canonical_line_chirho.as_bytes(),
        )?;
    maybe_fail_chirho(root_chirho, AfterRemovalEvidenceChirho)?;
    Ok(Some(
        PolicyHeadRemovalRecoveryOutcomeChirho::TransitionChirho {
            outcome_chirho: transition_chirho::complete_head_removal_unlocked_chirho(
                root_chirho,
                &prepared_chirho,
                fence_chirho,
            )?,
            domain_seq_chirho,
        },
    ))
}

pub(super) fn unset_resource_policy_head_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_principal_chirho: &str,
    fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Option<ResourcePolicyUnsetRecordChirho>> {
    if let Some(outcome_chirho) =
        recover_resource_policy_head_removal_unlocked_chirho(root_chirho, app_chirho, fence_chirho)?
    {
        return Ok(load_resource_policy_unset_records_chirho(root_chirho)?
            .into_iter()
            .find(|unset_chirho| unset_chirho.seq_chirho == outcome_chirho.domain_seq_chirho()));
    }
    let branch_chirho = resource_policy_ref_chirho(app_chirho);
    let Some(current_chirho) =
        head_removal_chirho::current_branch_hash_chirho(root_chirho, &branch_chirho)?
    else {
        verify_receipted_policy_absence_chirho(root_chirho, app_chirho)?;
        return Ok(None);
    };
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    historical_policy_head_chirho(
        &states_chirho,
        app_chirho,
        owner_principal_chirho,
        &current_chirho,
    )?;
    let min_at_ms_chirho = states_chirho
        .policy_records_chirho
        .values()
        .rev()
        .find(|state_chirho| state_chirho.app_chirho == app_chirho)
        .map(|state_chirho| state_chirho.at_ms_chirho + 1)
        .unwrap_or(0);
    let unset_chirho = gate1_authority_chirho::append_resource_policy_unset_record_unlocked_chirho(
        root_chirho,
        fence_chirho,
        app_chirho,
        owner_principal_chirho,
        current_chirho.clone(),
        min_at_ms_chirho,
    )?;
    maybe_fail_chirho(root_chirho, AfterDomainRecordChirho)?;
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    let appended_chirho = states_chirho
        .policy_unset_records_chirho
        .get(&unset_chirho.seq_chirho)
        .ok_or_else(|| anyhow!("resource policy unset append has no exact verified state"))?;
    if appended_chirho.app_chirho != unset_chirho.app_chirho
        || appended_chirho.owner_principal_chirho != unset_chirho.owner_principal_chirho
        || appended_chirho.previous_chirho != unset_chirho.previous_chirho
        || appended_chirho.at_ms_chirho != unset_chirho.at_ms_chirho
    {
        bail!("resource policy unset append does not match exact verified record");
    }
    let canonical_line_chirho = gate1_authority_chirho::resource_policy_unset_line_at_seq_chirho(
        root_chirho,
        unset_chirho.seq_chirho,
    )?;
    if serde_json::to_vec(&unset_chirho)? != canonical_line_chirho.as_bytes() {
        bail!("resource policy unset physical line does not round-trip the signed record");
    }
    let prepared_chirho =
        transition_chirho::append_caller_verified_prepared_head_removal_unlocked_chirho(
            root_chirho,
            HeadRemovalPreparedInputChirho {
                branch_chirho: &branch_chirho,
                from_chirho: &current_chirho,
                kind_chirho: head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho,
                app_chirho,
                route_chirho: None,
                owner_principal_chirho,
                domain_log_chirho: RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO,
                domain_seq_chirho: unset_chirho.seq_chirho,
                prepared_fence_chirho: fence_chirho,
                at_ms_chirho: now_ms_chirho(),
            },
            canonical_line_chirho.as_bytes(),
        )?;
    maybe_fail_chirho(root_chirho, AfterRemovalEvidenceChirho)?;
    transition_chirho::complete_head_removal_unlocked_chirho(
        root_chirho,
        &prepared_chirho,
        fence_chirho,
    )?;
    maybe_fail_chirho(root_chirho, AfterBranchRemoveChirho)?;
    Ok(Some(unset_chirho))
}

/// Absence of the resource-policy branch is honest only when the app has no policy history
/// or its latest policy event is an unset covered by removal evidence; an uncovered latest
/// set must never read as "no limits".
pub(super) fn verify_receipted_policy_absence_chirho(
    root_chirho: &Path,
    app_chirho: &str,
) -> Result<()> {
    // Only the absence of the whole policy log is a trustworthy parse-free signal (whole-log
    // deletion is the anchors/backup arc); any per-app row scan must run over VERIFIED states,
    // or a content-edited row could hide an app's history from an unverified filter.
    if !policy_records_path_chirho(root_chirho).exists() {
        return Ok(());
    }
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    match resource_policy_chirho::latest_policy_event_chirho(
        app_chirho,
        &states_chirho.policy_records_chirho,
        &states_chirho.policy_unset_records_chirho,
    ) {
        None => Ok(()),
        Some(LatestPolicyEventChirho::SetChirho { .. }) => {
            bail!(
                "resource policy branch for app '{app_chirho}' is absent without removal \
                 evidence; refusing to read unreceipted absence as no limits"
            );
        }
        Some(LatestPolicyEventChirho::UnsetChirho { seq_chirho, .. }) => {
            let legacy_chirho = head_removal_chirho::load_head_removal_records_chirho(root_chirho)?;
            let prepared_records_chirho =
                transition_chirho::root_signed_prepared_head_removal_records_chirho(root_chirho)?;
            if !cites_policy_unset_chirho(
                &legacy_chirho,
                &prepared_records_chirho,
                app_chirho,
                seq_chirho,
            ) {
                bail!(
                    "resource policy branch for app '{app_chirho}' is absent and its latest \
                     unset record {seq_chirho} has no removal evidence; run recovery before \
                     trusting absence"
                );
            }
            Ok(())
        }
    }
}

fn cites_policy_unset_chirho(
    legacy_chirho: &[head_removal_chirho::HeadRemovalRecordChirho],
    prepared_records_chirho: &[HeadRemovalPreparedRecordChirho],
    app_chirho: &str,
    domain_seq_chirho: u64,
) -> bool {
    legacy_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho
            == head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.domain_seq_chirho == domain_seq_chirho
    }) || prepared_records_chirho.iter().any(|record_chirho| {
        record_chirho.kind_chirho
            == head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.domain_seq_chirho == domain_seq_chirho
    })
}

fn bind_policy_prepared_records_chirho(
    root_chirho: &Path,
    states_chirho: &VerifiedResourceStatesChirho,
    prepared_records_chirho: &[HeadRemovalPreparedRecordChirho],
) -> Result<(Vec<PreparedHeadRemovalChirho>, Vec<u64>)> {
    let mut bound_chirho = Vec::new();
    let mut domain_seqs_chirho = Vec::new();
    for record_chirho in prepared_records_chirho {
        if record_chirho.kind_chirho
            != head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
        {
            continue;
        }
        if record_chirho.branch_chirho != resource_policy_ref_chirho(&record_chirho.app_chirho)
            || record_chirho.route_chirho.is_some()
            || record_chirho.domain_log_chirho != RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO
        {
            bail!("resource policy removal Prepared record has mismatched family scope");
        }
        let state_chirho = states_chirho
            .policy_unset_records_chirho
            .get(&record_chirho.domain_seq_chirho)
            .ok_or_else(|| {
                anyhow!("resource policy removal domain sequence has no exact verified record")
            })?;
        validate_domain_unset_chirho(
            state_chirho,
            &record_chirho.app_chirho,
            &record_chirho.owner_principal_chirho,
            &record_chirho.from_chirho,
        )?;
        let line_chirho = gate1_authority_chirho::resource_policy_unset_line_at_seq_chirho(
            root_chirho,
            record_chirho.domain_seq_chirho,
        )?;
        bound_chirho.push(
            transition_chirho::bind_caller_verified_prepared_head_removal_chirho(
                root_chirho,
                record_chirho,
                line_chirho.as_bytes(),
            )?,
        );
        domain_seqs_chirho.push(record_chirho.domain_seq_chirho);
    }
    Ok((bound_chirho, domain_seqs_chirho))
}

fn legacy_pending_policy_removal_chirho<'a_chirho>(
    states_chirho: &VerifiedResourceStatesChirho,
    legacy_chirho: &'a_chirho [head_removal_chirho::HeadRemovalRecordChirho],
    app_chirho: &str,
    current_chirho: &HashChirho,
) -> Result<Option<&'a_chirho head_removal_chirho::HeadRemovalRecordChirho>> {
    let Some(LatestPolicyEventChirho::UnsetChirho {
        seq_chirho: latest_seq_chirho,
        state_chirho,
    }) = resource_policy_chirho::latest_policy_event_chirho(
        app_chirho,
        &states_chirho.policy_records_chirho,
        &states_chirho.policy_unset_records_chirho,
    )
    else {
        return Ok(None);
    };
    Ok(legacy_chirho.iter().find(|record_chirho| {
        record_chirho.kind_chirho
            == head_removal_chirho::HeadRemovalKindChirho::ResourcePolicyUnsetChirho
            && record_chirho.branch_chirho == resource_policy_ref_chirho(app_chirho)
            && record_chirho.from_chirho == *current_chirho
            && record_chirho.app_chirho == app_chirho
            && record_chirho.route_chirho.is_none()
            && record_chirho.domain_log_chirho == RESOURCE_POLICY_UNSET_RECORDS_LOG_CHIRHO
            && record_chirho.domain_seq_chirho == latest_seq_chirho
            && validate_domain_unset_chirho(
                state_chirho,
                app_chirho,
                &record_chirho.owner_principal_chirho,
                &record_chirho.from_chirho,
            )
            .is_ok()
    }))
}

fn latest_domain_only_unset_chirho<'a_chirho>(
    states_chirho: &'a_chirho VerifiedResourceStatesChirho,
    legacy_chirho: &[head_removal_chirho::HeadRemovalRecordChirho],
    prepared_records_chirho: &[HeadRemovalPreparedRecordChirho],
    app_chirho: &str,
) -> Option<(u64, &'a_chirho VerifiedResourcePolicyUnsetStateChirho)> {
    let Some(LatestPolicyEventChirho::UnsetChirho {
        seq_chirho,
        state_chirho,
    }) = resource_policy_chirho::latest_policy_event_chirho(
        app_chirho,
        &states_chirho.policy_records_chirho,
        &states_chirho.policy_unset_records_chirho,
    )
    else {
        return None;
    };
    (!cites_policy_unset_chirho(
        legacy_chirho,
        prepared_records_chirho,
        app_chirho,
        seq_chirho,
    ))
    .then_some((seq_chirho, state_chirho))
}

fn historical_policy_head_chirho(
    states_chirho: &VerifiedResourceStatesChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
    current_chirho: &HashChirho,
) -> Result<()> {
    states_chirho
        .policy_records_chirho
        .values()
        .rev()
        .find(|state_chirho| {
            state_chirho.app_chirho == app_chirho
                && state_chirho.owner_principal_chirho == owner_principal_chirho
                && state_chirho.resource_policy_chirho == *current_chirho
        })
        .map(|_| ())
        .ok_or_else(|| anyhow!("resource policy raw head is not exact verified set history"))
}

fn validate_domain_unset_chirho(
    state_chirho: &VerifiedResourcePolicyUnsetStateChirho,
    app_chirho: &str,
    owner_principal_chirho: &str,
    from_chirho: &HashChirho,
) -> Result<()> {
    if state_chirho.app_chirho != app_chirho
        || state_chirho.owner_principal_chirho != owner_principal_chirho
        || state_chirho.previous_chirho != *from_chirho
    {
        bail!("resource policy removal domain row does not match the reviewed unset");
    }
    Ok(())
}
