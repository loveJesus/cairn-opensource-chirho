// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Receipted positive head transitions for resource policies: set completes its ref move with an
//! Applied receipt, and old-road reads bind the raw head to exact verified signed history.
//! Workflow: `spec-chirho/workflows-chirho/distributed-ha-chirho/cairn-engine-definition-of-done-chirho.md`.

use super::*;
use cairn_economic_governance_chirho::resource_policy_chirho::LatestPolicyEventChirho;
use cairn_writer_head_chirho::head_transition_chirho::{
    self, HeadTransitionIdentityInputChirho, HeadTransitionRecoveryOutcomeChirho,
    PreparedHeadTransitionChirho,
};

pub(super) const RESOURCE_POLICY_HEAD_REASON_CHIRHO: &str = "resource-policy";
const RESOURCE_POLICY_TRANSITION_OPERATION_SCHEMA_CHIRHO: &str =
    "resource-policy-transition-operation-v1-chirho";

fn resource_policy_transition_operation_bytes_chirho(
    record_chirho: &ResourcePolicyRecordChirho,
) -> Result<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct ResourcePolicyTransitionOperationChirho<'a_chirho> {
        schema_chirho: &'static str,
        app_chirho: &'a_chirho str,
        owner_principal_chirho: &'a_chirho str,
    }
    Ok(serde_json::to_vec(
        &ResourcePolicyTransitionOperationChirho {
            schema_chirho: RESOURCE_POLICY_TRANSITION_OPERATION_SCHEMA_CHIRHO,
            app_chirho: &record_chirho.app_chirho,
            owner_principal_chirho: &record_chirho.owner_principal_chirho,
        },
    )?)
}

/// Derive the transition id for a freshly built v2 record before it is signed, so the signature
/// covers the exact head transition the record authorizes.
pub(super) fn derive_policy_record_transition_id_chirho(
    root_chirho: &Path,
    record_chirho: &ResourcePolicyRecordChirho,
) -> Result<String> {
    let epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| anyhow!("resource policy v2 record is missing its prepared fence epoch"))?;
    let prepared_fence_chirho = writer_head_chirho::WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho = resource_policy_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = resource_policy_ref_chirho(&record_chirho.app_chirho);
    head_transition_chirho::derive_head_transition_id_chirho(&HeadTransitionIdentityInputChirho {
        family_log_chirho: RESOURCE_POLICY_RECORDS_LOG_CHIRHO,
        family_seq_chirho: record_chirho.seq_chirho,
        branch_chirho: &branch_chirho,
        previous_chirho: &record_chirho.previous_chirho,
        next_chirho: &record_chirho.resource_policy_chirho,
        reason_chirho: RESOURCE_POLICY_HEAD_REASON_CHIRHO,
        operation_bytes_chirho: &operation_bytes_chirho,
        prepared_fence_chirho: &prepared_fence_chirho,
        at_ms_chirho: record_chirho.at_ms_chirho,
    })
}

/// Bind one caller-verified v2 resource-policy record to its prepared head transition.
pub(super) fn prepared_from_verified_policy_record_chirho(
    root_chirho: &Path,
    record_chirho: &ResourcePolicyRecordChirho,
) -> Result<PreparedHeadTransitionChirho> {
    if record_chirho.schema_chirho != RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        bail!("only verified resource policy v2 rows can become prepared head transitions");
    }
    let epoch_chirho = record_chirho
        .prepared_writer_fence_epoch_chirho
        .ok_or_else(|| {
            anyhow!("verified resource policy v2 row is missing its prepared fence epoch")
        })?;
    let prepared_fence_chirho = writer_head_chirho::WriterFenceTokenChirho {
        group_chirho: writer_head_chirho::consistency_group_for_root_chirho(root_chirho)?,
        epoch_chirho,
        issued_at_ms_chirho: 0,
    };
    let operation_bytes_chirho = resource_policy_transition_operation_bytes_chirho(record_chirho)?;
    let branch_chirho = resource_policy_ref_chirho(&record_chirho.app_chirho);
    head_transition_chirho::bind_caller_verified_head_transition_chirho(
        &HeadTransitionIdentityInputChirho {
            family_log_chirho: RESOURCE_POLICY_RECORDS_LOG_CHIRHO,
            family_seq_chirho: record_chirho.seq_chirho,
            branch_chirho: &branch_chirho,
            previous_chirho: &record_chirho.previous_chirho,
            next_chirho: &record_chirho.resource_policy_chirho,
            reason_chirho: RESOURCE_POLICY_HEAD_REASON_CHIRHO,
            operation_bytes_chirho: &operation_bytes_chirho,
            prepared_fence_chirho: &prepared_fence_chirho,
            at_ms_chirho: record_chirho.at_ms_chirho,
        },
        &record_chirho.transition_id_chirho,
        &serde_json::to_vec(record_chirho)?,
    )
}

/// Recover at most one pending v2 positive transition for `app_chirho`, gated on the exact
/// verified LAST EVENT being that set record — so a receipted unset that superseded an old set can
/// never be undone by re-completing it, and a stale Applied receipt never deletes later history.
///
/// Called unconditionally on every set and unset (mirroring the billing precedent), because the
/// torn-completion window — the ref durably moved to the new head but the Applied receipt not yet
/// appended — is invisible to any parse-only head-vs-record probe, so a probe would false-negative
/// exactly there and wedge the app forever. Full verification here is the accepted set-path cost
/// (billing parity); the verified-prefix watermark is the standing perf fix.
pub(super) fn recover_resource_policy_head_transition_unlocked_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    writer_fence_chirho: &writer_head_chirho::WriterFenceTokenChirho,
) -> Result<Option<HeadTransitionRecoveryOutcomeChirho>> {
    gate1_authority_chirho::reconcile_resource_policies_authority_prefix_unlocked_chirho(
        root_chirho,
        writer_fence_chirho,
    )?;
    // Recovery reads verified states spanning BOTH policy family logs; the reconcile above only
    // tail-recovers the policy-records log, so a crash-torn unset-log tail would fail the strict
    // typed loader on every retry (a regression the removal path avoids because it reconciles the
    // unset prefix first). Repair the unset log's torn tail here too, mirroring billing recovering
    // the exact log it then strictly reads.
    seqlog_chirho::recover_jsonl_len_unlocked_chirho(&policy_unset_records_path_chirho(
        root_chirho,
    ))?;
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    let Some(LatestPolicyEventChirho::SetChirho {
        seq_chirho,
        state_chirho,
    }) = cairn_economic_governance_chirho::resource_policy_chirho::latest_policy_event_chirho(
        app_chirho,
        &states_chirho.policy_records_chirho,
        &states_chirho.policy_unset_records_chirho,
    )
    else {
        return Ok(None);
    };
    let record_chirho = verified_resource_policy_records_old_road_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| {
            record_chirho.seq_chirho == seq_chirho && record_chirho.app_chirho == app_chirho
        })
        .ok_or_else(|| {
            anyhow!("verified latest resource policy set event has no physical record row")
        })?;
    if record_chirho.schema_chirho != RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        return Ok(None);
    }
    if record_chirho.resource_policy_chirho != state_chirho.resource_policy_chirho
        || record_chirho.previous_chirho != state_chirho.previous_chirho
        || record_chirho.at_ms_chirho != state_chirho.at_ms_chirho
    {
        bail!("resource policy record row diverges from its verified state at seq {seq_chirho}");
    }
    let prepared_chirho = vec![prepared_from_verified_policy_record_chirho(
        root_chirho,
        &record_chirho,
    )?];
    let head_chirho = refs_chirho::load_refs_chirho(root_chirho)?
        .branches_chirho
        .get(&resource_policy_ref_chirho(app_chirho))
        .cloned();
    let Some(pending_index_chirho) =
        head_transition_chirho::pending_head_transition_index_unlocked_chirho(
            root_chirho,
            &head_chirho,
            &prepared_chirho,
        )?
    else {
        return Ok(None);
    };
    Ok(Some(
        head_transition_chirho::complete_head_transition_unlocked_chirho(
            root_chirho,
            &prepared_chirho[pending_index_chirho],
            writer_fence_chirho,
        )?,
    ))
}

/// Old-road read gate. Full-verifies both policy family logs — a forged or tampered row fails
/// closed here (the forge fix) — and requires the present ref head to equal the app's VERIFIED
/// LATEST SET EVENT, then receipt-gates a v2 head. The last-event rank (which billing does not need,
/// because billing has no unset/removal protocol) is what stops a ref resurrected after a receipted
/// unset, or raw-rolled-back to a superseded set, from re-authorizing revoked metered usage: those
/// heads are not the latest set event and fail closed. A v1 latest-set head is verified but not
/// receipt-gated (the documented legacy read residual until the watermark arc).
pub(super) fn require_selected_policy_head_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    head_chirho: &HashChirho,
) -> Result<()> {
    let states_chirho = verified_resource_states_with_options_chirho(root_chirho, true, false)?;
    let seq_chirho =
        match cairn_economic_governance_chirho::resource_policy_chirho::latest_policy_event_chirho(
            app_chirho,
            &states_chirho.policy_records_chirho,
            &states_chirho.policy_unset_records_chirho,
        ) {
            Some(LatestPolicyEventChirho::SetChirho {
                seq_chirho,
                state_chirho,
            }) if &state_chirho.resource_policy_chirho == head_chirho => seq_chirho,
            _ => bail!(
            "resource policy ref for app '{app_chirho}' does not match the verified latest set \
             event; refusing to serve a superseded, removed, resurrected, or forged policy head"
        ),
        };
    let selecting_chirho = verified_resource_policy_records_old_road_chirho(root_chirho)?
        .into_iter()
        .find(|record_chirho| {
            record_chirho.seq_chirho == seq_chirho && record_chirho.app_chirho == app_chirho
        })
        .ok_or_else(|| anyhow!("verified latest resource policy set event has no record row"))?;
    if selecting_chirho.schema_chirho != RESOURCE_POLICY_RECORD_V2_SCHEMA_CHIRHO {
        return Ok(());
    }
    if !head_transition_chirho::verified_head_transition_receipt_chirho(
        root_chirho,
        &prepared_from_verified_policy_record_chirho(root_chirho, &selecting_chirho)?,
    )? {
        bail!("selected resource policy v2 record has no valid Applied receipt");
    }
    Ok(())
}
