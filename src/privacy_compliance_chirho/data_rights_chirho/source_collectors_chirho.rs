// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have everlasting life. - John 3:16

//! Source-family collectors for portable subject exports.

use super::{
    exact_matches_chirho, load_subject_export_evidence_records_chirho, match_account_chirho,
    match_agent_report_body_chirho, match_agent_report_hash_chirho, match_billing_tags_chirho,
    match_capability_chirho, match_exact_chirho, match_optional_account_chirho,
    push_if_matched_chirho, push_matching_records_chirho,
    redacted_replica_target_for_subject_export_chirho, SubjectRecordExportChirho,
};
use crate::effect_chirho::run_intent_chirho;
use crate::{
    agent_authority_chirho, agent_report_chirho, app_build_request_chirho, app_chirho,
    attenuation_chirho, compliance_evidence_chirho, data_residency_chirho, effect_pricing_chirho,
    head_removal_transition_chirho, legacy_evidence_readers_chirho, onboarding_chirho,
    privacy_backup_chirho, resource_chirho, retention_chirho, reversion_legacy_evidence_chirho,
    review_chirho,
};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

pub(super) fn export_governance_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    push_matching_records_chirho(
        "attenuation.grants-chirho",
        attenuation_chirho::load_grants_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "grantor_chirho",
                &record_chirho.grantor_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "grantee_chirho",
                &record_chirho.grantee_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_capability_chirho(
                "capability_chirho",
                &record_chirho.capability_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "privacy.export-evidence-chirho",
        load_subject_export_evidence_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "subject_chirho",
                &record_chirho.subject_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "requested_by_chirho",
                &record_chirho.requested_by_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "privacy.backup-key-policies-chirho",
        privacy_backup_chirho::load_privacy_backup_key_policy_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "declared_by_chirho",
                &record_chirho.declared_by_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "privacy.retention-records-chirho",
        retention_chirho::load_private_blob_retention_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "operator_chirho",
                &record_chirho.operator_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    for record_chirho in privacy_backup_chirho::load_privacy_replica_targets_chirho(root_chirho)? {
        let matches_chirho = exact_matches_chirho(
            "registered_by_chirho",
            &record_chirho.registered_by_chirho,
            subject_chirho,
        );
        push_if_matched_chirho(
            "privacy.replica-targets-chirho",
            matches_chirho,
            redacted_replica_target_for_subject_export_chirho(&record_chirho),
            out_chirho,
        )?;
    }
    push_matching_records_chirho(
        "data-residency.policies-chirho",
        data_residency_chirho::load_data_residency_policy_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "tenant_chirho",
                &record_chirho.tenant_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "operator_chirho",
                &record_chirho.operator_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "data-residency.attestations-chirho",
        data_residency_chirho::load_data_residency_attestation_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "tenant_chirho",
                &record_chirho.tenant_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "operator_chirho",
                &record_chirho.operator_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "compliance-evidence.records-chirho",
        compliance_evidence_chirho::load_compliance_evidence_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "generated_by_chirho",
                &record_chirho.generated_by_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    Ok(())
}

pub(super) fn export_product_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    push_matching_records_chirho(
        "apps.records-chirho",
        app_chirho::load_app_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "apps.routes-chirho",
        app_chirho::load_app_route_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "apps.params-chirho",
        app_chirho::load_app_params_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "apps.client-owner-bindings-chirho",
        app_chirho::load_client_owner_binding_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "user_principal_chirho",
                &record_chirho.user_principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "apps.template-deploys-chirho",
        app_chirho::load_template_app_deploy_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "user_principal_chirho",
                &record_chirho.user_principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "apps.build-requests-chirho",
        app_build_request_chirho::load_app_build_request_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    let run_intent_subject_hashes_chirho =
        run_intent_chirho::run_intent_subject_index_hashes_chirho(root_chirho, subject_chirho)?;
    push_matching_records_chirho(
        "run-intents.records-chirho",
        run_intent_chirho::load_run_intent_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, _subject_chirho, _key_ids_chirho| {
            run_intent_chirho::run_intent_subject_matches_chirho(
                record_chirho,
                &run_intent_subject_hashes_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "pricebook.records-chirho",
        effect_pricing_chirho::load_price_book_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "billing.policy-records-chirho",
        crate::legacy_billing_evidence_chirho::load_billing_policy_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "resource.policy-records-chirho",
        resource_chirho::load_resource_policy_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "onboarding.records-chirho",
        onboarding_chirho::load_onboarding_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    Ok(())
}

pub(super) fn export_finance_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    // W1.3 scope: engine subject export keeps generic finance logs here. Stripe-family money
    // records now live in the Perffection product crate, whose subject-export contribution is a
    // named follow-up instead of a root-to-product dependency.
    push_matching_records_chirho(
        "ledger.entries-chirho",
        crate::legacy_ledger_evidence_chirho::verified_entries_single_road_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            for posting_chirho in &record_chirho.postings_chirho {
                match_account_chirho(
                    "postings_chirho.account_chirho",
                    &posting_chirho.account_chirho,
                    subject_chirho,
                    &mut matches_chirho,
                );
            }
            match_billing_tags_chirho(
                "billing_tags_chirho",
                &record_chirho.billing_tags_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "billing.usage-chirho",
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "caller_chirho",
                &record_chirho.caller_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_account_chirho(
                "payer_chirho",
                &record_chirho.payer_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_billing_tags_chirho(
                "billing_tags_chirho",
                &record_chirho.billing_tags_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "billing.compensations-chirho",
        legacy_evidence_readers_chirho::load_billing_compensations_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "caller_chirho",
                &record_chirho.caller_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_account_chirho(
                "payer_chirho",
                &record_chirho.payer_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_billing_tags_chirho(
                "billing_tags_chirho",
                &record_chirho.billing_tags_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "resource.usage-chirho",
        resource_chirho::load_resource_usage_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "user_chirho",
                &record_chirho.user_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "actor_chirho",
                &record_chirho.actor_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "credit-holds.records-chirho",
        legacy_evidence_readers_chirho::load_credit_holds_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "caller_chirho",
                &record_chirho.caller_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_account_chirho(
                "payer_chirho",
                &record_chirho.payer_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_billing_tags_chirho(
                "billing_tags_chirho",
                &record_chirho.billing_tags_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    Ok(())
}

pub(super) fn export_change_control_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    push_matching_records_chirho(
        "review.records-chirho",
        review_chirho::load_review_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "owner_principal_chirho",
                &record_chirho.owner_principal_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        // Intentional singular: export labels use `review.*` for SecurityChangeAudit retention; compliance labels use plural `reviews.*`.
        "review.policy-envelopes-chirho",
        review_chirho::load_review_policy_envelope_records_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| match &record_chirho.scope_chirho {
            review_chirho::ReviewPolicyEnvelopeScopeChirho::OwnerPrincipalChirho {
                owner_principal_chirho,
            } => exact_matches_chirho(
                "scope_chirho.owner_principal_chirho",
                owner_principal_chirho,
                subject_chirho,
            ),
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "refs.head-removals-chirho",
        head_removal_transition_chirho::load_head_removal_evidence_values_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            record_chirho["owner_principal_chirho"]
                .as_str()
                .map(|owner_chirho| {
                    exact_matches_chirho("owner_principal_chirho", owner_chirho, subject_chirho)
                })
                .unwrap_or_default()
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "reversion.rollback-events-chirho",
        reversion_legacy_evidence_chirho::load_rollback_events_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho("actor_chirho", &record_chirho.actor_chirho, subject_chirho)
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "reversion.manual-remediation-resolutions-chirho",
        reversion_legacy_evidence_chirho::load_manual_remediation_resolutions_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "operator_chirho",
                &record_chirho.operator_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    push_matching_records_chirho(
        "reversion.compensation-executions-chirho",
        reversion_legacy_evidence_chirho::load_compensation_executions_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            exact_matches_chirho(
                "caller_chirho",
                &record_chirho.caller_chirho,
                subject_chirho,
            )
        },
        key_ids_chirho,
    )?;
    Ok(())
}

pub(super) fn export_oversight_records_chirho(
    root_chirho: &Path,
    subject_chirho: &str,
    key_ids_chirho: &BTreeSet<String>,
    out_chirho: &mut Vec<SubjectRecordExportChirho>,
) -> Result<()> {
    push_matching_records_chirho(
        "agent-reports.budget-grants-chirho",
        agent_report_chirho::load_agent_report_budget_grants_chirho(root_chirho)?,
        subject_chirho,
        out_chirho,
        |record_chirho, subject_chirho, _key_ids_chirho| {
            let mut matches_chirho = Vec::new();
            match_exact_chirho(
                "agent_principal_chirho",
                &record_chirho.agent_principal_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            match_exact_chirho(
                "granted_by_chirho",
                &record_chirho.granted_by_chirho,
                subject_chirho,
                &mut matches_chirho,
            );
            matches_chirho
        },
        key_ids_chirho,
    )?;
    for record_chirho in agent_report_chirho::load_agent_report_records_chirho(root_chirho)? {
        let report_chirho = agent_report_chirho::load_agent_report_chirho(
            root_chirho,
            &record_chirho.report_chirho,
        )
        .with_context(|| format!("load agent report {}", record_chirho.report_chirho.0))?;
        let mut matches_chirho = Vec::new();
        match_exact_chirho(
            "producer_principal_chirho",
            &record_chirho.producer_principal_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_agent_report_body_chirho(
            "report_body_chirho",
            &report_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        push_if_matched_chirho(
            "agent-reports.records-chirho",
            matches_chirho,
            serde_json::json!({
                "record_chirho": record_chirho,
                "report_body_chirho": report_chirho,
            }),
            out_chirho,
        )?;
    }
    for record_chirho in agent_report_chirho::load_agent_report_charge_records_chirho(root_chirho)?
    {
        let mut matches_chirho = Vec::new();
        match_exact_chirho(
            "producer_principal_chirho",
            &record_chirho.producer_principal_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_exact_chirho(
            "priority_review_chirho.reviewer_principal_chirho",
            &record_chirho
                .priority_review_chirho
                .reviewer_principal_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_agent_report_hash_chirho(
            root_chirho,
            "report_chirho",
            &record_chirho.report_chirho,
            subject_chirho,
            &mut matches_chirho,
        )?;
        push_if_matched_chirho(
            "agent-reports.charges-chirho",
            matches_chirho,
            record_chirho,
            out_chirho,
        )?;
    }
    for record_chirho in
        agent_authority_chirho::load_agent_authority_response_records_chirho(root_chirho)?
    {
        let mut matches_chirho = Vec::new();
        match_exact_chirho(
            "admin_principal_chirho",
            &record_chirho.admin_principal_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_exact_chirho(
            "agent_principal_chirho",
            &record_chirho.agent_principal_chirho,
            subject_chirho,
            &mut matches_chirho,
        );
        match_optional_account_chirho(
            "scope_chirho",
            record_chirho.scope_chirho.as_deref(),
            subject_chirho,
            &mut matches_chirho,
        );
        match_agent_report_hash_chirho(
            root_chirho,
            "report_chirho",
            &record_chirho.report_chirho,
            subject_chirho,
            &mut matches_chirho,
        )?;
        push_if_matched_chirho(
            "agent-authority.responses-chirho",
            matches_chirho,
            record_chirho,
            out_chirho,
        )?;
    }
    Ok(())
}
