// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Source snapshot collection for signed compliance evidence packs.

use super::{digest_value_chirho, ComplianceEvidenceSourceChirho};
use crate::model_chirho::EffectChirho;
use crate::{
    agent_authority_chirho, agent_report_chirho, app_build_request_chirho, app_chirho,
    attenuation_chirho, dag_private_value_chirho, data_residency_chirho, data_rights_chirho,
    dns_apply_chirho, dns_zone_chirho, domain_binding_chirho, effect_chirho, effect_pricing_chirho,
    head_removal_chirho, head_removal_transition_chirho, identity_chirho,
    legacy_evidence_readers_chirho, legal_hold_chirho, mailbox_apply_chirho, mailbox_chirho,
    native_worker_chirho, oauth_chirho, onboarding_chirho, privacy_backup_chirho, privacy_chirho,
    realtime_ledger_bound_evidence_chirho, realtime_legacy_evidence_chirho, refs_chirho,
    resource_chirho, retention_chirho, reversion_legacy_evidence_chirho, review_chirho,
};
use anyhow::{Context, Result};
use cairn_gate1_authority_log_chirho::authority_log_chirho;
use cairn_tenant_placement_authority_chirho::topology_chirho::plan_store_chirho::plan_index_evidence_chirho;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct SourceSnapshotChirho {
    pub(super) source_chirho: String,
    pub(super) verifier_chirho: String,
    pub(super) status_chirho: String,
    pub(super) records_chirho: Vec<Value>,
    pub(super) verified_chirho: Value,
    pub(super) error_chirho: Option<String>,
    pub(super) notes_chirho: Vec<String>,
}

/// Historical accounting rows retain this captured DTO after live legacy generation is removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct AccountingControlSnapshotChirho {
    pub(super) period_start_ms_chirho: u64,
    pub(super) period_end_ms_chirho: u64,
    pub(super) ledger_verified_count_chirho: usize,
    pub(super) ledger_source_digest_chirho: String,
    pub(super) ledger_cutoff_chirho: u64,
    pub(super) period_entry_count_chirho: usize,
    pub(super) period_line_count_chirho: usize,
    pub(super) balanced_by_asset_chirho: BTreeMap<String, i64>,
}

pub(super) fn collect_source_snapshots_chirho(
    root_chirho: &Path,
) -> Result<Vec<SourceSnapshotChirho>> {
    let mut snapshots_chirho = Vec::new();
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "placement.topology-plan-index-chirho",
        "verify_topology_plan_index_chirho",
        |root_chirho| {
            plan_index_evidence_chirho::load_verified_topology_plan_index_chirho(root_chirho)
                .map_err(|refusal_chirho| anyhow::anyhow!("{refusal_chirho:?}"))
        },
        |root_chirho| {
            plan_index_evidence_chirho::verify_topology_plan_index_chirho(root_chirho)
                .map_err(|refusal_chirho| anyhow::anyhow!("{refusal_chirho:?}"))
        },
        &[
            "unsigned index: both CAS objects and canonical-plan binding verified; hashes only",
            "no grant approval, historical completeness, or subject-export claim",
        ],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.records-chirho",
        "verify_identities_chirho",
        identity_chirho::load_identities_chirho,
        identity_chirho::verify_identities_chirho,
        &["registered principals and wallet bindings"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.sessions-chirho",
        "verify_sessions_chirho",
        identity_chirho::load_sessions_chirho,
        identity_chirho::verify_sessions_chirho,
        &["signed login sessions"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.session-revocations-chirho",
        "verify_session_revocations_chirho",
        identity_chirho::load_session_revocations_chirho,
        identity_chirho::verify_session_revocations_chirho,
        &["signed login session revocations"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.credential-resets-chirho",
        "verify_credential_resets_chirho",
        identity_chirho::load_credential_resets_chirho,
        identity_chirho::verify_credential_resets_chirho,
        &["signed operator credential resets: revoke-before-replace, no credential value or hash"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.recovery-code-events-chirho",
        "verify_recovery_code_events_chirho",
        identity_chirho::load_recovery_code_events_chirho,
        identity_chirho::verify_recovery_code_events_chirho,
        &["signed recovery and setup code mints, uses and burns: a state digest, never the code or its hash"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "publication.intents-chirho",
        "verify_publication_intents_chirho",
        crate::publication_chirho::load_publication_intents_chirho,
        crate::publication_chirho::verify_publication_intents_chirho,
        &["signed self-service publication intents (the declassification act; tenant roots)"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "publication.applied-chirho",
        "verify_publication_applied_chirho",
        crate::publication_chirho::load_publication_applied_chirho,
        crate::publication_chirho::verify_publication_applied_chirho,
        &["signed platform outcomes per publication intent, viewer named by digest"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "publication.owners-chirho",
        "verify_publication_owners_chirho",
        crate::publication_chirho::apply_chirho::load_publication_owners_chirho,
        crate::publication_chirho::apply_chirho::verify_publication_owners_chirho,
        &["signed platform bindings (tenant, user digest) -> derived owner principal"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "publication.slug-claims-chirho",
        "verify_slug_claims_chirho",
        crate::publication_chirho::apply_chirho::load_slug_claims_chirho,
        crate::publication_chirho::apply_chirho::verify_slug_claims_chirho,
        &["signed first-come slug ownership at the platform level, user named by digest"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "publication.reserved-slugs-chirho",
        "verify_reserved_slugs_chirho",
        crate::publication_chirho::apply_chirho::load_reserved_slugs_chirho,
        crate::publication_chirho::apply_chirho::verify_reserved_slugs_chirho,
        &["signed operator slug reservations with a closed reason vocabulary; no subject"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.auth-attempts-chirho",
        "verify_auth_attempts_chirho",
        identity_chirho::load_auth_attempts_chirho,
        identity_chirho::verify_auth_attempts_chirho,
        &["signed public credential attempt limiter evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "identity.credential-change-attempts-chirho",
        "verify_credential_change_attempts_chirho",
        identity_chirho::load_verified_credential_change_attempts_chirho,
        identity_chirho::verify_credential_change_attempts_chirho,
        &["signed per-session credential-change guess-budget evidence; session token hash, no credential"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.clients-chirho",
        "verify_clients_chirho",
        oauth_chirho::load_clients_chirho,
        oauth_chirho::verify_clients_chirho,
        &["app-owned OAuth clients"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.connection-clients-chirho",
        "verify_connection_clients_chirho",
        oauth_chirho::load_connection_clients_chirho,
        oauth_chirho::verify_connection_clients_chirho,
        &["app-owned OAuth clients of apps opened to limited keys, in the successor-only store (K4)"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.scoped-tokens-chirho",
        "verify_scoped_tokens_chirho",
        oauth_chirho::load_scoped_tokens_chirho,
        oauth_chirho::verify_scoped_tokens_chirho,
        &["scoped access tokens"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.scoped-token-uses-chirho",
        "verify_scoped_token_uses_chirho",
        oauth_chirho::load_scoped_token_uses_chirho,
        oauth_chirho::verify_scoped_token_uses_chirho,
        &["token use and rate-limit evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.connection-tokens-chirho",
        "verify_connection_tokens_chirho",
        oauth_chirho::load_connection_tokens_chirho,
        oauth_chirho::verify_connection_tokens_chirho,
        &["limited keys of connection clients, in the successor-only store (K4)"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "oauth.connection-token-uses-chirho",
        "verify_connection_token_uses_chirho",
        oauth_chirho::load_connection_token_uses_chirho,
        oauth_chirho::verify_connection_token_uses_chirho,
        &["connection key use and rate-limit evidence, in the successor-only store (K4)"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "attenuation.grants-chirho",
        "verify_grants_chirho",
        attenuation_chirho::load_grants_chirho,
        attenuation_chirho::verify_grants_chirho,
        &["capability attenuation grants"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "agent-authority.responses-chirho",
        "verify_agent_authority_responses_chirho",
        agent_authority_chirho::load_agent_authority_response_records_chirho,
        agent_authority_chirho::verify_agent_authority_responses_chirho,
        &["admin-reviewed agent authority changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.blob-records-chirho",
        "verify_privacy_logs_chirho",
        privacy_chirho::load_privacy_blob_records_chirho,
        |root_chirho| {
            Ok(privacy_chirho::verify_privacy_logs_chirho(root_chirho)?.blob_records_chirho)
        },
        &["crypto-shredded private blob metadata"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.private-dag-values-chirho",
        "verify_private_dag_values_chirho",
        dag_private_value_chirho::load_private_dag_value_records_chirho,
        dag_private_value_chirho::verify_private_dag_values_chirho,
        &["private DAG value hashes mapped to subject-bound private blobs"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.erasure-records-chirho",
        "verify_privacy_logs_chirho",
        privacy_chirho::load_privacy_erasure_records_chirho,
        |root_chirho| {
            Ok(privacy_chirho::verify_privacy_logs_chirho(root_chirho)?.erasure_records_chirho)
        },
        &["signed crypto-shred requests"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.access-records-chirho",
        "verify_privacy_logs_chirho",
        privacy_chirho::load_privacy_access_records_chirho,
        |root_chirho| {
            Ok(privacy_chirho::verify_privacy_logs_chirho(root_chirho)?.access_records_chirho)
        },
        &["signed private blob access evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.backup-key-policies-chirho",
        "verify_privacy_backups_chirho",
        privacy_backup_chirho::load_privacy_backup_key_policy_records_chirho,
        |root_chirho| {
            Ok(
                privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)?
                    .backup_key_policy_records_chirho,
            )
        },
        &["signed backup key-material policy for erasure coverage"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.retention-records-chirho",
        "verify_private_blob_retention_chirho",
        retention_chirho::load_private_blob_retention_records_chirho,
        retention_chirho::verify_private_blob_retention_chirho,
        &["signed private-blob retention sweep evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.replica-targets-chirho",
        "verify_privacy_backups_chirho",
        privacy_backup_chirho::load_privacy_replica_targets_chirho,
        |root_chirho| {
            Ok(
                privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)?
                    .replica_targets_chirho,
            )
        },
        &["registered local backup replica roots for erasure propagation"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.erasure-propagations-chirho",
        "verify_privacy_backups_chirho",
        privacy_backup_chirho::load_privacy_erasure_propagation_records_chirho,
        |root_chirho| {
            Ok(
                privacy_backup_chirho::verify_privacy_backups_chirho(root_chirho)?
                    .erasure_propagation_records_chirho,
            )
        },
        &["signed local backup/replica shred-key propagation evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "legal-holds.records-chirho",
        "verify_legal_holds_chirho",
        legal_hold_chirho::load_legal_hold_records_chirho,
        |root_chirho| Ok(legal_hold_chirho::verify_legal_holds_chirho(root_chirho)?.records_chirho),
        &["signed per-subject legal hold place/release evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "privacy.export-evidence-chirho",
        "verify_subject_export_evidence_chirho",
        data_rights_chirho::load_subject_export_evidence_records_chirho,
        data_rights_chirho::verify_subject_export_evidence_chirho,
        &["GDPR access and portability evidence"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "data-residency.policies-chirho",
        "verify_data_residency_chirho",
        data_residency_chirho::load_data_residency_policy_records_chirho,
        data_residency_chirho::verify_data_residency_chirho,
        &[
            "tenant residency policy history; evidence of declared controls, not physical geolocation",
        ],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "domains.bindings-chirho",
        "verify_domain_binding_records_chirho",
        domain_binding_chirho::load_domain_binding_records_chirho,
        domain_binding_chirho::verify_domain_binding_records_chirho,
        &["signed host/path-to-app routing bindings; host, path prefix, app, and owner principal only, no private content"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "dns.applies-chirho",
        "verify_dns_apply_records_chirho",
        dns_apply_chirho::load_dns_apply_records_chirho,
        dns_apply_chirho::verify_dns_apply_records_chirho,
        &["signed DNS apply intent records (stub no-network performer; live provider apply is operator-gated); domain, applied zone seq, record count, and owner principal only, no private content"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "dns.zones-chirho",
        "verify_dns_zone_records_chirho",
        dns_zone_chirho::load_dns_zone_records_chirho,
        dns_zone_chirho::verify_dns_zone_records_chirho,
        &["signed desired-state DNS zone records (zones as stones); domain, record set, and owner principal only, no private content; live apply is a separate gated effect"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "mailboxes.applies-chirho",
        "verify_mailbox_apply_records_chirho",
        mailbox_apply_chirho::load_mailbox_apply_records_chirho,
        mailbox_apply_chirho::verify_mailbox_apply_records_chirho,
        &["signed mailbox apply intent records (stub no-network performer; live Mailu provisioning is operator-gated); domain, live mailbox count, and owner principal only, no addresses"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "mailboxes.records-chirho",
        "verify_mailbox_records_chirho",
        mailbox_chirho::load_mailbox_records_chirho,
        mailbox_chirho::verify_mailbox_records_chirho,
        &["signed mailbox/alias provisioning records; domain, root-private keyed local-part blind index, kind, status, hash-scheme label, and private-blob refs only; local-part and alias-target plaintext stay in crypto-shreddable private blobs"],
    )?;
    snapshots_chirho.push(data_residency_attestations_snapshot_chirho(root_chirho)?);
    snapshots_chirho.push(privacy_scan_snapshot_chirho(root_chirho)?);
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "ledger.entries-chirho",
        "verify_ledger_chirho",
        crate::legacy_ledger_evidence_chirho::load_entries_chirho,
        crate::legacy_ledger_evidence_chirho::verify_ledger_chirho,
        &["signed double-entry financial log"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "billing.policies-chirho",
        "verify_billing_policies_chirho",
        crate::legacy_billing_evidence_chirho::load_billing_policy_records_chirho,
        crate::legacy_billing_evidence_chirho::verify_billing_policies_single_road_chirho,
        &["app payer policy history"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "billing.usage-chirho",
        "verify_billing_usage_chirho",
        crate::legacy_billing_evidence_chirho::load_billing_usage_chirho,
        crate::legacy_billing_evidence_chirho::verify_billing_usage_single_road_chirho,
        &["billable effect usage records"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "billing.compensations-chirho",
        "verify_billing_compensations_chirho",
        legacy_evidence_readers_chirho::load_billing_compensations_chirho,
        crate::legacy_billing_evidence_chirho::verify_billing_compensations_single_road_chirho,
        &["compensating refunds"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "resource.policies-chirho",
        "verify_resource_policies_chirho",
        resource_chirho::load_resource_policy_records_chirho,
        resource_chirho::verify_resource_policies_chirho,
        &["app resource policies"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "resource.policy-unsets-chirho",
        "verify_resource_policy_unsets_chirho",
        resource_chirho::load_resource_policy_unset_records_chirho,
        resource_chirho::verify_resource_policy_unsets_chirho,
        &["app resource policy rollback-to-absent tombstones"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "resource.usage-chirho",
        "verify_resource_usage_chirho",
        resource_chirho::load_resource_usage_chirho,
        resource_chirho::verify_resource_usage_chirho,
        &["resource usage and billing bridges"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "pricebook.records-chirho",
        "verify_price_books_chirho",
        effect_pricing_chirho::load_price_book_records_chirho,
        effect_pricing_chirho::verify_price_books_chirho,
        &["owner-gated app price book history"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "holds.records-chirho",
        "verify_credit_holds_chirho",
        legacy_evidence_readers_chirho::load_credit_holds_chirho,
        crate::legacy_holds_evidence_chirho::verify_credit_holds_single_road_chirho,
        &["credit hold lifecycle"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.records-chirho",
        "verify_apps_chirho",
        app_chirho::load_app_records_chirho,
        app_chirho::verify_apps_chirho,
        &["app deploy and ownership changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.routes-chirho",
        "verify_app_routes_chirho",
        app_chirho::load_app_route_records_chirho,
        app_chirho::verify_app_routes_chirho,
        &["route DAG module changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.static-assets-chirho",
        "verify_app_static_assets_chirho",
        app_chirho::load_app_static_asset_records_chirho,
        app_chirho::verify_app_static_assets_chirho,
        &["owner-signed app static asset records"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.params-chirho",
        "verify_app_params_chirho",
        app_chirho::load_app_params_records_chirho,
        app_chirho::verify_app_params_chirho,
        &["signed app params hash bindings"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.client-owner-bindings-chirho",
        "verify_client_owner_bindings_chirho",
        app_chirho::load_client_owner_binding_records_chirho,
        app_chirho::verify_client_owner_bindings_chirho,
        &["signed browser-user to client-owner bindings for client-owned generated apps"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.template-registry-chirho",
        "verify_template_registry_chirho",
        app_chirho::load_template_registry_records_chirho,
        app_chirho::verify_template_registry_chirho,
        &["signed allowlist of reviewed template DAGs for app-builder deploys"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.template-deploys-chirho",
        "verify_template_app_deploy_records_chirho",
        app_chirho::load_template_app_deploy_records_chirho,
        app_chirho::verify_template_app_deploy_records_chirho,
        &["signed narrow template-app deploy audit"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.build-requests-chirho",
        "verify_app_build_request_records_chirho",
        app_build_request_chirho::load_app_build_request_records_chirho,
        |root_chirho| {
            let records_chirho =
                app_build_request_chirho::load_app_build_request_records_chirho(root_chirho)?;
            app_build_request_chirho::verify_app_build_request_records_chirho(
                root_chirho,
                &records_chirho,
            )?;
            Ok(records_chirho.len())
        },
        &["owner-gated private app build request metadata"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.input-policies-chirho",
        "verify_app_input_policies_chirho",
        app_chirho::load_app_input_policy_records_chirho,
        app_chirho::verify_app_input_policies_chirho,
        &["app input privacy policy changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.request-access-policies-chirho",
        "verify_app_request_access_policies_chirho",
        app_chirho::load_app_request_access_policy_records_chirho,
        app_chirho::verify_app_request_access_policies_chirho,
        &["app-wide authenticated request admission policy changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.key-authorities-chirho",
        "verify_app_key_authority_records_chirho",
        app_chirho::load_app_key_authority_records_chirho,
        app_chirho::verify_app_key_authority_records_chirho,
        &["app route openings to limited keys"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.response-policies-chirho",
        "verify_app_response_policies_chirho",
        app_chirho::load_app_response_policy_records_chirho,
        app_chirho::verify_app_response_policies_chirho,
        &["app root response content-type policy changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "apps.route-response-policies-chirho",
        "verify_app_route_response_policies_chirho",
        app_chirho::load_app_route_response_policy_records_chirho,
        app_chirho::verify_app_route_response_policies_chirho,
        &["app route response content-type policy changes"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "reviews.records-chirho",
        "verify_review_records_chirho",
        review_chirho::load_review_records_chirho,
        review_chirho::verify_review_records_chirho,
        &["promote-by-diff change management"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        // Intentional plural: compliance source labels use `reviews.*`; export labels use singular `review.*` for SecurityChangeAudit retention.
        "reviews.policy-envelopes-chirho",
        "verify_review_policy_envelopes_chirho",
        review_chirho::load_review_policy_envelope_records_chirho,
        review_chirho::verify_review_policy_envelopes_chirho,
        &["signed owner-scoped review authority bounds"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "onboarding.records-chirho",
        "verify_onboarding_chirho",
        onboarding_chirho::load_onboarding_records_chirho,
        onboarding_chirho::verify_onboarding_chirho,
        &["owner-managed app onboarding guide history"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "native.stateless-attestations-chirho",
        "verify_native_stateless_attestations_chirho",
        native_worker_chirho::load_native_stateless_attestations_chirho,
        native_worker_chirho::verify_native_stateless_attestations_chirho,
        &["signed native-worker statelessness and seccomp profile attestations"],
    )?;
    push_refs_snapshot_chirho(&mut snapshots_chirho, root_chirho)?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "refs.head-removals-chirho",
        "verify_head_removal_records_chirho",
        head_removal_transition_chirho::load_head_removal_evidence_values_chirho,
        head_removal_chirho::verify_head_removal_records_chirho,
        &["signed evidence for mutable head removals"],
    )?;
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "gate1.authority-log-chirho",
        "verify_gate1_authority_log_chirho",
        authority_log_chirho::load_gate1_authority_records_chirho,
        authority_log_chirho::verify_gate1_authority_log_chirho,
        &["fence-gated Gate 1 authority-log envelopes"],
    )?;
    snapshots_chirho.push(effect_snapshot_chirho(root_chirho)?);
    snapshots_chirho.push(volatile_effect_snapshot_chirho(root_chirho)?);
    push_source_chirho(
        &mut snapshots_chirho,
        root_chirho,
        "run-intents.records-chirho",
        "verify_run_intent_records_chirho",
        effect_chirho::run_intent_chirho::load_run_intent_records_chirho,
        effect_chirho::run_intent_chirho::verify_run_intent_records_chirho,
        &["signed served DAG request admission lifecycle"],
    )?;
    push_realtime_snapshots_chirho(&mut snapshots_chirho, root_chirho)?;
    push_reversion_snapshots_chirho(&mut snapshots_chirho, root_chirho)?;
    push_agent_report_snapshots_chirho(&mut snapshots_chirho, root_chirho)?;
    snapshots_chirho.sort_by(|left_chirho, right_chirho| {
        left_chirho.source_chirho.cmp(&right_chirho.source_chirho)
    });
    Ok(snapshots_chirho)
}

fn push_source_chirho<T, V, LoadChirho, VerifyChirho>(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    root_chirho: &Path,
    source_chirho: &str,
    verifier_chirho: &str,
    load_chirho: LoadChirho,
    verify_chirho: VerifyChirho,
    notes_chirho: &[&str],
) -> Result<()>
where
    T: Serialize,
    V: Serialize,
    LoadChirho: Fn(&Path) -> Result<Vec<T>>,
    VerifyChirho: Fn(&Path) -> Result<V>,
{
    let mut status_chirho = "verified-chirho".to_string();
    let mut errors_chirho = Vec::new();
    let verified_chirho = match verify_chirho(root_chirho) {
        Ok(verified_chirho) => serde_json::to_value(verified_chirho)?,
        Err(error_chirho) => {
            status_chirho = "failed-chirho".to_string();
            errors_chirho.push(format!("verify: {error_chirho}"));
            Value::Null
        }
    };
    let records_chirho = match load_chirho(root_chirho) {
        Ok(records_chirho) => records_chirho
            .into_iter()
            .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        Err(error_chirho) => {
            status_chirho = "failed-chirho".to_string();
            errors_chirho.push(format!("load: {error_chirho}"));
            Vec::new()
        }
    };
    snapshots_chirho.push(SourceSnapshotChirho {
        source_chirho: source_chirho.to_string(),
        verifier_chirho: verifier_chirho.to_string(),
        status_chirho,
        records_chirho,
        verified_chirho,
        error_chirho: (!errors_chirho.is_empty()).then(|| errors_chirho.join("; ")),
        notes_chirho: notes_chirho
            .iter()
            .map(|note_chirho| (*note_chirho).to_string())
            .collect(),
    });
    Ok(())
}

fn data_residency_attestations_snapshot_chirho(root_chirho: &Path) -> Result<SourceSnapshotChirho> {
    let mut status_chirho = "verified-chirho".to_string();
    let mut errors_chirho = Vec::new();
    let verified_chirho = match data_residency_chirho::verify_data_residency_chirho(root_chirho) {
        Ok(report_chirho) => {
            if report_chirho.noncompliant_attestations_chirho > 0 {
                status_chirho = "failed-chirho".to_string();
                errors_chirho.push(format!(
                    "noncompliant-attestations:{}",
                    report_chirho.noncompliant_attestations_chirho
                ));
            }
            serde_json::to_value(report_chirho)?
        }
        Err(error_chirho) => {
            status_chirho = "failed-chirho".to_string();
            errors_chirho.push(format!("verify: {error_chirho}"));
            Value::Null
        }
    };
    let records_chirho =
        match data_residency_chirho::load_data_residency_attestation_records_chirho(root_chirho) {
            Ok(records_chirho) => records_chirho
                .into_iter()
                .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
                .collect::<Result<Vec<_>>>()?,
            Err(error_chirho) => {
                status_chirho = "failed-chirho".to_string();
                errors_chirho.push(format!("load: {error_chirho}"));
                Vec::new()
            }
        };
    Ok(SourceSnapshotChirho {
        source_chirho: "data-residency.attestations-chirho".to_string(),
        verifier_chirho: "verify_data_residency_chirho".to_string(),
        status_chirho,
        records_chirho,
        verified_chirho,
        error_chirho: (!errors_chirho.is_empty()).then(|| errors_chirho.join("; ")),
        notes_chirho: vec![
            "signed point-in-time region assertions; operator-sourced, not hardware attestation"
                .to_string(),
            "noncompliant signed attestations are valid evidence but fail compliance posture"
                .to_string(),
        ],
    })
}

fn privacy_scan_snapshot_chirho(root_chirho: &Path) -> Result<SourceSnapshotChirho> {
    let report_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho)?;
    let finding_count_chirho = report_chirho.findings_chirho.len();
    let records_chirho = report_chirho
        .findings_chirho
        .iter()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SourceSnapshotChirho {
        source_chirho: "privacy.scan-findings-chirho".to_string(),
        verifier_chirho: "scan_privacy_surfaces_chirho".to_string(),
        status_chirho: if finding_count_chirho == 0 {
            "verified-chirho".to_string()
        } else {
            "failed-chirho".to_string()
        },
        records_chirho,
        verified_chirho: serde_json::to_value(report_chirho)?,
        error_chirho: (finding_count_chirho > 0)
            .then(|| format!("privacy scan found {finding_count_chirho} finding(s)")),
        notes_chirho: vec![
            "zero findings means no structural privacy hazards were detected".to_string(),
        ],
    })
}

fn push_refs_snapshot_chirho(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    root_chirho: &Path,
) -> Result<()> {
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let reflog_chirho = refs_chirho::reflog_chirho(root_chirho)?;
    snapshots_chirho.push(SourceSnapshotChirho {
        source_chirho: "refs.current-chirho".to_string(),
        verifier_chirho: "load_refs_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: vec![serde_json::to_value(refs_chirho)?],
        verified_chirho: json!({ "refs_chirho": 1 }),
        error_chirho: None,
        notes_chirho: vec!["current mutable branch/tag state".to_string()],
    });
    snapshots_chirho.push(SourceSnapshotChirho {
        source_chirho: "refs.reflog-chirho".to_string(),
        verifier_chirho: "reflog_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: reflog_chirho
            .into_iter()
            .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        verified_chirho: json!({ "append_only_reflog_chirho": true }),
        error_chirho: None,
        notes_chirho: vec!["branch movements and rollbacks".to_string()],
    });
    Ok(())
}

fn effect_snapshot_chirho(root_chirho: &Path) -> Result<SourceSnapshotChirho> {
    let effects_chirho = load_effect_records_chirho(root_chirho)?;
    let effect_idem_keys_chirho = effects_chirho
        .iter()
        .map(|effect_chirho| effect_chirho.idem_key_chirho.0.clone())
        .collect::<Vec<_>>();
    let effect_idem_key_digest_chirho =
        digest_value_chirho(&serde_json::to_value(&effect_idem_keys_chirho)?)?;
    Ok(SourceSnapshotChirho {
        source_chirho: "effects.records-chirho".to_string(),
        verifier_chirho: "verify_effect_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: effects_chirho
            .into_iter()
            .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        verified_chirho: json!({
            "effects_verified_chirho": true,
            "effect_membership_chirho": "idempotency-key-captured-v1-chirho",
            "effect_idem_keys_chirho": effect_idem_keys_chirho,
            "effect_idem_key_digest_chirho": effect_idem_key_digest_chirho,
        }),
        error_chirho: None,
        notes_chirho: vec!["record-replay blessed effect objects by idempotency key".to_string()],
    })
}

fn volatile_effect_snapshot_chirho(root_chirho: &Path) -> Result<SourceSnapshotChirho> {
    let records_chirho = effect_chirho::load_volatile_effect_records_chirho(root_chirho)?;
    Ok(SourceSnapshotChirho {
        source_chirho: "effects.volatile-records-chirho".to_string(),
        verifier_chirho: "load_volatile_effect_records_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: records_chirho
            .into_iter()
            .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        verified_chirho: json!({ "volatile_effect_records_verified_chirho": true }),
        error_chirho: None,
        notes_chirho: vec![
            "append-only live ReadStoreChirho/QueryChirho execution history".to_string(),
        ],
    })
}

fn load_effect_records_chirho(root_chirho: &Path) -> Result<Vec<EffectChirho>> {
    let dir_chirho = root_chirho.join("effects-chirho");
    if !dir_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    for entry_chirho in std::fs::read_dir(&dir_chirho)? {
        let path_chirho = entry_chirho?.path();
        if path_chirho.is_file() {
            paths_chirho.push(path_chirho);
        }
    }
    paths_chirho.sort();
    let mut effects_chirho = Vec::new();
    for path_chirho in paths_chirho {
        let bytes_chirho = std::fs::read(&path_chirho)
            .with_context(|| format!("read {}", path_chirho.display()))?;
        let effect_record_chirho: EffectChirho = serde_json::from_slice(&bytes_chirho)
            .with_context(|| format!("decode effect {}", path_chirho.display()))?;
        effect_chirho::verify_effect_chirho(root_chirho, &effect_record_chirho)?;
        effects_chirho.push(effect_record_chirho);
    }
    Ok(effects_chirho)
}

fn push_realtime_snapshots_chirho(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    root_chirho: &Path,
) -> Result<()> {
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "realtime.sessions-chirho",
        "verify_realtime_chirho",
        realtime_legacy_evidence_chirho::load_realtime_sessions_chirho,
        |root_chirho| {
            Ok(realtime_ledger_bound_evidence_chirho::verify_realtime_chirho(root_chirho)?.0)
        },
        &["long-lived blessed-session lifecycle records"],
    )?;
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "realtime.events-chirho",
        "verify_realtime_chirho",
        realtime_legacy_evidence_chirho::load_realtime_events_chirho,
        |root_chirho| {
            Ok(realtime_ledger_bound_evidence_chirho::verify_realtime_chirho(root_chirho)?.1)
        },
        &["session activity and settlement ticks"],
    )?;
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "realtime.epilogues-chirho",
        "verify_realtime_epilogues_chirho",
        realtime_legacy_evidence_chirho::load_realtime_epilogues_chirho,
        realtime_ledger_bound_evidence_chirho::verify_realtime_epilogues_chirho,
        &["pure-DAG session epilogue records"],
    )?;
    Ok(())
}

fn push_reversion_snapshots_chirho(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    root_chirho: &Path,
) -> Result<()> {
    let (status_chirho, verified_value_chirho, error_chirho) =
        match reversion_legacy_evidence_chirho::verify_reversion_evidence_chirho(root_chirho) {
            Ok(verified_chirho) => (
                "verified-chirho".to_string(),
                json!({
                    "rollback_events_chirho": verified_chirho.rollback_events_chirho,
                    "compensations_chirho": verified_chirho.compensations_chirho,
                    "compensation_executions_chirho": verified_chirho.compensation_executions_chirho,
                    "manual_resolutions_chirho": verified_chirho.manual_resolutions_chirho,
                    "rollback_completions_chirho": verified_chirho.rollback_completions_chirho,
                }),
                None,
            ),
            Err(error_chirho) => (
                "failed-chirho".to_string(),
                Value::Null,
                Some(error_chirho.to_string()),
            ),
        };
    push_reversion_source_chirho(
        snapshots_chirho,
        "reversion.rollback-events-chirho",
        reversion_legacy_evidence_chirho::load_rollback_events_chirho(root_chirho)?,
        &verified_value_chirho,
        &status_chirho,
        error_chirho.as_deref(),
        "signed causal rollback events",
    )?;
    push_reversion_source_chirho(
        snapshots_chirho,
        "reversion.compensations-chirho",
        reversion_legacy_evidence_chirho::load_compensation_records_chirho(root_chirho)?,
        &verified_value_chirho,
        &status_chirho,
        error_chirho.as_deref(),
        "compensation plan records",
    )?;
    push_reversion_source_chirho(
        snapshots_chirho,
        "reversion.executions-chirho",
        reversion_legacy_evidence_chirho::load_compensation_executions_chirho(root_chirho)?,
        &verified_value_chirho,
        &status_chirho,
        error_chirho.as_deref(),
        "compensation execution records",
    )?;
    push_reversion_source_chirho(
        snapshots_chirho,
        "reversion.manual-resolutions-chirho",
        reversion_legacy_evidence_chirho::load_manual_remediation_resolutions_chirho(root_chirho)?,
        &verified_value_chirho,
        &status_chirho,
        error_chirho.as_deref(),
        "manual remediation close-out records",
    )?;
    push_reversion_source_chirho(
        snapshots_chirho,
        "reversion.rollback-completions-chirho",
        reversion_legacy_evidence_chirho::load_rollback_completions_chirho(root_chirho)?,
        &verified_value_chirho,
        &status_chirho,
        error_chirho.as_deref(),
        "rollback completion summaries",
    )?;
    Ok(())
}

fn push_reversion_source_chirho<T: Serialize>(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    source_chirho: &str,
    records_chirho: Vec<T>,
    verified_chirho: &Value,
    status_chirho: &str,
    error_chirho: Option<&str>,
    note_chirho: &str,
) -> Result<()> {
    snapshots_chirho.push(SourceSnapshotChirho {
        source_chirho: source_chirho.to_string(),
        verifier_chirho: "verify_reversion_evidence_chirho".to_string(),
        status_chirho: status_chirho.to_string(),
        records_chirho: records_chirho
            .into_iter()
            .map(|record_chirho| serde_json::to_value(record_chirho).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?,
        verified_chirho: verified_chirho.clone(),
        error_chirho: error_chirho.map(str::to_string),
        notes_chirho: vec![note_chirho.to_string()],
    });
    Ok(())
}

fn push_agent_report_snapshots_chirho(
    snapshots_chirho: &mut Vec<SourceSnapshotChirho>,
    root_chirho: &Path,
) -> Result<()> {
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "agent-reports.records-chirho",
        "verify_agent_report_records_chirho",
        agent_report_chirho::load_agent_report_records_chirho,
        agent_report_chirho::verify_agent_report_records_chirho,
        &["structured agent oversight reports"],
    )?;
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "agent-reports.budget-grants-chirho",
        "verify_agent_report_accounting_chirho",
        agent_report_chirho::load_agent_report_budget_grants_chirho,
        agent_report_chirho::verify_agent_report_accounting_chirho,
        &["report budget grants"],
    )?;
    push_source_chirho(
        snapshots_chirho,
        root_chirho,
        "agent-reports.charges-chirho",
        "verify_agent_report_accounting_chirho",
        agent_report_chirho::load_agent_report_charge_records_chirho,
        agent_report_chirho::verify_agent_report_accounting_chirho,
        &["report budget charge rows"],
    )?;
    Ok(())
}
pub(super) fn source_summaries_chirho(
    snapshots_chirho: &[SourceSnapshotChirho],
) -> Result<Vec<ComplianceEvidenceSourceChirho>> {
    snapshots_chirho
        .iter()
        .map(|snapshot_chirho| {
            Ok(ComplianceEvidenceSourceChirho {
                source_chirho: snapshot_chirho.source_chirho.clone(),
                verifier_chirho: snapshot_chirho.verifier_chirho.clone(),
                status_chirho: snapshot_chirho.status_chirho.clone(),
                records_chirho: snapshot_chirho.records_chirho.len(),
                prefix_digest_chirho: digest_value_chirho(&serde_json::to_value(
                    &snapshot_chirho.records_chirho,
                )?)?,
                verified_chirho: snapshot_chirho.verified_chirho.clone(),
                error_chirho: snapshot_chirho.error_chirho.clone(),
                notes_chirho: snapshot_chirho.notes_chirho.clone(),
            })
        })
        .collect()
}
