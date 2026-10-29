// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Thin CLI shell for report and fail-gate commands.

use crate::args_chirho::CommandChirho;
use cairn_report_command_chirho as report_command_chirho;
use std::path::Path;

#[cfg(test)]
pub(crate) use report_command_chirho::{
    enforce_compliance_evidence_fail_on_coverage_gaps_chirho,
    enforce_compliance_evidence_fail_on_failed_sources_chirho,
    enforce_compliance_evidence_fail_on_manual_controls_chirho,
    enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho,
    enforce_compliance_evidence_verify_fail_on_failed_sources_chirho,
    enforce_compliance_evidence_verify_fail_on_manual_controls_chirho,
    enforce_data_residency_fail_on_violations_chirho, enforce_privacy_scan_fail_on_findings_chirho,
    enforce_privacy_verify_fail_on_empty_evidence_chirho, privacy_verify_cli_report_chirho,
    volatile_effect_list_cli_report_chirho, volatile_effect_list_text_chirho,
    PrivacyVerifyCliReportChirho, PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO,
    VOLATILE_EFFECT_LIST_REPORT_SCHEMA_CHIRHO,
};

pub(crate) fn handle_volatile_effect_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::VolatileEffectsChirho(args_chirho) => {
            report_command_chirho::run_volatile_effects_report_chirho(
                root_chirho,
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::VolatileEffectsVerifyChirho(args_chirho) => {
            report_command_chirho::run_volatile_effects_verify_report_chirho(
                root_chirho,
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_smoke_report_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::ContactExampleSmokeChirho(args_chirho) => {
            report_command_chirho::run_contact_example_smoke_report_chirho(
                root_chirho,
                args_chirho.manifest_chirho.as_deref(),
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoSmokeChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_smoke_report_chirho(
                root_chirho,
                &args_chirho.config_chirho,
                &args_chirho.expected_config_digest_chirho,
                &args_chirho.plan_chirho,
                &args_chirho.expected_plan_digest_chirho,
                &args_chirho.issuer_secret_name_chirho,
                &args_chirho.activation_authorization_chirho,
                &args_chirho.expected_activation_authorization_digest_chirho,
                &args_chirho.payer_credential_secret_name_chirho,
                &args_chirho.app_root_chirho,
                args_chirho.manifest_chirho.as_deref(),
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoGeoSeedChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_geo_seed_report_chirho(
                root_chirho,
                &args_chirho.config_chirho,
                &args_chirho.expected_config_digest_chirho,
                &args_chirho.plan_chirho,
                &args_chirho.expected_plan_digest_chirho,
                &args_chirho.issuer_secret_name_chirho,
                &args_chirho.activation_authorization_chirho,
                &args_chirho.expected_activation_authorization_digest_chirho,
                &args_chirho.payer_credential_secret_name_chirho,
                &args_chirho.app_root_chirho,
                args_chirho.manifest_chirho.as_deref(),
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CasLifecycleBootstrapChirho(args_chirho) => {
            report_command_chirho::run_cas_lifecycle_bootstrap_report_chirho(
                root_chirho,
                args_chirho.offline_migration_quiesced_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoContinuationChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_continuation_report_chirho(
                root_chirho,
                &args_chirho.reviewed_inputs_dir_chirho,
                &args_chirho.expected_config_digest_chirho,
                &args_chirho.storage_namespace_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoReviewedCandidatePinChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_reviewed_candidate_pin_report_chirho(
                root_chirho,
                &args_chirho.source_review_report_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoInputsAuthorChirho(args_chirho) => {
            let destination_authority_enrollment_chirho =
                cairn_ledger_regenesis_chirho::read_digest_bound_destination_authority_enrollment_chirho(
                    &args_chirho.destination_authority_enrollment_path_chirho,
                    &args_chirho.expected_destination_authority_enrollment_digest_chirho,
                    &args_chirho.cluster_genesis_roster_path_chirho,
                    &args_chirho.cluster_genesis_roster_head_path_chirho,
                    &args_chirho.cluster_genesis_roster_operator_pubkey_hex_chirho,
                )?;
            report_command_chirho::run_credits_demo_inputs_author_report_chirho(
                &report_command_chirho::CreditsDemoInputsAuthorRequestChirho {
                    root_chirho,
                    payer_chirho: &args_chirho.payer_chirho,
                    config_output_chirho: &args_chirho.config_output_chirho,
                    plan_output_chirho: &args_chirho.plan_output_chirho,
                    activation_authorization_output_chirho: &args_chirho
                        .activation_authorization_output_chirho,
                    issuer_secret_name_chirho: &args_chirho.issuer_secret_name_chirho,
                    activation_secret_name_chirho: &args_chirho.activation_secret_name_chirho,
                    payer_credential_secret_name_chirho: &args_chirho
                        .payer_credential_secret_name_chirho,
                    destination_authority_enrollment_chirho:
                        &destination_authority_enrollment_chirho,
                    serve_port_chirho: args_chirho.serve_port_chirho,
                },
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoProviderPrepareChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_provider_prepare_report_chirho(
                &report_command_chirho::CreditsDemoProviderPrepareRequestChirho {
                    root_chirho,
                    connection_secret_name_chirho: &args_chirho.connection_secret_name_chirho,
                },
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::CreditsDemoConcurrencyTokenChirho(args_chirho) => {
            report_command_chirho::run_credits_demo_concurrency_token_report_chirho(
                &report_command_chirho::CreditsDemoConcurrencyTokenRequestChirho {
                    root_chirho,
                    connection_secret_name_chirho: &args_chirho.connection_secret_name_chirho,
                },
            )?;
            Ok(true)
        }
        CommandChirho::AgentAuthoredBackendSmokeChirho(args_chirho) => {
            report_command_chirho::run_agent_authored_backend_smoke_report_chirho(
                root_chirho,
                args_chirho.manifest_chirho.as_deref(),
                args_chirho.overcap_manifest_chirho.as_deref(),
                args_chirho.undeclared_effect_manifest_chirho.as_deref(),
                args_chirho.brief_chirho.as_deref(),
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::LearnerHandoverDrillChirho(args_chirho) => {
            report_command_chirho::run_learner_handover_drill_report_chirho(
                args_chirho.fixture_root_chirho.as_deref(),
                args_chirho.allow_non_fixture_root_chirho,
                args_chirho.json_chirho,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) fn handle_report_verifier_command_chirho(
    root_chirho: &Path,
    command_chirho: &CommandChirho,
) -> anyhow::Result<bool> {
    match command_chirho {
        CommandChirho::PrivacyVerifyChirho(args_chirho) => {
            report_command_chirho::run_privacy_verify_report_command_chirho(
                root_chirho,
                args_chirho.json_chirho,
                args_chirho.fail_on_empty_evidence_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::PrivacyScanChirho(args_chirho) => {
            report_command_chirho::run_privacy_scan_report_command_chirho(
                root_chirho,
                args_chirho.json_chirho,
                args_chirho.fail_on_findings_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::SeqlogScanChirho(args_chirho) => {
            report_command_chirho::run_seqlog_scan_report_command_chirho(
                root_chirho,
                args_chirho.json_chirho,
                args_chirho.fail_on_findings_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::ComplianceEvidenceGenerateChirho(args_chirho) => {
            report_command_chirho::run_compliance_evidence_generate_report_command_chirho(
                root_chirho,
                report_command_chirho::ComplianceEvidenceGenerateCommandInputChirho {
                    frameworks_chirho: &args_chirho.frameworks_chirho,
                    period_start_ms_chirho: args_chirho.period_start_ms_chirho,
                    period_end_ms_chirho: args_chirho.period_end_ms_chirho,
                    generated_by_chirho: &args_chirho.generated_by_chirho,
                    fail_on_failed_sources_chirho: args_chirho.fail_on_failed_sources_chirho,
                    fail_on_coverage_gaps_chirho: args_chirho.fail_on_coverage_gaps_chirho,
                    fail_on_manual_controls_chirho: args_chirho.fail_on_manual_controls_chirho,
                },
            )?;
            Ok(true)
        }
        CommandChirho::ComplianceEvidenceShowChirho { pack_chirho } => {
            report_command_chirho::run_compliance_evidence_show_report_command_chirho(
                root_chirho,
                pack_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::ComplianceEvidenceVerifyChirho(args_chirho) => {
            report_command_chirho::run_compliance_evidence_verify_report_command_chirho(
                root_chirho,
                args_chirho.pack_chirho.as_deref(),
                args_chirho.fail_on_failed_sources_chirho,
                args_chirho.fail_on_coverage_gaps_chirho,
                args_chirho.fail_on_manual_controls_chirho,
            )?;
            Ok(true)
        }
        CommandChirho::DataResidencyVerifyChirho(args_chirho) => {
            report_command_chirho::run_data_residency_verify_report_command_chirho(
                root_chirho,
                args_chirho.fail_on_violations_chirho,
            )?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
