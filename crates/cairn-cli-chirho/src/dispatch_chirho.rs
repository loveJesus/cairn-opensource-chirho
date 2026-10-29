// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! Command dispatch: every CLI subcommand arm, delegating into the cairn-chirho library (shrinks wave by wave as families move to their own crates).
// Our identifiers carry the `Chirho` suffix by convention, so every enum's variants share it.
#![allow(clippy::enum_variant_names)]
use crate::args_chirho::{CliChirho, CommandChirho};
use crate::cli_context_chirho::CliContextChirho;
use clap::Parser;
pub fn run_chirho() -> anyhow::Result<()> {
    let cli_chirho = CliChirho::parse();
    run_cli_chirho(cli_chirho)
}
pub fn run_cli_chirho(cli_chirho: CliChirho) -> anyhow::Result<()> {
    let cli_context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho)?;
    let command_chirho = cli_chirho.command_chirho;
    let root_chirho = cli_context_chirho.root_chirho();
    if matches!(
        &command_chirho,
        CommandChirho::Gd7ObligationProcessingListChirho
    ) {
        crate::display_cli_chirho::handle_gd7_obligation_processing_list_chirho(root_chirho)?;
        return Ok(());
    }
    if let CommandChirho::Gd7ObligationProcessingDisposeChirho {
        mint_identity_chirho,
        operator_key_id_chirho,
        disposition_path_chirho,
    } = &command_chirho
    {
        crate::display_cli_chirho::handle_gd7_obligation_processing_dispose_chirho(
            root_chirho,
            mint_identity_chirho,
            operator_key_id_chirho,
            disposition_path_chirho,
        )?;
        return Ok(());
    }
    if let CommandChirho::Gd7OperatorRosterSetChirho {
        group_digest_chirho,
        signer_key_id_chirho,
        roster_path_chirho,
    } = &command_chirho
    {
        crate::display_cli_chirho::handle_gd7_operator_roster_set_chirho(
            root_chirho,
            group_digest_chirho,
            signer_key_id_chirho,
            roster_path_chirho,
        )?;
        return Ok(());
    }
    if crate::index_cli_chirho::handle_index_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::state_cli_chirho::handle_state_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::state_cli_chirho::handle_reversion_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::dag_cli_chirho::handle_cas_node_build_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::dag_cli_chirho::handle_dag_utility_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::dag_cli_chirho::handle_dag_module_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::dag_cli_chirho::handle_core_dag_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::dag_cli_chirho::handle_compile_demo_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::audit_cli_chirho::handle_run_audit_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::credential_cli_chirho::handle_secret_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::ledger_host_author_cli_chirho::handle_ledger_host_author_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::ledger_regenesis_cli_chirho::handle_ledger_regenesis_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::served_llm_dev_bootstrap_cli_chirho::handle_served_llm_dev_bootstrap_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::shadow_canary_cli_chirho::handle_shadow_canary_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::ledger_mirror_live_head_cli_chirho::handle_ledger_mirror_live_head_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::runtime_package_cli_chirho::handle_runtime_package_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::maintenance_cli_chirho::handle_maintenance_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::domain_cli_chirho::handle_domain_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::status_cli_chirho::handle_app_status_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::status_cli_chirho::handle_app_info_status_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::status_cli_chirho::handle_app_source_status_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::status_cli_chirho::handle_ops_status_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::template_registry_cli_chirho::handle_template_registry_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::publication_cli_chirho::handle_publication_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::report_cli_chirho::handle_smoke_report_command_chirho(root_chirho, &command_chirho)? {
        return Ok(());
    }
    if crate::report_cli_chirho::handle_volatile_effect_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::report_cli_chirho::handle_report_verifier_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    if crate::data_residency_cli_chirho::handle_data_residency_command_chirho(
        root_chirho,
        &command_chirho,
    )? {
        return Ok(());
    }
    let command_chirho = match crate::privacy_cli_chirho::handle_privacy_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::runtime_cli_chirho::handle_runtime_command_chirho(
        root_chirho,
        cli_context_chirho.tenant_chirho(),
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::app_deploy_cli_chirho::handle_app_deploy_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::app_review_cli_chirho::handle_app_review_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::native_cli_chirho::handle_native_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::economic_cli_chirho::handle_economic_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::realtime_cli_chirho::handle_realtime_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::agent_report_cli_chirho::handle_agent_report_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho =
        match crate::agent_authority_cli_chirho::handle_agent_authority_command_chirho(
            root_chirho,
            command_chirho,
        )? {
            Some(command_chirho) => command_chirho,
            None => return Ok(()),
        };
    let command_chirho = match crate::onboarding_cli_chirho::handle_onboarding_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho = match crate::identity_cli_chirho::handle_identity_command_chirho(
        root_chirho,
        command_chirho,
    )? {
        Some(command_chirho) => command_chirho,
        None => return Ok(()),
    };
    let command_chirho =
        match crate::demo_cli_chirho::handle_demo_command_chirho(root_chirho, command_chirho)? {
            Some(command_chirho) => command_chirho,
            None => return Ok(()),
        };
    match command_chirho {
        CommandChirho::Gd7ObligationProcessingListChirho => {
            unreachable!("GD7 obligation display is handled before the main dispatch match")
        }
        CommandChirho::Gd7ObligationProcessingDisposeChirho { .. } => {
            unreachable!("GD7 obligation disposal is handled before the main dispatch match")
        }
        CommandChirho::Gd7OperatorRosterSetChirho { .. } => {
            unreachable!("GD7 operator roster setup is handled before the main dispatch match")
        }
        CommandChirho::CasAddChirho { .. }
        | CommandChirho::RunNodeChirho(..)
        | CommandChirho::NodeBuildChirho(..)
        | CommandChirho::NodeCheckChirho(..) => {
            unreachable!("CAS/node-build commands are handled before the main dispatch match")
        }
        CommandChirho::NativeBuildChirho(..)
        | CommandChirho::NativeShowChirho { .. }
        | CommandChirho::NativeNodeBuildChirho(..)
        | CommandChirho::NativePrewarmChirho { .. }
        | CommandChirho::NativeRunChirho(..)
        | CommandChirho::NativeVerifyChirho { .. }
        | CommandChirho::NativeStatelessAttestChirho(..)
        | CommandChirho::NativeStatelessAttestationsChirho
        | CommandChirho::NativeStatelessVerifyChirho
        | CommandChirho::NativeBenchChirho(..)
        | CommandChirho::NativeWorkerUpcaseChildChirho
        | CommandChirho::NativeWorkerForbiddenSyscallChildChirho
        | CommandChirho::NativeWorkerFramedCounterChildChirho
        | CommandChirho::NativeWorkerFramedUpcaseChildChirho
        | CommandChirho::NativeWorkerFramedRespondExitChildChirho
        | CommandChirho::NativeWorkerFramedHotLoopChildChirho => {
            unreachable!("native commands are handled before the main dispatch match")
        }
        CommandChirho::NodeTemplateChirho { .. } | CommandChirho::BlessedChirho => {
            unreachable!("dag utility commands are handled before the main dispatch match")
        }
        CommandChirho::SecretSetChirho(..)
        | CommandChirho::SecretRefChirho(..)
        | CommandChirho::SecretListChirho => {
            unreachable!("secret commands are handled before the main dispatch match")
        }
        CommandChirho::DagGraphChirho(..)
        | CommandChirho::DagModuleBuildChirho(..)
        | CommandChirho::DagModuleShowChirho { .. }
        | CommandChirho::DagModuleCheckChirho { .. }
        | CommandChirho::DagModuleComposeChirho(..)
        | CommandChirho::DagModuleCompositionShowChirho { .. }
        | CommandChirho::DagModuleCompositionCheckChirho { .. }
        | CommandChirho::DagModuleRunChirho(..) => {
            unreachable!("dag module commands are handled before the main dispatch match")
        }
        CommandChirho::RuntimePackageBuildChirho(..)
        | CommandChirho::RuntimePackageShowChirho { .. }
        | CommandChirho::RuntimePackageCheckChirho { .. }
        | CommandChirho::RuntimePackageSmokeChirho(..) => {
            unreachable!("runtime-package commands are handled before the main dispatch match")
        }
        CommandChirho::PublishChirho(..)
        | CommandChirho::GcChirho
        | CommandChirho::ProjectChirho(..)
        | CommandChirho::QueryChirho { .. } => {
            unreachable!("maintenance commands are handled before the main dispatch match")
        }
        CommandChirho::LedgerBalancesChirho
        | CommandChirho::LedgerVerifyChirho
        | CommandChirho::PaidEffectsChirho => {
            unreachable!(
                "ledger, gas, and paid-effect commands are handled before the main dispatch match"
            )
        }
        CommandChirho::DagRunChirho(..)
        | CommandChirho::DagBuildChirho(..)
        | CommandChirho::DagDemoChirho { .. }
        | CommandChirho::DagEffectDemoChirho { .. } => {
            unreachable!("core DAG commands are handled before the main dispatch match")
        }
        CommandChirho::CounterDemoChirho | CommandChirho::SsrDemoChirho { .. } => {
            unreachable!("core demo commands are handled before the main dispatch match")
        }
        CommandChirho::CompileDemoChirho { .. }
        | CommandChirho::CompileChainDemoChirho { .. }
        | CommandChirho::CompileEffectDemoChirho { .. } => {
            unreachable!("compile demo commands are handled before the main dispatch match")
        }
        CommandChirho::RunShowChirho { .. }
        | CommandChirho::InspectChirho { .. }
        | CommandChirho::AuditChirho { .. }
        | CommandChirho::VerifyChirho { .. }
        | CommandChirho::RunCacheVerifyChirho(..)
        | CommandChirho::RunIntentStartupPreflightChirho(..) => {
            unreachable!("run audit commands are handled before the main dispatch match")
        }
        CommandChirho::VolatileEffectsChirho(..)
        | CommandChirho::VolatileEffectsVerifyChirho(..) => {
            unreachable!("volatile effect commands are handled before the main dispatch match")
        }
        CommandChirho::AppDescriptorChirho(..)
        | CommandChirho::PlatformMcpChirho(..)
        | CommandChirho::AppDocsChirho(..)
        | CommandChirho::AppCapabilitiesChirho(..) => {
            unreachable!("app info status commands are handled before the main dispatch match")
        }
        CommandChirho::DnsApplyStubChirho(..)
        | CommandChirho::MailboxApplyStubChirho(..)
        | CommandChirho::MailboxAppliesChirho(..)
        | CommandChirho::DnsAppliesChirho(..)
        | CommandChirho::DomainStatusChirho(..)
        | CommandChirho::MailboxSetChirho(..)
        | CommandChirho::MailboxRemoveChirho(..)
        | CommandChirho::MailboxesChirho(..)
        | CommandChirho::DnsZoneSetChirho(..)
        | CommandChirho::DnsZonesChirho(..)
        | CommandChirho::DomainBindingsChirho(..)
        | CommandChirho::DomainBindChirho(..)
        | CommandChirho::DomainUnbindChirho(..) => {
            unreachable!("domain commands are handled before the main dispatch match")
        }
        CommandChirho::RollbackChirho(..) => {
            unreachable!("state commands are handled before the main dispatch match")
        }
        CommandChirho::ReversionEventsChirho
        | CommandChirho::ReversionCompensationsChirho
        | CommandChirho::ReversionExecutionsChirho
        | CommandChirho::ReversionCompletionsChirho
        | CommandChirho::ReversionVerifyChirho
        | CommandChirho::ReversionManualResolutionsChirho => {
            unreachable!("reversion commands are handled before the main dispatch match")
        }
        CommandChirho::BranchChirho(..)
        | CommandChirho::RefsChirho
        | CommandChirho::ReflogChirho
        | CommandChirho::KvPutChirho(..)
        | CommandChirho::KvGetChirho(..)
        | CommandChirho::KvVersionChirho
        | CommandChirho::KvRollbackChirho { .. } => {
            unreachable!("state commands are handled before the main dispatch match")
        }
        CommandChirho::DeployChirho(..)
        | CommandChirho::AppManifestDeployChirho { .. }
        | CommandChirho::AppSourceDeployChirho(..)
        | CommandChirho::AppRouteDeployChirho(..)
        | CommandChirho::AppRouteUndeployChirho(..)
        | CommandChirho::UndeployChirho(..) => {
            unreachable!("app deploy commands are handled before the main dispatch match")
        }
        CommandChirho::AppSourceCandidateChirho(..) | CommandChirho::AppSourceReviewChirho(..) => {
            unreachable!("app source status commands are handled before the main dispatch match")
        }
        CommandChirho::ContactExampleSmokeChirho(..)
        | CommandChirho::CreditsDemoInputsAuthorChirho(..)
        | CommandChirho::CreditsDemoProviderPrepareChirho(..)
        | CommandChirho::CreditsDemoConcurrencyTokenChirho(..)
        | CommandChirho::CreditsDemoSmokeChirho(..)
        | CommandChirho::CreditsDemoGeoSeedChirho(..)
        | CommandChirho::CreditsDemoContinuationChirho(..)
        | CommandChirho::CreditsDemoReviewedCandidatePinChirho(..)
        | CommandChirho::CasLifecycleBootstrapChirho(..)
        | CommandChirho::AgentAuthoredBackendSmokeChirho(..)
        | CommandChirho::LearnerHandoverDrillChirho(..) => {
            unreachable!("smoke report commands are handled before the main dispatch match")
        }
        CommandChirho::LaunchReadinessChirho(..)
        | CommandChirho::OpsRestoreDrillChirho(..)
        | CommandChirho::OpsCustodyInventoryChirho(..) => {
            unreachable!("ops status commands are handled before the main dispatch match")
        }
        CommandChirho::TenantAppVerifyChirho
        | CommandChirho::TenantMigrationVerifyChirho
        | CommandChirho::AppsChirho
        | CommandChirho::AppStatusChirho { .. } => {
            unreachable!("app status commands are handled before the main dispatch match")
        }
        CommandChirho::TemplateRegistrySetChirho(_) | CommandChirho::AppVerifyChirho => {
            unreachable!("template registry commands are handled before the main dispatch match")
        }
        CommandChirho::PublicationApplyChirho(_)
        | CommandChirho::PublicationReserveSlugChirho(_)
        | CommandChirho::PublicationVerifyChirho => {
            unreachable!("publication commands are handled before the main dispatch match")
        }
        CommandChirho::ReviewDiffChirho(..)
        | CommandChirho::ReviewPromoteChirho(..)
        | CommandChirho::ReviewPolicyEnvelopeSetChirho(..)
        | CommandChirho::ReviewPolicyEnvelopeVerifyChirho
        | CommandChirho::ReviewRejectChirho(..)
        | CommandChirho::ReviewsChirho
        | CommandChirho::ReviewVerifyChirho => {
            unreachable!("app review commands are handled before the main dispatch match")
        }
        CommandChirho::PriceBookSetChirho(..)
        | CommandChirho::PriceBookShowChirho { .. }
        | CommandChirho::PriceBookHistoryChirho { .. }
        | CommandChirho::PriceBookVerifyChirho => {
            unreachable!("price book commands are handled before the main dispatch match")
        }
        CommandChirho::BillingPolicyShowChirho { .. }
        | CommandChirho::BillingPolicyHistoryChirho { .. }
        | CommandChirho::BillingPolicyVerifyChirho
        | CommandChirho::BillingRollupChirho(..)
        | CommandChirho::BillingCompensationsChirho => {
            unreachable!("billing commands are handled before the main dispatch match")
        }
        CommandChirho::ResourcePolicySetChirho(..)
        | CommandChirho::ResourcePolicyUnsetChirho(..)
        | CommandChirho::ResourcePolicyShowChirho { .. }
        | CommandChirho::ResourcePolicyHistoryChirho { .. }
        | CommandChirho::ResourcePolicyVerifyChirho
        | CommandChirho::ResourceUseChirho(..)
        | CommandChirho::ResourceUsageChirho(..)
        | CommandChirho::ResourceRollupChirho(..)
        | CommandChirho::ResourceStatusChirho(..) => {
            unreachable!("resource commands are handled before the main dispatch match")
        }
        CommandChirho::HoldsChirho | CommandChirho::HoldsVerifyChirho => {
            unreachable!("credit hold commands are handled before the main dispatch match")
        }
        CommandChirho::RealtimeOpenChirho(..)
        | CommandChirho::RealtimeEventChirho(..)
        | CommandChirho::RealtimeTickChirho(..)
        | CommandChirho::RealtimeProviderUsageChirho(..)
        | CommandChirho::RealtimeOpenAiUsageImportChirho(..)
        | CommandChirho::RealtimeCloseChirho(..)
        | CommandChirho::RealtimeTranscriptRevealChirho(..)
        | CommandChirho::RealtimeSessionsChirho
        | CommandChirho::RealtimeEventsChirho
        | CommandChirho::RealtimeVerifyChirho
        | CommandChirho::RealtimeSweepChirho(..)
        | CommandChirho::RealtimeEpilogueChirho(..)
        | CommandChirho::RealtimeEpiloguesChirho
        | CommandChirho::RealtimeEpilogueVerifyChirho => {
            unreachable!("realtime commands are handled before the main dispatch match")
        }
        CommandChirho::AgentReportCreateChirho(..)
        | CommandChirho::AgentReportShowChirho { .. }
        | CommandChirho::AgentReportsChirho(..)
        | CommandChirho::AgentReportVerifyChirho
        | CommandChirho::AgentReportBudgetGrantChirho(..)
        | CommandChirho::AgentReportBudgetChirho(..)
        | CommandChirho::AgentReportChargesChirho(..) => {
            unreachable!("agent report commands are handled before the main dispatch match")
        }
        CommandChirho::AgentAuthorityRespondChirho(..)
        | CommandChirho::AgentAuthorityShowChirho(..)
        | CommandChirho::AgentAuthorityCheckChirho(..)
        | CommandChirho::AgentAuthorityResponsesChirho(..)
        | CommandChirho::AgentAuthorityVerifyChirho => {
            unreachable!("agent authority commands are handled before the main dispatch match")
        }
        CommandChirho::PrivacyExportChirho(..)
        | CommandChirho::PrivacyEraseChirho(..)
        | CommandChirho::PrivacyErasureHistoryChirho(..)
        | CommandChirho::PrivacyRetentionSweepChirho(..)
        | CommandChirho::PrivacyRetentionHistoryChirho
        | CommandChirho::PrivacyRetentionVerifyChirho
        | CommandChirho::LegalHoldPlaceChirho(..)
        | CommandChirho::LegalHoldReleaseChirho(..)
        | CommandChirho::LegalHoldsChirho(..)
        | CommandChirho::LegalHoldVerifyChirho
        | CommandChirho::PrivacyReplicaRegisterChirho(..)
        | CommandChirho::PrivacyReplicasChirho
        | CommandChirho::PrivacyBackupPolicySetChirho(..)
        | CommandChirho::PrivacyBackupPoliciesChirho
        | CommandChirho::PrivacyErasurePropagateChirho(..)
        | CommandChirho::PrivacyErasurePropagationsChirho(..) => {
            unreachable!("privacy, legal hold, and backup commands are handled before the main dispatch match")
        }
        CommandChirho::PrivacyVerifyChirho(..)
        | CommandChirho::PrivacyScanChirho(..)
        | CommandChirho::SeqlogScanChirho(..)
        | CommandChirho::ComplianceEvidenceGenerateChirho(..)
        | CommandChirho::ComplianceEvidenceShowChirho { .. }
        | CommandChirho::ComplianceEvidenceVerifyChirho(..) => {
            unreachable!("report verifier commands are handled before the main dispatch match")
        }
        CommandChirho::DataResidencySetChirho(..)
        | CommandChirho::DataResidencyShowChirho
        | CommandChirho::DataResidencyAttestChirho(..)
        | CommandChirho::DataResidencyCheckPlacementChirho(..) => {
            unreachable!("data residency commands are handled before the main dispatch match")
        }
        CommandChirho::DataResidencyVerifyChirho(..) => {
            unreachable!("report verifier commands are handled before the main dispatch match")
        }
        CommandChirho::OnboardingSetChirho(..)
        | CommandChirho::OnboardingShowChirho { .. }
        | CommandChirho::OnboardingHistoryChirho { .. }
        | CommandChirho::OnboardingVerifyChirho => {
            unreachable!("onboarding commands are handled before the main dispatch match")
        }
        CommandChirho::IdentityRegisterChirho(..)
        | CommandChirho::IdentityListChirho
        | CommandChirho::IdentityCredentialInventoryChirho(..)
        | CommandChirho::IdentityCredentialSetChirho(..)
        | CommandChirho::IdentityCredentialResetChirho(..)
        | CommandChirho::IdentityInviteChirho(..)
        | CommandChirho::IdentityRecoveryCodeMintChirho(..)
        | CommandChirho::IdentityRecoveryCodeEventsChirho(..)
        | CommandChirho::IdentityRecoveryCodeEventsVerifyChirho
        | CommandChirho::IdentityLoginChirho { .. }
        | CommandChirho::IdentitySessionsListChirho { .. }
        | CommandChirho::IdentitySessionRevokeChirho(..)
        | CommandChirho::IdentityVerifyChirho
        | CommandChirho::IdentitySessionsVerifyChirho
        | CommandChirho::IdentitySessionRevocationsVerifyChirho
        | CommandChirho::IdentityCredentialResetsVerifyChirho
        | CommandChirho::OauthClientRegisterChirho(..)
        | CommandChirho::OauthClientsChirho
        | CommandChirho::OauthTokenChirho(..)
        | CommandChirho::OauthLimitedKeyChirho(..)
        | CommandChirho::OauthUsesChirho
        | CommandChirho::OauthVerifyChirho
        | CommandChirho::OauthConnectionVerifyChirho => {
            unreachable!(
                "identity, wallet, and oauth commands are handled before the main dispatch match"
            )
        }
        CommandChirho::ServeChirho(..)
        | CommandChirho::UpChirho(..)
        | CommandChirho::LedgerCompensationPreviewChirho(..)
        | CommandChirho::LedgerRuntimePreflightChirho(..)
        | CommandChirho::LedgerCompensationExecuteChirho(..)
        | CommandChirho::QueryEffectChirho(..) => {
            unreachable!("runtime commands are handled before the main dispatch match")
        }
        CommandChirho::LedgerRegenesisChirho(..) => {
            unreachable!("ledger regenesis is handled before the main dispatch match")
        }
        CommandChirho::ServedLlmDevBootstrapChirho(..) => {
            unreachable!("served-llm dev bootstrap is handled before the main dispatch match")
        }
        CommandChirho::LedgerShadowCanaryReportChirho(..)
        | CommandChirho::LedgerShadowCanaryVerdictChirho(..) => {
            unreachable!("shadow canary reporting is handled before the main dispatch match")
        }
        CommandChirho::LedgerMirrorLiveHeadReportChirho(..)
        | CommandChirho::LedgerMirrorLiveHeadVerdictChirho(..) => {
            unreachable!("live mirror head reporting is handled before the main dispatch match")
        }
        CommandChirho::LedgerDestinationAuthorityEnrollChirho(..)
        | CommandChirho::LedgerHostAuthorReviewChirho(..)
        | CommandChirho::LedgerHostAuthorChirho(..)
        | CommandChirho::LedgerHostActivationAuthorChirho(..) => {
            unreachable!("ledger host authoring is handled before the main dispatch match")
        }
        CommandChirho::IndexProjectChirho(..)
        | CommandChirho::IndexGetChirho(..)
        | CommandChirho::IndexRollbackChirho { .. }
        | CommandChirho::IndexVerifyChirho { .. }
        | CommandChirho::IndexProvenanceProjectChirho
        | CommandChirho::IndexProvenanceFindChirho(..)
        | CommandChirho::IndexProvenanceVerifyChirho { .. } => {
            unreachable!("index commands are handled before the main dispatch match")
        }
    }
}
#[cfg(test)]
#[path = "dispatch_guard_tests_chirho.rs"]
mod guard_tests_chirho;
#[cfg(test)]
#[path = "dispatch_tests_a_chirho.rs"]
mod tests_a_chirho;
#[cfg(test)]
#[path = "dispatch_tests_b_chirho.rs"]
mod tests_b_chirho;
