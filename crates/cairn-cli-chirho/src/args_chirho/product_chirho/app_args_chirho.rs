// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Grouped clap argument payloads for `app_args_chirho`.

use std::path::PathBuf;

#[derive(clap::Args)]
pub struct DeployArgsChirho {
    pub name_chirho: String,
    pub dag_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}

#[derive(clap::Args)]
pub struct AppSourceDeployArgsChirho {
    pub manifest_chirho: PathBuf,
    #[arg(long = "owner")]
    pub owner_chirho: Option<String>,
    #[arg(long = "allow-unreviewed-dev")]
    pub allow_unreviewed_dev_chirho: bool,
}

#[derive(clap::Args)]
pub struct AppSourceCandidateArgsChirho {
    #[arg(long = "manifest")]
    pub manifest_chirho: PathBuf,
    #[arg(long = "owner")]
    pub owner_chirho: Option<String>,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct AppSourceReviewArgsChirho {
    #[arg(long = "manifest")]
    pub manifest_chirho: PathBuf,
    #[arg(long = "owner")]
    pub owner_chirho: Option<String>,
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "steward-view")]
    pub steward_view_chirho: bool,
}

#[derive(clap::Args)]
pub struct ContactExampleSmokeArgsChirho {
    #[arg(long = "manifest")]
    pub manifest_chirho: Option<PathBuf>,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct CreditsDemoInputsAuthorArgsChirho {
    #[arg(long = "payer-chirho")]
    pub payer_chirho: String,
    #[arg(long = "config-output-chirho")]
    pub config_output_chirho: PathBuf,
    #[arg(long = "plan-output-chirho")]
    pub plan_output_chirho: PathBuf,
    #[arg(long = "activation-authorization-output-chirho")]
    pub activation_authorization_output_chirho: PathBuf,
    #[arg(long = "issuer-secret-name-chirho")]
    pub issuer_secret_name_chirho: String,
    #[arg(long = "activation-secret-name-chirho")]
    pub activation_secret_name_chirho: String,
    #[arg(long = "payer-credential-secret-name-chirho")]
    pub payer_credential_secret_name_chirho: String,
    #[arg(long = "destination-authority-enrollment-chirho")]
    pub destination_authority_enrollment_path_chirho: PathBuf,
    #[arg(long = "expected-destination-authority-enrollment-digest-chirho")]
    pub expected_destination_authority_enrollment_digest_chirho: String,
    #[arg(long = "cluster-genesis-roster-chirho")]
    pub cluster_genesis_roster_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-head-chirho")]
    pub cluster_genesis_roster_head_path_chirho: PathBuf,
    #[arg(long = "cluster-genesis-roster-operator-pubkey-hex-chirho")]
    pub cluster_genesis_roster_operator_pubkey_hex_chirho: String,
    #[arg(long = "serve-port-chirho", default_value_t = 8798)]
    pub serve_port_chirho: u16,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct CreditsDemoProviderPrepareArgsChirho {
    #[arg(long = "connection-secret-name-chirho")]
    pub connection_secret_name_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct CreditsDemoConcurrencyTokenArgsChirho {
    #[arg(long = "connection-secret-name-chirho")]
    pub connection_secret_name_chirho: String,
}

/// Give a root lifecycle state through the tested primitives. The migration flag is spelled out in
/// full because it is an ASSERTION the operator makes and cairn cannot verify: the offline
/// migration path skips the empty-root check, and its safety rests on the root being quiesced.
#[derive(clap::Args)]
pub struct CasLifecycleBootstrapArgsChirho {
    /// Populated (pre-F4) root: assert no concurrent publisher, collector, or root replacement.
    #[arg(long = "offline-migration-quiesced-chirho")]
    pub offline_migration_quiesced_chirho: bool,
}

/// Re-enter a CONSUMED credits-demo root. All coordinates are explicit: the runtime root comes from
/// the global config, the reviewed inputs stay outside it, and the substrate namespace is the
/// operator's verified value rather than a default this command could guess wrong.
#[derive(clap::Args)]
pub struct CreditsDemoContinuationArgsChirho {
    #[arg(long = "reviewed-inputs-dir-chirho")]
    pub reviewed_inputs_dir_chirho: PathBuf,
    /// Reviewed BLAKE3 of the external bundle's exact host-config bytes.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
    #[arg(long = "storage-namespace-chirho")]
    pub storage_namespace_chirho: String,
}

/// Persist the bounded reviewed-candidate locator for a consumed root created before fresh setup
/// began writing it. The report hash is explicit operator input and is fully verified before write.
#[derive(clap::Args)]
pub struct CreditsDemoReviewedCandidatePinArgsChirho {
    #[arg(long = "source-review-report-chirho")]
    pub source_review_report_chirho: String,
}

#[derive(clap::Args)]
pub struct CreditsDemoSmokeArgsChirho {
    #[arg(long = "config-chirho")]
    pub config_chirho: PathBuf,
    /// Reviewed BLAKE3 of the exact config bytes, supplied outside the config's filesystem.
    #[arg(long = "expected-config-digest-chirho")]
    pub expected_config_digest_chirho: String,
    #[arg(long = "plan-chirho")]
    pub plan_chirho: PathBuf,
    #[arg(long = "expected-plan-digest-chirho")]
    pub expected_plan_digest_chirho: String,
    #[arg(long = "issuer-secret-name-chirho")]
    pub issuer_secret_name_chirho: String,
    #[arg(long = "activation-authorization-chirho")]
    pub activation_authorization_chirho: PathBuf,
    #[arg(long = "expected-activation-authorization-digest-chirho")]
    pub expected_activation_authorization_digest_chirho: String,
    /// The payer credential's SECRET-STORE ref name (never a raw credential value on the CLI).
    #[arg(long = "payer-credential-secret-name-chirho")]
    pub payer_credential_secret_name_chirho: String,
    /// REQUIRED (#6019): the checked-in app source root is an operator-reviewed input — no
    /// build-machine env fallback exists in the production path.
    #[arg(long = "app-root-chirho")]
    pub app_root_chirho: PathBuf,
    #[arg(long = "manifest-chirho")]
    pub manifest_chirho: Option<PathBuf>,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct AgentAuthoredBackendSmokeArgsChirho {
    #[arg(long = "manifest")]
    pub manifest_chirho: Option<PathBuf>,
    #[arg(long = "overcap-manifest")]
    pub overcap_manifest_chirho: Option<PathBuf>,
    #[arg(long = "undeclared-effect-manifest")]
    pub undeclared_effect_manifest_chirho: Option<PathBuf>,
    #[arg(long = "brief")]
    pub brief_chirho: Option<PathBuf>,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct LaunchReadinessArgsChirho {
    #[arg(long = "manifest")]
    pub manifest_chirho: Option<PathBuf>,
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-production-blockers")]
    pub fail_on_production_blockers_chirho: bool,
}

#[derive(clap::Args)]
pub struct OpsRestoreDrillArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fail-on-restore-blockers")]
    pub fail_on_restore_blockers_chirho: bool,
}

#[derive(clap::Args)]
pub struct LearnerHandoverDrillArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "fixture-root-chirho")]
    pub fixture_root_chirho: Option<PathBuf>,
    #[arg(long = "allow-non-fixture-root-chirho")]
    pub allow_non_fixture_root_chirho: bool,
}

#[derive(clap::Args)]
pub struct OpsCustodyInventoryArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
    #[arg(long = "config")]
    pub config_chirho: Option<PathBuf>,
    #[arg(long = "env-file")]
    pub env_file_chirho: Option<PathBuf>,
    #[arg(long = "fail-on-custody-blockers")]
    pub fail_on_custody_blockers_chirho: bool,
}

#[derive(clap::Args)]
pub struct AppRouteDeployArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "route")]
    pub route_chirho: String,
    pub dag_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}
#[derive(clap::Args)]
pub struct AppRouteUndeployArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "route")]
    pub route_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}
#[derive(clap::Args)]
pub struct ReviewDiffArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "candidate")]
    pub candidate_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}
#[derive(clap::Args)]
pub struct ReviewPromoteArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "candidate")]
    pub candidate_chirho: String,
    #[arg(long = "source-review-report")]
    pub source_review_report_chirho: Option<String>,
    #[arg(long = "source-manifest")]
    pub source_manifest_chirho: Option<String>,
    #[arg(long = "raw-manifest")]
    pub raw_manifest_chirho: Option<String>,
    #[arg(long = "accept-capability-escalation")]
    pub accept_capability_escalation_chirho: bool,
    #[arg(long = "accept-cost-increase")]
    pub accept_cost_increase_chirho: bool,
}
#[derive(clap::Args)]
pub struct ReviewPolicyEnvelopeSetArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "allow-capability")]
    pub allowed_capability_labels_chirho: Vec<String>,
    #[arg(long = "max-cost-token")]
    pub max_candidate_cost_token_chirho: i64,
    #[arg(long = "allow-contract-ref")]
    pub allowed_contract_refs_chirho: Vec<String>,
}
#[derive(clap::Args)]
pub struct ReviewRejectArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
    #[arg(long = "candidate")]
    pub candidate_chirho: String,
    #[arg(long = "source-review-report")]
    pub source_review_report_chirho: Option<String>,
    #[arg(long = "source-manifest")]
    pub source_manifest_chirho: Option<String>,
    #[arg(long = "raw-manifest")]
    pub raw_manifest_chirho: Option<String>,
    #[arg(long = "reason")]
    pub reason_chirho: String,
}

#[derive(clap::Args)]
pub struct UndeployArgsChirho {
    pub name_chirho: String,
    #[arg(long = "owner")]
    pub owner_chirho: String,
}

#[derive(clap::Args)]
pub struct AppDescriptorArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct AppDocsArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "mcp")]
    pub mcp_chirho: bool,
}

#[derive(clap::Args)]
pub struct PlatformMcpArgsChirho {
    #[arg(long = "json")]
    pub json_chirho: bool,
}

#[derive(clap::Args)]
pub struct AppCapabilitiesArgsChirho {
    #[arg(long = "app")]
    pub app_chirho: String,
    #[arg(long = "json")]
    pub json_chirho: bool,
}
