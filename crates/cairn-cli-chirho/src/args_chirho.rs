// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
use cairn_run_intent_preflight_chirho::RunIntentStartupPreflightArgsChirho as RunIntentPreflightArgsChirho;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
#[path = "args_chirho/product_chirho/agent_args_chirho.rs"]
pub mod agent_args_chirho;
#[path = "args_chirho/product_chirho/app_args_chirho.rs"]
pub mod app_args_chirho;
#[path = "args_chirho/product_chirho/auth_args_chirho.rs"]
pub mod auth_args_chirho;
#[path = "args_chirho/reporting_chirho/compliance_args_chirho.rs"]
pub mod compliance_args_chirho;
#[path = "args_chirho/product_chirho/content_args_chirho.rs"]
pub mod content_args_chirho;
#[path = "args_chirho/core_chirho/core_args_chirho.rs"]
pub mod core_args_chirho;
#[path = "args_chirho/product_chirho/domain_args_chirho.rs"]
pub mod domain_args_chirho;
#[path = "args_chirho/product_chirho/economic_args_chirho.rs"]
pub mod economic_args_chirho;
#[path = "args_chirho/core_chirho/ops_args_chirho.rs"]
pub mod ops_args_chirho;
#[path = "args_chirho/reporting_chirho/privacy_args_chirho.rs"]
pub mod privacy_args_chirho;
#[path = "args_chirho/product_chirho/realtime_args_chirho.rs"]
pub mod realtime_args_chirho;
#[path = "args_chirho/core_chirho/state_args_chirho.rs"]
pub mod state_args_chirho;
/// Crate version PLUS the source commit that built these bytes.
///
/// `version` alone rendered `cairn-chirho 0.1.0` on every node, identical across provably different
/// binaries -- so CF8[12]'s source-commit binding could not be obtained by asking the binary. A
/// `-dirty` suffix marks a tree with uncommitted changes, because a bare commit id would claim a
/// provenance the bytes do not have.
pub const VERSION_WITH_COMMIT_CHIRHO: &str =
    cairn_build_identity_chirho::version_with_commit_chirho!();

#[derive(Parser)]
#[command(
    name = "cairn-chirho",
    version = VERSION_WITH_COMMIT_CHIRHO,
    about = "Content-addressed dataflow DAG runtime"
)]
pub struct CliChirho {
    /// Store root — the cairn of content-addressed objects.
    #[arg(long = "root", default_value = ".cairn-chirho")]
    pub root_chirho: PathBuf,
    #[cfg_attr(
        doc,
        doc = "Optional tenant id; when set, commands operate inside `root/tenants-chirho/<tenant>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Optional tenant id; when set, commands operate inside root/tenants-chirho/<tenant>."
    )]
    #[arg(long = "tenant", global = true)]
    pub tenant_chirho: Option<String>,
    #[command(subcommand)]
    pub command_chirho: CommandChirho,
}
#[derive(Subcommand)]
pub enum CommandChirho {
    /// Display GD7 obligation-processing records with verifier-backed VALID/INVALID labels.
    #[command(name = "gd7-obligation-processing-list")]
    Gd7ObligationProcessingListChirho,
    /// Apply one externally signed operator disposition to a HeldManual GD7 record.
    #[command(name = "gd7-obligation-processing-dispose")]
    Gd7ObligationProcessingDisposeChirho {
        #[arg(long = "mint-identity-chirho")]
        mint_identity_chirho: String,
        #[arg(long = "operator-key-id-chirho")]
        operator_key_id_chirho: String,
        #[arg(long = "disposition-path-chirho")]
        disposition_path_chirho: PathBuf,
    },
    /// Install one custody-signed GD7 operator roster revision.
    #[command(name = "gd7-operator-roster-set")]
    Gd7OperatorRosterSetChirho {
        #[arg(long = "group-digest-chirho")]
        group_digest_chirho: String,
        #[arg(long = "signer-key-id-chirho")]
        signer_key_id_chirho: String,
        #[arg(long = "roster-path-chirho")]
        roster_path_chirho: PathBuf,
    },
    /// Content-address a file into the store. (works today)
    #[command(name = "cas-add")]
    CasAddChirho { file_chirho: PathBuf },
    /// Run the bundled pure-WASM example node under a fuel budget. (works today)
    #[command(name = "run-node")]
    RunNodeChirho(core_args_chirho::RunNodeArgsChirho),
    /// Build + store a NodeDefChirho from a WASM/WAT module; prints its hash.
    #[command(name = "node-build")]
    NodeBuildChirho(core_args_chirho::NodeBuildArgsChirho),
    /// Validate a stored node + run it on sample input (pure nodes). The authoring `check`.
    #[command(name = "node-check")]
    NodeCheckChirho(core_args_chirho::NodeCheckArgsChirho),
    /// Build + store a Tier-2 native worker spec around a content-addressed executable.
    #[command(name = "native-build")]
    NativeBuildChirho(core_args_chirho::NativeBuildArgsChirho),
    /// Wrap a stored NativeProgramSpecChirho in a DAG-runnable NodeDefChirho.
    #[command(name = "native-node-build")]
    NativeNodeBuildChirho(core_args_chirho::NativeNodeBuildArgsChirho),
    /// Show a stored NativeProgramSpecChirho as JSON.
    #[command(name = "native-show")]
    NativeShowChirho { spec_chirho: String },
    /// Materialize a native worker executable from CAS into the warm worker directory.
    #[command(name = "native-prewarm")]
    NativePrewarmChirho { spec_chirho: String },
    /// Run a native worker on bytes through the cache-compatible RunResultChirho path.
    #[command(name = "native-run")]
    NativeRunChirho(core_args_chirho::NativeRunArgsChirho),
    /// Verify a stored native worker spec and its executable CAS object.
    #[command(name = "native-verify")]
    NativeVerifyChirho { spec_chirho: String },
    /// Prove/attest that a framed native worker is stateless under a repeat probe.
    #[command(name = "native-stateless-attest")]
    NativeStatelessAttestChirho(core_args_chirho::NativeStatelessAttestArgsChirho),
    /// List signed framed native statelessness attestations.
    #[command(name = "native-stateless-attestations")]
    NativeStatelessAttestationsChirho,
    /// Verify signed framed native statelessness attestations.
    #[command(name = "native-stateless-verify")]
    NativeStatelessVerifyChirho,
    /// Measure the same hot loop through fuel-metered WASM and a warm native worker.
    #[command(name = "native-bench")]
    NativeBenchChirho(core_args_chirho::NativeBenchArgsChirho),
    #[command(name = "__native-worker-upcase-child", hide = true)]
    NativeWorkerUpcaseChildChirho,
    #[command(name = "__native-worker-forbidden-syscall-child", hide = true)]
    NativeWorkerForbiddenSyscallChildChirho,
    #[command(name = "__native-worker-framed-counter-child", hide = true)]
    NativeWorkerFramedCounterChildChirho,
    #[command(name = "__native-worker-framed-upcase-child", hide = true)]
    NativeWorkerFramedUpcaseChildChirho,
    #[command(name = "__native-worker-framed-respond-exit-child", hide = true)]
    NativeWorkerFramedRespondExitChildChirho,
    #[command(name = "__native-worker-framed-hot-loop-child", hide = true)]
    NativeWorkerFramedHotLoopChildChirho,
    #[cfg_attr(
        doc,
        doc = "Write a starter pure bytes-ABI node template (.wat) to `<out>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Write a starter pure bytes-ABI node template (.wat) to <out>."
    )]
    #[command(name = "node-template")]
    NodeTemplateChirho { out_chirho: PathBuf },
    /// Show the signed blessed-effect registry + verify it (the small fixed set of effects).
    #[command(name = "blessed")]
    BlessedChirho,
    /// Store a private tenant secret from a local file; prints a safe secret ref.
    #[command(name = "secret-set")]
    SecretSetChirho(ops_args_chirho::SecretSetArgsChirho),
    /// Print a safe JSON secret ref (never the value).
    #[command(name = "secret-ref")]
    SecretRefChirho(ops_args_chirho::SecretRefArgsChirho),
    /// List private tenant secret refs without printing values.
    #[command(name = "secret-list")]
    SecretListChirho,
    /// Render a stored DagChirho as a graph (mermaid default, or --format dot).
    #[command(name = "dag-graph")]
    DagGraphChirho(core_args_chirho::DagGraphArgsChirho),
    /// Build + store a DagModuleChirho descriptor around an existing DAG; prints its hash.
    #[command(name = "dag-module-build")]
    DagModuleBuildChirho(core_args_chirho::DagModuleBuildArgsChirho),
    /// Show a stored DagModuleChirho descriptor as JSON.
    #[command(name = "dag-module-show")]
    DagModuleShowChirho { module_chirho: String },
    /// Validate a stored DagModuleChirho against its wrapped DAG and node port schemas.
    #[command(name = "dag-module-check")]
    DagModuleCheckChirho { module_chirho: String },
    /// Compose stored DagModuleChirho descriptors through typed public ports.
    #[command(name = "dag-module-compose")]
    DagModuleComposeChirho(core_args_chirho::DagModuleComposeArgsChirho),
    /// Show a stored DagModuleCompositionChirho descriptor as JSON.
    #[command(name = "dag-module-composition-show")]
    DagModuleCompositionShowChirho { composition_chirho: String },
    /// Validate a stored DagModuleCompositionChirho and its expanded DagChirho.
    #[command(name = "dag-module-composition-check")]
    DagModuleCompositionCheckChirho { composition_chirho: String },
    /// Run a stored DagModuleCompositionChirho through its expanded DagChirho.
    #[command(name = "dag-module-run")]
    DagModuleRunChirho(core_args_chirho::DagModuleRunArgsChirho),
    /// Build a lean/server runtime package manifest for a stored DagModuleChirho.
    #[command(name = "runtime-package-build")]
    RuntimePackageBuildChirho(core_args_chirho::RuntimePackageBuildArgsChirho),
    /// Show a stored RuntimePackageChirho manifest as JSON.
    #[command(name = "runtime-package-show")]
    RuntimePackageShowChirho { package_chirho: String },
    /// Validate a stored RuntimePackageChirho against its source module and executable bytes.
    #[command(name = "runtime-package-check")]
    RuntimePackageCheckChirho { package_chirho: String },
    /// Smoke a deployed runtime package artifact endpoint against the local validated package.
    #[command(name = "runtime-package-smoke")]
    RuntimePackageSmokeChirho(core_args_chirho::RuntimePackageSmokeArgsChirho),
    /// Publish a dagapp (DAG + its nodes/wasm closure) to a running cairn server over HTTP.
    #[command(name = "publish")]
    PublishChirho(ops_args_chirho::PublishArgsChirho),
    /// Print all verified (account, asset) balances.
    #[command(name = "ledger-balances")]
    LedgerBalancesChirho,
    /// Verify the ledger: contiguous seqs, every entry balanced + signed.
    #[command(name = "ledger-verify")]
    LedgerVerifyChirho,
    /// Verify G1 for this root: a tenant root holds at most one customer app.
    #[command(name = "tenant-app-verify")]
    TenantAppVerifyChirho,
    /// Run the non-authoritative migration precheck; activation still requires a real source fence.
    #[command(name = "tenant-migration-verify")]
    TenantMigrationVerifyChirho,
    /// List the registered priced effects (name, price in token, provider).
    #[command(name = "paid-effects")]
    PaidEffectsChirho,
    /// Run a stored DagChirho (by hash) on an input string, using the cache.
    #[command(name = "dag-run")]
    DagRunChirho(core_args_chirho::DagRunArgsChirho),
    /// Build + store a DagChirho from stored NodeDefChirho hashes.
    #[command(name = "dag-build")]
    DagBuildChirho(core_args_chirho::DagBuildArgsChirho),
    /// Build + store the example `upcase -> reverse` DAG and run it on an input string.
    #[command(name = "dag-demo")]
    DagDemoChirho { input_chirho: String },
    /// Build + run a `read(ReadStore effect) -> upcase(pure)` DAG on a stored key.
    #[command(name = "dag-effect-demo")]
    DagEffectDemoChirho { key_chirho: String },
    /// Build + deploy the dogfood hit-counter app (read -> inc_u64 -> write on key "count").
    #[command(name = "counter-demo")]
    CounterDemoChirho,
    #[cfg_attr(
        doc,
        doc = "Deploy a stored DagChirho under an app name (served at `/app-chirho/<name>`)."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Deploy a stored DagChirho under an app name (served at /app-chirho/<name>)."
    )]
    #[command(name = "deploy")]
    DeployChirho(app_args_chirho::DeployArgsChirho),
    /// Deploy an app from a JSON manifest over existing DAG/module/package primitives.
    #[command(name = "app-manifest-deploy")]
    AppManifestDeployChirho { manifest_chirho: PathBuf },
    /// Build and deploy or publish an app from one source manifest.
    #[command(name = "app-source-deploy")]
    AppSourceDeployChirho(app_args_chirho::AppSourceDeployArgsChirho),
    /// Build a source manifest into a review-only candidate without moving app refs.
    #[command(name = "app-source-candidate")]
    AppSourceCandidateChirho(app_args_chirho::AppSourceCandidateArgsChirho),
    /// Build and review a source manifest without moving app refs.
    #[command(name = "app-source-review")]
    AppSourceReviewChirho(app_args_chirho::AppSourceReviewArgsChirho),
    /// Run the checked-in contact source-manifest smoke and emit privacy-safe evidence.
    #[command(name = "contact-example-smoke")]
    ContactExampleSmokeChirho(app_args_chirho::ContactExampleSmokeArgsChirho),
    /// Author the reviewable credits-demo plan/config from existing identity and secret custody.
    #[command(name = "credits-demo-inputs-author-chirho")]
    CreditsDemoInputsAuthorChirho(app_args_chirho::CreditsDemoInputsAuthorArgsChirho),
    /// Establish the external credits-demo PostgreSQL schema + seed before the smoke run.
    #[command(name = "credits-demo-provider-prepare-chirho")]
    CreditsDemoProviderPrepareChirho(app_args_chirho::CreditsDemoProviderPrepareArgsChirho),
    /// Read the verified current credits-demo seed-row concurrency token without mutation.
    #[command(name = "credits-demo-concurrency-token-chirho")]
    CreditsDemoConcurrencyTokenChirho(app_args_chirho::CreditsDemoConcurrencyTokenArgsChirho),
    /// Drive the credits-demo LocalPhaseB money arc + verifier suite and emit the PASS packet.
    #[command(name = "credits-demo-smoke")]
    CreditsDemoSmokeChirho(app_args_chirho::CreditsDemoSmokeArgsChirho),
    /// Seed H3 plus the reviewed app/route/price state without running an elected-era SSR smoke.
    #[command(name = "credits-demo-geo-seed-chirho")]
    CreditsDemoGeoSeedChirho(app_args_chirho::CreditsDemoSmokeArgsChirho),
    /// Re-enter a CONSUMED credits-demo root and drive its reviewed doors to completion.
    #[command(name = "credits-demo-continuation")]
    CreditsDemoContinuationChirho(app_args_chirho::CreditsDemoContinuationArgsChirho),
    /// One-time migration: validate and pin a reviewed candidate coordinate without scanning CAS.
    #[command(name = "credits-demo-reviewed-candidate-pin")]
    CreditsDemoReviewedCandidatePinChirho(
        app_args_chirho::CreditsDemoReviewedCandidatePinArgsChirho,
    ),
    /// Give a root CAS lifecycle state; a populated pre-F4 root needs the offline-migration flag.
    #[command(name = "cas-lifecycle-bootstrap")]
    CasLifecycleBootstrapChirho(app_args_chirho::CasLifecycleBootstrapArgsChirho),
    /// Run the checked-in agent-authored backend smoke and emit review-safe evidence.
    #[command(name = "agent-authored-backend-smoke")]
    AgentAuthoredBackendSmokeChirho(app_args_chirho::AgentAuthoredBackendSmokeArgsChirho),
    /// Run the first-candidate launch readiness report without promoting live/provider work.
    #[command(name = "launch-readiness")]
    LaunchReadinessChirho(app_args_chirho::LaunchReadinessArgsChirho),
    /// Run a local backup/restore verifier drill without closing hosted ops blockers.
    #[command(name = "ops-restore-drill")]
    OpsRestoreDrillChirho(app_args_chirho::OpsRestoreDrillArgsChirho),
    /// Run a fixture-only steward handover drill over app refs, effects, and query projection.
    #[command(name = "learner-handover-drill")]
    LearnerHandoverDrillChirho(app_args_chirho::LearnerHandoverDrillArgsChirho),
    /// Report key/secret/config file custody posture without exposing paths or values.
    #[command(name = "ops-custody-inventory")]
    OpsCustodyInventoryChirho(app_args_chirho::OpsCustodyInventoryArgsChirho),
    #[command(name = "apps")]
    AppsChirho,
    /// Show one deployed app: its DAG hash, routes, and ref-change count.
    #[command(name = "app-status")]
    AppStatusChirho { name_chirho: String },
    #[cfg_attr(
        doc,
        doc = "Deploy an app-owned route DAG module under `app-route/<app>/<route>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Deploy an app-owned route DAG module under app-route/<app>/<route>."
    )]
    #[command(name = "app-route-deploy")]
    AppRouteDeployChirho(app_args_chirho::AppRouteDeployArgsChirho),
    /// Undeploy an app-owned route DAG module.
    #[command(name = "app-route-undeploy")]
    AppRouteUndeployChirho(app_args_chirho::AppRouteUndeployArgsChirho),
    #[command(name = "template-registry-set")]
    TemplateRegistrySetChirho(crate::template_registry_cli_chirho::TemplateRegistrySetArgsChirho),
    /// Apply one tenant's verified publication intents on this platform root (the timer's command).
    #[command(name = "publication-apply")]
    PublicationApplyChirho(crate::publication_cli_chirho::PublicationApplyArgsChirho),
    /// Reserve a slug nobody may publish under (the public app's name, the workspace app's name).
    #[command(name = "publication-reserve-slug")]
    PublicationReserveSlugChirho(crate::publication_cli_chirho::PublicationReserveSlugArgsChirho),
    /// Verify every publication log on this root: intents, applied, owners, claims, reserved.
    #[command(name = "publication-verify")]
    PublicationVerifyChirho,
    #[command(name = "app-verify")]
    AppVerifyChirho,
    /// Diff a candidate app DAG against the live app by declared capabilities and cost.
    #[command(name = "review-diff")]
    ReviewDiffChirho(app_args_chirho::ReviewDiffArgsChirho),
    /// Promote a reviewed candidate DAG to the live app ref.
    #[command(name = "review-promote")]
    ReviewPromoteChirho(app_args_chirho::ReviewPromoteArgsChirho),
    #[command(name = "review-policy-envelope-set")]
    ReviewPolicyEnvelopeSetChirho(app_args_chirho::ReviewPolicyEnvelopeSetArgsChirho),
    #[command(name = "review-policy-envelope-verify")]
    ReviewPolicyEnvelopeVerifyChirho,
    /// Reject a reviewed candidate DAG without moving the app ref.
    #[command(name = "review-reject")]
    ReviewRejectChirho(app_args_chirho::ReviewRejectArgsChirho),
    /// List signed review promote/reject records.
    #[command(name = "reviews")]
    ReviewsChirho,
    /// Verify signed review records and recompute their diffs.
    #[command(name = "review-verify")]
    ReviewVerifyChirho,
    /// Set the current signed, content-addressed price book for an owned app.
    #[command(name = "pricebook-set")]
    PriceBookSetChirho(economic_args_chirho::PriceBookSetArgsChirho),
    /// Show the current price book for an app.
    #[command(name = "pricebook-show")]
    PriceBookShowChirho { app_chirho: String },
    /// Show signed price-book history for an app.
    #[command(name = "pricebook-history")]
    PriceBookHistoryChirho { app_chirho: String },
    /// Verify signed price-book records and their content-addressed objects.
    #[command(name = "pricebook-verify")]
    PriceBookVerifyChirho,
    /// Show the current billing policy for an app.
    #[command(name = "billing-policy-show")]
    BillingPolicyShowChirho { app_chirho: String },
    /// Show signed billing-policy history for an app.
    #[command(name = "billing-policy-history")]
    BillingPolicyHistoryChirho { app_chirho: String },
    /// Verify signed billing policy and billing usage records.
    #[command(name = "billing-policy-verify")]
    BillingPolicyVerifyChirho,
    /// Fold signed billing usage records by user, app, run, or effect.
    #[command(name = "billing-rollup")]
    BillingRollupChirho(economic_args_chirho::BillingRollupArgsChirho),
    /// List signed billing compensation records.
    #[command(name = "billing-compensations")]
    BillingCompensationsChirho,
    /// Set app-defined resource meters and action charge vectors from JSON.
    #[command(name = "resource-policy-set")]
    ResourcePolicySetChirho(economic_args_chirho::ResourcePolicySetArgsChirho),
    /// Remove the current app resource policy after owner check, recording a signed unset row.
    #[command(name = "resource-policy-unset")]
    ResourcePolicyUnsetChirho(economic_args_chirho::ResourcePolicyUnsetArgsChirho),
    /// Show the current app resource policy.
    #[command(name = "resource-policy-show")]
    ResourcePolicyShowChirho { app_chirho: String },
    /// Show signed resource-policy history for an app.
    #[command(name = "resource-policy-history")]
    ResourcePolicyHistoryChirho { app_chirho: String },
    /// Verify signed resource policies and usage records.
    #[command(name = "resource-policy-verify")]
    ResourcePolicyVerifyChirho,
    /// Record one app-level resource-accounting decision for an action.
    #[command(name = "resource-use")]
    ResourceUseChirho(economic_args_chirho::ResourceUseArgsChirho),
    /// List signed app-level resource usage records.
    #[command(name = "resource-usage")]
    ResourceUsageChirho(economic_args_chirho::ResourceUsageArgsChirho),
    /// Fold signed app-level resource usage by app, user, section, action, or resource.
    #[command(name = "resource-rollup")]
    ResourceRollupChirho(economic_args_chirho::ResourceRollupArgsChirho),
    /// Show remaining app-defined resource quotas and routed attempts.
    #[command(name = "resource-status")]
    ResourceStatusChirho(economic_args_chirho::ResourceStatusArgsChirho),
    /// List signed credit hold records.
    #[command(name = "holds")]
    HoldsChirho,
    /// Verify signed credit hold records and their ledger postings.
    #[command(name = "holds-verify")]
    HoldsVerifyChirho,
    /// Open a signed realtime session reserve.
    #[command(name = "realtime-open")]
    RealtimeOpenChirho(realtime_args_chirho::RealtimeOpenArgsChirho),
    /// Record a non-billing realtime event payload.
    #[command(name = "realtime-event")]
    RealtimeEventChirho(realtime_args_chirho::RealtimeEventArgsChirho),
    /// Settle elapsed realtime seconds from signed server timestamps.
    #[command(name = "realtime-tick")]
    RealtimeTickChirho(realtime_args_chirho::RealtimeTickArgsChirho),
    /// Record a signed provider usage observation for realtime reconciliation.
    #[command(name = "realtime-provider-usage")]
    RealtimeProviderUsageChirho(realtime_args_chirho::RealtimeProviderUsageArgsChirho),
    /// Import OpenAI Realtime response.done receipts into signed provider usage observations.
    #[command(name = "realtime-openai-usage-import")]
    RealtimeOpenAiUsageImportChirho(realtime_args_chirho::RealtimeOpenAiUsageImportArgsChirho),
    /// Close a realtime session from the current signed server timestamp.
    #[command(name = "realtime-close")]
    RealtimeCloseChirho(realtime_args_chirho::RealtimeCloseArgsChirho),
    /// Decrypt a closed realtime transcript and append signed plaintext-free access evidence.
    #[command(name = "realtime-transcript-reveal")]
    RealtimeTranscriptRevealChirho(realtime_args_chirho::RealtimeTranscriptRevealArgsChirho),
    /// List signed realtime session records.
    #[command(name = "realtime-sessions")]
    RealtimeSessionsChirho,
    /// List signed realtime event records.
    #[command(name = "realtime-events")]
    RealtimeEventsChirho,
    /// Verify realtime session/event logs and ledger rows.
    #[command(name = "realtime-verify")]
    RealtimeVerifyChirho,
    /// Force-close stale realtime sessions and release unused reserve.
    #[command(name = "realtime-sweep")]
    RealtimeSweepChirho(realtime_args_chirho::RealtimeSweepArgsChirho),
    /// Run a closed realtime transcript artifact through a pure DAG epilogue.
    #[command(name = "realtime-epilogue")]
    RealtimeEpilogueChirho(realtime_args_chirho::RealtimeEpilogueArgsChirho),
    /// List signed realtime epilogue DAG records.
    #[command(name = "realtime-epilogues")]
    RealtimeEpiloguesChirho,
    /// Verify realtime epilogue DAG records and their provenance.
    #[command(name = "realtime-epilogue-verify")]
    RealtimeEpilogueVerifyChirho,
    /// Emit a typed, evidence-backed agent report into the signed report stream.
    #[command(name = "agent-report-create")]
    AgentReportCreateChirho(agent_args_chirho::AgentReportCreateArgsChirho),
    /// Show one stored AgentReportChirho body by content hash.
    #[command(name = "agent-report-show")]
    AgentReportShowChirho { report_chirho: String },
    /// List signed agent report records.
    #[command(name = "agent-reports")]
    AgentReportsChirho(agent_args_chirho::AgentReportsArgsChirho),
    /// Verify signed agent report records and their content-addressed bodies.
    #[command(name = "agent-report-verify")]
    AgentReportVerifyChirho,
    /// Grant signed report budget tokens to one agent.
    #[command(name = "agent-report-budget-grant")]
    AgentReportBudgetGrantChirho(agent_args_chirho::AgentReportBudgetGrantArgsChirho),
    /// Show one agent's cumulative report budget balance.
    #[command(name = "agent-report-budget")]
    AgentReportBudgetChirho(agent_args_chirho::AgentReportBudgetArgsChirho),
    /// List signed report budget charges.
    #[command(name = "agent-report-charges")]
    AgentReportChargesChirho(agent_args_chirho::AgentReportChargesArgsChirho),
    /// Apply a signed admin response that changes an agent authority ref.
    #[command(name = "agent-authority-respond")]
    AgentAuthorityRespondChirho(agent_args_chirho::AgentAuthorityRespondArgsChirho),
    /// Show the current content-addressed authority state for one agent.
    #[command(name = "agent-authority-show")]
    AgentAuthorityShowChirho(agent_args_chirho::AgentAuthorityShowArgsChirho),
    /// Check whether the current authority ref permits one agent action scope.
    #[command(name = "agent-authority-check")]
    AgentAuthorityCheckChirho(agent_args_chirho::AgentAuthorityCheckArgsChirho),
    /// List signed agent authority response records.
    #[command(name = "agent-authority-responses")]
    AgentAuthorityResponsesChirho(agent_args_chirho::AgentAuthorityResponsesArgsChirho),
    /// Verify signed agent authority responses and current authority refs.
    #[command(name = "agent-authority-verify")]
    AgentAuthorityVerifyChirho,
    /// Export subject-tied signed logs and private blob refs, optionally with decrypted payloads.
    #[command(name = "privacy-export")]
    PrivacyExportChirho(privacy_args_chirho::PrivacyExportArgsChirho),
    /// Crypto-shred all current private blob keys for one opaque subject.
    #[command(name = "privacy-erase")]
    PrivacyEraseChirho(privacy_args_chirho::PrivacyEraseArgsChirho),
    /// List signed subject erasure records.
    #[command(name = "privacy-erasure-history")]
    PrivacyErasureHistoryChirho(privacy_args_chirho::PrivacyErasureHistoryArgsChirho),
    /// Apply generic private-blob retention by crypto-shredding expired keys.
    #[command(name = "privacy-retention-sweep")]
    PrivacyRetentionSweepChirho(privacy_args_chirho::PrivacyRetentionSweepArgsChirho),
    /// Show signed generic private-blob retention sweep history.
    #[command(name = "privacy-retention-history")]
    PrivacyRetentionHistoryChirho,
    /// Verify signed generic private-blob retention sweep records.
    #[command(name = "privacy-retention-verify")]
    PrivacyRetentionVerifyChirho,
    /// Place a signed per-subject legal hold that pauses privacy erasure.
    #[command(name = "legal-hold-place")]
    LegalHoldPlaceChirho(privacy_args_chirho::LegalHoldPlaceArgsChirho),
    /// Release a signed per-subject legal hold.
    #[command(name = "legal-hold-release")]
    LegalHoldReleaseChirho(privacy_args_chirho::LegalHoldReleaseArgsChirho),
    /// List signed legal hold records.
    #[command(name = "legal-holds")]
    LegalHoldsChirho(privacy_args_chirho::LegalHoldsArgsChirho),
    /// Verify signed legal hold records.
    #[command(name = "legal-hold-verify")]
    LegalHoldVerifyChirho,
    /// Register a local filesystem backup/replica root for erasure propagation.
    #[command(name = "privacy-replica-register")]
    PrivacyReplicaRegisterChirho(privacy_args_chirho::PrivacyReplicaRegisterArgsChirho),
    /// List signed local backup/replica targets.
    #[command(name = "privacy-replicas")]
    PrivacyReplicasChirho,
    /// Declare the signed backup key-material policy for privacy erasure coverage.
    #[command(name = "privacy-backup-policy-set")]
    PrivacyBackupPolicySetChirho(privacy_args_chirho::PrivacyBackupPolicySetArgsChirho),
    /// List signed backup key-material policy records.
    #[command(name = "privacy-backup-policies")]
    PrivacyBackupPoliciesChirho,
    /// Propagate one signed subject erasure to a registered local replica root.
    #[command(name = "privacy-erasure-propagate")]
    PrivacyErasurePropagateChirho(privacy_args_chirho::PrivacyErasurePropagateArgsChirho),
    /// List signed erasure propagation records.
    #[command(name = "privacy-erasure-propagations")]
    PrivacyErasurePropagationsChirho(privacy_args_chirho::PrivacyErasurePropagationsArgsChirho),
    /// Verify signed privacy blob and erasure records.
    #[command(name = "privacy-verify")]
    PrivacyVerifyChirho(privacy_args_chirho::PrivacyVerifyArgsChirho),
    /// Scan signed logs and JSON objects for structural private-data hazards.
    #[command(name = "privacy-scan")]
    PrivacyScanChirho(privacy_args_chirho::PrivacyScanArgsChirho),
    /// Scan JSONL evidence logs to prove no truncation or quarantine is required for recovery.
    #[command(name = "seqlog-scan")]
    SeqlogScanChirho(cairn_seqlog_scan_chirho::SeqlogScanArgsChirho),
    /// Generate a signed ISO/SOC control-evidence pack from live verified logs.
    #[command(name = "compliance-evidence-generate")]
    ComplianceEvidenceGenerateChirho(compliance_args_chirho::ComplianceEvidenceGenerateArgsChirho),
    /// Show a stored compliance evidence pack as JSON.
    #[command(name = "compliance-evidence-show")]
    ComplianceEvidenceShowChirho { pack_chirho: String },
    /// Verify signed compliance evidence records and their source prefixes.
    #[command(name = "compliance-evidence-verify")]
    ComplianceEvidenceVerifyChirho(compliance_args_chirho::ComplianceEvidenceVerifyArgsChirho),
    /// Set the current tenant data-residency policy.
    #[command(name = "data-residency-set")]
    DataResidencySetChirho(compliance_args_chirho::DataResidencySetArgsChirho),
    /// Show the current tenant data-residency policy.
    #[command(name = "data-residency-show")]
    DataResidencyShowChirho,
    /// Record a signed point-in-time region assertion against the current policy.
    #[command(name = "data-residency-attest")]
    DataResidencyAttestChirho(compliance_args_chirho::DataResidencyAttestArgsChirho),
    /// Check one placement candidate against the current tenant residency policy.
    #[command(name = "data-residency-check-placement")]
    DataResidencyCheckPlacementChirho(
        compliance_args_chirho::DataResidencyCheckPlacementArgsChirho,
    ),
    /// Verify signed data-residency policies and attestations.
    #[command(name = "data-residency-verify")]
    DataResidencyVerifyChirho(compliance_args_chirho::DataResidencyVerifyArgsChirho),
    /// Set the current owner-authored onboarding guide for an app.
    #[command(name = "onboarding-set")]
    OnboardingSetChirho(content_args_chirho::OnboardingSetArgsChirho),
    /// Show the current onboarding guide for an app.
    #[command(name = "onboarding-show")]
    OnboardingShowChirho { app_chirho: String },
    /// Show signed onboarding guide history for an app.
    #[command(name = "onboarding-history")]
    OnboardingHistoryChirho { app_chirho: String },
    /// Verify signed onboarding records and their content-addressed guide objects.
    #[command(name = "onboarding-verify")]
    OnboardingVerifyChirho,
    /// Register a cairn principal and bind it to one ledger wallet.
    #[command(name = "identity-register")]
    IdentityRegisterChirho(auth_args_chirho::IdentityRegisterArgsChirho),
    /// List registered principals and their wallets.
    #[command(name = "identity-list")]
    IdentityListChirho,
    /// Report local credential hash posture without exposing principals or key material.
    #[command(name = "identity-credential-inventory")]
    IdentityCredentialInventoryChirho(auth_args_chirho::IdentityCredentialInventoryArgsChirho),
    /// Add an HTTP credential to an existing credentialless principal from a mode-600 file.
    #[command(name = "identity-credential-set")]
    IdentityCredentialSetChirho(auth_args_chirho::IdentityCredentialSetArgsChirho),
    /// Replace a credentialed principal's HTTP credential from a mode-600 file, revoking every
    /// live session of that principal first and appending a signed reset record.
    #[command(name = "identity-credential-reset")]
    IdentityCredentialResetChirho(auth_args_chirho::IdentityCredentialResetArgsChirho),
    /// Register a credentialless USER principal and mint its setup code, which expires one lifetime later. The code
    /// prints ONCE on stdout; `--json` prints {"principal_chirho", "recovery_code_chirho", "expires_ms_chirho"}. Only
    /// user principals hold a mailable code: `--kind owner` is refused, and an owner is registered with a credential file.
    #[command(name = "identity-invite")]
    IdentityInviteChirho(auth_args_chirho::IdentityInviteArgsChirho),
    /// Mint a fresh recovery or setup code for an existing USER principal, burning any code before it. It expires one
    /// lifetime later and prints ONCE on stdout, as `identity-invite` does. An owner is refused: reset it with
    /// `identity-credential-reset`.
    #[command(name = "identity-recovery-code-mint")]
    IdentityRecoveryCodeMintChirho(auth_args_chirho::IdentityRecoveryCodeMintArgsChirho),
    /// List the recovery code events, each labelled VALID or INVALID; principals as hashes, never raw.
    #[command(name = "identity-recovery-code-events")]
    IdentityRecoveryCodeEventsChirho(auth_args_chirho::IdentityRecoveryCodeEventsArgsChirho),
    /// Verify the recovery code events: contiguous seqs, closed vocabulary, expiry rules and signatures.
    #[command(name = "identity-recovery-code-events-verify")]
    IdentityRecoveryCodeEventsVerifyChirho,
    /// Create a signed local session token for a registered principal.
    #[command(name = "identity-login")]
    IdentityLoginChirho { principal_chirho: String },
    /// List one principal's verified sessions with seq, issue/expiry, and live/expired/revoked state.
    #[command(name = "identity-sessions-list")]
    IdentitySessionsListChirho { principal_chirho: String },
    /// Revoke a signed identity session by token file or session sequence.
    #[command(name = "identity-session-revoke")]
    IdentitySessionRevokeChirho(auth_args_chirho::IdentitySessionRevokeArgsChirho),
    /// Verify identity records: contiguous seqs + signatures.
    #[command(name = "identity-verify")]
    IdentityVerifyChirho,
    /// Verify identity session records: contiguous seqs + signatures.
    #[command(name = "identity-sessions-verify")]
    IdentitySessionsVerifyChirho,
    /// Verify identity session revocation records: contiguous seqs + signatures.
    #[command(name = "identity-session-revocations-verify")]
    IdentitySessionRevocationsVerifyChirho,
    /// Verify identity credential reset records: contiguous seqs + signatures.
    #[command(name = "identity-credential-resets-verify")]
    IdentityCredentialResetsVerifyChirho,
    /// Register an app as an OAuth client owned by an owner principal.
    #[command(name = "oauth-client-register")]
    OauthClientRegisterChirho(auth_args_chirho::OauthClientRegisterArgsChirho),
    /// List OAuth clients.
    #[command(name = "oauth-clients")]
    OauthClientsChirho,
    /// Issue an app-scoped token after verifying the principal credential.
    #[command(name = "oauth-token")]
    OauthTokenChirho(auth_args_chirho::OauthTokenArgsChirho),
    /// Issue a limited key holding named actions over the app's current openings.
    #[command(name = "oauth-limited-key")]
    OauthLimitedKeyChirho(auth_args_chirho::OauthLimitedKeyArgsChirho),
    /// List signed scoped-token rate-limit use records.
    #[command(name = "oauth-uses")]
    OauthUsesChirho,
    /// Verify OAuth clients and scoped token records. The connection stores (K4) verify too, so a fault there fails
    /// this command; their counts print from `oauth-connection-verify`.
    #[command(name = "oauth-verify")]
    OauthVerifyChirho,
    /// Verify the connection stores' client, key and use logs (K4), each in its own numbering, and print their counts.
    #[command(name = "oauth-connection-verify")]
    OauthConnectionVerifyChirho,
    #[cfg_attr(
        doc,
        doc = "Undeploy an app: drop its `app/<name>` ref (objects remain for gc)."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Undeploy an app: drop its app/<name> ref (objects remain for gc)."
    )]
    #[command(name = "undeploy")]
    UndeployChirho(app_args_chirho::UndeployArgsChirho),
    #[cfg_attr(
        doc,
        doc = "Deploy a single-node SSR app: `read(<key>)`, served as HTML at `/ssr-chirho/<key>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Deploy a single-node SSR app: read(<key>), served as HTML at /ssr-chirho/<key>."
    )]
    #[command(name = "ssr-demo")]
    SsrDemoChirho { key_chirho: String },
    #[cfg_attr(
        doc,
        doc = "Compile the example upcase pure node to a self-contained wasm artifact, written to `<out>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Compile the example upcase pure node to a self-contained wasm artifact, written to <out>."
    )]
    #[command(name = "compile-demo")]
    CompileDemoChirho { out_chirho: PathBuf },
    #[cfg_attr(
        doc,
        doc = "Compose the upcase->reverse chain into ONE wasm (multi-node composition), written to `<out>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Compose the upcase->reverse chain into ONE wasm (multi-node composition), written to <out>."
    )]
    #[command(name = "compile-chain-demo")]
    CompileChainDemoChirho { out_chirho: PathBuf },
    #[cfg_attr(
        doc,
        doc = "Compose an EFFECTFUL chain (upcase -> dom_patch import) into ONE wasm, written to `<out>`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Compose an EFFECTFUL chain (upcase -> dom_patch import) into ONE wasm, written to <out>."
    )]
    #[command(name = "compile-effect-demo")]
    CompileEffectDemoChirho { out_chirho: PathBuf },
    /// Serve apps over HTTP: request -> server DAG -> payload.
    #[command(name = "serve")]
    ServeChirho(ops_args_chirho::ServeArgsChirho),
    /// Run the platform from cairn-chirho.toml (one command up: root, port, limits from config).
    #[command(name = "up")]
    UpChirho(ops_args_chirho::UpArgsChirho),
    /// Author one signed cluster-genesis destination-authority enrollment from an existing
    /// externally held keypair and a verified retained roster bundle.
    #[command(name = "ledger-destination-authority-enroll-chirho")]
    LedgerDestinationAuthorityEnrollChirho(
        ops_args_chirho::DestinationAuthorityEnrollmentAuthorArgsChirho,
    ),
    /// Derive one reviewed ledger-host authoring document and report what it authorizes. Writes
    /// nothing; the report's digest is what the authoring command below requires.
    #[command(name = "ledger-host-author-review-chirho")]
    LedgerHostAuthorReviewChirho(ops_args_chirho::LedgerHostAuthorReviewArgsChirho),
    /// Author and emit the ledger host config plus regenesis plan one reviewed document authorizes.
    #[command(name = "ledger-host-author-chirho")]
    LedgerHostAuthorChirho(ops_args_chirho::LedgerHostAuthorArgsChirho),
    /// Author the pre-signed H3 activation authorization from an existing config/plan. Writes it
    /// create-new (0600) and prints its digest for a later run's --expected-activation-authorization-digest-chirho.
    #[command(name = "ledger-host-activation-author-chirho")]
    LedgerHostActivationAuthorChirho(ops_args_chirho::LedgerHostActivationAuthorArgsChirho),
    /// Build and atomically publish one reviewed ledger regenesis plan.
    #[command(name = "ledger-regenesis-chirho")]
    LedgerRegenesisChirho(ops_args_chirho::LedgerRegenesisArgsChirho),
    /// Dev-only: fund a payer on a synthetic file-backed local ledger host via the single-node
    /// regenesis mint (mint-to-payer), so the served-LLM card's Hold can succeed. Refuses a
    /// production posture; no real provider, spend, host, or activation.
    #[command(name = "served-llm-dev-bootstrap-chirho")]
    ServedLlmDevBootstrapChirho(ops_args_chirho::ServedLlmDevBootstrapArgsChirho),
    /// Export one bounded path-free proof of this configured root's shadow-canary window.
    #[command(name = "ledger-shadow-canary-report-chirho")]
    LedgerShadowCanaryReportChirho(ops_args_chirho::LedgerShadowCanaryReportArgsChirho),
    /// Verify one captured shadow-canary report and bind a bounded verdict to its exact bytes.
    #[command(name = "ledger-shadow-canary-verdict-chirho")]
    LedgerShadowCanaryVerdictChirho(ops_args_chirho::LedgerShadowCanaryVerdictArgsChirho),
    /// Export one bounded live-only F1 mirror high-water report without opening resident authority.
    #[command(name = "ledger-mirror-live-head-report-chirho")]
    LedgerMirrorLiveHeadReportChirho(ops_args_chirho::LedgerMirrorLiveHeadReportArgsChirho),
    /// Verify one captured live-head report and bind a path-free verdict to its exact bytes.
    #[command(name = "ledger-mirror-live-head-verdict-chirho")]
    LedgerMirrorLiveHeadVerdictChirho(ops_args_chirho::LedgerMirrorLiveHeadVerdictArgsChirho),
    /// Preview the one verified current-plan PostgreSQL compensation without writing.
    #[command(name = "ledger-compensation-preview-chirho")]
    LedgerCompensationPreviewChirho(ops_args_chirho::LedgerCompensationArgsChirho),
    /// Open and immediately release the configured read/effect runtime without serving or writing.
    #[command(name = "ledger-runtime-preflight-chirho")]
    LedgerRuntimePreflightChirho(ops_args_chirho::LedgerRuntimePreflightArgsChirho),
    /// Execute the one verified current-plan PostgreSQL compensation.
    #[command(name = "ledger-compensation-execute-chirho")]
    LedgerCompensationExecuteChirho(ops_args_chirho::LedgerCompensationArgsChirho),
    #[command(name = "run-show")]
    RunShowChirho { id_chirho: String },
    #[command(name = "inspect")]
    InspectChirho { id_chirho: String },
    #[command(name = "audit")]
    AuditChirho { id_chirho: String },
    #[command(name = "verify")]
    VerifyChirho { id_chirho: String },
    #[command(name = "run-cache-verify")]
    RunCacheVerifyChirho(core_args_chirho::RunCacheVerifyArgsChirho),
    #[command(name = "run-intent-startup-preflight")]
    RunIntentStartupPreflightChirho(RunIntentPreflightArgsChirho),
    #[command(name = "volatile-effects")]
    VolatileEffectsChirho(compliance_args_chirho::VolatileEffectsArgsChirho),
    /// Verify signed live ReadStoreChirho/QueryChirho records and their CAS refs.
    #[command(name = "volatile-effects-verify")]
    VolatileEffectsVerifyChirho(compliance_args_chirho::VolatileEffectsVerifyArgsChirho),
    /// Show a deployed app's agent-readable API descriptor: its routes + each route's input mode
    /// and plain-language capability verdict (the source for generated docs and an MCP manifest).
    #[command(name = "app-descriptor")]
    AppDescriptorChirho(app_args_chirho::AppDescriptorArgsChirho),
    /// Generate a deployed app's API docs from its descriptor: Markdown by default, or the MCP tool
    /// manifest with --mcp (one source of truth -> the owner's page and the agent's tools).
    #[command(name = "app-docs")]
    AppDocsChirho(app_args_chirho::AppDocsArgsChirho),
    /// Show the platform MCP tool catalog: the owner tools an agent can drive (each marked
    /// read-only or gated-action), mapping to existing cairn commands — no MCP-only mutations.
    #[command(name = "platform-mcp")]
    PlatformMcpChirho(app_args_chirho::PlatformMcpArgsChirho),
    /// Show in plain language what a deployed app can do to the world (its capability summary).
    #[command(name = "app-capabilities")]
    AppCapabilitiesChirho(app_args_chirho::AppCapabilitiesArgsChirho),
    /// List signed host/path-to-app domain bindings (fail-closed verified).
    #[command(name = "domain-bindings")]
    DomainBindingsChirho(domain_args_chirho::DomainBindingsArgsChirho),
    #[cfg_attr(
        doc,
        doc = "Add a signed host/path-to-app domain binding (`host + path-prefix -> app[/route]`)."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Add a signed host/path-to-app domain binding (host + path-prefix -> app[/route])."
    )]
    #[command(name = "domain-bind")]
    DomainBindChirho(domain_args_chirho::DomainBindArgsChirho),
    /// Remove (unbind) a host/path-to-app domain binding by appending a signed removal.
    #[command(name = "domain-unbind")]
    DomainUnbindChirho(domain_args_chirho::DomainUnbindArgsChirho),
    #[cfg_attr(
        doc,
        doc = "Set a domain's desired DNS zone (replaces it). Each --record is `TYPE,NAME,VALUE,TTL[,PRIORITY]`."
    )]
    #[cfg_attr(
        not(doc),
        doc = "Set a domain's desired DNS zone (replaces it). Each --record is \"TYPE,NAME,VALUE,TTL[,PRIORITY]\"."
    )]
    #[command(name = "dns-zone-set")]
    DnsZoneSetChirho(domain_args_chirho::DnsZoneSetArgsChirho),
    /// Show signed desired-state DNS zones (fail-closed verified). Live apply is a separate gated effect.
    #[command(name = "dns-zones")]
    DnsZonesChirho(domain_args_chirho::DnsZonesArgsChirho),
    /// Add a customer mailbox or alias (PII-safe: local-part + target sealed in private blobs).
    #[command(name = "mailbox-set")]
    MailboxSetChirho(domain_args_chirho::MailboxSetArgsChirho),
    /// Remove a customer mailbox/alias by appending a signed removal record.
    #[command(name = "mailbox-remove")]
    MailboxRemoveChirho(domain_args_chirho::MailboxRemoveArgsChirho),
    /// List an owner's mailboxes/aliases as safe rows (no address plaintext).
    #[command(name = "mailboxes")]
    MailboxesChirho(domain_args_chirho::MailboxesArgsChirho),
    /// Show a domain's hosting status: its live routing bindings and desired DNS zone in one view.
    #[command(name = "domain-status")]
    DomainStatusChirho(domain_args_chirho::DomainStatusArgsChirho),
    /// Record an intent to apply a domain's desired DNS zone via the no-network stub performer
    /// (idempotent). Live provider apply is a separate operator-gated step, not this command.
    #[command(name = "dns-apply-stub")]
    DnsApplyStubChirho(domain_args_chirho::DnsApplyStubArgsChirho),
    /// List signed DNS apply records (fail-closed verified).
    #[command(name = "dns-applies")]
    DnsAppliesChirho(domain_args_chirho::DnsAppliesArgsChirho),
    /// Record an intent to provision a domain's live mailboxes via the no-network stub performer
    /// (idempotent). Live Mailu provisioning is a separate operator-gated step, not this command.
    #[command(name = "mailbox-apply-stub")]
    MailboxApplyStubChirho(domain_args_chirho::MailboxApplyStubArgsChirho),
    /// List signed mailbox apply records (fail-closed verified).
    #[command(name = "mailbox-applies")]
    MailboxAppliesChirho(domain_args_chirho::MailboxAppliesArgsChirho),
    /// Roll a branch back to an earlier object hash (move the ref).
    #[command(name = "rollback")]
    RollbackChirho(state_args_chirho::RollbackArgsChirho),
    /// List signed causal rollback events.
    #[command(name = "reversion-events")]
    ReversionEventsChirho,
    /// List signed compensation records emitted by causal rollback.
    #[command(name = "reversion-compensations")]
    ReversionCompensationsChirho,
    /// List signed compensation execution attempts.
    #[command(name = "reversion-executions")]
    ReversionExecutionsChirho,
    /// List signed rollback completion summaries.
    #[command(name = "reversion-completions")]
    ReversionCompletionsChirho,
    /// Verify retained causal rollback, compensation, grant, and completion evidence.
    #[command(name = "reversion-verify")]
    ReversionVerifyChirho,
    /// List signed manual-remediation resolution records.
    #[command(name = "reversion-manual-resolutions")]
    ReversionManualResolutionsChirho,
    /// Create or advance a branch to point at an object hash.
    #[command(name = "branch")]
    BranchChirho(state_args_chirho::BranchArgsChirho),
    /// List branches, tags, and HEAD.
    #[command(name = "refs")]
    RefsChirho,
    /// Show the reflog — every ref move, oldest first.
    #[command(name = "reflog")]
    ReflogChirho,
    /// Versioned store: write a value for a key; prints the version stamped.
    #[command(name = "kv-put")]
    KvPutChirho(state_args_chirho::KvPutArgsChirho),
    /// Versioned store: read a key — at the current view, or `--at <version>`.
    #[command(name = "kv-get")]
    KvGetChirho(state_args_chirho::KvGetArgsChirho),
    /// Versioned store: print the current view version.
    #[command(name = "kv-version")]
    KvVersionChirho,
    /// Versioned store: roll the view back (or forward) to a version.
    #[command(name = "kv-rollback")]
    KvRollbackChirho { to_chirho: u64 },
    /// Garbage-collect objects unreachable from refs.
    #[command(name = "gc")]
    GcChirho,
    /// Rebuild the SQLite read model from the store's current view (or `--at <version>`).
    #[command(name = "project")]
    ProjectChirho(ops_args_chirho::ProjectArgsChirho),
    /// Run a read-only SQL query against the read model.
    #[command(name = "query")]
    QueryChirho { sql_chirho: String },
    /// Run a scoped, metered query as a blessed effect.
    #[command(name = "query-effect")]
    QueryEffectChirho(state_args_chirho::QueryEffectArgsChirho),
    /// Build a persistent content-addressed index root from the store's current view.
    #[command(name = "index-project")]
    IndexProjectChirho(state_args_chirho::IndexProjectArgsChirho),
    /// Read one key through a persistent index root record.
    #[command(name = "index-get")]
    IndexGetChirho(state_args_chirho::IndexGetArgsChirho),
    /// Roll the current index ref back to a prior root record.
    #[command(name = "index-rollback")]
    IndexRollbackChirho { root_chirho: String },
    /// Verify a persistent index root record and its reachable HAMT nodes.
    #[command(name = "index-verify")]
    IndexVerifyChirho { root_chirho: String },
    /// Build an inverted provenance index for dependent-effect lookup.
    #[command(name = "index-provenance-project")]
    IndexProvenanceProjectChirho,
    /// Find effects causally dependent on a content-addressed state hash.
    #[command(name = "index-provenance-find")]
    IndexProvenanceFindChirho(state_args_chirho::IndexProvenanceFindArgsChirho),
    /// Verify an inverted provenance index root record.
    #[command(name = "index-provenance-verify")]
    IndexProvenanceVerifyChirho { root_chirho: String },
}
