// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The consume-reviewed-inputs production setup for the credits-demo LocalPhaseB smoke: it preflights
//! the supplied plan (digest + dormant-finality), the validated + custody-verified config, the DSN's
//! sanctioned-local-endpoint shape, and the operator-established external PostgreSQL preconditions
//! (all three reversible tables + keyed seed, fingerprint RECOMPUTED under the configured adapter
//! key — never a constant expectation, #6046) on a fresh root BEFORE any authoritative mutation,
//! then runs H3 regenesis, re-digests the immutable H3 packet against the receipt, retains the
//! signed pre-L2 balance head for the packet-evidence verifier, and performs the in-process
//! authoring emit + review-first Promote and the signed price book. Signer/issuer/adapter/DSN key
//! bytes are NEVER set here — they resolve from the operator root's secret store named by the config.
//!
//! Workflow: `spec-chirho/workflows-chirho/reversible-postgres-effect-chirho/credits-demo-localphaseb-smoke-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_chirho::config_chirho::LedgerHostConfigChirho;
use cairn_chirho::model_chirho::HashChirho;
use cairn_chirho::{
    app_source_manifest_chirho, cas_chirho, config_chirho, identity_chirho, refs_chirho,
    review_chirho,
};
use cairn_ledger_regenesis_chirho::{
    canonical_plan_bytes_chirho, load_canonical_ledger_regenesis_evidence_packet_chirho,
    load_canonical_ledger_regenesis_publication_manifest_chirho, plan_digest_chirho,
    run_ledger_regenesis_chirho, LedgerRegenesisH3aRequestChirho, LedgerRegenesisPlanV1Chirho,
    LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO,
    LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO,
};
use cairn_writer_head_chirho::head_transition_authority_chirho::HeadTransitionAuthorityPortChirho;
use postgres::{Client, NoTls};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::authoring_gate_chirho::preflight_authoring_gate_chirho;
use super::concurrency_token_chirho::read_credits_demo_concurrency_token_from_dsn_chirho;
use super::constants_chirho;
use super::continuation_chirho;
use super::types_chirho::{
    AppAuthorityChirho, AuthoringGateReportChirho, AuthoringProvenanceChirho,
    AuthorityCoordinatesChirho, ConfigAuthorityChirho, DormancyPostureChirho,
    ExternalPreconditionsChirho, PlanAuthorityChirho, AUTHORING_PROVENANCE_SCHEMA_CHIRHO,
    AUTHORITY_COORDINATES_SCHEMA_CHIRHO, DORMANCY_POSTURE_SCHEMA_CHIRHO,
    EXTERNAL_PRECONDITIONS_SCHEMA_CHIRHO,
};

/// The operator-reviewed inputs the production command consumes (one struct — no long positional
/// argument list to misorder).
pub struct CreditsDemoSmokeInputsChirho<'inputs_chirho> {
    pub root_chirho: &'inputs_chirho Path,
    pub config_path_chirho: &'inputs_chirho Path,
    pub expected_config_digest_chirho: &'inputs_chirho str,
    pub plan_path_chirho: &'inputs_chirho Path,
    pub expected_plan_digest_chirho: &'inputs_chirho str,
    pub issuer_secret_name_chirho: &'inputs_chirho str,
    pub activation_authorization_path_chirho: &'inputs_chirho Path,
    pub expected_activation_authorization_digest_chirho: &'inputs_chirho str,
    /// The payer's login credential, named as a SECRET-STORE ref (never a raw CLI value): served
    /// app requests authenticate through real scoped-token issuance, which requires it.
    pub payer_credential_secret_name_chirho: &'inputs_chirho str,
    pub app_root_chirho: &'inputs_chirho Path,
    pub manifest_path_chirho: Option<&'inputs_chirho Path>,
    /// C1 A3's per-voter births, from the test-kind geo seed only: setup registers the plan's payer
    /// under exactly this reviewed principal, so roots born from one plan hold the same payer. It must
    /// equal the plan's `initial_owner`. `None` everywhere else keeps the payer the operator registered
    /// before authoring.
    pub reviewed_payer_principal_chirho: Option<&'inputs_chirho str>,
}

/// A caller-supplied opener for the post-regenesis resident authority.
///
/// THE MONEY-AUTHORITY SEAM, and its SHAPE is the whole point. This road names NO resident-actor
/// door beyond the refusing production default it falls back to; a caller that needs a different
/// authority composition hands one in through this callback. So every symbol that reaches a GD7
/// compensation-provider door lives in the INJECTING crate, never here. That confinement is not
/// stylistic: `cairn-operator-smoke-chirho` reaches `cairn-cli-chirho` by three link paths, so a
/// door named here would make the SHIPPING CLI capable of autonomously completing a compensation.
/// `gd7_compensation_provider_door_has_no_shipping_binary_caller_chirho` executes that invariant.
///
/// Absence remains the refusing posture, in both halves: `None` keeps the production door (which
/// itself carries the test-kind fence), and a test-kind-marked config is refused at setup entry
/// before any mutation. Only an explicit injection admits a test-kind config here.
pub type CreditsDemoResidentOpenerChirho<'opener_chirho> = &'opener_chirho dyn Fn(
    &Path,
    &Path,
    &LedgerHostConfigChirho,
) -> Result<
    cairn_ledger_host_chirho::ResidentEffectJournalHandleChirho,
>;

/// Coordinates the served arc + verifier + packet stages consume from a prepared, preflighted root.
pub struct CreditsDemoSetupChirho {
    pub root_chirho: PathBuf,
    pub config_path_chirho: PathBuf,
    pub expected_config_digest_chirho: String,
    pub app_root_chirho: PathBuf,
    pub payer_chirho: String,
    pub owner_chirho: String,
    pub settlement_owner_chirho: String,
    pub billing_kind_chirho: String,
    pub plan_mint_amount_chirho: u64,
    /// The payer coordinate from each INDEPENDENT source (the five-principal chain's setup half).
    pub config_payer_member_chirho: String,
    pub identity_record_payer_chirho: String,
    pub plan_initial_owner_chirho: String,
    pub storage_namespace_chirho: String,
    pub journal_path_chirho: String,
    pub balance_projection_name_chirho: String,
    pub balance_head_path_chirho: String,
    /// The RETAINED signed pre-L2 regenesis-cut balance head (storage-relative path) the
    /// packet-evidence parent loads through the signature-verifying loader.
    pub retained_regenesis_head_path_chirho: String,
    /// The immutable H3 packet file (internal coordinate — never emitted in the packet).
    pub h3_packet_path_chirho: PathBuf,
    /// The host-bound publication manifest path remains internal; only its digest is emitted.
    pub h3_publication_manifest_path_chirho: PathBuf,
    pub dsn_chirho: String,
    /// The resolved payer credential (memory-only; a no-leak needle at emission) and the signed
    /// oauth client id the served arc issues scoped tokens against.
    pub payer_credential_chirho: String,
    pub oauth_client_id_chirho: String,
    /// Every configured secret ref name (signers + issuer + provider) — the packet no-leak scan
    /// re-resolves THESE at emission and refuses any resolved value in the JSON (#6067).
    pub secret_ref_names_chirho: Vec<String>,
    pub plan_digest_chirho: String,
    pub regenesis_packet_digest_chirho: String,
    pub regenesis_publication_manifest_digest_chirho: String,
    pub l2_spend_token_chirho: String,
    pub source_review_report_chirho: String,
    pub dormancy_chirho: DormancyPostureChirho,
    pub authoring_chirho: AuthoringProvenanceChirho,
    pub external_preconditions_chirho: ExternalPreconditionsChirho,
    pub authority_coordinates_chirho: AuthorityCoordinatesChirho,
}

/// Connect a synchronous PostgreSQL client to the sanctioned local endpoint. Every connection —
/// preflight and arc alike — goes through the served runtime's ONE LocalPhaseB DSN law
/// (`parse_local_phase_b_connection_config_chirho`, #6024/#6025/#6056) BEFORE any connection
/// attempt, so a non-local DSN refuses here and the smoke can never disagree with serving about
/// what "local" means.
pub fn connect_pg_chirho(dsn_chirho: &str) -> Result<Client> {
    let config_chirho =
        cairn_serve_runtime_chirho::parse_local_phase_b_connection_config_chirho(dsn_chirho)
            .context("LocalPhaseB DSN refused by the shared local-endpoint law")?;
    config_chirho.connect(NoTls).context(
        "sanctioned local PostgreSQL unavailable; credits-demo-smoke is operator evidence and \
         never skips green — start local PostgreSQL and retry",
    )
}

fn now_ms_chirho() -> u64 {
    // Checked conversion (#6096): a clock overflow degrades to 0, which can only FAIL dormancy
    // (checked_sub -> None -> bail) — a broken clock can never green a gate.
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration_chirho| u64::try_from(duration_chirho.as_millis()).ok())
        .unwrap_or(0)
}

/// The reviewed payer (C1 A3) must be the plan's payer, and its credential comes from the operator
/// secret store, as the served arc's does.
fn reviewed_payer_credential_chirho(
    root_chirho: &Path,
    plan_payer_chirho: &str,
    reviewed_payer_chirho: &str,
    payer_credential_secret_name_chirho: &str,
) -> Result<String> {
    if reviewed_payer_chirho != plan_payer_chirho {
        bail!("ReviewedPayerIsNotThePlanInitialOwnerChirho");
    }
    resolve_secret_string_chirho(root_chirho, payer_credential_secret_name_chirho)
        .context("resolve the payer credential from the operator secret store")
}

/// The read-only half (C1 A3): every check the registration makes, claiming nothing. It writes no
/// identity, key-file or attribution state, though taking the attribution lock can create that lock's
/// file (claude2 #29410). Setup runs it with its other read-only gates and registers the payer only after
/// regenesis (Agy #29339, claude2 #29344).
///
/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/promotion-restart-design-chirho.md`.
pub(super) fn precheck_reviewed_payer_chirho(
    root_chirho: &Path,
    plan_payer_chirho: &str,
    reviewed_payer_chirho: &str,
    payer_credential_secret_name_chirho: &str,
) -> Result<()> {
    let credential_chirho = reviewed_payer_credential_chirho(
        root_chirho,
        plan_payer_chirho,
        reviewed_payer_chirho,
        payer_credential_secret_name_chirho,
    )?;
    identity_chirho::precheck_reviewed_principal_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        reviewed_payer_chirho,
        Some(&credential_chirho),
    )
}

/// Register the plan's payer under the reviewed principal (C1 A3), repeating every precheck.
///
/// Workflow:
/// `spec-chirho/workflows-chirho/distributed-ha-chirho/healing-drills-chirho/promotion-restart-design-chirho.md`.
pub(super) fn register_reviewed_payer_chirho(
    root_chirho: &Path,
    plan_payer_chirho: &str,
    reviewed_payer_chirho: &str,
    payer_credential_secret_name_chirho: &str,
) -> Result<()> {
    let credential_chirho = reviewed_payer_credential_chirho(
        root_chirho,
        plan_payer_chirho,
        reviewed_payer_chirho,
        payer_credential_secret_name_chirho,
    )?;
    identity_chirho::register_identity_with_reviewed_principal_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        reviewed_payer_chirho,
        Some(&credential_chirho),
    )?;
    Ok(())
}

/// Where the plan payer's identity comes from. Either it is already registered, and the read-only phase
/// selects it, or it is a reviewed principal (C1 A3) that the read-only phase only prechecks and setup
/// registers after regenesis, beside the drawn owner.
enum PlanPayerIdentityChirho<'inputs_chirho> {
    SelectedChirho(String),
    ReviewedPendingChirho(&'inputs_chirho str),
}

/// The plan payer's identity, EXACT-selected from one verified identity load (#6048/#6049). Missing,
/// duplicate, or wrong-kind all REFUSE (fail-closed; never pick-latest, never a raw load).
fn select_plan_payer_identity_chirho(
    verified_identities_chirho: &[identity_chirho::IdentityRecordChirho],
    payer_chirho: &str,
) -> Result<String> {
    let mut payer_identity_matches_chirho = verified_identities_chirho
        .iter()
        .filter(|record_chirho| record_chirho.principal_chirho == payer_chirho);
    let payer_identity_chirho = payer_identity_matches_chirho.next().ok_or_else(|| {
        anyhow::anyhow!(
            "the plan initial_owner is not a registered identity (cannot authenticate the payer)"
        )
    })?;
    if payer_identity_matches_chirho.next().is_some() {
        bail!("duplicate identity records for the plan initial_owner (verified-log anomaly)");
    }
    if !matches!(
        payer_identity_chirho.kind_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho
    ) {
        bail!("the plan initial_owner identity is not a User principal (owner/payer split)");
    }
    Ok(payer_identity_chirho.principal_chirho.clone())
}

pub fn run_credits_demo_setup_chirho(
    inputs_chirho: &CreditsDemoSmokeInputsChirho<'_>,
    resident_opener_chirho: Option<CreditsDemoResidentOpenerChirho<'_>>,
) -> Result<CreditsDemoSetupChirho> {
    let root_chirho = inputs_chirho.root_chirho;
    let config_path_chirho = inputs_chirho.config_path_chirho;
    let plan_path_chirho = inputs_chirho.plan_path_chirho;
    let app_root_chirho = inputs_chirho.app_root_chirho;

    // --- PREFLIGHT (read-only; refuse before the first authoritative mutation) ---
    if inputs_chirho.expected_plan_digest_chirho.is_empty() {
        bail!("--expected-plan-digest-chirho is required (the plan authority is digest-bound)");
    }
    let config_chirho = config_chirho::load_digest_bound_config_chirho(
        config_path_chirho,
        inputs_chirho.expected_config_digest_chirho,
    )?;
    let config_digest_chirho = cairn_chirho::model_chirho::HashChirho(
        inputs_chirho.expected_config_digest_chirho.to_owned(),
    );
    // The exact reviewed bytes are authenticated before this custody check touches root identity.
    // Custody then proves the externally-bound file also belongs to this selected root owner.
    cairn_ledger_host_chirho::verify_host_ledger_config_custody_chirho(
        root_chirho,
        config_path_chirho,
    )
    .map_err(|error_chirho| anyhow::anyhow!("host config custody refused: {error_chirho:?}"))?;
    let custody_verified_chirho = true;
    let ledger_host_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("config lacks a [ledger_host_chirho] block"))?;
    ledger_host_chirho.validate_chirho()?;
    let postgres_effect_chirho = ledger_host_chirho
        .postgres_effect_chirho
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("config lacks a LocalPhaseB postgres_effect block"))?;
    // E1-e-1 scope: this fixes the fresh seeding road only. The consumed-root continuation road
    // remains separately held at its resident opener until its own reviewed design lands.
    //
    // E1-e-2: the fence is the DEFAULT posture, not the only one. With no injected opener this road
    // can reach nothing but the production resident door, so a test-kind-marked config must be
    // refused HERE — before the first authoritative mutation — and not at that door, which sits past
    // H3 regenesis and would leave a latched, half-seeded root. An injected opener means the caller
    // supplied its own authority composition (the test-kind drill crate's, which reaches the
    // compensation-provider door on purpose); fencing that would deny the very drill the marker
    // exists to permit. Absence still refuses — only an explicit injection admits.
    if resident_opener_chirho.is_none() {
        cairn_ledger_host_chirho::refuse_test_kind_marked_host_config_chirho(ledger_host_chirho)?;
    }
    // #6096: the config root binding is CANONICAL target equality (never lexical) — equivalent
    // reviewed aliases accept, genuinely different targets refuse, both resolved pre-mutation.
    let canonical_selected_chirho = root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize selected root {}", root_chirho.display()))?;
    let canonical_config_root_chirho = std::path::Path::new(&config_chirho.root_chirho)
        .canonicalize()
        .with_context(|| format!("canonicalize config root {}", config_chirho.root_chirho))?;
    let config_root_bound_chirho = canonical_config_root_chirho == canonical_selected_chirho;

    // Freshness: refuse a root that already carries ledger substrate or a deployed app ref.
    refuse_non_fresh_root_chirho(root_chirho, ledger_host_chirho)?;

    // Plan authority: digest == supplied expected; dormant-finality precondition.
    let plan_bytes_chirho = std::fs::read(plan_path_chirho)
        .with_context(|| format!("read regenesis plan {}", plan_path_chirho.display()))?;
    let plan_chirho: LedgerRegenesisPlanV1Chirho =
        serde_json::from_slice(&plan_bytes_chirho).context("parse canonical regenesis plan")?;
    let canonical_plan_bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("canonicalize supplied plan: {error_chirho:?}"))?;
    if plan_bytes_chirho != canonical_plan_bytes_chirho {
        bail!("supplied plan bytes are not canonical; refusing to silently re-canonicalize");
    }
    let plan_digest_chirho = plan_digest_chirho(&canonical_plan_bytes_chirho);
    let plan_digest_matches_expected_chirho =
        plan_digest_chirho == inputs_chirho.expected_plan_digest_chirho;
    if !plan_digest_matches_expected_chirho {
        bail!("supplied plan digest did not match --expected-plan-digest-chirho");
    }
    if !config_root_bound_chirho {
        bail!("config root_chirho is not bound to the selected operator root");
    }
    let payer_chirho = plan_chirho.initial_owner_chirho.clone();
    let plan_initial_owner_chirho = plan_chirho.initial_owner_chirho.clone();
    let dormancy_chirho = assert_dormant_finality_chirho(&plan_chirho)?;

    // The billing kind must BE the plan kind — the priced effect and the minted kind are one (#6).
    let billing_kind_chirho = postgres_effect_chirho.billing_kind_chirho.clone();
    if billing_kind_chirho != plan_chirho.kind_id_chirho {
        bail!("config billing kind does not equal the plan kind");
    }

    // Payer member: EXACT-selected by the plan-bound principal on the billing kind — never
    // positional; duplicate or missing REFUSES (#6).
    let mut payer_members_chirho =
        ledger_host_chirho
            .members_chirho
            .iter()
            .filter(|member_chirho| {
                member_chirho.owner_chirho == payer_chirho
                    && member_chirho.kind_id_chirho == billing_kind_chirho
            });
    let config_payer_member_chirho = payer_members_chirho
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("config has no member for the plan initial_owner on the billing kind")
        })?
        .owner_chirho
        .clone();
    if payer_members_chirho.next().is_some() {
        bail!("duplicate config members for the plan initial_owner on the billing kind");
    }
    // Settlement member: the UNIQUE other member on the billing kind, and it must equal the plan
    // policy's settlement owner (the meter's credit destination is plan-bound, not positional).
    let mut settlement_members_chirho =
        ledger_host_chirho
            .members_chirho
            .iter()
            .filter(|member_chirho| {
                member_chirho.owner_chirho != payer_chirho
                    && member_chirho.kind_id_chirho == billing_kind_chirho
            });
    let settlement_owner_chirho = settlement_members_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("config has no settlement member on the billing kind"))?
        .owner_chirho
        .clone();
    if settlement_members_chirho.next().is_some() {
        bail!("config has multiple non-payer members on the billing kind (settlement ambiguous)");
    }
    match plan_chirho
        .amended_policy_chirho
        .settlement_owner_chirho
        .as_ref()
    {
        Some(policy_settlement_chirho) if policy_settlement_chirho == &settlement_owner_chirho => {}
        Some(_) => {
            bail!("config settlement member does not equal the plan policy settlement owner")
        }
        None => bail!(
            "plan amended policy names no settlement owner; the settlement meter cannot be bound"
        ),
    }

    // Payer identity: EXACT-selected from ONE verified identity load (#6048/#6049). This phase makes
    // no authoritative write, so a reviewed payer (C1 A3) is only prechecked here; setup registers it after
    // regenesis, beside the drawn owner, and selects it there the same way.
    let plan_payer_identity_chirho = match inputs_chirho.reviewed_payer_principal_chirho {
        Some(reviewed_payer_chirho) => {
            precheck_reviewed_payer_chirho(
                root_chirho,
                &payer_chirho,
                reviewed_payer_chirho,
                inputs_chirho.payer_credential_secret_name_chirho,
            )?;
            PlanPayerIdentityChirho::ReviewedPendingChirho(reviewed_payer_chirho)
        }
        None => PlanPayerIdentityChirho::SelectedChirho(select_plan_payer_identity_chirho(
            &identity_chirho::load_verified_identities_chirho(root_chirho)?,
            &payer_chirho,
        )?),
    };

    // Balance route: EXACT-selected by the protocol projection name — never positional (#6).
    let mut balance_routes_chirho =
        ledger_host_chirho
            .projection_routes_chirho
            .iter()
            .filter(|route_chirho| {
                route_chirho.projection_name_chirho
                    == constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO
            });
    let balance_head_path_chirho = balance_routes_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("config has no balance projection route"))?
        .head_path_chirho
        .clone();
    if balance_routes_chirho.next().is_some() {
        bail!("config has duplicate balance projection routes");
    }

    // Config authority: the DSN + adapter secrets resolve from the operator secret store (custody);
    // the counts are DERIVED from the actual config/protocol ref sets, never asserted (#3).
    let signer_refs_chirho = [
        ledger_host_chirho
            .signer_secrets_chirho
            .journal_chirho
            .as_str(),
        ledger_host_chirho
            .signer_secrets_chirho
            .config_chirho
            .as_str(),
        ledger_host_chirho
            .signer_secrets_chirho
            .feeder_chirho
            .as_str(),
        ledger_host_chirho
            .signer_secrets_chirho
            .kind_root_chirho
            .as_str(),
        ledger_host_chirho
            .signer_secrets_chirho
            .effect_intent_chirho
            .as_str(),
        ledger_host_chirho
            .signer_secrets_chirho
            .effect_terminal_chirho
            .as_str(),
    ];
    let mut distinct_signer_refs_chirho = std::collections::BTreeSet::new();
    for ref_chirho in signer_refs_chirho {
        if !distinct_signer_refs_chirho.insert(ref_chirho) {
            bail!("signer secret refs are not pairwise distinct");
        }
    }
    let provider_secret_refs_chirho = [
        postgres_effect_chirho.connection_secret_chirho.as_str(),
        constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
    ];
    let mut secret_ref_names_chirho: Vec<String> = signer_refs_chirho
        .iter()
        .map(|name_chirho| name_chirho.to_string())
        .collect();
    secret_ref_names_chirho.push(inputs_chirho.issuer_secret_name_chirho.to_string());
    secret_ref_names_chirho.push(
        inputs_chirho
            .payer_credential_secret_name_chirho
            .to_string(),
    );
    secret_ref_names_chirho.extend(
        provider_secret_refs_chirho
            .iter()
            .map(|name_chirho| name_chirho.to_string()),
    );

    // The complete documented authoring rail runs READ-ONLY against one immutable local-Cargo
    // closure before authoritative mutation. Review later consumes the exact node artifact bytes
    // that complete fixtures executed, so check/test/build/fixtures/emit/promotion cannot attest
    // different source or WASM bytes.
    let authoring_gate_chirho =
        preflight_authoring_gate_chirho(app_root_chirho, inputs_chirho.manifest_path_chirho)?;

    let dsn_chirho = resolve_secret_string_chirho(
        root_chirho,
        &postgres_effect_chirho.connection_secret_chirho,
    )
    .context("resolve configured LocalPhaseB DSN from the operator secret store")?;
    let external_preconditions_chirho =
        verify_external_preconditions_chirho(&dsn_chirho, root_chirho)?;
    let l2_spend_token_chirho = external_preconditions_chirho
        .l2_spend_concurrency_token_chirho
        .clone();

    // --- AUTHORITATIVE MUTATIONS (verify-before-mutate: regenesis fully validates the plan/config/
    // issuer coordinates FIRST; only then do we register the ephemeral control-plane owner) ---
    let receipt_chirho = run_ledger_regenesis_chirho(LedgerRegenesisH3aRequestChirho {
        selected_root_chirho: root_chirho,
        config_path_chirho,
        plan_path_chirho,
        expected_plan_digest_chirho: &plan_digest_chirho,
        issuer_secret_name_chirho: inputs_chirho.issuer_secret_name_chirho,
        activation_authorization_path_chirho: inputs_chirho.activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: inputs_chirho
            .expected_activation_authorization_digest_chirho,
    })
    .map_err(|error_chirho| anyhow::anyhow!("ledger regenesis refused: {error_chirho:?}"))?;
    if receipt_chirho.plan_digest_chirho != plan_digest_chirho {
        bail!("regenesis receipt plan digest did not bind the verified plan");
    }

    // #9: re-read the immutable H3 packet and require its canonical re-digest EQUAL the regenesis
    // receipt's packet digest (an equality, never a non-empty check), then bind its plan digest
    // and its balance account to the verified plan coordinates.
    let h3_packet_path_chirho = root_chirho
        .join(&ledger_host_chirho.monitor_evidence_namespace_chirho)
        .join(LEDGER_REGENESIS_EVIDENCE_PACKET_FILE_CHIRHO);
    let (packet_chirho, packet_digest_chirho) =
        load_canonical_ledger_regenesis_evidence_packet_chirho(&h3_packet_path_chirho)
            .context("re-read immutable H3 evidence packet")?;
    if packet_digest_chirho != receipt_chirho.packet_digest_chirho {
        bail!("H3 packet re-digest did not equal the regenesis receipt packet digest");
    }
    if packet_chirho.plan_digest_chirho != plan_digest_chirho {
        bail!("H3 packet plan digest did not bind the verified plan");
    }
    let h3_publication_manifest_path_chirho = root_chirho
        .join(&ledger_host_chirho.monitor_evidence_namespace_chirho)
        .join(LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO);
    let (publication_manifest_chirho, publication_manifest_digest_chirho) =
        load_canonical_ledger_regenesis_publication_manifest_chirho(
            &h3_publication_manifest_path_chirho,
        )
        .context("re-read H3 publication manifest")?;
    if publication_manifest_digest_chirho != receipt_chirho.publication_manifest_digest_chirho {
        bail!("H3 publication manifest re-digest did not equal the regenesis receipt");
    }
    if publication_manifest_chirho.plan_digest_chirho != plan_digest_chirho
        || publication_manifest_chirho.packet_digest_chirho != receipt_chirho.packet_digest_chirho
        || publication_manifest_chirho.publication_proof_chirho
            != receipt_chirho.publication_proof_chirho
    {
        bail!("H3 publication manifest did not bind the reviewed plan, packet, and resident proof");
    }
    let mut packet_balance_rows_chirho =
        packet_chirho
            .projections_chirho
            .iter()
            .filter(|row_chirho| {
                row_chirho.projection_name_chirho
                    == constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO
            });
    let packet_balance_row_chirho = packet_balance_rows_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("H3 packet has no balance projection evidence"))?;
    if packet_balance_rows_chirho.next().is_some() {
        bail!("H3 packet has duplicate balance projection evidence rows");
    }
    if packet_balance_row_chirho.account_chirho.owner_chirho != payer_chirho
        || packet_balance_row_chirho.account_chirho.kind_id_chirho.0 != billing_kind_chirho
    {
        bail!("H3 packet balance account does not bind the plan initial_owner on the billing kind");
    }

    // Retain the SIGNED pre-L2 regenesis-cut balance head at a distinct storage path BEFORE any
    // serving or writes. The packet-evidence parent later loads it through the signature-verifying
    // loader — a tampered copy fails the feeder signature, a replayed different genuine receipt
    // fails the full packet==receipt coordinate equality (#6050 placement disposition).
    let namespace_root_chirho = root_chirho.join(&ledger_host_chirho.storage_namespace_chirho);
    let head_bytes_chirho = std::fs::read(namespace_root_chirho.join(&balance_head_path_chirho))
        .context("read regenesis-cut published balance head")?;
    let retained_regenesis_head_path_chirho =
        "published/regenesis-cut-balance-head-chirho.json".to_string();
    let retained_abs_chirho = namespace_root_chirho.join(&retained_regenesis_head_path_chirho);
    if retained_abs_chirho.exists() {
        bail!("retained regenesis-cut head already exists on a fresh root");
    }
    std::fs::write(&retained_abs_chirho, &head_bytes_chirho)
        .context("retain regenesis-cut balance head")?;

    let identity_record_payer_chirho = match plan_payer_identity_chirho {
        PlanPayerIdentityChirho::SelectedChirho(identity_record_payer_chirho) => {
            identity_record_payer_chirho
        }
        PlanPayerIdentityChirho::ReviewedPendingChirho(reviewed_payer_chirho) => {
            register_reviewed_payer_chirho(
                root_chirho,
                &payer_chirho,
                reviewed_payer_chirho,
                inputs_chirho.payer_credential_secret_name_chirho,
            )?;
            select_plan_payer_identity_chirho(
                &identity_chirho::load_verified_identities_chirho(root_chirho)?,
                &payer_chirho,
            )?
        }
    };
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )?
    .principal_chirho;
    if owner_chirho == payer_chirho {
        bail!("control-plane owner collided with the account principal");
    }
    // The served arc authenticates through REAL scoped-token issuance (app bearer tokens are
    // scoped tokens by law — a raw login token can never pass the app routes): register the
    // owner-signed oauth client and resolve the payer credential for the wire's issuance calls.
    let payer_credential_chirho = resolve_secret_string_chirho(
        root_chirho,
        inputs_chirho.payer_credential_secret_name_chirho,
    )
    .context("resolve the payer credential from the operator secret store")?;
    let oauth_client_chirho = cairn_chirho::oauth_chirho::register_client_chirho(
        root_chirho,
        constants_chirho::APP_CHIRHO,
        &owner_chirho,
    )?;

    // H3 permanently latched the root into elected writer era. Reopen that exact resident authority
    // before crossing any app, route, or price head door; the authority-less wrappers are valid only
    // for never-latched roots and correctly refuse this post-regenesis phase.
    //
    // THE INJECTION POINT. `None` is the shipping posture and reaches the production door, which
    // carries the test-kind fence and hands NO compensation provider through — so a build that
    // passes nothing completes nothing. An injected opener composes the authority itself; this road
    // never learns which door it went through, which is exactly why no door symbol appears here.
    let resident_chirho = match resident_opener_chirho {
        Some(open_resident_chirho) => {
            open_resident_chirho(root_chirho, config_path_chirho, ledger_host_chirho)
                .context("open injected resident authority for credits-demo head transitions")?
        }
        None => cairn_ledger_host_chirho::open_resident_effect_journal_handle_chirho(
            root_chirho,
            config_path_chirho,
            ledger_host_chirho,
            None,
        )
        .context("open post-regenesis resident authority for credits-demo head transitions")?,
    };
    let head_transition_authority_chirho = resident_chirho.head_transition_authority_chirho();

    let authoring_chirho = author_and_review_first_chirho(AuthorAndReviewFirstInputChirho {
        root_chirho,
        app_root_chirho: authoring_gate_chirho.snapshot_root_chirho(),
        emit_bytes_chirho: &authoring_gate_chirho.emit_bytes_chirho,
        manifest_regenerated_and_matched_chirho: authoring_gate_chirho
            .manifest_regenerated_and_matched_chirho,
        prepared_inputs_chirho: &authoring_gate_chirho.prepared_inputs_chirho,
        authoring_gate_report_chirho: authoring_gate_chirho.report_chirho.clone(),
        owner_chirho: &owner_chirho,
        head_transition_authority_chirho,
    })?;

    cairn_chirho::effect_pricing_chirho::set_price_book_with_head_transition_authority_chirho(
        root_chirho,
        constants_chirho::APP_CHIRHO,
        &owner_chirho,
        None,
        std::collections::BTreeMap::from([(
            constants_chirho::POSTGRES_REVERSIBLE_EFFECT_CHIRHO.to_string(),
            constants_chirho::POSTGRES_REVERSIBLE_PRICE_CHIRHO,
        )]),
        0,
        head_transition_authority_chirho,
    )?;

    let authority_coordinates_chirho = AuthorityCoordinatesChirho {
        schema_chirho: AUTHORITY_COORDINATES_SCHEMA_CHIRHO,
        plan_chirho: PlanAuthorityChirho {
            plan_digest_chirho: plan_digest_chirho.clone(),
            plan_digest_matches_expected_chirho,
            issuer_secret_ref_name_chirho: inputs_chirho.issuer_secret_name_chirho.to_string(),
            issuer_binding_verified_chirho: true,
        },
        config_chirho: ConfigAuthorityChirho {
            config_digest_chirho,
            config_validated_chirho: true,
            config_root_bound_chirho,
            custody_verified_chirho,
            signer_secret_ref_count_chirho: signer_refs_chirho.len(),
            provider_secret_ref_count_chirho: provider_secret_refs_chirho.len(),
        },
        app_chirho: AppAuthorityChirho {
            source_review_report_chirho: authoring_chirho.source_review_report_chirho.clone(),
            reviewed_app_record_seq_chirho: authoring_chirho.reviewed_app_record_seq_chirho,
            reviewed_promote_review_seq_chirho: authoring_chirho.reviewed_promote_review_seq_chirho,
            accepted_capability_escalation_chirho: authoring_chirho
                .accepted_capability_escalation_chirho,
            accepted_cost_increase_chirho: authoring_chirho.accepted_cost_increase_chirho,
        },
    };

    Ok(CreditsDemoSetupChirho {
        root_chirho: root_chirho.to_path_buf(),
        config_path_chirho: config_path_chirho.to_path_buf(),
        expected_config_digest_chirho: inputs_chirho.expected_config_digest_chirho.to_owned(),
        app_root_chirho: app_root_chirho.to_path_buf(),
        payer_chirho,
        owner_chirho,
        settlement_owner_chirho,
        billing_kind_chirho,
        plan_mint_amount_chirho: plan_chirho.initial_mint_amount_chirho,
        config_payer_member_chirho,
        identity_record_payer_chirho,
        plan_initial_owner_chirho,
        storage_namespace_chirho: ledger_host_chirho.storage_namespace_chirho.clone(),
        journal_path_chirho: ledger_host_chirho.journal_path_chirho.clone(),
        balance_projection_name_chirho: constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO
            .to_string(),
        balance_head_path_chirho,
        retained_regenesis_head_path_chirho,
        h3_packet_path_chirho,
        h3_publication_manifest_path_chirho,
        dsn_chirho,
        payer_credential_chirho,
        oauth_client_id_chirho: oauth_client_chirho.client_id_chirho,
        secret_ref_names_chirho,
        plan_digest_chirho,
        regenesis_packet_digest_chirho: receipt_chirho.packet_digest_chirho,
        regenesis_publication_manifest_digest_chirho: receipt_chirho
            .publication_manifest_digest_chirho,
        l2_spend_token_chirho,
        dormancy_chirho,
        source_review_report_chirho: authoring_chirho.source_review_report_chirho.clone(),
        authoring_chirho,
        external_preconditions_chirho,
        authority_coordinates_chirho,
    })
}

fn refuse_non_fresh_root_chirho(
    root_chirho: &Path,
    ledger_host_chirho: &LedgerHostConfigChirho,
) -> Result<()> {
    if root_chirho
        .join(&ledger_host_chirho.storage_namespace_chirho)
        .exists()
    {
        bail!("operator root already carries ledger substrate; refusing to merge into a non-fresh root");
    }
    let refs_chirho = refs_chirho::load_refs_chirho(root_chirho)?;
    let app_branch_chirho =
        cairn_chirho::app_chirho::app_branch_ref_name_chirho(constants_chirho::APP_CHIRHO);
    if refs_chirho.branches_chirho.contains_key(&app_branch_chirho) {
        bail!(
            "operator root already has a deployed credits-demo app ref; refusing a non-fresh root"
        );
    }
    Ok(())
}

pub(super) fn assert_dormant_finality_chirho(
    plan_chirho: &LedgerRegenesisPlanV1Chirho,
) -> Result<DormancyPostureChirho> {
    let Some(window_chirho) = plan_chirho
        .amended_policy_chirho
        .idempotency_window_chirho
        .as_ref()
    else {
        bail!(
            "regenesis plan amended policy lacks an idempotency window; the dormant-finality seam \
             cannot be proven"
        );
    };
    let retry_finality_horizon_ms_chirho = window_chirho.retry_finality_horizon_ms_chirho;
    let mint_age_exceeds_horizon_chirho = now_ms_chirho()
        .checked_sub(plan_chirho.mint_physical_ms_chirho)
        .is_some_and(|age_chirho| age_chirho > retry_finality_horizon_ms_chirho);
    if !mint_age_exceeds_horizon_chirho {
        bail!(
            "regenesis plan mint is not dormant beyond the retry-finality horizon; a non-dormant \
             plan would settle trivially and cannot prove the committed-hlc finality seam"
        );
    }
    Ok(DormancyPostureChirho {
        schema_chirho: DORMANCY_POSTURE_SCHEMA_CHIRHO,
        idempotency_window_present_chirho: true,
        retry_finality_horizon_ms_chirho,
        mint_age_exceeds_horizon_chirho,
        dormant_beyond_horizon_chirho: true,
    })
}

/// Verify (never establish) the operator-direct external preconditions: ALL three reversible
/// tables present, the seed row present with the sealed value, and its keyed before-state
/// fingerprint RECOMPUTED under the CONFIGURED operator adapter key (#6046 — the recomputed value
/// is recorded and becomes the L2 concurrency token; no constant expectation exists on this path,
/// so custody stays real and key rotation keeps working). The R4b distinct token is DERIVED from
/// that actual fingerprint with an explicit distinctness check.
pub(super) fn verify_external_preconditions_chirho(
    dsn_chirho: &str,
    root_chirho: &Path,
) -> Result<ExternalPreconditionsChirho> {
    let concurrency_token_chirho =
        read_credits_demo_concurrency_token_from_dsn_chirho(dsn_chirho, root_chirho)?;
    let mut client_chirho = connect_pg_chirho(dsn_chirho)?;
    // Fresh-provider preflight (#6058): the outcome tables must be EMPTY, so the verified rows
    // counted at the end of the arc are THIS arc's (emptiness cannot be forged into existence).
    for (table_chirho, label_chirho) in [
        (
            "cairn_reversible_forward_decisions_chirho",
            "forward decisions",
        ),
        (
            "cairn_reversible_comp_receipts_chirho",
            "compensation receipts",
        ),
    ] {
        let count_chirho: i64 = client_chirho
            .query_one(&format!("SELECT count(*)::bigint FROM {table_chirho}"), &[])
            .with_context(|| format!("preflight {label_chirho} emptiness"))?
            .get(0);
        if count_chirho != 0 {
            bail!("operator-established provider {label_chirho} table is not empty ({count_chirho} rows)");
        }
    }
    let r4b_distinct_token_chirho = derive_r4b_distinct_token_chirho(&concurrency_token_chirho)?;

    Ok(ExternalPreconditionsChirho {
        schema_chirho: EXTERNAL_PRECONDITIONS_SCHEMA_CHIRHO,
        operator_established_chirho: true,
        cairn_minted_chirho: false,
        pg_schema_installed_chirho: true,
        pg_tables_chirho: constants_chirho::REVERSIBLE_TABLES_CHIRHO.to_vec(),
        seed_subject_chirho: constants_chirho::FIXED_SUBJECT_CHIRHO.to_string(),
        seed_row_key_chirho: constants_chirho::FIXED_ROW_KEY_CHIRHO.to_string(),
        seed_value_utf8_chirho: String::from_utf8_lossy(constants_chirho::SEED_VALUE_CHIRHO)
            .to_string(),
        seed_before_state_fingerprint_chirho: concurrency_token_chirho.clone(),
        l2_spend_concurrency_token_chirho: concurrency_token_chirho,
        l2_token_bound_to_seed_fingerprint_chirho: true,
        r4b_distinct_token_chirho,
    })
}

/// Derive the R4b distinct-K token from the ACTUAL recorded fingerprint by flipping its first hex
/// character — a guaranteed-distinct valid 64-hex value under ANY operator key (self-maintaining
/// across key rotation), with an explicit distinctness check (#6046/#6047: never assume a constant
/// differs from every real key's fingerprint).
pub(super) fn derive_r4b_distinct_token_chirho(fingerprint_hex_chirho: &str) -> Result<String> {
    if fingerprint_hex_chirho.len() != 64
        || !fingerprint_hex_chirho
            .chars()
            .all(|char_chirho| char_chirho.is_ascii_hexdigit())
    {
        bail!("recorded seed fingerprint is not a 64-hex value");
    }
    let flipped_chirho = if fingerprint_hex_chirho.starts_with('0') {
        '1'
    } else {
        '0'
    };
    let token_chirho = format!("{flipped_chirho}{}", &fingerprint_hex_chirho[1..]);
    if token_chirho == fingerprint_hex_chirho {
        bail!("derived R4b token equals the L2 concurrency token (distinctness violated)");
    }
    Ok(token_chirho)
}

pub(super) fn resolve_secret_string_chirho(
    root_chirho: &Path,
    name_chirho: &str,
) -> Result<String> {
    let secret_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(name_chirho)?,
    )?;
    String::from_utf8(secret_chirho.as_bytes_chirho().to_vec())
        .context("configured DSN secret was not valid UTF-8")
}

struct AuthorAndReviewFirstInputChirho<'a> {
    root_chirho: &'a Path,
    app_root_chirho: &'a Path,
    emit_bytes_chirho: &'a [u8],
    manifest_regenerated_and_matched_chirho: Option<bool>,
    prepared_inputs_chirho: &'a app_source_manifest_chirho::AppSourcePreparedInputsChirho,
    authoring_gate_report_chirho: AuthoringGateReportChirho,
    owner_chirho: &'a str,
    head_transition_authority_chirho: &'a dyn HeadTransitionAuthorityPortChirho,
}

fn author_and_review_first_chirho(
    input_chirho: AuthorAndReviewFirstInputChirho<'_>,
) -> Result<AuthoringProvenanceChirho> {
    let AuthorAndReviewFirstInputChirho {
        root_chirho,
        app_root_chirho,
        emit_bytes_chirho,
        manifest_regenerated_and_matched_chirho,
        prepared_inputs_chirho,
        authoring_gate_report_chirho,
        owner_chirho,
        head_transition_authority_chirho,
    } = input_chirho;

    // The write phase consumes the preflight-PREPARED byte set (#6090): zero filesystem reads for
    // path-backed inputs here — the preflight→write TOCTOU is structurally closed.
    let review_report_chirho =
        app_source_manifest_chirho::build_app_source_review_from_prepared_bytes_for_owner_chirho(
            root_chirho,
            emit_bytes_chirho,
            app_root_chirho,
            owner_chirho,
            prepared_inputs_chirho,
        )?;
    if review_report_chirho.candidate_chirho.app_chirho != constants_chirho::APP_CHIRHO {
        bail!(
            "credits-demo manifest app changed to '{}'",
            review_report_chirho.candidate_chirho.app_chirho
        );
    }
    let source_manifest_chirho = review_report_chirho
        .candidate_chirho
        .source_manifest_chirho
        .clone()
        .ok_or_else(|| anyhow::anyhow!("review candidate lacked source manifest evidence"))?;
    let raw_manifest_hash_chirho = source_manifest_chirho
        .raw_manifest_hash_chirho
        .clone()
        .ok_or_else(|| anyhow::anyhow!("review candidate lacked a raw manifest hash"))?;
    if raw_manifest_hash_chirho != cas_chirho::hash_chirho(emit_bytes_chirho) {
        bail!("recorded raw manifest hash did not bind the emitted bytes");
    }
    let source_review_report_chirho = review_report_chirho
        .source_review_report_chirho
        .clone()
        .ok_or_else(|| anyhow::anyhow!("review report was not content-addressed"))?;
    // #12/#6100 (re-ruled on source, money/model concurred): the compensation authority's plan
    // digest is the SELECTED reviewed UNDO-PLAN digest — a distinct authority coordinate from the
    // regenesis plan. The reviewed candidate carries one binding per executable DAG; the packet
    // closes L4 by membership in this reviewed set while the authority itself verifies the unique
    // eligible selection internally.
    let undo_bindings_chirho = review_report_chirho
        .candidate_chirho
        .undo_plan_bindings_chirho
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("reviewed candidate carries no undo-plan bindings"))?;
    if undo_bindings_chirho.is_empty() {
        bail!("reviewed candidate carries an empty undo-plan binding set");
    }
    let reviewed_undo_plan_digests_chirho: Vec<HashChirho> = undo_bindings_chirho
        .iter()
        .map(|binding_chirho| binding_chirho.plan_digest_chirho.clone())
        .collect();
    // #6101 (b): INDEPENDENTLY re-select the eligible undo binding — the spend route's dag from
    // the reviewed candidate (exact, unique), then the one binding on that dag — so the packet
    // check is five-way-style independent sourcing, never preview self-equality.
    let mut spend_routes_chirho = review_report_chirho
        .candidate_chirho
        .routes_chirho
        .iter()
        .filter(|route_chirho| route_chirho.route_chirho == constants_chirho::SPEND_ROUTE_CHIRHO);
    let spend_route_chirho = spend_routes_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("reviewed candidate has no spend route"))?;
    if spend_routes_chirho.next().is_some() {
        bail!("reviewed candidate has duplicate spend routes");
    }
    let mut spend_bindings_chirho = undo_bindings_chirho
        .iter()
        .filter(|binding_chirho| binding_chirho.dag_chirho == spend_route_chirho.dag_chirho);
    let selected_undo_plan_digest_chirho = spend_bindings_chirho
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("reviewed candidate has no undo-plan binding for the spend route dag")
        })?
        .plan_digest_chirho
        .clone();
    if spend_bindings_chirho.next().is_some() {
        bail!("reviewed candidate has duplicate undo-plan bindings for the spend route dag");
    }
    let candidate_root_dag_chirho = review_report_chirho
        .candidate_chirho
        .root_dag_chirho
        .clone();
    // The owner substituted into the EFFECTIVE reviewed manifest (from the verified review candidate,
    // not the raw --owner input) must equal the app's control-plane owner.
    let reviewed_owner_substitution_chirho =
        review_report_chirho.candidate_chirho.owner_chirho.clone();
    let owner_matches_control_plane_owner_chirho =
        reviewed_owner_substitution_chirho == owner_chirho;
    if !owner_matches_control_plane_owner_chirho {
        bail!("effective reviewed manifest owner did not match the control-plane owner");
    }

    // Derive each acceptance from the VERIFIED absent-app review diff — never sign an acceptance
    // disconnected from the diff it acknowledges.
    let accept_capability_escalation_chirho = !review_report_chirho
        .review_chirho
        .added_capabilities_chirho
        .is_empty();
    let accept_cost_increase_chirho =
        review_report_chirho.review_chirho.cost_delta_token_chirho > 0;
    // Fresh roots persist the bounded review locator BEFORE promotion. Older consumed roots use
    // the one-time explicit pin command; neither path scans CAS to rediscover this coordinate.
    continuation_chirho::persist_reviewed_candidate_pointer_chirho(
        root_chirho,
        &source_review_report_chirho,
    )?;
    let promotion_chirho =
        review_chirho::promote_candidate_with_review_evidence_and_head_transition_authority_chirho(
            root_chirho,
            review_chirho::PromoteCandidateReviewEvidenceInputChirho {
                app_chirho: constants_chirho::APP_CHIRHO,
                owner_principal_chirho: owner_chirho,
                candidate_chirho: candidate_root_dag_chirho.clone(),
                accept_capability_escalation_chirho,
                accept_cost_increase_chirho,
                require_review_policy_envelope_chirho: false,
                source_evidence_chirho: review_chirho::ReviewSourceEvidenceChirho {
                    source_review_report_chirho: Some(source_review_report_chirho.clone()),
                    source_manifest_chirho: Some(
                        review_chirho::ReviewSourceManifestEvidenceChirho {
                            effective_manifest_hash_chirho: source_manifest_chirho
                                .effective_manifest_hash_chirho
                                .clone(),
                            raw_manifest_hash_chirho: Some(raw_manifest_hash_chirho.clone()),
                        },
                    ),
                },
            },
            head_transition_authority_chirho,
        )?;
    let review_for_install_chirho =
        app_source_manifest_chirho::load_app_source_review_report_for_promotion_chirho(
            root_chirho,
            constants_chirho::APP_CHIRHO,
            owner_chirho,
            &source_review_report_chirho,
            Some(&candidate_root_dag_chirho),
        )?;
    app_source_manifest_chirho::install_reviewed_app_source_report_with_head_transition_authority_chirho(
        root_chirho,
        owner_chirho,
        &review_for_install_chirho,
        head_transition_authority_chirho,
    )?;

    // The signed promotion must acknowledge exactly the derived diff decisions, and it must carry a
    // verified APP-RECORD (Deploy) binding — a missing Deploy seq is an authority failure.
    if promotion_chirho.accepted_capability_escalation_chirho != accept_capability_escalation_chirho
        || promotion_chirho.accepted_cost_increase_chirho != accept_cost_increase_chirho
    {
        bail!("signed promotion acceptances did not match the derived review-diff decisions");
    }
    let reviewed_app_record_seq_chirho = promotion_chirho
        .app_record_seq_chirho
        .ok_or_else(|| anyhow::anyhow!("promotion lacked a verified app-record (Deploy) seq"))?;
    let reviewed_promote_review_seq_chirho = promotion_chirho.seq_chirho;

    Ok(AuthoringProvenanceChirho {
        schema_chirho: AUTHORING_PROVENANCE_SCHEMA_CHIRHO,
        app_chirho: constants_chirho::APP_CHIRHO.to_string(),
        emitted_not_accepted_chirho: true,
        manifest_regenerated_and_matched_chirho,
        authoring_gate_chirho: authoring_gate_report_chirho,
        raw_manifest_hash_chirho,
        effective_manifest_hash_chirho: source_manifest_chirho.effective_manifest_hash_chirho,
        candidate_root_dag_chirho,
        source_review_report_chirho: source_review_report_chirho.0,
        reviewed_owner_substitution_chirho,
        owner_matches_control_plane_owner_chirho,
        reviewed_app_record_seq_chirho,
        reviewed_promote_review_seq_chirho,
        reviewed_undo_plan_digests_chirho,
        reviewed_selected_undo_plan_digest_chirho: selected_undo_plan_digest_chirho,
        accepted_capability_escalation_chirho: promotion_chirho
            .accepted_capability_escalation_chirho,
        accepted_cost_increase_chirho: promotion_chirho.accepted_cost_increase_chirho,
        cost_delta_token_chirho: promotion_chirho.diff_chirho.cost_delta_token_chirho,
    })
}

/// Count rows currently present in the external `cairn_reversible_values_chirho` table.
pub fn pg_values_row_count_chirho(dsn_chirho: &str) -> Result<i64> {
    let mut client_chirho = connect_pg_chirho(dsn_chirho)?;
    let row_chirho = client_chirho
        .query_one(
            "SELECT count(*)::bigint FROM cairn_reversible_values_chirho",
            &[],
        )
        .context("count reversible values")?;
    Ok(row_chirho.get::<_, i64>(0))
}

/// Count compensation receipts recorded in the external `cairn_reversible_comp_receipts_chirho`.
pub fn pg_comp_receipt_count_chirho(dsn_chirho: &str) -> Result<i64> {
    let mut client_chirho = connect_pg_chirho(dsn_chirho)?;
    let row_chirho = client_chirho
        .query_one(
            "SELECT count(*)::bigint FROM cairn_reversible_comp_receipts_chirho",
            &[],
        )
        .context("count reversible compensation receipts")?;
    Ok(row_chirho.get::<_, i64>(0))
}

#[cfg(test)]
mod e1e_early_refusal_tests_chirho {
    use super::*;
    use cairn_chirho::config_chirho::{
        serialize_config_chirho, ConfigChirho, LedgerHostConfigChirho,
        LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
        LedgerHostPostgresEffectConfigChirho, LedgerHostPostgresEffectPostureChirho,
        LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
        LedgerHostTestKindMarkerConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
        LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
    };
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    fn marked_config_chirho(root_chirho: &Path) -> String {
        serialize_config_chirho(&ConfigChirho {
            root_chirho: root_chirho.display().to_string(),
            ledger_host_chirho: Some(LedgerHostConfigChirho {
                schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO.to_owned(),
                storage_namespace_chirho: "ledger-substrate-chirho".to_owned(),
                monitor_evidence_namespace_chirho: "monitor-chirho".to_owned(),
                monitor_evidence_path_chirho: "monitor/cycles-chirho.jsonl".to_owned(),
                money_group_id_chirho: "money-group-chirho".to_owned(),
                cluster_id_chirho: "cluster-chirho".to_owned(),
                journal_path_chirho: "journals/main-chirho.jsonl".to_owned(),
                local_epoch_chirho: 1,
                members_chirho: vec![LedgerHostMemberConfigChirho {
                    owner_chirho: "test-owner-chirho".to_owned(),
                    kind_id_chirho: "drill-credits-chirho".to_owned(),
                }],
                kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
                kind_registry_id_chirho: "kind-registry-chirho".to_owned(),
                kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
                    principal_chirho: "test-kind-chirho-item6-drill-issuer-chirho".to_owned(),
                    verifying_key_hex_chirho: "11".repeat(32),
                },
                activation_authority_chirho: None,
                projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
                projection_registry_id_chirho: "projection-registry-chirho".to_owned(),
                source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
                source_registry_id_chirho: "source-registry-chirho".to_owned(),
                projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
                    projection_name_chirho: "balance-chirho".to_owned(),
                    head_path_chirho: "published/balance-head-chirho.json".to_owned(),
                }],
                signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
                    journal_chirho: "journal-secret-chirho".to_owned(),
                    config_chirho: "config-secret-chirho".to_owned(),
                    feeder_chirho: "feeder-secret-chirho".to_owned(),
                    kind_root_chirho: "kind-root-secret-chirho".to_owned(),
                    effect_intent_chirho: "effect-intent-secret-chirho".to_owned(),
                    effect_terminal_chirho: "effect-terminal-secret-chirho".to_owned(),
                },
                held_verifier_pins_chirho: None,
                migration_destination_authority_chirho: None,
                monitor_cadence_ms_chirho: 5_000,
                postgres_effect_chirho: Some(LedgerHostPostgresEffectConfigChirho {
                    schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
                    posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
                    connection_secret_chirho: "dsn-secret-chirho".to_owned(),
                    billing_kind_chirho: "drill-credits-chirho".to_owned(),
                }),
                control_plane_chirho: None,
                test_kind_chirho: Some(LedgerHostTestKindMarkerConfigChirho {
                    schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
                    // A CF8 drill root keeps the mandatory loss-witness posture (postgres-backed).
                    loss_witness_exempt_chirho: false,
                }),
                adopt_migrated_root_chirho: false,
            }),
            ..ConfigChirho::default()
        })
        .expect("serialize marked test-kind fixture config")
    }

    fn root_bytes_chirho(root_chirho: &Path) -> BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(root_chirho)
            .expect("read fixture root")
            .map(|entry_result_chirho| {
                let entry_chirho = entry_result_chirho.expect("read fixture entry");
                let path_chirho = entry_chirho.path();
                let bytes_chirho = if path_chirho.is_dir() {
                    b"<directory-entry-chirho>".to_vec()
                } else {
                    std::fs::read(&path_chirho).expect("read fixture entry bytes")
                };
                (
                    entry_chirho.file_name().to_string_lossy().into_owned(),
                    bytes_chirho,
                )
            })
            .collect()
    }

    /// A custody-clean root carrying ONLY the test-kind-marked config. Both arms below use it, so
    /// the injected/not-injected pair differs in exactly one variable: the opener.
    fn marked_fixture_root_chirho(label_chirho: &str) -> (PathBuf, PathBuf) {
        let root_chirho = std::env::temp_dir().join(format!(
            "cairn-e1e-{label_chirho}-{}-chirho",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).expect("create refusal root");
        let config_path_chirho = root_chirho.join("ledger-host-config-chirho.toml");
        std::fs::write(&config_path_chirho, marked_config_chirho(&root_chirho))
            .expect("write marked config");
        let mut permissions_chirho = std::fs::metadata(&config_path_chirho)
            .expect("read config metadata")
            .permissions();
        permissions_chirho.set_mode(0o600);
        std::fs::set_permissions(&config_path_chirho, permissions_chirho)
            .expect("set config custody mode");
        (root_chirho, config_path_chirho)
    }

    fn marked_inputs_chirho<'fixture_chirho>(
        root_chirho: &'fixture_chirho Path,
        config_path_chirho: &'fixture_chirho Path,
        expected_config_digest_chirho: &'fixture_chirho str,
        missing_plan_chirho: &'fixture_chirho Path,
        missing_activation_chirho: &'fixture_chirho Path,
        app_root_chirho: &'fixture_chirho Path,
    ) -> CreditsDemoSmokeInputsChirho<'fixture_chirho> {
        CreditsDemoSmokeInputsChirho {
            root_chirho,
            config_path_chirho,
            expected_config_digest_chirho,
            plan_path_chirho: missing_plan_chirho,
            expected_plan_digest_chirho: "expected-plan-chirho",
            issuer_secret_name_chirho: "issuer-secret-chirho",
            activation_authorization_path_chirho: missing_activation_chirho,
            expected_activation_authorization_digest_chirho: "activation-digest-chirho",
            payer_credential_secret_name_chirho: "payer-secret-chirho",
            app_root_chirho,
            manifest_path_chirho: None,
            reviewed_payer_principal_chirho: None,
        }
    }

    #[test]
    fn marked_setup_refuses_before_mutation_without_postgres_chirho() {
        let (root_chirho, config_path_chirho) = marked_fixture_root_chirho("early-refusal");
        let missing_plan_chirho = root_chirho.join("missing-plan-chirho.json");
        let missing_activation_chirho = root_chirho.join("missing-activation-chirho");
        let app_root_chirho = root_chirho.join("app-chirho");
        let expected_config_digest_chirho = cas_chirho::hash_chirho(
            &std::fs::read(&config_path_chirho).expect("read marked config"),
        )
        .0;
        let before_chirho = root_bytes_chirho(&root_chirho);
        let result_chirho = run_credits_demo_setup_chirho(
            &marked_inputs_chirho(
                &root_chirho,
                &config_path_chirho,
                &expected_config_digest_chirho,
                &missing_plan_chirho,
                &missing_activation_chirho,
                &app_root_chirho,
            ),
            None,
        );
        let error_chirho = match result_chirho {
            Ok(_) => panic!("marked setup must refuse before any database-dependent success path"),
            Err(error_chirho) => error_chirho,
        };
        assert!(error_chirho.to_string().contains(
            cairn_ledger_host_chirho::TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO
        ));
        // This fixture's root has no subdirectories, so the non-recursive snapshot and addition-only
        // control are sufficient; a populated root would require recursive and modification controls.
        // Non-attributing safety net: this minimal fixture cannot reach a mutation without a
        // plan, so the fence's causal proof is the refusal identity assertion above. This snapshot
        // still detects any unexpected pre-refusal write and is intentionally not claimed as proof
        // that the fence itself prevented a later mutation.
        assert_eq!(before_chirho, root_bytes_chirho(&root_chirho));
        std::fs::write(
            root_chirho.join("positive-control-mutation-chirho"),
            b"mutation",
        )
        .expect("write positive-control mutation");
        assert_ne!(before_chirho, root_bytes_chirho(&root_chirho));
        std::fs::remove_dir_all(&root_chirho).expect("remove refusal root");
    }

    /// E1-e-2, the ADMITTING half: an injected opener carries a test-kind-marked config PAST the
    /// early fence. Differential against the arm above on exactly one variable — the same root, the
    /// same marked config, the same inputs, `Some(..)` instead of `None`.
    ///
    /// ASSERT THE REASON, both directions. The refusal identity must NOT be the test-kind refusal
    /// (the fence did not fire) and MUST be the next gate this fixture legitimately fails
    /// (`read regenesis plan` — the plan file does not exist). Asserting only the absence would pass
    /// for any error at all, including a fence that moved somewhere earlier and refused for a
    /// different reason.
    ///
    /// HONEST SCOPE, so this is not read wider than it is: this arm proves the fence ADMITS, and
    /// nothing more. The injected opener is deliberately a panicking closure and is deliberately
    /// NEVER reached — this fixture cannot get past the missing plan to the resident-authority seam.
    /// That the seam DISPATCHES to the injected opener is a separate claim, proven on the full road
    /// by `injected_resident_opener_is_the_one_the_seeding_road_opens_chirho`, and the door that the
    /// test-kind opener reaches is proven in `cairn-ledger-geo-node-testkind-chirho`.
    #[test]
    fn injected_opener_admits_a_marked_config_past_the_early_fence_chirho() {
        let (root_chirho, config_path_chirho) = marked_fixture_root_chirho("injected-admit");
        let missing_plan_chirho = root_chirho.join("missing-plan-chirho.json");
        let missing_activation_chirho = root_chirho.join("missing-activation-chirho");
        let app_root_chirho = root_chirho.join("app-chirho");
        let expected_config_digest_chirho = cas_chirho::hash_chirho(
            &std::fs::read(&config_path_chirho).expect("read marked config"),
        )
        .0;

        let never_reached_opener_chirho =
            |_root_chirho: &Path,
             _config_path_chirho: &Path,
             _config_chirho: &LedgerHostConfigChirho| {
                panic!(
                "the injected opener must not be reached: this fixture has no plan, so the road \
                 cannot lawfully arrive at the resident-authority seam"
            )
            };
        let result_chirho = run_credits_demo_setup_chirho(
            &marked_inputs_chirho(
                &root_chirho,
                &config_path_chirho,
                &expected_config_digest_chirho,
                &missing_plan_chirho,
                &missing_activation_chirho,
                &app_root_chirho,
            ),
            Some(&never_reached_opener_chirho),
        );
        let error_chirho = match result_chirho {
            Ok(_) => panic!("this fixture has no plan; the injected road must still fail"),
            Err(error_chirho) => error_chirho,
        };
        let rendered_chirho = format!("{error_chirho:#}");
        assert!(
            !rendered_chirho.contains(
                cairn_ledger_host_chirho::TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO
            ),
            "an injected opener must admit a test-kind-marked config past the early fence; the \
             fence still fired: {rendered_chirho}"
        );
        assert!(
            rendered_chirho.contains("read regenesis plan"),
            "the injected road must proceed to the next gate (the missing plan). If this now names \
             a DIFFERENT gate, read it before editing: an EARLIER gate means something started \
             refusing ahead of the plan read, a LATER one means this fixture reached further than \
             it can lawfully go. Got: {rendered_chirho}"
        );
        std::fs::remove_dir_all(&root_chirho).expect("remove injected-admit root");
    }
}
