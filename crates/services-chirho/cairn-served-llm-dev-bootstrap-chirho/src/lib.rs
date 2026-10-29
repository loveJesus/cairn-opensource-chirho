// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Dev-only bootstrap that funds a payer on a synthetic file-backed local ledger host by driving the
//! single-node regenesis genesis+mint (Option 1), so the served-LLM card's Hold can succeed at a
//! local product-door root.
//!
//! MINT-TO-PAYER: the reviewed regenesis flow mints `--amount` of `--billing-kind` DIRECTLY to the
//! payer (`plan.initial_owner_chirho = payer`), exactly as the shipping credits-demo setup does —
//! there is no separate transfer, so this brick reconstructs no elected-writer authority and hand-
//! rolls no money-authority view. The settlement owner (`--owner-principal`) is a distinct config
//! member equal to the amended kind policy's settlement owner, ready to receive the served-LLM
//! per-draft price later. Every money check lives in the proven regenesis code and fails closed.
//!
//! DEV ONLY: the authored config always carries the test-kind marker, and [`refuse_production_posture_chirho`]
//! refuses any config that is not test-kind before the money operation, so this tool can never
//! bootstrap a real production ledger. Because the ledger is test-kind, a later serving brick must
//! open its resident authority through a TEST-KIND opener (the drill pattern) — the shipping resident
//! door refuses test-kind configs.

use anyhow::{bail, Context, Result};
use cairn_config_chirho::config_chirho::{
    serialize_config_chirho, ConfigChirho, LedgerHostActivationPinConfigChirho,
    LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
    LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
    LedgerHostTestKindMarkerConfigChirho, LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO,
    LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_regenesis_chirho::{
    author_ledger_regenesis_activation_chirho, canonical_plan_bytes_chirho, plan_digest_chirho,
    run_ledger_regenesis_chirho, LedgerRegenesisActivationAuthorRequestChirho,
    LedgerRegenesisH3aRequestChirho, LedgerRegenesisPlanV1Chirho,
    LedgerRegenesisProjectionRoutePlanChirho, LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

/// The stable refusal token the dev/production posture gate emits. Tests and callers match on THIS,
/// not on prose, so the refusal identity survives a wording change.
pub const SERVED_LLM_DEV_BOOTSTRAP_PRODUCTION_REFUSAL_CHIRHO: &str =
    "ServedLlmDevBootstrapProductionRefusedChirho";

pub const SERVED_LLM_DEV_BOOTSTRAP_REPORT_SCHEMA_V1_CHIRHO: &str =
    "served-llm-dev-bootstrap-report-v1-chirho";

// ---------------------------------------------------------------------------------------------------
// Fixed synthetic-root coordinates. A dev bootstrap owns its whole layout; only the payer, settlement
// owner, amount, and billing kind vary. These mirror the shipping regenesis fixture so the published
// root is H2-openable and conserved.
// ---------------------------------------------------------------------------------------------------

const FRESH_PARENT_CHIRHO: &str = "fresh-ledger-parent-chirho";
const STAGING_PARENT_CHIRHO: &str = "fresh-ledger-staging-chirho";
const STORAGE_NAMESPACE_CHIRHO: &str = "fresh-ledger-parent-chirho/ledger-chirho";
const MONITOR_EVIDENCE_NAMESPACE_CHIRHO: &str = "fresh-ledger-parent-chirho/ops-chirho";
const MONITOR_EVIDENCE_PATH_CHIRHO: &str = "monitor/cycles-chirho.jsonl";
const MONEY_GROUP_ID_CHIRHO: &str = "money-group-local-chirho";
const CLUSTER_ID_CHIRHO: &str = "cluster-local-chirho";
const JOURNAL_PATH_CHIRHO: &str = "journals/main-chirho.jsonl";
const LOCAL_EPOCH_CHIRHO: u64 = 1;
const KIND_REGISTRY_PATH_CHIRHO: &str = "registries/kinds-chirho.jsonl";
const KIND_REGISTRY_ID_CHIRHO: &str = "kind-registry-local-chirho";
const PROJECTION_REGISTRY_PATH_CHIRHO: &str = "registries/projections-chirho.jsonl";
const PROJECTION_REGISTRY_ID_CHIRHO: &str = "projection-registry-local-chirho";
const SOURCE_REGISTRY_PATH_CHIRHO: &str = "registries/sources-chirho.jsonl";
const SOURCE_REGISTRY_ID_CHIRHO: &str = "source-registry-local-chirho";
const BALANCE_PROJECTION_NAME_CHIRHO: &str = "balance-chirho";
const BALANCE_HEAD_PATH_CHIRHO: &str = "published/balance-head-chirho.json";
const MONITOR_CADENCE_MS_CHIRHO: u64 = 5_000;
const GENESIS_PHYSICAL_MS_CHIRHO: u64 = 1_000;
const MINT_PHYSICAL_MS_CHIRHO: u64 = 1_100;
const IDEMPOTENCY_HORIZON_MS_CHIRHO: u64 = 86_400_000;
const RETRY_FINALITY_HORIZON_MS_CHIRHO: u64 = 86_400_000;
const POLICY_UNIT_CHIRHO: &str = "credit-minor-chirho";
const POLICY_SHARD_ATTACHMENT_CHIRHO: &str = "shard-local-chirho";

/// The kind issuer principal. It MUST carry the reserved test-kind prefix, because the config's
/// test-kind marker and this prefix are mutually-required laws in `validate_chirho`.
const KIND_ISSUER_PRINCIPAL_SUFFIX_CHIRHO: &str = "llm-dev-issuer-chirho";
const ACTIVATION_PRINCIPAL_CHIRHO: &str = "ledger-activation-local-chirho";

// The operator-authored artifact file names, all created under the selected root at mode 0600.
/// The ledger config the bootstrap writes into the root it prepares; the dev served-LLM example
/// reads it from here by default.
pub const SERVED_LLM_DEV_CONFIG_FILE_CHIRHO: &str = "served-llm-dev-config-chirho.toml";
const PLAN_FILE_CHIRHO: &str = "served-llm-dev-plan-chirho.json";
const ACTIVATION_FILE_CHIRHO: &str = "served-llm-dev-activation-chirho.json";

// Secret-store names for the six runtime signers plus the two offline authorities. Values never
// leave this crate; they are synthetic dev seeds, safe only because the ledger is test-kind and
// custody derives every pin from the secret rather than trusting a flag.
const ISSUER_SECRET_NAME_CHIRHO: &str = "offline-kind-issuer-chirho";
const ACTIVATION_SECRET_NAME_CHIRHO: &str = "offline-ledger-activation-chirho";
const RUNTIME_SIGNER_SECRET_NAMES_CHIRHO: [&str; 6] = [
    "ledger-journal-secret-chirho",
    "ledger-config-secret-chirho",
    "ledger-feeder-secret-chirho",
    "ledger-kind-root-secret-chirho",
    "ledger-effect-intent-secret-chirho",
    "ledger-effect-terminal-secret-chirho",
];

/// Operator inputs. Every money and identity coordinate is a flag; storage layout is fixed above.
pub struct ServedLlmDevBootstrapRequestChirho<'request_chirho> {
    pub root_chirho: &'request_chirho Path,
    /// The account the mint credits (`plan.initial_owner_chirho`) and a config member on the billing
    /// kind. For the served-LLM Hold to charge this payer later, this should be the same identity
    /// principal the serving brick authenticates as (that brick registers it; this brick only funds
    /// the account).
    pub payer_principal_chirho: &'request_chirho str,
    /// The settlement owner (`amended_policy.settlement_owner_chirho`) and the other config member on
    /// the billing kind — the served-LLM per-draft price's credit destination.
    pub owner_principal_chirho: &'request_chirho str,
    pub amount_chirho: u64,
    pub billing_kind_chirho: &'request_chirho str,
}

/// What one bootstrap produced. All fields are non-secret coordinates; no key bytes are representable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ServedLlmDevBootstrapReportChirho {
    pub schema_chirho: &'static str,
    pub payer_principal_chirho: String,
    pub settlement_owner_principal_chirho: String,
    pub billing_kind_chirho: String,
    pub amount_chirho: u64,
    pub test_kind_marked_chirho: bool,
    pub config_file_chirho: String,
    pub plan_digest_chirho: String,
    pub packet_digest_chirho: String,
    pub publication_manifest_digest_chirho: String,
    pub final_parent_name_chirho: String,
    pub storage_namespace_chirho: String,
    pub journal_path_chirho: String,
    pub balance_projection_name_chirho: String,
    pub balance_head_path_chirho: String,
}

/// The dev/production posture gate: refuse any host config that is not test-kind marked, so this
/// bootstrap can never take money authority into a production ledger. Called before the money
/// operation; the inverse of the production `refuse_test_kind_marked_host_config_chirho` fence.
pub fn refuse_production_posture_chirho(config_chirho: &LedgerHostConfigChirho) -> Result<()> {
    if config_chirho.test_kind_chirho.is_none() {
        bail!(
            "{SERVED_LLM_DEV_BOOTSTRAP_PRODUCTION_REFUSAL_CHIRHO}: the served-LLM dev bootstrap will \
             only author a synthetic test-kind ledger; a production (unmarked) host config is refused"
        );
    }
    Ok(())
}

/// Bootstrap a synthetic, dev-only, file-backed local ledger host and fund the payer with exactly
/// `--amount` of `--billing-kind` through the single-node regenesis genesis+mint.
///
/// Fail-closed throughout: input shape is checked up front, the posture gate runs before any write,
/// and every money invariant (mint == max supply ceiling, replay supply == mint, conservation green)
/// is enforced inside `run_ledger_regenesis_chirho`, which refuses rather than half-funds.
pub fn run_served_llm_dev_bootstrap_chirho(
    request_chirho: ServedLlmDevBootstrapRequestChirho<'_>,
) -> Result<ServedLlmDevBootstrapReportChirho> {
    // --- Up-front input shape (clean errors; regenesis re-checks everything and fails closed). ---
    if request_chirho.amount_chirho == 0 {
        bail!("served-llm dev bootstrap --amount must be greater than zero");
    }
    if request_chirho.payer_principal_chirho == request_chirho.owner_principal_chirho {
        bail!(
            "served-llm dev bootstrap payer and owner (settlement) principals must be distinct \
             accounts on the billing kind"
        );
    }

    // --- Prepare the synthetic root (create if missing; refuse an already-bootstrapped one). ---
    std::fs::create_dir_all(request_chirho.root_chirho).with_context(|| {
        format!(
            "create served-llm dev bootstrap root {}",
            request_chirho.root_chirho.display()
        )
    })?;
    let root_chirho = request_chirho.root_chirho.canonicalize().with_context(|| {
        format!(
            "canonicalize served-llm dev bootstrap root {}",
            request_chirho.root_chirho.display()
        )
    })?;
    if root_chirho.join(FRESH_PARENT_CHIRHO).exists() {
        bail!(
            "served-llm dev bootstrap root already carries a published ledger ({}); refusing to \
             bootstrap over it",
            FRESH_PARENT_CHIRHO
        );
    }

    // --- Node identity + the eight synthetic secrets (six runtime signers + issuer + activation). ---
    // `sign_message_chirho` creates the root instance keypair if absent; regenesis reads it as the
    // single elected node.
    cairn_signer_chirho::signer_chirho::sign_message_chirho(
        &root_chirho,
        b"served-llm dev bootstrap node identity chirho",
    )
    .context("establish served-llm dev bootstrap node identity")?;
    provision_secrets_chirho(&root_chirho)?;

    // --- Author the test-kind config, run the posture gate, and write it under custody (0600). ---
    let kind_issuer_principal_chirho =
        format!("{LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}{KIND_ISSUER_PRINCIPAL_SUFFIX_CHIRHO}");
    let config_chirho = build_ledger_host_config_chirho(
        &root_chirho,
        &request_chirho,
        &kind_issuer_principal_chirho,
    )?;
    let ledger_host_config_chirho = config_chirho
        .ledger_host_chirho
        .as_ref()
        .expect("bootstrap authored a ledger host config block");
    refuse_production_posture_chirho(ledger_host_config_chirho)?;
    // Validate before writing, so a malformed synthetic config never reaches the disk or regenesis.
    ledger_host_config_chirho
        .validate_chirho()
        .context("validate authored served-llm dev bootstrap ledger host config")?;
    let config_path_chirho = dev_bootstrap_config_path_chirho(&root_chirho);
    let config_text_chirho = serialize_config_chirho(&config_chirho)
        .context("serialize served-llm dev bootstrap config")?;
    write_private_artifact_chirho(&config_path_chirho, config_text_chirho.as_bytes(), "config")?;

    // --- Author and write the mint-to-payer plan. ---
    let plan_chirho = build_plan_chirho(&request_chirho, &kind_issuer_principal_chirho);
    let plan_bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("canonicalize plan: {error_chirho:?}"))?;
    let expected_plan_digest_chirho = plan_digest_chirho(&plan_bytes_chirho);
    let plan_path_chirho = root_chirho.join(PLAN_FILE_CHIRHO);
    write_private_artifact_chirho(&plan_path_chirho, &plan_bytes_chirho, "plan")?;

    // --- Author the activation authorization in-process, then write it (0600). ---
    let activation_artifact_chirho =
        author_ledger_regenesis_activation_chirho(LedgerRegenesisActivationAuthorRequestChirho {
            selected_root_chirho: &root_chirho,
            config_path_chirho: &config_path_chirho,
            plan_path_chirho: &plan_path_chirho,
            expected_plan_digest_chirho: &expected_plan_digest_chirho,
            issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: ACTIVATION_SECRET_NAME_CHIRHO,
        })
        .map_err(|error_chirho| {
            anyhow::anyhow!("author activation authorization: {error_chirho:?}")
        })?;
    let activation_path_chirho = root_chirho.join(ACTIVATION_FILE_CHIRHO);
    write_private_artifact_chirho(
        &activation_path_chirho,
        &activation_artifact_chirho.canonical_bytes_chirho,
        "activation authorization",
    )?;

    // --- Drive the reviewed single-node regenesis genesis+mint. This is the money operation; it
    // registers the kind policy, mints exactly `--amount` to the payer, amends the policy to name the
    // settlement owner, replays to prove supply == mint, and publishes a conserved, H2-openable root. ---
    let receipt_chirho = run_ledger_regenesis_chirho(LedgerRegenesisH3aRequestChirho {
        selected_root_chirho: &root_chirho,
        config_path_chirho: &config_path_chirho,
        plan_path_chirho: &plan_path_chirho,
        expected_plan_digest_chirho: &expected_plan_digest_chirho,
        issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
        activation_authorization_path_chirho: &activation_path_chirho,
        expected_activation_authorization_digest_chirho: &activation_artifact_chirho
            .authorization_digest_chirho,
    })
    .map_err(|error_chirho| anyhow::anyhow!("ledger regenesis refused: {error_chirho:?}"))?;

    Ok(ServedLlmDevBootstrapReportChirho {
        schema_chirho: SERVED_LLM_DEV_BOOTSTRAP_REPORT_SCHEMA_V1_CHIRHO,
        payer_principal_chirho: request_chirho.payer_principal_chirho.to_owned(),
        settlement_owner_principal_chirho: request_chirho.owner_principal_chirho.to_owned(),
        billing_kind_chirho: request_chirho.billing_kind_chirho.to_owned(),
        amount_chirho: request_chirho.amount_chirho,
        test_kind_marked_chirho: true,
        config_file_chirho: SERVED_LLM_DEV_CONFIG_FILE_CHIRHO.to_owned(),
        plan_digest_chirho: receipt_chirho.plan_digest_chirho,
        packet_digest_chirho: receipt_chirho.packet_digest_chirho,
        publication_manifest_digest_chirho: receipt_chirho.publication_manifest_digest_chirho,
        final_parent_name_chirho: receipt_chirho.final_parent_name_chirho,
        storage_namespace_chirho: STORAGE_NAMESPACE_CHIRHO.to_owned(),
        journal_path_chirho: JOURNAL_PATH_CHIRHO.to_owned(),
        balance_projection_name_chirho: BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
        balance_head_path_chirho: BALANCE_HEAD_PATH_CHIRHO.to_owned(),
    })
}

/// Write the six runtime signer secrets and the two offline authority secrets as distinct, non-zero,
/// 32-byte synthetic dev seeds. Distinctness guarantees eight distinct ed25519 identities, so the
/// offline signers never collide with each other or with a runtime signer.
fn provision_secrets_chirho(root_chirho: &Path) -> Result<()> {
    for (index_chirho, secret_name_chirho) in RUNTIME_SIGNER_SECRET_NAMES_CHIRHO.iter().enumerate()
    {
        set_dev_seed_secret_chirho(
            root_chirho,
            secret_name_chirho,
            dev_seed_byte_chirho(index_chirho),
        )?;
    }
    set_dev_seed_secret_chirho(
        root_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        dev_seed_byte_chirho(6),
    )?;
    set_dev_seed_secret_chirho(
        root_chirho,
        ACTIVATION_SECRET_NAME_CHIRHO,
        dev_seed_byte_chirho(7),
    )?;
    Ok(())
}

/// The synthetic seed byte for slot `index_chirho` (0-based). `index + 1` keeps every seed non-zero
/// and pairwise distinct across the eight slots.
fn dev_seed_byte_chirho(index_chirho: usize) -> u8 {
    (index_chirho + 1) as u8
}

fn set_dev_seed_secret_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    seed_byte_chirho: u8,
) -> Result<()> {
    let mut seed_chirho = [seed_byte_chirho; 32];
    let result_chirho = cairn_secret_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        name_chirho,
        &seed_chirho,
    )
    .with_context(|| format!("set served-llm dev bootstrap secret {name_chirho}"))
    .map(|_ref_chirho| ());
    seed_chirho.zeroize();
    result_chirho
}

/// Derive the lowercase hex ed25519 verifying key of a synthetic seed, matching the offline signer's
/// own `verifying_key().as_bytes()` derivation so the config pin custody-verifies against the secret.
fn dev_verifying_key_hex_chirho(seed_byte_chirho: u8) -> String {
    let mut seed_chirho = [seed_byte_chirho; 32];
    let signing_key_chirho = ed25519_dalek::SigningKey::from_bytes(&seed_chirho);
    let verifying_key_bytes_chirho = signing_key_chirho.verifying_key().to_bytes();
    seed_chirho.zeroize();
    hex_lower_chirho(&verifying_key_bytes_chirho)
}

fn hex_lower_chirho(bytes_chirho: &[u8]) -> String {
    use std::fmt::Write;
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        let _ = write!(&mut encoded_chirho, "{byte_chirho:02x}");
    }
    encoded_chirho
}

fn build_ledger_host_config_chirho(
    root_chirho: &Path,
    request_chirho: &ServedLlmDevBootstrapRequestChirho<'_>,
    kind_issuer_principal_chirho: &str,
) -> Result<ConfigChirho> {
    let ledger_host_chirho = LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO.to_owned(),
        storage_namespace_chirho: STORAGE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_namespace_chirho: MONITOR_EVIDENCE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: MONITOR_EVIDENCE_PATH_CHIRHO.to_owned(),
        money_group_id_chirho: MONEY_GROUP_ID_CHIRHO.to_owned(),
        cluster_id_chirho: CLUSTER_ID_CHIRHO.to_owned(),
        journal_path_chirho: JOURNAL_PATH_CHIRHO.to_owned(),
        local_epoch_chirho: LOCAL_EPOCH_CHIRHO,
        // Both accounts on the billing kind: the payer (mint recipient) and the settlement owner.
        members_chirho: vec![
            LedgerHostMemberConfigChirho {
                owner_chirho: request_chirho.payer_principal_chirho.to_owned(),
                kind_id_chirho: request_chirho.billing_kind_chirho.to_owned(),
            },
            LedgerHostMemberConfigChirho {
                owner_chirho: request_chirho.owner_principal_chirho.to_owned(),
                kind_id_chirho: request_chirho.billing_kind_chirho.to_owned(),
            },
        ],
        kind_registry_path_chirho: KIND_REGISTRY_PATH_CHIRHO.to_owned(),
        kind_registry_id_chirho: KIND_REGISTRY_ID_CHIRHO.to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: kind_issuer_principal_chirho.to_owned(),
            verifying_key_hex_chirho: dev_verifying_key_hex_chirho(dev_seed_byte_chirho(6)),
        },
        activation_authority_chirho: Some(LedgerHostActivationPinConfigChirho {
            principal_chirho: ACTIVATION_PRINCIPAL_CHIRHO.to_owned(),
            verifying_key_hex_chirho: dev_verifying_key_hex_chirho(dev_seed_byte_chirho(7)),
        }),
        adopt_migrated_root_chirho: false,
        projection_registry_path_chirho: PROJECTION_REGISTRY_PATH_CHIRHO.to_owned(),
        projection_registry_id_chirho: PROJECTION_REGISTRY_ID_CHIRHO.to_owned(),
        source_registry_path_chirho: SOURCE_REGISTRY_PATH_CHIRHO.to_owned(),
        source_registry_id_chirho: SOURCE_REGISTRY_ID_CHIRHO.to_owned(),
        projection_routes_chirho: vec![LedgerHostProjectionRouteConfigChirho {
            projection_name_chirho: BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
            head_path_chirho: BALANCE_HEAD_PATH_CHIRHO.to_owned(),
        }],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[0].to_owned(),
            config_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[1].to_owned(),
            feeder_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[2].to_owned(),
            kind_root_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[3].to_owned(),
            effect_intent_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[4].to_owned(),
            effect_terminal_chirho: RUNTIME_SIGNER_SECRET_NAMES_CHIRHO[5].to_owned(),
        },
        held_verifier_pins_chirho: None,
        migration_destination_authority_chirho: None,
        monitor_cadence_ms_chirho: MONITOR_CADENCE_MS_CHIRHO,
        postgres_effect_chirho: None,
        control_plane_chirho: None,
        test_kind_chirho: Some(LedgerHostTestKindMarkerConfigChirho {
            schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
            // This is a SINGLE-NODE served-money dev root, not a CF8 multi-node drill root, so it opts
            // out of the CF8 loss-witness requirement. The exemption is honored only when the resident
            // actor is opened through the dedicated normal-settlement dev door
            // (`open_resident_effect_journal_handle_testkind_chirho`), never a drill/shared-elector door.
            loss_witness_exempt_chirho: true,
        }),
    };
    Ok(ConfigChirho {
        root_chirho: root_chirho.display().to_string(),
        ledger_host_chirho: Some(ledger_host_chirho),
        ..ConfigChirho::default()
    })
}

fn build_plan_chirho(
    request_chirho: &ServedLlmDevBootstrapRequestChirho<'_>,
    kind_issuer_principal_chirho: &str,
) -> LedgerRegenesisPlanV1Chirho {
    LedgerRegenesisPlanV1Chirho {
        schema_chirho: LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: FRESH_PARENT_CHIRHO.to_owned(),
        staging_parent_chirho: STAGING_PARENT_CHIRHO.to_owned(),
        storage_namespace_chirho: STORAGE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_namespace_chirho: MONITOR_EVIDENCE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: MONITOR_EVIDENCE_PATH_CHIRHO.to_owned(),
        money_group_id_chirho: MONEY_GROUP_ID_CHIRHO.to_owned(),
        cluster_id_chirho: CLUSTER_ID_CHIRHO.to_owned(),
        journal_path_chirho: JOURNAL_PATH_CHIRHO.to_owned(),
        local_epoch_chirho: LOCAL_EPOCH_CHIRHO,
        kind_registry_path_chirho: KIND_REGISTRY_PATH_CHIRHO.to_owned(),
        kind_registry_id_chirho: KIND_REGISTRY_ID_CHIRHO.to_owned(),
        projection_registry_path_chirho: PROJECTION_REGISTRY_PATH_CHIRHO.to_owned(),
        projection_registry_id_chirho: PROJECTION_REGISTRY_ID_CHIRHO.to_owned(),
        source_registry_path_chirho: SOURCE_REGISTRY_PATH_CHIRHO.to_owned(),
        source_registry_id_chirho: SOURCE_REGISTRY_ID_CHIRHO.to_owned(),
        projection_routes_chirho: vec![LedgerRegenesisProjectionRoutePlanChirho {
            projection_name_chirho: BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
            head_path_chirho: BALANCE_HEAD_PATH_CHIRHO.to_owned(),
        }],
        monitor_cadence_ms_chirho: MONITOR_CADENCE_MS_CHIRHO,
        issuer_principal_chirho: kind_issuer_principal_chirho.to_owned(),
        // MINT-TO-PAYER: the mint credits the payer directly (no transfer).
        initial_owner_chirho: request_chirho.payer_principal_chirho.to_owned(),
        kind_id_chirho: request_chirho.billing_kind_chirho.to_owned(),
        initial_policy_chirho: policy_chirho(request_chirho.amount_chirho, None),
        // The amended (current) policy names the settlement owner, which the served-LLM Finalize
        // credits. Naming a settlement owner makes the amended body differ from the initial one, as
        // the plan-policy law requires.
        amended_policy_chirho: policy_chirho(
            request_chirho.amount_chirho,
            Some(request_chirho.owner_principal_chirho.to_owned()),
        ),
        initial_mint_amount_chirho: request_chirho.amount_chirho,
        genesis_physical_ms_chirho: GENESIS_PHYSICAL_MS_CHIRHO,
        mint_physical_ms_chirho: MINT_PHYSICAL_MS_CHIRHO,
    }
}

/// One kind policy body. Supply is capped at the mint amount, so conservation is crisp (minted ==
/// max supply == in circulation), and the served-LLM Hold/Finalize is a within-kind transfer that
/// never changes supply.
fn policy_chirho(
    amount_chirho: u64,
    settlement_owner_chirho: Option<String>,
) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: POLICY_UNIT_CHIRHO.to_owned(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(amount_chirho),
        },
        rounding_chirho: RoundingChirho::ExactChirho,
        shard_attachment_chirho: POLICY_SHARD_ATTACHMENT_CHIRHO.to_owned(),
        settlement_owner_chirho,
        idempotency_window_chirho: Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: IDEMPOTENCY_HORIZON_MS_CHIRHO,
            retry_finality_horizon_ms_chirho: RETRY_FINALITY_HORIZON_MS_CHIRHO,
        }),
    }
}

/// Write an operator artifact owner-private (mode 0600) with its bytes synced to the device. The
/// config carries the host block under the same custody the regenesis flow re-checks.
fn write_private_artifact_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    label_chirho: &str,
) -> Result<()> {
    use std::io::Write;
    let mut options_chirho = std::fs::OpenOptions::new();
    options_chirho.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho.open(path_chirho).with_context(|| {
        format!(
            "create served-llm dev bootstrap {label_chirho} {}",
            path_chirho.display()
        )
    })?;
    file_chirho
        .write_all(bytes_chirho)
        .and_then(|()| file_chirho.sync_all())
        .with_context(|| {
            format!(
                "write served-llm dev bootstrap {label_chirho} {}",
                path_chirho.display()
            )
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "set private mode on {label_chirho} {}",
                    path_chirho.display()
                )
            })?;
    }
    Ok(())
}

fn dev_bootstrap_config_path_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join(SERVED_LLM_DEV_CONFIG_FILE_CHIRHO)
}

#[cfg(test)]
#[path = "tests_chirho.rs"]
mod tests_chirho;
