// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Explicit operator preparation for the credits-demo LocalPhaseB run. Input authoring consumes an
//! existing identity + secret-store custody and writes only three review artifacts. Provider prepare
//! consumes an existing loopback DSN, installs the adapter-owned schema, and inserts the one demo
//! seed row. The smoke itself never calls either preparation path.
//!
//! **Since brick #7 this module AUTHORS NOTHING ITSELF: it is a caller of the generic
//! custody-bound ledger-host authoring road.** The demo's compile-time coordinates are re-expressed
//! as one reviewed `LedgerHostAuthoringInputsV1Chirho` document
//! ([`credits_demo_authoring_inputs_chirho`]), and the config/plan pair is derived and emitted by
//! `author_and_emit_ledger_host_artifacts_chirho`. What that migration BUYS is the identity law:
//! the two offline pins are now derived by
//! `derived_kind_issuer_pin_chirho` / `derived_ledger_activation_pin_chirho`, which compare the
//! candidate's derived public half against every runtime signer's, so an offline issuer secret
//! holding the SAME 32 bytes as a runtime signer under a DIFFERENT name is refused. The road this
//! replaced could not see that — it compared names and discarded the loaded signer set — and a
//! measurement at the pre-migration commit confirmed it authored a bootable config pinning the
//! `kind_root_chirho` signer's own identity as the mint authority's outer trust root.
//!
//! Workflow: `deploy-chirho/cax11-artifacts-chirho/ops-and-smoke-chirho/cax11-credits-demo-localphaseb-regenesis-chirho.md`.

use anyhow::{bail, Context, Result};
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_regenesis_chirho::{
    author_and_emit_ledger_host_artifacts_chirho, author_ledger_regenesis_activation_chirho,
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringMemberInputChirho,
    LedgerHostAuthoringModeChirho, LedgerHostAuthoringPostgresEffectInputChirho,
    LedgerHostAuthoringRouteInputChirho, LedgerHostAuthoringSignerRefsInputChirho,
    LedgerHostEmissionRequestChirho, LedgerRegenesisActivationAuthorRequestChirho,
    VerifiedDestinationAuthorityEnrollmentChirho, LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO,
};
use cairn_postgres_effect_chirho::ports_chirho::ReversiblePostgresDatabasePortChirho;
use cairn_postgres_effect_chirho::{
    install_reversible_postgres_schema_chirho, PostgresDatabaseChirho,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::{constants_chirho, setup_chirho};

pub const CREDITS_DEMO_INPUTS_AUTHOR_REPORT_SCHEMA_CHIRHO: &str =
    "credits-demo-inputs-author-report-v2-chirho";
pub const CREDITS_DEMO_PROVIDER_PREPARE_REPORT_SCHEMA_CHIRHO: &str =
    "credits-demo-provider-prepare-report-v1-chirho";

/// Reported as the demo's provider secret-ref count: the DSN and the adapter evidence key.
const PROVIDER_SECRET_REF_COUNT_CHIRHO: u64 = 2;

pub struct CreditsDemoInputsAuthorRequestChirho<'request_chirho> {
    pub root_chirho: &'request_chirho Path,
    pub payer_chirho: &'request_chirho str,
    pub config_output_chirho: &'request_chirho Path,
    pub plan_output_chirho: &'request_chirho Path,
    pub activation_authorization_output_chirho: &'request_chirho Path,
    pub issuer_secret_name_chirho: &'request_chirho str,
    pub activation_secret_name_chirho: &'request_chirho str,
    pub payer_credential_secret_name_chirho: &'request_chirho str,
    pub destination_authority_enrollment_chirho:
        &'request_chirho VerifiedDestinationAuthorityEnrollmentChirho,
    pub serve_port_chirho: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CreditsDemoInputsAuthorReportChirho {
    pub schema_chirho: &'static str,
    pub payer_chirho: String,
    pub plan_digest_chirho: String,
    pub config_digest_chirho: String,
    pub activation_authorization_digest_chirho: String,
    pub destination_authority_enrollment_digest_chirho: String,
    pub plan_output_created_chirho: bool,
    pub config_output_created_chirho: bool,
    pub activation_authorization_output_created_chirho: bool,
    pub canonical_plan_chirho: bool,
    pub config_validated_chirho: bool,
    pub config_root_bound_chirho: bool,
    pub existing_identity_verified_chirho: bool,
    pub existing_secret_custody_verified_chirho: bool,
    pub signer_secret_ref_count_chirho: u64,
    pub provider_secret_ref_count_chirho: u64,
}

pub struct CreditsDemoProviderPrepareRequestChirho<'request_chirho> {
    pub root_chirho: &'request_chirho Path,
    pub connection_secret_name_chirho: &'request_chirho str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CreditsDemoProviderPrepareReportChirho {
    pub schema_chirho: &'static str,
    pub operator_established_chirho: bool,
    /// `false` means the smoke/arc did not mint this external state. The explicit operator command
    /// established it before the smoke and remains outside the evidence-producing call graph.
    pub cairn_minted_chirho: bool,
    pub established_outside_smoke_run_chirho: bool,
    pub schema_installed_chirho: bool,
    pub reversible_table_count_chirho: u64,
    pub total_values_rows_chirho: u64,
    pub target_values_rows_chirho: u64,
    pub forward_decision_rows_chirho: u64,
    pub compensation_receipt_rows_chirho: u64,
}

/// Author the canonical plan/config pair plus the separately signed activation artifact from
/// existing operator-reviewed identity and custody. The smoke must receive both reviewed digests.
///
/// **This is now a CALLER, not an author.** The config and plan are derived and written by
/// `author_and_emit_ledger_host_artifacts_chirho` from the one reviewed document this module builds
/// out of the demo's constants, so this road inherits the whole generic law set rather than
/// carrying a weaker copy of it: never-mint, the reviewed document's coordinate/path-alias/namespace
/// laws, the six-signer custody proof, and — the reason brick #7 exists — the **identity**
/// comparison that refuses an offline issuer or activation authority holding a runtime signer's own
/// 32 secret bytes under a different name. The mode is `ProductionChirho`: the credits demo emits a
/// production-shaped config and always has, so it is not marked test-kind to make anything pass.
///
/// **What this function still owns, and why.** The pre-signed activation AUTHORIZATION is a third
/// artifact the generic emission road deliberately does not author — it is a signing act whose
/// validity window is fixed at 15 minutes, so it belongs beside the start it authorizes. This road
/// therefore keeps the in-root / no-overwrite / `0600` law for that one artifact, resolves all three
/// outputs up front so an occupied path refuses before any secret is read, and rolls the emitted
/// pair back if the activation step fails.
pub fn author_credits_demo_inputs_chirho(
    request_chirho: &CreditsDemoInputsAuthorRequestChirho<'_>,
) -> Result<CreditsDemoInputsAuthorReportChirho> {
    let canonical_root_chirho = canonical_operator_root_chirho(request_chirho.root_chirho)?;
    // All three outputs are resolved and proven fresh BEFORE any secret is read. The emission road
    // re-resolves and re-checks the two it writes, authoritatively; resolving them here as well is
    // what lets the three-artifact distinctness law below compare resolved paths rather than the
    // spellings an operator typed.
    let plan_output_chirho = checked_fresh_output_chirho(
        &canonical_root_chirho,
        request_chirho.plan_output_chirho,
        "plan",
    )?;
    let config_output_chirho = checked_fresh_output_chirho(
        &canonical_root_chirho,
        request_chirho.config_output_chirho,
        "config",
    )?;
    let activation_authorization_output_chirho = checked_fresh_output_chirho(
        &canonical_root_chirho,
        request_chirho.activation_authorization_output_chirho,
        "activation authorization",
    )?;
    let distinct_outputs_chirho = BTreeSet::from([
        plan_output_chirho.as_path(),
        config_output_chirho.as_path(),
        activation_authorization_output_chirho.as_path(),
    ]);
    if distinct_outputs_chirho.len() != 3 {
        bail!("credits-demo review artifact outputs must be pairwise distinct");
    }

    verify_exact_payer_identity_chirho(&canonical_root_chirho, request_chirho.payer_chirho)?;
    verify_credits_demo_only_custody_chirho(
        &canonical_root_chirho,
        request_chirho.issuer_secret_name_chirho,
        request_chirho.activation_secret_name_chirho,
        request_chirho.payer_credential_secret_name_chirho,
    )?;

    let inputs_chirho = credits_demo_authoring_inputs_chirho(request_chirho.payer_chirho);
    let emitted_chirho =
        author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
            selected_root_chirho: &canonical_root_chirho,
            inputs_chirho: &inputs_chirho,
            destination_authority_enrollment_chirho: request_chirho
                .destination_authority_enrollment_chirho,
            issuer_secret_name_chirho: request_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: Some(request_chirho.activation_secret_name_chirho),
            config_output_chirho: &config_output_chirho,
            plan_output_chirho: &plan_output_chirho,
            serve_port_chirho: request_chirho.serve_port_chirho,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .map_err(|error_chirho| {
            anyhow::anyhow!("author credits-demo host config and plan: {error_chirho:?}")
        })?;

    let activation_artifact_chirho = match author_ledger_regenesis_activation_chirho(
        LedgerRegenesisActivationAuthorRequestChirho {
            selected_root_chirho: &canonical_root_chirho,
            config_path_chirho: &emitted_chirho.config_path_chirho,
            plan_path_chirho: &emitted_chirho.plan_path_chirho,
            expected_plan_digest_chirho: &emitted_chirho.plan_digest_chirho,
            issuer_secret_name_chirho: request_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: request_chirho.activation_secret_name_chirho,
        },
    ) {
        Ok(artifact_chirho) => artifact_chirho,
        Err(error_chirho) => {
            remove_emitted_pair_chirho(&emitted_chirho);
            return Err(anyhow::anyhow!(
                "author pre-signed ledger activation: {error_chirho:?}"
            ));
        }
    };
    if let Err(error_chirho) = write_private_create_new_chirho(
        &activation_authorization_output_chirho,
        &activation_artifact_chirho.canonical_bytes_chirho,
        "activation authorization",
    ) {
        remove_emitted_pair_chirho(&emitted_chirho);
        return Err(error_chirho);
    }

    Ok(CreditsDemoInputsAuthorReportChirho {
        schema_chirho: CREDITS_DEMO_INPUTS_AUTHOR_REPORT_SCHEMA_CHIRHO,
        payer_chirho: request_chirho.payer_chirho.to_owned(),
        plan_digest_chirho: emitted_chirho.plan_digest_chirho,
        config_digest_chirho: emitted_chirho.config_digest_chirho,
        activation_authorization_digest_chirho: activation_artifact_chirho
            .authorization_digest_chirho,
        destination_authority_enrollment_digest_chirho: emitted_chirho
            .destination_authority_enrollment_digest_chirho,
        plan_output_created_chirho: true,
        config_output_created_chirho: true,
        activation_authorization_output_created_chirho: true,
        canonical_plan_chirho: true,
        config_validated_chirho: true,
        config_root_bound_chirho: true,
        existing_identity_verified_chirho: true,
        existing_secret_custody_verified_chirho: true,
        // Reported from the custody road's own evidence rather than from a local literal: the count
        // this road can honestly publish is the number of runtime signers something actually proved.
        signer_secret_ref_count_chirho: emitted_chirho
            .custody_evidence_chirho
            .proven_runtime_signer_count_chirho,
        provider_secret_ref_count_chirho: PROVIDER_SECRET_REF_COUNT_CHIRHO,
    })
}

/// Undo the emitted pair after a later step in this three-artifact authoring failed.
///
/// Best effort by necessity: if a removal also fails there is nothing further this process can do,
/// and the error it must report is the one that caused the rollback, never a rollback failure that
/// would hide it.
fn remove_emitted_pair_chirho(
    emitted_chirho: &cairn_ledger_regenesis_chirho::LedgerHostEmittedArtifactsChirho,
) {
    let _remove_plan_result_chirho = fs::remove_file(&emitted_chirho.plan_path_chirho);
    let _remove_config_result_chirho = fs::remove_file(&emitted_chirho.config_path_chirho);
}

/// Establish the demo's external provider posture through the adapter-owned schema law. This is an
/// explicit operator command, not a smoke helper: it never creates a database, writes a secret, or
/// runs the LocalPhaseB arc.
pub fn prepare_credits_demo_provider_chirho(
    request_chirho: &CreditsDemoProviderPrepareRequestChirho<'_>,
) -> Result<CreditsDemoProviderPrepareReportChirho> {
    let canonical_root_chirho = canonical_operator_root_chirho(request_chirho.root_chirho)?;
    let dsn_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        &canonical_root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(
            request_chirho.connection_secret_name_chirho,
        )?,
    )?
    .into_string_chirho()
    .context("configured LocalPhaseB DSN secret was not UTF-8")?;
    let mut client_chirho = setup_chirho::connect_pg_chirho(&dsn_chirho)?;

    for table_chirho in constants_chirho::REVERSIBLE_TABLES_CHIRHO {
        let present_chirho: Option<String> = client_chirho
            .query_one("SELECT to_regclass($1)::text", &[&table_chirho])
            .with_context(|| format!("inspect preexisting reversible table {table_chirho}"))?
            .get(0);
        if present_chirho.is_some() {
            bail!("credits-demo provider preparation refuses preexisting table '{table_chirho}'");
        }
    }

    client_chirho
        .batch_execute("BEGIN")
        .context("begin atomic credits-demo provider preparation")?;
    install_reversible_postgres_schema_chirho(&mut client_chirho)
        .map_err(|error_chirho| anyhow::anyhow!("install reversible schema: {error_chirho:?}"))?;
    let inserted_chirho = client_chirho
        .execute(
            "INSERT INTO cairn_reversible_values_chirho \
             (subject_chirho, row_key_chirho, value_chirho) VALUES ($1, $2, $3)",
            &[
                &constants_chirho::FIXED_SUBJECT_CHIRHO,
                &constants_chirho::FIXED_ROW_KEY_CHIRHO,
                &constants_chirho::SEED_VALUE_CHIRHO,
            ],
        )
        .context("seed keyed reversible provider row with plain INSERT")?;
    if inserted_chirho != 1 {
        bail!("expected exactly one seeded reversible row, inserted {inserted_chirho}");
    }

    let mut database_chirho = PostgresDatabaseChirho::from_client_chirho(client_chirho);
    database_chirho
        .verify_schema_ready_chirho()
        .map_err(|error_chirho| anyhow::anyhow!("verify reversible schema: {error_chirho:?}"))?;
    let mut client_chirho = database_chirho.into_client_chirho();
    let total_values_rows_chirho =
        table_count_chirho(&mut client_chirho, "cairn_reversible_values_chirho")?;
    let forward_decision_rows_chirho = table_count_chirho(
        &mut client_chirho,
        "cairn_reversible_forward_decisions_chirho",
    )?;
    let compensation_receipt_rows_chirho =
        table_count_chirho(&mut client_chirho, "cairn_reversible_comp_receipts_chirho")?;
    let target_rows_chirho = client_chirho
        .query(
            "SELECT value_chirho FROM cairn_reversible_values_chirho \
             WHERE subject_chirho = $1 AND row_key_chirho = $2",
            &[
                &constants_chirho::FIXED_SUBJECT_CHIRHO,
                &constants_chirho::FIXED_ROW_KEY_CHIRHO,
            ],
        )
        .context("verify exact credits-demo seed row")?;
    if total_values_rows_chirho != 1
        || target_rows_chirho.len() != 1
        || forward_decision_rows_chirho != 0
        || compensation_receipt_rows_chirho != 0
    {
        bail!(
            "credits-demo provider preparation did not produce exact 1/0/0 posture \
             (values={total_values_rows_chirho}, target={}, forward={forward_decision_rows_chirho}, \
             compensation={compensation_receipt_rows_chirho})",
            target_rows_chirho.len()
        );
    }
    let seed_value_chirho: Vec<u8> = target_rows_chirho[0].get(0);
    if seed_value_chirho != constants_chirho::SEED_VALUE_CHIRHO {
        bail!("credits-demo provider seed value did not match the sealed protocol value");
    }
    let reversible_table_count_chirho =
        u64::try_from(constants_chirho::REVERSIBLE_TABLES_CHIRHO.len())
            .context("reversible table count overflow")?;
    let target_values_rows_chirho =
        u64::try_from(target_rows_chirho.len()).context("target provider row count overflow")?;
    client_chirho
        .batch_execute("COMMIT")
        .context("commit atomic credits-demo provider preparation")?;

    Ok(CreditsDemoProviderPrepareReportChirho {
        schema_chirho: CREDITS_DEMO_PROVIDER_PREPARE_REPORT_SCHEMA_CHIRHO,
        operator_established_chirho: true,
        cairn_minted_chirho: false,
        established_outside_smoke_run_chirho: true,
        schema_installed_chirho: true,
        reversible_table_count_chirho,
        total_values_rows_chirho,
        target_values_rows_chirho,
        forward_decision_rows_chirho,
        compensation_receipt_rows_chirho,
    })
}

/// The credits demo's compile-time coordinates, re-expressed as the ONE reviewed authoring document
/// the generic road reads.
///
/// This is brick #7's substance: the constants that used to be baked into a private plan builder and
/// a private config builder now appear exactly once, as coordinates, and both artifacts are derived
/// from them by `derive_ledger_host_artifacts_chirho`. Two consequences worth naming because they
/// are laws this road did not previously run — the config's registry paths are now proven pairwise
/// distinct (the config validator has no such check), and `ConfigPlanMismatchChirho` becomes
/// structurally unreachable rather than a runtime hope, because one document produces both.
///
/// The payer is the only runtime input: it is the reviewed identity this authoring run admits, and
/// it appears as the plan's initial owner and as the first membership row.
///
/// No key material is representable here and none is passed: the two verifier pins are DERIVED from
/// pre-provisioned secrets by the custody road, and the document type has no field for them.
pub fn credits_demo_authoring_inputs_chirho(
    payer_principal_chirho: &str,
) -> LedgerHostAuthoringInputsV1Chirho {
    LedgerHostAuthoringInputsV1Chirho {
        schema_chirho: LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: constants_chirho::FRESH_PARENT_CHIRHO.to_owned(),
        staging_parent_chirho: constants_chirho::STAGING_PARENT_CHIRHO.to_owned(),
        storage_namespace_chirho: constants_chirho::STORAGE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_namespace_chirho: constants_chirho::MONITOR_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: constants_chirho::MONITOR_EVIDENCE_PATH_CHIRHO.to_owned(),
        money_group_id_chirho: constants_chirho::MONEY_GROUP_ID_CHIRHO.to_owned(),
        cluster_id_chirho: constants_chirho::CLUSTER_ID_CHIRHO.to_owned(),
        local_epoch_chirho: constants_chirho::LOCAL_EPOCH_CHIRHO,
        journal_path_chirho: constants_chirho::JOURNAL_PATH_CHIRHO.to_owned(),
        kind_registry_path_chirho: constants_chirho::KIND_REGISTRY_PATH_CHIRHO.to_owned(),
        kind_registry_id_chirho: constants_chirho::KIND_REGISTRY_ID_CHIRHO.to_owned(),
        projection_registry_path_chirho: constants_chirho::PROJECTION_REGISTRY_PATH_CHIRHO
            .to_owned(),
        projection_registry_id_chirho: constants_chirho::PROJECTION_REGISTRY_ID_CHIRHO.to_owned(),
        source_registry_path_chirho: constants_chirho::SOURCE_REGISTRY_PATH_CHIRHO.to_owned(),
        source_registry_id_chirho: constants_chirho::SOURCE_REGISTRY_ID_CHIRHO.to_owned(),
        projection_routes_chirho: vec![
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::BALANCE_HEAD_PATH_CHIRHO.to_owned(),
            },
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: constants_chirho::MIRROR_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::MIRROR_HEAD_PATH_CHIRHO.to_owned(),
            },
        ],
        monitor_cadence_ms_chirho: constants_chirho::MONITOR_CADENCE_MS_CHIRHO,
        issuer_principal_chirho: constants_chirho::ISSUER_PRINCIPAL_CHIRHO.to_owned(),
        // Present, so the derived config schema is v2 — derived from what the document CONTAINS
        // rather than copied from a tag, which is how the migration keeps the emitted schema byte
        // for byte what this road always wrote.
        activation_principal_chirho: Some(constants_chirho::ACTIVATION_PRINCIPAL_CHIRHO.to_owned()),
        members_chirho: vec![
            LedgerHostAuthoringMemberInputChirho {
                owner_chirho: payer_principal_chirho.to_owned(),
                kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
            },
            LedgerHostAuthoringMemberInputChirho {
                owner_chirho: constants_chirho::SETTLEMENT_OWNER_CHIRHO.to_owned(),
                kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
            },
        ],
        signer_secrets_chirho: LedgerHostAuthoringSignerRefsInputChirho {
            journal_chirho: constants_chirho::JOURNAL_SECRET_NAME_CHIRHO.to_owned(),
            config_chirho: constants_chirho::CONFIG_SECRET_NAME_CHIRHO.to_owned(),
            feeder_chirho: constants_chirho::FEEDER_SECRET_NAME_CHIRHO.to_owned(),
            kind_root_chirho: constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO.to_owned(),
            effect_intent_chirho: constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO.to_owned(),
            effect_terminal_chirho: constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO.to_owned(),
        },
        initial_owner_chirho: payer_principal_chirho.to_owned(),
        kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
        initial_policy_chirho: localphaseb_policy_chirho(2_000),
        amended_policy_chirho: localphaseb_policy_chirho(1_500),
        initial_mint_amount_chirho: constants_chirho::INITIAL_MINT_AMOUNT_CHIRHO,
        genesis_physical_ms_chirho: constants_chirho::GENESIS_PHYSICAL_MS_CHIRHO,
        mint_physical_ms_chirho: constants_chirho::MINT_PHYSICAL_MS_CHIRHO,
        postgres_effect_chirho: Some(LedgerHostAuthoringPostgresEffectInputChirho {
            posture_chirho: cairn_chirho::config_chirho::LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
            connection_secret_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO.to_owned(),
            billing_kind_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
        }),
        test_kind_shared_journal_chirho: false,
    }
}

fn localphaseb_policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "credit-minor-chirho".to_owned(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(max_supply_chirho),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-credits-demo-localphaseb-chirho".to_owned(),
        settlement_owner_chirho: Some(constants_chirho::SETTLEMENT_OWNER_CHIRHO.to_owned()),
        idempotency_window_chirho: Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: constants_chirho::IDEMPOTENCY_HORIZON_MS_CHIRHO,
            retry_finality_horizon_ms_chirho: constants_chirho::RETRY_FINALITY_HORIZON_MS_CHIRHO,
        }),
    }
}

fn canonical_operator_root_chirho(root_chirho: &Path) -> Result<PathBuf> {
    let metadata_chirho = fs::symlink_metadata(root_chirho)
        .with_context(|| format!("inspect operator root {}", root_chirho.display()))?;
    if metadata_chirho.file_type().is_symlink() || !metadata_chirho.is_dir() {
        bail!("credits-demo operator root must be an existing non-symlink directory");
    }
    root_chirho
        .canonicalize()
        .with_context(|| format!("canonicalize operator root {}", root_chirho.display()))
}

fn checked_fresh_output_chirho(
    canonical_root_chirho: &Path,
    requested_output_chirho: &Path,
    label_chirho: &str,
) -> Result<PathBuf> {
    let joined_chirho = if requested_output_chirho.is_absolute() {
        requested_output_chirho.to_path_buf()
    } else {
        canonical_root_chirho.join(requested_output_chirho)
    };
    let parent_chirho = joined_chirho
        .parent()
        .ok_or_else(|| anyhow::anyhow!("credits-demo {label_chirho} output has no parent"))?
        .canonicalize()
        .with_context(|| format!("canonicalize credits-demo {label_chirho} output parent"))?;
    if !parent_chirho.starts_with(canonical_root_chirho) {
        bail!("credits-demo {label_chirho} output must remain inside the operator root");
    }
    let file_name_chirho = joined_chirho
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("credits-demo {label_chirho} output has no file name"))?;
    let output_chirho = parent_chirho.join(file_name_chirho);
    match fs::symlink_metadata(&output_chirho) {
        Ok(_) => bail!("credits-demo {label_chirho} output already exists; refusing overwrite"),
        Err(error_chirho) if error_chirho.kind() == std::io::ErrorKind::NotFound => {}
        Err(error_chirho) => {
            return Err(error_chirho).with_context(|| {
                format!("inspect credits-demo {label_chirho} output before authoring")
            })
        }
    }
    Ok(output_chirho)
}

fn verify_exact_payer_identity_chirho(root_chirho: &Path, payer_chirho: &str) -> Result<()> {
    let identities_chirho =
        cairn_chirho::identity_chirho::load_verified_identities_chirho(root_chirho)?;
    let mut matches_chirho = identities_chirho
        .iter()
        .filter(|record_chirho| record_chirho.principal_chirho == payer_chirho);
    let record_chirho = matches_chirho
        .next()
        .ok_or_else(|| anyhow::anyhow!("credits-demo payer is not a verified identity"))?;
    if matches_chirho.next().is_some() {
        bail!("credits-demo payer has duplicate verified identity records");
    }
    if !matches!(
        record_chirho.kind_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho
    ) {
        bail!("credits-demo payer identity must have UserChirho kind");
    }
    Ok(())
}

/// Prove the custody this demo needs that NO other home covers, and refuse the collisions no other
/// home checks.
///
/// **What moved out, and why this is a deletion rather than a relocation.** The six runtime signer
/// secrets used to be loaded here and the loaded set thrown away, which proved they existed and
/// proved nothing about whose keys the offline authorities were. That proof now belongs to
/// `bind_custody_and_derive_ledger_host_artifacts_chirho`, which loads the six itself and compares
/// the issuer's and activation authority's derived IDENTITIES against them — the check a name
/// comparison structurally cannot make. Their pairwise NAME distinctness belongs to the reviewed
/// document's own law, and the priced-effect DSN's collision with any of the eight belongs to the
/// custody road as well.
///
/// What is left is the complement: the adapter evidence key and the payer credential are the demo's
/// own operational secrets, so this proves they resolve and that neither name collides with any
/// authority name this run uses. The DSN is resolved here too — not for collision, but because the
/// LocalPhaseB local-endpoint law lives in the served-runtime crate that the operator regenesis
/// crate is forbidden to import, so this is the only road that can apply it.
fn verify_credits_demo_only_custody_chirho(
    root_chirho: &Path,
    issuer_secret_name_chirho: &str,
    activation_secret_name_chirho: &str,
    payer_credential_secret_name_chirho: &str,
) -> Result<()> {
    let _adapter_key_chirho =
        super::concurrency_token_chirho::load_adapter_evidence_key_chirho(root_chirho)?;

    let payer_credential_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(payer_credential_secret_name_chirho)?,
    )?
    .into_string_chirho()
    .context("payer credential secret was not UTF-8")?;
    if payer_credential_chirho.is_empty() {
        bail!("payer credential secret must not be empty");
    }

    let dsn_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(constants_chirho::DSN_SECRET_NAME_CHIRHO)?,
    )?
    .into_string_chirho()
    .context("LocalPhaseB DSN secret was not UTF-8")?;
    cairn_serve_runtime_chirho::parse_local_phase_b_connection_config_chirho(&dsn_chirho)
        .context("LocalPhaseB DSN refused by the shared local-endpoint law")?;

    // The same constants the reviewed document is built from, so the two cannot name different
    // secrets. Their pairwise distinctness among THEMSELVES is not asserted here — that law is the
    // document's, and re-running it here would be the second home this brick exists to remove.
    let other_names_chirho = BTreeSet::from([
        constants_chirho::JOURNAL_SECRET_NAME_CHIRHO,
        constants_chirho::CONFIG_SECRET_NAME_CHIRHO,
        constants_chirho::FEEDER_SECRET_NAME_CHIRHO,
        constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
        constants_chirho::DSN_SECRET_NAME_CHIRHO,
        issuer_secret_name_chirho,
        activation_secret_name_chirho,
    ]);
    let demo_only_names_chirho = [
        constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho,
    ];
    if demo_only_names_chirho[0] == demo_only_names_chirho[1] {
        bail!("credits-demo authority secret refs must be pairwise distinct");
    }
    for name_chirho in demo_only_names_chirho {
        cairn_chirho::secret_chirho::secret_ref_chirho(name_chirho)?;
        if other_names_chirho.contains(name_chirho) {
            bail!("credits-demo authority secret refs must be pairwise distinct");
        }
    }
    Ok(())
}

fn write_private_create_new_chirho(
    path_chirho: &Path,
    bytes_chirho: &[u8],
    label_chirho: &str,
) -> Result<()> {
    let mut options_chirho = OpenOptions::new();
    options_chirho.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options_chirho.mode(0o600);
    }
    let mut file_chirho = options_chirho
        .open(path_chirho)
        .with_context(|| format!("create credits-demo {label_chirho} review artifact"))?;
    file_chirho
        .write_all(bytes_chirho)
        .with_context(|| format!("write credits-demo {label_chirho} review artifact"))?;
    file_chirho
        .sync_all()
        .with_context(|| format!("sync credits-demo {label_chirho} review artifact"))?;
    Ok(())
}

fn table_count_chirho(client_chirho: &mut postgres::Client, table_chirho: &str) -> Result<u64> {
    let count_chirho: i64 = client_chirho
        .query_one(&format!("SELECT count(*)::bigint FROM {table_chirho}"), &[])
        .with_context(|| format!("count reversible provider table {table_chirho}"))?
        .get(0);
    u64::try_from(count_chirho).with_context(|| {
        format!("reversible provider table {table_chirho} returned negative count")
    })
}
