// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! TEST-SUPPORT ONLY (`cfg(test)`): deterministic secrets plus a throwaway PostgreSQL database.
//! The fixture creates those test-only inputs, then consumes the SAME production input-author and
//! provider-prepare laws as the operator CLI. No production command can reach database creation,
//! deterministic secret seeds, or secret installation.

use anyhow::{Context, Result};
use cairn_chirho::identity_chirho;
use cairn_ledger_regenesis_chirho::destination_authority_enrollment_test_support_chirho::{
    create_destination_authority_enrollment_test_fixture_chirho,
    DestinationAuthorityEnrollmentTestFixtureChirho,
};
use cairn_ledger_regenesis_chirho::{
    author_and_emit_ledger_host_artifacts_chirho, LedgerHostAuthoringModeChirho,
    LedgerHostEmissionRequestChirho,
};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::constants_chirho;
use super::operator_prepare_chirho::{
    author_credits_demo_inputs_chirho, credits_demo_authoring_inputs_chirho,
    prepare_credits_demo_provider_chirho, CreditsDemoInputsAuthorRequestChirho,
    CreditsDemoProviderPrepareRequestChirho,
};
use super::setup_chirho::connect_pg_chirho;

pub const PAYER_CREDENTIAL_CHIRHO: &str = "credits-demo-payer-credential-value-chirho";
pub const JOURNAL_SECRET_SEED_CHIRHO: u8 = 0x81;
pub const CONFIG_SECRET_SEED_CHIRHO: u8 = 0x82;
pub const FEEDER_SECRET_SEED_CHIRHO: u8 = 0x83;
pub const KIND_ROOT_SECRET_SEED_CHIRHO: u8 = 0x84;
pub const EFFECT_INTENT_SECRET_SEED_CHIRHO: u8 = 0x85;
pub const EFFECT_TERMINAL_SECRET_SEED_CHIRHO: u8 = 0x86;
pub const ISSUER_SECRET_SEED_CHIRHO: u8 = 0x2b;
pub const ACTIVATION_SECRET_SEED_CHIRHO: u8 = 0x2c;
pub const ADAPTER_EVIDENCE_SEED_CHIRHO: u8 = 0x33;

/// Reviewed inputs the fixture wrote through the production authoring law.
pub struct CreditsDemoFixtureInputsChirho {
    pub root_chirho: PathBuf,
    pub config_path_chirho: PathBuf,
    pub expected_config_digest_chirho: String,
    pub plan_path_chirho: PathBuf,
    pub expected_plan_digest_chirho: String,
    pub issuer_secret_name_chirho: String,
    pub activation_authorization_path_chirho: PathBuf,
    pub expected_activation_authorization_digest_chirho: String,
    pub payer_credential_secret_name_chirho: String,
    pub payer_chirho: String,
    pub db_name_chirho: String,
}

pub(crate) fn destination_authority_enrollment_fixture_chirho(
) -> &'static DestinationAuthorityEnrollmentTestFixtureChirho {
    static FIXTURE_CHIRHO: OnceLock<DestinationAuthorityEnrollmentTestFixtureChirho> =
        OnceLock::new();
    FIXTURE_CHIRHO.get_or_init(|| {
        create_destination_authority_enrollment_test_fixture_chirho(
            "credits-demo-operator-smoke-chirho",
        )
    })
}

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration_chirho| u64::try_from(duration_chirho.as_millis()).ok())
        .unwrap_or(0)
}

/// Create test-only custody and database state, then drive the production prep APIs exactly as the
/// hosted runbook will. The caller supplies review-artifact paths inside the fresh root.
pub fn prepare_credits_demo_fixture_root_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    plan_path_chirho: &Path,
) -> Result<CreditsDemoFixtureInputsChirho> {
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create fixture root {}", root_chirho.display()))?;
    set_all_fixture_secrets_chirho(root_chirho)?;

    let db_name_chirho = fresh_pg_database_chirho()?;
    let result_chirho = prepare_fixture_after_database_chirho(
        root_chirho,
        config_path_chirho,
        plan_path_chirho,
        &db_name_chirho,
    );
    if result_chirho.is_err() {
        drop_fixture_database_chirho(&db_name_chirho);
    }
    result_chirho
}

fn prepare_fixture_after_database_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    plan_path_chirho: &Path,
    db_name_chirho: &str,
) -> Result<CreditsDemoFixtureInputsChirho> {
    let dsn_chirho = format!("host=/tmp port=5432 dbname={db_name_chirho}");
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DSN_SECRET_NAME_CHIRHO,
        dsn_chirho.as_bytes(),
    )?;
    prepare_credits_demo_provider_chirho(&CreditsDemoProviderPrepareRequestChirho {
        root_chirho,
        connection_secret_name_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO,
    })?;

    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        PAYER_CREDENTIAL_CHIRHO.as_bytes(),
    )?;
    let payer_chirho = identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        PAYER_CREDENTIAL_CHIRHO,
    )?
    .principal_chirho;

    let activation_authorization_path_chirho = plan_path_chirho
        .with_file_name(constants_chirho::ACTIVATION_AUTHORIZATION_FILE_NAME_CHIRHO);
    for output_chirho in [
        config_path_chirho,
        plan_path_chirho,
        &activation_authorization_path_chirho,
    ] {
        let parent_chirho = output_chirho
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture review output has no parent"))?;
        std::fs::create_dir_all(parent_chirho)
            .with_context(|| format!("create fixture review dir {}", parent_chirho.display()))?;
    }
    let author_report_chirho =
        author_credits_demo_inputs_chirho(&CreditsDemoInputsAuthorRequestChirho {
            root_chirho,
            payer_chirho: &payer_chirho,
            config_output_chirho: config_path_chirho,
            plan_output_chirho: plan_path_chirho,
            activation_authorization_output_chirho: &activation_authorization_path_chirho,
            issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
            payer_credential_secret_name_chirho:
                constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
            destination_authority_enrollment_chirho:
                &destination_authority_enrollment_fixture_chirho().verified_chirho,
            serve_port_chirho: 8798,
        })?;

    Ok(CreditsDemoFixtureInputsChirho {
        root_chirho: root_chirho.to_path_buf(),
        config_path_chirho: config_path_chirho.to_path_buf(),
        expected_config_digest_chirho: author_report_chirho.config_digest_chirho,
        plan_path_chirho: plan_path_chirho.to_path_buf(),
        expected_plan_digest_chirho: author_report_chirho.plan_digest_chirho,
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO.to_string(),
        activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: author_report_chirho
            .activation_authorization_digest_chirho,
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO.to_string(),
        payer_chirho,
        db_name_chirho: db_name_chirho.to_owned(),
    })
}

/// The config and plan for a payer who is NOT registered on the root, in the order an A3 voter
/// authors them before its setup registers the reviewed payer (C1 A3). The emission law is the
/// production author's own, without that author's registered-payer check. There is no database and
/// no activation authorization: the DSN secret is a placeholder nothing connects to. This carries
/// setup past every check before its authoring gate and no further. Returns the config digest and
/// the plan digest.
pub(super) fn prepare_unregistered_payer_fixture_root_chirho(
    root_chirho: &Path,
    config_path_chirho: &Path,
    plan_path_chirho: &Path,
    payer_chirho: &str,
) -> Result<(String, String)> {
    std::fs::create_dir_all(root_chirho)
        .with_context(|| format!("create fixture root {}", root_chirho.display()))?;
    set_all_fixture_secrets_chirho(root_chirho)?;
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DSN_SECRET_NAME_CHIRHO,
        b"host=/nonexistent-chirho port=1 dbname=unused_chirho",
    )?;
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        PAYER_CREDENTIAL_CHIRHO.as_bytes(),
    )?;
    for output_chirho in [config_path_chirho, plan_path_chirho] {
        let parent_chirho = output_chirho
            .parent()
            .ok_or_else(|| anyhow::anyhow!("fixture review output has no parent"))?;
        std::fs::create_dir_all(parent_chirho)
            .with_context(|| format!("create fixture review dir {}", parent_chirho.display()))?;
    }
    let emitted_chirho =
        author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
            selected_root_chirho: root_chirho,
            inputs_chirho: &credits_demo_authoring_inputs_chirho(payer_chirho),
            destination_authority_enrollment_chirho:
                &destination_authority_enrollment_fixture_chirho().verified_chirho,
            issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: Some(
                constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
            ),
            config_output_chirho: config_path_chirho,
            plan_output_chirho: plan_path_chirho,
            serve_port_chirho: 8798,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .map_err(|error_chirho| {
            anyhow::anyhow!("author the fixture host config and plan: {error_chirho:?}")
        })?;
    Ok((
        emitted_chirho.config_digest_chirho,
        emitted_chirho.plan_digest_chirho,
    ))
}

/// Best-effort teardown of the fixture's throwaway sanctioned PostgreSQL database.
pub fn drop_fixture_database_chirho(db_name_chirho: &str) {
    if let Ok(mut admin_chirho) = connect_pg_chirho("host=/tmp port=5432 dbname=postgres") {
        let _drop_result_chirho =
            admin_chirho.batch_execute(&format!("DROP DATABASE IF EXISTS {db_name_chirho}"));
    }
}

fn set_all_fixture_secrets_chirho(root_chirho: &Path) -> Result<()> {
    let seeds_chirho: [(&str, u8); 9] = [
        (
            constants_chirho::JOURNAL_SECRET_NAME_CHIRHO,
            JOURNAL_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::CONFIG_SECRET_NAME_CHIRHO,
            CONFIG_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::FEEDER_SECRET_NAME_CHIRHO,
            FEEDER_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
            KIND_ROOT_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO,
            EFFECT_INTENT_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
            EFFECT_TERMINAL_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
            ISSUER_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
            ACTIVATION_SECRET_SEED_CHIRHO,
        ),
        (
            constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
            ADAPTER_EVIDENCE_SEED_CHIRHO,
        ),
    ];
    for (name_chirho, seed_chirho) in seeds_chirho {
        cairn_chirho::secret_chirho::set_secret_chirho(
            root_chirho,
            name_chirho,
            &[seed_chirho; 32],
        )?;
    }
    Ok(())
}

pub(super) fn fresh_pg_database_chirho() -> Result<String> {
    let now_chirho = now_ms_chirho();
    let process_chirho = u64::from(std::process::id());
    let shifted_chirho = now_chirho
        .checked_shl(8)
        .ok_or_else(|| anyhow::anyhow!("fixture database suffix overflow"))?;
    let unique_chirho = format!("{now_chirho}_{}", process_chirho ^ shifted_chirho);
    let db_name_chirho = format!("cairn_credits_demo_localphaseb_{unique_chirho}_chirho");
    let mut admin_chirho = connect_pg_chirho("host=/tmp port=5432 dbname=postgres")?;
    let _drop_result_chirho =
        admin_chirho.batch_execute(&format!("DROP DATABASE IF EXISTS {db_name_chirho}"));
    admin_chirho
        .batch_execute(&format!("CREATE DATABASE {db_name_chirho}"))
        .with_context(|| format!("create sanctioned PostgreSQL database {db_name_chirho}"))?;
    Ok(db_name_chirho)
}
