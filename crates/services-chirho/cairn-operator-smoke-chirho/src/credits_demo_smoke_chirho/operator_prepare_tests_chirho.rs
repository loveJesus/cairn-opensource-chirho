// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::concurrency_token_chirho::{
    derive_credits_demo_concurrency_token_from_rows_chirho,
    read_credits_demo_concurrency_token_chirho, CreditsDemoConcurrencyTokenRequestChirho,
    CreditsDemoSeedRowChirho, CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
    CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO, CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO,
    CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO,
};
use super::constants_chirho;
use super::fixture_chirho;
use super::operator_prepare_chirho::{
    author_credits_demo_inputs_chirho, prepare_credits_demo_provider_chirho,
    CreditsDemoInputsAuthorRequestChirho, CreditsDemoProviderPrepareRequestChirho,
    CREDITS_DEMO_INPUTS_AUTHOR_REPORT_SCHEMA_CHIRHO,
    CREDITS_DEMO_PROVIDER_PREPARE_REPORT_SCHEMA_CHIRHO,
};
use super::setup_chirho::assert_dormant_finality_chirho;
use cairn_ledger_regenesis_chirho::{plan_digest_chirho, LedgerRegenesisPlanV1Chirho};
use cairn_postgres_effect_chirho::crypto_chirho::AdapterEvidenceKeyChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-{label_chirho}-{nanos_chirho}-{}-{counter_chirho}",
        std::process::id()
    ))
}

fn set_test_custody_chirho(root_chirho: &Path) -> String {
    let signer_names_chirho = [
        constants_chirho::JOURNAL_SECRET_NAME_CHIRHO,
        constants_chirho::CONFIG_SECRET_NAME_CHIRHO,
        constants_chirho::FEEDER_SECRET_NAME_CHIRHO,
        constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
    ];
    for (index_chirho, name_chirho) in signer_names_chirho.iter().enumerate() {
        let seed_chirho = u8::try_from(index_chirho + 1).expect("test signer seed");
        cairn_chirho::secret_chirho::set_secret_chirho(
            root_chirho,
            name_chirho,
            &[seed_chirho; 32],
        )
        .unwrap();
    }
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        &[0x71; 32],
    )
    .unwrap();
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        &[0x73; 32],
    )
    .unwrap();
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[0x72; 32],
    )
    .unwrap();
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DSN_SECRET_NAME_CHIRHO,
        b"host=/tmp port=5432 dbname=postgres",
    )
    .unwrap();
    let credential_chirho = "credits-demo-author-test-credential-chirho";
    cairn_chirho::secret_chirho::set_secret_chirho(
        root_chirho,
        constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        credential_chirho.as_bytes(),
    )
    .unwrap();
    cairn_chirho::identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        cairn_chirho::identity_chirho::PrincipalKindChirho::UserChirho,
        credential_chirho,
    )
    .unwrap()
    .principal_chirho
}

fn seed_row_chirho() -> CreditsDemoSeedRowChirho {
    CreditsDemoSeedRowChirho {
        subject_chirho: constants_chirho::FIXED_SUBJECT_CHIRHO.to_string(),
        row_key_chirho: constants_chirho::FIXED_ROW_KEY_CHIRHO.to_string(),
        value_chirho: constants_chirho::SEED_VALUE_CHIRHO.to_vec(),
    }
}

fn assert_named_refusal_chirho(
    error_chirho: &anyhow::Error,
    expected_chirho: &str,
    neighbors_chirho: &[&str],
) {
    let message_chirho = error_chirho.to_string();
    assert!(
        message_chirho.contains(expected_chirho),
        "expected {expected_chirho}, got {message_chirho}"
    );
    for neighbor_chirho in neighbors_chirho {
        assert!(
            !message_chirho.contains(neighbor_chirho),
            "{expected_chirho} was confused with neighboring {neighbor_chirho}: {message_chirho}"
        );
    }
}

#[test]
fn concurrency_token_derivation_names_cardinality_and_binding_refusals_chirho() {
    let adapter_key_chirho = AdapterEvidenceKeyChirho::new_chirho([0x33; 32]).unwrap();
    let valid_row_chirho = seed_row_chirho();
    let valid_token_chirho = derive_credits_demo_concurrency_token_from_rows_chirho(
        &adapter_key_chirho,
        std::slice::from_ref(&valid_row_chirho),
    )
    .unwrap();
    assert_eq!(valid_token_chirho.len(), 64);
    assert!(valid_token_chirho
        .chars()
        .all(|char_chirho| char_chirho.is_ascii_hexdigit() && !char_chirho.is_ascii_uppercase()));

    for rows_chirho in [
        Vec::<CreditsDemoSeedRowChirho>::new(),
        vec![valid_row_chirho.clone(), valid_row_chirho.clone()],
    ] {
        let error_chirho = derive_credits_demo_concurrency_token_from_rows_chirho(
            &adapter_key_chirho,
            &rows_chirho,
        )
        .unwrap_err();
        assert_named_refusal_chirho(
            &error_chirho,
            CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO,
            &[
                CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO,
            ],
        );
    }

    for hostile_row_chirho in [
        CreditsDemoSeedRowChirho {
            subject_chirho: "0".repeat(64),
            ..valid_row_chirho.clone()
        },
        CreditsDemoSeedRowChirho {
            row_key_chirho: "0".repeat(64),
            ..valid_row_chirho.clone()
        },
        CreditsDemoSeedRowChirho {
            value_chirho: b"wrong-seed-value-chirho".to_vec(),
            ..valid_row_chirho
        },
    ] {
        let error_chirho = derive_credits_demo_concurrency_token_from_rows_chirho(
            &adapter_key_chirho,
            &[hostile_row_chirho],
        )
        .unwrap_err();
        assert_named_refusal_chirho(
            &error_chirho,
            CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
            &[
                CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO,
            ],
        );
    }
}

#[test]
fn wrong_seed_mutation_refuses_instead_of_returning_a_different_token_chirho() {
    let adapter_key_chirho = AdapterEvidenceKeyChirho::new_chirho([0x33; 32]).unwrap();
    let valid_row_chirho = seed_row_chirho();
    let valid_token_chirho = derive_credits_demo_concurrency_token_from_rows_chirho(
        &adapter_key_chirho,
        std::slice::from_ref(&valid_row_chirho),
    )
    .unwrap();

    let mut mutated_row_chirho = valid_row_chirho;
    mutated_row_chirho.value_chirho[0] ^= 0xff;
    assert_ne!(
        mutated_row_chirho.value_chirho,
        constants_chirho::SEED_VALUE_CHIRHO,
        "mutation must apply before the refusal arm runs"
    );
    let result_chirho = derive_credits_demo_concurrency_token_from_rows_chirho(
        &adapter_key_chirho,
        &[mutated_row_chirho],
    );
    let error_chirho = result_chirho
        .expect_err("wrong seed must named-refuse instead of producing any replacement token");
    assert_named_refusal_chirho(
        &error_chirho,
        CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
        &[CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO],
    );
    assert!(
        !error_chirho.to_string().contains(&valid_token_chirho),
        "binding refusal must not disclose the valid concurrency token"
    );
}

#[test]
fn concurrency_token_command_refuses_missing_custody_before_provider_access_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-token-missing-custody");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let error_chirho =
        read_credits_demo_concurrency_token_chirho(&CreditsDemoConcurrencyTokenRequestChirho {
            root_chirho: &root_chirho,
            connection_secret_name_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO,
        })
        .unwrap_err();
    assert_named_refusal_chirho(
        &error_chirho,
        CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO,
        &[
            CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO,
            CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO,
            CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
        ],
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn concurrency_token_source_has_one_derivation_and_no_mutation_surface_chirho() {
    let workspace_chirho = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let token_source_chirho = std::fs::read_to_string(
        workspace_chirho.join(
            "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/concurrency_token_chirho.rs",
        ),
    )
    .unwrap();
    assert_eq!(
        token_source_chirho
            .matches("row_fingerprint_chirho(")
            .count(),
        1,
        "money-token derivation must have exactly one production spelling"
    );
    for forbidden_chirho in [
        "INSERT INTO",
        "UPDATE cairn_",
        "DELETE FROM",
        "begin_serializable_transaction_chirho",
        "set_secret_chirho(",
        "run_credits_demo_wire_chirho",
        "effect_intent_key_chirho",
    ] {
        assert!(
            !token_source_chirho.contains(forbidden_chirho),
            "read-only token module gained mutation surface {forbidden_chirho}"
        );
    }
    let setup_source_chirho = std::fs::read_to_string(
        workspace_chirho.join(
            "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/setup_chirho.rs",
        ),
    )
    .unwrap();
    assert!(setup_source_chirho.contains("read_credits_demo_concurrency_token_from_dsn_chirho("));
    assert!(
        !setup_source_chirho.contains("row_fingerprint_chirho("),
        "smoke preflight must consume the shared derivation, never copy it"
    );
}

/// A payer credential named a runtime SIGNING authority by one leading space must be refused.
///
/// Measured at the defect's base: `author_credits_demo_inputs_chirho` ACCEPTED
/// `" credits-demo-kind-root-secret-chirho"`, and that name resolved byte-identical bytes to the
/// kind-root signing key. The custody road's pairwise-distinct law compares the RAW supplied
/// string, so it structurally could not see the collision — the secret-name validator was trimming
/// underneath it. The refusal therefore belongs to the validator's own law, NOT to the distinctness
/// law, which is what the neighbor assertion below pins.
///
/// Migration path: if this arm ever fails because the message is now the pairwise-distinct
/// refusal, the whitespace law was removed from the validator and each raw comparison is again
/// carrying custody separation on its own — retarget at whatever normalizes the name, and check
/// every OTHER raw comparison too. If it fails because the call was ACCEPTED, the defect regressed.
#[test]
fn inputs_author_refuses_a_payer_credential_spelling_a_signer_by_one_space_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-whitespace-collision");
    let review_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    std::fs::create_dir_all(&review_dir_chirho).unwrap();
    let payer_chirho = set_test_custody_chirho(&root_chirho);
    let colliding_chirho = format!(" {}", constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO);
    assert_ne!(
        colliding_chirho,
        constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        "the fixture must differ from the signer name as a RAW string, or it pins nothing"
    );

    let hostile_plan_chirho = review_dir_chirho.join("hostile-plan-chirho.json");
    let hostile_config_chirho = review_dir_chirho.join("hostile-config-chirho.toml");
    let hostile_authorization_chirho = review_dir_chirho.join("hostile-activation-chirho.json");
    let hostile_request_chirho = CreditsDemoInputsAuthorRequestChirho {
        root_chirho: &root_chirho,
        payer_chirho: &payer_chirho,
        config_output_chirho: &hostile_config_chirho,
        plan_output_chirho: &hostile_plan_chirho,
        activation_authorization_output_chirho: &hostile_authorization_chirho,
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho: &colliding_chirho,
        destination_authority_enrollment_chirho:
            &fixture_chirho::destination_authority_enrollment_fixture_chirho().verified_chirho,
        serve_port_chirho: 8798,
    };
    let refusal_chirho = author_credits_demo_inputs_chirho(&hostile_request_chirho).unwrap_err();
    assert_named_refusal_chirho(
        &refusal_chirho,
        cairn_chirho::secret_chirho::SECRET_NAME_SURROUNDING_WHITESPACE_REFUSAL_CHIRHO,
        &["credits-demo authority secret refs must be pairwise distinct"],
    );
    for output_chirho in [
        &hostile_plan_chirho,
        &hostile_config_chirho,
        &hostile_authorization_chirho,
    ] {
        assert!(
            !output_chirho.exists(),
            "the refusal must land before any review artifact is authored"
        );
    }

    // Positive control: the SAME road, same root, same fixture — the payer credential name without
    // the leading space is still accepted, so the arm above pins the whitespace and nothing else.
    let clean_request_chirho = CreditsDemoInputsAuthorRequestChirho {
        config_output_chirho: &review_dir_chirho.join("clean-config-chirho.toml"),
        plan_output_chirho: &review_dir_chirho.join("clean-plan-chirho.json"),
        activation_authorization_output_chirho: &review_dir_chirho
            .join("clean-activation-chirho.json"),
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        ..hostile_request_chirho
    };
    let report_chirho = author_credits_demo_inputs_chirho(&clean_request_chirho).unwrap();
    assert!(report_chirho.existing_secret_custody_verified_chirho);

    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn inputs_author_uses_existing_custody_and_refuses_overwrite_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-inputs-author");
    let review_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    std::fs::create_dir_all(&review_dir_chirho).unwrap();
    let payer_chirho = set_test_custody_chirho(&root_chirho);
    let plan_path_chirho = review_dir_chirho.join("plan-chirho.json");
    let config_path_chirho = review_dir_chirho.join("config-chirho.toml");
    let activation_authorization_path_chirho =
        review_dir_chirho.join("activation-authorization-chirho.json");
    let request_chirho = CreditsDemoInputsAuthorRequestChirho {
        root_chirho: &root_chirho,
        payer_chirho: &payer_chirho,
        config_output_chirho: &config_path_chirho,
        plan_output_chirho: &plan_path_chirho,
        activation_authorization_output_chirho: &activation_authorization_path_chirho,
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        destination_authority_enrollment_chirho:
            &fixture_chirho::destination_authority_enrollment_fixture_chirho().verified_chirho,
        serve_port_chirho: 8798,
    };

    let report_chirho = author_credits_demo_inputs_chirho(&request_chirho).unwrap();
    assert_eq!(
        report_chirho.schema_chirho,
        CREDITS_DEMO_INPUTS_AUTHOR_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.payer_chirho, payer_chirho);
    assert!(report_chirho.existing_identity_verified_chirho);
    assert!(report_chirho.existing_secret_custody_verified_chirho);
    assert_eq!(report_chirho.signer_secret_ref_count_chirho, 6);
    assert_eq!(report_chirho.provider_secret_ref_count_chirho, 2);
    let authorization_bytes_chirho = std::fs::read(&activation_authorization_path_chirho).unwrap();
    assert_eq!(
        report_chirho.activation_authorization_digest_chirho,
        cairn_ledger_host_chirho::resident_ledger_activation_authorization_digest_chirho(
            &authorization_bytes_chirho
        )
    );
    cairn_ledger_host_chirho::parse_canonical_resident_ledger_activation_authorization_chirho(
        &authorization_bytes_chirho,
    )
    .unwrap();

    let plan_bytes_chirho = std::fs::read(&plan_path_chirho).unwrap();
    let plan_chirho: LedgerRegenesisPlanV1Chirho =
        serde_json::from_slice(&plan_bytes_chirho).unwrap();
    assert_eq!(plan_chirho.initial_owner_chirho, payer_chirho);
    assert_eq!(plan_chirho.initial_mint_amount_chirho, 750);
    assert_eq!(
        report_chirho.plan_digest_chirho,
        plan_digest_chirho(&plan_bytes_chirho)
    );

    let config_chirho = cairn_chirho::config_chirho::load_config_chirho(&config_path_chirho)
        .expect("parse authored config");
    assert_eq!(config_chirho.port_chirho, 8798);
    assert_eq!(
        Path::new(&config_chirho.root_chirho)
            .canonicalize()
            .unwrap(),
        root_chirho.canonicalize().unwrap()
    );
    cairn_ledger_host_chirho::verify_host_ledger_config_custody_chirho(
        &root_chirho,
        &config_path_chirho,
    )
    .unwrap();
    #[cfg(unix)]
    for output_chirho in [
        &plan_path_chirho,
        &config_path_chirho,
        &activation_authorization_path_chirho,
    ] {
        use std::os::unix::fs::PermissionsExt;
        let mode_chirho = std::fs::metadata(output_chirho)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode_chirho, 0o600);
    }

    let plan_before_chirho = plan_bytes_chirho;
    let config_before_chirho = std::fs::read(&config_path_chirho).unwrap();
    let authorization_before_chirho = authorization_bytes_chirho;
    let refusal_chirho = author_credits_demo_inputs_chirho(&request_chirho).unwrap_err();
    assert!(refusal_chirho.to_string().contains("refusing overwrite"));
    assert_eq!(
        std::fs::read(&plan_path_chirho).unwrap(),
        plan_before_chirho
    );
    assert_eq!(
        std::fs::read(&config_path_chirho).unwrap(),
        config_before_chirho
    );
    assert_eq!(
        std::fs::read(&activation_authorization_path_chirho).unwrap(),
        authorization_before_chirho
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn smoke_source_cannot_reach_operator_provisioning_chirho() {
    let workspace_chirho = crate::workspace_root_for_operator_smoke_chirho();
    let smoke_dir_chirho = workspace_chirho
        .join("crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho");
    let mut production_paths_chirho = vec![workspace_chirho.join(
        "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho.rs",
    )];
    for entry_chirho in std::fs::read_dir(&smoke_dir_chirho).unwrap() {
        let entry_chirho = entry_chirho.unwrap();
        let file_name_chirho = entry_chirho.file_name();
        if entry_chirho.file_type().unwrap().is_file()
            && entry_chirho
                .path()
                .extension()
                .is_some_and(|extension_chirho| extension_chirho == "rs")
            && ![
                "fixture_chirho.rs",
                "operator_prepare_chirho.rs",
                "operator_prepare_tests_chirho.rs",
                "tests_chirho.rs",
            ]
            .contains(&file_name_chirho.to_string_lossy().as_ref())
        {
            production_paths_chirho.push(entry_chirho.path());
        }
    }
    production_paths_chirho.sort();
    for path_chirho in production_paths_chirho {
        let relative_chirho = path_chirho
            .strip_prefix(&workspace_chirho)
            .unwrap_or(&path_chirho)
            .display();
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for forbidden_chirho in [
            "prepare_credits_demo_provider_chirho(",
            "install_reversible_postgres_schema_chirho(",
            "INSERT INTO cairn_reversible_values_chirho",
        ] {
            assert!(
                !source_chirho.contains(forbidden_chirho),
                "smoke evidence path {relative_chirho} reached provider preparation via {forbidden_chirho}"
            );
        }
    }

    let prepare_source_chirho = std::fs::read_to_string(
        workspace_chirho.join(
            "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/operator_prepare_chirho.rs",
        ),
    )
    .unwrap();
    assert!(!prepare_source_chirho.contains("DROP DATABASE"));
    assert!(!prepare_source_chirho.contains("CREATE DATABASE"));
    assert!(!prepare_source_chirho.contains("set_secret_chirho("));
}

#[test]
#[ignore = "requires sanctioned local PostgreSQL (host=/tmp port=5432)"]
fn provider_prepare_establishes_once_and_then_refuses_preexisting_schema_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-provider-prepare");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let db_name_chirho = fixture_chirho::fresh_pg_database_chirho().unwrap();
    let result_chirho = (|| -> anyhow::Result<()> {
        let dsn_chirho = format!("host=/tmp port=5432 dbname={db_name_chirho}");
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            constants_chirho::DSN_SECRET_NAME_CHIRHO,
            dsn_chirho.as_bytes(),
        )?;
        let request_chirho = CreditsDemoProviderPrepareRequestChirho {
            root_chirho: &root_chirho,
            connection_secret_name_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO,
        };
        let report_chirho = prepare_credits_demo_provider_chirho(&request_chirho)?;
        assert_eq!(
            report_chirho.schema_chirho,
            CREDITS_DEMO_PROVIDER_PREPARE_REPORT_SCHEMA_CHIRHO
        );
        assert!(report_chirho.operator_established_chirho);
        assert!(!report_chirho.cairn_minted_chirho);
        assert!(report_chirho.established_outside_smoke_run_chirho);
        assert_eq!(report_chirho.total_values_rows_chirho, 1);
        assert_eq!(report_chirho.target_values_rows_chirho, 1);
        assert_eq!(report_chirho.forward_decision_rows_chirho, 0);
        assert_eq!(report_chirho.compensation_receipt_rows_chirho, 0);
        let refusal_chirho = prepare_credits_demo_provider_chirho(&request_chirho).unwrap_err();
        assert!(refusal_chirho.to_string().contains("preexisting table"));
        Ok(())
    })();
    fixture_chirho::drop_fixture_database_chirho(&db_name_chirho);
    let _remove_result_chirho = std::fs::remove_dir_all(root_chirho);
    result_chirho.unwrap();
}

#[test]
#[ignore = "requires sanctioned local PostgreSQL (host=/tmp port=5432)"]
fn operator_token_matches_smoke_preflight_without_mutating_provider_state_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-concurrency-token");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let db_name_chirho = fixture_chirho::fresh_pg_database_chirho().unwrap();
    let result_chirho = (|| -> anyhow::Result<()> {
        let dsn_chirho = format!("host=/tmp port=5432 dbname={db_name_chirho}");
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            constants_chirho::DSN_SECRET_NAME_CHIRHO,
            dsn_chirho.as_bytes(),
        )?;
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
            &[0x33; 32],
        )?;
        let request_chirho = CreditsDemoConcurrencyTokenRequestChirho {
            root_chirho: &root_chirho,
            connection_secret_name_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO,
        };

        let schema_error_chirho =
            read_credits_demo_concurrency_token_chirho(&request_chirho).unwrap_err();
        assert_named_refusal_chirho(
            &schema_error_chirho,
            CONCURRENCY_TOKEN_SCHEMA_REFUSAL_CHIRHO,
            &[
                CONCURRENCY_TOKEN_CUSTODY_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_ROW_COUNT_REFUSAL_CHIRHO,
                CONCURRENCY_TOKEN_BINDING_REFUSAL_CHIRHO,
            ],
        );

        prepare_credits_demo_provider_chirho(&CreditsDemoProviderPrepareRequestChirho {
            root_chirho: &root_chirho,
            connection_secret_name_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO,
        })?;

        let snapshot_chirho = || -> anyhow::Result<Vec<i64>> {
            let mut client_chirho = super::setup_chirho::connect_pg_chirho(&dsn_chirho)?;
            [
                "cairn_reversible_values_chirho",
                "cairn_reversible_forward_decisions_chirho",
                "cairn_reversible_comp_receipts_chirho",
            ]
            .iter()
            .map(|table_chirho| {
                client_chirho
                    .query_one(&format!("SELECT count(*)::bigint FROM {table_chirho}"), &[])
                    .map(|row_chirho| row_chirho.get(0))
                    .map_err(anyhow::Error::from)
            })
            .collect()
        };
        let before_chirho = snapshot_chirho()?;
        assert_eq!(before_chirho, vec![1, 0, 0]);

        let operator_token_chirho = read_credits_demo_concurrency_token_chirho(&request_chirho)?;
        let smoke_preflight_chirho =
            super::setup_chirho::verify_external_preconditions_chirho(&dsn_chirho, &root_chirho)?;
        assert_eq!(
            operator_token_chirho,
            smoke_preflight_chirho.l2_spend_concurrency_token_chirho
        );
        assert_eq!(
            operator_token_chirho,
            smoke_preflight_chirho.seed_before_state_fingerprint_chirho
        );
        assert_eq!(
            snapshot_chirho()?,
            before_chirho,
            "token command and smoke preflight must perform zero provider mutations"
        );
        Ok(())
    })();
    fixture_chirho::drop_fixture_database_chirho(&db_name_chirho);
    let _remove_result_chirho = std::fs::remove_dir_all(root_chirho);
    result_chirho.unwrap();
}

/// The PRE-MIGRATION config builder, frozen as a `#[cfg(test)]` reference.
///
/// This is a transcription of `canonical_localphaseb_config_bytes_chirho` exactly as it stood at
/// `355ef306`, the commit before brick #7 replaced it with a call to the generic custody-bound
/// author. It exists for one purpose: to make "the migration changed no emitted byte" an executable
/// assertion instead of a claim. It must never be edited to follow the production code — if it and
/// the emitted bytes disagree, the emitted bytes changed, and that is a money-authority artifact
/// changing shape.
///
/// The two verifier pins are parameters because they are derived from the root's secrets by
/// whichever road ran; passing the emitted config's own pins makes this comparison a statement about
/// every OTHER byte — the schema, the coordinates, the membership order, the route order, the
/// signer-ref block, the postgres block, and the absence of a test-kind marker.
fn frozen_pre_migration_config_bytes_chirho(
    canonical_root_chirho: &Path,
    payer_chirho: &str,
    serve_port_chirho: u16,
    issuer_pin_chirho: String,
    activation_pin_chirho: String,
) -> Vec<u8> {
    use cairn_chirho::config_chirho::{
        serialize_config_chirho, ConfigChirho, LedgerHostActivationPinConfigChirho,
        LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho, LedgerHostMemberConfigChirho,
        LedgerHostPostgresEffectConfigChirho, LedgerHostPostgresEffectPostureChirho,
        LedgerHostProjectionRouteConfigChirho, LedgerHostSignerRefsConfigChirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO, LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
    };
    let mut config_chirho = ConfigChirho::default();
    config_chirho.root_chirho = canonical_root_chirho.to_str().unwrap().to_owned();
    config_chirho.port_chirho = serve_port_chirho;
    config_chirho.ledger_host_chirho = Some(LedgerHostConfigChirho {
        schema_chirho: LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO.to_owned(),
        storage_namespace_chirho: constants_chirho::STORAGE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_namespace_chirho: constants_chirho::MONITOR_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: constants_chirho::MONITOR_EVIDENCE_PATH_CHIRHO.to_owned(),
        money_group_id_chirho: constants_chirho::MONEY_GROUP_ID_CHIRHO.to_owned(),
        cluster_id_chirho: constants_chirho::CLUSTER_ID_CHIRHO.to_owned(),
        journal_path_chirho: constants_chirho::JOURNAL_PATH_CHIRHO.to_owned(),
        local_epoch_chirho: constants_chirho::LOCAL_EPOCH_CHIRHO,
        members_chirho: vec![
            LedgerHostMemberConfigChirho {
                owner_chirho: payer_chirho.to_owned(),
                kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
            },
            LedgerHostMemberConfigChirho {
                owner_chirho: constants_chirho::SETTLEMENT_OWNER_CHIRHO.to_owned(),
                kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
            },
        ],
        kind_registry_path_chirho: constants_chirho::KIND_REGISTRY_PATH_CHIRHO.to_owned(),
        kind_registry_id_chirho: constants_chirho::KIND_REGISTRY_ID_CHIRHO.to_owned(),
        kind_issuer_chirho: LedgerHostIssuerPinConfigChirho {
            principal_chirho: constants_chirho::ISSUER_PRINCIPAL_CHIRHO.to_owned(),
            verifying_key_hex_chirho: issuer_pin_chirho,
        },
        activation_authority_chirho: Some(LedgerHostActivationPinConfigChirho {
            principal_chirho: constants_chirho::ACTIVATION_PRINCIPAL_CHIRHO.to_owned(),
            verifying_key_hex_chirho: activation_pin_chirho,
        }),
        projection_registry_path_chirho: constants_chirho::PROJECTION_REGISTRY_PATH_CHIRHO
            .to_owned(),
        projection_registry_id_chirho: constants_chirho::PROJECTION_REGISTRY_ID_CHIRHO.to_owned(),
        source_registry_path_chirho: constants_chirho::SOURCE_REGISTRY_PATH_CHIRHO.to_owned(),
        source_registry_id_chirho: constants_chirho::SOURCE_REGISTRY_ID_CHIRHO.to_owned(),
        projection_routes_chirho: vec![
            LedgerHostProjectionRouteConfigChirho {
                projection_name_chirho: constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::BALANCE_HEAD_PATH_CHIRHO.to_owned(),
            },
            LedgerHostProjectionRouteConfigChirho {
                projection_name_chirho: constants_chirho::MIRROR_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::MIRROR_HEAD_PATH_CHIRHO.to_owned(),
            },
        ],
        signer_secrets_chirho: LedgerHostSignerRefsConfigChirho {
            journal_chirho: constants_chirho::JOURNAL_SECRET_NAME_CHIRHO.to_owned(),
            config_chirho: constants_chirho::CONFIG_SECRET_NAME_CHIRHO.to_owned(),
            feeder_chirho: constants_chirho::FEEDER_SECRET_NAME_CHIRHO.to_owned(),
            kind_root_chirho: constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO.to_owned(),
            effect_intent_chirho: constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO.to_owned(),
            effect_terminal_chirho: constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO.to_owned(),
        },
        held_verifier_pins_chirho: None,
        migration_destination_authority_chirho: None,
        monitor_cadence_ms_chirho: constants_chirho::MONITOR_CADENCE_MS_CHIRHO,
        postgres_effect_chirho: Some(LedgerHostPostgresEffectConfigChirho {
            schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
            posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
            connection_secret_chirho: constants_chirho::DSN_SECRET_NAME_CHIRHO.to_owned(),
            billing_kind_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
        }),
        control_plane_chirho: None,
        test_kind_chirho: None,
        adopt_migrated_root_chirho: false,
    });
    serialize_config_chirho(&config_chirho)
        .unwrap()
        .into_bytes()
}

/// The PRE-MIGRATION plan builder, frozen for the same reason and under the same rule.
fn frozen_pre_migration_plan_bytes_chirho(payer_principal_chirho: &str) -> Vec<u8> {
    use cairn_kind_registry_chirho::record_chirho::{
        IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
    };
    use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
    use cairn_ledger_regenesis_chirho::{
        canonical_plan_bytes_chirho, LedgerRegenesisProjectionRoutePlanChirho,
        LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
    };
    let policy_chirho = |max_supply_chirho: u64| KindPolicyBodyChirho {
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
    };
    let plan_chirho = LedgerRegenesisPlanV1Chirho {
        schema_chirho: LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: constants_chirho::FRESH_PARENT_CHIRHO.to_owned(),
        staging_parent_chirho: constants_chirho::STAGING_PARENT_CHIRHO.to_owned(),
        storage_namespace_chirho: constants_chirho::STORAGE_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_namespace_chirho: constants_chirho::MONITOR_NAMESPACE_CHIRHO.to_owned(),
        monitor_evidence_path_chirho: constants_chirho::MONITOR_EVIDENCE_PATH_CHIRHO.to_owned(),
        money_group_id_chirho: constants_chirho::MONEY_GROUP_ID_CHIRHO.to_owned(),
        cluster_id_chirho: constants_chirho::CLUSTER_ID_CHIRHO.to_owned(),
        journal_path_chirho: constants_chirho::JOURNAL_PATH_CHIRHO.to_owned(),
        local_epoch_chirho: constants_chirho::LOCAL_EPOCH_CHIRHO,
        kind_registry_path_chirho: constants_chirho::KIND_REGISTRY_PATH_CHIRHO.to_owned(),
        kind_registry_id_chirho: constants_chirho::KIND_REGISTRY_ID_CHIRHO.to_owned(),
        projection_registry_path_chirho: constants_chirho::PROJECTION_REGISTRY_PATH_CHIRHO
            .to_owned(),
        projection_registry_id_chirho: constants_chirho::PROJECTION_REGISTRY_ID_CHIRHO.to_owned(),
        source_registry_path_chirho: constants_chirho::SOURCE_REGISTRY_PATH_CHIRHO.to_owned(),
        source_registry_id_chirho: constants_chirho::SOURCE_REGISTRY_ID_CHIRHO.to_owned(),
        projection_routes_chirho: vec![
            LedgerRegenesisProjectionRoutePlanChirho {
                projection_name_chirho: constants_chirho::BALANCE_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::BALANCE_HEAD_PATH_CHIRHO.to_owned(),
            },
            LedgerRegenesisProjectionRoutePlanChirho {
                projection_name_chirho: constants_chirho::MIRROR_PROJECTION_NAME_CHIRHO.to_owned(),
                head_path_chirho: constants_chirho::MIRROR_HEAD_PATH_CHIRHO.to_owned(),
            },
        ],
        monitor_cadence_ms_chirho: constants_chirho::MONITOR_CADENCE_MS_CHIRHO,
        issuer_principal_chirho: constants_chirho::ISSUER_PRINCIPAL_CHIRHO.to_owned(),
        initial_owner_chirho: payer_principal_chirho.to_owned(),
        kind_id_chirho: constants_chirho::BILLING_KIND_CHIRHO.to_owned(),
        initial_policy_chirho: policy_chirho(2_000),
        amended_policy_chirho: policy_chirho(1_500),
        initial_mint_amount_chirho: constants_chirho::INITIAL_MINT_AMOUNT_CHIRHO,
        genesis_physical_ms_chirho: constants_chirho::GENESIS_PHYSICAL_MS_CHIRHO,
        mint_physical_ms_chirho: constants_chirho::MINT_PHYSICAL_MS_CHIRHO,
    };
    canonical_plan_bytes_chirho(&plan_chirho).unwrap()
}

#[test]
fn dormancy_gate_refuses_current_mint_and_accepts_aged_plan_chirho() {
    let mut plan_chirho: LedgerRegenesisPlanV1Chirho = serde_json::from_slice(
        &frozen_pre_migration_plan_bytes_chirho("user/1706dd117e5700a1"),
    )
    .unwrap();
    let now_chirho = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_millis(),
    )
    .expect("test clock fits u64 milliseconds");
    let gap_chirho = 60_000;
    plan_chirho.genesis_physical_ms_chirho = now_chirho - gap_chirho;
    plan_chirho.mint_physical_ms_chirho = now_chirho;

    let fresh_error_chirho = assert_dormant_finality_chirho(&plan_chirho)
        .expect_err("Cf8DormantPlanFreshMintMutationSurvivedChirho");
    assert_eq!(
        fresh_error_chirho.to_string(),
        "regenesis plan mint is not dormant beyond the retry-finality horizon; a non-dormant plan would settle trivially and cannot prove the committed-hlc finality seam"
    );

    plan_chirho.mint_physical_ms_chirho =
        now_chirho - constants_chirho::RETRY_FINALITY_HORIZON_MS_CHIRHO - 1;
    plan_chirho.genesis_physical_ms_chirho = plan_chirho.mint_physical_ms_chirho - gap_chirho;
    let posture_chirho =
        assert_dormant_finality_chirho(&plan_chirho).expect("Cf8DormantPlanAgedMintRefusedChirho");
    assert!(posture_chirho.mint_age_exceeds_horizon_chirho);
    assert!(posture_chirho.dormant_beyond_horizon_chirho);
    assert_eq!(
        posture_chirho.retry_finality_horizon_ms_chirho,
        constants_chirho::RETRY_FINALITY_HORIZON_MS_CHIRHO
    );
}

/// **Brick #7 plus enrollment: the reviewed destination pin is the only config-byte change.**
///
/// A migration that silently changes a money-authority artifact is worse than no migration. The plan
/// remains byte-identical to the frozen pre-migration builder. The config now intentionally adds one
/// reviewed, public-only destination-authority section; removing exactly that section from the
/// emitted value must recover the frozen bytes, and the section itself is checked against the real
/// external enrollment key rather than against its own contents.
///
/// **Scope, stated because a wider claim would be false.** Byte-identity is asserted for the config
/// and the plan — the two artifacts §5 row 7 names, and the two the generic road authors. It is NOT
/// asserted for the third artifact, the pre-signed activation authorization: measured directly,
/// that artifact and the report differ between two runs of the SAME code, because the activation
/// statement binds the operator root's device and inode, its canonical-path digest, and an elected
/// node id. A byte-identity claim about it would be unfalsifiable-by-construction rather than
/// strong.
#[test]
fn enrollment_changes_only_the_reviewed_destination_pin_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-byte-identity");
    let review_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    std::fs::create_dir_all(&review_dir_chirho).unwrap();
    let payer_chirho = set_test_custody_chirho(&root_chirho);
    let plan_path_chirho = review_dir_chirho.join("plan-chirho.json");
    let config_path_chirho = review_dir_chirho.join("config-chirho.toml");
    let activation_path_chirho = review_dir_chirho.join("activation-authorization-chirho.json");
    let enrollment_fixture_chirho =
        fixture_chirho::destination_authority_enrollment_fixture_chirho();
    author_credits_demo_inputs_chirho(&CreditsDemoInputsAuthorRequestChirho {
        root_chirho: &root_chirho,
        payer_chirho: &payer_chirho,
        config_output_chirho: &config_path_chirho,
        plan_output_chirho: &plan_path_chirho,
        activation_authorization_output_chirho: &activation_path_chirho,
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        destination_authority_enrollment_chirho: &enrollment_fixture_chirho.verified_chirho,
        serve_port_chirho: 8798,
    })
    .unwrap();

    let emitted_plan_chirho = std::fs::read(&plan_path_chirho).unwrap();
    assert_eq!(
        emitted_plan_chirho,
        frozen_pre_migration_plan_bytes_chirho(&payer_chirho),
        "the migrated author emitted different PLAN bytes than the pre-migration builder; the \
         reviewed regenesis plan is a money-authority artifact, so this is a content change rather \
         than a refactor. Fix the derivation or the input document — never this frozen reference."
    );

    // The pins come from the emitted config itself, so this comparison is about every other byte.
    // They are then checked against the custody road's own derivation below, which is what stops
    // "take the pins from the artifact" becoming a way to pass while the pins are wrong.
    let mut parsed_chirho =
        cairn_chirho::config_chirho::load_config_chirho(&config_path_chirho).unwrap();
    let (
        issuer_pin_chirho,
        activation_pin_chirho,
        destination_pin_chirho,
        schema_chirho,
        test_kind_chirho,
    ) = {
        let ledger_host_chirho = parsed_chirho.ledger_host_chirho.as_ref().unwrap();
        (
            ledger_host_chirho
                .kind_issuer_chirho
                .verifying_key_hex_chirho
                .clone(),
            ledger_host_chirho
                .activation_authority_chirho
                .as_ref()
                .unwrap()
                .verifying_key_hex_chirho
                .clone(),
            ledger_host_chirho
                .migration_destination_authority_chirho
                .as_ref()
                .expect("the enrolled destination authority is emitted")
                .clone(),
            ledger_host_chirho.schema_chirho.clone(),
            ledger_host_chirho.test_kind_chirho.clone(),
        )
    };
    parsed_chirho
        .ledger_host_chirho
        .as_mut()
        .unwrap()
        .migration_destination_authority_chirho = None;
    let config_without_enrollment_chirho =
        cairn_chirho::config_chirho::serialize_config_chirho(&parsed_chirho)
            .unwrap()
            .into_bytes();
    assert_eq!(
        config_without_enrollment_chirho,
        frozen_pre_migration_config_bytes_chirho(
            &root_chirho.canonicalize().unwrap(),
            &payer_chirho,
            8798,
            issuer_pin_chirho.clone(),
            activation_pin_chirho.clone(),
        ),
        "the enrolled author changed CONFIG bytes outside the one new destination-authority \
         section. Fix the derivation or reviewed inputs — never the frozen reference."
    );

    // The pins themselves, checked against the fixture's known secrets rather than against the
    // artifact. `set_test_custody_chirho` seeds the offline issuer with `[0x71; 32]` and the
    // activation authority with `[0x73; 32]`; these are their ed25519 public halves, so a
    // derivation that started pinning some other key would fail here even though the byte
    // comparisons above take their pins from the emitted file.
    assert_eq!(
        issuer_pin_chirho, "e2fe2a39b7326642827d6d82d497622cd6c297fe78270eaa436b01f086b6f3cb",
        "the emitted issuer pin is no longer the public half of the fixture's issuer secret"
    );
    assert_eq!(
        activation_pin_chirho,
        "fec1428673f6afe89264b3807344ae8b269d125a503855202687db5a7128579f",
        "the emitted activation pin is no longer the public half of the fixture's activation secret"
    );
    let expected_destination_pubkey_chirho = std::fs::read_to_string(
        enrollment_fixture_chirho
            .destination_authority_signing_root_chirho
            .join("pubkey-chirho.hex"),
    )
    .unwrap();
    let expected_destination_pubkey_chirho = expected_destination_pubkey_chirho.trim();
    assert_eq!(
        destination_pin_chirho.key_id_chirho, expected_destination_pubkey_chirho,
        "the destination key id must be the reviewed external public key, not a friendly label"
    );
    assert_eq!(
        destination_pin_chirho.verifying_key_hex_chirho, expected_destination_pubkey_chirho,
        "the emitted destination pin is not the public half of the enrolled external key"
    );
    assert_eq!(schema_chirho, "ledger-host-config-v2-chirho");
    assert!(
        test_kind_chirho.is_none(),
        "the credits demo authors a PRODUCTION-shaped config; a test-kind marker here would mean \
         the migration changed the artifact's posture to make a check pass"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// **The gap brick #7 closes, pinned directly: a SEVENTH name over a runtime signer's OWN 32 bytes.**
///
/// The offline issuer secret is seeded with the same value as the runtime `kind_root_chirho` signer,
/// under a different name. Every name stays pairwise distinct, so a name comparison sees nothing —
/// which is exactly why the pre-migration road authored it. Measured at `355ef306` before this
/// brick: that road ACCEPTED this fixture and wrote a bootable config pinning
/// `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c` — the `kind_root_chirho`
/// signer's own identity — as the mint authority's outer trust root, collapsing the kind registry's
/// two-root containment into one root.
///
/// The neighbouring refusals are excluded by name, because "issuer secret name collides" and
/// "issuer identity collides" are similar-shaped errors and a fixture aimed at one can pass on the
/// other.
#[test]
fn same_bytes_different_name_issuer_is_refused_and_writes_nothing_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-same-bytes-issuer");
    let review_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    std::fs::create_dir_all(&review_dir_chirho).unwrap();
    let payer_chirho = set_test_custody_chirho(&root_chirho);
    // The ONLY change from the green fixture. `set_test_custody_chirho` seeds the six runtime
    // signers with `[1; 32]` … `[6; 32]` in role order, so `[4; 32]` is `kind_root_chirho`.
    cairn_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        &[4_u8; 32],
    )
    .unwrap();
    let kind_root_secret_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        &root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(
            constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        )
        .unwrap(),
    )
    .unwrap();
    let issuer_secret_chirho = cairn_chirho::secret_chirho::resolve_secret_ref_chirho(
        &root_chirho,
        &cairn_chirho::secret_chirho::secret_ref_chirho(
            constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        )
        .unwrap(),
    )
    .unwrap();
    // The fixture must actually violate the property it pins, asserted BEFORE the arm runs: two
    // distinct names over one set of 32 bytes.
    assert_eq!(
        kind_root_secret_chirho.as_bytes_chirho(),
        issuer_secret_chirho.as_bytes_chirho(),
        "fixture did not apply: the offline issuer secret must hold the kind_root signer's bytes"
    );
    assert_ne!(
        constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        "fixture must keep the two NAMES distinct, or it tests the name check instead"
    );

    let plan_path_chirho = review_dir_chirho.join("plan-chirho.json");
    let config_path_chirho = review_dir_chirho.join("config-chirho.toml");
    let activation_path_chirho = review_dir_chirho.join("activation-authorization-chirho.json");
    let refusal_chirho = author_credits_demo_inputs_chirho(&CreditsDemoInputsAuthorRequestChirho {
        root_chirho: &root_chirho,
        payer_chirho: &payer_chirho,
        config_output_chirho: &config_path_chirho,
        plan_output_chirho: &plan_path_chirho,
        activation_authorization_output_chirho: &activation_path_chirho,
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        destination_authority_enrollment_chirho:
            &fixture_chirho::destination_authority_enrollment_fixture_chirho().verified_chirho,
        serve_port_chirho: 8798,
    })
    .expect_err(
        "an offline issuer holding a runtime signer's own 32 bytes must be refused; this arm \
         PASSED before brick #7 and its passing again would mean the migration was reverted",
    );
    assert_named_refusal_chirho(
        &refusal_chirho,
        "IssuerIdentityCollisionChirho",
        &[
            "IssuerSecretNameCollisionChirho",
            "ActivationIdentityCollisionChirho",
            "ActivationSecretNameCollisionChirho",
            "RuntimeSignerDuplicateIdentityChirho",
        ],
    );
    assert!(
        refusal_chirho.to_string().contains("KindRootChirho"),
        "the refusal must name WHICH runtime role the issuer collided with: {refusal_chirho}"
    );
    for output_chirho in [
        &plan_path_chirho,
        &config_path_chirho,
        &activation_path_chirho,
    ] {
        assert!(
            !output_chirho.exists(),
            "a refused authoring must leave no artifact behind: {}",
            output_chirho.display()
        );
    }
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// The measurement that makes the arm above meaningful: **every check the PRE-MIGRATION road ran
/// accepts the same hostile fixture.**
///
/// Without this, "now refused" is only half a claim — a refusal could always have been there. This
/// re-runs the pre-migration check set (the six runtime signers load; every secret name pairwise
/// distinct) on the identical fixture and asserts it passes, so the difference is located exactly
/// where brick #7 put it: in the IDENTITY comparison that road never made.
///
/// It deliberately does not reconstruct the deleted pin helper. Re-creating an un-vouched pin
/// derivation to prove a point would put that road back in the tree, and the point is made by the
/// check set alone.
#[test]
fn the_pre_migration_check_set_accepts_the_same_bytes_issuer_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-pre-migration-check-set");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let _payer_chirho = set_test_custody_chirho(&root_chirho);
    cairn_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        &[4_u8; 32],
    )
    .unwrap();

    // Pre-migration check 1: the six runtime signers load, are 32 bytes, nonzero, and pairwise
    // distinct in name AND identity. This is the strongest check that road ran, and it passes —
    // because the collision is between an OFFLINE authority and a runtime signer, not among the six.
    let signer_config_chirho = cairn_chirho::config_chirho::LedgerHostSignerRefsConfigChirho {
        journal_chirho: constants_chirho::JOURNAL_SECRET_NAME_CHIRHO.to_owned(),
        config_chirho: constants_chirho::CONFIG_SECRET_NAME_CHIRHO.to_owned(),
        feeder_chirho: constants_chirho::FEEDER_SECRET_NAME_CHIRHO.to_owned(),
        kind_root_chirho: constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO.to_owned(),
        effect_intent_chirho: constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO.to_owned(),
        effect_terminal_chirho: constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO.to_owned(),
    };
    let signer_refs_chirho =
        cairn_ledger_host_chirho::host_ledger_signer_refs_from_config_chirho(&signer_config_chirho)
            .expect("pre-migration road built its signer refs from these six names");
    cairn_ledger_host_chirho::HostLedgerSignersChirho::load_existing_chirho(
        &root_chirho,
        &signer_refs_chirho,
    )
    .expect(
        "the pre-migration six-signer custody proof must ACCEPT this fixture — if it now refuses, \
         the collision moved among the six and this arm is measuring something else",
    );

    // Pre-migration check 2: every secret name pairwise distinct. Also passes, because the hostile
    // value is installed under its own name.
    let mut distinct_names_chirho = std::collections::BTreeSet::new();
    for name_chirho in [
        constants_chirho::JOURNAL_SECRET_NAME_CHIRHO,
        constants_chirho::CONFIG_SECRET_NAME_CHIRHO,
        constants_chirho::FEEDER_SECRET_NAME_CHIRHO,
        constants_chirho::KIND_ROOT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_INTENT_SECRET_NAME_CHIRHO,
        constants_chirho::EFFECT_TERMINAL_SECRET_NAME_CHIRHO,
        constants_chirho::DSN_SECRET_NAME_CHIRHO,
        constants_chirho::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
    ] {
        assert!(
            distinct_names_chirho.insert(name_chirho),
            "the pre-migration name-distinctness check must ACCEPT this fixture; a duplicate name \
             would mean the arm is measuring the name check rather than the identity gap"
        );
    }
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// The activation authority gets the same identity law, on the same road.
///
/// Its own neighbour is excluded explicitly: an activation secret holding a runtime signer's bytes
/// must refuse as an ACTIVATION identity collision, never as the issuer's.
#[test]
fn same_bytes_different_name_activation_authority_is_refused_chirho() {
    let root_chirho = temp_root_chirho("credits-demo-same-bytes-activation");
    let review_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    std::fs::create_dir_all(&review_dir_chirho).unwrap();
    let payer_chirho = set_test_custody_chirho(&root_chirho);
    cairn_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        &[2_u8; 32],
    )
    .unwrap();
    let refusal_chirho = author_credits_demo_inputs_chirho(&CreditsDemoInputsAuthorRequestChirho {
        root_chirho: &root_chirho,
        payer_chirho: &payer_chirho,
        config_output_chirho: &review_dir_chirho.join("config-chirho.toml"),
        plan_output_chirho: &review_dir_chirho.join("plan-chirho.json"),
        activation_authorization_output_chirho: &review_dir_chirho
            .join("activation-authorization-chirho.json"),
        issuer_secret_name_chirho: constants_chirho::DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
        activation_secret_name_chirho: constants_chirho::DEFAULT_ACTIVATION_SECRET_NAME_CHIRHO,
        payer_credential_secret_name_chirho:
            constants_chirho::DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        destination_authority_enrollment_chirho:
            &fixture_chirho::destination_authority_enrollment_fixture_chirho().verified_chirho,
        serve_port_chirho: 8798,
    })
    .expect_err("an activation authority holding a runtime signer's 32 bytes must be refused");
    assert_named_refusal_chirho(
        &refusal_chirho,
        "ActivationIdentityCollisionChirho",
        &[
            "IssuerIdentityCollisionChirho",
            "ActivationSecretNameCollisionChirho",
            "ActivationIdentityMatchesIssuerChirho",
        ],
    );
    assert!(
        refusal_chirho.to_string().contains("ConfigChirho"),
        "the refusal must name WHICH runtime role was collided with: {refusal_chirho}"
    );
    std::fs::remove_dir_all(root_chirho).unwrap();
}

/// The migrated road must reach the six runtime signers ONLY through the custody road.
///
/// The program's standing ruling is that no brick may accept a caller-supplied
/// `HostLedgerSignersChirho`; an AST guard enforces that inside the operator regenesis crate, which
/// does not scan this one. This is the same fence on the caller's side, and it is also what stops
/// the deleted six-signer load quietly coming back as "just a preflight" — which is precisely the
/// shape that made the identity law look present here while it was absent.
#[test]
fn migrated_credits_demo_road_holds_no_runtime_signer_set_chirho() {
    let source_chirho = std::fs::read_to_string(
        crate::workspace_root_for_operator_smoke_chirho().join(
            "crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho/operator_prepare_chirho.rs",
        ),
    )
    .unwrap();
    // Positive control: this really is the migrated road, and it really does author through the
    // generic emission road. Without it every absence below could be a statement about a file that
    // was renamed away.
    assert!(
        source_chirho.contains("author_and_emit_ledger_host_artifacts_chirho("),
        "the credits-demo road must author through the generic emission road (positive control)"
    );
    assert!(
        source_chirho.contains("pub fn credits_demo_authoring_inputs_chirho("),
        "the demo's constants must be expressed as one reviewed document (positive control)"
    );
    for forbidden_chirho in [
        "HostLedgerSignersChirho",
        "load_existing_chirho(",
        "host_ledger_signer_refs_from_config_chirho(",
        "offline_issuer_verifying_key_hex_chirho",
        "offline_activation_verifying_key_hex_chirho",
        "serialize_config_chirho(",
    ] {
        assert!(
            !source_chirho.contains(forbidden_chirho),
            "the migrated credits-demo road regained its own copy of a law the generic author \
             owns, via {forbidden_chirho}; the six runtime signers, the two pin derivations, and \
             the config serialization all belong to the custody and emission roads"
        );
    }
}
