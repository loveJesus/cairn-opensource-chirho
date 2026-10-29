// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Drives the REAL seeding binary to prove it reaches the road's INJECTED opener rather than the
//! production door, and that it and the serve binary cannot be mistaken for one another.
//!
//! WHY A DIFFERENTIAL AND NOT A DIRECT OBSERVATION. "The binary injected an opener" is not visible
//! from outside the process: injected or not, a seed against a bare drill root fails. What IS
//! observable is the ONE respect in which the two postures differ on a test-kind-MARKED config —
//! with nothing injected the seeding road refuses at the test-kind fence BEFORE any authoritative
//! mutation, and with an opener injected that fence is deliberately not applied. So both arms run on
//! the SAME root, the SAME 0600 config file and the SAME plan path, and the refusal IDENTITIES are
//! compared. Control first, so the absence assertion cannot be green-by-emptiness.
//!
//! THE FIXTURE CARRIES A `postgres_effect` BLOCK ON PURPOSE. The seeding road requires that block
//! several lines BEFORE it reaches the test-kind fence, so a fixture without one makes both arms
//! refuse identically for a reason that has nothing to do with injection — a differential that
//! compares two unrelated failures and proves nothing.

use cairn_config_chirho::config_chirho::{
    serialize_config_chirho, ConfigChirho, LedgerHostConfigChirho, LedgerHostIssuerPinConfigChirho,
    LedgerHostMemberConfigChirho, LedgerHostPostgresEffectConfigChirho,
    LedgerHostPostgresEffectPostureChirho, LedgerHostProjectionRouteConfigChirho,
    LedgerHostSignerRefsConfigChirho, LedgerHostTestKindMarkerConfigChirho,
    LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO, LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
    LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
};
use cairn_ledger_host_chirho::TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO;
use cairn_operator_smoke_chirho::credits_demo_smoke_chirho::{
    run_credits_demo_geo_seed_chirho, CreditsDemoSmokeInputsChirho,
};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const SEED_BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cairn-ledger-geo-node-testkind-seed-chirho");
const SERVE_BIN_CHIRHO: &str = env!("CARGO_BIN_EXE_cairn-ledger-geo-node-testkind-chirho");
const SEED_NAME_CHIRHO: &str = "cairn-ledger-geo-node-testkind-seed-chirho";
const SERVE_NAME_CHIRHO: &str = "cairn-ledger-geo-node-testkind-chirho";

fn run_chirho(bin_chirho: &str, args_chirho: &[&str]) -> Output {
    Command::new(bin_chirho)
        .args(args_chirho)
        .output()
        .expect("the built binary runs")
}

/// A VALID, custody-clean, test-kind-MARKED host config with a `postgres_effect` block, on a fresh
/// root. Valid matters twice over: an invalid config refuses inside the shared funnel for a reason
/// unrelated to the fence, and a missing `postgres_effect` block refuses BEFORE the fence.
fn marked_fixture_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-testkind-seedbin-{label_chirho}-{}-chirho",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).expect("create fixture root");

    let ledger_host_chirho = LedgerHostConfigChirho {
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
            principal_chirho: "test-kind-chirho-seed-bin-issuer-chirho".to_owned(),
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
        // REQUIRED BEFORE THE FENCE — see the module header.
        postgres_effect_chirho: Some(LedgerHostPostgresEffectConfigChirho {
            schema_chirho: LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO.to_owned(),
            posture_chirho: LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho,
            connection_secret_chirho: "seed-bin-dsn-chirho".to_owned(),
            billing_kind_chirho: "drill-credits-chirho".to_owned(),
        }),
        // THE MARKER: what the shipping seeding posture refuses and an injected opener admits.
        control_plane_chirho: None,
        test_kind_chirho: Some(LedgerHostTestKindMarkerConfigChirho {
            schema_chirho: LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO.to_owned(),
            loss_witness_exempt_chirho: false,
        }),
        adopt_migrated_root_chirho: false,
    };
    ledger_host_chirho
        .validate_chirho()
        .expect("the fixture config must be VALID, or both arms refuse for an unrelated reason");

    let config_path_chirho = root_chirho.join("ledger-host-config-chirho.toml");
    std::fs::write(
        &config_path_chirho,
        serialize_config_chirho(&ConfigChirho {
            root_chirho: root_chirho.display().to_string(),
            ledger_host_chirho: Some(ledger_host_chirho),
            ..ConfigChirho::default()
        })
        .expect("serialize marked fixture config"),
    )
    .expect("write marked fixture config");
    let mut permissions_chirho = std::fs::metadata(&config_path_chirho)
        .expect("read config metadata")
        .permissions();
    permissions_chirho.set_mode(0o600);
    std::fs::set_permissions(&config_path_chirho, permissions_chirho)
        .expect("set config custody mode");

    root_chirho
}

/// THE INJECTION, executed through the real binary: the seeding binary reaches a road posture the
/// test-kind fence does not guard, while the SAME road with nothing injected refuses these exact
/// inputs at that fence.
#[test]
fn the_seed_bin_takes_the_injected_opener_not_the_production_door_chirho() {
    let root_chirho = marked_fixture_chirho("fence-split");
    let config_path_chirho = root_chirho.join("ledger-host-config-chirho.toml");
    // Deliberately absent: the seeding road reads the plan immediately AFTER the fence, so this is
    // the first thing the injected arm can legitimately fail on. It also keeps the arm hermetic —
    // no PostgreSQL, no secret store, no authoritative mutation.
    let plan_path_chirho = root_chirho.join("absent-regenesis-plan-chirho.json");
    let app_root_chirho = root_chirho.join("absent-app-root-chirho");
    let activation_path_chirho = root_chirho.join("absent-activation-chirho.json");
    let expected_config_digest_chirho =
        blake3::hash(&std::fs::read(&config_path_chirho).expect("read marked ledger config"))
            .to_hex()
            .to_string();

    // CONTROL FIRST. The shipping posture passes no opener; on these exact inputs it must refuse at
    // the test-kind fence. If it ever stops doing so, the claim below would be satisfied by a
    // codebase with no fence at all.
    let control_chirho = run_credits_demo_geo_seed_chirho(
        &CreditsDemoSmokeInputsChirho {
            root_chirho: &root_chirho,
            config_path_chirho: &config_path_chirho,
            expected_config_digest_chirho: &expected_config_digest_chirho,
            plan_path_chirho: &plan_path_chirho,
            expected_plan_digest_chirho: "00",
            issuer_secret_name_chirho: "issuer-secret-chirho",
            activation_authorization_path_chirho: &activation_path_chirho,
            expected_activation_authorization_digest_chirho: "00",
            payer_credential_secret_name_chirho: "payer-credential-chirho",
            app_root_chirho: &app_root_chirho,
            manifest_path_chirho: None,
            reviewed_payer_principal_chirho: None,
        },
        None,
    );
    let control_refusal_chirho = match control_chirho {
        Ok(_) => panic!("the shipping seeding posture must refuse a test-kind-marked config"),
        Err(error_chirho) => format!("{error_chirho:#}"),
    };
    assert!(
        control_refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "control failed: the shipping posture (no injected opener) must refuse at the test-kind \
         fence, else this arm's absence assertion proves nothing. Got: {control_refusal_chirho}"
    );

    // THE CLAIM. Same root, same config file, same plan path — only the road's opener differs,
    // because this is the real seeding BINARY and it injects one.
    let seeded_chirho = run_chirho(
        SEED_BIN_CHIRHO,
        &[
            "--root-chirho",
            &root_chirho.display().to_string(),
            "--config-chirho",
            &config_path_chirho.display().to_string(),
            "--expected-config-digest-chirho",
            expected_config_digest_chirho.as_str(),
            "--plan-chirho",
            &plan_path_chirho.display().to_string(),
            "--expected-plan-digest-chirho",
            "00",
            "--issuer-secret-name-chirho",
            "issuer-secret-chirho",
            "--activation-authorization-chirho",
            &activation_path_chirho.display().to_string(),
            "--expected-activation-authorization-digest-chirho",
            "00",
            "--payer-credential-secret-name-chirho",
            "payer-credential-chirho",
            "--app-root-chirho",
            &app_root_chirho.display().to_string(),
        ],
    );
    let seed_refusal_chirho = String::from_utf8_lossy(&seeded_chirho.stderr).to_string();
    assert!(
        !seeded_chirho.status.success(),
        "the fixture supplies no plan, so the seeding binary must still fail — a success here means \
         it mutated a root on inputs this arm believed were incomplete"
    );
    assert!(
        !seed_refusal_chirho.contains(TEST_KIND_MARKED_LEDGER_HOST_CONFIG_REFUSAL_CHIRHO),
        "the seeding binary hit the TEST-KIND FENCE, so it is NOT injecting an opener — it is \
         running the shipping posture and can never seed a hosted drill root. Got: \
         {seed_refusal_chirho}"
    );

    // ASSERT THE REASON POSITIVELY, not merely the absence: the binary must get PAST the fence and
    // fail on the next step, which on these inputs is the plan read. Without this, a binary that
    // refused for ANY new reason (a bad flag parse, a panic) would satisfy the absence assertion
    // above while proving nothing about which posture it took.
    //
    // MIGRATION PATH, because this pins another crate's refusal wording: if this fails, read the new
    // refusal before editing. Still a PLAN-READ refusal under different words → retarget this
    // needle. A CUSTODY or VALIDATION refusal → the road now refuses EARLIER than the fence and the
    // differential no longer isolates injection; rebuild the fixture rather than the needle. The
    // test-kind refusal → the negative assertion above fires first and tells you directly.
    const PAST_THE_FENCE_REFUSAL_CHIRHO: &str = "read regenesis plan";
    assert!(
        seed_refusal_chirho.contains(PAST_THE_FENCE_REFUSAL_CHIRHO),
        "the seeding binary must reach the plan read — i.e. it admitted the test-kind config and \
         failed only for the absent plan. Got: {seed_refusal_chirho}"
    );

    std::fs::remove_dir_all(&root_chirho).expect("remove fixture root");
}

#[test]
fn the_seed_bin_names_its_own_tree_and_says_seed_chirho() {
    for flag_chirho in ["--version", "-V"] {
        let output_chirho = run_chirho(SEED_BIN_CHIRHO, &[flag_chirho]);
        let stdout_chirho = String::from_utf8(output_chirho.stdout).expect("utf8 version line");
        let line_chirho = stdout_chirho.trim_end();
        assert!(
            output_chirho.status.success(),
            "`{flag_chirho}` must exit 0; got {:?} with stdout {line_chirho:?}",
            output_chirho.status.code()
        );
        assert!(
            line_chirho.starts_with(&format!("{SEED_NAME_CHIRHO} ")),
            "a staged seeding binary must name ITSELF: it sits beside the serve binary, built from \
             the same tree, and the two differ only in bytes. Got {line_chirho:?}"
        );
        assert!(
            cairn_build_identity_chirho::version_line_names_a_tree_chirho(line_chirho),
            "a staged binary must name a 40-hex commit or the honest `unknown` marker. Got \
             {line_chirho:?}"
        );
    }
}

/// Neither binary may be invoked in the belief that it is the other. They sit in one directory on a
/// drill host, so each refusal names the other by name.
#[test]
fn the_two_binaries_refuse_each_others_argv_and_name_each_other_chirho() {
    // The SERVE binary's whole contract, aimed at the SEEDING binary.
    let seed_chirho = run_chirho(
        SEED_BIN_CHIRHO,
        &[
            "cluster.json",
            "ledger.toml",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "/selected-root",
        ],
    );
    let seed_stderr_chirho = String::from_utf8_lossy(&seed_chirho.stderr).to_string();
    assert!(
        !seed_chirho.status.success(),
        "four bare coordinates is the SERVE contract; the seeding binary must refuse it"
    );
    assert!(
        seed_stderr_chirho.contains(SERVE_NAME_CHIRHO),
        "the refusal must NAME the binary the operator actually meant, not merely list flags. Got: \
         {seed_stderr_chirho}"
    );

    // The SEEDING binary's flag line, aimed at the SERVE binary. The serve binary remains a narrow
    // four-coordinate positional surface, so this six-token named-flag line is still overlong.
    let serve_chirho = run_chirho(
        SERVE_BIN_CHIRHO,
        &[
            "--root-chirho",
            "/r",
            "--config-chirho",
            "/c",
            "--plan-chirho",
            "/p",
        ],
    );
    let serve_stderr_chirho = String::from_utf8_lossy(&serve_chirho.stderr).to_string();
    assert!(
        !serve_chirho.status.success(),
        "the serve binary must refuse the seeding binary's flag line"
    );
    assert!(
        serve_stderr_chirho.contains(&format!("usage: {SERVE_NAME_CHIRHO} ")),
        "it must refuse with its own digest-bound four-coordinate usage. Got: \
         {serve_stderr_chirho}"
    );
    // HONEST BOUNDARY, stated rather than papered over: the serve binary cannot name the seeding
    // binary, because teaching it to would change its argv handling. Its protection is the distinct
    // positional arity, and this asserts exactly that.
    assert!(
        !serve_stderr_chirho.contains(SEED_NAME_CHIRHO),
        "the serve binary must NOT have gained knowledge of the seeding binary; its refusal is its \
         own usage line. Got: {serve_stderr_chirho}"
    );
}
