// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Brick #6's arms, driven through the REAL clap surface and the REAL dispatch handler rather than
//! through a helper, because the claim is about what the shipped verbs do.
//!
//! **The central arm is `derive_before_print`.** The parse road returns a document with zero
//! money-policy validation, so the one thing an operator surface can get catastrophically wrong is
//! reporting on a document it never derived. That arm proves the hazard is real (the over-mint
//! document PARSES in full) and that both verbs refuse it anyway, with the money-policy identity
//! and with nothing written.
//!
//! Conventions carried from the earlier bricks, because a green here has to mean something.
//! 1. **Refusal IDENTITY through `downcast_ref`, never prose matching** — an exact enum comparison,
//!    plus an explicit `assert_ne!` against the neighbouring refusal wherever one could plausibly
//!    fire instead.
//! 2. **A positive control per arm**: the unmutated fixture must succeed through the same verb, so
//!    no arm can pass because the fixture went bad.
//! 3. **Refusals are checked at the FILESYSTEM too.** A refusal identity says nothing about what is
//!    on disk, and "nothing survives a refusal" is half of what this porcelain promises.
//! 4. **One coordinate differs between a passing and a refusing fixture**, so the refusal can only
//!    be the law under test.

use super::*;
use crate::args_chirho::ops_args_chirho::{
    DestinationAuthorityEnrollmentVerificationArgsChirho, LedgerHostActivationAuthorArgsChirho,
    LedgerHostAuthorArgsChirho, LedgerHostAuthorReviewArgsChirho,
    LedgerHostAuthoringCoordinatesArgsChirho, LedgerHostAuthoringModeArgChirho,
};
use crate::args_chirho::{CliChirho, CommandChirho};
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_host_chirho::parse_canonical_resident_ledger_activation_authorization_chirho;
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_regenesis_chirho::destination_authority_enrollment_test_support_chirho::{
    create_destination_authority_enrollment_test_fixture_chirho,
    DestinationAuthorityEnrollmentTestFixtureChirho,
};
use cairn_ledger_regenesis_chirho::{
    author_and_emit_ledger_host_artifacts_chirho,
    canonical_ledger_host_authoring_inputs_bytes_chirho,
    ledger_host_authoring_inputs_digest_chirho,
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho, prepare_money_stage_chirho,
    LedgerHostAuthoringInputsV1Chirho, LedgerHostAuthoringMemberInputChirho,
    LedgerHostAuthoringModeChirho, LedgerHostAuthoringRouteInputChirho,
    LedgerHostAuthoringSignerRefsInputChirho, LedgerHostEmissionRequestChirho,
    LedgerHostEmittedArtifactsChirho, LedgerRegenesisH3aRequestChirho,
    LedgerRegenesisRefusalChirho, LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO,
};
use cairn_signer_chirho::signer_chirho::sign_message_chirho;
use clap::Parser;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const ISSUER_SECRET_NAME_CHIRHO: &str = "cli-offline-issuer-chirho";
const ACTIVATION_SECRET_NAME_CHIRHO: &str = "cli-offline-activation-chirho";
const INPUTS_FILE_CHIRHO: &str = "reviewed-authoring-inputs-chirho.json";
const CONFIG_OUTPUT_CHIRHO: &str = "authored-host-config-chirho.toml";
const PLAN_OUTPUT_CHIRHO: &str = "authored-regenesis-plan-chirho.json";
const ACTIVATION_OUTPUT_CHIRHO: &str = "authored-activation-authorization-chirho.json";
const SERVE_PORT_CHIRHO: u16 = 8_931;
/// The digest prefix the activation authoring verb must print. Spelled here rather than imported so
/// an arm proving the digest shape cannot pass by agreeing with a renamed constant.
const ACTIVATION_AUTHORIZATION_DIGEST_PREFIX_CHIRHO: &str =
    "resident-ledger-activation-authorization-blake3-v1-chirho:";
/// One seed per role, so a fixture that accidentally reused a value would be a real identity
/// collision the custody road refuses rather than a silent pass.
const ROLE_SEEDS_CHIRHO: [u8; 6] = [11, 12, 13, 14, 15, 16];
const ISSUER_SEED_CHIRHO: u8 = 17;
const ACTIVATION_SEED_CHIRHO: u8 = 18;
/// The reserved prefix a test-kind run must use for both issuer coordinates. Spelled here rather
/// than imported so an arm proving the mode law cannot pass by agreeing with a renamed constant.
const TEST_KIND_PREFIX_CHIRHO: &str = "test-kind-chirho-";

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

/// A root whose eight secrets are pre-provisioned exactly as `secret-set` would leave them, plus a
/// reviewed document on disk. Nothing here creates a key through the code under test.
struct AuthorFixtureChirho {
    root_chirho: PathBuf,
    inputs_path_chirho: PathBuf,
    inputs_digest_chirho: String,
    enrollment_chirho: DestinationAuthorityEnrollmentTestFixtureChirho,
}

impl Drop for AuthorFixtureChirho {
    fn drop(&mut self) {
        let _removed_chirho = fs::remove_dir_all(&self.root_chirho);
    }
}

impl AuthorFixtureChirho {
    fn with_inputs_chirho(inputs_chirho: &LedgerHostAuthoringInputsV1Chirho) -> Self {
        let root_chirho = cli_author_temp_root_chirho();
        fs::create_dir(&root_chirho).unwrap();
        let signer_secrets_chirho = &inputs_chirho.signer_secrets_chirho;
        let names_chirho = [
            &signer_secrets_chirho.journal_chirho,
            &signer_secrets_chirho.config_chirho,
            &signer_secrets_chirho.feeder_chirho,
            &signer_secrets_chirho.kind_root_chirho,
            &signer_secrets_chirho.effect_intent_chirho,
            &signer_secrets_chirho.effect_terminal_chirho,
        ];
        for (name_chirho, seed_chirho) in names_chirho.iter().zip(ROLE_SEEDS_CHIRHO) {
            cairn_chirho::secret_chirho::set_secret_chirho(
                &root_chirho,
                name_chirho,
                &[seed_chirho; 32],
            )
            .unwrap();
        }
        let issuer_secret_name_chirho = issuer_secret_name_for_chirho(inputs_chirho);
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            &issuer_secret_name_chirho,
            &[ISSUER_SEED_CHIRHO; 32],
        )
        .unwrap();
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            ACTIVATION_SECRET_NAME_CHIRHO,
            &[ACTIVATION_SEED_CHIRHO; 32],
        )
        .unwrap();
        let inputs_path_chirho = root_chirho.join(INPUTS_FILE_CHIRHO);
        let bytes_chirho =
            canonical_ledger_host_authoring_inputs_bytes_chirho(inputs_chirho).unwrap();
        fs::write(&inputs_path_chirho, &bytes_chirho).unwrap();
        let inputs_digest_chirho = ledger_host_authoring_inputs_digest_chirho(&bytes_chirho);
        let enrollment_chirho =
            create_destination_authority_enrollment_test_fixture_chirho("cli-author-chirho");
        Self {
            root_chirho,
            inputs_path_chirho,
            inputs_digest_chirho,
            enrollment_chirho,
        }
    }

    fn valid_chirho() -> Self {
        Self::with_inputs_chirho(&valid_cli_inputs_chirho())
    }

    fn config_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(CONFIG_OUTPUT_CHIRHO)
    }

    fn plan_path_chirho(&self) -> PathBuf {
        self.root_chirho.join(PLAN_OUTPUT_CHIRHO)
    }

    fn no_artifacts_exist_chirho(&self) -> bool {
        !self.config_path_chirho().exists() && !self.plan_path_chirho().exists()
    }
}

/// A test-kind document names its issuer with the reserved prefix, and the custody road requires the
/// SECRET name to carry it too — so the fixture must provision the secret under that name.
fn issuer_secret_name_for_chirho(inputs_chirho: &LedgerHostAuthoringInputsV1Chirho) -> String {
    if inputs_chirho
        .issuer_principal_chirho
        .starts_with(TEST_KIND_PREFIX_CHIRHO)
    {
        format!("{TEST_KIND_PREFIX_CHIRHO}{ISSUER_SECRET_NAME_CHIRHO}")
    } else {
        ISSUER_SECRET_NAME_CHIRHO.to_owned()
    }
}

fn cli_author_temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-cli-ledger-host-author-{}-{now_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

fn cli_policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "credit-minor-chirho".to_owned(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(max_supply_chirho),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-cli-chirho".to_owned(),
        settlement_owner_chirho: Some("cli-settlement-chirho".to_owned()),
        idempotency_window_chirho: Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: 86_400_000,
            retry_finality_horizon_ms_chirho: 86_400_000,
        }),
    }
}

/// A complete reviewed document that derives cleanly: it mints 750 against a ceiling of 2,000.
fn valid_cli_inputs_chirho() -> LedgerHostAuthoringInputsV1Chirho {
    LedgerHostAuthoringInputsV1Chirho {
        schema_chirho: LEDGER_HOST_AUTHORING_INPUTS_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: "cli-ledger-parent-chirho".to_owned(),
        staging_parent_chirho: "cli-ledger-staging-chirho".to_owned(),
        storage_namespace_chirho: "cli-ledger-parent-chirho/ledger-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "cli-ledger-parent-chirho/ops-chirho".to_owned(),
        monitor_evidence_path_chirho: "monitor/cycles-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-cli-chirho".to_owned(),
        cluster_id_chirho: "cluster-cli-chirho".to_owned(),
        local_epoch_chirho: 3,
        journal_path_chirho: "journals/main-chirho.jsonl".to_owned(),
        kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-cli-chirho".to_owned(),
        projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-cli-chirho".to_owned(),
        source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-cli-chirho".to_owned(),
        projection_routes_chirho: vec![
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: "balance-chirho".to_owned(),
                head_path_chirho: "published/balance-head-chirho.json".to_owned(),
            },
            LedgerHostAuthoringRouteInputChirho {
                projection_name_chirho: "mirror-chirho".to_owned(),
                head_path_chirho: "published/mirror-head-chirho.json".to_owned(),
            },
        ],
        monitor_cadence_ms_chirho: 60_000,
        issuer_principal_chirho: "cli-kind-issuer-chirho".to_owned(),
        activation_principal_chirho: Some("cli-ledger-activation-chirho".to_owned()),
        members_chirho: vec![LedgerHostAuthoringMemberInputChirho {
            owner_chirho: "cli-settlement-chirho".to_owned(),
            kind_id_chirho: "prepaid-credits-chirho".to_owned(),
        }],
        signer_secrets_chirho: LedgerHostAuthoringSignerRefsInputChirho {
            journal_chirho: "cli-journal-secret-chirho".to_owned(),
            config_chirho: "cli-config-secret-chirho".to_owned(),
            feeder_chirho: "cli-feeder-secret-chirho".to_owned(),
            kind_root_chirho: "cli-kind-root-secret-chirho".to_owned(),
            effect_intent_chirho: "cli-effect-intent-secret-chirho".to_owned(),
            effect_terminal_chirho: "cli-effect-terminal-secret-chirho".to_owned(),
        },
        initial_owner_chirho: "cli-settlement-chirho".to_owned(),
        kind_id_chirho: "prepaid-credits-chirho".to_owned(),
        initial_policy_chirho: cli_policy_chirho(2_000),
        amended_policy_chirho: cli_policy_chirho(1_500),
        initial_mint_amount_chirho: 750,
        genesis_physical_ms_chirho: 5_000,
        mint_physical_ms_chirho: 5_250,
        postgres_effect_chirho: None,
        test_kind_shared_journal_chirho: false,
    }
}

// ---------------------------------------------------------------------------------------------
// Command construction (through the real arg types)
// ---------------------------------------------------------------------------------------------

fn coordinates_chirho(
    fixture_chirho: &AuthorFixtureChirho,
    issuer_secret_name_chirho: &str,
    mode_chirho: LedgerHostAuthoringModeArgChirho,
) -> LedgerHostAuthoringCoordinatesArgsChirho {
    LedgerHostAuthoringCoordinatesArgsChirho {
        inputs_path_chirho: fixture_chirho.inputs_path_chirho.clone(),
        issuer_secret_name_chirho: issuer_secret_name_chirho.to_owned(),
        activation_secret_name_chirho: Some(ACTIVATION_SECRET_NAME_CHIRHO.to_owned()),
        mode_chirho,
        destination_authority_enrollment_chirho:
            DestinationAuthorityEnrollmentVerificationArgsChirho {
                enrollment_path_chirho: fixture_chirho
                    .enrollment_chirho
                    .enrollment_path_chirho
                    .clone(),
                cluster_genesis_roster_path_chirho: fixture_chirho
                    .enrollment_chirho
                    .cluster_genesis_roster_path_chirho
                    .clone(),
                cluster_genesis_roster_head_path_chirho: fixture_chirho
                    .enrollment_chirho
                    .cluster_genesis_roster_head_path_chirho
                    .clone(),
                cluster_genesis_roster_operator_pubkey_hex_chirho: fixture_chirho
                    .enrollment_chirho
                    .cluster_genesis_roster_operator_pubkey_hex_chirho
                    .clone(),
            },
    }
}

fn review_command_chirho(
    fixture_chirho: &AuthorFixtureChirho,
    issuer_secret_name_chirho: &str,
    mode_chirho: LedgerHostAuthoringModeArgChirho,
) -> CommandChirho {
    CommandChirho::LedgerHostAuthorReviewChirho(LedgerHostAuthorReviewArgsChirho {
        coordinates_chirho: coordinates_chirho(
            fixture_chirho,
            issuer_secret_name_chirho,
            mode_chirho,
        ),
    })
}

fn author_command_chirho(
    fixture_chirho: &AuthorFixtureChirho,
    issuer_secret_name_chirho: &str,
    mode_chirho: LedgerHostAuthoringModeArgChirho,
    expected_inputs_digest_chirho: &str,
) -> CommandChirho {
    CommandChirho::LedgerHostAuthorChirho(LedgerHostAuthorArgsChirho {
        coordinates_chirho: coordinates_chirho(
            fixture_chirho,
            issuer_secret_name_chirho,
            mode_chirho,
        ),
        expected_inputs_digest_chirho: expected_inputs_digest_chirho.to_owned(),
        expected_destination_authority_enrollment_digest_chirho: fixture_chirho
            .enrollment_chirho
            .enrollment_digest_chirho
            .clone(),
        config_output_chirho: PathBuf::from(CONFIG_OUTPUT_CHIRHO),
        plan_output_chirho: PathBuf::from(PLAN_OUTPUT_CHIRHO),
        serve_port_chirho: SERVE_PORT_CHIRHO,
    })
}

/// The refusal identity, extracted rather than string-matched. A command that failed for a reason
/// this program did not raise (an IO error, a serialization error) fails the extraction loudly
/// instead of being silently read as "some refusal happened".
fn refusal_chirho(error_chirho: anyhow::Error) -> LedgerRegenesisRefusalChirho {
    error_chirho
        .downcast_ref::<LedgerRegenesisRefusalChirho>()
        .cloned()
        .unwrap_or_else(|| {
            panic!("expected a ledger regenesis refusal, got: {error_chirho:#}");
        })
}

// ---------------------------------------------------------------------------------------------
// Arms
// ---------------------------------------------------------------------------------------------

/// The clap surface: both verbs parse, and every coordinate lands where the handler reads it.
#[test]
fn both_authoring_verbs_parse_with_an_explicit_mode_chirho() {
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-chirho",
        "ledger-host-author-chirho",
        "--inputs-chirho",
        "reviewed-inputs-chirho.json",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--activation-secret-name-chirho",
        "offline-activation-chirho",
        "--mode-chirho",
        "production",
        "--destination-authority-enrollment-chirho",
        "destination-authority-enrollment-chirho.json",
        "--cluster-genesis-roster-chirho",
        "membership-roster-chirho.jsonl",
        "--cluster-genesis-roster-head-chirho",
        "membership-roster-head-chirho.json",
        "--cluster-genesis-roster-operator-pubkey-hex-chirho",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "--expected-inputs-digest-chirho",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--expected-destination-authority-enrollment-digest-chirho",
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--config-output-chirho",
        "host-config-chirho.toml",
        "--plan-output-chirho",
        "regenesis-plan-chirho.json",
        "--serve-port-chirho",
        "8931",
    ])
    .unwrap();
    let CommandChirho::LedgerHostAuthorChirho(args_chirho) = cli_chirho.command_chirho else {
        panic!("the ledger host author command did not parse");
    };
    assert_eq!(
        args_chirho.coordinates_chirho.inputs_path_chirho,
        PathBuf::from("reviewed-inputs-chirho.json")
    );
    assert_eq!(
        args_chirho.coordinates_chirho.mode_chirho,
        LedgerHostAuthoringModeArgChirho::ProductionChirho
    );
    assert_eq!(
        args_chirho.coordinates_chirho.activation_secret_name_chirho,
        Some("offline-activation-chirho".to_owned())
    );
    assert_eq!(args_chirho.serve_port_chirho, 8_931);

    let review_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-chirho",
        "ledger-host-author-review-chirho",
        "--inputs-chirho",
        "reviewed-inputs-chirho.json",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--mode-chirho",
        "test-kind",
        "--destination-authority-enrollment-chirho",
        "destination-authority-enrollment-chirho.json",
        "--cluster-genesis-roster-chirho",
        "membership-roster-chirho.jsonl",
        "--cluster-genesis-roster-head-chirho",
        "membership-roster-head-chirho.json",
        "--cluster-genesis-roster-operator-pubkey-hex-chirho",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ])
    .unwrap();
    let CommandChirho::LedgerHostAuthorReviewChirho(review_args_chirho) =
        review_chirho.command_chirho
    else {
        panic!("the ledger host author review command did not parse");
    };
    assert_eq!(
        review_args_chirho.coordinates_chirho.mode_chirho,
        LedgerHostAuthoringModeArgChirho::TestKindChirho
    );
    assert_eq!(
        review_args_chirho
            .coordinates_chirho
            .activation_secret_name_chirho,
        None,
        "an absent activation secret must stay absent, never default to the issuer"
    );
}

/// **THE MODE HAS NO DEFAULT, and this is the arm that keeps it that way.** A `default_value` on
/// `--mode-chirho` would let a forgotten argument decide whether a money-authority artifact is a
/// production one. If this arm ever fails because the invocation PARSED, that is the regression.
#[test]
fn the_authoring_mode_cannot_be_omitted_chirho() {
    // Positive control: the same invocation WITH a mode parses, so the failure below is about the
    // missing flag rather than about anything else in the argument list.
    CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-chirho",
        "ledger-host-author-review-chirho",
        "--inputs-chirho",
        "reviewed-inputs-chirho.json",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--mode-chirho",
        "production",
        "--destination-authority-enrollment-chirho",
        "destination-authority-enrollment-chirho.json",
        "--cluster-genesis-roster-chirho",
        "membership-roster-chirho.jsonl",
        "--cluster-genesis-roster-head-chirho",
        "membership-roster-head-chirho.json",
        "--cluster-genesis-roster-operator-pubkey-hex-chirho",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ])
    .expect("the control invocation must parse");

    let parsed_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-chirho",
        "ledger-host-author-review-chirho",
        "--inputs-chirho",
        "reviewed-inputs-chirho.json",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--destination-authority-enrollment-chirho",
        "destination-authority-enrollment-chirho.json",
        "--cluster-genesis-roster-chirho",
        "membership-roster-chirho.jsonl",
        "--cluster-genesis-roster-head-chirho",
        "membership-roster-head-chirho.json",
        "--cluster-genesis-roster-operator-pubkey-hex-chirho",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]);
    assert!(
        parsed_chirho.is_err(),
        "an authoring invocation with no --mode-chirho must not parse; a defaulted authoring mode \
         is how a missing argument decides a money question"
    );
}

/// **THE DERIVE-BEFORE-PRINT ARM.**
///
/// The hazard is proven first, not assumed: the over-mint document PARSES in full, so a review verb
/// that reported on the parse result would print a money statement nothing checked. Both verbs then
/// refuse it with the money-policy identity, and the authoring verb leaves nothing on disk.
///
/// The passing control differs from the refusing document in ONE coordinate — the ceiling — so the
/// refusal can only be the mint-versus-supply law.
#[test]
fn neither_verb_reports_on_a_document_it_has_not_derived_chirho() {
    let over_mint_chirho = {
        let mut inputs_chirho = valid_cli_inputs_chirho();
        inputs_chirho.initial_mint_amount_chirho = 10_000;
        inputs_chirho.initial_policy_chirho = cli_policy_chirho(2_000);
        inputs_chirho
    };
    let mut within_ceiling_chirho = over_mint_chirho.clone();
    within_ceiling_chirho.initial_policy_chirho = cli_policy_chirho(20_000);
    assert_ne!(
        over_mint_chirho, within_ceiling_chirho,
        "the two fixtures must differ, or the control below proves nothing"
    );

    // THE HAZARD, MEASURED: the un-derived parse road accepts a mint of 10,000 against a ceiling of
    // 2,000 in full. Everything below is only interesting because this passes.
    let raw_bytes_chirho =
        canonical_ledger_host_authoring_inputs_bytes_chirho(&over_mint_chirho).unwrap();
    parse_ledger_host_authoring_inputs_money_policy_unchecked_chirho(&raw_bytes_chirho)
        .expect("the parse road must accept the over-mint document, or this arm tests nothing");

    // CONTROL: the same document with a raised ceiling reviews and authors cleanly through the real
    // verbs, so neither refusal below can be about the fixture being broken.
    let control_chirho = AuthorFixtureChirho::with_inputs_chirho(&within_ceiling_chirho);
    assert!(handle_ledger_host_author_command_chirho(
        &control_chirho.root_chirho,
        &review_command_chirho(
            &control_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
        ),
    )
    .unwrap());
    assert!(handle_ledger_host_author_command_chirho(
        &control_chirho.root_chirho,
        &author_command_chirho(
            &control_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
            &control_chirho.inputs_digest_chirho,
        ),
    )
    .unwrap());

    let fixture_chirho = AuthorFixtureChirho::with_inputs_chirho(&over_mint_chirho);
    let review_refusal_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &review_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::ProductionChirho,
            ),
        )
        .expect_err(
            "the review verb must derive before it prints; a document minting above its ceiling \
             must never reach a report",
        ),
    );
    assert_eq!(
        review_refusal_chirho,
        LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho
    );

    let author_refusal_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &author_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::ProductionChirho,
                &fixture_chirho.inputs_digest_chirho,
            ),
        )
        .expect_err("the authoring verb must refuse a document minting above its ceiling"),
    );
    assert_eq!(
        author_refusal_chirho,
        LedgerRegenesisRefusalChirho::PlanPolicyRefusedChirho
    );
    assert_ne!(
        author_refusal_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsCoordinateRefusedChirho,
        "the neighbouring coordinate refusal would mean the document was rejected for its shape \
         rather than for its money policy, and this arm would be measuring the wrong law"
    );
    assert!(
        fixture_chirho.no_artifacts_exist_chirho(),
        "a refused authoring run must leave no artifact on disk"
    );
}

/// Review then author, end to end, through the real verbs — and the emitted pair is what the
/// consuming side accepts: the config parses with a ledger-host block, and the plan file's bytes
/// digest to the value the report printed.
#[test]
fn review_then_author_emits_a_consumable_config_and_plan_pair_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &review_command_chirho(
            &fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
        ),
    )
    .unwrap());
    assert!(
        fixture_chirho.no_artifacts_exist_chirho(),
        "the review verb must write nothing"
    );

    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &author_command_chirho(
            &fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
            &fixture_chirho.inputs_digest_chirho,
        ),
    )
    .unwrap());

    let config_text_chirho = fs::read_to_string(fixture_chirho.config_path_chirho()).unwrap();
    let parsed_config_chirho =
        cairn_chirho::config_chirho::parse_config_chirho(&config_text_chirho).unwrap();
    let host_block_chirho = parsed_config_chirho
        .ledger_host_chirho
        .as_ref()
        .expect("the emitted config must carry a ledger host block");
    host_block_chirho
        .validate_chirho()
        .expect("the emitted host block must satisfy the serve boundary's own validator");
    assert_eq!(parsed_config_chirho.port_chirho, SERVE_PORT_CHIRHO);
    assert!(
        host_block_chirho.test_kind_chirho.is_none(),
        "a production-mode authoring run must emit no test-kind marker"
    );
    assert!(
        host_block_chirho.activation_authority_chirho.is_some(),
        "an activation secret was supplied, so the emitted config must pin an activation authority"
    );
    assert_ne!(
        host_block_chirho
            .kind_issuer_chirho
            .verifying_key_hex_chirho,
        host_block_chirho
            .activation_authority_chirho
            .as_ref()
            .unwrap()
            .verifying_key_hex_chirho,
        "the two authority pins must be different keys"
    );

    // The reviewed document carried NO key material, so the pins in the emitted config can only
    // have come from the derivation over the pre-provisioned secrets.
    let inputs_text_chirho = fs::read_to_string(&fixture_chirho.inputs_path_chirho).unwrap();
    assert!(
        !inputs_text_chirho.contains(
            &host_block_chirho
                .kind_issuer_chirho
                .verifying_key_hex_chirho
        ),
        "the derived issuer pin must not appear in the reviewed document"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path_chirho in [
            fixture_chirho.config_path_chirho(),
            fixture_chirho.plan_path_chirho(),
        ] {
            let mode_chirho = fs::metadata(&path_chirho).unwrap().permissions().mode();
            assert_eq!(
                mode_chirho & 0o777,
                0o600,
                "an emitted authority artifact must be readable by its owner alone: {}",
                path_chirho.display()
            );
        }
    }

    // Re-running the same authoring refuses rather than overwriting, and leaves both files intact.
    let config_before_chirho = fs::read(fixture_chirho.config_path_chirho()).unwrap();
    let plan_before_chirho = fs::read(fixture_chirho.plan_path_chirho()).unwrap();
    let repeat_refusal_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &author_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::ProductionChirho,
                &fixture_chirho.inputs_digest_chirho,
            ),
        )
        .expect_err("re-authoring over an existing artifact must refuse"),
    );
    assert!(
        matches!(
            repeat_refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringOutputExistsChirho { .. }
        ),
        "the repeat refusal must name the occupied artifact, got: {repeat_refusal_chirho}"
    );
    assert_eq!(
        fs::read(fixture_chirho.config_path_chirho()).unwrap(),
        config_before_chirho
    );
    assert_eq!(
        fs::read(fixture_chirho.plan_path_chirho()).unwrap(),
        plan_before_chirho
    );
}

/// The review binding: an authoring run whose pasted digest is not the reviewed document's digest
/// refuses, and refuses BEFORE writing anything.
#[test]
fn authoring_refuses_a_document_that_is_not_the_reviewed_one_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    // Positive control: the same command with the right digest authors.
    let other_fixture_chirho = AuthorFixtureChirho::valid_chirho();
    assert!(handle_ledger_host_author_command_chirho(
        &other_fixture_chirho.root_chirho,
        &author_command_chirho(
            &other_fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
            &other_fixture_chirho.inputs_digest_chirho,
        ),
    )
    .unwrap());

    let wrong_digest_chirho = {
        // One character changed: still a well-formed digest, so this arm measures the COMPARISON
        // rather than the shape check below.
        let mut digest_chirho = fixture_chirho.inputs_digest_chirho.clone();
        let flipped_chirho = if digest_chirho.starts_with('a') {
            'b'
        } else {
            'a'
        };
        digest_chirho.replace_range(0..1, &flipped_chirho.to_string());
        digest_chirho
    };
    assert_ne!(wrong_digest_chirho, fixture_chirho.inputs_digest_chirho);
    let mismatch_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &author_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::ProductionChirho,
                &wrong_digest_chirho,
            ),
        )
        .expect_err("authoring from a document that is not the reviewed one must refuse"),
    );
    assert_eq!(
        mismatch_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsDigestMismatchChirho
    );
    assert!(fixture_chirho.no_artifacts_exist_chirho());

    let malformed_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &author_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::ProductionChirho,
                "not-a-digest-chirho",
            ),
        )
        .expect_err("a malformed expected digest must refuse"),
    );
    assert_eq!(
        malformed_chirho,
        LedgerRegenesisRefusalChirho::AuthoringInputsDigestInvalidChirho,
        "a mistyped digest must not read as a changed file"
    );
    assert!(fixture_chirho.no_artifacts_exist_chirho());
}

/// The reviewed document must be ONE real file. A missing path and a symlink are different
/// refusals, and the symlink case is the one that matters: a document read through a link is a
/// document whose bytes can change between review and authoring while the path stays the same.
#[test]
fn the_reviewed_document_must_be_one_real_file_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    // Positive control: the real file reviews cleanly through the same verb.
    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &review_command_chirho(
            &fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
        ),
    )
    .unwrap());

    let mut absent_chirho = review_command_chirho(
        &fixture_chirho,
        ISSUER_SECRET_NAME_CHIRHO,
        LedgerHostAuthoringModeArgChirho::ProductionChirho,
    );
    if let CommandChirho::LedgerHostAuthorReviewChirho(args_chirho) = &mut absent_chirho {
        args_chirho.coordinates_chirho.inputs_path_chirho = fixture_chirho
            .root_chirho
            .join("no-such-reviewed-document-chirho.json");
    }
    assert_eq!(
        refusal_chirho(
            handle_ledger_host_author_command_chirho(&fixture_chirho.root_chirho, &absent_chirho)
                .expect_err("an absent reviewed document must refuse")
        ),
        LedgerRegenesisRefusalChirho::AuthoringInputsUnavailableChirho
    );

    #[cfg(unix)]
    {
        let link_path_chirho = fixture_chirho.root_chirho.join("linked-inputs-chirho.json");
        std::os::unix::fs::symlink(&fixture_chirho.inputs_path_chirho, &link_path_chirho).unwrap();
        let mut linked_chirho = review_command_chirho(
            &fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
        );
        if let CommandChirho::LedgerHostAuthorReviewChirho(args_chirho) = &mut linked_chirho {
            args_chirho.coordinates_chirho.inputs_path_chirho = link_path_chirho;
        }
        let linked_refusal_chirho = refusal_chirho(
            handle_ledger_host_author_command_chirho(&fixture_chirho.root_chirho, &linked_chirho)
                .expect_err("a symlinked reviewed document must refuse"),
        );
        assert_eq!(
            linked_refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsNotRegularChirho
        );
        assert_ne!(
            linked_refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringInputsUnavailableChirho,
            "a symlink whose target exists must not read as an absent file; the two refusals send \
             an operator to different places"
        );
    }
}

/// **NEVER MINT, proven at the filesystem.** An authoring run against a root missing the issuer
/// secret refuses — and the secret store is byte-identical afterwards, so the CLI did not quietly
/// create the key it could not find.
#[test]
fn authoring_never_creates_the_secret_it_cannot_find_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    let secrets_before_chirho = secret_inventory_chirho(&fixture_chirho.root_chirho);
    assert!(
        !secrets_before_chirho.is_empty(),
        "the fixture must have provisioned secrets, or the comparison below is vacuous"
    );

    let refusal_result_chirho = handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &author_command_chirho(
            &fixture_chirho,
            "cli-issuer-secret-that-was-never-provisioned-chirho",
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
            &fixture_chirho.inputs_digest_chirho,
        ),
    );
    let refusal_chirho = refusal_chirho(
        refusal_result_chirho.expect_err("a missing issuer secret must be a hard refusal"),
    );
    assert_eq!(
        refusal_chirho,
        LedgerRegenesisRefusalChirho::IssuerSecretRefusedChirho,
        "the refusal must name the missing offline issuer secret"
    );
    assert_eq!(
        secret_inventory_chirho(&fixture_chirho.root_chirho),
        secrets_before_chirho,
        "the authoring command must create no key; a config author that can mint is a config \
         author that can silently invent an authority"
    );
    assert!(fixture_chirho.no_artifacts_exist_chirho());
}

/// The declared mode's naming law fires through the real verb, before any secret is read — and the
/// refusal names which coordinate disagreed.
#[test]
fn a_test_kind_run_over_production_names_refuses_at_the_mode_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    // Positive control: the same fixture in the mode its names actually declare.
    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &review_command_chirho(
            &fixture_chirho,
            ISSUER_SECRET_NAME_CHIRHO,
            LedgerHostAuthoringModeArgChirho::ProductionChirho,
        ),
    )
    .unwrap());

    let refusal_chirho = refusal_chirho(
        handle_ledger_host_author_command_chirho(
            &fixture_chirho.root_chirho,
            &review_command_chirho(
                &fixture_chirho,
                ISSUER_SECRET_NAME_CHIRHO,
                LedgerHostAuthoringModeArgChirho::TestKindChirho,
            ),
        )
        .expect_err("a test-kind run naming production coordinates must refuse"),
    );
    assert!(
        matches!(
            refusal_chirho,
            LedgerRegenesisRefusalChirho::AuthoringTestKindReservedNameMissingChirho { .. }
        ),
        "the mode slip must refuse with the mode's own identity, got: {refusal_chirho}"
    );
    assert!(fixture_chirho.no_artifacts_exist_chirho());
}

/// A test-kind authoring run emits a config carrying the marker every production resident-actor
/// door refuses. That fence is proven behaviourally in `cairn-ledger-host-chirho`; what this arm
/// closes is the AUTHOR's half — that the artifact the operator gets actually says what it is.
#[test]
fn a_test_kind_run_emits_a_marked_config_chirho() {
    let mut inputs_chirho = valid_cli_inputs_chirho();
    inputs_chirho.issuer_principal_chirho =
        format!("{TEST_KIND_PREFIX_CHIRHO}cli-kind-issuer-chirho");
    inputs_chirho.test_kind_shared_journal_chirho = true;
    let fixture_chirho = AuthorFixtureChirho::with_inputs_chirho(&inputs_chirho);
    let issuer_secret_name_chirho = issuer_secret_name_for_chirho(&inputs_chirho);

    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &author_command_chirho(
            &fixture_chirho,
            &issuer_secret_name_chirho,
            LedgerHostAuthoringModeArgChirho::TestKindChirho,
            &fixture_chirho.inputs_digest_chirho,
        ),
    )
    .unwrap());

    let config_text_chirho = fs::read_to_string(fixture_chirho.config_path_chirho()).unwrap();
    let host_block_chirho = cairn_chirho::config_chirho::parse_config_chirho(&config_text_chirho)
        .unwrap()
        .ledger_host_chirho
        .expect("the emitted config must carry a ledger host block");
    assert!(
        host_block_chirho.test_kind_chirho.is_some(),
        "a test-kind authoring run must emit a marked config, or the consumer fence has nothing to \
         refuse and the drill's artifact is indistinguishable from a production one"
    );
    assert_eq!(
        host_block_chirho.schema_chirho,
        cairn_chirho::config_chirho::LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO
    );
    let pins_chirho = host_block_chirho
        .held_verifier_pins_chirho
        .as_ref()
        .expect("the digest-bound shared-journal choice must reach the emitted config");
    assert_eq!(pins_chirho.journal_verifying_key_hex_chirho.len(), 64);
    assert!(pins_chirho.effect_intent_verifying_key_hex_chirho.is_none());
    assert!(pins_chirho
        .effect_terminal_verifying_key_hex_chirho
        .is_none());
}

/// The activation-author clap surface: every coordinate lands where the handler reads it. The two
/// secret arguments are NAMES, and there is no key-material flag to mistype.
#[test]
fn the_activation_author_verb_parses_with_all_its_coordinates_chirho() {
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-chirho",
        "ledger-host-activation-author-chirho",
        "--config-chirho",
        "authored-host-config-chirho.toml",
        "--plan-chirho",
        "authored-regenesis-plan-chirho.json",
        "--expected-plan-digest-chirho",
        "plan-blake3-v1-chirho:aaaa",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--activation-secret-name-chirho",
        "offline-activation-chirho",
        "--activation-authorization-output-chirho",
        "activation-authorization-chirho.json",
    ])
    .unwrap();
    let CommandChirho::LedgerHostActivationAuthorChirho(args_chirho) = cli_chirho.command_chirho
    else {
        panic!("the ledger host activation author command did not parse");
    };
    assert_eq!(
        args_chirho.config_path_chirho,
        PathBuf::from("authored-host-config-chirho.toml")
    );
    assert_eq!(
        args_chirho.plan_path_chirho,
        PathBuf::from("authored-regenesis-plan-chirho.json")
    );
    assert_eq!(
        args_chirho.expected_plan_digest_chirho,
        "plan-blake3-v1-chirho:aaaa"
    );
    assert_eq!(
        args_chirho.issuer_secret_name_chirho,
        "offline-issuer-chirho"
    );
    assert_eq!(
        args_chirho.activation_secret_name_chirho,
        "offline-activation-chirho"
    );
    assert_eq!(
        args_chirho.activation_authorization_output_chirho,
        PathBuf::from("activation-authorization-chirho.json")
    );
}

/// **THE ROUND-TRIP.** The activation-author verb signs the H3 authorization from an EXISTING
/// config/plan pair, and the artifact it writes is exactly what the real H3-A seed consumes: the
/// seed re-derives the activation statement, VERIFIES the signature against the config's pinned
/// activation authority and the printed digest, and mints. That end-to-end acceptance is the
/// signature-and-digest proof asked of this verb; a round-trip that only re-read the file would not
/// prove the seed accepts it.
///
/// It also proves the two properties this verb owns on its own: the printed digest is the
/// `--expected-activation-authorization-digest-chirho` form, and the output is written create-new
/// (0600) and never overwritten.
#[test]
fn the_activation_author_verb_emits_a_seed_consumable_authorization_chirho() {
    let fixture_chirho = AuthorFixtureChirho::valid_chirho();
    // Provision the root's node instance keypair the way an operator root already carries one: the
    // activation statement binds the elected node's public identity, so the offline authoring road
    // (and the seed) read it. `AuthorFixtureChirho` alone only provisions the eight named secrets,
    // which is enough for config/plan authoring but not for a statement that names this node.
    sign_message_chirho(
        &fixture_chirho.root_chirho,
        b"provision activation-author node identity chirho",
    )
    .unwrap();

    // Emit the config/plan pair through the same road the ledger-host-author verb calls, and take
    // the plan digest it produced — this is the "ledger-host-author test path" the seed also uses.
    let emitted_chirho =
        author_and_emit_ledger_host_artifacts_chirho(LedgerHostEmissionRequestChirho {
            selected_root_chirho: &fixture_chirho.root_chirho,
            inputs_chirho: &valid_cli_inputs_chirho(),
            destination_authority_enrollment_chirho: &fixture_chirho
                .enrollment_chirho
                .verified_chirho,
            issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
            activation_secret_name_chirho: Some(ACTIVATION_SECRET_NAME_CHIRHO),
            config_output_chirho: Path::new(CONFIG_OUTPUT_CHIRHO),
            plan_output_chirho: Path::new(PLAN_OUTPUT_CHIRHO),
            serve_port_chirho: SERVE_PORT_CHIRHO,
            mode_chirho: LedgerHostAuthoringModeChirho::ProductionChirho,
        })
        .expect(
            "the config/plan pair must author cleanly, or this arm proves nothing about the seed",
        );

    let activation_output_chirho = fixture_chirho.root_chirho.join(ACTIVATION_OUTPUT_CHIRHO);
    let args_chirho = activation_author_args_chirho(&emitted_chirho, &activation_output_chirho);
    let report_chirho =
        run_ledger_host_activation_author_chirho(&fixture_chirho.root_chirho, &args_chirho)
            .unwrap();

    // The verb's own two properties: the digest is the seed-consumable form, and the file was made.
    assert!(
        report_chirho
            .activation_authorization_digest_chirho
            .starts_with(ACTIVATION_AUTHORIZATION_DIGEST_PREFIX_CHIRHO),
        "the printed digest must be the resident-ledger-activation-authorization form a later run \
         pastes into --expected-activation-authorization-digest-chirho, got: {}",
        report_chirho.activation_authorization_digest_chirho
    );
    assert!(report_chirho.activation_authorization_output_created_chirho);
    assert!(activation_output_chirho.is_file());

    // The written bytes are a canonical ResidentLedgerActivationAuthorizationChirho, at mode 0600.
    let authorization_bytes_chirho = fs::read(&activation_output_chirho).unwrap();
    parse_canonical_resident_ledger_activation_authorization_chirho(&authorization_bytes_chirho)
        .expect(
        "the authored output must parse as a canonical ResidentLedgerActivationAuthorizationChirho",
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode_chirho = fs::metadata(&activation_output_chirho)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(
            mode_chirho & 0o777,
            0o600,
            "the signed authorization sits beside a secret store; it must be owner-only"
        );
    }

    // NO OVERWRITE: re-authoring at the same output refuses, and the artifact is byte-identical.
    let repeat_chirho = run_ledger_host_activation_author_chirho(
        &fixture_chirho.root_chirho,
        &activation_author_args_chirho(&emitted_chirho, &activation_output_chirho),
    );
    assert!(
        repeat_chirho.is_err(),
        "re-authoring over an existing activation authorization must refuse, never overwrite"
    );
    assert_eq!(
        fs::read(&activation_output_chirho).unwrap(),
        authorization_bytes_chirho,
        "a refused re-author must leave the existing authorization untouched"
    );

    // ROUTING: the dispatch handler wrapper routes the new verb and writes to a fresh output.
    let routed_output_chirho = fixture_chirho
        .root_chirho
        .join("routed-activation-authorization-chirho.json");
    assert!(handle_ledger_host_author_command_chirho(
        &fixture_chirho.root_chirho,
        &CommandChirho::LedgerHostActivationAuthorChirho(activation_author_args_chirho(
            &emitted_chirho,
            &routed_output_chirho,
        )),
    )
    .unwrap());
    assert!(routed_output_chirho.is_file());

    // THE CONSUMER-SIDE VERIFY: the real H3-A seed accepts the authored artifact plus the printed
    // digest — it verifies the signature against the config's activation pin, checks the digest,
    // and mints. Success here is the signature/digest proof this verb must earn.
    let stage_chirho = prepare_money_stage_chirho(LedgerRegenesisH3aRequestChirho {
        selected_root_chirho: &fixture_chirho.root_chirho,
        config_path_chirho: &emitted_chirho.config_path_chirho,
        plan_path_chirho: &emitted_chirho.plan_path_chirho,
        expected_plan_digest_chirho: &emitted_chirho.plan_digest_chirho,
        issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO,
        activation_authorization_path_chirho: &activation_output_chirho,
        expected_activation_authorization_digest_chirho: &report_chirho
            .activation_authorization_digest_chirho,
    })
    .expect(
        "the real H3-A seed must accept the authored authorization: verify its signature against \
         the pinned activation authority, match the printed digest, and mint",
    );
    assert_eq!(
        stage_chirho.proof_chirho().plan_digest_chirho,
        emitted_chirho.plan_digest_chirho
    );
    assert_eq!(
        stage_chirho.proof_chirho().replayed_supply_chirho,
        750,
        "the reviewed plan mints 750, so the seed the authored authorization unlocks must replay 750"
    );
}

/// Build one activation-author argument set aimed at a chosen output, from an emitted config/plan.
fn activation_author_args_chirho(
    emitted_chirho: &LedgerHostEmittedArtifactsChirho,
    output_chirho: &Path,
) -> LedgerHostActivationAuthorArgsChirho {
    LedgerHostActivationAuthorArgsChirho {
        config_path_chirho: emitted_chirho.config_path_chirho.clone(),
        plan_path_chirho: emitted_chirho.plan_path_chirho.clone(),
        expected_plan_digest_chirho: emitted_chirho.plan_digest_chirho.clone(),
        issuer_secret_name_chirho: ISSUER_SECRET_NAME_CHIRHO.to_owned(),
        activation_secret_name_chirho: ACTIVATION_SECRET_NAME_CHIRHO.to_owned(),
        activation_authorization_output_chirho: output_chirho.to_path_buf(),
    }
}

/// Every file under the root's secret store, by name and bytes. Used to prove the authoring
/// commands create nothing there.
fn secret_inventory_chirho(root_chirho: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let mut rows_chirho = Vec::new();
    let mut stack_chirho = vec![root_chirho.to_path_buf()];
    while let Some(path_chirho) = stack_chirho.pop() {
        let Ok(entries_chirho) = fs::read_dir(&path_chirho) else {
            continue;
        };
        for entry_chirho in entries_chirho.flatten() {
            let entry_path_chirho = entry_chirho.path();
            if entry_path_chirho.is_dir() {
                stack_chirho.push(entry_path_chirho);
                continue;
            }
            let relative_chirho = entry_path_chirho
                .strip_prefix(root_chirho)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            // The reviewed document and any emitted artifact are not secrets; excluding them keeps
            // this inventory about the one question it asks.
            if relative_chirho == INPUTS_FILE_CHIRHO
                || relative_chirho == CONFIG_OUTPUT_CHIRHO
                || relative_chirho == PLAN_OUTPUT_CHIRHO
            {
                continue;
            }
            rows_chirho.push((
                relative_chirho,
                fs::read(&entry_path_chirho).unwrap_or_default(),
            ));
        }
    }
    rows_chirho.sort();
    rows_chirho
}
