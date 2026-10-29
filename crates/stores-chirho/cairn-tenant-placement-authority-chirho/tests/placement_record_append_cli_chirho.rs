// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION of `cairn-placement-record-append-chirho`, including the SUCCESS path.
//!
//! The four refusal paths were run by hand and that was not enough: **a binary that fails on every
//! input passes all four.** Usage, unreadable, malformed and wrong-shape are each satisfied by a
//! program that does nothing but exit 1, so refusals alone cannot distinguish "refuses correctly" from
//! "never works". The success arm is the positive control for the whole binary.
//!
//! It matters more here than usual: this is the ONLY way to create a placement population, so without
//! this arm the binary's working path would first execute on a host during the migration ceremony —
//! and three of its five positional arguments are same-typed key ids, exactly the shape where a
//! transposition type-checks and runs.
//!
//! Helpers are named `..._placement_append_..._chirho` rather than the obvious short forms because a
//! workspace guard censuses by propagating function names defined exactly once; a test helper sharing
//! a production name silently drops files from that census.

use cairn_placement_chirho::capacity_chirho::capacity_dominance_chirho::AllocatableCapacityChirho;
use cairn_placement_chirho::failure_domain_chirho::FailureDomainChirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::placement_record_store_chirho::TENANT_PLACEMENT_RECORD_LOG_CHIRHO;
use cairn_tenant_placement_authority_chirho::*;
use std::path::{Path, PathBuf};
use std::process::Command;

struct PlacementAppendFixtureChirho {
    record_path_chirho: PathBuf,
    assignment_digest_chirho: String,
    placement_key_chirho: String,
    roster_key_chirho: String,
    plan_key_chirho: String,
}

/// Author one fully signed revision-0 record and write it where the binary can read it.
fn build_placement_append_fixture_chirho(scratch_chirho: &Path) -> PlacementAppendFixtureChirho {
    let key_of_chirho = |name_chirho: &str, message_chirho: &[u8]| {
        let root_chirho = scratch_chirho.join(name_chirho);
        sign_message_chirho(&root_chirho, message_chirho).unwrap();
        (pubkey_hex_chirho(&root_chirho).unwrap(), root_chirho)
    };
    let (placement_key_chirho, placement_root_chirho) =
        key_of_chirho("placement-key-chirho", b"provision-placement-chirho");
    let (roster_key_chirho, _roster_root_chirho) =
        key_of_chirho("roster-key-chirho", b"provision-roster-chirho");
    let (plan_key_chirho, _plan_root_chirho) =
        key_of_chirho("plan-key-chirho", b"provision-plan-chirho");

    let mut node_roots_chirho = (0..4)
        .map(|index_chirho| {
            key_of_chirho(
                &format!("node-{index_chirho}-chirho"),
                b"provision-node-chirho",
            )
        })
        .collect::<Vec<_>>();
    node_roots_chirho.sort_by(|left_chirho, right_chirho| left_chirho.0.cmp(&right_chirho.0));
    let held_observer_chirho = node_roots_chirho.pop().unwrap();

    let domains_chirho = [
        ("hetzner-chirho", "de-fsn-chirho"),
        ("ovh-chirho", "fr-gra-chirho"),
        ("ovh-chirho", "fr-rbx-chirho"),
    ]
    .map(|(provider_chirho, region_chirho)| FailureDomainChirho {
        provider_chirho: provider_chirho.to_string(),
        region_chirho: region_chirho.to_string(),
    });

    let assigned_nodes_chirho = node_roots_chirho
        .iter()
        .enumerate()
        .map(
            |(index_chirho, (node_id_chirho, _root_chirho))| TenantPlacementNodeBindingChirho {
                node_id_chirho: node_id_chirho.clone(),
                failure_domain_chirho: domains_chirho[index_chirho].clone(),
                expected_root_binding_chirho: format!(
                    "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
                    char::from(b'a' + u8::try_from(index_chirho).unwrap())
                        .to_string()
                        .repeat(64)
                ),
                expected_cluster_config_blake3_chirho: char::from(
                    b'd' + u8::try_from(index_chirho).unwrap(),
                )
                .to_string()
                .repeat(64),
            },
        )
        .collect::<Vec<_>>();

    let held_observer_node_chirho = TenantPlacementNodeBindingChirho {
        node_id_chirho: held_observer_chirho.0.clone(),
        failure_domain_chirho: FailureDomainChirho {
            provider_chirho: "hetzner-chirho".to_string(),
            region_chirho: "fi-hel-chirho".to_string(),
        },
        expected_root_binding_chirho: format!(
            "{TENANT_ROOT_BINDING_PREFIX_V1_CHIRHO}{}",
            "1".repeat(64)
        ),
        expected_cluster_config_blake3_chirho: "2".repeat(64),
    };
    let mut allowed_domains_chirho = domains_chirho.to_vec();
    allowed_domains_chirho.sort();

    let intent_chirho = TenantPlacementIntentChirho {
        schema_chirho: TENANT_PLACEMENT_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        digest_domain_chirho: TENANT_PLACEMENT_INTENT_DOMAIN_V1_CHIRHO.to_string(),
        revision_chirho: 0,
        previous_assignment_digest_chirho: None,
        tenant_id_chirho: "credits-demo-chirho".to_string(),
        consistency_group_id_chirho: "tenant-chirho:credits-demo-chirho".to_string(),
        preferred_node_chirho: assigned_nodes_chirho[0].node_id_chirho.clone(),
        assigned_nodes_chirho,
        held_observer_node_chirho,
        demand_chirho: AllocatableCapacityChirho {
            cpu_millicores_chirho: 500,
            memory_bytes_chirho: 512 * 1024 * 1024,
            durable_bytes_chirho: 10 * 1024 * 1024 * 1024,
        },
        residency_chirho: TenantPlacementResidencyChirho {
            allowed_domains_chirho,
        },
        topology_plan_digest_chirho: "f".repeat(64),
    };
    let intent_digest_chirho = tenant_placement_intent_digest_chirho(&intent_chirho).unwrap();

    let serving_chirho = node_roots_chirho
        .iter()
        .zip(&intent_chirho.assigned_nodes_chirho)
        .enumerate()
        .map(
            |(index_chirho, ((node_id_chirho, root_chirho), assigned_chirho))| {
                let mut receipt_chirho = TenantPlacementNodeReadinessReceiptChirho {
                    schema_chirho: TENANT_PLACEMENT_NODE_READINESS_SCHEMA_V2_CHIRHO.to_string(),
                    signature_domain_chirho: TENANT_PLACEMENT_NODE_READINESS_DOMAIN_V2_CHIRHO
                        .to_string(),
                    intent_digest_chirho: intent_digest_chirho.clone(),
                    node_id_chirho: node_id_chirho.clone(),
                    failure_domain_chirho: assigned_chirho.failure_domain_chirho.clone(),
                    root_binding_chirho: assigned_chirho.expected_root_binding_chirho.clone(),
                    cluster_config_blake3_chirho: assigned_chirho
                        .expected_cluster_config_blake3_chirho
                        .clone(),
                    activation_anchor_digest_chirho: Some(
                        char::from(b'3' + u8::try_from(index_chirho).unwrap())
                            .to_string()
                            .repeat(64),
                    ),
                    prepared_at_ms_chirho: 1_786_542_000_000,
                    signer_key_id_chirho: node_id_chirho.clone(),
                    sig_chirho: String::new(),
                };
                let unsigned_chirho =
                    unsigned_tenant_placement_readiness_message_chirho(&receipt_chirho).unwrap();
                receipt_chirho.sig_chirho =
                    sign_message_chirho(root_chirho, &unsigned_chirho).unwrap();
                receipt_chirho
            },
        )
        .collect::<Vec<_>>();

    let mut held_receipt_chirho = TenantPlacementHeldObserverReadinessReceiptChirho {
        schema_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_HELD_OBSERVER_READINESS_DOMAIN_V1_CHIRHO
            .to_string(),
        intent_digest_chirho: intent_digest_chirho.clone(),
        node_id_chirho: held_observer_chirho.0.clone(),
        failure_domain_chirho: intent_chirho
            .held_observer_node_chirho
            .failure_domain_chirho
            .clone(),
        root_binding_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_root_binding_chirho
            .clone(),
        cluster_config_blake3_chirho: intent_chirho
            .held_observer_node_chirho
            .expected_cluster_config_blake3_chirho
            .clone(),
        prepared_at_ms_chirho: 1_786_542_000_001,
        signer_key_id_chirho: held_observer_chirho.0.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho =
        unsigned_tenant_placement_held_observer_readiness_message_chirho(&held_receipt_chirho)
            .unwrap();
    held_receipt_chirho.sig_chirho =
        sign_message_chirho(&held_observer_chirho.1, &unsigned_chirho).unwrap();

    let mut record_chirho = TenantPlacementRecordChirho {
        schema_chirho: TENANT_PLACEMENT_RECORD_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: TENANT_PLACEMENT_RECORD_DOMAIN_V2_CHIRHO.to_string(),
        intent_chirho,
        intent_digest_chirho,
        serving_readiness_receipts_chirho: serving_chirho,
        held_observer_readiness_receipt_chirho: held_receipt_chirho,
        placement_key_id_chirho: placement_key_chirho.clone(),
        sig_chirho: String::new(),
    };
    let unsigned_chirho = unsigned_tenant_placement_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        sign_message_chirho(&placement_root_chirho, &unsigned_chirho).unwrap();

    let assignment_digest_chirho =
        tenant_placement_assignment_digest_chirho(&record_chirho).unwrap();
    let record_path_chirho = scratch_chirho.join("record-chirho.json");
    std::fs::write(
        &record_path_chirho,
        serde_json::to_vec(&record_chirho).unwrap(),
    )
    .unwrap();

    PlacementAppendFixtureChirho {
        record_path_chirho,
        assignment_digest_chirho,
        placement_key_chirho,
        roster_key_chirho,
        plan_key_chirho,
    }
}

fn run_placement_append_cli_chirho(arguments_chirho: &[&str]) -> (bool, String, String) {
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-placement-record-append-chirho"))
        .args(arguments_chirho)
        .output()
        .expect("the shipped binary runs");
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).to_string(),
        String::from_utf8_lossy(&output_chirho.stderr).to_string(),
    )
}

/// THE POSITIVE CONTROL — without this, every refusal arm below is satisfied by a binary that always
/// exits 1.
#[test]
fn the_shipped_binary_appends_a_verified_record_and_the_log_carries_it_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let scratch_chirho = temp_chirho.path().join("scratch-chirho");
    std::fs::create_dir_all(&scratch_chirho).unwrap();
    let root_chirho = temp_chirho.path().join("root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let fixture_chirho = build_placement_append_fixture_chirho(&scratch_chirho);

    let (ok_chirho, stdout_chirho, stderr_chirho) = run_placement_append_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        fixture_chirho.record_path_chirho.to_str().unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    ]);
    assert!(ok_chirho, "the success path must exit 0: {stderr_chirho}");
    assert!(
        stdout_chirho.contains(&fixture_chirho.assignment_digest_chirho),
        "stdout must name the assignment digest: {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("credits-demo-chirho")
            && stdout_chirho.contains("revision_chirho=0"),
        "stdout must name the tenant and revision: {stdout_chirho}"
    );

    let log_chirho =
        std::fs::read_to_string(root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO)).unwrap();
    assert_eq!(log_chirho.lines().count(), 1, "exactly one ref appended");
    assert!(
        log_chirho.contains(&fixture_chirho.assignment_digest_chirho),
        "the log must carry the digest the binary reported"
    );
}

/// Re-running with the identical record appends nothing and still succeeds.
#[test]
fn appending_the_identical_record_twice_leaves_one_entry_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let scratch_chirho = temp_chirho.path().join("scratch-chirho");
    std::fs::create_dir_all(&scratch_chirho).unwrap();
    let root_chirho = temp_chirho.path().join("root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let fixture_chirho = build_placement_append_fixture_chirho(&scratch_chirho);
    let arguments_chirho = [
        root_chirho.to_str().unwrap().to_string(),
        fixture_chirho
            .record_path_chirho
            .to_str()
            .unwrap()
            .to_string(),
        fixture_chirho.placement_key_chirho.clone(),
        fixture_chirho.roster_key_chirho.clone(),
        fixture_chirho.plan_key_chirho.clone(),
    ];
    let borrowed_chirho: Vec<&str> = arguments_chirho.iter().map(String::as_str).collect();

    assert!(run_placement_append_cli_chirho(&borrowed_chirho).0);
    assert!(
        run_placement_append_cli_chirho(&borrowed_chirho).0,
        "an exact duplicate is idempotent"
    );
    let log_chirho =
        std::fs::read_to_string(root_chirho.join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO)).unwrap();
    assert_eq!(
        log_chirho.lines().count(),
        1,
        "the duplicate appended nothing"
    );
}

/// TRANSPOSED KEY ARGUMENTS — three of five positionals are same-typed key ids, so a swap
/// type-checks and runs. It must refuse, and it must leave no log behind.
#[test]
fn transposed_authority_arguments_refuse_and_write_nothing_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let scratch_chirho = temp_chirho.path().join("scratch-chirho");
    std::fs::create_dir_all(&scratch_chirho).unwrap();
    let root_chirho = temp_chirho.path().join("root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let fixture_chirho = build_placement_append_fixture_chirho(&scratch_chirho);

    // placement and roster swapped — the exact operator slip this argument shape invites.
    let (ok_chirho, _stdout_chirho, stderr_chirho) = run_placement_append_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        fixture_chirho.record_path_chirho.to_str().unwrap(),
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.plan_key_chirho,
    ]);
    assert!(!ok_chirho, "transposed keys must refuse");
    assert!(
        stderr_chirho.contains("RecordUnverifiableChirho"),
        "and refuse as unverifiable rather than by a generic error: {stderr_chirho}"
    );
    assert!(
        !root_chirho
            .join(TENANT_PLACEMENT_RECORD_LOG_CHIRHO)
            .exists(),
        "a refused append must leave no log"
    );
}

/// The four operator-error paths, now COMMITTED rather than reported from a past run.
#[test]
fn operator_error_paths_refuse_by_their_own_identities_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let root_chirho = temp_chirho.path();

    let (ok_chirho, _out_chirho, err_chirho) = run_placement_append_cli_chirho(&[]);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("PlacementRecordAppendUsageRefusedChirho"),
        "{err_chirho}"
    );

    let (ok_chirho, _out_chirho, err_chirho) = run_placement_append_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        root_chirho.join("absent-chirho.json").to_str().unwrap(),
        "aa",
        "bb",
        "cc",
    ]);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("PlacementRecordFileUnreadableChirho"),
        "{err_chirho}"
    );

    let malformed_chirho = root_chirho.join("malformed-chirho.json");
    std::fs::write(&malformed_chirho, b"not json").unwrap();
    let (ok_chirho, _out_chirho, err_chirho) = run_placement_append_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        malformed_chirho.to_str().unwrap(),
        "aa",
        "bb",
        "cc",
    ]);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("PlacementRecordFileMalformedChirho"),
        "{err_chirho}"
    );

    let wrong_shape_chirho = root_chirho.join("wrong-shape-chirho.json");
    std::fs::write(&wrong_shape_chirho, br#"{"schema_chirho":"x"}"#).unwrap();
    let (ok_chirho, _out_chirho, err_chirho) = run_placement_append_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        wrong_shape_chirho.to_str().unwrap(),
        "aa",
        "bb",
        "cc",
    ]);
    assert!(!ok_chirho);
    assert!(
        err_chirho.contains("PlacementRecordFileMalformedChirho"),
        "{err_chirho}"
    );
}

fn run_placement_population_report_cli_chirho(arguments_chirho: &[&str]) -> (bool, String, String) {
    let output_chirho = Command::new(env!(
        "CARGO_BIN_EXE_cairn-placement-population-report-chirho"
    ))
    .args(arguments_chirho)
    .output()
    .expect("the shipped report binary runs");
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).to_string(),
        String::from_utf8_lossy(&output_chirho.stderr).to_string(),
    )
}

/// The reported CANDIDATE is exactly what the compared load accepts — and the load still refuses
/// anything else.
///
/// Both halves matter. The first proves the review path and the admission path agree, so an operator
/// who pins what the report printed gets a gate that opens. The second proves the split did not turn
/// the comparison off: the loader is still comparing, it is simply comparing against a number a human
/// carried across.
#[test]
fn the_reported_candidate_is_what_the_compared_load_accepts_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let scratch_chirho = temp_chirho.path().join("scratch-chirho");
    std::fs::create_dir_all(&scratch_chirho).unwrap();
    let root_chirho = temp_chirho.path().join("root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let fixture_chirho = build_placement_append_fixture_chirho(&scratch_chirho);
    assert!(
        run_placement_append_cli_chirho(&[
            root_chirho.to_str().unwrap(),
            fixture_chirho.record_path_chirho.to_str().unwrap(),
            &fixture_chirho.placement_key_chirho,
            &fixture_chirho.roster_key_chirho,
            &fixture_chirho.plan_key_chirho,
        ])
        .0
    );

    let (ok_chirho, stdout_chirho, stderr_chirho) = run_placement_population_report_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    ]);
    assert!(
        ok_chirho,
        "the report must succeed on a good store: {stderr_chirho}"
    );
    assert!(
        stdout_chirho.contains("REVIEW ONLY, admits nothing"),
        "the report must say in its OWN TEXT that it decides nothing: {stdout_chirho}"
    );
    let candidate_chirho = stdout_chirho
        .lines()
        .find_map(|line_chirho| line_chirho.strip_prefix("candidate_population_digest_chirho="))
        .expect("the report names a candidate digest")
        .to_string();

    // The pin an operator would copy across is accepted by the admission path.
    cairn_tenant_placement_authority_chirho::attestation_stores_chirho::placement_record_store_chirho::load_verified_placement_population_chirho(
        &root_chirho,
        &candidate_chirho,
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect("the reported candidate is what the load accepts");

    // And the comparison is still live: anything else refuses.
    let refusal_chirho = cairn_tenant_placement_authority_chirho::attestation_stores_chirho::placement_record_store_chirho::load_verified_placement_population_chirho(
        &root_chirho,
        &"0".repeat(64),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    )
    .expect_err("a wrong pin must still refuse");
    assert!(
        format!("{refusal_chirho:?}").contains("PopulationDigestMismatchChirho"),
        "splitting report from load must not turn the comparison off: {refusal_chirho:?}"
    );
}

/// The report refuses an empty store rather than printing a confident empty population.
#[test]
fn the_report_refuses_an_empty_store_rather_than_reporting_nothing_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    let scratch_chirho = temp_chirho.path().join("scratch-chirho");
    std::fs::create_dir_all(&scratch_chirho).unwrap();
    let root_chirho = temp_chirho.path().join("root-chirho");
    std::fs::create_dir_all(&root_chirho).unwrap();
    let fixture_chirho = build_placement_append_fixture_chirho(&scratch_chirho);

    let (ok_chirho, _stdout_chirho, stderr_chirho) = run_placement_population_report_cli_chirho(&[
        root_chirho.to_str().unwrap(),
        &fixture_chirho.placement_key_chirho,
        &fixture_chirho.roster_key_chirho,
        &fixture_chirho.plan_key_chirho,
    ]);
    assert!(!ok_chirho, "an empty store must refuse");
    assert!(
        stderr_chirho.contains("NoCurrentPlacementsChirho"),
        "and by the vacuity identity, so a reviewer is never handed a confident empty: {stderr_chirho}"
    );
}
