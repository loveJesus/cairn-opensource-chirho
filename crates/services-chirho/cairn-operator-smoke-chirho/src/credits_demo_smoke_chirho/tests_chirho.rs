// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Permanent PG integration pin + PG-free law pins for the credits-demo LocalPhaseB PASS packet, and
//! for setup's reviewed-payer steps (C1 A3).
//! The CLI itself NEVER skips green; the integration test is #[ignore]d only because sanctioned
//! local PostgreSQL may be absent in a given environment — the ignore reason names the exact
//! command to run it.

use super::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
}

/// TEST-ONLY app-root resolution: production requires --app-root-chirho explicitly (#6019); only
/// the in-repo integration test may derive the checked-in example from the workspace layout.
fn checked_in_app_root_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
        .join("examples-chirho")
        .join("tree-credits-demo-chirho")
}

fn workspace_root_chirho() -> PathBuf {
    crate::workspace_root_for_operator_smoke_chirho()
}

#[test]
#[ignore = "requires sanctioned local PostgreSQL (host=/tmp port=5432); run with: \
            CARGO_TARGET_DIR=<target> cargo test -p cairn-operator-smoke-chirho \
            credits_demo_localphaseb_pass_packet_emits_green_chirho -- --ignored --nocapture"]
fn credits_demo_localphaseb_pass_packet_emits_green_chirho() {
    let base_chirho = temp_dir_chirho("credits-demo-localphaseb");
    std::fs::create_dir_all(&base_chirho).unwrap();
    let root_chirho = base_chirho.join("operator-root-chirho");
    let inputs_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    let config_path_chirho = inputs_dir_chirho.join("host-config-chirho.toml");
    let plan_path_chirho = inputs_dir_chirho.join("plan-canonical-chirho.json");

    // The fixture stands up the operator root exactly as an operator would (secrets, fresh DB + DSN,
    // registered payer, identity-bound plan + 0600 config, schema + seed). The command consumes it.
    let inputs_chirho = fixture_chirho::prepare_credits_demo_fixture_root_chirho(
        &root_chirho,
        &config_path_chirho,
        &plan_path_chirho,
    )
    .expect("prepare fixture root");

    let app_root_chirho = checked_in_app_root_chirho();
    let packet_result_chirho = run_credits_demo_smoke_chirho(&CreditsDemoSmokeInputsChirho {
        root_chirho: &root_chirho,
        config_path_chirho: &inputs_chirho.config_path_chirho,
        expected_config_digest_chirho: &inputs_chirho.expected_config_digest_chirho,
        plan_path_chirho: &inputs_chirho.plan_path_chirho,
        expected_plan_digest_chirho: &inputs_chirho.expected_plan_digest_chirho,
        issuer_secret_name_chirho: &inputs_chirho.issuer_secret_name_chirho,
        activation_authorization_path_chirho: &inputs_chirho.activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: &inputs_chirho
            .expected_activation_authorization_digest_chirho,
        payer_credential_secret_name_chirho: &inputs_chirho.payer_credential_secret_name_chirho,
        app_root_chirho: &app_root_chirho,
        manifest_path_chirho: None,
        reviewed_payer_principal_chirho: None,
    });
    fixture_chirho::drop_fixture_database_chirho(&inputs_chirho.db_name_chirho);
    let packet_chirho = packet_result_chirho.expect("credits-demo LocalPhaseB PASS packet");

    assert!(packet_chirho.pass_chirho);
    assert!(!packet_chirho.delete_authorized_chirho);
    assert!(packet_chirho.phase_c_precondition_chirho);
    assert_eq!(
        packet_chirho.schema_chirho,
        types_chirho::PASS_PACKET_SCHEMA_CHIRHO
    );

    // Money arc.
    assert!(packet_chirho.conservation_chirho.green_chirho);
    assert_eq!(packet_chirho.conservation_chirho.minted_chirho, 750);
    assert_eq!(packet_chirho.conservation_chirho.balance_l1_chirho, 750);
    assert_eq!(
        packet_chirho.conservation_chirho.balance_after_l2_chirho,
        740
    );
    assert_eq!(packet_chirho.conservation_chirho.balance_final_chirho, 730);
    assert_eq!(
        packet_chirho.conservation_chirho.settlement_final_chirho,
        20
    );
    assert!(packet_chirho.conservation_chirho.no_refund_chirho);
    assert!(packet_chirho.conservation_chirho.conservation_holds_chirho);
    // The verified census structural pin (three distinct-saga pairs at the signed price).
    assert_eq!(
        packet_chirho.conservation_chirho.census_mint_count_chirho,
        1
    );
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .census_escrow_record_count_chirho,
        6
    );
    assert_eq!(
        packet_chirho.conservation_chirho.census_saga_count_chirho,
        3
    );
    assert_eq!(
        packet_chirho
            .conservation_chirho
            .census_settlement_meter_sum_chirho,
        20
    );
    assert!(
        packet_chirho
            .conservation_chirho
            .census_structure_bound_chirho
    );

    // Legs.
    assert!(packet_chirho.verifier_suite_chirho.green_chirho);
    assert!(
        packet_chirho
            .verifier_suite_chirho
            .ledger_substrate_chirho
            .packet_reopen_digest_matches_chirho
    );
    assert!(
        packet_chirho
            .verifier_suite_chirho
            .ledger_substrate_chirho
            .publication_manifest_reopen_digest_matches_chirho
    );
    let publication_manifest_path_chirho = root_chirho
        .join(constants_chirho::MONITOR_NAMESPACE_CHIRHO)
        .join(cairn_ledger_regenesis_chirho::LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO);
    let publication_manifest_bytes_chirho =
        std::fs::read(publication_manifest_path_chirho).unwrap();
    assert_eq!(
        cairn_ledger_regenesis_chirho::ledger_regenesis_publication_manifest_digest_chirho(
            &publication_manifest_bytes_chirho
        ),
        packet_chirho
            .coordinate_chain_chirho
            .regenesis_publication_manifest_digest_chirho
    );
    // #13/#6058: the ADAPTER-VERIFIED provider outcome census (1 committed / 1 DNE / 1 receipt).
    let provider_chirho = &packet_chirho
        .verifier_suite_chirho
        .pg_provider_outcome_chirho;
    assert_eq!(provider_chirho.committed_decisions_chirho, 1);
    assert_eq!(provider_chirho.definite_no_effect_decisions_chirho, 1);
    assert_eq!(provider_chirho.comp_receipt_rows_chirho, 1);
    assert!(provider_chirho.restored_row_fingerprint_matches_chirho);
    assert!(packet_chirho.no_legacy_chirho.green_chirho);
    assert_eq!(
        packet_chirho
            .no_legacy_chirho
            .credential_inventory_chirho
            .legacy_blake3_credentials_chirho,
        0
    );
    assert!(
        packet_chirho
            .no_legacy_chirho
            .artifact_census_chirho
            .money_spine_zero_chirho
    );
    assert!(matches!(
        packet_chirho
            .no_legacy_chirho
            .artifact_census_chirho
            .run_node_migration_chirho,
        types_chirho::RunNodeMigrationCensusChirho::NotApplicablePreLawChirho {
            v2_activation_authority_deployed_chirho: false
        }
    ));
    assert!(packet_chirho.credits_smoke_chirho.green_chirho);
    assert!(
        packet_chirho
            .credits_smoke_chirho
            .l1_matches_verified_regenesis_net_chirho
    );
    assert!(
        packet_chirho
            .credits_smoke_chirho
            .l5_matches_verified_final_net_chirho
    );

    // Escrow invariant read directly from the verified fold.
    assert!(
        packet_chirho
            .credits_smoke_chirho
            .r4b_distinct_retry_chirho
            .payer_held_zero_chirho
    );
    assert!(
        packet_chirho
            .credits_smoke_chirho
            .compensation_chirho
            .payer_held_zero_chirho
    );

    // Coordinate chain: owner/payer split + five-way independent principal chain + verified cuts.
    assert!(
        packet_chirho
            .coordinate_chain_chirho
            .owner_distinct_from_principal_chirho
    );
    assert!(
        packet_chirho
            .coordinate_chain_chirho
            .identity_config_plan_packet_viewer_same_chirho
    );
    assert!(
        packet_chirho
            .coordinate_chain_chirho
            .source_review_report_bound_by_compensation_chirho
    );
    assert!(
        packet_chirho
            .coordinate_chain_chirho
            .genesis_and_final_views_distinct_chirho
    );
    assert!(
        packet_chirho
            .coordinate_chain_chirho
            .l4_plan_chain_closed_chirho
    );
    assert_eq!(
        packet_chirho
            .coordinate_chain_chirho
            .regenesis_account_net_chirho,
        750
    );
    assert_eq!(
        packet_chirho
            .coordinate_chain_chirho
            .final_account_net_chirho,
        730
    );
    assert_eq!(
        packet_chirho
            .coordinate_chain_chirho
            .final_source_seq_chirho,
        packet_chirho
            .coordinate_chain_chirho
            .regenesis_source_seq_chirho
            + 6
    );

    // #6046 deterministic-fixture integration pin: under the fixture's public [0x33; 32] adapter
    // key the RECOMPUTED fingerprint reproduces the known value, and the R4b token is its derived
    // first-hex flip — production never compares against these constants.
    assert_eq!(
        packet_chirho
            .external_preconditions_chirho
            .seed_before_state_fingerprint_chirho,
        constants_chirho::FIXTURE_SEED_FINGERPRINT_CHIRHO
    );
    assert_eq!(
        packet_chirho
            .external_preconditions_chirho
            .r4b_distinct_token_chirho,
        format!(
            "0{}",
            &constants_chirho::FIXTURE_SEED_FINGERPRINT_CHIRHO[1..]
        )
    );

    // No secret / no host coordinate in the emitted packet.
    let json_chirho = serde_json::to_string(&packet_chirho).unwrap();
    evidence_chirho::assert_no_secret_or_path_leak_chirho(&json_chirho, &[]).unwrap();

    let _ = std::fs::remove_dir_all(&base_chirho);
}

/// E1-e-2 DISPATCH: the seeding road's post-regenesis resident authority is opened by the INJECTED
/// opener, not by the hard-coded production door.
///
/// This is the half the PG-free fence arms cannot reach. They prove the fence ADMITS an injection;
/// only a full road that actually completes H3 regenesis arrives at the resident-authority seam, so
/// only this arm can show which opener is invoked there.
///
/// WHAT MAKES IT ATTRIBUTING, since greenness alone would not be: if the road ignored the injection
/// and opened the production door itself, the seeded root would still come out green — the delegate
/// below IS that production door. The claim rests entirely on the CALL COUNT going 0 → 1. A road
/// that dropped the parameter leaves it at 0 and this fails; a road that opened both would leave 1
/// and a second live actor, which the era assertion inside the seed road would not tolerate.
///
/// SCOPE, stated so it is not read wider: this proves DISPATCH with a production config and a
/// production door as the delegate. It deliberately does not run a test-kind config through a
/// compensation-provider door end to end — the fixture that stands up a live database is
/// `cfg(test)` inside this crate, and this crate must never name a provider door. That the
/// test-kind opener reaches an unfenced door is proven separately, in
/// `cairn-ledger-geo-node-testkind-chirho`'s `ea_seeding_opener_door_chirho` arm.
#[test]
#[ignore = "requires sanctioned local PostgreSQL (host=/tmp port=5432); run with: \
            CARGO_TARGET_DIR=<target> cargo test -p cairn-operator-smoke-chirho \
            injected_resident_opener_is_the_one_the_seeding_road_opens_chirho -- --ignored --nocapture"]
fn injected_resident_opener_is_the_one_the_seeding_road_opens_chirho() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let base_chirho = temp_dir_chirho("credits-demo-injected-opener");
    std::fs::create_dir_all(&base_chirho).unwrap();
    let root_chirho = base_chirho.join("operator-root-chirho");
    let inputs_dir_chirho = root_chirho.join("reviewed-inputs-chirho");
    let config_path_chirho = inputs_dir_chirho.join("host-config-chirho.toml");
    let plan_path_chirho = inputs_dir_chirho.join("plan-canonical-chirho.json");

    let inputs_chirho = fixture_chirho::prepare_credits_demo_fixture_root_chirho(
        &root_chirho,
        &config_path_chirho,
        &plan_path_chirho,
    )
    .expect("prepare fixture root");
    // The F4 CAS lifecycle requires explicit initialization; the credits-demo fixture does not do
    // it, so without this the road dies in the app-deploy stage for a reason that has nothing to do
    // with the seam under test (see the FINDING note on the sibling PASS-packet arm, which is red
    // at this brick's base for exactly that reason).
    //
    // OFFLINE MIGRATION, not bootstrap: the fixture has already populated this root, and bootstrap
    // is the empty-root door — it refuses here with
    // `CasLifecycleLegacyRootRequiresOfflineMigrationChirho`. The migration door's stated
    // precondition is that the caller owns proof no publisher, collector, or whole-root replacement
    // is concurrent; this root was created moments ago by this single-threaded test and nothing
    // else can see it.
    cairn_durable_chirho::cas_lifecycle_chirho::migrate_cas_lifecycle_offline_chirho(&root_chirho)
        .expect("initialize CAS lifecycle on the quiesced fixture root");
    let app_root_chirho = checked_in_app_root_chirho();

    // The recorder delegates to the production door, so the seeded root is exactly what the
    // uninjected road would have produced. Only the count distinguishes the two.
    let opener_calls_chirho = AtomicUsize::new(0);
    let recording_opener_chirho =
        |selected_root_chirho: &Path,
         opened_config_path_chirho: &Path,
         opened_config_chirho: &cairn_chirho::config_chirho::LedgerHostConfigChirho| {
            opener_calls_chirho.fetch_add(1, Ordering::SeqCst);
            cairn_ledger_host_chirho::open_resident_effect_journal_handle_chirho(
                selected_root_chirho,
                opened_config_path_chirho,
                opened_config_chirho,
                None,
            )
        };

    let report_result_chirho = run_credits_demo_geo_seed_chirho(
        &CreditsDemoSmokeInputsChirho {
            root_chirho: &root_chirho,
            config_path_chirho: &inputs_chirho.config_path_chirho,
            expected_config_digest_chirho: &inputs_chirho.expected_config_digest_chirho,
            plan_path_chirho: &inputs_chirho.plan_path_chirho,
            expected_plan_digest_chirho: &inputs_chirho.expected_plan_digest_chirho,
            issuer_secret_name_chirho: &inputs_chirho.issuer_secret_name_chirho,
            activation_authorization_path_chirho: &inputs_chirho
                .activation_authorization_path_chirho,
            expected_activation_authorization_digest_chirho: &inputs_chirho
                .expected_activation_authorization_digest_chirho,
            payer_credential_secret_name_chirho: &inputs_chirho.payer_credential_secret_name_chirho,
            app_root_chirho: &app_root_chirho,
            manifest_path_chirho: None,
            reviewed_payer_principal_chirho: None,
        },
        Some(&recording_opener_chirho),
    );
    fixture_chirho::drop_fixture_database_chirho(&inputs_chirho.db_name_chirho);

    // THE CLAIM, asserted BEFORE the report is unwrapped and deliberately so: dispatch happens at
    // the resident-authority seam, which the road crosses before the app-authoring and price-book
    // stages. Unwrapping first would let ANY later-stage failure mask the dispatch evidence and
    // report it as though the seam were the problem.
    assert_eq!(
        opener_calls_chirho.load(Ordering::SeqCst),
        1,
        "the seeding road must open its post-regenesis resident authority through the INJECTED \
         opener exactly once. 0 means the injection was dropped and the road opened the hard-coded \
         production door instead — the widening would then be unreachable and a hosted test-kind \
         drill could never seed."
    );

    let report_chirho = report_result_chirho.expect("injected geo seed report");
    assert!(report_chirho.geo_seeded_chirho);
    assert!(!report_chirho.served_money_arc_executed_chirho);
    assert_eq!(report_chirho.writer_authority_era_chirho, "ElectedChirho");

    let _ = std::fs::remove_dir_all(&base_chirho);
}

/// #6056/#6057 matrix pin against the ONE shared LocalPhaseB DSN law (no PG needed): the smoke
/// preflight accepts exactly what serving accepts — Unix socket, IPv4/IPv6 loopback — and refuses
/// non-local endpoints BEFORE any connection attempt.
#[test]
fn shared_dsn_law_matrix_chirho() {
    for accepted_chirho in [
        "host=/tmp port=5432 dbname=cairn_test_chirho",
        "host=127.0.0.1 port=5432 dbname=cairn_test_chirho",
        "host=::1 dbname=cairn_test_chirho",
        "host=localhost dbname=cairn_test_chirho",
    ] {
        assert!(
            cairn_serve_runtime_chirho::parse_local_phase_b_connection_config_chirho(
                accepted_chirho
            )
            .is_ok(),
            "shared law must accept {accepted_chirho}"
        );
    }
    for refused_chirho in [
        "host=10.0.0.7 port=5432 dbname=cairn_test_chirho",
        "host=db.example.com dbname=cairn_test_chirho",
        "dbname=cairn_test_chirho",
    ] {
        assert!(
            cairn_serve_runtime_chirho::parse_local_phase_b_connection_config_chirho(
                refused_chirho
            )
            .is_err(),
            "shared law must refuse {refused_chirho}"
        );
    }
}

/// #6046/#6047: the R4b token derives from ANY 64-hex fingerprint as its first-hex flip — always
/// distinct, always valid — and malformed fingerprints refuse.
#[test]
fn r4b_token_derivation_chirho() {
    let from_zero_chirho = setup_chirho::derive_r4b_distinct_token_chirho(&"0".repeat(64)).unwrap();
    assert_eq!(from_zero_chirho, format!("1{}", "0".repeat(63)));
    let from_a_chirho = setup_chirho::derive_r4b_distinct_token_chirho(&"a".repeat(64)).unwrap();
    assert_eq!(from_a_chirho, format!("0{}", "a".repeat(63)));
    assert!(setup_chirho::derive_r4b_distinct_token_chirho("short").is_err());
    assert!(setup_chirho::derive_r4b_distinct_token_chirho(&"z".repeat(64)).is_err());
}

fn scan_rs_files_chirho(dir_chirho: &Path, found_chirho: &mut Vec<(PathBuf, String)>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            let name_chirho = path_chirho
                .file_name()
                .and_then(|name_chirho| name_chirho.to_str())
                .unwrap_or("");
            if name_chirho == ".git" || name_chirho == "target" || name_chirho == "node_modules" {
                continue;
            }
            scan_rs_files_chirho(&path_chirho, found_chirho);
        } else if path_chirho
            .extension()
            .and_then(|extension_chirho| extension_chirho.to_str())
            == Some("rs")
        {
            if let Ok(text_chirho) = std::fs::read_to_string(&path_chirho) {
                found_chirho.push((path_chirho, text_chirho));
            }
        }
    }
}

/// #6060/#6065/#6068 pre-delete superset pin: discovery collects EVERY artifact-name literal from
/// the SEALED delete-candidate source PATH SET (the path set is the filter — no name/family list
/// inside discovery), then asserts the FROZEN marker list is a superset. The frozen census
/// outlives the deleted code; this test dies with the delete.
#[test]
fn frozen_money_spine_marker_list_is_superset_of_live_names_chirho() {
    let workspace_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    // The sealed wave-1 delete-candidate source paths.
    scan_rs_files_chirho(
        &workspace_chirho.join("src/economic_flows_chirho"),
        &mut files_chirho,
    );
    if let Ok(text_chirho) =
        std::fs::read_to_string(workspace_chirho.join("src/economic_flows_chirho.rs"))
    {
        files_chirho.push((
            workspace_chirho.join("src/economic_flows_chirho.rs"),
            text_chirho,
        ));
    }
    scan_rs_files_chirho(
        &workspace_chirho.join("crates/domain-chirho/cairn-model-gate1-chirho"),
        &mut files_chirho,
    );
    let mut live_names_chirho = std::collections::BTreeSet::new();
    for (_path_chirho, text_chirho) in &files_chirho {
        let mut rest_chirho = text_chirho.as_str();
        while let Some(start_chirho) = rest_chirho.find('"') {
            let tail_chirho = &rest_chirho[start_chirho + 1..];
            let Some(end_chirho) = tail_chirho.find('"') else {
                break;
            };
            let literal_chirho = &tail_chirho[..end_chirho];
            // Every root-artifact literal in the delete-candidate sources: .jsonl logs plus the
            // exact known head-dir names. No family filter — the PATH SET is the filter.
            // SEALED EXCEPTION (#6065): `head-removals-chirho.jsonl` is a KEPT generic
            // head-removal surface (privacy/compliance/app) that the legacy sources also
            // reference — it is excluded from the frozen census by explicit ruling, never by a
            // curated family filter.
            if !literal_chirho.contains('/')
                && (literal_chirho.ends_with("-chirho.jsonl")
                    || literal_chirho == "gate1-authority-head-chirho")
                && literal_chirho != "head-removals-chirho.jsonl"
            {
                live_names_chirho.insert(literal_chirho.to_string());
            }
            rest_chirho = &tail_chirho[end_chirho + 1..];
        }
    }
    assert!(
        !live_names_chirho.is_empty(),
        "expected the live legacy delete-candidate sources to still name artifacts (pre-delete)"
    );
    for name_chirho in &live_names_chirho {
        assert!(
            constants_chirho::MONEY_SPINE_MARKER_NAMES_CHIRHO
                .iter()
                .any(|marker_chirho| marker_chirho == name_chirho),
            "live delete-candidate artifact name '{name_chirho}' is missing from the FROZEN \
             marker list"
        );
    }
}

/// #6052/#6053 G1 source guard: the smoke's production path consumes ONLY the packet-provenance-
/// sealed parent — zero caller-formed claims, zero direct low-verifier calls, zero raw identity
/// reads (#6049 (d)).
#[test]
fn smoke_source_consumes_only_sealed_surfaces_chirho() {
    let module_dir_chirho = workspace_root_chirho()
        .join("crates/services-chirho/cairn-operator-smoke-chirho/src/credits_demo_smoke_chirho");
    let mut files_chirho = Vec::new();
    scan_rs_files_chirho(&module_dir_chirho, &mut files_chirho);
    assert!(!files_chirho.is_empty());
    for (path_chirho, text_chirho) in &files_chirho {
        if path_chirho.ends_with("tests_chirho.rs") {
            continue;
        }
        for needle_chirho in [
            "H3RegenesisCutPacketClaimChirho {",
            "verify_and_bind_chirho(",
            "load_identities_chirho(",
            "find_identity_chirho(",
        ] {
            assert!(
                !text_chirho.contains(needle_chirho),
                "{} must not contain '{needle_chirho}' (sealed-surface guard)",
                path_chirho.display()
            );
        }
    }
}

/// #6056/#6057 (c): exactly ONE LocalPhaseB DSN-law definition exists workspace-wide.
#[test]
fn one_dsn_law_definition_workspace_wide_chirho() {
    let workspace_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    scan_rs_files_chirho(&workspace_chirho.join("crates"), &mut files_chirho);
    scan_rs_files_chirho(&workspace_chirho.join("src"), &mut files_chirho);
    // The needle is assembled at runtime so THIS test file cannot match itself.
    let needle_chirho = format!("fn {}(", "parse_local_phase_b_connection_config_chirho");
    let definitions_chirho: usize = files_chirho
        .iter()
        .map(|(_path_chirho, text_chirho)| text_chirho.matches(needle_chirho.as_str()).count())
        .sum();
    assert_eq!(
        definitions_chirho, 1,
        "expected exactly one LocalPhaseB DSN-law definition workspace-wide"
    );
}

/// #6069 contract guard: the moment a Packet-4 v2 marker TYPE lands in the workspace, the pre-law
/// census arm must be replaced by the authority-owned verifier — this test fails to force it.
#[test]
fn pre_law_census_dies_when_v2_marker_law_lands_chirho() {
    let workspace_chirho = workspace_root_chirho();
    let mut files_chirho = Vec::new();
    scan_rs_files_chirho(&workspace_chirho.join("crates"), &mut files_chirho);
    scan_rs_files_chirho(&workspace_chirho.join("src"), &mut files_chirho);
    let type_needle_chirho = format!("struct {}", "RuntimeContractMarkerV2Chirho");
    let enum_needle_chirho = format!("enum {}", "RuntimeContractMarkerV2Chirho");
    let landed_chirho = files_chirho.iter().any(|(_path_chirho, text_chirho)| {
        text_chirho.contains(type_needle_chirho.as_str())
            || text_chirho.contains(enum_needle_chirho.as_str())
    });
    assert!(
        !landed_chirho,
        "the v2 runtime-contract marker law has landed: replace the pre-law run/node census with \
         the authority-owned activation verifier (sealed #6066/#6068/#6069)"
    );
}

/// #6106 structural no-leak pins: URI-shaped and loopback-host coordinates refuse anywhere, the
/// bounded route values stay allowed ONLY under `path_chirho`.
#[test]
fn structural_no_leak_pins_chirho() {
    let allowed_chirho = r#"{"path_chirho":"/ssr-chirho/credits-demo-chirho"}"#;
    evidence_chirho::assert_no_secret_or_path_leak_chirho(allowed_chirho, &[]).unwrap();
    for refused_chirho in [
        r#"{"note_chirho":"file:///opt/secret-chirho"}"#,
        r#"{"note_chirho":"http://localhost:1234"}"#,
        r#"{"note_chirho":"LOCALHOST"}"#,
        r#"{"note_chirho":"/opt/secret-chirho"}"#,
        r#"{"other_chirho":"/ssr-chirho/credits-demo-chirho"}"#,
        r#"{"path_chirho":"/ssr-chirho/http://localhost"}"#,
        r#"{"path_chirho":"/ssr-chirho/../objects-chirho"}"#,
    ] {
        assert!(
            evidence_chirho::assert_no_secret_or_path_leak_chirho(refused_chirho, &[]).is_err(),
            "structural policy must refuse {refused_chirho}"
        );
    }
}

/// The setup's reviewed-payer steps (C1 A3). Both the precheck and the registration refuse a principal
/// that is not the plan's payer, and refuse before writing anything when the payer credential secret
/// is missing. The precheck claims nothing: no identity, key-file or attribution state. The registration
/// records exactly that principal with the
/// stored credential, and the payer can log in. Setup itself registers only after regenesis, so a
/// read-only gate's refusal leaves the root fit for a rerun.
mod reviewed_payer_chirho {
    use super::super::constants_chirho::{
        DEFAULT_ISSUER_SECRET_NAME_CHIRHO, DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
    };
    use super::super::fixture_chirho::prepare_unregistered_payer_fixture_root_chirho;
    use super::super::setup_chirho::{
        precheck_reviewed_payer_chirho, register_reviewed_payer_chirho,
        run_credits_demo_setup_chirho, CreditsDemoSmokeInputsChirho,
    };
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const PAYER_CHIRHO: &str = "user/0a1b2c3d4e5f6a7b";
    const CREDENTIAL_CHIRHO: &str = "reviewed-payer-credential-chirho-0001";

    fn tmp_root_chirho() -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let n_chirho =
            COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
        let root_chirho = std::env::temp_dir().join(format!("cairn-reviewed-payer-{n_chirho}"));
        let _ = std::fs::remove_dir_all(&root_chirho);
        std::fs::create_dir_all(&root_chirho).unwrap();
        root_chirho
    }

    fn identity_count_chirho(root_chirho: &std::path::Path) -> usize {
        cairn_chirho::identity_chirho::load_verified_identities_chirho(root_chirho)
            .unwrap()
            .len()
    }

    #[test]
    fn a_reviewed_payer_that_is_not_the_plan_payer_refuses_chirho() {
        let root_chirho = tmp_root_chirho();
        let error_chirho = register_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            "user/0a1b2c3d4e5f6a7c",
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .unwrap_err();
        assert_eq!(
            error_chirho.to_string(),
            "ReviewedPayerIsNotThePlanInitialOwnerChirho"
        );
        assert_eq!(identity_count_chirho(&root_chirho), 0);
    }

    #[test]
    fn a_missing_payer_credential_secret_refuses_before_registering_chirho() {
        let root_chirho = tmp_root_chirho();
        register_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .expect_err("no payer credential secret is stored");
        assert_eq!(identity_count_chirho(&root_chirho), 0);
    }

    #[test]
    fn a_reviewed_payer_registers_with_the_stored_credential_and_logs_in_chirho() {
        let root_chirho = tmp_root_chirho();
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
            CREDENTIAL_CHIRHO.as_bytes(),
        )
        .unwrap();
        register_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .unwrap();
        assert_eq!(identity_count_chirho(&root_chirho), 1);
        cairn_chirho::identity_chirho::login_identity_with_credential_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            CREDENTIAL_CHIRHO,
        )
        .expect("the reviewed payer logs in with the stored credential");
    }

    #[test]
    fn the_precheck_refuses_what_the_registration_refuses_and_claims_nothing_chirho() {
        let root_chirho = tmp_root_chirho();
        let error_chirho = precheck_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            "user/0a1b2c3d4e5f6a7c",
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .unwrap_err();
        assert_eq!(
            error_chirho.to_string(),
            "ReviewedPayerIsNotThePlanInitialOwnerChirho"
        );
        precheck_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .expect_err("no payer credential secret is stored");
        assert_eq!(identity_count_chirho(&root_chirho), 0);
    }

    #[test]
    fn a_passing_precheck_claims_nothing_and_registration_still_succeeds_chirho() {
        let root_chirho = tmp_root_chirho();
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
            CREDENTIAL_CHIRHO.as_bytes(),
        )
        .unwrap();
        precheck_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .unwrap();
        assert_eq!(identity_count_chirho(&root_chirho), 0);
        register_reviewed_payer_chirho(
            &root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .unwrap();
        assert_eq!(identity_count_chirho(&root_chirho), 1);
    }

    /// The database-free setup both setup arms share. The plan names a payer who is not registered yet,
    /// and the app root and the activation authorization are missing, so setup gets no further than its
    /// authoring gate.
    struct UnregisteredPayerSetupChirho {
        root_chirho: PathBuf,
        config_path_chirho: PathBuf,
        plan_path_chirho: PathBuf,
        config_digest_chirho: String,
        plan_digest_chirho: String,
    }

    impl UnregisteredPayerSetupChirho {
        fn new_chirho() -> Self {
            let root_chirho = tmp_root_chirho().canonicalize().unwrap();
            let config_path_chirho =
                root_chirho.join("review-chirho/ledger-host-config-chirho.toml");
            let plan_path_chirho = root_chirho.join("review-chirho/regenesis-plan-chirho.json");
            let (config_digest_chirho, plan_digest_chirho) =
                prepare_unregistered_payer_fixture_root_chirho(
                    &root_chirho,
                    &config_path_chirho,
                    &plan_path_chirho,
                    PAYER_CHIRHO,
                )
                .unwrap();
            Self {
                root_chirho,
                config_path_chirho,
                plan_path_chirho,
                config_digest_chirho,
                plan_digest_chirho,
            }
        }

        /// Runs setup with the reviewed payer, and returns its rendered refusal.
        fn refusal_chirho(&self) -> String {
            let missing_app_root_chirho = self.root_chirho.join("missing-app-chirho");
            let missing_activation_chirho = self
                .root_chirho
                .join("review-chirho/missing-activation-chirho.json");
            let inputs_chirho = CreditsDemoSmokeInputsChirho {
                root_chirho: &self.root_chirho,
                config_path_chirho: &self.config_path_chirho,
                expected_config_digest_chirho: &self.config_digest_chirho,
                plan_path_chirho: &self.plan_path_chirho,
                expected_plan_digest_chirho: &self.plan_digest_chirho,
                issuer_secret_name_chirho: DEFAULT_ISSUER_SECRET_NAME_CHIRHO,
                activation_authorization_path_chirho: &missing_activation_chirho,
                expected_activation_authorization_digest_chirho: "unused-activation-digest-chirho",
                payer_credential_secret_name_chirho: DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
                app_root_chirho: &missing_app_root_chirho,
                manifest_path_chirho: None,
                reviewed_payer_principal_chirho: Some(PAYER_CHIRHO),
            };
            match run_credits_demo_setup_chirho(&inputs_chirho, None) {
                Ok(_) => panic!("setup must refuse: the app root is missing"),
                Err(error_chirho) => format!("{error_chirho:#}"),
            }
        }
    }

    /// Setup registers the reviewed payer only after regenesis (Agy #29339, claude2 #29344). So when a
    /// read-only gate refuses after the precheck, the identity log is still empty and the root is still fit
    /// for a rerun. ASSERT THE REASON: the refusal must come from the authoring gate, which runs after the
    /// precheck. An earlier refusal would leave the log empty for the wrong reason.
    #[test]
    fn a_read_only_refusal_after_the_precheck_registers_nothing_chirho() {
        let setup_chirho = UnregisteredPayerSetupChirho::new_chirho();
        let rendered_chirho = setup_chirho.refusal_chirho();
        assert!(
            rendered_chirho.contains("inspect app root"),
            "the refusal must be the authoring gate's, which runs after the precheck. An earlier gate \
             would leave the log empty for the wrong reason: {rendered_chirho}"
        );
        assert_eq!(
            identity_count_chirho(&setup_chirho.root_chirho),
            0,
            "a refusal before regenesis must not register the reviewed payer"
        );
        precheck_reviewed_payer_chirho(
            &setup_chirho.root_chirho,
            PAYER_CHIRHO,
            PAYER_CHIRHO,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
        )
        .expect("the refused root is still fit for a rerun");
    }

    /// Setup refuses a bad reviewed payer through its precheck, before any authoritative write (claude2
    /// #29410). Here the stored credential is below the floor. ASSERT THE REASON: the floor's refusal, not
    /// the authoring gate's. This fixture's app root is missing too, so the arm also shows that the
    /// precheck runs before that gate.
    #[test]
    fn setup_refuses_a_bad_reviewed_payer_through_its_precheck_chirho() {
        let setup_chirho = UnregisteredPayerSetupChirho::new_chirho();
        cairn_chirho::secret_chirho::set_secret_chirho(
            &setup_chirho.root_chirho,
            DEFAULT_PAYER_CREDENTIAL_SECRET_NAME_CHIRHO,
            b"short-chirho",
        )
        .unwrap();
        let rendered_chirho = setup_chirho.refusal_chirho();
        assert!(
            rendered_chirho
                .contains(cairn_chirho::identity_chirho::IDENTITY_CREDENTIAL_FLOOR_MESSAGE_CHIRHO)
                && !rendered_chirho.contains("inspect app root"),
            "setup must refuse through the precheck, before its authoring gate: {rendered_chirho}"
        );
        assert_eq!(identity_count_chirho(&setup_chirho.root_chirho), 0);
    }
}
