// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

fn valid_host_block_chirho() -> String {
    format!(
        r#"
[ledger_host_chirho]
schema_chirho = "ledger-host-config-v1-chirho"
storage_namespace_chirho = "ledger-host-chirho"
monitor_evidence_namespace_chirho = "ledger-monitor-ops-chirho"
monitor_evidence_path_chirho = "cycles/conservation-chirho.jsonl"
money_group_id_chirho = "credits-money-group-chirho"
cluster_id_chirho = "credits-cluster-chirho"
journal_path_chirho = "journals/credits-chirho.jsonl"
local_epoch_chirho = 0
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "credits-kind-registry-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "credits-projections-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "credits-sources-chirho"
monitor_cadence_ms_chirho = 5000

[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"

[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-issuer-chirho"
verifying_key_hex_chirho = "{}"

[[ledger_host_chirho.projection_routes_chirho]]
projection_name_chirho = "credits-balances-chirho"
head_path_chirho = "projections/credits-balances-chirho"

[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "ledger-journal-key-chirho"
config_chirho = "ledger-config-key-chirho"
feeder_chirho = "ledger-feeder-key-chirho"
kind_root_chirho = "ledger-kind-root-key-chirho"
effect_intent_chirho = "effect-intent-key-chirho"
effect_terminal_chirho = "effect-terminal-key-chirho"
"#,
        "11".repeat(32)
    )
}

fn valid_host_block_with_activation_chirho() -> String {
    valid_host_block_chirho()
        .replace(
            LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
            LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        )
        .replace(
            "[[ledger_host_chirho.projection_routes_chirho]]",
            &format!(
                "[ledger_host_chirho.activation_authority_chirho]\n\
                 principal_chirho = \"platform-ledger-activation-chirho\"\n\
                 verifying_key_hex_chirho = \"{}\"\n\n\
                 [[ledger_host_chirho.projection_routes_chirho]]",
                "22".repeat(32)
            ),
        )
}

fn valid_host_block_with_held_pins_chirho() -> String {
    valid_host_block_with_activation_chirho()
        .replace(
            LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
        )
        .replace(
            "[ledger_host_chirho.signer_secrets_chirho]",
            &format!(
                "[ledger_host_chirho.held_verifier_pins_chirho]\n\
                 journal_verifying_key_hex_chirho = \"{}\"\n\n\
                 [ledger_host_chirho.signer_secrets_chirho]",
                "33".repeat(32)
            ),
        )
}

fn valid_host_block_with_live_held_pins_chirho() -> String {
    valid_host_block_with_held_pins_chirho()
        .replace(
            LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
            LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
        )
        .replace(
            &format!("journal_verifying_key_hex_chirho = \"{}\"", "33".repeat(32)),
            &format!(
                "journal_verifying_key_hex_chirho = \"{}\"\n\
                 effect_intent_verifying_key_hex_chirho = \"{}\"\n\
                 effect_terminal_verifying_key_hex_chirho = \"{}\"",
                "33".repeat(32),
                "44".repeat(32),
                "55".repeat(32)
            ),
        )
}

#[test]
fn parses_with_serde_defaults_chirho() {
    let config_chirho = parse_config_chirho("port_chirho = 9000").unwrap();
    assert_eq!(config_chirho.port_chirho, 9000);
    assert_eq!(config_chirho.root_chirho, ".");
    assert_eq!(config_chirho.tenant_chirho, None);
    assert_eq!(config_chirho.inflight_limit_chirho, 32);
    assert_eq!(config_chirho.served_request_window_ms_chirho, 60_000);
    assert_eq!(config_chirho.served_request_actor_max_chirho, 60);
    assert_eq!(
        config_chirho.served_request_actor_body_bytes_chirho,
        8_388_608
    );
    assert_eq!(config_chirho.served_request_global_max_chirho, 600);
    assert_eq!(
        config_chirho.served_request_global_body_bytes_chirho,
        67_108_864
    );
    assert_eq!(config_chirho.served_request_actor_bucket_cap_chirho, 4_096);
    assert_eq!(
        config_chirho.sign_in_principal_successes_per_hour_chirho,
        10
    );
    assert_eq!(config_chirho.sign_in_source_successes_per_hour_chirho, 60);
    assert_eq!(config_chirho.sign_in_source_failures_per_window_chirho, 100);
    assert_eq!(config_chirho.registration_token_chirho, "");
    assert_eq!(config_chirho.geo_cluster_config_chirho, None);
    assert_eq!(config_chirho.ledger_host_chirho, None);
}

#[test]
fn geo_cluster_config_is_explicit_nonempty_and_round_trips_chirho() {
    let config_chirho =
        parse_config_chirho("geo_cluster_config_chirho = \"geo/node-1-chirho.json\"").unwrap();
    assert_eq!(
        config_chirho.geo_cluster_config_chirho.as_deref(),
        Some("geo/node-1-chirho.json")
    );
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    let round_trip_chirho = parse_config_chirho(&serialized_chirho).unwrap();
    assert_eq!(
        round_trip_chirho.geo_cluster_config_chirho,
        config_chirho.geo_cluster_config_chirho
    );
    assert!(parse_config_chirho("geo_cluster_config_chirho = \"\"").is_err());
}

#[test]
fn typed_config_serializer_round_trips_the_validated_host_shape_chirho() {
    let source_chirho = format!(
        "root_chirho = \"/var/lib/cairn-chirho/test-root-chirho\"\nport_chirho = 8798\n{}",
        valid_host_block_chirho()
    );
    let config_chirho = parse_config_chirho(&source_chirho).unwrap();
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    let round_trip_chirho = parse_config_chirho(&serialized_chirho).unwrap();
    assert_eq!(round_trip_chirho.root_chirho, config_chirho.root_chirho);
    assert_eq!(round_trip_chirho.port_chirho, config_chirho.port_chirho);
    assert_eq!(
        round_trip_chirho.ledger_host_chirho,
        config_chirho.ledger_host_chirho
    );
}

#[test]
fn host_config_schema_versions_bound_activation_authority_chirho() {
    let v1_without_activation_chirho = valid_host_block_chirho();
    let v1_config_chirho = parse_config_chirho(&v1_without_activation_chirho).unwrap();
    let v1_host_chirho = v1_config_chirho.ledger_host_chirho.unwrap();
    assert_eq!(
        v1_host_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO
    );
    assert_eq!(v1_host_chirho.activation_authority_chirho, None);

    let v2_without_activation_chirho = v1_without_activation_chirho.replace(
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    );
    let v2_host_chirho = parse_config_chirho(&v2_without_activation_chirho)
        .unwrap()
        .ledger_host_chirho
        .unwrap();
    assert_eq!(
        v2_host_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
    );
    assert_eq!(v2_host_chirho.activation_authority_chirho, None);

    let v1_with_activation_chirho = valid_host_block_with_activation_chirho().replace(
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
    );
    assert_eq!(
        parse_config_chirho(&v1_with_activation_chirho)
            .unwrap_err()
            .to_string(),
        "ledger host config schema v1 cannot carry activation or held-verifier authority"
    );

    let unknown_schema_chirho = v1_without_activation_chirho.replace(
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
        "ledger-host-config-v5-chirho",
    );
    assert_eq!(
        parse_config_chirho(&unknown_schema_chirho)
            .unwrap_err()
            .to_string(),
        "unsupported ledger host config schema"
    );
}

#[test]
fn host_config_v3_requires_a_distinct_public_only_held_verifier_chirho() {
    let source_chirho = valid_host_block_with_held_pins_chirho();
    let host_chirho = parse_config_chirho(&source_chirho)
        .unwrap()
        .ledger_host_chirho
        .unwrap();
    assert_eq!(
        host_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO
    );
    assert_eq!(
        host_chirho
            .held_verifier_pins_chirho
            .as_ref()
            .unwrap()
            .journal_verifying_key_hex_chirho,
        "33".repeat(32)
    );
    assert_eq!(
        host_chirho
            .held_verifier_pins_chirho
            .as_ref()
            .unwrap()
            .effect_intent_verifying_key_hex_chirho,
        None
    );
    assert_eq!(
        host_chirho
            .held_verifier_pins_chirho
            .as_ref()
            .unwrap()
            .effect_terminal_verifying_key_hex_chirho,
        None
    );
    let serialized_chirho =
        serialize_config_chirho(&parse_config_chirho(&source_chirho).unwrap()).unwrap();
    assert!(!serialized_chirho.contains("effect_intent_verifying_key_hex_chirho"));
    assert!(!serialized_chirho.contains("effect_terminal_verifying_key_hex_chirho"));
    assert!(parse_config_chirho(&serialized_chirho).is_ok());

    let missing_chirho = source_chirho.replace(
        LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    );
    assert_eq!(
        parse_config_chirho(&missing_chirho)
            .unwrap_err()
            .to_string(),
        "ledger host config schema v2 cannot carry held-verifier authority"
    );
    let v3_without_pins_chirho = valid_host_block_with_activation_chirho().replace(
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
    );
    assert_eq!(
        parse_config_chirho(&v3_without_pins_chirho)
            .unwrap_err()
            .to_string(),
        "ledger host config schema v3 requires held-verifier authority"
    );
    let duplicate_issuer_key_chirho = source_chirho.replace(&"33".repeat(32), &"11".repeat(32));
    assert!(parse_config_chirho(&duplicate_issuer_key_chirho)
        .unwrap_err()
        .to_string()
        .contains("distinct from other authorities"));
}

#[test]
fn host_config_v4_requires_all_three_public_only_held_verifiers_chirho() {
    let source_chirho = valid_host_block_with_live_held_pins_chirho();
    let config_chirho = parse_config_chirho(&source_chirho).unwrap();
    let host_chirho = config_chirho.ledger_host_chirho.as_ref().unwrap();
    let pins_chirho = host_chirho.held_verifier_pins_chirho.as_ref().unwrap();
    assert_eq!(
        host_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO
    );
    assert_eq!(
        pins_chirho.journal_verifying_key_hex_chirho,
        "33".repeat(32)
    );
    assert_eq!(
        pins_chirho
            .effect_intent_verifying_key_hex_chirho
            .as_deref(),
        Some("44".repeat(32).as_str())
    );
    assert_eq!(
        pins_chirho
            .effect_terminal_verifying_key_hex_chirho
            .as_deref(),
        Some("55".repeat(32).as_str())
    );
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    assert_eq!(
        parse_config_chirho(&serialized_chirho)
            .unwrap()
            .ledger_host_chirho,
        config_chirho.ledger_host_chirho
    );

    let no_pins_chirho = valid_host_block_with_activation_chirho().replace(
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
    );
    assert!(parse_config_chirho(&no_pins_chirho)
        .unwrap_err()
        .to_string()
        .contains("schema v4 requires"));

    for missing_field_chirho in [
        format!(
            "effect_intent_verifying_key_hex_chirho = \"{}\"\n",
            "44".repeat(32)
        ),
        format!(
            "effect_terminal_verifying_key_hex_chirho = \"{}\"\n",
            "55".repeat(32)
        ),
    ] {
        let incomplete_chirho = source_chirho.replace(&missing_field_chirho, "");
        assert!(parse_config_chirho(&incomplete_chirho)
            .unwrap_err()
            .to_string()
            .contains("schema v4 requires"));
    }

    let v3_with_live_pins_chirho = source_chirho.replace(
        LEDGER_HOST_CONFIG_SCHEMA_V4_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V3_CHIRHO,
    );
    assert_eq!(
        parse_config_chirho(&v3_with_live_pins_chirho)
            .unwrap_err()
            .to_string(),
        "ledger host config schema v3 admits only journal held-verifier authority"
    );
}

#[test]
fn host_config_v4_verifier_roots_are_canonical_and_pairwise_distinct_chirho() {
    let source_chirho = valid_host_block_with_live_held_pins_chirho();
    for (from_key_chirho, duplicate_key_chirho) in [
        ("33".repeat(32), "11".repeat(32)),
        ("33".repeat(32), "22".repeat(32)),
        ("44".repeat(32), "11".repeat(32)),
        ("44".repeat(32), "22".repeat(32)),
        ("44".repeat(32), "33".repeat(32)),
        ("55".repeat(32), "11".repeat(32)),
        ("55".repeat(32), "22".repeat(32)),
        ("55".repeat(32), "33".repeat(32)),
        ("55".repeat(32), "44".repeat(32)),
    ] {
        let duplicate_chirho = source_chirho.replace(&from_key_chirho, &duplicate_key_chirho);
        assert!(parse_config_chirho(&duplicate_chirho)
            .unwrap_err()
            .to_string()
            .contains("pairwise distinct"));
    }

    for from_key_chirho in ["33".repeat(32), "44".repeat(32), "55".repeat(32)] {
        for invalid_key_chirho in ["00".repeat(32), "AA".repeat(32), "abcd".to_string()] {
            assert!(parse_config_chirho(
                &source_chirho.replace(&from_key_chirho, &invalid_key_chirho)
            )
            .is_err());
        }
    }
}

#[test]
fn activation_pin_round_trips_and_must_be_distinct_from_the_kind_issuer_chirho() {
    let source_chirho = valid_host_block_with_activation_chirho();
    let config_chirho = parse_config_chirho(&source_chirho).unwrap();
    let host_chirho = config_chirho.ledger_host_chirho.as_ref().unwrap();
    assert_eq!(
        host_chirho.schema_chirho,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO
    );
    let activation_chirho = host_chirho.activation_authority_chirho.as_ref().unwrap();
    assert_eq!(
        activation_chirho.principal_chirho,
        "platform-ledger-activation-chirho"
    );
    assert_eq!(activation_chirho.verifying_key_hex_chirho, "22".repeat(32));
    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    assert_eq!(
        parse_config_chirho(&serialized_chirho)
            .unwrap()
            .ledger_host_chirho,
        config_chirho.ledger_host_chirho
    );

    let duplicate_principal_chirho = source_chirho.replace(
        "principal_chirho = \"platform-ledger-activation-chirho\"",
        "principal_chirho = \"platform-issuer-chirho\"",
    );
    assert!(parse_config_chirho(&duplicate_principal_chirho).is_err());
    let duplicate_key_chirho = source_chirho.replace(&"22".repeat(32), &"11".repeat(32));
    assert!(parse_config_chirho(&duplicate_key_chirho).is_err());
    let malformed_key_chirho = source_chirho.replace(&"22".repeat(32), "abcd");
    assert!(parse_config_chirho(&malformed_key_chirho).is_err());
}

#[test]
fn strict_host_block_accepts_the_sealed_shape_chirho() {
    let config_chirho = parse_config_chirho(&valid_host_block_chirho()).unwrap();
    let host_chirho = config_chirho.ledger_host_chirho.unwrap();
    assert_eq!(host_chirho.local_epoch_chirho, 0);
    assert_eq!(host_chirho.members_chirho.len(), 1);
    assert_eq!(host_chirho.monitor_cadence_ms_chirho, 5_000);
    assert_eq!(
        host_chirho.monitor_evidence_namespace_chirho,
        "ledger-monitor-ops-chirho"
    );
    assert_eq!(
        host_chirho.money_group_id_chirho,
        "credits-money-group-chirho"
    );
    assert_eq!(host_chirho.postgres_effect_chirho, None);
}

#[test]
fn host_block_accepts_exact_platform_principal_members_chirho() {
    for owner_chirho in ["user/0123456789abcdef", "owner/fedcba9876543210"] {
        let configured_chirho = valid_host_block_chirho().replace(
            "owner_chirho = \"credits-user-chirho\"",
            &format!("owner_chirho = \"{owner_chirho}\""),
        );
        let config_chirho = parse_config_chirho(&configured_chirho).unwrap();
        assert_eq!(
            config_chirho.ledger_host_chirho.unwrap().members_chirho[0].owner_chirho,
            owner_chirho
        );
    }
}

#[test]
fn account_owner_principals_stay_exact_and_cannot_become_authority_coordinates_chirho() {
    for invalid_owner_chirho in [
        "viewer@example.com",
        "service/0123456789abcdef",
        "user/0123456789abcdef/extra",
        "user/0123456789abcde",
        "user/0123456789abcdeF",
        "/",
    ] {
        assert!(validate_ledger_account_owner_chirho(invalid_owner_chirho).is_err());
    }

    let member_principal_chirho = "user/0123456789abcdef";
    let configured_chirho = valid_host_block_chirho().replace(
        "owner_chirho = \"credits-user-chirho\"",
        &format!("owner_chirho = \"{member_principal_chirho}\""),
    );
    assert!(parse_config_chirho(&configured_chirho).is_ok());

    let issuer_chirho = configured_chirho.replace(
        "principal_chirho = \"platform-issuer-chirho\"",
        &format!("principal_chirho = \"{member_principal_chirho}\""),
    );
    assert!(parse_config_chirho(&issuer_chirho).is_err());

    let signer_chirho = configured_chirho.replace(
        "journal_chirho = \"ledger-journal-key-chirho\"",
        &format!("journal_chirho = \"{member_principal_chirho}\""),
    );
    assert!(parse_config_chirho(&signer_chirho).is_err());
}

#[test]
fn strict_host_postgres_effect_block_is_local_phase_b_only_chirho() {
    let configured_chirho = format!(
        "{}\n[ledger_host_chirho.postgres_effect_chirho]\nschema_chirho = \"{}\"\nposture_chirho = \"local-phase-b-chirho\"\nconnection_secret_chirho = \"cf7-postgres-dsn-chirho\"\nbilling_kind_chirho = \"credits-chirho\"\n",
        valid_host_block_chirho(),
        LEDGER_HOST_POSTGRES_EFFECT_CONFIG_SCHEMA_V1_CHIRHO,
    );
    let config_chirho = parse_config_chirho(&configured_chirho).unwrap();
    let postgres_chirho = config_chirho
        .ledger_host_chirho
        .unwrap()
        .postgres_effect_chirho
        .unwrap();
    assert_eq!(
        postgres_chirho.posture_chirho,
        LedgerHostPostgresEffectPostureChirho::LocalPhaseBChirho
    );
    assert_eq!(
        postgres_chirho.connection_secret_chirho,
        "cf7-postgres-dsn-chirho"
    );
    assert_eq!(postgres_chirho.billing_kind_chirho, "credits-chirho");

    let hosted_chirho = configured_chirho.replace(
        "posture_chirho = \"local-phase-b-chirho\"",
        "posture_chirho = \"hosted-chirho\"",
    );
    assert!(parse_config_chirho(&hosted_chirho).is_err());
    let caller_amount_chirho = configured_chirho.replace(
        "billing_kind_chirho = \"credits-chirho\"",
        "billing_kind_chirho = \"credits-chirho\"\namount_chirho = 10",
    );
    assert!(parse_config_chirho(&caller_amount_chirho).is_err());
}

#[test]
fn host_block_refuses_unknown_issuer_secret_duplicate_members_and_bad_cadence_chirho() {
    let issuer_secret_chirho = valid_host_block_chirho().replace(
        "verifying_key_hex_chirho =",
        "issuer_secret_ref_chirho = \"must-not-enter-serve-chirho\"\nverifying_key_hex_chirho =",
    );
    assert!(parse_config_chirho(&issuer_secret_chirho).is_err());

    let member_chirho = r#"
[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"
"#;
    let duplicate_chirho = valid_host_block_chirho().replace(
        "[ledger_host_chirho.kind_issuer_chirho]",
        &format!("{member_chirho}\n[ledger_host_chirho.kind_issuer_chirho]"),
    );
    assert!(parse_config_chirho(&duplicate_chirho).is_err());

    let zero_cadence_chirho = valid_host_block_chirho().replace(
        "monitor_cadence_ms_chirho = 5000",
        "monitor_cadence_ms_chirho = 0",
    );
    assert!(parse_config_chirho(&zero_cadence_chirho).is_err());
}

#[test]
fn host_block_refuses_empty_members_bad_paths_and_duplicate_signer_names_chirho() {
    let without_member_chirho = valid_host_block_chirho().replace(
        r#"[[ledger_host_chirho.members_chirho]]
owner_chirho = "credits-user-chirho"
kind_id_chirho = "credits-chirho"

"#,
        "members_chirho = []\n",
    );
    assert!(parse_config_chirho(&without_member_chirho).is_err());

    let traversal_chirho = valid_host_block_chirho().replace(
        "journal_path_chirho = \"journals/credits-chirho.jsonl\"",
        "journal_path_chirho = \"../credits-chirho.jsonl\"",
    );
    assert!(parse_config_chirho(&traversal_chirho).is_err());

    let duplicate_signer_chirho = valid_host_block_chirho().replace(
        "effect_terminal_chirho = \"effect-terminal-key-chirho\"",
        "effect_terminal_chirho = \"effect-intent-key-chirho\"",
    );
    assert!(parse_config_chirho(&duplicate_signer_chirho).is_err());

    let same_namespace_chirho = valid_host_block_chirho().replace(
        "monitor_evidence_namespace_chirho = \"ledger-monitor-ops-chirho\"",
        "monitor_evidence_namespace_chirho = \"ledger-host-chirho\"",
    );
    assert!(parse_config_chirho(&same_namespace_chirho).is_err());

    let nested_namespace_chirho = valid_host_block_chirho().replace(
        "monitor_evidence_namespace_chirho = \"ledger-monitor-ops-chirho\"",
        "monitor_evidence_namespace_chirho = \"ledger-host-chirho/ops-chirho\"",
    );
    assert!(parse_config_chirho(&nested_namespace_chirho).is_err());
}

#[test]
fn host_block_refuses_malformed_or_zero_issuer_key_chirho() {
    let malformed_chirho = valid_host_block_chirho().replace(&"11".repeat(32), "abcd");
    assert!(parse_config_chirho(&malformed_chirho).is_err());
    let zero_chirho = valid_host_block_chirho().replace(&"11".repeat(32), &"00".repeat(32));
    assert!(parse_config_chirho(&zero_chirho).is_err());
}

#[test]
fn config_file_loader_refuses_oversized_input_before_parsing_chirho() {
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path_chirho = std::env::temp_dir().join(format!(
        "cairn-config-oversized-{}-{nonce_chirho}-chirho.toml",
        std::process::id()
    ));
    std::fs::write(
        &path_chirho,
        vec![b'x'; MAX_CONFIG_FILE_BYTES_CHIRHO as usize + 1],
    )
    .unwrap();
    let error_chirho = match load_config_chirho(&path_chirho) {
        Ok(_) => panic!("oversized config unexpectedly loaded"),
        Err(error_chirho) => error_chirho,
    };
    std::fs::remove_file(path_chirho).unwrap();
    assert!(error_chirho.to_string().contains("exceeds"));
}

#[test]
fn digest_bound_config_loads_only_the_exact_reviewed_bytes_chirho() {
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path_chirho = std::env::temp_dir().join(format!(
        "cairn-config-digest-bound-{}-{nonce_chirho}-chirho.toml",
        std::process::id()
    ));
    let bytes_chirho = b"root_chirho = \"reviewed-root-chirho\"\nport_chirho = 9001\n";
    std::fs::write(&path_chirho, bytes_chirho).unwrap();
    let expected_digest_chirho = blake3::hash(bytes_chirho).to_hex().to_string();

    let config_chirho =
        load_digest_bound_config_chirho(&path_chirho, &expected_digest_chirho).unwrap();
    assert_eq!(config_chirho.root_chirho, "reviewed-root-chirho");
    assert_eq!(config_chirho.port_chirho, 9001);

    std::fs::write(
        &path_chirho,
        b"root_chirho = \"same-owner-foreign-root-chirho\"\nport_chirho = 9001\n",
    )
    .unwrap();
    let error_chirho =
        load_digest_bound_config_chirho(&path_chirho, &expected_digest_chirho).unwrap_err();
    std::fs::remove_file(path_chirho).unwrap();
    assert_eq!(
        error_chirho.downcast_ref::<DigestBoundConfigRefusalChirho>(),
        Some(&DigestBoundConfigRefusalChirho::ConfigDigestMismatchChirho)
    );
}

#[test]
fn digest_bound_config_refuses_mismatch_before_parsing_chirho() {
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path_chirho = std::env::temp_dir().join(format!(
        "cairn-config-digest-before-parse-{}-{nonce_chirho}-chirho.toml",
        std::process::id()
    ));
    std::fs::write(&path_chirho, b"this is not TOML").unwrap();

    let error_chirho = load_digest_bound_config_chirho(&path_chirho, &"11".repeat(32)).unwrap_err();
    std::fs::remove_file(path_chirho).unwrap();
    assert_eq!(
        error_chirho.downcast_ref::<DigestBoundConfigRefusalChirho>(),
        Some(&DigestBoundConfigRefusalChirho::ConfigDigestMismatchChirho)
    );
}

#[test]
fn digest_bound_config_refuses_bad_expectation_before_open_and_missing_without_defaults_chirho() {
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let missing_path_chirho = std::env::temp_dir().join(format!(
        "cairn-config-digest-missing-{}-{nonce_chirho}-chirho.toml",
        std::process::id()
    ));

    let grammar_error_chirho =
        load_digest_bound_config_chirho(&missing_path_chirho, &"AA".repeat(32)).unwrap_err();
    assert_eq!(
        grammar_error_chirho.downcast_ref::<DigestBoundConfigRefusalChirho>(),
        Some(&DigestBoundConfigRefusalChirho::ExpectedDigestInvalidChirho)
    );

    let missing_error_chirho =
        load_digest_bound_config_chirho(&missing_path_chirho, &"11".repeat(32)).unwrap_err();
    assert_eq!(
        missing_error_chirho.downcast_ref::<DigestBoundConfigRefusalChirho>(),
        Some(&DigestBoundConfigRefusalChirho::ConfigFileMissingChirho)
    );
}

/// The reserved-prefixed issuer principal a test-kind config must name. Built from the exported
/// constant rather than spelled, so a change to the prefix moves these arms with it instead of
/// leaving them green against a prefix nothing uses.
fn test_kind_issuer_principal_chirho() -> String {
    format!("{LEDGER_HOST_TEST_KIND_ISSUER_PRINCIPAL_PREFIX_CHIRHO}platform-issuer-chirho")
}

fn with_test_kind_marker_chirho(host_block_chirho: &str) -> String {
    format!(
        "{host_block_chirho}\n[ledger_host_chirho.test_kind_chirho]\nschema_chirho = \"{LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO}\"\n"
    )
}

fn with_reserved_issuer_principal_chirho(host_block_chirho: &str) -> String {
    host_block_chirho.replace(
        "principal_chirho = \"platform-issuer-chirho\"",
        &format!(
            "principal_chirho = \"{}\"",
            test_kind_issuer_principal_chirho()
        ),
    )
}

/// The two halves of brick #5's config law, asserted by IDENTITY in both directions.
///
/// The two refusals are near neighbours — both are about the marker and the reserved prefix — so
/// each arm asserts the message it expects AND that it is not the other one. Without the second
/// assertion a fixture aimed at "the marker is missing" would pass against a validator that emitted
/// "the prefix is missing" for every disagreement, and the law would be half-tested while green.
#[test]
fn test_kind_marker_and_reserved_issuer_principal_require_each_other_chirho() {
    // POSITIVE CONTROLS: both agreeing shapes must PARSE, or every refusal below could be a
    // fixture defect rather than the law firing.
    let production_chirho = valid_host_block_chirho();
    parse_config_chirho(&production_chirho).unwrap();
    let test_kind_chirho =
        with_test_kind_marker_chirho(&with_reserved_issuer_principal_chirho(&production_chirho));
    let parsed_test_kind_chirho = parse_config_chirho(&test_kind_chirho).unwrap();
    let marker_chirho = parsed_test_kind_chirho
        .ledger_host_chirho
        .as_ref()
        .unwrap()
        .test_kind_chirho
        .as_ref()
        .expect("the reviewed test-kind block must survive the round trip");
    assert_eq!(
        marker_chirho.schema_chirho,
        LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO
    );

    // MARKER WITHOUT THE RESERVED PRINCIPAL.
    let marker_only_chirho = with_test_kind_marker_chirho(&production_chirho);
    let refusal_chirho = parse_config_chirho(&marker_only_chirho)
        .expect_err("a marked config naming a production issuer must be refused")
        .to_string();
    assert!(
        refusal_chirho.contains("must name a"),
        "expected the missing-prefix refusal, got: {refusal_chirho}"
    );
    assert!(
        !refusal_chirho.contains("requires the test-kind marker"),
        "the missing-prefix arm fired the missing-MARKER refusal instead: {refusal_chirho}"
    );

    // RESERVED PRINCIPAL WITHOUT THE MARKER — the direction that makes deleting the marker cost
    // an issuer rename rather than one line.
    let principal_only_chirho = with_reserved_issuer_principal_chirho(&production_chirho);
    let refusal_chirho = parse_config_chirho(&principal_only_chirho)
        .expect_err("a reserved-prefixed issuer principal without the marker must be refused")
        .to_string();
    assert!(
        refusal_chirho.contains("requires the test-kind marker"),
        "expected the missing-marker refusal, got: {refusal_chirho}"
    );
    assert!(
        !refusal_chirho.contains("must name a"),
        "the missing-marker arm fired the missing-PREFIX refusal instead: {refusal_chirho}"
    );
}

#[test]
fn test_kind_marker_admits_only_its_reviewed_schema_chirho() {
    let agreeing_chirho = with_test_kind_marker_chirho(&with_reserved_issuer_principal_chirho(
        &valid_host_block_chirho(),
    ));
    parse_config_chirho(&agreeing_chirho).unwrap();

    let foreign_schema_chirho = agreeing_chirho.replace(
        LEDGER_HOST_TEST_KIND_MARKER_SCHEMA_V1_CHIRHO,
        "ledger-host-test-kind-marker-v9-chirho",
    );
    let refusal_chirho = parse_config_chirho(&foreign_schema_chirho)
        .expect_err("an unreviewed marker schema must be refused")
        .to_string();
    assert!(
        refusal_chirho.contains("unsupported ledger host test-kind marker schema"),
        "expected the marker schema refusal, got: {refusal_chirho}"
    );

    // `deny_unknown_fields` still covers the marker table itself: a second coordinate smuggled in
    // beside the schema must not be silently accepted.
    let extra_field_chirho = format!("{agreeing_chirho}issuer_principal_chirho = \"anything\"\n");
    assert!(parse_config_chirho(&extra_field_chirho).is_err());
}

/// The emission road writes its config through `serialize_config_chirho`, so a marked config that
/// parses but cannot be SERIALIZED would break test-kind authoring at the last step — and TOML is
/// order-sensitive about tables, which is exactly the kind of failure a parse-only arm cannot see.
#[test]
fn a_marked_host_config_survives_the_emission_serializer_round_trip_chirho() {
    let parsed_chirho = parse_config_chirho(&with_test_kind_marker_chirho(
        &with_reserved_issuer_principal_chirho(&valid_host_block_chirho()),
    ))
    .unwrap();
    let text_chirho = serialize_config_chirho(&parsed_chirho).unwrap();
    let reparsed_chirho = parse_config_chirho(&text_chirho).unwrap();
    assert_eq!(
        reparsed_chirho.ledger_host_chirho, parsed_chirho.ledger_host_chirho,
        "the emission serializer must round-trip a test-kind host block unchanged"
    );
    assert!(
        reparsed_chirho
            .ledger_host_chirho
            .as_ref()
            .unwrap()
            .test_kind_chirho
            .is_some(),
        "the marker must survive serialization: {text_chirho}"
    );
}

/// A production config carries no marker table at all, so the serialized bytes of every existing
/// reviewed config are unchanged by the field's arrival. This is the property brick #7's
/// byte-identity proof depends on.
#[test]
fn an_unmarked_host_config_serializes_without_a_test_kind_table_chirho() {
    let parsed_chirho = parse_config_chirho(&valid_host_block_chirho()).unwrap();
    assert!(parsed_chirho
        .ledger_host_chirho
        .as_ref()
        .unwrap()
        .test_kind_chirho
        .is_none());
    let text_chirho = serialize_config_chirho(&parsed_chirho).unwrap();
    assert!(
        !text_chirho.contains("test_kind_chirho"),
        "an unmarked config must not emit a test-kind table: {text_chirho}"
    );
}

/// A configured destination authority round-trips, and one sharing the kind issuer's key is refused.
///
/// The self-authorization check — the authority must not be the node's OWN key — cannot live here,
/// because config never sees the node identity. It is enforced in the actor where both are known,
/// and that split is deliberate rather than an omission.
#[test]
fn migration_destination_authority_round_trips_and_must_differ_from_the_kind_issuer_chirho() {
    let base_chirho = valid_host_block_chirho().replace(
        LEDGER_HOST_CONFIG_SCHEMA_V1_CHIRHO,
        LEDGER_HOST_CONFIG_SCHEMA_V2_CHIRHO,
    );
    let source_chirho = format!(
        "{base_chirho}\n[ledger_host_chirho.migration_destination_authority_chirho]\nkey_id_chirho = \"platform-migration-destination-chirho\"\nverifying_key_hex_chirho = \"{}\"\n",
        "33".repeat(32)
    );
    let config_chirho = parse_config_chirho(&source_chirho).unwrap();
    let host_chirho = config_chirho.ledger_host_chirho.as_ref().unwrap();
    let destination_chirho = host_chirho
        .migration_destination_authority_chirho
        .as_ref()
        .unwrap();
    assert_eq!(
        destination_chirho.key_id_chirho,
        "platform-migration-destination-chirho"
    );
    assert_eq!(destination_chirho.verifying_key_hex_chirho, "33".repeat(32));

    let serialized_chirho = serialize_config_chirho(&config_chirho).unwrap();
    assert_eq!(
        parse_config_chirho(&serialized_chirho)
            .unwrap()
            .ledger_host_chirho,
        config_chirho.ledger_host_chirho
    );

    // Absent stays absent: an unconfigured host must not acquire a destination authority by default.
    assert_eq!(
        parse_config_chirho(&base_chirho)
            .unwrap()
            .ledger_host_chirho
            .unwrap()
            .migration_destination_authority_chirho,
        None
    );

    let issuer_key_chirho = host_chirho
        .kind_issuer_chirho
        .verifying_key_hex_chirho
        .clone();
    let shared_key_chirho = source_chirho.replace(
        &format!("verifying_key_hex_chirho = \"{}\"", "33".repeat(32)),
        &format!("verifying_key_hex_chirho = \"{issuer_key_chirho}\""),
    );
    let refusal_chirho = parse_config_chirho(&shared_key_chirho)
        .expect_err("a destination authority sharing the kind issuer key must refuse");
    assert!(
        refusal_chirho
            .to_string()
            .contains("distinct from the kind issuer"),
        "{refusal_chirho}"
    );

    let activation_source_chirho = format!(
        "{}\n[ledger_host_chirho.migration_destination_authority_chirho]\nkey_id_chirho = \"platform-migration-destination-chirho\"\nverifying_key_hex_chirho = \"{}\"\n",
        valid_host_block_with_activation_chirho(),
        "22".repeat(32)
    );
    let activation_refusal_chirho = parse_config_chirho(&activation_source_chirho)
        .expect_err("destination and writer-activation authorities must use distinct keys");
    assert!(
        activation_refusal_chirho
            .to_string()
            .contains("distinct from the resident-writer activation authority"),
        "{activation_refusal_chirho}"
    );
}

#[path = "config_control_plane_tests_chirho.rs"]
mod config_control_plane_tests_chirho;
