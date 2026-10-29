// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use crate::args_chirho::{CliChirho, CommandChirho};
use crate::cli_context_chirho::CliContextChirho;
use cairn_chirho::effect_chirho::projection_read_chirho::{
    PublishedProjectionReadPortChirho, PublishedProjectionReadRequestChirho,
};
use cairn_chirho::model_chirho::RequestContextChirho;
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_composition_chirho::{FollowerServeOutcomeChirho, ProjectionReadOutcomeChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_regenesis_chirho::{
    author_ledger_regenesis_activation_chirho, canonical_plan_bytes_chirho,
    load_canonical_ledger_regenesis_publication_manifest_chirho, plan_digest_chirho,
    run_ledger_regenesis_chirho, LedgerRegenesisActivationAuthorRequestChirho,
    LedgerRegenesisH3aRequestChirho, LedgerRegenesisPlanV1Chirho,
    LedgerRegenesisProjectionRoutePlanChirho, LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
    LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO,
};
use cairn_serve_runtime_chirho::{
    LedgerConservationCycleOutcomeChirho, LedgerHostProjectionReadPortChirho,
};
use clap::Parser;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn porcelain_requires_the_review_binding_and_exposes_no_money_or_path_override_chirho() {
    let cli_chirho = CliChirho::try_parse_from([
        "cairn-chirho",
        "--root",
        "/tmp/operator-root-chirho",
        "--tenant",
        "tenant-ignored-for-regenesis-chirho",
        "ledger-regenesis-chirho",
        "--config-chirho",
        "host-config-chirho.toml",
        "--plan-chirho",
        "reviewed-plan-chirho.json",
        "--expected-plan-digest-chirho",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--issuer-secret-name-chirho",
        "offline-issuer-chirho",
        "--activation-authorization-chirho",
        "activation-authorization-chirho.json",
        "--expected-activation-authorization-digest-chirho",
        "resident-ledger-activation-authorization-blake3-v1-chirho:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ])
    .unwrap();
    let context_chirho = CliContextChirho::from_cli_chirho(&cli_chirho).unwrap();
    assert_eq!(
        context_chirho.root_chirho(),
        PathBuf::from("/tmp/operator-root-chirho")
    );
    let CommandChirho::LedgerRegenesisChirho(args_chirho) = cli_chirho.command_chirho else {
        panic!("ledger regenesis command did not parse");
    };
    assert_eq!(
        args_chirho.config_path_chirho,
        PathBuf::from("host-config-chirho.toml")
    );
    assert_eq!(
        args_chirho.plan_path_chirho,
        PathBuf::from("reviewed-plan-chirho.json")
    );
    assert_eq!(
        args_chirho.issuer_secret_name_chirho,
        "offline-issuer-chirho"
    );
    assert_eq!(
        args_chirho.activation_authorization_path_chirho,
        PathBuf::from("activation-authorization-chirho.json")
    );
    assert_eq!(
        args_chirho.expected_activation_authorization_digest_chirho,
        "resident-ledger-activation-authorization-blake3-v1-chirho:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    );
}

#[test]
fn porcelain_source_has_one_create_call_and_no_override_fields_chirho() {
    let source_chirho = include_str!("ledger_regenesis_cli_chirho.rs");
    assert_eq!(
        source_chirho
            .matches("run_ledger_regenesis_chirho(")
            .count(),
        1
    );
    let args_source_chirho = include_str!("../../args_chirho/core_chirho/ops_args_chirho.rs");
    let start_chirho = args_source_chirho
        .find("pub struct LedgerRegenesisArgsChirho")
        .unwrap();
    let args_tail_chirho = &args_source_chirho[start_chirho..];
    let end_chirho = args_tail_chirho.find("\n}\n").unwrap() + 3;
    let args_block_chirho = &args_tail_chirho[..end_chirho];
    assert!(!args_block_chirho.contains("amount_chirho"));
    assert!(!args_block_chirho.contains("storage_namespace_chirho"));
    assert!(!args_block_chirho.contains("journal_path_chirho"));
}

#[test]
fn served_runtime_has_no_regenesis_dependency_edge_chirho() {
    let serve_manifest_chirho = include_str!("../../../../cairn-serve-runtime-chirho/Cargo.toml");
    assert!(!serve_manifest_chirho.contains("cairn-ledger-regenesis-chirho"));
}

#[test]
fn porcelain_publishes_one_h2_openable_fresh_conserved_root_chirho() {
    let fixture_chirho = OperatorRegenesisFixtureChirho::new_chirho();
    let command_chirho = CommandChirho::LedgerRegenesisChirho(
        crate::args_chirho::ops_args_chirho::LedgerRegenesisArgsChirho {
            config_path_chirho: fixture_chirho.config_path_chirho.clone(),
            plan_path_chirho: fixture_chirho.plan_path_chirho.clone(),
            expected_plan_digest_chirho: fixture_chirho.expected_digest_chirho.clone(),
            issuer_secret_name_chirho: OFFLINE_ISSUER_SECRET_NAME_CHIRHO.to_owned(),
            activation_authorization_path_chirho: fixture_chirho
                .activation_authorization_path_chirho
                .clone(),
            expected_activation_authorization_digest_chirho: fixture_chirho
                .expected_activation_authorization_digest_chirho
                .clone(),
        },
    );
    assert!(
        handle_ledger_regenesis_command_chirho(&fixture_chirho.root_chirho, &command_chirho)
            .unwrap()
    );

    let config_chirho =
        cairn_chirho::config_chirho::load_config_chirho(&fixture_chirho.config_path_chirho)
            .unwrap();
    let ledger_host_config_chirho = config_chirho.ledger_host_chirho.as_ref().unwrap();
    let before_open_chirho = snapshot_operator_tree_chirho(&fixture_chirho.root_chirho);
    let port_chirho = LedgerHostProjectionReadPortChirho::open_existing_chirho(
        &fixture_chirho.root_chirho,
        &fixture_chirho.config_path_chirho,
        ledger_host_config_chirho,
    )
    .unwrap();
    assert_eq!(
        snapshot_operator_tree_chirho(&fixture_chirho.root_chirho),
        before_open_chirho,
        "H2 startup must not mutate the published ledger or ops namespaces"
    );

    let request_context_chirho = RequestContextChirho {
        user_principal_chirho: "operator-reader-chirho".to_owned(),
        app_chirho: "tree-credits-demo-chirho".to_owned(),
        owner_principal_chirho: "platform-credits-owner-chirho".to_owned(),
        client_id_chirho: "operator-client-chirho".to_owned(),
        token_hash_chirho: "operator-token-hash-chirho".to_owned(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    for projection_name_chirho in ["credits-balance-chirho", "credits-mirror-chirho"] {
        let read_chirho = port_chirho
            .read_published_projection_chirho(&PublishedProjectionReadRequestChirho {
                projection_name_chirho,
                requested_limit_chirho: 1,
                request_context_chirho: &request_context_chirho,
            })
            .unwrap();
        assert!(matches!(
            read_chirho.outcome_chirho,
            FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
        ));
        assert!(read_chirho.view_bytes_chirho.is_some());
    }

    let conservation_chirho = port_chirho.run_conservation_cycle_once_chirho().unwrap();
    assert!(matches!(
        conservation_chirho.outcome_chirho,
        LedgerConservationCycleOutcomeChirho::GreenChirho { .. }
    ));
}

#[test]
fn porcelain_report_digest_reopens_the_canonical_publication_manifest_chirho() {
    let fixture_chirho = OperatorRegenesisFixtureChirho::new_chirho();
    let receipt_chirho = run_ledger_regenesis_chirho(LedgerRegenesisH3aRequestChirho {
        selected_root_chirho: &fixture_chirho.root_chirho,
        config_path_chirho: &fixture_chirho.config_path_chirho,
        plan_path_chirho: &fixture_chirho.plan_path_chirho,
        expected_plan_digest_chirho: &fixture_chirho.expected_digest_chirho,
        issuer_secret_name_chirho: OFFLINE_ISSUER_SECRET_NAME_CHIRHO,
        activation_authorization_path_chirho: &fixture_chirho.activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: &fixture_chirho
            .expected_activation_authorization_digest_chirho,
    })
    .unwrap();
    let report_chirho = ledger_regenesis_report_chirho(receipt_chirho);
    let manifest_path_chirho = fixture_chirho
        .root_chirho
        .join("fresh-ledger-parent-chirho")
        .join("ops-chirho")
        .join(LEDGER_REGENESIS_PUBLICATION_MANIFEST_FILE_CHIRHO);
    let (manifest_chirho, manifest_digest_chirho) =
        load_canonical_ledger_regenesis_publication_manifest_chirho(&manifest_path_chirho).unwrap();
    assert_eq!(
        manifest_digest_chirho,
        report_chirho.publication_manifest_digest_chirho
    );
    assert_eq!(
        manifest_chirho.plan_digest_chirho,
        report_chirho.plan_digest_chirho
    );
    assert_eq!(
        manifest_chirho.packet_digest_chirho,
        report_chirho.packet_digest_chirho
    );
    assert_eq!(
        manifest_chirho.publication_proof_chirho,
        report_chirho.publication_proof_chirho
    );
}

const OFFLINE_ISSUER_SECRET_NAME_CHIRHO: &str = "offline-kind-issuer-chirho";
const OFFLINE_ACTIVATION_SECRET_NAME_CHIRHO: &str = "offline-ledger-activation-chirho";
const OPERATOR_RUNTIME_SECRET_NAMES_CHIRHO: [&str; 6] = [
    "ledger-journal-secret-chirho",
    "ledger-config-secret-chirho",
    "ledger-feeder-secret-chirho",
    "ledger-kind-root-secret-chirho",
    "ledger-effect-intent-secret-chirho",
    "ledger-effect-terminal-secret-chirho",
];

struct OperatorRegenesisFixtureChirho {
    root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    plan_path_chirho: PathBuf,
    expected_digest_chirho: String,
    activation_authorization_path_chirho: PathBuf,
    expected_activation_authorization_digest_chirho: String,
}

impl OperatorRegenesisFixtureChirho {
    fn new_chirho() -> Self {
        let root_chirho = operator_temp_root_chirho();
        fs::create_dir(&root_chirho).unwrap();
        cairn_signer_chirho::signer_chirho::sign_message_chirho(
            &root_chirho,
            b"provision CLI regenesis node identity chirho",
        )
        .unwrap();
        for (index_chirho, secret_name_chirho) in
            OPERATOR_RUNTIME_SECRET_NAMES_CHIRHO.iter().enumerate()
        {
            cairn_chirho::secret_chirho::set_secret_chirho(
                &root_chirho,
                secret_name_chirho,
                &[(index_chirho + 1) as u8; 32],
            )
            .unwrap();
        }
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            OFFLINE_ISSUER_SECRET_NAME_CHIRHO,
            &[7; 32],
        )
        .unwrap();
        cairn_chirho::secret_chirho::set_secret_chirho(
            &root_chirho,
            OFFLINE_ACTIVATION_SECRET_NAME_CHIRHO,
            &[8; 32],
        )
        .unwrap();
        let issuer_key_chirho = SigningKey::from_bytes(&[7; 32]);
        let issuer_key_hex_chirho =
            operator_hex_encode_chirho(issuer_key_chirho.verifying_key().as_bytes());
        let activation_key_chirho = SigningKey::from_bytes(&[8; 32]);
        let activation_key_hex_chirho =
            operator_hex_encode_chirho(activation_key_chirho.verifying_key().as_bytes());
        let config_path_chirho = root_chirho.join("cairn-regenesis-config-chirho.toml");
        fs::write(
            &config_path_chirho,
            operator_config_text_chirho(&issuer_key_hex_chirho, &activation_key_hex_chirho),
        )
        .unwrap();
        set_operator_private_mode_chirho(&config_path_chirho);
        let plan_path_chirho = root_chirho.join("ledger-regenesis-plan-chirho.json");
        let plan_bytes_chirho = canonical_plan_bytes_chirho(&operator_plan_chirho()).unwrap();
        fs::write(&plan_path_chirho, &plan_bytes_chirho).unwrap();
        let expected_digest_chirho = plan_digest_chirho(&plan_bytes_chirho);
        let activation_artifact_chirho = author_ledger_regenesis_activation_chirho(
            LedgerRegenesisActivationAuthorRequestChirho {
                selected_root_chirho: &root_chirho,
                config_path_chirho: &config_path_chirho,
                plan_path_chirho: &plan_path_chirho,
                expected_plan_digest_chirho: &expected_digest_chirho,
                issuer_secret_name_chirho: OFFLINE_ISSUER_SECRET_NAME_CHIRHO,
                activation_secret_name_chirho: OFFLINE_ACTIVATION_SECRET_NAME_CHIRHO,
            },
        )
        .unwrap();
        let activation_authorization_path_chirho =
            root_chirho.join("activation-authorization-chirho.json");
        fs::write(
            &activation_authorization_path_chirho,
            &activation_artifact_chirho.canonical_bytes_chirho,
        )
        .unwrap();
        set_operator_private_mode_chirho(&activation_authorization_path_chirho);
        Self {
            root_chirho,
            config_path_chirho,
            plan_path_chirho,
            expected_digest_chirho,
            activation_authorization_path_chirho,
            expected_activation_authorization_digest_chirho: activation_artifact_chirho
                .authorization_digest_chirho,
        }
    }
}

impl Drop for OperatorRegenesisFixtureChirho {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_chirho);
    }
}

fn operator_plan_chirho() -> LedgerRegenesisPlanV1Chirho {
    LedgerRegenesisPlanV1Chirho {
        schema_chirho: LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO.to_owned(),
        fresh_parent_chirho: "fresh-ledger-parent-chirho".to_owned(),
        staging_parent_chirho: "fresh-ledger-staging-chirho".to_owned(),
        storage_namespace_chirho: "fresh-ledger-parent-chirho/ledger-chirho".to_owned(),
        monitor_evidence_namespace_chirho: "fresh-ledger-parent-chirho/ops-chirho".to_owned(),
        monitor_evidence_path_chirho: "monitor/cycles-chirho.jsonl".to_owned(),
        money_group_id_chirho: "money-group-local-chirho".to_owned(),
        cluster_id_chirho: "cluster-local-chirho".to_owned(),
        journal_path_chirho: "journals/main-chirho.jsonl".to_owned(),
        local_epoch_chirho: 1,
        kind_registry_path_chirho: "registries/kinds-chirho.jsonl".to_owned(),
        kind_registry_id_chirho: "kind-registry-local-chirho".to_owned(),
        projection_registry_path_chirho: "registries/projections-chirho.jsonl".to_owned(),
        projection_registry_id_chirho: "projection-registry-local-chirho".to_owned(),
        source_registry_path_chirho: "registries/sources-chirho.jsonl".to_owned(),
        source_registry_id_chirho: "source-registry-local-chirho".to_owned(),
        projection_routes_chirho: vec![
            LedgerRegenesisProjectionRoutePlanChirho {
                projection_name_chirho: "credits-balance-chirho".to_owned(),
                head_path_chirho: "published/credits-balance-head-chirho.json".to_owned(),
            },
            LedgerRegenesisProjectionRoutePlanChirho {
                projection_name_chirho: "credits-mirror-chirho".to_owned(),
                head_path_chirho: "published/credits-mirror-head-chirho.json".to_owned(),
            },
        ],
        monitor_cadence_ms_chirho: 5_000,
        issuer_principal_chirho: "platform-kind-issuer-chirho".to_owned(),
        initial_owner_chirho: "platform-credits-owner-chirho".to_owned(),
        kind_id_chirho: "prepaid-credit-chirho".to_owned(),
        initial_policy_chirho: operator_policy_chirho(1_000),
        amended_policy_chirho: operator_policy_chirho(900),
        initial_mint_amount_chirho: 600,
        genesis_physical_ms_chirho: 1_000,
        mint_physical_ms_chirho: 1_100,
    }
}

fn operator_policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
    KindPolicyBodyChirho {
        unit_chirho: "credit-minor-chirho".to_owned(),
        precision_chirho: 0,
        mint_authority_chirho: MintAuthorityRecordChirho::PlatformPolicyChirho {
            max_supply_chirho: Some(max_supply_chirho),
        },
        rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
        shard_attachment_chirho: "shard-local-chirho".to_owned(),
        settlement_owner_chirho: None,
        idempotency_window_chirho: Some(IdempotencyWindowPolicyChirho {
            idempotency_horizon_ms_chirho: 86_400_000,
            retry_finality_horizon_ms_chirho: 86_400_000,
        }),
    }
}

fn snapshot_operator_tree_chirho(root_chirho: &Path) -> Vec<(String, bool, Vec<u8>)> {
    fn walk_chirho(
        root_chirho: &Path,
        path_chirho: &Path,
        rows_chirho: &mut Vec<(String, bool, Vec<u8>)>,
    ) {
        let mut entries_chirho = fs::read_dir(path_chirho)
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
        for entry_chirho in entries_chirho {
            let entry_path_chirho = entry_chirho.path();
            let relative_chirho = entry_path_chirho
                .strip_prefix(root_chirho)
                .unwrap()
                .to_string_lossy()
                .to_string();
            let metadata_chirho = fs::symlink_metadata(&entry_path_chirho).unwrap();
            if metadata_chirho.is_dir() {
                rows_chirho.push((relative_chirho, true, Vec::new()));
                walk_chirho(root_chirho, &entry_path_chirho, rows_chirho);
            } else {
                rows_chirho.push((relative_chirho, false, fs::read(entry_path_chirho).unwrap()));
            }
        }
    }
    let mut rows_chirho = Vec::new();
    walk_chirho(root_chirho, root_chirho, &mut rows_chirho);
    rows_chirho
}

fn operator_config_text_chirho(
    issuer_key_hex_chirho: &str,
    activation_key_hex_chirho: &str,
) -> String {
    format!(
        r#"[ledger_host_chirho]
schema_chirho = "ledger-host-config-v2-chirho"
storage_namespace_chirho = "fresh-ledger-parent-chirho/ledger-chirho"
monitor_evidence_namespace_chirho = "fresh-ledger-parent-chirho/ops-chirho"
monitor_evidence_path_chirho = "monitor/cycles-chirho.jsonl"
money_group_id_chirho = "money-group-local-chirho"
cluster_id_chirho = "cluster-local-chirho"
journal_path_chirho = "journals/main-chirho.jsonl"
local_epoch_chirho = 1
members_chirho = [{{ owner_chirho = "platform-credits-owner-chirho", kind_id_chirho = "prepaid-credit-chirho" }}]
kind_registry_path_chirho = "registries/kinds-chirho.jsonl"
kind_registry_id_chirho = "kind-registry-local-chirho"
projection_registry_path_chirho = "registries/projections-chirho.jsonl"
projection_registry_id_chirho = "projection-registry-local-chirho"
source_registry_path_chirho = "registries/sources-chirho.jsonl"
source_registry_id_chirho = "source-registry-local-chirho"
projection_routes_chirho = [{{ projection_name_chirho = "credits-balance-chirho", head_path_chirho = "published/credits-balance-head-chirho.json" }}, {{ projection_name_chirho = "credits-mirror-chirho", head_path_chirho = "published/credits-mirror-head-chirho.json" }}]
monitor_cadence_ms_chirho = 5000

[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-kind-issuer-chirho"
verifying_key_hex_chirho = "{issuer_key_hex_chirho}"

[ledger_host_chirho.activation_authority_chirho]
principal_chirho = "platform-ledger-activation-chirho"
verifying_key_hex_chirho = "{activation_key_hex_chirho}"

[ledger_host_chirho.signer_secrets_chirho]
journal_chirho = "ledger-journal-secret-chirho"
config_chirho = "ledger-config-secret-chirho"
feeder_chirho = "ledger-feeder-secret-chirho"
kind_root_chirho = "ledger-kind-root-secret-chirho"
effect_intent_chirho = "ledger-effect-intent-secret-chirho"
effect_terminal_chirho = "ledger-effect-terminal-secret-chirho"
"#
    )
}

fn operator_temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-cli-regenesis-test-{}-{now_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

fn operator_hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").unwrap();
    }
    encoded_chirho
}

#[cfg(unix)]
fn set_operator_private_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_operator_private_mode_chirho(_path_chirho: &Path) {}
