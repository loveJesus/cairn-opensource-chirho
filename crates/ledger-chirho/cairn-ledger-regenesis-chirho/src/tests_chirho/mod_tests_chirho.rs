// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use crate::plan_chirho::{
    canonical_plan_bytes_chirho, plan_digest_chirho, LedgerRegenesisPlanV1Chirho,
    LedgerRegenesisProjectionRoutePlanChirho, LEDGER_REGENESIS_PLAN_SCHEMA_V1_CHIRHO,
};
use cairn_kind_registry_chirho::record_chirho::{
    IdempotencyWindowPolicyChirho, KindPolicyBodyChirho, MintAuthorityRecordChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_secret_chirho::secret_chirho::set_secret_chirho;
use cairn_signer_chirho::signer_chirho::sign_message_chirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use ed25519_dalek::SigningKey;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "a6_geo_composition_tests_chirho.rs"]
mod a6_geo_composition_tests_chirho;
#[path = "completion_tests_chirho.rs"]
mod completion_tests_chirho;
#[path = "destination_authority_enrollment_tests_chirho.rs"]
mod destination_authority_enrollment_tests_chirho;
#[path = "harness1_adoption_fix_arms_chirho.rs"]
mod harness1_adoption_fix_arms_chirho;
#[path = "harness1_compensated_terminal_arms_chirho.rs"]
mod harness1_compensated_terminal_arms_chirho;
#[path = "harness1_conservation_provider_tests_chirho.rs"]
mod harness1_conservation_provider_tests_chirho;
#[path = "harness1_full_chain_drill_chirho.rs"]
mod harness1_full_chain_drill_chirho;
#[path = "harness1_gd7_mailbox_tests_chirho.rs"]
mod harness1_gd7_mailbox_tests_chirho;
#[path = "harness1_gd7_world_chirho.rs"]
mod harness1_gd7_world_chirho;
#[path = "harness1_mint_trigger_arms_chirho.rs"]
mod harness1_mint_trigger_arms_chirho;
#[path = "harness1_obligation_tail_arms_chirho.rs"]
mod harness1_obligation_tail_arms_chirho;
#[path = "harness1_opener_admission_tests_chirho.rs"]
mod harness1_opener_admission_tests_chirho;
#[path = "harness1_success_ladder_tests_chirho.rs"]
mod harness1_success_ladder_tests_chirho;
#[path = "harness1_two_root_world_tests_chirho.rs"]
mod harness1_two_root_world_tests_chirho;
#[path = "held_coordinator_tests_chirho.rs"]
mod held_coordinator_tests_chirho;
#[path = "issuer_tests_chirho.rs"]
mod issuer_tests_chirho;
#[path = "ledger_host_artifact_derivation_tests_chirho.rs"]
mod ledger_host_artifact_derivation_tests_chirho;
#[path = "ledger_host_artifact_emission_tests_chirho.rs"]
mod ledger_host_artifact_emission_tests_chirho;
#[path = "ledger_host_authoring_inputs_tests_chirho.rs"]
mod ledger_host_authoring_inputs_tests_chirho;
#[path = "ledger_host_authoring_mode_tests_chirho.rs"]
mod ledger_host_authoring_mode_tests_chirho;
#[path = "ledger_host_custody_binding_tests_chirho.rs"]
mod ledger_host_custody_binding_tests_chirho;
#[path = "localphaseb_support_tests_chirho.rs"]
mod localphaseb_support_tests_chirho;
#[path = "money_stage_tests_chirho.rs"]
mod money_stage_tests_chirho;
#[path = "plan_tests_chirho.rs"]
mod plan_tests_chirho;
#[path = "resident_actor_tests_chirho.rs"]
mod resident_actor_tests_chirho;

const ISSUER_SECRET_NAME_CHIRHO: &str = "offline-kind-issuer-chirho";
const ACTIVATION_SECRET_NAME_CHIRHO: &str = "offline-ledger-activation-chirho";
const ACTIVATION_SEED_BYTE_CHIRHO: u8 = 8;
#[cfg(unix)]
const TEST_FILE_DESCRIPTOR_TARGET_CHIRHO: libc::rlim_t = 10_240;
const RUNTIME_SECRET_NAMES_CHIRHO: [&str; 6] = [
    "ledger-journal-secret-chirho",
    "ledger-config-secret-chirho",
    "ledger-feeder-secret-chirho",
    "ledger-kind-root-secret-chirho",
    "ledger-effect-intent-secret-chirho",
    "ledger-effect-terminal-secret-chirho",
];

fn drive_campaign_chirho(nodes_chirho: &[Arc<RaftWriterElectorChirho>], campaigner_chirho: usize) {
    let mut bus_chirho = nodes_chirho[campaigner_chirho]
        .campaign_chirho()
        .expect("campaign starts");
    for _round_chirho in 0..1_000 {
        if bus_chirho.is_empty() {
            return;
        }
        let mut next_chirho = Vec::new();
        for message_chirho in bus_chirho.drain(..) {
            let target_chirho = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == message_chirho.to)
                .expect("every message target is in the fixed roster");
            next_chirho.extend(
                target_chirho
                    .step_chirho(message_chirho)
                    .expect("target accepts the campaign message"),
            );
        }
        bus_chirho = next_chirho;
    }
    panic!("campaign did not drain within the fixed test bound");
}

fn drive_transfer_chirho(
    nodes_chirho: &[Arc<RaftWriterElectorChirho>],
    leader_chirho: usize,
    target_raft_id_chirho: u64,
) {
    let mut bus_chirho = nodes_chirho[leader_chirho]
        .transfer_leadership_to_chirho(target_raft_id_chirho)
        .expect("leader starts the transfer");
    for _round_chirho in 0..1_000 {
        if bus_chirho.is_empty() {
            return;
        }
        let mut next_chirho = Vec::new();
        for (target_id_chirho, message_bytes_chirho) in bus_chirho.drain(..) {
            let target_chirho = nodes_chirho
                .iter()
                .find(|node_chirho| node_chirho.local_raft_id_chirho() == target_id_chirho)
                .expect("every transfer target is in the fixed roster");
            next_chirho.extend(
                target_chirho
                    .step_encoded_chirho(&message_bytes_chirho)
                    .expect("target accepts the transfer message"),
            );
        }
        bus_chirho = next_chirho;
    }
    panic!("leadership transfer did not drain within the fixed test bound");
}

fn drive_ticks_chirho(
    nodes_chirho: &[Arc<RaftWriterElectorChirho>],
    ticking_node_chirho: usize,
    tick_count_chirho: usize,
) {
    for _tick_chirho in 0..tick_count_chirho {
        let mut bus_chirho = nodes_chirho[ticking_node_chirho].tick_chirho();
        for _round_chirho in 0..1_000 {
            if bus_chirho.is_empty() {
                break;
            }
            let mut next_chirho = Vec::new();
            for message_chirho in bus_chirho.drain(..) {
                let target_chirho = nodes_chirho
                    .iter()
                    .find(|node_chirho| node_chirho.local_raft_id_chirho() == message_chirho.to)
                    .expect("every tick message target is in the fixed roster");
                next_chirho.extend(
                    target_chirho
                        .step_chirho(message_chirho)
                        .expect("target accepts the tick message"),
                );
            }
            bus_chirho = next_chirho;
        }
        assert!(
            bus_chirho.is_empty(),
            "tick messages drain within the fixed test bound"
        );
    }
}

struct RegenesisFixtureChirho {
    root_chirho: PathBuf,
    config_path_chirho: PathBuf,
    plan_path_chirho: PathBuf,
    plan_chirho: LedgerRegenesisPlanV1Chirho,
    expected_digest_chirho: String,
    issuer_secret_name_chirho: String,
    activation_secret_name_chirho: String,
    activation_authorization_path_chirho: PathBuf,
    expected_activation_authorization_digest_chirho: String,
}

impl Drop for RegenesisFixtureChirho {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root_chirho);
    }
}

fn fixture_chirho() -> RegenesisFixtureChirho {
    fixture_with_issuer_chirho(7, ISSUER_SECRET_NAME_CHIRHO, true)
}

fn request_chirho(
    fixture_chirho: &RegenesisFixtureChirho,
) -> crate::money_stage_chirho::LedgerRegenesisH3aRequestChirho<'_> {
    crate::money_stage_chirho::LedgerRegenesisH3aRequestChirho {
        selected_root_chirho: &fixture_chirho.root_chirho,
        config_path_chirho: &fixture_chirho.config_path_chirho,
        plan_path_chirho: &fixture_chirho.plan_path_chirho,
        expected_plan_digest_chirho: &fixture_chirho.expected_digest_chirho,
        issuer_secret_name_chirho: &fixture_chirho.issuer_secret_name_chirho,
        activation_authorization_path_chirho: &fixture_chirho.activation_authorization_path_chirho,
        expected_activation_authorization_digest_chirho: &fixture_chirho
            .expected_activation_authorization_digest_chirho,
    }
}

fn bind_fixture_initial_owner_chirho(
    fixture_chirho: &mut RegenesisFixtureChirho,
    owner_chirho: &str,
) {
    let mut plan_chirho = fixture_chirho.plan_chirho.clone();
    plan_chirho.initial_owner_chirho = owner_chirho.to_owned();
    write_fixture_plan_chirho(fixture_chirho, plan_chirho);
    let config_chirho = fs::read_to_string(&fixture_chirho.config_path_chirho).unwrap();
    let updated_config_chirho = config_chirho.replace(
        "owner_chirho = \"platform-credits-owner-chirho\"",
        &format!("owner_chirho = \"{owner_chirho}\""),
    );
    assert_ne!(updated_config_chirho, config_chirho);
    fs::write(&fixture_chirho.config_path_chirho, updated_config_chirho).unwrap();
    refresh_fixture_activation_authorization_chirho(fixture_chirho);
}

fn write_fixture_plan_chirho(
    fixture_chirho: &mut RegenesisFixtureChirho,
    plan_chirho: LedgerRegenesisPlanV1Chirho,
) {
    let bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho).unwrap();
    fs::write(&fixture_chirho.plan_path_chirho, &bytes_chirho).unwrap();
    fixture_chirho.expected_digest_chirho = plan_digest_chirho(&bytes_chirho);
    fixture_chirho.plan_chirho = plan_chirho;
}

fn refresh_fixture_activation_authorization_chirho(fixture_chirho: &mut RegenesisFixtureChirho) {
    let artifact_chirho = crate::money_stage_chirho::author_ledger_regenesis_activation_chirho(
        crate::money_stage_chirho::LedgerRegenesisActivationAuthorRequestChirho {
            selected_root_chirho: &fixture_chirho.root_chirho,
            config_path_chirho: &fixture_chirho.config_path_chirho,
            plan_path_chirho: &fixture_chirho.plan_path_chirho,
            expected_plan_digest_chirho: &fixture_chirho.expected_digest_chirho,
            issuer_secret_name_chirho: &fixture_chirho.issuer_secret_name_chirho,
            activation_secret_name_chirho: &fixture_chirho.activation_secret_name_chirho,
        },
    )
    .unwrap();
    fs::write(
        &fixture_chirho.activation_authorization_path_chirho,
        &artifact_chirho.canonical_bytes_chirho,
    )
    .unwrap();
    set_private_mode_chirho(&fixture_chirho.activation_authorization_path_chirho);
    fixture_chirho.expected_activation_authorization_digest_chirho =
        artifact_chirho.authorization_digest_chirho;
}

fn fixture_with_issuer_chirho(
    issuer_seed_byte_chirho: u8,
    issuer_secret_name_chirho: &str,
    include_held_verifier_pins_chirho: bool,
) -> RegenesisFixtureChirho {
    raise_test_file_descriptor_limit_chirho();
    let root_chirho = temp_root_chirho();
    fs::create_dir(&root_chirho).unwrap();
    sign_message_chirho(&root_chirho, b"provision regenesis node identity").unwrap();
    for (index_chirho, secret_name_chirho) in RUNTIME_SECRET_NAMES_CHIRHO.iter().enumerate() {
        set_secret_chirho(
            &root_chirho,
            secret_name_chirho,
            &[(index_chirho + 1) as u8; 32],
        )
        .unwrap();
    }
    if !RUNTIME_SECRET_NAMES_CHIRHO.contains(&issuer_secret_name_chirho) {
        set_secret_chirho(
            &root_chirho,
            issuer_secret_name_chirho,
            &[issuer_seed_byte_chirho; 32],
        )
        .unwrap();
    }
    set_secret_chirho(
        &root_chirho,
        ACTIVATION_SECRET_NAME_CHIRHO,
        &[ACTIVATION_SEED_BYTE_CHIRHO; 32],
    )
    .unwrap();
    let issuer_key_chirho = SigningKey::from_bytes(&[issuer_seed_byte_chirho; 32]);
    let issuer_key_hex_chirho = hex_encode_chirho(issuer_key_chirho.verifying_key().as_bytes());
    let activation_key_chirho = SigningKey::from_bytes(&[ACTIVATION_SEED_BYTE_CHIRHO; 32]);
    let activation_key_hex_chirho =
        hex_encode_chirho(activation_key_chirho.verifying_key().as_bytes());
    let config_path_chirho = root_chirho.join("cairn-regenesis-config-chirho.toml");
    fs::write(
        &config_path_chirho,
        config_text_chirho(
            &issuer_key_hex_chirho,
            &activation_key_hex_chirho,
            include_held_verifier_pins_chirho,
        ),
    )
    .unwrap();
    set_private_mode_chirho(&config_path_chirho);

    let plan_chirho = valid_plan_chirho();
    let plan_path_chirho = root_chirho.join("ledger-regenesis-plan-chirho.json");
    let plan_bytes_chirho = canonical_plan_bytes_chirho(&plan_chirho).unwrap();
    fs::write(&plan_path_chirho, &plan_bytes_chirho).unwrap();
    let expected_digest_chirho = plan_digest_chirho(&plan_bytes_chirho);
    let mut fixture_chirho = RegenesisFixtureChirho {
        root_chirho,
        config_path_chirho,
        plan_path_chirho,
        plan_chirho,
        expected_digest_chirho,
        issuer_secret_name_chirho: issuer_secret_name_chirho.to_owned(),
        activation_secret_name_chirho: ACTIVATION_SECRET_NAME_CHIRHO.to_owned(),
        activation_authorization_path_chirho: PathBuf::new(),
        expected_activation_authorization_digest_chirho: String::new(),
    };
    fixture_chirho.activation_authorization_path_chirho = fixture_chirho
        .root_chirho
        .join("ledger-activation-authorization-chirho.json");
    refresh_fixture_activation_authorization_chirho(&mut fixture_chirho);
    fixture_chirho
}

#[cfg(unix)]
fn raise_test_file_descriptor_limit_chirho() {
    static RESULT_CHIRHO: OnceLock<Result<(), String>> = OnceLock::new();
    let result_chirho = RESULT_CHIRHO.get_or_init(|| {
        let mut limits_chirho = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limits_chirho` is a valid writable `rlimit` for this process-wide query.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits_chirho) } != 0 {
            return Err(format!(
                "read test file-descriptor limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        if limits_chirho.rlim_cur >= TEST_FILE_DESCRIPTOR_TARGET_CHIRHO {
            return Ok(());
        }
        let target_chirho = if limits_chirho.rlim_max == libc::RLIM_INFINITY {
            TEST_FILE_DESCRIPTOR_TARGET_CHIRHO
        } else {
            TEST_FILE_DESCRIPTOR_TARGET_CHIRHO.min(limits_chirho.rlim_max)
        };
        if target_chirho <= limits_chirho.rlim_cur {
            return Err(format!(
                "test file-descriptor soft limit {} cannot be raised under hard limit {}",
                limits_chirho.rlim_cur, limits_chirho.rlim_max
            ));
        }
        let raised_chirho = libc::rlimit {
            rlim_cur: target_chirho,
            rlim_max: limits_chirho.rlim_max,
        };
        // SAFETY: `raised_chirho` preserves the hard limit and only raises this test process's soft limit.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised_chirho) } != 0 {
            return Err(format!(
                "raise test file-descriptor limit: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    });
    if let Err(detail_chirho) = result_chirho {
        panic!("regenesis test resource preflight failed: {detail_chirho}");
    }
}

#[cfg(not(unix))]
fn raise_test_file_descriptor_limit_chirho() {}

fn valid_plan_chirho() -> LedgerRegenesisPlanV1Chirho {
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
        projection_routes_chirho: vec![LedgerRegenesisProjectionRoutePlanChirho {
            projection_name_chirho: "credits-balance-chirho".to_owned(),
            head_path_chirho: "published/credits-balance-head-chirho.json".to_owned(),
        }],
        monitor_cadence_ms_chirho: 5_000,
        issuer_principal_chirho: "platform-kind-issuer-chirho".to_owned(),
        initial_owner_chirho: "platform-credits-owner-chirho".to_owned(),
        kind_id_chirho: "prepaid-credit-chirho".to_owned(),
        initial_policy_chirho: policy_chirho(1_000),
        amended_policy_chirho: policy_chirho(900),
        initial_mint_amount_chirho: 600,
        genesis_physical_ms_chirho: 1_000,
        mint_physical_ms_chirho: 1_100,
    }
}

fn policy_chirho(max_supply_chirho: u64) -> KindPolicyBodyChirho {
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

fn snapshot_tree_chirho(root_chirho: &Path) -> Vec<(String, bool, Vec<u8>)> {
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
                rows_chirho.push((
                    relative_chirho,
                    false,
                    fs::read(&entry_path_chirho).unwrap(),
                ));
            }
        }
    }
    let mut rows_chirho = Vec::new();
    walk_chirho(root_chirho, root_chirho, &mut rows_chirho);
    rows_chirho
}

fn config_text_chirho(
    issuer_key_hex_chirho: &str,
    activation_key_hex_chirho: &str,
    include_held_verifier_pins_chirho: bool,
) -> String {
    let journal_key_hex_chirho =
        hex_encode_chirho(SigningKey::from_bytes(&[1; 32]).verifying_key().as_bytes());
    let schema_chirho = if include_held_verifier_pins_chirho {
        "ledger-host-config-v3-chirho"
    } else {
        "ledger-host-config-v2-chirho"
    };
    let held_verifier_pins_chirho = if include_held_verifier_pins_chirho {
        format!(
            r#"
[ledger_host_chirho.held_verifier_pins_chirho]
journal_verifying_key_hex_chirho = "{journal_key_hex_chirho}"
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"[ledger_host_chirho]
schema_chirho = "{schema_chirho}"
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
projection_routes_chirho = [{{ projection_name_chirho = "credits-balance-chirho", head_path_chirho = "published/credits-balance-head-chirho.json" }}]
monitor_cadence_ms_chirho = 5000

[ledger_host_chirho.kind_issuer_chirho]
principal_chirho = "platform-kind-issuer-chirho"
verifying_key_hex_chirho = "{issuer_key_hex_chirho}"

[ledger_host_chirho.activation_authority_chirho]
principal_chirho = "platform-ledger-activation-chirho"
verifying_key_hex_chirho = "{activation_key_hex_chirho}"

{held_verifier_pins_chirho}
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

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-ledger-regenesis-test-{}-{now_chirho}-{counter_chirho}-chirho",
        std::process::id()
    ))
}

fn hex_encode_chirho(bytes_chirho: &[u8]) -> String {
    let mut encoded_chirho = String::with_capacity(bytes_chirho.len() * 2);
    for byte_chirho in bytes_chirho {
        use std::fmt::Write;
        write!(&mut encoded_chirho, "{byte_chirho:02x}").unwrap();
    }
    encoded_chirho
}

#[cfg(unix)]
fn set_private_mode_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(not(unix))]
fn set_private_mode_chirho(_path_chirho: &Path) {}
