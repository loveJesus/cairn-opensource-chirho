// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Proof by EXECUTION of the shipped `cairn-budget-verify-chirho`, with real ed25519 keys.
//!
//! The centrepiece is [`the_shipped_binary_stops_owing_a_release_once_one_is_recorded_chirho`]: the
//! crash-recovery property observed at the surface an operator actually uses. It asserts both that
//! the list empties AND that the balance returned exactly once, because an empty list alone would
//! also be produced by a store that had lost the reservation.
//!
//! Helpers carry a `budget_cli_` prefix — a workspace census propagates names defined exactly once,
//! and a helper colliding with a production entry point silently shrinks a security guard.

use cairn_placement_chirho::budget_chirho::budget_event_attestation_chirho::*;
use cairn_placement_chirho::budget_chirho::budget_funding_attestation_chirho::*;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::budget_event_store_chirho::{
    budget_evidence_scope_chirho, BUDGET_EVENT_LOG_CHIRHO,
};
use std::fs;
use std::process::Command;

const BUDGET_CLI_BUDGET_CHIRHO: &str = "budget-a-chirho";
const BUDGET_CLI_CEILING_CHIRHO: u64 = 100_000;

struct BudgetCliWorldChirho {
    root_chirho: tempfile::TempDir,
    authority_root_chirho: tempfile::TempDir,
    key_root_chirho: tempfile::TempDir,
    pubkey_chirho: String,
    funding_digest_chirho: String,
}

fn budget_cli_world_chirho() -> BudgetCliWorldChirho {
    let key_root_chirho = tempfile::tempdir().expect("key root");
    let pubkey_chirho = pubkey_hex_chirho(key_root_chirho.path()).expect("pubkey");
    let root_chirho = tempfile::tempdir().expect("root");
    pubkey_hex_chirho(root_chirho.path()).expect("root identity");
    let authority_root_chirho = tempfile::tempdir().expect("authority root");
    let scope_chirho =
        budget_evidence_scope_chirho(root_chirho.path(), BUDGET_CLI_BUDGET_CHIRHO).expect("scope");
    let funding_intent_chirho = BudgetFundingIntentChirho {
        schema_chirho: BUDGET_FUNDING_INTENT_SCHEMA_V1_CHIRHO.to_string(),
        evidence_root_key_id_chirho: scope_chirho.evidence_root_key_id_chirho,
        tenant_id_chirho: scope_chirho.tenant_id_chirho,
        budget_id_chirho: scope_chirho.budget_id_chirho,
        prepaid_ceiling_micros_chirho: BUDGET_CLI_CEILING_CHIRHO,
    };
    let mut funding_record_chirho = BudgetFundingAttestationChirho {
        schema_chirho: BUDGET_FUNDING_ATTESTATION_SCHEMA_V1_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_FUNDING_ATTESTATION_DOMAIN_V1_CHIRHO.to_string(),
        intent_digest_chirho: budget_funding_intent_digest_chirho(&funding_intent_chirho)
            .expect("funding digest"),
        intent_chirho: funding_intent_chirho,
        authority_key_id_chirho: pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    funding_record_chirho.sig_chirho = sign_message_chirho(
        key_root_chirho.path(),
        unsigned_budget_funding_message_chirho(&funding_record_chirho).as_bytes(),
    )
    .expect("sign funding");
    let funding_digest_chirho =
        budget_funding_record_digest_chirho(&funding_record_chirho).expect("funding record digest");
    let funding_record_path_chirho = key_root_chirho.path().join("funding-record-chirho.json");
    fs::write(
        &funding_record_path_chirho,
        serde_json::to_vec(&funding_record_chirho).expect("encode funding"),
    )
    .expect("write funding record");
    let publish_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-budget-funding-publish-chirho"))
        .arg(root_chirho.path())
        .arg(authority_root_chirho.path())
        .arg(&funding_record_path_chirho)
        .arg(&pubkey_chirho)
        .output()
        .expect("run shipped funding publisher");
    assert!(
        publish_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&publish_chirho.stderr)
    );
    BudgetCliWorldChirho {
        root_chirho,
        authority_root_chirho,
        key_root_chirho,
        pubkey_chirho,
        funding_digest_chirho,
    }
}

fn budget_cli_append_chirho(
    world_chirho: &BudgetCliWorldChirho,
    reservation_chirho: &str,
    kind_chirho: BudgetEventKindChirho,
    seq_chirho: u64,
) {
    let intent_chirho = BudgetEventIntentChirho {
        schema_chirho: BUDGET_EVENT_INTENT_SCHEMA_V2_CHIRHO.to_string(),
        evidence_root_key_id_chirho: budget_evidence_scope_chirho(
            world_chirho.root_chirho.path(),
            BUDGET_CLI_BUDGET_CHIRHO,
        )
        .expect("scope")
        .evidence_root_key_id_chirho,
        tenant_id_chirho: budget_evidence_scope_chirho(
            world_chirho.root_chirho.path(),
            BUDGET_CLI_BUDGET_CHIRHO,
        )
        .expect("scope")
        .tenant_id_chirho,
        budget_id_chirho: BUDGET_CLI_BUDGET_CHIRHO.to_string(),
        funding_record_digest_chirho: world_chirho.funding_digest_chirho.clone(),
        reservation_id_chirho: reservation_chirho.to_string(),
        kind_chirho,
        event_seq_chirho: seq_chirho,
    };
    let mut record_chirho = BudgetEventAttestationChirho {
        schema_chirho: BUDGET_EVENT_ATTESTATION_SCHEMA_V2_CHIRHO.to_string(),
        signature_domain_chirho: BUDGET_EVENT_ATTESTATION_DOMAIN_V2_CHIRHO.to_string(),
        intent_digest_chirho: budget_event_intent_digest_chirho(&intent_chirho).expect("digest"),
        intent_chirho,
        authority_key_id_chirho: world_chirho.pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = sign_message_chirho(
        world_chirho.key_root_chirho.path(),
        unsigned_budget_event_message_chirho(&record_chirho).as_bytes(),
    )
    .expect("sign");
    let record_path_chirho = world_chirho
        .key_root_chirho
        .path()
        .join(format!("budget-event-{seq_chirho}-chirho.json"));
    fs::write(
        &record_path_chirho,
        serde_json::to_vec(&record_chirho).expect("encode event"),
    )
    .expect("write event record");
    let append_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-budget-event-append-chirho"))
        .arg(world_chirho.root_chirho.path())
        .arg(world_chirho.authority_root_chirho.path())
        .arg(&record_path_chirho)
        .output()
        .expect("run shipped event appender");
    assert!(
        append_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&append_chirho.stderr)
    );
}

fn budget_cli_run_chirho(
    world_chirho: &BudgetCliWorldChirho,
    now_chirho: u64,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_cairn-budget-verify-chirho"))
        .arg(world_chirho.root_chirho.path())
        .arg(world_chirho.authority_root_chirho.path())
        .arg(BUDGET_CLI_BUDGET_CHIRHO)
        .arg(now_chirho.to_string())
        .output()
        .expect("run the shipped binary")
}

#[test]
fn the_read_road_refuses_checkpoint_ahead_until_the_write_repair_road_runs_chirho() {
    let world_chirho = budget_cli_world_chirho();
    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: 30_000,
            deadline_millis_chirho: 10_000,
        },
        1,
    );
    let log_path_chirho = world_chirho
        .root_chirho
        .path()
        .join(BUDGET_EVENT_LOG_CHIRHO);
    fs::write(&log_path_chirho, []).expect("simulate crash before append");

    let refused_chirho = budget_cli_run_chirho(&world_chirho, 5_000);
    assert!(!refused_chirho.status.success());
    assert!(
        String::from_utf8_lossy(&refused_chirho.stderr)
            .contains("CheckpointAheadOrAppendInFlightChirho"),
        "stderr: {}",
        String::from_utf8_lossy(&refused_chirho.stderr)
    );
    assert_eq!(fs::read(&log_path_chirho).expect("read refused log"), b"");

    let repaired_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-budget-repair-chirho"))
        .arg(world_chirho.root_chirho.path())
        .arg(world_chirho.authority_root_chirho.path())
        .output()
        .expect("run shipped repair road");
    assert!(
        repaired_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&repaired_chirho.stderr)
    );
    assert!(String::from_utf8_lossy(&repaired_chirho.stdout)
        .contains("RecoveredAbandonedCheckpointChirho"));

    let after_chirho = budget_cli_run_chirho(&world_chirho, 5_000);
    assert!(
        after_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&after_chirho.stderr)
    );
    assert!(
        String::from_utf8_lossy(&after_chirho.stdout).contains("\"available_micros_chirho\":70000")
    );
}

#[test]
fn the_shipped_binary_reports_a_replayed_balance_chirho() {
    // POSITIVE CONTROL: without it, a binary that reported an empty budget would satisfy the arms below.
    let world_chirho = budget_cli_world_chirho();
    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: 30_000,
            deadline_millis_chirho: 10_000,
        },
        1,
    );
    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::SettleChirho {
            settled_micros_chirho: 12_000,
        },
        2,
    );

    let output_chirho = budget_cli_run_chirho(&world_chirho, 5_000);
    assert!(
        output_chirho.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(stdout_chirho.contains("infrastructure-budget-report-v2-chirho"));
    assert!(stdout_chirho.contains("AuthenticatedFundingChirho"));
    assert!(
        stdout_chirho.contains("\"settled_micros_chirho\":12000"),
        "{stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"available_micros_chirho\":88000"),
        "the unused remainder returns: {stdout_chirho}"
    );
    assert!(
        stdout_chirho.contains("\"conservation_holds_chirho\":true"),
        "{stdout_chirho}"
    );
}

#[test]
fn the_shipped_binary_stops_owing_a_release_once_one_is_recorded_chirho() {
    // THE arm: crash recovery observed where an operator observes it. Re-running after appending the
    // release is exactly what a recovering node does when it cannot know whether its release landed.
    let world_chirho = budget_cli_world_chirho();
    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: 30_000,
            deadline_millis_chirho: 10_000,
        },
        1,
    );

    // Past the deadline: exactly this reservation is owed a release.
    let owed_chirho = budget_cli_run_chirho(&world_chirho, 10_001);
    let owed_stdout_chirho = String::from_utf8_lossy(&owed_chirho.stdout);
    assert!(
        owed_stdout_chirho.contains("\"awaiting_release_chirho\":[\"r1-chirho\"]"),
        "{owed_stdout_chirho}"
    );
    assert!(
        owed_stdout_chirho.contains("\"available_micros_chirho\":70000"),
        "still held while unresolved: {owed_stdout_chirho}"
    );

    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::ReleaseChirho,
        2,
    );

    // THE RE-DRIVE, same clock.
    let after_chirho = budget_cli_run_chirho(&world_chirho, 10_001);
    let after_stdout_chirho = String::from_utf8_lossy(&after_chirho.stdout);
    assert!(
        after_stdout_chirho.contains("\"awaiting_release_chirho\":[]"),
        "a recorded release must not be owed again: {after_stdout_chirho}"
    );
    assert!(
        after_stdout_chirho.contains("\"available_micros_chirho\":100000"),
        "and the credits returned EXACTLY once -- an empty list alone would also be produced by a \
         store that lost the reservation: {after_stdout_chirho}"
    );
    assert!(
        after_stdout_chirho.contains("\"settled_micros_chirho\":0"),
        "a deadline releases, it never settles: {after_stdout_chirho}"
    );
}

#[test]
fn the_budget_report_prints_no_private_material_or_paths_chirho() {
    let world_chirho = budget_cli_world_chirho();
    budget_cli_append_chirho(
        &world_chirho,
        "r1-chirho",
        BudgetEventKindChirho::ReserveChirho {
            requested_micros_chirho: 1_000,
            deadline_millis_chirho: 10_000,
        },
        1,
    );
    let output_chirho = budget_cli_run_chirho(&world_chirho, 1_000);
    let stdout_chirho = String::from_utf8_lossy(&output_chirho.stdout);
    assert!(
        stdout_chirho.contains(world_chirho.pubkey_chirho.as_str()),
        "the public authority key id is explicit provenance"
    );
    assert!(!stdout_chirho.contains(&*world_chirho.root_chirho.path().to_string_lossy()));
    assert!(!stdout_chirho.contains(&*world_chirho.authority_root_chirho.path().to_string_lossy()));
}
