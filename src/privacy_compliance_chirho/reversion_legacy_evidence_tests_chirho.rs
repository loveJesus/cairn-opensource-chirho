// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::attenuation_chirho::CapabilityLimitsChirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_BRANCH_CHIRHO: &str = "app/reversion-evidence-chirho";
const TEST_ACTOR_CHIRHO: &str = "reversion-auditor-chirho";

fn temp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    let sequence_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-reversion-evidence-test-chirho-{nanos_chirho}-{sequence_chirho}"
    ))
}

fn write_rollback_event_chirho(root_chirho: &Path, event_chirho: &RollbackEventChirho) {
    let mut bytes_chirho = serde_json::to_vec(event_chirho).expect("encode rollback event");
    bytes_chirho.push(b'\n');
    std::fs::write(rollback_events_path_chirho(root_chirho), bytes_chirho)
        .expect("write rollback event evidence");
}

fn historical_rollback_fixture_chirho() -> (PathBuf, RollbackEventChirho) {
    let root_chirho = temp_root_chirho();
    let from_chirho = cas_chirho::add_chirho(&root_chirho, b"historical-from-chirho")
        .expect("store source object");
    let to_chirho =
        cas_chirho::add_chirho(&root_chirho, b"historical-to-chirho").expect("store target object");
    let provenance_index_chirho =
        cas_chirho::add_chirho(&root_chirho, b"historical-provenance-chirho")
            .expect("store provenance index");

    refs_chirho::set_branch_chirho(&root_chirho, TEST_BRANCH_CHIRHO, from_chirho.clone())
        .expect("create historical branch");
    refs_chirho::commit_head_chirho(
        &root_chirho,
        TEST_BRANCH_CHIRHO,
        refs_chirho::HeadPreconditionChirho::ExpectedChirho(from_chirho.clone()),
        to_chirho.clone(),
        ROLLBACK_REASON_CHIRHO,
    )
    .expect("record historical rollback reflog move");

    let grant_chirho = attenuation_chirho::issue_root_grant_chirho(
        &root_chirho,
        "root-operator-chirho",
        TEST_ACTOR_CHIRHO,
        CapabilityChirho::CausalReversionChirho {
            branch_chirho: TEST_BRANCH_CHIRHO.to_string(),
        },
        CapabilityLimitsChirho::default(),
    )
    .expect("issue historical reversion grant");

    let mut event_chirho = RollbackEventChirho {
        schema_chirho: ROLLBACK_EVENT_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        branch_chirho: TEST_BRANCH_CHIRHO.to_string(),
        from_chirho,
        to_chirho,
        actor_chirho: TEST_ACTOR_CHIRHO.to_string(),
        grant_id_chirho: grant_chirho.grant_id_chirho,
        provenance_index_chirho,
        consumed_states_chirho: Vec::new(),
        dependent_effects_chirho: Vec::new(),
        plan_cost_token_chirho: 0,
        reason_chirho: "historical rollback evidence".to_string(),
        at_ms_chirho: grant_chirho.at_ms_chirho,
        sig_chirho: String::new(),
    };
    event_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &rollback_event_message_chirho(&event_chirho).expect("encode signed rollback event"),
    )
    .expect("sign rollback event");
    write_rollback_event_chirho(&root_chirho, &event_chirho);

    (root_chirho, event_chirho)
}

#[test]
fn retained_reversion_evidence_verifies_without_legacy_ledger_chirho() {
    let (root_chirho, _event_chirho) = historical_rollback_fixture_chirho();

    let verified_chirho =
        verify_reversion_evidence_chirho(&root_chirho).expect("verify historical evidence");

    assert_eq!(verified_chirho.rollback_events_chirho, 1);
    assert_eq!(verified_chirho.compensations_chirho, 0);
    assert_eq!(verified_chirho.compensation_executions_chirho, 0);
    assert_eq!(verified_chirho.manual_resolutions_chirho, 0);
    assert_eq!(verified_chirho.rollback_completions_chirho, 0);
    assert!(!root_chirho.join("ledger-chirho.jsonl").exists());

    std::fs::remove_dir_all(root_chirho).expect("remove test root");
}

#[test]
fn retained_reversion_evidence_rejects_tampered_record_chirho() {
    let (root_chirho, mut event_chirho) = historical_rollback_fixture_chirho();
    event_chirho.reason_chirho = "tampered historical rollback evidence".to_string();
    write_rollback_event_chirho(&root_chirho, &event_chirho);

    let error_chirho = verify_reversion_evidence_chirho(&root_chirho)
        .expect_err("tampered rollback evidence must fail closed");
    assert!(error_chirho
        .to_string()
        .contains("rollback event 0 signature invalid"));

    std::fs::remove_dir_all(root_chirho).expect("remove test root");
}
