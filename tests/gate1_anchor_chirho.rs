// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use cairn_chirho::gate1_anchor_chirho::{
    append_gate1_ledger_anchor_chirho, canonical_gate1_anchor_head_replication_text_chirho,
    export_gate1_anchor_head_replication_chirho, gate1_anchor_log_path_chirho,
    load_gate1_anchor_records_chirho, verify_gate1_anchor_head_replication_text_chirho,
    verify_gate1_anchor_records_chirho,
};
use cairn_model_gate1_chirho::{
    canonical_gate1_log_anchor_line_chirho, gate1_anchor_line_hash_chirho,
    unsigned_gate1_log_anchor_message_chirho, Gate1LogAnchorRecordChirho,
    GATE1_LEDGER_FAMILY_CHIRHO,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration_chirho| duration_chirho.as_millis() as u64)
        .unwrap_or(0)
}

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = now_ms_chirho();
    std::env::temp_dir().join(format!("cairn-gate1-anchor-test-{n_chirho}-{now_chirho}"))
}

fn rewrite_anchor_records_chirho(
    root_chirho: &Path,
    records_chirho: &[Gate1LogAnchorRecordChirho],
) {
    let mut file_chirho = fs::File::create(gate1_anchor_log_path_chirho(root_chirho)).unwrap();
    for record_chirho in records_chirho {
        writeln!(
            file_chirho,
            "{}",
            canonical_gate1_log_anchor_line_chirho(record_chirho).unwrap()
        )
        .unwrap();
    }
}

#[test]
fn ledger_anchor_append_verifies_and_chains_chirho() {
    let root_chirho = tmp_root_chirho();
    let first_chirho = append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    let second_chirho = append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    let verified_chirho = verify_gate1_anchor_records_chirho(&root_chirho).unwrap();
    assert_eq!(verified_chirho.anchor_record_count_chirho, 2);
    assert_eq!(
        second_chirho.prev_anchor_hash_chirho,
        Some(gate1_anchor_line_hash_chirho(&first_chirho).unwrap())
    );
    assert_eq!(
        verified_chirho.latest_by_family_chirho[GATE1_LEDGER_FAMILY_CHIRHO]
            .record_chirho
            .seq_chirho,
        1
    );
}

#[test]
fn broken_anchor_chain_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    let mut records_chirho = load_gate1_anchor_records_chirho(&root_chirho).unwrap();
    records_chirho[1].prev_anchor_hash_chirho = None;
    let message_chirho = unsigned_gate1_log_anchor_message_chirho(&records_chirho[1]).unwrap();
    records_chirho[1].sig_chirho =
        cairn_signer_chirho::signer_chirho::sign_message_chirho(&root_chirho, &message_chirho)
            .unwrap();
    rewrite_anchor_records_chirho(&root_chirho, &records_chirho);
    let error_chirho = verify_gate1_anchor_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("chain broken"));
}

#[test]
fn bad_anchor_signature_fails_closed_chirho() {
    let root_chirho = tmp_root_chirho();
    append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    let mut records_chirho = load_gate1_anchor_records_chirho(&root_chirho).unwrap();
    records_chirho[0].sig_chirho = "0".repeat(128);
    rewrite_anchor_records_chirho(&root_chirho, &records_chirho);
    let error_chirho = verify_gate1_anchor_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("signature invalid"));
}

#[test]
fn anchor_head_export_requires_nonempty_anchor_log_without_key_creation_chirho() {
    let root_chirho = tmp_root_chirho();
    let error_chirho = export_gate1_anchor_head_replication_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("non-empty verified anchor log"));
    assert!(!root_chirho.join("signing-key-chirho.bin").exists());
    assert!(!root_chirho.join("pubkey-chirho.hex").exists());
}

#[test]
fn anchor_head_verify_catches_dual_log_rollback_by_count_chirho() {
    let root_chirho = tmp_root_chirho();
    append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    append_gate1_ledger_anchor_chirho(&root_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&root_chirho).unwrap();
    let mut records_chirho = load_gate1_anchor_records_chirho(&root_chirho).unwrap();
    records_chirho.truncate(1);
    rewrite_anchor_records_chirho(&root_chirho, &records_chirho);

    let head_text_chirho =
        canonical_gate1_anchor_head_replication_text_chirho(&head_chirho).unwrap();
    let error_chirho =
        verify_gate1_anchor_head_replication_text_chirho(&root_chirho, &head_text_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("current anchor count 1 is below external retained count 2"));
}
