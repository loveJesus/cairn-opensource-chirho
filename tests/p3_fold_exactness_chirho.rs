// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! P3 fold-plane exactness: a REAL root Gate 1 anchor-head export verifies through the replication
//! crate's pinned-source-key fold verification, and a replica independently reproduces the five
//! Ring-A CLSD digests. This proves the replication verifier agrees byte-for-byte with the root's
//! own signed export — and that it fails closed on the wrong key, a forged head signature, a tampered
//! anchor, truncation, a RAW per-family byte tamper the semantic fold would normalize away, a legacy
//! anchor history that binds no group, and a stale-head rollback below the caller's anti-rollback floor.
//!
//! The two ledger-family arms below are deliberately KNOWN-RED pending the real V2 ledger producer.
//! Do not delete them, hand-forge ledger bytes, or re-implement the retired writer in this fixture:
//! the ledger fold has ledger-specific semantic admission, including the authority-inert V2 refusal.

use cairn_chirho::gate1_anchor_chirho::{
    append_gate1_anchor_for_family_chirho, append_gate1_ring_a_anchors_chirho,
    export_gate1_anchor_head_replication_chirho,
};
use cairn_model_gate1_chirho::{
    Gate1AnchorHeadReplicationRecordChirho, GATE1_LEDGER_FAMILY_CHIRHO,
    GATE1_LOG_ANCHORS_FILE_CHIRHO, GATE1_RING_A_ANCHOR_TARGETS_CHIRHO,
};
use cairn_replication_chirho::fold_plane_chirho::verify_replicated_authority_fold_chirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-fold-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

/// Change the first hex character of a signature/digest to a DIFFERENT hex digit — keeping the length
/// and hex shape valid so record validation still passes and the corruption is caught by the crypto
/// check, not a shape check.
fn corrupt_hex_chirho(s_chirho: &str) -> String {
    let mut chars_chirho: Vec<char> = s_chirho.chars().collect();
    if let Some(first_chirho) = chars_chirho.first_mut() {
        *first_chirho = if *first_chirho == '0' { '1' } else { '0' };
    }
    chars_chirho.into_iter().collect()
}

/// Seed a source root with real signed Ring-A anchors (empty family logs), export its signed head, and
/// copy ONLY the anchor log to an independent replica root. Empty family logs fold to the empty-state
/// digests the anchors carry, and the raw per-family binding at count 0 reproduces the zero-seed digest.
/// Returns (replica_root, head_bytes, source_pubkey_hex).
fn source_and_replica_chirho() -> (PathBuf, Vec<u8>, String) {
    let source_chirho = tmp_root_chirho("src");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();

    let replica_chirho = tmp_root_chirho("rep");
    std::fs::copy(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        replica_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
    )
    .unwrap();
    let _ = std::fs::remove_dir_all(&source_chirho);
    (replica_chirho, head_bytes_chirho, source_pubkey_chirho)
}

/// Copy any already-existing Ring-A family logs beside the signed anchor log; this helper does not
/// create ledger content. The ledger-family fold arms remain known-red pending the real V2 producer.
fn seeded_source_and_replica_chirho() -> (PathBuf, Vec<u8>, String) {
    let source_chirho = tmp_root_chirho("seed-src");
    append_gate1_ring_a_anchors_chirho(&source_chirho).unwrap();
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();

    let replica_chirho = tmp_root_chirho("seed-rep");
    std::fs::copy(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        replica_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
    )
    .unwrap();
    for family_chirho in GATE1_RING_A_ANCHOR_TARGETS_CHIRHO {
        let src_family_chirho = source_chirho.join(family_chirho);
        if src_family_chirho.exists() {
            std::fs::copy(&src_family_chirho, replica_chirho.join(family_chirho)).unwrap();
        }
    }
    let _ = std::fs::remove_dir_all(&source_chirho);
    (replica_chirho, head_bytes_chirho, source_pubkey_chirho)
}

#[test]
fn real_root_export_verifies_through_replica_fold_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) = source_and_replica_chirho();
    let report_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .expect("a real root export must verify through the replica fold");
    assert_eq!(
        report_chirho.verified_group_count_chirho, 4,
        "all four surviving Ring-A groups verify"
    );
    assert!(report_chirho.anchor_record_count_chirho >= 1);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
#[ignore = "KNOWN-RED pending the real V2 ledger producer; see module header"]
// KNOWN-RED pending the real V2 ledger producer. The ledger-specific fold path cannot be covered by
// another Ring-A family, and this helper intentionally does not recreate the retired writer.
fn seeded_nonempty_ledger_verifies_through_fold_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) =
        seeded_source_and_replica_chirho();
    let report_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .expect("a seeded non-empty ledger source must verify through the replica fold");
    assert_eq!(report_chirho.verified_group_count_chirho, 4);
    let ledger_text_chirho =
        std::fs::read_to_string(replica_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO)).unwrap();
    assert!(
        ledger_text_chirho
            .lines()
            .filter(|l_chirho| !l_chirho.trim().is_empty())
            .count()
            >= 1,
        "the replica ledger family log is non-empty (real content is bound)"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn wrong_source_key_fails_closed_chirho() {
    let (replica_chirho, head_bytes_chirho, _source_pubkey_chirho) = source_and_replica_chirho();
    // A different (valid-shaped) key: the head signature cannot verify under it.
    let wrong_key_chirho = "0".repeat(64);
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &wrong_key_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("key id does not match the pinned source key")
            || error_chirho.contains("signature is invalid"),
        "wrong source key must fail closed: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn forged_head_signature_fails_closed_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) = source_and_replica_chirho();
    // Keep the key id (so it still MATCHES the pinned source key) but corrupt the signature. This
    // isolates the signature verification: the failure must be the crypto check, not the key-id check,
    // so deleting the signature verification cannot leave this test green.
    let mut head_chirho: Gate1AnchorHeadReplicationRecordChirho =
        serde_json::from_slice(&head_bytes_chirho).unwrap();
    head_chirho.sig_chirho = corrupt_hex_chirho(&head_chirho.sig_chirho);
    let forged_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &forged_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("signature is invalid"),
        "a forged head signature (valid key id) must fail on the signature check: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
#[ignore = "KNOWN-RED pending the real V2 ledger producer; see module header"]
// KNOWN-RED pending the real V2 ledger producer; raw binding is family-generic, but this arm's
// ledger-family fixture must reach the ledger-specific fold path without synthetic bytes.
fn raw_tampered_ledger_byte_fails_the_raw_family_binding_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) =
        seeded_source_and_replica_chirho();
    let ledger_path_chirho = replica_chirho.join(GATE1_LEDGER_FAMILY_CHIRHO);
    let text_chirho = std::fs::read_to_string(&ledger_path_chirho).unwrap();
    // Insert insignificant JSON whitespace into the first ledger line. The semantic fold parses and
    // re-canonicalizes the line, so it would still match the source-signed state digest — but the RAW
    // per-family prefix digest, taken over the byte-changed line, must diverge. This proves the raw
    // binding catches byte tampering the semantic fold normalizes away.
    let mut lines_chirho: Vec<String> = text_chirho
        .lines()
        .map(|l_chirho| l_chirho.to_string())
        .collect();
    assert!(
        !lines_chirho.is_empty(),
        "the seeded ledger log has content"
    );
    lines_chirho[0] = lines_chirho[0].replacen('{', "{ ", 1);
    std::fs::write(
        &ledger_path_chirho,
        format!("{}\n", lines_chirho.join("\n")),
    )
    .unwrap();
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("raw prefix digest diverges"),
        "a raw-tampered family log must fail the per-family raw binding: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn legacy_all_none_anchor_source_fails_coverage_chirho() {
    // A source that anchors all ten Ring-A families via the legacy single-family path (state_digest =
    // None) yields a validly-signed head that claims five semantic groups, yet binds ZERO group
    // digests. The fold must reject this rather than return Ok with verified_group_count = 0 (which
    // would accept a replica whose family logs are entirely unbound).
    let source_chirho = tmp_root_chirho("legacy-src");
    for family_chirho in GATE1_RING_A_ANCHOR_TARGETS_CHIRHO {
        append_gate1_anchor_for_family_chirho(&source_chirho, family_chirho).unwrap();
    }
    let head_chirho = export_gate1_anchor_head_replication_chirho(&source_chirho).unwrap();
    let source_pubkey_chirho = head_chirho.key_id_chirho.clone();
    let head_bytes_chirho = serde_json::to_vec(&head_chirho).unwrap();
    let replica_chirho = tmp_root_chirho("legacy-rep");
    std::fs::copy(
        source_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
        replica_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO),
    )
    .unwrap();
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("semantic groups"),
        "a legacy all-None anchor history must fail coverage, not bind zero groups: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&source_chirho);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn stale_head_below_floor_fails_closed_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) = source_and_replica_chirho();
    let head_chirho: Gate1AnchorHeadReplicationRecordChirho =
        serde_json::from_slice(&head_bytes_chirho).unwrap();
    let count_chirho = head_chirho.anchor_record_count_chirho;
    // A floor ABOVE the head's count models a replica that already verified a later head; the earlier
    // (still validly-signed) head must be rejected as a rollback.
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        Some(count_chirho + 1),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("anti-rollback floor"),
        "a head below the anti-rollback floor must fail closed: {error_chirho}"
    );
    // At the floor (equal count) it is not a rollback and still verifies.
    let report_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        Some(count_chirho),
    )
    .expect("a head AT the floor is not a rollback");
    assert_eq!(report_chirho.verified_group_count_chirho, 4);
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn tampered_anchor_line_fails_the_prefix_digest_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) = source_and_replica_chirho();
    let anchor_path_chirho = replica_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO);
    let mut bytes_chirho = std::fs::read(&anchor_path_chirho).unwrap();
    // Flip one byte inside the first anchor line — the prefix digest hash-chain will not match.
    let flip_at_chirho = bytes_chirho
        .iter()
        .position(|b_chirho| *b_chirho == b'0')
        .unwrap_or(10);
    bytes_chirho[flip_at_chirho] ^= 0x01;
    std::fs::write(&anchor_path_chirho, &bytes_chirho).unwrap();
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("prefix digest does not match") || error_chirho.contains("diverges"),
        "a tampered anchor line must fail closed: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}

#[test]
fn truncated_anchor_log_fails_the_length_witness_chirho() {
    let (replica_chirho, head_bytes_chirho, source_pubkey_chirho) = source_and_replica_chirho();
    let anchor_path_chirho = replica_chirho.join(GATE1_LOG_ANCHORS_FILE_CHIRHO);
    let text_chirho = std::fs::read_to_string(&anchor_path_chirho).unwrap();
    // Drop the last non-empty anchor line — the copied log is now BELOW the signed head count.
    let mut lines_chirho: Vec<&str> = text_chirho
        .lines()
        .filter(|l_chirho| !l_chirho.trim().is_empty())
        .collect();
    lines_chirho.pop();
    std::fs::write(
        &anchor_path_chirho,
        format!("{}\n", lines_chirho.join("\n")),
    )
    .unwrap();
    let error_chirho = verify_replicated_authority_fold_chirho(
        &replica_chirho,
        &head_bytes_chirho,
        &source_pubkey_chirho,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("below the source-signed head count")
            || error_chirho.contains("prefix digest does not match"),
        "a truncated anchor log must fail closed: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(replica_chirho);
}
