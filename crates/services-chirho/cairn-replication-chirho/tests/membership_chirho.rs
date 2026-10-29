// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! D3 membership roster verification: an operator-signed roster resolves active source nodes, and a
//! forged record, a wrong operator key, or a non-contiguous seq fails the whole roster closed.

use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, unsigned_node_network_record_message_chirho,
    unsigned_preferred_leader_record_message_chirho, verify_membership_roster_lines_chirho,
    verify_membership_roster_with_head_chirho, verify_node_network_records_chirho,
    verify_preferred_leader_records_chirho, MembershipActionChirho, MembershipRosterHeadChirho,
    MembershipRosterRecordChirho, NodeNetworkRecordChirho, PreferredLeaderRecordChirho,
    MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO, MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO,
    NODE_NETWORK_RECORD_SCHEMA_CHIRHO, PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Build and operator-sign a roster head over `lines_chirho` (the length witness).
fn signed_head_chirho(operator_root_chirho: &Path, lines_chirho: &[Vec<u8>]) -> Vec<u8> {
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_string(),
        roster_record_count_chirho: lines_chirho.len() as u64,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(lines_chirho),
        at_ms_chirho: 9000,
        operator_key_id_chirho: operator_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_head_message_chirho(&head_chirho).unwrap();
    head_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    serde_json::to_vec(&head_chirho).unwrap()
}

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-p3-roster-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn signed_record_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    action_chirho: MembershipActionChirho,
    node_pubkey_chirho: &str,
    region_chirho: &str,
) -> Vec<u8> {
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        action_chirho,
        node_pubkey_hex_chirho: node_pubkey_chirho.to_string(),
        region_label_chirho: region_chirho.to_string(),
        at_ms_chirho: 1000 + seq_chirho,
        operator_key_id_chirho: operator_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

#[test]
fn operator_signed_roster_resolves_active_sources_chirho() {
    let operator_chirho = tmp_root_chirho("op");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_a_chirho = "a".repeat(64);
    let node_b_chirho = "b".repeat(64);
    let lines_chirho = vec![
        signed_record_chirho(
            &operator_chirho,
            0,
            MembershipActionChirho::AddNodeChirho,
            &node_a_chirho,
            "us-east-chirho",
        ),
        signed_record_chirho(
            &operator_chirho,
            1,
            MembershipActionChirho::AddNodeChirho,
            &node_b_chirho,
            "eu-west-chirho",
        ),
        signed_record_chirho(
            &operator_chirho,
            2,
            MembershipActionChirho::RemoveNodeChirho,
            &node_a_chirho,
            "",
        ),
    ];
    let verified_chirho =
        verify_membership_roster_lines_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert!(
        !verified_chirho.is_active_source_chirho(&node_a_chirho),
        "removed node is not active"
    );
    assert!(
        verified_chirho.is_active_source_chirho(&node_b_chirho),
        "added, not-removed node is active"
    );
    assert_eq!(
        verified_chirho.region_of_chirho(&node_b_chirho),
        Some("eu-west-chirho")
    );
    assert_eq!(verified_chirho.active_count_chirho(), 1);
    let _ = std::fs::remove_dir_all(operator_chirho);
}

#[test]
fn forged_roster_record_fails_closed_chirho() {
    let operator_chirho = tmp_root_chirho("op-forge");
    let attacker_chirho = tmp_root_chirho("attacker");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_a_chirho = "a".repeat(64);
    // A record whose operator_key_id claims the operator but is SIGNED by the attacker's key.
    let attacker_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&attacker_chirho).unwrap();
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        action_chirho: MembershipActionChirho::AddNodeChirho,
        node_pubkey_hex_chirho: node_a_chirho.clone(),
        region_label_chirho: "rogue-chirho".to_string(),
        at_ms_chirho: 1,
        operator_key_id_chirho: operator_pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_membership_roster_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&attacker_chirho, &message_chirho).unwrap();
    assert_ne!(operator_pubkey_chirho, attacker_pubkey_chirho);
    let lines_chirho = vec![serde_json::to_vec(&record_chirho).unwrap()];
    let error_chirho =
        verify_membership_roster_lines_chirho(&lines_chirho, &operator_pubkey_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("signature is invalid"),
        "a record forged under the operator key id but signed by another key must fail: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(attacker_chirho);
}

#[test]
fn wrong_operator_key_and_noncontiguous_seq_fail_closed_chirho() {
    let operator_chirho = tmp_root_chirho("op-wrong");
    let other_chirho = tmp_root_chirho("other");
    let node_a_chirho = "a".repeat(64);
    let lines_chirho = vec![signed_record_chirho(
        &operator_chirho,
        0,
        MembershipActionChirho::AddNodeChirho,
        &node_a_chirho,
        "us-east-chirho",
    )];
    // Verifying the operator-signed roster against a DIFFERENT operator key fails closed.
    let other_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&other_chirho).unwrap();
    assert!(verify_membership_roster_lines_chirho(&lines_chirho, &other_pubkey_chirho).is_err());

    // A non-contiguous seq fails closed.
    let bad_seq_chirho = vec![signed_record_chirho(
        &operator_chirho,
        5,
        MembershipActionChirho::AddNodeChirho,
        &node_a_chirho,
        "us-east-chirho",
    )];
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let error_chirho =
        verify_membership_roster_lines_chirho(&bad_seq_chirho, &operator_pubkey_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("not contiguous"),
        "non-contiguous seq must fail: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(operator_chirho);
    let _ = std::fs::remove_dir_all(other_chirho);
}

/// Build a 3-record roster [Add A, Add B, Remove A] so that dropping the tail re-adds the revoked A.
fn revoking_roster_chirho(operator_chirho: &Path) -> (String, String, Vec<Vec<u8>>) {
    let node_a_chirho = "a".repeat(64);
    let node_b_chirho = "b".repeat(64);
    let lines_chirho = vec![
        signed_record_chirho(
            operator_chirho,
            0,
            MembershipActionChirho::AddNodeChirho,
            &node_a_chirho,
            "us-east-chirho",
        ),
        signed_record_chirho(
            operator_chirho,
            1,
            MembershipActionChirho::AddNodeChirho,
            &node_b_chirho,
            "eu-west-chirho",
        ),
        signed_record_chirho(
            operator_chirho,
            2,
            MembershipActionChirho::RemoveNodeChirho,
            &node_a_chirho,
            "",
        ),
    ];
    (node_a_chirho, node_b_chirho, lines_chirho)
}

#[test]
fn honest_roster_with_head_verifies_chirho() {
    let operator_chirho = tmp_root_chirho("op-head-ok");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (node_a_chirho, node_b_chirho, lines_chirho) = revoking_roster_chirho(&operator_chirho);
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);

    let verified_chirho = verify_membership_roster_with_head_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
    )
    .expect("an honest roster + signed head must verify");
    assert!(!verified_chirho.is_active_source_chirho(&node_a_chirho));
    assert!(verified_chirho.is_active_source_chirho(&node_b_chirho));
    assert_eq!(verified_chirho.active_count_chirho(), 1);
    let _ = std::fs::remove_dir_all(operator_chirho);
}

#[test]
fn truncated_roster_tail_fails_the_length_witness_chirho() {
    let operator_chirho = tmp_root_chirho("op-head-trunc");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (node_a_chirho, _node_b_chirho, lines_chirho) = revoking_roster_chirho(&operator_chirho);
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);

    // Drop the trailing RemoveNode(A). Without the head this truncated prefix still verifies per-record
    // and re-adds the revoked A; the length witness must reject it.
    let mut truncated_chirho = lines_chirho.clone();
    truncated_chirho.pop();
    // The head-less path would wrongly re-activate A:
    let headless_chirho =
        verify_membership_roster_lines_chirho(&truncated_chirho, &operator_pubkey_chirho).unwrap();
    assert!(
        headless_chirho.is_active_source_chirho(&node_a_chirho),
        "without the witness the truncated roster silently re-adds the revoked node"
    );
    // With the head, truncation fails closed.
    let error_chirho = verify_membership_roster_with_head_chirho(
        &truncated_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("truncation/tamper"),
        "a dropped roster tail must fail the length witness: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(operator_chirho);
}

#[test]
fn forged_roster_head_signature_fails_chirho() {
    let operator_chirho = tmp_root_chirho("op-head-forge");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (_node_a_chirho, _node_b_chirho, lines_chirho) = revoking_roster_chirho(&operator_chirho);
    let head_bytes_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);

    // Corrupt the head signature (keep the operator key id) — it must fail on the crypto check.
    let mut head_chirho: MembershipRosterHeadChirho =
        serde_json::from_slice(&head_bytes_chirho).unwrap();
    let mut sig_chars_chirho: Vec<char> = head_chirho.sig_chirho.chars().collect();
    if let Some(first_chirho) = sig_chars_chirho.first_mut() {
        *first_chirho = if *first_chirho == '0' { '1' } else { '0' };
    }
    head_chirho.sig_chirho = sig_chars_chirho.into_iter().collect();
    let forged_head_chirho = serde_json::to_vec(&head_chirho).unwrap();

    let error_chirho = verify_membership_roster_with_head_chirho(
        &lines_chirho,
        &forged_head_chirho,
        &operator_pubkey_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("head signature is invalid"),
        "a forged roster head signature must fail closed: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(operator_chirho);
}

#[test]
fn tampered_roster_line_fails_the_prefix_digest_chirho() {
    let operator_chirho = tmp_root_chirho("op-head-tamper");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (_node_a_chirho, _node_b_chirho, lines_chirho) = revoking_roster_chirho(&operator_chirho);
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);

    // Swap in a validly-operator-signed but DIFFERENT record at index 1 (same count, different bytes):
    // the per-record checks would pass, but the prefix digest must diverge.
    let mut tampered_chirho = lines_chirho.clone();
    tampered_chirho[1] = signed_record_chirho(
        &operator_chirho,
        1,
        MembershipActionChirho::AddNodeChirho,
        &"c".repeat(64),
        "swapped-region-chirho",
    );
    let error_chirho = verify_membership_roster_with_head_chirho(
        &tampered_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(
        error_chirho.contains("prefix digest does not match"),
        "a tampered roster line must fail the prefix digest: {error_chirho}"
    );
    let _ = std::fs::remove_dir_all(operator_chirho);
}

// --- A2.1 slice 1: node-network records in the shared roster log ------------------------------------

#[allow(clippy::too_many_arguments)]
fn signed_network_record_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    node_pubkey_chirho: &str,
    raft_id_chirho: u64,
    wg_pubkey_chirho: &str,
    mesh_ip_chirho: &str,
    endpoint_chirho: &str,
) -> Vec<u8> {
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut record_chirho = NodeNetworkRecordChirho {
        schema_chirho: NODE_NETWORK_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        node_pubkey_hex_chirho: node_pubkey_chirho.to_string(),
        raft_id_chirho,
        wg_pubkey_chirho: wg_pubkey_chirho.to_string(),
        mesh_ip_chirho: mesh_ip_chirho.to_string(),
        endpoint_chirho: endpoint_chirho.to_string(),
        at_ms_chirho: 2000 + seq_chirho,
        operator_key_id_chirho: operator_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_node_network_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

#[test]
fn network_records_verify_and_latest_wins_chirho() {
    // Two operator-signed network records for one node (endpoint moved): the LATEST by log position wins
    // (A2-R4); the earlier one is cleanly superseded.
    let operator_chirho = tmp_root_chirho("net-latest");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_chirho = "a".repeat(64);
    let lines_chirho = vec![
        signed_network_record_chirho(
            &operator_chirho,
            0,
            &node_chirho,
            7,
            "WGOLD",
            "10.100.0.7",
            "old:51820",
        ),
        signed_network_record_chirho(
            &operator_chirho,
            1,
            &node_chirho,
            7,
            "WGNEW",
            "10.100.0.7",
            "new:51820",
        ),
    ];
    let verified_chirho =
        verify_node_network_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    let coords_chirho = verified_chirho.get(&node_chirho).unwrap();
    assert_eq!(
        coords_chirho.wg_pubkey_chirho, "WGNEW",
        "latest network record wins"
    );
    assert_eq!(coords_chirho.endpoint_chirho, "new:51820");
    assert_eq!(coords_chirho.raft_id_chirho, 7);
}

#[test]
fn network_record_forged_signature_fails_closed_chirho() {
    // A network record signed by the WRONG key fails the whole network verification.
    let operator_chirho = tmp_root_chirho("net-forge");
    let attacker_chirho = tmp_root_chirho("net-forge-attacker");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    // Sign with the attacker key but claim the operator key id — the operator-key verify must reject it.
    let mut record_chirho = NodeNetworkRecordChirho {
        schema_chirho: NODE_NETWORK_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        node_pubkey_hex_chirho: "b".repeat(64),
        raft_id_chirho: 4,
        wg_pubkey_chirho: "WG".to_string(),
        mesh_ip_chirho: "10.100.0.4".to_string(),
        endpoint_chirho: "h:51820".to_string(),
        at_ms_chirho: 2000,
        operator_key_id_chirho: operator_pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_node_network_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&attacker_chirho, &message_chirho).unwrap();
    let line_chirho = serde_json::to_vec(&record_chirho).unwrap();
    assert!(
        verify_node_network_records_chirho(&[line_chirho], &operator_pubkey_chirho).is_err(),
        "a network record not signed by the operator key must fail closed"
    );
}

#[test]
fn membership_verify_skips_network_lines_in_a_mixed_log_chirho() {
    // The roster log carries BOTH membership and network records in one seq space. Membership
    // verification resolves the members and skips network lines (seq stays contiguous over all lines).
    let operator_chirho = tmp_root_chirho("mixed");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_chirho = "c".repeat(64);
    let lines_chirho = vec![
        signed_record_chirho(
            &operator_chirho,
            0,
            MembershipActionChirho::AddNodeChirho,
            &node_chirho,
            "fr-chirho",
        ),
        signed_network_record_chirho(
            &operator_chirho,
            1,
            &node_chirho,
            3,
            "WG",
            "10.100.0.3",
            "h:51820",
        ),
    ];
    let membership_chirho =
        verify_membership_roster_lines_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert!(
        membership_chirho.is_active_source_chirho(&node_chirho),
        "the member is active; the interleaved network line was skipped, not fatal"
    );
    let network_chirho =
        verify_node_network_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert_eq!(network_chirho.get(&node_chirho).unwrap().raft_id_chirho, 3);
}

#[test]
fn membership_only_roster_verifies_identically_chirho() {
    // Backward compatibility: a membership-only roster (no network records) verifies exactly as before,
    // unaffected by the network-record addition.
    let operator_chirho = tmp_root_chirho("compat");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_chirho = "d".repeat(64);
    let lines_chirho = vec![signed_record_chirho(
        &operator_chirho,
        0,
        MembershipActionChirho::AddNodeChirho,
        &node_chirho,
        "us-chirho",
    )];
    let membership_chirho =
        verify_membership_roster_lines_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert!(membership_chirho.is_active_source_chirho(&node_chirho));
    // No network records -> empty network map, no error.
    let network_chirho =
        verify_node_network_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert!(network_chirho.is_empty());
}

#[test]
fn network_verify_fails_closed_on_unknown_schema_chirho() {
    // Symmetric-bail hardening: the network verifier must FAIL CLOSED on a line whose schema is neither
    // membership (skip) nor network (verify) — a garbage/trailing line can never be silently ignored.
    let operator_chirho = tmp_root_chirho("net-unknown");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let unknown_line_chirho =
        serde_json::to_vec(&serde_json::json!({"schema_chirho": "some-other-record-v1-chirho"}))
            .unwrap();
    assert!(
        verify_node_network_records_chirho(&[unknown_line_chirho], &operator_pubkey_chirho)
            .is_err(),
        "an unknown-schema line must fail the network verification closed, not be skipped"
    );
}

// ---- A1.4: the operator-signed preferred-leader record --------------------------------------------

fn signed_preferred_leader_record_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    group_id_chirho: &str,
    preferred_leader_raft_id_chirho: u64,
) -> Vec<u8> {
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap();
    let mut record_chirho = PreferredLeaderRecordChirho {
        schema_chirho: PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        group_id_chirho: group_id_chirho.to_string(),
        preferred_leader_raft_id_chirho,
        at_ms_chirho: 3000 + seq_chirho,
        operator_key_id_chirho: operator_pubkey_chirho,
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_preferred_leader_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(operator_root_chirho, &message_chirho).unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

#[test]
fn preferred_leader_records_verify_and_latest_wins_chirho() {
    // Two operator-signed preferred-leader records for one group (the operator RE-HOMES the primary): the
    // LATEST by log position wins; the earlier choice is cleanly superseded.
    let operator_chirho = tmp_root_chirho("pref-latest");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let group_chirho = "/var/lib/cairn-group-a-chirho";
    let lines_chirho = vec![
        signed_preferred_leader_record_chirho(&operator_chirho, 0, group_chirho, 1),
        signed_preferred_leader_record_chirho(&operator_chirho, 1, group_chirho, 3),
    ];
    let verified_chirho =
        verify_preferred_leader_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert_eq!(verified_chirho.len(), 1);
    assert_eq!(
        verified_chirho[group_chirho].preferred_leader_raft_id_chirho, 3,
        "the re-homed (latest) preferred leader wins"
    );
}

#[test]
fn forged_preferred_leader_signature_fails_closed_chirho() {
    // A record claiming the operator's key id but signed by an ATTACKER key must fail closed.
    let operator_chirho = tmp_root_chirho("pref-forged");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let attacker_chirho = tmp_root_chirho("pref-attacker");
    let mut record_chirho = PreferredLeaderRecordChirho {
        schema_chirho: PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho: 0,
        group_id_chirho: "/g".to_string(),
        preferred_leader_raft_id_chirho: 9,
        at_ms_chirho: 3000,
        operator_key_id_chirho: operator_pubkey_chirho.clone(),
        sig_chirho: String::new(),
    };
    let message_chirho = unsigned_preferred_leader_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&attacker_chirho, &message_chirho).unwrap();
    let forged_line_chirho = serde_json::to_vec(&record_chirho).unwrap();
    assert!(
        verify_preferred_leader_records_chirho(&[forged_line_chirho], &operator_pubkey_chirho)
            .is_err(),
        "a preferred-leader record signed by a non-operator key must fail closed"
    );
}

#[test]
fn three_schemas_coexist_in_one_roster_log_chirho() {
    // A mixed roster log (membership + network + preferred-leader) verifies with EACH verifier extracting
    // ONLY its own records and skipping the two siblings — the routing is symmetric. seq == line index
    // across ALL records (the shared length-witness space).
    let operator_chirho = tmp_root_chirho("three-schema");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let node_a_chirho = "a".repeat(64);
    let group_chirho = "/var/lib/cairn-group-x-chirho";
    let lines_chirho = vec![
        signed_record_chirho(
            &operator_chirho,
            0,
            MembershipActionChirho::AddNodeChirho,
            &node_a_chirho,
            "region-x",
        ),
        signed_network_record_chirho(
            &operator_chirho,
            1,
            &node_a_chirho,
            1,
            "WGa",
            "10.100.0.1",
            "host-a:51820",
        ),
        signed_preferred_leader_record_chirho(&operator_chirho, 2, group_chirho, 1),
    ];
    let membership_chirho =
        verify_membership_roster_lines_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert!(
        membership_chirho.is_active_source_chirho(&node_a_chirho),
        "the membership verifier extracts its record and skips the network + preferred lines"
    );
    let network_chirho =
        verify_node_network_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert_eq!(network_chirho.len(), 1);
    assert_eq!(network_chirho[&node_a_chirho].raft_id_chirho, 1);
    let preferred_chirho =
        verify_preferred_leader_records_chirho(&lines_chirho, &operator_pubkey_chirho).unwrap();
    assert_eq!(
        preferred_chirho[group_chirho].preferred_leader_raft_id_chirho, 1,
        "the preferred-leader verifier extracts its record and skips the membership + network lines"
    );
}

#[test]
fn preferred_leader_verify_fails_closed_on_unknown_schema_chirho() {
    // Symmetric-bail: the preferred-leader verifier fails closed on a schema that is neither a sibling
    // (skip) nor its own (verify) — a garbage/trailing line can never be silently ignored.
    let operator_chirho = tmp_root_chirho("pref-unknown");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let unknown_line_chirho =
        serde_json::to_vec(&serde_json::json!({"schema_chirho": "some-other-record-v1-chirho"}))
            .unwrap();
    assert!(
        verify_preferred_leader_records_chirho(&[unknown_line_chirho], &operator_pubkey_chirho)
            .is_err(),
        "an unknown-schema line must fail the preferred-leader verification closed"
    );
}
