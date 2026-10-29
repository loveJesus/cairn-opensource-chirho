// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A2.1 slice 2a: the non-secret elector-config derivation. Whole-log integrity is trusted first, the
//! membership↔network join is fail-closed (no partial config), the four-field collision set refuses
//! duplicates, output is byte-identical across derivations (sorted by raft id), and shareable evidence
//! redacts public endpoints.

use super::*;
use base64::engine::general_purpose::STANDARD as BASE64_CHIRHO;
use cairn_replication_chirho::membership_chirho::{
    roster_prefix_digest_chirho, unsigned_membership_roster_head_message_chirho,
    unsigned_membership_roster_message_chirho, unsigned_node_network_record_message_chirho,
    unsigned_preferred_leader_record_message_chirho, MembershipActionChirho,
    MembershipRosterHeadChirho, MembershipRosterRecordChirho, NodeNetworkRecordChirho,
    PreferredLeaderRecordChirho, MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO,
    MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO, NODE_NETWORK_RECORD_SCHEMA_CHIRHO,
    PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO,
};
use cairn_signer_chirho::signer_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub(super) struct NodeSpecChirho {
    pub(super) pubkey_chirho: String,
    pub(super) raft_id_chirho: u64,
    pub(super) wg_pubkey_chirho: String,
    pub(super) mesh_ip_chirho: String,
    pub(super) endpoint_chirho: String,
}

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-roster-config-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn spec_chirho(tag_chirho: char, raft_id_chirho: u64, mesh_last_chirho: u8) -> NodeSpecChirho {
    NodeSpecChirho {
        pubkey_chirho: tag_chirho.to_string().repeat(64),
        raft_id_chirho,
        wg_pubkey_chirho: format!("WG{tag_chirho}"),
        mesh_ip_chirho: format!("10.100.0.{mesh_last_chirho}"),
        endpoint_chirho: format!("host-{tag_chirho}:51820"),
    }
}

/// Decode 32 hex bytes (for the RFC 7748 known-answer vector) without adding a hex dependency.
fn hex32_chirho(hex_chirho: &str) -> [u8; 32] {
    let mut out_chirho = [0u8; 32];
    for i_chirho in 0..32 {
        out_chirho[i_chirho] =
            u8::from_str_radix(&hex_chirho[i_chirho * 2..i_chirho * 2 + 2], 16).unwrap();
    }
    out_chirho
}

/// A deterministic real WireGuard keypair (private key, its base64, its derived public base64). Any 32
/// bytes is a valid X25519 secret (the derivation clamps); vary `seed_chirho` for a distinct key.
fn wg_keypair_chirho(seed_chirho: u8) -> (WgLocalPrivateKeyChirho, String, String) {
    let priv_b64_chirho = BASE64_CHIRHO.encode([seed_chirho; 32]);
    let key_chirho = WgLocalPrivateKeyChirho::from_base64_chirho(&priv_b64_chirho).unwrap();
    let pub_b64_chirho = key_chirho.derive_wg_pubkey_base64_chirho().unwrap();
    (key_chirho, priv_b64_chirho, pub_b64_chirho)
}

fn signed_membership_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    pubkey_chirho: &str,
) -> Vec<u8> {
    signed_membership_action_line_chirho(
        operator_root_chirho,
        seq_chirho,
        pubkey_chirho,
        MembershipActionChirho::AddNodeChirho,
    )
}

fn signed_membership_action_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    pubkey_chirho: &str,
    action_chirho: MembershipActionChirho,
) -> Vec<u8> {
    let mut record_chirho = MembershipRosterRecordChirho {
        schema_chirho: MEMBERSHIP_ROSTER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        action_chirho,
        node_pubkey_hex_chirho: pubkey_chirho.to_string(),
        region_label_chirho: "region-chirho".to_string(),
        at_ms_chirho: 1000 + seq_chirho,
        operator_key_id_chirho: signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        operator_root_chirho,
        &unsigned_membership_roster_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

fn signed_network_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    spec_chirho: &NodeSpecChirho,
) -> Vec<u8> {
    let mut record_chirho = NodeNetworkRecordChirho {
        schema_chirho: NODE_NETWORK_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        node_pubkey_hex_chirho: spec_chirho.pubkey_chirho.clone(),
        raft_id_chirho: spec_chirho.raft_id_chirho,
        wg_pubkey_chirho: spec_chirho.wg_pubkey_chirho.clone(),
        mesh_ip_chirho: spec_chirho.mesh_ip_chirho.clone(),
        endpoint_chirho: spec_chirho.endpoint_chirho.clone(),
        at_ms_chirho: 2000 + seq_chirho,
        operator_key_id_chirho: signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        operator_root_chirho,
        &unsigned_node_network_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

fn signed_head_chirho(operator_root_chirho: &Path, lines_chirho: &[Vec<u8>]) -> Vec<u8> {
    let mut head_chirho = MembershipRosterHeadChirho {
        schema_chirho: MEMBERSHIP_ROSTER_HEAD_SCHEMA_CHIRHO.to_string(),
        roster_record_count_chirho: lines_chirho.len() as u64,
        roster_prefix_digest_chirho: roster_prefix_digest_chirho(lines_chirho),
        at_ms_chirho: 9000,
        operator_key_id_chirho: signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    head_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        operator_root_chirho,
        &unsigned_membership_roster_head_message_chirho(&head_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&head_chirho).unwrap()
}

/// Build a roster log (membership + network records interleaved, seq = line index) + its signed head.
pub(super) fn build_roster_chirho(
    operator_root_chirho: &Path,
    specs_chirho: &[NodeSpecChirho],
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut lines_chirho = Vec::new();
    for spec_chirho in specs_chirho {
        let seq_m_chirho = lines_chirho.len() as u64;
        lines_chirho.push(signed_membership_line_chirho(
            operator_root_chirho,
            seq_m_chirho,
            &spec_chirho.pubkey_chirho,
        ));
        let seq_n_chirho = lines_chirho.len() as u64;
        lines_chirho.push(signed_network_line_chirho(
            operator_root_chirho,
            seq_n_chirho,
            spec_chirho,
        ));
    }
    let head_chirho = signed_head_chirho(operator_root_chirho, &lines_chirho);
    (lines_chirho, head_chirho)
}

#[test]
fn derives_elector_config_from_verified_roster_chirho() {
    let operator_chirho = tmp_root_chirho("derive");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let specs_chirho = vec![spec_chirho('a', 1, 1), spec_chirho('b', 2, 2)];
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &specs_chirho);

    let (config_chirho, evidence_chirho) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap();
    assert_eq!(config_chirho.local_raft_id_chirho, 1);
    assert_eq!(config_chirho.listen_addr_chirho, "10.100.0.1:8300");
    assert_eq!(config_chirho.members_chirho.len(), 2);
    assert_eq!(config_chirho.members_chirho[0].raft_id_chirho, 1);
    assert_eq!(
        config_chirho.members_chirho[0].url_chirho,
        "http://10.100.0.1:8300"
    );
    assert_eq!(
        config_chirho.members_chirho[1].url_chirho,
        "http://10.100.0.2:8300"
    );
    assert!(config_chirho
        .members_chirho
        .iter()
        .all(|m_chirho| !m_chirho.learner_chirho));
    assert_eq!(evidence_chirho.member_count_chirho, 2);
    assert_eq!(evidence_chirho.raft_ids_chirho, vec![1, 2]);
}

#[test]
fn refuses_unverified_roster_chirho() {
    // A tampered roster (a line altered after the head was signed) fails the whole-log integrity check.
    let operator_chirho = tmp_root_chirho("unverified");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (mut lines_chirho, head_chirho) =
        build_roster_chirho(&operator_chirho, &[spec_chirho('a', 1, 1)]);
    lines_chirho[0].extend_from_slice(b" "); // tamper a byte -> head prefix-digest mismatch
    assert!(derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64)
    )
    .is_err());
}

#[test]
fn refuses_member_missing_network_coords_chirho() {
    // A2-R5: an active member with NO network record aborts the whole generation, not a partial config.
    let operator_chirho = tmp_root_chirho("missing-net");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    // Node 'a' has a membership record but NO network record.
    let mut lines_chirho = vec![signed_membership_line_chirho(
        &operator_chirho,
        0,
        &"a".repeat(64),
    )];
    let seq_chirho = lines_chirho.len() as u64;
    lines_chirho.push(signed_network_line_chirho(
        &operator_chirho,
        seq_chirho,
        &spec_chirho('b', 2, 2),
    ));
    lines_chirho.push(signed_membership_line_chirho(
        &operator_chirho,
        lines_chirho.len() as u64,
        &"b".repeat(64),
    ));
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);
    let err_chirho = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"b".repeat(64),
    )
    .unwrap_err()
    .to_string();
    assert!(
        err_chirho.contains("no network record"),
        "names the missing-coords member: {err_chirho}"
    );
}

#[test]
fn ignores_network_record_for_non_member_chirho() {
    // A2-R5 (audit fix, claude2): a network record for a NON-member is intentionally IGNORED, not an
    // abort — it's still operator-signed (a pre-provisioned or removed node), never an injection. Only
    // Direction 1 (every ACTIVE member must have coords) is load-bearing. Here node 'b' has a network
    // record but NEVER a membership record; derivation must SUCCEED over the real member 'a'. (Distinct
    // from derives_after_incremental_member_removal_chirho, which covers the was-a-member-then-removed
    // path; this covers the never-a-member / pre-provisioned path.)
    let operator_chirho = tmp_root_chirho("net-no-member");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    // Node 'a' is a full member; node 'b' has a network record but no membership.
    let mut lines_chirho = vec![
        signed_membership_line_chirho(&operator_chirho, 0, &"a".repeat(64)),
        signed_network_line_chirho(&operator_chirho, 1, &spec_chirho('a', 1, 1)),
    ];
    lines_chirho.push(signed_network_line_chirho(
        &operator_chirho,
        2,
        &spec_chirho('b', 2, 2),
    ));
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);
    let (config_chirho, _evidence_chirho) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .expect("a non-member network record must be ignored, not abort");
    assert_eq!(config_chirho.members_chirho.len(), 1);
    assert_eq!(config_chirho.members_chirho[0].raft_id_chirho, 1);
    assert!(
        config_chirho
            .members_chirho
            .iter()
            .all(|m_chirho| m_chirho.raft_id_chirho != 2),
        "the non-member (raft 2) must not appear as a member"
    );
}

#[test]
fn refuses_duplicate_network_identity_chirho() {
    // A2-R1: a collision on ANY of the four network-identity fields fails closed. Here two nodes share a
    // mesh ip.
    let operator_chirho = tmp_root_chirho("dup");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let mut a_chirho = spec_chirho('a', 1, 5);
    let mut b_chirho = spec_chirho('b', 2, 5); // SAME mesh_ip .5 as 'a'
    a_chirho.mesh_ip_chirho = "10.100.0.5".to_string();
    b_chirho.mesh_ip_chirho = "10.100.0.5".to_string();
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &[a_chirho, b_chirho]);
    let err_chirho = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("duplicate mesh ip"), "{err_chirho}");
}

#[test]
fn refuses_zero_raft_id_chirho() {
    // R6 shape: raft id 0 (reserved) is refused.
    let operator_chirho = tmp_root_chirho("zero");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) =
        build_roster_chirho(&operator_chirho, &[spec_chirho('a', 0, 1)]);
    let err_chirho = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("raft id 0"), "{err_chirho}");
}

#[test]
fn refuses_when_local_node_absent_chirho() {
    let operator_chirho = tmp_root_chirho("local-absent");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) =
        build_roster_chirho(&operator_chirho, &[spec_chirho('a', 1, 1)]);
    // Ask to derive for a node NOT in the roster.
    assert!(derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"z".repeat(64)
    )
    .is_err());
}

#[test]
fn two_derivations_are_byte_identical_chirho() {
    // A2-R4: two independent derivations from the same verified roster produce byte-identical config
    // (members sorted by raft id).
    let operator_chirho = tmp_root_chirho("identical");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    // Specs out of raft-id order to prove sorting normalizes them.
    let (lines_chirho, head_chirho) = build_roster_chirho(
        &operator_chirho,
        &[
            spec_chirho('a', 3, 3),
            spec_chirho('b', 1, 1),
            spec_chirho('c', 2, 2),
        ],
    );
    let (config_one_chirho, _) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"b".repeat(64),
    )
    .unwrap();
    let (config_two_chirho, _) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"b".repeat(64),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_vec(&config_one_chirho).unwrap(),
        serde_json::to_vec(&config_two_chirho).unwrap(),
        "two derivations from the same roster are byte-identical"
    );
    // And the member order is raft-id ascending regardless of roster order.
    let raft_order_chirho: Vec<u64> = config_one_chirho
        .members_chirho
        .iter()
        .map(|m_chirho| m_chirho.raft_id_chirho)
        .collect();
    assert_eq!(raft_order_chirho, vec![1, 2, 3]);
}

#[test]
fn shareable_evidence_redacts_public_endpoints_chirho() {
    // A2-R6: the evidence view carries only counts/raft-ids/mesh-ips; the public endpoints (fleet
    // topology) are the fixed redaction label, and the serialized evidence contains no endpoint host.
    let operator_chirho = tmp_root_chirho("redact");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) =
        build_roster_chirho(&operator_chirho, &[spec_chirho('a', 1, 1)]);
    let (_config_chirho, evidence_chirho) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap();
    assert_eq!(
        evidence_chirho.endpoints_chirho,
        REDACTED_ENDPOINT_LABEL_CHIRHO
    );
    let rendered_chirho = serde_json::to_string(&evidence_chirho).unwrap();
    assert!(
        !rendered_chirho.contains("host-a"),
        "the public endpoint host must not appear in evidence"
    );
    assert!(
        !rendered_chirho.contains("51820"),
        "the public endpoint port must not appear in evidence"
    );
}

#[test]
fn derives_after_incremental_member_removal_chirho() {
    // A2-R5 liveness (audit fix, claude2): network records are append-only with no remove primitive, but
    // membership HAS RemoveNodeChirho, so after a node is removed its network record PERSISTS in the log
    // forever. Deriving config must SUCCEED over the surviving members and IGNORE the removed node's
    // lingering (still operator-signed) network record — never abort. If this regresses, removing ANY
    // node bricks all future config derivation across the whole fleet.
    let operator_chirho = tmp_root_chirho("removal");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let x_chirho = spec_chirho('a', 1, 1); // added then removed; its network record lingers in the log
    let y_chirho = spec_chirho('b', 2, 2); // survives; the local node deriving its config
    let lines_chirho = vec![
        signed_membership_action_line_chirho(
            &operator_chirho,
            0,
            &x_chirho.pubkey_chirho,
            MembershipActionChirho::AddNodeChirho,
        ),
        signed_network_line_chirho(&operator_chirho, 1, &x_chirho),
        signed_membership_action_line_chirho(
            &operator_chirho,
            2,
            &y_chirho.pubkey_chirho,
            MembershipActionChirho::AddNodeChirho,
        ),
        signed_network_line_chirho(&operator_chirho, 3, &y_chirho),
        signed_membership_action_line_chirho(
            &operator_chirho,
            4,
            &x_chirho.pubkey_chirho,
            MembershipActionChirho::RemoveNodeChirho,
        ),
    ];
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);
    let (config_chirho, evidence_chirho) = derive_elector_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"b".repeat(64),
    )
    .expect("removing a node whose network record lingers must still derive, not abort");
    // Only the survivor Y is a member; the removed node X (raft 1) is excluded despite its lingering
    // network record.
    assert_eq!(config_chirho.local_raft_id_chirho, 2);
    assert_eq!(config_chirho.members_chirho.len(), 1);
    assert_eq!(config_chirho.members_chirho[0].raft_id_chirho, 2);
    assert!(
        config_chirho
            .members_chirho
            .iter()
            .all(|m_chirho| m_chirho.raft_id_chirho != 1),
        "the removed node must not reappear as a member"
    );
    assert_eq!(evidence_chirho.raft_ids_chirho, vec![2]);
}

// ---- Slice 2b: the SECRET WireGuard config ----------------------------------------------------------

/// Build a roster whose LOCAL node ('a') is signed with a REAL WireGuard public key (so the A2-R2 binding
/// check can pass), with `peer_specs_chirho` as the other members. Returns (lines, head, local key).
fn wg_roster_chirho(
    operator_root_chirho: &Path,
    local_pub_chirho: &str,
    peer_specs_chirho: &[NodeSpecChirho],
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut local_chirho = spec_chirho('a', 1, 1);
    local_chirho.wg_pubkey_chirho = local_pub_chirho.to_string();
    let mut specs_chirho = vec![local_chirho];
    for peer_chirho in peer_specs_chirho {
        specs_chirho.push(NodeSpecChirho {
            pubkey_chirho: peer_chirho.pubkey_chirho.clone(),
            raft_id_chirho: peer_chirho.raft_id_chirho,
            wg_pubkey_chirho: peer_chirho.wg_pubkey_chirho.clone(),
            mesh_ip_chirho: peer_chirho.mesh_ip_chirho.clone(),
            endpoint_chirho: peer_chirho.endpoint_chirho.clone(),
        });
    }
    build_roster_chirho(operator_root_chirho, &specs_chirho)
}

#[test]
fn derive_wg_pubkey_matches_rfc7748_basepoint_vector_chirho() {
    // RFC 7748 §6.1: X25519(a, 9). Proves our derivation is the same clamped scalar × Curve25519
    // basepoint that `wg pubkey` performs, byte-for-byte — the whole A2-R2 binding rests on this.
    let priv_chirho =
        hex32_chirho("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let expected_pub_chirho =
        hex32_chirho("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let key_chirho =
        WgLocalPrivateKeyChirho::from_base64_chirho(&BASE64_CHIRHO.encode(priv_chirho)).unwrap();
    assert_eq!(
        key_chirho.derive_wg_pubkey_base64_chirho().unwrap(),
        BASE64_CHIRHO.encode(expected_pub_chirho)
    );
}

#[test]
fn wg_private_key_rejects_malformed_input_chirho() {
    // 31 bytes (wrong length) and non-base64 both fail closed.
    let short_chirho = BASE64_CHIRHO.encode([1u8; 31]);
    assert!(WgLocalPrivateKeyChirho::from_base64_chirho(&short_chirho).is_err());
    assert!(WgLocalPrivateKeyChirho::from_base64_chirho("not-valid-base64-$$$").is_err());
}

#[test]
fn derives_wireguard_config_from_verified_roster_chirho() {
    let operator_chirho = tmp_root_chirho("wg-derive");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (local_key_chirho, local_priv_b64_chirho, local_pub_chirho) = wg_keypair_chirho(7);
    let (lines_chirho, head_chirho) = wg_roster_chirho(
        &operator_chirho,
        &local_pub_chirho,
        &[spec_chirho('b', 2, 2), spec_chirho('c', 3, 3)],
    );
    let config_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap();
    let text_chirho = config_chirho.secret_config_text_chirho();
    // [Interface]: this node's private key + mesh IP + listen port (from its own signed endpoint).
    assert!(text_chirho.contains("[Interface]"));
    assert!(text_chirho.contains(&format!("PrivateKey = {local_priv_b64_chirho}")));
    assert!(text_chirho.contains("Address = 10.100.0.1/32"));
    assert!(text_chirho.contains("ListenPort = 51820"));
    // Exactly two peers (b, c) — the local node is the interface, never its own peer.
    assert_eq!(text_chirho.matches("[Peer]").count(), 2);
    assert!(text_chirho.contains("PublicKey = WGb"));
    assert!(text_chirho.contains("AllowedIPs = 10.100.0.2/32"));
    assert!(text_chirho.contains("Endpoint = host-b:51820"));
    assert!(text_chirho.contains("PersistentKeepalive = 25"));
    assert!(
        !text_chirho.contains("PublicKey = WGa"),
        "local node is not its own peer"
    );
    // Peers in raft-id order: b (raft 2) before c (raft 3).
    assert!(
        text_chirho.find("WGb").unwrap() < text_chirho.find("WGc").unwrap(),
        "peers are ordered by raft id"
    );
    // Evidence carries only the non-secret facts.
    let evidence_chirho = config_chirho.evidence_chirho();
    assert_eq!(evidence_chirho.interface_pubkey_chirho, local_pub_chirho);
    assert_eq!(evidence_chirho.mesh_ip_chirho, "10.100.0.1");
    assert_eq!(evidence_chirho.listen_port_chirho, 51820);
    assert_eq!(evidence_chirho.peer_count_chirho, 2);
    assert_eq!(
        evidence_chirho.endpoints_chirho,
        REDACTED_ENDPOINT_LABEL_CHIRHO
    );
}

#[test]
fn refuses_when_local_wg_key_does_not_match_signed_pubkey_chirho() {
    // A2-R2: the local private key's public half MUST equal the node's operator-signed WG public key.
    // Here node 'a' is signed with key-7's pubkey but we hand derivation key-9 → refuse, and the error
    // names the node WITHOUT printing any key material.
    let operator_chirho = tmp_root_chirho("wg-mismatch");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (_signed_key_chirho, _signed_priv_chirho, signed_pub_chirho) = wg_keypair_chirho(7);
    let (wrong_key_chirho, wrong_priv_chirho, wrong_pub_chirho) = wg_keypair_chirho(9);
    assert_ne!(
        signed_pub_chirho, wrong_pub_chirho,
        "precondition: distinct keys"
    );
    let (lines_chirho, head_chirho) = wg_roster_chirho(&operator_chirho, &signed_pub_chirho, &[]);
    let err_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &wrong_key_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("does not match"), "{err_chirho}");
    assert!(
        err_chirho.contains(&"a".repeat(64)),
        "names the node: {err_chirho}"
    );
    assert!(
        !err_chirho.contains(&wrong_priv_chirho),
        "the error must never contain private key material"
    );
}

#[test]
fn wg_private_key_never_appears_in_emitted_evidence_chirho() {
    // A2-R3: the private key lives ONLY in the secret config text — never in evidence, never in a Debug.
    let operator_chirho = tmp_root_chirho("wg-noleak");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (local_key_chirho, local_priv_b64_chirho, local_pub_chirho) = wg_keypair_chirho(7);
    let (lines_chirho, head_chirho) = wg_roster_chirho(
        &operator_chirho,
        &local_pub_chirho,
        &[spec_chirho('b', 2, 2)],
    );
    let config_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap();
    // Sanity: the secret path DOES carry the key (else the no-leak assertions are vacuous).
    assert!(
        config_chirho
            .secret_config_text_chirho()
            .contains(&local_priv_b64_chirho),
        "the [Interface] carries the private key"
    );
    // But it must NOT leak into any non-secret surface.
    let evidence_json_chirho = serde_json::to_string(&config_chirho.evidence_chirho()).unwrap();
    assert!(
        !evidence_json_chirho.contains(&local_priv_b64_chirho),
        "private key must not appear in serialized evidence"
    );
    assert!(
        !evidence_json_chirho.contains("host-b"),
        "peer endpoints must not appear in evidence (A2-R6)"
    );
    let config_debug_chirho = format!("{config_chirho:?}");
    assert!(
        !config_debug_chirho.contains(&local_priv_b64_chirho),
        "private key must not appear in the config Debug"
    );
    assert!(
        config_debug_chirho.contains("redacted-secret"),
        "the config Debug redacts the secret text"
    );
    let key_debug_chirho = format!("{local_key_chirho:?}");
    assert!(
        !key_debug_chirho.contains(&local_priv_b64_chirho),
        "private key must not appear in the key Debug"
    );
}

#[test]
fn two_wireguard_derivations_are_byte_identical_chirho() {
    // A2-R4: two derivations from the same verified roster are byte-identical (peers sorted by raft id,
    // regardless of roster order).
    let operator_chirho = tmp_root_chirho("wg-identical");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (local_key_chirho, _priv_chirho, local_pub_chirho) = wg_keypair_chirho(7);
    // Peers given out of raft-id order to prove sorting normalizes them.
    let (lines_chirho, head_chirho) = wg_roster_chirho(
        &operator_chirho,
        &local_pub_chirho,
        &[spec_chirho('c', 3, 3), spec_chirho('b', 2, 2)],
    );
    let one_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap();
    let two_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap();
    assert_eq!(
        one_chirho.secret_config_text_chirho(),
        two_chirho.secret_config_text_chirho()
    );
    assert!(
        one_chirho.secret_config_text_chirho().find("WGb").unwrap()
            < one_chirho.secret_config_text_chirho().find("WGc").unwrap(),
        "peers sorted by raft id even when the roster lists them out of order"
    );
}

#[test]
fn wireguard_derivation_shares_fail_closed_join_chirho() {
    // The WG path consumes the SAME shared helper as the elector, so it inherits the fail-closed join:
    // an active member ('b') with no network record aborts the whole derivation (A2-R5 Direction 1),
    // before any [Interface] is rendered.
    let operator_chirho = tmp_root_chirho("wg-join");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (local_key_chirho, _priv_chirho, local_pub_chirho) = wg_keypair_chirho(7);
    let mut local_chirho = spec_chirho('a', 1, 1);
    local_chirho.wg_pubkey_chirho = local_pub_chirho;
    // 'a' full member+coords; 'b' has a membership record but NO network record.
    let lines_chirho = vec![
        signed_membership_line_chirho(&operator_chirho, 0, &"a".repeat(64)),
        signed_network_line_chirho(&operator_chirho, 1, &local_chirho),
        signed_membership_line_chirho(&operator_chirho, 2, &"b".repeat(64)),
    ];
    let head_chirho = signed_head_chirho(&operator_chirho, &lines_chirho);
    let err_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("no network record"), "{err_chirho}");
}

#[cfg(unix)]
#[test]
fn writes_secret_wireguard_config_mode_600_chirho() {
    // A2-R3 teeth: the secret config is written owner-only (0600), byte-for-byte.
    use std::os::unix::fs::PermissionsExt;
    let operator_chirho = tmp_root_chirho("wg-write");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (local_key_chirho, _priv_chirho, local_pub_chirho) = wg_keypair_chirho(7);
    let (lines_chirho, head_chirho) = wg_roster_chirho(
        &operator_chirho,
        &local_pub_chirho,
        &[spec_chirho('b', 2, 2)],
    );
    let config_chirho = derive_wireguard_config_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        &local_key_chirho,
    )
    .unwrap();
    let dir_chirho = tempfile::tempdir().unwrap();
    let path_chirho = dir_chirho.path().join("wg-chirho.conf");
    write_secret_wireguard_config_chirho(&path_chirho, &config_chirho).unwrap();
    let mode_chirho = std::fs::metadata(&path_chirho)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode_chirho, 0o600, "the WireGuard config is owner-only");
    assert_eq!(
        std::fs::read_to_string(&path_chirho).unwrap(),
        config_chirho.secret_config_text_chirho()
    );
}

// ---- A1.4: derive the operator-signed preferred leader --------------------------------------------

const PREFERRED_GROUP_CHIRHO: &str = "root-path-chirho:/var/lib/cairn-group-chirho";

fn signed_preferred_leader_line_chirho(
    operator_root_chirho: &Path,
    seq_chirho: u64,
    group_id_chirho: &str,
    preferred_raft_id_chirho: u64,
) -> Vec<u8> {
    let mut record_chirho = PreferredLeaderRecordChirho {
        schema_chirho: PREFERRED_LEADER_RECORD_SCHEMA_CHIRHO.to_string(),
        seq_chirho,
        group_id_chirho: group_id_chirho.to_string(),
        preferred_leader_raft_id_chirho: preferred_raft_id_chirho,
        at_ms_chirho: 3000 + seq_chirho,
        operator_key_id_chirho: signer_chirho::pubkey_hex_chirho(operator_root_chirho).unwrap(),
        sig_chirho: String::new(),
    };
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        operator_root_chirho,
        &unsigned_preferred_leader_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    serde_json::to_vec(&record_chirho).unwrap()
}

/// Build a roster (members a=raft1, b=raft2) with an optional preferred-leader line appended, plus head.
fn roster_with_preferred_chirho(
    operator_chirho: &Path,
    preferred_chirho: Option<u64>,
) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut lines_chirho = vec![
        signed_membership_line_chirho(operator_chirho, 0, &"a".repeat(64)),
        signed_network_line_chirho(operator_chirho, 1, &spec_chirho('a', 1, 1)),
        signed_membership_line_chirho(operator_chirho, 2, &"b".repeat(64)),
        signed_network_line_chirho(operator_chirho, 3, &spec_chirho('b', 2, 2)),
    ];
    if let Some(raft_id_chirho) = preferred_chirho {
        lines_chirho.push(signed_preferred_leader_line_chirho(
            operator_chirho,
            lines_chirho.len() as u64,
            PREFERRED_GROUP_CHIRHO,
            raft_id_chirho,
        ));
    }
    let head_chirho = signed_head_chirho(operator_chirho, &lines_chirho);
    (lines_chirho, head_chirho)
}

#[test]
fn derives_the_preferred_leader_for_a_group_chirho() {
    let operator_chirho = tmp_root_chirho("pref-derive");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) = roster_with_preferred_chirho(&operator_chirho, Some(2));
    let preferred_chirho = derive_preferred_leader_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        PREFERRED_GROUP_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        preferred_chirho,
        Some(2),
        "the operator's signed preferred leader (raft 2) is derived"
    );
}

#[test]
fn no_signed_preference_yields_none_chirho() {
    let operator_chirho = tmp_root_chirho("pref-none");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) = roster_with_preferred_chirho(&operator_chirho, None);
    let preferred_chirho = derive_preferred_leader_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        PREFERRED_GROUP_CHIRHO,
    )
    .unwrap();
    assert_eq!(
        preferred_chirho, None,
        "no signed preference -> the driver leaves leadership put"
    );
}

#[test]
fn refuses_a_preferred_leader_that_is_not_an_active_member_chirho() {
    // A preference for raft 9 (not a member) is a config error -> fail closed, never drive a bad re-home.
    let operator_chirho = tmp_root_chirho("pref-nonmember");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (lines_chirho, head_chirho) = roster_with_preferred_chirho(&operator_chirho, Some(9));
    let err_chirho = derive_preferred_leader_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
        PREFERRED_GROUP_CHIRHO,
    )
    .unwrap_err()
    .to_string();
    assert!(err_chirho.contains("not an active member"), "{err_chirho}");
}

#[test]
fn preferred_leader_requires_whole_log_integrity_chirho() {
    // A tampered roster line (after the head was signed) fails the whole-log integrity check BEFORE any
    // preferred-leader record is trusted.
    let operator_chirho = tmp_root_chirho("pref-tamper");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let (mut lines_chirho, head_chirho) = roster_with_preferred_chirho(&operator_chirho, Some(2));
    lines_chirho[0].extend_from_slice(b" "); // tamper -> head prefix-digest mismatch
    assert!(
        derive_preferred_leader_chirho(
            &lines_chirho,
            &head_chirho,
            &operator_pubkey_chirho,
            &"a".repeat(64),
            PREFERRED_GROUP_CHIRHO,
        )
        .is_err(),
        "a tampered roster must fail whole-log integrity before trusting the preference"
    );
}

#[test]
fn relay_mesh_proof_reuses_the_complete_signed_roster_join_chirho() {
    let operator_chirho = tmp_root_chirho("relay-mesh");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let specs_chirho = vec![spec_chirho('a', 1, 1), spec_chirho('b', 2, 2)];
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &specs_chirho);

    let proof_chirho = derive_verified_relay_mesh_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .expect("the complete verified population mints one relay-mesh proof");

    assert_eq!(proof_chirho.local_node_id_chirho(), "a".repeat(64));
    assert_eq!(
        proof_chirho.local_mesh_ip_chirho(),
        "10.100.0.1".parse::<IpAddr>().unwrap()
    );
    assert_eq!(proof_chirho.members_chirho().len(), 2);
    assert_eq!(
        proof_chirho.members_chirho()[1].node_id_chirho(),
        "b".repeat(64)
    );
    assert_eq!(
        proof_chirho.members_chirho()[1].mesh_ip_chirho(),
        "10.100.0.2".parse::<IpAddr>().unwrap()
    );

    let mut tampered_lines_chirho = lines_chirho;
    tampered_lines_chirho[0].extend_from_slice(b" ");
    assert!(
        derive_verified_relay_mesh_chirho(
            &tampered_lines_chirho,
            &head_chirho,
            &operator_pubkey_chirho,
            &"a".repeat(64),
        )
        .is_err(),
        "the relay proof must not bypass the whole-log head"
    );
}

#[test]
fn active_relay_mesh_requires_signed_key_up_flag_and_signed_address_chirho() {
    let operator_chirho = tmp_root_chirho("active-relay-mesh");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let specs_chirho = vec![spec_chirho('a', 1, 1), spec_chirho('b', 2, 2)];
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &specs_chirho);
    let proof_chirho = derive_verified_relay_mesh_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap();

    verify_active_relay_mesh_observation_chirho(
        &proof_chirho,
        "WGa",
        "4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN",
        "4: wg0 inet 10.100.0.1/32 scope global wg0",
    )
    .expect("all three signed interface bindings agree");

    let wrong_key_chirho = verify_active_relay_mesh_observation_chirho(
        &proof_chirho,
        "WGb",
        "4: wg0: <POINTOPOINT,NOARP,UP> mtu 1420 state UNKNOWN",
        "4: wg0 inet 10.100.0.1/32 scope global wg0",
    )
    .unwrap_err()
    .to_string();
    assert!(wrong_key_chirho.contains("public key differs"));

    let down_chirho = verify_active_relay_mesh_observation_chirho(
        &proof_chirho,
        "WGa",
        "4: wg0: <POINTOPOINT,NOARP> mtu 1420 state DOWN",
        "4: wg0 inet 10.100.0.1/32 scope global wg0",
    )
    .unwrap_err()
    .to_string();
    assert!(down_chirho.contains("is not UP"));

    let wrong_address_chirho = verify_active_relay_mesh_observation_chirho(
        &proof_chirho,
        "WGa",
        "4: wg0: <POINTOPOINT,NOARP,UP> mtu 1420 state UNKNOWN",
        "4: wg0 inet 10.100.0.9/32 scope global wg0",
    )
    .unwrap_err()
    .to_string();
    assert!(wrong_address_chirho.contains("lacks the signed local mesh address"));
}

#[test]
fn active_relay_mesh_requires_exact_signed_peers_and_routes_chirho() {
    let operator_chirho = tmp_root_chirho("active-relay-routes");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let specs_chirho = vec![spec_chirho('a', 1, 1), spec_chirho('b', 2, 2)];
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &specs_chirho);
    let proof_chirho = derive_verified_relay_mesh_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap();
    let remote_ip_chirho = "10.100.0.2".parse::<IpAddr>().unwrap();
    let valid_routes_chirho = vec![(
        remote_ip_chirho,
        "10.100.0.2 dev wg0 src 10.100.0.1 uid 1000\n".to_string(),
    )];

    verify_active_relay_mesh_peer_routes_chirho(
        &proof_chirho,
        "wg0",
        "WGb\t10.100.0.2/32\n",
        &valid_routes_chirho,
    )
    .expect("the exact signed peer routes through the exact active mesh");

    let wrong_peer_chirho = verify_active_relay_mesh_peer_routes_chirho(
        &proof_chirho,
        "wg0",
        "WG-unreviewed-chirho\t10.100.0.2/32\n",
        &valid_routes_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(wrong_peer_chirho.contains("peer-to-address mapping differs"));

    let missing_peer_chirho =
        verify_active_relay_mesh_peer_routes_chirho(&proof_chirho, "wg0", "", &valid_routes_chirho)
            .unwrap_err()
            .to_string();
    assert!(missing_peer_chirho.contains("peer-to-address mapping differs"));

    for bad_route_chirho in [
        "10.100.0.2 dev eth0 src 10.100.0.1 uid 1000\n",
        "10.100.0.2 dev wg0 src 10.100.0.9 uid 1000\n",
        "10.100.0.3 dev wg0 src 10.100.0.1 uid 1000\n",
    ] {
        let refusal_chirho = verify_active_relay_mesh_peer_routes_chirho(
            &proof_chirho,
            "wg0",
            "WGb\t10.100.0.2/32\n",
            &[(remote_ip_chirho, bad_route_chirho.to_string())],
        )
        .unwrap_err()
        .to_string();
        assert!(
            refusal_chirho.contains("does not route through"),
            "{refusal_chirho}"
        );
    }

    let missing_route_chirho = verify_active_relay_mesh_peer_routes_chirho(
        &proof_chirho,
        "wg0",
        "WGb\t10.100.0.2/32\n",
        &[],
    )
    .unwrap_err()
    .to_string();
    assert!(missing_route_chirho.contains("route population differs"));
}

#[test]
fn active_relay_mesh_refuses_swapped_signed_peer_address_bindings_chirho() {
    let operator_chirho = tmp_root_chirho("active-relay-peer-address");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let specs_chirho = vec![
        spec_chirho('a', 1, 1),
        spec_chirho('b', 2, 2),
        spec_chirho('c', 3, 3),
    ];
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &specs_chirho);
    let proof_chirho = derive_verified_relay_mesh_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    )
    .unwrap();
    let routes_chirho = vec![
        (
            "10.100.0.2".parse::<IpAddr>().unwrap(),
            "10.100.0.2 dev wg0 src 10.100.0.1 uid 1000\n".to_string(),
        ),
        (
            "10.100.0.3".parse::<IpAddr>().unwrap(),
            "10.100.0.3 dev wg0 src 10.100.0.1 uid 1000\n".to_string(),
        ),
    ];

    verify_active_relay_mesh_peer_routes_chirho(
        &proof_chirho,
        "wg0",
        "WGb\t10.100.0.2/32\nWGc\t10.100.0.3/32\n",
        &routes_chirho,
    )
    .expect("each signed peer key maps to its own signed mesh address");
    let swapped_chirho = verify_active_relay_mesh_peer_routes_chirho(
        &proof_chirho,
        "wg0",
        "WGb\t10.100.0.3/32\nWGc\t10.100.0.2/32\n",
        &routes_chirho,
    )
    .unwrap_err()
    .to_string();
    assert!(swapped_chirho.contains("peer-to-address mapping differs"));
}

#[test]
fn relay_mesh_refuses_non_host_addresses_and_command_shaped_interface_names_chirho() {
    let operator_chirho = tmp_root_chirho("relay-address");
    let operator_pubkey_chirho = signer_chirho::pubkey_hex_chirho(&operator_chirho).unwrap();
    let mut invalid_chirho = spec_chirho('a', 1, 1);
    invalid_chirho.mesh_ip_chirho = "0.0.0.0".to_string();
    let (lines_chirho, head_chirho) = build_roster_chirho(&operator_chirho, &[invalid_chirho]);
    let invalid_address_chirho = match derive_verified_relay_mesh_chirho(
        &lines_chirho,
        &head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    ) {
        Ok(_proof_chirho) => panic!("an unspecified mesh address must not mint relay evidence"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(invalid_address_chirho.contains("private-mesh scoped"));

    let mut public_chirho = spec_chirho('a', 1, 1);
    public_chirho.mesh_ip_chirho = "8.8.8.8".to_string();
    let (public_lines_chirho, public_head_chirho) =
        build_roster_chirho(&operator_chirho, &[public_chirho]);
    let public_address_chirho = match derive_verified_relay_mesh_chirho(
        &public_lines_chirho,
        &public_head_chirho,
        &operator_pubkey_chirho,
        &"a".repeat(64),
    ) {
        Ok(_proof_chirho) => panic!("a public mesh address must not mint relay evidence"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(public_address_chirho.contains("private-mesh scoped"));

    assert!(validate_wireguard_interface_name_chirho("wg0").is_ok());
    assert!(validate_wireguard_interface_name_chirho("cairn-chirho").is_ok());
    assert!(validate_wireguard_interface_name_chirho("sixteen-byte-name").is_err());
    assert!(validate_wireguard_interface_name_chirho("wg0;echo bad").is_err());
    assert!(validate_wireguard_interface_name_chirho("").is_err());
}
