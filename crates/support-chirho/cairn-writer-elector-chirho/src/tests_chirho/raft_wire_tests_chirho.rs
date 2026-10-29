// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Authentication tests for the signed Raft wire envelope: a genuine signed message verifies against the
//! roster, while a tampered signature, a non-rostered sender, and a rostered peer trying to impersonate
//! another peer's `from` are all rejected — the transport-auth BLOCKER fix, exercised at the wire layer.

// prost eraftpb `Message` is built by `default()` + field assignment (hidden fields).
#![allow(clippy::field_reassign_with_default)]

use crate::elector_port_chirho::NodeIdChirho;
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use crate::raft_wire_chirho::{
    decode_and_verify_message_chirho, decode_message_chirho, encode_message_chirho,
    encode_signed_message_chirho, SignedRaftMessageChirho,
};
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{Message, MessageType};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-raft-auth-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// Provision a signing root with a fresh node key and return `(root, node_id=pubkey)`.
fn provision_node_chirho(tag_chirho: &str) -> (PathBuf, NodeIdChirho) {
    let root_chirho = temp_root_chirho(tag_chirho);
    sign_message_chirho(&root_chirho, b"provision node key").unwrap();
    let pubkey_chirho = pubkey_hex_chirho(&root_chirho).unwrap();
    (root_chirho, NodeIdChirho(pubkey_chirho))
}

fn vote_message_chirho(from_chirho: u64, to_chirho: u64) -> Message {
    let mut message_chirho = Message::default();
    message_chirho.set_msg_type(MessageType::MsgRequestVote);
    message_chirho.from = from_chirho;
    message_chirho.to = to_chirho;
    message_chirho.term = 5;
    message_chirho
}

fn group_chirho(tag_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-raft-wire-{tag_chirho}-chirho"),
    }
}

#[test]
fn signed_message_round_trips_and_verifies_against_roster_chirho() {
    let (root1_chirho, node1_chirho) = provision_node_chirho("roundtrip-n1");
    let (root2_chirho, node2_chirho) = provision_node_chirho("roundtrip-n2");
    let roster_chirho = vec![(1u64, node1_chirho), (2u64, node2_chirho)];
    let group_chirho = group_chirho("roundtrip");

    let message_chirho = vote_message_chirho(1, 2);
    let envelope_chirho =
        encode_signed_message_chirho(&message_chirho, &group_chirho, &root1_chirho).unwrap();
    let verified_chirho =
        decode_and_verify_message_chirho(&envelope_chirho, &group_chirho, 2, &roster_chirho)
            .unwrap();
    assert_eq!(verified_chirho.from, 1);
    assert_eq!(verified_chirho.to, 2);
    assert_eq!(verified_chirho.term, 5);

    let _ = std::fs::remove_dir_all(&root1_chirho);
    let _ = std::fs::remove_dir_all(&root2_chirho);
}

#[test]
fn tampered_signature_is_rejected_chirho() {
    let (root1_chirho, node1_chirho) = provision_node_chirho("tamper-n1");
    let roster_chirho = vec![(1u64, node1_chirho)];
    let group_chirho = group_chirho("tamper");

    let envelope_chirho =
        encode_signed_message_chirho(&vote_message_chirho(1, 2), &group_chirho, &root1_chirho)
            .unwrap();
    let mut parsed_chirho: SignedRaftMessageChirho =
        serde_json::from_slice(&envelope_chirho).unwrap();
    parsed_chirho.sig_hex_chirho = "00".repeat(64); // a syntactically valid but wrong signature
    let tampered_chirho = serde_json::to_vec(&parsed_chirho).unwrap();

    assert!(
        decode_and_verify_message_chirho(&tampered_chirho, &group_chirho, 2, &roster_chirho)
            .is_err(),
        "a message with a wrong signature must be rejected"
    );

    let _ = std::fs::remove_dir_all(&root1_chirho);
}

#[test]
fn non_rostered_sender_is_rejected_chirho() {
    let (root1_chirho, node1_chirho) = provision_node_chirho("nonroster-n1");
    // The roster only knows raft id 1, but the (genuinely signed) message claims to come from id 99.
    let roster_chirho = vec![(1u64, node1_chirho)];
    let group_chirho = group_chirho("nonroster");

    let envelope_chirho =
        encode_signed_message_chirho(&vote_message_chirho(99, 1), &group_chirho, &root1_chirho)
            .unwrap();
    assert!(
        decode_and_verify_message_chirho(&envelope_chirho, &group_chirho, 1, &roster_chirho)
            .is_err(),
        "a message from an id that is not in the roster must be rejected"
    );

    let _ = std::fs::remove_dir_all(&root1_chirho);
}

#[test]
fn an_authenticated_elector_rejects_an_unsigned_message_at_step_chirho() {
    // Integration: with authentication enabled, `step_encoded_chirho` expects a signed envelope. A bare
    // prost-encoded message (what an attacker who only speaks the raw wire could send) is rejected before
    // it ever reaches `step`.
    let (root1_chirho, node1_chirho) = provision_node_chirho("elector-bare-n1");
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-auth-elector-chirho".to_string(),
    };
    let elector_chirho =
        RaftWriterElectorChirho::new_cluster_node_chirho(group_chirho, 1, vec![(1, node1_chirho)])
            .expect("build an authenticated elector")
            .with_message_authentication_chirho(root1_chirho.clone());

    let bare_bytes_chirho = encode_message_chirho(&vote_message_chirho(1, 1));
    assert!(
        elector_chirho
            .step_encoded_chirho(&bare_bytes_chirho)
            .is_err(),
        "an authenticated elector rejects a bare, unsigned message"
    );

    let _ = std::fs::remove_dir_all(&root1_chirho);
}

#[test]
fn a_rostered_peer_cannot_impersonate_anothers_from_chirho() {
    // Node 3 holds a real, rostered key — but it crafts a message claiming `from = 2`. The roster maps
    // id 2 to node 2's pubkey, so node 3's signature is verified against node 2's key and MUST fail.
    let (root2_chirho, node2_chirho) = provision_node_chirho("impersonate-n2");
    let (root3_chirho, node3_chirho) = provision_node_chirho("impersonate-n3");
    let roster_chirho = vec![(2u64, node2_chirho), (3u64, node3_chirho)];
    let group_chirho = group_chirho("impersonate");

    let impersonating_chirho = vote_message_chirho(2, 1); // claims to be node 2
    let envelope_chirho =
        encode_signed_message_chirho(&impersonating_chirho, &group_chirho, &root3_chirho).unwrap(); // signed by node 3
    assert!(
        decode_and_verify_message_chirho(&envelope_chirho, &group_chirho, 1, &roster_chirho)
            .is_err(),
        "a rostered peer must not be able to impersonate another peer's from"
    );

    let _ = std::fs::remove_dir_all(&root2_chirho);
    let _ = std::fs::remove_dir_all(&root3_chirho);
}

#[test]
fn signed_message_is_bound_to_exact_group_and_recipient_chirho() {
    let (root1_chirho, node1_chirho) = provision_node_chirho("binding-n1");
    let (root2_chirho, node2_chirho) = provision_node_chirho("binding-n2");
    let roster_chirho = vec![(1u64, node1_chirho), (2u64, node2_chirho)];
    let signed_group_chirho = group_chirho("binding-signed");
    let other_group_chirho = group_chirho("binding-other");
    let envelope_chirho = encode_signed_message_chirho(
        &vote_message_chirho(1, 2),
        &signed_group_chirho,
        &root1_chirho,
    )
    .unwrap();

    assert!(
        decode_and_verify_message_chirho(&envelope_chirho, &other_group_chirho, 2, &roster_chirho,)
            .is_err(),
        "a valid signed message must not cross consistency groups"
    );
    let mut retargeted_chirho: SignedRaftMessageChirho =
        serde_json::from_slice(&envelope_chirho).unwrap();
    retargeted_chirho.group_digest_chirho =
        cairn_writer_head_chirho::writer_head_chirho::consistency_group_digest_chirho(
            &other_group_chirho,
        )
        .unwrap();
    let retargeted_bytes_chirho = serde_json::to_vec(&retargeted_chirho).unwrap();
    assert!(
        decode_and_verify_message_chirho(
            &retargeted_bytes_chirho,
            &other_group_chirho,
            2,
            &roster_chirho,
        )
        .is_err(),
        "changing the plaintext group digest must invalidate the signature"
    );
    assert!(
        decode_and_verify_message_chirho(
            &envelope_chirho,
            &signed_group_chirho,
            1,
            &roster_chirho,
        )
        .is_err(),
        "a valid signed message must not be delivered to another roster member"
    );

    let _ = std::fs::remove_dir_all(&root1_chirho);
    let _ = std::fs::remove_dir_all(&root2_chirho);
}

#[test]
fn hostile_wire_bytes_are_rejected_without_panicking_chirho() {
    // The wire decode is a trust boundary (prost + serde-json + signature verify). Hostile or garbage
    // bytes must be REJECTED, never panic. This exercises the raft_wire internals the P4/P5 audit flagged
    // as not-deeply-covered, over a range of fixed and deterministic-pseudorandom inputs.
    let (root1_chirho, node1_chirho) = provision_node_chirho("hostile-n1");
    let roster_chirho = vec![(1u64, node1_chirho.clone())];
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-hostile-wire-chirho".to_string(),
    };
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho.clone(),
        1,
        vec![(1, node1_chirho)],
    )
    .expect("build an authenticated elector")
    .with_message_authentication_chirho(root1_chirho.clone());

    let mut cases_chirho: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8; 512],
        vec![0xffu8; 512],
        b"{".to_vec(),
        b"not an envelope at all".to_vec(),
        b"{\"message_bytes_chirho\":[],\"sig_hex_chirho\":\"zz\"}".to_vec(),
        b"{\"message_bytes_chirho\":[1,2,3],\"sig_hex_chirho\":\"00\"}".to_vec(),
    ];
    // Deterministic pseudo-random byte blobs (an LCG — no wall clock / RNG needed).
    let mut state_chirho: u64 = 0x1234_5678_9abc_def0;
    for _case_chirho in 0..96 {
        state_chirho = state_chirho
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let len_chirho = (state_chirho % 320) as usize;
        let blob_chirho: Vec<u8> = (0..len_chirho)
            .map(|i_chirho| ((state_chirho >> (i_chirho % 56)) & 0xff) as u8)
            .collect();
        cases_chirho.push(blob_chirho);
    }

    for case_chirho in &cases_chirho {
        // Bare decode is total (prost never panics; it returns Ok(default) or Err on garbage).
        let decode_chirho = catch_unwind(AssertUnwindSafe(|| decode_message_chirho(case_chirho)));
        assert!(
            decode_chirho.is_ok(),
            "decode_message must not panic on hostile bytes"
        );
        // Authenticated decode+verify must REJECT hostile bytes (no valid signed envelope from a rostered
        // peer can arise from garbage) and must not panic.
        let verify_chirho = catch_unwind(AssertUnwindSafe(|| {
            decode_and_verify_message_chirho(case_chirho, &group_chirho, 1, &roster_chirho)
        }));
        assert!(
            verify_chirho.is_ok(),
            "decode_and_verify must not panic on hostile bytes"
        );
        assert!(
            verify_chirho.unwrap().is_err(),
            "decode_and_verify must reject hostile bytes"
        );
        // The authenticated elector's transport entrypoint rejects hostile bytes (contained), never
        // stepping or panicking.
        assert!(
            elector_chirho.step_encoded_chirho(case_chirho).is_err(),
            "an authenticated elector rejects hostile wire bytes at step_encoded"
        );
    }

    let _ = std::fs::remove_dir_all(&root1_chirho);
}
