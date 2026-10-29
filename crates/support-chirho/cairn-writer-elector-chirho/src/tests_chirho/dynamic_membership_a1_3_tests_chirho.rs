// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.3 slice 1: the live authenticated-peer-set update on the elector (`update_members_chirho`). The
//! convergence driver (slice 3) uses this to add/remove a peer on a RUNNING elector with no restart; here
//! we prove it atomically changes WHO the elector authenticates, refuses the invariant-breaking updates
//! (dropping or remapping the local node, a duplicate raft id), and — the payoff — that the change is
//! actually consulted by the real inbound-message auth path.

// prost eraftpb `Message` is built by `default()` + field assignment (hidden fields).
#![allow(clippy::field_reassign_with_default)]

use super::election_test_support_chirho::voters_chirho;
use crate::elector_port_chirho::NodeIdChirho;
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use crate::raft_wire_chirho::encode_signed_message_chirho;
use cairn_signer_chirho::signer_chirho::{pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{Message, MessageType};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

fn group_chirho(tag_chirho: &str) -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: format!("/var/lib/cairn-a1-3-{tag_chirho}-chirho"),
    }
}

fn temp_root_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-a1-3-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

/// Provision a signing root with a fresh node key and return `(root, node_id = pubkey)`.
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

// ---- structural: the peer set changes, and the elector's invariants hold ---------------------------

#[test]
fn update_members_replaces_the_authenticated_peer_set_chirho() {
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho("replace"),
        1,
        voters_chirho(3),
    )
    .unwrap();
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3]
    );

    // Add a 4th peer.
    let mut with_four_chirho = voters_chirho(3);
    with_four_chirho.push((4, NodeIdChirho("4".repeat(64))));
    elector_chirho
        .update_members_chirho(with_four_chirho)
        .unwrap();
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3, 4]
    );

    // Remove peer 2 (the local node 1 stays).
    let without_two_chirho: Vec<_> = voters_chirho(3)
        .into_iter()
        .filter(|(id_chirho, _)| *id_chirho != 2)
        .collect();
    elector_chirho
        .update_members_chirho(without_two_chirho)
        .unwrap();
    assert_eq!(elector_chirho.authenticated_member_ids_chirho(), vec![1, 3]);
}

#[test]
fn update_members_refuses_dropping_the_local_node_chirho() {
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho("drop-local"),
        1,
        voters_chirho(3),
    )
    .unwrap();
    let without_local_chirho: Vec<_> = voters_chirho(3)
        .into_iter()
        .filter(|(id_chirho, _)| *id_chirho != 1)
        .collect();
    let err_chirho = elector_chirho
        .update_members_chirho(without_local_chirho)
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("local node"), "{err_chirho}");
    // A refused update leaves the set unchanged.
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3]
    );
}

#[test]
fn update_members_refuses_remapping_the_local_node_chirho() {
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho("remap-local"),
        1,
        voters_chirho(3),
    )
    .unwrap();
    // Local id 1 remapped to a DIFFERENT identity — a node must always authenticate as itself.
    let mut remapped_chirho = voters_chirho(3);
    remapped_chirho[0] = (1, NodeIdChirho("f".repeat(64)));
    let err_chirho = elector_chirho
        .update_members_chirho(remapped_chirho)
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("remapped"), "{err_chirho}");
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3]
    );
}

#[test]
fn update_members_refuses_duplicate_raft_id_chirho() {
    let elector_chirho =
        RaftWriterElectorChirho::new_cluster_node_chirho(group_chirho("dup"), 1, voters_chirho(3))
            .unwrap();
    let mut dup_chirho = voters_chirho(3);
    dup_chirho.push((2, NodeIdChirho("2".repeat(64)))); // raft id 2 listed twice
    let err_chirho = elector_chirho
        .update_members_chirho(dup_chirho)
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("appears twice"), "{err_chirho}");
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3]
    );
}

#[test]
fn update_members_refuses_a_node_under_two_raft_ids_chirho() {
    // The reverse of the bijection (audit MEDIUM, claude2): one node identity mapped to TWO raft ids would
    // let a single node authenticate as two voters and manufacture a self-majority. The elector enforces
    // its OWN auth-set invariant and does not trust the driver, so it refuses.
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho("dup-node"),
        1,
        voters_chirho(3),
    )
    .unwrap();
    let shared_node_chirho = NodeIdChirho("9".repeat(64));
    // Distinct raft ids 1/2/4, but raft ids 2 and 4 both map to the SAME node identity.
    let two_ids_one_node_chirho = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, shared_node_chirho.clone()),
        (4, shared_node_chirho),
    ];
    let err_chirho = elector_chirho
        .update_members_chirho(two_ids_one_node_chirho)
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("two raft ids"), "{err_chirho}");
    // A refused update leaves the set unchanged.
    assert_eq!(
        elector_chirho.authenticated_member_ids_chirho(),
        vec![1, 2, 3]
    );
}

// ---- behavioral: the live set is exactly what the inbound-auth path consults ------------------------

#[test]
fn update_members_changes_who_the_auth_path_verifies_chirho() {
    // The payoff: update_members_chirho actually governs inbound-message authentication on a running,
    // signed elector — not just an internal Vec. A genuine signed message from peer 2 is accepted while 2
    // is a member, rejected once 2 is removed, and accepted again once 2 is re-added.
    let (root1_chirho, node1_chirho) = provision_node_chirho("auth-n1");
    let (root2_chirho, node2_chirho) = provision_node_chirho("auth-n2");
    let group_chirho = group_chirho("auth");
    let elector_chirho = RaftWriterElectorChirho::new_cluster_node_chirho(
        group_chirho.clone(),
        1,
        vec![(1, node1_chirho.clone()), (2, node2_chirho.clone())],
    )
    .unwrap()
    .with_message_authentication_chirho(root1_chirho.clone());

    let signed_from_2_chirho =
        encode_signed_message_chirho(&vote_message_chirho(2, 1), &group_chirho, &root2_chirho)
            .unwrap();

    // Current member -> the signed message verifies and steps.
    assert!(
        elector_chirho
            .step_encoded_chirho(&signed_from_2_chirho)
            .is_ok(),
        "a signed message from a current member verifies"
    );

    // Remove peer 2 from the authenticated set -> its same signed message is now rejected at auth.
    elector_chirho
        .update_members_chirho(vec![(1, node1_chirho.clone())])
        .unwrap();
    assert!(
        elector_chirho
            .step_encoded_chirho(&signed_from_2_chirho)
            .is_err(),
        "after removal, the removed peer's signed message is rejected before step"
    );

    // Re-add peer 2 -> it verifies again.
    elector_chirho
        .update_members_chirho(vec![(1, node1_chirho), (2, node2_chirho)])
        .unwrap();
    assert!(
        elector_chirho
            .step_encoded_chirho(&signed_from_2_chirho)
            .is_ok(),
        "after re-adding, the peer's signed message verifies again"
    );

    let _ = std::fs::remove_dir_all(&root1_chirho);
    let _ = std::fs::remove_dir_all(&root2_chirho);
}
