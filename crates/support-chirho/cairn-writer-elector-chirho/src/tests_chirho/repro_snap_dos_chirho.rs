// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Regression for the crafted-message DoS (audit BLOCKER): a crafted `MsgSnapshot`, the single crafted
//! `MsgAppend` that panics raft-rs's unstable-log slice (`prevLogIndex` far ahead, `prevLogTerm=0`), and
//! a crafted `MsgPropose` are all CONTAINED at the elector boundary — they return an error or are dropped,
//! they never panic, never poison the mutex, and never permanently brick the node. Leadership reads stay
//! safe, and the process is unharmed (a fresh elector still elects). This asserts the fix that replaced
//! the earlier `repro_snap_dos` reproduction. If any step below panicked, this test would fail.

// prost-generated eraftpb messages are built by `default()` + field assignment: their struct literals
// require every generated field (some are version-specific), so the default-then-set form is the robust,
// idiomatic way to construct the adversarial messages here.
#![allow(clippy::field_reassign_with_default)]

use crate::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use crate::raft_elector_chirho::RaftWriterElectorChirho;
use crate::raft_wire_chirho::encode_message_chirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{ConfState, Entry, Message, MessageType, Snapshot, SnapshotMetadata};

fn crafted_msgsnapshot_chirho() -> Message {
    let mut conf_chirho = ConfState::default();
    conf_chirho.voters = vec![1, 2, 3];
    let mut meta_chirho = SnapshotMetadata::default();
    meta_chirho.index = 1_000_000;
    meta_chirho.term = 1_000_000;
    meta_chirho.conf_state = Some(conf_chirho);
    let mut snap_chirho = Snapshot::default();
    snap_chirho.metadata = Some(meta_chirho);
    let mut message_chirho = Message::default();
    message_chirho.set_msg_type(MessageType::MsgSnapshot);
    message_chirho.from = 2;
    message_chirho.to = 1;
    message_chirho.term = 1_000_000;
    message_chirho.snapshot = Some(snap_chirho);
    message_chirho
}

/// The single message the verify pass proved bricks a fresh node: an out-of-range append whose
/// `log_term = 0` slips past `match_term` and then panics the unstable-log slice.
fn crafted_msgappend_chirho() -> Message {
    let mut entry_chirho = Entry::default();
    entry_chirho.index = 1_000_001;
    entry_chirho.term = 1_000_000;
    let mut message_chirho = Message::default();
    message_chirho.set_msg_type(MessageType::MsgAppend);
    message_chirho.from = 2;
    message_chirho.to = 1;
    message_chirho.term = 1_000_000;
    message_chirho.index = 1_000_000;
    message_chirho.log_term = 0;
    message_chirho.commit = 1_000_001;
    message_chirho.entries = vec![entry_chirho];
    message_chirho
}

fn crafted_msgpropose_chirho() -> Message {
    let mut entry_chirho = Entry::default();
    entry_chirho.data = vec![0xde, 0xad];
    let mut message_chirho = Message::default();
    message_chirho.set_msg_type(MessageType::MsgPropose);
    message_chirho.from = 2;
    message_chirho.to = 1;
    message_chirho.term = 1_000_000;
    message_chirho.entries = vec![entry_chirho];
    message_chirho
}

#[test]
fn crafted_messages_are_contained_and_the_node_survives_chirho() {
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-snap-dos-chirho".to_string(),
    };
    let voters_chirho = vec![
        (1u64, NodeIdChirho("1".repeat(64))),
        (2u64, NodeIdChirho("2".repeat(64))),
        (3u64, NodeIdChirho("3".repeat(64))),
    ];
    let node_chirho =
        RaftWriterElectorChirho::new_cluster_node_chirho(group_chirho.clone(), 1, voters_chirho)
            .expect("build cluster node");

    // The read path works before any attack (and would panic on a poisoned mutex if the fix regressed).
    let _before_chirho = node_chirho.leadership_chirho(&group_chirho);

    // Each crafted message is CONTAINED — it returns a Result and does not panic/poison. (A panic here
    // would unwind out of step_encoded and fail the test.)
    let snap_bytes_chirho = encode_message_chirho(&crafted_msgsnapshot_chirho());
    assert!(
        node_chirho.step_encoded_chirho(&snap_bytes_chirho).is_ok(),
        "an election-only node drops MsgSnapshot without panicking"
    );
    let append_bytes_chirho = encode_message_chirho(&crafted_msgappend_chirho());
    let _append_result_chirho = node_chirho.step_encoded_chirho(&append_bytes_chirho);
    let propose_bytes_chirho = encode_message_chirho(&crafted_msgpropose_chirho());
    let _propose_result_chirho = node_chirho.step_encoded_chirho(&propose_bytes_chirho);

    // The node SURVIVES: the leadership read the canary depends on still works (no panic, no permanent
    // brick), returning some view rather than crashing the thread.
    let _after_chirho = node_chirho.leadership_chirho(&group_chirho);

    // And the process is unharmed: a fresh elector in a fresh group still elects a leader.
    let group2_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-snap-dos-survivor-chirho".to_string(),
    };
    let survivor_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        NodeIdChirho("f".repeat(64)),
        group2_chirho.clone(),
    )
    .expect("build survivor elector");
    survivor_chirho
        .campaign_chirho()
        .expect("survivor campaigns");
    assert!(
        survivor_chirho
            .leadership_chirho(&group2_chirho)
            .is_leader_chirho,
        "the process survives the DoS attempt — a fresh elector still elects"
    );
}
