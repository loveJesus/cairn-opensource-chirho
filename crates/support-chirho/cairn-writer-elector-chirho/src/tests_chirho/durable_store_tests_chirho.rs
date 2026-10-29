// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Crash-recovery tests for `DurableRaftStoreChirho`: the hard state (term/vote/commit) and log entries
//! survive a drop + reopen; a torn final append record is skipped; and — the safety property that
//! motivated the durable store — a durable elector that voted in a term recovers that vote after a
//! restart, so it advances to a NEW term rather than voting twice in the old one.

// prost eraftpb structs are built by `default()` + field assignment (they carry hidden fields).
#![allow(clippy::field_reassign_with_default)]

use crate::durable_store_chirho::DurableRaftStoreChirho;
use crate::elector_port_chirho::{NodeIdChirho, WriterElectorChirho};
use crate::raft_elector_chirho::{single_conf_change_chirho, RaftWriterElectorChirho};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{ConfChangeSingle, ConfChangeType, ConfChangeV2, Entry, HardState};
use raft::storage::Storage;
use raft::GetEntriesContext;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// A unique, non-existent temp directory for one test (no wall clock needed — pid + a counter are
/// unique within this test run).
fn temp_dir_chirho(tag_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-durable-raft-{tag_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    dir_chirho
}

fn entry_chirho(index_chirho: u64, term_chirho: u64, data_chirho: &[u8]) -> Entry {
    let mut entry_chirho = Entry::default();
    entry_chirho.index = index_chirho;
    entry_chirho.term = term_chirho;
    entry_chirho.data = data_chirho.to_vec();
    entry_chirho
}

#[test]
fn durable_store_round_trips_hard_state_and_entries_chirho() {
    let dir_chirho = temp_dir_chirho("round-trip");
    {
        let store_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        store_chirho
            .append_durable_chirho(&[entry_chirho(1, 7, b"alpha"), entry_chirho(2, 7, b"beta")])
            .unwrap();
        let mut hard_state_chirho = HardState::default();
        hard_state_chirho.term = 7;
        hard_state_chirho.vote = 1;
        hard_state_chirho.commit = 2;
        store_chirho
            .set_hardstate_durable_chirho(hard_state_chirho)
            .unwrap();
    }

    // Reopen a fresh store on the same directory — nothing is shared in memory with the first one.
    let reopened_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    let state_chirho = reopened_chirho.initial_state().unwrap();
    assert_eq!(state_chirho.hard_state.term, 7);
    assert_eq!(state_chirho.hard_state.vote, 1);
    assert_eq!(state_chirho.hard_state.commit, 2);
    assert_eq!(reopened_chirho.last_index().unwrap(), 2);
    let entries_chirho = reopened_chirho
        .entries(1, 3, None, GetEntriesContext::empty(false))
        .unwrap();
    assert_eq!(entries_chirho.len(), 2);
    assert_eq!(entries_chirho[0].data, b"alpha".to_vec());
    assert_eq!(entries_chirho[1].data, b"beta".to_vec());

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn append_overwrites_a_conflicting_index_on_reopen_chirho() {
    // Two batches where the second rewinds index 2 (raft's truncate-on-conflict): replaying the recorded
    // append order must reproduce the final log, not concatenate the stale entry.
    let dir_chirho = temp_dir_chirho("conflict");
    {
        let store_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        store_chirho
            .append_durable_chirho(&[entry_chirho(1, 1, b"a"), entry_chirho(2, 1, b"stale")])
            .unwrap();
        store_chirho
            .append_durable_chirho(&[entry_chirho(2, 2, b"fresh")])
            .unwrap();
    }
    let reopened_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    assert_eq!(reopened_chirho.last_index().unwrap(), 2);
    let entries_chirho = reopened_chirho
        .entries(2, 3, None, GetEntriesContext::empty(false))
        .unwrap();
    assert_eq!(entries_chirho.len(), 1);
    assert_eq!(entries_chirho[0].term, 2);
    assert_eq!(entries_chirho[0].data, b"fresh".to_vec());

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn torn_final_entry_record_is_skipped_on_reopen_chirho() {
    let dir_chirho = temp_dir_chirho("torn");
    {
        let store_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        store_chirho
            .append_durable_chirho(&[entry_chirho(1, 3, b"complete")])
            .unwrap();
    }
    // Simulate a crash mid-append: a length prefix claiming more bytes than actually made it to disk.
    let log_path_chirho = dir_chirho.join("raft-entries-chirho.log");
    let mut file_chirho = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path_chirho)
        .unwrap();
    file_chirho.write_all(&999u32.to_le_bytes()).unwrap();
    file_chirho.write_all(b"\x08\x02").unwrap(); // only 2 of the claimed 999 body bytes
    drop(file_chirho);

    // Reopen: the torn final record is dropped; the one complete entry survives.
    let reopened_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    assert_eq!(reopened_chirho.last_index().unwrap(), 1);
    let entries_chirho = reopened_chirho
        .entries(1, 2, None, GetEntriesContext::empty(false))
        .unwrap();
    assert_eq!(entries_chirho.len(), 1);
    assert_eq!(entries_chirho[0].data, b"complete".to_vec());

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn durable_elector_recovers_term_and_vote_across_restart_chirho() {
    let dir_chirho = temp_dir_chirho("elector-recover");
    let node_id_chirho = NodeIdChirho("a".repeat(64));
    let group_chirho = ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-durable-recover-chirho".to_string(),
    };

    let term_before_chirho;
    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        elector_chirho.campaign_chirho().unwrap();
        let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
        assert!(
            leadership_chirho.is_leader_chirho,
            "single node self-elects"
        );
        term_before_chirho = leadership_chirho.term_chirho;
        assert!(term_before_chirho >= 1, "a real election term was reached");
    }

    // The durable state on disk must remember the term AND the self-vote (raft id 1), so a restart at
    // that term cannot cast a second, conflicting vote.
    let store_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    let state_chirho = store_chirho.initial_state().unwrap();
    assert_eq!(
        state_chirho.hard_state.term, term_before_chirho,
        "recovered term matches the pre-restart term"
    );
    assert_eq!(
        state_chirho.hard_state.vote, 1,
        "recovered vote is self — no double-vote after restart"
    );

    // End-to-end: a reopened elector that campaigns again advances to a STRICTLY NEWER term, proving it
    // resumed from the recovered term rather than restarting from zero.
    let reopened_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
        dir_chirho.clone(),
        node_id_chirho,
        group_chirho.clone(),
    )
    .unwrap();
    reopened_chirho.campaign_chirho().unwrap();
    let after_chirho = reopened_chirho.leadership_chirho(&group_chirho);
    assert!(after_chirho.is_leader_chirho);
    assert!(
        after_chirho.term_chirho > term_before_chirho,
        "reopened node advances past the recovered term ({} > {})",
        after_chirho.term_chirho,
        term_before_chirho
    );

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn durable_store_recovers_the_log_over_random_append_truncate_sequences_chirho() {
    // Property/fuzz: deterministic pseudo-random (LCG — no RNG or clock) sequences of VALID raft log
    // operations — contiguous extends and rewinding truncations at a bumped term — each persisted; after a
    // drop + reopen the store must reproduce the EXACT log it last held. Hardens the append-only-log replay
    // (the crash-recovery mechanism) over many shapes beyond the targeted round-trip/conflict/torn tests.
    for case_chirho in 0..24u64 {
        let dir_chirho = temp_dir_chirho(&format!("prop-{case_chirho}"));
        let mut lcg_chirho: u64 = 0x9e37_79b9_7f4a_7c15 ^ case_chirho.wrapping_mul(0x1000_0001);

        let (pre_last_chirho, pre_entries_chirho) = {
            let store_chirho =
                DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
            let mut term_chirho: u64 = 1;
            // Seed one entry so a truncation has something to rewind.
            store_chirho
                .append_durable_chirho(&[entry_chirho(1, term_chirho, b"seed")])
                .unwrap();
            for _op_chirho in 0..40 {
                lcg_chirho = lcg_chirho
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                let last_chirho = store_chirho.last_index().unwrap();
                if lcg_chirho.is_multiple_of(2) {
                    // Extend: append 1-3 contiguous entries at last+1.
                    let count_chirho = 1 + (lcg_chirho >> 8) % 3;
                    let entries_chirho: Vec<Entry> = (0..count_chirho)
                        .map(|k_chirho| {
                            entry_chirho(
                                last_chirho + 1 + k_chirho,
                                term_chirho,
                                &[(lcg_chirho >> k_chirho) as u8],
                            )
                        })
                        .collect();
                    store_chirho.append_durable_chirho(&entries_chirho).unwrap();
                } else if last_chirho >= 1 {
                    // Truncate-rewrite: append at a random index in [1, last] at a bumped term (a leader
                    // change rewriting the tail). raft's append truncates from that index.
                    term_chirho += 1;
                    let idx_chirho = 1 + (lcg_chirho >> 16) % last_chirho;
                    store_chirho
                        .append_durable_chirho(&[entry_chirho(idx_chirho, term_chirho, b"rw")])
                        .unwrap();
                }
            }
            let last_chirho = store_chirho.last_index().unwrap();
            let entries_chirho = store_chirho
                .entries(1, last_chirho + 1, None, GetEntriesContext::empty(false))
                .unwrap();
            (last_chirho, entries_chirho)
        };

        // Reopen from disk: the replayed log must equal the exact pre-drop log.
        let reopened_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        assert_eq!(
            reopened_chirho.last_index().unwrap(),
            pre_last_chirho,
            "case {case_chirho}: recovered last index matches"
        );
        let recovered_chirho = reopened_chirho
            .entries(
                1,
                pre_last_chirho + 1,
                None,
                GetEntriesContext::empty(false),
            )
            .unwrap();
        assert_eq!(
            recovered_chirho, pre_entries_chirho,
            "case {case_chirho}: the recovered log matches the pre-drop log exactly"
        );

        let _ = std::fs::remove_dir_all(&dir_chirho);
    }
}

// --- A1.1 dynamic-membership apply path ---------------------------------------------------------
// A committed ConfChangeV2 is applied to the running election-only node and the new conf state +
// applied index persisted as ONE atomic record; a committed-but-unpersisted change re-surfaces and
// re-applies exactly once on restart (proven by deleting the atomic membership file — the
// crash-before-persist window R1 collapses); re-applying the SAME committed change through the real
// raft-rs apply_conf_change is idempotent (R2, tested not assumed); a >1-change proposal is refused
// before raft sees it (R3a).

/// The A1 membership file name (kept in step with `durable_store_chirho`), deleted below to simulate a
/// crash after a conf change committed but before its atomic membership write landed.
const MEMBERSHIP_FILE_CHIRHO: &str = "raft-membership-chirho.bin";

/// Advance the logical clock a few times so a proposed conf change commits (single-voter majority) and
/// its committed entry surfaces and applies. Under the election timeout, so a follower stays a follower.
fn pump_ticks_chirho(elector_chirho: &RaftWriterElectorChirho, ticks_chirho: usize) {
    for _ in 0..ticks_chirho {
        let _ = elector_chirho.tick_chirho();
    }
}

fn membership_group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::RootPathChirho {
        canonical_root_chirho: "/var/lib/cairn-membership-test-chirho".to_string(),
    }
}

#[test]
fn existing_only_elector_refuses_to_seed_missing_authority_state_chirho() {
    let dir_chirho = temp_dir_chirho("existing-only-missing");
    let error_chirho = match RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
        dir_chirho.clone(),
        NodeIdChirho("a".repeat(64)),
        membership_group_chirho(),
    ) {
        Ok(_elector_chirho) => panic!("serving must not seed a missing election generation"),
        Err(error_chirho) => error_chirho,
    };
    assert!(
        error_chirho.to_string().contains("No such file")
            || error_chirho.to_string().contains("not found"),
        "the refusal names the missing durable state: {error_chirho}"
    );
    assert!(
        !dir_chirho.exists(),
        "an existing-only refusal must not create authority state"
    );
}

#[test]
fn existing_only_elector_reopens_initialized_authority_state_chirho() {
    let dir_chirho = temp_dir_chirho("existing-only-reopen");
    let node_id_chirho = NodeIdChirho("b".repeat(64));
    let group_chirho = membership_group_chirho();
    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .expect("the authority ceremony initializes the durable generation");
        elector_chirho
            .campaign_chirho()
            .expect("the initialized generation can elect itself");
    }

    let reopened_chirho = RaftWriterElectorChirho::open_existing_durable_single_node_chirho(
        dir_chirho.clone(),
        node_id_chirho,
        group_chirho,
    )
    .expect("serving reopens the initialized durable generation");
    let (voters_chirho, learners_chirho) = reopened_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(voters_chirho, vec![1]);
    assert!(learners_chirho.is_empty());

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn existing_only_cluster_reopens_exact_voters_and_learners_chirho() {
    let dir_chirho = temp_dir_chirho("existing-cluster-reopen");
    let group_chirho = membership_group_chirho();
    let voters_chirho = vec![
        (1, NodeIdChirho("1".repeat(64))),
        (2, NodeIdChirho("2".repeat(64))),
    ];
    let learners_chirho = vec![(3, NodeIdChirho("3".repeat(64)))];
    {
        let _elector_chirho =
            RaftWriterElectorChirho::new_durable_cluster_node_with_learners_chirho(
                dir_chirho.clone(),
                group_chirho.clone(),
                1,
                voters_chirho.clone(),
                learners_chirho.clone(),
            )
            .expect("the authority ceremony initializes exact multi-node membership");
    }

    let reopened_chirho =
        RaftWriterElectorChirho::open_existing_durable_cluster_node_with_learners_chirho(
            dir_chirho.clone(),
            group_chirho,
            1,
            voters_chirho,
            learners_chirho,
        )
        .expect("serving reopens exact existing multi-node membership");
    assert_eq!(
        reopened_chirho.membership_snapshot_chirho().unwrap(),
        (vec![1, 2], vec![3])
    );

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn existing_only_cluster_refuses_recovered_membership_drift_chirho() {
    let dir_chirho = temp_dir_chirho("existing-cluster-drift");
    let group_chirho = membership_group_chirho();
    {
        let _elector_chirho =
            RaftWriterElectorChirho::new_durable_cluster_node_with_learners_chirho(
                dir_chirho.clone(),
                group_chirho.clone(),
                1,
                vec![
                    (1, NodeIdChirho("1".repeat(64))),
                    (2, NodeIdChirho("2".repeat(64))),
                ],
                vec![(3, NodeIdChirho("3".repeat(64)))],
            )
            .expect("initialize the durable source membership");
    }

    let result_chirho =
        RaftWriterElectorChirho::open_existing_durable_cluster_node_with_learners_chirho(
            dir_chirho.clone(),
            group_chirho,
            1,
            vec![
                (1, NodeIdChirho("1".repeat(64))),
                (3, NodeIdChirho("3".repeat(64))),
            ],
            vec![(2, NodeIdChirho("2".repeat(64)))],
        );
    assert!(
        result_chirho.is_err(),
        "authority serving must refuse recovered membership drift"
    );

    let recovered_chirho = DurableRaftStoreChirho::open_existing_with_learners_chirho(
        dir_chirho.clone(),
        vec![1, 2],
        vec![3],
    )
    .expect("the refusal leaves the durable membership readable");
    let recovered_state_chirho = recovered_chirho.initial_state().unwrap();
    assert_eq!(recovered_state_chirho.conf_state.voters, vec![1, 2]);
    assert_eq!(recovered_state_chirho.conf_state.learners, vec![3]);

    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn single_add_applies_and_persists_chirho() {
    let dir_chirho = temp_dir_chirho("dyn-add");
    let node_id_chirho = NodeIdChirho("a".repeat(64));
    let group_chirho = membership_group_chirho();
    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        elector_chirho.campaign_chirho().expect("self-elect");
        assert!(
            elector_chirho
                .leadership_chirho(&group_chirho)
                .is_leader_chirho
        );

        elector_chirho
            .propose_conf_change_chirho(
                Vec::new(),
                single_conf_change_chirho(ConfChangeType::AddLearnerNode, 2),
            )
            .expect("propose adding learner 2");
        pump_ticks_chirho(&elector_chirho, 5);

        let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho().unwrap();
        assert_eq!(voters_chirho, vec![1], "the sole voter is unchanged");
        assert_eq!(
            learners_chirho,
            vec![2],
            "learner 2 applied on the running group"
        );
    }

    // The applied membership survives a restart: the reopened store reads learner 2 and a non-zero
    // applied index from the single atomic membership file.
    let store_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    let state_chirho = store_chirho.initial_state().unwrap();
    assert_eq!(
        state_chirho.conf_state.learners,
        vec![2],
        "learner 2 persisted across restart"
    );
    assert!(
        store_chirho.recovered_applied_index_chirho() > 0,
        "the applied index was persisted with the membership"
    );
    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn restart_mid_change_converges_chirho() {
    let dir_chirho = temp_dir_chirho("dyn-restart");
    let node_id_chirho = NodeIdChirho("b".repeat(64));
    let group_chirho = membership_group_chirho();

    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        elector_chirho.campaign_chirho().expect("self-elect");
        elector_chirho
            .propose_conf_change_chirho(
                Vec::new(),
                single_conf_change_chirho(ConfChangeType::AddLearnerNode, 2),
            )
            .expect("propose adding learner 2");
        pump_ticks_chirho(&elector_chirho, 5);
        assert_eq!(
            elector_chirho.membership_snapshot_chirho().unwrap().1,
            vec![2]
        );
    }
    let applied_after_chirho = {
        let store_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        let applied_chirho = store_chirho.recovered_applied_index_chirho();
        assert!(applied_chirho > 0);
        applied_chirho
    };

    // Simulate a crash AFTER the conf change committed but BEFORE its atomic membership write landed:
    // delete the membership file. The log entry and the (separate) hard-state commit index persisted,
    // so the committed conf change is still in the recovered log above the recovered applied index (0).
    std::fs::remove_file(dir_chirho.join(MEMBERSHIP_FILE_CHIRHO))
        .expect("drop the membership file");

    {
        // The reopened node re-seeds a fresh membership, but the committed conf entry re-surfaces
        // (commit > applied 0) and re-applies — converging to learner 2 without any manual repair.
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho,
            group_chirho,
        )
        .unwrap();
        pump_ticks_chirho(&elector_chirho, 5);
        assert_eq!(
            elector_chirho.membership_snapshot_chirho().unwrap().1,
            vec![2],
            "the committed-but-unpersisted membership change re-applied on restart"
        );
    }
    let store_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    assert_eq!(
        store_chirho.initial_state().unwrap().conf_state.learners,
        vec![2]
    );
    assert_eq!(
        store_chirho.recovered_applied_index_chirho(),
        applied_after_chirho,
        "the re-applied change re-persisted at the same applied index"
    );
    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn reapply_is_idempotent_chirho() {
    // Pin raft-rs's ACTUAL re-apply behavior (R2): after applying a conf change for real, repeatedly
    // simulate crash-before-persist (delete the membership file) and reopen. Each restart re-applies the
    // SAME committed ConfChangeV2 through real raft-rs apply_conf_change and must converge to the
    // identical membership — never a duplicated learner, never an error.
    let dir_chirho = temp_dir_chirho("dyn-idempotent");
    let node_id_chirho = NodeIdChirho("c".repeat(64));
    let group_chirho = membership_group_chirho();

    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        elector_chirho.campaign_chirho().expect("self-elect");
        elector_chirho
            .propose_conf_change_chirho(
                Vec::new(),
                single_conf_change_chirho(ConfChangeType::AddLearnerNode, 2),
            )
            .expect("propose adding learner 2");
        pump_ticks_chirho(&elector_chirho, 5);
        assert_eq!(
            elector_chirho.membership_snapshot_chirho().unwrap().1,
            vec![2]
        );
    }

    for round_chirho in 0..2 {
        // The reopen path re-seeds the membership file; delete it again to force another real re-apply.
        let _ = std::fs::remove_file(dir_chirho.join(MEMBERSHIP_FILE_CHIRHO));
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        pump_ticks_chirho(&elector_chirho, 5);
        let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho().unwrap();
        assert_eq!(
            voters_chirho,
            vec![1],
            "round {round_chirho}: voter set stable"
        );
        assert_eq!(
            learners_chirho,
            vec![2],
            "round {round_chirho}: re-applying the same committed change is idempotent"
        );
    }
    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn reject_multi_change_proposal_chirho() {
    // R3a: a proposal carrying more than one change is refused before raft ever sees it, so no proposal
    // can drive a transition with two disjoint majorities.
    let dir_chirho = temp_dir_chirho("dyn-multi");
    let node_id_chirho = NodeIdChirho("d".repeat(64));
    let group_chirho = membership_group_chirho();
    let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
        dir_chirho.clone(),
        node_id_chirho,
        group_chirho,
    )
    .unwrap();
    elector_chirho.campaign_chirho().expect("self-elect");

    let mut add_two_chirho = ConfChangeSingle::default();
    add_two_chirho.set_change_type(ConfChangeType::AddLearnerNode);
    add_two_chirho.node_id = 2;
    let mut add_three_chirho = ConfChangeSingle::default();
    add_three_chirho.set_change_type(ConfChangeType::AddLearnerNode);
    add_three_chirho.node_id = 3;
    let mut two_change_chirho = ConfChangeV2::default();
    two_change_chirho.changes = vec![add_two_chirho, add_three_chirho];

    let err_chirho = elector_chirho
        .propose_conf_change_chirho(Vec::new(), two_change_chirho)
        .expect_err("a two-change proposal must be refused");
    assert!(
        err_chirho.to_string().contains("exactly one change"),
        "the refusal names the single-change rule: {err_chirho}"
    );

    pump_ticks_chirho(&elector_chirho, 3);
    let (voters_chirho, learners_chirho) = elector_chirho.membership_snapshot_chirho().unwrap();
    assert_eq!(voters_chirho, vec![1]);
    assert!(
        learners_chirho.is_empty(),
        "a rejected multi-change proposal changes nothing"
    );
    let _ = std::fs::remove_dir_all(&dir_chirho);
}

#[test]
fn applied_ahead_of_durable_commit_reopens_and_converges_chirho() {
    // A1.1f — the crash window claude2's audit found: a membership apply persists {conf', applied=i};
    // if a crash lands between that and the ready's hard-state write (commit=i), disk holds applied=i
    // while durable commit=i-1, and raft-rs panics at construction ("applied out of range") — the node
    // bricks on every restart. Synthesize exactly that on-disk state and prove the reopen clamp
    // (recovered_applied := min(applied, durable commit)) lets the node CONSTRUCT and converge, safe
    // because re-applying the committed change is idempotent (proven above).
    let dir_chirho = temp_dir_chirho("dyn-applied-ahead");
    let node_id_chirho = NodeIdChirho("e".repeat(64));
    let group_chirho = membership_group_chirho();

    // 1. A real, fully-completed membership change: learner 2 applied; membership file applied=i and
    //    hard state commit=i on disk.
    {
        let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
            dir_chirho.clone(),
            node_id_chirho.clone(),
            group_chirho.clone(),
        )
        .unwrap();
        elector_chirho.campaign_chirho().expect("self-elect");
        elector_chirho
            .propose_conf_change_chirho(
                Vec::new(),
                single_conf_change_chirho(ConfChangeType::AddLearnerNode, 2),
            )
            .expect("propose adding learner 2");
        pump_ticks_chirho(&elector_chirho, 5);
        assert_eq!(
            elector_chirho.membership_snapshot_chirho().unwrap().1,
            vec![2]
        );
    }

    // 2. Synthesize the crash window: rewrite the durable hard state so commit = i-1, leaving the
    //    membership file's applied=i ahead of it (as if the hard-state write was lost to a crash).
    {
        let store_chirho =
            DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
        let applied_i_chirho = store_chirho.recovered_applied_index_chirho();
        assert!(
            applied_i_chirho >= 1,
            "the conf change advanced the applied index"
        );
        let mut hard_state_chirho = store_chirho.initial_state().unwrap().hard_state;
        assert!(hard_state_chirho.commit >= applied_i_chirho);
        hard_state_chirho.commit = applied_i_chirho - 1;
        store_chirho
            .set_hardstate_durable_chirho(hard_state_chirho)
            .unwrap();
    }

    // 3. Reopen: WITHOUT the clamp this panics at construction; WITH it the node constructs, the
    //    committed change re-surfaces and re-applies, and membership converges on learner 2.
    let elector_chirho = RaftWriterElectorChirho::new_durable_single_node_chirho(
        dir_chirho.clone(),
        node_id_chirho,
        group_chirho,
    )
    .expect("the clamp must let the node CONSTRUCT, not boot-panic");
    elector_chirho
        .campaign_chirho()
        .expect("re-establish leadership");
    pump_ticks_chirho(&elector_chirho, 5);
    assert_eq!(
        elector_chirho.membership_snapshot_chirho().unwrap().1,
        vec![2],
        "the clamped node healed and converged on the committed membership"
    );

    // The healed store keeps applied at or below the durable commit.
    let reopened_chirho = DurableRaftStoreChirho::open_chirho(dir_chirho.clone(), vec![1]).unwrap();
    let state_chirho = reopened_chirho.initial_state().unwrap();
    assert!(
        reopened_chirho.recovered_applied_index_chirho() <= state_chirho.hard_state.commit,
        "after healing, the applied index never exceeds the durable commit"
    );
    let _ = std::fs::remove_dir_all(&dir_chirho);
}
