// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A1.3 slice 2: the pure convergence plan. It diffs the verified derived target against the live
//! `ConfState`, PRE-CLASSIFYING each step into `new_voters` (add-as-learner then promote), `promotions`
//! (already a live learner — just promote), and `removes` (a group member absent from the target). It is
//! deterministic (raft-id order), idempotent (a converged group yields an empty plan), and fail-closed
//! (empty / zero-id / duplicate-id targets refuse). No elector is mutated here; the safe apply is slice 3.

use super::*;

fn target_member_chirho(raft_id_chirho: u64) -> ElectorMemberChirho {
    ElectorMemberChirho {
        raft_id_chirho,
        pubkey_chirho: format!("pk-{raft_id_chirho}"),
        url_chirho: format!("http://10.100.0.{raft_id_chirho}:8300"),
        learner_chirho: false,
    }
}

fn target_chirho(ids_chirho: &[u64]) -> Vec<ElectorMemberChirho> {
    ids_chirho
        .iter()
        .map(|id_chirho| target_member_chirho(*id_chirho))
        .collect()
}

/// The raft ids of a member list, for terse assertions.
fn ids_chirho(members_chirho: &[ConvergenceMemberChirho]) -> Vec<u64> {
    members_chirho
        .iter()
        .map(|member_chirho| member_chirho.raft_id_chirho)
        .collect()
}

#[test]
fn adds_a_brand_new_voter_and_removes_a_dropped_one_chirho() {
    // Target wants {1,2,4}; the group runs voters {1,2,3}. 4 is brand-new (add as learner->promote); 3 is
    // dropped (remove). Nothing is a promotion (no live learners).
    let plan_chirho = plan_convergence_chirho(&target_chirho(&[1, 2, 4]), &[1, 2, 3], &[]).unwrap();
    assert_eq!(
        plan_chirho.new_voters_chirho,
        vec![ConvergenceMemberChirho {
            raft_id_chirho: 4,
            pubkey_hex_chirho: "pk-4".to_string(),
        }]
    );
    assert!(plan_chirho.promotions_chirho.is_empty());
    assert_eq!(plan_chirho.removes_chirho, vec![3]);
    assert!(!plan_chirho.is_converged_chirho());
}

#[test]
fn converged_group_yields_empty_plan_chirho() {
    // IDEMPOTENT: the group already matches the target -> nothing to add, promote, or remove.
    let plan_chirho = plan_convergence_chirho(&target_chirho(&[1, 2, 3]), &[1, 2, 3], &[]).unwrap();
    assert!(plan_chirho.new_voters_chirho.is_empty());
    assert!(plan_chirho.promotions_chirho.is_empty());
    assert!(plan_chirho.removes_chirho.is_empty());
    assert!(plan_chirho.is_converged_chirho());
}

#[test]
fn classifies_a_live_learner_as_a_promotion_not_an_add_chirho() {
    // Node 3 is already a live LEARNER and the target wants it as a voter -> it is a PROMOTION (slice 3
    // just promotes it), NOT a new_voter (add_learner on a live learner is a raft ConfChange error).
    let plan_chirho = plan_convergence_chirho(&target_chirho(&[1, 2, 3]), &[1, 2], &[3]).unwrap();
    assert!(plan_chirho.new_voters_chirho.is_empty());
    assert_eq!(
        plan_chirho.promotions_chirho,
        vec![ConvergenceMemberChirho {
            raft_id_chirho: 3,
            pubkey_hex_chirho: "pk-3".to_string(),
        }]
    );
    assert!(plan_chirho.removes_chirho.is_empty());
}

#[test]
fn splits_new_voters_from_promotions_in_one_plan_chirho() {
    // Target {1,2,3,5}; voters {1,2}, learners {3}. Node 5 is brand-new (new_voter); node 3 is a live
    // learner (promotion) — the split lands in the pure plan so slice 3 never guesses.
    let plan_chirho =
        plan_convergence_chirho(&target_chirho(&[1, 2, 3, 5]), &[1, 2], &[3]).unwrap();
    assert_eq!(ids_chirho(&plan_chirho.new_voters_chirho), vec![5]);
    assert_eq!(ids_chirho(&plan_chirho.promotions_chirho), vec![3]);
    assert!(plan_chirho.removes_chirho.is_empty());
}

#[test]
fn removes_a_stale_learner_not_in_target_chirho() {
    // Node 3 is a live learner but the target does NOT include it -> remove it (a stale/rogue learner).
    let plan_chirho = plan_convergence_chirho(&target_chirho(&[1, 2]), &[1, 2], &[3]).unwrap();
    assert!(plan_chirho.new_voters_chirho.is_empty());
    assert!(plan_chirho.promotions_chirho.is_empty());
    assert_eq!(plan_chirho.removes_chirho, vec![3]);
}

#[test]
fn new_voters_and_removes_are_both_populated_and_sorted_chirho() {
    // Target {1,4}; voters {1,2,3}. Add 4; remove {2,3} — both lists present and sorted (slice 3 orders
    // new_voters-before-removes at APPLY so quorum never dips).
    let plan_chirho = plan_convergence_chirho(&target_chirho(&[1, 4]), &[1, 2, 3], &[]).unwrap();
    assert_eq!(ids_chirho(&plan_chirho.new_voters_chirho), vec![4]);
    assert_eq!(plan_chirho.removes_chirho, vec![2, 3]);
}

#[test]
fn is_deterministic_regardless_of_input_order_chirho() {
    // The same membership, given in different orders, plans identically (raft-id order).
    let plan_a_chirho =
        plan_convergence_chirho(&target_chirho(&[4, 1, 2]), &[3, 2, 1], &[]).unwrap();
    let plan_b_chirho =
        plan_convergence_chirho(&target_chirho(&[2, 4, 1]), &[1, 3, 2], &[]).unwrap();
    assert_eq!(plan_a_chirho, plan_b_chirho);
    assert_eq!(ids_chirho(&plan_a_chirho.new_voters_chirho), vec![4]);
    assert_eq!(plan_a_chirho.removes_chirho, vec![3]);
}

#[test]
fn refuses_empty_target_chirho() {
    let err_chirho = plan_convergence_chirho(&[], &[1, 2, 3], &[])
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("EMPTY target"), "{err_chirho}");
}

#[test]
fn refuses_zero_raft_id_target_chirho() {
    let err_chirho = plan_convergence_chirho(&target_chirho(&[0, 1]), &[1], &[])
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("raft id 0"), "{err_chirho}");
}

#[test]
fn refuses_duplicate_target_raft_id_chirho() {
    let err_chirho = plan_convergence_chirho(&target_chirho(&[1, 2, 2]), &[1], &[])
        .unwrap_err()
        .to_string();
    assert!(err_chirho.contains("duplicate raft id 2"), "{err_chirho}");
}
