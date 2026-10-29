// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! What R3 gets (C5 B3-a4-i, item 17): the attempt read from the store, a retry by its identity alone that finds the requirement again by digest, and refusals by name that send nothing and change nothing.

use super::propagation_world_chirho::*;
use super::world_chirho::key_id_chirho;
use crate::leader_chirho::propagate_chirho::ErasurePropagationPolicyChirho;
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasureAttemptChirho, ErasureAttemptIdentityChirho,
    RecordRequirementRequestChirho, RequirementStandingChirho,
    ERASURE_PROPAGATION_STORE_DIR_CHIRHO,
};
use cairn_key_custody_chirho::{subject_digest_hex_chirho, ErasureStatusChirho};
use cairn_mirror_chirho::join_mirror_view_chirho;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// The digest of the root's erasure record at `seq`: a distinct one per seq, as a root's records are.
fn record_digest_chirho(seq_chirho: u64) -> String {
    format!("{:064x}", 0xe7a5_0000_u64 + seq_chirho)
}

/// Record the requirement at `seq` for all three holders and bind it to its own record digest.
fn record_bound_chirho(world_chirho: &PropagationWorldChirho, seq_chirho: u64) {
    world_chirho.record_chirho(seq_chirho, BTreeMap::new(), false);
    world_chirho
        .store_chirho
        .record_binding_chirho(
            &subject_chirho(),
            seq_chirho,
            &record_digest_chirho(seq_chirho),
        )
        .expect("requirement binds");
}

/// The attempt the store holds now for the requirement bound to `record_digest`, under the world's view.
fn attempt_for_record_chirho(
    world_chirho: &PropagationWorldChirho,
    record_digest_chirho: &str,
) -> Result<ErasureAttemptChirho, LeaderRefusalChirho> {
    let joined_chirho = join_mirror_view_chirho(
        &world_chirho.placement_chirho,
        world_chirho.leader_view_chirho.as_ref(),
    )
    .expect("the world's view joins");
    world_chirho.store_chirho.erasure_attempt_chirho(
        &subject_chirho(),
        record_digest_chirho,
        joined_chirho.view_chirho(),
    )
}

fn attempt_now_chirho(
    world_chirho: &PropagationWorldChirho,
    seq_chirho: u64,
) -> ErasureAttemptChirho {
    attempt_for_record_chirho(world_chirho, &record_digest_chirho(seq_chirho))
        .expect("the attempt reads")
}

/// Every directory, and every file's bytes, under `dir`, so an arm can show a refusal changed nothing.
fn tree_chirho(dir_chirho: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
    let mut tree_chirho = BTreeMap::new();
    let mut stack_chirho = vec![dir_chirho.to_path_buf()];
    while let Some(next_chirho) = stack_chirho.pop() {
        for entry_chirho in fs::read_dir(&next_chirho).expect("a readable directory") {
            let path_chirho = entry_chirho.expect("a readable entry").path();
            if fs::symlink_metadata(&path_chirho)
                .expect("an entry's metadata")
                .is_dir()
            {
                tree_chirho.insert(path_chirho.clone(), None);
                stack_chirho.push(path_chirho);
            } else {
                let bytes_chirho = fs::read(&path_chirho).expect("a readable file");
                tree_chirho.insert(path_chirho, Some(bytes_chirho));
            }
        }
    }
    tree_chirho
}

/// Retry `identity` and expect a refusal by the store: it names `case` on every failure, sends nothing, and
/// changes no file under the world's directory.
fn assert_refuses_unchanged_chirho(
    world_chirho: &PropagationWorldChirho,
    case_chirho: &str,
    identity_chirho: &ErasureAttemptIdentityChirho,
    expected_chirho: LeaderRefusalIdentityChirho,
) {
    let world_dir_chirho = world_chirho
        .leader_root_chirho
        .parent()
        .expect("the world's directory")
        .to_path_buf();
    let before_chirho = tree_chirho(&world_dir_chirho);
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let refused_chirho = match world_chirho.retry_chirho(
        identity_chirho,
        &recording_chirho,
        ErasurePropagationPolicyChirho::default(),
    ) {
        Ok(_) => panic!("the {case_chirho} case must refuse"),
        Err(error_chirho) => error_chirho.leader_identity_chirho().unwrap_or_else(|| {
            panic!("the {case_chirho} case refused outside the store: {error_chirho}")
        }),
    };
    assert_eq!(
        refused_chirho, expected_chirho,
        "the {case_chirho} case refuses by its own name"
    );
    assert!(
        recording_chirho.holders_chirho().is_empty(),
        "the {case_chirho} case sends nothing"
    );
    assert!(
        tree_chirho(&world_dir_chirho) == before_chirho,
        "the {case_chirho} case changes no file"
    );
}

#[test]
fn an_attempt_names_the_requirement_and_record_it_was_read_from_and_its_stored_status_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    let attempt_chirho = attempt_now_chirho(&world_chirho, 0);
    let view_chirho = world_chirho
        .store_chirho
        .subject_view_chirho(&subject_chirho())
        .unwrap();
    assert_eq!(
        attempt_chirho.identity_chirho(),
        &ErasureAttemptIdentityChirho {
            consistency_group_digest_chirho: world_chirho.group_chirho(),
            tenant_id_chirho: TENANT_CHIRHO.to_string(),
            genesis_instance_id_chirho: INSTANCE_CHIRHO.to_string(),
            subject_digest_chirho: subject_chirho(),
            erasure_record_digest_chirho: record_digest_chirho(0),
            requirement_digest_chirho: view_chirho.entries_chirho()[0]
                .0
                .requirement_digest_chirho()
                .to_string(),
        },
        "the identity is the store's context and the requirement's own coordinates"
    );
    let holders_chirho = world_chirho.holder_ids_chirho();
    let holders_chirho = holders_chirho
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        attempt_chirho.status_chirho(),
        &pending_chirho(&holders_chirho),
        "before any send, every stored holder is pending"
    );
    assert!(
        !attempt_chirho.is_complete_chirho(),
        "nothing is complete before any send"
    );
    let report_chirho = world_chirho
        .propagate_chirho(
            0,
            &world_chirho.seam_chirho(),
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        report_chirho.attempt_chirho.identity_chirho(),
        attempt_chirho.identity_chirho(),
        "the engine's report carries the attempt of the requirement it propagated"
    );
    assert!(
        report_chirho.attempt_chirho.is_complete_chirho(),
        "the report's attempt is read after the sends"
    );
    assert_eq!(
        attempt_now_chirho(&world_chirho, 0),
        report_chirho.attempt_chirho,
        "the report's attempt is the store's"
    );
}

#[test]
fn a_retry_by_identity_alone_reaches_only_the_open_holders_and_returns_a_fresh_snapshot_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    let down_chirho = world_chirho.peer_b_chirho.id_chirho().to_string();
    let mut origins_chirho = world_chirho.peer_origins_chirho.clone();
    origins_chirho.insert(down_chirho.clone(), dead_origin_chirho());
    let first_chirho = world_chirho
        .propagate_chirho(
            0,
            &world_chirho.seam_with_chirho(origins_chirho),
            ErasurePropagationPolicyChirho {
                attempts_per_holder_chirho: 1,
                ..ErasurePropagationPolicyChirho::default()
            },
        )
        .unwrap();
    assert_eq!(
        first_chirho.attempt_chirho.status_chirho(),
        &pending_chirho(&[&down_chirho]),
        "the first call's attempt is read after its sends: only the unreachable holder stays pending"
    );
    // The identity is all a caller keeps, through JSON and back.
    let kept_chirho = serde_json::to_string(first_chirho.attempt_chirho.identity_chirho()).unwrap();
    let identity_chirho: ErasureAttemptIdentityChirho = serde_json::from_str(&kept_chirho).unwrap();
    let seam_chirho = world_chirho.seam_chirho();
    let recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    let retried_chirho = world_chirho
        .retry_chirho(
            &identity_chirho,
            &recording_chirho,
            ErasurePropagationPolicyChirho::default(),
        )
        .unwrap();
    assert_eq!(
        recording_chirho.holders_chirho(),
        vec![down_chirho],
        "only the holder still open gets a frame"
    );
    assert_eq!(
        retried_chirho.identity_chirho(),
        &identity_chirho,
        "the retry returns the identity it was handed"
    );
    assert_eq!(
        retried_chirho.status_chirho(),
        &ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho,
        "the snapshot is read afresh after the send, never carried from the start of the call"
    );
    assert_eq!(
        retried_chirho,
        attempt_now_chirho(&world_chirho, 0),
        "the retry's attempt is the store's"
    );
}

#[test]
fn every_wrong_coordinate_refuses_by_name_sends_nothing_and_changes_nothing_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    record_bound_chirho(&world_chirho, 1);
    let good_chirho = attempt_now_chirho(&world_chirho, 0)
        .identity_chirho()
        .clone();
    let other_chirho = attempt_now_chirho(&world_chirho, 1)
        .identity_chirho()
        .clone();
    let cases_chirho = [
        (
            "group",
            ErasureAttemptIdentityChirho {
                consistency_group_digest_chirho: "cd".repeat(32),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptContextMismatchChirho,
        ),
        (
            "tenant",
            ErasureAttemptIdentityChirho {
                tenant_id_chirho: "another-tenant-chirho".to_string(),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptContextMismatchChirho,
        ),
        (
            "genesis instance",
            ErasureAttemptIdentityChirho {
                genesis_instance_id_chirho: "another-instance-chirho".to_string(),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptContextMismatchChirho,
        ),
        (
            "another subject",
            ErasureAttemptIdentityChirho {
                subject_digest_chirho: subject_digest_hex_chirho("another-subject-chirho"),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho,
        ),
        (
            "subject that is not a digest",
            ErasureAttemptIdentityChirho {
                subject_digest_chirho: "not-a-digest-chirho".to_string(),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho,
        ),
        (
            "record",
            ErasureAttemptIdentityChirho {
                erasure_record_digest_chirho: record_digest_chirho(7),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptRecordMismatchChirho,
        ),
        (
            "requirement",
            ErasureAttemptIdentityChirho {
                requirement_digest_chirho: "ef".repeat(32),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho,
        ),
        (
            "another requirement under this record",
            ErasureAttemptIdentityChirho {
                requirement_digest_chirho: other_chirho.requirement_digest_chirho.clone(),
                ..good_chirho.clone()
            },
            LeaderRefusalIdentityChirho::ErasureAttemptRecordMismatchChirho,
        ),
    ];
    for (case_chirho, identity_chirho, expected_chirho) in cases_chirho {
        assert_refuses_unchanged_chirho(
            &world_chirho,
            case_chirho,
            &identity_chirho,
            expected_chirho,
        );
    }
    let attempt_chirho = world_chirho
        .retry_chirho(
            &good_chirho,
            &world_chirho.seam_chirho(),
            ErasurePropagationPolicyChirho::default(),
        )
        .expect("the good identity still retries after every refusal");
    assert!(
        attempt_chirho.is_complete_chirho(),
        "the good identity's retry closes every holder"
    );
}

#[test]
fn a_carried_requirement_refuses_by_its_own_name_and_a_pending_one_as_unbound_chirho() {
    let world_chirho = propagation_world_chirho();
    world_chirho.record_chirho(0, BTreeMap::new(), false);
    world_chirho.record_chirho(
        1,
        BTreeMap::from([(0, EarlierErasureChirho::NeverRecordedChirho)]),
        false,
    );
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 1, &record_digest_chirho(1))
        .unwrap();
    let view_chirho = world_chirho
        .store_chirho
        .subject_view_chirho(&subject_chirho())
        .unwrap();
    let (carried_chirho, standing_chirho) = &view_chirho.entries_chirho()[0];
    assert_eq!(
        standing_chirho,
        &RequirementStandingChirho::CarriedByChirho {
            bound_seq_chirho: 1
        },
        "the fixture's seq 0 is carried by the bound seq 1"
    );
    let carrier_chirho = attempt_now_chirho(&world_chirho, 1)
        .identity_chirho()
        .clone();
    assert_refuses_unchanged_chirho(
        &world_chirho,
        "carried",
        &ErasureAttemptIdentityChirho {
            requirement_digest_chirho: carried_chirho.requirement_digest_chirho().to_string(),
            ..carrier_chirho
        },
        LeaderRefusalIdentityChirho::ErasureAttemptCarriedChirho,
    );

    let pending_world_chirho = propagation_world_chirho();
    pending_world_chirho.record_chirho(0, BTreeMap::new(), false);
    let pending_view_chirho = pending_world_chirho
        .store_chirho
        .subject_view_chirho(&subject_chirho())
        .unwrap();
    let (pending_chirho, standing_chirho) = &pending_view_chirho.entries_chirho()[0];
    assert_eq!(
        standing_chirho,
        &RequirementStandingChirho::PendingChirho,
        "the fixture's seq 0 is pending: unbound and carried by nothing"
    );
    assert_refuses_unchanged_chirho(
        &pending_world_chirho,
        "pending",
        &ErasureAttemptIdentityChirho {
            consistency_group_digest_chirho: pending_world_chirho.group_chirho(),
            tenant_id_chirho: TENANT_CHIRHO.to_string(),
            genesis_instance_id_chirho: INSTANCE_CHIRHO.to_string(),
            subject_digest_chirho: subject_chirho(),
            erasure_record_digest_chirho: record_digest_chirho(0),
            requirement_digest_chirho: pending_chirho.requirement_digest_chirho().to_string(),
        },
        LeaderRefusalIdentityChirho::ErasurePropagationRequirementUnboundChirho,
    );
}

#[test]
fn an_identity_round_trips_through_json_and_carries_no_status_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    let identity_chirho = attempt_now_chirho(&world_chirho, 0)
        .identity_chirho()
        .clone();
    let json_chirho = serde_json::to_value(&identity_chirho).unwrap();
    assert_eq!(
        serde_json::from_value::<ErasureAttemptIdentityChirho>(json_chirho.clone()).unwrap(),
        identity_chirho
    );
    let mut with_status_chirho = json_chirho;
    with_status_chirho["status_chirho"] =
        serde_json::json!("ErasureConfirmedByHolderReceiptsChirho");
    assert!(
        serde_json::from_value::<ErasureAttemptIdentityChirho>(with_status_chirho).is_err(),
        "an identity refuses a status field: a caller hands back coordinates, never a status"
    );
}

#[test]
fn a_pending_attempt_names_no_holder_in_its_debug_form_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    let attempt_chirho = attempt_now_chirho(&world_chirho, 0);
    let holders_chirho = world_chirho.holder_ids_chirho();
    // The control: inside the crate the status names every pending holder, so the needles are real.
    let status_shown_chirho = format!("{:?}", attempt_chirho.status_chirho());
    assert!(
        holders_chirho
            .iter()
            .all(|holder_chirho| status_shown_chirho.contains(holder_chirho)),
        "the pending status names every holder inside the crate"
    );
    let shown_chirho = format!("{attempt_chirho:?}");
    assert!(
        shown_chirho.contains(&attempt_chirho.identity_chirho().requirement_digest_chirho),
        "the debug form shows the identity"
    );
    for holder_chirho in &holders_chirho {
        assert!(
            !shown_chirho.contains(holder_chirho),
            "the debug form names no holder"
        );
    }
    assert!(
        shown_chirho.contains("complete_chirho: false"),
        "the debug form shows whether the attempt is complete"
    );
}

#[test]
fn the_attempt_read_refuses_a_record_no_binding_names_and_one_named_twice_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    assert_eq!(
        leader_refusal_chirho(attempt_for_record_chirho(
            &world_chirho,
            &record_digest_chirho(9)
        )),
        LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho,
        "a record no binding names is unknown"
    );
    // The world's own helper binds every seq to one fixed digest, which a root never does.
    world_chirho.record_chirho(1, BTreeMap::new(), true);
    world_chirho.record_chirho(2, BTreeMap::new(), true);
    assert_eq!(
        leader_refusal_chirho(attempt_for_record_chirho(&world_chirho, &"ab".repeat(32))),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho,
        "two bindings naming one record is state the store never writes"
    );
}

#[test]
fn a_requirement_replaced_during_a_retry_is_never_reported_under_the_old_identity_chirho() {
    let world_chirho = propagation_world_chirho();
    record_bound_chirho(&world_chirho, 0);
    let identity_chirho = attempt_now_chirho(&world_chirho, 0)
        .identity_chirho()
        .clone();
    let subject_chirho = subject_chirho();
    let subject_dir_chirho = world_chirho
        .leader_root_chirho
        .join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO)
        .join(&subject_chirho[..2])
        .join(&subject_chirho);
    let seam_chirho = world_chirho.seam_chirho();
    let mut recording_chirho = RecordingSeamChirho::passing_chirho(&seam_chirho);
    recording_chirho.after_chirho = Box::new(|index_chirho| {
        if index_chirho != 0 {
            return;
        }
        // Out of band, mid-call: the subject's files are replaced by another requirement at the same seq,
        // bound to the SAME record digest, so only the requirement digest tells them apart.
        fs::remove_dir_all(&subject_dir_chirho).unwrap();
        world_chirho
            .store_chirho
            .record_requirement_chirho(&RecordRequirementRequestChirho {
                subject_digest_chirho: subject_chirho.clone(),
                erasure_seq_chirho: 0,
                erased_below_blob_seq_chirho: BOUND_CHIRHO,
                key_ids_chirho: [key_id_chirho(3)].into(),
                holders_chirho: world_chirho.holder_ids_chirho(),
                earlier_chirho: BTreeMap::new(),
            })
            .unwrap();
        world_chirho
            .store_chirho
            .record_binding_chirho(&subject_chirho, 0, &record_digest_chirho(0))
            .unwrap();
    });
    let refused_chirho = world_chirho.retry_chirho(
        &identity_chirho,
        &recording_chirho,
        ErasurePropagationPolicyChirho::default(),
    );
    assert_eq!(
        leader_refusal_chirho(refused_chirho),
        LeaderRefusalIdentityChirho::ErasureAttemptUnknownChirho,
        "the replaced requirement is never reported under the old identity"
    );
    assert!(
        !recording_chirho.holders_chirho().is_empty(),
        "this refusal comes from the read-back after a delivery, not from the up-front checks"
    );
    assert_ne!(
        attempt_now_chirho(&world_chirho, 0).identity_chirho(),
        &identity_chirho,
        "the store now holds another requirement under the same record"
    );
}
