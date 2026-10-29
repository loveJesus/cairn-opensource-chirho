// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! gpt #29353: state an earlier attempt left visible may not be durable, so every retry passes its directory barrier before the next side effect or receipt, and a failing barrier refuses instead of signing.

use super::custody_tests_chirho::refusal_name_chirho;
use super::world_chirho::{key_id_chirho, world_chirho, WorldChirho, SUBJECT_CHIRHO};
use crate::barrier_chirho::test_hooks_chirho::{
    clear_failing_chirho, fail_syncs_of_chirho, take_events_chirho, EventKindChirho,
};
use crate::holder_chirho::KeyCustodyHolderChirho;
use cairn_key_custody_chirho::subject_digest_hex_chirho;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

fn custody_wire_chirho(
    world_chirho: &WorldChirho,
    holder_chirho: &KeyCustodyHolderChirho,
    number_chirho: u8,
    blob_seq_chirho: u64,
) -> Vec<u8> {
    world_chirho
        .custody_frame_chirho(
            holder_chirho,
            &key_id_chirho(number_chirho),
            SUBJECT_CHIRHO,
            blob_seq_chirho,
            number_chirho,
            &world_chirho.leader_chirho,
        )
        .to_wire_bytes_chirho()
        .unwrap()
}

fn erasure_wire_chirho(world_chirho: &WorldChirho, listed_chirho: &[u8]) -> (Vec<u8>, String) {
    let listed_chirho = listed_chirho
        .iter()
        .map(|number_chirho| key_id_chirho(*number_chirho))
        .collect::<Vec<_>>();
    let frame_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        5,
        &listed_chirho,
        &world_chirho.leader_chirho,
    );
    (
        frame_chirho.to_wire_bytes_chirho().unwrap(),
        frame_chirho.frame_digest_chirho().to_string(),
    )
}

fn terms_dir_chirho(world_chirho: &WorldChirho) -> PathBuf {
    world_chirho.holder_dir_chirho.join("terms-chirho")
}

fn tombstone_dir_chirho(world_chirho: &WorldChirho) -> PathBuf {
    let digest_chirho = subject_digest_hex_chirho(SUBJECT_CHIRHO);
    world_chirho
        .holder_dir_chirho
        .join("tombstones-chirho")
        .join(&digest_chirho[..2])
}

fn record_dir_chirho(world_chirho: &WorldChirho, frame_digest_chirho: &str) -> PathBuf {
    world_chirho
        .holder_dir_chirho
        .join("erasures-chirho")
        .join(&frame_digest_chirho[..2])
}

/// The position of the first event of `kind_chirho` on `path_chirho`, if any.
fn position_chirho(
    events_chirho: &[(EventKindChirho, PathBuf)],
    kind_chirho: EventKindChirho,
    path_chirho: &Path,
) -> Option<usize> {
    events_chirho
        .iter()
        .position(|(event_kind_chirho, event_path_chirho)| {
            *event_kind_chirho == kind_chirho && event_path_chirho == path_chirho
        })
}

fn first_unlink_chirho(events_chirho: &[(EventKindChirho, PathBuf)]) -> Option<usize> {
    events_chirho
        .iter()
        .position(|(kind_chirho, _)| *kind_chirho == EventKindChirho::UnlinkChirho)
}

/// Pin (a): the unlinks happened but their directory sync failed. A retry finds nothing left to
/// remove, yet must still sync before it signs, and while the sync keeps failing it signs nothing.
#[test]
fn an_erasure_retry_with_nothing_left_still_syncs_before_its_receipt_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1))
        .unwrap();
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    let (wire_chirho, _) = erasure_wire_chirho(&world_chirho, &[1]);
    fail_syncs_of_chirho(&subject_dir_chirho);
    take_events_chirho();
    assert_eq!(
        refusal_name_chirho(holder_chirho.admit_erasure_chirho(&wire_chirho)),
        "HolderStoreWriteFailedChirho"
    );
    let events_chirho = take_events_chirho();
    let last_unlink_chirho = events_chirho
        .iter()
        .rposition(|(kind_chirho, _)| *kind_chirho == EventKindChirho::UnlinkChirho)
        .expect("the first attempt unlinked the key");
    assert!(
        events_chirho[last_unlink_chirho..]
            .iter()
            .any(|(kind_chirho, path_chirho)| {
                *kind_chirho == EventKindChirho::SyncChirho && path_chirho == &subject_dir_chirho
            }),
        "the subject directory sync was not attempted after the unlinks"
    );
    assert!(!world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
        .exists());
    // Control: the sync still fails, and nothing is left to remove, so no shortcut may sign.
    assert_eq!(
        refusal_name_chirho(holder_chirho.admit_erasure_chirho(&wire_chirho)),
        "HolderStoreWriteFailedChirho"
    );
    clear_failing_chirho();
    take_events_chirho();
    holder_chirho
        .admit_erasure_chirho(&wire_chirho)
        .expect("the retry signs once the directory is durable");
    let events_chirho = take_events_chirho();
    assert!(first_unlink_chirho(&events_chirho).is_none());
    assert!(
        position_chirho(
            &events_chirho,
            EventKindChirho::SyncChirho,
            &subject_dir_chirho
        )
        .is_some(),
        "the retry signed without syncing the subject directory"
    );
}

/// Pin (b), term: a retry at a term equal to the stored high-water passes the term directory's
/// barrier before its first write, and refuses with nothing written when the barrier fails.
#[test]
fn an_equal_term_passes_its_barrier_before_any_write_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1))
        .unwrap();
    let terms_dir_chirho = terms_dir_chirho(&world_chirho);
    fail_syncs_of_chirho(&terms_dir_chirho);
    assert_eq!(
        refusal_name_chirho(holder_chirho.admit_custody_chirho(&custody_wire_chirho(
            &world_chirho,
            &holder_chirho,
            2,
            2
        ))),
        "HolderStoreWriteFailedChirho"
    );
    assert!(!world_chirho
        .binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2))
        .exists());
    clear_failing_chirho();
    take_events_chirho();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 2, 2))
        .unwrap();
    let events_chirho = take_events_chirho();
    let barrier_chirho = position_chirho(
        &events_chirho,
        EventKindChirho::SyncChirho,
        &terms_dir_chirho,
    )
    .expect("the equal-term barrier ran");
    let write_chirho = position_chirho(
        &events_chirho,
        EventKindChirho::WriteChirho,
        &world_chirho.binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2)),
    )
    .expect("the binding was written");
    assert!(barrier_chirho < write_chirho, "{events_chirho:?}");
}

/// Pin (b), tombstones and record: an erasure retry whose tombstones and record already exist passes
/// both directory barriers before any unlink, and refuses with every key still present when either
/// barrier fails.
#[test]
fn an_erasure_retry_syncs_its_tombstones_and_record_before_any_unlink_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1))
        .unwrap();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 2, 2))
        .unwrap();
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    let (wire_chirho, frame_digest_chirho) = erasure_wire_chirho(&world_chirho, &[1]);
    // The first attempt stores tombstones and the record, then cannot unlink.
    let mode_chirho = fs::metadata(&subject_dir_chirho)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    fs::set_permissions(&subject_dir_chirho, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        fs::write(subject_dir_chirho.join("probe-chirho"), b"x").is_err(),
        "the directory is still writable (running as root?)"
    );
    assert_eq!(
        refusal_name_chirho(holder_chirho.admit_erasure_chirho(&wire_chirho)),
        "HolderStoreWriteFailedChirho"
    );
    fs::set_permissions(&subject_dir_chirho, fs::Permissions::from_mode(mode_chirho)).unwrap();
    for failing_chirho in [
        tombstone_dir_chirho(&world_chirho),
        record_dir_chirho(&world_chirho, &frame_digest_chirho),
    ] {
        fail_syncs_of_chirho(&failing_chirho);
        assert_eq!(
            refusal_name_chirho(holder_chirho.admit_erasure_chirho(&wire_chirho)),
            "HolderStoreWriteFailedChirho",
            "{failing_chirho:?}"
        );
        assert!(
            world_chirho
                .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
                .exists(),
            "a key was unlinked past a failed barrier"
        );
        clear_failing_chirho();
    }
    take_events_chirho();
    holder_chirho.admit_erasure_chirho(&wire_chirho).unwrap();
    let events_chirho = take_events_chirho();
    let first_unlink_chirho = first_unlink_chirho(&events_chirho).expect("the retry unlinked");
    for barrier_dir_chirho in [
        tombstone_dir_chirho(&world_chirho),
        record_dir_chirho(&world_chirho, &frame_digest_chirho),
    ] {
        let barrier_chirho = position_chirho(
            &events_chirho,
            EventKindChirho::SyncChirho,
            &barrier_dir_chirho,
        )
        .expect("the barrier ran");
        assert!(barrier_chirho < first_unlink_chirho, "{events_chirho:?}");
    }
}

/// Pin (b), custody: an exact retry whose binding and key already match writes nothing, but passes the
/// subject directory's barrier before its receipt, and signs nothing while that barrier fails.
#[test]
fn a_matching_custody_retry_syncs_before_its_receipt_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let wire_chirho = custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1);
    let first_chirho = holder_chirho.admit_custody_chirho(&wire_chirho).unwrap();
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    fail_syncs_of_chirho(&subject_dir_chirho);
    assert_eq!(
        refusal_name_chirho(holder_chirho.admit_custody_chirho(&wire_chirho)),
        "HolderStoreWriteFailedChirho"
    );
    clear_failing_chirho();
    take_events_chirho();
    assert_eq!(
        holder_chirho.admit_custody_chirho(&wire_chirho).unwrap(),
        first_chirho
    );
    let events_chirho = take_events_chirho();
    assert!(!events_chirho
        .iter()
        .any(|(kind_chirho, _)| *kind_chirho == EventKindChirho::WriteChirho));
    assert!(
        position_chirho(
            &events_chirho,
            EventKindChirho::SyncChirho,
            &subject_dir_chirho
        )
        .is_some(),
        "the matching retry signed without syncing the subject directory"
    );
}

/// Pin (c): a reopened holder syncs the parent of every directory it finds already present, because the
/// process that created it may have died before that sync; a failing sync refuses the open.
#[test]
fn a_reopened_holder_syncs_existing_directories_before_using_them_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    holder_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1))
        .unwrap();
    drop(holder_chirho);
    let holder_parent_chirho = world_chirho
        .holder_dir_chirho
        .parent()
        .unwrap()
        .to_path_buf();
    fail_syncs_of_chirho(&holder_parent_chirho);
    let refused_chirho = crate::holder_chirho::KeyCustodyHolderChirho::open_chirho(
        world_chirho.holder_config_chirho(world_chirho.holder_chirho.id_chirho()),
    );
    assert_eq!(
        refused_chirho
            .err()
            .map(|error_chirho| error_chirho.wire_identity_chirho()),
        Some("HolderStoreUnreadableChirho".to_string())
    );
    clear_failing_chirho();
    let reopened_chirho = world_chirho.open_holder_chirho();
    take_events_chirho();
    reopened_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &reopened_chirho, 2, 2))
        .unwrap();
    let events_chirho = take_events_chirho();
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    let write_chirho = position_chirho(
        &events_chirho,
        EventKindChirho::WriteChirho,
        &world_chirho.binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2)),
    )
    .expect("the binding was written");
    // Each existing ancestor's parent is synced before the first write under it.
    let mut ancestor_chirho = subject_dir_chirho.as_path();
    while ancestor_chirho != world_chirho.holder_dir_chirho {
        let parent_chirho = ancestor_chirho.parent().unwrap();
        let synced_chirho =
            position_chirho(&events_chirho, EventKindChirho::SyncChirho, parent_chirho)
                .unwrap_or_else(|| panic!("{parent_chirho:?} was not synced: {events_chirho:?}"));
        assert!(synced_chirho < write_chirho, "{events_chirho:?}");
        ancestor_chirho = parent_chirho;
    }
    // Once made durable, an ancestor is not synced again by the same holder.
    take_events_chirho();
    reopened_chirho
        .admit_custody_chirho(&custody_wire_chirho(&world_chirho, &reopened_chirho, 3, 3))
        .unwrap();
    let again_chirho = take_events_chirho();
    assert!(
        position_chirho(
            &again_chirho,
            EventKindChirho::SyncChirho,
            &world_chirho.holder_dir_chirho
        )
        .is_none(),
        "{again_chirho:?}"
    );
}

/// Distinct subjects whose digests all share one two-hex shard.
fn subjects_in_one_shard_chirho(count_chirho: usize) -> Vec<String> {
    let shard_chirho = subject_digest_hex_chirho("app/contact-chirho/shard/0")[..2].to_string();
    let mut subjects_chirho = Vec::new();
    let mut number_chirho = 0_u32;
    while subjects_chirho.len() < count_chirho {
        let subject_chirho = format!("app/contact-chirho/shard/{number_chirho}");
        if subject_digest_hex_chirho(&subject_chirho)[..2] == shard_chirho {
            subjects_chirho.push(subject_chirho);
        }
        number_chirho += 1;
    }
    subjects_chirho
}

/// gpt #29372: what the holder remembers as synced is bounded by construction (the family directories and
/// their shards), so it does not grow with subjects, and a subject's own directory is never remembered:
/// a later write under an existing subject still syncs that subject's shard.
#[test]
fn the_sync_record_stays_bounded_and_subject_leaves_always_sync_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let subjects_chirho = subjects_in_one_shard_chirho(20);
    for (index_chirho, subject_chirho) in subjects_chirho.iter().enumerate() {
        let number_chirho = u8::try_from(index_chirho + 10).unwrap();
        let frame_chirho = world_chirho.custody_frame_chirho(
            &holder_chirho,
            &key_id_chirho(number_chirho),
            subject_chirho,
            1,
            number_chirho,
            &world_chirho.leader_chirho,
        );
        holder_chirho
            .admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
            .unwrap();
    }
    assert_eq!(
        holder_chirho.remembered_directory_count_chirho(),
        3,
        "terms-chirho, keys-chirho and the one shard, whatever the number of subjects"
    );
    let subject_chirho = &subjects_chirho[0];
    let shard_dir_chirho = world_chirho
        .holder_dir_chirho
        .join("keys-chirho")
        .join(&subject_digest_hex_chirho(subject_chirho)[..2]);
    take_events_chirho();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(200),
        subject_chirho,
        2,
        200,
        &world_chirho.leader_chirho,
    );
    holder_chirho
        .admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        .unwrap();
    let events_chirho = take_events_chirho();
    assert!(
        position_chirho(
            &events_chirho,
            EventKindChirho::SyncChirho,
            &shard_dir_chirho
        )
        .is_some(),
        "a write under an existing subject did not sync its shard: {events_chirho:?}"
    );
    assert_eq!(holder_chirho.remembered_directory_count_chirho(), 3);
}

/// agy #29374: a reopened holder's retry that writes nothing still makes the whole directory chain durable
/// before it signs: each ancestor's entry in its parent, then the subject directory itself.
#[test]
fn a_reopened_holders_no_write_retry_syncs_the_whole_chain_before_its_receipt_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let wire_chirho = custody_wire_chirho(&world_chirho, &holder_chirho, 1, 1);
    let first_chirho = holder_chirho.admit_custody_chirho(&wire_chirho).unwrap();
    drop(holder_chirho);
    let reopened_chirho = world_chirho.open_holder_chirho();
    take_events_chirho();
    assert_eq!(
        reopened_chirho.admit_custody_chirho(&wire_chirho).unwrap(),
        first_chirho
    );
    let events_chirho = take_events_chirho();
    assert!(
        !events_chirho
            .iter()
            .any(|(kind_chirho, _)| *kind_chirho == EventKindChirho::WriteChirho),
        "{events_chirho:?}"
    );
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    let mut dir_chirho = subject_dir_chirho.as_path();
    loop {
        let parent_chirho = dir_chirho.parent().unwrap();
        assert!(
            position_chirho(&events_chirho, EventKindChirho::SyncChirho, parent_chirho).is_some(),
            "{parent_chirho:?} was not synced: {events_chirho:?}"
        );
        if parent_chirho == world_chirho.holder_dir_chirho {
            break;
        }
        dir_chirho = parent_chirho;
    }
    assert!(
        position_chirho(
            &events_chirho,
            EventKindChirho::SyncChirho,
            &subject_dir_chirho
        )
        .is_some(),
        "{events_chirho:?}"
    );
}
