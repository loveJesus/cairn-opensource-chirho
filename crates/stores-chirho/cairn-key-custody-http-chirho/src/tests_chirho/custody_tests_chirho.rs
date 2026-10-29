// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Custody admission: the leader's key is stored privately beside its binding and receipted, and replays, conflicts, stale terms, non-leaders, tombstones and a key without its binding each refuse by name.

use super::world_chirho::{
    key_id_chirho, mode_chirho, record_chirho, world_chirho, FIRST_TERM_CHIRHO,
    OTHER_SUBJECT_CHIRHO, SUBJECT_CHIRHO,
};
use crate::refusal_chirho::HolderRefusalChirho;
use cairn_key_custody_chirho::decode_and_verify_custody_receipt_chirho;
use std::fs;
use std::os::unix::fs::PermissionsExt;

pub(super) fn refusal_name_chirho(result_chirho: Result<Vec<u8>, HolderRefusalChirho>) -> String {
    match result_chirho {
        Err(refusal_chirho) => refusal_chirho.wire_identity_chirho(),
        Ok(_) => panic!("the admission must refuse, but it answered a signed receipt"),
    }
}

#[test]
fn a_leaders_custody_frame_is_stored_privately_and_receipted_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.leader_chirho,
    );
    let wire_chirho = holder_chirho
        .admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        .expect("the leader's frame is admitted");
    let receipt_chirho = decode_and_verify_custody_receipt_chirho(&wire_chirho).unwrap();
    assert_eq!(
        receipt_chirho.custody_frame_digest_chirho(),
        frame_chirho.frame_digest_chirho()
    );
    assert_eq!(
        receipt_chirho.binding_chirho(),
        frame_chirho.binding_chirho()
    );
    let key_path_chirho = world_chirho.key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1));
    let binding_path_chirho = world_chirho.binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1));
    assert_eq!(
        fs::read(&key_path_chirho).unwrap(),
        record_chirho(SUBJECT_CHIRHO, 0x11)
            .to_key_file_bytes_chirho()
            .unwrap()
            .as_slice(),
        "the holder stores the root's own key-file bytes"
    );
    assert_eq!(mode_chirho(&key_path_chirho), 0o600);
    assert_eq!(mode_chirho(&binding_path_chirho), 0o600);
    assert_eq!(
        mode_chirho(&world_chirho.subject_dir_chirho(SUBJECT_CHIRHO)),
        0o700
    );
    assert_eq!(mode_chirho(&world_chirho.holder_dir_chirho), 0o700);
}

/// agy pin B2-C: a retry may change only the term, view or lease; a different key or blob seq under the
/// same key id refuses and leaves the stored key as it was.
#[test]
fn a_replay_answers_the_same_receipt_and_a_changed_key_refuses_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let admit_chirho = |key_id_chirho: &str, blob_seq_chirho: u64, fill_chirho: u8| {
        let frame_chirho = world_chirho.custody_frame_chirho(
            &holder_chirho,
            key_id_chirho,
            SUBJECT_CHIRHO,
            blob_seq_chirho,
            fill_chirho,
            &world_chirho.leader_chirho,
        );
        holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
    };
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.leader_chirho,
    );
    let wire_chirho = frame_chirho.to_wire_bytes_chirho().unwrap();
    let first_chirho = holder_chirho.admit_custody_chirho(&wire_chirho).unwrap();
    assert_eq!(
        holder_chirho.admit_custody_chirho(&wire_chirho).unwrap(),
        first_chirho,
        "an exact replay answers the same receipt"
    );
    assert_eq!(
        refusal_name_chirho(admit_chirho(&key_id_chirho(1), 3, 0x22)),
        "HolderCustodyConflictChirho",
        "other key bytes under a stored key id"
    );
    assert_eq!(
        refusal_name_chirho(admit_chirho(&key_id_chirho(1), 4, 0x11)),
        "HolderCustodyConflictChirho",
        "another blob seq under a stored key id"
    );
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO + 1);
    let retried_chirho =
        admit_chirho(&key_id_chirho(1), 3, 0x11).expect("a retry under a new term");
    assert_eq!(
        decode_and_verify_custody_receipt_chirho(&retried_chirho)
            .unwrap()
            .binding_chirho()
            .elected_term_chirho,
        FIRST_TERM_CHIRHO + 1
    );
    assert_eq!(
        fs::read(world_chirho.key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))).unwrap(),
        record_chirho(SUBJECT_CHIRHO, 0x11)
            .to_key_file_bytes_chirho()
            .unwrap()
            .as_slice()
    );
}

/// gpt #29211 (1): a frame that authenticates but is not from the current leader moves nothing, so it
/// cannot raise the term high-water and block the real leader.
#[test]
fn a_frame_from_a_non_leader_refuses_and_moves_nothing_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.peer_chirho,
    );
    let name_chirho = refusal_name_chirho(
        holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap()),
    );
    assert!(
        name_chirho.starts_with("CustodyAuthorityRefusedChirho"),
        "{name_chirho}"
    );
    assert!(!world_chirho.holder_dir_chirho.join("terms-chirho").exists());
    assert!(!world_chirho.holder_dir_chirho.join("keys-chirho").exists());
}

/// #29219 (1): the high-water is durable before the side effect, so a crash after it and before the key
/// still keeps a lower term out after a restart, even for another subject.
#[test]
fn a_crash_after_the_high_water_keeps_a_lower_term_out_after_restart_chirho() {
    let world_chirho = world_chirho();
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO + 1);
    let holder_chirho = world_chirho.open_holder_chirho();
    // A file where the key directory goes: the first touch of the key's path, reading its binding,
    // fails after the high-water is raised and before anything is written.
    let blocker_chirho = world_chirho.holder_dir_chirho.join("keys-chirho");
    fs::write(&blocker_chirho, b"a file where the key directory goes").unwrap();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        refusal_name_chirho(
            holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        ),
        "HolderStoreUnreadableChirho"
    );
    fs::remove_file(&blocker_chirho).unwrap();
    drop(holder_chirho);
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO);
    let reopened_chirho = world_chirho.open_holder_chirho();
    let stale_chirho = world_chirho.custody_frame_chirho(
        &reopened_chirho,
        &key_id_chirho(2),
        OTHER_SUBJECT_CHIRHO,
        3,
        0x22,
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        refusal_name_chirho(
            reopened_chirho.admit_custody_chirho(&stale_chirho.to_wire_bytes_chirho().unwrap())
        ),
        "HolderStaleTermChirho"
    );
    assert!(!world_chirho
        .subject_dir_chirho(OTHER_SUBJECT_CHIRHO)
        .exists());
    // Control: back at the high-water's term, the same key is admitted.
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO + 1);
    let current_chirho = world_chirho.custody_frame_chirho(
        &reopened_chirho,
        &key_id_chirho(2),
        OTHER_SUBJECT_CHIRHO,
        3,
        0x22,
        &world_chirho.leader_chirho,
    );
    reopened_chirho
        .admit_custody_chirho(&current_chirho.to_wire_bytes_chirho().unwrap())
        .expect("a frame at the high-water's term is admitted");
}

#[test]
fn a_key_an_erasure_covers_is_refused_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let erasure_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(7)],
        &world_chirho.leader_chirho,
    );
    holder_chirho
        .admit_erasure_chirho(&erasure_chirho.to_wire_bytes_chirho().unwrap())
        .expect("the erasure is admitted");
    let admit_chirho = |key_id_chirho: &str, blob_seq_chirho: u64| {
        let frame_chirho = world_chirho.custody_frame_chirho(
            &holder_chirho,
            key_id_chirho,
            SUBJECT_CHIRHO,
            blob_seq_chirho,
            0x33,
            &world_chirho.leader_chirho,
        );
        holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
    };
    assert_eq!(
        refusal_name_chirho(admit_chirho(&key_id_chirho(2), 3)),
        "CustodySubjectAlreadyErasedChirho",
        "below the bound"
    );
    assert_eq!(
        refusal_name_chirho(admit_chirho(&key_id_chirho(7), 9)),
        "CustodySubjectAlreadyErasedChirho",
        "a listed id above the bound"
    );
    admit_chirho(&key_id_chirho(3), 9).expect("an unlisted key above the bound is admitted");
}

#[test]
fn a_key_stored_without_its_binding_refuses_custody_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let other_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(9),
        SUBJECT_CHIRHO,
        1,
        0x99,
        &world_chirho.leader_chirho,
    );
    holder_chirho
        .admit_custody_chirho(&other_chirho.to_wire_bytes_chirho().unwrap())
        .expect("another key makes the subject directory");
    let key_path_chirho = world_chirho.key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1));
    fs::write(&key_path_chirho, b"{}").unwrap();
    fs::set_permissions(&key_path_chirho, fs::Permissions::from_mode(0o600)).unwrap();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        refusal_name_chirho(
            holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        ),
        "HolderKeyWithoutBindingChirho"
    );
    assert_eq!(fs::read(&key_path_chirho).unwrap(), b"{}");
}

/// agy pin B2-B, the order half: a binding that cannot be read refuses before the key is written, so a
/// key never lands without a binding beside it.
#[test]
fn a_custody_that_cannot_read_its_binding_never_writes_the_key_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    let other_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(9),
        SUBJECT_CHIRHO,
        1,
        0x99,
        &world_chirho.leader_chirho,
    );
    holder_chirho
        .admit_custody_chirho(&other_chirho.to_wire_bytes_chirho().unwrap())
        .unwrap();
    fs::create_dir(world_chirho.binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))).unwrap();
    let frame_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(1),
        SUBJECT_CHIRHO,
        3,
        0x11,
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        refusal_name_chirho(
            holder_chirho.admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        ),
        "HolderStoreUnreadableChirho"
    );
    assert!(!world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
        .exists());
}

#[test]
fn the_holder_refuses_to_open_on_another_nodes_key_chirho() {
    let world_chirho = world_chirho();
    let wrong_chirho = crate::holder_chirho::KeyCustodyHolderChirho::open_chirho(
        world_chirho.holder_config_chirho(world_chirho.peer_chirho.id_chirho()),
    );
    assert_eq!(
        wrong_chirho
            .err()
            .map(|error_chirho| error_chirho.wire_identity_chirho()),
        Some("HolderSignerUnavailableChirho".to_string())
    );
    assert!(
        !world_chirho.holder_dir_chirho.exists(),
        "a refused open made state"
    );
}
