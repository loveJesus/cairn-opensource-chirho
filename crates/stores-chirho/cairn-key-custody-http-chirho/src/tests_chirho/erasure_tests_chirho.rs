// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Erasure admission: the frame's tombstones are durable before anything is removed, the removal is fixed in a record before any unlink, and only the frame's own subject directory is touched.

use super::custody_tests_chirho::refusal_name_chirho;
use super::world_chirho::{
    key_id_chirho, world_chirho, WorldChirho, FIRST_TERM_CHIRHO, OTHER_SUBJECT_CHIRHO,
    SUBJECT_CHIRHO,
};
use crate::holder_chirho::KeyCustodyHolderChirho;
use cairn_key_custody_chirho::decode_and_verify_erasure_receipt_chirho;
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn store_key_chirho(
    world_chirho: &WorldChirho,
    holder_chirho: &KeyCustodyHolderChirho,
    number_chirho: u8,
    subject_chirho: &str,
    blob_seq_chirho: u64,
) {
    let frame_chirho = world_chirho.custody_frame_chirho(
        holder_chirho,
        &key_id_chirho(number_chirho),
        subject_chirho,
        blob_seq_chirho,
        number_chirho,
        &world_chirho.leader_chirho,
    );
    holder_chirho
        .admit_custody_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
        .expect("the key is stored");
}

fn erase_chirho(
    world_chirho: &WorldChirho,
    holder_chirho: &KeyCustodyHolderChirho,
    bound_chirho: u64,
    listed_chirho: &[u8],
) -> Result<Vec<u8>, crate::refusal_chirho::HolderRefusalChirho> {
    let listed_chirho = listed_chirho
        .iter()
        .map(|number_chirho| key_id_chirho(*number_chirho))
        .collect::<Vec<_>>();
    let frame_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        bound_chirho,
        &listed_chirho,
        &world_chirho.leader_chirho,
    );
    holder_chirho.admit_erasure_chirho(&frame_chirho.to_wire_bytes_chirho().unwrap())
}

/// The receipt's three lists, read from its wire JSON.
fn receipt_lists_chirho(wire_chirho: &[u8]) -> [BTreeSet<String>; 3] {
    decode_and_verify_erasure_receipt_chirho(wire_chirho).expect("the receipt verifies");
    let value_chirho: serde_json::Value = serde_json::from_slice(wire_chirho).unwrap();
    [
        "removed_key_ids_chirho",
        "already_absent_key_ids_chirho",
        "removed_by_subject_key_ids_chirho",
    ]
    .map(|field_chirho| {
        value_chirho[field_chirho]
            .as_array()
            .unwrap()
            .iter()
            .map(|id_chirho| id_chirho.as_str().unwrap().to_string())
            .collect()
    })
}

fn ids_chirho(numbers_chirho: &[u8]) -> BTreeSet<String> {
    numbers_chirho
        .iter()
        .map(|number_chirho| key_id_chirho(*number_chirho))
        .collect()
}

/// Run the closure with `dir_chirho` at `mode_chirho`, then restore its mode. The injection must take
/// effect, so a run as root fails loudly here instead of passing without it.
fn with_dir_mode_chirho<TChirho>(
    dir_chirho: &Path,
    mode_chirho: u32,
    run_chirho: impl FnOnce() -> TChirho,
) -> TChirho {
    let original_chirho = fs::metadata(dir_chirho).unwrap().permissions().mode() & 0o7777;
    fs::set_permissions(dir_chirho, fs::Permissions::from_mode(mode_chirho)).unwrap();
    assert!(
        fs::write(dir_chirho.join("probe-chirho"), b"x").is_err(),
        "the directory is still writable (running as root?)"
    );
    if mode_chirho & 0o400 == 0 {
        assert!(
            fs::read_dir(dir_chirho).is_err(),
            "the directory is still readable (running as root?)"
        );
    }
    let result_chirho = run_chirho();
    fs::set_permissions(dir_chirho, fs::Permissions::from_mode(original_chirho)).unwrap();
    result_chirho
}

#[test]
fn an_erasure_splits_the_listed_keys_and_removes_the_subject_rule_keys_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 1, SUBJECT_CHIRHO, 1);
    store_key_chirho(&world_chirho, &holder_chirho, 2, SUBJECT_CHIRHO, 2);
    store_key_chirho(&world_chirho, &holder_chirho, 3, SUBJECT_CHIRHO, 9);
    store_key_chirho(&world_chirho, &holder_chirho, 4, OTHER_SUBJECT_CHIRHO, 1);
    let wire_chirho = erase_chirho(&world_chirho, &holder_chirho, 5, &[1, 5]).unwrap();
    let [removed_chirho, absent_chirho, by_subject_chirho] = receipt_lists_chirho(&wire_chirho);
    assert_eq!(removed_chirho, ids_chirho(&[1]));
    assert_eq!(absent_chirho, ids_chirho(&[5]));
    assert_eq!(by_subject_chirho, ids_chirho(&[2]));
    for (number_chirho, kept_chirho) in [(1, false), (2, false), (3, true)] {
        let key_chirho = key_id_chirho(number_chirho);
        assert_eq!(
            world_chirho
                .key_path_chirho(SUBJECT_CHIRHO, &key_chirho)
                .exists(),
            kept_chirho
        );
        assert_eq!(
            world_chirho
                .binding_path_chirho(SUBJECT_CHIRHO, &key_chirho)
                .exists(),
            kept_chirho
        );
    }
    assert!(world_chirho
        .key_path_chirho(OTHER_SUBJECT_CHIRHO, &key_id_chirho(4))
        .exists());
}

/// agy pin B2-C: a listed id stored under another subject is reported absent and survives, because an
/// erasure scans and removes only its own subject's directory.
#[test]
fn an_erasure_touches_only_its_own_subjects_directory_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 4, OTHER_SUBJECT_CHIRHO, 1);
    let wire_chirho = erase_chirho(&world_chirho, &holder_chirho, 1, &[4]).unwrap();
    let [removed_chirho, absent_chirho, _] = receipt_lists_chirho(&wire_chirho);
    assert!(removed_chirho.is_empty());
    assert_eq!(absent_chirho, ids_chirho(&[4]));
    assert!(world_chirho
        .key_path_chirho(OTHER_SUBJECT_CHIRHO, &key_id_chirho(4))
        .exists());
}

/// The frame's tombstones are durable before any removal: when the removal fails, a key the frame
/// covers is already refused, and a retry finishes the erasure.
#[test]
fn the_tombstones_are_durable_before_any_key_is_removed_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 1, SUBJECT_CHIRHO, 1);
    store_key_chirho(&world_chirho, &holder_chirho, 2, SUBJECT_CHIRHO, 2);
    let subject_dir_chirho = world_chirho.subject_dir_chirho(SUBJECT_CHIRHO);
    let refused_chirho = with_dir_mode_chirho(&subject_dir_chirho, 0o500, || {
        let refusal_chirho =
            refusal_name_chirho(erase_chirho(&world_chirho, &holder_chirho, 5, &[1]));
        let late_chirho = world_chirho.custody_frame_chirho(
            &holder_chirho,
            &key_id_chirho(3),
            SUBJECT_CHIRHO,
            3,
            0x33,
            &world_chirho.leader_chirho,
        );
        let late_refusal_chirho = refusal_name_chirho(
            holder_chirho.admit_custody_chirho(&late_chirho.to_wire_bytes_chirho().unwrap()),
        );
        (refusal_chirho, late_refusal_chirho)
    });
    assert_eq!(refused_chirho.0, "HolderStoreWriteFailedChirho");
    assert_eq!(
        refused_chirho.1, "CustodySubjectAlreadyErasedChirho",
        "the tombstone was not durable before the removal"
    );
    assert!(world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
        .exists());
    let wire_chirho = erase_chirho(&world_chirho, &holder_chirho, 5, &[1]).unwrap();
    let [removed_chirho, _, by_subject_chirho] = receipt_lists_chirho(&wire_chirho);
    assert_eq!(removed_chirho, ids_chirho(&[1]));
    assert_eq!(by_subject_chirho, ids_chirho(&[2]));
    assert!(!world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
        .exists());
}

/// agy pin B2-A: the keys are gone but the receipt was never signed; the retry still reports the
/// subject-rule key, from the record fixed before the unlink, not from a new scan.
#[test]
fn a_retry_after_the_removal_reports_the_same_keys_from_its_record_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 1, SUBJECT_CHIRHO, 1);
    store_key_chirho(&world_chirho, &holder_chirho, 2, SUBJECT_CHIRHO, 2);
    let refusal_chirho = with_dir_mode_chirho(&world_chirho.sign_root_chirho, 0o000, || {
        refusal_name_chirho(erase_chirho(&world_chirho, &holder_chirho, 5, &[1]))
    });
    assert_eq!(refusal_chirho, "HolderSignerUnavailableChirho");
    assert!(!world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2))
        .exists());
    let wire_chirho = erase_chirho(&world_chirho, &holder_chirho, 5, &[1]).unwrap();
    let [removed_chirho, absent_chirho, by_subject_chirho] = receipt_lists_chirho(&wire_chirho);
    assert_eq!(removed_chirho, ids_chirho(&[1]));
    assert!(absent_chirho.is_empty());
    assert_eq!(by_subject_chirho, ids_chirho(&[2]));
}

#[test]
fn an_exact_erasure_replay_answers_the_same_receipt_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 1, SUBJECT_CHIRHO, 1);
    let frame_chirho = world_chirho.erasure_frame_chirho(
        SUBJECT_CHIRHO,
        5,
        &[key_id_chirho(1)],
        &world_chirho.leader_chirho,
    );
    let wire_chirho = frame_chirho.to_wire_bytes_chirho().unwrap();
    let first_chirho = holder_chirho.admit_erasure_chirho(&wire_chirho).unwrap();
    assert_eq!(
        holder_chirho.admit_erasure_chirho(&wire_chirho).unwrap(),
        first_chirho
    );
}

/// agy pin B2-B: a key whose binding cannot be read is tombstoned by id and removed, and the receipt is
/// refused, so a delayed custody frame cannot bring it back and the share stays pending.
#[test]
fn a_key_with_an_unreadable_binding_is_tombstoned_removed_and_left_pending_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 6, SUBJECT_CHIRHO, 9);
    let binding_path_chirho = world_chirho.binding_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(6));
    fs::write(&binding_path_chirho, b"not a binding").unwrap();
    assert_eq!(
        refusal_name_chirho(erase_chirho(&world_chirho, &holder_chirho, 5, &[])),
        "HolderErasureBindingUnverifiableChirho"
    );
    assert!(!world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(6))
        .exists());
    assert!(!binding_path_chirho.exists());
    let delayed_chirho = world_chirho.custody_frame_chirho(
        &holder_chirho,
        &key_id_chirho(6),
        SUBJECT_CHIRHO,
        9,
        6,
        &world_chirho.leader_chirho,
    );
    assert_eq!(
        refusal_name_chirho(
            holder_chirho.admit_custody_chirho(&delayed_chirho.to_wire_bytes_chirho().unwrap())
        ),
        "CustodySubjectAlreadyErasedChirho"
    );
    store_key_chirho(&world_chirho, &holder_chirho, 8, SUBJECT_CHIRHO, 9);
}

/// A key file's stranded temp may hold the key's bytes, so it is the key's to remove.
#[test]
fn a_stranded_temp_of_an_erased_key_is_removed_with_it_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 2, SUBJECT_CHIRHO, 2);
    let key_path_chirho = world_chirho.key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2));
    let temp_path_chirho = world_chirho
        .subject_dir_chirho(SUBJECT_CHIRHO)
        .join(format!(".{}.key.json.tmp-chirho-1-1", key_id_chirho(2)));
    fs::rename(&key_path_chirho, &temp_path_chirho).unwrap();
    let wire_chirho = erase_chirho(&world_chirho, &holder_chirho, 5, &[]).unwrap();
    let [_, _, by_subject_chirho] = receipt_lists_chirho(&wire_chirho);
    assert_eq!(by_subject_chirho, ids_chirho(&[2]));
    assert!(!temp_path_chirho.exists());
}

#[test]
fn an_unknown_entry_refuses_the_erasure_before_any_key_is_removed_chirho() {
    let world_chirho = world_chirho();
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 2, SUBJECT_CHIRHO, 2);
    fs::write(
        world_chirho
            .subject_dir_chirho(SUBJECT_CHIRHO)
            .join("notes.txt"),
        b"not the holder's",
    )
    .unwrap();
    assert_eq!(
        refusal_name_chirho(erase_chirho(&world_chirho, &holder_chirho, 5, &[])),
        "HolderStoreUnreadableChirho"
    );
    assert!(world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(2))
        .exists());
}

#[test]
fn an_erasure_below_the_term_high_water_refuses_after_restart_chirho() {
    let world_chirho = world_chirho();
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO + 1);
    let holder_chirho = world_chirho.open_holder_chirho();
    store_key_chirho(&world_chirho, &holder_chirho, 1, SUBJECT_CHIRHO, 1);
    drop(holder_chirho);
    world_chirho.set_term_chirho(FIRST_TERM_CHIRHO);
    let reopened_chirho = world_chirho.open_holder_chirho();
    assert_eq!(
        refusal_name_chirho(erase_chirho(&world_chirho, &reopened_chirho, 5, &[1])),
        "HolderStaleTermChirho"
    );
    assert!(world_chirho
        .key_path_chirho(SUBJECT_CHIRHO, &key_id_chirho(1))
        .exists());
}
