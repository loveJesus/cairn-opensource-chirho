// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Guards the construction rule of the HARNESS-1 two-root world: a second node is made by
//! PUBLISHING a second root, never by copying the first one.
//!
//! `harness1_gd7_world_chirho`'s header states that copy-and-re-key refuses. That is a claim in the
//! record and a future seat will read it as settled, so it is executable here rather than only
//! written down.

use super::harness1_gd7_world_chirho::{
    publish_tenant_regenesis_root_chirho, v4_ledger_config_chirho,
};
use cairn_ledger_host_chirho::open_resident_effect_journal_handle_chirho;
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use cairn_writer_head_chirho::writer_head_chirho::consistency_group_for_root_chirho;
use std::path::Path;

fn copy_tree_chirho(from_chirho: &Path, to_chirho: &Path) {
    std::fs::create_dir_all(to_chirho).unwrap();
    for entry_chirho in std::fs::read_dir(from_chirho).unwrap() {
        let entry_chirho = entry_chirho.unwrap();
        let target_chirho = to_chirho.join(entry_chirho.file_name());
        let file_type_chirho = entry_chirho.file_type().unwrap();
        if file_type_chirho.is_dir() {
            copy_tree_chirho(&entry_chirho.path(), &target_chirho);
        } else if file_type_chirho.is_file() {
            std::fs::copy(entry_chirho.path(), &target_chirho).unwrap();
        }
    }
}

/// A copied published root is not a second node; a second PUBLISH is — and both halves are proven.
///
/// The republished root is the POSITIVE CONTROL, and it is what makes the two refusals mean
/// anything. Without it, "the copy was refused" is equally consistent with "the opener rejects any
/// root at an unfamiliar path", which would not make copying wrong — it would make the whole
/// two-root world impossible. The control excludes that world.
///
/// # MIGRATION PATH
///
/// If the two copy arms start PASSING, copy-and-re-key has become admissible: that is a real change
/// in the engine, not a test bug — retarget this arm and rewrite the "not copied" section of
/// `harness1_gd7_world_chirho`'s header, because the header's stated reason for publishing twice
/// will have stopped being true. If the CONTROL starts failing, the two-root world itself is broken
/// and every HARNESS-1 arm above rung 1 rests on it; fix that before reading anything else here.
#[test]
fn a_copied_root_is_refused_while_a_republished_second_root_is_admitted_chirho() {
    let mut held_fixture_chirho = super::fixture_chirho();
    let mut second_fixture_chirho = super::fixture_chirho();
    let held_root_chirho = publish_tenant_regenesis_root_chirho(&mut held_fixture_chirho);
    let second_root_chirho = publish_tenant_regenesis_root_chirho(&mut second_fixture_chirho);
    let held_config_chirho = v4_ledger_config_chirho(&held_fixture_chirho.config_path_chirho);
    let second_config_chirho = v4_ledger_config_chirho(&second_fixture_chirho.config_path_chirho);

    // The tenant marker is what puts two roots at two paths into one group. If this ever stops
    // holding, the refusals below would be about tenancy rather than about copying.
    let held_group_chirho = consistency_group_for_root_chirho(&held_root_chirho).unwrap();
    assert_eq!(
        held_group_chirho,
        consistency_group_for_root_chirho(&second_root_chirho).unwrap(),
        "two published tenant roots must share one consistency group"
    );

    let copied_root_chirho = held_root_chirho
        .parent()
        .unwrap()
        .join("harness1-copied-root-chirho");
    let _ = std::fs::remove_dir_all(&copied_root_chirho);
    copy_tree_chirho(&held_root_chirho, &copied_root_chirho);
    let copied_root_chirho = copied_root_chirho.canonicalize().unwrap();
    let copied_config_chirho = copied_root_chirho.join("cairn-regenesis-config-chirho.toml");
    assert_eq!(
        consistency_group_for_root_chirho(&copied_root_chirho).unwrap(),
        held_group_chirho,
        "the copy carries the marker, so group membership is NOT what refuses it below"
    );
    // Rule out the boring explanation before reading the refusals as meaningful: the copy really
    // does carry a readable, byte-identical config at its own path, so nothing below refuses merely
    // because the config is missing.
    assert_eq!(
        std::fs::read(&copied_config_chirho).unwrap(),
        std::fs::read(&held_fixture_chirho.config_path_chirho).unwrap(),
        "the copied root carries its own copy of the config"
    );

    assert!(
        open_resident_effect_journal_handle_chirho(
            &copied_root_chirho,
            &copied_config_chirho,
            &held_config_chirho,
            None,
        )
        .is_err(),
        "a copied root still carrying the original node's key must not open as a second node"
    );

    let before_chirho = existing_keypair_pubkey_hex_chirho(&copied_root_chirho).unwrap();
    std::fs::remove_file(copied_root_chirho.join("signing-key-chirho.bin")).unwrap();
    sign_message_chirho(&copied_root_chirho, b"harness1 two-root arm re-key").unwrap();
    assert_ne!(
        before_chirho,
        existing_keypair_pubkey_hex_chirho(&copied_root_chirho).unwrap(),
        "re-keying must actually change the node identity, or the arm below proves nothing new"
    );
    assert!(
        open_resident_effect_journal_handle_chirho(
            &copied_root_chirho,
            &copied_config_chirho,
            &held_config_chirho,
            None,
        )
        .is_err(),
        "re-keying a copy does not repair the root-bound artifacts the copy inherited"
    );

    // POSITIVE CONTROL — the same opener, a different path, a genuinely published root.
    let control_chirho = open_resident_effect_journal_handle_chirho(
        &second_root_chirho,
        &second_fixture_chirho.config_path_chirho,
        &second_config_chirho,
        None,
    );
    assert!(
        control_chirho.is_ok(),
        "a republished second root at its own path must open: {:?}",
        control_chirho.err()
    );
    drop(control_chirho);

    let _ = std::fs::remove_dir_all(&copied_root_chirho);
}
