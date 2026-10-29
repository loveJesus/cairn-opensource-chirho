// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader's propagation store (C5 B3-a2): durable signed requirements, exact retries that keep their cut, recorded attempts bound and never carried, never-recorded ones carried once, every file verified where it sits, and bounds that refuse rather than omit.

use super::world_chirho::{key_id_chirho, SUBJECT_CHIRHO};
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasurePropagationStoreChirho, RecordRequirementRequestChirho,
    RequirementStandingChirho, ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO,
    ERASURE_PROPAGATION_STORE_DIR_CHIRHO, SUBJECT_SCAN_MAX_ENTRIES_CHIRHO,
};
use cairn_key_custody_chirho::{
    subject_digest_hex_chirho, ErasurePropagationContextChirho, KeyCustodyRefusalIdentityChirho,
    ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO,
};
use cairn_seqlog_chirho::seqlog_chirho::with_named_lock_chirho;
use cairn_signer_chirho::control_plane_signer_chirho::CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO;
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const TENANT_CHIRHO: &str = "item6-drill-chirho";
const INSTANCE_CHIRHO: &str = "genesis-instance-one-chirho";

struct LeaderWorldChirho {
    _dir_chirho: tempfile::TempDir,
    root_chirho: PathBuf,
    context_chirho: ErasurePropagationContextChirho,
    store_chirho: ErasurePropagationStoreChirho,
}

impl LeaderWorldChirho {
    fn subject_dir_chirho(&self) -> PathBuf {
        let subject_chirho = subject_chirho();
        self.root_chirho
            .join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO)
            .join(&subject_chirho[..2])
            .join(&subject_chirho)
    }

    fn reopened_chirho(&self) -> ErasurePropagationStoreChirho {
        ErasurePropagationStoreChirho::open_chirho(&self.root_chirho, self.context_chirho.clone())
            .expect("store reopens")
    }

    fn record_chirho(&self, request_chirho: &RecordRequirementRequestChirho) {
        self.store_chirho
            .record_requirement_chirho(request_chirho)
            .expect("requirement records");
    }

    fn standings_chirho(&self) -> BTreeMap<u64, RequirementStandingChirho> {
        self.store_chirho
            .subject_view_chirho(&subject_chirho())
            .expect("view loads")
            .entries_chirho()
            .iter()
            .map(|(requirement_chirho, standing_chirho)| {
                (
                    requirement_chirho.erasure_seq_chirho(),
                    standing_chirho.clone(),
                )
            })
            .collect()
    }
}

/// A synthetic root whose node key exists, and a store whose issuer is that key.
fn leader_world_chirho() -> LeaderWorldChirho {
    let dir_chirho = tempfile::tempdir().expect("temp dir");
    let root_chirho = dir_chirho.path().join("root-chirho");
    fs::create_dir(&root_chirho).expect("root");
    sign_message_chirho(&root_chirho, b"provision the leader's node key").expect("node key");
    let issuer_chirho = existing_keypair_pubkey_hex_chirho(&root_chirho).expect("issuer");
    let context_chirho = context_for_chirho(&issuer_chirho);
    let store_chirho =
        ErasurePropagationStoreChirho::open_chirho(&root_chirho, context_chirho.clone())
            .expect("store opens");
    LeaderWorldChirho {
        _dir_chirho: dir_chirho,
        root_chirho,
        context_chirho,
        store_chirho,
    }
}

fn context_for_chirho(issuer_chirho: &str) -> ErasurePropagationContextChirho {
    ErasurePropagationContextChirho::new_chirho(
        &"11".repeat(32),
        TENANT_CHIRHO,
        INSTANCE_CHIRHO,
        issuer_chirho,
    )
    .expect("context in form")
}

fn subject_chirho() -> String {
    subject_digest_hex_chirho(SUBJECT_CHIRHO)
}

fn holder_chirho(number_chirho: u8) -> String {
    format!("{number_chirho:064x}")
}

fn record_digest_chirho(fill_chirho: u8) -> String {
    format!("{fill_chirho:02x}").repeat(32)
}

fn request_chirho(
    seq_chirho: u64,
    keys_chirho: &[u8],
    holders_chirho: &[u8],
    bound_chirho: u64,
    earlier_chirho: &[(u64, EarlierErasureChirho)],
) -> RecordRequirementRequestChirho {
    RecordRequirementRequestChirho {
        subject_digest_chirho: subject_chirho(),
        erasure_seq_chirho: seq_chirho,
        erased_below_blob_seq_chirho: bound_chirho,
        key_ids_chirho: keys_chirho
            .iter()
            .map(|number_chirho| key_id_chirho(*number_chirho))
            .collect(),
        holders_chirho: holders_chirho
            .iter()
            .map(|number_chirho| holder_chirho(*number_chirho))
            .collect(),
        earlier_chirho: earlier_chirho.iter().cloned().collect(),
    }
}

fn never_recorded_chirho(seq_chirho: u64) -> (u64, EarlierErasureChirho) {
    (seq_chirho, EarlierErasureChirho::NeverRecordedChirho)
}

fn recorded_chirho(seq_chirho: u64, fill_chirho: u8) -> (u64, EarlierErasureChirho) {
    (
        seq_chirho,
        EarlierErasureChirho::RecordedChirho {
            erasure_record_digest_chirho: record_digest_chirho(fill_chirho),
        },
    )
}

fn leader_refusal_chirho<TChirho>(
    result_chirho: Result<TChirho, LeaderRefusalChirho>,
) -> LeaderRefusalIdentityChirho {
    match result_chirho {
        Ok(_) => panic!("expected a store refusal"),
        Err(error_chirho) => error_chirho
            .leader_identity_chirho()
            .unwrap_or_else(|| panic!("expected a store refusal, got {error_chirho}")),
    }
}

fn contract_refusal_chirho<TChirho>(
    result_chirho: Result<TChirho, LeaderRefusalChirho>,
) -> KeyCustodyRefusalIdentityChirho {
    match result_chirho {
        Ok(_) => panic!("expected a contract refusal"),
        Err(error_chirho) => error_chirho
            .contract_error_chirho()
            .unwrap_or_else(|| panic!("expected a contract refusal, got {error_chirho}"))
            .identity_chirho(),
    }
}

#[test]
fn a_recorded_requirement_is_durable_signed_and_then_bound_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(3, &[1, 2], &[1, 2], 9, &[]));
    assert_eq!(
        world_chirho.standings_chirho()[&3],
        RequirementStandingChirho::PendingChirho
    );
    let requirement_path_chirho = world_chirho.subject_dir_chirho().join("3.requirement.json");
    let mode_chirho = fs::metadata(&requirement_path_chirho)
        .expect("file")
        .permissions()
        .mode();
    assert_eq!(mode_chirho & 0o777, 0o600, "requirements are private");

    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(0xab))
        .expect("binds");
    match &world_chirho.standings_chirho()[&3] {
        RequirementStandingChirho::BoundChirho(binding_chirho) => {
            assert_eq!(
                binding_chirho.erasure_record_digest_chirho(),
                record_digest_chirho(0xab)
            )
        }
        other_chirho => panic!("expected bound, got {other_chirho:?}"),
    }
    let reopened_chirho = world_chirho.reopened_chirho();
    assert_eq!(
        reopened_chirho
            .subject_view_chirho(&subject_chirho())
            .expect("view"),
        world_chirho
            .store_chirho
            .subject_view_chirho(&subject_chirho())
            .expect("view"),
        "a reopened store reads the same verified state"
    );
}

#[test]
fn an_exact_retry_keeps_the_stored_cut_even_when_a_new_key_appeared_chirho() {
    // gpt #29838's step 4, at the store: the retry reuses the old cut, which lacks K2.
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(3, &[1, 2], &[1], 9, &[]));
    let bytes_before_chirho =
        fs::read(world_chirho.subject_dir_chirho().join("3.requirement.json")).unwrap();
    let retried_chirho = world_chirho
        .store_chirho
        .record_requirement_chirho(&request_chirho(3, &[1, 2, 9], &[1, 2], 12, &[]))
        .expect("an exact retry answers");
    assert_eq!(
        retried_chirho.key_ids_chirho(),
        &[key_id_chirho(1), key_id_chirho(2)]
    );
    assert_eq!(retried_chirho.erased_below_blob_seq_chirho(), 9);
    assert_eq!(
        fs::read(world_chirho.subject_dir_chirho().join("3.requirement.json")).unwrap(),
        bytes_before_chirho,
        "the stored requirement is never rewritten"
    );
}

#[test]
fn a_bound_seq_is_not_an_in_flight_retry_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(3, &[1], &[1], 9, &[]));
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(1))
        .expect("binds");
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho(3, &[1], &[1], 9, &[]))
        ),
        LeaderRefusalIdentityChirho::ErasureRequirementSeqAlreadyBoundChirho
    );
}

#[test]
fn a_store_ahead_of_the_root_log_refuses_as_rollback_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(5, &[1], &[1], 9, &[]));
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho(3, &[1], &[1], 9, &[]))
        ),
        LeaderRefusalIdentityChirho::ErasureRequirementSeqRollbackRefusedChirho
    );
    // A binding with no requirement of its own is the same out-of-step state.
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 5, &record_digest_chirho(1))
        .expect("binds");
    fs::copy(
        world_chirho.subject_dir_chirho().join("5.binding.json"),
        world_chirho.subject_dir_chirho().join("4.binding.json"),
    )
    .unwrap();
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho())
        ),
        LeaderRefusalIdentityChirho::ErasureRequirementSeqRollbackRefusedChirho
    );
}

#[test]
fn agys_sequence_carries_the_never_recorded_attempt_and_its_holders_chirho() {
    // S1's attempt at 1 crashed before its record; another subject took 1; S1 now erases at 2.
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    let carried_chirho = world_chirho
        .store_chirho
        .record_requirement_chirho(&request_chirho(
            2,
            &[2],
            &[2],
            6,
            &[never_recorded_chirho(1)],
        ))
        .expect("the successor records");
    assert_eq!(
        carried_chirho.key_ids_chirho(),
        &[key_id_chirho(1), key_id_chirho(2)]
    );
    assert_eq!(
        carried_chirho.holders_chirho(),
        &[holder_chirho(1), holder_chirho(2)]
    );
    assert_eq!(carried_chirho.succeeds_chirho().len(), 1);
    assert_eq!(carried_chirho.succeeds_chirho()[0].erasure_seq_chirho, 1);
    assert_eq!(
        world_chirho.standings_chirho()[&1],
        RequirementStandingChirho::PendingChirho
    );
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 2, &record_digest_chirho(2))
        .expect("binds");
    assert_eq!(
        world_chirho.standings_chirho()[&1],
        RequirementStandingChirho::CarriedByChirho {
            bound_seq_chirho: 2
        }
    );
}

#[test]
fn a_recorded_but_unbound_attempt_is_bound_and_never_carried_chirho() {
    // gpt #29788 point 2: the crash came after the record's append and before its binding.
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    let next_chirho = world_chirho
        .store_chirho
        .record_requirement_chirho(&request_chirho(
            4,
            &[2],
            &[2],
            6,
            &[recorded_chirho(1, 0x11)],
        ))
        .expect("the next erasure records");
    assert!(
        next_chirho.succeeds_chirho().is_empty(),
        "a recorded attempt is never carried"
    );
    assert_eq!(
        next_chirho.key_ids_chirho(),
        &[key_id_chirho(2)],
        "the cut is not widened"
    );
    match &world_chirho.standings_chirho()[&1] {
        RequirementStandingChirho::BoundChirho(binding_chirho) => {
            assert_eq!(
                binding_chirho.erasure_record_digest_chirho(),
                record_digest_chirho(0x11)
            )
        }
        other_chirho => panic!("expected the late binding, got {other_chirho:?}"),
    }
    assert_eq!(
        world_chirho.standings_chirho()[&4],
        RequirementStandingChirho::PendingChirho
    );
}

#[test]
fn the_roots_evidence_must_name_exactly_the_unbound_earlier_seqs_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    for earlier_chirho in [
        vec![],
        vec![never_recorded_chirho(1), never_recorded_chirho(2)],
    ] {
        assert_eq!(
            leader_refusal_chirho(
                world_chirho
                    .store_chirho
                    .record_requirement_chirho(&request_chirho(3, &[2], &[2], 6, &earlier_chirho))
            ),
            LeaderRefusalIdentityChirho::ErasureRequirementEvidenceStaleChirho
        );
    }
    world_chirho.record_chirho(&request_chirho(
        3,
        &[2],
        &[2],
        6,
        &[never_recorded_chirho(1)],
    ));
}

#[test]
fn a_predecessor_a_bound_successor_carries_is_not_carried_again_chirho() {
    // agy #29781: once 2 carried 1 and is bound, a later erasure at 5 does not carry 1 again. 2 stays its
    // own term, so 1 is still owed through it (gpt #29788).
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    world_chirho.record_chirho(&request_chirho(
        2,
        &[2],
        &[2],
        6,
        &[never_recorded_chirho(1)],
    ));
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 2, &record_digest_chirho(2))
        .expect("binds");
    let later_chirho = world_chirho
        .store_chirho
        .record_requirement_chirho(&request_chirho(
            5,
            &[3],
            &[3],
            8,
            &[never_recorded_chirho(1)],
        ))
        .expect("the later erasure records");
    assert!(later_chirho.succeeds_chirho().is_empty());
    let standings_chirho = world_chirho.standings_chirho();
    assert_eq!(
        standings_chirho[&1],
        RequirementStandingChirho::CarriedByChirho {
            bound_seq_chirho: 2
        }
    );
    assert_eq!(
        standings_chirho[&5],
        RequirementStandingChirho::PendingChirho
    );
}

#[test]
fn a_carried_requirement_is_never_bound_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    world_chirho.record_chirho(&request_chirho(
        2,
        &[2],
        &[2],
        6,
        &[never_recorded_chirho(1)],
    ));
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_binding_chirho(
            &subject_chirho(),
            1,
            &record_digest_chirho(1)
        )),
        LeaderRefusalIdentityChirho::ErasureRequirementAlreadySucceededChirho
    );
}

#[test]
fn a_binding_replays_equal_or_refuses_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(3, &[1], &[1], 9, &[]));
    let first_chirho = world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(1))
        .expect("binds");
    let replay_chirho = world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(1))
        .expect("an equal replay answers");
    assert_eq!(first_chirho, replay_chirho);
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_binding_chirho(
            &subject_chirho(),
            3,
            &record_digest_chirho(2)
        )),
        LeaderRefusalIdentityChirho::ErasureRequirementBindingConflictChirho
    );
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_binding_chirho(
            &subject_chirho(),
            7,
            &record_digest_chirho(1)
        )),
        LeaderRefusalIdentityChirho::ErasureRequirementMissingChirho
    );
}

#[test]
fn a_tampered_moved_or_missing_file_refuses_the_whole_subject_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    world_chirho.record_chirho(&request_chirho(
        2,
        &[2],
        &[2],
        6,
        &[never_recorded_chirho(1)],
    ));
    let dir_chirho = world_chirho.subject_dir_chirho();
    let subject_chirho = subject_chirho();

    // A requirement copied to another seq is not where it sits.
    fs::copy(
        dir_chirho.join("2.requirement.json"),
        dir_chirho.join("3.requirement.json"),
    )
    .unwrap();
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho
    );
    fs::remove_file(dir_chirho.join("3.requirement.json")).unwrap();

    // A changed field breaks its digest.
    let original_chirho = fs::read_to_string(dir_chirho.join("2.requirement.json")).unwrap();
    let tampered_chirho = original_chirho.replacen(
        "\"erased_below_blob_seq_chirho\":6",
        "\"erased_below_blob_seq_chirho\":5",
        1,
    );
    assert_ne!(tampered_chirho, original_chirho, "the tamper applied");
    fs::write(dir_chirho.join("2.requirement.json"), &tampered_chirho).unwrap();
    assert_eq!(
        contract_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho
    );
    fs::write(dir_chirho.join("2.requirement.json"), &original_chirho).unwrap();

    // A carried requirement that is gone would shrink coverage: refuse, never omit.
    let carried_bytes_chirho = fs::read(dir_chirho.join("1.requirement.json")).unwrap();
    fs::remove_file(dir_chirho.join("1.requirement.json")).unwrap();
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        LeaderRefusalIdentityChirho::ErasureRequirementCarriedMissingChirho
    );
    fs::write(dir_chirho.join("1.requirement.json"), &carried_bytes_chirho).unwrap();
    world_chirho
        .store_chirho
        .subject_view_chirho(&subject_chirho)
        .expect("restored");

    // A binding that names another requirement.
    // 1 and 2 are both unbound here, so the evidence names both, and 4 carries them.
    world_chirho.record_chirho(&request_chirho(
        4,
        &[3],
        &[3],
        8,
        &[never_recorded_chirho(1), never_recorded_chirho(2)],
    ));
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho, 4, &record_digest_chirho(4))
        .expect("binds");
    fs::copy(
        dir_chirho.join("4.binding.json"),
        dir_chirho.join("2.binding.json"),
    )
    .unwrap();
    assert_eq!(
        contract_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationBindingInvalidChirho
    );
}

#[test]
fn the_bounds_refuse_rather_than_omit_chirho() {
    let world_chirho = leader_world_chirho();
    let max_chirho = ERASURE_PROPAGATION_MAX_SUBJECT_REQUIREMENTS_CHIRHO as u64;
    for seq_chirho in 0..max_chirho {
        world_chirho.record_chirho(&request_chirho(seq_chirho, &[1], &[1], 4, &[]));
        world_chirho
            .store_chirho
            .record_binding_chirho(&subject_chirho(), seq_chirho, &record_digest_chirho(1))
            .expect("binds");
    }
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho(max_chirho, &[1], &[1], 4, &[]))
        ),
        LeaderRefusalIdentityChirho::ErasureRequirementSubjectFullChirho
    );
    assert!(
        !world_chirho
            .subject_dir_chirho()
            .join(format!("{max_chirho}.requirement.json"))
            .exists(),
        "a refused requirement leaves no file"
    );
}

#[test]
fn a_scan_refuses_strange_entries_and_too_many_and_skips_stranded_temps_chirho() {
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    let dir_chirho = world_chirho.subject_dir_chirho();
    let subject_chirho = subject_chirho();

    fs::write(
        dir_chirho.join(".5.requirement.json.tmp-chirho-123-4"),
        b"half written",
    )
    .unwrap();
    assert_eq!(
        world_chirho.standings_chirho().len(),
        1,
        "a stranded temp was never published"
    );

    for strange_chirho in ["01.requirement.json", "1.requirement.json.bak", "notes.txt"] {
        fs::write(dir_chirho.join(strange_chirho), b"x").unwrap();
        assert_eq!(
            leader_refusal_chirho(
                world_chirho
                    .store_chirho
                    .subject_view_chirho(&subject_chirho)
            ),
            LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho,
            "{strange_chirho}"
        );
        fs::remove_file(dir_chirho.join(strange_chirho)).unwrap();
    }
    fs::create_dir(dir_chirho.join("2.requirement.json")).unwrap();
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho
    );
    fs::remove_dir(dir_chirho.join("2.requirement.json")).unwrap();

    // The scan's cap is the store's own constant. B3-a3 raised it from four entries per requirement to five, for
    // the receipts directory; fill past whatever it is rather than past a copy of it.
    for number_chirho in 0..SUBJECT_SCAN_MAX_ENTRIES_CHIRHO {
        fs::write(
            dir_chirho.join(format!(".9.requirement.json.tmp-chirho-1-{number_chirho}")),
            b"x",
        )
        .unwrap();
    }
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho)
        ),
        LeaderRefusalIdentityChirho::LeaderStoreScanTooLargeChirho
    );
}

#[test]
fn the_store_lock_is_innermost_and_refuses_the_reverse_by_name_chirho() {
    let world_chirho = leader_world_chirho();
    // The erasure's order: the erasure-records lock, then the store's.
    with_named_lock_chirho(
        &world_chirho.root_chirho,
        "privacy-erasure-records-chirho",
        || {
            Ok(world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho()))
        },
    )
    .expect("the store's lock nests inside the erasure-records lock")
    .expect("the view loads");
    for outer_name_chirho in [
        "privacy-erasure-records-chirho",
        "privacy-account-attribution-chirho",
        "privacy-subject-rights-chirho",
    ] {
        let refused_chirho = world_chirho.store_chirho.with_store_lock_chirho(|| {
            Ok(with_named_lock_chirho(
                &world_chirho.root_chirho,
                outer_name_chirho,
                || Ok(()),
            ))
        });
        let message_chirho = format!(
            "{:#}",
            refused_chirho
                .expect("the store lock is taken")
                .unwrap_err()
        );
        assert!(
            message_chirho.contains("NamedLockOrderChirho"),
            "{outer_name_chirho}: {message_chirho}"
        );
    }
}

#[test]
fn the_lineage_bound_is_c2_1s_chirho() {
    assert_eq!(
        ERASURE_PROPAGATION_LINEAGE_FIELD_MAX_BYTES_CHIRHO,
        CONTROL_PLANE_LINEAGE_FIELD_MAX_BYTES_CHIRHO
    );
}

#[test]
fn the_store_never_mints_a_key_and_signs_only_as_its_issuer_chirho() {
    let dir_chirho = tempfile::tempdir().expect("temp dir");
    let root_chirho = dir_chirho.path().join("keyless-root-chirho");
    fs::create_dir(&root_chirho).unwrap();
    let store_chirho = ErasurePropagationStoreChirho::open_chirho(
        &root_chirho,
        context_for_chirho(&holder_chirho(7)),
    )
    .expect("store opens");
    assert_eq!(
        leader_refusal_chirho(store_chirho.record_requirement_chirho(&request_chirho(
            1,
            &[1],
            &[1],
            4,
            &[]
        ))),
        LeaderRefusalIdentityChirho::LeaderSignerUnavailableChirho
    );
    assert!(
        no_key_material_chirho(&root_chirho),
        "a refused signature mints nothing"
    );

    // A root that has a key, under a context naming another issuer, signs nothing either.
    let world_chirho = leader_world_chirho();
    let other_chirho = ErasurePropagationStoreChirho::open_chirho(
        &world_chirho.root_chirho,
        context_for_chirho(&holder_chirho(7)),
    )
    .expect("store opens");
    assert_eq!(
        leader_refusal_chirho(other_chirho.record_requirement_chirho(&request_chirho(
            1,
            &[1],
            &[1],
            4,
            &[]
        ))),
        LeaderRefusalIdentityChirho::LeaderSignerUnavailableChirho
    );
}

#[test]
fn a_record_from_another_issuer_refuses_as_a_context_mismatch_chirho() {
    // The C2 old-issuer residual: a store reading under a new issuer refuses the old one's files.
    let world_chirho = leader_world_chirho();
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    let other_chirho = ErasurePropagationStoreChirho::open_chirho(
        &world_chirho.root_chirho,
        context_for_chirho(&holder_chirho(7)),
    )
    .expect("store opens");
    assert_eq!(
        contract_refusal_chirho(other_chirho.subject_view_chirho(&subject_chirho())),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationContextMismatchChirho
    );
}

fn no_key_material_chirho(root_chirho: &Path) -> bool {
    fs::read_dir(root_chirho)
        .expect("root")
        .filter_map(Result::ok)
        .all(|entry_chirho| {
            let name_chirho = entry_chirho.file_name();
            let name_chirho = name_chirho.to_string_lossy();
            !name_chirho.contains("signing-key") && !name_chirho.contains("pubkey")
        })
}

#[test]
fn a_key_count_beyond_the_frame_bound_refuses_before_any_file_chirho() {
    let world_chirho = leader_world_chirho();
    let mut request_chirho = request_chirho(1, &[], &[1], 4, &[]);
    request_chirho.key_ids_chirho = (0..=cairn_key_custody_chirho::ERASURE_MAX_KEY_IDS_CHIRHO)
        .map(|number_chirho| format!("{number_chirho:032x}"))
        .collect();
    assert_eq!(
        contract_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho)
        ),
        KeyCustodyRefusalIdentityChirho::ErasurePropagationRequirementInvalidChirho
    );
    assert!(!world_chirho
        .subject_dir_chirho()
        .join("1.requirement.json")
        .exists());
}

#[test]
fn an_exact_retry_and_an_equal_binding_replay_each_pass_the_subject_barrier_chirho() {
    // gpt #29353's rule, kept for the leader (gpt #29838): visible is not durable, so a retry that
    // writes nothing still syncs, and a failed sync refuses instead of answering.
    use crate::barrier_chirho::test_hooks_chirho::{
        clear_failing_chirho, fail_syncs_of_chirho, take_events_chirho, EventKindChirho,
    };
    let world_chirho = leader_world_chirho();
    let dir_chirho = world_chirho.subject_dir_chirho();
    let synced_chirho = |events_chirho: &[(EventKindChirho, PathBuf)]| {
        events_chirho.iter().any(|(kind_chirho, path_chirho)| {
            *kind_chirho == EventKindChirho::SyncChirho && *path_chirho == dir_chirho
        })
    };
    world_chirho.record_chirho(&request_chirho(3, &[1], &[1], 9, &[]));
    take_events_chirho();
    world_chirho.record_chirho(&request_chirho(3, &[1], &[1], 9, &[]));
    assert!(
        synced_chirho(&take_events_chirho()),
        "the exact retry passes the barrier"
    );
    fail_syncs_of_chirho(&dir_chirho);
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho(3, &[1], &[1], 9, &[]))
        ),
        LeaderRefusalIdentityChirho::LeaderStoreWriteFailedChirho
    );
    clear_failing_chirho();

    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(1))
        .expect("binds");
    take_events_chirho();
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 3, &record_digest_chirho(1))
        .expect("an equal replay answers");
    assert!(
        synced_chirho(&take_events_chirho()),
        "the equal replay passes the barrier"
    );
    fail_syncs_of_chirho(&dir_chirho);
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_binding_chirho(
            &subject_chirho(),
            3,
            &record_digest_chirho(1)
        )),
        LeaderRefusalIdentityChirho::LeaderStoreWriteFailedChirho
    );
    clear_failing_chirho();
}

#[test]
fn a_linked_or_replaced_store_directory_refuses_and_only_true_absence_reads_empty_chirho() {
    // gpt #29898: a link at the store's directory, its shard or the subject's directory is never "absent",
    // and is never followed.
    use std::os::unix::fs::symlink;
    let world_chirho = leader_world_chirho();
    let subject_chirho = subject_chirho();
    let never_chirho = subject_digest_hex_chirho("app/contact-chirho/submission/never-recorded");
    assert!(world_chirho
        .store_chirho
        .subject_view_chirho(&never_chirho)
        .expect("a genuinely absent subject reads empty")
        .entries_chirho()
        .is_empty());
    world_chirho.record_chirho(&request_chirho(1, &[1], &[1], 4, &[]));
    let dir_chirho = world_chirho.subject_dir_chirho();
    let bytes_chirho = fs::read(dir_chirho.join("1.requirement.json")).unwrap();
    let refused_chirho = |label_chirho: &str| {
        assert_eq!(
            leader_refusal_chirho(
                world_chirho
                    .store_chirho
                    .subject_view_chirho(&subject_chirho)
            ),
            LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho,
            "{label_chirho}"
        );
    };

    let moved_chirho = world_chirho.root_chirho.join("moved-subject-chirho");
    fs::rename(&dir_chirho, &moved_chirho).unwrap();
    let empty_chirho = world_chirho.root_chirho.join("empty-subject-chirho");
    fs::create_dir(&empty_chirho).unwrap();
    fs::set_permissions(&empty_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    for (label_chirho, target_chirho) in [
        (
            "a dangling link",
            world_chirho.root_chirho.join("nowhere-chirho"),
        ),
        ("a link to the moved directory", moved_chirho.clone()),
        ("a link to an empty directory", empty_chirho.clone()),
    ] {
        symlink(&target_chirho, &dir_chirho).unwrap();
        refused_chirho(label_chirho);
        fs::remove_file(&dir_chirho).unwrap();
    }
    fs::write(&dir_chirho, b"not a directory").unwrap();
    refused_chirho("a regular file");
    fs::remove_file(&dir_chirho).unwrap();
    fs::rename(&moved_chirho, &dir_chirho).unwrap();

    let shard_chirho = dir_chirho.parent().unwrap().to_path_buf();
    let moved_shard_chirho = world_chirho.root_chirho.join("moved-shard-chirho");
    fs::rename(&shard_chirho, &moved_shard_chirho).unwrap();
    symlink(&moved_shard_chirho, &shard_chirho).unwrap();
    refused_chirho("a linked shard");
    fs::remove_file(&shard_chirho).unwrap();
    fs::rename(&moved_shard_chirho, &shard_chirho).unwrap();

    // The store's own directory, substituted after the store was opened.
    let base_chirho = world_chirho
        .root_chirho
        .join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO);
    let moved_base_chirho = world_chirho.root_chirho.join("moved-base-chirho");
    fs::rename(&base_chirho, &moved_base_chirho).unwrap();
    symlink(&moved_base_chirho, &base_chirho).unwrap();
    refused_chirho("a linked store directory");
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .record_requirement_chirho(&request_chirho(1, &[1], &[1], 4, &[]))
        ),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho,
        "a write through a linked store directory refuses before it writes"
    );
    fs::remove_file(&base_chirho).unwrap();
    fs::rename(&moved_base_chirho, &base_chirho).unwrap();

    fs::set_permissions(&dir_chirho, fs::Permissions::from_mode(0o755)).unwrap();
    refused_chirho("a non-private subject directory");
    fs::set_permissions(&dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(
        fs::read(dir_chirho.join("1.requirement.json")).unwrap(),
        bytes_chirho,
        "no refusal changed the stored requirement"
    );
    assert_eq!(
        world_chirho.standings_chirho().len(),
        1,
        "the restored subject reads again"
    );
}
