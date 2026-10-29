// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The leader store's receipts and erasure status (C5 B3-a3, item 14 D5 and D6): recorded only for a bound requirement and only when they close a share, kept where they belong, re-verified on every read, and a subject complete only when every requirement is discharged.

use super::world_chirho::{
    key_id_chirho, world_chirho, WorldChirho, OTHER_SUBJECT_CHIRHO, SUBJECT_CHIRHO,
};
use crate::leader_chirho::refusal_chirho::{LeaderRefusalChirho, LeaderRefusalIdentityChirho};
use crate::leader_chirho::store_chirho::{
    EarlierErasureChirho, ErasurePropagationStoreChirho, ErasureReceiptRecordedChirho,
    RecordRequirementRequestChirho, RequirementErasureChirho, ERASURE_PROPAGATION_STORE_DIR_CHIRHO,
    ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO,
};
use cairn_key_custody_chirho::{
    subject_digest_hex_chirho, ErasurePropagationContextChirho, ErasureStatusChirho,
    VerifiedErasureReceiptChirho,
};
use cairn_signer_chirho::signer_chirho::{existing_keypair_pubkey_hex_chirho, sign_message_chirho};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

const TENANT_CHIRHO: &str = "item6-drill-chirho";
const INSTANCE_CHIRHO: &str = "genesis-instance-one-chirho";
/// The bound every requirement here is erased below.
const BOUND_CHIRHO: u64 = 5;

/// The holder world, and a leader store on its own root whose group is that world's group.
struct ReceiptWorldChirho {
    world_chirho: WorldChirho,
    _dir_chirho: tempfile::TempDir,
    root_chirho: PathBuf,
    store_chirho: ErasurePropagationStoreChirho,
}

fn receipt_world_chirho() -> ReceiptWorldChirho {
    let world_chirho = world_chirho();
    let dir_chirho = tempfile::tempdir().expect("temp dir");
    let root_chirho = dir_chirho.path().join("leader-root-chirho");
    fs::create_dir(&root_chirho).expect("root");
    sign_message_chirho(&root_chirho, b"provision the leader's node key").expect("node key");
    let issuer_chirho = existing_keypair_pubkey_hex_chirho(&root_chirho).expect("issuer");
    let group_chirho = world_chirho
        .joined_chirho()
        .view_chirho()
        .consistency_group_digest_chirho()
        .to_string();
    let context_chirho = ErasurePropagationContextChirho::new_chirho(
        &group_chirho,
        TENANT_CHIRHO,
        INSTANCE_CHIRHO,
        &issuer_chirho,
    )
    .expect("context in form");
    let store_chirho = ErasurePropagationStoreChirho::open_chirho(&root_chirho, context_chirho)
        .expect("store opens");
    ReceiptWorldChirho {
        world_chirho,
        _dir_chirho: dir_chirho,
        root_chirho,
        store_chirho,
    }
}

fn subject_chirho() -> String {
    subject_digest_hex_chirho(SUBJECT_CHIRHO)
}

fn ids_chirho(numbers_chirho: &[u8]) -> Vec<String> {
    numbers_chirho
        .iter()
        .map(|number_chirho| key_id_chirho(*number_chirho))
        .collect()
}

impl ReceiptWorldChirho {
    /// Every node the world places: the leader, the holder and the peer.
    fn all_holders_chirho(&self) -> BTreeSet<String> {
        [
            &self.world_chirho.leader_chirho,
            &self.world_chirho.holder_chirho,
            &self.world_chirho.peer_chirho,
        ]
        .iter()
        .map(|node_chirho| node_chirho.id_chirho().to_string())
        .collect()
    }

    /// Record the requirement at `seq` over keys 1 and 2 for `holders`, and, when asked, bind it.
    fn record_chirho(&self, seq_chirho: u64, holders_chirho: BTreeSet<String>, bind_chirho: bool) {
        self.store_chirho
            .record_requirement_chirho(&RecordRequirementRequestChirho {
                subject_digest_chirho: subject_chirho(),
                erasure_seq_chirho: seq_chirho,
                erased_below_blob_seq_chirho: BOUND_CHIRHO,
                key_ids_chirho: ids_chirho(&[1, 2]).into_iter().collect(),
                holders_chirho,
                earlier_chirho: BTreeMap::<u64, EarlierErasureChirho>::new(),
            })
            .expect("requirement records");
        if bind_chirho {
            self.store_chirho
                .record_binding_chirho(&subject_chirho(), seq_chirho, &"ab".repeat(32))
                .expect("requirement binds");
        }
    }

    /// The peer's genuine receipt closing its share: keys 1 and 2 at the requirement's bound.
    fn peer_receipt_chirho(&self) -> VerifiedErasureReceiptChirho {
        self.world_chirho.erasure_receipt_for_chirho(
            &self.world_chirho.peer_chirho,
            SUBJECT_CHIRHO,
            BOUND_CHIRHO,
            &ids_chirho(&[1]),
            &ids_chirho(&[2]),
        )
    }

    fn status_chirho(&self, seq_chirho: u64) -> Result<ErasureStatusChirho, LeaderRefusalChirho> {
        let joined_chirho = self.world_chirho.joined_chirho();
        self.store_chirho.requirement_erasure_status_chirho(
            &subject_chirho(),
            seq_chirho,
            joined_chirho.view_chirho(),
        )
    }

    fn receipts_dir_chirho(&self, seq_chirho: u64) -> PathBuf {
        let subject_chirho = subject_chirho();
        self.root_chirho
            .join(ERASURE_PROPAGATION_STORE_DIR_CHIRHO)
            .join(&subject_chirho[..2])
            .join(&subject_chirho)
            .join(format!("{seq_chirho}.receipts"))
    }

    fn receipt_path_chirho(
        &self,
        seq_chirho: u64,
        receipt_chirho: &VerifiedErasureReceiptChirho,
    ) -> PathBuf {
        self.receipts_dir_chirho(seq_chirho)
            .join(receipt_chirho.holder_node_id_chirho())
            .join(format!(
                "{}.json",
                receipt_chirho.erasure_frame_digest_chirho()
            ))
    }
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

fn pending_chirho(holders_chirho: &[&str]) -> ErasureStatusChirho {
    ErasureStatusChirho::ErasurePropagationPendingChirho {
        pending_holders_chirho: holders_chirho
            .iter()
            .map(|holder_chirho| holder_chirho.to_string())
            .collect(),
    }
}

#[test]
fn a_bound_requirements_receipt_records_once_closes_its_share_and_replays_equal_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let receipt_chirho = world_chirho.peer_receipt_chirho();
    assert_eq!(
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 0, &receipt_chirho)
            .unwrap(),
        ErasureReceiptRecordedChirho::CreatedChirho
    );
    let path_chirho = world_chirho.receipt_path_chirho(0, &receipt_chirho);
    assert_eq!(
        fs::metadata(&path_chirho).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 0, &receipt_chirho)
            .unwrap(),
        ErasureReceiptRecordedChirho::ReplayedChirho
    );
    let world_nodes_chirho = &world_chirho.world_chirho;
    assert_eq!(
        world_chirho.status_chirho(0).unwrap(),
        pending_chirho(&[
            world_nodes_chirho.leader_chirho.id_chirho(),
            world_nodes_chirho.holder_chirho.id_chirho(),
        ]),
        "the peer's share is closed; the leader's and the holder's are not"
    );
}

#[test]
fn a_receipt_is_refused_for_an_unbound_requirement_and_leaves_no_file_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), false);
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_erasure_receipt_chirho(
            &subject_chirho(),
            0,
            &world_chirho.peer_receipt_chirho(),
        )),
        LeaderRefusalIdentityChirho::ErasureReceiptRequirementUnboundChirho
    );
    assert_eq!(
        leader_refusal_chirho(world_chirho.status_chirho(0)),
        LeaderRefusalIdentityChirho::ErasureReceiptRequirementUnboundChirho
    );
    assert!(!world_chirho.receipts_dir_chirho(0).exists());
}

#[test]
fn a_receipt_for_another_subject_group_or_holder_refuses_by_name_and_leaves_no_file_chirho() {
    let world_chirho = receipt_world_chirho();
    let without_peer_chirho = world_chirho
        .all_holders_chirho()
        .into_iter()
        .filter(|holder_chirho| holder_chirho != world_chirho.world_chirho.peer_chirho.id_chirho())
        .collect();
    world_chirho.record_chirho(0, without_peer_chirho, true);
    let unnamed_holder_chirho = world_chirho.peer_receipt_chirho();
    let other_subject_chirho = world_chirho.world_chirho.erasure_receipt_for_chirho(
        &world_chirho.world_chirho.holder_chirho,
        OTHER_SUBJECT_CHIRHO,
        BOUND_CHIRHO,
        &ids_chirho(&[1, 2]),
        &[],
    );
    for (name_chirho, receipt_chirho) in [
        ("unnamed holder", &unnamed_holder_chirho),
        ("other subject", &other_subject_chirho),
    ] {
        assert_eq!(
            leader_refusal_chirho(world_chirho.store_chirho.record_erasure_receipt_chirho(
                &subject_chirho(),
                0,
                receipt_chirho,
            )),
            LeaderRefusalIdentityChirho::ErasureReceiptNotForRequirementChirho,
            "{name_chirho}"
        );
    }
    assert!(!world_chirho.receipts_dir_chirho(0).exists());

    // Another group: a second store whose context names another group, with the same holders and a bound
    // requirement, is offered the world's genuine receipt. (A second world would not do: the group digest comes
    // from the tenant binding, not the node set, so it would match.)
    let other_dir_chirho = tempfile::tempdir().expect("temp dir");
    let other_root_chirho = other_dir_chirho.path().join("other-leader-root-chirho");
    fs::create_dir(&other_root_chirho).expect("root");
    sign_message_chirho(&other_root_chirho, b"provision the other leader's node key").expect("key");
    let other_store_chirho = ErasurePropagationStoreChirho::open_chirho(
        &other_root_chirho,
        ErasurePropagationContextChirho::new_chirho(
            &"22".repeat(32),
            TENANT_CHIRHO,
            INSTANCE_CHIRHO,
            &existing_keypair_pubkey_hex_chirho(&other_root_chirho).expect("issuer"),
        )
        .expect("context in form"),
    )
    .expect("store opens");
    other_store_chirho
        .record_requirement_chirho(&RecordRequirementRequestChirho {
            subject_digest_chirho: subject_chirho(),
            erasure_seq_chirho: 0,
            erased_below_blob_seq_chirho: BOUND_CHIRHO,
            key_ids_chirho: ids_chirho(&[1, 2]).into_iter().collect(),
            holders_chirho: world_chirho.all_holders_chirho(),
            earlier_chirho: BTreeMap::new(),
        })
        .expect("requirement records");
    other_store_chirho
        .record_binding_chirho(&subject_chirho(), 0, &"ab".repeat(32))
        .expect("requirement binds");
    let genuine_chirho = world_chirho.peer_receipt_chirho();
    assert_ne!(
        genuine_chirho.consistency_group_digest_chirho(),
        "22".repeat(32),
        "the fixture must really differ in group"
    );
    assert_eq!(
        leader_refusal_chirho(other_store_chirho.record_erasure_receipt_chirho(
            &subject_chirho(),
            0,
            &genuine_chirho,
        )),
        LeaderRefusalIdentityChirho::ErasureReceiptNotForRequirementChirho,
        "other group"
    );
}

#[test]
fn a_receipt_that_does_not_close_its_share_is_never_stored_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let peer_chirho = &world_chirho.world_chirho.peer_chirho;
    let omits_a_key_chirho = world_chirho.world_chirho.erasure_receipt_for_chirho(
        peer_chirho,
        SUBJECT_CHIRHO,
        BOUND_CHIRHO,
        &ids_chirho(&[1]),
        &[],
    );
    let lower_bound_chirho = world_chirho.world_chirho.erasure_receipt_for_chirho(
        peer_chirho,
        SUBJECT_CHIRHO,
        BOUND_CHIRHO - 1,
        &ids_chirho(&[1, 2]),
        &[],
    );
    for (name_chirho, receipt_chirho) in [
        ("omits a key", &omits_a_key_chirho),
        ("lower bound", &lower_bound_chirho),
    ] {
        assert_eq!(
            leader_refusal_chirho(world_chirho.store_chirho.record_erasure_receipt_chirho(
                &subject_chirho(),
                0,
                receipt_chirho,
            )),
            LeaderRefusalIdentityChirho::ErasureReceiptDoesNotCloseChirho,
            "{name_chirho}"
        );
    }
    assert!(!world_chirho.receipts_dir_chirho(0).exists());
}

#[test]
fn a_different_receipt_at_a_stored_path_refuses_and_the_stored_one_stands_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let stored_chirho = world_chirho.peer_receipt_chirho();
    world_chirho
        .store_chirho
        .record_erasure_receipt_chirho(&subject_chirho(), 0, &stored_chirho)
        .unwrap();
    let path_chirho = world_chirho.receipt_path_chirho(0, &stored_chirho);
    let bytes_before_chirho = fs::read(&path_chirho).unwrap();
    // The same frame, answered with another split of its ids: another valid receipt at the same path.
    let resplit_chirho = world_chirho.world_chirho.erasure_receipt_for_chirho(
        &world_chirho.world_chirho.peer_chirho,
        SUBJECT_CHIRHO,
        BOUND_CHIRHO,
        &ids_chirho(&[1, 2]),
        &[],
    );
    assert_eq!(
        resplit_chirho.erasure_frame_digest_chirho(),
        stored_chirho.erasure_frame_digest_chirho(),
        "the fixture must really collide on its path"
    );
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_erasure_receipt_chirho(
            &subject_chirho(),
            0,
            &resplit_chirho,
        )),
        LeaderRefusalIdentityChirho::ErasureReceiptConflictChirho
    );
    assert_eq!(fs::read(&path_chirho).unwrap(), bytes_before_chirho);
}

#[test]
fn a_full_holder_refuses_a_new_receipt_but_an_exact_replay_still_passes_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let peer_chirho = &world_chirho.world_chirho.peer_chirho;
    // Each bound at or above the requirement's makes a distinct frame whose receipt still closes the share.
    let receipt_at_chirho = |offset_chirho: u64| {
        world_chirho.world_chirho.erasure_receipt_for_chirho(
            peer_chirho,
            SUBJECT_CHIRHO,
            BOUND_CHIRHO + offset_chirho,
            &ids_chirho(&[1, 2]),
            &[],
        )
    };
    let cap_chirho = ERASURE_RECEIPTS_MAX_PER_HOLDER_CHIRHO as u64;
    for offset_chirho in 0..cap_chirho {
        assert_eq!(
            world_chirho
                .store_chirho
                .record_erasure_receipt_chirho(
                    &subject_chirho(),
                    0,
                    &receipt_at_chirho(offset_chirho)
                )
                .unwrap(),
            ErasureReceiptRecordedChirho::CreatedChirho
        );
    }
    assert_eq!(
        leader_refusal_chirho(world_chirho.store_chirho.record_erasure_receipt_chirho(
            &subject_chirho(),
            0,
            &receipt_at_chirho(cap_chirho),
        )),
        LeaderRefusalIdentityChirho::ErasureReceiptHolderFullChirho
    );
    assert_eq!(
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 0, &receipt_at_chirho(0))
            .unwrap(),
        ErasureReceiptRecordedChirho::ReplayedChirho,
        "an exact replay passes its barrier even at the cap"
    );
    let holder_dir_chirho = world_chirho
        .receipts_dir_chirho(0)
        .join(peer_chirho.id_chirho());
    assert_eq!(
        fs::read_dir(holder_dir_chirho).unwrap().count() as u64,
        cap_chirho
    );
}

#[test]
fn a_tampered_moved_misnamed_or_linked_receipt_refuses_the_subject_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let receipt_chirho = world_chirho.peer_receipt_chirho();
    world_chirho
        .store_chirho
        .record_erasure_receipt_chirho(&subject_chirho(), 0, &receipt_chirho)
        .unwrap();
    let path_chirho = world_chirho.receipt_path_chirho(0, &receipt_chirho);
    let original_chirho = fs::read(&path_chirho).unwrap();
    let refuses_chirho = |name_chirho: &str| {
        assert!(
            world_chirho.status_chirho(0).is_err(),
            "{name_chirho}: the read must refuse"
        );
    };

    // Tampered: one id flipped. The signature no longer verifies.
    let text_chirho = String::from_utf8(original_chirho.clone()).unwrap();
    fs::write(
        &path_chirho,
        text_chirho.replacen(&key_id_chirho(1), &key_id_chirho(9), 1),
    )
    .unwrap();
    refuses_chirho("tampered");
    fs::write(&path_chirho, &original_chirho).unwrap();
    world_chirho
        .status_chirho(0)
        .expect("restored, it reads again");

    // Misnamed: the file is not named by its own frame digest.
    let misnamed_chirho = path_chirho.with_file_name(format!("{}.json", "cd".repeat(32)));
    fs::rename(&path_chirho, &misnamed_chirho).unwrap();
    refuses_chirho("misnamed");
    fs::rename(&misnamed_chirho, &path_chirho).unwrap();

    // Moved: the receipt sits under another named holder's directory.
    let moved_dir_chirho = world_chirho
        .receipts_dir_chirho(0)
        .join(world_chirho.world_chirho.holder_chirho.id_chirho());
    fs::create_dir(&moved_dir_chirho).unwrap();
    fs::set_permissions(&moved_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    let moved_chirho = moved_dir_chirho.join(path_chirho.file_name().unwrap());
    fs::rename(&path_chirho, &moved_chirho).unwrap();
    refuses_chirho("moved");
    fs::rename(&moved_chirho, &path_chirho).unwrap();
    fs::remove_dir(&moved_dir_chirho).unwrap();

    // Not private: the receipts directory, then a holder's, opened to the group. The subject's scan admits a
    // directory by name; only the receipts reader's probe sees its mode.
    let receipts_dir_chirho = world_chirho.receipts_dir_chirho(0);
    let holder_dir_chirho = path_chirho.parent().unwrap().to_path_buf();
    for dir_chirho in [&receipts_dir_chirho, &holder_dir_chirho] {
        fs::set_permissions(dir_chirho, fs::Permissions::from_mode(0o755)).unwrap();
        refuses_chirho("not private");
        fs::set_permissions(dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    }
    world_chirho
        .status_chirho(0)
        .expect("private again, it reads again");

    // Planted: a genuine, holder-signed receipt that closes nothing, written straight into the store. Recording
    // would refuse it; the read refuses it too, by re-testing every stored receipt.
    let omits_a_key_chirho = world_chirho.world_chirho.erasure_receipt_for_chirho(
        &world_chirho.world_chirho.peer_chirho,
        SUBJECT_CHIRHO,
        BOUND_CHIRHO,
        &ids_chirho(&[1]),
        &[],
    );
    let planted_chirho = world_chirho.receipt_path_chirho(0, &omits_a_key_chirho);
    fs::write(
        &planted_chirho,
        omits_a_key_chirho
            .record_chirho()
            .to_wire_bytes_chirho()
            .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&planted_chirho, fs::Permissions::from_mode(0o600)).unwrap();
    refuses_chirho("planted, closing nothing");
    fs::remove_file(&planted_chirho).unwrap();
    world_chirho
        .status_chirho(0)
        .expect("without it, the store reads again");

    // A stranded temp from a crashed write was never published, so it is skipped.
    let temp_chirho =
        path_chirho.with_file_name(format!(".{}.json.tmp-chirho-1-2", "ef".repeat(32)));
    fs::write(&temp_chirho, b"half written").unwrap();
    world_chirho
        .status_chirho(0)
        .expect("a stranded temp is skipped");
    fs::remove_file(&temp_chirho).unwrap();

    // Linked: the receipts directory is a link to a real one elsewhere.
    let receipts_dir_chirho = world_chirho.receipts_dir_chirho(0);
    let elsewhere_chirho = world_chirho.root_chirho.join("elsewhere-chirho");
    fs::rename(&receipts_dir_chirho, &elsewhere_chirho).unwrap();
    std::os::unix::fs::symlink(&elsewhere_chirho, &receipts_dir_chirho).unwrap();
    refuses_chirho("linked");
    fs::remove_file(&receipts_dir_chirho).unwrap();
    fs::rename(&elsewhere_chirho, &receipts_dir_chirho).unwrap();
    world_chirho
        .status_chirho(0)
        .expect("restored, it reads again");
}

#[test]
fn a_receipts_directory_beside_an_unbound_requirement_refuses_the_subject_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), false);
    let receipts_dir_chirho = world_chirho.receipts_dir_chirho(0);
    fs::create_dir(&receipts_dir_chirho).unwrap();
    fs::set_permissions(&receipts_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        leader_refusal_chirho(
            world_chirho
                .store_chirho
                .subject_view_chirho(&subject_chirho())
        ),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho
    );
}

#[test]
fn a_subject_is_complete_only_when_every_bound_requirement_is_discharged_chirho() {
    let world_chirho = receipt_world_chirho();
    let joined_chirho = world_chirho.world_chirho.joined_chirho();
    let nodes_chirho = &world_chirho.world_chirho;
    // gpt #29788: S@2 bound with one holder never answering, then S@5 bound and fully answered.
    world_chirho.record_chirho(2, world_chirho.all_holders_chirho(), true);
    for node_chirho in [&nodes_chirho.leader_chirho, &nodes_chirho.peer_chirho] {
        let receipt_chirho = nodes_chirho.erasure_receipt_for_chirho(
            node_chirho,
            SUBJECT_CHIRHO,
            BOUND_CHIRHO,
            &ids_chirho(&[1, 2]),
            &[],
        );
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 2, &receipt_chirho)
            .unwrap();
    }
    world_chirho.record_chirho(5, world_chirho.all_holders_chirho(), true);
    for node_chirho in [
        &nodes_chirho.leader_chirho,
        &nodes_chirho.holder_chirho,
        &nodes_chirho.peer_chirho,
    ] {
        let receipt_chirho = nodes_chirho.erasure_receipt_for_chirho(
            node_chirho,
            SUBJECT_CHIRHO,
            BOUND_CHIRHO,
            &ids_chirho(&[1, 2]),
            &[],
        );
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 5, &receipt_chirho)
            .unwrap();
    }
    let status_chirho = world_chirho
        .store_chirho
        .subject_erasure_status_chirho(&subject_chirho(), joined_chirho.view_chirho())
        .unwrap();
    assert_eq!(
        status_chirho.entries_chirho(),
        &[
            (
                2,
                RequirementErasureChirho::BoundChirho {
                    status_chirho: pending_chirho(&[nodes_chirho.holder_chirho.id_chirho()]),
                },
            ),
            (
                5,
                RequirementErasureChirho::BoundChirho {
                    status_chirho: ErasureStatusChirho::ErasureConfirmedByHolderReceiptsChirho,
                },
            ),
        ]
    );
    assert!(
        !status_chirho.is_complete_chirho(),
        "the newer complete requirement never stands in for the older pending one"
    );
    let holder_receipt_chirho = nodes_chirho.erasure_receipt_for_chirho(
        &nodes_chirho.holder_chirho,
        SUBJECT_CHIRHO,
        BOUND_CHIRHO,
        &ids_chirho(&[1, 2]),
        &[],
    );
    world_chirho
        .store_chirho
        .record_erasure_receipt_chirho(&subject_chirho(), 2, &holder_receipt_chirho)
        .unwrap();
    assert!(world_chirho
        .store_chirho
        .subject_erasure_status_chirho(&subject_chirho(), joined_chirho.view_chirho())
        .unwrap()
        .is_complete_chirho());
}

#[test]
fn a_subject_with_no_requirement_is_not_complete_chirho() {
    let world_chirho = receipt_world_chirho();
    let joined_chirho = world_chirho.world_chirho.joined_chirho();
    let status_chirho = world_chirho
        .store_chirho
        .subject_erasure_status_chirho(&subject_chirho(), joined_chirho.view_chirho())
        .unwrap();
    assert!(status_chirho.entries_chirho().is_empty());
    assert!(!status_chirho.is_complete_chirho());
}

#[test]
fn a_carried_requirement_discharges_with_its_bound_carrier_and_an_uncarried_one_blocks_chirho() {
    let world_chirho = receipt_world_chirho();
    let joined_chirho = world_chirho.world_chirho.joined_chirho();
    let nodes_chirho = &world_chirho.world_chirho;
    let subject_status_chirho = || {
        world_chirho
            .store_chirho
            .subject_erasure_status_chirho(&subject_chirho(), joined_chirho.view_chirho())
            .unwrap()
    };
    // S@0 is never recorded: unbound, and carried by nothing yet, so it blocks the subject.
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), false);
    assert_eq!(
        subject_status_chirho().entries_chirho(),
        &[(0, RequirementErasureChirho::PendingChirho)]
    );
    assert!(!subject_status_chirho().is_complete_chirho());
    // S@1 carries it and is bound; until its holders answer, neither is discharged.
    world_chirho
        .store_chirho
        .record_requirement_chirho(&RecordRequirementRequestChirho {
            subject_digest_chirho: subject_chirho(),
            erasure_seq_chirho: 1,
            erased_below_blob_seq_chirho: BOUND_CHIRHO,
            key_ids_chirho: ids_chirho(&[1, 2]).into_iter().collect(),
            holders_chirho: world_chirho.all_holders_chirho(),
            earlier_chirho: BTreeMap::from([(0, EarlierErasureChirho::NeverRecordedChirho)]),
        })
        .expect("the successor records and carries S@0");
    world_chirho
        .store_chirho
        .record_binding_chirho(&subject_chirho(), 1, &"ab".repeat(32))
        .expect("the successor binds");
    assert_eq!(
        subject_status_chirho().entries_chirho()[0],
        (
            0,
            RequirementErasureChirho::CarriedByChirho {
                bound_seq_chirho: 1,
                discharged_chirho: false,
            }
        )
    );
    assert!(!subject_status_chirho().is_complete_chirho());
    for node_chirho in [
        &nodes_chirho.leader_chirho,
        &nodes_chirho.holder_chirho,
        &nodes_chirho.peer_chirho,
    ] {
        let receipt_chirho = nodes_chirho.erasure_receipt_for_chirho(
            node_chirho,
            SUBJECT_CHIRHO,
            BOUND_CHIRHO,
            &ids_chirho(&[1, 2]),
            &[],
        );
        world_chirho
            .store_chirho
            .record_erasure_receipt_chirho(&subject_chirho(), 1, &receipt_chirho)
            .unwrap();
    }
    assert_eq!(
        subject_status_chirho().entries_chirho()[0],
        (
            0,
            RequirementErasureChirho::CarriedByChirho {
                bound_seq_chirho: 1,
                discharged_chirho: true,
            }
        )
    );
    assert!(subject_status_chirho().is_complete_chirho());
}

/// The receipts directory's own probe acts alone only when it holds no holder directory: each holder directory's
/// probe re-checks every component above it. An emptied, non-private receipts directory still refuses the read.
#[test]
fn an_empty_receipts_directory_that_is_not_private_refuses_the_read_chirho() {
    let world_chirho = receipt_world_chirho();
    world_chirho.record_chirho(0, world_chirho.all_holders_chirho(), true);
    let receipts_dir_chirho = world_chirho.receipts_dir_chirho(0);
    fs::create_dir(&receipts_dir_chirho).unwrap();
    fs::set_permissions(&receipts_dir_chirho, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        leader_refusal_chirho(world_chirho.status_chirho(0)),
        LeaderRefusalIdentityChirho::LeaderStoreUnreadableChirho
    );
    fs::set_permissions(&receipts_dir_chirho, fs::Permissions::from_mode(0o700)).unwrap();
    world_chirho
        .status_chirho(0)
        .expect("private again, an empty receipts directory reads as no receipts");
}
