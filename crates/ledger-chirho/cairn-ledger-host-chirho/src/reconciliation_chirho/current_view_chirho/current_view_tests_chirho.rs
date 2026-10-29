// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho;
use cairn_writer_elector_chirho::elector_port_chirho::LeadershipChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_head_chirho::writer_head_chirho::{
    compose_writer_epoch_chirho, consistency_group_digest_chirho,
};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct TestRootChirho {
    path_chirho: PathBuf,
}

impl TestRootChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock remains after the Unix epoch")
            .as_nanos();
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-gd7-current-view-{label_chirho}-{nanos_chirho}-{counter_chirho}"
        ));
        fs::create_dir_all(&path_chirho).expect("create current-view test root");
        Self { path_chirho }
    }

    fn storage_chirho(&self) -> FsLedgerStorageChirho {
        FsLedgerStorageChirho::open_existing_chirho(&self.path_chirho)
            .expect("open current-view test storage")
    }
}

impl Drop for TestRootChirho {
    fn drop(&mut self) {
        let _remove_result_chirho = fs::remove_dir_all(&self.path_chirho);
    }
}

#[derive(Clone)]
struct FakeControlSignerChirho {
    key_id_chirho: String,
    key_chirho: [u8; 32],
}

impl FakeControlSignerChirho {
    fn new_chirho(key_id_chirho: String, key_byte_chirho: u8) -> Self {
        Self {
            key_id_chirho,
            key_chirho: [key_byte_chirho; 32],
        }
    }

    fn signature_chirho(&self, line_chirho: &str) -> String {
        blake3::keyed_hash(&self.key_chirho, line_chirho.as_bytes())
            .to_hex()
            .to_string()
    }
}

impl Gd7ReconciliationVerifierPortChirho for FakeControlSignerChirho {
    fn key_id_chirho(&self) -> String {
        self.key_id_chirho.clone()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.signature_chirho(canonical_unsigned_chirho) == sig_chirho
    }
}

impl Gd7ReconciliationSignerPortChirho for FakeControlSignerChirho {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
        Ok(self.signature_chirho(canonical_unsigned_chirho))
    }
}

struct GuardProbingSignerChirho<'ports_chirho> {
    signer_chirho: &'ports_chirho FakeControlSignerChirho,
    authority_chirho: &'ports_chirho LocalAppendAuthorityHandleChirho,
    signing_guard_held_chirho: &'ports_chirho Cell<bool>,
    verifying_guard_held_chirho: &'ports_chirho Cell<bool>,
}

impl Gd7ReconciliationVerifierPortChirho for GuardProbingSignerChirho<'_> {
    fn key_id_chirho(&self) -> String {
        self.signer_chirho.key_id_chirho()
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.verifying_guard_held_chirho.set(matches!(
            self.authority_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
        ));
        self.signer_chirho
            .verify_chirho(canonical_unsigned_chirho, sig_chirho)
    }
}

impl Gd7ReconciliationSignerPortChirho for GuardProbingSignerChirho<'_> {
    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> anyhow::Result<String> {
        self.signing_guard_held_chirho.set(matches!(
            self.authority_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
        ));
        self.signer_chirho.sign_chirho(canonical_unsigned_chirho)
    }
}

struct SequenceElectorChirho {
    node_id_chirho: NodeIdChirho,
    observations_chirho: RefCell<VecDeque<LeadershipChirho>>,
    fallback_chirho: LeadershipChirho,
}

impl SequenceElectorChirho {
    fn new_chirho(
        node_id_chirho: NodeIdChirho,
        observations_chirho: impl IntoIterator<Item = LeadershipChirho>,
        fallback_chirho: LeadershipChirho,
    ) -> Self {
        Self {
            node_id_chirho,
            observations_chirho: RefCell::new(observations_chirho.into_iter().collect()),
            fallback_chirho,
        }
    }
}

impl WriterElectorChirho for SequenceElectorChirho {
    fn leadership_chirho(&self, _group_chirho: &ConsistencyGroupIdChirho) -> LeadershipChirho {
        self.observations_chirho
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| self.fallback_chirho.clone())
    }

    fn node_id_chirho(&self) -> &NodeIdChirho {
        &self.node_id_chirho
    }
}

fn stable_follower_leadership_chirho(
    winner_node_chirho: &NodeIdChirho,
    term_chirho: u64,
) -> LeadershipChirho {
    LeadershipChirho {
        is_leader_chirho: false,
        leader_id_chirho: Some(winner_node_chirho.clone()),
        term_chirho,
        lease_valid_chirho: false,
    }
}

fn warm_winner_elector_chirho(
    winner_node_chirho: &NodeIdChirho,
    group_chirho: &ConsistencyGroupIdChirho,
) -> RaftWriterElectorChirho {
    let elector_chirho = RaftWriterElectorChirho::new_single_node_chirho(
        winner_node_chirho.clone(),
        group_chirho.clone(),
    )
    .expect("construct one-voter current-view elector")
    .with_leadership_warmup_lease_chirho();
    elector_chirho
        .campaign_chirho()
        .expect("campaign one-voter current-view elector");
    for _tick_chirho in 0..10 {
        let _messages_chirho = elector_chirho.tick_chirho();
    }
    elector_chirho
}

fn challenge_for_test_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    winner_node_chirho: &NodeIdChirho,
    term_chirho: u64,
    nonce_byte_chirho: u8,
) -> Gd7WinnerCurrentViewChallengeChirho {
    Gd7WinnerCurrentViewChallengeChirho {
        schema_chirho: GD7_WINNER_CURRENT_VIEW_CHALLENGE_SCHEMA_V1_CHIRHO.to_owned(),
        nonce_chirho: format!("{nonce_byte_chirho:02x}").repeat(32),
        consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho)
            .expect("digest current-view group"),
        expected_winner_node_chirho: winner_node_chirho.0.clone(),
        held_node_chirho: "ee".repeat(32),
        transfer_identity_digest_chirho: "dd".repeat(32),
        raft_term_chirho: term_chirho,
    }
}

fn issued_challenge_for_test_chirho(
    group_chirho: &ConsistencyGroupIdChirho,
    winner_node_chirho: &NodeIdChirho,
    term_chirho: u64,
) -> IssuedGd7WinnerCurrentViewChallengeChirho {
    let leadership_chirho = stable_follower_leadership_chirho(winner_node_chirho, term_chirho);
    let elector_chirho = SequenceElectorChirho::new_chirho(
        NodeIdChirho("ff".repeat(32)),
        [leadership_chirho.clone()],
        leadership_chirho,
    );
    generate_gd7_winner_current_view_challenge_chirho(
        &elector_chirho,
        group_chirho,
        winner_node_chirho,
        &NodeIdChirho("ee".repeat(32)),
        &"dd".repeat(32),
    )
    .expect("issue fresh current-view challenge")
}

fn transport_challenge_for_test_chirho(
    issued_challenge_chirho: &IssuedGd7WinnerCurrentViewChallengeChirho,
) -> Gd7WinnerCurrentViewChallengeChirho {
    parse_canonical_gd7_winner_current_view_challenge_chirho(
        &issued_challenge_chirho
            .canonical_bytes_chirho()
            .expect("encode issued current-view challenge"),
    )
    .expect("parse transported current-view challenge")
}

fn snapshot_for_test_chirho(term_chirho: u64) -> Gd7WinnerJournalSnapshotChirho {
    Gd7WinnerJournalSnapshotChirho {
        genesis_digest_chirho: "ab".repeat(32),
        cut_chirho: Gd7JournalTailCoordinateChirho {
            epoch_chirho: compose_writer_epoch_chirho(term_chirho, 1)
                .expect("compose current-view test epoch"),
            seq_chirho: 7,
            record_digest_chirho: "cd".repeat(32),
        },
    }
}

fn persist_bundle_root_for_test_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    snapshot_chirho: &Gd7WinnerJournalSnapshotChirho,
) -> VerifiedGd7WinnerViewBundleRootChirho {
    let root_chirho = Gd7WinnerViewBundleRootChirho {
        schema_chirho: GD7_WINNER_VIEW_BUNDLE_ROOT_SCHEMA_V1_CHIRHO.to_owned(),
        consistency_group_digest_chirho: consistency_group_digest_chirho(group_chirho)
            .expect("digest current-view bundle group"),
        projection_fold_ref_chirho: account_net_projection_fold_ref_chirho().0,
        winner_journal_genesis_digest_chirho: snapshot_chirho.genesis_digest_chirho.clone(),
        source_cut_chirho: snapshot_chirho.cut_chirho.clone(),
        lowest_page_ref_chirho: Some("ef".repeat(32)),
        page_count_chirho: 1,
        row_count_chirho: 1,
    };
    validate_bundle_root_shape_chirho(&root_chirho).expect("validate current-view bundle root");
    let bytes_chirho =
        canonical_json_chirho(&root_chirho).expect("encode current-view bundle root");
    let object_digest_chirho = digest_bytes_chirho(&bytes_chirho);
    let path_chirho =
        gd7_winner_view_bundle_root_path_chirho(&object_digest_chirho).expect("bundle root path");
    create_exact_chirho(
        storage_chirho,
        &path_chirho,
        &bytes_chirho,
        MAX_GD7_WINNER_VIEW_BUNDLE_ROOT_BYTES_CHIRHO,
    )
    .expect("persist current-view bundle root");
    load_verified_bundle_root_chirho(storage_chirho, &object_digest_chirho)
        .expect("reload current-view bundle root")
}

fn seal_fixture_chirho(
    storage_chirho: &dyn LedgerStoragePortChirho,
    signer_chirho: &FakeControlSignerChirho,
    group_chirho: &ConsistencyGroupIdChirho,
    winner_node_chirho: &NodeIdChirho,
) -> (
    IssuedGd7WinnerCurrentViewChallengeChirho,
    VerifiedGd7WinnerCurrentViewEvidenceChirho,
    VerifiedGd7WinnerViewBundleRootChirho,
) {
    let elector_chirho = warm_winner_elector_chirho(winner_node_chirho, group_chirho);
    let leadership_chirho = elector_chirho.leadership_chirho(group_chirho);
    let issued_challenge_chirho = issued_challenge_for_test_chirho(
        group_chirho,
        winner_node_chirho,
        leadership_chirho.term_chirho,
    );
    let challenge_chirho = transport_challenge_for_test_chirho(&issued_challenge_chirho);
    let snapshot_chirho = snapshot_for_test_chirho(leadership_chirho.term_chirho);
    let bundle_root_chirho =
        persist_bundle_root_for_test_chirho(storage_chirho, group_chirho, &snapshot_chirho);
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let guard_was_held_chirho = Cell::new(false);
    let signing_guard_held_chirho = Cell::new(false);
    let verifying_guard_held_chirho = Cell::new(false);
    let probing_signer_chirho = GuardProbingSignerChirho {
        signer_chirho,
        authority_chirho: &handle_chirho,
        signing_guard_held_chirho: &signing_guard_held_chirho,
        verifying_guard_held_chirho: &verifying_guard_held_chirho,
    };
    let verified_chirho = seal_gd7_winner_current_view_chirho(
        storage_chirho,
        &probing_signer_chirho,
        &handle_chirho,
        challenge_chirho,
        &bundle_root_chirho,
        || {
            guard_was_held_chirho.set(matches!(
                handle_chirho.try_acquire_chirho(),
                Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
            ));
            Ok(snapshot_chirho)
        },
    )
    .expect("seal challenged current-view evidence");
    assert!(guard_was_held_chirho.get());
    assert!(signing_guard_held_chirho.get());
    assert!(verifying_guard_held_chirho.get());
    assert!(handle_chirho.try_acquire_chirho().is_ok());
    (issued_challenge_chirho, verified_chirho, bundle_root_chirho)
}

#[test]
fn challenged_current_view_binds_freshness_cut_root_and_generation_chirho() {
    let root_chirho = TestRootChirho::new_chirho("accept");
    let storage_chirho = root_chirho.storage_chirho();
    let winner_node_chirho = NodeIdChirho("11".repeat(32));
    let held_node_chirho = NodeIdChirho("22".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "current-view-group-chirho".to_owned(),
    };
    let signer_chirho = FakeControlSignerChirho::new_chirho(winner_node_chirho.0.clone(), 0x31);
    let (issued_challenge_chirho, sealed_chirho, bundle_root_chirho) = seal_fixture_chirho(
        &storage_chirho,
        &signer_chirho,
        &group_chirho,
        &winner_node_chirho,
    );
    let stable_chirho = stable_follower_leadership_chirho(
        &winner_node_chirho,
        sealed_chirho.evidence_chirho.raft_term_chirho,
    );
    let held_elector_chirho = SequenceElectorChirho::new_chirho(
        held_node_chirho,
        [stable_chirho.clone(), stable_chirho.clone()],
        stable_chirho,
    );
    let expected_inspection_chirho = sealed_chirho.clone().into_inspection_chirho();
    let verified_chirho = inspect_challenged_gd7_winner_current_view_chirho(
        &storage_chirho,
        &signer_chirho,
        &held_elector_chirho,
        &group_chirho,
        &winner_node_chirho,
        issued_challenge_chirho,
        &sealed_chirho.object_digest_chirho,
    )
    .expect("verify challenged current-view response");
    assert_eq!(verified_chirho, expected_inspection_chirho);
    assert_eq!(
        verified_chirho.bundle_root_object_digest_chirho,
        bundle_root_chirho.object_digest_chirho
    );
    assert!(
        verified_chirho
            .evidence_chirho
            .winner_process_generation_chirho
            > 0
    );

    let replay_challenge_chirho = issued_challenge_for_test_chirho(
        &group_chirho,
        &winner_node_chirho,
        verified_chirho.evidence_chirho.raft_term_chirho,
    );
    let replay_leadership_chirho = stable_follower_leadership_chirho(
        &winner_node_chirho,
        verified_chirho.evidence_chirho.raft_term_chirho,
    );
    let replay_elector_chirho = SequenceElectorChirho::new_chirho(
        NodeIdChirho("23".repeat(32)),
        [replay_leadership_chirho.clone()],
        replay_leadership_chirho,
    );
    assert_eq!(
        inspect_challenged_gd7_winner_current_view_chirho(
            &storage_chirho,
            &signer_chirho,
            &replay_elector_chirho,
            &group_chirho,
            &winner_node_chirho,
            replay_challenge_chirho,
            &verified_chirho.evidence_object_digest_chirho,
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho
    );
}

#[test]
fn challenged_current_view_refuses_election_change_between_observations_chirho() {
    let root_chirho = TestRootChirho::new_chirho("leadership-change");
    let storage_chirho = root_chirho.storage_chirho();
    let winner_node_chirho = NodeIdChirho("31".repeat(32));
    let held_node_chirho = NodeIdChirho("32".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "leadership-change-group-chirho".to_owned(),
    };
    let signer_chirho = FakeControlSignerChirho::new_chirho(winner_node_chirho.0.clone(), 0x51);
    let (issued_challenge_chirho, sealed_chirho, _bundle_root_chirho) = seal_fixture_chirho(
        &storage_chirho,
        &signer_chirho,
        &group_chirho,
        &winner_node_chirho,
    );
    let term_chirho = sealed_chirho.evidence_chirho.raft_term_chirho;
    let before_chirho = stable_follower_leadership_chirho(&winner_node_chirho, term_chirho);
    let after_chirho = stable_follower_leadership_chirho(&winner_node_chirho, term_chirho + 1);
    let elector_chirho = SequenceElectorChirho::new_chirho(
        held_node_chirho,
        [before_chirho, after_chirho.clone()],
        after_chirho,
    );
    let reader_chirho =
        Gd7WinnerCurrentViewReaderChirho::new_chirho(&storage_chirho, &signer_chirho);
    assert_eq!(
        reader_chirho
            .verify_challenged_chirho(
                &elector_chirho,
                &group_chirho,
                &winner_node_chirho,
                issued_challenge_chirho,
                &sealed_chirho.object_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::LeadershipChangedChirho
    );
}

#[test]
fn current_view_cut_mismatch_refuses_before_evidence_creation_chirho() {
    let root_chirho = TestRootChirho::new_chirho("cut-mismatch");
    let storage_chirho = root_chirho.storage_chirho();
    let winner_node_chirho = NodeIdChirho("41".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "cut-mismatch-group-chirho".to_owned(),
    };
    let signer_chirho = FakeControlSignerChirho::new_chirho(winner_node_chirho.0.clone(), 0x61);
    let elector_chirho = warm_winner_elector_chirho(&winner_node_chirho, &group_chirho);
    let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
    let issued_challenge_chirho = issued_challenge_for_test_chirho(
        &group_chirho,
        &winner_node_chirho,
        leadership_chirho.term_chirho,
    );
    let challenge_chirho = transport_challenge_for_test_chirho(&issued_challenge_chirho);
    let snapshot_chirho = snapshot_for_test_chirho(leadership_chirho.term_chirho);
    let bundle_root_chirho =
        persist_bundle_root_for_test_chirho(&storage_chirho, &group_chirho, &snapshot_chirho);
    let mut advanced_snapshot_chirho = snapshot_chirho;
    advanced_snapshot_chirho.cut_chirho.seq_chirho += 1;
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    assert_eq!(
        seal_gd7_winner_current_view_chirho(
            &storage_chirho,
            &signer_chirho,
            &handle_chirho,
            challenge_chirho,
            &bundle_root_chirho,
            || Ok(advanced_snapshot_chirho),
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::JournalCutMismatchChirho
    );
    let evidence_prefix_chirho =
        StoragePathChirho::new_chirho("gd7-reconciliation-chirho/winner-current-views-chirho/");
    assert!(storage_chirho
        .list_chirho(&evidence_prefix_chirho)
        .expect("list current-view test evidence")
        .is_empty());
}

#[test]
fn current_view_refuses_cross_group_root_and_wrong_signer_before_creation_chirho() {
    let root_chirho = TestRootChirho::new_chirho("authority-mismatch");
    let storage_chirho = root_chirho.storage_chirho();
    let winner_node_chirho = NodeIdChirho("49".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "authority-group-chirho".to_owned(),
    };
    let other_group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "other-authority-group-chirho".to_owned(),
    };
    let signer_chirho = FakeControlSignerChirho::new_chirho(winner_node_chirho.0.clone(), 0x69);
    let elector_chirho = warm_winner_elector_chirho(&winner_node_chirho, &group_chirho);
    let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
    let snapshot_chirho = snapshot_for_test_chirho(leadership_chirho.term_chirho);
    let wrong_group_root_chirho =
        persist_bundle_root_for_test_chirho(&storage_chirho, &other_group_chirho, &snapshot_chirho);
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let issued_challenge_chirho = issued_challenge_for_test_chirho(
        &group_chirho,
        &winner_node_chirho,
        leadership_chirho.term_chirho,
    );
    assert_eq!(
        seal_gd7_winner_current_view_chirho(
            &storage_chirho,
            &signer_chirho,
            &handle_chirho,
            transport_challenge_for_test_chirho(&issued_challenge_chirho),
            &wrong_group_root_chirho,
            || Ok(snapshot_chirho.clone()),
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::BundleRootMismatchChirho
    );

    let correct_root_chirho =
        persist_bundle_root_for_test_chirho(&storage_chirho, &group_chirho, &snapshot_chirho);
    let wrong_signer_chirho = FakeControlSignerChirho::new_chirho("4a".repeat(32), 0x6a);
    let second_challenge_chirho = issued_challenge_for_test_chirho(
        &group_chirho,
        &winner_node_chirho,
        leadership_chirho.term_chirho,
    );
    assert_eq!(
        seal_gd7_winner_current_view_chirho(
            &storage_chirho,
            &wrong_signer_chirho,
            &handle_chirho,
            transport_challenge_for_test_chirho(&second_challenge_chirho),
            &correct_root_chirho,
            || Ok(snapshot_chirho),
        )
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::WrongSignerChirho
    );
    let evidence_prefix_chirho =
        StoragePathChirho::new_chirho("gd7-reconciliation-chirho/winner-current-views-chirho/");
    assert!(storage_chirho
        .list_chirho(&evidence_prefix_chirho)
        .expect("list authority-mismatch evidence")
        .is_empty());
}

#[test]
fn current_view_root_and_signature_tamper_fail_closed_chirho() {
    let root_chirho = TestRootChirho::new_chirho("tamper");
    let storage_chirho = root_chirho.storage_chirho();
    let winner_node_chirho = NodeIdChirho("51".repeat(32));
    let held_node_chirho = NodeIdChirho("52".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "tamper-group-chirho".to_owned(),
    };
    let signer_chirho = FakeControlSignerChirho::new_chirho(winner_node_chirho.0.clone(), 0x71);
    let (root_challenge_chirho, root_sealed_chirho, bundle_root_chirho) = seal_fixture_chirho(
        &storage_chirho,
        &signer_chirho,
        &group_chirho,
        &winner_node_chirho,
    );
    let root_path_chirho =
        gd7_winner_view_bundle_root_path_chirho(bundle_root_chirho.object_digest_chirho())
            .expect("tampered root path");
    let mut tampered_root_chirho = bundle_root_chirho.root_chirho().clone();
    tampered_root_chirho.row_count_chirho += 1;
    storage_chirho
        .atomic_write_chirho(
            &root_path_chirho,
            &canonical_json_chirho(&tampered_root_chirho).expect("encode tampered root"),
        )
        .expect("write tampered root");
    let term_chirho = root_sealed_chirho.evidence_chirho.raft_term_chirho;
    let stable_chirho = stable_follower_leadership_chirho(&winner_node_chirho, term_chirho);
    let elector_chirho = SequenceElectorChirho::new_chirho(
        held_node_chirho.clone(),
        [stable_chirho.clone()],
        stable_chirho.clone(),
    );
    let reader_chirho =
        Gd7WinnerCurrentViewReaderChirho::new_chirho(&storage_chirho, &signer_chirho);
    assert_eq!(
        reader_chirho
            .verify_challenged_chirho(
                &elector_chirho,
                &group_chirho,
                &winner_node_chirho,
                root_challenge_chirho,
                &root_sealed_chirho.object_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::ObjectDigestMismatchChirho
    );

    let restored_root_bytes_chirho =
        canonical_json_chirho(bundle_root_chirho.root_chirho()).expect("restore root bytes");
    storage_chirho
        .atomic_write_chirho(&root_path_chirho, &restored_root_bytes_chirho)
        .expect("restore exact bundle root");
    let (signature_challenge_chirho, signature_sealed_chirho, _signature_root_chirho) =
        seal_fixture_chirho(
            &storage_chirho,
            &signer_chirho,
            &group_chirho,
            &winner_node_chirho,
        );
    let signature_evidence_path_chirho =
        gd7_winner_current_view_path_chirho(&signature_sealed_chirho.object_digest_chirho)
            .expect("signature current-view evidence path");
    let signature_evidence_bytes_chirho = storage_chirho
        .read_all_chirho(&signature_evidence_path_chirho)
        .expect("read signature current-view evidence")
        .expect("signature current-view evidence exists");
    let mut tampered_evidence_chirho: Gd7WinnerCurrentViewEvidenceChirho =
        serde_json::from_slice(&signature_evidence_bytes_chirho)
            .expect("decode signature current-view evidence");
    tampered_evidence_chirho.sig_chirho = "00".repeat(32);
    let tampered_evidence_bytes_chirho =
        canonical_json_chirho(&tampered_evidence_chirho).expect("encode signature tamper");
    let tampered_evidence_digest_chirho = digest_bytes_chirho(&tampered_evidence_bytes_chirho);
    let tampered_evidence_path_chirho =
        gd7_winner_current_view_path_chirho(&tampered_evidence_digest_chirho)
            .expect("signature-tamper path");
    storage_chirho
        .create_durable_chirho(
            &tampered_evidence_path_chirho,
            &tampered_evidence_bytes_chirho,
        )
        .expect("persist signature tamper");
    let signature_elector_chirho =
        SequenceElectorChirho::new_chirho(held_node_chirho, [stable_chirho.clone()], stable_chirho);
    assert_eq!(
        reader_chirho
            .verify_challenged_chirho(
                &signature_elector_chirho,
                &group_chirho,
                &winner_node_chirho,
                signature_challenge_chirho,
                &tampered_evidence_digest_chirho,
            )
            .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::InvalidSignatureChirho
    );
}

#[test]
fn current_view_challenge_is_exact_canonical_and_bounded_chirho() {
    let winner_node_chirho = NodeIdChirho("61".repeat(32));
    let group_chirho = ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: "challenge-shape-group-chirho".to_owned(),
    };
    let challenge_chirho = challenge_for_test_chirho(&group_chirho, &winner_node_chirho, 3, 0x81);
    let bytes_chirho = challenge_chirho
        .canonical_bytes_chirho()
        .expect("encode canonical challenge");
    let parsed_chirho = parse_canonical_gd7_winner_current_view_challenge_chirho(&bytes_chirho)
        .expect("parse canonical challenge");
    assert_eq!(parsed_chirho, challenge_chirho);

    let mut whitespace_chirho = bytes_chirho.clone();
    whitespace_chirho.push(b'\n');
    assert_eq!(
        parse_canonical_gd7_winner_current_view_challenge_chirho(&whitespace_chirho).unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::InvalidChallengeChirho
    );
    assert_eq!(
        parse_canonical_gd7_winner_current_view_challenge_chirho(&vec![
            b'x';
            MAX_GD7_WINNER_CURRENT_VIEW_CHALLENGE_BYTES_CHIRHO
                + 1
        ])
        .unwrap_err(),
        Gd7WinnerCurrentViewRefusalChirho::OversizedChallengeChirho
    );
}
