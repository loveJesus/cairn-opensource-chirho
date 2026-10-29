// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::port_chirho::require_common_bootstrap_pair_chirho;
use super::{
    LedgerMirrorDenseChainHasherChirho, LedgerMirrorRecoveryHeadReceiptChirho,
    LedgerMirrorVerifiedPrefixManifestChirho, LedgerMirrorVerifiedPrefixManifestInputChirho,
    LedgerMirrorVerifiedPrefixPageChirho, ProductionLedgerMirrorRecoveryInputChirho,
    ProductionLedgerMirrorRecoveryPortChirho, VerifiedLedgerMirrorRecoveryHeadPairChirho,
};
use crate::client_chirho::{private_mesh_agent_chirho, LedgerMirrorDirectoryChirho};
use crate::server_chirho::{ledger_mirror_router_chirho, LedgerMirrorServerStateChirho};
use crate::store_chirho::{
    LedgerMirrorBootstrapCommitPreparationChirho, LedgerMirrorBootstrapHeadChirho,
    LedgerMirrorFollowerStoreChirho, LedgerMirrorRecoverySourceHeadChirho,
};
use crate::tests_chirho::{
    election_observation_chirho, journal_verifier_chirho, placement_fixture_chirho,
    placement_successor_fixture_chirho, provision_node_chirho, recovery_journal_fixture_chirho,
    signed_record_chirho, FixedElectionViewChirho, RunningMirrorServerChirho,
    GENESIS_DIGEST_CHIRHO, JOURNAL_KEY_ID_CHIRHO,
};
use cairn_ledger_log_chirho::losing_suffix_chirho::{
    LosingSuffixCursorChirho, LosingSuffixPageRequestChirho, LosingSuffixReadErrorChirho,
    LosingSuffixReaderChirho, VerifiedLosingJournalTailChirho, VerifiedLosingSuffixPageChirho,
};
use cairn_ledger_log_chirho::recovery_mirror_chirho::{
    LedgerMirrorOrdinaryTermAcceptanceReceiptChirho, LedgerMirrorPrefixSourceChirho,
    LedgerMirrorRecoveryPortChirho, LedgerMirrorRecoveryPortErrorChirho,
};
use cairn_mirror_chirho::{
    join_mirror_view_chirho, MirrorLeadershipViewChirho, MirrorResidencyPolicyChirho,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

const GROUP_DIGEST_CHIRHO: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const ASSIGNMENT_DIGEST_CHIRHO: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
const VIEW_DIGEST_CHIRHO: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const PREDECESSOR_BOOTSTRAP_ASSIGNMENT_DIGEST_CHIRHO: &str =
    "7777777777777777777777777777777777777777777777777777777777777777";

pub(super) struct TestCanonicalHistorySourceChirho {
    pub(super) anchor_mismatch_chirho: bool,
}

impl LosingSuffixReaderChirho for TestCanonicalHistorySourceChirho {
    fn injected_journal_key_id_chirho(&self) -> String {
        JOURNAL_KEY_ID_CHIRHO.to_string()
    }

    fn revalidate_current_losing_tail_chirho(
        &self,
    ) -> Result<VerifiedLosingJournalTailChirho, LosingSuffixReadErrorChirho> {
        panic!("test canonical source does not revalidate a tail")
    }

    fn decode_verified_losing_suffix_cursor_chirho(
        &self,
        _bytes_chirho: &[u8],
    ) -> Result<LosingSuffixCursorChirho, LosingSuffixReadErrorChirho> {
        panic!("test canonical source does not decode cursors")
    }

    fn read_verified_losing_suffix_page_chirho(
        &self,
        _request_chirho: &LosingSuffixPageRequestChirho,
    ) -> Result<VerifiedLosingSuffixPageChirho, LosingSuffixReadErrorChirho> {
        if self.anchor_mismatch_chirho {
            return Err(LosingSuffixReadErrorChirho::AnchorDigestMismatchChirho);
        }
        panic!("a non-behind source head must not traverse canonical history")
    }
}

impl LedgerMirrorPrefixSourceChirho for TestCanonicalHistorySourceChirho {
    fn canonical_genesis_line_chirho(&self) -> Result<String, LedgerMirrorRecoveryPortErrorChirho> {
        panic!("candidate selection does not read canonical genesis")
    }
}

struct RecoveryFixtureChirho {
    leader_root_chirho: tempfile::TempDir,
    leader_node_id_chirho: String,
    first_holder_root_chirho: tempfile::TempDir,
    first_holder_node_id_chirho: String,
    second_holder_root_chirho: tempfile::TempDir,
    second_holder_node_id_chirho: String,
    journal_root_chirho: tempfile::TempDir,
}

pub(super) struct RecoveryManifestBindingChirho<'binding_chirho> {
    pub(super) leader_root_chirho: &'binding_chirho Path,
    pub(super) leader_node_id_chirho: &'binding_chirho str,
    pub(super) assigned_node_ids_chirho: [String; 3],
    pub(super) consistency_group_digest_chirho: &'binding_chirho str,
    pub(super) assignment_digest_chirho: &'binding_chirho str,
    pub(super) membership_view_digest_chirho: &'binding_chirho str,
    pub(super) expected_term_chirho: u64,
}

impl RecoveryFixtureChirho {
    fn new_chirho() -> Self {
        let leader_root_chirho = tempfile::tempdir().expect("leader root");
        let first_holder_root_chirho = tempfile::tempdir().expect("first holder root");
        let second_holder_root_chirho = tempfile::tempdir().expect("second holder root");
        let journal_root_chirho = tempfile::tempdir().expect("journal root");
        let leader_node_id_chirho = provision_node_chirho(leader_root_chirho.path());
        let first_holder_node_id_chirho = provision_node_chirho(first_holder_root_chirho.path());
        let second_holder_node_id_chirho = provision_node_chirho(second_holder_root_chirho.path());
        provision_node_chirho(journal_root_chirho.path());
        Self {
            leader_root_chirho,
            leader_node_id_chirho,
            first_holder_root_chirho,
            first_holder_node_id_chirho,
            second_holder_root_chirho,
            second_holder_node_id_chirho,
            journal_root_chirho,
        }
    }

    fn assigned_node_ids_chirho(&self) -> [String; 3] {
        [
            self.leader_node_id_chirho.clone(),
            self.first_holder_node_id_chirho.clone(),
            self.second_holder_node_id_chirho.clone(),
        ]
    }

    fn manifest_chirho(
        &self,
        dense_chain_digest_override_chirho: Option<String>,
    ) -> (
        LedgerMirrorVerifiedPrefixManifestChirho,
        crate::family_chirho::LedgerMirrorRecordChirho,
    ) {
        let record_chirho =
            signed_record_chirho(self.journal_root_chirho.path(), JOURNAL_KEY_ID_CHIRHO);
        let mut hasher_chirho = LedgerMirrorDenseChainHasherChirho::new_chirho();
        hasher_chirho
            .update_chirho(&record_chirho)
            .expect("hash record");
        let (record_count_chirho, dense_chain_digest_chirho) = hasher_chirho.finish_chirho();
        let manifest_chirho = LedgerMirrorVerifiedPrefixManifestChirho::sign_chirho(
            LedgerMirrorVerifiedPrefixManifestInputChirho {
                origin_leader_node_id_chirho: self.leader_node_id_chirho.clone(),
                consistency_group_digest_chirho: GROUP_DIGEST_CHIRHO.to_string(),
                assignment_digest_chirho: ASSIGNMENT_DIGEST_CHIRHO.to_string(),
                assigned_node_ids_chirho: self.assigned_node_ids_chirho(),
                expected_term_chirho: 7,
                membership_view_digest_chirho: VIEW_DIGEST_CHIRHO.to_string(),
                cluster_id_chirho: record_chirho.cluster_id_chirho.clone(),
                journal_genesis_digest_chirho: GENESIS_DIGEST_CHIRHO.to_string(),
                tail_seq_chirho: record_chirho.record_seq_chirho,
                tail_record_digest_chirho: record_chirho.record_digest_chirho.clone(),
                tail_epoch_chirho: record_chirho.record_epoch_chirho,
                tail_hlc_physical_ms_chirho: record_chirho.record_hlc_physical_ms_chirho,
                tail_hlc_logical_chirho: record_chirho.record_hlc_logical_chirho,
                record_count_chirho,
                dense_chain_digest_chirho: dense_chain_digest_override_chirho
                    .unwrap_or(dense_chain_digest_chirho),
            },
            self.leader_root_chirho.path(),
        )
        .expect("sign prefix manifest");
        (manifest_chirho, record_chirho)
    }

    fn follower_store_chirho(
        &self,
        root_chirho: &Path,
        holder_node_id_chirho: &str,
    ) -> LedgerMirrorFollowerStoreChirho {
        LedgerMirrorFollowerStoreChirho::open_chirho(
            root_chirho,
            holder_node_id_chirho.to_string(),
            journal_verifier_chirho(self.journal_root_chirho.path()),
        )
        .expect("open follower store")
    }
}

pub(super) fn manifest_for_record_chirho(
    binding_chirho: RecoveryManifestBindingChirho<'_>,
    record_chirho: &crate::family_chirho::LedgerMirrorRecordChirho,
    tail_digest_override_chirho: Option<String>,
) -> LedgerMirrorVerifiedPrefixManifestChirho {
    let mut hasher_chirho = LedgerMirrorDenseChainHasherChirho::new_chirho();
    hasher_chirho
        .update_chirho(record_chirho)
        .expect("hash recovery record");
    let (record_count_chirho, dense_chain_digest_chirho) = hasher_chirho.finish_chirho();
    LedgerMirrorVerifiedPrefixManifestChirho::sign_chirho(
        LedgerMirrorVerifiedPrefixManifestInputChirho {
            origin_leader_node_id_chirho: binding_chirho.leader_node_id_chirho.to_string(),
            consistency_group_digest_chirho: binding_chirho
                .consistency_group_digest_chirho
                .to_string(),
            assignment_digest_chirho: binding_chirho.assignment_digest_chirho.to_string(),
            assigned_node_ids_chirho: binding_chirho.assigned_node_ids_chirho,
            expected_term_chirho: binding_chirho.expected_term_chirho,
            membership_view_digest_chirho: binding_chirho.membership_view_digest_chirho.to_string(),
            cluster_id_chirho: record_chirho.cluster_id_chirho.clone(),
            journal_genesis_digest_chirho: record_chirho.journal_genesis_digest_chirho.clone(),
            tail_seq_chirho: record_chirho.record_seq_chirho,
            tail_record_digest_chirho: tail_digest_override_chirho
                .unwrap_or_else(|| record_chirho.record_digest_chirho.clone()),
            tail_epoch_chirho: record_chirho.record_epoch_chirho,
            tail_hlc_physical_ms_chirho: record_chirho.record_hlc_physical_ms_chirho,
            tail_hlc_logical_chirho: record_chirho.record_hlc_logical_chirho,
            record_count_chirho,
            dense_chain_digest_chirho,
        },
        binding_chirho.leader_root_chirho,
    )
    .expect("sign recovery prefix manifest")
}

pub(super) fn residency_chirho(
    placement_chirho: &cairn_tenant_placement_authority_chirho::VerifiedTenantPlacementChirho,
) -> MirrorResidencyPolicyChirho {
    MirrorResidencyPolicyChirho::allowed_domains_chirho(
        placement_chirho
            .intent_chirho()
            .residency_chirho
            .allowed_domains_chirho
            .clone(),
    )
}

pub(super) fn commit_prefix_chirho(
    store_chirho: &LedgerMirrorFollowerStoreChirho,
    holder_root_chirho: &Path,
    manifest_chirho: &LedgerMirrorVerifiedPrefixManifestChirho,
    record_chirho: &crate::family_chirho::LedgerMirrorRecordChirho,
) -> LedgerMirrorRecoveryHeadReceiptChirho {
    assert!(!store_chirho
        .begin_verified_prefix_chirho(manifest_chirho.clone(), None)
        .expect("begin prefix"));
    store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                manifest_chirho.manifest_digest_chirho().to_string(),
                0,
                vec![record_chirho.clone()],
            )
            .expect("build page"),
        )
        .expect("stage page");
    let LedgerMirrorBootstrapCommitPreparationChirho::SignChirho(input_chirho) = store_chirho
        .prepare_bootstrap_commit_chirho(manifest_chirho.manifest_digest_chirho())
        .expect("prepare bootstrap commit")
    else {
        panic!("first commit requires a signature");
    };
    let head_chirho =
        LedgerMirrorBootstrapHeadChirho::sign_chirho(*input_chirho, holder_root_chirho)
            .expect("sign bootstrap head");
    store_chirho
        .commit_bootstrap_chirho(head_chirho)
        .expect("commit bootstrap head");
    let source_chirho = store_chirho
        .load_recovery_source_head_chirho()
        .expect("load source head")
        .expect("source head present");
    assert!(matches!(
        source_chirho,
        LedgerMirrorRecoverySourceHeadChirho::BootstrapChirho(_)
    ));
    LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
        &source_chirho,
        holder_root_chirho,
    )
    .expect("sign recovery receipt")
}

#[test]
fn recovery_receipt_cannot_replay_as_ordinary_term_acceptance_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let recovery_receipt_chirho = commit_prefix_chirho(
        &store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let recovery_wire_chirho = recovery_receipt_chirho
        .to_wire_bytes_chirho()
        .expect("encode one valid recovery-domain receipt");
    let refusal_chirho =
        match LedgerMirrorOrdinaryTermAcceptanceReceiptChirho::decode_and_verify_chirho(
            &recovery_wire_chirho,
        ) {
            Ok(_) => {
                panic!("a valid recovery signature cannot enter the ordinary-term receipt domain")
            }
            Err(error_chirho) => error_chirho,
        };
    assert_eq!(
        refusal_chirho.detail_chirho(),
        "OrdinaryTermReceiptMalformedChirho"
    );
}

#[test]
fn staged_prefix_is_inert_until_the_signed_bootstrap_head_commits_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );

    assert!(!store_chirho
        .begin_verified_prefix_chirho(manifest_chirho.clone(), None)
        .expect("begin prefix"));
    assert!(store_chirho
        .load_recovery_source_head_chirho()
        .expect("read pre-page source")
        .is_none());
    store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                manifest_chirho.manifest_digest_chirho().to_string(),
                0,
                vec![record_chirho.clone()],
            )
            .expect("build page"),
        )
        .expect("stage page");
    assert!(store_chirho
        .load_recovery_source_head_chirho()
        .expect("read staged source")
        .is_none());

    let LedgerMirrorBootstrapCommitPreparationChirho::SignChirho(input_chirho) = store_chirho
        .prepare_bootstrap_commit_chirho(manifest_chirho.manifest_digest_chirho())
        .expect("prepare commit")
    else {
        panic!("first commit requires signature");
    };
    let head_chirho = LedgerMirrorBootstrapHeadChirho::sign_chirho(
        *input_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
    )
    .expect("sign head");
    store_chirho
        .commit_bootstrap_chirho(head_chirho)
        .expect("commit head");
    let source_chirho = store_chirho
        .load_recovery_source_head_chirho()
        .expect("read committed source")
        .expect("committed source exists");
    assert_eq!(
        source_chirho.tail_record_chirho().record_digest_chirho,
        record_chirho.record_digest_chirho
    );
    assert!(store_chirho
        .begin_verified_prefix_chirho(manifest_chirho.clone(), None)
        .expect("idempotent begin sees committed manifest"));
    assert!(matches!(
        store_chirho
            .prepare_bootstrap_commit_chirho(manifest_chirho.manifest_digest_chirho())
            .expect("idempotent commit preparation"),
        LedgerMirrorBootstrapCommitPreparationChirho::AlreadyCommittedChirho
    ));
}

#[test]
fn same_leader_term_advance_reuses_the_exact_historical_prefix_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (initial_manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let initial_receipt_chirho = commit_prefix_chirho(
        &store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &initial_manifest_chirho,
        &record_chirho,
    );
    let next_view_digest_chirho = "4".repeat(64);
    let incompatible_assignment_chirho = "5".repeat(64);
    let incompatible_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: initial_manifest_chirho
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: &incompatible_assignment_chirho,
            membership_view_digest_chirho: &next_view_digest_chirho,
            expected_term_chirho: initial_manifest_chirho.expected_term_chirho() + 1,
        },
        &record_chirho,
        None,
    );
    assert!(!store_chirho
        .begin_verified_prefix_chirho(incompatible_manifest_chirho.clone(), None)
        .expect("a changed placement binding stages instead of reusing history"));
    store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                incompatible_manifest_chirho
                    .manifest_digest_chirho()
                    .to_string(),
                0,
                vec![record_chirho.clone()],
            )
            .expect("build inert incompatible stage"),
        )
        .expect("complete inert incompatible stage");

    let next_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: initial_manifest_chirho
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: initial_manifest_chirho.assignment_digest_chirho(),
            membership_view_digest_chirho: &next_view_digest_chirho,
            expected_term_chirho: initial_manifest_chirho.expected_term_chirho() + 1,
        },
        &record_chirho,
        None,
    );
    assert!(store_chirho
        .begin_verified_prefix_chirho(next_manifest_chirho.clone(), None)
        .expect("a current manifest may reuse the same leader's exact historical prefix"));
    let stale_stage_refusal_chirho = match store_chirho
        .prepare_bootstrap_commit_chirho(incompatible_manifest_chirho.manifest_digest_chirho())
    {
        Ok(_) => panic!("reusing the committed prefix must clear stale inert staging"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(stale_stage_refusal_chirho.contains("LedgerMirrorPrefixStageUnavailableChirho"));

    let source_chirho = store_chirho
        .load_recovery_source_head_chirho()
        .expect("load reused historical source")
        .expect("historical source remains present");
    let reused_receipt_chirho =
        LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
            &source_chirho,
            fixture_chirho.first_holder_root_chirho.path(),
        )
        .expect("sign receipt from unchanged historical head");
    assert_eq!(
        reused_receipt_chirho.historical_term_chirho(),
        initial_receipt_chirho.historical_term_chirho()
    );
    assert_eq!(
        reused_receipt_chirho.source_manifest_digest_chirho(),
        initial_receipt_chirho.source_manifest_digest_chirho()
    );
    assert_ne!(
        reused_receipt_chirho.source_manifest_digest_chirho(),
        Some(next_manifest_chirho.manifest_digest_chirho())
    );
}

#[test]
fn older_current_term_cannot_reuse_a_newer_historical_prefix_head_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (initial_manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    commit_prefix_chirho(
        &store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &initial_manifest_chirho,
        &record_chirho,
    );
    let older_view_digest_chirho = "6".repeat(64);
    let older_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: initial_manifest_chirho
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: initial_manifest_chirho.assignment_digest_chirho(),
            membership_view_digest_chirho: &older_view_digest_chirho,
            expected_term_chirho: initial_manifest_chirho.expected_term_chirho() - 1,
        },
        &record_chirho,
        None,
    );
    let refusal_chirho = store_chirho
        .begin_verified_prefix_chirho(older_manifest_chirho, None)
        .expect_err("current authority cannot move behind the durable historical term")
        .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorBootstrapHeadAuthorityRollbackRefusedChirho"));

    let successor_assignment_digest_chirho = "7".repeat(64);
    let divergent_group_digest_chirho = "8".repeat(64);
    let successor_view_digest_chirho = "9".repeat(64);
    let divergent_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: &divergent_group_digest_chirho,
            assignment_digest_chirho: &successor_assignment_digest_chirho,
            membership_view_digest_chirho: &successor_view_digest_chirho,
            expected_term_chirho: initial_manifest_chirho.expected_term_chirho() + 1,
        },
        &record_chirho,
        None,
    );
    assert!(!store_chirho
        .begin_verified_prefix_chirho(
            divergent_manifest_chirho.clone(),
            Some(initial_manifest_chirho.assignment_digest_chirho()),
        )
        .expect("a non-assignment mismatch must stage even with predecessor authority"));
    store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                divergent_manifest_chirho
                    .manifest_digest_chirho()
                    .to_string(),
                0,
                vec![record_chirho.clone()],
            )
            .expect("build completed divergent prefix stage"),
        )
        .expect("complete divergent prefix stage");

    let predecessor_rollback_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: initial_manifest_chirho
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: &successor_assignment_digest_chirho,
            membership_view_digest_chirho: &older_view_digest_chirho,
            expected_term_chirho: initial_manifest_chirho.expected_term_chirho() - 1,
        },
        &record_chirho,
        None,
    );
    let predecessor_refusal_chirho = store_chirho
        .begin_verified_prefix_chirho(
            predecessor_rollback_manifest_chirho,
            Some(initial_manifest_chirho.assignment_digest_chirho()),
        )
        .expect_err("predecessor reuse must not bypass the authority rollback guard")
        .to_string();
    assert!(predecessor_refusal_chirho
        .contains("LedgerMirrorBootstrapHeadAuthorityRollbackRefusedChirho"));
    assert!(matches!(
        store_chirho
            .prepare_bootstrap_commit_chirho(divergent_manifest_chirho.manifest_digest_chirho())
            .expect("hard predecessor refusal must leave the existing stage untouched"),
        LedgerMirrorBootstrapCommitPreparationChirho::SignChirho(_)
    ));
}

#[test]
fn historical_bootstrap_reuse_requires_one_common_two_holder_binding_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let first_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let second_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.second_holder_root_chirho.path(),
        &fixture_chirho.second_holder_node_id_chirho,
    );
    let first_receipt_chirho = commit_prefix_chirho(
        &first_store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let second_receipt_chirho = commit_prefix_chirho(
        &second_store_chirho,
        fixture_chirho.second_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    require_common_bootstrap_pair_chirho(&first_receipt_chirho, &second_receipt_chirho)
        .expect("the common historical bootstrap pair remains reusable");

    let divergent_receipt_chirho = second_receipt_chirho
        .resign_source_for_test_chirho(
            "verified-prefix-bootstrap-chirho",
            Some("f".repeat(64)),
            fixture_chirho.second_holder_root_chirho.path(),
        )
        .expect("sign a record-valid mixed-manifest fixture");
    let refusal_chirho =
        require_common_bootstrap_pair_chirho(&first_receipt_chirho, &divergent_receipt_chirho)
            .expect_err("mixed historical manifests cannot pass current-holder readiness")
            .to_string();
    assert_eq!(
        refusal_chirho,
        "LedgerMirrorCurrentHolderPrefixBindingRefusedChirho"
    );

    let live_twin_chirho = second_receipt_chirho
        .resign_source_for_test_chirho(
            "live-high-water-chirho",
            None,
            fixture_chirho.second_holder_root_chirho.path(),
        )
        .expect("sign the source-kind boundary fixture");
    require_common_bootstrap_pair_chirho(&first_receipt_chirho, &live_twin_chirho)
        .expect("the common-bootstrap check does not reject supported mixed source kinds");
}

#[test]
fn truncated_or_digest_divergent_prefix_cannot_mint_a_bootstrap_head_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    store_chirho
        .begin_verified_prefix_chirho(manifest_chirho.clone(), None)
        .expect("begin truncated prefix");
    let error_chirho = match store_chirho
        .prepare_bootstrap_commit_chirho(manifest_chirho.manifest_digest_chirho())
    {
        Ok(_) => panic!("truncated prefix must refuse"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(error_chirho.contains("LedgerMirrorPrefixStageIncompleteChirho"));

    let (wrong_manifest_chirho, _) = fixture_chirho.manifest_chirho(Some("a".repeat(64)));
    store_chirho
        .begin_verified_prefix_chirho(wrong_manifest_chirho.clone(), None)
        .expect("replace with wrong closure manifest");
    store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                wrong_manifest_chirho.manifest_digest_chirho().to_string(),
                0,
                vec![record_chirho],
            )
            .expect("build divergent page"),
        )
        .expect("stage divergent page");
    let error_chirho = match store_chirho
        .prepare_bootstrap_commit_chirho(wrong_manifest_chirho.manifest_digest_chirho())
    {
        Ok(_) => panic!("wrong dense closure must refuse"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(error_chirho.contains("LedgerMirrorPrefixSealClosureRefusedChirho"));
}

#[test]
fn recovery_cut_requires_the_exact_two_holders_of_one_bootstrap_manifest_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let first_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let second_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.second_holder_root_chirho.path(),
        &fixture_chirho.second_holder_node_id_chirho,
    );
    let first_receipt_chirho = commit_prefix_chirho(
        &first_store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let second_receipt_chirho = commit_prefix_chirho(
        &second_store_chirho,
        fixture_chirho.second_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let pair_chirho = VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
        first_receipt_chirho.clone(),
        second_receipt_chirho,
    )
    .expect("exact historical holder pair joins");
    assert_eq!(pair_chirho.tail_seq_chirho(), 1);
    let error_chirho = VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
        first_receipt_chirho.clone(),
        first_receipt_chirho,
    )
    .expect_err("one holder cannot substitute for the pair")
    .to_string();
    assert!(error_chirho.contains("LedgerMirrorRecoveryHeadPopulationRefusedChirho"));
    assert!(!error_chirho.contains("LedgerMirrorRecoveryHeadTailMismatchRefusedChirho"));
}

#[test]
fn recovery_head_tail_mismatch_is_distinct_from_an_absent_holder_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let first_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let second_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.second_holder_root_chirho.path(),
        &fixture_chirho.second_holder_node_id_chirho,
    );
    let first_receipt_chirho = commit_prefix_chirho(
        &first_store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let second_receipt_chirho = commit_prefix_chirho(
        &second_store_chirho,
        fixture_chirho.second_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    )
    .resign_tail_for_test_chirho(
        2,
        "4".repeat(64),
        fixture_chirho.second_holder_root_chirho.path(),
    )
    .expect("sign a mismatched forward tail under the real second-holder key");

    let refusal_chirho = VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
        first_receipt_chirho,
        second_receipt_chirho,
    )
    .expect_err("the adopter cannot advance beyond the other holder's exact tail")
    .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorRecoveryHeadTailMismatchRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorRecoveryHeadPopulationRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorRecoveryHeadUnavailableChirho"));
}

#[test]
fn valid_foreign_cluster_signature_cannot_substitute_for_the_assigned_holder_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let foreign_root_chirho = tempfile::tempdir().expect("foreign signer root");
    provision_node_chirho(foreign_root_chirho.path());
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.second_holder_root_chirho.path(),
        &fixture_chirho.second_holder_node_id_chirho,
    );
    let assigned_receipt_chirho = commit_prefix_chirho(
        &store_chirho,
        fixture_chirho.second_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let foreign_signed_chirho = assigned_receipt_chirho
        .replace_signature_for_test_chirho(foreign_root_chirho.path())
        .expect("replace only the holder signature with another valid node key");
    let wire_chirho = serde_json::to_vec(&foreign_signed_chirho).expect("encode adversarial head");

    let refusal_chirho = LedgerMirrorRecoveryHeadReceiptChirho::decode_and_verify_chirho(
        &wire_chirho,
        &fixture_chirho.second_holder_node_id_chirho,
    )
    .expect_err("a valid non-holder signer must not satisfy the assigned holder slot")
    .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorRecoveryHeadSignatureRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorRecoveryHeadHolderIdentityRefusedChirho"));
}

#[test]
fn older_valid_matching_pair_remains_admissible_without_a_monotonic_head_anchor_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let first_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    let second_store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.second_holder_root_chirho.path(),
        &fixture_chirho.second_holder_node_id_chirho,
    );
    let old_first_chirho = commit_prefix_chirho(
        &first_store_chirho,
        fixture_chirho.first_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );
    let old_second_chirho = commit_prefix_chirho(
        &second_store_chirho,
        fixture_chirho.second_holder_root_chirho.path(),
        &manifest_chirho,
        &record_chirho,
    );

    let old_pair_chirho = VerifiedLedgerMirrorRecoveryHeadPairChirho::join_chirho(
        old_first_chirho,
        old_second_chirho,
    )
    .expect("an internally consistent older signed pair remains admissible today");
    assert_eq!(old_pair_chirho.tail_seq_chirho(), 1);
    assert!(
        old_pair_chirho.tail_seq_chirho() < 2,
        "executable nonclaim: no monotonic-head substrate proves this pair is the newest pair"
    );
}

#[test]
fn two_empty_historical_holder_stores_select_bootstrap_instead_of_recovery_chirho() {
    let placement_fixture_chirho = placement_fixture_chirho();
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let leader_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let local_store_root_chirho = tempfile::tempdir().expect("local empty follower store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            leader_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open local empty follower store"),
    );

    let mut remote_root_custody_chirho = Vec::new();
    let mut remote_server_custody_chirho = Vec::new();
    let mut endpoints_chirho = BTreeMap::new();
    for holder_chirho in &placement_fixture_chirho.serving_nodes_chirho[1..] {
        let remote_root_chirho = tempfile::tempdir().expect("remote empty follower store");
        let remote_store_chirho = Arc::new(
            LedgerMirrorFollowerStoreChirho::open_chirho(
                remote_root_chirho.path(),
                holder_chirho.node_id_chirho.clone(),
                journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
            )
            .expect("open remote empty follower store"),
        );
        let remote_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
            Arc::new(FixedElectionViewChirho {
                observation_chirho: election_observation_chirho(
                    &placement_fixture_chirho.placement_chirho,
                    &leader_chirho.node_id_chirho,
                    false,
                ),
            });
        let remote_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
            holder_chirho.node_id_chirho.clone(),
            holder_chirho.root_chirho().to_path_buf(),
            Arc::clone(&placement_fixture_chirho.placement_chirho),
            remote_election_chirho,
            residency_chirho(&placement_fixture_chirho.placement_chirho),
            remote_store_chirho,
        )
        .expect("compose empty remote recovery server");
        let remote_server_chirho = RunningMirrorServerChirho::start_chirho(
            ledger_mirror_router_chirho(remote_state_chirho),
        );
        endpoints_chirho.insert(
            holder_chirho.node_id_chirho.clone(),
            remote_server_chirho.endpoint_chirho.clone(),
        );
        remote_root_custody_chirho.push(remote_root_chirho);
        remote_server_custody_chirho.push(remote_server_chirho);
    }
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: leader_chirho.node_id_chirho.clone(),
            sign_root_chirho: leader_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: leader_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(endpoints_chirho),
            follower_store_chirho: local_store_chirho,
        },
    );

    assert!(recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &TestCanonicalHistorySourceChirho {
                anchor_mismatch_chirho: false,
            },
        )
        .expect("two absent heads select first bootstrap")
        .is_none());
    assert_eq!(remote_root_custody_chirho.len(), 2);
    assert_eq!(remote_server_custody_chirho.len(), 2);
}

#[test]
fn production_recovery_refuses_when_the_second_historical_holder_head_is_unavailable_chirho() {
    let placement_fixture_chirho = placement_fixture_chirho();
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let historical_leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let adopter_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let remote_holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[2];
    let local_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        local_election_chirho.as_ref(),
    )
    .expect("join adopter election and placement");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned nodes");
    let manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: historical_leader_chirho.root_chirho(),
            leader_node_id_chirho: &historical_leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let local_store_root_chirho = tempfile::tempdir().expect("local recovery holder store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            adopter_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open adopter follower store"),
    );
    commit_prefix_chirho(
        &local_store_chirho,
        adopter_chirho.root_chirho(),
        &manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );

    let remote_store_root_chirho = tempfile::tempdir().expect("remote recovery holder store");
    let remote_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            remote_store_root_chirho.path(),
            remote_holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open empty remote follower store"),
    );
    let remote_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                false,
            ),
        });
    let remote_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        remote_holder_chirho.node_id_chirho.clone(),
        remote_holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        remote_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        remote_store_chirho,
    )
    .expect("compose empty remote recovery server");
    let remote_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(remote_state_chirho));
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        remote_holder_chirho.node_id_chirho.clone(),
        remote_server_chirho.endpoint_chirho.clone(),
    )]));
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: adopter_chirho.node_id_chirho.clone(),
            sign_root_chirho: adopter_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: local_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho,
            follower_store_chirho: local_store_chirho,
        },
    );

    let refusal_chirho = recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.local_tail_chirho,
            &TestCanonicalHistorySourceChirho {
                anchor_mismatch_chirho: false,
            },
        )
        .expect_err("recovery must not degrade to the adopter's one available holder head");
    assert!(
        refusal_chirho
            .detail_chirho()
            .contains("LedgerMirrorRecoveryHeadUnavailableChirho"),
        "unexpected missing-holder refusal: {}",
        refusal_chirho.detail_chirho()
    );
    assert!(!refusal_chirho
        .detail_chirho()
        .contains("LedgerMirrorRecoveryHeadTailMismatchRefusedChirho"));
}

#[test]
fn behind_local_head_that_contradicts_canonical_history_refuses_before_remote_selection_chirho() {
    let placement_fixture_chirho = placement_fixture_chirho();
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let historical_leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let adopter_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let local_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &adopter_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        local_election_chirho.as_ref(),
    )
    .expect("join adopter election and placement");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned nodes");
    let manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: historical_leader_chirho.root_chirho(),
            leader_node_id_chirho: &historical_leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let local_store_root_chirho = tempfile::tempdir().expect("local recovery holder store");
    let local_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            local_store_root_chirho.path(),
            adopter_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open adopter follower store"),
    );
    commit_prefix_chirho(
        &local_store_chirho,
        adopter_chirho.root_chirho(),
        &manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );
    let recovery_chirho = ProductionLedgerMirrorRecoveryPortChirho::new_chirho(
        ProductionLedgerMirrorRecoveryInputChirho {
            local_node_id_chirho: adopter_chirho.node_id_chirho.clone(),
            sign_root_chirho: adopter_chirho.root_chirho().to_path_buf(),
            placement_chirho: Arc::clone(&placement_fixture_chirho.placement_chirho),
            election_view_chirho: local_election_chirho,
            residency_chirho: residency_chirho(&placement_fixture_chirho.placement_chirho),
            directory_chirho: LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::new()),
            follower_store_chirho: local_store_chirho,
        },
    );

    let refusal_chirho = recovery_chirho
        .select_recovery_candidate_chirho(
            &journal_fixture_chirho.advanced_local_tail_chirho,
            &TestCanonicalHistorySourceChirho {
                anchor_mismatch_chirho: true,
            },
        )
        .expect_err("a behind but contradictory local head must never be discarded as stale");
    assert!(
        refusal_chirho
            .detail_chirho()
            .contains("LedgerMirrorLocalRecoveryHeadCanonicalHistoryDivergenceRefusedChirho"),
        "unexpected canonical-history refusal: {}",
        refusal_chirho.detail_chirho()
    );
    assert!(!refusal_chirho
        .detail_chirho()
        .contains("LedgerMirrorRecoveryHeadUnavailableChirho"));
    assert!(!refusal_chirho
        .detail_chirho()
        .contains("LedgerMirrorRecoveryHeadBindingMismatchRefusedChirho"));
}

#[test]
fn current_leader_term_mismatch_refuses_prefix_transfer_before_staging_chirho() {
    let placement_fixture_chirho = placement_fixture_chirho();
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let leader_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        leader_election_chirho.as_ref(),
    )
    .expect("join current leader view");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned nodes");
    let wrong_term_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho() + 1,
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let holder_store_root_chirho = tempfile::tempdir().expect("holder prefix store");
    let holder_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            holder_store_root_chirho.path(),
            holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open holder prefix store"),
    );
    let holder_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let holder_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        holder_chirho.node_id_chirho.clone(),
        holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        holder_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        Arc::clone(&holder_store_chirho),
    )
    .expect("compose holder prefix server");
    let holder_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(holder_state_chirho));
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        holder_chirho.node_id_chirho.clone(),
        holder_server_chirho.endpoint_chirho.clone(),
    )]));

    let refusal_chirho = directory_chirho
        .begin_verified_prefix_chirho(
            &holder_chirho.node_id_chirho,
            &wrong_term_manifest_chirho,
            &private_mesh_agent_chirho(),
        )
        .expect_err("a manifest signed for a non-current term must refuse")
        .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorPrefixManifestAuthorityRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorPrefixManifestSignatureRefusedChirho"));
    assert!(holder_store_chirho
        .load_recovery_source_head_chirho()
        .expect("inspect holder source head")
        .is_none());
}

#[test]
fn successor_authority_reuses_its_signed_predecessor_prefix_over_http_chirho() {
    let placement_fixture_chirho =
        placement_successor_fixture_chirho(PREDECESSOR_BOOTSTRAP_ASSIGNMENT_DIGEST_CHIRHO);
    let journal_fixture_chirho = recovery_journal_fixture_chirho();
    let leader_chirho = &placement_fixture_chirho.serving_nodes_chirho[0];
    let holder_chirho = &placement_fixture_chirho.serving_nodes_chirho[1];
    let leader_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                true,
            ),
        });
    let joined_chirho = join_mirror_view_chirho(
        &placement_fixture_chirho.placement_chirho,
        leader_election_chirho.as_ref(),
    )
    .expect("join current leader view");
    let assigned_node_ids_chirho: [String; 3] = placement_fixture_chirho
        .placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|binding_chirho| binding_chirho.node_id_chirho.clone())
        .collect::<Vec<_>>()
        .try_into()
        .expect("three assigned nodes");
    let old_view_digest_chirho = "8".repeat(64);
    let old_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho: assigned_node_ids_chirho.clone(),
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: PREDECESSOR_BOOTSTRAP_ASSIGNMENT_DIGEST_CHIRHO,
            membership_view_digest_chirho: &old_view_digest_chirho,
            expected_term_chirho: joined_chirho.term_chirho() - 1,
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    let holder_store_root_chirho = tempfile::tempdir().expect("holder prefix store");
    let holder_store_chirho = Arc::new(
        LedgerMirrorFollowerStoreChirho::open_chirho(
            holder_store_root_chirho.path(),
            holder_chirho.node_id_chirho.clone(),
            journal_verifier_chirho(journal_fixture_chirho.journal_root_chirho.path()),
        )
        .expect("open holder prefix store"),
    );
    let old_receipt_chirho = commit_prefix_chirho(
        &holder_store_chirho,
        holder_chirho.root_chirho(),
        &old_manifest_chirho,
        &journal_fixture_chirho.source_record_chirho,
    );

    let current_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: leader_chirho.root_chirho(),
            leader_node_id_chirho: &leader_chirho.node_id_chirho,
            assigned_node_ids_chirho,
            consistency_group_digest_chirho: joined_chirho
                .view_chirho()
                .consistency_group_digest_chirho(),
            assignment_digest_chirho: placement_fixture_chirho
                .placement_chirho
                .assignment_digest_chirho(),
            membership_view_digest_chirho: &joined_chirho.view_chirho().view_digest_chirho(),
            expected_term_chirho: joined_chirho.term_chirho(),
        },
        &journal_fixture_chirho.source_record_chirho,
        None,
    );
    assert_ne!(
        current_manifest_chirho.assignment_digest_chirho(),
        old_manifest_chirho.assignment_digest_chirho(),
        "the positive path must cross a real placement successor"
    );
    assert!(!holder_store_chirho
        .begin_verified_prefix_chirho(current_manifest_chirho.clone(), None)
        .expect("without verified predecessor authority the current manifest must stage"));
    let holder_election_chirho: Arc<dyn MirrorLeadershipViewChirho> =
        Arc::new(FixedElectionViewChirho {
            observation_chirho: election_observation_chirho(
                &placement_fixture_chirho.placement_chirho,
                &leader_chirho.node_id_chirho,
                false,
            ),
        });
    let holder_state_chirho = LedgerMirrorServerStateChirho::new_chirho(
        holder_chirho.node_id_chirho.clone(),
        holder_chirho.root_chirho().to_path_buf(),
        Arc::clone(&placement_fixture_chirho.placement_chirho),
        holder_election_chirho,
        residency_chirho(&placement_fixture_chirho.placement_chirho),
        Arc::clone(&holder_store_chirho),
    )
    .expect("compose holder prefix server");
    let holder_server_chirho =
        RunningMirrorServerChirho::start_chirho(ledger_mirror_router_chirho(holder_state_chirho));
    let directory_chirho = LedgerMirrorDirectoryChirho::new_chirho(BTreeMap::from([(
        holder_chirho.node_id_chirho.clone(),
        holder_server_chirho.endpoint_chirho.clone(),
    )]));

    assert!(directory_chirho
        .begin_verified_prefix_chirho(
            &holder_chirho.node_id_chirho,
            &current_manifest_chirho,
            &private_mesh_agent_chirho(),
        )
        .expect("successor authority reuses its exact signed-predecessor prefix"));
    let stale_stage_refusal_chirho = match holder_store_chirho
        .prepare_bootstrap_commit_chirho(current_manifest_chirho.manifest_digest_chirho())
    {
        Ok(_) => panic!("widened reuse must clear the same inert stage as exact reuse"),
        Err(error_chirho) => error_chirho.to_string(),
    };
    assert!(stale_stage_refusal_chirho.contains("LedgerMirrorPrefixStageUnavailableChirho"));
    let source_chirho = holder_store_chirho
        .load_recovery_source_head_chirho()
        .expect("load historical source after HTTP begin")
        .expect("historical source remains present");
    let retained_receipt_chirho =
        LedgerMirrorRecoveryHeadReceiptChirho::sign_from_source_head_chirho(
            &source_chirho,
            holder_chirho.root_chirho(),
        )
        .expect("sign retained historical source");
    assert_eq!(
        retained_receipt_chirho.assignment_digest_chirho(),
        PREDECESSOR_BOOTSTRAP_ASSIGNMENT_DIGEST_CHIRHO,
        "retaining the predecessor head must retain its predecessor receipt assignment"
    );
    assert_eq!(
        retained_receipt_chirho.historical_term_chirho(),
        old_receipt_chirho.historical_term_chirho()
    );
    assert_eq!(
        retained_receipt_chirho.source_manifest_digest_chirho(),
        old_receipt_chirho.source_manifest_digest_chirho()
    );
    assert_ne!(
        retained_receipt_chirho.source_manifest_digest_chirho(),
        Some(current_manifest_chirho.manifest_digest_chirho())
    );
}

#[test]
fn signed_manifest_head_mismatch_refuses_the_transferred_chain_by_identity_chirho() {
    let fixture_chirho = RecoveryFixtureChirho::new_chirho();
    let (base_manifest_chirho, record_chirho) = fixture_chirho.manifest_chirho(None);
    let wrong_head_manifest_chirho = manifest_for_record_chirho(
        RecoveryManifestBindingChirho {
            leader_root_chirho: fixture_chirho.leader_root_chirho.path(),
            leader_node_id_chirho: &fixture_chirho.leader_node_id_chirho,
            assigned_node_ids_chirho: fixture_chirho.assigned_node_ids_chirho(),
            consistency_group_digest_chirho: base_manifest_chirho.consistency_group_digest_chirho(),
            assignment_digest_chirho: base_manifest_chirho.assignment_digest_chirho(),
            membership_view_digest_chirho: base_manifest_chirho.membership_view_digest_chirho(),
            expected_term_chirho: base_manifest_chirho.expected_term_chirho(),
        },
        &record_chirho,
        Some("4".repeat(64)),
    );
    let store_chirho = fixture_chirho.follower_store_chirho(
        fixture_chirho.first_holder_root_chirho.path(),
        &fixture_chirho.first_holder_node_id_chirho,
    );
    store_chirho
        .begin_verified_prefix_chirho(wrong_head_manifest_chirho.clone(), None)
        .expect("stage the signed wrong-head manifest");
    let refusal_chirho = store_chirho
        .store_verified_prefix_page_chirho(
            LedgerMirrorVerifiedPrefixPageChirho::new_chirho(
                wrong_head_manifest_chirho
                    .manifest_digest_chirho()
                    .to_string(),
                0,
                vec![record_chirho],
            )
            .expect("encode the real transferred chain"),
        )
        .expect_err("the signed manifest head must match the first transferred record")
        .to_string();
    assert!(refusal_chirho.contains("LedgerMirrorPrefixPageCrossContinuityRefusedChirho"));
    assert!(!refusal_chirho.contains("LedgerMirrorPrefixManifestAuthorityRefusedChirho"));
}
