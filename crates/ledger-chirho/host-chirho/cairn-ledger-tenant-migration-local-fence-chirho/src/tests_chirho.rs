// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use anyhow::Result;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_ledger_tenant_migration_chirho::{
    open_verified_tenant_ledger_tail_chirho, RootMoveChirho, SourceAppendFenceWitnessChirho,
    TenantLedgerVerificationViewsChirho, TenantMigrationAttemptIdentityChirho,
    TenantMigrationFenceIdentityChirho, VerifiedTenantMigrationRootChirho, WriterChirho,
};
use cairn_tenant_chirho::migration_completeness_chirho::{
    preliminary_migration_check_chirho, verify_migration_completeness_chirho,
    RootSurfaceEnumeratorChirho,
};
use cairn_tenant_chirho::self_containment_chirho::{
    verify_tenant_self_containment_chirho, TenantLogReferenceChirho, TenantObjectResolverChirho,
};
use cairn_tenant_chirho::surface_disposition_chirho::verify_surface_dispositions_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::LocalAppendAuthorityRefusalChirho;
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;
use raft::eraftpb::{Message, MessageType};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const TENANT_ID_CHIRHO: &str = "tenant-local-fence-chirho";
const CLUSTER_ID_CHIRHO: &str = "tenant-local-fence-cluster-chirho";
const JOURNAL_PATH_CHIRHO: &str = "journals/tenant-local-fence-chirho.jsonl";
const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
static TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

struct TestClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for TestClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

struct TestSignerChirho;

impl LedgerSignerPortChirho for TestSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "tenant-local-fence-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "tenant-local-fence-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .is_ok_and(|expected_chirho| expected_chirho == sig_chirho)
    }
}

struct AllMembersChirho;

impl MembershipViewChirho for AllMembersChirho {
    fn status_chirho(
        &self,
        _account_chirho: &AccountIdChirho,
        _epoch_chirho: ShardEpochChirho,
    ) -> MembershipStatusChirho {
        MembershipStatusChirho::MemberChirho
    }
}

struct MoneyRegistryChirho;

impl KindRegistryViewChirho for MoneyRegistryChirho {
    fn resolve_chirho(&self, policy_ref_chirho: &AssetKindRefChirho) -> KindResolutionChirho {
        if policy_ref_chirho.0 .0 == MONEY_POLICY_REF_CHIRHO {
            KindResolutionChirho::CurrentChirho(KindPolicyViewChirho {
                kind_id_chirho: MONEY_KIND_CHIRHO.into(),
                mint_authority_chirho: MintAuthorityPolicyChirho::PlatformPolicyChirho {
                    max_supply_chirho: None,
                },
                rounding_chirho: RoundingChirho::NearestTiesToEvenChirho,
                settlement_owner_chirho: None,
                idempotency_window_chirho: None,
            })
        } else {
            KindResolutionChirho::UnknownChirho
        }
    }
}

struct NoMintAuthorityChirho;

impl AuthorityVerifierViewChirho for NoMintAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }

    fn verify_burn_chirho(
        &self,
        _evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        AuthorityVerdictChirho::UnverifiedChirho
    }
}

struct TestViewsChirho {
    clock_chirho: TestClockChirho,
    signer_chirho: TestSignerChirho,
    membership_chirho: AllMembersChirho,
    registry_chirho: MoneyRegistryChirho,
    authority_chirho: NoMintAuthorityChirho,
}

impl TestViewsChirho {
    fn new_chirho() -> Self {
        Self {
            clock_chirho: TestClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            signer_chirho: TestSignerChirho,
            membership_chirho: AllMembersChirho,
            registry_chirho: MoneyRegistryChirho,
            authority_chirho: NoMintAuthorityChirho,
        }
    }

    fn journal_ports_chirho<'views_chirho>(
        &'views_chirho self,
        storage_chirho: &'views_chirho FsLedgerStorageChirho,
    ) -> JournalPortsChirho<'views_chirho> {
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: &self.signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    fn verification_views_chirho(&self) -> TenantLedgerVerificationViewsChirho<'_> {
        TenantLedgerVerificationViewsChirho {
            signer_chirho: &self.signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }
}

struct RootJournalFixtureChirho {
    platform_root_chirho: PathBuf,
    root_chirho: VerifiedTenantMigrationRootChirho,
    storage_chirho: FsLedgerStorageChirho,
    views_chirho: TestViewsChirho,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
}

impl RootJournalFixtureChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        let sequence_chirho = TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let platform_root_chirho = std::env::temp_dir().join(format!(
            "cairn-tenant-local-fence-{label_chirho}-{}-{sequence_chirho}-chirho",
            std::process::id()
        ));
        fs::create_dir_all(&platform_root_chirho).expect("create fixture platform root");
        let tenant_root_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, TENANT_ID_CHIRHO)
                .expect("prepare fixture tenant root");
        let storage_root_chirho = tenant_root_chirho.join("ledger-storage-chirho");
        fs::create_dir_all(&storage_root_chirho).expect("create fixture ledger namespace");
        let root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(&tenant_root_chirho)
                .expect("verify fixture tenant root");
        let storage_chirho = FsLedgerStorageChirho::open_existing_chirho(&storage_root_chirho)
            .expect("open fixture ledger namespace");
        let views_chirho = TestViewsChirho::new_chirho();
        let journal_path_chirho = StoragePathChirho::new_chirho(JOURNAL_PATH_CHIRHO);
        let cluster_id_chirho = ClusterIdChirho(CLUSTER_ID_CHIRHO.to_owned());
        LedgerJournalChirho::create_chirho(
            views_chirho.journal_ports_chirho(&storage_chirho),
            journal_path_chirho.clone(),
            cluster_id_chirho.clone(),
            7,
        )
        .expect("create fixture journal");
        Self {
            platform_root_chirho,
            root_chirho,
            storage_chirho,
            views_chirho,
            journal_path_chirho,
            cluster_id_chirho,
        }
    }

    fn verified_cut_chirho(
        &self,
    ) -> cairn_ledger_tenant_migration_chirho::VerifiedTenantLedgerCutChirho {
        open_verified_tenant_ledger_tail_chirho(
            self.root_chirho.clone(),
            &self.storage_chirho,
            self.views_chirho.verification_views_chirho(),
            &self.journal_path_chirho,
            &self.cluster_id_chirho,
        )
        .expect("full-verify fixture tail")
    }
}

impl Drop for RootJournalFixtureChirho {
    fn drop(&mut self) {
        let _remove_chirho = fs::remove_dir_all(&self.platform_root_chirho);
    }
}

struct OneSurfaceChirho;

impl RootSurfaceEnumeratorChirho for OneSurfaceChirho {
    fn observed_surfaces_chirho(&self) -> Vec<String> {
        vec!["refs-chirho".to_owned()]
    }
}

struct AllPresentChirho;

impl TenantObjectResolverChirho for AllPresentChirho {
    fn resolves_in_tenant_chirho(&self, _hash_chirho: &str) -> bool {
        true
    }
}

fn preliminary_check_chirho(
) -> cairn_tenant_chirho::migration_completeness_chirho::PreliminaryMigrationCheckChirho {
    let completeness_chirho = verify_migration_completeness_chirho(
        &BTreeSet::from(["refs-chirho".to_owned()]),
        &OneSurfaceChirho,
    );
    let containment_chirho = verify_tenant_self_containment_chirho(
        &[TenantLogReferenceChirho {
            log_name_chirho: "ledger-chirho".to_owned(),
            seq_chirho: 1,
            hash_chirho: "verified-object-chirho".to_owned(),
        }],
        &AllPresentChirho,
    );
    let disposition_chirho =
        verify_surface_dispositions_chirho(&["objects-chirho".to_owned()], None);
    preliminary_migration_check_chirho(
        &completeness_chirho,
        &containment_chirho,
        &disposition_chirho,
        None,
        None,
    )
    .expect("build evidence-bearing preliminary check")
}

fn prepared_attempt_chirho(
    source_chirho: &RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
) -> (RootMoveChirho, TenantMigrationAttemptIdentityChirho) {
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    let attempt_chirho = move_chirho
        .prepare_source_append_fence_attempt_chirho(source_chirho.verified_cut_chirho())
        .unwrap();
    (move_chirho, attempt_chirho)
}

fn warmed_single_node_chirho() -> Arc<RaftWriterElectorChirho> {
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("a".repeat(64)),
            ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: TENANT_ID_CHIRHO.to_owned(),
            },
        )
        .expect("build local fence elector")
        .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    elector_chirho
}

fn activate_attempt_marker_chirho(
    elector_chirho: &RaftWriterElectorChirho,
    attempt_chirho: &TenantMigrationAttemptIdentityChirho,
) {
    elector_chirho
        .local_append_authority_handle_chirho()
        .try_prepare_handoff_chirho(attempt_chirho.digest_chirho())
        .expect("prepare exact migration attempt marker")
        .activate_chirho();
}

fn fence_identity_chirho(
    attempt_chirho: TenantMigrationAttemptIdentityChirho,
    source_chirho: &RootJournalFixtureChirho,
) -> TenantMigrationFenceIdentityChirho {
    TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
        attempt_chirho,
        source_chirho.verified_cut_chirho(),
    )
    .unwrap()
}

#[test]
fn exact_active_marker_runs_the_contract_and_blocks_ordinary_append_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("active-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("active-target");
    let (mut move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);
    assert!(matches!(
        broad_handle_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));

    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho(attempt_chirho, &source_chirho),
        broad_handle_chirho.handoff_read_handle_chirho(),
    )
    .unwrap();
    assert!(witness_chirho.remains_active_chirho());
    move_chirho
        .record_source_append_fence_chirho(witness_chirho)
        .unwrap();
    assert_eq!(move_chirho.writer_chirho(), WriterChirho::NobodyChirho);
}

#[test]
fn unrelated_active_marker_refuses_by_identity_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("unrelated-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("unrelated-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    broad_handle_chirho
        .try_prepare_handoff_chirho(&"f".repeat(64))
        .unwrap()
        .activate_chirho();

    assert_eq!(
        LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
            fence_identity_chirho(attempt_chirho, &source_chirho),
            broad_handle_chirho.handoff_read_handle_chirho(),
        )
        .unwrap_err(),
        LocalTenantMigrationFenceRefusalChirho::AttemptMarkerMismatchChirho
    );
}

#[test]
fn exact_marker_on_another_authority_group_refuses_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("wrong-group-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("wrong-group-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("a".repeat(64)),
            ConsistencyGroupIdChirho::TenantChirho {
                tenant_id_chirho: "another-tenant-chirho".to_owned(),
            },
        )
        .expect("build wrong-group local fence elector")
        .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);

    assert_eq!(
        LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
            fence_identity_chirho(attempt_chirho, &source_chirho),
            broad_handle_chirho.handoff_read_handle_chirho(),
        )
        .unwrap_err(),
        LocalTenantMigrationFenceRefusalChirho::SourceAuthorityGroupMismatchChirho
    );
}

#[test]
fn releasing_the_exact_marker_makes_the_witness_inactive_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("release-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("release-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);
    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho(attempt_chirho.clone(), &source_chirho),
        broad_handle_chirho.handoff_read_handle_chirho(),
    )
    .unwrap();
    assert!(witness_chirho.remains_active_chirho());

    broad_handle_chirho
        .try_acquire_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap()
        .release_chirho();
    assert!(!witness_chirho.remains_active_chirho());
}

#[test]
fn same_digest_reactivation_does_not_reanimate_an_old_witness_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("reactivate-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("reactivate-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);
    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho(attempt_chirho.clone(), &source_chirho),
        broad_handle_chirho.handoff_read_handle_chirho(),
    )
    .unwrap();

    broad_handle_chirho
        .try_acquire_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap()
        .release_chirho();
    broad_handle_chirho
        .try_prepare_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap()
        .activate_chirho();
    assert!(
        !witness_chirho.remains_active_chirho(),
        "a marker gap must permanently invalidate a witness even when the same digest is reused"
    );
}

#[test]
fn idempotent_restore_preserves_the_live_marker_generation_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("restore-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("restore-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);
    let initial_generation_chirho = broad_handle_chirho
        .try_acquire_handoff_read_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho(attempt_chirho.clone(), &source_chirho),
        broad_handle_chirho.handoff_read_handle_chirho(),
    )
    .unwrap();

    broad_handle_chirho
        .restore_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    let restored_generation_chirho = broad_handle_chirho
        .try_acquire_handoff_read_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    assert_eq!(
        restored_generation_chirho.handoff_activation_generation_chirho(),
        initial_generation_chirho.handoff_activation_generation_chirho(),
        "restoring the same live marker must not mint a new activation lifetime"
    );
    assert!(witness_chirho.remains_active_chirho());
}

#[test]
fn raft_term_and_generation_drift_make_the_witness_inactive_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("term-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("term-target");
    let (_move_chirho, attempt_chirho) = prepared_attempt_chirho(&source_chirho, &target_chirho);
    let elector_chirho = warmed_single_node_chirho();
    let broad_handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    activate_attempt_marker_chirho(&elector_chirho, &attempt_chirho);
    let initial_generation_chirho = broad_handle_chirho
        .try_acquire_handoff_read_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    let witness_chirho = LocalTenantMigrationFenceWitnessChirho::bind_active_chirho(
        fence_identity_chirho(attempt_chirho.clone(), &source_chirho),
        broad_handle_chirho.handoff_read_handle_chirho(),
    )
    .unwrap();

    let mut higher_term_heartbeat_chirho = Message::default();
    higher_term_heartbeat_chirho.set_msg_type(MessageType::MsgHeartbeat);
    higher_term_heartbeat_chirho.from = 2;
    higher_term_heartbeat_chirho.to = 1;
    higher_term_heartbeat_chirho.term = initial_generation_chirho.published_raft_term_chirho() + 1;
    elector_chirho
        .step_chirho(higher_term_heartbeat_chirho)
        .unwrap();
    assert!(!witness_chirho.remains_active_chirho());

    elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    let changed_generation_chirho = broad_handle_chirho
        .try_acquire_handoff_read_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    assert!(
        changed_generation_chirho.process_generation_chirho()
            > initial_generation_chirho.process_generation_chirho()
    );
    assert!(
        changed_generation_chirho.published_raft_term_chirho()
            > initial_generation_chirho.published_raft_term_chirho()
    );
    assert!(!witness_chirho.remains_active_chirho());
}
