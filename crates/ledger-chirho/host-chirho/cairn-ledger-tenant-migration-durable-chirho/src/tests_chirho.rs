// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::coordinator_chirho::TenantMigrationOperationInputsChirho;
use anyhow::Result;
use cairn_ledger_host_storage_chirho::FsLedgerStorageChirho;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, AuthorityVerifierViewChirho, KindPolicyViewChirho,
    KindRegistryViewChirho, KindResolutionChirho, MembershipStatusChirho, MembershipViewChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::{
    LedgerClockPortChirho, LedgerSignerPortChirho, LedgerStoragePortChirho, StoragePathChirho,
};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, ClusterIdChirho, DigestChirho,
};
use cairn_ledger_model_chirho::ShardEpochChirho;
use cairn_ledger_tenant_migration_chirho::{
    open_verified_tenant_ledger_tail_chirho, RootMoveChirho, TenantLedgerVerificationViewsChirho,
    TenantMigrationAttemptIdentityChirho, TenantMigrationRefusalChirho,
    VerifiedTenantMigrationRootChirho, WriterChirho,
};
use cairn_tenant_chirho::migration_completeness_chirho::{
    preliminary_migration_check_chirho, verify_migration_completeness_chirho,
    PreliminaryMigrationCheckChirho, RootSurfaceEnumeratorChirho,
};
use cairn_tenant_chirho::self_containment_chirho::{
    verify_tenant_self_containment_chirho, TenantLogReferenceChirho, TenantObjectResolverChirho,
};
use cairn_tenant_chirho::surface_disposition_chirho::verify_surface_dispositions_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use cairn_writer_elector_chirho::elector_port_chirho::NodeIdChirho;
use cairn_writer_elector_chirho::raft_elector_chirho::RaftWriterElectorChirho;
use cairn_writer_elector_chirho::{
    LocalAppendAuthorityRefusalChirho, LocalAppendHandoffControlHandleChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::{
    consistency_group_digest_chirho, ConsistencyGroupIdChirho,
};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const TENANT_ID_CHIRHO: &str = "tenant-durable-migration-chirho";
const CLUSTER_ID_CHIRHO: &str = "tenant-durable-migration-cluster-chirho";
const JOURNAL_PATH_CHIRHO: &str = "journals/tenant-durable-migration-chirho.jsonl";
const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const NODE_ID_CHIRHO: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
static TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
static CONTROL_SIGNER_CHIRHO: TestControlSignerChirho = TestControlSignerChirho;

struct TestClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl LedgerClockPortChirho for TestClockChirho {
    fn physical_now_ms_chirho(&self) -> u64 {
        self.now_ms_chirho.get()
    }
}

struct TestLedgerSignerChirho;

impl LedgerSignerPortChirho for TestLedgerSignerChirho {
    fn sign_chirho(&self, signed_content_line_chirho: &str) -> Result<String> {
        Ok(format!(
            "tenant-durable-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "tenant-durable-key-chirho".to_owned()
    }

    fn verify_chirho(&self, signed_content_line_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(signed_content_line_chirho)
            .is_ok_and(|expected_chirho| expected_chirho == sig_chirho)
    }
}

struct TestControlSignerChirho;

impl TenantMigrationControlSignerPortChirho for TestControlSignerChirho {
    fn key_id_chirho(&self) -> String {
        NODE_ID_CHIRHO.to_owned()
    }

    fn sign_chirho(&self, canonical_unsigned_chirho: &str) -> Result<String> {
        Ok(blake3::hash(canonical_unsigned_chirho.as_bytes())
            .to_hex()
            .to_string())
    }

    fn verify_chirho(&self, canonical_unsigned_chirho: &str, sig_chirho: &str) -> bool {
        self.sign_chirho(canonical_unsigned_chirho)
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
    signer_chirho: TestLedgerSignerChirho,
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
            signer_chirho: TestLedgerSignerChirho,
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
    tenant_root_path_chirho: PathBuf,
    root_chirho: VerifiedTenantMigrationRootChirho,
    ledger_storage_chirho: FsLedgerStorageChirho,
    control_storage_chirho: FsLedgerStorageChirho,
    views_chirho: TestViewsChirho,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
}

impl RootJournalFixtureChirho {
    fn new_chirho(label_chirho: &str) -> Self {
        Self::new_with_opening_epoch_chirho(label_chirho, 7)
    }

    /// Build a fixture whose journal opens at a chosen epoch.
    ///
    /// The opening epoch feeds genesis, so two fixtures built at DIFFERENT epochs hold different
    /// genesis records and therefore different cuts. That is the only lever here that makes a target
    /// diverge from a source: this crate's fixtures cannot append to a journal, and a real append
    /// needs the whole ledger write path.
    fn new_with_opening_epoch_chirho(label_chirho: &str, opening_epoch_chirho: u64) -> Self {
        let sequence_chirho = TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let platform_root_chirho = std::env::temp_dir().join(format!(
            "cairn-tenant-durable-{label_chirho}-{}-{sequence_chirho}-chirho",
            std::process::id()
        ));
        fs::create_dir_all(&platform_root_chirho).expect("create fixture platform root");
        let tenant_root_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, TENANT_ID_CHIRHO)
                .expect("prepare fixture tenant root");
        let ledger_storage_root_chirho = tenant_root_chirho.join("ledger-storage-chirho");
        fs::create_dir_all(&ledger_storage_root_chirho).expect("create ledger namespace");
        let root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(&tenant_root_chirho)
                .expect("verify fixture tenant root");
        let ledger_storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&ledger_storage_root_chirho)
                .expect("open ledger namespace");
        let control_storage_chirho =
            FsLedgerStorageChirho::open_existing_chirho(&tenant_root_chirho)
                .expect("open migration control namespace");
        let views_chirho = TestViewsChirho::new_chirho();
        let journal_path_chirho = StoragePathChirho::new_chirho(JOURNAL_PATH_CHIRHO);
        let cluster_id_chirho = ClusterIdChirho(CLUSTER_ID_CHIRHO.to_owned());
        LedgerJournalChirho::create_chirho(
            views_chirho.journal_ports_chirho(&ledger_storage_chirho),
            journal_path_chirho.clone(),
            cluster_id_chirho.clone(),
            opening_epoch_chirho,
        )
        .expect("create fixture journal");
        Self {
            platform_root_chirho,
            tenant_root_path_chirho: tenant_root_chirho,
            root_chirho,
            ledger_storage_chirho,
            control_storage_chirho,
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
            &self.ledger_storage_chirho,
            self.views_chirho.verification_views_chirho(),
            &self.journal_path_chirho,
            &self.cluster_id_chirho,
        )
        .expect("full-verify fixture tail")
    }

    fn store_chirho(&self) -> TenantMigrationStoreChirho<'_> {
        TenantMigrationStoreChirho::new_chirho(
            &self.control_storage_chirho,
            &CONTROL_SIGNER_CHIRHO,
            consistency_group_digest_chirho(&tenant_group_chirho()).unwrap(),
            NODE_ID_CHIRHO.to_owned(),
        )
        .expect("open migration store")
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

fn preliminary_check_chirho() -> PreliminaryMigrationCheckChirho {
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

fn tenant_group_chirho() -> ConsistencyGroupIdChirho {
    ConsistencyGroupIdChirho::TenantChirho {
        tenant_id_chirho: TENANT_ID_CHIRHO.to_owned(),
    }
}

fn operation_authority_chirho() -> TenantMigrationOperationAuthorityBindingChirho {
    operation_authority_with_label_chirho("fixture-adoption-chirho")
}

fn operation_authority_with_label_chirho(
    adoption_label_chirho: &str,
) -> TenantMigrationOperationAuthorityBindingChirho {
    TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(format!(
        r#"{{"destination_intent_chirho":"fixture-destination-chirho","writer_adoption_intent_chirho":"{adoption_label_chirho}"}}"#,
    ))
    .expect("build canonical fixture operation authority")
}

fn warmed_single_node_chirho() -> Arc<RaftWriterElectorChirho> {
    let elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho(NODE_ID_CHIRHO.to_owned()),
            tenant_group_chirho(),
        )
        .expect("build durable migration elector")
        .with_leadership_warmup_lease_chirho(),
    );
    elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        elector_chirho.tick_chirho();
    }
    elector_chirho
}

fn operation_inputs_chirho<'inputs_chirho>(
    source_chirho: &'inputs_chirho RootJournalFixtureChirho,
    target_chirho: &'inputs_chirho RootJournalFixtureChirho,
) -> TenantMigrationOperationInputsChirho<'inputs_chirho> {
    operation_inputs_with_authority_chirho(
        source_chirho,
        target_chirho,
        operation_authority_chirho(),
    )
}

fn operation_inputs_with_authority_chirho<'inputs_chirho>(
    source_chirho: &'inputs_chirho RootJournalFixtureChirho,
    target_chirho: &'inputs_chirho RootJournalFixtureChirho,
    operation_authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
) -> TenantMigrationOperationInputsChirho<'inputs_chirho> {
    TenantMigrationOperationInputsChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
        preliminary_check_chirho(),
        &source_chirho.ledger_storage_chirho,
        source_chirho.views_chirho.verification_views_chirho(),
        &source_chirho.journal_path_chirho,
        &source_chirho.cluster_id_chirho,
        operation_authority_chirho,
    )
}

fn preparing_attempt_chirho(
    source_chirho: &RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
) -> (RootMoveChirho, TenantMigrationAttemptIdentityChirho) {
    preparing_attempt_with_authority_chirho(
        source_chirho,
        target_chirho,
        operation_authority_chirho(),
    )
}

fn preparing_attempt_with_authority_chirho(
    source_chirho: &RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
    authority_chirho: TenantMigrationOperationAuthorityBindingChirho,
) -> (RootMoveChirho, TenantMigrationAttemptIdentityChirho) {
    let mut move_chirho = RootMoveChirho::new_with_operation_authority_binding_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
        authority_chirho.binding_digest_chirho().to_owned(),
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

#[test]
fn operation_authority_requires_one_canonical_bounded_object_chirho() {
    assert!(matches!(
        TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(
            r#"{ "authority_chirho": "spaced-chirho" }"#.to_owned()
        ),
        Err(TenantMigrationOperationAuthorityRefusalChirho::CanonicalPayloadChirho)
    ));
    assert!(matches!(
        TenantMigrationOperationAuthorityBindingChirho::from_canonical_payload_chirho(
            r#"["not-an-object-chirho"]"#.to_owned()
        ),
        Err(TenantMigrationOperationAuthorityRefusalChirho::CanonicalPayloadChirho)
    ));
}

#[test]
fn operation_authority_changes_the_attempt_identity_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("authority-attempt-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("authority-attempt-target");
    let (_first_move_chirho, first_attempt_chirho) = preparing_attempt_with_authority_chirho(
        &source_chirho,
        &target_chirho,
        operation_authority_with_label_chirho("first-adoption-chirho"),
    );
    let (_second_move_chirho, second_attempt_chirho) = preparing_attempt_with_authority_chirho(
        &source_chirho,
        &target_chirho,
        operation_authority_with_label_chirho("second-adoption-chirho"),
    );

    assert_ne!(
        first_attempt_chirho.digest_chirho(),
        second_attempt_chirho.digest_chirho()
    );
}

fn commit_preparing_only_chirho<'a>(
    source_chirho: &'a RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
) -> (TenantMigrationStoreChirho<'a>, ActiveTenantMigrationChirho) {
    let (_move_chirho, attempt_chirho) = preparing_attempt_chirho(source_chirho, target_chirho);
    let cut_chirho = source_chirho.verified_cut_chirho();
    let preparation_chirho = control_chirho
        .try_prepare_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    let store_chirho = source_chirho.store_chirho();
    let (committed_chirho, durable_chirho) = store_chirho
        .commit_preparing_chirho(
            TENANT_ID_CHIRHO.to_owned(),
            CLUSTER_ID_CHIRHO.to_owned(),
            JOURNAL_PATH_CHIRHO.to_owned(),
            attempt_chirho.digest_chirho().to_owned(),
            TenantMigrationCutClaimChirho::from_verified_chirho(cut_chirho.cut_chirho()),
            operation_authority_chirho(),
        )
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);
    drop(preparation_chirho.activate_chirho());
    (store_chirho, committed_chirho.active_chirho)
}

fn migration_head_path_chirho(source_chirho: &RootJournalFixtureChirho) -> StoragePathChirho {
    source_chirho
        .control_storage_chirho
        .list_chirho(&StoragePathChirho::new_chirho(
            "tenant-migration-control-chirho",
        ))
        .unwrap()
        .into_iter()
        .find(|path_chirho| {
            path_chirho
                .key_chirho()
                .ends_with("active-head-chirho.json")
        })
        .expect("migration head exists")
}

#[test]
fn begin_persists_source_fence_before_returning_and_blocks_ordinary_append_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("begin-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("begin-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);

    let prepared_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(inputs_chirho)
        .unwrap();

    assert_eq!(
        prepared_chirho.active_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::SourceFencedChirho
    );
    assert_eq!(
        prepared_chirho.move_chirho.writer_chirho(),
        WriterChirho::NobodyChirho
    );
    assert!(matches!(
        broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
    assert_eq!(
        store_chirho.load_current_chirho().unwrap(),
        Some(prepared_chirho.active_chirho)
    );
}

#[test]
fn preparing_crash_restores_exact_marker_then_reverifies_into_source_fenced_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("crash-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("crash-target");
    let first_elector_chirho = warmed_single_node_chirho();
    let first_control_chirho = first_elector_chirho
        .local_append_authority_handle_chirho()
        .handoff_control_handle_chirho();
    let (mut store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &first_control_chirho);
    drop(first_elector_chirho);

    let restarted_elector_chirho = warmed_single_node_chirho();
    let restarted_broad_chirho = restarted_elector_chirho.local_append_authority_handle_chirho();
    let restarted_control_chirho = restarted_broad_chirho.handoff_control_handle_chirho();
    let startup_chirho = restore_tenant_migration_startup_chirho(
        &store_chirho,
        &restarted_control_chirho,
        Some(preparing_chirho.clone()),
    )
    .unwrap();
    assert_eq!(
        startup_chirho.active_attempt_digest_chirho(),
        Some(preparing_chirho.attempt_digest_chirho())
    );
    assert!(matches!(
        restarted_broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));

    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);
    let recovered_chirho = store_chirho
        .bind_operation_session_chirho(&restarted_control_chirho)
        .unwrap()
        .recover_source_fenced_chirho(inputs_chirho)
        .unwrap();
    assert_eq!(
        recovered_chirho.active_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::SourceFencedChirho
    );
    assert_eq!(
        recovered_chirho.move_chirho.writer_chirho(),
        WriterChirho::NobodyChirho
    );
}

#[test]
fn aborted_head_never_claims_or_releases_a_foreign_marker_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("aborted-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("aborted-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (mut store_chirho, _preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    let aborted_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .abort_current_chirho()
        .unwrap();
    let foreign_digest_chirho = "f".repeat(64);
    drop(
        broad_chirho
            .try_prepare_handoff_chirho(&foreign_digest_chirho)
            .unwrap()
            .activate_chirho(),
    );

    let startup_chirho = restore_tenant_migration_startup_chirho(
        &store_chirho,
        &control_chirho,
        Some(aborted_chirho.active_chirho),
    )
    .unwrap();
    assert!(matches!(
        startup_chirho,
        TenantMigrationStartupBarrierChirho::AbortedChirho {
            released_owned_marker_chirho: false,
            ..
        }
    ));
    assert!(control_chirho
        .handoff_read_handle_chirho()
        .try_acquire_handoff_read_chirho(&foreign_digest_chirho)
        .is_ok());
}

#[test]
fn changed_or_omitted_startup_inspection_refuses_before_marker_mutation_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("inspect-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("inspect-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, _preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    broad_chirho
        .try_acquire_handoff_chirho(
            store_chirho
                .load_current_chirho()
                .unwrap()
                .unwrap()
                .attempt_digest_chirho(),
        )
        .unwrap()
        .release_chirho();

    assert!(matches!(
        restore_tenant_migration_startup_chirho(&store_chirho, &control_chirho, None),
        Err(TenantMigrationCoordinatorRefusalChirho::DurableHeadChangedChirho)
    ));
    assert!(broad_chirho.try_acquire_chirho().is_ok());
}

#[test]
fn corrupted_signed_head_refuses_instead_of_restoring_a_marker_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("corrupt-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("corrupt-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    broad_chirho
        .try_acquire_handoff_chirho(preparing_chirho.attempt_digest_chirho())
        .unwrap()
        .release_chirho();
    let head_path_chirho = migration_head_path_chirho(&source_chirho);
    let mut head_bytes_chirho = source_chirho
        .control_storage_chirho
        .read_all_chirho(&head_path_chirho)
        .unwrap()
        .unwrap();
    let mutation_index_chirho = head_bytes_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho == b'a')
        .expect("head carries a mutable byte");
    head_bytes_chirho[mutation_index_chirho] = b'b';
    source_chirho
        .control_storage_chirho
        .atomic_write_chirho(&head_path_chirho, &head_bytes_chirho)
        .unwrap();

    assert!(store_chirho.load_current_chirho().is_err());
    assert!(broad_chirho.try_acquire_chirho().is_ok());
}

#[test]
fn truncated_signed_head_refuses_instead_of_becoming_no_attempt_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("truncate-head-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("truncate-head-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    broad_chirho
        .try_acquire_handoff_chirho(preparing_chirho.attempt_digest_chirho())
        .unwrap()
        .release_chirho();
    let head_path_chirho = migration_head_path_chirho(&source_chirho);
    let head_len_chirho = source_chirho
        .control_storage_chirho
        .object_len_chirho(&head_path_chirho)
        .unwrap()
        .unwrap();
    source_chirho
        .control_storage_chirho
        .truncate_durable_chirho(&head_path_chirho, head_len_chirho - 1)
        .unwrap();

    assert!(matches!(
        store_chirho.load_current_chirho(),
        Err(TenantMigrationStoreRefusalChirho::MalformedHeadChirho)
            | Err(TenantMigrationStoreRefusalChirho::NonCanonicalHeadChirho)
    ));
    assert!(broad_chirho.try_acquire_chirho().is_ok());
}

#[test]
fn persisted_ordinary_cut_forgery_refuses_full_reverification_and_keeps_freeze_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("forged-cut-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("forged-cut-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (_move_chirho, attempt_chirho) = preparing_attempt_chirho(&source_chirho, &target_chirho);
    let verified_cut_chirho = source_chirho.verified_cut_chirho();
    let mut forged_claim_chirho =
        TenantMigrationCutClaimChirho::from_verified_chirho(verified_cut_chirho.cut_chirho());
    forged_claim_chirho.record_digest_chirho = "0".repeat(64);
    let preparation_chirho = control_chirho
        .try_prepare_handoff_chirho(attempt_chirho.digest_chirho())
        .unwrap();
    let mut store_chirho = source_chirho.store_chirho();
    let (_committed_chirho, durable_chirho) = store_chirho
        .commit_preparing_chirho(
            TENANT_ID_CHIRHO.to_owned(),
            CLUSTER_ID_CHIRHO.to_owned(),
            JOURNAL_PATH_CHIRHO.to_owned(),
            attempt_chirho.digest_chirho().to_owned(),
            forged_claim_chirho,
            operation_authority_chirho(),
        )
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);
    drop(preparation_chirho.activate_chirho());
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);

    assert!(matches!(
        store_chirho
            .bind_operation_session_chirho(&control_chirho)
            .unwrap()
            .recover_source_fenced_chirho(inputs_chirho),
        Err(
            TenantMigrationCoordinatorRefusalChirho::MigrationContractChirho(
                TenantMigrationRefusalChirho::JournalVerificationRefusedChirho
            )
        )
    ));
    assert!(matches!(
        broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
}

#[test]
fn recovery_refuses_a_different_target_root_without_releasing_source_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("wrong-target-source");
    let original_target_chirho = RootJournalFixtureChirho::new_chirho("wrong-target-original");
    let replacement_target_chirho =
        RootJournalFixtureChirho::new_chirho("wrong-target-replacement");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (mut store_chirho, _preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &original_target_chirho, &control_chirho);
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &replacement_target_chirho);

    assert!(matches!(
        store_chirho
            .bind_operation_session_chirho(&control_chirho)
            .unwrap()
            .recover_source_fenced_chirho(inputs_chirho),
        Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho)
    ));
    assert!(matches!(
        broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
}

#[test]
fn recovery_refuses_replacement_authority_without_releasing_source_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("wrong-authority-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("wrong-authority-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (mut store_chirho, _preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    let inputs_chirho = operation_inputs_with_authority_chirho(
        &source_chirho,
        &target_chirho,
        operation_authority_with_label_chirho("replacement-adoption-chirho"),
    );

    assert!(matches!(
        store_chirho
            .bind_operation_session_chirho(&control_chirho)
            .unwrap()
            .recover_source_fenced_chirho(inputs_chirho),
        Err(TenantMigrationCoordinatorRefusalChirho::DurableIdentityMismatchChirho)
    ));
    assert!(matches!(
        broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
}

#[test]
fn wrong_local_node_binding_refuses_before_claiming_the_durable_attempt_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("wrong-node-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("wrong-node-target");
    let original_elector_chirho = warmed_single_node_chirho();
    let original_broad_chirho = original_elector_chirho.local_append_authority_handle_chirho();
    let original_control_chirho = original_broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &original_control_chirho);
    original_broad_chirho
        .try_acquire_handoff_chirho(preparing_chirho.attempt_digest_chirho())
        .unwrap()
        .release_chirho();
    let foreign_elector_chirho = Arc::new(
        RaftWriterElectorChirho::new_single_node_chirho(
            NodeIdChirho("b".repeat(64)),
            tenant_group_chirho(),
        )
        .unwrap()
        .with_leadership_warmup_lease_chirho(),
    );
    foreign_elector_chirho.campaign_chirho().unwrap();
    for _warmup_tick_chirho in 0..10 {
        foreign_elector_chirho.tick_chirho();
    }
    let foreign_broad_chirho = foreign_elector_chirho.local_append_authority_handle_chirho();
    let foreign_control_chirho = foreign_broad_chirho.handoff_control_handle_chirho();

    assert!(matches!(
        restore_tenant_migration_startup_chirho(
            &store_chirho,
            &foreign_control_chirho,
            Some(preparing_chirho),
        ),
        Err(TenantMigrationCoordinatorRefusalChirho::AuthorityBindingMismatchChirho)
    ));
    assert!(foreign_broad_chirho.try_acquire_chirho().is_ok());
}

#[test]
fn exact_preparing_operation_retry_is_idempotent_and_does_not_advance_the_head_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("replay-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("replay-target");
    let elector_chirho = warmed_single_node_chirho();
    let control_chirho = elector_chirho
        .local_append_authority_handle_chirho()
        .handoff_control_handle_chirho();
    let (store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    let cut_chirho = source_chirho.verified_cut_chirho();
    let (replayed_chirho, replay_durable_chirho) = store_chirho
        .commit_preparing_chirho(
            TENANT_ID_CHIRHO.to_owned(),
            CLUSTER_ID_CHIRHO.to_owned(),
            JOURNAL_PATH_CHIRHO.to_owned(),
            preparing_chirho.attempt_digest_chirho().to_owned(),
            TenantMigrationCutClaimChirho::from_verified_chirho(cut_chirho.cut_chirho()),
            operation_authority_chirho(),
        )
        .unwrap()
        .into_parts_chirho();
    assert!(replay_durable_chirho);
    assert_eq!(replayed_chirho.active_chirho, preparing_chirho);
    assert_eq!(
        replayed_chirho
            .active_chirho
            .checkpoint_chirho()
            .transition_seq_chirho,
        0
    );
    assert!(matches!(
        store_chirho.commit_preparing_chirho(
            TENANT_ID_CHIRHO.to_owned(),
            CLUSTER_ID_CHIRHO.to_owned(),
            JOURNAL_PATH_CHIRHO.to_owned(),
            preparing_chirho.attempt_digest_chirho().to_owned(),
            TenantMigrationCutClaimChirho::from_verified_chirho(cut_chirho.cut_chirho()),
            operation_authority_with_label_chirho("replacement-adoption-chirho"),
        ),
        Err(TenantMigrationStoreRefusalChirho::ActiveAttemptMismatchChirho)
    ));
}

/// Drive the PRODUCTION activation mover with the fence identity this attempt actually recorded.
///
/// This replaced a `#[cfg(test)]` store hook. The tests below now reach the activated phase by the
/// same path production uses, so what they pin is the shipping transition rather than a state only
/// a test could construct — the arms that follow assert the mover's own bindings separately.
trait ActivateWithRecordedFenceChirho {
    fn activate_with_recorded_fence_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho>;
}

impl ActivateWithRecordedFenceChirho for TenantMigrationStoreChirho<'_> {
    fn activate_with_recorded_fence_chirho(
        &self,
        active_chirho: &ActiveTenantMigrationChirho,
    ) -> Result<TenantMigrationCommitOutcomeChirho, TenantMigrationStoreRefusalChirho> {
        let recorded_chirho = active_chirho
            .checkpoint_chirho
            .fence_identity_digest_chirho
            .clone()
            .expect("a source-fenced checkpoint records its fence identity");
        self.commit_target_activated_chirho(
            active_chirho.attempt_digest_chirho(),
            active_chirho.checkpoint_ref_chirho(),
            &recorded_chirho,
        )
    }
}

/// RETARGETED 2026-08-18 when the durable activated-phase BRIDGE landed (`9da14979`, whose own
/// subject is "bridge the durable activated phase"). Corrected 2026-08-19: this line previously read
/// "when activation landed", which reads as though a tenant root can be activated. It cannot — that
/// commit touched the barrier, the coordinator and these tests and did NOT touch `store_chirho.rs`,
/// so the only thing that can enter this phase is the `#[cfg(test)]` hook below. What this arm pins
/// is how startup TREATS the phase, never that anything may legitimately reach it.
///
/// The fixture below is UNCHANGED from the version that pinned the refusal, so this test's new green
/// is a statement about the code rather than about the test. If this now REFUSES, the bridge
/// regressed; if it returns any barrier other than `TargetActivatedSourceRetainedChirho`, the
/// durable phase and the barrier have diverged.
///
/// The second assertion is the one that matters and it is byte-identical to the pre-activation
/// version: the retained source must still be frozen. Activation changes who may write, never
/// whether the old writer may resume.
#[test]
fn activated_target_phase_freezes_the_retained_source_at_startup_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("reserved-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("reserved-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);
    let source_fenced_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(inputs_chirho)
        .unwrap()
        .active_chirho;
    let (reserved_chirho, durable_chirho) = store_chirho
        .activate_with_recorded_fence_chirho(&source_fenced_chirho)
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);

    let barrier_chirho = restore_tenant_migration_startup_chirho(
        &store_chirho,
        &control_chirho,
        Some(reserved_chirho.active_chirho.clone()),
    )
    .expect("an activated attempt must no longer refuse as an unimplemented reserved phase");
    let TenantMigrationStartupBarrierChirho::TargetActivatedSourceRetainedChirho {
        attempt_digest_chirho,
    } = &barrier_chirho
    else {
        panic!("expected the retained-source barrier, got {barrier_chirho:?}");
    };
    assert_eq!(
        attempt_digest_chirho,
        reserved_chirho.active_chirho.attempt_digest_chirho()
    );
    assert!(barrier_chirho.blocks_mutations_chirho());
    // The freeze reason must name ACTIVATION, not a live source fence. Both freeze; reporting the
    // wrong one sends a reader looking for an in-flight migration that is already finished.
    let reason_chirho = barrier_chirho
        .mutation_freeze_reason_chirho()
        .expect("a frozen barrier must say why");
    assert!(
        reason_chirho.contains("target is activated"),
        "{reason_chirho}"
    );
    assert!(!reason_chirho.contains("active tenant migration source fence"));

    assert!(matches!(
        broad_chirho.try_acquire_chirho(),
        Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
    ));
}

/// Restart safety at this layer: re-running startup on the same activated head is idempotent and
/// never thaws the source. A second start is exactly what a crash between persist and serve looks
/// like from here.
#[test]
fn re_entering_startup_on_an_activated_head_stays_frozen_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("reentry-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("reentry-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);
    let source_fenced_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(inputs_chirho)
        .unwrap()
        .active_chirho;
    let (reserved_chirho, durable_chirho) = store_chirho
        .activate_with_recorded_fence_chirho(&source_fenced_chirho)
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);

    for _attempt_chirho in 0..2 {
        let barrier_chirho = restore_tenant_migration_startup_chirho(
            &store_chirho,
            &control_chirho,
            Some(reserved_chirho.active_chirho.clone()),
        )
        .expect("re-entry on an activated head must not refuse");
        assert!(barrier_chirho.blocks_mutations_chirho());
        assert!(matches!(
            broad_chirho.try_acquire_chirho(),
            Err(LocalAppendAuthorityRefusalChirho::HandoffActiveChirho)
        ));
    }
}

/// The reserved refusal must not vanish: recovering a SOURCE FENCE on an activated attempt is still
/// out of order, and that is a different question from whether startup can serve the phase.
#[test]
fn source_fence_recovery_still_refuses_on_an_activated_head_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("recover-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("recover-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();
    let inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);
    let source_fenced_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(inputs_chirho)
        .unwrap()
        .active_chirho;
    let (_reserved_chirho, durable_chirho) = store_chirho
        .activate_with_recorded_fence_chirho(&source_fenced_chirho)
        .unwrap()
        .into_parts_chirho();
    assert!(durable_chirho);

    let recovery_inputs_chirho = operation_inputs_chirho(&source_chirho, &target_chirho);
    let recovered_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .recover_source_fenced_chirho(recovery_inputs_chirho);
    assert!(matches!(
        recovered_chirho,
        Err(TenantMigrationCoordinatorRefusalChirho::UnsupportedReservedPhaseChirho)
    ));
}

/// Reach `SourceFencedChirho` through the real begin path and hand back store + active attempt.
fn source_fenced_for_activation_chirho<'a>(
    source_chirho: &'a RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
    control_chirho: &LocalAppendHandoffControlHandleChirho,
) -> (TenantMigrationStoreChirho<'a>, ActiveTenantMigrationChirho) {
    let mut store_chirho = source_chirho.store_chirho();
    let inputs_chirho = operation_inputs_chirho(source_chirho, target_chirho);
    let active_chirho = store_chirho
        .bind_operation_session_chirho(control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(inputs_chirho)
        .unwrap()
        .active_chirho;
    (store_chirho, active_chirho)
}

#[test]
fn activation_from_source_fenced_with_the_recorded_fence_lands_the_phase_chirho() {
    // POSITIVE CONTROL for the three refusal arms below. Without it, each of them could be refusing
    // for a reason that has nothing to do with the property it names, and all three would look
    // exactly as green.
    let source_chirho = RootJournalFixtureChirho::new_chirho("activate-ok-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("activate-ok-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, active_chirho) =
        source_fenced_for_activation_chirho(&source_chirho, &target_chirho, &control_chirho);

    let (activated_chirho, durable_chirho) = store_chirho
        .activate_with_recorded_fence_chirho(&active_chirho)
        .expect("an established source fence activates under its own recorded fence identity")
        .into_parts_chirho();
    assert!(durable_chirho);
    assert_eq!(
        activated_chirho.active_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    );
}

#[test]
fn activation_with_a_different_fence_identity_refuses_by_that_name_not_as_an_ordering_error_chirho()
{
    // THE BINDING. The phase order here is entirely legal — only the fence identity is wrong — so an
    // arm that accepted any refusal would pass while the binding did nothing. Assert the identity
    // AND assert it is not the neighbouring refusal, because `InvalidTransitionChirho` is exactly
    // what a caller would see if the binding were dropped and the phase check alone survived.
    let source_chirho = RootJournalFixtureChirho::new_chirho("activate-bind-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("activate-bind-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, active_chirho) =
        source_fenced_for_activation_chirho(&source_chirho, &target_chirho, &control_chirho);

    let refusal_chirho = store_chirho
        .commit_target_activated_chirho(
            active_chirho.attempt_digest_chirho(),
            active_chirho.checkpoint_ref_chirho(),
            "a-fence-identity-this-attempt-never-recorded-chirho",
        )
        .expect_err("a fence identity this attempt never recorded must not activate it");
    assert_eq!(
        refusal_chirho,
        TenantMigrationStoreRefusalChirho::FenceIdentityMismatchChirho
    );
    assert_ne!(
        refusal_chirho,
        TenantMigrationStoreRefusalChirho::InvalidTransitionChirho
    );

    // And the durable phase did not move: a refused activation leaves the source fence exactly where
    // it was, not in some half-state.
    let current_chirho = store_chirho.load_current_chirho().unwrap().unwrap();
    assert_eq!(
        current_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::SourceFencedChirho
    );
}

#[test]
fn activation_from_preparing_refuses_as_out_of_order_and_not_as_a_fence_mismatch_chirho() {
    // THE PHASE GATE, and the third case that separates it from the binding above. `PreparingChirho`
    // means the source is not yet provably frozen, so activating there could leave TWO writers. The
    // fixture supplies a fence identity that is wrong too, so if the mover checked the binding
    // BEFORE the phase this arm would see the mismatch refusal — asserting the not-equal below is
    // what pins the ordering of the two checks rather than merely their presence.
    let source_chirho = RootJournalFixtureChirho::new_chirho("activate-early-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("activate-early-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    assert_eq!(
        preparing_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::PreparingChirho
    );

    let refusal_chirho = store_chirho
        .commit_target_activated_chirho(
            preparing_chirho.attempt_digest_chirho(),
            preparing_chirho.checkpoint_ref_chirho(),
            "also-not-a-recorded-fence-identity-chirho",
        )
        .expect_err("activation before the source fence is established must refuse");
    assert_eq!(
        refusal_chirho,
        TenantMigrationStoreRefusalChirho::InvalidTransitionChirho
    );
    assert_ne!(
        refusal_chirho,
        TenantMigrationStoreRefusalChirho::FenceIdentityMismatchChirho
    );
}

#[test]
fn exact_activation_retry_is_idempotent_and_does_not_advance_the_head_chirho() {
    // NO DOUBLE-MOVE. A crash between commit and reply re-drives activation, and the retry must
    // re-confirm rather than advance a second transition. If the head ref moves, the attempt has
    // taken two transitions on one authorisation.
    let source_chirho = RootJournalFixtureChirho::new_chirho("activate-retry-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("activate-retry-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (store_chirho, active_chirho) =
        source_fenced_for_activation_chirho(&source_chirho, &target_chirho, &control_chirho);

    let first_chirho = store_chirho
        .activate_with_recorded_fence_chirho(&active_chirho)
        .expect("first activation")
        .into_parts_chirho()
        .0
        .active_chirho;
    let head_after_first_chirho = first_chirho.checkpoint_ref_chirho().to_owned();

    let second_chirho = store_chirho
        .activate_with_recorded_fence_chirho(&first_chirho)
        .expect("the exact retry re-confirms rather than refusing")
        .into_parts_chirho()
        .0
        .active_chirho;

    assert_eq!(
        second_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    );
    assert_eq!(
        second_chirho.checkpoint_ref_chirho(),
        head_after_first_chirho,
        "the retry advanced the head, so activation moved twice on one authorisation"
    );
}

fn activation_inputs_chirho<'inputs_chirho>(
    target_chirho: &'inputs_chirho RootJournalFixtureChirho,
) -> TenantMigrationActivationInputsChirho<'inputs_chirho> {
    TenantMigrationActivationInputsChirho::new_chirho(
        target_chirho.root_chirho.clone(),
        &target_chirho.ledger_storage_chirho,
        target_chirho.views_chirho.verification_views_chirho(),
        &target_chirho.journal_path_chirho,
        &target_chirho.cluster_id_chirho,
    )
}

#[test]
fn the_coordinator_activates_the_target_and_the_contract_moves_the_writer_chirho() {
    // The whole step-2 path end to end: begin through the real source fence, then activate. The
    // WRITER assertion is what makes it more than a smoke test — the contract moves the writer only
    // if it accepted the warrant.
    //
    // MEASURED LIMITATION, do not read this arm as more than it is. It does NOT pin that the target
    // is verified at the SOURCE'S EXACT FENCED CUT. Mutating the coordinator to open the target at
    // its own tail instead of the fenced prefix leaves this arm GREEN, because both fixtures hold
    // identical content, so on this fixture tail and prefix are the same cut and the two readings
    // cannot diverge. Pinning that property needs a target whose journal differs from the source's
    // fenced cut, and no fixture here can extend a journal yet — see step 3 of the activation
    // tasklist, where that gap is tracked rather than left riding inside this green test.
    //
    // What this arm DOES carry causally: the coordinator reaches the contract, the contract issues a
    // warrant, activation is accepted, the durable phase lands, and the writer moves.
    let source_chirho = RootJournalFixtureChirho::new_chirho("coord-activate-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("coord-activate-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();

    let prepared_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(operation_inputs_chirho(&source_chirho, &target_chirho))
        .expect("begin reaches the source fence");
    assert_eq!(
        prepared_chirho.move_chirho.writer_chirho(),
        WriterChirho::NobodyChirho
    );

    let activated_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .activate_target_chirho(
            prepared_chirho.move_chirho,
            activation_inputs_chirho(&target_chirho),
        )
        .expect("the target verifies at the source's fenced cut and activates");

    assert_eq!(
        activated_chirho.active_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::TargetActivatedSourceRetainedChirho
    );
    assert_eq!(
        activated_chirho.move_chirho.writer_chirho(),
        WriterChirho::TargetChirho,
        "the contract did not move the writer, so activation did not really happen"
    );
}

#[test]
fn a_target_that_does_not_carry_the_fenced_cut_refuses_at_the_verification_not_the_binding_chirho()
{
    // STEP 3c — this is the arm whose absence I recorded as a tracked gap, now closed.
    //
    // The property: the target is verified at the SOURCE'S EXACT FENCED CUT, not at whatever the
    // target happens to hold. A target built at a different opening epoch carries a different
    // genesis and therefore does not contain the source's fenced record at all.
    //
    // WHY THE IDENTITY IS THE WHOLE ASSERTION. Both readings REFUSE, so an arm that merely checked
    // `is_err()` would pass under either and prove nothing — measured, not assumed:
    //
    //   verified at the fenced prefix (correct) -> JournalVerificationRefusedChirho
    //   verified at the target's own tail (mut) -> SourceFenceTargetCutMismatchChirho
    //
    // The second is the CONTRACT's binding comparison catching it one layer later. That backstop is
    // real and the system is safe either way — which is exactly why only the identity distinguishes
    // "the coordinator asked the right question" from "something downstream saved us".
    let source_chirho = RootJournalFixtureChirho::new_chirho("divergent-source");
    let target_chirho =
        RootJournalFixtureChirho::new_with_opening_epoch_chirho("divergent-target", 9);
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let mut store_chirho = source_chirho.store_chirho();

    // Begin succeeds: the source fence verifies only the SOURCE, so a divergent target is not
    // detected here. That is the point — nothing before activation has looked at the target's cut.
    let prepared_chirho = store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .begin_source_fenced_chirho(operation_inputs_chirho(&source_chirho, &target_chirho))
        .expect("the source fence does not depend on the target's content");

    let refusal_chirho = match store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .activate_target_chirho(
            prepared_chirho.move_chirho,
            activation_inputs_chirho(&target_chirho),
        ) {
        Ok(_activated_chirho) => {
            panic!("a target that does not carry the fenced cut must not activate")
        }
        Err(refusal_chirho) => refusal_chirho,
    };

    assert!(
        matches!(
            refusal_chirho,
            TenantMigrationCoordinatorRefusalChirho::MigrationContractChirho(
                TenantMigrationRefusalChirho::JournalVerificationRefusedChirho
            )
        ),
        "expected the fenced-prefix verification to refuse, got {refusal_chirho:?}"
    );
    assert!(
        !matches!(
            refusal_chirho,
            TenantMigrationCoordinatorRefusalChirho::MigrationContractChirho(
                TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho
            )
        ),
        "this is the backstop identity: the coordinator opened the target's own tail instead of the \
         cut the source fenced at, and only the contract's binding comparison caught it"
    );

    // And nothing moved: a refused activation leaves the attempt fenced, not half-activated.
    let current_chirho = store_chirho.load_current_chirho().unwrap().unwrap();
    assert_eq!(
        current_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::SourceFencedChirho
    );
}

#[test]
fn a_target_root_nested_inside_the_source_is_refused_by_its_own_identity_chirho() {
    // FOUND WHILE BUILDING STEP 4, not while looking for it. `same_root_chirho` compares roots for
    // IDENTITY via a binding match, so a target sitting INSIDE the source is two different roots and
    // passed. Measured first, then fixed: a nested tenant root both prepares and verifies, so this
    // was reachable rather than theoretical.
    //
    // Why it matters: activating onto a root nested in the source, then retiring the source, erases
    // the key of a tree the target lives inside.
    //
    // The identity is the assertion. `SameRootRefusedChirho` is the neighbour, and a nested pair
    // must NOT produce it — if it did, the new check would be dead and the old one would be doing
    // the work by accident.
    let outer_chirho = RootJournalFixtureChirho::new_chirho("nested-outer");
    // INSIDE the outer's tenant root, not beside it. An earlier version of this fixture put the
    // inner platform next to the tenant root, so the canonical roots never nested and the arm failed
    // loudly rather than passing while measuring nothing.
    let inner_platform_chirho = outer_chirho
        .tenant_root_path_chirho
        .join("inner-platform-chirho");
    std::fs::create_dir_all(&inner_platform_chirho).expect("inner platform");
    let inner_tenant_root_chirho =
        prepare_tenant_root_chirho(&inner_platform_chirho, TENANT_ID_CHIRHO)
            .expect("a nested tenant root prepares — that is the hazard");
    let inner_chirho =
        VerifiedTenantMigrationRootChirho::open_existing_chirho(&inner_tenant_root_chirho)
            .expect("a nested tenant root verifies — that is the hazard");

    for (source_chirho, target_chirho, direction_chirho) in [
        (
            outer_chirho.root_chirho.clone(),
            inner_chirho.clone(),
            "target inside source",
        ),
        (
            inner_chirho.clone(),
            outer_chirho.root_chirho.clone(),
            "source inside target",
        ),
    ] {
        let refusal_chirho = RootMoveChirho::new_chirho(source_chirho, target_chirho)
            .err()
            .unwrap_or_else(|| panic!("{direction_chirho} must refuse"));
        assert!(
            matches!(
                refusal_chirho,
                TenantMigrationRefusalChirho::NestedRootRefusedChirho
            ),
            "{direction_chirho}: expected the nesting identity, got {refusal_chirho:?}"
        );
        assert!(
            !matches!(
                refusal_chirho,
                TenantMigrationRefusalChirho::SameRootRefusedChirho
            ),
            "{direction_chirho}: the OLD identity fired, so the nesting check is dead code"
        );
    }
}

#[test]
fn activating_a_preparing_attempt_is_an_illegal_transition_not_a_missing_attempt_chirho() {
    // FOUND IN MY OWN REVIEW of this brick, not by a failing test. The phase mismatch used a
    // catch-all that answered `NoActiveAttemptChirho` for every non-fenced phase — telling a caller
    // activating from `PreparingChirho` that no attempt exists, when one does and is simply not
    // fenced yet. One refusal standing for two different facts is the shape this brick has already
    // paid for twice at the store layer.
    //
    // The identity IS the assertion. Both readings refuse, so an arm checking `is_err()` would pass
    // under the catch-all and prove nothing.
    let source_chirho = RootJournalFixtureChirho::new_chirho("preparing-activate-source");
    let target_chirho = RootJournalFixtureChirho::new_chirho("preparing-activate-target");
    let elector_chirho = warmed_single_node_chirho();
    let broad_chirho = elector_chirho.local_append_authority_handle_chirho();
    let control_chirho = broad_chirho.handoff_control_handle_chirho();
    let (mut store_chirho, preparing_chirho) =
        commit_preparing_only_chirho(&source_chirho, &target_chirho, &control_chirho);
    assert_eq!(
        preparing_chirho.phase_chirho(),
        TenantMigrationPhaseChirho::PreparingChirho
    );
    let (move_chirho, _attempt_chirho) = preparing_attempt_chirho(&source_chirho, &target_chirho);

    let refusal_chirho = match store_chirho
        .bind_operation_session_chirho(&control_chirho)
        .unwrap()
        .activate_target_chirho(move_chirho, activation_inputs_chirho(&target_chirho))
    {
        Ok(_activated_chirho) => {
            panic!("a preparing attempt must not activate — the source is not provably frozen")
        }
        Err(refusal_chirho) => refusal_chirho,
    };
    assert!(
        matches!(
            refusal_chirho,
            TenantMigrationCoordinatorRefusalChirho::StoreChirho(
                TenantMigrationStoreRefusalChirho::InvalidTransitionChirho
            )
        ),
        "expected an illegal-transition identity, got {refusal_chirho:?}"
    );
    assert!(
        !matches!(
            refusal_chirho,
            TenantMigrationCoordinatorRefusalChirho::NoActiveAttemptChirho
        ),
        "the catch-all is back: a preparing attempt is being reported as no attempt at all"
    );
}
