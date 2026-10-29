// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use anyhow::Result;
use cairn_ledger_log_chirho::admission_chirho::{
    AuthorityVerdictChirho, KindPolicyViewChirho, KindResolutionChirho, MembershipStatusChirho,
    MintAuthorityPolicyChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{
    AppendLegRequestChirho, AppendRequestChirho, LedgerJournalChirho,
};
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::asset_op_chirho::RoundingChirho;
use cairn_ledger_model_chirho::ids_chirho::{
    AccountIdChirho, AssetKindIdChirho, AssetKindRefChirho, DigestChirho,
};
use cairn_ledger_model_chirho::record_chirho::{AttributionChirho, LedgerOpChirho, LegDeltaChirho};
use cairn_ledger_model_chirho::{LogIdChirho, ShardEpochChirho};
use cairn_tenant_chirho::migration_completeness_chirho::{
    preliminary_migration_check_chirho, verify_migration_completeness_chirho,
    RootSurfaceEnumeratorChirho,
};
use cairn_tenant_chirho::self_containment_chirho::{
    verify_tenant_self_containment_chirho, TenantLogReferenceChirho, TenantObjectResolverChirho,
};
use cairn_tenant_chirho::surface_disposition_chirho::verify_surface_dispositions_chirho;
use cairn_tenant_chirho::tenant_chirho::prepare_tenant_root_chirho;
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const TENANT_ID_CHIRHO: &str = "tenant-move-chirho";
const CLUSTER_ID_CHIRHO: &str = "tenant-move-cluster-chirho";
const JOURNAL_PATH_CHIRHO: &str = "journals/tenant-move-chirho.jsonl";
const MONEY_KIND_CHIRHO: &str = "money-chirho";
const MONEY_POLICY_REF_CHIRHO: &str = "policy-money-v1-chirho";
const MINT_EVIDENCE_CHIRHO: &str = "evidence-good-mint-chirho";
static TEMP_COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);

struct TestClockChirho {
    now_ms_chirho: Cell<u64>,
}

impl TestClockChirho {
    fn set_chirho(&self, now_ms_chirho: u64) {
        self.now_ms_chirho.set(now_ms_chirho);
    }
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
            "tenant-move-sig-{}",
            &blake3::hash(signed_content_line_chirho.as_bytes()).to_hex()[..16]
        ))
    }

    fn key_id_chirho(&self) -> String {
        "tenant-move-key-chirho".to_owned()
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

struct MintAuthorityChirho;

impl AuthorityVerifierViewChirho for MintAuthorityChirho {
    fn verify_mint_chirho(
        &self,
        evidence_chirho: &DigestChirho,
        _kind_id_chirho: &AssetKindIdChirho,
    ) -> AuthorityVerdictChirho {
        if evidence_chirho.0 == MINT_EVIDENCE_CHIRHO {
            AuthorityVerdictChirho::VerifiedChirho
        } else {
            AuthorityVerdictChirho::UnverifiedChirho
        }
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
    authority_chirho: MintAuthorityChirho,
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
            authority_chirho: MintAuthorityChirho,
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
    storage_chirho: FsLedgerStorageChirho,
    views_chirho: TestViewsChirho,
    journal_path_chirho: StoragePathChirho,
    cluster_id_chirho: ClusterIdChirho,
}

impl RootJournalFixtureChirho {
    fn new_chirho(label_chirho: &str, tenant_id_chirho: &str) -> Self {
        let platform_root_chirho = unique_temp_root_chirho(label_chirho);
        fs::create_dir_all(&platform_root_chirho).expect("create fixture platform root");
        let tenant_root_path_chirho =
            prepare_tenant_root_chirho(&platform_root_chirho, tenant_id_chirho)
                .expect("prepare fixture tenant root");
        let storage_root_chirho = tenant_root_path_chirho.join("ledger-storage-chirho");
        fs::create_dir_all(&storage_root_chirho).expect("create fixture ledger namespace");
        let root_chirho =
            VerifiedTenantMigrationRootChirho::open_existing_chirho(&tenant_root_path_chirho)
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
            tenant_root_path_chirho,
            root_chirho,
            storage_chirho,
            views_chirho,
            journal_path_chirho,
            cluster_id_chirho,
        }
    }

    fn verified_cut_chirho(&self) -> VerifiedTenantLedgerCutChirho {
        open_verified_tenant_ledger_tail_chirho(
            self.root_chirho.clone(),
            &self.storage_chirho,
            self.views_chirho.verification_views_chirho(),
            &self.journal_path_chirho,
            &self.cluster_id_chirho,
        )
        .expect("full-verify fixture tail")
    }

    fn append_mint_chirho(&self, idempotency_key_chirho: &str) {
        self.views_chirho.clock_chirho.set_chirho(1_001);
        let mut journal_chirho = LedgerJournalChirho::open_chirho(
            self.views_chirho.journal_ports_chirho(&self.storage_chirho),
            self.journal_path_chirho.clone(),
            &self.cluster_id_chirho,
        )
        .expect("open fixture journal for append");
        journal_chirho
            .append_chirho(mint_request_chirho(idempotency_key_chirho))
            .expect("append fixture mint");
    }

    fn corrupt_journal_chirho(&self) {
        let mut bytes_chirho = self
            .storage_chirho
            .read_all_chirho(&self.journal_path_chirho)
            .expect("read fixture journal")
            .expect("fixture journal exists");
        let index_chirho = bytes_chirho
            .iter()
            .position(|byte_chirho| *byte_chirho == b'a')
            .expect("fixture journal has a mutable body byte");
        bytes_chirho[index_chirho] = b'b';
        self.storage_chirho
            .atomic_write_chirho(&self.journal_path_chirho, &bytes_chirho)
            .expect("write corrupt fixture journal");
    }
}

impl Drop for RootJournalFixtureChirho {
    fn drop(&mut self) {
        let _remove_chirho = fs::remove_dir_all(&self.platform_root_chirho);
    }
}

fn unique_temp_root_chirho(label_chirho: &str) -> PathBuf {
    let sequence_chirho = TEMP_COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-tenant-migration-{label_chirho}-{}-{sequence_chirho}-chirho",
        std::process::id()
    ))
}

fn mint_request_chirho(idempotency_key_chirho: &str) -> AppendRequestChirho {
    AppendRequestChirho {
        op_chirho: LedgerOpChirho::MintChirho {
            authority_evidence_chirho: DigestChirho(MINT_EVIDENCE_CHIRHO.to_owned()),
        },
        legs_chirho: vec![AppendLegRequestChirho {
            account_chirho: LogIdChirho::new_chirho("issuer-chirho", MONEY_KIND_CHIRHO),
            kind_policy_ref_chirho: AssetKindRefChirho(DigestChirho(
                MONEY_POLICY_REF_CHIRHO.to_owned(),
            )),
            delta_chirho: LegDeltaChirho::CreditChirho,
            amount_chirho: 10,
            counterpart_chirho: None,
        }],
        idempotency_key_chirho: idempotency_key_chirho.to_owned(),
        provenance_chirho: None,
        attribution_chirho: AttributionChirho::PlatformChirho,
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

fn all_carried_chirho() -> CarriedObligationsChirho {
    CarriedObligationsChirho {
        signed_history_complete_chirho: true,
        projections_rebuilt_chirho: true,
        privacy_key_custody_transferred_chirho: true,
        audit_coordinates_preserved_chirho: true,
    }
}

/// Test-only admission that this pure contract does not itself fence an append path.
/// Production must provide a real `SourceAppendFenceWitnessChirho` implementation in the durable
/// adapter; keeping this name at every fixture call prevents the tests from implying otherwise.
#[derive(Debug)]
struct UnfencedPureContractOnlyChirho {
    fence_identity_chirho: TenantMigrationFenceIdentityChirho,
    reports_active_chirho: Arc<AtomicBool>,
    liveness_observed_chirho: Option<Arc<AtomicBool>>,
}

impl SourceAppendFenceWitnessChirho for UnfencedPureContractOnlyChirho {
    fn fence_identity_chirho(&self) -> &TenantMigrationFenceIdentityChirho {
        &self.fence_identity_chirho
    }

    fn remains_active_chirho(&self) -> bool {
        if let Some(observed_chirho) = &self.liveness_observed_chirho {
            observed_chirho.store(true, Ordering::SeqCst);
        }
        self.reports_active_chirho.load(Ordering::SeqCst)
    }
}

fn unfenced_pure_contract_only_chirho(
    attempt_chirho: TenantMigrationAttemptIdentityChirho,
    source_cut_chirho: VerifiedTenantLedgerCutChirho,
) -> UnfencedPureContractOnlyChirho {
    UnfencedPureContractOnlyChirho {
        fence_identity_chirho:
            TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
                attempt_chirho,
                source_cut_chirho,
            )
            .expect("bind test-only post-fence identity"),
        reports_active_chirho: Arc::new(AtomicBool::new(true)),
        liveness_observed_chirho: None,
    }
}

fn inactive_fence_for_refusal_arm_chirho(
    attempt_chirho: TenantMigrationAttemptIdentityChirho,
    source_cut_chirho: VerifiedTenantLedgerCutChirho,
) -> UnfencedPureContractOnlyChirho {
    UnfencedPureContractOnlyChirho {
        fence_identity_chirho:
            TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
                attempt_chirho,
                source_cut_chirho,
            )
            .expect("bind inactive test-only post-fence identity"),
        reports_active_chirho: Arc::new(AtomicBool::new(false)),
        liveness_observed_chirho: None,
    }
}

fn prepare_attempt_chirho(
    move_chirho: &mut RootMoveChirho,
    source_chirho: &RootJournalFixtureChirho,
) -> TenantMigrationAttemptIdentityChirho {
    move_chirho
        .prepare_source_append_fence_attempt_chirho(source_chirho.verified_cut_chirho())
        .expect("derive pre-fence attempt identity")
}

fn prepared_move_chirho(
    source_chirho: &RootJournalFixtureChirho,
    target_chirho: &RootJournalFixtureChirho,
) -> RootMoveChirho {
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .expect("bind fixture migration roots");
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    move_chirho
}

#[test]
fn preliminary_check_cannot_activate_and_exact_fenced_cut_can_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("target", TENANT_ID_CHIRHO);
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .expect("bind distinct same-tenant roots");
    let mut writers_chirho = vec![move_chirho.writer_chirho()];

    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    writers_chirho.push(move_chirho.writer_chirho());
    let mut warrant_move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    warrant_move_chirho.begin_preparing_chirho().unwrap();
    warrant_move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    let warrant_attempt_chirho = prepare_attempt_chirho(&mut warrant_move_chirho, &source_chirho);
    warrant_move_chirho
        .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            warrant_attempt_chirho,
            source_chirho.verified_cut_chirho(),
        ))
        .unwrap();
    let early_warrant_chirho = warrant_move_chirho
        .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
        .unwrap();
    assert_eq!(
        move_chirho.activate_target_chirho(&early_warrant_chirho),
        Err(TenantMigrationRefusalChirho::OutOfOrderChirho {
            from_chirho: RootMovePhaseChirho::PreliminaryTargetCheckedChirho,
            attempted_chirho: "activate_target_chirho",
        }),
        "preflight evidence must not make activation reachable"
    );
    assert_eq!(move_chirho.writer_chirho(), WriterChirho::SourceChirho);

    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
    move_chirho
        .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        ))
        .unwrap();
    writers_chirho.push(move_chirho.writer_chirho());
    let warrant_chirho = move_chirho
        .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
        .unwrap();
    writers_chirho.push(move_chirho.writer_chirho());
    move_chirho.activate_target_chirho(&warrant_chirho).unwrap();
    writers_chirho.push(move_chirho.writer_chirho());
    move_chirho
        .retire_source_chirho(&all_carried_chirho())
        .unwrap();
    writers_chirho.push(move_chirho.writer_chirho());

    assert_eq!(
        writers_chirho,
        vec![
            WriterChirho::SourceChirho,
            WriterChirho::SourceChirho,
            WriterChirho::NobodyChirho,
            WriterChirho::NobodyChirho,
            WriterChirho::TargetChirho,
            WriterChirho::TargetChirho,
        ]
    );
}

#[test]
fn a_source_append_after_precheck_invalidates_the_old_target_cut_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("stale-source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("stale-target", TENANT_ID_CHIRHO);
    let target_cut_before_fence_chirho = target_chirho.verified_cut_chirho();
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();

    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
    source_chirho.append_mint_chirho("source-advanced-chirho");
    move_chirho
        .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        ))
        .unwrap();
    let refusal_chirho = move_chirho
        .record_post_fence_target_verified_chirho(target_cut_before_fence_chirho)
        .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantMigrationRefusalChirho::SourceFenceTargetCutMismatchChirho
    );
    assert_eq!(move_chirho.writer_chirho(), WriterChirho::NobodyChirho);
}

#[test]
fn same_root_alias_and_foreign_tenant_are_refused_by_identity_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("identity-source", TENANT_ID_CHIRHO);
    let same_root_alias_chirho = VerifiedTenantMigrationRootChirho::open_existing_chirho(
        &source_chirho.tenant_root_path_chirho.join("."),
    )
    .unwrap();
    assert_eq!(
        RootMoveChirho::new_chirho(source_chirho.root_chirho.clone(), same_root_alias_chirho)
            .unwrap_err(),
        TenantMigrationRefusalChirho::SameRootRefusedChirho
    );

    let foreign_tenant_chirho =
        RootJournalFixtureChirho::new_chirho("foreign-tenant", "other-tenant-chirho");
    assert_eq!(
        RootMoveChirho::new_chirho(
            source_chirho.root_chirho.clone(),
            foreign_tenant_chirho.root_chirho.clone(),
        )
        .unwrap_err(),
        TenantMigrationRefusalChirho::TenantMismatchChirho
    );
}

#[test]
fn attempt_and_fence_identities_bind_every_migration_coordinate_chirho() {
    let source_chirho =
        RootJournalFixtureChirho::new_chirho("identity-base-source", TENANT_ID_CHIRHO);
    let target_chirho =
        RootJournalFixtureChirho::new_chirho("identity-base-target", TENANT_ID_CHIRHO);
    let alternate_source_chirho =
        RootJournalFixtureChirho::new_chirho("identity-other-source", TENANT_ID_CHIRHO);
    let alternate_target_chirho =
        RootJournalFixtureChirho::new_chirho("identity-other-target", TENANT_ID_CHIRHO);

    let mut base_move_chirho = prepared_move_chirho(&source_chirho, &target_chirho);
    let base_attempt_chirho = prepare_attempt_chirho(&mut base_move_chirho, &source_chirho);
    let mut source_variant_move_chirho =
        prepared_move_chirho(&alternate_source_chirho, &target_chirho);
    let source_variant_attempt_chirho =
        prepare_attempt_chirho(&mut source_variant_move_chirho, &alternate_source_chirho);
    let mut target_variant_move_chirho =
        prepared_move_chirho(&source_chirho, &alternate_target_chirho);
    let target_variant_attempt_chirho =
        prepare_attempt_chirho(&mut target_variant_move_chirho, &source_chirho);

    // These private test values isolate tenant text from filesystem identity. Public constructors
    // separately prove the marker and custody binding; this arm proves the hash includes the tenant.
    let tenant_variant_source_root_chirho = VerifiedTenantMigrationRootChirho {
        custody_chirho: Arc::clone(&source_chirho.root_chirho.custody_chirho),
        tenant_id_chirho: "identity-other-tenant-chirho".to_owned(),
    };
    let tenant_variant_target_root_chirho = VerifiedTenantMigrationRootChirho {
        custody_chirho: Arc::clone(&target_chirho.root_chirho.custody_chirho),
        tenant_id_chirho: "identity-other-tenant-chirho".to_owned(),
    };
    let tenant_variant_attempt_chirho = derive_attempt_identity_chirho(
        &tenant_variant_source_root_chirho,
        &tenant_variant_target_root_chirho,
        base_attempt_chirho
            .preliminary_source_binding_chirho
            .clone(),
        None,
    )
    .unwrap();
    let authority_binding_digest_chirho = "a".repeat(64);
    let authority_variant_attempt_chirho = derive_attempt_identity_chirho(
        &source_chirho.root_chirho,
        &target_chirho.root_chirho,
        base_attempt_chirho
            .preliminary_source_binding_chirho
            .clone(),
        Some(&authority_binding_digest_chirho),
    )
    .unwrap();

    require_same_binding_chirho(
        &base_attempt_chirho.preliminary_source_binding_chirho,
        &source_variant_attempt_chirho.preliminary_source_binding_chirho,
        TenantMigrationRefusalChirho::SourceFenceCutChangedChirho,
    )
    .expect("source-root arm must keep the preliminary cut identical");
    require_same_binding_chirho(
        &base_attempt_chirho.preliminary_source_binding_chirho,
        &target_variant_attempt_chirho.preliminary_source_binding_chirho,
        TenantMigrationRefusalChirho::SourceFenceCutChangedChirho,
    )
    .expect("target-root arm must keep the preliminary cut identical");

    source_chirho.append_mint_chirho("identity-post-cut-one-chirho");
    alternate_source_chirho.append_mint_chirho("identity-post-cut-one-chirho");
    let first_post_cut_chirho = source_chirho.verified_cut_chirho();
    let alternate_source_post_cut_chirho = alternate_source_chirho.verified_cut_chirho();
    require_same_binding_chirho(
        &binding_from_cut_chirho(first_post_cut_chirho.clone()),
        &binding_from_cut_chirho(alternate_source_post_cut_chirho.clone()),
        TenantMigrationRefusalChirho::SourceFenceCutChangedChirho,
    )
    .expect("source-root arm must keep the post-fence cut identical");
    let mut cut_variant_move_chirho = prepared_move_chirho(&source_chirho, &target_chirho);
    let cut_variant_attempt_chirho = cut_variant_move_chirho
        .prepare_source_append_fence_attempt_chirho(first_post_cut_chirho.clone())
        .unwrap();

    for (label_chirho, variant_chirho) in [
        ("tenant", &tenant_variant_attempt_chirho),
        ("source-root", &source_variant_attempt_chirho),
        ("target-root", &target_variant_attempt_chirho),
        ("pre-fence-cut", &cut_variant_attempt_chirho),
        ("operation-authority", &authority_variant_attempt_chirho),
    ] {
        assert_ne!(
            base_attempt_chirho.digest_chirho(),
            variant_chirho.digest_chirho(),
            "attempt identity must bind {label_chirho}"
        );
    }

    let base_fence_chirho = TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
        base_attempt_chirho.clone(),
        first_post_cut_chirho.clone(),
    )
    .unwrap();
    let tenant_variant_post_cut_chirho = VerifiedTenantLedgerCutChirho {
        root_chirho: tenant_variant_source_root_chirho,
        cluster_id_chirho: first_post_cut_chirho.cluster_id_chirho.clone(),
        journal_path_chirho: first_post_cut_chirho.journal_path_chirho.clone(),
        cut_chirho: first_post_cut_chirho.cut_chirho.clone(),
    };
    let tenant_variant_fence_chirho =
        TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
            tenant_variant_attempt_chirho,
            tenant_variant_post_cut_chirho,
        )
        .unwrap();
    let source_variant_fence_chirho =
        TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
            source_variant_attempt_chirho,
            alternate_source_post_cut_chirho,
        )
        .unwrap();
    let target_variant_fence_chirho =
        TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
            target_variant_attempt_chirho,
            first_post_cut_chirho,
        )
        .unwrap();
    source_chirho.append_mint_chirho("identity-post-cut-two-chirho");
    let cut_variant_fence_chirho =
        TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
            base_attempt_chirho,
            source_chirho.verified_cut_chirho(),
        )
        .unwrap();

    for (label_chirho, variant_chirho) in [
        ("tenant", &tenant_variant_fence_chirho),
        ("source-root", &source_variant_fence_chirho),
        ("target-root", &target_variant_fence_chirho),
        ("post-fence-cut", &cut_variant_fence_chirho),
    ] {
        assert_ne!(
            base_fence_chirho.digest_chirho(),
            variant_chirho.digest_chirho(),
            "fence identity must bind {label_chirho}"
        );
    }
}

#[test]
fn a_fence_witness_for_another_prepared_attempt_refuses_before_liveness_chirho() {
    let source_chirho =
        RootJournalFixtureChirho::new_chirho("foreign-attempt-source", TENANT_ID_CHIRHO);
    let target_chirho =
        RootJournalFixtureChirho::new_chirho("foreign-attempt-target", TENANT_ID_CHIRHO);
    let mut selected_move_chirho = prepared_move_chirho(&source_chirho, &target_chirho);
    let selected_attempt_chirho = prepare_attempt_chirho(&mut selected_move_chirho, &source_chirho);
    source_chirho.append_mint_chirho("foreign-attempt-cut-change-chirho");
    let mut other_move_chirho = prepared_move_chirho(&source_chirho, &target_chirho);
    let other_attempt_chirho = prepare_attempt_chirho(&mut other_move_chirho, &source_chirho);
    assert_ne!(selected_attempt_chirho, other_attempt_chirho);

    let liveness_observed_chirho = Arc::new(AtomicBool::new(false));
    let foreign_witness_chirho = UnfencedPureContractOnlyChirho {
        fence_identity_chirho:
            TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
                other_attempt_chirho,
                source_chirho.verified_cut_chirho(),
            )
            .unwrap(),
        reports_active_chirho: Arc::new(AtomicBool::new(true)),
        liveness_observed_chirho: Some(Arc::clone(&liveness_observed_chirho)),
    };
    assert_eq!(
        selected_move_chirho.record_source_append_fence_chirho(foreign_witness_chirho),
        Err(TenantMigrationRefusalChirho::SourceFenceAttemptMismatchChirho)
    );
    assert_eq!(
        selected_move_chirho.phase_chirho(),
        RootMovePhaseChirho::SourceFenceAttemptPreparedChirho
    );
    assert!(
        !liveness_observed_chirho.load(Ordering::SeqCst),
        "a foreign attempt must refuse before consulting witness liveness"
    );
}

#[test]
fn a_cut_bound_to_a_third_root_cannot_verify_the_selected_target_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("binding-source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("binding-target", TENANT_ID_CHIRHO);
    let third_chirho = RootJournalFixtureChirho::new_chirho("binding-third", TENANT_ID_CHIRHO);
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
    move_chirho
        .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        ))
        .unwrap();

    let refusal_chirho = move_chirho
        .record_post_fence_target_verified_chirho(third_chirho.verified_cut_chirho())
        .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantMigrationRefusalChirho::TargetRootMismatchChirho
    );
}

#[test]
fn corrupt_journal_bytes_never_become_a_verified_tenant_cut_chirho() {
    let fixture_chirho = RootJournalFixtureChirho::new_chirho("corrupt", TENANT_ID_CHIRHO);
    fixture_chirho.corrupt_journal_chirho();
    let refusal_chirho = open_verified_tenant_ledger_tail_chirho(
        fixture_chirho.root_chirho.clone(),
        &fixture_chirho.storage_chirho,
        fixture_chirho.views_chirho.verification_views_chirho(),
        &fixture_chirho.journal_path_chirho,
        &fixture_chirho.cluster_id_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantMigrationRefusalChirho::JournalVerificationRefusedChirho
    );
}

#[test]
fn read_time_clock_does_not_change_the_record_carried_cut_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("hlc-source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("hlc-target", TENANT_ID_CHIRHO);
    source_chirho.views_chirho.clock_chirho.set_chirho(2_000);
    target_chirho.views_chirho.clock_chirho.set_chirho(9_000);

    assert_eq!(
        source_chirho.verified_cut_chirho().cut_chirho(),
        target_chirho.verified_cut_chirho().cut_chirho(),
        "HLC equality must come from the signed record, not the reader's clock"
    );
}

#[test]
fn a_ledger_namespace_outside_the_bound_root_is_refused_chirho() {
    let root_chirho = RootJournalFixtureChirho::new_chirho("namespace-root", TENANT_ID_CHIRHO);
    let outside_chirho =
        RootJournalFixtureChirho::new_chirho("namespace-outside", TENANT_ID_CHIRHO);
    let refusal_chirho = open_verified_tenant_ledger_tail_chirho(
        root_chirho.root_chirho.clone(),
        &outside_chirho.storage_chirho,
        outside_chirho.views_chirho.verification_views_chirho(),
        &outside_chirho.journal_path_chirho,
        &outside_chirho.cluster_id_chirho,
    )
    .unwrap_err();
    assert_eq!(
        refusal_chirho,
        TenantMigrationRefusalChirho::LedgerNamespaceOutsideRootChirho
    );
}

#[test]
fn a_replayed_source_fence_must_name_the_same_verified_source_cut_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("retry-source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("retry-target", TENANT_ID_CHIRHO);
    let initial_cut_chirho = source_chirho.verified_cut_chirho();
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
        .prepare_source_append_fence_attempt_chirho(initial_cut_chirho.clone())
        .unwrap();
    move_chirho
        .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho.clone(),
            initial_cut_chirho,
        ))
        .unwrap();

    source_chirho.append_mint_chirho("changed-source-cut-after-fence-witness-chirho");
    assert_eq!(
        move_chirho.record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        )),
        Err(TenantMigrationRefusalChirho::SourceFenceCutChangedChirho)
    );
}

#[test]
fn an_inactive_source_fence_witness_cannot_advance_the_phase_chirho() {
    let source_chirho =
        RootJournalFixtureChirho::new_chirho("inactive-fence-source", TENANT_ID_CHIRHO);
    let target_chirho =
        RootJournalFixtureChirho::new_chirho("inactive-fence-target", TENANT_ID_CHIRHO);
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);

    assert_eq!(
        move_chirho.record_source_append_fence_chirho(inactive_fence_for_refusal_arm_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        )),
        Err(TenantMigrationRefusalChirho::SourceAppendFenceNotActiveChirho)
    );
    assert_eq!(
        move_chirho.phase_chirho(),
        RootMovePhaseChirho::SourceFenceAttemptPreparedChirho
    );
    assert_eq!(move_chirho.writer_chirho(), WriterChirho::SourceChirho);
}

#[test]
fn a_source_fence_that_becomes_inactive_refuses_activation_chirho() {
    let source_chirho =
        RootJournalFixtureChirho::new_chirho("dropped-fence-source", TENANT_ID_CHIRHO);
    let target_chirho =
        RootJournalFixtureChirho::new_chirho("dropped-fence-target", TENANT_ID_CHIRHO);
    let reports_active_chirho = Arc::new(AtomicBool::new(true));
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();
    move_chirho.begin_preparing_chirho().unwrap();
    move_chirho
        .record_preliminary_target_check_chirho(preliminary_check_chirho())
        .unwrap();
    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
    move_chirho
        .record_source_append_fence_chirho(UnfencedPureContractOnlyChirho {
            fence_identity_chirho:
                TenantMigrationFenceIdentityChirho::bind_post_fence_source_cut_chirho(
                    attempt_chirho,
                    source_chirho.verified_cut_chirho(),
                )
                .unwrap(),
            reports_active_chirho: Arc::clone(&reports_active_chirho),
            liveness_observed_chirho: None,
        })
        .unwrap();
    let warrant_chirho = move_chirho
        .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
        .unwrap();

    reports_active_chirho.store(false, Ordering::SeqCst);
    assert_eq!(
        move_chirho.activate_target_chirho(&warrant_chirho),
        Err(TenantMigrationRefusalChirho::SourceAppendFenceNotActiveChirho)
    );
    assert_eq!(
        move_chirho.phase_chirho(),
        RootMovePhaseChirho::SourceFenceWitnessedTargetVerifiedChirho
    );
    assert_eq!(move_chirho.writer_chirho(), WriterChirho::NobodyChirho);
}

#[test]
fn retirement_refuses_each_unverified_carried_obligation_chirho() {
    for (label_chirho, carried_chirho) in [
        (
            "signed_history_complete_chirho",
            CarriedObligationsChirho {
                signed_history_complete_chirho: false,
                ..all_carried_chirho()
            },
        ),
        (
            "projections_rebuilt_chirho",
            CarriedObligationsChirho {
                projections_rebuilt_chirho: false,
                ..all_carried_chirho()
            },
        ),
        (
            "privacy_key_custody_transferred_chirho",
            CarriedObligationsChirho {
                privacy_key_custody_transferred_chirho: false,
                ..all_carried_chirho()
            },
        ),
        (
            "audit_coordinates_preserved_chirho",
            CarriedObligationsChirho {
                audit_coordinates_preserved_chirho: false,
                ..all_carried_chirho()
            },
        ),
    ] {
        let source_chirho = RootJournalFixtureChirho::new_chirho(
            &format!("obligation-source-{label_chirho}"),
            TENANT_ID_CHIRHO,
        );
        let target_chirho = RootJournalFixtureChirho::new_chirho(
            &format!("obligation-target-{label_chirho}"),
            TENANT_ID_CHIRHO,
        );
        let mut move_chirho = RootMoveChirho::new_chirho(
            source_chirho.root_chirho.clone(),
            target_chirho.root_chirho.clone(),
        )
        .unwrap();
        move_chirho.begin_preparing_chirho().unwrap();
        move_chirho
            .record_preliminary_target_check_chirho(preliminary_check_chirho())
            .unwrap();
        let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
        move_chirho
            .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
                attempt_chirho,
                source_chirho.verified_cut_chirho(),
            ))
            .unwrap();
        let warrant_chirho = move_chirho
            .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
            .unwrap();
        move_chirho.activate_target_chirho(&warrant_chirho).unwrap();

        assert_eq!(
            move_chirho.retire_source_chirho(&carried_chirho),
            Err(TenantMigrationRefusalChirho::ObligationsNotCarriedChirho {
                missing_chirho: vec![label_chirho],
            }),
            "withholding {label_chirho} must refuse retirement"
        );
        assert_eq!(
            move_chirho.phase_chirho(),
            RootMovePhaseChirho::ActivatedChirho
        );
    }
}

#[test]
fn every_transition_is_idempotent_and_stale_earlier_retries_do_not_rewind_chirho() {
    let source_chirho = RootJournalFixtureChirho::new_chirho("redrive-source", TENANT_ID_CHIRHO);
    let target_chirho = RootJournalFixtureChirho::new_chirho("redrive-target", TENANT_ID_CHIRHO);
    let mut move_chirho = RootMoveChirho::new_chirho(
        source_chirho.root_chirho.clone(),
        target_chirho.root_chirho.clone(),
    )
    .unwrap();

    for _retry_chirho in 0..3 {
        move_chirho.begin_preparing_chirho().unwrap();
        assert_eq!(
            move_chirho.phase_chirho(),
            RootMovePhaseChirho::PreparingChirho
        );
    }
    for _retry_chirho in 0..3 {
        move_chirho
            .record_preliminary_target_check_chirho(preliminary_check_chirho())
            .unwrap();
        assert_eq!(
            move_chirho.phase_chirho(),
            RootMovePhaseChirho::PreliminaryTargetCheckedChirho
        );
    }
    let attempt_chirho = prepare_attempt_chirho(&mut move_chirho, &source_chirho);
    for _retry_chirho in 0..2 {
        assert_eq!(
            prepare_attempt_chirho(&mut move_chirho, &source_chirho),
            attempt_chirho
        );
    }
    for _retry_chirho in 0..3 {
        move_chirho
            .record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
                attempt_chirho.clone(),
                source_chirho.verified_cut_chirho(),
            ))
            .unwrap();
        assert_eq!(move_chirho.writer_chirho(), WriterChirho::NobodyChirho);
    }
    let mut warrant_chirho = move_chirho
        .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
        .unwrap();
    for _retry_chirho in 0..2 {
        warrant_chirho = move_chirho
            .record_post_fence_target_verified_chirho(target_chirho.verified_cut_chirho())
            .unwrap();
    }
    for _retry_chirho in 0..3 {
        move_chirho.activate_target_chirho(&warrant_chirho).unwrap();
        assert_eq!(move_chirho.writer_chirho(), WriterChirho::TargetChirho);
    }

    assert_eq!(
        move_chirho.begin_preparing_chirho(),
        Err(TenantMigrationRefusalChirho::OutOfOrderChirho {
            from_chirho: RootMovePhaseChirho::ActivatedChirho,
            attempted_chirho: "begin_preparing_chirho",
        })
    );
    assert_eq!(
        move_chirho.record_preliminary_target_check_chirho(preliminary_check_chirho()),
        Err(TenantMigrationRefusalChirho::OutOfOrderChirho {
            from_chirho: RootMovePhaseChirho::ActivatedChirho,
            attempted_chirho: "record_preliminary_target_check_chirho",
        })
    );
    assert_eq!(
        move_chirho.record_source_append_fence_chirho(unfenced_pure_contract_only_chirho(
            attempt_chirho,
            source_chirho.verified_cut_chirho(),
        )),
        Err(TenantMigrationRefusalChirho::OutOfOrderChirho {
            from_chirho: RootMovePhaseChirho::ActivatedChirho,
            attempted_chirho: "record_source_append_fence_chirho",
        })
    );
    for _retry_chirho in 0..3 {
        move_chirho
            .retire_source_chirho(&all_carried_chirho())
            .unwrap();
        assert_eq!(
            move_chirho.phase_chirho(),
            RootMovePhaseChirho::SourceRetiredChirho
        );
    }
}
