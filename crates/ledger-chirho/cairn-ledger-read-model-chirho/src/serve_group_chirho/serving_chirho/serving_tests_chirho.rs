// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::feeder_chirho::{
    feed_projection_once_chirho, follow_receipt_signed_content_chirho, FollowReceiptChirho,
};
use crate::follower_chirho::FollowerReadRefusalChirho;
use crate::publication_chirho::{load_published_projection_chirho, publish_projection_chirho};
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, BalancesFoldChirho, MemStorageChirho,
    OpenAuthorityChirho, OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::record_chirho::HlcChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "serving-test-registry-chirho";

struct HarnessChirho {
    storage_chirho: MemStorageChirho,
    journal_signer_chirho: TestSignerChirho,
    feeder_root_chirho: TestSignerChirho,
    registry_root_chirho: TestSignerChirho,
    clock_chirho: StepClockChirho,
    membership_chirho: AllMembersChirho,
    kind_registry_chirho: OpenRegistryChirho,
    authority_chirho: OpenAuthorityChirho,
}

impl HarnessChirho {
    fn new_chirho() -> Self {
        HarnessChirho {
            storage_chirho: MemStorageChirho::default(),
            journal_signer_chirho: TestSignerChirho {
                name_chirho: "journal-root-chirho",
            },
            feeder_root_chirho: TestSignerChirho {
                name_chirho: "feeder-root-chirho",
            },
            registry_root_chirho: TestSignerChirho {
                name_chirho: "projection-registry-root-chirho",
            },
            clock_chirho: StepClockChirho {
                now_ms_chirho: Cell::new(1_000),
            },
            membership_chirho: AllMembersChirho,
            kind_registry_chirho: OpenRegistryChirho,
            authority_chirho: OpenAuthorityChirho,
        }
    }

    fn journal_ports_chirho(&self) -> JournalPortsChirho<'_> {
        JournalPortsChirho {
            storage_chirho: &self.storage_chirho,
            signer_chirho: &self.journal_signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.kind_registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    fn source_chirho<'harness_chirho>(
        &'harness_chirho self,
        path_chirho: &'harness_chirho StoragePathChirho,
        cluster_chirho: &'harness_chirho ClusterIdChirho,
    ) -> ProjectionSourceChirho<'harness_chirho> {
        ProjectionSourceChirho {
            journal_ports_chirho: self.journal_ports_chirho(),
            journal_path_chirho: path_chirho,
            cluster_chirho,
        }
    }

    fn register_chirho(&self, descriptor_chirho: ProjectionDescriptorChirho) {
        append_projection_registry_op_chirho(
            &self.storage_chirho,
            &self.registry_root_chirho,
            &registry_path_chirho(),
            REGISTRY_ID_CHIRHO,
            ProjectionRegistryOpChirho::RegisterProjectionChirho { descriptor_chirho },
        )
        .unwrap();
    }

    fn registry_chirho(&self) -> crate::registry_chirho::VerifiedProjectionRegistryChirho {
        load_verified_projection_registry_chirho(
            &self.storage_chirho,
            &self.registry_root_chirho,
            &registry_path_chirho(),
            REGISTRY_ID_CHIRHO,
        )
        .unwrap()
    }

    /// Create the journal at `path` and mint the two seed balances.
    fn seed_journal_chirho(&self, path_chirho: &StoragePathChirho) {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.journal_ports_chirho(),
            path_chirho.clone(),
            cluster_chirho(),
            1,
        )
        .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-serve-1"))
            .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("bob-chirho", 300, "idem-serve-2"))
            .unwrap();
    }

    fn append_more_chirho(&self, path_chirho: &StoragePathChirho, idem_chirho: &str) {
        let mut journal_chirho = LedgerJournalChirho::open_chirho(
            self.journal_ports_chirho(),
            path_chirho.clone(),
            &cluster_chirho(),
        )
        .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("carol-chirho", 5, idem_chirho))
            .unwrap();
    }

    /// Re-sign a crafted receipt with the feeder root so only NON-signature nets can refuse it.
    fn resign_chirho(&self, receipt_chirho: &mut FollowReceiptChirho) {
        receipt_chirho.feeder_sig_chirho = String::new();
        let content_chirho = follow_receipt_signed_content_chirho(receipt_chirho).unwrap();
        receipt_chirho.feeder_sig_chirho = self
            .feeder_root_chirho
            .sign_chirho(&content_chirho)
            .unwrap();
    }
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-serve-chirho".to_string())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/serve-cluster-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/serving-registry-chirho.jsonl".to_string())
}

/// A descriptor + the exact verified-source evidence it binds, for a given family id and policy.
fn descriptor_with_chirho(
    name_chirho: &str,
    family_id_chirho: &str,
    read_policy_chirho: ProjectionReadPolicyChirho,
    max_lag_ms_chirho: u64,
) -> (
    ProjectionDescriptorChirho,
    Vec<VerifiedProjectionSourceChirho>,
) {
    let sources_chirho = vec![VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: family_id_chirho.to_string(),
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        },
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
    }];
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: name_chirho.to_string(),
        source_families_chirho: vec![ProjectionSourceBindingChirho {
            family_id_chirho: family_id_chirho.to_string(),
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        }],
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: max_lag_ms_chirho,
            read_policy_chirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: evidence_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    (descriptor_chirho, sources_chirho)
}

fn journal_family_chirho() -> String {
    journal_source_family_id_chirho(&cluster_chirho())
}

#[test]
fn fresh_read_serves_end_to_end_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    match outcome_chirho {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            view_chirho,
            lag_ms_chirho,
        }) => {
            // No records landed since the feed: the receipt IS the live tail — zero lag, and the
            // served view's state digest is exactly the receipt-bound bytes digest.
            assert_eq!(lag_ms_chirho, 0);
            assert_eq!(
                view_chirho.state_digest_chirho.0,
                materialized_chirho.receipt_chirho.view_digest_hex_chirho
            );
            assert_eq!(
                view_chirho.watermark_chirho.source_family_id_chirho,
                journal_family_chirho()
            );
        }
        other_chirho => panic!("expected a fresh read, got {other_chirho:?}"),
    }
}

#[test]
fn served_read_refuses_torn_source_without_repairing_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-read-only-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-read-only-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow_mut()
        .get_mut(path_local_chirho.key_chirho())
        .unwrap()
        .extend_from_slice(br#"{"schema_chirho":"ledger-record-v1-chirho"#);
    let before_chirho = harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow()
        .clone();

    let error_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("ReadOnlyRecoveryRequiredChirho"));
    assert_eq!(
        *harness_chirho.storage_chirho.objects_chirho.borrow(),
        before_chirho,
        "a served projection read must be incapable of journal repair"
    );
}

#[test]
fn effect_host_exact_cut_refuses_inside_lag_window_across_restart_and_heals_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_chirho = journal_path_chirho();
    let cluster_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-effect-host-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-effect-host-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let head_path_chirho =
        StoragePathChirho("projections/effect-host-head-chirho.json".to_string());
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho,
    )
    .unwrap();
    harness_chirho.append_more_chirho(&path_chirho, "idem-effect-host-behind");

    let projection_only_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
    )
    .unwrap();
    assert!(matches!(
        projection_only_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            lag_ms_chirho: 0..=5_000,
            ..
        })
    ));

    let effect_host_chirho = serve_effect_host_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
    )
    .unwrap();
    assert_eq!(
        effect_host_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EffectCutBehindChirho,
        ))
    );

    // Reconstruct the registry and signed published head from storage: no process-local poison bit
    // can be responsible for the refusal surviving a restart.
    let reopened_registry_chirho = harness_chirho.registry_chirho();
    let reopened_materialized_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let after_restart_chirho = serve_effect_host_follower_read_chirho(
        &reopened_registry_chirho,
        &reopened_materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
    )
    .unwrap();
    assert_eq!(after_restart_chirho, effect_host_chirho);

    let refreshed_chirho = feed_projection_once_chirho(
        &reopened_registry_chirho,
        "balances-effect-host-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &refreshed_chirho,
        &head_path_chirho,
    )
    .unwrap();
    let reopened_refreshed_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    assert!(matches!(
        serve_effect_host_follower_read_chirho(
            &reopened_registry_chirho,
            &reopened_refreshed_chirho,
            &harness_chirho.feeder_root_chirho,
            &sources_chirho,
            harness_chirho.source_chirho(&path_chirho, &cluster_chirho),
        )
        .unwrap(),
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            lag_ms_chirho: 0,
            ..
        })
    ));
}

#[test]
fn effect_host_exact_cut_requires_seq_digest_and_hlc_chirho() {
    let watermark_chirho = ProjectionWatermarkChirho {
        source_family_id_chirho: "ledger-journal-exact-cut-chirho".to_string(),
        source_seq_chirho: 7,
        source_hlc_chirho: HlcChirho {
            physical_ms_chirho: 101,
            logical_chirho: 2,
        },
        signed_prefix_digest_chirho: DigestChirho("ab".repeat(32)),
    };
    let exact_cut_chirho = VerifiedProjectionReadCutChirho {
        descriptor_ref_chirho: DigestChirho("cd".repeat(32)),
        view_prefix_chirho: watermark_chirho.clone(),
        current_head_chirho: VerifiedProjectionSourceHeadChirho {
            source_family_id_chirho: watermark_chirho.source_family_id_chirho.clone(),
            source_seq_chirho: watermark_chirho.source_seq_chirho,
            source_hlc_chirho: watermark_chirho.source_hlc_chirho.clone(),
            signed_prefix_digest_chirho: watermark_chirho.signed_prefix_digest_chirho.clone(),
        },
    };
    assert!(effect_host_cut_is_exact_chirho(&exact_cut_chirho));

    let mut seq_mismatch_chirho = exact_cut_chirho.clone();
    seq_mismatch_chirho.current_head_chirho.source_seq_chirho += 1;
    assert!(!effect_host_cut_is_exact_chirho(&seq_mismatch_chirho));

    let mut digest_mismatch_chirho = exact_cut_chirho.clone();
    digest_mismatch_chirho
        .current_head_chirho
        .signed_prefix_digest_chirho = DigestChirho("ef".repeat(32));
    assert!(!effect_host_cut_is_exact_chirho(&digest_mismatch_chirho));

    let mut hlc_mismatch_chirho = exact_cut_chirho;
    hlc_mismatch_chirho
        .current_head_chirho
        .source_hlc_chirho
        .logical_chirho += 1;
    assert!(!effect_host_cut_is_exact_chirho(&hlc_mismatch_chirho));
}

#[test]
fn staleness_policy_decides_refuse_or_degrade_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (refuse_descriptor_chirho, refuse_sources_chirho) = descriptor_with_chirho(
        "balances-refuse-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5,
    );
    let (degrade_descriptor_chirho, degrade_sources_chirho) = descriptor_with_chirho(
        "balances-degrade-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::ServeDegradedWithLagChirho,
        5,
    );
    let refuse_digest_chirho =
        projection_descriptor_digest_chirho(&refuse_descriptor_chirho).unwrap();
    let degrade_digest_chirho =
        projection_descriptor_digest_chirho(&degrade_descriptor_chirho).unwrap();
    harness_chirho.register_chirho(refuse_descriptor_chirho);
    harness_chirho.register_chirho(degrade_descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let feed_chirho = |name_chirho: &str, digest_chirho: &DigestChirho| {
        feed_projection_once_chirho(
            &registry_chirho,
            name_chirho,
            digest_chirho,
            &BalancesFoldChirho,
            harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
            &harness_chirho.feeder_root_chirho,
        )
        .unwrap()
    };
    let refuse_feed_chirho = feed_chirho("balances-refuse-chirho", &refuse_digest_chirho);
    let degrade_feed_chirho = feed_chirho("balances-degrade-chirho", &degrade_digest_chirho);
    // The journal moves on: the materializations are now behind by more than the 5ms contract.
    harness_chirho.append_more_chirho(&path_local_chirho, "idem-serve-3");
    harness_chirho.append_more_chirho(&path_local_chirho, "idem-serve-4");
    let serve_chirho = |materialized_chirho: &MaterializedProjectionChirho,
                        sources_chirho: &[VerifiedProjectionSourceChirho]| {
        serve_follower_read_chirho(
            &registry_chirho,
            materialized_chirho,
            &harness_chirho.feeder_root_chirho,
            sources_chirho,
            harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        )
        .unwrap()
    };
    match serve_chirho(&refuse_feed_chirho, &refuse_sources_chirho) {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho,
                max_lag_ms_chirho,
            },
        )) => {
            assert!(
                lag_ms_chirho > 5,
                "lag {lag_ms_chirho} must exceed contract"
            );
            assert_eq!(max_lag_ms_chirho, 5);
        }
        other_chirho => panic!("refuse-when-stale must refuse, got {other_chirho:?}"),
    }
    match serve_chirho(&degrade_feed_chirho, &degrade_sources_chirho) {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::DegradedChirho {
            lag_ms_chirho,
            max_lag_ms_chirho,
            ..
        }) => {
            // The SAME staleness serves — but LABELED, with the lag and the exceeded contract on
            // the read (the no-silent-downgrade law's positive half).
            assert!(lag_ms_chirho > 5);
            assert_eq!(max_lag_ms_chirho, 5);
        }
        other_chirho => panic!("serve-degraded must label, got {other_chirho:?}"),
    }
}

#[test]
fn forged_or_foreign_receipt_gate_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // Tampered cut: the signature no longer covers the receipt.
    let mut tampered_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    tampered_chirho.receipt_chirho.source_tail_seq_chirho += 1;
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &tampered_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ReceiptSignatureChirho
        )
    );
    // Foreign root: a journal signature is never feeder evidence (per-authority keys).
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.journal_signer_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ReceiptSignatureChirho
        )
    );
}

#[test]
fn tampered_view_bytes_gate_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let mut materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // A flipped balance byte must never serve under the original receipt.
    materialized_chirho.view_bytes_chirho[2] ^= 1;
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ViewBytesDigestMismatchChirho
        )
    );
}

#[test]
fn superseded_retired_and_unknown_gate_refuse_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_v1_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_v1_chirho = projection_descriptor_digest_chirho(&descriptor_v1_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_v1_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_v1_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_v1_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // UNKNOWN: a validly re-signed receipt naming a projection the registry never saw.
    let mut unknown_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: materialized_v1_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_v1_chirho.receipt_chirho.clone(),
    };
    unknown_chirho.receipt_chirho.projection_name_chirho = "no-such-projection-chirho".to_string();
    harness_chirho.resign_chirho(&mut unknown_chirho.receipt_chirho);
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &unknown_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionUnknownChirho
        )
    );
    // SUPERSEDED: amend to v2 — the v1 receipt's revision no longer serves.
    let (mut descriptor_v2_chirho, _) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        1_000,
    );
    descriptor_v2_chirho
        .staleness_contract_chirho
        .max_owner_hlc_lag_ms_chirho = 1_000;
    let digest_v2_chirho = projection_descriptor_digest_chirho(&descriptor_v2_chirho).unwrap();
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_v1_chirho.clone(),
            descriptor_chirho: descriptor_v2_chirho,
        },
    )
    .unwrap();
    let registry_chirho = harness_chirho.registry_chirho();
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_v1_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionSupersededChirho
        )
    );
    // RETIRED: feed v2 first, retire, then even the CURRENT-until-retirement receipt refuses.
    let materialized_v2_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_v2_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RetireProjectionChirho {
            name_chirho: "balances-chirho".to_string(),
        },
    )
    .unwrap();
    let registry_chirho = harness_chirho.registry_chirho();
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_v2_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionRetiredChirho
        )
    );
}

#[test]
fn rebuilt_journal_instance_gate_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_a_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_a_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // A destroy-and-recreate of the same cluster is a DIFFERENT instance: its genesis carries a
    // later HLC, so the genesis digest differs and the old receipt must not serve over it.
    let path_b_chirho =
        StoragePathChirho("journals/serve-cluster-rebuilt-chirho.jsonl".to_string());
    harness_chirho.seed_journal_chirho(&path_b_chirho);
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_b_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::SourceInstanceMismatchChirho
        )
    );
}

#[test]
fn receipt_ahead_of_live_prefix_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // A validly signed receipt claiming a cut BEYOND the live verified prefix (a rolled-back or
    // truncated source, or feeder evidence from a future no one can verify) must refuse.
    let mut ahead_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    ahead_chirho.receipt_chirho.source_tail_seq_chirho += 1;
    ahead_chirho.receipt_chirho.source_tail_hlc_chirho = HlcChirho {
        physical_ms_chirho: ahead_chirho
            .receipt_chirho
            .source_tail_hlc_chirho
            .physical_ms_chirho
            + 100,
        logical_chirho: 0,
    };
    ahead_chirho.receipt_chirho.source_tail_line_digest_chirho = DigestChirho("ab".repeat(32));
    harness_chirho.resign_chirho(&mut ahead_chirho.receipt_chirho);
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &ahead_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::WatermarkBeyondVerifiedPrefixChirho
        ))
    );
}

#[test]
fn equal_seq_fork_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // THE FORK NET: same seq, same HLC, same genesis — but the receipt's tail-line digest names a
    // DIFFERENT history. Without the line-digest binding this receipt would read as fresh; with
    // it, the equal-seq head-mismatch net refuses the impersonation.
    let mut forked_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    forked_chirho.receipt_chirho.source_tail_line_digest_chirho = DigestChirho("ab".repeat(32));
    harness_chirho.resign_chirho(&mut forked_chirho.receipt_chirho);
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &forked_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho
        ))
    );
}

#[test]
fn descriptor_family_mismatch_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    // The descriptor binds a family id that is NOT this journal's canonical family: the feed does
    // not consult families, but the SERVE classifier must refuse the family mismatch.
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-badfam-chirho",
        "some-other-family-chirho",
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-badfam-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::SourceFamilyMismatchChirho
        ))
    );
}

#[test]
fn descriptor_evidence_gate_refuses_on_source_mismatch_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, _) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // The caller's verified-source evidence names a different privacy evidence ref than the
    // descriptor's derived binding: the descriptor evidence gate must refuse, typed.
    let wrong_sources_chirho = vec![VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: journal_family_chirho(),
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        },
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: DigestChirho("dd".repeat(32)),
    }];
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &wrong_sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    match outcome_chirho {
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::DescriptorEvidenceChirho { reason_chirho },
        ) => {
            assert!(reason_chirho.contains("evidence"));
        }
        other_chirho => panic!("expected a descriptor-evidence refusal, got {other_chirho:?}"),
    }
}

/// The lossy-shadow RED (claude's #5041 should-fix): two view byte-strings whose LOSSY UTF-8
/// conversions are IDENTICAL (0xFF and 0xFE both become U+FFFD) must NOT share a receipt — the
/// binding hashes RAW bytes, so wearing receipt A over shadow-twin bytes B refuses.
#[test]
fn lossy_utf8_shadow_view_bytes_refuse_chirho() {
    struct RawBytesFoldChirho {
        bytes_chirho: Vec<u8>,
    }
    impl crate::feeder_chirho::ProjectionFoldPortChirho for RawBytesFoldChirho {
        fn fold_chirho(
            &self,
            _source_chirho: &crate::feeder_chirho::VerifiedSourceStateChirho<'_>,
        ) -> anyhow::Result<Vec<u8>> {
            Ok(self.bytes_chirho.clone())
        }
    }
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    harness_chirho.seed_journal_chirho(&path_local_chirho);
    let (descriptor_chirho, sources_chirho) = descriptor_with_chirho(
        "balances-chirho",
        &journal_family_chirho(),
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let original_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &RawBytesFoldChirho {
            bytes_chirho: vec![b'v', 0xFF],
        },
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let shadow_bytes_chirho = vec![b'v', 0xFE];
    assert_eq!(
        String::from_utf8_lossy(&original_chirho.view_bytes_chirho),
        String::from_utf8_lossy(&shadow_bytes_chirho),
        "the twin must be a true lossy shadow for this RED to bite"
    );
    let worn_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: shadow_bytes_chirho,
        receipt_chirho: original_chirho.receipt_chirho.clone(),
    };
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &worn_chirho,
        &harness_chirho.feeder_root_chirho,
        &sources_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ViewBytesDigestMismatchChirho
        )
    );
}
