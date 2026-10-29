// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::follower_chirho::FollowerReadRefusalChirho;
use crate::merge_chirho::CanonicalProjectionMergeChirho;
use crate::merge_feeder_chirho::{
    feed_merge_projection_once_chirho, merge_receipt_signed_content_chirho, MergeFoldPortChirho,
    MergeFollowReceiptChirho,
};
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, MemStorageChirho, OpenAuthorityChirho,
    OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "merge-serving-test-registry-chirho";

struct EventListFoldChirho;

impl MergeFoldPortChirho for EventListFoldChirho {
    fn fold_chirho(&self, merged_chirho: &CanonicalProjectionMergeChirho) -> Result<Vec<u8>> {
        let lines_chirho: Vec<String> = merged_chirho
            .ordered_events_chirho
            .iter()
            .map(|event_chirho| {
                format!(
                    "{}:{}",
                    event_chirho.source_family_id_chirho, event_chirho.source_seq_chirho
                )
            })
            .collect();
        Ok(lines_chirho.join("\n").into_bytes())
    }
}

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
                name_chirho: "merge-feeder-root-chirho",
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

    fn ports_chirho(&self) -> JournalPortsChirho<'_> {
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
            journal_ports_chirho: self.ports_chirho(),
            journal_path_chirho: path_chirho,
            cluster_chirho,
        }
    }

    fn seed_journal_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        cluster_chirho: &ClusterIdChirho,
        count_chirho: u32,
        idem_prefix_chirho: &str,
    ) {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_chirho(),
            path_chirho.clone(),
            cluster_chirho.clone(),
            1,
        )
        .unwrap();
        for index_chirho in 0..count_chirho {
            journal_chirho
                .append_chirho(mint_request_chirho(
                    "alice-chirho",
                    700 + u64::from(index_chirho),
                    &format!("{idem_prefix_chirho}-{index_chirho}"),
                ))
                .unwrap();
        }
    }

    fn append_more_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        cluster_chirho: &ClusterIdChirho,
        idem_chirho: &str,
    ) {
        let mut journal_chirho = LedgerJournalChirho::open_chirho(
            self.ports_chirho(),
            path_chirho.clone(),
            cluster_chirho,
        )
        .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("bob-chirho", 5, idem_chirho))
            .unwrap();
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

    fn resign_chirho(&self, receipt_chirho: &mut MergeFollowReceiptChirho) {
        receipt_chirho.feeder_sig_chirho = String::new();
        let content_chirho = merge_receipt_signed_content_chirho(receipt_chirho).unwrap();
        receipt_chirho.feeder_sig_chirho = self
            .feeder_root_chirho
            .sign_chirho(&content_chirho)
            .unwrap();
    }
}

fn cluster_a_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-mserve-a-chirho".to_string())
}

fn cluster_b_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-mserve-b-chirho".to_string())
}

fn path_a_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/mserve-a-chirho.jsonl".to_string())
}

fn path_b_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/mserve-b-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/merge-serving-registry-chirho.jsonl".to_string())
}

fn merge_descriptor_chirho(
    name_chirho: &str,
    read_policy_chirho: ProjectionReadPolicyChirho,
    max_lag_ms_chirho: u64,
) -> (
    ProjectionDescriptorChirho,
    Vec<VerifiedProjectionSourceChirho>,
) {
    let mut families_chirho = [
        journal_source_family_id_chirho(&cluster_a_chirho()),
        journal_source_family_id_chirho(&cluster_b_chirho()),
    ];
    families_chirho.sort();
    let sources_chirho: Vec<VerifiedProjectionSourceChirho> = families_chirho
        .iter()
        .map(|family_chirho| VerifiedProjectionSourceChirho {
            binding_chirho: ProjectionSourceBindingChirho {
                family_id_chirho: family_chirho.clone(),
                source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
            },
            privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
            privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
        })
        .collect();
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: name_chirho.to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
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

/// Seed both journals, register the named projection, feed it, and return everything a serve
/// needs. Ordering note: descriptor bindings are the sorted families [A, B].
fn seeded_feed_chirho(
    harness_chirho: &HarnessChirho,
    name_chirho: &str,
    read_policy_chirho: ProjectionReadPolicyChirho,
    max_lag_ms_chirho: u64,
) -> (
    crate::registry_chirho::VerifiedProjectionRegistryChirho,
    MaterializedMergeProjectionChirho,
    Vec<VerifiedProjectionSourceChirho>,
    DigestChirho,
) {
    let (descriptor_chirho, evidence_chirho) =
        merge_descriptor_chirho(name_chirho, read_policy_chirho, max_lag_ms_chirho);
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_chirho(&path_a_local_chirho, &cluster_a_local_chirho),
        harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
    ];
    let materialized_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        name_chirho,
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    (
        registry_chirho,
        materialized_chirho,
        evidence_chirho,
        digest_chirho,
    )
}

fn serve_now_chirho(
    harness_chirho: &HarnessChirho,
    registry_chirho: &crate::registry_chirho::VerifiedProjectionRegistryChirho,
    materialized_chirho: &MaterializedMergeProjectionChirho,
    evidence_chirho: &[VerifiedProjectionSourceChirho],
) -> FollowerServeOutcomeChirho {
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    serve_merge_follower_read_chirho(
        registry_chirho,
        materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        evidence_chirho,
        &[
            harness_chirho.source_chirho(&path_a_local_chirho, &cluster_a_local_chirho),
            harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
        ],
    )
    .unwrap()
}

#[test]
fn fresh_merge_read_serves_and_policy_split_on_stale_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 2, "idem-msa");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 2, "idem-msb");
    let (registry_chirho, refuse_feed_chirho, refuse_evidence_chirho, _) = seeded_feed_chirho(
        &harness_chirho,
        "stream-refuse-chirho",
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5,
    );
    // Unmoved sources: every per-source lag is zero — the composite is Fresh at lag 0.
    match serve_now_chirho(
        &harness_chirho,
        &registry_chirho,
        &refuse_feed_chirho,
        &refuse_evidence_chirho,
    ) {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho {
            lag_ms_chirho,
            ..
        }) => assert_eq!(lag_ms_chirho, 0),
        other_chirho => panic!("expected fresh, got {other_chirho:?}"),
    }
    // Register the degrade twin BEFORE the sources move, feeding at the same cut.
    let (registry_chirho, degrade_feed_chirho, degrade_evidence_chirho, _) = seeded_feed_chirho(
        &harness_chirho,
        "stream-degrade-chirho",
        ProjectionReadPolicyChirho::ServeDegradedWithLagChirho,
        5,
    );
    // ONE source (B) moves beyond the 5ms contract; A stays at the cut. The composite read is as
    // stale as its stalest source: refuse-policy refuses, degrade-policy serves LABELED.
    harness_chirho.append_more_chirho(&path_b_chirho(), &cluster_b_chirho(), "idem-msb-move");
    harness_chirho.append_more_chirho(&path_b_chirho(), &cluster_b_chirho(), "idem-msb-move2");
    match serve_now_chirho(
        &harness_chirho,
        &registry_chirho,
        &refuse_feed_chirho,
        &refuse_evidence_chirho,
    ) {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::StaleBeyondContractChirho {
                lag_ms_chirho,
                max_lag_ms_chirho,
            },
        )) => {
            assert!(lag_ms_chirho > 5);
            assert_eq!(max_lag_ms_chirho, 5);
        }
        other_chirho => panic!("refuse-when-stale must refuse, got {other_chirho:?}"),
    }
    match serve_now_chirho(
        &harness_chirho,
        &registry_chirho,
        &degrade_feed_chirho,
        &degrade_evidence_chirho,
    ) {
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::DegradedChirho {
            lag_ms_chirho,
            max_lag_ms_chirho,
            ..
        }) => {
            assert!(lag_ms_chirho > 5);
            assert_eq!(max_lag_ms_chirho, 5);
        }
        other_chirho => panic!("serve-degraded must label, got {other_chirho:?}"),
    }
}

#[test]
fn merge_serve_gate_refusals_are_typed_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-mga");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-mgb");
    let (registry_chirho, materialized_chirho, evidence_chirho, digest_chirho) = seeded_feed_chirho(
        &harness_chirho,
        "stream-gates-chirho",
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    // Forged: tampered frontier without re-signing fails the signature gate.
    let mut forged_chirho = MaterializedMergeProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    forged_chirho
        .receipt_chirho
        .safe_frontier_hlc_chirho
        .physical_ms_chirho += 1;
    assert_eq!(
        serve_now_chirho(
            &harness_chirho,
            &registry_chirho,
            &forged_chirho,
            &evidence_chirho
        ),
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ReceiptSignatureChirho
        )
    );
    // Frontier lie: RE-SIGNED asserted frontier that its own cuts contradict.
    harness_chirho.resign_chirho(&mut forged_chirho.receipt_chirho);
    assert_eq!(
        serve_now_chirho(
            &harness_chirho,
            &registry_chirho,
            &forged_chirho,
            &evidence_chirho
        ),
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::SafeFrontierMismatchChirho
        )
    );
    // Tampered view bytes refuse the binding.
    let mut tampered_chirho = MaterializedMergeProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    tampered_chirho.view_bytes_chirho[0] ^= 1;
    assert_eq!(
        serve_now_chirho(
            &harness_chirho,
            &registry_chirho,
            &tampered_chirho,
            &evidence_chirho
        ),
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ViewBytesDigestMismatchChirho
        )
    );
    // Equal-seq fork on source A: crafted cut line digest, validly re-signed → classifier net.
    let mut forked_chirho = MaterializedMergeProjectionChirho {
        view_bytes_chirho: materialized_chirho.view_bytes_chirho.clone(),
        receipt_chirho: materialized_chirho.receipt_chirho.clone(),
    };
    forked_chirho.receipt_chirho.source_cuts_chirho[0].head_line_digest_chirho =
        DigestChirho("ab".repeat(32));
    harness_chirho.resign_chirho(&mut forked_chirho.receipt_chirho);
    assert_eq!(
        serve_now_chirho(
            &harness_chirho,
            &registry_chirho,
            &forked_chirho,
            &evidence_chirho
        ),
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::RefusedChirho(
            FollowerReadRefusalChirho::EqualSeqHeadMismatchChirho
        ))
    );
    // Superseded: amend the projection — the old receipt's revision no longer serves.
    let (descriptor_v2_chirho, _) = merge_descriptor_chirho(
        "stream-gates-chirho",
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        1_000,
    );
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::AmendProjectionChirho {
            supersedes_digest_chirho: digest_chirho,
            descriptor_chirho: descriptor_v2_chirho,
        },
    )
    .unwrap();
    let registry_chirho = harness_chirho.registry_chirho();
    assert_eq!(
        serve_now_chirho(
            &harness_chirho,
            &registry_chirho,
            &materialized_chirho,
            &evidence_chirho
        ),
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::ProjectionSupersededChirho
        )
    );
}

#[test]
fn rebuilt_merge_source_instance_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-mra");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-mrb");
    let (registry_chirho, materialized_chirho, evidence_chirho, _) = seeded_feed_chirho(
        &harness_chirho,
        "stream-rebuild-chirho",
        ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        5_000,
    );
    // Rebuild B at a different path: same cluster, LATER genesis HLC — a different instance.
    let rebuilt_path_chirho =
        StoragePathChirho("journals/mserve-b-rebuilt-chirho.jsonl".to_string());
    harness_chirho.seed_journal_chirho(&rebuilt_path_chirho, &cluster_b_chirho(), 1, "idem-mrb2");
    let path_a_local_chirho = path_a_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let outcome_chirho = serve_merge_follower_read_chirho(
        &registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &evidence_chirho,
        &[
            harness_chirho.source_chirho(&path_a_local_chirho, &cluster_a_local_chirho),
            harness_chirho.source_chirho(&rebuilt_path_chirho, &cluster_b_local_chirho),
        ],
    )
    .unwrap();
    assert_eq!(
        outcome_chirho,
        FollowerServeOutcomeChirho::GateRefusedChirho(
            ServeGateRefusalChirho::SourceInstanceMismatchChirho
        )
    );
}
