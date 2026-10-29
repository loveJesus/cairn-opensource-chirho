// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    VerifiedProjectionSourceChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::follower_chirho::ProjectionReadOutcomeChirho;
use crate::merge_chirho::CanonicalProjectionMergeChirho;
use crate::merge_feeder_chirho::{
    feed_merge_projection_once_chirho, feed_merge_projection_with_heartbeats_chirho,
    merge_equivalence_canary_with_heartbeats_chirho, MergeFoldPortChirho,
};
use crate::merge_serving_chirho::serve_merge_follower_read_chirho;
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::serving_chirho::{journal_source_family_id_chirho, FollowerServeOutcomeChirho};
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, MemStorageChirho, OpenAuthorityChirho,
    OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::JournalPortsChirho;
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "heartbeat-test-registry-chirho";

struct EventListFoldChirho;

impl MergeFoldPortChirho for EventListFoldChirho {
    fn fold_chirho(
        &self,
        merged_chirho: &CanonicalProjectionMergeChirho,
    ) -> anyhow::Result<Vec<u8>> {
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
                name_chirho: "heartbeat-feeder-root-chirho",
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
}

fn cluster_a_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-hb-a-chirho".to_string())
}

fn cluster_b_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-hb-b-chirho".to_string())
}

fn path_a_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/hb-a-chirho.jsonl".to_string())
}

fn path_b_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/hb-b-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/heartbeat-registry-chirho.jsonl".to_string())
}

fn merge_descriptor_chirho() -> (
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
        name_chirho: "hb-stream-chirho".to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 100_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: evidence_chirho,
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    };
    (descriptor_chirho, sources_chirho)
}

#[test]
fn mint_contract_split_and_advance_laws_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-hbm");
    let path_local_chirho = path_b_chirho();
    let cluster_local_chirho = cluster_b_chirho();
    // Undeclared: attested-tail-only — no promise.
    let plain_chirho = mint_source_heartbeat_chirho(
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
        ClockContractChirho::UndeclaredChirho,
    )
    .unwrap();
    assert!(plain_chirho.clock_promise_ms_chirho.is_none());
    verify_source_heartbeat_chirho(&plain_chirho, &harness_chirho.feeder_root_chirho).unwrap();
    assert!(
        verify_source_heartbeat_chirho(&plain_chirho, &harness_chirho.journal_signer_chirho)
            .is_err()
    );
    // Declared-monotone: the promise is the pre-open clock reading, beyond the tail HLC.
    let promised_chirho = mint_source_heartbeat_chirho(
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
        ClockContractChirho::DeclaredMonotoneChirho,
    )
    .unwrap();
    let promise_chirho = promised_chirho.clock_promise_ms_chirho.unwrap();
    assert!(promise_chirho > promised_chirho.observed_hlc_chirho.physical_ms_chirho);
    assert!(effective_head_hlc_chirho(&promised_chirho) > promised_chirho.observed_hlc_chirho);
    assert_eq!(
        effective_head_hlc_chirho(&plain_chirho),
        plain_chirho.observed_hlc_chirho
    );
    // Advance laws: forward passes; regressed promise and withdrawal refuse.
    heartbeat_advances_chirho(&plain_chirho, &promised_chirho).unwrap();
    assert!(heartbeat_advances_chirho(&promised_chirho, &plain_chirho)
        .unwrap_err()
        .to_string()
        .contains("withdrawn"));
    let mut regressed_chirho = promised_chirho.clone();
    regressed_chirho.clock_promise_ms_chirho = Some(promise_chirho - 1);
    assert!(
        heartbeat_advances_chirho(&promised_chirho, &regressed_chirho)
            .unwrap_err()
            .to_string()
            .contains("promise regressed")
    );
}

#[test]
fn idle_source_promise_unlocks_the_frontier_and_serves_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    // B is IDLE (1 early record); A is ACTIVE (its records land AFTER B's tail).
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-hb-b");
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-hb-a");
    harness_chirho.append_more_chirho(&path_a_chirho(), &cluster_a_chirho(), "idem-hb-a2");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho { descriptor_chirho },
    )
    .unwrap();
    let registry_chirho = load_verified_projection_registry_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_chirho(&path_a_local_chirho, &cluster_a_local_chirho),
        harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
    ];
    // WITHOUT a heartbeat: B's early tail pins the frontier — only B's event is admitted (A's
    // records all landed later).
    let plain_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "hb-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let plain_view_chirho = String::from_utf8(plain_chirho.view_bytes_chirho.clone()).unwrap();
    assert_eq!(plain_view_chirho.lines().count(), 1, "{plain_view_chirho}");
    // WITH a declared-monotone heartbeat on B minted NOW (after A's records): the promise clears
    // A's HLCs, the frontier advances to A's head, and ALL THREE events serve in canonical order.
    let heartbeat_chirho = mint_source_heartbeat_chirho(
        harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
        &harness_chirho.feeder_root_chirho,
        ClockContractChirho::DeclaredMonotoneChirho,
    )
    .unwrap();
    let heartbeats_chirho = [None, Some(&heartbeat_chirho)];
    let promised_feed_chirho = feed_merge_projection_with_heartbeats_chirho(
        &registry_chirho,
        "hb-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &heartbeats_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let promised_view_chirho =
        String::from_utf8(promised_feed_chirho.view_bytes_chirho.clone()).unwrap();
    assert_eq!(
        promised_view_chirho.lines().count(),
        3,
        "{promised_view_chirho}"
    );
    // The receipt's B-cut carries the promise + heartbeat digest; the frontier equals A's head.
    let b_cut_chirho = &promised_feed_chirho.receipt_chirho.source_cuts_chirho[1];
    assert_eq!(
        b_cut_chirho.clock_promise_ms_chirho,
        heartbeat_chirho.clock_promise_ms_chirho
    );
    assert_eq!(
        b_cut_chirho.heartbeat_digest_hex_chirho.as_deref(),
        Some(
            heartbeat_digest_hex_chirho(&heartbeat_chirho)
                .unwrap()
                .as_str()
        )
    );
    // The with-heartbeats canary agrees byte-for-byte at the same vector.
    merge_equivalence_canary_with_heartbeats_chirho(
        &registry_chirho,
        &promised_feed_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &heartbeats_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // SERVING accepts the promise-advanced frontier (the gate re-derives with promises) and the
    // read is fresh at this cut.
    let outcome_chirho = serve_merge_follower_read_chirho(
        &registry_chirho,
        &promised_feed_chirho,
        &harness_chirho.feeder_root_chirho,
        &evidence_chirho,
        &sources_chirho,
    )
    .unwrap();
    assert!(matches!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
    ));
    // A FOREIGN-signed heartbeat refuses loudly (never a silent tail-only downgrade).
    let mut forged_chirho = heartbeat_chirho.clone();
    forged_chirho.feeder_sig_chirho = "forged-chirho".to_string();
    let error_chirho = feed_merge_projection_with_heartbeats_chirho(
        &registry_chirho,
        "hb-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &[None, Some(&forged_chirho)],
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("signature"));
}

#[test]
fn h5_violation_net_fires_under_a_regressing_clock_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-hbv-b");
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-hbv-a");
    harness_chirho.append_more_chirho(&path_a_chirho(), &cluster_a_chirho(), "idem-hbv-a2");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
        ProjectionRegistryOpChirho::RegisterProjectionChirho { descriptor_chirho },
    )
    .unwrap();
    let registry_chirho = load_verified_projection_registry_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &registry_path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_chirho(&path_a_local_chirho, &cluster_a_local_chirho),
        harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
    ];
    let heartbeat_chirho = mint_source_heartbeat_chirho(
        harness_chirho.source_chirho(&path_b_local_chirho, &cluster_b_local_chirho),
        &harness_chirho.feeder_root_chirho,
        ClockContractChirho::DeclaredMonotoneChirho,
    )
    .unwrap();
    let promised_feed_chirho = feed_merge_projection_with_heartbeats_chirho(
        &registry_chirho,
        "hb-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &[None, Some(&heartbeat_chirho)],
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // A clean check first: no violations while the clock behaves.
    assert!(heartbeat_promise_violation_check_chirho(
        &promised_feed_chirho.receipt_chirho,
        &sources_chirho,
    )
    .unwrap()
    .is_empty());
    // THE BREACH claude's contract reading predicted: REGRESS the clock below the promise. The
    // engine tolerates regression by keeping physical at the tail and bumping logical — so B
    // admits a record whose HLC sits BELOW the promised frontier. The h5 net must name it.
    harness_chirho.clock_chirho.now_ms_chirho.set(500);
    harness_chirho.append_more_chirho(&path_b_chirho(), &cluster_b_chirho(), "idem-hbv-late");
    let violations_chirho = heartbeat_promise_violation_check_chirho(
        &promised_feed_chirho.receipt_chirho,
        &sources_chirho,
    )
    .unwrap();
    assert_eq!(violations_chirho.len(), 1);
    let violation_chirho = &violations_chirho[0];
    assert_eq!(
        violation_chirho.family_id_chirho,
        journal_source_family_id_chirho(&cluster_b_chirho())
    );
    assert_eq!(violation_chirho.record_seq_chirho, 2);
    assert!(
        violation_chirho.record_hlc_chirho
            <= promised_feed_chirho.receipt_chirho.safe_frontier_hlc_chirho
    );
}
