// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionReadPolicyChirho, ProjectionRebuildLawChirho,
    ProjectionSourceBindingChirho, StalenessContractChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
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
use cairn_ledger_log_chirho::ports_chirho::{LedgerStoragePortChirho, StoragePathChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "merge-feeder-test-registry-chirho";

/// The record-stream fold used by every test: one line per merged event, canonical coordinates.
struct EventListFoldChirho;

impl MergeFoldPortChirho for EventListFoldChirho {
    fn fold_chirho(&self, merged_chirho: &CanonicalProjectionMergeChirho) -> Result<Vec<u8>> {
        let lines_chirho: Vec<String> = merged_chirho
            .ordered_events_chirho
            .iter()
            .map(|event_chirho| {
                format!(
                    "{}:{}:{}.{}",
                    event_chirho.source_family_id_chirho,
                    event_chirho.source_seq_chirho,
                    event_chirho.source_hlc_chirho.physical_ms_chirho,
                    event_chirho.source_hlc_chirho.logical_chirho
                )
            })
            .collect();
        Ok(lines_chirho.join("\n").into_bytes())
    }
}

/// A nondeterministic merge-fold twin — the merge canary's prey.
struct FlipMergeFoldChirho {
    calls_chirho: Cell<u64>,
}

impl MergeFoldPortChirho for FlipMergeFoldChirho {
    fn fold_chirho(&self, merged_chirho: &CanonicalProjectionMergeChirho) -> Result<Vec<u8>> {
        self.calls_chirho.set(self.calls_chirho.get() + 1);
        let mut bytes_chirho = EventListFoldChirho.fold_chirho(merged_chirho)?;
        if self.calls_chirho.get() > 1 {
            bytes_chirho.push(b'!');
        }
        Ok(bytes_chirho)
    }
}

/// A TOCTOU storage wrapper: serves honest bytes until `tamper_after_reads` read_all calls have
/// happened for the marked path, then serves a mutated copy — the re-read-binding net's prey.
struct ToctouStorageChirho<'inner_chirho> {
    inner_chirho: &'inner_chirho MemStorageChirho,
    marked_path_chirho: String,
    reads_seen_chirho: Cell<u64>,
    tamper_after_reads_chirho: u64,
}

impl LedgerStoragePortChirho for ToctouStorageChirho<'_> {
    fn create_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<cairn_ledger_log_chirho::ports_chirho::CreateDurableOutcomeChirho> {
        self.inner_chirho
            .create_durable_chirho(path_chirho, bytes_chirho)
    }

    fn append_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .append_durable_chirho(path_chirho, bytes_chirho)
    }

    fn read_all_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<Vec<u8>>> {
        let bytes_chirho = self.inner_chirho.read_all_chirho(path_chirho)?;
        if path_chirho.0 != self.marked_path_chirho {
            return Ok(bytes_chirho);
        }
        self.reads_seen_chirho.set(self.reads_seen_chirho.get() + 1);
        if self.reads_seen_chirho.get() <= self.tamper_after_reads_chirho {
            return Ok(bytes_chirho);
        }
        Ok(bytes_chirho.map(|mut mutated_chirho| {
            // Flip one byte INSIDE the first record line's amount region: parse still succeeds
            // for a lines-split, but the stored-line digest walk must now diverge.
            let target_chirho = mutated_chirho
                .iter()
                .position(|byte_chirho| *byte_chirho == b'7')
                .unwrap_or(10);
            mutated_chirho[target_chirho] = b'8';
            mutated_chirho
        }))
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<u64>> {
        self.inner_chirho.object_len_chirho(path_chirho)
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.inner_chirho
            .read_exact_range_chirho(path_chirho, offset_chirho, len_chirho)
    }

    fn atomic_write_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        bytes_chirho: &[u8],
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .atomic_write_chirho(path_chirho, bytes_chirho)
    }

    fn truncate_durable_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        len_chirho: u64,
    ) -> anyhow::Result<()> {
        self.inner_chirho
            .truncate_durable_chirho(path_chirho, len_chirho)
    }

    fn rename_chirho(
        &self,
        from_chirho: &StoragePathChirho,
        to_chirho: &StoragePathChirho,
    ) -> anyhow::Result<()> {
        self.inner_chirho.rename_chirho(from_chirho, to_chirho)
    }

    fn remove_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<()> {
        self.inner_chirho.remove_chirho(path_chirho)
    }

    fn list_chirho(
        &self,
        prefix_chirho: &StoragePathChirho,
    ) -> anyhow::Result<Vec<StoragePathChirho>> {
        self.inner_chirho.list_chirho(prefix_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<bool> {
        self.inner_chirho.exists_chirho(path_chirho)
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

    fn ports_with_chirho<'harness_chirho>(
        &'harness_chirho self,
        storage_chirho: &'harness_chirho dyn LedgerStoragePortChirho,
    ) -> JournalPortsChirho<'harness_chirho> {
        JournalPortsChirho {
            storage_chirho,
            signer_chirho: &self.journal_signer_chirho,
            clock_chirho: &self.clock_chirho,
            membership_chirho: &self.membership_chirho,
            kind_registry_chirho: &self.kind_registry_chirho,
            authority_chirho: &self.authority_chirho,
        }
    }

    fn source_with_chirho<'harness_chirho>(
        &'harness_chirho self,
        storage_chirho: &'harness_chirho dyn LedgerStoragePortChirho,
        path_chirho: &'harness_chirho StoragePathChirho,
        cluster_chirho: &'harness_chirho ClusterIdChirho,
    ) -> ProjectionSourceChirho<'harness_chirho> {
        ProjectionSourceChirho {
            journal_ports_chirho: self.ports_with_chirho(storage_chirho),
            journal_path_chirho: path_chirho,
            cluster_chirho,
        }
    }

    /// Create a journal for `cluster` at `path` with `count` mints (clock interleaves naturally).
    fn seed_journal_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        cluster_chirho: &ClusterIdChirho,
        count_chirho: u32,
        idem_prefix_chirho: &str,
    ) {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.ports_with_chirho(&self.storage_chirho),
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

    fn register_chirho(&self, descriptor_chirho: crate::ProjectionDescriptorChirho) {
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
}

fn cluster_a_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-merge-a-chirho".to_string())
}

fn cluster_b_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-merge-b-chirho".to_string())
}

fn path_a_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/merge-a-chirho.jsonl".to_string())
}

fn path_b_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/merge-b-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/merge-feeder-registry-chirho.jsonl".to_string())
}

/// A two-source record-stream descriptor over clusters A and B (bindings in strict byte order),
/// plus its exact verified-source evidence.
fn merge_descriptor_chirho() -> (
    crate::ProjectionDescriptorChirho,
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
    let descriptor_chirho = crate::ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "activity-stream-chirho".to_string(),
        source_families_chirho: sources_chirho
            .iter()
            .map(|source_chirho| source_chirho.binding_chirho.clone())
            .collect(),
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
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
fn merge_feed_orders_across_sources_and_receipt_binds_the_vector_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    // Interleave: A gets 2 records, then B gets 2 records, then A gets 1 more — the shared step
    // clock makes HLCs globally distinct, so the oracle's HLC-major order interleaves families.
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 2, "idem-ma");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 2, "idem-mb");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_a_local_chirho,
            &cluster_a_local_chirho,
        ),
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_b_local_chirho,
            &cluster_b_local_chirho,
        ),
    ];
    let fold_chirho = EventListFoldChirho;
    let materialized_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &digest_chirho,
        &fold_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let view_chirho = String::from_utf8(materialized_chirho.view_bytes_chirho.clone()).unwrap();
    let lines_chirho: Vec<&str> = view_chirho.lines().collect();
    // The safe frontier is min(head A, head B) = head A's HLC (A seeded first), so exactly A's 2
    // events and any B events at-or-before it appear; A's records predate all of B's, so the
    // frontier admits exactly A's two events.
    assert_eq!(lines_chirho.len(), 2);
    assert!(lines_chirho[0].starts_with(&format!(
        "{}:1:",
        journal_source_family_id_chirho(&cluster_a_chirho())
    )));
    assert!(lines_chirho[1].starts_with(&format!(
        "{}:2:",
        journal_source_family_id_chirho(&cluster_a_chirho())
    )));
    // The receipt binds BOTH source cuts (instance identity + head coordinates) + the frontier.
    let receipt_chirho = &materialized_chirho.receipt_chirho;
    assert_eq!(receipt_chirho.source_cuts_chirho.len(), 2);
    assert_eq!(receipt_chirho.source_cuts_chirho[0].head_seq_chirho, 2);
    assert_eq!(receipt_chirho.source_cuts_chirho[1].head_seq_chirho, 2);
    assert_eq!(
        receipt_chirho.safe_frontier_hlc_chirho,
        receipt_chirho.source_cuts_chirho[0].head_hlc_chirho
    );
    verify_merge_follow_receipt_chirho(receipt_chirho, &harness_chirho.feeder_root_chirho).unwrap();
    assert!(verify_merge_follow_receipt_chirho(
        receipt_chirho,
        &harness_chirho.journal_signer_chirho
    )
    .is_err());
    // The merge canary passes for the honest fold at the same vector.
    merge_equivalence_canary_chirho(
        &registry_chirho,
        &materialized_chirho,
        &fold_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
}

#[test]
fn merge_canary_fires_on_divergent_fold_and_bails_on_moved_vector_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-ca");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-cb");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_a_local_chirho,
            &cluster_a_local_chirho,
        ),
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_b_local_chirho,
            &cluster_b_local_chirho,
        ),
    ];
    let flip_chirho = FlipMergeFoldChirho {
        calls_chirho: Cell::new(0),
    };
    let materialized_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &digest_chirho,
        &flip_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let error_chirho = merge_equivalence_canary_chirho(
        &registry_chirho,
        &materialized_chirho,
        &flip_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("MERGE EQUIVALENCE CANARY FIRED"));
    // A moved source vector is an honest re-feed signal, never a lie verdict.
    let mut journal_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.ports_with_chirho(&harness_chirho.storage_chirho),
        path_b_chirho(),
        &cluster_b_chirho(),
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("bob-chirho", 5, "idem-cb-move"))
        .unwrap();
    drop(journal_chirho);
    let honest_fold_chirho = EventListFoldChirho;
    let error_chirho = merge_equivalence_canary_chirho(
        &registry_chirho,
        &materialized_chirho,
        &honest_fold_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("source vector moved"));
}

#[test]
fn toctou_reread_divergence_fails_closed_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 2, "idem-ta");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-tb");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    // The verified open reads the journal object once (read #1); the extraction re-read is #2.
    // Serving honest bytes to the open and MUTATED bytes to the re-read is exactly the TOCTOU the
    // binding law must refuse: the deep laws passed, but the event bytes are no longer the proven
    // chain.
    let toctou_chirho = ToctouStorageChirho {
        inner_chirho: &harness_chirho.storage_chirho,
        marked_path_chirho: path_a_chirho().0,
        reads_seen_chirho: Cell::new(0),
        tamper_after_reads_chirho: 1,
    };
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_with_chirho(
            &toctou_chirho,
            &path_a_local_chirho,
            &cluster_a_local_chirho,
        ),
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_b_local_chirho,
            &cluster_b_local_chirho,
        ),
    ];
    let error_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    let detail_chirho = error_chirho.to_string();
    assert!(
        detail_chirho.contains("re-read") || detail_chirho.contains("bind"),
        "TOCTOU divergence must fail the binding law, got: {detail_chirho}"
    );
}

#[test]
fn merge_feed_refuses_swapped_source_order_and_non_current_registry_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    harness_chirho.seed_journal_chirho(&path_a_chirho(), &cluster_a_chirho(), 1, "idem-sa");
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-sb");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    // Swapped order: descriptor binds [A, B] but the caller supplies [B, A].
    let swapped_chirho = [
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_b_local_chirho,
            &cluster_b_local_chirho,
        ),
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_a_local_chirho,
            &cluster_a_local_chirho,
        ),
    ];
    let error_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &digest_chirho,
        &EventListFoldChirho,
        &evidence_chirho,
        &swapped_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("descriptor binds"));
    // Unknown digest refuses through the registry gate.
    let error_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &DigestChirho("ff".repeat(32)),
        &EventListFoldChirho,
        &evidence_chirho,
        &[
            harness_chirho.source_with_chirho(
                &harness_chirho.storage_chirho,
                &path_a_local_chirho,
                &cluster_a_local_chirho,
            ),
            harness_chirho.source_with_chirho(
                &harness_chirho.storage_chirho,
                &path_b_local_chirho,
                &cluster_b_local_chirho,
            ),
        ],
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("UNKNOWN"));
}

/// The rotated-source positive (closing the CF4 boundary's named gap): a source that ROTATED
/// mid-history extracts through the read-only recomposed stream, the binding walk verifies the
/// seam by the same digest law, and the merged view carries events from BOTH sides of the seal.
#[test]
fn rotated_source_extracts_across_the_seam_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    // Journal A: 2 records, ROTATE (seal -> manifest -> fresh active), then 1 more record — the
    // event stream spans the sealed segment AND the post-rotation active.
    {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            harness_chirho.ports_with_chirho(&harness_chirho.storage_chirho),
            path_a_chirho(),
            cluster_a_chirho(),
            1,
        )
        .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-ra-0"))
            .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("alice-chirho", 701, "idem-ra-1"))
            .unwrap();
        journal_chirho.rotate_chirho().unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("alice-chirho", 702, "idem-ra-2"))
            .unwrap();
    }
    harness_chirho.seed_journal_chirho(&path_b_chirho(), &cluster_b_chirho(), 1, "idem-rb");
    let (descriptor_chirho, evidence_chirho) = merge_descriptor_chirho();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    harness_chirho.register_chirho(descriptor_chirho);
    let registry_chirho = harness_chirho.registry_chirho();
    let path_a_local_chirho = path_a_chirho();
    let path_b_local_chirho = path_b_chirho();
    let cluster_a_local_chirho = cluster_a_chirho();
    let cluster_b_local_chirho = cluster_b_chirho();
    let sources_chirho = [
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_a_local_chirho,
            &cluster_a_local_chirho,
        ),
        harness_chirho.source_with_chirho(
            &harness_chirho.storage_chirho,
            &path_b_local_chirho,
            &cluster_b_local_chirho,
        ),
    ];
    let fold_chirho = EventListFoldChirho;
    let materialized_chirho = feed_merge_projection_once_chirho(
        &registry_chirho,
        "activity-stream-chirho",
        &digest_chirho,
        &fold_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // A rotated first (its 3 records all predate B's single record), so the frontier = A's head
    // and exactly A's three events — INCLUDING the two sealed ones — appear in order.
    let view_chirho = String::from_utf8(materialized_chirho.view_bytes_chirho.clone()).unwrap();
    let family_a_chirho = journal_source_family_id_chirho(&cluster_a_chirho());
    let lines_chirho: Vec<&str> = view_chirho.lines().collect();
    assert_eq!(lines_chirho.len(), 3);
    for (index_chirho, line_chirho) in lines_chirho.iter().enumerate() {
        assert!(line_chirho.starts_with(&format!("{}:{}:", family_a_chirho, index_chirho + 1)));
    }
    // The receipt's A-cut binds the post-rotation verified head; the canary re-extracts across
    // the seam and agrees byte-for-byte.
    assert_eq!(
        materialized_chirho.receipt_chirho.source_cuts_chirho[0].head_seq_chirho,
        3
    );
    merge_equivalence_canary_chirho(
        &registry_chirho,
        &materialized_chirho,
        &fold_chirho,
        &evidence_chirho,
        &sources_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
}
