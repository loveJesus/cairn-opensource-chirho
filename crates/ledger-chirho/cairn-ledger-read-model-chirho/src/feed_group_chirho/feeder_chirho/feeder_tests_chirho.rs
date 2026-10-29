// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    projection_descriptor_digest_chirho, ProjectionCostClassChirho, ProjectionDescriptorChirho,
    ProjectionReadPolicyChirho, ProjectionRebuildLawChirho, ProjectionSourceBindingChirho,
    StalenessContractChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, BalancesFoldChirho, MemStorageChirho,
    OpenAuthorityChirho, OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::DigestChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;
use std::collections::BTreeMap;

const REGISTRY_ID_CHIRHO: &str = "feeder-test-registry-chirho";

/// A deliberately NONDETERMINISTIC fold twin — the canary's prey.
struct FlipFoldChirho {
    calls_chirho: Cell<u64>,
}

impl ProjectionFoldPortChirho for FlipFoldChirho {
    fn fold_chirho(&self, source_chirho: &VerifiedSourceStateChirho<'_>) -> Result<Vec<u8>> {
        self.calls_chirho.set(self.calls_chirho.get() + 1);
        let mut bytes_chirho = BalancesFoldChirho.fold_chirho(source_chirho)?;
        if self.calls_chirho.get() > 1 {
            bytes_chirho.push(b'!');
        }
        Ok(bytes_chirho)
    }
}

fn descriptor_chirho() -> ProjectionDescriptorChirho {
    ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "balances-chirho".to_string(),
        source_families_chirho: vec![ProjectionSourceBindingChirho {
            family_id_chirho: "cluster-feeder-chirho".to_string(),
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        }],
        fold_fn_ref_chirho: DigestChirho("bb".repeat(32)),
        staleness_contract_chirho: StalenessContractChirho {
            max_owner_hlc_lag_ms_chirho: 5_000,
            read_policy_chirho: ProjectionReadPolicyChirho::RefuseWhenStaleChirho,
        },
        cost_class_chirho: ProjectionCostClassChirho::StandingWriteRateChirho,
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_floor_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
        rebuild_law_chirho: ProjectionRebuildLawChirho::DropAndRefoldChirho,
    }
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/feeder-cluster-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/feeder-registry-chirho.jsonl".to_string())
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

    fn cluster_chirho(&self) -> ClusterIdChirho {
        ClusterIdChirho("cluster-feeder-chirho".to_string())
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

    /// Create the journal, mint two balances, register the projection; return the digest.
    fn seed_chirho(&self) -> DigestChirho {
        let mut journal_chirho = LedgerJournalChirho::create_chirho(
            self.journal_ports_chirho(),
            journal_path_chirho(),
            self.cluster_chirho(),
            1,
        )
        .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-feed-1"))
            .unwrap();
        journal_chirho
            .append_chirho(mint_request_chirho("bob-chirho", 300, "idem-feed-2"))
            .unwrap();
        drop(journal_chirho);
        append_projection_registry_op_chirho(
            &self.storage_chirho,
            &self.registry_root_chirho,
            &registry_path_chirho(),
            REGISTRY_ID_CHIRHO,
            ProjectionRegistryOpChirho::RegisterProjectionChirho {
                descriptor_chirho: descriptor_chirho(),
            },
        )
        .unwrap();
        projection_descriptor_digest_chirho(&descriptor_chirho()).unwrap()
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

#[test]
fn feed_materializes_view_with_verified_receipt_and_canary_passes_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = harness_chirho.cluster_chirho();
    let digest_chirho = harness_chirho.seed_chirho();
    let registry_chirho = harness_chirho.registry_chirho();
    let fold_chirho = BalancesFoldChirho;
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &fold_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // The view is the deterministic balances snapshot.
    let view_chirho: BTreeMap<String, i128> =
        serde_json::from_slice(&materialized_chirho.view_bytes_chirho).unwrap();
    assert_eq!(view_chirho["alice-chirho:credits-chirho"], 700);
    assert_eq!(view_chirho["bob-chirho:credits-chirho"], 300);
    // The receipt binds the source cut and verifies against the FEEDER root — and NOT against the
    // journal's root (per-authority keys: a journal signature is never feeder evidence).
    assert_eq!(materialized_chirho.receipt_chirho.source_tail_seq_chirho, 2);
    verify_follow_receipt_chirho(
        &materialized_chirho.receipt_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    assert!(verify_follow_receipt_chirho(
        &materialized_chirho.receipt_chirho,
        &harness_chirho.journal_signer_chirho,
    )
    .is_err());
    // A tampered receipt (cut moved one forward) fails the signature.
    let mut tampered_chirho = materialized_chirho.receipt_chirho.clone();
    tampered_chirho.source_tail_seq_chirho = 3;
    assert!(
        verify_follow_receipt_chirho(&tampered_chirho, &harness_chirho.feeder_root_chirho).is_err()
    );
    // The canary: independent re-open + re-fold byte-equality — PASSES for the honest fold.
    equivalence_canary_chirho(
        &materialized_chirho,
        &fold_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
}

#[test]
fn feed_and_canary_refuse_torn_source_without_repairing_storage_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = harness_chirho.cluster_chirho();
    let digest_chirho = harness_chirho.seed_chirho();
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

    harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow_mut()
        .get_mut(path_local_chirho.key_chirho())
        .unwrap()
        .extend_from_slice(br#"{"schema_chirho":"ledger-record-v1-chirho"#);
    let torn_storage_chirho = harness_chirho
        .storage_chirho
        .objects_chirho
        .borrow()
        .clone();

    let feed_error_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(feed_error_chirho
        .to_string()
        .contains("ReadOnlyRecoveryRequiredChirho"));
    assert_eq!(
        *harness_chirho.storage_chirho.objects_chirho.borrow(),
        torn_storage_chirho
    );

    let canary_error_chirho = equivalence_canary_chirho(
        &materialized_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap_err();
    assert!(canary_error_chirho
        .to_string()
        .contains("ReadOnlyRecoveryRequiredChirho"));
    assert_eq!(
        *harness_chirho.storage_chirho.objects_chirho.borrow(),
        torn_storage_chirho
    );
}

#[test]
fn canary_fires_on_a_divergent_fold_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = harness_chirho.cluster_chirho();
    let digest_chirho = harness_chirho.seed_chirho();
    let registry_chirho = harness_chirho.registry_chirho();
    let flip_chirho = FlipFoldChirho {
        calls_chirho: Cell::new(0),
    };
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &flip_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let error_chirho = equivalence_canary_chirho(
        &materialized_chirho,
        &flip_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("EQUIVALENCE CANARY FIRED"));
}

#[test]
fn feed_refuses_superseded_retired_and_unknown_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = harness_chirho.cluster_chirho();
    let digest_v1_chirho = harness_chirho.seed_chirho();
    // Amend to v2: v1 becomes superseded.
    let mut descriptor_v2_chirho = descriptor_chirho();
    descriptor_v2_chirho
        .staleness_contract_chirho
        .max_owner_hlc_lag_ms_chirho = 1_000;
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
    let fold_chirho = BalancesFoldChirho;
    let feed_chirho = |digest_chirho: &DigestChirho| {
        feed_projection_once_chirho(
            &registry_chirho,
            "balances-chirho",
            digest_chirho,
            &fold_chirho,
            harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
            &harness_chirho.feeder_root_chirho,
        )
    };
    assert!(feed_chirho(&digest_v1_chirho)
        .unwrap_err()
        .to_string()
        .contains("SUPERSEDED"));
    assert!(feed_chirho(&DigestChirho("ff".repeat(32)))
        .unwrap_err()
        .to_string()
        .contains("UNKNOWN"));
    // Retire: every digest refuses.
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
    let error_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_v1_chirho,
        &fold_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("RETIRED"));
}

/// CF4 acceptance ("canary green under sim faults"): a FAULTING storage must make the feed and
/// the canary FAIL CLOSED — a typed error, never a served view and never a false verdict in
/// either direction (no false CLEAN, no false FIRED).
struct FaultyStorageChirho<'inner_chirho> {
    inner_chirho: &'inner_chirho MemStorageChirho,
    fail_reads_after_chirho: std::cell::Cell<u64>,
    fail_full_reads_only_chirho: bool,
}

impl FaultyStorageChirho<'_> {
    fn before_read_chirho(&self, full_object_chirho: bool) -> anyhow::Result<()> {
        if self.fail_full_reads_only_chirho && !full_object_chirho {
            return Ok(());
        }
        let left_chirho = self.fail_reads_after_chirho.get();
        if left_chirho == 0 {
            anyhow::bail!("injected storage fault (sim)");
        }
        self.fail_reads_after_chirho.set(left_chirho - 1);
        Ok(())
    }
}

impl cairn_ledger_log_chirho::ports_chirho::LedgerStoragePortChirho for FaultyStorageChirho<'_> {
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
        self.before_read_chirho(true)?;
        self.inner_chirho.read_all_chirho(path_chirho)
    }

    fn object_len_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<Option<u64>> {
        self.before_read_chirho(false)?;
        self.inner_chirho.object_len_chirho(path_chirho)
    }

    fn read_exact_range_chirho(
        &self,
        path_chirho: &StoragePathChirho,
        offset_chirho: u64,
        len_chirho: u64,
    ) -> anyhow::Result<Vec<u8>> {
        self.before_read_chirho(false)?;
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
        self.before_read_chirho(false)?;
        self.inner_chirho.list_chirho(prefix_chirho)
    }

    fn exists_chirho(&self, path_chirho: &StoragePathChirho) -> anyhow::Result<bool> {
        self.before_read_chirho(false)?;
        self.inner_chirho.exists_chirho(path_chirho)
    }
}

#[test]
fn feed_and_canary_fail_closed_under_injected_storage_faults_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = harness_chirho.cluster_chirho();
    let digest_chirho = harness_chirho.seed_chirho();
    let registry_chirho = harness_chirho.registry_chirho();
    let fold_chirho = BalancesFoldChirho;
    // An honest feed first (all reads succeed).
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &fold_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    // Now every storage read faults: the FEED fails typed (never a view), and the CANARY fails
    // typed (never a verdict) — fail-closed in both directions under the sim fault.
    let faulty_chirho = FaultyStorageChirho {
        inner_chirho: &harness_chirho.storage_chirho,
        fail_reads_after_chirho: std::cell::Cell::new(0),
        fail_full_reads_only_chirho: false,
    };
    let faulty_ports_chirho = JournalPortsChirho {
        storage_chirho: &faulty_chirho,
        signer_chirho: &harness_chirho.journal_signer_chirho,
        clock_chirho: &harness_chirho.clock_chirho,
        membership_chirho: &harness_chirho.membership_chirho,
        kind_registry_chirho: &harness_chirho.kind_registry_chirho,
        authority_chirho: &harness_chirho.authority_chirho,
    };
    let faulty_source_chirho = ProjectionSourceChirho {
        journal_ports_chirho: faulty_ports_chirho,
        journal_path_chirho: &path_local_chirho,
        cluster_chirho: &cluster_local_chirho,
    };
    assert!(feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &fold_chirho,
        faulty_source_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .is_err());
    assert!(
        equivalence_canary_chirho(&materialized_chirho, &fold_chirho, faulty_source_chirho)
            .is_err(),
        "a faulting canary must refuse, never render a verdict"
    );
    // The advisory sidecar metadata miss is allowed, but the following full-journal fallback read
    // faults. The canary must refuse rather than turning the fast-path miss into a verdict.
    let flaky_chirho = FaultyStorageChirho {
        inner_chirho: &harness_chirho.storage_chirho,
        fail_reads_after_chirho: std::cell::Cell::new(0),
        fail_full_reads_only_chirho: true,
    };
    let flaky_ports_chirho = JournalPortsChirho {
        storage_chirho: &flaky_chirho,
        signer_chirho: &harness_chirho.journal_signer_chirho,
        clock_chirho: &harness_chirho.clock_chirho,
        membership_chirho: &harness_chirho.membership_chirho,
        kind_registry_chirho: &harness_chirho.kind_registry_chirho,
        authority_chirho: &harness_chirho.authority_chirho,
    };
    let flaky_source_chirho = ProjectionSourceChirho {
        journal_ports_chirho: flaky_ports_chirho,
        journal_path_chirho: &path_local_chirho,
        cluster_chirho: &cluster_local_chirho,
    };
    assert!(
        equivalence_canary_chirho(&materialized_chirho, &fold_chirho, flaky_source_chirho).is_err(),
        "a full-journal fault after the advisory sidecar miss must refuse before a verdict"
    );
}
