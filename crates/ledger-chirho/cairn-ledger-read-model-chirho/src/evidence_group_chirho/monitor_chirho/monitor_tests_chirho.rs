// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    VerifiedProjectionSourceChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::feeder_chirho::{feed_projection_once_chirho, follow_receipt_signed_content_chirho};
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::serving_chirho::journal_source_family_id_chirho;
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, MemStorageChirho, OpenAuthorityChirho,
    OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_log_chirho::ports_chirho::StoragePathChirho;
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "monitor-test-registry-chirho";

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
                name_chirho: "monitor-feeder-root-chirho",
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
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-monitor-chirho".to_string())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/monitor-cluster-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/monitor-registry-chirho.jsonl".to_string())
}

fn supply_descriptor_chirho() -> (ProjectionDescriptorChirho, DigestChirho) {
    let family_chirho = journal_source_family_id_chirho(&cluster_chirho());
    let sources_chirho = vec![VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: family_chirho,
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        },
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
    }];
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    let descriptor_chirho = ProjectionDescriptorChirho {
        schema_chirho: PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO.to_string(),
        name_chirho: "supply-chirho".to_string(),
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
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    (descriptor_chirho, digest_chirho)
}

/// Create the journal + registry, mint once, feed cut 1; mint more, feed cut 2; return both.
fn two_cuts_chirho(
    harness_chirho: &HarnessChirho,
) -> (MaterializedProjectionChirho, MaterializedProjectionChirho) {
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.journal_ports_chirho(),
        journal_path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-mon-1"))
        .unwrap();
    drop(journal_chirho);
    let (descriptor_chirho, digest_chirho) = supply_descriptor_chirho();
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
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let prev_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "supply-chirho",
        &digest_chirho,
        &SupplyFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let mut journal_chirho = LedgerJournalChirho::open_chirho(
        harness_chirho.journal_ports_chirho(),
        journal_path_chirho(),
        &cluster_chirho(),
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("bob-chirho", 60, "idem-mon-2"))
        .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("carol-chirho", 40, "idem-mon-3"))
        .unwrap();
    drop(journal_chirho);
    let next_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "supply-chirho",
        &digest_chirho,
        &SupplyFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    (prev_chirho, next_chirho)
}

#[test]
fn conserved_interval_reports_clean_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (prev_chirho, next_chirho) = two_cuts_chirho(&harness_chirho);
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let report_chirho = conservation_check_chirho(
        &prev_chirho,
        &next_chirho,
        &harness_chirho.feeder_root_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(report_chirho.prev_seq_chirho, 1);
    assert_eq!(report_chirho.next_seq_chirho, 3);
    assert_eq!(report_chirho.kinds_checked_chirho, 1);
    assert!(
        report_chirho.alarms_chirho.is_empty(),
        "an honest mint interval must reconcile: {report_chirho:?}"
    );
}

#[test]
fn doctored_view_fires_the_alarm_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (prev_chirho, next_chirho) = two_cuts_chirho(&harness_chirho);
    // Doctor the NEXT view: claim 50 more supply than the records warrant, re-bind the digest,
    // and RE-SIGN the receipt with the honest feeder root — every receipt law passes, so ONLY
    // the conservation comparison can catch it. This is the monitor's reason to exist: evidence
    // that is internally consistent yet lies about the money.
    let mut supply_chirho: std::collections::BTreeMap<String, u64> =
        serde_json::from_slice(&next_chirho.view_bytes_chirho).unwrap();
    *supply_chirho.get_mut("credits-chirho").unwrap() += 50;
    let doctored_bytes_chirho = serde_json::to_vec(&supply_chirho).unwrap();
    let mut doctored_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: doctored_bytes_chirho,
        receipt_chirho: next_chirho.receipt_chirho.clone(),
    };
    doctored_chirho.receipt_chirho.view_digest_hex_chirho =
        view_bytes_digest_hex_chirho(&doctored_chirho.view_bytes_chirho);
    doctored_chirho.receipt_chirho.feeder_sig_chirho = String::new();
    let content_chirho =
        follow_receipt_signed_content_chirho(&doctored_chirho.receipt_chirho).unwrap();
    doctored_chirho.receipt_chirho.feeder_sig_chirho = harness_chirho
        .feeder_root_chirho
        .sign_chirho(&content_chirho)
        .unwrap();
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let report_chirho = conservation_check_chirho(
        &prev_chirho,
        &doctored_chirho,
        &harness_chirho.feeder_root_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert_eq!(report_chirho.alarms_chirho.len(), 1);
    let alarm_chirho = &report_chirho.alarms_chirho[0];
    assert_eq!(alarm_chirho.kind_chirho, "credits-chirho");
    assert_eq!(alarm_chirho.view_delta_chirho, 150);
    assert_eq!(alarm_chirho.records_delta_chirho, 100);
}

#[test]
fn evidence_failures_refuse_before_any_report_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (prev_chirho, next_chirho) = two_cuts_chirho(&harness_chirho);
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    // Foreign root: no report.
    assert!(conservation_check_chirho(
        &prev_chirho,
        &next_chirho,
        &harness_chirho.journal_signer_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .is_err());
    // Forged INTERIOR cut: a validly re-signed prev receipt whose bound line digest is not an
    // ancestor of the live chain — the interior-ancestry law refuses (the monitor closes the
    // interior-rewrite class for its own comparisons).
    let mut forged_chirho = MaterializedProjectionChirho {
        view_bytes_chirho: prev_chirho.view_bytes_chirho.clone(),
        receipt_chirho: prev_chirho.receipt_chirho.clone(),
    };
    forged_chirho.receipt_chirho.source_tail_line_digest_chirho = DigestChirho("ab".repeat(32));
    forged_chirho.receipt_chirho.feeder_sig_chirho = String::new();
    let content_chirho =
        follow_receipt_signed_content_chirho(&forged_chirho.receipt_chirho).unwrap();
    forged_chirho.receipt_chirho.feeder_sig_chirho = harness_chirho
        .feeder_root_chirho
        .sign_chirho(&content_chirho)
        .unwrap();
    let error_chirho = conservation_check_chirho(
        &forged_chirho,
        &next_chirho,
        &harness_chirho.feeder_root_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("NOT an ancestor"));
    // Swapped order refuses.
    assert!(conservation_check_chirho(
        &next_chirho,
        &prev_chirho,
        &harness_chirho.feeder_root_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap_err()
    .to_string()
    .contains("swap"));
}
