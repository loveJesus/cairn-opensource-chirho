// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    VerifiedProjectionSourceChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::feeder_chirho::{feed_projection_once_chirho, ProjectionSourceChirho};
use crate::follower_chirho::ProjectionReadOutcomeChirho;
use crate::registry_chirho::{
    append_projection_registry_op_chirho, load_verified_projection_registry_chirho,
    ProjectionRegistryOpChirho,
};
use crate::serving_chirho::{
    journal_source_family_id_chirho, serve_follower_read_chirho, FollowerServeOutcomeChirho,
};
use crate::test_support_chirho::{
    mint_request_chirho, AllMembersChirho, BalancesFoldChirho, MemStorageChirho,
    OpenAuthorityChirho, OpenRegistryChirho, StepClockChirho, TestSignerChirho,
};
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_model_chirho::ids_chirho::{ClusterIdChirho, DigestChirho};
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "publication-test-registry-chirho";

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
}

fn cluster_chirho() -> ClusterIdChirho {
    ClusterIdChirho("cluster-publish-chirho".to_string())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/publish-cluster-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/publication-registry-chirho.jsonl".to_string())
}

fn head_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/heads-chirho/balances-chirho".to_string())
}

fn descriptor_chirho() -> (
    ProjectionDescriptorChirho,
    Vec<VerifiedProjectionSourceChirho>,
) {
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
        name_chirho: "balances-chirho".to_string(),
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

/// Seed journal + registry, feed once, and return everything publication needs.
fn seeded_feed_chirho(
    harness_chirho: &HarnessChirho,
) -> (
    crate::registry_chirho::VerifiedProjectionRegistryChirho,
    MaterializedProjectionChirho,
    Vec<VerifiedProjectionSourceChirho>,
) {
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.journal_ports_chirho(),
        journal_path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-pub-1"))
        .unwrap();
    drop(journal_chirho);
    let (descriptor_chirho, evidence_chirho) = descriptor_chirho();
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
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let materialized_chirho = feed_projection_once_chirho(
        &registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    (registry_chirho, materialized_chirho, evidence_chirho)
}

#[test]
fn publish_load_serve_round_trip_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (registry_chirho, materialized_chirho, evidence_chirho) =
        seeded_feed_chirho(&harness_chirho);
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    // Idempotent re-publication of the same materialization.
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    let loaded_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    assert_eq!(
        loaded_chirho.view_bytes_chirho,
        materialized_chirho.view_bytes_chirho
    );
    assert_eq!(
        loaded_chirho.receipt_chirho,
        materialized_chirho.receipt_chirho
    );
    // The loaded materialization serves through the FULL gate ladder — publication changes
    // nothing about serving law.
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    let outcome_chirho = serve_follower_read_chirho(
        &registry_chirho,
        &loaded_chirho,
        &harness_chirho.feeder_root_chirho,
        &evidence_chirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
    )
    .unwrap();
    assert!(matches!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
    ));
}

#[test]
fn crash_between_cas_and_commit_leaves_the_old_view_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (_registry_chirho, v1_chirho, _evidence_chirho) = seeded_feed_chirho(&harness_chirho);
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &v1_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    // Simulate the v2 CRASH CUT: the CAS half lands (new view bytes written), the receipt commit
    // never happens. The published head must still load v1 intact — OLD, never partial.
    let fake_v2_bytes_chirho = b"{\"fake-v2\":true}".to_vec();
    let fake_v2_digest_chirho =
        crate::feeder_chirho::view_bytes_digest_hex_chirho(&fake_v2_bytes_chirho);
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &view_cas_path_chirho(&fake_v2_digest_chirho),
            &fake_v2_bytes_chirho,
        )
        .unwrap();
    let loaded_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    assert_eq!(loaded_chirho.view_bytes_chirho, v1_chirho.view_bytes_chirho);
    assert_eq!(loaded_chirho.receipt_chirho, v1_chirho.receipt_chirho);
}

#[test]
fn missing_or_divergent_view_bytes_refuse_never_partial_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (_registry_chirho, materialized_chirho, _evidence_chirho) =
        seeded_feed_chirho(&harness_chirho);
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    let cas_path_chirho =
        view_cas_path_chirho(&materialized_chirho.receipt_chirho.view_digest_hex_chirho);
    // Divergent bytes at the CAS path: the binding re-hash refuses.
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&cas_path_chirho, b"tampered-view-chirho")
        .unwrap();
    let error_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("re-hash"));
    // Missing bytes: a receipt without its view REFUSES (never a partial read).
    harness_chirho
        .storage_chirho
        .remove_chirho(&cas_path_chirho)
        .unwrap();
    let error_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("view bytes"));
}

#[test]
fn tampered_or_foreign_head_receipt_refuses_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (_registry_chirho, materialized_chirho, _evidence_chirho) =
        seeded_feed_chirho(&harness_chirho);
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    // Tamper the stored head receipt JSON (cut moved forward): the signature refuses at load.
    let mut tampered_chirho = materialized_chirho.receipt_chirho.clone();
    tampered_chirho.source_tail_seq_chirho += 1;
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &head_path_chirho(),
            &serde_json::to_vec(&tampered_chirho).unwrap(),
        )
        .unwrap();
    let error_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("signature"));
    // Restore the honest receipt, then verify a FOREIGN root also refuses the load.
    publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap();
    let error_chirho = load_published_projection_chirho(
        &harness_chirho.storage_chirho,
        &head_path_chirho(),
        &harness_chirho.journal_signer_chirho,
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("signature"));
}

#[test]
fn publication_refuses_a_materialization_whose_bytes_do_not_match_its_receipt_chirho() {
    let harness_chirho = HarnessChirho::new_chirho();
    let (_registry_chirho, mut materialized_chirho, _evidence_chirho) =
        seeded_feed_chirho(&harness_chirho);
    materialized_chirho.view_bytes_chirho[0] ^= 1;
    let error_chirho = publish_projection_chirho(
        &harness_chirho.storage_chirho,
        &materialized_chirho,
        &head_path_chirho(),
    )
    .unwrap_err();
    assert!(error_chirho.to_string().contains("publication refused"));
    // Nothing was committed: the head stays absent.
    assert!(harness_chirho
        .storage_chirho
        .read_all_chirho(&head_path_chirho())
        .unwrap()
        .is_none());
}
