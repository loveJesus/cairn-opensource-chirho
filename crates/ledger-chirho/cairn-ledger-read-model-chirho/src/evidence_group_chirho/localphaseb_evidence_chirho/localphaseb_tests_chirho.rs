// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Low cut/census constructor seam pins (#6050/#6051/#6117-2): the happy verify-and-bind over a
//! real journal + published head + retained copy, the retained-head TAMPER refusal (the same-seq
//! fork seam — a modified retained receipt can never bind), the wrong-claimed-net/owner refusals,
//! and the retained digest-column bounds. Identification note (#6117-2): interior prev-chain/tail
//! tampers over the SAME shared walk are already pinned by the monitor's evidence-refusal tests
//! (`evidence_failures_refuse_before_any_report_chirho`); density stays the walk's
//! belt-and-suspenders line per #6051.

use super::*;
use crate::account_net_chirho::AccountNetProjectionFoldChirho;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    ProjectionCostClassChirho, ProjectionDescriptorChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    VerifiedProjectionSourceChirho, PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
};
use crate::feeder_chirho::feed_projection_once_chirho;
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
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use cairn_model_privacy_chirho::PrivacyClassChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "localphaseb-test-registry-chirho";
const PROJECTION_CHIRHO: &str = "credits-balance-chirho";

struct LowHarnessChirho {
    storage_chirho: MemStorageChirho,
    journal_signer_chirho: TestSignerChirho,
    feeder_root_chirho: TestSignerChirho,
    registry_root_chirho: TestSignerChirho,
    clock_chirho: StepClockChirho,
    membership_chirho: AllMembersChirho,
    kind_registry_chirho: OpenRegistryChirho,
    authority_chirho: OpenAuthorityChirho,
}

impl LowHarnessChirho {
    fn new_chirho() -> Self {
        LowHarnessChirho {
            storage_chirho: MemStorageChirho::default(),
            journal_signer_chirho: TestSignerChirho {
                name_chirho: "journal-root-chirho",
            },
            feeder_root_chirho: TestSignerChirho {
                name_chirho: "localphaseb-feeder-root-chirho",
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
    ClusterIdChirho("cluster-localphaseb-low-chirho".to_string())
}

fn journal_path_chirho() -> StoragePathChirho {
    StoragePathChirho("journals/localphaseb-low-chirho.jsonl".to_string())
}

fn registry_path_chirho() -> StoragePathChirho {
    StoragePathChirho("projections/localphaseb-low-chirho.jsonl".to_string())
}

fn balance_descriptor_chirho() -> (ProjectionDescriptorChirho, DigestChirho) {
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
        name_chirho: PROJECTION_CHIRHO.to_string(),
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

struct LowFixtureChirho {
    harness_chirho: LowHarnessChirho,
    claim_chirho: H3RegenesisCutPacketClaimChirho,
    retained_path_chirho: StoragePathChirho,
    final_path_chirho: StoragePathChirho,
}

/// Mint 750 to alice, publish the cut (the "regenesis" head), RETAIN a copy of the signed head at
/// a distinct path (the smoke's pre-L2 snapshot semantics), reuse the same signed head as the
/// "final" head at the same tail, and build the claim the packet parent would form.
fn low_fixture_chirho() -> LowFixtureChirho {
    let harness_chirho = LowHarnessChirho::new_chirho();
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        harness_chirho.journal_ports_chirho(),
        journal_path_chirho(),
        cluster_chirho(),
        1,
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 750, "idem-low-1"))
        .unwrap();
    drop(journal_chirho);
    let (descriptor_chirho, digest_chirho) = balance_descriptor_chirho();
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
    let published_chirho = feed_projection_once_chirho(
        &registry_chirho,
        PROJECTION_CHIRHO,
        &digest_chirho,
        &AccountNetProjectionFoldChirho,
        harness_chirho.source_chirho(&path_local_chirho, &cluster_local_chirho),
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let receipt_chirho = &published_chirho.receipt_chirho;
    let claim_chirho = H3RegenesisCutPacketClaimChirho {
        projection_name_chirho: receipt_chirho.projection_name_chirho.clone(),
        descriptor_digest_chirho: receipt_chirho.descriptor_digest_chirho.clone(),
        source_seq_chirho: receipt_chirho.source_tail_seq_chirho,
        source_hlc_chirho: receipt_chirho.source_tail_hlc_chirho.clone(),
        signed_prefix_digest_chirho: receipt_chirho.source_tail_line_digest_chirho.clone(),
        view_digest_hex_chirho: receipt_chirho.view_digest_hex_chirho.clone(),
        account_owner_chirho: "alice-chirho".to_string(),
        account_kind_chirho: "credits-chirho".to_string(),
        account_net_chirho: 750,
    };
    // Persist the view BYTES object the loader resolves by digest (the publish path's law).
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &StoragePathChirho(format!(
                "projections/views-chirho/{}",
                receipt_chirho.view_digest_hex_chirho
            )),
            &published_chirho.view_bytes_chirho,
        )
        .unwrap();
    let head_bytes_chirho = serde_json::to_vec(receipt_chirho).unwrap();
    let retained_path_chirho = StoragePathChirho("published/retained-low-chirho.json".to_string());
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&retained_path_chirho, &head_bytes_chirho)
        .unwrap();
    let final_path_chirho = StoragePathChirho("published/final-low-chirho.json".to_string());
    harness_chirho
        .storage_chirho
        .atomic_write_chirho(&final_path_chirho, &head_bytes_chirho)
        .unwrap();
    LowFixtureChirho {
        harness_chirho,
        claim_chirho,
        retained_path_chirho,
        final_path_chirho,
    }
}

fn run_low_chirho(fixture_chirho: &LowFixtureChirho) -> Result<VerifiedLocalPhaseBEvidenceChirho> {
    let path_local_chirho = journal_path_chirho();
    let cluster_local_chirho = cluster_chirho();
    VerifiedLocalPhaseBEvidenceChirho::verify_and_bind_chirho(
        LocalPhaseBEvidencePortsChirho {
            source_chirho: fixture_chirho
                .harness_chirho
                .source_chirho(&path_local_chirho, &cluster_local_chirho),
            storage_chirho: &fixture_chirho.harness_chirho.storage_chirho,
            feeder_root_chirho: &fixture_chirho.harness_chirho.feeder_root_chirho,
            final_head_path_chirho: &fixture_chirho.final_path_chirho,
        },
        &fixture_chirho.claim_chirho,
        &fixture_chirho.retained_path_chirho,
    )
}

#[test]
fn low_constructor_binds_a_real_cut_and_census_chirho() {
    let fixture_chirho = low_fixture_chirho();
    let evidence_chirho = run_low_chirho(&fixture_chirho).unwrap();
    assert_eq!(evidence_chirho.regenesis_account_net_chirho(), 750);
    assert_eq!(evidence_chirho.final_account_net_chirho(), 750);
    assert_eq!(evidence_chirho.tail_seq_chirho(), 1);
    assert_eq!(evidence_chirho.op_census_chirho().mint_count_chirho, 1);
    assert_eq!(
        evidence_chirho.op_census_chirho().mint_total_amount_chirho,
        750
    );
    // Digest-at-seq bounds on the retained column: 0 = genesis, tail resolves, beyond refuses.
    assert_eq!(
        evidence_chirho
            .ancestor_line_digest_at_seq_chirho(0)
            .unwrap(),
        evidence_chirho.genesis_digest_chirho()
    );
    assert!(evidence_chirho
        .ancestor_line_digest_at_seq_chirho(1)
        .is_ok());
    assert!(evidence_chirho
        .ancestor_line_digest_at_seq_chirho(2)
        .is_err());
}

#[test]
fn low_constructor_refuses_tampered_retained_head_chirho() {
    let fixture_chirho = low_fixture_chirho();
    // Same-seq fork seam: rewrite the retained head with a DIFFERENT view digest while keeping
    // everything else — the receipt signature no longer verifies, so a forked/tampered retained
    // cut can never bind.
    let bytes_chirho = fixture_chirho
        .harness_chirho
        .storage_chirho
        .read_all_chirho(&fixture_chirho.retained_path_chirho)
        .unwrap()
        .unwrap();
    let mut receipt_chirho: crate::feeder_chirho::FollowReceiptChirho =
        serde_json::from_slice(&bytes_chirho).unwrap();
    receipt_chirho.view_digest_hex_chirho = "ff".repeat(32);
    fixture_chirho
        .harness_chirho
        .storage_chirho
        .atomic_write_chirho(
            &fixture_chirho.retained_path_chirho,
            &serde_json::to_vec(&receipt_chirho).unwrap(),
        )
        .unwrap();
    let error_chirho = run_low_chirho(&fixture_chirho).unwrap_err();
    let message_chirho = format!("{error_chirho:#}");
    assert!(
        message_chirho.contains("receipt") || message_chirho.contains("signature"),
        "unexpected refusal: {message_chirho}"
    );
}

#[test]
fn low_constructor_refuses_wrong_claimed_net_chirho() {
    let mut fixture_chirho = low_fixture_chirho();
    fixture_chirho.claim_chirho.account_net_chirho = 751;
    let error_chirho = run_low_chirho(&fixture_chirho).unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("does not equal the VERIFIED view's exact-selected net"));
}

#[test]
fn low_constructor_refuses_wrong_claimed_owner_chirho() {
    let mut fixture_chirho = low_fixture_chirho();
    fixture_chirho.claim_chirho.account_owner_chirho = "mallory-chirho".to_string();
    let error_chirho = run_low_chirho(&fixture_chirho).unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("no row for the packet-claimed account"));
}
