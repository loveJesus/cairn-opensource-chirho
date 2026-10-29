// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::descriptor_chirho::{
    derive_projection_privacy_evidence_ref_chirho, projection_descriptor_digest_chirho,
    verify_projection_descriptor_chirho, ProjectionCostClassChirho, ProjectionReadPolicyChirho,
    ProjectionRebuildLawChirho, ProjectionSourceBindingChirho, StalenessContractChirho,
    PROJECTION_DESCRIPTOR_SCHEMA_V1_CHIRHO,
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
use cairn_chain_core_chirho::stored_line_digest_hex_chirho;
use cairn_ledger_log_chirho::journal_chirho::{JournalPortsChirho, LedgerJournalChirho};
use cairn_ledger_model_chirho::ids_chirho::ClusterIdChirho;
use std::cell::Cell;

const REGISTRY_ID_CHIRHO: &str = "source-test-registry-chirho";

fn storage_chirho() -> MemStorageChirho {
    MemStorageChirho::default()
}

fn root_chirho() -> TestSignerChirho {
    TestSignerChirho {
        name_chirho: "source-registry-root-chirho",
    }
}

fn path_chirho() -> StoragePathChirho {
    StoragePathChirho("registries/sources-chirho.jsonl".to_string())
}

fn declaration_chirho(
    family_chirho: &str,
    floor_chirho: PrivacyClassChirho,
) -> SourceDeclarationChirho {
    SourceDeclarationChirho {
        family_id_chirho: family_chirho.to_string(),
        schema_ref_chirho: DigestChirho("aa".repeat(32)),
        privacy_floor_chirho: floor_chirho,
        privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
    }
}

#[test]
fn lifecycle_floor_monotone_and_resolution_chirho() {
    let storage_local_chirho = storage_chirho();
    let root_local_chirho = root_chirho();
    let append_chirho = |op_chirho: SourceRegistryOpChirho| {
        append_source_registry_op_chirho(
            &storage_local_chirho,
            &root_local_chirho,
            &path_chirho(),
            REGISTRY_ID_CHIRHO,
            op_chirho,
        )
    };
    append_chirho(SourceRegistryOpChirho::RegisterSourceChirho {
        declaration_chirho: declaration_chirho("family-a-chirho", PrivacyClassChirho::SafeChirho),
    })
    .unwrap();
    // Duplicate registration refuses (first registration wins).
    assert!(append_chirho(SourceRegistryOpChirho::RegisterSourceChirho {
        declaration_chirho: declaration_chirho("family-a-chirho", PrivacyClassChirho::SafeChirho),
    })
    .unwrap_err()
    .to_string()
    .contains("already registered"));
    // Floor RAISE is a legal amend.
    append_chirho(SourceRegistryOpChirho::AmendSourceChirho {
        declaration_chirho: declaration_chirho(
            "family-a-chirho",
            PrivacyClassChirho::AnalyticalChirho,
        ),
    })
    .unwrap();
    // Floor LOWER refuses — the downgrade class.
    assert!(append_chirho(SourceRegistryOpChirho::AmendSourceChirho {
        declaration_chirho: declaration_chirho("family-a-chirho", PrivacyClassChirho::SafeChirho),
    })
    .unwrap_err()
    .to_string()
    .contains("LOWERS"));
    // Resolution against the CURRENT declaration.
    let registry_chirho = load_verified_source_registry_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let descriptor_chirho = descriptor_for_chirho("family-a-chirho");
    let resolved_chirho =
        resolve_projection_sources_chirho(&registry_chirho, &descriptor_chirho).unwrap();
    assert_eq!(resolved_chirho.len(), 1);
    assert_eq!(
        resolved_chirho[0].privacy_floor_chirho,
        PrivacyClassChirho::AnalyticalChirho
    );
    // Schema drift refuses: a descriptor pinning a different schema revision.
    let mut drifted_chirho = descriptor_for_chirho("family-a-chirho");
    drifted_chirho.source_families_chirho[0].source_schema_ref_chirho =
        DigestChirho("bb".repeat(32));
    assert!(
        resolve_projection_sources_chirho(&registry_chirho, &drifted_chirho)
            .unwrap_err()
            .to_string()
            .contains("schema drift")
    );
    // Retire: resolution refuses afterward.
    append_chirho(SourceRegistryOpChirho::RetireSourceChirho {
        family_id_chirho: "family-a-chirho".to_string(),
    })
    .unwrap();
    let registry_chirho = load_verified_source_registry_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    assert!(
        resolve_projection_sources_chirho(&registry_chirho, &descriptor_chirho)
            .unwrap_err()
            .to_string()
            .contains("RETIRED")
    );
    // Unregistered family refuses.
    let unknown_chirho = descriptor_for_chirho("family-z-chirho");
    assert!(
        resolve_projection_sources_chirho(&registry_chirho, &unknown_chirho)
            .unwrap_err()
            .to_string()
            .contains("UNREGISTERED")
    );
}

/// A minimal descriptor binding one family under the canonical schema ref, with the evidence
/// digest DERIVED from the registry's would-be resolution (Analytical floor era).
fn descriptor_for_chirho(family_chirho: &str) -> crate::ProjectionDescriptorChirho {
    let sources_chirho = vec![crate::descriptor_chirho::VerifiedProjectionSourceChirho {
        binding_chirho: ProjectionSourceBindingChirho {
            family_id_chirho: family_chirho.to_string(),
            source_schema_ref_chirho: DigestChirho("aa".repeat(32)),
        },
        privacy_floor_chirho: PrivacyClassChirho::AnalyticalChirho,
        privacy_evidence_ref_chirho: DigestChirho("cc".repeat(32)),
    }];
    let evidence_chirho = derive_projection_privacy_evidence_ref_chirho(&sources_chirho).unwrap();
    crate::ProjectionDescriptorChirho {
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
    }
}

#[test]
fn tampered_torn_and_cross_registry_fail_closed_chirho() {
    let storage_local_chirho = storage_chirho();
    let root_local_chirho = root_chirho();
    append_source_registry_op_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        SourceRegistryOpChirho::RegisterSourceChirho {
            declaration_chirho: declaration_chirho(
                "family-a-chirho",
                PrivacyClassChirho::SafeChirho,
            ),
        },
    )
    .unwrap();
    let honest_chirho = storage_local_chirho
        .read_all_chirho(&path_chirho())
        .unwrap()
        .unwrap();
    // Torn tail (no trailing LF) fails closed.
    let mut torn_chirho = honest_chirho.clone();
    torn_chirho.pop();
    storage_local_chirho
        .atomic_write_chirho(&path_chirho(), &torn_chirho)
        .unwrap();
    assert!(load_verified_source_registry_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap_err()
    .to_string()
    .contains("torn tail"));
    // Tampered byte fails the canonical/signature laws.
    let mut tampered_chirho = honest_chirho.clone();
    let flip_chirho = tampered_chirho
        .iter()
        .position(|byte_chirho| *byte_chirho == b'a')
        .unwrap();
    tampered_chirho[flip_chirho] = b'b';
    storage_local_chirho
        .atomic_write_chirho(&path_chirho(), &tampered_chirho)
        .unwrap();
    assert!(load_verified_source_registry_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .is_err());
    // Cross-registry replay: the honest bytes under a DIFFERENT registry id refuse at the anchor.
    storage_local_chirho
        .atomic_write_chirho(&path_chirho(), &honest_chirho)
        .unwrap();
    assert!(load_verified_source_registry_chirho(
        &storage_local_chirho,
        &root_local_chirho,
        &path_chirho(),
        "another-registry-chirho",
    )
    .unwrap_err()
    .to_string()
    .contains("prev mismatch at seq 0"));
    // Foreign root refuses by signature.
    let foreign_chirho = TestSignerChirho {
        name_chirho: "foreign-root-chirho",
    };
    assert!(load_verified_source_registry_chirho(
        &storage_local_chirho,
        &foreign_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap_err()
    .to_string()
    .contains("signature"));
    let _ = stored_line_digest_hex_chirho("anchor-use-keepalive-chirho");
}

/// END-TO-END (the CF7 §2 wiring): resolve evidence FROM THE SIGNED REGISTRY (no caller-supplied
/// floors anywhere) → verify the descriptor → feed → serve fresh. Then RAISE the source floor and
/// prove the old descriptor's evidence no longer verifies — the re-registration discipline.
#[test]
fn resolved_evidence_feeds_and_serves_then_floor_raise_forces_reregistration_chirho() {
    struct HarnessChirho {
        storage_chirho: MemStorageChirho,
        journal_signer_chirho: TestSignerChirho,
        feeder_root_chirho: TestSignerChirho,
        registry_root_chirho: TestSignerChirho,
        source_root_chirho: TestSignerChirho,
        clock_chirho: StepClockChirho,
        membership_chirho: AllMembersChirho,
        kind_registry_chirho: OpenRegistryChirho,
        authority_chirho: OpenAuthorityChirho,
    }
    let harness_chirho = HarnessChirho {
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
        source_root_chirho: TestSignerChirho {
            name_chirho: "source-registry-root-chirho",
        },
        clock_chirho: StepClockChirho {
            now_ms_chirho: Cell::new(1_000),
        },
        membership_chirho: AllMembersChirho,
        kind_registry_chirho: OpenRegistryChirho,
        authority_chirho: OpenAuthorityChirho,
    };
    let ports_chirho = JournalPortsChirho {
        storage_chirho: &harness_chirho.storage_chirho,
        signer_chirho: &harness_chirho.journal_signer_chirho,
        clock_chirho: &harness_chirho.clock_chirho,
        membership_chirho: &harness_chirho.membership_chirho,
        kind_registry_chirho: &harness_chirho.kind_registry_chirho,
        authority_chirho: &harness_chirho.authority_chirho,
    };
    let cluster_local_chirho = ClusterIdChirho("cluster-src-chirho".to_string());
    let journal_path_chirho = StoragePathChirho("journals/src-cluster-chirho.jsonl".to_string());
    let family_chirho = journal_source_family_id_chirho(&cluster_local_chirho);
    let mut journal_chirho = LedgerJournalChirho::create_chirho(
        ports_chirho,
        journal_path_chirho.clone(),
        cluster_local_chirho.clone(),
        1,
    )
    .unwrap();
    journal_chirho
        .append_chirho(mint_request_chirho("alice-chirho", 700, "idem-src-1"))
        .unwrap();
    drop(journal_chirho);
    // Register the SOURCE at Analytical.
    append_source_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.source_root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        SourceRegistryOpChirho::RegisterSourceChirho {
            declaration_chirho: declaration_chirho(
                &family_chirho,
                PrivacyClassChirho::AnalyticalChirho,
            ),
        },
    )
    .unwrap();
    let source_registry_chirho = load_verified_source_registry_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.source_root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    // The descriptor is built FROM the resolved evidence — nothing caller-chosen.
    let descriptor_chirho = descriptor_for_chirho(&family_chirho);
    let resolved_chirho =
        resolve_projection_sources_chirho(&source_registry_chirho, &descriptor_chirho).unwrap();
    verify_projection_descriptor_chirho(descriptor_chirho.clone(), &resolved_chirho).unwrap();
    let digest_chirho = projection_descriptor_digest_chirho(&descriptor_chirho).unwrap();
    let projection_registry_path_chirho =
        StoragePathChirho("registries/projections-src-chirho.jsonl".to_string());
    append_projection_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &projection_registry_path_chirho,
        "src-projections-chirho",
        ProjectionRegistryOpChirho::RegisterProjectionChirho {
            descriptor_chirho: descriptor_chirho.clone(),
        },
    )
    .unwrap();
    let projection_registry_chirho = load_verified_projection_registry_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.registry_root_chirho,
        &projection_registry_path_chirho,
        "src-projections-chirho",
    )
    .unwrap();
    let source_chirho = ProjectionSourceChirho {
        journal_ports_chirho: ports_chirho,
        journal_path_chirho: &journal_path_chirho,
        cluster_chirho: &cluster_local_chirho,
    };
    let materialized_chirho = feed_projection_once_chirho(
        &projection_registry_chirho,
        "balances-chirho",
        &digest_chirho,
        &BalancesFoldChirho,
        source_chirho,
        &harness_chirho.feeder_root_chirho,
    )
    .unwrap();
    let outcome_chirho = serve_follower_read_chirho(
        &projection_registry_chirho,
        &materialized_chirho,
        &harness_chirho.feeder_root_chirho,
        &resolved_chirho,
        source_chirho,
    )
    .unwrap();
    assert!(matches!(
        outcome_chirho,
        FollowerServeOutcomeChirho::ReadChirho(ProjectionReadOutcomeChirho::FreshChirho { .. })
    ));
    // RAISE the source floor to Quasi: resolution now yields evidence the OLD descriptor cannot
    // verify against — feeds/serves built from fresh resolution REFUSE until re-registration.
    append_source_registry_op_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.source_root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
        SourceRegistryOpChirho::AmendSourceChirho {
            declaration_chirho: declaration_chirho(&family_chirho, PrivacyClassChirho::QuasiChirho),
        },
    )
    .unwrap();
    let source_registry_chirho = load_verified_source_registry_chirho(
        &harness_chirho.storage_chirho,
        &harness_chirho.source_root_chirho,
        &path_chirho(),
        REGISTRY_ID_CHIRHO,
    )
    .unwrap();
    let raised_chirho =
        resolve_projection_sources_chirho(&source_registry_chirho, &descriptor_chirho).unwrap();
    assert!(
        verify_projection_descriptor_chirho(descriptor_chirho, &raised_chirho)
            .unwrap_err()
            .to_string()
            .contains("privacy"),
        "a raised source floor must break the old descriptor's evidence binding"
    );
}
