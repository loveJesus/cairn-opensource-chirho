// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use super::*;
use crate::app_source_manifest_chirho::{
    build_app_source_review_chirho, AppSourceDagManifestChirho, AppSourceDeployManifestChirho,
    AppSourceDeploySourceChirho, AppSourceDeployTargetChirho, AppSourceManifestChirho,
    AppSourceNodeManifestChirho, AppSourceNodeSourceChirho, APP_SOURCE_MANIFEST_SCHEMA_CHIRHO,
};
use crate::model_chirho::{DagChirho, HashChirho, NodeDefChirho, RequestContextChirho};
use crate::{identity_chirho, review_chirho};
use cairn_effect_commit_ledger_chirho::LedgerEffectCommitAdapterChirho;
use cairn_ledger_model_chirho::ids_chirho::AssetKindIdChirho;
use cairn_postgres_effect_chirho::{
    canonical_request_bytes_chirho, DesiredPostgresStateChirho, ExpectedPostgresStateChirho,
    ReversiblePostgresRequestChirho,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn current_plan_authority_requires_exactly_one_postgres_effect_chirho() {
    let (single_root_chirho, single_owner_chirho, _) =
        promoted_postgres_app_chirho("single-current-plan", 1);
    mint_verified_current_undo_plan_authority_chirho(
        &single_root_chirho,
        "single-current-plan",
        &single_owner_chirho,
    )
    .unwrap();
    assert!(matches!(
        mint_verified_current_undo_plan_authority_chirho(
            &single_root_chirho,
            "single-current-plan",
            "foreign-owner-chirho",
        ),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentAppRefusedChirho)
    ));

    let (empty_root_chirho, empty_owner_chirho, _) =
        promoted_postgres_app_chirho("empty-current-plan", 0);
    assert!(matches!(
        mint_verified_current_undo_plan_authority_chirho(
            &empty_root_chirho,
            "empty-current-plan",
            &empty_owner_chirho,
        ),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::NoEligiblePlanEffectChirho)
    ));

    let (multiple_root_chirho, multiple_owner_chirho, _) =
        promoted_postgres_app_chirho("multiple-current-plan", 2);
    assert!(matches!(
        mint_verified_current_undo_plan_authority_chirho(
            &multiple_root_chirho,
            "multiple-current-plan",
            &multiple_owner_chirho,
        ),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligiblePlanEffectsChirho)
    ));

    std::fs::remove_dir_all(single_root_chirho).unwrap();
    std::fs::remove_dir_all(empty_root_chirho).unwrap();
    std::fs::remove_dir_all(multiple_root_chirho).unwrap();
}

#[test]
fn current_plan_authority_refuses_same_dag_with_a_different_current_route_set_chirho() {
    let app_chirho = "route-mismatch-current-plan";
    let (root_chirho, owner_chirho, _) = promoted_postgres_app_chirho(app_chirho, 1);
    let current_dag_chirho = crate::app_chirho::app_status_chirho(&root_chirho, app_chirho)
        .unwrap()
        .dag_chirho
        .unwrap();
    crate::app_chirho::deploy_app_route_unreviewed_dev_chirho(
        &root_chirho,
        app_chirho,
        "later-route-chirho",
        current_dag_chirho,
        &owner_chirho,
    )
    .unwrap();

    assert!(matches!(
        mint_verified_current_undo_plan_authority_chirho(&root_chirho, app_chirho, &owner_chirho,),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::CurrentPromotionRefusedChirho)
    ));
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn current_compensation_preview_writes_no_journal_evidence_or_provider_state_chirho() {
    use super::super::tests_chirho::{
        run_scoped_postgres_node_chirho, JournalHarnessChirho, MemoryPostgresDatabaseChirho,
        ScopedPostgresNodeInputsChirho, APP_PRICE_POLICY_CHIRHO, MONEY_KIND_CHIRHO,
    };

    let app_name_chirho = "preview-current-plan";
    let (root_chirho, owner_chirho, price_book_chirho) =
        promoted_postgres_app_chirho(app_name_chirho, 1);
    let user_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
    )
    .unwrap()
    .principal_chirho;
    let status_chirho =
        crate::app_chirho::app_status_chirho(&root_chirho, app_name_chirho).unwrap();
    let dag_chirho: DagChirho = crate::store_chirho::get_object_chirho(
        &root_chirho,
        status_chirho.dag_chirho.as_ref().unwrap(),
    )
    .unwrap();
    let node_hash_chirho = dag_chirho.nodes_chirho[0].clone();
    let node_chirho: NodeDefChirho =
        crate::store_chirho::get_object_chirho(&root_chirho, &node_hash_chirho).unwrap();
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &root_chirho,
        super::super::ADAPTER_EVIDENCE_SECRET_NAME_CHIRHO,
        &[7_u8; 32],
    )
    .unwrap();
    let subject_chirho = HashChirho("a".repeat(64));
    let row_key_chirho = HashChirho("b".repeat(64));
    let value_ref_chirho = crate::privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            &subject_chirho.0,
        ),
        &subject_chirho.0,
        b"preview-new-value-chirho",
    )
    .unwrap();
    let request_bytes_chirho = canonical_request_bytes_chirho(&ReversiblePostgresRequestChirho {
        schema_chirho: "reversible-postgres-request-v1-chirho".to_owned(),
        subject_chirho: subject_chirho.clone(),
        row_key_chirho: row_key_chirho.clone(),
        expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
        desired_chirho: DesiredPostgresStateChirho::PresentChirho { value_ref_chirho },
    })
    .unwrap();
    let input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &request_bytes_chirho).unwrap();
    let context_chirho = RequestContextChirho {
        user_principal_chirho: user_chirho.clone(),
        app_chirho: app_name_chirho.to_owned(),
        owner_principal_chirho: owner_chirho.clone(),
        client_id_chirho: "preview-client-chirho".to_owned(),
        token_hash_chirho: "preview-token-chirho".to_owned(),
        price_book_chirho: Some(price_book_chirho),
        billing_policy_chirho: None,
        key_limit_chirho: None,
    };
    let authority_chirho = mint_verified_current_undo_plan_authority_chirho(
        &root_chirho,
        app_name_chirho,
        &owner_chirho,
    )
    .unwrap();
    let harness_chirho = JournalHarnessChirho::new_chirho(&user_chirho);
    let mut journal_chirho = harness_chirho.funded_journal_chirho(&user_chirho);
    let mut database_chirho = MemoryPostgresDatabaseChirho::ready_chirho();
    let run_chirho = HashChirho("9".repeat(64));
    let mut journal_adapter_chirho = LedgerEffectCommitAdapterChirho::new_chirho(
        &mut journal_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
    );
    let mut runtime_chirho = super::super::LocalPostgresEffectCompositionChirho::open_chirho(
        &root_chirho,
        &mut journal_adapter_chirho,
        &mut database_chirho,
        &harness_chirho.intent_root_chirho,
        &harness_chirho.terminal_root_chirho,
        &APP_PRICE_POLICY_CHIRHO,
        AssetKindIdChirho(MONEY_KIND_CHIRHO.to_owned()),
    )
    .unwrap();
    run_scoped_postgres_node_chirho(
        &ScopedPostgresNodeInputsChirho {
            root_chirho: &root_chirho,
            node_chirho: &node_chirho,
            node_hash_chirho: &node_hash_chirho,
            input_hash_chirho: &input_hash_chirho,
            context_chirho: &context_chirho,
            run_chirho: &run_chirho,
        },
        false,
        &mut runtime_chirho,
    )
    .unwrap();

    let journal_before_chirho = harness_chirho.storage_chirho.snapshot_chirho();
    let evidence_before_chirho = evidence_snapshot_chirho(&root_chirho);
    let database_before_chirho = (*runtime_chirho.database_chirho).clone();
    let preview_chirho = runtime_chirho
        .preview_current_compensation_chirho(&authority_chirho)
        .unwrap();
    assert_eq!(
        preview_chirho.verdict_chirho,
        CurrentPostgresCompensationPreviewVerdictChirho::ExecutableChirho
    );
    assert_eq!(
        harness_chirho.storage_chirho.snapshot_chirho(),
        journal_before_chirho
    );
    assert_eq!(
        evidence_snapshot_chirho(&root_chirho),
        evidence_before_chirho
    );
    assert_eq!(*runtime_chirho.database_chirho, database_before_chirho);

    runtime_chirho.database_chirho.set_row_chirho(
        &subject_chirho,
        &row_key_chirho,
        b"newer-world-state-chirho",
    );
    let journal_before_chirho = harness_chirho.storage_chirho.snapshot_chirho();
    let evidence_before_chirho = evidence_snapshot_chirho(&root_chirho);
    let database_before_chirho = (*runtime_chirho.database_chirho).clone();
    let preview_chirho = runtime_chirho
        .preview_current_compensation_chirho(&authority_chirho)
        .unwrap();
    assert_eq!(
        preview_chirho.verdict_chirho,
        CurrentPostgresCompensationPreviewVerdictChirho::MustNotExecuteChirho
    );
    assert_eq!(
        harness_chirho.storage_chirho.snapshot_chirho(),
        journal_before_chirho
    );
    assert_eq!(
        evidence_snapshot_chirho(&root_chirho),
        evidence_before_chirho
    );
    assert_eq!(*runtime_chirho.database_chirho, database_before_chirho);

    let second_subject_chirho = HashChirho("c".repeat(64));
    let second_row_key_chirho = HashChirho("d".repeat(64));
    let second_value_ref_chirho = crate::privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            &second_subject_chirho.0,
        ),
        &second_subject_chirho.0,
        b"second-preview-value-chirho",
    )
    .unwrap();
    let second_request_bytes_chirho =
        canonical_request_bytes_chirho(&ReversiblePostgresRequestChirho {
            schema_chirho: "reversible-postgres-request-v1-chirho".to_owned(),
            subject_chirho: second_subject_chirho,
            row_key_chirho: second_row_key_chirho,
            expected_before_chirho: ExpectedPostgresStateChirho::AbsentChirho,
            desired_chirho: DesiredPostgresStateChirho::PresentChirho {
                value_ref_chirho: second_value_ref_chirho,
            },
        })
        .unwrap();
    let second_input_hash_chirho =
        crate::cas_chirho::add_chirho(&root_chirho, &second_request_bytes_chirho).unwrap();
    let second_run_chirho = HashChirho("8".repeat(64));
    run_scoped_postgres_node_chirho(
        &ScopedPostgresNodeInputsChirho {
            root_chirho: &root_chirho,
            node_chirho: &node_chirho,
            node_hash_chirho: &node_hash_chirho,
            input_hash_chirho: &second_input_hash_chirho,
            context_chirho: &context_chirho,
            run_chirho: &second_run_chirho,
        },
        false,
        &mut runtime_chirho,
    )
    .unwrap();
    assert!(matches!(
        runtime_chirho.preview_current_compensation_chirho(&authority_chirho),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::MultipleEligibleJournalEffectsChirho)
    ));

    let replacement_dag_chirho = crate::store_chirho::put_object_chirho(
        &root_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    crate::app_chirho::deploy_app_chirho(
        &root_chirho,
        app_name_chirho,
        replacement_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    assert!(matches!(
        runtime_chirho.preview_current_compensation_chirho(&authority_chirho),
        Err(VerifiedCurrentUndoPlanAuthorityErrorChirho::StaleAuthorityChirho)
    ));
    drop(runtime_chirho);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

pub(in super::super) fn promoted_postgres_app_chirho(
    app_chirho: &str,
    effect_count_chirho: usize,
) -> (PathBuf, String, HashChirho) {
    let root_chirho = temp_root_chirho(app_chirho);
    let artifact_dir_chirho = root_chirho.join("artifacts-chirho");
    std::fs::create_dir_all(&artifact_dir_chirho).unwrap();
    let artifact_chirho = artifact_dir_chirho.join("guest-chirho.wat");
    std::fs::write(
        &artifact_chirho,
        include_str!("../../../../examples-chirho/upcase-chirho.wat"),
    )
    .unwrap();
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let mut nodes_chirho = Vec::new();
    for index_chirho in 0..effect_count_chirho {
        nodes_chirho.push(AppSourceNodeManifestChirho {
            id_chirho: format!("postgres_node_{index_chirho}_chirho"),
            name_chirho: format!("postgres_node_{index_chirho}_chirho"),
            entry_chirho: Some("upcase_chirho".to_owned()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: vec![format!(
                "paid:postgres_reversible_chirho:verified-caller-{index_chirho}-chirho"
            )],
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho.clone(),
            },
        });
    }
    if nodes_chirho.is_empty() {
        nodes_chirho.push(AppSourceNodeManifestChirho {
            id_chirho: "pure_node_chirho".to_owned(),
            name_chirho: "pure_node_chirho".to_owned(),
            entry_chirho: Some("upcase_chirho".to_owned()),
            fuel_chirho: 1_000_000,
            capabilities_chirho: Vec::new(),
            source_chirho: AppSourceNodeSourceChirho::PathChirho {
                path_chirho: artifact_chirho.clone(),
            },
        });
    }
    let dag_nodes_chirho = nodes_chirho
        .iter()
        .map(|node_chirho| node_chirho.id_chirho.clone())
        .collect();
    let manifest_chirho = AppSourceManifestChirho {
        schema_chirho: APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_owned(),
        app_chirho: app_chirho.to_owned(),
        owner_chirho: owner_chirho.clone(),
        nodes_chirho,
        dags_chirho: vec![AppSourceDagManifestChirho {
            id_chirho: "current_plan_dag_chirho".to_owned(),
            nodes_chirho: dag_nodes_chirho,
            edges_chirho: Vec::new(),
        }],
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(AppSourceDeploySourceChirho::DagIdChirho {
                id_chirho: "current_plan_dag_chirho".to_owned(),
            }),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho: AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let review_report_chirho =
        build_app_source_review_chirho(&root_chirho, Path::new("."), &manifest_chirho).unwrap();
    review_chirho::promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        app_chirho,
        &owner_chirho,
        review_report_chirho
            .candidate_chirho
            .root_dag_chirho
            .clone(),
        true,
        true,
        review_report_chirho.source_review_report_chirho.clone(),
    )
    .unwrap();
    let (price_book_chirho, _, _) = crate::effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        app_chirho,
        &owner_chirho,
        None,
        BTreeMap::from([(POSTGRES_REVERSIBLE_EFFECT_SUBTYPE_CHIRHO.to_owned(), 10)]),
        0,
    )
    .unwrap();
    (root_chirho, owner_chirho, price_book_chirho)
}

fn evidence_snapshot_chirho(root_chirho: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let evidence_root_chirho = root_chirho.join("effect-commit-evidence-chirho");
    let mut snapshot_chirho = BTreeMap::new();
    collect_evidence_snapshot_chirho(
        &evidence_root_chirho,
        &evidence_root_chirho,
        &mut snapshot_chirho,
    );
    snapshot_chirho
}

fn collect_evidence_snapshot_chirho(
    base_chirho: &Path,
    current_chirho: &Path,
    snapshot_chirho: &mut BTreeMap<PathBuf, Vec<u8>>,
) {
    let Ok(entries_chirho) = std::fs::read_dir(current_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho {
        let entry_chirho = entry_chirho.unwrap();
        let path_chirho = entry_chirho.path();
        if path_chirho.is_dir() {
            collect_evidence_snapshot_chirho(base_chirho, &path_chirho, snapshot_chirho);
        } else {
            snapshot_chirho.insert(
                path_chirho.strip_prefix(base_chirho).unwrap().to_path_buf(),
                std::fs::read(path_chirho).unwrap(),
            );
        }
    }
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nonce_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "cairn-current-plan-authority-{label_chirho}-{}-{nonce_chirho}-{count_chirho}",
        std::process::id()
    ))
}
