// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::PortChirho;
use crate::{app_source_manifest_chirho, cas_chirho, identity_chirho};
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-review-test-{label_chirho}-{n_chirho}-{}",
        now_ms_chirho()
    ))
}

fn schema_chirho(root_chirho: &Path) -> HashChirho {
    cas_chirho::add_chirho(root_chirho, b"bytes").unwrap()
}

fn node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let schema_chirho = schema_chirho(root_chirho);
    let wasm_chirho = cas_chirho::add_chirho(root_chirho, name_chirho.as_bytes()).unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: name_chirho.to_string(),
        impl_wasm_chirho: wasm_chirho,
        entry_chirho: name_chirho.to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho,
        fuel_limit_chirho: 1,
        ..Default::default()
    };
    store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap()
}

fn dag_chirho(root_chirho: &Path, nodes_chirho: Vec<HashChirho>) -> HashChirho {
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho,
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

fn write_jsonl_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn review_schema_fixture_chirho() -> (PathBuf, ReviewRecordChirho) {
    let root_chirho = temp_root_chirho("schema");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(&root_chirho, "schema_live_chirho", Vec::new())],
    );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "reviewschema",
        live_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "schema_candidate_chirho",
            Vec::new(),
        )],
    );
    let record_chirho = reject_candidate_chirho(
        &root_chirho,
        "reviewschema",
        &owner_chirho.principal_chirho,
        candidate_chirho,
        "not yet",
    )
    .unwrap();
    (root_chirho, record_chirho)
}

fn app_fixture_chirho(label_chirho: &str) -> (PathBuf, String, HashChirho, HashChirho) {
    let root_chirho = temp_root_chirho(label_chirho);
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            &format!("{label_chirho}_live_chirho"),
            Vec::new(),
        )],
    );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        label_chirho,
        live_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            &format!("{label_chirho}_candidate_chirho"),
            Vec::new(),
        )],
    );
    (root_chirho, owner_chirho, live_chirho, candidate_chirho)
}

fn test_object_path_chirho(root_chirho: &Path, hash_chirho: &HashChirho) -> PathBuf {
    root_chirho
        .join("objects-chirho")
        .join(&hash_chirho.0[0..2])
        .join(&hash_chirho.0[2..])
}

fn source_manifest_evidence_chirho(
    root_chirho: &Path,
    label_chirho: &str,
) -> ReviewSourceManifestEvidenceChirho {
    let effective_manifest_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &serde_json::json!({
            "schema_chirho": "review-source-manifest-fixture-v1-chirho",
            "label_chirho": label_chirho,
        }),
    )
    .unwrap();
    let raw_manifest_hash_chirho = cas_chirho::add_chirho(
        root_chirho,
        format!("{{\"label_chirho\":\"{label_chirho}\"}}").as_bytes(),
    )
    .unwrap();
    ReviewSourceManifestEvidenceChirho {
        effective_manifest_hash_chirho,
        raw_manifest_hash_chirho: Some(raw_manifest_hash_chirho),
    }
}

fn source_review_report_hash_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    candidate_chirho: &HashChirho,
) -> HashChirho {
    let effective_manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho: Vec::new(),
        deploy_chirho: app_source_manifest_chirho::AppSourceDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            root_chirho: Some(
                app_source_manifest_chirho::AppSourceDeploySourceChirho::StoredDagChirho {
                    hash_chirho: candidate_chirho.clone(),
                },
            ),
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: Vec::new(),
            runtime_packages_chirho: Vec::new(),
            target_chirho:
                app_source_manifest_chirho::AppSourceDeployTargetChirho::LocalDeployChirho,
        },
    };
    let candidate_report_chirho = app_source_manifest_chirho::build_app_source_candidate_chirho(
        root_chirho,
        Path::new("."),
        &effective_manifest_chirho,
    )
    .unwrap();
    let review_chirho =
        review_current_app_candidate_chirho(root_chirho, app_chirho, candidate_chirho.clone())
            .unwrap();
    let report_chirho = app_source_manifest_chirho::AppSourceReviewReportChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_REVIEW_REPORT_SCHEMA_CHIRHO
            .to_string(),
        source_review_report_chirho: None,
        candidate_chirho: candidate_report_chirho,
        review_chirho,
        non_authoritative_chirho: true,
    };
    app_source_manifest_chirho::put_app_source_review_report_chirho(root_chirho, &report_chirho)
        .unwrap()
}

#[test]
fn collect_dag_capabilities_dedups_and_summarizes_chirho() {
    let root_chirho = temp_root_chirho("collect-caps");
    // Two nodes, the first holding two capabilities and the second repeating one of them —
    // the distinct set should be exactly the two capabilities, in first-seen order.
    let node_a_chirho = node_chirho(
        &root_chirho,
        "writer",
        vec![
            CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "contact/".to_string(),
            },
            CapabilityChirho::PaidEffectChirho {
                effect_chirho: "send_crm_email_chirho".to_string(),
                caller_chirho: "owner/x".to_string(),
            },
        ],
    );
    let node_b_chirho = node_chirho(
        &root_chirho,
        "writer-again",
        vec![CapabilityChirho::WriteStoreChirho {
            prefix_chirho: "contact/".to_string(),
        }],
    );
    let dag_hash_chirho = dag_chirho(&root_chirho, vec![node_a_chirho, node_b_chirho]);

    let caps_chirho = crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
        &root_chirho,
        &dag_hash_chirho,
    )
    .unwrap();
    assert_eq!(
        caps_chirho.len(),
        2,
        "duplicate capability across nodes is collapsed"
    );
    let summary_chirho =
        crate::capability_plain_chirho::summarize_capabilities_chirho(&caps_chirho);
    assert!(summary_chirho.can_write_data_chirho);
    assert!(summary_chirho.can_send_messages_chirho);
    assert!(summary_chirho.can_spend_money_chirho);
    assert!(summary_chirho
        .sentence_chirho
        .ends_with(" — and nothing else."));

    // A capability-free (pure) DAG summarizes to "cannot touch the outside world".
    let pure_node_chirho = node_chirho(&root_chirho, "pure", vec![]);
    let pure_dag_chirho = dag_chirho(&root_chirho, vec![pure_node_chirho]);
    let pure_caps_chirho = crate::dag_capability_scan_chirho::collect_dag_capabilities_chirho(
        &root_chirho,
        &pure_dag_chirho,
    )
    .unwrap();
    assert!(pure_caps_chirho.is_empty());
    let pure_summary_chirho =
        crate::capability_plain_chirho::summarize_capabilities_chirho(&pure_caps_chirho);
    assert!(pure_summary_chirho.is_pure_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_records_are_schema_tagged_and_unknown_schema_fails_chirho() {
    let (root_chirho, record_chirho) = review_schema_fixture_chirho();

    assert_eq!(record_chirho.schema_chirho, REVIEW_RECORD_SCHEMA_CHIRHO);
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);

    let mut bad_record_chirho = record_chirho.clone();
    bad_record_chirho.schema_chirho = "review-record-v9-chirho".to_string();
    write_jsonl_chirho(
        &review_records_path_chirho(&root_chirho),
        &[bad_record_chirho],
    );
    let error_chirho = load_review_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported schema"));
    assert!(verify_review_records_chirho(&root_chirho).is_err());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn legacy_review_records_without_schema_still_verify_chirho() {
    let (root_chirho, mut record_chirho) = review_schema_fixture_chirho();

    record_chirho.schema_chirho.clear();
    record_chirho.sig_chirho = signer_chirho::sign_message_chirho(
        &root_chirho,
        &review_record_message_chirho(&record_chirho).unwrap(),
    )
    .unwrap();
    write_jsonl_chirho(
        &review_records_path_chirho(&root_chirho),
        std::slice::from_ref(&record_chirho),
    );

    let text_chirho = std::fs::read_to_string(review_records_path_chirho(&root_chirho)).unwrap();
    assert!(!text_chirho.contains("schema_chirho"));
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);
    assert!(load_review_records_chirho(&root_chirho)
        .unwrap()
        .iter()
        .all(|record_chirho| record_chirho.schema_chirho.is_empty()));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_promote_signs_source_manifest_evidence_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewsource");
    let source_manifest_chirho = source_manifest_evidence_chirho(&root_chirho, "reviewsource");

    let record_chirho = promote_candidate_with_source_manifest_chirho(
        &root_chirho,
        "reviewsource",
        &owner_chirho,
        candidate_chirho.clone(),
        false,
        false,
        Some(source_manifest_chirho.clone()),
    )
    .unwrap();

    assert_eq!(
        record_chirho.source_manifest_chirho,
        Some(source_manifest_chirho)
    );
    assert_eq!(record_chirho.candidate_chirho, candidate_chirho);
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);
    let text_chirho = std::fs::read_to_string(review_records_path_chirho(&root_chirho)).unwrap();
    assert!(text_chirho.contains("source_manifest_chirho"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_promote_signs_source_review_report_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewreport");
    let source_review_report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewreport",
        &owner_chirho,
        &candidate_chirho,
    );

    let record_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewreport",
        &owner_chirho,
        candidate_chirho.clone(),
        false,
        false,
        Some(source_review_report_chirho.clone()),
    )
    .unwrap();

    assert_eq!(
        record_chirho.source_review_report_chirho,
        Some(source_review_report_chirho)
    );
    assert_eq!(record_chirho.candidate_chirho, candidate_chirho);
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_promote_refuses_an_already_live_unreviewed_same_dag_without_writes_chirho() {
    let root_chirho = temp_root_chirho("reviewunreviewedlive");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "reviewunreviewedlive_candidate_chirho",
            Vec::new(),
        )],
    );
    app_chirho::deploy_app_unreviewed_dev_chirho(
        &root_chirho,
        "reviewunreviewedlive",
        candidate_chirho.clone(),
        &owner_chirho,
    )
    .unwrap();
    let report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewunreviewedlive",
        &owner_chirho,
        &candidate_chirho,
    );
    let app_records_before_chirho = app_chirho::verified_app_records_chirho(&root_chirho).unwrap();
    let route_records_before_chirho =
        app_chirho::load_app_route_records_chirho(&root_chirho).unwrap();
    let asset_records_before_chirho =
        app_chirho::load_app_static_asset_records_chirho(&root_chirho).unwrap();

    let error_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewunreviewedlive",
        &owner_chirho,
        candidate_chirho.clone(),
        false,
        false,
        Some(report_chirho),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("cannot promote an already-live unreviewed dev candidate"));
    assert_eq!(
        app_chirho::verified_app_records_chirho(&root_chirho).unwrap(),
        app_records_before_chirho
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());
    assert_eq!(
        app_chirho::load_app_route_records_chirho(&root_chirho).unwrap(),
        route_records_before_chirho
    );
    assert_eq!(
        app_chirho::load_app_static_asset_records_chirho(&root_chirho).unwrap(),
        asset_records_before_chirho
    );
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let resolved_chirho =
        app_chirho::resolve_app_dag_chirho(&root_chirho, &refs_chirho, "reviewunreviewedlive")
            .unwrap();
    assert_eq!(resolved_chirho.dag_chirho, candidate_chirho);
    assert!(resolved_chirho.unreviewed_dev_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_first_promotion_creates_and_reuses_a_reviewed_live_record_chirho() {
    let root_chirho = temp_root_chirho("reviewfirst");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "reviewfirst_candidate_chirho",
            Vec::new(),
        )],
    );
    let report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewfirst",
        &owner_chirho,
        &candidate_chirho,
    );

    let first_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewfirst",
        &owner_chirho,
        candidate_chirho.clone(),
        false,
        false,
        Some(report_chirho),
    )
    .unwrap();

    assert_eq!(first_chirho.app_record_seq_chirho, Some(0));
    let app_records_chirho = app_chirho::verified_app_records_chirho(&root_chirho).unwrap();
    assert_eq!(app_records_chirho.len(), 1);
    assert!(app_action_is_reviewed_deploy_chirho(
        &app_records_chirho[0].action_chirho
    ));
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);
    let refs_chirho = refs_chirho::load_refs_chirho(&root_chirho).unwrap();
    let resolved_chirho =
        app_chirho::resolve_app_dag_chirho(&root_chirho, &refs_chirho, "reviewfirst").unwrap();
    assert_eq!(resolved_chirho.dag_chirho, candidate_chirho);
    assert!(!resolved_chirho.unreviewed_dev_chirho);

    let repeated_report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewfirst",
        &owner_chirho,
        &candidate_chirho,
    );
    let repeated_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewfirst",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(repeated_report_chirho),
    )
    .unwrap();
    assert_eq!(repeated_chirho.app_record_seq_chirho, Some(0));
    assert_eq!(
        app_chirho::verified_app_records_chirho(&root_chirho)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 2);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_promote_rejects_report_for_different_candidate_chirho() {
    let (root_chirho, owner_chirho, live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewwrongreport");
    let other_candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "reviewwrongreport_other_chirho",
            Vec::new(),
        )],
    );
    let source_review_report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewwrongreport",
        &owner_chirho,
        &other_candidate_chirho,
    );

    let error_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewwrongreport",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(source_review_report_chirho),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("source report candidate"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "reviewwrongreport")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_verify_rejects_tampered_source_review_report_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewtamperreport");
    let source_review_report_chirho = source_review_report_hash_chirho(
        &root_chirho,
        "reviewtamperreport",
        &owner_chirho,
        &candidate_chirho,
    );
    promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "reviewtamperreport",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(source_review_report_chirho.clone()),
    )
    .unwrap();
    std::fs::write(
        test_object_path_chirho(&root_chirho, &source_review_report_chirho),
        b"{\"tampered_chirho\":true}",
    )
    .unwrap();

    let error_chirho = verify_review_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("review source report"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_verify_rejects_tampered_effective_source_manifest_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewtampermanifest");
    let source_manifest_chirho =
        source_manifest_evidence_chirho(&root_chirho, "reviewtampermanifest");
    promote_candidate_with_source_manifest_chirho(
        &root_chirho,
        "reviewtampermanifest",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(source_manifest_chirho.clone()),
    )
    .unwrap();
    std::fs::write(
        test_object_path_chirho(
            &root_chirho,
            &source_manifest_chirho.effective_manifest_hash_chirho,
        ),
        b"{\"tampered_chirho\":true}",
    )
    .unwrap();

    let error_chirho = verify_review_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("review source manifest"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_verify_rejects_missing_raw_source_manifest_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewrawmanifest");
    let source_manifest_chirho = source_manifest_evidence_chirho(&root_chirho, "reviewrawmanifest");
    promote_candidate_with_source_manifest_chirho(
        &root_chirho,
        "reviewrawmanifest",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(source_manifest_chirho.clone()),
    )
    .unwrap();
    std::fs::remove_file(test_object_path_chirho(
        &root_chirho,
        source_manifest_chirho
            .raw_manifest_hash_chirho
            .as_ref()
            .unwrap(),
    ))
    .unwrap();

    let error_chirho = verify_review_records_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("review raw source manifest"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_promote_validates_source_manifest_before_deploy_chirho() {
    let (root_chirho, owner_chirho, live_chirho, candidate_chirho) =
        app_fixture_chirho("reviewmissingsource");
    let missing_hash_chirho = HashChirho("f".repeat(64));
    let error_chirho = promote_candidate_with_source_manifest_chirho(
        &root_chirho,
        "reviewmissingsource",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(ReviewSourceManifestEvidenceChirho {
            effective_manifest_hash_chirho: missing_hash_chirho,
            raw_manifest_hash_chirho: None,
        }),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("review source manifest"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "reviewmissingsource")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_diff_surfaces_capability_and_cost_delta_chirho() {
    let root_chirho = temp_root_chirho("diff");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let pure_node_chirho = node_chirho(&root_chirho, "pure_chirho", Vec::new());
    let live_chirho = dag_chirho(&root_chirho, vec![pure_node_chirho]);
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "reviewapp",
        live_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        None,
        BTreeMap::from([("echo_paid_chirho".to_string(), 17)]),
        0,
    )
    .unwrap();
    let paid_node_chirho = node_chirho(
        &root_chirho,
        "paid_chirho",
        vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: "user/demo".to_string(),
        }],
    );
    let candidate_chirho = dag_chirho(&root_chirho, vec![paid_node_chirho]);

    let diff_chirho =
        review_current_app_candidate_chirho(&root_chirho, "reviewapp", candidate_chirho).unwrap();
    assert_eq!(diff_chirho.cost_delta_token_chirho, 17);
    assert_eq!(
        diff_chirho.candidate_paid_effects_chirho[0].unit_cost_token_chirho,
        17
    );
    assert!(diff_chirho
        .added_capabilities_chirho
        .iter()
        .any(|cap_chirho| cap_chirho.contains("PaidEffectChirho(effect=echo_paid_chirho")));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_current_app_candidate_requires_verified_live_app_ref_chirho() {
    let root_chirho = temp_root_chirho("tamper-live");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(&root_chirho, "live_chirho", Vec::new())],
    );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "reviewtamper",
        live_chirho,
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    let forged_live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(&root_chirho, "forged_live_chirho", Vec::new())],
    );
    refs_chirho::set_branch_chirho(&root_chirho, "app/reviewtamper", forged_live_chirho).unwrap();
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(&root_chirho, "candidate_chirho", Vec::new())],
    );

    let error_chirho =
        review_current_app_candidate_chirho(&root_chirho, "reviewtamper", candidate_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("ref does not match any signed app deploy record"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn promote_requires_escalation_and_bindings_then_records_pure_decision_chirho() {
    let root_chirho = temp_root_chirho("promote");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(&root_chirho, "pure_chirho", Vec::new())],
    );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "reviewapp",
        live_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();
    effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        None,
        BTreeMap::from([("echo_paid_chirho".to_string(), 17)]),
        0,
    )
    .unwrap();
    let paid_node_chirho = node_chirho(
        &root_chirho,
        "paid_chirho",
        vec![CapabilityChirho::PaidEffectChirho {
            effect_chirho: "echo_paid_chirho".to_string(),
            caller_chirho: owner_chirho.principal_chirho.clone(),
        }],
    );
    let candidate_chirho = dag_chirho(&root_chirho, vec![paid_node_chirho]);

    assert!(promote_candidate_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        candidate_chirho.clone(),
        false,
        true,
    )
    .is_err());
    assert!(promote_candidate_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        candidate_chirho.clone(),
        true,
        false,
    )
    .is_err());
    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        candidate_chirho.clone(),
        true,
        true,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("requires complete verified undo-plan bindings"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "reviewapp")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );

    let pure_candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "pure_candidate_chirho",
            Vec::new(),
        )],
    );
    let promoted_chirho = promote_candidate_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        pure_candidate_chirho.clone(),
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        promoted_chirho.decision_chirho,
        ReviewDecisionChirho::PromoteChirho
    );
    assert_eq!(promoted_chirho.diff_chirho.cost_delta_token_chirho, 0);
    assert!(promoted_chirho.diff_chirho.price_book_chirho.is_some());
    assert_eq!(
        promoted_chirho.review_policy_envelope_chirho,
        Some(ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho {
            checked_envelope_count_chirho: 0
        })
    );
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "reviewapp")
            .unwrap()
            .dag_chirho,
        Some(pure_candidate_chirho.clone())
    );

    let rejected_chirho = reject_candidate_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        pure_candidate_chirho,
        "not this revision",
    )
    .unwrap();
    assert_eq!(
        rejected_chirho.decision_chirho,
        ReviewDecisionChirho::RejectChirho
    );
    effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "reviewapp",
        &owner_chirho.principal_chirho,
        None,
        BTreeMap::from([("echo_paid_chirho".to_string(), 29)]),
        0,
    )
    .unwrap();
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 2);
    assert!(crate::legacy_ledger_evidence_chirho::verify_ledger_chirho(&root_chirho).is_ok());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_retry_cannot_grant_v2_authority_to_current_legacy_effectful_root_chirho() {
    let root_chirho = temp_root_chirho("review-retry-legacy");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap();
    let legacy_effectful_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "legacy_effectful_chirho",
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "legacy/review-retry-chirho".to_string(),
            }],
        )],
    );
    app_chirho::deploy_app_chirho(
        &root_chirho,
        "legacyreviewapp",
        legacy_effectful_chirho.clone(),
        &owner_chirho.principal_chirho,
    )
    .unwrap();

    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "legacyreviewapp",
        &owner_chirho.principal_chirho,
        legacy_effectful_chirho.clone(),
        false,
        false,
    )
    .unwrap_err();
    assert!(error_chirho
        .to_string()
        .contains("requires complete verified undo-plan bindings"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "legacyreviewapp")
            .unwrap()
            .dag_chirho,
        Some(legacy_effectful_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
