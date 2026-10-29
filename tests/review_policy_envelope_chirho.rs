// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_chirho::model_chirho::{
    CapabilityChirho, DagChirho, HashChirho, NodeDefChirho, PortChirho,
};
use cairn_chirho::review_chirho::{
    load_review_records_chirho, promote_candidate_chirho,
    promote_candidate_with_review_evidence_chirho,
    promote_candidate_with_source_review_report_chirho, review_current_app_candidate_chirho,
    set_review_policy_envelope_chirho, verify_review_policy_envelopes_chirho,
    verify_review_records_chirho, PromoteCandidateReviewEvidenceInputChirho,
    ReviewPolicyEnvelopeEvidenceChirho, ReviewSourceEvidenceChirho,
};
use cairn_chirho::{
    app_chirho, app_source_manifest_chirho, cas_chirho, effect_pricing_chirho, identity_chirho,
    store_chirho,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-review-envelope-test-{label_chirho}-{n_chirho}-{}",
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
    node_with_contract_set_chirho(root_chirho, name_chirho, capabilities_chirho, None)
}

fn descriptor_v2_node_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
) -> HashChirho {
    let contract_set_chirho =
        cairn_undo_plan_chirho::contract_chirho::canonical_authoring_reversion_contract_set_chirho(
        );
    let contract_set_digest_chirho =
        cairn_undo_plan_chirho::canonical_chirho::contract_set_digest_chirho(&contract_set_chirho)
            .unwrap();
    node_with_contract_set_chirho(
        root_chirho,
        name_chirho,
        capabilities_chirho,
        Some(contract_set_digest_chirho),
    )
}

fn node_with_contract_set_chirho(
    root_chirho: &Path,
    name_chirho: &str,
    capabilities_chirho: Vec<CapabilityChirho>,
    effect_contract_set_chirho: Option<HashChirho>,
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
        effect_contract_set_chirho,
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

fn write_jsonl_chirho<TChirho: Serialize>(path_chirho: &Path, records_chirho: &[TChirho]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
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

fn source_review_report_with_contract_refs_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
    candidate_chirho: &HashChirho,
    contract_refs_chirho: Vec<String>,
) -> HashChirho {
    let review_chirho =
        review_current_app_candidate_chirho(root_chirho, app_chirho, candidate_chirho.clone())
            .unwrap();
    let effective_manifest_chirho = app_source_manifest_chirho::AppSourceManifestChirho {
        schema_chirho: app_source_manifest_chirho::APP_SOURCE_MANIFEST_SCHEMA_CHIRHO.to_string(),
        app_chirho: app_chirho.to_string(),
        owner_chirho: owner_chirho.to_string(),
        nodes_chirho: Vec::new(),
        dags_chirho: Vec::new(),
        modules_chirho: Vec::new(),
        assets_chirho: Vec::new(),
        contract_refs_chirho,
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
fn review_policy_envelope_latest_valid_row_wins_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, _candidate_chirho) =
        app_fixture_chirho("envelopelatest");
    let candidate_with_write_chirho = dag_chirho(
        &root_chirho,
        vec![descriptor_v2_node_chirho(
            &root_chirho,
            "write_candidate_chirho",
            vec![CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "envelopelatest/".to_string(),
            }],
        )],
    );
    let _first_chirho = set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopelatest",
        &owner_chirho,
        Vec::new(),
        0,
        Vec::new(),
    )
    .unwrap();
    let second_chirho = set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopelatest",
        &owner_chirho,
        vec!["WriteStoreChirho(prefix=envelopelatest/)".to_string()],
        0,
        Vec::new(),
    )
    .unwrap();
    let source_review_report_chirho = source_review_report_with_contract_refs_chirho(
        &root_chirho,
        "envelopelatest",
        &owner_chirho,
        &candidate_with_write_chirho,
        Vec::new(),
    );

    let record_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "envelopelatest",
        &owner_chirho,
        candidate_with_write_chirho.clone(),
        true,
        false,
        Some(source_review_report_chirho),
    )
    .unwrap();

    match record_chirho.review_policy_envelope_chirho {
        Some(ReviewPolicyEnvelopeEvidenceChirho::BoundChirho {
            envelope_seq_chirho,
            envelope_line_hash_chirho,
        }) => {
            assert_eq!(envelope_seq_chirho, second_chirho.seq_chirho);
            assert_eq!(
                envelope_line_hash_chirho,
                HashChirho(
                    blake3::hash(serde_json::to_string(&second_chirho).unwrap().as_bytes())
                        .to_hex()
                        .to_string()
                )
            );
        }
        other_chirho => panic!("expected bound envelope evidence, got {other_chirho:?}"),
    }
    assert_eq!(
        verify_review_policy_envelopes_chirho(&root_chirho).unwrap(),
        2
    );
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopelatest")
            .unwrap()
            .dag_chirho,
        Some(candidate_with_write_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_wrong_scope_counts_without_selection_chirho() {
    let root_chirho = temp_root_chirho("envelopewrongscope");
    let other_owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    set_review_policy_envelope_chirho(
        &root_chirho,
        "wrongscopeother",
        &other_owner_chirho,
        vec!["ClockChirho".to_string()],
        0,
        Vec::new(),
    )
    .unwrap();
    let live_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "wrong_scope_live_chirho",
            Vec::new(),
        )],
    );
    app_chirho::deploy_app_chirho(&root_chirho, "wrongscopeapp", live_chirho, &owner_chirho)
        .unwrap();
    let candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "wrong_scope_candidate_chirho",
            Vec::new(),
        )],
    );

    let record_chirho = promote_candidate_chirho(
        &root_chirho,
        "wrongscopeapp",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
    )
    .unwrap();

    assert_eq!(
        record_chirho.review_policy_envelope_chirho,
        Some(ReviewPolicyEnvelopeEvidenceChirho::AbsentChirho {
            checked_envelope_count_chirho: 1
        })
    );
    assert_eq!(
        verify_review_policy_envelopes_chirho(&root_chirho).unwrap(),
        1
    );
    assert_eq!(verify_review_records_chirho(&root_chirho).unwrap(), 1);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_blocks_capability_even_with_ack_chirho() {
    let (root_chirho, owner_chirho, live_chirho, _candidate_chirho) =
        app_fixture_chirho("envelopecapblock");
    set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopecapblock",
        &owner_chirho,
        Vec::new(),
        0,
        Vec::new(),
    )
    .unwrap();
    let clock_candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "clock_blocked_chirho",
            vec![CapabilityChirho::ClockChirho],
        )],
    );

    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "envelopecapblock",
        &owner_chirho,
        clock_candidate_chirho,
        true,
        true,
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("capability bound blocks ClockChirho"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopecapblock")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_blocks_cost_even_with_ack_chirho() {
    let (root_chirho, owner_chirho, live_chirho, _candidate_chirho) =
        app_fixture_chirho("envelopecostblock");
    effect_pricing_chirho::set_price_book_chirho(
        &root_chirho,
        "envelopecostblock",
        &owner_chirho,
        None,
        BTreeMap::from([("echo_paid_chirho".to_string(), 17)]),
        0,
    )
    .unwrap();
    let paid_capability_chirho = CapabilityChirho::PaidEffectChirho {
        effect_chirho: "echo_paid_chirho".to_string(),
        caller_chirho: owner_chirho.clone(),
    };
    set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopecostblock",
        &owner_chirho,
        vec![cairn_review_policy_chirho::review_capability_label_chirho(
            &paid_capability_chirho,
        )],
        10,
        Vec::new(),
    )
    .unwrap();
    let paid_candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "paid_blocked_chirho",
            vec![paid_capability_chirho],
        )],
    );

    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "envelopecostblock",
        &owner_chirho,
        paid_candidate_chirho,
        true,
        true,
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("cost bound max=10 candidate=17"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopecostblock")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_contract_refs_fail_closed_without_source_refs_chirho() {
    let (root_chirho, owner_chirho, live_chirho, candidate_chirho) =
        app_fixture_chirho("envelopecontract");
    set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopecontract",
        &owner_chirho,
        Vec::new(),
        0,
        vec![format!("blessed-contract:{}", "a".repeat(64))],
    )
    .unwrap();

    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "envelopecontract",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("contract-ref bound requires source evidence contract refs"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopecontract")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_contract_refs_pass_with_source_refs_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("envelopecontractpass");
    let contract_ref_chirho = format!("blessed-contract:{}", "a".repeat(64));
    let source_review_report_chirho = source_review_report_with_contract_refs_chirho(
        &root_chirho,
        "envelopecontractpass",
        &owner_chirho,
        &candidate_chirho,
        vec![contract_ref_chirho.clone()],
    );
    set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopecontractpass",
        &owner_chirho,
        Vec::new(),
        0,
        vec![contract_ref_chirho],
    )
    .unwrap();

    let record_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "envelopecontractpass",
        &owner_chirho,
        candidate_chirho.clone(),
        false,
        false,
        Some(source_review_report_chirho),
    )
    .unwrap();

    assert_eq!(record_chirho.candidate_chirho, candidate_chirho);
    assert!(matches!(
        record_chirho.review_policy_envelope_chirho,
        Some(ReviewPolicyEnvelopeEvidenceChirho::BoundChirho { .. })
    ));
    verify_review_records_chirho(&root_chirho).unwrap();

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_contract_refs_fail_on_outside_source_ref_chirho() {
    let (root_chirho, owner_chirho, live_chirho, candidate_chirho) =
        app_fixture_chirho("envelopecontractoutside");
    let allowed_ref_chirho = format!("blessed-contract:{}", "a".repeat(64));
    let outside_ref_chirho = format!("blessed-contract:{}", "b".repeat(64));
    let source_review_report_chirho = source_review_report_with_contract_refs_chirho(
        &root_chirho,
        "envelopecontractoutside",
        &owner_chirho,
        &candidate_chirho,
        vec![outside_ref_chirho.clone()],
    );
    set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopecontractoutside",
        &owner_chirho,
        Vec::new(),
        0,
        vec![allowed_ref_chirho],
    )
    .unwrap();

    let error_chirho = promote_candidate_with_source_review_report_chirho(
        &root_chirho,
        "envelopecontractoutside",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
        Some(source_review_report_chirho),
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains(&outside_ref_chirho));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopecontractoutside")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn learner_promotion_requires_review_policy_envelope_chirho() {
    let (root_chirho, owner_chirho, live_chirho, candidate_chirho) =
        app_fixture_chirho("learnerenvelope");
    let source_review_report_chirho = source_review_report_with_contract_refs_chirho(
        &root_chirho,
        "learnerenvelope",
        &owner_chirho,
        &candidate_chirho,
        Vec::new(),
    );

    let error_chirho = promote_candidate_with_review_evidence_chirho(
        &root_chirho,
        PromoteCandidateReviewEvidenceInputChirho {
            app_chirho: "learnerenvelope",
            owner_principal_chirho: &owner_chirho,
            candidate_chirho: candidate_chirho.clone(),
            accept_capability_escalation_chirho: false,
            accept_cost_increase_chirho: false,
            require_review_policy_envelope_chirho: true,
            source_evidence_chirho: ReviewSourceEvidenceChirho {
                source_review_report_chirho: Some(source_review_report_chirho.clone()),
                source_manifest_chirho: None,
            },
        },
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("learner promotion requires a review-policy envelope"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "learnerenvelope")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    set_review_policy_envelope_chirho(
        &root_chirho,
        "learnerenvelope",
        &owner_chirho,
        Vec::new(),
        0,
        Vec::new(),
    )
    .unwrap();

    let record_chirho = promote_candidate_with_review_evidence_chirho(
        &root_chirho,
        PromoteCandidateReviewEvidenceInputChirho {
            app_chirho: "learnerenvelope",
            owner_principal_chirho: &owner_chirho,
            candidate_chirho: candidate_chirho.clone(),
            accept_capability_escalation_chirho: false,
            accept_cost_increase_chirho: false,
            require_review_policy_envelope_chirho: true,
            source_evidence_chirho: ReviewSourceEvidenceChirho {
                source_review_report_chirho: Some(source_review_report_chirho),
                source_manifest_chirho: None,
            },
        },
    )
    .unwrap();
    assert_eq!(record_chirho.candidate_chirho, candidate_chirho);

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_tampered_latest_does_not_fallback_to_looser_chirho() {
    let (root_chirho, owner_chirho, live_chirho, _candidate_chirho) =
        app_fixture_chirho("envelopedowngrade");
    let clock_candidate_chirho = dag_chirho(
        &root_chirho,
        vec![node_chirho(
            &root_chirho,
            "downgrade_clock_candidate_chirho",
            vec![CapabilityChirho::ClockChirho],
        )],
    );
    let looser_chirho = set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopedowngrade",
        &owner_chirho,
        vec!["ClockChirho".to_string()],
        0,
        Vec::new(),
    )
    .unwrap();
    let strict_chirho = set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopedowngrade",
        &owner_chirho,
        Vec::new(),
        0,
        Vec::new(),
    )
    .unwrap();
    let mut tampered_strict_chirho = strict_chirho;
    tampered_strict_chirho.max_candidate_cost_token_chirho = 99;
    write_jsonl_chirho(
        &root_chirho.join("review-policy-envelopes-chirho.jsonl"),
        &[looser_chirho, tampered_strict_chirho],
    );

    let error_chirho = promote_candidate_chirho(
        &root_chirho,
        "envelopedowngrade",
        &owner_chirho,
        clock_candidate_chirho,
        true,
        true,
    )
    .unwrap_err()
    .to_string();

    assert!(error_chirho.contains("signature invalid"));
    assert!(!error_chirho.contains("capability bound blocks"));
    assert_eq!(
        app_chirho::app_status_chirho(&root_chirho, "envelopedowngrade")
            .unwrap()
            .dag_chirho,
        Some(live_chirho)
    );
    assert!(load_review_records_chirho(&root_chirho).unwrap().is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn review_policy_envelope_tamper_fails_closed_chirho() {
    let (root_chirho, owner_chirho, _live_chirho, candidate_chirho) =
        app_fixture_chirho("envelopetamper");
    let envelope_chirho = set_review_policy_envelope_chirho(
        &root_chirho,
        "envelopetamper",
        &owner_chirho,
        Vec::new(),
        0,
        Vec::new(),
    )
    .unwrap();
    let mut tampered_chirho = envelope_chirho.clone();
    tampered_chirho.max_candidate_cost_token_chirho = 99;
    write_jsonl_chirho(
        &root_chirho.join("review-policy-envelopes-chirho.jsonl"),
        &[tampered_chirho],
    );

    let verify_error_chirho = verify_review_policy_envelopes_chirho(&root_chirho)
        .unwrap_err()
        .to_string();
    assert!(verify_error_chirho.contains("signature invalid"));
    let promote_error_chirho = promote_candidate_chirho(
        &root_chirho,
        "envelopetamper",
        &owner_chirho,
        candidate_chirho,
        false,
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(promote_error_chirho.contains("signature invalid"));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
