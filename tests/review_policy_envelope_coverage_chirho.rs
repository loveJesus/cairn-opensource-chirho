// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

use cairn_chirho::model_chirho::{DagChirho, HashChirho, NodeDefChirho, PortChirho};
use cairn_chirho::{
    app_chirho, cas_chirho, compliance_evidence_chirho, data_rights_chirho, identity_chirho,
    retention_chirho, review_chirho, store_chirho,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms_chirho() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-review-policy-envelope-coverage-{label_chirho}-{}-{n_chirho}-{}",
        std::process::id(),
        now_ms_chirho()
    ))
}

fn invalid_signature_chirho() -> String {
    "00".repeat(64)
}

fn write_jsonl_records_chirho<T: Serialize>(path_chirho: &Path, records_chirho: &[T]) {
    let mut text_chirho = String::new();
    for record_chirho in records_chirho {
        text_chirho.push_str(&serde_json::to_string(record_chirho).unwrap());
        text_chirho.push('\n');
    }
    std::fs::write(path_chirho, text_chirho).unwrap();
}

fn deploy_review_policy_fixture_app_chirho(
    root_chirho: &Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> HashChirho {
    let schema_chirho = cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_chirho = cas_chirho::add_chirho(root_chirho, b"review policy fixture wasm").unwrap();
    let node_chirho = NodeDefChirho {
        name_chirho: format!("{app_chirho}_node_chirho"),
        impl_wasm_chirho: wasm_chirho,
        entry_chirho: "review_policy_fixture_chirho".to_string(),
        inputs_chirho: vec![PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_chirho.clone(),
        }],
        outputs_chirho: vec![PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho,
        }],
        capabilities_chirho: Vec::new(),
        fuel_limit_chirho: 1,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let dag_hash_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(
        root_chirho,
        app_chirho,
        dag_hash_chirho.clone(),
        owner_chirho,
    )
    .unwrap();
    dag_hash_chirho
}

fn seed_review_policy_envelope_chirho(root_chirho: &Path, app_chirho: &str) -> (String, String) {
    let owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let other_owner_chirho = identity_chirho::register_identity_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_review_policy_fixture_app_chirho(root_chirho, app_chirho, &owner_chirho);
    review_chirho::set_review_policy_envelope_chirho(
        root_chirho,
        app_chirho,
        &owner_chirho,
        Vec::new(),
        17,
        Vec::new(),
    )
    .unwrap();
    (owner_chirho, other_owner_chirho)
}

#[test]
fn portable_export_covers_verified_review_policy_envelopes_chirho() {
    let root_chirho = tmp_root_chirho("export");
    let (owner_chirho, other_owner_chirho) =
        seed_review_policy_envelope_chirho(&root_chirho, "policyapp");

    let owner_export_chirho =
        data_rights_chirho::export_subject_portable_data_chirho(&root_chirho, &owner_chirho, false)
            .unwrap();
    let policy_exports_chirho = owner_export_chirho
        .records_chirho
        .iter()
        .filter(|record_chirho| record_chirho.source_chirho == "review.policy-envelopes-chirho")
        .collect::<Vec<_>>();
    assert_eq!(policy_exports_chirho.len(), 1);
    assert_eq!(
        policy_exports_chirho[0].matched_by_chirho,
        vec!["scope_chirho.owner_principal_chirho".to_string()]
    );
    assert_eq!(
        policy_exports_chirho[0]
            .retention_policy_chirho
            .category_chirho,
        retention_chirho::DataRetentionCategoryChirho::SecurityChangeAuditChirho
    );

    let other_export_chirho = data_rights_chirho::export_subject_portable_data_chirho(
        &root_chirho,
        &other_owner_chirho,
        false,
    )
    .unwrap();
    assert!(!other_export_chirho
        .records_chirho
        .iter()
        .any(|record_chirho| record_chirho.source_chirho == "review.policy-envelopes-chirho"));

    let mut envelopes_chirho =
        review_chirho::load_review_policy_envelope_records_chirho(&root_chirho).unwrap();
    envelopes_chirho[0].sig_chirho = invalid_signature_chirho();
    write_jsonl_records_chirho(
        &root_chirho.join("review-policy-envelopes-chirho.jsonl"),
        &envelopes_chirho,
    );
    let export_error_chirho = format!(
        "{:?}",
        data_rights_chirho::export_subject_portable_data_chirho(&root_chirho, &owner_chirho, false)
            .unwrap_err()
    );
    assert!(export_error_chirho.contains("verify review.policy-envelopes-chirho"));
    assert!(export_error_chirho.contains("review-policy envelope 0 signature invalid"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn compliance_sources_include_verified_review_policy_envelopes_chirho() {
    let root_chirho = tmp_root_chirho("compliance");
    let _owner_chirho = seed_review_policy_envelope_chirho(&root_chirho, "reviewpolicy");
    let receipt_chirho = compliance_evidence_chirho::generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator-review-policy-envelope-chirho",
    )
    .unwrap();
    let policy_source_chirho = receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == "reviews.policy-envelopes-chirho")
        .expect("review policy envelope source");
    assert_eq!(policy_source_chirho.status_chirho, "verified-chirho");
    assert_eq!(
        policy_source_chirho.verifier_chirho,
        "verify_review_policy_envelopes_chirho"
    );
    assert_eq!(policy_source_chirho.records_chirho, 1);

    let mut envelopes_chirho =
        review_chirho::load_review_policy_envelope_records_chirho(&root_chirho).unwrap();
    envelopes_chirho[0].sig_chirho = invalid_signature_chirho();
    write_jsonl_records_chirho(
        &root_chirho.join("review-policy-envelopes-chirho.jsonl"),
        &envelopes_chirho,
    );
    let tampered_receipt_chirho =
        compliance_evidence_chirho::generate_compliance_evidence_pack_chirho(
            &root_chirho,
            &[String::from("soc2")],
            0,
            now_ms_chirho() + 1,
            "operator-review-policy-envelope-chirho",
        )
        .unwrap();
    let tampered_source_chirho = tampered_receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == "reviews.policy-envelopes-chirho")
        .expect("tampered review policy envelope source");
    assert_eq!(tampered_source_chirho.status_chirho, "failed-chirho");
    assert!(tampered_source_chirho
        .error_chirho
        .as_deref()
        .unwrap_or_default()
        .contains("review-policy envelope 0 signature invalid"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}
