// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

fn tmp_root_chirho() -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-compliance-test-{nanos_chirho}-{n_chirho}"))
}

#[test]
fn evidence_pack_verifies_and_survives_valid_appends_chirho() {
    let root_chirho = tmp_root_chirho();
    legal_hold_chirho::place_legal_hold_chirho(
        &root_chirho,
        "hold/case-1",
        "subject/test-chirho",
        "case/ref-1",
        "reason/initial-chirho",
        "operator/test-chirho",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert_eq!(
        receipt_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_RECEIPT_SCHEMA_CHIRHO
    );
    assert_eq!(
        receipt_chirho.record_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_RECORD_SCHEMA_CHIRHO
    );
    assert_eq!(receipt_chirho.controls_chirho, 4);
    assert_eq!(receipt_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(receipt_chirho.manual_controls_chirho, 1);
    assert_eq!(receipt_chirho.failed_sources_chirho, 0);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 0);
    let record_log_chirho =
        std::fs::read_to_string(compliance_evidence_records_path_chirho(&root_chirho)).unwrap();
    assert!(record_log_chirho.contains(COMPLIANCE_EVIDENCE_RECORD_SCHEMA_CHIRHO));
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(
        verification_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_VERIFY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(verification_chirho.packs_chirho, 1);
    assert_eq!(verification_chirho.controls_chirho, 4);
    assert_eq!(verification_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(verification_chirho.manual_controls_chirho, 1);
    assert_eq!(verification_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 0);

    legal_hold_chirho::place_legal_hold_chirho(
        &root_chirho,
        "hold/case-2",
        "subject/test-chirho",
        "case/ref-2",
        "reason/later-chirho",
        "operator/test-chirho",
    )
    .unwrap();
    let verification_after_append_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_after_append_chirho.packs_chirho, 1);
    assert_eq!(verification_after_append_chirho.controls_chirho, 4);
    assert_eq!(
        verification_after_append_chirho.evidence_backed_controls_chirho,
        3
    );
    assert_eq!(verification_after_append_chirho.manual_controls_chirho, 1);
    assert_eq!(verification_after_append_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_after_append_chirho.coverage_gaps_chirho, 0);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn framework_normalization_uses_fixed_product_order_chirho() {
    let normalized_chirho = normalize_frameworks_chirho(&[
        "iso27018".to_string(),
        "soc2".to_string(),
        "iso27001".to_string(),
        "soc2-chirho".to_string(),
    ])
    .unwrap();
    assert_eq!(
        normalized_chirho,
        vec![
            FRAMEWORK_SOC2_CHIRHO.to_string(),
            FRAMEWORK_ISO27001_CHIRHO.to_string(),
            FRAMEWORK_ISO27018_CHIRHO.to_string(),
        ]
    );
}

#[test]
fn default_all_frameworks_generate_canonical_self_verifying_pack_chirho() {
    let root_chirho = tmp_root_chirho();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();

    let canonical_chirho = normalize_frameworks_chirho(&[]).unwrap();
    assert_eq!(
        receipt_chirho.record_chirho.frameworks_chirho,
        canonical_chirho
    );
    assert_eq!(
        receipt_chirho.pack_body_chirho.frameworks_chirho,
        receipt_chirho.record_chirho.frameworks_chirho
    );
    assert_eq!(receipt_chirho.failed_sources_chirho, 0);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 0);
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.packs_chirho, 1);
    assert_eq!(verification_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 0);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn historical_compliance_verify_survives_later_ledger_appends_chirho() {
    let root_chirho = tmp_root_chirho();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let verification_chirho = verify_compliance_evidence_chirho(&root_chirho, None).unwrap();
    assert_eq!(verification_chirho.records_chirho, 1);
    assert_eq!(verification_chirho.packs_chirho, 1);
    assert_eq!(verification_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 0);
    assert_eq!(verification_chirho.target_pack_chirho, None);
    let targeted_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(targeted_chirho.packs_chirho, 1);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn effect_membership_snapshot_survives_later_path_sorted_effect_chirho() {
    let root_chirho = tmp_root_chirho();
    crate::effect_chirho::run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("m-captured-effect-chirho".to_string()),
        crate::model_chirho::CapabilityChirho::ClockChirho,
        b"{}",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let pack_chirho =
        load_compliance_evidence_pack_chirho(&root_chirho, &receipt_chirho.pack_chirho).unwrap();
    let effect_source_chirho = pack_chirho
        .sources_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == "effects.records-chirho")
        .expect("effect source");
    assert_eq!(effect_source_chirho.records_chirho, 1);
    assert_eq!(
        effect_source_chirho.verified_chirho["effect_idem_keys_chirho"][0],
        "m-captured-effect-chirho"
    );

    crate::effect_chirho::run_effect_chirho(
        &root_chirho,
        0,
        HashChirho("a-later-effect-sorts-before-chirho".to_string()),
        crate::model_chirho::CapabilityChirho::ClockChirho,
        b"{}",
    )
    .unwrap();

    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.packs_chirho, 1);
    assert_eq!(verification_chirho.failed_sources_chirho, 0);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn legacy_effect_source_without_membership_ids_is_not_greenwashed_chirho() {
    let root_chirho = tmp_root_chirho();
    let legacy_source_chirho = ComplianceEvidenceSourceChirho {
        source_chirho: "effects.records-chirho".to_string(),
        verifier_chirho: "verify_effect_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: 1,
        prefix_digest_chirho: "legacy-digest-chirho".to_string(),
        verified_chirho: json!({ "effects_verified_chirho": true }),
        error_chirho: None,
        notes_chirho: Vec::new(),
    };
    let error_chirho =
        persistent_effect_source_still_valid_chirho(&root_chirho, &legacy_source_chirho)
            .unwrap_err();
    assert!(
        format!("{error_chirho:#}").contains("legacy snapshot lacks stable effect membership ids")
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn evidence_verify_reports_failed_source_count_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("privacy-leak-chirho.jsonl"),
        "{\"email_chirho\":\"person@example.com\"}\n",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert_eq!(
        receipt_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_RECEIPT_SCHEMA_CHIRHO
    );
    assert_eq!(receipt_chirho.controls_chirho, 4);
    assert_eq!(receipt_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(receipt_chirho.manual_controls_chirho, 1);
    assert_eq!(receipt_chirho.failed_sources_chirho, 1);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 1);
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(
        verification_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_VERIFY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(verification_chirho.packs_chirho, 1);
    assert_eq!(verification_chirho.controls_chirho, 4);
    assert_eq!(verification_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(verification_chirho.manual_controls_chirho, 1);
    assert_eq!(verification_chirho.failed_sources_chirho, 1);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 1);
    assert!(serde_json::to_string(&verification_chirho)
        .unwrap()
        .contains(COMPLIANCE_EVIDENCE_VERIFY_REPORT_SCHEMA_CHIRHO));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn privacy_scan_evidence_rejects_disappeared_captured_finding_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let leak_path_chirho = root_chirho.join("privacy-leak-chirho.jsonl");
    std::fs::write(
        &leak_path_chirho,
        "{\"email_chirho\":\"person@example.com\"}\n",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert!(receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .any(|source_chirho| {
            source_chirho.source_chirho == "privacy.scan-findings-chirho"
                && source_chirho.status_chirho == "failed-chirho"
                && source_chirho.records_chirho == 1
        }));

    std::fs::write(&leak_path_chirho, "{\"ssn_chirho\":\"123-45-6789\"}\n").unwrap();
    let error_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho))
            .unwrap_err()
            .to_string();
    assert!(error_chirho
        .contains("compliance source 'privacy.scan-findings-chirho' finding no longer present"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn residency_violations_are_failed_compliance_source_chirho() {
    let platform_root_chirho = tmp_root_chirho();
    let root_chirho =
        crate::tenant_chirho::prepare_tenant_root_chirho(&platform_root_chirho, "tenant-a-chirho")
            .unwrap();
    data_residency_chirho::set_data_residency_policy_chirho(
        &root_chirho,
        &[String::from("eu-fsn1")],
        &[String::from("eu-fsn1")],
        "operator/residency-chirho",
        true,
    )
    .unwrap();
    data_residency_chirho::attest_data_residency_chirho(
        &root_chirho,
        "eu-fsn1",
        "eu-fsn1",
        "eu-fsn1",
        "config/host-region-chirho",
        "operator/residency-chirho",
    )
    .unwrap();
    data_residency_chirho::attest_data_residency_chirho(
        &root_chirho,
        "us-east-1",
        "us-east-1",
        "eu-fsn1",
        "config/host-region-chirho",
        "operator/residency-chirho",
    )
    .unwrap();

    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("iso27001")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert!(receipt_chirho.failed_sources_chirho >= 1);
    let residency_source_chirho = receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == "data-residency.attestations-chirho")
        .unwrap();
    assert_eq!(residency_source_chirho.status_chirho, "failed-chirho");
    assert_eq!(residency_source_chirho.records_chirho, 2);
    assert_eq!(
        residency_source_chirho.verified_chirho["schema_chirho"],
        data_residency_chirho::DATA_RESIDENCY_VERIFY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(
        residency_source_chirho.verified_chirho["noncompliant_attestations_chirho"],
        1
    );
    assert!(residency_source_chirho
        .error_chirho
        .as_deref()
        .unwrap()
        .contains("noncompliant-attestations:1"));
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(
        verification_chirho.failed_sources_chirho,
        receipt_chirho.failed_sources_chirho
    );

    let _ = std::fs::remove_dir_all(platform_root_chirho);
}

#[test]
fn legacy_evidence_record_without_schema_still_verifies_chirho() {
    let root_chirho = tmp_root_chirho();
    legal_hold_chirho::place_legal_hold_chirho(
        &root_chirho,
        "hold/case-legacy",
        "subject/test-chirho",
        "case/ref-legacy",
        "reason/legacy-chirho",
        "operator/test-chirho",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let mut record_chirho = receipt_chirho.record_chirho.clone();
    record_chirho.schema_chirho.clear();
    record_chirho.sig_chirho.clear();
    let message_chirho = compliance_evidence_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&root_chirho, &message_chirho).unwrap();
    let path_chirho = compliance_evidence_records_path_chirho(&root_chirho);
    std::fs::write(
        &path_chirho,
        format!("{}\n", serde_json::to_string(&record_chirho).unwrap()),
    )
    .unwrap();
    assert!(!std::fs::read_to_string(&path_chirho)
        .unwrap()
        .contains("schema_chirho"));

    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.packs_chirho, 1);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn unsupported_record_schema_is_rejected_chirho() {
    let root_chirho = tmp_root_chirho();
    legal_hold_chirho::place_legal_hold_chirho(
        &root_chirho,
        "hold/case-schema",
        "subject/test-chirho",
        "case/ref-schema",
        "reason/schema-chirho",
        "operator/test-chirho",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let mut record_chirho = receipt_chirho.record_chirho.clone();
    record_chirho.schema_chirho = "unknown-compliance-record-v9-chirho".to_string();
    record_chirho.sig_chirho.clear();
    let message_chirho = compliance_evidence_record_message_chirho(&record_chirho).unwrap();
    record_chirho.sig_chirho =
        signer_chirho::sign_message_chirho(&root_chirho, &message_chirho).unwrap();
    std::fs::write(
        compliance_evidence_records_path_chirho(&root_chirho),
        format!("{}\n", serde_json::to_string(&record_chirho).unwrap()),
    )
    .unwrap();

    let error_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho))
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("unsupported compliance evidence record schema"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn evidence_record_tamper_is_rejected_chirho() {
    let root_chirho = tmp_root_chirho();
    privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/test-chirho",
        ),
        "user/test-chirho",
        b"private payload",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("iso27001")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let path_chirho = compliance_evidence_records_path_chirho(&root_chirho);
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replace("operator/test-chirho", "operator/tampered-chirho"),
    )
    .unwrap();
    let error_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho))
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("signature invalid")
            || error_chirho.contains("generated_by mismatch")
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn source_log_tamper_is_rejected_chirho() {
    let root_chirho = tmp_root_chirho();
    privacy_chirho::store_private_blob_chirho(
        &root_chirho,
        &crate::privacy_chirho::PrivateBlobAttributionChirho::for_test_subject_chirho(
            "user/test-chirho",
        ),
        "user/test-chirho",
        b"private payload",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("iso27701")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    let path_chirho = root_chirho.join("privacy-blob-records-chirho.jsonl");
    let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
    std::fs::write(
        &path_chirho,
        text_chirho.replace("user/test-chirho", "user/tampered-chirho"),
    )
    .unwrap();
    let error_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho))
            .unwrap_err()
            .to_string();
    assert!(
        error_chirho.contains("status changed") || error_chirho.contains("prefix digest mismatch")
    );

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn coverage_gaps_report_unmapped_jsonl_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("unmapped-log-chirho.jsonl"),
        "{\"safe_ref_chirho\":\"abc123\"}\n",
    )
    .unwrap();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert!(receipt_chirho
        .pack_body_chirho
        .coverage_gaps_chirho
        .iter()
        .any(|gap_chirho| gap_chirho.path_chirho == "unmapped-log-chirho.jsonl"));
    assert_eq!(
        receipt_chirho.schema_chirho,
        COMPLIANCE_EVIDENCE_RECEIPT_SCHEMA_CHIRHO
    );
    assert_eq!(receipt_chirho.controls_chirho, 4);
    assert_eq!(receipt_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(receipt_chirho.manual_controls_chirho, 1);
    assert_eq!(receipt_chirho.failed_sources_chirho, 0);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 1);
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.controls_chirho, 4);
    assert_eq!(verification_chirho.evidence_backed_controls_chirho, 3);
    assert_eq!(verification_chirho.manual_controls_chirho, 1);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 1);

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn unsupported_control_status_is_rejected_chirho() {
    let control_chirho = ComplianceControlEvidenceChirho {
        framework_chirho: FRAMEWORK_SOC2_CHIRHO.to_string(),
        control_chirho: "cc-test-chirho".to_string(),
        title_chirho: "Test control".to_string(),
        assertion_chirho: "Test assertion".to_string(),
        source_refs_chirho: Vec::new(),
        status_chirho: "unknown-status-chirho".to_string(),
        notes_chirho: Vec::new(),
    };

    let error_chirho = control_counts_chirho(&[control_chirho])
        .unwrap_err()
        .to_string();
    assert!(error_chirho.contains("unsupported compliance control status"));
    assert!(error_chirho.contains("cc-test-chirho"));
}

#[test]
fn claimed_jsonl_files_map_to_folded_sources_chirho() {
    let root_chirho = tmp_root_chirho();
    let snapshots_chirho = collect_source_snapshots_chirho(&root_chirho).unwrap();
    let sources_chirho: BTreeSet<String> = snapshots_chirho
        .into_iter()
        .map(|snapshot_chirho| snapshot_chirho.source_chirho)
        .collect();
    for (file_chirho, source_chirho) in claimed_source_files_chirho() {
        assert!(
            sources_chirho.contains(source_chirho),
            "{file_chirho} suppresses coverage gaps but does not map to folded source {source_chirho}"
        );
    }

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn claimed_jsonl_files_cover_production_root_logs_chirho() {
    let claimed_chirho = claimed_jsonl_files_chirho();
    let claimed_dynamic_chirho =
        BTreeSet::from([crate::source_scan_chirho::REFS_REFLOG_LOGICAL_SURFACE_CHIRHO]);
    let production_logs_chirho =
        crate::source_scan_chirho::production_jsonl_logical_surface_inventory_chirho();
    let missing_chirho = production_logs_chirho.coverage_gaps_chirho(
        |file_chirho| claimed_chirho.contains(file_chirho),
        |logical_name_chirho| claimed_dynamic_chirho.contains(logical_name_chirho),
    );
    let unexplained_chirho = crate::privacy_chirho::unexplained_literal_root_gaps_chirho(
        &missing_chirho.literal_root_files_chirho,
    )
    .unwrap_or_else(|stale_chirho| panic!("{stale_chirho}"));
    assert!(
        unexplained_chirho.is_empty(),
        "literal production JSONL logs are not claimed by compliance evidence: {unexplained_chirho:?}"
    );
    assert!(
        missing_chirho
            .dynamic_per_branch_populations_chirho
            .is_empty(),
        "dynamic production JSONL populations are not claimed by compliance evidence: {:?}",
        missing_chirho.dynamic_per_branch_populations_chirho
    );
}

#[test]
fn archived_product_logs_remain_visible_as_historical_coverage_gaps_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    let historical_files_chirho = historical_untyped_jsonl_files_chirho();
    assert_eq!(historical_files_chirho.len(), 12);
    for file_chirho in &historical_files_chirho {
        std::fs::write(root_chirho.join(file_chirho), b"{}\n").unwrap();
    }

    let gaps_chirho = coverage_gaps_chirho(&root_chirho).unwrap();
    assert_eq!(gaps_chirho.len(), historical_files_chirho.len());
    assert!(gaps_chirho.iter().all(|gap_chirho| {
        historical_files_chirho.contains(gap_chirho.path_chirho.as_str())
            && gap_chirho.reason_chirho
                == "historical-product-jsonl-without-active-typed-collector-chirho"
    }));
    assert!(gaps_chirho
        .iter()
        .any(|gap_chirho| gap_chirho.path_chirho == "stripe-payout-observations-chirho.jsonl"));
    assert!(gaps_chirho
        .iter()
        .any(|gap_chirho| gap_chirho.path_chirho == "statements-chirho.jsonl"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

fn captured_accounting_source_chirho() -> ComplianceEvidenceSourceChirho {
    let snapshot_chirho = AccountingControlSnapshotChirho {
        period_start_ms_chirho: 0,
        period_end_ms_chirho: 100,
        ledger_verified_count_chirho: 2,
        ledger_source_digest_chirho: "11".repeat(32),
        ledger_cutoff_chirho: 2,
        period_entry_count_chirho: 2,
        period_line_count_chirho: 4,
        balanced_by_asset_chirho: [("cash-chirho".to_string(), 0)].into_iter().collect(),
    };
    let verified_chirho = serde_json::to_value(snapshot_chirho).unwrap();
    let records_chirho = vec![verified_chirho.clone()];
    ComplianceEvidenceSourceChirho {
        source_chirho: "accounting.period-close-chirho".to_string(),
        verifier_chirho: "build_accounting_export_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: records_chirho.len(),
        prefix_digest_chirho: digest_value_chirho(&serde_json::to_value(records_chirho).unwrap())
            .unwrap(),
        verified_chirho,
        error_chirho: None,
        notes_chirho: vec!["captured before CF6 wave-1 removal".to_string()],
    }
}

#[test]
fn fresh_compliance_pack_omits_archived_money_sources_chirho() {
    let root_chirho = tmp_root_chirho();
    let receipt_chirho = generate_compliance_evidence_pack_chirho(
        &root_chirho,
        &[],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap();
    assert!(receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .all(|source_chirho| source_chirho.source_chirho != "accounting.period-close-chirho"));
    assert!(receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .all(|source_chirho| source_chirho.source_chirho != ARCHIVED_EXTERNAL_USAGE_SOURCE_CHIRHO));
    assert!(
        receipt_chirho
            .pack_body_chirho
            .sources_chirho
            .iter()
            .all(|source_chirho| source_chirho.source_chirho
                != ARCHIVED_EXTERNAL_PRICES_SOURCE_CHIRHO)
    );
    for archived_source_chirho in [
        ARCHIVED_COUPON_ISSUES_SOURCE_CHIRHO,
        ARCHIVED_COUPON_REDEMPTIONS_SOURCE_CHIRHO,
        ARCHIVED_STRIPE_IDENTITY_SOURCE_CHIRHO,
    ] {
        assert!(receipt_chirho
            .pack_body_chirho
            .sources_chirho
            .iter()
            .all(|source_chirho| source_chirho.source_chirho != archived_source_chirho));
    }
    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 0);
    assert!(verification_chirho
        .accounting_prefix_verdicts_chirho
        .is_empty());
    assert!(verification_chirho
        .archived_source_verdicts_chirho
        .is_empty());
    let _ = std::fs::remove_dir_all(root_chirho);
}

fn captured_archived_source_chirho(source_chirho: &str) -> ComplianceEvidenceSourceChirho {
    let verified_chirho = serde_json::json!({
        "captured_external_source_chirho": source_chirho,
    });
    let records_chirho = vec![verified_chirho.clone()];
    ComplianceEvidenceSourceChirho {
        source_chirho: source_chirho.to_string(),
        verifier_chirho: "archived_money_source_verifier_chirho".to_string(),
        status_chirho: "verified-chirho".to_string(),
        records_chirho: records_chirho.len(),
        prefix_digest_chirho: digest_value_chirho(&serde_json::to_value(records_chirho).unwrap())
            .unwrap(),
        verified_chirho,
        error_chirho: None,
        notes_chirho: vec!["captured before CF6 wave-1 removal".to_string()],
    }
}

#[test]
fn captured_archived_money_sources_return_typed_archive_verdicts_chirho() {
    let root_chirho = tmp_root_chirho();
    let sources_chirho = vec![
        captured_archived_source_chirho(ARCHIVED_EXTERNAL_USAGE_SOURCE_CHIRHO),
        captured_archived_source_chirho(ARCHIVED_EXTERNAL_PRICES_SOURCE_CHIRHO),
        captured_archived_source_chirho(ARCHIVED_COUPON_ISSUES_SOURCE_CHIRHO),
        captured_archived_source_chirho(ARCHIVED_COUPON_REDEMPTIONS_SOURCE_CHIRHO),
        captured_archived_source_chirho(ARCHIVED_STRIPE_IDENTITY_SOURCE_CHIRHO),
    ];
    let frameworks_chirho = all_frameworks_chirho();
    let controls_chirho = control_evidence_chirho(&frameworks_chirho);
    let pack_chirho = ComplianceEvidencePackChirho {
        schema_chirho: COMPLIANCE_EVIDENCE_SCHEMA_CHIRHO.to_string(),
        generated_ms_chirho: 1,
        generated_by_chirho: "operator/test-chirho".to_string(),
        period_start_ms_chirho: 0,
        period_end_ms_chirho: 1,
        frameworks_chirho,
        controls_chirho,
        source_digest_chirho: digest_value_chirho(&serde_json::to_value(&sources_chirho).unwrap())
            .unwrap(),
        sources_chirho,
        coverage_gaps_chirho: Vec::new(),
        scope_notes_chirho: Vec::new(),
    };
    let pack_hash_chirho = store_chirho::put_object_chirho(&root_chirho, &pack_chirho).unwrap();
    append_compliance_evidence_record_chirho(&root_chirho, &pack_hash_chirho, &pack_chirho)
        .unwrap();

    let verification_chirho =
        verify_compliance_evidence_chirho(&root_chirho, Some(&pack_hash_chirho)).unwrap();
    assert_eq!(
        verification_chirho.archived_source_verdicts_chirho,
        vec![
            ArchivedComplianceSourceVerdictChirho {
                source_chirho: ARCHIVED_EXTERNAL_USAGE_SOURCE_CHIRHO.to_string(),
                status_chirho: "source-archived-chirho".to_string(),
                verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
                recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
            },
            ArchivedComplianceSourceVerdictChirho {
                source_chirho: ARCHIVED_EXTERNAL_PRICES_SOURCE_CHIRHO.to_string(),
                status_chirho: "source-archived-chirho".to_string(),
                verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
                recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
            },
            ArchivedComplianceSourceVerdictChirho {
                source_chirho: ARCHIVED_COUPON_ISSUES_SOURCE_CHIRHO.to_string(),
                status_chirho: "source-archived-chirho".to_string(),
                verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
                recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
            },
            ArchivedComplianceSourceVerdictChirho {
                source_chirho: ARCHIVED_COUPON_REDEMPTIONS_SOURCE_CHIRHO.to_string(),
                status_chirho: "source-archived-chirho".to_string(),
                verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
                recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
            },
            ArchivedComplianceSourceVerdictChirho {
                source_chirho: ARCHIVED_STRIPE_IDENTITY_SOURCE_CHIRHO.to_string(),
                status_chirho: "source-archived-chirho".to_string(),
                verifier_disposition_chirho: "recover-verifier-from-tag-chirho".to_string(),
                recovery_tag_chirho: CF6_WAVE1_MONEY_SPINE_ARCHIVE_TAG_CHIRHO.to_string(),
            },
        ]
    );

    let snapshots_chirho = collect_source_snapshots_chirho(&root_chirho).unwrap();
    let mut unknown_pack_chirho = pack_chirho;
    unknown_pack_chirho.sources_chirho = vec![captured_archived_source_chirho(
        "external.unknown-source-chirho",
    )];
    let error_chirho =
        verify_pack_source_prefixes_chirho(&root_chirho, &unknown_pack_chirho, &snapshots_chirho)
            .unwrap_err()
            .to_string();
    assert!(error_chirho.contains("missing compliance source 'external.unknown-source-chirho'"));

    let _ = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn captured_accounting_row_is_artifact_only_without_snapshot_or_ledger_chirho() {
    let root_chirho = tmp_root_chirho();
    assert!(!root_chirho.join("ledger-chirho.jsonl").exists());
    let accounting_row_chirho = captured_accounting_source_chirho();
    let snapshots_chirho = collect_source_snapshots_chirho(&root_chirho).unwrap();
    assert!(snapshots_chirho
        .iter()
        .all(|snapshot_chirho| snapshot_chirho.source_chirho != "accounting.period-close-chirho"));
    let pack_chirho = ComplianceEvidencePackChirho {
        schema_chirho: COMPLIANCE_EVIDENCE_SCHEMA_CHIRHO.to_string(),
        generated_ms_chirho: 0,
        generated_by_chirho: "operator/test-chirho".to_string(),
        period_start_ms_chirho: 0,
        period_end_ms_chirho: 100,
        frameworks_chirho: Vec::new(),
        controls_chirho: Vec::new(),
        sources_chirho: vec![accounting_row_chirho.clone()],
        coverage_gaps_chirho: Vec::new(),
        source_digest_chirho: "22".repeat(32),
        scope_notes_chirho: Vec::new(),
    };
    let verdicts_chirho =
        verify_pack_source_prefixes_chirho(&root_chirho, &pack_chirho, &snapshots_chirho).unwrap();
    assert_eq!(
        verdicts_chirho.accounting_prefix_verdicts_chirho,
        vec!["artifact-only-ledger-recoverable-at-tag-chirho".to_string()]
    );
    assert!(verdicts_chirho.archived_source_verdicts_chirho.is_empty());

    let mut tampered_chirho = accounting_row_chirho.clone();
    tampered_chirho.prefix_digest_chirho = "00".repeat(32);
    let digest_error_chirho =
        accounting_period_close_source_still_valid_chirho(None, &tampered_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        digest_error_chirho.contains("captured digest mismatch"),
        "unexpected error: {digest_error_chirho}"
    );

    let mut flipped_chirho = accounting_row_chirho;
    flipped_chirho.status_chirho = "failed-chirho".to_string();
    let status_error_chirho =
        accounting_period_close_source_still_valid_chirho(None, &flipped_chirho)
            .unwrap_err()
            .to_string();
    assert!(
        status_error_chirho.contains("status mismatch"),
        "unexpected error: {status_error_chirho}"
    );
    assert!(!root_chirho.join("ledger-chirho.jsonl").exists());
    let _ = std::fs::remove_dir_all(root_chirho);
}
