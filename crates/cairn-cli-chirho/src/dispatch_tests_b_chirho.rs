// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//! Dispatch helper tests, part B.
use crate::display_cli_chirho::{
    realtime_epilogues_list_text_chirho, realtime_events_list_text_chirho,
    realtime_sessions_list_text_chirho,
};
use crate::report_cli_chirho::{
    enforce_compliance_evidence_fail_on_coverage_gaps_chirho,
    enforce_compliance_evidence_fail_on_failed_sources_chirho,
    enforce_compliance_evidence_fail_on_manual_controls_chirho,
    enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho,
    enforce_compliance_evidence_verify_fail_on_failed_sources_chirho,
    enforce_compliance_evidence_verify_fail_on_manual_controls_chirho,
    enforce_data_residency_fail_on_violations_chirho, enforce_privacy_scan_fail_on_findings_chirho,
    enforce_privacy_verify_fail_on_empty_evidence_chirho, privacy_verify_cli_report_chirho,
    volatile_effect_list_cli_report_chirho, volatile_effect_list_text_chirho,
    PrivacyVerifyCliReportChirho, PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO,
    VOLATILE_EFFECT_LIST_REPORT_SCHEMA_CHIRHO,
};
use cairn_chirho::model_chirho::{CapabilityChirho, HashChirho};
use cairn_chirho::{
    compliance_evidence_chirho, data_residency_chirho, effect_chirho, legal_hold_chirho,
    privacy_backup_chirho, privacy_chirho, realtime_legacy_evidence_chirho,
};
#[test]
fn privacy_scan_fail_on_findings_guard_chirho() {
    let mut report_chirho = privacy_chirho::PrivacyScanReportChirho::default();
    assert!(enforce_privacy_scan_fail_on_findings_chirho(&report_chirho, true).is_ok());
    report_chirho
        .findings_chirho
        .push(privacy_chirho::PrivacyScanFindingChirho {
            source_chirho: "leak-chirho.jsonl".to_string(),
            line_chirho: Some(1),
            path_chirho: "$.email_chirho".to_string(),
            kind_chirho: "email-like-chirho".to_string(),
            detail_chirho: "string resembles an email address; raw value is intentionally omitted"
                .to_string(),
        });
    assert!(enforce_privacy_scan_fail_on_findings_chirho(&report_chirho, false).is_ok());
    assert_eq!(
        enforce_privacy_scan_fail_on_findings_chirho(&report_chirho, true)
            .unwrap_err()
            .to_string(),
        "privacy-scan found 1 finding(s)"
    );
}
#[test]
fn privacy_verify_json_report_is_schema_tagged_chirho() {
    let report_chirho = privacy_chirho::PrivacyVerifyReportChirho {
        blob_records_chirho: 2,
        erasure_records_chirho: 1,
        access_records_chirho: 3,
    };
    let legal_hold_report_chirho = legal_hold_chirho::LegalHoldVerifyReportChirho {
        records_chirho: 4,
        active_holds_chirho: 1,
    };
    let backup_report_chirho = privacy_backup_chirho::PrivacyBackupVerifyReportChirho {
        backup_key_policy_records_chirho: 5,
        replica_targets_chirho: 2,
        erasure_propagation_records_chirho: 6,
    };
    let value_chirho = serde_json::to_value(privacy_verify_cli_report_chirho(
        &report_chirho,
        &legal_hold_report_chirho,
        &backup_report_chirho,
        7,
        8,
    ))
    .unwrap();
    assert_eq!(
        value_chirho["schema_chirho"],
        PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(value_chirho["blob_records_chirho"], 2);
    assert_eq!(value_chirho["active_legal_holds_chirho"], 1);
    assert_eq!(value_chirho["backup_key_policy_records_chirho"], 5);
    assert_eq!(value_chirho["privacy_retention_records_chirho"], 7);
    assert_eq!(value_chirho["export_evidence_records_chirho"], 8);
}
#[test]
fn privacy_verify_fail_on_empty_evidence_guard_chirho() {
    let empty_report_chirho = PrivacyVerifyCliReportChirho {
        schema_chirho: PRIVACY_VERIFY_REPORT_SCHEMA_CHIRHO,
        blob_records_chirho: 0,
        erasure_records_chirho: 0,
        access_records_chirho: 0,
        legal_hold_records_chirho: 0,
        active_legal_holds_chirho: 0,
        backup_key_policy_records_chirho: 0,
        replica_targets_chirho: 0,
        erasure_propagation_records_chirho: 0,
        privacy_retention_records_chirho: 0,
        export_evidence_records_chirho: 0,
    };
    assert!(
        enforce_privacy_verify_fail_on_empty_evidence_chirho(&empty_report_chirho, false).is_ok()
    );
    let error_chirho =
        enforce_privacy_verify_fail_on_empty_evidence_chirho(&empty_report_chirho, true)
            .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "privacy-verify found no evidence record(s)"
    );
    let nonempty_report_chirho = PrivacyVerifyCliReportChirho {
        blob_records_chirho: 1,
        ..empty_report_chirho
    };
    assert!(
        enforce_privacy_verify_fail_on_empty_evidence_chirho(&nonempty_report_chirho, true).is_ok()
    );
}
#[test]
fn data_residency_fail_on_violations_guard_chirho() {
    let clean_report_chirho = data_residency_chirho::DataResidencyVerifyReportChirho {
        schema_chirho: data_residency_chirho::DATA_RESIDENCY_VERIFY_REPORT_SCHEMA_CHIRHO
            .to_string(),
        tenant_chirho: cairn_chirho::tenant_chirho::TenantIdChirho::TenantChirho(
            "tenant-demo-chirho".to_string(),
        ),
        policy_records_chirho: 1,
        attestation_records_chirho: 1,
        noncompliant_attestations_chirho: 0,
        current_policy_chirho: None,
    };
    assert!(enforce_data_residency_fail_on_violations_chirho(&clean_report_chirho, true).is_ok());
    let dirty_report_chirho = data_residency_chirho::DataResidencyVerifyReportChirho {
        noncompliant_attestations_chirho: 2,
        ..clean_report_chirho
    };
    assert!(enforce_data_residency_fail_on_violations_chirho(&dirty_report_chirho, false).is_ok());
    assert_eq!(
        enforce_data_residency_fail_on_violations_chirho(&dirty_report_chirho, true)
            .unwrap_err()
            .to_string(),
        "data-residency-verify found 2 noncompliant attestation(s)"
    );
}
#[test]
fn compliance_evidence_fail_on_failed_sources_guard_chirho() {
    let clean_pack_chirho =
        compliance_evidence_pack_with_source_statuses_and_gaps_chirho(&["verified-chirho"], 0);
    assert!(
        enforce_compliance_evidence_fail_on_failed_sources_chirho(&clean_pack_chirho, true).is_ok()
    );
    let dirty_pack_chirho = compliance_evidence_pack_with_source_statuses_and_gaps_chirho(
        &["verified-chirho", "failed-chirho", "failed-chirho"],
        0,
    );
    assert!(
        enforce_compliance_evidence_fail_on_failed_sources_chirho(&dirty_pack_chirho, false)
            .is_ok()
    );
    assert_eq!(
        enforce_compliance_evidence_fail_on_failed_sources_chirho(&dirty_pack_chirho, true)
            .unwrap_err()
            .to_string(),
        "compliance-evidence found 2 failed source(s)"
    );
}
#[test]
fn compliance_evidence_fail_on_coverage_gaps_guard_chirho() {
    let clean_pack_chirho =
        compliance_evidence_pack_with_source_statuses_and_gaps_chirho(&["verified-chirho"], 0);
    assert!(
        enforce_compliance_evidence_fail_on_coverage_gaps_chirho(&clean_pack_chirho, true).is_ok()
    );
    let dirty_pack_chirho =
        compliance_evidence_pack_with_source_statuses_and_gaps_chirho(&["verified-chirho"], 2);
    assert!(
        enforce_compliance_evidence_fail_on_coverage_gaps_chirho(&dirty_pack_chirho, false).is_ok()
    );
    assert_eq!(
        enforce_compliance_evidence_fail_on_coverage_gaps_chirho(&dirty_pack_chirho, true)
            .unwrap_err()
            .to_string(),
        "compliance-evidence found 2 coverage gap(s)"
    );
}
#[test]
fn compliance_evidence_verify_fail_on_failed_sources_guard_chirho() {
    let clean_report_chirho = compliance_evidence_verification_with_counts_chirho(0, 0, 0);
    assert!(
        enforce_compliance_evidence_verify_fail_on_failed_sources_chirho(
            &clean_report_chirho,
            true
        )
        .is_ok()
    );
    let dirty_report_chirho = compliance_evidence_verification_with_counts_chirho(3, 0, 0);
    assert!(
        enforce_compliance_evidence_verify_fail_on_failed_sources_chirho(
            &dirty_report_chirho,
            false
        )
        .is_ok()
    );
    let error_chirho = enforce_compliance_evidence_verify_fail_on_failed_sources_chirho(
        &dirty_report_chirho,
        true,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "compliance-evidence verification found 3 failed source(s)"
    );
}
#[test]
fn compliance_evidence_verify_fail_on_coverage_gaps_guard_chirho() {
    let clean_report_chirho = compliance_evidence_verification_with_counts_chirho(0, 0, 0);
    assert!(
        enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho(&clean_report_chirho, true)
            .is_ok()
    );
    let dirty_report_chirho = compliance_evidence_verification_with_counts_chirho(0, 4, 0);
    assert!(
        enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho(
            &dirty_report_chirho,
            false
        )
        .is_ok()
    );
    let error_chirho =
        enforce_compliance_evidence_verify_fail_on_coverage_gaps_chirho(&dirty_report_chirho, true)
            .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "compliance-evidence verification found 4 coverage gap(s)"
    );
}
#[test]
fn compliance_evidence_fail_on_manual_controls_guard_chirho() {
    let clean_pack_chirho =
        compliance_evidence_pack_with_source_statuses_gaps_and_manual_controls_chirho(
            &["verified-chirho"],
            0,
            0,
        );
    assert!(
        enforce_compliance_evidence_fail_on_manual_controls_chirho(&clean_pack_chirho, true)
            .is_ok()
    );
    let dirty_pack_chirho =
        compliance_evidence_pack_with_source_statuses_gaps_and_manual_controls_chirho(
            &["verified-chirho"],
            0,
            2,
        );
    assert!(
        enforce_compliance_evidence_fail_on_manual_controls_chirho(&dirty_pack_chirho, false)
            .is_ok()
    );
    let error_chirho =
        enforce_compliance_evidence_fail_on_manual_controls_chirho(&dirty_pack_chirho, true)
            .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "compliance-evidence found 2 manual-required control(s)"
    );
}
#[test]
fn compliance_evidence_verify_fail_on_manual_controls_guard_chirho() {
    let clean_report_chirho = compliance_evidence_verification_with_counts_chirho(0, 0, 0);
    assert!(
        enforce_compliance_evidence_verify_fail_on_manual_controls_chirho(
            &clean_report_chirho,
            true
        )
        .is_ok()
    );
    let dirty_report_chirho = compliance_evidence_verification_with_counts_chirho(0, 0, 5);
    assert!(
        enforce_compliance_evidence_verify_fail_on_manual_controls_chirho(
            &dirty_report_chirho,
            false
        )
        .is_ok()
    );
    let error_chirho = enforce_compliance_evidence_verify_fail_on_manual_controls_chirho(
        &dirty_report_chirho,
        true,
    )
    .unwrap_err();
    assert_eq!(
        error_chirho.to_string(),
        "compliance-evidence verification found 5 manual-required control(s)"
    );
}
fn compliance_evidence_verification_with_counts_chirho(
    failed_sources_chirho: usize,
    coverage_gaps_chirho: usize,
    manual_controls_chirho: usize,
) -> compliance_evidence_chirho::ComplianceEvidenceVerificationChirho {
    compliance_evidence_chirho::ComplianceEvidenceVerificationChirho {
        schema_chirho: "compliance-evidence-verify-report-v1-chirho".to_string(),
        records_chirho: 1,
        packs_chirho: 1,
        controls_chirho: 3 + manual_controls_chirho,
        evidence_backed_controls_chirho: 3,
        manual_controls_chirho,
        source_prefixes_chirho: 4,
        failed_sources_chirho,
        coverage_gaps_chirho,
        accounting_prefix_verdicts_chirho: Vec::new(),
        archived_source_verdicts_chirho: Vec::new(),
        target_pack_chirho: None,
    }
}
fn compliance_evidence_pack_with_source_statuses_and_gaps_chirho(
    statuses_chirho: &[&str],
    coverage_gaps_chirho: usize,
) -> compliance_evidence_chirho::ComplianceEvidencePackChirho {
    compliance_evidence_pack_with_source_statuses_gaps_and_manual_controls_chirho(
        statuses_chirho,
        coverage_gaps_chirho,
        0,
    )
}
fn compliance_evidence_pack_with_source_statuses_gaps_and_manual_controls_chirho(
    statuses_chirho: &[&str],
    coverage_gaps_chirho: usize,
    manual_controls_chirho: usize,
) -> compliance_evidence_chirho::ComplianceEvidencePackChirho {
    compliance_evidence_chirho::ComplianceEvidencePackChirho {
        schema_chirho: "compliance-evidence-pack/v1-chirho".to_string(),
        generated_ms_chirho: 0,
        generated_by_chirho: "operator/test-chirho".to_string(),
        period_start_ms_chirho: 0,
        period_end_ms_chirho: 1,
        frameworks_chirho: vec!["soc2-chirho".to_string()],
        controls_chirho: (0..manual_controls_chirho)
            .map(
                |index_chirho| compliance_evidence_chirho::ComplianceControlEvidenceChirho {
                    framework_chirho: "soc2-chirho".to_string(),
                    control_chirho: format!("manual-{index_chirho}-chirho"),
                    title_chirho: format!("Manual control {index_chirho}"),
                    assertion_chirho: "manual-required-chirho".to_string(),
                    source_refs_chirho: Vec::new(),
                    status_chirho: "manual-required-chirho".to_string(),
                    notes_chirho: Vec::new(),
                },
            )
            .collect(),
        sources_chirho: statuses_chirho
            .iter()
            .enumerate()
            .map(|(index_chirho, status_chirho)| {
                let failed_chirho = *status_chirho == "failed-chirho";
                compliance_evidence_chirho::ComplianceEvidenceSourceChirho {
                    source_chirho: format!("source-{index_chirho}-chirho"),
                    verifier_chirho: "verify_test_source_chirho".to_string(),
                    status_chirho: (*status_chirho).to_string(),
                    records_chirho: 0,
                    prefix_digest_chirho: format!("digest-{index_chirho}-chirho"),
                    verified_chirho: serde_json::json!({
                        "failed_chirho": failed_chirho
                    }),
                    error_chirho: failed_chirho.then(|| "source failed".to_string()),
                    notes_chirho: Vec::new(),
                }
            })
            .collect(),
        coverage_gaps_chirho: (0..coverage_gaps_chirho)
            .map(
                |index_chirho| compliance_evidence_chirho::ComplianceCoverageGapChirho {
                    path_chirho: format!("gap-{index_chirho}-chirho.jsonl"),
                    reason_chirho: "unmapped-production-jsonl-chirho".to_string(),
                },
            )
            .collect(),
        source_digest_chirho: "digest-chirho".to_string(),
        scope_notes_chirho: Vec::new(),
    }
}
#[test]
fn volatile_effect_list_json_report_is_schema_tagged_chirho() {
    let request_chirho =
        HashChirho("1111111111111111111111111111111111111111111111111111111111111111".into());
    let response_chirho =
        HashChirho("2222222222222222222222222222222222222222222222222222222222222222".into());
    let idem_chirho =
        HashChirho("3333333333333333333333333333333333333333333333333333333333333333".into());
    let record_chirho = effect_chirho::VolatileEffectDisplayRecordChirho {
        line_chirho: 8,
        record_chirho: Some(effect_chirho::VolatileEffectRecordChirho {
            schema_chirho: effect_chirho::VOLATILE_EFFECT_RECORD_SCHEMA_CHIRHO.to_string(),
            seq_chirho: 7,
            effect_chirho: cairn_chirho::model_chirho::EffectChirho {
                seq_chirho: 5,
                idem_key_chirho: idem_chirho.clone(),
                capability_chirho: CapabilityChirho::QueryChirho {
                    prefix_chirho: "contacts-chirho".to_string(),
                    caller_chirho: "user/alice".to_string(),
                    max_rows_chirho: 10,
                },
                request_chirho: request_chirho.clone(),
                response_chirho: Some(response_chirho.clone()),
                sig_chirho: "effect-sig-chirho".to_string(),
                at_chirho: "1234".to_string(),
            },
            sig_chirho: "record-sig-chirho".to_string(),
        }),
        validation_error_chirho: None,
    };
    let invalid_record_chirho = effect_chirho::VolatileEffectDisplayRecordChirho {
        line_chirho: 9,
        record_chirho: None,
        validation_error_chirho: Some("decode VolatileEffectRecordChirho: bad row".to_string()),
    };
    let display_records_chirho = vec![record_chirho, invalid_record_chirho];
    let value_chirho = serde_json::to_value(volatile_effect_list_cli_report_chirho(
        &display_records_chirho,
    ))
    .unwrap();
    assert_eq!(
        value_chirho["schema_chirho"],
        VOLATILE_EFFECT_LIST_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(value_chirho["records_chirho"][0]["line_chirho"], 8);
    assert_eq!(value_chirho["records_chirho"][0]["valid_chirho"], true);
    assert!(value_chirho["records_chirho"][0]["validation_error_chirho"].is_null());
    assert_eq!(value_chirho["records_chirho"][0]["seq_chirho"], 7);
    assert_eq!(value_chirho["records_chirho"][0]["effect_seq_chirho"], 5);
    assert_eq!(
        value_chirho["records_chirho"][0]["request_chirho"],
        request_chirho.0
    );
    assert_eq!(
        value_chirho["records_chirho"][0]["response_chirho"],
        response_chirho.0
    );
    assert_eq!(
        value_chirho["records_chirho"][0]["idem_key_chirho"],
        idem_chirho.0
    );
    assert_eq!(
        value_chirho["records_chirho"][0]["record_sig_chirho"],
        "record-sig-chirho"
    );
    assert_eq!(value_chirho["records_chirho"][1]["line_chirho"], 9);
    assert_eq!(value_chirho["records_chirho"][1]["valid_chirho"], false);
    assert_eq!(
        value_chirho["records_chirho"][1]["validation_error_chirho"],
        "decode VolatileEffectRecordChirho: bad row"
    );
    assert!(value_chirho["records_chirho"][1]["seq_chirho"].is_null());
    let text_chirho = volatile_effect_list_text_chirho(&display_records_chirho);
    assert!(text_chirho.contains("#7\tVALID"));
    assert!(text_chirho.contains("line=9\tINVALID"));
    assert!(text_chirho.contains("validation_error=decode VolatileEffectRecordChirho: bad row"));
}
#[test]
fn realtime_list_text_marks_invalid_rows_chirho() {
    let session_records_chirho = vec![
        realtime_legacy_evidence_chirho::RealtimeDisplayRecordChirho::<
            realtime_legacy_evidence_chirho::RealtimeSessionRecordChirho,
        > {
            line_chirho: 4,
            record_chirho: None,
            validation_error_chirho: Some("signature invalid".to_string()),
        },
    ];
    let event_records_chirho = vec![
        realtime_legacy_evidence_chirho::RealtimeDisplayRecordChirho::<
            realtime_legacy_evidence_chirho::RealtimeEventRecordChirho,
        > {
            line_chirho: 5,
            record_chirho: None,
            validation_error_chirho: Some("ledger signature invalid".to_string()),
        },
    ];
    let epilogue_records_chirho = vec![
        realtime_legacy_evidence_chirho::RealtimeDisplayRecordChirho::<
            realtime_legacy_evidence_chirho::RealtimeEpilogueRecordChirho,
        > {
            line_chirho: 6,
            record_chirho: None,
            validation_error_chirho: Some("epilogue signature invalid".to_string()),
        },
    ];
    let sessions_chirho = realtime_sessions_list_text_chirho(&session_records_chirho);
    let events_chirho = realtime_events_list_text_chirho(&event_records_chirho);
    let epilogues_chirho = realtime_epilogues_list_text_chirho(&epilogue_records_chirho);
    assert!(sessions_chirho.contains("line=4\tINVALID"));
    assert!(sessions_chirho.contains("validation_error=signature invalid"));
    assert!(events_chirho.contains("line=5\tINVALID"));
    assert!(events_chirho.contains("validation_error=ledger signature invalid"));
    assert!(epilogues_chirho.contains("line=6\tINVALID"));
    assert!(epilogues_chirho.contains("validation_error=epilogue signature invalid"));
}

/// The operator `kv-put` door seals through the same helper as the blessed write arm, so no
/// production door can write a plaintext value into the versioned store. The oracle reads the real
/// `.redb` FILE, not our own types.
#[test]
fn operator_kv_put_seals_the_row_and_leaves_no_plaintext_in_the_redb_file_chirho() {
    let needle_chirho = "Zebediah Planted-Needle chirho";
    let nanos_chirho = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root_chirho = std::env::temp_dir().join(format!("cairn-kv-put-seal-{nanos_chirho}"));
    std::fs::create_dir_all(&root_chirho).unwrap();

    let handled_chirho = crate::state_cli_chirho::handle_state_command_chirho(
        &root_chirho,
        &crate::args_chirho::CommandChirho::KvPutChirho(
            crate::args_chirho::state_args_chirho::KvPutArgsChirho {
                key_chirho: "operator-notes-chirho/one".to_string(),
                value_chirho: format!("note about {needle_chirho}"),
            },
        ),
    )
    .unwrap();
    assert!(handled_chirho);

    let redb_path_chirho = cairn_dag_command_chirho::kv_path_chirho(&root_chirho);
    let redb_bytes_chirho = std::fs::read(&redb_path_chirho).unwrap();
    assert!(
        !redb_bytes_chirho
            .windows(needle_chirho.len())
            .any(|window_chirho| window_chirho == needle_chirho.as_bytes()),
        "kv-put rested a plaintext value in the versioned store FILE"
    );

    // The row is a sealed envelope under the operator namespace and unseals to the exact value.
    let store_chirho =
        cairn_chirho::versioned_chirho::VersionedStoreChirho::open_chirho(&redb_path_chirho)
            .unwrap();
    let row_chirho = store_chirho
        .get_chirho("operator-notes-chirho/one")
        .unwrap()
        .unwrap();
    drop(store_chirho);
    let cairn_chirho::store_seal_chirho::StoreValueViewChirho::SealedChirho(sealed_chirho) =
        cairn_chirho::store_seal_chirho::detect_sealed_store_value_chirho(&row_chirho).unwrap()
    else {
        panic!("kv-put left an unsealed row");
    };
    assert!(sealed_chirho
        .subject_chirho
        .starts_with(cairn_chirho::store_seal_chirho::OPERATOR_STORE_SEAL_SUBJECT_PREFIX_CHIRHO));
    assert_eq!(
        cairn_chirho::store_seal_chirho::unseal_store_value_chirho(&root_chirho, &sealed_chirho)
            .unwrap(),
        format!("note about {needle_chirho}").as_bytes()
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}
