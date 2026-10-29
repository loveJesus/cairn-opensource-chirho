// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

#[test]
fn source_distribution_inherits_no_production_evidence_chirho() {
    assert!(external_production_evidence_chirho().is_empty());
    let blockers_chirho = production_blockers_chirho();
    assert!(!blockers_chirho.is_empty());
    assert!(blockers_chirho.iter().all(|gate_chirho| {
        gate_chirho.required_for_production_chirho
            && !gate_chirho.required_evidence_chirho.is_empty()
    }));
}

#[test]
#[cfg_attr(
    not(feature = "operator-smoke-tests-chirho"),
    ignore = "real localhost contact smoke; enable operator-smoke-tests-chirho"
)]
fn launch_readiness_preserves_contact_privacy_and_inherited_read_hold_chirho() {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-source-readiness-{}-{}-chirho",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root_chirho).unwrap();
    let manifest_path_chirho = default_launch_readiness_manifest_path_chirho();
    let report_chirho = run_launch_readiness_chirho(&root_chirho, &manifest_path_chirho)
        .expect("source readiness report");

    assert_eq!(
        report_chirho.schema_chirho,
        LAUNCH_READINESS_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(report_chirho.contact_chirho.submit_status_chirho, 200);
    assert_eq!(report_chirho.contact_chirho.list_status_chirho, 400);
    assert!(!report_chirho.local_candidate_ready_chirho);
    assert!(!report_chirho.production_ready_chirho);
    assert!(has_production_blockers_chirho(&report_chirho));
    assert!(report_chirho.external_evidence_chirho.is_empty());
    assert!(
        report_chirho
            .contact_chirho
            .contact_raw_body_absent_from_cas_chirho
    );
    assert_eq!(report_chirho.contact_chirho.privacy_scan_findings_chirho, 0);

    let json_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(json_chirho.contains(&report_chirho.manifest_hash_chirho.0));
    assert_eq!(
        report_chirho.root_scope_chirho,
        operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO
    );
    assert_eq!(
        report_chirho.manifest_source_chirho,
        operator_evidence_chirho::MANIFEST_SOURCE_REDACTED_CHIRHO
    );
    for private_chirho in [
        root_chirho.display().to_string(),
        manifest_path_chirho.display().to_string(),
        "Alice".to_string(),
        "alice@example.com".to_string(),
        "bakery".to_string(),
        "followup@example.net".to_string(),
        "Private contract scope".to_string(),
        "Gate code 2468".to_string(),
    ] {
        assert!(!json_chirho.contains(&private_chirho));
    }
    let production_pos_chirho = json_chirho.find("production_ready_chirho").unwrap();
    let local_pos_chirho = json_chirho.find("local_candidate_ready_chirho").unwrap();
    assert!(production_pos_chirho < local_pos_chirho);
    let _ = std::fs::remove_dir_all(root_chirho);
}
