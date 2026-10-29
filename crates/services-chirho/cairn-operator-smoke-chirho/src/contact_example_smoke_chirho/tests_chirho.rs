// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!("cairn-{label_chirho}-{nanos_chirho}-{n_chirho}"))
}

#[test]
#[cfg_attr(
    not(feature = "operator-smoke-tests-chirho"),
    ignore = "operator smoke: builds wasm32 cargo examples and runs local HTTP contact flow; enable with --features operator-smoke-tests-chirho"
)]
fn contact_example_smoke_emits_schema_tagged_safe_evidence_chirho() {
    let root_chirho = temp_root_chirho("contact-example-smoke-report");
    let manifest_path_chirho = default_contact_example_manifest_path_chirho();
    let report_chirho =
        run_contact_example_smoke_chirho(&root_chirho, &manifest_path_chirho).unwrap();
    let runtime_root_chirho = contact_example_smoke_runtime_root_chirho(&root_chirho).unwrap();
    assert!(
        !runtime_root_chirho.join("ledger-chirho.jsonl").exists(),
        "the contact smoke must not mint or initialize the retired legacy ledger"
    );
    assert_eq!(
        report_chirho.schema_chirho,
        CONTACT_EXAMPLE_SMOKE_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(
        report_chirho.deploy_chirho.schema_chirho,
        app_source_manifest_chirho::APP_SOURCE_DEPLOY_REPORT_SCHEMA_CHIRHO
    );
    assert_eq!(
        report_chirho.manifest_hash_chirho,
        cas_chirho::hash_chirho(&std::fs::read(&manifest_path_chirho).unwrap())
    );
    assert_eq!(
        report_chirho.manifest_source_chirho,
        operator_evidence_chirho::MANIFEST_SOURCE_REDACTED_CHIRHO
    );
    assert_eq!(
        report_chirho.root_scope_chirho,
        operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO
    );
    assert_eq!(
        report_chirho.manifest_template_owner_chirho,
        "owner/replace-with-local-owner-principal"
    );
    assert_eq!(report_chirho.submit_chirho.status_chirho, 200);
    assert_eq!(report_chirho.list_refresh_chirho.status_chirho, 400);
    assert_eq!(report_chirho.read_evidence_chirho.len(), 2);
    assert!(matches!(
        &report_chirho.read_evidence_chirho[0],
        ContactExampleReadEvidenceChirho::ServedRefusedNoLedgerSourceChirho {
            status_chirho: 400,
            zero_effect_volatile_billing_mutation_chirho: true,
            ..
        }
    ));
    assert!(matches!(
        &report_chirho.read_evidence_chirho[1],
        ContactExampleReadEvidenceChirho::OperatorDirectReadChirho {
            row_count_chirho: 1,
            ..
        }
    ));
    assert_eq!(
        report_chirho.missing_owner_session_chirho.status_chirho,
        401
    );
    assert_eq!(report_chirho.app_state_chirho.status_chirho, 200);
    assert_eq!(report_chirho.reveal_chirho.status_chirho, 200);
    assert!(
        report_chirho
            .reveal_chirho
            .contains_expected_private_body_chirho
    );
    assert!(
        report_chirho
            .private_body_chirho
            .raw_body_absent_from_cas_chirho
    );
    assert!(
        report_chirho
            .private_body_chirho
            .private_blob_roundtrip_verified_chirho
    );
    assert!(report_chirho
        .persisted_chirho
        .contact_key_chirho
        .starts_with("contacts-chirho/"));
    assert!(
        report_chirho
            .persisted_chirho
            .contact_safe_surfaces_pii_free_chirho
    );
    assert!(report_chirho.privacy_scan_chirho.findings_chirho.is_empty());
    let json_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(json_chirho.contains(&report_chirho.manifest_hash_chirho.0));
    assert!(json_chirho.contains(CONTACT_EXAMPLE_SERVED_READ_POSTURE_CHIRHO));
    assert!(json_chirho.contains(CONTACT_EXAMPLE_OPERATOR_READ_POSTURE_CHIRHO));
    assert!(json_chirho.contains(operator_evidence_chirho::MANIFEST_SOURCE_REDACTED_CHIRHO));
    assert!(json_chirho.contains(operator_evidence_chirho::LOCAL_ROOT_REDACTED_CHIRHO));
    assert!(!json_chirho.contains("\"manifest_path_chirho\""));
    assert!(!json_chirho.contains("\"root_chirho\""));
    assert!(!json_chirho.contains(&root_chirho.display().to_string()));
    assert!(!json_chirho.contains(&manifest_path_chirho.display().to_string()));
    for needle_chirho in [
        "Alice",
        "alice@example.com",
        "alice%40example.com",
        "bakery",
        "Apartment+above",
    ] {
        assert!(!json_chirho.contains(needle_chirho));
    }
    let _ = std::fs::remove_dir_all(&root_chirho);
}
