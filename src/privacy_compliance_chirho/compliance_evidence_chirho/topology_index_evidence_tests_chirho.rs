// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use cairn_placement_chirho::topology_chirho::topology_grant_chirho::{
    DesiredTopologyPlanChirho, NodeRoleChirho, PlannedNodeChirho,
};
use cairn_tenant_placement_authority_chirho::topology_chirho::plan_store_chirho::{
    plan_index_evidence_chirho::load_verified_topology_plan_index_chirho,
    store_topology_plan_chirho, TOPOLOGY_PLAN_INDEX_LOG_CHIRHO,
};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};

const PLAN_MARKER_CHIRHO: &str = "unapproved-fixture-provider-chirho";
const SOURCE_CHIRHO: &str = "placement.topology-plan-index-chirho";

struct EvidenceRootChirho {
    path_chirho: PathBuf,
}

impl EvidenceRootChirho {
    fn new_chirho() -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-topology-evidence-{}-{nanos_chirho}-{counter_chirho}-chirho",
            std::process::id()
        ));
        std::fs::create_dir(&path_chirho).unwrap();
        Self { path_chirho }
    }
}

impl Drop for EvidenceRootChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path_chirho);
    }
}

fn store_fixture_chirho(root_chirho: &Path, rate_chirho: u64) {
    store_topology_plan_chirho(
        root_chirho,
        &DesiredTopologyPlanChirho {
            cited_grant_id_chirho: "unapproved-fixture-grant-chirho".to_owned(),
            nodes_chirho: vec![PlannedNodeChirho {
                provider_chirho: PLAN_MARKER_CHIRHO.to_owned(),
                role_chirho: NodeRoleChirho::WorkerChirho,
            }],
            spend_rate_micros_per_hour_chirho: rate_chirho,
            proposed_grant_chirho: None,
        },
    )
    .unwrap();
}

fn generate_pack_chirho(root_chirho: &Path) -> ComplianceEvidenceReceiptChirho {
    generate_compliance_evidence_pack_chirho(
        root_chirho,
        &[String::from("soc2")],
        0,
        now_ms_chirho() + 1,
        "operator/test-chirho",
    )
    .unwrap()
}

#[test]
fn topology_index_evidence_covers_real_rows_without_exporting_plan_contents_chirho() {
    let root_chirho = EvidenceRootChirho::new_chirho();
    let root_chirho = &root_chirho.path_chirho;
    store_fixture_chirho(root_chirho, 10);
    let scan_chirho = privacy_chirho::scan_privacy_surfaces_chirho(root_chirho).unwrap();
    assert_eq!(scan_chirho.jsonl_files_chirho, 1);
    assert_eq!(scan_chirho.jsonl_rows_chirho, 1);
    assert!(scan_chirho.findings_chirho.is_empty(), "{scan_chirho:?}");

    let snapshots_chirho = collect_source_snapshots_chirho(root_chirho).unwrap();
    let source_chirho = snapshots_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == SOURCE_CHIRHO)
        .unwrap();
    let rows_chirho = load_verified_topology_plan_index_chirho(root_chirho).unwrap();
    assert_eq!(source_chirho.status_chirho, "verified-chirho");
    assert_eq!(source_chirho.verified_chirho, json!(1));
    assert_eq!(
        source_chirho.records_chirho,
        vec![json!({
            "plan_hash_chirho": rows_chirho[0].plan_hash_chirho,
            "serde_address_chirho": rows_chirho[0].serde_address_chirho,
        })]
    );
    assert!(!serde_json::to_string(source_chirho)
        .unwrap()
        .contains(PLAN_MARKER_CHIRHO));

    let receipt_chirho = generate_pack_chirho(root_chirho);
    assert_eq!(receipt_chirho.failed_sources_chirho, 0);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 0);
    let summary_chirho = receipt_chirho
        .pack_body_chirho
        .sources_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == SOURCE_CHIRHO)
        .unwrap();
    assert_eq!(summary_chirho.records_chirho, 1);
    assert_eq!(summary_chirho.status_chirho, "verified-chirho");
    assert!(!serde_json::to_string(&receipt_chirho.pack_body_chirho)
        .unwrap()
        .contains(PLAN_MARKER_CHIRHO));
    let verification_chirho =
        verify_compliance_evidence_chirho(root_chirho, Some(&receipt_chirho.pack_chirho)).unwrap();
    assert_eq!(verification_chirho.failed_sources_chirho, 0);
    assert_eq!(verification_chirho.coverage_gaps_chirho, 0);
}

#[test]
fn topology_index_evidence_marks_a_broken_binding_failed_and_invalidates_the_pack_chirho() {
    let root_chirho = EvidenceRootChirho::new_chirho();
    let root_chirho = &root_chirho.path_chirho;
    store_fixture_chirho(root_chirho, 10);
    store_fixture_chirho(root_chirho, 20);
    let receipt_chirho = generate_pack_chirho(root_chirho);
    assert_eq!(receipt_chirho.failed_sources_chirho, 0);
    let path_chirho = root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO);
    let original_chirho = std::fs::read(&path_chirho).unwrap();
    let mut rows_chirho = load_verified_topology_plan_index_chirho(root_chirho).unwrap();
    rows_chirho[1].serde_address_chirho = rows_chirho[0].serde_address_chirho.clone();
    let mut bytes_chirho = Vec::new();
    for row_chirho in rows_chirho {
        serde_json::to_writer(&mut bytes_chirho, &row_chirho).unwrap();
        bytes_chirho.push(b'\n');
    }
    std::fs::write(&path_chirho, bytes_chirho).unwrap();

    let snapshots_chirho = collect_source_snapshots_chirho(root_chirho).unwrap();
    let source_chirho = snapshots_chirho
        .iter()
        .find(|source_chirho| source_chirho.source_chirho == SOURCE_CHIRHO)
        .unwrap();
    assert_eq!(source_chirho.status_chirho, "failed-chirho");
    assert!(source_chirho.records_chirho.is_empty());
    assert!(source_chirho
        .error_chirho
        .as_deref()
        .unwrap()
        .contains("CanonicalBindingMismatchChirho"));
    assert!(!serde_json::to_string(source_chirho)
        .unwrap()
        .contains(PLAN_MARKER_CHIRHO));
    let error_chirho =
        verify_compliance_evidence_chirho(root_chirho, Some(&receipt_chirho.pack_chirho))
            .unwrap_err();
    assert!(
        error_chirho.to_string().contains(SOURCE_CHIRHO),
        "{error_chirho}"
    );
    let failed_chirho = generate_pack_chirho(root_chirho);
    assert_eq!(failed_chirho.failed_sources_chirho, 1);
    assert_eq!(failed_chirho.coverage_gaps_chirho, 0);

    std::fs::write(&path_chirho, original_chirho).unwrap();
    assert!(
        verify_compliance_evidence_chirho(root_chirho, Some(&receipt_chirho.pack_chirho)).is_ok()
    );
}

#[test]
fn topology_index_evidence_leaves_other_present_pending_logs_as_coverage_gaps_chirho() {
    let root_chirho = EvidenceRootChirho::new_chirho();
    let root_chirho = &root_chirho.path_chirho;
    store_fixture_chirho(root_chirho, 10);
    let pending_chirho = privacy_chirho::production_logs_pending_owner_review_chirho();
    assert!(!pending_chirho.contains_key(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO));
    assert!(pending_chirho.contains_key("node-usage-measurements-chirho.jsonl"));
    assert_eq!(generate_pack_chirho(root_chirho).coverage_gaps_chirho, 0);
    std::fs::write(
        root_chirho.join("node-usage-measurements-chirho.jsonl"),
        b"",
    )
    .unwrap();
    let receipt_chirho = generate_pack_chirho(root_chirho);
    assert_eq!(receipt_chirho.coverage_gaps_chirho, 1);
    assert_eq!(
        receipt_chirho.pack_body_chirho.coverage_gaps_chirho[0],
        ComplianceCoverageGapChirho {
            path_chirho: "node-usage-measurements-chirho.jsonl".to_owned(),
            reason_chirho: "unmapped-production-jsonl-chirho".to_owned(),
        }
    );
}
