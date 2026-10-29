// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use cairn_tenant_placement_authority_chirho::topology_chirho::plan_store_chirho::{
    store_topology_plan_chirho, TOPOLOGY_PLAN_INDEX_LOG_CHIRHO,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct EvidenceRootChirho(PathBuf);

impl EvidenceRootChirho {
    fn new_chirho() -> Self {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let nanos_chirho = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let counter_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let path_chirho = std::env::temp_dir().join(format!(
            "cairn-cli-topology-evidence-{}-{nanos_chirho}-{counter_chirho}-chirho",
            std::process::id()
        ));
        std::fs::create_dir(&path_chirho).unwrap();
        Self(path_chirho)
    }
}

impl Drop for EvidenceRootChirho {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run_chirho(root_chirho: &Path, args_chirho: &[&str], success_chirho: bool) -> Value {
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
        .arg("--root")
        .arg(root_chirho)
        .args(args_chirho)
        .output()
        .unwrap();
    assert_eq!(
        output_chirho.status.success(),
        success_chirho,
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output_chirho.stdout),
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    serde_json::from_slice(&output_chirho.stdout).unwrap()
}

#[test]
fn topology_index_cli_gates_measure_valid_failed_and_unmapped_evidence_chirho() {
    let root_chirho = EvidenceRootChirho::new_chirho();
    let root_chirho = &root_chirho.0;
    let plan_chirho = serde_json::from_value(json!({
        "cited_grant_id_chirho": "unapproved-fixture-grant-chirho",
        "nodes_chirho": [{"provider_chirho": "fixture-provider-chirho", "role_chirho": "WorkerChirho"}],
        "spend_rate_micros_per_hour_chirho": 10,
        "proposed_grant_chirho": null,
    })).unwrap();
    store_topology_plan_chirho(root_chirho, &plan_chirho).unwrap();
    let scan_chirho = run_chirho(
        root_chirho,
        &["privacy-scan", "--json", "--fail-on-findings"],
        true,
    );
    assert_eq!(scan_chirho["jsonl_rows_chirho"], 1);
    assert_eq!(scan_chirho["findings_chirho"], json!([]));
    let generate_args_chirho = [
        "compliance-evidence-generate",
        "--fail-on-failed-sources",
        "--fail-on-coverage-gaps",
    ];
    let receipt_chirho = run_chirho(root_chirho, &generate_args_chirho, true);
    assert_eq!(receipt_chirho["failed_sources_chirho"], 0);
    assert_eq!(receipt_chirho["coverage_gaps_chirho"], 0);
    let pack_chirho = receipt_chirho["pack_chirho"].as_str().unwrap();
    run_chirho(
        root_chirho,
        &[
            "compliance-evidence-verify",
            pack_chirho,
            "--fail-on-failed-sources",
            "--fail-on-coverage-gaps",
        ],
        true,
    );

    let path_chirho = root_chirho.join(TOPOLOGY_PLAN_INDEX_LOG_CHIRHO);
    let original_chirho = std::fs::read(&path_chirho).unwrap();
    let mut row_chirho: Value = serde_json::from_slice(&original_chirho).unwrap();
    row_chirho["serde_address_chirho"] = json!("0".repeat(64));
    std::fs::write(&path_chirho, serde_json::to_vec(&row_chirho).unwrap()).unwrap();
    let failed_chirho = run_chirho(root_chirho, &generate_args_chirho, false);
    assert_eq!(failed_chirho["failed_sources_chirho"], 1);
    let sources_chirho = failed_chirho["pack_body_chirho"]["sources_chirho"]
        .as_array()
        .unwrap();
    let source_chirho = sources_chirho
        .iter()
        .find(|source_chirho| {
            source_chirho["source_chirho"] == "placement.topology-plan-index-chirho"
        })
        .unwrap();
    assert_eq!(source_chirho["status_chirho"], "failed-chirho");
    assert!(source_chirho["error_chirho"]
        .as_str()
        .unwrap()
        .contains("ObjectAbsentChirho"));
    std::fs::write(&path_chirho, original_chirho).unwrap();
    run_chirho(
        root_chirho,
        &[
            "compliance-evidence-verify",
            pack_chirho,
            "--fail-on-failed-sources",
            "--fail-on-coverage-gaps",
        ],
        true,
    );

    std::fs::write(
        root_chirho.join("node-usage-measurements-chirho.jsonl"),
        b"",
    )
    .unwrap();
    let gap_chirho = run_chirho(root_chirho, &generate_args_chirho, false);
    assert_eq!(gap_chirho["failed_sources_chirho"], 0);
    assert_eq!(gap_chirho["coverage_gaps_chirho"], 1);
    assert_eq!(
        gap_chirho["pack_body_chirho"]["coverage_gaps_chirho"],
        json!([{
            "path_chirho": "node-usage-measurements-chirho.jsonl",
            "reason_chirho": "unmapped-production-jsonl-chirho",
        }])
    );
}
