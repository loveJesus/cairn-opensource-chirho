// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Execution proof for the review-only capacity/load snapshot reporter.
//!
//! The positive control compares the shipped binary's candidate with the exact digest consumed by
//! admission, then changes a non-usage log and proves the candidate moves. A report that merely
//! exits successfully, prints a constant, or covers only the salient usage input fails this arm.

use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::capacity_attestation_store_chirho::NODE_CAPACITY_ATTESTATION_LOG_CHIRHO;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::lifecycle_transition_store_chirho::NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO;
use cairn_tenant_placement_authority_chirho::attestation_stores_chirho::usage_measurement_store_chirho::NODE_USAGE_MEASUREMENT_LOG_CHIRHO;
use cairn_tenant_placement_authority_chirho::capacity_admission_impl_chirho::capacity_load_snapshot_digest_chirho;
use std::path::Path;
use std::process::Command;

const CANDIDATE_PREFIX_CHIRHO: &str = "candidate_capacity_load_snapshot_digest_chirho=";

fn stage_snapshot_logs_chirho(root_chirho: &Path) {
    std::fs::write(
        root_chirho.join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO),
        b"capacity-evidence-chirho\n",
    )
    .unwrap();
    std::fs::write(
        root_chirho.join(NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO),
        b"lifecycle-evidence-chirho\n",
    )
    .unwrap();
    std::fs::write(
        root_chirho.join(NODE_USAGE_MEASUREMENT_LOG_CHIRHO),
        b"usage-evidence-chirho\n",
    )
    .unwrap();
}

fn run_snapshot_report_chirho(root_chirho: &Path) -> (bool, String, String) {
    let output_chirho = Command::new(env!(
        "CARGO_BIN_EXE_cairn-capacity-load-snapshot-report-chirho"
    ))
    .arg(root_chirho)
    .output()
    .expect("the shipped snapshot reporter runs");
    (
        output_chirho.status.success(),
        String::from_utf8_lossy(&output_chirho.stdout).to_string(),
        String::from_utf8_lossy(&output_chirho.stderr).to_string(),
    )
}

fn reported_candidate_chirho(stdout_chirho: &str) -> &str {
    stdout_chirho
        .lines()
        .find_map(|line_chirho| line_chirho.strip_prefix(CANDIDATE_PREFIX_CHIRHO))
        .expect("the review report names its candidate digest")
}

#[test]
fn the_reported_candidate_is_the_exact_snapshot_admission_compares_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    stage_snapshot_logs_chirho(temp_chirho.path());
    let expected_before_chirho = capacity_load_snapshot_digest_chirho(temp_chirho.path()).unwrap();

    let (ok_before_chirho, stdout_before_chirho, stderr_before_chirho) =
        run_snapshot_report_chirho(temp_chirho.path());
    assert!(
        ok_before_chirho,
        "candidate reports: {stderr_before_chirho}"
    );
    assert!(
        stdout_before_chirho.contains("REVIEW ONLY, admits nothing"),
        "the operator-facing boundary travels with the candidate"
    );
    assert_eq!(
        reported_candidate_chirho(&stdout_before_chirho),
        expected_before_chirho
    );

    std::fs::write(
        temp_chirho
            .path()
            .join(NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO),
        b"lifecycle-evidence-chirho\nnext-transition-chirho\n",
    )
    .unwrap();
    let expected_after_chirho = capacity_load_snapshot_digest_chirho(temp_chirho.path()).unwrap();
    assert_ne!(
        expected_before_chirho, expected_after_chirho,
        "a non-usage evidence change must move the three-log snapshot"
    );

    let (ok_after_chirho, stdout_after_chirho, stderr_after_chirho) =
        run_snapshot_report_chirho(temp_chirho.path());
    assert!(
        ok_after_chirho,
        "changed candidate reports: {stderr_after_chirho}"
    );
    assert_eq!(
        reported_candidate_chirho(&stdout_after_chirho),
        expected_after_chirho
    );
}

#[test]
fn an_incomplete_snapshot_refuses_instead_of_reporting_a_partial_candidate_chirho() {
    let temp_chirho = tempfile::tempdir().unwrap();
    std::fs::write(
        temp_chirho
            .path()
            .join(NODE_CAPACITY_ATTESTATION_LOG_CHIRHO),
        b"capacity-evidence-chirho\n",
    )
    .unwrap();
    std::fs::write(
        temp_chirho
            .path()
            .join(NODE_LIFECYCLE_TRANSITION_LOG_CHIRHO),
        b"lifecycle-evidence-chirho\n",
    )
    .unwrap();

    let (ok_chirho, stdout_chirho, stderr_chirho) = run_snapshot_report_chirho(temp_chirho.path());
    assert!(!ok_chirho, "a partial three-log snapshot must refuse");
    assert!(stdout_chirho.is_empty(), "no partial candidate is emitted");
    assert!(
        stderr_chirho.contains("EvidenceSnapshotUnavailableChirho"),
        "the unavailable snapshot keeps its named identity: {stderr_chirho}"
    );
}
