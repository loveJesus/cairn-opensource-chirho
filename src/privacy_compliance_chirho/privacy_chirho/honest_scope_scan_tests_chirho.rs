// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Gate 1 honest-scope privacy scanner classification tests.

use super::super::{scan_privacy_surfaces_chirho, PrivacyScanReportChirho};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let pid_chirho = std::process::id();
    std::env::temp_dir().join(format!(
        "cairn-hscope-{pid_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}

fn has_finding_chirho(
    report_chirho: &PrivacyScanReportChirho,
    path_prefix_chirho: &str,
    kind_chirho: &str,
) -> bool {
    report_chirho.findings_chirho.iter().any(|finding_chirho| {
        finding_chirho.path_chirho.starts_with(path_prefix_chirho)
            && finding_chirho.kind_chirho == kind_chirho
    })
}

#[test]
fn privacy_scan_treats_gate1_honest_scope_as_bounded_metadata_chirho() {
    let root_chirho = tmp_root_chirho();
    let object_dir_chirho = root_chirho.join("objects-chirho").join("e4");
    std::fs::create_dir_all(&object_dir_chirho).unwrap();
    std::fs::write(
        object_dir_chirho.join("c3f0676626f8c593bb32c722e60b1ba5d4dd1d4aec863c36be316402901240"),
        r#"{
          "schema_chirho": "gate1-checkpoint-report-v1-chirho",
          "status_chirho": "gate1-flip-ready-all-four-digests-match-chirho",
          "honest_scope_chirho": [
            "gate1-checkpoint appends signed anchor evidence only; it does not flip authority or reroute readers",
            "live_verified_clsd_digest_chirho is the independent live/root-verified view; typed and anchor state digests are persisted prefix evidence over the same cut",
            "authority_log_clsd_digest_chirho is folded from root-signature-verified authority records through the pure oracle witness path",
            "a clean report means flip-ready evidence exists; G1.7 still requires the explicit L.J. go-moment"
          ]
        }"#,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("unknown-field-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"commentary_chirho":"This arbitrary operator note is still unclassified free text."}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(!has_finding_chirho(
        &report_chirho,
        "$.honest_scope_chirho",
        "unclassified-free-text-field-chirho"
    ));
    assert!(has_finding_chirho(
        &report_chirho,
        "$.commentary_chirho",
        "unclassified-free-text-field-chirho"
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn privacy_scan_still_runs_pii_detectors_on_honest_scope_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    std::fs::write(
        root_chirho.join("bad-honest-scope-log-chirho.jsonl"),
        r#"{"seq_chirho":0,"honest_scope_chirho":["contact security@example.com before shipping"]}"#,
    )
    .unwrap();

    let report_chirho = scan_privacy_surfaces_chirho(&root_chirho).unwrap();
    assert!(has_finding_chirho(
        &report_chirho,
        "$.honest_scope_chirho",
        "email-like-chirho"
    ));
    assert!(!has_finding_chirho(
        &report_chirho,
        "$.honest_scope_chirho",
        "unclassified-free-text-field-chirho"
    ));
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_text_chirho.contains("security@example.com"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}
