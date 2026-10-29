// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_context_path_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "tree-build-authoring-context-cli-{now_chirho}-{n_chirho}"
        ))
        .join("authoring-context-chirho.json")
}

#[test]
fn authoring_context_cli_writes_artifact_and_reports_hash_chirho() {
    let output_path_chirho = tmp_context_path_chirho();
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("authoring-context")
        .arg("--json")
        .arg("--output")
        .arg(&output_path_chirho)
        .output()
        .expect("run tree-build-chirho authoring-context --json");
    assert!(
        output_chirho.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert!(
        output_chirho.stderr.is_empty(),
        "json mode should keep diagnostics on stdout, stderr={}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let report_chirho: Value =
        serde_json::from_slice(&output_chirho.stdout).expect("json report parses");
    assert_eq!(
        report_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some("tree-build-authoring-context-report-v1-chirho")
    );

    let bytes_chirho = std::fs::read(&output_path_chirho).expect("context artifact exists");
    let pack_chirho: Value = serde_json::from_slice(&bytes_chirho).expect("context JSON parses");
    assert_eq!(
        pack_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some("tree-build-authoring-context-v1-chirho")
    );
    assert_eq!(
        report_chirho
            .get("artifact_blake3_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some(blake3::hash(&bytes_chirho).to_hex().as_str())
    );
    assert!(pack_chirho
        .get("honest_scope_chirho")
        .and_then(|value_chirho| value_chirho.as_array())
        .is_some_and(
            |scope_chirho| scope_chirho.iter().any(|line_chirho| line_chirho
                .as_str()
                .is_some_and(|line_chirho| line_chirho.contains("not authority")))
        ));

    let _ = std::fs::remove_dir_all(output_path_chirho.parent().unwrap());
}
