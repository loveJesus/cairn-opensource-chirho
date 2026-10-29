// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

#[test]
fn native_bench_reports_matching_hot_loop_results_chirho() {
    let root_chirho = tmp_root_chirho("bench");
    let output_chirho = std::process::Command::new(env!("CARGO_BIN_EXE_cairn-chirho"))
        .args([
            "--root",
            root_chirho.to_str().unwrap(),
            "native-bench",
            "--iterations",
            "1000",
            "--samples",
            "1",
            "--allow-unsupported-sandbox",
        ])
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "native-bench failed: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );

    let report_chirho: serde_json::Value = serde_json::from_slice(&output_chirho.stdout).unwrap();
    assert_eq!(
        report_chirho["wasm_result_chirho"],
        report_chirho["native_result_chirho"]
    );
    assert_eq!(report_chirho["warm_slots_chirho"], 1);
    assert!(report_chirho["wasm_elapsed_us_chirho"].as_u64().unwrap() > 0);
    assert!(report_chirho["native_elapsed_us_chirho"].as_u64().unwrap() > 0);

    let _ = std::fs::remove_dir_all(root_chirho);
}

fn tmp_root_chirho(label_chirho: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let nanos_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "cairn-native-bench-{label_chirho}-{nanos_chirho}-{n_chirho}"
    ))
}
