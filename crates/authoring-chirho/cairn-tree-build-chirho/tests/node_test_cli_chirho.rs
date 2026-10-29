// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use serde_json::Value;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const UPCASER_WAT_CHIRHO: &str = r#";; For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (func (export "alloc_chirho") (param $len_chirho i32) (result i32)
    (local $ptr_chirho i32)
    global.get $heap_chirho
    local.set $ptr_chirho
    global.get $heap_chirho
    local.get $len_chirho
    i32.add
    global.set $heap_chirho
    local.get $ptr_chirho)
  (func (export "upcase_chirho") (param $ptr_chirho i32) (param $len_chirho i32) (result i64)
    (local $idx_chirho i32)
    (local $byte_chirho i32)
    (block $done_chirho
      (loop $loop_chirho
        local.get $idx_chirho
        local.get $len_chirho
        i32.ge_u
        br_if $done_chirho
        local.get $ptr_chirho
        local.get $idx_chirho
        i32.add
        i32.load8_u
        local.set $byte_chirho
        (if
          (i32.and
            (i32.ge_u (local.get $byte_chirho) (i32.const 97))
            (i32.le_u (local.get $byte_chirho) (i32.const 122)))
          (then
            local.get $ptr_chirho
            local.get $idx_chirho
            i32.add
            local.get $byte_chirho
            i32.const 32
            i32.sub
            i32.store8))
        local.get $idx_chirho
        i32.const 1
        i32.add
        local.set $idx_chirho
        br $loop_chirho))
    (i64.or
      (i64.shl (i64.extend_i32_u (local.get $ptr_chirho)) (i64.const 32))
      (i64.extend_i32_u (local.get $len_chirho)))))
"#;

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    std::env::temp_dir().join(format!(
        "tree-build-node-test-cli-{}-{n_chirho}",
        std::process::id()
    ))
}

fn write_fixture_app_chirho(root_chirho: &std::path::Path, expected_chirho: &[u8]) {
    let expected_hash_chirho = blake3::hash(expected_chirho).to_hex().to_string();
    std::fs::create_dir_all(root_chirho.join("fixtures_chirho/node-tests-chirho")).unwrap();
    std::fs::create_dir_all(root_chirho.join("fixtures_chirho/node-inputs-chirho")).unwrap();
    std::fs::create_dir_all(root_chirho.join("fixtures_chirho/node-expected-chirho")).unwrap();
    std::fs::create_dir_all(root_chirho.join("fixtures_chirho/node-wasm-chirho")).unwrap();
    std::fs::write(
        root_chirho.join("fixtures_chirho/node-wasm-chirho/upcase_chirho.wat"),
        UPCASER_WAT_CHIRHO,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("fixtures_chirho/node-inputs-chirho/input_chirho.txt"),
        b"hello",
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("fixtures_chirho/node-expected-chirho/output_chirho.txt"),
        expected_chirho,
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("fixtures_chirho/node-tests-chirho/upcase_chirho.toml"),
        format!(
            "# For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)\n\
schema_chirho = \"tree-build-node-fixture-v1-chirho\"\n\
fixture_chirho = \"upcase_default_chirho\"\n\
node_chirho = \"view_contact_chirho/upcase_chirho\"\n\
wasm_chirho = \"fixtures_chirho/node-wasm-chirho/upcase_chirho.wat\"\n\
entry_chirho = \"upcase_chirho\"\n\
input_chirho = \"fixtures_chirho/node-inputs-chirho/input_chirho.txt\"\n\
expected_output_chirho = \"fixtures_chirho/node-expected-chirho/output_chirho.txt\"\n\
expected_output_blake3_chirho = \"{expected_hash_chirho}\"\n"
        ),
    )
    .unwrap();
}

#[test]
fn test_json_reports_schema_and_keeps_stderr_empty_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    write_fixture_app_chirho(&root_chirho, b"HELLO");

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("test")
        .arg("--json")
        .arg(&root_chirho)
        .output()
        .expect("run tree-build-chirho test --json");

    assert!(output_chirho.status.success());
    assert!(
        output_chirho.stderr.is_empty(),
        "json mode should keep stderr empty: {}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    let report_chirho: Value =
        serde_json::from_slice(&output_chirho.stdout).expect("test report json parses");
    assert_eq!(
        report_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some("tree-build-node-test-report-v1-chirho")
    );
    assert_eq!(
        report_chirho
            .get("fixture_count_chirho")
            .and_then(|value_chirho| value_chirho.as_u64()),
        Some(1)
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn test_text_failure_names_node_fixture_and_diff_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    write_fixture_app_chirho(&root_chirho, b"WRONG");

    let output_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("test")
        .arg(&root_chirho)
        .output()
        .expect("run tree-build-chirho test");

    assert!(!output_chirho.status.success());
    let stderr_chirho = String::from_utf8_lossy(&output_chirho.stderr);
    assert!(stderr_chirho.contains("node-fixture-output-mismatch-chirho"));
    assert!(stderr_chirho.contains("view_contact_chirho/upcase_chirho"));
    assert!(stderr_chirho.contains("upcase_default_chirho"));
    assert!(stderr_chirho.contains("byte 0"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}
