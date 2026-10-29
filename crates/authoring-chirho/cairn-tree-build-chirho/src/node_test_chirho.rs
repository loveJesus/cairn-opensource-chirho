// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Runs checked table fixtures for pure app nodes through the real WASM bytes runner.

use cairn_wasmtime_runner_chirho::runner_chirho::run_node_bytes_with_limits_chirho;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const NODE_FIXTURE_SCHEMA_CHIRHO: &str = "tree-build-node-fixture-v1-chirho";
pub const NODE_TEST_REPORT_SCHEMA_CHIRHO: &str = "tree-build-node-test-report-v1-chirho";
const DEFAULT_FUEL_LIMIT_CHIRHO: u64 = 10_000_000;
const DEFAULT_MAX_OUTPUT_BYTES_CHIRHO: usize = 1_048_576;
const DEFAULT_MAX_MEMORY_BYTES_CHIRHO: usize = 67_108_864;

#[derive(Clone, Debug, Deserialize)]
struct NodeFixtureSpecChirho {
    schema_chirho: String,
    fixture_chirho: String,
    node_chirho: String,
    wasm_chirho: PathBuf,
    entry_chirho: String,
    input_chirho: PathBuf,
    expected_output_chirho: PathBuf,
    expected_output_blake3_chirho: String,
    #[serde(default = "default_fuel_limit_chirho")]
    fuel_limit_chirho: u64,
    #[serde(default = "default_max_output_bytes_chirho")]
    max_output_bytes_chirho: usize,
    #[serde(default = "default_max_memory_bytes_chirho")]
    max_memory_bytes_chirho: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeTestReportChirho {
    pub schema_chirho: &'static str,
    pub clean_chirho: bool,
    pub fixture_count_chirho: usize,
    pub failures_chirho: Vec<NodeTestFailureChirho>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NodeTestFailureChirho {
    pub code_chirho: String,
    pub node_chirho: String,
    pub fixture_chirho: String,
    pub fixture_path_chirho: String,
    pub message_chirho: String,
    pub expected_hash_chirho: Option<String>,
    pub actual_hash_chirho: Option<String>,
    pub first_diff_chirho: Option<String>,
    pub input_path_chirho: Option<String>,
    pub wasm_path_chirho: Option<String>,
    pub expected_output_path_chirho: Option<String>,
}

pub fn node_test_report_chirho(app_root_chirho: &Path) -> NodeTestReportChirho {
    let fixture_paths_chirho = match find_fixture_paths_chirho(app_root_chirho) {
        Ok(paths_chirho) => paths_chirho,
        Err(error_chirho) => {
            return NodeTestReportChirho {
                schema_chirho: NODE_TEST_REPORT_SCHEMA_CHIRHO,
                clean_chirho: false,
                fixture_count_chirho: 0,
                failures_chirho: vec![NodeTestFailureChirho::simple_chirho(
                    "node-fixture-discovery-error-chirho",
                    "(unknown-chirho)",
                    "(unknown-chirho)",
                    &app_root_chirho.display().to_string(),
                    &error_chirho,
                )],
            };
        }
    };
    let mut failures_chirho = Vec::new();
    for fixture_path_chirho in &fixture_paths_chirho {
        if let Err(failure_chirho) = run_fixture_file_chirho(app_root_chirho, fixture_path_chirho) {
            failures_chirho.push(*failure_chirho);
        }
    }
    NodeTestReportChirho {
        schema_chirho: NODE_TEST_REPORT_SCHEMA_CHIRHO,
        clean_chirho: failures_chirho.is_empty(),
        fixture_count_chirho: fixture_paths_chirho.len(),
        failures_chirho,
    }
}

fn run_fixture_file_chirho(
    app_root_chirho: &Path,
    fixture_path_chirho: &Path,
) -> Result<(), Box<NodeTestFailureChirho>> {
    let fixture_display_chirho = fixture_path_chirho.display().to_string();
    let fixture_text_chirho = fs::read_to_string(fixture_path_chirho).map_err(|error_chirho| {
        Box::new(NodeTestFailureChirho::simple_chirho(
            "node-fixture-read-error-chirho",
            "(unknown-chirho)",
            "(unknown-chirho)",
            &fixture_display_chirho,
            &format!("read fixture TOML: {error_chirho}"),
        ))
    })?;
    let fixture_chirho: NodeFixtureSpecChirho =
        toml::from_str(&fixture_text_chirho).map_err(|error_chirho| {
            Box::new(NodeTestFailureChirho::simple_chirho(
                "node-fixture-parse-error-chirho",
                "(unknown-chirho)",
                "(unknown-chirho)",
                &fixture_display_chirho,
                &format!("parse fixture TOML: {error_chirho}"),
            ))
        })?;
    if fixture_chirho.schema_chirho != NODE_FIXTURE_SCHEMA_CHIRHO {
        return Err(Box::new(failure_for_fixture_chirho(
            "node-fixture-schema-mismatch-chirho",
            &fixture_chirho,
            fixture_path_chirho,
            &format!(
                "expected schema {NODE_FIXTURE_SCHEMA_CHIRHO}, found {}",
                fixture_chirho.schema_chirho
            ),
        )));
    }
    if !is_hex_hash_chirho(&fixture_chirho.expected_output_blake3_chirho) {
        return Err(Box::new(failure_for_fixture_chirho(
            "node-fixture-invalid-expected-hash-chirho",
            &fixture_chirho,
            fixture_path_chirho,
            "expected_output_blake3_chirho must be a 64-hex BLAKE3 digest",
        )));
    }

    let wasm_path_chirho =
        resolve_fixture_path_chirho(app_root_chirho, &fixture_chirho.wasm_chirho);
    let input_path_chirho =
        resolve_fixture_path_chirho(app_root_chirho, &fixture_chirho.input_chirho);
    let expected_path_chirho =
        resolve_fixture_path_chirho(app_root_chirho, &fixture_chirho.expected_output_chirho);

    let wasm_bytes_chirho = read_bytes_chirho(
        "node-fixture-wasm-read-error-chirho",
        &fixture_chirho,
        fixture_path_chirho,
        &wasm_path_chirho,
    )?;
    let input_bytes_chirho = read_bytes_chirho(
        "node-fixture-input-read-error-chirho",
        &fixture_chirho,
        fixture_path_chirho,
        &input_path_chirho,
    )?;
    let expected_bytes_chirho = read_bytes_chirho(
        "node-fixture-expected-read-error-chirho",
        &fixture_chirho,
        fixture_path_chirho,
        &expected_path_chirho,
    )?;
    let expected_file_hash_chirho = hash_hex_chirho(&expected_bytes_chirho);
    if expected_file_hash_chirho != fixture_chirho.expected_output_blake3_chirho {
        let mut failure_chirho = failure_for_fixture_chirho(
            "node-fixture-expected-hash-mismatch-chirho",
            &fixture_chirho,
            fixture_path_chirho,
            "expected output file does not match expected_output_blake3_chirho",
        );
        failure_chirho.expected_hash_chirho =
            Some(fixture_chirho.expected_output_blake3_chirho.clone());
        failure_chirho.actual_hash_chirho = Some(expected_file_hash_chirho);
        failure_chirho.expected_output_path_chirho =
            Some(expected_path_chirho.display().to_string());
        return Err(Box::new(failure_chirho));
    }

    let outcome_chirho = run_node_bytes_with_limits_chirho(
        &wasm_bytes_chirho,
        &fixture_chirho.entry_chirho,
        &input_bytes_chirho,
        fixture_chirho.fuel_limit_chirho,
        fixture_chirho.max_output_bytes_chirho,
        fixture_chirho.max_memory_bytes_chirho,
    )
    .map_err(|error_chirho| {
        let mut failure_chirho = failure_for_fixture_chirho(
            "node-fixture-runner-error-chirho",
            &fixture_chirho,
            fixture_path_chirho,
            &format!("runner failed: {error_chirho}"),
        );
        failure_chirho.input_path_chirho = Some(input_path_chirho.display().to_string());
        failure_chirho.wasm_path_chirho = Some(wasm_path_chirho.display().to_string());
        Box::new(failure_chirho)
    })?;

    let actual_hash_chirho = hash_hex_chirho(&outcome_chirho.output_chirho);
    if actual_hash_chirho != fixture_chirho.expected_output_blake3_chirho {
        let mut failure_chirho = failure_for_fixture_chirho(
            "node-fixture-output-mismatch-chirho",
            &fixture_chirho,
            fixture_path_chirho,
            "actual node output differs from expected output",
        );
        failure_chirho.expected_hash_chirho =
            Some(fixture_chirho.expected_output_blake3_chirho.clone());
        failure_chirho.actual_hash_chirho = Some(actual_hash_chirho);
        failure_chirho.first_diff_chirho =
            first_diff_chirho(&expected_bytes_chirho, &outcome_chirho.output_chirho);
        failure_chirho.input_path_chirho = Some(input_path_chirho.display().to_string());
        failure_chirho.wasm_path_chirho = Some(wasm_path_chirho.display().to_string());
        failure_chirho.expected_output_path_chirho =
            Some(expected_path_chirho.display().to_string());
        return Err(Box::new(failure_chirho));
    }
    Ok(())
}

fn read_bytes_chirho(
    code_chirho: &str,
    fixture_chirho: &NodeFixtureSpecChirho,
    fixture_path_chirho: &Path,
    path_chirho: &Path,
) -> Result<Vec<u8>, Box<NodeTestFailureChirho>> {
    fs::read(path_chirho).map_err(|error_chirho| {
        Box::new(failure_for_fixture_chirho(
            code_chirho,
            fixture_chirho,
            fixture_path_chirho,
            &format!("read {}: {error_chirho}", path_chirho.display()),
        ))
    })
}

fn failure_for_fixture_chirho(
    code_chirho: &str,
    fixture_chirho: &NodeFixtureSpecChirho,
    fixture_path_chirho: &Path,
    message_chirho: &str,
) -> NodeTestFailureChirho {
    NodeTestFailureChirho::simple_chirho(
        code_chirho,
        &fixture_chirho.node_chirho,
        &fixture_chirho.fixture_chirho,
        &fixture_path_chirho.display().to_string(),
        message_chirho,
    )
}

fn find_fixture_paths_chirho(app_root_chirho: &Path) -> Result<Vec<PathBuf>, String> {
    let fixture_root_chirho = app_root_chirho.join("fixtures_chirho/node-tests-chirho");
    if !fixture_root_chirho.exists() {
        return Ok(Vec::new());
    }
    let mut paths_chirho = Vec::new();
    collect_toml_files_chirho(&fixture_root_chirho, &mut paths_chirho)?;
    paths_chirho.sort();
    Ok(paths_chirho)
}

fn collect_toml_files_chirho(
    dir_chirho: &Path,
    paths_chirho: &mut Vec<PathBuf>,
) -> Result<(), String> {
    let entries_chirho = fs::read_dir(dir_chirho)
        .map_err(|error_chirho| format!("read {}: {error_chirho}", dir_chirho.display()))?;
    let mut children_chirho = Vec::new();
    for entry_chirho in entries_chirho {
        let entry_chirho = entry_chirho.map_err(|error_chirho| {
            format!("read {} entry: {error_chirho}", dir_chirho.display())
        })?;
        children_chirho.push(entry_chirho.path());
    }
    children_chirho.sort();
    for child_chirho in children_chirho {
        let metadata_chirho = fs::symlink_metadata(&child_chirho)
            .map_err(|error_chirho| format!("stat {}: {error_chirho}", child_chirho.display()))?;
        if metadata_chirho.file_type().is_symlink() {
            continue;
        }
        if metadata_chirho.is_dir() {
            collect_toml_files_chirho(&child_chirho, paths_chirho)?;
        } else if child_chirho
            .extension()
            .and_then(|ext_chirho| ext_chirho.to_str())
            == Some("toml")
        {
            paths_chirho.push(child_chirho);
        }
    }
    Ok(())
}

fn resolve_fixture_path_chirho(app_root_chirho: &Path, path_chirho: &Path) -> PathBuf {
    if path_chirho.is_absolute() {
        path_chirho.to_path_buf()
    } else {
        app_root_chirho.join(path_chirho)
    }
}

fn hash_hex_chirho(bytes_chirho: &[u8]) -> String {
    blake3::hash(bytes_chirho).to_hex().to_string()
}

fn is_hex_hash_chirho(value_chirho: &str) -> bool {
    value_chirho.len() == 64
        && value_chirho
            .bytes()
            .all(|byte_chirho| byte_chirho.is_ascii_hexdigit())
}

fn first_diff_chirho(expected_chirho: &[u8], actual_chirho: &[u8]) -> Option<String> {
    let min_len_chirho = expected_chirho.len().min(actual_chirho.len());
    for idx_chirho in 0..min_len_chirho {
        if expected_chirho[idx_chirho] != actual_chirho[idx_chirho] {
            return Some(format!(
                "byte {idx_chirho}: expected 0x{:02x}, actual 0x{:02x}",
                expected_chirho[idx_chirho], actual_chirho[idx_chirho]
            ));
        }
    }
    if expected_chirho.len() != actual_chirho.len() {
        Some(format!(
            "length differs: expected {} byte(s), actual {} byte(s)",
            expected_chirho.len(),
            actual_chirho.len()
        ))
    } else {
        None
    }
}

fn default_fuel_limit_chirho() -> u64 {
    DEFAULT_FUEL_LIMIT_CHIRHO
}

fn default_max_output_bytes_chirho() -> usize {
    DEFAULT_MAX_OUTPUT_BYTES_CHIRHO
}

fn default_max_memory_bytes_chirho() -> usize {
    DEFAULT_MAX_MEMORY_BYTES_CHIRHO
}

impl NodeTestFailureChirho {
    fn simple_chirho(
        code_chirho: &str,
        node_chirho: &str,
        fixture_chirho: &str,
        fixture_path_chirho: &str,
        message_chirho: &str,
    ) -> Self {
        Self {
            code_chirho: code_chirho.to_string(),
            node_chirho: node_chirho.to_string(),
            fixture_chirho: fixture_chirho.to_string(),
            fixture_path_chirho: fixture_path_chirho.to_string(),
            message_chirho: message_chirho.to_string(),
            expected_hash_chirho: None,
            actual_hash_chirho: None,
            first_diff_chirho: None,
            input_path_chirho: None,
            wasm_path_chirho: None,
            expected_output_path_chirho: None,
        }
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
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

    fn scratch_root_chirho(tag_chirho: &str) -> PathBuf {
        static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
        let count_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
        let root_chirho = std::env::temp_dir().join(format!(
            "tree-build-node-test-{tag_chirho}-{}-{count_chirho}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root_chirho);
        root_chirho
    }

    fn write_fixture_app_chirho(
        root_chirho: &Path,
        expected_bytes_chirho: &[u8],
        expected_hash_chirho: &str,
    ) {
        fs::create_dir_all(root_chirho.join("fixtures_chirho/node-tests-chirho")).unwrap();
        fs::create_dir_all(root_chirho.join("fixtures_chirho/node-inputs-chirho")).unwrap();
        fs::create_dir_all(root_chirho.join("fixtures_chirho/node-expected-chirho")).unwrap();
        fs::create_dir_all(root_chirho.join("fixtures_chirho/node-wasm-chirho")).unwrap();
        fs::write(
            root_chirho.join("fixtures_chirho/node-wasm-chirho/upcase_chirho.wat"),
            UPCASER_WAT_CHIRHO,
        )
        .unwrap();
        fs::write(
            root_chirho.join("fixtures_chirho/node-inputs-chirho/default_chirho.txt"),
            b"hello",
        )
        .unwrap();
        fs::write(
            root_chirho.join("fixtures_chirho/node-expected-chirho/default_chirho.txt"),
            expected_bytes_chirho,
        )
        .unwrap();
        fs::write(
            root_chirho.join("fixtures_chirho/node-tests-chirho/upcase_default_chirho.toml"),
            format!(
                "schema_chirho = \"{NODE_FIXTURE_SCHEMA_CHIRHO}\"\n\
fixture_chirho = \"upcase_default_chirho\"\n\
node_chirho = \"view_contact_chirho/upcase_chirho\"\n\
wasm_chirho = \"fixtures_chirho/node-wasm-chirho/upcase_chirho.wat\"\n\
entry_chirho = \"upcase_chirho\"\n\
input_chirho = \"fixtures_chirho/node-inputs-chirho/default_chirho.txt\"\n\
expected_output_chirho = \"fixtures_chirho/node-expected-chirho/default_chirho.txt\"\n\
expected_output_blake3_chirho = \"{expected_hash_chirho}\"\n\
fuel_limit_chirho = 10000000\n\
max_output_bytes_chirho = 1048576\n\
max_memory_bytes_chirho = 67108864\n"
            ),
        )
        .unwrap();
    }

    #[test]
    fn node_fixture_passes_deterministically_chirho() {
        let root_chirho = scratch_root_chirho("clean");
        write_fixture_app_chirho(&root_chirho, b"HELLO", &hash_hex_chirho(b"HELLO"));

        let first_chirho = node_test_report_chirho(&root_chirho);
        let second_chirho = node_test_report_chirho(&root_chirho);

        assert!(first_chirho.clean_chirho, "{first_chirho:?}");
        assert_eq!(first_chirho, second_chirho);
        assert_eq!(first_chirho.fixture_count_chirho, 1);
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn broken_fixture_names_node_fixture_hashes_and_byte_diff_chirho() {
        let root_chirho = scratch_root_chirho("broken");
        write_fixture_app_chirho(&root_chirho, b"WRONG", &hash_hex_chirho(b"WRONG"));

        let report_chirho = node_test_report_chirho(&root_chirho);

        assert!(!report_chirho.clean_chirho);
        let failure_chirho = report_chirho.failures_chirho.first().unwrap();
        assert_eq!(
            failure_chirho.code_chirho,
            "node-fixture-output-mismatch-chirho"
        );
        assert_eq!(
            failure_chirho.node_chirho,
            "view_contact_chirho/upcase_chirho"
        );
        assert_eq!(failure_chirho.fixture_chirho, "upcase_default_chirho");
        assert_eq!(
            failure_chirho.expected_hash_chirho,
            Some(hash_hex_chirho(b"WRONG"))
        );
        assert_eq!(
            failure_chirho.actual_hash_chirho,
            Some(hash_hex_chirho(b"HELLO"))
        );
        assert!(failure_chirho
            .first_diff_chirho
            .as_deref()
            .unwrap()
            .contains("byte 0"));
        let _ = fs::remove_dir_all(&root_chirho);
    }

    #[test]
    fn expected_file_hash_mismatch_fails_before_runner_chirho() {
        let root_chirho = scratch_root_chirho("expected-hash");
        write_fixture_app_chirho(&root_chirho, b"HELLO", &hash_hex_chirho(b"DIFFERENT"));

        let report_chirho = node_test_report_chirho(&root_chirho);

        assert!(!report_chirho.clean_chirho);
        assert_eq!(
            report_chirho.failures_chirho[0].code_chirho,
            "node-fixture-expected-hash-mismatch-chirho"
        );
        let _ = fs::remove_dir_all(&root_chirho);
    }
}
