// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use serde_json::Value;
use std::os::unix::fs::symlink as symlink_chirho;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

fn tmp_root_chirho() -> std::path::PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho =
        COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed) ^ ((std::process::id() as u64) << 32);
    let now_chirho = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("tree-build-check-json-{now_chirho}-{n_chirho}"))
}

fn run_check_json_chirho(root_chirho: &std::path::Path) -> Value {
    let output_chirho = Command::new(env!("CARGO_BIN_EXE_tree-build-chirho"))
        .arg("check")
        .arg("--json")
        .arg(root_chirho)
        .output()
        .expect("run tree-build-chirho check --json");
    assert!(
        !output_chirho.status.success(),
        "broken tree should fail check --json"
    );
    assert!(
        output_chirho.stderr.is_empty(),
        "--json should keep diagnostics on stdout, stderr={}",
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    serde_json::from_slice(&output_chirho.stdout).expect("json report parses")
}

fn write_stale_asset_app_chirho(root_chirho: &std::path::Path) {
    let dag_chirho = root_chirho.join("dags_chirho/d_chirho");
    let role_chirho = dag_chirho.join("nodes_chirho/render_chirho");
    let src_chirho = root_chirho.join("src");
    std::fs::create_dir_all(dag_chirho.join("surface_chirho")).unwrap();
    std::fs::create_dir_all(&role_chirho).unwrap();
    std::fs::create_dir_all(&src_chirho).unwrap();
    std::fs::write(
        src_chirho.join("render_chirho.rs"),
        "const CSS_CHIRHO: &str = \"/app-assets-chirho/demo-app-chirho/by-name-chirho/missing-chirho.css\";\n",
    )
    .unwrap();
    symlink_chirho(
        "../../../../src/render_chirho.rs",
        role_chirho.join("render_chirho.rs"),
    )
    .unwrap();
    std::fs::write(
        root_chirho.join("app-chirho.toml"),
        "schema_chirho = \"app-descriptor-v0-chirho\"\n\
         app_chirho = \"demo-app-chirho\"\n\
         owner_chirho = \"owner/test-chirho\"\n\
         package_chirho = \"demo-package-chirho\"\n\
         [root_chirho]\n\
         dag_chirho = \"d_chirho\"\n\
         input_mode_chirho = \"plain\"\n\
         route_label_chirho = \"home-chirho\"\n\
         [[asset_chirho]]\n\
         name_chirho = \"present-chirho.css\"\n\
         path_chirho = \"assets_chirho/present-chirho.css\"\n\
         content_type_chirho = \"text/css\"\n",
    )
    .unwrap();
}

#[test]
fn check_json_reports_schema_and_stable_codes_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();

    let first_chirho = run_check_json_chirho(&root_chirho);
    let second_chirho = run_check_json_chirho(&root_chirho);

    assert_eq!(first_chirho, second_chirho);
    assert_eq!(
        first_chirho
            .get("schema_chirho")
            .and_then(|value_chirho| value_chirho.as_str()),
        Some("tree-build-check-report-v1-chirho")
    );
    assert_eq!(
        first_chirho
            .get("finding_count_chirho")
            .and_then(|value_chirho| value_chirho.as_u64()),
        Some(1)
    );
    assert_eq!(
        first_chirho
            .get("findings_chirho")
            .and_then(|value_chirho| value_chirho.as_array())
            .and_then(|findings_chirho| findings_chirho.first())
            .and_then(|finding_chirho| finding_chirho.get("code_chirho"))
            .and_then(|code_chirho| code_chirho.as_str()),
        Some("no-dags-chirho")
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn check_json_reports_stale_asset_reference_chirho() {
    let root_chirho = tmp_root_chirho();
    std::fs::create_dir_all(&root_chirho).unwrap();
    write_stale_asset_app_chirho(&root_chirho);

    let report_chirho = run_check_json_chirho(&root_chirho);
    let findings_chirho = report_chirho
        .get("findings_chirho")
        .and_then(|value_chirho| value_chirho.as_array())
        .expect("findings array");
    let stale_chirho = findings_chirho
        .iter()
        .find(|finding_chirho| {
            finding_chirho
                .get("code_chirho")
                .and_then(|code_chirho| code_chirho.as_str())
                == Some("stale-asset-reference-chirho")
        })
        .unwrap_or_else(|| panic!("stale asset reference finding missing: {report_chirho}"));
    assert!(stale_chirho
        .get("found_chirho")
        .and_then(|found_chirho| found_chirho.as_str())
        .is_some_and(|found_chirho| found_chirho.contains("missing-chirho.css")));

    let _ = std::fs::remove_dir_all(&root_chirho);
}
