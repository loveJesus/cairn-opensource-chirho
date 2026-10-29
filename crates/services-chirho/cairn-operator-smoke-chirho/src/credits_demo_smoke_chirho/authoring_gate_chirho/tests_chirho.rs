// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! Behavioral mutations for the CF7 source-closure, command, fixture, and artifact promotion gate.

use super::command_chirho::{
    absolute_compile_time_cargo_path_chirho, run_bounded_command_chirho, trusted_cargo_chirho,
    CommandLimitsChirho,
};
use super::fixture_chirho::{run_exact_node_fixtures_chirho, CapturedNodeArtifactChirho};
use super::snapshot_chirho::snapshot_source_closure_chirho;
use super::*;
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

const UPCASER_WAT_CHIRHO: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples-chirho/upcase-chirho.wat"
));
static ENVIRONMENT_LOCK_CHIRHO: Mutex<()> = Mutex::new(());

#[test]
fn compile_time_cargo_coordinate_must_be_absolute_chirho() {
    let refusal_chirho = absolute_compile_time_cargo_path_chirho("cargo")
        .expect_err("relative Cargo coordinate must refuse")
        .to_string();
    assert!(
        refusal_chirho.contains("compile-time Cargo executable path must be absolute"),
        "relative-path refusal identity drifted: {refusal_chirho}"
    );
    assert_eq!(
        absolute_compile_time_cargo_path_chirho("/toolchain/bin/cargo")
            .expect("absolute Cargo coordinate"),
        PathBuf::from("/toolchain/bin/cargo")
    );
}

fn credits_demo_root_chirho() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("examples-chirho/tree-credits-demo-chirho")
}

fn scratch_root_chirho(tag_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "cairn-cf7-authoring-{tag_chirho}-{}-{}-chirho",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos()
    ));
    let _result_chirho = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).expect("create scratch root");
    root_chirho
}

#[cfg(unix)]
fn make_executable_chirho(path_chirho: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o700))
        .expect("make test command executable");
}

struct EnvironmentGuardChirho {
    _lock_chirho: MutexGuard<'static, ()>,
    original_chirho: Vec<(&'static str, Option<OsString>)>,
}

impl EnvironmentGuardChirho {
    fn set_chirho(values_chirho: &[(&'static str, &OsStr)]) -> Self {
        let lock_chirho = ENVIRONMENT_LOCK_CHIRHO
            .lock()
            .expect("lock environment mutation");
        let original_chirho = values_chirho
            .iter()
            .map(|(name_chirho, _value_chirho)| (*name_chirho, std::env::var_os(name_chirho)))
            .collect();
        for (name_chirho, value_chirho) in values_chirho {
            std::env::set_var(name_chirho, value_chirho);
        }
        Self {
            _lock_chirho: lock_chirho,
            original_chirho,
        }
    }
}

impl Drop for EnvironmentGuardChirho {
    fn drop(&mut self) {
        for (name_chirho, value_chirho) in &self.original_chirho {
            match value_chirho {
                Some(value_chirho) => std::env::set_var(name_chirho, value_chirho),
                None => std::env::remove_var(name_chirho),
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn bound_gate_ignores_fake_runtime_cargo_and_executes_real_tests_chirho() {
    let fake_root_chirho = scratch_root_chirho("fake-cargo");
    let fake_cargo_chirho = fake_root_chirho.join("cargo-chirho");
    let sentinel_chirho = fake_root_chirho.join("invoked-chirho");
    std::fs::write(
        &fake_cargo_chirho,
        "#!/bin/sh\n\
# For God so loved the world, that he gave his only begotten Son. - John 3:16\n\
: > \"$CF7_FAKE_CARGO_SENTINEL_CHIRHO\"\n\
printf 'test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\\n'\n\
exit 0\n",
    )
    .expect("write fake cargo");
    make_executable_chirho(&fake_cargo_chirho);
    let _environment_chirho = EnvironmentGuardChirho::set_chirho(&[
        ("CARGO", fake_cargo_chirho.as_os_str()),
        (
            "CF7_FAKE_CARGO_SENTINEL_CHIRHO",
            sentinel_chirho.as_os_str(),
        ),
    ]);

    let gate_chirho =
        preflight_authoring_gate_chirho(&credits_demo_root_chirho(), None).expect("bound gate");
    assert!(
        !sentinel_chirho.exists(),
        "caller-controlled fake Cargo must never run"
    );
    assert_eq!(gate_chirho.report_chirho.local_package_count_chirho, 3);
    assert_eq!(
        gate_chirho.report_chirho.artifact_dispositions_chirho.len(),
        4
    );
    let test_count_chirho = gate_chirho
        .report_chirho
        .steps_chirho
        .iter()
        .find_map(|step_chirho| match step_chirho {
            AuthoringGateStepEvidenceChirho::GuestTestsChirho {
                test_count_chirho, ..
            } => Some(*test_count_chirho),
            _ => None,
        })
        .expect("guest test evidence");
    assert_eq!(test_count_chirho, 14);
    verify_authoring_gate_report_chirho(
        &gate_chirho.report_chirho,
        &gate_chirho.report_chirho.source_tree_blake3_chirho,
        &gate_chirho.report_chirho.cargo_executable_blake3_chirho,
        &gate_chirho.emit_bytes_chirho,
        4,
    )
    .expect("verify bound report");
    drop(_environment_chirho);
    let _result_chirho = std::fs::remove_dir_all(fake_root_chirho);
}

#[test]
fn report_refuses_omitted_steps_zero_tests_and_incomplete_dispositions_chirho() {
    let source_chirho = "a".repeat(64);
    let cargo_chirho = "b".repeat(64);
    let emit_bytes_chirho = b"{\"schema_chirho\":\"fixture-chirho\"}";
    let manifest_chirho = hash_bytes_chirho(emit_bytes_chirho);
    let disposition_chirho = AuthoringGateArtifactDispositionChirho {
        node_id_chirho: "node_chirho".to_string(),
        node_identity_chirho: "dag_chirho/node_chirho".to_string(),
        artifact_path_chirho: "target/node_chirho.wasm".to_string(),
        artifact_blake3_chirho: "c".repeat(64),
        artifact_bytes_chirho: 10,
        fixture_count_chirho: 1,
        disposition_chirho: "fixture-executed-exact-bytes-chirho",
    };
    let report_chirho = AuthoringGateReportChirho {
        schema_chirho: AUTHORING_GATE_REPORT_SCHEMA_CHIRHO,
        source_tree_blake3_chirho: source_chirho.clone(),
        source_entry_count_chirho: 3,
        local_package_count_chirho: 1,
        cargo_executable_blake3_chirho: cargo_chirho.clone(),
        emitted_manifest_blake3_chirho: manifest_chirho.clone(),
        artifact_dispositions_chirho: vec![disposition_chirho],
        steps_chirho: vec![
            AuthoringGateStepEvidenceChirho::CheckChirho {
                source_tree_blake3_chirho: source_chirho.clone(),
                finding_count_chirho: 0,
            },
            AuthoringGateStepEvidenceChirho::GuestTestsChirho {
                source_tree_blake3_chirho: source_chirho.clone(),
                exit_code_chirho: 0,
                test_count_chirho: 1,
            },
            AuthoringGateStepEvidenceChirho::WasmExamplesBuildChirho {
                source_tree_blake3_chirho: source_chirho.clone(),
                exit_code_chirho: 0,
                artifact_count_chirho: 1,
            },
            AuthoringGateStepEvidenceChirho::NodeFixturesChirho {
                source_tree_blake3_chirho: source_chirho.clone(),
                fixture_count_chirho: 1,
                pure_node_count_chirho: 1,
                disposition_count_chirho: 1,
                failure_count_chirho: 0,
            },
            AuthoringGateStepEvidenceChirho::EmitChirho {
                source_tree_blake3_chirho: source_chirho.clone(),
                emitted_manifest_blake3_chirho: manifest_chirho,
                emitted_manifest_bytes_chirho: emit_bytes_chirho.len(),
            },
        ],
    };
    for (index_chirho, label_chirho) in [
        "check-chirho",
        "guest-tests-chirho",
        "wasm-examples-build-chirho",
        "node-fixtures-chirho",
        "emit-chirho",
    ]
    .iter()
    .enumerate()
    {
        let mut omitted_chirho = report_chirho.clone();
        omitted_chirho.steps_chirho.remove(index_chirho);
        let error_chirho = verify_authoring_gate_report_chirho(
            &omitted_chirho,
            &source_chirho,
            &cargo_chirho,
            emit_bytes_chirho,
            1,
        )
        .expect_err("omitted step must refuse");
        assert!(
            error_chirho
                .to_string()
                .contains(&format!("missing authoring gate step '{label_chirho}'")),
            "wrong omission refusal for {label_chirho}: {error_chirho}"
        );
    }

    let mut zero_tests_chirho = report_chirho.clone();
    match &mut zero_tests_chirho.steps_chirho[1] {
        AuthoringGateStepEvidenceChirho::GuestTestsChirho {
            test_count_chirho, ..
        } => *test_count_chirho = 0,
        _ => panic!("second report step stopped being guest tests"),
    }
    assert!(verify_authoring_gate_report_chirho(
        &zero_tests_chirho,
        &source_chirho,
        &cargo_chirho,
        emit_bytes_chirho,
        1,
    )
    .expect_err("zero tests must refuse")
    .to_string()
    .contains("unsuccessful or empty"));

    let mut incomplete_chirho = report_chirho;
    incomplete_chirho.artifact_dispositions_chirho[0].fixture_count_chirho = 0;
    assert!(verify_authoring_gate_report_chirho(
        &incomplete_chirho,
        &source_chirho,
        &cargo_chirho,
        emit_bytes_chirho,
        1,
    )
    .expect_err("empty disposition must refuse")
    .to_string()
    .contains("incomplete artifact disposition"));
}

#[test]
fn fixtures_execute_captured_bytes_even_when_declared_path_bytes_differ_chirho() {
    let root_chirho = scratch_root_chirho("fixture-exact");
    write_fixture_chirho(
        &root_chirho,
        "upcase_chirho",
        "view_chirho/upcase_chirho",
        "target/upcase_chirho.wasm",
    );
    let declared_wasm_chirho = root_chirho.join("target/upcase_chirho.wasm");
    std::fs::create_dir_all(declared_wasm_chirho.parent().expect("target parent"))
        .expect("create target");
    std::fs::write(&declared_wasm_chirho, b"not-the-captured-wasm-chirho")
        .expect("write divergent path bytes");
    let artifacts_chirho = vec![captured_upcase_chirho(
        "upcase",
        "view_chirho/upcase_chirho",
        "target/upcase_chirho.wasm",
    )];

    let report_chirho =
        run_exact_node_fixtures_chirho(&root_chirho, &artifacts_chirho).expect("exact fixture");
    assert_eq!(report_chirho.fixture_count_chirho, 1);
    assert_eq!(report_chirho.dispositions_chirho.len(), 1);
    assert_eq!(
        report_chirho.dispositions_chirho[0].artifact_blake3_chirho,
        hash_bytes_chirho(UPCASER_WAT_CHIRHO)
    );
    let _result_chirho = std::fs::remove_dir_all(root_chirho);
}

#[test]
fn fixtures_refuse_omitted_pure_node_and_foreign_wasm_path_chirho() {
    let omission_root_chirho = scratch_root_chirho("fixture-omission");
    write_fixture_chirho(
        &omission_root_chirho,
        "first_chirho",
        "view_chirho/first_chirho",
        "target/first_chirho.wasm",
    );
    let omission_artifacts_chirho = vec![
        captured_upcase_chirho(
            "first",
            "view_chirho/first_chirho",
            "target/first_chirho.wasm",
        ),
        captured_upcase_chirho(
            "second",
            "view_chirho/second_chirho",
            "target/second_chirho.wasm",
        ),
    ];
    let omission_chirho =
        run_exact_node_fixtures_chirho(&omission_root_chirho, &omission_artifacts_chirho)
            .expect_err("an emitted pure node without a fixture must refuse");
    assert!(omission_chirho
        .to_string()
        .contains("has no fixture disposition"));

    let foreign_root_chirho = scratch_root_chirho("fixture-foreign");
    write_fixture_chirho(
        &foreign_root_chirho,
        "foreign_chirho",
        "view_chirho/first_chirho",
        "target/foreign_chirho.wasm",
    );
    let foreign_chirho = run_exact_node_fixtures_chirho(
        &foreign_root_chirho,
        &[captured_upcase_chirho(
            "first",
            "view_chirho/first_chirho",
            "target/first_chirho.wasm",
        )],
    )
    .expect_err("foreign fixture WASM must refuse");
    assert!(foreign_chirho
        .to_string()
        .contains("references foreign WASM path"));
    let _result_chirho = std::fs::remove_dir_all(omission_root_chirho);
    let _result_chirho = std::fs::remove_dir_all(foreign_root_chirho);
}

#[test]
fn fixture_wasm_paths_refuse_absolute_and_escaping_forms_chirho() {
    for (tag_chirho, wasm_chirho) in [
        ("absolute", "/tmp/foreign-chirho.wasm"),
        ("escaping", "../../foreign-chirho.wasm"),
    ] {
        let root_chirho = scratch_root_chirho(tag_chirho);
        write_fixture_chirho(
            &root_chirho,
            tag_chirho,
            "view_chirho/upcase_chirho",
            wasm_chirho,
        );
        let error_chirho = run_exact_node_fixtures_chirho(
            &root_chirho,
            &[captured_upcase_chirho(
                "upcase",
                "view_chirho/upcase_chirho",
                "target/upcase_chirho.wasm",
            )],
        )
        .expect_err("unsafe fixture WASM path must refuse");
        let message_chirho = error_chirho.to_string();
        assert!(
            message_chirho.contains("must be a nonempty relative path")
                || message_chirho.contains("escaping or non-normal"),
            "unsafe path refused for the wrong reason: {message_chirho}"
        );
        let _result_chirho = std::fs::remove_dir_all(root_chirho);
    }
}

#[test]
fn snapshot_materializes_local_path_dependency_bytes_chirho() {
    let root_chirho = scratch_root_chirho("path-closure");
    write_two_package_closure_chirho(&root_chirho);
    let cargo_chirho = trusted_cargo_chirho().expect("trusted cargo");
    let snapshot_chirho =
        snapshot_source_closure_chirho(&root_chirho.join("app-chirho"), &cargo_chirho)
            .expect("snapshot local path closure");
    assert_eq!(snapshot_chirho.local_package_count_chirho, 2);
    let dependency_copy_chirho = snapshot_chirho
        .root_chirho()
        .join("../dep-chirho/src/lib.rs");
    assert_eq!(
        std::fs::read_to_string(&dependency_copy_chirho).expect("read snapshotted dependency"),
        "// For God so loved the world. - John 3:16\npub fn value_chirho() -> u8 { 7 }\n"
    );
    std::fs::write(
        root_chirho.join("dep-chirho/src/lib.rs"),
        "// For God so loved the world. - John 3:16\npub fn value_chirho() -> u8 { 9 }\n",
    )
    .expect("mutate original dependency");
    assert!(std::fs::read_to_string(dependency_copy_chirho)
        .expect("reread snapshotted dependency")
        .contains("{ 7 }"));
    snapshot_chirho
        .assert_unchanged_chirho("dependency mutation control")
        .expect("snapshot must not follow original dependency");
    drop(snapshot_chirho);
    let _result_chirho = std::fs::remove_dir_all(root_chirho);
}

#[cfg(unix)]
#[test]
fn snapshot_refuses_escaping_symlink_source_chirho() {
    let root_chirho = scratch_root_chirho("symlink-closure");
    let app_chirho = root_chirho.join("app-chirho");
    let outside_chirho = scratch_root_chirho("symlink-outside");
    std::fs::write(root_chirho.join(".git"), "gitdir: synthetic-chirho\n")
        .expect("write git marker");
    std::fs::create_dir_all(app_chirho.join("src")).expect("create app src");
    std::fs::write(
        app_chirho.join("Cargo.toml"),
        "# For God so loved the world. - John 3:16\n\
[package]\nname = \"symlink-app-chirho\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
[workspace]\n",
    )
    .expect("write app manifest");
    std::fs::write(
        app_chirho.join("Cargo.lock"),
        "# For God so loved the world. - John 3:16\nversion = 4\n\
[[package]]\nname = \"symlink-app-chirho\"\nversion = \"0.1.0\"\n",
    )
    .expect("write app lock");
    std::fs::write(
        outside_chirho.join("lib.rs"),
        "// For God so loved the world. - John 3:16\n",
    )
    .expect("write outside source");
    std::os::unix::fs::symlink(outside_chirho.join("lib.rs"), app_chirho.join("src/lib.rs"))
        .expect("create escaping source symlink");

    let error_chirho = snapshot_source_closure_chirho(
        &app_chirho,
        &trusted_cargo_chirho().expect("trusted cargo"),
    )
    .expect_err("escaping source symlink must refuse");
    assert!(error_chirho.to_string().contains("contains symlink"));
    let _result_chirho = std::fs::remove_dir_all(root_chirho);
    let _result_chirho = std::fs::remove_dir_all(outside_chirho);
}

#[cfg(unix)]
#[test]
fn bounded_command_runner_terminates_hang_and_output_flood_chirho() {
    let root_chirho = scratch_root_chirho("bounded-command");
    let hanging_chirho = root_chirho.join("hang-chirho");
    std::fs::write(
        &hanging_chirho,
        "#!/bin/sh\n# For God so loved the world. - John 3:16\nwhile :; do sleep 1; done\n",
    )
    .expect("write hanging command");
    make_executable_chirho(&hanging_chirho);
    let mut hanging_command_chirho = std::process::Command::new(&hanging_chirho);
    let timeout_chirho = run_bounded_command_chirho(
        &mut hanging_command_chirho,
        "hanging-mutation-chirho",
        CommandLimitsChirho {
            timeout_chirho: Duration::from_millis(150),
            max_stream_bytes_chirho: 1024,
        },
    )
    .expect_err("hanging command must time out");
    assert!(timeout_chirho.to_string().contains("timeout"));

    let flooding_chirho = root_chirho.join("flood-chirho");
    std::fs::write(
        &flooding_chirho,
        "#!/bin/sh\n# For God so loved the world. - John 3:16\n\
while :; do printf '0123456789abcdef0123456789abcdef'; done\n",
    )
    .expect("write flooding command");
    make_executable_chirho(&flooding_chirho);
    let mut flooding_command_chirho = std::process::Command::new(&flooding_chirho);
    let overflow_chirho = run_bounded_command_chirho(
        &mut flooding_command_chirho,
        "output-flood-mutation-chirho",
        CommandLimitsChirho {
            timeout_chirho: Duration::from_secs(2),
            max_stream_bytes_chirho: 1024,
        },
    )
    .expect_err("output flood must exceed the bound");
    assert!(overflow_chirho.to_string().contains("output bound"));
    let _result_chirho = std::fs::remove_dir_all(root_chirho);
}

fn captured_upcase_chirho(
    node_id_chirho: &str,
    node_identity_chirho: &str,
    artifact_path_chirho: &str,
) -> CapturedNodeArtifactChirho {
    CapturedNodeArtifactChirho {
        node_id_chirho: node_id_chirho.to_string(),
        node_identities_chirho: BTreeSet::from([node_identity_chirho.to_string()]),
        entry_chirho: "upcase_chirho".to_string(),
        artifact_path_chirho: PathBuf::from(artifact_path_chirho),
        artifact_blake3_chirho: hash_bytes_chirho(UPCASER_WAT_CHIRHO),
        bytes_chirho: UPCASER_WAT_CHIRHO.to_vec(),
    }
}

fn write_fixture_chirho(
    root_chirho: &Path,
    fixture_chirho: &str,
    node_chirho: &str,
    wasm_chirho: &str,
) {
    let fixture_root_chirho = root_chirho.join("fixtures_chirho");
    std::fs::create_dir_all(fixture_root_chirho.join("node-tests-chirho"))
        .expect("create fixture specs");
    std::fs::create_dir_all(fixture_root_chirho.join("node-inputs-chirho"))
        .expect("create fixture inputs");
    std::fs::create_dir_all(fixture_root_chirho.join("node-expected-chirho"))
        .expect("create fixture outputs");
    std::fs::write(
        fixture_root_chirho.join("node-inputs-chirho/input-chirho.txt"),
        b"hello",
    )
    .expect("write fixture input");
    std::fs::write(
        fixture_root_chirho.join("node-expected-chirho/output-chirho.txt"),
        b"HELLO",
    )
    .expect("write fixture output");
    std::fs::write(
        fixture_root_chirho
            .join("node-tests-chirho")
            .join(format!("{fixture_chirho}.toml")),
        format!(
            "# For God so loved the world. - John 3:16\n\
schema_chirho = \"tree-build-node-fixture-v1-chirho\"\n\
fixture_chirho = \"{fixture_chirho}\"\n\
node_chirho = \"{node_chirho}\"\n\
wasm_chirho = \"{wasm_chirho}\"\n\
entry_chirho = \"upcase_chirho\"\n\
input_chirho = \"fixtures_chirho/node-inputs-chirho/input-chirho.txt\"\n\
expected_output_chirho = \"fixtures_chirho/node-expected-chirho/output-chirho.txt\"\n\
expected_output_blake3_chirho = \"{}\"\n\
fuel_limit_chirho = 10000000\n\
max_output_bytes_chirho = 1048576\n\
max_memory_bytes_chirho = 67108864\n",
            hash_bytes_chirho(b"HELLO")
        ),
    )
    .expect("write fixture spec");
}

fn write_two_package_closure_chirho(root_chirho: &Path) {
    let app_chirho = root_chirho.join("app-chirho");
    let dependency_chirho = root_chirho.join("dep-chirho");
    std::fs::write(root_chirho.join(".git"), "gitdir: synthetic-chirho\n")
        .expect("write git marker");
    std::fs::create_dir_all(app_chirho.join("src")).expect("create app source");
    std::fs::create_dir_all(dependency_chirho.join("src")).expect("create dependency source");
    std::fs::write(
        app_chirho.join("Cargo.toml"),
        "# For God so loved the world. - John 3:16\n\
[package]\nname = \"closure-app-chirho\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
[workspace]\n\
[dependencies]\nclosure-dep-chirho = { path = \"../dep-chirho\" }\n",
    )
    .expect("write app manifest");
    std::fs::write(
        dependency_chirho.join("Cargo.toml"),
        "# For God so loved the world. - John 3:16\n\
[package]\nname = \"closure-dep-chirho\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write dependency manifest");
    std::fs::write(
        app_chirho.join("src/lib.rs"),
        "// For God so loved the world. - John 3:16\n\
pub fn app_chirho() -> u8 { closure_dep_chirho::value_chirho() }\n",
    )
    .expect("write app source");
    std::fs::write(
        dependency_chirho.join("src/lib.rs"),
        "// For God so loved the world. - John 3:16\npub fn value_chirho() -> u8 { 7 }\n",
    )
    .expect("write dependency source");
    std::fs::write(
        app_chirho.join("Cargo.lock"),
        "# For God so loved the world. - John 3:16\nversion = 4\n\
[[package]]\nname = \"closure-app-chirho\"\nversion = \"0.1.0\"\n\
dependencies = [\n \"closure-dep-chirho\",\n]\n\
[[package]]\nname = \"closure-dep-chirho\"\nversion = \"0.1.0\"\n",
    )
    .expect("write app lock");
}
