// For God so loved the world, that He gave His only Begotten Son, that whosoever believeth in Him should not perish but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::model_chirho::{TreeGenerateBriefChirho, TREE_GENERATE_BRIEF_SCHEMA_CHIRHO};
use crate::provider_chirho::ProviderRequestChirho;
use crate::runner_chirho::RedactionSetChirho;
use std::path::PathBuf;
use std::process::Command;

fn temp_root_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = std::env::temp_dir().join(format!(
        "{label_chirho}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(&root_chirho).unwrap();
    root_chirho
}

fn write_brief_chirho(root_chirho: &std::path::Path, private_notes_chirho: &str) -> PathBuf {
    let brief_chirho = root_chirho.join("brief-chirho.json");
    std::fs::write(
        &brief_chirho,
        serde_json::json!({
            "schema_chirho": TREE_GENERATE_BRIEF_SCHEMA_CHIRHO,
            "app_chirho": "g1-test-chirho",
            "public_request_chirho": "Build a simple contact page.",
            "private_operator_notes_chirho": private_notes_chirho,
            "constraints_chirho": ["stay pure by default"]
        })
        .to_string(),
    )
    .unwrap();
    brief_chirho
}

fn false_command_chirho() -> PathBuf {
    PathBuf::from("/usr/bin/false")
}

fn base_options_chirho(
    root_chirho: &std::path::Path,
    brief_chirho: PathBuf,
) -> GenerateOptionsChirho {
    GenerateOptionsChirho {
        brief_path_chirho: brief_chirho,
        output_root_chirho: root_chirho.join("generated-app-chirho"),
        runtime_root_chirho: root_chirho.join("runtime-root-chirho"),
        owner_chirho: "owner/g1-test-chirho".to_string(),
        provider_mode_chirho: ProviderModeChirho::DeterministicStubChirho,
        stub_scenario_chirho: StubScenarioChirho::BrokenLoopChirho,
        provider_config_secret_chirho: None,
        authoring_context_chirho: None,
        tree_build_chirho: false_command_chirho(),
        cairn_cli_chirho: false_command_chirho(),
        max_iterations_chirho: 1,
        max_provider_calls_chirho: 1,
    }
}

fn assert_no_operator_path_leak_chirho(text_chirho: &str, root_chirho: &std::path::Path) {
    assert!(!text_chirho.contains(&root_chirho.display().to_string()));
    if let Ok(canonical_chirho) = std::fs::canonicalize(root_chirho) {
        assert!(!text_chirho.contains(&canonical_chirho.display().to_string()));
    }
    assert!(!text_chirho.contains("/private/var"));
    if let Some(home_chirho) = std::env::var_os("HOME") {
        let home_chirho = home_chirho.to_string_lossy();
        assert!(!text_chirho.contains(home_chirho.as_ref()));
    }
}

#[test]
fn deterministic_stub_can_request_hostile_capability_chirho() {
    let root_chirho = temp_root_chirho("g1-hostile-plan-chirho");
    let plan_chirho = crate::model_chirho::GeneratedSourcePlanChirho::ScaffoldContactChirho {
        hostile_capability_chirho: true,
    };
    crate::source_plan_chirho::apply_source_plan_chirho(&plan_chirho, &root_chirho).unwrap();
    let card_chirho = std::fs::read_to_string(
        root_chirho
            .join("dags_chirho")
            .join("view_contact_chirho")
            .join("nodes_chirho")
            .join("save_contact_chirho")
            .join("blessed-contract-chirho.toml"),
    )
    .unwrap();
    assert!(card_chirho.contains("contract_chirho = \"write-store\""));
    assert!(card_chirho.contains("scope_chirho = \"g1-generated-store-chirho\""));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn generated_output_copy_filter_excludes_build_artifacts_chirho() {
    assert!(!crate::runner_chirho::should_copy_generated_entry_chirho(
        std::ffi::OsStr::new("target")
    ));
    assert!(!crate::runner_chirho::should_copy_generated_entry_chirho(
        std::ffi::OsStr::new(".emitted-manifest-chirho.json")
    ));
    assert!(crate::runner_chirho::should_copy_generated_entry_chirho(
        std::ffi::OsStr::new("dags_chirho")
    ));
}

#[test]
fn missing_brief_failure_redacts_operator_path_chirho() {
    let root_chirho = temp_root_chirho("g1-missing-brief-redaction-chirho");
    let missing_brief_chirho = root_chirho.join("missing-private-brief-sentinel-chirho.json");
    let options_chirho = base_options_chirho(&root_chirho, missing_brief_chirho.clone());
    let report_chirho = run_tree_generation_chirho(&options_chirho);
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_chirho.ok_chirho);
    assert!(report_text_chirho.contains("[operator-local-redacted-chirho]"));
    assert!(!report_text_chirho.contains(&missing_brief_chirho.display().to_string()));
    assert_no_operator_path_leak_chirho(&report_text_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn missing_authoring_context_failure_redacts_operator_path_chirho() {
    let root_chirho = temp_root_chirho("g1-missing-context-redaction-chirho");
    let brief_chirho = write_brief_chirho(&root_chirho, "private note");
    let missing_context_chirho = root_chirho.join("missing-authoring-context-sentinel-chirho.json");
    let mut options_chirho = base_options_chirho(&root_chirho, brief_chirho);
    options_chirho.authoring_context_chirho = Some(missing_context_chirho.clone());
    let report_chirho = run_tree_generation_chirho(&options_chirho);
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_chirho.ok_chirho);
    assert!(report_text_chirho.contains("[operator-local-redacted-chirho]"));
    assert!(!report_text_chirho.contains(&missing_context_chirho.display().to_string()));
    assert_no_operator_path_leak_chirho(&report_text_chirho, &root_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn cargo_failure_diagnostics_are_safe_for_provider_prompt_chirho() {
    let root_chirho = temp_root_chirho("g1-cargo-diagnostics-redaction-chirho");
    let brief_chirho = write_brief_chirho(&root_chirho, "private note");
    let options_chirho = base_options_chirho(&root_chirho, brief_chirho);
    let mut redactions_chirho = RedactionSetChirho::from_options_chirho(&options_chirho);
    redactions_chirho.push_path_chirho(&root_chirho);
    let home_chirho = std::env::var("HOME").unwrap_or_else(|_| "/Users/test-chirho".to_string());
    let private_root_chirho =
        root_chirho
            .display()
            .to_string()
            .replacen("/var/", "/private/var/", 1);
    let script_chirho = root_chirho.join("cargo-failure-chirho.sh");
    std::fs::write(
        &script_chirho,
        format!(
            "printf '%s\\n' 'error: failed at {home_chirho}/.cargo/registry/src/lib.rs' >&2\n\
             printf '%s\\n' 'note: compiler at {home_chirho}/.rustup/toolchains/stable/bin/rustc' >&2\n\
             printf '%s\\n' 'artifact: {private_root_chirho}/target/wasm32-unknown-unknown/debug/app.wasm' >&2\n\
             exit 1\n"
        ),
    )
    .unwrap();
    let mut steps_chirho = Vec::new();
    let result_chirho = crate::runner_chirho::run_step_chirho(
        &mut steps_chirho,
        &redactions_chirho,
        "cargo-build-wasm-examples-chirho",
        Command::new("/bin/sh").arg(&script_chirho),
    );
    assert!(result_chirho.is_err());
    let detail_chirho = &steps_chirho[0].detail_chirho;
    assert!(detail_chirho.contains("[operator-local-redacted-chirho]"));
    assert_no_operator_path_leak_chirho(detail_chirho, &root_chirho);
    assert!(!detail_chirho.contains(".cargo"));
    assert!(!detail_chirho.contains(".rustup"));

    let brief_model_chirho = TreeGenerateBriefChirho {
        schema_chirho: TREE_GENERATE_BRIEF_SCHEMA_CHIRHO.to_string(),
        app_chirho: "g1-test-chirho".to_string(),
        public_request_chirho: "Build a simple contact page.".to_string(),
        private_operator_notes_chirho: Some("private note".to_string()),
        constraints_chirho: vec!["stay pure by default".to_string()],
    };
    let mode_chirho = ProviderModeChirho::OpenRouterChirho;
    let scenario_chirho = StubScenarioChirho::ValidContactChirho;
    let request_chirho = ProviderRequestChirho {
        root_chirho: &options_chirho.runtime_root_chirho,
        mode_chirho: &mode_chirho,
        stub_scenario_chirho: &scenario_chirho,
        config_secret_chirho: Some("tree-generate-openrouter-chirho"),
        brief_chirho: &brief_model_chirho,
        authoring_context_chirho: None,
        diagnostics_chirho: Some(detail_chirho),
        attempt_chirho: 1,
    };
    let prompt_chirho = crate::provider_chirho::prompt_chirho(&request_chirho);
    assert_no_operator_path_leak_chirho(&prompt_chirho, &root_chirho);
    assert!(!prompt_chirho.contains(".cargo"));
    assert!(!prompt_chirho.contains(".rustup"));
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn path_scrub_catches_nonboundary_and_relative_paths_but_preserves_urls_chirho() {
    let redactions_chirho = RedactionSetChirho::default();
    let diagnostics_chirho = "\
linker flag -L/opt/secret-toolchain-chirho/lib
relative path ../../x/private-build-cache-chirho/file.rs
docs https://docs.rs/cairn-chirho/example should stay useful
";
    let scrubbed_chirho = redactions_chirho.redact_report_text_chirho(diagnostics_chirho);
    assert!(!scrubbed_chirho.contains("/opt/secret-toolchain-chirho"));
    assert!(!scrubbed_chirho.contains("../../x/private-build-cache-chirho"));
    assert!(scrubbed_chirho.contains("https://docs.rs/cairn-chirho/example"));
    assert!(scrubbed_chirho.contains("[operator-local-redacted-chirho]"));
}

#[test]
fn failure_report_redacts_private_brief_text_chirho() {
    let root_chirho = temp_root_chirho("g1-redaction-chirho");
    let runtime_root_chirho = root_chirho.join("runtime-root-chirho");
    let output_root_chirho = root_chirho.join("generated-app-chirho");
    let sentinel_chirho = "g1-private-brief-sentinel-should-not-appear-chirho";
    let brief_chirho = write_brief_chirho(&root_chirho, sentinel_chirho);
    let options_chirho = GenerateOptionsChirho {
        brief_path_chirho: brief_chirho,
        output_root_chirho,
        runtime_root_chirho,
        owner_chirho: "owner/g1-test-chirho".to_string(),
        provider_mode_chirho: ProviderModeChirho::DeterministicStubChirho,
        stub_scenario_chirho: StubScenarioChirho::BrokenLoopChirho,
        provider_config_secret_chirho: None,
        authoring_context_chirho: None,
        tree_build_chirho: false_command_chirho(),
        cairn_cli_chirho: false_command_chirho(),
        max_iterations_chirho: 1,
        max_provider_calls_chirho: 1,
    };
    let report_chirho = run_tree_generation_chirho(&options_chirho);
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_chirho.ok_chirho);
    assert_eq!(report_chirho.provider_chirho, "deterministic-stub-chirho");
    assert_eq!(
        report_chirho
            .counters_chirho
            .provider_calls_attempted_chirho,
        1
    );
    assert_eq!(
        report_chirho
            .counters_chirho
            .provider_calls_completed_chirho,
        1
    );
    assert_eq!(report_chirho.step_count_run_chirho, 1);
    assert_eq!(report_chirho.step_count_total_chirho, 5);
    assert_eq!(
        report_chirho.steps_chirho[0].name_chirho,
        "tree-build-check-chirho"
    );
    assert!(report_text_chirho.contains("brief-blake3:"));
    assert!(!report_text_chirho.contains(sentinel_chirho));
    assert!(!report_text_chirho.contains("Build a simple contact page."));
    assert!(!report_chirho.brief_chirho.raw_text_in_report_chirho);
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn openrouter_config_error_does_not_leak_secret_value_chirho() {
    let root_chirho = temp_root_chirho("g1-openrouter-secret-redaction-chirho");
    let runtime_root_chirho = root_chirho.join("runtime-root-chirho");
    let output_root_chirho = root_chirho.join("generated-app-chirho");
    let sentinel_chirho = "g1-openrouter-secret-value-should-not-appear-chirho";
    cairn_secret_chirho::secret_chirho::set_secret_chirho(
        &runtime_root_chirho,
        "tree-generate-openrouter-chirho",
        sentinel_chirho.as_bytes(),
    )
    .unwrap();
    let brief_chirho = write_brief_chirho(&root_chirho, "private note");
    let options_chirho = GenerateOptionsChirho {
        brief_path_chirho: brief_chirho,
        output_root_chirho,
        runtime_root_chirho,
        owner_chirho: "owner/g1-test-chirho".to_string(),
        provider_mode_chirho: ProviderModeChirho::OpenRouterChirho,
        stub_scenario_chirho: StubScenarioChirho::ValidContactChirho,
        provider_config_secret_chirho: Some("tree-generate-openrouter-chirho".to_string()),
        authoring_context_chirho: None,
        tree_build_chirho: false_command_chirho(),
        cairn_cli_chirho: false_command_chirho(),
        max_iterations_chirho: 1,
        max_provider_calls_chirho: 1,
    };
    let report_chirho = run_tree_generation_chirho(&options_chirho);
    let report_text_chirho = serde_json::to_string(&report_chirho).unwrap();
    assert!(!report_chirho.ok_chirho);
    assert!(report_text_chirho.contains("config secret is not valid JSON"));
    assert!(!report_text_chirho.contains(sentinel_chirho));
    assert_eq!(
        report_chirho
            .counters_chirho
            .provider_calls_attempted_chirho,
        1
    );
    assert_eq!(
        report_chirho
            .counters_chirho
            .provider_calls_completed_chirho,
        0
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
