// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! The whole chain for a branching private app: a real app tree on disk -> `tree-build` walk,
//! check, emit -> the emitted manifest parsed by the engine's model -> DAG/module artifacts built
//! (named phi ports and bindings accepted) -> the DAG run on a private request through the
//! rejection branch, with the blessed write skipped without invocation and no plaintext in CAS.
//!
//! The cargo-example guests emit lowers to are replaced by `path-chirho` WAT guests before the
//! build, exactly as the beta host packet's `host_ready_app_manifest_chirho.py` does for hosted
//! deploys — the shape the engine consumes is the emitted one; only the guest bytes' origin differs.

use super::*;
use crate::dag_chirho::{
    run_dag_with_context_and_private_input_chirho, tests_chirho::skipped_wat_chirho,
};
use crate::model_chirho::{DagChirho, RequestContextChirho, RunStatusChirho};
use crate::{cache_chirho, cas_chirho, dag_private_value_chirho};
use cairn_tree_build_chirho::check_chirho::check_app_tree_chirho;
use cairn_tree_build_chirho::emit_chirho::{
    emit_manifest_chirho, AppDescriptorChirho, AppRootChirho,
};
use cairn_tree_build_chirho::tree_chirho::walk_app_tree_chirho;
use std::os::unix::fs::symlink as symlink_chirho;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const SUBJECT_CHIRHO: &str = "user/phi-tree-end-to-end-chirho";
const HTML_CHIRHO: &str = "html_partial_v1";
const REQUEST_CHIRHO: &str = "http_request_v1";
const STATE_CHIRHO: &str = "state_v1";
const PRIVATE_EDGE_CARD_CHIRHO: &str =
    "schema_chirho = \"private-edge-v1-chirho\"\nsubject_source_chirho = \"request-user-chirho\"\n";

fn tmp_dir_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let dir_chirho = std::env::temp_dir().join(format!(
        "cairn-phi-e2e-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    dir_chirho
}

fn request_context_chirho() -> RequestContextChirho {
    RequestContextChirho {
        user_principal_chirho: SUBJECT_CHIRHO.to_string(),
        app_chirho: "phi-tree-app".to_string(),
        owner_principal_chirho: "owner/phi-tree-chirho".to_string(),
        client_id_chirho: "browser-session-chirho".to_string(),
        token_hash_chirho: "token-phi-tree-chirho".to_string(),
        price_book_chirho: None,
        billing_policy_chirho: None,
        key_limit_chirho: None,
    }
}

fn role_dir_chirho(app_chirho: &Path, role_chirho: &str) -> PathBuf {
    app_chirho
        .join("dags_chirho/save_chirho/nodes_chirho")
        .join(role_chirho)
}

fn add_impl_role_chirho(app_chirho: &Path, role_chirho: &str) -> PathBuf {
    let dir_chirho = role_dir_chirho(app_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(
        app_chirho.join("src").join(format!("{role_chirho}.rs")),
        "// guest source placeholder\n",
    )
    .unwrap();
    symlink_chirho(
        format!("../../../../src/{role_chirho}.rs"),
        dir_chirho.join(format!("{role_chirho}.rs")),
    )
    .unwrap();
    dir_chirho
}

fn private_out_dir_chirho(dir_chirho: &Path, name_chirho: &str, type_chirho: &str) {
    let out_chirho = dir_chirho.join(format!("out-{name_chirho}-{type_chirho}-chirho"));
    std::fs::create_dir_all(&out_chirho).unwrap();
    // The marker sits in the PRODUCER's out dir and is read through each consumer's symlink —
    // the convention the perffection workspace tree uses today.
    std::fs::write(
        out_chirho.join("private-edge-chirho.toml"),
        PRIVATE_EDGE_CARD_CHIRHO,
    )
    .unwrap();
}

fn wire_chirho(
    consumer_chirho: &Path,
    name_chirho: &str,
    type_chirho: &str,
    producer_role_chirho: &str,
    out_name_chirho: &str,
) {
    symlink_chirho(
        format!("../{producer_role_chirho}/out-{out_name_chirho}-{type_chirho}-chirho"),
        consumer_chirho.join(format!("in-{name_chirho}-{type_chirho}-chirho")),
    )
    .unwrap();
}

fn wire_from_surface_chirho(consumer_chirho: &Path, name_chirho: &str) {
    symlink_chirho(
        format!("../../surface_chirho/in-request-{REQUEST_CHIRHO}-chirho"),
        consumer_chirho.join(format!("in-{name_chirho}-{REQUEST_CHIRHO}-chirho")),
    )
    .unwrap();
}

/// request -> build_write -> write_state (blessed write-store) -> render_saved -> merge.saved
/// request -> render_rejected -> merge.rejected ; surface out <- merge.page
fn write_branching_tree_chirho(app_chirho: &Path) {
    std::fs::create_dir_all(app_chirho.join("src")).unwrap();
    let dag_chirho = app_chirho.join("dags_chirho/save_chirho");
    std::fs::create_dir_all(
        dag_chirho
            .join("surface_chirho")
            .join(format!("in-request-{REQUEST_CHIRHO}-chirho")),
    )
    .unwrap();

    let build_chirho = add_impl_role_chirho(app_chirho, "build_write_chirho");
    wire_from_surface_chirho(&build_chirho, "request");
    private_out_dir_chirho(&build_chirho, "request", STATE_CHIRHO);

    let write_chirho = role_dir_chirho(app_chirho, "write_state_chirho");
    std::fs::create_dir_all(&write_chirho).unwrap();
    let contract_hash_chirho =
        cairn_tree_build_chirho::blessed_catalog_chirho::lookup_blessed_contract_chirho(
            "write-store",
        )
        .expect("write-store is catalogued")
        .contract_hash_chirho();
    std::fs::write(
        write_chirho.join("blessed-contract-chirho.toml"),
        format!(
            "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"page-state-chirho\"\nintent_chirho = \"Append one validated page version for the signed-in viewer.\"\n"
        ),
    )
    .unwrap();
    wire_chirho(
        &write_chirho,
        "request",
        STATE_CHIRHO,
        "build_write_chirho",
        "request",
    );
    private_out_dir_chirho(&write_chirho, "state", STATE_CHIRHO);

    let saved_chirho = add_impl_role_chirho(app_chirho, "render_saved_chirho");
    wire_chirho(
        &saved_chirho,
        "state",
        STATE_CHIRHO,
        "write_state_chirho",
        "state",
    );
    private_out_dir_chirho(&saved_chirho, "page", HTML_CHIRHO);

    let rejected_chirho = add_impl_role_chirho(app_chirho, "render_rejected_chirho");
    wire_from_surface_chirho(&rejected_chirho, "request");
    private_out_dir_chirho(&rejected_chirho, "page", HTML_CHIRHO);

    let merge_chirho = role_dir_chirho(app_chirho, "merge_chirho");
    std::fs::create_dir_all(&merge_chirho).unwrap();
    std::fs::write(
        merge_chirho.join("builtin-phi-chirho.toml"),
        "schema_chirho = \"builtin-phi-v1-chirho\"\nintent_chirho = \"The saved page or the rejection view: exactly one branch is live.\"\n",
    )
    .unwrap();
    wire_chirho(
        &merge_chirho,
        "saved",
        HTML_CHIRHO,
        "render_saved_chirho",
        "page",
    );
    wire_chirho(
        &merge_chirho,
        "rejected",
        HTML_CHIRHO,
        "render_rejected_chirho",
        "page",
    );
    private_out_dir_chirho(&merge_chirho, "page", HTML_CHIRHO);
    symlink_chirho(
        format!("../nodes_chirho/merge_chirho/out-page-{HTML_CHIRHO}-chirho"),
        dag_chirho
            .join("surface_chirho")
            .join(format!("out-page-{HTML_CHIRHO}-chirho")),
    )
    .unwrap();
}

fn descriptor_chirho() -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: "phi-tree-app".to_string(),
        owner_chirho: "owner/phi-tree-chirho".to_string(),
        package_chirho: "phi-tree-app-chirho".to_string(),
        request_access_policy_chirho: Some("authenticated".to_string()),
        root_chirho: AppRootChirho {
            dag_chirho: "save_chirho".to_string(),
            input_mode_chirho: "private-blob-ref".to_string(),
            subject_chirho: Some("request-user-chirho".to_string()),
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: Some("accept-body".to_string()),
            route_label_chirho: "save-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    }
}

/// Swap the cargo-example guests for WAT files (cargo-free), keeping every other emitted byte.
/// `build_write` emits the skipped stone (the form is invalid), `render_rejected` upcases the
/// request, `render_saved` would upcase but never runs live.
fn host_ready_chirho(
    mut manifest_chirho: serde_json::Value,
    guests_chirho: &Path,
) -> serde_json::Value {
    let upcase_wat_chirho = include_str!("../../../examples-chirho/upcase-chirho.wat");
    std::fs::write(guests_chirho.join("skipped.wat"), skipped_wat_chirho()).unwrap();
    std::fs::write(guests_chirho.join("upcase.wat"), upcase_wat_chirho).unwrap();
    for node_chirho in manifest_chirho["nodes_chirho"].as_array_mut().unwrap() {
        if node_chirho["source_chirho"]["kind_chirho"] != "cargo-example-chirho" {
            continue;
        }
        let (file_chirho, entry_chirho) = match node_chirho["id_chirho"].as_str().unwrap() {
            "build_write" => ("skipped.wat", "emit_skipped_chirho"),
            "render_saved" | "render_rejected" => ("upcase.wat", "upcase_chirho"),
            other_chirho => panic!("unexpected cargo-example node {other_chirho}"),
        };
        node_chirho["source_chirho"] = serde_json::json!({
            "kind_chirho": "path-chirho",
            "path_chirho": guests_chirho.join(file_chirho),
        });
        node_chirho["entry_chirho"] = serde_json::Value::String(entry_chirho.to_string());
    }
    manifest_chirho
}

#[test]
fn branching_private_tree_emits_builds_and_runs_through_the_phi_chirho() {
    let app_chirho = tmp_dir_chirho("app");
    let guests_chirho = tmp_dir_chirho("guests");
    let root_chirho = tmp_dir_chirho("root");
    write_branching_tree_chirho(&app_chirho);

    let tree_chirho = walk_app_tree_chirho(&app_chirho);
    let findings_chirho = check_app_tree_chirho(&tree_chirho);
    assert!(
        findings_chirho.is_empty(),
        "the branching tree must check clean: {findings_chirho:?}"
    );
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho()).unwrap();
    let merge_chirho = emitted_chirho["nodes_chirho"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node_chirho| node_chirho["id_chirho"] == "merge")
        .expect("phi node emitted");
    assert_eq!(
        merge_chirho["source_chirho"]["kind_chirho"],
        "builtin-phi-chirho"
    );

    let manifest_chirho: AppSourceManifestChirho =
        serde_json::from_value(host_ready_chirho(emitted_chirho, &guests_chirho))
            .expect("the emitted phi manifest parses as the engine's app-source model");
    let artifacts_chirho = build_app_source_manifest_artifacts_chirho(
        &root_chirho,
        &guests_chirho,
        &manifest_chirho,
        None,
    )
    .expect("named phi ports and the phi output binding build into DAG + module artifacts");
    let dag_hash_chirho = artifacts_chirho
        .dag_hashes_chirho
        .get("save_dag")
        .expect("save_dag built")
        .clone();
    assert!(
        artifacts_chirho
            .module_hashes_chirho
            .contains_key("save_module"),
        "the module binds the phi's page port as the response"
    );
    let dag_chirho: DagChirho =
        store_chirho::get_object_chirho(&root_chirho, &dag_hash_chirho).unwrap();
    assert_eq!(dag_chirho.edges_chirho.len(), 4);
    assert!(
        dag_chirho
            .edges_chirho
            .iter()
            .all(|edge_chirho| edge_chirho.privacy_chirho.is_some()),
        "every edge of the workspace-shaped tree is private"
    );

    let request_chirho = b"draft: hello";
    let context_chirho = request_context_chirho();
    let report_chirho = run_dag_with_context_and_private_input_chirho(
        &root_chirho,
        &dag_chirho,
        SUBJECT_CHIRHO,
        request_chirho,
        Some(&context_chirho),
    )
    .expect("the invalid form takes the rejection branch through the phi");
    assert_eq!(report_chirho.payload_chirho, b"DRAFT: HELLO");
    assert!(
        cas_chirho::get_chirho(&root_chirho, &report_chirho.payload_hash_chirho).is_err(),
        "the rendered rejection view must not rest in public CAS"
    );
    assert!(
        cas_chirho::get_chirho(&root_chirho, &cas_chirho::hash_chirho(request_chirho)).is_err(),
        "the submitted draft must not rest in public CAS"
    );
    assert!(
        dag_private_value_chirho::verified_private_dag_value_record_for_subject_chirho(
            &root_chirho,
            SUBJECT_CHIRHO,
            &report_chirho.payload_hash_chirho,
        )
        .unwrap()
        .is_some()
    );

    let write_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "write_state_chirho")
        .expect("the blessed write node ran (as skipped)");
    let write_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, &write_run_chirho.run_chirho)
            .unwrap()
            .unwrap();
    assert!(
        matches!(
            write_result_chirho.status_chirho,
            RunStatusChirho::SkippedChirho { .. }
        ),
        "the blessed write was skipped without invocation"
    );
    assert_eq!(write_result_chirho.effects_chirho.len(), 1);
    let skipped_hash_chirho = cache_chirho::skipped_stone_hash_chirho(&root_chirho).unwrap();
    assert_eq!(
        write_result_chirho.effects_chirho[0].request_chirho, skipped_hash_chirho,
        "the only effect record is the signed skip, whose request is the stone"
    );
    let phi_run_chirho = report_chirho
        .node_runs_chirho
        .iter()
        .find(|run_chirho| run_chirho.node_name_chirho == "merge_chirho")
        .expect("the phi ran");
    let phi_result_chirho =
        cache_chirho::load_result_chirho(&root_chirho, &phi_run_chirho.run_chirho)
            .unwrap()
            .unwrap();
    assert_eq!(
        phi_result_chirho.outputs_chirho.get("page"),
        Some(&report_chirho.payload_hash_chirho),
        "the phi's named output port carries the live branch's value"
    );
    crate::verify_chirho::verify_run_cache_chirho(&root_chirho).expect("run cache verifies");

    for dir_chirho in [&app_chirho, &guests_chirho, &root_chirho] {
        let _ = std::fs::remove_dir_all(dir_chirho);
    }
}
