// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. — John 3:16 (KJV)

//! A branching tree (request -> write branch | rejection branch -> phi) checks clean and lowers to
//! named-port edges; every phi finding code fires on its own broken variant; emit refuses the
//! shapes check refuses.

use crate::check_chirho::{check_app_tree_chirho, FindingChirho};
use crate::emit_chirho::{emit_manifest_chirho, AppDescriptorChirho, AppRootChirho};
use crate::tree_chirho::{walk_app_tree_chirho, PHI_CARD_SCHEMA_CHIRHO};
use serde_json::Value;
use std::os::unix::fs::symlink as symlink_chirho;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const HTML_CHIRHO: &str = "html_partial_v1";
const REQUEST_CHIRHO: &str = "http_request_v1";
const STATE_CHIRHO: &str = "state_v1";

fn tmp_root_chirho(label_chirho: &str) -> PathBuf {
    static COUNTER_CHIRHO: AtomicU64 = AtomicU64::new(0);
    let n_chirho = COUNTER_CHIRHO.fetch_add(1, Ordering::Relaxed);
    let root_chirho = std::env::temp_dir().join(format!(
        "tb-phi-{label_chirho}-{}-{n_chirho}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root_chirho);
    std::fs::create_dir_all(root_chirho.join("src")).unwrap();
    root_chirho
}

fn codes_chirho(findings_chirho: &[FindingChirho]) -> Vec<String> {
    findings_chirho
        .iter()
        .map(|finding_chirho| finding_chirho.code_chirho.clone())
        .collect()
}

fn dag_dir_chirho(root_chirho: &Path) -> PathBuf {
    root_chirho.join("dags_chirho/save_chirho")
}

fn role_dir_chirho(root_chirho: &Path, role_chirho: &str) -> PathBuf {
    dag_dir_chirho(root_chirho)
        .join("nodes_chirho")
        .join(role_chirho)
}

/// An implementation role whose `.rs` link resolves to a real file under `src/`.
fn add_impl_role_chirho(root_chirho: &Path, role_chirho: &str) -> PathBuf {
    let dir_chirho = role_dir_chirho(root_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(
        root_chirho.join("src").join(format!("{role_chirho}.rs")),
        "// test impl\n",
    )
    .unwrap();
    symlink_chirho(
        format!("../../../../src/{role_chirho}.rs"),
        dir_chirho.join(format!("{role_chirho}.rs")),
    )
    .unwrap();
    dir_chirho
}

fn add_write_role_chirho(root_chirho: &Path, role_chirho: &str) -> PathBuf {
    let dir_chirho = role_dir_chirho(root_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    let contract_hash_chirho =
        crate::blessed_catalog_chirho::lookup_blessed_contract_chirho("write-store")
            .expect("write-store is catalogued")
            .contract_hash_chirho();
    std::fs::write(
        dir_chirho.join("blessed-contract-chirho.toml"),
        format!(
            "schema_chirho = \"blessed-card-v2-chirho\"\ncontract_chirho = \"write-store\"\ncontract_hash_chirho = \"{contract_hash_chirho}\"\nscope_chirho = \"scope-chirho\"\nintent_chirho = \"Append one validated page version.\"\n"
        ),
    )
    .unwrap();
    dir_chirho
}

fn phi_card_chirho(schema_chirho: &str, intent_chirho: &str) -> String {
    format!("schema_chirho = \"{schema_chirho}\"\nintent_chirho = \"{intent_chirho}\"\n")
}

fn add_phi_role_chirho(root_chirho: &Path, role_chirho: &str, card_chirho: &str) -> PathBuf {
    let dir_chirho = role_dir_chirho(root_chirho, role_chirho);
    std::fs::create_dir_all(&dir_chirho).unwrap();
    std::fs::write(dir_chirho.join("builtin-phi-chirho.toml"), card_chirho).unwrap();
    dir_chirho
}

fn out_dir_chirho(dir_chirho: &Path, name_chirho: &str, type_chirho: &str) -> PathBuf {
    let out_chirho = dir_chirho.join(format!("out-{name_chirho}-{type_chirho}-chirho"));
    std::fs::create_dir_all(&out_chirho).unwrap();
    out_chirho
}

/// `<consumer>/in-<name>-<type>-chirho -> ../<producer>/out-<out_name>-<type>-chirho`.
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

fn wire_from_surface_chirho(consumer_chirho: &Path, name_chirho: &str, type_chirho: &str) {
    symlink_chirho(
        format!("../../surface_chirho/in-request-{type_chirho}-chirho"),
        consumer_chirho.join(format!("in-{name_chirho}-{type_chirho}-chirho")),
    )
    .unwrap();
}

/// request -> build_write -> write_state -> render_saved -> merge.saved
/// request -> render_rejected -> merge.rejected ; surface out <- merge.page
fn branching_tree_chirho(label_chirho: &str) -> PathBuf {
    let root_chirho = tmp_root_chirho(label_chirho);
    let dag_chirho = dag_dir_chirho(&root_chirho);
    std::fs::create_dir_all(
        dag_chirho
            .join("surface_chirho")
            .join(format!("in-request-{REQUEST_CHIRHO}-chirho")),
    )
    .unwrap();

    let build_chirho = add_impl_role_chirho(&root_chirho, "build_write_chirho");
    wire_from_surface_chirho(&build_chirho, "request", REQUEST_CHIRHO);
    out_dir_chirho(&build_chirho, "request", STATE_CHIRHO);

    let write_chirho = add_write_role_chirho(&root_chirho, "write_state_chirho");
    wire_chirho(
        &write_chirho,
        "request",
        STATE_CHIRHO,
        "build_write_chirho",
        "request",
    );
    out_dir_chirho(&write_chirho, "state", STATE_CHIRHO);

    let saved_chirho = add_impl_role_chirho(&root_chirho, "render_saved_chirho");
    wire_chirho(
        &saved_chirho,
        "state",
        STATE_CHIRHO,
        "write_state_chirho",
        "state",
    );
    out_dir_chirho(&saved_chirho, "page", HTML_CHIRHO);

    let rejected_chirho = add_impl_role_chirho(&root_chirho, "render_rejected_chirho");
    wire_from_surface_chirho(&rejected_chirho, "request", REQUEST_CHIRHO);
    out_dir_chirho(&rejected_chirho, "page", HTML_CHIRHO);

    let merge_chirho = add_phi_role_chirho(
        &root_chirho,
        "merge_chirho",
        &phi_card_chirho(PHI_CARD_SCHEMA_CHIRHO, "Exactly one branch is live."),
    );
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
    out_dir_chirho(&merge_chirho, "page", HTML_CHIRHO);

    symlink_chirho(
        format!("../nodes_chirho/merge_chirho/out-page-{HTML_CHIRHO}-chirho"),
        dag_chirho
            .join("surface_chirho")
            .join(format!("out-page-{HTML_CHIRHO}-chirho")),
    )
    .unwrap();
    root_chirho
}

fn descriptor_chirho() -> AppDescriptorChirho {
    AppDescriptorChirho {
        app_chirho: "phi-app".to_string(),
        owner_chirho: "owner/phi-chirho".to_string(),
        package_chirho: "phi-app-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            dag_chirho: "save_chirho".to_string(),
            input_mode_chirho: "plain".to_string(),
            subject_chirho: None,
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

/// One way to break the clean fixture, applied to its root.
type BreakChirho = Box<dyn Fn(&Path)>;

fn findings_for_chirho(root_chirho: &Path) -> Vec<String> {
    codes_chirho(&check_app_tree_chirho(&walk_app_tree_chirho(root_chirho)))
}

fn node_by_id_chirho<'a>(manifest_chirho: &'a Value, id_chirho: &str) -> &'a Value {
    manifest_chirho["nodes_chirho"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node_chirho| node_chirho["id_chirho"] == id_chirho)
        .unwrap_or_else(|| panic!("node {id_chirho} emitted"))
}

fn edge_set_chirho(manifest_chirho: &Value) -> Vec<(String, String, String, String)> {
    let mut edges_chirho: Vec<_> = manifest_chirho["dags_chirho"][0]["edges_chirho"]
        .as_array()
        .unwrap()
        .iter()
        .map(|edge_chirho| {
            (
                edge_chirho["from_node_chirho"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                edge_chirho["from_port_chirho"]
                    .as_str()
                    .unwrap()
                    .to_string(),
                edge_chirho["to_node_chirho"].as_str().unwrap().to_string(),
                edge_chirho["to_port_chirho"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    edges_chirho.sort();
    edges_chirho
}

#[test]
fn branching_phi_tree_checks_clean_and_lowers_named_ports_chirho() {
    let root_chirho = branching_tree_chirho("clean");
    assert_eq!(
        findings_for_chirho(&root_chirho),
        Vec::<String>::new(),
        "the branching tree must check clean"
    );

    let manifest_chirho =
        emit_manifest_chirho(&walk_app_tree_chirho(&root_chirho), &descriptor_chirho()).unwrap();
    let merge_chirho = node_by_id_chirho(&manifest_chirho, "merge");
    assert_eq!(merge_chirho["entry_chirho"], "phi_chirho");
    assert_eq!(merge_chirho["fuel_chirho"], 0);
    assert!(
        merge_chirho.get("capabilities_chirho").is_none(),
        "a phi carries no capability key at all"
    );
    assert_eq!(
        merge_chirho["source_chirho"]["kind_chirho"], "builtin-phi-chirho",
        "the manifest tag keeps the suffix, as cargo-example-chirho does"
    );
    assert_eq!(
        merge_chirho["source_chirho"]["input_ports_chirho"],
        serde_json::json!(["rejected", "saved"]),
        "phi input ports are the in- connection names in connection-name order"
    );
    assert_eq!(merge_chirho["source_chirho"]["output_port_chirho"], "page");

    assert_eq!(
        edge_set_chirho(&manifest_chirho),
        vec![
            ("build_write", "out", "write_state", "in"),
            ("render_rejected", "out", "merge", "rejected"),
            ("render_saved", "out", "merge", "saved"),
            ("write_state", "out", "render_saved", "in"),
        ]
        .into_iter()
        .map(|(a_chirho, b_chirho, c_chirho, d_chirho)| {
            (
                a_chirho.to_string(),
                b_chirho.to_string(),
                c_chirho.to_string(),
                d_chirho.to_string(),
            )
        })
        .collect::<Vec<_>>()
    );

    let module_chirho = &manifest_chirho["modules_chirho"][0];
    assert_eq!(
        module_chirho["input_bindings_chirho"][0]["node_chirho"], "build_write",
        "the request binds to the FIRST surface-wired role in sorted order"
    );
    assert_eq!(
        module_chirho["input_bindings_chirho"][0]["node_port_chirho"],
        "in"
    );
    assert_eq!(
        module_chirho["output_bindings_chirho"][0]["node_chirho"],
        "merge"
    );
    assert_eq!(
        module_chirho["output_bindings_chirho"][0]["node_port_chirho"], "page",
        "the response reads the phi's named output port"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn every_phi_finding_code_fires_on_its_own_broken_variant_chirho() {
    let cases_chirho: Vec<(&str, BreakChirho, &str)> = vec![
        (
            "bad-schema",
            Box::new(|root_chirho| {
                std::fs::write(
                    role_dir_chirho(root_chirho, "merge_chirho").join("builtin-phi-chirho.toml"),
                    phi_card_chirho("builtin-phi-v0-chirho", "x"),
                )
                .unwrap();
            }),
            "phi-card-invalid-chirho",
        ),
        (
            "unknown-field",
            Box::new(|root_chirho| {
                std::fs::write(
                    role_dir_chirho(root_chirho, "merge_chirho").join("builtin-phi-chirho.toml"),
                    format!(
                        "{}fuel_chirho = 7\n",
                        phi_card_chirho(PHI_CARD_SCHEMA_CHIRHO, "x")
                    ),
                )
                .unwrap();
            }),
            "phi-card-invalid-chirho",
        ),
        (
            "empty-intent",
            Box::new(|root_chirho| {
                std::fs::write(
                    role_dir_chirho(root_chirho, "merge_chirho").join("builtin-phi-chirho.toml"),
                    phi_card_chirho(PHI_CARD_SCHEMA_CHIRHO, "  "),
                )
                .unwrap();
            }),
            "phi-card-invalid-chirho",
        ),
        (
            "one-input",
            Box::new(|root_chirho| {
                std::fs::remove_file(
                    role_dir_chirho(root_chirho, "merge_chirho")
                        .join(format!("in-rejected-{HTML_CHIRHO}-chirho")),
                )
                .unwrap();
            }),
            "phi-inputs-too-few-chirho",
        ),
        (
            "two-outputs",
            Box::new(|root_chirho| {
                out_dir_chirho(
                    &role_dir_chirho(root_chirho, "merge_chirho"),
                    "second",
                    HTML_CHIRHO,
                );
            }),
            "phi-output-count-chirho",
        ),
        (
            "type-mismatch",
            Box::new(|root_chirho| {
                let merge_chirho = role_dir_chirho(root_chirho, "merge_chirho");
                std::fs::remove_file(merge_chirho.join(format!("in-saved-{HTML_CHIRHO}-chirho")))
                    .unwrap();
                // A saved wire of a DIFFERENT type than the phi output, from a producer of that type.
                wire_chirho(
                    &merge_chirho,
                    "saved",
                    STATE_CHIRHO,
                    "write_state_chirho",
                    "state",
                );
            }),
            "phi-port-type-mismatch-chirho",
        ),
        (
            "surface-wired",
            Box::new(|root_chirho| {
                let merge_chirho = role_dir_chirho(root_chirho, "merge_chirho");
                std::fs::remove_file(
                    merge_chirho.join(format!("in-rejected-{HTML_CHIRHO}-chirho")),
                )
                .unwrap();
                wire_from_surface_chirho(&merge_chirho, "rejected", REQUEST_CHIRHO);
            }),
            "phi-input-not-a-role-wire-chirho",
        ),
        (
            "pinned",
            Box::new(|root_chirho| {
                let merge_chirho = role_dir_chirho(root_chirho, "merge_chirho");
                std::fs::remove_file(
                    merge_chirho.join(format!("in-rejected-{HTML_CHIRHO}-chirho")),
                )
                .unwrap();
                let pin_chirho = merge_chirho.join(format!("in-rejected-{HTML_CHIRHO}-chirho"));
                std::fs::create_dir_all(&pin_chirho).unwrap();
                std::fs::write(pin_chirho.join("content_chirho.html"), "<p>pinned</p>").unwrap();
            }),
            "phi-input-not-a-role-wire-chirho",
        ),
        (
            "overbound-phi",
            Box::new(|root_chirho| {
                let merge_chirho = role_dir_chirho(root_chirho, "merge_chirho");
                symlink_chirho(
                    "../../../../src/render_saved_chirho.rs",
                    merge_chirho.join("merge_chirho.rs"),
                )
                .unwrap();
            }),
            "role-overbound-chirho",
        ),
        (
            "overbound-blessed",
            Box::new(|root_chirho| {
                let write_chirho = role_dir_chirho(root_chirho, "write_state_chirho");
                symlink_chirho(
                    "../../../../src/render_saved_chirho.rs",
                    write_chirho.join("write_state_chirho.rs"),
                )
                .unwrap();
            }),
            "role-overbound-chirho",
        ),
    ];
    for (label_chirho, break_chirho, expected_chirho) in cases_chirho {
        let root_chirho = branching_tree_chirho(label_chirho);
        assert!(
            findings_for_chirho(&root_chirho).is_empty(),
            "{label_chirho}: fixture must start clean"
        );
        break_chirho(&root_chirho);
        let codes_chirho = findings_for_chirho(&root_chirho);
        assert!(
            codes_chirho
                .iter()
                .any(|code_chirho| code_chirho == expected_chirho),
            "{label_chirho}: expected {expected_chirho} in {codes_chirho:?}"
        );
        let emitted_chirho =
            emit_manifest_chirho(&walk_app_tree_chirho(&root_chirho), &descriptor_chirho());
        if expected_chirho != "phi-port-type-mismatch-chirho"
            && expected_chirho != "phi-input-not-a-role-wire-chirho"
        {
            assert!(
                emitted_chirho.is_err(),
                "{label_chirho}: emit must refuse what check refuses"
            );
        }
        let _ = std::fs::remove_dir_all(&root_chirho);
    }
}

#[test]
fn emit_refuses_a_surface_wired_phi_as_entry_node_chirho() {
    let root_chirho = branching_tree_chirho("phi-entry");
    let merge_chirho = role_dir_chirho(&root_chirho, "merge_chirho");
    std::fs::remove_file(merge_chirho.join(format!("in-rejected-{HTML_CHIRHO}-chirho"))).unwrap();
    wire_from_surface_chirho(&merge_chirho, "rejected", HTML_CHIRHO);
    let error_chirho =
        emit_manifest_chirho(&walk_app_tree_chirho(&root_chirho), &descriptor_chirho())
            .expect_err("a phi wired from the surface cannot be an entry node");
    assert!(
        error_chirho.contains("cannot be an entry node"),
        "{error_chirho}"
    );
    let _ = std::fs::remove_dir_all(&root_chirho);
}
