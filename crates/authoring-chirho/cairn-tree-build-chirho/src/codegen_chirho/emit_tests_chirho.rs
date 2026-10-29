// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

//! Golden test: tree-build emits the manifest the hand-proven one matches (normalized so node /
//! edge / binding ORDER never causes a false diff — only structure and values are pinned).

use super::*;
use crate::tree_chirho::walk_app_tree_chirho;
use serde_json::Value;

fn demo_app_root_chirho() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho/tree-contact-chirho")
}

/// Sort every array of objects by its serialized form so order is irrelevant in comparison.
fn normalize_chirho(value_chirho: &Value) -> Value {
    match value_chirho {
        Value::Array(items_chirho) => {
            let mut normalized_chirho: Vec<Value> =
                items_chirho.iter().map(normalize_chirho).collect();
            normalized_chirho.sort_by_key(|v_chirho| v_chirho.to_string());
            Value::Array(normalized_chirho)
        }
        Value::Object(map_chirho) => {
            let mut out_chirho = serde_json::Map::new();
            for (k_chirho, v_chirho) in map_chirho {
                out_chirho.insert(k_chirho.clone(), normalize_chirho(v_chirho));
            }
            Value::Object(out_chirho)
        }
        other_chirho => other_chirho.clone(),
    }
}

fn assert_no_parent_source_paths_chirho(value_chirho: &Value) {
    match value_chirho {
        Value::Object(map_chirho) => {
            if let Some(path_chirho) = map_chirho.get("path_chirho").and_then(Value::as_str) {
                assert!(
                    !path_chirho
                        .split('/')
                        .any(|segment_chirho| segment_chirho == ".."),
                    "emitted manifest source path must not escape app root: {path_chirho}"
                );
            }
            for child_chirho in map_chirho.values() {
                assert_no_parent_source_paths_chirho(child_chirho);
            }
        }
        Value::Array(items_chirho) => {
            for child_chirho in items_chirho {
                assert_no_parent_source_paths_chirho(child_chirho);
            }
        }
        _ => {}
    }
}

#[test]
fn emitted_manifest_matches_the_hand_proven_one_chirho() {
    let root_chirho = demo_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let hand_text_chirho =
        std::fs::read_to_string(root_chirho.join("receive-message-source-manifest-chirho.json"))
            .expect("hand manifest reads");
    let hand_chirho: Value = serde_json::from_str(&hand_text_chirho).expect("hand manifest parses");

    assert_eq!(
        normalize_chirho(&emitted_chirho),
        normalize_chirho(&hand_chirho),
        "tree-build emit must reproduce the hand-proven manifest (normalized)\nEMITTED:\n{}\n",
        serde_json::to_string_pretty(&emitted_chirho).unwrap()
    );
    assert_no_parent_source_paths_chirho(&emitted_chirho);
}

fn pizzeria_app_root_chirho() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho/tree-pizzeria-chirho")
}

fn app_builder_root_chirho() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../examples-chirho/tree-app-builder-chirho")
}

fn template_landing_root_chirho() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../examples-chirho/tree-template-landing-chirho")
}

/// The blessed-write order page: emit the place_order dag as a standalone root and prove it matches
/// the hand-proven Phase 1 manifest, including the blessed save_order reify node (capability +
/// template wasm). (The multi-route home+order emit is a separate step.)
#[test]
fn emitted_place_order_matches_hand_manifest_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = AppDescriptorChirho {
        app_chirho: "tree-pizzeria-order".to_string(),
        owner_chirho: "owner/replace-with-local-owner-principal".to_string(),
        package_chirho: "tree-pizzeria-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            dag_chirho: "place_order_chirho".to_string(),
            input_mode_chirho: "plain".to_string(),
            subject_chirho: None,
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: None,
            route_label_chirho: "place-order-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    };
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let hand_text_chirho =
        std::fs::read_to_string(root_chirho.join("place-order-source-manifest-chirho.json"))
            .expect("hand manifest reads");
    let hand_chirho: Value = serde_json::from_str(&hand_text_chirho).expect("hand manifest parses");

    assert_eq!(
        normalize_chirho(&emitted_chirho),
        normalize_chirho(&hand_chirho),
        "tree-build emit must reproduce the hand-proven place_order manifest (normalized)\nEMITTED:\n{}\n",
        serde_json::to_string_pretty(&emitted_chirho).unwrap()
    );
    assert_no_parent_source_paths_chirho(&emitted_chirho);
}

#[test]
fn emitted_template_landing_matches_checked_in_manifest_chirho() {
    let root_chirho = template_landing_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let checked_text_chirho =
        std::fs::read_to_string(root_chirho.join(".emitted-manifest-chirho.json"))
            .expect("checked-in manifest reads");
    let checked_chirho: Value =
        serde_json::from_str(&checked_text_chirho).expect("checked-in manifest parses");

    assert_eq!(
        normalize_chirho(&emitted_chirho),
        normalize_chirho(&checked_chirho),
        "tree-build emit must reproduce the checked-in template landing manifest (normalized)\nEMITTED:\n{}\n",
        serde_json::to_string_pretty(&emitted_chirho).unwrap()
    );
    let nodes_chirho = emitted_chirho["nodes_chirho"]
        .as_array()
        .expect("nodes array");
    let render_node_chirho = nodes_chirho
        .iter()
        .find(|node_chirho| node_chirho["id_chirho"] == "render_template_landing")
        .expect("template render node emitted");
    assert!(
        render_node_chirho.get("capabilities_chirho").is_none(),
        "template render node stays pure/zero-capability"
    );
    assert_no_parent_source_paths_chirho(&emitted_chirho);
}

/// Internal modules are reviewable source-manifest modules, but not deployable HTTP routes.
#[test]
fn emitted_internal_module_is_not_a_deploy_route_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = AppDescriptorChirho {
        app_chirho: "tree-pizzeria-internal".to_string(),
        owner_chirho: "owner/replace-with-local-owner-principal".to_string(),
        package_chirho: "tree-pizzeria-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            dag_chirho: "view_home_chirho".to_string(),
            input_mode_chirho: "plain".to_string(),
            subject_chirho: None,
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: None,
            route_label_chirho: "home-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![AppInternalModuleChirho {
            dag_chirho: "place_order_chirho".to_string(),
        }],
        asset_chirho: vec![],
    };
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    assert!(
        emitted_chirho["deploy_chirho"]
            .get("routes_chirho")
            .is_none(),
        "internal module does not create a public route array"
    );

    let modules_chirho = emitted_chirho["modules_chirho"]
        .as_array()
        .expect("modules array");
    let internal_module_chirho = modules_chirho
        .iter()
        .find(|module_chirho| module_chirho["id_chirho"] == "place_order_module")
        .expect("internal module emitted");
    assert!(
        internal_module_chirho["route_labels_chirho"]
            .as_array()
            .expect("route labels")
            .is_empty(),
        "internal module carries no public route label"
    );

    let nodes_chirho = emitted_chirho["nodes_chirho"]
        .as_array()
        .expect("nodes array");
    let save_order_chirho = nodes_chirho
        .iter()
        .find(|node_chirho| node_chirho["id_chirho"] == "save_order")
        .expect("internal blessed node emitted");
    assert_eq!(
        save_order_chirho["capabilities_chirho"][0],
        "write-store:orders-chirho"
    );
}

/// Multi-route: emit the whole pizzeria app from app-chirho.toml (home root + order WRITE route +
/// order-list QUERY route) and assert it lowers to three dags/modules, the blessed save_order
/// (write-store) and query_orders (query + paired identity) nodes, and a deploy with home as root
/// plus both named routes.
#[test]
fn emitted_pizzeria_app_has_home_order_and_order_list_routes_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let dags_chirho = emitted_chirho["dags_chirho"]
        .as_array()
        .expect("dags array");
    let modules_chirho = emitted_chirho["modules_chirho"]
        .as_array()
        .expect("modules array");
    assert_eq!(dags_chirho.len(), 3, "home + order + order-list dags");
    assert_eq!(modules_chirho.len(), 3, "home + order + order-list modules");

    let nodes_chirho = emitted_chirho["nodes_chirho"]
        .as_array()
        .expect("nodes array");
    let find_node_chirho = |id_chirho: &str| {
        nodes_chirho
            .iter()
            .find(|n_chirho| n_chirho["id_chirho"] == id_chirho)
            .unwrap_or_else(|| panic!("missing emitted node {id_chirho}"))
    };

    // Blessed write node: one write-store cap over the built-in inert template wasm.
    let save_chirho = find_node_chirho("save_order");
    assert_eq!(
        save_chirho["capabilities_chirho"][0],
        "write-store:orders-chirho"
    );
    assert_eq!(
        save_chirho["source_chirho"]["kind_chirho"],
        "builtin-node-template-chirho"
    );
    assert_eq!(
        save_chirho["source_chirho"]["template_chirho"],
        "node-template-chirho"
    );

    // Blessed query node: the metered-read cap PLUS the paired identity it runs as (order-independent).
    let query_chirho = find_node_chirho("query_orders");
    let caps_chirho: Vec<&str> = query_chirho["capabilities_chirho"]
        .as_array()
        .expect("query caps")
        .iter()
        .map(|cap_chirho| cap_chirho.as_str().expect("cap string"))
        .collect();
    assert_eq!(caps_chirho.len(), 2, "query node has query + identity caps");
    assert!(caps_chirho.contains(&"query:orders-chirho:order-query-caller:50"));
    assert!(caps_chirho.contains(
        &"identity:order-query-caller:source-manifest-client-chirho:source-manifest-token-chirho"
    ));
    assert_eq!(
        query_chirho["source_chirho"]["kind_chirho"],
        "builtin-node-template-chirho"
    );
    assert_eq!(
        query_chirho["source_chirho"]["template_chirho"],
        "node-template-chirho"
    );
    assert_no_parent_source_paths_chirho(&emitted_chirho);

    // Deploy: home root + order + order-list routes.
    let deploy_chirho = &emitted_chirho["deploy_chirho"];
    assert_eq!(
        deploy_chirho["root_chirho"]["id_chirho"],
        "view_home_module"
    );
    let route_names_chirho: Vec<&str> = deploy_chirho["routes_chirho"]
        .as_array()
        .expect("routes array")
        .iter()
        .map(|route_chirho| route_chirho["route_chirho"].as_str().expect("route name"))
        .collect();
    assert_eq!(route_names_chirho.len(), 2, "order + order-list routes");
    assert!(route_names_chirho.contains(&"order-chirho"));
    assert!(route_names_chirho.contains(&"order-list-chirho"));
}

#[test]
fn emitted_descriptor_assets_lower_to_source_manifest_assets_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = AppDescriptorChirho {
        app_chirho: "tree-pizzeria-assets".to_string(),
        owner_chirho: "owner/replace-with-local-owner-principal".to_string(),
        package_chirho: "tree-pizzeria-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            dag_chirho: "view_home_chirho".to_string(),
            input_mode_chirho: "plain".to_string(),
            subject_chirho: None,
            safe_metadata_chirho: vec![],
            request_body_policy_chirho: None,
            route_label_chirho: "home-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![],
        asset_chirho: vec![AppAssetChirho {
            name_chirho: "site-chirho.css".to_string(),
            path_chirho: "styles_chirho/site-chirho.css".to_string(),
            content_type_chirho: "text/css".to_string(),
        }],
    };
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let assets_chirho = emitted_chirho["assets_chirho"]
        .as_array()
        .expect("assets array");
    assert_eq!(assets_chirho.len(), 1);
    assert_eq!(assets_chirho[0]["name_chirho"], "site-chirho.css");
    assert_eq!(assets_chirho[0]["content_type_chirho"], "text/css");
    assert_eq!(
        assets_chirho[0]["source_chirho"]["kind_chirho"],
        "path-chirho"
    );
    assert_eq!(
        assets_chirho[0]["source_chirho"]["path_chirho"],
        "styles_chirho/site-chirho.css"
    );
}

#[test]
fn emitted_named_route_carries_no_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let route_chirho = descriptor_chirho
        .route_chirho
        .first_mut()
        .expect("pizzeria descriptor has a named route");
    route_chirho.request_body_policy_chirho = Some("no-body".to_string());
    let route_name_chirho = route_chirho.route_chirho.clone();

    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");
    let emitted_route_chirho = emitted_chirho["deploy_chirho"]["routes_chirho"]
        .as_array()
        .expect("routes array")
        .iter()
        .find(|candidate_chirho| candidate_chirho["route_chirho"] == route_name_chirho)
        .expect("selected route emitted");

    assert_eq!(
        emitted_route_chirho["request_body_policy_chirho"]["kind_chirho"],
        "no-body-chirho"
    );
}

#[test]
fn emitted_named_route_carries_accept_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let route_chirho = descriptor_chirho
        .route_chirho
        .first_mut()
        .expect("pizzeria descriptor has a named route");
    route_chirho.request_body_policy_chirho = Some("accept-body".to_string());
    let route_name_chirho = route_chirho.route_chirho.clone();

    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");
    let emitted_route_chirho = emitted_chirho["deploy_chirho"]["routes_chirho"]
        .as_array()
        .expect("routes array")
        .iter()
        .find(|candidate_chirho| candidate_chirho["route_chirho"] == route_name_chirho)
        .expect("selected route emitted");

    assert_eq!(
        emitted_route_chirho["request_body_policy_chirho"]["kind_chirho"],
        "accept-body-chirho"
    );
}

#[test]
fn emitted_named_route_refuses_unknown_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.route_chirho[0].request_body_policy_chirho =
        Some("sometimes-body".to_string());

    let error_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho)
        .expect_err("unknown route body policy must fail closed");
    assert!(error_chirho.contains("unknown request_body_policy_chirho 'sometimes-body'"));
}

#[test]
fn emitted_root_carries_no_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.root_chirho.request_body_policy_chirho = Some("no-body".to_string());

    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    assert_eq!(
        emitted_chirho["deploy_chirho"]["request_body_policy_chirho"]["kind_chirho"],
        "no-body-chirho"
    );
}

#[test]
fn emitted_root_carries_accept_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.root_chirho.request_body_policy_chirho = Some("accept-body".to_string());

    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    assert_eq!(
        emitted_chirho["deploy_chirho"]["request_body_policy_chirho"]["kind_chirho"],
        "accept-body-chirho"
    );
}

#[test]
fn emitted_root_refuses_unknown_body_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.root_chirho.request_body_policy_chirho = Some("sometimes-body".to_string());

    let error_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho)
        .expect_err("unknown root body policy must fail closed");
    assert!(error_chirho.contains("unknown request_body_policy_chirho 'sometimes-body'"));
}

#[test]
fn emitted_authenticated_request_access_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.request_access_policy_chirho = Some("authenticated".to_string());

    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");
    assert_eq!(
        emitted_chirho["deploy_chirho"]["request_access_policy_chirho"]["kind_chirho"],
        "authenticated-chirho"
    );
}

#[test]
fn emitted_request_access_policy_refuses_unknown_value_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let mut descriptor_chirho =
        load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    descriptor_chirho.request_access_policy_chirho = Some("sometimes-authenticated".to_string());

    let error_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho)
        .expect_err("unknown request access policy must fail closed");
    assert!(error_chirho.contains("unknown request_access_policy_chirho 'sometimes-authenticated'"));
}

#[test]
fn emitted_private_input_safe_metadata_policy_chirho() {
    let root_chirho = pizzeria_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = AppDescriptorChirho {
        app_chirho: "tree-pizzeria-safe-metadata".to_string(),
        owner_chirho: "owner/replace-with-local-owner-principal".to_string(),
        package_chirho: "tree-pizzeria-chirho".to_string(),
        request_access_policy_chirho: None,
        root_chirho: AppRootChirho {
            dag_chirho: "view_home_chirho".to_string(),
            input_mode_chirho: "private-blob-ref".to_string(),
            subject_chirho: Some("app/tree-pizzeria/intake".to_string()),
            safe_metadata_chirho: vec![AppSafeMetadataChirho {
                key_chirho: "request_kind_chirho".to_string(),
                allowed_values_chirho: vec!["visit_chirho".to_string()],
            }],
            request_body_policy_chirho: None,
            route_label_chirho: "home-chirho".to_string(),
            key_access_chirho: None,
        },
        route_chirho: vec![],
        internal_module_chirho: vec![],
        asset_chirho: vec![],
    };
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    assert_eq!(
        emitted_chirho["deploy_chirho"]["input_mode_chirho"]["kind_chirho"],
        "private-blob-ref-chirho"
    );
    assert_eq!(
        emitted_chirho["deploy_chirho"]["input_mode_chirho"]["safe_metadata_chirho"][0]
            ["key_chirho"],
        "request_kind_chirho"
    );
    assert_eq!(
        emitted_chirho["deploy_chirho"]["input_mode_chirho"]["safe_metadata_chirho"][0]
            ["allowed_values_chirho"][0],
        "visit_chirho"
    );
}

#[test]
fn emitted_app_builder_marks_private_input_and_intermediate_edges_chirho() {
    let root_chirho = app_builder_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let emitted_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");

    let build_route_chirho = emitted_chirho["deploy_chirho"]["routes_chirho"]
        .as_array()
        .expect("routes array")
        .iter()
        .find(|route_chirho| route_chirho["route_chirho"] == "build-chirho")
        .expect("build route emitted");
    assert_eq!(
        build_route_chirho["input_mode_chirho"]["kind_chirho"],
        "private-blob-ref-chirho"
    );
    assert_eq!(
        build_route_chirho["input_mode_chirho"]["subject_chirho"],
        "request-user-chirho"
    );

    let build_dag_chirho = emitted_chirho["dags_chirho"]
        .as_array()
        .expect("dags array")
        .iter()
        .find(|dag_chirho| dag_chirho["id_chirho"] == "view_build_dag")
        .expect("build dag emitted");
    let mut private_edges_chirho: Vec<String> = build_dag_chirho["edges_chirho"]
        .as_array()
        .expect("edges array")
        .iter()
        .filter(|edge_chirho| edge_chirho.get("privacy_chirho").is_some())
        .map(|edge_chirho| {
            format!(
                "{}->{}",
                edge_chirho["from_node_chirho"].as_str().unwrap(),
                edge_chirho["to_node_chirho"].as_str().unwrap()
            )
        })
        .collect();
    private_edges_chirho.sort();
    assert_eq!(
        private_edges_chirho,
        vec![
            "llm->validate".to_string(),
            "prompt->llm".to_string(),
            "validate->deploy".to_string()
        ]
    );
    for edge_chirho in build_dag_chirho["edges_chirho"].as_array().unwrap() {
        if edge_chirho.get("privacy_chirho").is_some() {
            assert_eq!(
                edge_chirho["privacy_chirho"]["kind_chirho"],
                "private-blob-ref-chirho"
            );
            assert_eq!(
                edge_chirho["privacy_chirho"]["subject_source_chirho"],
                "request-user-chirho"
            );
        }
    }
    assert_no_parent_source_paths_chirho(&emitted_chirho);
}

/// Byte-law pin: `emit_manifest_bytes_chirho` is the single source of the exact bytes the
/// `tree-build-chirho emit` CLI writes to stdout — pretty JSON plus one terminal newline. An
/// in-process reviewer (the credits-demo LocalPhaseB smoke) that hashes these bytes as its RAW
/// manifest provenance must reproduce the CLI's stdout byte-for-byte, so this pins the contract and
/// keeps the two producers from drifting (the class of defect a compact/no-newline reserialize
/// would silently introduce).
#[test]
fn emit_manifest_bytes_are_pretty_json_plus_one_terminal_newline_chirho() {
    let root_chirho = demo_app_root_chirho();
    let tree_chirho = walk_app_tree_chirho(&root_chirho);
    let descriptor_chirho = load_app_descriptor_chirho(&root_chirho).expect("app descriptor loads");
    let manifest_chirho = emit_manifest_chirho(&tree_chirho, &descriptor_chirho).expect("emit ok");
    let bytes_chirho =
        emit_manifest_bytes_chirho(&tree_chirho, &descriptor_chirho).expect("emit bytes ok");

    let mut expected_stdout_chirho = serde_json::to_string_pretty(&manifest_chirho)
        .expect("pretty json")
        .into_bytes();
    expected_stdout_chirho.push(b'\n');
    assert_eq!(bytes_chirho, expected_stdout_chirho);
    assert_eq!(bytes_chirho.last().copied(), Some(b'\n'));
    assert_ne!(
        bytes_chirho
            .get(bytes_chirho.len().wrapping_sub(2))
            .copied(),
        Some(b'\n'),
        "exactly one terminal newline"
    );
}
