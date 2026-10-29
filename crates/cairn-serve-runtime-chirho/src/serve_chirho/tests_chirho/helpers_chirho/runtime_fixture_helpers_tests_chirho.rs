// For God so loved the world, that He gave His only Begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

pub(super) const CONTACT_RENDER_PARTIAL_WAT_CHIRHO: &str = r#"
;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (data (i32.const 16) "<section data-contact-chirho=\"received\"><p>Thanks &mdash; your message was received and stored safely.</p></section>")
  (func (export "alloc_chirho") (param $len i32) (result i32)
(local $p i32)
global.get $heap_chirho
local.set $p
global.get $heap_chirho
local.get $len
i32.add
global.set $heap_chirho
local.get $p)
  (func (export "contact_render_chirho") (param $ptr i32) (param $len i32) (result i64)
(i64.or
  (i64.shl (i64.extend_i32_u (i32.const 16)) (i64.const 32))
  (i64.const 116))))
"#;

pub(super) const CONTACT_LIST_ROUTE_RENDER_WAT_CHIRHO: &str = r#"
;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (data (i32.const 16) "<section data-contact-list-chirho=\"ready\"><pre>")
  (data (i32.const 80) "</pre></section>")
  (func (export "alloc_chirho") (param $len i32) (result i32)
(local $p i32)
global.get $heap_chirho
local.set $p
global.get $heap_chirho
local.get $len
i32.add
global.set $heap_chirho
local.get $p)
  (func $copy_chirho (param $dst i32) (param $src i32) (param $len i32)
(local $i i32)
(block $done
  (loop $loop
    local.get $i
    local.get $len
    i32.ge_u
    br_if $done
    local.get $dst
    local.get $i
    i32.add
    local.get $src
    local.get $i
    i32.add
    i32.load8_u
    i32.store8
    local.get $i
    i32.const 1
    i32.add
    local.set $i
    br $loop)))
  (func (export "contact_list_chirho") (param $ptr i32) (param $len i32) (result i64)
(local $out i32)
(local $total i32)
global.get $heap_chirho
local.set $out
local.get $len
i32.const 63
i32.add
local.set $total
global.get $heap_chirho
local.get $total
i32.add
global.set $heap_chirho
local.get $out
i32.const 16
i32.const 47
call $copy_chirho
local.get $out
i32.const 47
i32.add
local.get $ptr
local.get $len
call $copy_chirho
local.get $out
i32.const 47
i32.add
local.get $len
i32.add
i32.const 80
i32.const 16
call $copy_chirho
(i64.or
  (i64.shl (i64.extend_i32_u (local.get $out)) (i64.const 32))
  (i64.extend_i32_u (local.get $total)))))
"#;

pub(super) const CONTACT_LIST_REQUEST_WAT_CHIRHO: &str = r#"
;; For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
(module
  (memory (export "memory") 1)
  (global $heap_chirho (mut i32) (i32.const 1024))
  (data (i32.const 16) "{\"prefix_chirho\":\"contacts-chirho\",\"limit_chirho\":50}")
  (func (export "alloc_chirho") (param $len i32) (result i32)
(local $p i32)
global.get $heap_chirho
local.set $p
global.get $heap_chirho
local.get $len
i32.add
global.set $heap_chirho
local.get $p)
  (func (export "contact_list_request_chirho") (param $ptr i32) (param $len i32) (result i64)
(i64.or
  (i64.shl (i64.extend_i32_u (i32.const 16)) (i64.const 32))
  (i64.const 53))))
"#;

pub(super) fn runtime_package_node_loader_smoke_chirho(
    base_url_chirho: &str,
    package_hash_chirho: &HashChirho,
) {
    if !node_available_for_smoke_chirho("runtime package JS loader smoke") {
        return;
    }
    let host_url_chirho = runtime_package_host_file_url_chirho();
    let code_chirho = format!(
        r#"
const hostUrlChirho = {host_url_chirho:?};
const packageChirho = {package_chirho:?};
const baseUrlChirho = {base_url_chirho:?};
const hostChirho = await import(hostUrlChirho);
const artifactChirho = await hostChirho.fetchRuntimePackageChirho(packageChirho, {{ baseUrlChirho }});
if (artifactChirho.manifest_chirho.entry_chirho !== "upcase_chirho") {{
  throw new Error("unexpected entry " + artifactChirho.manifest_chirho.entry_chirho);
}}
if (artifactChirho.executable_hash_chirho !== artifactChirho.manifest_chirho.executable_chirho) {{
  throw new Error("runtime-package host did not verify executable hash");
}}
const outputChirho = await hostChirho.runRuntimePackageTextChirho(
  packageChirho,
  "hello, runtime package",
  {{ baseUrlChirho }},
);
if (outputChirho !== "HELLO, RUNTIME PACKAGE") {{
  throw new Error("unexpected runtime-package output " + outputChirho);
}}
console.log(outputChirho);
"#,
        package_chirho = package_hash_chirho.0
    );
    let output_chirho = std::process::Command::new("node")
        .arg("--input-type=module")
        .arg("--eval")
        .arg(code_chirho)
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "runtime package JS loader smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output_chirho.stdout),
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output_chirho.stdout).trim(),
        "HELLO, RUNTIME PACKAGE"
    );
}

pub(super) fn run_htmx_lite_node_smoke_chirho(base_url_chirho: Option<&str>) -> bool {
    let Ok(version_chirho) = std::process::Command::new("node").arg("--version").output() else {
        eprintln!("skipping htmx-lite JS smoke: node not found");
        return false;
    };
    if !version_chirho.status.success() {
        eprintln!("skipping htmx-lite JS smoke: node --version failed");
        return false;
    }

    let smoke_path_chirho = workspace_root_for_test_chirho()
        .join("client-chirho/htmx-lite-smoke-chirho.mjs")
        .canonicalize()
        .unwrap();
    let mut command_chirho = std::process::Command::new("node");
    command_chirho.arg(smoke_path_chirho);
    if let Some(base_url_chirho) = base_url_chirho {
        command_chirho.env("CAIRN_CHIRHO_CONTACT_SMOKE_BASE_URL", base_url_chirho);
        command_chirho.env(
            "CAIRN_CONTACT_LIST_REFUSAL_BODIES_CHIRHO",
            serde_json::to_string(&[
                crate::serve_chirho::public_error_chirho::execution_refusal_plain_body_chirho(
                    cairn_chirho::dag_chirho::refusal_chirho::DagExecutionKnowledgeChirho::MayHaveExecutedChirho,
                    cairn_chirho::dag_chirho::refusal_chirho::DagExecutionAttemptOrdinalChirho::FirstChirho,
                ),
                crate::serve_chirho::public_error_chirho::execution_refusal_plain_body_chirho(
                    cairn_chirho::dag_chirho::refusal_chirho::DagExecutionKnowledgeChirho::PriorAttemptFailedChirho,
                    cairn_chirho::dag_chirho::refusal_chirho::DagExecutionAttemptOrdinalChirho::FailedReplayChirho,
                ),
            ])
            .unwrap(),
        );
    }
    let output_chirho = command_chirho.output().unwrap();
    assert!(
        output_chirho.status.success(),
        "htmx-lite JS smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output_chirho.stdout),
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output_chirho.stdout).trim(),
        "htmx-lite-ok"
    );
    true
}

pub(super) fn htmx_lite_node_smoke_chirho() -> bool {
    run_htmx_lite_node_smoke_chirho(None)
}

pub(super) fn htmx_lite_real_server_smoke_chirho(base_url_chirho: &str) -> bool {
    run_htmx_lite_node_smoke_chirho(Some(base_url_chirho))
}

pub(super) fn contact_example_manifest_path_chirho() -> std::path::PathBuf {
    workspace_root_for_test_chirho()
        .join("examples-chirho/contact-persisting-source-manifest-chirho.example.json")
}

pub(super) fn contact_example_manifest_for_owner_chirho(
    owner_chirho: &str,
) -> cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho {
    let manifest_text_chirho =
        std::fs::read_to_string(contact_example_manifest_path_chirho()).unwrap();
    let mut manifest_chirho: cairn_chirho::app_source_manifest_chirho::AppSourceManifestChirho =
        serde_json::from_str(&manifest_text_chirho).unwrap();
    manifest_chirho.owner_chirho = owner_chirho.to_string();
    manifest_chirho
}

pub(super) fn perffection_intake_manifest_path_chirho() -> std::path::PathBuf {
    workspace_root_for_test_chirho()
        .join("examples-chirho/perffection-intake-source-manifest-chirho.example.json")
}

fn workspace_root_for_test_chirho() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .to_path_buf()
}

pub(super) fn store_transform_dag_chirho(
    root_chirho: &std::path::Path,
    wasm_chirho: &str,
    entry_chirho: &str,
) -> HashChirho {
    let wasm_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, wasm_chirho.as_bytes()).unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: entry_chirho.to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: entry_chirho.to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: HashChirho("bytes".to_string()),
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

pub(super) fn deploy_transform_app_for_owner_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
    wasm_chirho: &str,
    entry_chirho: &str,
) -> HashChirho {
    let dag_chirho = store_transform_dag_chirho(root_chirho, wasm_chirho, entry_chirho);
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho.clone(), owner_chirho)
        .unwrap();
    dag_chirho
}

pub(super) fn deploy_transform_app_route_for_owner_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    wasm_chirho: &str,
    entry_chirho: &str,
) -> HashChirho {
    let dag_chirho = store_transform_dag_chirho(root_chirho, wasm_chirho, entry_chirho);
    app_chirho::deploy_app_route_chirho(
        root_chirho,
        app_chirho,
        route_chirho,
        dag_chirho.clone(),
        owner_chirho,
    )
    .unwrap();
    dag_chirho
}

pub(super) fn deploy_transform_app_route_with_request_body_policy_for_owner_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    route_chirho: &str,
    owner_chirho: &str,
    wasm_chirho: &str,
    entry_chirho: &str,
    request_body_policy_chirho: cairn_chirho::app_chirho::AppRouteRequestBodyPolicyChirho,
) -> HashChirho {
    let dag_chirho = store_transform_dag_chirho(root_chirho, wasm_chirho, entry_chirho);
    cairn_chirho::app_manifest_chirho::deploy_app_manifest_chirho(
        root_chirho,
        &cairn_chirho::app_manifest_chirho::AppDeployManifestChirho {
            request_access_policy_chirho: None,
            request_body_policy_chirho: None,
            schema_chirho: cairn_chirho::app_manifest_chirho::APP_DEPLOY_MANIFEST_SCHEMA_CHIRHO
                .to_string(),
            app_chirho: app_chirho.to_string(),
            owner_chirho: owner_chirho.to_string(),
            root_chirho: None,
            input_mode_chirho: None,
            response_content_type_chirho: None,
            params_chirho: None,
            routes_chirho: vec![
                cairn_chirho::app_manifest_chirho::AppDeployRouteManifestChirho {
                    route_chirho: route_chirho.to_string(),
                    source_chirho:
                        cairn_chirho::app_manifest_chirho::AppDeployDagSourceChirho::DagChirho {
                            hash_chirho: dag_chirho.clone(),
                        },
                    input_mode_chirho: None,
                    request_body_policy_chirho: Some(request_body_policy_chirho),
                    response_content_type_chirho: None,
                    params_chirho: None,
                    key_access_chirho: None,
                },
            ],
            runtime_packages_chirho: Vec::new(),
        },
    )
    .unwrap();
    dag_chirho
}

pub(super) fn set_plain_app_input_policy_for_test_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
) {
    app_chirho::set_app_input_policy_chirho(
        root_chirho,
        app_chirho,
        None,
        owner_chirho,
        app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();
}

pub(super) fn store_runtime_package_module_chirho(root_chirho: &std::path::Path) -> HashChirho {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let wasm_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        root_chirho,
        include_str!("../../../../../../examples-chirho/upcase-chirho.wat").as_bytes(),
    )
    .unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: "runtime_package_upcase_chirho".to_string(),
        impl_wasm_chirho: wasm_hash_chirho,
        entry_chirho: "upcase_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![],
        fuel_limit_chirho: 1_000_000,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let (_dag_chirho, dag_hash_chirho) = cairn_chirho::dag_author_chirho::build_dag_chirho(
        root_chirho,
        cairn_chirho::dag_author_chirho::DagBuildInputChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let (_module_chirho, module_hash_chirho) =
        cairn_chirho::dag_module_chirho::build_dag_module_chirho(
            root_chirho,
            cairn_chirho::dag_module_chirho::DagModuleBuildInputChirho {
                name_chirho: "runtime_package_upcase_chirho".to_string(),
                dag_chirho: dag_hash_chirho,
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "request".to_string(),
                        node_chirho: node_hash_chirho.clone(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "response".to_string(),
                        node_chirho: node_hash_chirho,
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: Vec::new(),
                metadata_chirho: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    module_hash_chirho
}

pub(super) fn store_runtime_package_effect_module_chirho(
    root_chirho: &std::path::Path,
) -> (HashChirho, HashChirho) {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let builtin_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:write-store-chirho").unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: "runtime_package_effect_chirho".to_string(),
        impl_wasm_chirho: builtin_hash_chirho,
        entry_chirho: "write_store_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![
            cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
                prefix_chirho: "runtime-package-secret-chirho".to_string(),
            },
        ],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    let (_dag_chirho, dag_hash_chirho) = cairn_chirho::dag_author_chirho::build_dag_chirho(
        root_chirho,
        cairn_chirho::dag_author_chirho::DagBuildInputChirho {
            nodes_chirho: vec![node_hash_chirho.clone()],
            edges_chirho: Vec::new(),
        },
    )
    .unwrap();
    let (_module_chirho, module_hash_chirho) =
        cairn_chirho::dag_module_chirho::build_dag_module_chirho(
            root_chirho,
            cairn_chirho::dag_module_chirho::DagModuleBuildInputChirho {
                name_chirho: "runtime_package_effect_chirho".to_string(),
                dag_chirho: dag_hash_chirho.clone(),
                version_chirho: "v1".to_string(),
                previous_module_chirho: None,
                input_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "request".to_string(),
                        node_chirho: node_hash_chirho.clone(),
                        node_port_chirho: "in".to_string(),
                    },
                ],
                output_bindings_chirho: vec![
                    cairn_chirho::dag_module_chirho::DagModuleBindingInputChirho {
                        public_name_chirho: "response".to_string(),
                        node_chirho: node_hash_chirho,
                        node_port_chirho: "out".to_string(),
                    },
                ],
                route_labels_chirho: Vec::new(),
                metadata_chirho: std::collections::BTreeMap::new(),
            },
        )
        .unwrap();
    (module_hash_chirho, dag_hash_chirho)
}

pub(super) fn store_write_effect_dag_chirho(
    root_chirho: &std::path::Path,
    key_chirho: &str,
) -> HashChirho {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let builtin_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:write-store-chirho").unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: "store_contact_ref_chirho".to_string(),
        impl_wasm_chirho: builtin_hash_chirho,
        entry_chirho: "write_store_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![
            cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
                prefix_chirho: key_chirho.to_string(),
            },
        ],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

pub(super) fn store_query_effect_dag_chirho(
    root_chirho: &std::path::Path,
    prefix_chirho: &str,
    caller_chirho: &str,
    max_rows_chirho: u64,
) -> HashChirho {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let builtin_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:query-chirho").unwrap();
    let node_chirho = cairn_chirho::model_chirho::NodeDefChirho {
        name_chirho: "query_contacts_chirho".to_string(),
        impl_wasm_chirho: builtin_hash_chirho,
        entry_chirho: "query_chirho".to_string(),
        inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "in".to_string(),
            schema_chirho: schema_hash_chirho.clone(),
        }],
        outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
            name_chirho: "out".to_string(),
            schema_chirho: schema_hash_chirho,
        }],
        capabilities_chirho: vec![
            cairn_chirho::model_chirho::CapabilityChirho::QueryChirho {
                prefix_chirho: prefix_chirho.to_string(),
                caller_chirho: caller_chirho.to_string(),
                max_rows_chirho,
            },
            cairn_chirho::model_chirho::CapabilityChirho::UserIdentityChirho {
                principal_chirho: caller_chirho.to_string(),
                client_id_chirho: String::new(),
                token_hash_chirho: String::new(),
            },
        ],
        fuel_limit_chirho: 0,
        ..Default::default()
    };
    let node_hash_chirho = store_chirho::put_object_chirho(root_chirho, &node_chirho).unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![node_hash_chirho],
            edges_chirho: vec![],
        },
    )
    .unwrap()
}

pub(super) fn store_contact_write_render_dag_chirho(root_chirho: &std::path::Path) -> HashChirho {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let identity_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        root_chirho,
        include_str!("../../../../../../examples-chirho/node-template-chirho.wat").as_bytes(),
    )
    .unwrap();
    let builtin_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:write-store-chirho").unwrap();
    let render_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        root_chirho,
        CONTACT_RENDER_PARTIAL_WAT_CHIRHO.as_bytes(),
    )
    .unwrap();
    let input_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "contact_record_chirho".to_string(),
            impl_wasm_chirho: identity_hash_chirho,
            entry_chirho: "node_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    let write_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "store_contact_chirho".to_string(),
            impl_wasm_chirho: builtin_hash_chirho,
            entry_chirho: "write_store_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            capabilities_chirho: vec![
                cairn_chirho::model_chirho::CapabilityChirho::WriteStoreChirho {
                    prefix_chirho: "contacts-chirho/latest".to_string(),
                },
            ],
            fuel_limit_chirho: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let render_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "contact_render_chirho".to_string(),
            impl_wasm_chirho: render_hash_chirho,
            entry_chirho: "contact_render_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![
                input_chirho.clone(),
                write_chirho.clone(),
                render_chirho.clone(),
            ],
            edges_chirho: vec![
                cairn_chirho::model_chirho::EdgeChirho {
                    from_node_chirho: input_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: write_chirho.clone(),
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
                cairn_chirho::model_chirho::EdgeChirho {
                    from_node_chirho: write_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: render_chirho,
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
            ],
        },
    )
    .unwrap()
}

pub(super) fn store_contact_list_route_dag_chirho(
    root_chirho: &std::path::Path,
    caller_chirho: &str,
) -> HashChirho {
    let schema_hash_chirho = cairn_chirho::cas_chirho::add_chirho(root_chirho, b"bytes").unwrap();
    let request_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        root_chirho,
        CONTACT_LIST_REQUEST_WAT_CHIRHO.as_bytes(),
    )
    .unwrap();
    let builtin_hash_chirho =
        cairn_chirho::cas_chirho::add_chirho(root_chirho, b"builtin:query-chirho").unwrap();
    let render_hash_chirho = cairn_chirho::cas_chirho::add_chirho(
        root_chirho,
        CONTACT_LIST_ROUTE_RENDER_WAT_CHIRHO.as_bytes(),
    )
    .unwrap();
    let request_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "contact_list_request_chirho".to_string(),
            impl_wasm_chirho: request_hash_chirho,
            entry_chirho: "contact_list_request_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    let query_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "query_contacts_chirho".to_string(),
            impl_wasm_chirho: builtin_hash_chirho,
            entry_chirho: "query_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            capabilities_chirho: vec![
                cairn_chirho::model_chirho::CapabilityChirho::QueryChirho {
                    prefix_chirho: "contacts-chirho".to_string(),
                    caller_chirho: caller_chirho.to_string(),
                    max_rows_chirho: 50,
                },
                cairn_chirho::model_chirho::CapabilityChirho::UserIdentityChirho {
                    principal_chirho: caller_chirho.to_string(),
                    client_id_chirho: String::new(),
                    token_hash_chirho: String::new(),
                },
            ],
            fuel_limit_chirho: 0,
            ..Default::default()
        },
    )
    .unwrap();
    let render_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &cairn_chirho::model_chirho::NodeDefChirho {
            name_chirho: "contact_list_render_chirho".to_string(),
            impl_wasm_chirho: render_hash_chirho,
            entry_chirho: "contact_list_chirho".to_string(),
            inputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "in".to_string(),
                schema_chirho: schema_hash_chirho.clone(),
            }],
            outputs_chirho: vec![cairn_chirho::model_chirho::PortChirho {
                name_chirho: "out".to_string(),
                schema_chirho: schema_hash_chirho,
            }],
            capabilities_chirho: Vec::new(),
            fuel_limit_chirho: 1_000_000,
            ..Default::default()
        },
    )
    .unwrap();
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![
                request_chirho.clone(),
                query_chirho.clone(),
                render_chirho.clone(),
            ],
            edges_chirho: vec![
                cairn_chirho::model_chirho::EdgeChirho {
                    from_node_chirho: request_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: query_chirho.clone(),
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
                cairn_chirho::model_chirho::EdgeChirho {
                    from_node_chirho: query_chirho,
                    from_port_chirho: "out".to_string(),
                    to_node_chirho: render_chirho,
                    to_port_chirho: "in".to_string(),
                    privacy_chirho: None,
                },
            ],
        },
    )
    .unwrap()
}

pub(super) fn scoped_headers_for_app_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
    user_secret_chirho: &str,
) -> (identity_chirho::IdentityRecordChirho, HeaderMap) {
    let user_chirho = identity_chirho::register_identity_with_credential_chirho(
        root_chirho,
        identity_chirho::PrincipalKindChirho::UserChirho,
        user_secret_chirho,
    )
    .unwrap();
    let client_chirho =
        oauth_chirho::register_client_chirho(root_chirho, app_chirho, owner_chirho).unwrap();
    let token_chirho = oauth_chirho::issue_scoped_token_chirho(
        root_chirho,
        &user_chirho.principal_chirho,
        user_secret_chirho,
        &client_chirho.client_id_chirho,
        vec!["invoke_chirho".to_string()],
    )
    .unwrap();
    let mut headers_chirho = HeaderMap::new();
    headers_chirho.insert(
        AUTHORIZATION,
        format!("Bearer {}", token_chirho.token_chirho)
            .parse()
            .unwrap(),
    );
    (user_chirho, headers_chirho)
}

pub(super) fn verified_query_headers_for_app_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
    user_secret_chirho: &str,
) -> (String, HeaderMap) {
    let mut prices_chirho = std::collections::BTreeMap::new();
    prices_chirho.insert("query_chirho".to_string(), 1);
    effect_pricing_chirho::set_price_book_chirho(
        root_chirho,
        app_chirho,
        owner_chirho,
        None,
        prices_chirho,
        0,
    )
    .unwrap();
    let (user_chirho, headers_chirho) =
        scoped_headers_for_app_chirho(root_chirho, app_chirho, owner_chirho, user_secret_chirho);
    (user_chirho.principal_chirho, headers_chirho)
}

pub(super) fn store_empty_dag_chirho(root_chirho: &std::path::Path) -> HashChirho {
    store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: Vec::new(),
            edges_chirho: Vec::new(),
        },
    )
    .unwrap()
}

pub(super) fn app_state_for_root_chirho(root_chirho: &std::path::Path) -> AppStateChirho {
    AppStateChirho {
        runtime_chirho: Arc::new(ServedRuntimeRootChirho::new_chirho(root_chirho)),
        tenant_chirho: cairn_chirho::tenant_chirho::tenant_id_for_root_chirho(root_chirho).unwrap(),
        invoke_lock_chirho: Arc::new(tokio::sync::Mutex::new(())),
        inflight_chirho: Arc::new(tokio::sync::Semaphore::new(8)),
        served_request_abuse_gate_chirho: Arc::new(
            ServedRequestAbuseGateChirho::new_chirho(ServedRequestAbuseLimitsChirho::default())
                .unwrap(),
        ),
        sign_in_gate_chirho: Arc::new(SignInGateChirho::new_chirho(
            &ServedRequestAbuseLimitsChirho::default(),
        )),
        publish_token_chirho: Arc::new(String::new()),
        registration_token_chirho: Arc::new(String::new()),
        connection_issuance_enabled_chirho: false,
        domain_routing_enabled_chirho: false,
        write_dispatch_chirho: None,
        local_read_authority_chirho: None,
    }
}

pub(super) fn served_admission_for_state_chirho(
    state_chirho: &AppStateChirho,
    body_bytes_chirho: usize,
) -> ServedDagAdmissionChirho {
    state_chirho
        .served_request_abuse_gate_chirho
        .admit_chirho(
            state_chirho.inflight_chirho.clone(),
            None,
            &axum::http::HeaderMap::new(),
            None,
            body_bytes_chirho,
        )
        .unwrap()
}

pub(super) fn runtime_tree_snapshot_chirho(
    root_chirho: &std::path::Path,
) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn visit_chirho(
        root_chirho: &std::path::Path,
        current_chirho: &std::path::Path,
        snapshot_chirho: &mut std::collections::BTreeMap<String, Vec<u8>>,
    ) {
        let mut entries_chirho = std::fs::read_dir(current_chirho)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries_chirho.sort_by_key(|entry_chirho| entry_chirho.file_name());
        for entry_chirho in entries_chirho {
            let path_chirho = entry_chirho.path();
            let relative_chirho = path_chirho
                .strip_prefix(root_chirho)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path_chirho.is_dir() {
                snapshot_chirho.insert(format!("{relative_chirho}/"), Vec::new());
                visit_chirho(root_chirho, &path_chirho, snapshot_chirho);
            } else {
                snapshot_chirho.insert(relative_chirho, std::fs::read(path_chirho).unwrap());
            }
        }
    }

    let mut snapshot_chirho = std::collections::BTreeMap::new();
    visit_chirho(root_chirho, root_chirho, &mut snapshot_chirho);
    snapshot_chirho
}

pub(super) fn deploy_empty_app_for_owner_chirho(
    root_chirho: &std::path::Path,
    app_chirho: &str,
    owner_chirho: &str,
) -> HashChirho {
    let dag_chirho = store_chirho::put_object_chirho(
        root_chirho,
        &DagChirho {
            nodes_chirho: vec![],
            edges_chirho: vec![],
        },
    )
    .unwrap();
    app_chirho::deploy_app_chirho(root_chirho, app_chirho, dag_chirho.clone(), owner_chirho)
        .unwrap();
    dag_chirho
}
