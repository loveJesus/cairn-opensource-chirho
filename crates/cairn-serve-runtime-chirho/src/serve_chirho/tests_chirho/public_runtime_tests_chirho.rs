// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16

use super::*;

#[test]
fn app_descriptor_docs_mcp_served_over_http_chirho() {
    let root_chirho = temp_root_chirho("app-descriptor-http");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    deploy_transform_app_for_owner_chirho(
        &root_chirho,
        "shopapp",
        &owner_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );

    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let descriptor_chirho =
            http_get_for_smoke_chirho(&addr_chirho, "/app-descriptor-chirho/shopapp");
        assert_eq!(descriptor_chirho.status_chirho, 200);
        let descriptor_json_chirho: serde_json::Value =
            serde_json::from_slice(&descriptor_chirho.body_chirho).unwrap();
        assert_eq!(
            descriptor_json_chirho["schema_chirho"],
            "app-descriptor-v1-chirho"
        );
        assert_eq!(descriptor_json_chirho["app_chirho"], "shopapp");

        let docs_chirho = http_get_for_smoke_chirho(&addr_chirho, "/app-docs-chirho/shopapp");
        assert_eq!(docs_chirho.status_chirho, 200);
        assert!(docs_chirho
            .headers_chirho
            .get("content-type")
            .unwrap()
            .starts_with("text/markdown"));
        assert!(
            String::from_utf8_lossy(&docs_chirho.body_chirho).contains("# shopapp — API reference")
        );

        let mcp_chirho = http_get_for_smoke_chirho(&addr_chirho, "/app-mcp-chirho/shopapp");
        assert_eq!(mcp_chirho.status_chirho, 200);
        let mcp_json_chirho: serde_json::Value =
            serde_json::from_slice(&mcp_chirho.body_chirho).unwrap();
        assert_eq!(
            mcp_json_chirho["schema_chirho"],
            "app-mcp-manifest-v1-chirho"
        );
        assert!(!mcp_json_chirho["tools_chirho"]
            .as_array()
            .unwrap()
            .is_empty());

        let missing_chirho =
            http_get_for_smoke_chirho(&addr_chirho, "/app-descriptor-chirho/not-deployed-chirho");
        assert_eq!(missing_chirho.status_chirho, 404);

        // The platform MCP catalog serves as a static public tool list.
        let platform_mcp_resp_chirho =
            http_get_for_smoke_chirho(&addr_chirho, "/platform-mcp-chirho");
        assert_eq!(platform_mcp_resp_chirho.status_chirho, 200);
        let platform_json_chirho: serde_json::Value =
            serde_json::from_slice(&platform_mcp_resp_chirho.body_chirho).unwrap();
        assert_eq!(
            platform_json_chirho["schema_chirho"],
            "platform-mcp-manifest-v1-chirho"
        );
        assert!(!platform_json_chirho["tools_chirho"]
            .as_array()
            .unwrap()
            .is_empty());

        server_chirho.abort();
    });

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_package_routes_deliver_lean_browser_artifacts_chirho() {
    let root_chirho = temp_root_chirho("runtime-package-delivery");
    let module_hash_chirho = store_runtime_package_module_chirho(&root_chirho);
    let (package_chirho, package_hash_chirho) =
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
            let manifest_response_chirho = runtime_package_manifest_get_chirho(
                State(state_chirho.clone()),
                AxPath(package_hash_chirho.0.clone()),
            )
            .await;
            assert_eq!(manifest_response_chirho.status(), StatusCode::OK);
            let manifest_body_chirho =
                axum::body::to_bytes(manifest_response_chirho.into_body(), usize::MAX)
                    .await
                    .unwrap();
            let manifest_chirho: cairn_chirho::runtime_profile_chirho::RuntimePackageChirho =
                serde_json::from_slice(&manifest_body_chirho).unwrap();
            assert_eq!(manifest_chirho, package_chirho);
            assert_eq!(
                manifest_chirho.profile_chirho,
                cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho
            );
            assert_eq!(manifest_chirho.entry_chirho, "upcase_chirho");
            assert_eq!(
                manifest_chirho.object_hashes_chirho,
                vec![manifest_chirho.executable_chirho.clone()]
            );
            assert!(!manifest_chirho
                .object_hashes_chirho
                .contains(&manifest_chirho.module_chirho));
            assert!(manifest_chirho.excluded_items_chirho.contains(
                &cairn_chirho::runtime_profile_chirho::RuntimePackageItemKindChirho::LedgerDescriptorsChirho
            ));
            assert!(manifest_chirho.excluded_items_chirho.contains(
                &cairn_chirho::runtime_profile_chirho::RuntimePackageItemKindChirho::ResourceDescriptorsChirho
            ));
            assert!(manifest_chirho.excluded_items_chirho.contains(
                &cairn_chirho::runtime_profile_chirho::RuntimePackageItemKindChirho::OwnerDescriptorsChirho
            ));
            assert!(manifest_chirho.excluded_items_chirho.contains(
                &cairn_chirho::runtime_profile_chirho::RuntimePackageItemKindChirho::SchedulerDescriptorsChirho
            ));

            let executable_response_chirho = runtime_package_executable_get_chirho(
                State(state_chirho),
                AxPath(package_hash_chirho.0.clone()),
            )
            .await;
            assert_eq!(executable_response_chirho.status(), StatusCode::OK);
            assert_eq!(
                executable_response_chirho
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .unwrap(),
                "application/wasm"
            );
            let executable_body_chirho =
                axum::body::to_bytes(executable_response_chirho.into_body(), usize::MAX)
                    .await
                    .unwrap();
            let expected_executable_chirho =
                cairn_chirho::cas_chirho::get_chirho(&root_chirho, &package_chirho.executable_chirho)
                    .unwrap();
            assert_eq!(
                executable_body_chirho.as_ref(),
                expected_executable_chirho.as_slice()
            );
            let outcome_chirho = cairn_chirho::runner_chirho::run_node_bytes_chirho(
                executable_body_chirho.as_ref(),
                &manifest_chirho.entry_chirho,
                b"served package",
                1_000_000,
            )
            .unwrap();
            assert_eq!(outcome_chirho.output_chirho, b"SERVED PACKAGE");
        });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_package_routes_fail_closed_for_bad_package_refs_chirho() {
    let root_chirho = temp_root_chirho("runtime-package-fail-closed");
    let module_hash_chirho = store_runtime_package_module_chirho(&root_chirho);
    let (package_chirho, _package_hash_chirho) =
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
    let (_server_package_chirho, server_package_hash_chirho) =
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::ServerChirho,
        )
        .unwrap();
    let mut tampered_package_obj_chirho = package_chirho.clone();
    tampered_package_obj_chirho.executable_chirho =
        tampered_package_obj_chirho.module_chirho.clone();
    let tampered_package_chirho =
        store_chirho::put_object_chirho(&root_chirho, &tampered_package_obj_chirho).unwrap();

    let (effect_module_hash_chirho, effect_dag_hash_chirho) =
        store_runtime_package_effect_module_chirho(&root_chirho);
    assert!(
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &effect_module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .is_err()
    );
    let effect_package_chirho = cairn_chirho::runtime_profile_chirho::RuntimePackageChirho {
        profile_chirho:
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        module_chirho: effect_module_hash_chirho,
        dag_chirho: effect_dag_hash_chirho,
        executable_chirho: package_chirho.executable_chirho.clone(),
        entry_chirho: package_chirho.entry_chirho.clone(),
        abi_chirho: cairn_chirho::runtime_profile_chirho::BYTES_ABI_CHIRHO.to_string(),
        inputs_chirho: package_chirho.inputs_chirho.clone(),
        outputs_chirho: package_chirho.outputs_chirho.clone(),
        capabilities_chirho: Vec::new(),
        included_items_chirho: package_chirho.included_items_chirho.clone(),
        excluded_items_chirho: package_chirho.excluded_items_chirho.clone(),
        object_hashes_chirho: package_chirho.object_hashes_chirho.clone(),
    };
    let effect_package_hash_chirho =
        store_chirho::put_object_chirho(&root_chirho, &effect_package_chirho).unwrap();

    let state_chirho = app_state_for_root_chirho(&root_chirho);
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let tampered_manifest_chirho = runtime_package_manifest_get_chirho(
            State(state_chirho.clone()),
            AxPath(tampered_package_chirho.0.clone()),
        )
        .await;
        assert_eq!(tampered_manifest_chirho.status(), StatusCode::BAD_REQUEST);

        let tampered_executable_chirho = runtime_package_executable_get_chirho(
            State(state_chirho.clone()),
            AxPath(tampered_package_chirho.0.clone()),
        )
        .await;
        assert_eq!(tampered_executable_chirho.status(), StatusCode::BAD_REQUEST);

        let tampered_demo_chirho = runtime_package_demo_chirho(
            State(state_chirho.clone()),
            AxPath(tampered_package_chirho.0.clone()),
        )
        .await;
        assert_eq!(tampered_demo_chirho.status(), StatusCode::BAD_REQUEST);

        let effect_manifest_chirho = runtime_package_manifest_get_chirho(
            State(state_chirho.clone()),
            AxPath(effect_package_hash_chirho.0.clone()),
        )
        .await;
        assert_eq!(effect_manifest_chirho.status(), StatusCode::BAD_REQUEST);

        let effect_demo_chirho = runtime_package_demo_chirho(
            State(state_chirho.clone()),
            AxPath(effect_package_hash_chirho.0.clone()),
        )
        .await;
        assert_eq!(effect_demo_chirho.status(), StatusCode::BAD_REQUEST);

        let server_manifest_chirho = runtime_package_manifest_get_chirho(
            State(state_chirho.clone()),
            AxPath(server_package_hash_chirho.0.clone()),
        )
        .await;
        assert_eq!(server_manifest_chirho.status(), StatusCode::BAD_REQUEST);

        let server_demo_chirho = runtime_package_demo_chirho(
            State(state_chirho.clone()),
            AxPath(server_package_hash_chirho.0.clone()),
        )
        .await;
        assert_eq!(server_demo_chirho.status(), StatusCode::BAD_REQUEST);

        let missing_manifest_chirho = runtime_package_manifest_get_chirho(
            State(state_chirho.clone()),
            AxPath("0".repeat(64)),
        )
        .await;
        assert_eq!(missing_manifest_chirho.status(), StatusCode::NOT_FOUND);

        let missing_demo_chirho =
            runtime_package_demo_chirho(State(state_chirho.clone()), AxPath("0".repeat(64))).await;
        assert_eq!(missing_demo_chirho.status(), StatusCode::NOT_FOUND);

        let invalid_hash_chirho = runtime_package_executable_get_chirho(
            State(state_chirho.clone()),
            AxPath("not-a-content-hash-chirho".to_string()),
        )
        .await;
        assert_eq!(invalid_hash_chirho.status(), StatusCode::BAD_REQUEST);

        let invalid_demo_chirho = runtime_package_demo_chirho(
            State(state_chirho),
            AxPath("not-a-content-hash-chirho".to_string()),
        )
        .await;
        assert_eq!(invalid_demo_chirho.status(), StatusCode::BAD_REQUEST);
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_package_artifact_routes_smoke_over_local_http_chirho() {
    let root_chirho = temp_root_chirho("runtime-package-http-smoke");
    let module_hash_chirho = store_runtime_package_module_chirho(&root_chirho);
    let (package_chirho, package_hash_chirho) =
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
    let expected_executable_chirho =
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &package_chirho.executable_chirho)
            .unwrap();
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let listener_chirho = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_chirho = listener_chirho.local_addr().unwrap().to_string();
        let app_chirho = runtime_router_for_root_chirho(
            &root_for_server_chirho,
            8,
            String::new(),
            String::new(),
            false,
            ServedRequestAbuseLimitsChirho::default(),
        )
        .unwrap();
        let server_chirho = tokio::spawn(async move {
            axum::serve(
                listener_chirho,
                app_chirho.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let manifest_response_chirho = http_get_for_smoke_chirho(
            &addr_chirho,
            &format!(
                "/runtime-package-chirho/{}/manifest-chirho",
                package_hash_chirho.0
            ),
        );
        assert_eq!(manifest_response_chirho.status_chirho, 200);
        assert!(manifest_response_chirho
            .headers_chirho
            .get("content-type")
            .unwrap()
            .starts_with("application/json"));
        let manifest_chirho: cairn_chirho::runtime_profile_chirho::RuntimePackageChirho =
            serde_json::from_slice(&manifest_response_chirho.body_chirho).unwrap();
        assert_eq!(manifest_chirho, package_chirho);
        assert_eq!(manifest_chirho.entry_chirho, "upcase_chirho");

        let host_js_response_chirho =
            http_get_for_smoke_chirho(&addr_chirho, "/runtime-package-host-chirho.js");
        assert_eq!(host_js_response_chirho.status_chirho, 200);
        assert!(host_js_response_chirho
            .headers_chirho
            .get("content-type")
            .unwrap()
            .starts_with("application/javascript"));
        assert!(
            String::from_utf8_lossy(&host_js_response_chirho.body_chirho)
                .contains("runRuntimePackageTextChirho")
        );

        let demo_response_chirho = http_get_for_smoke_chirho(
            &addr_chirho,
            &format!("/runtime-package-demo-chirho/{}", package_hash_chirho.0),
        );
        assert_eq!(demo_response_chirho.status_chirho, 200);
        let demo_html_chirho = String::from_utf8_lossy(&demo_response_chirho.body_chirho);
        assert!(demo_html_chirho.contains(&package_hash_chirho.0));
        assert!(demo_html_chirho.contains("/runtime-package-host-chirho.js"));

        let executable_response_chirho = http_get_for_smoke_chirho(
            &addr_chirho,
            &format!(
                "/runtime-package-chirho/{}/executable-chirho",
                package_hash_chirho.0
            ),
        );
        assert_eq!(executable_response_chirho.status_chirho, 200);
        assert_eq!(
            executable_response_chirho
                .headers_chirho
                .get("content-type")
                .unwrap(),
            "application/wasm"
        );
        assert_eq!(
            executable_response_chirho.body_chirho,
            expected_executable_chirho
        );
        runtime_package_node_loader_smoke_chirho(
            &format!("http://{addr_chirho}"),
            &package_hash_chirho,
        );

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn runtime_package_js_host_blake3_matches_cairn_hashes_chirho() {
    if !node_available_for_smoke_chirho("runtime package JS BLAKE3 smoke") {
        return;
    }
    let multi_chunk_bytes_chirho = (0..1500)
        .map(|index_chirho| (index_chirho % 251) as u8)
        .collect::<Vec<_>>();
    let multi_chunk_json_chirho = serde_json::to_string(&multi_chunk_bytes_chirho).unwrap();
    let host_url_chirho = runtime_package_host_file_url_chirho();
    let empty_hash_chirho = blake3::hash(b"").to_hex().to_string();
    let abc_hash_chirho = blake3::hash(b"abc").to_hex().to_string();
    let multi_chunk_hash_chirho = blake3::hash(&multi_chunk_bytes_chirho).to_hex().to_string();
    let code_chirho = format!(
        r#"
const hostUrlChirho = {host_url_chirho:?};
const hostChirho = await import(hostUrlChirho);
const samplesChirho = [
  [new Uint8Array(), {empty_hash_chirho:?}],
  [new TextEncoder().encode("abc"), {abc_hash_chirho:?}],
  [Uint8Array.from({multi_chunk_json_chirho}), {multi_chunk_hash_chirho:?}],
];
for (const [bytesChirho, expectedChirho] of samplesChirho) {{
  const actualChirho = hostChirho.blake3HexChirho(bytesChirho);
  if (actualChirho !== expectedChirho) {{
    throw new Error(`BLAKE3 mismatch: ${{actualChirho}} !== ${{expectedChirho}}`);
  }}
}}
try {{
  hostChirho.validateRuntimePackageManifestForBrowserChirho({{
    profile_chirho: "ServerChirho",
    executable_chirho: {empty_hash_chirho:?},
    abi_chirho: "bytes-abi-v1-chirho",
    entry_chirho: "upcase_chirho",
    capabilities_chirho: [],
    object_hashes_chirho: [{empty_hash_chirho:?}],
  }});
  throw new Error("expected server runtime package manifest to be refused");
}} catch (errorChirho) {{
  if (!String(errorChirho.message).includes("not public")) {{
    throw errorChirho;
  }}
}}
"#
    );
    let output_chirho = std::process::Command::new("node")
        .arg("--input-type=module")
        .arg("--eval")
        .arg(code_chirho)
        .output()
        .unwrap();
    assert!(
        output_chirho.status.success(),
        "runtime package JS BLAKE3 smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output_chirho.stdout),
        String::from_utf8_lossy(&output_chirho.stderr)
    );
}

#[test]
fn runtime_package_js_host_rejects_tampered_executable_before_run_chirho() {
    if !node_available_for_smoke_chirho("runtime package JS executable tamper smoke") {
        return;
    }
    let root_chirho = temp_root_chirho("runtime-package-js-tamper");
    let module_hash_chirho = store_runtime_package_module_chirho(&root_chirho);
    let (package_chirho, package_hash_chirho) =
        cairn_chirho::runtime_profile_chirho::build_runtime_package_chirho(
            &root_chirho,
            &module_hash_chirho,
            cairn_chirho::runtime_profile_chirho::RuntimeProfileKindChirho::BrowserChirho,
        )
        .unwrap();
    let manifest_bytes_chirho = serde_json::to_vec(&package_chirho).unwrap();
    let mut tampered_executable_chirho =
        cairn_chirho::cas_chirho::get_chirho(&root_chirho, &package_chirho.executable_chirho)
            .unwrap();
    tampered_executable_chirho[0] ^= 0xff;

    let listener_chirho = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let server_chirho = format!("http://{}", listener_chirho.local_addr().unwrap());
    let manifest_for_thread_chirho = manifest_bytes_chirho.clone();
    let executable_for_thread_chirho = tampered_executable_chirho.clone();
    let server_thread_chirho = std::thread::spawn(move || {
        let mut manifest_stream_chirho =
            accept_with_timeout_chirho(&listener_chirho, std::time::Duration::from_secs(5));
        let manifest_request_chirho = read_mock_http_request_chirho(&mut manifest_stream_chirho);
        assert!(manifest_request_chirho.contains("/manifest-chirho"));
        write_mock_http_response_chirho(
            &mut manifest_stream_chirho,
            "application/json",
            &manifest_for_thread_chirho,
        );

        let mut executable_stream_chirho =
            accept_with_timeout_chirho(&listener_chirho, std::time::Duration::from_secs(5));
        let executable_request_chirho =
            read_mock_http_request_chirho(&mut executable_stream_chirho);
        assert!(executable_request_chirho.contains("/executable-chirho"));
        write_mock_http_response_chirho(
            &mut executable_stream_chirho,
            "application/wasm",
            &executable_for_thread_chirho,
        );
    });

    let host_url_chirho = runtime_package_host_file_url_chirho();
    let code_chirho = format!(
        r#"
const hostUrlChirho = {host_url_chirho:?};
const packageChirho = {package_chirho:?};
const baseUrlChirho = {server_chirho:?};
const hostChirho = await import(hostUrlChirho);
try {{
  await hostChirho.runRuntimePackageTextChirho(packageChirho, "tampered", {{ baseUrlChirho }});
  throw new Error("expected executable hash mismatch");
}} catch (errorChirho) {{
  if (!String(errorChirho.message).includes("executable hash")) {{
    throw errorChirho;
  }}
}}
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
        "runtime package JS tamper smoke failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output_chirho.stdout),
        String::from_utf8_lossy(&output_chirho.stderr)
    );
    server_thread_chirho.join().unwrap();
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn contact_demo_page_routes_are_same_origin_chirho() {
    let root_chirho = temp_root_chirho("contact-demo-page");
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let index_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/");
        assert_eq!(index_response_chirho.status_chirho, 200);
        let index_html_chirho = String::from_utf8_lossy(&index_response_chirho.body_chirho);
        assert!(index_html_chirho.contains("/contact-demo-chirho"));

        let page_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/contact-demo-chirho");
        assert_eq!(page_response_chirho.status_chirho, 200);
        assert!(page_response_chirho
            .headers_chirho
            .get("content-type")
            .unwrap()
            .starts_with("text/html"));
        let page_html_chirho = String::from_utf8_lossy(&page_response_chirho.body_chirho);
        assert!(page_html_chirho.contains("/htmx-lite-chirho.js"));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact\""));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact/contact-list\""));
        assert!(!page_html_chirho.contains("unpkg.com"));
        assert!(!page_html_chirho.contains("https://"));

        let js_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/htmx-lite-chirho.js");
        assert_eq!(js_response_chirho.status_chirho, 200);
        assert!(js_response_chirho
            .headers_chirho
            .get("content-type")
            .unwrap()
            .starts_with("application/javascript"));
        let js_chirho = String::from_utf8_lossy(&js_response_chirho.body_chirho);
        assert!(js_chirho.contains("AFTER_REQUEST_EVENT_CHIRHO"));
        assert!(js_chirho.contains("BODY_TRIGGER_CHIRHO"));
        assert!(js_chirho.contains("URLSearchParams"));
        htmx_lite_node_smoke_chirho();

        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn platform_root_customer_write_refuses_before_persistence_chirho() {
    let root_chirho = temp_root_chirho("platform-root-customer-write-refusal");
    assert_eq!(
        cairn_chirho::tenant_chirho::tenant_id_for_root_chirho(&root_chirho).unwrap(),
        cairn_chirho::tenant_chirho::TenantIdChirho::PlatformRootChirho
    );
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let contact_dag_chirho = store_contact_write_render_dag_chirho(&root_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact",
        contact_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();

    let raw_body_chirho =
        b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Platform+root+must+refuse";
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    let response_chirho = runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/contact",
            &[("content-type", "application/x-www-form-urlencoded")],
            raw_body_chirho,
        );
        server_chirho.abort();
        response_chirho
    });
    // The identity is the tenant-root gate's own, so it attributes the refusal; the operator detail
    // (the WriteStoreChirho text, PlatformRootChirho, the restart flag) stays out of the body.
    let response_text_chirho = String::from_utf8_lossy(&response_chirho.body_chirho);
    assert!(!response_text_chirho.contains("WriteStoreChirho"));
    assert!(!response_text_chirho.contains("PlatformRootChirho"));
    assert!(!response_text_chirho.contains("--tenant"));
    assert_served_control_plane_attack_blocked_chirho(
        &root_chirho,
        &response_chirho,
        raw_body_chirho,
        &["Alice", "alice@example.com", "Platform root must refuse"],
        403,
        Some("app-write-not-available-chirho"),
    );

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn contact_demo_write_stays_private_while_legacy_list_refuses_chirho() {
    let root_chirho = tenant_root_for_test_chirho("contact-demo-live-app");
    let owner_chirho = identity_chirho::register_identity_chirho(
        &root_chirho,
        identity_chirho::PrincipalKindChirho::OwnerChirho,
    )
    .unwrap()
    .principal_chirho;
    let query_caller_chirho = "contact-live-query-caller";
    let contact_dag_chirho = store_contact_write_render_dag_chirho(&root_chirho);
    cairn_chirho::app_chirho::deploy_app_chirho(
        &root_chirho,
        "contact",
        contact_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        None,
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PrivateBlobRefChirho {
            subject_chirho: "app/contact/inbox".to_string(),
            safe_metadata_chirho: Vec::new(),
        },
    )
    .unwrap();
    let list_dag_chirho = store_contact_list_route_dag_chirho(&root_chirho, query_caller_chirho);
    cairn_chirho::app_chirho::deploy_app_route_chirho(
        &root_chirho,
        "contact",
        "contact-list",
        list_dag_chirho,
        &owner_chirho,
    )
    .unwrap();
    cairn_chirho::app_chirho::set_app_input_policy_chirho(
        &root_chirho,
        "contact",
        Some("contact-list"),
        &owner_chirho,
        cairn_chirho::app_chirho::AppInputModeChirho::PlainChirho,
    )
    .unwrap();

    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let listener_chirho = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_chirho = listener_chirho.local_addr().unwrap().to_string();
        let app_chirho = runtime_router_for_root_chirho(
            &root_for_server_chirho,
            8,
            String::new(),
            String::new(),
            false,
            ServedRequestAbuseLimitsChirho::default(),
        )
        .unwrap();
        let server_chirho = tokio::spawn(async move {
            axum::serve(
                listener_chirho,
                app_chirho.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        wait_for_serve_health_chirho(&addr_chirho);

        let page_response_chirho = http_get_for_smoke_chirho(&addr_chirho, "/contact-demo-chirho");
        assert_eq!(page_response_chirho.status_chirho, 200);
        let page_html_chirho = String::from_utf8_lossy(&page_response_chirho.body_chirho);
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact\""));
        assert!(page_html_chirho.contains("hx-post=\"/app-chirho/contact/contact-list\""));

        let raw_body_chirho =
            b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
        let write_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/contact",
            &[("content-type", "application/x-www-form-urlencoded")],
            raw_body_chirho,
        );
        assert_eq!(write_response_chirho.status_chirho, 200);
        let list_response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            "/app-chirho/contact/contact-list",
            &[("content-type", "application/json")],
            b"",
        );
        assert_eq!(
            list_response_chirho.status_chirho,
            400,
            "{}",
            String::from_utf8_lossy(&list_response_chirho.body_chirho)
        );
        assert!(crate::serve_chirho::public_error_chirho::fixed_execution_refusal_knowledge_chirho(&String::from_utf8_lossy(
            &list_response_chirho.body_chirho
        ))
        .is_some());
        server_chirho.abort();
    });

    let raw_body_chirho =
            b"name_chirho=Alice+Example&email_chirho=alice%40example.com&message_chirho=Apartment+above+the+bakery";
    let raw_hash_chirho = cairn_chirho::cas_chirho::hash_chirho(raw_body_chirho);
    assert!(cairn_chirho::cas_chirho::get_chirho(&root_chirho, &raw_hash_chirho).is_err());
    // One person blob; the rest are F4 store-seal artifacts under `app-store/`.
    let blob_records_chirho =
        cairn_chirho::privacy_chirho::load_privacy_blob_records_chirho(&root_chirho).unwrap();
    assert_eq!(
        non_store_seal_blob_subjects_chirho(&root_chirho),
        vec!["app/contact/inbox".to_string()]
    );
    let person_blob_chirho = blob_records_chirho
        .iter()
        .find(|record_chirho| record_chirho.subject_chirho == "app/contact/inbox")
        .unwrap();
    assert_eq!(
        cairn_chirho::privacy_chirho::load_private_blob_chirho(
            &root_chirho,
            &person_blob_chirho.blob_chirho,
        )
        .unwrap(),
        raw_body_chirho
    );

    let store_chirho = versioned_chirho::VersionedStoreChirho::open_chirho(
        &root_chirho.join("versioned-chirho.redb"),
    )
    .unwrap();
    let stored_contact_chirho = store_chirho
        .get_chirho("contacts-chirho/latest")
        .unwrap()
        .unwrap();
    let stored_contact_text_chirho = String::from_utf8(stored_contact_chirho).unwrap();
    assert!(stored_contact_text_chirho.contains("app-private-input-ref-v1-chirho"));
    assert!(!stored_contact_text_chirho.contains("Alice"));
    assert!(!stored_contact_text_chirho.contains("alice@example.com"));
    assert!(!stored_contact_text_chirho.contains("bakery"));
    drop(store_chirho);

    let rows_chirho =
        cairn_chirho::query_chirho::query_prefix_chirho(&root_chirho, "contacts-chirho", 50)
            .unwrap();
    assert_eq!(rows_chirho.len(), 1);
    assert_eq!(rows_chirho[0].key_chirho, "contacts-chirho/latest");
    assert!(rows_chirho[0]
        .value_chirho
        .contains("app-private-input-ref-v1-chirho"));
    assert!(!rows_chirho[0].value_chirho.contains("Alice"));
    assert!(!rows_chirho[0].value_chirho.contains("alice@example.com"));
    assert!(!rows_chirho[0].value_chirho.contains("bakery"));

    // The balance assertion here died with the V1 ledger writer at CF6 wave-1: nothing can post an
    // entry, so the map is empty and indexing it panics. Removed rather than retargeted to zero --
    // `assert_eq!(balance, 0)` on a tree with no money cannot fail, which is the shape this arc
    // refuses. The PRIVACY assertions above are this test's actual subject and are untouched.
    let effects_chirho = std::fs::read_dir(root_chirho.join("effects-chirho"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(effects_chirho.len(), 1);
    for effect_chirho in effects_chirho {
        let effect_text_chirho = std::fs::read_to_string(effect_chirho.path()).unwrap();
        assert!(!effect_text_chirho.contains("Alice"));
        assert!(!effect_text_chirho.contains("alice@example.com"));
        assert!(!effect_text_chirho.contains("bakery"));
    }
    let live_effects_chirho =
        cairn_chirho::effect_chirho::load_volatile_effect_records_chirho(&root_chirho).unwrap();
    assert!(live_effects_chirho.is_empty());

    let _ = std::fs::remove_dir_all(&root_chirho);
}

#[test]
fn candidate_preview_route_labels_unreviewed_pure_output_chirho() {
    let root_chirho = temp_root_chirho("candidate-preview-route");
    let dag_hash_chirho = store_transform_dag_chirho(
        &root_chirho,
        include_str!("../../../../../examples-chirho/upcase-chirho.wat"),
        "upcase_chirho",
    );
    let port_chirho = unused_local_port_chirho();
    let addr_chirho = format!("127.0.0.1:{port_chirho}");
    let root_for_server_chirho = root_chirho.clone();
    let runtime_chirho = tokio::runtime::Runtime::new().unwrap();
    runtime_chirho.block_on(async {
        let server_chirho = tokio::spawn(async move {
            serve_quiet_chirho(&root_for_server_chirho, port_chirho, 8, String::new()).await
        });
        wait_for_serve_health_chirho(&addr_chirho);
        let response_chirho = http_request_for_smoke_chirho(
            &addr_chirho,
            "POST",
            &format!("/preview-chirho/{}", dag_hash_chirho.0),
            &[],
            b"hello world",
        );
        assert_eq!(response_chirho.status_chirho, 200);
        assert_eq!(response_chirho.body_chirho, b"HELLO WORLD");
        assert_eq!(
            response_chirho
                .headers_chirho
                .get(cairn_app_preview_chirho::PREVIEW_UNREVIEWED_HEADER_CHIRHO),
            Some(&"true".to_string())
        );
        assert!(!root_chirho.join("effects-chirho").exists());
        assert!(!root_chirho.join("runkeys-chirho").exists());
        server_chirho.abort();
    });
    let _ = std::fs::remove_dir_all(&root_chirho);
}
