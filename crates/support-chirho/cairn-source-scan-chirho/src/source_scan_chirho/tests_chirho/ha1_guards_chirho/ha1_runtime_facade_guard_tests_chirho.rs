// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;

const SERVE_TREE_PREFIX_CHIRHO: &str = "crates/cairn-serve-runtime-chirho/src/serve_chirho";
const SERVE_ROOT_MODULE_CHIRHO: &str = "crates/cairn-serve-runtime-chirho/src/serve_chirho.rs";
const SERVE_STARTUP_MODULE_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_lifecycle_chirho/startup_chirho.rs";
const SERVE_STATE_MODULE_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_lifecycle_chirho/state_chirho.rs";
const SERVE_RUNTIME_PORTS_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_ports_chirho.rs";
const SERVE_APP_HTTP_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/app_http_chirho.rs";
const SERVE_APP_ROOT_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/app_web_chirho/app_root_chirho.rs";
const SERVE_INVOKE_TRANSPORT_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/invoke_transport_chirho.rs";
const SERVE_RESOURCE_GATE_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/resource_gate_chirho.rs";
const APP_SIGNED_RECORD_MESSAGES_CHIRHO: &str =
    "crates/runtime-chirho/cairn-model-app-chirho/src/signed_record_messages_chirho.rs";
const REVIEWED_SOURCE_INSTALL_CHIRHO: &str =
    "src/app_runtime_chirho/app_source_manifest_chirho/reviewed_install_chirho.rs";
const SERVE_PUBLIC_RUN_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/public_run_chirho.rs";
const SERVE_REALTIME_WS_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/realtime_ws_chirho.rs";
const SERVE_SSR_WEB_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/ssr_web_chirho.rs";
const SERVE_ADMISSION_GATE_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/request_admission_chirho/served_request_abuse_gate_chirho.rs";
const SERVE_APP_SESSION_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/app_web_chirho/app_session_chirho.rs";
const SERVE_SESSION_WEB_HELPERS_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/session_web_helpers_chirho.rs";
const SERVE_APP_ASSETS_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/app_web_chirho/app_assets_chirho.rs";
const SERVE_PUBLIC_ROUTES_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/public_routes_chirho.rs";
const RUN_INTENT_MODULE_CHIRHO: &str =
    "src/execution_runtime_chirho/effect_chirho/run_intent_chirho.rs";

fn function_call_statements_chirho(text_chirho: &str, function_chirho: &str) -> Vec<String> {
    let production_chirho = production_text_chirho(text_chirho);
    let lines_chirho: Vec<&str> = production_chirho.lines().collect();
    let mut calls_chirho = Vec::new();
    let mut index_chirho = 0usize;
    let prefix_chirho = format!("{function_chirho}(");
    while index_chirho < lines_chirho.len() {
        let trimmed_chirho = lines_chirho[index_chirho].trim();
        if !trimmed_chirho.starts_with(&prefix_chirho) {
            index_chirho += 1;
            continue;
        }
        let mut call_chirho = trimmed_chirho.to_string();
        while !call_chirho.contains(");")
            && !call_chirho.contains(")?;")
            && index_chirho + 1 < lines_chirho.len()
        {
            index_chirho += 1;
            call_chirho.push(' ');
            call_chirho.push_str(lines_chirho[index_chirho].trim());
        }
        calls_chirho.push(call_chirho);
        index_chirho += 1;
    }
    calls_chirho
}

fn function_source_chirho<'a>(text_chirho: &'a str, function_chirho: &str) -> &'a str {
    let marker_chirho = format!("fn {function_chirho}(");
    let start_chirho = text_chirho
        .find(&marker_chirho)
        .unwrap_or_else(|| panic!("missing function {function_chirho}"));
    let function_chirho = &text_chirho[start_chirho..];
    let open_chirho = function_chirho
        .find('{')
        .unwrap_or_else(|| panic!("missing body for {marker_chirho}"));
    let mut depth_chirho = 0usize;
    for (offset_chirho, byte_chirho) in function_chirho[open_chirho..].bytes().enumerate() {
        match byte_chirho {
            b'{' => depth_chirho += 1,
            b'}' => {
                depth_chirho -= 1;
                if depth_chirho == 0 {
                    return &function_chirho[..open_chirho + offset_chirho + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function {marker_chirho}");
}

fn read_production_source_chirho(path_chirho: &str) -> String {
    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(path_chirho)).unwrap();
    production_text_chirho(&source_chirho).to_string()
}

#[test]
fn runtime_serve_up_require_explicit_platform_root_override_chirho() {
    let rel_chirho =
        "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs";
    let path_chirho = workspace_root_chirho().join(rel_chirho);
    assert!(
        path_chirho.is_file(),
        "runtime tenant-root guard target is missing: {rel_chirho}"
    );
    let text_chirho =
        std::fs::read_to_string(&path_chirho).expect("read runtime tenant-root guard target");
    let production_chirho = production_text_chirho(&text_chirho);
    // The `matches().count()==3` and `guard_calls.len()==2` count freezes were demoted to the
    // advisory structure report; the serve/up implicit-PlatformRoot refusal engine claim stays RED.
    let guard_calls_chirho = function_call_statements_chirho(
        &text_chirho,
        "require_runtime_platform_root_override_chirho",
    );
    assert!(
        guard_calls_chirho.iter().any(|call_chirho| {
            call_chirho.contains("cli_tenant_chirho")
                && call_chirho.contains("allow_platform_root_chirho")
                && call_chirho.contains("\"serve\"")
        }) && guard_calls_chirho.iter().any(|call_chirho| {
            call_chirho.contains("&up_tenant_chirho")
                && call_chirho.contains("allow_platform_root_chirho")
                && call_chirho.contains("\"up\"")
        }),
        "serve and up must both reject implicit PlatformRootChirho before starting runtime serving"
    );
    assert!(
        production_chirho.contains("--allow-platform-root-chirho")
            && production_chirho.contains("--tenant <tenant-id>"),
        "runtime platform-root refusal must name the explicit operator override and tenant path"
    );
}

#[test]
fn serve_customer_execution_seams_do_not_bypass_runtime_facade_chirho() {
    let execution_files_chirho = [
        SERVE_ROOT_MODULE_CHIRHO,
        SERVE_APP_HTTP_CHIRHO,
        SERVE_INVOKE_TRANSPORT_CHIRHO,
        SERVE_PUBLIC_RUN_CHIRHO,
        SERVE_REALTIME_WS_CHIRHO,
        SERVE_SSR_WEB_CHIRHO,
    ];
    let forbidden_chirho = [
        "state_chirho.root_chirho",
        "root_chirho: Arc<PathBuf>",
        "Arc::new(root_chirho.to_path_buf())",
    ];
    let mut offenders_chirho = Vec::new();
    for rel_chirho in execution_files_chirho {
        let path_chirho = workspace_root_chirho().join(rel_chirho);
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for token_chirho in forbidden_chirho {
            if production_chirho.contains(token_chirho) {
                offenders_chirho.push(format!("{rel_chirho}: {token_chirho}"));
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "customer execution seams must use ServedRuntimeRootChirho facade, not direct AppState root path bypasses: {offenders_chirho:?}"
    );
}

#[test]
fn request_body_policy_stays_verified_and_pre_persistence_chirho() {
    let app_http_chirho = read_production_source_chirho(SERVE_APP_HTTP_CHIRHO);
    let direct_post_chirho =
        function_source_chirho(&app_http_chirho, "app_route_post_request_chirho");
    let direct_check_chirho = direct_post_chirho
        .find("direct_route_rejects_request_body_chirho(")
        .unwrap();
    let direct_read_chirho = direct_post_chirho
        .find("read_served_app_request_body_chirho(")
        .unwrap();
    // The handler runs the request through the road that also finishes the browser answer (the
    // caller-key carrier); the core it calls is read by name below.
    let direct_run_chirho = direct_post_chirho
        .find("run_and_finish_app_http_chirho(")
        .unwrap();
    assert!(direct_check_chirho < direct_read_chirho && direct_read_chirho < direct_run_chirho);

    let domain_chirho = function_source_chirho(&app_http_chirho, "domain_binding_fallback_chirho");
    let domain_read_chirho = domain_chirho
        .find("read_served_app_request_body_chirho(")
        .unwrap();
    assert!(
        domain_chirho
            .find("direct_route_rejects_request_body_chirho(")
            .unwrap()
            < domain_read_chirho
    );
    assert!(
        domain_chirho
            .find("direct_app_rejects_request_body_chirho(")
            .unwrap()
            < domain_read_chirho
    );
    let final_run_chirho = function_source_chirho(
        &app_http_chirho,
        "run_app_http_with_method_for_served_request_and_uri_chirho",
    );
    let final_input_chirho = final_run_chirho
        .find("app_http_dag_input_value_chirho(")
        .unwrap();
    let final_execute_chirho = final_run_chirho
        .find("try_run_served_input_with_context_chirho(")
        .unwrap();
    let final_policies_chirho = final_run_chirho
        .match_indices("!selection_chirho.accepts_request_body_chirho()")
        .map(|(index_chirho, _match_chirho)| index_chirho)
        .collect::<Vec<_>>();
    assert!(!final_policies_chirho.is_empty());
    assert!(final_policies_chirho.iter().all(|index_chirho| {
        *index_chirho < final_input_chirho && *index_chirho < final_execute_chirho
    }));

    let app_root_chirho = read_production_source_chirho(SERVE_APP_ROOT_CHIRHO);
    let root_post_chirho = function_source_chirho(&app_root_chirho, "app_post_request_chirho");
    assert!(
        root_post_chirho
            .find("direct_app_rejects_request_body_chirho(")
            .unwrap()
            < root_post_chirho
                .find("read_served_app_request_body_chirho(")
                .unwrap()
    );

    let invoke_chirho = read_production_source_chirho(SERVE_INVOKE_TRANSPORT_CHIRHO);
    let invoke_critical_chirho = function_source_chirho(&invoke_chirho, "invoke_critical_chirho");
    let invoke_input_chirho = invoke_critical_chirho
        .find("app_dag_input_chirho(")
        .unwrap();
    let invoke_execute_chirho = invoke_critical_chirho
        .find("try_run_served_with_context_and_caller_key_chirho(")
        .unwrap();
    let invoke_policies_chirho = invoke_critical_chirho
        .match_indices("!selection_chirho.accepts_request_body_chirho()")
        .map(|(index_chirho, _match_chirho)| index_chirho)
        .collect::<Vec<_>>();
    assert!(!invoke_policies_chirho.is_empty());
    assert!(invoke_policies_chirho.iter().all(|index_chirho| {
        *index_chirho < invoke_input_chirho && *index_chirho < invoke_execute_chirho
    }));

    let ports_chirho = read_production_source_chirho(SERVE_RUNTIME_PORTS_CHIRHO);
    let preflight_chirho = function_source_chirho(
        &ports_chirho,
        "direct_app_route_accepts_request_body_chirho",
    );
    assert!(preflight_chirho.contains("resolve_app_route_chirho("));
    assert!(preflight_chirho.contains("verified_app_route_request_body_policy_chirho("));
    let root_preflight_chirho =
        function_source_chirho(&ports_chirho, "direct_app_accepts_request_body_chirho");
    assert!(root_preflight_chirho.contains("resolve_app_dag_chirho("));
    assert!(root_preflight_chirho.contains("app_root_request_body_policy_chirho("));
    let resource_gate_chirho = read_production_source_chirho(SERVE_RESOURCE_GATE_CHIRHO);
    assert_eq!(
        resource_gate_chirho
            .matches("verified_app_route_request_body_policy_chirho(")
            .count(),
        3,
        "every direct or rerouted named-route selection must carry the verified body policy"
    );
    assert!(
        read_production_source_chirho(APP_SIGNED_RECORD_MESSAGES_CHIRHO)
            .contains("request_body_policy_chirho")
    );
    assert!(
        read_production_source_chirho(REVIEWED_SOURCE_INSTALL_CHIRHO)
            .contains("verified_app_route_request_body_policy_chirho(")
    );
}

fn allowed_public_delivery_delegate_line_chirho(trimmed_chirho: &str) -> bool {
    trimmed_chirho.starts_with("pub(super) fn ensure_public_run_dag_is_pure_wasm_chirho(")
        || trimmed_chirho.starts_with("cairn_app_preview_chirho::preview_dag_payload_chirho(")
        || trimmed_chirho
            .starts_with("runtime_profile_chirho::validate_public_runtime_package_chirho(")
        || trimmed_chirho.starts_with("crate::cas_chirho::get_chirho(")
        || trimmed_chirho.starts_with("Ok(crate::cas_chirho::get_chirho(")
        || trimmed_chirho.starts_with("app_descriptor_chirho::app_descriptor_chirho(")
        || trimmed_chirho.starts_with("app_chirho::app_static_asset_by_name_chirho(")
        || trimmed_chirho.starts_with("app_chirho::app_static_asset_by_hash_chirho(")
        || trimmed_chirho.starts_with("app_chirho::app_static_asset_bytes_chirho(")
}

#[test]
fn served_public_delivery_helpers_stay_behind_runtime_facade_chirho() {
    // The exact facade-call SET freeze was demoted to the advisory structure report; the
    // no-raw-CAS/pure-wasm/package-validation-bypass engine claim stays RED here.
    let files_chirho = [
        SERVE_APP_ASSETS_CHIRHO,
        SERVE_PUBLIC_ROUTES_CHIRHO,
        SERVE_PUBLIC_RUN_CHIRHO,
    ];
    let forbidden_direct_markers_chirho = [
        "ensure_public_run_dag_is_pure_wasm_chirho(",
        "cairn_app_preview_chirho::preview_dag_payload_chirho(",
        "runtime_profile_chirho::validate_public_runtime_package_chirho(",
        "crate::cas_chirho::get_chirho(",
        "app_descriptor_chirho::app_descriptor_chirho(",
        "app_chirho::app_static_asset_by_name_chirho(",
        "app_chirho::app_static_asset_by_hash_chirho(",
        "app_chirho::app_static_asset_bytes_chirho(",
    ];
    let mut direct_offenders_chirho = Vec::new();
    for rel_chirho in files_chirho {
        let text_chirho = std::fs::read_to_string(workspace_root_chirho().join(rel_chirho))
            .expect("read served public delivery helper target");
        let production_chirho = production_text_chirho(&text_chirho);
        for line_chirho in production_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if allowed_public_delivery_delegate_line_chirho(trimmed_chirho) {
                continue;
            }
            for marker_chirho in forbidden_direct_markers_chirho {
                let facade_marker_chirho = marker_chirho
                    .strip_prefix("crate::")
                    .unwrap_or(marker_chirho);
                if trimmed_chirho.contains(marker_chirho)
                    && !trimmed_chirho.contains(&format!(".{facade_marker_chirho}"))
                {
                    direct_offenders_chirho.push(format!("{rel_chirho}: {trimmed_chirho}"));
                }
            }
        }
    }
    assert!(
        direct_offenders_chirho.is_empty(),
        "served public-delivery security controls must be reached through ServedRuntimeRootChirho, not direct root-path calls: {direct_offenders_chirho:?}"
    );
}

fn allowed_owner_session_gate_raw_line_chirho(rel_chirho: &str, trimmed_chirho: &str) -> bool {
    (rel_chirho == SERVE_ROOT_MODULE_CHIRHO
        && trimmed_chirho.starts_with("fn require_owner_session_chirho("))
        || (rel_chirho == SERVE_RUNTIME_PORTS_CHIRHO
            && (trimmed_chirho.starts_with("pub(super) fn require_owner_session_chirho(")
                || trimmed_chirho.starts_with("super::require_owner_session_chirho(")))
}

fn allowed_principal_session_gate_raw_line_chirho(rel_chirho: &str, trimmed_chirho: &str) -> bool {
    (rel_chirho == SERVE_ROOT_MODULE_CHIRHO
        && trimmed_chirho.starts_with(
            "require_principal_session_chirho(root_chirho, headers_chirho, principal_chirho)",
        ))
        || (rel_chirho == SERVE_SESSION_WEB_HELPERS_CHIRHO
            && trimmed_chirho.starts_with("pub(super) fn require_principal_session_chirho("))
        || (rel_chirho == SERVE_RUNTIME_PORTS_CHIRHO
            && (trimmed_chirho.starts_with("pub(super) fn require_principal_session_chirho(")
                || trimmed_chirho.starts_with("super::require_principal_session_chirho(")))
}

#[test]
fn owner_session_gate_stays_behind_runtime_facade_chirho() {
    // The per-file facade-call count SET freeze was demoted to the advisory structure report; the
    // owner-session-authority-only-via-facade raw-call ban engine claim stays RED here.
    let mut raw_offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(SERVE_TREE_PREFIX_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for line_chirho in production_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if !trimmed_chirho.contains("require_owner_session_chirho(")
                || trimmed_chirho.contains(".require_owner_session_chirho(")
                || allowed_owner_session_gate_raw_line_chirho(&rel_chirho, trimmed_chirho)
            {
                continue;
            }
            raw_offenders_chirho.push(format!("{rel_chirho}: {trimmed_chirho}"));
        }
    }
    assert!(
        raw_offenders_chirho.is_empty(),
        "served owner-session authority gate must enter through ServedRuntimeRootChirho; raw production calls are only allowed at the helper definition and facade delegate: {raw_offenders_chirho:?}"
    );
}

#[test]
fn principal_session_gate_stays_behind_runtime_facade_chirho() {
    // The per-file facade-call count SET freeze was demoted to the advisory structure report; the
    // principal-session-authority-only-via-facade raw-call ban engine claim stays RED here.
    let mut raw_offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(SERVE_TREE_PREFIX_CHIRHO) {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for line_chirho in production_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            if !trimmed_chirho.contains("require_principal_session_chirho(")
                || trimmed_chirho.contains(".require_principal_session_chirho(")
                || allowed_principal_session_gate_raw_line_chirho(&rel_chirho, trimmed_chirho)
            {
                continue;
            }
            raw_offenders_chirho.push(format!("{rel_chirho}: {trimmed_chirho}"));
        }
    }
    assert!(
        raw_offenders_chirho.is_empty(),
        "served principal-session authority gate must enter through ServedRuntimeRootChirho; raw production calls are only allowed at the helper definition, the owner-session helper's internal principal check, and the facade delegate: {raw_offenders_chirho:?}"
    );
}

#[test]
fn raw_dag_run_intent_calls_stay_behind_served_runtime_facade_chirho() {
    let allowed_chirho = SERVE_RUNTIME_PORTS_CHIRHO;
    let run_intent_module_chirho = RUN_INTENT_MODULE_CHIRHO;
    let markers_chirho = [
        "run_intent_chirho::run_dag_with_intent_chirho(",
        "run_intent_chirho::run_dag_with_private_input_intent_chirho(",
        "run_intent_chirho::run_dag_with_intent_and_projection_read_chirho(",
        "run_intent_chirho::run_dag_with_private_input_intent_and_projection_read_chirho(",
        "run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(",
        "run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_intent_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_intent_and_projection_read_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_projection_read_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(",
        "crate::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_projection_read_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_projection_read_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(",
        "cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho(",
        "use crate::effect_chirho::run_intent_chirho::{",
        "use crate::effect_chirho::run_intent_chirho::run_dag_with",
        "use cairn_chirho::effect_chirho::run_intent_chirho::{",
        "use cairn_chirho::effect_chirho::run_intent_chirho::run_dag_with",
    ];
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if rel_chirho == run_intent_module_chirho || rel_chirho == allowed_chirho {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        let production_chirho = production_text_chirho(&text_chirho);
        for marker_chirho in markers_chirho {
            if production_chirho.contains(marker_chirho) {
                offenders_chirho.push(format!("{rel_chirho}: {marker_chirho}"));
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "served customer DAG execution must enter raw run_intent only through {allowed_chirho}: {offenders_chirho:?}"
    );
    let facade_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(allowed_chirho)).unwrap();
    // C5 2a: the facade's every run takes a ports bundle, which carries a signed-out request's declared owner; the
    // projection-read convenience entries carry none, so the facade must not call them.
    assert!(!facade_chirho
        .contains("run_intent_chirho::run_dag_with_intent_and_projection_read_chirho("));
    assert!(!facade_chirho.contains(
        "run_intent_chirho::run_dag_with_private_input_intent_and_projection_read_chirho("
    ));
    assert!(
        facade_chirho.contains("run_intent_chirho::run_dag_with_intent_and_effect_runtime_chirho(")
    );
    assert!(facade_chirho.contains(
        "run_intent_chirho::run_dag_with_private_input_intent_and_effect_runtime_chirho("
    ));
    assert_eq!(
        facade_chirho
            .matches("self.projection_read_chirho.as_deref()")
            .count(),
        6,
        "served public and private DAG facades must share the injected projection-read authority across projection-only, postgres-effect, and dev llm-served branches"
    );
    let accepted_facade_module_markers_chirho = [
        "crate::effect_chirho::run_intent_chirho::",
        "use crate::effect_chirho::run_intent_chirho",
        "cairn_chirho::effect_chirho::run_intent_chirho::",
        "use cairn_chirho::effect_chirho::run_intent_chirho",
    ];
    assert!(
        accepted_facade_module_markers_chirho
            .iter()
            .any(|marker_chirho| facade_chirho.contains(marker_chirho)),
        "{allowed_chirho} must keep an explicit accepted run_intent module path marker so the guard remains live after the serve crate cut"
    );
}

#[test]
fn served_dag_persistence_requires_bounded_read_only_admission_chirho() {
    let root_source_chirho =
        std::fs::read_to_string(workspace_root_chirho().join(SERVE_ROOT_MODULE_CHIRHO)).unwrap();
    let root_production_chirho = production_text_chirho(&root_source_chirho);
    for wrapper_chirho in [
        "try_run_chirho",
        "try_run_with_context_chirho",
        "try_run_served_with_context_chirho",
        "try_run_served_input_with_context_chirho",
    ] {
        let wrapper_source_chirho = function_source_chirho(&root_production_chirho, wrapper_chirho);
        assert!(
            wrapper_source_chirho.contains("&ServedDagAdmissionChirho"),
            "{wrapper_chirho} must require the private served-DAG admission type so unadmitted persistence is a compile error"
        );
    }
    let mut root_async_facade_calls_chirho = Vec::new();
    let mut root_pure_sync_facade_calls_chirho = Vec::new();
    let mut internal_sync_facade_calls_chirho = Vec::new();
    let mut direct_facade_offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(SERVE_TREE_PREFIX_CHIRHO)
            && rel_chirho != SERVE_ROOT_MODULE_CHIRHO
        {
            continue;
        }
        let source_chirho = read_production_source_chirho(&rel_chirho);
        for line_chirho in source_chirho.lines() {
            let trimmed_chirho = line_chirho.trim();
            let async_call_chirho = trimmed_chirho
                .contains(".run_dag_with_intent_for_served_request_chirho(")
                || trimmed_chirho
                    .contains(".run_dag_with_intent_for_served_request_and_caller_key_chirho(")
                || trimmed_chirho
                    .contains(".run_dag_with_private_input_intent_for_served_request_chirho(");
            let sync_call_chirho = trimmed_chirho.contains(".run_dag_with_intent_chirho(")
                || trimmed_chirho.contains(".run_dag_with_optional_caller_key_chirho(")
                || trimmed_chirho.contains(".run_dag_with_private_input_intent_chirho(")
                || trimmed_chirho
                    .contains(".run_dag_with_private_input_intent_optional_caller_key_chirho(");
            if async_call_chirho && rel_chirho == SERVE_ROOT_MODULE_CHIRHO {
                root_async_facade_calls_chirho.push(format!("{rel_chirho}:{trimmed_chirho}"));
            } else if sync_call_chirho && rel_chirho == SERVE_ROOT_MODULE_CHIRHO {
                root_pure_sync_facade_calls_chirho.push(format!("{rel_chirho}:{trimmed_chirho}"));
            } else if sync_call_chirho && rel_chirho == SERVE_RUNTIME_PORTS_CHIRHO {
                internal_sync_facade_calls_chirho.push(format!("{rel_chirho}:{trimmed_chirho}"));
            } else if async_call_chirho || sync_call_chirho {
                direct_facade_offenders_chirho.push(format!("{rel_chirho}:{trimmed_chirho}"));
            }
        }
    }
    assert!(
        direct_facade_offenders_chirho.is_empty(),
        "serve child modules must not bypass admitted root wrappers or the blocking facade: {direct_facade_offenders_chirho:?}"
    );
    assert_eq!(
        root_async_facade_calls_chirho.len(),
        2,
        "only admitted public/private root wrappers may enter the async served facade: {root_async_facade_calls_chirho:?}"
    );
    assert_eq!(
        root_pure_sync_facade_calls_chirho.len(),
        1,
        "only the capability-rejected public run wrapper may enter the synchronous provider-absent facade: {root_pure_sync_facade_calls_chirho:?}"
    );
    // Served-overload (ii) deleted the two provider-absent fast paths that ran a served DAG on the async worker, so every
    // served run now executes on the blocking pool: the legacy sync bridge plus the blocking public and private branches.
    assert_eq!(
        internal_sync_facade_calls_chirho.len(),
        3,
        "the legacy sync bridge plus the blocking public/private branches must remain internal to the one runtime facade: {internal_sync_facade_calls_chirho:?}"
    );
    assert!(
        read_production_source_chirho(SERVE_STARTUP_MODULE_CHIRHO)
            .contains("into_make_service_with_connect_info"),
        "the production server must expose the real peer SocketAddr to served request admission"
    );
    assert!(
        read_production_source_chirho(SERVE_STATE_MODULE_CHIRHO)
            .contains("served request unavailable\\n")
            && !function_source_chirho(
                &read_production_source_chirho(SERVE_STATE_MODULE_CHIRHO),
                "served_request_rejected_response_chirho"
            )
            .contains("error_chirho"),
        "quota refusal must be one generic 429 and must not reveal which quota failed"
    );

    let app_source_chirho = read_production_source_chirho(SERVE_APP_HTTP_CHIRHO);
    let app_run_chirho = function_source_chirho(
        &app_source_chirho,
        "run_app_http_with_method_for_served_request_and_uri_chirho",
    );
    let app_admit_chirho = app_run_chirho
        .find("admit_served_dag_request_chirho(")
        .unwrap();
    assert!(
        // K1 renamed the app road's call: it now names the route, for the limited-key gate.
        app_run_chirho.find("request_context_for_app_route_chirho(").unwrap() < app_admit_chirho
            && app_admit_chirho < app_run_chirho.find("load_refs_chirho(").unwrap()
            && app_admit_chirho
                < app_run_chirho
                    .find("app_http_dag_input_value_chirho(")
                    .unwrap()
            && app_admit_chirho
                < app_run_chirho
                    .find("try_run_served_input_with_context_chirho(")
                    .unwrap(),
        "app and domain-routed requests must admit after verified context but before selection, input persistence, or execution"
    );

    let invoke_source_chirho = read_production_source_chirho(SERVE_INVOKE_TRANSPORT_CHIRHO);
    for invoke_function_chirho in ["invoke_chirho", "process_invoke_json_with_headers_chirho"] {
        let invoke_body_chirho =
            function_source_chirho(&invoke_source_chirho, invoke_function_chirho);
        assert!(
            invoke_body_chirho.find("request_context_for_app_chirho(").unwrap()
                < invoke_body_chirho
                    .find("admit_served_dag_request_chirho(")
                    .unwrap()
                && invoke_body_chirho
                    .find("admit_served_dag_request_chirho(")
                    .unwrap()
                    < invoke_body_chirho.find("invoke_critical_chirho(").unwrap(),
            "{invoke_function_chirho} must admit each HTTP request or WS message before the serialized persistence path"
        );
    }
    assert!(
        function_source_chirho(&invoke_source_chirho, "handle_ws_chirho")
            .contains("process_invoke_json_with_headers_chirho(")
    );

    let public_source_chirho = read_production_source_chirho(SERVE_PUBLIC_RUN_CHIRHO);
    let public_run_chirho = function_source_chirho(&public_source_chirho, "run_dag_http_chirho");
    assert!(
        public_run_chirho
            .find("admit_served_dag_request_chirho(")
            .unwrap()
            < public_run_chirho.find("try_run_chirho(").unwrap()
    );
    // Preview JOINED the in-memory admission in served-overload (ii) (PFE b8be185 (b)): it executes WASM in this
    // process, so it is bounded like a served run. Admission is backpressure, not a durable record. Preview's
    // no-persistence property is pinned by BEHAVIOR in `preview_takes_admission_but_persists_nothing_chirho` (a
    // byte-identical root, with a /run-chirho positive control); this replaces the old lexical no-admission assertion,
    // whose spelling was never the safety property. Here: preview admits before it executes, through the pure executor.
    let preview_chirho = function_source_chirho(&public_source_chirho, "preview_dag_http_chirho");
    assert!(
        preview_chirho
            .find("admit_served_dag_request_chirho(")
            .unwrap()
            < preview_chirho.find(".preview_dag_payload_chirho(").unwrap(),
        "preview must admit before it executes"
    );
    let preview_executor_chirho =
        function_source_chirho(&public_source_chirho, "preview_dag_payload_for_root_chirho");
    assert!(
        preview_executor_chirho.contains("cairn_app_preview_chirho::preview_dag_payload_chirho(")
            && !preview_executor_chirho.contains("try_run_chirho(")
            && !preview_executor_chirho.contains("run_dag_with_"),
        "preview executes through the pure preview executor, never a run-intent facade"
    );

    let ssr_source_chirho = read_production_source_chirho(SERVE_SSR_WEB_CHIRHO);
    let ssr_run_chirho = function_source_chirho(&ssr_source_chirho, "ssr_get_chirho");
    let ssr_admit_chirho = ssr_run_chirho
        .find("admit_served_dag_request_chirho(")
        .unwrap();
    assert!(
        ssr_run_chirho
            .find("request_context_for_app_chirho(")
            .unwrap()
            < ssr_admit_chirho
            && ssr_admit_chirho < ssr_run_chirho.find("load_refs_chirho(").unwrap()
            && ssr_admit_chirho < ssr_run_chirho.find("app_dag_input_chirho(").unwrap()
            && ssr_admit_chirho
                < ssr_run_chirho
                    .find("try_run_served_with_context_chirho(")
                    .unwrap()
    );

    let expected_admissions_chirho = [
        (SERVE_APP_HTTP_CHIRHO, 1usize),
        (SERVE_INVOKE_TRANSPORT_CHIRHO, 2usize),
        // The public run, plus preview's in-memory admission (served-overload (ii)).
        (SERVE_PUBLIC_RUN_CHIRHO, 2usize),
        (SERVE_SSR_WEB_CHIRHO, 1usize),
    ];
    for (path_chirho, expected_chirho) in expected_admissions_chirho {
        let source_chirho = read_production_source_chirho(path_chirho);
        assert_eq!(
            source_chirho
                .matches("admit_served_dag_request_chirho(")
                .count(),
            expected_chirho,
            "{path_chirho} changed its reviewed admission-call inventory"
        );
    }

    let gate_source_chirho = [
        read_production_source_chirho(SERVE_ADMISSION_GATE_CHIRHO),
        read_production_source_chirho("crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/request_admission_chirho/served_request_abuse_gate_chirho/ingress_chirho.rs"),
    ].join("\n");
    for forbidden_chirho in [
        "std::fs",
        "File::",
        "OpenOptions",
        "store_chirho",
        "append_",
        "sign_",
        "serde",
        "Serialize",
        "Deserialize",
        "Debug",
    ] {
        assert!(
            !gate_source_chirho.contains(forbidden_chirho),
            "served request gate must remain bounded process memory with no durable or printable identity surface: {forbidden_chirho}"
        );
    }
    for required_chirho in [
        "try_acquire_owned(",
        "actor_bucket_cap_chirho",
        "blake3::Hasher::new_derive_key(",
        "is_loopback()",
        "X_FORWARDED_FOR_CHIRHO",
        "to_ipv4_mapped()",
        "network_chirho[8..].fill(0)",
    ] {
        assert!(
            gate_source_chirho.contains(required_chirho),
            "served request gate lost required bounded/trusted-source behavior: {required_chirho}"
        );
    }

    let app_session_chirho = read_production_source_chirho(SERVE_APP_SESSION_CHIRHO);
    assert!(
        app_session_chirho.find("if input_chirho.is_empty()").unwrap()
            < app_session_chirho
                .find("app_private_input_safe_metadata_chirho(")
                .unwrap()
            && app_session_chirho.find("if input_chirho.is_empty()").unwrap()
                < app_session_chirho
                    .find("privacy_chirho::store_private_blob_chirho(")
                    .unwrap(),
        "empty private input must become absent/public-empty before metadata extraction or randomized sealing"
    );
}
