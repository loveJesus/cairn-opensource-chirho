// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use std::collections::BTreeSet;

const SERVE_TREE_PREFIX_CHIRHO: &str = "crates/cairn-serve-runtime-chirho/src/";
const SERVE_ROOT_MODULE_CHIRHO: &str = "crates/cairn-serve-runtime-chirho/src/serve_chirho.rs";
const SERVE_APP_HTTP_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/app_http_chirho.rs";
const SERVE_INVOKE_TRANSPORT_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/invoke_transport_chirho.rs";
const SERVE_PUBLIC_RUN_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/public_run_chirho.rs";
const SERVE_SSR_WEB_CHIRHO: &str =
    "crates/cairn-serve-runtime-chirho/src/serve_chirho/runtime_web_chirho/ssr_web_chirho.rs";

#[test]
fn customer_app_write_execution_requires_tenant_root_guard_chirho() {
    let expected_executor_surfaces_chirho: BTreeSet<String> = [
        format!("{SERVE_APP_HTTP_CHIRHO}:try_run_served_input_with_context_chirho(:1:guarded:/app-chirho"),
        format!(
            "{SERVE_INVOKE_TRANSPORT_CHIRHO}:try_run_served_with_context_and_caller_key_chirho(:1:guarded:/invoke-chirho"
        ),
        format!("{SERVE_PUBLIC_RUN_CHIRHO}:try_run_chirho(:1:capability-rejected"),
        format!("{SERVE_SSR_WEB_CHIRHO}:try_run_served_with_context_chirho(:1:guarded:/ssr-chirho"),
        format!("{SERVE_ROOT_MODULE_CHIRHO}:executor-wrappers:8:wrapper-definitions"),
    ]
    .into_iter()
    .collect();
    let mut actual_executor_surfaces_chirho = BTreeSet::new();
    let guarded_surfaces_chirho = [
        (
            SERVE_APP_HTTP_CHIRHO,
            "try_run_served_input_with_context_chirho(",
            "/app-chirho",
            "app_http_dag_input_value_chirho(",
        ),
        (
            SERVE_INVOKE_TRANSPORT_CHIRHO,
            "try_run_served_with_context_and_caller_key_chirho(",
            "/invoke-chirho",
            "app_dag_input_chirho(",
        ),
        (
            SERVE_SSR_WEB_CHIRHO,
            "try_run_served_with_context_chirho(",
            "/ssr-chirho",
            "app_dag_input_chirho(",
        ),
    ];
    for path_chirho in workspace_production_rs_files_chirho() {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(SERVE_TREE_PREFIX_CHIRHO) {
            continue;
        }
        let text_chirho =
            std::fs::read_to_string(&path_chirho).expect("read app runtime execution surface");
        let production_chirho = production_text_chirho(&text_chirho);
        if rel_chirho == SERVE_ROOT_MODULE_CHIRHO {
            let wrapper_count_chirho = production_chirho.matches("try_run_chirho(").count()
                + production_chirho
                    .matches("try_run_with_context_chirho(")
                    .count()
                + production_chirho
                    .matches("try_run_served_with_context_chirho(")
                    .count()
                + production_chirho
                    .matches("try_run_served_with_context_and_caller_key_chirho(")
                    .count()
                + production_chirho
                    .matches("try_run_served_input_with_context_chirho(")
                    .count();
            if wrapper_count_chirho > 0 {
                assert!(
                    production_chirho.contains("fn try_run_chirho(")
                        && production_chirho.contains("fn try_run_with_context_chirho(")
                        && production_chirho.contains("fn try_run_served_with_context_chirho(")
                        && production_chirho.contains(
                            "fn try_run_served_with_context_and_caller_key_chirho(",
                        )
                        && production_chirho
                            .contains("fn try_run_served_input_with_context_chirho("),
                    "serve_chirho.rs executor matches must remain wrapper definitions/plumbing, not a hidden handler"
                );
                actual_executor_surfaces_chirho.insert(format!(
                    "{rel_chirho}:executor-wrappers:{wrapper_count_chirho}:wrapper-definitions"
                ));
            }
            continue;
        }
        for function_chirho in [
            "try_run_served_input_with_context_chirho(",
            "try_run_served_with_context_and_caller_key_chirho(",
            "try_run_served_with_context_chirho(",
            "try_run_with_context_chirho(",
            "try_run_chirho(",
        ] {
            let count_chirho = production_chirho.matches(function_chirho).count();
            if count_chirho == 0 {
                continue;
            }
            let posture_chirho = if rel_chirho.ends_with("public_run_chirho.rs")
                && function_chirho == "try_run_chirho("
            {
                let capability_reject_index_chirho = production_chirho
                    .find("ensure_public_run_dag_is_pure_wasm_chirho(")
                    .expect("public /run-chirho capability rejection guard exists");
                let public_run_index_chirho = production_chirho
                    .find("try_run_chirho(")
                    .expect("public /run-chirho executor call exists");
                assert!(
                    capability_reject_index_chirho < public_run_index_chirho,
                    "public /run-chirho must reject capability-bearing DAGs before execution"
                );
                "capability-rejected".to_string()
            } else {
                let matched_surface_chirho = guarded_surfaces_chirho
                    .iter()
                    .find(|(guarded_rel_chirho, guarded_function_chirho, _, _)| {
                        guarded_rel_chirho == &rel_chirho
                            && guarded_function_chirho == &function_chirho
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "unreviewed customer DAG executor seam lacks tenant-root write-guard classification: {rel_chirho}:{function_chirho}"
                        )
                    });
                format!("guarded:{}", matched_surface_chirho.2)
            };
            actual_executor_surfaces_chirho.insert(format!(
                "{rel_chirho}:{function_chirho}:{count_chirho}:{posture_chirho}"
            ));
        }
    }
    assert_eq!(
        actual_executor_surfaces_chirho, expected_executor_surfaces_chirho,
        "every served runtime DAG executor seam must be either tenant-root guarded or explicitly capability-rejected"
    );
    for (rel_chirho, function_chirho, surface_chirho, input_call_chirho) in guarded_surfaces_chirho
    {
        let path_chirho = workspace_root_chirho().join(rel_chirho);
        assert!(
            path_chirho.is_file(),
            "customer write tenant-root guard target is missing: {rel_chirho}"
        );
        let text_chirho =
            std::fs::read_to_string(&path_chirho).expect("read customer write guard target");
        let production_chirho = production_text_chirho(&text_chirho);
        assert_eq!(
            production_chirho
                .matches("ensure_customer_write_tenant_root_chirho(")
                .count(),
            1,
            "{rel_chirho} must call ensure_customer_write_tenant_root_chirho exactly once before customer app input construction"
        );
        let guard_index_chirho = production_chirho
            .find("ensure_customer_write_tenant_root_chirho(")
            .expect("guard call exists");
        let guard_tail_chirho = &production_chirho[guard_index_chirho..];
        let guard_end_chirho = guard_tail_chirho
            .find(") {")
            .or_else(|| guard_tail_chirho.find(")?;"))
            .unwrap_or(guard_tail_chirho.len());
        let guard_call_chirho = &guard_tail_chirho[..guard_end_chirho];
        assert!(
            guard_call_chirho.contains("&selection_chirho.dag_chirho")
                && guard_call_chirho.contains(surface_chirho),
            "{rel_chirho} guard must bind the selected DAG and name {surface_chirho}: {:?}",
            guard_call_chirho
        );
        let executor_index_chirho = production_chirho[guard_index_chirho..]
            .find(function_chirho)
            .map(|index_chirho| guard_index_chirho + index_chirho)
            .unwrap_or_else(|| panic!("{rel_chirho} missing {function_chirho}"));
        let input_index_chirho = production_chirho[guard_index_chirho..]
            .find(input_call_chirho)
            .map(|index_chirho| guard_index_chirho + index_chirho)
            .unwrap_or_else(|| panic!("{rel_chirho} missing {input_call_chirho}"));
        assert!(
            guard_index_chirho < input_index_chirho,
            "{rel_chirho} must reject PlatformRootChirho WriteStore app execution before request input construction"
        );
        assert!(
            guard_index_chirho < executor_index_chirho,
            "{rel_chirho} must reject PlatformRootChirho WriteStore app execution before DAG execution"
        );
    }
}
