// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Workspace hygiene caps, ratchets, and family guards moved out of the source scan hub.

use super::*;
use syn::visit::Visit;

const PROJECTION_DETERMINISM_FILES_CHIRHO: &[&str] = &[
    "crates/cairn-projection-chirho/src/gate1_state_digest_chirho.rs",
    "crates/cairn-projection-chirho/src/projection_chirho.rs",
    "crates/cairn-projection-chirho/src/semantic_billing_chirho.rs",
    "crates/cairn-projection-chirho/src/semantic_holds_chirho.rs",
    "crates/cairn-projection-chirho/src/semantic_parity_chirho.rs",
    "crates/cairn-projection-chirho/src/semantic_resources_chirho.rs",
    "crates/cairn-projection-chirho/src/typed_ingestion_chirho.rs",
];

const INPUT_PROJECTION_CRATE_CHIRHO: &str = "crates/runtime-chirho/cairn-input-projection-chirho";
const LEDGER_CONSERVATION_MONITOR_CRATE_CHIRHO: &str =
    "crates/ledger-chirho/cairn-ledger-conservation-monitor-chirho";
const LEDGER_READ_MODEL_CRATE_CHIRHO: &str = "crates/ledger-chirho/cairn-ledger-read-model-chirho";
const INPUT_PROJECTION_CRATE_SRC_CHIRHO: &str =
    "crates/runtime-chirho/cairn-input-projection-chirho/src/";
const INPUT_PROJECTION_INERT_CONSUMER_FILES_CHIRHO: &[&str] = &[
    "crates/authoring-chirho/cairn-tree-build-chirho/src/input_projection_chirho/mod.rs",
    "crates/runtime-chirho/cairn-model-app-chirho/src/app_source_manifest_v2_chirho/mod.rs",
    "crates/runtime-chirho/cairn-undo-plan-chirho/src/contract_chirho.rs",
    "crates/runtime-chirho/cairn-wasmtime-runner-chirho/src/input_attestation_chirho/mod.rs",
];
const INPUT_PROJECTION_FORBIDDEN_SOURCE_TOKENS_CHIRHO: &[&str] = &[
    "cairn_chirho::",
    "cairn_durable_chirho",
    "cairn_seqlog_chirho",
    "cairn_signer_chirho",
    "cairn_writer_head_chirho",
    "std::env",
    "std::fs",
    "std::net",
    "std::process",
    "wasmtime",
    "NodeDefChirho",
    "RunKeyChirho",
    "effect_chirho::",
    "refs_chirho::",
    "runner_chirho::",
    "sign_message_chirho(",
    "store_chirho::",
];

const ROOT_DIRECT_UNLOCKED_SEQLOG_APPEND_CALL_COUNT_CHIRHO: usize = 0;

const ROOT_DIRECT_UNLOCKED_SEQLOG_APPEND_FILES_CHIRHO: &[&str] = &[];

#[test]
fn walker_sees_root_and_crate_sources_chirho() {
    let files_chirho = workspace_production_rs_files_chirho();
    let names_chirho: Vec<String> = files_chirho
        .iter()
        .map(|path_chirho| workspace_relative_chirho(path_chirho))
        .collect();
    assert!(names_chirho
        .iter()
        .any(|name_chirho| name_chirho == "crates/cairn-cli-chirho/src/main.rs"));
    assert!(names_chirho
        .iter()
        .any(|name_chirho| name_chirho == "crates/support-chirho/cairn-secret-chirho/src/lib.rs"));
    assert!(names_chirho
        .iter()
        .any(|name_chirho| name_chirho == "src/lib.rs"));
    assert!(
        names_chirho.iter().any(|name_chirho| {
            name_chirho
                == "src/app_runtime_chirho/app_source_manifest_chirho/review_test_hooks_tests_chirho.rs"
        }),
        "a feature-gated production module must stay scanned despite its test-looking filename"
    );
    assert!(
        !names_chirho.iter().any(|name_chirho| {
            name_chirho
                == "crates/support-chirho/cairn-source-scan-chirho/src/production_scan_tests_chirho.rs"
        }),
        "a parent-declared cfg-test module must stay out of production scans"
    );
    assert!(
        names_chirho
            .iter()
            .any(|name_chirho| name_chirho.starts_with("crates/")),
        "walker must see workspace crate sources, not just src/"
    );
    let jsonl_surfaces_chirho = production_jsonl_logical_surface_inventory_chirho();
    assert!(!jsonl_surfaces_chirho.literal_root_files_chirho().is_empty());
    assert!(!jsonl_surfaces_chirho
        .dynamic_per_branch_populations_chirho()
        .is_empty());
}

#[test]
fn root_direct_unlocked_seqlog_append_sites_do_not_grow_chirho() {
    let expected_files_chirho: BTreeSet<String> = ROOT_DIRECT_UNLOCKED_SEQLOG_APPEND_FILES_CHIRHO
        .iter()
        .map(|path_chirho| (*path_chirho).to_string())
        .collect();
    let mut actual_files_chirho = BTreeSet::new();
    let mut actual_sites_chirho = Vec::new();
    for (file_chirho, line_chirho, text_chirho) in
        production_source_lines_matching_chirho("seqlog_chirho::append_jsonl_unlocked_chirho")
    {
        if !file_chirho.starts_with("src/") {
            continue;
        }
        actual_files_chirho.insert(file_chirho.clone());
        actual_sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
    }
    let unexpected_chirho: Vec<String> = actual_files_chirho
        .difference(&expected_files_chirho)
        .cloned()
        .collect();
    assert!(
        unexpected_chirho.is_empty(),
        "new root direct seqlog append files must use append_serialized_jsonl_chirho or append_recovered_jsonl_unlocked_chirho, or explicitly ratchet the reviewed file list: {unexpected_chirho:?}; all sites: {actual_sites_chirho:?}"
    );
    assert_eq!(
        actual_files_chirho, expected_files_chirho,
        "root direct seqlog append file list shrank; lower ROOT_DIRECT_UNLOCKED_SEQLOG_APPEND_FILES_CHIRHO in the same sweep"
    );
    assert_eq!(
        actual_sites_chirho.len(),
        ROOT_DIRECT_UNLOCKED_SEQLOG_APPEND_CALL_COUNT_CHIRHO,
        "root direct seqlog append call count changed; lower the constant on shrink or investigate growth: {actual_sites_chirho:?}"
    );
}

#[test]
fn runtime_executor_never_uses_explicit_caller_paid_charge_chirho() {
    let executor_files_chirho = [
        "src/execution_runtime_chirho/cache_chirho.rs",
        "src/execution_runtime_chirho/dag_chirho.rs",
        "src/execution_runtime_chirho/native_worker_chirho.rs",
    ];
    let offenders_chirho =
        production_source_lines_matching_chirho("invoke_priced_with_run_chirho(")
            .into_iter()
            .filter(|(file_chirho, _line_chirho, _text_chirho)| {
                executor_files_chirho.contains(&file_chirho.as_str())
            })
            .map(|(file_chirho, line_chirho, text_chirho)| {
                format!("{file_chirho}:{line_chirho}: {text_chirho}")
            })
            .collect::<Vec<_>>();
    assert!(
        offenders_chirho.is_empty(),
        "served/native runtime executors must not charge a self-declared explicit caller; use verified RequestContextChirho app billing instead: {offenders_chirho:?}"
    );
}

#[test]
fn legacy_paid_executor_primitives_stay_removed_chirho() {
    let explicit_paid_sites_chirho =
        production_source_lines_matching_chirho("run_authorized_explicit_paid_effect_chirho(");
    assert!(
        explicit_paid_sites_chirho.is_empty(),
        "the removed node-less explicit-paid primitive must not return: {explicit_paid_sites_chirho:?}"
    );

    let priced_executor_sites_chirho =
        production_source_lines_matching_chirho("invoke_priced_with_run_chirho(");
    assert!(
        priced_executor_sites_chirho.is_empty(),
        "the removed legacy priced-effect executor must not return: {priced_executor_sites_chirho:?}"
    );
}

#[test]
fn blessed_registry_v2_runtime_admission_stays_exactly_allowlisted_chirho() {
    let expected_resolver_callers_chirho = std::collections::BTreeMap::from([(
        "src/app_authoring_chirho/blessed_chirho/v2_registry_chirho/effect_admission_chirho.rs"
            .to_string(),
        1usize,
    )]);
    let mut actual_resolver_callers_chirho = std::collections::BTreeMap::<String, usize>::new();
    let mut resolver_sites_chirho = Vec::new();
    for (file_chirho, line_chirho, text_chirho) in production_source_lines_matching_chirho(
        "resolve_registry_v2_contract_for_capability_chirho(",
    ) {
        *actual_resolver_callers_chirho
            .entry(file_chirho.clone())
            .or_insert(0) += 1;
        resolver_sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
    }
    assert_eq!(
        actual_resolver_callers_chirho, expected_resolver_callers_chirho,
        "raw registry-v2 resolution must stay behind the one admission-capability module: {resolver_sites_chirho:?}"
    );

    let source_chirho = std::fs::read_to_string(workspace_root_chirho().join(
        "src/app_authoring_chirho/blessed_chirho/v2_registry_chirho/effect_admission_chirho.rs",
    ))
    .unwrap();
    assert!(
        source_chirho.contains("fn resolve_registry_v2_contract_for_capability_chirho<'a>(")
            && !source_chirho
                .contains("pub fn resolve_registry_v2_contract_for_capability_chirho<'a>(")
            && !source_chirho
                .contains("pub(crate) fn resolve_registry_v2_contract_for_capability_chirho<'a>(")
            && !source_chirho
                .contains("pub(super) fn resolve_registry_v2_contract_for_capability_chirho<'a>("),
        "the raw registry-v2 resolver must remain private inside the admission-capability module"
    );

    let expected_verified_issuers_chirho = std::collections::BTreeMap::from([
        (
            "src/execution_runtime_chirho/cache_chirho.rs".to_string(),
            2usize,
        ),
        (
            "src/execution_runtime_chirho/native_worker_chirho.rs".to_string(),
            1usize,
        ),
    ]);
    let mut actual_verified_issuers_chirho = std::collections::BTreeMap::<String, usize>::new();
    let mut issuer_sites_chirho = Vec::new();
    for (file_chirho, line_chirho, text_chirho) in
        production_source_lines_matching_chirho("admit_verified_node_effect_chirho(")
    {
        if file_chirho
            == "src/app_authoring_chirho/blessed_chirho/v2_registry_chirho/effect_admission_chirho.rs"
        {
            continue;
        }
        *actual_verified_issuers_chirho
            .entry(file_chirho.clone())
            .or_insert(0) += 1;
        issuer_sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
    }
    assert_eq!(
        actual_verified_issuers_chirho, expected_verified_issuers_chirho,
        "verified-node admission issuers are an exact reviewed runtime surface: {issuer_sites_chirho:?}"
    );

    let expected_legacy_issuers_chirho = std::collections::BTreeMap::from([
        (
            "src/execution_runtime_chirho/effect_chirho.rs".to_string(),
            2usize,
        ),
        (
            "src/execution_runtime_chirho/native_worker_chirho.rs".to_string(),
            1usize,
        ),
    ]);
    let mut actual_legacy_issuers_chirho = std::collections::BTreeMap::<String, usize>::new();
    let mut legacy_sites_chirho = Vec::new();
    for (file_chirho, line_chirho, text_chirho) in
        production_source_lines_matching_chirho("admit_legacy_operator_effect_chirho(")
    {
        if file_chirho
            == "src/app_authoring_chirho/blessed_chirho/v2_registry_chirho/effect_admission_chirho.rs"
        {
            continue;
        }
        *actual_legacy_issuers_chirho
            .entry(file_chirho.clone())
            .or_insert(0) += 1;
        legacy_sites_chirho.push(format!("{file_chirho}:{line_chirho}: {text_chirho}"));
    }
    assert_eq!(
        actual_legacy_issuers_chirho, expected_legacy_issuers_chirho,
        "node-less legacy admission must remain confined to reviewed operator/internal wrappers: {legacy_sites_chirho:?}"
    );

    let verified_native_callers_chirho = production_source_lines_matching_chirho(
        "run_verified_native_node_cached_with_context_chirho(",
    )
    .into_iter()
    .filter(|(file_chirho, _line_chirho, _text_chirho)| {
        file_chirho != "src/execution_runtime_chirho/native_worker_chirho.rs"
    })
    .collect::<Vec<_>>();
    assert_eq!(
        verified_native_callers_chirho.len(),
        1,
        "the verified native-node entry must remain called only by the DAG runtime: {verified_native_callers_chirho:?}"
    );
    assert_eq!(
        verified_native_callers_chirho[0].0, "src/execution_runtime_chirho/dag_chirho.rs",
        "the verified native-node entry must remain called only by the DAG runtime"
    );
}

#[test]
fn app_deployment_callers_stay_classified_and_exact_chirho() {
    let descriptor_v2_gated_callers_chirho = std::collections::BTreeMap::from([
        (
            "src/app_authoring_chirho/app_manifest_chirho.rs".to_string(),
            3usize,
        ),
        (
            "src/app_runtime_chirho/publish_chirho.rs".to_string(),
            2usize,
        ),
        (
            "src/governance_flows_chirho/review_chirho/mod.rs".to_string(),
            1usize,
        ),
        (
            "src/app_runtime_chirho/app_chirho/template_app_deploy_chirho.rs".to_string(),
            1usize,
        ),
        // The self-service publication applier: `judge_chirho` resolves the template on the
        // verified registry and runs `verify_descriptor_v2_deployment_chirho` on its root DAG
        // before `ApplyChirho` is reachable; that verified hash is the only thing it deploys.
        (
            "src/app_runtime_chirho/publication_chirho/apply_chirho.rs".to_string(),
            1usize,
        ),
    ]);
    let operator_legacy_callers_chirho = std::collections::BTreeMap::from([
        (
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/core_chirho/demo_cli_chirho.rs"
                .to_string(),
            2usize,
        ),
        (
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/product_chirho/app_chirho/app_deploy_cli_chirho.rs"
                .to_string(),
            2usize,
        ),
        (
            "crates/services-chirho/cairn-learner-handover-chirho/src/lib.rs".to_string(),
            1usize,
        ),
    ]);
    let low_level_facade_callers_chirho = std::collections::BTreeMap::from([(
        "src/app_runtime_chirho/app_chirho/app_route_chirho.rs".to_string(),
        2usize,
    )]);
    // Putting back a failed promotion's prior surface (PFE #25681, CAIRN #25683). It deploys only the root and the
    // route DAGs that `capture_app_live_surface_chirho` read from the app's verified records just before the
    // promotion, so it can re-establish a state that was already live and nothing else. Its surface type has private
    // fields, constructed only by that capture, and the module's only public entry is the promote wrapper: no caller
    // can hand it a DAG. A reviewer judges THAT argument here; it is not a descriptor-v2 check.
    let prior_live_restore_callers_chirho = std::collections::BTreeMap::from([(
        "src/app_runtime_chirho/app_source_manifest_chirho/reviewed_surface_restore_chirho.rs"
            .to_string(),
        2usize,
    )]);
    let mut expected_callers_chirho = descriptor_v2_gated_callers_chirho.clone();
    expected_callers_chirho.extend(operator_legacy_callers_chirho.clone());
    expected_callers_chirho.extend(low_level_facade_callers_chirho);
    expected_callers_chirho.extend(prior_live_restore_callers_chirho);

    let deployment_functions_chirho = [
        "deploy_app_chirho(",
        "deploy_app_unreviewed_dev_chirho(",
        "deploy_app_route_chirho(",
        "deploy_app_route_unreviewed_dev_chirho(",
        "deploy_app_route_with_request_body_policy_chirho(",
    ]
    .map(|name_chirho| name_chirho.trim_end_matches('('));
    let (actual_callers_chirho, forbidden_indirections_chirho) =
        parsed_call_inventory_chirho(&deployment_functions_chirho);
    assert!(
        forbidden_indirections_chirho.is_empty(),
        "low-level deployment functions may only be invoked as direct parsed calls; aliases, function pointers, and macro-hidden calls are forbidden: {forbidden_indirections_chirho:?}"
    );
    assert_eq!(
        actual_callers_chirho, expected_callers_chirho,
        "every parsed low-level app/root/route deployment call must stay exactly classified as descriptor-v2 binding-verified-or-pure, named operator legacy, or the prior-live restore; no unlabelled deployment door may appear"
    );
}

#[test]
fn legacy_effect_execution_callers_stay_operator_or_internal_chirho() {
    let legacy_functions_chirho = [
        "run_effect_chirho",
        "run_effect_with_context_chirho",
        "run_effect_with_context_and_value_storage_chirho",
        "run_net_request_with_private_headers_chirho",
        "run_native_program_cached_chirho",
        "run_native_program_cached_with_context_chirho",
        "run_native_program_node_cached_with_context_chirho",
    ];
    let expected_callers_chirho = std::collections::BTreeMap::from([
        (
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/core_chirho/native_cli_chirho.rs"
                .to_string(),
            1usize,
        ),
        (
            "crates/cairn-cli-chirho/src/cli_helpers_chirho/operations_chirho/runtime_cli_chirho.rs"
                .to_string(),
            1usize,
        ),
        (
            "crates/services-chirho/cairn-dag-command-chirho/src/lib.rs".to_string(),
            1usize,
        ),
        (
            "src/execution_runtime_chirho/effect_chirho.rs".to_string(),
            2usize,
        ),
        (
            "src/execution_runtime_chirho/native_worker_chirho.rs".to_string(),
            2usize,
        ),
    ]);
    let (actual_callers_chirho, forbidden_indirections_chirho) =
        parsed_call_inventory_chirho(&legacy_functions_chirho);
    assert!(
        forbidden_indirections_chirho.is_empty(),
        "legacy effect execution entries may only be direct parsed calls; aliases, function pointers, and macro-hidden calls are forbidden: {forbidden_indirections_chirho:?}"
    );
    assert_eq!(
        actual_callers_chirho, expected_callers_chirho,
        "node-less legacy effect execution must remain confined to exact operator/internal callers; app DAG execution uses verified-node admission"
    );
}

fn parsed_call_inventory_chirho(
    guarded_functions_chirho: &[&str],
) -> (std::collections::BTreeMap<String, usize>, Vec<String>) {
    let mut actual_callers_chirho = std::collections::BTreeMap::<String, usize>::new();
    let mut forbidden_indirections_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho() {
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        if !guarded_functions_chirho
            .iter()
            .any(|name_chirho| text_chirho.contains(name_chirho))
        {
            continue;
        }
        let production_chirho = production_text_chirho(&text_chirho);
        let syntax_chirho = syn::parse_file(production_chirho.as_ref()).unwrap_or_else(
            |error_chirho| {
                panic!(
                    "failed to parse production Rust source {} for exact call inventory: {error_chirho}",
                    workspace_relative_chirho(&path_chirho)
                )
            },
        );
        let file_chirho = workspace_relative_chirho(&path_chirho);
        let mut visitor_chirho = ExactCallInventoryVisitorChirho {
            file_chirho: &file_chirho,
            guarded_functions_chirho,
            direct_calls_chirho: &mut actual_callers_chirho,
            forbidden_indirections_chirho: &mut forbidden_indirections_chirho,
        };
        visitor_chirho.visit_file(&syntax_chirho);
    }
    (actual_callers_chirho, forbidden_indirections_chirho)
}

struct ExactCallInventoryVisitorChirho<'a> {
    file_chirho: &'a str,
    guarded_functions_chirho: &'a [&'a str],
    direct_calls_chirho: &'a mut std::collections::BTreeMap<String, usize>,
    forbidden_indirections_chirho: &'a mut Vec<String>,
}

impl ExactCallInventoryVisitorChirho<'_> {
    fn guarded_function_chirho(&self, expression_chirho: &syn::Expr) -> Option<String> {
        let syn::Expr::Path(path_chirho) = expression_chirho else {
            return None;
        };
        let name_chirho = path_chirho.path.segments.last()?.ident.to_string();
        self.guarded_functions_chirho
            .contains(&name_chirho.as_str())
            .then_some(name_chirho)
    }

    fn use_tree_renames_guarded_chirho(&self, tree_chirho: &syn::UseTree) -> bool {
        match tree_chirho {
            syn::UseTree::Path(path_chirho) => {
                self.use_tree_renames_guarded_chirho(&path_chirho.tree)
            }
            syn::UseTree::Group(group_chirho) => group_chirho
                .items
                .iter()
                .any(|item_chirho| self.use_tree_renames_guarded_chirho(item_chirho)),
            syn::UseTree::Rename(rename_chirho) => self
                .guarded_functions_chirho
                .contains(&rename_chirho.ident.to_string().as_str()),
            syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
        }
    }

    fn macro_names_guarded_function_chirho(
        &self,
        tokens_chirho: proc_macro2::TokenStream,
    ) -> Option<String> {
        for token_chirho in tokens_chirho {
            match token_chirho {
                proc_macro2::TokenTree::Ident(ident_chirho) => {
                    let name_chirho = ident_chirho.to_string();
                    if self
                        .guarded_functions_chirho
                        .contains(&name_chirho.as_str())
                    {
                        return Some(name_chirho);
                    }
                }
                proc_macro2::TokenTree::Group(group_chirho) => {
                    if let Some(name_chirho) =
                        self.macro_names_guarded_function_chirho(group_chirho.stream())
                    {
                        return Some(name_chirho);
                    }
                }
                proc_macro2::TokenTree::Punct(_) | proc_macro2::TokenTree::Literal(_) => {}
            }
        }
        None
    }
}

impl<'ast_chirho> Visit<'ast_chirho> for ExactCallInventoryVisitorChirho<'_> {
    fn visit_expr_call(&mut self, call_chirho: &'ast_chirho syn::ExprCall) {
        if self.guarded_function_chirho(&call_chirho.func).is_some() {
            *self
                .direct_calls_chirho
                .entry(self.file_chirho.to_string())
                .or_insert(0) += 1;
            for argument_chirho in &call_chirho.args {
                self.visit_expr(argument_chirho);
            }
            return;
        }
        syn::visit::visit_expr_call(self, call_chirho);
    }

    fn visit_expr_path(&mut self, path_chirho: &'ast_chirho syn::ExprPath) {
        if let Some(name_chirho) = path_chirho
            .path
            .segments
            .last()
            .map(|part_chirho| part_chirho.ident.to_string())
        {
            if self
                .guarded_functions_chirho
                .contains(&name_chirho.as_str())
            {
                self.forbidden_indirections_chirho.push(format!(
                    "{}: non-call reference to {name_chirho}",
                    self.file_chirho
                ));
                return;
            }
        }
        syn::visit::visit_expr_path(self, path_chirho);
    }

    fn visit_item_use(&mut self, use_chirho: &'ast_chirho syn::ItemUse) {
        if self.use_tree_renames_guarded_chirho(&use_chirho.tree) {
            self.forbidden_indirections_chirho.push(format!(
                "{}: renamed low-level deployment import",
                self.file_chirho
            ));
        }
        syn::visit::visit_item_use(self, use_chirho);
    }

    fn visit_macro(&mut self, macro_chirho: &'ast_chirho syn::Macro) {
        if let Some(name_chirho) =
            self.macro_names_guarded_function_chirho(macro_chirho.tokens.clone())
        {
            self.forbidden_indirections_chirho.push(format!(
                "{}: macro token stream names {name_chirho}",
                self.file_chirho
            ));
            return;
        }
        syn::visit::visit_macro(self, macro_chirho);
    }
}

#[test]
fn deployment_call_inventory_rejects_indirect_authority_paths_chirho() {
    let syntax_chirho = syn::parse_file(
        r#"
        use crate::deploy_app_chirho as bypass_chirho;

        fn fixture_chirho() {
            deploy_app_chirho();
            let pointer_chirho = crate::deploy_app_chirho;
            hidden_chirho!(deploy_app_chirho());
        }
        "#,
    )
    .unwrap();
    let deployment_functions_chirho = ["deploy_app_chirho"];
    let mut calls_chirho = std::collections::BTreeMap::new();
    let mut violations_chirho = Vec::new();
    let mut visitor_chirho = ExactCallInventoryVisitorChirho {
        file_chirho: "fixture_chirho.rs",
        guarded_functions_chirho: &deployment_functions_chirho,
        direct_calls_chirho: &mut calls_chirho,
        forbidden_indirections_chirho: &mut violations_chirho,
    };
    visitor_chirho.visit_file(&syntax_chirho);
    assert_eq!(calls_chirho.get("fixture_chirho.rs"), Some(&1));
    assert_eq!(violations_chirho.len(), 3);
    assert!(violations_chirho
        .iter()
        .any(|violation_chirho| violation_chirho.contains("renamed")));
    assert!(violations_chirho
        .iter()
        .any(|violation_chirho| violation_chirho.contains("non-call reference")));
    assert!(violations_chirho
        .iter()
        .any(|violation_chirho| violation_chirho.contains("macro token stream")));
}

fn collect_provider_adapter_crate_dirs_chirho(dir_chirho: &Path, out_chirho: &mut Vec<PathBuf>) {
    let Ok(entries_chirho) = std::fs::read_dir(dir_chirho) else {
        return;
    };
    for entry_chirho in entries_chirho.flatten() {
        let path_chirho = entry_chirho.path();
        if !path_chirho.is_dir() {
            continue;
        }
        let name_chirho = entry_chirho.file_name().to_string_lossy().to_string();
        if name_chirho.starts_with('.') || name_chirho == "target" {
            continue;
        }
        if name_chirho.ends_with("-adapter-chirho") && path_chirho.join("Cargo.toml").is_file() {
            out_chirho.push(path_chirho.clone());
        }
        collect_provider_adapter_crate_dirs_chirho(&path_chirho, out_chirho);
    }
}

#[test]
fn provider_adapter_crates_must_not_import_root_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let mut adapter_crates_chirho = Vec::new();
    collect_provider_adapter_crate_dirs_chirho(
        &root_chirho.join("crates"),
        &mut adapter_crates_chirho,
    );
    adapter_crates_chirho.sort();
    let forbidden_cargo_deps_chirho = [
        "cairn-chirho",
        "cairn-perffection-stripe-chirho",
        "cairn-model-economic-chirho",
    ];
    let forbidden_rust_tokens_chirho = [
        "cairn_chirho::",
        "ledger_chirho",
        "seqlog_chirho",
        "privacy_chirho",
        "effect_chirho",
        "store_chirho",
        "root_chirho",
        "reconciliation_chirho",
        "private_blob",
        "sign_message",
    ];
    let mut offenders_chirho = Vec::new();
    for crate_dir_chirho in adapter_crates_chirho {
        let cargo_toml_chirho =
            std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml")).unwrap();
        for dep_chirho in forbidden_cargo_deps_chirho {
            let dep_line_chirho = format!("{dep_chirho} =");
            if cargo_toml_chirho.contains(&dep_line_chirho) {
                offenders_chirho.push(format!(
                    "{}/Cargo.toml imports forbidden dependency {dep_chirho}",
                    workspace_relative_chirho(&crate_dir_chirho)
                ));
            }
        }

        let mut files_chirho = Vec::new();
        collect_rs_files_chirho(&crate_dir_chirho.join("src"), &mut files_chirho);
        for path_chirho in files_chirho {
            let label_chirho = workspace_relative_chirho(&path_chirho);
            let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
            for (line_chirho, source_chirho) in
                production_text_chirho(&text_chirho).lines().enumerate()
            {
                let trimmed_chirho = source_chirho.trim();
                if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                    continue;
                }
                for token_chirho in forbidden_rust_tokens_chirho {
                    if trimmed_chirho.contains(token_chirho) {
                        offenders_chirho.push(format!(
                            "{label_chirho}:{} contains forbidden adapter authority token {token_chirho}: {trimmed_chirho}",
                            line_chirho + 1
                        ));
                    }
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "provider adapter crates must stay free of Cairn root-authority deps/imports: {offenders_chirho:?}"
    );
}

#[test]
fn archived_perffection_stripe_pillar_stays_out_of_generic_workspace_chirho() {
    let root_chirho = workspace_root_chirho();
    let workspace_manifest_chirho =
        std::fs::read_to_string(root_chirho.join("Cargo.toml")).unwrap();
    let cli_manifest_chirho =
        std::fs::read_to_string(root_chirho.join("crates/cairn-cli-chirho/Cargo.toml")).unwrap();
    let pillar_root_chirho = root_chirho.join("crates/cairn-perffection-platform-chirho");

    assert!(
        !workspace_manifest_chirho.contains("cairn-perffection-stripe-chirho"),
        "the archived Stripe product pillar must not return as a generic workspace member"
    );
    assert!(
        !cli_manifest_chirho.contains("cairn-perffection-stripe-chirho"),
        "the generic CLI must not regain a product Stripe dependency"
    );
    assert!(
        !pillar_root_chirho
            .join("cairn-perffection-stripe-chirho")
            .exists()
            && !pillar_root_chirho
                .join("cairn-perffection-stripe-adapter-chirho")
                .exists(),
        "parked product code belongs in the archive tag until the Perffection-owned extraction"
    );

    let mut cli_sources_chirho = Vec::new();
    collect_rs_files_chirho(
        &root_chirho.join("crates/cairn-cli-chirho/src"),
        &mut cli_sources_chirho,
    );
    let forbidden_cli_tokens_chirho = [
        "cairn_perffection_stripe_chirho",
        "stripe_router_chirho",
        "StripeCheckoutChirho",
        "ConnectAccountRecordChirho",
        "PayoutRunChirho",
        "StripeTopupRecordChirho",
        "ReconciliationVerifyChirho",
    ];
    let mut offenders_chirho = Vec::new();
    for path_chirho in cli_sources_chirho {
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for token_chirho in forbidden_cli_tokens_chirho {
            if source_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{} contains archived product token {token_chirho}",
                    workspace_relative_chirho(&path_chirho)
                ));
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "the generic CLI must not restore archived Stripe product composition: {offenders_chirho:?}"
    );
}

#[test]
fn projection_materialize_stays_deterministic_chirho() {
    let forbidden_tokens_chirho = [
        "SystemTime",
        "UNIX_EPOCH",
        "Instant::",
        "thread_rng",
        "random::<",
        "rand::",
        "HashMap",
        "DefaultHasher",
        "std::env::var",
        "current_dir",
    ];
    let mut offenders_chirho = Vec::new();
    for file_chirho in PROJECTION_DETERMINISM_FILES_CHIRHO {
        let path_chirho = workspace_root_chirho().join(file_chirho);
        assert!(
            path_chirho.is_file(),
            "projection determinism guard target is missing: {file_chirho}"
        );
        let text_chirho =
            std::fs::read_to_string(&path_chirho).expect("read projection guard target");
        let production_chirho = production_text_chirho(&text_chirho);
        for (line_chirho, source_chirho) in production_chirho.lines().enumerate() {
            let trimmed_chirho = source_chirho.trim();
            if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
                continue;
            }
            for token_chirho in forbidden_tokens_chirho {
                if trimmed_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{file_chirho}:{} contains {token_chirho}: {trimmed_chirho}",
                        line_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "Gate 1 projection materialization must stay deterministic and process-stable: {offenders_chirho:?}"
    );
}

fn input_projection_forbidden_source_sites_in_text_chirho(
    rel_chirho: &str,
    text_chirho: &str,
) -> Vec<String> {
    let mut offenders_chirho = Vec::new();
    let production_chirho = production_text_chirho(text_chirho);
    for (line_index_chirho, line_chirho) in production_chirho.lines().enumerate() {
        let trimmed_chirho = line_chirho.trim();
        if trimmed_chirho.is_empty() || trimmed_chirho.starts_with("//") {
            continue;
        }
        for token_chirho in INPUT_PROJECTION_FORBIDDEN_SOURCE_TOKENS_CHIRHO {
            if trimmed_chirho.contains(token_chirho) {
                offenders_chirho.push(format!(
                    "{rel_chirho}:{}:{token_chirho}: {trimmed_chirho}",
                    line_index_chirho + 1
                ));
            }
        }
    }
    offenders_chirho
}

#[test]
fn input_projection_packet3_stays_authority_inert_and_downward_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_dir_chirho = root_chirho.join(INPUT_PROJECTION_CRATE_CHIRHO);
    let manifest_chirho = std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml")).unwrap();
    let dependencies_chirho = manifest_chirho
        .split_once("[dependencies]")
        .expect("input-projection manifest must declare dependencies")
        .1
        .split("\n[")
        .next()
        .unwrap();
    let actual_dependencies_chirho: BTreeSet<&str> = dependencies_chirho
        .lines()
        .filter_map(|line_chirho| line_chirho.split_once('='))
        .map(|(name_chirho, _value_chirho)| name_chirho.trim())
        .filter(|name_chirho| !name_chirho.is_empty())
        .collect();
    let expected_dependencies_chirho = BTreeSet::from([
        "anyhow",
        "blake3",
        "cairn-core-chirho",
        "cairn-model-privacy-chirho",
        "serde",
        "serde_json",
    ]);
    assert_eq!(
        actual_dependencies_chirho, expected_dependencies_chirho,
        "input-projection packet 2 must keep its exact downward, authority-free dependency set"
    );

    let workspace_manifest_chirho =
        std::fs::read_to_string(root_chirho.join("Cargo.toml")).unwrap();
    assert_eq!(
        workspace_manifest_chirho
            .matches("crates/runtime-chirho/cairn-input-projection-chirho")
            .count(),
        1,
        "input-projection must be registered exactly once as a workspace member"
    );

    let mut production_files_chirho = Vec::new();
    collect_rs_files_chirho(&crate_dir_chirho.join("src"), &mut production_files_chirho);
    let mut offenders_chirho = Vec::new();
    for path_chirho in production_files_chirho {
        let rel_chirho = workspace_relative_chirho(&path_chirho);
        if !rel_chirho.starts_with(INPUT_PROJECTION_CRATE_SRC_CHIRHO)
            || rel_chirho.ends_with("tests_chirho.rs")
            || rel_chirho.ends_with("_tests_chirho.rs")
        {
            continue;
        }
        let text_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        offenders_chirho.extend(input_projection_forbidden_source_sites_in_text_chirho(
            &rel_chirho,
            &text_chirho,
        ));
    }
    assert!(
        offenders_chirho.is_empty(),
        "input-projection packet 2 gained an I/O, authority, signer, or runner surface: {offenders_chirho:?}"
    );

    let external_consumers_chirho =
        production_source_lines_matching_chirho("cairn_input_projection_chirho::")
            .into_iter()
            .filter(|(file_chirho, _line_chirho, _text_chirho)| {
                !file_chirho.starts_with(INPUT_PROJECTION_CRATE_SRC_CHIRHO)
            })
            .collect::<Vec<_>>();
    let actual_consumer_files_chirho = external_consumers_chirho
        .iter()
        .map(|(file_chirho, _line_chirho, _text_chirho)| file_chirho.clone())
        .collect::<BTreeSet<_>>();
    let expected_consumer_files_chirho = INPUT_PROJECTION_INERT_CONSUMER_FILES_CHIRHO
        .iter()
        .map(|file_chirho| (*file_chirho).to_string())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_consumer_files_chirho, expected_consumer_files_chirho,
        "input projection may have only the reviewed inert model, authoring, undo-plan privacy, and custom-section extractor consumers before packet 4: {external_consumers_chirho:?}"
    );

    let activated_root_sites_chirho =
        production_source_lines_matching_chirho("APP_SOURCE_MANIFEST_V2_SCHEMA_CHIRHO")
            .into_iter()
            .filter(|(file_chirho, _line_chirho, _text_chirho)| file_chirho.starts_with("src/"))
            .collect::<Vec<_>>();
    assert!(
        activated_root_sites_chirho.is_empty(),
        "packet 3 must not activate source-manifest v2 in a root production reader: {activated_root_sites_chirho:?}"
    );

    let v1_manifest_boundary_files_chirho =
        production_source_lines_matching_chirho("require_app_source_manifest_v1_chirho(")
            .into_iter()
            .fold(
                std::collections::BTreeMap::<String, usize>::new(),
                |mut counts_chirho, site_chirho| {
                    *counts_chirho.entry(site_chirho.0).or_default() += 1;
                    counts_chirho
                },
            );
    assert_eq!(
        v1_manifest_boundary_files_chirho,
        std::collections::BTreeMap::from([
            (
                "src/app_runtime_chirho/app_source_manifest_chirho.rs".to_string(),
                4,
            ),
            (
                "src/app_runtime_chirho/app_source_manifest_chirho/prepared_inputs_chirho.rs"
                    .to_string(),
                1,
            ),
            (
                "src/app_runtime_chirho/app_source_manifest_chirho/subscription_view_binding_chirho.rs"
                    .to_string(),
                1,
            ),
        ]),
        "path and stored-hash source-manifest readers must reject non-v1 schema immediately after permissive deserialization: {v1_manifest_boundary_files_chirho:?}"
    );

    let tree_emitter_chirho =
        std::fs::read_to_string(root_chirho.join(
            "crates/authoring-chirho/cairn-tree-build-chirho/src/codegen_chirho/emit_chirho.rs",
        ))
        .unwrap();
    assert!(tree_emitter_chirho.contains("app-source-manifest-v1-chirho"));
    assert!(!tree_emitter_chirho.contains("app-source-manifest-v2-chirho"));

    let attestation_reader_files_chirho =
        production_source_lines_matching_chirho("read_input_schema_attestation_chirho(")
            .into_iter()
            .map(|(file_chirho, _line_chirho, _text_chirho)| file_chirho)
            .collect::<BTreeSet<_>>();
    assert_eq!(
        attestation_reader_files_chirho,
        BTreeSet::from([
            "crates/authoring-chirho/cairn-tree-build-chirho/src/input_projection_chirho/mod.rs"
                .to_string(),
            "crates/runtime-chirho/cairn-wasmtime-runner-chirho/src/input_attestation_chirho/mod.rs"
                .to_string(),
        ]),
        "the inert custom-section reader must remain defined in the runner and called only by tree-build"
    );

    let inert_checker_sites_chirho =
        production_source_lines_matching_chirho("check_inert_input_projection_chirho(");
    assert!(
        inert_checker_sites_chirho.is_empty(),
        "packet 3 defines the generic checker but must have zero production callers until atomic activation: {inert_checker_sites_chirho:?}"
    );
    let tree_projection_chirho = std::fs::read_to_string(root_chirho.join(
        "crates/authoring-chirho/cairn-tree-build-chirho/src/input_projection_chirho/mod.rs",
    ))
    .unwrap();
    assert!(tree_projection_chirho.contains("pub fn check_inert_input_projection_chirho<"));

    let sdk_exact_chirho = std::fs::read_to_string(
        root_chirho.join("crates/cairn-node-sdk-chirho/src/exact_json_chirho/mod.rs"),
    )
    .unwrap();
    assert_eq!(
        sdk_exact_chirho
            .matches("#[link_section = \"cairn-input-schema-chirho\"]")
            .count(),
        1,
        "the SDK must emit the contract's exact WASM custom-section name"
    );
    assert!(
        !sdk_exact_chirho.contains(".custom_section.cairn-input-schema-chirho"),
        "the dotted linker spelling emits the wrong physical WASM custom-section name"
    );
}

#[test]
fn input_projection_inertness_guard_detects_authority_and_io_plants_chirho() {
    let planted_chirho = "use std::fs;\nfn invoke_chirho(value_chirho: RunKeyChirho) { runner_chirho::run_node_chirho(value_chirho); }";
    let offenders_chirho = input_projection_forbidden_source_sites_in_text_chirho(
        "crates/runtime-chirho/cairn-input-projection-chirho/src/planted_chirho.rs",
        planted_chirho,
    );
    assert!(offenders_chirho
        .iter()
        .any(|site_chirho| site_chirho.contains("std::fs")));
    assert!(offenders_chirho
        .iter()
        .any(|site_chirho| site_chirho.contains("RunKeyChirho")));
    assert!(offenders_chirho
        .iter()
        .any(|site_chirho| site_chirho.contains("runner_chirho::")));
}

#[test]
fn review_policy_crate_stays_leaf_no_io_or_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_dir_chirho = root_chirho.join("crates/domain-chirho/cairn-review-policy-chirho");
    let manifest_chirho = std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml"))
        .expect("read review policy Cargo.toml");
    let depends_on_root_chirho = manifest_chirho
        .lines()
        .any(|line_chirho| line_chirho.trim_start().starts_with("cairn-chirho"));
    assert!(
        !depends_on_root_chirho,
        "cairn-review-policy-chirho must not depend on root cairn-chirho"
    );

    let mut files_chirho = Vec::new();
    collect_rs_files_chirho(&crate_dir_chirho.join("src"), &mut files_chirho);
    let forbidden_chirho = [
        "std::fs",
        "std::path",
        "read_to_string",
        "write(",
        "File::",
        "cairn_chirho::",
        "store_chirho::",
        "refs_chirho::",
        "identity_chirho::",
        "effect_chirho::",
        "seqlog_chirho::",
        "crate::app_chirho",
        "cairn_chirho::app_chirho",
        "effect_pricing_chirho::",
        "pricebook_chirho::",
        "paid_chirho::",
    ];
    let mut offenders_chirho = Vec::new();
    for file_chirho in files_chirho {
        let text_chirho = std::fs::read_to_string(&file_chirho).unwrap();
        for (line_chirho, text_chirho) in production_text_chirho(&text_chirho).lines().enumerate() {
            for needle_chirho in forbidden_chirho {
                if text_chirho.contains(needle_chirho) {
                    offenders_chirho.push(format!(
                        "{}:{}:{needle_chirho}",
                        workspace_relative_chirho(&file_chirho),
                        line_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "review policy crate must stay pure/leaf: no root dependency, filesystem/path I/O, or root authority imports: {offenders_chirho:?}"
    );
}

#[test]
fn ledger_conservation_monitor_stays_pure_detect_only_and_downward_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_dir_chirho = root_chirho.join(LEDGER_CONSERVATION_MONITOR_CRATE_CHIRHO);
    let manifest_chirho = std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml"))
        .expect("read ledger conservation monitor Cargo.toml");
    let dependency_section_chirho = manifest_chirho
        .split_once("[dependencies]")
        .expect("ledger conservation monitor must declare dependencies")
        .1
        .split("\n[")
        .next()
        .unwrap();
    let dependency_lines_chirho = dependency_section_chirho
        .lines()
        .map(str::trim)
        .filter(|line_chirho| !line_chirho.is_empty() && !line_chirho.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(
        dependency_lines_chirho,
        vec!["cairn-ledger-model-chirho = { path = \"../cairn-ledger-model-chirho\" }"],
        "the CF4 checker must depend downward only on ledger-model"
    );

    let forbidden_source_tokens_chirho = [
        "std::fs",
        "std::io",
        "std::net",
        "std::process",
        "std::thread",
        "std::time",
        "File::",
        "OpenOptions",
        "TcpStream",
        "UdpSocket",
        "Command::",
        "cairn_durable_chirho",
        "cairn_seqlog_chirho",
        "cairn_signer_chirho",
        "cairn_store",
        "cairn_writer",
    ];
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| path_chirho.starts_with(crate_dir_chirho.join("src")))
    {
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for (line_index_chirho, line_chirho) in
            production_text_chirho(&source_chirho).lines().enumerate()
        {
            for token_chirho in forbidden_source_tokens_chirho {
                if line_chirho.contains(token_chirho) {
                    offenders_chirho.push(format!(
                        "{}:{}:{token_chirho}",
                        workspace_relative_chirho(&path_chirho),
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "the CF4 conservation monitor is detect-only: no I/O, signer, log, store, or writer authority: {offenders_chirho:?}"
    );
}

#[test]
fn ledger_read_model_stays_pure_non_authoritative_and_downward_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_dir_chirho = root_chirho.join(LEDGER_READ_MODEL_CRATE_CHIRHO);
    let manifest_chirho = std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml"))
        .expect("read ledger read-model Cargo.toml");
    let dependency_section_chirho = manifest_chirho
        .split_once("[dependencies]")
        .expect("ledger read-model must declare dependencies")
        .1
        .split("\n[")
        .next()
        .unwrap();
    let actual_dependencies_chirho = dependency_section_chirho
        .lines()
        .filter_map(|line_chirho| line_chirho.split_once('='))
        .map(|(name_chirho, _value_chirho)| name_chirho.trim())
        .filter(|name_chirho| !name_chirho.is_empty())
        .collect::<BTreeSet<_>>();
    let expected_dependencies_chirho = BTreeSet::from([
        "anyhow",
        "blake3",
        // The CF4 brick-1b/2 expansion (#4972 rulings): cairn-chain-core is a PURE law crate (no
        // I/O, no signer, no clock), and cairn-ledger-log supplies the INJECTED ports plus the
        // verified journal open the feeder/registry consume — a downward dependency that mints no
        // authority here. What the read-model DOES with those ports stays pinned by its own laws
        // (registry-CURRENT feed gate, feeder-root-only receipts, the equivalence canary), and the
        // ambient-I/O token scan below still applies to every read-model source file unchanged.
        "cairn-chain-core-chirho",
        "cairn-ledger-log-chirho",
        "cairn-ledger-model-chirho",
        "cairn-model-privacy-chirho",
        "serde",
        "serde_json",
    ]);
    assert_eq!(
        actual_dependencies_chirho, expected_dependencies_chirho,
        "the CF4 read-model must depend only on pure domain leaves, the shared chain law, the \
         injected ledger ports, and serialization helpers"
    );

    let workspace_manifest_chirho =
        std::fs::read_to_string(root_chirho.join("Cargo.toml")).unwrap();
    let workspace_member_count_chirho = workspace_manifest_chirho
        .lines()
        .filter(|line_chirho| {
            line_chirho.trim().trim_end_matches(',').trim_matches('"')
                == LEDGER_READ_MODEL_CRATE_CHIRHO
        })
        .count();
    assert_eq!(
        workspace_member_count_chirho, 1,
        "the CF4 read-model must be registered exactly once as a workspace member"
    );
    let root_dependencies_chirho = workspace_manifest_chirho
        .split_once("[dependencies]")
        .unwrap()
        .1
        .split("\n[")
        .next()
        .unwrap();
    assert!(
        !root_dependencies_chirho.contains("cairn-ledger-read-model-chirho"),
        "the root runtime must not gain a production dependency on the CF4 read-model"
    );
    let root_dev_dependencies_chirho = workspace_manifest_chirho
        .split_once("[dev-dependencies]")
        .unwrap()
        .1
        .split("\n[")
        .next()
        .unwrap();
    assert!(
        root_dev_dependencies_chirho.contains(
            "cairn-ledger-read-model-chirho = { path = \"crates/ledger-chirho/cairn-ledger-read-model-chirho\" }"
        ),
        "the reviewed producer-to-served-verifier test seam must remain dev-only"
    );

    let forbidden_source_tokens_chirho = [
        "std::fs",
        "std::io",
        "std::net",
        "std::process",
        "std::thread",
        "std::time",
        "File::",
        "OpenOptions",
        "TcpStream",
        "UdpSocket",
        "Command::",
        "cairn_chirho::",
        "cairn_durable_chirho",
        "cairn_seqlog_chirho",
        "cairn_signer_chirho",
        "cairn_store",
        "cairn_writer",
        "create_durable_chirho",
        "append_durable_chirho",
        "atomic_write_chirho",
        "admit_chirho(",
    ];
    // The crate's COMPLETE write inventory, explicit by law (#4972a + the CF7 §3 publication
    // ruling): the projection REGISTRY appends its own signed CONFIG chain, and PUBLICATION
    // atomically writes DERIVED artifacts only (CAS view bytes + the signed receipt head — the
    // old-or-refuse commit point; rebuildable evidence, never money records). Every VIEW surface
    // (descriptor/follower/merge/feeder/serving) keeps the full ban: views stay derived and
    // write-free, and no read-model file may ever sign money, bill, admit, or touch a
    // journal/store writer beyond these two named surfaces.
    let sanctioned_writes_chirho = [
        ("registry_chirho.rs", "append_durable_chirho"),
        ("source_registry_chirho.rs", "append_durable_chirho"),
        ("publication_chirho.rs", "atomic_write_chirho"),
    ];
    let mut offenders_chirho = Vec::new();
    for path_chirho in workspace_production_rs_files_chirho()
        .into_iter()
        .filter(|path_chirho| path_chirho.starts_with(crate_dir_chirho.join("src")))
    {
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        for (line_index_chirho, line_chirho) in
            production_text_chirho(&source_chirho).lines().enumerate()
        {
            for token_chirho in forbidden_source_tokens_chirho {
                if line_chirho.contains(token_chirho) {
                    let sanctioned_here_chirho =
                        sanctioned_writes_chirho
                            .iter()
                            .any(|(file_chirho, write_token_chirho)| {
                                token_chirho == *write_token_chirho
                                    && path_chirho
                                        .file_name()
                                        .is_some_and(|name_chirho| name_chirho == *file_chirho)
                            });
                    if sanctioned_here_chirho {
                        continue;
                    }
                    offenders_chirho.push(format!(
                        "{}:{}:{token_chirho}",
                        workspace_relative_chirho(&path_chirho),
                        line_index_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "the CF4 read-model is derived and non-authoritative: no I/O, signer, log, store, writer, or admission authority (sanctioned exceptions: the registry's own config-chain append; publication's derived-artifact atomic writes): {offenders_chirho:?}"
    );
}

#[test]
fn review_use_case_crate_stays_port_only_no_io_or_authority_chirho() {
    let root_chirho = workspace_root_chirho();
    let crate_dir_chirho = root_chirho.join("crates/services-chirho/cairn-review-use-case-chirho");
    let manifest_chirho = std::fs::read_to_string(crate_dir_chirho.join("Cargo.toml"))
        .expect("read review use-case Cargo.toml");
    let depends_on_root_chirho = manifest_chirho
        .lines()
        .any(|line_chirho| line_chirho.trim_start().starts_with("cairn-chirho"));
    assert!(
        !depends_on_root_chirho,
        "cairn-review-use-case-chirho must not depend on root cairn-chirho"
    );

    let mut files_chirho = Vec::new();
    collect_rs_files_chirho(&crate_dir_chirho.join("src"), &mut files_chirho);
    let forbidden_chirho = [
        "std::fs",
        "std::path",
        "read_to_string",
        "write(",
        "File::",
        "cairn_chirho::",
        "store_chirho::",
        "refs_chirho::",
        "identity_chirho::",
        "effect_chirho::",
        "seqlog_chirho::",
        "crate::app_chirho",
        "cairn_chirho::app_chirho",
        "effect_pricing_chirho::",
        "pricebook_chirho::",
        "paid_chirho::",
        "deploy_app_chirho",
        "append_review_record_chirho",
        "sign_message_chirho",
    ];
    let mut offenders_chirho = Vec::new();
    for file_chirho in files_chirho {
        let text_chirho = std::fs::read_to_string(&file_chirho).unwrap();
        for (line_chirho, text_chirho) in production_text_chirho(&text_chirho).lines().enumerate() {
            for needle_chirho in forbidden_chirho {
                if text_chirho.contains(needle_chirho) {
                    offenders_chirho.push(format!(
                        "{}:{}:{needle_chirho}",
                        workspace_relative_chirho(&file_chirho),
                        line_chirho + 1
                    ));
                }
            }
        }
    }
    assert!(
        offenders_chirho.is_empty(),
        "review use-case crate must stay port-only: no root dependency, filesystem/path I/O, or root authority imports: {offenders_chirho:?}"
    );
}

#[test]
fn smoke_report_structs_do_not_publish_local_paths_chirho() {
    // Workspace-aware: smoke reports stay path-free wherever the smoke modules live.
    for path_chirho in workspace_production_rs_files_chirho() {
        let Some(file_name_chirho) = path_chirho
            .file_name()
            .and_then(|name_chirho| name_chirho.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if !file_name_chirho.ends_with("_smoke_chirho.rs") {
            continue;
        }
        let source_chirho = std::fs::read_to_string(&path_chirho).unwrap();
        if !source_chirho.contains("SmokeReportChirho") {
            continue;
        }
        for line_chirho in source_chirho.lines() {
            let line_chirho = line_chirho.trim();
            assert!(
                !(line_chirho.starts_with("pub ") && line_chirho.contains("_path_chirho: String")),
                "{} publishes a local path field in a smoke report: {}",
                file_name_chirho,
                line_chirho
            );
            assert!(
                !(line_chirho.starts_with("pub ") && line_chirho == "pub root_chirho: String,"),
                "{} publishes a local root path field in a smoke report",
                file_name_chirho
            );
        }
    }
}

// Relocated from cas_chirho.rs: that file compiles inside the cairn-core-chirho crate, which
// cannot reach this lib-side workspace walker. Same assertions, now workspace-wide.
#[test]
fn object_store_raw_access_stays_cas_or_inventory_only_chirho() {
    // The path helper and both verifying readers stay inside CAS. This lexical census
    // classifies the access sites; behavioral tests cover hashing and the bounded reader.
    let object_path_refs_chirho = production_source_lines_matching_chirho("object_path_chirho(");
    assert_eq!(
        object_path_refs_chirho.len(),
        3,
        "production object_path_chirho refs must stay centralized in cas_chirho: {object_path_refs_chirho:?}"
    );
    for (file_chirho, _line_chirho, text_chirho) in object_path_refs_chirho {
        let allowed_chirho = file_chirho == "crates/cairn-core-chirho/src/cas_chirho.rs"
            && matches!(
                text_chirho.as_str(),
                "pub(crate) fn object_path_chirho(root_chirho: &Path, addr_chirho: &HashChirho) -> PathBuf {"
                    | "let bytes_chirho = match fs::read(object_path_chirho(root_chirho, addr_chirho)) {"
                    | "&object_path_chirho(root_chirho, addr_chirho),"
            );
        assert!(
            allowed_chirho,
            "production object_path_chirho ref escaped CAS: {file_chirho}: {text_chirho}"
        );
    }

    let raw_store_refs_chirho = production_source_lines_matching_chirho("\"objects-chirho\"");
    assert_eq!(
        raw_store_refs_chirho.len(),
        14,
        "production objects-chirho refs must stay CAS/inventory/root-evidence/policy-name only: {raw_store_refs_chirho:?}"
    );
    for (file_chirho, _line_chirho, text_chirho) in raw_store_refs_chirho {
        let allowed_chirho = match file_chirho.as_str() {
            "crates/cairn-core-chirho/src/cas_chirho.rs" => {
                text_chirho == ".join(\"objects-chirho\")"
            }
            // The workspace-wide scan (vs the old src/-only scan) also sees the portable
            // filesystem store adapter — itself a CAS implementation surface.
            "crates/stores-chirho/cairn-store-fs-chirho/src/lib.rs" => {
                text_chirho == "self.root_chirho.join(\"objects-chirho\")"
            }
            // The P3 local-fs replication adapter reads a SOURCE root's objects to pull them; it is
            // read-only transport (verification is the receiver's job) and holds no write authority.
            "crates/stores-chirho/cairn-replication-localfs-chirho/src/lib.rs" => {
                text_chirho == "self.source_root_chirho.join(\"objects-chirho\")"
            }
            // F4's descriptor-relative CAS lifecycle IS the CAS write/delete surface: both refs
            // open the objects directory under custody verification (atomic no-replace publish,
            // verified delete) — openat-style directory names, never a raw path join.
            "crates/support-chirho/cairn-durable-chirho/src/cas_lifecycle_chirho.rs" => {
                text_chirho == "\"objects-chirho\","
            }
            "crates/support-chirho/cairn-seqlog-chirho/src/seqlog_chirho.rs" => {
                text_chirho == "| \"objects-chirho\""
            }
            "src/governance_flows_chirho/gc_chirho.rs" => {
                text_chirho == "| \"objects-chirho\""
                    || text_chirho
                        == "let objects_dir_chirho = root_chirho.join(\"objects-chirho\");"
            }
            "src/privacy_compliance_chirho/privacy_chirho/scan_chirho.rs" => {
                text_chirho == "| \"objects-chirho\""
                    || text_chirho
                        == "let objects_dir_chirho = root_chirho.join(\"objects-chirho\");"
            }
            "src/governance_flows_chirho/privacy_backup_chirho.rs" => {
                text_chirho == "|| root_chirho.join(\"objects-chirho\").is_dir()"
            }
            "src/operator_flows_chirho/ops_restore_drill_chirho.rs" => {
                text_chirho
                    == "cas_objects_chirho: count_regular_files_chirho(&root_chirho.join(\"objects-chirho\"))?,"
            }
            // A NAME IN A POLICY TABLE, NOT AN ACCESS — a category this allowlist did not have
            // before, so it is worth stating rather than filing quietly under "inventory".
            //
            // CF8 clause 5 requires every root surface to carry an explicit disposition, and a table
            // that says what happens to the object store on a tenant-root move must be able to SAY
            // "objects-chirho". This entry is a `&str` in a const array of (surface, disposition)
            // pairs: no path join, no open, no read, no write. The scanner cannot tell a name from a
            // path join, and it SHOULD NOT try — over-scanning is the correct error for a guard, and
            // the reviewed allowlist is where "seen, and it is a name" gets recorded by a human.
            //
            // If this file ever grows an actual path join or read against the object store, that is
            // a real escape and this entry must not be widened to cover it: the disposition table
            // decides POLICY about surfaces and must never acquire the ability to touch one.
            "crates/support-chirho/cairn-tenant-chirho/src/surface_disposition_chirho.rs" => {
                text_chirho == "\"objects-chirho\","
            }
            _ => false,
        };
        assert!(
            allowed_chirho,
            "production objects-chirho access escaped verified CAS/inventory allowlist: {file_chirho}: {text_chirho}"
        );
    }
}
